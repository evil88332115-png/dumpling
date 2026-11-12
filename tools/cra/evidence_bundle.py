#!/usr/bin/env python3
"""evidence_bundle.py：每個發行版本凍結一份證據包（掃了什麼、怎麼判的），離開本機與 GitLab artifacts 保存 10 年（CRA M-5）。

用法：
  python3 -I evidence_bundle.py create --result <結果資料夾> [--project <CRA 專案>] --out <資料夾>
                                      [--name <檔名>] [--time <UTC，例如 2026-11-03T08:00:00Z>] [--secrets-file <檔案>]
  python3 -I evidence_bundle.py verify <證據包.tar.xz> [--sha256 <另外保存的 sha256>]

create：--result 是 scan-flash-package.sh 的結果資料夾（每個 <rootfs>/ 有 scan/、cra-project/），或 sca-scan 的輸出資料夾
  （這時 --project 給 CRA 專案，也就是有 CRA/Config 的資料夾）。只收白名單裡的檔案（SBOM、Grype／DT 結果、status.tsv、meta.json、
  核心與 NVIDIA 對照、CRA/Config、CRA/Reports、pkgdb、刷機包清點、映像靜態檢查 image-check/、自有軟體 own-software/、板子檢查 board-test/…），
  **不收刷機包、rootfs、映像 tar、logs/、commands.tsv**。
  在 --out 寫三個檔：<名稱>.tar.xz、<名稱>.manifest.json（與包內 manifest.json 相同）、<名稱>.tar.xz.sha256。
  manifest：每個檔案的大小與 sha256、產品名稱與版本、刷機包的身分（檔名、大小、核對過的 md5；刷機包本身不收）、工具與資料庫版本
  （讀不到的寫 unknown，不猜）、sca-center commit、檢查項目。
  決定性：時間（frozen_utc，也是 tar 內的 mtime）＝收進來的檔案最新的 mtime，或 --time；tar 成員依名稱排序、uid/gid 0、權限 0644。
  同樣的輸入再做一次，三個檔案逐位元組相同。已經有同名證據包時：相同 → 不重寫；不同 → FAIL（不覆寫已凍結的證據）。
  結果資料夾可能含不可信刷機包的資料：逐層不跟隨符號連結（O_NOFOLLOW）、只收一般檔案（硬連結、裝置檔、FIFO 不收）、單檔與總量上限、
  看起來是封存檔、映像或執行檔的不收。先複製到暫存區（結果資料夾旁邊，不在 --out），連同 manifest 與每個 .xz 解壓後的內容，
  用 tools/pilot/lib/leakscan.py 比對秘密（PILOT_ENV 的 DT／DejaCode／ScanCode.io 金鑰與 --secrets-file；秘密不出現在指令列），
  再檢查私鑰與常見 token 的樣式；有任何命中 → FAIL，什麼都不寫。寫入 --out：暫存檔（fsync）→ rename，旁邊的檔先、封存檔最後；
  失敗時刪掉已寫的，不留半套。
  印一行：EVIDENCE<TAB>OK｜ATTENTION｜FAIL<TAB>說明。ATTENTION：證據包照樣寫出，但缺了該有的東西
  （沒有 VEX、CRA 文件不是 OK、沒有 SBOM、刷機包 md5 沒有核對、沒有秘密清單、有檔案因為連結或大小沒收…），manifest 的 checks 列出來。
verify：重算包內每個檔案的 sha256 與大小，和包內 manifest 比對（內容不同、缺少、多出都算），旁邊有 .manifest.json 與 .sha256 時也比對。
  只讀 tar 結構，不解開到磁碟。可信的錨點是另外保存的 sha256（--sha256）：旁邊的檔可以和封存檔一起被換掉。
  旁邊的檔有缺、又沒有給 --sha256 → ATTENTION。印一行：EVIDENCE-VERIFY<TAB>OK｜ATTENTION｜FAIL<TAB>說明。
退出碼：OK 0、ATTENTION 2、FAIL 1、參數錯 64；未預期的錯誤也是 FAIL（create 不寫任何東西）。
"""
import argparse
import contextlib
import datetime
import errno
import hashlib
import importlib.util
import json
import lzma
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SCHEMA = "sca-center-evidence-bundle/1"
LIMITS = {"file": 512 << 20, "total": 4 << 30, "files": 5000}
CHUNK = 1 << 20
UNKNOWN = "unknown"

# sca-scan 輸出資料夾裡要收的檔案（相對路徑）。.json 也收 .json.xz（cra_report 兩種都讀）
SCAN_FILES = ("status.tsv", "meta.json", "report.json", "report.html",
              "sbom/sbom.cdx.json", "sbom/sbom.upload.cdx.json",
              "scan/grype.json", "scan/grype-db-status.txt", "scan/sbomgate.json", "scan/sbomgate.txt", "scan/lockfiles.json",
              "scan/govulncheck.json", "scan/kernel-coverage.json", "scan/kernel-config.json", "scan/kernel-boot.json", "scan/kernel-module-map.json",
              "scan/l4t-kernel-map.json",
              "scan/nvidia-bulletins.json", "scan/distro-recheck.json",
              "dt/findings.json", "dt/deb-sources.json", "dt/data-sources.json", "dt/version.json",
              "dejacode/compliance.json", "dejacode/NOTICE.txt")
# CRA 專案：這些資料夾第一層、副檔名符合的一般檔案
PROJECT_DIRS = (("CRA/Config", (".json",)), ("CRA/Reports", (".md", ".json", ".tsv")), ("CRA/templates", (".md",)))
FLASH_TOP = ("status.tsv", "summary.md", "summary.json", "list.json", "flash-inventory.json", "provenance.json")
FLASH_TARGET = ("rootfs-tar.json", "package-dependencies.md", "pkgdb/dpkg-status", "pkgdb/extended_states", "pkgdb/pkgdb.json",
                "image-check/image-check.json", "image-check/image-check.md", "board-test/board-test.json",
                "own-software/own-software.json")       # 產品自有軟體（只在設定 sbom.own_software 時存在）
# 匯入的板子檢查結果 <rootfs>/board-test/<名稱>/：board_import.py 只會寫這些檔名（兩支板子腳本的輸出與 import.json）
# （*.err 是工具的 stderr，和 logs/ 一樣不收；summary.txt 已記每項檢查的狀態）
BOARD_RESULT = re.compile(r"^(?:[a-z0-9-]+\.(?:txt|dat|log|gnmap|nmap|xml)|(?:ssh-audit|testssl)-\d{1,5}\.json|import\.json)$")
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,120}$")
NOT_INCLUDED = ("刷機包、rootfs、映像 tar 一律不收（機密、很大）；logs/、commands.tsv、*.stderr.txt、pid 不收；"
                "只收白名單的檔案（evidence_bundle.py 的 SCAN_FILES、PROJECT_DIRS、FLASH_TOP、FLASH_TARGET、board-test/<名稱>/ 的 BOARD_RESULT）")
# 樣式檢查：完整的 PEM 私鑰區塊與常見 token（leakscan 只比對已知的值）
SECRET_PATTERNS = (
    ("private-key", re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----\s+[A-Za-z0-9+/=\s]{64,}?-----END [A-Z0-9 ]*PRIVATE KEY-----")),
    ("dt-api-key", re.compile(rb"\bodt_[A-Za-z0-9]{32,}")),
    ("gitlab-token", re.compile(rb"\bglpat-[A-Za-z0-9_-]{20,}")),
    ("github-token", re.compile(rb"\b(?:ghp|gho|ghs|ghu)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}")),
    ("aws-key", re.compile(rb"\bAKIA[0-9A-Z]{16}\b")),
)
MIN_SECRET = 8
SECRET_KEYS = ("DT_API_KEY", "DEJACODE_API_KEY", "SCANCODEIO_API_KEY")   # 同 sca-scan 的 secret()
SHA256_RE = re.compile(r"[0-9a-fA-F]{64}")
RANK = {"OK": 0, "INFO": 0, "ATTENTION": 1, "FAIL": 2}


class Fail(Exception):
    pass


class Skip(Exception):
    """這個檔案不收（原因寫進 manifest 的 skipped）。"""


def now_iso(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def clean(v, n=200):
    """不可信資料裡的字串：去控制字元、截斷。"""
    if v is None:
        return None
    if isinstance(v, (int, float, bool)):
        return v
    return re.sub(r"[\x00-\x1f\x7f]", " ", str(v))[:n]


def text(v, n=200):
    """產品名稱、版本這類欄位：字串或數字 → 字串；其他型別（物件、陣列、布林）→ None。"""
    if v is None or isinstance(v, (dict, list, bool)):
        return None
    return clean(str(v), n)


def as_dict(v):
    return v if isinstance(v, dict) else {}


def known(v):
    v = clean(v)
    return UNKNOWN if v in (None, "", "未知", "?") else v


def slug(v, n=40):
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", str(v or "")).strip("-._")[:n].strip("-._")
    return s or UNKNOWN


# ---------- 讀結果資料夾（不跟隨符號連結） ----------

def open_path(root_fd, rel, directory=False):
    """從 root_fd 逐層以 O_NOFOLLOW 開 rel。不存在 → None；經過符號連結或型別不對 → Skip。"""
    parts = rel.split("/")
    fd = os.dup(root_fd)
    try:
        for i, p in enumerate(parts):
            last = i == len(parts) - 1
            flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
            flags |= os.O_DIRECTORY if (not last or directory) else os.O_NONBLOCK
            try:
                if last and not directory and not stat.S_ISREG(os.stat(p, dir_fd=fd, follow_symlinks=False).st_mode):
                    raise Skip("不是一般檔案")     # 裝置檔、FIFO 不開
                nfd = os.open(p, flags, dir_fd=fd)
            except OSError as e:
                if e.errno == errno.ENOENT:
                    return None
                if e.errno in (errno.ELOOP, errno.EMLINK):
                    raise Skip("符號連結，不跟隨")
                if e.errno == errno.ENOTDIR:
                    raise Skip("上層是符號連結或不是資料夾")
                raise Skip(f"開不了（{errno.errorcode.get(e.errno, e.errno)}）")
            os.close(fd)
            fd = nfd
        st = os.fstat(fd)
        if directory != stat.S_ISDIR(st.st_mode) or (not directory and not stat.S_ISREG(st.st_mode)):
            raise Skip("不是一般檔案" if not directory else "不是資料夾")
        r, fd = fd, None
        return r
    finally:
        if fd is not None:
            os.close(fd)


ARCHIVE_MAGIC = (b"BZh", b"\x7fELF", b"hsqs", b"sqsh", b"\x1f\x8b", b"PK\x03\x04", b"\x28\xb5\x2f\xfd",   # bzip2 ELF squashfs gzip zip zstd
                 b"7z\xbc\xaf\x27\x1c", b"070701", b"070702", b"070707", b"\xc7\x71", b"\x71\xc7",       # 7z cpio
                 b"\x3a\xff\x26\xed", b"\xfd7zXZ\x00", b"\x04\x22\x4d\x18")                              # Android sparse、xz、lz4


def looks_like_archive(head):
    """封存檔、映像、執行檔：不是證據檔，可能是映像或刷機包的一部分。
    ext2/3/4：超級區塊的 s_magic（1080）＋ s_state（1082，1–3），只看 magic 會誤判中文（「S」後面接 0xEF 開頭的全形字）。"""
    return (head[257:262] == b"ustar" or head.startswith(ARCHIVE_MAGIC)
            or (head[1080:1082] == b"\x53\xef" and head[1082:1084] in (b"\x01\x00", b"\x02\x00", b"\x03\x00")))


class Stager:
    def __init__(self, stage, limits):
        self.stage, self.limits = stage, limits
        self.files = {}      # 包內相對路徑 → {bytes, sha256}
        self.skipped = []
        self.total = 0
        self.mtime = 0

    def add_fd(self, fd, dest):
        st = os.fstat(fd)
        if st.st_size > self.limits["file"]:
            raise Skip(f"太大（{st.st_size} 位元組 > 上限 {self.limits['file']}）")
        if st.st_nlink > 1:
            raise Skip(f"硬連結（st_nlink {st.st_nlink}），可能指向結果資料夾以外的檔案，不收")
        if len(self.files) >= self.limits["files"]:
            raise Fail(f"檔案數超過上限 {self.limits['files']}")
        out = self.stage / dest
        out.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        h, n = hashlib.sha256(), 0
        with os.fdopen(os.dup(fd), "rb") as f, open(os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as o:
            first = True
            while True:
                b = f.read(CHUNK)
                if not b:
                    break
                if first:
                    first = False
                    head = b[:4096]
                    if dest.endswith(".xz"):
                        if head[:6] != b"\xfd7zXZ\x00":
                            raise Skip("副檔名 .xz 但不是 xz")
                        try:
                            head = lzma.LZMADecompressor().decompress(b, max_length=4096)
                        except lzma.LZMAError:
                            raise Skip("xz 解不開")
                    if looks_like_archive(head):
                        raise Skip("內容看起來是封存檔或執行檔（tar／bzip2／ELF…），不收")
                n += len(b)
                if n > self.limits["file"]:
                    raise Skip(f"讀取時超過上限 {self.limits['file']}")
                h.update(b)
                o.write(b)
        self.total += n
        if self.total > self.limits["total"]:
            raise Fail(f"總量超過上限 {self.limits['total']} 位元組")
        self.files[dest] = {"bytes": n, "sha256": h.hexdigest()}
        self.mtime = max(self.mtime, int(st.st_mtime))

    def add(self, root_fd, rel, dest):
        """rel 不存在 → False；不收 → 記 skipped。"""
        try:
            fd = open_path(root_fd, rel)
            if fd is None:
                return False
            try:
                self.add_fd(fd, dest)
            finally:
                os.close(fd)
            return True
        except Skip as e:
            (self.stage / dest).unlink(missing_ok=True)
            self.skipped.append({"path": dest, "reason": str(e)})
            return False

    def dir_ok(self, root_fd, rel, dest):
        """資料夾存在而且不是符號連結 → True；不存在 → False；連結等 → 記一次 skipped。"""
        if not rel:
            return True
        try:
            fd = open_path(root_fd, rel, directory=True)
        except Skip as e:
            self.skipped.append({"path": dest, "reason": str(e)})
            return False
        if fd is None:
            return False
        os.close(fd)
        return True

    def add_scan(self, root_fd, base, dest_base):
        if not self.dir_ok(root_fd, base, dest_base):
            return
        for rel in SCAN_FILES:
            src, dst = f"{base}/{rel}" if base else rel, f"{dest_base}/{rel}"
            if not self.add(root_fd, src, dst) and rel.endswith(".json"):
                self.add(root_fd, src + ".xz", dst + ".xz")

    def add_board(self, root_fd, base, dest_base):
        """<rootfs>/board-test/<名稱>/ 的板子結果（board_import.py 匯入的；只收 BOARD_RESULT 的檔名，隱藏的暫存資料夾不收）。"""
        try:
            dfd = open_path(root_fd, base, directory=True)
        except Skip as e:
            self.skipped.append({"path": dest_base, "reason": str(e)})
            return
        if dfd is None:
            return
        try:
            names = sorted(os.listdir(dfd))
        finally:
            os.close(dfd)
        for n in names:
            if n == "board-test.json" or n.startswith("."):
                continue
            if not SAFE_NAME.match(n):
                self.skipped.append({"path": f"{dest_base}/{clean(n, 80)}", "reason": "名稱有不允許的字元"})
                continue
            try:
                sfd = open_path(root_fd, f"{base}/{n}", directory=True)
            except Skip as e:
                self.skipped.append({"path": f"{dest_base}/{n}", "reason": str(e)})
                continue
            if sfd is None:
                continue
            try:
                files = sorted(os.listdir(sfd))
            finally:
                os.close(sfd)
            for f in files:
                if BOARD_RESULT.match(f):
                    self.add(root_fd, f"{base}/{n}/{f}", f"{dest_base}/{n}/{f}")
                elif not f.endswith(".err"):
                    self.skipped.append({"path": f"{dest_base}/{n}/{clean(f, 80)}", "reason": "不是板子檢查結果的檔名"})

    def add_project(self, root_fd, base, dest_base):
        if not self.dir_ok(root_fd, base, dest_base):
            return
        for d, exts in PROJECT_DIRS:
            src = f"{base}/{d}" if base else d
            try:
                dfd = open_path(root_fd, src, directory=True)
            except Skip as e:
                self.skipped.append({"path": f"{dest_base}/{d}", "reason": str(e)})
                continue
            if dfd is None:
                continue
            try:
                names = sorted(os.listdir(dfd))
            finally:
                os.close(dfd)
            for n in names:
                if SAFE_NAME.match(n) and n.endswith(exts):
                    self.add(root_fd, f"{src}/{n}", f"{dest_base}/{d}/{n}")
                elif n.endswith(exts):
                    self.skipped.append({"path": f"{dest_base}/{d}/{clean(n, 80)}", "reason": "檔名有不允許的字元"})


# ---------- 讀已複製的檔案，整理 manifest ----------

def load_json(stage, rel, limit):
    for r, xz in ((rel, False), (rel + ".xz", True)):
        p = stage / r
        if p.is_file():
            try:
                data = p.read_bytes()
                if xz:
                    d = lzma.LZMADecompressor()
                    data = d.decompress(data, max_length=limit)
                return json.loads(data)
            except (ValueError, lzma.LZMAError, OSError):
                return None
    return None


def read_status(stage, rel):
    p = stage / rel
    if not p.is_file():
        return None
    rows = {}
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines()[1:]:
        f = line.split("\t")
        if len(f) >= 2 and f[0]:
            rows[f[0]] = (f[1], f[2] if len(f) > 2 else "")
    return rows


def status_summary(rows):
    if rows is None:
        return None
    counts = {}
    for s, _ in rows.values():
        counts[clean(s, 20)] = counts.get(clean(s, 20), 0) + 1
    return {"counts": dict(sorted(counts.items())),
            "not_ok": [f"{clean(k, 60)} {clean(s, 20)}" for k, (s, _) in sorted(rows.items()) if s not in ("OK", "INFO")][:80]}


def tools_of(stage, d, limit):
    """d：包內 sca-scan 輸出的相對路徑。只記讀得到的；其他寫 unknown。"""
    meta = as_dict(load_json(stage, f"{d}/meta.json", limit))
    mt = meta.get("tools") if isinstance(meta.get("tools"), dict) else {}
    tools = {k: known(mt.get(k)) for k in ("syft", "grype", "cdxgen", "govulncheck", "bwrap") if k in mt}
    for k in ("syft", "grype"):
        tools.setdefault(k, UNKNOWN)
    tools["dependency_track"] = known(meta.get("dt_version"))
    sbom = as_dict(load_json(stage, f"{d}/sbom/sbom.cdx.json", limit))
    tc = as_dict(sbom.get("metadata")).get("tools") or {}
    comps = tc.get("components") if isinstance(tc, dict) else tc if isinstance(tc, list) else []
    gen = [f"{clean(c.get('name'), 40)} {clean(c.get('version'), 40)}" for c in comps or [] if isinstance(c, dict) and c.get("name")]
    tools["sbom_generator"] = "; ".join(gen[:5]) or UNKNOWN
    built, schema = meta.get("grype_db_built"), meta.get("grype_db_schema")
    p = stage / f"{d}/scan/grype-db-status.txt"
    if p.is_file() and not (built and schema):
        txt = p.read_text(encoding="utf-8", errors="replace")
        m1, m2 = re.search(r"(?m)^Built:\s*(.+)$", txt), re.search(r"(?m)^Schema:\s*(.+)$", txt)
        built, schema = built or (m1 and m1.group(1).strip()), schema or (m2 and m2.group(1).strip())
    data = {"grype_db": {"built": known(built), "schema": known(schema)}}
    ds = load_json(stage, f"{d}/dt/data-sources.json", limit)
    if isinstance(ds, dict):
        data["dt_sources"] = [{"source": clean(r.get("label") or r.get("name"), 40), "status": known(r.get("status")),
                               "completed_at": known(r.get("completed_at"))} for r in ds.get("sources") or [] if isinstance(r, dict)][:20]
        nm = ds.get("nvd_mirror") if isinstance(ds.get("nvd_mirror"), dict) else {}
        data["nvd_mirror"] = {"mode": known(nm.get("mode")), "modified": known(nm.get("modified"))}
        data["dt_vuln_status"] = known(ds.get("vuln_status"))
    else:
        data["dt_sources"], data["nvd_mirror"] = UNKNOWN, {"mode": UNKNOWN, "modified": UNKNOWN}
    kc = load_json(stage, f"{d}/scan/kernel-config.json", limit)
    cd = kc.get("cve_data") if isinstance(kc, dict) and isinstance(kc.get("cve_data"), dict) else None
    data["kernel_cna"] = ({"commit_or_date": known(cd.get("commit_or_date")), "fetched_utc": known(cd.get("fetched_utc")),
                           "source": known(cd.get("source"))} if cd else UNKNOWN)
    nb = load_json(stage, f"{d}/scan/nvidia-bulletins.json", limit)
    m = nb.get("mirror") if isinstance(nb, dict) and isinstance(nb.get("mirror"), dict) else None
    data["nvidia_bulletins"] = {"commit": known(m.get("commit")), "fetched_utc": known(m.get("fetched_utc"))} if m else UNKNOWN
    dr = load_json(stage, f"{d}/scan/distro-recheck.json", limit)
    m = dr.get("mirror") if isinstance(dr, dict) and isinstance(dr.get("mirror"), dict) else None
    data["osv_distro"] = {"fetched_utc": known(m.get("fetched_utc"))} if m else UNKNOWN
    lm = load_json(stage, f"{d}/scan/l4t-kernel-map.json", limit)
    data["l4t_kernel_map"] = ({"release": known(lm.get("release") if not isinstance(lm.get("release"), dict) else
                                                 lm["release"].get("l4t") or json.dumps(lm["release"], sort_keys=True)[:120])}
                              if isinstance(lm, dict) else UNKNOWN)
    scan = {k: text(meta.get(k)) for k in ("name", "version", "content_version", "mode", "image_id", "digest", "content_sha256",
                                              "started", "finished") if meta.get(k) is not None}
    return tools, data, scan, meta


def cra_of(stage, p, limit):
    """p：包內 CRA 專案的相對路徑。"""
    cfg = load_json(stage, f"{p}/CRA/Config/config.json", limit)
    prod = as_dict(as_dict(cfg).get("product"))
    s = load_json(stage, f"{p}/CRA/Reports/summary.json", limit)
    cra = None
    if isinstance(s, dict):
        docs = as_dict(s.get("documents"))
        gate = as_dict(as_dict(s.get("vex")).get("gate"))
        cra = {"status": text(s.get("status"), 20), "generated": text(s.get("generated")),
               "documents": {clean(k, 60): text(v.get("status"), 20) for k, v in sorted(docs.items()) if isinstance(v, dict)},
               "vex_gate": text(gate.get("verdict"), 40)}
    return {"name": text(prod.get("name")), "version": text(prod.get("version"))}, cra, isinstance(cfg, dict)


def provenance(stage):
    """<結果>/provenance.json（scan-flash-package.sh 的 A-provenance）→ dict 或 None。"""
    pv = load_json(stage, "provenance.json", 1 << 20)
    return pv if isinstance(pv, dict) and pv.get("schema") == "sca-center-flash-provenance/1" else None


def flash_identity(stage, top):
    lj = load_json(stage, "list.json", 64 << 20)
    lj = lj if isinstance(lj, dict) else {}
    arch = lj.get("archive") if isinstance(lj.get("archive"), dict) else {}
    src = lj.get("source") if isinstance(lj.get("source"), dict) else {}
    md5s, md5d = (top or {}).get("A-md5", (None, ""))
    m = re.search(r"\b[0-9a-f]{32}\b", md5d or "") if md5s == "OK" else None
    fname = arch.get("file") or (os.path.basename(str(src.get("path") or "")) or None)
    nbytes = arch.get("bytes") if isinstance(arch.get("bytes"), int) else None
    # sha256：掃描時一次讀完刷機包算的（provenance.json）；檔名與大小要和 list.json 相同才用（不同 → 不是同一個刷機包的紀錄）
    pv = provenance(stage)
    ps = pv.get("source") if pv and isinstance(pv.get("source"), dict) else {}
    md5 = m.group(0) if m else None
    # A-md5 有核對過的 md5 時，provenance 的 md5 要相同（不同 → 不是同一個刷機包的紀錄）
    sha = ps.get("sha256") if (ps.get("type") == "archive" and ps.get("file") == fname and nbytes is not None and ps.get("bytes") == nbytes
                               and isinstance(ps.get("sha256"), str) and SHA256_RE.fullmatch(ps["sha256"])
                               and (md5 is None or ps.get("md5") == md5)) else None
    if sha:
        note = ("刷機包與 rootfs 不收；檔名與大小取自 list.json，md5 取自 status.tsv 的 A-md5，sha256 取自 provenance.json"
                + (f"（沿用 {clean(pv.get('carried_from'), 120)} 的紀錄，這次沒有重算）" if pv.get("carried_from") else "（掃描時算的）"))
    elif ps and ps.get("type") == "archive":
        note = "刷機包與 rootfs 不收；provenance.json 的檔名、大小或 md5 和 list.json／A-md5 不同，sha256 不用（寫 unknown）"
    else:
        note = "刷機包與 rootfs 不收；身分取自 list.json 與 status.tsv 的 A-md5（沒有 provenance.json 的 sha256：較舊的掃描，或 --dir）"
    return {"type": known(src.get("type")), "file": known(fname), "bytes": nbytes if nbytes is not None else UNKNOWN,
            "md5": m.group(0) if m else UNKNOWN, "md5_check": known(md5s),
            "sha256": sha or UNKNOWN, "sha256_source": ("carried" if pv.get("carried_from") else "computed") if sha else UNKNOWN,
            "included": False, "note": note}


def scan_commit(stage, layout):
    """掃描當時的 sca-center commit：scan-flash-package.sh 寫在 provenance.json；沒有時 unknown（不用打包時的 commit 代替）。"""
    pv = provenance(stage) if layout == "flash-package" else None
    tc = pv.get("sca_center") if pv and isinstance(pv.get("sca_center"), dict) else {}
    c = tc.get("commit")
    if isinstance(c, str) and re.fullmatch(r"[0-9a-f]{40}", c):
        return c, {"from": known(tc.get("from")), "dirty": tc.get("dirty") if isinstance(tc.get("dirty"), bool) else None,
                   "note": "掃描時的 sca-center commit（provenance.json）" + ("；掃描時有未提交的改動" if tc.get("dirty") else "")}
    return UNKNOWN, {"note": "掃描當時的 sca-center commit 沒有記在結果裡（較舊的 scan-flash-package.sh，或 sca-scan 的輸出：meta.json 沒有這個欄位）"}


def sca_center_commit():
    try:
        if (ROOT / ".git").exists():
            r = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=10)
            if r.returncode == 0 and re.fullmatch(r"[0-9a-f]{40}", r.stdout.strip()):
                return r.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    m = re.fullmatch(r"app-([0-9a-f]{40})", ROOT.resolve().name)   # 常駐環境：sca-persist/app-<commit>
    return m.group(1) if m else UNKNOWN


def pilot_secrets(path):
    """PILOT_ENV 裡的金鑰值（只讀已知鍵，不 source、不印）。"""
    out = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                m = re.match(r"^\s*(?:export\s+)?([A-Z_]+)=(.*)$", line.rstrip("\r\n"))
                if m and m.group(1) in SECRET_KEYS:
                    v = m.group(2)
                    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                        v = v[1:-1]
                    if v:
                        out.append(v)
    except OSError:
        return None
    return out


def leakscan_mod():
    spec = importlib.util.spec_from_file_location("sca_leakscan", ROOT / "tools" / "pilot" / "lib" / "leakscan.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_secrets(secrets_file, pilot_env):
    """回傳 (秘密值, 太短而忽略的值數)。不印、不放指令列。"""
    vals = []
    if pilot_env:
        vals += pilot_secrets(pilot_env) or []
    if secrets_file:
        try:
            with open(secrets_file, "rb") as f:
                vals += [l.rstrip(b"\r\n").decode("utf-8", "surrogateescape") for l in f if l.strip()]
        except OSError:
            raise Fail("讀不到 --secrets-file")
    short = sum(1 for v in vals if len(v) < MIN_SECRET)
    return [v for v in vals if len(v) >= MIN_SECRET], short   # 太短的值會比對到一般文字（leakscan 是子字串比對）


def secret_hits(work, stage, vals, limit, total_limit, staged=0):
    """暫存區（含 manifest.json）與每個 .xz 解壓後的內容：leakscan 比對秘密值，再比對私鑰與 token 樣式。回傳命中的包內路徑。
    秘密清單與解壓的內容都在 work（不在 --out、不進 tar），掃完刪除。"""
    plain = work / "plain"
    plain.mkdir(mode=0o700)
    total = staged       # 複製的量＋解壓的量一起算總量上限：xz 炸彈不能塞滿暫存區的磁碟
    for p in sorted(stage.rglob("*.xz")):
        dst = plain / p.relative_to(stage)
        dst.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        n = 0
        try:
            with lzma.open(p, "rb") as fi, open(os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as fo:
                for b in iter(lambda: fi.read(CHUNK), b""):
                    n += len(b)
                    total += len(b)
                    if n > limit:
                        raise Fail(f"{p.relative_to(stage)} 解壓後超過上限 {limit} 位元組：無法檢查秘密，沒有寫出證據包")
                    if total > total_limit:
                        raise Fail(f"複製與 .xz 解壓後的總量超過上限 {total_limit} 位元組（到 {p.relative_to(stage)}）：無法檢查秘密，沒有寫出證據包")
                    fo.write(b)
        except (lzma.LZMAError, EOFError):
            raise Fail(f"{p.relative_to(stage)} 解不開：無法檢查秘密，沒有寫出證據包")

    def label(h):
        h = Path(h)
        return f"{h.relative_to(plain)}（解壓後）" if plain in h.parents else str(h.relative_to(stage))
    sd = work / "secrets"
    sd.mkdir(mode=0o700)
    lf = sd / "list.txt"
    try:
        with open(os.open(lf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as f:
            for v in vals:
                f.write(v.encode("utf-8", "surrogateescape") + b"\n")
        hits = {label(h) for h in leakscan_mod().scan(str(lf), [str(stage), str(plain)])}
    finally:
        shutil.rmtree(sd, ignore_errors=True)
    for root in (stage, plain):
        for p in sorted(root.rglob("*")):
            if p.is_file():
                data = p.read_bytes()
                for name, rx in SECRET_PATTERNS:
                    if rx.search(data):
                        hits.add(f"{label(p)}（{name}）")
    shutil.rmtree(plain, ignore_errors=True)
    return sorted(hits)


def publish(out, items):
    """items：[(最後的路徑, 來源)]，依序放上去（旁邊的檔先、封存檔最後）。先全部在 --out 寫成暫存檔（O_EXCL、fsync），
    再逐一 os.link（已存在就失敗，不覆寫別的執行寫的檔）；檔案系統不支援硬連結（NAS）時才退回「檢查不存在＋rename」
    （這時和同時執行的另一次之間有很小的競爭）。任何一步失敗：刪掉暫存檔與這次放上去的檔，不留半套。"""
    tmps, done = [], []
    try:
        for final, src in items:
            t = out / f".{final.name}.tmp-{os.getpid()}"
            with open(src, "rb") as fi, open(os.open(t, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as fo:
                tmps.append((t, final))
                shutil.copyfileobj(fi, fo, CHUNK)
                fo.flush()
                os.fsync(fo.fileno())
        for t, final in tmps:
            try:
                _link(t, final)
            except FileExistsError:
                raise Fail(f"{final.name} 在寫入時出現了（可能是同時執行的另一次）：不覆寫")
            except OSError as e:
                if e.errno not in NO_LINK:
                    raise
                if final.exists() or final.is_symlink():
                    raise Fail(f"{final.name} 在寫入時出現了（可能是同時執行的另一次）：不覆寫")
                _rename(t, final)
            done.append(final)
            with contextlib.suppress(FileNotFoundError):
                t.unlink()
        try:
            dfd = os.open(out, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            pass
    except BaseException:
        for t, _ in tmps:
            with contextlib.suppress(OSError):
                t.unlink()
        for f in done:
            with contextlib.suppress(OSError):
                f.unlink()
        raise


_rename = os.rename
_link = os.link
# 檔案系統不支援硬連結時 os.link 的錯誤
NO_LINK = {errno.EPERM, errno.EXDEV, errno.EMLINK, errno.ENOSYS, getattr(errno, "ENOTSUP", -1), getattr(errno, "EOPNOTSUPP", -2)}


# ---------- tar ----------

def write_tar(fobj, base, stage, rels, mtime):
    """決定性的 tar.xz：名稱排序、uid/gid 0、權限 0644、mtime 固定、沒有資料夾成員。"""
    with lzma.LZMAFile(fobj, "w", preset=6) as xz, tarfile.open(fileobj=xz, mode="w", format=tarfile.PAX_FORMAT) as t:
        for rel in sorted(rels):
            p = stage / rel
            ti = tarfile.TarInfo(f"{base}/{rel}")
            ti.size, ti.mtime, ti.mode, ti.uid, ti.gid, ti.uname, ti.gname = p.stat().st_size, mtime, 0o644, 0, 0, "", ""
            with open(p, "rb") as f:
                t.addfile(ti, f)


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(CHUNK), b""):
            h.update(b)
    return h.hexdigest()


def parse_time(s):
    try:
        t = datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        raise Fail(f"--time 看不懂：{clean(s, 60)}（例如 2026-11-03T08:00:00Z）")
    if t.tzinfo is None:
        raise Fail("--time 要有時區（UTC 用 Z）")
    return int(t.timestamp())


# ---------- create ----------

def in_shared_tmp(p):
    """realpath 後在 /tmp、/var/tmp、/dev/shm（本身或底下）：連結也算。"""
    r = os.path.realpath(p)
    for d in ("/tmp", "/var/tmp", "/dev/shm"):
        for x in {d, os.path.realpath(d)}:
            if r == x or r.startswith(x.rstrip("/") + "/"):
                return True
    return False


def work_dir(result):
    """暫存區（複製的檔案、秘密清單、解壓的 .xz）：不放 --out（可能是保存用的 NAS），放結果資料夾旁邊（權限同結果），
    EVIDENCE_WORK_DIR 可指定；都不能寫時用 XDG_RUNTIME_DIR。mkdtemp 建成 0700。"""
    for d in (os.environ.get("EVIDENCE_WORK_DIR"), str(result.parent), os.environ.get("XDG_RUNTIME_DIR")):
        if d:
            try:
                return Path(tempfile.mkdtemp(prefix=".evidence-work.", dir=d))
            except OSError:
                continue
    raise Fail("找不到可以寫的暫存區（結果資料夾的上層、EVIDENCE_WORK_DIR、XDG_RUNTIME_DIR）")


def worst(sts):
    return max(sts, key=lambda s: RANK.get(s, 1), default="OK")


def create(result, out, project=None, name=None, time=None, secrets_file=None, pilot_env=None, allow_tmp=False, limits=None):
    """回傳 (狀態, 說明, manifest 或 None)。FAIL 時 --out 裡不留任何東西（暫存區也刪）。"""
    limits = dict(LIMITS, **(limits or {}))
    result = Path(result).resolve()
    if not result.is_dir():
        raise Fail(f"--result 不是資料夾：{result}")
    out = Path(out).absolute()
    if not allow_tmp and in_shared_tmp(out):
        raise Fail(f"--out 不要放在共用的暫存區（{out}）：證據包有產品資料")
    if project is not None and not Path(project).is_dir():
        raise Fail(f"--project 不是資料夾：{project}")
    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    work = work_dir(result)
    try:
        stage = work / "stage"
        stage.mkdir(mode=0o700)
        return _create(result, out, work, stage, project, name, time, secrets_file, pilot_env, limits)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _create(result, out, work, stage, project, name, time, secrets_file, pilot_env, limits):
    sg = Stager(stage, limits)
    checks = []

    def check(item, st, detail):
        checks.append({"item": item, "status": st, "detail": detail})

    rfd = os.open(result, os.O_RDONLY | os.O_DIRECTORY)
    try:
        targets = []   # (名稱, 包內 sca-scan 路徑, 包內 CRA 專案路徑或 None)
        flash = (result / "list.json").is_file() or any(
            not e.is_symlink() and e.is_dir() and (Path(e.path) / "scan" / "status.tsv").is_file() for e in os.scandir(result))
        if flash:
            layout = "flash-package"
            for rel in FLASH_TOP:
                sg.add(rfd, rel, rel)
            for e in sorted(os.scandir(result), key=lambda e: e.name):
                if not SAFE_NAME.match(e.name):
                    continue
                if e.is_symlink():
                    if (Path(e.path) / "scan").exists():
                        sg.skipped.append({"path": e.name, "reason": "符號連結，不跟隨"})
                    continue
                if not e.is_dir() or not (Path(e.path) / "scan" / "status.tsv").exists():
                    continue
                v = e.name
                sg.add_scan(rfd, f"{v}/scan", f"{v}/scan")
                sg.add_project(rfd, f"{v}/cra-project", f"{v}/cra-project")
                for rel in FLASH_TARGET:
                    sg.add(rfd, f"{v}/{rel}", f"{v}/{rel}")
                sg.add_board(rfd, f"{v}/board-test", f"{v}/board-test")
                targets.append((v, f"{v}/scan", f"{v}/cra-project"))
        elif (result / "status.tsv").is_file() and (result / "meta.json").is_file():
            layout = "sca-scan"
            sg.add_scan(rfd, "", "scan")
            targets.append(("scan", "scan", None))
        else:
            raise Fail(f"{result} 不是 scan-flash-package 的結果（list.json、<rootfs>/scan/status.tsv）也不是 sca-scan 的輸出（status.tsv、meta.json）")
    finally:
        os.close(rfd)
    if layout == "sca-scan" and project is not None:
        pfd = os.open(Path(project).resolve(), os.O_RDONLY | os.O_DIRECTORY)
        try:
            sg.add_project(pfd, "", "cra-project")
        finally:
            os.close(pfd)
        targets = [("scan", "scan", "cra-project")]
    if not targets:
        raise Fail("結果資料夾裡沒有任何 <rootfs>/scan/status.tsv（沒有可以凍結的掃描）")

    top = read_status(stage, "status.tsv") if layout == "flash-package" else None
    tinfo, products = [], []
    for v, sd, pd in targets:
        tools, data, scan, meta = tools_of(stage, sd, limits["file"])
        st = read_status(stage, f"{sd}/status.tsv")
        prod, cra, have_cfg = cra_of(stage, pd, limits["file"]) if pd else ({"name": None, "version": None}, None, False)
        if prod["version"] and layout == "flash-package" and prod["version"].endswith(f" ({v})"):
            prod["version"] = prod["version"][:-len(f" ({v})")]
        products.append(prod if prod["name"] or prod["version"] else
                        {"name": text(meta.get("name")), "version": text(meta.get("version")),
                         "from": "meta.json"})
        tinfo.append({"name": v, "scan": sd, "cra_project": pd, "product": prod, "scan_meta": scan, "tools": tools, "data": data,
                      "scan_status": status_summary(st), "cra": cra})
        lab = "" if layout == "sca-scan" else f"{v}："
        if not any(f"{sd}/sbom/sbom.cdx.json{x}" in sg.files for x in ("", ".xz")):
            check(f"sbom:{v}", "ATTENTION", f"{lab}沒有 sbom/sbom.cdx.json")
        has_dt = any(f"{sd}/dt/findings.json{x}" in sg.files for x in ("", ".xz"))
        tmiss = [k for k, ok in (("meta.json", f"{sd}/meta.json" in sg.files), ("Grype 版本", tools["grype"] != UNKNOWN),
                                 ("Grype DB 建立時間", data["grype_db"]["built"] != UNKNOWN),
                                 ("DT 版本", not has_dt or tools["dependency_track"] != UNKNOWN)) if not ok]
        if tmiss:
            check(f"tools:{v}", "ATTENTION", f"{lab}工具或資料庫版本讀不到：{'、'.join(tmiss)}")
        if not any(f"{sd}/{r}{x}" in sg.files for r in ("dt/findings.json", "scan/grype.json") for x in ("", ".xz")):
            check(f"findings:{v}", "ATTENTION", f"{lab}沒有 DT findings 也沒有 Grype 結果")
        if st and any(s == "FAIL" for s, _ in st.values()):
            check(f"scan-status:{v}", "ATTENTION", f"{lab}掃描有 FAIL：" + "、".join(k for k, (s, _) in st.items() if s == "FAIL")[:300])
        if pd is None:
            check(f"cra:{v}", "ATTENTION", "沒有給 --project：證據包沒有 CRA 設定與文件")
            continue
        if not have_cfg:
            check(f"cra-config:{v}", "ATTENTION", f"{lab}沒有 CRA/Config/config.json")
        if cra is None:
            check(f"cra-documents:{v}", "ATTENTION", f"{lab}沒有 CRA/Reports/summary.json（CRA 文件沒有產生）")
        elif cra["status"] != "OK":
            bad = [f"{k} {s}" for k, s in cra["documents"].items() if s != "OK"]
            check(f"cra-documents:{v}", "ATTENTION", f"{lab}CRA 文件 {cra['status']}：{'、'.join(bad)[:300]}")
        miss = [n for n in ("vex.cdx.json", "vex.openvex.json", "sbom.cdx.json") if f"{pd}/CRA/Reports/{n}" not in sg.files]
        if miss:
            check(f"cra-reports:{v}", "ATTENTION", f"{lab}CRA/Reports 沒有 {'、'.join(miss)}")
    flash_pkg = flash_identity(stage, top) if layout == "flash-package" else None
    scommit, sinfo = scan_commit(stage, layout)
    if layout == "flash-package" and scommit == UNKNOWN:
        check("scan-commit", "ATTENTION", "掃描當時的 sca-center commit 不明（沒有 provenance.json）")
    elif scommit != UNKNOWN and (sinfo.get("dirty") is True or (sinfo.get("from") == "git" and sinfo.get("dirty") is None)):
        check("scan-commit", "ATTENTION", "掃描時的程式有未提交的改動（或改動狀態不明）：scan_commit 不等於實際執行的程式")
    if flash_pkg and flash_pkg["type"] == "archive" and flash_pkg["sha256"] == UNKNOWN:
        check("flash-package-sha256", "ATTENTION", "刷機包的 sha256 不明（沒有 provenance.json，或和 list.json 對不上）")
    if flash_pkg and flash_pkg["md5_check"] != "OK":
        check("flash-package-md5", "ATTENTION", f"刷機包的 md5 沒有核對（A-md5 {flash_pkg['md5_check']}）")
    if sg.skipped:
        check("skipped", "ATTENTION", f"{len(sg.skipped)} 個檔案沒有收：" + "；".join(f"{s['path']}（{s['reason']}）" for s in sg.skipped[:5]))

    named = [p for p in products if p.get("name") or p.get("version")]
    product = {"name": named[0].get("name") if named else None, "version": named[0].get("version") if named else None}
    if len({(p.get("name"), p.get("version")) for p in named}) > 1:
        check("product", "ATTENTION", "各 rootfs 的產品名稱或版本不同：" + "、".join(f"{p.get('name')} {p.get('version')}" for p in named)[:300])
    frozen = parse_time(time) if time else (sg.mtime or 0)
    stamp = datetime.datetime.fromtimestamp(frozen, datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = name or f"evidence-{slug(product['name'])}-{slug(product['version'])}-{stamp}"
    if not SAFE_NAME.match(base) or len(base) > 120:
        raise Fail(f"--name 只能用英數字與 . _ -（最多 120 字）：{clean(base, 80)}")

    vals, short = load_secrets(secrets_file, pilot_env)
    if not vals:
        check("secret-list", "ATTENTION", "沒有秘密清單（PILOT_ENV 讀不到或沒有金鑰、沒有 --secrets-file）：只做了私鑰與 token 的樣式檢查")
    if short:
        check("secret-list-short", "ATTENTION", f"秘密清單有 {short} 個值短於 {MIN_SECRET} 個字元，沒有拿來比對")
    manifest = {
        "schema": SCHEMA, "bundle": base, "layout": layout, "frozen_utc": now_iso(frozen),
        "frozen_utc_from": "--time" if time else "收進來的檔案最新的 mtime（同樣的輸入再做一次結果相同）",
        "source_result": clean(result.name), "product": product, "flash_package": flash_pkg,
        "sca_center": {"bundle_tool_commit": sca_center_commit(), "scan_commit": scommit, **sinfo},
        "targets": tinfo, "not_included": NOT_INCLUDED, "skipped": sg.skipped,
        "limits": limits, "checks": checks, "status": worst(c["status"] for c in checks),
        "files": [{"path": k, **sg.files[k]} for k in sorted(sg.files)],
    }
    mbytes = (json.dumps(manifest, ensure_ascii=False, indent=1, sort_keys=True) + "\n").encode("utf-8")
    (stage / "manifest.json").write_bytes(mbytes)
    # 秘密：暫存區（含 manifest、.xz 解壓後）在寫任何東西到 --out 之前
    hits = secret_hits(work, stage, vals, limits["file"], limits["total"], sg.total)
    if hits:
        return "FAIL", f"暫存的檔案裡有秘密（{len(hits)} 個：{'、'.join(hits[:5])}）：沒有寫出證據包", None

    arch = out / f"{base}.tar.xz"
    tmp = work / "bundle.tar.xz"
    with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as f:
        write_tar(f, base, stage, list(sg.files) + ["manifest.json"], frozen)
    sha = sha256_file(tmp)
    side = {out / f"{base}.manifest.json": mbytes, out / f"{base}.tar.xz.sha256": f"{sha}  {base}.tar.xz\n".encode()}
    existed = arch.exists() or arch.is_symlink()
    same_file = lambda p, b: p.is_file() and not p.is_symlink() and p.read_bytes() == b  # noqa: E731
    reused = []
    if existed:
        same = (arch.is_file() and not arch.is_symlink() and sha256_file(arch) == sha
                and all(same_file(p, b) for p, b in side.items()))
        if not same:
            return "FAIL", f"{out} 已經有 {base} 的證據包（或旁邊的檔案）而且內容不同：不覆寫已凍結的證據（換 --out 或 --name）", None
    else:
        # 沒有 .tar.xz、卻有旁邊的檔：上一次在放封存檔之前中斷留下的。內容和這次相同就沿用；不同就停下來寫明是哪個檔
        left = [p for p in side if p.exists() or p.is_symlink()]
        bad = [p.name for p in left if not same_file(p, side[p])]
        if bad:
            return "FAIL", (f"{out} 有 {'、'.join(bad)}，但沒有 {arch.name}：上一次沒寫完留下的，內容和這次不同。"
                            "確認不是正在執行的另一次之後刪掉再重做"), None
        reused = [p.name for p in left]
        items = []
        for p, b in side.items():
            if p in left:
                continue
            t = work / p.name
            t.write_bytes(b)
            items.append((p, t))
        publish(out, items + [(arch, tmp)])     # 封存檔最後：看到 .tar.xz 就表示三個檔都在
    size = arch.stat().st_size
    st = manifest["status"]
    detail = (f"{arch}：{len(sg.files)} 個檔案（{sg.total} 位元組，壓縮後 {size}），sha256 {sha[:16]}…"
              + ("；已經存在、內容相同，沒有重寫" if existed else "")
              + (f"；沿用上一次沒寫完留下的 {'、'.join(reused)}（內容相同）" if reused else "")
              + ("；" + "；".join(c["detail"] for c in checks if c["status"] != "OK") if st != "OK" else ""))
    return st, detail[:1500], manifest


# ---------- verify ----------

def verify(archive, limits=None, expect_sha256=None):
    """回傳 (OK｜ATTENTION｜FAIL, 說明)。expect_sha256：另外保存的封存檔 sha256（可信的錨點；旁邊的 .sha256 可以和封存檔一起被換掉）。"""
    limits = dict(LIMITS, **(limits or {}))
    archive = Path(archive)
    got, extra_bad, manifest_raw, bases = {}, [], None, set()
    try:
        with tarfile.open(archive, "r:xz") as t:
            n = 0
            for m in t:
                n += 1
                if n > limits["files"] + 10:
                    return "FAIL", f"成員超過 {limits['files']} 個"
                parts = m.name.split("/")
                if len(parts) < 2 or any(p in ("", ".", "..") for p in parts) or m.name.startswith("/"):
                    extra_bad.append(f"{clean(m.name, 80)}（路徑不合法）")
                    continue
                bases.add(parts[0])
                rel = "/".join(parts[1:])
                if not m.isreg():
                    extra_bad.append(f"{clean(m.name, 80)}（不是一般檔案）")
                    continue
                if m.size > limits["file"] + 1:
                    extra_bad.append(f"{clean(rel, 80)}（太大）")
                    continue
                f = t.extractfile(m)
                if rel == "manifest.json":
                    if manifest_raw is not None:
                        extra_bad.append("manifest.json（重複）")
                    manifest_raw = f.read(64 << 20)
                    continue
                h, size = hashlib.sha256(), 0
                for b in iter(lambda: f.read(CHUNK), b""):
                    h.update(b)
                    size += len(b)
                if rel in got:
                    extra_bad.append(f"{clean(rel, 80)}（重複）")
                got[rel] = {"bytes": size, "sha256": h.hexdigest()}
    except (tarfile.TarError, lzma.LZMAError, EOFError, OSError) as e:
        return "FAIL", f"讀不了 {archive.name}（{type(e).__name__}）"
    if manifest_raw is None:
        return "FAIL", "包裡沒有 manifest.json"
    if "manifest.json（重複）" in extra_bad:
        return "FAIL", "包裡有兩個以上的 manifest.json（重複），不知道哪一個是真的"
    try:
        man = json.loads(manifest_raw)
        want = {x["path"]: {"bytes": x["bytes"], "sha256": x["sha256"]} for x in man["files"]}
        base = man["bundle"]
    except (ValueError, KeyError, TypeError):
        return "FAIL", "manifest.json 格式不對"
    if man.get("schema") != SCHEMA:
        return "FAIL", f"manifest 的 schema 不是 {SCHEMA}"
    probs = []
    if bases != {base}:
        probs.append(f"最上層資料夾不是 {clean(base, 80)}（{'、'.join(sorted(clean(b, 40) for b in bases))[:200]}）")
    changed = sorted(k for k in want if k in got and got[k] != want[k])
    missing = sorted(k for k in want if k not in got)
    extra = sorted(k for k in got if k not in want) + extra_bad
    for lab, xs in (("內容不同", changed), ("缺少", missing), ("多出", extra)):
        if xs:
            probs.append(f"{lab} {len(xs)}：{'、'.join(xs[:5])}")
    side, absent = [], []
    if expect_sha256 is not None:
        if not SHA256_RE.fullmatch(expect_sha256):
            return "FAIL", "--sha256 要是 64 個十六進位字元"
        if sha256_file(archive) != expect_sha256.lower():
            probs.append("封存檔的 sha256 與 --sha256 不符")
        else:
            side.append("--sha256")
    mp = archive.with_name(archive.name[:-len(".tar.xz")] + ".manifest.json") if archive.name.endswith(".tar.xz") else None
    if mp and mp.is_file():
        side.append("manifest")
        if mp.read_bytes() != manifest_raw:
            probs.append(f"{mp.name} 與包內的 manifest.json 不同")
    else:
        absent.append(".manifest.json")
    sp = archive.with_name(archive.name + ".sha256")
    if sp.is_file():
        side.append("sha256")
        w = sp.read_text(encoding="utf-8", errors="replace").split()
        if not w or w[0] != sha256_file(archive):
            probs.append(f"{sp.name} 與證據包的 sha256 不符")
    else:
        absent.append(".sha256")
    if probs:
        return "FAIL", "；".join(probs)[:1500]
    msg = (f"{len(want)} 個檔案的大小與 sha256 都和 manifest 相符（{base}，凍結時間 {clean(man.get('frozen_utc'))}）"
           + (f"；{'、'.join(side)} 也相符" if side else ""))
    if absent and expect_sha256 is None:
        return "ATTENTION", msg + f"；旁邊沒有 {'、'.join(absent)}，也沒有給 --sha256：只核對了包內（包內的 manifest 可以和檔案一起被改）"
    return "OK", msg


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        print(f"{self.prog}: 參數錯誤：{message}", file=sys.stderr)
        sys.exit(64)


def main(argv=None):
    ap = Parser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create")
    c.add_argument("--result", required=True)
    c.add_argument("--project")
    c.add_argument("--out", required=True)
    c.add_argument("--name")
    c.add_argument("--time")
    c.add_argument("--secrets-file")
    v = sub.add_parser("verify")
    v.add_argument("archive")
    v.add_argument("--sha256", help="另外保存的封存檔 sha256（可信的錨點）")
    a = ap.parse_args(argv)
    if a.cmd == "verify" and a.sha256 is not None and not SHA256_RE.fullmatch(a.sha256):
        ap.error("--sha256 要是 64 個十六進位字元（空的或格式不對時不能當作錨點）")
    if a.cmd == "verify":
        try:
            st, detail = verify(a.archive, expect_sha256=a.sha256)
        except Exception as e:   # noqa: BLE001  不可信的封存檔：任何例外都是 FAIL
            st, detail = "FAIL", f"{type(e).__name__}：{clean(e, 300)}"
        print(f"EVIDENCE-VERIFY\t{st}\t{detail}")
        return {"OK": 0, "ATTENTION": 2}.get(st, 1)
    pe = os.environ.get("PILOT_ENV") or str(ROOT / "deploy" / "pilot" / "state" / "pilot.env")
    try:
        st, detail, _ = create(a.result, a.out, project=a.project, name=a.name, time=a.time, secrets_file=a.secrets_file,
                               pilot_env=pe, allow_tmp=os.environ.get("EVIDENCE_ALLOW_TMP_OUT") == "1")
    except Fail as e:
        st, detail = "FAIL", str(e)
    except Exception as e:   # noqa: BLE001  不可信的輸入：任何例外都是 FAIL（create 失敗時不寫任何東西）
        st, detail = "FAIL", f"{type(e).__name__}：{clean(e, 300)}"
    print(f"EVIDENCE\t{st}\t{detail}")
    return {"OK": 0, "ATTENTION": 2}.get(st, 1)


if __name__ == "__main__":
    sys.exit(main())
