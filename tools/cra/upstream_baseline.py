#!/usr/bin/env python3
"""與 NVIDIA 原版（Jetson Linux BSP、public_sources）逐檔比對：證明哪些檔案是 NVIDIA 原版、哪些是 RD 改過的。

為什麼要做：NVIDIA 的安全公告（security bulletin）只對「NVIDIA 原版」的檔案完整適用。
產品用 NVIDIA BSP 加公開原始碼再加 RD 修改，要能指出哪些檔案和 NVIDIA 發行版逐位元組相同（公告直接套用），
哪些是 RD 改過或新增的（要另外判斷）。本工具只做「是不是同一個檔案」的比對，不證明有沒有漏洞。

兩個子命令（只用 Python 標準函式庫；用 python3 -I 執行；唯讀；tar 用串流讀取；不執行任何內容）：

  artifacts --ours <刷機包資料夾或 .tbz2> --upstream <NVIDIA BSP .tbz2 或解開的 Linux_for_Tegra 資料夾>
            --out <資料夾> [--exclude rootfs/ ...]
      逐檔 sha256，兩邊各去掉最上層資料夾（product-aOrinNanoFlashOSTool/ 對 Linux_for_Tegra/）後用相對路徑對齊。
      分類 same／modified／ours_only／upstream_only；依最上層資料夾（bootloader、kernel、nv_tegra、tools…）分組計數。
      NVIDIA 閉源開機韌體（與報告 SBOM 表共用 bootloader_coverage.classify／VENDOR_PATTERNS，只看 bootloader/ 底下第一層的檔名）另外列出 same 或不同。
      輸出 upstream-baseline-artifacts.json／.md；stdout 一行 `A0-artifacts<TAB>狀態<TAB>說明`。
      OK＝閉源韌體全部與 NVIDIA 相同；ATTENTION＝有閉源韌體 modified／ours_only；GAP＝upstream 缺或讀不了、
      或兩邊都找不到任何閉源韌體（無法判斷）；FAIL＝程式錯誤。

  source --ours <我們的 sources 資料夾> --upstream <NVIDIA public_sources.tbz2 或解開的資料夾>
         --out <資料夾> [--component 名稱=ours子路徑:upstream成員[:加上的前綴] ...]
      public_sources.tbz2 裡是一個一個元件的 tarball（kernel_src.tbz2、kernel_oot_modules_src.tbz2 …）。
      預設對應表 DEFAULT_COMPONENTS（Jetson r39）：tarball 裡的路徑本來就是「sources/ 底下的相對路徑」
      （例如 kernel/kernel-noble/…、nvidia-oot/…），ours 子路徑只是限定比對範圍。ours 子路徑 "." 表示
      「只比 upstream 成員裡出現的最上層資料夾」（kernel_oot_modules_src 同時含 nvgpu、nvidia-oot、hwpm、hardware…）。
      找不到對應的元件標 NOT_ASSESSED（不是 same）；public_sources 裡沒有對應我們目錄的成員、我們 sources/ 裡
      沒有被任何元件涵蓋的資料夾也都列出。
      編譯產物（IGNORE_* 常數）只在「只存在一邊」時忽略（數量記錄在 json）；兩邊都有的路徑一律比對，不會因為檔名像產物而被藏起來。
      輸出 upstream-baseline-source.json／.md；stdout 一行 `A0-source<TAB>狀態<TAB>說明`。
      OK＝每個元件都比過且沒有 modified／ours_only；ATTENTION＝有 modified／ours_only 或有 NOT_ASSESSED 元件；
      GAP＝upstream 缺或讀不了；FAIL＝程式錯誤。

安全：tar 成員只當資料讀；符號連結、硬連結、裝置檔一律不讀內容、記進 rejected；絕對路徑與含 .. 的路徑拒絕；
資料夾走訪不跟隨符號連結。

後續（還沒做）：modified_files(json) 回傳每個元件 RD 改過的檔案集合，之後的工具可用它標記
「CVE 的修補 commit 動到的檔案是否也是 RD 改過的檔案」（修補不能直接套用、要人工判斷）。
"""
from __future__ import annotations

import argparse
import bz2
import fnmatch
import hashlib
import json
import lzma
import os
import posixpath
import re
import stat
import sys
import tarfile
import zlib
from datetime import datetime, timezone
from pathlib import Path

TOOL = "upstream_baseline"
SCHEMA_ARTIFACTS = "sca-center-upstream-baseline-artifacts/1"
SCHEMA_SOURCE = "sca-center-upstream-baseline-source/1"
CLASSES = ("same", "modified", "ours_only", "upstream_only")
CHUNK = 1 << 20
MAX_OUT = 16 << 20      # DecompReader 每批解壓輸出上限（解壓炸彈：一個壓縮塊可以解出幾百 MB）
MD_LIST_CAP = 60

# ---------------------------------------------------------------- 閉源開機韌體
# 分類與報告的 SBOM 表（bootloader_coverage.py 的 "Vendor closed-source firmware"）共用同一份：bootloader_coverage.classify()／VENDOR_PATTERNS。
# 只看 bootloader/ 第一層的檔名；UEFI（uefi_*.bin）、BOOTAA64.efi、dtb／bct 資料檔、.deb／.pkg 不算閉源韌體。
_BC = None


def bc_module():
    global _BC
    if _BC is None:
        import importlib.util
        p = Path(__file__).resolve().with_name("bootloader_coverage.py")
        spec = importlib.util.spec_from_file_location("sca_center_bootloader_coverage_ub", p)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        _BC = m
    return _BC


RD_BUILT_BINARIES = {"l4t_initrd.img", "bootaa64.efi"}      # RD 自己重建的檔案，與原版不同是預期的


def _bl_first_level(rel: str):
    d, _, b = rel.partition("/")
    return b if d.lower() == "bootloader" and b and "/" not in b else None


def closed_family(rel: str):
    """bootloader/<檔名>（只第一層）被 bootloader_coverage.classify 判成 vendor_firmware 時回傳標籤，否則 None。"""
    if _bl_first_level(rel) is None:
        return None
    cls, lab = bc_module().classify({"type": "file", "path": rel})
    return lab if cls == "vendor_firmware" else None


def closed_patterns():
    return [{"regex": p, "label": lab} for p, lab in bc_module().VENDOR_PATTERNS]


def other_binary(rel: str):
    """bootloader/ 第一層、bootloader_coverage.classify 判成 unclassified（認不得的韌體型檔案）：回傳 True。"""
    if _bl_first_level(rel) is None:
        return False
    return bc_module().classify({"type": "file", "path": rel})[0] == "unclassified"


# ---------------------------------------------------------------- 編譯產物忽略表（source 子命令；兩邊都套用）
# 原則：忽略表只隱藏「只存在一邊」的檔案；同一路徑兩邊都有的檔案一律比對，不會因為檔名像產物就被藏起來
# （避免漏掉 RD 真的改過的檔案）。被忽略的檔案數量記在 json 的 ignored。
IGNORE_DIRS = {"generated", "__pycache__", ".git", ".tmp_versions", "nvidia-conftest", "_out", "test_fortify"}
IGNORE_NAME_GLOBS = [
    "*.o", "*.ko", "*.a", "*.so", "*.so.*", "*.elf", "*.pyc", "*.log",
    "*.cmd", ".*.cmd", "*.mod", "*.mod.c", "*.mod.o", "*.o.d", ".*.o.d", ".*.d",
    ".tmp*", "*.tmp", "modules.order", "Module.symvers", "modules.builtin", "modules.builtin.*", "*.symtypes",
    "*.dtb", "*.dtbo", "vmlinux", "vmlinux.*", "System.map", ".version", "compile_commands.json", ".config.old",
    "*.gcno",
    # kernel 編譯時由工具產生的原始碼／中間檔
    ".config", ".vmlinux*", ".checked-*", "config_data", "config_data.gz", "*.asn1.c", "*.asn1.h", "*.lex.c", "*.tab.c", "*.tab.h",
    "*.lds", "*.s", "utsversion-tmp.h", "nv_compiler.h", "initramfs_data.cpio", "initramfs_inc_data",
]
# 路徑中含這些連續片段也算產物（kernel 的 include/config/、nvidia 驅動 conftest 的產生物）
IGNORE_PATH_PARTS = ("/include/config/", "/kernel-open/conftest/")
IGNORE_REL_PREFIXES = ()
# 這些原因的被忽略路徑逐一列在 json（其他原因只記數量，*.o 等太多）；這幾類可能含手寫的檔案，要讓人看得到
LIST_IGNORED_REASONS = {"dir:generated", "name:*.lds", "name:*.s", "name:*.tab.c", "name:*.tab.h", "name:*.lex.c"}


def note_ignore(counts: dict, paths: dict, why: str, rel: str):
    counts[why] = counts.get(why, 0) + 1
    if why in LIST_IGNORED_REASONS:
        paths.setdefault(why, []).append(rel)


def ignore_reason(rel: str):
    """相對路徑是編譯產物就回傳原因字串（用於計數），否則 None。"""
    parts = rel.split("/")
    for p in parts[:-1]:
        if p in IGNORE_DIRS:
            return f"dir:{p}"
    base = parts[-1]
    for pp in IGNORE_PATH_PARTS:
        if pp in "/" + rel:
            return f"path:{pp.strip('/')}"
    for g in IGNORE_NAME_GLOBS:
        if fnmatch.fnmatchcase(base, g):
            return f"name:{g}"
    for pre in IGNORE_REL_PREFIXES:
        if rel.startswith(pre):
            return f"prefix:{pre}"
    return None


# ---------------------------------------------------------------- 基本工具
class Gap(Exception):
    """輸入缺少或讀不了（狀態 GAP，不是程式錯誤）。"""


def now_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def norm_rel(name: str):
    """tar 成員名稱正規化成相對 POSIX 路徑；絕對路徑、含 .. 回傳 None（拒絕）；空或 . 回傳 ""。"""
    n = name
    while n.startswith("./"):
        n = n[2:]
    if n.startswith("/"):
        return None
    n = posixpath.normpath(n) if n else ""
    if n in ("", "."):
        return ""
    if n == ".." or n.startswith("../") or "/../" in n:
        return None
    return n


def sha256_fileobj(f):
    h = hashlib.sha256()
    for c in iter(lambda: f.read(CHUNK), b""):
        h.update(c)
    return h.hexdigest()


def sha256_path(p):
    with open(p, "rb") as f:
        return sha256_fileobj(f)


class HashReader:
    """包住檔案物件，邊讀邊算整個檔案的 sha256（給 tarfile 串流模式用）。"""

    def __init__(self, f):
        self.f, self.h, self.n = f, hashlib.sha256(), 0

    def read(self, n=-1):
        b = self.f.read(n)
        self.h.update(b)
        self.n += len(b)
        return b

    def drain(self):
        while self.read(CHUNK):
            pass


class DecompReader:
    """壓縮串流（bz2／gz／xz／未壓縮，bz2 與 gz 可多段）解壓成連續位元組；記錄解壓後總長、最後一個非零位元組的位置，
    以及壓縮串流是否完整結束（用來偵測被截斷的封存檔）。"""

    def __init__(self, f):
        self.f, self.total, self.last_nz, self.complete, self.buf, self.pos = f, 0, 0, False, b"", 0
        head = f.read(CHUNK)
        self.pending = head
        if head[:3] == b"BZh":
            self.kind, self.d = "bz2", bz2.BZ2Decompressor()
        elif head[:2] == b"\x1f\x8b":
            self.kind, self.d = "gz", zlib.decompressobj(31)
        elif head[:6] == b"\xfd7zXZ\x00":
            self.kind, self.d = "xz", lzma.LZMADecompressor()
        else:
            self.kind, self.d = "raw", None
        self.done = False

    def _backlog(self):
        """bz2／xz 的解壓器內部還有已輸入、還沒吐完的資料（max_length 擋住了）。"""
        d = self.d
        return d is not None and self.kind in ("bz2", "xz") and not d.eof and not d.needs_input

    def _more(self):
        """解出下一批位元組（可能是空的；每次最多約 MAX_OUT，擋解壓炸彈）；串流結束時 done=True。"""
        if self.done:
            return b""
        raw, self.pending = self.pending, b""
        if not raw and not self._backlog():
            raw = self.f.read(CHUNK)
            if self.kind == "raw":
                if not raw:
                    self.done = self.complete = True
                return raw
            if not raw:
                self.done = True          # 壓縮串流還沒結束就沒資料了：complete 維持 False（若上一段剛好結束則在下面設定）
                return b""
        elif self.kind == "raw":
            return raw
        out = b""
        while raw or self._backlog():
            if len(out) >= MAX_OUT:
                break
            if self.d is None:
                if self.kind == "bz2" and raw[:3] == b"BZh":
                    self.d = bz2.BZ2Decompressor()
                elif self.kind == "gz" and raw[:2] == b"\x1f\x8b":
                    self.d = zlib.decompressobj(31)
                elif raw.strip(b"\x00") == b"":
                    raw = b""
                    break
                else:
                    raise tarfile.ReadError("壓縮串流結尾有無法辨識的資料")
            out += self.d.decompress(raw, MAX_OUT - len(out))
            if self.kind == "gz":
                eof = self.d.eof
                raw = self.d.unused_data if eof else self.d.unconsumed_tail
            else:
                eof = self.d.eof
                raw = self.d.unused_data if eof else b""
            if eof:
                self.d = None
                self.complete = True
                if not raw:
                    break
                if self.kind == "xz":
                    raise tarfile.ReadError("xz 串流後面還有資料")
            else:
                self.complete = False
        self.pending = raw          # 因為輸出上限停下來時，剩下的輸入留到下一次
        return out

    def read(self, n=-1):
        want = n if n is not None and n >= 0 else 1 << 62
        # buf 是 bytes，pos 是讀到哪裡：不再每次讀取都複製剩下的緩衝（高壓縮比的成員解出來很大，
        # 舊寫法每讀 16 KB 就複製一次剩下的全部 → 平方時間）。每批 _more 最多 MAX_OUT，所以併接的成本有上限
        while len(self.buf) - self.pos < want and not self.done:
            b = self._more()
            if b:
                self.buf = self.buf[self.pos:] + b if self.pos else self.buf + b
                self.pos = 0
        out = self.buf[self.pos:self.pos + want]
        self.pos += len(out)
        if self.pos >= len(self.buf):
            self.buf, self.pos = b"", 0
        if out:
            stripped = out.rstrip(b"\x00")
            if stripped:
                self.last_nz = self.total + len(stripped)
            self.total += len(out)
        return out

    def drain(self):
        while self.read(CHUNK):
            pass


def iter_tar(fileobj, want=None):
    """串流讀 tar，逐一產生 ('file', 相對路徑, 大小, sha256) 或 ('reject', 名稱, 原因, None)。
    want(相對路徑) 回傳 False 的一般檔案不讀內容（產生 ('skip', 路徑, 大小, None)）。
    讀完會檢查封存檔是否完整（壓縮串流有結束、tar 結尾有兩個全零區塊）；不完整丟 tarfile.ReadError。"""
    rd = DecompReader(fileobj)
    with tarfile.open(fileobj=rd, mode="r|") as t:
        for m in t:
            if m.isdir():
                continue
            if m.issym() or m.islnk() or m.isdev() or m.isfifo() or not m.isfile():
                kind = "symlink" if m.issym() else "hardlink" if m.islnk() else "special"
                yield ("reject", m.name, kind, m.linkname if (m.issym() or m.islnk()) else None)
                continue
            rel = norm_rel(m.name)
            if rel is None:
                yield ("reject", m.name, "unsafe-path", None)
                continue
            if rel == "":
                continue
            if want is not None and not want(rel):
                yield ("skip", rel, m.size, None)
                continue
            f = t.extractfile(m)
            yield ("file", rel, m.size, sha256_fileobj(f))
        end = t.offset
    rd.drain()
    check_complete(rd, end)


def check_complete(rd, end):
    if not rd.complete:
        raise tarfile.ReadError("封存檔被截斷（壓縮串流沒有結束）")
    if rd.total < end + 1024 or rd.last_nz > end:
        raise tarfile.ReadError("封存檔被截斷（tar 結尾缺少結束區塊）")


def walk_dir(root: Path, want=None, prune=None):
    """資料夾走訪（不跟隨符號連結）。產生同 iter_tar 的四元組。prune(相對資料夾路徑)==True 的資料夾不進入。"""
    root = Path(root)
    for dp, dns, fns in os.walk(root, followlinks=False):
        reld = os.path.relpath(dp, root)
        reld = "" if reld == "." else reld.replace(os.sep, "/")
        keep = []
        for d in sorted(dns):
            rd = f"{reld}/{d}" if reld else d
            if os.path.islink(os.path.join(dp, d)):
                yield ("reject", rd, "symlink", os.readlink(os.path.join(dp, d)))
            elif prune is not None and prune(rd):
                continue
            else:
                keep.append(d)
        dns[:] = keep
        for fn in sorted(fns):
            fp = os.path.join(dp, fn)
            rel = f"{reld}/{fn}" if reld else fn
            st = os.lstat(fp)
            if stat.S_ISLNK(st.st_mode):
                yield ("reject", rel, "symlink", os.readlink(fp))
            elif not stat.S_ISREG(st.st_mode):
                yield ("reject", rel, "special", None)
            elif want is not None and not want(rel):
                yield ("skip", rel, st.st_size, None)
            else:
                yield ("file", rel, st.st_size, sha256_path(fp))


def top_of(rel: str):
    return rel.split("/", 1)[0] if "/" in rel else "(top)"


def open_archive(path: Path):
    return HashReader(open(path, "rb"))


# ---------------------------------------------------------------- artifacts
def _find_l4t_root(p: Path):
    if (p / "bootloader").is_dir():
        return p
    subs = [d for d in sorted(p.iterdir()) if d.is_dir() and not d.is_symlink() and (d / "bootloader").is_dir()]
    return subs[0] if len(subs) == 1 else p


def add_file(files: dict, dups: set, rel: str, val):
    """同一個（正規化後的）路徑出現第二次：不採用任何一份，記成重複（之後不會被判成 same）。"""
    if rel in files or rel in dups:
        dups.add(rel)
        files.pop(rel, None)
    else:
        files[rel] = val


NO_STRIP_TOPS = {"bootloader", "kernel", "rootfs", "tools", "nv_tegra"}


def _strip_top(files: dict, rejected: list, dups: set):
    allp = list(files) + list(dups)
    tops = {k.split("/", 1)[0] for k in allp if "/" in k}
    if len(tops) == 1 and not (tops & NO_STRIP_TOPS):
        top = next(iter(tops))
        dups = {k[len(top) + 1:] if k.startswith(top + "/") else k for k in dups}
        files = {(k[len(top) + 1:] if k.startswith(top + "/") else k): v for k, v in files.items()}
        rejected = [dict(r, name=r["name"].split("/", 1)[1] if r["name"].startswith(top + "/") else r["name"]) for r in rejected]
        return files, rejected, dups, top
    return files, rejected, dups, None


def load_artifact_tree(spec: str, role: str, excludes):
    """回傳 dict(files={相對路徑:(sha,大小)}, rejected=[...], identity={...})。讀不了丟 Gap。"""
    p = Path(spec)
    if not p.exists():
        raise Gap(f"{role} 不存在：{spec}")
    files, rejected, ident, dups = {}, [], {"path": str(p)}, set()
    try:
        if p.is_dir():
            if p.is_symlink():
                raise Gap(f"{role} 是符號連結：{spec}")
            root = _find_l4t_root(p)
            ident.update(type="dir", root=str(root))
            for kind, rel, a, b in walk_dir(root, prune=lambda d: any((d + "/").startswith(x) for x in excludes)):
                if kind == "reject":
                    rejected.append({"name": rel, "reason": a, "target": b})
                elif kind == "file":
                    add_file(files, dups, rel, (b, a))
            ident["top_folder"] = root.name
        elif p.is_file() and not p.is_symlink():
            hr = open_archive(p)
            ident.update(type="archive", file_name=p.name, size=p.stat().st_size)
            try:
                for kind, rel, a, b in iter_tar(hr):
                    if kind == "reject":
                        rejected.append({"name": rel, "reason": a, "target": b})
                    elif kind == "file":
                        add_file(files, dups, rel, (b, a))
                hr.drain()
            finally:
                hr.f.close()
            ident["sha256"] = hr.h.hexdigest()
            files, rejected, dups, top = _strip_top(files, rejected, dups)
            ident["top_folder"] = top
        else:
            raise Gap(f"{role} 不是一般檔案或資料夾：{spec}")
    except (OSError, tarfile.TarError, EOFError) as e:
        raise Gap(f"{role} 讀取失敗：{type(e).__name__}: {e}")
    files = {k: v for k, v in files.items() if not any(k.startswith(x) for x in excludes)}
    dups = {k for k in dups if not any(k.startswith(x) for x in excludes)}
    return {"files": files, "rejected": rejected, "identity": ident, "duplicates": sorted(dups)}


def read_source_url(archive: Path):
    """archive 旁邊的 SOURCE 檔（key=url 每行或同一行多個 key=value）有這個檔名的網址就回傳。"""
    sf = archive.parent / "SOURCE"
    try:
        txt = sf.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    for m in re.finditer(r"(?:^|\s)\w+=(\S+)", txt):
        u = m.group(1)
        if u.rstrip("/").rsplit("/", 1)[-1] == archive.name:
            return u
    return None


def read_listed_sha(archive: Path):
    """archive 旁邊 SHA256-*.txt／<名稱>.sha256 裡列的 sha256（找到名稱相同的那行）。"""
    cands = list(archive.parent.glob("SHA256*.txt")) + [archive.parent / (archive.name + ".sha256")]
    for c in cands:
        try:
            for line in c.read_text(encoding="utf-8", errors="replace").splitlines():
                parts = line.split()
                if parts and re.fullmatch(r"[0-9a-fA-F]{64}", parts[0]) and (len(parts) == 1 or parts[-1].lstrip("*") == archive.name):
                    return parts[0].lower(), c.name
        except OSError:
            continue
    return None, None


def compare_maps(ours: dict, up: dict):
    res = {c: [] for c in CLASSES}
    for k in sorted(set(ours) | set(up)):
        if k in ours and k in up:
            if ours[k][0] == up[k][0]:
                res["same"].append(k)
            else:
                res["modified"].append(k)
        elif k in ours:
            res["ours_only"].append(k)
        else:
            res["upstream_only"].append(k)
    return res


def artifacts_run(ours, upstream, excludes):
    excludes = [e if e.endswith("/") else e + "/" for e in excludes]
    out = {"schema": SCHEMA_ARTIFACTS, "tool": TOOL, "generated": now_utc(), "exclude": excludes,
           "closed_firmware_patterns": closed_patterns(), "closed_firmware_source": "bootloader_coverage.classify (VENDOR_PATTERNS)"}
    try:
        up = load_artifact_tree(upstream, "upstream", excludes)
    except Gap as e:
        out.update(status="GAP", detail=str(e), ours=None, upstream={"path": str(upstream)})
        return out
    try:
        our = load_artifact_tree(ours, "ours", excludes)
    except Gap as e:
        out.update(status="GAP", detail=str(e), ours={"path": str(ours)}, upstream=up["identity"])
        return out
    ui = up["identity"]
    if ui.get("type") == "archive":
        ap = Path(upstream)
        ui["url"] = read_source_url(ap)
        listed, listed_in = read_listed_sha(ap)
        if listed:
            ui["sha256_listed"], ui["sha256_listed_in"], ui["sha256_matches_listed"] = listed, listed_in, listed == ui["sha256"]
    alld = set(our["duplicates"]) | set(up["duplicates"])
    for tr in (our, up):
        for k in alld:
            tr["files"].pop(k, None)
    res = compare_maps(our["files"], up["files"])
    by_top = {}
    for c in CLASSES:
        for k in res[c]:
            by_top.setdefault(top_of(k), dict.fromkeys(CLASSES, 0))[c] += 1
    sets = {c: set(res[c]) for c in CLASSES}
    closed, others = [], []
    for k in sorted(set(our["files"]) | set(up["files"])):
        fam = closed_family(k)
        if fam:
            closed.append({"path": k, "family": fam, "status": next(c for c in CLASSES if k in sets[c])})
        elif other_binary(k):
            others.append({"path": k, "status": next(c for c in CLASSES if k in sets[c]),
                           "note": "RD 重建，與原版不同是預期的" if k.rsplit("/", 1)[-1].lower() in RD_BUILT_BINARIES else "未分類的二進位檔"})
    ccount = dict.fromkeys(CLASSES, 0)
    for e in closed:
        ccount[e["status"]] += 1
    # 閉源韌體檔名是符號連結：兩邊都是相對路徑的符號連結、目標相同、而且目標本身是「相同」的閉源韌體 → 可接受（記在 symlinks_same）
    def link_ok(side, r):
        other = up if side == "ours" else our
        if r["reason"] != "symlink" or not r.get("target") or r["target"].startswith("/"):
            return False
        tgt = posixpath.normpath(posixpath.join(posixpath.dirname(r["name"]), r["target"]))
        peer = [x for x in other["rejected"] if x["name"] == r["name"] and x["reason"] == "symlink" and x.get("target") == r["target"]]
        return bool(peer) and bool(closed_family(tgt)) and tgt in sets["same"]
    rej_all = [dict(r, side=side) for side in ("ours", "upstream") for r in (our if side == "ours" else up)["rejected"] if closed_family(r["name"])]
    syml_same = [r for r in rej_all if link_ok(r["side"], r)]
    rej_closed = [r for r in rej_all if r not in syml_same]
    dup_closed = [k for k in sorted(alld) if closed_family(k)]
    bad_other = [e for e in others if e["status"] != "same" and not e["note"].startswith("RD")]
    reasons = []
    if ccount["modified"] or ccount["ours_only"]:
        reasons.append(f"閉源開機韌體有 {ccount['modified'] + ccount['ours_only']} 個檔案與 NVIDIA 原版不同或只有我們有")
    if ccount["upstream_only"]:
        reasons.append(f"有 {ccount['upstream_only']} 個閉源開機韌體只有 NVIDIA 有（我們的刷機包沒有）")
    if rej_closed:
        reasons.append(f"有 {len(rej_closed)} 個閉源開機韌體檔名是符號連結或特殊檔，未讀取")
    if alld:
        reasons.append(f"有 {len(alld)} 個路徑在封存檔裡重複出現（含 {len(dup_closed)} 個閉源韌體），未採用")
    if bad_other:
        reasons.append(f"有 {len(bad_other)} 個未分類的二進位檔與原版不同或只有一邊有")
    nonempty = bool(our["files"]) and bool(up["files"])
    if nonempty and not res["same"]:
        status, detail = "GAP", "兩邊都有檔案但沒有任何一個路徑相同，路徑沒有對齊（最上層資料夾不一致？），無法比對"
    elif not closed and not reasons:
        status, detail = "GAP", "兩邊都找不到符合樣式的閉源開機韌體檔案，無法判斷（目錄對齊是否正確？）"
    elif reasons:
        status, detail = "ATTENTION", "；".join(reasons)
    elif ccount["same"] == 0:
        status, detail = "GAP", "沒有任何閉源開機韌體可確認與原版相同"
    else:
        status = "OK"
        detail = f"NVIDIA 閉源開機韌體 {ccount['same']} 個檔案與 NVIDIA 原版相同"
    out.update(status=status, detail=detail, ours=our["identity"], upstream=ui,
               counts={c: len(res[c]) for c in CLASSES}, by_top=dict(sorted(by_top.items())),
               closed_firmware={"counts": ccount, "files": closed, "rejected_names": rej_closed, "symlinks_same": syml_same, "duplicate_paths": dup_closed},
               other_binaries=others, duplicates={"ours": our["duplicates"], "upstream": up["duplicates"]},
               modified=[{"path": k, "ours_sha256": our["files"][k][0], "upstream_sha256": up["files"][k][0],
                          "ours_size": our["files"][k][1], "upstream_size": up["files"][k][1]} for k in res["modified"]],
               ours_only=[{"path": k, "sha256": our["files"][k][0], "size": our["files"][k][1]} for k in res["ours_only"]],
               upstream_only=[{"path": k, "sha256": up["files"][k][0], "size": up["files"][k][1]} for k in res["upstream_only"]],
               rejected={"ours": our["rejected"], "upstream": up["rejected"]},
               scope_note="只證明「與 NVIDIA 發行版是不是同一個檔案」；不證明有沒有漏洞，也不涵蓋 rootfs 與未列入比對的路徑。")
    return out


def _cap(items, fmt, cap=MD_LIST_CAP):
    ls = [f"- {fmt(x)}" for x in items[:cap]]
    if len(items) > cap:
        ls.append(f"- …（還有 {len(items) - cap} 筆，完整清單在 json）")
    return ls or ["- （無）"]


def artifacts_md(d):
    L = ["# 與 NVIDIA 原版的成品比對（刷機包）", "", f"- 狀態：{d['status']}", f"- 說明：{d.get('detail', '')}", f"- 產生時間：{d['generated']}", ""]
    if d["status"] == "GAP" and "counts" not in d:
        L += ["沒有完成比對（輸入缺少或讀不了）；不可當成「與原版相同」。", ""]
        return "\n".join(L) + "\n"
    u, o = d["upstream"], d["ours"]
    L += ["## 比對對象", "", f"- 我們：{o.get('path')}（{o.get('type')}）",
          f"- NVIDIA：{u.get('file_name') or u.get('path')}" + (f"，{u['size']:,} bytes，sha256 {u['sha256']}" if u.get("sha256") else ""),
          ] + ([f"- NVIDIA 網址：{u['url']}"] if u.get("url") else []) + (
        [f"- 檔案旁列出的 sha256（{u['sha256_listed_in']}）：{'相符' if u['sha256_matches_listed'] else '不符'}"] if u.get("sha256_listed") else []) + [
        f"- 排除：{', '.join(d['exclude']) or '（無）'}", ""]
    c = d["counts"]
    L += ["## 結果", "", "| 類別 | 檔案數 |", "|---|---|", f"| 與 NVIDIA 原版相同 | {c['same']:,} |", f"| 同名但內容不同 | {c['modified']:,} |",
          f"| 只有我們有 | {c['ours_only']:,} |", f"| 只有 NVIDIA 有 | {c['upstream_only']:,} |", "", "依最上層資料夾：", "",
          "| 資料夾 | 相同 | 不同 | 只有我們 | 只有 NVIDIA |", "|---|---|---|---|---|"]
    L += [f"| {k} | {v['same']} | {v['modified']} | {v['ours_only']} | {v['upstream_only']} |" for k, v in d["by_top"].items()]
    cf = d["closed_firmware"]
    L += ["", "## NVIDIA 閉源開機韌體", "", f"依檔名樣式（bootloader/ 第一層）找到 {len(cf['files'])} 個：相同 {cf['counts']['same']}、不同 {cf['counts']['modified']}、"
          f"只有我們有 {cf['counts']['ours_only']}、只有 NVIDIA 有 {cf['counts']['upstream_only']}。UEFI（uefi_bins/、BOOTAA64.efi）由原始碼編譯，不算閉源。", ""]
    odd = [e for e in cf["files"] if e["status"] != "same"]
    L += _cap(odd, lambda e: f"{e['path']}（{e['family']}）：{e['status']}") if odd else ["- 全部相同"]
    if d.get("other_binaries"):
        L += ["", "bootloader/ 第一層其他二進位檔（不符合閉源樣式）：", ""] + _cap(d["other_binaries"], lambda e: f"{e['path']}：{e['status']}（{e['note']}）")
    dp = d.get("duplicates") or {}
    if dp.get("ours") or dp.get("upstream"):
        L += ["", "封存檔內重複出現的路徑（未採用、不算相同）：", ""] + _cap(list(dp.get("ours", [])) + list(dp.get("upstream", [])), lambda e: e)
    L += ["", "## 同名但內容不同（RD 改過或重編）", ""] + _cap(d["modified"], lambda e: e["path"])
    L += ["", "## 只有我們有", ""] + _cap(d["ours_only"], lambda e: e["path"])
    L += ["", "## 只有 NVIDIA 有", ""] + _cap(d["upstream_only"], lambda e: e["path"])
    rj = d["rejected"]
    L += ["", f"符號連結等不讀取的項目：我們 {len(rj['ours'])}、NVIDIA {len(rj['upstream'])}（不計入上表，明細在 json）。", "", d["scope_note"], ""]
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------- source
# (元件名, ours 子路徑 或 None, upstream 成員 tarball 檔名 或 None, 加在成員內路徑前面的前綴, 說明)
DEFAULT_COMPONENTS = [
    ("kernel", "kernel", "kernel_src.tbz2", "", ""),
    ("kernel_oot_modules", ".", "kernel_oot_modules_src.tbz2", "", "含 nvidia-oot、nvgpu、hwpm、hardware 等；只比 upstream 出現的最上層資料夾"),
    ("nvgpu_standalone", "nvgpu", "kernel_nvgpu_src.tbz2", "nvgpu/", "kernel_nvgpu_src 的路徑沒有 nvgpu/ 前綴，補上後對 sources/nvgpu"),
    ("nvdisplay", "nvdisplay", "nvidia_kernel_display_driver_source.tbz2", "", ""),
    ("unifiedgpudisp", "unifiedgpudisp", "nvidia_unified_gpu_display_driver_source.tbz2", "", ""),
    ("uefi", "uefi", None, "", "public_sources 沒有 UEFI（edk2／edk2-nvidia 由 git 抓），本工具不比"),
    ("atf_t234", None, "atf_t234_src.tbz2", "", "我們的 sources/ 沒有對應資料夾"),
    ("optee", None, "nvidia-jetson-optee-source.tbz2", "", "我們的 sources/ 沒有對應資料夾"),
]
# public_sources 裡不是這個專案要比的元件（相同或重複內容）；仍列在 unmapped_upstream_members，不會被當成已比對
MEMBER_SUFFIXES = (".tbz2", ".tar.bz2", ".tar.gz", ".tgz", ".tar", ".tar.xz")


def parse_component(s: str):
    name, eq, rest = s.partition("=")
    parts = rest.split(":")
    if not eq or not name or len(parts) not in (2, 3) or not parts[0] or not parts[1]:
        raise ValueError(f"--component 格式是 名稱=ours子路徑:upstream成員[:前綴]：{s}")
    pre = parts[2] if len(parts) == 3 else ""
    if pre and not pre.endswith("/"):
        pre += "/"
    return (name, parts[0], parts[1], pre, "使用者指定")


def _member_key(name: str):
    return posixpath.basename(name.rstrip("/"))


def read_component_upstream(src, members_wanted: dict, prefixes: dict):
    """src：public_sources 壓縮檔（Path）或資料夾。members_wanted：{成員檔名: [元件名…]}。
    回傳 ({元件名: {'files':{key:(sha,size)}, 'rejected':[...], 'ignored':{原因:數}}}, 找到的成員檔名集合, 所有成員檔名[(名稱,大小)], identity)。"""
    comp = {}
    found, all_members = set(), []
    ident = {"path": str(src)}

    sp = Path(src)
    if sp.is_file() and not sp.is_symlink():
        ident.update(type="archive", file_name=sp.name, size=sp.stat().st_size)
        hr = open_archive(sp)
        try:
            rd = DecompReader(hr)
            with tarfile.open(fileobj=rd, mode="r|") as t:
                for m in t:
                    if not m.isfile():
                        continue
                    base = _member_key(m.name)
                    if not base.endswith(MEMBER_SUFFIXES):
                        continue
                    all_members.append((base, m.size))
                    names = members_wanted.get(base)
                    if not names:
                        continue
                    found.add(base)
                    ff = t.extractfile(m)
                    _feed_nested(ff, names, comp, prefixes)
                end = t.offset
            rd.drain()
            check_complete(rd, end)
            hr.drain()
        except (OSError, tarfile.TarError, EOFError) as e:
            raise Gap(f"upstream 讀取失敗：{type(e).__name__}: {e}")
        finally:
            hr.f.close()
        ident["sha256"] = hr.h.hexdigest()
        url = read_source_url(sp)
        if url:
            ident["url"] = url
        listed, listed_in = read_listed_sha(sp)
        if listed:
            ident["sha256_listed"], ident["sha256_listed_in"], ident["sha256_matches_listed"] = listed, listed_in, listed == ident["sha256"]
    elif sp.is_dir() and not sp.is_symlink():
        ident["type"] = "dir"
        bases = [sp, sp / "Linux_for_Tegra" / "source", sp / "source"]
        seen = set()
        for b in bases:
            if b.is_dir():
                for c in sorted(b.iterdir()):
                    if c.name.endswith(MEMBER_SUFFIXES) and c.is_file() and not c.is_symlink() and c.name not in seen:
                        seen.add(c.name)
                        all_members.append((c.name, c.stat().st_size))
                        names = members_wanted.get(c.name)
                        if names:
                            found.add(c.name)
                            try:
                                with open(c, "rb") as f:
                                    _feed_nested(f, names, comp, prefixes)
                            except (OSError, tarfile.TarError, EOFError) as e:
                                raise Gap(f"upstream 成員 {c.name} 讀取失敗：{type(e).__name__}: {e}")
        # 子路徑（資料夾）形式的成員：--component 的 upstream 成員若是 sp 底下的資料夾
        for base, names in members_wanted.items():
            if base in found:
                continue
            d = sp / base
            if d.is_dir() and not d.is_symlink():
                found.add(base)
                for n in names:
                    pre = prefixes[n]
                    c = comp.setdefault(n, {"files": {}, "rejected": [], "ignored": {}, "dups": set()})
                    for kind, rel, a, b in walk_dir(d):
                        if kind == "reject":
                            c["rejected"].append({"name": rel, "reason": a})
                        else:
                            add_file(c["files"], c["dups"], pre + rel, (b, a))
    else:
        raise Gap(f"upstream 不存在或不是檔案／資料夾：{src}")
    return comp, found, all_members, ident


def _feed_nested(fobj, names, comp, prefixes):
    """upstream 成員全部讀進來（忽略表之後才套用，見 source_run）。"""
    for n in names:
        comp.setdefault(n, {"files": {}, "rejected": [], "ignored": {}, "dups": set()})
    for kind, rel, a, b in iter_tar(fobj):
        if kind == "reject":
            for n in names:
                comp[n]["rejected"].append({"name": rel, "reason": a})
        else:
            for n in names:
                add_file(comp[n]["files"], comp[n]["dups"], prefixes[n] + rel, (b, a))


def read_ours_component(root: Path, sub: str, upstream_files: dict):
    """走訪 ours 的子路徑；只對 upstream 也有的檔案算 sha256。回傳 (files{key:(sha或None,大小)}, rejected, ignored{原因:數}, ignored_paths{原因:[路徑]})。
    key 是相對 sources 根目錄的路徑。sub=="." 時只走 upstream 出現的最上層資料夾。"""
    files, rejected, ignored, ipaths = {}, [], {}, {}
    if sub == ".":
        tops = sorted({k.split("/", 1)[0] for k in upstream_files if "/" in k})
        bases = [(t, root / t) for t in tops]
    else:
        bases = [(sub.strip("/"), root / sub)]
    for relbase, base in bases:
        if not base.is_dir() or base.is_symlink():
            if base.is_symlink():
                rejected.append({"name": relbase, "reason": "symlink"})
            continue

        def want(r, relbase=relbase):
            k = relbase + "/" + r
            return k in upstream_files

        for kind, rel, a, b in walk_dir(base, want=want):
            k = relbase + "/" + rel
            if kind == "reject":
                rejected.append({"name": k, "reason": a})
            elif kind == "skip":
                why = ignore_reason(k)
                if why:
                    note_ignore(ignored, ipaths, why, k)
                else:
                    files[k] = (None, a)      # ours_only：不需要 hash
            else:
                files[k] = (b, a)
    return files, rejected, ignored, ipaths


def source_run(ours, upstream, user_components):
    out = {"schema": SCHEMA_SOURCE, "tool": TOOL, "generated": now_utc(),
           "ignore": {"dirs": sorted(IGNORE_DIRS), "name_globs": IGNORE_NAME_GLOBS}}
    oroot = Path(ours)
    if not oroot.is_dir() or oroot.is_symlink():
        out.update(status="GAP", detail=f"ours 不是資料夾：{ours}", upstream={"path": str(upstream)})
        return out
    comps = list(DEFAULT_COMPONENTS)
    if user_components:
        byname = {c[0]: c for c in comps}
        for c in user_components:
            byname[c[0]] = c
        comps = list(byname.values())
    members_wanted, prefixes = {}, {}
    for name, sub, member, pre, _ in comps:
        if member and sub is not None and (oroot / sub).is_dir():
            members_wanted.setdefault(_member_key(member), []).append(name)
            prefixes[name] = pre
    try:
        cu, found, all_members, ident = read_component_upstream(upstream, members_wanted, prefixes)
    except Gap as e:
        out.update(status="GAP", detail=str(e), ours={"path": str(oroot)}, upstream={"path": str(upstream)})
        return out
    results, covered_tops = [], set()
    for name, sub, member, pre, note in comps:
        r = {"name": name, "ours_subpath": sub, "upstream_member": member, "prefix": pre, "note": note}
        if member is None:
            r.update(status="NOT_ASSESSED", reason=note or "沒有對應的 upstream 成員")
        elif sub is None or not (oroot / sub).is_dir():
            r.update(status="NOT_ASSESSED", reason=f"ours 沒有對應資料夾（{sub}）" if sub else (note or "ours 沒有對應資料夾"))
        elif _member_key(member) not in found:
            r.update(status="NOT_ASSESSED", reason=f"upstream 找不到成員 {member}")
        else:
            up = cu[name]
            of, orej, oign, oipaths = read_ours_component(oroot, sub, up["files"])
            dups = set(up["dups"])
            for k2 in dups:
                of.pop(k2, None)
            # 只存在 upstream、且是編譯產物的檔案不算「只有 NVIDIA 有」
            upf, uipaths = {}, {}
            for k2, v2 in up["files"].items():
                why = None if k2 in of else ignore_reason(k2)
                if why:
                    note_ignore(up["ignored"], uipaths, why, k2)
                else:
                    upf[k2] = v2
            res = compare_maps(of, upf)
            if not of or not upf:
                r.update(status="NOT_ASSESSED", reason=f"其中一邊沒有可比對的檔案（ours {len(of)}、upstream {len(upf)}）")
            elif not res["same"]:
                r.update(status="NOT_ASSESSED", reason="兩邊都有檔案但沒有任何路徑相同，路徑沒有對齊")
            else:
                if sub == ".":
                    covered_tops |= {k.split("/", 1)[0] for k in upf if "/" in k}
                else:
                    covered_tops.add(sub.strip("/").split("/", 1)[0])
                r.update(status="ASSESSED", counts={c: len(res[c]) for c in CLASSES}, same=len(res["same"]),
                         modified=[{"path": k, "ours_sha256": of[k][0], "upstream_sha256": upf[k][0]} for k in res["modified"]],
                         ours_only=[{"path": k, "size": of[k][1]} for k in res["ours_only"]],
                         upstream_only=[{"path": k, "size": upf[k][1]} for k in res["upstream_only"]],
                         duplicates=sorted(dups),
                         ignored={"ours": oign, "upstream": up["ignored"],
                                  "ours_total": sum(oign.values()), "upstream_total": sum(up["ignored"].values()),
                                  "ours_paths": oipaths, "upstream_paths": uipaths},
                         rejected={"ours": orej, "upstream": up["rejected"]})
        results.append(r)
    used = {_member_key(c[2]) for c in comps if c[2]}
    unmapped = [{"member": n, "size": s} for n, s in sorted(set(all_members)) if n not in used]
    uncovered = sorted(d.name for d in oroot.iterdir() if d.is_dir() and not d.is_symlink() and d.name not in covered_tops)
    assessed = [r for r in results if r["status"] == "ASSESSED"]
    na = [r for r in results if r["status"] != "ASSESSED"]
    tm = sum(r["counts"]["modified"] for r in assessed)
    to = sum(r["counts"]["ours_only"] for r in assessed)
    ts = sum(r["counts"]["same"] for r in assessed)
    tu = sum(r["counts"]["upstream_only"] for r in assessed)
    if not assessed:
        status = "GAP"
    elif tm or to or tu or na or any(r.get("duplicates") for r in assessed):
        status = "ATTENTION"
    else:
        status = "OK"
    detail = (f"{len(assessed)} 個元件已比對（相同 {ts:,}、不同 {tm:,}、只有我們 {to:,}、只有 NVIDIA {tu:,}）；"
              f"{len(na)} 個元件 NOT_ASSESSED"
              + (f"；{sum(len(r['duplicates']) for r in assessed)} 個路徑在 upstream 重複出現（未採用）" if any(r.get("duplicates") for r in assessed) else ""))
    out.update(status=status, detail=detail, ours={"path": str(oroot)}, upstream=ident, components=results,
               totals={"same": ts, "modified": tm, "ours_only": to, "upstream_only": tu},
               unmapped_upstream_members=unmapped, uncovered_ours_dirs=uncovered,
               scope_note="只證明「與 NVIDIA public_sources 是不是同一個檔案」；沒對應的元件與資料夾不代表與 NVIDIA 相同。")
    return out


def source_md(d):
    L = ["# 與 NVIDIA public_sources 的原始碼比對", "", f"- 狀態：{d['status']}", f"- 說明：{d.get('detail', '')}", f"- 產生時間：{d['generated']}", ""]
    if "components" not in d:
        L += ["沒有完成比對（輸入缺少或讀不了）；不可當成「與原版相同」。", ""]
        return "\n".join(L) + "\n"
    u = d["upstream"]
    L += ["## 比對對象", "", f"- 我們：{d['ours']['path']}",
          f"- NVIDIA：{u.get('file_name') or u.get('path')}" + (f"，{u['size']:,} bytes，sha256 {u['sha256']}" if u.get("sha256") else "")]
    if u.get("url"):
        L.append(f"- NVIDIA 網址：{u['url']}")
    L += ["- 忽略編譯產物：資料夾 " + "、".join(d["ignore"]["dirs"]) + "；檔名 " + " ".join(d["ignore"]["name_globs"]), "",
          "## 各元件", "", "| 元件 | 狀態 | 相同 | 不同 | 只有我們 | 只有 NVIDIA | 忽略（我們／NVIDIA） |", "|---|---|---|---|---|---|---|"]
    for r in d["components"]:
        if r["status"] == "ASSESSED":
            c = r["counts"]
            L.append(f"| {r['name']} | 已比對 | {c['same']:,} | {c['modified']:,} | {c['ours_only']:,} | {c['upstream_only']:,} | "
                     f"{r['ignored']['ours_total']:,}／{r['ignored']['upstream_total']:,} |")
        else:
            L.append(f"| {r['name']} | NOT_ASSESSED：{r['reason']} | - | - | - | - | - |")
    for r in d["components"]:
        if r["status"] != "ASSESSED":
            continue
        L += ["", f"### {r['name']}", "", "同名但內容不同（RD 改過）：", ""] + _cap(r["modified"], lambda e: e["path"])
        L += ["", "只有我們有：", ""] + _cap(r["ours_only"], lambda e: e["path"])
        if r["upstream_only"]:
            L += ["", "只有 NVIDIA 有：", ""] + _cap(r["upstream_only"], lambda e: e["path"])
    L += ["", "## 沒有對應、沒比對的部分", "", "public_sources 內沒有被任何元件使用的成員：", ""] + _cap(d["unmapped_upstream_members"], lambda e: f"{e['member']}（{e['size']:,} bytes）")
    L += ["", "我們 sources/ 裡沒有被任何元件涵蓋的資料夾：", ""] + _cap(d["uncovered_ours_dirs"], lambda e: e)
    L += ["", d["scope_note"], ""]
    return "\n".join(L) + "\n"


def modified_files(doc, kinds=("modified", "ours_only")):
    """從 upstream-baseline-source.json（dict 或檔案路徑）取出每個元件 RD 改過的檔案：{元件名: {相對 sources/ 的路徑}}。
    kinds 預設包含 modified（同名不同）與 ours_only（RD 新增）。只含已比對的元件。
    後續（未實作）：用這個集合標記「CVE 修補 commit 動到的檔案是否為 RD 改過的檔案」。"""
    if not isinstance(doc, dict):
        doc = json.loads(Path(doc).read_text(encoding="utf-8"))
    out = {}
    for r in doc.get("components", []):
        if r.get("status") == "ASSESSED":
            out[r["name"]] = {e["path"] for k in kinds for e in r.get(k, [])}
    return out


# ---------------------------------------------------------------- CLI
def write_outputs(outdir: Path, stem: str, doc: dict, md: str):
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / f"{stem}.json").write_text(json.dumps(doc, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    (outdir / f"{stem}.md").write_text(md, encoding="utf-8")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="upstream_baseline.py", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("artifacts")
    a.add_argument("--ours", required=True)
    a.add_argument("--upstream", required=True)
    a.add_argument("--out", required=True)
    a.add_argument("--exclude", action="append", default=None, help="略過的相對路徑前綴（可重複；預設 rootfs/）")
    s = sub.add_parser("source")
    s.add_argument("--ours", required=True)
    s.add_argument("--upstream", required=True)
    s.add_argument("--out", required=True)
    s.add_argument("--component", action="append", default=[], help="名稱=ours子路徑:upstream成員[:前綴]（可重複；同名覆蓋預設）")
    args = ap.parse_args(argv)
    label = "A0-artifacts" if args.cmd == "artifacts" else "A0-source"
    try:
        if args.cmd == "artifacts":
            doc = artifacts_run(args.ours, args.upstream, args.exclude if args.exclude is not None else ["rootfs/"])
            write_outputs(Path(args.out), "upstream-baseline-artifacts", doc, artifacts_md(doc))
        else:
            try:
                comps = [parse_component(c) for c in args.component]
            except ValueError as e:
                print(f"{label}\tFAIL\t{e}")
                return 64
            doc = source_run(args.ours, args.upstream, comps)
            write_outputs(Path(args.out), "upstream-baseline-source", doc, source_md(doc))
    except Exception as e:   # noqa: BLE001  最外層：任何錯誤都要報 FAIL，不能靜默
        print(f"{label}\tFAIL\t{type(e).__name__}: {e}")
        return 1
    print(f"{label}\t{doc['status']}\t{doc.get('detail', '')}")
    return 0 if doc["status"] == "OK" else 2


if __name__ == "__main__":
    sys.exit(main())
