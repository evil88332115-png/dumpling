#!/usr/bin/env python3
"""pkg_why.py：漏洞多的套件「為什麼在映像裡」，給工程師決定能不能從出貨映像拿掉（CRA Annex I Part I (2)(j) 攻擊面最小化的紀錄）。

用法：
  python3 -I pkg_why.py extract --from <rootfs tar｜刷機包 tbz2｜rootfs 資料夾> [--prefix <rootfs 在刷機包裡的路徑>] --out <資料夾>
  python3 -I pkg_why.py report --pkgdb <extract 的資料夾> --summary <CRA/Reports/summary.json> --out <md> [--top N]
  python3 -I pkg_why.py rank --pkgdb <extract 的資料夾> --summary <summary.json> --out <md> [--json <json>] [--top N]
                             [--base-pkgdb <候選基底的 extract 資料夾> --keep <產品要裝的套件清單>]

extract：從映像取出兩個小檔，寫到 --out：
  dpkg-status（var/lib/dpkg/status：每個已安裝套件的 Depends／Recommends／Provides、原始碼套件、Priority）、
  extended_states（var/lib/apt/extended_states：哪些套件是被別的套件連帶裝進來的（Auto-Installed: 1）；沒有這個檔案時無法分辨手動／連帶）、
  pkgdb.json（來源、sha256、說明）。印一行：PKGDB<TAB>狀態<TAB>說明（OK；沒有 dpkg status → GAP）。
  來源是不可信資料：只用 tar 串流讀這兩個成員（tools/demo/flash_package.py 的讀法），不解開到磁碟、不跟隨連結、不執行任何東西；
  單一檔案上限 64 MB。刷機包要整個解壓（數 GB 的 bzip2，幾分鐘）；scan-flash-package.sh 從自己寫的 rootfs tar 讀，幾秒。
report：讀 summary.json 的 vex.gate.open_components（還沒處理完的列：untriaged、exploitable、in_triage，依元件彙總），
  列數最多的 --top 個（預設 30）deb 套件，各寫：實際安裝的二進位套件、直接依賴它的套件、往上追到「手動安裝」套件的最短路徑
  （Pre-Depends／Depends 與 Recommends；apt 預設會裝 Recommends）、一句提示。核心與非 deb 套件另列（dpkg 沒有它們的依賴資料）。
  印一行：D-pkg-why<TAB>狀態<TAB>說明。
rank：拿掉套件或換基底「可以少掉多少未處理的漏洞列」的估計排行（CRA Annex I Part I (2)(j)；計畫總表 #11）。
  - 每個手動安裝、不是基本套件（Priority required／important、Essential）的套件 M：拿掉 M 時 apt 會一起拿掉的套件
    ＝依賴它的套件（Pre-Depends／Depends 的每一組替代都被拿掉才算壞掉，反覆到不變）＋之後沒有被剩下的手動安裝套件
    以 Depends／Recommends 需要的連帶安裝套件（apt autoremove；Recommends 預設算需要）。
  - 情境：不裝 Recommends（連帶安裝、只靠 Recommends 走得到的套件）；不裝開發套件（手動安裝的 -dev、gcc、make…一起拿掉）。
  - 換基底：--base-pkgdb（候選基底映像的 extract 結果）＋ --keep（產品要的套件，一行一個名稱，# 開頭是註解）：
    新映像 ＝ 候選基底已安裝的套件 ＋ keep 及它們在目前映像的依賴（Depends＋Recommends）；目前有、新映像沒有的套件算拿掉。
    候選基底有、目前沒有的套件另列（漏洞要掃描新映像才知道）。
  - 一個原始碼套件的列只在它**所有**已安裝的二進位套件都被拿掉時才算少掉（部分拿掉另列，不算）。
  - 會拿掉基本套件的選項標「不可行」，不排進前面。替代依賴（a | b）在 autoremove 時兩個都算需要（保守，少算效益）。
  印一行：D-pkg-rank<TAB>狀態<TAB>說明；沒有 extended_states 時是 ATTENTION（手動／連帶是推定的）。
提示只依 dpkg 的資料：自家程式直接載入的函式庫（dlopen）、腳本呼叫的指令、客戶指定要裝的套件都看不到。拿掉前要在實際板子上確認功能。
"""
import argparse
import collections
import contextlib
import datetime
import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
FILES = {"var/lib/dpkg/status": "dpkg-status", "var/lib/apt/extended_states": "extended_states"}
MAX_FILE = 64 << 20
LISTS_DIR = "var/lib/dpkg/info"        # *.list：每個套件擁有的檔案（pkgdb/dpkg-file-owners 的來源；runtime_evidence.py 用）
OWNERS_NAME = "dpkg-file-owners"
ROOTFS_FILES_NAME = "rootfs-files"   # 映像裡所有項目的完整清單（kind<TAB>/path<TAB>link 目標）；第一行 #complete 或 #partial
MAX_ROOTFS_FILES = 128 << 20
MAX_LISTS = 128 << 20


def _list_pkg(fn):
    """'libssl3t64:arm64.list' → 'libssl3t64'；不是 .list → None。"""
    return fn[:-5].split(":", 1)[0] if fn.endswith(".list") and len(fn) > 5 else None


def rootfs_files_text(entries, partial=False):
    """[(kind, 絕對路徑, link 目標或 "")] → 第一行 #complete／#partial，之後每行 kind<TAB>path<TAB>link。路徑或目標含換行／tab 的略過並算 partial。"""
    out = []
    for kind, path, link in entries:
        if any(c in path or c in (link or "") for c in "\t\n\r"):
            partial = True
            continue
        out.append(f"{kind}\t{path}\t{link or ''}")
    body = "\n".join(out) + "\n" if out else ""
    return ("#partial\n" if partial or len(body) > MAX_ROOTFS_FILES else "#complete\n") + (body if len(body) <= MAX_ROOTFS_FILES else "")


def owners_text(lists, partial=False):
    """{套件: 檔案清單文字} → 'pkg<TAB>path' 每行一筆（排序、去重）。只收絕對路徑。"""
    out = []
    for pkg in sorted(lists):
        for line in lists[pkg].splitlines():
            if line.startswith("/") and "\t" not in line and line != "/.":
                out.append(f"{pkg}\t{line}")
    body = "\n".join(sorted(set(out))) + "\n" if out else ""
    return ("#partial\n" if partial else "") + body
STRONG = ("Pre-Depends", "Depends")
WEAK = ("Recommends",)
BASE_PRIORITY = ("required", "important")
DEV_RE = re.compile(r"(-dev|-dev-bin|-doc|-dbg|-dbgsym)$|^(build-essential|gcc(-\d+)?|g\+\+(-\d+)?|cpp(-\d+)?|make|dpkg-dev|cmake|autoconf|automake|libtool)$")
STATE_LABEL = {"untriaged": "沒有判定", "exploitable": "受影響", "in_triage": "調查中"}
INSTALLED = ("installed", "triggers-pending", "triggers-awaited")      # 檔案在磁碟上、滿足依賴的狀態
MAX_PATHS = 3
MAX_DEPTH = 12


class Fail(Exception):
    pass


def flash_package():
    spec = importlib.util.spec_from_file_location("sca_center_flash_package", ROOT / "tools" / "demo" / "flash_package.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


# ---------- extract ----------

def read_limited(f, size):
    if size > MAX_FILE:
        raise Fail(f"檔案太大（{size} bytes，上限 {MAX_FILE}）")
    data = f.read(MAX_FILE + 1)
    if len(data) > MAX_FILE:
        raise Fail(f"檔案太大（上限 {MAX_FILE}）")
    return data


def extract_dir(fp, src, prefix):
    """rootfs 資料夾：前綴與檔案路徑逐層 lstat，不跟隨符號連結；最後以 O_NOFOLLOW 打開。回傳 ({rel: bytes}, notes)。"""
    got, notes = {}, []
    for rel in FILES:
        p = src
        bad = None
        for part in prefix + tuple(rel.split("/")):
            p = os.path.join(p, part)
            try:
                st = os.lstat(p)
            except FileNotFoundError:
                bad = "不存在"
                break
            if stat.S_ISLNK(st.st_mode):
                bad = "是符號連結（不跟隨）"
                break
        if bad is None and not stat.S_ISREG(st.st_mode):
            bad = "不是一般檔案"
        if bad:
            notes.append(f"{rel} {bad}")
            continue
        try:
            f = fp.open_nofollow(p)
        except OSError as e:
            notes.append(f"{rel} 讀不到（{e.strerror or type(e).__name__}）")
            continue
        with f:
            got[rel] = read_limited(f, os.fstat(f.fileno()).st_size)
    lists = extract_lists_dir(fp, src, prefix, notes)
    part = any("超過" in n and LISTS_DIR in n for n in notes)
    if lists or part:
        got[OWNERS_NAME] = owners_text(lists, part).encode()
    ents, partial = [], False
    try:
        for e in fp.dir_entries(os.path.join(src, *prefix)):
            if e.kind in ("unreadable", "unreadable_dir") or not e.parts:
                partial = True
                continue
            ents.append((e.kind, "/" + "/".join(e.parts), e.link if isinstance(e.link, str) else ("/" + "/".join(e.link) if e.link else "")))
    except fp.Fail as ex:
        partial = True
        notes.append(f"rootfs 檔案清單讀不完（{ex}）")
    got[ROOTFS_FILES_NAME] = rootfs_files_text(ents, partial).encode()
    return got, notes


def extract_lists_dir(fp, src, prefix, notes):
    """rootfs 資料夾的 var/lib/dpkg/info/*.list → {套件: 文字}。路徑逐層 lstat（不跟隨符號連結）；失敗只記 notes，不影響 dpkg-status。"""
    d = src
    for part in prefix + tuple(LISTS_DIR.split("/")):
        d = os.path.join(d, part)
        try:
            if stat.S_ISLNK(os.lstat(d).st_mode):
                notes.append(f"{LISTS_DIR} 的路徑有符號連結（不跟隨），沒有檔案擁有者清單")
                return {}
        except OSError:
            notes.append(f"沒有 {LISTS_DIR}（沒有檔案擁有者清單）")
            return {}
    out, total = {}, 0
    for fn in sorted(os.listdir(d)):
        pkg = _list_pkg(fn)
        if pkg is None:
            continue
        p = os.path.join(d, fn)
        try:
            if not stat.S_ISREG(os.lstat(p).st_mode):
                continue
            with fp.open_nofollow(p) as f:
                data = read_limited(f, os.fstat(f.fileno()).st_size)
        except (OSError, Fail):
            notes.append(f"{LISTS_DIR}/{fn} 讀不到")
            continue
        total += len(data)
        if total > MAX_LISTS:
            notes.append(f"{LISTS_DIR} 超過 {MAX_LISTS} bytes，後面的沒有收")
            break
        out[pkg] = out.get(pkg, "") + data.decode("utf-8", "replace") + "\n"
    return out


def extract_tar(fp, src, prefix):
    """tar（壓縮或未壓縮）串流讀取，只取 FILES 的成員；硬連結的目標再讀一次壓縮檔。回傳 ({rel: bytes}, notes)。"""
    want = {"/".join(prefix + tuple(rel.split("/"))): rel for rel in FILES}
    got, notes, links = {}, [], {}
    lists, ltotal, lpre, lpartial = {}, 0, "/".join(prefix + tuple(LISTS_DIR.split("/"))) + "/", False
    ents, fpart, ppre = [], False, ("/".join(prefix) + "/") if prefix else ""
    with fp.open_stream(src) as t:
        for e in fp.tar_entries(t):
            if e.name is None:
                fpart = True               # 名稱不合法的成員：清單不能說完整
            elif e.name.startswith(ppre) and len(e.name) > len(ppre):
                ents.append((e.kind, "/" + e.name[len(ppre):], e.link if isinstance(e.link, str) else ("/" + "/".join(e.link[len(prefix):]) if e.link else "")))
            rel = want.get(e.name)
            if rel is None:
                if e.kind == "file" and e.name.startswith(lpre) and "/" not in e.name[len(lpre):] and _list_pkg(e.name[len(lpre):]) \
                        and ltotal > MAX_LISTS:
                    lpartial = True
                    notes.append(f"{LISTS_DIR} 超過 {MAX_LISTS} bytes，後面的沒有收") if not any(LISTS_DIR in n for n in notes) else None
                if e.kind == "file" and e.name.startswith(lpre) and "/" not in e.name[len(lpre):] and _list_pkg(e.name[len(lpre):]) \
                        and ltotal <= MAX_LISTS:
                    with contextlib.closing(e.open()) as f:
                        data = read_limited(f, e.size)
                    ltotal += len(data)
                    pkg = _list_pkg(e.name[len(lpre):])
                    lists[pkg] = lists.get(pkg, "") + data.decode("utf-8", "replace") + "\n"
                continue
            if e.kind == "file":
                with contextlib.closing(e.open()) as f:
                    got[rel] = read_limited(f, e.size)
                links.pop(rel, None)
            elif e.kind == "hardlink" and e.link:
                got.pop(rel, None)
                links[rel] = "/".join(e.link)
            else:
                got.pop(rel, None)
                links.pop(rel, None)          # 後面的成員取代前面的硬連結
                notes.append(f"{rel} 是 {e.kind}（{'不跟隨' if e.kind == 'symlink' else '不讀'}）")
    if links:
        def cb(name, e):
            for rel, tgt in links.items():
                if tgt == name:
                    with contextlib.closing(e.open()) as f:
                        got[rel] = read_limited(f, e.size)
        left = fp.fetch_members(src, sorted(set(links.values())), cb)
        notes += [f"{rel} 是硬連結，目標 {tgt} 讀不到" for rel, tgt in links.items() if tgt in left]
    if lists:
        got[OWNERS_NAME] = owners_text(lists, lpartial).encode()
    else:
        notes.append(f"沒有 {LISTS_DIR}/*.list（沒有檔案擁有者清單）")
    got[ROOTFS_FILES_NAME] = rootfs_files_text(ents, fpart).encode()
    return got, notes


def do_extract(src, prefix, out):
    fp = flash_package()
    pp = ()
    if prefix:
        pp = tuple(fp.split_name(prefix) or ())
        if not pp:
            raise Fail(f"--prefix 不合法：{prefix}")
    if os.path.isdir(src):
        got, notes = extract_dir(fp, src, pp)
        kind = "dir"
    elif os.path.isfile(src):
        try:
            got, notes = extract_tar(fp, src, pp)
        except fp.Fail as e:
            raise Fail(str(e))
        kind = "archive" if pp else "rootfs-tar"
    else:
        raise Fail(f"--from 不是檔案也不是資料夾：{src}")
    os.makedirs(out, exist_ok=True)
    meta = {"schema": "sca-center-pkgdb/1", "source": {"type": kind, "file": os.path.basename(os.path.abspath(src)),
                                                       "prefix": "/".join(pp) or None},
            "extracted_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "files": {}, "notes": notes}
    for rel, name in list(FILES.items()) + [(OWNERS_NAME, OWNERS_NAME), (ROOTFS_FILES_NAME, ROOTFS_FILES_NAME)]:
        p = os.path.join(out, name)
        with contextlib.suppress(FileNotFoundError):
            os.remove(p)                       # 不留上一次的檔案冒充這次的
        if rel in got:
            with open(p, "wb") as f:
                f.write(got[rel])
            meta["files"][name] = {"path": rel, "bytes": len(got[rel]), "sha256": hashlib.sha256(got[rel]).hexdigest()}
    with open(os.path.join(out, "pkgdb.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=1)
    if "dpkg-status" not in meta["files"]:
        return "GAP", "映像裡沒有 var/lib/dpkg/status" + (f"（{'；'.join(notes)}）" if notes else "")
    n = sum(1 for _ in _paragraphs(got["var/lib/dpkg/status"].decode("utf-8", "replace")))
    return "OK", (f"dpkg status {n} 個套件段落" + ("；extended_states 有" if "extended_states" in meta["files"]
                                                    else "；沒有 extended_states（無法分辨手動／連帶安裝）"))


# ---------- report ----------

def dep_names(field):
    """Depends 欄位 → [[名稱, …（同一組的替代）], …]；去掉版本、架構限定與 :any。"""
    out = []
    for group in (field or "").split(","):
        alts = []
        for alt in group.split("|"):
            alt = re.sub(r"\([^)]*\)|\[[^]]*\]|<[^>]*>", "", alt).strip()
            if alt:
                alts.append(alt.split(":", 1)[0])
        if alts:
            out.append(alts)
    return out


class PkgDB:
    def __init__(self, status_text, ext_text=None):
        self.pkgs = {}                  # 名稱 → 段落（同名多架構：顯示用第一個；依賴、Provides 合併每個架構）
        self.archs = collections.defaultdict(set)
        self.deps = collections.defaultdict(list)    # 名稱 → [(依賴的名稱, 種類)]
        paras, provides = [], collections.defaultdict(set)
        # 每一個段落（不管安裝狀態；同名多架構都留）：no_vuln_data 要看 unpacked、half-configured 等沒有裝完的套件與它們的 hold
        self.all_paras = collections.defaultdict(list)
        for d in _paragraphs(status_text):
            self.all_paras[d["Package"]].append(d)
            st = d.get("Status", "").split()
            if len(st) != 3 or st[2] not in INSTALLED:
                continue
            name = d["Package"]
            self.pkgs.setdefault(name, d)
            self.archs[name].add(d.get("Architecture") or "?")
            paras.append(d)
            for p in dep_names(d.get("Provides")):
                provides[p[0]].add(name)
        for d in paras:
            name = d["Package"]
            for fields, kind in ((STRONG, "depends"), (WEAK, "recommends")):
                for f in fields:
                    for alts in dep_names(d.get(f)):
                        for a in alts:
                            for tgt in ({a} if a in self.pkgs else set()) | provides.get(a, set()):
                                if tgt != name and (tgt, kind) not in self.deps[name]:
                                    self.deps[name].append((tgt, kind))
        # 拿掉時判斷「依賴壞掉」用：每個 Pre-Depends／Depends 一組替代 → 已安裝的目標集合（目前就不滿足的組不算）
        self.strong_groups = collections.defaultdict(list)
        for d in paras:
            name = d["Package"]
            for f in STRONG:
                for alts in dep_names(d.get(f)):
                    tg = set()
                    for a in alts:
                        tg |= ({a} if a in self.pkgs else set()) | provides.get(a, set())
                    tg.discard(name)
                    if tg and tg not in self.strong_groups[name]:
                        self.strong_groups[name].append(tg)
        self.rdeps = collections.defaultdict(dict)   # 名稱 → {依賴它的套件: 種類（depends 優先）}
        for name, ds in self.deps.items():
            for tgt, kind in ds:
                if self.rdeps[tgt].get(name) != "depends":
                    self.rdeps[tgt][name] = kind
        self.has_ext = ext_text is not None
        self.auto = set()
        if ext_text is not None:
            auto_archs = collections.defaultdict(set)
            for d in _paragraphs(ext_text):
                if d.get("Auto-Installed", "").strip() == "1":
                    auto_archs[d["Package"]].add(d.get("Architecture") or "?")
            # 同名多架構：每個安裝的架構都是連帶安裝才算連帶（Architecture: all 在 extended_states 記成本機架構）
            self.auto = {n for n, aa in auto_archs.items() if n in self.pkgs and all(x in aa or x == "all" for x in self.archs[n])}
        self.by_source = collections.defaultdict(set)
        for name, d in self.pkgs.items():
            src = (d.get("Source") or name).split(" ", 1)[0]
            self.by_source[src].add(name)
        # 從所有手動安裝的套件往下走：任何依賴、只走 Depends、只從非開發套件出發。提示用這三個集合判斷，不看顯示用的路徑
        roots = [n for n in self.pkgs if self.manual(n)]
        self.reach_any = self._forward(roots, ("depends", "recommends"))
        self.reach_strong = self._forward(roots, ("depends",))
        # 「只被開發套件帶進來」＝從任何非開發的手動安裝套件都走不到（執行期套件依賴開發套件時，拿掉開發套件也會拿掉它，所以不算）
        self.reach_nodev = self._forward([r for r in roots if not is_dev(r)], ("depends", "recommends"))

    def manual(self, name):
        """手動安裝；沒有 extended_states 時：沒有任何套件依賴它的才當頂層。"""
        if self.has_ext:
            return name not in self.auto
        return not self.rdeps.get(name)

    def base(self, name):
        d = self.pkgs.get(name, {})
        return d.get("Priority") in BASE_PRIORITY or d.get("Essential") == "yes"

    def essential(self, name):
        d = self.pkgs.get(name, {})
        return d.get("Essential") == "yes" or d.get("Priority") == "required"

    def removal(self, start):
        """拿掉 start（集合）時 apt 會一起拿掉的套件：依賴壞掉的（反覆到不變）＋ autoremove。回傳集合（含 start）。"""
        removed = {n for n in start if n in self.pkgs}
        q = collections.deque(removed)
        while q:
            cur = q.popleft()
            for up in self.rdeps.get(cur, {}):
                if up not in removed and any(g <= removed for g in self.strong_groups.get(up, ())):
                    removed.add(up)
                    q.append(up)
        # autoremove 的起點：剩下的手動安裝套件與基本套件（基本套件不會被 autoremove）
        keep = self._forward([n for n in self.pkgs if (self.manual(n) or self.base(n)) and n not in removed], ("depends", "recommends"), removed)
        return removed | {n for n in self.pkgs if not self.manual(n) and n not in keep}

    def _forward(self, starts, kinds, skip=frozenset()):
        seen, q = set(starts), collections.deque(starts)
        while q:
            for t, k in self.deps.get(q.popleft(), ()):
                if k in kinds and t not in seen and t not in skip:
                    seen.add(t)
                    q.append(t)
        return seen

    def why(self, name):
        """往上（依賴它的套件）找最近的手動安裝套件（走到手動安裝的就不再往上）。
        回傳 (全部的頂層（排序）, 顯示用的最短路徑 [(路徑 [頂層, …, name], 經過 recommends)]，最多 MAX_PATHS 條)。"""
        if self.manual(name):
            return [name], [([name], False)]
        prev = {name: None}
        q = collections.deque([(name, 0)])
        found = []
        while q:
            cur, depth = q.popleft()
            if depth >= MAX_DEPTH:
                continue
            for up in sorted(self.rdeps.get(cur, {})):
                if up in prev:
                    continue
                prev[up] = cur
                if self.manual(up):
                    found.append(up)
                else:
                    q.append((up, depth + 1))
        paths = []
        for r in found[:MAX_PATHS]:
            path, weak, x = [r], False, r
            while prev[x] is not None:
                weak |= self.rdeps[prev[x]][x] == "recommends"
                x = prev[x]
                path.append(x)
            paths.append((path, weak))
        return sorted(found), paths


def is_dev(name):
    return bool(DEV_RE.search(name))


def _paragraphs(text):
    for para in re.split(r"\n\s*\n", text or ""):
        d = {}
        for line in para.splitlines():
            if line[:1] in (" ", "\t") or ":" not in line:
                continue
            k, _, v = line.partition(":")
            d[k.strip()] = v.strip()
        if d.get("Package"):
            yield d


def source_name(purl):
    m = re.match(r"^pkg:deb/[^/]+/([^@?#]+)", purl or "")
    return m.group(1) if m else None


def hint(db, bins, info):
    """一句提示。「可以拿掉」類的提示只依可達集合（全部的手動安裝套件），不依顯示用的路徑。"""
    if any(db.base(b) for b in bins):
        return "系統基本套件（Priority required／important）：通常要保留"
    if not any(db.rdeps.get(b) for b in bins):
        if db.has_ext and all(b in db.auto for b in bins):
            return "連帶安裝，但沒有任何已安裝的套件以 Depends／Recommends 需要它：確認自家程式沒有直接用到就可以拿掉"
        return "被直接指定安裝，沒有其他套件以 Depends／Recommends 需要它：確認產品用不用，不用就從安裝清單拿掉"
    roots = sorted({r for b in bins for r in info[b][0]}, key=lambda r: (is_dev(r), r))     # 執行期的套件列在前面
    # held：從手動安裝的套件走得到；stuck：有套件依賴它、卻走不到（只靠循環留著）。沒有人依賴的連帶安裝套件兩邊都不算（本來就能拿掉）
    held = [b for b in bins if b in db.reach_any]
    stuck = [b for b in bins if b not in db.reach_any and db.rdeps.get(b)]
    if held and not stuck:
        if not any(b in db.reach_nodev for b in held):
            devs = sorted({x for b in held for p, _ in info[b][1] for x in p[:-1] if is_dev(x)} | {r for r in roots if is_dev(r)})
            return (f"只被開發套件帶進來（{', '.join(devs[:3]) or '開發套件'}{' …' if len(devs) > 3 else ''}）："
                    "出貨映像不裝開發套件的話，它就不會被裝進來")
        if not any(b in db.reach_strong for b in held):
            return "只因為 Recommends 被裝進來：安裝時加 --no-install-recommends 就不會裝（確認功能不受影響）"
    elif stuck and not held:
        return "找不到手動安裝的上層套件（依賴關係有循環）：請人工確認"
    if not roots:
        return "找不到手動安裝的上層套件（依賴關係超過追蹤深度）：請人工確認"
    if all(db.manual(b) for b in bins):
        others = sorted({u for b in bins for u in db.rdeps.get(b, {})})
        return (f"被直接指定安裝，另外 {', '.join(others[:3])}{' 等' if len(others) > 3 else ''} 也依賴它："
                "要拿掉得先確認這些套件用不用")
    return (f"被 {', '.join(roots[:3])}{f' 等 {len(roots)} 個' if len(roots) > 3 else ''} 帶進來：要拿掉得先確認這些套件用不用")


def component_bins(db, c):
    """open_components 的一列 → 板子上實際安裝的二進位套件（排序）。"""
    src = source_name(c.get("purl")) or c.get("component")
    bins = sorted((db.by_source.get(src, set()) | {b for b in c.get("installed_as") or [] if isinstance(b, str) and b in db.pkgs}))
    if not bins and c.get("component") in db.pkgs:
        bins = [c["component"]]
    return bins


def tiers_text(t):
    return "、".join(f"{k.upper() if k != 'other' else '其他'} {n}" for k, n in t.items())


def cell(x):
    return str(x).replace("|", "\\|").replace("\n", " ")


def do_report(pkgdb, summary, out, top):
    try:
        s = json.loads(Path(summary).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise Fail(f"讀不到 {summary}（{type(e).__name__}）")
    comps = ((s.get("vex") or {}).get("gate") or {}).get("open_components")
    if not isinstance(comps, list):
        raise Fail(f"{summary} 沒有 vex.gate.open_components（cra_report 版本太舊，或 VEX 沒有產生）")
    db = load_db(pkgdb)
    if db is None:
        return "GAP", f"{pkgdb} 沒有 dpkg-status（先執行 pkg_why.py extract）", None
    meta = {}
    with contextlib.suppress(OSError, ValueError):
        meta = json.loads((Path(pkgdb) / "pkgdb.json").read_text(encoding="utf-8"))
    debs = [c for c in comps if c.get("type") == "deb"]
    others = [c for c in comps if c.get("type") != "deb"]
    rows, sections, missing = [], [], 0
    for c in debs[:top]:
        bins = component_bins(db, c)
        st = "、".join(f"{STATE_LABEL.get(k, k)} {n}" for k, n in (c.get("states") or {}).items())
        head = f"{c['component']} {c.get('version') or ''}".strip()
        if not bins:
            missing += 1
            rows.append([head, c["rows"], "（dpkg 裡找不到）", "", "SBOM 有、dpkg status 沒有：可能不是用 apt 安裝的，請人工確認"])
            sections.append(f"### {head}（{c['rows']} 列：{st}；{tiers_text(c.get('tiers') or {})}）\n\n"
                            "dpkg status 裡找不到這個原始碼套件安裝的二進位套件：可能不是用 apt 安裝的（直接複製的檔案），請人工確認。\n")
            continue
        info = {b: db.why(b) for b in bins}
        h = hint(db, bins, info)
        roots = sorted({r for b in bins for r in info[b][0]}, key=lambda r: (is_dev(r), r))
        rows.append([head, c["rows"], ", ".join(bins), ", ".join(roots[:4]) + (" …" if len(roots) > 4 else ""), h])
        lines = [f"### {head}（{c['rows']} 列：{st}；{tiers_text(c.get('tiers') or {})}）", ""]
        for b in bins:
            d = db.pkgs[b]
            tag = ("手動安裝" if db.manual(b) else "連帶安裝") if db.has_ext else ("頂層（沒有套件依賴它）" if db.manual(b) else "被依賴")
            lines.append(f"- **{b}** {d.get('Version', '')}（{tag}；Priority {d.get('Priority') or '?'}）")
            rd = db.rdeps.get(b, {})
            if rd:
                names = sorted(rd)
                lines.append("  - 直接依賴它的：" + ", ".join(f"{n}{'（Recommends）' if rd[n] == 'recommends' else ''}" for n in names[:12])
                             + (f" …（共 {len(names)} 個）" if len(names) > 12 else ""))
            else:
                lines.append("  - 直接依賴它的：沒有")
            for path, weak in info[b][1]:
                if len(path) > 1:
                    lines.append("  - 裝進來的路徑：" + " → ".join(path) + ("（經過 Recommends）" if weak else ""))
        lines += ["", f"提示：{h}", ""]
        sections.append("\n".join(lines))
    src = meta.get("source") or {}
    md = ["# 套件依賴說明", "",
          "這份說明列出**漏洞列數最多的 Ubuntu 套件為什麼會在映像裡**，給工程師決定能不能從出貨映像拿掉。"
          "拿掉不需要的套件，那個套件的漏洞就不在產品裡（CRA Annex I Part I (2)(j)：攻擊面最小化）。", "",
          "怎麼讀：", "",
          "- 「漏洞列數」只算還沒處理完的列（沒有判定、受影響、調查中）。",
          "- 「實際安裝」是板子上的二進位套件名稱（漏洞資料庫用的是 Ubuntu 的原始碼套件名稱）。",
          "- 「帶進來的頂層套件」是往上追依賴關係，追到的**手動安裝**套件（"
          + ("依 var/lib/apt/extended_states" if db.has_ext else "映像裡沒有 extended_states，改用「沒有其他套件依賴它」的套件") + "）。",
          "- 只依 dpkg 的資料：自家程式直接載入的函式庫、腳本呼叫的指令、客戶指定要裝的套件都看不到。"
          "**拿掉前要在實際板子上確認功能**；客戶指定的套件要先問客戶。", "",
          f"資料來源：{src.get('type', '?')} {src.get('file', '?')}" + (f"（{src['prefix']}）" if src.get("prefix") else "")
          + f"；dpkg 已安裝套件 {len(db.pkgs)} 個；漏洞資料 {Path(summary).name}"
          + (f"（{s['generated']}）" if s.get("generated") else "") + "。", "",
          f"## 摘要（前 {min(top, len(debs))} 個，共 {len(debs)} 個 deb 套件有未處理的列）", "",
          "| 套件 | 漏洞列數 | 實際安裝 | 帶進來的頂層套件 | 提示 |", "|---|---|---|---|---|"]
    md += ["| " + " | ".join(cell(x) for x in r) + " |" for r in rows]
    md += ["", "## 每個套件", ""] + sections
    if others:
        md += ["## 不是 deb 套件（dpkg 沒有依賴資料）", "", "| 元件 | 類型 | 漏洞列數 |", "|---|---|---|"]
        md += [f"| {cell(c['component'])} {cell(c.get('version') or '')} | {cell(c.get('type'))} | {c['rows']} |" for c in others[:top]]
        md += ["", "核心（kernel）看 kernel-vulnerabilities.md；Python 等套件要看是哪個應用帶進來的（requirements、安裝腳本）。", ""]
    Path(out).write_text("\n".join(md) + "\n", encoding="utf-8")
    st = "OK"
    detail = (f"{min(top, len(debs))} 個 deb 套件（共 {len(debs)} 個有未處理的列）；非 deb {len(others)} 個"
              + (f"；dpkg 找不到 {missing} 個" if missing else "") + ("" if db.has_ext else "；沒有 extended_states（頂層是推定的）"))
    if missing or not db.has_ext:
        st = "ATTENTION"
    return st, detail, out


def load_summary(summary):
    try:
        s = json.loads(Path(summary).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise Fail(f"讀不到 {summary}（{type(e).__name__}）")
    comps = ((s.get("vex") or {}).get("gate") or {}).get("open_components") if isinstance(s, dict) else None
    if not isinstance(comps, list):
        raise Fail(f"{summary} 沒有 vex.gate.open_components（cra_report 版本太舊，或 VEX 沒有產生）")
    return s, [c for c in comps if isinstance(c, dict) and isinstance(c.get("rows"), int) and not isinstance(c.get("rows"), bool)]


def read_db_file(p):
    """pkgdb 資料夾裡的一個檔案 → 文字；不存在 → None。符號連結、不是一般檔案、超過 MAX_FILE → Fail（不跟隨、不讀）。
    以 O_NOFOLLOW｜O_NONBLOCK 打開，再用 fstat 確認打開的就是一般檔案（lstat 與 open 之間被換掉也擋得到；
    換成 FIFO 時 O_NONBLOCK 讓 open 不會卡住等寫入端，fstat 再擋下。一般檔案的讀取不受 O_NONBLOCK 影響）。"""
    try:
        st = os.lstat(p)
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(st.st_mode):
        raise Fail(f"{p} 是符號連結（不跟隨）")
    if not stat.S_ISREG(st.st_mode):
        raise Fail(f"{p} 不是一般檔案")
    fd = os.open(p, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as f:
        fst = os.fstat(f.fileno())
        if not stat.S_ISREG(fst.st_mode):
            raise Fail(f"{p} 不是一般檔案")
        data = read_limited(f, fst.st_size)
    return data.decode("utf-8", errors="replace")


def load_db(pkgdb):
    """extract 的資料夾 → PkgDB；沒有 dpkg-status → None。檔案的檢查見 read_db_file。"""
    status = read_db_file(Path(pkgdb) / "dpkg-status")
    if status is None:
        return None
    return PkgDB(status, read_db_file(Path(pkgdb) / "extended_states"))


def read_keep(path):
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as e:
        raise Fail(f"讀不到 --keep {path}（{type(e).__name__}）")
    names = [ln.split("#", 1)[0].strip() for ln in lines]
    return sorted({n.split(":", 1)[0] for n in names if n})


class Benefit:
    """open_components（deb）對到的二進位套件；算一個「拿掉的套件集合」少掉幾列。"""

    def __init__(self, db, comps):
        self.items = []          # (元件, 二進位套件集合)
        self.not_found = []
        for c in comps:
            if c.get("type") != "deb":
                continue
            bins = set(component_bins(db, c))
            if bins:
                self.items.append((c, bins))
            else:
                self.not_found.append(c)
        self.total = sum(c["rows"] for c, _ in self.items)

    def of(self, removed, own=None):
        """removed：拿掉後不在映像的套件（含本來就會 autoremove 的）；own：這個選項自己拿掉的（部分拿掉只看它）。"""
        own = removed if own is None else own
        full = [c for c, b in self.items if b <= removed]
        part = [c for c, b in self.items if b & own and not b <= removed]
        tiers = collections.Counter()
        exploitable = 0
        for c in full:
            for k, n in (c.get("tiers") or {}).items():
                if isinstance(n, int):
                    tiers[k] += n
            n = (c.get("states") or {}).get("exploitable")
            exploitable += n if isinstance(n, int) else 0
        return {"rows": sum(c["rows"] for c in full), "exploitable": exploitable, "tiers": dict(sorted(tiers.items())),
                "components": sorted(f"{c['component']} {c.get('version') or ''}".strip() for c in full),
                "partial": sorted(f"{c['component']} {c.get('version') or ''}".strip() for c in part)}


def option(db, ben, label, kind, start, removed, orphans=frozenset()):
    """orphans：現在就沒有人需要的連帶安裝套件（apt autoremove 本來就會拿掉）：算效益時一起算，但不列為這個選項拿掉的。"""
    b = ben.of(set(removed) | set(orphans), set(removed) - set(orphans))
    removed = set(removed) - set(orphans)
    blocked = sorted(n for n in removed if db.essential(n))
    manual_too = sorted(n for n in removed - set(start) if db.manual(n))
    return {"option": label, "kind": kind, "start": sorted(start), "removed_packages": len(removed), "removed": sorted(removed),
            "also_removes_manual": manual_too, "blocked_by_essential": blocked, "feasible": not blocked, **b}


def do_rank(pkgdb, summary, out, json_out, top, base_pkgdb=None, keep=None):
    s, comps = load_summary(summary)
    db = load_db(pkgdb)
    if db is None:
        return "GAP", f"{pkgdb} 沒有 dpkg-status（先執行 pkg_why.py extract）", None
    if bool(base_pkgdb) != bool(keep):
        raise Fail("--base-pkgdb 與 --keep 要一起給")
    ben = Benefit(db, comps)
    orphans = db.removal(set())
    opts = []
    for m in sorted(n for n in db.pkgs if db.manual(n) and not db.base(n)):
        opts.append(option(db, ben, m, "remove", {m}, db.removal({m}), orphans))
    scen = []
    if orphans:
        scen.append(option(db, ben, "apt autoremove（現在就沒有套件需要的連帶安裝套件）", "autoremove", set(), orphans))
    if db.has_ext:
        # 起點和 removal() 的 keep 相同：手動安裝與基本套件（debootstrap 的基本套件常被標成連帶安裝）
        strong = db._forward([n for n in db.pkgs if db.manual(n) or db.base(n)], ("depends",))
        scen.append(option(db, ben, "不裝 Recommends（--no-install-recommends）", "no-recommends", set(),
                           {n for n in db.pkgs if not db.manual(n) and not db.base(n) and n not in strong}, orphans))
    devs = {n for n in db.pkgs if db.manual(n) and is_dev(n)}
    if devs:
        scen.append(option(db, ben, "不裝開發套件（" + ", ".join(sorted(devs)[:4]) + (" …" if len(devs) > 4 else "") + "）", "no-dev",
                           devs, db.removal(devs), orphans))
    base = None
    if base_pkgdb:
        bdb = load_db(base_pkgdb)
        if bdb is None:
            raise Fail(f"{base_pkgdb} 沒有 dpkg-status")
        names = read_keep(keep)
        missing = [n for n in names if n not in db.pkgs]
        new = set(bdb.pkgs) | db._forward([n for n in names if n in db.pkgs], ("depends", "recommends"))
        o = option(db, ben, f"換基底（{Path(base_pkgdb).name}）＋ keep {len(names)} 個", "rebase", set(), set(db.pkgs) - new)
        o["blocked_by_essential"], o["feasible"] = [], True       # 基本套件由候選基底自己提供
        # 候選基底有同名、不同版本的套件：不算少掉也不算留下（新版本的列要掃描新映像才知道）
        changed = sorted(n for n in set(bdb.pkgs) & set(db.pkgs) if bdb.pkgs[n].get("Version") != db.pkgs[n].get("Version"))
        chg = set(changed)
        changed_rows = sorted(((f"{c['component']} {c.get('version') or ''}".strip(), c["rows"]) for c, b in ben.items if b & chg),
                              key=lambda x: (-x[1], x[0]))
        base = {**o, "added": sorted(set(bdb.pkgs) - set(db.pkgs)), "keep_not_installed": missing, "version_changed": changed,
                "version_changed_rows": [{"component": n, "rows": r} for n, r in changed_rows]}
    feas = sorted((o for o in opts if o["feasible"] and o["rows"]), key=lambda o: (-o["rows"], -o["exploitable"], o["removed_packages"], o["option"]))
    blocked = [o for o in opts if not o["feasible"] and o["rows"]]
    other_rows = sum(c["rows"] for c in comps if c.get("type") != "deb")
    res = {"schema": "sca-center-pkg-rank/1", "summary": Path(summary).name, "generated": s.get("generated"),
           "has_extended_states": db.has_ext, "open_rows_deb": ben.total, "open_rows_not_deb": other_rows,
           "not_in_dpkg": sorted(c["component"] for c in ben.not_found), "scenarios": scen, "rebase": base,
           "ranking": feas[:top], "ranking_total": len(feas), "blocked": blocked}

    def row(o):
        t = "、".join(f"{k.upper()} {n}" for k, n in o["tiers"].items())
        extra = ("；也會拿掉手動安裝的 " + ", ".join(o["also_removes_manual"][:4]) + (" …" if len(o["also_removes_manual"]) > 4 else "")
                 if o["also_removes_manual"] else "")
        return [o["option"], o["rows"], o["exploitable"], t or "—", o["removed_packages"],
                ", ".join(o["components"][:5]) + (" …" if len(o["components"]) > 5 else "") + extra]

    head = ["| 選項 | 少掉的列 | 其中受影響 | 層級 | 一起拿掉的套件數 | 少掉的元件 |", "|---|---|---|---|---|---|"]
    md = ["# 拿掉套件／換基底的效益排行（估計）", "",
          f"未處理的列（deb 套件）共 {ben.total} 列；不是 deb 的（核心、Python 等）另有 {other_rows} 列，不在這份估計內。"
          "「列」是漏洞比對列（同一個 CVE 在不同套件各算一列），不是去重的 CVE 數。下面每個選項估計「拿掉之後**少掉**多少列」：一個原始碼套件的列只在它所有已安裝的"
          "二進位套件都被拿掉時才算。依 dpkg 的依賴資料推算（apt 的拿掉＋autoremove），**不是**實際測過：自家程式直接載入的函式庫、"
          "腳本呼叫的指令、客戶指定的套件都看不到，拿掉前要在實際板子上確認功能。", ""]
    if not db.has_ext:
        md += ["**映像裡沒有 extended_states**：手動／連帶安裝是推定的（沒有其他套件依賴的當手動），估計可能偏多。", ""]
    md += ["## 情境", ""]
    if scen:
        md += head + ["| " + " | ".join(cell(x) for x in row(o)) + " |" for o in scen] + [""]
    else:
        md += ["（沒有：需要 extended_states 才能算 Recommends；沒有手動安裝的開發套件）", ""]
    if base:
        md += ["## 換基底", "", *head, "| " + " | ".join(cell(x) for x in row(base)) + " |", "",
               f"候選基底有、目前映像沒有的套件 {len(base['added'])} 個（漏洞要掃描新映像才知道）"
               + (f"：{', '.join(base['added'][:10])}{' …' if len(base['added']) > 10 else ''}" if base["added"] else "") + "。"]
        if base["version_changed"]:
            md += [f"候選基底裡同名、不同版本的套件 {len(base['version_changed'])} 個：不算少掉也不算留下，新版本的列要掃描新映像才知道"
                   + ("（目前這些套件的列：" + ", ".join(x["component"] + " " + str(x["rows"]) for x in base["version_changed_rows"][:8])
                      + (" …" if len(base["version_changed_rows"]) > 8 else "") + "）" if base["version_changed_rows"] else "") + "。"]
        md += ["**新映像自己的列沒有評估**：上面的數字只是目前映像少掉的列，換基底後要重新掃描。"]
        if base["keep_not_installed"]:
            md += [f"keep 清單裡目前映像沒有安裝的：{', '.join(base['keep_not_installed'])}（依賴無法推算）。"]
        md += [""]
    md += [f"## 拿掉單一套件（前 {len(feas[:top])} 個，共 {len(feas)} 個有效益）", ""]
    md += (head + ["| " + " | ".join(cell(x) for x in row(o)) + " |" for o in feas[:top]]) if feas else ["（沒有：拿掉任何一個手動安裝的套件都不會少掉整個原始碼套件的列）"]
    md += [""]
    part = sorted({p for o in feas[:top] for p in o["partial"]})
    if part:
        md += [f"只拿掉部分二進位套件、所以不算少掉的元件：{', '.join(part[:10])}{' …' if len(part) > 10 else ''}。", ""]
    if blocked:
        md += ["## 不可行（會拿掉基本套件）", "", "| 選項 | 少掉的列 | 會拿掉的基本套件 |", "|---|---|---|"]
        md += [f"| {cell(o['option'])} | {o['rows']} | {cell(', '.join(o['blocked_by_essential'][:5]))} |" for o in blocked[:top]] + [""]
    if ben.not_found:
        md += [f"dpkg 裡找不到的元件 {len(ben.not_found)} 個（不是用 apt 安裝的，不在估計內）："
               + ", ".join(sorted(c["component"] for c in ben.not_found)[:10]) + "。", ""]
    Path(out).write_text("\n".join(md) + "\n", encoding="utf-8")
    if json_out:
        Path(json_out).write_text(json.dumps(res, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    best = feas[0] if feas else None
    detail = (f"未處理 {ben.total} 列；單一套件效益最大：" + (f"{best['option']} {best['rows']} 列" if best else "沒有")
              + "".join(f"；{o['kind']} {o['rows']} 列" for o in scen)
              + (f"；換基底少掉 {base['rows']} 列（新映像的列未評估）" if base else "")
              + ("" if db.has_ext else "；沒有 extended_states（推定）"))
    ok = db.has_ext and not ben.not_found and not (base and base["keep_not_installed"])
    return ("OK" if ok else "ATTENTION"), detail, res


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("extract")
    a.add_argument("--from", dest="from_", required=True)
    a.add_argument("--prefix")
    a.add_argument("--out", required=True)
    a = sub.add_parser("report")
    a.add_argument("--pkgdb", required=True)
    a.add_argument("--summary", required=True)
    a.add_argument("--out", required=True)
    a.add_argument("--top", type=int, default=30)
    a = sub.add_parser("rank")
    a.add_argument("--pkgdb", required=True)
    a.add_argument("--summary", required=True)
    a.add_argument("--out", required=True)
    a.add_argument("--json")
    a.add_argument("--top", type=int, default=20)
    a.add_argument("--base-pkgdb")
    a.add_argument("--keep")
    a = ap.parse_args(argv)
    tag = {"extract": "PKGDB", "report": "D-pkg-why", "rank": "D-pkg-rank"}[a.cmd]
    try:
        if a.cmd == "extract":
            st, detail = do_extract(a.from_, a.prefix, a.out)
        elif a.cmd == "report":
            st, detail, _ = do_report(a.pkgdb, a.summary, a.out, max(1, a.top))
        else:
            st, detail, _ = do_rank(a.pkgdb, a.summary, a.out, a.json, max(1, a.top), a.base_pkgdb, a.keep)
    except (Fail, OSError) as e:
        print(f"{tag}\tFAIL\t{e}")
        return 3
    print(f"{tag}\t{st}\t{detail}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
