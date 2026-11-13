#!/usr/bin/env python3
"""產品自有軟體併進產品 SBOM：設定 sbom.own_software 列出的 rootfs 路徑或樣式 → 雜湊 → pkg:generic 元件。

用法：
  python3 -I own_software.py --from <rootfs tar｜刷機包 tbz2｜rootfs 資料夾> [--prefix <rootfs 在刷機包裡的路徑>]
                             --config <產品的 config.json> --out <資料夾> [--max-file-size <bytes>]
  python3 -I own_software.py --config <config.json> --configured     （有設定 sbom.own_software → exit 0，沒有 → exit 1）
  python3 -I own_software.py [--config <config.json>] --declaration --out <資料夾>
                             （設定沒有列自有軟體時：宣告的結果寫成 own-software.json，印 B-own-software 那一行；見下面「沒有列自有軟體」）

寫出 --out/own-software.json，stdout 第一行 `B-own-software<TAB>狀態<TAB>說明`：
OK（每個樣式都對到檔案、都算了雜湊）；GAP（有樣式對不到檔案、符號連結被拒絕、超過大小上限、讀不到）；FAIL（來源讀取失敗）；
SKIP（設定沒有 sbom.own_software：什麼都不寫）。之後每個 GAP 一行 `GAP<TAB>樣式或路徑<TAB>原因`，
版本未知的檔案一行 `INFO<TAB>路徑<TAB>版本未知…`（最多 LIST_MAX 行）。退出碼：OK／SKIP 0、GAP 2、FAIL 1、參數錯誤 64。
cra_report.py 讀 <scan>/../own-software/own-software.json（或 --own-software），用當時的設定（名稱、版本、製造商）建元件。

沒有列自有軟體（sbom.own_software 沒寫或是空陣列）：檢查不可以悄悄消失（scan-flash-package.sh 用 --declaration 寫狀態列）。
- 沒有宣告（沒寫、空陣列但沒有理由、或根本沒有產品設定）→ GAP「沒有宣告自有軟體，無法確認產品自有元件是否都在 SBOM」。
- 明確宣告沒有：`"own_software": []` 加上 `"own_software_none_reason": "<理由>"` → OK，說明寫「製造商宣告沒有自有軟體：<理由>」
  （是宣告，掃描沒有驗證；理由會出現在 sbom.md）。
- 列了自有軟體又寫 own_software_none_reason → 設定矛盾，GAP（設定錯誤）。
--declaration 寫的 own-software.json 只有 declaration 與 status（沒有 patterns／files）；cra_report.py 讀到它才在 SBOM 文件標出來，
沒有這個檔案的流程（例如只跑 cra_report.py）輸出照舊。

設定（config.schema.json 的 sbom.own_software）：字串或 {"path": …, "name": …, "version": …} 的陣列。
- path：rootfs 裡的路徑（開頭的 / 可寫可不寫），每一層可用 fnmatch 萬用字元（* ? [..]；不跨 /、不對到 . 開頭的名稱；不支援 **）。
  含 .. 的路徑是設定錯誤。只照設定：不用啟發式猜哪些檔案是自有的。
- name：只在這一筆剛好對到一個檔案時用；否則用檔名（.ko 用 modinfo 的 name）。
- version：設定直接給的版本；沒給時 .ko 用 modinfo 的 version；都沒有 → 版本未知（不填，不從檔名猜）。

映像是不可信資料（同 image_check.py，讀法也共用它的程式）：tar 只串流讀，不解開到磁碟；名稱是絕對路徑或含 .. 的成員拒絕；
符號連結只在記憶體裡的映像命名空間解析（絕對連結從映像的根開始；相對連結的 .. 超出 rootfs 的根 → 拒絕，記 GAP；跳躍有上限）；
資料夾來源用 lstat 走訪，讀檔案時一層一層 openat（每層 O_NOFOLLOW），fstat 的 (st_dev, st_ino, st_size) 要和走訪時的 lstat
相同（不同 → GAP）；硬連結依 (st_dev, st_ino) 合成一個檔案。不執行映像裡的任何東西。每個檔案、總量、樣式數、對到的檔案數都有上限。
串流讀的時候先算路徑字面上符合樣式的檔案；經過符號連結或硬連結才對到的檔案，tar 來源再讀一次：用第一次記的成員序號取同一個
成員（重複的名稱以最後一個為準，和命名空間一致；硬連結取它之前最後一次出現的同名成員，和 GNU tar 解開時一樣），核對名稱、
型別、大小與來源檔的 (st_dev, st_ino, st_size, mtime, ctime)，對不上 → GAP。
FAIL 的訊息不寫主機的絕對路徑。
輸出穩定：檔案依路徑排序、樣式依設定的順序，不含時間與本機的絕對路徑。
"""
import argparse
import collections
import contextlib
import fnmatch
import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
import tarfile
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCHEMA = "sca-center-own-software/1"
TOOL_VERSION = "2026-11-09.3"
FILE_MAX = 256 << 20          # 單檔：超過的不讀、不算雜湊（GAP）
TOTAL_MAX = 8 << 30           # 算雜湊的總量
PATTERNS_MAX = 256            # sbom.own_software 的筆數
MATCH_MAX = 10_000            # 對到的檔案（全部樣式合計）
GLOB_WORK = 2_000_000         # 展開萬用字元時看過的名稱數
PATTERN_LEN = 1024
LIST_MAX = 50                 # stdout 的 GAP／版本未知最多各印幾行；sbom.md 的表最多幾列
KO_SUFFIX = (".ko", ".ko.xz", ".ko.gz", ".ko.zst")
REF = "sca-center:own:"
SOURCE = "own software (configuration sbom.own_software)"


class Fail(Exception):
    pass


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


_IC = _FW = None


def icmod():
    """image_check.py（映像的讀法與命名空間；python3 -I 不把這個資料夾放進 sys.path，依路徑載入）。"""
    global _IC
    if _IC is None:
        _IC = _load("sca_center_image_check", HERE / "image_check.py")
    return _IC


def fwmod():
    """firmware_bom.py（modinfo 解析、元件的共用小工具）。"""
    global _FW
    if _FW is None:
        _FW = _load("sca_center_firmware_bom", HERE / "firmware_bom.py")
    return _FW


# ---------- 設定 ----------

def configured(cfg):
    """設定有沒有 sbom.own_software（非空的陣列）。沒有 → 什麼都不做（輸出和沒有這個功能時一樣）。"""
    sb = cfg.get("sbom") if isinstance(cfg, dict) else None
    v = sb.get("own_software") if isinstance(sb, dict) else None
    return isinstance(v, list) and len(v) > 0


NONE_REASON_KEY = "own_software_none_reason"
NONE_REASON_MAX = 500
UNDECLARED = ("no own software declared (configuration sbom.own_software): it cannot be confirmed that all of the manufacturer's "
              "own components are in the SBOM; list them, or declare that there are none with sbom.own_software = [] and "
              "sbom.own_software_none_reason")


def declaration(cfg):
    """設定對自有軟體的宣告 → (kind, 說明)。kind：listed（有列）、none（明確宣告沒有，說明＝理由）、undeclared（沒宣告）、
    conflict（列了又寫沒有的理由）。cfg 是 None（沒有產品設定）→ undeclared。"""
    sb = cfg.get("sbom") if isinstance(cfg, dict) else None
    sb = sb if isinstance(sb, dict) else {}
    v, why = sb.get("own_software"), sb.get(NONE_REASON_KEY)
    has_why = isinstance(why, str) and why.strip() != ""
    if isinstance(v, list) and v:
        return ("conflict", f"sbom.own_software lists entries but sbom.{NONE_REASON_KEY} is also set: the configuration contradicts itself") \
            if has_why else ("listed", None)
    if isinstance(v, list) and has_why:
        w = " ".join(why.split())
        if len(w) > NONE_REASON_MAX or any(ord(c) < 32 or ord(c) == 127 for c in w):
            return "undeclared", f"sbom.{NONE_REASON_KEY} is too long or has control characters: " + UNDECLARED
        return "none", w
    if v is not None and not isinstance(v, list):
        return "undeclared", "sbom.own_software is not a list: " + UNDECLARED
    return "undeclared", (UNDECLARED if cfg is not None else "no product configuration: " + UNDECLARED)


def declaration_info(cfg, doc_name="own-software.json"):
    """沒有列自有軟體時給 cra_report.py 的 info（和 build() 的 info 同樣的鍵，text() 也能用）。"""
    kind, why = declaration(cfg)
    mf = (cfg.get("manufacturer") or {}) if isinstance(cfg, dict) else {}
    info = {"status": "OK" if kind == "none" else "GAP", "file": doc_name, "supplier": mf.get("name") if isinstance(mf, dict) else None,
            "config_errors": [], "patterns": [], "components": 0, "merged_with_flash_modules": [], "unmerged_flash_modules": [],
            "version_unknown": 0, "gaps": [] if kind == "none" else [why], "files": [], "declaration": kind}
    if kind == "none":
        info["none_reason"] = why
    return info


def norm_pattern(p):
    """設定的路徑 → (正規化的樣式, 錯誤)。開頭的 / 拿掉；空的層與 . 拿掉；.. 、** 、控制字元、過長 → 錯誤。"""
    if not isinstance(p, str) or not p.strip():
        return None, "path is empty"
    if len(p) > PATTERN_LEN or any(ord(c) < 32 or ord(c) == 127 for c in p):
        return None, "path too long or has control characters"
    parts = [x for x in p.strip().split("/") if x not in ("", ".")]
    if not parts:
        return None, "path is the root directory"
    if ".." in parts:
        return None, "path contains .. (paths are inside the root file system)"
    if any("**" in x for x in parts):
        return None, "** is not supported (use one * per directory level)"
    if len(parts) >= 256:
        return None, "path has too many levels"
    return "/".join(parts), None


def entries(cfg):
    """sbom.own_software → (筆的清單 [{pattern, name, version}], 錯誤)。順序同設定；同一個樣式出現兩次 → 合成一筆。"""
    raw = ((cfg.get("sbom") or {}).get("own_software") or []) if isinstance(cfg, dict) else []
    out, errs, seen = [], [], {}
    if not isinstance(raw, list):
        return [], ["sbom.own_software is not a list"]
    if len(raw) > PATTERNS_MAX:
        errs.append(f"sbom.own_software has {len(raw)} entries; only the first {PATTERNS_MAX} are used")
        raw = raw[:PATTERNS_MAX]
    for i, x in enumerate(raw):
        d = x if isinstance(x, dict) else {"path": x}
        pat, why = norm_pattern(d.get("path"))
        if why:
            errs.append(f"sbom.own_software[{i}]: {why}")
            continue
        e = {"pattern": pat, "name": _s(d.get("name")), "version": _s(d.get("version"))}
        if pat in seen:
            o = out[seen[pat]]
            for k in ("name", "version"):
                if e[k] and o[k] and e[k] != o[k]:
                    errs.append(f"sbom.own_software: {pat} listed twice with different {k}s ({o[k]}, {e[k]}); {k} not used")
                    o[k + "_conflict"] = True
                o[k] = o[k] or e[k]
            continue
        seen[pat] = len(out)
        out.append(e)
    return out, errs


def _s(v, limit=300):
    if isinstance(v, str):
        v = v.strip()
        return v[:limit] if v else None
    return None


def wild(part):
    return any(c in part for c in "*?[")


def name_match(name, part):
    """一層的比對：萬用字元不對到 . 開頭的名稱（shell 的規則；樣式自己以 . 開頭時可以）。"""
    if not wild(part):
        return name == part
    if name.startswith(".") and not part.startswith("."):
        return False
    return fnmatch.fnmatchcase(name, part)


def literal_match(path, pats):
    """串流讀的時候：路徑字面上（不經過符號連結）符合某個樣式 → 先算雜湊（只是少讀一次，最後以命名空間解析的結果為準）。"""
    parts = path.split("/")
    for pp in pats:
        if len(pp) == len(parts) and all(name_match(a, b) for a, b in zip(parts, pp)):
            return True
    return False


def is_ko(path):
    return path.endswith(KO_SUFFIX)


# ---------- 映像的命名空間（image_check.Image） ----------

NOT_FOUND = "not found"
LINK_MISSING = "symbolic link target not in the root file system"
ESCAPE = "symbolic link points outside the root file system (.. above /): rejected"


def resolve_strict(img, path):
    """映像裡的路徑 → (實際路徑, None) 或 (None, 原因)。和 image_check.Image.resolve 一樣只查記憶體裡的命名空間，
    但相對連結的 .. 超出 rootfs 的根時拒絕（不默默停在根：這種連結多半指向建置主機的路徑）。
    找不到的那一層來自某個連結的目標 → LINK_MISSING；是原本路徑的一層（例如穿過有效的 /lib → usr/lib 之後才缺）→ NOT_FOUND。"""
    ic = icmod()
    queue = collections.deque((p, False) for p in path.split("/") if p not in ("", "."))    # (名稱, 是否來自連結的目標)
    out, hops = [], 0
    while queue:
        c, from_link = queue.popleft()
        if c == "..":
            if not out:
                return None, ESCAPE
            out.pop()
            continue
        cand = "/".join(out + [c])
        node = img.nodes.get(cand)
        if node is None:
            return None, (LINK_MISSING if from_link else NOT_FOUND)
        if node[0] == "symlink":
            hops += 1
            tgt = node[3] or ""
            if hops > ic.MAX_HOPS:
                return None, "too many symbolic links (loop?)"
            if not tgt or len(tgt) > ic.LINK_MAX:
                return None, "symbolic link with an empty or too long target"
            if tgt.startswith("/"):
                out = []                  # 絕對連結：從映像的根開始（裝置上就是這樣解析）
            queue.extendleft(reversed([(p, True) for p in tgt.split("/") if p not in ("", ".")]))
            continue
        if queue and node[0] != "dir":
            return None, "a path component is not a directory"
        out.append(c)
    return "/".join(out), None


def is_symlink_name(img, lp):
    """列出的路徑最後一層本身是不是符號連結（上層照樣解析）。"""
    parent, _, name = lp.rpartition("/")
    real, why = resolve_strict(img, parent) if parent else ("", None)
    if why:
        return False
    node = img.nodes.get(f"{real}/{name}" if real else name)
    return node is not None and node[0] == "symlink"


def expand(img, pattern, budget):
    """一個樣式在映像命名空間裡展開 → ([(列出的路徑, 實際路徑)], [(列出的路徑, 原因)], 是否超過工作量)。
    每一層先解析目前的資料夾（跟隨符號連結），萬用字元對資料夾的子項目比對（依名稱排序）；萬用字元在中間層展開出來的候選
    只留解析後是資料夾的（和最後一層只留檔案一樣）。記原因的情況：
    - 連結逃出 rootfs（.. 超出根）：一律記（裝置上那個路徑可能真的解析到別的檔案）；
    - 列出的名稱本身是指不到東西的連結：記；
    - 不是資料夾、連結迴圈、空的連結：只在到那一層為止都是樣式字面寫出的路徑時記（萬用字元展開出來的不相干項目不算 GAP）；
    - 找不到：不另外記（整個樣式一個都沒對到時才是 GAP）。"""
    cur, probs, cut = [""], [], False
    parts = pattern.split("/")

    def report(lp, why, literal):
        if why == ESCAPE or (literal and why not in (NOT_FOUND, LINK_MISSING)):
            probs.append((lp, why))

    for i, part in enumerate(parts):
        last = i == len(parts) - 1
        literal_before = not any(wild(x) for x in parts[:i])          # 到上一層為止都是字面寫出的
        literal = literal_before and not wild(part)
        nxt = []
        for base in cur:
            if wild(part):
                real, why = resolve_strict(img, base) if base else ("", None)
                if why:
                    report(base, why, literal_before)
                    continue
                node = img.nodes.get(real) if real else ["dir"]
                if node is None or node[0] != "dir":
                    if node is not None and literal_before:
                        probs.append((base, "a path component is not a directory"))
                    continue
                names = img.children.get(real, ())
                budget[0] -= 1 + len(names)
                if budget[0] < 0:
                    cut = True
                    break
                cands = sorted(n for n in names if name_match(n, part))
            else:
                budget[0] -= 1
                cands = [part]
            for n in cands:
                lp = f"{base}/{n}" if base else n
                if not last:
                    if wild(part):                    # 萬用字元的候選：只留資料夾
                        real, why = resolve_strict(img, lp)
                        if why:
                            report(lp, why, False)
                            continue
                        node = img.nodes.get(real)
                        if node is None or node[0] != "dir":
                            continue
                    nxt.append(lp)
                    continue
                real, why = resolve_strict(img, lp)
                if why == LINK_MISSING and is_symlink_name(img, lp):
                    probs.append((lp, why))
                    continue
                if why:
                    report(lp, why, literal)
                    continue
                node = img.nodes.get(real)
                if node is None:
                    if is_symlink_name(img, lp):
                        probs.append((lp, LINK_MISSING))
                elif node[0] in ("file", "hardlink"):
                    nxt.append((lp, real))
                elif wild(part):
                    continue                 # 萬用字元對到的資料夾、裝置等：不是檔案，略過（樣式要的是檔案）
                elif node[0] == "dir":
                    probs.append((lp, "is a directory (list the files, for example with a * pattern)"))
                else:
                    probs.append((lp, f"not a regular file ({node[0]})"))
        if cut:
            break
        cur = nxt
    return (cur if not cut else []), probs, cut


# ---------- 讀取與雜湊 ----------

class Changed(OSError):
    """讀取時發現內容不是走訪（或第一次讀取）時看到的那一份。"""


class Reading:
    def __init__(self, file_max, total_max):
        self.file_max, self.total_max, self.total = file_max, total_max, 0
        self.hashed = {}          # 映像裡的路徑 → 結果（一般檔案）

    def digest(self, path, size, opener):
        """→ {size, sha256, sha512, elf, modinfo…} 或 {"error": 原因}。tar 成員的大小來自標頭：超過上限就不讀。"""
        if size > self.file_max:
            return {"error": f"larger than the size limit ({size} > {self.file_max} bytes): not hashed", "size": size}
        if self.total + size > self.total_max:
            return {"error": f"total hashing limit reached ({self.total_max} bytes): not hashed", "size": size}
        try:
            f = opener()
        except Changed as e:
            return {"error": e.strerror}
        except OSError as e:
            return {"error": f"unreadable ({e.strerror or type(e).__name__})"}
        keep = [] if is_ko(path) else None
        h2, h5, n, head = hashlib.sha256(), hashlib.sha512(), 0, b""
        mod_max = fwmod().MOD_MAX
        with contextlib.closing(f):
            while True:
                try:
                    b = f.read(min(1 << 20, self.file_max + 1 - n))
                except OSError as e:
                    return {"error": f"unreadable ({e.strerror or type(e).__name__})"}
                if not b:
                    break
                if len(head) < 4:
                    head += b[:4 - len(head)]
                h2.update(b)
                h5.update(b)
                n += len(b)
                if keep is not None:
                    if n > mod_max:
                        keep = None
                    else:
                        keep.append(b)
                if n > self.file_max:          # 資料夾來源：讀的時候檔案變大
                    return {"error": f"larger than the size limit (> {self.file_max} bytes): not hashed", "size": n}
        if n != size:
            return {"error": f"size changed while reading ({size} bytes expected, {n} read): not used"}
        self.total += n
        r = {"size": n, "sha256": h2.hexdigest(), "sha512": h5.hexdigest(), "elf": head == b"\x7fELF"}
        if is_ko(path):
            r.update(fwmod().module_info(b"".join(keep), path) if keep is not None
                     else {"modinfo": None, "modinfo_note": "module larger than the limit"})
        return r


def open_under(base, rel, expect=None):
    """資料夾來源的讀取：從 base 一層一層 openat（O_NOFOLLOW；中間層要是資料夾），最後一層只開一般檔案。
    expect：走訪時 lstat 的 (st_dev, st_ino, st_size)；fstat 不一樣 → Changed（檔案在走訪之後被換掉）。"""
    parts = rel.split("/")
    fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0))
    try:
        for p in parts[:-1]:
            nfd = os.open(p, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=fd)
            os.close(fd)
            fd = nfd
        lfd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0), dir_fd=fd)
    finally:
        os.close(fd)
    try:
        st = os.fstat(lfd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError(22, "not a regular file")
        if expect is not None and (st.st_dev, st.st_ino, st.st_size) != tuple(expect):
            raise Changed(116, "file changed between the directory walk and the read (device, inode or size differ): not used")
        return os.fdopen(lfd, "rb")
    except BaseException:
        os.close(lfd)
        raise


def iter_dir(fp, src, pp, img, ident, first_inode):
    """資料夾來源（image_check.iter_dir 的走訪：flash_package.dir_entries，lstat、不跟隨符號連結），但檔案用 open_under 打開
    （每一層 O_NOFOLLOW，fstat 和走訪時的 lstat 比對）。ident：路徑 → (st_dev, st_ino, st_size)；first_inode：同一個 inode
    （硬連結）第一次出現的路徑（走訪依名稱排序，結果穩定）。"""
    base = os.path.abspath(src)
    for part in pp:
        base = os.path.join(base, part)
        st = os.lstat(base)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise Fail(f"--prefix 的 {part} 是符號連結或不是資料夾（不跟隨）")
    for e in fp.dir_entries(base):
        path = "/".join(e.parts)
        if e.kind in ("unreadable", "unreadable_dir"):
            img.note("unreadable", path)
            continue
        opener, size = None, 0
        if e.kind == "file":
            try:
                st = os.lstat(e.raw)
            except OSError:
                img.note("unreadable", path)
                continue
            if not stat.S_ISREG(st.st_mode):
                img.note("unreadable", path)
                continue
            ident[path] = (st.st_dev, st.st_ino, st.st_size)
            if st.st_nlink > 1:
                first_inode.setdefault((st.st_dev, st.st_ino), path)
            opener, size = (lambda p=path, b=base: open_under(b, p, ident[p])), st.st_size
        yield path, e.kind, e.mode, size, e.link, None, opener


def iter_tar(fp, t, pp, img, pos):
    """tar 來源（image_check.iter_tar 的規則：拒絕絕對路徑與 ..、rootfs 外的略過），另外記每個成員在 tar 裡的序號
    （pos：rootfs 裡的路徑 → 最後一次出現的序號；硬連結 → 它自己的序號），第二次讀取用序號取同一個成員、核對大小與型別。"""
    n = len(pp)
    for idx, m in enumerate(fp.members(t)):
        parts = fp.split_name(m.name)
        if parts is None:
            img.note("rejected", m.name)
            continue
        if tuple(parts[:n]) != pp or len(parts) == n:
            continue
        path = "/".join(parts[n:])
        k = fp.tar_kind(m)
        link = None
        if k == "symlink":
            link = m.linkname
        elif k == "hardlink":
            lp = fp.split_name(m.linkname)
            if lp is None:
                img.note("rejected", m.name)
                continue
            link = "/".join(lp[n:]) if tuple(lp[:n]) == pp and len(lp) > n else "\0" + "/".join(lp)  # \0：rootfs 外
        pos[path] = idx
        yield path, k, m.mode & 0o7777, (m.size if k == "file" else 0), link, m.uid, (lambda m=m: t.extractfile(m))


def source_id(src):
    """來源檔的身分：兩次讀取之間核對。含 st_ctime_ns：同樣大小的原地改寫就算把 mtime 改回去，ctime 也會變（使用者改不回 ctime）。
    看不出來的：和第一次讀取落在同一個檔案系統時間刻度內（ext4 約幾毫秒）的同大小原地改寫。"""
    st = os.stat(src)
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def canonical(img, real, ident=None, first_inode=None, pos=None, pp=()):
    """→ (元件的路徑, 錯誤, 第二次讀取要取的內容或 None)。
    - 資料夾來源：同一個 (st_dev, st_ino) 的檔案合併到第一次走訪到的路徑（和 tar 一樣只算一個檔案）。
    - tar 的硬連結的內容是「硬連結之前最後一個同名成員」（GNU tar 解開時就是這樣）：
      - 目標現在的那一筆（命名空間裡最後一次出現）在硬連結之前、是一般檔案 → 同一份內容，合併到目標的路徑；
      - 目標在硬連結之後才被重新定義（換成另一個檔案、符號連結…），或在這個 rootfs 以外（\\0 開頭，刷機包裡另一個 rootfs）
        → 留在硬連結自己的路徑，第二次讀取取 ("before", 壓縮檔全名, 硬連結的序號, 顯示用的名稱)；
      - 目標在硬連結之前已經是符號連結等（不是一般檔案）→ 錯誤（GAP）。"""
    if ident is not None and real in ident:
        return first_inode.get(ident[real][:2], real), None, None
    node = img.nodes.get(real)
    if node is None or node[0] not in ("file", "hardlink"):
        return real, "not a regular file", None
    if node[0] == "file":
        return real, None, None
    pos = pos or {}
    h, link, hops = pos.get(real, -1), node[3] or "", 0
    while True:
        if not link:
            return real, "hard link with an empty target", None
        if link.startswith("\0"):
            return real, None, ("before", link[1:], h, link[1:])
        tnode, tpos = img.nodes.get(link), pos.get(link)
        if tnode is not None and tpos is not None and tpos < h:
            if tnode[0] == "file":
                return link, None, None
            if tnode[0] != "hardlink":
                return real, f"hard link to a {tnode[0]} (not a regular file)", None
            hops += 1
            if hops > 8:
                return real, "hard link chain too long", None
            h, link = tpos, tnode[3] or ""
            continue
        return real, None, ("before", "/".join(pp + tuple(link.split("/"))), h, link)


def printable(path):
    """路徑原樣可以寫進輸出（沒有控制字元、不是無法編碼的名稱）；否則 clean() 之後可能和別的路徑相同 → 不當元件，記 GAP。"""
    return icmod().clean(path, PATH_LIMIT) == path


PATH_LIMIT = 8192


def second_read_tar(fp, src, pp, img, rd, want, pos, sid):
    """tar 的第二次讀取。want 的鍵：
    - ("at", 路徑)：用第一次讀取記的序號取同一個成員（重複的名稱以最後一個為準，和命名空間一致），核對名稱、型別、大小；
    - ("before", 壓縮檔全名, 硬連結的序號, 顯示名稱)：硬連結之前最後一次出現的同名成員。每出現一次就重設（最後一次不是一般檔案
      → GAP，不拿更早的一般檔案），並核對硬連結那個成員還是指向它。
    對不上 → 不用那份內容（GAP）。最後再核對來源檔的身分。→ {鍵: 結果}"""
    changed = {"error": "content changed between the two reads of the archive (member name, type or size differ): not used"}
    at, before, hl, res = {}, {}, {}, {}
    for w in want:
        if w[0] == "at":
            at[pos[w[1]]] = w
        else:
            before.setdefault(w[1], []).append(w)
            hl.setdefault(w[2], []).append(w)
    last = max([*at, *hl], default=-1)
    with fp.open_stream(src) as t:
        for idx, m in enumerate(fp.members(t)):
            if idx > last:
                break
            parts = fp.split_name(m.name)
            full = "/".join(parts) if parts is not None else None
            kind = fp.tar_kind(m)
            if idx in at:
                w = at[idx]
                node = img.nodes.get(w[1])
                if full != "/".join(pp + (w[1],)) or kind != "file" or node is None or node[0] != "file" or m.size != node[2]:
                    res[w] = changed
                else:
                    res[w] = rd.digest(w[1], m.size, lambda m=m: t.extractfile(m))
            ws = [w for w in before.get(full, ()) if idx < w[2]]
            if ws:
                r = (rd.digest(full, m.size, lambda m=m: t.extractfile(m)) if kind == "file" else
                     {"error": f"the hard link's target is a {kind} at that point of the archive (not a regular file)"})
                for w in ws:
                    res[w] = r
            for w in hl.get(idx, ()):
                lp = fp.split_name(m.linkname) if kind == "hardlink" else None
                if lp is None or "/".join(lp) != w[1]:
                    res[w] = changed
    if source_id(src) != sid:
        return {w: {"error": "the source archive changed during the second read: not used"} for w in want}
    return res


def collect(src, prefix, ents, file_max=FILE_MAX, total_max=TOTAL_MAX):
    """→ own-software.json 的內容（不含 tool／schema）。ents：entries() 的結果。"""
    ic = icmod()
    fp = ic.flash_package()
    pp = ()
    if prefix:
        pp = tuple(fp.split_name(prefix) or ())
        if not pp:
            raise Fail(f"--prefix 不合法：{prefix}")
    img = ic.Image()
    rd = Reading(file_max, total_max)
    pats = [e["pattern"].split("/") for e in ents]
    ident, first_inode, pos = None, None, {}

    def feed(it):
        for path, kind, mode, size, link, uid, opener in it:
            if len(path) > ic.PATH_MAX or path.count("/") >= ic.DEPTH_MAX:
                img.note("rejected", path[:200])
                continue
            img.add(path, kind, mode, size, link, uid)
            rd.hashed.pop(path, None)                 # 同一路徑再出現（tar 後面的覆蓋前面的）
            if kind == "file" and literal_match(path, pats):
                rd.hashed[path] = rd.digest(path, size, opener)

    sid = None
    if os.path.isdir(src):
        stype = "dir"
        ident, first_inode = {}, {}
        feed(iter_dir(fp, src, pp, img, ident, first_inode))
    elif os.path.isfile(src):
        stype = "archive" if pp else "rootfs-tar"
        sid = source_id(src)
        try:
            with fp.open_stream(src) as t:
                feed(iter_tar(fp, t, pp, img, pos))
                tpos = getattr(getattr(t, "fileobj", None), "pos", None)
                if isinstance(tpos, int) and tpos < t.offset + tarfile.BLOCKSIZE:
                    raise Fail(f"tar 在中途結束（讀到 {tpos} bytes，最後一個標頭在 {t.offset}）：檔案不完整")
        except fp.Fail as e:
            raise Fail(str(e))
        except (tarfile.TarError, EOFError) as e:
            raise Fail(f"tar 讀取失敗：{ic.clean(e, 200)}")
    else:
        raise Fail(f"--from 不是檔案也不是資料夾：{os.path.basename(os.path.abspath(src))}")
    if not img.nodes:
        raise Fail("來源裡沒有任何項目" + (f"（--prefix {'/'.join(pp)}）" if pp else ""))

    # 樣式在命名空間裡展開；硬連結（同一個檔案的另一個名稱）合併到內容所在的路徑
    budget, files, pat_out, problems, matched_total = [GLOB_WORK], {}, [], [], 0
    for e in ents:
        found, probs, cut = expand(img, e["pattern"], budget)
        reasons = []
        if cut:
            reasons.append(f"too many names to search (limit {GLOB_WORK}): not completely searched")
        n = 0
        for lp, real in found:
            key, err, how = canonical(img, real, ident, first_inode, pos, pp)
            if key not in files and matched_total >= MATCH_MAX:
                reasons.append(f"more than {MATCH_MAX} files matched in total: the rest are not in the SBOM")
                break
            if key not in files:
                matched_total += 1
                files[key] = {"path": key, "listed_as": set(), "patterns": set(), "names": set()}
                if err:
                    files[key]["result"] = {"error": err}
                if how:
                    files[key]["how"] = how
            files[key]["listed_as"].add(lp)
            files[key]["names"].add(real)
            files[key]["patterns"].add(e["pattern"])
            n += 1
        for lp, why in probs:
            problems.append({"path": ic.clean(lp), "pattern": e["pattern"], "reason": why})
        if not n and not probs:
            reasons.append("listed but not found: no file in the root file system matches")
        pat_out.append({"pattern": e["pattern"], "matched": n, "status": "GAP" if reasons or probs else "OK",
                        "reasons": sorted(set(reasons)) + sorted({f"{ic.clean(lp)}: {why}" for lp, why in probs})})

    # 還沒算雜湊的 → 第二次讀取（("at", 路徑) 或硬連結的 ("before", 全名, 序號, 名稱)，見 canonical）
    want = {}
    for key, f in files.items():
        if "result" in f:
            continue
        if not printable(key):
            f["result"] = {"error": "file name has control or non-UTF-8 characters (shown escaped): not added"}
            continue
        if f.get("how"):
            f["hardlink_of"] = f["how"][3]
            want.setdefault(f["how"], []).append(key)
        elif key in rd.hashed:
            f["result"] = rd.hashed[key]
        else:
            want.setdefault(("at", key), []).append(key)
    if want and stype == "dir":
        base = os.path.join(os.path.abspath(src), *pp)
        for w, keys in sorted(want.items()):
            tgt = w[1]
            r = rd.digest(tgt, img.nodes[tgt][2], lambda t=tgt: open_under(base, t, ident.get(t)))
            for key in keys:
                files[key]["result"] = r
    elif want:
        if source_id(src) != sid:
            res = {t: {"error": "the source archive changed between the two reads: not used"} for t in want}
        else:
            try:
                res = second_read_tar(fp, src, pp, img, rd, want, pos, sid)
            except fp.Fail as e:
                raise Fail(str(e))
            except (tarfile.TarError, EOFError) as e:
                raise Fail(f"tar 第二次讀取失敗：{ic.clean(e, 200)}")
        for t, keys in want.items():
            for key in keys:
                files[key]["result"] = res.get(t) or {"error": "content not found when the archive was read again"}

    out_files, seen = [], set()
    for real in sorted(files):
        f = files[real]
        r = f.get("result") or {"error": "not read"}
        rec = {"path": ic.clean(real, PATH_LIMIT), "listed_as": sorted(ic.clean(x, PATH_LIMIT) for x in f["listed_as"]),
               "patterns": sorted(f["patterns"])}
        other = sorted(ic.clean(x, PATH_LIMIT) for x in f["names"] if x != real)
        if other:
            rec["hard_links"] = other
        if "hardlink_of" in f:
            rec["hardlink_of"] = ic.clean(f["hardlink_of"], PATH_LIMIT)
        if not r.get("error") and rec["path"] in seen:
            r = {"error": "another file has the same name after escaping: not added"}
        if r.get("error"):
            problems.append({"path": rec["path"], "pattern": "; ".join(rec["patterns"]), "reason": r["error"]})
            for p in pat_out:
                if p["pattern"] in f["patterns"]:
                    p["status"] = "GAP"
                    p["reasons"] = sorted(set(p["reasons"]) | {f"{rec['path']}: {r['error']}"})
            continue
        seen.add(rec["path"])
        rec.update({k: r[k] for k in ("size", "sha256", "sha512", "elf") if k in r})
        if "modinfo" in r:
            rec["modinfo"] = r["modinfo"]
            if r.get("modinfo_note"):
                rec["modinfo_note"] = ic.clean(r["modinfo_note"], 200)
        out_files.append(rec)
    for p in pat_out:
        p["matched"] = sum(1 for f in out_files if p["pattern"] in f["patterns"])
    problems.sort(key=lambda x: (x["path"], x["pattern"], x["reason"]))
    rejected = img.cov.get("rejected", 0)
    st = "OK" if all(p["status"] == "OK" for p in pat_out) and not problems else "GAP"
    return {"source": {"type": stype, "file": ic.clean(os.path.basename(os.path.abspath(src))), "prefix": "/".join(pp) or None},
            "limits": {"file_max": file_max, "total_max": total_max, "match_max": MATCH_MAX},
            "status": st, "patterns": pat_out, "files": out_files, "problems": problems,
            "rejected_members": rejected, "second_read": bool(want)}


# ---------- 產品 SBOM 的元件（cra_report.py 用） ----------

def version_of(f, ents_by_pat):
    """→ (版本或 None, 依據說明)。設定的 version 優先；.ko 用 modinfo 的 version；兩筆設定給不同版本 → 未知（不猜）。"""
    vs = {ents_by_pat[p]["version"] for p in f.get("patterns") or () if p in ents_by_pat and ents_by_pat[p].get("version")}
    if any(ents_by_pat.get(p, {}).get("version_conflict") for p in f.get("patterns") or ()):
        return None, "version unknown: the configuration gives different versions for this file"
    if len(vs) > 1:
        return None, f"version unknown: the configuration gives different versions for this file ({', '.join(sorted(vs))})"
    if vs:
        return next(iter(vs)), "configuration sbom.own_software"
    mi = f.get("modinfo") if isinstance(f.get("modinfo"), dict) else {}
    mv = _s(mi.get("version"))
    if mv:
        return mv, "modinfo version"
    return None, "version unknown: no version in sbom.own_software" + (" and no modinfo version" if "modinfo" in f else "") + \
        " (not guessed from the file name)"


def purl(name, version, sha256):
    q = urllib.parse.quote
    return f"pkg:generic/{q(name, safe='')}" + (f"@{q(version, safe='')}" if version else "") + f"?checksum=sha256:{sha256}"


def ctype(path, spec):
    fw = fwmod()
    if is_ko(path):
        return "device-driver" if fw.spec_at_least(spec, (1, 5)) else "library"
    if re.search(r"\.so(?:\.[0-9][0-9.]*)?$", path.rsplit("/", 1)[-1]):
        return "library"
    return "application"


def _hex(v, n):
    return isinstance(v, str) and len(v) == n and all(c in "0123456789abcdef" for c in v)


def build(doc, cfg, spec, flash_comps=None, flash_prefix=None, doc_name="own-software.json"):
    """own-software.json（collect 的結果）＋目前的設定 → (新元件, 頂層 ref, info)。
    flash_comps：firmware_bom.build 的元件（同一個檔案已經是刷機包的 kernel 模組時不重複列，改在那個元件上標自有軟體；原地修改）。
    doc 是 None（找不到或讀不到）→ 沒有元件，status GAP。"""
    fw = fwmod()
    ents, cerrs = entries(cfg)
    mf = cfg.get("manufacturer") or {}
    org = fw.entity({"name": mf.get("name"), "url": mf.get("website"), "email": mf.get("email")})
    new = fw.spec_at_least(spec, (1, 6))
    info = {"status": "OK", "file": doc_name, "supplier": org["name"] if org else None, "config_errors": cerrs, "patterns": [],
            "components": 0, "merged_with_flash_modules": [], "unmerged_flash_modules": [], "version_unknown": 0, "gaps": [], "files": []}
    if not isinstance(doc, dict) or not isinstance(doc.get("patterns"), list) or not isinstance(doc.get("files"), list):
        info["status"] = "GAP"
        info["gaps"].append(f"{doc_name} not found or not readable: the manufacturer's own software is missing from the SBOM "
                            "(run own_software.py on the root file system; scan-flash-package.sh does this when the product configuration "
                            "lists sbom.own_software)")
        info["patterns"] = [{"pattern": e["pattern"], "matched": 0, "status": "GAP", "reasons": ["not inventoried"]} for e in ents]
        return [], [], info
    info["source"] = {k: _s(v) for k, v in (doc.get("source") or {}).items() if k in ("type", "file", "prefix")} \
        if isinstance(doc.get("source"), dict) else {}
    by_pat = {e["pattern"]: e for e in ents}
    dpats = {p.get("pattern"): p for p in doc["patterns"] if isinstance(p, dict) and isinstance(p.get("pattern"), str)}
    for e in ents:
        p = dpats.get(e["pattern"])
        if p is None:
            info["patterns"].append({"pattern": e["pattern"], "matched": 0, "status": "GAP",
                                     "reasons": [f"not in {doc_name} (it was made for a different list): run own_software.py again"]})
        else:
            info["patterns"].append({"pattern": e["pattern"], "matched": p.get("matched") if isinstance(p.get("matched"), int) else 0,
                                     "status": "OK" if p.get("status") == "OK" else "GAP",
                                     "reasons": [_s(r, 400) for r in p.get("reasons") or [] if _s(r, 400)][:LIST_MAX]})
    for c in cerrs:
        info["gaps"].append(f"configuration: {c}")
    for p in info["patterns"]:
        if p["status"] != "OK":
            info["gaps"] += [f"`{p['pattern']}`: {r}" for r in p["reasons"]] or [f"`{p['pattern']}`: not complete"]

    # 刷機包的 kernel 模組（firmware_bom）：rootfs 裡的路徑 → 元件
    flash = {}
    if flash_comps and flash_prefix:
        for c in flash_comps:
            pv = next((q.get("value") for q in c.get("properties") or [] if q.get("name") == "sca-center:flash-package-path"), None)
            src = next((q.get("value") for q in c.get("properties") or [] if q.get("name") == "sca-center:source"), None)
            if src == "flash-inventory: kernel module" and isinstance(pv, str) and pv.startswith(flash_prefix + "/"):
                flash[pv[len(flash_prefix) + 1:]] = c

    comps, top, refs = [], [], set()
    for f in sorted((x for x in doc["files"] if isinstance(x, dict) and isinstance(x.get("path"), str)), key=lambda x: x["path"]):
        mine = sorted(p for p in f.get("patterns") or [] if p in by_pat)
        if not mine or not _hex(f.get("sha256"), 64):
            continue
        f = dict(f, patterns=mine)
        path = f["path"]
        fname = path.rsplit("/", 1)[-1]
        ver, basis = version_of(f, by_pat)
        mi = f.get("modinfo") if isinstance(f.get("modinfo"), dict) else None
        single = [by_pat[p]["name"] for p in mine if by_pat[p].get("name") and not by_pat[p].get("name_conflict")
                  and next((x["matched"] for x in info["patterns"] if x["pattern"] == p), 0) == 1]
        name = (single[0] if len(set(single)) == 1 else None) or _s((mi or {}).get("name")) or (fname.split(".ko")[0] if is_ko(fname) else fname)
        row = {"path": "/" + path, "name": name, "version": ver, "sha256": f["sha256"], "patterns": mine}
        aliases = ({path} | {x for x in (f.get("listed_as") or []) + (f.get("hard_links") or []) if isinstance(x, str)}
                   | ({f["hardlink_of"]} if isinstance(f.get("hardlink_of"), str) else set()))
        hit = next((flash[a] for a in sorted(aliases) if a in flash), None)
        if hit is not None:
            props = hit.setdefault("properties", [])
            listed = "listed in sbom.own_software: " + "; ".join(mine)
            h = {x.get("alg"): x.get("content") for x in hit.get("hashes") or [] if isinstance(x, dict)}
            row["merged"] = True
            if h.get("SHA-256") != f["sha256"]:
                # 雜湊不同：不能確定是同一個檔案 → 不合併。元件維持刷機包清點的樣子（supplier、版本、hashes 不動，不加 purl），
                # 只記兩個雜湊與 GAP；屬性名稱寫明沒有合併（不讓人以為這個元件已經標成自有軟體）
                props.append(fw.prop("sca-center:own-software-unmerged", listed + " (SHA-256 differs: not merged)"))
                props.append(fw.prop("sca-center:own-software-sha256", f["sha256"]))
                info["unmerged_flash_modules"].append("/" + path)
                info["gaps"].append(f"`/{path}`: SHA-256 differs between the flash package inventory and {doc_name} "
                                    "(both recorded on the component; supplier, version and purl not changed)")
                row["version"], row["merged"] = hit.get("version"), "sha256 differs"
                info["files"].append(row)
                continue
            # 同一個檔案：不重複列；那個元件標成自有軟體（supplier 改成製造商，原本的刷機包提供者留在屬性）
            props.append(fw.prop("sca-center:own-software", listed))
            info["merged_with_flash_modules"].append("/" + path)
            if ver is None:
                info["version_unknown"] += 1
            old = hit.get("supplier")
            if org:
                if old and old.get("name") != org["name"]:
                    props.append(fw.prop("sca-center:flash-package-supplier", old.get("name")))
                hit["supplier"] = org
                if new:
                    hit["manufacturer"] = org
            if ver:
                if hit.get("version") and hit["version"] != ver:
                    props.append(fw.prop("sca-center:replaced-version", hit["version"]))
                hit["version"] = ver
            else:
                if hit.get("version"):
                    props.append(fw.prop("sca-center:replaced-version", hit.pop("version")))
                props.append(fw.prop("sca-center:version-status", "unknown"))
            props[:] = [q for q in props if q.get("name") != "sca-center:version-basis"]
            props.append(fw.prop("sca-center:version-basis", basis))
            hit["purl"] = purl(hit.get("name") or name, ver, f["sha256"])
            info["files"].append(row)
            continue
        if ver is None:
            info["version_unknown"] += 1
        if REF + path in refs:
            info["gaps"].append(f"`/{path}`: listed twice in {doc_name}: added once")
            continue
        refs.add(REF + path)
        c = {"type": ctype(path, spec), "bom-ref": REF + path, "name": name}
        if ver:
            c["version"] = ver
        if org:
            c["supplier"] = org
            if new:
                c["manufacturer"] = org
        hs = [{"alg": "SHA-256", "content": f["sha256"]}]
        if _hex(f.get("sha512"), 128):
            hs.append({"alg": "SHA-512", "content": f["sha512"]})
        c["hashes"] = hs
        c["purl"] = purl(name, ver, f["sha256"])
        props = [fw.prop("bsi:component:filename", fname)]
        if f.get("elf") is True:
            props += [fw.prop(k, v) for k, v in zip(fw.BSI_FLAGS, ("executable", "no archive", "unstructured"))]
        props += [fw.prop("sca-center:source", SOURCE), fw.prop("sca-center:own-software-path", "/" + path),
                  fw.prop("sca-center:own-software-pattern", "; ".join(mine))]
        other = sorted(x for x in aliases if x != path)
        if other:
            props.append(fw.prop("sca-center:own-software-listed-as", "; ".join("/" + x for x in other)))
        props.append(fw.prop("sca-center:version-basis", basis))
        if not ver:
            props.append(fw.prop("sca-center:version-status", "unknown"))
        if mi is not None:
            for k in ("vermagic", "srcversion"):
                if _s(mi.get(k)):
                    props.append(fw.prop(f"sca-center:modinfo-{k}", _s(mi[k])))
            if _s(mi.get("license")):
                c["licenses"] = [{"license": {"name": _s(mi["license"]), **({"acknowledgement": "declared"} if new else {})}}]
        elif "modinfo" in f:
            props.append(fw.prop("sca-center:modinfo", f"not available: {_s(f.get('modinfo_note')) or 'not read'}"))
        c["properties"] = props
        comps.append(c)
        top.append(c["bom-ref"])
        info["files"].append(row)
    if not org:
        info["gaps"].append("manufacturer.name missing: supplier not set")
    info["components"] = len(comps)
    info["merged_with_flash_modules"].sort()
    info["unmerged_flash_modules"].sort()
    info["status"] = "GAP" if info["gaps"] else "OK"
    return comps, top, info


def text(info, table):
    """sbom.md 第 6 節後面的一小節（設定 sbom.own_software 時，或 --declaration 寫了宣告的結果時）。"""
    if info.get("declaration") == "none":
        return "\n".join(["### Manufacturer's own software (configuration `sbom.own_software`)", "",
                          f"**Status: OK** (declaration). The manufacturer declares that the product has no own software "
                          f"(configuration `sbom.own_software` = [], `sbom.{NONE_REASON_KEY}`): {info.get('none_reason')}. "
                          "This is the manufacturer's statement; the scan did not verify it."])
    if info.get("declaration") == "undeclared":
        return "\n".join(["### Manufacturer's own software (configuration `sbom.own_software`)", "",
                          "**Status: GAP**. " + (info["gaps"][0] if info.get("gaps") else UNDECLARED) + "."])
    out = ["### Manufacturer's own software (configuration `sbom.own_software`)", "",
           f"**Status: {info['status']}**. Files listed in the product configuration were hashed in the root file system "
           f"(`{info.get('file')}`, made by `own_software.py`"
           + (f" from `{info['source'].get('file')}`" + (f", root file system `{info['source']['prefix']}`" if info['source'].get('prefix') else "")
              if info.get("source") else "") + "). "
           f"Added as components: **{info['components']}**"
           + (f"; already in the SBOM as kernel modules from the flash package and marked as own software there (not listed twice): "
              f"{len(info['merged_with_flash_modules'])}" if info["merged_with_flash_modules"] else "") + ". "
           + (f"Supplier: {info['supplier']} (configuration `manufacturer.name`)." if info.get("supplier") else
              "Supplier: **TO BE COMPLETED** (configuration `manufacturer.name`)."), ""]
    if info["files"]:
        def note(r):
            if r.get("merged") == "sha256 differs":
                return " (flash package kernel module, **SHA-256 differs**: not merged)"
            return " (flash package kernel module)" if r.get("merged") else ""
        rows = [[r["name"], r["version"] or "**version unknown**", f"`{r['path']}`", r["sha256"][:16] + "…",
                 ", ".join(f"`{p}`" for p in r["patterns"]) + note(r)] for r in info["files"][:LIST_MAX]]
        out += [table(["Component", "Version", "Path in the root file system", "SHA-256", "Listed as"], rows)]
        if len(info["files"]) > LIST_MAX:
            out += ["", f"… {len(info['files'])} files in total (full list in `summary.json`)."]
        out += [""]
    if info["version_unknown"]:
        out += [f"Version unknown for {info['version_unknown']} file(s): no `version` in `sbom.own_software` and no `modinfo` "
                "version. The version is left empty; it is not guessed from the file name.", ""]
    if info["gaps"]:
        out += ["**GAP** – own software that is listed but not in the SBOM, or not complete:", ""]
        out += [f"- {g}" for g in info["gaps"][:LIST_MAX]] + ([f"- … ({len(info['gaps'])} in total; see `summary.json`)"]
                                                              if len(info["gaps"]) > LIST_MAX else [])
        out += [""]
    out += ["These components have generic Package URLs (`pkg:generic`): they are not matched against vulnerability databases, "
            "so vulnerabilities in the manufacturer's own software are **not assessed** by this scan."]
    return "\n".join(out)


# ---------- 命令列 ----------

class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        print(f"參數錯誤：{message}", file=sys.stderr)
        sys.exit(64)


def read_config(p):
    try:
        with open(p, encoding="utf-8") as f:
            cfg = json.load(f)
    except (OSError, ValueError) as e:
        raise Fail(f"讀不到設定 {os.path.basename(p)}：{type(e).__name__}")
    if not isinstance(cfg, dict):
        raise Fail(f"設定 {os.path.basename(p)} 不是 JSON 物件")
    return cfg


def run(src, prefix, config, out, file_max=FILE_MAX):
    """→ (狀態, 說明, 要印的其他行)。"""
    cfg = read_config(config)
    if not configured(cfg):
        return "SKIP", "設定沒有 sbom.own_software：不執行", []
    ents, cerrs = entries(cfg)
    if declaration(cfg)[0] == "conflict":
        cerrs = cerrs + [declaration(cfg)[1]]
    if not ents:
        return "FAIL", "sbom.own_software 沒有可用的路徑：" + "；".join(cerrs[:5]), []
    doc = collect(src, prefix, ents, file_max)
    doc = {"schema": SCHEMA, "tool_version": TOOL_VERSION, **doc, "config_errors": cerrs}
    if cerrs:
        doc["status"] = "GAP"
    os.makedirs(out, exist_ok=True)
    tmp = os.path.join(out, ".own-software.json.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1, sort_keys=True)
        f.write("\n")
    os.replace(tmp, os.path.join(out, "own-software.json"))
    lines = [f"GAP\t(config)\t{c}" for c in cerrs]
    for p in doc["patterns"]:
        lines += [f"GAP\t{p['pattern']}\t{r}" for r in p["reasons"]] if p["status"] != "OK" else []
    by_pat = {e["pattern"]: e for e in ents}
    unknown = [f["path"] for f in doc["files"] if version_of(f, by_pat)[0] is None]
    gaps = lines[:LIST_MAX] + ([f"GAP\t…\t共 {len(lines)} 行（own-software.json 的 patterns、problems）"] if len(lines) > LIST_MAX else [])
    info = [f"INFO\t/{p}\t版本未知（設定沒有 version，也沒有 modinfo 的 version；不從檔名猜）" for p in unknown[:LIST_MAX]]
    if len(unknown) > LIST_MAX:
        info.append(f"INFO\t…\t版本未知共 {len(unknown)} 個")
    n_gap = sum(1 for p in doc["patterns"] if p["status"] != "OK")
    detail = (f"{len(ents)} 個樣式、{len(doc['files'])} 個檔案算了雜湊" + (f"、對不到或不完整的樣式 {n_gap} 個" if n_gap else "")
              + (f"、設定錯誤 {len(cerrs)} 個" if cerrs else "") + (f"、版本未知 {len(unknown)} 個" if unknown else "")
              + (f"、拒絕的成員 {doc['rejected_members']} 個" if doc["rejected_members"] else "") + "；own-software.json")
    return doc["status"], detail, gaps + info


def fail_text(e, paths):
    """FAIL 的說明：不寫主機的絕對路徑（OSError 只留檔名；其他訊息裡出現的 --from／--config／--out 與它們的上層資料夾換成檔名）。"""
    if isinstance(e, OSError):
        return f"{type(e).__name__}: {e.strerror or e}" + (f" ({os.path.basename(str(e.filename))})" if e.filename else "")
    msg = f"{type(e).__name__}: {e}"
    subs = set()
    for p in paths:
        if p:
            ap = os.path.abspath(p)
            subs |= {(ap, os.path.basename(ap)), (p, os.path.basename(ap)), (os.path.dirname(ap) + "/", "")}
    for a, b in sorted(subs, key=lambda x: -len(x[0])):
        if len(a) > 1:
            msg = msg.replace(a, b)
    return msg


def main(argv=None):
    ap = Parser(description="產品自有軟體（設定 sbom.own_software）→ own-software.json")
    ap.add_argument("--version", action="version", version=f"{SCHEMA} {TOOL_VERSION}")
    ap.add_argument("--from", dest="from_")
    ap.add_argument("--prefix")
    ap.add_argument("--config", help="產品的 config.json（--declaration 以外必填）")
    ap.add_argument("--out")
    ap.add_argument("--max-file-size", type=int, default=FILE_MAX, help=f"單檔上限（bytes，預設 {FILE_MAX}）")
    ap.add_argument("--configured", action="store_true", help="只看設定有沒有 sbom.own_software（有 → 0，沒有 → 1）")
    ap.add_argument("--declaration", action="store_true",
                    help="設定沒有列自有軟體時：把宣告的結果寫成 --out/own-software.json，印 B-own-software 那一行（OK 0、GAP 2）；有列 → 參數錯誤")
    a = ap.parse_args(argv)
    if a.declaration:
        if not a.out:
            ap.error("--declaration 需要 --out")
        try:
            cfg = read_config(a.config) if a.config else None
        except Fail as e:
            print(f"B-own-software\tFAIL\t{e}")
            return 1
        kind, why = declaration(cfg)
        if kind in ("listed", "conflict"):
            ap.error("設定有列 sbom.own_software：用 --from 執行，不是 --declaration")
        st = "OK" if kind == "none" else "GAP"
        os.makedirs(a.out, exist_ok=True)
        tmp = os.path.join(a.out, ".own-software.json.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"schema": SCHEMA, "tool_version": TOOL_VERSION, "status": st, "declaration": {"kind": kind, "detail": why}},
                      f, ensure_ascii=False, indent=1, sort_keys=True)
            f.write("\n")
        os.replace(tmp, os.path.join(a.out, "own-software.json"))
        msg = (f"製造商宣告沒有自有軟體：{why}（是宣告，掃描沒有驗證）" if kind == "none" else
               ("沒有產品設定：" if cfg is None else "") + "沒有宣告自有軟體（sbom.own_software），無法確認產品自有元件是否都在 SBOM；"
               f"沒有自有軟體時寫 sbom.own_software: [] 與 sbom.{NONE_REASON_KEY}")
        print(f"B-own-software\t{st}\t{msg[:480]}")
        return 0 if st == "OK" else 2
    if not a.config:
        ap.error("需要 --config（只有 --declaration 可以不給：沒有產品設定）")
    if a.configured:
        try:
            return 0 if configured(read_config(a.config)) else 1
        except Fail as e:
            print(e, file=sys.stderr)
            return 64
    if not a.from_ or not a.out or a.max_file_size <= 0:
        ap.error("需要 --from 與 --out（--max-file-size 要大於 0）")
    try:
        st, detail, lines = run(a.from_, a.prefix, a.config, a.out, a.max_file_size)
    except Exception as e:              # 不可信的輸入：任何錯誤都要留下 FAIL 那一行
        print(f"B-own-software\tFAIL\t{icmod().clean(fail_text(e, (a.from_, a.config, a.out)), 400)}")
        return 1
    print(f"B-own-software\t{st}\t{detail[:480]}")
    for x in lines:
        print(x)
    return {"OK": 0, "SKIP": 0, "GAP": 2}.get(st, 1)


if __name__ == "__main__":
    sys.exit(main())
