#!/usr/bin/env python3
"""kernel_oot_record.py：樹外模組（out-of-tree，例如 NVIDIA 的 nvidia-oot、nvgpu）的建置紀錄（kernel_config.py 的 --oot-build-record）。

樹外模組是對著核心 headers 另外編的，核心自己的建置紀錄（--build-record）看不到它們讀了哪些核心標頭檔。這裡讀樹外模組建置資料夾裡的
kbuild 紀錄（.<物件>.o.cmd 的 source_／deps_、.<模組>.ko.cmd），回答「這個核心標頭檔有沒有被已編的樹外模組用到」。

不可信的資料：資料夾唯讀走訪、不跟隨符號連結（資料夾連結不走進去、檔案以 O_NOFOLLOW 打開）、只讀一般檔案；單一檔案、合計、項目數
都有上限；不執行任何東西，只解析文字（.cmd 與 .mod 的清單）與模組 ELF 的 .modinfo。

「完整」的條件（任何一項不成立，那個模組就不算有紀錄，kernel_config.py 回到「標頭檔因為樹外模組而 unknown」）：
  - 模組有自己的 .<模組>.ko.cmd（kbuild 的連結指令，完整、以換行結尾）；
  - 它連結的每一個物件（.ko.cmd 指令裡的 *.o）都有自己的 .cmd，編譯的 .cmd 要完整（有 deps_ 與結尾的兩行）；組合物件（ld -r、@x.mod）
    的成員（x.mod 的每一行）也要有 .cmd，遞迴到編譯的物件；
  - 資料夾裡的 .cmd 有任何一個被截斷或看不懂 → 整份紀錄 GAP（不用）。
映像的樹外 .ko 與紀錄的對應靠模組名稱（- 與 _ 視為相同）；紀錄資料夾裡有那個 .ko 時再驗證它和映像的是同一份建置，依序：
.modinfo 的 srcversion（兩邊都有而不同 → 不是同一份程式，不再試別的方法；唯一的例外是 verify_build_path_only：用紀錄的原始碼重算
srcversion，只把 kbuild 產生檔裡的建置路徑換成映像的就和映像相同，見檔尾）；srcversion 兩邊其中一邊讀不到 → ELF 區段比對
（ko_sections／compare_ko_sections，見檔尾：區段內容、符號表、重定位都要相同；第 2 級只允許建置日期時間／建置者／建置路徑的字串不同）。
名稱相同、沒有 .ko 可比的只靠名稱（identity name_only）。同名的候選有好幾個時，只要有一個用內容驗證過就採用（其他候選的不符不抵銷）。"""
import hashlib
import os
import posixpath
import re
import stat
import struct

MAX_OOT_CMD = 16 << 20           # 單一 .cmd／.mod（估計：一般最大約 1 MB）
MAX_OOT_TOTAL = 4 << 30          # 讀進來的內容合計
MAX_OOT_ENTRIES = 3_000_000      # 走訪的項目數
MAX_OOT_PATHS = 3_000_000        # source_／deps_ 裡不同的路徑數
MAX_OOT_KO = 256 << 20           # 讀 srcversion 的 .ko 大小上限
MAX_OOT_EXAMPLES = 5
MAX_CLOSURE = 100_000            # 一個模組的物件走訪上限
CMD_NAME_RE = re.compile(r"^\.(.+)\.cmd$")
TOKEN_RE = re.compile(r"[^\s;|&()<>'\"`=]+")


class OotRecord:
    """讀進來的樹外模組建置紀錄。"""

    def __init__(self, path):
        self.path = path
        self.label = os.path.basename(os.path.normpath(path)) or path
        self.error = None
        self.cmds = {}            # 目標（.cmd 內容裡的 savedcmd 目標，正規化）→ {"dir": 實際資料夾, "src": [...], "link": [...], "mods": [...]}
        self.kos = {}             # 模組名稱（- 換成 _）→ {"target": .ko 的目標, "dir": 實際資料夾, "file": 紀錄資料夾裡的 .ko 路徑或 None}
        self.by_base = {}         # 路徑的檔名 → {完整路徑（正規化）: 物件}（標頭檔查詢用）
        self.npaths = self.ncmds = self.nobj = self.entries = 0
        self.read = 0
        self.anomalies, self.links, self.oversize = [], 0, []
        self.n_anomalies = self.n_oversize = 0

    def _note(self, bucket, name):
        if bucket is self.anomalies:
            self.n_anomalies += 1
        elif bucket is self.oversize:
            self.n_oversize += 1
        if len(bucket) < MAX_OOT_EXAMPLES:
            bucket.append(name)


def _norm(t):
    if not t or "\x00" in t:
        return None
    p = posixpath.normpath(t)
    return p if p not in (".", "") else None


def read_oot_record(path, kc):
    """資料夾 → OotRecord。kc：kernel_config 模組（parse_cmd、cmd_complete、flash_package 共用）。問題記在 .error（GAP）。"""
    rec = OotRecord(path)
    try:
        st = os.lstat(path)
    except OSError as e:
        rec.error = f"cannot read the out-of-tree build record ({type(e).__name__})"
        return rec
    if not stat.S_ISDIR(st.st_mode):
        rec.error = "the out-of-tree build record must be a directory (symbolic links are not followed)"
        return rec
    fp = kc.flash_package()
    root = os.path.abspath(path)
    try:
        for d, dirs, files in os.walk(root, followlinks=False):
            keep = []
            for n in sorted(dirs):
                p = os.path.join(d, n)
                try:
                    s = os.lstat(p)
                except OSError:
                    continue
                if stat.S_ISDIR(s.st_mode):
                    keep.append(n)
                else:
                    rec.links += 1
            dirs[:] = keep
            for n in sorted(files):
                rec.entries += 1
                if rec.entries > MAX_OOT_ENTRIES:
                    rec.error = f"more than {MAX_OOT_ENTRIES} entries in the out-of-tree build record"
                    return rec
                m = CMD_NAME_RE.match(n)
                if not m:
                    continue
                full = os.path.join(d, n)
                try:
                    s = os.lstat(full)
                except OSError:
                    continue
                if not stat.S_ISREG(s.st_mode):
                    rec.links += 1
                    rec._note(rec.anomalies, f"{n} is not a regular file")
                    continue
                if s.st_size > MAX_OOT_CMD:
                    rec._note(rec.oversize, n)
                    continue
                if rec.read + s.st_size > MAX_OOT_TOTAL:
                    rec.error = f"more than {MAX_OOT_TOTAL >> 20} MB of .cmd files"
                    return rec
                try:
                    with fp.open_nofollow(full) as f:
                        data = f.read(s.st_size + 1)
                except OSError:
                    rec._note(rec.anomalies, f"{n} cannot be read")
                    continue
                rec.read += len(data)
                _add_cmd(rec, kc, d, n, m.group(1), data.decode("utf-8", "replace"))
                if rec.error:
                    return rec
    except OSError as e:
        rec.error = f"cannot walk the out-of-tree build record ({type(e).__name__})"
        return rec
    if rec.oversize:
        rec.error = f"{rec.n_oversize} .cmd file(s) are larger than {MAX_OOT_CMD >> 20} MB: {', '.join(rec.oversize)}"
    elif rec.anomalies:
        rec.error = f"{rec.n_anomalies} .cmd file(s) are truncated or not in kbuild's format: {', '.join(rec.anomalies)}"
    elif not rec.cmds:
        rec.error = "no kbuild .cmd files in the out-of-tree build record"
    return rec


def _add_cmd(rec, kc, d, fname, stem, text):
    target, src, deps, keys, saved, has_deps = kc.parse_cmd(text)
    if not target or keys - {target} or not kc.cmd_complete(text, target, bool(src), has_deps):
        rec._note(rec.anomalies, fname)
        return
    t = _norm(target)
    # .<名稱>.cmd 的目標一定以 <名稱> 結尾（kbuild 的規則）；對不上 → 看不懂
    if t is None or posixpath.basename(t) != stem:
        rec._note(rec.anomalies, fname)
        return
    rec.ncmds += 1
    link = []
    mods = []
    if not src:
        for tok in TOKEN_RE.findall(saved):
            if tok.endswith(".o"):
                n = _norm(tok)
                if n is not None and n != t:
                    link.append(n)
        mods = [posixpath.basename(x) for x in re.findall(r"(?:^|\s)@(\S+\.mod)(?:\s|$)", saved)]
    elif t.endswith(".ko"):
        rec._note(rec.anomalies, fname)
        return
    info = {"dir": d, "src": bool(src), "link": link, "mods": mods}
    rec.cmds[t] = info
    if t.endswith(".ko"):
        # kbuild の .ko 連結：入力のオブジェクトは .ko.cmd の指令に出る
        for tok in TOKEN_RE.findall(saved):
            if tok.endswith(".o"):
                n = _norm(tok)
                if n is not None and n not in info["link"]:
                    info["link"].append(n)
        name = posixpath.basename(t)[:-3].replace("-", "_")
        ko_file = os.path.join(d, posixpath.basename(t))
        rec.kos.setdefault(name, []).append({"target": t, "dir": d, "file": ko_file})
    if src:
        rec.nobj += 1
        for p in list(src) + list(deps):
            n = _norm(p)
            if n is None:
                continue
            bucket = rec.by_base.setdefault(posixpath.basename(n), {})
            if n not in bucket:
                rec.npaths += 1
                if rec.npaths > MAX_OOT_PATHS:
                    rec.error = f"more than {MAX_OOT_PATHS} distinct source/deps paths"
                    return
                bucket[n] = posixpath.basename(t)


def _mod_members(rec, kc, d, modname):
    """<d>/<modname>（kbuild 的 .mod：一行一個物件路徑）→ 物件路徑清單或 None（讀不到、太大、看不懂）。"""
    p = os.path.join(d, modname)
    try:
        s = os.lstat(p)
        if not stat.S_ISREG(s.st_mode) or s.st_size > (1 << 20):
            return None
        with kc.flash_package().open_nofollow(p) as f:
            lines = f.read(s.st_size + 1).decode("utf-8", "replace").splitlines()
    except OSError:
        return None
    out = []
    for l in lines:
        l = l.strip()
        if not l:
            continue
        if not l.endswith(".o") or " " in l:
            return None
        n = _norm(l)
        if n is None:
            return None
        out.append(n)
    return out or None


def module_candidates(recs, name):
    """模組名稱 → [(紀錄, {"target", "dir", "file"})]（所有紀錄裡 .<名稱>.ko.cmd 的位置）。"""
    return [(r, c) for r in recs for c in r.kos.get(name, ())]


def module_closure(recs, kc, ko_target):
    """.ko 的目標 → (True, 物件數) 或 (False, 原因)。.ko.cmd 連結的每個物件、組合物件（ld -r、@x.mod）的每個成員都有完整的 .cmd；
    物件的 .cmd 可以在任何一份紀錄裡（例如 nvethernet 的 nvethernetrm 在另一個資料夾，用符號連結接進來）。"""
    seen, todo = set(), [ko_target]
    while todo:
        t = todo.pop()
        if t in seen:
            continue
        seen.add(t)
        if len(seen) > MAX_CLOSURE:
            return False, "too many objects"
        hit = next(((r, r.cmds[t]) for r in recs if t in r.cmds), None)
        if hit is None:
            return False, f"no .cmd for {posixpath.basename(t)}"
        r, info = hit
        if info["src"]:
            continue
        members = list(info["link"])
        for mf in info["mods"]:
            ms = _mod_members(r, kc, info["dir"], mf)
            if ms is None:
                return False, f"cannot read {mf}"
            members += ms
        for m in members:
            if m not in seen:
                todo.append(m)
    return True, len(seen)


def header_hit(rec, path):
    """核心標頭檔（樹內相對路徑，例如 include/linux/x.h）→ 紀錄裡用到它的物件名稱或 None。紀錄的路徑是建置機器上的絕對路徑，
    以 "/<路徑>" 結尾（或完全相同）就算用到——樹外模組自己的同名標頭也會命中（只會偏向 affected）。"""
    p = _norm(path)
    if p is None:
        return None
    for full, obj in (rec.by_base.get(posixpath.basename(p)) or {}).items():
        if full == p or full.endswith("/" + p):
            return obj
    return None


# =====================================================================================================
# 模組 .ko 的 ELF 區段比對（映像的樹外 .ko 沒有 srcversion 時，驗證紀錄資料夾裡的 .ko 是同一份建置）
# =====================================================================================================
# 只用標準函式庫讀 ELF64 little-endian（aarch64、x86_64）的區段表；不執行任何東西；全部有邊界檢查。
# 比對的區段：SHT_PROGBITS（程式碼與資料），排除這些名稱開頭的：.debug*、.note*、.comment、.BTF*、.gnu_debuglink、.modinfo、__versions、
# .gnu.linkonce*（除錯資訊、建置備註、版本字串與 modversions：重編時會不同，不影響程式行為）。重定位區段（SHT_RELA）與符號表不比。
# 第 1 級 "sections"：所有納入比對的區段，名稱、內容的 sha256 都相同；符號表（名稱、型別、所在區段、偏移、大小；不含 STT_FILE 與區段符號）相同；
#   程式碼與資料區段的重定位（偏移、型別、符號名稱、addend；符號用名稱而不是索引）相同；至少有一個非空的 .text*/.data* 區段。
#   雜湊與解析的位元組總量上限 2 倍檔案大小＋1 MB（重疊的區段不能放大成本）。殘留限制：不比 .debug*／.BTF 等除錯資訊與 .modinfo 以外的 modinfo 欄位。
#   上面「重定位」取代了先前「重定位區段不比」的限制。
# 第 2 級 "sections_masked"（標明遮罩）：只有字串區段不同（.rodata.str*，或小於 4 KB、內容全是可列印文字的其他 .rodata* 區段，例如版本／建置橫幅），
#   且該區段以 NUL 切開的字串，數量相同，不同的字串逐一遮罩後相同。遮罩的只有：
#   - 日期 "Nov 11 2026"（__DATE__）、時間 "12:34:56"（__TIME__）、ISO 日期 "2026-11-11"、date 指令格式 "Wed Oct 28 11:18:21 AM CST 2026"；
#   - 括號裡的建置者 "(user@host)"；
#   - 指向原始碼或物件檔的絕對路徑（以 .c .h .S .cc .cpp .o .ko 結尾，例如 __FILE__）：兩邊的路徑最後 3 層（不足則全部）要相同，只有前面的建置目錄不同。
#   以 NUL 切開後略過空字串（區段對齊補的 NUL 會隨字串長度改變）；字串的數量與順序仍要相同。
#   其他字串不同（例如裝置名稱、格式字串、非原始碼路徑）一律不遮罩 → 不採用。
ELF_EXCLUDE_PREFIX = (".debug", ".note", ".BTF", ".gnu.linkonce")
ELF_EXCLUDE_NAMES = {".comment", ".gnu_debuglink", ".modinfo", "__versions"}
STR_SECTION_PREFIX = ".rodata.str"
MAX_BANNER = 4096                    # 小的 .rodata* 區段，內容全是可列印文字（例如驅動的版本／建置橫幅）：和 .rodata.str* 一樣當字串區段
BANNER_RE = re.compile(rb"[\x20-\x7e\t\n\0]*[\x20-\x7e][\x20-\x7e\t\n\0]*")
MAX_ELF_SECTIONS = 262144
MAX_STR_SECTION = 8 << 20           # 一個 .rodata.str* 區段留下的原始內容上限（超過 → 只能比 sha256，不能遮罩）
MAX_STR_TOTAL = 32 << 20            # 一個 .ko 留下的字串區段合計上限
SHT_PROGBITS, SHT_SYMTAB, SHT_RELA, SHT_REL = 1, 2, 4, 9
CODE_PREFIX = (".text", ".data", ".init.text", ".exit.text", ".init.data")
MAX_SYMS = 2_000_000
MAX_RELOCS = 5_000_000
MASK_DATE = re.compile(rb"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [ 0-9]\d \d{4}\b")
MASK_FULLDATE = re.compile(rb"\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [ 0-9]\d \d{2}:\d{2}:\d{2}(?: [AP]M)?(?: [A-Z]{2,5})? \d{4}\b")
MASK_USERHOST = re.compile(rb"\([\w.-]+@[\w.-]+\)")
MASK_TIME = re.compile(rb"(?<![\d:])\d{2}:\d{2}:\d{2}(?![\d:])")
MASK_ISO = re.compile(rb"(?<![\d-])\d{4}-\d{2}-\d{2}(?![\d-])")
MASK_PATH = re.compile(rb"(?<![\w./+@-])/(?:[\w.+@-]+/)+[\w.+@-]+\.(?:c|h|S|cc|cpp|o|ko)\b")
PATH_TAIL = 3


def _is_stringy(name, size, body):
    return name.startswith(STR_SECTION_PREFIX) or (name.startswith(".rodata") and 0 < size <= MAX_BANNER and BANNER_RE.fullmatch(body) is not None)


def ko_sections(data):
    """.ko 位元組（解壓後，不可信）→ {"ok": True, "machine", "type", "digests": {區段名: [sha256 十六進位…]}, "strings": {區段名: [bytes…] 或 None},
    "code_bytes", "relocs": {目標區段名#序號: (sha256, [(r_offset, 型別, 符號名稱, addend)…])}, "symbols": sha256}
    或 {"ok": False, "reason"}。只接受 ELF64 little-endian。重定位的符號用名稱（區段符號用 "§區段名"）而不是索引；符號表排除 STT_FILE 與區段符號。
    雜湊的位元組總量有上限（區段重疊不能讓成本放大）。"""
    try:
        if len(data) < 64 or data[:4] != b"\x7fELF":
            return {"ok": False, "reason": "not an ELF file"}
        if data[4] != 2 or data[5] != 1:
            return {"ok": False, "reason": "section comparison supports ELF64 little-endian only"}
        etype, machine = struct.unpack_from("<HH", data, 0x10)
        shoff = struct.unpack_from("<Q", data, 0x28)[0]
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
        if shnum == 0 and shoff and shentsize >= 0x40 and shoff + shentsize <= len(data):
            # 區段數 ≥ 0xff00（-ffunction-sections 的大模組）：真正的數量在區段 0 的 sh_size，區段名稱表的索引（0xffff）在 sh_link
            shnum = struct.unpack_from("<Q", data, shoff + 0x20)[0]
            if shstrndx == 0xFFFF:
                shstrndx = struct.unpack_from("<I", data, shoff + 0x28)[0]
        if not (0 < shnum <= MAX_ELF_SECTIONS and shentsize >= 0x40 and shstrndx < shnum and shoff + shnum * shentsize <= len(data)):
            return {"ok": False, "reason": "ELF section table is missing or out of range"}
        secs = []
        for i in range(shnum):
            b = shoff + i * shentsize
            nm, ty = struct.unpack_from("<II", data, b)
            off, size = struct.unpack_from("<QQ", data, b + 0x18)
            link, info = struct.unpack_from("<II", data, b + 0x28)
            secs.append((nm, ty, off, size, link, info))
        _, _, so, ss = secs[shstrndx][:4]
        if so + ss > len(data):
            return {"ok": False, "reason": "ELF section name table is out of range"}
        names = data[so:so + ss]
        budget = 2 * len(data) + (1 << 20)         # 雜湊與解析的位元組總量（重疊的區段不能讓成本倍增）
        used = 0
        snames, stringy = [], {}
        for nm, ty, off, size, link, info in secs:
            if nm >= len(names) or names.find(b"\0", nm) < 0:
                return {"ok": False, "reason": "ELF section name is out of range"}
            snames.append(names[nm:names.find(b"\0", nm)].decode("utf-8", "replace"))
        digests, strings, total, code_bytes = {}, {}, 0, 0
        for idx, (nm, ty, off, size, link, info) in enumerate(secs):
            name = snames[idx]
            if ty != SHT_PROGBITS or name.startswith(ELF_EXCLUDE_PREFIX) or name in ELF_EXCLUDE_NAMES:
                continue
            if off + size > len(data):
                return {"ok": False, "reason": f"section {name} is out of range"}
            used += size
            if used > budget:
                return {"ok": False, "reason": "sections overlap or are too large: hashing limit exceeded"}
            body = data[off:off + size]
            digests.setdefault(name, []).append(hashlib.sha256(body).hexdigest())
            if size and name.startswith(CODE_PREFIX):
                code_bytes += size
            if _is_stringy(name, size, body):
                stringy[idx] = name
                if size <= MAX_STR_SECTION and total + size <= MAX_STR_TOTAL:
                    total += size
                    strings.setdefault(name, []).append(body)
                else:
                    strings.setdefault(name, []).append(None)
        # 符號表（名稱）與重定位（符號名稱＋型別＋偏移＋addend）
        symnames, symtab_sig, nsyms = None, None, 0
        for idx, (nm, ty, off, size, link, info) in enumerate(secs):
            if ty != SHT_SYMTAB:
                continue
            if symnames is not None:
                return {"ok": False, "reason": "more than one symbol table"}
            if off + size > len(data) or link >= shnum or size % 24:
                return {"ok": False, "reason": "symbol table is out of range"}
            _, _, sto, sts = secs[link][:4]
            used += size + sts
            if sto + sts > len(data) or used > budget or size // 24 > MAX_SYMS:
                return {"ok": False, "reason": "symbol string table is out of range or limits exceeded"}
            strtab, symnames, sig = data[sto:sto + sts], [], []
            for n_off, sinfo, _o, shndx, value, ssize in struct.iter_unpack("<IBBHQQ", data[off:off + size]):
                stype = sinfo & 15
                end = strtab.find(b"\0", n_off) if n_off < len(strtab) else -1
                if n_off and end < 0:
                    return {"ok": False, "reason": "symbol name is out of range"}
                nm_ = strtab[n_off:end].decode("utf-8", "replace") if end >= 0 else ""
                if stype == 3:                                   # STT_SECTION：用它指的區段名稱
                    symnames.append("§" + (snames[shndx] if shndx < shnum else "?"))
                    continue
                symnames.append(nm_)
                if stype == 4:                                   # STT_FILE：來源檔名，不比
                    continue
                if shndx == 0:
                    sec_name = "UND"
                elif shndx < shnum:
                    sec_name = snames[shndx]
                else:
                    sec_name = f"#{shndx:x}"
                strlike = shndx in stringy
                sig.append((nm_, sinfo, sec_name, None if strlike else value, None if strlike else ssize))
            sig.sort(key=repr)
            symtab_sig = hashlib.sha256(repr(sig).encode()).hexdigest()
            nsyms = len(sig)
        relocs, nrel = {}, 0
        for idx, (nm, ty, off, size, link, info) in enumerate(secs):
            if ty not in (SHT_RELA, SHT_REL):
                continue
            if info >= shnum or snames[info].startswith(ELF_EXCLUDE_PREFIX) or snames[info] in ELF_EXCLUDE_NAMES or secs[info][1] != SHT_PROGBITS:
                continue                                         # 只比程式碼／資料區段的重定位（除錯資訊的不比）
            esz = 24 if ty == SHT_RELA else 16
            if symnames is None or off + size > len(data) or size % esz:
                return {"ok": False, "reason": "relocation section cannot be read (no symbol table or out of range)"}
            used += size
            nrel += size // esz
            if used > budget or nrel > MAX_RELOCS:
                return {"ok": False, "reason": "relocation limits exceeded"}
            ents = []
            for r in struct.iter_unpack("<QQq" if ty == SHT_RELA else "<QQ", data[off:off + size]):
                sym = r[1] >> 32
                if sym >= len(symnames):
                    return {"ok": False, "reason": "relocation names a symbol that does not exist"}
                ents.append((r[0], r[1] & 0xFFFFFFFF, symnames[sym], r[2] if ty == SHT_RELA else 0))
            key = snames[info]
            n = 0
            while f"{key}#{n}" in relocs:
                n += 1
            relocs[f"{key}#{n}"] = (hashlib.sha256(repr(ents).encode()).hexdigest(), ents)
        return {"ok": True, "machine": machine, "type": etype, "digests": digests, "strings": strings, "code_bytes": code_bytes,
                "relocs": relocs, "symbols": symtab_sig, "nsyms": nsyms}
    except (struct.error, ValueError, IndexError) as ex:
        return {"ok": False, "reason": f"ELF cannot be parsed ({type(ex).__name__})"}


def _tail(path):
    comps = path.split(b"/")[1:]
    return comps[-PATH_TAIL:]


def _masked_equal(a, b, kinds):
    """兩個字串（bytes）遮罩日期、時間、建置路徑後相同 → True（kinds 記用了哪幾種遮罩）。"""
    pa, pb = MASK_PATH.findall(a), MASK_PATH.findall(b)
    if len(pa) != len(pb) or any(_tail(x) != _tail(y) for x, y in zip(pa, pb)):
        return False
    if pa:
        kinds.add("build path")

    def mask(x):
        # 日期時間只在「建置橫幅」的脈絡裡遮罩：字串裡有月份名稱的日期，或 ISO 日期加 HH:MM:SS；單獨的時間、單獨的 ISO 日期、MAC 位址
        # （00:11:22:33:44:55）、逾時值（10:20:30）、韌體日期（2024-01-05）都不遮罩 → 不同就不採用。(user@host) 也只在有日期時間戳記的字串裡遮罩。
        stamped = bool(MASK_FULLDATE.search(x) or MASK_DATE.search(x) or (MASK_ISO.search(x) and MASK_TIME.search(x)))
        if MASK_PATH.search(x):
            x = MASK_PATH.sub(b"<P>", x)
        if stamped:
            kinds.add("build date/time")
            for rx, rep in ((MASK_FULLDATE, b"<D>"), (MASK_DATE, b"<D>"), (MASK_ISO, b"<D>"), (MASK_TIME, b"<T>")):
                x = rx.sub(rep, x)
            if MASK_USERHOST.search(x):
                kinds.add("builder user@host")
                x = MASK_USERHOST.sub(b"<U>", x)
        return x
    return mask(a) == mask(b)


def compare_ko_sections(img, rec):
    """映像的 .ko 與紀錄的 .ko（ko_sections 的結果）→ (層級, 說明)。層級："sections"（第 1 級）、"sections_masked"（第 2 級）、None（不採用，說明是原因）。"""
    if not img.get("ok") or not rec.get("ok"):
        return None, "ELF sections of the image's or the record's .ko cannot be read: " + (img.get("reason") if not img.get("ok") else rec.get("reason"))
    if (img["machine"], img["type"]) != (rec["machine"], rec["type"]):
        return None, "ELF machine or type differs"
    if not img.get("code_bytes") or not rec.get("code_bytes"):
        return None, "no non-empty .text*/.data* section to compare"
    if img["symbols"] != rec["symbols"]:
        return None, "symbol table differs (names, binding, section, offset or size of symbols)"
    di, dr = img["digests"], rec["digests"]
    diff = sorted(k for k in set(di) | set(dr) if di.get(k) != dr.get(k))
    ri, rr = img["relocs"], rec["relocs"]
    if set(ri) != set(rr):
        return None, "relocation sections differ"
    rdiff = sorted(k for k in ri if ri[k][0] != rr[k][0])
    if not diff and not rdiff:
        return "sections", "code and data sections, symbols and relocations identical; debug/notes/modinfo ignored"
    if not all(k in img["strings"] and k in rec["strings"] for k in diff):
        return None, "code or data section(s) differ: " + ", ".join(diff[:3])
    if not diff:
        return None, "relocations differ although all sections are identical: " + ", ".join(rdiff[:3])
    # 字串長度改變時，指向字串區段的重定位 addend 會跟著變：只有「符號是有差異的字串區段的區段符號」的 addend 可以不同，其餘（偏移、型別、符號）要相同
    sd = {"§" + k for k in diff}
    for k in rdiff:
        ea, eb = ri[k][1], rr[k][1]
        if len(ea) != len(eb) or any(x[:3] != y[:3] or (x[3] != y[3] and x[2] not in sd) for x, y in zip(ea, eb)):
            return None, f"relocations in {k} differ beyond string addends"
    kinds, nstr = set(), 0
    for k in diff:
        si, sr = img["strings"].get(k), rec["strings"].get(k)
        if not si or not sr or len(si) != len(sr) or any(x is None for x in si + sr):
            return None, f"string section {k} differs and cannot be compared string by string"
        for x, y in zip(si, sr):
            xs, ys = [t for t in x.split(b"\0") if t], [t for t in y.split(b"\0") if t]     # 空字串＝對齊補的 NUL（路徑長度不同時補的數量也不同）
            if len(xs) != len(ys):
                return None, f"string section {k} has a different number of strings"
            for u, v in zip(xs, ys):
                if u != v:
                    if not _masked_equal(u, v, kinds):
                        return None, f"string section {k} differs in a string that is not a build date/time or build path"
                    nstr += 1
    return "sections_masked", (f"code and data sections and symbols identical, relocations identical except addends into the differing string sections; only {nstr} string(s) in {', '.join(diff)} differ, and only in "
                               f"{' / '.join(sorted(kinds))} (masked); debug/notes/modinfo ignored")


# =====================================================================================================
# srcversion 重算（scripts/mod/sumversion.c 的移植）：srcversion 不同時，檢查是不是只因為建置路徑不同
# =====================================================================================================
# srcversion＝MD4（.mod 列出的每個物件：它的 source_ 檔＋deps_ 裡同一資料夾的檔，去掉空白與 /* */ 註解）。kbuild 產生的檔
# （例如 mods.dtb.S：.incbin "<建置資料夾>/mods.dtb"）會把建置資料夾的絕對路徑寫進內容，所以同一份原始碼在不同資料夾編，srcversion 就不同。
# 規則（srcversion_build_path）：
#   1. 用紀錄的 .mod／.cmd 與 .cmd 裡寫的原始碼檔（建置機器上的路徑，要讀得到）重算，結果要等於紀錄 .ko 的 srcversion（證明重算正確、
#      原始碼就是紀錄編的那一份）；
#   2. 只在「kbuild 產生的 .dtb.S」（檔名以 .dtb.S 結尾，而且紀錄裡有它自己的 .<檔名>.cmd、那個 .cmd 不是編譯指令）裡，把紀錄的建置路徑前綴換成映像的建置路徑前綴再算，結果要等於映像的 srcversion。
#   映像的前綴從映像 .ko 字串區段裡的原始碼絕對路徑（__FILE__）找：和紀錄的原始碼檔路徑尾端相同（至少 PATH_TAIL 層）的那一個，
#   前面不同的部分就是兩邊的前綴；找到的前綴對要剛好一組。任何一步做不到 → None（照舊「不是同一份建置」）。
# 這個移植要和核心的實作逐位元相同：MD4 的訊息字以大端序讀（le32_to_cpu_array 用 ntohl）、長度字是原生整數、輸出每個字再位元組反轉。
SV_SPACE = b" \t\n\v\f\r"
MAX_SV_FILE = 16 << 20           # 單一原始碼檔
MAX_SV_TOTAL = 64 << 20          # 一次重算餵進去的原始碼合計（重複列出的檔也算）；純 Python 約 0.3 秒／MB
MAX_SV_GLOBAL = 256 << 20        # 一次執行（所有模組、所有重算）合計：惡意紀錄不能讓重算跑幾個小時
MAX_SV_FILES = 20000             # 一次重算讀的檔案數
SV_DENY_PREFIX = ("/proc/", "/sys/", "/dev/", "/run/")
SV_GENERATED_EXT = (".dtb.S",)   # 可以換路徑的產生檔：只有 kbuild 的 cmd_dt_S_dtb（.incbin "<建置資料夾>/x.dtb"）


def _sv_rol(x, s):
    x &= 0xFFFFFFFF
    return ((x << s) | (x >> (32 - s))) & 0xFFFFFFFF


def _sv_transform(h, X):
    a, b, c, d = h
    for i in range(16):
        a, b, c, d = d, _sv_rol(a + ((b & c) | (~b & d)) + X[i], (3, 7, 11, 19)[i % 4]), b, c
    for i in range(16):
        a, b, c, d = d, _sv_rol(a + ((b & c) | (b & d) | (c & d)) + X[(i % 4) * 4 + i // 4] + 0x5A827999, (3, 5, 9, 13)[i % 4]), b, c
    for i, k in enumerate((0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)):
        a, b, c, d = d, _sv_rol(a + (b ^ c ^ d) + X[k] + 0x6ED9EBA1, (3, 9, 11, 15)[i % 4]), b, c
    return [(h[0] + a) & 0xFFFFFFFF, (h[1] + b) & 0xFFFFFFFF, (h[2] + c) & 0xFFFFFFFF, (h[3] + d) & 0xFFFFFFFF]


def sumversion_md4(data):
    """sumversion.c 的 md4_init／md4_update／md4_final_ascii（在 little-endian 建置機器上）→ 32 個十六進位大寫字元。"""
    h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
    n = len(data)
    full = n - n % 64
    for o in range(0, full, 64):
        h = _sv_transform(h, struct.unpack(">16I", data[o:o + 64]))
    tail = data[full:] + b"\x80"
    if len(tail) > 56:
        tail += b"\0" * (64 - len(tail))
        h = _sv_transform(h, struct.unpack(">16I", tail))
        tail = b""
    tail += b"\0" * (56 - len(tail))
    h = _sv_transform(h, list(struct.unpack(">14I", tail)) + [(n << 3) & 0xFFFFFFFF, (n >> 29) & 0xFFFFFFFF])
    return "".join("%08X" % struct.unpack("<I", struct.pack(">I", x))[0] for x in h)


def sumversion_feed(text, out):
    """sumversion.c 的 parse_file（＋parse_string、parse_comment）：去掉空白、反斜線換行與 /* */ 註解，字串整段保留。"""
    n = text.find(b"\0")                    # read_text_file＋strlen：第一個 NUL 之後不算
    f = text if n < 0 else text[:n]
    L, i = len(f), 0
    while i < L:
        ch = f[i]
        if ch == 0x5C and i + 1 < L and f[i + 1] == 0x0A:
            i += 2
            continue
        if ch in SV_SPACE:
            i += 1
            continue
        if ch == 0x22:
            out.append(ch)
            k = 1
            while k < L - i:
                out.append(f[i + k])
                if f[i + k] == 0x22 and f[i + k - 1] != 0x5C:
                    break
                k += 1
            i += k + 1
            continue
        if ch == 0x2F and i + 1 < L and f[i + 1] == 0x2A:
            k = 2
            while k < L - i:
                if f[i + k - 1] == 0x2A and f[i + k] == 0x2F:
                    break
                k += 1
            i += k + 1
            continue
        out.append(ch)
        i += 1


class SvBudget:
    """重算的上限。一次執行建一個（global_left 跨模組共用），每次重算再重設 files／bytes。"""

    def __init__(self, global_bytes=MAX_SV_GLOBAL):
        self.files = self.bytes = 0
        self.global_left = global_bytes
        self.exhausted = False

    def reset(self):
        self.files = self.bytes = 0


def _sv_read(path, budget):
    """建置機器上的原始碼檔（.cmd 寫的絕對路徑）→ bytes 或 None。只讀一般檔案、不跟隨最後一層的符號連結、有大小與數量上限。"""
    if not isinstance(path, str) or not path.startswith("/") or "\x00" in path:
        return None
    canon = "/" + posixpath.normpath(path).lstrip("/") + "/"          # /./sys/…、//proc/…、/x/../dev/… 都先正規化再比
    if canon.startswith(SV_DENY_PREFIX):
        return None
    budget.files += 1
    if budget.files > MAX_SV_FILES:
        return None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOCTTY", 0))
    except OSError:
        return None
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_size > MAX_SV_FILE or budget.bytes + s.st_size > MAX_SV_TOTAL:
            return None
        if s.st_size > budget.global_left:
            budget.exhausted = True
            return None
        with os.fdopen(fd, "rb", closefd=False) as f:
            data = f.read(s.st_size + 1)
        if len(data) > s.st_size:
            return None
        budget.bytes += len(data)
        budget.global_left -= len(data)
        return data
    except OSError:
        return None
    finally:
        os.close(fd)


def _sv_cmd_for(recs, obj):
    """物件（.mod 裡的建置路徑）→ 紀錄資料夾裡它的 .cmd 檔路徑或 None（可以在任何一份紀錄；呼叫端把候選所屬的紀錄放第一個）。"""
    t = _norm(obj)
    for r in recs:
        info = r.cmds.get(t) if t else None
        if info is not None:
            return os.path.join(info["dir"], "." + posixpath.basename(t) + ".cmd")
    return None


def _sv_generated(recs, path):
    """路徑是可以換建置路徑的 kbuild 產生檔 → True：檔名以 .dtb.S 結尾，某份紀錄有它自己的 .cmd，而且那個 .cmd 不是編譯指令（沒有 source_）。
    只看「有沒有 .cmd」不夠：紀錄可以多放一個 .foo.c.cmd 把真正的原始碼冒充成產生檔。"""
    t = _norm(path)
    if not t or not t.endswith(SV_GENERATED_EXT):
        return False
    return any(t in r.cmds and not r.cmds[t]["src"] for r in recs)


def _sv_swap(data, swap):
    """只換「路徑開頭」的前綴（前一個字元不是路徑字元），回傳 (新內容, 換了幾處)。"""
    rx = re.compile(rb"(?<![\w.+@/-])" + re.escape(swap[0]))
    return rx.subn(lambda m: swap[1], data)


def recompute_srcversion(recs, kc, ko_dir, ko_target, swap=None, budget=None):
    """紀錄的模組 → (srcversion 23 字元, 用到的檔案數, 換過路徑的產生檔數) 或 (None, 原因, 0)。
    swap＝(紀錄前綴 bytes, 映像前綴 bytes)：只在 kbuild 產生的檔裡替換。照 sumversion.c：.mod 每行一個物件（.a 略過）；
    每個物件讀 .<物件>.cmd：source_ 行的檔，deps_ 之後以反斜線結尾的行裡、和物件在同一資料夾的檔。"""
    modname = posixpath.basename(ko_target)[:-3] + ".mod"
    p = os.path.join(ko_dir, modname)
    budget = budget or SvBudget()
    budget.reset()
    buf, nswap = bytearray(), 0
    try:
        s = os.lstat(p)
        if not stat.S_ISREG(s.st_mode) or s.st_size > MAX_OOT_CMD:
            return None, f"{modname} is missing, not a regular file or too large", 0
        with kc.flash_package().open_nofollow(p) as f:
            mtext = f.read(s.st_size + 1)
    except OSError:
        return None, f"{modname} cannot be read", 0
    n0 = mtext.find(b"\0")                  # read_text_file：第一個 NUL 之後不算
    if n0 >= 0:
        mtext = mtext[:n0]
    objs = [x for x in mtext.split(b"\n") if x]
    if not objs:
        return None, f"{modname} lists no object", 0

    def feed(path):
        nonlocal nswap
        data = _sv_read(path, budget)
        if data is None:
            return False
        if swap and _sv_generated(recs, path):
            data, hits = _sv_swap(data, swap)
            nswap += bool(hits)
        sumversion_feed(data, buf)
        return True

    for ob in objs:
        o = ob.decode("utf-8", "surrogateescape")
        if o.endswith(".a"):
            continue
        cut = o.rfind("/")
        if cut < 0:
            return None, f"object {o} in {modname} is not an absolute build path", 0
        d = o[:cut + 1]
        cmd = _sv_cmd_for(recs, o)
        if cmd is None:
            return None, f"no .cmd for {posixpath.basename(o)}", 0
        try:
            cs = os.lstat(cmd)
            if not stat.S_ISREG(cs.st_mode) or cs.st_size > MAX_OOT_CMD:
                return None, f"{posixpath.basename(cmd)} is not a regular file or too large", 0
            with kc.flash_package().open_nofollow(cmd) as f:
                ctext = f.read(cs.st_size + 1)
        except OSError:
            return None, f"{posixpath.basename(cmd)} cannot be read", 0
        n0 = ctext.find(b"\0")
        if n0 >= 0:
            ctext = ctext[:n0]
        check = False
        for raw in ctext.split(b"\n"):
            line = raw.lstrip(SV_SPACE)
            if line.startswith(b"source_"):
                sp = line.rfind(b" ")
                if sp < 0:
                    return None, f"malformed source_ line in {posixpath.basename(cmd)}", 0
                src = line[sp + 1:].decode("utf-8", "surrogateescape")
                if not feed(src):
                    if budget.exhausted:
                        return None, f"the limit of {MAX_SV_GLOBAL >> 20} MB of source read for srcversion recomputation in one run is used up", 0
                    return None, f"source file {src} cannot be read on this machine", 0
                continue
            if line.startswith(b"deps_"):
                check = True
                continue
            if not check:
                continue
            if not line.endswith(b"\\"):
                break
            m = re.search(rb"[ \t\n\v\f\r]", line)
            path = (line[:m.start()] if m else line).decode("utf-8", "surrogateescape")
            at = path.find(d)
            if at >= 0 and at + len(d) - 1 == path.rfind("/"):
                if not feed(path):
                    if budget.exhausted:
                        return None, f"the limit of {MAX_SV_GLOBAL >> 20} MB of source read for srcversion recomputation in one run is used up", 0
                    return None, f"dependency {path} cannot be read on this machine", 0
    return sumversion_md4(bytes(buf))[:23], budget.files, nswap


def _sv_source_paths(recs, kc, ko_dir, ko_target):
    """紀錄模組的 source_ 檔（不含 kbuild 產生的檔）→ 絕對路徑清單。"""
    out = []
    p = os.path.join(ko_dir, posixpath.basename(ko_target)[:-3] + ".mod")
    try:
        with kc.flash_package().open_nofollow(p) as f:
            objs = [x.decode("utf-8", "surrogateescape") for x in f.read(MAX_OOT_CMD + 1).split(b"\n") if x]
    except OSError:
        return out
    for o in objs:
        t = _norm(o)
        for r in recs:
            info = r.cmds.get(t) if t else None
            if info is None:
                continue
            try:
                with kc.flash_package().open_nofollow(os.path.join(info["dir"], "." + posixpath.basename(t) + ".cmd")) as f:
                    txt = f.read(MAX_OOT_CMD + 1)
            except OSError:
                break
            for line in txt.split(b"\n"):
                line = line.lstrip(SV_SPACE)
                if line.startswith(b"source_") and b" " in line:
                    src = line[line.rfind(b" ") + 1:].decode("utf-8", "surrogateescape")
                    if src.startswith("/") and not _sv_generated(recs, src):
                        out.append(src)
            break
    return out


def build_path_prefixes(rec_sources, image_strings):
    """紀錄的原始碼路徑＋映像 .ko 字串區段（{區段名: [bytes 或 None]}）→ (紀錄前綴 bytes, 映像前綴 bytes) 或 (None, 原因)。
    映像字串裡的原始碼絕對路徑（MASK_PATH）和紀錄的原始碼路徑檔名相同、尾端至少 PATH_TAIL 層相同時，取最長的相同尾端，
    前面的部分就是兩邊的建置路徑前綴；全部配對要得到同一組前綴，而且兩邊不同。"""
    img_paths = set()
    for bodies in (image_strings or {}).values():
        for body in bodies or ():
            if body:
                img_paths.update(MASK_PATH.findall(body))
    by_base = {}
    for ip in img_paths:
        by_base.setdefault(ip.rsplit(b"/", 1)[-1], []).append(ip)
    pairs = set()
    for rs in rec_sources:
        rb = rs.encode("utf-8", "surrogateescape")
        rc = rb.split(b"/")
        for ip in by_base.get(rc[-1], ()):
            ic = ip.split(b"/")
            n = 0
            while n < min(len(rc), len(ic)) - 1 and rc[-1 - n] == ic[-1 - n]:
                n += 1
            if n < PATH_TAIL:
                continue
            pairs.add((b"/".join(rc[:-n]) + b"/", b"/".join(ic[:-n]) + b"/"))
    if not pairs:
        return None, "no source file path of the module appears in the image's .ko strings, so the image's build path is unknown"
    if len(pairs) > 1:
        return None, f"source paths in the image's .ko give {len(pairs)} different build-path prefixes"
    rp, ip = pairs.pop()
    if rp == ip or len(rp) < 2 or len(ip) < 2:
        return None, "the record and the image have the same build path"
    return (rp, ip), None


def verify_build_path_only(recs, kc, cand, rec_sv, img_sv, image_strings, budget=None):
    """srcversion 不同（rec_sv ≠ img_sv）時：差異是不是只來自建置路徑 → (True, 說明) 或 (False, 原因)。
    recs：候選所屬的紀錄放第一個（.cmd 先在那份找）。budget：SvBudget（一次執行共用一個）。"""
    budget = budget or SvBudget()
    v0, files, _ = recompute_srcversion(recs, kc, cand["dir"], cand["target"], budget=budget)
    if v0 is None:
        return False, f"srcversion cannot be recomputed from the record ({files})"
    if v0 != rec_sv:
        return False, f"srcversion recomputed from the record and its source files ({v0}) differs from the record's .ko ({rec_sv}): the source files changed after the build"
    pre, why = build_path_prefixes(_sv_source_paths(recs, kc, cand["dir"], cand["target"]), image_strings)
    if pre is None:
        return False, why
    v1, files1, nswap = recompute_srcversion(recs, kc, cand["dir"], cand["target"], swap=pre, budget=budget)
    if v1 is None:
        return False, f"srcversion cannot be recomputed with the image's build path ({files1})"
    if not nswap:
        return False, "no kbuild-generated .dtb.S of the module contains the record's build path"
    if v1 != img_sv:
        return False, f"srcversion recomputed with the image's build path ({v1}) still differs from the image's .ko ({img_sv}): the source differs"
    return True, (f"srcversion differs only because of the build path: recomputed from {files} source file(s) it equals the record's .ko, and with "
                  f"{pre[0].decode('utf-8', 'replace')} replaced by {pre[1].decode('utf-8', 'replace')} in {nswap} kbuild-generated file(s) it equals the image's .ko ({img_sv})")
