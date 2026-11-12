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
.modinfo 的 srcversion（兩邊都有而不同 → 不是同一份程式，不再試別的方法）；srcversion 兩邊其中一邊讀不到 → ELF 區段比對
（ko_sections／compare_ko_sections，見檔尾：區段內容、符號表、重定位都要相同；第 2 級只允許建置日期時間／建置者／建置路徑的字串不同）。
名稱相同、沒有 .ko 可比的只靠名稱（identity name_only）。同名的候選有好幾個時，只要有一個用內容驗證過就採用（其他候選的不符不抵銷）。"""
import hashlib
import os
import posixpath
import re
import stat
import struct

MAX_OOT_CMD = 16 << 20           # 單一 .cmd／.mod（實測最大約 1 MB）
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
