"""Rockchip update.img（RKFW 外層＋RKAF 分割區表）的唯讀解析：分割區表、32 位元溢位的修正、ext4 唯讀讀取、boot 分割區（FIT）的核心。

給 tools/demo/flash_package.py 用：open_stream／open_source 遇到開頭是 RKFW 的檔案時，改用這裡的 VirtualTar，把 update.img
呈現成一個「虛擬的 tar」，成員是：
  rootfs/…                名稱是 rootfs 的 ext4 分割區裡的檔案（Python 直接讀 ext4 的資料結構：不掛載、不用 debugfs、不需要 root）
  bootloader/<名稱>.img   ext4 以外的分割區原樣（MiniLoaderAll、uboot、boot、recovery、misc…；firmware_bom.py 當刷機韌體）
  config/<名稱>.txt       package-file、parameter（文字）
  kernel/Image            boot 分割區（FIT）裡 type = "kernel" 的映像：lz4 在這裡解開，其他壓縮（gzip、xz…）原樣，
                          由 kernel_config.py 依開頭的 magic 自己解（它讀 <--prefix 的上一層>/kernel/Image 的 IKCONFIG）
所以 list、rootfs-tar、image_check.py、pkg_why.py、kernel_config.py（--prefix rootfs）不用改就能讀 update.img。

格式（afptool／rkImageMaker 的排法；欄位位置在一個內部 RK3588 映像上人工核對過）：
  RKFW：0 "RKFW"；0x19 loader 位移（u32 LE）、0x1d loader 長度、0x21 RKAF 位移、0x25 RKAF 長度；檔案最後 32 bytes 是 MD5（十六進位文字）。
  RKAF：0 "RKAF"、4 長度（u32）、8 model[0x22]、0x2a id[0x1e]、0x48 manufacturer[0x38]、0x80 unknown、0x84 version、
        0x88 分割區數（u32，最多 16）、0x8c 起每個分割區 0x70 bytes：name[32]、file[60]、nand_size、pos（相對 RKAF 開頭）、
        nand_addr、padded_size、size（都是 u32 LE）。
32 位元溢位：超過 4 GB 的映像，pos、size 與 RKAF 的長度只存低 32 位元（實例：rootfs 的 size 存成「真正的值 − 2^32」，之後每個
分割區的 pos 都少 2^32，RKAF 長度也少 2^32）。修正只用可以證明的條件，每個值的候選是「存的值 + k × 2^32」：
  - 真正的 RKAF 結尾 R = 檔案大小 − RKAF 位移 − 32（MD5 結尾；沒有 32 個十六進位字元的結尾 → GAP）；
  - 分割區依表的順序連續：第一個在表頭之後，之後每一個的位置在上一個的結尾之後 SLACK 以內；最後一個的結尾在 R 之前 SLACK 以內；
  - RKAF 的長度欄位：某個候選落在最後一個結尾與 R 之間；
  - 內容的錨：某個候選位置的內容認得出來（ext4 超級區塊、FIT d00dfeed、ANDROID!、squashfs、RK loader 的 BOOT／LDR）的分割區，
    只能放在認得出內容的位置（否則「前一個分割區吸收 2^32、rootfs 往後挪 4 GB」也符合其他條件）；
  - 位置 +1024 是 ext4 超級區塊（magic 0xEF53）的分割區：大小在檔案系統大小（blocks_count × 區塊大小）到 +2^31 之間
    （候選相差 2^32，所以最多一個符合）。
  所有條件都成立的組合恰好一個才採用（每個分割區記 overflow_corrected），零個或多個 → GAP（記原因與存的值），不猜。
不可信資料：每個位移與長度都檢查範圍；分割區名稱只接受 [A-Za-z0-9._-]（其他的只記錄，不拿來選 rootfs、不當成成員名稱）；
ext4 的目錄項名稱含 / 或 NUL、「.」「..」、目錄迴圈、指到檔案系統以外的區塊都拒絕並計數；只讀，不執行任何東西、不寫到磁碟。
"""
import bisect
import errno
import hashlib
import io
import os
import re
import struct
import tarfile
import zipfile

TWO32 = 1 << 32
SLACK = 1 << 16                # 分割區之間、最後一個到 RKAF 結尾、ext4 檔案系統到分割區大小，最多差這麼多（對齊用的填充）
RKAF_HDR = 0x8c
PART_SIZE = 0x70
MAX_PARTS = 16
MD5_TRAILER = 32
SEARCH_BUDGET = 20000          # 溢位修正的搜尋步數上限（超過 → GAP）
NAME_OK = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}")
TEXT_PARTS = ("package-file", "parameter")
# 已知的韌體或設定分割區（ext4 以外）：其他名稱的分割區內容沒有掃描 → ATTENTION（例如放了程式的自訂分割區）
KNOWN_PARTS = TEXT_PARTS + ("bootloader", "uboot", "trust", "misc", "boot", "recovery", "resource", "dtbo", "vbmeta",
                            "baseparameter", "logo", "security")
ROOTFS_PART = "rootfs"
BOOT_PART = "boot"
PREFIX = "rootfs"              # 虛擬 tar 裡 rootfs 的前綴（flash_package 的 VARIANTS 之一）
FIT_MAX = 256 << 20            # boot 分割區的 FIT 表頭（含內嵌資料）讀進記憶體的上限
KERNEL_MAX = 256 << 20         # 核心（lz4 解開後）的上限
SQUASHFS_MAGIC = b"hsqs"
# 分割區開頭認得的內容（溢位修正的「錨」）：某個候選位置有這些 magic 的分割區，只能放在有同樣 magic 的位置
CONTENT_MAGIC = ((b"\xd0\x0d\xfe\xed", "fit"), (b"ANDROID!", "android-boot"), (SQUASHFS_MAGIC, "squashfs"),
                 (b"BOOT", "rk-loader"), (b"LDR ", "rk-loader"))


class RkError(Exception):
    """結構錯誤（不是 update.img、截斷、表頭超出檔案）。"""


class Ext4Error(Exception):
    pass


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def magic(path, n=4):
    with open(path, "rb") as f:
        return f.read(n)


def is_rkfw(path):
    return magic(path) == b"RKFW"


def is_zip(path):
    return magic(path) == b"PK\x03\x04"


def cstr(b):
    """固定長度、NUL 結尾的欄位 → 顯示用的字串（不可印的字元跳脫）。"""
    return b.split(b"\0", 1)[0].decode("ascii", "backslashreplace")


def cands(stored, lo, hi):
    """stored + k × 2^32（k ≥ 0）落在 [lo, hi] 的值。"""
    if hi < lo:
        return []
    k = max(0, -(-(lo - stored) // TWO32))
    out = []
    v = stored + k * TWO32
    while v <= hi and len(out) < 64:
        out.append(v)
        v += TWO32
    return out


def pread(fd, off, n):
    if off < 0 or n < 0:
        raise OSError(errno.EINVAL, "負的位移")
    out = bytearray()
    while len(out) < n:
        b = os.pread(fd, n - len(out), off + len(out))
        if not b:
            break
        out += b
    return bytes(out)


class Range(io.RawIOBase):
    """檔案裡的一段（os.pread，不共用檔案位置）。"""

    def __init__(self, fd, off, size):
        self.fd, self.pos, self.end = fd, off, off + size

    def readable(self):
        return True

    def readinto(self, b):
        n = min(len(b), self.end - self.pos)
        if n <= 0:
            return 0
        data = os.pread(self.fd, n, self.pos)
        if not data:
            raise OSError(errno.EIO, "檔案比分割區表記的短")
        b[:len(data)] = data
        self.pos += len(data)
        return len(data)


def stream(raw):
    return io.BufferedReader(raw, 1 << 20)


# ---------- ext4 超級區塊 ----------

INCOMPAT_FILETYPE, INCOMPAT_RECOVER, INCOMPAT_META_BG, INCOMPAT_EXTENTS = 0x2, 0x4, 0x10, 0x40
INCOMPAT_64BIT, INCOMPAT_INLINE_DATA, INCOMPAT_ENCRYPT = 0x80, 0x8000, 0x10000
INCOMPAT_OK = 0x2 | 0x4 | 0x10 | 0x40 | 0x80 | 0x100 | 0x200 | 0x400 | 0x2000 | 0x4000 | 0x8000 | 0x10000 | 0x20000
INCOMPAT_NAMES = {0x1: "compression", 0x8: "journal_dev", 0x1000: "dirdata"}
RO_SPARSE_SUPER, RO_GDT_CSUM, RO_METADATA_CSUM = 0x1, 0x10, 0x400
COMPAT_SPARSE_SUPER2 = 0x200


def superblock(fd, off):
    """off（ext4 分割區的開頭）+1024 的超級區塊 → dict；不是 ext4（magic 不對、區塊大小不合理）→ None。"""
    sb = pread(fd, off + 1024, 1024)
    if len(sb) < 1024 or u16(sb, 0x38) != 0xEF53:
        return None
    log = u32(sb, 0x18)
    if log > 6:
        return None
    bs = 1024 << log
    incompat = u32(sb, 0x60)
    blocks = u32(sb, 0x04) | ((u32(sb, 0x150) << 32) if incompat & INCOMPAT_64BIT else 0)
    if blocks == 0:
        return None
    rev = u32(sb, 0x4C)
    return {"block_size": bs, "blocks": blocks, "fs_bytes": blocks * bs, "inodes": u32(sb, 0x00), "free_inodes": u32(sb, 0x10),
            "first_data_block": u32(sb, 0x14), "blocks_per_group": u32(sb, 0x20), "inodes_per_group": u32(sb, 0x28),
            "rev": rev, "inode_size": u16(sb, 0x58) if rev >= 1 else 128, "first_ino": u32(sb, 0x54) if rev >= 1 else 11,
            "compat": u32(sb, 0x5C), "incompat": incompat, "ro_compat": u32(sb, 0x64),
            "desc_size": (u16(sb, 0xFE) or 32) if incompat & INCOMPAT_64BIT else 32, "first_meta_bg": u32(sb, 0x104),
            "backup_bgs": (u32(sb, 0x24C), u32(sb, 0x250)), "label": cstr(sb[0x78:0x88]), "uuid": sb[0x68:0x78].hex()}


def sb_json(sb):
    used = max(0, sb["inodes"] - sb["free_inodes"])
    return {"block_size": sb["block_size"], "blocks": sb["blocks"], "fs_bytes": sb["fs_bytes"], "label": sb["label"], "uuid": sb["uuid"],
            "incompat": hex(sb["incompat"]), "ro_compat": hex(sb["ro_compat"]), "inodes_used": used,
            # 保留的 inode（1–10）與 lost+found（11）以外還有在用的 → 裡面有檔案（超級區塊的計數，不保證最新）
            "has_files": used > sb["first_ino"]}


# ---------- ext4 唯讀讀取 ----------

S_IFMT = 0xF000
KINDS = {0x8000: "file", 0x4000: "dir", 0xA000: "symlink", 0x2000: "chr", 0x6000: "blk", 0x1000: "fifo", 0xC000: "socket"}
EXTENTS_FL, INLINE_DATA_FL, ENCRYPT_FL = 0x80000, 0x10000000, 0x800
MAX_DIR = 64 << 20             # 一個目錄的內容上限
MAX_DIR_ENTRIES = 200_000      # 一個目錄的項目上限（超過 → 這個目錄算讀不到）
MAX_LOADED = 3_000_000         # 整個 rootfs 讀進記憶體的目錄項目總數上限（超過 → 之後的目錄算讀不到；實際的 rootfs 約幾十萬）
MAX_FILE = 1 << 40             # 一般檔案（含稀疏檔）的大小上限
MAX_SYMLINK = 4096
MAX_DEPTH = 128
EXT_MAX_DEPTH = 5


class Inode:
    __slots__ = ("ino", "mode", "uid", "gid", "size", "mtime", "links", "flags", "block", "blocks", "file_acl", "raw")

    @property
    def kind(self):
        return KINDS.get(self.mode & S_IFMT, "other")


class Ext4:
    """一個 ext4（或 ext2／ext3）分割區：base（在檔案裡的位移）、limit（分割區大小）。只讀；任何不合理的值 → Ext4Error。"""

    def __init__(self, fd, base, limit):
        sb = superblock(fd, base)
        if sb is None:
            raise Ext4Error("不是 ext4（位置 +1024 沒有超級區塊 magic 0xEF53）")
        bad = sb["incompat"] & ~INCOMPAT_OK
        if bad:
            names = [INCOMPAT_NAMES.get(1 << i, hex(1 << i)) for i in range(32) if bad >> i & 1]
            raise Ext4Error(f"不支援的 ext4 功能 {', '.join(names)}（incompat {hex(sb['incompat'])}）")
        bs, ds, isz = sb["block_size"], sb["desc_size"], sb["inode_size"]
        if sb["fs_bytes"] > limit:
            raise Ext4Error(f"檔案系統 {sb['fs_bytes']} bytes 比分割區 {limit} bytes 大（分割區被截斷）")
        if not (0 < sb["blocks_per_group"] <= 8 * bs and 0 < sb["inodes_per_group"] <= 8 * bs):
            raise Ext4Error("每個群組的區塊數或 inode 數不合理")
        if isz < 128 or isz > bs or isz & (isz - 1):
            raise Ext4Error(f"inode 大小 {isz} 不合理")
        if ds < 32 or ds > bs or ds & (ds - 1):
            raise Ext4Error(f"群組描述大小 {ds} 不合理")
        if sb["first_data_block"] >= sb["blocks"]:
            raise Ext4Error("first_data_block 超出檔案系統")
        self.groups = -(-(sb["blocks"] - sb["first_data_block"]) // sb["blocks_per_group"])
        if sb["inodes"] > self.groups * sb["inodes_per_group"] or sb["inodes"] < 2:
            raise Ext4Error("inode 總數和群組數對不起來")
        self.fd, self.base, self.sb, self.bs, self.ds = fd, base, sb, bs, ds
        self.filetype = bool(sb["incompat"] & INCOMPAT_FILETYPE)
        self.csum = bool(sb["ro_compat"] & (RO_GDT_CSUM | RO_METADATA_CSUM))
        self.recover = bool(sb["incompat"] & INCOMPAT_RECOVER)
        self._gd = {}

    def block(self, n, count=1):
        if n < 0 or n + count > self.sb["blocks"]:
            raise Ext4Error(f"區塊 {n} 超出檔案系統（{self.sb['blocks']} 個區塊）")
        data = pread(self.fd, self.base + n * self.bs, count * self.bs)
        if len(data) != count * self.bs:
            raise Ext4Error(f"區塊 {n} 讀不完整（檔案被截斷）")
        return data

    def has_super(self, g):
        sb = self.sb
        if g == 0:
            return True
        if sb["compat"] & COMPAT_SPARSE_SUPER2:
            return g in sb["backup_bgs"]
        if not sb["ro_compat"] & RO_SPARSE_SUPER or g == 1:
            return True
        for p in (3, 5, 7):
            x = p
            while x < g:
                x *= p
            if x == g:
                return True
        return False

    def gdesc(self, g):
        if g in self._gd:
            return self._gd[g]
        if not 0 <= g < self.groups:
            raise Ext4Error(f"群組 {g} 超出範圍")
        sb, bs, ds = self.sb, self.bs, self.ds
        dpb = bs // ds
        fdb = sb["first_data_block"]
        if sb["incompat"] & INCOMPAT_META_BG and g // dpb >= sb["first_meta_bg"]:
            g0 = g // dpb * dpb
            blk, off = fdb + g0 * sb["blocks_per_group"] + (1 if self.has_super(g0) else 0), (g % dpb) * ds
        else:
            blk, off = fdb + 1 + g * ds // bs, g * ds % bs
        raw = self.block(blk)[off:off + ds]
        itable = u32(raw, 0x08) | ((u32(raw, 0x28) << 32) if ds >= 64 else 0)
        unused = u16(raw, 0x1C) | ((u16(raw, 0x32) << 16) if ds >= 64 else 0)
        d = (itable, u16(raw, 0x12), unused)
        if len(self._gd) < 1 << 16:
            self._gd[g] = d
        return d

    def inode(self, ino):
        sb = self.sb
        if not 1 <= ino <= sb["inodes"]:
            raise Ext4Error(f"inode {ino} 超出範圍")
        g, idx = divmod(ino - 1, sb["inodes_per_group"])
        itable, flags, unused = self.gdesc(g)
        if self.csum and (flags & 0x1 or idx >= sb["inodes_per_group"] - unused):
            raise Ext4Error(f"inode {ino} 在還沒初始化的 inode 表裡")
        isz = sb["inode_size"]
        off = itable * self.bs + idx * isz
        if itable == 0 or off + isz > sb["fs_bytes"]:
            raise Ext4Error(f"inode {ino} 的位置超出檔案系統")
        raw = pread(self.fd, self.base + off, isz)
        if len(raw) != isz:
            raise Ext4Error(f"inode {ino} 讀不完整")
        i = Inode()
        i.ino, i.raw = ino, raw
        i.mode = u16(raw, 0x00)
        i.uid = u16(raw, 0x02) | (u16(raw, 0x78) << 16)
        i.gid = u16(raw, 0x18) | (u16(raw, 0x7A) << 16)
        i.size = u32(raw, 0x04) | (u32(raw, 0x6C) << 32)
        i.mtime = u32(raw, 0x10)
        i.links = u16(raw, 0x1A)
        i.blocks = u32(raw, 0x1C) | (u16(raw, 0x74) << 32)
        i.flags = u32(raw, 0x20)
        i.block = raw[0x28:0x28 + 60]
        i.file_acl = u32(raw, 0x68) | (u16(raw, 0x76) << 32)
        if isz > 128:
            extra = u16(raw, 0x80)
            if 128 + extra >= 0x8C and isz >= 0x8C:
                i.mtime |= (u32(raw, 0x88) & 3) << 32       # 2038 年以後：時間的高位元
        return i

    # --- 內容的位置 ---
    def runs(self, i):
        """一般檔案、目錄、長的符號連結 → 排好的 [(邏輯區塊, 實體區塊, 數量, 已初始化)]。"""
        n = -(-i.size // self.bs)
        if i.flags & EXTENTS_FL:
            out, seen = [], set()
            self._extents(i.block, None, out, seen)
            out.sort()
            last = 0
            for lb, _, ln, _ in out:
                if lb < last:
                    raise Ext4Error(f"inode {i.ino} 的 extent 重疊")
                last = lb + ln
            return out
        return self._blockmap(i, n)

    def _extents(self, data, depth, out, seen):
        mg, entries, mx, d = struct.unpack_from("<HHHH", data, 0)
        if mg != 0xF30A:
            raise Ext4Error("extent 表頭不對")
        if entries > mx or 12 + entries * 12 > len(data) or d > EXT_MAX_DEPTH or (depth is not None and d != depth):
            raise Ext4Error("extent 表頭的數量或深度不合理")
        for k in range(entries):
            o = 12 + k * 12
            if d == 0:
                lb, ln, hi, lo = struct.unpack_from("<IHHI", data, o)
                init = ln <= 32768
                ln = ln if init else ln - 32768
                if ln == 0:
                    continue
                p = (hi << 32) | lo
                if p + ln > self.sb["blocks"]:
                    raise Ext4Error("extent 指到檔案系統以外")
                out.append((lb, p, ln, init))
                if len(out) > self.sb["blocks"]:
                    raise Ext4Error("extent 太多")
            else:
                _, lo, hi = struct.unpack_from("<IIH", data, o)
                p = (hi << 32) | lo
                if p in seen or len(seen) > self.sb["blocks"]:
                    raise Ext4Error("extent 樹有迴圈")
                seen.add(p)
                self._extents(self.block(p), d - 1, out, seen)

    def _blockmap(self, i, n):
        ptrs = struct.unpack("<15I", i.block)
        per = self.bs // 4
        out = []

        def add(lb, p):
            if p >= self.sb["blocks"]:
                raise Ext4Error("區塊指標指到檔案系統以外")
            if out and out[-1][0] + out[-1][2] == lb and out[-1][1] + out[-1][2] == p:
                out[-1] = (out[-1][0], out[-1][1], out[-1][2] + 1, True)
            else:
                out.append((lb, p, 1, True))

        def walk(p, level, lb):
            """level 層的間接區塊 p，涵蓋從 lb 開始的 per^level 個邏輯區塊。"""
            if lb >= n:
                return
            span = per ** (level - 1)
            if p == 0:
                return
            tbl = struct.unpack(f"<{per}I", self.block(p))
            for k, q in enumerate(tbl):
                s = lb + k * span
                if s >= n:
                    break
                if q == 0:
                    continue
                if level == 1:
                    add(s, q)
                else:
                    walk(q, level - 1, s)
        for k in range(12):
            if k >= n:
                return out
            if ptrs[k]:
                add(k, ptrs[k])
        lb = 12
        for level, p in ((1, ptrs[12]), (2, ptrs[13]), (3, ptrs[14])):
            walk(p, level, lb)
            lb += per ** level
        return out

    def inline(self, i):
        """inline_data 的內容：i_block 的 60 bytes＋inode 內延伸屬性 system.data 的值。"""
        extra = b""
        raw = i.raw
        if len(raw) > 128:
            start = 128 + u16(raw, 0x80)
            if start + 4 <= len(raw) and u32(raw, start) == 0xEA020000:
                base = start + 4
                o = base
                while o + 16 <= len(raw):
                    nl, idx, voff, vino, vsize = struct.unpack_from("<BBHII", raw, o)
                    if nl == 0 and idx == 0 and voff == 0 and vino == 0:
                        break
                    name = raw[o + 16:o + 16 + nl]
                    if idx == 7 and name == b"data" and vino == 0:
                        if base + voff + vsize > len(raw):
                            raise Ext4Error(f"inode {i.ino} 的 inline data 超出 inode")
                        extra = raw[base + voff:base + voff + vsize]
                        break
                    o += (16 + nl + 3) & ~3
        return i.block + extra

    def open(self, i):
        """一般檔案 → 讀內容的檔案物件（洞與未初始化的 extent 讀成 0）。"""
        if i.flags & INLINE_DATA_FL:
            data = self.inline(i)
            if len(data) < i.size:
                raise Ext4Error(f"inode {i.ino} 的 inline data 比大小短")
            return io.BytesIO(data[:i.size])
        return stream(ExtReader(self, self.runs(i), i.size))

    def symlink(self, i):
        if i.size > MAX_SYMLINK:
            raise Ext4Error("符號連結的目標太長")
        if i.flags & INLINE_DATA_FL:
            t = self.inline(i)[:i.size]
        elif i.size < 60 and i.blocks - (self.bs // 512 if i.file_acl else 0) <= 0:
            t = i.block[:i.size]                       # fast symlink：目標就在 i_block
        else:
            with self.open(i) as f:
                t = f.read(i.size)
        if len(t) != i.size or b"\0" in t:
            raise Ext4Error("符號連結的目標不完整或含 NUL")
        return t

    def entries(self, i):
        """目錄 → [(名稱 bytes, inode 編號)]（不含 . 與 ..）。壞掉的目錄區塊：該區塊其餘的項目略過，回傳 (項目, 壞的區塊數)。"""
        if i.size > MAX_DIR:
            raise Ext4Error(f"目錄太大（{i.size} bytes）")
        out, bad = [], 0
        if not i.flags & INLINE_DATA_FL:
            rs = sorted((p, ln) for _, p, ln, _ in self.runs(i))
            if any(a[0] + a[1] > b[0] for a, b in zip(rs, rs[1:])):
                raise Ext4Error("目錄的多個區塊指到同一個實體區塊")
        if i.flags & INLINE_DATA_FL:
            data = self.inline(i)
            regions = [data[4:60], data[60:i.size] if i.size > 60 else b""]
        else:
            with self.open(i) as f:
                data = f.read(i.size)
            regions = [data[o:o + self.bs] for o in range(0, len(data), self.bs)]
        for blk in regions:
            o = 0
            while o + 8 <= len(blk):
                ino, rl = u32(blk, o), u16(blk, o + 4)
                nl = blk[o + 6] if self.filetype else u16(blk, o + 6)
                if rl < 8 or rl % 4 or o + rl > len(blk) or 8 + nl > rl:
                    bad += 1
                    break
                if ino:
                    name = blk[o + 8:o + 8 + nl]
                    if name not in (b".", b".."):
                        out.append((name, ino))
                        if len(out) > MAX_DIR_ENTRIES:
                            raise Ext4Error(f"目錄的項目超過 {MAX_DIR_ENTRIES} 個")
                o += rl
        return out, bad


class ExtReader(io.RawIOBase):
    def __init__(self, fs, runs, size):
        self.fs, self.size, self.pos = fs, size, 0
        self.runs = runs
        self.starts = [r[0] for r in runs]

    def readable(self):
        return True

    def readinto(self, b):
        if self.pos >= self.size:
            return 0
        bs = self.fs.bs
        want = min(len(b), self.size - self.pos)
        lb, within = divmod(self.pos, bs)
        k = bisect.bisect_right(self.starts, lb) - 1
        if k >= 0 and self.runs[k][0] <= lb < self.runs[k][0] + self.runs[k][2]:
            r0, p0, ln, init = self.runs[k]
            n = min(want, (r0 + ln - lb) * bs - within)
            if init:
                off = self.fs.base + (p0 + lb - r0) * bs + within
                data = os.pread(self.fs.fd, n, off)
                if len(data) != n:
                    raise OSError(errno.EIO, "檔案內容讀不完整（映像被截斷）")
            else:
                data = b"\0" * n
        else:
            nxt = self.starts[k + 1] if k + 1 < len(self.starts) else None
            end = self.size if nxt is None else min(self.size, nxt * bs)
            n = min(want, end - self.pos)
            data = b"\0" * n
        b[:n] = data
        self.pos += n
        return n


# ---------- FIT（boot 分割區）裡的核心 ----------

FDT_BEGIN, FDT_END_NODE, FDT_PROP, FDT_NOP, FDT_END = 1, 2, 3, 4, 9


def fdt_tree(blob):
    """FDT（flattened device tree，big-endian）→ {"name", "props", "children"}。所有位移都檢查範圍；不合理 → ValueError。"""
    if len(blob) < 40 or struct.unpack_from(">I", blob, 0)[0] != 0xD00DFEED:
        raise ValueError("不是 FDT（magic 不是 d00dfeed）")
    total, off_s, off_str, _, ver, _, _, size_str, size_s = struct.unpack_from(">9I", blob, 4)
    if total > len(blob) or off_s >= total or off_str > total:
        raise ValueError("FDT 表頭的位移超出範圍")
    end = off_s + size_s if ver >= 17 else total
    send = off_str + size_str if ver >= 3 else total
    if end > total or send > total:
        raise ValueError("FDT 的區段超出範圍")
    root, stack, o, n = None, [], off_s, 0
    while o + 4 <= end:
        tok = struct.unpack_from(">I", blob, o)[0]
        o += 4
        n += 1
        if n > 200000:
            raise ValueError("FDT 太大")
        if tok == FDT_BEGIN:
            z = blob.find(b"\0", o, end)
            if z < 0:
                raise ValueError("FDT 節點名稱沒有結尾")
            node = {"name": blob[o:z].decode("ascii", "replace"), "props": {}, "children": []}
            o = (z + 1 + 3) & ~3
            if stack:
                stack[-1]["children"].append(node)
            elif root is None:
                root = node
            else:
                raise ValueError("FDT 有兩個根節點")
            stack.append(node)
            if len(stack) > 32:
                raise ValueError("FDT 太深")
        elif tok == FDT_END_NODE:
            if not stack:
                raise ValueError("FDT 的節點結尾多了")
            stack.pop()
        elif tok == FDT_PROP:
            if o + 8 > end or not stack:
                raise ValueError("FDT 屬性超出範圍")
            ln, no = struct.unpack_from(">II", blob, o)
            o += 8
            if o + ln > end or off_str + no >= send:
                raise ValueError("FDT 屬性超出範圍")
            z = blob.find(b"\0", off_str + no, send)
            if z < 0:
                raise ValueError("FDT 屬性名稱沒有結尾")
            stack[-1]["props"][blob[off_str + no:z].decode("ascii", "replace")] = bytes(blob[o:o + ln])
            o = (o + ln + 3) & ~3
        elif tok == FDT_NOP:
            continue
        elif tok == FDT_END:
            break
        else:
            raise ValueError(f"FDT 不認得的 token {tok}")
    if root is None or stack:
        raise ValueError("FDT 結構不完整")
    return root, total


def prop_str(node, name):
    v = node["props"].get(name)
    return v.split(b"\0", 1)[0].decode("ascii", "replace") if v is not None else None


def prop_u32(node, name):
    v = node["props"].get(name)
    return struct.unpack(">I", v[:4])[0] if v is not None and len(v) >= 4 else None


def child(node, name):
    return next((c for c in node["children"] if c["name"] == name), None)


def fit_kernel(fd, off, size):
    """boot 分割區（FIT）→ (核心的資料來源, 說明 dict)。資料來源是 ("range", 位移, 長度) 或 ("bytes", 內容) 或 None。"""
    info = {"format": None, "image": None, "compression": None, "note": None}
    head = pread(fd, off, min(size, 40))
    if len(head) >= 8 and head[:8] == b"ANDROID!":
        info["format"] = "android-boot"
        info["note"] = "boot is an Android boot image, not a FIT: kernel not extracted (not supported yet)"
        return None, info
    if len(head) < 40 or struct.unpack_from(">I", head, 0)[0] != 0xD00DFEED:
        info["note"] = "boot partition is not a FIT (no d00dfeed magic): kernel not extracted"
        return None, info
    info["format"] = "fit"
    total = struct.unpack_from(">I", head, 4)[0]
    if total > size or total > FIT_MAX:
        info["note"] = f"FIT header size {total} is larger than the partition or the {FIT_MAX >> 20} MB limit: kernel not extracted"
        return None, info
    blob = pread(fd, off, total)
    try:
        root, total = fdt_tree(blob)
    except ValueError as e:
        info["note"] = f"FIT structure is invalid ({e}): kernel not extracted"
        return None, info
    images = child(root, "images")
    kern = [c for c in (images or {"children": []})["children"] if prop_str(c, "type") == "kernel"]
    if len(kern) != 1:
        cfgs = child(root, "configurations")
        dflt = prop_str(cfgs, "default") if cfgs else None
        cfg = child(cfgs, dflt) if cfgs and dflt else None
        kname = prop_str(cfg, "kernel") if cfg else None
        kern = [c for c in kern if c["name"] == kname]
        if len(kern) != 1:
            info["note"] = "FIT has no single kernel image (and no default configuration naming one): kernel not extracted"
            return None, info
    k = kern[0]
    info["image"] = k["name"]
    info["compression"] = prop_str(k, "compression") or "none"
    if child(k, "cipher") is not None:
        info["note"] = "the FIT kernel is encrypted (cipher node): kernel not extracted"
        return None, info
    if "data" in k["props"]:
        src = ("bytes", k["props"]["data"])
        dlen = len(src[1])
    else:
        dlen = prop_u32(k, "data-size")
        pos = prop_u32(k, "data-position")
        if pos is None and prop_u32(k, "data-offset") is not None:
            pos = ((total + 3) & ~3) + prop_u32(k, "data-offset")
        if dlen is None or pos is None or pos + dlen > size:
            info["note"] = "FIT kernel data position/size missing or outside the partition: kernel not extracted"
            return None, info
        src = ("range", off + pos, dlen)
    info["bytes"] = dlen
    comp = info["compression"]
    if comp == "lz4":
        if dlen > FIT_MAX:
            info["note"] = f"lz4 kernel data ({dlen} bytes) is larger than the {FIT_MAX >> 20} MB limit: kernel not extracted"
            return None, info
        data = src[1] if src[0] == "bytes" else pread(fd, src[1], src[2])
        try:
            src = ("bytes", lz4_decompress(data, KERNEL_MAX))
        except (ValueError, MemoryError) as e:
            info["note"] = f"lz4 kernel could not be decompressed ({e}): kernel not extracted"
            return None, info
        info["unpacked_bytes"] = len(src[1])
    elif comp not in ("none", "gzip", "bzip2", "lzma", "xz", "zstd"):
        info["note"] = f"kernel compression {comp!r} is not supported: kernel not extracted"
        return None, info
    return src, info


def lz4_block(src, out, cap, base=0):
    """LZ4 區塊 → 接在 out 後面。base：可以參照的最早位置（獨立區塊是區塊的開頭）。"""
    i, n = 0, len(src)
    while i < n:
        tok = src[i]
        i += 1
        lit = tok >> 4
        if lit == 15:
            while True:
                if i >= n:
                    raise ValueError("truncated literal length")
                b = src[i]
                i += 1
                lit += b
                if b != 255:
                    break
        if i + lit > n:
            raise ValueError("truncated literals")
        if len(out) + lit > cap:
            raise ValueError(f"larger than {cap >> 20} MB")
        out += src[i:i + lit]
        i += lit
        if i >= n:
            break
        if i + 2 > n:
            raise ValueError("truncated offset")
        off = src[i] | (src[i + 1] << 8)
        i += 2
        ml = tok & 15
        if ml == 15:
            while True:
                if i >= n:
                    raise ValueError("truncated match length")
                b = src[i]
                i += 1
                ml += b
                if b != 255:
                    break
        ml += 4
        if len(out) + ml > cap:
            raise ValueError(f"larger than {cap >> 20} MB")
        start = len(out) - off
        if off == 0 or start < base:
            raise ValueError("match offset outside the window")
        if off >= ml:
            out += out[start:start + ml]
        else:
            pat = bytes(out[start:])
            out += (pat * (ml // off + 1))[:ml]
        if len(out) > cap:
            raise ValueError(f"larger than {cap >> 20} MB")
    if len(out) > cap:
        raise ValueError(f"larger than {cap >> 20} MB")


def lz4_decompress(data, cap):
    """LZ4 frame（0x184D2204）或 legacy（0x184C2102，lz4 -l，核心的 Image.lz4）→ bytes。"""
    out = bytearray()
    i, n = 0, len(data)
    while i + 4 <= n:
        mg = u32(data, i)
        if mg == 0x184C2102:
            i += 4
            while i + 4 <= n:
                cs = u32(data, i)
                if cs == 0x184C2102:
                    break
                if cs > n - i - 4:
                    if n - i == 4:                     # 核心建置在最後加的 4 bytes 原始大小
                        i = n
                        break
                    raise ValueError("truncated legacy block")
                start = len(out)
                lz4_block(data[i + 4:i + 4 + cs], out, cap, start)
                i += 4 + cs
            continue
        if 0x184D2A50 <= mg <= 0x184D2A5F:              # skippable frame
            if i + 8 > n:
                raise ValueError("truncated skippable frame")
            i += 8 + u32(data, i + 4)
            continue
        if mg != 0x184D2204:
            if not out:
                raise ValueError("not an LZ4 frame")
            break
        if i + 7 > n:
            raise ValueError("truncated frame header")
        flg = data[i + 4]
        if flg >> 6 != 1:
            raise ValueError("unsupported LZ4 frame version")
        indep, bchk, csize, cchk, dictid = flg & 0x20, flg & 0x10, flg & 0x08, flg & 0x04, flg & 0x01
        if dictid:
            raise ValueError("LZ4 dictionary not supported")
        i += 6 + (8 if csize else 0) + 1                # magic、FLG、BD、[content size]、HC
        fstart = len(out)
        while True:
            if i + 4 > n:
                raise ValueError("truncated block")
            bsz = u32(data, i)
            i += 4
            if bsz == 0:
                break
            raw, bsz = bsz & 0x80000000, bsz & 0x7FFFFFFF
            if i + bsz > n:
                raise ValueError("truncated block")
            if raw:
                if len(out) + bsz > cap:
                    raise ValueError(f"larger than {cap >> 20} MB")
                out += data[i:i + bsz]
            else:
                lz4_block(data[i:i + bsz], out, cap, len(out) if indep else fstart)
            if len(out) > cap:
                raise ValueError(f"larger than {cap >> 20} MB")
            i += bsz + (4 if bchk else 0)
        i += 4 if cchk else 0
    return bytes(out)


# ---------- update.img ----------

class RkImage:
    """解析 RKFW／RKAF 與分割區表，修正 32 位元溢位。結構錯誤 → RkError；位置無法證明 → status GAP（不丟例外）。"""

    def __init__(self, path):
        self.path = os.path.abspath(path)
        self.fd = os.open(self.path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        try:
            self._parse()
        except BaseException:
            os.close(self.fd)
            raise

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    def _parse(self):
        fd = self.fd
        F = os.fstat(fd).st_size
        self.bytes = F
        hdr = pread(fd, 0, 0x29)
        if len(hdr) < 0x29 or hdr[:4] != b"RKFW":
            raise RkError("不是 Rockchip update.img（開頭不是 RKFW，或檔案太短）")
        loff, llen, ioff, ilen = struct.unpack_from("<IIII", hdr, 0x19)
        self.rkaf_offset = ioff
        self.rkfw = {"loader_offset": loff, "loader_length": llen, "rkaf_offset": ioff, "rkaf_length_stored": ilen,
                     "loader_in_header_area": loff + llen <= ioff}
        if ioff < 0x29 or ioff + RKAF_HDR + MD5_TRAILER > F:
            raise RkError(f"RKAF 位移 {ioff} 超出檔案（{F} bytes）")
        rk = pread(fd, ioff, RKAF_HDR + MAX_PARTS * PART_SIZE)
        if rk[:4] != b"RKAF":
            raise RkError(f"位移 {ioff} 不是 RKAF")
        n = u32(rk, 0x88)
        if not 1 <= n <= MAX_PARTS:
            raise RkError(f"分割區數 {n} 不合理（1–{MAX_PARTS}）")
        if len(rk) < RKAF_HDR + n * PART_SIZE or ioff + RKAF_HDR + n * PART_SIZE > F - MD5_TRAILER:
            raise RkError("RKAF 的分割區表被截斷")
        self.rkaf = {"length_stored": u32(rk, 4), "model": cstr(rk[8:0x2a]), "id": cstr(rk[0x2a:0x48]),
                     "manufacturer": cstr(rk[0x48:0x80]), "version": u32(rk, 0x84), "num_parts": n}
        self.hdr_end = RKAF_HDR + n * PART_SIZE
        tr = pread(fd, F - MD5_TRAILER, MD5_TRAILER)
        self.trailer = tr.decode("ascii").lower() if re.fullmatch(rb"[0-9a-fA-F]{32}", tr) else None
        self.real_len = F - ioff - MD5_TRAILER if self.trailer else None
        self.parts = []
        for k in range(n):
            o = RKAF_HDR + k * PART_SIZE
            name = rk[o:o + 32].split(b"\0", 1)[0]
            ns, pos, na, pad, size = struct.unpack_from("<5I", rk, o + 92)
            nm = name.decode("ascii", "replace")
            self.parts.append({"index": k, "name": cstr(rk[o:o + 32]), "name_ok": bool(NAME_OK.fullmatch(nm)) and nm.isascii(),
                               "file": cstr(rk[o + 32:o + 92]), "nand_size": ns, "nand_addr": na, "pos_stored": pos,
                               "padded_size_stored": pad, "size_stored": size, "pos": None, "size": None,
                               "offset_in_file": None, "ext4": None, "content": None, "anchored": None, "overflow_corrected": None,
                               "fs": None})
        self.status, self.reason, self.solutions = "OK", None, 0
        self._resolve()

    def _resolve(self):
        R = self.real_len
        if R is None:
            self.status, self.reason = "GAP", "檔案最後沒有 32 個十六進位字元的 MD5 結尾：真正的 RKAF 結尾無法確定，分割區位置無法證明"
            return
        chain = [p for p in self.parts if not (p["pos_stored"] == 0 and p["size_stored"] == 0)]
        if not chain:
            self.status, self.reason = "GAP", "分割區表沒有任何非空的分割區"
            return
        sbc, sols, budget = {}, [], [SEARCH_BUDGET]
        L = self.rkaf["length_stored"]

        def sb_at(pos):
            if pos not in sbc:
                sbc[pos] = superblock(self.fd, self.rkaf_offset + pos)
            return sbc[pos]

        def kind_at(pos):
            if sb_at(pos):
                return "ext4"
            head = pread(self.fd, self.rkaf_offset + pos, 8)
            return next((k for m, k in CONTENT_MAGIC if head.startswith(m)), None)
        allowed = {}
        for p in chain:
            cs = cands(p["pos_stored"], self.hdr_end, R)
            typed = [x for x in cs if kind_at(x)]
            allowed[p["index"]] = set(typed or cs)
            p["anchored"] = bool(typed)

        def dfs(i, prev_end, acc):
            if len(sols) > 1 or budget[0] <= 0:
                return
            budget[0] -= 1
            if i == len(chain):
                if 0 <= R - prev_end < SLACK and cands(L, prev_end, R):
                    sols.append(list(acc))
                return
            p = chain[i]
            lo = self.hdr_end if i == 0 else prev_end
            hi = R if i == 0 else min(R, prev_end + SLACK - 1)
            for pos in cands(p["pos_stored"], lo, hi):
                if pos not in allowed[p["index"]]:
                    continue
                sb = sb_at(pos)
                if sb:
                    sizes = cands(p["size_stored"], sb["fs_bytes"], min(R - pos, sb["fs_bytes"] + TWO32 // 2 - 1))
                else:
                    sizes = cands(p["size_stored"], 0, R - pos)
                for s in sizes:
                    acc.append((pos, s, sb))
                    dfs(i + 1, pos + s, acc)
                    acc.pop()
        dfs(0, 0, [])
        self.solutions = len(sols)
        if budget[0] <= 0:
            self.status, self.reason = "GAP", f"分割區位置的組合太多（搜尋超過 {SEARCH_BUDGET} 步）：無法證明，不猜"
            return
        if len(sols) != 1:
            stored = "；".join(f"{p['name']} pos {p['pos_stored']} size {p['size_stored']}" for p in chain)
            why = "沒有任何一組" if not sols else "有不只一組"
            self.status = "GAP"
            self.reason = (f"{why}位置與大小同時符合「依序連續、結尾在 RKAF 結尾（{R} bytes）、RKAF 長度欄位、ext4 大小」"
                           f"（存的值：{stored}；RKAF 長度 {L}）：分割區位置無法證明，不猜")
            return
        for p, (pos, size, sb) in zip(chain, sols[0]):
            p.update({"pos": pos, "size": size, "offset_in_file": self.rkaf_offset + pos, "ext4": bool(sb),
                      "overflow_corrected": pos != p["pos_stored"] or size != p["size_stored"],
                      "fs": sb_json(sb) if sb else None})
            p["content"] = kind_at(pos)
            if p["content"] == "squashfs":
                p["fs_type"] = "squashfs"
        for p in self.parts:
            if p["pos"] is None:
                p.update({"pos": 0, "size": 0, "ext4": False, "overflow_corrected": False, "empty": True})
        ends = max(p["pos"] + p["size"] for p in chain)
        self.rkaf["length"] = cands(L, ends, R)[0]
        self.rkaf["length_corrected"] = self.rkaf["length"] != L

    @property
    def ok(self):
        return self.status == "OK"

    def corrected(self):
        return [p["name"] for p in self.parts if p.get("overflow_corrected")] + (["RKAF length"] if self.rkaf.get("length_corrected") else [])

    def named(self, name):
        """名稱合法、非空的分割區（同名多個 → 全部）。"""
        return [p for p in self.parts if p["name_ok"] and p["name"] == name and not p.get("empty")]

    def rootfs(self):
        """→ (分割區, None) 或 (None, 原因)。"""
        if not self.ok:
            return None, self.reason
        rs = self.named(ROOTFS_PART)
        if len(rs) != 1:
            return None, ("沒有名稱是 rootfs 的分割區" if not rs else f"rootfs 分割區有 {len(rs)} 個") + "：沒有可以掃描的 rootfs"
        p = rs[0]
        if not p["ext4"]:
            return None, f"rootfs 分割區不是 ext4（{p.get('fs_type') or '沒有 ext4 超級區塊'}）：不支援，沒有掃描"
        return p, None

    def hash_all(self):
        """一次依序讀完整個檔案：整個檔案的 md5／sha256、MD5 結尾核對（前面全部的 md5）、每個分割區與 RKFW loader 的 sha256。"""
        F, fd = self.bytes, self.fd
        whole_md5, whole_sha, body_md5 = hashlib.md5(), hashlib.sha256(), hashlib.md5()
        ranges = []
        for p in self.parts:
            if self.ok and not p.get("empty"):
                ranges.append((p["offset_in_file"], p["offset_in_file"] + p["size"], p))
        lo, ll = self.rkfw["loader_offset"], self.rkfw["loader_length"]
        loader = {}
        if 0 < lo and lo + ll <= F and ll:
            ranges.append((lo, lo + ll, loader))
        hs = {id(x): hashlib.sha256() for _, _, x in ranges}
        pos, body_end = 0, F - MD5_TRAILER
        while pos < F:
            b = os.pread(fd, 4 << 20, pos)
            if not b:
                raise RkError("讀取中檔案變短")
            end = pos + len(b)
            whole_md5.update(b)
            whole_sha.update(b)
            if pos < body_end:
                body_md5.update(b[:body_end - pos])
            for a, z, x in ranges:
                if a < end and z > pos:
                    hs[id(x)].update(b[max(a, pos) - pos:min(z, end) - pos])
            pos = end
        for a, z, x in ranges:
            x["sha256"] = hs[id(x)].hexdigest()
        if loader:
            self.rkfw["loader_sha256"] = loader["sha256"]
        got = body_md5.hexdigest()
        self.md5_trailer = {"trailer": self.trailer, "computed": got, "match": (got == self.trailer) if self.trailer else None}
        return {"bytes": F, "md5": whole_md5.hexdigest(), "sha256": whole_sha.hexdigest()}

    def kernel(self):
        """boot 分割區的核心 → (資料來源, 說明)。"""
        if not self.ok:
            return None, {"note": self.reason}
        bs = [p for p in self.named(BOOT_PART) if not p["ext4"]]
        if len(bs) != 1:
            return None, {"note": "no boot partition" if not bs else f"{len(bs)} boot partitions"}
        p = bs[0]
        return fit_kernel(self.fd, p["offset_in_file"], p["size"])

    def table(self):
        return {"status": self.status, "reason": self.reason, "solutions": self.solutions, "slack": SLACK,
                "real_rkaf_length": self.real_len, "overflow_corrected": self.corrected(),
                "rkfw": self.rkfw, "rkaf": self.rkaf, "partitions": self.parts}


# ---------- 虛擬 tar ----------

class RkInfo(tarfile.TarInfo):
    __slots__ = ("rk_open",)


def tinfo(name, typ, size=0, mode=0o644, mtime=0, uid=0, gid=0, linkname="", opener=None, dev=(0, 0)):
    t = RkInfo(name)
    t.type, t.size, t.mode, t.mtime, t.uid, t.gid, t.linkname = typ, size, mode, mtime, uid, gid, linkname
    t.devmajor, t.devminor = dev
    t.rk_open = opener
    return t


def new_stats():
    return {"reader": "rockchip_img.py（ext4 唯讀解析）", "dirs": 0, "files": 0, "symlinks": 0, "hardlinks": 0, "devices": 0,
            "fifos": 0, "skipped_sockets": 0, "skipped_other": 0, "unreadable_files": 0, "unreadable_dirs": 0,
            "corrupt_dir_blocks": 0, "rejected_names": 0, "dir_loops": 0, "too_deep": 0, "unreadable_inodes": 0,
            "journal_needs_recovery": False, "entries_limit": False, "kernel_area_losses": 0, "examples": []}


# 核心模組與 headers 的位置：這裡有沒讀到的項目時，C-kernel-config／C-kernel-module-map（直接讀虛擬 tar，看不到計數）的
# 模組清單與 .config 可能不完整（K2「模組不存在」的證據不可靠）
KERNEL_AREAS = tuple(f"{PREFIX}/{d}" for d in ("lib/modules", "usr/lib/modules", "usr/src")) + ("lib/modules", "usr/lib/modules", "usr/src")


LOSS_KEYS = ("unreadable_files", "unreadable_dirs", "unreadable_inodes", "corrupt_dir_blocks", "skipped_other", "rejected_names",
             "dir_loops", "too_deep")


def losses(stats):
    """rootfs 走訪時漏掉的（讀不到、格式不對、拒絕）：{種類: 數量}，沒有漏掉 → {}。"""
    return {k: stats.get(k, 0) for k in LOSS_KEYS if stats.get(k)}


class VirtualTar:
    """RkImage → tarfile 串流模式的介面（next()、members、extractfile()），給 flash_package.tar_entries、kernel_config.feed_tar、
    image_check.iter_tar 用。layout 不是 OK → RkError（呼叫端轉成 Fail）。"""

    def __init__(self, img, stats=None):
        rp, why = img.rootfs()
        if rp is None:
            raise RkError(why)
        self.img, self.members, self.offset = img, [], 0
        try:
            self.fs = Ext4(img.fd, rp["offset_in_file"], rp["size"])
        except Ext4Error as e:
            raise RkError(f"rootfs 分割區的 ext4 讀不到：{e}")
        try:
            self.root = self.fs.inode(2)
        except Ext4Error as e:
            raise RkError(f"rootfs 的根目錄讀不到：{e}")
        if self.root.kind != "dir":
            raise RkError("rootfs 的根目錄（inode 2）不是目錄")
        self.stats = stats if stats is not None else new_stats()
        self.stats["journal_needs_recovery"] = self.fs.recover
        self.loaded = 0
        self._it = self._gen()

    def next(self):
        m = next(self._it, None)
        if m is not None:
            self.members.append(m)
        return m

    def extractfile(self, m):
        op = getattr(m, "rk_open", None)
        return op() if op else None

    def close(self):
        self.img.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    def note(self, text):
        if text.startswith(KERNEL_AREAS):
            self.stats["kernel_area_losses"] += 1
        if len(self.stats["examples"]) < 200:
            self.stats["examples"].append(text)

    def _gen(self):
        img, fd = self.img, self.img.fd
        yield tinfo("bootloader", tarfile.DIRTYPE, mode=0o755)
        seen = set()
        for p in img.parts:
            if p.get("empty") or not p["name_ok"] or p["ext4"] or p["name"] in seen:
                continue
            seen.add(p["name"])
            sub, ext = ("config", ".txt") if p["name"] in TEXT_PARTS else ("bootloader", ".img")
            yield tinfo(f"{sub}/{p['name']}{ext}", tarfile.REGTYPE, size=p["size"],
                        opener=lambda p=p: stream(Range(fd, p["offset_in_file"], p["size"])))
        src, _ = img.kernel()
        if src is not None:
            if src[0] == "bytes":
                data = src[1]
                yield tinfo("kernel/Image", tarfile.REGTYPE, size=len(data), opener=lambda d=data: io.BytesIO(d))
            else:
                yield tinfo("kernel/Image", tarfile.REGTYPE, size=src[2], opener=lambda s=src: stream(Range(fd, s[1], s[2])))
        yield from self._walk()

    def _walk(self):
        fs, st, root = self.fs, self.stats, self.root
        pfx = getattr(self, "prefix", PREFIX)          # android_img.py 用同一個走訪器，前綴不同
        yield tinfo(pfx, tarfile.DIRTYPE, mode=root.mode & 0o7777, mtime=root.mtime, uid=root.uid, gid=root.gid)
        first = {}                       # 一般檔案的 inode → 第一次出現的名稱（之後的寫成硬連結）
        visited = {2}
        stack = [((), self._list(root, pfx))]
        while stack:
            base, it = stack[-1]
            nxt = next(it, None)
            if nxt is None:
                stack.pop()
                continue
            name, ino = nxt
            if b"/" in name or b"\0" in name or not name:
                st["rejected_names"] += 1
                self.note(f"{'/'.join(base)}/{name!r}（名稱含 / 或 NUL）")
                continue
            parts = base + (name.decode("utf-8", "surrogateescape"),)
            if len(parts) > MAX_DEPTH:
                st["too_deep"] += 1
                self.note(f"{'/'.join(parts[:8])}/…（超過 {MAX_DEPTH} 層）")
                continue
            path = pfx + "/" + "/".join(parts)
            try:
                i = fs.inode(ino)
            except Ext4Error as e:
                st["unreadable_inodes"] += 1          # 不寫成成員（型別不明；讀的程式不必處理打開失敗）：只計數
                self.note(f"{path}（{e}）")
                continue
            k = i.kind
            common = dict(mode=i.mode & 0o7777, mtime=i.mtime, uid=i.uid, gid=i.gid)
            if k == "dir":
                if ino in visited:
                    st["dir_loops"] += 1
                    self.note(f"{path}（目錄 inode {ino} 已經出現過：迴圈或多重連結，不再走進去）")
                    continue
                visited.add(ino)
                st["dirs"] += 1
                yield tinfo(path, tarfile.DIRTYPE, **common)
                stack.append((parts, self._list(i, path)))
            elif k == "file":
                if ino in first:
                    st["hardlinks"] += 1
                    yield tinfo(path, tarfile.LNKTYPE, linkname=first[ino], **common)
                    continue
                why = None
                if i.flags & ENCRYPT_FL:
                    why = "加密的檔案（ext4 encryption）"
                elif i.size > MAX_FILE:
                    why = f"大小 {i.size} 超過上限 {MAX_FILE}"
                else:
                    try:
                        if not i.flags & INLINE_DATA_FL:
                            fs.runs(i)               # 先確認區塊位置都在範圍內（讀不到的不報大小）
                    except Ext4Error as e:
                        why = str(e)
                if why:
                    st["unreadable_files"] += 1
                    self.note(f"{path}（{why}）")
                    continue
                if i.links > 1:
                    first[ino] = path
                st["files"] += 1
                yield tinfo(path, tarfile.REGTYPE, size=i.size, opener=lambda i=i: self._open(i), **common)
            elif k == "symlink":
                try:
                    t = fs.symlink(i)
                except Ext4Error as e:
                    st["unreadable_files"] += 1
                    self.note(f"{path}（符號連結：{e}）")
                    continue
                st["symlinks"] += 1
                yield tinfo(path, tarfile.SYMTYPE, linkname=t.decode("utf-8", "surrogateescape"), **common)
            elif k in ("chr", "blk"):
                b0, b1 = u32(i.block, 0), u32(i.block, 4)
                dev = (((b0 >> 8) & 0xFF, b0 & 0xFF) if b0 else ((b1 & 0xFFF00) >> 8, (b1 & 0xFF) | ((b1 >> 12) & 0xFFF00)))
                st["devices"] += 1
                yield tinfo(path, tarfile.CHRTYPE if k == "chr" else tarfile.BLKTYPE, dev=dev, **common)
            elif k == "fifo":
                st["fifos"] += 1
                yield tinfo(path, tarfile.FIFOTYPE, **common)
            elif k == "socket":
                st["skipped_sockets"] += 1          # tar 沒有 socket 型別
            else:
                st["skipped_other"] += 1
                self.note(f"{path}（不認得的 inode 型別 {oct(i.mode & S_IFMT)}）")

    def _list(self, i, path):
        try:
            ents, bad = self.fs.entries(i)
        except Ext4Error as e:
            self.stats["unreadable_dirs"] += 1
            self.note(f"{path}/（目錄讀不到：{e}）")
            return iter(())
        if bad:
            self.stats["corrupt_dir_blocks"] += bad
            self.note(f"{path}/（{bad} 個目錄區塊格式不對，其餘項目略過）")
        self.loaded += len(ents)
        if self.loaded > MAX_LOADED:
            self.stats["unreadable_dirs"] += 1
            self.stats["entries_limit"] = True
            self.note(f"{path}/（目錄項目總數超過 {MAX_LOADED}：沒有讀）")
            return iter(())
        return iter(sorted(ents))

    def _open(self, i):
        try:
            return self.fs.open(i)
        except Ext4Error as e:
            raise OSError(errno.EIO, str(e))


def open_virtual(path, stats=None):
    """update.img → VirtualTar（位置無法證明、沒有 ext4 的 rootfs → RkError）。"""
    img = RkImage(path)
    try:
        return VirtualTar(img, stats)
    except BaseException:
        img.close()
        raise


# ---------- zip 裡的 update.img ----------

def zip_member(zf, member=None):
    """zip 裡要用的 update.img：member 指定時用那個名稱；否則檔名（最後一層，不分大小寫）是 update.img 的唯一一個。"""
    infos = [i for i in zf.infolist() if not i.is_dir()]
    if member is not None:
        m = [i for i in infos if i.filename == member]
        if len(m) != 1:
            raise RkError(f"zip 裡沒有 {member!r}")
        return m[0]
    m = [i for i in infos if i.filename.replace("\\", "/").rsplit("/", 1)[-1].lower() == "update.img"]
    if len(m) == 1:
        return m[0]
    imgs = [i.filename for i in infos if i.filename.lower().endswith(".img")][:20]
    if not m:
        raise RkError(f"zip 裡沒有 update.img（.img 檔：{', '.join(imgs) or '無'}；用 --member 指定）")
    raise RkError(f"zip 裡有 {len(m)} 個 update.img（{', '.join(i.filename for i in m)}）：用 --member 指定")


def zip_info(path, member=None):
    """zip 的成員清單（名稱、大小；不打開內容）與選到的 update.img。"""
    with zipfile.ZipFile(path) as zf:
        m = zip_member(zf, member)
        infos = [i for i in zf.infolist() if not i.is_dir()]
        return {"file": os.path.basename(path), "bytes": os.path.getsize(path), "member": m.filename, "member_bytes": m.file_size,
                "member_compress": zipfile.compressor_names.get(m.compress_type, str(m.compress_type)),
                "members_count": len(infos),
                "other_members": [{"name": i.filename, "bytes": i.file_size} for i in infos if i is not m][:200],
                "note": "Other zip members (for example Windows flashing tools) are listed by name and size only: not opened, not scanned."}


def extract_member(path, out, member=None, free=None):
    """zip 裡的 update.img → out（串流複製，zipfile 核對 CRC）。其他成員不解開。→ (成員資訊, 寫出的 bytes)。"""
    with zipfile.ZipFile(path) as zf:
        m = zip_member(zf, member)
        if m.flag_bits & 0x1:
            raise RkError(f"{m.filename} 是加密的 zip 成員")
        if free is not None and free < m.file_size + (1 << 30):
            raise RkError(f"{os.path.dirname(os.path.abspath(out))} 的空間不夠：{m.filename} 有 {m.file_size} bytes（需要再多 1 GiB）")
        n = 0
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0), 0o600)
        ok = False
        try:
            with zf.open(m) as src, os.fdopen(fd, "wb") as dst:
                while True:
                    b = src.read(4 << 20)
                    if not b:
                        break
                    n += len(b)
                    if n > m.file_size:
                        raise RkError(f"{m.filename} 解開後比 zip 記的 {m.file_size} bytes 大")
                    dst.write(b)
            if n != m.file_size:
                raise RkError(f"{m.filename} 解開後 {n} bytes，zip 記的是 {m.file_size}")
            ok = True
        finally:
            if not ok:
                try:
                    os.remove(out)
                except OSError:
                    pass
        return m, n
