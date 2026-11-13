"""原始磁碟映像（Raspberry Pi OS 的 .img、.img.xz、.img.gz；MBR 或 GPT 分割區表）→ 與 Rockchip 一致的虛擬 tar。

給 tools/demo/flash_package.py 用：open_stream／open_source 遇到磁碟映像時改用這裡的 RpiTar，
把映像呈現成 tar 串流：rootfs/…（ext4 root 分割區）、bootloader/<boot 分割區的檔案>（start*.elf、fixup*.dat、bootcode.bin、config.txt、
cmdline.txt、overlays/、*.dtb）、kernel/<kernel*.img、initramfs*>。

規則：
- 映像是不可信資料：只讀（os.pread），不掛載、不用 loop 裝置、不用 sudo、不執行裡面的任何東西；所有數值都驗證並設上限。
- 分割區表：MBR（含延伸分割區的 EBR 鏈，最多 MAX_PARTS 個，迴圈偵測）或 GPT（表頭與分割區陣列的 CRC32 都核對）。
  重疊、超出檔案大小（被截斷）、數值不合理 → 記錄原因（status GAP），不猜。
- FAT12／16／32 唯讀解析（含長檔名 VFAT）；ext4 用 rockchip_img.py 的 Ext4 與 VirtualTar（不複製程式碼）。
- 壓縮（.xz／.gz）：隨機存取需要未壓縮的檔案，所以由 extract_image() 串流解壓到結果資料夾的暫存檔（大小上限、剩餘空間檢查、
  O_EXCL、0600、失敗即刪除）；用完由 scan-flash-package.sh 刪除。磁碟需求 ≈ 未壓縮的映像大小（Raspberry Pi OS lite 約 3 GB）。
- Raspberry Pi 4／5 的 EEPROM 開機程式不在映像裡（在板子上）：list.json 的 disk_image.not_in_image 明列為「沒有涵蓋」。
- boot 分割區依內容選，不依順序（Radxa 等映像的第一個 FAT 是小的 config 分割區，核心與 extlinux 在後面的 EFI system 分割區）：
  FAT 分割區的根目錄（以及 boot/）有核心（KERNEL_RE）、extlinux/、EFI/ 或 Raspberry Pi 韌體（bootcode.bin、start*.elf）才算有開機檔；
  恰好一個有 → 它；多個有 → 其中恰好一個是 EFI system 分割區才選它，否則不猜；都沒有 → 只有一個 FAT 時用它，
  否則恰好一個 EFI system 分割區才選它，否則不猜。只有 config.txt 不算（Radxa 的 config 分割區也有）。不猜時 boot_why 寫原因。
"""
import errno
import gzip
import hashlib
import importlib.util
import io
import lzma
import os
import re
import struct
import tarfile
import zlib

SECTOR = 512
MAX_PARTS = 64                  # MBR（含邏輯分割區）與 GPT 最多讀幾個分割區
GPT_MAX_ENTRIES = 256
GPT_MAX_ENTRY_SIZE = 512
EXT_CHAIN_MAX = 32              # 延伸分割區鏈的步數上限
MAX_IMAGE = 64 << 30            # 解壓後的映像上限
MIN_FREE_AFTER = 1 << 30        # 解壓時磁碟至少要留下的空間
FAT_MAX_FAT_BYTES = 32 << 20    # FAT 表讀進記憶體的上限
FAT_MAX_DIR_BYTES = 8 << 20     # 一個目錄的內容上限
FAT_MAX_ENTRIES = 50000         # 走訪的目錄項目總數上限
FAT_MAX_DEPTH = 16
FAT_MAX_FILE = 1 << 32
PREFIX = "rootfs"
KERNEL_RE = re.compile(r"^(kernel[A-Za-z0-9_.+-]*\.img|initramfs[A-Za-z0-9_.+-]*|Image|zImage|vmlinu[xz][A-Za-z0-9_.+-]*)$")
BOOT_FW_RE = re.compile(r"^(bootcode\.bin|start[A-Za-z0-9_]*\.elf)$", re.I)   # Raspberry Pi 的 GPU 韌體（在 boot 分割區）
BOOT_DIRS = ("extlinux", "efi")                                                  # 小寫比對
GPT_TYPES = {
    "C12A7328-F81F-11D2-BA4B-00A0C93EC93B": "EFI system",
    "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7": "Microsoft basic data (FAT/NTFS)",
    "0FC63DAF-8483-4772-8E79-3D69D8477DE4": "Linux filesystem",
    "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F": "Linux swap",
    "933AC7E1-2EB4-4F13-B844-0E14E2AEF915": "Linux /home",
}
MBR_TYPES = {0x01: "FAT12", 0x04: "FAT16 <32M", 0x06: "FAT16", 0x0B: "FAT32 (CHS)", 0x0C: "FAT32 (LBA)", 0x0E: "FAT16 (LBA)",
             0x07: "NTFS/exFAT", 0x82: "Linux swap", 0x83: "Linux", 0xEE: "GPT protective", 0x05: "extended", 0x0F: "extended (LBA)",
             0x85: "Linux extended", 0xFD: "Linux RAID", 0xEF: "EFI system"}
NOT_IN_IMAGE = [{
    "name": "Raspberry Pi 4 / 5 EEPROM bootloader (pieeprom, recovery.bin)",
    "status": "NOT_ASSESSED",
    "note": "The Raspberry Pi 4 and 5 boot from an EEPROM on the board, not from this image. It is not in the image, so it was not "
            "inventoried or scanned; its version depends on what was flashed to each board. Not covered.",
}]
_RK = None


class RpiError(Exception):
    pass


def rk():
    """rockchip_img.py（Ext4 與 VirtualTar；python3 -I 不把這個資料夾放進 sys.path，依路徑載入）。"""
    global _RK
    if _RK is None:
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rockchip_img.py")
        spec = importlib.util.spec_from_file_location("sca_center_rockchip_img_rpi", p)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        _RK = m
    return _RK


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def pread(fd, off, n):
    if off < 0 or n < 0:
        raise OSError(errno.EINVAL, "negative offset")
    out = bytearray()
    while len(out) < n:
        try:
            b = os.pread(fd, n - len(out), off + len(out))
        except (OverflowError, ValueError):
            raise OSError(errno.EINVAL, "offset out of range")
        if not b:
            break
        out += b
    return bytes(out)


# ---------- 偵測 ----------

def _mbr_entries(b):
    """512 位元組的 MBR → [(boot, type, start, sectors)]（四個）；簽章不對 → None。"""
    if len(b) < 512 or b[510:512] != b"\x55\xaa":
        return None
    out = []
    for i in range(4):
        e = b[446 + 16 * i:462 + 16 * i]
        out.append((e[0], e[4], u32(e, 8), u32(e, 12)))
    return out


def head_is_disk(head):
    """檔案開頭（至少 512 位元組，有 GPT 時要 1024）是不是磁碟映像：GPT 表頭，或有效的 MBR（至少一個分割區、旗標合理）。"""
    if len(head) >= 520 and head[512:520] == b"EFI PART":
        return _mbr_entries(head[:512]) is not None
    if len(head) >= 262 and head[257:262] == b"ustar":
        return False
    ents = _mbr_entries(head[:512])
    if ents is None:
        return False
    used = [e for e in ents if e[1] != 0 or e[2] or e[3]]
    if not used or any(e[0] not in (0, 0x80) for e in ents):
        return False
    return all(e[1] != 0 and e[3] > 0 and e[2] > 0 for e in used)


def detect(path):
    """→ 'raw-disk-img'、'raw-disk-img-xz'、'raw-disk-img-gz' 或 None（不是磁碟映像）。壓縮檔只解開開頭 2 KB 判斷。"""
    try:
        with open(path, "rb") as f:
            m = f.read(6)
            f.seek(0)
            if m[:6] == b"\xfd7zXZ\x00":
                d = lzma.LZMADecompressor()
                head = d.decompress(f.read(1 << 16), 2048)
                return "raw-disk-img-xz" if head_is_disk(head) else None
            if m[:2] == b"\x1f\x8b":
                with gzip.GzipFile(fileobj=f) as g:
                    head = g.read(2048)
                return "raw-disk-img-gz" if head_is_disk(head) else None
            return "raw-disk-img" if head_is_disk(f.read(2048)) else None
    except (OSError, EOFError, lzma.LZMAError, zlib.error):
        return None


# ---------- 壓縮映像 → 暫存檔 ----------

def extract_image(path, out, max_bytes=MAX_IMAGE):
    """.img.xz／.img.gz → out（串流解壓；不執行任何東西）。→ (未壓縮 bytes, sha256)。空間不夠、超過上限、壞的壓縮 → RpiError，out 刪除。"""
    d = os.path.dirname(os.path.abspath(out))
    free = os.statvfs(d)
    avail = free.f_bavail * free.f_frsize
    if avail < MIN_FREE_AFTER + (1 << 30):
        raise RpiError(f"{d} free space is {avail} bytes: not enough to decompress an image (keep at least {MIN_FREE_AFTER} bytes free)")
    with open(path, "rb") as f:
        m = f.read(6)
    try:
        src = lzma.open(path, "rb") if m == b"\xfd7zXZ\x00" else gzip.open(path, "rb") if m[:2] == b"\x1f\x8b" else None
    except OSError as e:
        raise RpiError(f"cannot open compressed image: {e}")
    if src is None:
        raise RpiError("not an .xz or .gz file")
    try:
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except OSError as e:
        raise RpiError(f"cannot create the output file {os.path.basename(out)} ({e.strerror}); it must not exist already")
    n, h, ok, last = 0, hashlib.sha256(), False, 0
    try:
        with src, os.fdopen(fd, "wb") as dst:
            while True:
                b = src.read(4 << 20)
                if not b:
                    break
                n += len(b)
                if n > max_bytes:
                    raise RpiError(f"decompressed size exceeds the limit of {max_bytes} bytes")
                if n - last >= (256 << 20):
                    last = n
                    s = os.statvfs(d)
                    if s.f_bavail * s.f_frsize < MIN_FREE_AFTER:
                        raise RpiError(f"{d} is running out of space after {n} bytes")
                h.update(b)
                dst.write(b)
        ok = True
    except (OSError, EOFError, lzma.LZMAError, zlib.error) as e:
        raise RpiError(f"decompression failed: {type(e).__name__}: {e}")
    finally:
        if not ok:
            try:
                os.remove(out)
            except OSError:
                pass
    return n, h.hexdigest()


# ---------- 分割區表 ----------

def _guid(b):
    a, c, d = struct.unpack_from("<IHH", b, 0)
    return f"{a:08X}-{c:04X}-{d:04X}-{b[8:10].hex().upper()}-{b[10:16].hex().upper()}"


def read_table(fd, size):
    """→ (scheme, parts, notes, disk_id)。parts：index、type、type_name、start_lba、sectors、offset、size、bootable、name；
    notes：不合理的地方（只記錄，呼叫端設 GAP）。結構錯誤（沒有表、GPT 的 CRC 不對）→ RpiError。"""
    head = pread(fd, 0, 1024)
    mbr = _mbr_entries(head[:512])
    if mbr is None:
        raise RpiError("no MBR/GPT signature (0x55AA) at offset 510: not a partitioned disk image")
    notes, parts = [], []
    total = size // SECTOR
    if len(head) >= 520 and head[512:520] == b"EFI PART":
        return _read_gpt(fd, size, head)
    if any(e[1] == 0xEE for e in mbr):
        raise RpiError("protective MBR (0xEE) but no GPT header at LBA 1")
    disk_id = head[440:444].hex()
    idx = 0
    ext = []
    for i, (boot, typ, start, sec) in enumerate(mbr):
        if typ == 0 and not start and not sec:
            continue
        if typ in (0x05, 0x0F, 0x85):
            ext.append((start, sec))
            continue
        idx += 1
        parts.append(_part(idx, f"{typ:#04x}", MBR_TYPES.get(typ, "unknown"), start, sec, bool(boot & 0x80), "", i + 1))
    for base, esec in ext:
        cur, seen = base, set()
        for _ in range(EXT_CHAIN_MAX):
            if cur in seen or cur * SECTOR + SECTOR > size:
                notes.append("extended partition chain is looping or beyond the file: logical partitions not read further")
                break
            seen.add(cur)
            ebr = pread(fd, cur * SECTOR, SECTOR)
            ents = _mbr_entries(ebr)
            if ents is None:
                notes.append("extended partition boot record has no 0x55AA signature: logical partitions not read further")
                break
            (b1, t1, s1, n1), (b2, t2, s2, n2) = ents[0], ents[1]
            if t1 and n1:
                idx += 1
                parts.append(_part(idx, f"{t1:#04x}", MBR_TYPES.get(t1, "unknown"), cur + s1, n1, bool(b1 & 0x80), "", idx))
            if t2 in (0x05, 0x0F, 0x85) and s2:
                cur = base + s2
            else:
                break
            if len(parts) >= MAX_PARTS:
                notes.append(f"more than {MAX_PARTS} partitions: the rest is not read")
                break
    if not parts:
        raise RpiError("MBR has no usable partition")
    return "mbr", _validate(parts, size, notes), notes, disk_id


def _part(index, typ, type_name, start, sec, bootable, name, slot):
    return {"index": index, "slot": slot, "type": typ, "type_name": type_name, "start_lba": start, "sectors": sec,
            "offset_in_file": start * SECTOR, "size": sec * SECTOR, "bootable": bootable, "name": name}


def _validate(parts, size, notes):
    parts = sorted(parts[:MAX_PARTS], key=lambda p: p["start_lba"])
    prev_end = 0
    for p in parts:
        end = p["offset_in_file"] + p["size"]
        p["truncated"] = end > size
        p["overlaps_previous"] = p["offset_in_file"] < prev_end
        if p["sectors"] == 0:
            p["empty"] = True
        if p["truncated"]:
            notes.append(f"partition {p['index']} ends at byte {end}, beyond the file ({size} bytes): the image is truncated")
        if p["overlaps_previous"]:
            notes.append(f"partition {p['index']} overlaps the previous partition")
        prev_end = max(prev_end, end)
    return parts


def _read_gpt(fd, size, head):
    h = head[512:1024]
    hsz = u32(h, 12)
    if not 92 <= hsz <= 512:
        raise RpiError(f"GPT header size {hsz} is not plausible")
    hb = bytearray(pread(fd, SECTOR, hsz))
    want = u32(hb, 16)
    hb[16:20] = b"\0\0\0\0"
    if zlib.crc32(bytes(hb)) & 0xFFFFFFFF != want:
        raise RpiError("GPT header CRC32 does not match")
    first_usable, last_usable = u64(h, 40), u64(h, 48)
    ent_lba, nent, esz, ecrc = u64(h, 72), u32(h, 80), u32(h, 84), u32(h, 88)
    if not (1 <= nent <= GPT_MAX_ENTRIES and 128 <= esz <= GPT_MAX_ENTRY_SIZE and esz & (esz - 1) == 0):
        raise RpiError(f"GPT entry count {nent} or entry size {esz} is not plausible")
    if ent_lba < 2 or ent_lba * SECTOR + nent * esz > size:
        raise RpiError(f"GPT partition entry array (LBA {ent_lba}) is outside the file ({size} bytes): truncated or invalid")
    try:
        arr = pread(fd, ent_lba * SECTOR, nent * esz)
    except OSError as e:
        raise RpiError(f"GPT partition entry array cannot be read: {e}")
    if len(arr) != nent * esz:
        raise RpiError("GPT partition entry array is beyond the file (truncated)")
    if zlib.crc32(arr) & 0xFFFFFFFF != ecrc:
        raise RpiError("GPT partition array CRC32 does not match")
    notes, parts = [], []
    for i in range(nent):
        e = arr[i * esz:(i + 1) * esz]
        if e[:16] == b"\0" * 16:
            continue
        first, last = u64(e, 32), u64(e, 40)
        if last < first or first < first_usable or last > last_usable:
            raise RpiError(f"GPT entry {i + 1} has an LBA range outside the usable area")
        guid = _guid(e[:16])
        nm = e[56:128].decode("utf-16-le", "replace").split("\0")[0]
        parts.append(_part(len(parts) + 1, guid, GPT_TYPES.get(guid, "unknown"), first, last - first + 1, False, nm, i + 1))
    if not parts:
        raise RpiError("GPT has no partition")
    return "gpt", _validate(parts, size, notes), notes, _guid(h[56:72])


# ---------- FAT12／16／32 ----------

class FatError(Exception):
    pass


def lfn_sum(short):
    s = 0
    for c in short:
        s = (((s & 1) << 7) + (s >> 1) + c) & 0xFF
    return s


class Fat:
    """一個 FAT12／16／32 檔案系統（唯讀）。base：在檔案裡的位移；limit：分割區大小。任何不合理的值 → FatError。"""

    def __init__(self, fd, base, limit):
        b = pread(fd, base, 512)
        if len(b) < 512 or b[510:512] != b"\x55\xaa":
            raise FatError("no 0x55AA boot sector signature")
        self.fd, self.base = fd, base
        bps, spc, rsvd, nf = u16(b, 11), b[13], u16(b, 14), b[16]
        rootent, tot16, fsz16 = u16(b, 17), u16(b, 19), u16(b, 22)
        tot32, fsz32 = u32(b, 32), u32(b, 36)
        if bps not in (512, 1024, 2048, 4096) or spc == 0 or spc & (spc - 1) or spc > 128 or rsvd < 1 or nf not in (1, 2) or b[21] < 0xF0:
            raise FatError("boot sector (BPB) values are not those of a FAT file system")
        total = tot16 or tot32
        fsz = fsz16 or fsz32
        if total == 0 or fsz == 0:
            raise FatError("FAT size or sector count is zero")
        self.bps, self.spc, self.total = bps, spc, total
        if total * bps > limit:
            raise FatError(f"file system ({total * bps} bytes) is larger than the partition ({limit} bytes): truncated")
        root_sectors = -(-rootent * 32 // bps)
        self.root_start = (rsvd + nf * fsz) * bps
        self.data_start = rsvd + nf * fsz + root_sectors
        if self.data_start >= total:
            raise FatError("no data area")
        self.clusters = (total - self.data_start) // spc
        self.kind = 12 if self.clusters < 4085 else 16 if self.clusters < 65525 else 32
        if self.kind == 32:
            if rootent != 0 or fsz16 != 0:
                raise FatError("FAT32 with a fixed root directory area")
            self.root_cluster = u32(b, 44)
            if not 2 <= self.root_cluster < self.clusters + 2:
                raise FatError("FAT32 root cluster is out of range")
        else:
            if rootent == 0:
                raise FatError("FAT12/16 without a root directory area")
            self.root_cluster, self.root_bytes = 0, rootent * 32
        need = {12: (self.clusters + 2) * 3 // 2 + 1, 16: (self.clusters + 2) * 2, 32: (self.clusters + 2) * 4}[self.kind]
        if fsz * bps < need or fsz * bps > FAT_MAX_FAT_BYTES:
            raise FatError("FAT table size is not plausible")
        self.fat = pread(fd, base + rsvd * bps, fsz * bps)
        if len(self.fat) != fsz * bps:
            raise FatError("FAT table is beyond the partition (truncated)")
        self.label = b[71:82].decode("cp437", "replace").strip() if self.kind == 32 else b[43:54].decode("cp437", "replace").strip()
        self.cbytes = spc * bps

    def next(self, c):
        f = self.fat
        if self.kind == 16:
            v = u16(f, c * 2)
            return -1 if v >= 0xFFF8 else v
        if self.kind == 32:
            v = u32(f, c * 4) & 0x0FFFFFFF
            return -1 if v >= 0x0FFFFFF8 else v
        o = c + c // 2
        v = u16(f, o)
        v = v >> 4 if c & 1 else v & 0xFFF
        return -1 if v >= 0xFF8 else v

    def chain(self, c, limit_bytes=None):
        """開頭簇 → 簇的清單。迴圈、指到空閒／壞簇／範圍外 → FatError。"""
        out, seen = [], set()
        cap = self.clusters if limit_bytes is None else min(self.clusters, -(-limit_bytes // self.cbytes))
        while c != -1:
            if c < 2 or c >= self.clusters + 2:
                raise FatError(f"cluster chain goes to cluster {c} (out of range, free or bad)")
            if c in seen:
                raise FatError("cluster chain loops")
            seen.add(c)
            out.append(c)
            if len(out) > cap:
                raise FatError("cluster chain is longer than the file size needs: not read, fail-closed")
            c = self.next(c)
            if c == 0 or (c > 0 and c >= 0xFF7 and self.kind == 12) or (c > 0 and c >= 0xFFF7 and self.kind == 16):
                raise FatError("cluster chain reaches a free or bad cluster")
        return out

    def runs(self, chain, size):
        """簇鏈 → [(檔案裡的位移, 長度)]，連續的簇合併，總長度截到 size。"""
        out, left = [], size
        for c in chain:
            if left <= 0:
                break
            off = self.base + (self.data_start + (c - 2) * self.spc) * self.bps
            n = min(self.cbytes, left)
            if out and out[-1][0] + out[-1][1] == off:
                out[-1] = (out[-1][0], out[-1][1] + n)
            else:
                out.append((off, n))
            left -= n
        return out

    def read_dir(self, cluster):
        """目錄的原始內容。cluster 0 = FAT12/16 的固定根目錄。"""
        if cluster == 0:
            if self.kind == 32:
                cluster = self.root_cluster
            else:
                d = pread(self.fd, self.base + self.root_start, self.root_bytes)
                if len(d) != self.root_bytes:
                    raise FatError("root directory is beyond the partition")
                return d
        ch = self.chain(cluster, FAT_MAX_DIR_BYTES)
        data = b"".join(pread(self.fd, o, n) for o, n in self.runs(ch, len(ch) * self.cbytes))
        if len(data) != len(ch) * self.cbytes:
            raise FatError("directory is beyond the partition")
        return data

    def entries(self, data):
        """目錄內容 → ([{name, dir, cluster, size, mtime, short}], 壞的長檔名數)。略過刪除項、磁碟區標籤、. 與 ..。"""
        out, lfn, bad_lfn = [], [], 0
        for i in range(0, len(data) - 31, 32):
            e = data[i:i + 32]
            if e[0] == 0:
                break
            if e[0] == 0xE5:
                lfn = []
                continue
            attr = e[11]
            if attr & 0x3F == 0x0F:
                lfn.append(e)
                continue
            if attr & 0x08:
                lfn = []
                continue
            short = bytearray(e[:11])
            if short[0] == 0x05:
                short[0] = 0xE5
            base, ext = bytes(short[:8]).rstrip(b" "), bytes(short[8:11]).rstrip(b" ")
            bs, es = base.decode("cp437", "replace"), ext.decode("cp437", "replace")
            if e[12] & 0x08:
                bs = bs.lower()
            if e[12] & 0x10:
                es = es.lower()
            name = bs + ("." + es if es else "")
            if lfn:
                nm = self._lfn(lfn, lfn_sum(bytes(e[:11])))
                if nm is None:
                    bad_lfn += 1
                else:
                    name = nm
            lfn = []
            if name in (".", "..") or not name:
                continue
            cl = u16(e, 26) | (u16(e, 20) << 16 if self.kind == 32 else 0)
            out.append({"name": name, "dir": bool(attr & 0x10), "cluster": cl, "size": u32(e, 28), "mtime": _dos_time(u16(e, 24), u16(e, 22)),
                        "short": bytes(e[:11]).decode("cp437", "replace")})
        return out, bad_lfn

    @staticmethod
    def _lfn(ents, csum):
        # 磁碟上的順序：最後一段（0x40 旗標、序號 n）先，序號遞減到 1，再來是短名稱項目
        if not ents or not ents[0][0] & 0x40:
            return None
        n = ents[0][0] & 0x3F
        if n != len(ents):
            return None
        chars = b""
        for k, e in enumerate(ents):
            if e[0] & 0x3F != n - k or e[13] != csum:
                return None
            chars = (e[1:11] + e[14:26] + e[28:32]) + chars
        s = chars.decode("utf-16-le", "replace")
        s = s.split("\0")[0].rstrip("￿")
        return s or None


def _dos_time(d, t):
    import calendar
    try:
        return calendar.timegm((1980 + (d >> 9), max(1, d >> 5 & 15), max(1, d & 31), t >> 11, min(59, t >> 5 & 63), min(59, (t & 31) * 2)))
    except (ValueError, OverflowError):
        return 0


class RunsReader(io.RawIOBase):
    """FAT 檔案的內容：位移區段的串接（os.pread）。"""

    def __init__(self, fd, runs):
        self.fd, self.runs, self.i, self.o = fd, runs, 0, 0

    def readable(self):
        return True

    def readinto(self, b):
        while self.i < len(self.runs) and self.o >= self.runs[self.i][1]:
            self.i, self.o = self.i + 1, 0
        if self.i >= len(self.runs):
            return 0
        off, n = self.runs[self.i]
        k = min(len(b), n - self.o)
        data = os.pread(self.fd, k, off + self.o)
        if not data:
            raise OSError(errno.EIO, "file is shorter than the partition table says")
        b[:len(data)] = data
        self.o += len(data)
        return len(data)


def valid_component(name):
    return bool(name) and name not in (".", "..") and len(name) <= 255 and not re.search(r"[\x00-\x1f/\\]", name)


# ---------- 映像 ----------

def _probe(fd, p):
    """分割區的檔案系統：'ext'（超級區塊 magic）、'fat'（BPB 有效）、'other'、'empty'。"""
    if p["sectors"] == 0 or p.get("truncated"):
        return "empty" if p["sectors"] == 0 else "other"
    sb = pread(fd, p["offset_in_file"] + 1024, 1024)
    if len(sb) >= 58 and u16(sb, 0x38) == 0xEF53:
        return "ext"
    try:
        Fat(fd, p["offset_in_file"], p["size"])
        return "fat"
    except (FatError, OSError, struct.error):
        return "other"


class RpiImage:
    """磁碟映像：分割區表、各分割區的檔案系統種類、boot（依內容選的 FAT 分割區，見模組說明）與 rootfs（ext4）的選擇。
    rootfs() 介面與 rockchip_img.RkImage 相同（VirtualTar 用）。"""

    def __init__(self, path):
        self.path = path
        self.fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        try:
            self.size = os.fstat(self.fd).st_size
            if self.size < 4096:
                raise RpiError("file is too small to be a disk image")
            self.scheme, self.parts, self.notes, self.disk_id = read_table(self.fd, self.size)
            self.notes = list(self.notes)
            for p in self.parts:
                p["fs_kind"] = _probe(self.fd, p)
            self._root = self._pick_root()
            self._boot = self._pick_boot()
        except BaseException:
            os.close(self.fd)
            raise

    def close(self):
        try:
            os.close(self.fd)
        except OSError:
            pass

    def _pick_root(self):
        cands = []
        for p in self.parts:
            if p["fs_kind"] != "ext":
                continue
            try:
                fs = rk().Ext4(self.fd, p["offset_in_file"], p["size"])
                ents, _ = fs.entries(fs.inode(2))
                names = {n for n, _i in ents}
                p["fs"] = {"label": fs.sb.get("label"), "fs_bytes": fs.sb["fs_bytes"]}
                p["has_root_dirs"] = b"etc" in names and b"usr" in names
                p["root_error"] = None
            except Exception as e:      # noqa: BLE001
                p["has_root_dirs"], p["root_error"] = False, f"{type(e).__name__}: {e}"
                continue
            if p["has_root_dirs"]:
                cands.append(p)
        if len(cands) == 1:
            self.root_why = None
            return cands[0]
        self.root_why = ("no ext4 partition with /etc and /usr" if not cands
                         else f"{len(cands)} ext4 partitions look like a root file system: not guessing which one")
        return None

    def _boot_signs(self, p):
        """FAT 分割區根目錄（與 boot/）裡的開機檔名稱（最多 10 個）；讀不到 → []，原因記在 p["boot_error"]。"""
        signs = []
        try:
            fat = Fat(self.fd, p["offset_in_file"], p["size"])
            todo = [("", 0)]
            while todo:
                pre, cl = todo.pop(0)
                ents, _bad = fat.entries(fat.read_dir(cl))
                for e in ents:
                    n, low = e["name"], e["name"].lower()
                    if e["dir"] and low in BOOT_DIRS:
                        signs.append(pre + n + "/")
                    elif e["dir"] and low == "boot" and not pre and e["cluster"] >= 2:
                        todo.append((n + "/", e["cluster"]))
                    elif not e["dir"] and (KERNEL_RE.match(n) or BOOT_FW_RE.match(n)):
                        signs.append(pre + n)
        except (FatError, OSError, struct.error) as e:
            p["boot_error"] = f"{type(e).__name__}: {e}"
        return sorted(signs)[:10]

    def _pick_boot(self):
        self.boot_why = None
        fats = [p for p in self.parts if p["fs_kind"] == "fat"]
        for p in fats:
            p["boot_signs"] = self._boot_signs(p)
        esp = [p for p in fats if p["type_name"] == "EFI system"]
        signed = [p for p in fats if p["boot_signs"]]
        if len(signed) == 1:
            return signed[0]
        if signed:
            esp_signed = [p for p in signed if p in esp]
            if len(esp_signed) == 1:
                return esp_signed[0]
            self.boot_why = f"{len(signed)} FAT partitions have boot files (kernel, extlinux/, EFI/ or firmware): not guessing which one"
            return None
        if len(fats) == 1:
            return fats[0]
        if len(esp) == 1:
            return esp[0]
        self.boot_why = ("no FAT partition" if not fats else
                         f"{len(fats)} FAT partitions and none has boot files (kernel, extlinux/, EFI/ or firmware): not guessing which one")
        return None

    def rootfs(self):
        return self._root, self.root_why

    def boot(self):
        return self._boot

    def hash_all(self):
        """一次讀完：整個映像與每個分割區的 sha256。"""
        whole = hashlib.sha256()
        hs = [(p, hashlib.sha256()) for p in self.parts if not p.get("truncated") and p["sectors"]]
        pos = 0
        while pos < self.size:
            b = os.pread(self.fd, min(4 << 20, self.size - pos), pos)
            if not b:
                break
            whole.update(b)
            for p, h in hs:
                lo, hi = p["offset_in_file"], p["offset_in_file"] + p["size"]
                if pos < hi and pos + len(b) > lo:
                    h.update(b[max(lo, pos) - pos:min(hi, pos + len(b)) - pos])
            pos += len(b)
        for p, h in hs:
            p["sha256"] = h.hexdigest()
        return {"bytes": self.size, "sha256": whole.hexdigest()}

    def table(self):
        keep = ("index", "slot", "type", "type_name", "name", "start_lba", "sectors", "offset_in_file", "size", "bootable", "fs_kind",
                "truncated", "overlaps_previous", "sha256", "label", "fs", "has_root_dirs", "boot_signs", "boot_error")
        return {"scheme": self.scheme, "disk_id": self.disk_id, "sector_size": SECTOR,
                "boot_partition": self._boot["index"] if self._boot is not None else None, "boot_why": self.boot_why,
                "partitions": [{k: p[k] for k in keep if k in p} for p in self.parts]}

    @property
    def ok(self):
        return self._root is not None and not any(p.get("truncated") for p in self.parts)


# ---------- 虛擬 tar ----------

class RpiTar(rk().VirtualTar):
    """RpiImage → tarfile 串流介面（rockchip_img.VirtualTar 的 rootfs 走訪重用）；開頭先列 boot 分割區（bootloader/、kernel/）。"""

    def __init__(self, img, stats=None):
        super().__init__(img, stats)
        self.fat_stats = {"files": 0, "dirs": 0, "rejected_names": 0, "unreadable": 0, "bad_long_names": 0, "limit": False,
                          "fat_kind": None, "examples": []}

    def _gen(self):
        tinfo, T = rk().tinfo, tarfile
        yield tinfo("bootloader", T.DIRTYPE, mode=0o755)
        b = self.img.boot()
        if b is not None:
            try:
                yield from self._fat(b)
            except (FatError, OSError) as e:
                self.fat_stats["unreadable"] += 1
                self._fnote(f"boot partition: {e}")
        yield from self._walk()

    def _fnote(self, t):
        if len(self.fat_stats["examples"]) < 100:
            self.fat_stats["examples"].append(t)

    def _fat(self, p):
        tinfo, T, st = rk().tinfo, tarfile, self.fat_stats
        fd = self.img.fd
        fat = Fat(fd, p["offset_in_file"], p["size"])
        st["fat_kind"] = f"FAT{fat.kind}"
        loaded, seen = 0, set()
        todo = [((), 0)]
        while todo:
            base, cl = todo.pop(0)
            try:
                ents, bad = fat.entries(fat.read_dir(cl))
            except FatError as e:
                st["unreadable"] += 1
                self._fnote(f"/{'/'.join(base)}: {e}")
                continue
            st["bad_long_names"] += bad
            for e in sorted(ents, key=lambda x: x["name"]):
                loaded += 1
                if loaded > FAT_MAX_ENTRIES:
                    st["limit"] = True
                    return
                nm = e["name"]
                if not valid_component(nm) or len(base) >= FAT_MAX_DEPTH:
                    st["rejected_names"] += 1
                    self._fnote(f"/{'/'.join(base)}/{nm!r} (name or depth rejected)")
                    continue
                parts = base + (nm,)
                rel = "/".join(parts)
                if e["dir"]:
                    if e["cluster"] < 2 or e["cluster"] in seen:
                        st["unreadable"] += 1
                        self._fnote(f"{rel}/ (directory cluster {e['cluster']} invalid or seen before)")
                        continue
                    seen.add(e["cluster"])
                    st["dirs"] += 1
                    yield tinfo("bootloader/" + rel, T.DIRTYPE, mode=0o755, mtime=e["mtime"])
                    todo.append((parts, e["cluster"]))
                    continue
                if e["size"] > FAT_MAX_FILE:
                    st["unreadable"] += 1
                    continue
                try:
                    runs = fat.runs(fat.chain(e["cluster"], e["size"]), e["size"]) if e["size"] else []
                    if sum(n for _o, n in runs) != e["size"]:
                        raise FatError("cluster chain does not match the file size (shorter or longer than needed): not read, fail-closed")
                except FatError as err:
                    st["unreadable"] += 1
                    self._fnote(f"{rel} ({err})")
                    continue
                st["files"] += 1
                top = len(parts) == 1 and KERNEL_RE.match(nm)
                name = ("kernel/" + nm) if top else "bootloader/" + rel
                yield tinfo(name, T.REGTYPE, size=e["size"], mode=0o644, mtime=e["mtime"],
                            opener=lambda r=runs: io.BufferedReader(RunsReader(fd, r), 1 << 20))


def open_virtual(path, stats=None):
    """磁碟映像 → RpiTar（沒有可用的 rootfs → RpiError）。"""
    img = RpiImage(path)
    try:
        rp, why = img.rootfs()
        if rp is None:
            raise RpiError(why)
        try:
            return RpiTar(img, stats)
        except rk().RkError as e:
            raise RpiError(str(e))
    except BaseException:
        img.close()
        raise


def losses(stats):
    return rk().losses(stats)


def new_stats():
    s = rk().new_stats()
    s["reader"] = "rpi_img.py (MBR/GPT, FAT, ext4 read-only parsing)"
    return s
