"""Android image packages: read-only inventory of what can be analysed honestly (phase 1).

Used by tools/demo/flash_package.py (archive_format / open_stream / open_source / do_list) when the input is an Android image
package.  Nothing is executed or mounted; everything is parsed from bytes with the standard library.  The input is untrusted:
every offset and length is range-checked, sizes are capped, names are validated.

Accepted inputs
  * a directory, a zip or a plain (uncompressed) tar holding images (a factory zip with image-*.zip inside is opened one level);
  * a single image: Android sparse (0xED26FF3A), super.img (LP metadata), boot / vendor_boot / init_boot, dtbo, vbmeta,
    or a bare EROFS filesystem image.
What is read
  * sparse images are expanded (streamed) into a temporary file in the work folder (capped, deleted afterwards);
  * super.img: LP metadata slot 0 -> logical partitions and extents (fragmented partitions are copied to a temporary file);
  * ext4 (reader of rockchip_img.py) and EROFS (uncompressed layouts: flat plain, flat inline, chunk based);
    EROFS files stored in a compressed layout are listed but NOT_ASSESSED (no decoder in phase 1);
    f2fs, squashfs and unknown filesystems are NOT_ASSESSED;
  * boot headers v0-v4 (kernel, ramdisk, dtb), vendor_boot v3/v4: kernel version string and IKCONFIG, ramdisk (cpio) file list.
Work folder: the folder given by the caller (flash_package list: next to the result files), else $ANDROID_WORKDIR; no fallback
(never /tmp, never the current directory, never inside a git work tree).
Virtual tar layout (for the same consumers as the Rockchip virtual tar)
  <partition>/...   file systems (system, vendor, product, system_ext, odm, vendor_dlkm, system_dlkm, ...)
  boot/<image>.img, boot/<image>/ramdisk/..., boot/<image>/dtb/<n>.dtb   boot-like images
  bootloader/<image>.img   images that are not file systems (vbmeta, dtbo, unknown)
  kernel/Image             kernel (decompressed when gzip/lz4/xz/bzip2/lzma)
Not done in phase 1 (stated in the output, never shown as clean): vulnerability matching of Android components
(no dpkg, no Android Security Bulletin data), APK/APEX content, compressed EROFS, f2fs.
"""
import bz2
import hashlib
import importlib.util
import io
import json
import lzma
import os
import re
import shutil
import struct
import sys
import tarfile
import tempfile
import zipfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))

# ---------- limits (module constants so tests can lower them) ----------
MAX_IMAGE = 32 << 30           # largest raw image written to the work folder
MAX_WORK = 64 << 30            # all temporary files together
MIN_FREE = 1 << 30             # keep this much free space on the work folder
SMALL_MAX = 1 << 20            # build.prop and friends
APK_MEM_MAX = 128 << 20        # APKs up to this size are read into memory (hash + manifest)
SO_SCAN_MAX = 64 << 20         # shared libraries up to this size are scanned for version strings
LIST_CAP = 50000               # entries per category kept in the JSON
RAMDISK_MAX = 256 << 20
KERNEL_MAX = 256 << 20
CPIO_MAX_ENTRIES = 200000
NESTED_ZIP_MAX = 8 << 30
MAX_MEMBERS = 20000            # zip / tar / directory entries looked at
DTB_MAX = 64 << 20
RAMDISK_FRAGMENTS_MAX = 256

NAME_OK = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


class AndroidError(Exception):
    pass


CATCH = (AndroidError, OSError, struct.error, ValueError, RuntimeError, MemoryError, IndexError, OverflowError,
         EOFError, zlib.error, lzma.LZMAError)


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


_RK = None
_KC = False


def rk():
    global _RK
    if _RK is None:
        _RK = _load("sca_center_rockchip_img_android", os.path.join(HERE, "rockchip_img.py"))
    return _RK


def kernel_config():
    """tools/pilot/lib/kernel_config.py (IKCONFIG extraction) or None when this Python cannot load it."""
    global _KC
    if _KC is False:
        try:
            _KC = _load("sca_center_kernel_config_android", os.path.join(HERE, "..", "pilot", "lib", "kernel_config.py"))
        except Exception:                                   # SyntaxError on old Pythons, missing file...
            _KC = None
    return _KC


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def cstr(b):
    return b.split(b"\0", 1)[0].decode("utf-8", "backslashreplace")


def pread(fd, off, n):
    return rk().pread(fd, off, n)


def sha256_range(fd, off, size):
    h = hashlib.sha256()
    pos, end = off, off + size
    while pos < end:
        b = os.pread(fd, min(4 << 20, end - pos), pos)
        if not b:
            raise OSError("short read")
        h.update(b)
        pos += len(b)
    return h.hexdigest()


def hash_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(4 << 20)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


# ---------- detection ----------

SPARSE_MAGIC = b"\x3a\xff\x26\xed"
EROFS_MAGIC = 0xE0F5E1E2
F2FS_MAGIC = 0xF2F52010


def sniff_head(head):
    if head[:4] == SPARSE_MAGIC:
        return "sparse"
    if head[:8] == b"ANDROID!":
        return "boot"
    if head[:8] == b"VNDRBOOT":
        return "vendor_boot"
    if head[:4] == b"AVB0":
        return "vbmeta"
    if head[:4] == b"\xd7\xb7\xab\x1e":
        return "dtbo"
    return None


def sniff_fd_range(fd, off):
    """File system kind at fd+off: ext4, erofs, f2fs, squashfs or unknown."""
    sb = pread(fd, off + 1024, 0x40)
    if len(sb) >= 0x3A and u16(sb, 0x38) == 0xEF53:
        return "ext4"
    if len(sb) >= 4 and u32(sb, 0) == EROFS_MAGIC:
        return "erofs"
    if len(sb) >= 4 and u32(sb, 0) == F2FS_MAGIC:
        return "f2fs"
    if pread(fd, off, 4) == b"hsqs":
        return "squashfs"
    return "unknown"


def sniff_fd(fd):
    """Raw image on disk -> boot, vendor_boot, vbmeta, dtbo, super, ext4, erofs, f2fs, squashfs or unknown."""
    k = sniff_head(pread(fd, 0, 16))
    if k and k != "sparse":
        return k
    if pread(fd, 4096, 4) == b"gDla":
        return "super"
    return sniff_fd_range(fd, 0)


def _zip_names(path):
    try:
        with zipfile.ZipFile(path) as zf:
            return [i.filename for i in zf.infolist() if not i.is_dir()][:5000]
    except (zipfile.BadZipFile, OSError):
        return []


def _names_look_android(names):
    base = [n.replace("\\", "/").rsplit("/", 1)[-1].lower() for n in names]
    if "update.img" in base or "package-file" in base or "flash.sh" in base or any(b.startswith("rootfs") for b in base):
        return False                        # Rockchip update.img container / Rockchip or Jetson Linux split packages keep their own path
    imgs = {b[:-4] for b in base if b.endswith(".img")}
    nested = [b for b in base if re.fullmatch(r"image-.*\.zip", b)]
    return bool(imgs & {"super", "boot", "system", "vendor", "init_boot", "vendor_boot", "product"} or nested)


def _tar_looks_android(path):
    names = []
    try:
        with tarfile.open(path, "r:") as t:
            for i, m in enumerate(t):
                if i > 2000:
                    break
                if m.isreg():
                    names.append(m.name)
    except (tarfile.TarError, OSError):
        return False
    return _names_look_android(names)


def detect(path):
    """File -> 'android' when it is an Android package this module reads, else None.  Cheap (header bytes / member names)."""
    try:
        with open(path, "rb") as f:
            head = f.read(4096 + 4)
            if head[:4] == b"PK\x03\x04":
                return "android" if _names_look_android(_zip_names(path)) else None
            if sniff_head(head) or head[4096:4100] == b"gDla":
                return "android"
            if head[257:262] == b"ustar":
                return "android" if _tar_looks_android(path) else None
            return "android" if sniff_fd_range(f.fileno(), 0) == "erofs" else None
    except OSError:
        return None


def is_android_dir(path):
    try:
        names = [d.name for d in os.scandir(path)]
    except OSError:
        return False
    low = {n.lower() for n in names}
    if "flash.sh" in low or any(n.startswith("rootfs") for n in low) or "update.img" in low:
        return False
    return _names_look_android(names)


# ---------- sparse ----------

def readn(src, n):
    out = bytearray()
    while len(out) < n:
        b = src.read(n - len(out))
        if not b:
            break
        out += b
    return bytes(out)


def unsparse(src, out_path, cap=None, reserve=None):
    """Android sparse stream -> raw file (zero runs stay holes).  Returns an info dict.  AndroidError on anything inconsistent."""
    cap = MAX_IMAGE if cap is None else cap
    hdr = readn(src, 28)
    if len(hdr) < 28 or hdr[:4] != SPARSE_MAGIC:
        raise AndroidError("not an Android sparse image")
    _, major, minor, fhs, chs, blk, total_blks, total_chunks, _crc = struct.unpack("<IHHHHIIII", hdr)
    if major != 1 or fhs < 28 or chs < 12 or chs > 64 or fhs > 4096:
        raise AndroidError(f"unsupported sparse header (version {major}.{minor}, header sizes {fhs}/{chs})")
    if blk < 512 or blk > (1 << 24) or blk % 4:
        raise AndroidError(f"implausible sparse block size {blk}")
    size = total_blks * blk
    if size > cap:
        raise AndroidError(f"expanded size {size} exceeds the cap {cap}")
    if total_chunks > total_blks + 1:
        raise AndroidError("more chunks than blocks")
    if fhs > 28:
        readn(src, fhs - 28)
    if reserve is not None:
        reserve(size)                                       # space check + accounting before anything is written
    if shutil.disk_usage(os.path.dirname(os.path.abspath(out_path))).free < MIN_FREE:
        raise AndroidError("not enough free space in the work folder")
    pos = written = 0                                       # pos in blocks
    kinds = {"raw": 0, "fill": 0, "dont_care": 0, "crc32": 0}
    with open(out_path, "wb") as out:
        out.truncate(size)
        for _ in range(total_chunks):
            ch = readn(src, chs)
            if len(ch) < chs:
                raise AndroidError("sparse image truncated in a chunk header")
            typ, _, csz, tsz = struct.unpack_from("<HHII", ch, 0)
            body = tsz - chs
            if body < 0:
                raise AndroidError("negative chunk size")
            if typ not in (0xCAC1, 0xCAC2, 0xCAC3, 0xCAC4):
                raise AndroidError(f"unknown sparse chunk type {typ:#x}")
            if typ in (0xCAC1, 0xCAC2, 0xCAC3) and pos + csz > total_blks:
                raise AndroidError("chunks run past the end of the image")
            if typ == 0xCAC1:
                if body != csz * blk:
                    raise AndroidError("raw chunk size does not match its block count")
                left = body
                out.seek(pos * blk)
                while left:
                    b = readn(src, min(left, 4 << 20))
                    if not b:
                        raise AndroidError("sparse image truncated in raw data")
                    if b.count(0) == len(b):
                        out.seek(len(b), 1)
                    else:
                        out.write(b)
                        written += len(b)
                    left -= len(b)
                pos += csz
                kinds["raw"] += 1
            elif typ == 0xCAC2:
                if body != 4:
                    raise AndroidError("bad fill chunk")
                fill = readn(src, 4)
                if len(fill) < 4:
                    raise AndroidError("sparse image truncated in a fill chunk")
                if fill != b"\0\0\0\0":
                    out.seek(pos * blk)
                    piece = fill * (min(csz * blk, 1 << 20) // 4)
                    left = csz * blk
                    while left:
                        n = min(left, len(piece))
                        out.write(piece[:n])
                        left -= n
                    written += csz * blk
                pos += csz
                kinds["fill"] += 1
            elif typ == 0xCAC3:
                if body:
                    raise AndroidError("dont-care chunk with a body")
                pos += csz
                kinds["dont_care"] += 1
            elif typ == 0xCAC4:
                if body != 4 or csz != 0:
                    raise AndroidError("bad crc32 chunk")
                readn(src, 4)
                kinds["crc32"] += 1
            else:
                raise AndroidError(f"unknown sparse chunk type {typ:#x}")
            if written > cap:
                raise AndroidError("expanded data exceeds the cap")
    if pos != total_blks:
        raise AndroidError(f"chunks cover {pos} of {total_blks} blocks")
    return {"block_size": blk, "blocks": total_blks, "expanded_bytes": size, "chunks": kinds,
            "note": "image_checksum / CRC chunks are not verified" if kinds["crc32"] else None}


# ---------- LP metadata (super.img) ----------

LP_GEOMETRY_OFF = 4096
LP_METADATA_OFF = 4096 * 3
LP_SECTOR = 512


def parse_super(fd):
    """super.img -> dict (partitions with extents).  Metadata slot 0 only.  AndroidError when geometry/metadata do not verify."""
    g = pread(fd, LP_GEOMETRY_OFF, 52)
    if len(g) < 52 or u32(g, 0) != 0x616C4467:
        raise AndroidError("no LP geometry (magic gDla) at 4096")
    gsize = u32(g, 4)
    if gsize < 52 or gsize > 4096:
        raise AndroidError("implausible LP geometry size")
    graw = bytearray(pread(fd, LP_GEOMETRY_OFF, gsize))
    want = bytes(graw[8:40])
    graw[8:40] = b"\0" * 32
    if hashlib.sha256(bytes(graw)).digest() != want:
        raise AndroidError("LP geometry checksum mismatch")
    max_meta, slots, lbs = u32(g, 40), u32(g, 44), u32(g, 48)
    if not (0 < max_meta <= 1 << 24) or not (1 <= slots <= 8) or lbs == 0:
        raise AndroidError("implausible LP geometry values")
    off = LP_METADATA_OFF
    h = pread(fd, off, 128)
    if len(h) < 128 or u32(h, 0) != 0x414C5030:
        raise AndroidError("no LP metadata header (magic 0PLA) for slot 0")
    major, minor, hsize = u16(h, 4), u16(h, 6), u32(h, 8)
    if major != 10 or hsize < 128 or hsize > 4096:
        raise AndroidError(f"unsupported LP metadata version {major}.{minor}")
    hraw = bytearray(pread(fd, off, hsize))
    hsum = bytes(hraw[12:44])
    hraw[12:44] = b"\0" * 32
    if hashlib.sha256(bytes(hraw)).digest() != hsum:
        raise AndroidError("LP metadata header checksum mismatch")
    tsize, tsum = u32(h, 44), bytes(h[48:80])
    if tsize > max_meta:
        raise AndroidError("LP tables larger than max metadata size")
    tables = pread(fd, off + hsize, tsize)
    if len(tables) != tsize or hashlib.sha256(tables).digest() != tsum:
        raise AndroidError("LP tables checksum mismatch")
    desc = [struct.unpack_from("<III", h, 80 + 12 * i) for i in range(4)]    # partitions, extents, groups, block devices
    for o, n, sz in desc:
        if n > 4096 or (n and (sz < 8 or o + n * sz > tsize)):
            raise AndroidError("LP table out of range")
    (po, pn, ps), (eo, en, es), (go, gn, gs), (bo, bn, bs) = desc
    if (pn and ps < 52) or (en and es < 24) or (gn and gs < 48) or (bn and bs < 64):
        raise AndroidError("LP table entry too small")
    groups = [cstr(tables[go + i * gs:go + i * gs + 36]) for i in range(gn)]
    bdevs = [{"name": cstr(tables[bo + i * bs + 24:bo + i * bs + 60]), "size": u64(tables, bo + i * bs + 16)} for i in range(bn)]
    extents = []
    for i in range(en):
        b = eo + i * es
        extents.append({"sectors": u64(tables, b), "type": u32(tables, b + 8), "data": u64(tables, b + 12), "source": u32(tables, b + 20)})
    parts = []
    for i in range(pn):
        b = po + i * ps
        name = cstr(tables[b:b + 36])
        attrs, first, num, grp = struct.unpack_from("<IIII", tables, b + 36)
        if first + num > en:
            raise AndroidError(f"partition {name!r}: extent index out of range")
        ex = extents[first:first + num]
        parts.append({"name": name, "attributes": attrs, "group": groups[grp] if grp < len(groups) else None,
                      "extents": ex, "size": sum(e["sectors"] for e in ex) * LP_SECTOR})
    return {"metadata_version": f"{major}.{minor}", "slot_count": slots, "max_metadata_size": max_meta, "logical_block_size": lbs,
            "block_devices": bdevs, "groups": groups, "partitions": parts, "slot_read": 0}


# ---------- EROFS (uncompressed layouts) ----------

class ErofsError(Exception):
    pass


E_PLAIN, E_COMPRESSED_FULL, E_INLINE, E_COMPRESSED_COMPACT, E_CHUNK = 0, 1, 2, 3, 4
E_LAYOUT = {0: "flat_plain", 1: "compressed_full", 2: "flat_inline", 3: "compressed_compact", 4: "chunk_based"}


class EInode:
    __slots__ = ("nid", "mode", "uid", "gid", "size", "mtime", "links", "layout", "iu", "xsize", "off", "isize", "ino")

    @property
    def kind(self):
        return rk().KINDS.get(self.mode & 0xF000, "other")


class Erofs:
    """Read-only EROFS: superblock, compact/extended inodes, directories, flat plain / flat inline / chunk-based data.
    Compressed layouts are recognised but not decoded (the caller marks those files NOT_ASSESSED)."""

    def __init__(self, fd, base, limit):
        sb = pread(fd, base + 1024, 128)
        if len(sb) < 128 or u32(sb, 0) != EROFS_MAGIC:
            raise ErofsError("no EROFS superblock (magic 0xE0F5E1E2 at 1024)")
        self.bits = sb[12]
        if not 9 <= self.bits <= 16:
            raise ErofsError(f"implausible EROFS block size bits {self.bits}")
        self.bs = 1 << self.bits
        self.root_nid = u16(sb, 14)
        self.build_time = u64(sb, 24)
        self.blocks = u32(sb, 36)
        self.meta = u32(sb, 40)
        self.incompat = u32(sb, 80)
        self.label = cstr(sb[64:80])
        self.uuid = sb[48:64].hex()
        self.fd, self.base, self.limit = fd, base, limit
        if self.blocks == 0 or self.blocks * self.bs > limit:
            raise ErofsError(f"EROFS size {self.blocks * self.bs} bytes does not fit its container ({limit} bytes)")
        if self.meta >= self.blocks:
            raise ErofsError("meta_blkaddr outside the file system")

    def info(self):
        return {"type": "erofs", "block_size": self.bs, "blocks": self.blocks, "fs_bytes": self.blocks * self.bs, "label": self.label,
                "uuid": self.uuid, "feature_incompat": hex(self.incompat), "build_time": self.build_time}

    def read(self, off, n):
        if off < 0 or n < 0 or off + n > self.blocks * self.bs:
            raise ErofsError(f"read at {off}+{n} outside the file system")
        d = pread(self.fd, self.base + off, n)
        if len(d) != n:
            raise ErofsError("image truncated")
        return d

    def inode(self, nid):
        off = self.meta * self.bs + nid * 32
        h = self.read(off, 32)
        fmt = u16(h, 0)
        i = EInode()
        i.nid, i.off = nid, off
        i.layout = (fmt >> 1) & 7
        xc = u16(h, 2)
        i.xsize = 0 if xc == 0 else 12 + (xc - 1) * 4
        i.mode = u16(h, 4)
        if fmt & 1 == 0:                                      # compact, 32 bytes
            i.isize, i.links, i.size, i.iu = 32, u16(h, 6), u32(h, 8), u32(h, 16)
            i.ino, i.uid, i.gid, i.mtime = u32(h, 20), u16(h, 24), u16(h, 26), self.build_time
        else:                                                 # extended, 64 bytes
            h += self.read(off + 32, 32)
            i.isize, i.size, i.iu, i.ino = 64, u64(h, 8), u32(h, 16), u32(h, 20)
            i.uid, i.gid, i.mtime, i.links = u32(h, 24), u32(h, 28), u64(h, 32), u32(h, 44)
        if i.layout not in E_LAYOUT:
            raise ErofsError(f"inode {nid}: unknown data layout {i.layout}")
        return i

    @staticmethod
    def compressed(i):
        return i.layout in (E_COMPRESSED_FULL, E_COMPRESSED_COMPACT)

    def segments(self, i):
        """Data of a non-compressed inode -> [(kind, a, b)]: ('fd', file offset, length), ('mem', bytes, 0), ('zero', length, 0)."""
        size, bs = i.size, self.bs
        if size == 0 or i.kind in ("chr", "blk", "fifo", "socket"):
            return []
        if size > rk().MAX_FILE:
            raise ErofsError(f"size {size} over the limit")
        if i.layout == E_PLAIN:
            if i.iu * bs + size > self.blocks * bs:
                raise ErofsError("data blocks outside the file system")
            return [("fd", self.base + i.iu * bs, size)]
        if i.layout == E_INLINE:
            full = size // bs * bs
            tail = size - full
            segs = []
            if full:
                if i.iu * bs + full > self.blocks * bs:
                    raise ErofsError("data blocks outside the file system")
                segs.append(("fd", self.base + i.iu * bs, full))
            if tail:
                to = i.off + i.isize + i.xsize
                if to // bs != (to + tail - 1) // bs:
                    raise ErofsError("inline tail crosses a block boundary")
                segs.append(("mem", self.read(to, tail), 0))
            return segs
        if i.layout == E_CHUNK:
            fmt = i.iu & 0xFFFF
            idx = bool(fmt & 0x20)
            cbits = self.bits + (fmt & 0x1F)
            if cbits > 40:
                raise ErofsError("implausible chunk size")
            csize = 1 << cbits
            n = -(-size // csize)
            if n > 1 << 22:
                raise ErofsError("too many chunks")
            unit = 8 if idx else 4
            p = -(-(i.off + i.isize + i.xsize) // unit) * unit
            tab = self.read(p, n * unit)
            segs, left = [], size
            for k in range(n):
                ln = min(csize, left)
                left -= ln
                if idx:
                    dev, blk = u16(tab, k * 8 + 2), u32(tab, k * 8 + 4) | (u16(tab, k * 8) << 32)
                    hole = blk in (0xFFFFFFFFFFFF, 0xFFFFFFFF)
                    if dev != 0 and not hole:
                        raise ErofsError("chunk on an extra device (multi-device EROFS)")
                else:
                    blk = u32(tab, k * 4)
                    hole = blk == 0xFFFFFFFF
                if hole:
                    segs.append(("zero", ln, 0))
                else:
                    if blk * bs + ln > self.blocks * bs:
                        raise ErofsError("chunk outside the file system")
                    segs.append(("fd", self.base + blk * bs, ln))
            return segs
        raise ErofsError(f"layout {E_LAYOUT[i.layout]} is compressed")

    def data(self, i, cap=1 << 26):
        if i.size > cap:
            raise ErofsError("too large to load")
        out = bytearray()
        for k, a, b in self.segments(i):
            out += os.pread(self.fd, b, a) if k == "fd" else a if k == "mem" else b"\0" * a
        return bytes(out)

    def open(self, i):
        return SegReader(self.fd, self.segments(i))

    def entries(self, i):
        """Directory inode -> ([(name bytes, nid, file_type)], number of bad blocks)."""
        if self.compressed(i):
            raise ErofsError("compressed directory")
        if i.size > rk().MAX_DIR:
            raise ErofsError("directory too large")
        data = self.data(i, rk().MAX_DIR)
        out, bad = [], 0
        for o in range(0, len(data), self.bs):
            blk = data[o:o + self.bs]
            if len(blk) < 12:
                bad += 1
                continue
            first = u16(blk, 8)
            if first % 12 or first == 0 or first > len(blk):
                bad += 1
                continue
            n = first // 12
            offs = [u16(blk, k * 12 + 8) for k in range(n)]
            if offs != sorted(offs) or offs[-1] > len(blk):
                bad += 1
                continue
            for k in range(n):
                end = offs[k + 1] if k + 1 < n else len(blk)
                name = blk[offs[k]:end]
                if k + 1 == n:
                    name = name.split(b"\0", 1)[0]
                out.append((name, u64(blk, k * 12), blk[k * 12 + 10]))
                if len(out) > rk().MAX_DIR_ENTRIES:
                    raise ErofsError("too many directory entries")
        return out, bad


class SegReader(io.RawIOBase):
    def __init__(self, fd, segs):
        self.fd, self.segs, self.k, self.o = fd, segs, 0, 0

    def readable(self):
        return True

    def readinto(self, b):
        while self.k < len(self.segs):
            kind, a, bb = self.segs[self.k]
            ln = bb if kind == "fd" else len(a) if kind == "mem" else a
            if self.o >= ln:
                self.k, self.o = self.k + 1, 0
                continue
            n = min(len(b), ln - self.o)
            if kind == "fd":
                d = os.pread(self.fd, n, a + self.o)
                if len(d) != n:
                    raise OSError(5, "image truncated")
            elif kind == "mem":
                d = a[self.o:self.o + n]
            else:
                d = b"\0" * n
            b[:n] = d
            self.o += n
            return n
        return 0


def stream_of(raw):
    return io.BufferedReader(raw, 1 << 20)


class ErofsWalker:
    """Yields tar infos like rockchip_img.VirtualTar._walk.  Compressed regular files are yielded with rk_open None
    (listed, size known, content NOT_ASSESSED) and counted in stats['not_assessed_compressed']."""

    def __init__(self, fs, prefix, stats):
        self.fs, self.prefix, self.stats = fs, prefix, stats
        stats.setdefault("not_assessed_compressed", 0)

    def note(self, text):
        if len(self.stats["examples"]) < 200:
            self.stats["examples"].append(text)

    def _walk(self):
        R, fs, st = rk(), self.fs, self.stats
        try:
            root = fs.inode(fs.root_nid)
        except ErofsError as e:
            raise AndroidError(f"EROFS root inode unreadable: {e}")
        if root.kind != "dir":
            raise AndroidError("EROFS root inode is not a directory")
        yield R.tinfo(self.prefix, tarfile.DIRTYPE, mode=root.mode & 0o7777, mtime=root.mtime, uid=root.uid, gid=root.gid)
        first, visited = {}, {root.nid}
        stack = [((), iter(self._list(root, self.prefix)))]
        while stack:
            base, it = stack[-1]
            nxt = next(it, None)
            if nxt is None:
                stack.pop()
                continue
            name, nid, _ = nxt
            if name in (b".", b".."):
                continue
            if b"/" in name or b"\0" in name or not name:
                st["rejected_names"] += 1
                self.note(f"{'/'.join(base)}/{name!r} (bad name)")
                continue
            parts = base + (name.decode("utf-8", "surrogateescape"),)
            if len(parts) > R.MAX_DEPTH:
                st["too_deep"] += 1
                continue
            path = self.prefix + "/" + "/".join(parts)
            try:
                i = fs.inode(nid)
            except ErofsError as e:
                st["unreadable_inodes"] += 1
                self.note(f"{path} ({e})")
                continue
            k = i.kind
            common = dict(mode=i.mode & 0o7777, mtime=i.mtime, uid=i.uid, gid=i.gid)
            if k == "dir":
                if nid in visited:
                    st["dir_loops"] += 1
                    self.note(f"{path} (directory seen twice)")
                    continue
                visited.add(nid)
                st["dirs"] += 1
                yield R.tinfo(path, tarfile.DIRTYPE, **common)
                stack.append((parts, iter(self._list(i, path))))
            elif k == "file":
                if nid in first:
                    st["hardlinks"] += 1
                    yield R.tinfo(path, tarfile.LNKTYPE, linkname=first[nid], **common)
                    continue
                if i.links > 1:
                    first[nid] = path
                if fs.compressed(i):
                    st["not_assessed_compressed"] += 1
                    self.note(f"{path} (compressed layout {E_LAYOUT[i.layout]}: content NOT_ASSESSED)")
                    yield R.tinfo(path, tarfile.REGTYPE, size=i.size, opener=None, **common)
                    continue
                try:
                    fs.segments(i)
                except ErofsError as e:
                    st["unreadable_files"] += 1
                    self.note(f"{path} ({e})")
                    continue
                st["files"] += 1
                yield R.tinfo(path, tarfile.REGTYPE, size=i.size, opener=lambda i=i: stream_of(fs.open(i)), **common)
            elif k == "symlink":
                t = None
                try:
                    if not fs.compressed(i):
                        t = fs.data(i, R.MAX_SYMLINK)
                except ErofsError as e:
                    self.note(f"{path} (symlink: {e})")
                if t is None:
                    st["unreadable_files"] += 1
                    continue
                st["symlinks"] += 1
                yield R.tinfo(path, tarfile.SYMTYPE, linkname=t.decode("utf-8", "surrogateescape"), **common)
            elif k in ("chr", "blk"):
                st["devices"] += 1
                yield R.tinfo(path, tarfile.CHRTYPE if k == "chr" else tarfile.BLKTYPE,
                              dev=((i.iu >> 8) & 0xFFF, (i.iu & 0xFF) | ((i.iu >> 12) & 0xFFF00)), **common)
            elif k == "fifo":
                st["fifos"] += 1
                yield R.tinfo(path, tarfile.FIFOTYPE, **common)
            elif k == "socket":
                st["skipped_sockets"] += 1
            else:
                st["skipped_other"] += 1

    def _list(self, i, path):
        try:
            ents, bad = self.fs.entries(i)
        except ErofsError as e:
            self.stats["unreadable_dirs"] += 1
            self.note(f"{path}/ (directory unreadable: {e})")
            return []
        if bad:
            self.stats["corrupt_dir_blocks"] += bad
            self.note(f"{path}/ ({bad} bad directory blocks)")
        return sorted(ents)


class Ext4Walker:
    """rockchip_img.VirtualTar's walker with another prefix (no update.img around it)."""

    def __init__(self, fd, base, size, prefix, stats):
        R = rk()
        try:
            self.fs = R.Ext4(fd, base, size)
            root = self.fs.inode(2)
        except R.Ext4Error as e:
            raise AndroidError(f"ext4 not readable: {e}")
        if root.kind != "dir":
            raise AndroidError("ext4 root inode is not a directory")
        vt = R.VirtualTar.__new__(R.VirtualTar)
        vt.fs, vt.root, vt.stats, vt.loaded, vt.prefix, vt.members, vt.offset = self.fs, root, stats, 0, prefix, [], 0
        stats["journal_needs_recovery"] = self.fs.recover
        self.vt = vt

    def _walk(self):
        return self.vt._walk()


# ---------- boot images ----------

def os_version(v):
    a, b, c = (v >> 25) & 0x7F, (v >> 18) & 0x7F, (v >> 11) & 0x7F
    y, m = ((v >> 4) & 0x7F) + 2000, v & 0xF
    if v == 0 or a == 0:
        return None, None
    return f"{a}.{b}.{c}", (f"{y:04d}-{m:02d}" if 1 <= m <= 12 else None)


def parse_boot(fd, size):
    """boot.img / init_boot.img (header v0-v4) -> dict with kernel/ramdisk/second/dtb ranges (absolute offsets)."""
    h = pread(fd, 0, 4096)
    if len(h) < 1632:
        raise AndroidError("boot header truncated")
    if h[:8] != b"ANDROID!":
        raise AndroidError("not a boot image")
    ver = u32(h, 40)
    if ver > 4:
        raise AndroidError(f"unsupported boot header version {ver}")
    ksz = u32(h, 8)
    rsz = u32(h, 12) if ver >= 3 else u32(h, 16)
    if ver >= 3:
        page = 4096
        osv, cmd = u32(h, 16), cstr(h[44:44 + 1536])
        second = rec = dtb = 0
        extra = {"boot_signature_size": u32(h, 1580) if ver == 4 else 0}
    else:
        page = u32(h, 36)
        if page not in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536):
            raise AndroidError(f"implausible page size {page}")
        second = u32(h, 24)
        osv, cmd = u32(h, 44), cstr(h[64:64 + 512]) + cstr(h[608:608 + 1024])
        rec = u32(h, 1632) if ver >= 1 and len(h) >= 1636 else 0
        dtb = u32(h, 1648) if ver >= 2 and len(h) >= 1652 else 0
        extra = {"name": cstr(h[48:64])}
    ver_s, spl = os_version(osv)
    off = page
    parts = {}
    for nm, ln in (("kernel", ksz), ("ramdisk", rsz), ("second", second), ("recovery_dtbo", rec), ("dtb", dtb)):
        if ln:
            if off + ln > size:
                raise AndroidError(f"{nm} ({ln} bytes at {off}) runs past the end of the file ({size})")
            parts[nm] = (off, ln)
        off += -(-ln // page) * page
    return {"header_version": ver, "page_size": page, "os_version": ver_s, "os_patch_level": spl, "cmdline": cmd, "parts": parts, **extra}


def parse_vendor_boot(fd, size):
    h = pread(fd, 0, 4096 * 2)
    if len(h) < 2128 or h[:8] != b"VNDRBOOT":
        raise AndroidError("not a vendor_boot image")
    ver = u32(h, 8)
    if ver not in (3, 4):
        raise AndroidError(f"unsupported vendor_boot header version {ver}")
    page = u32(h, 12)
    if page not in (2048, 4096, 8192, 16384):
        raise AndroidError(f"implausible page size {page}")
    hsz = u32(h, 2096)
    rsz, dtb = u32(h, 24), u32(h, 2100)
    cmd = cstr(h[28:28 + 2048])
    tab_sz = tab_n = tab_es = boot_cfg = 0
    if ver == 4:
        tab_sz, tab_n, tab_es, boot_cfg = u32(h, 2112), u32(h, 2116), u32(h, 2120), u32(h, 2124)
    if hsz < 2100 or hsz > 4096 * 4:
        raise AndroidError("implausible vendor_boot header size")
    if tab_n > RAMDISK_FRAGMENTS_MAX or tab_sz > (1 << 20) or (tab_n and (tab_es < 12 or tab_es > 4096 or tab_n * tab_es > tab_sz)):
        raise AndroidError("implausible vendor ramdisk table")
    off = -(-hsz // page) * page
    parts = {}
    for nm, ln in (("vendor_ramdisk", rsz), ("dtb", dtb), ("ramdisk_table", tab_sz), ("bootconfig", boot_cfg)):
        if ln:
            if off + ln > size:
                raise AndroidError(f"{nm} runs past the end of the file")
            parts[nm] = (off, ln)
        off += -(-ln // page) * page
    return {"header_version": ver, "page_size": page, "cmdline": cmd, "parts": parts, "table_entries": tab_n, "table_entry_size": tab_es}


def decompress(data, cap):
    """Auto-detect gzip / lz4 / bzip2 / xz / raw -> (bytes or None, format, reason).  zstd and failures: (None, fmt, reason)."""
    d = bytes(data[:8])
    try:
        if d[:2] == b"\x1f\x8b":
            out, rest = bytearray(), bytes(data)
            while rest:
                o = zlib.decompressobj(31)
                out += o.decompress(rest, cap - len(out) + 1)
                if len(out) > cap:
                    return None, "gzip", f"larger than {cap >> 20} MB"
                rest = o.unused_data
                if not rest.startswith(b"\x1f\x8b"):
                    break
            return bytes(out), "gzip", None
        if d[:4] in (b"\x04\x22\x4d\x18", b"\x02\x21\x4c\x18"):
            return rk().lz4_decompress(bytes(data), cap), "lz4", None
        if d[:3] == b"BZh":
            out = bz2.BZ2Decompressor().decompress(bytes(data), cap + 1)
            return (out, "bzip2", None) if len(out) <= cap else (None, "bzip2", f"larger than {cap >> 20} MB")
        if d[:6] == b"\xfd7zXZ\x00":
            out = lzma.LZMADecompressor().decompress(bytes(data), cap + 1)
            return (out, "xz", None) if len(out) <= cap else (None, "xz", f"larger than {cap >> 20} MB")
        if d[:4] == b"\x28\xb5\x2f\xfd":
            return None, "zstd", "zstd is not supported by this reader"
    except (ValueError, OSError, EOFError, zlib.error, lzma.LZMAError) as e:
        return None, "compressed", f"decompression failed: {e}"
    return bytes(data), "raw", None


def cpio_files(data):
    """newc cpio -> ([{path, size, mode, off}], notes, rejected names)."""
    out, rej, pos, n = [], 0, 0, len(data)
    while pos + 110 <= n:
        if data[pos:pos + 6] not in (b"070701", b"070702"):
            if not out:
                return out, ["not a newc cpio archive"], rej
            break
        try:
            f = [int(data[pos + 6 + 8 * k:pos + 14 + 8 * k], 16) for k in range(13)]
        except ValueError:
            return out, ["bad cpio header field"], rej
        mode, fsz, nsz = f[1], f[6], f[11]
        name_off = pos + 110
        if nsz == 0 or name_off + nsz > n:
            return out, ["truncated cpio name"], rej
        name = data[name_off:name_off + nsz - 1].decode("utf-8", "surrogateescape")
        d_off = (name_off + nsz + 3) & ~3
        if name == "TRAILER!!!":
            break
        if d_off + fsz > n:
            return out, ["truncated cpio data"], rej
        clean = name[2:] if name.startswith("./") else name.lstrip("/")
        if clean in ("", "."):
            pass
        elif ".." in clean.split("/") or "\0" in clean:
            rej += 1
        else:
            out.append({"path": clean, "size": fsz, "mode": mode, "off": d_off})
        if len(out) > CPIO_MAX_ENTRIES:
            return out, ["too many cpio entries"], rej
        pos = (d_off + fsz + 3) & ~3
    return out, [], rej


def split_dtbs(blob):
    out, o = [], 0
    while o + 8 <= len(blob) and blob[o:o + 4] == b"\xd0\x0d\xfe\xed" and len(out) < 4096:
        sz = struct.unpack_from(">I", blob, o + 4)[0]
        if sz < 40 or o + sz > len(blob):
            break
        out.append((o, sz))
        o += (sz + 3) & ~3
    return out


def dtb_info(blob):
    try:
        R = rk()
        root, _ = R.fdt_tree(blob)
        comp = root["props"].get("compatible", b"").rstrip(b"\0").decode("ascii", "replace").replace("\0", ", ")
        return {"model": R.prop_str(root, "model"), "compatible": comp or None}
    except (ValueError, struct.error):
        return {"model": None, "compatible": None}


BANNER = re.compile(rb"Linux version ([^\s\x00]+) \(([^\n\x00]{0,400})")


def analyse_kernel(blob):
    """Kernel as stored in boot.img -> (decompressed bytes or None, info)."""
    info = {"stored_bytes": len(blob), "sha256": hashlib.sha256(blob).hexdigest()}
    data, fmt, why = decompress(blob, KERNEL_MAX)
    info["compression"] = fmt
    if data is None:
        info.update(status="NOT_ASSESSED", reason=why, version=None, ikconfig={"status": "NOT_ASSESSED", "reason": why})
        return None, info
    info["unpacked_bytes"] = len(data)
    m = BANNER.search(data)
    info["version"] = m.group(1).decode("ascii", "replace") if m else None
    info["banner"] = m.group(0).decode("utf-8", "replace") if m else None
    if not m:
        info["version_note"] = "no 'Linux version' banner found (not a Linux kernel image, or not decodable): version unknown"
    kc = kernel_config()
    if kc is None:
        info["ikconfig"] = {"status": "NOT_ASSESSED", "reason": "tools/pilot/lib/kernel_config.py cannot be loaded by this Python (needs 3.12+)"}
    else:
        try:
            cfg, _cfmt, cwhy, complete = kc.extract_ikconfig(data)
        except Exception as e:                              # untrusted input: never fail the whole package
            cfg, cwhy, complete = None, f"IKCONFIG extraction failed: {e}", None
        if cfg is not None:
            info["ikconfig"] = {"status": "OK" if complete else "ATTENTION", "bytes": len(cfg), "complete": bool(complete),
                                "sha256": hashlib.sha256(cfg).hexdigest(), "note": cwhy}
        else:
            info["ikconfig"] = {"status": "NOT_ASSESSED", "reason": cwhy or "no IKCONFIG in the kernel"}
    info["status"] = "OK" if info["version"] else "ATTENTION"
    return data, info


# ---------- properties, APK, shared libraries ----------

PROP_FILES = ("build.prop", "default.prop", "prop.default")
FACT_KEYS = {
    "android_version": ("ro.build.version.release", "ro.build.version.release_or_codename", "ro.system.build.version.release"),
    "sdk_level": ("ro.build.version.sdk", "ro.system.build.version.sdk"),
    "security_patch": ("ro.build.version.security_patch",),
    "vendor_security_patch": ("ro.vendor.build.security_patch",),
    "fingerprint": ("ro.build.fingerprint", "ro.system.build.fingerprint"),
    "vendor_fingerprint": ("ro.vendor.build.fingerprint",),
    "build_id": ("ro.build.id", "ro.system.build.id"),
    "build_display_id": ("ro.build.display.id",),
    "build_type": ("ro.build.type",),
}
SPL_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
PRIORITY = ("system", "system_ext", "product", "vendor", "odm")


def parse_props(text):
    out = {}
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#") or "=" not in ln:
            continue
        k, v = ln.split("=", 1)
        k = k.strip()
        if re.fullmatch(r"[A-Za-z0-9_.\-]{1,200}", k):
            out[k] = v.strip()[:500]
    return out


def read_axml(data):
    """Binary AndroidManifest.xml -> {'package', 'versionName', 'versionCode'} of the <manifest> element; ValueError otherwise."""
    if len(data) < 8 or u16(data, 0) != 0x0003:
        raise ValueError("not binary XML")
    total = u32(data, 4)
    if total > len(data):
        raise ValueError("truncated")
    pos, strings = 8, None
    while pos + 8 <= total:
        typ, hsz, sz = struct.unpack_from("<HHI", data, pos)
        if sz < 8 or hsz < 8 or pos + sz > total:
            raise ValueError("bad chunk")
        if typ == 0x0001 and strings is None:
            cnt, _sty, flags, sstart = struct.unpack_from("<IIII", data, pos + 8)
            if cnt > 200000 or 28 + cnt * 4 > sz:
                raise ValueError("bad string pool")
            utf8 = bool(flags & 0x100)
            strings = []
            for k in range(cnt):
                so = pos + sstart + u32(data, pos + 28 + 4 * k)
                if so >= pos + sz:
                    raise ValueError("string offset")
                if utf8:
                    ln = data[so]
                    so += 2 if ln & 0x80 else 1
                    bl = data[so]
                    so += 1
                    if bl & 0x80:
                        bl = ((bl & 0x7F) << 8) | data[so]
                        so += 1
                    strings.append(data[so:so + bl].decode("utf-8", "replace"))
                else:
                    ln = u16(data, so)
                    so += 2
                    if ln & 0x8000:
                        ln = ((ln & 0x7FFF) << 16) | u16(data, so)
                        so += 2
                    strings.append(data[so:so + ln * 2].decode("utf-16-le", "replace"))
        elif typ == 0x0102:
            if strings is None:
                raise ValueError("element before string pool")
            b = pos + 16
            name_i, a_start, _a_size, a_cnt = struct.unpack_from("<IHHH", data, b + 4)
            if name_i >= len(strings) or strings[name_i] != "manifest":
                raise ValueError("first element is not <manifest>")
            res = {}
            for k in range(min(a_cnt, 64)):
                _ns, nm, raw, _vsz, _r0, dtype, dat = struct.unpack_from("<IIIHBBI", data, b + a_start + k * 20)
                if nm >= len(strings):
                    continue
                key = strings[nm]
                if key in ("package", "versionName"):
                    idx = raw if raw != 0xFFFFFFFF else dat if dtype == 3 else None
                    if idx is not None and idx < len(strings):
                        res[key] = strings[idx]
                elif key == "versionCode" and dtype in (0x10, 0x11):
                    res[key] = dat
            return res
        pos += sz
    raise ValueError("no <manifest> element")


def apk_manifest(data):
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            info = zf.getinfo("AndroidManifest.xml")
            if info.file_size > 8 << 20:
                return None, "AndroidManifest.xml larger than 8 MB"
            return read_axml(zf.read(info)), None
    except (zipfile.BadZipFile, KeyError, ValueError, IndexError, struct.error, RuntimeError, NotImplementedError, EOFError, zlib.error) as e:
        return None, f"manifest not parsed: {e}"


LIBS = (
    ("openssl", re.compile(rb"OpenSSL (\d+\.\d+\.\d+[a-z]{0,2})( \(compatible; BoringSSL\))?"), ("libcrypto", "libssl")),
    ("libpng", re.compile(rb"libpng version (\d+\.\d+\.\d+(?:\.\d+)?)()"), ("libpng",)),
    ("zlib", re.compile(rb"(?:inflate|deflate) (\d+\.\d+\.\d+(?:\.\d+)?) Copyright()"), ("libz",)),
    ("sqlite", re.compile(rb"(3\.\d{1,2}\.\d{1,2}(?:\.\d{1,2})?) 20\d\d-\d\d-\d\d \d\d:\d\d:\d\d [0-9a-f]{16,}()"), ("libsqlite",)),
    ("curl", re.compile(rb"libcurl/(\d+\.\d+\.\d+)()"), ("libcurl",)),
    ("libxml2", re.compile(rb"libxml2[ /-](\d+\.\d+\.\d+)()"), ("libxml2",)),
)
ELF_MACHINE = {183: "aarch64", 40: "arm", 62: "x86_64", 3: "x86", 243: "riscv", 8: "mips"}


def lib_versions(base, data):
    """Shared library bytes + file name -> [{component, version, status}] (version strings only)."""
    out = []
    for comp, rx, hints in LIBS:
        if not any(base.startswith(h) for h in hints):
            continue
        for m in rx.finditer(data):
            ver, c = m.group(1).decode("ascii", "replace"), comp
            if m.group(2):
                c, ver = "boringssl", None                   # "OpenSSL 1.1.1 (compatible; BoringSSL)" is an API level, not a release
            rec = {"component": c, "version": ver, "status": "version string, not verified"}
            if rec not in out:
                out.append(rec)
            if len(out) >= 8:
                break
    return out


# ---------- the package ----------

class Part:
    """One thing found in the package: a file system (kind 'fs') or another image."""

    def __init__(self, name, kind, fd, off, size, origin):
        self.name, self.kind, self.fd, self.off, self.size, self.origin = name, kind, fd, off, size, origin
        self.prefix = name
        self.status, self.reasons = "OK", []
        self.fs = None
        self.sha256 = None
        self.opener = None                  # (prefix, stats) -> walker
        self.props, self.apks, self.libs, self.apex = {}, [], [], []
        self.extra = {}

    def na(self, why):
        self.status = "NOT_ASSESSED"
        self.reasons.append(why)

    def att(self, why):
        if self.status == "OK":
            self.status = "ATTENTION"
        self.reasons.append(why)

    def json(self):
        d = {"name": self.name, "prefix": self.prefix, "kind": self.kind, "bytes": self.size, "sha256": self.sha256, "origin": self.origin,
             "status": self.status, "reasons": self.reasons}
        if self.fs:
            d["fs"] = self.fs
        d.update(self.extra)
        return d


def check_not_in_git(path):
    """Temporary files (expanded images) must never land inside a git work tree."""
    d = os.path.abspath(path)
    while True:
        if os.path.exists(os.path.join(d, ".git")):
            raise AndroidError(f"work folder {path} is inside a git work tree ({d}): refusing to write temporary images there")
        up = os.path.dirname(d)
        if up == d:
            return
        d = up


class AndroidPackage:
    def __init__(self, source, workdir=None):
        self.source = os.path.abspath(source)
        self.own_work = workdir is None
        base = workdir
        if base is None:
            env = os.environ.get("ANDROID_WORKDIR")
            if not env:
                raise AndroidError("no work folder: set ANDROID_WORKDIR to a folder on the data disk (outside any git work tree)")
            check_not_in_git(env)
            os.makedirs(env, exist_ok=True)
            base = tempfile.mkdtemp(prefix="android-work-", dir=env)
        else:
            check_not_in_git(base)
        self.work = base
        os.makedirs(self.work, exist_ok=True)
        self.work_used = 0
        self.fds, self.temps = {}, []
        self.parts, self.boots, self.pending = [], [], []
        self.other_members, self.notes, self.images = [], [], []
        self.lp = None
        self._n = 0
        self.kernel = None
        self.kernel_data = None
        self.facts = {}

    # --- temp handling ---
    def temp(self, name):
        self._n += 1
        p = os.path.join(self.work, f"{self._n:03d}-{re.sub(r'[^A-Za-z0-9._-]', '_', name)[:60]}")
        self.temps.append(p)
        return p

    def check_space(self, need, what):
        if need > MAX_IMAGE:
            raise AndroidError(f"{what}: {need} bytes exceeds the cap {MAX_IMAGE}")
        if self.work_used + need > MAX_WORK:
            raise AndroidError(f"{what}: work folder cap {MAX_WORK} reached")
        free = shutil.disk_usage(self.work).free
        if free < need + MIN_FREE:
            raise AndroidError(f"{what}: not enough free space in the work folder ({free} bytes free, {need} needed)")

    def reserve(self, need):
        self.check_space(need, "expanded image")
        self.work_used += need

    def expand(self, opener, tmp):
        """Sparse member -> raw temp file; accounting is released again when it fails."""
        before = self.work_used
        try:
            with opener() as s:
                return unsparse(s, tmp, reserve=self.reserve)
        except BaseException:
            self.work_used = before
            try:
                os.remove(tmp)
            except OSError:
                pass
            raise

    def fd(self, path):
        if path not in self.fds:
            self.fds[path] = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        return self.fds[path]

    def close(self):
        for fd in self.fds.values():
            try:
                os.close(fd)
            except OSError:
                pass
        self.fds = {}
        for p in self.temps:
            try:
                os.remove(p)
            except OSError:
                pass
        self.temps = []
        if self.own_work or getattr(self, "remove_work", False):
            shutil.rmtree(self.work, ignore_errors=True)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    # --- ingest ---
    def load(self):
        src = self.source
        if os.path.isdir(src):
            for d in sorted(os.scandir(src), key=lambda d: d.name):
                if not self.count_member():
                    break
                if d.is_file(follow_symlinks=False):
                    self.ingest_path(d.path, d.name, f"dir:{d.name}", depth=0)
        else:
            with open(src, "rb") as f:
                head = f.read(4096 + 4)
            if head[:4] == b"PK\x03\x04":
                self.ingest_zip(src, "", 0)
            elif head[257:262] == b"ustar":
                self.ingest_tar(src)
            else:
                self.ingest_path(src, os.path.basename(src) if os.path.basename(src).lower().endswith((".img", ".zip"))
                                 else os.path.basename(src) + ".img", os.path.basename(src), depth=0)
        self.analyse()
        return self

    def count_member(self):
        self.members_seen = getattr(self, "members_seen", 0) + 1
        if self.members_seen > MAX_MEMBERS:
            if not getattr(self, "members_capped", False):
                self.members_capped = True
                self.bad_image("members", "package", None, f"more than {MAX_MEMBERS} archive/directory entries: the rest were not looked at")
            return False
        return True

    def ingest_tar(self, path):
        with tarfile.open(path, "r:") as t:
            for m in t:
                if not self.count_member():
                    break
                if m.isreg():
                    self.ingest_stream(m.name, m.size, lambda m=m, t=t: t.extractfile(m), "tar:" + m.name, 0)

    def ingest_zip(self, path, prefix, depth):
        with zipfile.ZipFile(path) as zf:
            for i in zf.infolist():
                if not self.count_member():
                    break
                if i.is_dir():
                    continue
                if i.flag_bits & 1:
                    self.other_members.append({"name": prefix + i.filename, "bytes": i.file_size, "note": "encrypted member, not opened"})
                    continue
                self.ingest_stream(i.filename, i.file_size, lambda i=i, zf=zf: zf.open(i), "zip:" + prefix + i.filename, depth)

    def other(self, origin, size):
        if len(self.other_members) < 200:
            self.other_members.append({"name": origin, "bytes": size, "note": "not an image: listed by name and size only, not opened"})

    def bad_image(self, stem, origin, size, why):
        self.images.append({"name": stem[:64], "origin": origin, "bytes": size, "status": "NOT_ASSESSED", "reason": why})

    def ingest_stream(self, name, size, opener, origin, depth):
        base = name.replace("\\", "/").rsplit("/", 1)[-1]
        low = base.lower()
        if not (low.endswith(".img") or low.endswith(".zip")):
            self.other(origin, size)
            return
        stem = base[:-4]
        if not NAME_OK.fullmatch(stem):
            self.bad_image(stem, origin, size, "unsafe file name, not opened")
            return
        try:
            with opener() as s:
                head = readn(s, 16)
            if head[:4] == b"PK\x03\x04":
                if depth >= 1:
                    self.bad_image(stem, origin, size, "zip nested deeper than one level")
                    return
                if size > NESTED_ZIP_MAX:
                    raise AndroidError("nested zip too large")
                self.check_space(size, origin)
                tmp = self.temp(base)
                self.work_used += size
                try:
                    with opener() as s, open(tmp, "wb") as o:
                        shutil.copyfileobj(s, o, 4 << 20)
                    self.ingest_zip(tmp, origin + "!", depth + 1)
                finally:
                    os.remove(tmp)
                    self.work_used -= size
                return
            if head[:4] == SPARSE_MAGIC:
                tmp = self.temp(stem + ".raw")
                info = self.expand(opener, tmp)
                self.add_raw(tmp, stem, origin, sparse=info, src_bytes=size)
                return
            self.check_space(size, origin)
            tmp = self.temp(stem + ".raw")
            self.work_used += size
            with opener() as s, open(tmp, "wb") as o:
                shutil.copyfileobj(s, o, 4 << 20)
            self.add_raw(tmp, stem, origin)
        except CATCH + (zipfile.BadZipFile, tarfile.TarError, NotImplementedError) as e:
            self.bad_image(stem, origin, size, str(e))

    def ingest_path(self, path, name, origin, depth):
        low = name.lower()
        size = os.path.getsize(path)
        if not (low.endswith(".img") or low.endswith(".zip")):
            self.other(origin, size)
            return
        stem = name[:-4]
        if low.endswith(".zip"):
            if depth >= 1:
                return
            try:
                self.ingest_zip(path, origin + "!", depth + 1)
            except (zipfile.BadZipFile, OSError) as e:
                self.bad_image(stem, origin, size, f"zip not readable: {e}")
            return
        if not NAME_OK.fullmatch(stem):
            self.bad_image(stem, origin, size, "unsafe file name, not opened")
            return
        try:
            with open(path, "rb") as f:
                head = f.read(16)
            if head[:4] == SPARSE_MAGIC:
                tmp = self.temp(stem + ".raw")
                info = self.expand(lambda: open(path, "rb"), tmp)
                self.add_raw(tmp, stem, origin, sparse=info, src_sha=hash_file(path), src_bytes=size)
            else:
                self.add_raw(path, stem, origin)
        except CATCH as e:
            self.bad_image(stem, origin, size, f"{type(e).__name__}: {e}" if not isinstance(e, AndroidError) else str(e))

    def add_raw(self, path, name, origin, sparse=None, src_sha=None, src_bytes=None):
        fd = self.fd(path)
        size = os.fstat(fd).st_size
        rec = {"name": name, "origin": origin, "kind": sniff_fd(fd), "bytes": src_bytes or size, "raw_bytes": size,
               "sha256": src_sha or sha256_range(fd, 0, size)}
        if sparse:
            rec["sparse"] = sparse
        self.images.append(rec)
        self.pending.append((rec, fd, size))

    # --- analysis ---
    def analyse(self):
        for rec, fd, size in self.pending:
            kind = rec["kind"]
            try:
                if kind == "super":
                    self.do_super(rec, fd, size)
                elif kind in ("ext4", "erofs", "f2fs", "squashfs"):
                    p = Part(rec["name"], "fs", fd, 0, size, rec["origin"])
                    p.sha256 = rec["sha256"]
                    self.parts.append(p)
                    self.open_fs(p, kind)
                elif kind in ("boot", "vendor_boot"):
                    self.do_boot(rec, fd, size, kind)
                else:
                    p = Part(rec["name"], kind, fd, 0, size, rec["origin"])
                    p.sha256 = rec["sha256"]
                    if kind == "dtbo":
                        self.do_dtbo(p)
                    elif kind == "vbmeta":
                        p.extra["note"] = "AVB metadata: presence recorded only, signature not verified"
                    else:
                        p.na("unrecognised image content: not analysed")
                    self.parts.append(p)
            except CATCH as e:
                why = str(e) if isinstance(e, AndroidError) else f"{type(e).__name__}: {e}"
                if self.parts and self.parts[-1].name == rec["name"] and self.parts[-1].kind == kind:
                    self.parts[-1].na(f"{kind}: {why}")
                else:
                    p = Part(rec["name"], kind, fd, 0, size, rec["origin"])
                    p.sha256 = rec.get("sha256")
                    p.na(f"{kind}: {why}")
                    self.parts.append(p)
        self.pending = []
        self.assign_prefixes()
        for p in self.parts:
            if p.opener is not None:
                try:
                    self.scan_fs(p)
                except CATCH as e:                              # untrusted input: never a traceback
                    p.na(f"scan failed: {type(e).__name__}: {e}")
        self.pick_kernel()
        self.facts = self.build_facts()

    def assign_prefixes(self):
        stripped = {}
        for p in self.parts:
            if p.kind == "fs" and p.status != "EMPTY":
                stripped.setdefault(re.sub(r"_[ab]$", "", p.name), []).append(p)
        for s, ps in stripped.items():
            if len(ps) == 1 and s != ps[0].name:
                ps[0].extra["slot_suffix_removed"] = ps[0].name[len(s):]
                ps[0].prefix = s
        seen = {}
        for p in self.parts:
            q = p.prefix
            seen[q] = seen.get(q, 0) + 1
            if seen[q] > 1:
                p.prefix = f"{q}~{seen[q]}"
                p.reasons.append(f"name {q!r} used more than once (for example a separate image and a super partition): prefix {p.prefix}")

    def do_super(self, rec, fd, size):
        lp = parse_super(fd)
        self.lp = {k: v for k, v in lp.items() if k != "partitions"}
        self.lp["image"] = rec["name"]
        claimed = 0
        for lpp in lp["partitions"]:
            raw_name = lpp["name"]
            name = raw_name if NAME_OK.fullmatch(raw_name) else (re.sub(r"[^A-Za-z0-9._-]", "_", raw_name).lstrip("._-")[:64] or "unnamed")
            p = Part(name, "fs", fd, 0, lpp["size"], f"{rec['origin']} (logical partition)")
            if name != raw_name:
                p.extra["lp_name_raw"] = raw_name
                p.reasons.append("partition name contains characters outside [A-Za-z0-9._-]: sanitised")
            p.extra["lp"] = {"attributes": lpp["attributes"], "group": lpp["group"], "extents": lpp["extents"]}
            if lpp["attributes"] & 8:
                p.reasons.append("LP attribute DISABLED set")
            self.parts.append(p)
            ex = lpp["extents"]
            if not ex or lpp["size"] == 0:
                p.status = "EMPTY"
                p.reasons.append("no extents in slot 0 metadata (partition not populated in this image)")
                continue
            if any(e["type"] != 0 for e in ex):
                p.na("LP extent of type 'zero' or unknown: layout not supported")
                continue
            if any(e["source"] != 0 for e in ex):
                p.na("LP extent on another block device (multi-device super): only the first device is in this image")
                continue
            if any((e["data"] + e["sectors"]) * LP_SECTOR > size for e in ex):
                p.na(f"extents run past the end of {rec['name']}.img ({size} bytes): image truncated or metadata-only")
                continue
            claimed += lpp["size"]
            if claimed > size:
                p.na("partition extents overlap or add up to more than the image size: not read (avoids repeated hashing of the same bytes)")
                continue
            start = ex[0]["data"] * LP_SECTOR
            contiguous, pos = True, start
            for e in ex:
                if e["data"] * LP_SECTOR != pos:
                    contiguous = False
                pos += e["sectors"] * LP_SECTOR
            if contiguous:
                p.fd, p.off = fd, start
            else:
                try:
                    self.reserve(lpp["size"])
                    tmp = self.temp(p.name + ".lp")
                    with open(tmp, "wb") as o:
                        for e in ex:
                            left, o_ = e["sectors"] * LP_SECTOR, e["data"] * LP_SECTOR
                            while left:
                                b = os.pread(fd, min(left, 4 << 20), o_)
                                if not b:
                                    raise AndroidError("short read")
                                o.write(b)
                                o_ += len(b)
                                left -= len(b)
                    p.fd, p.off = self.fd(tmp), 0
                    p.reasons.append(f"{len(ex)} extents, not contiguous: copied to a temporary file")
                except CATCH as e:
                    p.na(f"fragmented partition could not be assembled: {e}")
                    continue
            p.sha256 = sha256_range(p.fd, p.off, p.size)
            self.open_fs(p, sniff_fd_range(p.fd, p.off))
        if lp["slot_count"] > 1:
            self.notes.append(f"super: only metadata slot 0 of {lp['slot_count']} was read; partitions listed only in other slots are not shown")

    def open_fs(self, p, kind):
        R = rk()
        try:
            if kind == "ext4":
                Ext4Walker(p.fd, p.off, p.size, p.name, R.new_stats())          # validates
                p.fs = dict(R.sb_json(R.superblock(p.fd, p.off)), type="ext4")
                p.opener = lambda prefix, stats: Ext4Walker(p.fd, p.off, p.size, prefix, stats)
            elif kind == "erofs":
                e = Erofs(p.fd, p.off, p.size)
                p.fs = e.info()
                p.opener = lambda prefix, stats: ErofsWalker(e, prefix, stats)
            else:
                p.fs = {"type": kind}
                p.na(f"file system {kind} is not supported by this reader (phase 1): contents not listed")
        except (R.Ext4Error, ErofsError, AndroidError) as e:
            p.fs = {"type": kind}
            p.na(f"{kind} not readable: {e}")

    def walker(self, p, stats):
        return p.opener(p.prefix, stats)._walk()

    def scan_fs(self, p):
        R = rk()
        st = R.new_stats()
        st["reader"] = "android_img.py"
        info = {"files": 0, "dirs": 0, "bytes": 0}
        capped = set()
        try:
            for ti in self.walker(p, st):
                rel = ti.name[len(p.prefix) + 1:]
                if ti.isdir():
                    info["dirs"] += 1
                    continue
                if not ti.isreg():
                    continue
                info["files"] += 1
                info["bytes"] += ti.size
                base = rel.rsplit("/", 1)[-1]
                low = base.lower()
                if base in PROP_FILES and rel.count("/") <= 3:
                    self.read_prop(p, ti, rel)
                elif low.endswith(".apk"):
                    if len(p.apks) < LIST_CAP:
                        self.add_apk(p, ti, rel)
                    else:
                        capped.add("APK")
                elif low.endswith((".apex", ".capex")):
                    p.apex.append({"path": f"{p.prefix}/{rel}", "bytes": ti.size})
                elif re.search(r"\.so(\.\d+)*$", low):
                    if len(p.libs) < LIST_CAP:
                        self.add_lib(p, ti, rel)
                    else:
                        capped.add("shared object")
        except AndroidError as e:
            p.na(str(e))
        p.extra["contents"] = info
        if capped:
            p.na(f"{' and '.join(sorted(capped))} list truncated at {LIST_CAP} entries: the rest were not inventoried")
        lost = R.losses(st)
        if lost:
            p.att("entries not read: " + ", ".join(f"{k} {v}" for k, v in lost.items()))
        if st.get("not_assessed_compressed"):
            p.na(f"{st['not_assessed_compressed']} file(s) stored in a compressed EROFS layout: names and sizes listed, "
                 "content NOT_ASSESSED (no decoder in phase 1)")
        if st.get("journal_needs_recovery"):
            p.att("ext4 journal needs recovery: content may be incomplete")
        p.extra["walk_stats"] = {k: v for k, v in st.items() if k != "reader" and v not in (0, False, [])}

    def read_prop(self, p, ti, rel):
        if ti.size > SMALL_MAX:
            p.att(f"{rel}: larger than {SMALL_MAX} bytes, not read")
            return
        if ti.rk_open is None:
            return                                       # compressed EROFS: the partition is already NOT_ASSESSED
        try:
            with ti.rk_open() as f:
                text = f.read(SMALL_MAX + 1).decode("utf-8", "replace")
        except OSError as e:
            p.att(f"{rel}: not readable ({e})")
            return
        p.props[f"{p.prefix}/{rel}"] = parse_props(text)

    def add_apk(self, p, ti, rel):
        rec = {"path": f"{p.prefix}/{rel}", "bytes": ti.size, "sha256": None, "package": None, "version_name": None, "version_code": None,
               "manifest": "NOT_ASSESSED"}
        p.apks.append(rec)
        if ti.rk_open is None:
            rec["note"] = "content in a compressed EROFS layout: NOT_ASSESSED"
            return
        try:
            with ti.rk_open() as f:
                if ti.size <= APK_MEM_MAX:
                    data = f.read(ti.size + 1)
                    rec["sha256"] = hashlib.sha256(data).hexdigest()
                    man, why = apk_manifest(data)
                    if man and man.get("package"):
                        rec.update(package=man["package"], version_name=man.get("versionName"), version_code=man.get("versionCode"),
                                   manifest="parsed from binary AndroidManifest.xml (best effort, not verified against aapt)")
                    else:
                        rec["note"] = why or "no package attribute"
                else:
                    h = hashlib.sha256()
                    for b in iter(lambda: f.read(4 << 20), b""):
                        h.update(b)
                    rec["sha256"] = h.hexdigest()
                    rec["note"] = f"larger than {APK_MEM_MAX >> 20} MB: manifest not parsed"
        except OSError as e:
            rec["note"] = f"not readable: {e}"

    def add_lib(self, p, ti, rel):
        base = rel.rsplit("/", 1)[-1]
        rec = {"path": f"{p.prefix}/{rel}", "bytes": ti.size, "sha256": None, "arch": None, "versions": []}
        p.libs.append(rec)
        if ti.rk_open is None:
            rec["note"] = "content in a compressed EROFS layout: NOT_ASSESSED"
            return
        try:
            with ti.rk_open() as f:
                if ti.size <= SO_SCAN_MAX:
                    data = f.read(ti.size + 1)
                    rec["sha256"] = hashlib.sha256(data).hexdigest()
                    if data[:4] == b"\x7fELF" and len(data) > 20:
                        rec["arch"] = ELF_MACHINE.get(u16(data, 18), f"machine {u16(data, 18)}") + (" 64-bit" if data[4] == 2 else " 32-bit")
                    rec["versions"] = lib_versions(base, data)
                else:
                    h = hashlib.sha256()
                    for b in iter(lambda: f.read(4 << 20), b""):
                        h.update(b)
                    rec["sha256"] = h.hexdigest()
                    rec["note"] = "too large to scan for version strings"
        except OSError as e:
            rec["note"] = f"not readable: {e}"

    def do_dtbo(self, p):
        h = pread(p.fd, 0, 32)
        if len(h) < 32:
            raise AndroidError("dtbo header truncated")
        _total, _hsz, esz, cnt, eoff = struct.unpack_from(">5I", h, 4)
        if cnt > 4096 or esz < 20 or eoff + cnt * esz > p.size:
            raise AndroidError("dtbo table out of range")
        ents = []
        for k in range(cnt):
            sz, off, ident, rev = struct.unpack_from(">4I", pread(p.fd, eoff + k * esz, 20), 0)
            if off + sz > p.size:
                raise AndroidError(f"dtbo entry {k} out of range")
            ents.append({"bytes": sz, "id": ident, "rev": rev})
        p.extra["dtbo_entries"] = ents
        p.extra["dtb_count"] = cnt

    def do_boot(self, rec, fd, size, kind):
        info = parse_boot(fd, size) if kind == "boot" else parse_vendor_boot(fd, size)      # may raise: nothing registered yet
        p = Part(rec["name"], kind, fd, 0, size, rec["origin"])
        p.sha256 = rec["sha256"]
        p.extra["ramdisk"] = {"status": "NOT_ASSESSED", "reason": "not read"}
        boot = {"name": rec["name"], "fd": fd, "info": info, "ramdisk": None, "dtbs": [], "part": p, "kernel_data": None}
        self.parts.append(p)
        self.boots.append(boot)
        p.extra["header"] = {k: v for k, v in info.items() if k != "parts"}
        p.extra["header"]["ranges"] = {k: {"offset": o, "bytes": n} for k, (o, n) in info["parts"].items()}
        p.extra["ramdisk"] = {"status": "NOT_ASSESSED", "reason": "no ramdisk in this image"}
        if "kernel" in info["parts"]:
            off, n = info["parts"]["kernel"]
            if n > KERNEL_MAX:
                p.extra["kernel"] = {"status": "NOT_ASSESSED", "reason": f"kernel larger than {KERNEL_MAX >> 20} MB", "version": None}
            else:
                boot["kernel_data"], p.extra["kernel"] = analyse_kernel(pread(fd, off, n))
        rd = info["parts"].get("ramdisk") or info["parts"].get("vendor_ramdisk")
        if rd:
            self.read_ramdisk(p, boot, fd, rd, info)
        dt = info["parts"].get("dtb")
        if dt and dt[1] > DTB_MAX:
            p.na(f"dtb area larger than {DTB_MAX >> 20} MB: not read")
        elif dt:
            blob = pread(fd, *dt)
            boot["dtbs"] = [(blob[o:o + n], dtb_info(blob[o:o + n])) for o, n in split_dtbs(blob)]
            p.extra["dtb_count"] = len(boot["dtbs"])
            p.extra["dtbs"] = [{"bytes": len(b), **i} for b, i in boot["dtbs"]]

    def read_ramdisk(self, p, boot, fd, rd, info):
        off, n = rd
        if n > RAMDISK_MAX:
            p.extra["ramdisk"] = {"status": "NOT_ASSESSED", "reason": f"ramdisk larger than {RAMDISK_MAX >> 20} MB"}
            p.na("ramdisk too large")
            return
        raw = pread(fd, off, n)
        frags = [raw]
        if info.get("table_entries") and "ramdisk_table" in info["parts"]:
            es = info["table_entry_size"]
            tn = info["table_entries"]
            if tn > RAMDISK_FRAGMENTS_MAX or es < 12 or es > 4096 or tn * es > info["parts"]["ramdisk_table"][1]:
                p.extra["ramdisk"] = {"status": "NOT_ASSESSED", "reason": "vendor ramdisk table implausible (entry count or size)"}
                p.na("vendor ramdisk table implausible (entry count or size): ramdisk not read")
                return
            tab = pread(fd, info["parts"]["ramdisk_table"][0], tn * es)
            frags = []
            for k in range(tn):
                if es < 12 or (k + 1) * es > len(tab):
                    break
                sz, so = u32(tab, k * es), u32(tab, k * es + 4)
                if so + sz > len(raw):
                    p.extra["ramdisk"] = {"status": "NOT_ASSESSED", "reason": "vendor ramdisk table entry out of range"}
                    p.na("vendor ramdisk table entry out of range")
                    return
                frags.append(raw[so:so + sz])
        files, notes, rej, fmts, blobs = [], [], 0, [], []
        budget = RAMDISK_MAX                                   # decompressed bytes over all fragments
        for fr in frags:
            if budget <= 0:
                notes.append("decompressed ramdisk fragments exceed the total cap: the rest were not read")
                break
            data, fmt, why = decompress(fr, budget)
            fmts.append(fmt)
            if data is not None:
                budget -= len(data)
            if data is None:
                notes.append(f"{fmt}: {why}")
                continue
            fl, nt, rj = cpio_files(data)
            notes += nt
            rej += rj
            blobs.append(data)
            files += [dict(f, blob=len(blobs) - 1) for f in fl[:max(0, CPIO_MAX_ENTRIES - len(files))]]
        boot["ramdisk"] = (blobs, files)
        st = "OK" if not notes else "ATTENTION" if files else "NOT_ASSESSED"
        p.extra["ramdisk"] = {"status": st, "compression": fmts, "files": len(files), "rejected_names": rej, "notes": notes,
                              "bytes": sum(f["size"] for f in files)}
        if notes:
            (p.att if st == "ATTENTION" else p.na)("ramdisk: " + "; ".join(notes))
        for f in files:
            if f["path"].rsplit("/", 1)[-1] in PROP_FILES and f["size"] <= SMALL_MAX and f["mode"] & 0xF000 == 0x8000:
                text = blobs[f["blob"]][f["off"]:f["off"] + f["size"]].decode("utf-8", "replace")
                p.props[f"boot/{p.name}/ramdisk/{f['path']}"] = parse_props(text)

    def pick_kernel(self):
        cands = [b for b in self.boots if b["part"].extra.get("kernel")]
        self.kernel, self.kernel_data = None, None
        for b in cands:
            if b["part"].extra["kernel"].get("version"):
                self.kernel, self.kernel_data = dict(b["part"].extra["kernel"], image=b["name"]), b["kernel_data"]
                break
        if self.kernel is None and cands:
            self.kernel, self.kernel_data = dict(cands[0]["part"].extra["kernel"], image=cands[0]["name"]), cands[0]["kernel_data"]
        if len(cands) > 1:
            self.notes.append("more than one boot image contains a kernel (" + ", ".join(b["name"] for b in cands) + "): the first with a version is used")
        if self.kernel is None:
            self.kernel = {"status": "NOT_ASSESSED", "reason": "no boot image with a kernel in the package", "version": None}

    def build_facts(self):
        files = []
        for p in self.parts:
            for src, pr in p.props.items():
                pri = PRIORITY.index(p.prefix) if p.prefix in PRIORITY else 50 if src.startswith("boot/") else 20
                files.append((pri, src, pr))
        files.sort(key=lambda x: (x[0], x[1]))
        facts = {}
        for fact, keys in FACT_KEYS.items():
            found = [{"key": k, "value": pr[k], "source": src} for _, src, pr in files for k in keys if k in pr]
            if found:
                f0 = {"value": found[0]["value"], "source": found[0]["source"], "all": found[:12],
                      "conflict": len({f["value"] for f in found if f["key"] == found[0]["key"]}) > 1}
                if "security_patch" in fact and not SPL_RE.fullmatch(f0["value"]):
                    f0["invalid"] = True
                    f0["note"] = "value is not in YYYY-MM-DD form"
                facts[fact] = f0
            else:
                facts[fact] = {"value": None, "status": "NOT_ASSESSED", "reason": self.no_prop_reason()}
        return facts

    def no_prop_reason(self):
        fss = [p for p in self.parts if p.kind == "fs"]
        if not fss:
            return "no file system image (system/vendor) in the package"
        na = [p.name for p in fss if p.status == "NOT_ASSESSED"]
        return "no matching property in the readable build.prop files" + (f"; not assessed: {', '.join(na)}" if na else "")

    # --- results ---
    def status(self):
        """GAP when anything that matters is not assessed; ATTENTION for partial or odd results; OK only when nothing is open."""
        if not self.parts and not self.images:
            return "GAP", "no Android image recognised in the package"
        gap, att = [], []
        bad = sorted({p.name for p in self.parts if p.status == "NOT_ASSESSED"} | {i["name"] for i in self.images if i.get("status") == "NOT_ASSESSED"})
        if bad:
            gap.append("not assessed: " + ", ".join(bad[:20]))
        if (self.kernel or {}).get("status") == "NOT_ASSESSED":
            gap.append("kernel not assessed (" + str(self.kernel.get("reason")) + ")")
        for k in ("android_version", "security_patch"):
            if self.facts.get(k, {}).get("value") is None:
                gap.append(f"{k} NOT_ASSESSED")
        if gap:
            return "GAP", "; ".join(gap)
        names = [p.name for p in self.parts if p.status == "ATTENTION"]
        if names:
            att.append("attention: " + ", ".join(names))
        nm = sum(1 for p in self.parts for a in p.apks if not a["package"])
        if nm:
            att.append(f"{nm} APK manifest(s) not parsed")
        for k, f in self.facts.items():
            if f.get("conflict"):
                att.append(f"{k}: conflicting values across files")
            if f.get("invalid"):
                att.append(f"{k}: value is not in YYYY-MM-DD form")
        att += self.notes[:3]
        if att:
            return "ATTENTION", "; ".join(att)
        return "OK", "inventory of the recognised images is complete (vulnerability matching was not run)"

    def summary(self):
        st, detail = self.status()
        apks = [a for p in self.parts for a in p.apks]
        libs = [x for p in self.parts for x in p.libs]
        apex = [a for p in self.parts for a in p.apex]
        wk = [{"component": v["component"], "version": v["version"], "library": x["path"], "sha256": x["sha256"], "status": v["status"]}
              for x in libs for v in x["versions"]]
        def spl_of(f):
            if f.get("value") is None:
                return {"value": None, "status": "NOT_ASSESSED", "reason": f.get("reason")}
            bad = bool(f.get("conflict") or f.get("invalid"))
            return {"value": None if bad else f["value"], "raw": f["value"], "conflict": bool(f.get("conflict")),
                    "invalid": bool(f.get("invalid")), "source": f.get("source"),
                    **({"status": "NOT_ASSESSED", "reason": "conflicting values across files" if f.get("conflict") else "not in YYYY-MM-DD form"} if bad else {})}
        return {
            "status": st, "detail": detail, "source": os.path.basename(self.source),
            "facts": self.facts, "kernel": self.kernel,
            "partitions": [p.json() for p in self.parts], "images": self.images, "super": self.lp,
            "boot_images": [{"name": b["name"], **b["part"].extra.get("header", {}), "dtb_count": b["part"].extra.get("dtb_count", 0),
                             "ramdisk": b["part"].extra.get("ramdisk")} for b in self.boots],
            "apks": {"count": len(apks), "with_package_name": sum(1 for a in apks if a["package"]),
                     "note": ("Package name and version were read from the binary AndroidManifest.xml of each APK (best effort, not verified against aapt); "
                              "entries without a package name could not be parsed (reason in 'note'). APK contents (dex, native code, assets) were not analysed.")
                     if apks else "No APK found in the readable file systems.",
                     "items": apks},
            "apex": {"count": len(apex), "note": "APEX/CAPEX modules (including com.android.* mainline modules) are listed by path only: not opened.",
                     "items": apex},
            "native_libs": {"count": len(libs), "well_known_versions": wk,
                            "note": "Versions are strings found inside the library files (OpenSSL, libpng, zlib, sqlite, curl, libxml2): "
                                    "version string, not verified. A library without a match is not 'clean': it was only not recognised.",
                            "items": libs},
            "other_members": self.other_members,
            "security_patch_level": {
                "system": spl_of(self.facts["security_patch"]), "vendor": spl_of(self.facts["vendor_security_patch"]),
                "boot_header": next((b["info"].get("os_patch_level") for b in self.boots if b["info"].get("os_patch_level")), None),
                "comparison": {"status": "NOT_ASSESSED",
                               "reason": "Android Security Bulletin data is not in the offline mirrors yet. The patch level is recorded "
                                         "so a later step can compare it with the bulletins."}},
            "vulnerability_matching": {
                "status": "NOT_RUN",
                "reason": "Phase 1 is an inventory. Android components (system libraries, APKs, APEX, vendor HALs) are not matched against any "
                          "vulnerability source, and the dpkg-based path is not used (Android has no dpkg database). "
                          "The absence of findings here means NOT_ASSESSED, not 'no vulnerabilities'.",
                "kernel": ("The kernel version and IKCONFIG are recorded; kernel/Image is in the virtual tar so the existing kernel checks can read it. "
                           "It is not wired into the scan script in phase 1." if self.kernel and self.kernel.get("version")
                           else "No kernel version available: kernel CVE matching cannot be done."),
                "not_assessed_partitions": [p.name for p in self.parts if p.kind == "fs" and p.status == "NOT_ASSESSED"]},
        }

    # --- virtual tar ---
    def entries(self):
        R = rk()
        yield R.tinfo("boot", tarfile.DIRTYPE, mode=0o755)
        yield R.tinfo("bootloader", tarfile.DIRTYPE, mode=0o755)
        seen = set()
        for p in self.parts:
            if p.kind == "fs":
                if p.opener is not None:
                    try:
                        for ti in self.walker(p, R.new_stats()):
                            if ti.isreg() and ti.rk_open is None:
                                continue
                            yield ti
                    except AndroidError:
                        continue
            elif p.kind in ("boot", "vendor_boot"):
                yield from self.boot_entries(p)
            elif f"bootloader/{p.name}.img" not in seen:
                seen.add(f"bootloader/{p.name}.img")
                yield R.tinfo(f"bootloader/{p.name}.img", tarfile.REGTYPE, size=p.size,
                              opener=lambda p=p: stream_of(R.Range(p.fd, p.off, p.size)))
        if self.kernel_data is not None:
            yield R.tinfo("kernel", tarfile.DIRTYPE, mode=0o755)
            yield R.tinfo("kernel/Image", tarfile.REGTYPE, size=len(self.kernel_data), opener=lambda d=self.kernel_data: io.BytesIO(d))

    def boot_entries(self, p):
        R = rk()
        b = next((x for x in self.boots if x["part"] is p), None)
        yield R.tinfo(f"boot/{p.name}.img", tarfile.REGTYPE, size=p.size, opener=lambda p=p: stream_of(R.Range(p.fd, p.off, p.size)))
        if b is None:
            return
        if b["ramdisk"]:
            blobs, files = b["ramdisk"]
            yield R.tinfo(f"boot/{p.name}/ramdisk", tarfile.DIRTYPE, mode=0o755)
            seen = set()
            for f in files:
                if f["mode"] & 0xF000 != 0x8000 or f["path"] in seen:
                    continue
                seen.add(f["path"])
                yield R.tinfo(f"boot/{p.name}/ramdisk/{f['path']}", tarfile.REGTYPE, size=f["size"], mode=f["mode"] & 0o7777,
                              opener=lambda d=blobs[f["blob"]], f=f: io.BytesIO(d[f["off"]:f["off"] + f["size"]]))
        for k, (blob, _) in enumerate(b["dtbs"]):
            yield R.tinfo(f"boot/{p.name}/dtb/{k}.dtb", tarfile.REGTYPE, size=len(blob), opener=lambda d=blob: io.BytesIO(d))


class AndroidTar:
    """tarfile-like (next / members / extractfile / close) over AndroidPackage.entries()."""

    def __init__(self, pkg):
        self.pkg, self.members = pkg, []
        self._it = pkg.entries()

    def next(self):
        m = next(self._it, None)
        if m is not None:
            self.members.append(m)
        return m

    def extractfile(self, m):
        op = getattr(m, "rk_open", None)
        return op() if op else None

    def close(self):
        self.pkg.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


def open_virtual(path, workdir=None):
    pkg = AndroidPackage(path, workdir)
    try:
        pkg.load()
        return AndroidTar(pkg)
    except BaseException:
        pkg.close()
        raise


# ---------- outputs ----------

def summary_md(s):
    L = ["# Android package summary (phase 1: inventory)", "", f"Status: **{s['status']}** - {s['detail']}", "",
         "Vulnerability matching: **NOT_RUN**. This is an inventory. No Android component was matched against a vulnerability source; "
         "no result here means NOT_ASSESSED, not 'no vulnerabilities'.", "", "## Identity", ""]
    f = s["facts"]
    for lab, k in (("Android version (ro.build.version.release)", "android_version"), ("SDK level", "sdk_level"),
                   ("Security patch level (system)", "security_patch"), ("Security patch level (vendor)", "vendor_security_patch"),
                   ("Fingerprint", "fingerprint"), ("Vendor fingerprint", "vendor_fingerprint"), ("Build id", "build_id")):
        v = f[k]
        if v.get("value") is None:
            L.append(f"- {lab}: NOT_ASSESSED ({v.get('reason')})")
        else:
            L.append(f"- {lab}: {v['value']} (from {v['source']})" + (" - CONFLICTING VALUES across files, see JSON" if v.get("conflict") else ""))
    sp = s["security_patch_level"]
    L.append(f"- Patch level from boot header: {sp['boot_header'] or 'not recorded'}")
    L.append(f"- Comparison with Android Security Bulletins: {sp['comparison']['status']} - {sp['comparison']['reason']}")
    k = s["kernel"]
    L += ["", "## Kernel", ""]
    if k.get("version"):
        L.append(f"- Version: {k['version']} (image {k.get('image')}, {k.get('compression')})")
        ik = k.get("ikconfig", {})
        L.append(f"- IKCONFIG: {ik.get('status')}" + (f" ({ik.get('reason')})" if ik.get("reason") else ""))
    else:
        L.append(f"- Version unknown: {k.get('reason') or k.get('version_note') or 'no kernel'}")
    L += ["", "## Partitions and images", "", "| name | kind | fs | bytes | status | notes |", "|---|---|---|---|---|---|"]
    for p in s["partitions"]:
        L.append(f"| {p['name']} | {p['kind']} | {(p.get('fs') or {}).get('type', '')} | {p['bytes']} | {p['status']} | {'; '.join(p['reasons'])[:200]} |")
    for i in s["images"]:
        if i.get("status") == "NOT_ASSESSED":
            L.append(f"| {i['name']} | image | | {i.get('bytes')} | NOT_ASSESSED | {i.get('reason')} |")
    a = s["apks"]
    L += ["", "## APKs", "", f"{a['count']} APK(s), {a['with_package_name']} with a parsed package name. {a['note']}", ""]
    for x in a["items"][:50]:
        L.append(f"- {x['path']} ({x['bytes']} bytes, sha256 {x['sha256']})" + (f" {x['package']} {x['version_name']}" if x["package"] else ""))
    if a["count"] > 50:
        L.append(f"- ... {a['count'] - 50} more in android-summary.json")
    n = s["native_libs"]
    L += ["", "## Native libraries", "", f"{n['count']} shared object(s). {n['note']}", ""]
    for w in n["well_known_versions"][:50]:
        L.append(f"- {w['component']} {w['version'] or '(no release version)'} in {w['library']} - {w['status']}")
    L += ["", "## Not done in phase 1", "",
          "- Matching of Android components (platform, libraries, APKs, APEX) against vulnerability data.",
          "- Android Security Bulletin comparison (not in the mirrors).",
          "- APK/APEX contents, compressed EROFS contents, f2fs, squashfs.", ""]
    return "\n".join(L)


def do_list(archive, directory, out, inventory):
    """flash_package.py list for an Android package -> result dict (same files as the other formats + android-summary.*)."""
    src = directory or archive
    outdir = os.path.dirname(os.path.abspath(out))
    work = os.path.join(outdir, f".android-work-{os.getpid()}")      # on the result folder's disk; removed afterwards
    pkg = AndroidPackage(src, work)
    pkg.remove_work = True
    with pkg:
        pkg.load()
        s = pkg.summary()
        inv = []
        for i in pkg.images:
            inv.append({"path": f"images/{i['name']}.img", "type": "file", "size": i.get("bytes"), "sha256": i.get("sha256"),
                        "kind": i.get("kind"), "origin": i["origin"], "status": i.get("status")})
        for p in pkg.parts:
            if p.kind == "fs" and p.sha256 and p.origin.endswith("(logical partition)"):
                inv.append({"path": f"{p.prefix}.img", "type": "file", "size": p.size, "sha256": p.sha256, "kind": "logical partition", "origin": p.origin})
        inv += [{"path": a["path"], "type": "file", "size": a["bytes"], "sha256": a["sha256"], "kind": "apk", "package": a["package"]}
                for a in s["apks"]["items"]]
        inv += [{"path": x["path"], "type": "file", "size": x["bytes"], "sha256": x["sha256"], "kind": "shared object"} for x in s["native_libs"]["items"]]
    source = {"type": "dir" if directory else "archive", "file": os.path.basename(src), "path": os.path.abspath(src),
              "reader": "android_img.py (sparse, LP metadata, ext4, EROFS uncompressed, boot images)", "format": "android"}
    if not directory:
        source["bytes"] = os.path.getsize(src)
    android = {k: s[k] for k in ("status", "detail", "facts", "kernel", "security_patch_level", "vulnerability_matching")}
    android["partitions"] = [{"name": p["name"], "kind": p["kind"], "fs": (p.get("fs") or {}).get("type"), "bytes": p["bytes"],
                              "status": p["status"], "reasons": p["reasons"]} for p in s["partitions"]]
    android["summary_file"] = "android-summary.json"
    result = {"source": source, "archive": {"file": os.path.basename(src), "bytes": source.get("bytes")}, "members": len(inv),
              "rejected_members_count": 0, "rejected_members": [], "rootfs": [], "ambiguous": {},
              "flash_package": {"flash_sh": [], "board_configs": [], "bootloader_files": 0, "bootloader_bytes": 0,
                                "outside_rootfs_files": len(inv), "outside_rootfs_unreadable": 0, "outside_rootfs_unreadable_examples": [],
                                "outside_rootfs_dirs_not_walked": 0, "outside_rootfs_by_dir": {}, "kernel_modules": {}},
              "other_deliverables": None, "inventory_file": os.path.basename(inventory), "android": android}
    with open(inventory, "w", encoding="utf-8") as f:
        json.dump({"source": source, "note": "Android package inventory (phase 1): images, partitions, APKs and shared objects with sha256. "
                   "Nothing here was matched against vulnerability data.", "outside_rootfs": inv, "bootloader": [], "kernel_modules": {},
                   "android": android}, f, ensure_ascii=False, indent=1)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=1)
    with open(os.path.join(outdir, "android-summary.json"), "w", encoding="utf-8") as f:
        json.dump(s, f, ensure_ascii=False, indent=1)
    with open(os.path.join(outdir, "android-summary.md"), "w", encoding="utf-8") as f:
        f.write(summary_md(s) + "\n")
    return result


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 2:
        print("usage: android_img.py <package> <out-dir>", file=sys.stderr)
        return 64
    os.makedirs(argv[1], exist_ok=True)
    isdir = os.path.isdir(argv[0])
    r = do_list(None if isdir else argv[0], argv[0] if isdir else None,
                os.path.join(argv[1], "list.json"), os.path.join(argv[1], "flash-inventory.json"))
    print(r["android"]["status"], r["android"]["detail"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
