#!/usr/bin/env python3
"""Rockchip GPT 原始磁碟：清點第一個分割區之前的原始磁區（idbloader、u-boot.itb），以原始磁區為準（D-027）。

用法（raw-sectors.sh 呼叫；一律 python3 -I）：
  raw_sectors.py inventory --image <未壓縮的 disk.img> --out <raw-sectors.json> --board <板子名稱>
                           [--deb <u-boot 套件 .deb>]... [--slot <名稱>=<LBA>]...
最後一行印 `raw-sectors: OK｜GAP｜FAIL（說明）`；結束碼 OK 0、FAIL 1、GAP 3、用法錯誤 64。

做法：
- 分割區表用 tools/demo/rpi_img.py 的 RpiImage 讀（GPT 表頭與陣列的 CRC 都核對）；只接受 GPT。
- 槽位（預設 idbloader＝LBA 64、u-boot.itb＝LBA 16384、trust＝LBA 24576）取自板子廠商 u-boot 套件裡 setup.sh 的寫入位置
  （Radxa u-boot-rk2410 2017.09-64；只讀文字，沒有執行）。第一個分割區之前、GPT 之後的非零磁區依「前面最近的槽位」分組成區段；
  落在第一個槽位之前的非零資料是身分不明的區段 → GAP。
- 區段的身分只從內容讀：開頭的 magic（RKNS＝Rockchip idblock、d00dfeed＝FIT／FDT）、FIT 裡各映像的描述、型別與雜湊
  （外部資料依 FIT 的 data-offset／data-size 取出、重算 sha256 對照 FIT 記載的值）、以固定樣式找到的版本字串。
  版本字串只取版本欄位（例如 TF-A 的 git describe），不收建置者名稱等其他文字。
- 佐證：同一個槽位的檔案在 (1) sources.yml 的官方 u-boot 套件（.deb）、(2) 映像 rootfs 的 /usr/lib/u-boot/<板子>/ 裡；
  逐位元組相同記「一致」，不同記「不一致」，找不到記「找不到」。**不拿套件版本推磁區裡的版本**。
- GAP 的條件：區段沒有任何「一致」、來源互相矛盾（有「不一致」）、FIT 有映像的雜湊不符或無法驗證、身分認不出來、
  第一個槽位之前有身分不明的資料、來源有某槽位的檔案但磁區全零、第一個分割區之前沒有任何非零磁區或區域太大沒有清點。
- 映像與套件是不可信資料：只讀（os.pread、記憶體內解 ar／tar），不掛載、不解到磁碟、不執行。所有長度都有上限。
"""
import argparse
import hashlib
import importlib.util
import io
import json
import lzma
import os
import re
import struct
import sys
import tarfile
import gzip
import zlib

SECTOR = 512
GPT_END_LBA = 34                       # 預設：LBA 0 保護 MBR、1 GPT 表頭、2–33 分割區陣列（128 項 × 128 bytes）；實際依 GPT 表頭計算
MAX_PRE_PARTITION = 64 << 20           # 第一個分割區之前最多讀 64 MiB
MAX_REGION = 16 << 20                  # 一個區段最多 16 MiB
DEFAULT_SLOTS = (("idbloader.img", 64), ("u-boot.itb", 16384), ("trust.img", 24576))
DEB_MAX = 64 << 20                     # .deb 檔的上限（目前的 u-boot-rk2410 約 18 MB）
DEB_MEMBER_MAX = DEB_MAX
TAR_UNPACKED_MAX = 512 << 20           # data.tar 解開後的上限（u-boot-rk2410 實測 90 MB：一個套件包了幾十塊板子）
DEB_AR_MAX_MEMBERS = 16
TAR_MAX_MEMBERS = 50000
TAR_FILE_MAX = 32 << 20
FDT_MAX_NODES = 2000
FDT_MAX_DEPTH = 16
FDT_MAX_PROP = 1 << 20

OK, FAIL, GAP, USAGE = 0, 1, 3, 64

# 版本字串的固定樣式（只取版本欄位）
VERSION_PATTERNS = (
    ("U-Boot SPL", re.compile(rb"U-Boot SPL ([A-Za-z0-9]+-20[0-9]{2}\.[0-9]{2}[A-Za-z0-9._+-]{0,80}|20[0-9]{2}\.[0-9]{2}[A-Za-z0-9._+-]{0,80})")),
    ("U-Boot", re.compile(rb"U-Boot ([A-Za-z0-9]+-20[0-9]{2}\.[0-9]{2}[A-Za-z0-9._+-]{0,80}|20[0-9]{2}\.[0-9]{2}[A-Za-z0-9._+-]{0,80})")),
    ("Rockchip DDR init", re.compile(rb"ddr-(v[0-9]+\.[0-9]+)-[0-9a-f]{6,16}")),
    ("TF-A BL31 (Rockchip rkbin)", re.compile(rb"bl31-(v[0-9]+\.[0-9]+)")),
    ("TF-A git describe", re.compile(rb"(v[0-9]+\.[0-9]+-[0-9]+-g[0-9a-f]{7,12})")),
    ("OP-TEE", re.compile(rb"OP-TEE version: ([0-9][A-Za-z0-9._+-]{0,40})")),
)


class RawError(Exception):
    pass


class UsageError(Exception):
    pass


DEB_ERRORS = (RawError, OSError, tarfile.TarError, lzma.LZMAError, EOFError, zlib.error, ValueError, struct.error)


def load_rpi_img(root):
    p = os.path.join(root, "tools", "demo", "rpi_img.py")
    spec = importlib.util.spec_from_file_location("dumpling_rpi_img", p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def pread_exact(fd, n, off):
    out = bytearray()
    while len(out) < n:
        b = os.pread(fd, n - len(out), off + len(out))
        if not b:
            raise RawError("映像讀不完整（offset %d）" % off)
        out += b
    return bytes(out)


# ---------------------------------------------------------------- FDT／FIT

def parse_fdt(buf):
    """最小的 FDT 解析：回傳 (totalsize, {節點路徑: {屬性: bytes}})。格式錯 → RawError。"""
    if len(buf) < 40 or buf[:4] != b"\xd0\x0d\xfe\xed":
        raise RawError("不是 FDT")
    total, off_struct, off_strings, _rsv, version, _lc, _boot, size_strings, size_struct = struct.unpack(">9I", buf[4:40])
    if total > len(buf) or total < 40:
        raise RawError("FDT totalsize 超出範圍")
    if version < 16:
        raise RawError("FDT 版本 %d 太舊" % version)
    if not (off_struct + size_struct <= total and off_strings + size_strings <= total):
        raise RawError("FDT 區塊超出 totalsize")
    strings = buf[off_strings:off_strings + size_strings]
    o, end = off_struct, off_struct + size_struct
    path, nodes, count, ended = [], {}, 0, False

    def cstr(b, i, limit):
        j = b.find(b"\0", i, limit)
        if j < 0:
            raise RawError("FDT 字串沒有結尾")
        return b[i:j], j

    while o + 4 <= end:
        tok = struct.unpack(">I", buf[o:o + 4])[0]
        o += 4
        if tok == 1:                                   # BEGIN_NODE
            name, j = cstr(buf, o, end)
            o = (j + 1 + 3) & ~3
            path.append(name.decode("ascii", "replace"))
            if len(path) > FDT_MAX_DEPTH:
                raise RawError("FDT 太深")
            count += 1
            if count > FDT_MAX_NODES:
                raise RawError("FDT 節點太多")
            nodes.setdefault("/".join(path[1:]), {})
        elif tok == 2:                                 # END_NODE
            if not path:
                raise RawError("FDT 節點不對稱")
            path.pop()
        elif tok == 3:                                 # PROP
            if o + 8 > end:
                raise RawError("FDT 屬性截斷")
            ln, nameoff = struct.unpack(">II", buf[o:o + 8])
            o += 8
            if ln > FDT_MAX_PROP or o + ln > end:
                raise RawError("FDT 屬性長度超出範圍")
            if nameoff >= len(strings):
                raise RawError("FDT 屬性名稱超出範圍")
            pname, _ = cstr(strings, nameoff, len(strings))
            if not path:
                raise RawError("FDT 屬性不在節點裡")
            nodes["/".join(path[1:])][pname.decode("ascii", "replace")] = buf[o:o + ln]
            o = (o + ln + 3) & ~3
        elif tok == 4:                                 # NOP
            continue
        elif tok == 9:                                 # END
            ended = True
            break
        else:
            raise RawError("FDT 不認得的 token %d" % tok)
    if not ended:
        raise RawError("FDT 沒有 END（截斷）")
    if path:
        raise RawError("FDT 有節點沒有關閉")
    return total, nodes


def _text(v):
    if v is None:
        return None
    t = v.split(b"\0", 1)[0]
    return t.decode("ascii", "replace")[:120] if t and all(32 <= c < 127 for c in t) else None


def _u32(v):
    return struct.unpack(">I", v)[0] if v is not None and len(v) == 4 else None


def fit_images(buf):
    """FIT（u-boot.itb）：每個 /images/<名稱> 的描述、型別、資料大小、FIT 記載的雜湊與重算的結果。"""
    total, nodes = parse_fdt(buf)
    out = {"description": _text(nodes.get("", {}).get("description")), "images": [], "configurations": []}
    # 外部資料的起點：上游 U-Boot 是 FDT 大小進位到 4 bytes；Rockchip 的 U-Boot 2017.09 實測是進位到 512 bytes。
    # 兩種都試，以 FIT 記載的雜湊確認是哪一種（記在 data_base），不寫死、不猜。
    bases = (("upstream-4", (total + 3) & ~3), ("block-512", (total + 511) & ~511))
    cache = {}

    def sha(start, size):
        k = (start, size)
        if k not in cache:
            cache[k] = hashlib.sha256(buf[start:start + size]).hexdigest()
        return cache[k]

    hashes = {}
    for hp in nodes:
        parts = hp.split("/")
        if len(parts) == 3 and parts[0] == "images" and parts[2].startswith("hash"):
            algo, val = _text(nodes[hp].get("algo")), nodes[hp].get("value")
            if algo == "sha256" and val is not None and len(val) == 32:
                hashes.setdefault(parts[1], val.hex())
    for path in sorted(nodes):
        parts = path.split("/")
        if len(parts) == 2 and parts[0] == "images":
            props = nodes[path]
            want = hashes.get(parts[1])
            base_used, digest, size_out = None, None, None
            if "data" in props:
                where, digest, size_out = "embedded", hashlib.sha256(props["data"]).hexdigest(), len(props["data"])
            else:
                off, size = _u32(props.get("data-offset")), _u32(props.get("data-size"))
                pos = _u32(props.get("data-position"))
                where = "missing"
                if size is not None and pos is not None:
                    if pos + size <= len(buf):
                        where, base_used, digest, size_out = "external", "data-position", sha(pos, size), size
                    else:
                        where = "out-of-range"
                elif size is not None and off is not None:
                    cands = [(label, base + off) for label, base in bases if base + off + size <= len(buf)]
                    if not cands:
                        where = "out-of-range"
                    elif want:
                        hit = next((c for c in cands if sha(c[1], size) == want), None)
                        label, start = hit or cands[0]
                        where, base_used, digest, size_out = "external", label, sha(start, size), size
                    elif len({sha(st, size) for _l, st in cands}) == 1:
                        where, base_used, digest, size_out = "external", "+".join(l for l, _s in cands), sha(cands[0][1], size), size
                    else:
                        # 沒有 sha256 可以確認、兩種起點的內容又不同：不選（不猜）
                        where = "ambiguous"
            img = {"name": parts[1], "description": _text(props.get("description")), "type": _text(props.get("type")),
                   "arch": _text(props.get("arch")), "compression": _text(props.get("compression")),
                   "data": where, "size": size_out, "sha256": digest, "data_base": base_used, "fit_hash": None}
            if want:
                img["fit_hash"] = {"algo": "sha256", "value": want, "matches": (img["sha256"] == want) if img["sha256"] else None}
            out["images"].append(img)
        elif len(parts) == 2 and parts[0] == "configurations":
            out["configurations"].append({"name": parts[1], "description": _text(nodes[path].get("description"))})
    return out


# ---------------------------------------------------------------- 身分

def versions(buf):
    found = []
    for label, rx in VERSION_PATTERNS:
        vals = sorted({m.group(1).decode("ascii") for m in rx.finditer(buf)})
        for v in vals[:4]:
            found.append({"component": label, "version": v})
    return found


def identify(buf):
    ident = {"kind": "unknown", "versions": versions(buf)}
    if buf[:4] == b"RKNS":
        ident["kind"] = "rockchip-idblock"
    elif buf[:4] == b"\xd0\x0d\xfe\xed":
        ident["kind"] = "fit"
        try:
            ident["fit"] = fit_images(buf)
        except RawError as e:
            ident["kind"], ident["fit_error"] = "fdt-unparsed", str(e)
    return ident


# ---------------------------------------------------------------- 佐證來源

def _ar_members(b):
    if b[:8] != b"!<arch>\n":
        raise RawError("不是 ar（.deb）")
    o, out = 8, {}
    while o + 60 <= len(b):
        if len(out) >= DEB_AR_MAX_MEMBERS:
            raise RawError("ar 成員超過 %d 個" % DEB_AR_MAX_MEMBERS)
        if b[o + 58:o + 60] != b"`\n":
            raise RawError("ar 成員標頭格式錯")
        name = b[o:o + 16].decode("ascii", "replace").strip().rstrip("/")
        try:
            size = int(b[o + 48:o + 58].decode("ascii").strip())
        except ValueError:
            raise RawError("ar 成員大小格式錯")
        if size < 0 or size > DEB_MEMBER_MAX or o + 60 + size > len(b):
            raise RawError("ar 成員大小超出範圍")
        out[name] = b[o + 60:o + 60 + size]
        o += 60 + size + (size & 1)
    return out


def _open_tar(name, data):
    if name.endswith(".xz"):
        d = lzma.LZMADecompressor()
        raw = d.decompress(data, max_length=TAR_UNPACKED_MAX + 1)
        if len(raw) <= TAR_UNPACKED_MAX and not d.eof:
            raise RawError("%s 的 xz 串流不完整（截斷）" % name)
    elif name.endswith(".gz"):
        raw = gzip.GzipFile(fileobj=io.BytesIO(data)).read(TAR_UNPACKED_MAX + 1)
    elif name.endswith(".tar"):
        raw = data
    else:
        raise RawError("%s 的壓縮格式不支援（只讀 xz／gz／未壓縮）" % name)
    if len(raw) > TAR_UNPACKED_MAX:
        raise RawError("data.tar 解開後太大")
    return tarfile.open(fileobj=io.BytesIO(raw), mode="r:")


def _members(t):
    """逐個迭代 tar 成員（不用 getmembers 一次載入），數量有上限。"""
    for i, m in enumerate(t):
        if i >= TAR_MAX_MEMBERS:
            raise RawError("tar 成員超過 %d 個" % TAR_MAX_MEMBERS)
        yield m


def deb_files(path, board, wanted):
    """官方 .deb 裡 usr/lib/u-boot/<板子>/<檔名> 的內容 → {檔名: bytes}、套件名稱與版本。"""
    if not os.path.isfile(path) or os.path.islink(path) or os.lstat(path).st_size > DEB_MAX:
        raise RawError("套件檔不是一般檔案或太大")
    with open(path, "rb") as f:
        mem = _ar_members(f.read())
    info = {"package": None, "version": None}
    ctrl = next((k for k in mem if k.startswith("control.tar")), None)
    if ctrl:
        with _open_tar(ctrl, mem[ctrl]) as t:
            for m in _members(t):
                if m.isfile() and m.name.lstrip("./") == "control" and m.size < 65536:
                    for line in t.extractfile(m).read().decode("utf-8", "replace").splitlines():
                        k, _, v = line.partition(":")
                        if k in ("Package", "Version"):
                            info[k.lower()] = v.strip()[:100]
    data = next((k for k in mem if k.startswith("data.tar")), None)
    files = {}
    if data:
        with _open_tar(data, mem[data]) as t:
            for m in _members(t):
                n = m.name.lstrip("./")
                for w in wanted:
                    if n == "usr/lib/u-boot/%s/%s" % (board, w) and m.isfile() and m.size <= TAR_FILE_MAX:
                        files[w] = t.extractfile(m).read()
    return files, info


def rootfs_files(rpi, im, board, wanted):
    """映像 rootfs 的 /usr/lib/u-boot/<板子>/<檔名>（ext4 唯讀走訪；符號連結不跟）。"""
    root, why = im.rootfs()
    if root is None:
        return {}, "rootfs 讀不到（%s）" % why
    Ext4 = rpi.rk().Ext4
    fs = Ext4(im.fd, root["offset_in_file"], root["size"])
    ino = 2
    for comp in ("usr", "lib", "u-boot", board):
        ents, _bad = fs.entries(fs.inode(ino))
        nxt = dict(ents).get(comp.encode())
        if nxt is None:
            return {}, "rootfs 沒有 /usr/lib/u-boot/%s" % board
        i = fs.inode(nxt)
        if (i.mode & 0o170000) != 0o040000:
            return {}, "rootfs 的 /usr/lib/u-boot/%s 路徑上有非目錄（不跟符號連結）" % board
        ino = nxt
    ents, _bad = fs.entries(fs.inode(ino))
    out = {}
    for name, n in ents:
        w = name.decode("utf-8", "replace")
        if w in wanted:
            i = fs.inode(n)
            if (i.mode & 0o170000) == 0o100000 and i.size <= TAR_FILE_MAX:
                with fs.open(i) as f:
                    out[w] = f.read(i.size)
    return out, None


# ---------------------------------------------------------------- 清點

SCAN_START_LBA = 2                     # LBA 0 保護 MBR、LBA 1 GPT 表頭；從 LBA 2 開始清點，只排除分割區陣列實際佔用的區間


def gpt_array(fd):
    """GPT 分割區陣列佔用的區間 [起始 LBA, 結束 LBA)（依主要 GPT 表頭；rpi_img 已核對過表頭與陣列的 CRC）。
    陣列不一定緊接在表頭後面（例如放在 LBA 128），所以不能假設 LBA 34 之前都是陣列。"""
    h = pread_exact(fd, 92, SECTOR)
    ent_lba, num, esz = struct.unpack("<Q", h[72:80])[0], struct.unpack("<I", h[80:84])[0], struct.unpack("<I", h[84:88])[0]
    if not (2 <= ent_lba <= 1 << 20 and 0 < num <= 1024 and 128 <= esz <= 4096):
        raise RawError("GPT 表頭的分割區陣列欄位不合理")
    return ent_lba, ent_lba + -(-(num * esz) // SECTOR)


def regions_of(fd, first_lba, slots, array=(2, GPT_END_LBA)):
    """LBA 2 到第一個分割區之前（排除 GPT 分割區陣列的區間）的非零磁區 → 依槽位分組的區段 [(槽位名或 None, 起始 LBA, 磁區數)]。
    區域超過上限 → RawError（呼叫端當 GAP：沒有清點）。"""
    start_lba = SCAN_START_LBA
    if first_lba <= start_lba:
        return []
    if (first_lba - start_lba) * SECTOR > MAX_PRE_PARTITION:
        raise RawError("第一個分割區之前的區域超過 %d MiB，沒有清點" % (MAX_PRE_PARTITION >> 20))
    pre = pread_exact(fd, (first_lba - start_lba) * SECTOR, start_lba * SECTOR)
    nz = [lba for lba in range(start_lba, first_lba)
          if not array[0] <= lba < array[1] and any(pre[(lba - start_lba) * SECTOR:(lba - start_lba + 1) * SECTOR])]
    slots = sorted([s for s in slots if start_lba <= s[1] < first_lba], key=lambda s: s[1])
    groups = {}
    for lba in nz:
        owner = None
        for name, start in slots:
            if start <= lba:
                owner = (name, start)
        key = owner if owner else (None, None)
        groups.setdefault(key, []).append(lba)
    out = []
    for (name, start), lbas in sorted(groups.items(), key=lambda kv: kv[1][0]):
        s = start if name else lbas[0]
        out.append((name, s, lbas[-1] + 1 - s))
    return out


def inventory(a, root):
    rpi = load_rpi_img(root)
    slots = list(DEFAULT_SLOTS)
    for s in a.slot or []:
        name, _, lba = s.partition("=")
        if not re.match(r"^[A-Za-z0-9._-]{1,64}$", name) or not lba.isdigit():
            raise UsageError("--slot 要寫成 <檔名>=<LBA>")
        slots = [x for x in slots if x[0] != name] + [(name, int(lba))]
    if not re.match(r"^[a-z0-9][a-z0-9._-]{0,63}$", a.board):
        raise UsageError("--board 不合法")
    if not os.path.isfile(a.image) or os.path.islink(a.image):
        raise RawError("映像不是一般檔案")
    im = rpi.RpiImage(a.image)
    try:
        t = im.table()
        if t["scheme"] != "gpt":
            raise RawError("分割區表是 %s，不是 GPT（Rockchip 的原始磁區清點只支援 GPT）" % t["scheme"])
        if not t["partitions"]:
            raise RawError("GPT 沒有分割區")
        first = min(p["start_lba"] for p in t["partitions"])
        wanted = [s[0] for s in slots]
        sources = []
        for d in a.deb or []:
            try:
                files, info = deb_files(d, a.board, wanted)
                sources.append({"source": "package", "file": os.path.basename(d), "package": info["package"],
                                "version": info["version"], "files": files, "error": None})
            except DEB_ERRORS as e:
                why = e.strerror if isinstance(e, OSError) and e.strerror else str(e)
                sources.append({"source": "package", "file": os.path.basename(d), "files": {}, "error": "%s: %s" % (type(e).__name__, why[:200])})
        try:
            files, err = rootfs_files(rpi, im, a.board, wanted)
        except Exception as e:      # noqa: BLE001  ext4 解析錯誤：記下來當 GAP，不中斷
            files, err = {}, "%s: %s" % (type(e).__name__, e)
        sources.append({"source": "rootfs", "file": "/usr/lib/u-boot/%s/" % a.board, "files": files, "error": err})

        regions, gaps, notes = [], [], []
        arr = gpt_array(im.fd)
        gpt_end = arr[1]
        in_part = [s for s in slots if s[1] >= first]
        if in_part:
            notes.append("槽位落在分割區裡（不屬於分割區之前的原始磁區），沒有清點：%s" % "、".join("%s（LBA %d）" % s for s in in_part))
        for name, lba in slots:
            if lba < SCAN_START_LBA or arr[0] <= lba < arr[1]:
                gaps.append("槽位 %s（LBA %d）落在 GPT 表頭或分割區陣列裡，沒辦法清點" % (name, lba))
        try:
            found = regions_of(im.fd, first, slots, arr)
        except RawError as e:
            found = None
            gaps.append(str(e))
        if found == [] and first <= gpt_end:
            gaps.append("第一個分割區緊接在 GPT 之後，沒有放開機程式的原始磁區（開機程式可能在別處，例如 SPI flash：映像裡沒有，不推測）")
        elif found == []:
            gaps.append("第一個分割區之前沒有任何非零磁區（開機程式可能在別處，例如 SPI flash：映像裡沒有，不推測）")
        for name, start, n in found or []:
            if n * SECTOR > MAX_REGION:
                gaps.append("LBA %d 的區段超過 %d MiB，沒有清點" % (start, MAX_REGION >> 20))
                continue
            buf = pread_exact(im.fd, n * SECTOR, start * SECTOR)
            r = {"slot": name, "start_lba": start, "sectors": n, "sha256": hashlib.sha256(buf).hexdigest(),
                 "identity": identify(buf), "corroboration": []}
            for s in sources:
                f = s["files"].get(name) if name else None
                if s.get("error") and f is None:
                    state = "找不到（%s）" % s["error"]
                elif f is None:
                    state = "找不到"
                else:
                    # 檔案結尾可能是全零的磁區（非零區段比檔案短）：直接讀槽位起算、檔案長度的原始位元組比對；
                    # 區段的非零資料超出檔案長度 → 不一致（磁區裡有檔案以外的東西）
                    try:
                        raw = pread_exact(im.fd, len(f), start * SECTOR) if len(f) <= MAX_REGION else b""
                    except RawError:
                        raw = b""                      # 映像在檔案長度內就結束 → 不一致
                    tail = buf[len(f):] if len(buf) > len(f) else b""
                    state = "一致" if f and raw == f and not any(tail) else "不一致"
                r["corroboration"].append({"source": s["source"], "file": s["file"], "package": s.get("package"),
                                           "version": s.get("version"), "state": state,
                                           "sha256": hashlib.sha256(f).hexdigest() if f is not None else None})
            why = []
            if name is None:
                why.append("第一個槽位之前有身分不明的資料")
            if r["identity"]["kind"] in ("unknown", "fdt-unparsed"):
                why.append("內容的格式認不出來")
            fit = r["identity"].get("fit")
            if fit and any(i["fit_hash"] and i["fit_hash"]["matches"] is False for i in fit["images"]):
                why.append("FIT 裡有映像的雜湊跟 FIT 記載的不符")
            if fit:
                unv = [i["name"] for i in fit["images"] if not (i["fit_hash"] and i["fit_hash"]["matches"] is True)
                       and not (i["fit_hash"] and i["fit_hash"]["matches"] is False)]
                if unv:
                    why.append("FIT 裡有映像的雜湊無法驗證（%s）" % "、".join(unv[:8]))
                if not fit["images"]:
                    why.append("FIT 裡沒有任何映像")
            if not any(c["state"] == "一致" for c in r["corroboration"]):
                why.append("沒有任何佐證來源一致")
            elif any(c["state"] == "不一致" for c in r["corroboration"]):
                why.append("佐證來源互相矛盾（有一致也有不一致）")
            if why:
                gaps.append("LBA %d（%s）：%s" % (start, name or "未知", "；".join(why)))
            regions.append(r)
        # 反向檢查：佐證來源裡有這個槽位的檔案，磁區卻是全零（例如開機程式被清掉、或放在別處）
        have = {r["slot"] for r in regions if r["slot"]}
        for name, lba in slots:
            srcs = [s["source"] + " " + s["file"] for s in sources if name in s["files"]]
            if found is not None and srcs and name not in have and SCAN_START_LBA <= lba < first and not arr[0] <= lba < arr[1]:
                gaps.append("槽位 %s（LBA %d）在 %s 有檔案，磁區卻是全零" % (name, lba, "、".join(srcs)))
        doc = {"schema": 1, "platform": a.platform, "board": a.board, "image": os.path.basename(a.image),
               "partition_table": {"scheme": t["scheme"], "first_partition_lba": first,
                                   "partitions": [{k: p.get(k) for k in ("index", "name", "type_name", "start_lba", "sectors", "fs_kind")}
                                                  for p in t["partitions"]]},
               "slots": [{"name": n, "lba": l} for n, l in slots],
               "slots_source": "板子廠商 u-boot 套件 setup.sh 的寫入位置（只讀文字，沒有執行）",
               "regions": regions,
               "sources": [{k: v for k, v in s.items() if k != "files"} | {"found": sorted(s["files"])} for s in sources],
               "gpt_entry_array_lba": list(arr), "notes": notes,
               "status": "GAP" if gaps else "OK", "gaps": gaps,
               "note": "以原始磁區為準；套件只當佐證，不拿套件版本推磁區裡的版本（D-027）。閉源成品（DDR 初始化、TF-A BL31）的安全公告比對不在這一步。"}
    finally:
        im.close()
    tmp = a.out + ".part"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1, sort_keys=False)
        f.write("\n")
    os.replace(tmp, a.out)
    return doc


def main(argv=None):
    ap = argparse.ArgumentParser(description="Rockchip 原始磁區清點")
    sub = ap.add_subparsers(dest="cmd")
    i = sub.add_parser("inventory")
    i.add_argument("--image", required=True)
    i.add_argument("--out", required=True)
    i.add_argument("--board", required=True)
    i.add_argument("--platform", default="rockchip")
    i.add_argument("--deb", action="append")
    i.add_argument("--slot", action="append")
    try:
        a = ap.parse_args(argv)
    except SystemExit:
        print("raw-sectors: FAIL（參數錯誤）")
        return USAGE
    if a.cmd != "inventory":
        print("raw-sectors: FAIL（要給子指令 inventory）")
        return USAGE
    root = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
    try:
        doc = inventory(a, root)
    except UsageError as e:
        print("raw-sectors: FAIL（%s）" % e)
        return USAGE
    except Exception as e:      # noqa: BLE001  分割區表、讀檔錯誤：FAIL 並寫原因，不猜
        why = ("%s（%s）" % (e.strerror, os.path.basename(e.filename or ""))) if isinstance(e, OSError) and e.strerror else str(e)[:200]
        print("raw-sectors: FAIL（%s: %s）" % (type(e).__name__, why))
        return FAIL
    n = len(doc["regions"])
    if doc["status"] == "OK":
        print("raw-sectors: OK（%d 個區段，都有佐證一致、沒有矛盾）" % n)
        return OK
    msg = "；".join(doc["gaps"])
    print("raw-sectors: GAP（%d 個區段；%s）" % (n, msg if len(msg) <= 300 else msg[:297] + "…"))
    return GAP


if __name__ == "__main__":
    sys.exit(main())
