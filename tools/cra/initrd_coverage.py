#!/usr/bin/env python3
"""initrd_coverage.py：rootfs 的 /boot/initrd* 裡有哪些 ELF／腳本，各自有沒有被套件掃描涵蓋。唯讀，不執行任何東西。

用法（python3 -I）：
  python3 -I initrd_coverage.py --from <rootfs tar｜刷機包 tbz2｜rootfs 資料夾> [--prefix <rootfs 在刷機包裡的路徑>]
                                [--inventory <flash-inventory.json>] --out <資料夾>

寫出 --out/initrd-coverage.json 與 initrd-coverage.md；stdout 一行 `B-initrd-coverage<TAB>狀態<TAB>說明`：
  OK       每個 initrd 都讀得懂，裡面每個 ELF／腳本都有 sha256 相同、而且屬於 dpkg 套件的 rootfs 檔案（記「copy of <套件> <版本>」）；
  GAP      有 ELF／腳本在 rootfs 裡找不到相同內容的套件檔案（initrd-only，沒有被涵蓋），或 initrd 讀不懂／超過上限（NOT_ASSESSED）；
  INFO     rootfs 的 /boot 沒有 initrd*（沒有東西要評估，不是「安全」的判斷）；
  FAIL     來源讀不到或結果寫不出來。退出碼：OK／INFO 0、GAP 2、FAIL 1、參數錯誤 64。

做法（映像是不可信資料）：
- rootfs 只串流讀（tar 不解開到磁碟；讀法與 image_check.py 共用）；initrd 讀進記憶體（單檔上限 INITRD_MAX），在記憶體裡解壓、解析 cpio（newc），
  不寫到主機檔案系統、不執行。名稱是絕對路徑或含 .. 的項目拒絕並計數；項目數、解壓後總量、單檔大小都有上限。
- 解壓：gzip、xz／lzma、bzip2 用 Python 標準函式庫；zstd 用 Python 3.14 的 compression.zstd，沒有時用 zstd 指令（與 jetson_rootfs.py 相同的做法）；
  lz4 用 rockchip_img.py 的 lz4_decompress。這兩種的後面不再找下一段（假設是最後一段）。前面可以有未壓縮的 early cpio（微碼）。
  讀不懂的格式 → 該 initrd 標 NOT_ASSESSED，不猜。
- initrd 裡的 ELF（開頭 \\x7fELF）與腳本（開頭 #!）算 sha256；rootfs 裡同樣開頭的一般檔案也算 sha256。
  (a) 有 sha256 相同、而且屬於某個 dpkg 套件（var/lib/dpkg/info/*.list）的 rootfs 檔案 → 「copy of <套件> <版本>」（版本來自 var/lib/dpkg/status）；
  (b) 其他一律列「initrd-only, not covered」（GAP）。相同內容的 rootfs 檔案不屬於任何套件時，原因另寫。
- 不寫「沒用」「可移除」。flash-inventory.json 裡的 *initrd* 檔（例如 bootloader/l4t_initrd.img，只在燒錄時使用）另列，標「只在燒錄時使用」，不分析。
"""
import argparse
import collections
import contextlib
import hashlib
import importlib.util
import json
import lzma
import bz2
import os
import re
import subprocess
import sys
import tarfile
import threading
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCHEMA = "sca-center-initrd-coverage/1"
TOOL_VERSION = "2026-11-11.1"
INITRD_MAX = 256 << 20        # 單一 initrd 檔（壓縮後）
INITRDS_MAX = 8               # /boot 下最多處理幾個 initrd 檔
OUT_MAX = 2 << 30             # 單一 initrd 解壓後的總量
ENTRIES_MAX = 300_000         # 單一 initrd 的 cpio 項目
NAME_MAX = 4096
HASH_MAX = 128 << 20          # initrd 與 rootfs 裡算雜湊的單檔上限
ROOTFS_HASH_TOTAL = 16 << 30  # rootfs 算雜湊的總量
SEGMENTS_MAX = 16
FILES_JSON_MAX = 20_000
SHA_PATHS = 16                # 每個 sha256 記幾個 rootfs 路徑
STATUS_MAX = 64 << 20         # var/lib/dpkg/status
NEWC = (b"070701", b"070702")
S_IFMT, S_IFREG, S_IFDIR, S_IFLNK = 0o170000, 0o100000, 0o040000, 0o120000


class Fail(Exception):
    pass


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


_IC = _RK = None


def icmod():
    global _IC
    if _IC is None:
        _IC = _load("sca_center_image_check", HERE / "image_check.py")
    return _IC


def rkmod():
    global _RK
    if _RK is None:
        _RK = _load("sca_center_rockchip_img", HERE.parent / "demo" / "rockchip_img.py")
    return _RK


# ---------------------------------------------------------------- rootfs（串流讀）

def sha_of_stream(head, f, size):
    h = hashlib.sha256(head)
    left = size - len(head)
    while left > 0:
        c = f.read(min(1 << 20, left))
        if not c:
            return None
        h.update(c)
        left -= len(c)
    return h.hexdigest()


def is_initrd_name(path):
    if path.count("/") != 1 or not path.startswith("boot/"):
        return False
    return path.split("/", 1)[1].startswith(("initrd", "initramfs"))


def load_rootfs(src, prefix):
    """→ (img, initrds{路徑: bytes｜None}, initrd_notes{路徑: 說明}, by_sha{sha: [路徑]}, source, cov)。"""
    ic = icmod()
    fp = ic.flash_package()
    pp = tuple(fp.split_name(prefix) or ()) if prefix else ()
    if prefix and not pp:
        raise Fail("--prefix is not valid")
    img = ic.Image()
    initrds, notes = {}, {}
    by_sha = collections.defaultdict(list)
    sha_at = {}
    st = {"hashed": 0, "hash_cap": 0, "text": 0}

    def feed(it):
        for path, kind, mode, size, link, uid, opener in it:
            if len(path) > ic.PATH_MAX or path.count("/") >= ic.DEPTH_MAX:
                img.note("rejected", path[:200])
                continue
            img.add(path, kind, mode, size, link, uid)
            if kind == "hardlink":
                if link in sha_at:
                    sha_at[path] = sha_at[link]
                    if len(by_sha[sha_at[link]]) < SHA_PATHS:
                        by_sha[sha_at[link]].append(path)
                    img.nodes[path][2] = img.nodes[link][2] if link in img.nodes else 0
                continue
            if kind != "file":
                continue
            name = path.rsplit("/", 1)[-1]
            is_list = path.startswith("var/lib/dpkg/info/") and name.endswith(".list")
            is_status = path == "var/lib/dpkg/status"
            is_rd = is_initrd_name(path)
            if is_rd and len(initrds) >= INITRDS_MAX:
                notes[path] = f"more than {INITRDS_MAX} initrd files in /boot: not read"
                continue
            if is_rd and size > INITRD_MAX:
                initrds[path] = None
                notes[path] = f"larger than the {INITRD_MAX >> 20} MB limit: not read"
                continue
            small = size <= ic.TEXT_LIST_MAX if is_list else size <= STATUS_MAX if is_status else False
            if (is_list or is_status) and not small:
                img.note("cap_text", path)
                continue
            if (is_list or is_status) and st["text"] + size > ic.TEXT_TOTAL:
                img.note("cap_text_total", path)
                continue
            try:
                f = opener()
            except OSError as e:
                img.note("unreadable", f"{path} ({e.strerror or type(e).__name__})")
                if is_rd:
                    initrds[path] = None
                    notes[path] = "could not be read"
                continue
            with contextlib.closing(f):
                if is_rd:
                    initrds[path] = f.read(size + 1)[:INITRD_MAX]
                    if len(initrds[path]) != size:
                        initrds[path] = None
                        notes[path] = "short read: not assessed"
                    continue
                if is_list or is_status:
                    st["text"] += size
                    img.content[path] = f.read(size)
                    continue
                if size < 4 or size > HASH_MAX:
                    if size > HASH_MAX:
                        st["hash_cap"] += 1
                    continue
                head = f.read(4)
                if head[:4] != b"\x7fELF" and head[:2] != b"#!":
                    continue
                if st["hashed"] + size > ROOTFS_HASH_TOTAL:
                    st["hash_cap"] += 1
                    continue
                h = sha_of_stream(head, f, size)
                if h is None:
                    img.note("unreadable", f"{path} (short read)")
                    continue
                st["hashed"] += size
                sha_at[path] = h
                if len(by_sha[h]) < SHA_PATHS:
                    by_sha[h].append(path)

    if os.path.isdir(src):
        kind = "dir"
        feed(ic.iter_dir(fp, src, pp, img))
    elif os.path.isfile(src):
        kind = "archive" if pp else "rootfs-tar"
        try:
            with fp.open_stream(src) as t:
                feed(ic.iter_tar(fp, t, pp, img))
                pos = getattr(getattr(t, "fileobj", None), "pos", None)
                if isinstance(pos, int) and pos < t.offset + tarfile.BLOCKSIZE:
                    raise Fail("the archive ends early (incomplete tar)")
        except fp.Fail as e:
            raise Fail(ic.clean(e, 200))
        except (tarfile.TarError, EOFError) as e:
            raise Fail(f"tar read failed: {ic.clean(e, 120)}")
    else:
        raise Fail("--from is neither a file nor a folder")
    if not img.nodes:
        raise Fail("the source has no entries" + (" under --prefix" if pp else ""))
    source = {"type": kind, "file": ic.clean(os.path.basename(os.path.abspath(src))), "prefix": "/".join(pp) or None}
    return img, initrds, notes, by_sha, source, st


def dpkg_versions(img):
    """var/lib/dpkg/status → {套件: 版本}（Status 是 installed 的；同名多架構取第一個）。"""
    data = img.content.get("var/lib/dpkg/status")
    out = {}
    if not data:
        return out
    for block in data.decode("utf-8", "replace").split("\n\n"):
        pkg = ver = stt = None
        for ln in block.splitlines():
            if ln.startswith("Package: "):
                pkg = ln[9:].strip()
            elif ln.startswith("Version: "):
                ver = ln[9:].strip()
            elif ln.startswith("Status: "):
                stt = ln[8:].strip()
        if pkg and ver and stt and stt.endswith(" installed"):
            out.setdefault(pkg, ver)
    return out


# ---------------------------------------------------------------- initrd（記憶體裡解壓、解析 cpio）

class Budget:
    def __init__(self, cap):
        self.left = cap


class Buf:
    """chunk 迭代器上的 read／skip；總量超過 budget → Fail。"""

    def __init__(self, gen, budget):
        self.g, self.b, self.eof, self.budget, self.total = iter(gen), bytearray(), False, budget, 0

    def _fill(self, n):
        while len(self.b) < n and not self.eof:
            try:
                c = next(self.g)
            except StopIteration:
                self.eof = True
                break
            self.budget.left -= len(c)
            if self.budget.left < 0:
                raise Fail(f"decompressed size is over the {OUT_MAX >> 20} MB limit")
            self.b += c

    def read(self, n):
        self._fill(n)
        out = bytes(self.b[:n])
        del self.b[:n]
        self.total += len(out)
        return out

    def skip(self, n):
        while n > 0:
            c = self.read(min(n, 1 << 20))
            if not c:
                raise Fail("the archive ends early")
            n -= len(c)

    def drain(self):
        while not self.eof:
            self.b.clear()
            self._fill(1 << 20)


def raw_gen(data, pos):
    for i in range(pos, len(data), 1 << 20):
        yield data[i:i + (1 << 20)]


def zlib_gen(data, pos, st):
    d = zlib.decompressobj(31)
    i = pos
    while i < len(data) and not d.eof:
        chunk = data[i:i + 65536]
        i += len(chunk)
        buf = chunk
        while buf and not d.eof:
            out = d.decompress(buf, 1 << 20)
            if out:
                yield out
            buf = d.unconsumed_tail
        if d.eof:
            st["end"] = i - len(d.unused_data)
    if not d.eof:
        raise Fail("gzip data is truncated")


def stream_gen(make, data, pos, st, name):
    """lzma／bz2／zstd（decompress(data, max_length)／eof／needs_input／unused_data 的介面）。"""
    d = make()
    i = pos
    while i < len(data) and not d.eof:
        chunk = data[i:i + 65536]
        i += len(chunk)
        out = d.decompress(chunk, 1 << 20)
        while True:
            if out:
                yield out
            if d.eof or d.needs_input:
                break
            out = d.decompress(b"", 1 << 20)
        if d.eof:
            st["end"] = i - len(d.unused_data)
    if not d.eof:
        raise Fail(f"{name} data is truncated")


def zstd_cmd_gen(data, pos):
    """zstd 指令（Python 沒有 compression.zstd 時；同 jetson_rootfs.py）。"""
    import shutil
    if not shutil.which("zstd"):
        raise Fail("zstd compressed, and neither Python compression.zstd nor the zstd command is available")
    p = subprocess.Popen(["zstd", "-dc", "--"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    def feed():
        try:
            p.stdin.write(bytes(data[pos:]))
        except OSError:
            pass
        finally:
            with contextlib.suppress(OSError):
                p.stdin.close()
    th = threading.Thread(target=feed, daemon=True)
    th.start()
    try:
        while True:
            c = p.stdout.read(1 << 20)
            if not c:
                break
            yield c
    finally:
        p.kill()
        p.wait()
    if p.returncode not in (0, -9):
        raise Fail("zstd could not decompress the data")


def detect(data, pos):
    m = data[pos:pos + 6]
    if m in NEWC:
        return "cpio"
    if m[:2] == b"\x1f\x8b":
        return "gzip"
    if m[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if m[:3] == b"BZh":
        return "bzip2"
    if m[:4] == b"\x28\xb5\x2f\xfd":
        return "zstd"
    if m[:4] in (b"\x04\x22\x4d\x18", b"\x02\x21\x4c\x18"):
        return "lz4"
    if m[:1] == b"\x5d" and len(data) > pos + 13:
        return "lzma"
    return None


def parse_cpio(buf, on_file, counters):
    """newc → on_file(path, mode, nlink, ino_key, size, reader)。TRAILER 或資料用完時結束。"""
    while True:
        h = buf.read(110)
        if len(h) == 0:
            return "end"
        if len(h) < 110 or h[:6] not in NEWC:
            raise Fail("not a valid newc cpio entry")
        try:
            v = [int(h[6 + 8 * i:14 + 8 * i], 16) for i in range(13)]
        except ValueError:
            raise Fail("cpio header is not valid")
        ino, mode, _uid, _gid, nlink, _mt, size, dmaj, dmin, _rmaj, _rmin, nsize, _chk = v
        if nsize == 0 or nsize > NAME_MAX:
            raise Fail("cpio name length is not valid")
        name = buf.read(nsize)
        if len(name) < nsize:
            raise Fail("the archive ends early")
        buf.skip((-(110 + nsize)) % 4)
        name = name.rstrip(b"\x00").decode("utf-8", "replace")
        if name == "TRAILER!!!":
            return "trailer"
        counters["entries"] += 1
        if counters["entries"] > ENTRIES_MAX:
            raise Fail(f"more than {ENTRIES_MAX} entries")
        on_file(name, mode, nlink, (dmaj, dmin, ino), size, buf)
        buf.skip((-size) % 4)


def safe_name(name):
    n = name
    while n.startswith("./"):
        n = n[2:]
    if n in ("", "."):
        return None
    if n.startswith("/") or any(p == ".." for p in n.split("/")) or "\x00" in n:
        return False
    return n.strip("/") or None


def read_initrd(data):
    """initrd 的位元組 → 結果 dict。壞掉或讀不懂的格式：status NOT_ASSESSED 加 note。"""
    res = {"status": "OK", "note": None, "formats": [], "entries": 0, "files": [], "dirs": 0, "symlinks": 0, "other": 0, "rejected": 0,
           "rejected_examples": [], "elf": 0, "script": 0, "too_large": 0}
    counters = {"entries": 0}
    budget = Budget(OUT_MAX)
    pending = {}                   # (dev, ino) → 還沒有資料的 cpio 硬連結名稱

    def add(name, size, kind, sha):
        res["elf" if kind == "elf" else "script"] += 1
        if len(res["files"]) < FILES_JSON_MAX:
            res["files"].append({"path": name, "kind": kind, "size": size, "sha256": sha})

    def on_file(raw, mode, nlink, key, size, buf):
        ft = mode & S_IFMT
        name = safe_name(raw)
        if name is False:
            res["rejected"] += 1
            if len(res["rejected_examples"]) < 5:
                res["rejected_examples"].append(raw[:120].encode("unicode_escape").decode())
            buf.skip(size)
            return
        if name is None:
            buf.skip(size)
            return
        if ft == S_IFDIR:
            res["dirs"] += 1
            buf.skip(size)
            return
        if ft == S_IFLNK:
            res["symlinks"] += 1
            buf.skip(size)
            return
        if ft != S_IFREG:
            res["other"] += 1
            buf.skip(size)
            return
        if size == 0 and nlink > 1:
            pending.setdefault(key, []).append(name)
            return
        if size < 4:
            buf.skip(size)
            return
        head = buf.read(4)
        kind = "elf" if head == b"\x7fELF" else "script" if head[:2] == b"#!" else None
        if kind is None:
            buf.skip(size - 4)
            pending.pop(key, None)
            return
        if size > HASH_MAX:
            buf.skip(size - 4)
            res["too_large"] += 1
            for n in [name] + pending.pop(key, []):
                if len(res["files"]) < FILES_JSON_MAX:
                    res["files"].append({"path": n, "kind": kind, "size": size, "sha256": None})
                res["elf" if kind == "elf" else "script"] += 1
            return
        h = hashlib.sha256(head)
        left = size - 4
        while left > 0:
            c = buf.read(min(1 << 20, left))
            if not c:
                raise Fail("the archive ends early")
            h.update(c)
            left -= len(c)
        for n in [name] + pending.pop(key, []):
            add(n, size, kind, h.hexdigest())

    pos, segs = 0, 0
    try:
        while pos < len(data):
            while pos < len(data) and data[pos] == 0:
                pos += 1
            if pos >= len(data):
                break
            segs += 1
            if segs > SEGMENTS_MAX:
                raise Fail(f"more than {SEGMENTS_MAX} segments")
            fmt = detect(data, pos)
            if fmt is None:
                raise Fail("unknown data format (not cpio, gzip, xz, bzip2, zstd or lz4)")
            st = {}
            last = False
            if fmt == "cpio":
                buf = Buf(raw_gen(data, pos), budget)
                parse_cpio(buf, on_file, counters)
                pos += buf.total
                res["formats"].append("cpio")
                continue
            if fmt == "gzip":
                gen = zlib_gen(data, pos, st)
            elif fmt in ("xz", "lzma"):
                gen = stream_gen(lambda: lzma.LZMADecompressor(lzma.FORMAT_AUTO), data, pos, st, fmt)
            elif fmt == "bzip2":
                gen = stream_gen(bz2.BZ2Decompressor, data, pos, st, fmt)
            elif fmt == "zstd":
                try:
                    from compression import zstd      # Python 3.14
                    gen = stream_gen(zstd.ZstdDecompressor, data, pos, st, fmt)
                except ImportError:
                    gen, last = zstd_cmd_gen(data, pos), True
            else:      # lz4
                try:
                    out = rkmod().lz4_decompress(bytes(data[pos:]), OUT_MAX)
                except Exception as e:      # noqa: BLE001
                    raise Fail(f"lz4 could not be decompressed ({type(e).__name__})")
                gen, last = iter([bytes(out)]), True
            buf = Buf(gen, budget)
            parse_cpio(buf, on_file, counters)
            res["formats"].append(fmt)
            buf.drain()
            if last or "end" not in st:
                break
            pos = st["end"]
    except Fail as e:
        res["status"], res["note"] = "NOT_ASSESSED", str(e)
    except (zlib.error, lzma.LZMAError, OSError, EOFError, ValueError) as e:
        res["status"], res["note"] = "NOT_ASSESSED", f"decompression failed ({type(e).__name__})"
    res["entries"] = counters["entries"]
    if res["status"] == "OK" and not res["formats"]:
        res["status"], res["note"] = "NOT_ASSESSED", "empty file"
    if res["status"] == "OK" and counters["entries"] == 0:
        res["status"], res["note"] = "NOT_ASSESSED", "no cpio entries found"
    return res


# ---------------------------------------------------------------- 比對與輸出

def classify_files(files, by_sha, owners, versions):
    out = []
    for f in sorted(files, key=lambda x: x["path"]):
        r = dict(f)
        sha = f.get("sha256")
        if sha is None:
            r.update(result="initrd_only", reason="file is larger than the hashing limit: not compared")
        else:
            paths = sorted(by_sha.get(sha) or [])
            owned = [(p, owners.map.get(p)) for p in paths if owners.map.get(p)]
            if owned:
                p, pkg = owned[0]
                r.update(result="package_copy", package=pkg, version=versions.get(pkg), rootfs_path="/" + p)
            elif paths:
                r.update(result="initrd_only", reason="an identical file exists in the root file system but it is not part of a dpkg package"
                         if owners.available else "an identical file exists in the root file system, but there are no dpkg file lists to tell its package",
                         rootfs_path="/" + paths[0])
            else:
                r.update(result="initrd_only", reason="no identical file (sha256) in the root file system")
        out.append(r)
    return out


def build(src, prefix, inventory):
    img, initrds, notes, by_sha, source, st = load_rootfs(src, prefix)
    owners = icmod().Owners(img)
    versions = dpkg_versions(img)
    items = []
    for path in sorted(set(initrds) | set(notes)):
        data = initrds.get(path)
        it = {"path": "/" + path, "size": img.nodes[path][2] if path in img.nodes else None}
        if data is None:
            it.update(status="NOT_ASSESSED", note=notes.get(path) or "not read", formats=[], files=[], elf=0, script=0, entries=0)
        else:
            it["sha256"] = hashlib.sha256(data).hexdigest()
            r = read_initrd(data)
            r["files"] = classify_files(r["files"], by_sha, owners, versions)
            it.update(r)
        c = collections.Counter(f["result"] for f in it["files"])
        it["package_copies"], it["initrd_only"] = c["package_copy"], c["initrd_only"]
        items.append(it)
    aliases = sorted("/" + p for p, n in img.nodes.items() if is_initrd_name(p) and n[0] == "symlink")
    flashing = []
    for x in (inventory or {}).get("bootloader") or []:
        if isinstance(x, dict) and isinstance(x.get("path"), str) and "initrd" in x["path"].rsplit("/", 1)[-1].lower():
            flashing.append({"path": x["path"], "size": x.get("size"), "sha256": x.get("sha256"),
                             "note": "used during flashing only; not part of the running system; not analyzed here"})
    n_only = sum(i["initrd_only"] for i in items)
    n_copy = sum(i["package_copies"] for i in items)
    n_na = sum(1 for i in items if i["status"] != "OK")
    n_elf = sum(i["elf"] for i in items)
    n_scr = sum(i["script"] for i in items)
    if not items:
        status = "INFO"
        detail = "no initrd file in /boot of the root file system: nothing to assess"
    else:
        status = "GAP" if (n_only or n_na) else "OK"
        detail = (f"{len(items)} initrd file(s) in /boot; {n_elf} ELF and {n_scr} script file(s) inside: "
                  f"{n_copy} identical to a dpkg package file (covered through that package), {n_only} initrd-only (not covered)"
                  + (f"; {n_na} initrd file(s) not assessed" if n_na else ""))
    if flashing:
        detail += f"; {len(flashing)} flashing-time initrd listed (not analyzed)"
    doc = {"schema": SCHEMA, "tool_version": TOOL_VERSION, "status": status, "detail": detail, "source": source,
           "initrds": items, "initrd_symlinks": aliases, "flashing_initrds": flashing,
           "summary": {"initrd_files": len(items), "elf": n_elf, "script": n_scr, "package_copies": n_copy, "initrd_only": n_only,
                       "not_assessed": n_na},
           "dpkg_file_lists_available": owners.available,
           "limits": {"rootfs_files_over_hash_limit": st["hash_cap"], "rootfs_notes": dict(sorted(img.cov.items()))},
           "method": ("sha256 of every ELF (\\x7fELF) and script (#!) in the initrd, compared with the same kind of file in the root file system; "
                      "a match counts only when that root file system file belongs to a dpkg package. Read-only; nothing is extracted or executed.")}
    return doc


def markdown(doc):
    s = doc["summary"]
    L = ["## initrd 涵蓋（/boot/initrd*）", "",
         f"- 狀態：{doc['status']}。{doc['detail']}。",
         "- initrd 在每次開機時執行。表中「copy of」＝裡面的檔案與 rootfs 裡某個 dpkg 套件的檔案 sha256 相同，弱點比對由那個套件涵蓋；"
         "「initrd-only」＝找不到相同內容的套件檔案，沒有被任何掃描涵蓋（GAP）。",
         "- 照實列出，不判斷有沒有用、能不能移除。", ""]
    for it in doc["initrds"]:
        L += [f"### {it['path']}", ""]
        if it["status"] != "OK":
            L += [f"- NOT_ASSESSED：{it.get('note')}", ""]
            continue
        L += [f"- 格式：{' + '.join(it['formats'])}；項目 {it['entries']}；ELF {it['elf']}、腳本 {it['script']}；"
              f"套件檔案的複本 {it['package_copies']}、initrd-only {it['initrd_only']}",
              f"- sha256：{it.get('sha256')}"]
        if it["rejected"]:
            L.append(f"- 拒絕的名稱（絕對路徑或含 ..）：{it['rejected']} 個")
        L.append("")
        only = [f for f in it["files"] if f["result"] == "initrd_only"]
        if only:
            L += ["initrd-only（沒有被涵蓋，GAP）：", "", "| 路徑 | 類型 | 大小 | sha256 | 原因 |", "|---|---|---|---|---|"]
            for f in only[:200]:
                L.append(f"| {f['path']} | {f['kind']} | {f['size']} | {(f.get('sha256') or '—')[:16]}… | {f['reason']} |")
            if len(only) > 200:
                L.append(f"| …共 {len(only)} 個（initrd-coverage.json） | | | | |")
            L.append("")
        cp = [f for f in it["files"] if f["result"] == "package_copy"]
        if cp:
            by = collections.Counter((f["package"], f["version"]) for f in cp)
            L += ["套件檔案的複本（依套件）：", "", "| 套件 | 版本 | 檔案數 |", "|---|---|---|"]
            L += [f"| {p} | {v or 'unknown'} | {n} |" for (p, v), n in sorted(by.items(), key=lambda x: (x[0][0], x[0][1] or ""))]
            L.append("")
    if not doc["initrds"]:
        L += ["rootfs 的 /boot 沒有 initrd*：沒有東西要評估（不代表其他開機階段沒有問題）。", ""]
    if doc["flashing_initrds"]:
        L += ["### 只在燒錄時使用的 initrd", ""]
        for x in doc["flashing_initrds"]:
            L.append(f"- {x['path']}（{x.get('size')} bytes，sha256 {str(x.get('sha256'))[:16]}…）：只在燒錄時使用；不是執行中系統的一部分；這裡不分析。")
        L.append("")
    if not doc["dpkg_file_lists_available"]:
        L += ["- 這個 rootfs 沒有 dpkg 檔案清單：沒有任何複本能歸到套件。", ""]
    return "\n".join(L)


def write_atomic(path, text):
    tmp = str(path) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)


def line(st, detail):
    d = detail.replace("\t", " ").replace("\n", " ")
    print(f"B-initrd-coverage\t{st}\t{d[:470]}")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0], allow_abbrev=False)
    ap.add_argument("--version", action="version", version=f"{SCHEMA} {TOOL_VERSION}")
    ap.add_argument("--from", dest="from_", required=True)
    ap.add_argument("--prefix")
    ap.add_argument("--inventory")
    ap.add_argument("--out", required=True)
    try:
        a = ap.parse_args(argv)
    except SystemExit as e:
        return 64 if e.code else 0
    try:
        inv = None
        if a.inventory:
            try:
                with open(a.inventory, encoding="utf-8") as f:
                    inv = json.load(f)
            except (OSError, ValueError):
                inv = None
        doc = build(a.from_, a.prefix, inv if isinstance(inv, dict) else None)
        os.makedirs(a.out, exist_ok=True)
        write_atomic(os.path.join(a.out, "initrd-coverage.json"), json.dumps(doc, ensure_ascii=False, indent=1, sort_keys=True) + "\n")
        write_atomic(os.path.join(a.out, "initrd-coverage.md"), markdown(doc))
        line(doc["status"], doc["detail"])
        return 2 if doc["status"] == "GAP" else 0
    except Fail as e:
        line("FAIL", str(e))
        return 1
    except Exception as e:      # noqa: BLE001
        line("FAIL", f"initrd_coverage.py could not complete ({type(e).__name__}: {str(e)[:100]})")
        return 1


if __name__ == "__main__":
    sys.exit(main())
