"""廠商 Jetson 刷機包（flash package，Linux_for_Tegra 形式的 tbz2，或已經解開的資料夾）→ 清點、選出 rootfs、轉成可以 docker import 的 tar。

用法（scan-flash-package.sh 會依序呼叫；也可以單獨用）。來源是 --archive <tbz2> 或 --dir <解開的資料夾> 其中之一：
  python3 -I flash_package.py md5 --archive <tbz2> --md5 <.md5 檔>            （「雜湊  檔名」、「雜湊 *檔名」、BSD 格式或只有雜湊）
  python3 -I flash_package.py md5 --dir <資料夾> --md5 <逐檔的 md5 清單>       （每一列「雜湊  相對路徑」）
  python3 -I flash_package.py list (--archive A | --dir D) --out <list.json> --inventory <flash-inventory.json> [--version <產品版本>]
        [--deliverables <交付資料夾>]（壓縮檔旁邊的其他交付檔：只記名稱、大小、sha256，不打開）
  python3 -I flash_package.py pick --list <list.json> --rootfs <rootfs_no_gui|rootfs_gui|rootfs|all>
  python3 -I flash_package.py rootfs-tar (--archive A | --dir D) --target <前綴>=<輸出.tar>=<報告.json> [--target …]
        （多個 --target 在同一次讀取裡寫出：壓縮檔只解壓一次）
  python3 -I flash_package.py cra-config --list <list.json> --variant <名稱> --name <產品> --version <版本> --out <config.json> [--manufacturer <名稱>]
  python3 -I flash_package.py summary --out-dir <結果資料夾> --variant <名稱> [--variant …]
  python3 -I flash_package.py format --archive <檔案>             （印 tar、rockchip-img、rockchip-zip、raw-disk-img、raw-disk-img-xz、或 raw-disk-img-gz）
  python3 -I flash_package.py img-extract --archive <.img.xz|.img.gz> --out <disk.img>   （原始磁碟映像：串流解壓到暫存檔；大小上限與剩餘空間檢查）
  Raspberry Pi OS 等原始磁碟映像（MBR／GPT；tools/demo/rpi_img.py）：boot 的 FAT 分割區與 root 的 ext4 分割區都直接讀（不掛載），
  呈現成虛擬 tar：rootfs/…、bootloader/<boot 分割區的檔案>、kernel/<kernel*.img、initramfs*>。壓縮的映像先 img-extract；
  list 的 --container 可給原本壓縮的檔案（list.json 記那個檔案）。list.json／清點檔的分割區資訊在 disk_image。
  python3 -I flash_package.py rk-extract --archive <zip> --out <update.img> [--member <zip 裡的名稱>]
        （Rockchip：zip 裡只複製 update.img 一個成員，其他成員不解開）
  python3 -I flash_package.py rk-status --list <list.json>         （Rockchip 分割區表的狀態：一行「狀態<TAB>說明」）
  Rockchip 的 list 另外可以給 --container <zip>：list.json 記的刷機包是那個 zip（--archive 是從裡面取出的 update.img）。

規則：
- 刷機包是公司的機密產品，也是不可信資料：壓縮檔只用 tarfile 的串流模式讀結構與內容，**不解開到主機的檔案系統**，
  不執行裡面的任何東西。bzip2 而且有 lbzip2／pbzip2 時用它們多執行緒解壓（只解壓，tar 結構仍由這裡讀；FLASHPKG_PARALLEL=0 關閉）。
- 資料夾用 os.scandir＋lstat 走訪，**不跟隨符號連結**；硬連結以 (st_dev, st_ino) 辨識，第二個以後寫成 tar 的硬連結。
  讀不到的檔案與資料夾（例如別的帳號解開的 etc/shadow）不中止，計數並列出。讀取時大小和 lstat 不同的檔案補零或截斷到 lstat 的大小並計數。
  rootfs 以外的資料夾只走到 DIR_MAX_DEPTH 層（原始碼等大型樹不整個走）。
- 串流讀取時清掉 tarfile 累積的成員清單，記憶體不隨成員數增加（每個成員的內容直接從來源複製到輸出，不先存成暫存檔）。
- rootfs：路徑中第一個名稱是 rootfs_no_gui、rootfs_gui 或 rootfs 的資料夾（例如 <top>/Linux_for_Tegra/rootfs_no_gui）。
  同一個名稱出現在兩個不同的位置時不猜，要用 --prefix 指定。
- 轉出的 tar 以 rootfs 為根（./etc/…）：一般檔案、資料夾、符號連結（目標原樣保留，不跟隨）；硬連結改寫到新的路徑
  （目標不在這個 rootfs 或還沒寫出時略過並記錄）；裝置檔、FIFO、socket 略過並計數；權限位元原樣保留（含 setuid），擁有者一律 0（root）。
  成員名稱是絕對路徑或含 `..` 時拒絕並記錄；路徑經過已寫出的符號連結（例如 lib/… 而 lib 是連結）也拒絕。
- 刷機包裡 rootfs 以外的檔案（bootloader/、kernel/、flash.sh、*.conf…）只清點（路徑、大小、雜湊），不掃弱點：
  它們是燒進 QSPI／分割區的東西；cra_report.py 產生產品 SBOM 時把其中的韌體加進去（tools/cra/firmware_bom.py）。
- 清點的檔案記 sha256、sha512 與修改時間（mtime）；rootfs 的 lib/modules/<版本>/updates/ 底下的 kernel 模組（NVIDIA 另外編的
  OOT 模組等）另外記在清點檔的 kernel_modules（路徑、雜湊、modinfo 的 name／version／vermagic…；tools/cra/firmware_bom.py 解析 ELF，
  不執行），給 cra_report.py 併進產品 SBOM。
- Rockchip update.img（開頭是 RKFW；tools/demo/rockchip_img.py）：分割區表＋32 位元溢位修正，名稱是 rootfs 的 ext4 分割區
  直接讀 ext4 的資料結構（不掛載、不用 debugfs、不需要 root），呈現成虛擬的 tar：rootfs/…、bootloader/<分割區>.img、
  config/<package-file|parameter>.txt、kernel/Image（boot 分割區 FIT 裡的核心）。之後的 list、rootfs-tar 與 open_stream 的使用者
  （image_check.py、pkg_why.py、kernel_config.py）照舊。分割區位置無法證明 → list 照樣寫出 list.json（rockchip.status GAP、沒有 rootfs）。
  zip 裡的 update.img 先用 rk-extract 取出（open_stream 不直接讀 zip）。
- L4T 版本：rootfs 的 etc/nv_tegra_release 與 var/lib/dpkg/status 的 nvidia-l4t-core、nvidia-l4t-kernel 版本，三個來源並列；
  不一致時 ATTENTION，都沒有時 GAP。
"""
import argparse
import bz2
import contextlib
import datetime
import errno
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import lzma
import tempfile
import zipfile
import zlib
from pathlib import Path

VARIANTS = ("rootfs_no_gui", "rootfs_gui", "rootfs")
NV_RELEASE = "etc/nv_tegra_release"
DPKG_STATUS = "var/lib/dpkg/status"
OS_RELEASE = ("etc/os-release", "usr/lib/os-release")
SMALL_MAX = 64 << 20          # 讀進記憶體的小檔（dpkg status、nv_tegra_release）上限
LIST_MAX = 200                # 報告裡每種清單最多列幾筆（數量另計）
SPOOL = 64 << 20              # 第二次讀取時，硬連結目標的內容先放記憶體，超過才寫到輸出旁的暫存檔
DIR_MAX_DEPTH = 8             # 資料夾來源：rootfs 以外最多走幾層


class Fail(Exception):
    pass


# ---------- 來源：壓縮檔（tar 串流）或資料夾（scandir＋lstat） ----------

class Entry:
    """來源裡的一個項目。parts：路徑元件（不合法時 None）；kind：file／dir／symlink／hardlink／device／fifo／socket／other／
    unreadable（lstat 失敗）／unreadable_dir（資料夾讀不到內容）；link：符號連結的目標（字串，原樣）或硬連結的目標（路徑元件或 None）。
    key：資料夾來源的一般檔案、st_nlink > 1 時是 (st_dev, st_ino)（硬連結由消費端依自己的範圍判斷）；壓縮檔來源是 None。
    descend：資料夾來源用，消費端設成 False 就不走進這個資料夾。failed：消費端讀不到內容時設成 True。"""
    __slots__ = ("raw", "parts", "kind", "mode", "mtime", "size", "link", "_open", "descend", "failed", "key")

    def __init__(self, raw, parts, kind, mode=0o644, mtime=0, size=0, link=None, opener=None, key=None):
        self.raw, self.parts, self.kind, self.mode, self.mtime, self.size, self.link = raw, parts, kind, mode, mtime, size, link
        self._open, self.descend, self.failed, self.key = opener, True, False, key

    def open(self):
        return self._open()

    @property
    def name(self):
        """路徑元件接成的名稱（壓縮檔裡的位置；不合法時 None）。"""
        return "/".join(self.parts) if self.parts is not None else None


def tar_kind(m):
    if m.isreg():
        return "file"
    if m.isdir():
        return "dir"
    if m.issym():
        return "symlink"
    if m.islnk():
        return "hardlink"
    if m.ischr() or m.isblk():
        return "device"
    if m.isfifo():
        return "fifo"
    return "other"


def decompressor(path):
    """壓縮檔要用的外部解壓程式（bzip2 而且有 lbzip2／pbzip2）或 None（Python 內建）。"""
    with open(path, "rb") as f:
        magic = f.read(3)
    if magic == b"BZh" and os.environ.get("FLASHPKG_PARALLEL", "1") != "0":
        return shutil.which("lbzip2") or shutil.which("pbzip2")
    return None


@contextlib.contextmanager
def open_stream(path):
    """壓縮的 tar → 串流模式的 TarFile。bzip2 在沒有外部程式時用 bz2.open（支援 pbzip2 產生的多段 bzip2）。"""
    path = os.path.abspath(path)          # 以 / 開頭：檔名不會被外部程式當成選項
    fmt = archive_format(path)
    if fmt == "rockchip-zip":
        raise Fail(f"{os.path.basename(path)} 是 zip：先用 flash_package.py rk-extract 取出 update.img（scan-flash-package.sh 會自動做）")
    if fmt == "rockchip-img":
        rk = rkmod()
        try:
            vt = rk.open_virtual(path)
        except rk.RkError as e:
            raise Fail(f"{os.path.basename(path)}：{e}")
        with vt:
            yield vt
        return
    if fmt in ("raw-disk-img-xz", "raw-disk-img-gz"):
        raise Fail(f"{os.path.basename(path)} 是壓縮的磁碟映像：先用 flash_package.py img-extract 解壓（scan-flash-package.sh 會自動做）")
    if fmt == "raw-disk-img":
        rp = rpimod()
        try:
            vt = rp.open_virtual(path)
        except rp.RpiError as e:
            raise Fail(f"{os.path.basename(path)}：{e}")
        with vt:
            yield vt
        return
    tool = decompressor(path)
    if not tool:
        with open(path, "rb") as f:
            bz = f.read(3) == b"BZh"
        if bz:
            with bz2.open(path, "rb") as raw, tarfile.open(fileobj=raw, mode="r|") as t:
                yield t
        else:
            with tarfile.open(path, mode="r|*") as t:
                yield t
        return
    with tempfile.TemporaryFile() as err:
        p = subprocess.Popen([tool, "-d", "-c", path], stdout=subprocess.PIPE, stderr=err)
        ok = False
        try:
            with tarfile.open(fileobj=p.stdout, mode="r|") as t:
                yield t
            while p.stdout.read(1 << 20):   # tar 結尾之後的填充：讀完，解壓程式才不會因為管線關閉而失敗
                pass
            ok = True
        finally:
            if not ok:
                p.kill()
            p.stdout.close()
            rc = p.wait()
        if rc != 0:
            err.seek(0)
            raise Fail(f"{os.path.basename(tool)} 解壓失敗（exit {rc}）：{err.read().decode(errors='replace')[-200:]}")


def members(t):
    """逐一取出成員；處理完一個再取下一個，並清掉 tarfile 累積的清單（記憶體不隨成員數增加）。"""
    while True:
        m = t.next()
        if m is None:
            return
        yield m
        t.members.clear()


def tar_entries(t):
    for m in members(t):
        k = tar_kind(m)
        link = m.linkname if k == "symlink" else split_name(m.linkname) if k == "hardlink" else None
        yield Entry(m.name, split_name(m.name), k, m.mode & 0o7777, m.mtime, m.size if k == "file" else 0, link,
                    (lambda m=m: t.extractfile(m)))


def dir_entries(root):
    """資料夾 → Entry（先序、每層依名稱排序）。不跟隨符號連結；讀不到的資料夾產生 unreadable_dir 項目並略過內容。
    硬連結不在這裡判斷：一般檔案帶 key（st_nlink > 1 時），由消費端在自己的範圍（每個 rootfs）裡決定寫成硬連結或檔案。"""
    root = os.path.abspath(root)
    try:
        top = sorted(os.scandir(root), key=lambda d: d.name)
    except OSError as e:
        raise Fail(f"讀不到資料夾 {root}：{e.strerror}")
    stack = [((), iter(top))]
    while stack:
        base, it = stack[-1]
        de = next(it, None)
        if de is None:
            stack.pop()
            continue
        parts = base + (de.name,)
        full = de.path
        try:
            st = os.lstat(full)
        except OSError:
            yield Entry(full, parts, "unreadable")
            continue
        mode, mtime = stat.S_IMODE(st.st_mode), int(st.st_mtime)
        if stat.S_ISDIR(st.st_mode):
            e = Entry(full, parts, "dir", mode, mtime)
            yield e
            if not e.descend:
                continue
            try:
                children = sorted(os.scandir(full), key=lambda d: d.name)
            except OSError:
                yield Entry(full, parts, "unreadable_dir", mode, mtime)
                continue
            stack.append((parts, iter(children)))
        elif stat.S_ISLNK(st.st_mode):
            try:
                target = os.readlink(full)
            except OSError:
                yield Entry(full, parts, "unreadable")
                continue
            yield Entry(full, parts, "symlink", mode, mtime, 0, target)
        elif stat.S_ISREG(st.st_mode):
            yield Entry(full, parts, "file", mode, mtime, st.st_size, None, (lambda p=full: open_nofollow(p)),
                        (st.st_dev, st.st_ino) if st.st_nlink > 1 else None)
        elif stat.S_ISCHR(st.st_mode) or stat.S_ISBLK(st.st_mode):
            yield Entry(full, parts, "device", mode, mtime)
        elif stat.S_ISFIFO(st.st_mode):
            yield Entry(full, parts, "fifo", mode, mtime)
        elif stat.S_ISSOCK(st.st_mode):
            yield Entry(full, parts, "socket", mode, mtime)
        else:
            yield Entry(full, parts, "other", mode, mtime)


def open_nofollow(path):
    """只打開一般檔案：O_NOFOLLOW（最後一層是符號連結就失敗）、O_NONBLOCK（FIFO 不會卡住），再以 fstat 確認。"""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "不是一般檔案", path)
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def resolve_alias(alias, name, limit=64):
    """硬連結的名稱 → 最後指到的一般檔案名稱（壓縮檔裡的硬連結可以連到另一個硬連結）。"""
    seen = 0
    while name in alias and seen < limit:
        name, seen = alias[name], seen + 1
    return name


def fetch_members(archive, wanted, callback):
    """第二次讀取壓縮檔：wanted 裡的成員（一般檔案）交給 callback(名稱, Entry)。只在第一次讀取無法取得硬連結的內容時使用。"""
    left = set(wanted)
    with open_stream(archive) as t:
        for e in tar_entries(t):
            n = e.name
            if n in left and e.kind == "file":
                callback(n, e)
                left.discard(n)
                if not left:
                    break
        # 沒讀完就離開：open_stream 會停掉解壓程式
    return left


@contextlib.contextmanager
def open_source(archive=None, directory=None):
    """--archive 或 --dir → (Entry 的產生器, 來源說明)。"""
    if directory:
        if not os.path.isdir(directory):
            raise Fail(f"不是資料夾：{directory}")
        yield dir_entries(directory), {"type": "dir", "path": os.path.abspath(directory), "reader": "os.scandir（lstat，不跟隨符號連結）"}
        return
    if archive_format(os.path.abspath(archive)) == "rockchip-img":
        # 分割區位置無法證明或沒有 ext4 的 rootfs：不丟例外，給空的清單與原因（list 照樣寫出分割區表；rootfs-tar 用原因失敗）
        rk = rkmod()
        stats = rk.new_stats()
        src = {"type": "archive", "file": os.path.basename(archive), "bytes": os.path.getsize(archive),
               "reader": "rockchip_img.py（RKFW／RKAF 分割區表、ext4 唯讀解析）", "format": "rockchip-update-img", "ext4": stats}
        try:
            vt = rk.open_virtual(archive, stats)
        except rk.RkError as e:
            src["unusable"] = str(e)
            yield iter(()), src
            return
        with vt:
            yield tar_entries(vt), src
        return
    if archive_format(os.path.abspath(archive)) == "raw-disk-img":
        rp = rpimod()
        stats = rp.new_stats()
        src = {"type": "archive", "file": os.path.basename(archive), "bytes": os.path.getsize(archive),
               "reader": "rpi_img.py（MBR／GPT 分割區表、FAT、ext4 唯讀解析）", "format": "raw-disk-img", "ext4": stats}
        try:
            vt = rp.open_virtual(archive, stats)
        except rp.RpiError as e:
            src["unusable"] = str(e)
            yield iter(()), src
            return
        with vt:
            src["fat"] = vt.fat_stats
            yield tar_entries(vt), src
        return
    tool = decompressor(os.path.abspath(archive))
    with open_stream(archive) as t:
        yield tar_entries(t), {"type": "archive", "file": os.path.basename(archive), "bytes": os.path.getsize(archive),
                               "reader": os.path.basename(tool) if tool else "Python bz2（單執行緒）"}


class Sized(io.RawIOBase):
    """讀滿 size 個位元組：來源比較短補零、比較長截斷（資料夾來源在讀取中被改動時，tar 仍然正確）。changed：有沒有補或截。"""

    def __init__(self, f, size):
        self.f, self.left, self.changed = f, size, False

    def readable(self):
        return True

    def readinto(self, b):
        if self.left <= 0:
            return 0
        n = min(len(b), self.left)
        data = self.f.read(n)
        if not data:
            self.changed = True
            data = b"\0" * n
        b[:len(data)] = data
        self.left -= len(data)
        if self.left == 0 and self.f.read(1):
            self.changed = True
        return len(data)


def split_name(name):
    """tar 成員名稱 → 路徑元件（去掉 ./ 與空的元件）；絕對路徑或含 .. → None。"""
    if name.startswith("/"):
        return None
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        return None
    return tuple(parts)


CTL_RE = re.compile(r"[\x00-\x1f\x7f]")


def check_prefix(prefix):
    """rootfs 前綴含控制字元（TAB、換行、任何 < 0x20 或 DEL）→ Fail。
    前綴會被腳本當成以 TAB 分隔的欄位與路徑使用，含 TAB／換行的成員名稱可以讓後面的欄位錯位，所以一律拒絕，不嘗試跳脫。"""
    if CTL_RE.search(prefix):
        raise Fail(f"rootfs 前綴含控制字元（TAB、換行等），拒絕處理：{prefix!r}")
    return prefix


def find_variant(parts):
    """路徑元件 → (rootfs 名稱, 前綴元件數) 或 None。取第一個符合的元件。"""
    for i, p in enumerate(parts):
        if p in VARIANTS:
            return p, i + 1
    return None


def sha256_stream(f):
    h = hashlib.sha256()
    n = 0
    for b in iter(lambda: f.read(1 << 20), b""):
        h.update(b)
        n += len(b)
    return h.hexdigest(), n


def hash_stream(f, limit=None):
    """→ (sha256, sha512, 位元組數, 內容或 None)。limit：讀到的內容不超過這個大小時一起回傳（給模組解析用）。"""
    h2, h5, n, keep = hashlib.sha256(), hashlib.sha512(), 0, [] if limit else None
    for b in iter(lambda: f.read(1 << 20), b""):
        h2.update(b)
        h5.update(b)
        n += len(b)
        if keep is not None:
            if n > limit:
                keep = None
            else:
                keep.append(b)
    return h2.hexdigest(), h5.hexdigest(), n, (b"".join(keep) if keep is not None else None)


_FW = None
_RK = None


def rkmod():
    """tools/demo/rockchip_img.py（Rockchip update.img 的解析；python3 -I 不把這個資料夾放進 sys.path，依路徑載入）。"""
    global _RK
    if _RK is None:
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rockchip_img.py")
        spec = importlib.util.spec_from_file_location("sca_center_rockchip_img", p)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        _RK = m
    return _RK


_RPI = None


def rpimod():
    """tools/demo/rpi_img.py（原始磁碟映像：MBR／GPT、FAT、ext4；python3 -I 不把這個資料夾放進 sys.path，依路徑載入）。"""
    global _RPI
    if _RPI is None:
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rpi_img.py")
        spec = importlib.util.spec_from_file_location("sca_center_rpi_img", p)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        _RPI = m
    return _RPI


def is_disk_format(fmt):
    return fmt in ("raw-disk-img", "raw-disk-img-xz", "raw-disk-img-gz")


def archive_format(path):
    """--archive 的格式。偵測順序（各格式互不搶輸入）：RKFW → rockchip-img；zip → rockchip-zip；
    bzip2 → tar；其他試 raw-disk-img（MBR／GPT 的磁碟映像，
    .xz／.gz 壓縮的是 raw-disk-img-xz／-gz）；都不是 → tar（Jetson 的 tbz2 等，照舊）。"""
    with open(path, "rb") as f:
        head = f.read(6)
    if head[:4] == b"RKFW":
        return "rockchip-img"
    if head[:4] == b"PK\x03\x04":
        return "rockchip-zip"
    if head[:3] == b"BZh":
        return "tar"
    return rpimod().detect(path) or "tar"


def fwmod():
    """tools/cra/firmware_bom.py（kernel 模組的 modinfo 解析；python3 -I 不把這個資料夾放進 sys.path，依路徑載入）。"""
    global _FW
    if _FW is None:
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "cra", "firmware_bom.py")
        spec = importlib.util.spec_from_file_location("sca_center_firmware_bom", p)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        _FW = m
    return _FW


def sha256_file(path):
    with open(path, "rb") as f:
        return sha256_stream(f)[0]


def md5_file(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


PROV_SCHEMA = "sca-center-flash-provenance/1"


def md5_sha256_file(path):
    """一次讀完：→ (md5, sha256, 位元組數)。刷機包有好幾 GB，md5 核對與 sha256 不分兩次讀。"""
    m, h, n = hashlib.md5(), hashlib.sha256(), 0
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            m.update(b)
            h.update(b)
            n += len(b)
    return m.hexdigest(), h.hexdigest(), n


def tool_commit(root):
    """掃描時的 sca-center commit：git 工作目錄用 rev-parse（有未提交的改動時 dirty=True）；常駐環境的部署資料夾是 app-<commit>
    （sca-persist/current → app-<commit>）。都不是時 unknown，不猜。"""
    root = Path(root)
    try:
        if (root / ".git").exists():
            r = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=10)
            if r.returncode == 0 and re.fullmatch(r"[0-9a-f]{40}", r.stdout.strip()):
                try:      # 改動狀態查不到（逾時等）時 commit 照樣記，dirty 是 None（不明）
                    d = subprocess.run(["git", "--no-optional-locks", "-C", str(root), "status", "--porcelain", "--untracked-files=normal"],
                                       capture_output=True, text=True, timeout=30)
                    dirty = bool(d.stdout.strip()) if d.returncode == 0 else None
                except (OSError, subprocess.SubprocessError):
                    dirty = None
                return {"commit": r.stdout.strip(), "from": "git", "dirty": dirty}
    except (OSError, subprocess.SubprocessError):
        pass
    m = re.fullmatch(r"app-([0-9a-f]{40})", root.resolve().name)
    if m:
        return {"commit": m.group(1), "from": "deploy-dir", "dirty": None}
    env = os.environ.get("SCA_CENTER_COMMIT", "")
    if re.fullmatch(r"[0-9a-f]{40}", env):      # CRA 掃描精靈跑的是 origin/main 的 git archive（沒有 .git）：它告知自己取的 commit；工作樹是 archive 的原樣，所以 dirty=False
        return {"commit": env, "from": "wizard-archive", "dirty": False}
    return {"commit": "unknown", "from": "unknown", "dirty": None}


def provenance(root, out, archive=None, srcdir=None, previous=None, now=None):
    """<結果>/provenance.json：這次掃描用的 sca-center commit 與刷機包的身分（--archive：檔名、大小、md5、sha256；--dir：只有資料夾名稱）。
    previous：上一次的 provenance.json（--rescan-from）。有 --archive 時重算並和上一次的 sha256 比對（不同 → FAIL）；
    沒給 --archive／--dir 時沿用上一次的刷機包身分（carried_from 寫上一次的資料夾名稱）。→ (狀態, 說明, dict)。"""
    prev = None
    if previous and os.path.isfile(previous):
        try:
            with open(previous, encoding="utf-8") as f:
                prev = json.load(f)
        except (OSError, ValueError):
            prev = None
        if not (isinstance(prev, dict) and prev.get("schema") == PROV_SCHEMA):
            prev = None
    psrc = prev.get("source") if isinstance(prev, dict) and isinstance(prev.get("source"), dict) else None
    st, msgs, carried = "OK", [], None
    if archive:
        md5, sha, n = md5_sha256_file(archive)
        src = {"type": "archive", "file": os.path.basename(archive), "bytes": n, "md5": md5, "sha256": sha}
        msgs.append(f"{src['file']} {n} bytes；md5 {md5}；sha256 {sha}")
        if psrc and psrc.get("type") == "archive" and isinstance(psrc.get("sha256"), str):
            if psrc["sha256"] != sha:
                st = "FAIL"
                msgs.append(f"和上一次的 sha256 {psrc['sha256']} 不同：不是同一個刷機包")
            else:
                msgs.append("和上一次的 sha256 相同")
    elif srcdir:
        src = {"type": "dir", "file": os.path.basename(os.path.normpath(srcdir)), "bytes": None, "md5": None, "sha256": None}
        msgs.append(f"--dir {src['file']}：資料夾沒有單一的雜湊（逐檔的 md5 見 A-md5）")
    elif psrc:
        src, carried = dict(psrc), os.path.basename(os.path.dirname(os.path.abspath(previous)))
        msgs.append(f"沿用上一次（{carried}）的刷機包身分：{src.get('file')} sha256 {src.get('sha256') or '—'}（這次沒有重算）")
    else:
        src = None
        msgs.append("沒有刷機包身分（沒給 --archive／--dir，上一次也沒有 provenance.json）")
        st = "ATTENTION"
    tc = tool_commit(root)
    if tc["commit"] == "unknown":
        st = "ATTENTION" if st == "OK" else st
        msgs.append("sca-center commit 不明（不是 git 工作目錄，也不是部署的 app-<commit>）")
    else:
        msgs.append(f"sca-center {tc['commit'][:12]}（{tc['from']}{'，有未提交的改動' if tc['dirty'] else '，改動狀態不明' if tc['from'] == 'git' and tc['dirty'] is None else ''}）")
        if tc["dirty"] or (tc["from"] == "git" and tc["dirty"] is None):
            st = "ATTENTION" if st == "OK" else st
    doc = {"schema": PROV_SCHEMA, "generated_utc": now or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "sca_center": tc, "source": src, "carried_from": carried}
    tmp = f"{out}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
        f.write("\n")
    os.replace(tmp, out)
    return st, "；".join(msgs), doc


MD5_LINE = re.compile(r"^\s*(?:MD5\s*\((?P<n2>.+)\)\s*=\s*)?(?P<h>[0-9a-fA-F]{32})(?:(?P<sep>\s+\*?)(?P<n>.*))?\s*$")


def parse_md5_lines(text):
    """.md5 檔 → [(雜湊, 檔名或 None, 格式)]。格式：md5sum-text（「雜湊  檔名」）、md5sum-binary（「雜湊 *檔名」）、
    bsd（「MD5 (檔名) = 雜湊」）、hash-only（只有雜湊）。"""
    out = []
    for line in text.splitlines():
        m = MD5_LINE.match(line)
        if not m:
            continue
        if m.group("n2"):
            name, fmt = m.group("n2").strip(), "bsd"
        else:
            name = (m.group("n") or "").strip() or None
            fmt = "hash-only" if not name else "md5sum-binary" if "*" in (m.group("sep") or "") else "md5sum-text"
        out.append((m.group("h").lower(), name, fmt))
    return out


def parse_md5_file(text, archive_name=None):
    """單一檔案的 .md5 → (雜湊, 檔名或 None, 格式)；多列時取檔名和 archive_name 相同的一列（沒有就取第一列）。
    沒有雜湊 → (None, None, None)。"""
    r = parse_md5_lines(text)
    if archive_name:
        for x in r:
            if x[1] and os.path.basename(x[1].lstrip("*")) == archive_name:
                return x
    return r[0] if r else (None, None, None)


# ---------- 版本 ----------

def dpkg_paragraphs(text):
    for para in re.split(r"\n\s*\n", text):
        d = {}
        for line in para.splitlines():
            if line[:1] in (" ", "\t") or ":" not in line:
                continue
            k, _, v = line.partition(":")
            d[k.strip()] = v.strip()
        if d.get("Package"):
            yield d


def dpkg_summary(text):
    installed, wanted = 0, {}
    for d in dpkg_paragraphs(text):
        st = d.get("Status", "").split()
        if len(st) == 3 and st[2] == "installed":
            installed += 1
            if d["Package"] in ("nvidia-l4t-core", "nvidia-l4t-kernel"):
                wanted[d["Package"]] = d.get("Version", "")
    return {"installed_packages": installed, "nvidia-l4t-core": wanted.get("nvidia-l4t-core"),
            "nvidia-l4t-kernel": wanted.get("nvidia-l4t-kernel")}


def l4t_from_nv_release(text):
    """'# R39 (release), REVISION: 2.1, …' → '39.2.1'。"""
    m = re.search(r"#\s*R(\d+)\s*\(release\),\s*REVISION:\s*(\d+(?:\.\d+)*)", text or "")
    return f"{m.group(1)}.{m.group(2)}" if m else None


def l4t_from_core(ver):
    m = re.match(r"^(?:\d+:)?(\d+\.\d+(?:\.\d+)*)-", ver or "")
    return m.group(1) if m else None


def l4t_from_kernel(ver):
    m = re.search(r"-tegra-(\d+\.\d+(?:\.\d+)*)-", ver or "")
    return m.group(1) if m else None


def l4t_release(nv_text, dpkg):
    """回傳 {release, status, detail, sources}。三個來源並列，不互相覆蓋。"""
    src = {"nv_tegra_release": l4t_from_nv_release(nv_text),
           "nvidia-l4t-core": l4t_from_core((dpkg or {}).get("nvidia-l4t-core")),
           "nvidia-l4t-kernel": l4t_from_kernel((dpkg or {}).get("nvidia-l4t-kernel"))}
    vals = sorted({v for v in src.values() if v})
    found = "、".join(f"{k} {v}" for k, v in src.items() if v) or "無"
    if not vals:
        return {"release": None, "status": "GAP", "detail": "rootfs 沒有 nv_tegra_release，dpkg 也沒有 nvidia-l4t-core／kernel：無法判斷 L4T 版本",
                "sources": src}
    if len(vals) > 1:
        return {"release": None, "status": "ATTENTION", "detail": f"來源不一致：{found}", "sources": src}
    missing = [k for k, v in src.items() if not v]
    return {"release": vals[0], "status": "OK", "detail": f"L4T {vals[0]}（{found}" + (f"；沒有 {'、'.join(missing)}" if missing else "") + "）",
            "sources": src}


def version_note(product_version, release):
    """產品版本（例如 V39.2.0.1）與 L4T 版本的關係，一句話。"""
    if not product_version or not release:
        return None
    pv = re.sub(r"^[vV]", "", product_version)
    if pv == release or pv.startswith(release + "."):
        return f"產品版本 {product_version} 以 L4T 版本 {release} 開頭"
    return f"注意：產品版本 {product_version} 不是以實際的 L4T 版本 {release} 開頭（以 rootfs 內的版本為準）"


# ---------- list ----------

COUNT_KEY = {"file": "files", "dir": "dirs", "symlink": "symlinks", "hardlink": "hardlinks", "device": "devices", "fifo": "fifos",
             "socket": "sockets", "unreadable": "unreadable", "unreadable_dir": "unreadable_dirs"}


def new_cand(variant, prefix):
    return {"variant": variant, "prefix": prefix, "files": 0, "dirs": 0, "symlinks": 0, "hardlinks": 0, "devices": 0, "fifos": 0,
            "sockets": 0, "other": 0, "unreadable": 0, "unreadable_dirs": 0, "bytes": 0, "hardlinks_outside": 0,
            "nv_tegra_release": None, "dpkg": None, "os_release": None, "notes": []}


def os_pretty(text):
    m = re.search(r'^PRETTY_NAME="?([^"\n]*)"?', text or "", re.M)
    return m.group(1) if m else None


def read_small(e):
    """小檔的內容（文字）；讀不到 → None（e.failed 設成 True）。"""
    try:
        with contextlib.closing(e.open()) as f:
            return f.read(SMALL_MAX).decode("utf-8", "replace")
    except OSError:
        e.failed = True
        return None


def deliverables(folder, exclude=()):
    """交付資料夾最上層的其他檔案（MCU 韌體、版本說明…）：名稱、大小、sha256。不解壓、不解析；只對一般檔案計算
    sha256（O_NOFOLLOW、O_NONBLOCK 打開，fstat 確認），資料夾只記名稱，不走進去。"""
    out = []
    try:
        des = sorted(os.scandir(folder), key=lambda d: d.name)
    except OSError as e:
        return [{"error": f"讀不到 {folder}：{e.strerror}"}]
    ex = {os.path.abspath(x) for x in exclude if x}
    for de in des:
        if os.path.abspath(de.path) in ex:
            continue
        try:
            st = os.lstat(de.path)
        except OSError:
            out.append({"name": de.name, "type": "unreadable"})
            continue
        if stat.S_ISREG(st.st_mode):
            e = {"name": de.name, "type": "file", "size": st.st_size, "mtime": int(st.st_mtime)}
            try:
                with open_nofollow(de.path) as f:
                    e["sha256"], e["sha512"], e["size"], _ = hash_stream(f)
            except OSError as err:
                e["error"] = err.strerror or str(err)
            out.append(e)
        elif stat.S_ISDIR(st.st_mode):
            out.append({"name": de.name, "type": "dir", "note": "not inventoried"})
        elif stat.S_ISLNK(st.st_mode):
            out.append({"name": de.name, "type": "symlink", "target": os.readlink(de.path)})
        else:
            out.append({"name": de.name, "type": "other"})
    return out


def module_content(e, item, fw):
    """模組的內容 → 雜湊、修改時間、modinfo 寫進 item。"""
    item["size"], item["mtime"] = e.size, int(e.mtime or 0)
    try:
        with contextlib.closing(e.open()) as f:
            item["sha256"], item["sha512"], _, data = hash_stream(f, fw.MOD_MAX)
    except OSError as err:
        e.failed = True
        item["error"] = err.strerror or "讀不到"
        return item
    item.update(fw.module_info(data, item["path"]) if data is not None else {"modinfo": None, "modinfo_note": "module larger than the limit"})
    return item


def module_item(e, k, rel, fw, first=None):
    """rootfs 裡的一個 kernel 模組 → 清點紀錄（一般檔案：雜湊、修改時間、modinfo；符號連結只記目標）。
    硬連結：資料夾來源直接讀內容（first：同 inode 第一次出現的路徑）；壓縮檔來源先記目標，目標在 updates/ 以外時由呼叫端第二次讀取補內容。"""
    item = {"path": rel, "type": k, "mode": oct(e.mode)}
    if k == "symlink":
        item["target"] = e.link
    elif k == "hardlink" and e.key is not None:
        item["target"] = first
        module_content(e, item, fw)
    elif k == "hardlink":
        item["target"] = "/".join(e.link) if e.link else None
    elif k == "file":
        module_content(e, item, fw)
    return item


def apply_small(c, rel, text):
    if rel == NV_RELEASE:
        c["nv_tegra_release"] = text.splitlines()[0][:300] if text else ""
    elif rel == DPKG_STATUS:
        c["dpkg"] = dpkg_summary(text)
    elif not c["os_release"] or rel == "etc/os-release":
        c["os_release"] = os_pretty(text)


def do_list(out, inventory, archive=None, directory=None, product_version=None, deliverables_dir=None, container=None):
    rkimg = None
    if archive and archive_format(os.path.abspath(archive)) == "rockchip-img":
        rk = rkmod()
        try:
            rkimg = rk.RkImage(archive)      # 結構錯誤（不是 RKAF、截斷）→ Fail；位置無法證明 → status GAP，照樣寫出
        except rk.RkError as e:
            raise Fail(f"{os.path.basename(archive)}：{e}")
    elif archive and archive_format(os.path.abspath(archive)) == "raw-disk-img":
        rp = rpimod()
        try:
            rkimg = rp.RpiImage(archive)      # 分割區表壞掉 → Fail；沒有可用的 rootfs → disk_image.status GAP，照樣寫出
        except rp.RpiError as e:
            raise Fail(f"{os.path.basename(archive)}：{e}")
    elif container:
        raise Fail("--container 只用於 Rockchip update.img 的 zip 或壓縮的磁碟映像")
    try:
        return _do_list(out, inventory, archive, directory, product_version, deliverables_dir, container, rkimg)
    finally:
        if rkimg is not None:
            rkimg.close()


def _do_list(out, inventory, archive, directory, product_version, deliverables_dir, container, rkimg):
    cands, inv, rejected, unreadable = {}, [], [], []
    top = {}
    n_members = depth_limited = 0
    alias, small, pending = {}, {}, {}      # 硬連結 → 目標；讀過的小檔（全名 → 文字）；要第二次讀取的小檔（全名 → [(前綴, rel)]）
    inodes = {}                             # 資料夾來源：(前綴, key) 已出現過 → 之後同 inode 的算硬連結
    mods = {}                               # rootfs 前綴 → lib/modules/*/updates/ 的 kernel 模組
    mod_links = {}                          # 硬連結到 updates/ 以外的模組：目標全名 → [清點紀錄]
    fw = fwmod()
    with open_source(archive, directory) as (entries, source):
        for e in entries:
            n_members += 1
            parts = e.parts
            if parts is None:
                rejected.append(e.raw)
                continue
            if not parts:
                continue
            k = e.kind
            if k == "hardlink" and e.link:
                alias[e.name] = "/".join(e.link)
            fv = find_variant(parts)
            if fv:
                variant, n = fv
                prefix = check_prefix("/".join(parts[:n]))
                c = cands.setdefault(prefix, new_cand(variant, prefix))
                rel = "/".join(parts[n:])
                if not rel:
                    if k == "unreadable_dir":
                        c["unreadable_dirs"] += 1
                    continue
                if k == "file" and e.key is not None:
                    if (prefix, e.key) in inodes:
                        k = "hardlink"           # 資料夾來源：同一個 rootfs 裡同 inode 的第二個以後
                    inodes.setdefault((prefix, e.key), rel)
                c[COUNT_KEY.get(k, "other")] += 1
                if k == "file":
                    c["bytes"] += e.size
                if fw.is_module_path(rel):
                    it = module_item(e, k, rel, fw, inodes.get((prefix, e.key)) if e.key is not None else None)
                    mods.setdefault(prefix, []).append(it)
                    if k == "hardlink" and e.key is None and e.link and not fw.is_module_path("/".join(e.link[n:])):
                        # 壓縮檔的硬連結指向 updates/ 以外：內容在別的成員，第二次讀取時補雜湊與 modinfo
                        mod_links.setdefault(resolve_alias(alias, "/".join(e.link)), []).append(it)
                if k == "hardlink" and e.link is not None and tuple(e.link[:n]) != parts[:n]:
                    c["hardlinks_outside"] += 1   # 壓縮檔：硬連結指向這個 rootfs 以外（轉 tar 時改寫成一般檔案）
                if rel in (NV_RELEASE, DPKG_STATUS) + OS_RELEASE:
                    if k == "file" and e.size <= SMALL_MAX:
                        text = read_small(e)
                        if text is None:
                            c["notes"].append(f"{rel} 讀不到（權限）")
                        else:
                            small[e.name] = text
                            apply_small(c, rel, text)
                    elif k == "hardlink" and e.key is not None:     # 資料夾來源的硬連結：內容就在這個檔案
                        text = read_small(e)
                        if text is not None:
                            apply_small(c, rel, text)
                    elif k == "hardlink" and e.link:
                        final = resolve_alias(alias, "/".join(e.link))
                        if final in small:
                            apply_small(c, rel, small[final])
                        else:
                            pending.setdefault(final, []).append((prefix, rel))
                        c["notes"].append(f"{rel} 是硬連結 → {'/'.join(e.link)}（讀目標的內容）")
                    elif k == "symlink":
                        c["notes"].append(f"{rel} 是符號連結 → {e.link}（不跟隨）")
                    else:
                        c["notes"].append(f"{rel} 不是一般檔案（{k}）或太大，沒有讀")
                continue
            # rootfs 以外：清點（刷機用的部分不掃弱點；韌體由 cra_report.py 加進產品 SBOM）
            path = "/".join(parts)
            if k == "dir":
                if len(parts) >= DIR_MAX_DEPTH and not any(p in VARIANTS for p in parts):
                    e.descend = False          # 資料夾來源：rootfs 以外太深的不走（原始碼等）
                    depth_limited += 1
                continue
            if k in ("unreadable", "unreadable_dir"):
                unreadable.append(path)
                continue
            tk = "/".join(parts[:2]) if len(parts) > 2 else "/".join(parts[:-1]) or "."
            s = top.setdefault(tk, {"files": 0, "bytes": 0})
            item = {"path": path, "type": k, "mode": oct(e.mode)}
            if k == "file":
                item["size"], item["mtime"] = e.size, int(e.mtime or 0)
                try:
                    with contextlib.closing(e.open()) as f:
                        item["sha256"], item["sha512"], _, _ = hash_stream(f)
                except OSError as err:
                    e.failed = True
                    item["error"] = err.strerror or "讀不到"
                    unreadable.append(path)
                s["files"] += 1
                s["bytes"] += e.size
            elif k == "symlink":
                item["target"] = e.link
            elif k == "hardlink":
                item["target"] = "/".join(e.link) if e.link else None
            inv.append(item)
    if pending and archive:
        # 硬連結的目標不是已經讀過的小檔（例如指向別的檔名）：再讀一次壓縮檔，只取這些成員
        def got(name, e):
            if e.size <= SMALL_MAX:
                text = read_small(e)
                if text is not None:
                    for prefix, rel in pending[name]:
                        apply_small(cands[prefix], rel, text)
        for name in fetch_members(archive, list(pending), got):
            for prefix, rel in pending[name]:
                cands[prefix]["notes"].append(f"{rel} 是硬連結，目標 {name} 不在壓縮檔裡（或不是一般檔案）：沒有讀到內容")
    if mod_links and archive:
        def got_mod(name, e):
            for it in mod_links[name]:
                module_content(e, it, fw)
        for name in fetch_members(archive, list(mod_links), got_mod):
            for it in mod_links[name]:
                it["error"] = f"硬連結的目標 {name} 不在壓縮檔裡（或不是一般檔案）"
    by_variant = {}
    for c in cands.values():
        if rkimg is not None:
            # Rockchip：rootfs 就是名稱是 rootfs 的分割區（不是用內容猜的）；沒有 L4T。磁碟映像：ext4 root 分割區，同樣沒有 L4T
            c["l4t"] = {"release": None, "status": "INFO", "sources": {}, "note": None,
                        "detail": ("原始磁碟映像" if is_disk_image(rkimg) else "Rockchip update.img") + "：不是 NVIDIA Jetson，沒有 L4T 版本"}
            c["looks_like_rootfs"] = True
            continue
        c["l4t"] = l4t_release(c["nv_tegra_release"] or "", c["dpkg"])
        c["l4t"]["note"] = version_note(product_version, c["l4t"]["release"])
        c["looks_like_rootfs"] = bool(c["dpkg"] or c["nv_tegra_release"])
        if not c["looks_like_rootfs"]:
            c["not_rootfs_reason"] = (f"沒有 {DPKG_STATUS} 也沒有 {NV_RELEASE}（{c['files']} 個檔案）"
                                      + (f"；{'；'.join(c['notes'][:3])}" if c["notes"] else ""))
        by_variant.setdefault(c["variant"], []).append(c["prefix"])
    boot = [x for x in inv if "bootloader" in x["path"].split("/")[:-1]]
    flash_sh = [x["path"] for x in inv if x["path"].split("/")[-1] == "flash.sh"]
    roots = sorted({p.rsplit("/", 1)[0] if "/" in p else "" for p in flash_sh})
    confs = [x["path"] for x in inv if x["path"].endswith(".conf") and (x["path"].rsplit("/", 1)[0] if "/" in x["path"] else "") in roots]
    others = None
    if deliverables_dir:
        a = container or archive
        excl = [a] + ([a + ".md5"] if a else [])
        others = deliverables(deliverables_dir, excl)
    rkinfo = diskimg = None
    if rkimg is not None and is_disk_image(rkimg):
        diskimg = disk_image_info(rkimg, source, container, cands, inv)
    elif rkimg is not None:
        rkinfo = rockchip_info(rkimg, source, container, cands)
    result = {
        "source": source, "archive": {"file": source.get("file") or os.path.basename(source.get("path", "")), "bytes": source.get("bytes")},
        "members": n_members, "rejected_members_count": len(rejected), "rejected_members": rejected[:LIST_MAX],
        "rootfs": sorted(cands.values(), key=lambda c: c["prefix"]),
        "ambiguous": {v: p for v, p in by_variant.items() if len(p) > 1},
        "flash_package": {"flash_sh": flash_sh, "board_configs": confs, "bootloader_files": len(boot),
                          "bootloader_bytes": sum(x.get("size", 0) for x in boot), "outside_rootfs_files": len(inv),
                          "outside_rootfs_unreadable": len(unreadable), "outside_rootfs_unreadable_examples": unreadable[:LIST_MAX],
                          "outside_rootfs_dirs_not_walked": depth_limited,
                          "outside_rootfs_by_dir": dict(sorted(top.items())),
                          "kernel_modules": {p: len(v) for p, v in sorted(mods.items())}},
        "other_deliverables": others,
        "inventory_file": os.path.basename(inventory),
    }
    if rkinfo is not None:
        result["rockchip"] = rkinfo
        if container:
            result["archive"] = {"file": rkinfo["container"]["file"], "bytes": rkinfo["container"]["bytes"]}
    if diskimg is not None:
        result["disk_image"] = diskimg
        if container:
            result["archive"] = {"file": diskimg["container"]["file"], "bytes": diskimg["container"]["bytes"]}
    with open(inventory, "w", encoding="utf-8") as f:
        json.dump({"source": source, "note": "刷機包裡 rootfs 以外的檔案（bootloader/、kernel/、flash.sh、*.conf…）。沒有掃弱點；"
                   "cra_report.py 把其中的韌體加進產品 SBOM（firmware_bom.py）。", "bootloader": boot, "outside_rootfs": inv,
                   "kernel_modules": {p: sorted(v, key=lambda x: x["path"]) for p, v in sorted(mods.items())},
                   "kernel_modules_note": "rootfs 的 lib/modules/<版本>/updates/ 底下的 kernel 模組（鍵是 rootfs 在刷機包裡的位置）："
                                          "雜湊與 modinfo（name、version、vermagic…）。",
                   "other_deliverables": others,
                   "other_deliverables_note": "壓縮檔旁邊的其他交付檔（MCU 韌體、版本說明、原始碼資料夾…）：只記名稱、大小、sha256，沒有打開，沒有掃描。",
                   **({"rockchip": rkinfo,
                       "rockchip_note": "Rockchip update.img 的分割區表（位置與大小是溢位修正後的值，存的值另列）與每個分割區的 sha256；"
                                        "ext4 以外的分割區另外以 bootloader/<名稱>.img 清點（outside_rootfs），boot 的核心是 kernel/Image。"}
                      if rkinfo is not None else {}),
                   **({"disk_image": diskimg,
                       "disk_image_note": "Raw disk image (MBR/GPT): partition table, per-partition sha256, boot (FAT) files under bootloader/, kernel images "
                                          "under kernel/. The Raspberry Pi 4/5 EEPROM bootloader is not in the image (disk_image.not_in_image)."}
                      if diskimg is not None else {})},
                  f, ensure_ascii=False, indent=1)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=1)
    return result


def is_disk_image(img):
    return type(img).__name__ == "RpiImage"


def disk_image_info(img, source, container, cands, inv):
    """list.json 的 disk_image：分割區表、整個映像與各分割區的 sha256、boot／rootfs 的選擇、status（OK／ATTENTION／GAP）與一句說明。"""
    rp = rpimod()
    hashes = img.hash_all()
    st, notes = ("OK", []) if img.ok else ("GAP", [])
    root, why = img.rootfs()
    if root is None:
        notes.append(f"沒有可用的 rootfs：{why}")
    for n in img.notes:
        st = "GAP"
        notes.append(n)
    if any(p.get("truncated") for p in img.parts):
        st = "GAP"

    def att(text):
        nonlocal st
        st = "ATTENTION" if st == "OK" else st
        notes.append(text)
    if source.get("unusable") and st == "OK":
        st, notes = "GAP", [source["unusable"]]
    boot = img.boot()
    if boot is None:
        att("沒有 FAT 的 boot 分割區：沒有 bootloader／kernel 清點")
    fat = source.get("fat") or {}
    ext4 = source.get("ext4") or {}
    if ext4.get("journal_needs_recovery"):
        att("rootfs 的 ext4 日誌還沒套用（needs_recovery）：讀到的內容可能不完整")
    lost = rp.losses(ext4)
    if lost:
        att("rootfs 有項目沒有讀到（" + "、".join(f"{k} {v}" for k, v in lost.items()) + "）：裡面的套件不會在 SBOM 裡")
    if ext4.get("kernel_area_losses"):
        att(f"其中 {ext4['kernel_area_losses']} 個在 lib/modules 或 usr/src 底下：模組清單與核心設定可能不完整")
    if fat.get("unreadable") or fat.get("rejected_names") or fat.get("limit"):
        att(f"boot 分割區有項目沒有讀到（讀不到 {fat.get('unreadable', 0)}、名稱拒絕 {fat.get('rejected_names', 0)}"
            f"{'、超過項目上限' if fat.get('limit') else ''}）")
    others = [p for p in img.parts if p is not root and p is not boot and not p.get("empty") and p["fs_kind"] != "empty"]
    if others:
        att("分割區 " + "、".join(f"{p['index']}（{p['fs_kind']}）" for p in others) + " 只清點 sha256，內容沒有掃描")
    parts = "、".join(f"p{p['index']} {p['type_name']}（{p['size']} bytes，{p['fs_kind']}）" for p in img.parts)
    head = [f"磁碟映像 {hashes['bytes']} bytes，{img.scheme.upper()} 分割區 {len(img.parts)} 個：{parts}"]
    if root is not None:
        head.append(f"rootfs：p{root['index']} ext4（label {(root.get('fs') or {}).get('label') or '—'}）")
    if boot is not None:
        head.append(f"boot：p{boot['index']} {fat.get('fat_kind') or 'FAT'}（label 見 partitions）")
    bf = [x for x in inv if x["path"].startswith("bootloader/") and x["type"] == "file"]
    kf = [x for x in inv if x["path"].startswith("kernel/") and x["type"] == "file"]
    head.append(f"bootloader 檔案 {len(bf)} 個、kernel 檔案 {len(kf)} 個；Raspberry Pi 4/5 的 EEPROM 開機程式不在映像裡（沒有涵蓋）")
    out = {"status": st, "detail": "；".join(notes + head), "image": hashes, "reader": source.get("reader"),
           "fat": fat, "not_in_image": rp.NOT_IN_IMAGE, "boot_files": len(bf), "kernel_files": [x["path"] for x in kf],
           "container": ({"file": os.path.basename(container), "bytes": os.path.getsize(container)} if container else None),
           "compression_note": ("The image was shipped compressed and decompressed in full to a temporary file for random access; "
                                "the temporary file is deleted after the scan." if container else None)}
    out.update(img.table())
    return out


def rockchip_info(img, source, container, cands):
    """list.json 的 rockchip：分割區表、整個 update.img 的雜湊與 MD5 結尾、status（OK／ATTENTION／GAP）與一句說明。"""
    hashes = img.hash_all()
    table = img.table()
    st, notes = ("OK", []) if img.ok else ("GAP", [img.reason])
    rp, why = img.rootfs() if img.ok else (None, None)
    if img.ok and rp is None:
        st, notes = "GAP", [why]
    if source.get("unusable") and st == "OK":
        st, notes = "GAP", [source["unusable"]]

    def att(text):
        nonlocal st
        st = "ATTENTION" if st == "OK" else st
        notes.append(text)
    mt = img.md5_trailer
    if mt["match"] is False:
        att(f"檔案最後的 MD5 {mt['trailer']} 和前面內容的 md5 {mt['computed']} 不同（檔案損壞，或結尾不是整個檔案的 md5）")
    bad = [p["name"] for p in img.parts if not p["name_ok"]]
    if bad:
        att(f"分割區名稱不合法（只記錄，不使用）：{', '.join(repr(x) for x in bad[:5])}")
    if img.ok:
        others = [p["name"] for p in img.parts if p["ext4"] and p is not rp and (p.get("fs") or {}).get("has_files")]
        if others:
            att(f"ext4 分割區 {'、'.join(others)} 裡有檔案，沒有掃描（只記 sha256）")
    ext4 = source.get("ext4") or {}
    if ext4.get("journal_needs_recovery"):
        att("rootfs 的 ext4 日誌還沒套用（needs_recovery）：讀到的內容可能不完整")
    lost = rkmod().losses(ext4)
    if lost:
        att("rootfs 有項目沒有讀到（" + "、".join(f"{k} {v}" for k, v in lost.items()) + "；例子見 rootfs-tar.json）：裡面的套件不會在 SBOM 裡")
    if ext4.get("kernel_area_losses"):
        att(f"其中 {ext4['kernel_area_losses']} 個在 lib/modules 或 usr/src 底下：C-kernel-config 與 C-kernel-module-map 看不到這些計數，"
            "模組清單與核心設定可能不完整，這次的 K2（模組不存在）證據不要採用")
    if img.ok:
        odd = [f"{p['name']}（{p['content']}）" for p in img.parts if not p.get("empty") and not p["ext4"] and p["size"]
               and (p["content"] in ("squashfs", "android-boot") or p["name"] not in rkmod().KNOWN_PARTS)]
        if odd:
            att(f"分割區 {'、'.join(odd)} 的內容沒有掃描（只清點 sha256）")
    _, kinfo = img.kernel()
    parts = "、".join(f"{p['name']}（{p['size']} bytes{'，ext4' if p['ext4'] else ''}）" for p in img.parts
                      if not p.get("empty") and p["size"] is not None)
    head = [f"update.img {hashes['bytes']} bytes", f"RKAF 分割區 {len(img.parts)} 個：{parts or '位置無法證明'}"]
    corr = img.corrected()
    if corr:
        head.append(f"32 位元溢位已修正：{'、'.join(corr)}（唯一一組符合的位置與大小）")
    head.append("MD5 結尾相符" if mt["match"] else "MD5 結尾不符" if mt["match"] is False else "沒有 MD5 結尾")
    if rp is not None:
        head.append(f"rootfs：ext4 {rp['fs']['fs_bytes']} bytes（label {rp['fs']['label'] or '—'}）")
    if kinfo.get("note"):
        head.append(f"核心：{kinfo['note']}")
    elif kinfo.get("format"):
        head.append(f"核心：boot 的 FIT {kinfo.get('image')}（compression {kinfo.get('compression')}）→ kernel/Image")
    out = {"status": st, "detail": "；".join(notes + head), "update_img": hashes, "md5_trailer": mt, "kernel": kinfo,
           "container": rkmod().zip_info(container) if container else None}
    out.update({("layout_" + k if k in ("status", "reason") else k): v for k, v in table.items()})
    return out


def pick(result, variant):
    """list 的結果＋rootfs 名稱 → 前綴；找不到或有多個 → Fail。"""
    ps = [check_prefix(c["prefix"]) for c in result["rootfs"] if c["variant"] == variant]
    if not ps:
        raise Fail(f"刷機包裡沒有 {variant}（找到的：{', '.join(c['prefix'] for c in result['rootfs']) or '無'}）")
    if len(ps) > 1:
        raise Fail(f"{variant} 出現在 {len(ps)} 個位置（{', '.join(ps)}）：用 --prefix 指定")
    return ps[0]


def variants_all(result):
    """--rootfs all：rootfs_no_gui、rootfs_gui 與 rootfs 裡看起來是完整 rootfs（有 dpkg status 或 nv_tegra_release）、位置唯一的。"""
    out = []
    for v in VARIANTS:
        cs = [c for c in result["rootfs"] if c["variant"] == v]
        if len(cs) == 1 and cs[0]["looks_like_rootfs"]:
            out.append(v)
    return out


SMALL_PLACEHOLDER = 100   # 名稱是 rootfs、檔案少於這個數的：L4T 本來就有的空 rootfs 資料夾，只記 INFO


def excluded(result):
    """--rootfs all 沒有選的 rootfs 與原因：[(狀態, 名稱, 前綴, 原因)]。不會無聲略過。"""
    out = []
    for c in result["rootfs"]:
        same = [x for x in result["rootfs"] if x["variant"] == c["variant"]]
        if len(same) > 1:
            out.append(("ATTENTION", c["variant"], c["prefix"], f"{c['variant']} 出現在 {len(same)} 個位置，沒有選（用 --rootfs {c['variant']} --prefix 指定）"))
        elif not c["looks_like_rootfs"]:
            st = "INFO" if c["variant"] == "rootfs" and c["files"] < SMALL_PLACEHOLDER else "ATTENTION"
            out.append((st, c["variant"], c["prefix"], "不像完整的 rootfs，沒有掃描：" + c.get("not_rootfs_reason", "")))
    return out


# ---------- rootfs-tar ----------

class Range(io.RawIOBase):
    """檔案裡的一段（給從已寫出的 tar 讀回某個成員的內容用）。"""

    def __init__(self, f, off, size):
        self.f, self.pos, self.end = f, off, off + size

    def readable(self):
        return True

    def readinto(self, b):
        n = min(len(b), self.end - self.pos)
        if n <= 0:
            return 0
        self.f.seek(self.pos)
        data = self.f.read(n)
        b[:len(data)] = data
        self.pos += len(data)
        return len(data)


FILE_LIKE = ("file", "hardlink", "materialized")   # 輸出裡有內容、可以當硬連結目標的類型


class Target:
    """一個要轉出的 rootfs：前綴、輸出的 tar、報告。index：輸出裡每個一般檔案的內容位置（rel → (位移, 大小)），
    給其他 rootfs 指過來的硬連結讀回內容；inodes：資料夾來源的 (st_dev, st_ino) → rel（只在這個 rootfs 裡寫成硬連結）。"""

    def __init__(self, prefix, out, report):
        pp = split_name(prefix)
        if not pp:
            raise Fail(f"前綴不合法：{prefix!r}")
        self.pp, self.n, self.out, self.report = pp, len(pp), out, report
        self.written, self.links, self.index, self.inodes, self.tar, self.rd = {}, set(), {}, {}, None, None
        self.rep = {"prefix": "/".join(pp), "written": {"file": 0, "dir": 0, "symlink": 0, "hardlink": 0},
                    "bytes": 0, "setuid_setgid": 0, "skipped_devices": 0, "skipped_fifos": 0, "skipped_sockets": 0, "skipped_other": 0,
                    "hardlinks_materialized": 0, "hardlinks_from_second_pass": 0, "skipped_hardlinks": 0,
                    "unreadable_files": 0, "unreadable_dirs": 0, "size_changed_while_reading": 0,
                    "rejected": 0, "rejected_through_symlink": 0, "dropped_under_symlink": 0,
                    "examples": {"skipped": [], "rejected": [], "hardlinks_skipped": [], "hardlinks_materialized": [], "unreadable": []}}

    def note(self, key, text):
        if len(self.rep["examples"][key]) < LIST_MAX:
            self.rep["examples"][key].append(text)

    def tinfo(self, e, path):
        ti = tarfile.TarInfo("./" + path)
        ti.mode, ti.mtime = e.mode & 0o7777, e.mtime
        ti.uid = ti.gid = 0
        ti.uname = ti.gname = "root"
        return ti

    def write_content(self, ti, f, size):
        """一般檔案寫進輸出，回傳讀取時大小有沒有改變；記下內容的位置。"""
        ti.type, ti.size = tarfile.REGTYPE, size
        src = Sized(f, size)
        self.tar.addfile(ti, io.BufferedReader(src, 1 << 20))
        path = ti.name[2:]
        self.index[path] = (self.tar.offset - (-(-size // tarfile.BLOCKSIZE)) * tarfile.BLOCKSIZE, size)
        self.rep["bytes"] += size
        if src.changed:
            self.rep["size_changed_while_reading"] += 1
        return src.changed

    def read_back(self, rel):
        """這個輸出裡 rel 的內容（檔案物件）或 None。"""
        loc = self.index.get(rel)
        if loc is None:
            return None
        self.tar.fileobj.flush()
        if self.rd is None:
            self.rd = open(self.out, "rb")
        return io.BufferedReader(Range(self.rd, *loc), 1 << 20)

    def mark(self, path, k):
        old = self.written.get(path)
        if k == "symlink" and old == "dir":
            # 資料夾後來變成符號連結：之前寫在它底下的不能再當硬連結目標（tar 解開時會經過連結）
            pre = path + "/"
            gone = [p for p in self.written if p.startswith(pre)]
            for p in gone:
                del self.written[p]
                self.index.pop(p, None)
            self.rep["dropped_under_symlink"] += len(gone)
        self.written[path] = k
        if k not in FILE_LIKE:
            self.index.pop(path, None)
        if k != "symlink":
            self.links.discard(path)        # 同一個路徑後來寫成別的類型：不再是連結
        else:
            self.links.add(path)

    def add(self, e, rel, run):
        rep, path, k = self.rep, "/".join(rel), e.kind
        if any("/".join(rel[:i]) in self.links for i in range(1, len(rel))):
            rep["rejected_through_symlink"] += 1
            self.note("rejected", f"{e.raw}（經過符號連結）")
            if k == "dir":
                e.descend = False
            return
        ti = self.tinfo(e, path)
        if k == "file" and e.key is not None and self.written.get(self.inodes.get(e.key)) in FILE_LIKE:
            # 資料夾來源：同一個 rootfs 裡已經寫過同一個 inode → tar 的硬連結
            ti.type, ti.linkname = tarfile.LNKTYPE, "./" + self.inodes[e.key]
            self.tar.addfile(ti)
            self.index[path] = self.index.get(self.inodes[e.key])
            self.mark(path, "hardlink")
            rep["written"]["hardlink"] += 1
            return
        if k == "file":
            try:
                f = e.open()
            except OSError as err:
                e.failed = True
                rep["unreadable_files"] += 1
                self.note("unreadable", f"{path}（{err.strerror or '讀不到'}）")
                return
            with contextlib.closing(f):
                self.write_content(ti, f, e.size)
            if e.mode & 0o6000:
                rep["setuid_setgid"] += 1
            if e.key is not None:
                self.inodes[e.key] = path
        elif k == "dir":
            ti.type = tarfile.DIRTYPE
            self.tar.addfile(ti)
        elif k == "symlink":
            ti.type, ti.linkname = tarfile.SYMTYPE, e.link
            self.tar.addfile(ti)
        elif k == "hardlink":
            self.add_hardlink(e, rel, ti, run)   # 自己計數與記錄（硬連結、改寫成一般檔案或排進第二次讀取）
            return
        elif k == "unreadable_dir":
            rep["unreadable_dirs"] += 1
            self.note("unreadable", f"{path}/（資料夾）")
            return
        elif k == "unreadable":
            rep["unreadable_files"] += 1
            self.note("unreadable", path)
            return
        else:
            rep[{"device": "skipped_devices", "fifo": "skipped_fifos", "socket": "skipped_sockets"}.get(k, "skipped_other")] += 1
            self.note("skipped", f"{e.raw}（{k}）")
            return
        self.mark(path, k)
        rep["written"][k] += 1

    def add_hardlink(self, e, rel, ti, run):
        """壓縮檔的硬連結。目標在這個 rootfs 而且已寫出 → tar 硬連結；目標在別的 rootfs（cp -al 的兩棵樹）或已被取代
        → 從已寫出的 tar 讀回內容，寫成一般檔案；都沒有 → 排進第二次讀取。回傳 False：略過（已計數）。"""
        rep, path, tp = self.rep, "/".join(rel), e.link
        if not tp:
            rep["skipped_hardlinks"] += 1
            self.note("hardlinks_skipped", f"{e.raw} → （目標名稱不合法：絕對路徑或含 ..）")
            return False
        tgt = "/".join(tp[self.n:]) if tp[:self.n] == self.pp and len(tp) > self.n else None
        if tgt is not None and self.written.get(tgt) in FILE_LIKE:
            ti.type, ti.linkname = tarfile.LNKTYPE, "./" + tgt
            self.tar.addfile(ti)
            self.index[path] = self.index.get(tgt)
            self.mark(path, "hardlink")
            rep["written"]["hardlink"] += 1
            return True
        final = resolve_alias(run["alias"], "/".join(tp))
        fp_ = tuple(final.split("/"))
        for t in run["targets"]:
            if fp_[:t.n] == t.pp and len(fp_) > t.n:
                f = t.read_back("/".join(fp_[t.n:]))
                if f is not None:
                    size = t.index["/".join(fp_[t.n:])][1]
                    with contextlib.closing(f):
                        self.write_content(ti, f, size)
                    self.mark(path, "materialized")
                    rep["written"]["file"] += 1
                    rep["hardlinks_materialized"] += 1
                    self.note("hardlinks_materialized", f"{path} ← {final}")
                    return True
        run["pending"].setdefault(final, []).append((self, path, ti))
        self.mark(path, "pending")
        return True


def do_rootfs_tar(targets, archive=None, directory=None):
    """targets：[(前綴, 輸出 tar, 報告 json)]。來源讀一次，同時寫出每個 rootfs 的 tar；硬連結的目標拿不到內容時
    （目標不在選定的 rootfs 裡）才再讀一次壓縮檔，只取那些成員。"""
    ts = [Target(*t) for t in targets]
    if len({t.pp for t in ts}) != len(ts):
        raise Fail("同一個前綴指定了兩次")
    run = {"targets": ts, "alias": {}, "pending": {}}
    ok = False
    try:
        with contextlib.ExitStack() as stack:
            for t in ts:
                t.tar = stack.enter_context(tarfile.open(t.out, "w", format=tarfile.PAX_FORMAT))
            with open_source(archive, directory) as (entries, source):
                for t in ts:
                    t.rep["source"] = source
                for e in entries:
                    parts = e.parts
                    if parts is None:
                        # 位置不合法的成員：名稱裡出現某個 rootfs 前綴時算它的拒絕，其他的不管（list 另外記）
                        for t in ts:
                            if "/".join(t.pp) in e.raw:
                                t.rep["rejected"] += 1
                                t.note("rejected", e.raw)
                        continue
                    if e.kind == "hardlink" and e.link:
                        run["alias"][e.name] = "/".join(e.link)
                    t = next((t for t in ts if parts[:t.n] == t.pp), None)
                    if t is None:
                        # 資料夾來源：不在任何 rootfs、也不是通往 rootfs 的上層資料夾 → 不走進去
                        if e.kind == "dir" and not any(t.pp[:len(parts)] == parts for t in ts):
                            e.descend = False
                        continue
                    if len(parts) == t.n:
                        if e.kind == "unreadable_dir":
                            t.rep["unreadable_dirs"] += 1
                            t.note("unreadable", "（rootfs 本身）")
                        continue
                    t.add(e, parts[t.n:], run)
                if source.get("unusable"):
                    raise Fail(source["unusable"])
                x = source.get("ext4")
                for t in ts:          # Rockchip：ext4 裡漏掉的（虛擬 tar 沒有對應的成員）也算進報告，B-rootfs-tar 才會 ATTENTION
                    if x:
                        t.rep["unreadable_files"] += x["unreadable_files"] + x["unreadable_inodes"] + x["skipped_other"]
                        t.rep["unreadable_dirs"] += x["unreadable_dirs"] + x["corrupt_dir_blocks"]
                        t.rep["rejected"] += x["rejected_names"] + x["dir_loops"] + x["too_deep"]
                        for ex in x["examples"]:
                            t.note("unreadable", ex)
            if run["pending"]:
                second_pass(archive, run)
            for t in ts:
                if t.rd is not None:
                    t.rd.close()
        empty = [t.rep["prefix"] for t in ts if not t.written]
        if empty:
            raise Fail(f"{'、'.join(empty)} 底下沒有任何成員")
        ok = True
    finally:
        if not ok:
            for t in ts:
                with contextlib.suppress(OSError):
                    os.remove(t.out)
    for t in ts:
        t.rep["out_bytes"] = os.path.getsize(t.out)
        with open(t.report, "w", encoding="utf-8") as f:
            json.dump(t.rep, f, ensure_ascii=False, indent=1)
    return [t.rep for t in ts]


def second_pass(archive, run):
    """硬連結的目標不在選定的 rootfs 裡（例如只選 rootfs_gui，它的檔案硬連結到 rootfs_no_gui）：再讀一次壓縮檔，
    取出這些目標的內容，寫成一般檔案（附加在 tar 的後面；docker import 以最後一個為準）。"""
    pending = run["pending"]
    work = os.path.dirname(os.path.abspath(run["targets"][0].out))

    def got(name, e):
        with tempfile.SpooledTemporaryFile(SPOOL, dir=work) as sp, contextlib.closing(e.open()) as f:
            shutil.copyfileobj(io.BufferedReader(Sized(f, e.size)), sp)
            for t, path, ti in pending[name]:
                if t.written.get(path) != "pending":
                    continue                     # 第一次讀取時這個路徑後來被別的成員取代
                sp.seek(0)
                t.write_content(ti, sp, e.size)
                t.mark(path, "materialized")
                t.rep["written"]["file"] += 1
                t.rep["hardlinks_from_second_pass"] += 1
                t.note("hardlinks_materialized", f"{path} ← {name}（第二次讀取）")
    if archive is None:
        left = set(pending)
    else:
        left = fetch_members(archive, list(pending), got)
    for name in left:
        for t, path, _ in pending[name]:
            if t.written.get(path) == "pending":
                del t.written[path]
                t.rep["skipped_hardlinks"] += 1
                t.note("hardlinks_skipped", f"{path} → {name}（目標不在壓縮檔裡或不是一般檔案）")


# ---------- CRA 設定 ----------

TBC = "TO BE COMPLETED"


def cra_config(result, variant, name, version, archive_md5=None, manufacturer=None):
    """沒有 --product-config 時的最小 config.json：只填產品名稱、版本與識別（製造商只有 --manufacturer 時才填）；
    其他欄位留給 cra_report 標 TO BE COMPLETED。cra_report 一定要 manufacturer.name：沒有公司共用設定也沒有 --manufacturer 時
    呼叫端不產生 CRA 文件（不放假的製造商名稱：它會被當成「已提供」，也會寫進產品 SBOM）。"""
    c = next((x for x in result["rootfs"] if x["variant"] == variant), None)
    rel = (c or {}).get("l4t", {}).get("release")
    ident = (f"Flash package {result['archive']['file']}" + (f" (MD5 {archive_md5})" if archive_md5 else "")
             + f", root filesystem {variant}" + (f", NVIDIA Jetson Linux (L4T) {rel}" if rel else ""))
    cfg = {"$comment": ("Generated by tools/demo/flash_package.py (scan-flash-package.sh) because no --product-config was given. "
                        "Only product name, version and identification are filled; every other field is " + TBC + ". "
                        "Replace with the product's real CRA/Config/config.json."),
           "schema_version": 1,
           "product": {"name": name, "version": f"{version} ({variant})", "identification": ident},
           "sbom": {"component_type": "firmware"}}
    if manufacturer:
        cfg["manufacturer"] = {"name": manufacturer}
    return cfg


# ---------- summary ----------

def read_tsv(path):
    rows = {}
    try:
        with open(path, encoding="utf-8") as f:
            next(f, None)
            for line in f:
                p = line.rstrip("\n").split("\t")
                if len(p) >= 2:
                    rows[p[0]] = (p[1], p[2] if len(p) > 2 else "")
    except OSError:
        return None
    return rows


def read_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def summarize(out_dir, variants):
    lst = read_json(os.path.join(out_dir, "list.json")) or {"rootfs": []}
    res = []
    for v in variants:
        d = os.path.join(out_dir, v)
        st = read_tsv(os.path.join(d, "scan", "status.tsv")) or {}
        cra = read_json(os.path.join(d, "cra-project", "CRA", "Reports", "summary.json")) or {}
        meta = read_json(os.path.join(d, "scan", "meta.json")) or {}
        cand = next((c for c in lst["rootfs"] if c["variant"] == v), {})
        rt = read_json(os.path.join(d, "rootfs-tar.json")) or {}
        top = read_tsv(os.path.join(out_dir, "status.tsv")) or {}
        cnt = cra.get("counts") or {}
        k, nk = cnt.get("kernel") or {}, cnt.get("non_kernel") or {}
        bc = read_json(os.path.join(d, "bootloader-coverage.json"))      # 沒有（舊的結果）→ 不加這個鍵，輸出和以前相同
        ic = read_json(os.path.join(d, "initrd-coverage.json"))          # 沒有（舊的結果）→ 不加這個鍵
        res.append({**({"initrd_coverage": {"status": ic.get("status"), "detail": ic.get("detail"), "summary": ic.get("summary"),
                                            "file": f"{v}/initrd-coverage.md"}} if isinstance(ic, dict) else {}),
            **({"bootloader_coverage": {"status": bc.get("status"), "detail": bc.get("detail"), "counts": bc.get("counts"),
                                                "file": f"{v}/bootloader-coverage.md"}} if isinstance(bc, dict) else {}),
            "variant": v, "prefix": cand.get("prefix"), "l4t": (cand.get("l4t") or {}).get("release"),
            "l4t_detail": (cand.get("l4t") or {}).get("detail"), "l4t_note": (cand.get("l4t") or {}).get("note"),
            "os": cand.get("os_release"), "dpkg_packages": (cand.get("dpkg") or {}).get("installed_packages"),
            "sbom_packages": cnt.get("sbom_packages"),
            "unreadable": {"files": rt.get("unreadable_files"), "dirs": rt.get("unreadable_dirs")} if rt else None,
            "stages": {s: st[s] for s in st if s in ("C-kernel-l4t-map", "C-kernel-coverage", "C-kernel-config", "C-grype", "C-grype-db", "C-grype-db-update", "C-mirror-freshness") or s.startswith("D-dt-")},
            "cra_status": cra.get("status"),
            "cra_note": top[f"D-cra-{v}"][1] if top.get(f"D-cra-{v}", ("",))[0] in ("NOT_RUN", "FAIL") else None,
            "rootfs_tar": top.get(f"B-rootfs-tar-{v}"), "risk_status": ((cra.get("documents") or {}).get("risk-assessment") or {}).get("status"),
            "vuln_rows": {"total": cnt.get("rows"), "kernel": k.get("rows"), "non_kernel": nk.get("rows"),
                          "p1": cnt.get("p1"), "p2": cnt.get("p2"), "p3": cnt.get("p3"), "accepted": cnt.get("accepted"),
                          "kev_open": cnt.get("kev_open"), "kernel_section": k.get("section")},
            "dt": {"name": meta.get("name"), "version": meta.get("version"), "url": meta.get("dt_project_url")},
            "report_html": os.path.join(d, "scan", "report.html"),
            "cra_reports": os.path.join(d, "cra-project", "CRA", "Reports"),
        })
    return res


def summary_md(res):
    na = "—"
    lines = ["# 刷機包掃描摘要", ""]
    for r in res:
        vr = {k: (na if v is None else v) for k, v in r["vuln_rows"].items()}
        lines += [f"## {r['variant']}（{r['prefix'] or na}）", "",
                  f"- L4T：{r['l4t'] or '無法判斷'}；{r['l4t_detail'] or na}" + (f"；{r['l4t_note']}" if r["l4t_note"] else ""),
                  f"- 作業系統：{r['os'] or na}；dpkg 已安裝套件 {r['dpkg_packages'] if r['dpkg_packages'] is not None else na}；"
                  f"SBOM 套件 {r['sbom_packages'] if r['sbom_packages'] is not None else na}",
                  *([f"- 讀不到、沒有放進映像：檔案 {r['unreadable']['files']}、資料夾 {r['unreadable']['dirs']}（見 rootfs-tar.json；"
                      "這些檔案裡的套件不會出現在 SBOM）"] if r.get("unreadable") and (r["unreadable"]["files"] or r["unreadable"]["dirs"]) else []),
                  f"- DT 專案：{r['dt']['name'] or na} @ {r['dt']['version'] or na}" + (f"（{r['dt']['url']}）" if r["dt"]["url"] else ""),
                  f"- 弱點（CRA 去重後的列數）：全部 {vr['total']}；核心 {vr['kernel']}（8.7 節 {vr['kernel_section']}）；"
                  f"其他元件 {vr['non_kernel']}；P1 {vr['p1']}、P2 {vr['p2']}、P3 {vr['p3']}、"
                  f"accepted {vr['accepted']}；未處理的 KEV {vr['kev_open']}",
                  f"- CRA 文件：{r['cra_status'] or '沒有產生'}（風險評估 {r['risk_status'] or na}）" + (f"；{r['cra_note']}" if r.get("cra_note") else ""),
                  *([f"- rootfs 轉 tar：{r['rootfs_tar'][0]}；{r['rootfs_tar'][1]}"] if r.get("rootfs_tar") and r["rootfs_tar"][0] != "OK" else []),
                  *([f"- Bootloader 與韌體涵蓋：{r['bootloader_coverage']['status']}；{r['bootloader_coverage']['detail']}"
                     f"（NVIDIA 閉源韌體沒有成分層級掃描，標 GAP；UEFI 映像與原始碼的一致性檢查、rootfs 裡的廠商通用 capsule 見 `{r['bootloader_coverage']['file']}`）"]
                    if r.get("bootloader_coverage") else []),
                  *([f"- initrd 涵蓋：{r['initrd_coverage']['status']}；{r['initrd_coverage']['detail']}（見 `{r['initrd_coverage']['file']}`）"]
                    if r.get("initrd_coverage") else []),
                  "",
                  "| 階段 | 狀態 | 說明 |", "|---|---|---|"]
        for s, (stv, det) in sorted(r["stages"].items()):
            lines.append(f"| {s} | {stv} | {det.replace('|', '／')[:300]} |")
        if not r["stages"]:
            lines.append(f"| （沒有 sca-scan 結果） | NOT_RUN | {na} |")
        lines += ["", f"- 報告：`{r['report_html']}`", f"- CRA 文件：`{r['cra_reports']}`", ""]
    return "\n".join(lines)


# ---------- 指令列 ----------

def check_md5_dir(directory, text):
    """資料夾＋逐檔 md5 清單 → (狀態, 說明)。清單裡的路徑不能是絕對路徑或含 ..；找不到的檔案算不符。"""
    lines = [x for x in parse_md5_lines(text) if x[1]]
    if not lines:
        return "FAIL", "md5 清單裡沒有「雜湊  檔名」的列（--dir 需要逐檔的清單）"
    bad, missing, ok = [], [], 0
    for h, name, _ in lines:
        parts = split_name(name.lstrip("*"))
        if not parts:
            bad.append(f"{name}（路徑不合法）")
            continue
        p = os.path.join(directory, *parts)
        if os.path.islink(p) or not os.path.isfile(p):
            missing.append(name)
            continue
        try:
            got = md5_file(p)
        except OSError as e:
            missing.append(f"{name}（{e.strerror}）")
            continue
        if got == h:
            ok += 1
        else:
            bad.append(name)
    fmts = sorted({f for _, _, f in lines})
    if bad or missing:
        return "FAIL", f"{len(lines)} 個檔案：相符 {ok}、不符 {len(bad)}（{'、'.join(bad[:5])}）、找不到或讀不到 {len(missing)}（{'、'.join(missing[:5])}）"
    return "OK", f"{len(lines)} 個檔案全部相符（格式 {'、'.join(fmts)}）"


def parse_target(s):
    p = s.split("=")
    if len(p) != 3 or not all(p):
        raise Fail(f"--target 要是 <前綴>=<輸出.tar>=<報告.json>：{s!r}")
    return tuple(p)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    def source_args(a):
        g = a.add_mutually_exclusive_group(required=True)
        g.add_argument("--archive")
        g.add_argument("--dir")

    a = sub.add_parser("md5")
    source_args(a)
    a.add_argument("--md5", required=True)
    a.add_argument("--got", help="已經算好的 md5（provenance 一次讀完時算的），不再讀一次壓縮檔")
    a = sub.add_parser("provenance")
    a.add_argument("--root", required=True)
    a.add_argument("--out", required=True)
    g = a.add_mutually_exclusive_group()
    g.add_argument("--archive")
    g.add_argument("--dir")
    a.add_argument("--previous")
    a = sub.add_parser("list")
    source_args(a)
    a.add_argument("--out", required=True)
    a.add_argument("--inventory", required=True)
    a.add_argument("--version")
    a.add_argument("--deliverables")
    a.add_argument("--container")
    a = sub.add_parser("format")
    a.add_argument("--archive", required=True)
    a = sub.add_parser("rk-extract")
    a.add_argument("--archive", required=True)
    a.add_argument("--out", required=True)
    a.add_argument("--member")
    a = sub.add_parser("img-extract")
    a.add_argument("--archive", required=True)
    a.add_argument("--out", required=True)
    a.add_argument("--max-bytes", type=int)
    a = sub.add_parser("rk-status")
    a.add_argument("--list", required=True)
    a.add_argument("--if-present", action="store_true", help="list.json 沒有 rockchip 時什麼都不印（不是 Rockchip 的刷機包）")
    a = sub.add_parser("pick")
    a.add_argument("--list", required=True)
    a.add_argument("--rootfs", required=True)
    a = sub.add_parser("rootfs-tar")
    source_args(a)
    a.add_argument("--target", action="append", required=True)
    a = sub.add_parser("cra-config")
    a.add_argument("--list", required=True)
    a.add_argument("--variant", required=True)
    a.add_argument("--name", required=True)
    a.add_argument("--version", required=True)
    a.add_argument("--md5")
    a.add_argument("--manufacturer")
    a.add_argument("--out", required=True)
    a = sub.add_parser("summary")
    a.add_argument("--out-dir", required=True)
    a.add_argument("--variant", action="append", required=True)
    a = ap.parse_args(argv)
    try:
        if a.cmd == "provenance":
            st, msg, _ = provenance(a.root, a.out, a.archive, a.dir, a.previous)
            print(f"{st}\t{msg}")
            return 1 if st == "FAIL" else 0
        if a.cmd == "md5":
            with open(a.md5, encoding="utf-8-sig", errors="replace") as f:
                text = f.read(1 << 20)
            if a.dir:
                st, msg = check_md5_dir(a.dir, text)
                print(f"{st}\t{msg}")
                return 0 if st == "OK" else 1
            want, fname, fmt = parse_md5_file(text, os.path.basename(a.archive))
            if not want:
                print(f"FAIL\t{os.path.basename(a.md5)} 裡沒有 MD5 值")
                return 1
            got = a.got.lower() if a.got and re.fullmatch(r"[0-9a-fA-F]{32}", a.got) else md5_file(a.archive)
            base = os.path.basename(a.archive)
            nm = f"；.md5 檔記的檔名是 {fname}，和 {base} 不同" if fname and os.path.basename(fname) != base else ""
            if got != want:
                print(f"FAIL\tMD5 {got} 和 {os.path.basename(a.md5)} 的 {want} 不同（.md5 格式 {fmt}）{nm}")
                return 1
            print(f"{'ATTENTION' if nm else 'OK'}\tMD5 {got} 相符（.md5 格式 {fmt}）{nm}")
            return 0
        if a.cmd == "list":
            r = do_list(a.out, a.inventory, a.archive, a.dir, a.version, a.deliverables, a.container)
            for c in r["rootfs"]:
                print("\t".join([c["variant"], c["prefix"], str(c["files"]), str(c["bytes"]), str(c["unreadable"] + c["unreadable_dirs"]),
                                 c["l4t"]["status"], c["l4t"]["detail"]]))
            return 0
        if a.cmd == "format":
            print(archive_format(a.archive))
            return 0
        if a.cmd == "rk-extract":
            rk = rkmod()
            if archive_format(a.archive) != "rockchip-zip":
                raise Fail(f"{os.path.basename(a.archive)} 不是 zip")
            try:
                m, n = rk.extract_member(a.archive, a.out, a.member, shutil.disk_usage(os.path.dirname(os.path.abspath(a.out))).free)
            except (rk.RkError, zipfile.BadZipFile, zipfile.LargeZipFile, NotImplementedError, RuntimeError, EOFError,
                    zlib.error, lzma.LZMAError, ValueError) as e:
                raise Fail(f"{os.path.basename(a.archive)}：{e}")
            print(f"OK\t{m.filename}（{n} bytes，{zipfile.compressor_names.get(m.compress_type, m.compress_type)}，CRC 相符）"
                  f"→ {os.path.basename(a.out)}；其他成員沒有解開")
            return 0
        if a.cmd == "img-extract":
            rp = rpimod()
            if archive_format(a.archive) not in ("raw-disk-img-xz", "raw-disk-img-gz"):
                raise Fail(f"{os.path.basename(a.archive)} 不是 .xz／.gz 壓縮的磁碟映像")
            try:
                n, sha = rp.extract_image(a.archive, a.out, a.max_bytes or rp.MAX_IMAGE)
            except rp.RpiError as e:
                raise Fail(f"{os.path.basename(a.archive)}：{e}")
            print(f"OK\t{n} bytes 解壓到 {os.path.basename(a.out)}（sha256 {sha}）；暫存檔，掃描完刪除")
            return 0
        if a.cmd == "rk-status":
            r = read_json(a.list)
            x = (r or {}).get("rockchip") or (r or {}).get("disk_image")
            if x is None and r is not None and a.if_present:
                return 0
            if not isinstance(x, dict) or x.get("status") not in ("OK", "ATTENTION", "GAP"):
                print(f"FAIL\t{a.list} 沒有 Rockchip／磁碟映像的分割區表")
                return 1
            print(f"{x['status']}\t{x.get('detail') or ''}")
            return 0
        if a.cmd == "pick":
            r = read_json(a.list)
            if r is None:
                raise Fail(f"讀不到 {a.list}")
            vs = variants_all(r) if a.rootfs == "all" else [a.rootfs]
            if a.rootfs == "all":
                for st, v, p, why in excluded(r):       # 沒有選的要說出來，不無聲略過
                    print("\t".join(["SKIP", st, v, p, why]))
            if not vs:
                raise Fail("刷機包裡沒有看起來完整、位置唯一的 rootfs（rootfs_no_gui／rootfs_gui／rootfs）")
            for v in vs:
                c = next(c for c in r["rootfs"] if c["prefix"] == pick(r, v))
                print("\t".join([v, c["prefix"], str(c["bytes"])]))
            return 0
        if a.cmd == "rootfs-tar":
            reps = do_rootfs_tar([parse_target(x) for x in a.target], a.archive, a.dir)
            for r in reps:
                w = r["written"]
                print(f"{r['prefix']}\t檔案 {w['file']}、資料夾 {w['dir']}、符號連結 {w['symlink']}、硬連結 {w['hardlink']}（{r['bytes']} bytes）；"
                      f"略過裝置檔 {r['skipped_devices']}、FIFO {r['skipped_fifos']}、socket {r['skipped_sockets']}、其他 {r['skipped_other']}、"
                      f"硬連結 {r['skipped_hardlinks']}；硬連結改寫成檔案 {r['hardlinks_materialized'] + r['hardlinks_from_second_pass']}"
                      f"（第二次讀取 {r['hardlinks_from_second_pass']}）；讀不到的檔案 {r['unreadable_files']}、資料夾 {r['unreadable_dirs']}；"
                      f"拒絕 {r['rejected']}（經過符號連結 {r['rejected_through_symlink']}）；讀取中大小改變 {r['size_changed_while_reading']}；"
                      f"setuid／setgid {r['setuid_setgid']}；讀取方式 {r['source']['reader']}")
            return 0
        if a.cmd == "cra-config":
            r = read_json(a.list)
            if r is None:
                raise Fail(f"讀不到 {a.list}")
            cfg = cra_config(r, a.variant, a.name, a.version, a.md5, a.manufacturer)
            os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
            with open(a.out, "w", encoding="utf-8") as f:
                json.dump(cfg, f, ensure_ascii=False, indent=1)
            return 0
        if a.cmd == "summary":
            res = summarize(a.out_dir, a.variant)
            md = summary_md(res)
            with open(os.path.join(a.out_dir, "summary.md"), "w", encoding="utf-8") as f:
                f.write(md + "\n")
            with open(os.path.join(a.out_dir, "summary.json"), "w", encoding="utf-8") as f:
                json.dump(res, f, ensure_ascii=False, indent=1)
            print(md)
            return 0
    except (Fail, OSError, tarfile.TarError, EOFError) as e:
        print(f"錯誤：{e}", file=sys.stderr)
        return 1
    return 64


if __name__ == "__main__":
    sys.exit(main())
