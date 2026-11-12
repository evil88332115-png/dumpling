#!/usr/bin/env python3
"""kernel_modules.py：從產品映像的 rootfs（與板子的 lsmod）產生 CRA/Config/kernel-modules.json（schema sca-center-kernel-modules/1），
證據規則 K2 的輸入（tools/cra/README.md「K2 的輸入」；格式由 vex_export.check_kernel_modules 驗證）。

用法（通常經 board_import.py --kernel-modules-from …，見 tools/demo/board-test.md「核心模組清單」）：
  python3 -I kernel_modules.py --from <rootfs 資料夾｜rootfs tar｜docker save 的 tar｜刷機包 tbz2 或解開的資料夾> [--prefix <rootfs 在刷機包裡的路徑>]
      [--kernel-version <版本>] (--scan <sca-scan 的輸出資料夾（讀 meta.json）> | --image-sha256 sha256:<64 hex>)
      --owner <負責人> [--captured YYYY-MM-DD] [--lsmod <板子的 lsmod 或 /proc/modules>] [--modules-disabled true|false]
      [--accept-unread-initramfs] --out <kernel-modules.json> [--replace]
印一行 D-kernel-modules<TAB>狀態<TAB>說明。OK／ATTENTION：寫了檔案（ATTENTION＝有限制，見說明與旁邊的 kernel-modules.sources.json）；
GAP：輸入不足，**沒有寫檔案**；原本的 kernel-modules.json 改名成 kernel-modules.json.stale-<UTC 時間>（K2 不再讀它，說明裡寫出來）；
FAIL：參數或讀寫錯誤（讀映像失敗時同樣把原本的檔改名：可能只是環境的問題〔權限、磁碟〕，但這次沒有證明清單還是對的，偏保守）。退出碼 0 OK、2 ATTENTION／GAP、1 FAIL、64 參數錯誤。
--replace：已有內容不同的 kernel-modules.json 時取代（旁邊的 kernel-modules.sources.json 一起換）。

讀法（不執行映像裡的任何東西、不掛載、不 chroot、不解開到磁碟）：沿用 tools/pilot/lib/kernel_config.py 的 collect()（資料夾用 lstat
走訪不跟隨連結；tar、刷機包串流讀）。記下所有一般檔案的路徑（不讀內容）與所有符號連結；只讀這些檔案的內容：*/modprobe.d/ 的 *.conf、
*.alias，名稱是 initrd*、initramfs* 的檔、extlinux.conf、modules.builtin、/etc/nv_tegra_release、刷機包的 bootloader/l4t_initrd.img。
名稱是 *.ko、*.ko.gz、*.ko.xz、*.ko.zst 的檔只讀開頭（壓縮的在記憶體裡只解出開頭，輸入最多 1 MB、輸出 64 個位元組；依魔數判斷壓縮）：
內容是 ELF 的可重定位檔（\\x7fELF、e_type ET_REL）才算核心模組。不是 ELF（例如 /usr/share/doc 的 COPYING.nvidia-uvm.ko.gz、vim 的
韓文教學 tutor.ko）或 ELF 卻不是 ET_REL → 不列，個數與例子寫在 sources 的 modules.ignored_non_module_files；在模組資料夾以外的只寫進
sources 的 info（不影響狀態），在模組資料夾裡的寫進 notes（ATTENTION）。打不開、解不開、沒有解壓程式（zstd）、名稱是 .ko* 的連結指到
映像裡沒有的位置、tar 輸入裡連結指到名稱不是 .ko* 的檔（內容已經讀不到）→ 判斷不了，照樣當作模組列出（偏保守），寫在
modules.unchecked_module_files 與 notes。資料夾輸入時，連結指到名稱不是 .ko* 的檔會回頭讀那個檔的開頭（O_NOFOLLOW）。
符號連結一律在映像裡解析（以 rootfs 為根，不碰主機）。資料夾走訪時讀不到的資料夾或檔案：在模組資料夾、modprobe.d、/boot 底下（或是
它們的上層、或是模組資料夾裡的連結指到的位置）→ GAP；其他位置 → ATTENTION（可能藏著模組），列出路徑。

各欄位：
  image_sha256：取自掃描的 meta.json（digest ＞ image_id ＞ content_sha256：cra_report 比對 K2 用的就是這幾個值），或 --image-sha256
    （有 --scan 時必須是 meta.json 裡的其中一個）。都沒有 → GAP。**不從 rootfs 計算**：scan-flash-package 的映像 ID 是 docker import
    當下產生的，從 rootfs 算不出來。
  kernel_version：--kernel-version，沒給時映像只有一個核心模組資料夾才用它（多個 → GAP，不猜）。
  modules_in_image：
    - /lib/modules/<版本>/ 與 /usr/lib/modules/<版本>/（L4T 可能是兩個各自存在的資料夾）底下所有 *.ko、*.ko.xz、*.ko.zst、*.ko.gz
      （含 updates/、extra/ 與其他子資料夾；映像裡的連結照樣解析，名稱是 .ko 的連結指到任何一般檔案都以連結的名稱列；build、source 不走），
      以相對於模組資料夾的路徑去重；
    - initramfs 裡這個核心的模組寫成 initramfs:<initrd 的路徑>:<相對路徑>（K2 只比檔名，前綴只是出處；initramfs 裡的 .ko 不檢查內容）。
    initramfs：/boot（在映像裡解析連結）的 initrd*、initramfs*（檔名有別的核心版本的不讀）、extlinux.conf 的 INITRD，以及刷機包的
    bootloader/l4t_initrd.img（--from 是刷機包＋--prefix 時，同一次讀取裡讀；recovery／initrd flash 用）。newc cpio，可以是多段
    （未壓縮的 early cpio＋壓縮的主體）；gzip、xz、lzma、bzip2 用 Python，zstd 用 Python 3.14 的 compression.zstd 或主機的 zstd，
    lz4 用主機的 lz4（只把資料從 stdin 餵給解壓程式，不寫檔）。任何一個 initramfs（含 l4t_initrd.img）讀不了 → 預設 GAP（它的模組
    可以載入，漏掉會讓 K2 誤判「已移除」）；--accept-unread-initramfs 時照寫，限制寫在 source 與 $comment，modprobe.d 的 install 擋住行
    全部不放（被擋的模組可能就在沒讀到的 initramfs 裡，無法證明），ATTENTION。輸入只有 rootfs（L4T 映像）而沒有讀到 l4t_initrd.img → ATTENTION。
    沒有找到任何 initramfs → ATTENTION（確認映像真的不用 initramfs）。
  modules_outside_dirs（有才寫）：模組資料夾以外的 *.ko*（例如 /opt/vendor/x.ko，可以用 insmod 載入），映像裡的絕對路徑，ATTENTION；
    其他核心版本的模組資料夾不列。不放進 modules_in_image：對應表的 modules_present 只看模組資料夾，放進去會讓 K2 的「兩份清單矛盾」
    檢查對每一列都成立；K2 另外把同名的模組當作還在（不判「已移除」）。
  modules_builtin：模組資料夾的 modules.builtin（兩個資料夾都有時取聯集）；沒有或是空的 → null（K2 不判「已移除」），ATTENTION。
  modules_softdep：模組資料夾的 modules.softdep（depmod 產生）的原始行，第一行是 depmod 的標頭（兩個資料夾都有時取聯集）。K2 沒有這個欄位
    就不認 install 的擋住（kmod v34 以前有 softdep 的模組會略過 install）。沒有這個檔、或第一行不是標頭 → 不寫、ATTENTION；讀不到 → GAP。
    消費端（vex_export）還不認得這個欄位時也不寫（ATTENTION）。
  modprobe_d：kmod 的規則算出的有效行，**原文**，每個元素是一個實體行（續行不接起來，反斜線照留；行尾 CR／CRLF 與頭尾空白去掉，
    行中間的 CR 換成空白而且擋住行全部不放；內部的空白不動）、依有效順序：/etc/modprobe.d、
    /usr/local/lib/modprobe.d、/usr/lib/modprobe.d、/lib/modprobe.d 依序，同名檔只用最前面那個（/etc 蓋過 /usr/lib 與 /lib；
    連到 /dev/null＝遮蔽），只讀 *.conf 與 *.alias（不含 . 開頭），依檔名排序後逐行；# 開頭與空行不收。
    所有目錄的檔合在一起依檔名排序（不是一個目錄接一個目錄），這就是生效順序。
    /run/modprobe.d：開機後是 tmpfs，映像裡的內容不會生效，執行時另外放進去的也不知道：映像裡的 /run/modprobe.d 不讀（它的行不算
    「禁止載入」），有檔案時 ATTENTION；它和 /usr/local/lib、/usr/lib、/lib 的某個檔同名時，那個檔執行時可能被換掉：它的擋住行不放
    （withheld：a same-name file in /run/modprobe.d may replace it at runtime）。
    initramfs 裡的 modprobe.d（同樣的規則）也讀：rootfs 的 install <模組> /bin/false 之類的行，如果某個 initramfs 有這個模組、它自己的
    設定卻沒有擋，就不放進 modprobe_d（開機早期可以載入；偏保守），記在 sources 的 withheld 與 notes。
    消費端只收文字清單，所以每行的來源檔、被蓋掉的檔、不放的行寫在旁邊的 kernel-modules.sources.json。讀不到的 conf（連到映像裡沒有收
    內容的檔）照樣蓋掉同名檔、沒有行（偏保守），ATTENTION；modprobe.d 資料夾本身連到沒有收的位置 → GAP。
    不看：核心命令列的 modprobe.blacklist=。
  loaded：--lsmod（lsmod 或 /proc/modules 的格式），或 board_import 匯入的板子結果；沒有 → null（K2 全部是 K3），ATTENTION。
    和 modules_in_image＋modules_outside_dirs 矛盾（有載入卻不在映像裡）→ GAP（消費端會 FAIL；多半是板子跑的不是這個映像或核心）。
  modules_disabled：--modules-disabled 或板子的 sysctl kernel.modules_disabled；沒有 → null。
  owner：必填，佔位字（vex_export.author_missing）或 <…> → 參數錯誤。captured：預設今天（UTC）。
"""
import argparse
import bz2
import datetime
import fnmatch
import hashlib
import importlib.util
import io
import json
import lzma
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import zlib
from pathlib import Path

SCHEMA = "sca-center-kernel-modules/1"
SOURCES_SCHEMA = "sca-center-kernel-modules-sources/1"
STAGE = "D-kernel-modules"
TOOL_VERSION = "2026-11-06.1"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
MODULE_EXT = (".ko", ".ko.xz", ".ko.zst", ".ko.gz")
MODULE_ROOTS = (("lib", "modules"), ("usr", "lib", "modules"))
SKIP_IN_MODDIR = {"build", "source"}                 # 模組資料夾裡指向建置樹的連結：不是模組
# kmod 的設定資料夾（優先順序由高到低）；/run/modprobe.d 開機後是 tmpfs：映像裡的內容不讀
MODPROBE_DIRS = ("etc/modprobe.d", "run/modprobe.d", "usr/local/lib/modprobe.d", "usr/lib/modprobe.d", "lib/modprobe.d")
RUNTIME_DIRS = ("run/modprobe.d",)
CONF_EXT = (".conf", ".alias")
INITRD_RE = re.compile(r"^(?:initrd|initramfs)")
VER_IN_NAME = re.compile(r"\d+\.\d+")
PKG_INITRD = ("bootloader", "l4t_initrd.img")
IMAGE_RE = re.compile(r"^(?:sha256:)?([0-9a-f]{64})$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
KVER_RE = re.compile(r"^[A-Za-z0-9._+~-]{1,128}$")
MODNAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
MAX_CONF = 1 << 20              # 單一 modprobe.d 檔
MAX_CONF_LINES = 20_000
MAX_SMALL = 1 << 20             # extlinux.conf、modules.builtin
MAX_INITRD = 512 << 20          # 單一 initrd（壓縮的）
MAX_INITRD_TOTAL = 1 << 30
MAX_CPIO_OUT = 4 << 30          # initramfs 解壓後的上限
MAX_LINKS = 2_000_000
MAX_FILES = 3_000_000
# 名稱是 .ko* 的檔：只讀開頭判斷是不是核心模組（ELF、ET_REL）；壓縮的只解出開頭（輸入、輸出都有上限，不解整個檔）
KO_HEAD = 64                    # 要看的開頭（ELF 標頭的 e_ident＋e_type 只要 18 個位元組）
KO_IN_CAP = 1 << 20             # 壓縮的 .ko 最多讀這麼多壓縮資料來解出開頭（zstd 一個 block 最多 128 KB）
KO_CHUNK = 64 << 10
ELF_MAGIC = b"\x7fELF"
ET_REL = 1
CPIO_MAGIC = (b"070701", b"070702")
SOFTDEP_HEADER = "# Soft dependencies extracted from modules themselves."   # depmod 寫在 modules.softdep 的第一行
S_IFREG, S_IFLNK = 0o100000, 0o120000


class Gap(Exception):
    """輸入不足：不寫檔案。"""


class InputError(Exception):
    """參數或讀寫錯誤（FAIL）。"""


def _load(name, path):
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m
    except Exception as e:
        raise InputError(f"無法載入 {path}（{type(e).__name__}: {str(e)[:120]}）")


_mods = {}


def kernel_config():
    """tools/pilot/lib/kernel_config.py（collect、VFS、split_name）。它要 Python 3.12 以上（語法），所以只在需要時載入。"""
    if "kc" not in _mods:
        if sys.version_info < (3, 12):
            raise InputError(f"讀映像要 Python 3.12 以上（tools/pilot/lib/kernel_config.py）；這個是 {sys.version.split()[0]}")
        _mods["kc"] = _load("sca_center_kernel_config", ROOT / "tools" / "pilot" / "lib" / "kernel_config.py")
    return _mods["kc"]


def vex_export():
    if "vx" not in _mods:
        _mods["vx"] = _load("sca_center_vex_export_km", HERE / "vex_export.py")
    return _mods["vx"]


def owner_problem(owner):
    """負責人：消費端的佔位字規則（vex_export.author_missing），另外 <名字> 這種範本也不收。"""
    if vex_export().author_missing(owner) or re.search(r"[<>]", owner or ""):
        return f"--owner 要是負責人的名字（不能是空的或佔位字：{owner!r}）"
    return None


def now_utc():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def show(parts):
    return "/" + "/".join(parts)


def under(p, d):
    return p[:len(d)] == d


# =====================================================================================================
# 1. 從映像擷取（kernel_config.collect 的讀法，留下這裡要的東西）
# =====================================================================================================

def is_module_name(n):
    return n.endswith(MODULE_EXT)


def elf_kind(head):
    """解壓後的開頭 → ("module"|"not_module"|"unknown", 說明)。核心模組是 ELF 的可重定位檔（e_type ET_REL；
    核心的 load_module 不收其他種類）。開頭不是 \\x7fELF → 不是模組（例如 /usr/share/doc 的 COPYING.x.ko.gz、vim 的 tutor.ko）。"""
    if not head.startswith(ELF_MAGIC):
        if len(head) < len(ELF_MAGIC) and ELF_MAGIC.startswith(head) and head:
            return "unknown", "too short to check"
        return "not_module", "not ELF (starts with " + (head[:8].hex() or "nothing: empty file") + ")"
    if len(head) < 18 or head[5] not in (1, 2):
        return "unknown", "ELF header too short or unknown byte order"
    et = int.from_bytes(head[16:18], "little" if head[5] == 1 else "big")
    return ("module", "ELF ET_REL") if et == ET_REL else ("not_module", f"ELF but e_type {et}, not ET_REL (a kernel module is relocatable)")


def _head_py(dec, f, buf):
    """Python 的解壓物件：一段一段讀（最多 KO_IN_CAP），只要 KO_HEAD 個位元組的輸出 → (開頭, 解完了沒有)。"""
    out, total = b"", len(buf)
    while True:
        if buf:
            out += dec.decompress(buf, KO_HEAD - len(out))
        if len(out) >= KO_HEAD or dec.eof:
            return out, True
        if total >= KO_IN_CAP:
            return out, False
        buf = f.read(min(KO_CHUNK, KO_IN_CAP - total))
        if not buf:
            return out, False
        total += len(buf)


def _head_tool(tool, data):
    """主機的解壓程式（zstd）：餵最多 KO_IN_CAP 的壓縮資料（stdin），只讀 KO_HEAD 個位元組的輸出；輸入截斷的錯誤不管（只要開頭）。"""
    p = subprocess.Popen([tool, "-d", "-c", "-q"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    def writer():
        try:
            p.stdin.write(data)
        except (BrokenPipeError, OSError):
            pass
        finally:
            try:
                p.stdin.close()
            except OSError:
                pass
    th = threading.Thread(target=writer, daemon=True)
    th.start()
    out = b""
    try:
        while len(out) < KO_HEAD:
            b = p.stdout.read(KO_HEAD - len(out))
            if not b:
                break
            out += b
    finally:
        p.kill()
        p.stdout.close()
        p.wait()
        th.join(5)
    return out


def ko_verdict(opener, size):
    """名稱是 .ko* 的檔 → ("module"|"not_module"|"unknown", 說明)。依內容的魔數判斷壓縮（kmod 也是看魔數），只解出開頭：
    gzip、xz 用 Python，zstd 用 Python 3.14 的 compression.zstd 或主機的 zstd。打不開、解不開、沒有解壓程式 → unknown
    （照樣當作模組列出：可能是模組，不能默默丟掉）。"""
    if opener is None:
        return "unknown", "content not available"
    try:
        f = opener()
    except OSError as e:
        return "unknown", f"cannot open ({e.strerror or type(e).__name__})"
    try:
        head = f.read(KO_HEAD)
        if head[:2] == b"\x1f\x8b":
            dec, how = zlib.decompressobj(31), "gzip"
        elif head[:6] == b"\xfd7zXZ\x00":
            dec, how = lzma.LZMADecompressor(lzma.FORMAT_XZ), "xz"
        elif head[:4] == b"\x28\xb5\x2f\xfd":
            how = "zstd"
            z = zstd_decoder()
            if z is None:
                return "unknown", "zstd-compressed, but no zstd decoder (Python 3.14 compression.zstd or the zstd tool)"
            if z[0] == "tool":
                data = head + f.read(KO_IN_CAP - len(head))
                out = _head_tool(z[1], data)
                if not out:
                    return "unknown", "zstd: no output from the first 1 MB"
                return elf_kind(out)
            dec = z[1]()
        else:
            return elf_kind(head)
        out, done = _head_py(dec, f, head)
        if len(out) < len(ELF_MAGIC) and not done:
            return "unknown", f"{how}: no output from the first {KO_IN_CAP >> 20} MB (truncated?)"
        return elf_kind(out)
    except (OSError, EOFError, zlib.error, lzma.LZMAError, ValueError) as e:
        return "unknown", f"cannot read or decompress ({type(e).__name__})"
    except Exception as e:          # compression.zstd.ZstdError 等
        return "unknown", f"cannot decompress ({type(e).__name__})"
    finally:
        try:
            f.close()
        except Exception:
            pass


def wanted(parts):
    """要讀內容的檔 → (種類, 上限) 或 None。"""
    name = parts[-1]
    if len(parts) >= 2 and parts[-2] == "modprobe.d" and name.endswith(CONF_EXT):
        return "conf", MAX_CONF
    if INITRD_RE.match(name):
        return "initrd", MAX_INITRD
    if name in ("extlinux.conf", "modules.builtin", "modules.softdep") or parts == ("etc", "nv_tegra_release"):
        return "small", MAX_SMALL
    return None


def make_collected(pkg_root=None):
    kc = kernel_config()

    class KmodCollected(kc.Collected):
        """files：映像裡每個一般檔案（沒讀內容的是 b""；有讀內容的路徑在 content）。links：所有符號連結。
        unread：資料夾走訪時讀不到的資料夾或檔案，以及有名稱、卻讀不到內容的檔。docker 層的 whiteout 沿用 Collected.whiteout。"""

        def __init__(self):
            super().__init__()
            self.content, self.too_big, self.unread = set(), {}, {}
            # 名稱是 .ko* 的一般檔案 → ko_verdict 的結果（("module"|"not_module"|"unknown", 說明)）
            self.ko_check = {}
            self.base_dir = None      # --from 是資料夾時：rootfs 在磁碟上的位置（連結指到名稱不是 .ko* 的檔時，回頭讀它的開頭）
            self.initrd_bytes = 0
            self.pkg_root, self.pkg_initrd = pkg_root, None      # 刷機包的 Linux_for_Tegra 資料夾；(路徑, bytes 或 None, 原因)

        def _put(self, parts, data, layer, has_content):
            self.links.pop(parts, None)
            self.too_big.pop(parts, None)
            self.ko_check.pop(parts, None)
            self.files[parts] = data
            self.layer[parts] = layer
            (self.content.add if has_content else self.content.discard)(parts)

        def content_of(self, parts):
            return self.files.get(parts) if parts in self.content and parts in self.files else None

        def ko_kind(self, parts):
            """映像裡的一般檔案（名稱是 .ko* 的連結解析後的目標）→ ("module"|"not_module"|"unknown", 說明)。
            沒有判斷過（連結指到名稱不是 .ko* 的檔）：資料夾輸入時回頭讀它的開頭（O_NOFOLLOW）；tar 輸入讀不到了 → unknown（照樣列，偏保守）。"""
            v = self.ko_check.get(parts)
            if v is None and self.base_dir is not None and parts in self.files:
                path = os.path.join(self.base_dir, *parts)
                v = ko_verdict(lambda: kernel_config().flash_package().open_nofollow(path), 0)
                self.ko_check[parts] = v
            return v or ("unknown", "content not checked (link target is not named *.ko* and the input is an archive)")

        def feed(self, parts, kind, link=None, opener=None, size=0, layer=0):
            if not parts:
                return
            if kind == "symlink":
                if len(self.links) >= MAX_LINKS:
                    raise kc.InputError(f"映像的符號連結超過 {MAX_LINKS} 個")
                self.files.pop(parts, None)
                self.content.discard(parts)
                self.ko_check.pop(parts, None)
                self.links[parts] = link
                self.layer[parts] = layer
                return
            if kind != "file":
                if kind == "dir" and parts in self.links and self.layer.get(parts, -1) < layer:
                    del self.links[parts]          # 上層的資料夾蓋過下層同名的連結（docker 層）
                return
            if len(self.files) >= MAX_FILES:
                raise kc.InputError(f"映像的檔案超過 {MAX_FILES} 個")
            w = wanted(parts)
            if w is None:
                self._put(parts, b"", layer, False)
                if is_module_name(parts[-1]):
                    self.ko_check[parts] = ko_verdict(opener, size)
                return
            want, cap = w
            if size > cap or (want == "initrd" and self.initrd_bytes + size > MAX_INITRD_TOTAL):
                self._put(parts, b"", layer, False)
                self.too_big[parts] = size
                return
            try:
                data = kc.read_all(opener, size)
            except OSError as e:
                self._put(parts, b"", layer, False)
                self.unread[parts] = f"打不開（{e.strerror or type(e).__name__}）"
                return
            if want == "initrd":
                self.initrd_bytes += len(data)
            self._put(parts, data, layer, True)

        def hardlink(self, parts, target, layer):
            """tar 的硬連結：目標有讀內容就照樣讀；目標沒讀內容、這個名稱卻要內容 → 讀不到；其他當一般檔案。"""
            if not parts:
                return
            data = self.content_of(target) if target is not None else None
            if data is not None:
                self.feed(parts, "file", opener=lambda d=data: io.BytesIO(d), size=len(data), layer=layer)
            elif wanted(parts) is not None:
                self._put(parts, b"", layer, False)
                self.unread[parts] = "tar 的硬連結，目標的內容沒有收"
            else:
                v = self.ko_check.get(target) if target is not None else None
                self._put(parts, b"", layer, False)
                if is_module_name(parts[-1]):
                    # 目標也是 .ko*：沿用它的判斷；目標不是（沒有讀開頭）→ 不知道（照樣列）
                    self.ko_check[parts] = v or ("unknown", "tar hard link to a file whose content was not checked")

        def unreadable(self, parts, kind, raw):
            if parts and kind in ("unreadable", "unreadable_dir"):
                self.unread[parts] = "讀不到的資料夾" if kind == "unreadable_dir" else "讀不到（lstat 或 readlink 失敗）"

        def outside(self, parts, kind, opener, size):
            """刷機包裡 rootfs 以外的成員：只讀 <Linux_for_Tegra>/bootloader/l4t_initrd.img。"""
            if self.pkg_root is None or parts != self.pkg_root + PKG_INITRD:
                return
            label = "/".join(parts)
            if kind != "file":
                self.pkg_initrd = (label, None, f"不是一般檔案（{kind}）")
            elif size > MAX_INITRD:
                self.pkg_initrd = (label, None, f"超過上限（{size >> 20} MB）")
            else:
                self.pkg_initrd = (label, kc.read_all(opener, size), None)

        def whiteout(self, parts, layer, opaque=False):
            super().whiteout(parts, layer, opaque)
            n = len(parts)
            for d in (self.unread, self.too_big, self.ko_check):
                for k in [k for k in d if k[:n] == parts and (len(k) > n or not opaque) and self.layer.get(k, 0) < layer]:
                    del d[k]

    return KmodCollected()


def read_pkg_initrd_dir(src, strip):
    """--from 是解開的刷機包資料夾＋--prefix：<rootfs 的上層>/bootloader/l4t_initrd.img（不跟隨連結）。→ (路徑, bytes 或 None, 原因) 或 None。"""
    if not strip or len(strip) < 2:
        return None
    rel = strip[:-1] + PKG_INITRD
    p = os.path.join(src, *rel)
    label = "/".join(rel)
    for i in range(1, len(rel)):              # 中間的資料夾也不能是連結（不跟到別處）
        try:
            if not stat.S_ISDIR(os.lstat(os.path.join(src, *rel[:i])).st_mode):
                return label, None, f"{'/'.join(rel[:i])} 不是資料夾（可能是符號連結）"
        except FileNotFoundError:
            return None
        except OSError as e:
            return label, None, f"讀不到（{e.strerror}）"
    try:
        st = os.lstat(p)
    except FileNotFoundError:
        return None
    except OSError as e:
        return label, None, f"讀不到（{e.strerror}）"
    if not stat.S_ISREG(st.st_mode):
        return label, None, "不是一般檔案（可能是符號連結）"
    if st.st_size > MAX_INITRD:
        return label, None, f"超過上限（{st.st_size >> 20} MB）"
    try:
        with kernel_config().flash_package().open_nofollow(p) as f:
            return label, f.read(MAX_INITRD + 1), None
    except OSError as e:
        return label, None, f"讀不到（{e.strerror}）"


def read_image(src, prefix=None):
    kc = kernel_config()
    strip = kc.split_name(prefix) if prefix else None
    pkg_root = tuple(strip[:-1]) if strip and len(strip) >= 2 else None
    try:
        col, info = kc.collect(src, prefix, col=make_collected(pkg_root))
    except (kc.InputError, kc.flash_package().Fail) as e:
        raise InputError(str(e))
    except (tarfile.TarError, EOFError, zlib.error, lzma.LZMAError) as e:
        raise InputError(f"{os.path.basename(str(src))} 讀不完（{type(e).__name__}）")
    if col is None:
        raise Gap(f"{src} 是核心原始碼樹，不是 rootfs")
    if os.path.isdir(src):
        col.base_dir = os.path.join(src, *strip) if strip else src
    if os.path.isdir(src) and pkg_root:
        col.pkg_initrd = read_pkg_initrd_dir(src, strip)
    return col, info, kc.VFS(col)


def unread_check(col, vfs, extra_dirs=()):
    """讀不到的路徑：在要看的資料夾（模組資料夾、modprobe.d、/boot、extra_dirs）底下或是它們的上層 → Gap；其他 → notes 用的清單。"""
    dirs = set(extra_dirs)
    for d in [r for r in MODULE_ROOTS] + [tuple(x.split("/")) for x in MODPROBE_DIRS] + [("boot",)]:
        dirs.add(d)
        r = vfs.resolve(d)
        if r is not None:
            dirs.add(r)
    bad, other = [], []
    for p, why in sorted(col.unread.items()):
        (bad if any(under(p, d) or under(d, p) for d in dirs) else other).append(f"{show(p)}（{why}）")
    if bad:
        raise Gap(f"讀不到 {len(bad)} 個在模組資料夾、modprobe.d 或 /boot 底下（或上層、或模組資料夾裡的連結指到）的路徑：{'；'.join(bad[:5])}"
                  "（以有權限的帳號讀，或改用 rootfs tar／刷機包）")
    return other


# =====================================================================================================
# 2. 模組資料夾
# =====================================================================================================

def kernel_versions(col, vfs):
    """兩個模組根（/lib/modules、/usr/lib/modules）底下的版本資料夾（有任何檔案或連結的）。"""
    vers = set()
    for r in MODULE_ROOTS:
        rr = vfs.resolve(r)
        if rr is None:
            continue
        for v in vfs.children.get(rr, ()):
            p = rr + (v,)
            if p in col.files:
                continue
            if p in col.links:
                q = vfs.resolve(p)
                if q is None or q not in vfs.children or q in col.files:
                    continue
            vers.add(v)
    return sorted(vers)


def module_tree(col, vfs, ver):
    """/lib/modules/<ver>/ 與 /usr/lib/modules/<ver>/ → ({相對路徑}, 資訊, {走過的實際資料夾})。
    連結在映像裡解析；名稱是 .ko 的連結指到任何一般檔案都列（以連結的名稱）；同一個實際資料夾只走一次；build、source 不走。
    內容不是 ELF 可重定位檔的（ko_kind 是 not_module）不列，記在 info["not_module"]；判斷不了的（unknown）照樣列、記在 info["unchecked"]。"""
    found, info = set(), {"roots": [], "dangling": [], "symlinked_ko": 0, "unresolved_targets": [], "not_module": [], "unchecked": []}

    def add(lrel, target, shown):
        k, why = col.ko_kind(target)
        if k == "not_module":
            info["not_module"].append((shown, why))
            return False
        if k == "unknown":
            info["unchecked"].append((shown, why))
        found.add("/".join(lrel))
        return True
    seen = set()
    for r in MODULE_ROOTS:
        top = r + (ver,)
        real = vfs.resolve(top)
        if real is None or real not in vfs.children or real in col.files:
            continue
        info["roots"].append(show(top) + ("" if real == top else f" -> {show(real)}"))
        stack = [((), real)]
        while stack:
            rel, d = stack.pop()
            if d in seen:
                continue
            seen.add(d)
            for n in sorted(vfs.children.get(d, ())):
                if not rel and n in SKIP_IN_MODDIR:
                    continue
                p, lrel = d + (n,), rel + (n,)
                if p in col.links:
                    q = vfs.resolve(p)
                    if q is not None and q in col.files:
                        if is_module_name(n) and add(lrel, q, show(p)):
                            info["symlinked_ko"] += 1
                    elif q is not None and q in vfs.children:
                        stack.append((lrel, q))
                    else:
                        # 目標不在映像裡收到的東西：可能是讀不到的資料夾（build 用 unread_check 判 GAP），或真的不存在
                        if q is not None:
                            info["unresolved_targets"].append(q)
                        if is_module_name(n):
                            info["dangling"].append(show(p))
                elif p in col.files:
                    if is_module_name(n):
                        add(lrel, p, show(p))
                elif p in vfs.children:
                    stack.append((lrel, p))
    return found, info, seen


def outside_modules(col, vfs, seen, vers):
    """模組資料夾以外的 *.ko*（實際路徑不在走過的資料夾、也不在其他核心版本的模組資料夾）→
    (絕對路徑清單, 其他版本的個數, 不是模組的 [(路徑, 原因)], 判斷不了的 [(路徑, 原因)])。
    內容不是 ELF 可重定位檔的（文件 COPYING.x.ko.gz、vim 的 tutor.ko）不列；判斷不了的照樣列（偏保守）。"""
    others = set()
    for r in MODULE_ROOTS:
        rr = vfs.resolve(r)
        if rr is not None:
            others |= {rr + (v,) for v in vers}
    out, n_other, not_mod, unchecked = [], 0, [], []
    for p in col.files:
        if not is_module_name(p[-1]) or any(under(p, d) for d in seen):
            continue
        if any(under(p, d) for d in others):
            n_other += 1
            continue
        k, why = col.ko_kind(p)
        if k == "not_module":
            not_mod.append((show(p), why))
            continue
        if k == "unknown":
            unchecked.append((show(p), why))
        out.append(show(p))
    # 名稱是 .ko* 的符號連結（insmod /opt/v/x.ko 照樣載入連結指到的檔）：目標在映像裡 → 判斷目標的內容，是模組就以連結的路徑列；
    # 目標解不開、不在映像裡 → 判斷不了，照樣列（偏保守）；目標是資料夾 → 不是模組
    for p in list(col.links):
        if not is_module_name(p[-1]) or any(under(p, d) for d in seen):
            continue
        if any(under(p, d) for d in others):
            n_other += 1
            continue
        q = vfs.resolve(p)
        if q is not None and q in vfs.children and q not in col.files:
            continue
        if q is None or q not in col.files:
            k, why = "unknown", f"symlink to {str(col.links[p])[:120]}, which is not a file in the image (or cannot be resolved)"
        else:
            k, why = col.ko_kind(q)
            why = f"symlink to {show(q)}: {why}"
        if k == "not_module":
            not_mod.append((show(p), why))
            continue
        if k == "unknown":
            unchecked.append((show(p), why))
        out.append(show(p))
    return sorted(out), n_other, sorted(not_mod), sorted(unchecked)


def builtin_list(col, vfs, ver, notes):
    seen, out, srcs = set(), set(), []
    for r in MODULE_ROOTS:
        p = vfs.resolve(r + (ver, "modules.builtin"))
        if p is None or p in seen:
            continue
        seen.add(p)
        if p in col.too_big:
            notes.append(f"{show(p)} 超過 {MAX_SMALL >> 20} MB，沒有讀")
            continue
        data = col.content_of(p)
        if data is None:
            continue
        names = {ln.strip() for ln in data.decode("utf-8", "replace").splitlines() if ln.strip() and not ln.startswith("#")}
        srcs.append((show(p), names))
        out |= names
    if len(srcs) == 2 and srcs[0][1] != srcs[1][1]:
        notes.append(f"{srcs[0][0]} 與 {srcs[1][0]} 內容不同：取聯集")
    if not srcs:
        notes.append(f"映像沒有 modules.builtin（/lib/modules/{ver}/、/usr/lib/modules/{ver}/）：modules_builtin 寫 null（K2 不判「已移除」）")
        return None, []
    if not out:
        notes.append("modules.builtin 是空的：modules_builtin 寫 null（K2 不判「已移除」）")
        return None, [s for s, _ in srcs]
    return sorted(out), [s for s, _ in srcs]


# =====================================================================================================
# 3. modprobe.d（kmod 的規則）
# =====================================================================================================

def conf_lines(text):
    """一個 .conf → (行, 有沒有夾在行中間的 CR)。每個元素就是檔案裡的一個實體行（只用 LF 分行，行尾的 CR／CRLF 去掉，頭尾空白去掉）：
    kmod 的續行（行尾的反斜線）不接起來，原樣保留反斜線（消費端看到反斜線就不認 install 的擋住；接起來會丟掉這個證據）。
    空行與 # 開頭的註解不收，但含反斜線的註解照收（kmod 的續行可能把下一行併進註解）。行中間的 CR 換成空白（不輸出 CR），
    呼叫端另外把擋住行全部不放（kmod 怎麼讀那一行不確定）。"""
    out, cr = [], False
    for raw in text.split("\n"):
        if raw.endswith("\r"):
            raw = raw[:-1]
        if "\r" in raw:
            cr = True
            raw = raw.replace("\r", " ")
        line = raw.strip()
        if not line or (line.startswith("#") and "\\" not in line):
            continue
        out.append(line)
        if len(out) >= MAX_CONF_LINES:
            break
    return out, cr


def combine_modprobe(dirs):
    """dirs：[(資料夾標籤, [(檔名, 狀態, bytes 或 None, 連結目標)])]（優先順序由高到低；狀態 used｜masked｜unreadable）→
    (行, 每行的來源, 檔案紀錄, 被蓋掉的檔, notes)。同名檔只用最前面那個，依檔名排序後逐行（kmod）。"""
    chosen, files, overridden, notes = {}, [], [], []
    for label, entries in dirs:
        for n, status, data, link in sorted(entries):
            f = f"{label}/{n}"
            if n in chosen:
                overridden.append({"file": f, "by": chosen[n]})
                continue
            chosen[n] = f
            rec = {"file": f, "status": status, "lines": 0}
            if link:
                rec["link"] = link
            if status == "unreadable":
                notes.append(f"{f}{' 連到 ' + link if link else ''}：內容沒有讀到，同名的低優先檔照樣當作被蓋掉")
            elif status == "used":
                rec["_data"] = data
            files.append(rec)
    lines, sources = [], []
    for rec in sorted(files, key=lambda r: r["file"].rsplit("/", 1)[-1]):
        data = rec.pop("_data", None)
        if data is None:
            continue
        ls, cr = conf_lines(data.decode("utf-8", "replace"))
        rec["lines"], rec["sha256"] = len(ls), hashlib.sha256(data).hexdigest()
        if cr:
            rec["carriage_return_inside_line"] = True
            notes.append(f"{rec['file']} 有夾在行中間的 CR：換成空白輸出；kmod 怎麼讀那一行不確定，擋住行全部不放")
        for ln in ls:
            lines.append(ln)
            sources.append({"line": ln, "file": rec["file"]})
    return lines, sources, sorted(files, key=lambda r: r["file"]), overridden, notes


def rootfs_modprobe_dirs(col, vfs):
    """rootfs 的 modprobe.d → combine_modprobe 的輸入、/run/modprobe.d 裡不讀的檔。資料夾連到沒收內容的位置 → Gap。"""
    known = {tuple(d.split("/")) for d in MODPROBE_DIRS}
    out, seen, runtime = [], [], []
    for d in MODPROBE_DIRS:
        dp = tuple(d.split("/"))
        r = vfs.resolve(dp)
        if r is None:
            raise Gap(f"/{d} 的連結解析不了（太多層）")
        if r in seen:
            continue
        seen.append(r)
        if r != dp and r not in known and r[-1:] != ("modprobe.d",):
            if r in vfs.children or any(dp[:i] in col.links for i in range(1, len(dp) + 1)):
                raise Gap(f"/{d} 連到 {show(r)}，那裡的檔案沒有讀內容（只讀 */modprobe.d/ 底下的）：不知道有效的 modprobe 設定")
        entries = []
        for n in sorted(vfs.children.get(r, ())):
            if not n.endswith(CONF_EXT) or n.startswith("."):
                continue
            p = r + (n,)
            if p in col.links:
                tgt = col.links[p]
                q = vfs.resolve(p)
                if tgt == "/dev/null" or q == ("dev", "null"):
                    entries.append((n, "masked", None, tgt))
                    continue
                data = col.content_of(q) if q is not None else None
                entries.append((n, "used", data, tgt) if data is not None else (n, "unreadable", None, tgt))
            elif p in col.files:
                data = col.content_of(p)
                entries.append((n, "used", data, None) if data is not None else (n, "unreadable", None, None))
        if d in RUNTIME_DIRS:
            runtime += [f"/{d}/{e[0]}" for e in entries]
            continue
        out.append(("/" + d, entries))
    return out, runtime


# =====================================================================================================
# 4. initramfs（newc cpio；可以是多段、壓縮）
# =====================================================================================================

class CpioError(Exception):
    pass


def cpio_wants(name):
    """initramfs 裡要讀內容的檔：modprobe.d 的 .conf、.alias。"""
    t = name.lstrip("./").split("/")
    return len(t) >= 2 and t[-2] == "modprobe.d" and t[-1].endswith(CONF_EXT)


class Cpio:
    """逐段餵入的 newc cpio 解析器：記名稱與種類；modprobe.d 的設定另留內容（cpio_wants），其他內容跳過不留。"""

    def __init__(self, limit=MAX_CPIO_OUT):
        self.buf, self.skip, self.total, self.limit = bytearray(), 0, 0, limit
        self.in_archive, self.trailers, self.entries = False, 0, []
        self.data, self.cap = {}, None          # 名稱 → 內容；正在收的 [名稱, 還要幾個位元組, bytearray]

    def clean(self):
        return not self.in_archive and not self.skip and not any(self.buf)

    def _take(self, view):
        """跳過（或收下）最多 self.skip 個位元組；回傳用掉的數量。"""
        n = min(self.skip, len(view))
        if self.cap is not None and self.cap[1] > 0:
            k = min(n, self.cap[1])
            self.cap[2] += view[:k]
            self.cap[1] -= k
            if self.cap[1] == 0:
                self.data[self.cap[0]] = bytes(self.cap[2])
        self.skip -= n
        if not self.skip:
            self.cap = None
        return n

    def feed(self, data):
        """餵入；遇到不是 cpio 的資料（兩個 archive 之間）→ 回傳剩下的位元組（呼叫端判斷是不是壓縮的下一段），否則 None。"""
        self.total += len(data)
        if self.total > self.limit:
            raise CpioError(f"解壓後超過 {self.limit >> 30} GB")
        if self.skip and not self.buf:
            data = data[self._take(memoryview(data)):]
        self.buf += data
        b, pos = self.buf, 0
        while True:
            if self.skip:
                pos += self._take(memoryview(b)[pos:])
                if self.skip:
                    break
            if not self.in_archive:
                while pos < len(b) and b[pos] == 0:
                    pos += 1
                if len(b) - pos < 6:
                    break
                if bytes(b[pos:pos + 6]) not in CPIO_MAGIC:
                    rest = bytes(b[pos:])
                    self.buf = bytearray()
                    return rest
                self.in_archive = True
            if len(b) - pos < 110:
                break
            h = bytes(b[pos:pos + 110])
            if h[:6] not in CPIO_MAGIC:
                raise CpioError("cpio 的標頭不對（資料損毀或截斷）")
            try:
                mode, fsize, nsize = int(h[14:22], 16), int(h[54:62], 16), int(h[94:102], 16)
            except ValueError:
                raise CpioError("cpio 的標頭不是十六進位")
            if not 1 <= nsize <= 4096:
                raise CpioError("cpio 的檔名長度不對")
            hlen = (110 + nsize + 3) & ~3
            if len(b) - pos < hlen:
                break
            name = bytes(b[pos + 110:pos + 110 + nsize - 1]).decode("utf-8", "replace")
            pos += hlen
            if name == "TRAILER!!!":
                self.in_archive = False
                self.trailers += 1
                continue
            typ = mode & 0o170000
            self.entries.append((name, typ))
            self.skip = (fsize + 3) & ~3
            if typ == S_IFREG and fsize <= MAX_CONF and cpio_wants(name):
                self.cap = [name, fsize, bytearray()]
                if fsize == 0:
                    self.data[name] = b""
        del self.buf[:pos]
        return None


def _decompress_py(d, data, cp):
    """Python 的解壓物件；回傳這一段後面剩下的位元組。"""
    for i in range(0, len(data), 1 << 20):
        chunk = data[i:i + (1 << 20)]
        out = d.decompress(chunk)
        if out and cp.feed(out) is not None:
            raise CpioError("壓縮段裡有不是 cpio 的資料")
        if d.eof:
            return d.unused_data + data[i + len(chunk):]
    if hasattr(d, "flush"):
        out = d.flush()
        if out and cp.feed(out) is not None:
            raise CpioError("壓縮段裡有不是 cpio 的資料")
    if not d.eof:
        raise CpioError("壓縮資料截斷")
    return b""


def _decompress_tool(tool, data, cp):
    """主機的解壓程式（zstd、lz4）：資料從 stdin 餵進去，輸出串流給解析器；不寫檔。整段（去掉結尾的 0）都是這個格式。"""
    data = data.rstrip(b"\0")
    p = subprocess.Popen([tool, "-d", "-c", "-q"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    def writer():
        try:
            p.stdin.write(data)
        except (BrokenPipeError, OSError):
            pass
        finally:
            try:
                p.stdin.close()
            except OSError:
                pass
    th = threading.Thread(target=writer, daemon=True)
    th.start()
    try:
        while True:
            out = p.stdout.read(1 << 20)
            if not out:
                break
            if cp.feed(out) is not None:
                raise CpioError("壓縮段裡有不是 cpio 的資料")
    except BaseException:
        p.kill()
        raise
    finally:
        p.stdout.close()
        rc = p.wait()
        th.join(5)
    if rc != 0:
        raise CpioError(f"{os.path.basename(tool)} 解壓失敗（exit {rc}）")
    return b""


def zstd_decoder():
    try:
        from compression import zstd      # Python 3.14 起
        return ("py", zstd.ZstdDecompressor)
    except ImportError:
        t = shutil.which("zstd")
        return ("tool", t) if t else None


def lz4_decoder():
    t = shutil.which("lz4")
    return ("tool", t) if t else None


def parse_initramfs(data):
    """initramfs 的位元組 → (Cpio, [壓縮方式])。讀不了 → CpioError。"""
    cp, methods, rest = Cpio(), [], data
    while rest:
        r = cp.feed(rest)
        if r is None:
            break
        rest = r
        if not cp.clean():
            raise CpioError("cpio 沒有結尾就接了其他資料")
        if rest[:2] == b"\x1f\x8b":
            methods.append("gzip")
            rest = _decompress_py(zlib.decompressobj(31), rest, cp)
        elif rest[:6] == b"\xfd7zXZ\x00":
            methods.append("xz")
            rest = _decompress_py(lzma.LZMADecompressor(lzma.FORMAT_XZ), rest, cp)
        elif rest[:3] == b"\x5d\x00\x00":
            methods.append("lzma")
            rest = _decompress_py(lzma.LZMADecompressor(lzma.FORMAT_ALONE), rest, cp)
        elif rest[:3] == b"BZh":
            methods.append("bzip2")
            rest = _decompress_py(bz2.BZ2Decompressor(), rest, cp)
        elif rest[:4] == b"\x28\xb5\x2f\xfd":
            methods.append("zstd")
            dec = zstd_decoder()
            if dec is None:
                raise CpioError("zstd 壓縮：這個 Python 沒有 compression.zstd，主機也沒有 zstd")
            rest = _decompress_py(dec[1](), rest, cp) if dec[0] == "py" else _decompress_tool(dec[1], rest, cp)
        elif rest[:4] == b"\x02\x21\x4c\x18":
            methods.append("lz4")
            dec = lz4_decoder()
            if dec is None:
                raise CpioError("lz4 壓縮：主機沒有 lz4")
            rest = _decompress_tool(dec[1], rest, cp)
        else:
            raise CpioError(f"不認得的格式（開頭 {rest[:4].hex()}）")
        if not cp.clean():
            raise CpioError("壓縮段的 cpio 沒有結尾（截斷）")
    if not cp.clean():
        raise CpioError("cpio 截斷")
    if not cp.trailers:
        raise CpioError("不是 cpio（沒有 TRAILER!!!）")
    return cp, methods


def initramfs_modprobe(cp):
    """initramfs 的 modprobe.d → combine_modprobe 的輸入（同樣的優先順序；/run 不讀）。"""
    by = {}
    for name, typ in cp.entries:
        t = tuple(x for x in name.split("/") if x not in ("", "."))
        if len(t) < 2 or t[-2] != "modprobe.d" or not t[-1].endswith(CONF_EXT) or t[-1].startswith("."):
            continue
        d = "/".join(t[:-1])
        if typ == S_IFREG and name in cp.data:
            by.setdefault(d, []).append((t[-1], "used", cp.data[name], None))
        elif typ in (S_IFREG, S_IFLNK):
            by.setdefault(d, []).append((t[-1], "unreadable", None, "link" if typ == S_IFLNK else None))
    return [("/" + d, by.get(d, [])) for d in MODPROBE_DIRS if d not in RUNTIME_DIRS and d in by]


def initramfs_candidates(col, vfs, ver, notes):
    """rootfs 裡要讀的 initrd：/boot（在映像裡解析）的 initrd*、initramfs*（檔名含別的核心版本的不讀）＋ extlinux.conf 的 INITRD。
    → [(parts, 為什麼)]、[(標籤, 讀不了的原因)]、/boot 的實際位置。"""
    cands, unread, seen = [], [], set()

    def add(p, why):
        if p not in seen:
            seen.add(p)
            cands.append((p, why))
    boot = vfs.resolve(("boot",))
    names = sorted(vfs.children.get(boot, ())) if boot is not None else []
    for n in names:
        if not INITRD_RE.match(n):
            continue
        p = boot + (n,)
        if p in col.links:
            q = vfs.resolve(p)
            if q is None or q not in col.files:
                notes.append(f"/boot/{n} 連到 {col.links[p]}（映像裡沒有這個檔）：不讀")
            continue
        if p not in col.files:
            continue
        if VER_IN_NAME.search(n) and ver not in n:
            notes.append(f"/boot/{n} 看起來是別的核心的 initramfs，不讀")
            continue
        add(p, "/boot")
    ext = col.content_of(vfs.resolve(("boot", "extlinux", "extlinux.conf")) or ())
    if ext is not None:
        for ln in ext.decode("utf-8", "replace").splitlines():
            t = ln.split()
            if len(t) >= 2 and t[0].upper() == "INITRD":
                q = vfs.resolve(tuple(x for x in t[1].split("/") if x))
                if q is not None and q in col.files and INITRD_RE.match(q[-1]):
                    add(q, "extlinux.conf INITRD")
                else:
                    unread.append((f"extlinux.conf INITRD {t[1][:120]}", "映像裡沒有這個檔，或名稱不是 initrd*、initramfs*（沒有讀內容）"))
    return cands, unread, boot


def read_initramfs(label, data, ver, why, kc, notes):
    """→ (模組, 紀錄, modprobe 的輸入 或 None, 讀不了的原因 或 None)。"""
    try:
        cp, methods = parse_initramfs(data)
    except CpioError as e:
        return set(), {"path": label, "found_by": why, "status": "unreadable", "reason": str(e),
                       "sha256": hashlib.sha256(data).hexdigest()}, None, str(e)
    mods, other = set(), set()
    for name, typ in cp.entries:
        if typ not in (S_IFREG, S_IFLNK) or not is_module_name(name):
            continue
        parts = kc.split_name(name)
        mp = kc.modules_part(parts) if parts else None
        if mp is None:
            continue
        if mp[0] == ver:
            mods.add(f"initramfs:{label.lstrip('/')}:{'/'.join(mp[1])}")
        else:
            other.add(mp[0])
    if other:
        notes.append(f"{label} 有別的核心（{'、'.join(sorted(other)[:3])}）的模組：不列")
    md = initramfs_modprobe(cp)
    rec = {"path": label, "found_by": why, "status": "read", "compression": methods or ["none"], "entries": len(cp.entries),
           "modules": len(mods), "other_kernel_versions": sorted(other), "sha256": hashlib.sha256(data).hexdigest(),
           "modprobe_d_files": sum(len(e) for _, e in md)}
    return mods, rec, md, None


# =====================================================================================================
# 5. lsmod、映像雜湊
# =====================================================================================================

def parse_lsmod(text):
    """lsmod 或 /proc/modules 的文字 → (名稱清單, 讀不懂的行數)。"""
    names, bad = set(), 0
    for i, ln in enumerate(text.splitlines()):
        t = ln.split()
        if not t:
            continue
        if i == 0 and t[0] == "Module":
            continue
        if len(t) >= 2 and MODNAME_RE.match(t[0]) and t[1].isdigit():
            names.add(t[0])
        else:
            bad += 1
    return sorted(names), bad


def read_lsmod_file(path):
    """--lsmod 的檔案 → (名稱清單, 出處, notes)。"""
    with open(path, "rb") as f:
        data = f.read((4 << 20) + 1)
    if len(data) > 4 << 20:
        raise InputError(f"{path} 超過 4 MB，不像 lsmod 的輸出")
    names, bad = parse_lsmod(data.decode("utf-8", "replace"))
    notes = [f"{os.path.basename(path)}：{bad} 行讀不懂（不是 lsmod／/proc/modules 的格式），略過"] if bad else []
    return names, f"lsmod file {os.path.basename(path)}", notes


def board_inputs(board, ver, notes):
    """board_import 匯入的板子結果（最新的每塊板子一筆：{"stem", "kernel", "loaded", "bad", "modules_disabled"}）→
    (loaded, 出處, modules_disabled)。只用 uname -r 等於 ver 的板子；有一塊沒有 lsmod 就整個 null（只用其他板子會少列載入的模組）。
    modules_disabled：每塊都是 1 才 true，有一塊 0 就 false，其他 null。"""
    same = [r for r in board if r.get("kernel") == ver]
    for r in board:
        if r.get("kernel") != ver:
            notes.append(f"board-test/{r['stem']}：板子的核心是 {r.get('kernel') or '不知道（os.txt 沒有 uname）'}，不是 {ver}：lsmod 不用")
    if not same:
        return None, "no board run with this kernel", None
    miss = [r["stem"] for r in same if not r.get("loaded")]
    for r in same:
        if r.get("bad"):
            notes.append(f"board-test/{r['stem']}/lsmod.txt：{r['bad']} 行讀不懂，略過")
    md = [r.get("modules_disabled") for r in same]
    mdv = False if False in md else True if md and all(x is True for x in md) else None
    if miss:
        notes.append(f"{'、'.join('board-test/' + m for m in miss)} 沒有 lsmod.txt（或是空的）：loaded 寫 null（舊版 board-on-device.sh 沒有收；重測）")
        return None, "board run without lsmod", mdv
    names = sorted({n for r in same for n in r["loaded"]})
    return names, "lsmod from " + ", ".join(f"board-test/{r['stem']}" for r in same), mdv


def scan_image_ids(scan):
    """sca-scan 的輸出資料夾 → [(鍵, 雜湊)]（meta.json 或 meta.json.xz 的 digest、image_id、content_sha256；cra_report 比對的值）。"""
    for n in ("meta.json", "meta.json.xz"):
        p = Path(scan) / n
        if p.is_file() and not p.is_symlink():
            try:
                raw = p.read_bytes() if n.endswith(".json") else lzma.decompress(p.read_bytes())
                m = json.loads(raw.decode("utf-8"))
            except (OSError, ValueError, lzma.LZMAError) as e:
                raise InputError(f"{p} 讀不懂（{type(e).__name__}）")
            if not isinstance(m, dict):
                raise InputError(f"{p} 不是 JSON 物件")
            out = []
            for k in ("digest", "image_id", "content_sha256"):
                x = IMAGE_RE.match(str(m.get(k) or "").strip().lower())
                if x and x.group(1) not in [h for _, h in out]:
                    out.append((k, x.group(1)))
            return out, str(p)
    return None, None


def resolve_image(scan, explicit):
    """→ ("sha256:<hex>", 出處)。"""
    ids, where = scan_image_ids(scan) if scan else (None, None)
    if explicit:
        m = IMAGE_RE.match(explicit.strip().lower())
        if not m:
            raise InputError(f"--image-sha256 要是 sha256:<64 個十六進位字元>：{explicit[:80]}")
        if ids is not None and m.group(1) not in [h for _, h in ids]:
            raise Gap(f"--image-sha256 {m.group(1)[:12]}… 不是這次掃描的映像（{where}："
                      f"{'、'.join(f'{k} {h[:12]}…' for k, h in ids) or '沒有映像雜湊'}）")
        return "sha256:" + m.group(1), "--image-sha256" + (f" (matches {where})" if ids else "")
    if scan and ids is None:
        raise Gap(f"{scan} 沒有 meta.json：不知道掃描的映像雜湊（或用 --image-sha256）")
    if not ids:
        raise Gap(f"{where or '沒有 --scan'}：沒有映像雜湊（digest、image_id、content_sha256）；K2 只用取自掃描映像的清單"
                  if scan else "沒有映像雜湊：要給 --scan <sca-scan 的輸出> 或 --image-sha256")
    k, h = ids[0]
    return "sha256:" + h, f"{where} {k}"


# =====================================================================================================
# 6. 組合、檢查、寫入
# =====================================================================================================

def consumer_blocked(vx, lines, softdep, names):
    """消費端（vex_export）會判「被 install 擋住」的模組 → {名稱: 擋住的那一行}。names：要問的模組（正規化後的名稱）。
    支援兩版的消費端：install_block（fnmatch、第一條符合的生效、softdep 讓 install 失效；softdep 是 modules_softdep 的行，None＝沒有收）
    與舊版（modprobe_state 回傳 {模組: [行]}）。"""
    st = vx.modprobe_state(lines)
    if hasattr(vx, "install_block"):
        _, inst, soft = st
        if softdep is None:
            soft = None
        else:
            mf, mbs = vx.modprobe_lines(softdep)
            soft = soft + [vx.kmod_pattern(f[1]) for f in mf if f[0] == "softdep" and len(f) >= 2] + ([None] if mbs else [])
        out = {}
        for m in names:
            ln = vx.install_block(m, inst, soft)
            if ln:
                out[m] = ln
        return out
    blocked = st[1]
    return {m: blocked[m][0] for m in names if m in blocked}


def _fields(ln):
    """消費端（kmod）的分欄：只用空白與 tab。"""
    return [x for x in str(ln).replace("\t", " ").split(" ") if x]


def _uncertain(vx, ln, pat):
    """樣式不確定（kmod_pattern 是 None：[、]、[^ 等）或行裡有反斜線：消費端遇到它就停止判擋住；拿掉它反而可能讓後面的行生效。"""
    return "\\" in str(ln) or (hasattr(vx, "kmod_pattern") and vx.kmod_pattern(pat) is None)


def _install_matches(vx, pat, m):
    if hasattr(vx, "kmod_pattern"):
        p = vx.kmod_pattern(pat)
        return p is not None and fnmatch.fnmatchcase(m, p)
    return vx.norm_module(pat) == m


def withhold_blocks(lines, sources, vx, drop=None, file_reason=None, all_reason=None):
    """不放進 modprobe_d 的「擋住」行（install <樣式> /bin/false 之類，BLOCK_CMDS）：
    all_reason：全部的擋住行（拿光之後沒有任何模組算被擋）；file_reason：{來源檔: 原因}；drop：{模組: 原因}（符合這個模組的擋住行）。
    逐檔、逐模組時不拿樣式不確定或有反斜線的行（消費端本來就在那裡停止判擋住，拿掉會讓後面的行生效）。
    → (行, 來源, 不放的紀錄)。呼叫端要用 guarded_withhold（檢查拿掉之後沒有新的模組變成被擋）。"""
    drop, file_reason = drop or {}, file_reason or {}
    keep_l, keep_s, withheld = [], [], []
    for ln, src in zip(lines, sources):
        f = _fields(ln)
        why = None
        if len(f) >= 3 and f[0] == "install" and " ".join(f[2:]) in vx.BLOCK_CMDS:
            if all_reason:
                why = all_reason
            elif not _uncertain(vx, ln, f[1]):
                why = file_reason.get(src["file"]) or next((r for m, r in sorted(drop.items()) if _install_matches(vx, f[1], m)), None)
        if why:
            withheld.append({"line": ln, "file": src["file"], "because": why})
        else:
            keep_l.append(ln)
            keep_s.append(src)
    return keep_l, keep_s, withheld


GUARD_REASON = "withholding only some block lines would make another module count as blocked; all block lines withheld"


def guarded_withhold(lines, sources, vx, softdep, names, notes, drop=None, file_reason=None, all_reason=None):
    """withhold_blocks，再用消費端自己的判定（consumer_blocked）比較拿掉前後：names（映像裡的模組）裡有任何模組拿掉後才變成被擋 →
    改成全部的擋住行都不放（拿光之後沒有模組算被擋），寫 note。保證：拿掉後被擋的模組 ⊆ 拿掉前的。"""
    kl, ks, wh = withhold_blocks(lines, sources, vx, drop, file_reason, all_reason)
    if not wh:
        return kl, ks, wh
    before = set(consumer_blocked(vx, lines, softdep, names))
    new = set(consumer_blocked(vx, kl, softdep, names)) - before
    if new:
        notes.append(f"只拿掉部分擋住行會讓 {'、'.join(sorted(new)[:5])} 變成被擋：改成 modprobe_d 的擋住行全部不放")
        kl, ks, wh = withhold_blocks(lines, sources, vx, all_reason=GUARD_REASON)
    return kl, ks, wh


def softdep_list(col, vfs, ver, notes):
    """/lib/modules/<ver>/、/usr/lib/modules/<ver>/ 的 modules.softdep → (原始行 或 None, 來源)。第一行要是 depmod 的標頭；
    兩個都有而內容不同 → 聯集（標頭在前；softdep 多只會讓 install 更不算被擋）。沒有讀到內容（太大）→ Gap。"""
    seen, out, srcs = set(), [], []
    for r in MODULE_ROOTS:
        p = vfs.resolve(r + (ver, "modules.softdep"))
        if p is None or p in seen or p not in col.files:
            continue
        seen.add(p)
        data = col.content_of(p)
        if data is None:
            raise Gap(f"{show(p)} 讀不到內容（{col.unread.get(p) or ('超過 ' + str(MAX_SMALL >> 20) + ' MB') }）")
        ls = [x.rstrip("\r") for x in data.decode("utf-8", "replace").split("\n") if x.strip()]
        if not ls or ls[0].strip() != SOFTDEP_HEADER:
            notes.append(f"{show(p)} 的第一行不是 depmod 的標頭（{SOFTDEP_HEADER}）：不寫 modules_softdep（K2 不認 install 的擋住）")
            return None, [show(p)]
        srcs.append(show(p))
        for x in ls:
            if x not in out:
                out.append(x)
    if not srcs:
        notes.append(f"映像沒有 modules.softdep（/lib/modules/{ver}/、/usr/lib/modules/{ver}/）：不寫 modules_softdep"
                     "（K2 不認 install 的擋住，只剩 modules_disabled）")
        return None, []
    return out, srcs


def build(src, prefix=None, kernel_version=None, owner=None, captured=None, image=None, image_from="",
          loaded=None, loaded_from=None, modules_disabled=None, accept_unread_initramfs=False, input_notes=(), board=None):
    """→ (文件, 來源紀錄, notes)。輸入不足 → Gap。input_notes：呼叫端的注意事項（lsmod 讀不懂的行等），併進 notes。"""
    kc = kernel_config()
    vx = vex_export()
    col, info, vfs = read_image(src, prefix)
    notes = list(input_notes)
    unread_check(col, vfs)
    vers = kernel_versions(col, vfs)
    if kernel_version:
        if kernel_version not in vers:
            raise Gap(f"映像沒有核心模組資料夾 /lib/modules/{kernel_version}/ 或 /usr/lib/modules/{kernel_version}/（有：{'、'.join(vers) or '沒有'}）")
        ver = kernel_version
    elif len(vers) == 1:
        ver = vers[0]
    elif not vers:
        raise Gap("映像沒有核心模組資料夾（/lib/modules/<版本>/、/usr/lib/modules/<版本>/）：不寫 kernel-modules.json")
    else:
        raise Gap(f"映像有 {len(vers)} 個核心模組資料夾（{'、'.join(vers[:4])}）：用 --kernel-version 指定，不猜")
    mods, tree, seen = module_tree(col, vfs, ver)
    # 連結走到的資料夾、以及連結指到卻沒有內容的位置（可能是讀不到的資料夾）也要讀得到
    other_unread = unread_check(col, vfs, set(seen) | set(tree["unresolved_targets"]))
    if other_unread:
        notes.append(f"讀不到 {len(other_unread)} 個其他位置的路徑（可能藏著 .ko，沒有列）：{'；'.join(other_unread[:5])}")
    for d in tree["dangling"][:20]:
        notes.append(f"{d} 是指到映像裡沒有的位置的連結：不列")
    if not mods:
        nm = len(tree["not_module"])
        raise Gap(f"/lib/modules/{ver}/、/usr/lib/modules/{ver}/ 底下沒有任何 .ko" + (f"（{nm} 個名稱是 .ko* 的檔不是 ELF 模組）" if nm else "")
                  + "：modules_in_image 不能是空的（消費端會當成全部移除）")
    out_mods, n_other_ver, out_not_mod, out_unchecked = outside_modules(col, vfs, seen, [v for v in vers if v != ver])
    if out_mods:
        notes.append(f"模組資料夾以外有 {len(out_mods)} 個 .ko（以映像裡的絕對路徑列進 modules_outside_dirs；可以用 insmod 載入，"
                     "K2 不判同名的模組「已移除」）：" + "、".join(out_mods[:5]))
    # 不是模組的 .ko*：模組資料夾裡的（不該有，可能是損毀或放錯）→ notes（ATTENTION）；模組資料夾以外的（文件的 COPYING.x.ko.gz、
    # vim 的 tutor.ko）→ info（只是說明，不影響狀態）
    not_mod, info_notes = sorted(tree["not_module"] + out_not_mod), []
    if tree["not_module"]:
        notes.append(f"模組資料夾裡有 {len(tree['not_module'])} 個名稱是 .ko* 的檔不是核心模組（內容不是 ELF 可重定位檔），不列"
                     "（ignored_non_module_files）：" + "、".join(f"{a}（{b}）" for a, b in sorted(tree["not_module"])[:5]))
    if out_not_mod:
        info_notes.append(f"模組資料夾以外有 {len(out_not_mod)} 個名稱是 .ko* 的檔不是核心模組（內容不是 ELF 可重定位檔），不列"
                          "（ignored_non_module_files）：" + "、".join(f"{a}（{b}）" for a, b in out_not_mod[:5]))
    unchecked = sorted(tree["unchecked"] + out_unchecked)
    if unchecked:
        notes.append(f"{len(unchecked)} 個 .ko* 的內容判斷不了（讀不到、解不開），照樣當作模組列出（unchecked_module_files）："
                     + "、".join(f"{a}（{b}）" for a, b in unchecked[:5]))
    builtin, builtin_src = builtin_list(col, vfs, ver, notes)
    softdep, softdep_src = softdep_list(col, vfs, ver, notes)
    if softdep is not None and "modules_softdep" not in getattr(vx, "KMOD_KEYS", ()):
        notes.append("這版的 vex_export 還不認得 modules_softdep：不寫（K2 照舊版的規則判 install）")
        softdep = None
    md_dirs, runtime = rootfs_modprobe_dirs(col, vfs)
    md_lines, md_sources, md_files, md_over, md_notes = combine_modprobe(md_dirs)
    notes += md_notes
    if runtime:
        notes.append(f"映像裡的 /run/modprobe.d 有 {len(runtime)} 個檔（{'、'.join(runtime[:3])}）：開機後 /run 是 tmpfs，這些不生效，沒有讀"
                     "（執行時另外放進去的設定也不知道）")
    # initramfs：rootfs 的（讀不了 → GAP）＋刷機包的 l4t_initrd.img（讀不了 → ATTENTION）
    cands, ir_unread, boot = initramfs_candidates(col, vfs, ver, notes)
    ir_mods, ir_recs, ir_md = set(), [], []
    for p, why in cands:
        label = show(p)
        if p in col.too_big:
            ir_unread.append((label, f"超過上限（{col.too_big[p] >> 20} MB）"))
            ir_recs.append({"path": label, "found_by": why, "status": "unreadable", "reason": "too large"})
            continue
        data = col.content_of(p)
        if data is None:
            ir_unread.append((label, col.unread.get(p, "內容沒有讀到")))
            ir_recs.append({"path": label, "found_by": why, "status": "unreadable", "reason": col.unread.get(p, "content not read")})
            continue
        m, rec, md, err = read_initramfs(label, data, ver, why, kc, notes)
        ir_recs.append(rec)
        if err:
            ir_unread.append((label, err))
            continue
        ir_mods |= m
        ir_md.append((label, m, combine_modprobe(md)[0]))
    if not cands and not ir_unread:
        notes.append(f"映像的 /boot{'（' + show(boot) + '）' if boot not in (None, ('boot',)) else ''} 沒有 initrd*、initramfs*："
                     "沒有讀到 initramfs 的模組（確認這個映像開機不用 initramfs）")
    pkg = col.pkg_initrd
    if pkg is not None:
        label, data, why = pkg
        if data is None:
            ir_unread.append((label, why))
            ir_recs.append({"path": label, "found_by": "flash package", "status": "unreadable", "reason": why})
        else:
            m, rec, md, err = read_initramfs(label, data, ver, "flash package", kc, notes)
            ir_recs.append(rec)
            if err:
                ir_unread.append((label, err))
            else:
                ir_mods |= m
                ir_md.append((label, m, combine_modprobe(md)[0]))
    elif col.content_of(("etc", "nv_tegra_release")) is not None:
        notes.append("這是 L4T 映像，但輸入只有 rootfs：刷機包的 bootloader/l4t_initrd.img 沒有讀（要讀就用刷機包＋--prefix）")
    limitation = None
    if ir_unread:
        what = "；".join(f"{a}: {b}" for a, b in ir_unread)[:600]
        if not accept_unread_initramfs:
            raise Gap(f"initramfs 讀不了（{what}）：它的模組開機就能載入，漏掉會讓 K2 誤判「已移除」。"
                      "確認後要照寫（限制會寫進 source）加 --accept-unread-initramfs")
        limitation = f"initramfs NOT read ({what})"
        notes.append(f"initramfs 讀不了，照 --accept-unread-initramfs 寫出（限制寫在 source）：{what}")
    # 不放的擋住行：有 initramfs 沒讀到（全部）；/run/modprobe.d 有同名檔（執行時可能被換掉）；initramfs 有這個模組而它自己沒擋
    present_ir = {vx.norm_module(m) for _, mods_, _ in ir_md for m in mods_}
    rootfs_blocked = consumer_blocked(vx, md_lines, softdep, present_ir)
    drop = {}
    for label, mods_, ir_lines in ir_md:
        names = {vx.norm_module(m) for m in mods_}
        ir_blocked = consumer_blocked(vx, ir_lines, softdep, names)
        for m in sorted(names & set(rootfs_blocked)):
            if m not in ir_blocked:
                drop.setdefault(m, f"in {label} without a block there")
                notes.append(f"{m}：rootfs 的 modprobe.d 擋住，但 {label} 裡有這個模組、它的設定沒有擋：擋住的 install 行不放進 modprobe_d（開機早期可以載入）")
    run_names = {r.rsplit("/", 1)[-1] for r in runtime}
    file_reason = {f["file"]: "a same-name file in /run/modprobe.d may replace it at runtime" for f in md_files
                   if f["status"] == "used" and f["file"].rsplit("/", 1)[-1] in run_names and not f["file"].startswith("/etc/")}
    if file_reason:
        notes.append(f"/run/modprobe.d 有同名的檔，執行時可能換掉 {'、'.join(sorted(file_reason))}：它們的擋住行不放（無法證明生效）")
    all_reason = ("initramfs not read" if ir_unread else
                  "a modprobe.d file has a carriage return inside a line" if any(f.get("carriage_return_inside_line") for f in md_files)
                  else None)
    if ir_unread:
        notes.append("有 initramfs 沒讀到：被擋的模組都可能在裡面，modprobe.d 的擋住行全部不放進 modprobe_d（無法證明被擋）")
    all_mods = sorted(mods) + sorted(ir_mods)
    guard_names = {vx.norm_module(m) for m in all_mods + out_mods} | {vx.norm_module(f[1]) for f in map(_fields, md_lines)
                                                          if len(f) >= 3 and f[0] == "install"}
    md_lines, md_sources, withheld = guarded_withhold(md_lines, md_sources, vx, softdep, guard_names, notes, drop, file_reason, all_reason)
    if loaded is None and loaded_from is None and board:
        loaded, loaded_from, mdis = board_inputs(board, ver, notes)
        if modules_disabled is None:
            modules_disabled = mdis
    if loaded is not None:
        if not loaded:
            notes.append(f"{loaded_from}：沒有任何模組，loaded 寫 null（消費端不收 []）")
            loaded = None
        else:
            present = {vx.norm_module(m) for m in all_mods + out_mods}
            bad = sorted({vx.norm_module(m) for m in loaded} - present)
            if bad:
                raise Gap(f"{loaded_from} 有載入、卻不在映像的模組清單裡：{', '.join(bad[:8])}{' …' if len(bad) > 8 else ''}"
                          "（板子跑的多半不是這個映像或核心）；不寫 kernel-modules.json")
    if loaded is None and loaded_from is None:
        notes.append("沒有板子的 lsmod：loaded 寫 null（K2 對每個模組都標 K3，不判 not_affected）")
    sub = {"updates": 0, "extra": 0, "other": 0}
    for m in mods:
        top = m.split("/", 1)[0]
        sub[top if top in ("updates", "extra") else "other"] += 1
    src_txt = (f"image rootfs ({info.get('label')} {info.get('file') or info.get('path') or ''}"
               f"{', prefix ' + info['prefix'] if info.get('prefix') else ''}): {', '.join(tree['roots'])}"
               f"{f'; {len(out_mods)} .ko outside the module dirs' if out_mods else ''}"
               f"; initramfs: {', '.join(r['path'] + ' ' + r['status'] for r in ir_recs) or 'none found'}"
               f"; modprobe.d: {len(md_lines)} effective lines from {sum(1 for f in md_files if f['status'] == 'used')} files"
               f"{f' ({len(withheld)} install lines withheld: initramfs)' if withheld else ''}"
               f"; loaded: {loaded_from or 'not captured'}; image hash: {image_from}")
    if limitation:
        src_txt += f"; LIMITATION: {limitation}"
    doc = {"schema": SCHEMA, "image_sha256": image, "kernel_version": ver, "captured": captured, "owner": owner,
           "source": src_txt[:2000], "modules_in_image": all_mods, **({"modules_outside_dirs": out_mods} if out_mods else {}),
           "modules_builtin": builtin, "modprobe_d": md_lines,
           **({"modules_softdep": softdep} if softdep is not None else {}),
           "modules_disabled": modules_disabled, "loaded": sorted(set(loaded)) if loaded else None,
           "$comment": (f"Generated by tools/cra/kernel_modules.py {TOOL_VERSION}. modprobe_d holds the effective lines verbatim and in "
                        "effective order (same-name override applied; image /run/modprobe.d not used); each line's source file, the "
                        "overridden files and withheld lines are in kernel-modules.sources.json next to this file. Modules outside "
                        "the module dirs are listed by absolute path in modules_outside_dirs, initramfs modules as initramfs:<initrd>:<path>; "
                        "files named *.ko* that are not ELF relocatable objects are not modules and not listed (counted in the sources file)."
                        + (f" LIMITATION: {limitation}" if limitation else ""))}
    sources = {"schema": SOURCES_SCHEMA, "tool_version": TOOL_VERSION, "generated": now_utc(),
               "image_sha256": {"value": image, "from": image_from},
               "rootfs": {k: v for k, v in info.items() if k in ("type", "label", "file", "path", "prefix", "layers")},
               "kernel_version": ver, "kernel_versions_in_image": vers,
               "modules": {"roots": tree["roots"], "rootfs": len(mods), "updates": sub["updates"], "extra": sub["extra"],
                           "other": sub["other"], "via_symlink": tree["symlinked_ko"], "outside_module_dirs": out_mods,
                           "other_kernel_versions": n_other_ver, "initramfs": len(ir_mods), "dangling_links": tree["dangling"][:50],
                           "ignored_non_module_files": {"count": len(not_mod), "in_module_dirs": len(tree["not_module"]),
                                                        "examples": [{"path": a, "why": b} for a, b in not_mod[:20]]},
                           "unchecked_module_files": {"count": len(unchecked),
                                                      "examples": [{"path": a, "why": b} for a, b in unchecked[:20]]}},
               "modules_builtin": {"count": len(builtin) if builtin else None, "files": builtin_src},
               "modules_softdep": {"lines": len(softdep) if softdep is not None else None, "files": softdep_src},
               "modprobe_d": {"dirs_in_priority_order": ["/" + d for d in MODPROBE_DIRS], "runtime_not_read": runtime,
                              "files": md_files, "overridden": md_over, "lines": md_sources, "withheld": withheld},
               "initramfs": ir_recs, "initramfs_unread": [{"what": a, "reason": b} for a, b in ir_unread],
               "unreadable_paths": other_unread[:200],
               "loaded": {"from": loaded_from, "count": len(set(loaded)) if loaded else None},
               "modules_disabled": modules_disabled, "notes": notes,
               # 不影響狀態（OK／ATTENTION）的說明：模組資料夾以外不是模組的 .ko*
               "info": info_notes}
    return doc, sources, notes


def self_check(doc):
    """寫出前用消費端的驗證（vex_export.check_kernel_modules）；不過 → InputError（程式錯誤，不寫）。"""
    vx = vex_export()
    try:
        vx.check_kernel_modules(doc)
    except vx.VexInputError as e:
        raise InputError(f"產生的檔案沒有通過 vex_export.check_kernel_modules：{e}")


def sources_path(out):
    return Path(out).with_name("kernel-modules.sources.json")


def _safe_target(out, base=None):
    """寫入的資料夾：base（例如結果資料夾）到 out 的上層，每一層都要是資料夾、不能是符號連結（lstat）；沒有 base 時只看上層。"""
    out = Path(out)
    d = out.parent
    chain = [d]
    if base is not None:
        base = Path(base)
        try:
            rel = d.relative_to(base)
        except ValueError:
            raise InputError(f"{out} 不在 {base} 底下")
        chain = [base] + [base.joinpath(*rel.parts[:i]) for i in range(1, len(rel.parts) + 1)]
    for c in chain:
        try:
            st = os.lstat(c)
        except FileNotFoundError:
            raise Gap(f"{c} 不存在（沒有 CRA 專案？）")
        if not stat.S_ISDIR(st.st_mode):
            raise InputError(f"{c} 不是資料夾（可能是符號連結），拒絕寫入")
    for p in (out, sources_path(out)):
        if os.path.lexists(p) and (os.path.islink(p) or not os.path.isfile(p)):
            raise InputError(f"{p} 不是一般檔案（連結或資料夾），不覆寫")
    return out


def _write(path, text):
    tmp = tempfile.NamedTemporaryFile("w", dir=path.parent, prefix="." + path.name + ".", suffix=".tmp", delete=False, encoding="utf-8")
    try:
        with tmp:
            tmp.write(text)
        os.chmod(tmp.name, 0o600)
        os.replace(tmp.name, path)
    except BaseException:
        Path(tmp.name).unlink(missing_ok=True)
        raise


def write(out, doc, sources, replace=False, base=None):
    """→ "written"｜"unchanged"｜"conflict"。"""
    out = _safe_target(out, base)
    text = json.dumps(doc, ensure_ascii=False, indent=1) + "\n"
    if out.exists():
        old = out.read_text(encoding="utf-8", errors="replace")
        if old == text:
            return "unchanged"
        if not replace:
            return "conflict"
    sources = dict(sources, output=out.name, output_sha256=hashlib.sha256(text.encode()).hexdigest())
    _write(sources_path(out), json.dumps(sources, ensure_ascii=False, indent=1) + "\n")
    _write(out, text)
    return "written"


def move_aside(out):
    """這次沒有產生新的清單：原本的 kernel-modules.json（與 sources）改名，K2 不再讀它。→ 說明（沒有原本的檔時空字串）。"""
    out = Path(out)
    if not out.is_file() or out.is_symlink():
        return ""
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    moved = []
    for p in (out, sources_path(out)):
        if p.is_file() and not p.is_symlink():
            dst = p.with_name(f"{p.name}.stale-{stamp}")
            os.rename(p, dst)
            moved.append(dst.name)
    return f"；原本的 {out.name} 已改名成 {moved[0]}（K2 不再用它；要恢復就改回原名）"


def generate(out, src, prefix=None, kernel_version=None, owner=None, captured=None, scan=None, image_sha256=None,
             loaded=None, loaded_from=None, modules_disabled=None, accept_unread_initramfs=False, replace=False, input_notes=(),
             board=None, base=None):
    """整個流程 → (狀態, 說明)。參數錯誤 → InputError（不動原本的檔）；GAP、讀映像失敗 → 原本的檔改名（move_aside）。
    base：寫入位置的上層（board_import 的結果資料夾），base 到 out 之間每一層都要是真的資料夾。"""
    p = owner_problem(owner)
    if p:
        raise InputError(p)
    captured = captured or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    if not DATE_RE.match(captured):
        raise InputError(f"--captured 要是 YYYY-MM-DD：{captured[:40]}")
    try:
        datetime.date.fromisoformat(captured)
    except ValueError:
        raise InputError(f"--captured 不是合法的日期：{captured}")
    if kernel_version and not KVER_RE.match(kernel_version):
        raise InputError(f"--kernel-version 不合法：{kernel_version[:80]}")
    try:
        _safe_target(out, base)
    except Gap as e:
        return "GAP", f"沒有寫 {Path(out).name}：{e}"
    try:
        image, image_from = resolve_image(scan, image_sha256)
        doc, sources, notes = build(src, prefix, kernel_version, owner.strip(), captured, image, image_from, loaded, loaded_from,
                                    modules_disabled, accept_unread_initramfs, input_notes, board)
    except Gap as e:
        return "GAP", f"沒有寫 {Path(out).name}：{e}" + move_aside(out)
    except InputError as e:
        raise InputError(f"{e}" + move_aside(out))
    self_check(doc)
    st = "ATTENTION" if notes else "OK"
    sources["status"] = st
    r = write(out, doc, sources, replace, base)
    s = sources["modules"]
    summ = (f"核心 {doc['kernel_version']}；模組 {s['rootfs']}（updates {s['updates']}、extra {s['extra']}）＋模組資料夾外 "
            f"{len(s['outside_module_dirs'])}＋initramfs {s['initramfs']}；modules.builtin {len(doc['modules_builtin'] or []) or 'null'}；"
            f"modprobe.d 有效行 {len(doc['modprobe_d'])}；loaded {len(doc['loaded']) if doc['loaded'] else 'null'}；映像 {image[:19]}…")
    if r == "conflict":
        return "ATTENTION", f"沒有寫：{out} 已經有內容不同的檔案（K2 照樣用舊的；要取代加 --replace）；這次的結果：{summ}"
    return st, (f"{'沒有變更' if r == 'unchanged' else '已寫入'} {out}：{summ}"
                + (f"；注意 {len(notes)} 項：{'；'.join(notes[:4])[:600]}" if notes else ""))


def line(st, detail):
    print(f"{STAGE}\t{st}\t" + re.sub(r"[\t\r\n]+", " ", str(detail))[:1500])


def bool_arg(v):
    if v is None:
        return None
    if v in ("true", "1"):
        return True
    if v in ("false", "0"):
        return False
    raise argparse.ArgumentTypeError("要是 true 或 false")


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        print(f"參數錯誤：{message}", file=sys.stderr)
        sys.exit(64)


def main(argv=None):
    ap = Parser(description="從映像的 rootfs（與板子的 lsmod）產生 CRA/Config/kernel-modules.json（K2 的輸入）")
    ap.add_argument("--from", dest="src", required=True)
    ap.add_argument("--prefix")
    ap.add_argument("--kernel-version")
    ap.add_argument("--scan", help="sca-scan 的輸出資料夾（讀 meta.json 的映像雜湊）")
    ap.add_argument("--image-sha256")
    ap.add_argument("--owner", required=True)
    ap.add_argument("--captured")
    ap.add_argument("--lsmod")
    ap.add_argument("--modules-disabled", type=bool_arg)
    ap.add_argument("--accept-unread-initramfs", action="store_true")
    ap.add_argument("--out", required=True)
    ap.add_argument("--replace", action="store_true", help="已有內容不同的 kernel-modules.json（與 sources）時取代")
    a = ap.parse_args(argv)
    os.umask(0o077)
    try:
        loaded, loaded_from, inotes = read_lsmod_file(a.lsmod) if a.lsmod else (None, None, [])
        st, detail = generate(a.out, a.src, a.prefix, a.kernel_version, a.owner, a.captured, a.scan, a.image_sha256,
                              loaded, loaded_from, a.modules_disabled, a.accept_unread_initramfs, a.replace, inotes)
    except (InputError, OSError) as e:
        line("FAIL", e)
        return 1
    line(st, detail)
    return {"OK": 0, "FAIL": 1}.get(st, 2)


if __name__ == "__main__":
    sys.exit(main())
