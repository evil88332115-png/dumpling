#!/usr/bin/env python3
"""coreboot 類 BIOS 映像（例如 Dasharo）的 CBFS 只讀解析：版本、建置設定、FSP、VBT、payload 身分與雜湊。

x86_firmware.py 在 BIOS 映像（或 BIOS 區域）裡呼叫 analyze()；只依賴標準函式庫。

輸入是不可信資料：只讀、不執行、不把解壓結果寫到磁碟；所有 offset／length 都對區域邊界檢查；全部是迴圈（沒有遞迴）。

找 CBFS：
- 優先用 FMAP（flashmap，`__FMAP__`）：驗證標頭（版本 1、區域數、名稱可列印、區域在 flash 範圍內）。映像裡也會有 `__FMAP__` 字串常數
  （coreboot 程式碼本身），所以每個候選都要驗證，最多看 MAX_FMAP_CANDIDATES 個。flash 的起點：有名叫 FMAP 的區域時用
  「FMAP 的位置 − 該區域的 offset」；否則依 FMAP 宣告的大小在整個檔案或 BIOS 區域之間選。
  區域開頭是 `LARCHIVE` 的才是 CBFS（COREBOOT＝RO、FW_MAIN_A＝RW_A、FW_MAIN_B＝RW_B、RW_LEGACY…，其他名稱照原名）。
  已經接受的 CBFS 區域與別的區域重疊時，後者略過並記 incomplete（不走兩次）。
- 沒有 FMAP（或 FMAP 裡沒有 CBFS 區域）才退回掃 `LARCHIVE`：16 bytes 對齊、檔頭欄位與長度驗證通過、而且至少連續 2 個有效檔案才算一個 CBFS。
  這時區域是「第一個檔頭到最後一個檔案的結尾」。

CBFS 檔頭（big endian；coreboot src/commonlib/bsd/include/commonlib/bsd/cbfs_serialized.h）：
  `LARCHIVE`、len、type、attributes_offset、offset（資料相對檔頭的位置），後面是檔名（NUL 結尾）。檔案之間對齊 64 bytes（CBFS_ALIGNMENT，
  相對區域開頭）。屬性是 tag、len（含這 8 bytes）的串列；tag 0x42435a4c＝壓縮（compression 0 無、1 LZMA、2 LZ4；decompressed_size）。
  FMAP 結構（little endian；同目錄的 fmap_serialized.h）：signature、ver_major、ver_minor、base（u64）、size、name[32]、nareas（u16）、
  每個區域 offset（u32）、size、name[32]、flags（u16）。

壓縮：LZMA 用標準庫（FORMAT_ALONE）；LZ4 自己寫（lz4_block、lz4_frame）。LZ4 frame 照 coreboot 的 ulz4fn
（src/commonlib/bsd/lz4_wrapper.c）的做法：一個 frame、區塊必須獨立、保留位元必須是 0、不支援字典；
標頭／區塊／內容的 xxh32 檢查碼 coreboot 不驗證，這裡也不驗證（沒有真實的 LZ4 CBFS 樣本可比對，只有測試自組的資料）。
**解壓縮有上限**：單檔 MAX_FILE_OUT（文字類 MAX_TEXT_OUT）、整個映像合計 MAX_TOTAL_OUT；屬性宣告的解壓後大小超過上限就不解
（記 incomplete）；實際輸出超過宣告也停。只有要讀的檔案才解壓（revision、build_info、config、vbt、fsp*、payload 標頭），其他檔案只記屬性與儲存內容的雜湊。
相同內容（儲存的雜湊＋壓縮屬性相同）的檔案只解一次、只計一次總量。

讀出的內容（原型是評估用腳本，這裡照它的做法重寫）：
- `revision`（coreboot 的 build.h：`#define NAME "值"`）與 `build_info`（`KEY: 值`）：COREBOOT_VERSION、COREBOOT_ORIGIN_GIT_REVISION、
  DASHARO_VERSION、COREBOOT_BUILD、建置時間（COREBOOT_VERSION_TIMESTAMP 轉 UTC）、MAINBOARD_VENDOR／PART_NUMBER。
- `config`（coreboot .config）：只保留關鍵欄位（CONFIG_EDK2_TAG_OR_REV 與 repository、CONFIG_PAYLOAD_*、CONFIG_SOC_*、CONFIG_VBOOT、
  CONFIG_LOCALVERSION 等），其餘只留整份的雜湊與大小。
- FSP（`fsp*.bin` 或 type 0x60）：解壓後前 FSP_SEARCH 個 bytes 內的 `FSPH`（FSP_INFO_HEADER：Intel FSP EAS 2.x，同 edk2
  IntelFsp2Pkg/Include/FspInfoHeader.h 的欄位）：SpecVersion、HeaderRevision、ImageRevision（a.b.c.d）、ImageId、ImageSize、ImageBase、
  ComponentAttribute（bits 15:12 類型 1＝T、2＝M、3＝S、4＝O；bit 0 build type、bit 1 release type）。
- `vbt*.bin`：`$VBT` 標頭（Linux i915 drivers/gpu/drm/i915/display/intel_vbt_defs.h 的 struct vbt_header、struct bdb_header；
  coreboot src/drivers/intel/gma/intel_bios.h 同）：signature[20]、version（×100，例如 100＝1.00）、header_size、vbt_size、bdb_offset；
  BDB 標頭 `BIOS_DATA_BLOCK `＋version（×100，228＝2.28）。
- SELF payload（type 0x20）：segment 表（type、compression、offset、load 位址、長度、記憶體大小；`>4sIIQII`，到 ENTR 為止），
  整個儲存內容的雜湊。**不展開 payload 內的內容**（例如 edk2 的 firmware volume）。
- `cpu_microcode_blob.bin`、`intel_fit`：只記位置，讓 x86_firmware 的 microcode 加 found-in。

回傳的 dict 見 analyze()。出問題的地方（結構壞掉、解不開、超過上限）寫在 "incomplete"（x86_firmware 會變 ATTENTION），不影響其他部分。
"""
import hashlib
import importlib.util
import lzma
import re
import struct
import sys
import time
from pathlib import Path


def _sibling(name):
    """同目錄的模組。python3 -I 不把腳本目錄放進 sys.path，而且這個模組本身常是用檔案路徑載入的（x86_firmware.load_sibling），
    所以先看已經載入的，沒有就用檔案路徑載入；測試 import 過就共用同一個。"""
    mod = sys.modules.get(name)
    if mod is None:
        spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().with_name(name + ".py"))
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        try:
            spec.loader.exec_module(mod)
        except BaseException:
            sys.modules.pop(name, None)
            raise
    return mod


parse_vbt = _sibling("intel_vbt").parse_vbt     # VBT 標頭解析搬到 intel_vbt.py（AMI 映像與 Intel legacy VBIOS 共用）

CBFS_MAGIC = b"LARCHIVE"
FMAP_MAGIC = b"__FMAP__"
CBFS_ALIGN = 64                          # CBFS_ALIGNMENT
CBFS_HEADER = 24                         # LARCHIVE＋len＋type＋attributes_offset＋offset
MAX_DATA_OFFSET = 0x10000                # 資料相對檔頭的位置（含檔名、屬性、對齊填充；xip 檔案會對齊到 4 KiB 以上）
MAX_FMAP_CANDIDATES = 64                 # 看幾個 `__FMAP__`（程式碼常數也有這個字串）
MAX_FMAP_AREAS = 256                     # nareas 是 u16；coreboot 實際約 20–60 個
MAX_FLASH = 1 << 30                      # FMAP 宣告的 flash 大小上限
MAX_REGIONS = 32                         # CBFS 區域數
MAX_FILES = 8192                         # 每個 CBFS 區域的檔案數
MAX_FILES_TOTAL = 32768                  # 整個映像
MAX_ATTRS = 32                           # 每個檔案的屬性數
MAX_SCAN_CANDIDATES = 4096               # 沒有 FMAP 時，`LARCHIVE` 候選數
MAX_RESYNC = 1 << 16                     # 區域裡找下一個檔頭時看幾個 `LARCHIVE`
MAX_FILE_OUT = 16 << 20                  # 單一檔案解壓後大小（FSP 等）
MAX_TEXT_OUT = 1 << 20                   # 文字類（revision、build_info、config）與 VBT
MAX_TOTAL_OUT = 64 << 20                 # 整個映像解壓後合計
MAX_SEGMENTS = 64                        # SELF segment 數
MAX_LIST = 64                            # 單一 property 清單（SOC 等）最多列幾項
FSP_SEARCH = 0x1000                      # 在 FSP 檔案開頭多少 bytes 內找 `FSPH`
MAX_VALUE = 256                          # 從文字讀出的單一值的長度上限

TYPES = {0x00: "deleted", 0x01: "bootblock", 0x02: "cbfs header", 0x10: "stage (legacy)", 0x11: "stage", 0x20: "payload (SELF)",
         0x21: "fit payload", 0x30: "option ROM", 0x40: "bootsplash", 0x50: "raw", 0x51: "vsa", 0x52: "mbi", 0x53: "microcode",
         0x54: "intel fit", 0x60: "fsp", 0x61: "mrc", 0x62: "mma", 0x63: "efi", 0x70: "struct", 0x80: "amdfw", 0xaa: "cmos default",
         0xab: "spd", 0xac: "mrc cache", 0x1aa: "cmos layout", 0xffffffff: "empty"}
TYPE_EMPTY = (0x00000000, 0xFFFFFFFF)    # CBFS_TYPE_DELETED、CBFS_TYPE_NULL
TYPE_SELF = 0x20
TYPE_FSP = 0x60
COMPRESSION = {0: "none", 1: "lzma", 2: "lz4"}
ATTR_COMPRESSION = 0x42435A4C
ROLES = {"COREBOOT": "RO", "FW_MAIN_A": "RW_A", "FW_MAIN_B": "RW_B", "RW_LEGACY": "RW_LEGACY"}
KNOWN_CBFS = tuple(ROLES)
FSP_TYPES = {1: "T", 2: "M", 3: "S", 4: "O"}
SELF_TYPES = (b"CODE", b"DATA", b"BSS ", b"PARA", b"ENTR")
FSP_NAME = re.compile(r"fsp[a-z]?(?:[_.\-].*)?\.bin", re.I)
VBT_NAME = re.compile(r"vbt(?:[_.\-].*)?\.bin", re.I)
DEFINE = re.compile(r"#define[ \t]+([A-Z0-9_]+)[ \t]+(.+?)[ \t]*")
CONFIG_LINE = re.compile(r"CONFIG_([A-Za-z0-9_]+)=(.*)")
FULL_SHA = re.compile(r"[0-9a-f]{40}")
DASHARO_EDK2 = re.compile(r"https://github\.com/dasharo/edk2(?:\.git)?/?", re.I)
REVISION_KEYS = ("COREBOOT_VERSION", "COREBOOT_ORIGIN_GIT_REVISION", "COREBOOT_EXTRA_VERSION", "DASHARO_VERSION", "COREBOOT_BUILD",
                 "COREBOOT_VERSION_TIMESTAMP", "COREBOOT_DMI_DATE")
BUILD_INFO_KEYS = ("COREBOOT_VERSION", "MAINBOARD_VENDOR", "MAINBOARD_PART_NUMBER")
CONFIG_KEYS = ("LOCALVERSION", "VBOOT", "EDK2_TAG_OR_REV", "EDK2_REPOSITORY", "EDK2_PLATFORMS_TAG_OR_REV", "EDK2_PLATFORMS_REPOSITORY",
               "MAINBOARD_VENDOR", "MAINBOARD_PART_NUMBER")


class CbfsError(ValueError):
    """這個檔案（或這個結構）不能用；訊息會進 incomplete。"""


class TooBig(CbfsError):
    pass


class Lz4Error(CbfsError):
    pass


# ---------- 解壓縮 ----------

def _lz4_len(src, i, n, total, max_out):
    """LZ4 的延伸長度（每個 255 繼續）；→ (長度, 新位置)。超過 max_out 就停（惡意輸入的長度溢位）。"""
    while True:
        if i >= n:
            raise Lz4Error("LZ4: truncated length")
        b = src[i]
        i += 1
        total += b
        if total > max_out:
            raise TooBig(f"LZ4: length exceeds the output limit {max_out}")
        if b != 255:
            return total, i


def lz4_block(src, max_out):
    """LZ4 block 解碼。惡意輸入（offset 0、offset 超過已輸出長度、長度溢位、輸入截斷）一律 raise Lz4Error／TooBig；
    輸出超過 max_out 也 raise。最後一個 sequence 只有 literal（LZ4 block 規格）。"""
    n = len(src)
    out = bytearray()
    i = 0
    while True:
        if i >= n:
            raise Lz4Error("LZ4: truncated block (no token)")
        token = src[i]
        i += 1
        lit = token >> 4
        if lit == 15:
            lit, i = _lz4_len(src, i, n, lit, max_out)
        if lit > n - i:
            raise Lz4Error("LZ4: literal run extends past the input")
        if len(out) + lit > max_out:
            raise TooBig(f"LZ4: output exceeds {max_out}")
        out += src[i:i + lit]
        i += lit
        if i == n:
            return bytes(out)
        if n - i < 2:
            raise Lz4Error("LZ4: truncated match offset")
        offset = src[i] | (src[i + 1] << 8)
        i += 2
        if offset == 0:
            raise Lz4Error("LZ4: match offset 0")
        if offset > len(out):
            raise Lz4Error(f"LZ4: match offset {offset} is beyond the {len(out)} bytes decoded so far")
        mlen = token & 15
        if mlen == 15:
            mlen, i = _lz4_len(src, i, n, mlen, max_out)
        mlen += 4
        if len(out) + mlen > max_out:
            raise TooBig(f"LZ4: output exceeds {max_out}")
        start = len(out) - offset
        if offset >= mlen:
            out += out[start:start + mlen]
        else:                                    # 重疊複製：重複最後 offset 個 bytes
            out += (bytes(out[start:]) * (mlen // offset + 1))[:mlen]


def lz4_frame(src, max_out):
    """LZ4 frame（magic 0x184D2204）：一個 frame、獨立區塊；→ bytes。照 coreboot ulz4fn 的限制。"""
    n = len(src)
    if n < 7 or src[:4] != b"\x04\x22\x4d\x18":
        raise Lz4Error("LZ4: not a frame (bad magic)")
    flg, bd = src[4], src[5]
    if flg >> 6 != 1:
        raise Lz4Error("LZ4: unsupported frame version")
    if flg & 0x03 or bd & 0x8F:
        raise Lz4Error("LZ4: reserved/dictionary bits set")
    if not flg & 0x20:
        raise Lz4Error("LZ4: dependent blocks are not supported")
    block_max = {4: 64 << 10, 5: 256 << 10, 6: 1 << 20, 7: 4 << 20}.get((bd >> 4) & 7)
    if block_max is None:
        raise Lz4Error("LZ4: invalid block size id")
    i = 6
    declared = None
    if flg & 0x08:
        if n < i + 8:
            raise Lz4Error("LZ4: truncated frame header")
        declared = struct.unpack_from("<Q", src, i)[0]
        i += 8
        if declared > max_out:
            raise TooBig(f"LZ4: declared content size {declared} exceeds {max_out}")
    i += 1                                       # header checksum（不驗證，同 coreboot）
    out = bytearray()
    while True:
        if i + 4 > n:
            raise Lz4Error("LZ4: truncated frame (no EndMark)")
        raw = struct.unpack_from("<I", src, i)[0]
        i += 4
        size = raw & 0x7FFFFFFF
        if size == 0:
            break
        if size > block_max:
            raise Lz4Error("LZ4: block larger than the declared maximum block size")
        if size > n - i:
            raise Lz4Error("LZ4: block extends past the input")
        block = src[i:i + size]
        i += size
        if flg & 0x10:
            i += 4                               # block checksum（不驗證）
        room = max_out - len(out)
        if raw & 0x80000000:
            if size > room:
                raise TooBig(f"LZ4: output exceeds {max_out}")
            out += block
        else:
            out += lz4_block(block, min(block_max, room))
    if declared is not None and declared != len(out):
        raise Lz4Error(f"LZ4: content size {declared} declared but {len(out)} decoded")
    return bytes(out)


def lzma_alone(src, declared, cap):
    """LZMA（.lzma／FORMAT_ALONE）→ 恰好 declared bytes（宣告的解壓後大小；超過 cap 不解）。"""
    if declared > cap:
        raise TooBig(f"declared size {declared} exceeds the limit {cap}")
    d = lzma.LZMADecompressor(lzma.FORMAT_ALONE)
    try:
        out = d.decompress(src, max_length=declared + 1)
    except (lzma.LZMAError, EOFError, ValueError, OverflowError, MemoryError) as e:
        raise CbfsError(f"LZMA decode failed ({type(e).__name__})")
    if len(out) != declared or not d.eof:
        raise CbfsError(f"LZMA stream does not match the declared size {declared} (got {len(out)}{'' if d.eof else ', not ended'})")
    return out


def decompress(kind, stored, declared, cap):
    """CBFS 壓縮屬性（1 LZMA、2 LZ4）→ bytes；declared 是屬性裡的解壓後大小。大小與結束都核對。"""
    if declared > cap:
        raise TooBig(f"declared size {declared} exceeds the limit {cap}")
    if kind == 1:
        return lzma_alone(stored, declared, cap)
    if kind == 2:
        out = lz4_frame(stored, declared)
        if len(out) != declared:
            raise CbfsError(f"LZ4 output {len(out)} bytes, declared {declared}")
        return out
    raise CbfsError(f"unknown compression {kind}")


# ---------- FMAP ----------

def _cstr(b):
    """NUL 結尾的欄位 → 字串；不是可列印 ASCII（或沒有 NUL）→ None。"""
    z = b.find(b"\0")
    if z < 0:
        return None
    s = bytes(b[:z])
    return s.decode("ascii") if s and all(32 <= c < 127 for c in s) else None


def clean(s, limit=MAX_VALUE):
    """不可信的字串放進輸出前：控制字元與非 ASCII 換成 ?，截短。"""
    return "".join(c if 32 <= ord(c) < 127 else "?" for c in str(s))[:limit]


def parse_fmap(data, pos, hi):
    """pos 的 `__FMAP__` → dict，或 None（不是有效的 FMAP）。"""
    if pos + 56 > hi:
        return None
    ver_major, ver_minor, base, size = struct.unpack_from("<BBQI", data, pos + 8)
    name = _cstr(data[pos + 22:pos + 54])
    nareas = struct.unpack_from("<H", data, pos + 54)[0]
    if ver_major != 1 or name is None or not 1 <= nareas <= MAX_FMAP_AREAS or not 0 < size <= MAX_FLASH:
        return None
    if pos + 56 + 42 * nareas > hi:
        return None
    areas = []
    for k in range(nareas):
        a = pos + 56 + 42 * k
        o, s = struct.unpack_from("<II", data, a)
        flags = struct.unpack_from("<H", data, a + 40)[0]
        nm = _cstr(data[a + 8:a + 40])
        if nm is None:
            return None
        areas.append({"name": nm, "offset": o, "size": s, "flags": flags})
    return {"offset": pos, "version": f"{ver_major}.{ver_minor}", "base": base, "size": size, "name": name, "areas": areas}


def find_fmap(data, lo, hi, budget=None):
    """→ (fmap 或 None, [說明])。有多個不同的有效 FMAP 時用第一個，並記說明（不確定哪個才是真的）。"""
    found, notes, p = [], [], lo
    for k in range(MAX_FMAP_CANDIDATES):
        i = data.find(FMAP_MAGIC, p, hi)
        if i < 0:
            break
        p = i + 1
        f = parse_fmap(data, i, hi)
        if f and all(f["areas"] != g["areas"] for g in found):
            found.append(f)
        if budget is not None:
            budget.check()
    else:
        if data.find(FMAP_MAGIC, p, hi) >= 0:
            notes.append(f"more than {MAX_FMAP_CANDIDATES} __FMAP__ candidates; the rest were not examined")
    if len(found) > 1:
        notes.append(f"{len(found)} different valid FMAPs (at " + ", ".join(f"0x{f['offset']:x}" for f in found) + "); using the first")
    return (found[0] if found else None), notes


def flash_start(fm, data, lo, hi):
    """FMAP 的區域 offset 是相對 flash 起點（有 Intel descriptor 時 flash 是整個檔案，不只 BIOS 區域）。
    → (起點, None)；起點不合理 → (None, 原因)。"""
    fa = next((a for a in fm["areas"] if a["name"] == "FMAP"), None)
    if fa is not None and fm["offset"] - fa["offset"] >= 0:
        start = fm["offset"] - fa["offset"]
    elif fm["size"] == hi - lo:
        start = lo
    elif fm["size"] == len(data):
        start = 0
    else:
        start = lo
    if start < 0 or start + fm["size"] > len(data):
        return None, f"FMAP flash (start 0x{start:x}, size 0x{fm['size']:x}) does not fit in the file ({len(data)} bytes)"
    return start, None


# ---------- CBFS ----------

def sha(b):
    return {"sha256": hashlib.sha256(b).hexdigest(), "sha512": hashlib.sha512(b).hexdigest()}


def entry_at(data, pos, end):
    """pos 的 CBFS 檔頭 → dict；欄位不合理 raise CbfsError。長度與 offset 都對 end（區域結尾）檢查。"""
    if pos + CBFS_HEADER > end:
        raise CbfsError("header extends past the region")
    ln, ty, ao, off = struct.unpack_from(">IIII", data, pos + 8)
    if off < CBFS_HEADER or off > MAX_DATA_OFFSET:
        raise CbfsError(f"data offset {off} is out of range")
    if pos + off > end or ln > end - pos - off:
        raise CbfsError(f"entry (data offset {off}, length {ln}) extends past the end of the region")
    raw = data[pos + CBFS_HEADER:pos + off]
    z = raw.find(b"\0")
    if z < 0:
        raise CbfsError("file name is not NUL-terminated")
    nm = bytes(raw[:z])
    if any(c < 32 or c > 126 for c in nm):
        raise CbfsError("file name has non-printable bytes")
    e = {"name": nm.decode("ascii"), "type": ty, "offset": pos, "data_offset": pos + off, "length": ln,
         "compression": 0, "decompressed_size": None, "attr_note": None}
    if ao:
        if ao < CBFS_HEADER or ao >= off:
            e["attr_note"] = f"attributes offset {ao} is out of range"
        else:
            a, n = pos + ao, 0
            while a + 8 <= pos + off and n < MAX_ATTRS:
                tag, alen = struct.unpack_from(">II", data, a)
                if tag in (0, 0xFFFFFFFF):          # CBFS_FILE_ATTR_TAG_UNUSED／UNUSED2：屬性串列結束（後面是填充）
                    break
                if alen < 8 or a + alen > pos + off:
                    e["attr_note"] = "malformed attribute list"
                    break
                if tag == ATTR_COMPRESSION:
                    if alen < 16:
                        e["attr_note"] = "malformed compression attribute"
                        break
                    e["compression"], e["decompressed_size"] = struct.unpack_from(">II", data, a + 8)
                a += alen
                n += 1
    return e


def find_header(data, frm, end, start):
    """frm 之後第一個對齊（相對區域開頭 start）的 `LARCHIVE`；→ (位置或 None, 看過的候選數是否用完)。"""
    for _ in range(MAX_RESYNC):
        i = data.find(CBFS_MAGIC, frm, end)
        if i < 0:
            return None, False
        if (i - start) % CBFS_ALIGN == 0:
            return i, False
        frm = i + 1
    return None, True


def walk(data, start, end, budget=None, resync=True, file_cap=None):
    """區域 [start, end) 的 CBFS 檔案。→ (檔案 list, 空檔案數, 問題 list, 實際走到的結尾)。
    resync：檔頭壞掉或下一個位置不是檔頭時，往後找下一個對齊的 `LARCHIVE`（FMAP 區域）；False 時在那裡結束（掃描模式）。"""
    files, empty, problems = [], 0, []
    pos, covered = start, start
    file_cap = MAX_FILES if file_cap is None else file_cap
    while pos + CBFS_HEADER <= end:
        if budget is not None and (len(files) + empty) % 256 == 0:
            budget.check()
        if len(files) + empty >= file_cap:
            problems.append(f"more than {file_cap} entries; the rest of the region was not listed")
            return files, empty, problems, covered
        try:
            if data[pos:pos + 8] != CBFS_MAGIC:
                raise CbfsError("no CBFS entry here")
            e = entry_at(data, pos, end)
        except CbfsError as err:
            if not resync:
                break
            nxt, over = find_header(data, pos + 1, end, start)
            stop = nxt if nxt is not None else end
            if data.count(b"\xff", pos, stop) != stop - pos or str(err) != "no CBFS entry here":
                problems.append(f"0x{pos:x}: {err}" + (f"; skipped {stop - pos} bytes" if stop - pos > 0 else ""))
            if over:
                problems.append("too many LARCHIVE strings while looking for the next entry; the rest of the region was not listed")
            if nxt is None:
                break
            pos = nxt
            continue
        e["sha256"] = hashlib.sha256(memoryview(data)[e["data_offset"]:e["data_offset"] + e["length"]]).hexdigest()
        if e["type"] in TYPE_EMPTY:
            empty += 1
        else:
            files.append(e)
            if e["attr_note"]:
                problems.append(f"0x{pos:x} '{clean(e['name'])}': {e['attr_note']}")
        covered = e["data_offset"] + e["length"]
        pos = start + (((covered - start) + CBFS_ALIGN - 1) // CBFS_ALIGN) * CBFS_ALIGN
    return files, empty, problems, covered


def scan_regions(data, lo, hi, budget=None):
    """沒有 FMAP：掃 `LARCHIVE`。→ ([區域], [問題])。"""
    regions, problems, p, tried, seen = [], [], lo, 0, 0
    while True:
        i = data.find(CBFS_MAGIC, p, hi)
        if i < 0:
            break
        p = i + 1
        seen += 1
        if seen > MAX_RESYNC:
            problems.append(f"more than {MAX_RESYNC} LARCHIVE strings; the rest of the image was not scanned")
            break
        if i % 16 or (regions and i < regions[-1]["offset"] + regions[-1]["size"]):
            continue
        tried += 1
        if tried > MAX_SCAN_CANDIDATES:
            problems.append(f"more than {MAX_SCAN_CANDIDATES} LARCHIVE candidates; the rest were not examined")
            break
        if budget is not None:
            budget.check()
        try:
            entry_at(data, i, hi)
        except CbfsError:
            continue
        files, empty, probs, covered = walk(data, i, hi, budget, resync=False)
        if len(files) + empty >= 2:
            regions.append({"name": f"cbfs@0x{i:x}", "role": f"cbfs@0x{i:x}", "offset": i, "size": covered - i,
                            "files": files, "empty": empty, "problems": probs})
            p = covered
            if len(regions) >= MAX_REGIONS:
                problems.append(f"more than {MAX_REGIONS} CBFS regions; the rest were not examined")
                break
    return regions, problems


def fmap_regions(data, fm, start, budget=None):
    """FMAP 的區域裡開頭是 `LARCHIVE` 的 → CBFS 區域。→ ([區域], [問題])。"""
    regions, problems = [], []
    order = sorted(fm["areas"], key=lambda a: (KNOWN_CBFS.index(a["name"]) if a["name"] in ROLES else len(KNOWN_CBFS), a["offset"]))
    #                                          已知名稱優先（RO、RW_A、RW_B…）；其餘依位置
    for a in order:
        known = a["name"] in ROLES
        s, e = start + a["offset"], start + a["offset"] + a["size"]
        if a["offset"] + a["size"] > fm["size"] or e > len(data):
            if known:
                problems.append(f"FMAP area {a['name']} (offset 0x{a['offset']:x}, size 0x{a['size']:x}) is outside the flash/image")
            continue
        if data[s:s + 8] != CBFS_MAGIC:
            if known and a["size"]:
                problems.append(f"FMAP area {a['name']} has no CBFS header at its start")
            continue
        clash = next((r for r in regions if s < r["offset"] + r["size"] and r["offset"] < e), None)
        if clash:
            problems.append(f"FMAP area {a['name']} overlaps CBFS region {clash['name']}; not parsed twice")
            continue
        if len(regions) >= MAX_REGIONS:
            problems.append(f"more than {MAX_REGIONS} CBFS regions; the rest were not examined")
            break
        files, empty, probs, _ = walk(data, s, e, budget)
        regions.append({"name": a["name"], "role": ROLES.get(a["name"], a["name"]), "offset": s, "size": a["size"],
                        "files": files, "empty": empty, "problems": [f"{a['name']}: {x}" for x in probs]})
    return regions, problems


# ---------- 檔案內容 ----------

class Reader:
    """要讀的檔案：解壓一次、總量上限、相同內容共用結果。"""

    def __init__(self, data, max_total=None, max_file=None, max_text=None):
        self.data = data
        self.max_total = MAX_TOTAL_OUT if max_total is None else max_total
        self.total_left = self.max_total
        self.max_file = MAX_FILE_OUT if max_file is None else max_file
        self.max_text = MAX_TEXT_OUT if max_text is None else max_text
        self.cache = {}

    def stored(self, f):
        return memoryview(self.data)[f["data_offset"]:f["data_offset"] + f["length"]]

    def read(self, f, cap):
        """f 的內容（解壓後）→ bytes 或 memoryview；不能用 raise CbfsError。"""
        comp = f["compression"]
        if comp == 0:
            if f["length"] > cap:
                raise TooBig(f"size {f['length']} exceeds the limit {cap}")
            return self.stored(f)
        if comp not in (1, 2):
            raise CbfsError(f"unknown compression {comp}")
        declared = f["decompressed_size"]
        if declared is None:
            raise CbfsError("compressed without a decompressed size")
        key = (f["sha256"], comp, declared)
        if key in self.cache:
            r = self.cache[key]
            if isinstance(r, CbfsError):
                raise r
            return r
        try:
            if declared > cap:
                raise TooBig(f"declared decompressed size {declared} exceeds the limit {cap}")
            if declared > self.total_left:
                raise TooBig(f"declared decompressed size {declared} exceeds the remaining total limit {self.total_left}")
            r = decompress(comp, bytes(self.stored(f)), declared, cap)
            self.total_left -= len(r)
        except CbfsError as e:
            self.cache[key] = e
            raise
        self.cache[key] = r
        return r


def text_values(raw, keys, fmt):
    """revision（#define）／build_info（KEY: 值）→ {key: 值}；只取 keys。"""
    out = {}
    for line in bytes(raw).decode("utf-8", "replace").splitlines():
        if fmt == "define":
            m = DEFINE.fullmatch(line)
            k, v = (m.group(1), m.group(2)) if m else (None, None)
            if v is not None and len(v) >= 2 and v[0] == v[-1] == '"':
                v = v[1:-1]
        else:
            k, sep, v = line.partition(":")
            k, v = k.strip(), v.strip()
            if not sep:
                k = None
        if k in keys and k not in out:
            out[k] = clean(v)
    return out


def parse_config(raw):
    """coreboot .config → 關鍵欄位（原文不保留）。"""
    keys, payload, soc, lines = {}, [], [], 0
    for line in bytes(raw).decode("utf-8", "replace").splitlines():
        m = CONFIG_LINE.fullmatch(line)
        if not m:
            continue
        lines += 1
        k, v = m.group(1), m.group(2)
        if len(v) >= 2 and v[0] == v[-1] == '"':
            v = v[1:-1]
        if k in CONFIG_KEYS:
            keys.setdefault("CONFIG_" + k, clean(v))
        elif v == "y" and k.startswith("PAYLOAD_"):
            payload.append("CONFIG_" + k)
        elif v == "y" and k.startswith("SOC_"):
            soc.append("CONFIG_" + k)
    return {"keys": keys, "payload": sorted(payload), "soc": sorted(soc)[:MAX_LIST], "soc_total": len(soc), "lines": lines}


def parse_fsph(d):
    """解壓後的 FSP 檔案 → dict 或 None。`FSPH` 要在前 FSP_SEARCH bytes 內，欄位要合理（找到第一個合理的）。"""
    d = bytes(d[:FSP_SEARCH + 0x48])
    p = 0
    while True:
        i = d.find(b"FSPH", p, FSP_SEARCH + 4)
        if i < 0 or i + 0x24 > len(d):
            return None
        p = i + 1
        hl = struct.unpack_from("<I", d, i + 4)[0]
        spec, hrev, rev = d[i + 10], d[i + 11], struct.unpack_from("<I", d, i + 12)[0]
        iid = d[i + 16:i + 24]
        size, base = struct.unpack_from("<II", d, i + 24)
        comp_attr = struct.unpack_from("<H", d, i + 34)[0]
        if not 0x20 <= hl <= 0x200 or not iid or not all(32 <= c < 127 for c in iid) or not 1 <= comp_attr >> 12 <= 4:
            continue
        return {"offset_in_file": i, "header_length": hl, "spec_version": f"{spec >> 4}.{spec & 15}", "header_revision": hrev,
                "revision": f"{rev >> 24}.{(rev >> 16) & 255}.{(rev >> 8) & 255}.{rev & 255}", "image_id": iid.decode("ascii").strip(),
                "image_size": size, "image_base": f"0x{base:08x}", "component_attribute": f"0x{comp_attr:04x}",
                "type": FSP_TYPES[comp_attr >> 12], "build_type": "release" if comp_attr & 1 else "debug",
                "release_type": "official" if comp_attr & 2 else "test"}


def parse_self(raw, total):
    """SELF payload 的 segment 表 → (segments, entry 或 None, [問題])。raw 只要有開頭的標頭；total 是整個 payload 的長度（檢查 segment 範圍）。"""
    segs, problems, p, entry = [], [], 0, None
    n = total
    while len(segs) < MAX_SEGMENTS:
        if p + 28 > len(raw):
            problems.append("segment table runs past the end of the payload (no ENTR segment)")
            break
        t, c, off, load, ln, mem = struct.unpack_from(">4sIIQII", raw, p)
        p += 28
        if t not in SELF_TYPES:
            problems.append(f"unknown segment type {clean(t.decode('latin-1'), 8)!r}")
            break
        if t == b"ENTR":
            entry = load
            break
        s = {"type": t.decode("ascii").strip(), "compression": COMPRESSION.get(c, f"unknown({c})"), "offset": off,
             "load_address": f"0x{load:x}", "length": ln, "memory_length": mem}
        if t in (b"CODE", b"DATA") and off + ln > n:
            problems.append(f"segment {s['type']} (offset {off}, length {ln}) extends past the payload ({n} bytes)")
        segs.append(s)
    else:
        problems.append(f"more than {MAX_SEGMENTS} segments")
    return segs, entry, problems


def build_time(ts):
    """COREBOOT_VERSION_TIMESTAMP（epoch 秒）→ UTC ISO 8601；不是合理數字 → None。"""
    try:
        t = int(ts)
    except (TypeError, ValueError):
        return None
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t)) if 0 < t < 4102444800 else None


def loc(region, f):
    return {"region": region["name"], "role": region["role"], "file": f["name"], "offset": f["data_offset"], "length": f["length"],
            "header_offset": f["offset"]}


def classify(f):
    n = f["name"]
    if f["type"] == TYPE_SELF:
        return "payload"
    if n in ("revision", "build_info", "config"):
        return n
    if f["type"] == TYPE_FSP or FSP_NAME.fullmatch(n):
        return "fsp"
    if VBT_NAME.fullmatch(n):
        return "vbt"
    if n in ("cpu_microcode_blob.bin", "intel_fit"):
        return "found-in"
    return None


def merge(items, key, make, location):
    """相同內容只記一次：items[key] 不存在就 make()，並加上 location。"""
    it = items.get(key)
    if it is None:
        it = items[key] = make()
        it["locations"] = []
    it["locations"].append(location)
    return it


def analyze(data, lo=0, hi=None, budget=None, max_total=None, max_file=None, max_text=None):
    """data[lo:hi] 裡的 CBFS。沒有 CBFS → None。offset 都是 data 裡的絕對位置。

    {"method": "fmap"|"scan", "fmap": {...}|None,
     "regions": [{"name", "role", "offset", "size", "entries", "empty", "files": [{name, type, type_name, offset, data_offset, length,
                  compression, decompressed_size, sha256}]}],
     "coreboot": [...], "payloads": [...], "fsp": [...], "vbt": [...]（各項有 locations）,
     "microcode_files": [位置], "incomplete": [字串], "gaps": [字串], "limits": {...}}
    """
    hi = len(data) if hi is None else min(hi, len(data))
    if hi - lo < CBFS_HEADER:
        return None
    problems, method, fm_out = [], "scan", None
    fm, notes = find_fmap(data, lo, hi, budget)
    problems += notes
    regions = []
    if fm:
        start, why = flash_start(fm, data, lo, hi)
        if start is None:
            problems.append(why)
        else:
            regions, probs = fmap_regions(data, fm, start, budget)
            problems += probs
            method = "fmap"
        fm_out = {"offset": fm["offset"], "version": fm["version"], "name": fm["name"], "size": fm["size"],
                  "areas": len(fm["areas"]), "flash_start": start}
    if not regions:
        regions, probs = scan_regions(data, lo, hi, budget)
        problems += probs
        if fm and method == "fmap":
            method = "scan"
            problems.append("FMAP has no CBFS area; scanned for LARCHIVE instead")
    if not regions:
        return None
    reader = Reader(data, max_total, max_file, max_text)
    r = {"method": method, "fmap": fm_out, "regions": [], "coreboot": [], "payloads": [], "fsp": [], "vbt": [], "microcode_files": [],
         "incomplete": [], "gaps": []}
    inc = r["incomplete"]
    inc += problems
    total_files = 0
    cb, pl, fsp, vbt = {}, {}, {}, {}

    def read(region, f, cap, what):
        try:
            return reader.read(f, cap)
        except CbfsError as e:
            inc.append(f"CBFS {region['role']} '{clean(f['name'])}' ({what}): {e}")
            return None

    for region in regions:
        total_files += len(region["files"]) + region["empty"]
        if total_files > MAX_FILES_TOTAL:
            inc.append(f"more than {MAX_FILES_TOTAL} CBFS entries in total; the rest were not examined")
            break
        inc += region["problems"]
        found = {"revision": None, "build_info": None, "config": None}
        payloads, fsps, vbts = [], [], []
        for f in region["files"]:
            if budget is not None:
                budget.check()
            kind = classify(f)
            if kind in found and found[kind] is None:
                raw = read(region, f, reader.max_text, kind)
                if raw is not None:
                    found[kind] = (f, raw)
            elif kind == "found-in":
                r["microcode_files"].append(loc(region, f))
            elif kind == "fsp":
                raw = read(region, f, reader.max_file, "fsp")
                if raw is not None:
                    h = parse_fsph(raw)
                    if h is None:
                        inc.append(f"CBFS {region['role']} '{clean(f['name'])}': no valid FSPH header in the first {FSP_SEARCH} bytes")
                    else:
                        fsps.append((f, raw, h))
            elif kind == "vbt":
                raw = read(region, f, reader.max_text, "vbt")
                if raw is not None:
                    v = parse_vbt(raw)
                    if v is None:
                        inc.append(f"CBFS {region['role']} '{clean(f['name'])}': not a valid $VBT table")
                    else:
                        vbts.append((f, raw, v))
            elif kind == "payload":
                payloads.append(f)
        rev = text_values(found["revision"][1], REVISION_KEYS, "define") if found["revision"] else {}
        bi = text_values(found["build_info"][1], BUILD_INFO_KEYS, "info") if found["build_info"] else {}
        cfg = None
        if found["config"]:
            cfg = parse_config(found["config"][1])
            cfg.update(sha(bytes(found["config"][1])), size=len(found["config"][1]))
        if rev or bi or cfg:                         # coreboot：revision／build_info／config 相同的區域合併
            evidence = [found[k][0] for k in ("revision", "build_info", "config") if found[k]]
            key = tuple(f["sha256"] for f in (found["revision"] and found["revision"][0], found["build_info"] and found["build_info"][0],
                                              found["config"] and found["config"][0]) if f)
            ver = rev.get("COREBOOT_VERSION") or bi.get("COREBOOT_VERSION")
            if rev.get("COREBOOT_VERSION") and bi.get("COREBOOT_VERSION") and rev["COREBOOT_VERSION"] != bi["COREBOOT_VERSION"]:
                inc.append(f"CBFS {region['role']}: COREBOOT_VERSION differs between 'revision' ({rev['COREBOOT_VERSION']}) "
                           f"and 'build_info' ({bi['COREBOOT_VERSION']}); using 'revision'")
            it = merge(cb, key, lambda: {
                "version": ver, "version_basis": "revision" if rev.get("COREBOOT_VERSION") else "build_info",
                "git_revision": rev.get("COREBOOT_ORIGIN_GIT_REVISION"), "dasharo_version": rev.get("DASHARO_VERSION"),
                "extra_version": rev.get("COREBOOT_EXTRA_VERSION"), "build": rev.get("COREBOOT_BUILD"),
                "build_time": build_time(rev.get("COREBOOT_VERSION_TIMESTAMP")), "dmi_date": rev.get("COREBOOT_DMI_DATE"),
                "mainboard_vendor": bi.get("MAINBOARD_VENDOR"), "mainboard_part": bi.get("MAINBOARD_PART_NUMBER"),
                "config": cfg, "evidence_sha256": {k: found[k][0]["sha256"] for k in found if found[k]},
                "hash": sha(bytes(found["revision"][1] if found["revision"] else found["build_info"][1] if found["build_info"] else
                                  found["config"][1]))},
                loc(region, evidence[0]))
            it["evidence_files"] = sorted({found[k][0]["name"] for k in found if found[k]})
        for f in payloads:
            raw = None
            if f["compression"] == 0:
                raw = reader.stored(f)[:28 * (MAX_SEGMENTS + 1)]
            else:
                raw = read(region, f, reader.max_file, "payload")
            segs, entry, probs = parse_self(raw, f["length"] if f["compression"] == 0 else len(raw)) if raw is not None else ([], None, [])
            inc += [f"CBFS {region['role']} '{clean(f['name'])}': {x}" for x in probs]
            stored = bytes(reader.stored(f))
            it = merge(pl, (f["sha256"], f["compression"]), lambda: {
                "file": f["name"], "length": f["length"], "compression": COMPRESSION.get(f["compression"], str(f["compression"])),
                "segments": segs, "entry": f"0x{entry:x}" if entry is not None else None, "hash": sha(stored),
                "config": cfg}, loc(region, f))
            _ = it
        for f, raw, h in fsps:
            content = sha(bytes(raw))
            it = merge(fsp, content["sha256"], lambda: {**h, "file": f["name"], "hash": content, "stored_sha256": f["sha256"],
                                                        "length": len(raw)}, loc(region, f))
            _ = it
        for f, raw, v in vbts:
            content = sha(bytes(raw))
            merge(vbt, content["sha256"], lambda: {**v, "file": f["name"], "hash": content, "stored_sha256": f["sha256"],
                                                   "length": len(raw)}, loc(region, f))
        r["regions"].append({"name": region["name"], "role": region["role"], "offset": region["offset"], "size": region["size"],
                             "entries": len(region["files"]) + region["empty"], "empty": region["empty"],
                             "files": [{"name": clean(f["name"]), "type": f["type"], "type_name": TYPES.get(f["type"], "?"),
                                        "offset": f["offset"], "data_offset": f["data_offset"], "length": f["length"],
                                        "compression": COMPRESSION.get(f["compression"], f"unknown({f['compression']})"),
                                        "decompressed_size": f["decompressed_size"], "sha256": f["sha256"]} for f in region["files"]]})
        if not found["revision"] and not found["build_info"] and any(f["name"] in ("bootblock", "romstage", "fallback/romstage") for f in region["files"]):
            merge(cb, ("stages", region["name"]), lambda: {"version": None, "version_basis": None, "git_revision": None,
                                                           "dasharo_version": None, "extra_version": None, "build": None,
                                                           "build_time": None, "dmi_date": None, "mainboard_vendor": None,
                                                           "mainboard_part": None, "config": cfg, "evidence_sha256": {},
                                                           "evidence_files": [], "hash": None},
                  {"region": region["name"], "role": region["role"], "file": "bootblock", "offset": region["offset"],
                   "length": 0, "header_offset": region["offset"]})
    any_cfg = next((it["config"] for it in cb.values() if it["config"]), None)
    for it in pl.values():                             # payload 所在區域沒有 config：用別的區域的，並註明
        it["config_source"] = "same CBFS region" if it["config"] else ("other CBFS region" if any_cfg else None)
        it["config"] = it["config"] or any_cfg
    r["coreboot"], r["payloads"], r["fsp"], r["vbt"] = list(cb.values()), list(pl.values()), list(fsp.values()), list(vbt.values())
    if not any(it["version"] for it in r["coreboot"]):
        r["gaps"].append("CBFS found but no 'revision'/'build_info' with COREBOOT_VERSION: coreboot version not read")
    if r["payloads"]:
        r["gaps"].append("coreboot payload (SELF) contents, for example edk2 firmware volumes, are not expanded here; only the payload identity is read")
    r["limits"] = {"max_file_out": reader.max_file, "max_text_out": reader.max_text, "max_total_out": reader.max_total,
                   "decompressed_total": reader.max_total - reader.total_left}
    return r
