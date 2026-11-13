#!/usr/bin/env python3
"""AMD 平台 BIOS 映像的 PSP／BIOS 目錄、微碼與 AGESA 版本：只讀解析（x86_firmware.py 辨識出 AMD 平台時呼叫 analyze()）。

只依賴標準函式庫與同目錄的 uefi_image.py（C1；找 AGESA 字串時用它解開 firmware volume）。輸入是不可信資料：只讀、不執行、不寫磁碟；
所有欄位先對照檔案範圍與上限（MAX_*）才使用；看不懂的一律記 problem（對外是 GAP），不猜。

## 做什麼
1. Embedded Firmware Structure（EFS，簽章 0x55AA55AA，位置照 coreboot util/amdfwtool/amdfwread.c 的 fw_header_offsets，每個 16 MiB 視窗各找一次）
   → 指標欄位 → PSP 目錄（L1 `$PSP`、L2 `$PL2`、combo `2PSP`）與 BIOS 目錄（`$BHD`、`$BL2`、`2BHD`）。目錄裡的項目若指向另一個目錄
   （PSP 的 0x40、BIOS 的 0x70、combo 的每一項……只要解出的位置開頭是目錄 cookie）就往下走，深度、目錄數、項目總數都有上限，循環不重複走。
2. 每個目錄項目：type、subprogram、instance、rom id、位置、大小、旗標。PSP 韌體條目的標頭（0x100 bytes）通過檢查才讀版本；其餘版本欄位記 GAP。
3. BIOS 目錄 type 0x66 的 AMD 微碼：patch level（patch_id）、日期、equivalence id；微碼前面有 container 的等價表（`DMA\\0`）時才對出 CPUID，
   否則只列 equivalence id（不猜對照）。
4. AGESA 版本字串（`AGESA!V<n>` 後面接的字串）：整個映像的原始位元組找一次，再走訪 firmware volume（LZMA 等解開）找一次，不同值全部列出。

## 格式出處（只讀公開的格式說明核對欄位，沒有複製程式碼；程式是自己寫的）
- coreboot `src/vendorcode/amd/psp/psp_efs.h`（EFS 欄位）、`psp_directory.h`（目錄標頭、項目、type 編號、cookie）、`bios_directory.h`
  （BIOS 目錄項目與 type）、`combo_directory.h`（combo 目錄）、`util/amdfwtool/amdfwtool.h`（`amd_fw_header`：PSP 韌體標頭的版本欄位
  +0x60、size_total +0x6c、fw_type +0x7c）。AMD 文件 #55758（Embedded Firmware Structure／PSP directory）。授權 GPL-2.0-only；
  這裡只引用欄位位置、編號與意義的事實，type 名稱沿用上游的識別字（去掉前綴）。
- PSPTool（PSPReverse/PSPTool）的 `entry.py`：目錄的 address mode 與項目 address mode 的取捨（目錄是「實體位址」或「相對 BIOS」時以目錄為準，
  只有「相對目錄」「相對 slot」才用項目自己的）、大於 16 MiB 的映像把 0xFFxxxxxx 位址遮成 24 bits。授權 GPL-3.0；只引用行為描述。
- AMD 微碼 container／patch 標頭：Linux 核心 `arch/x86/kernel/cpu/microcode/amd.c`（`DMA\\0` 魔術字、等價表型別 0、patch 型別 1、
  `microcode_header_amd`、等價表項目 16 bytes）。

## 結構（小端）
EFS（位置 E）：+0 簽章；+0x04 imc、+0x08 gec、+0x0C xhci；+0x10 psp_directory（也可能是 combo）、+0x14 new_psp_directory；
  +0x18 bios0、+0x1C bios1、+0x20 bios2、+0x28 bios3；+0x2C psp_bak_directory；+0x30、+0x34、+0x38 Promontory 韌體指標（這裡不解析，有值就記 GAP）。
  指標值 0／0xFFFFFFFF／0xFFFFFFFE 是「沒有」。
目錄標頭 16 bytes：cookie、checksum、num_entries、additional_info（版本 0：dir_size 位元 0–9、address_mode 位元 29–30；版本 1：bit 31＝1，
  address_mode 位元 24–25）。checksum＝Fletcher-32（16 位元字、模 65535）涵蓋 +8 到最後一個項目結尾。
PSP 項目 16 bytes：type u8、subprogram u8、flags u16（位元 0–1 rom id、位元 2 writable、位元 3–6 instance）、size u32、
  位址 u64（位元 0–61 值，位元 62–63 address mode）。size 0xFFFFFFFF 的項目（例如 type 0x0B 的 soft fuse）位址欄位是「值」不是位置。
BIOS 項目 24 bytes：type u8、region_type u8、flags u8（位元 0 reset、1 copy、2 ro、3 compressed、4–7 instance）、
  flags2 u8（位元 0–2 subprogram、3–4 rom id、5 writable）、size u32、來源 u64（同上的 62＋2 位元）、dest u64（0xFF…FF＝沒有）。
combo 目錄：32 bytes 標頭（cookie、checksum、num_entries、lookup、16 bytes 保留，checksum 涵蓋 +8 起），項目 16 bytes：id_sel u32、id u32、目錄位址 u64。
位址：address mode 0（實體）或 1（相對視窗開頭）。值在 2^32−W 以上是「映射在 4 GB 頂端的視窗」位置（W＝視窗大小，最大 16 MiB；
  偏移＝值−(2^32−W)，大於 16 MiB 的映像等於遮成 24 bits），其餘是視窗內偏移；視窗＝EFS 所在的 16 MiB 區塊。
  mode 2＝相對目錄開頭；mode 3（相對 slot）slot 起點未知 → 不解。指向目錄的指標一定用 cookie 驗證，視窗開頭和 0 兩種基底都試，只有一個成立才採用。

## 上限與放大控制（見 MAX_*）
視窗內 EFS 數、目錄數、深度、每個目錄的項目數、全部目錄的項目總數、雜湊總量（同一段 offset＋size 只算一次）、單一項目大小、微碼數、AGESA 標記數與
解開後內容總量；循環（目錄指標回到走訪路徑上的目錄）不重複走。regex 只用固定字面值；AGESA 用 bytes.find。
"""
import hashlib
import importlib.util
import struct
import sys
from pathlib import Path

WINDOW = 16 << 20                      # AMD 位址視窗：4 GB 頂端往下最多 16 MiB
MAX_EFS = 8                            # 每個映像最多記幾個 EFS
MAX_SIG_HITS = 4096                    # 全檔找 EFS 簽章的候選數
MAX_SHIFT = 0x10000                    # 視窗開頭到映像開頭的位移（例如更新包的標頭）上限
MAX_DIRS = 64                          # 每個映像最多解析的目錄數（含 L2、combo）
MAX_DEPTH = 4                          # 目錄指標巢狀深度（EFS 指到的是 0）
MAX_DIR_ENTRIES = 256                  # 單一目錄的項目數（coreboot MAX_PSP_ENTRIES 0xFF；實際約 10–40）
MAX_ENTRIES_TOTAL = 4096               # 全部目錄的項目總數（跨巢狀累計）
MAX_BLOB = 64 << 20                    # 單一項目的大小；更大的不當成韌體條目（記 problem）
MAX_HASH_TOTAL = 256 << 20             # 為 SBOM 算雜湊的總量（同 offset＋size 只算一次）
MAX_UCODE = 64                         # 每個映像列出的微碼 patch 數
MAX_EQUIV = 256                        # 一個 container 的等價表項目數
MAX_PATCHES = 16                       # 一個 container 的 patch 數
MAX_PROBLEMS_SHOWN = 12                # 每種 problem 在 JSON 裡逐一列出的筆數（其餘只計數）
MAX_AGESA_MARKERS = 4096               # 全部內容裡 `AGESA!V` 標記的總數
MAX_AGESA_VALUES = 16                  # 不同的 AGESA 值最多記幾個
MAX_AGESA_LOCATIONS = 8                # 每個值最多記幾個位置
MAX_AGESA_INSPECT = 1 << 30            # 走訪 firmware volume 時去重後送進搜尋的位元組總量
AGESA_VALUE_LEN = 64                   # AGESA 標記後面讀的字串長度上限
AGESA_MARK = b"AGESA!V"

EFS_SIG = b"\xaa\x55\xaa\x55"
# coreboot util/amdfwtool/amdfwread.c 的 fw_header_offsets（和 x86_firmware.AMD_EFS_OFFSETS 相同；這個模組不依賴 x86_firmware）
EFS_OFFSETS = (0xFA0000, 0xF20000, 0xE20000, 0xC20000, 0x820000, 0x020000, 0x7A0000, 0x720000, 0x620000, 0x420000,
               0x3A0000, 0x320000, 0x220000)
EFS_SIZE = 0x3C                        # 讀到 promontory19 指標（+0x38）為止
EFS_POINTERS = ((0x10, "psp_directory"), (0x14, "new_psp_directory"), (0x2C, "psp_bak_directory"),
                (0x18, "bios0"), (0x1C, "bios1"), (0x20, "bios2"), (0x28, "bios3"))
EFS_UNPARSED = ((0x04, "imc"), (0x08, "gec"), (0x0C, "xhci"), (0x30, "promontory"), (0x34, "lp_promontory"), (0x38, "promontory19"))
NO_POINTER = (0, 0xFFFFFFFF, 0xFFFFFFFE)

COOKIES = {b"$PSP": "psp", b"$PL2": "psp-l2", b"$BHD": "bios", b"$BL2": "bios-l2", b"2PSP": "combo-psp", b"2BHD": "combo-bios"}
KIND_TEXT = {"psp": "PSP directory L1", "psp-l2": "PSP directory L2", "bios": "BIOS directory L1", "bios-l2": "BIOS directory L2",
             "combo-psp": "PSP combo directory", "combo-bios": "BIOS combo directory"}
HEADER = {"psp": 0x10, "psp-l2": 0x10, "bios": 0x10, "bios-l2": 0x10, "combo-psp": 0x20, "combo-bios": 0x20}
ENTRY_SIZE = {"psp": 16, "psp-l2": 16, "bios": 24, "bios-l2": 24, "combo-psp": 16, "combo-bios": 16}
ADDR_MASK = (1 << 62) - 1
VALUE_SIZE = 0xFFFFFFFF                # 項目 size 的「這不是位置，位址欄位是值」標記

# PSP 目錄項目 type → 名稱（coreboot psp_directory.h 的 enum amd_fw_type，去掉 AMD_FW_PSP_ 前綴；0x5F 上游有兩個名稱）
PSP_TYPES = {
    0x00: "PUBKEY", 0x01: "BOOTLOADER", 0x02: "SECURED_OS", 0x03: "RECOVERY", 0x04: "NVRAM", 0x05: "RTM_PUBKEY", 0x08: "SMU_FIRMWARE",
    0x09: "SECURED_DEBUG", 0x0A: "ABL_PUBKEY", 0x0B: "FUSE_CHAIN", 0x0C: "TRUSTLETS", 0x0D: "TRUSTLETKEY", 0x12: "SMU_FIRMWARE2",
    0x13: "DEBUG_UNLOCK", 0x15: "TEEIPKEY", 0x1A: "SEV_DRIVER", 0x1B: "BOOT_DRIVER", 0x1C: "SOC_DRIVER", 0x1D: "DEBUG_DRIVER",
    0x1F: "INTERFACE_DRIVER", 0x20: "HW_IPCFG", 0x21: "WRAPPED_IKEK", 0x22: "TOKEN_UNLOCK", 0x24: "SEC_GASKET", 0x25: "MP2_FW",
    0x28: "DRIVER_ENTRIES", 0x29: "KVM_IMAGE", 0x2A: "MP5", 0x2D: "S0I3_DRIVER",
    0x30: "ABL0", 0x31: "ABL1", 0x32: "ABL2", 0x33: "ABL3", 0x34: "ABL4", 0x35: "ABL5", 0x36: "ABL6", 0x37: "ABL7",
    0x38: "SEV_DATA", 0x39: "SEV_CODE", 0x3A: "WHITELIST", 0x3C: "VBIOS_BTLOADER", 0x40: "L2_PTR", 0x42: "DXIO", 0x44: "USB_PHY",
    0x45: "TOS_SEC_POLICY", 0x47: "DRTM_TA", 0x48: "RECOVERYAB_A", 0x49: "BIOS_TABLE", 0x4A: "RECOVERYAB_B", 0x50: "KEYDB_BL",
    0x51: "KEYDB_TOS", 0x52: "VERSTAGE", 0x53: "VERSTAGE_SIG", 0x54: "RPMC_NVRAM", 0x55: "SPL", 0x58: "DMCU_ERAM", 0x59: "DMCU_ISR",
    0x5A: "MSMU", 0x5C: "SPIROM_CFG", 0x5D: "MPIO", 0x5F: "TPMLITE_OR_SMUSCS", 0x64: "RAS_DRIVER", 0x65: "RAS_TA", 0x67: "FHP_DRIVER",
    0x68: "SPDM_DRIVER", 0x69: "DPE_DRIVER", 0x6E: "AB_NVRAM", 0x71: "DMCUB", 0x73: "BOOTLOADER_AB", 0x76: "RIB", 0x85: "AMF_SRAM",
    0x86: "AMF_DRAM", 0x87: "MFD_MPM", 0x88: "AMF_WLAN", 0x89: "AMF_MFD", 0x8C: "MPDMA_TF", 0x8D: "TA_IKEK", 0x8E: "SFDR", 0x90: "MPCCX",
    0x91: "GMI3_PHY", 0x92: "MPDMA_PM", 0x94: "LSDMA", 0x95: "C20_MP", 0x98: "FCFG_TABLE", 0x9A: "MINIMSMU", 0x9B: "GFXIMU_0",
    0x9C: "GFXIMU_1", 0x9D: "SRAM_FW_EXT", 0x9F: "TOS_WHITELIST", 0xA0: "S3IMG", 0xA2: "UMSMU", 0xA4: "USBDP", 0xA5: "USBSS", 0xA6: "USB4",
}
# BIOS 目錄項目 type（coreboot bios_directory.h 的 enum amd_bios_type，去掉 AMD_BIOS_ 前綴）
BIOS_TYPES = {0x05: "RTM_PUBKEY", 0x07: "SIG", 0x60: "APCB", 0x61: "APOB", 0x62: "BIN", 0x63: "APOB_NV", 0x64: "PMUI", 0x65: "PMUD",
              0x66: "UCODE", 0x68: "APCB_BK", 0x69: "EARLY_VGA", 0x6A: "MP2_CFG", 0x6B: "PSP_SHARED_MEM", 0x6D: "NV_ST", 0x70: "L2_PTR"}
UCODE_TYPE = 0x66
# 指向另一個目錄的項目 type（名稱沿用上游）；不是這些 type 但解出的位置開頭是目錄 cookie 時也會往下走
POINTER_TYPES = {"psp": (0x40, 0x48, 0x49, 0x4A), "psp-l2": (0x40, 0x48, 0x49, 0x4A), "bios": (0x70,), "bios-l2": (0x70,)}
ISH_TYPES = (0x48, 0x4A)               # RECOVERYAB_A／B：size 0 時位址指到 Image Slot Header
ISH_LEN = 0x20
PSP_HDR_LEN = 0x100                    # amd_fw_header
PSP_VERSION_AT, PSP_SIZE_AT, PSP_TYPE_AT = 0x60, 0x6C, 0x7C

UCODE_MAGIC = b"DMA\x00"               # container 魔術字（Linux amd.c UCODE_MAGIC 0x00414d44）
UCODE_HDR_LEN = 0x1A                   # microcode_header_amd 到 processor_rev_id（+0x18 u16）結束


class Ctx:
    """一次 analyze() 的狀態。"""

    def __init__(self, data, budget):
        self.data, self.n, self.budget = data, len(data), budget
        self.dirs, self.by_off, self.problems, self.counts = [], {}, [], {}
        self.entries_total = 0
        self.hash_left = MAX_HASH_TOTAL
        self.hashed = {}

    def problem(self, code, where, text):
        self.counts[code] = self.counts.get(code, 0) + 1
        self.problems.append({"code": code, "where": where, "text": text})

    def check(self):
        if self.budget is not None:
            self.budget.check()


def u32(d, o):
    return struct.unpack_from("<I", d, o)[0]


def fletcher32(buf):
    """16 位元小端字、模 65535 的 Fletcher-32（奇數長度的最後一個 byte 不算；目錄涵蓋範圍一定是偶數）。"""
    s1 = s2 = 0
    for (w,) in struct.iter_unpack("<H", buf[:len(buf) & ~1]):
        s1 = (s1 + w) % 65535
        s2 = (s2 + s1) % 65535
    return (s2 << 16) | s1


def window_size(n, base):
    """視窗大小：該視窗內的檔案位元組數往上取 2 的次方，最大 16 MiB（小於 16 MiB 的映像整個就是視窗）。"""
    left = max(n - base, 1)
    w = 1
    while w < left and w < WINDOW:
        w <<= 1
    return min(w, WINDOW)


def to_offset(value, base, w):
    """位址值 → 檔案偏移（不檢查範圍）。值 ≥ 2^32 → None。2^32−w 以上是映射在 4 GB 頂端的位置，其餘當成視窗內偏移。"""
    if value >= 1 << 32:
        return None
    if value >= (1 << 32) - w:
        return base + value - ((1 << 32) - w)
    return base + value


def hex_or_none(v):
    return None if v is None else f"0x{v:x}"


def bcd_date(v):
    """AMD 微碼日期：u32 的十六進位數字就是 mmddyyyy（BCD）。不是合法日期 → None。"""
    s = f"{v:08x}"
    if not s.isdigit():
        return None
    mm, dd, yyyy = int(s[:2]), int(s[2:4]), int(s[4:])
    if not (1 <= mm <= 12 and 1 <= dd <= 31 and 2000 <= yyyy <= 2099):
        return None
    return f"{yyyy:04d}-{mm:02d}-{dd:02d}"


# ---------- EFS ----------

def pointers_resolve(ctx, p, base):
    """p の EFS の指標のどれかが、base を基底にして目錄 cookie の位置に着くか。"""
    w = window_size(ctx.n, base)
    for o, _ in EFS_POINTERS:
        v = u32(ctx.data, p + o)
        if v in NO_POINTER:
            continue
        off = to_offset(v, base, w)
        if off is not None and off + 4 <= ctx.n and bytes(ctx.data[off:off + 4]) in COOKIES:
            return True
    return False


def find_efs(ctx):
    """EFS 簽章の位置 → [(位置, 基底)]。基底＝EFS_OFFSETS のどれかを引いた値で、4 KiB 単位の整数。
    16 MiB 視窗の開頭（ずれ 0）なら指標が解けなくても採用（解けなければ problem になる）。カプセルの先頭ヘッダー分ずれている
    （ずれ 0 でなく MAX_SHIFT 以内）場合は、指標のどれかが目錄 cookie に着いたときだけ採用する。"""
    hits, pos = [], ctx.data.find(EFS_SIG)
    while pos >= 0 and len(hits) < MAX_SIG_HITS:
        hits.append(pos)
        pos = ctx.data.find(EFS_SIG, pos + 1)
    if pos >= 0:
        ctx.problem("efs-limit", "image", f"more than {MAX_SIG_HITS} EFS signature candidates; the rest are not examined")
    found = {}
    for p in hits:
        if p + EFS_SIZE > ctx.n:
            continue
        for o in EFS_OFFSETS:
            base = p - o
            if base < 0 or base % 0x1000:
                continue
            shift = base % WINDOW
            if shift == 0 or (shift <= MAX_SHIFT and pointers_resolve(ctx, p, base)):
                if p not in found or found[p][1] > shift:
                    found[p] = (base, shift)
                break_ok = shift == 0
                if break_ok:
                    break
    out = sorted((p, b) for p, (b, _) in found.items())
    if len(out) > MAX_EFS:
        ctx.problem("efs-limit", "image", f"{len(out)} EFS signatures found; only the first {MAX_EFS} are parsed")
        out = out[:MAX_EFS]
    return out


def efs_info(ctx, p, base):
    d = ctx.data
    ptrs = {name: u32(d, p + o) for o, name in EFS_POINTERS}
    other = {name: u32(d, p + o) for o, name in EFS_UNPARSED}
    for name, v in other.items():
        if v not in NO_POINTER:
            ctx.problem("efs-pointer-unparsed", f"EFS@0x{p:x}", f"EFS {name} pointer 0x{v:08x} is present but this firmware component is not parsed")
    return {"offset": p, "window_base": base, "window_size": window_size(ctx.n, base),
            "pointers": {k: f"0x{v:08x}" for k, v in ptrs.items()}, "other_pointers": {k: f"0x{v:08x}" for k, v in other.items()},
            "_raw": ptrs}


# ---------- 目錄 ----------

def dir_mode(info):
    return (info >> 24) & 3 if info >> 31 else (info >> 29) & 3


def follow(ctx, value, bases, via, depth, stack):
    """指標值（EFS 或 combo 項目）→ 驗證目錄 cookie 後解析。基底依序試（EFS 所在視窗的開頭優先，其次 0＝整個檔案的偏移），
    第一個在目標位置看到目錄 cookie 的採用；兩個基底都成立時仍採用視窗內的，另一個位置記在 base_alternative（供人核對）。"""
    cands = []
    for base, w in bases:
        off = to_offset(value, base, w)
        if off is not None and 0 <= off and off + 16 <= ctx.n and bytes(ctx.data[off:off + 4]) in COOKIES and off not in [c[0] for c in cands]:
            cands.append((off, base, w))
    if not cands:
        ctx.problem("pointer-unresolved", via, f"{via}: pointer 0x{value:x} does not resolve to a PSP/BIOS directory (no directory cookie at the target)")
        return None
    off, base, w = cands[0]
    rec = parse_dir(ctx, off, base, w, via, depth, stack)
    if rec is not None and len(cands) > 1:
        rec["base_alternative"] = f"0x{cands[1][0]:x}"
    return rec


def parse_dir(ctx, off, base, w, via, depth, stack):
    d = ctx.data
    if off in stack:
        ctx.problem("dir-loop", f"0x{off:x}", f"{via}: directory at 0x{off:x} points back into the path that led to it (loop); not followed again")
        return None
    done = ctx.by_off.get(off)
    if done is not None:
        if via not in done["reached_via"] and len(done["reached_via"]) < 8:
            done["reached_via"].append(via)
        return done
    ctx.check()
    if len(ctx.dirs) >= MAX_DIRS:
        ctx.problem("dir-limit", f"0x{off:x}", f"more than {MAX_DIRS} directories; the directory at 0x{off:x} and the rest are not parsed")
        return None
    if depth > MAX_DEPTH:
        ctx.problem("dir-limit", f"0x{off:x}", f"directory nesting deeper than {MAX_DEPTH}; the directory at 0x{off:x} is not parsed")
        return None
    cookie = bytes(d[off:off + 4])
    kind = COOKIES[cookie]
    hdr, esz = HEADER[kind], ENTRY_SIZE[kind]
    num, info = u32(d, off + 8), u32(d, off + 12)
    rec = {"kind": kind, "cookie": cookie.decode("ascii"), "offset": off, "base": base, "window_size": w, "reached_via": [via],
           "num_entries": num, "checksum": f"0x{u32(d, off + 4):08x}", "checksum_ok": None, "parsed": False, "trusted": False, "entries": [],
           "address_mode": None, "size": None}
    ctx.by_off[off] = rec
    ctx.dirs.append(rec)
    where = f"{KIND_TEXT[kind]} @0x{off:x}"
    if kind.startswith("combo"):
        rec["lookup"] = info
    else:
        rec["address_mode"] = dir_mode(info)
        rec["additional_info"] = f"0x{info:08x}"
    if num > MAX_DIR_ENTRIES:
        ctx.problem("dir-too-many-entries", where, f"{where}: {num} entries (limit {MAX_DIR_ENTRIES}); entries not parsed")
        return rec
    if ctx.entries_total + num > MAX_ENTRIES_TOTAL:
        ctx.problem("dir-limit", where, f"{where}: more than {MAX_ENTRIES_TOTAL} directory entries in total; entries not parsed")
        return rec
    end = off + hdr + num * esz
    if end > ctx.n:
        ctx.problem("dir-truncated", where, f"{where}: {num} entries would end at 0x{end:x}, past the end of the file (0x{ctx.n:x}); entries not parsed")
        return rec
    ctx.entries_total += num
    rec["size"] = end - off
    calc = fletcher32(d[off + 8:end])
    rec["checksum_ok"] = calc == u32(d, off + 4)
    rec["parsed"] = True
    rec["trusted"] = rec["checksum_ok"]
    if not rec["checksum_ok"]:
        ctx.problem("dir-checksum", where, f"{where}: checksum {rec['checksum']} does not match the computed 0x{calc:08x}; entries are listed but not used for versions, hashes or microcode")
    for i in range(num):
        e = off + hdr + i * esz
        if kind.startswith("combo"):
            id_sel, cid, addr = struct.unpack_from("<IIQ", d, e)
            ent = {"index": i, "id_sel": id_sel, "id": f"0x{cid:08x}", "address": f"0x{addr:x}", "child": None}
            rec["entries"].append(ent)
            if addr in (0, (1 << 64) - 1, 0xFFFFFFFF):
                continue
            ch = follow(ctx, addr, [(base, w)] + ([(0, w)] if base else []), f"{where} entry {i} (id 0x{cid:08x})", depth + 1, stack + (off,))
            ent["child"] = None if ch is None else ch["offset"]
        else:
            rec["entries"].append(entry(ctx, rec, i, e, where, depth, stack))
    return rec


def entry(ctx, rec, i, e, where, depth, stack):
    d, kind = ctx.data, rec["kind"]
    bios = kind.startswith("bios")
    if bios:
        typ, region, f1, f2, size, src, dest = struct.unpack_from("<BBBBIQQ", d, e)
        ent = {"index": i, "type": typ, "type_name": BIOS_TYPES.get(typ), "region_type": region, "reset": bool(f1 & 1), "copy": bool(f1 & 2),
               "read_only": bool(f1 & 4), "compressed": bool(f1 & 8), "instance": f1 >> 4, "subprogram": f2 & 7, "rom_id": (f2 >> 3) & 3,
               "writable": bool(f2 & 0x20), "dest": None if dest == (1 << 64) - 1 else f"0x{dest:x}"}
    else:
        typ, sub, fl, size, src = struct.unpack_from("<BBHIQ", d, e)
        ent = {"index": i, "type": typ, "type_name": PSP_TYPES.get(typ), "subprogram": sub, "rom_id": fl & 3, "writable": bool(fl & 4),
               "instance": (fl >> 3) & 15, "flags": f"0x{fl:04x}"}
    emode, value = src >> 62, src & ADDR_MASK
    ent.update(size=size, value=f"0x{value:x}", entry_address_mode=emode, offset=None, kind="blob", version=None, version_basis=None, sha256=None, sha512=None)
    where_e = f"{where} entry {i} (type 0x{typ:02x}{' ' + ent['type_name'] if ent['type_name'] else ''})"
    ent["where"] = where_e
    if ent["type_name"] is None:
        ctx.problem("type-unknown", where_e, f"{where_e}: entry type 0x{typ:02x} is not in the public type lists used here (coreboot psp_directory.h／bios_directory.h); not interpreted")
    if size == VALUE_SIZE:
        ent["kind"] = "value"               # 位址欄位是值（例如 soft fuse chain），不是位置
        return ent
    ish = size == 0 and not bios and typ in ISH_TYPES
    if size == 0 and not ish:
        ent["kind"] = "empty"               # 沒有來源資料（例如只有 dest 的 APOB）
        return ent
    mode = rec["address_mode"] if rec["address_mode"] in (0, 1) else emode
    if mode == 3:
        ctx.problem("entry-address", where_e, f"{where_e}: address mode 3 (relative to slot) is not supported; location not resolved")
        ent["kind"] = "unresolved"
        return ent
    off = rec["offset"] + value if mode == 2 else to_offset(value, rec["base"], rec["window_size"])
    if ish:                                 # A/B 復原：size 0 的 0x48／0x4A 項目指到 Image Slot Header（0x20 bytes），裡面有 L2 目錄的位置
        return ish_entry(ctx, rec, ent, off, where_e, depth, stack)
    if off is None or off < 0:
        ctx.problem("entry-address", where_e, f"{where_e}: address 0x{value:x} cannot be resolved (mode {mode})")
        ent["kind"] = "unresolved"
        return ent
    ent["offset"] = off
    if 0 <= off and off + 16 <= ctx.n and bytes(d[off:off + 4]) in COOKIES and size >= 16:
        ent["kind"] = "directory-pointer"   # 解出的位置是另一個目錄：往下走（不是韌體條目）
        ch = parse_dir(ctx, off, rec["base"], rec["window_size"], where_e, depth + 1, stack + (rec["offset"],))
        ent["child"] = None if ch is None else ch["offset"]
        return ent
    if typ in POINTER_TYPES.get(kind, ()):
        ent["kind"] = "unresolved"
        ctx.problem("pointer-unresolved", where_e, f"{where_e}: directory pointer entry does not point to a directory (no cookie at 0x{off:x})")
        return ent
    if size > MAX_BLOB:
        ctx.problem("entry-size", where_e, f"{where_e}: size 0x{size:x} is larger than the limit 0x{MAX_BLOB:x}; not read")
        ent["kind"] = "unresolved"
        return ent
    if bios and ent["compressed"]:
        ent["size_note"] = "compressed entry: the stored extent is not known from the size field, so range and overlap checks are skipped"
        return ent
    if off + size > ctx.n:
        ctx.problem("entry-range", where_e, f"{where_e}: range 0x{off:x}+0x{size:x} extends past the end of the file (0x{ctx.n:x})")
        ent["kind"] = "unresolved"
    return ent


def ish_entry(ctx, rec, ent, off, where_e, depth, stack):
    """Image Slot Header（coreboot ish.h 的 ish_directory_table，0x20 bytes：checksum、boot_priority、update_retry_count、glitch_retry_count＋3 保留、
    pl2_location、psp_id、slot_max_size、保留）。pl2_location 用 cookie 驗證後往下走。checksum 的算法沒有公開說明可核對 → 不驗證，記一筆 problem。"""
    d = ctx.data
    if off is None or off < 0 or off + ISH_LEN > ctx.n:
        ctx.problem("entry-address", where_e, f"{where_e}: image slot header cannot be read (address outside the file)")
        ent["kind"] = "unresolved"
        return ent
    ent["offset"], ent["kind"] = off, "ish"
    cks, prio, retry, _, pl2, psp_id, slot_max, _ = struct.unpack_from("<IIIIIIII", d, off)
    ent["ish"] = {"checksum": f"0x{cks:08x}", "checksum_verified": False, "boot_priority": f"0x{prio:08x}", "update_retry_count": f"0x{retry:08x}",
                  "pl2_location": f"0x{pl2:08x}", "psp_id": f"0x{psp_id:08x}", "slot_max_size": f"0x{slot_max:08x}"}
    if not ctx.counts.get("ish-unverified"):
        ctx.problem("ish-unverified", where_e, "image slot header (A/B recovery) checksums are not verified: no documented algorithm was available to check against; "
                    "the L2 directory location in each header is accepted only if a directory cookie is found there")
    else:
        ctx.counts["ish-unverified"] += 1
    ent["child"] = None
    if pl2 not in NO_POINTER:
        ch = follow(ctx, pl2, [(rec["base"], rec["window_size"])] + ([(0, rec["window_size"])] if rec["base"] else []), f"{where_e} slot header pl2_location",
                    depth + 1, stack + (rec["offset"],))
        ent["child"] = None if ch is None else ch["offset"]
    return ent


# ---------- 條目內容：PSP 標頭版本、微碼 ----------

def digests(ctx, off, size):
    """(sha256, sha512)；同一段只算一次，總量有上限（超過 → None, None 並記 problem 一次）。"""
    key = (off, size)
    if key in ctx.hashed:
        return ctx.hashed[key]
    if size > ctx.hash_left:
        if not ctx.counts.get("hash-limit"):
            ctx.problem("hash-limit", "image", f"hashing limit {MAX_HASH_TOTAL} bytes reached; later entries have no hash")
        ctx.hashed[key] = (None, None)
        return ctx.hashed[key]
    ctx.hash_left -= size
    v = memoryview(ctx.data)[off:off + size]
    ctx.hashed[key] = (hashlib.sha256(v).hexdigest(), hashlib.sha512(v).hexdigest())
    return ctx.hashed[key]


def psp_version(ctx, ent):
    """PSP 韌體標頭（amd_fw_header）：fw_type（+0x7C）與目錄項目的 type 相同、size_total（+0x6C）在 0x100 到項目大小之間才讀 +0x60 的 4 bytes。
    顯示成 byte 反序的十六進位 `aa.bb.cc.dd`（amdfwtool、PSPTool 的顯示方式）；欄位全 0 或全 1 當作沒有版本。"""
    d, off, size = ctx.data, ent["offset"], ent["size"]
    if size < PSP_HDR_LEN or off + PSP_HDR_LEN > ctx.n:
        return None
    if d[off + PSP_TYPE_AT] != ent["type"] or not (PSP_HDR_LEN <= u32(d, off + PSP_SIZE_AT) <= size):
        return None
    raw = bytes(d[off + PSP_VERSION_AT:off + PSP_VERSION_AT + 4])
    if raw in (b"\x00" * 4, b"\xff" * 4):        # 欄位沒有填（全 0／全 1）：不是版本
        return None
    return ".".join(f"{b:02x}" for b in reversed(raw))


def patch_header(d, o, avail):
    """AMD 微碼 patch 標頭（microcode_header_amd）→ dict 或 None。日期是 BCD mmddyyyy、patch_id 與 equivalence id 不是 0／全 1 才算。"""
    if avail < UCODE_HDR_LEN:
        return None
    date, pid, data_id, dlen, init, csum, nb, sb, equiv = struct.unpack_from("<IIHBBIIIH", d, o)
    iso = bcd_date(date)
    if iso is None or pid in (0, 0xFFFFFFFF) or equiv in (0, 0xFFFF):
        return None
    return {"patch_id": f"0x{pid:08x}", "date": iso, "equiv_id": f"0x{equiv:04x}", "data_id": f"0x{data_id:04x}"}


def parse_ucode(ctx, ent):
    """BIOS 目錄 type 0x66 的項目 → ([微碼 dict], problem 文字或 None)。
    項目開頭是 `DMA\\0` container（等價表＋patch 區段）或單一 patch 標頭；其他 → 看不懂。"""
    d, off, size = ctx.data, ent["offset"], ent["size"]
    if d[off:off + 4] == UCODE_MAGIC:
        if size < 12 + 16:
            return [], "container is too short"
        typ, eq_size = struct.unpack_from("<II", d, off + 4)
        if typ != 0 or eq_size % 16 or eq_size > MAX_EQUIV * 16 or 12 + eq_size > size:
            return [], f"container equivalence table is not valid (type {typ}, size 0x{eq_size:x})"
        equiv = {}
        for p in range(off + 12, off + 12 + eq_size, 16):
            cpu, _, _, eq, _ = struct.unpack_from("<IIIHH", d, p)
            if cpu == 0:
                break
            equiv.setdefault(eq, []).append(cpu)
        out, p, end = [], off + 12 + eq_size, off + size
        while p + 8 <= end and len(out) < MAX_PATCHES:
            stype, ssize = struct.unpack_from("<II", d, p)
            if stype == 0 and ssize == 0:
                break
            if stype != 1 or ssize < UCODE_HDR_LEN or p + 8 + ssize > end:
                return out, f"container section at +0x{p - off:x} is not a valid patch section (type {stype}, size 0x{ssize:x})"
            h = patch_header(d, p + 8, ssize)
            if h is None:
                return out, f"container patch at +0x{p + 8 - off:x} has an invalid header"
            cpus = equiv.get(int(h["equiv_id"], 16))
            out.append({**h, "cpuids": None if cpus is None else [f"{c:08X}" for c in sorted(set(cpus))], "form": "container", "patch_size": ssize,
                        "patch_offset": p + 8})
            p += 8 + ssize
        return out, (None if out else "container has no patch section")
    h = patch_header(d, off, size)
    if h is None:
        return [], "neither a DMA container nor a patch header (date, patch id or equivalence id invalid)"
    return [{**h, "cpuids": None, "form": "raw-patch", "patch_size": size, "patch_offset": off}], None


def collect_contents(ctx, amd):
    """已解析（checksum 通過）的目錄項目 → psp_firmware、microcode。"""
    psp, ucode, seen_u = {}, [], {}
    unversioned = {}
    for rec in ctx.dirs:
        if not rec["trusted"] or rec["kind"].startswith("combo"):
            continue
        for ent in rec["entries"]:
            if ent["kind"] != "blob" or ent["offset"] is None:
                continue
            if rec["kind"].startswith("psp"):
                v = psp_version(ctx, ent)
                if v is None:
                    unversioned.setdefault((ent["type"], ent["type_name"]), []).append(ent["where"])
                    continue
                ent["version"], ent["version_basis"] = v, "PSP firmware header (amd_fw_header) +0x60; fw_type and size_total agree with the directory entry"
                ent["sha256"], ent["sha512"] = digests(ctx, ent["offset"], ent["size"])
                key = (ent["type"], ent["subprogram"], v, ent["sha256"] or f"{ent['offset']}:{ent['size']}")
                p = psp.setdefault(key, {"type": ent["type"], "type_name": ent["type_name"], "subprogram": ent["subprogram"], "version": v,
                                         "size": ent["size"], "sha256": ent["sha256"], "sha512": ent["sha512"], "locations": []})
                if len(p["locations"]) < 16:
                    p["locations"].append({"directory": f"{KIND_TEXT[rec['kind']]} @0x{rec['offset']:x}", "index": ent["index"],
                                           "instance": ent["instance"], "offset": ent["offset"]})
            elif ent["type"] == UCODE_TYPE:
                if len(ucode) >= MAX_UCODE:
                    ctx.problem("ucode-limit", ent["where"], f"more than {MAX_UCODE} microcode patches; the rest are not listed")
                    continue
                patches, why = parse_ucode(ctx, ent)
                if why:
                    ctx.problem("ucode-unrecognised", ent["where"], f"{ent['where']}: microcode entry not fully understood ({why})")
                for h in patches:
                    sha = digests(ctx, h["patch_offset"], h["patch_size"])
                    k = (h["patch_id"], h["equiv_id"], sha[0] or (h["patch_offset"], h["patch_size"]))
                    m = seen_u.get(k)
                    loc = {"directory": f"{KIND_TEXT[rec['kind']]} @0x{rec['offset']:x}", "index": ent["index"], "instance": ent["instance"],
                           "offset": h["patch_offset"]}
                    if m is None:
                        m = seen_u[k] = {**h, "sha256": sha[0], "sha512": sha[1], "locations": []}
                        ucode.append(m)
                    if len(m["locations"]) < 16:
                        m["locations"].append(loc)
    if unversioned:
        n = sum(len(v) for v in unversioned.values())
        names = ", ".join(f"0x{t:02x}{' ' + nm if nm else ''}×{len(v)}" for (t, nm), v in sorted(unversioned.items()))
        ctx.problem("version-unverified", "PSP directories", f"{n} PSP directory entries have no verifiable version field "
                    f"(no PSP header with fw_type and size_total matching the entry, or an all-zero／all-one version field): {names}")
    if any(m["cpuids"] is None for m in ucode):
        ctx.problem("ucode-cpuid", "BIOS directories", "microcode patches are not inside a container with an equivalence table, so only the equivalence id is listed "
                    "(the mapping from equivalence id to CPUID is not guessed)")
    amd["psp_firmware"] = sorted(psp.values(), key=lambda x: (x["type"], x["subprogram"], x["version"]))
    amd["microcode"] = sorted(ucode, key=lambda x: (x["equiv_id"], x["patch_id"]))


# ---------- 範圍重疊 ----------

def check_overlaps(ctx):
    """同一個目錄內的條目範圍互相重疊、目錄表（標頭＋項目）和任何條目範圍重疊、目錄表互相重疊 → problem。
    不同目錄指到完全相同的範圍是正常的（共用條目）；不同目錄的條目大小不同但起點相同或互相包含（例如 L1 保留較大的區間）不算。
    壓縮的 BIOS 條目沒有可靠的儲存範圍，略過。"""
    tables = [(r["offset"], r["offset"] + r["size"], f"{KIND_TEXT[r['kind']]} @0x{r['offset']:x}") for r in ctx.dirs if r["size"]]

    def sweep(items, scope):
        top = None                          # (起點, 終點, 說明)：目前涵蓋到最遠的範圍
        for s, e, label in sorted(set(items)):
            if top is not None and s < top[1] and (s, e) != (top[0], top[1]):
                ctx.problem("entry-overlap", scope, f"{scope}: {label} [0x{s:x}, 0x{e:x}) overlaps {top[2]} [0x{top[0]:x}, 0x{top[1]:x})")
            if top is None or e > top[1]:
                top = (s, e, label)

    for r in ctx.dirs:
        if not r["parsed"] or r["kind"].startswith("combo") and not r["entries"]:
            continue
        items = [(r["offset"], r["offset"] + r["size"], "the directory table itself")] if r["size"] else []
        for ent in r["entries"]:
            if ent.get("kind") == "blob" and ent.get("offset") is not None and not ent.get("compressed") and ent["offset"] + ent["size"] <= ctx.n:
                items.append((ent["offset"], ent["offset"] + ent["size"], f"entry {ent['index']} (type 0x{ent['type']:02x})"))
        sweep(items, f"{KIND_TEXT[r['kind']]} @0x{r['offset']:x}")
    sweep(tables, "directory tables")
    blobs = [(ent["offset"], ent["offset"] + ent["size"], f"entry {ent['index']} of {KIND_TEXT[r['kind']]} @0x{r['offset']:x}")
             for r in ctx.dirs for ent in r["entries"] if ent.get("kind") == "blob" and ent.get("offset") is not None and not ent.get("compressed")
             and ent["offset"] + ent["size"] <= ctx.n]
    for ts, te, tl in tables:
        for bs, be, bl in blobs:
            if bs < te and ts < be:
                ctx.problem("entry-overlap", "directory tables", f"{tl} partly overlaps {bl}")


# ---------- AGESA ----------

def _sibling(name):
    """同目錄的模組（python3 -I 不把腳本目錄放進 sys.path；測試 import 過就共用同一個）。"""
    mod = sys.modules.get(name)
    if mod is None:
        path = Path(__file__).resolve().with_name(name + ".py")
        try:
            spec = importlib.util.spec_from_file_location(name, path)
            mod = importlib.util.module_from_spec(spec)
            sys.modules[name] = mod
            spec.loader.exec_module(mod)
        except (OSError, ImportError, AttributeError, SyntaxError) as e:
            sys.modules.pop(name, None)
            raise ImportError(f"cannot load {name}.py ({type(e).__name__})")
    return mod


def read_agesa(buf, pos):
    """pos 是 `AGESA!V` 的位置 → (tag, value, truncated)。tag＝`V` 加最多 4 個英數字（例如 V9）；中間最多一個 NUL 或空白；
    value＝接著最多 AGESA_VALUE_LEN 個可列印 ASCII（去頭尾空白）。"""
    i = pos + len(AGESA_MARK)
    j = i
    while j < len(buf) and j - i < 4 and (48 <= buf[j] <= 57 or 65 <= buf[j] <= 90 or 97 <= buf[j] <= 122):
        j += 1
    tag = "V" + bytes(buf[i:j]).decode("ascii")
    if j < len(buf) and buf[j] in (0, 0x20):
        j += 1
    k = j
    while k < len(buf) and k - j < AGESA_VALUE_LEN and 0x20 <= buf[k] < 0x7F:
        k += 1
    truncated = k - j == AGESA_VALUE_LEN and k < len(buf) and 0x20 <= buf[k] < 0x7F
    return tag, bytes(buf[j:k]).decode("ascii").strip(), truncated


def agesa_search(data, budget=None, soft=()):
    """走訪 firmware volume（uefi_image，LZMA 等解開；FV 以外的非空白位元組它也當原始內容送進來）搜尋；uefi_image 載入不了或走訪失敗時改搜原始位元組。
    → {"values": [{tag, value, count, found}], "problems": [文字], "complete": bool, "stats": {...}}。永遠回傳，不丟例外（soft 的例外除外時也只記為不完整）。"""
    r = {"values": [], "problems": [], "complete": False, "walk": False, "stats": {"markers": 0, "inspected_bytes": 0, "fvs": 0, "ffs_files": 0}}
    table, st, seen = {}, r["stats"], set()
    state = {"capped": False, "inspect_capped": False}

    def inspect(buf, where):
        if budget is not None:
            budget.check()
        pos = buf.find(AGESA_MARK)
        while pos >= 0:
            if st["markers"] >= MAX_AGESA_MARKERS:
                if not state["capped"]:
                    state["capped"] = True
                    r["problems"].append(f"more than {MAX_AGESA_MARKERS} AGESA markers; the rest are not read")
                return
            st["markers"] += 1
            tag, value, trunc = read_agesa(buf, pos)
            if not value:
                r["problems"].append(f"AGESA marker without a readable version string at {where} +0x{pos:x}")
            else:
                key = (tag, value)
                e = table.get(key)
                if e is None:
                    if len(table) >= MAX_AGESA_VALUES:
                        r["problems"].append(f"more than {MAX_AGESA_VALUES} distinct AGESA strings; the rest are not listed")
                        e = {"found": [], "count": 0}
                    else:
                        e = table[key] = {"tag": "AGESA!" + tag, "value": value, "count": 0, "found": [], "truncated": trunc}
                e["count"] += 1
                if len(e["found"]) < MAX_AGESA_LOCATIONS:
                    e["found"].append({"where": where, "offset": pos})
            pos = buf.find(AGESA_MARK, pos + 1)

    def walk_inspect(buf, module):
        n = len(buf)
        if n == 0:
            return
        k = (n, hashlib.blake2b(buf, digest_size=16).digest())
        if k in seen:
            return
        seen.add(k)
        if st["inspected_bytes"] + n > MAX_AGESA_INSPECT:
            if not state["inspect_capped"]:
                state["inspect_capped"] = True
                r["problems"].append(f"more than {MAX_AGESA_INSPECT} bytes of distinct UEFI content; the rest was not searched")
            return
        st["inspected_bytes"] += n
        inspect(buf, "uefi:" + (module or "?"))

    complete = True
    try:
        ui = _sibling("uefi_image")
    except ImportError as e:
        r["problems"].append(f"{e}; compressed UEFI content was not searched for AGESA strings (only the raw bytes were)")
        try:
            inspect(data, "image")
        except soft as e2:
            r["problems"].append(f"stopped early: {e2}")
        r["values"] = list(table.values())
        return r

    class AgesaScan(ui.Scan):
        def scan_bytes(self, buf, module=None):           # 覆寫：不做函式庫指紋，只找 AGESA（和 uefi_gfx.py 同樣的做法）
            walk_inspect(buf, module)

    sc = AgesaScan()
    r["walk"] = True
    try:
        ui.parse_fvs(bytes(data), sc, 0)
    except ui.Stop as e:
        r["problems"].append(f"UEFI walk reached a limit ({e}); the AGESA search is incomplete")
        complete = False
    except soft as e:
        r["problems"].append(f"stopped early: {e}")
        complete = False
    except Exception as e:      # noqa: BLE001 — 不可信輸入：任何例外都只記為不完整
        r["problems"].append(f"UEFI walk failed ({type(e).__name__}); the AGESA search is incomplete")
        complete = False
        try:
            inspect(data, "image")          # 走訪失敗：至少把原始位元組搜一遍
        except soft:
            pass
    st["fvs"], st["ffs_files"] = sc.fvs, sc.files
    # 最上層、FV 以外的位元組 uefi_image 當原始內容送進 scan_bytes 了（有被搜尋），所以不算沒解開
    undec = [x for x in sc.undecoded if not (x["where"] == "image" and "outside any valid firmware volume" in x["reason"])]
    if undec:
        why = sorted({" ".join(str(x["reason"]).split())[:120] for x in undec})[:3]
        r["problems"].append(f"{len(undec)} UEFI parts were not decoded ({'; '.join(why)}); the AGESA search did not look inside them")
        complete = False
    if sc.notes or sc.parse_errors:
        first = " ".join(str(sc.notes[0]).split())[:120] if sc.notes else f"{sc.parse_errors} parse errors"
        r["problems"].append(f"the UEFI walk reported structure warnings ({first}); the AGESA search may be incomplete")
        complete = False
    if not sc.fvs:
        r["problems"].append("no UEFI firmware volume was decoded; only the raw bytes were searched for AGESA strings")
        complete = False
    if state["capped"] or state["inspect_capped"]:
        complete = False
    r["complete"] = complete
    r["values"] = sorted(table.values(), key=lambda x: (x["tag"], x["value"]))
    return r


# ---------- 入口 ----------

GAP_TEXT = {
    "efs-limit": "EFS limit", "efs-pointer-unparsed": "EFS pointers present but not parsed", "pointer-unresolved": "pointers that do not resolve to a directory",
"dir-loop": "directory loops", "dir-limit": "directory limits reached",
    "dir-too-many-entries": "directories with too many entries", "dir-truncated": "directories running past the end of the file",
    "dir-checksum": "directory checksum mismatches", "type-unknown": "entries of unknown type", "entry-address": "entries whose address cannot be resolved",
    "entry-size": "entries too large", "entry-range": "entries outside the file", "entry-overlap": "overlapping ranges", "version-unverified": "entries without a version",
    "no-directory": "no usable PSP/BIOS directory", "efs-no-pointer": "EFS without directory pointers",
    "ucode-unrecognised": "microcode entries not understood", "ucode-cpuid": "microcode without CPUID", "ucode-limit": "microcode limit", "hash-limit": "hash limit", "ish-unverified": "image slot header checksums not verified",
}
ATTENTION_CODES = ("dir-checksum", "dir-loop", "entry-overlap", "entry-range", "dir-limit")


def summarize(problems, counts):
    """problem 清單 → gap 文字（每種 code 一行：件數與前幾個例子）。"""
    out, by = [], {}
    for p in problems:
        by.setdefault(p["code"], []).append(p["text"])
    for code, texts in by.items():
        shown = texts[:3]
        out.append(f"AMD: {GAP_TEXT.get(code, code)} ({counts[code]}): " + "; ".join(shown) + ("; …" if counts[code] > len(shown) else ""))
    return out


def analyze(data, budget=None, soft=()):
    """AMD 平台映像的位元組 → dict（可轉 JSON）。永遠回傳（soft 例外＝超時：已有的結果照給，記 incomplete）。
    鍵：efs、directories、psp_firmware、microcode、agesa、problems（逐筆）、gaps（彙整後的文字）、attention（要 ATTENTION 的理由）、incomplete、stats。"""
    data = bytes(data) if not isinstance(data, bytes) else data
    ctx = Ctx(data, budget)
    amd = {"efs": [], "directories": [], "psp_firmware": [], "microcode": [], "agesa": {"values": [], "complete": False, "problems": []},
           "problems": [], "gaps": [], "attention": [], "incomplete": [], "stats": {}}
    efs = []
    try:
        efs = [efs_info(ctx, p, b) for p, b in find_efs(ctx)]
        for x in efs:
            raw = x.pop("_raw")
            base, w = x["window_base"], x["window_size"]
            bases = [(base, w)] + ([(0, w)] if base else [])
            n_before = len(ctx.dirs)
            for _, name in EFS_POINTERS:
                if raw[name] in NO_POINTER:
                    continue
                follow(ctx, raw[name], bases, f"EFS@0x{x['offset']:x} {name}", 0, ())
            x["directories_found"] = len(ctx.dirs) - n_before
            if not x["directories_found"] and not any(raw[n] not in NO_POINTER for _, n in EFS_POINTERS):
                ctx.problem("efs-no-pointer", f"EFS@0x{x['offset']:x}", f"EFS at 0x{x['offset']:x} has no PSP/BIOS directory pointer")
        amd["efs"] = efs
        collect_contents(ctx, amd)
        check_overlaps(ctx)
    except soft as e:
        amd["incomplete"].append(f"AMD PSP/BIOS directory parse stopped early: {e}")
    try:
        ag = agesa_search(data, budget, soft)
    except soft as e:
        ag = {"values": [], "problems": [f"stopped early: {e}"], "complete": False, "walk": False, "stats": {}}
    amd["agesa"] = ag
    amd["directories"] = [{k: v for k, v in r.items() if k != "window_size"} for r in ctx.dirs]
    shown, seen = [], {}
    for p in ctx.problems:
        seen[p["code"]] = seen.get(p["code"], 0) + 1
        if seen[p["code"]] <= MAX_PROBLEMS_SHOWN:
            shown.append(p)
    amd["problems"] = shown
    counts = dict(ctx.counts)
    if not ctx.dirs:
        counts["no-directory"] = 1
        shown.append({"code": "no-directory", "where": "image", "text": "no PSP/BIOS directory could be parsed (EFS missing or its pointers do not resolve to directories)"})
    gaps = summarize(shown, counts)
    if not amd["microcode"]:
        gaps.append("AMD: no microcode patch was read from a BIOS directory (type 0x66); this is not 'no microcode'")
    for t in ag["problems"][:3]:
        gaps.append("AMD: AGESA search: " + t)
    if not ag["values"] and ag["complete"] is False:
        gaps.append("AMD: no AGESA string found in a search that was not complete (not found does not mean absent)")
    elif not ag["values"]:
        gaps.append("AMD: no AGESA string found")
    amd["gaps"] = gaps
    amd["attention"] = [f"{GAP_TEXT[c]} ({counts[c]})" for c in ATTENTION_CODES if counts.get(c)]
    if len(ag["values"]) > 1:
        amd["attention"].append("more than one AGESA string: " + ", ".join(f"{x['tag']} {x['value']}" for x in ag["values"]))
    amd["stats"] = {"efs": len(efs), "directories": len(ctx.dirs), "entries": ctx.entries_total,
                    "psp_firmware": len(amd["psp_firmware"]), "microcode": len(amd["microcode"]), "agesa_values": len(ag["values"]),
                    "problems": dict(counts), "hashed_bytes": MAX_HASH_TOTAL - ctx.hash_left}
    return amd


def summary_text(amd):
    """一行摘要（狀態、SBOM property 用）。"""
    ag = amd["agesa"]["values"]
    return (f"{amd['stats']['directories']} directories, {amd['stats']['entries']} entries, {len(amd['psp_firmware'])} versioned PSP firmware items, "
            f"{len(amd['microcode'])} microcode patches, AGESA: " + (", ".join(f"{x['tag']} {x['value']}" for x in ag) if ag else "not found"))


def markdown_lines(amd, e):
    """fw-inventory.md 的 AMD 區段（e＝呼叫端的 md_esc，不可信字串都要過它）。"""
    L = ["", "### AMD PSP／BIOS 目錄、微碼與 AGESA", "", "- " + e(summary_text(amd)), ""]
    if amd["efs"]:
        L += ["| EFS 位置 | 視窗 | 指標 |", "|---|---|---|"]
        L += [f"| 0x{x['offset']:x} | 0x{x['window_base']:x}（{x['window_size'] >> 20} MiB） | "
              + e("；".join(f"{k}={v}" for k, v in x["pointers"].items() if v not in ("0x00000000", "0xffffffff", "0xfffffffe")) or "沒有") + " |" for x in amd["efs"]]
        L.append("")
    for r in amd["directories"]:
        flag = "" if r["trusted"] else ("（checksum 不符，條目不採用）" if r["parsed"] else "（沒有解析）")
        L += [f"#### {e(KIND_TEXT[r['kind']])} `{e(r['cookie'])}` @0x{r['offset']:x}{flag}", "",
              f"{r['num_entries']} 項；checksum {r['checksum']}（{'相符' if r['checksum_ok'] else '不符' if r['checksum_ok'] is False else '未檢查'}）；來源：" + e("；".join(r["reached_via"])), ""]
        if r["kind"].startswith("combo"):
            if r["entries"]:
                L += ["| # | id | 目錄位址 | 解到 |", "|---|---|---|---|"]
                L += [f"| {x['index']} | {e(x['id'])} | {e(x['address'])} | {hex_or_none(x['child']) or '無'} |" for x in r["entries"]]
                L.append("")
            continue
        if r["entries"]:
            L += ["| # | type | 名稱 | sub | inst | 位置 | 大小 | 版本 |", "|---|---|---|---|---|---|---|---|"]
            for x in r["entries"]:
                loc = hex_or_none(x["offset"]) if x["kind"] in ("blob", "directory-pointer") else x["kind"]
                L.append(f"| {x['index']} | 0x{x['type']:02x} | {e(x['type_name'] or '未知')} | {x['subprogram']} | {x['instance']} | {e(loc or '未解')} | 0x{x['size']:x} | {e(x['version'] or '')} |")
            L.append("")
    L += ["#### AMD 微碼（BIOS 目錄 type 0x66）", ""]
    if amd["microcode"]:
        L += ["| patch level | 日期 | equivalence id | CPUID | 形式 | 大小 | 位置 |", "|---|---|---|---|---|---|---|"]
        L += [f"| {m['patch_id']} | {m['date']} | {m['equiv_id']} | {e(', '.join(m['cpuids']) if m['cpuids'] else '未對出（沒有等價表）')} | {m['form']} | 0x{m['patch_size']:x} | "
              + e("；".join(f"{x['directory']} #{x['index']} @0x{x['offset']:x}" for x in m["locations"][:2])) + " |" for m in amd["microcode"]]
    else:
        L.append("沒有讀到（GAP，不是沒有微碼）。")
    L += ["", "#### AGESA", ""]
    if amd["agesa"]["values"]:
        L += ["| 標記 | 字串 | 次數 | 位置 |", "|---|---|---|---|"]
        L += [f"| {e(x['tag'])} | {e(x['value'])} | {x['count']} | " + e("；".join(f"{w['where']} +0x{w['offset']:x}" for w in x["found"][:2])) + " |" for x in amd["agesa"]["values"]]
    else:
        L.append("沒有找到" + ("" if amd["agesa"]["complete"] else "（搜尋不完整，不代表不存在）") + "。")
    return L
