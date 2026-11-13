#!/usr/bin/env python3
"""AMD 平台 BIOS 映像的 PSP／BIOS 目錄、微碼與 AGESA 版本：只讀解析（x86_firmware.py 辨識出 AMD 平台時呼叫 analyze()）。

只依賴標準函式庫與同目錄的 uefi_image.py（C1；找 AGESA 字串時用它解開 firmware volume），而且只用它的公開介面：Scan 子類別覆寫 scan_bytes、parse_fvs、Stop、Scan 的結果欄位（fvs、files、undecoded、notes、parse_errors）；不讀它呼叫端的區域變數。
輸入是不可信資料：只讀、不執行、不寫磁碟；
所有欄位先對照檔案範圍與上限（MAX_*）才使用；看不懂的一律記 problem（對外是 GAP），不猜。analyze() 永遠回傳 dict、不丟例外
（soft 參數列的例外＝超時，也只記為不完整）：單一條目的解析錯誤只影響那個條目（problem `entry-error`），其他階段出錯記在 incomplete，已有的結果照給。

## 做什麼
1. Embedded Firmware Structure（EFS，簽章 0x55AA55AA，位置照 coreboot util/amdfwtool/amdfwread.c 依 ROM 大小（≤4／≤8／其餘 MiB）分的三張 fw_header_offsets 表，每個視窗各查一次；
   視窗＝16 MiB 區塊，更新包有標頭造成位移時，指標之一要真的指到目錄 cookie 才採用）
   → 指標欄位 → PSP 目錄（L1 `$PSP`、L2 `$PL2`、combo `2PSP`）與 BIOS 目錄（`$BHD`、`$BL2`、`2BHD`）。目錄裡的項目若指向另一個目錄
   （PSP 的 0x40、BIOS 的 0x70、combo 的每一項……只要解出的位置開頭是目錄 cookie）就往下走，深度、目錄數、項目總數都有上限；每個（位置，基底）只解析一次，循環只是一條指向已存在目錄的邊。
2. 每個目錄項目：type、subprogram、instance、rom id、位置、大小、旗標。PSP 韌體條目的標頭（0x100 bytes）通過檢查才讀版本；其餘版本欄位記 GAP。
3. BIOS 目錄 type 0x66 的 AMD 微碼：patch level（patch_id）、日期、equivalence id；微碼前面有 container 的等價表（`DMA\\0`）時才對出 CPUID，
   否則只列 equivalence id（不猜對照）。
4. AGESA 版本字串（`AGESA!V<n>` 後面接的字串）：走訪 firmware volume（LZMA 等解開）搜尋，另外找整個映像原始位元組裡的標記；原始位元組裡只要有任何標記就讓搜尋標為不完整
   （公開介面沒有辦法證明那個位置有被走訪搜尋過；精確的位置涵蓋留到 M7），只在原始位元組裡有的值列出（位置 `image (raw bytes)`）；不同值全部列出。標記後沒有分隔符、字串被截斷、字串讀不出來的都不當成版本（GAP）。

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
  address_mode 位元 24–25）。checksum＝Fletcher-32（coreboot util/amdfwtool/amdfwtool.c 的 fletcher32：初值 0xFFFF、16 位元字、每 359 個字與最後各折疊一次）
  涵蓋 +8 到最後一個項目結尾。Image Slot Header 的 checksum 用同一個函式，涵蓋 +4 到 +0x20（amdfwtool.c integrate_psp_ab_ish）。
PSP 項目 16 bytes：type u8、subprogram u8、flags u16（位元 0–1 rom id、位元 2 writable、位元 3–6 instance）、size u32、
  位址 u64（位元 0–61 值，位元 62–63 address mode）。size 0xFFFFFFFF 的項目（例如 type 0x0B 的 soft fuse）位址欄位是「值」不是位置。
BIOS 項目 24 bytes：type u8、region_type u8、flags u8（位元 0 reset、1 copy、2 ro、3 compressed、4–7 instance）、
  flags2 u8（位元 0–2 subprogram、3–4 rom id、5 writable）、size u32、來源 u64（同上的 62＋2 位元）、dest u64（0xFF…FF＝沒有）。
combo 目錄：32 bytes 標頭（cookie、checksum、num_entries、lookup、16 bytes 保留，checksum 涵蓋 +8 起），項目 16 bytes：id_sel u32、id u32、目錄位址 u64。
位址：address mode 0（實體）或 1（相對視窗開頭）。值在 2^32−W 以上是「映射在 4 GB 頂端的視窗」位置（W＝視窗大小，最大 16 MiB；
  偏移＝值−(2^32−W)，大於 16 MiB 的映像等於遮成 24 bits），其餘是視窗內偏移；視窗＝EFS 所在的 16 MiB 區塊。
  mode 2＝相對目錄開頭；mode 3（相對 slot）slot 起點未知 → 不解。指向目錄的指標一定用 cookie 驗證。目錄裡的位址（L2 指標、slot header、條目）一律用該目錄自己的基底。

## 競爭的讀法（resolve_readings）
EFS 有位移時指標值可以是「視窗座標」（加視窗開頭）或「整個檔案的偏移」（加 0）；combo 項目也一樣。兩種讀法都在目標位置看到目錄 cookie，或同一個位置被不同的基底讀到，
就有一組互相競爭的讀法：兩邊都解析、都列在 inventory。每一組依「各自的結構檢查」決定（reading_state）。原則：只有結構上的正面證據才算不通過；沒有被完整檢查過的讀法不可以被採用，也不可以替另一邊背書。
  證據（讀錯基底時才會出現的結構性反證）：目錄表超出檔案、checksum 不符；條目的位址解不出來（超過 4 GiB、負的）、條目範圍或壓縮條目的起點超出檔案、指標條目沒指到目錄；
  A/B 復原的 slot header checksum 不符、或 checksum 相符但 pl2_location 沒指到目錄；combo 有位址的項目沒指到目錄；目錄表本身落在自己某個條目的範圍裡。不看版本欄位這類內容的判斷。
  限制（無法判斷，不是證據）：解析被超時或例外打斷、項目數超過 MAX_DIR_ENTRIES、項目總數超過 MAX_ENTRIES_TOTAL、目錄數或深度超過上限（那一種讀法沒有紀錄）、
  address mode 3、條目大小超過 MAX_BLOB、A/B 復原條目的大小不是 0 或 0x100、條目解析出錯。
  每一種讀法都有被完整檢查而且恰好一種通過 → 採用它，有證據不通過的標「未採用」（rejected，附證據，記 reading-rejected，ATTENTION）；通過的有兩種以上而且解讀結果完全相同
  （條目逐項相同、指到的內容雜湊相同、子目錄位置相同；拿不到雜湊不算相同） → 都採用（記 reading-equivalent）；通過的有兩種以上但內容不同、都沒通過、有任何一種無法判斷（限制）、
  或有讀法沒有紀錄 → 整組維持歧義（ambiguous，GAP：pointer-ambiguous／dir-ambiguous），條目只列在 inventory、不進 SBOM；沒有任何一種被採用時，沒通過的也不標未採用。
  碰到任何上限（目錄數、深度、項目數、項目總數、EFS 數）、發現目錄循環、比較內容時雜湊上限用完、或目錄階段沒走完（超時或例外）時，所有競爭的讀法一律維持歧義
  （目錄階段沒走完時所有紀錄都不採用也不拒絕）。
  指標的那一組只作用在那一個指標的邊（同一個目錄若也從別的單一讀法的指標到得了，仍然確定）；同一個位置不同基底的那一組作用在紀錄本身。
  確定的目錄＝從 EFS 出發只走通過的邊到得了的；被採用讀法的子目錄沿用它的基底、確定；被拒絕讀法底下只能經由它到得了的子目錄跟著不採用，經由歧義的讀法才到得了的子目錄是歧義。
  結果只取決於走訪到的紀錄與邊（走訪依深度逐層、同層依（位置，基底）排序），和 EFS、指標的處理順序無關。

## 上限與放大控制（見 MAX_*）
視窗內 EFS 數、目錄數、深度、每個目錄的項目數、全部目錄的項目總數、雜湊總量（同一段 offset＋size 只算一次）、單一項目大小、微碼數、AGESA 標記數與
送進搜尋的走訪內容總量（MAX_AGESA_INSPECT，不去重）；每個（位置，基底）只解析一次，循環不重複走。regex 只用固定字面值；AGESA 用 bytes.find。
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
MAX_AGESA_INSPECT = 1 << 30            # 走訪 firmware volume 時送進搜尋的位元組總量（每次 scan_bytes 的內容都算，不去重）
AGESA_VALUE_LEN = 64                   # AGESA 標記後面讀的字串長度上限
AGESA_MARK = b"AGESA!V"

EFS_SIG = b"\xaa\x55\xaa\x55"
# coreboot util/amdfwtool/amdfwread.c 的 fw_header_offsets（ROM 大於 8 MiB）、fw_header_offsets_8MiB、fw_header_offsets_4MiB（ROM ≤ 4 MiB）；
# 視窗大小 ≤ 4 MiB 用 4 MiB 表、≤ 8 MiB 用 8 MiB 表、其餘用 16 MiB 表（視窗大小見 window_size）
EFS_OFFSETS_16 = (0xFA0000, 0xF20000, 0xE20000, 0xC20000, 0x820000, 0x020000)
EFS_OFFSETS_8 = (0x7A0000, 0x720000, 0x620000, 0x420000, 0x020000)
EFS_OFFSETS_4 = (0x3A0000, 0x320000, 0x220000, 0x020000)
EFS_OFFSETS = tuple(sorted(set(EFS_OFFSETS_16 + EFS_OFFSETS_8 + EFS_OFFSETS_4), reverse=True))


def efs_offsets(w):
    return EFS_OFFSETS_4 if w <= 4 << 20 else EFS_OFFSETS_8 if w <= 8 << 20 else EFS_OFFSETS_16

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
ISH_TYPES = (0x48, 0x4A)               # RECOVERYAB_A／B：位址指到 Image Slot Header（0x20 bytes）
ISH_LEN = 0x20
ISH_ENTRY_SIZE = 0x100                 # coreboot 寫的是 BLOB_ALIGNMENT（0x100）；實際映像也有 0。其他大小不解讀（ish-size）
APOB_TYPE = 0x61
PSP_HDR_LEN = 0x100                    # amd_fw_header
PSP_VERSION_AT, PSP_SIZE_AT, PSP_TYPE_AT = 0x60, 0x6C, 0x7C

UCODE_MAGIC = b"DMA\x00"               # container 魔術字（Linux amd.c UCODE_MAGIC 0x00414d44）
UCODE_HDR_LEN = 0x1A                   # microcode_header_amd 到 processor_rev_id（+0x18 u16）結束


class Ctx:
    """一次 analyze() 的狀態。"""

    def __init__(self, data, budget):
        self.data, self.n, self.budget = data, len(data), budget
        self.dirs, self.by_key, self.problems, self.counts = [], {}, [], {}
        self.edges = []                 # (上一層目錄的 (位置, 基底) 或 None＝EFS, 這一層的 (位置, 基底), 這條邊所屬的指標讀法組（frozenset of (位置, 基底)）或 None)
        self.groups = []                # 一個指標有兩種以上讀法時的 {"keys": [(位置, 基底)…], "via": 來源說明, "value": 指標值}
        self.pending, self.attempted, self.via = {}, set(), {}      # 下一層待解析的 {(位置, 基底): 視窗大小}、已經排進解析的、每個紀錄的來源說明集合
        self.uncertain = set()          # 上限、循環等讓「哪一種讀法才是真的」無法判斷的原因（非空 → 所有競爭的讀法維持歧義）
        self.dir_done = False           # 目錄階段整個走完（沒有被超時或例外打斷）
        self.entries_total = 0
        self.hash_left = MAX_HASH_TOTAL
        self.hashed = {}

    def problem(self, code, where, text):
        self.counts[code] = self.counts.get(code, 0) + 1
        self.problems.append({"code": code, "where": where, "text": text})

    def limit(self, where, text, code="dir-limit"):
        """碰到上限：記 problem，並讓所有競爭的讀法維持歧義（上限讓哪些紀錄沒被解析取決於內容，工具沒辦法保證沒有漏掉的讀法）。"""
        self.problem(code, where, text)
        self.uncertain.add("a limit was reached (" + code + ")")

    def check(self):
        if self.budget is not None:
            self.budget.check()


def u32(d, o):
    return struct.unpack_from("<I", d, o)[0]


def fletcher32(buf):
    """coreboot util/amdfwtool/amdfwtool.c 的 fletcher32：c0＝c1＝0xFFFF 起算，16 位元小端字，每 359 個字折疊一次（高 16 位加回低 16 位），最後再折疊一次；
    奇數長度的最後一個 byte 不算。"""
    n = len(buf) // 2
    words = struct.unpack_from("<%dH" % n, buf) if n else ()
    c0 = c1 = 0xFFFF
    for i in range(0, n, 359):
        for w in words[i:i + 359]:
            c0 = (c0 + w) & 0xFFFFFFFF
            c1 = (c1 + c0) & 0xFFFFFFFF
        c0 = (c0 & 0xFFFF) + (c0 >> 16)
        c1 = (c1 & 0xFFFF) + (c1 >> 16)
    c0 = (c0 & 0xFFFF) + (c0 >> 16)
    c1 = (c1 & 0xFFFF) + (c1 >> 16)
    return ((c1 << 16) | c0) & 0xFFFFFFFF


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

def cookie_at(ctx, off):
    return off is not None and 0 <= off and off + 16 <= ctx.n and bytes(ctx.data[off:off + 4]) in COOKIES


def pointers_resolve(ctx, p, base):
    """p 位置的 EFS，有沒有任何一個目錄指標以 base 為基底時指到目錄 cookie。"""
    w = window_size(ctx.n, base)
    for o, _ in EFS_POINTERS:
        v = u32(ctx.data, p + o)
        if v not in NO_POINTER and cookie_at(ctx, to_offset(v, base, w)):
            return True
    return False


def find_efs(ctx):
    """全檔的 EFS 簽章候選 → [(位置, 視窗開頭)]。視窗開頭＝位置減掉該視窗大小對應的那張 coreboot 表裡的偏移，必須是 4 KiB 的整數倍。
    視窗開頭是 16 MiB 的整數倍（沒有位移）時，指標解不出來也採用（會記 pointer-unresolved）；
    有位移（更新包的標頭，不超過 MAX_SHIFT）時，指標之一要真的指到目錄 cookie 才採用。"""
    hits, pos = [], ctx.data.find(EFS_SIG)
    while pos >= 0 and len(hits) < MAX_SIG_HITS:
        hits.append(pos)
        pos = ctx.data.find(EFS_SIG, pos + 1)
    if pos >= 0:
        ctx.limit("image", f"more than {MAX_SIG_HITS} EFS signature candidates; the rest are not examined", "efs-limit")
    found = {}
    for p in hits:
        if p + EFS_SIZE > ctx.n:
            continue
        for o in EFS_OFFSETS:
            base = p - o
            if base < 0 or base % 0x1000 or o not in efs_offsets(window_size(ctx.n, base)):
                continue
            shift = base % WINDOW
            if shift == 0 or (shift <= MAX_SHIFT and pointers_resolve(ctx, p, base)):
                if p not in found or found[p][1] > shift:
                    found[p] = (base, shift)
    out = sorted((p, b) for p, (b, _) in found.items())
    if len(out) > MAX_EFS:
        ctx.limit("image", f"{len(out)} EFS signatures found; only the first {MAX_EFS} are parsed", "efs-limit")
        out = out[:MAX_EFS]
    return out


def efs_info(ctx, p, base):
    d = ctx.data
    ptrs = {name: u32(d, p + o) for o, name in sorted(EFS_POINTERS)}
    other = {name: u32(d, p + o) for o, name in sorted(EFS_UNPARSED)}
    for name, v in other.items():
        if v not in NO_POINTER:
            ctx.problem("efs-pointer-unparsed", f"EFS@0x{p:x}", f"EFS {name} pointer 0x{v:08x} is present but this firmware component is not parsed")
    return {"offset": p, "window_base": base, "window_size": window_size(ctx.n, base),
            "pointers": {k: f"0x{v:08x}" for k, v in ptrs.items()}, "other_pointers": {k: f"0x{v:08x}" for k, v in other.items()},
            "_raw": ptrs}


# ---------- 目錄 ----------

def dir_mode(info):
    return (info >> 24) & 3 if info >> 31 else (info >> 29) & 3


def cands_of(ctx, value, bases):
    """指標值 → 在目標位置看到目錄 cookie 的讀法 [(位置, 基底, 視窗大小)]；bases＝可用的基底清單（視窗開頭、0）。不同位置才算不同的讀法。"""
    cands = []
    for base, _ in bases:
        w = window_size(ctx.n, base)             # 視窗大小只由基底決定（同一個基底的讀法不能因為是從哪個 EFS 來的而不同）
        off = to_offset(value, base, w)
        if cookie_at(ctx, off) and off not in [c[0] for c in cands]:
            cands.append((off, base, w))
    return cands


def add_edge(ctx, parent, off, base, w, via, grp=None):
    """登記一條邊（上一層→這一層）與待解析的目錄；不遞迴。"""
    key = (off, base)
    ctx.edges.append((parent, key, grp))
    ctx.via.setdefault(key, set()).add(via)
    if key not in ctx.attempted and key not in ctx.pending:
        ctx.pending[key] = w


def request(ctx, parent, value, bases, via):
    """指標值（EFS、combo 項目、slot header 的 pl2_location）→ 驗證目錄 cookie；登記邊與待解析的目錄，不遞迴（解析由 walk() 依深度逐層做，
    所以一個紀錄用的深度、循環與上限的影響都不依賴走到它的順序）。回傳在目標位置看到目錄 cookie 的讀法 [(位置, 基底, 視窗大小)]；沒有 → pointer-unresolved。
    兩個以上的讀法 → 記成一組互相競爭的讀法（ctx.groups），之後由 resolve_readings() 依各自的結構檢查決定。"""
    cands = cands_of(ctx, value, bases)
    if not cands:
        ctx.problem("pointer-unresolved", via, f"{via}: pointer 0x{value:x} does not resolve to a PSP/BIOS directory (no directory cookie at the target)")
        return []
    grp = None
    if len(cands) > 1:
        grp = frozenset((o, b) for o, b, _ in cands)
        ctx.groups.append({"keys": sorted(grp), "via": via, "value": value})
    for off, base, w in cands:
        add_edge(ctx, parent, off, base, w, via, grp)
    return cands


def walk(ctx):
    """依深度逐層解析待解析的目錄：每個（位置，基底）只解析一次，用它最淺的深度；同一層內依（位置，基底）排序。上限（目錄數、深度、項目總數）因此只取決於映像內容。
    循環只是一條指向已存在節點的邊（loops_of() 事後在圖上找）。"""
    depth = 0
    while ctx.pending:
        cur, ctx.pending = ctx.pending, {}
        ctx.attempted.update(cur)
        for key in sorted(cur):
            off, base = key
            ctx.check()
            if len(ctx.dirs) >= MAX_DIRS:
                ctx.limit(f"0x{off:x}", f"more than {MAX_DIRS} directories; the directory at 0x{off:x} and the rest are not parsed")
                continue
            if depth > MAX_DEPTH:
                ctx.limit(f"0x{off:x}", f"directory nesting deeper than {MAX_DEPTH}; the directory at 0x{off:x} is not parsed")
                continue
            parse_dir(ctx, off, base, cur[key])
        depth += 1


def parse_dir(ctx, off, base, w):
    d = ctx.data
    key = (off, base)                   # 同一個位置用不同基底讀是不同的紀錄（內容可能完全不同）
    cookie = bytes(d[off:off + 4])
    kind = COOKIES[cookie]
    hdr, esz = HEADER[kind], ENTRY_SIZE[kind]
    num, info = u32(d, off + 8), u32(d, off + 12)
    rec = {"kind": kind, "cookie": cookie.decode("ascii"), "offset": off, "base": base, "window_size": w, "reached_via": [],
           "num_entries": num, "checksum": f"0x{u32(d, off + 4):08x}", "checksum_ok": None, "parsed": False, "trusted": False, "entries": [],
           "address_mode": None, "size": None, "checksum_calc": None, "unparsed": None, "complete": False,
           "status": "ambiguous", "ambiguous": True, "rejected": False}
    # unparsed：("evidence"｜"limit", 原因)——表超出檔案是結構上的證據；項目數／總數上限是工具的限制（不是證據）。
    # complete：這個紀錄的解析走完了（沒有被超時之類的例外打斷）。status／ambiguous／rejected：resolve_readings() 決定
    # （adopted＝確定、ambiguous＝GAP、rejected＝另一種讀法才採用）；沒走到那一步時維持 ambiguous。
    ctx.by_key[key] = rec
    ctx.dirs.append(rec)
    where = f"{KIND_TEXT[kind]} @0x{off:x}"
    if kind.startswith("combo"):
        rec["lookup"] = info
    else:
        rec["address_mode"] = dir_mode(info)
        rec["additional_info"] = f"0x{info:08x}"
    if num > MAX_DIR_ENTRIES:
        rec["unparsed"] = ("limit", f"{num} entries (limit {MAX_DIR_ENTRIES})")
        ctx.limit(where, f"{where}: {num} entries (limit {MAX_DIR_ENTRIES}); entries not parsed", "dir-too-many-entries")
        rec["complete"] = True
        return rec
    if ctx.entries_total + num > MAX_ENTRIES_TOTAL:
        rec["unparsed"] = ("limit", f"more than {MAX_ENTRIES_TOTAL} directory entries in total")
        ctx.limit(where, f"{where}: more than {MAX_ENTRIES_TOTAL} directory entries in total; entries not parsed")
        rec["complete"] = True
        return rec
    end = off + hdr + num * esz
    if end > ctx.n:
        rec["unparsed"] = ("evidence", f"{num} entries would end at 0x{end:x}, past the end of the file (0x{ctx.n:x})")
        ctx.problem("dir-truncated", where, f"{where}: {num} entries would end at 0x{end:x}, past the end of the file (0x{ctx.n:x}); entries not parsed")
        rec["complete"] = True
        return rec
    ctx.entries_total += num
    rec["size"] = end - off
    calc = fletcher32(d[off + 8:end])
    rec["checksum_ok"] = calc == u32(d, off + 4)
    rec["checksum_calc"] = calc
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
                ent["no_pointer"] = True
                continue
            # combo 的項目和 EFS 的指標一樣有兩種解讀
            cands = request(ctx, key, addr, [(base, w)] + ([(0, w)] if base else []), f"{where} entry {i} (id 0x{cid:08x})")
            ent["child"] = cands[0][0] if len(cands) == 1 else None
            ent["children"] = [c[0] for c in cands]
            ent["directories_seen"] = len(cands)       # child／children／directories_seen 只由 cookie 判斷的位置算出，不看目錄有沒有被解析
        else:
            try:
                ent = entry(ctx, rec, i, e, where)
            except (struct.error, IndexError, ValueError, OverflowError) as ex:      # 不該發生（都有檢查邊界）；只影響這一個條目
                ent = unresolved({"index": i, "type": d[e] if e < ctx.n else None, "size": 0, "offset": None, "type_name": None,
                                  "version": None, "where": f"{where} entry {i}"}, "the entry could not be parsed", limit=True)
                ctx.problem("entry-error", ent["where"], f"{ent['where']}: parse failed ({type(ex).__name__}); this entry is not interpreted")
            rec["entries"].append(ent)
    rec["complete"] = True
    return rec


def unresolved(ent, why, limit=False):
    """條目解不出來：limit＝False 是結構上的證據（位址或範圍超出檔案、指標沒指到目錄…）；True 是工具的限制（不解的 address mode、超過大小上限、A/B 條目大小不合…），不是證據。"""
    ent["kind"], ent["why"], ent["limit"] = "unresolved", why, limit
    return ent


def entry(ctx, rec, i, e, where):
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
    name = f" {ent['type_name']}" if ent["type_name"] else ""
    where_e = f"{where} entry {i} (type 0x{typ:02x}{name})"
    ent["where"] = where_e
    if ent["type_name"] is None:
        ctx.problem("type-unknown", where_e, f"{where_e}: entry type 0x{typ:02x} is not in the public type lists used here (coreboot psp_directory.h／bios_directory.h); not interpreted")
    if size == VALUE_SIZE:
        ent["kind"] = "value"               # 位址欄位是值（例如 soft fuse chain），不是位置
        return ent
    ish = not bios and typ in ISH_TYPES and size in (0, ISH_ENTRY_SIZE)
    if not bios and typ in ISH_TYPES and not ish:
        unresolved(ent, f"A/B recovery entry with size 0x{size:x} (expected 0 or 0x{ISH_ENTRY_SIZE:x})", limit=True)
        ctx.problem("ish-size", where_e, f"{where_e}: A/B recovery entry with size 0x{size:x} (expected 0 or 0x{ISH_ENTRY_SIZE:x}, the slot header entry sizes); not interpreted")
        return ent
    if size == 0 and bios and typ == APOB_TYPE and dest not in (0, (1 << 64) - 1):
        # APOB（AGESA 開機時寫入記憶體的資料）只有 destination：coreboot util/amdfwtool/amdfwtool.c 要求 APOB 一定要有 destination（"APOB destination not provided"），
        # source／size 可以是 0（coreboot 的條件是 `!dest`，所以 destination 是 0 也不算有）。有 destination 的 size 0 APOB 不當成「沒有資料」的缺口。
        ent["kind"] = "dest-only"
        return ent
    if size == 0 and not ish:
        ent["kind"] = "empty"
        ctx.problem("entry-empty", where_e, f"{where_e}: size 0, no data in the directory entry; what it stands for is not known")
        return ent
    mode = rec["address_mode"] if rec["address_mode"] in (0, 1) else emode
    if mode == 3:
        ctx.problem("entry-address", where_e, f"{where_e}: address mode 3 (relative to slot) is not supported; location not resolved")
        return unresolved(ent, "address mode 3 (relative to slot) is not supported", limit=True)
    off = rec["offset"] + value if mode == 2 else to_offset(value, rec["base"], rec["window_size"])
    if ish:                                 # A/B 復原：0x48／0x4A 項目指到 Image Slot Header（0x20 bytes），裡面有 L2 目錄的位置
        return ish_entry(ctx, rec, ent, off, where_e)
    if off is None or off < 0:
        ctx.problem("entry-address", where_e, f"{where_e}: address 0x{value:x} cannot be resolved (mode {mode})")
        return unresolved(ent, f"address 0x{value:x} cannot be resolved (mode {mode})")
    ent["offset"] = off
    if bios and ent["compressed"]:
        # 壓縮的條目：size 不一定是儲存範圍（可能是解壓後大小），起點要在檔案內；內容不解析、不當成明文（包括 type 0x66 微碼）
        ent["kind"] = "compressed"
        if off >= ctx.n:
            ctx.problem("entry-range", where_e, f"{where_e}: compressed entry starts at 0x{off:x}, past the end of the file (0x{ctx.n:x})")
            unresolved(ent, f"compressed entry starts at 0x{off:x}, past the end of the file (0x{ctx.n:x})")
        else:
            past = f"; its size field (0x{size:x}) runs past the end of the file" if off + size > ctx.n else ""
            ctx.problem("entry-compressed", where_e, f"{where_e}: compressed entry, content not decompressed or interpreted{past}")
        return ent
    if cookie_at(ctx, off) and size >= 16:
        ent["kind"] = "directory-pointer"   # 解出的位置是另一個目錄：往下走（不是韌體條目）；只用這個目錄自己的基底
        ent["child"], ent["children"], ent["directories_seen"] = off, [off], 1
        add_edge(ctx, (rec["offset"], rec["base"]), off, rec["base"], rec["window_size"], where_e)
        return ent
    if typ in POINTER_TYPES.get(kind, ()):
        ctx.problem("pointer-unresolved", where_e, f"{where_e}: directory pointer entry does not point to a directory (no cookie at 0x{off:x})")
        return unresolved(ent, f"directory pointer entry does not point to a directory (no cookie at 0x{off:x})")
    if size > MAX_BLOB:
        ctx.problem("entry-size", where_e, f"{where_e}: size 0x{size:x} is larger than the limit 0x{MAX_BLOB:x}; not read")
        return unresolved(ent, f"size 0x{size:x} is larger than the limit 0x{MAX_BLOB:x}", limit=True)
    if off + size > ctx.n:
        ctx.problem("entry-range", where_e, f"{where_e}: range 0x{off:x}+0x{size:x} extends past the end of the file (0x{ctx.n:x})")
        unresolved(ent, f"range 0x{off:x}+0x{size:x} extends past the end of the file (0x{ctx.n:x})")
    return ent


def ish_entry(ctx, rec, ent, off, where_e):
    """Image Slot Header（coreboot ish.h 的 ish_directory_table，0x20 bytes：checksum、boot_priority、update_retry_count、glitch_retry_count＋3 保留、
    pl2_location、psp_id、slot_max_size、保留）。checksum＝fletcher32（+4 到 +0x20；coreboot amdfwtool.c integrate_psp_ab_ish），不符 → 不採用 pl2_location。
    pl2_location 還要在目標位置看到目錄 cookie 才往下走。"""
    d = ctx.data
    if off is None or off < 0 or off + ISH_LEN > ctx.n:
        ctx.problem("entry-address", where_e, f"{where_e}: image slot header cannot be read (address outside the file)")
        return unresolved(ent, "image slot header cannot be read (address outside the file)")
    ent["offset"], ent["kind"], ent["child"] = off, "ish", None
    cks, prio, retry, _, pl2, psp_id, slot_max, _ = struct.unpack_from("<IIIIIIII", d, off)
    calc = fletcher32(d[off + 4:off + ISH_LEN])
    ent["ish"] = {"checksum": f"0x{cks:08x}", "checksum_verified": calc == cks, "boot_priority": f"0x{prio:08x}", "update_retry_count": f"0x{retry:08x}",
                  "pl2_location": f"0x{pl2:08x}", "psp_id": f"0x{psp_id:08x}", "slot_max_size": f"0x{slot_max:08x}"}
    if calc != cks:
        ctx.problem("ish-checksum", where_e, f"{where_e}: image slot header checksum 0x{cks:08x} does not match the computed 0x{calc:08x}; its L2 directory location is not used")
        return ent
    if pl2 not in NO_POINTER:
        cands = request(ctx, (rec["offset"], rec["base"]), pl2, [(rec["base"], rec["window_size"])], f"{where_e} slot header pl2_location")
        ent["child"] = cands[0][0] if cands else None
        ent["directories_seen"] = len(cands)
    return ent


def finish_walk(ctx):
    """走訪結束後：紀錄依（位置，基底）排序、reached_via／readings 排序（所以輸出不依賴處理順序）、在圖上找循環。"""
    ctx.dirs.sort(key=lambda r: (r["offset"], r["base"]))
    for k, r in ctx.by_key.items():
        r["reached_via"] = sorted(ctx.via.get(k, ()))[:8]
    for g in ctx.groups:
        for k in g["keys"]:
            r = ctx.by_key.get(k)
            if r is not None:
                r["readings"] = sorted(set(r.get("readings", [])) | {f"0x{o:x}" for o, b in g["keys"] if (o, b) != k})
    adj = {}
    for p, c, _ in ctx.edges:
        if p is not None and p in ctx.by_key and c in ctx.by_key:
            adj.setdefault(p, set()).add(c)

    def reach(a):
        seen, todo = set(), [a]
        while todo:
            x = todo.pop()
            for y in adj.get(x, ()):
                if y not in seen:
                    seen.add(y)
                    todo.append(y)
        return seen
    reached = {k: reach(k) for k in adj}
    for p in sorted(adj):
        for c in sorted(adj[p]):
            if p == c or p in reached.get(c, ()):
                w = f"{KIND_TEXT[ctx.by_key[p]['kind']]} @0x{p[0]:x}"
                ctx.problem("dir-loop", w, f"{w}: points to the directory at 0x{c[0]:x} (window base 0x{c[1]:x}), which leads back to it (loop); the loop is not followed again")
                ctx.uncertain.add("a directory loop was found")


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
    if off < 0 or off + size > ctx.n:
        return [], "the entry extends past the end of the file"
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
    """已解析（checksum 通過）的目錄項目 → psp_firmware、microcode。單一條目的錯誤只影響那個條目（entry-error）。"""
    psp_d, ucode_d, seen_d = {}, [], {}
    psp_amb, ucode_amb, seen_u_amb = {}, [], {}
    unversioned = {}

    def one(rec, ent):
        amb = rec["ambiguous"]
        psp, ucode, seen_u = (psp_amb, ucode_amb, seen_u_amb) if amb else (psp_d, ucode_d, seen_d)
        if rec["kind"].startswith("psp"):
            v = psp_version(ctx, ent)
            if v is None:
                unversioned.setdefault((ent["type"], ent["type_name"]), []).append(ent["where"])
                return
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
                return
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

    for rec in sorted(ctx.dirs, key=lambda r: (r["offset"], r["base"])):       # 位置清單的順序不依賴 ctx.dirs 的順序
        if not rec["trusted"] or rec["rejected"] or rec["kind"].startswith("combo"):
            continue
        for ent in rec["entries"]:
            if ent["kind"] != "blob" or ent["offset"] is None:
                continue
            try:
                one(rec, ent)
            except (struct.error, IndexError, ValueError, OverflowError) as ex:
                ctx.problem("entry-error", ent["where"], f"{ent['where']}: content parse failed ({type(ex).__name__}); this entry is not interpreted")
    if unversioned:
        n = sum(len(v) for v in unversioned.values())
        names = ", ".join(f"0x{t:02x}{' ' + nm if nm else ''}×{len(v)}" for (t, nm), v in sorted(unversioned.items()))
        ctx.problem("version-unverified", "PSP directories", f"{n} PSP directory entries have no verifiable version field "
                    f"(no PSP header with fw_type and size_total matching the entry, or an all-zero／all-one version field): {names}")
    if any(m["cpuids"] is None for m in ucode_d + ucode_amb):
        ctx.problem("ucode-cpuid", "BIOS directories", "microcode patches are not inside a container with an equivalence table, so only the equivalence id is listed "
                    "(the mapping from equivalence id to CPUID is not guessed)")
    psp_key = lambda x: (x["type"], x["subprogram"], x["version"], x["sha256"] or "", x["size"])      # noqa: E731
    uc_key = lambda x: (x["equiv_id"], x["patch_id"], x["sha256"] or "", x["patch_size"])           # noqa: E731
    amd["psp_firmware"] = sorted(psp_d.values(), key=psp_key)
    amd["microcode"] = sorted(ucode_d, key=uc_key)
    # 歧義目錄裡讀到的項目：列在 inventory，不進 SBOM；不和確定目錄裡的同一份內容去重（兩邊各自照實列出）
    amd["ambiguous"] = {"psp_firmware": sorted(psp_amb.values(), key=psp_key), "microcode": sorted(ucode_amb, key=uc_key)}


# ---------- 競爭的讀法：採用、不採用、無法判斷 ----------

FAIL_SHOWN = 3                          # 一個讀法沒通過時，訊息裡最多列幾條證據（其餘只計數）
NO_POINTER_TEXT = ("0x00000000", "0xffffffff", "0xfffffffe")


def reading_state(rec):
    """一種讀法（目錄紀錄＝位置＋基底）自己的結構檢查 → (證據, 無法判斷的原因)，兩個都是文字清單。證據（結構上的正面反證）只有：
      1. 目錄表超出檔案、checksum 不符；
      2. 條目的位址解不出來（超過 4 GiB、負的）、條目範圍或壓縮條目的起點超出檔案、指標條目沒指到目錄；
      3. A/B 復原的 Image Slot Header：checksum 不符、或 checksum 相符但 pl2_location 沒指到目錄；
      4. combo 目錄有位址的項目沒指到目錄；
      5. 目錄表本身落在自己某個條目的範圍裡（條目是韌體內容，不會包著它自己的目錄表）。
    無法判斷（工具的限制，不是證據）：解析被超時或例外打斷、項目數超過 MAX_DIR_ENTRIES、項目總數超過 MAX_ENTRIES_TOTAL、address mode 3、條目大小超過 MAX_BLOB、
    A/B 復原條目的大小不是 0 或 0x100、條目解析出錯。沒有證據、有無法判斷的原因 → 這一種讀法沒有被完整檢查過，不可以被採用，也不可以替另一邊背書。
    不含「條目內容看起來對不對」（版本標頭之類）：那是內容的判斷，不是這一種讀法的結構證據。"""
    ev, unk = [], []
    if not rec["complete"]:
        unk.append("the directory was not fully parsed (the analysis stopped early)")
    if rec["unparsed"]:
        (ev if rec["unparsed"][0] == "evidence" else unk).append(rec["unparsed"][1])
    elif rec["parsed"] and not rec["checksum_ok"]:
        ev.append(f"checksum {rec['checksum']} does not match the computed 0x{rec['checksum_calc']:08x}")
    for ent in rec["entries"]:
        i = ent["index"]
        if rec["kind"].startswith("combo"):
            if not ent.get("no_pointer") and not ent.get("directories_seen"):
                ev.append(f"entry {i}: pointer {ent['address']} does not lead to a directory")
            continue
        typ = "type 0x%02x" % ent["type"] if ent.get("type") is not None else "type unknown"
        if ent.get("kind") == "unresolved":
            (unk if ent.get("limit") else ev).append(f"entry {i} ({typ}): {ent.get('why') or 'not resolved'}")
        elif ent.get("kind") == "ish":
            ish = ent["ish"]
            if not ish["checksum_verified"]:
                ev.append(f"entry {i} ({typ}): image slot header checksum {ish['checksum']} does not match")
            elif ish["pl2_location"] not in NO_POINTER_TEXT and not ent.get("directories_seen"):
                ev.append(f"entry {i} ({typ}): slot header pl2_location {ish['pl2_location']} does not lead to a directory")
    if rec["parsed"] and rec["size"]:
        ts, te = rec["offset"], rec["offset"] + rec["size"]
        for ent in rec["entries"]:
            if ent.get("kind") == "blob" and ent["offset"] is not None and ent["offset"] < te and ts < ent["offset"] + ent["size"]:
                ev.append(f"the directory table [0x{ts:x}, 0x{te:x}) lies inside the range [0x{ent['offset']:x}, 0x{ent['offset'] + ent['size']:x}) of its own entry {ent['index']} (type 0x{ent['type']:02x})")
    return ev, unk


def entry_sig(ctx, ent):
    """條目的「解讀結果」（不含位址欄位的原值，因為同一個原值在不同基底會指到不同的位置）；內容用雜湊（超過雜湊上限拿不到 → None，視為不同）。"""
    k = ent.get("kind")
    sig = (k,) + tuple(ent.get(f) for f in ("index", "type", "subprogram", "instance", "rom_id", "writable", "size", "flags", "region_type",
                                            "reset", "copy", "read_only", "compressed", "dest"))
    if k == "blob":
        sha = digests(ctx, ent["offset"], ent["size"])[0]
        return None if sha is None else sig + (sha,)
    if k == "value":
        return sig + (ent["value"],)
    if k == "compressed":
        return sig + (ent["offset"],)               # 壓縮內容不解讀、大小不可靠：要位置相同才算相同
    if k == "directory-pointer":
        return sig + (ent.get("child"),)
    if k == "ish":
        return sig + (tuple(sorted(ent["ish"].items())), ent.get("child"))
    return sig


def same_content(ctx, a, b):
    """兩種都通過結構檢查的讀法，解讀結果是不是完全一樣（條目逐項相同：type／大小／旗標、條目指到的內容的 SHA-256、子目錄位置）。"""
    if a["kind"] != b["kind"] or a["num_entries"] != b["num_entries"] or len(a["entries"]) != len(b["entries"]):
        return False
    for x, y in zip(a["entries"], b["entries"]):
        if a["kind"].startswith("combo"):
            sx = (x["id_sel"], x["id"], x.get("no_pointer"), tuple(sorted(x.get("children", []))))
            sy = (y["id_sel"], y["id"], y.get("no_pointer"), tuple(sorted(y.get("children", []))))
        else:
            sx, sy = entry_sig(ctx, x), entry_sig(ctx, y)
            if sx is None or sy is None:
                return False
        if sx != sy:
            return False
    return True


def verdict(ctx, keys, states, force=""):
    """一組互相競爭的讀法（同一個指標的不同讀法，或同一個位置的不同基底）→ {"selected", "rejected", "contested", "equal", "why"}（都是排序過的 key 清單）。
    採用要同時滿足：每一種讀法都有被完整檢查（沒有無法判斷的原因、都解析出來了）、而且恰好一種通過（或通過的有兩種以上而且解讀結果完全相同）。
    不採用（rejected）只在有讀法被採用時才有：沒通過（有結構證據）的那些。其餘情況（有任何一種無法判斷、都沒通過、通過的有兩種以上但內容不同、force＝上限或循環讓整個結果無法判斷）
    → 全部維持歧義（contested）。"""
    ks = sorted(keys)
    have = [k for k in ks if k in ctx.by_key]

    def none(why):
        return {"selected": [], "rejected": [], "contested": have, "equal": False, "why": why}
    if force:
        return none(force)
    if len(have) < len(ks):
        return none("another reading of it was not parsed (a limit was reached)")
    unknown = [k for k in ks if states[k][1] and not states[k][0]]
    if unknown:
        return none("a reading could not be fully checked (" + states[unknown[0]][1][0] + ")")
    passers = [k for k in ks if not states[k][0]]
    failers = [k for k in ks if states[k][0]]
    if not passers:
        return none("none of the readings passes the structure checks")
    if len(passers) == 1:
        return {"selected": passers, "rejected": failers, "contested": [], "equal": False, "why": ""}
    if all(same_content(ctx, ctx.by_key[passers[0]], ctx.by_key[k]) for k in passers[1:]):
        return {"selected": passers, "rejected": failers, "contested": [], "equal": True, "why": ""}
    return none("more than one reading passes the structure checks and their contents differ")


def resolve_readings(ctx):
    """每個目錄紀錄（位置，基底）標成 adopted（確定）／ambiguous（無法判斷，GAP）／rejected（另一種讀法才被採用）。
    競爭的讀法有兩種：(a) 同一個指標（EFS 或 combo 項目）的兩種讀法（視窗開頭、0），(b) 同一個位置被不同基底讀到。每一組用 verdict() 決定。
    (a) 的結果只作用在「這個指標的那條邊」（同一個目錄若也從別的、單一讀法的指標到得了，仍然確定）；(b) 的結果作用在紀錄本身。
    確定的紀錄＝從 EFS 出發，只走「通過的邊」（單一讀法的指標，或指標的讀法被採用的那一邊）而且紀錄本身沒被 (b) 判掉，到得了的。其餘：
    被 (b) 判為不採用、或所有進來的邊都是被判不採用的讀法／來自不採用的目錄 → rejected；剩下的 → ambiguous。
    目錄階段沒走完（超時或例外）時不做任何採用或拒絕（所有紀錄維持 ambiguous）；碰到上限、循環、雜湊上限時所有競爭的讀法維持歧義。
    結果只取決於走訪到的紀錄與邊（走訪本身依深度逐層、同層排序，見 walk()），和 EFS、指標的處理順序無關。"""
    if not ctx.dir_done:
        return                              # 紀錄維持預設的 ambiguous
    h0 = ctx.counts.get("hash-limit", 0)
    force = "; ".join(sorted(ctx.uncertain))
    result = decide(ctx, force)
    if ctx.counts.get("hash-limit", 0) > h0:        # 比較內容時雜湊上限用完了：哪些組被比較到取決於處理順序 → 全部不判斷
        ctx.uncertain.add("the hashing limit was reached")
        result = decide(ctx, "the hashing limit was reached")
    apply_status(ctx, result)


def decide(ctx, force):
    recs = ctx.by_key
    cache = {}

    def state(k):
        if k not in cache:
            cache[k] = reading_state(recs[k])
        return cache[k]

    ptr = {}
    for g in ctx.groups:
        ptr.setdefault(frozenset(g["keys"]), []).append(g)
    for gl in ptr.values():
        gl.sort(key=lambda g: (g["via"], g["value"]))               # 訊息與 members 的列舉不依賴處理順序
    by_off = {}
    for k in recs:
        by_off.setdefault(k[0], []).append(k)
    off_groups = {o: ks for o, ks in by_off.items() if len(ks) > 1}
    pv = {gk: verdict(ctx, gk, {k: state(k) for k in gk if k in recs}, force) for gk in sorted(ptr, key=sorted)}
    ov = {o: verdict(ctx, ks, {k: state(k) for k in ks}, force) for o, ks in sorted(off_groups.items())}

    def off_state(k):
        v = ov.get(k[0])
        return None if v is None else "selected" if k in v["selected"] else "rejected" if k in v["rejected"] else "contested"

    def edge_ok(c, g):
        return c in recs and (g is None or c in pv[g]["selected"]) and off_state(c) in (None, "selected")

    kids, incoming = {}, {}
    for p, c, g in ctx.edges:
        if c in recs:
            kids.setdefault(p, []).append((c, g))
            incoming.setdefault(c, []).append((p, g))
    definite, queue, seen_parents = set(), [None], set()
    while queue:
        p = queue.pop()
        if p in seen_parents:
            continue
        seen_parents.add(p)
        for c, g in kids.get(p, []):
            if edge_ok(c, g) and c not in definite:
                definite.add(c)
                queue.append(c)
    rejected = {k for k in recs if off_state(k) == "rejected"}
    changed = True
    while changed:
        changed = False
        for k in recs:
            inc = incoming.get(k)
            if k in rejected or k in definite or not inc:
                continue
            if all((g is not None and k in pv[g]["rejected"]) or (p is not None and p in rejected) for p, g in inc):
                rejected.add(k)
                changed = True
    members = {}                        # 紀錄 → 它所屬的競爭組（為了訊息）
    for gk in sorted(ptr, key=sorted):
        for k in sorted(gk):
            members.setdefault(k, []).append(("pointer", gk, pv[gk], ptr[gk][0]))
    for o, ks in sorted(off_groups.items()):
        for k in sorted(ks):
            members.setdefault(k, []).append(("offset", frozenset(ks), ov[o], None))
    return {"definite": definite, "rejected": rejected, "ptr": ptr, "pv": pv, "off_groups": off_groups, "ov": ov, "off_state": off_state, "members": members, "state": state}


def apply_status(ctx, R):
    recs, state = ctx.by_key, R["state"]

    def desc(k):
        return f"{KIND_TEXT[recs[k]['kind']]} @0x{k[0]:x} (window base 0x{k[1]:x})"

    def evidence(k):
        ev, unk = state(k)
        parts = []
        if ev:
            parts.append("does not pass the structure checks: " + "; ".join(ev[:FAIL_SHOWN]) + (f"; and {len(ev) - FAIL_SHOWN} more" if len(ev) > FAIL_SHOWN else ""))
        if unk:
            parts.append("could not be fully checked: " + "; ".join(unk[:FAIL_SHOWN]))
        return "; ".join(parts) or "passes the structure checks"
    for k, r in sorted(recs.items()):
        r["status"] = "adopted" if k in R["definite"] else "rejected" if k in R["rejected"] else "ambiguous"
        r["ambiguous"], r["rejected"] = r["status"] == "ambiguous", r["status"] == "rejected"
        if k[0] in R["off_groups"]:
            r["other_bases"] = sorted(f"0x{o[1]:x}" for o in R["off_groups"][k[0]] if o != k)
        if k in R["members"]:
            r["reading_fail"], r["reading_unknown"] = state(k)
        w = desc(k)
        if r["status"] == "rejected":
            direct = [(kind, v, gl) for kind, gk, v, gl in R["members"].get(k, []) if k in v["rejected"]]
            if direct:
                kind, v, gl = direct[0]
                alt = list(v["selected"])
                r["rejected_because"] = state(k)[0]
                r["used_instead"] = [desc(a) for a in alt]
                what = f"pointer 0x{gl['value']:x}" if kind == "pointer" else f"offset 0x{k[0]:x}"
                ctx.problem("reading-rejected", w, f"{w}: this reading is not used, it {evidence(k)}; the other reading of the same {what} ({', '.join(desc(a) for a in alt)}) "
                            "passes the structure checks and is used instead; the entries of this reading are listed but not used for versions, hashes or microcode")
            else:
                r["rejected_because"] = ["reached only through readings that are not used"]
                ctx.problem("reading-rejected", w, f"{w}: not used, it is reached only through readings that are not used (see the reading-rejected entries above it)")
        elif r["status"] == "ambiguous":
            if R["off_state"](k) == "contested":
                v = R["ov"][k[0]]
                why = (f"the same offset was reached with other window bases ({', '.join(r['other_bases'])}) and the readings cannot be told apart ({v['why']}); this reading {evidence(k)}")
            else:
                cont = [(kind, gk, v, gl) for kind, gk, v, gl in R["members"].get(k, []) if k in v["contested"] and kind == "pointer"]
                if cont:
                    why = (f"reachable only through a pointer that reads as a directory in more than one way and the readings cannot be told apart ({cont[0][2]['why']}; other reading"
                           f"{'s' if len(r.get('readings', [])) > 1 else ''}: {', '.join(r.get('readings', []))})")
                else:
                    why = "it is below such a directory"
            ctx.problem("dir-ambiguous", w, f"{w}: {why}; its {r['num_entries']} entries, versions and microcode are listed but not used for the SBOM")
    for gk, gl in sorted(R["ptr"].items(), key=lambda x: sorted(x[0])):
        v = R["pv"][gk]
        for g in sorted(gl, key=lambda x: x["via"]):
            readings = "; ".join(f"{desc(k)}: {evidence(k)}" for k in sorted(gk) if k in recs)
            if v["contested"]:
                ctx.problem("pointer-ambiguous", g["via"], f"{g['via']}: pointer 0x{g['value']:x} reads as a directory {len(gk)} ways ({readings}); {v['why']}; this tool does not decide which one the hardware uses: "
                            "all readings are parsed and listed, and none of them is used for the SBOM unless it is also reached by an unambiguous pointer")
            elif v["equal"]:
                ctx.problem("reading-equivalent", g["via"], f"{g['via']}: pointer 0x{g['value']:x} reads as a directory {len(gk)} ways ({readings}); the readings that pass have identical contents "
                            "(entries, sizes, flags and hashes of what they point to), so it does not matter which one the hardware uses and all of them are used")
    for o, ks in sorted(R["off_groups"].items()):
        if R["ov"][o]["equal"]:
            ctx.problem("reading-equivalent", f"0x{o:x}", f"directory at 0x{o:x} was read with window bases {', '.join('0x%x' % k[1] for k in sorted(ks))}; the readings that pass have identical contents, so all of them are used")


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
    """pos 是 `AGESA!V` 的位置 → (tag, value, status, end)；end＝標記這一段（到字串結尾，或到讀不下去的地方）之後的位置。tag＝`V` 加 1–4 個英數字（例如 V9）；tag 後面一定要接一個 NUL 或空白當分隔，
    value＝接著最多 AGESA_VALUE_LEN 個可列印 ASCII（去頭尾空白）。status：
      ok         正常
      truncated  字串在長度上限被截斷（value 只是前綴，不能當完整版本）
      nosep      tag 後面不是 NUL 或空白（tag 和字串黏在一起或 tag 超過 4 個字元，切不出來）→ value 是 None
      empty      分隔符後面沒有可列印字元 → value 是 None"""
    i = pos + len(AGESA_MARK)
    j = i
    while j < len(buf) and j - i < 4 and (48 <= buf[j] <= 57 or 65 <= buf[j] <= 90 or 97 <= buf[j] <= 122):
        j += 1
    tag = "V" + bytes(buf[i:j]).decode("ascii")
    if j == i or j >= len(buf) or buf[j] not in (0, 0x20):
        return tag, None, "nosep", j
    j += 1
    k = j
    while k < len(buf) and k - j < AGESA_VALUE_LEN and 0x20 <= buf[k] < 0x7F:
        k += 1
    value = bytes(buf[j:k]).decode("ascii").strip()
    if not value:
        return tag, None, "empty", k
    return tag, value, ("truncated" if k - j == AGESA_VALUE_LEN and k < len(buf) and 0x20 <= buf[k] < 0x7F else "ok"), k


def agesa_search(data, budget=None, soft=()):
    """AGESA 字串。走訪 firmware volume（uefi_image，LZMA 等解開；FV 以外的非空白位元組它也送進來）逐塊內容找 `AGESA!V` 標記；
    另外找整個映像原始位元組裡的標記；原始位元組裡只要有任何標記，就把搜尋標為不完整（沒有正式介面可以證明那個位置有被走訪搜尋過；M7 再補），
    只在原始位元組裡有的值也列出來（位置 image (raw bytes)）。uefi_image 載入不了或走訪失敗時只有原始位元組的結果（不完整）。
    → {"values": [{tag, value, count, found, truncated}], "problems": [文字，已去重], "complete": bool, "stats": {...}}。永遠回傳，不丟例外。"""
    r = {"values": [], "problems": [], "complete": False, "walk": False, "stats": {"markers": 0, "raw_markers": 0, "inspected_bytes": 0, "fvs": 0, "ffs_files": 0}}
    table, st = {}, r["stats"]
    seen_problems = set()
    walk_counts, raw_counts, raw_locs = {}, {}, {}
    state = {"capped": False, "raw_capped": False, "inspect_capped": False, "values_capped": False}

    def note(text):
        if text not in seen_problems:
            seen_problems.add(text)
            r["problems"].append(text)

    def scan(buf, where, counts, count_key, locs=None):
        """在 buf 找標記；每個標記用 (tag, value, status) 計數。回傳 False＝超過標記總數上限。"""
        pos = buf.find(AGESA_MARK)
        while pos >= 0:
            if st[count_key] >= MAX_AGESA_MARKERS:
                if not state["capped"]:
                    state["capped"] = True
                    note(f"more than {MAX_AGESA_MARKERS} AGESA markers; the rest are not read")
                return False
            st[count_key] += 1
            tag, value, status, end = read_agesa(buf, pos)
            key = (tag, value, status)
            counts[key] = counts.get(key, 0) + 1
            if locs is not None:
                locs.setdefault(key, []).append(pos)
            if count_key == "markers":
                if status in ("nosep", "empty"):
                    note(f"AGESA marker without a readable version string ({'no NUL or space after the tag' if status == 'nosep' else 'nothing after the separator'}) in {where}; not used")
                else:
                    e = table.get((tag, value))
                    if e is None:
                        if len(table) >= MAX_AGESA_VALUES:
                            state["values_capped"] = True
                            note(f"more than {MAX_AGESA_VALUES} distinct AGESA strings; the rest are not listed")
                            e = {"found": [], "count": 0}
                        else:
                            e = table[(tag, value)] = {"tag": "AGESA!" + tag, "value": value, "count": 0, "found": [], "truncated": status == "truncated"}
                    if status == "truncated":
                        e["truncated"] = True
                        note(f"AGESA string longer than {AGESA_VALUE_LEN} characters (starts with '{value[:24]}…'): only the first {AGESA_VALUE_LEN} were read, so it is not used as a complete version")
                    e["count"] += 1
                    if len(e["found"]) < MAX_AGESA_LOCATIONS:
                        e["found"].append({"where": where, "offset": pos})
            pos = buf.find(AGESA_MARK, pos + 1)
        return True

    def walk_inspect(buf, module):
        """走訪（uefi_image.parse_fvs）每送來一塊內容就呼叫一次：只在內容裡找標記。不判斷內容是原始位元組的切片還是解壓縮來的（公開介面沒有這個資訊）。"""
        n = len(buf)
        if n == 0:
            return
        if budget is not None:
            budget.check()
        if st["inspected_bytes"] + n > MAX_AGESA_INSPECT:
            if not state["inspect_capped"]:
                state["inspect_capped"] = True
                note(f"more than {MAX_AGESA_INSPECT} bytes of UEFI content; the rest was not searched")
            return
        st["inspected_bytes"] += n
        scan(buf, "uefi:" + (module or "?"), walk_counts, "markers")

    complete = True
    try:
        if budget is not None:
            budget.check()
        scan(data, "image", raw_counts, "raw_markers", raw_locs)
    except soft as e:
        note(f"stopped early: {e}")
        return finish(r, table, complete=False)
    try:
        ui = _sibling("uefi_image")
    except ImportError as e:
        note(f"{e}; compressed UEFI content was not searched for AGESA strings (only the raw bytes were)")
        for key, n in raw_counts.items():                  # 只有原始位元組：把它們當成結果
            tag, value, status = key
            if value is not None:
                table[(tag, value)] = {"tag": "AGESA!" + tag, "value": value, "count": n, "truncated": status == "truncated",
                                       "found": [{"where": "image", "offset": o} for o in raw_locs[key][:MAX_AGESA_LOCATIONS]]}
            else:
                note(f"AGESA marker without a readable version string in image; not used")
        return finish(r, table, complete=False)

    class AgesaScan(ui.Scan):
        def scan_bytes(self, buf, module=None):           # 覆寫：不做函式庫指紋，只找 AGESA（和 uefi_gfx.py 同樣的做法）
            walk_inspect(buf, module)

    sc = AgesaScan()
    r["walk"] = True
    try:
        ui.parse_fvs(bytes(data), sc, 0)
    except ui.Stop as e:
        note(f"UEFI walk reached a limit ({e}); the AGESA search is incomplete")
        complete = False
    except soft as e:
        note(f"stopped early: {e}")
        complete = False
    except Exception as e:      # noqa: BLE001 — 不可信輸入：任何例外都只記為不完整
        note(f"UEFI walk failed ({type(e).__name__}); the AGESA search is incomplete")
        complete = False
    st["fvs"], st["ffs_files"] = sc.fvs, sc.files
    # 沒解開的部分一律讓搜尋不完整，包括最上層 FV 以外的非空白位元組（uefi_image 只把它們當原始內容搜尋，裡面的壓縮串流不會被解開）；不依賴它的 reason 字串
    undec = list(sc.undecoded)
    if undec:
        why = sorted({" ".join(str(x["reason"]).split())[:120] for x in undec})[:3]
        note(f"{len(undec)} UEFI parts were not decoded ({'; '.join(why)}); the AGESA search did not look inside them")
        complete = False
    if sc.notes or sc.parse_errors:
        first = " ".join(str(sc.notes[0]).split())[:120] if sc.notes else f"{sc.parse_errors} parse errors"
        note(f"the UEFI walk reported structure warnings ({first}); the AGESA search may be incomplete")
        complete = False
    if not sc.fvs:
        note("no UEFI firmware volume was decoded; only the raw bytes were searched for AGESA strings")
        complete = False
    if state["capped"] or state["inspect_capped"] or state["values_capped"]:
        complete = False
    # 原始位元組裡只要有任何 AGESA 標記，就標不完整：沒有正式介面可以證明那個位置有被走訪搜尋過（走訪收到的內容不分原始切片或解壓縮來的，
    # 解壓縮出來的內容也可能和原始位元組裡另一處沒被搜尋的複本完全相同）。精確的位置涵蓋留到 C1 提供回呼介面之後（M7）。
    # 原始位元組裡有、走訪結果裡沒有的 (tag, value)：加進表裡，位置寫 image (raw bytes)；走訪結果裡已經有的：只標不完整，不重複計數。
    if raw_counts:
        complete = False
        note(f"{st['raw_markers']} AGESA marker(s) in the raw image bytes: there is no formal interface that can show the UEFI walk searched those raw byte positions, "
             "so the search is marked incomplete (to be refined in M7); values found only in the raw bytes are listed with the location 'image (raw bytes)'")
        if not state["capped"]:
            raw_only = {}
            for (tag, value, status), n in raw_counts.items():
                if value is None or (tag, value) in table:
                    continue
                e = raw_only.setdefault((tag, value), {"count": 0, "found": [], "truncated": False})
                e["count"] += n
                e["truncated"] = e["truncated"] or status == "truncated"
                e["found"] += [{"where": "image (raw bytes)", "offset": o} for o in raw_locs[(tag, value, status)]]
            for (tag, value), e in sorted(raw_only.items()):
                if len(table) >= MAX_AGESA_VALUES:
                    note(f"more than {MAX_AGESA_VALUES} distinct AGESA strings; the rest are not listed")
                    break
                if e["truncated"]:
                    note(f"AGESA string longer than {AGESA_VALUE_LEN} characters (starts with '{value[:24]}…'): only the first {AGESA_VALUE_LEN} were read, so it is not used as a complete version")
                table[(tag, value)] = {"tag": "AGESA!" + tag, "value": value, "count": e["count"], "found": e["found"][:MAX_AGESA_LOCATIONS], "truncated": e["truncated"]}
    return finish(r, table, complete)


def finish(r, table, complete):
    r["complete"] = complete
    r["values"] = sorted(table.values(), key=lambda x: (x["tag"], x["value"]))
    return r


# ---------- 入口 ----------

GAP_TEXT = {
    "efs-limit": "EFS limit", "efs-pointer-unparsed": "EFS pointers present but not parsed", "pointer-unresolved": "pointers that do not resolve to a directory",
    "pointer-ambiguous": "pointers readable as a directory in two ways that cannot be told apart", "dir-ambiguous": "directories reachable only through readings that cannot be told apart",
    "reading-rejected": "directory readings not used (another reading of the same pointer or offset passes the structure checks)",
    "reading-equivalent": "pointer or offset readings with identical contents (all used)", "dir-loop": "directory loops", "dir-limit": "directory limits reached",
    "dir-too-many-entries": "directories with too many entries", "dir-truncated": "directories running past the end of the file",
    "dir-checksum": "directory checksum mismatches", "type-unknown": "entries of unknown type", "entry-address": "entries whose address cannot be resolved",
    "entry-size": "entries too large", "entry-range": "entries outside the file", "entry-overlap": "overlapping ranges", "version-unverified": "entries without a version",
    "entry-empty": "entries with size 0", "entry-compressed": "compressed entries not interpreted", "entry-error": "entries that failed to parse",
    "no-directory": "no usable PSP/BIOS directory", "efs-no-pointer": "EFS without directory pointers", "internal-error": "parse stages that failed",
    "ucode-unrecognised": "microcode entries not understood", "ucode-cpuid": "microcode without CPUID", "ucode-limit": "microcode limit", "hash-limit": "hash limit",
    "ish-checksum": "image slot header checksum mismatches", "ish-size": "A/B recovery entries with an unexpected size",
}
ATTENTION_CODES = ("dir-checksum", "pointer-ambiguous", "dir-ambiguous", "reading-rejected", "ish-checksum", "dir-loop", "entry-overlap", "entry-range", "dir-limit", "entry-error", "internal-error")


def summarize(problems, counts):
    """problem 清單 → gap 文字（每種 code 一行：件數與前幾個例子）。"""
    out, by = [], {}
    for p in problems:
        by.setdefault(p["code"], []).append(p["text"])
    for code, texts in by.items():
        shown = texts[:3]
        out.append(f"AMD: {GAP_TEXT.get(code, code)} ({counts[code]}): " + "; ".join(shown) + ("; …" if counts[code] > len(shown) else ""))
    return out


def run_stage(ctx, amd, name, fn, soft):
    """一個階段；超時（soft）或其他例外只讓這個階段不完整，已有的結果照給。"""
    try:
        fn()
    except soft as e:
        amd["incomplete"].append(f"AMD {name} stopped early: {e}")
    except Exception as e:      # noqa: BLE001 — 不可信輸入：任何例外都只記成這個階段失敗，不能讓整份結果作廢
        ctx.problem("internal-error", name, f"AMD {name} failed ({type(e).__name__}); results of this stage may be missing")


def analyze(data, budget=None, soft=()):
    """AMD 平台映像的位元組 → dict（可轉 JSON）。永遠回傳、不丟例外（soft 例外＝超時：已有的結果照給，記 incomplete）。
    鍵：efs、directories、psp_firmware、microcode、agesa、problems（逐筆）、gaps（彙整後的文字）、attention（要 ATTENTION 的理由）、incomplete、stats。"""
    data = bytes(data) if not isinstance(data, bytes) else data
    ctx = Ctx(data, budget)
    amd = {"efs": [], "directories": [], "psp_firmware": [], "microcode": [], "agesa": {"values": [], "complete": False, "problems": []},
           "problems": [], "gaps": [], "attention": [], "incomplete": [], "stats": {}}

    def directories():
        roots = []
        for p, b in sorted(find_efs(ctx)):                 # 排序：EFS 的處理順序不影響結果
            x = efs_info(ctx, p, b)
            raw = x.pop("_raw")
            amd["efs"].append(x)
            base, w = x["window_base"], x["window_size"]
            bases = [(base, w)] + ([(0, w)] if base else [])
            keys = set()
            for _, name in sorted(EFS_POINTERS):
                if raw[name] not in NO_POINTER:
                    keys |= {(o, bb) for o, bb, _ in request(ctx, None, raw[name], bases, f"EFS@0x{p:x} {name}")}
            roots.append((x, keys))
            if not any(raw[n] not in NO_POINTER for _, n in EFS_POINTERS):
                ctx.problem("efs-no-pointer", f"EFS@0x{p:x}", f"EFS at 0x{p:x} has no PSP/BIOS directory pointer")
        walk(ctx)
        finish_walk(ctx)
        adj = {}
        for p_, c, _ in ctx.edges:
            adj.setdefault(p_, set()).add(c)
        for x, keys in roots:                               # 這個 EFS 的指標到得了的目錄紀錄數（沿著邊走，不看處理順序）
            seen, todo = set(), [k for k in keys if k in ctx.by_key]
            while todo:
                k = todo.pop()
                if k not in seen:
                    seen.add(k)
                    todo += [c for c in adj.get(k, ()) if c in ctx.by_key]
            x["directories_found"] = len(seen)
        ctx.dir_done = True

    run_stage(ctx, amd, "PSP/BIOS directory parse", directories, soft)
    run_stage(ctx, amd, "directory reading check", lambda: resolve_readings(ctx), soft)
    amd["ambiguous"] = {"psp_firmware": [], "microcode": []}
    run_stage(ctx, amd, "firmware and microcode extraction", lambda: collect_contents(ctx, amd), soft)
    run_stage(ctx, amd, "range overlap check", lambda: check_overlaps(ctx), soft)
    try:
        ag = agesa_search(data, budget, soft)
    except soft as e:
        ag = {"values": [], "problems": [f"stopped early: {e}"], "complete": False, "walk": False, "stats": {}}
    except Exception as e:      # noqa: BLE001
        ag = {"values": [], "problems": [f"AGESA search failed ({type(e).__name__})"], "complete": False, "walk": False, "stats": {}}
    amd["agesa"] = ag
    ctx.dirs.sort(key=lambda r: (r["offset"], r["base"]))
    ctx.problems.sort(key=lambda p: (p["code"], p["where"], p["text"]))        # 問題的順序（和每種只列前幾筆）不依賴處理順序
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
    for t in ag["problems"][:6]:
        gaps.append("AMD: AGESA search: " + t)
    if not [x for x in ag["values"] if not x.get("truncated")] and ag["complete"] is False:
        gaps.append("AMD: no complete AGESA version string found in a search that was not complete (not found does not mean absent)")
    elif not [x for x in ag["values"] if not x.get("truncated")]:
        gaps.append("AMD: no complete AGESA version string found")
    amd["gaps"] = gaps
    amd["attention"] = [f"{GAP_TEXT[c]} ({counts[c]})" for c in ATTENTION_CODES if counts.get(c)]
    full = [x for x in ag["values"] if not x.get("truncated")]
    if len(full) > 1:
        amd["attention"].append("more than one AGESA string: " + ", ".join(f"{x['tag']} {x['value']}" for x in full))
    amd["stats"] = {"efs": len(amd["efs"]), "directories": len(ctx.dirs), "entries": ctx.entries_total,
                    "directories_ambiguous": sum(1 for r in ctx.dirs if r["ambiguous"]), "directories_rejected": sum(1 for r in ctx.dirs if r["rejected"]),
                    "psp_firmware": len(amd["psp_firmware"]), "microcode": len(amd["microcode"]), "agesa_values": len(full),
                    "problems": dict(counts), "hashed_bytes": MAX_HASH_TOTAL - ctx.hash_left}
    return amd


def summary_text(amd):
    """一行摘要（狀態、SBOM property 用）。"""
    ag = [x for x in amd["agesa"]["values"] if not x.get("truncated")]
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
        if r["rejected"]:
            flag += ("（**未採用**：" + e("；".join(r.get("rejected_because", [])[:3])) + (f"；改用 {e('、'.join(r['used_instead']))}" if r.get("used_instead") else "")
                     + "。條目與版本只列出，不進 SBOM）")
        elif r["ambiguous"]:
            flag += ("（**歧義**：" + (f"同一個指標的另一種讀法在 {e(', '.join(r['readings']))}；" if r.get("readings") else f"同一個位置也用視窗開頭 {e(', '.join(r['other_bases']))} 讀過；"
                                     if r.get("other_bases") else "它在這樣的目錄底下；")
                     + "兩種以上的讀法都通過結構檢查而內容不同、或都沒通過，工具不判斷哪個是硬體實際使用的，條目與版本不進 SBOM）")
        L += [f"#### {e(KIND_TEXT[r['kind']])} `{e(r['cookie'])}` @0x{r['offset']:x}（視窗開頭 0x{r['base']:x}）{flag}", "",
              f"{r['num_entries']} 項；checksum {r['checksum']}（{'相符' if r['checksum_ok'] else '不符' if r['checksum_ok'] is False else '未檢查'}）；來源：" + e("；".join(r["reached_via"])), ""]
        if r["kind"].startswith("combo"):
            if r["entries"]:
                L += ["| # | id | 目錄位址 | 解到 |", "|---|---|---|---|"]
                L += [f"| {x['index']} | {e(x['id'])} | {e(x['address'])} | {e(', '.join(f'0x{c:x}' for c in x.get('children', [])) or '無')} |" for x in r["entries"]]
                L.append("")
            continue
        if r["entries"]:
            L += ["| # | type | 名稱 | sub | inst | 位置 | 大小 | 版本 |", "|---|---|---|---|---|---|---|---|"]
            for x in r["entries"]:
                loc = hex_or_none(x["offset"]) if x["kind"] in ("blob", "directory-pointer", "ish", "compressed") else x["kind"]
                note = x["kind"] if x["kind"] in ("ish", "compressed", "empty", "dest-only", "value", "unresolved") else ""
                if x["kind"] == "ish":
                    note = "slot header，checksum " + ("相符" if x["ish"]["checksum_verified"] else "不符")
                L.append(f"| {x['index']} | 0x{x['type']:02x} | {e(x['type_name'] or '未知')} | {x.get('subprogram', '')} | {x.get('instance', '')} | {e(loc or '未解')} | 0x{x['size']:x} | {e(x['version'] or note)} |")
            L.append("")
    amb = amd.get("ambiguous") or {"psp_firmware": [], "microcode": []}
    if amb["psp_firmware"] or amb["microcode"]:
        L += ["#### 歧義目錄裡的版本與微碼（GAP：不進 SBOM）", "",
              "下列項目只在「兩種解讀都成立」的目錄裡讀到（見上面標 **歧義** 的目錄）。工具不判斷哪一個解讀才是硬體實際使用的，所以只列出，不當成確定的結果。", ""]
        L += [f"- PSP type 0x{p['type']:02x} {e(p['type_name'] or '')} sub {p['subprogram']}：版本 {e(p['version'])}（{e('；'.join(x['directory'] + ' #' + str(x['index']) for x in p['locations'][:2]))}）" for p in amb["psp_firmware"]]
        L += [f"- 微碼 patch level {m['patch_id']}、equivalence id {m['equiv_id']}、{m['date']}（{e('；'.join(x['directory'] + ' #' + str(x['index']) for x in m['locations'][:2]))}）" for m in amb["microcode"]]
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
        L += [f"| {e(x['tag'])} | {e(x['value'])}{'（被截斷，不是完整版本）' if x.get('truncated') else ''} | {x['count']} | " + e("；".join(f"{w['where']} +0x{w['offset']:x}" for w in x["found"][:2])) + " |" for x in amd["agesa"]["values"]]
    else:
        L.append("沒有找到" + ("" if amd["agesa"]["complete"] else "（搜尋不完整，不代表不存在）") + "。")
    L += [""] + [f"- AGESA 搜尋：{e(p)}" for p in amd["agesa"]["problems"]]
    return L
