#!/usr/bin/env python3
"""Intel 內顯的 vBIOS 子元件辨識：legacy VBIOS option ROM、UEFI GOP 驅動（PE32+）。只依賴標準函式庫，只讀、不執行。

x86_firmware.py 在 option ROM 掃描結果裡呼叫 legacy_info()；GOP 驅動的辨識（gop_driver）已經寫好、用測試資料測過，
但還沒有接到 BIOS 映像的走訪上（要等 uefi_image.py 把 AMI 映像的 FV 解開，見 docs/notes/c2-vbios.md「接線介面」）。

輸入是不可信資料：所有長度都對資料長度與上限檢查；字串一律限制長度與字元集；不寫磁碟、不執行。

## Intel legacy VBIOS（vendor 0x8086、PCIR class code 0x03xxxx、有 x86 影像）

版本字串的格式**只對一份公開樣本核對過**（Intel NUC 11 的 BIOS 更新檔 PATGL357.0059 裡 GOP 檔案內的 legacy VBIOS，
該樣本的細節見 docs/notes/c2-vbios.md；樣本本身不進 repo）。樣本的 ROM 裡有：
  `Intel(R) ICL Mobile/Desktop PCI Accelerated SVGA BIOS`（橫幅）、
  `Build Number: 1003 PC 14.34  11/15/2018  02:15:39`（建置編號、PC 版本、建置日期時間；欄位之間 1～2 個空白）。
這裡把「建置編號 PC 版本」（`1003 PC 14.34`）當 SBOM 的 version，日期時間原樣記在 build_time（不轉格式：日期順序沒有標示，
樣本的 11/15 只能是月/日；其他樣本沒有核對過）。橫幅或 Build Number 行格式不符時 version 是 None（GAP，不猜），ROM 仍列出。
ROM 裡可能內嵌 `$VBT <平台名稱>`（樣本是 `$VBT ICELAKE`，VBT 1.00、BDB 2.23、3945 bytes）：用 intel_vbt 解析標頭，記在 vbt。
PCIR 的 device id 不拿來當辨識（樣本是 0x0406，不是任何一個 Tiger Lake／Ice Lake 的顯示裝置 ID：legacy VBIOS 的 PCIR 裝置 ID 常是範本值）。

## Intel GOP 驅動（UEFI 驅動，PE32+ x64，subsystem 10～13）

樣本（同一份 BIOS）的 GOP PE 裡：UTF-16 字串 `Intel(R) GOP Driver`（驅動名稱）之後，隔著一段 NUL 填充，是一個只有數字的 UTF-16 字串
（樣本是 `1070`），再之後是 `Intel(R) Graphics Controller`；這些字串都被程式碼引用，但沒有逆向確認用途。
同一份 BIOS 的 release notes 寫 `Integrated Graphics GOP UEFI Driver: 17.0.1070`，所以把 `1070` 當 build 編號（靠對照，不是靠程式碼確認）。
PE 本身沒有版本資源（沒有資源目錄）、時間戳是 0、PE 標頭的 image／subsystem 版本都是 0；`17.0` 在 PE 裡沒有找到，
所以 gop_driver() 讀得到的 version 只有 build 編號（`1070`），不是完整的 `17.0.1070`；完整版本要靠 release notes（版本清單）。
這個讀法只對一份樣本核對過。
"""
import importlib.util
import re
import struct
import sys
from pathlib import Path

INTEL_VID = 0x8086
PCI_BASE_CLASS_DISPLAY = 0x03
CODE_TYPE_X86 = 0
MAX_TEXT = 128                         # 從不可信資料讀出來的字串長度上限
MAX_VBT_CANDIDATES = 8                 # 一個 ROM 裡看幾個 `$VBT `
MAX_PE = 64 << 20                      # gop_driver() 接受的 PE 大小上限
GOP_DRIVER_NAME = "Intel(R) GOP Driver"
GOP_NAME_WINDOW = 0x200                # 驅動名稱之後找版本字串的範圍（bytes）
EFI_SUBSYSTEMS = {10: "EFI application", 11: "EFI boot service driver", 12: "EFI runtime driver", 13: "EFI ROM"}
PE_MACHINES = {0x8664: "x64", 0x14C: "ia32", 0xAA64: "arm64"}

BANNER_HEAD, BANNER_TAIL = b"Intel(R)", b"SVGA BIOS"
MAX_BANNER_TAILS = 1024          # 最多看幾個 "SVGA BIOS"（構造的 ROM 可以塞滿）
BUILD_RE = re.compile(rb"Build Number:[ \t]*(\d{1,6})[ \t]+PC[ \t]+(\d{1,3}\.\d{1,3})[ \t]+(\d{2}/\d{2}/\d{4}[ \t]+\d{2}:\d{2}:\d{2})")
BUILD_PREFIX = b"Build Number:"
GOP_VERSION_RE = re.compile(r"[0-9]{1,6}(?:\.[0-9]{1,6}){0,3}")


def _sibling(name):
    """同目錄的模組（python3 -I 不把腳本目錄放進 sys.path；測試 import 過就共用同一個）。"""
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


def is_legacy_vbios(rom):
    """x86_firmware.option_roms() 的一個 ROM dict → 是不是 Intel legacy VBIOS（vendor 0x8086、顯示類別、有 x86 影像）。
    class 是 PCIR class code 的三個 bytes 反過來寫（base class 在最前面，例如 VGA 是 `030000`）。"""
    cls = rom.get("class") or ""
    return (rom.get("vendor") == f"{INTEL_VID:04x}" and len(cls) == 6 and int(cls[:2], 16) == PCI_BASE_CLASS_DISPLAY
            and any(i["code_type"] == CODE_TYPE_X86 for i in rom.get("images", ())))


def _text(b):
    return b.decode("ascii", "replace")


def find_banner(rom):
    """`Intel(R) … SVGA BIOS`（中間 1～MAX_TEXT 個可列印 ASCII）→ bytes 或 None。
    先找結尾的 "SVGA BIOS"，再往前最多 MAX_TEXT＋8 bytes 找 "Intel(R)"：工作量是線性的。
    （用 regex `Intel\(R\)[ -~]{1,128}?SVGA BIOS` 對滿是 "Intel(R)" 的構造 ROM 會有 128 倍放大。）"""
    j, seen = rom.find(BANNER_TAIL), 0
    while j >= 0 and seen < MAX_BANNER_TAILS:
        seen += 1
        lo = max(0, j - MAX_TEXT - len(BANNER_HEAD))
        i = rom.find(BANNER_HEAD, lo, j)
        while i >= 0:
            mid = rom[i + len(BANNER_HEAD):j]
            if 1 <= len(mid) <= MAX_TEXT and all(0x20 <= c <= 0x7E for c in mid):
                return rom[i:j + len(BANNER_TAIL)]
            i = rom.find(BANNER_HEAD, i + 1, j)
        j = rom.find(BANNER_TAIL, j + 1)
    return None


def legacy_info(rom):
    """Intel legacy VBIOS 的 ROM 位元組 → dict：
    banner（橫幅或 None）、version（`建置編號 PC 版本` 或 None）、build_number、pc_version、build_time（原樣的日期時間字串）、
    version_note（version 是 None 的原因，否則 None）、vbt（內嵌的 VBT：{offset, signature, version, bdb_version, vbt_size}，沒有則 None）。
    Build Number 行有多個、內容不同 → version 是 None（分不出來，不猜）。"""
    rom = bytes(rom)
    banner = find_banner(rom)
    builds = {mm.groups() for mm in BUILD_RE.finditer(rom)}
    r = {"banner": _text(banner) if banner else None, "version": None, "build_number": None, "pc_version": None, "build_time": None,
         "version_note": None, "vbt": None}
    if len(builds) == 1:
        num, pc, when = next(iter(builds))
        r.update(version=f"{_text(num)} PC {_text(pc)}", build_number=_text(num), pc_version=_text(pc),
                 build_time=" ".join(_text(when).split()))
    elif builds:
        r["version_note"] = f"{len(builds)} different 'Build Number:' lines in the ROM; cannot tell which one is the VBIOS version"
    else:
        r["version_note"] = ("no 'Build Number: <n> PC <x.y> <date> <time>' line in the ROM"
                             + (" (the 'Build Number:' text exists but its format differs)" if BUILD_PREFIX in rom else ""))
    for off, v in _sibling("intel_vbt").find_vbt(rom, MAX_VBT_CANDIDATES)[:1]:
        r["vbt"] = {"offset": off, "signature": v["signature"], "version": v["version"], "bdb_version": v["bdb_version"],
                    "vbt_size": v["vbt_size"]}
    return r


def _utf16_at(pe, p, limit):
    """p 位置的 UTF-16LE 字串（可列印 ASCII，到 NUL 為止，最多 limit 個字元）→ str 或 None（不是這種字串）。"""
    chars = []
    while p + 2 <= len(pe) and len(chars) <= limit:
        lo, hi = pe[p], pe[p + 1]
        if lo == 0 and hi == 0:
            return "".join(chars) if chars else None
        if hi != 0 or not 32 <= lo < 127:
            return None
        chars.append(chr(lo))
        p += 2
    return None


def pe_info(pe):
    """PE32+ 位元組 → dict(machine, subsystem, subsystem_name, size) 或 None（不是 PE、欄位對不上、不是 EFI subsystem）。"""
    n = len(pe)
    if n < 0x100 or n > MAX_PE or pe[:2] != b"MZ":
        return None
    e = struct.unpack_from("<I", pe, 0x3C)[0]
    if e < 0x40 or e + 24 + 0x60 > n or pe[e:e + 4] != b"PE\0\0":
        return None
    machine, _, _, _, _, opt_size, _ = struct.unpack_from("<HHIIIHH", pe, e + 4)
    o = e + 24
    magic = struct.unpack_from("<H", pe, o)[0]
    if magic not in (0x10B, 0x20B) or opt_size < 0x60 or o + opt_size > n:
        return None
    subsystem = struct.unpack_from("<H", pe, o + 68)[0]
    if subsystem not in EFI_SUBSYSTEMS:
        return None
    return {"machine": PE_MACHINES.get(machine, f"0x{machine:04x}"), "subsystem": subsystem,
            "subsystem_name": EFI_SUBSYSTEMS[subsystem], "size": n}


def gop_driver(pe):
    """PE32+ 位元組（一個 FFS 的 PE32 section 內容）→ Intel GOP 驅動的 dict，不是 Intel GOP 驅動 → None。
    {name, version, version_basis, version_note, machine, subsystem, subsystem_name, size}。
    判斷：是 EFI subsystem 的 PE，而且有 UTF-16 字串 `Intel(R) GOP Driver`（找到的第一個，要以 NUL 結尾）。
    version：驅動名稱之後 GOP_NAME_WINDOW bytes 內第一個非空的 UTF-16 字串，必須只有數字與點（最多 4 段）；否則 version 是 None
    （version_note 寫原因，不猜）。只有 build 編號（見模組說明），不是 `17.0.1070` 這種完整版本。"""
    pe = bytes(pe)
    info = pe_info(pe)
    if info is None:
        return None
    needle = GOP_DRIVER_NAME.encode("utf-16-le") + b"\0\0"
    i = pe.find(needle)
    while i >= 0 and i % 2:               # UTF-16 字串要 2 bytes 對齊
        i = pe.find(needle, i + 1)
    if i < 0:
        return None
    p, end = i + len(needle), min(len(pe), i + len(needle) + GOP_NAME_WINDOW)
    while p + 2 <= end and pe[p:p + 2] == b"\0\0":
        p += 2
    text = _utf16_at(pe, p, 32) if p + 2 <= end else None
    ver, note = None, None
    if text is None:
        note = f"no string within {GOP_NAME_WINDOW} bytes after the driver name"
    elif GOP_VERSION_RE.fullmatch(text):
        ver = text
    else:
        note = "the string after the driver name is not a version number"
    return {"name": GOP_DRIVER_NAME, "version": ver, "version_note": note,
            "version_basis": "UTF-16 digit string after the 'Intel(R) GOP Driver' string in the PE (build number only)",
            **info}
