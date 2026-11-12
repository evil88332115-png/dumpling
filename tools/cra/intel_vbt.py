#!/usr/bin/env python3
"""Intel VBT（Video BIOS Table）標頭的只讀解析：coreboot 的 vbt.bin、BIOS 映像裡的 GOP 用 VBT、Intel legacy VBIOS 裡內嵌的 VBT 共用。

只依賴標準函式庫。輸入是不可信資料：只讀、不執行；所有欄位都對資料長度檢查。

格式依據（Linux i915 drivers/gpu/drm/i915/display/intel_vbt_defs.h 的 struct vbt_header、struct bdb_header；
coreboot src/drivers/intel/gma/intel_bios.h 同）：
  vbt_header（小端）：signature[20]（`$VBT ` 加平台名稱，例如 `$VBT SKYLAKE`）、version u16（×100，100＝1.00）、header_size u16、
  vbt_size u16、vbt_checksum u8、reserved u8、bdb_offset u32、aim_offset[4]。
  bdb_header：signature[16]（`BIOS_DATA_BLOCK `）、version u16（×100，228＝2.28）、header_size u16、bdb_size u16。

parse_vbt() 原本在 coreboot_cbfs.py，搬到這裡讓 AMI 映像與 Intel legacy VBIOS 也能用（行為不變；coreboot_cbfs 仍以同名匯出）。
"""
import struct

SIGNATURE = b"$VBT "
MIN_HEADER = 48                          # vbt_header 的實際大小（coreboot、i915 的 header_size 下限）


def parse_vbt(d):
    """解壓後的 vbt.bin → dict 或 None。"""
    n = len(d)
    if n < 48 or bytes(d[:4]) != b"$VBT":
        return None
    sig = bytes(d[:20]).rstrip(b"\0 ")
    ver, hsize, vsize, csum, _, bdb = struct.unpack_from("<HHHBBI", d, 20)
    if hsize < 48 or hsize > n or vsize > n or vsize < hsize or any(c < 32 or c > 126 for c in sig):
        return None
    r = {"signature": sig.decode("ascii"), "version": f"{ver // 100}.{ver % 100:02d}", "version_raw": ver, "header_size": hsize,
         "vbt_size": vsize, "bdb_version": None, "bdb_version_raw": None}
    if bdb + 22 <= vsize and bytes(d[bdb:bdb + 16]) == b"BIOS_DATA_BLOCK ":
        bv = struct.unpack_from("<H", d, bdb + 16)[0]
        r["bdb_version_raw"], r["bdb_version"] = bv, f"{bv // 100}.{bv % 100:02d}"
    return r


def find_vbt(data, limit=16):
    """data 裡的 `$VBT ` 候選（最多 limit 個）→ [(offset, parse_vbt 的結果)]，只列標頭檢查通過的。
    不是每個 `$VBT ` 都是 VBT（映像裡也有說明文字），所以一定要過 parse_vbt 的檢查；vbt_size 超出 data 的候選不收。"""
    out, pos, seen = [], 0, 0
    while seen < limit:
        i = data.find(SIGNATURE, pos)
        if i < 0:
            break
        seen += 1
        pos = i + 1
        r = parse_vbt(memoryview(data)[i:])
        if r and i + r["vbt_size"] <= len(data):
            out.append((i, r))
    return out
