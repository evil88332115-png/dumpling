#!/usr/bin/env python3
"""AMI BIOS Guard（PFAT）封裝的解封裝：把 `_AMIPFAT` 封裝裡的 block 資料依順序組回 SPI／BIOS 映像（只在記憶體裡）。

用途：Intel NUC 等 AMI Aptio 平台的 BIOS 更新檔（.CAP）是 PFAT 封裝，映像內容被切成 block，直接掃描看不到 flash descriptor、
ME、微碼、UEFI firmware volume。這個模組只解封裝，`x86_firmware.py` 再照常解析組回來的映像。

只依賴標準函式庫。輸入是不可信資料：
- 所有長度欄位都先對照剩餘位元組與上限（MAX_*）才使用；不認得的版本、欄位互相矛盾的封裝回傳錯誤原因（不丟例外給呼叫端）。
- 不寫磁碟、不執行任何內容；BIOS Guard script 只檢查位元組長度與 begin／end opcode，不解讀、不執行。
- **不驗證簽章**：封裝裡的 BIOS Guard 簽章區（RSA 公鑰與簽章）只量長度、跳過，不驗證（result["signature_verified"] 永遠是 False）。
- 巢狀（block 組出來的檔案、封裝尾端裡又有 PFAT）處理到深度 MAX_DEPTH，更深的記為未解析。

格式依據（只讀原始碼核對欄位，沒有執行、沒有複製程式碼）：
  platomav/BIOSUtilities 的 biosutilities/ami_pfat_extract.py（AmiBiosGuardHeader、IntelBiosGuardHeader、IntelBiosGuardSignature* 結構與
  「封裝標頭是文字清單」的解析流程）與 biosutilities/common/patterns.py 的 PAT_AMI_PFAT。該專案授權是 BSD-2-Clause-Patent 型條款
  （Copyright (c) 2019-2025 Plato Mavropoulos；GitHub 偵測不到 SPDX 標籤）；這裡只引用欄位位置與意義的事實描述，程式碼是自己寫的，
  並用公開樣本（Intel NUC 11 PATGL357.0059）核對過。Intel BIOS Guard 本身是 Intel 平台功能，欄位名稱沿用上述原始碼。

封裝結構（小端；偏移相對於封裝開頭 P，P＝標記 `_AMIPFAT` 的位置 − 8）：
  P+0x00 u32 Size        封裝標頭總長（含下面的文字）
  P+0x04 u32 Checksum    用途不明（原始碼的註解是「?」），不使用也不驗證
  P+0x08 char[8] Tag     `_AMIPFAT`
  P+0x10 u8  Flags       用途不明，只記錄
  P+0x11 …Size           UTF-8 文字，每行一項：
                           第 1 行  `AMI_BIOS_GUARD_FLASH_CONFIGURATIONS`，後面可接 `II` 與每個檔案一組 4 位十六進位的 flash 順序索引
                           之後每行 `<flags> <param> <count>;<name>`：一個檔案、由 count 個 block 組成
  P+Size 開始是連續的 block，依檔案行的順序、每個檔案 count 個。每個 block：
    0x30 位元組 Intel BIOS Guard header（BGVerMajor u16、BGVerMinor u16、PlatformID[16]、Attributes u32（bit0 SFAM）、
         ScriptVerMajor u16、ScriptVerMinor u16、ScriptSize u32、DataSize u32、BIOSSVN u32、ECSVN u32、VendorInfo u32）
    ScriptSize 位元組的 script（8 位元組一個 opcode；開頭 begin、結尾 end）
    DataSize 位元組的資料（組映像要的就是這個）
    Attributes.SFAM 為 1 時再接簽章區：8 位元組簽章標頭（第 1 個 u32 為 1 → RSA-2048、2 或 3 → RSA-3072）＋ RSA 結構
         （2048：modulus 256 + exponent 4 + signature 256；3072：384 + 4 + 384）
  最後一個 block 之後的位元組（out-of-bounds，OOB）：記錄長度；開頭若又是 PFAT 則遞迴處理。
"""
import hashlib
import re
import struct

MAX_DEPTH = 4                     # 巢狀 PFAT 深度上限（外層是 0）；更深的記為未解析
MAX_HEADER = 1 << 20              # 封裝標頭（文字清單）長度上限
MAX_FILES = 64                    # 一個封裝宣告的檔案數上限
MAX_BLOCKS = 1 << 16              # 一個封裝宣告的 block 總數上限
MAX_SCRIPT = 1 << 20              # 單一 block 的 script 長度上限
MAX_IMAGE = 512 << 20             # 組回來的映像（單一檔案）上限，與 x86_firmware.MAX_FILE 一致
MAX_TOTAL = 1 << 30               # 一次解封裝（含巢狀）組回的位元組總量上限
SEARCH_LIMIT = 1 << 16            # 在輸入開頭這個範圍內找 `_AMIPFAT` 標記（AMI 封裝標頭在檔案開頭附近）

TAG = b"_AMIPFAT"
CONFIG_TEXT = b"AMI_BIOS_GUARD_FLASH_CONFIGURATIONS"
HDR_LEN = 0x11                    # Size + Checksum + Tag + Flags
BG_HDR_LEN = 0x30
SIG_HDR_LEN = 8
SIG_RSA = {2048: SIG_HDR_LEN + 256 + 4 + 256, 3072: SIG_HDR_LEN + 384 + 4 + 384}
SIG_BY_TYPE = {1: 2048, 2: 3072, 3: 3072}      # 簽章標頭第 1 個 u32 → RSA 位元數
OPCODE_LEN = 8
OP_BEGIN = b"\x01" + b"\x00" * 7
OP_END = b"\xff" + b"\x00" * 7
SIG_NOTE = "BIOS Guard 簽章未驗證（只解封裝，沒有檢查 RSA 簽章）"


class PfatError(ValueError):
    """封裝不合格式：訊息是給人看的原因。"""


def _sha256(b):
    return hashlib.sha256(b).hexdigest()


def find(data, limit=SEARCH_LIMIT):
    """→ 封裝開頭的位置（標記位置 − 8），沒有 PFAT 標記回傳 None。只看輸入開頭的 limit 位元組。"""
    head = data[:limit + HDR_LEN + len(CONFIG_TEXT)]
    m = re.search(re.escape(TAG) + b"." + re.escape(CONFIG_TEXT), head, re.S)
    if not m or m.start() < 8:
        return None
    return m.start() - 8


DIGITS = re.compile(r"[0-9]{1,9}")


def _nm(name):
    """錯誤訊息裡的檔名（截短：名稱來自不可信輸入，可以很長）。"""
    return repr(name[:60]) + ("…" if len(name) > 60 else "")


def _parse_header(data, p):
    """→ (標頭總長, flags, [(旗標, 參數, block 數, 名稱)], flash 順序索引 list 或 None)。"""
    if len(data) - p < HDR_LEN:
        raise PfatError("封裝標頭被截斷")
    size, _checksum = struct.unpack_from("<II", data, p)
    flags = data[p + 0x10]
    if size < HDR_LEN or size > MAX_HEADER:
        raise PfatError(f"封裝標頭長度不合理（{size}）")
    if p + size > len(data):
        raise PfatError(f"封裝標頭長度（{size}）超出檔案")
    try:
        lines = data[p + HDR_LEN:p + size].decode("utf-8").splitlines()
    except UnicodeDecodeError:
        raise PfatError("封裝標頭文字不是 UTF-8")
    if not lines or not lines[0].startswith(CONFIG_TEXT.decode()):
        raise PfatError("封裝標頭文字的第 1 行不是 AMI_BIOS_GUARD_FLASH_CONFIGURATIONS")
    title = lines[0]
    order = None
    if "II" in title:
        raw = title.split("II", 1)[1]
        if not re.fullmatch(r"(?:[0-9A-Fa-f]{4})+", raw):
            raise PfatError("flash 順序索引欄位格式不對")
        order = [int(raw[i:i + 4], 16) for i in range(0, len(raw), 4)]
    files = []
    for line in lines[1:]:
        if not line.strip():
            continue
        info, sep, name = line.partition(";")
        parts = info.split()
        # 數字欄位只接 ASCII 數字、最多 9 位：str.isdigit() 對上標數字（²）也是 True，int() 卻會丟 ValueError；
        # 超長的數字字串 int() 也會丟 ValueError（Python 的整數字串轉換上限）
        if not sep or len(parts) != 3 or not name or not DIGITS.fullmatch(parts[0]) or not DIGITS.fullmatch(parts[2]):
            raise PfatError(f"檔案清單的行格式不對：{line[:60]!r}")
        files.append((int(parts[0]), parts[1], int(parts[2]), name))
        if len(files) > MAX_FILES:
            raise PfatError(f"宣告的檔案數太多（超過 {MAX_FILES}）")
    if not files:
        raise PfatError("封裝標頭沒有列出任何檔案")
    if order is not None and len(order) != len(files):
        raise PfatError(f"flash 順序索引數（{len(order)}）和檔案數（{len(files)}）不符")
    total = sum(f[2] for f in files)
    if total == 0 or total > MAX_BLOCKS:
        raise PfatError(f"宣告的 block 數不合理（{total}）")
    if total * BG_HDR_LEN > len(data) - p - size:
        raise PfatError(f"宣告 {total} 個 block，但剩下的位元組不夠放 header（截斷或長度矛盾）")
    return size, flags, files, order


def _script_note(script):
    if len(script) % OPCODE_LEN:
        return "script 長度不是 8 的倍數"
    if script[:OPCODE_LEN] != OP_BEGIN or script[-OPCODE_LEN:] != OP_END:
        return "script 缺少 begin／end opcode"
    return None


def _signature_len(data, off, marker, end, cached):
    """簽章區長度（含 8 位元組標頭）。標頭第 1 個 u32 已知就照它；否則用「下一個 block header 標記出現的位置」推（已推過的沿用）。"""
    if end - off < SIG_HDR_LEN:
        raise PfatError("簽章區被截斷")
    kind = struct.unpack_from("<I", data, off)[0]
    if kind in SIG_BY_TYPE:
        return SIG_RSA[SIG_BY_TYPE[kind]], SIG_BY_TYPE[kind]
    if cached:
        return cached, None
    nxt = data.find(marker, off, min(end, off + SIG_RSA[3072] + len(marker)))
    if nxt >= 0 and nxt - off in SIG_RSA.values():
        return nxt - off, None
    raise PfatError(f"簽章區格式不認得（標頭 0x{kind:X}），也推不出長度")


def parse(data, offset=None, depth=0, budget=None, acc=None):
    """解一個 PFAT 封裝。→ dict（見 unwrap）。不合格式時丟 PfatError。
    acc：[已組回的位元組數]，巢狀共用，讓 MAX_TOTAL 是整次解封裝（含巢狀）的總量。"""
    acc = [0] if acc is None else acc
    p = find(data) if offset is None else offset
    if p is None:
        raise PfatError("沒有 PFAT 標記")
    size, flags, files, order = _parse_header(data, p)
    pos = p + size
    n_total = sum(f[2] for f in files)
    out_files, notes, marker, sig_len, sig_bits = [], [], None, 0, set()
    first = None
    for fi, (fflags, param, count, name) in enumerate(files):
        chunks, size_sum, n_sig = [], 0, 0
        for bi in range(count):
            if budget is not None:
                budget.check()
            if len(data) - pos < BG_HDR_LEN:
                raise PfatError(f"檔案 {_nm(name)} 的第 {bi + 1}/{count} 個 block header 被截斷")
            (vmaj, vmin) = struct.unpack_from("<HH", data, pos)
            plat = data[pos + 4:pos + 20]
            attrs, smaj, smin, ssize, dsize, bsvn, ecsvn, vendor = struct.unpack_from("<IHHIIIII", data, pos + 20)
            hdr_marker = data[pos:pos + 20]
            if marker is None:
                marker, first = hdr_marker, {"bg_version": f"{vmaj}.{vmin}", "script_version": f"{smaj}.{smin}",
                                             "bios_svn": bsvn, "ec_svn": ecsvn, "platform_id": plat.rstrip(b"\x00").decode("ascii", "replace")
                                             if all(32 <= c < 127 or c == 0 for c in plat) else plat.hex()}
            elif hdr_marker != marker:
                raise PfatError(f"檔案 {_nm(name)} 的第 {bi + 1}/{count} 個 block 的 BIOS Guard 版本／平台 ID 和第一個 block 不同（欄位矛盾）")
            if ssize > MAX_SCRIPT or ssize > len(data) - pos - BG_HDR_LEN:
                raise PfatError(f"檔案 {_nm(name)} 的第 {bi + 1}/{count} 個 block 的 script 長度（{ssize}）超出檔案或上限")
            doff = pos + BG_HDR_LEN + ssize
            if dsize > len(data) - doff:
                raise PfatError(f"檔案 {_nm(name)} 的第 {bi + 1}/{count} 個 block 的資料長度（{dsize}）超出檔案（截斷或長度矛盾）")
            if size_sum + dsize > MAX_IMAGE or acc[0] + dsize > MAX_TOTAL:
                raise PfatError(f"檔案 {_nm(name)} 組回來的大小超過上限")
            sn = _script_note(data[pos + BG_HDR_LEN:doff])
            if sn and sn not in notes:
                notes.append(sn)
            chunks.append(data[doff:doff + dsize])
            size_sum += dsize
            acc[0] += dsize
            pos = doff + dsize
            if attrs & 1:                          # SFAM：後面接簽章區
                slen, bits = _signature_len(data, pos, marker, len(data), sig_len)
                sig_len = slen
                if bits:
                    sig_bits.add(bits)
                if slen > len(data) - pos:
                    raise PfatError(f"檔案 {_nm(name)} 的第 {bi + 1}/{count} 個 block 的簽章區超出檔案")
                pos += slen
                n_sig += 1
        out_files.append({"name": name, "flags": fflags, "param": param, "blocks": count, "signed_blocks": n_sig,
                          "flash_index": order[fi] if order else None, "size": size_sum, "data": b"".join(chunks)})
    oob = data[pos:]
    result = {"offset": p, "header_size": size, "flags": flags, "files": out_files, "blocks": n_total,
              "block_info": first, "signature_bits": sorted(sig_bits), "oob": oob, "oob_size": len(oob), "notes": notes,
              "signature_verified": False, "nested": [], "unparsed": []}
    # 巢狀：每個組出來的檔案、尾端資料開頭如果又是 PFAT 就遞迴（深度有上限）
    subjects = [(f"file[{i}] {f['name']}", f["data"]) for i, f in enumerate(out_files)] + ([("trailing data", oob)] if oob else [])
    for label, blob in subjects:
        if find(blob) is None:
            continue
        if depth + 1 > MAX_DEPTH:
            result["unparsed"].append(f"{label}：巢狀 PFAT 超過深度上限 {MAX_DEPTH}，沒有解開")
            continue
        try:
            sub = parse(blob, None, depth + 1, budget, acc)
        except PfatError as e:
            result["unparsed"].append(f"{label}：巢狀 PFAT 解不開（{e}）")
            continue
        sub["source"] = label
        result["nested"].append(sub)
        result["unparsed"] += sub["unparsed"]
    return result


def images(result):
    """→ [(標籤, bytes, flash 順序索引或 None)]：解封裝後可以當 BIOS 映像去解析的內容，依封裝順序（有索引時檔案依索引排），最後是尾端資料。
    巢狀 PFAT 解開的內容取代它的來源（來源本身只剩封裝）。"""
    nested = {n["source"]: n for n in result["nested"]}
    files = []
    for i, f in enumerate(result["files"]):
        label = f"file[{i}] {f['name']}"
        files += ([(f"{label} > {l}", b, f["flash_index"]) for l, b, _ in images(nested[label])] if label in nested
                  else [(label, f["data"], f["flash_index"])])
    if files and all(x[2] is not None for x in files):
        files.sort(key=lambda x: x[2])
    oob = result["oob"]
    if oob:
        files += ([(f"trailing > {l}", b, None) for l, b, _ in images(nested["trailing data"])] if "trailing data" in nested
                  else [("trailing data", oob, None)])
    return files


def unwrap(data, budget=None):
    """偵測並解開 PFAT。→ None（不是 PFAT）；否則 dict：
    {"ok": bool, "error": 原因或 None, "image": 組回的映像 bytes 或 None, "image_label": …, "orig_sha256", "image_sha256",
     "files": [{name, flags, param, blocks, signed_blocks, flash_index, size, sha256}], "notes": [...], "unparsed": [...],
     "signature_verified": False, "info": {...}}
    image：各檔案（有 flash 順序索引時依索引，否則依清單順序）接起來，再接封裝尾端資料——與 PFAT 解開工具的 ALL 相同，
    不是 SPI 位址對應的映像（script 沒有解讀）。budget 有 check()（超時丟例外給呼叫端處理）。"""
    if find(data) is None:
        return None
    base = {"ok": False, "error": None, "image": None, "image_label": None, "orig_sha256": _sha256(data), "image_sha256": None,
            "files": [], "notes": [SIG_NOTE], "unparsed": [], "signature_verified": False, "info": {}}
    try:
        r = parse(data, None, 0, budget)
    except PfatError as e:
        base["error"] = str(e)
        return base
    except (ValueError, struct.error, IndexError, OverflowError, MemoryError) as e:   # 有檢查邊界，不該發生；發生就當格式錯誤
        base["error"] = f"解析失敗（{type(e).__name__}）"
        return base
    imgs = images(r)
    blob = b"".join(b for _, b, _ in imgs)
    base.update(ok=True, image=blob, image_sha256=_sha256(blob),
                image_label=f"{len(imgs)} 個區段（含尾端資料）" if len(imgs) > 1 else imgs[0][0],
                files=[{k: v for k, v in f.items() if k != "data"} | {"sha256": _sha256(f["data"])} for f in r["files"]],
                notes=[SIG_NOTE] + r["notes"], unparsed=r["unparsed"],
                info={"offset": r["offset"], "header_size": r["header_size"], "flags": r["flags"], "blocks": r["blocks"],
                      "oob_size": r["oob_size"], "nested": len(r["nested"]), "signature_bits": r["signature_bits"], **(r["block_info"] or {})})
    return base
