#!/usr/bin/env python3
"""Intel CSE 的 IFWI 分割區配置：CSE layout table → BPDT → 主程式分割區的 `$CPD` → `<名稱>.man` 的 `$MN2` manifest。

x86_firmware.py 的 ME 版本原本靠 `$FPT` 分割區表（或名稱是 FTPR 的 `$CPD`）。新世代的 CSE 區域不用 `$FPT` 找主程式：
區域開頭是 CSE layout table，指到 1～5 個 boot partition（BP1…BP5），每個 boot partition 開頭是 BPDT（Boot Partition Descriptor Table），
BPDT 的項目指到各子分割區（每個是一個 `$CPD` 目錄）。`$FPT` 只剩在 data partition 裡，不在區域開頭，也不列主程式。
新世代（例如 CSME 18）沒有 FTPR 那一項：CSE 主程式在 RBEP（BPDT type 1）與 NFTP（type 7）兩個分割區，各自的 manifest 版本相同。

只讀、不執行、不寫磁碟；輸入是不可信資料。所有走訪都有固定上限（沒有全檔掃描、沒有 regex）：boot partition 最多 MAX_BP 個、
每個 BPDT 最多 MAX_BPDT_ENTRIES 項、每個 `$CPD` 最多 MAX_CPD_ENTRIES 項，只讀 FTPR／RBEP／NFTP 三種分割區，總量固定。
BPDT 項目裡的 S-BPDT（type 5）不往下追（不會有循環或遞迴）。

格式依據（只引用欄位定義與出處，程式是自己寫的，沒有複製或改寫任何 GPL 程式碼）：
- BPDT 表頭 0x18 bytes：signature 0x000055AA、descriptor_count(u16)、version(1 或 2)、flags、checksum、ifwi_version、fit_tool_version(4×u16)；
  項目 12 bytes：version 1＝type(u16)、flags(u16)、offset(u32)、size(u32)，version 2（layout 1.7）＝type(u32)、offset、size；
  offset 相對這個 BPDT 的開頭（＝boot partition 開頭）。出處：coreboot `util/cbfstool/ifwitool.c`（bpdt_header、bpdt_entry、
  子分割區類型表）與 `src/soc/intel/common/block/include/intelblocks/cse_layout.h`（BPDT version 1.7 的欄位、類型編號）。
- `$CPD`（子分割區目錄）：+0 tag、+4 項目數、+8 header version、+9 entry version(1)、+0xA header 長度、+0xC 分割區名稱 4 bytes。
  header version 1：長度 0x10，+0xB 是 8 位元 checksum（整個 header 加全部項目的 8 位元總和為 0；ifwitool.c 的 subpart_dir_header 註解）。
  header version 2：長度 0x14，+0xB 保留，+0x10 是 32 位元 checksum（把這個欄位當 0，對 header 加全部項目算 CRC-32；版本 2 的欄位位移
  與版本 1 不同；出處：cse_layout.h 的 subpart_hdr、MEAnalyzer 的 CPD_Header_R1／R2，CRC-32 的算法是對公開樣本逐項驗證出來的）。
  每個項目 0x18 bytes：名稱 12 bytes、+0xC offset（低 25 bits，相對 `$CPD` 開頭；高位元是壓縮旗標，manifest 不可壓縮）、+0x10 長度、+0x14 保留。
- `$MN2` manifest：+0x10 vendor 0x8086、+0x14 BCD 日期、+0x1C tag、+0x24 的 major.minor.hotfix.build（4×u16；cse_layout.h 的
  subpart_entry_manifest_header、MEAnalyzer 的 MN2_Manifest）。
- CSE layout table（區域開頭；MEAnalyzer 的 CSE_Layout_Table_16／17，coreboot cse_layout.h 的 cse_layout）：
  layout 1.7＝+0 ROM bypass 16 bytes、+0x10 Size(u16)、+0x12 Flags(bit 0＝CSE redundancy：BP2 是 BP1 的備份)、+0x14 checksum(u32)、
  +0x18 data(offset,size)、+0x20…+0x44 BP1…BP5(offset,size)、+0x48 temp pages、+0x50 external error log（Size 0x48 以上才有）；欄位都是 u32，offset 相對區域開頭。
  **Size 從 +0x10 起算**（表的總長是 0x10＋Size）。MEAnalyzer 的註解寫 Size 是 0x40（沒有 ELog）或 0x48（有 ELog），公開真樣本是 0x58（Meteor Lake，兩個版本）與
  0x60（Arrow Lake-U/H FSP 的 Dasharo NovaCustom NUC BOX v0.9.2：表總長 0x70，結構與 CRC 算法同 0x58）。
  **checksum 是 CRC-32**，範圍是 d[+0x10:+0x14] ＋ 4 個 0（checksum 欄位本身不入算）＋ d[+0x18:+0x10+Size]（MEAnalyzer 的驗證程式；
  三個真樣本的 stored 值都相符）。本模組逐值認 Size 0x40、0x48、0x58、0x60（不用「範圍」或「8 的倍數」之類的規則：Size 決定 CRC 的涵蓋範圍，
  未知的 Size 沒有依據，CRC 算得對也不代表欄位排列相同）；CRC 不符 → GAP；Size 是其他值（例如 0x5C、0x64、0x68、0x70）→ 不認（none）。
  0x40 與 0x48 只有 MEAnalyzer 的欄位定義與驗證程式為依據，沒有真樣本核對（測試用合成資料）。
  公開定義（MEAnalyzer、coreboot cse_layout.h）只到 +0x58（external error log 結尾）；Size 0x58 的 +0x58…+0x67 與 Size 0x60 的 +0x58…+0x6F 沒有公開欄位定義
  （三個真樣本都是 0）。這段只要有任何非 0 的 byte（就算 CRC 相符）就不解讀這張表，回 GAP：不知道那裡是不是另一個 boot partition 指標，
  照讀會漏掉 FTPR／NFTP 的來源或讓「兩個來源一致」的判斷出錯。BP1…BP5 的位置固定在 +0x20…+0x44，不受 Size 影響；external error log 與 temp pages 不讀。
  layout 1.6＝同樣 16 bytes ROM bypass，+0x10 data(offset,size)、+0x18…+0x3C BP1…BP5(offset,size)、+0x40 u64 checksum，表長 0x48，
  之後到 0x1000 全是 0xFF（MEAnalyzer 也用這個填充當辨識條件之一，因為 1.6 沒有標記）。MEAnalyzer 註解說 checksum 是整張表（不含 ROM bypass）的二補數和；
  唯一的公開樣本（Comet Lake）存的是 0x22，我試過位元組、u32、u64 的加總都湊不成 0，算法沒確認，**不驗證**。
  兩種 layout 都以「每個非空 BPn 都真的指到 BPDT、範圍不重疊不超出區域」確認。

主程式（CSE 版本）的判定，不猜：
- 看 BPDT 的 type 2（FTPR）、type 1（RBEP）、type 7（NFTP）三種分割區。分割區名稱必須是對應的 FTPR／RBEP／NFTP，
  `$CPD` 表頭、checksum、`<名稱>.man` 項目、`$MN2` 都要過，版本不能全是 0。
- 有 FTPR：取 FTPR.man 的版本；沒有 FTPR（新世代）：RBEP 與 NFTP 兩種類型各至少要有一份，而且版本相同才採用。
  同一類型的多份拷貝（例如 redundancy 開啟時 BP2 是 BP1 的備份）不算獨立來源；只有一種類型 → 不採用。
- 讀得到的主程式 manifest 版本互相不同、任何一個 BPDT 或主程式分割區結構不一致（越界、重疊、重複項目、名稱不符、checksum 不符、manifest 壞）→ 不回報版本，
  回報原因（呼叫端維持 unknown／GAP）。
- 限制：只看 CSE 區域本身（呼叫端給的範圍）；區域外的 IFWI（例如整個放在 BIOS 區域裡的平台）、capsule 包著的區域、layout table 之外的配置不處理。
"""
import struct
import zlib

BPDT_SIG = 0x000055AA
BPDT_HDR = 0x18
BPDT_ENTRY = 0x0C
MAX_BP = 5                             # layout 1.7 最多 5 個 boot partition
MAX_BPDT_ENTRIES = 48                  # 實際約 5～10 項；coreboot 的類型表到 33
MAX_CPD_ENTRIES = 256
LAYOUT_17_SIZES = (0x40, 0x48, 0x58, 0x60)    # Size 欄位（從 +0x10 起算）：MEAnalyzer 的 0x40／0x48、公開真樣本的 0x58（NovaCustom V540TU）與 0x60（NovaCustom NUC BOX v0.9.2）；
                                              # 逐值列舉，不用範圍規則：其他值沒有依據（見模組 docstring）
LAYOUT_17_KNOWN = 0x58                        # 公開定義（MEAnalyzer、coreboot）到 +0x58 為止（ELog 結尾）；表內再往後的位元組沒有公開欄位定義
LAYOUT_16_SIZE = 0x48
LAYOUT_PAD = 0x1000                      # 1.6 的表後面填 0xFF 到這裡
MAIN_TYPES = {2: "FTPR", 1: "RBEP", 7: "NFTP"}    # BPDT 類型 → `$CPD` 名稱（ifwitool.c 與 cse_layout.h 的類型表）
PARSE_ERRORS = (struct.error, IndexError, ValueError, OverflowError)


def u16(d, o):
    return struct.unpack_from("<H", d, o)[0]


def u32(d, o):
    return struct.unpack_from("<I", d, o)[0]


def erased(d, p, size):
    """p～p+size 全是 0xFF（flash 清除過）。"""
    return not d[p:p + size].strip(b"\xff")


def layout_table(d, base, end):
    """區域開頭的 CSE layout table → ({"version", "ranges": [(名稱, 相對 offset, size)]}, None)；不像 layout table → (None, None)；
    像（layout 1.7 的 Size 欄位對）但 CRC 不符或內容矛盾 → (None, 原因)。"""
    if base + 0x20 > end:
        return None, None
    size = end - base
    sz = u16(d, base + 0x10)
    if sz in LAYOUT_17_SIZES:
        total = 0x10 + sz
        if base + total > end:
            return None, f"CSE layout table at 0x{base:x} (Size 0x{sz:x}) goes past the end of the region"
        want = u32(d, base + 0x14)
        got = zlib.crc32(d[base + 0x10:base + 0x14] + bytes(4) + d[base + 0x18:base + total])
        if got != want:
            return None, f"CSE layout table at 0x{base:x}: CRC-32 mismatch (stored 0x{want:08x}, computed 0x{got:08x})"
        if total > LAYOUT_17_KNOWN and any(d[base + LAYOUT_17_KNOWN:base + total]):
            return None, (f"CSE layout table at 0x{base:x} (Size 0x{sz:x}): the bytes after the defined fields "
                          f"(0x{LAYOUT_17_KNOWN:x}-0x{total - 1:x}) are not all zero; their meaning is not publicly documented, so the table is not interpreted")
        ver, strict, head = "1.7", True, total
        pairs = [("data", u32(d, base + 0x18), u32(d, base + 0x1C))]
        pairs += [(f"BP{i + 1}", u32(d, base + 0x20 + 8 * i), u32(d, base + 0x24 + 8 * i)) for i in range(MAX_BP)]
    else:
        if size < LAYOUT_16_SIZE or not erased(d, base + LAYOUT_16_SIZE, min(LAYOUT_PAD, size) - LAYOUT_16_SIZE):
            return None, None
        ver, strict, head = "1.6", False, LAYOUT_16_SIZE
        pairs = [("data", u32(d, base + 0x10), u32(d, base + 0x14))]
        pairs += [(f"BP{i + 1}", u32(d, base + 0x18 + 8 * i), u32(d, base + 0x1C + 8 * i)) for i in range(MAX_BP)]
    used = [(n, o, s) for n, o, s in pairs if o or s]
    why = None
    for n, o, s in used:
        if s == 0 or o < head or o + s > size:
            why = f"CSE layout table (layout {ver}) {n} 0x{o:x}+0x{s:x} is outside the region (size 0x{size:x}) or overlaps the table"
            break
    if why is None:
        srt = sorted(used, key=lambda x: x[1])
        for a, b in zip(srt, srt[1:]):
            if a[1] + a[2] > b[1]:
                why = f"CSE layout table (layout {ver}): {a[0]} 0x{a[1]:x}+0x{a[2]:x} overlaps {b[0]} 0x{b[1]:x}"
                break
    if why is not None:
        return (None, why) if strict else (None, None)    # 1.6 沒有標記：矛盾時當作不是 layout table
    if not any(n != "data" for n, _, _ in used):
        return None, None
    return {"version": ver, "ranges": used}, None


def bpdt_entries(d, lbp, lbp_end):
    """lbp 位置的 BPDT → ({類型: (相對 offset, size)（只含 size>0 的項目）}, 項目數, None) 或 (None, 0, 原因)。
    offset 相對 BPDT 開頭；非空項目必須在表頭＋項目表之後、boot partition 之內、彼此不重疊；FTPR／RBEP／NFTP 不可重複。"""
    if lbp + BPDT_HDR > lbp_end or u32(d, lbp) != BPDT_SIG:
        return None, 0, f"no BPDT signature at 0x{lbp:x}"
    cnt, ver = u16(d, lbp + 4), d[lbp + 6]
    if ver not in (1, 2):
        return None, 0, f"BPDT at 0x{lbp:x} has version {ver} (supported: 1, 2)"
    if not 1 <= cnt <= MAX_BPDT_ENTRIES:
        return None, 0, f"BPDT at 0x{lbp:x} declares {cnt} entries (accepted 1-{MAX_BPDT_ENTRIES})"
    hdr_end = BPDT_HDR + BPDT_ENTRY * cnt
    if lbp + hdr_end > lbp_end:
        return None, 0, f"BPDT at 0x{lbp:x}: the entry table goes past the end of the boot partition"
    span = lbp_end - lbp
    ents = []
    for i in range(cnt):
        e = lbp + BPDT_HDR + BPDT_ENTRY * i
        typ = u32(d, e) if ver == 2 else u16(d, e)
        off, size = u32(d, e + 4), u32(d, e + 8)
        if size == 0:
            continue
        if off < hdr_end or off + size > span:
            return None, cnt, (f"BPDT at 0x{lbp:x}: entry {i} (type {typ}) 0x{off:x}+0x{size:x} is outside the boot partition "
                               f"(size 0x{span:x}) or overlaps the BPDT")
        ents.append((off, size, typ, i))
    ents.sort()
    for a, b in zip(ents, ents[1:]):
        if a[0] + a[1] > b[0]:
            return None, cnt, f"BPDT at 0x{lbp:x}: entries {a[3]} (type {a[2]}) and {b[3]} (type {b[2]}) overlap"
    out = {}
    for off, size, typ, i in ents:
        if typ in MAIN_TYPES:
            if typ in out:
                return None, cnt, f"BPDT at 0x{lbp:x} has two non-empty {MAIN_TYPES[typ]} entries (type {typ})"
            out[typ] = (off, size)
    return out, cnt, None


def cpd_manifest(d, p, pend, name):
    """p～pend 的子分割區：`$CPD` 目錄 → `<name>.man` 的 `$MN2` → ({"offset", "version", "date_raw"}, None) 或 (None, 原因)。"""
    if p + 0x10 > pend or d[p:p + 4] != b"$CPD":
        return None, f"{name} partition at 0x{p:x} does not start with $CPD"
    cnt, hv, ev, hl = u32(d, p + 4), d[p + 8], d[p + 9], d[p + 0x0A]
    if (hv, hl) not in ((1, 0x10), (2, 0x14)) or ev != 1:
        return None, f"{name} $CPD at 0x{p:x}: header version {hv}, entry version {ev}, header length 0x{hl:x} (supported: 1/0x10, 2/0x14, entry version 1)"
    if not 1 <= cnt <= MAX_CPD_ENTRIES:
        return None, f"{name} $CPD at 0x{p:x} declares {cnt} entries (accepted 1-{MAX_CPD_ENTRIES})"
    tab = hl + 0x18 * cnt
    if p + tab > pend:
        return None, f"{name} $CPD at 0x{p:x}: the entry table goes past the end of the partition"
    got = d[p + 0x0C:p + 0x10].rstrip(b"\x00")
    if got != name.encode():
        return None, f"$CPD at 0x{p:x} is named {got.decode('ascii', 'replace')!r}, expected {name!r}"
    blk = bytearray(d[p:p + tab])
    if hv == 1:
        if sum(blk) & 0xFF:
            return None, f"{name} $CPD at 0x{p:x}: 8-bit checksum mismatch"
    else:
        want = u32(blk, 0x10)
        blk[0x10:0x14] = bytes(4)
        if zlib.crc32(bytes(blk)) != want:
            return None, f"{name} $CPD at 0x{p:x}: CRC-32 checksum mismatch"
    man = (name + ".man").encode()
    hits = [k for k in range(cnt) if d[p + hl + 0x18 * k:p + hl + 0x18 * k + 12].rstrip(b"\x00") == man]
    if len(hits) != 1:
        return None, f"{name} $CPD at 0x{p:x} has {'no' if not hits else 'more than one'} {name}.man entry"
    e = p + hl + 0x18 * hits[0]
    raw, length = u32(d, e + 0x0C), u32(d, e + 0x10)
    off = raw & 0x1FFFFFF
    if raw >> 25:
        return None, f"{name}.man in the $CPD at 0x{p:x} has compression flags 0x{raw >> 25:x}"
    h = p + off
    if length < 0x2C or off < tab or h + length > pend:
        return None, f"{name}.man (0x{off:x}+0x{length:x}) is outside the {name} partition or overlaps its $CPD entry table"
    if d[h + 0x1C:h + 0x20] != b"$MN2" or u32(d, h + 0x10) != 0x8086:
        return None, f"{name}.man at 0x{h:x} is not a valid $MN2 manifest"
    ver = struct.unpack_from("<4H", d, h + 0x24)
    if not any(ver):
        return None, f"{name}.man at 0x{h:x} has version 0.0.0.0"
    return {"offset": h, "version": ".".join(map(str, ver)), "date_raw": u32(d, h + 0x14)}, None


def find_cse(d, base, end, budget=None):
    """base～end（CSE 區域）的主程式 manifest → dict：
    status＝none（沒有 layout table 也沒有 BPDT：不是這種配置，呼叫端不必理）、
            found（version、date_raw、offset＝manifest 檔案位置、basis、sources）、
            gap（認得出這種配置，但沒有可用或一致的版本；note 是原因）。"""
    end = min(end, len(d))
    try:
        return _find(d, base, end, budget)
    except PARSE_ERRORS as e:
        return {"status": "gap", "note": f"CSE layout/BPDT structures are unreadable ({type(e).__name__})"}


def _find(d, base, end, budget):
    lay, why = layout_table(d, base, end)
    if why:
        return {"status": "gap", "note": why}
    problems, how = [], None
    lbps = []                                           # (名稱, boot partition 開頭, 結尾)
    if lay:
        how = f"CSE layout table {lay['version']}"
        for n, o, s in lay["ranges"]:
            if n == "data":
                continue
            p = base + o
            if erased(d, p, s):                         # 配置了但整個 boot partition 都是 0xFF（清除過的 flash）；只有表頭是 0xFF 不算
                continue
            lbps.append((n, p, p + s))
    elif base + 4 <= end and u32(d, base) == BPDT_SIG:
        how = "BPDT at the region start"
        lbps.append(("LBP", base, end))
    else:
        return {"status": "none"}
    cands = []
    for lname, lbp, lend in lbps:
        if budget is not None:
            budget.check()
        ents, _, why = bpdt_entries(d, lbp, lend)
        if why:
            problems.append(f"{lname}: {why}")
            continue
        for typ in (2, 1, 7):
            if typ not in ents:
                continue
            name = MAIN_TYPES[typ]
            off, size = ents[typ]
            m, why = cpd_manifest(d, lbp + off, lbp + off + size, name)
            if m is None:
                problems.append(f"{lname}: {why}")
            else:
                cands.append({"name": name, "lbp": lname, "partition": lbp + off, **m})
    if not lbps and not problems:
        return {"status": "gap", "note": f"{how}: every boot partition is empty (erased)"}
    if problems:
        return {"status": "gap", "note": "; ".join(problems)}
    if not cands:
        return {"status": "gap", "note": f"{how}: no FTPR, RBEP or NFTP partition with a manifest in the BPDT"}
    desc = ", ".join(f"{c['lbp']} {c['name']}.man {c['version']} at 0x{c['offset']:x}" for c in cands)
    if len({c["version"] for c in cands}) > 1:
        return {"status": "gap", "note": f"{how}: the main-program manifests disagree ({desc}); no version is reported"}
    ftpr = next((c for c in cands if c["name"] == "FTPR"), None)
    kinds = {c["name"] for c in cands}
    if ftpr is None and not {"RBEP", "NFTP"} <= kinds:
        return {"status": "gap", "note": (f"{how}: no FTPR partition and no {' or '.join(sorted({'RBEP', 'NFTP'} - kinds))} partition ({desc}); "
                                          "RBEP and NFTP must both be present with the same version (copies of one type are not independent), so no version is reported")}
    pick = ftpr or next(c for c in cands if c["name"] == "RBEP")     # 有 FTPR 取它；否則取第一個 RBEP（各份版本都相同）
    return {"status": "found", "version": pick["version"], "date_raw": pick["date_raw"], "offset": pick["offset"],
            "basis": f"BPDT ({how}): {desc}" + ("" if ftpr else "; no FTPR partition, RBEP and NFTP agree"),
            "sources": cands, "layout": how}
