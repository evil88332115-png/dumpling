#!/usr/bin/env python3
"""出貨的 UEFI 映像（uefi_*.bin）解開後，確認哪些內建函式庫真的編進去（只讀、不執行任何東西）。

做法：照 UEFI PI 規格解析 Firmware Volume（FV）→ FFS 檔 → section（GUID-defined LZMA、CRC32、壓縮 section、PE32、UI、嵌套的 FV）。
每一層解開的內容只在記憶體裡掃一次就丟掉；每個函式庫有一張指紋表（字串樣式＋建置路徑樣式＋門檻）。

每個函式庫的結果（映像層級）：
  present       字串或建置路徑的證據達門檻（至少 PRESENT_MIN_STRINGS 種不同的字串，或至少一個建置路徑）。
  absent        映像完整解開（解析成功、所有壓縮 section 都解開、沒有超過限制）而且所有樣式的命中數都是 0。
  not_assessed  其他情形：有 section 解不開（例如 EFI_STANDARD_COMPRESSION 本工具不支援）、超過解壓縮限制、解析失敗而退回標頭掃描、
                或只有零星命中（沒到 present 的門檻）。不可當成 absent。
解析失敗時退回「標頭掃描」（整個檔案原始位元組＋找得到的 LZMA 串流），結果記 method=header_scan；這個方法不能證明全部解開，所以不給 absent。

限制（防解壓縮炸彈）：遞迴深度 MAX_DEPTH、單層解開大小 MAX_LAYER、全部解開的總量 MAX_TOTAL、FFS 檔數 MAX_FILES；宣告大小超過限制的串流不解開，記為未解開。
註：不分大小寫的 "mbed" 會命中 "embed"（asn1_item_embed_d2i、EmbeddedPkg）；樣式前面都要求不是英文字母。

用法：python3 -I uefi_image.py <映像檔>...    （印每個映像的 JSON 摘要）
"""
import json
import lzma
import re
import struct
import sys
from pathlib import Path

SCHEMA = "sca-center-uefi-image-libs/1"
MAX_DEPTH = 6
MAX_LAYER = 256 << 20
MAX_TOTAL = 512 << 20
MAX_FILES = 50000
MAX_MODULES_LISTED = 2000
MAX_EXAMPLES = 5
PRESENT_MIN_STRINGS = 3         # 至少幾種不同的字串命中才算 present
PRESENT_MIN_PATHS = 1           # 或至少幾個建置路徑

# ---------------------------------------------------------------- 指紋表（要加函式庫就在這裡加一筆）
# 每個樣式：(種類 "string"／"path", 位元組 regex)。樣式前面一律 (?<![A-Za-z])，避免 "embed" 之類的子字串命中。
# 所有樣式都以字面字串開頭、其後的重複有上限：不放「開頭不限長度的字元類別」（對一長串數字與斜線會變成平方時間而卡住）。
# path 種類只比對字面的標記，命中後再往前後各最多 PATH_CONTEXT 個路徑字元取成證據字串（expand_path）。
# weak：True＝這個函式庫的字串在去除除錯／錯誤字串的 RELEASE 建置裡可能幾乎不留痕跡，所以「沒有命中」不能單獨證明不在（absent 要 DSC 佐證）。
# dsc_markers：平台 DSC 的函式庫類別對應裡，指到這個函式庫的 INF 路徑標記（不分大小寫）；
# alt_markers：指到「另一種實作」的 INF 路徑標記（佐證：函式庫類別被對應到另一種實作）。
NB = rb"(?<![A-Za-z])"
PATH_CONTEXT = 200
FINGERPRINTS = {
    "openssl": {
        "label": "OpenSSL",
        "weak": True,
        "dsc_markers": ["/OpensslLib/"],
        "alt_markers": ["/MbedTlsLib/"],
        "patterns": [
            ("string", NB + rb"ossl_[a-z0-9_]{4,}"),
            ("string", NB + rb"OPENSSL_[A-Z0-9_]{4,}"),
            ("string", NB + rb"ECDHE-(?:RSA|ECDSA)-AES(?:128|256)-GCM-SHA(?:256|384)"),
            ("string", NB + rb"id-aes(?:128|192|256)-GCM"),
            ("path", rb"OpensslLib"),
            ("path", rb"openssl[/\\](?:crypto|ssl)[/\\]"),
        ],
        "version": rb"OpenSSL (\d\.\d+\.\d+[a-z]?)",
    },
    "mbedtls": {
        "label": "Mbed TLS",
        "weak": True,
        "dsc_markers": ["/MbedTlsLib/"],
        "alt_markers": ["/OpensslLib/"],
        "patterns": [
            ("string", NB + rb"mbedtls_[a-z0-9_]{3,}"),
            ("string", NB + rb"MBEDTLS_[A-Z0-9_]{3,}"),
            ("string", rb"(?i)(?<![a-z])mbed[ _-]?tls"),
            ("string", NB + rb"TLS-(?:ECDHE|DHE|ECDH|RSA|PSK|ECJPAKE)-[A-Z0-9-]{0,40}WITH-[A-Z0-9-]{1,60}"),
            ("string", NB + rb"psa_(?:crypto_init|import_key|generate_random|hash_compute|cipher_encrypt|key_derivation_setup)\b"),
            ("path", rb"(?i)(?<![a-z])mbedtls[a-z0-9_-]{0,40}[/\\]"),
        ],
        "version": rb"(?i)mbed ?TLS (\d\.\d+\.\d+)",
    },
}
PATH_CH = re.compile(rb"[A-Za-z0-9_./\\-]")


def expand_path(data, s, e):
    """字面標記的位置 → 前後各最多 PATH_CONTEXT 個路徑字元的字串（只作證據；不影響命中數）。"""
    a = s
    while a > 0 and s - a < PATH_CONTEXT and PATH_CH.match(data, a - 1):
        a -= 1
    b = e
    while b < len(data) and b - e < PATH_CONTEXT and PATH_CH.match(data, b):
        b += 1
    return data[a:b].decode("latin-1")


COMPILED = {k: [(kind, re.compile(p)) for kind, p in v["patterns"]] for k, v in FINGERPRINTS.items()}
VERSION_RE = {k: re.compile(v["version"]) for k, v in FINGERPRINTS.items() if v.get("version")}

# ---------------------------------------------------------------- UEFI PI 常數
FFS2 = bytes.fromhex("78e58c8c3d8a1c4f9935896185c32dd3")
FFS3 = bytes.fromhex("7ac07354cb3dca4dbd6f1e9689e7349a")
GUID_LZMA = bytes.fromhex("98584eee14395942" "9d6edc7bd79403cf")           # EE4E5898-3914-4259-9D6E-DC7BD79403CF
GUID_LZMA_X86 = bytes.fromhex("bde62ad45213fb4b" "909aca72a6eae889")       # D42AE6BD-1352-4BFB-909A-CA72A6EAE889
GUID_CRC32 = bytes.fromhex("b0cd1bfc317daa49" "936aa4600d9dd083")          # FC1BCDB0-7D31-49AA-936A-A4600D9DD083
FILE_TYPES = {0x01: "RAW", 0x02: "FREEFORM", 0x03: "SECURITY_CORE", 0x04: "PEI_CORE", 0x05: "DXE_CORE", 0x06: "PEIM", 0x07: "DRIVER",
              0x08: "COMBINED_PEIM_DRIVER", 0x09: "APPLICATION", 0x0A: "MM", 0x0B: "FIRMWARE_VOLUME_IMAGE", 0x0C: "COMBINED_MM_DXE",
              0x0D: "MM_CORE", 0x0E: "MM_STANDALONE", 0x0F: "MM_CORE_STANDALONE", 0xF0: "PAD"}
SEC_COMPRESSION, SEC_GUID_DEFINED, SEC_UI, SEC_FV_IMAGE, SEC_VERSION = 0x01, 0x02, 0x15, 0x17, 0x14
SEC_NAMES = {0x10: "PE32", 0x11: "PIC", 0x12: "TE", 0x13: "DXE_DEPEX", 0x14: "VERSION", 0x15: "UI", 0x16: "COMPAT16", 0x18: "FREEFORM_SUBTYPE_GUID",
             0x19: "RAW", 0x1B: "PEI_DEPEX", 0x1C: "MM_DEPEX"}


class Stop(Exception):
    """整體限制（檔案數、總解開量）到了：停止，結果標為未完整。"""


def guid_str(b):
    return "%08X-%04X-%04X-%s-%s" % (struct.unpack_from("<IHH", b, 0) + (b[8:10].hex().upper(), b[10:16].hex().upper()))


class Scan:
    def __init__(self):
        self.hits = {k: {"strings": 0, "paths": 0, "distinct": set(), "paths_seen": set(), "versions": set(), "by_module": {}} for k in FINGERPRINTS}
        self.modules, self.layers, self.undecoded, self.notes = [], [], [], []
        self.total = 0
        self.files = 0
        self.fvs = 0
        self.fv_bytes = 0
        self.parse_errors = 0
        self.outside_bytes = 0
        self.outside_nonblank = 0

    def scan_bytes(self, data, module=None):
        for lib, pats in COMPILED.items():
            h = self.hits[lib]
            for kind, rx in pats:
                for m in rx.finditer(data):
                    s = m.group()[:200].decode("latin-1") if kind == "string" else expand_path(data, m.start(), m.end())
                    if kind == "string":
                        h["strings"] += 1
                        h["distinct"].add(s)
                    else:
                        h["paths"] += 1
                        h["paths_seen"].add(s)
                    h["by_module"][module or "?"] = h["by_module"].get(module or "?", 0) + 1
            v = VERSION_RE.get(lib)
            if v:
                h["versions"].update(x.decode("latin-1") for x in v.findall(data))

    def undec(self, where, reason):
        self.undecoded.append({"where": where, "reason": reason})


def lzma_decode(buf, sc, where):
    """LZMA-alone 串流 → 位元組或 None（原因記在 sc.undecoded）。宣告大小與限制先檢查，再用 max_length 解開。"""
    if len(buf) < 13:
        sc.undec(where, "LZMA stream shorter than its 13-byte header")
        return None
    size = int.from_bytes(buf[5:13], "little")
    unknown = size == (1 << 64) - 1
    room = min(MAX_LAYER, MAX_TOTAL - sc.total)
    if (not unknown and size > room) or room <= 0:
        sc.undec(where, f"declared decompressed size {size} exceeds the limit (layer {MAX_LAYER}, remaining total {max(room, 0)})")
        return None
    want = room if unknown else size
    try:
        d = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE, memlimit=MAX_LAYER * 2)
        out = d.decompress(bytes(buf), max_length=want)
    except (lzma.LZMAError, MemoryError, ValueError) as e:
        sc.undec(where, f"LZMA decode failed ({type(e).__name__})")
        return None
    if (unknown and not d.eof) or (not unknown and len(out) != size):
        sc.undec(where, f"LZMA stream ended early or is larger than declared (got {len(out)} of {size if not unknown else 'unknown'})")
        return None
    sc.total += len(out)
    return out


def parse_sections(buf, sc, depth, ctx, where):
    """buf 是一串 section → True（整串結構正確）或 False（結構錯：呼叫端把整塊當原始內容掃）。ctx：{"ui": 名稱 list}。"""
    pos, n = 0, len(buf)
    ok = True
    while pos + 4 <= n:
        size = buf[pos] | buf[pos + 1] << 8 | buf[pos + 2] << 16
        typ = buf[pos + 3]
        hdr = 4
        if size == 0xFFFFFF:
            if pos + 8 > n:
                return False
            size, hdr = struct.unpack_from("<I", buf, pos + 4)[0], 8
        if size < hdr or pos + size > n:
            return False
        body = buf[pos + hdr:pos + size]
        sw = f"{where}/sec@{pos:#x}"
        if typ == SEC_COMPRESSION:
            if len(body) < 5:
                ok = False
            elif body[4] == 0:
                ok = parse_sections(body[5:], sc, depth, ctx, sw) and ok
            else:
                sc.undec(sw, f"compression section type {body[4]} (EFI_STANDARD_COMPRESSION) is not supported")
                sc.scan_bytes(bytes(body[5:]), ctx["name"])      # 解不開的內容仍掃（只會增加命中，不會證明沒有）
        elif typ == SEC_GUID_DEFINED:
            ok = guid_defined(body, hdr, sc, depth, ctx, sw) and ok
        elif typ == SEC_FV_IMAGE:
            if depth + 1 > MAX_DEPTH:
                sc.undec(sw, f"nested FV deeper than {MAX_DEPTH}")
            else:
                parse_fvs(bytes(body), sc, depth + 1, sw)
        elif typ == SEC_UI:
            name = bytes(body).decode("utf-16le", "replace").rstrip("\x00")[:200]
            ctx["ui"].append(name)
            ctx["name"] = name or ctx["name"]
            sc.scan_bytes(name.encode("ascii", "replace"), ctx["name"])
        elif typ == SEC_VERSION:
            sc.scan_bytes(bytes(body), ctx["name"])
        else:
            sc.scan_bytes(bytes(body), ctx["name"])
        nxt = (pos + size + 3) & ~3
        if nxt > pos + size and not blank(buf[pos + size:min(nxt, n)]):
            sc.notes.append(f"{sw}: non-blank alignment bytes after the section")
            ok = False
        pos = nxt
    if pos < n and not blank(buf[pos:]):
        sc.notes.append(f"{where}: {n - pos} trailing non-blank bytes after the last section")
        sc.scan_bytes(bytes(buf[pos:]), ctx["name"])
        ok = False
    return ok


def guid_defined(body, hdr, sc, depth, ctx, where):
    if len(body) < 20:
        return False
    guid = bytes(body[:16])
    off, attr = struct.unpack_from("<HH", body, 16)
    if off < hdr + 20 or off - hdr > len(body):      # DataOffset 從 section 標頭起算
        return False
    data = body[off - hdr:]
    if guid in (GUID_LZMA, GUID_LZMA_X86):
        if depth + 1 > MAX_DEPTH:
            sc.undec(where, f"compressed layer deeper than {MAX_DEPTH}")
            return True
        out = lzma_decode(data, sc, where + f" lzma[{guid_str(guid)}]")
        if out is None:
            return True            # 已記為未解開
        sc.layers.append({"where": where, "kind": "lzma" + ("+x86" if guid == GUID_LZMA_X86 else ""), "compressed": len(data), "size": len(out), "depth": depth + 1})
        if not parse_sections(out, sc, depth + 1, ctx, where + ">lzma"):
            # 解開的內容不是 section 串：整塊當原始內容掃（結構不明，但內容有被掃到）
            sc.notes.append(f"{where}: decompressed data is not a section stream; scanned as raw bytes")
            sc.scan_bytes(out, ctx["name"])
        return True
    if guid == GUID_CRC32:
        return parse_sections(data, sc, depth, ctx, where + ">crc32")
    if attr & 0x01:          # PROCESSING_REQUIRED 但不認得的 GUID（加密、簽章…）
        sc.undec(where, f"GUID-defined section {guid_str(guid)} needs processing that is not supported")
        sc.scan_bytes(bytes(data), ctx["name"])
        return True
    return parse_sections(data, sc, depth, ctx, where + ">guid")


def parse_ffs(buf, start, end, sc, depth, where):
    """FV 內 [start,end) 的 FFS 檔。結構有問題的地方都記成未解開（sc.undecoded）：header 不合理、結束標記之後還有非空白內容、
    PAD 檔有非空白內容。這些位元組仍會當原始內容掃一次（只會增加命中，不會證明沒有）。"""
    pos = (start + 7) & ~7
    while pos + 24 <= end:
        hdr = buf[pos:pos + 24]
        fw = f"{where}/ffs@{pos:#x}"
        if hdr == b"\xff" * 24 or hdr == b"\x00" * 24:
            if not blank(buf[pos:end]):
                sc.undec(fw, "non-blank bytes after the end-of-files marker (an empty 24-byte header) were not parsed")
                sc.scan_bytes(bytes(buf[pos:end]), "outside-ffs")
            return
        guid, ftype, attr = bytes(hdr[:16]), hdr[18], hdr[19]
        size = hdr[20] | hdr[21] << 8 | hdr[22] << 16
        hl = 24
        if attr & 0x01:
            if pos + 32 > end:
                sc.parse_errors += 1
                sc.undec(fw, "FFS large-file header runs past the end of the volume")
                sc.scan_bytes(bytes(buf[pos:end]), "outside-ffs")
                return
            size, hl = struct.unpack_from("<Q", buf, pos + 24)[0], 32
        if size < hl or pos + size > end:
            sc.parse_errors += 1
            sc.undec(fw, f"FFS file header has an impossible size ({size})")
            sc.scan_bytes(bytes(buf[pos:end]), "outside-ffs")
            return
        sc.files += 1
        if sc.files > MAX_FILES:
            raise Stop(f"more than {MAX_FILES} FFS files")
        body = buf[pos + hl:pos + size]
        ctx = {"ui": [], "name": guid_str(guid)}
        if ftype == 0xF0:
            if not blank(body):
                sc.undec(fw, "PAD file has non-blank content")
                sc.scan_bytes(bytes(body), ctx["name"])
        else:
            if not parse_sections(body, sc, depth, ctx, fw):
                sc.notes.append(f"{fw}: file body is not a clean section stream; scanned as raw bytes")
                sc.scan_bytes(bytes(body), ctx["name"])
            if len(sc.modules) < MAX_MODULES_LISTED:
                sc.modules.append({"guid": guid_str(guid), "type": FILE_TYPES.get(ftype, f"0x{ftype:02x}"), "ui_name": ctx["ui"][0] if ctx["ui"] else None,
                                   "size": size, "depth": depth})
        pos = (pos + size + 7) & ~7
    if pos < end and not blank(buf[pos:end]):
        sc.undec(f"{where}/ffs@{pos:#x}", "bytes after the last file are too short for a file header and not blank")
        sc.scan_bytes(bytes(buf[pos:end]), "outside-ffs")


def parse_fvs(data, sc, depth, where="image"):
    """data 裡所有 FV（找 _FVH 簽章、檢查標頭）→ 回傳 [(起, 止)]。FV 以外的位元組（每一層，包含嵌套的 FV 與 LZMA 解開後的 FV）都掃成原始內容；
    有非空白內容就記成未解開（可能是沒解析的容器）。沒有任何合法 FV 的地方（FV image section 的 _FVH 壞掉）也記成未解開。"""
    spans, pos = [], 0
    for m in re.finditer(rb"_FVH", data):
        o = m.start() - 40
        if o < pos or o < 0 or o + 56 > len(data):
            continue
        fvlen = struct.unpack_from("<Q", data, o + 32)[0]
        hlen = struct.unpack_from("<H", data, o + 48)[0]
        fsguid = bytes(data[o + 16:o + 32])
        if fsguid not in (FFS2, FFS3):
            continue
        if hlen < 56 or hlen > fvlen or o + fvlen > len(data) or fvlen > MAX_LAYER:
            sc.undec(f"{where}/fv@{o:#x}", f"FV header is inconsistent (length {fvlen}, header {hlen})")
            continue
        sc.fvs += 1
        sc.fv_bytes += fvlen
        spans.append((o, o + fvlen))
        pos = o + fvlen
        ext = struct.unpack_from("<H", data, o + 52)[0]
        start = o + hlen
        if ext and o + ext + 20 <= o + fvlen:
            extsz = struct.unpack_from("<I", data, o + ext + 16)[0]
            start = max(start, o + ext + extsz)
        parse_ffs(data, start, o + fvlen, sc, depth, f"{where}/fv@{o:#x}")
    cur, outside, nonblank = 0, 0, 0
    for a, b in spans + [(len(data), len(data))]:
        if a > cur:
            seg = data[cur:a]
            outside += len(seg)
            sc.scan_bytes(bytes(seg), "outside-fv")
            if not blank(seg):
                nonblank += len(seg)
        cur = max(cur, b)
    if nonblank:
        sc.undec(where, f"{nonblank} bytes outside any valid firmware volume are not blank and were scanned only as raw bytes")
    if not spans and depth > 0:
        sc.undec(where, "no valid firmware volume found in a nested FV image")
    sc.outside_bytes += outside
    sc.outside_nonblank += nonblank
    return spans


def blank(b):
    return not b.strip(b"\xff\x00")


def lzma_candidates(data):
    """標頭掃描用：LZMA-alone 串流的可能起點（props 0x5d、字典大小 2 的次方、解開大小合理）。"""
    for m in re.finditer(rb"\x5d...\x00", data, re.S):
        o = m.start()
        if o + 13 > len(data):
            continue
        dsz = struct.unpack_from("<I", data, o + 1)[0]
        size = int.from_bytes(data[o + 5:o + 13], "little")
        if dsz and dsz & (dsz - 1) == 0 and (1024 <= size <= MAX_LAYER or size == (1 << 64) - 1):
            yield o


def header_scan(data, sc, depth=0, seen=None, where="image"):
    seen = seen if seen is not None else set()
    sc.scan_bytes(data, where)
    if depth >= MAX_DEPTH:
        return
    for o in lzma_candidates(data):
        key = (depth, o)
        if key in seen:
            continue
        seen.add(key)
        w = f"{where}>lzma@{o:#x}"
        n0 = len(sc.undecoded)
        out = lzma_decode(data[o:], sc, w)
        if out is None:
            del sc.undecoded[n0:]      # 候選位置不一定真的是串流；解不開不記（反正 header_scan 本來就不給 absent）
            continue
        sc.layers.append({"where": w, "kind": "lzma", "compressed": None, "size": len(out), "depth": depth + 1})
        header_scan(out, sc, depth + 1, seen, w)


def lib_results(sc, complete, corroboration=None):
    out = {}
    names = {m["guid"]: m["ui_name"] for m in sc.modules if m.get("ui_name")}
    for lib, h in sc.hits.items():
        nd, npth = len(h["distinct"]), len(h["paths_seen"])
        total = h["strings"] + h["paths"]
        if nd >= PRESENT_MIN_STRINGS or npth >= PRESENT_MIN_PATHS:
            res, why = "present", f"{nd} distinct library strings and {npth} build paths found in the decoded image"
        elif total == 0 and complete and FINGERPRINTS[lib].get("weak") and not (corroboration or {}).get(lib, {}).get("ok"):
            c = (corroboration or {}).get(lib) or {}
            res, why = "not_assessed", ("the image was fully decoded and no pattern matched, but the markers of this library are weak (a stripped release "
                                        "build leaves few strings), so absence needs corroboration from the platform DSC, which is missing: "
                                        + (c.get("reason") or "no platform DSC was given"))
        elif total == 0 and complete:
            res, why = "absent", "the image was fully decoded and no pattern of this library matched" + (
                "; corroborated by the platform DSC" if FINGERPRINTS[lib].get("weak") else "")
        elif total == 0:
            res, why = "not_assessed", "no match, but the image was not fully decoded (see undecoded / method)"
        else:
            res, why = "not_assessed", f"only weak evidence ({nd} distinct strings, {npth} paths), below the threshold for present"
        out[lib] = {"result": res, "reason": why, "strings": h["strings"], "distinct_strings": nd, "paths": h["paths"],
                    "distinct_paths": npth, "string_examples": sorted(h["distinct"])[:MAX_EXAMPLES], "path_examples": sorted(h["paths_seen"])[:MAX_EXAMPLES],
                    "versions_seen": sorted(h["versions"])[:5],
                    **({"corroboration": (corroboration or {}).get(lib)} if (corroboration or {}).get(lib) else {}),
                    "top_modules": [names.get(m, m) for m, _ in sorted(h["by_module"].items(), key=lambda x: -x[1])[:5]]}
    return out


def analyze(data, corroboration=None):
    """一個映像的位元組 → 結果 dict。永遠回傳，不丟例外。
    complete＝解析成功、沒有任何未解開的地方（undecoded）、也沒有結構警告（notes）；缺任何一項都不是 complete（absent 不成立）。
    corroboration：{函式庫: {"ok", "reason", "evidence", ...}}（corroborate() 的結果）；weak 的函式庫要 ok 才能給 absent。"""
    sc = Scan()
    method, err, outside_info = "fv_parse", None, None
    try:
        spans = parse_fvs(data, sc, 0)
        if not spans or sc.parse_errors:
            raise ValueError("no valid firmware volume" if not spans else "FFS parse error")
        outside_info = {"bytes": sc.outside_bytes, "nonblank_bytes": sc.outside_nonblank}
    except Stop as e:
        err = str(e)
        sc.undec("image", f"limit reached: {e}")
    except Exception as e:      # noqa: BLE001 — 輸入是不可信資料：任何例外都退回標頭掃描，不能讓檢查整個失敗
        err = f"{type(e).__name__}: {e}"
        sc2 = Scan()
        try:
            header_scan(data, sc2)
        except Exception as e2:      # noqa: BLE001
            sc2.undec("image", f"header scan failed ({type(e2).__name__})")
        sc, method = sc2, "header_scan"
        sc.notes.append(f"FV parsing failed ({err}); fell back to the header scan, which cannot prove that everything was decoded")
    complete = method == "fv_parse" and err is None and not sc.undecoded and not sc.notes
    return {"schema": SCHEMA, "method": method, "complete": complete, "parse_error": err, "fvs": sc.fvs, "ffs_files": sc.files,
            "decompressed_total": sc.total, "layers": sc.layers[:200], "undecoded": sc.undecoded[:50], "notes": sc.notes[:20],
            "modules": sc.modules, "modules_count": len(sc.modules), "outside_fv": outside_info,
            "limits": {"max_depth": MAX_DEPTH, "max_layer": MAX_LAYER, "max_total": MAX_TOTAL, "max_files": MAX_FILES},
            "libraries": lib_results(sc, complete, corroboration)}


def _load(name, path):
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def read_config_defines(files):
    """Kconfig 的 .config／config.dsc.inc（CONFIG_X=值 的行）→ ({名稱: 值}, 讀到的檔案, 讀不到的原因)。沒列出的 CONFIG_ 符號視為沒定義。"""
    d, ok, bad = {}, [], []
    for f in files:
        try:
            with open(f, "rb") as fh:
                txt = fh.read(4 << 20).decode("utf-8", "replace")
        except OSError as e:
            bad.append(f"{f}: {type(e).__name__}")
            continue
        ok.append(str(f))
        for ln in txt.splitlines():
            m = re.match(r"^(CONFIG_[A-Za-z0-9_]+)=(.*)$", ln.strip())
            if m:
                d[m.group(1)] = m.group(2).strip().replace('"', "").replace("'", "")
    return d, ok, bad


def corroborate(tree_path, dsc_rels, defines_files=()):
    """平台 DSC 佐證：weak 的函式庫（字串可能被去光）只有在 DSC 把函式庫類別對應到「另一種實作」時，才允許 absent。
    回傳 {函式庫: {"ok", "reason", "dsc", "evidence", ...}}。條件（每個函式庫、每份 DSC 都要成立）：
      1. uefi_dsc 的分析沒有走到這個函式庫的任何 INF（包含 maybe 的行），而且沒有任何函式庫類別對應（active 或 maybe）指到它；
      2. 至少一個 active 的函式庫類別對應指到另一種實作（FINGERPRINTS[...]["alt_markers"]）。
    沒有給 DSC、讀不到、分析失敗 → ok False 並說明原因（不丟例外）。證據是 檔案:行 的對應（product-a：OpensslLib|…/OpensslLibFull.inf 等）。"""
    out = {}
    here = Path(__file__).resolve().parent
    if not dsc_rels:
        return {k: {"ok": False, "reason": "no platform DSC was given (--platform-dsc) or found from a build log", "dsc": [], "evidence": []}
                for k in FINGERPRINTS if FINGERPRINTS[k].get("weak")}
    try:
        us = _load("sca_center_uefi_source_for_image", here / "uefi_source.py")
        dscm = _load("sca_center_uefi_dsc_for_image", here / "uefi_dsc.py")
        tree = us.Tree(str(tree_path))
        defs, defs_ok, defs_bad = read_config_defines(defines_files)
        ana = dscm.analyze(tree, list(dsc_rels), defs, False, bool(defs_ok))
    except Exception as e:      # noqa: BLE001
        return {k: {"ok": False, "reason": f"the platform DSC could not be analysed ({type(e).__name__})", "dsc": list(dsc_rels), "evidence": []}
                for k in FINGERPRINTS if FINGERPRINTS[k].get("weak")}
    maps = ana.get("class_mappings") or []
    for lib, fp in FINGERPRINTS.items():
        if not fp.get("weak"):
            continue
        mine = [m.lower() for m in fp["dsc_markers"]]
        alt = [m.lower() for m in fp["alt_markers"]]
        blocking = list(ana.get("blocking_problems") or [])
        inf_problems = []
        for x in (ana.get("missing_inf") or []):       # uefi_dsc 的訊息是中文：轉成英文的「INF（在哪一行被用到）」
            m = re.match(r"^(\S+?:\d+): (\S+\.inf)", str(x))
            inf_problems.append(f"{m.group(2)} (named at {m.group(1)})" if m else "an INF file that could not be read")
        e = {"ok": False, "reason": "", "dsc": list(dsc_rels), "evidence": [], "defines_files": [Path(f).parent.name + "/" + Path(f).name for f in defs_ok], "defines_files_unreadable": defs_bad,
             "config_complete": bool(ana.get("config_complete")), "unresolved_includes": [str(b)[:300] for b in blocking[:5]],
             "unresolved_includes_count": len(blocking), "missing_inf_count": len(inf_problems), "missing_inf_first": [x[:200] for x in inf_problems[:3]]}
        lib_state = (ana.get("libs") or {}).get(lib) or {}
        to_mine = [m for m in maps if any(k in ("/" + m["path"]).lower() for k in mine) or any(k.strip("/") in m["class"].lower() for k in mine)]
        to_alt = [m for m in maps if m.get("active") is True and any(k in ("/" + m["path"]).lower() for k in alt)]
        if not ana.get("files_read"):
            e["reason"] = "the platform DSC could not be read"
        elif blocking:
            e["reason"] = (f"{len(blocking)} unresolved include/read item(s) in the platform DSC could hide a library class mapping to {fp['label']} "
                           f"(first: {blocking[0]})")
        elif lib_state.get("state") == "yes" or lib_state.get("reached"):
            e["reason"] = f"the platform DSC reaches {fp['label']} ({'; '.join(lib_state.get('evidence') or [])[:300]})"
        elif to_mine:
            e["reason"] = f"a library class mapping points to {fp['label']}: {to_mine[0]['file']}:{to_mine[0]['line']} {to_mine[0]['class']}|{to_mine[0]['path']}"
        elif not to_alt:
            e["reason"] = "no active library class mapping in the platform DSC points to the other implementation"
        else:
            e["ok"] = True
            e["reason"] = f"the platform DSC maps the crypto library classes to the other implementation and never to {fp['label']}"
            e["evidence"] = [f"{m['file']}:{m['line']}: {m['class']}|{m['path']}" for m in to_alt[:4]] + \
                [f"{m['file']}:{m['line']}: {m['class']}|{m['path']}" for m in maps if m["class"] in ("BaseCryptLib", "TlsLib") and m.get("active") is True][:4]
        out[lib] = e
    return out


def combine(images):
    """多個映像的結果（analyze 的輸出，含 "path"）→ 每個函式庫的總結：所有映像都 absent → absent；有 present → present；其他 not_assessed。
    沒有映像 → 空。注意：只要有任何映像是 present，這個函式庫在產品裡就是有編進去的映像（出貨的其中一個）。"""
    out = {}
    for lib in FINGERPRINTS:
        rs = [(i.get("path"), (i.get("libraries") or {}).get(lib, {}).get("result", "not_assessed")) for i in images]
        if not rs:
            continue
        vals = {r for _, r in rs}
        res = "present" if "present" in vals else "absent" if vals == {"absent"} else "not_assessed"
        out[lib] = {"result": res, "images": len(rs), "present_in": [p for p, r in rs if r == "present"],
                    "not_assessed_in": [p for p, r in rs if r == "not_assessed"]}
    return out


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print(__doc__)
        return 64
    for p in argv:
        with open(p, "rb") as f:
            r = analyze(f.read(MAX_LAYER + 1))
        r["modules"] = r["modules"][:20]
        print(p)
        print(json.dumps(r, indent=1, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
