#!/usr/bin/env python3
"""AMI Aptio V 核心版本：從 BIOS 映像的 Firmware ID 紀錄（簽章字串 `$FID`）讀 Core Major／Core Minor（純函式，只用標準函式庫，不碰檔案）。

**結構沒有 AMI 的公開文件。** 這裡的欄位位置只從公開映像（廠商公開下載的 BIOS 更新檔）反推，沒有複製任何程式碼，沒有用非公開或外洩的 AMI 資料；
依據、各欄位的觀察與限制見 docs/notes/c2-ami-core.md。值是映像自己宣告的欄位，沒有簽章驗證（同 D-050 的 PSP 條目版本）：映像被改過，這裡讀不出來。

## 紀錄結構（偏移從 `$FID` 的 `$` 起算；全部是從樣本推出來的，不是規格）
  +0   4   `$FID`
  +4   1   結構版本：只見過 0x04；不是 4 → 不認得
  +5   2   u16 小端，標準部分的長度：只見過 120（0x78）；不是 120 → 不認得
  +7   9   BIOS tag：1～8 個可列印 ASCII，後面補 NUL 到 9 位元組
  +16  16  用途不明，不使用
  +32  3×4 Core Major、Core Minor、Project Major、Project Minor：每個是兩位 ASCII 數字加 NUL（`30 35 00` ＝ "05"）
  +44  7   建置時間：u16 年（小端）、月、日、時、分、秒（只在值合理時才採用，否則不報日期）
紀錄前面一定有下列兩種前導之一（程式碼模組裡當比對常數用的 `$FID` 位元組前面沒有，靠這個濾掉）：
  - FFS 形式：前 16 位元組是 FREEFORM_SUBTYPE_GUID section 的子類型 GUID 2EBE0275-6458-4AF9-91ED-D3F4EDB100AA
  - FIDT 形式：前 36 位元組是 ACPI 表頭，簽章 `FIDT`、表長（u32 小端，+4）在 156～4096

GUID 的名稱只參考公開工具的 GUID 清單，只取名稱，沒有複製程式碼：`Fid`（3FD1D3A2-…）見 9elements/converged-security-suite 的 `pkg/uefi/ffs/consts/guid.go`（BSD-3-Clause）；`SignOn`（2EBE0275-…）見 fwupd 的 `libfwupdplugin/fu-efi-section.c`（LGPL-2.1-or-later）。

## 結果狀態（summarize 的 status）
  read            至少一份通過結構檢查的紀錄，所有紀錄的 Core 相同
  not-found       沒有任何帶前導的 `$FID`（沒找到不代表不存在；完整與否看 complete）
  conflict        通過結構檢查的紀錄之間 Core 不同：不挑一個值、不給版本
  layout-unknown  有帶前導的 `$FID`，但沒有任何一份通過結構檢查（結構版本、長度、tag、版本欄位不合或被截斷）
  not-searched    沒有走訪 UEFI 內容

Core Major 不是 5 時有版本但沒有 product（產品不確定，不寫產品名）。核心版本 `5.17` 與公告寫法 `AptioV_5.017` 的對應（A1）沒有 AMI 或板廠的明文，
所以衍生的公告寫法固定標明是推導；同一個 major 內次版號隨發行遞增（A2）也沒有明文。
"""
import hashlib
import re
import struct

SUBTYPE_GUID = bytes.fromhex("7502be2e5864f94a91edd3f4edb100aa")      # 2EBE0275-6458-4AF9-91ED-D3F4EDB100AA 的 GUID bytes（小端）
FID_MAGIC = b"$FID"
REC_REV = 4
REC_LEN = 120
FIDT_MAGIC = b"FIDT"
ACPI_HDR = 36
FIDT_MIN_LEN = ACPI_HDR + REC_LEN
FIDT_MAX_LEN = 4096
MAX_PER_BLOCK = 64                    # 一塊內容裡最多看幾個 `$FID`（程式碼模組的常數很少，超過的記 truncated）
MAX_HEAD = 64                         # 結構不合時留給人看的原始位元組數
AMI_VENDOR = "American Megatrends"
PRODUCT_APTIO_V = "Aptio V"
APTIO_V_MAJOR = 5
STATUSES = ("read", "not-found", "conflict", "layout-unknown", "not-searched")
FORMS = ("ffs-section", "fidt-acpi")

TAG_RE = re.compile(rb"([\x21-\x7e][\x20-\x7e]{0,7})\x00*")        # 1～8 個可列印 ASCII（第一個不是空白），其餘補 NUL；整個欄位 9 位元組
VER_RE = re.compile(rb"([0-9]{2})\x00")                            # 兩位 ASCII 數字加 NUL（不用 str.isdigit：全角數字等會被誤收）
ADVISORY_RE = re.compile(r"AptioV_[0-9]\.[0-9]{3}")

BASIS = ("AMI Firmware ID record ($FID): Core Major and Core Minor fields (two ASCII digits each); the layout is inferred from public images, "
         "not from AMI documentation; the value is self-declared by the image (no signature check)")
ADVISORY_FORM_BASIS = ("derived (assumption A1: the three-digit form pads the two-digit FID minor); not stated by AMI; "
                       "assumption A2 (the minor increases with each release inside one major) is not stated by AMI either")
PRODUCT_BASIS = "core major version 5 (AMI advisories name the Aptio V line AptioV_5.xxx); the product is not confirmed by AMI"
CAVEAT = ("the core is AMI's base version and a fix back-ported by the board vendor cannot be seen in the image; "
          "the mapping of the core's notation to the advisory's (A1) is not yet confirmed by AMI or the board vendor; "
          "this is a lead for the responsible unit to compare with the board vendor's advisory, not a vulnerability determination")


def _clean(b):
    return "".join(chr(x) if 0x20 <= x < 0x7f else "?" for x in b)


def _build_date(b):
    """+44 的 7 位元組 → ISO 8601（無時區）；值不合理 → None（不報日期，不影響紀錄是否有效）。"""
    year, mo, d, h, mi, s = struct.unpack("<HBBBBB", b)
    if 1990 <= year <= 2100 and 1 <= mo <= 12 and 1 <= d <= 31 and h < 24 and mi < 60 and s < 60:
        return f"{year:04d}-{mo:02d}-{d:02d}T{h:02d}:{mi:02d}:{s:02d}"
    return None


def parse_record(buf, o):
    """buf[o:o+4] 是 `$FID`，檢查結構 → {"ok": True, tag, core, project, build, sha256} 或 {"ok": False, "why", "head"}。"""
    head = bytes(buf[o:o + MAX_HEAD]).hex()
    if len(buf) - o < REC_LEN:
        return {"ok": False, "why": f"record truncated ({len(buf) - o} bytes available, {REC_LEN} expected)", "head": head}
    rec = bytes(buf[o:o + REC_LEN])
    if rec[4] != REC_REV:
        return {"ok": False, "why": f"structure version 0x{rec[4]:02x} (only 0x{REC_REV:02x} is known)", "head": head}
    size = struct.unpack_from("<H", rec, 5)[0]
    if size != REC_LEN:
        return {"ok": False, "why": f"length field {size} (only {REC_LEN} is known)", "head": head}
    m = TAG_RE.fullmatch(rec[7:16])
    if m is None:
        return {"ok": False, "why": "BIOS tag is not 1-8 printable ASCII characters followed by NUL", "head": head}
    nums = []
    for i in range(4):
        v = VER_RE.fullmatch(rec[32 + 3 * i:35 + 3 * i])
        if v is None:
            return {"ok": False, "why": "version field is not two ASCII digits followed by NUL", "head": head}
        nums.append(int(v.group(1)))
    return {"ok": True, "tag": m.group(1).decode("ascii"), "core": [nums[0], nums[1]], "project": [nums[2], nums[3]],
            "build": _build_date(rec[44:51]), "sha256": hashlib.sha256(rec).hexdigest()}


def find_fid(body, module=None):
    """一塊內容（葉節點內容）→ 帶前導的 `$FID` 候選清單：
    [{"form", "offset", "module", "ok", ...parse_record 的欄位}]；`$FID` 前面沒有前導（程式碼裡的常數）的不列。
    FIDT 前導的表長不在範圍內也列成不合的候選（ok False）。一塊內容最多看 MAX_PER_BLOCK 個 `$FID`，超過時最後一筆是 {"truncated": True}。"""
    out = []
    n = 0
    pos = body.find(FID_MAGIC)
    while pos != -1:
        n += 1
        if n > MAX_PER_BLOCK:
            out.append({"truncated": True, "offset": pos, "module": module})
            break
        form = None
        if pos >= len(SUBTYPE_GUID) and body[pos - len(SUBTYPE_GUID):pos] == SUBTYPE_GUID:
            form = "ffs-section"
        elif pos >= ACPI_HDR and body[pos - ACPI_HDR:pos - ACPI_HDR + 4] == FIDT_MAGIC:
            form = "fidt-acpi"
        if form is not None:
            rec = parse_record(body, pos)
            if rec["ok"] and form == "fidt-acpi":
                tlen = struct.unpack_from("<I", body, pos - ACPI_HDR + 4)[0]
                if not FIDT_MIN_LEN <= tlen <= FIDT_MAX_LEN:
                    rec = {"ok": False, "why": f"FIDT table length {tlen} is outside {FIDT_MIN_LEN}-{FIDT_MAX_LEN}", "head": bytes(body[pos:pos + MAX_HEAD]).hex()}
            out.append({"form": form, "offset": pos, "module": module, **rec})
        pos = body.find(FID_MAGIC, pos + 1)
    return out


def entry_key(c):
    """候選 → 去重的鍵（同一份紀錄、同一種形式合成一個項目；位置另記）。"""
    if c["ok"]:
        return ("ok", c["sha256"], c["form"])
    return ("bad", hashlib.sha256((c["why"] + c["head"]).encode()).hexdigest(), c["form"])


def where_text(w):
    return f"{w['module']} {w['form']} +0x{w['offset']:x}"


def not_searched(reason):
    return {"status": "not-searched", "performed": False, "complete": False, "incomplete": [reason], "reason": reason, "count": 0, "found": [],
            "valid": 0, "invalid": 0, "candidates": [], "bad": [], "gaps": [f"AMI core version (Firmware ID record): not searched ({reason})"]}


def core_text(core):
    return f"{core[0]}.{core[1]}"


def advisory_form(major, minor):
    """核心 (5, 17) → `AptioV_5.017`（A1 的推導；只有 Aptio V）。"""
    if major != APTIO_V_MAJOR:
        return None
    s = f"AptioV_{major}.{minor:03d}"
    return s if ADVISORY_RE.fullmatch(s) else None


def summarize(entries, incomplete=(), truncated=False, max_found=32):
    """項目清單（find_fid 的候選依 entry_key 合併：每項有 "found"＝位置清單 [{module, form, offset}] 與 "seen"＝遇到幾次）→ 結果 dict（可轉 JSON）。
    incomplete：走訪沒走完的原因（空＝所有找到的 firmware volume 都解開了）；truncated：候選數超過上限（不完整）。"""
    inc = list(incomplete) + (["more Firmware ID candidates than the search limit; the rest were not looked at"] if truncated else [])
    valid = [e for e in entries if e["ok"]]
    bad = [e for e in entries if not e["ok"]]
    if valid and bad:           # 有可讀的紀錄，同時有前導正確但結構不合的候選：狀態維持 read，但不能說「所有紀錄都讀到了」；
        # 放在最前面：報告、SBOM 與規則表 basis 只取前 3 個原因，這一項不能被走訪層的原因擠掉
        inc.insert(0, f"{len(bad)} Firmware ID candidate(s) with the expected preamble do not match the known layout ({'; '.join(sorted({e['why'] for e in bad})[:3])})")
    cores = sorted({tuple(e["core"]) for e in valid})
    r = {"performed": True, "complete": not inc, "incomplete": inc, "valid": len(valid), "invalid": len(bad),
         "count": sum(e["seen"] for e in valid), "candidates": [], "bad": [], "found": [], "gaps": []}
    inc_txt = "; ".join(inc[:3])
    if valid and len(cores) == 1:
        r["status"] = "read"
        major, minor = cores[0]
        r["major"], r["minor"] = major, minor
        r["core"] = core_text(cores[0])
        r["core_fid"] = f"{major:02d}.{minor:02d}"
        r["product"] = PRODUCT_APTIO_V if major == APTIO_V_MAJOR else None
        r["advisory_form"] = advisory_form(major, minor)
        r["tags"] = sorted({e["tag"] for e in valid})
        r["projects"] = sorted({f"{e['project'][0]}.{e['project'][1]:02d}" for e in valid})
        r["build_dates"] = sorted({e["build"] for e in valid if e.get("build")})
        r["evidence_sha256"] = sorted({e["sha256"] for e in valid})
        r["forms"] = {f: sum(e["seen"] for e in valid if e["form"] == f) for f in FORMS if any(e["form"] == f for e in valid)}
        r["found"] = list(dict.fromkeys(where_text(w) for e in valid for w in e["found"]))[:max_found]      # 位置相同、內容不同的紀錄只列一次（份數在 count，雜湊在 evidence_sha256）
        if bad:
            r["note"] = (f"{len(bad)} more Firmware ID candidate(s) with the expected preamble did not pass the structure check and were ignored "
                         f"({'; '.join(sorted({e['why'] for e in bad})[:3])})")
        return r
    if valid:
        r["status"] = "conflict"
        r["candidates"] = [{"core": core_text(e["core"]), "tag": e["tag"], "project": f"{e['project'][0]}.{e['project'][1]:02d}",
                            "found": [where_text(w) for w in e["found"]][:4]} for e in sorted(valid, key=lambda x: (x["core"], x["tag"], x["sha256"]))][:16]
        r["gaps"].append("AMI core version (Firmware ID record): the records disagree on the core version "
                         f"({', '.join(core_text(c) for c in cores)}); no value is chosen, no version is reported; candidates are listed in the inventory")
        return r
    if bad:
        r["status"] = "layout-unknown"
        r["bad"] = [{"why": e["why"], "head": e["head"], "form": e["form"], "found": [where_text(w) for w in e["found"]][:4]}
                    for e in sorted(bad, key=lambda x: (x["why"], x["head"]))][:8]
        r["gaps"].append(f"AMI core version (Firmware ID record): {len(bad)} `$FID` candidate(s) with the expected preamble do not match the known layout "
                         f"({'; '.join(sorted({e['why'] for e in bad})[:3])}); first bytes: {bad[0]['head']}")
        return r
    r["status"] = "not-found"
    r["gaps"].append("AMI core version (Firmware ID record): not found in the decoded UEFI content"
                     + (f" ({inc_txt}); not found does not mean absent" if inc else "; a core version may still be recorded somewhere else"))
    return r


def search_text(s):
    """BIOS 映像元件的 sca-center:ami-core-search：狀態加一句說明。"""
    st = s["status"]
    if st == "read":
        # 有可讀的紀錄、同時有結構不合的候選時採用可讀的那份（D-058）：BIOS 層級也寫明，不只在元件與 note
        used = (f"; the readable record(s) were used although {s['invalid']} candidate(s) with the expected preamble do not match the known layout"
                if s.get("invalid") else "")
        return (f"read: core {s['core']} from {s['count']} Firmware ID record(s)" + used + ("" if s["complete"] else "; the search was incomplete: "
                + "; ".join(s["incomplete"][:3])))
    if st == "conflict":
        return "conflict: Firmware ID records disagree on the core version; no value is chosen"
    if st == "layout-unknown":
        return "layout-unknown: `$FID` with the expected preamble found, the layout is not the known one"
    if st == "not-found":
        return "not-found: no Firmware ID record in the decoded UEFI content" + ("" if s["complete"] else "; the search was incomplete, not found does not mean absent")
    return "not-searched: " + s.get("reason", "")
