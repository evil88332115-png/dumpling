#!/usr/bin/env python3
"""韌體 SBOM 的廠商公告規則表比對（離線，CI 不連網）：用 tools/cra/data/fw-advisory-rules.json（schema dumpling-fw-advisory-rules/1）。
一個公告一筆規則（INTEL-SA、AMD-SB、AMI-SA），條件是元件＋版本範圍，出處（官方公告網址與讀取日期）與審核狀態（初審／確認，只記角色）都在規則裡。
格式比照 D-039 的規則庫（tools/cra/vex-rules.example.json：schema、rules[]、id、match、日期）。

這不是漏洞判定：
- 結果只是**建議**（affected／not-affected／NOT_ASSESSED），由負責單位確認；SBOM 的 dumpling:vuln-assessment 維持 NOT_ASSESSED，這個模組不碰它。
- 規則是人從官方公告頁讀出來整理的；表有「最後整理日期」，之後的新公告沒有收錄。
- not-affected 只表示「版本不低於公告列的修正版本」（依據類型 vendor-statement，D-035），不代表沒有其他漏洞（AMI 的公告例外：D-058 第一版不輸出 not-affected，廠商是 AMI 或有 ami_core 條件的規則，任何條件判出的 not-affected 都降成 NOT_ASSESSED）。
- 比不到（沒有規則、版本讀不到、順序不確定、版本線不同…）一律 NOT_ASSESSED：資料庫沒有資料，以廠商公告為準。

元件種類（固定清單 COMPONENTS，每一種有自己的條件欄位與版本比較函式）：
  amd_agesa      family（image 裡 AGESA 字串的名稱，例如 ComboAM4v2PI）、fixed_in、可選 affected_from。AGESA 的版本不能用數字順序比
                 （1.2.0.B < 1.2.0.C < 1.2.0.Ca < 1.2.0.Cb < 1.2.0.Cc < … < 1.2.0.F < 1.2.0.10；ComboAM5PI 的 1.0.0.7a 比 1.0.7.0 晚發佈），
                 所以順序寫在規則表的 orderings[]（每個 family 一份版本序列，每個版本附 AMD 公告列的發佈日期與出處，日期必須嚴格遞增）；
                 fixed_in、affected_from 必須在序列裡；image 的版本不在序列裡 → NOT_ASSESSED（agesa-order-unknown），不猜。
  amd_psp        psp_type（PSP 目錄的 type）、fixed_in（四個十六進位 byte，例如 00.0b.00.17，與 SBOM 的 PSP 版本同格式，逐 byte 比）
  amd_microcode  equiv_id（0x + 4 位十六進位）或 cpuid（8 位十六進位）二選一、fixed_in（patch level，0x + 8 位十六進位，無號整數比）
  intel_csme     line（版本線 major.minor，例如 16.1）、fixed_in（三或四段數字，開頭必須是 line）、可選 affected_from；
                 image 的 major.minor 不是 line → 這條規則不適用（out-of-scope）；family 讀不出來是 CSME 才比（TXE、SPS、ME 不比；矛盾 → NOT_ASSESSED）
  intel_fsp      line（FSP ImageRevision 的前兩段）、fixed_in（四段數字）、可選 affected_from
  ami_core       product、可選 fixed_in（`AptioV_<主>.<三位數次版號>`，例如 AptioV_5.044）；比對輸入是 ami_core.py 從映像的 Firmware ID 紀錄讀到的核心版本（D-058）：
                 核心版本讀不到、結構不合、互相矛盾 → NOT_ASSESSED（no-ami-core-version／ami-fid-layout-unknown／ami-core-conflict）；Core Major 不是 5（沒有產品）→
                 NOT_ASSESSED（ami-product-unknown）；product 不同 → out-of-scope；跨 major 不比 → NOT_ASSESSED（ami-core-line-differs）；
                 核心**低於** fixed_in → affected 建議（preliminary；核心是 AMI 的基底版本，板廠回補的修正看不出來，對應的寫法 A1 尚未確認，這是線索不是判定）；
                 核心**不低於** fixed_in → 一律 NOT_ASSESSED（ami-core-mapping-unverified）：第一版不輸出 not-affected，等 A1 有公開依據再另立決策開放。
                 沒有核心版本資料（只有映像的 AMI 線索）時，只把「可能相關的 AMI 公告」列給負責單位對照，不給建議
  bios_image     name_prefix（映像檔名開頭）、fixed_in（數字或點分數字）；用版本清單宣告的 BIOS 版本比；沒有宣告 → NOT_ASSESSED

單一規則對單一元件的結果（evaluate_condition）：affected｜not-affected｜NOT_ASSESSED｜out-of-scope（條件的 family／line／type／equiv_id／cpuid／檔名與這個元件不同，
不算比對）。整個元件的建議（evaluate）：
  1. 規則表不能用（讀不到、sha256 不符、schema 驗證失敗）→ 所有元件 NOT_ASSESSED（table-unreadable／table-sha-mismatch／table-invalid）；呼叫端要把狀態標 ATTENTION。
  2. 任何一條規則是 affected → affected（rule_ids ＝ 判 affected 的規則）。
  3. 否則有 NOT_ASSESSED（版本讀不到、順序不確定、版本線以外的原因）→ NOT_ASSESSED：有一條讀不懂就不能說 not-affected。
  4. 否則有 not-affected → not-affected。
  5. 否則（沒有任何規則適用）→ NOT_ASSESSED（no-rule；同元件種類的規則都是別的 family／版本線時 no-rule-for-line）：資料庫沒有資料，以廠商公告為準。
review.state ＝ preliminary｜confirmed；元件的 state 由 rule_ids 的規則決定（兩種都有 → preliminary+confirmed）。

規則表的 schema 驗證很嚴：每一層都只收列出的欄位（不認得的欄位整張表拒收）、id 用 fullmatch、元件固定清單、版本格式依元件驗證、日期要是真的日期且前後一致、
sources 的網址要符合廠商官方公告頁的格式而且與 id 對得上、review 的人只寫角色（不收 email 或連結）。任何一條不過 → 整張表 table-invalid，所有元件 NOT_ASSESSED，不會悄悄少算幾筆。
完整性：檔案 sha256 固定在 TABLE_SHA256（理由與流程見 docs/notes/c2-firmware-advisory.md「規則表」）；改規則表一定要同時改這個常數。
"""
import datetime
import hashlib
import json
import re
import sys
import unicodedata
from pathlib import Path

TABLE_PATH = Path(__file__).resolve().parent / "data" / "fw-advisory-rules.json"
# 規則表檔案本身的 sha256（改規則表後要一起更新：python3 tools/cra/fw_advisory_rules.py sha256；tests 會核對）。
# 檔案被改動、截斷、少幾筆規則或換成別的內容時，所有元件一律 NOT_ASSESSED（table-sha-mismatch），報告狀態 ATTENTION。
TABLE_SHA256 = "5d4713308ba9e3962b2e0a99e5ab5ca9f1cab479dc4b1b9fa6bcf34ecb0c56df"
SCHEMA = "dumpling-fw-advisory-rules/1"
MAX_TABLE = 1 << 20
MAX_RULES = 500
MAX_CONDITIONS = 16
COMPONENTS = ("amd_agesa", "amd_psp", "amd_microcode", "intel_csme", "intel_fsp", "ami_core", "bios_image")
SUGGESTIONS = ("affected", "not-affected", "NOT_ASSESSED")
STATES = ("preliminary", "confirmed")
NO_DATA = "no data in the database; the vendor advisory is authoritative"
SUGGESTION_ONLY = "this is a suggestion from a hand-compiled rule table, not a vulnerability assessment; whether the product is affected is decided by the vendor advisory"
# sources[].verification：版本值怎麼讀到的（核對狀態）。direct＝直接下載官方頁面或 PDF 的原文解析；summary-tool＝只經網頁摘要工具讀到（沒有原文、沒有第二個獨立來源，負責單位確認時必須直接對照原頁面）；
# independent:nvd＝除了讀官方頁面，版本門檻另經 NVD 的 CPE 版本範圍核對相符（只涵蓋 NVD 有 Intel CPE 設定的 CVE）。
VERIFICATIONS = ("direct", "summary-tool", "independent:nvd")
VERIFICATION_RANK = {"summary-tool": 0, "independent:nvd": 1, "direct": 2}       # 一條規則有幾個出處時取最弱的
EVIDENCE_TYPE = "vendor-statement"                  # D-035：排除（not-affected）的依據類型
AMI_NO_CORE = "the SBOM has no AMI core version"
AMI_REASONS = {"conflict": ("ami-core-conflict", "the Firmware ID records of the image disagree on the AMI core version; no value is chosen"),
               "layout-unknown": ("ami-fid-layout-unknown", "the image has a Firmware ID ($FID) record whose layout is not the known one; no AMI core version is read")}
AMI_FIXED_RE = re.compile(r"AptioV_([0-9])\.([0-9]{3})")
AMI_INCOMPLETE = ("the image was not fully decoded or has Firmware ID candidates that do not match the known layout ({why}); "
                  "parts that were not decoded may hold records with a different core version")
AMI_CAVEAT = ("the core is AMI's base version, and a fix back-ported by the board vendor cannot be seen in the image; "
              "the mapping of the core's notation to the advisory's (A1) is not yet confirmed by AMI or the board vendor "
              "(A1: the two-digit FID minor equals the last two digits of the three-digit advisory minor), and the order inside one major (A2) is assumed; "
              "this is a lead for the responsible unit to compare with the board vendor's advisory, not a vulnerability determination")

# ── id、廠商、網址（對照官方頁面）────────────────────────────────────────────────────────────────────────────────
# AMD：https://www.amd.com/en/resources/product-security/bulletin/amd-sb-7014.html（編號 4 位數；允許 4～5 位，因為 AMD 的編號沒有公開的位數規定）
# Intel：https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01372.html（INTEL-SA- 加 5 位數）
# AMI：https://www.ami.com/security-advisories/ 列出 AMI-SA-2026003（AMI-SA- 加 4 位西元年與 3 位流水號，共 7 位數），每則連到 PDF
ID_RES = {"AMD": re.compile(r"AMD-SB-[0-9]{4,5}"), "Intel": re.compile(r"INTEL-SA-[0-9]{5}"), "AMI": re.compile(r"AMI-SA-[0-9]{7}")}
URL_RES = {
    "AMD": re.compile(r"https://www\.amd\.com/en/resources/product-security/bulletin/(amd-sb-[0-9]{4,5})\.html"),
    "Intel": re.compile(r"https://www\.intel\.com/content/www/us/en/security-center/advisory/(intel-sa-[0-9]{5})\.html"),
    "AMI": re.compile(r"https://(?:go\.ami\.com|9443417\.fs1\.hubspotusercontent-na1\.net)/hubfs/(?:9443417/)?Security%20Advisories/(?:20[0-9]{2}/)?(AMI-SA-[0-9]{7})\.pdf"),
}
AMI_INDEX_URL = "https://www.ami.com/security-advisories/"
ORDER_URL_RE = re.compile(r"https://www\.amd\.com/en/resources/product-security/bulletin/amd-sb-[0-9]{4,5}\.html")
COMPONENT_VENDORS = {"amd_agesa": "AMD", "amd_psp": "AMD", "amd_microcode": "AMD", "intel_csme": "Intel", "intel_fsp": "Intel", "ami_core": "AMI"}

# ── 版本格式 ────────────────────────────────────────────────────────────────────────────────────────────────────
FAMILY_RE = re.compile(r"[A-Za-z][A-Za-z0-9]{2,31}")
AGESA_VER_RE = re.compile(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9A-Za-z]{1,6}")
AGESA_STR_RE = re.compile(r"([A-Za-z][A-Za-z0-9]{2,31})[ _]+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9A-Za-z]{1,6})")
LINE_RE = re.compile(r"[0-9]{1,3}\.[0-9]{1,3}")
CSME_VER_RE = re.compile(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,4}(?:\.[0-9]{1,6})?")
FSP_VER_RE = re.compile(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,5}\.[0-9]{1,5}")
PSP_VER_RE = re.compile(r"[0-9a-f]{2}(?:\.[0-9a-f]{2}){3}")
EQUIV_RE = re.compile(r"0x[0-9a-f]{4}")
CPUID_RE = re.compile(r"[0-9A-F]{8}")
PATCH_RE = re.compile(r"0x[0-9a-f]{8}")
BIOS_VER_RE = re.compile(r"[0-9]{1,8}(?:\.[0-9]{1,8}){0,3}")
NAME_PREFIX_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
TEXT_RE = re.compile(r"[^\x00-\x1f\x7f\u2028\u2029]{1,200}")
NOTE_RE = re.compile(r"[^\x00-\x1f\x7f\u2028\u2029]{1,600}")
CVE_RE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,7}")
DATE_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
# 角色名稱：只寫角色，不收 email、連結、@ 提及、Markdown 連結語法；允許中文與全形括號
ROLE_RE = re.compile(r"[^\x00-\x1f\x7f\u2028\u2029@<>\[\]()\\`|:/!*_#~$&]{1,80}")


class TableError(Exception):
    def __init__(self, reason, detail):
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


def _bad(where, why):
    raise TableError("table-invalid", f"{where}: {why}")


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _keys(obj, required, optional, where):
    """物件只能有 required＋optional 的欄位；缺必填或多了不認得的欄位都拒收。"""
    if not isinstance(obj, dict):
        _bad(where, "must be an object")
    for k in obj:
        if k not in required and k not in optional:
            _bad(where, f"unknown field {k!r}")
    for k in required:
        if k not in obj:
            _bad(where, f"missing field {k!r}")


def _str(v, rx, where):
    if not isinstance(v, str) or not rx.fullmatch(v):
        _bad(where, "bad format")
    if v.strip() == "" or v != v.strip():
        _bad(where, "must not be empty, whitespace only, or have leading or trailing whitespace")
    if any(unicodedata.category(ch)[0] == "C" or unicodedata.category(ch) in ("Zl", "Zp") for ch in v):
        _bad(where, "control or format characters (including bidi overrides and zero-width) are not allowed")
    return v


def _date(v, where):
    _str(v, DATE_RE, where)
    try:
        d = datetime.date.fromisoformat(v)
    except ValueError:
        _bad(where, "not a real date")
    if not 2000 <= d.year <= 2100:
        _bad(where, "year out of range")
    return d


# ── 版本比較函式（每一種格式一個）──────────────────────────────────────────────────────────────────────────────
def parse_agesa(s):
    """image 的 AGESA 字串 'ComboAM4v2PI 1.2.0.B' → (family, version)；格式不對 → None。family 之間的空白與底線已在字串裡分開。"""
    if not isinstance(s, str):
        return None
    m = AGESA_STR_RE.fullmatch(s.strip())
    return (m.group(1), m.group(2)) if m else None


def agesa_index(sequence, version):
    """版本在序列裡的位置（不分大小寫）；不在序列 → None。"""
    key = version.lower()
    for i, v in enumerate(sequence):
        if v.lower() == key:
            return i
    return None


def agesa_compare(sequence, a, b):
    """用規則表的順序序列比較兩個 AGESA 版本 → -1／0／1；任一個不在序列裡（順序不確定）→ None。"""
    ia, ib = agesa_index(sequence, a), agesa_index(sequence, b)
    if ia is None or ib is None:
        return None
    return (ia > ib) - (ia < ib)


def parse_dotted(s, rx):
    """點分數字版本（CSME、FSP）→ tuple；格式不對 → None。"""
    if not isinstance(s, str) or not rx.fullmatch(s):
        return None
    return tuple(int(x) for x in s.split("."))


def dotted_compare(ver, bound):
    """ver（3～4 段）與 bound（3 或 4 段）比較：只比 bound 有的段數；ver 的段數不夠 → None。"""
    if len(ver) < len(bound):
        return None
    a, b = ver[:len(bound)], bound
    return (a > b) - (a < b)


def parse_psp(s):
    """'00.0b.00.17' → (0x00, 0x0b, 0x00, 0x17)；格式不對 → None。"""
    if not isinstance(s, str) or not PSP_VER_RE.fullmatch(s.lower()):
        return None
    return tuple(int(x, 16) for x in s.split("."))


def parse_hex(s, rx):
    """'0x0800126f' → 整數（大小寫都收，先轉小寫再用 rx 驗證）；格式不對 → None。"""
    if not isinstance(s, str):
        return None
    t = s.lower()
    return int(t, 16) if rx.fullmatch(t) else None


def parse_bios(s):
    """版本清單宣告的 BIOS 版本（'3404'、'1.2.3'）→ tuple；格式不對 → None。"""
    if not isinstance(s, str) or not BIOS_VER_RE.fullmatch(s.strip()):
        return None
    return tuple(int(x) for x in s.strip().split("."))


def tuple_compare(a, b):
    """長度不同的數字 tuple：短的補 0 再比。"""
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a > b) - (a < b)


# ── 載入與驗證 ───────────────────────────────────────────────────────────────────────────────────────────────────
class Table:
    """載入並驗證過的規則表。"""

    def __init__(self, doc, sha256):
        self.doc = doc
        self.sha256 = sha256
        self.updated = doc["table_updated"]
        self.rules = doc["rules"]
        self.orderings = {o["family"].lower(): [v["version"] for v in o["sequence"]] for o in doc["orderings"]}
        self.ordering_names = {o["family"].lower(): o["family"] for o in doc["orderings"]}
        self.by_id = {r["id"]: r for r in self.rules}

    def verification(self, rule_id):
        """一條規則的核對狀態：所有出處裡最弱的一個。"""
        return min((s["verification"] for s in self.by_id[rule_id]["sources"]), key=VERIFICATION_RANK.__getitem__)

    def counts(self):
        c = {s: 0 for s in STATES}
        for r in self.rules:
            c[r["review"]["state"]] += 1
        return c

    def label(self):
        c = self.counts()
        return (f"fw-advisory-rules.json (schema {SCHEMA}; {len(self.rules)} rules: {c['preliminary']} preliminary, {c['confirmed']} confirmed; "
                f"last compiled {self.updated}; table sha256 {self.sha256[:16]}…)")


def _validate_sources(srcs, rule, updated, where):
    if not isinstance(srcs, list) or not 1 <= len(srcs) <= 8:
        _bad(where, "sources must be a list of 1..8 entries")
    seen = set()
    for i, s in enumerate(srcs):
        w = f"{where}[{i}]"
        _keys(s, ("url", "read_at", "verification"), (), w)
        if not isinstance(s["verification"], str) or s["verification"] not in VERIFICATIONS:
            _bad(w + ".verification", "must be one of " + ", ".join(VERIFICATIONS))
        url = s["url"]
        if not isinstance(url, str) or len(url) > 300:
            _bad(w, "url")
        m = URL_RES[rule["vendor"]].fullmatch(url)
        if m:
            if m.group(1).lower() != rule["id"].lower():
                _bad(w, "url does not match the rule id")
        elif not (rule["vendor"] == "AMI" and url == AMI_INDEX_URL):
            _bad(w, "url is not an official advisory page of the vendor")
        if url in seen:
            _bad(w, "duplicate url")
        seen.add(url)
        if _date(s["read_at"], w + ".read_at") > updated:
            _bad(w, "read_at is after table_updated")


def _validate_condition(c, rule, orderings, where):
    if not isinstance(c, dict) or c.get("component") not in COMPONENTS:
        _bad(where, "component must be one of " + ", ".join(COMPONENTS))
    comp = c["component"]
    want = COMPONENT_VENDORS.get(comp)
    if want and want != rule["vendor"]:
        _bad(where, f"component {comp} belongs to a {want} advisory")
    if comp == "amd_agesa":
        _keys(c, ("component", "family", "fixed_in"), ("affected_from", "note"), where)
        fam = _str(c["family"], FAMILY_RE, where + ".family")
        seq = orderings.get(fam.lower())
        if seq is None:
            _bad(where, f"family {fam!r} has no ordering in orderings[]")
        for k in ("fixed_in", "affected_from"):
            if k in c:
                _str(c[k], AGESA_VER_RE, f"{where}.{k}")
                if agesa_index(seq, c[k]) is None:
                    _bad(where, f"{k} {c[k]!r} is not in the ordering of {fam}")
        if "affected_from" in c and agesa_index(seq, c["affected_from"]) > agesa_index(seq, c["fixed_in"]):
            _bad(where, "affected_from is after fixed_in")
    elif comp == "amd_psp":
        _keys(c, ("component", "psp_type", "fixed_in"), ("note",), where)
        if not _is_int(c["psp_type"]) or not 0 <= c["psp_type"] <= 255:
            _bad(where + ".psp_type", "must be an integer 0..255")
        _str(c["fixed_in"], PSP_VER_RE, where + ".fixed_in")
    elif comp == "amd_microcode":
        _keys(c, ("component", "fixed_in"), ("equiv_id", "cpuid", "note"), where)
        if ("equiv_id" in c) == ("cpuid" in c):
            _bad(where, "exactly one of equiv_id, cpuid")
        if "equiv_id" in c:
            _str(c["equiv_id"], EQUIV_RE, where + ".equiv_id")
        else:
            _str(c["cpuid"], CPUID_RE, where + ".cpuid")
        _str(c["fixed_in"], PATCH_RE, where + ".fixed_in")
    elif comp == "intel_csme":
        _keys(c, ("component", "line", "fixed_in"), ("affected_from", "note"), where)
        line = _str(c["line"], LINE_RE, where + ".line")
        for k in ("fixed_in", "affected_from"):
            if k in c:
                _str(c[k], CSME_VER_RE, f"{where}.{k}")
                if not (c[k] + ".").startswith(line + "."):
                    _bad(where, f"{k} does not start with line {line}")
        if "affected_from" in c and parse_dotted(c["affected_from"], CSME_VER_RE) > parse_dotted(c["fixed_in"], CSME_VER_RE):
            _bad(where, "affected_from is after fixed_in")
    elif comp == "intel_fsp":
        _keys(c, ("component", "line", "fixed_in"), ("affected_from", "note"), where)
        line = _str(c["line"], LINE_RE, where + ".line")
        for k in ("fixed_in", "affected_from"):
            if k in c:
                _str(c[k], FSP_VER_RE, f"{where}.{k}")
                if not (c[k] + ".").startswith(line + "."):
                    _bad(where, f"{k} does not start with line {line}")
        if "affected_from" in c and parse_dotted(c["affected_from"], FSP_VER_RE) > parse_dotted(c["fixed_in"], FSP_VER_RE):
            _bad(where, "affected_from is after fixed_in")
    elif comp == "ami_core":
        _keys(c, ("component", "product"), ("fixed_in", "note"), where)
        _str(c["product"], TEXT_RE, where + ".product")
        if "fixed_in" in c:
            _str(c["fixed_in"], AMI_FIXED_RE, where + ".fixed_in")
    else:                                                              # bios_image
        _keys(c, ("component", "name_prefix", "fixed_in"), ("note",), where)
        _str(c["name_prefix"], NAME_PREFIX_RE, where + ".name_prefix")
        _str(c["fixed_in"], BIOS_VER_RE, where + ".fixed_in")
    if "note" in c:
        _str(c["note"], NOTE_RE, where + ".note")


def _validate_review(rv, updated, where):
    _keys(rv, ("state", "preliminary_by", "preliminary_at"), ("confirmed_by", "confirmed_at"), where)
    if rv["state"] not in STATES:
        _bad(where + ".state", "must be preliminary or confirmed")
    _str(rv["preliminary_by"], ROLE_RE, where + ".preliminary_by")
    p = _date(rv["preliminary_at"], where + ".preliminary_at")
    if p > updated:
        _bad(where, "preliminary_at is after table_updated")
    has = ("confirmed_by" in rv, "confirmed_at" in rv)
    if rv["state"] == "preliminary":
        if any(has):
            _bad(where, "a preliminary rule must not have confirmed_by or confirmed_at")
    else:
        if not all(has):
            _bad(where, "a confirmed rule needs confirmed_by and confirmed_at")
        _str(rv["confirmed_by"], ROLE_RE, where + ".confirmed_by")
        c = _date(rv["confirmed_at"], where + ".confirmed_at")
        if c < p or c > updated:
            _bad(where, "confirmed_at must be between preliminary_at and table_updated")


def validate(doc):
    """schema 驗證；任何一條不過就丟 TableError('table-invalid')。型別怪到驗證程式自己出錯（不能雜湊的值、深度過深…）也一律是 TableError，不會是 TypeError。"""
    try:
        _validate(doc)
    except TableError:
        raise
    except (TypeError, ValueError, KeyError, AttributeError, IndexError, RecursionError) as e:
        raise TableError("table-invalid", f"validation failed ({type(e).__name__})")


def _validate(doc):
    _keys(doc, ("schema", "table_updated", "orderings", "rules"), ("$comment",), "table")
    if doc["schema"] != SCHEMA:
        _bad("schema", f"must be {SCHEMA}")
    if "$comment" in doc:
        _str(doc["$comment"], re.compile(r"[^\x00-\x1f\x7f]{1,2000}"), "$comment")
    updated = _date(doc["table_updated"], "table_updated")
    ords = doc["orderings"]
    if not isinstance(ords, list) or len(ords) > 32:
        _bad("orderings", "must be a list")
    if not isinstance(doc["rules"], list):
        _bad("rules", "must be a list")
    orderings, seen = {}, set()
    for i, o in enumerate(ords):
        w = f"orderings[{i}]"
        _keys(o, ("family", "component", "sequence"), (), w)
        fam = _str(o["family"], FAMILY_RE, w + ".family")
        if o["component"] != "amd_agesa":
            _bad(w + ".component", "only amd_agesa has an ordering")
        if fam.lower() in seen:
            _bad(w, "duplicate family")
        seen.add(fam.lower())
        seq = o["sequence"]
        if not isinstance(seq, list) or not 2 <= len(seq) <= 64:
            _bad(w + ".sequence", "must be a list of 2..64 entries")
        prev, vers = None, set()
        for j, e in enumerate(seq):
            ww = f"{w}.sequence[{j}]"
            _keys(e, ("version", "listed", "source"), (), ww)
            v = _str(e["version"], AGESA_VER_RE, ww + ".version")
            if v.lower() in vers:
                _bad(ww, "duplicate version")
            vers.add(v.lower())
            d = _date(e["listed"], ww + ".listed")
            if prev is not None and d <= prev:
                _bad(ww, "release dates must be strictly increasing (the order is taken from the vendor's dates)")
            if d > updated:
                _bad(ww, "listed is after table_updated")
            prev = d
            if not isinstance(e["source"], str) or not ORDER_URL_RE.fullmatch(e["source"]):
                _bad(ww + ".source", "must be an official AMD bulletin url")
        orderings[fam.lower()] = [e["version"] for e in seq]
    rules = doc["rules"]
    if not isinstance(rules, list) or not 1 <= len(rules) <= MAX_RULES:
        _bad("rules", f"must be a list of 1..{MAX_RULES} rules")
    ids = set()
    for i, r in enumerate(rules):
        w = f"rules[{i}]"
        _keys(r, ("id", "vendor", "title", "published", "cves", "sources", "match", "review"), ("revised", "note"), w)
        if not isinstance(r["vendor"], str) or r["vendor"] not in ID_RES:
            _bad(w + ".vendor", "must be one of " + ", ".join(ID_RES))
        if not isinstance(r["id"], str):
            _bad(w + ".id", "bad format")
        _str(r["id"], ID_RES[r["vendor"]], w + ".id")
        if r["id"] in ids:
            _bad(w, "duplicate id")
        ids.add(r["id"])
        _str(r["title"], TEXT_RE, w + ".title")
        pub = _date(r["published"], w + ".published")
        if "revised" in r and not pub <= _date(r["revised"], w + ".revised") <= updated:
            _bad(w, "revised must be between published and table_updated")
        if pub > updated:
            _bad(w, "published is after table_updated")
        if "note" in r:
            _str(r["note"], NOTE_RE, w + ".note")
        cves = r["cves"]
        if not isinstance(cves, list) or len(cves) > 64:
            _bad(w + ".cves", "must be a list of at most 64 distinct CVE ids")
        for c in cves:
            _str(c, CVE_RE, w + ".cves")
        if len(set(cves)) != len(cves):
            _bad(w + ".cves", "must be a list of at most 64 distinct CVE ids")
        _validate_sources(r["sources"], r, updated, w + ".sources")
        m = r["match"]
        if not isinstance(m, list) or not 1 <= len(m) <= MAX_CONDITIONS:
            _bad(w + ".match", f"must be a list of 1..{MAX_CONDITIONS} conditions")
        for j, c in enumerate(m):
            _validate_condition(c, r, orderings, f"{w}.match[{j}]")
        _validate_review(r["review"], updated, w + ".review")
        if r["review"]["state"] == "confirmed" and any(s["verification"] == "summary-tool" for s in r["sources"]):
            _bad(w + ".review", "a confirmed rule must not have a summary-tool source: compare the version values with the vendor page directly first")


def load(path=None, expected_sha256=None):
    """規則表 → Table；讀不到、不是一般檔案、超過上限、sha256 不符、JSON 或 schema 不對 → TableError。expected_sha256 預設用程式裡固定的值。"""
    p = Path(path) if path else TABLE_PATH
    want = TABLE_SHA256 if expected_sha256 is None else expected_sha256
    try:
        if p.is_symlink() or not p.is_file():
            raise TableError("table-unreadable", "not a regular file")
        with open(p, "rb") as fh:
            data = fh.read(MAX_TABLE + 1)
    except OSError as e:
        raise TableError("table-unreadable", type(e).__name__)
    if len(data) > MAX_TABLE:
        raise TableError("table-unreadable", "larger than limit")
    sha = hashlib.sha256(data).hexdigest()
    if sha != want:
        raise TableError("table-sha-mismatch", f"table sha256 {sha[:16]}… differs from the pinned {want[:16]}…")
    try:
        doc = json.loads(data.decode("utf-8"), parse_constant=_no_constant, object_pairs_hook=_no_duplicates)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise TableError("table-unreadable", "not valid JSON")
    try:
        validate(doc)
    except TableError:
        raise
    except Exception as e:                       # 結構奇怪到驗證程式本身出錯：一樣整張拒收
        raise TableError("table-invalid", f"validation failed ({type(e).__name__})")
    return Table(doc, sha)


def _no_duplicates(pairs):
    """重複的鍵（json.loads 預設悄悄取最後一個）一律拒收：不能用重複的欄位把前面的條件蓋掉。"""
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError("duplicate key " + k)
        d[k] = v
    return d


def _no_constant(name):
    raise ValueError(name)                       # NaN、Infinity 不是 JSON


def load_default():
    """→ (Table 或 None, 失敗時的 TableError 或 None)。"""
    try:
        return load(), None
    except TableError as e:
        return None, e


# ── 比對 ────────────────────────────────────────────────────────────────────────────────────────────────────────
def _r(result, reason=None, detail=""):
    return {"result": result, "reason": reason, "detail": detail}


OUT = "out-of-scope"


def cond_agesa(table, c, comp):
    p = parse_agesa(comp.get("value"))
    if p is None:
        return _r("NOT_ASSESSED", "version-unreadable", f"the AGESA string {comp.get('value')!r} is not '<family> <a.b.c.d>'")
    fam, ver = p
    if fam.lower() != c["family"].lower():
        return _r(OUT, "family-mismatch", f"rule covers family {c['family']}, this is {fam}")
    seq = table.orderings[fam.lower()]
    if agesa_index(seq, ver) is None:
        return _r("NOT_ASSESSED", "agesa-order-unknown", f"{fam} {ver} is not in the table's ordering of {c['family']} (not guessed)")
    if "affected_from" in c and agesa_compare(seq, ver, c["affected_from"]) < 0:
        return _r("NOT_ASSESSED", "below-affected-from", f"{fam} {ver} is below the listed affected range start {c['affected_from']}")
    if agesa_compare(seq, ver, c["fixed_in"]) < 0:
        return _r("affected", None, f"{fam} {ver} is below fixed_in {c['fixed_in']} (order from the table's ordering of {c['family']})")
    return _r("not-affected", None, f"{fam} {ver} is not below fixed_in {c['fixed_in']} (order from the table's ordering of {c['family']})")


def cond_dotted(c, comp, rx, label):
    ver = parse_dotted(comp.get("version"), rx)
    if ver is None:
        return _r("NOT_ASSESSED", "version-unreadable", f"the {label} version {comp.get('version')!r} is not a plain dotted number")
    line = tuple(int(x) for x in c["line"].split("."))
    if ver[:2] != line:
        return _r(OUT, "line-mismatch", f"rule covers version line {c['line']}, this is {'.'.join(map(str, ver[:2]))}")
    fixed = parse_dotted(c["fixed_in"], rx)
    cmp_ = dotted_compare(ver, fixed)
    if cmp_ is None:
        return _r("NOT_ASSESSED", "version-too-short", f"the version {comp['version']} has fewer fields than fixed_in {c['fixed_in']}")
    if "affected_from" in c:
        lo = dotted_compare(ver, parse_dotted(c["affected_from"], rx))
        if lo is None:
            return _r("NOT_ASSESSED", "version-too-short", f"the version {comp['version']} has fewer fields than affected_from {c['affected_from']}")
        if lo < 0:
            return _r("NOT_ASSESSED", "below-affected-from", f"{comp['version']} is below the listed affected range start {c['affected_from']}")
    if cmp_ < 0:
        return _r("affected", None, f"{comp['version']} is below fixed_in {c['fixed_in']} (line {c['line']})")
    return _r("not-affected", None, f"{comp['version']} is not below fixed_in {c['fixed_in']} (line {c['line']})")


def cond_csme(c, comp):
    """CSME：映像分不出 CSME／TXE／SPS（x86_firmware 的 family）。family 是 CSME（版本清單寫明，listed）或由版本推定（inferred，結果加註）才比；
    family 是別的、矛盾、讀不出來（也推定不了）→ NOT_ASSESSED。"""
    if comp.get("family_conflict"):
        return _r("NOT_ASSESSED", "family-conflict", "the version list gives conflicting ME families for this version; nothing is inferred")
    fam = comp.get("family")
    if fam and fam != "CSME":
        return _r("NOT_ASSESSED", "family-not-csme", f"the version list says this ME is {fam}, not CSME; CSME rules are not applied to it")
    if comp.get("family_basis") not in ("listed", "inferred"):
        return _r("NOT_ASSESSED", "family-unknown", "the ME family (CSME, TXE or SPS) cannot be read from the image and cannot be inferred from the version")
    r = cond_dotted(c, comp, CSME_VER_RE, "CSME")
    if r["result"] in ("affected", "not-affected") and comp.get("family_basis") == "inferred":
        r["detail"] += "; the ME family (CSME) is inferred from the version, not declared"
    return r


def cond_psp(c, comp):
    if _int_or_none(comp.get("type")) != c["psp_type"]:
        return _r(OUT, "type-mismatch", f"rule covers PSP type {c['psp_type']}")
    ver, fixed = parse_psp(comp.get("version")), parse_psp(c["fixed_in"])
    if ver is None:
        return _r("NOT_ASSESSED", "version-unreadable", f"the PSP version {comp.get('version')!r} is not four hexadecimal bytes")
    if ver < fixed:
        return _r("affected", None, f"PSP type {c['psp_type']} version {comp['version']} is below fixed_in {c['fixed_in']} (byte-wise)")
    return _r("not-affected", None, f"PSP type {c['psp_type']} version {comp['version']} is not below fixed_in {c['fixed_in']} (byte-wise)")


def _int_or_none(v):
    if _is_int(v):
        return v
    if isinstance(v, str):
        try:
            return int(v, 0)
        except ValueError:
            return None
    return None


def cond_ucode(c, comp):
    if "equiv_id" in c:
        have = (comp.get("equiv_id") or "").lower()
        if have != c["equiv_id"]:
            return _r(OUT, "equiv-mismatch", f"rule covers equivalence id {c['equiv_id']}")
    else:
        cpuids = comp.get("cpuids")
        if not cpuids:
            return _r("NOT_ASSESSED", "cpuid-unknown", "the CPUID of this microcode patch was not determined (no equivalence table in the image); not guessed")
        if c["cpuid"] not in {x.upper() for x in cpuids}:
            return _r(OUT, "cpuid-mismatch", f"rule covers CPUID {c['cpuid']}")
    pid = parse_hex(comp.get("patch_id"), PATCH_RE)
    if pid is None:
        return _r("NOT_ASSESSED", "version-unreadable", f"the patch level {comp.get('patch_id')!r} is not 0x + 8 hexadecimal digits")
    fixed = int(c["fixed_in"], 16)
    if pid < fixed:
        return _r("affected", None, f"patch level 0x{pid:08x} is below fixed_in {c['fixed_in']}")
    return _r("not-affected", None, f"patch level 0x{pid:08x} is not below fixed_in {c['fixed_in']}")


def cond_bios(c, comp):
    name = str(comp.get("file") or "").rsplit("/", 1)[-1].rsplit("!", 1)[-1]
    if not name.lower().startswith(c["name_prefix"].lower()):
        return _r(OUT, "name-mismatch", f"rule covers images whose file name starts with {c['name_prefix']}")
    if not comp.get("declared_version"):
        return _r("NOT_ASSESSED", "no-declared-version", "the version list does not declare a BIOS version for this image")
    ver, fixed = parse_bios(comp["declared_version"]), parse_bios(c["fixed_in"])
    if ver is None:
        return _r("NOT_ASSESSED", "version-unreadable", f"the declared BIOS version {comp['declared_version']!r} is not a dotted number")
    if tuple_compare(ver, fixed) < 0:
        return _r("affected", None, f"declared BIOS version {comp['declared_version']} is below fixed_in {c['fixed_in']}")
    return _r("not-affected", None, f"declared BIOS version {comp['declared_version']} is not below fixed_in {c['fixed_in']}")


def _ami_norm(s):
    return re.sub(r"\s+", "", str(s)).lower()


def _ami_why(a):
    inc = a.get("incomplete")
    if isinstance(inc, list) and inc:
        return "; ".join(str(x)[:160] for x in inc[:3])
    return "no reason recorded"


def cond_ami(c, comp):
    """AMI 核心版本（D-058）。comp["ami_core"]＝ami_core.summarize 的結果（至少 status、product、major、minor）；沒有 → 沒有核心版本資料。
    低於修正版本才給 affected 建議；不低於一律 NOT_ASSESSED（A1 未確認，不輸出 not-affected）。"""
    a = comp.get("ami_core")
    if not isinstance(a, dict) or not isinstance(a.get("status"), str) or a["status"] in ("not-found", "not-searched"):
        return _r("NOT_ASSESSED", "no-ami-core-version", AMI_NO_CORE)
    if a["status"] in AMI_REASONS:
        return _r("NOT_ASSESSED", *AMI_REASONS[a["status"]])
    if a["status"] != "read" or not (_is_int(a.get("major")) and _is_int(a.get("minor"))):
        return _r("NOT_ASSESSED", "no-ami-core-version", AMI_NO_CORE)
    core = f"{a['major']}.{a['minor']}"
    if not a.get("product"):
        return _r("NOT_ASSESSED", "ami-product-unknown", f"the image's AMI core version is {core} but its major version does not name a known AMI product line; no product is assumed")
    if _ami_norm(a["product"]) != _ami_norm(c["product"]):
        return _r(OUT, "product-mismatch", f"rule covers product {c['product']}, this is {a['product']}")
    if "fixed_in" not in c:
        return _r("NOT_ASSESSED", "rule-has-no-fixed-in", f"the rule gives no fixed version; the image's AMI core version is {core}")
    m = AMI_FIXED_RE.fullmatch(c["fixed_in"])
    fixed = (int(m.group(1)), int(m.group(2)))
    have = (a["major"], a["minor"])
    if have[0] != fixed[0]:
        return _r("NOT_ASSESSED", "ami-core-line-differs",
                  f"the image's AMI core major version is {have[0]} but fixed_in {c['fixed_in']} is in major {fixed[0]}; versions of different majors are not compared")
    if have < fixed:
        return _r("affected", None, f"AMI core {core} (Firmware ID record; self-declared by the image, unsigned) is below fixed_in {c['fixed_in']} "
                                    f"(compared as integers: {have[0]}.{have[1]:03d} < {fixed[0]}.{fixed[1]:03d}); " + AMI_CAVEAT
                                    + ("" if a.get("complete") is True else "; " + AMI_INCOMPLETE.format(why=_ami_why(a))))
    return _r("NOT_ASSESSED", "ami-core-mapping-unverified",
              f"AMI core {core} is not below fixed_in {c['fixed_in']}, but the mapping of the core's notation to the advisory's (A1) is not yet confirmed by AMI "
              "or the board vendor, so no not-affected suggestion is given")


def evaluate_condition(table, c, comp):
    """一個條件對一個元件 → {"result", "reason", "detail"}（result 見檔頭）。條件已通過 validate。"""
    k = c["component"]
    if k == "amd_agesa":
        return cond_agesa(table, c, comp)
    if k == "amd_psp":
        return cond_psp(c, comp)
    if k == "amd_microcode":
        return cond_ucode(c, comp)
    if k == "intel_csme":
        return cond_csme(c, comp)
    if k == "intel_fsp":
        return cond_dotted(c, comp, FSP_VER_RE, "FSP")
    if k == "ami_core":
        return cond_ami(c, comp)
    return cond_bios(c, comp)


def _na(reason, basis, table=None, **extra):
    return {"suggestion": "NOT_ASSESSED", "reason": reason, "rule_ids": [], "state": None, "basis": basis + "; " + NO_DATA, "verification": {},
            "results": [], "evidence": [], "related": [], "source": table.label() if table is not None else None, **extra}


def unavailable(err):
    """規則表不能用（TableError）→ NOT_ASSESSED 結果。"""
    return _na(err.reason, f"the advisory rule table cannot be used ({err.detail})")


def _state_of(table, ids):
    s = {table.by_id[i]["review"]["state"] for i in ids}
    if not s:
        return None
    return "+".join(x for x in STATES if x in s)


def _ami_downgrade_reason(comp):
    """AMI 公告的 not-affected 降級時的原因代碼：元件的 AMI 核心版本沒讀到（或矛盾、結構不合）時用那個原因，讀到了才是 ami-core-mapping-unverified。"""
    a = comp.get("ami_core")
    st = a.get("status") if isinstance(a, dict) else None
    if isinstance(st, str) and st in AMI_REASONS:
        return AMI_REASONS[st][0]
    if st != "read":
        return "no-ami-core-version"
    return "ami-core-mapping-unverified"


def evaluate(table_or_err, kind, comp):
    """一個元件（kind ∈ COMPONENTS，bios_image 會同時看 ami_core）對整張表 → 建議。comp 的欄位依 kind（見檔頭與 x86_firmware 的呼叫端）。"""
    if isinstance(table_or_err, TableError):
        return unavailable(table_or_err)
    table = table_or_err
    # bios_image 同時看 ami_core 規則（只在沒有 AMI 核心版本元件時；有 ami_core 元件時由那個元件比，同一條規則不出兩個建議）
    kinds = (kind, "ami_core") if kind == "bios_image" and not comp.get("ami_core_component") else (kind,)
    results, related, other_scope = [], [], []
    for r in table.rules:
        for j, c in enumerate(r["match"]):
            if c["component"] not in kinds:
                continue
            if c["component"] == "ami_core":
                if not comp.get("ami"):
                    continue
                if kind == "bios_image":
                    related.append(r["id"])
            res = evaluate_condition(table, c, comp)
            if res["result"] == "not-affected" and (r["vendor"] == "AMI" or any(x["component"] == "ami_core" for x in r["match"])):
                # AMI 的公告（廠商是 AMI，或規則有 ami_core 條件）不採用 not-affected（D-058：A1 未確認，第一版不輸出）；
                # 不論是哪一種條件（ami_core、bios_image 或日後新增的種類）判出的 not-affected 都降級
                res = _r("NOT_ASSESSED", _ami_downgrade_reason(comp),
                         "AMI advisories give no not-affected suggestion until the mapping of the core's notation (A1) is confirmed (D-058); " + res["detail"])
            res.update(rule=r["id"], condition=j, state=r["review"]["state"], sources=[s["url"] for s in r["sources"]])
            if res["result"] == OUT:
                other_scope.append(res)
            else:
                results.append(res)
    related = sorted(dict.fromkeys(related))
    per_rule = {}
    for res in results:                         # 同一條規則的幾個條件：affected > NOT_ASSESSED > not-affected
        order = {"affected": 0, "NOT_ASSESSED": 1, "not-affected": 2}
        cur = per_rule.get(res["rule"])
        if cur is None or order[res["result"]] < order[cur["result"]]:
            per_rule[res["rule"]] = res
    chosen = list(per_rule.values())
    aff = [x for x in chosen if x["result"] == "affected"]
    nas = [x for x in chosen if x["result"] == "NOT_ASSESSED"]
    nots = [x for x in chosen if x["result"] == "not-affected"]
    lines = [f"{x['rule']} [{x['state']}]: {x['result']}" + (f" ({x['reason']})" if x["reason"] else "") + f": {x['detail']}" for x in chosen]
    if aff:
        sugg, reason, ids = "affected", None, [x["rule"] for x in aff]
    elif nas:
        sugg, reason, ids = "NOT_ASSESSED", nas[0]["reason"], []
    elif nots:
        sugg, reason, ids = "not-affected", None, [x["rule"] for x in nots]
    else:
        sugg, ids = "NOT_ASSESSED", []
        reason = "no-rule-for-line" if other_scope else "no-rule"
        lines.append("no rule applies to this component" + (f" (rules for other families, version lines or types were not compared: "
                                                           f"{', '.join(sorted({x['rule'] for x in other_scope}))})" if other_scope else ""))
    ids = sorted(dict.fromkeys(ids))
    basis = "; ".join(lines)
    if sugg == "NOT_ASSESSED":
        basis += "; " + NO_DATA
    elif sugg == "not-affected":
        basis += f"; evidence type {EVIDENCE_TYPE}: the vendor advisory lists a fixed version that this version is not below; " + SUGGESTION_ONLY
    else:
        basis += "; " + SUGGESTION_ONLY
    if related and sugg == "NOT_ASSESSED" and kind == "bios_image":
        basis += f"; possibly related AMI advisories (not matched): {', '.join(related)}"
    evidence = sorted({u for x in nots for u in x["sources"]}) if sugg == "not-affected" else []
    ver = {i: table.verification(i) for i in ids}
    if any(v == "summary-tool" for v in ver.values()):
        basis += ("; the version values of " + ", ".join(i for i, v in ver.items() if v == "summary-tool")
                  + " were read only through a page summary tool and are not independently verified: compare them with the vendor page directly")
    return {"suggestion": sugg, "reason": reason, "rule_ids": ids, "state": _state_of(table, ids), "basis": basis, "verification": ver,
            "results": [{k: v for k, v in x.items() if k != "sources"} for x in chosen], "evidence": evidence,
            "related": related, "source": table.label()}


def counts(results):
    """建議清單 → {suggestion: 數量}（只含出現過的）。"""
    c = {}
    for r in results:
        c[r["suggestion"]] = c.get(r["suggestion"], 0) + 1
    return c


def main(argv=None):
    """維護用：`fw_advisory_rules.py sha256 [檔]` 印出檔案的 sha256（更新 TABLE_SHA256 用）；`verify [檔]` 不看固定值，只驗證 schema。"""
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] not in ("sha256", "verify") or len(argv) > 2:
        print("usage: fw_advisory_rules.py sha256|verify [table.json]", file=sys.stderr)
        return 64
    p = Path(argv[1]) if len(argv) == 2 else TABLE_PATH
    try:
        data = p.read_bytes()
    except OSError as e:
        print(f"cannot read: {type(e).__name__}", file=sys.stderr)
        return 1
    sha = hashlib.sha256(data).hexdigest()
    if argv[0] == "sha256":
        print(sha)
        return 0
    try:
        t = load(p, expected_sha256=sha)
    except TableError as e:
        print(f"INVALID {e.reason}: {e.detail}")
        return 1
    print(f"OK {len(t.rules)} rules, sha256 {sha}, pinned {'yes' if sha == TABLE_SHA256 else 'NO (update TABLE_SHA256)'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
