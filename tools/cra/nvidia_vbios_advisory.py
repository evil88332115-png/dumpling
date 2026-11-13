#!/usr/bin/env python3
"""韌體 SBOM 的 NVIDIA vBIOS 公告比對（離線）：用 repo 內的 NVIDIA 公告對照表 tools/pilot/lib/nvidia-bulletins-gpu-firmware.json（是否已經負責人確認看 reviewed_until 與表裡有沒有待審項目）
（NVIDIA product-security 的 gpu-firmware 群組公告，由人審核後填表），依 vBIOS 版本與 PCI vendor／device ID 判斷
affected（受影響）／fixed（已修補）／NOT_ASSESSED。

這不是漏洞判定：
- 消費型與專業型顯卡的 vBIOS 幾乎沒有公開公告（2026-11 的鏡像裡標題有 VBIOS 的只有一則，而且是 HGX／DGX 伺服器）；主要管道是 NVIDIA 的合作夥伴通知。
  所以絕大多數 vBIOS 的結果會是 NOT_ASSESSED：資料庫沒有資料，以廠商公告為準。沒有比對到不代表沒有漏洞。
- fixed 只表示「這份表裡某一則已審核的公告把這個版本列為已修補」，不代表沒有其他漏洞；表可能落後於最新公告（鏡像日期見 advisory-source）。
- 表的內容由人從公告整理；程式不猜版本範圍，也不讀 CSAF／網路。CI 只讀 repo 裡的表。

表的格式沿用 C1 的 `sca-nvidia-bulletins-table/1`（先用 C1 的 validate_table 驗），vBIOS 列在 C1 欄位之外多了這幾個欄位（C1 的程式碼不認得它們，
也不會拒絕它們）；`line` 寫 `vbios`，C1 的版本欄位（fixed_in、affected_below、affected_max）因為只收點分十進位而留 null：
  pci_vendor            PCI vendor ID，4 位十六進位（NVIDIA ＝ 10de）
  pci_devices           PCI device ID 清單，每個 4 位十六進位
  vbios_affected_below  受影響版本「低於」這個版本（公告 prior to）
  vbios_affected_max    受影響版本「最高到」這個版本，含（公告 and earlier）
  vbios_fixed_in        修正版本（公告 updated version）
  版本寫成 option ROM 裡的 `XX.XX.XX.XX.XX`（每段兩位十六進位）；可只寫前幾段（例如 `94.04`），比較時只比 SBOM 版本的前幾段。
  這三個欄位至少要有一個；fixed_in 低於 affected_below、或不高於 affected_max（缺的段補 00／FF 後比）的列自相矛盾，整張表視為壞掉；已審核（reviewed=true）的列才會參與比對，未審核的列只計數。
頂層另有 `mirror`：{commit（40 碼）、commit_date、fetched_utc（ISO 8601）}，記表是對哪一份鏡像審核的（鏡像的時間點）。
`reviewed_until` 是審核者看過的最新公告的日期（不是鏡像 commit 的日期）；兩者分開記。

比對規則（依序，第一個成立的就是結果）：
1. 表讀不到、不是一般檔案、超過上限、JSON 或 C1 的 validate_table 驗證失敗、已審核的 vBIOS 列欄位不對、公告編號（bulletins[].id、rows[].bulletin、not_applicable[].bulletin）不是 1～8 位數字、
   mirror 有寫但三個鍵（commit、commit_date、fetched_utc）缺一個或格式不對 → NOT_ASSESSED（table-unreadable／table-invalid）。
2. 表的 reviewed_until 是 null，或表裡還有只有初審意見（reviewed=false）的公告 → 表尚未經負責人確認 → NOT_ASSESSED（table-not-reviewed）。
3. SBOM 的 vBIOS 版本讀不到、不是 XX.XX.XX.XX.XX（例如佔位字串）→ NOT_ASSESSED（version-unreadable）；ROM 裡有兩個以上不同的版本字串 → NOT_ASSESSED（version-ambiguous）。
4. PCI vendor 不是 10de（含任何一個 x86／EFI 開機影像的 vendor）、device ID 讀不到（全 0 或全 f）、各影像的 device ID 不一致 → NOT_ASSESSED（vendor-mismatch／device-unreadable／device-ambiguous）。
5. option ROM 鏈沒有正常結束（沒有 terminated 這個鍵也算）或開頭不確定 → NOT_ASSESSED（rom-incomplete）：版本字串可能不是這個 ROM 的。
6. 表裡已審核、vendor 與 device ID 都對得上的列：沒有 → NOT_ASSESSED（no-row）。表裡有任何未審核的列時，整張表算未經負責人確認（見 2，table-not-reviewed，列出數量）。
7. 逐列比版本：fixed_in 以上 → fixed；低於 affected_below（或不高於 affected_max）→ affected；落在受影響範圍與修正版本之間的空隙、或列沒有可比較的版本 → gap。
   整份：任何 affected → affected（有 gap 的列另加註）；沒有 affected、有 gap → NOT_ASSESSED（range-gap）；全部 fixed → fixed。
8. 表的 mirror 整個沒寫或是 null → fixed 降成 NOT_ASSESSED（table-stale，日期不明）；mirror 有寫但缺 commit、commit_date、fetched_utc 任一個，或格式不對（沒有時區也算）→ 載入時 table-invalid（見 1）。
   mirror 的日期超過 MAX_MIRROR_AGE_DAYS 或在未來（比現在晚超過一天）→ 同樣 fixed 降成 NOT_ASSESSED（table-stale，表可能漏了較新的公告）；
   affected 與其他結果照舊但加註。現在時間由呼叫端傳入（now 參數；測試一律傳固定的時間），沒給才用牆上時鐘。
所有 NOT_ASSESSED 的 basis 都以「資料庫沒有資料，以廠商公告為準」收尾（SBOM 內是英文）。
"""
import datetime
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TABLE_PATH = HERE.parent / "pilot" / "lib" / "nvidia-bulletins-gpu-firmware.json"
C1_MODULE_PATH = HERE.parent / "pilot" / "lib" / "nvidia_bulletins.py"
MAX_TABLE = 4 << 20
MAX_MIRROR_AGE_DAYS = 90
FUTURE_TOLERANCE_DAYS = 1                  # fetched_utc 比現在晚超過這麼多天 → 當成讀不到（時鐘或表有問題）
NVIDIA_VID = "10de"
VBIOS_CODE_TYPES = (0, 3)                  # x86_firmware.VBIOS_CODE_TYPES：顯卡開機用的影像（legacy x86、EFI）
MATCHES = ("affected", "fixed", "NOT_ASSESSED")
SOURCE_URL = "github.com/NVIDIA/product-security"
NO_DATA = ("no data in the database; the vendor advisory is authoritative "
           "(public NVIDIA bulletins almost never cover consumer graphics-card vBIOS; those are communicated to NVIDIA's partners, "
           "so ask the graphics-card team or the NVIDIA partner channel)")
CAVEAT = ("this matches only the reviewed rows of the table (NVIDIA product-security, gpu-firmware group); it is not a complete vulnerability assessment "
          "and the vendor advisory is authoritative")
DEVICE_CAVEAT = ("the PCI device ID is the one in the option ROM's PCIR header; a board may report a different ID at runtime (not checked), "
                 "and the version is the first XX.XX.XX.XX.XX string inside the ROM")
VER_RE = re.compile(r"^[0-9A-Fa-f]{2}(?:\.[0-9A-Fa-f]{2}){0,4}$")
HEX4_RE = re.compile(r"^[0-9a-f]{4}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
BULLETIN_ID_RE = re.compile(r"^[0-9]{1,8}$")      # 與 C1 nvidia_bulletins.py 的 BULLETIN_ID_RE 相同；公告編號會寫進報告與 SBOM，只收數字（不能帶 @、連結語法）
ROW_VERSION_KEYS = ("vbios_affected_below", "vbios_affected_max", "vbios_fixed_in")


class TableError(Exception):
    def __init__(self, reason, detail):
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


def _c1():
    """C1 的 tools/pilot/lib/nvidia_bulletins.py（只用它的 validate_table 與 InputError；不改它）。載入的是本 repo 自己的程式。"""
    mod = sys.modules.get("nvidia_bulletins_c1_for_c2")
    if mod is None:
        try:
            spec = importlib.util.spec_from_file_location("nvidia_bulletins_c1_for_c2", C1_MODULE_PATH)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            if not callable(getattr(mod, "validate_table", None)) or not hasattr(mod, "InputError"):
                raise AttributeError("validate_table")
        except (OSError, ImportError, AttributeError, SyntaxError) as e:
            raise TableError("table-unreadable", f"cannot load the NVIDIA bulletin tool for validation ({type(e).__name__})")
        sys.modules["nvidia_bulletins_c1_for_c2"] = mod
    return mod


def parse_version(s):
    """'94.04.5E.00.92' → (0x94, 0x04, 0x5E, 0x00, 0x92)；1～5 段、每段兩位十六進位；格式不對（含 XX 佔位）→ None。"""
    if not isinstance(s, str) or not VER_RE.fullmatch(s):
        return None
    return tuple(int(x, 16) for x in s.split("."))


def _pad(t, fill):
    """1～5 段的版本補成 5 段（受影響上界補 FF、其他補 00）。"""
    return tuple(t) + (fill,) * (5 - len(t))


def _cmp_prefix(ver, bound):
    """ver（完整版本的 tuple）與 bound（可能只有前幾段）比較，只比 bound 有的那幾段。"""
    a, b = ver[:len(bound)], bound
    return (a > b) - (a < b)


class Table:
    """載入並檢查過的對照表。rows：已審核、可比對的 vBIOS 列；unreviewed：未審核的列。"""

    def __init__(self, doc, sha256):
        self.doc = doc
        self.sha256 = sha256
        self.reviewed_until = doc.get("reviewed_until")
        m = doc.get("mirror") if isinstance(doc.get("mirror"), dict) else {}
        self.mirror_commit = m.get("commit") if isinstance(m.get("commit"), str) and COMMIT_RE.fullmatch(m["commit"]) else None
        self.mirror_commit_date = m.get("commit_date") if isinstance(m.get("commit_date"), str) else None
        self.mirror_fetched = _parse_utc(m.get("fetched_utc"))
        self.mirror_fetched_text = m.get("fetched_utc") if self.mirror_fetched else None
        self.rows, self.unreviewed = [], []
        for r in doc.get("rows", []):
            (self.rows if r["reviewed"] else self.unreviewed).append(r)
        self.not_applicable = [x["bulletin"] for x in doc.get("not_applicable", []) if x.get("reviewed", True) is not False]
        self.awaiting = [x["bulletin"] for x in doc.get("not_applicable", []) if x.get("reviewed", True) is False]      # 初審意見、還沒有人確認
        # 負責人確認過：reviewed_until 有值，而且沒有只有初審意見的公告、沒有未審核的列（只填了 reviewed_until、公告或列還是 reviewed=false 都算沒確認）
        self.confirmed = self.reviewed_until is not None and not self.awaiting and not self.unreviewed
        self.bulletins = [b["id"] for b in doc.get("bulletins", [])]
        self.parsed = []                         # (row, vendor, {devices}, {key: tuple})
        for r in self.rows:
            self.parsed.append((r, r["pci_vendor"], set(r["pci_devices"]), {k: parse_version(r[k]) for k in ROW_VERSION_KEYS if r.get(k)}))

    def stale(self, now):
        """mirror 日期超過上限、讀不到、或在未來（比 now 晚超過一天）→ True。now 沒有時區時當成 UTC。"""
        if self.mirror_fetched is None:
            return True
        if now.tzinfo is None:
            now = now.replace(tzinfo=datetime.timezone.utc)
        age = (now - self.mirror_fetched).total_seconds() / 86400
        return age > MAX_MIRROR_AGE_DAYS or age < -FUTURE_TOLERANCE_DAYS

    def label(self):
        c = self.mirror_commit[:12] if self.mirror_commit else "unknown"
        f = self.mirror_fetched_text or "unknown"
        return (f"{SOURCE_URL} mirror commit {c} (fetched {f}), group gpu-firmware; table nvidia-bulletins-gpu-firmware.json "
                f"reviewed_until {self.reviewed_until or 'null'}, sha256 {self.sha256[:16]}…; "
                f"{len(self.rows)} reviewed vBIOS rows, {len(self.unreviewed)} unreviewed"
                + (f", {len(self.not_applicable)} bulletins confirmed as not mappable to option ROM versions ({', '.join(self.not_applicable)})" if self.not_applicable else "")
                + (f", {len(self.awaiting)} bulletins with a preliminary opinion (not mappable to option ROM versions) awaiting confirmation ({', '.join(self.awaiting)})" if self.awaiting else ""))


TIME_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3}|\.\d{6})?(?:Z|[+-]\d{2}:\d{2})")


def _parse_utc(s):
    """只收 YYYY-MM-DDTHH:MM:SS，秒後面可以有 3 或 6 位小數，時區寫 Z 或 ±HH:MM（和 C1 一致）；其他一律 None。
    不直接丟給 fromisoformat：Python 3.10 與 3.12 能讀的格式不同（3.11 起才收 `+0000`、空白分隔、沒有秒、任意位數小數），結果不能隨直譯器版本變。"""
    if not isinstance(s, str) or not TIME_RE.fullmatch(s):
        return None
    try:
        return datetime.datetime.fromisoformat(s[:-1] + "+00:00" if s.endswith("Z") else s)
    except ValueError:                             # 月份、日、時、分、秒超出範圍，或時區偏移超出範圍
        return None


def validate_rows(doc):
    """已審核的 vBIOS 列（reviewed=true）的欄位檢查；不對就丟 TableError（表被改壞時不比對，不是靜默少算）。"""
    def bad(i, why):
        raise TableError("table-invalid", f"rows[{i}]: {why}")
    for i, r in enumerate(doc.get("rows", [])):
        if not r["reviewed"]:
            continue
        if r.get("pci_vendor") != NVIDIA_VID:
            bad(i, "pci_vendor must be '10de'")
        d = r.get("pci_devices")
        if not isinstance(d, list) or not d or not all(isinstance(x, str) and HEX4_RE.fullmatch(x) for x in d):
            bad(i, "pci_devices must be a non-empty list of 4-digit lowercase hex strings")
        if not any(r.get(k) for k in ROW_VERSION_KEYS):
            bad(i, "needs at least one of vbios_affected_below, vbios_affected_max, vbios_fixed_in")
        for k in ROW_VERSION_KEYS:
            if r.get(k) is not None and parse_version(r[k]) is None:
                bad(i, f"{k} is not an XX.XX.XX.XX.XX version: {r[k]!r}")
        if r.get("vbios_affected_below") and r.get("vbios_affected_max"):
            bad(i, "vbios_affected_below and vbios_affected_max are mutually exclusive")
        fixed = parse_version(r["vbios_fixed_in"]) if r.get("vbios_fixed_in") else None
        if fixed:
            lo = _pad(fixed, 0x00)
            if r.get("vbios_affected_below") and lo < _pad(parse_version(r["vbios_affected_below"]), 0x00):
                bad(i, "vbios_fixed_in is lower than vbios_affected_below (contradictory row)")
            if r.get("vbios_affected_max") and lo <= _pad(parse_version(r["vbios_affected_max"]), 0xFF):
                bad(i, "vbios_fixed_in is not above vbios_affected_max (contradictory row)")


def validate_ids(doc):
    """公告編號（bulletins[].id、rows[].bulletin、not_applicable[].bulletin；未審核的也檢查）只收 BULLETIN_ID_RE；不對整張表視為壞掉。"""
    def bad(where, v):
        raise TableError("table-invalid", f"{where}: bulletin id must be 1 to 8 digits, got {str(v)[:40]!r}")
    for name, key in (("bulletins", "id"), ("rows", "bulletin"), ("not_applicable", "bulletin")):
        for i, x in enumerate(doc.get(name, [])):
            v = x.get(key) if isinstance(x, dict) else None
            if not (isinstance(v, str) and BULLETIN_ID_RE.fullmatch(v)):      # fullmatch：`$` 會放行結尾的換行字元（"9001\n"）
                bad(f"{name}[{i}].{key}", v)


def validate_mirror(doc):
    """mirror 整個沒寫或是 null → 日期不明，比對時 table-stale。有寫就要是物件，commit（40 碼十六進位）、commit_date、fetched_utc 三個都有，
    兩個時間都是有時區的 ISO 8601（見 _parse_utc），否則 table-invalid。"""
    m = doc.get("mirror")
    if m is None:
        return
    if not isinstance(m, dict):
        raise TableError("table-invalid", "mirror must be an object")
    for k in ("commit", "commit_date", "fetched_utc"):
        if k not in m or m[k] is None:
            raise TableError("table-invalid", f"mirror.{k} is missing (mirror needs commit, commit_date and fetched_utc)")
    if not (isinstance(m["commit"], str) and COMMIT_RE.fullmatch(m["commit"])):
        raise TableError("table-invalid", "mirror.commit must be 40 lowercase hex digits")
    for k in ("commit_date", "fetched_utc"):
        if _parse_utc(m[k]) is None:
            raise TableError("table-invalid", f"mirror.{k} must be YYYY-MM-DDTHH:MM:SS with optional .fff or .ffffff and a Z or +HH:MM time zone")


def load(path=None):
    """表 → Table；讀不到、超過上限、JSON 或結構不對 → TableError。"""
    p = Path(path) if path else TABLE_PATH
    try:
        if p.is_symlink() or not p.is_file():
            raise TableError("table-unreadable", "not a regular file")
        with open(p, "rb") as fh:
            data = fh.read(MAX_TABLE + 1)
    except OSError as e:
        raise TableError("table-unreadable", type(e).__name__)
    if len(data) > MAX_TABLE:
        raise TableError("table-unreadable", "larger than limit")
    try:
        doc = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise TableError("table-unreadable", "not valid JSON")
    c1 = _c1()
    try:
        c1.validate_table(doc)
    except c1.InputError as e:
        raise TableError("table-invalid", f"validate_table: {e}")
    except (TypeError, KeyError, AttributeError, ValueError):
        raise TableError("table-invalid", "validate_table: unexpected structure")
    validate_rows(doc)
    validate_ids(doc)
    validate_mirror(doc)
    return Table(doc, hashlib.sha256(data).hexdigest())


def load_default():
    """→ (Table 或 None, 失敗時的 TableError 或 None)。"""
    try:
        return load(), None
    except TableError as e:
        return None, e


def _na(reason, basis, notes=None, source=None):
    return {"match": "NOT_ASSESSED", "reason": reason, "basis": basis + "; " + NO_DATA, "bulletins": [], "cves": [],
            "notes": list(notes or []), "source": source}


def unavailable(err):
    return _na(err.reason, f"the NVIDIA bulletin table cannot be used ({err.detail})")


def _row_result(ver, parsed):
    """一列對一個版本：'fixed'、'affected'、'gap'。"""
    row, _v, _d, k = parsed
    fixed = k.get("vbios_fixed_in")
    if fixed and _cmp_prefix(ver, fixed) >= 0:
        return "fixed"
    if k.get("vbios_affected_below"):
        return "affected" if _cmp_prefix(ver, k["vbios_affected_below"]) < 0 else "gap"
    if k.get("vbios_affected_max"):
        return "affected" if _cmp_prefix(ver, k["vbios_affected_max"]) <= 0 else "gap"
    if fixed:
        return "affected"
    return "gap"


def _rows_text(rows):
    return "; ".join(f"bulletin {r['bulletin']} {r['cve']}" for r in rows)


def match_vbios(table_or_err, v, now=None):
    """inventory 的一個 vBIOS（vendor、device、version、images、terminated、start_note）→ 比對結果 dict：
    match（affected／fixed／NOT_ASSESSED）、reason、basis、bulletins、cves、notes、source。"""
    if isinstance(table_or_err, TableError):
        return unavailable(table_or_err)
    table = table_or_err
    src = table.label()
    now = now if now is not None else datetime.datetime.now(datetime.timezone.utc)
    if not table.confirmed:
        pend = f"; bulletins with a preliminary opinion only: {', '.join(table.awaiting)}" if table.awaiting else ""
        unrev = f"; {len(table.unreviewed)} unreviewed rows" if table.unreviewed else ""
        return _na("table-not-reviewed", "the NVIDIA bulletin table has not been confirmed by the responsible reviewer yet (表尚未經負責人確認; "
                   f"{'reviewed_until is null' if table.reviewed_until is None else 'reviewed_until is set but a bulletin or row is still unconfirmed'}{pend}{unrev})", source=src)
    ver_text = v.get("version")
    ver = parse_version(ver_text) if isinstance(ver_text, str) and len(ver_text) == 14 else None
    if ver is None:
        return _na("version-unreadable", f"the vBIOS version could not be read as XX.XX.XX.XX.XX ({ver_text!r}: absent or a placeholder)", source=src)
    others = [x for x in (v.get("other_versions") or []) if isinstance(x, str)]
    if others:
        return _na("version-ambiguous", f"the option ROM contains more than one XX.XX.XX.XX.XX string ({', '.join([ver_text] + others)}); "
                   "which one is the vBIOS version is not known", source=src)
    vendor = str(v.get("vendor") or "").lower()
    imgs = [i for i in v.get("images") or [] if isinstance(i, dict) and i.get("code_type") in VBIOS_CODE_TYPES]
    vendors = {vendor} | {str(i.get("vendor") or "").lower() for i in imgs if "vendor" in i}
    if vendors != {NVIDIA_VID}:
        return _na("vendor-mismatch", f"the PCI vendor ID is {', '.join(sorted(x or 'unreadable' for x in vendors))}, not only {NVIDIA_VID} "
                   "(checked for the ROM and every x86/EFI boot image)", source=src)
    devs = {str(i.get("device") or "").lower() for i in imgs} or {str(v.get("device") or "").lower()}
    if len(devs) > 1:
        return _na("device-ambiguous", f"the boot images of the option ROM carry different PCI device IDs ({', '.join(sorted(devs))})", source=src)
    dev = next(iter(devs))
    if not HEX4_RE.fullmatch(dev) or dev in ("0000", "ffff"):
        return _na("device-unreadable", f"the PCI device ID could not be read from the option ROM ({dev!r})", source=src)
    if v.get("terminated") != "last-flag" or v.get("start_note"):            # 沒有 terminated 這個鍵：不知道鏈有沒有正常結束，當作不完整
        return _na("rom-incomplete", "the option ROM chain did not end normally or its start is ambiguous, so the version string may not belong to this ROM",
                   source=src)
    stale = table.stale(now)
    notes = []
    if stale:
        notes.append(f"the table was reviewed against a mirror older than {MAX_MIRROR_AGE_DAYS} days or of unknown date: refresh the table "
                     "(docs/notes/c2-firmware-advisory.md); newer NVIDIA bulletins may be missing")
    where = f"vBIOS {ver_text} on PCI {vendor}:{dev}"
    rows = [p for p in table.parsed if p[1] == vendor and dev in p[2]]
    if not rows:
        unrev = [r for r in table.unreviewed if isinstance(r.get("pci_devices"), list) and dev in r["pci_devices"]]
        if unrev:
            return _na("unreviewed-row", f"{where}: the table has {len(unrev)} unreviewed row(s) for this device ID ({_rows_text(unrev)}); "
                       "unreviewed rows are not used", notes, src)
        return _na("no-row", f"{where}: the NVIDIA bulletin table has no reviewed row for this PCI device ID ({len(table.parsed)} reviewed vBIOS row(s) in total)",
                   notes, src)
    res = [(_row_result(ver, p), p[0]) for p in rows]
    aff = [r for k, r in res if k == "affected"]
    fix = [r for k, r in res if k == "fixed"]
    gap = [r for k, r in res if k == "gap"]
    ids = lambda rs: sorted({r["bulletin"] for r in rs})
    cves = lambda rs: sorted({r["cve"] for r in rs})
    base = {"bulletins": ids(aff or fix), "cves": cves(aff or fix), "source": src, "reason": None}
    if aff:
        if gap:
            notes.append(f"{len(gap)} other row(s) for this device are between the affected range and the fixed version or have no comparable version "
                         f"({_rows_text(gap)}): confirm with the vendor advisory")
        if fix:
            notes.append(f"the version is already at or above the fixed version in: {_rows_text(fix)}")
        notes.append(DEVICE_CAVEAT)
        return {"match": "affected", "basis": f"{where} is listed as affected by {_rows_text(aff)} (reviewed table rows); " + CAVEAT,
                "notes": notes, **base}
    if gap:
        return {**_na("range-gap", f"{where} falls between the affected range and the fixed version, or a row has no comparable version "
                      f"({_rows_text(gap)})", notes, src)}
    if stale:
        return {**_na("table-stale", f"{where} is at or above the fixed version in {_rows_text(fix)}, but the table's mirror is too old to rely on",
                      notes + [DEVICE_CAVEAT], src), "bulletins": ids(fix), "cves": cves(fix)}
    notes.append(DEVICE_CAVEAT)
    return {"match": "fixed", "basis": f"{where} is at or above the fixed version listed in {_rows_text(fix)} (reviewed table rows); "
            "this says nothing about other vulnerabilities; " + CAVEAT, "notes": notes, **base}


def counts(results):
    c = {}
    for r in results:
        c[r["match"]] = c.get(r["match"], 0) + 1
    return c
