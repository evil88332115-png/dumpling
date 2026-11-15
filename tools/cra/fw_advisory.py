#!/usr/bin/env python3
"""韌體 SBOM 的 Intel 微碼公告比對（離線）：用 tools/cra/data/intel-microcode-releases.json（由 intel_ucode_releases.py 從 Intel 公開的
releasenote.md 產生）找出「比 SBOM 裡的微碼 revision 更新的 release」，列出那些 release 的 INTEL-SA 當**候選**。

這不是漏洞判定：
- 來源只在 release 層級列公告，沒有逐 CPUID 列出；候選公告不一定影響這個 CPUID。
- 資料表只涵蓋 Intel 公開的 Linux 微碼套件；套件不含只能由 BIOS 載入的微碼、OEM 專用版本。
- `up-to-date` 只表示資料表裡沒有更新的 revision，不代表沒有漏洞。
- 比不到（資料表讀不到、sha256 不符、CPUID／platform／revision 對不上）一律 NOT_ASSESSED：資料庫沒有資料，以廠商公告為準。

比對規則（依序，第一個成立的就是結果）：
1. 資料表讀不到、結構不對、sha256 與程式裡固定的值不符 → NOT_ASSESSED（table-unreadable／table-sha-mismatch）。
2. SBOM 的 revision 讀不到、CPUID 不是 8 位十六進位 → NOT_ASSESSED（revision-unreadable／bad-cpuid）。
3. CPUID 轉成 F-M-S（family-model-stepping），platform id 當遮罩；F-M-S 不在資料表 → NOT_ASSESSED（cpuid-not-in-table）；
   F-M-S 在、但沒有相同的 platform id 遮罩 → NOT_ASSESSED（platform-mismatch，列出資料表有的遮罩）。
4. 該 (F-M-S, platform id) 在資料表的事件（new／updated／removed，release 由新到舊）：最新的事件是 removed → NOT_ASSESSED（removed）；
   最新的 release 對這個鍵列了不同的 New Ver → NOT_ASSESSED（ambiguous）。
5. 最新 revision ＝最新的 new／updated 事件的 New Ver。SBOM revision 比它新 → NOT_ASSESSED（revision-newer-than-table）。
6. 候選公告（release 層級，取聯集，每個公告記來源 how）：
   a. New Ver 大於 SBOM revision 的 release 的公告（how＝來源的 security／updated／update-to）。
   b. 「New Disclosures Updated in Prior Releases」表：這個鍵在揭露表有一列，而且 revision ≤ 那一列 Old／New 中有值的較大者 → 揭露那個 release 的公告（how＝disclosed）。
      語意（對原文的判斷）：這個表列的是「先前 release 已經發佈、現在才揭露有公告涵蓋」的微碼；N/A 表示沒有對應的新 revision，所以取有值的那個當上界。拿不準，所以保守：不高於上界的 revision 都列。
   c. 人工對照的散文（資料表的 prose_rules，目前是 20250812 的一句「ADL、RPL、SPR、EMR、MTL、ARL 的微碼先前已在 2025-05 發佈」）：
      鍵在對照裡、而且 revision 低於基準 revision → 那個 release 的公告（how＝prose）。對照的 GAP（歧義、沒有基準）只加註。
   d. 同一個 F-M-S 另有 platform 遮罩與 SBOM 的遮罩有交集，而且那個鍵在 SBOM 這個鍵最後一次更新之後的 release 還有更新 → 那些 release 的公告（how＝superseded-mask）。
7. SBOM revision ＝最新 revision：沒有 b／c 的候選時，若 6.d 成立 → NOT_ASSESSED（superseded-platform-mask，basis 列出較新的鍵、它的最新 revision 與之後各 release 的公告當參考）；否則 up-to-date。
   有 b 的候選 → affected-candidate。遮罩互不相交但另一個遮罩在之後仍有更新 → 結果不變，加註。
8. SBOM revision 比最新的舊：有任何候選公告 → affected-candidate；沒有 → older-no-sa（有較新的 revision，但沒有列公告；不是「沒有漏洞」）。
revision 以無號 32 位整數比較（十六進位，不分大小寫、前導零不影響）。有 extended signature 的微碼，每個 signature 各算一次，
整份微碼取：任何一個 affected-candidate → affected-candidate；否則任何一個 NOT_ASSESSED → NOT_ASSESSED；否則有 older-no-sa → older-no-sa；否則 up-to-date。
"""
import hashlib
import json
import re
from pathlib import Path

TABLE_PATH = Path(__file__).resolve().parent / "data" / "intel-microcode-releases.json"
# 資料表檔案本身的 sha256（重新產生資料表後要一起更新；tests 會核對）。檔案被改動、截斷或換成別的內容時，比對一律 NOT_ASSESSED。
TABLE_SHA256 = "253aab94c3c2a14eda457b1ee4a7a1490e00d4e854622cd9f05e77a07904e271"
SCHEMA = "dumpling-intel-microcode-releases/1"
MAX_TABLE = 4 << 20
MATCHES = ("affected-candidate", "older-no-sa", "up-to-date", "NOT_ASSESSED")
NO_DATA = "no data in the database; the vendor advisory (Intel INTEL-SA) is authoritative"
CAVEAT = ("advisories are listed per release in the source, not per CPUID; a candidate advisory does not necessarily affect this CPUID")
UP_TO_DATE = "no newer revision in the table; this does not mean there are no vulnerabilities, refer to the Intel advisories"
CPUID_RE = re.compile(r"^[0-9A-Fa-f]{8}$")
REV_RE = re.compile(r"^0[xX][0-9A-Fa-f]{1,8}$")
PF_RE = re.compile(r"^0[xX][0-9A-Fa-f]{1,2}$")
ROW_KEYS = ("new", "updated", "removed", "disclosed")
SA_RE = re.compile(r"^INTEL-SA-\d{5}$")
HOWS = ("security", "updated", "update-to")
TAG_RE = re.compile(r"^microcode-[A-Za-z0-9-]+$")


class TableError(Exception):
    def __init__(self, reason, detail):
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


class Table:
    """載入並檢查過的資料表。events[(fms, pi)] ＝ [(release 序號（0＝最新）, kind, old, new, tag)]。"""

    def __init__(self, doc, sha256):
        self.doc = doc
        self.sha256 = sha256
        self.source = doc["source"]
        self.releases = doc["releases"]
        self.index = {r["tag"]: i for i, r in enumerate(self.releases)}
        self.security = {}                      # tag -> [(id, how)]（去重）
        self.sa_by_tag = {}
        self.events = {}
        self.fms_pis = {}
        for i, r in enumerate(self.releases):
            ids, seen = [], set()
            for s in r["security"]:
                if (s["id"], s["how"]) not in seen:
                    seen.add((s["id"], s["how"]))
                    ids.append((s["id"], s["how"]))
            self.security[r["tag"]] = ids
            self.sa_by_tag[r["tag"]] = list(dict.fromkeys(x[0] for x in ids))
            for kind in ROW_KEYS:
                for row in r[kind]:
                    self.events.setdefault((row[0], row[1]), []).append((i, kind, row[2], row[3], r["tag"]))
                    self.fms_pis.setdefault(row[0], set()).add(row[1])
        self.prose = {}                         # (fms, pi) -> [(rule, ref_revision)]
        self.prose_gaps = {}                    # (fms, pi) -> [(rule, why)]（歧義、沒有基準）
        self.prose_unlisted = {}                # (fms, pi) -> [(rule, why)]（同 F-M-S 的其他 platform，原文沒提到）
        for rule in doc.get("prose_rules", []):
            for fms, pi, ref, _how in rule["keys"]:
                self.prose.setdefault((fms, pi), []).append((rule, int(ref, 16)))
            for g in rule["gaps"]:
                if "key" in g:
                    f, p = g["key"].split("/")
                    self.prose_gaps.setdefault((f, p), []).append((rule, g["why"]))
            for g in rule.get("unlisted", []):
                f, p = g["key"].split("/")
                self.prose_unlisted.setdefault((f, p), []).append((rule, g["why"]))

    def label(self):
        s = self.source
        return (f"{s['repo'].split('github.com/')[-1]} {s['tag']} (commit {s['commit'][:12]}, {s['path']} sha256 {s['sha256'][:16]}…; "
                f"table sha256 {self.sha256[:16]}…)")


def _hex8(v):
    return isinstance(v, str) and re.fullmatch(r"[0-9a-f]{8}", v) is not None


def validate(doc):
    """結構檢查；不對就丟 TableError（資料表被改壞時不比對，不是靜默少算）。"""
    def bad(why):
        raise TableError("table-unreadable", "structure: " + why)
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        bad("schema")
    src = doc.get("source")
    if not isinstance(src, dict) or not all(isinstance(src.get(k), str) and src[k] for k in ("repo", "tag", "commit", "path", "sha256")):
        bad("source")
    rels = doc.get("releases")
    if not isinstance(rels, list) or not rels:
        bad("releases")
    seen = set()
    prev_date = None
    for r in rels:
        if not isinstance(r, dict) or not isinstance(r.get("tag"), str) or not TAG_RE.fullmatch(r["tag"]) or r["tag"] in seen:
            bad("release tag")
        seen.add(r["tag"])
        d = r.get("date")
        if d is not None:
            if not isinstance(d, str) or not re.fullmatch(r"\d{4}-\d\d-\d\d", d):
                bad("date in " + r["tag"])
            if prev_date is not None and d > prev_date:
                bad("releases are not ordered newest first at " + r["tag"])        # 順序決定「較新」的判斷
            prev_date = d
        sec = r.get("security")
        if not isinstance(sec, list) or not all(isinstance(s, dict) and isinstance(s.get("id"), str) and SA_RE.fullmatch(s["id"])
                                                 and s.get("how") in HOWS for s in sec):
            bad("security in " + r["tag"])
        for k in ROW_KEYS:
            rows = r.get(k)
            if not isinstance(rows, list):
                bad(f"{k} in {r['tag']}")
            for row in rows:
                if (not isinstance(row, list) or len(row) != 6 or not all(isinstance(x, str) for x in row)
                        or not re.fullmatch(r"[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}", row[0]) or not re.fullmatch(r"[0-9a-f]{2}", row[1])
                        or not all(x == "" or x == "N/A" or _hex8(x) for x in (row[2], row[3]))):
                    bad(f"row in {r['tag']}")
                if k in ("new", "updated") and not _hex8(row[3]):
                    bad(f"row without new revision in {r['tag']}")
    rules = doc.get("prose_rules", [])
    if not isinstance(rules, list):
        bad("prose_rules")
    for rule in rules:
        if (not isinstance(rule, dict) or rule.get("release") not in seen or rule.get("ref_release") not in seen
                or not isinstance(rule.get("line"), int) or not isinstance(rule.get("keys"), list) or not isinstance(rule.get("gaps"), list)
                or not isinstance(rule.get("quote"), str) or not isinstance(rule.get("interpretation"), str)):
            bad("prose_rules entry")
        for k in rule["keys"]:
            if (not isinstance(k, list) or len(k) != 4 or not all(isinstance(x, str) for x in k)
                    or not re.fullmatch(r"[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}", k[0]) or not re.fullmatch(r"[0-9a-f]{2}", k[1]) or not _hex8(k[2])):
                bad("prose_rules key")
        if not isinstance(rule.get("unlisted", []), list):
            bad("prose_rules unlisted")
        if not all(isinstance(g, dict) and "key" in g for g in rule.get("unlisted", [])):
            bad("prose_rules unlisted entry")
        for g in rule["gaps"] + rule.get("unlisted", []):
            if not isinstance(g, dict) or not isinstance(g.get("why"), str) or ("key" in g and not re.fullmatch(r"[0-9a-f-]{8}/[0-9a-f]{2}", str(g["key"]))):
                bad("prose_rules gap")


def load(path=None, expected_sha256=None):
    """資料表 → Table；讀不到、超過上限、sha256 不符、JSON 或結構不對 → TableError。expected_sha256 預設用程式裡固定的值。"""
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
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise TableError("table-unreadable", "not valid JSON")
    validate(doc)
    return Table(doc, sha)


def load_default():
    """→ (Table 或 None, 失敗時的 TableError 或 None)。"""
    try:
        return load(), None
    except TableError as e:
        return None, e


def fms_of(cpuid):
    """CPUID（8 位十六進位）→ 'FF-MM-SS'（family-model-stepping，小寫十六進位）；格式不對 → None。
    family ＝ base family（family 為 0xF 時加 extended family）；model ＝ extended model:model（family 6 或 0xF 時）；stepping 在最低 4 位元。"""
    if not isinstance(cpuid, str) or not CPUID_RE.fullmatch(cpuid):
        return None
    v = int(cpuid, 16)
    fam = (v >> 8) & 0xF
    model = (v >> 4) & 0xF
    if fam in (0x6, 0xF):
        model |= ((v >> 16) & 0xF) << 4
    if fam == 0xF:
        fam += (v >> 20) & 0xFF
    return "%02x-%02x-%02x" % (fam, model, v & 0xF)


def rev_value(rev):
    """'0xF8'／'0x000000F8' → 整數（無號 32 位）；格式不對 → None。"""
    if not isinstance(rev, str) or not REV_RE.fullmatch(rev):
        return None
    return int(rev, 16)


def pf_value(pf):
    """'0x94' → '94'（遮罩的兩位小寫十六進位）；格式不對 → None。"""
    if not isinstance(pf, str) or not PF_RE.fullmatch(pf):
        return None
    return "%02x" % int(pf, 16)


def _na(reason, basis, **extra):
    return {"match": "NOT_ASSESSED", "reason": reason, "basis": basis + "; " + NO_DATA, "candidates": [], "releases": [],
            "latest_revision": None, "latest_release": None, "notes": [], **extra}


def unavailable(err):
    """資料表不能用（TableError）→ NOT_ASSESSED 結果。"""
    return _na(err.reason, f"the advisory table cannot be used ({err.detail})")


class _Cands:
    """候選公告的累積：id -> {id, releases, how}。"""

    def __init__(self, table):
        self.table = table
        self.by = {}
        self.tags = set()

    def add(self, tag, how=None):
        self.tags.add(tag)
        for sa, h in self.table.security.get(tag, []):
            c = self.by.setdefault(sa, {"id": sa, "releases": [], "how": []})
            if tag not in c["releases"]:
                c["releases"].append(tag)
            hw = how or h
            if hw not in c["how"]:
                c["how"].append(hw)

    def result(self):
        order = lambda t: -self.table.index[t]               # 舊 → 新
        out = sorted(self.by.values(), key=lambda c: c["id"])
        for c in out:
            c["releases"].sort(key=order)
        return out, sorted(self.tags, key=order)


def _superseding(table, fms, pf, own_newest):
    """同一個 F-M-S 的其他 platform 遮罩，在比 own_newest 更新的 release 還有 new／updated 的：
    → ([與 SBOM 遮罩有交集的], [互不相交的])，每項 (遮罩, 最新 revision, 最新 release, [更新的 release tag（舊→新）])。"""
    inter, disjoint = [], []
    mine = int(pf, 16)
    for other in sorted(table.fms_pis.get(fms, ())):
        if other == pf:
            continue
        upd = [e for e in table.events.get((fms, other), []) if e[1] in ("new", "updated")]
        if not upd:
            continue
        later = sorted({e[0] for e in upd if e[0] < own_newest}, reverse=True)
        if not later:
            continue
        top = min(e[0] for e in upd)
        latest = sorted({e[3] for e in upd if e[0] == top})[-1]
        item = (other, latest, table.releases[top]["tag"], [table.releases[i]["tag"] for i in later])
        (inter if mine & int(other, 16) else disjoint).append(item)
    return inter, disjoint


def match_signature(table, cpuid, platform_id, revision):
    """一組 (CPUID, platform id, revision) 的比對 → dict（match、reason、basis、candidates、releases、latest_revision、latest_release、notes）。
    candidates：[{"id", "releases": [tag…], "how": [...]}]。規則見檔頭。"""
    sig = f"CPUID {cpuid} platform id {platform_id} revision {revision}"
    fms = fms_of(cpuid)
    if fms is None:
        return _na("bad-cpuid", f"{sig}: CPUID is not an 8-digit hexadecimal value")
    pf = pf_value(platform_id)
    if pf is None:
        return _na("platform-unreadable", f"{sig}: platform id is not readable")
    rev = rev_value(revision)
    if rev is None:
        return _na("revision-unreadable", f"{sig}: revision is not readable")
    sigtxt = f"F-M-S {fms}/platform mask {pf} (CPUID {cpuid.upper()}) revision 0x{rev:08x}"
    pis = table.fms_pis.get(fms)
    if not pis:
        return _na("cpuid-not-in-table", f"{sigtxt}: F-M-S {fms} is not listed in the table ({table.source['tag']})")
    ev = table.events.get((fms, pf))
    if not ev:
        return _na("platform-mismatch", f"{sigtxt}: F-M-S {fms} is listed only with platform mask(s) {', '.join(sorted(pis))}, not {pf}")
    main = [e for e in ev if e[1] != "disclosed"]
    cands = _Cands(table)
    notes, extra = [], []

    # 6.b 揭露表：revision ≤ 那一列 Old／New 中有值的較大者 → 揭露那個 release 的公告
    for e in ev:
        if e[1] != "disclosed":
            continue
        vals = [int(x, 16) for x in (e[2], e[3]) if _hex8(x)]
        if vals and rev <= max(vals):
            cands.add(e[4], "disclosed")
            extra.append(f"the 'New Disclosures Updated in Prior Releases' table of {e[4]} lists this signature up to revision 0x{max(vals):08x}; "
                         "its advisories are candidates by the disclosure table (release level)")
        elif vals:
            notes.append(f"this signature also appears in the 'New Disclosures Updated in Prior Releases' table of {e[4]} (up to 0x{max(vals):08x}); "
                         "the revision is above that, so it is not used")
    # 6.c 人工對照的散文
    for rule, ref in table.prose.get((fms, pf), []):
        if rev < ref:
            cands.add(rule["release"], "prose")
            extra.append(f"{rule['release']} line {rule['line']} (prose, compiled by hand, see prose_rules in the table) covers the platforms' microcode released "
                         f"in {rule['ref_release']}; this revision is below that platform's 0x{ref:08x}, so the advisories of {rule['release']} are candidates (release level)")
    for rule, why in table.prose_gaps.get((fms, pf), []):
        notes.append(f"GAP in the hand-compiled prose mapping of {rule['release']} line {rule['line']}: {why}; nothing is inferred from it")
    for rule, why in table.prose_unlisted.get((fms, pf), []):
        notes.append(f"the same F-M-S has a platform in the hand-compiled prose mapping of {rule['release']} line {rule['line']}; this platform is not mentioned there ({why})")
    if not main:
        if cands.by:
            out, tags = cands.result()
            return {"match": "affected-candidate", "reason": None, "latest_revision": None, "latest_release": None,
                    "basis": f"{sigtxt}: the table has only disclosure/prose entries for this signature; " + "; ".join(extra) + f"; {CAVEAT}; candidates are not confirmed findings",
                    "candidates": out, "releases": tags, "notes": notes}
        return _na("no-revision-history", f"{sigtxt}: the table has only a 'New Disclosures' entry for this signature, no revision history")
    newest = min(e[0] for e in main)
    newest_kinds = {e[1] for e in main if e[0] == newest}
    if "removed" in newest_kinds and not newest_kinds & {"new", "updated"}:
        tag = next(e[4] for e in main if e[0] == newest)
        return _na("removed", f"{sigtxt}: the latest table entry for this signature is a removal in {tag}")
    upd = [e for e in main if e[1] in ("new", "updated")]
    top = min(e[0] for e in upd)
    tops = {e[3] for e in upd if e[0] == top}
    if len(tops) > 1:
        return _na("ambiguous", f"{sigtxt}: release {upd[0][4]} lists different new revisions ({', '.join(sorted(tops))}) for this signature")
    latest = int(tops.pop(), 16)
    latest_tag = next(e[4] for e in upd if e[0] == top)
    base = {"latest_revision": f"0x{latest:08x}", "latest_release": latest_tag}
    listed = {int(x, 16) for e in ev for x in (e[2], e[3]) if _hex8(x)}
    for e in ev:
        if e[1] == "disclosed" and rev in {int(x, 16) for x in (e[2], e[3]) if _hex8(x)}:
            sa = table.sa_by_tag.get(e[4], [])
            notes.append(f"this revision appears in the 'New Disclosures Updated in Prior Releases' table of {e[4]}"
                         + (f"; that release lists {', '.join(sa)}" if sa else ""))
    if rev > latest:
        return {**_na("revision-newer-than-table", f"{sigtxt}: the revision is newer than the table's latest 0x{latest:08x} ({latest_tag}); "
                      "the table may be older than the firmware, or this is a BIOS-only/OEM revision"), **base, "notes": notes}
    own_newest = top
    inter, disjoint = _superseding(table, fms, pf, own_newest)
    # 6.a 比它新的 release
    newer = sorted({e[0] for e in upd if int(e[3], 16) > rev}, reverse=True) if rev < latest else []      # 等於最新（含被 revert 的）不看較舊 release 的較大值
    for i in newer:
        cands.add(table.releases[i]["tag"])
    for other, olatest, otag, later in disjoint:
        notes.append(f"the same F-M-S has another platform mask {other} (disjoint from {pf}) that is updated after {latest_tag}: "
                     f"latest 0x{olatest} ({otag}); this signature's own result is unchanged")
    sup_txt = []
    for other, olatest, otag, later in inter:
        sup_txt.append(f"platform mask {other} (overlaps {pf}) has newer updates: latest 0x{olatest} ({otag}); releases after {latest_tag}: "
                       + ", ".join(f"{t} [{', '.join(table.sa_by_tag.get(t, [])) or 'no INTEL-SA listed'}]" for t in later))
    where = "listed in the table" if rev in listed else "not listed in the table (BIOS-only/OEM revision, or older than the table's coverage)"
    first, last = table.releases[-1]["tag"], table.releases[0]["tag"]
    if rev == latest:
        head = f"{sigtxt}: equals the table's latest revision for this mask ({latest_tag})"
        higher = sorted({(int(e[3], 16), e[4]) for e in upd if int(e[3], 16) > latest})
        if higher:                                         # 歷史上出現過更大的 New Ver，後來退回現在這個 revision
            notes.append("an earlier release listed a larger revision for this signature and a later release went back to this one: "
                         + ", ".join(f"0x{v:08x} ({t})" for v, t in higher))
        if not cands.by and inter:
            return {"match": "NOT_ASSESSED", "reason": "superseded-platform-mask", "candidates": [], "releases": [], **base, "notes": notes,
                    "basis": f"{head}, but " + "; ".join(sup_txt) + "; the newer entries are reference candidates, not findings; " + NO_DATA}
        for other, olatest, otag, later in inter:             # 6.d：交集的更新也列成候選
            for t in later:
                cands.add(t, "superseded-mask")
        if cands.by:
            out, tags = cands.result()
            return {"match": "affected-candidate", "reason": None, "candidates": out, "releases": tags, **base, "notes": notes,
                    "basis": f"{head}; " + "; ".join(extra + sup_txt) + f"; {CAVEAT}; candidates are not confirmed findings"}
        return {"match": "up-to-date", "reason": None, "basis": f"{head}; {UP_TO_DATE}", "candidates": [], "releases": [], **base, "notes": notes}
    for other, olatest, otag, later in inter:
        for t in later:
            cands.add(t, "superseded-mask")
    out, tags = cands.result()
    newer_tags = [table.releases[i]["tag"] for i in newer]                 # 舊 → 新
    common = (f"{sigtxt}: revision {where}; table latest 0x{latest:08x} ({latest_tag}); {len(newer_tags)} newer release(s) "
              f"({newer_tags[0]} .. {newer_tags[-1]}); table covers {first} .. {last}") if newer_tags else \
             f"{sigtxt}: revision {where}; table latest 0x{latest:08x} ({latest_tag}); table covers {first} .. {last}"
    if out:
        return {"match": "affected-candidate", "reason": None,
                "basis": "; ".join([common] + extra + sup_txt) + f"; candidate advisories: {', '.join(c['id'] for c in out)}; {CAVEAT}; candidates are not confirmed findings",
                "candidates": out, "releases": tags, **base, "notes": notes}
    return {"match": "older-no-sa", "reason": None,
            "basis": "; ".join([common] + extra + sup_txt) + "; none of the newer releases lists an INTEL-SA in the table; this does not mean there are no vulnerabilities, refer to the Intel advisories",
            "candidates": [], "releases": tags, **base, "notes": notes}


def match_microcode(table_or_err, u):
    """SBOM／inventory 的一份微碼 dict（cpuid、platform_id、revision、extended_signatures）→ 比對結果。
    table_or_err：Table 或 TableError。結果含 per-signature 清單（signatures），整份的 match 用優先順序合併（見檔頭）。"""
    if isinstance(table_or_err, TableError):
        r = unavailable(table_or_err)
        return {**r, "signatures": [], "source": None}
    table = table_or_err
    sigs = [(u.get("cpuid"), u.get("platform_id"))] + [(x.get("cpuid"), x.get("platform_id")) for x in u.get("extended_signatures", [])]
    seen, results = set(), []
    for cpuid, pf in sigs:
        k = (str(cpuid).upper(), str(pf).upper())
        if k in seen:
            continue
        seen.add(k)
        r = match_signature(table, cpuid, pf, u.get("revision"))
        r["signature"] = {"cpuid": cpuid, "platform_id": pf}
        results.append(r)
    order = {m: i for i, m in enumerate(("affected-candidate", "NOT_ASSESSED", "older-no-sa", "up-to-date"))}
    top = min(results, key=lambda r: order[r["match"]])
    cand = {}
    for r in results:
        for c in r["candidates"]:
            m = cand.setdefault(c["id"], {"id": c["id"], "releases": [], "how": []})
            m["releases"] += [x for x in c["releases"] if x not in m["releases"]]
            m["how"] += [x for x in c["how"] if x not in m["how"]]
    if len(results) == 1:
        basis = results[0]["basis"]
    else:
        basis = " | ".join(f"[{r['signature']['cpuid']}/{r['signature']['platform_id']}] {r['match']}: {r['basis']}" for r in results)
    out = {"match": top["match"], "reason": top.get("reason") if top["match"] == "NOT_ASSESSED" else None, "basis": basis,
           "candidates": sorted(cand.values(), key=lambda c: c["id"]), "releases": top["releases"],
           "latest_revision": top["latest_revision"], "latest_release": top["latest_release"],
           "notes": [n for r in results for n in r.get("notes", [])],
           "signatures": [{"cpuid": r["signature"]["cpuid"], "platform_id": r["signature"]["platform_id"], "match": r["match"],
                           "reason": r.get("reason"), "latest_revision": r["latest_revision"]} for r in results],
           "source": table.label()}
    if top["match"] == "affected-candidate":
        out["releases"] = sorted({t for r in results for t in r["releases"]}, key=lambda t: [x["tag"] for x in table.releases].index(t), reverse=True)
    return out


def counts(results):
    """比對結果清單 → {match: 數量}（只含出現過的）。"""
    c = {}
    for r in results:
        c[r["match"]] = c.get(r["match"], 0) + 1
    return c
