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
6. 相等 → up-to-date。
7. 比它舊 → 候選 ＝ New Ver 大於 SBOM revision 的 release（含曾被復原的），公告取聯集。有公告 → affected-candidate；
   沒有公告 → older-no-sa（有較新的 revision，但那些 release 沒有列公告；不是「沒有漏洞」）。
revision 以無號 32 位整數比較（十六進位，不分大小寫、前導零不影響）。有 extended signature 的微碼，每個 signature 各算一次，
整份微碼取：任何一個 affected-candidate → affected-candidate；否則任何一個 NOT_ASSESSED → NOT_ASSESSED；否則有 older-no-sa → older-no-sa；否則 up-to-date。
"""
import hashlib
import json
import re
from pathlib import Path

TABLE_PATH = Path(__file__).resolve().parent / "data" / "intel-microcode-releases.json"
# 資料表檔案本身的 sha256（重新產生資料表後要一起更新；tests 會核對）。檔案被改動、截斷或換成別的內容時，比對一律 NOT_ASSESSED。
TABLE_SHA256 = "fce67c80ab6111e60f316253ffd62b61c5342018e58d7c38e7a1508c2db8d2a9"
SCHEMA = "dumpling-intel-microcode-releases/1"
MAX_TABLE = 4 << 20
MATCHES = ("affected-candidate", "older-no-sa", "up-to-date", "NOT_ASSESSED")
NO_DATA = "no data in the database; the vendor advisory (Intel INTEL-SA) is authoritative"
NO_DATA_ZH = "資料庫沒有資料，以廠商公告為準"
CAVEAT = ("advisories are listed per release in the source, not per CPUID; a candidate advisory does not necessarily affect this CPUID")
UP_TO_DATE = "no newer revision in the table; this does not mean there are no vulnerabilities, refer to the Intel advisories"
CPUID_RE = re.compile(r"^[0-9A-Fa-f]{8}$")
REV_RE = re.compile(r"^0[xX][0-9A-Fa-f]{1,8}$")
PF_RE = re.compile(r"^0[xX][0-9A-Fa-f]{1,2}$")
ROW_KEYS = ("new", "updated", "removed", "disclosed")
SA_RE = re.compile(r"^INTEL-SA-\d{5}$")
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
        self.sa_by_tag = {}
        self.events = {}
        self.fms_pis = {}
        for i, r in enumerate(self.releases):
            ids = []
            for s in r["security"]:
                if s["id"] not in ids:
                    ids.append(s["id"])
            self.sa_by_tag[r["tag"]] = ids
            for kind in ROW_KEYS:
                for row in r[kind]:
                    self.events.setdefault((row[0], row[1]), []).append((i, kind, row[2], row[3], r["tag"]))
                    self.fms_pis.setdefault(row[0], set()).add(row[1])

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
    for r in rels:
        if not isinstance(r, dict) or not isinstance(r.get("tag"), str) or not TAG_RE.match(r["tag"]) or r["tag"] in seen:
            bad("release tag")
        seen.add(r["tag"])
        sec = r.get("security")
        if not isinstance(sec, list) or not all(isinstance(s, dict) and isinstance(s.get("id"), str) and SA_RE.match(s["id"]) for s in sec):
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
    if not isinstance(cpuid, str) or not CPUID_RE.match(cpuid):
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
    if not isinstance(rev, str) or not REV_RE.match(rev):
        return None
    return int(rev, 16)


def pf_value(pf):
    """'0x94' → '94'（遮罩的兩位小寫十六進位）；格式不對 → None。"""
    if not isinstance(pf, str) or not PF_RE.match(pf):
        return None
    return "%02x" % int(pf, 16)


def _na(reason, basis, **extra):
    return {"match": "NOT_ASSESSED", "reason": reason, "basis": basis + "; " + NO_DATA, "candidates": [], "releases": [],
            "latest_revision": None, "latest_release": None, **extra}


def unavailable(err):
    """資料表不能用（TableError）→ NOT_ASSESSED 結果。"""
    return _na(err.reason, f"the advisory table cannot be used ({err.detail})")


def match_signature(table, cpuid, platform_id, revision):
    """一組 (CPUID, platform id, revision) 的比對 → dict（match、reason、basis、candidates、releases、latest_revision、latest_release、notes）。
    candidates：[{"id", "releases": [tag…], "how": [...]}]。"""
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
    if not main:
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
    notes = []
    listed = {int(x, 16) for e in ev for x in (e[2], e[3]) if _hex8(x)}
    for e in ev:
        if e[1] == "disclosed" and rev in {int(x, 16) for x in (e[2], e[3]) if _hex8(x)}:
            sa = table.sa_by_tag.get(e[4], [])
            notes.append(f"this revision appears in the 'New Disclosures Updated in Prior Releases' table of {e[4]} (not interpreted by this tool)"
                         + (f"; that release lists {', '.join(sa)}" if sa else ""))
    if rev > latest:
        return {**_na("revision-newer-than-table", f"{sigtxt}: the revision is newer than the table's latest 0x{latest:08x} ({latest_tag}); "
                      "the table may be older than the firmware, or this is a BIOS-only/OEM revision"), **base, "notes": notes}
    if rev == latest:
        return {"match": "up-to-date", "reason": None, "basis": f"{sigtxt}: equals the table's latest revision ({latest_tag}); {UP_TO_DATE}",
                "candidates": [], "releases": [], **base, "notes": notes}
    newer = []                                   # (idx, tag)
    for e in upd:
        if int(e[3], 16) > rev and (e[0], e[4]) not in newer:
            newer.append((e[0], e[4]))
    newer.sort(key=lambda x: -x[0])              # 舊 → 新
    tags = [t for _, t in newer]
    cand = {}
    for t in tags:
        for sa in table.sa_by_tag.get(t, []):
            c = cand.setdefault(sa, {"id": sa, "releases": [], "how": []})
            c["releases"].append(t)
            for r in table.releases:
                if r["tag"] == t:
                    for s in r["security"]:
                        if s["id"] == sa and s["how"] not in c["how"]:
                            c["how"].append(s["how"])
    cands = sorted(cand.values(), key=lambda c: c["id"])
    where = "listed in the table" if rev in listed else ("not listed in the table (BIOS-only/OEM revision, or older than the table's coverage)")
    first, last = table.releases[-1]["tag"], table.releases[0]["tag"]
    common = (f"{sigtxt}: revision {where}; table latest 0x{latest:08x} ({latest_tag}); {len(tags)} newer release(s) "
              f"({tags[0]} .. {tags[-1]}); table covers {first} .. {last}")
    if cands:
        return {"match": "affected-candidate", "reason": None,
                "basis": f"{common}; candidate advisories: {', '.join(c['id'] for c in cands)}; {CAVEAT}; candidates are not confirmed findings",
                "candidates": cands, "releases": tags, **base, "notes": notes}
    return {"match": "older-no-sa", "reason": None,
            "basis": f"{common}; none of the newer releases lists an INTEL-SA in the table; this does not mean there are no vulnerabilities, refer to the Intel advisories",
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
