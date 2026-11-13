#!/usr/bin/env python3
"""Intel 微碼發佈資料表的產生器：把 Intel 公開的 releasenote.md（固定 tag、固定 commit、固定 sha256）解析成
tools/cra/data/intel-microcode-releases.json，供 fw_advisory.py 離線比對韌體 SBOM 裡的微碼。

用法：
  python3 -I intel_ucode_releases.py generate [--source <releasenote.md>] --out <json>
      沒有 --source 時從固定的 raw.githubusercontent.com 網址（以 commit SHA 為準）下載；兩種來源都要 sha256 與固定值相符才解析。
  python3 -I intel_ucode_releases.py verify [--source <releasenote.md>] --table <json>
      重新解析固定來源，與 <json> 逐項比對（只有 generated_at 不比）；不相符退出碼 1。

輸入是不可信資料：只當文字讀、不執行；大小有上限；解析不了的行一律記進 `unparsed`（不會悄悄略過）。
這是人工執行的步驟（不在 CI 裡每次重抓）；步驟寫在 docs/notes/c2-firmware-advisory.md。

releasenote.md 的格式（2026-11-13 對固定來源逐段核對）：
- 每個 release 一段：`# Release Notes` 後接 `## [<標題>](https://github.com/.../releases/tag/<tag>)`。tag 以連結網址為準
  （有一段標題寫成 `microcode-2022027`，網址是 `microcode-20220207`）。段落由新到舊。標題沒有日期，日期只能取自 tag 名稱。
- `### Purpose`（有一段叫 `### Functional Updates`）：項目符號。`Security updates for [INTEL-SA-xxxxx](…)` 是這個 release 列的公告，
  **只在 release 層級，不分 CPUID**；寫法有 `INTEL-SA-INTEL-SA-00972`（重複前綴）、`INTEL-SA-000617`（六位數）、`Update to SA00270`（沒有
  前綴）、`Updated security updates for …`（更新先前的公告）、`[INTEL-SA-NA]`（沒有適用的公告）。
- `### New Platforms`／`### Updated Platforms`（有一段拼成 `Updated Platforms0`）／`### Removed Platforms`／
  `### New Disclosures Updated in Prior Releases`：表格 `Processor | Stepping | F-M-S/PI | Old Ver | New Ver | Products`。
  F-M-S 是 family-model-stepping（十六進位），PI 是 platform id 遮罩（8 位元，微碼檔頭的 processor flags），版本是 8 位十六進位 revision。
  Removed 表的 New Ver 是空的；New 表的 Old Ver 是空的；Disclosures 表的 New Ver 可以是 `N/A`。表格沒有內容時寫 `None`。
- `### Change History` 與其他散文：原文記在 `other`。
"""
import argparse
import hashlib
import json
import re
import sys
import urllib.request
from pathlib import Path

SCHEMA = "dumpling-intel-microcode-releases/1"
REPO_URL = "https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files"
TAG = "microcode-20261110"
COMMIT = "d71fe4e2f0f70a49ebbac7f2c7e915f181361974"
PATH = "releasenote.md"
RAW_URL = f"https://raw.githubusercontent.com/intel/Intel-Linux-Processor-Microcode-Data-Files/{COMMIT}/{PATH}"
SOURCE_SHA256 = "338b556b2e8788e68f542361d2835f1344b2ad42b40991756beb1fc8a5cf11f3"
SOURCE_BYTES = 157503
MAX_BYTES = 4 << 20
MAX_LINES = 100000
RETRIEVED = "2026-11-13"

TAG_URL = re.compile(r"^\[(?P<title>[^\]]*)\]\(https://github\.com/intel/Intel-Linux-Processor-Microcode-Data-Files/releases/tag/(?P<tag>[A-Za-z0-9._-]+)\)\s*$")
TAG_DATE = re.compile(r"^microcode-(\d{4})(\d{2})(\d{2})(?:-rev\d+|[a-z])?$")
FMS_PI = re.compile(r"^([0-9a-fA-F]{2})-([0-9a-fA-F]{2})-([0-9a-fA-F]{2})/([0-9a-fA-F]{2})$")
REV = re.compile(r"^[0-9a-fA-F]{8}$")
SA_ID = re.compile(r"(?:INTEL-SA-)+(\d{4,6})|(?<![A-Za-z0-9])SA(\d{5})(?![0-9])", re.I)
SA_NA = re.compile(r"\[INTEL-SA-NA\]", re.I)
SA_URL = re.compile(r"/advisory/(intel-sa-\d{4,6})\.html", re.I)
SECTIONS = {"purpose": "purpose", "functional updates": "purpose", "new platforms": "new", "updated platforms": "updated",
            "removed platforms": "removed", "new disclosures updated in prior releases": "disclosed", "change history": "history"}
ROW_KINDS = ("new", "updated", "removed", "disclosed")
HEADER = ["processor", "stepping", "f-m-s/pi", "old ver", "new ver", "products"]


class GenError(Exception):
    pass


def norm_sa(num):
    """INTEL-SA 編號 → INTEL-SA-NNNNN（五位數；六位數且開頭是 0 的去掉一個 0）。"""
    n = int(num)
    return "INTEL-SA-%05d" % n


def tag_date(tag):
    m = TAG_DATE.match(tag)
    if not m:
        return None
    y, mo, d = (int(x) for x in m.groups())
    if not (2000 <= y <= 2100 and 1 <= mo <= 12 and 1 <= d <= 31):
        return None
    return "%04d-%02d-%02d" % (y, mo, d)


def security_bullet(text):
    """Purpose 的一個項目 → (how, [INTEL-SA…], na) 或 None（不是公告項目）。how：security／updated／update-to。"""
    t = text.strip()
    low = t.lower()
    if low.startswith("security updates for"):
        how = "security"
    elif low.startswith("updated security updates for"):
        how = "updated"
    elif low.startswith("update to sa"):
        how = "update-to"
    else:
        return None
    ids = []
    for m in SA_ID.finditer(t):
        sa = norm_sa(m.group(1) or m.group(2))
        if sa not in ids:
            ids.append(sa)
    return how, ids, bool(SA_NA.search(t))


def row_cells(line):
    s = line.strip()
    if not s.startswith("|"):
        return None
    s = s[1:]
    if s.endswith("|"):
        s = s[:-1]
    return [c.strip() for c in s.split("|")]


def parse(text):
    """releasenote.md 的全文 → {"releases": [...], "unparsed": [...]}。看不懂的行記進 unparsed（行號、所在 release／區段、原文前 300 字）。"""
    lines = text.splitlines()
    if len(lines) > MAX_LINES:
        raise GenError(f"行數超過 {MAX_LINES}")
    releases, unparsed = [], []
    cur = None
    section = None            # purpose／new／updated／removed／disclosed／history／None
    last_bullet = None        # 前一個 Purpose 項目（接續行用）：(類型, index)
    header_seen = False

    def note(i, why, raw):
        unparsed.append({"line": i, "release": cur["tag"] if cur else None, "section": section, "why": why, "text": raw.strip()[:300]})

    for i, raw in enumerate(lines, 1):
        line = raw.rstrip("\r\n")
        s = line.strip()
        if not s:
            continue
        if s == "# Release Notes":
            section, last_bullet = None, None
            continue
        if s.startswith("## "):
            m = TAG_URL.match(s[3:])
            if m:
                tag = m.group("tag")
                cur = {"tag": tag, "date": tag_date(tag), "security": [], "security_na": False, "functional_updates": 0,
                       "purpose_other": [], "other": [], "new": [], "updated": [], "removed": [], "disclosed": []}
                if cur["date"] is None:
                    note(i, "tag 名稱不是 microcode-YYYYMMDD 形式，沒有日期", s)
                if m.group("title") != tag:
                    cur["heading"] = m.group("title")
                if any(r["tag"] == tag for r in releases):
                    raise GenError(f"第 {i} 行：重複的 release {tag}")
                releases.append(cur)
                section, last_bullet, header_seen = None, None, False
            elif cur is not None:        # release 內的 `## Update: …` 之類的小標題：原文保留
                cur["other"].append(s[3:].strip()[:300])
            else:
                note(i, "release 標題之前的 ## 標題", s)
            continue
        if cur is None:
            note(i, "第一個 release 標題之前的內容", s)
            continue
        if s.startswith("### "):
            name = s[4:].strip()
            key = SECTIONS.get(name.lower())
            if key is None and name.lower().rstrip("0123456789") in SECTIONS and name.lower().endswith("0"):
                key = SECTIONS[name.lower().rstrip("0")]            # `Updated Platforms0`：多了一個 0 的筆誤
                note(i, f"小標題 `{name}` 多了尾碼，當成 `{name.rstrip('0')}` 讀", s)
            if key is None:
                section = None
                note(i, "不認得的小標題；底下的內容不當成資料", s)
            else:
                section = key
            last_bullet, header_seen = None, False
            continue
        if s.startswith("|"):
            cells = row_cells(s)
            if section not in ROW_KINDS:
                note(i, "表格不在 New／Updated／Removed／Disclosures 區段裡", s)
                continue
            if all(re.fullmatch(r":?-{3,}:?", c) for c in cells):
                continue
            if [c.lower() for c in cells] == HEADER:
                header_seen = True
                continue
            if not header_seen:
                note(i, "表格沒有認得的表頭就出現資料列", s)
                continue
            if len(cells) != 6:
                note(i, f"表格列有 {len(cells)} 欄（預期 6）", s)
                continue
            proc, step, fms, old, new, _products = cells
            m = FMS_PI.match(fms)
            if not m:
                note(i, "F-M-S/PI 不是 FF-MM-SS/PI 形式", s)
                continue
            bad = [v for v in (old, new) if v and v.upper() != "N/A" and not REV.match(v)]
            if bad:
                note(i, "Old Ver／New Ver 不是 8 位十六進位", s)
                continue
            if not proc:
                note(i, "沒有 Processor 欄", s)
                continue
            if section == "new" and old:
                note(i, "New Platforms 的 Old Ver 不是空的（照記）", s)
            if section == "removed" and new:
                note(i, "Removed Platforms 的 New Ver 不是空的（照記）", s)
            if section in ("updated", "new") and (not new or new.upper() == "N/A"):
                note(i, "New／Updated Platforms 沒有 New Ver，這一列沒有收", s)
                continue
            cur[section].append(["%s-%s-%s" % tuple(x.lower() for x in m.groups()[:3]), m.group(4).lower(),
                                 "N/A" if old.upper() == "N/A" else old.lower(), "N/A" if new.upper() == "N/A" else new.lower(),
                                 proc, step])
            continue
        if section == "purpose":
            if s.startswith("- "):
                body = s[2:].strip()
                sb = security_bullet(body)
                if sb is not None:
                    how, ids, na = sb
                    if na:
                        cur["security_na"] = True
                    elif not ids:
                        note(i, "像公告項目但讀不到 INTEL-SA 編號", s)
                    urls = {u.lower() for u in SA_URL.findall(body)}
                    if urls and ids and {x.lower() for x in ids} != urls:
                        note(i, "文字的編號與連結網址的編號不同（以文字為準）", s)
                    for sa in ids:
                        cur["security"].append({"id": sa, "how": how})
                    last_bullet = None
                elif body.startswith("Update for functional issues."):
                    cur["functional_updates"] += 1
                    last_bullet = ("func", None)
                else:
                    cur["purpose_other"].append(body[:300])
                    last_bullet = ("other", len(cur["purpose_other"]) - 1)
                continue
            if last_bullet is not None and not s.startswith("#"):
                if last_bullet[0] == "other":
                    cur["purpose_other"][last_bullet[1]] = (cur["purpose_other"][last_bullet[1]] + " " + s)[:300]
                continue          # 功能更新項目的接續行（長網址換行）
            if s.startswith("*") and s.endswith("*"):
                cur["other"].append(s.strip("*").strip()[:300])
                continue
            cur["other"].append(s[:300])
            note(i, "Purpose 裡的非項目文字，原文記在 other", s)
            continue
        if section in ROW_KINDS:
            if s == "None":
                continue
            note(i, "表格區段裡的非表格文字", s)
            continue
        if section == "history":
            cur["other"].append(s[:300])
            continue
        note(i, "區段之外的文字", s)
    for r in releases:
        add_text_removals(r)
    if not releases:
        raise GenError("沒有找到任何 release 段落")
    return {"releases": releases, "unparsed": unparsed}


TEXT_REMOVED = re.compile(r"\bRemoved\s+([A-Za-z0-9_+-]+)/([0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2})/([0-9a-fA-F]{2})\b")


def add_text_removals(rel):
    """Purpose 的文字寫「Removed <名稱>/<F-M-S>/<PI> due to …」而 Removed Platforms 表沒有那一列時（microcode-20260812 只有文字），
    補一列 removed（Old Ver 與 Stepping 沒寫，留空；processor 記文字裡的名稱）。表裡已經有同一個 F-M-S／PI 的不重複補。"""
    have = {(x[0], x[1]) for x in rel["removed"]}
    for text in rel["purpose_other"]:
        for m in TEXT_REMOVED.finditer(text):
            fms, pi = m.group(2).lower(), m.group(3).lower()
            if (fms, pi) not in have:
                rel["removed"].append([fms, pi, "", "", m.group(1), ""])
                have.add((fms, pi))


def check_order(releases):
    """段落應由新到舊（依 tag 日期）；不是的列出來。"""
    out = []
    prev = None
    for r in releases:
        if r["date"] and prev and r["date"] > prev[1]:
            out.append(f"{r['tag']}（{r['date']}）排在 {prev[0]}（{prev[1]}）之後，順序不是由新到舊")
        if r["date"]:
            prev = (r["tag"], r["date"])
    return out


def read_source(path=None):
    """固定來源的文字（核對 sha256 與大小）。path 給了就讀檔，否則從固定網址下載。"""
    if path:
        p = Path(path)
        if p.is_symlink() or not p.is_file():
            raise GenError("--source 不是一般檔案")
        with open(p, "rb") as fh:
            data = fh.read(MAX_BYTES + 1)
    else:
        req = urllib.request.Request(RAW_URL, headers={"User-Agent": "dumpling-intel-ucode-releases"})
        with urllib.request.urlopen(req, timeout=60) as r:       # 固定的 https 網址（以 commit SHA 為準）
            data = r.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise GenError("來源超過上限")
    sha = hashlib.sha256(data).hexdigest()
    if sha != SOURCE_SHA256 or len(data) != SOURCE_BYTES:
        raise GenError(f"來源的 sha256／大小與固定值不符（{sha}、{len(data)} bytes；預期 {SOURCE_SHA256}、{SOURCE_BYTES}）")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise GenError("來源不是 UTF-8")


def build(text, generated_at):
    p = parse(text)
    rel = p["releases"]
    order = check_order(rel)
    unparsed = p["unparsed"] + [{"line": None, "release": None, "section": None, "why": x, "text": ""} for x in order]
    return {
        "schema": SCHEMA,
        "source": {"repo": REPO_URL, "tag": TAG, "commit": COMMIT, "path": PATH, "url": RAW_URL, "sha256": SOURCE_SHA256,
                   "bytes": SOURCE_BYTES, "retrieved": RETRIEVED},
        "generator": "tools/cra/intel_ucode_releases.py",
        "generated_at": generated_at,
        "row_format": ["f-m-s", "platform-id-mask", "old-revision", "new-revision", "processor", "stepping"],
        "notes": ["releases 由新到舊（照來源順序）；date 取自 tag 名稱（來源標題沒有日期）。",
                  "security 是 release 層級的公告清單：來源沒有逐 CPUID 列出公告。",
                  "new／updated 是各 F-M-S／platform id 的 revision 變化；removed 是移除（沒有 New Ver）；disclosed 是「New Disclosures Updated in Prior Releases」表，不當成新 revision。",
                  "資料表只涵蓋來源列出的 release；來源的 releases 數與最舊 tag 見 coverage。"],
        "coverage": {"releases": len(rel), "newest": rel[0]["tag"], "oldest": rel[-1]["tag"],
                     "rows": {k: sum(len(r[k]) for r in rel) for k in ROW_KINDS}},
        "unparsed": unparsed,
        "releases": rel,
    }


def dump(doc):
    """穩定的 JSON 輸出：結構縮排、只含純量的陣列（資料列）收成一行。"""
    s = json.dumps(doc, ensure_ascii=False, indent=1, sort_keys=False)
    s = re.sub(r'\[\n\s+((?:"[^"\n]*"|-?\d+|null|true|false)(?:,\n\s+(?:"[^"\n]*"|-?\d+|null|true|false))*)\n\s+\]',
               lambda m: "[" + ", ".join(x.strip() for x in m.group(1).split(",\n")) + "]", s)
    return s + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0], allow_abbrev=False)
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate", allow_abbrev=False)
    g.add_argument("--source")
    g.add_argument("--out", required=True)
    g.add_argument("--generated-at", help="寫進資料表的產生時間（預設現在 UTC，ISO 8601）")
    v = sub.add_parser("verify", allow_abbrev=False)
    v.add_argument("--source")
    v.add_argument("--table", required=True)
    a = ap.parse_args(argv)
    try:
        text = read_source(a.source)
        if a.cmd == "generate":
            import datetime
            at = a.generated_at or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            doc = build(text, at)
            out = Path(a.out)
            tmp = out.with_name("." + out.name + ".tmp")
            tmp.write_text(dump(doc), encoding="utf-8")
            tmp.replace(out)
            data = out.read_bytes()
            print(f"INTEL-UCODE-RELEASES\tOK\t{doc['coverage']['releases']} releases、{sum(doc['coverage']['rows'].values())} 列、"
                  f"unparsed {len(doc['unparsed'])}；表 sha256 {hashlib.sha256(data).hexdigest()}")
            return 0
        have = json.loads(Path(a.table).read_text(encoding="utf-8"))
        want = build(text, have.get("generated_at"))
        if have != want:
            print("INTEL-UCODE-RELEASES\tFAIL\t資料表與固定來源重新解析的結果不同（只有 generated_at 不比）")
            return 1
        print("INTEL-UCODE-RELEASES\tOK\t資料表與固定來源重新解析的結果相同")
        return 0
    except (GenError, OSError, ValueError) as e:
        print(f"INTEL-UCODE-RELEASES\tFAIL\t{e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
