#!/usr/bin/env python3
"""兩份同一產品的報告比較：列出哪些列新增、消失、分類或判定改變，並盡量附上原因。一個指令。

用法：
    python3 -I tools/cra/report_diff.py --previous <舊報告資料夾> --current <新報告資料夾> --out <新的空資料夾>
        [--grype-db <vulnerability.db>]

報告資料夾：report_package.py 的輸出（有 內部存檔/vulnerability-rows.json），或 cra_report.py 的 Reports 資料夾。
輸出：
    changes-since-previous.json   機器可讀（內部）
    changes-since-previous.zh.md  中文（內部）
    changes-since-previous.md     英文（可給客戶；過 supplier_package.check_customer_text）

規則：
- 原因只寫證據撐得住的：元件版本變了、元件不見了、（有給 --grype-db 時）資料庫現在標示發行版不受影響／CVE 已撤回；
  其餘一律寫「原因未判定」，不猜。有給 --grype-db 時，資料庫是「這一次」用的版本，只能證明現在的狀態，不能證明舊報告當時的狀態；
  舊報告當時的狀態只引用它自己列上的 fix_state。
- 兩份報告的矛盾並列：舊的、新的都寫出來，不改寫任何一邊。
- 只用標準函式庫。
"""
import argparse
import collections
import json
import re
import sqlite3
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

ROWS_FILE = "vulnerability-rows.json"
ROWS_SCHEMA = "sca-center-vulnerability-rows/1"
SCHEMA = "sca-center-report-diff/1"
ARCH = "內部存檔"
PURPOSE_EN = "Rows that were added or removed since the previous report, and changes in status, with reasons where they could be determined"
OUT_JSON, OUT_ZH, OUT_EN = "changes-since-previous.json", "changes-since-previous.zh.md", "changes-since-previous.md"

TIER_EN = {"p1": "Priority (known exploited)", "p3": "Tracked", "nvidia_bulletin": "Under assessment (supplier bulletin)",
           "accepted": "Assessed, not affected", "distro_fixed": "Fixed by the distribution"}
TIER_ZH = {"p1": "立即處理（P1）", "p3": "持續追蹤", "nvidia_bulletin": "NVIDIA 公告評估中", "accepted": "經評估不受影響",
           "distro_fixed": "發行版已修補"}
STATE_EN = {"exploitable": "affected", "in_triage": "under assessment", "resolved": "fixed", "not_affected": "not affected",
            "false_positive": "not affected", None: "no statement"}
STATE_ZH = {"exploitable": "受影響", "in_triage": "評估中", "resolved": "已修補", "not_affected": "不受影響",
            "false_positive": "誤報", None: "無判定"}


class DiffError(Exception):
    pass


# ---------------------------------------------------------------- 讀取

def find_dirs(folder):
    """→ (rows 檔所在資料夾, 放 summary／scan-status 的資料夾)。"""
    f = Path(folder)
    for d in (f / ARCH, f):
        if (d / ROWS_FILE).is_file():
            return d
    raise DiffError(f"{folder} 裡找不到 {ROWS_FILE}（要給 report_package 的輸出，或 cra_report 的 Reports 資料夾）")


def read_rows(d):
    p = d / ROWS_FILE
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise DiffError(f"{p} 讀不了：{e}")
    if not isinstance(doc, dict) or doc.get("schema") != ROWS_SCHEMA or not isinstance(doc.get("rows"), list):
        raise DiffError(f"{p} 不是 {ROWS_SCHEMA} 格式")
    out = {}
    for r in doc["rows"]:
        k = (str(r.get("id")), str(r.get("component")), str(r.get("version")))
        if k in out:
            raise DiffError(f"{p} 有重複的列 {k}")
        out[k] = r
    return doc, out


def stage_map(d):
    """scan-status.tsv → {stage: (status, detail)}；沒有就是空的（資料日期標「未記錄」）。"""
    p = d / "scan-status.tsv"
    res = {}
    if p.is_file():
        for ln in p.read_text(encoding="utf-8", errors="replace").splitlines()[1:]:
            c = ln.split("\t", 2)
            if len(c) >= 2:
                res[c[0]] = (c[1], c[2] if len(c) > 2 else "")
    return res


def read_sbom(folder):
    """→ {"names": {SBOM 名稱: {版本}}, "aliases": {purl 名稱或 upstream 來源套件名: {版本}}}；找不到或讀不了就是 None（不猜）。
    列的元件名常是來源套件名（acl），SBOM 裡是二進位套件名（libacl1，purl 的 upstream=acl），所以三種名稱都要比。"""
    for p in (Path(folder) / "交給PM" / "SBOM" / "sbom.cdx.json", Path(folder) / "sbom.cdx.json", Path(folder) / ARCH / "sbom.cdx.json"):
        if p.is_file():
            try:
                comps_ = json.loads(p.read_text(encoding="utf-8")).get("components") or []
            except (OSError, ValueError, AttributeError):
                return None
            names, aliases = collections.defaultdict(set), collections.defaultdict(set)
            for c in comps_:
                if not (isinstance(c, dict) and c.get("name") and c.get("version")):
                    continue
                v = str(c["version"])
                names[c["name"]].add(v)
                purl = str(c.get("purl") or "")
                m = re.match(r"pkg:[^/]+/(?:[^/@?]+/)?([^/@?]+)@", purl)
                if m:
                    aliases[m.group(1)].add(v)
                up = purl_parts(purl).get("upstream")
                if up:
                    aliases[re.sub(r"[ (].*", "", up)].add(v)
            return {"names": names, "aliases": aliases}
    return None


def data_info(d, doc):
    """工具版本與資料日期，取自 scan-status.tsv 與 summary.json；沒有的欄位是 None（不猜）。"""
    st = stage_map(d)

    def grab(stage, rx):
        m = re.search(rx, st.get(stage, ("", ""))[1])
        return m.group(1) if m else None

    tools = {}
    for m in re.finditer(r"\b([A-Za-z][\w-]*) (\d+\.\d+[\w.+-]*)", st.get("A-tools", ("", ""))[1]):
        tools[m.group(1)] = m.group(2)
    dt = grab("D-dt-project", r"DT (\d+\.\d+[\w.]*)")
    if dt:
        tools["Dependency-Track"] = dt
    gen = None
    try:
        gen = json.loads((d / "summary.json").read_text(encoding="utf-8")).get("generated")
    except (OSError, ValueError, AttributeError):
        pass
    return {"report_generated": gen or doc.get("generated"),
            "tools": tools or None,
            "vuln_db_built": grab("C-grype-db", r"Built=(\S+?)（"),
            "ubuntu_tracker_fetched": grab("D-ubuntu-status", r"fetched_utc=([0-9TZ:\-]+)"),
            "ubuntu_tracker_commit": grab("D-ubuntu-status", r"Tracker commit (\w+)"),
            "ubuntu_priority_fetched": grab("D-ubuntu-priority", r"fetched_utc=([0-9TZ:\-]+)"),
            "nvd_completed": grab("D-dt-data-sources", r"NVD COMPLETED（完成 ([0-9TZ:\-]+)"),
            "osv_completed": grab("D-dt-data-sources", r"OSV COMPLETED（完成 ([0-9TZ:\-]+)"),
            "euvd_downloaded": grab("C-euvd", r"索引下載於 ([0-9TZ:\-]+)"),
            "mirror_finished": grab("C-mirror-freshness", r"finished=([0-9TZ:\-]+)")}


# ---------------------------------------------------------------- 資料庫（選用，唯讀）

def purl_parts(purl):
    q = {}
    if purl and "?" in purl:
        for kv in purl.split("?", 1)[1].split("#")[0].split("&"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                q[k] = v
    return q


class GrypeDb:
    def __init__(self, path):
        try:
            self.c = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            self.built = self.c.execute("select build_timestamp from db_metadata").fetchone()[0]
        except sqlite3.Error as e:
            raise DiffError(f"弱點資料庫 {path} 讀不了：{e}")
        self.path = str(path)

    def lookup(self, row):
        """→ dict：這個 CVE 在資料庫裡對這個發行版與套件現在的狀態。不是 deb／沒有 distro 時回 None（不查）。"""
        q = purl_parts(row.get("purl"))
        m = re.match(r"(ubuntu|debian)-(\d+)", q.get("distro", ""))
        if not m or not str(row.get("purl", "")).startswith("pkg:deb/"):
            return None
        osn, major = m.group(1), m.group(2)
        pkg = re.sub(r"[ (].*", "", q.get("upstream") or row["component"])
        vid = row["id"]
        h = self.c.execute("select status,published_date,modified_date,withdrawn_date from vulnerability_handles where name=? and provider_id=?",
                           (vid, osn)).fetchall()
        res = {"os": q["distro"].replace("ubuntu-", "Ubuntu ").replace("debian-", "Debian "), "package": pkg, "record": bool(h),
               "status": h[0][0] if h else None, "published": h[0][1] if h else None, "modified": h[0][2] if h else None,
               "withdrawn": h[0][3] if h else None}
        for t in ("affected", "unaffected"):
            sql = (f"select b.value from {t}_package_handles x join vulnerability_handles v on v.id=x.vulnerability_id "
                   "join operating_systems o on o.id=x.operating_system_id join packages p on p.id=x.package_id "
                   "left join blobs b on b.id=x.blob_id where v.name=? and o.name=? and o.major_version=? and p.name=?")
            states = []
            for (blob,) in self.c.execute(sql, (vid, osn, major, pkg)):
                try:
                    for r in json.loads(blob)["ranges"]:
                        states.append(r.get("fix", {}).get("state"))
                except (TypeError, ValueError, KeyError):
                    states.append("unreadable")
            res[t] = sorted(set(states))
        return res


# ---------------------------------------------------------------- 比較

def rk(r):
    return {"id": r["id"], "component": r["component"], "version": r["version"]}


def vex_view(r):
    v = r.get("vex") or {}
    return {"state": v.get("state"), "source": v.get("source"), "rule": v.get("rule")}


def presence(comp, ver, by_comp, sbom):
    """元件在另一份報告裡的狀態：same（同版本還在）／other（版本不同，回傳版本）／absent／None（不知道，不下結論）。
    先看那份報告的列；沒有列再看 SBOM 的名稱，其次 purl 名稱與 upstream（來源套件名）。
    只有名稱完全相符才拿版本比；只靠 purl／upstream 對到名稱時，版本相同才算 same，否則不下結論（二進位套件版本可能和來源套件不同）。
    三種名稱都對不到才是 absent。"""
    vers = by_comp.get(comp)
    if vers is None and sbom is not None:
        vers = sbom["names"].get(comp)
        if vers is None:
            al = sbom["aliases"].get(comp)
            if al is None:
                return "absent", None
            return ("same", None) if ver in al else (None, None)
    if vers is None:
        return None, None
    return ("same", None) if ver in vers else ("other", ", ".join(sorted(vers)))


def reason_removed(r, cur_by_comp, cur_sbom, dbi, dates):
    comp, ver = r["component"], r["version"]
    pres, other = presence(comp, ver, cur_by_comp, cur_sbom)
    if pres == "other":
        return "version_changed", {"old": ver, "new": other}, None
    if pres == "absent":
        return "component_removed", {}, None
    ev = dbi.lookup(r) if dbi else None
    if ev:
        if ev["withdrawn"] or ev["status"] in ("rejected", "withdrawn"):
            return "db_rejected", {}, ev
        if ev["unaffected"] and not ev["affected"]:
            return "db_not_affected", {"os": ev["os"], "pkg": ev["package"]}, ev
        if ev["affected"]:
            return "db_still_affected", {"os": ev["os"], "pkg": ev["package"]}, ev
    if pres is None:
        return "component_absent", {}, ev
    return "data_unknown", {"prev_db": dates[0].get("vuln_db_built"), "cur_db": dates[1].get("vuln_db_built")}, ev


def reason_added(r, prev_by_comp, prev_sbom, dbi, dates):
    comp, ver = r["component"], r["version"]
    pres, other = presence(comp, ver, prev_by_comp, prev_sbom)
    if pres == "other":
        return "version_changed", {"old": other, "new": ver}, None
    if pres == "absent":
        return "component_new", {}, None
    if pres is None:
        return "component_new_rows", {}, None
    ev = dbi.lookup(r) if dbi else None
    pb = dates[0].get("vuln_db_built")
    if ev and ev["record"] and pb and ev["modified"] and str(ev["modified"]).replace(" ", "T")[:19] > pb.replace("Z", "")[:19]:
        return "db_modified_after", {"modified": str(ev["modified"])[:19], "prev_db": pb}, ev
    return "data_unknown", {"prev_db": pb, "cur_db": dates[1].get("vuln_db_built")}, ev


def compute(prev_dir, cur_dir, grype_db=None):
    pd, cd = find_dirs(prev_dir), find_dirs(cur_dir)
    pdoc, prev = read_rows(pd)
    cdoc, cur = read_rows(cd)
    dates = (data_info(pd, pdoc), data_info(cd, cdoc))
    dbi = GrypeDb(grype_db) if grype_db else None
    psb, csb = read_sbom(prev_dir), read_sbom(cur_dir)
    pc, cc = collections.defaultdict(set), collections.defaultdict(set)
    for (_, c, v) in prev:
        pc[c].add(v)
    for (_, c, v) in cur:
        cc[c].add(v)
    removed, added = [], []
    for k in sorted(set(prev) - set(cur)):
        code, par, ev = reason_removed(prev[k], cc, csb, dbi, dates)
        removed.append({**rk(prev[k]), "tier": prev[k]["tier"], "vex": vex_view(prev[k]), "fix_state": prev[k].get("fix_state"),
                        "reason": code, "reason_params": par, **({"db_evidence": ev} if ev else {})})
    for k in sorted(set(cur) - set(prev)):
        code, par, ev = reason_added(cur[k], pc, psb, dbi, dates)
        added.append({**rk(cur[k]), "tier": cur[k]["tier"], "vex": vex_view(cur[k]), "fix_state": cur[k].get("fix_state"),
                      "reason": code, "reason_params": par, **({"db_evidence": ev} if ev else {})})
    tier, vexc, fixc, newx, oldx = [], [], [], [], []
    for k in sorted(set(prev) & set(cur)):
        a, b = prev[k], cur[k]
        if a["tier"] != b["tier"]:
            tier.append({**rk(a), "from": a["tier"], "to": b["tier"]})
        if vex_view(a) != vex_view(b):
            vexc.append({**rk(a), "from": vex_view(a), "to": vex_view(b),
                         "fix_info_also_changed": a.get("fix_state") != b.get("fix_state")})
        if a.get("fix_state") != b.get("fix_state") or (a.get("fix_versions") or []) != (b.get("fix_versions") or []):
            fixc.append({**rk(a), "from": {"fix_state": a.get("fix_state"), "fix_versions": a.get("fix_versions") or []},
                         "to": {"fix_state": b.get("fix_state"), "fix_versions": b.get("fix_versions") or []}})
        if bool(a.get("exploited")) != bool(b.get("exploited")):
            (newx if b.get("exploited") else oldx).append({**rk(a), "tier": b["tier"], "evidence_now": b.get("exploitation_evidence") or [],
                                                           "evidence_before": a.get("exploitation_evidence") or []})
    return {"schema": SCHEMA, "internal_only_fields": ["tools", "db_evidence"],
            "previous": {"folder": Path(prev_dir).name, "rows": len(prev), **dates[0]},
            "current": {"folder": Path(cur_dir).name, "rows": len(cur), **dates[1]},
            "grype_db_check": {"path": dbi.path, "built": dbi.built} if dbi else None,
            "counts": {"added": len(added), "removed": len(removed), "tier_changed": len(tier), "vex_changed": len(vexc),
                       "fix_state_changed": len(fixc), "newly_exploited": len(newx), "no_longer_exploited": len(oldx)},
            "removed": removed, "added": added, "tier_changes": tier, "vex_changes": vexc, "fix_state_changes": fixc,
            "newly_exploited": newx, "no_longer_exploited": oldx}


# ---------------------------------------------------------------- 文字

def _d(x):
    return x or "未記錄"


def reason_zh(code, p, kind="removed"):
    return {
        "component_removed": "元件名稱（含 purl 名稱、upstream）都對不到新報告的 SBOM（已從產品移除，或不再被辨識；未判定哪一種）",
        "component_absent": "新報告裡這個元件已沒有任何列，也沒有 SBOM 可對照（可能已從產品移除，或不再被回報；未判定哪一種）",
        "component_new": "元件名稱（含 purl 名稱、upstream）都對不到舊報告的 SBOM（新增的元件，或之前沒被辨識；未判定哪一種）",
        "component_new_rows": "這個元件在舊報告裡沒有任何列，也沒有 SBOM 可對照（新增的元件，或之前沒被回報；未判定哪一種）",
        "version_changed": f"元件版本變了：{p.get('old')} → {p.get('new')}",
        "db_rejected": "資料庫現在標示這個 CVE 已撤回或駁回",
        "db_not_affected": f"弱點資料已改變：資料庫現在標示 {p.get('os')} 的 {p.get('pkg')} 不受影響（發行版狀態變更）",
        "db_still_affected": f"資料庫現在仍把 {p.get('os')} 的 {p.get('pkg')} 列為受影響，但新報告沒有這一列：原因未判定（需人工查）",
        "db_modified_after": f"資料庫的紀錄在舊報告的資料庫建置（{p.get('prev_db')}）之後才修改（{p.get('modified')}）；元件版本未變",
        "data_unknown": ("弱點資料不再回報這一筆" if kind == "removed" else "弱點資料新回報了這一筆") + "（元件與版本未變）；原因未判定"
                        + (f"（資料庫建置：{_d(p.get('prev_db'))} → {_d(p.get('cur_db'))}）" if p.get("prev_db") != p.get("cur_db") else "（兩份報告的資料庫建置時間相同）"),
    }[code]


def reason_en(code, p):
    return {
        "component_removed": "The component was not found in the new report's component list; whether it was removed from the product or is no longer identified is not determined.",
        "component_absent": "The component has no rows in the new report (it may have been removed from the product, or it is no longer reported); not determined which.",
        "component_new": "The component was not found in the previous report's component list; whether it is new or was not identified before is not determined.",
        "component_new_rows": "The component had no rows in the previous report (it is new, or it was not reported before); not determined which.",
        "version_changed": f"The installed version changed from {p.get('old')} to {p.get('new')}.",
        "db_rejected": "The vulnerability data now marks this identifier as withdrawn or rejected.",
        "db_not_affected": f"Vulnerability data changed: the distribution now lists {p.get('pkg')} on {p.get('os')} as not affected.",
        "db_still_affected": f"The vulnerability data still lists {p.get('pkg')} on {p.get('os')} as affected, but the new report has no row for it; reason not determined.",
        "db_modified_after": f"The vulnerability record was modified ({p.get('modified')}) after the previous report's data was built ({p.get('prev_db')}). The component version is unchanged.",
    }[code]


def reason_en_full(kind, code, p):
    if code == "data_unknown":
        base = ("No longer reported by the vulnerability data (the component version is unchanged); reason not determined."
                if kind == "removed" else
                "Newly reported by the vulnerability data (the component version is unchanged); reason not determined.")
        if p.get("prev_db") != p.get("cur_db"):
            base += f" Vulnerability data dates differ: {p.get('prev_db') or 'not recorded'} to {p.get('cur_db') or 'not recorded'}."
        return base
    return reason_en(code, p)


def group(items, keyf):
    g = collections.OrderedDict()
    for it in items:
        g.setdefault(keyf(it), []).append(it)
    return g


def comps(items):
    return "; ".join(f"{i['component']} {i['version']}" for i in items)


FIX_EN = {"not-fixed": "no fix available", "fixed": "fixed", "wont-fix": "the distribution will not fix", "unknown": "unknown"}


def fixname(s, lang):
    s = s or "-"
    if lang != "zh":
        s = FIX_EN.get(s, "no fix data" if "data" in s else s)
    return s


def fx(d_, lang):
    s = fixname(d_["fix_state"], lang)
    return s + (f" ({', '.join(d_['fix_versions'])})" if d_["fix_versions"] else "")


def render(d, lang):
    zh = lang == "zh"
    T = (lambda a, b: a if zh else b)
    L = []
    pv, cu, c = d["previous"], d["current"], d["counts"]
    L += [T("# 與前一份報告的差異（內部）", "# Changes since the previous report"), ""]
    L += [T("比較兩份報告的「列」（一個 CVE 在一個元件版本上的一筆）。原因只寫證據撐得住的；其餘寫「未判定」，不猜。",
            "This compares the rows of the two reports (a row is one vulnerability on one component version). Reasons are given only where the evidence supports them; otherwise the reason is stated as not determined."), ""]
    L += [T("## 資料與工具", "## Data used"), "",
          T("| 項目 | 前一份 | 這一份 |", "| Item | Previous | Current |"), "|---|---|---|"]
    nr = T("未記錄", "not recorded")
    rows = [(T("報告產生時間", "Report generated"), "report_generated"), (T("列數", "Rows"), "rows"),
            (T("弱點資料庫建置", "Vulnerability database built"), "vuln_db_built"),
            (T("Ubuntu 安全追蹤資料取得時間", "Distribution security tracker fetched"), "ubuntu_tracker_fetched"),
            (T("Ubuntu priority 資料取得時間", "Distribution priority data fetched"), "ubuntu_priority_fetched"),
            (T("NVD 資料完成時間", "NVD data completed"), "nvd_completed"), (T("OSV 資料完成時間", "OSV data completed"), "osv_completed"),
            (T("EUVD 索引下載", "EUVD index downloaded"), "euvd_downloaded")]
    if zh:
        rows += [("Ubuntu 追蹤 commit", "ubuntu_tracker_commit"), ("鏡像最近成功", "mirror_finished")]
    else:
        rows = [r for r in rows if r[1] not in ("nvd_completed", "osv_completed", "euvd_downloaded")]
        rows += [("Vulnerability data last refreshed", "mirror_finished")]
    for lab, key in rows:
        L.append(f"| {lab} | {pv.get(key) if pv.get(key) is not None else nr} | {cu.get(key) if cu.get(key) is not None else nr} |")
    if zh:
        for nm in sorted(set((pv.get("tools") or {}).keys()) | set((cu.get("tools") or {}).keys())):
            a, b = (pv.get("tools") or {}).get(nm, nr), (cu.get("tools") or {}).get(nm, nr)
            L.append(f"| {nm} | {a} | {b}{'（版本不同）' if a != b else ''} |")
    same_db = pv.get("vuln_db_built") == cu.get("vuln_db_built")
    L += ["", (T("兩份報告用的弱點資料庫建置時間" + ("相同。" if same_db else "不同；列的增減可能來自資料更新。"),
                 "The vulnerability database build time is " + ("the same in both reports." if same_db else "different; added or removed rows can come from the data update."))
                if pv.get("vuln_db_built") and cu.get("vuln_db_built") else T("至少一份報告沒有記錄弱點資料庫建置時間；不能判定資料是否相同。", "The database build time is not recorded in at least one report; it cannot be said whether the data are the same."))]
    if zh and d.get("grype_db_check"):
        L += ["", f"資料庫檢查（--grype-db）：{d['grype_db_check']['path']}，建置 {d['grype_db_check']['built']}。這是目前的資料庫，只能證明現在的狀態，不能證明舊報告當時的狀態。"]
    L += ["", T("## 摘要", "## Summary"), "", T("| 類別 | 列數 |", "| Category | Rows |"), "|---|---|"]
    names = [("added", T("新增的列", "Rows added")), ("removed", T("消失的列", "Rows removed")), ("tier_changed", T("分類改變", "Handling category changed")),
             ("vex_changed", T("判定狀態改變", "Assessment changed")), ("fix_state_changed", T("修補資訊改變", "Fix information changed")),
             ("newly_exploited", T("新增被已知利用", "Newly listed as known exploited")),
             ("no_longer_exploited", T("不再被列為已知利用", "No longer listed as known exploited"))]
    L += [f"| {n} | {c[k]} |" for k, n in names]
    L += ["", T(f"列數：{pv['rows']} → {cu['rows']}。", f"Rows: {pv['rows']} to {cu['rows']}."), ""]

    def tiername(t):
        return (TIER_ZH if zh else TIER_EN).get(t, t)

    def stname(s):
        return (STATE_ZH if zh else STATE_EN).get(s, s)

    def section(title, items, kind):
        nonlocal L
        L.append(f"## {title}")
        L.append("")
        if not items:
            L += [T("沒有。", "None."), ""]
            return
        g = group(items, lambda i: (i["id"], i["reason"], json.dumps(i["reason_params"], sort_keys=True), i["tier"],
                                     i["vex"]["state"], i["fix_state"]))
        L += [T("| CVE | 元件 | 原本分類／狀態 | 原因 |", "| CVE | Components | Category and status | Reason |") if kind == "removed" else
              T("| CVE | 元件 | 分類／狀態 | 原因 |", "| CVE | Components | Category and status | Reason |"), "|---|---|---|---|"]
        for (vid, code, par, tier, _vs, _fs), its in g.items():
            p = json.loads(par)
            why = reason_zh(code, p, kind) if zh else reason_en_full(kind, code, p)
            fs = its[0]["fix_state"]
            L.append(f"| {vid} | {comps(its)} | {tiername(tier)} / {stname(its[0]['vex']['state'])}"
                     f"{T('；修補狀態 ', '; fix status ')}{fixname(fs, lang)} | {why} |")
        L.append("")

    section(T("消失的列", "Rows removed"), d["removed"], "removed")
    section(T("新增的列", "Rows added"), d["added"], "added")

    def change_section(title, items, desc):
        nonlocal L
        L.append(f"## {title}")
        L.append("")
        if not items:
            L += [T("沒有。", "None."), ""]
            return
        L += [T("| CVE | 元件 | 之前 | 現在 | 說明 |", "| CVE | Components | Before | Now | Note |"), "|---|---|---|---|---|"]
        g = group(items, lambda i: (i["id"], json.dumps(i["from"], sort_keys=True), json.dumps(i["to"], sort_keys=True)))
        for (vid, a, b), its in g.items():
            L.append(f"| {vid} | {comps(its)} | {desc[0](json.loads(a))} | {desc[0](json.loads(b))} | {desc[1](json.loads(a), json.loads(b), its[0])} |")
        L.append("")

    same_ver = T("元件版本未變；", "Component version unchanged; ")

    def vex_note(a, b, it):
        extra = T("同一列的修補資訊也改變了（見「修補資訊改變」）。", "The fix information of the same row also changed (see below).") if it.get("fix_info_also_changed") else ""
        if a["state"] == b["state"]:
            return T(f"狀態相同（{stname(a['state'])}），依據的規則改變；原因未判定。", "the status is the same; reason not determined. ") + extra
        return T("判定狀態改變；原因未判定。", "the assessment changed; reason not determined. ") + extra

    change_section(T("分類改變", "Handling category changed"), d["tier_changes"],
                   (tiername, lambda a, b, it: same_ver + T("原因未判定；同列其他改變見下面各節。", "reason not determined; other changes to the same row are listed in the sections below.")))
    change_section(T("判定狀態改變", "Assessment changed"), d["vex_changes"],
                   ((lambda v: f"{stname(v['state'])}" + (f" ({v['rule']})" if zh and v.get("rule") else "") + (f" [{v['source']}]" if zh and v.get("source") else "")),
                    lambda a, b, it: same_ver + vex_note(a, b, it)))
    change_section(T("修補資訊改變", "Fix information changed"), d["fix_state_changes"],
                   ((lambda f: fx(f, lang)), lambda a, b, it: same_ver + T("修補資訊改變；原因未判定。", "reason not determined.")))
    for key, title, em in (("newly_exploited", T("新增被已知利用", "Newly listed as known exploited"), True),
                           ("no_longer_exploited", T("不再被列為已知利用", "No longer listed as known exploited"), False)):
        L += [f"## {title}", ""]
        if not d[key]:
            L += [T("沒有。", "None."), ""]
            continue
        L += [T("| CVE | 元件 | 證據 |", "| CVE | Components | Evidence |"), "|---|---|---|"]
        g = group(d[key], lambda i: (i["id"], json.dumps(i["evidence_now" if em else "evidence_before"])))
        for (vid, ev), its in g.items():
            e = ", ".join(json.loads(ev)) if zh else T("", "listed in a known-exploited-vulnerabilities catalogue" if em else "no longer listed in such a catalogue")
            L.append(f"| {vid} | {comps(its)} | {e or '-'} |")
        L.append("")
    return "\n".join(L).rstrip("\n") + "\n"


def customer_view(d):
    """英文版用的資料：拿掉內部欄位（工具版本、資料庫檢查路徑）。"""
    c = json.loads(json.dumps(d))
    for k in ("previous", "current"):
        c[k].pop("tools", None)
        c[k].pop("folder", None)
    c["grype_db_check"] = None
    return c


def write_outputs(d, out_dir, internal=True, customer_dir=None):
    """internal：寫 json 與中文 md；customer_dir：寫英文 md（過客戶檔案檢查，不過就丟錯，不放行）。"""
    from supplier_package import check_customer_text
    out = Path(out_dir)
    en = render(customer_view(d), "en")
    bad = check_customer_text(OUT_EN, en)
    if bad:
        raise DiffError("英文版沒過客戶檔案檢查：" + "; ".join(bad))       # 先檢查，失敗時不留空資料夾
    out.mkdir(parents=True, exist_ok=True)
    if internal:
        (out / OUT_JSON).write_text(json.dumps(d, ensure_ascii=False, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        (out / OUT_ZH).write_text(render(d, "zh"), encoding="utf-8")
    if customer_dir:
        Path(customer_dir).mkdir(parents=True, exist_ok=True)
        (Path(customer_dir) / OUT_EN).write_text(en, encoding="utf-8")
    elif internal:
        (out / OUT_EN).write_text(en, encoding="utf-8")


def register_in_package(pkg_dir, name):
    """把 name 登記進客戶資料包的 summary.json（files）與 SHA256SUMS；其餘內容不動（summary.json 自己的雜湊重算）。"""
    import hashlib
    pkg = Path(pkg_dir)
    h = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    sj, sums = pkg / "summary.json", pkg / "SHA256SUMS"
    readme = pkg / "README.md"
    if readme.is_file():           # README 的檔案表也要列出來（插在 summary.json 那一列前）
        txt = readme.read_text(encoding="utf-8")
        row = f"| `{name}` | {PURPOSE_EN} | `{h(pkg / name)}` |"
        if f"| `{name}` |" not in txt and "| `summary.json` |" in txt:
            readme.write_text(txt.replace("| `summary.json` |", row + "\n| `summary.json` |", 1), encoding="utf-8")
    if sj.is_file():
        doc = json.loads(sj.read_text(encoding="utf-8"))
        for f_ in doc.get("files", []):
            if f_.get("file") == "README.md" and readme.is_file():
                f_["sha256"] = h(readme)
        doc.setdefault("files", []).append({"file": name, "sha256": h(pkg / name), "status": "OK"})
        sj.write_text(json.dumps(doc, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    if sums.is_file():
        lines = [ln for ln in sums.read_text(encoding="utf-8").splitlines() if ln.strip()]
        keep = [ln for ln in lines if not ln.endswith(("  summary.json", "  README.md"))]
        if readme.is_file():
            keep.insert(0, f"{h(readme)}  README.md")
        keep.append(f"{h(pkg / name)}  {name}")
        if sj.is_file():
            keep.append(f"{h(sj)}  summary.json")
        sums.write_text("\n".join(keep) + "\n", encoding="utf-8")


def main(argv=None):
    ap = argparse.ArgumentParser(description="比較同一產品的兩份報告")
    ap.add_argument("--previous", required=True)
    ap.add_argument("--current", required=True)
    ap.add_argument("--out", required=True, help="新的空資料夾")
    ap.add_argument("--grype-db", help="（選用）這一次用的 vulnerability.db，唯讀，用來核對發行版狀態")
    try:
        a = ap.parse_args(argv)
    except SystemExit as e:
        return 64 if e.code else 0
    out = Path(a.out)
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        print(f"FAIL\t--out 要不存在或是空的：{out}", file=sys.stderr)
        return 1
    try:
        d = compute(a.previous, a.current, a.grype_db)
        write_outputs(d, out)
    except DiffError as e:
        print(f"FAIL\t{e}", file=sys.stderr)
        return 1
    print("\t".join(f"{k}={v}" for k, v in d["counts"].items()))
    print(f"OK\t{out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
