#!/usr/bin/env python3
"""report.py：把 sca-scan 的輸出資料夾整理成 report.html（單一檔案、內嵌 CSS、無外部資源、可離線開啟、支援深色模式）與 report.json。

用法：python3 -I tools/pilot/report.py --out <sca-scan 的輸出資料夾>

讀取（缺檔就照實標示，不猜）：
  meta.json、status.tsv、sbom/sbom.cdx.json、scan/grype.json、scan/sbomgate.json、scan/govulncheck.json、scan/kernel-coverage.json、scan/l4t-kernel-map.json、scan/nvidia-bulletins.json、
  dt/findings.json、dt/deb-sources.json、dejacode/compliance.json、dejacode/scio-summary.json

規則（專案驗收原則、試行版範圍）：
- 任何非 OK 的階段（未完成或不完整）放在最前面；整體狀態只有 FAIL／INCOMPLETE／COMPLETE，COMPLETE 也不代表沒有弱點。
- 報告自己不寫任何結論字樣（FORBIDDEN_WORDS，測試會檢查）；0 筆比對只描述為「比對結果 0 筆」並附範圍說明。
  階段說明與工具輸出原樣顯示（不改寫證據）；conclusion_hits() 找出肯定句的結論字樣，只放行「不代表…」「不可當作…」這類否定句型。
- Grype 與 DT 的結果並列，不互相覆蓋；不一致處列出。
- 版本未知（規則 13，sbomgate 判定）的元件另列；對它們的比對（Grype 與 DT 都一樣）移到「未比對」區，不算進弱點計數。
退出碼：0 報告已產生；3 輸入資料夾不存在；4 內部錯誤。
"""
import argparse
import collections
import html
import json
import os
import re
import sys
from urllib.parse import unquote, urlsplit

STATUSES = ("FAIL", "NOT_ASSESSED", "GAP", "NOT_RUN", "ATTENTION", "OK")   # 由嚴重到輕；排序用
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "UNKNOWN")
SEV_LABEL = {"CRITICAL": "嚴重", "HIGH": "高", "MEDIUM": "中", "LOW": "低", "NEGLIGIBLE": "可忽略／資訊", "UNKNOWN": "未知"}
CATEGORIES = ("作業系統套件", "語言套件", "執行檔", "其他")
OS_TYPES = {"deb", "rpm", "apk", "alpm", "portage"}
LANG_PURL_TYPES = {"pypi", "npm", "golang", "maven", "cargo", "gem", "nuget", "composer", "pear", "pecl", "conan", "hex",
                   "pub", "swift", "cocoapods", "hackage", "cran", "conda", "cpan", "luarocks", "bitbucket", "swid"}
BINARY_TYPES = {"binary"}
EPSS_PERCENTILE_HIGH = 0.9      # 「EPSS 高」的門檻：百分位 >= 0.9（只用於摘要表的挑選與標示，排序仍用完整數值）
ALIAS_KEYS = ("cveId", "ghsaId", "osvId", "snykId", "sonatypeId", "vulnDbId")
# OSV 的 Ubuntu／Debian 紀錄以 CVE 編號命名（UBUNTU-CVE-2026-1、DEBIAN-CVE-2026-1，upstream 欄位就是那個 CVE），DT 5.2.0 讀進來時
# 沒有保留別名，和 Grype 的 CVE-2026-1 對不上（Jetson R39.2.1 示範映像：Jetson 的 deb 列 7082 列只有 Grype、7468 列只有 DT、兩邊都有只有 41 列）。
# 依命名規則取回 CVE 編號當別名；其他前綴（USN-、DSA-、DLA-）不是一對一，不處理。
DISTRO_CVE_ID = re.compile(r"(?:UBUNTU|DEBIAN)-(CVE-\d{4}-\d+)")


# 報告不可出現的結論字樣（肯定句）。否定句型（例如「不代表沒有弱點」「不可當作沒有弱點」「不代表安全」）是工具原文的限定說明，放行。
FORBIDDEN_WORDS = ("沒有弱點", "無弱點", "未發現弱點", "沒有發現弱點", "零弱點", "沒有問題", "通過", "安全", "No vulnerabilities found")
NEGATION_PREFIXES = ("不代表", "不可當作", "不能當作", "不等於", "不是", "不可解讀為", "不可顯示為", "不可視為", "並非", "不能證明",
                     "does not mean", "doesn't mean", "not mean", "is not", "not proof")
CLAUSE_BREAKS = "，。；：！？、\n（）()「」『』[]|" + ";:!?."


def conclusion_hits(text):
    """回傳 text 中肯定句的結論字樣（同一子句內、在它之前出現否定句型的不算），每筆含前文片段。
    子句以標點切開，所以「不代表沒有弱點或安全」整句放行，「掃描完成，沒有弱點」的後半句會被抓到。"""
    hits, low = [], text.lower()
    for w in FORBIDDEN_WORDS:
        wl = w.lower()
        i = low.find(wl)
        while i >= 0:
            j = i
            while j > 0 and text[j - 1] not in CLAUSE_BREAKS and i - j < 40:
                j -= 1
            clause = low[j:i]
            if not any(n.lower() in clause for n in NEGATION_PREFIXES):
                hits.append(text[max(0, i - 12):i + len(w) + 4])
            i = low.find(wl, i + 1)
    return hits


# ---------- 讀檔 ----------

def load_json(path):
    """回傳 (資料, 錯誤說明)。檔案不存在 → (None, None)；無法解析 → (None, 說明)。"""
    if not os.path.isfile(path):
        return None, None
    try:
        with open(path, encoding="utf-8-sig") as f:
            return json.load(f), None
    except (OSError, ValueError, RecursionError) as e:
        return None, f"{os.path.basename(path)} 無法解析（{type(e).__name__}）"


def read_status(path):
    rows = []
    if not os.path.isfile(path):
        return rows
    with open(path, encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            parts = line.rstrip("\n").split("\t")
            if i == 0 and parts[:2] == ["stage", "status"]:
                continue
            if not parts or not parts[0]:
                continue
            st = parts[1] if len(parts) > 1 else ""
            row = {"stage": parts[0], "status": st, "detail": parts[2] if len(parts) > 2 else ""}
            if st not in STATUSES:   # 不認得的狀態一律視為 FAIL（不讓它被當成 OK）
                row["detail"] = f"（狀態欄「{st}」不是合法值，視為 FAIL）{row['detail']}"
                row["status"] = "FAIL"
            rows.append(row)
    return rows


def iter_json_stream(text):
    dec, i = json.JSONDecoder(), 0
    while i < len(text):
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text):
            break
        obj, i = dec.raw_decode(text, i)
        yield obj


# ---------- purl 與分類 ----------

def purl_parts(p):
    """pkg:type/namespace/name@version?qualifiers#subpath → (type, 名稱（含 namespace，已解碼）, 版本)；不是 purl 回 None。"""
    if not isinstance(p, str) or not p.startswith("pkg:"):
        return None
    body = p[4:].split("#", 1)[0].split("?", 1)[0]
    if "/" not in body:
        return None
    typ, rest = body.split("/", 1)
    ver = ""
    if "@" in rest:
        rest, ver = rest.rsplit("@", 1)
    return typ.lower(), unquote(rest), unquote(ver)


def norm_name(typ, name):
    if typ == "pypi":
        return re.sub(r"[-_.]+", "-", name.lower())
    if typ in ("npm",):
        return name.lower()
    return name


def pkg_key(purl, name=None, version=None):
    """比對 Grype 與 DT 的套件鍵：purl 去掉 qualifiers 與 subpath（pypi、npm 名稱大小寫折疊）；沒有 purl 時用 名稱@版本。"""
    pp = purl_parts(purl)
    if pp:
        typ, nm, ver = pp
        return f"pkg:{typ}/{norm_name(typ, nm)}@{ver or (version or '')}"
    return f"{name or '?'}@{version or ''}"


def display_purl(purl):
    if not isinstance(purl, str):
        return ""
    return purl.split("?", 1)[0].split("#", 1)[0]


def category_of(purl, artifact_type=None, sbom_types=None):
    t = (artifact_type or "").lower()
    if not t and sbom_types is not None:
        t = (sbom_types.get(pkg_key(purl)) or "").lower()
    if t in OS_TYPES:
        return "作業系統套件"
    if t in BINARY_TYPES:
        return "執行檔"
    pp = purl_parts(purl)
    ptyp = pp[0] if pp else ""
    if ptyp in OS_TYPES:
        return "作業系統套件"
    if ptyp in LANG_PURL_TYPES:
        return "語言套件"
    return "其他"


def sbom_type_index(sbom):
    """SBOM 元件的 Syft 套件類型（syft:package:type 屬性），用來替只有 purl 的 DT finding 分類（例如 pkg:generic 的執行檔）。"""
    out = {}
    if not isinstance(sbom, dict):
        return out
    stack = list(sbom.get("components") or [])
    while stack:
        c = stack.pop()
        if not isinstance(c, dict):
            continue
        stack.extend(c.get("components") or [])
        for p in c.get("properties") or []:
            if isinstance(p, dict) and p.get("name") == "syft:package:type" and c.get("purl"):
                out[pkg_key(c["purl"])] = p.get("value")
    return out


def norm_sev(s):
    s = (s or "").strip().upper()
    if s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return s
    if s in ("NEGLIGIBLE", "INFO"):
        return "NEGLIGIBLE"
    return "UNKNOWN"


def fnum(x):
    return float(x) if isinstance(x, (int, float)) and not isinstance(x, bool) else None


# ---------- 弱點：讀 Grype 與 DT ----------

def grype_records(grype, sbom_types):
    recs = []
    for m in (grype or {}).get("matches") or []:
        if not isinstance(m, dict):
            continue
        v, a = m.get("vulnerability") or {}, m.get("artifact") or {}
        vid = v.get("id") or "?"
        ids = {vid} | {r.get("id") for r in m.get("relatedVulnerabilities") or [] if isinstance(r, dict) and r.get("id")}
        epss = [e for e in v.get("epss") or [] if isinstance(e, dict)]
        fix = v.get("fix") or {}
        recs.append({
            "tool": "grype", "id": vid, "ids": ids, "purl": display_purl(a.get("purl")) or f"{a.get('type', '?')}:{a.get('name', '?')}",
            "name": a.get("name"), "version": a.get("version"), "key": pkg_key(a.get("purl"), a.get("name"), a.get("version")),
            "category": category_of(a.get("purl"), a.get("type")), "severity": norm_sev(v.get("severity")),
            "severity_raw": v.get("severity"), "fix_versions": [x for x in fix.get("versions") or [] if isinstance(x, str)],
            "fix_state": fix.get("state"), "kev": bool(v.get("knownExploited")),
            "epss": max((fnum(e.get("epss")) for e in epss if fnum(e.get("epss")) is not None), default=None),
            "epss_percentile": max((fnum(e.get("percentile")) for e in epss if fnum(e.get("percentile")) is not None), default=None),
            "namespace": v.get("namespace"),
        })
    return recs


def dt_records(findings, sbom_types):
    recs = []
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        c, v = f.get("component") or {}, f.get("vulnerability") or {}
        vid = v.get("vulnId") or "?"
        ids = {vid}
        m = DISTRO_CVE_ID.fullmatch(vid)
        if m:
            ids.add(m.group(1))
        for al in v.get("aliases") or []:
            if isinstance(al, dict):
                ids |= {al[k] for k in ALIAS_KEYS if isinstance(al.get(k), str) and al.get(k)}
        an = f.get("analysis") or {}
        recs.append({
            "tool": "dt", "id": vid, "ids": ids, "source": v.get("source"), "purl": display_purl(c.get("purl")) or c.get("name") or "?",
            "name": c.get("name"), "version": c.get("version"), "key": pkg_key(c.get("purl"), c.get("name"), c.get("version")),
            "category": category_of(c.get("purl"), None, sbom_types), "severity": norm_sev(v.get("severity")),
            "severity_raw": v.get("severity"), "kev": bool(v.get("isKev")), "epss": fnum(v.get("epssScore")),
            "epss_percentile": fnum(v.get("epssPercentile")), "suppressed": bool(an.get("isSuppressed")), "analysis_state": an.get("state"),
        })
    return recs


def dt_to_binaries(recs, deb_sources, sbom_types):
    """DT 以 Debian／Ubuntu 原始碼套件比對到的紀錄，對回實際安裝的二進位套件（dt/deb-sources.json，lib/deb_sources.py 寫的）。
    added：只給 DT 的原始碼套件元件（沒有安裝），紀錄改掛到各個二進位套件；shared_sources：SBOM 裡本來就有原始碼同名同版本的套件，
    紀錄保留，另外複製到同一原始碼的其他二進位套件。這樣才和 Grype（以二進位套件記錄）合成同一列，不會拆成「只有 Grype」「只有 DT」。"""
    if not isinstance(deb_sources, dict):
        return recs
    move, copy = {}, {}
    for kind, m in (("added", move), ("shared_sources", copy)):
        for x in deb_sources.get(kind) or []:
            if isinstance(x, dict) and isinstance(x.get("purl"), str):
                m[pkg_key(x["purl"])] = [b for b in x.get("binary_purls") or [] if isinstance(b, str)]
    out = []
    for r in recs:
        bins = move.get(r["key"]) if r["tool"] == "dt" else None
        if bins is None and r["tool"] == "dt":
            bins = copy.get(r["key"])
            if bins is not None:
                out.append(r)
        if not bins:
            out.append(r)
            continue
        for b in bins:
            pp = purl_parts(b) or ("deb", r["name"], r["version"])
            out.append(dict(r, purl=display_purl(b), name=pp[1].split("/")[-1], version=pp[2], key=pkg_key(b),
                            category=category_of(b, None, sbom_types), via_source=r["name"]))
    return out


def unify(recs, govuln_levels, bridges=None):
    """同一套件（pkg_key）內，以 ID 與別名的交集把 Grype 與 DT 的紀錄連成一列（union-find）；不刪除、不覆蓋任何一方。
    bridges：其他來源提供的別名群組（例如 govulncheck 讀到的 OSV 記錄的 aliases），只用來補別名，不新增紀錄。"""
    bridges = bridges or {}
    by_pkg = collections.defaultdict(list)
    for r in recs:
        extra = set().union(*(bridges.get(i, set()) for i in r["ids"])) if r["ids"] else set()
        r = dict(r, ids=r["ids"] | extra)
        by_pkg[r["key"]].append(r)
    rows = []
    for key, rs in by_pkg.items():
        parent = list(range(len(rs)))

        def find(i):
            while parent[i] != i:
                parent[i] = parent[parent[i]]
                i = parent[i]
            return i
        owner = {}
        for i, r in enumerate(rs):
            for vid in r["ids"]:
                if vid in owner:
                    parent[find(i)] = find(owner[vid])
                else:
                    owner[vid] = i
        groups = collections.defaultdict(list)
        for i, r in enumerate(rs):
            groups[find(i)].append(r)
        for g in groups.values():
            gr = [r for r in g if r["tool"] == "grype"]
            dt = [r for r in g if r["tool"] == "dt"]
            ids = set().union(*(r["ids"] for r in g))
            primary = sorted({r["id"] for r in gr} or {r["id"] for r in dt})
            cat = next((r["category"] for r in gr), None) or next((r["category"] for r in dt), "其他")
            row = {
                "key": key, "purl": (gr or dt)[0]["purl"], "name": (gr or dt)[0]["name"], "version": (gr or dt)[0]["version"],
                "category": cat, "ids": primary, "aliases": sorted(ids - set(primary)),
                "grype": [{"id": r["id"], "severity": r["severity"], "severity_raw": r["severity_raw"], "fix_versions": r["fix_versions"],
                           "fix_state": r["fix_state"], "kev": r["kev"], "epss": r["epss"], "epss_percentile": r["epss_percentile"]}
                          for r in _dedupe(gr)],
                "dt": [{"id": r["id"], "source": r["source"], "severity": r["severity"], "severity_raw": r["severity_raw"], "kev": r["kev"],
                        "epss": r["epss"], "epss_percentile": r["epss_percentile"], "suppressed": r["suppressed"],
                        "analysis_state": r["analysis_state"], **({"via_source": r["via_source"]} if r.get("via_source") else {})}
                       for r in _dedupe(dt)],
            }
            row["kev"] = any(x["kev"] for x in row["grype"] + row["dt"])
            row["epss"] = max((x["epss"] for x in row["grype"] + row["dt"] if x["epss"] is not None), default=None)
            row["epss_percentile"] = max((x["epss_percentile"] for x in row["grype"] + row["dt"] if x["epss_percentile"] is not None), default=None)
            row["fix_versions"] = sorted({v for x in row["grype"] for v in x["fix_versions"]})
            row["severity_rank"] = min((SEVERITIES.index(x["severity"]) for x in row["grype"] + row["dt"]), default=len(SEVERITIES) - 1)
            lv = [govuln_levels[i] for i in ids if i in govuln_levels]
            row["govulncheck"] = max(lv, key=GOVULN_RANK.index) if lv else None
            rows.append(row)
    rows.sort(key=lambda r: (not r["kev"], -(r["epss"] if r["epss"] is not None else -1), r["severity_rank"], r["ids"][0] if r["ids"] else "", r["key"]))
    return rows


def _dedupe(rs):
    seen, out = set(), []
    for r in rs:
        k = (r["id"], r.get("severity"), tuple(r.get("fix_versions") or ()))
        if k not in seen:
            seen.add(k)
            out.append(r)
    return out


def discrepancies(row, grype_ran, dt_ran):
    notes = []
    if grype_ran and dt_ran:
        # 沒有別名的紀錄無法跨工具對應（例如 DT 的 PYSEC-* 沒有別名資料），可能其實是同一個弱點：照實標出，不自行猜測合併
        noalias = "（這筆沒有別名資料，無法與另一工具對應；可能是同一弱點的不同編號）" if not row["aliases"] else ""
        if row["grype"] and not row["dt"]:
            notes.append("只有 Grype" + noalias)
        if row["dt"] and not row["grype"]:
            notes.append("只有 DT" + noalias)
        gs = {x["severity"] for x in row["grype"]}
        ds = {x["severity"] for x in row["dt"]}
        if gs and ds and gs != ds:
            notes.append("嚴重度不同：Grype " + "／".join(SEV_LABEL[x] for x in sorted(gs, key=SEVERITIES.index))
                         + "，DT " + "／".join(SEV_LABEL[x] for x in sorted(ds, key=SEVERITIES.index)))
        gk = any(x["kev"] for x in row["grype"])
        dk = any(x["kev"] for x in row["dt"])
        if row["grype"] and row["dt"] and gk != dk:
            notes.append(f"KEV 標示不同：Grype {'是' if gk else '否'}，DT {'是' if dk else '否'}")
    if any(x.get("suppressed") for x in row["dt"]):
        notes.append("DT 已抑制（suppressed；原始比對保留）")
    return notes


# ---------- govulncheck ----------

GOVULN_RANK = ["模組層（未匯入受影響套件）", "已匯入受影響套件", "呼叫到受影響函式"]


def govulncheck_summary(path):
    """回傳 (各 OSV ID 的列, {ID 或別名: 層級}, {ID 或別名: 同一 OSV 記錄的全部 ID})。"""
    if not os.path.isfile(path):
        return None, None, None
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
        osv, levels, info = {}, {}, {}
        for o in iter_json_stream(text):
            if "osv" in o and isinstance(o["osv"], dict):
                osv[o["osv"].get("id")] = o["osv"].get("aliases") or []
            if "finding" in o:
                f = o["finding"]
                tr = (f.get("trace") or [{}])[0]
                lv = 2 if tr.get("function") else 1 if tr.get("package") else 0
                fid = f.get("osv")
                if lv >= levels.get(fid, -1):
                    levels[fid] = lv
                    info[fid] = {"module": tr.get("module"), "version": tr.get("version"), "fixed_version": f.get("fixed_version")}
        rows = []
        for fid, lv in sorted(levels.items(), key=lambda x: (-x[1], x[0])):
            rows.append({"id": fid, "aliases": sorted(osv.get(fid, [])), "level": GOVULN_RANK[lv], **info[fid]})
        id_levels, bridges = {}, {}
        for r in rows:
            for i in [r["id"]] + r["aliases"]:
                id_levels[i] = r["level"]
        for fid, al in osv.items():
            grp = {fid, *al}
            for i in grp:
                bridges.setdefault(i, set()).update(grp)
        return rows, id_levels, bridges
    except (ValueError, AttributeError, TypeError, IndexError) as e:
        return {"error": f"govulncheck 輸出無法解析（{type(e).__name__}）"}, {}, {}


# ---------- 主流程：組資料 ----------

def count_components(sbom):
    """SBOM 的元件數（含巢狀；不含 metadata.component）。讀不到 → None。"""
    if not isinstance(sbom, dict):
        return None

    def walk(cs):
        n = 0
        for c in cs or []:
            if isinstance(c, dict):
                n += 1 + walk(c.get("components"))
        return n
    return walk(sbom.get("components"))


def kernel_map_keys(kmap):
    """scan/l4t-kernel-map.json（lib/l4t_kernel.py）→ {對應的 Canonical 核心的套件鍵: 原本的 nvidia-l4t-kernel 名稱與版本}；沒有對應時空的。"""
    if not isinstance(kmap, dict) or kmap.get("status") != "OK":
        return {}
    c = (kmap.get("map_entry") or {}).get("component")
    k = (kmap.get("l4t_kernel") or [None])[0]
    if not isinstance(c, dict) or not isinstance(c.get("purl"), str) or not isinstance(k, dict):
        return {}
    return {pkg_key(c["purl"]): f"{k.get('name')} {k.get('version')}"}


def license_chain(sbom, prep, scio, comp):
    """授權的數量鏈：原始 SBOM → 上傳 ScanCode.io（移除 file／過長／其他）→ ScanCode.io 套件 → DejaCode 產品套件。缺的環節是 None。"""
    ch = {"sbom_components": count_components(sbom), "scio_upload": None, "removed_file": None, "removed_too_long": None,
          "removed_other": None, "scio_packages": None, "scio_unique_purls": None, "dejacode_packages": None}
    if isinstance(prep, dict):
        try:
            cin, cout = int(prep["components_in"]), int(prep["components_out"])
            rf, rl = int(prep.get("removed_file_components") or 0), len(prep.get("removed_too_long") or [])
            # 只供比對的合成元件（C-kernel-l4t-map 加的，不在原始 SBOM）：scio_prep 移除，不算「其他」（不是少了授權判定的套件）
            rm = len(prep.get("removed_matching_only") or [])
            ch.update(scio_upload=cout, removed_file=rf, removed_too_long=rl, removed_matching_only=rm,
                      removed_other=cin - cout - rf - rl - rm, scio_input=cin)
        except (KeyError, TypeError, ValueError):
            pass
    if isinstance(scio, dict):
        ch["scio_packages"], ch["scio_unique_purls"] = scio.get("packages"), scio.get("unique_purls")
    if isinstance(comp, dict):
        ch["dejacode_packages"] = comp.get("packages")
    return ch


def build(out_dir):
    meta, meta_err = load_json(os.path.join(out_dir, "meta.json"))
    meta = meta if isinstance(meta, dict) else {}
    stages = read_status(os.path.join(out_dir, "status.tsv"))
    sts = {s["stage"]: s["status"] for s in stages}
    problems = []      # 報告本身讀檔遇到的問題（也算不完整）
    if meta_err:
        problems.append(meta_err)
    if not stages:
        problems.append("沒有 status.tsv 或是空的：不知道哪些階段執行過")
    sbom, e = load_json(os.path.join(out_dir, "sbom", "sbom.cdx.json"))
    if e:
        problems.append(e)
    sbom_types = sbom_type_index(sbom)
    grype, e = load_json(os.path.join(out_dir, "scan", "grype.json"))
    if e:
        problems.append(e)
    gate, e = load_json(os.path.join(out_dir, "scan", "sbomgate.json"))
    if e:
        problems.append(e)
    findings, e = load_json(os.path.join(out_dir, "dt", "findings.json"))
    if e:
        problems.append(e)
    comp, e = load_json(os.path.join(out_dir, "dejacode", "compliance.json"))
    if e:
        problems.append(e)
    scio, _ = load_json(os.path.join(out_dir, "dejacode", "scio-summary.json"))
    prep, _ = load_json(os.path.join(out_dir, "dejacode", "scio-prep.json"))
    pscan, _ = load_json(os.path.join(out_dir, "dejacode", "package-scans.json"))
    nsum, _ = load_json(os.path.join(out_dir, "dejacode", "notice-summary.json"))
    fsum, _ = load_json(os.path.join(out_dir, "scancode", "files-summary.json"))
    lockfiles, e = load_json(os.path.join(out_dir, "scan", "lockfiles.json"))
    if e:
        problems.append(e)
    gv_rows, gv_levels, gv_bridges = govulncheck_summary(os.path.join(out_dir, "scan", "govulncheck.json"))
    if isinstance(gv_rows, dict):
        problems.append(gv_rows["error"])
        gv_rows = None

    grype_ran = isinstance(grype, dict) and isinstance(grype.get("matches"), list)
    dt_ran = isinstance(findings, list)
    # D-dt-findings 在資料源不完整時記 GAP（讀取本身完成）；「讀取完整」與「資料源完整」分開
    dt_sources_complete = sts.get("D-dt-data-sources") == "OK"
    dt_complete = dt_ran and (sts.get("D-dt-findings") == "OK" or (sts.get("D-dt-findings") == "GAP" and not dt_sources_complete))
    dt_sources, _ = load_json(os.path.join(out_dir, "dt", "data-sources.json"))
    dt_sources = dt_sources if isinstance(dt_sources, dict) else None
    # 作業系統核心的比對涵蓋（C-kernel-coverage，lib/kernelcheck.py）：狀態以 status.tsv 為準，版本取自 kernel-coverage.json
    kc, _ = load_json(os.path.join(out_dir, "scan", "kernel-coverage.json"))
    kernel = None
    if "C-kernel-coverage" in sts:
        vers = [x.get("version") for x in (kc.get("versions") or []) if isinstance(x, dict) and x.get("version")] if isinstance(kc, dict) else []
        kernel = {"status": sts["C-kernel-coverage"], "versions": vers}
    # NVIDIA 安全公告（C-nvidia-bulletins，lib/nvidia_bulletins.py）：狀態列在階段表；有發現（對照表已審核的列）時弱點節另外註明筆數
    nvb, _ = load_json(os.path.join(out_dir, "scan", "nvidia-bulletins.json"))
    nvidia = None
    if "C-nvidia-bulletins" in sts and isinstance(nvb, dict):
        nvidia = {"status": sts["C-nvidia-bulletins"], "version": (nvb.get("jetson_linux") or {}).get("version"),
                  "findings": sorted({(f.get("vulnerability") or {}).get("vulnId") or "?" for f in nvb.get("findings") or [] if isinstance(f, dict)})}

    # 規則 13：版本未知的元件（sbomgate 判定）。對它們的比對不算進弱點，移到「未比對」區。
    unknown_components, unknown_keys = [], set()
    if isinstance(gate, dict):
        for c in gate.get("component_details") or []:
            if isinstance(c, dict) and c.get("class") != "RESOLVED":
                unknown_components.append({k: c.get(k) for k in ("name", "version", "purl", "class", "why", "superseded_by_resolved", "self_component")})
                unknown_keys.add(pkg_key(c.get("purl"), c.get("name"), c.get("version")))
    # sbomgate 把「對專案本身、沒有版本」的 Grype 比對移到 excluded_matches（SELF_NO_VERSION）；報告同樣排除，不猜版本。
    # 依據：koel 的 Grype 對 pkg:composer/phanan/koel（無版本）給了 8 筆，報告原本仍列成「只有 Grype」（2026-10-24 準確度第二次實機判讀）。
    self_excl = set()
    if isinstance(gate, dict):
        for x in gate.get("excluded_matches") or []:
            if isinstance(x, dict) and x.get("excluded_reason") == "SELF_NO_VERSION" and not x.get("version"):
                self_excl.add((x.get("id"), display_purl(x.get("purl"))))
    deb_src, e = load_json(os.path.join(out_dir, "dt", "deb-sources.json"))
    if e:
        problems.append(e + "：DT 以原始碼套件比對到的紀錄沒有對回二進位套件")
    recs = grype_records(grype if grype_ran else None, sbom_types) + dt_to_binaries(dt_records(findings if dt_ran else None, sbom_types), deb_src, sbom_types)
    for r in recs:
        if r["key"] in unknown_keys:
            r["excluded_code"], r["excluded_reason"] = "RULE13", "版本未知（規則 13）"
        elif r["tool"] == "grype" and not r["version"] and (r["id"], r["purl"]) in self_excl:
            r["excluded_code"], r["excluded_reason"] = "SELF_NO_VERSION", "專案本身、沒有版本（SELF_NO_VERSION）"
    excluded = [r for r in recs if r.get("excluded_reason")]
    recs = [r for r in recs if not r.get("excluded_reason")]
    rows = unify(recs, gv_levels or {}, gv_bridges or {})
    kmap = kernel_map_keys(load_json(os.path.join(out_dir, "scan", "l4t-kernel-map.json"))[0])
    self_ex = collections.defaultdict(set)      # Grype 因 SELF_NO_VERSION 排除的 套件鍵 → ID＋別名
    for x in excluded:
        if x["tool"] == "grype" and x["excluded_code"] == "SELF_NO_VERSION":
            self_ex[x["key"]] |= set(x["ids"])
    for r in rows:
        r["notes"] = discrepancies(r, grype_ran, dt_ran)
        if r["dt"] and not r["grype"] and self_ex.get(r["key"], set()) & set(r["ids"]):
            # Grype 其實有比對到、只是被排除：「只有 DT」的說法不正確（DT 那筆照樣保留，矛盾並列）
            r["notes"] = [n for n in r["notes"] if not n.startswith("只有 DT")] + [
                "Grype 的同一筆因「專案本身、沒有版本」（SELF_NO_VERSION）排除，見「排除、未計入的比對」；DT 這筆照樣列出"]
        if r["key"] in kmap:
            # C-kernel-l4t-map 加的只供比對的元件：產品裡裝的是 NVIDIA 的核心套件，不是這個 Ubuntu 套件
            # 不放進 notes（notes 是 Grype／DT 的不一致，會被算進 discrepancy_rows）；表格的套件欄另外標示
            r["mapped_from"] = kmap[r["key"]]

    counts = {}
    for tool in ("grype", "dt"):
        ran = grype_ran if tool == "grype" else dt_ran
        if not ran:
            counts[tool] = None
            continue
        t = {c: {s: 0 for s in SEVERITIES} for c in CATEGORIES}
        for r in rows:
            for x in r[tool]:
                t[r["category"]][x["severity"]] += 1
        counts[tool] = t
    uniq = {tool: len({i for r in rows if r[tool] for i in r["ids"]}) for tool in ("grype", "dt")}

    order = {s: i for i, s in enumerate(STATUSES)}
    incomplete = sorted([s for s in stages if s["status"] != "OK"], key=lambda s: order[s["status"]])
    if problems:
        incomplete = [{"stage": "R-report-input", "status": "FAIL", "detail": "；".join(problems)}] + incomplete
    overall = "FAIL" if any(s["status"] == "FAIL" for s in incomplete) else ("INCOMPLETE" if incomplete or not stages else "COMPLETE")

    lic = None
    if isinstance(comp, dict):
        rws = [r for r in comp.get("rows") or [] if isinstance(r, dict)]
        dist = collections.Counter((r.get("license_expression") or "（沒有授權資料）") for r in rws)
        unknown = [{"package": r.get("package"), "license_expression": r.get("license_expression") or "",
                    "label": "unknown（沒有授權資料）" if r.get("verdict") == "no_license" else "未評估（授權沒有 usage policy 或對不到 DejaCode 授權）",
                    "unassessed_keys": r.get("unassessed_keys") or []}
                   for r in rws if r.get("verdict") in ("no_license", "not_assessed")]
        lic = {"product": comp.get("product"), "packages": comp.get("packages"), "counts": comp.get("counts") or {},
               "counts_or_choice": comp.get("counts_or_choice"), "or_choice_differs": comp.get("or_choice_differs") or 0,
               "or_choice": [{"package": r.get("package"), "license_expression": r.get("license_expression"),
                              "verdict": r.get("verdict"), "or_choice_verdict": r.get("or_choice_verdict")}
                             for r in rws if r.get("or_choice_verdict") not in (None, r.get("verdict"))],
               "distribution": dist.most_common(), "unknown": unknown,
               "attention": [{"package": r.get("package"), "license_expression": r.get("license_expression"), "verdict": r.get("verdict")}
                             for r in rws if r.get("verdict") in ("error", "warning")]}

    links = {}
    for k, label in (("dt_project_url", "Dependency-Track 專案頁"), ("dejacode_product_url", "DejaCode 產品頁")):
        u = meta.get(k)
        if isinstance(u, str) and urlsplit(u).scheme in ("http", "https"):
            links[k] = {"label": label, "url": u}

    gate_summary = None
    if isinstance(gate, dict):
        va = gate.get("vulnerability_analysis") or {}
        gate_summary = {"sbom": (gate.get("sbom") or {}).get("status"), "vulnerability_analysis": va.get("status"),
                        "reasons": va.get("reasons") or [], "notes": va.get("notes") or [], "dependency_tree": gate.get("dependency_tree"),
                        "excluded_matches": gate.get("excluded_matches") or [], "unmapped_matches": gate.get("unmapped_matches") or [],
                        "grype_db": gate.get("grype_db")}
    return {
        "schema": "sca-pilot-report/1",
        "overall": overall,
        "overall_note": "整體狀態只描述各階段是否完成；COMPLETE 也只表示在這份 SBOM 與這些資料庫範圍內比對完成。",
        "identity": meta,
        "stages": stages,
        "incomplete": incomplete,
        "vulnerabilities": {
            "tools_run": {"grype": grype_ran, "dt": dt_ran, "dt_complete": dt_complete, "dt_sources_complete": dt_sources_complete},
            "rows": rows, "counts": counts, "unique_ids": uniq,
            "discrepancy_rows": sum(1 for r in rows if r["notes"]),
        },
        "version_unknown": {"components": unknown_components, "excluded_records": [
            {"tool": r["tool"], "id": r["id"], "purl": r["purl"], "version": r["version"], "reason": r["excluded_reason"],
             "code": r["excluded_code"]} for r in excluded],
            "sbomgate": gate_summary},
        "govulncheck": gv_rows,
        "licenses": lic,
        "scancodeio": scio,
        "license_chain": license_chain(sbom, prep, scio, comp),
        # 逐套件掃描（dejacode/package-scans.json 的 status_counts）、NOTICE 摘要（notice-summary.json）、專案或映像的檔案層級掃描（scancode/files-summary.json）
        "package_scans": (pscan.get("status_counts") if isinstance(pscan, dict) else None),
        "notice": nsum if isinstance(nsum, dict) else None,
        "files_scan": fsum if isinstance(fsum, dict) else None,
        "lockfiles": lockfiles,
        "links": links,
        "dt_data_sources": dt_sources,
        "kernel_coverage": kernel,
        "nvidia_bulletins": nvidia,
    }


# ---------- HTML ----------

CSS = """
:root{--bg:#ffffff;--fg:#1d2127;--muted:#5b6470;--line:#d9dde3;--card:#f5f7fa;--head:#eef1f5;
--fail:#b42318;--fail-bg:#fde8e7;--warn:#9a5b00;--warn-bg:#fff4dc;--gap:#7a3fb0;--gap-bg:#f3e9fc;--ok:#1f7a3a;--ok-bg:#e5f5ea;--na:#4b5563;--na-bg:#eceff3;--link:#0b5cad}
@media (prefers-color-scheme: dark){:root{--bg:#14171c;--fg:#e4e7eb;--muted:#9aa4b1;--line:#2f353e;--card:#1b1f26;--head:#222831;
--fail:#ff8a80;--fail-bg:#3a1714;--warn:#ffc266;--warn-bg:#352812;--gap:#d4a8ff;--gap-bg:#2a1a3a;--ok:#7ddc95;--ok-bg:#15301e;--na:#c3cad4;--na-bg:#262c35;--link:#8cc4ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,"Segoe UI","Noto Sans TC","PingFang TC","Microsoft JhengHei",sans-serif}
main{max-width:1200px;margin:0 auto;padding:16px}h1{font-size:22px;margin:8px 0}h2{font-size:18px;margin:28px 0 8px;border-bottom:1px solid var(--line);padding-bottom:4px}
h3{font-size:15px;margin:16px 0 6px}a{color:var(--link)}code,.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12.5px;word-break:break-all}
.card{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:10px 14px;margin:8px 0}
.alert{border-left:5px solid var(--fail);background:var(--fail-bg)}.alert.inc{border-left-color:var(--warn);background:var(--warn-bg)}
table{border-collapse:collapse;width:100%;margin:6px 0}th,td{border:1px solid var(--line);padding:4px 6px;text-align:left;vertical-align:top}th{background:var(--head);font-weight:600}
.wrap{overflow-x:auto}.muted{color:var(--muted)}.num{text-align:right;font-variant-numeric:tabular-nums}
.b{display:inline-block;padding:0 6px;border-radius:4px;font-size:12px;font-weight:600;white-space:nowrap}
.FAIL{color:var(--fail);background:var(--fail-bg)}.ATTENTION{color:var(--warn);background:var(--warn-bg)}.GAP,.NOT_ASSESSED{color:var(--gap);background:var(--gap-bg)}
.NOT_RUN{color:var(--na);background:var(--na-bg)}.OK{color:var(--ok);background:var(--ok-bg)}.INCOMPLETE{color:var(--warn);background:var(--warn-bg)}.COMPLETE{color:var(--ok);background:var(--ok-bg)}
.kev{color:var(--fail);background:var(--fail-bg)}.net{color:var(--warn);background:var(--warn-bg)}
details{margin:6px 0}summary{cursor:pointer;font-weight:600}ul{margin:4px 0;padding-left:20px}
"""


def e(x):
    return html.escape("" if x is None else str(x), quote=True)


def badge(s, cls=None):
    return f'<span class="b {e(cls or s)}">{e(s)}</span>'


def fmt_epss(score, pct):
    if score is None and pct is None:
        return "—"
    s = f"{score:.4f}" if score is not None else "?"
    p = f"（百分位 {pct:.2f}）" if pct is not None else ""
    return s + p


def vuln_table(rows, show_tools):
    h = ['<div class="wrap"><table><tr><th>ID（別名）</th><th>套件 purl</th><th>版本</th><th>修補版本（Grype）</th><th>KEV／EPSS</th>']
    if show_tools["grype"]:
        h.append("<th>Grype</th>")
    if show_tools["dt"]:
        h.append("<th>DT</th>")
    h.append("<th>不一致與備註</th></tr>")
    for r in rows:
        ids = "<br>".join(f"<code>{e(i)}</code>" for i in r["ids"])
        if r["aliases"]:
            ids += '<br><span class="muted">別名：' + "、".join(f"<code>{e(a)}</code>" for a in r["aliases"]) + "</span>"
        kev = badge("KEV", "kev") + " " if r["kev"] else ""
        pc = f"<code>{e(r['purl'])}</code>"
        if r.get("mapped_from"):
            pc += f'<br><span class="muted">只供比對的 Canonical 核心（C-kernel-l4t-map），產品裡安裝的是 {e(r["mapped_from"])}</span>'
        cells = [ids, pc, f"<code>{e(r['version'])}</code>",
                 e("、".join(r["fix_versions"])) if r["fix_versions"] else (e(next((x["fix_state"] for x in r["grype"] if x.get("fix_state")), "—"))),
                 kev + e(fmt_epss(r["epss"], r["epss_percentile"]))]
        if show_tools["grype"]:
            cells.append("<br>".join(f"{e(SEV_LABEL[x['severity']])}（{e(x['id'])}）" for x in r["grype"]) or '<span class="muted">未比對到</span>')
        if show_tools["dt"]:
            cells.append("<br>".join(f"{e(SEV_LABEL[x['severity']])}（{e(x['id'])}，{e(x['source'])}"
                                     + (f"，以原始碼套件 {e(x['via_source'])} 比對" if x.get("via_source") else "") + "）"
                                     + ("，已抑制" if x["suppressed"] else "")
                                     for x in r["dt"]) or '<span class="muted">未比對到</span>')
        notes = list(r["notes"])
        if r.get("govulncheck"):
            notes.append(f"govulncheck：{r['govulncheck']}")
        cells.append("<br>".join(e(n) for n in notes) or "—")
        h.append("<tr>" + "".join(f"<td>{c}</td>" for c in cells) + "</tr>")
    h.append("</table></div>")
    return "".join(h)


def render_dt_sources(rep):
    """首頁：DT 的弱點與 KEV 資料源最近一次 mirror 狀態（dt/data-sources.json，sca-scan D 段讀取）。"""
    st = {s["stage"]: s for s in rep["stages"]}
    ds = rep.get("dt_data_sources")
    if not ds:
        s = st.get("D-dt-data-sources")
        why = f"{s['status']}：{s['detail']}" if s else "沒有 D-dt-data-sources 階段（舊版輸出或 DT 沒有執行）"
        return f'<div class="card"><h3 style="margin-top:2px">DT 弱點資料源</h3><p class="muted">沒有資料源狀態：{e(why)}</p></div>'
    rows = "".join(
        f"<tr><td>{e(r.get('label'))}</td><td>{e('弱點' if r.get('kind') == 'vuln' else 'KEV')}</td>"
        f"<td>{badge(r.get('status') or '未知', 'OK' if r.get('status') == 'COMPLETED' else ('FAIL' if r.get('status') == 'FAILED' else 'GAP'))}</td>"
        f"<td><code>{e(r.get('started_at') or '—')}</code></td><td><code>{e(r.get('completed_at') or '—')}</code></td>"
        f"<td>{e(r.get('failure_reason') or r.get('problem') or '')}</td></tr>" for r in ds.get("sources") or [])
    vs, ks = st.get("D-dt-data-sources"), st.get("D-dt-kev-sources")
    head = f"弱點資料源 {badge(vs['status']) if vs else badge('NOT_RUN')}　KEV 資料源 {badge(ks['status']) if ks else badge('NOT_RUN')}"
    note = ("NVD 或 OSV 最近一次 mirror 不是 COMPLETED 時，DT 的弱點結果記為不完整（GAP）：缺的弱點可能只是資料源沒有下載完成。"
            "這裡只看最近一次 mirror；COMPLETED 也只表示那次下載完成，不代表資料涵蓋所有弱點。GitHub（GHSA）依設計關閉；EPSS 沒有 mirror 狀態 API（未核對）。")
    nm = ds.get("nvd_mirror")
    nvd_html = ""
    if isinstance(nm, dict):
        if nm.get("mode") == "1":
            when = f"modified {nm.get('modified')}（{nm.get('age_days')} 天前，上限 {nm.get('max_age_days')} 天）" if nm.get("modified") else "日期未知"
            nvd_html = f"<p>NVD 來源：內部鏡像 {badge(nm.get('status') or 'GAP')} {e(when)}。{e(nm.get('detail') or '')}</p>"
        else:
            nvd_html = "<p class='muted'>NVD 來源：DT 直接連 nvd.nist.gov（沒有使用內部鏡像）</p>"
    cov = ds.get("osv_coverage")
    cov_html = ""
    if isinstance(cov, dict):
        bt = "、".join(f"{k} {v}" for k, v in (cov.get("by_type") or {}).items())
        cov_html = (f"<p>OSV 生態系涵蓋 {badge(cov.get('status') or '?')} {e(cov.get('detail'))}</p>"
                    + (f"<p class='muted'>SBOM 的 purl 類型：{e(bt)}</p>" if bt else ""))
    return (f'<div class="card"><h3 style="margin-top:2px">DT 弱點資料源（最近一次 mirror）</h3><p>{head}</p>'
            f'<div class="wrap"><table><tr><th>資料源</th><th>用途</th><th>狀態</th><th>開始（UTC）</th><th>完成（UTC）</th><th>失敗原因／問題</th></tr>{rows}</table></div>'
            f'{nvd_html}{cov_html}<p class="muted">{e(note)}</p></div>')


def render(rep):
    m, v = rep["identity"], rep["vulnerabilities"]
    tr = v["tools_run"]
    p = ['<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8">',
         '<meta name="viewport" content="width=device-width,initial-scale=1">',
         "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\">",
         '<meta name="color-scheme" content="light dark">',
         f"<title>CRA掃描報告：{e(m.get('name') or '未命名')}</title><style>{CSS}</style></head><body><main>"]
    # --- 1. 身分 ---
    p.append(f"<h1>CRA掃描報告：{e(m.get('name') or '未命名')} {badge(rep['overall'])}</h1>")
    p.append(f'<p class="muted">{e(rep["overall_note"])}</p>')
    net = []
    if (m.get("network") or {}).get("data_sources_online", True):
        net.append(badge("連網：線上資料源", "net"))
    if (m.get("network") or {}).get("sbom_resolution_online"):
        net.append(badge("連網解析", "net"))
    tools = m.get("tools") or {}
    idrows = [("來源類型", {"git": "git（固定 commit）", "dir": "本機資料夾", "image": "容器映像", "sbom": "提供的 SBOM（未執行產生器）"}.get(m.get("mode"), m.get("mode"))),
              ("來源", m.get("source")), ("commit", m.get("commit")), ("映像 digest", m.get("digest")), ("映像 ID", m.get("image_id")),
              ("內容 sha256（資料夾，不含 .git）", m.get("content_sha256")), ("git HEAD（參考；工作區可能有未提交的修改）", m.get("git_head")),
              ("DT 專案版本", m.get("version")), ("DejaCode 產品版本（「:」換成「-」）", m.get("dejacode_version")), ("開始／結束（UTC）", f"{m.get('started', '?')} → {m.get('finished', '?')}"),
              ("工具版本", "、".join(f"{k} {vv}" for k, vv in sorted(tools.items())) or None),
              ("Grype 資料庫", f"建置 {m.get('grype_db_built')}（schema {m.get('grype_db_schema') or '?'}）" if m.get("grype_db_built") else None),
              ("DT 版本", m.get("dt_version")), ("ScanCode.io 版本", m.get("scancodeio_version")),
              ("依賴樹（sbomgate --tree）", m.get("dependency_tree"))]
    lf = rep.get("lockfiles")
    if isinstance(lf, dict):
        idrows.append(("鎖定檔判定（規則 11）", f"{lf.get('reason', '')}"))
        for x in lf.get("ecosystems") or []:
            idrows.append((f"　{x.get('ecosystem')}", ("有鎖定檔" if x.get("status") == "lock" else "缺鎖定檔") + "：" + "、".join(
                mm.get("manifest", "") + (f" → {mm['lockfile']}" + (f"（{mm['via']}）" if mm.get("via") else "") if mm.get("lockfile") else ("（沒有依賴）" if mm.get("status") == "no-deps" else "（沒有鎖定檔）"))
                for mm in x.get("manifests") or [])))
        if lf.get("manifests_not_checked"):
            idrows.append(("sbomgate 未比對的清單檔", "、".join(lf["manifests_not_checked"]) + "（sbomgate 只核對 package.json、requirements*.txt）"))
    if m.get("upload_versions_removed") not in (None, "", "0"):
        idrows.append(("上傳 DT／ScanCode.io 的 SBOM", f"移除了 {m['upload_versions_removed']} 個版本未知元件的版本（規則 13；sbom/sbom.upload.cdx.json，原始 SBOM 原樣保留）"))
    p.append('<div class="card"><table>' + "".join(f"<tr><th>{e(k)}</th><td><code>{e(val)}</code></td></tr>" for k, val in idrows if val)
             + f"<tr><th>網路</th><td>{' '.join(net)} <span class='muted'>{e((m.get('network') or {}).get('note', ''))}</span></td></tr></table></div>")
    # --- 2. 未完成或不完整（最前面） ---
    inc = rep["incomplete"]
    if inc:
        p.append(f'<div class="card alert {"" if rep["overall"] == "FAIL" else "inc"}"><h2 style="margin-top:4px">未完成或不完整的項目（{len(inc)}）</h2>'
                 "<p>下列階段沒有完整完成。以下的弱點與授權結果<b>只涵蓋實際完成的部分</b>，不可解讀為整體結論。</p><table><tr><th>階段</th><th>狀態</th><th>說明</th></tr>"
                 + "".join(f"<tr><td><code>{e(s['stage'])}</code></td><td>{badge(s['status'])}</td><td>{e(s['detail'])}</td></tr>" for s in inc)
                 + "</table></div>")
    else:
        p.append('<div class="card"><p>每個階段都記為 OK。OK 只表示該階段執行完成且輸出可用；弱點與授權結果仍以下方內容為準。</p></div>')
    p.append(render_dt_sources(rep))
    links = rep["links"]
    if links:
        p.append('<div class="card">' + "　".join(f'<a href="{e(l["url"])}" rel="noreferrer">{e(l["label"])}</a>' for l in links.values()) + "</div>")
    # --- 3. 弱點 ---
    p.append("<h2>弱點</h2>")
    kc = rep.get("kernel_coverage")
    if kc and kc["status"] == "GAP":
        p.append(f'<div class="card alert inc">作業系統核心（版本 {e("、".join(kc["versions"]) or "未知")}）沒有做漏洞比對，'
                 "核心的漏洞不在下面的數字裡（見 <code>C-kernel-coverage</code>）。</div>")
    nv = rep.get("nvidia_bulletins")
    if nv and nv["findings"]:
        p.append(f'<div class="card alert">NVIDIA 安全公告（Jetson Linux {e(nv["version"] or "?")}）另有 {len(nv["findings"])} 筆發現：'
                 f'{e("、".join(nv["findings"][:10]))}{" 等" if len(nv["findings"]) > 10 else ""}。不在下面的 Grype／DT 數字裡'
                 '（見 <code>C-nvidia-bulletins</code> 與 <code>scan/nvidia-bulletins.json</code>）。</div>')
    if not tr["grype"] and not tr["dt"]:
        p.append('<div class="card alert inc">Grype 與 DT 都沒有可讀的結果：缺少弱點比對資料（見上方狀態）。</div>')
    else:
        srcs = []
        srcs.append("Grype：" + ("有結果" if tr["grype"] else "沒有結果"))
        dt_note = ("" if tr["dt_complete"] else "（讀取不完整）") + ("" if tr.get("dt_sources_complete") else "（弱點資料源不完整或狀態未知，見「DT 弱點資料源」：DT 的比對結果不完整）")
        srcs.append("DT：" + ("有結果" + dt_note if tr["dt"] else "沒有結果"))
        p.append(f'<p>{e("；".join(srcs))}。兩個工具的結果並列，不互相覆蓋；計數單位是「套件 × 弱點（以 ID 與別名合併）」。'
                 + (f"已排除版本未知元件與「專案本身、沒有版本」的比對紀錄 {len(rep['version_unknown']['excluded_records'])} 筆（Grype 與 DT 的原始紀錄筆數，見下一節）。</p>"
                    if rep["version_unknown"]["sbomgate"] is not None else "沒有 sbomgate 結果，未能排除版本未知元件的比對（見下一節）。</p>"))
        hdr = "".join(f"<th>{e(SEV_LABEL[s])}</th>" for s in SEVERITIES)
        for tool, label in (("grype", "Grype"), ("dt", "DT")):
            c = v["counts"].get(tool)
            if c is None:
                p.append(f"<h3>{label}</h3><p class='muted'>沒有 {label} 結果，不列計數。</p>")
                continue
            tot = sum(sum(x.values()) for x in c.values())
            p.append(f"<h3>{label}（{tot} 筆；不重複 ID {v['unique_ids'][tool]}）</h3><div class='wrap'><table><tr><th>分類</th>{hdr}<th>合計</th></tr>")
            for cat in CATEGORIES:
                p.append(f"<tr><td>{e(cat)}</td>" + "".join(f"<td class='num'>{c[cat][s]}</td>" for s in SEVERITIES)
                         + f"<td class='num'>{sum(c[cat].values())}</td></tr>")
            p.append("</table></div>")
            if tot == 0:
                p.append(f"<p class='muted'>{label} 比對結果 0 筆；這只是在這份 SBOM 與該工具資料庫範圍內的比對結果。</p>")
        rows = v["rows"]
        top = [r for r in rows if r["kev"] or (r["epss_percentile"] or 0) >= EPSS_PERCENTILE_HIGH]
        p.append(f"<h3>KEV 與 EPSS 高（百分位 ≥ {EPSS_PERCENTILE_HIGH}）：{len(top)} 筆</h3>")
        p.append(vuln_table(top[:100], tr) if top else "<p class='muted'>沒有標為 KEV 或 EPSS 百分位達門檻的比對（KEV、EPSS 資料取自 Grype DB 與 DT，未收錄不等於不會被利用）。</p>")
        if v["discrepancy_rows"]:
            dis = [r for r in rows if r["notes"]]
            p.append(f"<details><summary>Grype 與 DT 不一致或有備註：{len(dis)} 筆</summary>{vuln_table(dis, tr)}</details>")
        for cat in CATEGORIES:
            rs = [r for r in rows if r["category"] == cat]
            if rs:
                p.append(f"<details{' open' if len(rs) <= 50 else ''}><summary>{e(cat)}：{len(rs)} 筆</summary>{vuln_table(rs, tr)}</details>")
    gv = rep.get("govulncheck")
    if gv is not None:
        p.append(f"<h3>govulncheck（Go 可達性）：{len(gv)} 個 OSV ID</h3>")
        if gv:
            p.append("<div class='wrap'><table><tr><th>ID（別名）</th><th>層級</th><th>模組</th><th>修補版本</th></tr>" + "".join(
                f"<tr><td><code>{e(r['id'])}</code><br><span class='muted'>{e('、'.join(r['aliases']))}</span></td><td>{e(r['level'])}</td>"
                f"<td><code>{e(r.get('module'))}@{e(r.get('version'))}</code></td><td>{e(r.get('fixed_version') or '—')}</td></tr>" for r in gv) + "</table></div>")
    # --- 4. 版本未知 ---
    vu = rep["version_unknown"]
    p.append("<h2>版本未知的元件（規則 13：未比對）與排除的比對</h2>")
    if vu["sbomgate"] is None:
        p.append("<p class='muted'>沒有 sbomgate 結果（見狀態表），無法判斷哪些元件版本未知。</p>")
    else:
        g = vu["sbomgate"]
        p.append(f"<div class='card'>sbomgate：SBOM {badge(g['sbom'] or '?', 'NOT_RUN')} 弱點分析 {badge(g['vulnerability_analysis'] or '?', 'OK' if g['vulnerability_analysis'] == 'COMPLETE' else 'GAP')}"
                 + ("<ul>" + "".join(f"<li>{e(x)}</li>" for x in g["reasons"] + [f'注意：{n}' for n in g["notes"]]) + "</ul>" if g["reasons"] or g["notes"] else "")
                 + "</div>")
        if vu["components"]:
            up = m.get("upload_versions_removed")
            p.append("<p>下列元件的版本來自範圍下限、沒有版本或無法辨識。<b>不做弱點比對</b>（避免把範圍下限當成實際版本而產生誤報，或在版本未知時顯示為沒有比對到）。"
                     + (f"上傳 DT 與 ScanCode.io 前已移除這 {e(up)} 個元件的版本（保留名稱與不含版本的 purl；sbom/sbom.upload.cdx.json），原始 SBOM 原樣保留在 sbom/sbom.cdx.json。"
                        if up not in (None, "", "0") else "這次沒有產生移除版本的上傳用 SBOM（見 C-upload-sbom 階段）。")
                     + "若 Grype 或 DT 仍有這些元件的比對，本報告把它們移到下表，不計入弱點數。</p>")
            p.append("<div class='wrap'><table><tr><th>名稱</th><th>SBOM 中的版本</th><th>purl</th><th>判定</th><th>原因</th></tr>" + "".join(
                f"<tr><td>{e(c['name'])}</td><td><code>{e(c['version'])}</code></td><td><code>{e(c['purl'])}</code></td><td>{e(c['class'])}"
                + ("（已有解析後的同名元件）" if c.get("superseded_by_resolved") else "") + ("（專案本身）" if c.get("self_component") else "")
                + f"</td><td>{e(c['why'])}</td></tr>" for c in vu["components"]) + "</table></div>")
        else:
            p.append("<p class='muted'>sbomgate 沒有判定任何版本未知的元件。</p>")
        if vu["excluded_records"]:
            p.append(f"<details><summary>排除、未計入的比對（原因見表）：{len(vu['excluded_records'])} 筆</summary><div class='wrap'><table><tr><th>工具</th><th>ID</th><th>purl</th><th>版本</th><th>原因</th></tr>"
                     + "".join(f"<tr><td>{e(x['tool'])}</td><td><code>{e(x['id'])}</code></td><td><code>{e(x['purl'])}</code></td><td><code>{e(x['version'])}</code></td>"
                               f"<td>{e(x.get('reason'))}</td></tr>"
                               for x in vu["excluded_records"]) + "</table></div></details>")
        if g["unmapped_matches"]:
            p.append(f"<p>另有 {len(g['unmapped_matches'])} 筆 Grype 比對找不到對應的 SBOM 元件（保留在上方弱點表）。</p>")
    # --- 5. 授權 ---
    p.append("<h2>授權（DejaCode）</h2>")
    ch = rep.get("license_chain") or {}

    def n(x):
        return "?" if x is None else str(x)
    mo = (f"；另移除只供比對的元件 {ch['removed_matching_only']} 個（C-kernel-l4t-map 加的 Canonical 核心，不在原始 SBOM、不是安裝的套件）"
          if ch.get("removed_matching_only") else "")
    rm = (f"（移除 file {n(ch.get('removed_file'))}、過長 {n(ch.get('removed_too_long'))}、其他 {n(ch.get('removed_other'))}{mo}）"
          if ch.get("scio_upload") is not None else "（沒有轉換紀錄）")
    p.append("<div class='card'><b>數量鏈</b>：原始 SBOM 元件 " + e(n(ch.get("sbom_components")))
             + " → 上傳 ScanCode.io " + e(n(ch.get("scio_upload"))) + e(rm)
             + " → ScanCode.io 套件 " + e(n(ch.get("scio_packages"))) + (f"（唯一 purl {e(ch['scio_unique_purls'])}）" if ch.get("scio_unique_purls") is not None else "")
             + " → DejaCode 產品套件 " + e(n(ch.get("dejacode_packages")))
             + "<br><span class='muted'>「?」表示該環節沒有執行或沒有結果（見狀態表 E-*）；每一段減少的元件在 DejaCode 沒有授權判定。"
               "原始 SBOM 含 file 等非套件元件，元件數不等於套件數。</span></div>")
    lic = rep["licenses"]
    if lic is None:
        p.append("<p class='muted'>沒有 DejaCode 讀回的授權資料（見狀態表 E-*）。</p>")
    else:
        cn = lic["counts"]
        lab = {"error": "error（政策禁止）", "warning": "warning", "pass": "usage policy 無警示", "no_license": "unknown（沒有授權資料）", "not_assessed": "未評估"}
        p.append(f"<p>產品 <code>{e(lic['product'])}</code>，套件 {e(lic['packages'])} 個。</p><table><tr>" + "".join(f"<th>{e(lab.get(k, k))}</th>" for k in cn)
                 + "</tr><tr>" + "".join(f"<td class='num'>{e(n)}</td>" for n in cn.values()) + "</tr></table>")
        p.append("<details><summary>授權分布</summary><table><tr><th>授權運算式</th><th>套件數</th></tr>"
                 + "".join(f"<tr><td><code>{e(k)}</code></td><td class='num'>{n}</td></tr>" for k, n in lic["distribution"]) + "</table></details>")
        if lic["unknown"]:
            p.append(f"<h3>unknown 與未評估：{len(lic['unknown'])} 個（不是合規）</h3><div class='wrap'><table><tr><th>套件</th><th>授權運算式</th><th>標示</th><th>未評估的授權鍵</th></tr>"
                     + "".join(f"<tr><td><code>{e(x['package'])}</code></td><td><code>{e(x['license_expression'])}</code></td><td>{e(x['label'])}</td>"
                               f"<td>{e('、'.join(x['unassessed_keys']))}</td></tr>" for x in lic["unknown"]) + "</table></div>")
        if lic["attention"]:
            p.append(f"<details open><summary>usage policy 為 error 或 warning：{len(lic['attention'])} 個</summary><table><tr><th>套件</th><th>授權運算式</th><th>判定</th></tr>"
                     + "".join(f"<tr><td><code>{e(x['package'])}</code></td><td><code>{e(x['license_expression'])}</code></td><td>{e(x['verdict'])}</td></tr>" for x in lic["attention"])
                     + "</table></details>")
        if lic.get("or_choice"):
            p.append(f"<details><summary>授權運算式有 OR、擇一時等級不同：{len(lic['or_choice'])} 個</summary>"
                     "<p class='muted'>上表照 DejaCode 的算法（運算式裡每個授權都算，取最嚴重的）。這裡列出依 SPDX 的 OR 語意可以改選另一個授權時的等級；"
                     "要採用時在 DejaCode 設定產品套件的授權（concluded license），這裡不代替授權決策。</p>"
                     "<table><tr><th>套件</th><th>授權運算式</th><th>DejaCode 判定</th><th>OR 擇一</th></tr>"
                     + "".join(f"<tr><td><code>{e(x['package'])}</code></td><td><code>{e(x['license_expression'])}</code></td><td>{e(x['verdict'])}</td>"
                               f"<td>{e(x['or_choice_verdict'])}</td></tr>" for x in lic["or_choice"]) + "</table></details>")
    ps_ = rep.get("package_scans")
    if ps_ is not None:
        p.append("<h3>逐套件掃描（ScanCode.io）</h3><p>DejaCode 下載每個套件給 ScanCode.io 掃描授權與版權：" + "、".join(f"{e(k)} {e(v)}" for k, v in sorted(ps_.items()))
                 + "。<span class='muted'>no_scan＝下載網址不可達或沒有送出；not_scannable＝推不出下載網址（例如 apk）；"
                   "沒有掃描成功的套件，授權只有 SBOM 宣告的部分，版權沒有評估。</span></p>")
    ns = rep.get("notice")
    if ns is not None:
        cl = {"detected": "偵測到版權聲明", "holder_only": "只有版權人", "inferred": "DejaCode 推定（不是偵測結果）",
              "dejacode_only": "只有 DejaCode 欄位", "none": "沒有"}
        cc = ns.get("copyright_class") or {}
        p.append("<h3>版權與 NOTICE</h3><p>版權：" + "、".join(f"{e(cl.get(k, k))} {e(v)}" for k, v in sorted(cc.items()))
                 + f"。NOTICE 草稿：<a href='dejacode/NOTICE.txt'>dejacode/NOTICE.txt</a>（缺授權 {len(ns.get('missing_license') or [])}、"
                   f"沒有偵測到版權 {len(ns.get('missing_copyright') or [])}、授權沒有全文 {len(ns.get('licenses_without_text') or [])}；發布前要人工確認）。</p>")
    fs = rep.get("files_scan")
    if fs is not None:
        p.append("<h3>檔案層級授權與版權（專案本身或映像）</h3><p>" + e(fs.get("pipeline") or "") + "：檔案 " + e(n(fs.get("files")))
                 + "、有授權偵測 " + e(n(fs.get("files_with_license"))) + "、有版權聲明 " + e(n(fs.get("files_with_copyright")))
                 + (f"；不屬於任何套件的檔案中有授權 {e(fs['loose_files_with_license'])}" if fs.get("loose_files_with_license") is not None else "")
                 + "。<span class='muted'>明細：scancode/files-summary.json。</span></p>")
        if fs.get("licenses"):
            p.append("<details><summary>偵測到的授權（SPDX）</summary><table><tr><th>授權</th><th>檔案數</th></tr>"
                     + "".join(f"<tr><td><code>{e(k)}</code></td><td class='num'>{e(v)}</td></tr>" for k, v in fs["licenses"][:50]) + "</table></details>")
    # --- 6. 全部階段 ---
    p.append("<h2>全部階段</h2><div class='wrap'><table><tr><th>階段</th><th>狀態</th><th>說明</th></tr>"
             + "".join(f"<tr><td><code>{e(s['stage'])}</code></td><td>{badge(s['status'])}</td><td>{e(s['detail'])}</td></tr>" for s in rep["stages"])
             + "</table></div>")
    if (m.get("network") or {}).get("sbom_resolution_online"):
        p.append("<div class='card alert inc'><b>連網解析</b>：這次用了 --allow-network-resolve。這個選項只能用於可信的專案："
                 "沙箱有網路時，專案的建置腳本可以連到外部，也可以連到主機 127.0.0.1 上沒有驗證的服務（例如 Ollama 11434 埠）。"
                 "SBOM 的版本是解析當下的結果。</div>")
    p.append("<p class='muted'>沙箱：不可信的程式在 bwrap 內執行，家目錄與 GitHub runner 目錄以 tmpfs 遮蔽、/run 遮蔽；"
             "連網的步驟（govulncheck、--allow-network-resolve）可以連到主機 127.0.0.1 上沒有驗證的服務，bwrap 無法依目的地過濾。</p>")
    p.append("<p class='muted'>試行版的已知限制：資料源為線上版本（非離線鏡像）；沒有片段比對、韌體分析、SSVC、VEX 轉換；準確度只以 tests/expected 與已知答案映像驗收"
             "。</p></main></body></html>")
    return "".join(p)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True, help="sca-scan 的輸出資料夾")
    a = ap.parse_args(argv)
    if not os.path.isdir(a.out):
        print(f"不是資料夾：{a.out}", file=sys.stderr)
        return 3
    try:
        rep = build(a.out)
        page = render(rep)
        with open(os.path.join(a.out, "report.json"), "w", encoding="utf-8") as f:
            json.dump(rep, f, ensure_ascii=False, indent=1, default=sorted)
        with open(os.path.join(a.out, "report.html"), "w", encoding="utf-8") as f:
            f.write(page)
    except Exception as ex:   # 報告壞掉不可默默產生半份
        print(f"內部錯誤：{type(ex).__name__}: {ex}", file=sys.stderr)
        return 4
    print(f"整體 {rep['overall']}；未完成或不完整 {len(rep['incomplete'])} 項；弱點列 {len(rep['vulnerabilities']['rows'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
