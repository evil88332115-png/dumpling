#!/usr/bin/env python3
"""kernel_merge.py：映像有多顆核心時，逐顆判定的結果怎麼合併成「產品」的結論（M7d-1，D-036／D-061）。只放純函式（沒有網路、不改輸入），
判定邏輯集中在這一個檔案，方便獨立驗證；vex_export.py（K1／K2 的讀取端）與 cra_report.py（核心列去重、報告）呼叫它。

名詞
  核心（版本）  映像出貨的核心，以 /usr/lib/modules/<版本>/ 的資料夾名稱為準（sca-scan 的 scan/kernel-versions.json）。
  judged       sca-scan 逐顆交給判定工具（kernel_config.py、kernel_module_map.py）的核心；每顆一份 scan/kernels/<版本>/kernel-config.json。
  單顆的結果    每個 CVE 對某一顆核心：affected／not_affected／unknown（kernel_config.py 的 decision）。

合併規則（merge_cve；每個 CVE）
  1. 任一顆 affected → 產品 affected。
  2. 每一顆**出貨**的核心都有可採用的結果（usable），而且都是 not_affected → 產品 not_affected（呼叫端另外照 D-035 寫依據：build-record，
     位置逐顆列出核心版本與 config SHA-256）。出貨的核心清單是 shipped；沒有人知道 shipped（None）時不排除。
  3. 其他一律不排除（unknown）：有一顆 unknown、有一顆沒有結果（no_result：沒有檔案、結果不可採用、沒有這個 CVE）、有出貨的核心沒判定
     （not_judged）、這一列對不到核心（row_matched False）。維持「沒有判定」的行為（VEX 的 in_triage／NOT_ASSESSED）。
  K2（只有 kernel-modules.json 那一顆）：呼叫端用 overrides 指定「這一顆因 K2 是 not_affected」；其他核心仍然只看 K1，
  K2 不適用的核心不會被 overrides 變成 not_affected（overrides 只會出現在 K2 真的成立的那一顆）。沒判定的核心不能被 overrides 蓋過。

核心列的合併（merge_rows）：同一個 CVE 在好幾個核心套件上各一列 → 一列，帶 kernel_packages。合併欄位時一律保守：嚴重度取最高、
fix_state 只要有一個套件不是 fixed 就不是 fixed、修補版本取聯集、有人在 DT 設的排除只在每個套件都有同樣的排除時才保留。
"""
import os
import re
import stat

AFFECTED, NOT_AFFECTED, UNKNOWN = "affected", "not_affected", "unknown"
NO_RESULT, NOT_JUDGED = "no_result", "not_judged"
DECISIONS = (AFFECTED, NOT_AFFECTED, UNKNOWN)
STATES = DECISIONS + (NO_RESULT, NOT_JUDGED)

VER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+~-]{0,99}$")       # 同 sca-scan／kernel_versions.py：版本會成為路徑的一段，沒有 /、不是 ..
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

# 核心套件對到哪顆核心（package_scope 的 scope）
SCOPE_KERNEL, SCOPE_PRODUCT, SCOPE_UNMATCHED = "kernel", "product", "unmatched"


def valid_version(v):
    return isinstance(v, str) and bool(VER_RE.match(v))


# ---------- 合併規則 ----------

def kernel_state(version, judged, results, cve):
    """一顆出貨核心對一個 CVE 的狀態：
      not_judged  沒有交給判定工具（不在 judged）；
      no_result   judged 了但沒有可採用的結果（results[version] 不是 {"usable": True, …}），或結果裡沒有這個 CVE，或值不認得；
      affected／not_affected／unknown  結果裡的判定。
    results：{版本: {"usable": bool, "decisions": {CVE: 判定}} 或 None}。"""
    if version not in judged:
        return NOT_JUDGED
    r = results.get(version) if isinstance(results, dict) else None
    if not isinstance(r, dict) or r.get("usable") is not True:
        return NO_RESULT
    d = (r.get("decisions") or {}).get(cve)
    return d if d in DECISIONS else NO_RESULT


def override_states(states, overrides):
    """K2：overrides {版本: not_affected} 蓋過那顆核心的狀態（新的 dict）。只有 not_affected 能蓋；沒判定（not_judged）的核心不能被蓋過；
    不在 states 裡的版本忽略。K2 不適用的核心不會出現在 overrides，所以它的狀態維持 K1 的結果。"""
    out = dict(states)
    for v, s in (overrides or {}).items():
        if v in out and s == NOT_AFFECTED and out[v] != NOT_JUDGED:
            out[v] = NOT_AFFECTED
    return out


def merge_states(states, shipped_known=True, row_matched=True):
    """各顆核心的狀態 {版本: 狀態}（要涵蓋全部出貨的核心）→ (產品的判定, 原因代碼)。
    原因：affected、all_not_affected、unknown:<版本>、no_result:<版本>、not_judged:<版本>、shipped_unknown、row_unmatched、no_kernels。"""
    if not states:
        return UNKNOWN, "no_kernels"
    aff = sorted(v for v, s in states.items() if s == AFFECTED)
    if aff:
        return AFFECTED, "affected"                     # 規則 1：任一顆 affected，其他顆是什麼都一樣
    if not shipped_known:
        return UNKNOWN, "shipped_unknown"
    if not row_matched:
        return UNKNOWN, "row_unmatched"
    for want in (NOT_JUDGED, NO_RESULT, UNKNOWN):        # 其他一律不排除；原因依輕重挑一個（沒判定 > 沒結果 > unknown）
        bad = sorted(v for v, s in states.items() if s == want)
        if bad:
            return UNKNOWN, f"{want}:{bad[0]}"
    if all(s == NOT_AFFECTED for s in states.values()):
        return NOT_AFFECTED, "all_not_affected"
    return UNKNOWN, "unrecognized_state"                 # 不認得的狀態值：不排除


def merge_cve(cve, shipped, judged, results, overrides=None, row_matched=True):
    """一個 CVE 在整個產品上的判定 → {"decision", "reason", "states"}。
    shipped：映像出貨的核心版本清單；None＝讀不出來（不排除）。judged：判定過的核心版本清單。
    要看的核心＝shipped 與 judged 的聯集（judged 但沒出貨的核心若判定 affected 也算：偏保守）；其中只有 shipped 的核心都 not_affected 才排除
    （judged 但沒出貨的核心不要求 not_affected，但有 affected 就 affected；它沒有結果不擋排除）。
    overrides：{版本: not_affected}（K2；只對判定過的核心有效）。row_matched：這一列的核心套件都對得到判定過的核心。"""
    shipped_known = isinstance(shipped, (list, tuple, set, frozenset))
    ship = sorted(set(shipped)) if shipped_known else []
    judged = list(judged or ())
    names = sorted(set(ship) | set(judged))
    states = override_states({v: kernel_state(v, judged, results, cve) for v in names}, overrides)
    if shipped_known and ship:
        # 沒出貨的 judged 核心：不要求 not_affected（它不在映像裡），只留 affected 的證據
        need = {v: s for v, s in states.items() if v in ship or s == AFFECTED}
    else:
        need = dict(states)
    decision, reason = merge_states(need, shipped_known and bool(ship), row_matched)
    return {"decision": decision, "reason": reason, "states": states}


def row_states(cve_states):
    """一列有好幾個 CVE：每顆核心的狀態 → 這一列在那顆核心上的狀態。cve_states：[{版本: 狀態}, …]（每個 CVE 一份）。
    任一個 CVE affected → affected；全部 not_affected → not_affected；否則有 not_judged → not_judged、有 no_result → no_result、其他 unknown。"""
    out = {}
    for v in sorted({v for s in cve_states for v in s}):
        ss = [s.get(v, NO_RESULT) for s in cve_states]
        if not ss:
            out[v] = NO_RESULT
        elif AFFECTED in ss:
            out[v] = AFFECTED
        elif all(x == NOT_AFFECTED for x in ss):
            out[v] = NOT_AFFECTED
        else:
            out[v] = next((w for w in (NOT_JUDGED, NO_RESULT, UNKNOWN) if w in ss), UNKNOWN)
    return out


# ---------- 核心套件對到哪顆核心 ----------

_MODDIR = re.compile(r"^/(?:usr/)?lib/modules/([^/]+)(?:/|$)")
_BOOTFILE = re.compile(r"^/boot/(?:vmlinuz|vmlinux|System\.map|config|initrd\.img)-([^/]+)$")


def kernel_version_of_path(path):
    """dpkg 的檔案路徑 → 它屬於哪顆核心的版本字串（/usr/lib/modules/<版本>/… 與 /lib/modules/<版本>/…，或 /boot/vmlinuz-<版本> 等）；
    不是核心的檔案 → None。版本字串只取合法的（不含 /、不是 ..）。"""
    m = _MODDIR.match(path) or _BOOTFILE.match(path)
    return m.group(1) if m and valid_version(m.group(1)) else None


MAX_OWNERS_BYTES = 512 * 1024 * 1024


def read_kernel_owners(pkgdb):
    """pkgdb 資料夾（pkg_why.py extract）的 dpkg-file-owners（每行「套件<TAB>路徑」；映像 var/lib/dpkg/info/*.list 的內容）→
    ({套件名稱: {核心版本}}, None)；沒有、不是一般檔案、被截斷（#partial）、空的、讀不了 → (None, 原因)。
    只留核心的檔案（kernel_version_of_path）；擁有者的套件名稱去掉 :<架構>。不跟隨符號連結；逐行讀，不整個載入。"""
    if pkgdb is None:
        return None, "no pkgdb"
    p = os.path.join(str(pkgdb), "dpkg-file-owners")
    try:
        st = os.lstat(p)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_OWNERS_BYTES:
            return None, "dpkg-file-owners is not a regular file or too large"
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None, "the scanned image has no dpkg file lists"
    except OSError as e:
        return None, f"dpkg-file-owners unreadable ({type(e).__name__})"
    owners, n = {}, 0
    try:
        with os.fdopen(fd, "rb") as f:
            for i, raw in enumerate(f):
                line = raw.decode("utf-8", "replace").rstrip("\n")
                if i == 0 and line.startswith("#partial"):
                    return None, "the dpkg file lists are partial"
                pkg, _, path = line.partition("\t")
                if not pkg or not path.startswith("/"):
                    continue
                n += 1
                v = kernel_version_of_path(path)
                if v is not None:
                    owners.setdefault(pkg.split(":", 1)[0], set()).add(v)
    except OSError as e:
        return None, f"dpkg-file-owners unreadable ({type(e).__name__})"
    return (owners, None) if n else (None, "dpkg-file-owners is empty")


def package_scope(name, owners, shipped):
    """一個核心套件（名稱）→ {"scope", "kernels"}：
      kernel     這個套件擁有的核心檔案都屬於出貨的核心（shipped）→ kernels＝那些核心（排序）；
      product    對不到任何一顆核心（meta 套件、linux-base 等沒有核心檔案的套件；或沒有檔案清單 owners 是 None）→ 算整個產品：
                 所有判定過的核心都要看；
      unmatched  擁有的核心檔案裡有不是出貨核心的版本（資料自相矛盾）→ 對不到，這一列不排除。
    owners：read_kernel_owners 的結果（None＝沒有檔案清單）。shipped：出貨的核心；None＝不明（不核對，不會有 unmatched）。"""
    if not isinstance(owners, dict):
        return {"scope": SCOPE_PRODUCT, "kernels": []}
    vs = owners.get(str(name or ""))
    if not vs:
        return {"scope": SCOPE_PRODUCT, "kernels": []}
    if shipped is None:                    # 出貨的核心清單不明（沒有 kernel-versions.json 的舊掃描）：不能核對，套件擁有的核心檔案就是它對到的核心
        return {"scope": SCOPE_KERNEL, "kernels": sorted(vs)}
    ship = set(shipped)
    bad = sorted(v for v in vs if v not in ship)
    if bad:
        return {"scope": SCOPE_UNMATCHED, "kernels": sorted(v for v in vs if v in ship), "unknown_kernels": bad}
    return {"scope": SCOPE_KERNEL, "kernels": sorted(vs)}


def row_matched(packages):
    """這一列的核心套件都對得到判定過的核心（沒有一個 unmatched）。沒有套件清單 → 不認得（False）。"""
    return bool(packages) and all(isinstance(p, dict) and p.get("scope") in (SCOPE_KERNEL, SCOPE_PRODUCT) for p in packages)


# ---------- 核心列的合併（每個 CVE 一列） ----------

FIX_WORST_FIRST = ("not-fixed", "wont-fix", "unknown", "no Grype data")      # 非 fixed 的狀態，依「最需要處理」排前面（同 cra_report.fix_state）


def merge_fix_state(states):
    """各套件的 fix_state → 一個：全部 fixed 才是 fixed；有一個不是 fixed 就不是 fixed（取 FIX_WORST_FIRST 裡最前面的）。"""
    states = [s for s in states]
    if states and all(s == "fixed" for s in states):
        return "fixed"
    for s in FIX_WORST_FIRST:
        if s in states:
            return s
    return next((s for s in states if s != "fixed"), "no Grype data")


def package_of(row, scope):
    """一列 → kernel_packages 的一筆（名稱、版本、purl、對到的核心與依據）。"""
    return {"name": row.get("name") or row.get("component"), "component": row.get("component"), "version": row.get("version"),
            "purl": row.get("purl") or "", "scope": scope["scope"], "kernels": list(scope.get("kernels") or []),
            **({"installed_as": list(row["installed_as"])} if row.get("installed_as") else {}),
            **({"unknown_kernels": list(scope["unknown_kernels"])} if scope.get("unknown_kernels") else {})}


def _pkg_key(p):
    return (0 if p["scope"] == SCOPE_KERNEL else 1, str(p["name"] or ""), str(p["version"] or ""), str(p["purl"] or ""))


def annotate_single(row, scope):
    """只有一個核心套件的列（多顆核心時也要有 kernel_packages，K1／K2 的讀取端靠它判斷這一列對不對得到核心）：新的列，不改輸入。"""
    r = dict(row)
    r["kernel_packages"] = [package_of(row, scope)]
    return r


def _union(lists):
    out = []
    for xs in lists:
        for x in xs or []:
            if x not in out:
                out.append(x)
    return out


def merge_rows(rows, scopes, sev_rank):
    """同一個 CVE 的核心列（至少 2 列，都是 is_kernel_row）→ 一列（新的 dict，不改輸入）。
    rows：cra_report 的列；scopes：{id(row)：package_scope 的結果}（以列物件的 id() 為鍵，呼叫端依列算好）；sev_rank：{嚴重度: 排名（小＝重）}。
    主列（元件、版本、purl 等身分欄位的來源）：有對到核心的套件排前面，再依名稱、版本、purl 排序，取第一個。
    欄位：
      severity／severity_source／severity_detail／severity_dt：取最嚴重的那一列的值（同樣重時取主列順序在前的）；sev_by_source 每個來源取最重；
      cvss：分數最高的；epss、epss_pct：各取最大；kev、kev_by_cve：任一個是；kev_sources、source_ids、all_ids、cves、installed_as、sources、
        grype_namespaces、fix_versions：聯集（保留順序）；n_findings、grype_matches：加總；
      fix_state：merge_fix_state；fix：不同的說明用「; 」連起來；fix_next：每一列都有而且相同才留，否則 None（用到 {fix_version} 的規則不套用）；
      analysis（DT 人工分析）：每一列都有判定的分析時全留（from_dt 取最保守的）；只有部分列有 → 拿掉會關閉弱點的（NOT_AFFECTED、RESOLVED、FALSE_POSITIVE、
        解決類）判定，只留 EXPLOITABLE、IN_TRIAGE、有抑制標記的，並在 kernel_merge["dropped_analysis"] 記下（一個套件上的排除不能代表其他套件）；
      found_by：全部相同才留，否則拿掉。tier：呼叫端重算（tier_of）。
    新欄位：kernel_packages（每個套件一筆，主列的在第一個）、kernel_merge {"members": 套件數, "dropped_analysis": […]}。"""
    if len(rows) < 2:
        raise ValueError("merge_rows needs at least two rows")
    pk = {id(r): package_of(r, scopes[id(r)]) for r in rows}
    ordered = sorted(rows, key=lambda r: _pkg_key(pk[id(r)]))
    base = dict(ordered[0])

    def rank(r):
        return sev_rank.get(str(r.get("severity") or "").upper(), 9)

    best = min(ordered, key=rank)                      # min 取第一個最小：同樣重時主列順序在前的
    for k in ("severity", "severity_source", "severity_detail"):
        if k in best:
            base[k] = best[k]
    if any("severity_dt" in r for r in ordered):
        base["severity_dt"] = min((r["severity_dt"] for r in ordered if "severity_dt" in r), key=lambda s: sev_rank.get(str(s).upper(), 9))
    srcs = sorted({s for r in ordered for s in (r.get("sev_by_source") or {})})
    if srcs:
        base["sev_by_source"] = {s: min((r["sev_by_source"][s] for r in ordered if s in (r.get("sev_by_source") or {}) and r["sev_by_source"][s]),
                                        key=lambda x: sev_rank.get(str(x).upper(), 9), default=None) for s in srcs}
    scored = [r for r in ordered if r.get("cvss_score") is not None]
    if scored:
        top = max(scored, key=lambda r: r["cvss_score"])
        base["cvss_score"], base["cvss"] = top["cvss_score"], top.get("cvss")
    for k in ("epss", "epss_pct"):
        vals = [r[k] for r in ordered if r.get(k) is not None]
        base[k] = max(vals) if vals else None
    base["kev"] = any(r.get("kev") for r in ordered)
    if any(r.get("kev_by_cve") for r in ordered):
        base["kev_by_cve"] = True
    for k in ("kev_sources", "source_ids", "all_ids", "cves", "installed_as", "sources", "grype_namespaces", "fix_versions"):
        if any(k in r for r in ordered):
            u = _union(r.get(k) for r in ordered)
            base[k] = sorted(u) if k in ("source_ids", "all_ids", "cves", "grype_namespaces", "fix_versions", "installed_as") else u
    for k in ("n_findings", "grype_matches"):
        if any(k in r for r in ordered):
            base[k] = sum(int(r.get(k) or 0) for r in ordered)
    if any("fix_state" in r for r in ordered):
        base["fix_state"] = merge_fix_state([r.get("fix_state") for r in ordered if "fix_state" in r])
    if any("fix" in r for r in ordered):
        fx = []
        for r in ordered:
            if r.get("fix") and r["fix"] not in fx:
                fx.append(r["fix"])
        base["fix"] = "; ".join(fx)
    nxt = [r.get("fix_next") for r in ordered]
    base["fix_next"] = nxt[0] if nxt and all(x == nxt[0] for x in nxt) and nxt[0] is not None else None
    eo = [e for r in ordered for e in r.get("epss_other") or []]
    if eo:
        by = {}
        for e in eo:
            if e["source"] not in by or e["probability"] > by[e["source"]]["probability"]:
                by[e["source"]] = e
        base["epss_other"] = [by[s] for s in ("same CVE", "Grype") if s in by] + [e for s, e in sorted(by.items()) if s not in ("same CVE", "Grype")]
    fb = {r.get("found_by") for r in ordered}
    if len(fb) > 1:
        base.pop("found_by", None)
    # DT 的人工分析
    closing = ("NOT_AFFECTED", "RESOLVED", "RESOLVED_WITH_PEDIGREE", "FALSE_POSITIVE")
    has = [any(str(a.get("state") or "").upper() for a in (r.get("analysis") or [])) for r in ordered]
    allan = [a for r in ordered for a in r.get("analysis") or []]
    dropped = []
    if any(has) and not all(has):
        keep = []
        for a in allan:
            if str(a.get("state") or "").upper() in closing:
                dropped.append({"state": str(a.get("state")).upper(), "vuln_id": a.get("vuln_id")})
            else:
                keep.append(a)
        allan = keep
    base["analysis"] = allan
    # usn
    for k in ("usn_merged",):
        if any(k in r for r in ordered):
            m = {}
            for r in ordered:
                for u, cves in (r.get(k) or {}).items():
                    m.setdefault(u, cves)
            base[k] = dict(sorted(m.items()))
    if any("usn_listed" in r for r in ordered):
        base["usn_listed"] = sorted(_union(r.get("usn_listed") for r in ordered))
    base["kernel_packages"] = [pk[id(r)] for r in ordered]
    base["kernel_merge"] = {"members": len(ordered), **({"dropped_analysis": dropped} if dropped else {})}
    return base


def group_kernel_rows(rows):
    """rows（已經標好 row["kernel"]）→ ([不是核心的列 + 單獨的核心列…照原順序], {CVE 編號: [核心列…]})：回傳依 row["id"] 分組的核心列。
    只做分組（不改列）：呼叫端決定要不要合併。"""
    groups = {}
    for r in rows:
        if r.get("kernel"):
            groups.setdefault(r["id"], []).append(r)
    return groups
