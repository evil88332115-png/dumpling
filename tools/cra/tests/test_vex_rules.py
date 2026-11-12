"""vex_export.py 的批次規則（CRA/Config/vex-rules.json）：格式驗證（禁止的狀態、缺 response）、每個條件、KEV 永遠不套用、P1 的限制、
優先順序與 shadowed、範本（含缺值）、輸出穩定、閘門（OK／ATTENTION 仍受影響／GAP）、rules check 的乾跑、rules add 的安全性，
以及 cra_report 的整合（VEX 小節的規則表、summary.json 的 vex.rules）。"""
import copy
import json
import os
import random
import stat
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import vex_export as vx  # noqa: E402
from test_cra_report import finding, make_project, make_scan, run, write_json  # noqa: E402
from test_vex_export import NVB, PBOM, ann, dt, kcfg, row  # noqa: E402
from test_cra_distro import recheck_doc  # noqa: E402

CLI = HERE.parent / "vex_export.py"
KVER = "6.8.0-1021.21"


def rule(rid="R1", scope="all", state="exploitable", response=("update",), detail="Fixed in {fix_version}.", rec=None, **match):
    s = {"state": state, "detail_template": detail}
    if response:
        s["response"] = list(response)
    if rec:
        s["recommendation"] = rec
    return {"id": rid, "description": f"rule {rid}", "author": "Alice", "date": "2026-11-02", "reason": "bulk decision",
            "match": dict(scope=scope, **match), "set": s}


def doc(*rules):
    return {"schema": vx.RULES_SCHEMA, "rules": list(rules)}


def krow(rid, **kw):
    return row(rid, "linux-nvidia-tegra", KVER, kernel=True, **kw)


def assess(rs, rules, **kw):
    ctx = kw.pop("ctx", {"kernel_fix_all": {"linux-nvidia-tegra": "6.8.0-1036.39"}})
    return vx.assess(rs, rules=rules, rule_ctx=ctx, **kw)


def gate(allr, conf, **kw):
    return vx.gate(allr, conf, **{"grype_checked": True, "not_assessed": [], **kw})


# ---------- 格式驗證 ----------

@pytest.mark.parametrize("state", ["not_affected", "resolved", "resolved_with_pedigree", "false_positive"])
def test_forbidden_states_rejected_with_clear_error(state):
    with pytest.raises(vx.VexInputError) as e:
        vx.check_rules(doc(rule(state=state, response=())))
    assert f"規則不能設 {state}" in str(e.value) and "逐列的證據" in str(e.value)


def test_rule_validation_errors():
    bad = [
        (rule(state="in_triage", response=(), rec="x"), "recommendation：只用在 exploitable"),
        (rule(detail="Fixed in {fix_versoin}"), "不認得的欄位 {fix_versoin}"),
        (rule(detail="{component.__class__}"), "不認得的欄位"),
        (rule(detail="{component!r}"), "不認得的欄位 {component!r}"),
        (rule(detail="{component:>10}"), "不認得的欄位"),
        (rule(detail="Fixed {"), "範本格式錯"),
        (rule(kev=True), "kev：只能是 false"),
        (rule(scope="non_kernel", kernel_config=["affected"]), "kernel_config：只用在 scope kernel"),
        (rule(kernel_config=["not_affected"], scope="kernel"), "not_affected 不是可用的值"),
        (rule(scope="everything"), "scope：必填"),
        (rule(fix_state=["fixed", "fixed"]), "不重複"),
        (rule(tier=["p4"]), "p4 不是可用的值"),
        (rule(purl_prefix=["pkg:deb/ubuntu/openssl@3"]), "purl_prefix"),
        (rule(epss_percentile_max=1.5), "0 到 1"),
        (rule(include_no_epss=True), "只配 epss_percentile_max"),
        (rule(allow_p1="yes"), "allow_p1"),
        (dict(rule(), date="2026-13-01"), "YYYY-MM-DD"),
        (dict(rule(), id="R 1"), "id：只能用"),
        (dict(rule(), extra=1), "extra：不認得的鍵"),
        (dict(rule(), reason=""), "reason：必填"),
    ]
    for r, msg in bad:
        with pytest.raises(vx.VexInputError) as e:
            vx.check_rules(doc(r))
        assert msg in str(e.value), (msg, str(e.value))
    with pytest.raises(vx.VexInputError, match="和 rules\\[0\\] 相同"):
        vx.check_rules(doc(rule("R1"), rule("R1")))
    with pytest.raises(vx.VexInputError, match="schema"):
        vx.check_rules({"rules": []})
    # 正確的：in_triage 不需要 response；kev false 可以寫明
    assert len(vx.check_rules(doc(rule(state="in_triage", response=(), detail="Under review ({cve}).", kev=False),
                                  rule("R2", severity=["high"], epss_percentile_max=0.5, include_no_epss=True)))) == 2


def test_rules_file_errors_fail_report(tmp_path):
    proj, scan = make_project(tmp_path / "p"), make_scan(tmp_path / "s")
    write_json(proj / vx.RULES_REL, doc(rule(state="not_affected", response=())))
    r, s, _ = run(proj, scan)
    assert r.returncode == 1 and "VEX 批次規則檔有錯" in r.stdout and "規則不能設 not_affected" in r.stdout and s["status"] == "FAIL"


# ---------- 條件 ----------

def test_each_match_criterion():
    base = dict(fix_state="fixed", fix_next="1.2", severity="HIGH", epss_pct=0.1, tier="p2")
    rows = {
        "deb": row("CVE-1", **base),
        "pypi": row("CVE-2", "requests", "2.0", purl="pkg:pypi/requests@2.0", **base),
        "kern": krow("CVE-3", **base),
        "nofix": row("CVE-4", **dict(base, fix_state="not-fixed", fix_next=None)),
        "p3low": row("CVE-5", **dict(base, tier="p3", severity="LOW")),
        "epss_hi": row("CVE-6", **dict(base, epss_pct=0.8)),
        "epss_none": row("CVE-7", **dict(base, epss_pct=None)),
    }

    def hits(**m):
        allr, _, info = assess(copy.deepcopy(list(rows.values())), [rule(detail="d {cve}", **m)])
        return sorted(k for k, r in zip(rows, allr) if r["vex"])

    assert hits(scope="all") == sorted(rows)
    assert hits(scope="kernel") == ["kern"]
    assert hits(scope="non_kernel") == sorted(set(rows) - {"kern"})
    assert hits(purl_prefix=["pkg:pypi/"]) == ["pypi"]
    assert hits(purl_prefix=["PKG:deb/ubuntu/open"]) == ["deb", "epss_hi", "epss_none", "nofix", "p3low"]
    assert hits(purl_type=["pypi"]) == ["pypi"]
    assert hits(fix_state=["not-fixed", "wont-fix"]) == ["nofix"]
    assert hits(tier=["p3"]) == ["p3low"]
    assert hits(severity=["low", "MEDIUM"]) == ["p3low"]
    assert "epss_hi" not in hits(epss_percentile_max=0.5) and "epss_none" not in hits(epss_percentile_max=0.5)
    assert "epss_none" in hits(epss_percentile_max=0.5, include_no_epss=True)
    assert hits(scope="non_kernel", purl_type=["deb"], fix_state=["fixed"], tier=["p2"], epss_percentile_max=0.5) == ["deb"]   # AND


def test_kernel_config_criterion_only_for_checked_kernel_component():
    k = kcfg([{"cve": "CVE-1", "decision": "affected"}, {"cve": "CVE-2", "decision": "unknown"},
              {"cve": "CVE-3", "decision": "affected"}, {"cve": "CVE-4", "decision": "unknown"}])
    rs = [krow("CVE-1"), krow("CVE-2"), krow("CVE-5"),                                  # CVE-5 沒有結果
          row("CVE-3", "linux-other", "5.0", kernel=True),                                 # 別的核心
          krow("CVE-1", cves=["CVE-1", "CVE-2"], all_ids=["CVE-1", "CVE-2"], key=["CVE-1", "x", KVER]),   # 一個 affected → affected
          krow("CVE-4", cves=["CVE-4", "CVE-5"], all_ids=["CVE-4", "CVE-5"], key=["CVE-4", "y", KVER])]   # CVE-5 沒有結果 → 不成立
    allr, _, _ = assess(rs, [rule("A", "kernel", detail="a", kernel_config=["affected"]),
                             rule("U", "kernel", state="in_triage", response=(), detail="u", kernel_config=["unknown"])], kcfg=k)
    assert [r["vex"] and r["vex"]["rule"] for r in allr[:6]] == ["A", "U", None, None, "A", None]
    # status 不是 OK 時沒有結果
    allr, _, _ = assess([krow("CVE-1")], [rule("A", "kernel", detail="a", kernel_config=["affected"])], kcfg=kcfg(k["results"], "GAP"))
    assert allr[0]["vex"] is None


# ---------- KEV、P1 ----------

def test_kev_rows_never_matched():
    rs = [row("CVE-1", kev=True, tier="p1"), row("CVE-2", kev=True, tier="p3"), row("CVE-3", tier="p3"), row("CVE-4", tier="p3")]
    allr, _, info = assess(rs, [rule(detail="d", allow_p1=True)], ctx={"exploited": ["CVE-3"]})   # CVE-3：EUVD 已遭利用
    assert [r["vex"] is not None for r in allr] == [False, False, False, True]
    assert info["rules"][0]["excluded_kev"] == 3 and info["rules"][0]["applied"] == 1
    g = gate(allr, [])
    assert g["assessment"]["untriaged"] == 3 and g["verdict"] == "ATTENTION"


def test_p1_guard_and_fall_through():
    rs = [row("CVE-1", tier="p1"), row("CVE-2", tier="distro_fixed", tier_before="p1"), row("CVE-3", tier="p2")]
    allr, _, info = assess(copy.deepcopy(rs), [rule("R1", detail="d")])
    assert [r["vex"] is not None for r in allr] == [False, False, True] and info["rules"][0]["excluded_p1"] == 2
    # P1 不套用第一條，換下一條（allow_p1）
    allr, _, info = assess(copy.deepcopy(rs), [rule("R1", detail="d"), rule("R2", detail="e", allow_p1=True)])
    assert [r["vex"]["rule"] for r in allr] == ["R2", "R2", "R1"]
    assert info["rules"][0]["excluded_p1"] == 2 and info["rules"][1]["applied"] == 2


# ---------- 優先順序 ----------

def test_rules_never_override_other_sources_and_count_shadowed():
    k = kcfg([{"cve": "CVE-2025-1", "decision": "not_affected", "detail": "x"}])
    rs = [row("CVE-1", analysis=dt("NOT_AFFECTED", "CODE_NOT_PRESENT")), row("CVE-2"), row("CVE-2024-6119"),
          krow("CVE-2025-1"), row("CVE-2021-34401", "nvidia-l4t-core", "39.2.1-20260806224157", tier="p3"), row("CVE-9")]
    rules = [rule(detail="d")]
    allr, conf, info = assess(rs, rules, drc=recheck_doc(), kcfg=k, nvb=NVB,
                              annotations=[ann("CVE-2", "exploitable", purl="pkg:deb/ubuntu/openssl", response=["will_not_fix"])])
    assert [r["vex"]["source"] for r in allr[:6]] == ["dt", "annotation", "distro", "kconfig", "nvidia", "rule"]
    st = info["rules"][0]
    assert st["applied"] == sum(1 for r in allr if r["vex"] and r["vex"]["source"] == "rule")
    assert st["shadowed"] == {s: 1 for s in ("dt", "annotation", "distro", "kconfig", "nvidia")}
    assert conf == [] and allr[1]["vex"]["state"] == "exploitable" and allr[1]["vex"]["response"] == ["will_not_fix"]


def test_dt_analysis_without_justification_blocks_rule():
    """DT 的 NOT_AFFECTED 沒有理由：不採用（閘門點名），規則也不能寫一個相反的 exploitable。"""
    allr, _, info = assess([row("CVE-1", analysis=dt("NOT_AFFECTED")), row("CVE-2")], [rule(detail="d")])
    assert allr[0]["vex"] is None and allr[1]["vex"]["source"] == "rule" and info["rules"][0]["shadowed"] == {"dt": 1}
    assert gate(allr, [])["dt_without_justification"][0]["id"] == "CVE-1"


def test_dt_analysis_on_alias_finding_blocks_rule_for_main_and_split_rows():
    """GHSA（別名 CVE-A、CVE-B）上人設的 NOT_AFFECTED：不能當這兩個 CVE 的陳述，但規則也不能替它們寫 exploitable。"""
    an = [{"state": "NOT_AFFECTED", "suppressed": False, "justification": "CODE_NOT_REACHABLE", "response": "", "details": "checked",
           "vuln_id": "GHSA-aaaa-bbbb-cccc", "cves": ["CVE-2024-0001", "CVE-2024-0002"]}]
    r = row("CVE-2024-0001", "foo", "1.0", purl="pkg:pypi/foo@1.0", cves=["CVE-2024-0001", "CVE-2024-0002"], analysis=an,
            fix_state="fixed", fix_next="1.2", source_ids=["GITHUB:GHSA-aaaa-bbbb-cccc"])
    allr, conf, info = assess([r], [rule("R4", "non_kernel", detail="Fixed in {fix_version}.", purl_type=["pypi"])])
    assert allr[0]["vex"] is None and [x["vex"] for x in allr[0]["vex_extra"]] == [None]
    assert info["rules"][0]["shadowed"] == {"dt": 2} and info["rules"][0]["applied"] == 0 and conf == []
    # 分析在 UBUNTU-CVE-X 的 finding、這一列是 CVE-X（狀態 NOT_SET 的不算）
    an2 = [{"state": "EXPLOITABLE", "suppressed": False, "justification": "", "response": "", "details": "",
            "vuln_id": "UBUNTU-CVE-2024-0009", "cves": []}]
    assert vx.dt_decided(row("CVE-2024-0009", analysis=an2)) is True
    assert vx.dt_decided(row("CVE-2024-0009", analysis=[dict(an2[0], state="NOT_SET")])) is False
    assert vx.dt_decided(row("CVE-2024-0008", analysis=an2)) is False


def test_dt_suppressed_rows_and_nvidia_extra_rows_get_no_rule():
    sup = [{"state": "", "suppressed": True, "justification": "", "response": "", "details": ""}]
    allr, _, info = assess([row("CVE-1", analysis=sup), row("CVE-2")], [rule(detail="d")], nvb=NVB)
    assert allr[0]["vex"] is None and "suppressed in Dependency-Track without an analysis state" in allr[0]["vex_note"]
    assert info["suppressed_without_state"] == 1 and allr[1]["vex"]["source"] == "rule"
    nv = [r for r in allr if r.get("tier") == "nvidia_bulletin"]
    assert nv and all(r["vex"] is None or r["vex"]["source"] == "nvidia" for r in nv)
    assert info["rules"][0]["shadowed"] == {"dt_suppressed": 1} and info["rules"][0]["applied"] == 1


def test_first_matching_rule_in_file_order_wins():
    rs = [row("CVE-1", fix_state="fixed", fix_next="2"), row("CVE-2", fix_state="not-fixed")]
    allr, _, info = assess(rs, [rule("A", detail="a", fix_state=["fixed"]), rule("B", state="in_triage", response=(), detail="b")])
    assert [r["vex"]["rule"] for r in allr] == ["A", "B"]
    assert [(x["id"], x["applied"], x["shadowed"]) for x in info["rules"]] == [("A", 1, {}), ("B", 1, {})]


# ---------- 範本 ----------

def test_templates_and_missing_values():
    rs = [krow("CVE-1", fix_state="fixed", fix_next="6.8.0-1030.1"), krow("CVE-2", fix_state="fixed", fix_next=None),
          row("CVE-3", "linux-x", "1", kernel=True, fix_state="fixed", fix_next="2")]       # 別的核心元件：沒有 kernel_fix_all
    r1 = rule("K", "kernel", detail="Fixed in {fix_version} ({cve}, {component} {installed_version}).",
              rec="Move to linux-nvidia-tegra {kernel_fix_all} or later.", fix_state=["fixed"])
    r2 = rule("K2", "kernel", state="in_triage", response=(), detail="No usable fix version for {cve}; literal {{x}}.")
    allr, _, info = assess(rs, [r1, r2])
    v = allr[0]["vex"]
    assert v == {"source": "rule", "state": "exploitable", "response": ["update"], "rule": "K", "rule_author": "Alice",
                 "detail": f"Fixed in 6.8.0-1030.1 (CVE-1, linux-nvidia-tegra {KVER}). (bulk rule K: rule K)",
                 "action_statement": "Move to linux-nvidia-tegra 6.8.0-1036.39 or later. (bulk rule K: rule K)"}
    assert allr[1]["vex"]["rule"] == "K2" and allr[1]["vex"]["detail"] == "No usable fix version for CVE-2; literal {x}. (bulk rule K2: rule K2)"
    assert allr[2]["vex"]["rule"] == "K2"
    assert info["rules"][0]["template_missing"] == 2 and info["rules"][0]["applied"] == 1


def test_next_fix_for_template():
    import cra_report as cr
    r = {"fix_state": "fixed", "ptype": "deb", "version": "6.8.0-1021.21", "fix_versions": ["6.8.0-1012.12", "6.8.0-1036.39", "6.8.0-1030.31"]}
    assert cr.next_fix(r) == "6.8.0-1030.31"
    assert cr.next_fix(dict(r, fix_versions=["6.8.0-1012.12"])) is None
    assert cr.next_fix({"fix_state": "fixed", "ptype": "pypi", "version": "1.0", "fix_versions": ["1.26.18", "2.0.7"]}) == "1.26.18, 2.0.7"
    assert cr.next_fix(dict(r, fix_state="not-fixed")) is None


# ---------- 輸出 ----------

def test_rule_statements_in_cyclonedx_and_openvex_are_deterministic():
    rs = [row("CVE-2026-1", fix_state="fixed", fix_next="3.0.13-0ubuntu3.12", tier="p3"),
          row("CVE-2026-2", "libssl3t64", fix_state="not-fixed", tier="p3"),
          row("CVE-2026-3", analysis=dt("NOT_AFFECTED", "CODE_NOT_PRESENT"))]
    rules = [rule("R3", "non_kernel", detail="Fixed in {fix_version}.", rec="apt upgrade to {fix_version} in the next image.",
                  fix_state=["fixed"]),
             rule("R9", state="in_triage", response=(), detail="No fix yet for {component}.")]
    outs = []
    for seed in (1, 2):
        rr = copy.deepcopy(rs)
        random.Random(seed).shuffle(rr)
        allr, conf, info = assess(rr, rules)
        g = gate(allr, conf)
        cdx, _ = vx.cdx_vex(allr, PBOM, {"finished": "2026-11-02T00:00:00Z"}, {"name": "EX"}, g["verdict"])
        ov = vx.openvex(cdx, "Example Co.", vx.purl_by_bomlink(PBOM))
        outs.append((vx.dumps(cdx), vx.dumps(ov), json.dumps(info["rules"], sort_keys=True)))
    assert outs[0] == outs[1]
    cdx, ov = json.loads(outs[0][0]), json.loads(outs[0][1])
    v = {x["id"]: x for x in cdx["vulnerabilities"]}
    props = {p["name"]: p["value"] for p in v["CVE-2026-1"]["properties"]}
    assert props["sca-center:vex-rule"] == "R3" and props["sca-center:vex-source"] == "rule"
    assert v["CVE-2026-1"]["analysis"] == {"state": "exploitable", "response": ["update"],
                                           "detail": "Fixed in 3.0.13-0ubuntu3.12. (bulk rule R3: rule R3)"}
    assert "sca-center:vex-rule" not in {p["name"] for p in v["CVE-2026-3"]["properties"]}
    s = {x["vulnerability"]["name"]: x for x in ov["statements"]}
    assert s["CVE-2026-1"]["status"] == "affected"
    assert s["CVE-2026-1"]["action_statement"] == "apt upgrade to 3.0.13-0ubuntu3.12 in the next image. (bulk rule R3: rule R3)"
    assert s["CVE-2026-2"]["status"] == "under_investigation" and "(bulk rule R9: rule R9)" in s["CVE-2026-2"]["status_notes"]
    assert vx.label(next(r for r in allr if r["id"] == "CVE-2026-1")) == "exploitable (rule R3)"


# ---------- 閘門 ----------

def test_gate_assessment_and_open_affected():
    rules = [rule("U", detail="u {fix_version}", fix_state=["fixed"]), rule("T", state="in_triage", response=(), detail="t")]
    # 規則讓每一列都有判定，但有 exploitable → ATTENTION（評估完整、要有人做出貨決定），不是 OK
    allr, conf, _ = assess([row("CVE-1", fix_state="fixed", fix_next="2"),
                            row("CVE-3", analysis=dt("EXPLOITABLE", response="WORKAROUND_AVAILABLE"))], rules)
    g = gate(allr, conf)
    assert g["verdict"] == "ATTENTION" and g["assessment"] == {"complete": True, "untriaged": 0, "extra_cves_untriaged": 0,
                                                               "untriaged_for_gate": 0, "by_rule": 1, "in_triage_by_rule": 0}
    assert g["open_affected"] == {"rows": 2, "by_response": {"update": 1, "workaround_available": 1}, "by_rule": 1, "individual": 1}
    assert g["reasons"] == ["assessment complete; 2 affected rows (exploitable; 1 by bulk rules) need a release decision by a person "
                            "(fixed before placing on the market, or a documented risk-based justification): by response update 1, "
                            "workaround_available 1"]
    # 沒有 exploitable、沒有 untriaged、沒有規則設的 in_triage → OK
    allr, conf, _ = assess([row("CVE-4", analysis=dt("RESOLVED")), row("CVE-5", analysis=dt("IN_TRIAGE"))], rules)
    assert gate(allr, conf)["verdict"] == "OK"
    # 還有 untriaged：理由不寫 assessment complete
    allr, conf, _ = assess([row("CVE-1", fix_state="fixed", fix_next="2"), row("CVE-5", kev=True)], rules)
    g = gate(allr, conf)
    assert g["verdict"] == "ATTENTION" and g["reasons"][0].startswith("1 untriaged") and g["reasons"][1].startswith("1 affected rows")
    # 清單不完整 → GAP
    allr, conf, _ = assess([row("CVE-2", fix_state="not-fixed")], rules)
    assert gate(allr, conf, data_status="GAP")["verdict"] == "GAP"


def test_rule_in_triage_counts_as_not_assessed_but_nvidia_presumed_does_not():
    rules = [rule("T", state="in_triage", response=(), detail="t")]
    allr, conf, _ = assess([row("CVE-2", fix_state="not-fixed"), row("CVE-4", analysis=dt("RESOLVED"))], rules)
    g = gate(allr, conf)
    assert g["verdict"] == "ATTENTION" and g["reasons"] == ["set to in_triage by bulk rule, not individually assessed: 1"]
    assert g["assessment"]["complete"] is False and g["assessment"]["untriaged_for_gate"] == 1 and g["assessment"]["untriaged"] == 0
    # 同時有 exploitable：不寫 assessment complete
    allr, conf, _ = assess([row("CVE-2", fix_state="not-fixed"), row("CVE-3", analysis=dt("EXPLOITABLE", response="UPDATE"))], rules)
    assert gate(allr, conf)["reasons"][1].startswith("1 affected rows")
    # NVIDIA 推定的 in_triage（公告日期當證據）照舊不擋
    allr, conf, _ = assess([row("CVE-2021-34401", "nvidia-l4t-core", "39.2.1-20260806224157")], [], nvb=dict(NVB, needs_vendor_confirmation=[],
                           presumed_included=NVB["presumed_included"][:1]))
    g = gate(allr, conf)
    assert allr[0]["vex"]["source"] == "nvidia" and g["verdict"] == "OK" and g["assessment"]["untriaged_for_gate"] == 0


# ---------- CLI 與 cra_report ----------

RULE_FINDINGS = [
    finding("zlib1g", "1:1.3.dfsg-3.1ubuntu2", "CVE-2026-1001", "NVD", "MEDIUM", epss=0.1),
    finding("zlib1g", "1:1.3.dfsg-3.1ubuntu2", "CVE-2026-1002", "NVD", "MEDIUM", epss=0.1),
    finding("requests", "2.31.0", "GHSA-xxxx-yyyy-zzzz", "GITHUB", "MEDIUM", [{"cveId": "CVE-2026-1003"}], epss=0.1,
            purl="pkg:pypi/requests@2.31.0"),
    finding("curl", "8.5.0-2ubuntu10", "CVE-2026-1004", "NVD", "HIGH", kev=True, epss=0.2),          # KEV：不套用
    finding("paramiko", "2.12.0", "CVE-2026-1005", "NVD", "MEDIUM", epss=0.95, purl="pkg:pypi/paramiko@2.12.0"),   # P1
    finding("libxml2", "2.9.14", "CVE-2026-1006", "NVD", "LOW", epss=0.1,
            analysis={"isSuppressed": False, "state": "NOT_AFFECTED", "justification": "CODE_NOT_REACHABLE", "details": "x"}),
]
RULE_GRYPE = {"matches": [
    {"vulnerability": {"id": "CVE-2026-1001", "fix": {"state": "fixed", "versions": ["1:1.3.dfsg-3.1ubuntu2.1"]}},
     "relatedVulnerabilities": [], "artifact": {"name": "zlib1g", "version": "1:1.3.dfsg-3.1ubuntu2", "type": "deb"}},
    {"vulnerability": {"id": "CVE-2026-1002", "fix": {"state": "not-fixed", "versions": []}},
     "relatedVulnerabilities": [], "artifact": {"name": "zlib1g", "version": "1:1.3.dfsg-3.1ubuntu2", "type": "deb"}},
    {"vulnerability": {"id": "GHSA-xxxx-yyyy-zzzz", "fix": {"state": "fixed", "versions": ["2.32.0"]}},
     "relatedVulnerabilities": [{"id": "CVE-2026-1003"}], "artifact": {"name": "requests", "version": "2.31.0", "type": "python"}},
    {"vulnerability": {"id": "CVE-2026-1004", "fix": {"state": "fixed", "versions": ["8.5.0-2ubuntu10.9"]}},
     "relatedVulnerabilities": [], "artifact": {"name": "curl", "version": "8.5.0-2ubuntu10", "type": "deb"}},
    {"vulnerability": {"id": "CVE-2026-1005", "fix": {"state": "fixed", "versions": ["3.4.0"]}},
     "relatedVulnerabilities": [], "artifact": {"name": "paramiko", "version": "2.12.0", "type": "python"}},
    {"vulnerability": {"id": "CVE-2026-1006", "fix": {"state": "fixed", "versions": ["2.9.15"]}},
     "relatedVulnerabilities": [], "artifact": {"name": "libxml2", "version": "2.9.14", "type": "deb"}},
]}
EXAMPLE_RULES = doc(
    rule("R3", "non_kernel", detail="Fixed in {fix_version} by the distribution; installed {installed_version}.",
         rec="apt upgrade {component} to {fix_version} or later in the next image.", purl_type=["deb"], fix_state=["fixed"]),
    rule("R4", "non_kernel", detail="Fixed upstream in {fix_version}; installed {installed_version}.",
         rec="Upgrade {component} to {fix_version} or later in the next release.", purl_type=["pypi"], fix_state=["fixed"]))


def cli(*args):
    env = dict(os.environ, CRA_COMPANY_CONFIG="none")
    return subprocess.run([sys.executable, "-I", str(CLI), *args], capture_output=True, text=True, timeout=60, env=env)


@pytest.fixture
def renv(tmp_path):
    proj = make_project(tmp_path / "proj")
    scan = make_scan(tmp_path / "scan", findings=RULE_FINDINGS, grype=RULE_GRYPE)
    write_json(proj / vx.RULES_REL, EXAMPLE_RULES)
    return proj, scan


def test_rules_check_dry_run_counts(renv):
    proj, scan = renv
    r = cli("rules", "check", "--project", str(proj))
    assert r.returncode == 0 and "格式正確，2 條規則" in r.stdout and "RULE" not in r.stdout
    r = cli("rules", "check", "--project", str(proj), "--scan", str(scan))
    assert r.returncode == 0, r.stdout + r.stderr
    lines = r.stdout.splitlines()
    r3 = next(x for x in lines if x.startswith("RULE\tR3"))
    r4 = next(x for x in lines if x.startswith("RULE\tR4"))
    # R3：zlib1g CVE-2026-1001；curl 在 KEV、libxml2 已有 DT 判定。R4：requests；paramiko 是 P1
    assert "套用 1 列" in r3 and "DT 1" in r3 and "KEV 1" in r3
    assert "套用 1 列" in r4 and "P1 1" in r4
    assert any(x.startswith("  例\tCVE-2026-1001\tzlib1g") and "Fixed in 1:1.3.dfsg-3.1ubuntu2.1" in x for x in lines)
    gl = next(x for x in lines if x.startswith("GATE"))
    assert "untriaged 3" in gl and "規則判定 2" in gl and "exploitable 2" in gl
    # 沒有判定的 3 列分組、列出套件
    rest = [x for x in lines if x.startswith("REST")]
    assert len(rest) == 2 and rest[0].startswith("REST\t沒有判定的 3 列")
    groups = [x for x in lines if x.startswith("  組\t")]
    assert groups and sum(int(x.split("\t")[3].split(" ")[0]) for x in groups) == 3
    assert any(x.startswith("  套件\t") for x in lines)
    assert not (proj / "CRA" / "Reports").exists()                 # 乾跑不寫專案的文件
    # 規則檔有禁止的狀態 → FAIL
    write_json(proj / vx.RULES_REL, doc(rule(state="resolved", response=())))
    r = cli("rules", "check", "--project", str(proj), "--scan", str(scan))
    assert r.returncode == 1 and r.stdout.startswith("FAIL") and "規則不能設 resolved" in r.stdout


def test_report_section_and_summary_with_rules(renv):
    proj, scan = renv
    r, s, reports = run(proj, scan)
    assert r.returncode in (0, 2), r.stdout + r.stderr
    v = s["vex"]
    assert v["rules"]["file"] == "CRA/Config/vex-rules.json" and v["rules"]["count"] == 2
    assert [(x["id"], x["applied"]) for x in v["rules"]["rules"]] == [("R3", 1), ("R4", 1)]
    assert v["sources"]["rule"] == 2 and v["gate"]["open_affected"]["by_rule"] == 2
    ra = (reports / "risk-assessment.md").read_text(encoding="utf-8")
    assert "#### Bulk triage rules" in ra and "| R3 | rule R3 | Alice | 2026-11-02 | bulk decision | exploitable (update) |" in ra
    assert "(a) Assessment completeness: 3 untriaged rows" in ra and "(b) Open affected: 2 rows are `exploitable`" in ra
    assert "Annex I Part I point (2)(a)" in ra and "exploitable (rule R3)" in ra
    cdx = json.loads((reports / "vex.cdx.json").read_text(encoding="utf-8"))
    assert sum(1 for x in cdx["vulnerabilities"] for p in x["properties"] if p["name"] == "sca-center:vex-rule") == 2
    # 規則檔不存在時文件寫明
    (proj / vx.RULES_REL).unlink()
    r, s, reports = run(proj, scan)
    assert s["vex"]["rules"] is None and "Bulk triage rules: no `CRA/Config/vex-rules.json`" in (reports / "risk-assessment.md").read_text(encoding="utf-8")


def test_rules_add_is_safe(tmp_path):
    proj = tmp_path / "p"
    proj.mkdir()
    base = ["rules", "add", "--project", str(proj), "--author", "Alice", "--reason", "why", "--date", "2026-11-02"]
    r = cli(*base, "--id", "R1", "--description", "kernel fixed", "--scope", "kernel", "--fix-state", "fixed", "--state", "exploitable",
            "--response", "update", "--detail-template", "Fixed in {fix_version}.")
    assert r.returncode == 0 and "新增規則 R1" in r.stdout, r.stdout + r.stderr
    p = proj / vx.RULES_REL
    os.chmod(p, 0o640)
    before = p.read_bytes()
    for extra, msg in ((["--state", "not_affected"], "規則不能設 not_affected"),
                       (["--state", "in_triage", "--detail-template", "{bogus}"], "不認得的欄位 {bogus}")):
        args = [*base, "--id", "R2", "--description", "d", "--scope", "all", *extra]
        if "--detail-template" not in extra:
            args += ["--detail-template", "x"]
        r = cli(*args)
        assert r.returncode == 1 and msg in r.stdout and "沒有修改" in r.stdout, (msg, r.stdout)
    r = cli(*base, "--id", "R1", "--description", "dup", "--scope", "all", "--state", "in_triage", "--detail-template", "x")
    assert r.returncode == 1 and "已有 id R1" in r.stdout
    assert p.read_bytes() == before
    r = cli(*base, "--id", "R2", "--description", "non-kernel", "--scope", "non_kernel", "--purl-type", "deb", "--severity", "low",
            "--epss-max", "0.5", "--include-no-epss", "--state", "in_triage", "--detail-template", "Review {cve}.")
    assert r.returncode == 0
    r = cli(*base, "--id", "R1", "--description", "kernel fixed v2", "--scope", "kernel", "--fix-state", "fixed", "--state", "exploitable",
            "--response", "update", "--detail-template", "Fixed in {fix_version}.", "--replace")
    assert r.returncode == 0 and "取代規則 R1" in r.stdout
    d = json.loads(p.read_text(encoding="utf-8"))
    assert [(x["id"], x["description"]) for x in d["rules"]] == [("R1", "kernel fixed v2"), ("R2", "non-kernel")]   # 取代保留位置
    assert d["rules"][1]["match"] == {"scope": "non_kernel", "purl_type": ["deb"], "severity": ["LOW"], "epss_percentile_max": 0.5,
                                      "include_no_epss": True}
    assert stat.S_IMODE(p.stat().st_mode) == 0o640 and (p.parent / ".vex-rules.json.lock").exists()
    assert not [x for x in p.parent.iterdir() if x.name.startswith(".vex-rules.") and x.name != ".vex-rules.json.lock"]
    # 已有的檔案壞掉 → 不改
    p.write_text("{broken", encoding="utf-8")
    r = cli(*base, "--id", "R3", "--description", "d", "--scope", "all", "--state", "in_triage", "--detail-template", "x")
    assert r.returncode == 1 and "不是 JSON" in r.stdout and p.read_text(encoding="utf-8") == "{broken"


V = os.environ.get("VERIFY_DIR") or os.path.join(os.environ.get("SCA_TEST_DATA", "/nonexistent-sca-test-data"), "verify")


@pytest.mark.skipif(not os.path.exists(f"{V}/cdx/schema/bom-1.6.schema.json") and os.environ.get("SCA_REQUIRE_TEST_DATA", "").strip() in ("", "0"),
                    reason="上游 schema 缺少（見 scripts/ci/fetch-test-data.sh）")
def test_rule_statements_pass_official_schemas():
    jsonschema = pytest.importorskip("jsonschema")
    from referencing import Registry, Resource
    reg = Registry()
    for n in ("spdx.schema.json", "jsf-0.82.schema.json", "cryptography-defs.schema.json"):
        d = json.load(open(f"{V}/cdx/schema/{n}"))
        reg = reg.with_resource(d.get("$id", n), Resource.from_contents(d)).with_resource(n, Resource.from_contents(d))
    allr, conf, _ = assess([row("CVE-2026-1", fix_state="fixed", fix_next="3.0.13-0ubuntu3.12"), row("CVE-2026-2", "libssl3t64")],
                           [rule("R3", detail="Fixed in {fix_version}.", rec="Upgrade to {fix_version}.", fix_state=["fixed"]),
                            rule("R9", state="in_triage", response=(), detail="No fix yet.")])
    cdx, _ = vx.cdx_vex(allr, PBOM, {"finished": "2026-11-02T00:00:00Z"}, {"name": "EX"}, "ATTENTION")
    ov = vx.openvex(cdx, "Example Co.", vx.purl_by_bomlink(PBOM))
    errs = list(jsonschema.Draft7Validator(json.load(open(f"{V}/cdx/schema/bom-1.6.schema.json")), registry=reg).iter_errors(cdx))
    assert not errs, [e.message for e in errs[:3]]
    errs = list(jsonschema.Draft202012Validator(json.load(open(f"{V}/ovx/openvex_json_schema.json")),
                                                format_checker=jsonschema.FormatChecker()).iter_errors(ov))
    assert not errs, [e.message for e in errs[:3]]


def test_example_rules_file_is_valid_and_safe():
    d = json.loads((HERE.parent / "vex-rules.example.json").read_text(encoding="utf-8"))
    rules = vx.check_rules(d)
    assert [r["id"] for r in rules] == ["K1", "K2", "U1", "R1", "R2", "R3", "R4", "R5"]
    assert all(r["set"]["state"] in vx.RULE_STATES and not r["match"].get("allow_p1") for r in rules if not r.get("evidence"))
    assert [r["evidence"] for r in rules if r.get("evidence")] == ["K1", "K2", "U1"]
    assert d["author"] == "專案負責人" and all("author" not in r for r in d["rules"])
    # 範例沒填名字 → 閘門會提醒；證據規則（not_affected）在填名字之前完全不套用
    assert [r["author_missing"] for r in vx.effective_rules(d)] == [True] * 8



# ---------- 責任人：檔案最上層的預設、規則自己的優先、佔位字 ----------

def test_author_default_override_and_placeholder(tmp_path):
    def norule_author(rid, **kw):
        r = rule(rid, **kw)
        del r["author"]
        return r
    d = dict(doc(norule_author("R1", detail="a"), dict(rule("R2", detail="b"), author="Bob"), dict(rule("R3", detail="c"), author="(Your Name)"),
                 dict(rule("R4", detail="d"), author="  ")), author="Lead")
    (tmp_path / "CRA" / "Config").mkdir(parents=True)
    (tmp_path / vx.RULES_REL).write_text(json.dumps(d), encoding="utf-8")
    rules, info = vx.load_rules(tmp_path)
    assert [(r["author"], r["author_missing"]) for r in rules] == [("Lead", False), ("Bob", False), ("(Your Name)", True), ("Lead", False)]
    assert info["author"] == "Lead" and info["without_author"] == ["R3"]
    for top in ("專案負責人", "to be completed", ""):
        (tmp_path / vx.RULES_REL).write_text(json.dumps(dict(doc(norule_author("R1", detail="a")), author=top)), encoding="utf-8")
        assert vx.load_rules(tmp_path)[1]["without_author"] == ["R1"]
    with pytest.raises(vx.VexInputError, match="沒有責任人"):
        vx.check_rules(doc(norule_author("R1", detail="a")))
    with pytest.raises(vx.VexInputError, match="author：要是文字"):
        vx.check_rules(dict(doc(rule()), author=3))
    # 閘門：其他都沒問題時，沒有責任人的規則也讓閘門 ATTENTION
    allr, conf, _ = assess([row("CVE-4", analysis=dt("RESOLVED"))], [])
    assert gate(allr, conf)["verdict"] == "OK"
    g = gate(allr, conf, rules_without_author=["R1", "R3"])
    assert g["verdict"] == "ATTENTION" and g["reasons"] == ["bulk rules without a named author: R1, R3"] and g["rules_without_author"] == ["R1", "R3"]


def test_report_with_placeholder_author(renv):
    proj, scan = renv
    d = copy.deepcopy(EXAMPLE_RULES)
    for r in d["rules"]:
        del r["author"]
    d["author"] = "專案負責人"
    d["rules"][1]["author"] = "Bob"
    write_json(proj / vx.RULES_REL, d)
    r, s, reports = run(proj, scan)
    assert s["vex"]["rules"]["without_author"] == ["R3"] and "bulk rules without a named author: R3" in s["vex"]["gate"]["reasons"]
    ra = (reports / "risk-assessment.md").read_text(encoding="utf-8")
    assert "| R3 | rule R3 | author: TO BE COMPLETED |" in ra and "| R4 | rule R4 | Bob |" in ra
    cdx = json.loads((reports / "vex.cdx.json").read_text(encoding="utf-8"))
    authors = sorted(p["value"] for x in cdx["vulnerabilities"] for p in x["properties"] if p["name"] == "sca-center:vex-rule-author")
    assert authors == ["Bob", "專案負責人"]                         # 佔位字照原樣寫，不替人編名字
    out = cli("rules", "check", "--project", str(proj))
    assert out.returncode == 0 and "WARN\t沒有責任人（空的或佔位字）：R3" in out.stdout


def test_rules_add_author_optional_with_file_default(tmp_path):
    args = ["--description", "d", "--reason", "why", "--scope", "all", "--state", "in_triage", "--detail-template", "x"]
    r = cli("rules", "add", "--project", str(tmp_path), "--id", "R1", *args)
    assert r.returncode == 1 and "新的規則要加 --author" in r.stdout and not (tmp_path / vx.RULES_REL).exists()
    write_json(tmp_path / vx.RULES_REL, {"schema": vx.RULES_SCHEMA, "author": "Lead", "rules": []})
    r = cli("rules", "add", "--project", str(tmp_path), "--id", "R1", *args)
    assert r.returncode == 0, r.stdout
    r = cli("rules", "add", "--project", str(tmp_path), "--id", "R2", "--author", "Bob", *args)
    d = json.loads((tmp_path / vx.RULES_REL).read_text(encoding="utf-8"))
    assert r.returncode == 0 and d["author"] == "Lead" and "author" not in d["rules"][0] and d["rules"][1]["author"] == "Bob"
