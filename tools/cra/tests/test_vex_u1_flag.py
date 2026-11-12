"""證據規則 U1（Ubuntu CVE Tracker 的 not-affected，scan/ubuntu-status.json）與可能誤報的標記 distro_no_range_upstream_excludes：
U1 的版本註記、conflict、文字註記；嚴重度／EPSS 不是輸入、KEV／被利用的列不套用、人的判定不被蓋過（同 K1／K2）；標記只標不改狀態；
cra_report 的整合；照抄範例規則檔（含 U1）不改任何輸出。全部是合成資料。"""
import copy
import itertools
import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import vex_export as vx  # noqa: E402
from test_cra_report import FINDINGS, finding, make_project, make_scan, run, write_json  # noqa: E402
from test_cra_distro import OSSL  # noqa: E402
from test_vex_evidence import (IMG, OTHER_IMG, assess, by_id, ctx, erule, ev_env, example_noop, rules_of,  # noqa: E402
                               summary_of)
from test_vex_export import DEB, dt, row  # noqa: E402
from test_vex_rules import krow  # noqa: E402

OSSL_PURL = DEB.format("openssl", OSSL)


def ustat(entries, comps=None, status="OK"):
    return {"schema": vx.USTATUS_SCHEMA, "status": status, "detail": "x",
            "mirror": {"commit": "a" * 40, "commit_date": "2026-11-04T00:00:00Z"},
            "components": comps if comps is not None else {OSSL_PURL: {"source": "openssl", "source_version": OSSL, "release": "noble"}},
            "entries": entries, "mirror_counts": {}}


UST = ustat({"CVE-U1": {"openssl": {"noble": {"status": "not-affected", "note": OSSL}}},              # 和安裝的版本完全相同
             "CVE-U2": {"openssl": {"noble": {"status": "not-affected", "note": "3.0.13-0ubuntu3.4"}}},
             "CVE-U3": {"openssl": {"noble": {"status": "not-affected", "note": "3.0.13-0ubuntu3.20"}}},
             "CVE-U4": {"openssl": {"noble": {"status": "not-affected", "note": "3.0.13-0ubuntu3.4", "conflict": [{"status": "needed", "note": ""}]}}},
             "CVE-U5": {"openssl": {"noble": {"status": "not-affected", "note": "code not compiled"}}},
             "CVE-U6": {"openssl": {"noble": {"status": "needed", "note": ""}}},
             "CVE-U7": {"openssl": {"jammy": {"status": "not-affected", "note": ""}}},
             "CVE-U9": {"openssl": {"noble": {"status": "not-affected", "note": ""}}}})                  # 沒有版本註記


def test_u1_rule_validation():
    assert [r["evidence"] for r in rules_of(erule("U1", "U1"), erule("U1b", "U1", images=[IMG]))] == ["U1", "U1"]
    assert "U1" in vx.EVIDENCE_FUNCS and vx.EVIDENCE_KINDS == ("K1", "K2", "U1", "U2")


def test_u1_sees_only_artifact_fields_and_never_uses_severity_or_epss(monkeypatch):
    seen = []
    f = vx.EVIDENCE_FUNCS["U1"]
    monkeypatch.setitem(vx.EVIDENCE_FUNCS, "U1", lambda v, ec: (seen.append(set(v)), f(v, ec))[1])
    rules = rules_of(erule("U1", "U1"))
    base = [row("CVE-U1"), row("CVE-U2"), row("CVE-U3"), row("CVE-U6")]
    want = None
    for sev, epss, tier in itertools.product(("CRITICAL", "LOW"), (None, 0.0, 0.99), ("p1", "p2", "p3")):
        rows = [dict(r, severity=sev, epss_pct=epss, epss=epss, tier=tier) for r in base]
        got = [(r["id"], (r["vex"] or {}).get("state")) for r in assess(rows, rules, ubuntu_status=UST)[0]]
        want = want or got
        assert got == want, (sev, epss, tier)
    assert want == [("CVE-U1", "not_affected"), ("CVE-U2", "not_affected"), ("CVE-U3", None), ("CVE-U6", None)]
    assert seen and all(s == set(vx.EVIDENCE_VIEW_KEYS) for s in seen)


def test_u1_kev_exploited_and_human_decisions():
    rules = rules_of(erule("U1", "U1"))
    allr, _, info = assess([row("CVE-U1", kev=True), row("CVE-U2", exploited_sources=["EUVD"])], rules, ubuntu_status=UST)
    assert all(r["vex"] is None for r in allr) and summary_of(info, "U1")["excluded_kev"] == 2
    allr, _, info = assess([row("CVE-U1")], rules, ubuntu_status=UST, exploited=["CVE-U1"])
    assert allr[0]["vex"] is None and summary_of(info, "U1")["excluded_kev"] == 1
    anns = [{"cve": "CVE-U1", "purl": "pkg:deb/ubuntu/openssl", "version": OSSL, "state": "exploitable", "response": ["will_not_fix"],
             "detail": "used by the product", "author": "Carol", "date": "2026-11-03"}]
    allr, conf, info = vx.assess([row("CVE-U1"), row("CVE-U2", analysis=dt("", suppressed=True))], annotations=anns, rules=rules,
                                 rule_ctx=ctx(ubuntu_status=UST))
    assert allr[0]["vex"]["source"] == "annotation" and allr[1]["vex"] is None
    assert summary_of(info, "U1")["shadowed"] == {"annotation": 1, "dt_suppressed": 1}
    assert allr[0]["rule_shadowed"][0] == {"rule": "U1", "evidence": "U1", "would_set": "not_affected", "decided_by": "annotation",
                                           "state": "exploitable"}
    assert ("CVE-U1", "annotation:exploitable", "rule:not_affected") in {(c["id"], c["used"], c["other"]) for c in conf}
    # 規則不生效（映像不符）→ 不套用
    allr, _, info = assess([row("CVE-U1")], rules_of(erule("U1", "U1", images=[OTHER_IMG])), ubuntu_status=UST)
    assert allr[0]["vex"] is None and summary_of(info, "U1")["inactive_rows"] == 1


def test_u1_status_and_version_notes():
    rules = rules_of(erule("U1", "U1"))
    ids = ["CVE-U1", "CVE-U2", "CVE-U3", "CVE-U4", "CVE-U5", "CVE-U6", "CVE-U7", "CVE-U8", "CVE-U9"]
    allr, _, info = assess([row(i) for i in ids], rules, ubuntu_status=UST)
    r = by_id(allr)
    assert r["CVE-U1"]["vex"]["state"] == "not_affected" and f"not-affected ({OSSL}), installed {OSSL}" in r["CVE-U1"]["vex"]["detail"]
    assert "not-affected (3.0.13-0ubuntu3.4), installed " + OSSL in r["CVE-U2"]["vex"]["detail"]
    assert r["CVE-U2"]["vex"]["justification"] == "code_not_present" and "commit aaaaaaaaaaaa" in r["CVE-U2"]["vex"]["detail"]
    # 舊的 revision（註記 3.0.13-0ubuntu3.20、安裝 3.0.13-0ubuntu3.11）：不套用，獨立的標記（之後整批人工判斷）
    m3 = r["CVE-U3"]["vex_markers"][0]
    assert r["CVE-U3"]["vex"] is None and m3["code"] == "U1-older-revision"
    assert f"U1 not applied: older revision than the tracker note (evaluated at 3.0.13-0ubuntu3.20, installed {OSSL})" in m3["detail"]
    assert vx.label(r["CVE-U3"]) == "untriaged [U1 not applied: older revision]"
    for i in ("CVE-U3", "CVE-U4", "CVE-U5", "CVE-U6", "CVE-U7", "CVE-U8", "CVE-U9"):
        assert r[i]["vex"] is None, i
    for i, txt in (("CVE-U9", "U1 not applied: not-affected without a version note"),
                   ("CVE-U4", "U1 not applied (conflicting tracker lines: not-affected (3.0.13-0ubuntu3.4) and needed)"), ("CVE-U5", "note that is not a version")):
        assert r[i]["vex_markers"][0]["code"] == "U1-not-applied" and txt in r[i]["vex_markers"][0]["detail"], i
    assert not r["CVE-U6"].get("vex_markers") and not r["CVE-U7"].get("vex_markers")
    s = summary_of(info, "U1")
    assert s["applied"] == 2 and s["not_applied"] == {"conflict": 1, "no_entry": 2, "no_version_note": 1, "note_not_version": 1,
                                                       "older_revision": 1, "other_status": 1}
    assert s["markers"] == {"U1-not-applied": 3, "U1-older-revision": 1}
    assert {x["reason"] for x in s["not_applied_sample"]} == set(s["not_applied"])
    # 狀態改了（鏡像更新後不再是 not-affected）→ 自動不套用
    ch = copy.deepcopy(UST)
    ch["entries"]["CVE-U1"]["openssl"]["noble"]["status"] = "needs-triage"
    assert assess([row("CVE-U1")], rules, ubuntu_status=ch)[0][0]["vex"] is None
    # 一列多個 CVE：每個都要 not-affected
    assert assess([row("CVE-U1", cves=["CVE-U1", "CVE-U6"])], rules, ubuntu_status=UST)[0][0]["vex"] is None
    # 核心的列、沒有 CVE 的列、不知道原始碼套件的列、沒有檔案、status 不是 OK
    assert assess([krow("CVE-U1")], rules, ubuntu_status=UST)[0][0]["vex"] is None
    other = row("CVE-U1", "libfoo", "1.0")
    a, _, info = assess([other], rules, ubuntu_status=UST)
    assert a[0]["vex"] is None and summary_of(info, "U1")["not_applied"] == {"source_unknown": 1}
    for u in (None, dict(UST, status="NOT_RUN")):
        a, _, info = assess([row("CVE-U1")], rules, ubuntu_status=u)
        assert a[0]["vex"] is None and summary_of(info, "U1")["not_applied"] == {"no_data": 1}


# ---------- 可能誤報（distro_no_range_upstream_excludes） ----------

def distro_match(cve, name, ver, constraint="none (unknown)", ns="ubuntu:distro:ubuntu:24.04"):
    return {"vulnerability": {"id": cve, "namespace": ns, "fix": {"state": "not-fixed", "versions": []}},
            "relatedVulnerabilities": [{"id": cve, "namespace": "nvd:cpe"}],
            "matchDetails": [{"type": "exact-direct-match", "matcher": "dpkg-matcher",
                              "searchedBy": {"distro": {"type": "ubuntu", "version": "24.04"}, "namespace": ns,
                                             "package": {"name": name, "version": ver}},
                              "found": {"vulnerabilityID": cve, "versionConstraint": constraint}}],
            "artifact": {"name": name, "version": ver, "type": "deb", "upstreams": []}}


def cpe_match(cve, product, constraint, art="iperf3-static"):
    return {"vulnerability": {"id": cve, "namespace": "nvd:cpe"},
            "matchDetails": [{"type": "cpe-match", "matcher": "stock-matcher", "searchedBy": {"namespace": "nvd:cpe"},
                              "found": {"vulnerabilityID": cve, "versionConstraint": constraint,
                                        "cpes": [f"cpe:2.3:a:es:{product}:*:*:*:*:*:*:*:*"]}}],
            "artifact": {"name": art, "version": "3.13", "type": "binary"}}


def test_upstream_version_and_constraint_helpers():
    assert vx.upstream_numeric("3.16-1build2") == (3, 16) and vx.upstream_numeric("1:2.4.1+dfsg-3") == (2, 4, 1)
    assert vx.upstream_numeric("1.0~rc1-1") is None and vx.upstream_numeric("2.0a-1") is None
    assert vx.constraint_contains("< 3.14 (unknown)", (3, 16)) is False and vx.constraint_contains("< 3.14 (unknown)", (3, 13, 9)) is True
    assert vx.constraint_contains(">= 2.0, < 2.4.1 || >= 3.0, < 3.1 (unknown)", (3, 0, 5)) is True
    assert vx.constraint_contains(">= 2.0, < 2.4.1 || >= 3.0, < 3.1 (unknown)", (2, 5)) is False
    assert vx.constraint_contains("= 3.14", (3, 14, 0)) is True
    assert vx.constraint_contains("none (unknown)", (1,)) is None and vx.constraint_contains("< 3.14rc1", (3, 16)) is None


def test_distro_no_range_upstream_excludes_flag():
    ip = row("CVE-2023-38403", "iperf3", "3.16-1build2", source_ids=["OSV:UBUNTU-CVE-2023-38403"])
    grype = {"matches": [distro_match("CVE-2023-38403", "iperf3", "3.16-1build2"), cpe_match("CVE-2023-38403", "iperf3", "< 3.14 (unknown)")]}
    us = ustat({"CVE-2023-38403": {"iperf3": {"noble": {"status": "needed", "note": ""}}}},
               comps={ip["purl"]: {"source": "iperf3", "source_version": "3.16-1build2", "release": "noble"}})
    allr, _, _ = vx.assess([copy.deepcopy(ip)])
    out = vx.upstream_exclusion_flags(allr, grype, us)
    assert out["flagged"] == 1 and out["candidates"] == 1 and allr[0]["vex"] is None        # 只標記，不改狀態
    ev = out["rows"][0]
    assert ev["upstream_version"] == "3.16" and ev["upstream_ranges"][0]["constraint"] == "< 3.14 (unknown)"
    assert ev["ubuntu_status"] == "needed in noble (Ubuntu CVE Tracker mirror)" and "changelog.Debian.gz" in ev["ubuntu_changelog"]
    assert allr[0]["vex_markers"][0]["code"] == "distro_no_range_upstream_excludes" and "[possible false positive]" in vx.label(allr[0])
    # 不標的情況（原因計數）
    cases = [
        ({"matches": [distro_match("CVE-2023-38403", "iperf3", "3.16-1build2")]}, ip, "no_range_data"),
        ({"matches": [distro_match("CVE-2023-38403", "iperf3", "3.16-1build2"), cpe_match("CVE-2023-38403", "iperf3", "< 3.17 (unknown)")]}, ip,
         "range_includes_version"),
        ({"matches": [distro_match("CVE-2023-38403", "iperf3", "3.16-1build2"), cpe_match("CVE-2023-38403", "iperf3", "< 3.14 (unknown)"),
                      cpe_match("CVE-2023-38403", "iperf3", ">= 3.15, < 3.17 (unknown)")]}, ip, "range_includes_version"),
        ({"matches": [distro_match("CVE-2023-38403", "iperf3", "3.16-1build2"), cpe_match("CVE-2023-38403", "other", "< 3.14 (unknown)")]}, ip,
         "no_range_data"),
        ({"matches": [distro_match("CVE-2023-38403", "iperf3", "3.16~rc1-1"), cpe_match("CVE-2023-38403", "iperf3", "< 3.14 (unknown)")]},
         dict(ip, version="3.16~rc1-1"), "version_not_comparable"),
        ({"matches": [distro_match("CVE-2023-38403", "iperf3", "3.16-1build2"), cpe_match("CVE-2023-38403", "iperf3", "< 3.14-beta")]}, ip,
         "range_not_comparable"),
        ({"matches": [distro_match("CVE-2023-38403", "iperf3", "3.16-1build2", "< 3.16-2 (deb)"),
                      cpe_match("CVE-2023-38403", "iperf3", "< 3.14 (unknown)")]}, ip, None),
        ({"matches": [distro_match("CVE-2023-38403", "iperf3", "3.16-1build2", ns="nvd:cpe"),
                      cpe_match("CVE-2023-38403", "iperf3", "< 3.14 (unknown)")]}, ip, None),
        (grype, dict(ip, source_ids=["OSV:UBUNTU-CVE-2023-38403", "NVD:CVE-2023-38403"]), "dt_nvd_match"),
        (grype, dict(ip, analysis=dt("NOT_AFFECTED", "code_not_present", details="checked")), "decided_by_person"),
        (grype, dict(ip, version="3.16-1build3", key=["x", "iperf3", "3.16-1build3"]), "not_in_table"),
    ]
    for g, r, why in cases:
        allr, _, _ = vx.assess([copy.deepcopy(r)])
        out = vx.upstream_exclusion_flags(allr, g, None)
        assert out["flagged"] == 0 and out["not_flagged"] == ({why: 1} if why else {}), (why, out)
        assert not allr[0].get("vex_markers")
    assert vx.upstream_exclusion_flags([], None)["basis"] is None


# ---------- cra_report 的整合 ----------

def u1_env(tmp_path, rules):
    proj, sc = ev_env(tmp_path, rules)
    write_json(sc / "scan" / "ubuntu-status.json", ustat({"CVE-2025-0003": {"openssl": {"noble": {"status": "not-affected",
                                                                                                    "note": "3.0.13-0ubuntu3.4"}}}}))
    return proj, sc


def test_report_integration_with_u1(tmp_path):
    proj, sc = u1_env(tmp_path, [erule("K1", "K1", images=[IMG]), erule("K2", "K2"), erule("U1", "U1")])
    r, s, rep = run(proj, sc)
    assert r.returncode in (0, 2), r.stdout + r.stderr
    v = s["vex"]
    rs = {x["id"]: x for x in v["rules"]["rules"]}
    assert rs["U1"]["applied"] == 1 and rs["K1"]["applied"] == 1 and rs["K2"]["applied"] == 1
    assert s["counts"]["accepted_by_vex"] == {"rule": 3} and s["inputs"]["scan/ubuntu-status.json"]["sha256"]
    assert v["evidence_inputs"]["ubuntu_status"] == "OK" and v["evidence_inputs"]["ubuntu_tracker_commit"] == "a" * 40
    cdx = json.loads((rep / "vex.cdx.json").read_text(encoding="utf-8"))
    u = next(x for x in cdx["vulnerabilities"] if x["id"] == "CVE-2025-0003")
    props = {p["name"]: p["value"] for p in u["properties"]}
    assert props["sca-center:vex-rule-evidence"] == "U1" and props["sca-center:vex-rule-inputs"] == "Ubuntu CVE Tracker commit aaaaaaaaaaaa"
    md = (rep / "risk-assessment.md").read_text(encoding="utf-8")
    assert "Ubuntu status OK (tracker commit aaaaaaaaaaaa)" in md
    # Ubuntu 的狀態改了 → U1 自動不套用
    write_json(sc / "scan" / "ubuntu-status.json", ustat({"CVE-2025-0003": {"openssl": {"noble": {"status": "needed", "note": ""}}}}))
    rs2 = {x["id"]: x for x in run(proj, sc)[1]["vex"]["rules"]["rules"]}
    assert rs2["U1"]["applied"] == 0 and rs2["U1"]["not_applied"] == {"other_status": 1, "source_unknown": 1}


def test_example_rules_file_with_u1_changes_no_output(tmp_path):
    def extra(proj, sc):
        write_json(sc / "scan" / "ubuntu-status.json", ustat({"CVE-2025-0003": {"openssl": {"noble": {"status": "not-affected", "note": ""}}}}))
    s = example_noop(tmp_path, extra)
    assert [x["id"] for x in s["vex"]["rules"]["rules"] if x.get("evidence")] == ["K1", "K2", "U1"]


def test_report_marks_possible_false_positive(tmp_path):
    f = finding("iperf3", "3.16-1build2", "UBUNTU-CVE-2023-38403", "OSV", "MEDIUM")
    grype = {"matches": [distro_match("CVE-2023-38403", "iperf3", "3.16-1build2"), cpe_match("CVE-2023-38403", "iperf3", "< 3.14 (unknown)")]}
    r, s, rep = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s", findings=FINDINGS + [f], grype=grype))
    assert r.returncode in (0, 2), r.stdout + r.stderr
    fl = s["vex"]["upstream_excludes"]
    assert fl["flagged"] == 1 and fl["rows"][0]["id"] == "CVE-2023-38403" and fl["rows"][0]["upstream_version"] == "3.16"
    assert "not available offline: check https://ubuntu.com/security/CVE-2023-38403" == fl["rows"][0]["ubuntu_status"]
    md = (rep / "risk-assessment.md").read_text(encoding="utf-8")
    assert "Possible false positives (`distro_no_range_upstream_excludes`): 1 rows." in md
    assert "| 1 | CVE-2023-38403 | iperf3 | 3.16-1build2 (3.16) | < 3.14 (unknown) for cpe:2.3:a:es:iperf3:" in md
    assert any("CVE-2023-38403" in x and "untriaged [possible false positive]" in x for x in md.splitlines())
    assert s["vex"]["sources"]["rule"] == 0 and s["vex"]["gate"]["counts"]["total"]["not_affected"] == 1   # 只標記（1 是 FINDINGS 裡 DT 的判定）


# ---------- 被 U1 排除的清單（vex.u1_excluded）：每一筆都有理由與證據 ----------

def ustat_full(entries):
    """ubuntu_status.py 的完整輸出欄位（mirror 的 source／fetched_utc、cve_info）。"""
    u = ustat(entries)
    u["mirror"].update(source="https://git.launchpad.net/ubuntu-cve-tracker", fetched_utc="2026-11-04T01:00:00Z")
    u["cve_info"] = {c: {"priority": None if c == "CVE-U1" else "medium", "tracker_file": f"active/{c}"} for c in entries}
    return u


def test_u1_excluded_list_has_reason_and_evidence():
    rules = rules_of(erule("U1", "U1"))
    allr, _, info = assess([row(i) for i in ("CVE-U1", "CVE-U2", "CVE-U3", "CVE-U4", "CVE-U6")], rules, ubuntu_status=ustat_full(UST["entries"]))
    ex = info["u1_excluded"]
    assert [x["id"] for x in ex] == ["CVE-U1", "CVE-U2"]           # 只有最後判定是 U1 的 not_affected（U3 是舊 revision）
    tr = {"source": "https://git.launchpad.net/ubuntu-cve-tracker", "commit": "a" * 40, "commit_date": "2026-11-04T00:00:00Z",
          "fetched_utc": "2026-11-04T01:00:00Z"}
    assert ex[1] == {
        "id": "CVE-U2", "component": ex[1]["component"], "version": OSSL, "tier": ex[1]["tier"], "state": "not_affected",
        "justification": "code_not_present", "rule": "U1", "rule_author": ex[1]["rule_author"], "rule_date": ex[1]["rule_date"],
        "rule_reason": ex[1]["rule_reason"],
        "reason": f"Ubuntu CVE Tracker marks source package openssl not-affected in noble for CVE-U2 (installed source version {OSSL} "
                  "has the same epoch and upstream version as the tracker note 3.0.13-0ubuntu3.4 (only the Debian revision may differ) "
                  "and is not older)",
        "source_package": "openssl", "source_version": OSSL, "release": "noble", "purl": OSSL_PURL, "tracker": tr,
        "cves": [{"cve": "CVE-U2", "ubuntu_status": "not-affected", "ubuntu_note": "3.0.13-0ubuntu3.4",
                  "version_check": f"installed source version {OSSL} has the same epoch and upstream version as the tracker note "
                                   "3.0.13-0ubuntu3.4 (only the Debian revision may differ) and is not older",
                  "ubuntu_priority": "medium", "ubuntu_priority_from": "cve", "tracker_file": "active/CVE-U2",
                  "url": "https://ubuntu.com/security/CVE-U2"}]}
    assert ex[1]["rule_author"] and ex[1]["rule_date"] and ex[1]["rule_reason"]
    c1 = ex[0]["cves"][0]
    assert c1["ubuntu_note"] == OSSL and c1["ubuntu_priority"] is None and c1["ubuntu_priority_from"] is None
    # 每一筆都附 Ubuntu 的 not-affected 證據
    assert all(c["ubuntu_status"] == "not-affected" and c["tracker_file"] and x["tracker"]["commit"] for x in ex for c in x["cves"])
    # 被人蓋過、KEV／被利用的列不在清單裡
    anns = [{"cve": "CVE-U1", "purl": "pkg:deb/ubuntu/openssl", "version": OSSL, "state": "exploitable", "response": ["will_not_fix"],
             "detail": "used by the product", "author": "Carol", "date": "2026-11-03"}]
    _, _, info = vx.assess([row("CVE-U1"), row("CVE-U2", kev=True)], annotations=anns, rules=rules,
                           rule_ctx=ctx(ubuntu_status=ustat_full(UST["entries"])))
    assert info["u1_excluded"] == []


@pytest.mark.parametrize("status,note", [
    ("ignored", "end of standard support"), ("ignored", "wont-fix"), ("deferred", "2024-06-17"), ("needed", ""), ("needs-triage", ""),
    ("pending", "3.0.13-0ubuntu3.12"), ("in-progress", ""), ("released", "3.0.13-0ubuntu3.4"), ("DNE", ""), ("Not-Affected", ""),
    ("not-affected-ish", ""), ("", "")])
def test_u1_excludes_only_not_affected(status, note):
    """ignored（含 wont-fix 這類「上游不修」）、deferred、released 等都不是 not-affected：漏洞還在或要走別的路徑，U1 不排除。"""
    e = {"CVE-X": {"openssl": {"noble": {"status": status, "note": note}}}}
    allr, _, info = assess([row("CVE-X")], rules_of(erule("U1", "U1")), ubuntu_status=ustat_full(e))
    assert allr[0]["vex"] is None and info["u1_excluded"] == [] and summary_of(info, "U1")["not_applied"] == {"other_status": 1}


def test_end_to_end_real_mirror_to_report(tmp_path):
    """假的 tracker 倉庫 → 真的 tools/mirror/ubuntu-cve-status.sh → tools/pilot/lib/ubuntu_status.py（CLI）→ cra_report：
    U1 只排除 not-affected 而且版本符合的列，排除清單的出處是鏡像的 commit 與 tracker 裡的檔案；conflict 的列標 U1 not applied。"""
    import importlib.util
    import subprocess
    root = HERE.parents[2]
    spec = importlib.util.spec_from_file_location("pilot_test_ubuntu_status", root / "tools/pilot/tests/test_ubuntu_status.py")
    pt = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pt)
    files = {"active/CVE-2025-0003": ("Candidate: CVE-2025-0003\nPriority: low\n\nPatches_openssl:\n"
                                      "jammy_openssl: needed\nnoble_openssl: not-affected (3.0.13-0ubuntu3.4)\n"),
             "retired/CVE-2024-1000": ("Candidate: CVE-2024-1000\nPriority:\n\nPatches_openssl:\n"
                                       "noble_openssl: not-affected (3.0.13-0ubuntu3.4)\nnoble_openssl: needed\n")}
    m = pt.make_mirror(tmp_path / "mirror", files=files)
    proj, sc = u1_env(tmp_path, [erule("U1", "U1")])
    fs = json.loads((sc / "dt" / "findings.json").read_text(encoding="utf-8"))
    o = next(f for f in fs if f["vulnerability"].get("vulnId") == "CVE-2025-0003" and f["component"]["version"] == OSSL)
    c = copy.deepcopy(o)
    c["vulnerability"]["vulnId"] = "CVE-2024-1000"
    write_json(sc / "dt" / "findings.json", fs + [c])
    r = subprocess.run([sys.executable, "-I", str(root / "tools/pilot/lib/ubuntu_status.py"), "--findings", str(sc / "dt" / "findings.json"),
                        "--sbom", str(sc / "sbom" / "sbom.cdx.json"), "--mirror", str(m), "--out", str(sc / "scan" / "ubuntu-status.json")],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0 and r.stdout.startswith("D-ubuntu-status\tOK\t"), r.stdout + r.stderr
    r, s, rep = run(proj, sc)
    assert r.returncode in (0, 2), r.stdout + r.stderr
    ex = s["vex"]["u1_excluded"]
    assert [(x["id"], x["version"]) for x in ex] == [("CVE-2025-0003", OSSL)]
    src = pt.source(m)
    assert ex[0]["tracker"]["commit"] == src["commit"] and ex[0]["tracker"]["source"] == src["source"].strip()
    assert ex[0]["cves"][0]["tracker_file"] == "active/CVE-2025-0003" and ex[0]["cves"][0]["ubuntu_priority"] == "low"
    rows = {x["id"]: x for x in s["vex"]["rules"]["rules"]}
    assert rows["U1"]["applied"] == 1 and rows["U1"]["not_applied"].get("conflict") == 1
    md = (rep / "risk-assessment.md").read_text(encoding="utf-8")
    assert "Rows set to `not_affected` by evidence rule U1: 1." in md
    assert f"| active/CVE-2025-0003 @ {src['commit'][:12]} (" in md
    assert any("CVE-2024-1000" in ln and "U1 not applied" in ln for ln in md.splitlines())


def test_u1_needs_a_debian_installed_version():
    """安裝的原始碼版本不是版本（比不出來）→ 不排除，標記請人判定（驗證代理的重現）。"""
    rules = rules_of(erule("U1", "U1"))
    for sv in ("unknown", "z", "a:1.0", "${source:Version}", "3.0.13-1\n", ""):
        u = ustat_full({"CVE-U2": {"openssl": {"noble": {"status": "not-affected", "note": "3.0.13-1"}}}})
        u["components"][OSSL_PURL]["source_version"] = sv
        allr, _, info = assess([row("CVE-U2")], rules, ubuntu_status=u)
        assert allr[0]["vex"] is None and info["u1_excluded"] == [], sv
        if sv:
            assert allr[0]["vex_markers"][0]["code"] == "U1-not-applied" and "not a Debian version" in allr[0]["vex_markers"][0]["detail"]


def test_malformed_ubuntu_status_is_no_data_not_a_crash():
    rules = rules_of(erule("U1", "U1"))
    for e, c in (({"CVE-U1": {"openssl": "x"}}, None), ({"CVE-U1": {"openssl": {"noble": {"status": 3}}}}, None),
                 ({}, {OSSL_PURL: "x"}), ({}, {OSSL_PURL: {"source": 1, "source_version": OSSL, "release": "noble"}})):
        u = ustat(e, c)
        allr, _, info = assess([row("CVE-U1")], rules, ubuntu_status=u)
        assert allr[0]["vex"] is None and summary_of(info, "U1")["not_applied"] == {"no_data": 1}
        assert "malformed" in info["evidence_inputs"]["ubuntu_status"]
        assert vx.upstream_exclusion_flags(allr, {"matches": []}, vx.ubuntu_status_of(u)[0])["flagged"] == 0


def test_report_marker_counts_include_possible_false_positives(tmp_path):
    f = finding("iperf3", "3.16-1build2", "UBUNTU-CVE-2023-38403", "OSV", "MEDIUM")
    grype = {"matches": [distro_match("CVE-2023-38403", "iperf3", "3.16-1build2"), cpe_match("CVE-2023-38403", "iperf3", "< 3.14 (unknown)")]}
    r, s, rep = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s", findings=FINDINGS + [f], grype=grype))
    assert s["vex"]["markers"].get("distro_no_range_upstream_excludes") == 1 == s["vex"]["gate"]["untriaged_markers"]["distro_no_range_upstream_excludes"]


# ---------- 審查 H1：not-affected (版本) 是「這個版本不受影響」，不是下限 ----------

XZ_PURL = DEB.format("xz-utils", "{}")


def test_u1_needs_the_same_upstream_version_xz_backdoor():
    """CVE-2024-3094（xz 後門）：noble not-affected (5.4.5-0.3)、jammy not-affected (5.2.5-2ubuntu1)。有後門的 5.6.x 比註記新，不能排除。"""
    rules = rules_of(erule("U1", "U1"))
    ent = {"CVE-2024-3094": {"xz-utils": {"noble": {"status": "not-affected", "note": "5.4.5-0.3"},
                                          "jammy": {"status": "not-affected", "note": "5.2.5-2ubuntu1"}}}}
    cases = [("5.6.1-1", "noble", None), ("5.6.1+really5.4.5-1", "noble", None), ("5.6.0-0.2", "jammy", None),
             ("5.4.5-0.3", "noble", "not_affected"), ("5.4.5-0.3ubuntu0.1", "noble", "not_affected"),
             ("5.2.5-2ubuntu1", "jammy", "not_affected"), ("1:5.4.5-0.3", "noble", None), ("5.4.5-0.2", "noble", None)]
    for ver, rel, want in cases:
        purl = XZ_PURL.format(ver).replace("ubuntu-24.04", "ubuntu-24.04" if rel == "noble" else "ubuntu-22.04")
        u = ustat_full(ent)
        u["components"] = {purl: {"source": "xz-utils", "source_version": ver, "release": rel}}
        r = row("CVE-2024-3094", "xz-utils", ver)
        r["purl"] = purl
        allr, _, info = assess([r], rules, ubuntu_status=u)
        assert (allr[0]["vex"] or {}).get("state") == want, (ver, rel, allr[0]["vex"])
        if want is None:
            m = allr[0]["vex_markers"][0]
            assert m["code"] == ("U1-older-revision" if ver == "5.4.5-0.2" else "U1-not-applied") and info["u1_excluded"] == [], ver
            if ver.startswith(("5.6", "1:")):
                assert "installed upstream version differs from the tracker note" in m["detail"], ver


def test_deb_version_parts_follows_dpkg():
    vp = vx.deb_version_parts
    assert vp("5.4.5-0.3ubuntu0.1") == (0, "5.4.5", "0.3ubuntu0.1") and vp("1:1.3.dfsg-3.1ubuntu2.1") == (1, "1.3.dfsg", "3.1ubuntu2.1")
    assert vp("5.6.1+really5.4.5-1") == (0, "5.6.1+really5.4.5", "1") and vp("2.0") == (0, "2.0", "")
    assert vp("1.2-3-4") == (0, "1.2-3", "4") and vp("3.0.13~rc1-1") == (0, "3.0.13~rc1", "1")
    assert vp("2147483647:1.0-1") == (2147483647, "1.0", "1")
    for bad in ("1.0-", "-1", "a1.0", "1:", ":1.0", "1.0 ", "1.0\n", "", "1.0-a_b", "${source:Version}", "1:2:3-1",
                "2147483648:1.0-1", "99999999999999999999:1"):
        assert vp(bad) is None, bad


def test_u1_priority_prefers_the_package_priority():
    rules = rules_of(erule("U1", "U1"))
    u = ustat_full({"CVE-U2": {"openssl": {"noble": {"status": "not-affected", "note": "3.0.13-0ubuntu3.4", "priority": "low"}}}})
    ex = assess([row("CVE-U2")], rules, ubuntu_status=u)[2]["u1_excluded"]
    assert ex[0]["cves"][0]["ubuntu_priority"] == "low" and ex[0]["cves"][0]["ubuntu_priority_from"] == "package"


def test_u1_older_revision_is_not_applied_with_its_own_marker():
    """revision 比註記舊：預設不套用，獨立的標記 U1-older-revision（之後整批人工判斷）；鏡像裡其他版本的狀態不影響判定。"""
    rules = rules_of(erule("U1", "U1"))
    for oth in (None, {"jammy": {"status": "needed", "note": ""}}, {"jammy": {"status": "released", "note": "3.0.13-0ubuntu3.15"}},
                {"jammy": {"status": "deferred", "note": ""}}):
        u = ustat_full({"CVE-R": {"openssl": {"noble": {"status": "not-affected", "note": "3.0.13-0ubuntu3.20"}}}})
        if oth:
            u["other_releases"] = {"CVE-R": {"openssl": oth}}
        allr, _, info = assess([row("CVE-R")], rules, ubuntu_status=u)
        assert allr[0]["vex"] is None and allr[0]["vex_markers"][0]["code"] == "U1-older-revision", oth
        assert summary_of(info, "U1")["not_applied"] == {"older_revision": 1} and info["u1_excluded"] == []
    # 1.2-3 對安裝的 1.2-2（修補可能是 Debian 在 1.2-3 打的）
    u = ustat_full({"CVE-R": {"openssl": {"noble": {"status": "not-affected", "note": "1.2-3"}}}})
    u["components"][OSSL_PURL]["source_version"] = "1.2-2"
    assert assess([row("CVE-R")], rules, ubuntu_status=u)[0][0]["vex_markers"][0]["code"] == "U1-older-revision"
    # 註記相同或比註記新：照常套用
    for note in (OSSL, "3.0.13-0ubuntu3.4"):
        u = ustat_full({"CVE-R": {"openssl": {"noble": {"status": "not-affected", "note": note}}}})
        assert assess([row("CVE-R")], rules, ubuntu_status=u)[0][0]["vex"]["state"] == "not_affected", note
