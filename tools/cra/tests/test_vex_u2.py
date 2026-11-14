"""證據規則 U2（Ubuntu 打包的 Python 模組：Ubuntu CVE Tracker 對擁有者的原始碼套件是 released，而且安裝的原始碼版本不比註記舊 → resolved）：
套用條件、不套用的原因、KEV／人的判定不被蓋過、只交出擁有者身分、沒設定 U2 時輸出不變、同一份資料下批次規則 R8（沒有修補資訊）接手 Ubuntu 沒有資料的列。
全部是合成資料。"""
import copy
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import vex_export as vx  # noqa: E402
from test_vex_evidence import assess, by_id, ctx, erule, rules_of, summary_of  # noqa: E402
from test_vex_export import DEB, row  # noqa: E402

OWN_VER = "2.0.7-1ubuntu0.7"
OWN_PURL = DEB.format("python3-urllib3", OWN_VER)


def ustat(entries, comps=None):
    return {"schema": vx.USTATUS_SCHEMA, "status": "OK", "detail": "x",
            "mirror": {"commit": "b" * 40, "commit_date": "2026-11-06T00:00:00Z"},
            "components": comps if comps is not None else {OWN_PURL: {"source": "python-urllib3", "source_version": OWN_VER, "release": "noble"}},
            "entries": entries, "mirror_counts": {}}


def e(status, note=""):
    return {"python-urllib3": {"noble": {"status": status, "note": note}}}


UST = ustat({"CVE-P1": e("released", "2.0.7-1ubuntu0.4"),           # 比安裝的舊 → 已修好
             "CVE-P2": e("released", OWN_VER),                       # 一樣 → 已修好
             "CVE-P3": e("released", "2.0.7-1ubuntu0.9"),            # 比安裝的新 → 還沒到
             "CVE-P4": e("needed"),
             "CVE-P5": e("ignored", "end of life"),
             "CVE-P6": e("released", "see bug 1234"),
             "CVE-P7": {"python-urllib3": {"noble": {"status": "released", "note": "2.0.7-1ubuntu0.4", "conflict": [{"status": "needed", "note": ""}]}}}})


def prow(cve, owner=True, **kw):
    """pypi 的 urllib3，由 Ubuntu 的 python3-urllib3 裝的（deb_python）。PyPI 的修補版本寫在 fix_*，U2 不看。"""
    o = {"name": "python3-urllib3", "version": OWN_VER, "source": "python-urllib3", "purl": OWN_PURL}
    dp = {"owner": o, "pypi_fix": ["2.6.0"]} if owner else {"owner": None, "source_owner": o, "candidates": ["python3-urllib3 " + OWN_VER]}
    r = row(cve, "urllib3", "2.0.7", purl="pkg:pypi/urllib3@2.0.7", tier="p3", deb_python=dp, ptype="pypi", fix_state="fixed",
            fix_versions=["2.6.0"], fix_next="2.6.0", installed_as=[])
    r.update(kw)
    return r


def test_u2_rule_is_valid_and_resolves_when_ubuntu_already_fixed_it():
    rules = rules_of(erule("U2", "U2"))
    ids = ["CVE-P1", "CVE-P2", "CVE-P3", "CVE-P4", "CVE-P5", "CVE-P6", "CVE-P7", "CVE-P8"]
    allr, _, info = assess([prow(i) for i in ids], rules, ubuntu_status=UST)
    r = by_id(allr)
    for i in ("CVE-P1", "CVE-P2"):
        v = r[i]["vex"]
        assert v["state"] == "resolved" and v["source"] == "rule" and v["evidence"] == "U2" and v["rule"] == "U2"
        assert "justification" not in v and "commit bbbbbbbbbbbb" in v["detail"] and "PyPI fix versions do not apply" in v["detail"]
    assert "CVE-P1: released 2.0.7-1ubuntu0.4" in r["CVE-P1"]["vex"]["detail"] and OWN_VER in r["CVE-P1"]["vex"]["detail"]
    for i in ids[2:]:
        assert r[i]["vex"] is None, i
    s = summary_of(info, "U2")
    assert s["state"] == "resolved" and s["applied"] == 2 and s["non_kernel"] == 2
    assert s["not_applied"] == {"installed_older": 1, "other_status": 2, "note_not_version": 1, "conflict": 1, "no_entry": 1}
    # 候選都來自同一個原始碼套件（source_owner）也一樣
    allr, _, _ = assess([prow("CVE-P1", owner=False)], rules, ubuntu_status=UST)
    assert allr[0]["vex"]["state"] == "resolved"


def test_u2_needs_every_cve_and_other_inputs():
    rules = rules_of(erule("U2", "U2"))
    # 一列多個 CVE：每個都要 released 而且不比註記舊
    assert assess([prow("CVE-P1", cves=["CVE-P1", "CVE-P3"])], rules, ubuntu_status=UST)[0][0]["vex"] is None
    assert assess([prow("CVE-P1", cves=["CVE-P1", "CVE-P2"])], rules, ubuntu_status=UST)[0][0]["vex"]["state"] == "resolved"
    # 沒有擁有者的列、不是 Python 模組的 deb 列、核心的列：不看
    plain = row("CVE-P1", "urllib3", "2.0.7", purl="pkg:pypi/urllib3@2.0.7", tier="p3")
    a, _, info = assess([plain], rules, ubuntu_status=UST)
    assert a[0]["vex"] is None and summary_of(info, "U2")["not_applied"] == {}
    # 擁有者的原始碼套件不在 Tracker 的元件表、沒有檔案、status 不是 OK
    a, _, info = assess([prow("CVE-P1")], rules, ubuntu_status=ustat(UST["entries"], comps={}))
    assert a[0]["vex"] is None and summary_of(info, "U2")["not_applied"] == {"source_unknown": 1}
    for u in (None, dict(UST, status="NOT_RUN")):
        a, _, info = assess([prow("CVE-P1")], rules, ubuntu_status=u)
        assert a[0]["vex"] is None and summary_of(info, "U2")["not_applied"] == {"no_data": 1}


def test_u2_never_over_kev_or_a_human_decision_and_sees_only_the_owner_identity(monkeypatch):
    rules = rules_of(erule("U2", "U2"))
    a, _, info = assess([prow("CVE-P1", kev=True), prow("CVE-P2", exploited_sources=["EUVD"])], rules, ubuntu_status=UST)
    assert all(r["vex"] is None for r in a) and summary_of(info, "U2")["excluded_kev"] == 2
    assert "would set resolved" in vx.assess(copy.deepcopy([prow("CVE-P1", kev=True)]), rules=rules,
                                             rule_ctx=ctx(ubuntu_status=UST))[0][0]["vex_note"]
    anns = [{"cve": "CVE-P1", "purl": "pkg:pypi/urllib3", "version": "2.0.7", "state": "exploitable", "response": ["update"],
             "detail": "used by the product", "author": "Carol", "date": "2026-11-03"}]
    allr, _, info = vx.assess(copy.deepcopy([prow("CVE-P1")]), annotations=anns, rules=rules,
                              rule_ctx=ctx(ubuntu_status=UST))
    assert allr[0]["vex"]["source"] == "annotation" and summary_of(info, "U2")["shadowed"] == {"annotation": 1}
    assert allr[0]["rule_shadowed"][0]["would_set"] == "resolved"
    seen = []
    f = vx.EVIDENCE_FUNCS["U2"]
    monkeypatch.setitem(vx.EVIDENCE_FUNCS, "U2", lambda v, ec: (seen.append(v), f(v, ec))[1])
    assess([prow("CVE-P1", severity="CRITICAL", epss_pct=0.99, tier="p1")], rules, ubuntu_status=UST)
    assert seen and all(set(v) == set(vx.EVIDENCE_VIEW_KEYS) for v in seen)
    assert set(seen[0]["deb_python"]) == set(vx.DEB_PYTHON_VIEW_KEYS) and "pypi_fix" not in seen[0]["deb_python"]


def test_without_a_u2_rule_nothing_changes():
    rows = [prow("CVE-P1"), prow("CVE-P2", owner=False)]
    only_batch = rules_of({"id": "R8", "author": "Alice", "description": "no data", "date": "2026-11-01", "reason": "r",
                           "match": {"scope": "all", "fix_state": ["no Grype data"]},
                           "set": {"state": "exploitable", "response": ["can_not_fix"], "detail_template": "{component}"}})
    a, _, _ = assess(rows, only_batch, ubuntu_status=UST)
    assert all(r["vex"] is None for r in a)


def test_batch_rule_for_no_fix_information_covers_deb_python_rows_and_rows_without_a_version():
    rules = rules_of({"id": "R8", "author": "Alice", "description": "no fix information", "date": "2026-11-01", "reason": "r",
                      "match": {"scope": "all", "fix_state": ["no Grype data"]},
                      "set": {"state": "exploitable", "response": ["can_not_fix"],
                              "detail_template": "Insufficient data: no fix information for {component}; treated as affected.",
                              "recommendation": "Look for fix information for {component}."}})
    nodata = prow("CVE-N1", fix_state="no Grype data", fix_versions=[], fix_next=None)
    nodata["deb_python"]["owner"]["purl"] = OWN_PURL
    noversion = row("CVE-N2", "fuse", "", purl="pkg:generic/fuse", tier="p3", fix_state="no Grype data", fix_versions=[], fix_next=None)
    p1 = row("CVE-N3", "gdb", "1.0", tier="p1", fix_state="no Grype data", fix_versions=[], fix_next=None)
    a, _, info = assess([nodata, noversion, p1], rules, ubuntu_status=UST)
    r = by_id(a)
    assert r["CVE-N1"]["vex"]["state"] == "exploitable" and r["CVE-N1"]["vex"]["response"] == ["can_not_fix"]
    assert r["CVE-N1"]["vex"]["detail"].startswith("applied to the Ubuntu package python3-urllib3")
    assert r["CVE-N2"]["vex"]["rule"] == "R8" and "Insufficient data" in r["CVE-N2"]["vex"]["detail"]
    assert r["CVE-N3"]["vex"] is None      # P1 rows are decided by a person (no allow_p1)


# ---------- review fixes: F1 owner-row human decision, F2 tier, F3 bare numbers, F4 coverage ----------

def test_real_deb_version_rejects_bare_numbers():
    for ok in ("2.0.7-1ubuntu0.4", "1:1.3.dfsg-3.1", "5.4.5", "20260601~24.04.1"):
        assert vx.real_deb_version(ok), ok
    for bad in ("1", "0", "1234", "1:2", "", "abc", "see bug 1234"):
        assert not vx.real_deb_version(bad), bad
    ust = ustat({"CVE-B1": e("released", "1"), "CVE-B2": e("released", "0"), "CVE-B3": e("released", "1234")})
    a, _, info = assess([prow(c) for c in ("CVE-B1", "CVE-B2", "CVE-B3")], rules_of(erule("U2", "U2")), ubuntu_status=ust)
    assert all(r["vex"] is None for r in a) and summary_of(info, "U2")["not_applied"] == {"note_not_version": 3}
    # the installed source version must be a real version too
    comps = {OWN_PURL: {"source": "python-urllib3", "source_version": "7", "release": "noble"}}
    a, _, info = assess([prow("CVE-P1")], rules_of(erule("U2", "U2")), ubuntu_status=ustat(UST["entries"], comps=comps))
    assert a[0]["vex"] is None and summary_of(info, "U2")["not_applied"] == {"source_version_not_version": 1}


def test_u2_not_applied_branches_no_cve_version_forms_and_compare():
    rules = rules_of(erule("U2", "U2"))
    a, _, info = assess([prow("CVE-P1", cves=[])], rules, ubuntu_status=UST)
    assert a[0]["vex"] is None and summary_of(info, "U2")["not_applied"] == {"no_cve": 1}
    comps = {OWN_PURL: {"source": "python-urllib3", "source_version": "${source:Version}", "release": "noble"}}
    a, _, info = assess([prow("CVE-P1")], rules, ubuntu_status=ustat(UST["entries"], comps=comps))
    assert a[0]["vex"] is None and summary_of(info, "U2")["not_applied"] == {"source_version_not_version": 1}
    a, _, info = assess([prow("CVE-P1")], rules, ubuntu_status=UST, vercmp=None)
    assert a[0]["vex"] is None and summary_of(info, "U2")["not_applied"] == {"no_version_compare": 1}


def test_u2_never_touches_kernel_rows():
    rules = rules_of(erule("U2", "U2"))
    a, _, info = assess([prow("CVE-P1", kernel=True)], rules, ubuntu_status=UST)
    assert a[0]["vex"] is None and summary_of(info, "U2")["not_applied"] == {} and summary_of(info, "U2")["applied"] == 0


def test_u2_source_owner_with_several_cves():
    rules = rules_of(erule("U2", "U2"))
    a, _, info = assess([prow("CVE-P1", owner=False, cves=["CVE-P1", "CVE-P2"])], rules, ubuntu_status=UST)
    assert a[0]["vex"]["state"] == "resolved" and "CVE-P1: released" in a[0]["vex"]["detail"] and "CVE-P2: released" in a[0]["vex"]["detail"]
    a, _, info = assess([prow("CVE-P1", owner=False, cves=["CVE-P1", "CVE-P3"])], rules, ubuntu_status=UST)
    assert a[0]["vex"] is None and set(summary_of(info, "U2")["not_applied"]) == {"installed_older"}
    a, _, info = assess([prow("CVE-P1", owner=False, cves=["CVE-P1", "CVE-P4"])], rules, ubuntu_status=UST)
    assert a[0]["vex"] is None and set(summary_of(info, "U2")["not_applied"]) == {"other_status"}


def test_full_output_is_the_same_with_and_without_u2_except_for_the_u2_rows():
    rows = [prow("CVE-P1"), prow("CVE-P3"), prow("CVE-P4", owner=False), row("CVE-X", "openssl", "3.0.13-0ubuntu3.11", tier="p2")]
    plain = rules_of({"id": "R8", "author": "Alice", "description": "no data", "date": "2026-11-01", "reason": "r",
                      "match": {"scope": "all", "fix_state": ["no Grype data"]},
                      "set": {"state": "exploitable", "response": ["can_not_fix"], "detail_template": "{component}"}})
    withu2 = rules_of(erule("U2", "U2"), {"id": "R8", "author": "Alice", "description": "no data", "date": "2026-11-01", "reason": "r",
                                          "match": {"scope": "all", "fix_state": ["no Grype data"]},
                                          "set": {"state": "exploitable", "response": ["can_not_fix"], "detail_template": "{component}"}})
    a0, c0, i0 = assess(rows, plain, ubuntu_status=UST)
    a1, c1, i1 = assess(rows, withu2, ubuntu_status=UST)
    assert c0 == c1
    for x, y in zip(a0, a1):
        if x["id"] == "CVE-P1":
            assert x["vex"] is None and y["vex"]["state"] == "resolved"
            assert {k: v for k, v in x.items() if k != "vex"} == {k: v for k, v in y.items() if k != "vex"}
        else:
            assert x == y, x["id"]
    assert "u2_resolved" not in i0 and [r["id"] for r in i1["u2_resolved"]] == ["CVE-P1"]
    # 因 D-035 而變：info 多了 evidence（排除的依據統計）；有 U2 時多一筆 resolved 的排除，所以 evidence 兩邊不同（下面另外核對）
    strip = lambda i: {k: v for k, v in i.items() if k not in ("rules", "u2_resolved", "sources", "evidence_inputs", "evidence")}      # noqa: E731
    assert strip(i0) == strip(i1)
    assert i0["evidence"]["exclusions"] == 0 and i1["evidence"]["exclusions"] == 1 and i1["evidence"]["by_type"]["vendor-statement"] == 1
    assert {r["id"] for r in i0["rules"]} == {"R8"} and {r["id"] for r in i1["rules"]} == {"U2", "R8"}
    assert next(r for r in i0["rules"] if r["id"] == "R8") == next(r for r in i1["rules"] if r["id"] == "R8")
    u = i1["u2_resolved"][0]
    assert u["state"] == "resolved" and u["rule"] == "U2" and u["source_package"] == "python-urllib3" and u["cves"][0]["ubuntu_note"] == "2.0.7-1ubuntu0.4"


def owner_env():
    """pillow: the Ubuntu source package row has CVE-2026-5002 (Ubuntu fixed it in the installed version), and so has the Python module."""
    import test_cra_ubuntu_tracker_fix as t
    return t, t.py_rows("CVE-2026-5002")


def u2_doc():
    return vx.effective_rules({"schema": vx.RULES_SCHEMA, "author": "Alice",
                               "rules": [erule("U2", "U2")]})


def test_u2_defers_to_a_human_decision_on_the_owning_deb_row():
    t, rs = owner_env()
    ann = [{"cve": "CVE-2026-5002", "purl": "pkg:deb/ubuntu/pillow", "version": t.PV, "state": "exploitable", "response": ["update"],
            "detail": "used by the product", "author": "Carol", "date": "2026-11-03"}]
    ctx_ = dict(ctx(ubuntu_status=t.ustat()))
    # without the owner decision U2 resolves the module row
    a, _, info = vx.assess(copy.deepcopy(rs), rules=u2_doc(), rule_ctx=ctx_)
    assert t.py_of(a, "CVE-2026-5002")["vex"]["state"] == "resolved" and summary_of(info, "U2")["applied"] == 1
    # with it, the module row follows the person's decision, and the case is recorded
    a, conf, info = vx.assess(copy.deepcopy(rs), annotations=ann, rules=u2_doc(), rule_ctx=ctx_)
    x = t.py_of(a, "CVE-2026-5002")
    assert x["vex"]["source"] == "annotation" and x["vex"]["state"] == "exploitable" and x["vex"]["detail"].startswith("inherited from the decision on")
    s = summary_of(info, "U2")
    assert s["applied"] == 0 and s["owner_decided"] == 1 and s["shadowed"] == {"annotation": 1} and info["u2_resolved"] == []
    assert x["rule_shadowed"][0]["rule"] == "U2" and x["rule_shadowed"][0]["would_set"] == "resolved" and x["rule_shadowed"][0]["decided_by"] == "annotation"
    assert "U2 not applied" in x["vex_note"] and "has a decision by a person" in x["vex_note"]
    assert ("CVE-2026-5002", "annotation:exploitable", "rule:resolved (U2)") in {(c["id"], c["used"], c["other"]) for c in conf}
    # a person's decision on the owner row that agrees (resolved bucket) is used too, without a conflict
    ann2 = [dict(ann[0], state="not_affected", justification="code_not_reachable")]
    del ann2[0]["response"]
    a, conf, _ = vx.assess(copy.deepcopy(rs), annotations=ann2, rules=u2_doc(), rule_ctx=ctx_)
    assert t.py_of(a, "CVE-2026-5002")["vex"]["state"] == "not_affected"


def test_report_moves_u2_rows_to_the_distribution_fixed_section_and_lists_them(tmp_path):
    import test_cra_ubuntu_tracker_fix as t
    from test_cra_distro import recheck_doc
    from test_cra_report import META
    from test_vex_evidence import IMG, doc
    f = [t.finding("pillow", t.PV, "CVE-2026-5002", "NVD", "MEDIUM", purl=t.PIL_SRC),
         t.finding("pillow", "10.2.0", "GHSA-0000-pppp-pppp", "GITHUB", "MEDIUM", [{"cveId": "CVE-2026-5002"}], purl="pkg:pypi/pillow@10.2.0")]

    def build(name, rules):
        proj = t.make_project(tmp_path / f"p{name}", t.MIN_CFG)
        if rules:
            t.write_json(proj / vx.RULES_REL, doc(*rules))
        sc = t.make_scan(tmp_path / f"s{name}", findings=f, grype={"matches": []}, sbom=dict(t.SBOM, components=t.PYSBOM, **{}),
                         meta=dict(META, digest=IMG, finished="2026-11-05T01:02:03Z"), stages={"D-distro-recheck": "OK"})
        t.write_json(sc / "scan" / "ubuntu-status.json", t.ustat())
        t.write_json(sc / "scan" / "distro-recheck.json", recheck_doc(rows=[]))
        return t.run(proj, sc)
    r0, s0, rep0 = build("0", [])
    r1, s1, rep1 = build("1", [erule("U2", "U2")])
    assert r0.returncode in (0, 2) and r1.returncode in (0, 2), r1.stdout + r1.stderr
    # tiering: the U2 row leaves P3 and is counted with the distribution-fixed rows (rule 5c), like a distro_fixed row
    assert s1["counts"]["distro_fixed"] == s0["counts"]["distro_fixed"] + 1
    assert s1["counts"]["p3"] == s0["counts"]["p3"] - 1
    g1, g0 = s1["vex"]["gate"]["counts"]["total"], s0["vex"]["gate"]["counts"]["total"]
    assert g1["resolved"] == g0["resolved"] + 1 and g1["untriaged"] == g0["untriaged"] - 1 and g1["rows"] == g0["rows"]
    u = s1["vex"]["u2_resolved"]
    assert [(x["id"], x["tier_before"], x["tier"], x["state"]) for x in u] == [("CVE-2026-5002", "p3", "distro_fixed", "resolved")]
    assert "u2_resolved" not in s0["vex"]
    md = (rep1 / "risk-assessment.md").read_text(encoding="utf-8")
    assert "Python modules installed by an Ubuntu package" in md and "evidence rule U2" in md
    assert "evidence rule U2" not in (rep0 / "risk-assessment.md").read_text(encoding="utf-8")
    # the VEX statement itself says resolved by rule U2
    cdx = json.loads((rep1 / "vex.cdx.json").read_text(encoding="utf-8"))
    st = [v for v in cdx["vulnerabilities"] if v["id"] == "CVE-2026-5002" and v["analysis"]["state"] == "resolved"]
    assert st and {p["name"]: p["value"] for p in st[0]["properties"]}["sca-center:vex-rule-evidence"] == "U2"
