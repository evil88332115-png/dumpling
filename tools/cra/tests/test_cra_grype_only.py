"""cra_report.py：Grype 有、DT 沒有的比對成為「只有 Grype」的列（found_by "grype only"，Source IDs GRYPE:…）。
以前只在交叉核對寫數量與前 10 個編號、閘門多一個理由，比對本身沒有列、沒有 VEX（實際映像：219 個 CVE、438 筆比對，含對外服務
iperf3 上 CVSS ≥ 7、AV:N 的弱點，應該在必須判斷範圍內）。現在和其他列一樣分級、判斷、寫 VEX。DT 的列逐字不變。資料全部是合成的。"""
import copy
import json

from test_cra_exploitation import cfg_of, run as xrun, setup
from test_cra_report import (DEB, FINDINGS, GRYPE, KFINDINGS, KGRYPE, META, SBOM, finding, kernel_scan, kmatch, make_project,
                             make_scan, run, write_json)
from test_vex_evidence import IMG, erule
from test_vex_export import kcfg
from test_vex_rules import doc
import cra_report as cr
import vex_export as vx

NET = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
IPERF = DEB.format("iperf3", "3.16-1build2")


def gmatch(cve, purl, name, version, sev="Medium", nvd_score=None, vector=NET, kev=False, epss=None, state="not-fixed", rel=True):
    """Grype 的一筆 Ubuntu 比對（主紀錄 ubuntu namespace）；nvd_score：relatedVulnerabilities 的 NVD 紀錄的 CVSS 3.1。"""
    v = {"id": cve, "namespace": "ubuntu:distro:ubuntu:24.04", "severity": sev, "fix": {"state": state, "versions": []}}
    if kev:
        v["knownExploited"] = [{"cve": cve}]
    if epss is not None:
        v["epss"] = [{"cve": cve, "epss": epss, "percentile": 0.5, "date": "2026-11-01"}]
    related = [{"id": cve, "namespace": "nvd:cpe", "severity": "High",
                "cvss": [{"source": "nvd@nist.gov", "type": "Primary", "version": "3.1", "vector": vector,
                          "metrics": {"baseScore": nvd_score}}] if nvd_score is not None else []}] if rel else []
    return {"vulnerability": v, "relatedVulnerabilities": related,
            "artifact": {"name": name, "version": version, "type": "deb", "purl": purl}}


def iperf_services():
    return {"schema": "sca-center-exposed-services/1", "collected": "2026-11-01", "source": "synthetic",
            "services": [{"program": "/usr/bin/iperf3", "package": "iperf3:arm64", "protocol": "tcp", "port": 5201, "address": "0.0.0.0"}]}


DT_ONE = [finding("libother1", "1.0-1", "CVE-2026-9008", "NVD", "LOW")]


def test_exposed_service_grype_only_cve_is_must_assess_p3(tmp_path):
    """對外服務（iperf3）上只有 Grype 有的 CVE，CVSS 7.5 AV:N（Grype 的 NVD 紀錄）：exploitation 的 P3、在必須判斷範圍內、沒有判斷。"""
    grype = {"matches": [gmatch("CVE-2026-7001", IPERF, "iperf3", "3.16-1build2", nvd_score=7.5)]}
    proj, scan = setup(tmp_path, findings=DT_ONE, evidence=None, anns=None, euvd=None, services=iperf_services(), grype=grype)
    r, s, reports = xrun(proj, scan)
    assert s["status"] != "FAIL", r.stdout + r.stderr
    by = {x["id"]: x for x in s["exploitation"]["must_assess"]["list"]}
    x = by["CVE-2026-7001"]
    assert (x["tier"], x["assessed"], x["component"], x["found_by"]) == ("p3", False, "iperf3", "grype only")
    assert x["dt_findings"]["total"] == 0
    assert x["why"] == ["exposed, CVSS 7.5 (Grype nvd@nist.gov v3.1) AV:N: /usr/bin/iperf3 (tcp/5201 on 0.0.0.0)"]
    assert s["counts"]["grype_only_advisories"] == 1 and s["counts"]["rows"] == 2
    t = (reports / "risk-assessment.md").read_text(encoding="utf-8")
    row = next(ln for ln in t.split("### 8.6 P3")[1].splitlines() if "CVE-2026-7001" in ln)
    assert "GRYPE:CVE-2026-7001" in row and "| iperf3 (found only by Grype) | 3.16-1build2 |" in row and "7.5 (v3)" in row and "| not-fixed |" in row


def test_grype_only_kev_cve_is_p1_in_both_schemes(tmp_path):
    """Grype 的 knownExploited（DT 沒有這個 CVE）：一列，KEV 欄 YES (Grype)，P1（current 與 exploitation 都是）。"""
    grype = {"matches": [gmatch("CVE-2026-7002", DEB.format("libkev9", "1.0-1"), "libkev9", "1.0-1", sev="Low", kev=True)]}
    for scheme in (None, "exploitation"):
        proj, scan = setup(tmp_path, cfg=cfg_of(scheme=scheme), findings=DT_ONE, evidence=None, anns=None, euvd=None,
                           services=iperf_services(), grype=grype, name=f"k-{scheme}")
        r, s, reports = xrun(proj, scan)
        row = next(ln for ln in (reports / "risk-assessment.md").read_text(encoding="utf-8").split("### 8.4 P1")[1].split("### 8.5")[0]
                   .splitlines() if "CVE-2026-7002" in ln)
        assert "| YES (Grype) |" in row and "GRYPE:CVE-2026-7002" in row, scheme
        assert s["counts"]["p1"] == 1 and s["counts"]["kev_open"] == 1 and s["counts"]["kev_grype_only_not_in_table"] == []
        assert not any("not in the risk table" in d for d in s["documents"]["risk-assessment"]["detail"])
        if scheme:
            assert {x["id"]: x["tier"] for x in s["exploitation"]["must_assess"]["list"]}["CVE-2026-7002"] == "p1"


def test_grype_only_kernel_cve_handled_by_k1(tmp_path):
    """只有 Grype 有的核心 CVE（同一個對應的 Canonical 核心元件）：核心的列（8.7 節），證據規則 K1（kernel-config 判 not_affected）
    照樣套用，VEX 有它的陳述。"""
    g = copy.deepcopy(KGRYPE)
    g["matches"].append(kmatch("CVE-2025-0150", "not-fixed"))
    sc = kernel_scan(tmp_path / "s", findings=KFINDINGS, grype=g)
    write_json(sc / "meta.json", dict(META, digest=IMG, finished="2026-11-05T01:02:03Z"))
    write_json(sc / "scan" / "kernel-config.json", kcfg([{"cve": "CVE-2025-0150", "decision": "not_affected", "detail": "CONFIG_X is not set"}]))
    proj = make_project(tmp_path / "p")
    write_json(proj / vx.RULES_REL, doc(erule("K1", "K1", images=[IMG])))
    r, s, rep = run(proj, sc)
    assert s["status"] != "FAIL", r.stdout + r.stderr
    k = s["counts"]["kernel"]
    assert k["grype_only_rows"] == 1 and k["rows"] == 9 and k["accepted"] == 2
    rs = {x["id"]: x for x in s["vex"]["rules"]["rules"]}
    assert rs["K1"]["applied"] == 1
    cdx = json.loads((rep / "vex.cdx.json").read_text(encoding="utf-8"))
    v = next(x for x in cdx["vulnerabilities"] if x["id"] == "CVE-2025-0150")
    props = {p["name"]: p["value"] for p in v["properties"]}
    assert v["analysis"]["state"] == "not_affected" and props["sca-center:vex-rule"] == "K1"
    assert props["sca-center:source-ids"] == "GRYPE:CVE-2025-0150"
    kd = (rep / "kernel-vulnerabilities.md").read_text(encoding="utf-8")
    row = next(ln for ln in kd.split("## Full list")[1].splitlines() if "| CVE-2025-0150 |" in ln)
    assert "| ACCEPTED |" in row and "not_affected (rule K1)" in row


def test_grype_cve_equal_to_dt_ghsa_alias_is_not_a_second_row(tmp_path):
    """DT 的 GHSA 別名含 CVE-X、Grype 以 CVE-X 為主編號：交叉核對算對上，不另加只有 Grype 的列。"""
    fs = [finding("lib", "1.0", "GHSA-aaaa-bbbb-cccc", "GITHUB", "HIGH", [{"cveId": "CVE-2026-7003"}], purl="pkg:npm/lib@1.0")]
    grype = {"matches": [{"vulnerability": {"id": "CVE-2026-7003", "fix": {"state": "fixed", "versions": ["1.1"]}},
                          "relatedVulnerabilities": [], "artifact": {"name": "lib", "version": "1.0", "type": "npm", "purl": "pkg:npm/lib@1.0"}}]}
    r, s, rep = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s", findings=fs, grype=grype))
    c = s["counts"]
    assert (c["rows"], c["grype_only_advisories"], c["grype_advisories_without_dt"]) == (1, 0, 0)
    t = (rep / "risk-assessment.md").read_text(encoding="utf-8")
    assert "GRYPE:" not in t.split("### 8.4")[1] and "| fixed in 1.1 |" in t


def test_vex_statements_for_grype_only_rows_point_to_sbom_components(tmp_path):
    """只有 Grype 的列有判定時寫進 VEX，affects 指向產品 SBOM 的元件（以 purl 對；DT 沒有這個元件也一樣）。"""
    sbom = copy.deepcopy(SBOM)
    sbom["components"].append({"type": "library", "bom-ref": "iperf3-ref", "name": "iperf3", "version": "3.16-1build2", "purl": IPERF})
    grype = {"matches": GRYPE["matches"][:2] + [gmatch("CVE-2026-7001", IPERF, "iperf3", "3.16-1build2", nvd_score=7.5)]}
    proj = make_project(tmp_path / "p")
    write_json(proj / vx.ANN_REL, {"schema": vx.ANN_SCHEMA, "annotations": [
        {"cve": "CVE-2026-7001", "purl": "pkg:deb/ubuntu/iperf3", "state": "not_affected", "justification": "code_not_reachable",
         "detail": "The vulnerable option is not used.", "author": "PSIRT lead", "date": "2026-11-01"}]})
    r, s, rep = run(proj, make_scan(tmp_path / "s", grype=grype, sbom=sbom))
    assert s["status"] != "FAIL", r.stdout + r.stderr
    cdx = json.loads((rep / "vex.cdx.json").read_text(encoding="utf-8"))
    v = next(x for x in cdx["vulnerabilities"] if x["id"] == "CVE-2026-7001")
    assert v["analysis"]["state"] == "not_affected" and len(v["affects"]) == 1 and v["affects"][0]["ref"].endswith("#iperf3-ref")
    assert not any(c.get("name") == "iperf3" for c in cdx.get("components") or [])
    assert s["counts"]["accepted_by_vex"] == {"annotation": 1} and s["vex"]["gate"]["grype_only_advisories"] == 0
    ov = json.loads((rep / "vex.openvex.json").read_text(encoding="utf-8"))
    assert any(st["vulnerability"]["name"] == "CVE-2026-7001" for st in ov["statements"])


def test_dt_rows_unchanged_and_grype_only_row_values(tmp_path):
    """DT 的列逐字不變（另外建列）；只有 Grype 的列帶 Grype 的嚴重度（各 namespace 各一個來源）、CVSS、EPSS、修補狀態、namespace 與標記。"""
    pol = cr.policy_of({})
    g = copy.deepcopy(GRYPE)
    g["matches"].append(gmatch("CVE-2026-7004", DEB.format("libz9", "1.0-1"), "libz9", "1.0-1", sev="Negligible", nvd_score=9.8,
                               epss=0.42, state="wont-fix"))
    idx, _ = cr.grype_index(g)
    rows = cr.build_rows(FINDINGS, pol, idx, True)
    before = json.dumps(rows, sort_keys=True)
    go, unlisted, unknown = cr.grype_only_rows(g, rows, pol, idx, True)
    assert json.dumps(rows, sort_keys=True) == before and unlisted == [] and unknown == []
    assert json.dumps(cr.build_rows(FINDINGS, pol, idx, True), sort_keys=True) == before
    r = {x["id"]: x for x in go}["CVE-2026-7004"]
    assert (r["found_by"], r["sources"], r["source_ids"], r["grype_namespaces"]) == (
        "grype only", ["grype"], ["GRYPE:CVE-2026-7004"], ["nvd:cpe", "ubuntu:distro:ubuntu:24.04"])
    assert r["sev_by_source"] == {"NVD": "HIGH", "UBUNTU": "LOW"} and r["severity"] == "HIGH" and r["severity_source"] == "nvd-cvss"
    assert (r["cvss_score"], r["epss"], r["fix_state"], r["n_findings"], r["grype_matches"]) == (9.8, 0.42, "wont-fix", 0, 1)
    assert [a["state"] for a in r["analysis"]] == [""] and r["tier"] == "p2"        # current：HIGH → P2（沒有 DT 分析，不是 accepted）
    # 沒有元件身分（沒有名稱也沒有 purl）的比對不能成列：逐一回報
    g2 = {"matches": [{"vulnerability": {"id": "CVE-2026-7005"}, "artifact": {"version": "1"}}]}
    assert cr.grype_only_rows(g2, rows, pol, idx, True) == ([], [{"id": "CVE-2026-7005", "cves": ["CVE-2026-7005"], "package": "?"}], [])


def test_unlisted_grype_match_blocks_gate_by_name(tmp_path):
    g = {"matches": GRYPE["matches"][:2] + [{"vulnerability": {"id": "CVE-2026-7005"}, "artifact": {"version": "1"}}]}
    r, s, rep = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s", grype=g))
    gate = s["vex"]["gate"]
    assert gate["grype_only_advisories"] == 1 and gate["verdict"] != "OK"
    assert any("could not be listed as rows" in x and "CVE-2026-7005" in x for x in gate["reasons"])
    assert s["counts"]["grype_only_unlisted"] == 1 and s["counts"]["grype_only_advisories"] == 0
    assert any("CVE-2026-7005" in d and "not assessed" in d for d in s["documents"]["risk-assessment"]["detail"])


# ---------- 審查後補：每個元件分開比、規則 13、NVIDIA 列、大小寫、依日期的出貨關卡、8.3 節的說明 ----------

def _cross(md):
    return next(ln for ln in md.splitlines() if ln.startswith("Cross-check:"))


def _pm(id_, purl, name, version, rel=(), typ="python", state="fixed", fixv=("9.9.9",)):
    return {"vulnerability": {"id": id_, "severity": "High", "fix": {"state": state, "versions": list(fixv)}},
            "relatedVulnerabilities": [{"id": x} for x in rel],
            "artifact": {"name": name, "version": version, "type": typ, "purl": purl}}


def test_same_cve_on_pip_copy_is_its_own_row_but_deb_owned_module_is_covered(tmp_path):
    """DT 在 deb 的 python3-urllib3 2.0.7-1 上有 CVE-X。Grype 在 (a) pip 另裝的 urllib3 1.25.0 → 不同的元件，一列只有 Grype 的列；
    (b) Ubuntu 套件 python3-urllib3 裝進 dist-packages 的 urllib3 2.0.7 → 同一份安裝的程式（deb_python 的擁有者），算對上、不另加。"""
    deb = DEB.format("python3-urllib3", "2.0.7-1")
    fs = [finding("python3-urllib3", "2.0.7-1", "CVE-2026-7777", "NVD", "HIGH", purl=deb)]
    sbom = copy.deepcopy(SBOM)
    sbom["components"] += [
        {"type": "library", "name": "python3-urllib3", "version": "2.0.7-1", "purl": deb},
        {"type": "library", "name": "urllib3", "version": "2.0.7", "purl": "pkg:pypi/urllib3@2.0.7",
         "properties": [{"name": "syft:location:0:path", "value": "/usr/lib/python3/dist-packages/urllib3-2.0.7.dist-info/METADATA"}]},
        {"type": "library", "name": "urllib3", "version": "1.25.0", "purl": "pkg:pypi/urllib3@1.25.0",
         "properties": [{"name": "syft:location:0:path", "value": "/opt/app/venv/lib/python3.12/site-packages/urllib3-1.25.0.dist-info/METADATA"}]}]
    grype = {"matches": [_pm("CVE-2026-7777", deb, "python3-urllib3", "2.0.7-1", typ="deb"),
                         _pm("GHSA-zzzz-yyyy-xxxx", "pkg:pypi/urllib3@2.0.7", "urllib3", "2.0.7", rel=["CVE-2026-7777"]),
                         _pm("GHSA-zzzz-yyyy-xxxx", "pkg:pypi/urllib3@1.25.0", "urllib3", "1.25.0", rel=["CVE-2026-7777"])]}
    r, s, rep = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s", findings=fs, grype=grype, sbom=sbom))
    c = s["counts"]
    assert (c["rows"], c["grype_only_advisories"], c["grype_advisories_without_dt"], c["grype_only_cves"]) == (2, 1, 1, 0)
    md = (rep / "risk-assessment.md").read_text(encoding="utf-8")
    assert [ln for ln in md.splitlines() if "| urllib3 (found only by Grype) | 1.25.0 |" in ln]
    assert not [ln for ln in md.splitlines() if "| 2.0.7 |" in ln and "found only by Grype" in ln]
    assert ("on the same component: 1 Grype advisory has no counterpart in Dependency-Track (CVE-2026-7777), "
            "0 Dependency-Track rows have no counterpart in Grype") in _cross(md)


def test_vendored_copy_and_second_version_are_own_rows(tmp_path):
    """同一個 CVE：DT 在 deb 的 libexpat1 上；Grype 在打包進應用程式的 expat（pkg:generic，vendored 的副本）上 → 一列。
    同一個 npm 套件兩個版本都裝了：DT 只有 4.17.20 → Grype 的 4.17.20 算對上，4.17.15 是一列。"""
    expat = DEB.format("libexpat1", "2.6.1-2")
    fs = [finding("libexpat1", "2.6.1-2", "CVE-2026-7101", "NVD", "HIGH", purl=expat),
          finding("lodash", "4.17.20", "CVE-2026-7102", "NVD", "HIGH", purl="pkg:npm/lodash@4.17.20")]
    grype = {"matches": [_pm("CVE-2026-7101", expat, "libexpat1", "2.6.1-2", typ="deb"),
                         _pm("CVE-2026-7101", "pkg:generic/expat@2.5.0", "expat", "2.5.0", typ="binary"),
                         _pm("CVE-2026-7102", "pkg:npm/lodash@4.17.20", "lodash", "4.17.20", typ="npm"),
                         _pm("CVE-2026-7102", "pkg:npm/lodash@4.17.15", "lodash", "4.17.15", typ="npm")]}
    r, s, rep = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s", findings=fs, grype=grype))
    c = s["counts"]
    assert (c["rows"], c["grype_only_advisories"], c["grype_advisories_without_dt"], c["dt_only_rows"]) == (4, 2, 2, 0)
    md = (rep / "risk-assessment.md").read_text(encoding="utf-8")
    assert "| expat (found only by Grype) | 2.5.0 |" in md and "| lodash (found only by Grype) | 4.17.15 |" in md
    assert "| lodash | 4.17.20 |" in md and "| lodash (found only by Grype) | 4.17.20 |" not in md


def test_dt_row_on_other_component_counts_as_dt_only(tmp_path):
    """交叉核對的另一邊也每個元件分開：Grype 只在別的元件上有同一個 CVE → 這一列 DT 列沒有對應。"""
    fs = [finding("lodash", "4.17.20", "CVE-2026-7102", "NVD", "HIGH", purl="pkg:npm/lodash@4.17.20")]
    grype = {"matches": [_pm("CVE-2026-7102", "pkg:npm/lodash@4.17.15", "lodash", "4.17.15", typ="npm")]}
    r, s, rep = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s", findings=fs, grype=grype))
    assert (s["counts"]["dt_only_rows"], s["counts"]["grype_only_advisories"]) == (1, 1)


def test_ids_compared_case_insensitively():
    pol = cr.policy_of({})
    fs = [finding("lib", "1.0", "GHSA-AAAA-BBBB-CCCC", "GITHUB", "HIGH", purl="pkg:npm/lib@1.0")]
    g = {"matches": [_pm("ghsa-aaaa-bbbb-cccc", "pkg:npm/lib@1.0", "lib", "1.0", typ="npm")]}
    idx, _ = cr.grype_index(g)
    rows = cr.build_rows(fs, pol, idx, True)
    assert cr.grype_uncovered(g, cr.dt_rows_of(rows)) == [] and cr.grype_only_rows(g, rows, pol, idx, True) == ([], [], [])


def test_version_unknown_components_are_gap_not_rows(tmp_path):
    """專案規則 13：sbomgate 排除的比對（requests >=2.0 當成 2.0：VERSION_FROM_RANGE；沒有版本：NO_VERSION）不成列、不做弱點比對；
    資料狀態 GAP、交叉核對與閘門逐一點名。沒有 sbomgate 時，artifact 沒有版本的比對也一樣（NO_VERSION）。"""
    gm = [_pm("GHSA-j8r2-6x86-q33q", "pkg:pypi/requests@2.0", "requests", "2.0", rel=["CVE-2023-32681"]),
          _pm("CVE-2026-8888", "pkg:deb/ubuntu/libnover", "libnover", "", typ="deb"),
          _pm("CVE-2026-8889", "pkg:npm/nover", "nover", "", typ="npm")]
    gate = {"excluded_matches": [
        {"id": "GHSA-j8r2-6x86-q33q", "package": "requests", "version": "2.0", "purl": "pkg:pypi/requests@2.0", "excluded_reason": "VERSION_FROM_RANGE"},
        {"id": "CVE-2026-8888", "package": "libnover", "version": None, "purl": "pkg:deb/ubuntu/libnover", "excluded_reason": "NO_VERSION"}]}
    scan = make_scan(tmp_path / "s", grype={"matches": GRYPE["matches"][:2] + gm})
    write_json(scan / "scan" / "sbomgate.json", gate)
    r, s, rep = run(make_project(tmp_path / "p"), scan)
    c = s["counts"]
    assert (c["rows"], c["grype_only_advisories"], c["grype_version_unknown"]) == (9, 0, 3)
    md = (rep / "risk-assessment.md").read_text(encoding="utf-8")
    assert not any("| requests" in ln or "| libnover" in ln or "| nover" in ln for ln in md.splitlines())
    d = s["documents"]["risk-assessment"]
    assert d["status"] == "GAP"
    why = next(x for x in d["detail"] if "project rule 13" in x)
    assert ("GHSA-j8r2-6x86-q33q (CVE-2023-32681) on requests 2.0 (VERSION_FROM_RANGE)" in why and "CVE-2026-8888 on libnover (NO_VERSION)" in why
            and "CVE-2026-8889 on nover (NO_VERSION)" in why)
    g = s["vex"]["gate"]
    assert g["verdict"] == "GAP" and sum("version unknown, project rule 13" in x for x in g["not_assessed"]) == 3
    assert "not listed as rows (GAP)" in _cross(md)


def test_collision_with_nvidia_row_names_extra_cves(tmp_path):
    """只有 Grype 的列和 NVIDIA 公告的列同一個（編號、元件、版本）：不另成列；Grype 那筆另外的 CVE 不在任何一列 → 資料狀態點名
    （以前只在另有只有 Grype 的列時才點名）。"""
    core = "pkg:deb/ubuntu/nvidia-l4t-core@36.4.3-20250101000000?arch=arm64"
    nvf = finding("nvidia-l4t-core", "36.4.3-20250101000000", "CVE-2026-24154", "NVIDIA", "HIGH", purl=core)
    scan = make_scan(tmp_path / "s", findings=[], grype={"matches": [
        _pm("CVE-2026-24154", core, "nvidia-l4t-core", "36.4.3-20250101000000", rel=["CVE-2026-24155"], typ="deb")]})
    write_json(scan / "scan" / "nvidia-bulletins.json", {"status": "OK", "findings": [nvf]})
    r, s, rep = run(make_project(tmp_path / "p"), scan)
    assert s["status"] != "FAIL", r.stdout + r.stderr
    assert (s["counts"]["rows"], s["counts"]["grype_only_advisories"]) == (1, 0)
    assert any("1 CVE of them is in no row: CVE-2026-24155" in x for x in s["documents"]["risk-assessment"]["detail"])


def test_date_gate_blocks_on_grype_only_must_assess_row(tmp_path):
    """分級方式 exploitation、首次上市日在 2027-12-11 之後：必須判斷範圍裡沒判斷的只有 Grype 的列擋出貨。"""
    grype = {"matches": [gmatch("CVE-2026-7001", IPERF, "iperf3", "3.16-1build2", nvd_score=7.5)]}
    proj, scan = setup(tmp_path, cfg=cfg_of(market="2028-01-01"), findings=DT_ONE, evidence=None, anns=None, euvd=None,
                       services=iperf_services(), grype=grype)
    r, s, reports = xrun(proj, scan)
    g = s["exploitation"]["gate"]
    assert (g["after_cutoff"], g["verdict"], g["blocking_rows"], g["not_assessed"]) == (True, "BLOCKED", 1, 1)


def test_rows_paragraph_only_with_grype_only_rows(tmp_path):
    """8.3 節「Rows found only by Grype …」只在有只有 Grype 的列時寫；Grype 的比對都對上時文件和以前一樣。"""
    r, s, rep = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s", grype={"matches": GRYPE["matches"][:2]}))
    md = (rep / "risk-assessment.md").read_text(encoding="utf-8")
    assert s["counts"]["grype_only_advisories"] == 0 and "Rows found only by Grype" not in md
    assert "the binary packages installed from it are shown in brackets.\n\n" in md
    r, s, rep = run(make_project(tmp_path / "p2"), make_scan(tmp_path / "s2"))
    assert "shown in brackets.\nRows found only by Grype" in (rep / "risk-assessment.md").read_text(encoding="utf-8")


def test_deb_binaries_of_the_same_source_package_are_one_component(tmp_path):
    """deb：同一個原始碼套件編出來的二進位套件是同一份程式碼。DT 在 bluez 上、Grype 在 libbluetooth3（upstream bluez）上的同一個 CVE
    算對上（purl 的 upstream qualifier 或 Grype 的 upstreams）；別的原始碼套件（gst-plugins-bad 與 gst-plugins-base 有同一個 CVE）不算。"""
    bluez = DEB.format("bluez", "5.72-0ubuntu5.5")
    libbt = "pkg:deb/ubuntu/libbluetooth3@5.72-0ubuntu5.5?arch=arm64&upstream=bluez&distro=ubuntu-24.04"
    base = "pkg:deb/ubuntu/gst-plugins-base1.0@1.24.2-1ubuntu0.4?arch=source&distro=ubuntu-24.04"
    bad = "pkg:deb/ubuntu/libgstreamer-plugins-bad1.0-0@1.24.2-1ubuntu4?arch=arm64&distro=ubuntu-24.04"
    fs = [finding("bluez", "5.72-0ubuntu5.5", "CVE-2026-7201", "NVD", "HIGH", purl=bluez),
          finding("gst-plugins-base1.0", "1.24.2-1ubuntu0.4", "UBUNTU-CVE-2026-7202", "OSV", "HIGH", purl=base)]
    m_bad = _pm("CVE-2026-7202", bad, "libgstreamer-plugins-bad1.0-0", "1.24.2-1ubuntu4", typ="deb")
    m_bad["artifact"]["upstreams"] = [{"name": "gst-plugins-bad1.0"}]
    grype = {"matches": [_pm("CVE-2026-7201", libbt, "libbluetooth3", "5.72-0ubuntu5.5", typ="deb"), m_bad]}
    r, s, rep = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s", findings=fs, grype=grype))
    c = s["counts"]
    assert (c["rows"], c["grype_only_advisories"], c["dt_only_rows"]) == (3, 1, 1)
    md = (rep / "risk-assessment.md").read_text(encoding="utf-8")
    assert "| libgstreamer-plugins-bad1.0-0 (found only by Grype) |" in md and "found only by Grype) | 5.72" not in md
    assert "| bluez (also found by Grype on libbluetooth3) | 5.72-0ubuntu5.5 |" in md


# ---------- 再審查：同一個原始碼套件的其他二進位套件（grype_binaries） ----------

DHCP_V = "4.4.3-P1-4ubuntu2"
DHCP_CLI = f"pkg:deb/ubuntu/isc-dhcp-client@{DHCP_V}?arch=arm64&distro=ubuntu-24.04&upstream=isc-dhcp"


def _dhcp(tmp_path, srv_version=DHCP_V, services=None, anns=None, name="dhcp", findings=None, common=False):
    """DT 只在 isc-dhcp-client（common=True 時另有 isc-dhcp-common）上有 CVE-2026-5555（CVSS 9.8）；Grype 在 isc-dhcp-server
    （同一個原始碼套件 isc-dhcp）上有。"""
    srv = f"pkg:deb/ubuntu/isc-dhcp-server@{srv_version}?arch=arm64&distro=ubuntu-24.04&upstream=isc-dhcp"
    com = DHCP_CLI.replace("isc-dhcp-client", "isc-dhcp-common")
    fs = findings or [finding("isc-dhcp-client", DHCP_V, "CVE-2026-5555", "NVD", "HIGH", cvss=9.8, purl=DHCP_CLI)]
    m = gmatch("CVE-2026-5555", srv, "isc-dhcp-server", srv_version, sev="High", nvd_score=9.8)
    m["artifact"]["upstreams"] = [{"name": "isc-dhcp"}]
    svc = services if services is not None else {
        "schema": "sca-center-exposed-services/1", "collected": "2026-11-01", "source": "synthetic",
        "services": [{"program": "/usr/sbin/dhcpd", "package": "isc-dhcp-server:arm64", "protocol": "udp", "port": 67, "address": "0.0.0.0"}]}
    proj, scan = setup(tmp_path, findings=fs, evidence=None, anns=anns, euvd=None, services=svc, grype={"matches": [m]}, name=name)
    sb = copy.deepcopy(SBOM)
    for n, p, v in (("isc-dhcp-common", com, DHCP_V), ("isc-dhcp-client", DHCP_CLI, DHCP_V), ("isc-dhcp-server", srv, srv_version)):
        sb["components"].append({"type": "library", "bom-ref": n + "-ref", "name": n, "version": v, "purl": p})
    write_json(scan / "sbom" / "sbom.cdx.json", sb)
    r, s, rep = xrun(proj, scan)
    assert s["status"] != "FAIL", r.stdout + r.stderr
    return s, rep


def _is_na(v):
    return {"name": "dumpling:assessment", "value": "NOT_ASSESSED"} in (v.get("properties") or [])


def _stmts(rep, cve="CVE-2026-5555", not_assessed=False):
    """VEX 的陳述（狀態、指向的元件）。M7c-1（A4／D-057）起沒有判定的列也寫成 in_triage 加 NOT_ASSESSED：預設只看有判定的陳述
    （這些測試要確認的是「不會有矛盾或繼承來的判定」）；not_assessed=True 只看沒有評估的那幾條。"""
    cdx = json.loads((rep / "vex.cdx.json").read_text(encoding="utf-8")) if (rep / "vex.cdx.json").exists() else {"vulnerabilities": []}
    return [(v["analysis"]["state"], sorted(a["ref"].split("#")[1] for a in v["affects"])) for v in cdx["vulnerabilities"]
            if v["id"] == cve and _is_na(v) == not_assessed]


def test_exposed_server_binary_of_same_source_is_its_own_row(tmp_path):
    """再審查的重現（dhcp.py）：DT 只在 client 上、Grype 在對外的 server 上（同一個原始碼套件、同一個版本）→ server 自成一列只有 Grype 的列，
    在必須判斷範圍內（1 列）；client 的列不帶 server（不併進去，不沿用 client 的判定）。"""
    s, rep = _dhcp(tmp_path)
    c = s["counts"]
    # client 的列在 Grype 有對應（同一個原始碼套件、同一個版本的 server），交叉核對不算「DT 列沒有對應」（再審查 L-c）
    assert (c["rows"], c["grype_only_advisories"], c["grype_advisories_without_dt"], c["dt_only_rows"]) == (2, 1, 1, 0)
    m = s["exploitation"]["must_assess"]
    assert m["rows"] == 1 and [(x["component"], x.get("found_by"), x["tier"], x["assessed"]) for x in m["list"]] == [
        ("isc-dhcp-server", "grype only", "p3", False)]
    assert m["list"][0]["why"] == ["exposed, CVSS 9.8 (Grype nvd@nist.gov v3.1) AV:N: /usr/sbin/dhcpd (udp/67 on 0.0.0.0)"]
    md = (rep / "risk-assessment.md").read_text(encoding="utf-8")
    assert "| isc-dhcp-server (found only by Grype) |" in md and "also found by Grype" not in md


def test_client_not_affected_is_not_inherited_by_exposed_server(tmp_path):
    """dhcp_na.py：人在 DT 對 client 判 NOT_AFFECTED → client 的列 accepted；server 是自己一列、untriaged，VEX 的 not_affected 不指向 server。"""
    fs = [finding("isc-dhcp-client", DHCP_V, "CVE-2026-5555", "NVD", "HIGH", cvss=9.8, purl=DHCP_CLI,
                  analysis={"isSuppressed": True, "state": "NOT_AFFECTED", "justification": "CODE_NOT_REACHABLE",
                            "details": "dhclient not started on this product"})]
    s, rep = _dhcp(tmp_path, findings=fs)
    by = {x["component"]: x for x in s["exploitation"]["must_assess"]["list"]}
    assert set(by) == {"isc-dhcp-server"} and (by["isc-dhcp-server"]["vex"], by["isc-dhcp-server"]["assessed"]) == ("untriaged", False)
    st = _stmts(rep)
    assert st == [("not_affected", ["isc-dhcp-client-ref"])] and not any("isc-dhcp-server-ref" in refs for _, refs in st)
    # A4：server 的列沒有判定 → VEX 有一條 in_triage 加 NOT_ASSESSED（沒有評估），不是 client 的 not_affected
    assert _stmts(rep, not_assessed=True) == [("in_triage", ["isc-dhcp-server-ref"])]
    assert s["vex"]["gate"]["verdict"] != "OK" and s["vex"]["gate"]["assessment"]["untriaged"] == 1


def test_two_dt_rows_on_same_source_give_one_server_row_and_no_contradiction(tmp_path):
    """dhcp2.py：DT 在 isc-dhcp-common（EXPLOITABLE）與 isc-dhcp-client（NOT_AFFECTED）上都有；Grype 在對外的 server 上 → server 只有一列，
    兩條 DT 的陳述都不指向 server（server 沒有互相矛盾的陳述）。"""
    com = DHCP_CLI.replace("isc-dhcp-client", "isc-dhcp-common")
    fs = [finding("isc-dhcp-common", DHCP_V, "CVE-2026-5555", "NVD", "HIGH", cvss=9.8, purl=com,
                  analysis={"isSuppressed": False, "state": "EXPLOITABLE", "details": "x"}),
          finding("isc-dhcp-client", DHCP_V, "CVE-2026-5555", "NVD", "HIGH", cvss=9.8, purl=DHCP_CLI,
                  analysis={"isSuppressed": True, "state": "NOT_AFFECTED", "justification": "CODE_NOT_REACHABLE", "details": "x"})]
    s, rep = _dhcp(tmp_path, findings=fs)
    assert (s["counts"]["rows"], s["counts"]["grype_only_advisories"], s["counts"]["dt_only_rows"]) == (3, 1, 0)
    md = (rep / "risk-assessment.md").read_text(encoding="utf-8")
    assert "0 Dependency-Track rows have no counterpart in Grype" in _cross(md)
    assert sum("| GRYPE:CVE-2026-5555 | isc-dhcp-server (found only by Grype) |" in ln for ln in md.splitlines()) == 1
    st = _stmts(rep)
    assert sorted(st) == [("exploitable", ["isc-dhcp-common-ref"]), ("not_affected", ["isc-dhcp-client-ref"])]


def test_same_source_other_version_is_its_own_row(tmp_path):
    """同一個原始碼套件、版本不同（偏保守）：不併進 DT 的列，自成一列只有 Grype 的列；DT 的列沒有 grype_binaries。"""
    s, rep = _dhcp(tmp_path, srv_version="4.4.3-P1-4ubuntu3")
    c = s["counts"]
    assert (c["rows"], c["grype_only_advisories"]) == (2, 1)
    by = {x["component"]: x for x in s["exploitation"]["must_assess"]["list"]}
    assert set(by) == {"isc-dhcp-server"} and by["isc-dhcp-server"]["found_by"] == "grype only"
    md = (rep / "risk-assessment.md").read_text(encoding="utf-8")
    assert "also found by Grype" not in md and "| isc-dhcp-server (found only by Grype) | 4.4.3-P1-4ubuntu3 |" in md


def test_same_source_binary_not_exposed_is_text_only(tmp_path):
    """server 不在對外服務清單：不另成列，DT 列的元件欄寫出 server，但不進必須判斷範圍，VEX 的 affects 也不指向 server（沒有人評估過它）。"""
    svc = {"schema": "sca-center-exposed-services/1", "collected": "2026-11-01", "source": "synthetic",
           "services": [{"program": "/usr/sbin/sshd", "package": "openssh-server", "protocol": "tcp", "port": 22}]}
    ann = {"schema": vx.ANN_SCHEMA, "annotations": [
        {"cve": "CVE-2026-5555", "purl": "pkg:deb/ubuntu/isc-dhcp-client", "state": "not_affected", "justification": "code_not_reachable",
         "detail": "dhclient is not started.", "author": "PSIRT lead", "date": "2026-11-01"}]}
    s, rep = _dhcp(tmp_path, services=svc, anns=ann)
    assert s["counts"]["rows"] == 1 and s["exploitation"]["must_assess"]["rows"] == 0 and s["counts"]["dt_only_rows"] == 0
    assert "| isc-dhcp-client (also found by Grype on isc-dhcp-server) |" in (rep / "risk-assessment.md").read_text(encoding="utf-8")
    assert _stmts(rep) == [("not_affected", ["isc-dhcp-client-ref"])]


# ---------- 再審查 H2：DT 對同一個 CVE 的 KEV、EPSS（以及 EUVD）也給只有 Grype 的列 ----------

def test_grype_only_row_gets_dt_same_cve_kev_epss_and_euvd(tmp_path):
    """kev.py：DT 在 deb 的 python3-urllib3 上的 CVE 是 KEV（帶 EPSS）；Grype 在 pip 另裝的 urllib3 2.0.0 上有同一個 CVE、沒有 knownExploited
    → 只有 Grype 的列也是 KEV（YES (same CVE)）、P1，批次規則不套用；DT 的 EPSS 並列顯示。EUVD 標示的 CVE 也進 P1。"""
    fs = [finding("python3-urllib3", "1.26.5-1", "CVE-2026-7777", "NVD", "MEDIUM", kev=True, cvss=5.0, epss=0.8),
          finding("libeu9", "1.0-1", "CVE-2026-7778", "NVD", "LOW")]
    g = {"matches": [
        {"vulnerability": {"id": "GHSA-aaaa-bbbb-7777", "namespace": "github:language:python", "severity": "Medium",
                           "fix": {"state": "fixed", "versions": ["2.2.2"]}},
         "relatedVulnerabilities": [{"id": "CVE-2026-7777", "namespace": "nvd:cpe", "severity": "Medium"}],
         "artifact": {"name": "urllib3", "version": "2.0.0", "type": "python", "purl": "pkg:pypi/urllib3@2.0.0"}},
        gmatch("CVE-2026-7778", DEB.format("libeu9-tools", "2.0-1"), "libeu9-tools", "2.0-1", sev="Low")]}
    rules = {"schema": "sca-center-vex-rules/1", "rules": [
        {"id": "R9", "description": "everything", "author": "PSIRT lead", "date": "2026-11-01", "reason": "synthetic",
         "match": {"scope": "all"}, "set": {"state": "exploitable", "response": ["update"], "detail_template": "Update {component}."}}]}
    euvd = {"status": "OK", "cves": {"CVE-2026-7778": {"exploited": "yes", "kev_sources": ["eukev_kev"]}}}
    proj, scan = setup(tmp_path, findings=fs, evidence=None, anns=None, euvd=euvd, services=None, grype=g)
    write_json(proj / "CRA" / "Config" / "vex-rules.json", rules)
    r, s, rep = xrun(proj, scan)
    assert s["status"] != "FAIL", r.stdout + r.stderr
    md = (rep / "risk-assessment.md").read_text(encoding="utf-8")
    p1 = md.split("### 8.4 P1")[1].split("### 8.5")[0]
    row = next(ln for ln in p1.splitlines() if "| urllib3 (found only by Grype) |" in ln)
    assert "| YES (same CVE) |" in row and "same CVE 0.0800 (p0.800)" in row
    eu = next(ln for ln in p1.splitlines() if "| libeu9-tools (found only by Grype) |" in ln)
    assert "exploited: EUVD (ENISA EU KEV)" in eu
    assert s["exploitation"]["tiers"]["p1"] == 4 and s["counts"]["kev_open"] == 2
    rs = {x["id"]: x for x in s["vex"]["rules"]["rules"]}
    assert rs["R9"]["excluded_kev"] == 4


def test_rule13_falls_back_to_sbom_without_sbomgate(tmp_path):
    """沒有 scan/sbomgate.json：以 SBOM 的 cdx:pypi:versionSpecifiers（信心值 0.5、沒有實際解析的證據）判斷版本來自範圍 → 不成列、GAP、點名。"""
    sbom = copy.deepcopy(SBOM)
    sbom["components"].append({"type": "library", "name": "requests", "version": "2.0", "purl": "pkg:pypi/requests@2.0",
                               "properties": [{"name": "cdx:pypi:versionSpecifiers", "value": ">=2.0"}],
                               "evidence": {"identity": [{"field": "purl", "confidence": 0.5,
                                                          "methods": [{"technique": "manifest-analysis", "confidence": 0.5}]}]}})
    g = {"matches": GRYPE["matches"][:2] + [_pm("GHSA-j8r2-6x86-q33q", "pkg:pypi/requests@2.0", "requests", "2.0", rel=["CVE-2023-32681"])]}
    r, s, rep = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s", grype=g, sbom=sbom))
    assert (s["counts"]["grype_only_advisories"], s["counts"]["grype_version_unknown"]) == (0, 1)
    assert any("on requests 2.0 (VERSION_FROM_RANGE)" in d for d in s["documents"]["risk-assessment"]["detail"])
    assert s["documents"]["risk-assessment"]["status"] == "GAP"
    md = (rep / "risk-assessment.md").read_text(encoding="utf-8")
    assert not any(ln.startswith("| ") and "| requests" in ln for ln in md.splitlines())


def test_purl_less_match_does_not_cover_across_ecosystems(tmp_path):
    """沒有 purl 的 Grype 比對（再審查 L3）只和同一個類型、或同樣沒有 purl 的 DT 元件對上：npm 的 foo 1.0 不涵蓋 pypi 的 foo 1.0。"""
    pol = cr.policy_of({})
    fs = [finding("foo", "1.0", "CVE-2026-7301", "NVD", "HIGH", purl="pkg:npm/foo@1.0")]
    m_py = {"vulnerability": {"id": "CVE-2026-7301"}, "artifact": {"name": "foo", "version": "1.0", "type": "python"}}
    m_npm = {"vulnerability": {"id": "CVE-2026-7301"}, "artifact": {"name": "foo", "version": "1.0", "type": "npm"}}
    m_unk = {"vulnerability": {"id": "CVE-2026-7301"}, "artifact": {"name": "foo", "version": "1.0"}}
    g = {"matches": [m_py, m_npm, m_unk]}
    rows = cr.build_rows(fs, pol, cr.grype_index(g)[0], True)
    unc = [m for m, _ in cr.grype_uncovered(g, cr.dt_rows_of(rows))]
    assert unc == [m_py, m_unk]
    # 沒有 purl 的 DT 元件：沒有 purl、類型不明的比對對得上
    fs2 = [dict(finding("foo", "1.0", "CVE-2026-7301", "NVD", "HIGH"), component={"name": "foo", "version": "1.0"})]
    rows2 = cr.build_rows(fs2, pol, cr.grype_index(g)[0], True)
    assert [m for m, _ in cr.grype_uncovered({"matches": [m_unk]}, cr.dt_rows_of(rows2))] == []


def test_no_grype_no_sbomgate_does_not_load_sbomgate(tmp_path, monkeypatch):
    """再審查 L-a：沒有 Grype 結果、也沒有 sbomgate.json 時不需要規則 13 的 SBOM 退路（沒有 Grype 的比對要判斷）；sbomgate.py 載入不了也不 FAIL。"""
    def missing():
        raise cr.Fail("sbomgate.py missing")
    monkeypatch.setattr(cr, "sbomgatemod", missing)
    sbom = copy.deepcopy(SBOM)
    sbom["components"].append({"type": "library", "name": "requests", "version": "2.0", "purl": "pkg:pypi/requests@2.0",
                               "properties": [{"name": "cdx:pypi:versionSpecifiers", "value": ">=2.0"}]})
    scan = make_scan(tmp_path / "s", grype=None, sbom=sbom)
    proj = make_project(tmp_path / "p")
    cfg = json.loads((proj / "CRA" / "Config" / "config.json").read_text(encoding="utf-8"))
    s = cr.generate(proj, scan, tmp_path / "out", cfg, [])
    assert s["status"] != "FAIL" and s["counts"]["grype_version_unknown"] is None


def test_grype_only_severity_source_names_grype_not_dependency_track(tmp_path):
    """再審查 L-b：只有 Grype 的列沒有 DT 的 finding，嚴重度來源寫 Grype 的 namespace（Grype (nvd)），不寫 Dependency-Track。"""
    g = {"matches": GRYPE["matches"][:2] + [
        gmatch("CVE-2026-7401", DEB.format("libsev9", "1.0-1"), "libsev9", "1.0-1", sev="Low", nvd_score=9.8),
        _pm("GHSA-ssss-ssss-ssss", "pkg:npm/sevpkg@1.0", "sevpkg", "1.0", typ="npm")]}
    g["matches"][-1]["vulnerability"].update(severity="Critical", namespace="github:language:javascript")
    upri = {"schema": "sca-center-ubuntu-priority/1", "status": "OK", "mirror": {"fetched_utc": "2026-11-04T00:00:00Z"},
            "cves": {"CVE-2026-7401": {"priority": "low", "record": "UBUNTU-CVE-2026-7401"}}}
    scan = make_scan(tmp_path / "s", grype=g)
    write_json(scan / "scan" / "ubuntu-priority.json", upri)
    r, s, rep = run(make_project(tmp_path / "p"), scan)
    md = (rep / "risk-assessment.md").read_text(encoding="utf-8")
    deb = next(ln for ln in md.splitlines() if "| libsev9 (found only by Grype) |" in ln)
    assert "| Ubuntu priority (low); Grype (nvd) HIGH |" in deb and "Dependency-Track" not in deb
    npm = next(ln for ln in md.splitlines() if "| sevpkg (found only by Grype) |" in ln)
    assert "| CRITICAL | Grype (github) |" in npm



# ---------- 廠商核心（Grype、DT 都沒有核心的列；CVE 清單來自 Linux 核心 CNA 的版本比對）----------

VK = {"name": "linux-kernel", "version": "6.1.118", "purl": "pkg:generic/linux-kernel@6.1.118",
      "cpe": "cpe:2.3:o:linux:linux_kernel:6.1.118:*:*:*:*:*:*:*"}


def vendor_kernel_scan(tmp_path, euvd=None):
    sc = make_scan(tmp_path / "s", findings=DT_ONE, grype={"matches": []})
    write_json(sc / "meta.json", dict(META, digest=IMG, finished="2026-11-05T01:02:03Z"))
    write_json(sc / "scan" / "kernel-cve-list.json", {"schema": "sca-center-kernel-cna-version/1", "mirror": {"commit": "a" * 40}, "cves": [
        {"cve": "CVE-2026-8001", "verdict": "affected", "reason": "semver ranges"},
        {"cve": "CVE-2026-8002", "verdict": "affected", "reason": "semver ranges"},
        {"cve": "CVE-2026-8003", "verdict": "unknown", "reason": "no semver information"}]})
    k = kcfg([{"cve": "CVE-2026-8001", "decision": "affected", "detail": "x.c is built", "files": [{"path": "x.c", "built": True}]},
              {"cve": "CVE-2026-8002", "decision": "not_affected", "detail": "CONFIG_X is not set", "files": [{"path": "y.c", "built": False}]},
              {"cve": "CVE-2026-8003", "decision": "unknown", "detail": "header file"}])
    k["component"] = dict(VK)
    k["inputs"] = {"kernel_cves": 3, "cves_origin": "kernel-cna-version (kernel 6.1.118)"}
    write_json(sc / "scan" / "kernel-config.json", k)
    if euvd is not None:
        write_json(sc / "scan" / "euvd.json", euvd)
    return sc


def test_vendor_kernel_rows_from_cna_list(tmp_path):
    """Grype、DT 都沒有核心的列、有 CNA 版本比對的 CVE 清單與用了它的 kernel-config.json：核心的列、K1 的判定進 VEX；
    版本判斷不了（unknown）的列標「version could not be determined」，不寫成受影響；已被利用（EUVD）且受影響 → P1。"""
    eu = {"stage": "C-euvd", "status": "OK", "cves": {"CVE-2026-8001": {"in_euvd": True, "exploited": "yes", "kev_sources": ["cisa_kev"]}}}
    sc = vendor_kernel_scan(tmp_path, eu)
    r, s, rep = run(make_project(tmp_path / "p"), sc)
    assert s["status"] != "FAIL", r.stdout + r.stderr
    assert s["counts"]["kernel_cna"]["rows"] == 3 and s["counts"]["kernel_cna"]["version_unknown"] == 1
    t = (rep / "risk-assessment.md").read_text(encoding="utf-8") + (rep / "kernel-vulnerabilities.md").read_text(encoding="utf-8")
    assert "CVE-2026-8001" in t and "exploited: EUVD (CISA KEV)" in t and s["counts"]["p1"] == 1
    assert "version could not be determined (unknown), not shown as affected" in t and "KERNEL-CNA:CVE-2026-8001" in t
    v = json.loads((rep / "vex.cdx.json").read_text(encoding="utf-8"))["vulnerabilities"]
    by = {x["id"]: x["analysis"]["state"] for x in v if not _is_na(x)}
    # unknown 不當成沒問題，沒有判定的 VEX 陳述；A4（M7c-1）起它寫成 in_triage 加 NOT_ASSESSED（沒有評估），不是 not_affected
    assert by.get("CVE-2026-8002") == "not_affected" and "CVE-2026-8003" not in by
    assert {x["id"] for x in v if _is_na(x)} >= {"CVE-2026-8003"}
    assert s["counts"]["kernel"]["rows"] == 3 and s["counts"]["kernel"]["accepted"] >= 1


def test_vendor_kernel_rows_not_added_otherwise(tmp_path):
    """kernel-config.json 不是用這份清單 → 不加；已有核心的列（Grype／DT 的 Canonical 核心）→ 照舊，不加。"""
    sc = vendor_kernel_scan(tmp_path)
    k = json.loads((sc / "scan" / "kernel-config.json").read_text(encoding="utf-8"))
    del k["inputs"]["cves_origin"]
    write_json(sc / "scan" / "kernel-config.json", k)
    r, s, rep = run(make_project(tmp_path / "p"), sc)
    assert "kernel_cna" not in s["counts"] and "KERNEL-CNA" not in (rep / "risk-assessment.md").read_text(encoding="utf-8")
    sc2 = kernel_scan(tmp_path / "s2", findings=KFINDINGS, grype=KGRYPE)
    write_json(sc2 / "scan" / "kernel-cve-list.json", {"schema": "sca-center-kernel-cna-version/1", "cves": [{"cve": "CVE-2026-8001", "verdict": "affected"}]})
    k2 = kcfg([{"cve": "CVE-2026-8001", "decision": "affected", "detail": "x"}])
    k2["inputs"] = {"cves_origin": "kernel-cna-version (kernel 6.1.118)"}
    k2["component"] = dict(VK)
    write_json(sc2 / "scan" / "kernel-config.json", k2)
    r, s, rep = run(make_project(tmp_path / "p2"), sc2)
    assert "kernel_cna" not in s["counts"]


def test_vendor_kernel_rows_from_explicit_list(tmp_path):
    """KERNEL_CVES（明確給的清單）：沒有 kernel-cve-list.json，以 kernel-config.json 的 results 為準；核心的列照樣建立（不是 no_kernel），
    已被利用且受影響 → P1，K1 not_affected 進 VEX，元件欄標「版本沒有比對」。"""
    eu = {"stage": "C-euvd", "status": "OK", "cves": {"CVE-2026-8001": {"in_euvd": True, "exploited": "yes", "kev_sources": ["cisa_kev"]}}}
    sc = vendor_kernel_scan(tmp_path, eu)
    (sc / "scan" / "kernel-cve-list.json").unlink()
    k = json.loads((sc / "scan" / "kernel-config.json").read_text(encoding="utf-8"))
    k["inputs"]["cves_origin"] = "KERNEL_CVES（明確給的清單）"
    write_json(sc / "scan" / "kernel-config.json", k)
    r, s, rep = run(make_project(tmp_path / "p"), sc)
    assert s["status"] != "FAIL", r.stdout + r.stderr
    assert s["counts"]["kernel"]["section"] != "no_kernel" and s["counts"]["kernel"]["rows"] == 3 and s["counts"]["p1"] == 1
    assert s["counts"]["kernel_cna"]["rows"] == 3 and s["counts"]["kernel_cna"]["version_unknown"] == 0
    t = (rep / "risk-assessment.md").read_text(encoding="utf-8") + (rep / "kernel-vulnerabilities.md").read_text(encoding="utf-8")
    assert "explicit list (KERNEL_CVES), kernel version not compared" in t
    v = json.loads((rep / "vex.cdx.json").read_text(encoding="utf-8"))["vulnerabilities"]
    assert {x["id"]: x["analysis"]["state"] for x in v}.get("CVE-2026-8002") == "not_affected"
