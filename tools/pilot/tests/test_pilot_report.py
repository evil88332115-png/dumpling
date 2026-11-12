"""report.py 的單元測試（小型假資料）：不完整時不出現結論字樣、分類計數、Grype 與 DT 並列與不一致、版本未知、授權、HTML 自足。"""
import json
import re

import pytest

from pilot_fixtures import ALL_OK, FORBIDDEN, assert_no_conclusion, dfind, gmatch, make_out, report, run_report, visible_text

PY = "pkg:pypi/requests@2.19.0"


def test_gap_report_never_claims_no_vulnerabilities(tmp_path):
    out = make_out(tmp_path, [("B-sbom-cdxgen", "OK", "4 components"), ("C-grype", "OK", "0 matches（比對完成；不代表沒有其他弱點）"),
                              ("C-sbomgate", "GAP", "PARTIAL：COMPLETE 只表示…，不代表沒有弱點或安全。"), ("D-dt-findings", "NOT_RUN", "--no-upload")],
                   grype=[], gate={"sbom": {"status": "OK"}, "vulnerability_analysis": {"status": "PARTIAL", "reasons": ["依賴樹完整性未被宣告為 full"],
                                                                                         "notes": ["『有效 0 筆』不是沒有弱點的證據"]},
                                   "component_details": []})
    rep, page = run_report(out)
    assert rep["overall"] == "INCOMPLETE"
    assert_no_conclusion(page)
    assert "不代表沒有弱點或安全" in visible_text(page)        # 證據原樣顯示，不改寫
    assert "PASS" not in page
    # 非 OK 的階段在最前面（在弱點區之前）
    assert page.index("未完成或不完整的項目") < page.index("<h2>弱點</h2>")
    assert [s["stage"] for s in rep["incomplete"]] == ["C-sbomgate", "D-dt-findings"]   # GAP 排在 NOT_RUN 前
    assert "比對結果 0 筆" in page


@pytest.mark.parametrize("st", ["NOT_ASSESSED", "NOT_RUN", "GAP", "FAIL", "ATTENTION"])
def test_any_non_ok_stage_is_listed_first_and_overall_not_complete(tmp_path, st):
    out = make_out(tmp_path, ALL_OK + [("X-stage", st, "說明")], grype=[], findings=[])
    rep, page = run_report(out)
    assert rep["overall"] == ("FAIL" if st == "FAIL" else "INCOMPLETE")
    assert rep["incomplete"][0]["stage"] == "X-stage"
    assert "X-stage" in page[: page.index("<h2>弱點</h2>")]
    for w in FORBIDDEN:      # 階段說明不含這些字時，報告自己產生的文字一個都不可有（連否定句也沒有）
        assert w not in page


def test_all_ok_still_no_conclusion_words(tmp_path):
    rep, page = run_report(make_out(tmp_path, ALL_OK, grype=[], findings=[]))
    assert rep["overall"] == "COMPLETE"
    assert rep["incomplete"] == []
    for w in FORBIDDEN:
        assert w not in page


def test_unknown_status_value_counts_as_fail(tmp_path):
    rep, _ = run_report(make_out(tmp_path, ALL_OK + [("Z", "PASS", "")]))
    assert rep["overall"] == "FAIL"
    assert rep["incomplete"][0]["stage"] == "Z" and rep["incomplete"][0]["status"] == "FAIL"


def test_missing_status_file_is_incomplete(tmp_path):
    out = make_out(tmp_path, [])
    (out / "status.tsv").unlink()
    rep, page = run_report(out)
    assert rep["overall"] == "FAIL"
    assert "沒有 status.tsv" in page


def test_category_counts_per_tool(tmp_path):
    grype = [
        gmatch("CVE-2024-1", "libssl3", "3.0.1", "pkg:deb/debian/libssl3@3.0.1?arch=amd64&distro=debian-12", "deb", "Critical"),
        gmatch("CVE-2024-2", "libssl3", "3.0.1", "pkg:deb/debian/libssl3@3.0.1?arch=amd64&distro=debian-12", "deb", "Negligible"),
        gmatch("CVE-2026-109618", "php-cli", "8.4.26", "pkg:generic/php-cli@8.4.26", "binary", "Critical"),
        gmatch("GHSA-aaaa-bbbb-cccc", "requests", "2.19.0", PY, "python", "Medium"),
        gmatch("GHSA-dddd-eeee-ffff", "actions/checkout", "v2", "pkg:github/actions/checkout@v2", "github-action", "Unknown"),
    ]
    findings = [dfind("CVE-2026-109618", "php-cli", "8.4.26", "pkg:generic/php-cli@8.4.26", "CRITICAL")]
    sbom = {"components": [{"purl": "pkg:generic/php-cli@8.4.26", "properties": [{"name": "syft:package:type", "value": "binary"}]}]}
    rep, page = run_report(make_out(tmp_path, ALL_OK, grype=grype, findings=findings, sbom=sbom))
    c = rep["vulnerabilities"]["counts"]
    assert c["grype"]["作業系統套件"]["CRITICAL"] == 1 and c["grype"]["作業系統套件"]["NEGLIGIBLE"] == 1
    assert c["grype"]["執行檔"]["CRITICAL"] == 1
    assert c["grype"]["語言套件"]["MEDIUM"] == 1
    assert c["grype"]["其他"]["UNKNOWN"] == 1
    assert sum(sum(x.values()) for x in c["grype"].values()) == 5
    # DT 只有 purl（pkg:generic）：以 SBOM 的 syft:package:type=binary 分類為執行檔
    assert c["dt"]["執行檔"]["CRITICAL"] == 1
    assert sum(sum(x.values()) for x in c["dt"].values()) == 1
    for cat in ("作業系統套件", "語言套件", "執行檔", "其他"):
        assert cat in page


def test_grype_and_dt_side_by_side_with_discrepancies(tmp_path):
    grype = [
        gmatch("GHSA-x84v-xcm2-53pg", "requests", "2.19.0", PY, "python", "High", related=["CVE-2018-18074"], fix=["2.20.0"]),
        gmatch("GHSA-only-grype-0001", "requests", "2.19.0", PY, "python", "Low"),
    ]
    findings = [
        dfind("CVE-2018-18074", "requests", "2.19.0", PY, "MEDIUM", source="NVD"),   # 同一弱點（Grype 的 related），嚴重度不同
        dfind("PYSEC-2026-9999", "requests", "2.19.0", PY, "UNASSIGNED", source="OSV"),
    ]
    rep, page = run_report(make_out(tmp_path, ALL_OK, grype=grype, findings=findings))
    rows = {r["ids"][0]: r for r in rep["vulnerabilities"]["rows"]}
    both = rows["GHSA-x84v-xcm2-53pg"]
    assert both["grype"][0]["severity"] == "HIGH" and both["dt"][0]["severity"] == "MEDIUM"   # 兩邊都保留，不互相覆蓋
    assert "CVE-2018-18074" in both["aliases"]
    assert both["fix_versions"] == ["2.20.0"]
    assert any("嚴重度不同" in n for n in both["notes"])
    assert any(n.startswith("只有 Grype") for n in rows["GHSA-only-grype-0001"]["notes"])
    assert any(n.startswith("只有 DT") for n in rows["PYSEC-2026-9999"]["notes"])
    assert rep["vulnerabilities"]["discrepancy_rows"] == 3
    # 計數各自獨立：Grype 2 筆、DT 2 筆
    c = rep["vulnerabilities"]["counts"]
    assert sum(c["grype"]["語言套件"].values()) == 2 and sum(c["dt"]["語言套件"].values()) == 2
    assert c["grype"]["語言套件"]["HIGH"] == 1 and c["dt"]["語言套件"]["MEDIUM"] == 1
    assert "嚴重度不同" in page and "只有 DT" in page and "pkg:pypi/requests@2.19.0" in page


def test_dt_not_run_means_no_only_grype_notes(tmp_path):
    grype = [gmatch("GHSA-aaaa-bbbb-cccc", "requests", "2.19.0", PY, "python")]
    rep, page = run_report(make_out(tmp_path, [("C-grype", "OK", ""), ("D-dt-findings", "NOT_RUN", "--no-upload")], grype=grype))
    assert rep["vulnerabilities"]["counts"]["dt"] is None
    assert rep["vulnerabilities"]["rows"][0]["notes"] == []
    assert "沒有 DT 結果" in page


def test_grype_purl_qualifiers_match_dt_purl(tmp_path):
    p = "pkg:deb/debian/libssl3@3.0.1?arch=amd64&distro=debian-12"
    rep, _ = run_report(make_out(tmp_path, ALL_OK, grype=[gmatch("CVE-2024-1", "libssl3", "3.0.1", p, "deb")],
                                 findings=[dfind("CVE-2024-1", "libssl3", "3.0.1", "pkg:deb/debian/libssl3@3.0.1?arch=amd64&distro=debian-12")]))
    rows = rep["vulnerabilities"]["rows"]
    assert len(rows) == 1 and rows[0]["grype"] and rows[0]["dt"] and rows[0]["notes"] == []


def test_dt_source_package_findings_map_back_to_binaries(tmp_path):
    """DT 以原始碼套件（dt/deb-sources.json）比對到的紀錄，對回二進位套件，和 Grype 合成一列（不拆成只有 Grype／只有 DT）。"""
    D = "distro=ubuntu-24.04"
    b1 = f"pkg:deb/ubuntu/libfreerdp3-3@3.5.1-1?arch=arm64&upstream=freerdp3&{D}"
    b2 = f"pkg:deb/ubuntu/libwinpr3-3@3.5.1-1?arch=arm64&upstream=freerdp3&{D}"
    ssl = f"pkg:deb/ubuntu/libssl3t64@3.0.13-1?arch=arm64&upstream=openssl&{D}"
    out = make_out(tmp_path, ALL_OK + [("D-dt-deb-sources", "OK", "")],
                   grype=[gmatch("CVE-2026-1", "libfreerdp3-3", "3.5.1-1", b1, "deb"), gmatch("CVE-2026-1", "libwinpr3-3", "3.5.1-1", b2, "deb"),
                          gmatch("CVE-2026-2", "libssl3t64", "3.0.13-1", ssl, "deb"),
                          gmatch("CVE-2026-2", "openssl", "3.0.13-1", f"pkg:deb/ubuntu/openssl@3.0.13-1?arch=arm64&{D}", "deb")],
                   findings=[dfind("UBUNTU-CVE-2026-1", "freerdp3", "3.5.1-1", f"pkg:deb/ubuntu/freerdp3@3.5.1-1?arch=source&{D}", source="OSV"),
                             dfind("CVE-2026-2", "openssl", "3.0.13-1", f"pkg:deb/ubuntu/openssl@3.0.13-1?arch=arm64&{D}", source="OSV")])
    (out / "dt" / "deb-sources.json").write_text(json.dumps({
        "added": [{"purl": f"pkg:deb/ubuntu/freerdp3@3.5.1-1?arch=source&{D}", "binaries": "libfreerdp3-3, libwinpr3-3", "binary_purls": [b1, b2]}],
        "shared_sources": [{"purl": "pkg:deb/ubuntu/openssl@3.0.13-1", "binary_purls": [ssl]}]}), encoding="utf-8")
    rep, page = run_report(out)
    rows = {r["key"]: r for r in rep["vulnerabilities"]["rows"]}
    assert sorted(rows) == ["pkg:deb/ubuntu/libfreerdp3-3@3.5.1-1", "pkg:deb/ubuntu/libssl3t64@3.0.13-1",
                            "pkg:deb/ubuntu/libwinpr3-3@3.5.1-1", "pkg:deb/ubuntu/openssl@3.0.13-1"]
    for r in rows.values():
        assert r["grype"] and r["dt"] and r["notes"] == []
    assert rows["pkg:deb/ubuntu/libwinpr3-3@3.5.1-1"]["dt"][0]["via_source"] == "freerdp3"
    assert rows["pkg:deb/ubuntu/libwinpr3-3@3.5.1-1"]["ids"] == ["CVE-2026-1"]       # UBUNTU-CVE-2026-1 依命名規則對到 CVE
    assert "UBUNTU-CVE-2026-1" in rows["pkg:deb/ubuntu/libwinpr3-3@3.5.1-1"]["aliases"]
    assert "via_source" not in rows["pkg:deb/ubuntu/openssl@3.0.13-1"]["dt"][0]
    assert "以原始碼套件 freerdp3 比對" in page


def test_kev_then_epss_ordering(tmp_path):
    grype = [
        gmatch("CVE-A", "a", "1", "pkg:npm/a@1", "npm", "Critical", epss=0.01, pct=0.5),
        gmatch("CVE-B", "b", "1", "pkg:npm/b@1", "npm", "Low", epss=0.9, pct=0.99),
        gmatch("CVE-C", "c", "1", "pkg:npm/c@1", "npm", "Low", kev=True),
    ]
    rep, page = run_report(make_out(tmp_path, ALL_OK, grype=grype, findings=[]))
    assert [r["ids"][0] for r in rep["vulnerabilities"]["rows"]] == ["CVE-C", "CVE-B", "CVE-A"]
    assert "KEV" in page


def test_dt_kev_and_epss_fields(tmp_path):
    f = [dfind("CVE-2021-44228", "log4j-core", "2.14.1", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "CRITICAL", kev=True, epss=0.94, pct=0.999)]
    rep, _ = run_report(make_out(tmp_path, ALL_OK, grype=[], findings=f))
    r = rep["vulnerabilities"]["rows"][0]
    assert r["kev"] and r["epss"] == 0.94 and r["dt"][0]["kev"]
    assert any(n.startswith("只有 DT") for n in r["notes"])


def test_version_unknown_components_are_listed_and_excluded(tmp_path):
    gate = {"sbom": {"status": "OK"}, "vulnerability_analysis": {"status": "NOT_ASSESSED", "reasons": ["所有元件版本都未知"], "notes": []},
            "component_details": [{"name": "requests", "version": "2.0", "purl": "pkg:pypi/requests@2.0", "class": "VERSION_FROM_RANGE",
                                   "why": "帶有 cdx:pypi:versionSpecifiers='>=2.0'", "superseded_by_resolved": False}],
            "excluded_matches": [{"id": "GHSA-x84v-xcm2-53pg", "package": "requests", "version": "2.0", "excluded_reason": "VERSION_FROM_RANGE"}]}
    grype = [gmatch("GHSA-x84v-xcm2-53pg", "requests", "2.0", "pkg:pypi/requests@2.0", "python")]
    findings = [dfind("CVE-2018-18074", "requests", "2.0", "pkg:pypi/requests@2.0")]
    rep, page = run_report(make_out(tmp_path, [("C-sbomgate", "NOT_ASSESSED", "")], grype=grype, findings=findings, gate=gate))
    assert rep["vulnerabilities"]["rows"] == []                       # 不計入弱點
    vu = rep["version_unknown"]
    assert vu["components"][0]["class"] == "VERSION_FROM_RANGE"
    assert {(x["tool"], x["id"]) for x in vu["excluded_records"]} == {("grype", "GHSA-x84v-xcm2-53pg"), ("dt", "CVE-2018-18074")}
    assert "不做弱點比對" in page and "requests" in page
    assert_no_conclusion(page)


def test_licenses_distribution_and_unknown(tmp_path):
    comp = {"product": "demo:1", "packages": 4, "counts": {"error": 1, "warning": 0, "pass": 1, "no_license": 1, "not_assessed": 1},
            "rows": [{"package": "pkg:npm/a@1", "license_expression": "mit", "verdict": "pass", "unassessed_keys": []},
                     {"package": "pkg:npm/b@1", "license_expression": "", "verdict": "no_license", "unassessed_keys": []},
                     {"package": "pkg:npm/c@1", "license_expression": "wtfpl", "verdict": "not_assessed", "unassessed_keys": ["wtfpl"]},
                     {"package": "pkg:npm/d@1", "license_expression": "agpl-3.0", "verdict": "error", "unassessed_keys": []}]}
    rep, page = run_report(make_out(tmp_path, ALL_OK, grype=[], findings=[], comp=comp))
    lic = rep["licenses"]
    assert dict(map(tuple, lic["distribution"]))["（沒有授權資料）"] == 1
    assert {u["package"]: u["label"].split("（")[0] for u in lic["unknown"]} == {"pkg:npm/b@1": "unknown", "pkg:npm/c@1": "未評估"}
    assert lic["attention"][0]["package"] == "pkg:npm/d@1"
    assert "unknown（沒有授權資料）" in page and "wtfpl" in page


def test_links_only_http_and_escaped(tmp_path):
    meta = {"dt_project_url": "http://dt.local/projects/u-1", "dejacode_product_url": "javascript:alert(1)", "name": "<b>x</b>"}
    rep, page = run_report(make_out(tmp_path, ALL_OK, grype=[], findings=[], meta=meta))
    assert "dt_project_url" in rep["links"] and "dejacode_product_url" not in rep["links"]
    assert 'href="http://dt.local/projects/u-1"' in page
    assert "javascript:" not in page and "<b>x</b>" not in page and "&lt;b&gt;x&lt;/b&gt;" in page


def test_html_is_self_contained_with_dark_mode(tmp_path):
    rep, page = run_report(make_out(tmp_path, ALL_OK, grype=[gmatch("CVE-1", "a", "1", "pkg:npm/a@1", "npm")], findings=[]))
    assert "prefers-color-scheme: dark" in page
    assert "Content-Security-Policy" in page and "default-src 'none'" in page
    assert not re.search(r"<(script|link|img|iframe)\b", page)
    assert not re.search(r'\bsrc="', page)
    assert page.startswith("<!doctype html>") and page.rstrip().endswith("</html>")


def test_govulncheck_levels_and_alias_bridge(tmp_path):
    gv = [{"config": {"scanner_name": "govulncheck"}},
          {"osv": {"id": "GO-2021-0113", "aliases": ["CVE-2021-38561", "GHSA-ppp9-7jff-5vj2"]}},
          {"finding": {"osv": "GO-2021-0113", "fixed_version": "v0.3.7", "trace": [{"module": "golang.org/x/text", "version": "v0.3.6"}]}},
          {"finding": {"osv": "GO-2021-0113", "fixed_version": "v0.3.7",
                       "trace": [{"module": "golang.org/x/text", "version": "v0.3.6", "package": "golang.org/x/text/language", "function": "Parse"}]}}]
    k = "pkg:golang/golang.org/x/text@v0.3.6"
    grype = [gmatch("GHSA-ppp9-7jff-5vj2", "golang.org/x/text", "v0.3.6", k, "go-module", related=["CVE-2021-38561"])]
    findings = [dfind("GO-2021-0113", "golang.org/x/text", "v0.3.6", k, source="OSV")]   # DT 這筆沒有別名：靠 govulncheck 的 OSV 別名對應
    rep, page = run_report(make_out(tmp_path, ALL_OK, grype=grype, findings=findings, govuln=gv))
    assert rep["govulncheck"][0]["level"] == "呼叫到受影響函式"
    rows = rep["vulnerabilities"]["rows"]
    assert len(rows) == 1 and rows[0]["grype"] and rows[0]["dt"] and rows[0]["govulncheck"] == "呼叫到受影響函式"


def test_dt_record_without_alias_is_flagged_not_merged(tmp_path):
    grype = [gmatch("GHSA-x84v-xcm2-53pg", "requests", "2.19.0", PY, "python", related=["CVE-2018-18074"])]
    findings = [dfind("PYSEC-2018-28", "requests", "2.19.0", PY, source="OSV")]
    rep, _ = run_report(make_out(tmp_path, ALL_OK, grype=grype, findings=findings))
    rows = rep["vulnerabilities"]["rows"]
    assert len(rows) == 2
    dt_only = [r for r in rows if r["dt"]][0]
    assert "沒有別名資料" in dt_only["notes"][0]


def test_cli_missing_dir_returns_3(tmp_path):
    assert report.main(["--out", str(tmp_path / "nope")]) == 3


def test_unparseable_input_is_reported_not_crash(tmp_path):
    out = make_out(tmp_path, ALL_OK)
    (out / "scan" / "grype.json").write_text("{broken", encoding="utf-8")
    rep, page = run_report(out)
    assert rep["overall"] == "FAIL"
    assert rep["incomplete"][0]["stage"] == "R-report-input" and "grype.json" in rep["incomplete"][0]["detail"]
    assert rep["vulnerabilities"]["tools_run"]["grype"] is False


def test_stage_detail_is_shown_verbatim(tmp_path):
    out = make_out(tmp_path, [("C-sbomgate", "GAP", "不代表沒有弱點；『有效 0 筆』不是沒有弱點的證據；0 個元件（不可當作沒有弱點）")])
    rep, page = run_report(out)
    assert rep["stages"][0]["detail"].startswith("不代表沒有弱點")
    assert "不代表沒有弱點；『有效 0 筆』不是沒有弱點的證據" in visible_text(page)   # 不改寫證據
    assert_no_conclusion(page)                                                      # 否定句型放行


@pytest.mark.parametrize("detail", ["掃描完成，沒有弱點", "結果：無弱點", "驗收通過"])
def test_affirmative_conclusion_in_stage_detail_is_caught(tmp_path, detail):
    rep, page = run_report(make_out(tmp_path, [("C-x", "OK", detail)]))
    assert report.conclusion_hits(visible_text(page)), detail


def test_conclusion_hits_negation_rules():
    assert report.conclusion_hits("不代表沒有弱點") == []
    assert report.conclusion_hits("不可當作沒有弱點，也不等於無弱點") == []
    assert report.conclusion_hits("不是沒有弱點的證據") == []
    assert len(report.conclusion_hits("這個專案沒有弱點")) == 1
    assert len(report.conclusion_hits("不代表沒有弱點；但這裡沒有弱點")) == 1
    assert len(report.conclusion_hits("整體通過")) == 1
    # 複審加入的字樣；否定句型以子句為範圍（「不代表沒有弱點或安全」整句放行）
    assert report.conclusion_hits("COMPLETE 只表示比對完成，不代表沒有弱點或安全。") == []
    assert report.conclusion_hits("只表示比對完成，不代表安全") == []
    for t in ("未發現弱點", "掃描結果：沒有發現弱點", "零弱點", "沒有問題", "此映像安全", "No vulnerabilities found", "no vulnerabilities found."):
        assert report.conclusion_hits(t), t
    assert report.conclusion_hits("This does not mean no vulnerabilities found") == []
    assert len(report.conclusion_hits("不代表安全；這個映像安全")) == 1


def test_self_no_version_matches_are_excluded(tmp_path):
    """sbomgate 的 SELF_NO_VERSION（Grype 對專案本身、沒有版本的 purl 的比對）不可列進弱點表或計數（koel 8 筆，2026-10-24 判讀）。"""
    gate = {"sbom": {"status": "OK"}, "vulnerability_analysis": {"status": "COMPLETE", "reasons": [], "notes": []}, "component_details": [],
            "excluded_matches": [{"id": "GHSA-r37h-j483-cjjm", "package": "phanan/koel", "purl": "pkg:composer/phanan/koel", "version": None,
                                  "excluded_reason": "SELF_NO_VERSION", "self_source": "metadata.component"}]}
    grype = [gmatch("GHSA-r37h-j483-cjjm", "phanan/koel", "", "pkg:composer/phanan/koel", "php-composer"),
             gmatch("GHSA-gv7v-rgg6-548h", "laravel/framework", "v8.25.0", "pkg:composer/laravel/framework@v8.25.0", "php-composer"),
             # 同一個 ID、但套件有版本：不可被排除
             gmatch("GHSA-r37h-j483-cjjm", "phanan/koel", "5.0.0", "pkg:composer/phanan/koel@5.0.0", "php-composer")]
    rep, page = run_report(make_out(tmp_path, ALL_OK, grype=grype, findings=[], gate=gate))
    rows = rep["vulnerabilities"]["rows"]
    assert {(r["name"], r["version"]) for r in rows} == {("laravel/framework", "v8.25.0"), ("phanan/koel", "5.0.0")}
    assert sum(sum(c.values()) for c in rep["vulnerabilities"]["counts"]["grype"].values()) == 2
    ex = rep["version_unknown"]["excluded_records"]
    assert [(x["id"], x["purl"], x["reason"]) for x in ex] == [("GHSA-r37h-j483-cjjm", "pkg:composer/phanan/koel", "專案本身、沒有版本（SELF_NO_VERSION）")]
    assert "SELF_NO_VERSION" in page
    assert_no_conclusion(page)


def test_self_no_version_edges(tmp_path):
    """qualifiers、gate 版本為空字串、同一 ID 在兩個沒有版本的 purl、DT 在同一個 purl 上有 finding（備註不可寫「只有 DT」）。"""
    gate = {"sbom": {"status": "OK"}, "vulnerability_analysis": {"status": "COMPLETE", "reasons": [], "notes": []}, "component_details": [],
            "excluded_matches": [
                {"id": "GHSA-1", "purl": "pkg:composer/acme/app?repository_url=x", "version": "", "excluded_reason": "SELF_NO_VERSION"},
                {"id": "GHSA-1", "purl": "pkg:npm/acme-app", "version": None, "excluded_reason": "SELF_NO_VERSION"}]}
    grype = [gmatch("GHSA-1", "acme/app", "", "pkg:composer/acme/app?repository_url=x", "php-composer"),
             gmatch("GHSA-1", "acme-app", "", "pkg:npm/acme-app", "npm"),
             gmatch("GHSA-1", "other", "", "pkg:npm/other", "npm")]           # 不是專案本身：保留
    findings = [dfind("GHSA-1", "acme-app", "", "pkg:npm/acme-app")]
    rep, page = run_report(make_out(tmp_path, ALL_OK, grype=grype, findings=findings, gate=gate))
    rows = rep["vulnerabilities"]["rows"]
    assert {(r["name"], bool(r["grype"]), bool(r["dt"])) for r in rows} == {("other", True, False), ("acme-app", False, True)}
    dtrow = next(r for r in rows if r["name"] == "acme-app")
    assert not any(n.startswith("只有 DT") for n in dtrow["notes"]) and any("SELF_NO_VERSION" in n for n in dtrow["notes"])
    assert len(rep["version_unknown"]["excluded_records"]) == 2
    assert "排除、未計入的比對（原因見表）" in page and "因此排除" not in page


def test_no_sbomgate_does_not_claim_exclusion(tmp_path):
    rep, page = run_report(make_out(tmp_path, ALL_OK, grype=[gmatch("CVE-1", "a", "1", "pkg:npm/a@1", "npm")], findings=[]))
    assert rep["version_unknown"]["sbomgate"] is None
    assert "沒有 sbomgate 結果，未能排除版本未知元件的比對" in page and "比對紀錄 0 筆" not in page
