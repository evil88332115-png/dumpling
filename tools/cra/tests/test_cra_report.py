"""cra_report.py 的測試：合成的小型 sca-scan 輸出（欄位格式照 DT findings 與 Grype 結果的實際形狀）。"""
import json
import lzma
import os
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import cra_report as cr  # noqa: E402

CLI = HERE.parent / "cra_report.py"
EXAMPLE = json.loads((HERE.parent / "config.example.json").read_text(encoding="utf-8"))
EXAMPLE["sbom"].pop("own_software", None)   # 自有軟體要 own-software.json（test_own_software.py 測）；這裡共用的範例不含
MIN_CFG = {"schema_version": 1, "manufacturer": {"name": "Example Co."}, "product": {"name": "EX-J100"}}
OK_STAGES = ["B-sbom-syft", "C-sbomgate", "C-upload-sbom", "D-dt-data-sources", "D-dt-kev-sources", "D-dt-osv-coverage",
             "D-dt-vuln-analysis", "D-dt-findings", "C-grype-db", "C-grype"]
DEB = "pkg:deb/ubuntu/{}@{}?arch=arm64&distro=ubuntu-24.04"


def finding(name, version, vid, source="NVD", severity="MEDIUM", aliases=(), kev=False, epss=None, purl=None, analysis=None, cvss=5.0):
    v = {"source": source, "vulnId": vid, "severity": severity, "cvssV3BaseScore": cvss, "isKev": kev, "aliases": list(aliases)}
    if epss is not None:
        v.update(epssScore=epss / 10, epssPercentile=epss)
    return {"component": {"name": name, "version": version, "purl": purl or DEB.format(name, version)},
            "vulnerability": v, "analysis": analysis or {"isSuppressed": False}}


FINDINGS = [
    # 同一個 CVE 經 GHSA 與 PYSEC 兩筆（別名互指）→ 一列；KEV → P1
    finding("brotli", "1.1.0", "GHSA-9v8h-qqgm-4m35", "GITHUB", "CRITICAL", [{"cveId": "CVE-2026-111497"}, {"osvId": "PYSEC-2026-4322"}],
            kev=True, epss=0.99, purl="pkg:pypi/brotli@1.1.0"),
    finding("brotli", "1.1.0", "PYSEC-2026-4322", "OSV", "CRITICAL", [{"cveId": "CVE-2026-111497"}, {"ghsaId": "GHSA-9v8h-qqgm-4m35"}],
            kev=True, epss=0.99, purl="pkg:pypi/brotli@1.1.0"),
    finding("paramiko", "2.12.0", "GHSA-45x7-px36-x8w8", "GITHUB", "MEDIUM", [{"cveId": "CVE-2023-48795"}], epss=0.95,
            purl="pkg:pypi/paramiko@2.12.0"),                                                             # EPSS ≥ 0.9 → P1
    finding("accountsservice", "23.13.9-2ubuntu6", "UBUNTU-CVE-2026-61897", "OSV", "HIGH"),            # → CVE-2026-61897, P2
    finding("openssl", "3.0.13-0ubuntu3.11", "CVE-2025-0003", "NVD", "LOW", epss=0.2),                 # P3
    finding("openssl", "3.0.13-0ubuntu3.12", "CVE-2025-0003", "NVD", "LOW"),                           # 不同版本 → 另一列
    finding("libfoo1", "1.0-1", "CVE-2025-0004", "NVD", "CRITICAL",
            analysis={"isSuppressed": True, "state": "NOT_AFFECTED", "justification": "CODE_NOT_REACHABLE", "details": "feature disabled"}),
    finding("libbar1", "2.0-1", "CVE-2025-0005", "NVD", "HIGH", analysis={"isSuppressed": False, "state": "FALSE_POSITIVE"}),
    # 同一個 CVE 兩筆，只有一筆 suppressed → 不算 accepted
    finding("libbaz1", "3.0-1", "CVE-2025-0006", "NVD", "HIGH", analysis={"isSuppressed": True}),
    finding("libbaz1", "3.0-1", "UBUNTU-CVE-2025-0006", "OSV", "HIGH"),
    finding("tool", "0.1", "GHSA-aaaa-bbbb-cccc", "GITHUB", "UNASSIGNED", purl="pkg:golang/example.com/tool@0.1"),   # 沒有 CVE
]
GRYPE = {"matches": [
    {"vulnerability": {"id": "GHSA-9v8h-qqgm-4m35", "fix": {"state": "fixed", "versions": ["1.2.1"]}},
     "relatedVulnerabilities": [{"id": "CVE-2026-111497"}], "artifact": {"name": "brotli", "version": "1.1.0", "type": "python"}},
    {"vulnerability": {"id": "CVE-2026-61897", "fix": {"state": "not-fixed", "versions": []}},
     "relatedVulnerabilities": [{"id": "CVE-2026-61897"}], "artifact": {"name": "accountsservice", "version": "23.13.9-2ubuntu6", "type": "deb"}},
    {"vulnerability": {"id": "CVE-2025-9999", "fix": {"state": "wont-fix", "versions": []}},       # DT 沒有 → 交叉核對
     "relatedVulnerabilities": [], "artifact": {"name": "libsrc-bin", "version": "1.0", "type": "deb"}},
]}
SBOM = {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": "urn:uuid:1", "metadata": {"tools": {"components": [{"name": "syft", "version": "1.55.0"}]}},
        "components": [{"type": "library", "name": "brotli", "version": "1.1.0", "purl": "pkg:pypi/brotli@1.1.0"},
                       {"type": "library", "name": "openssl", "version": "3.0.13-0ubuntu3.11", "purl": DEB.format("openssl", "3.0.13-0ubuntu3.11"),
                        "components": [{"type": "library", "name": "nested", "version": "1"}]},
                       {"type": "operating-system", "name": "ubuntu", "version": "24.04"},
                       {"type": "file", "name": "/etc/passwd"}]}
META = {"name": "jetson-r39.2.1-base", "version": "sha256:abc", "mode": "image", "dt_version": "5.2.0", "tools": {"grype": "0.121.0"}}


def write_json(p, obj, xz=False):
    p.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(obj).encode()
    if xz:
        Path(str(p) + ".xz").write_bytes(lzma.compress(data))
    else:
        p.write_bytes(data)


def make_scan(d, findings=FINDINGS, grype=GRYPE, sbom=SBOM, meta=META, stages=None, xz=False):
    for rel, obj in (("dt/findings.json", findings), ("scan/grype.json", grype), ("sbom/sbom.cdx.json", sbom), ("meta.json", meta)):
        if obj is not None:
            write_json(d / rel, obj, xz=xz and rel != "meta.json")
    if stages is not False:
        st = dict.fromkeys(OK_STAGES, "OK")
        st.update(stages or {})
        (d / "status.tsv").write_text("stage\tstatus\tdetail\n" + "".join(f"{k}\t{v}\tdetail of {k}\n" for k, v in st.items()), encoding="utf-8")
    return d


def make_project(d, cfg=None, templates=None):
    write_json(d / "CRA" / "Config" / "config.json", EXAMPLE if cfg is None else cfg)
    for name, text in (templates or {}).items():
        (d / "CRA" / "templates").mkdir(parents=True, exist_ok=True)
        (d / "CRA" / "templates" / f"{name}.md").write_text(text, encoding="utf-8")
    return d


def run(project, scan, *extra):
    # 不受主機上的公司共用設定（/etc/sca-gitlab/company.json、CRA_COMPANY_CONFIG）影響
    env = dict(os.environ, CRA_COMPANY_CONFIG="none")
    r = subprocess.run([sys.executable, "-I", str(CLI), "--project", str(project), "--scan", str(scan), *extra],
                       capture_output=True, text=True, timeout=60, env=env)
    reports = project / "CRA" / "Reports"
    summary = json.loads((reports / "summary.json").read_text(encoding="utf-8")) if (reports / "summary.json").exists() else None
    return r, summary, reports


def clean_security(base):
    """掃描資料夾旁邊放三種安全測試都有、沒有待檢視項目的結果（<base>/image-check、<base>/board-test）：
    沒有這些時風險評估的安全測試是 NOT RUN（ATTENTION），要測「全部 OK」的測試用這個。"""
    write_json(base / "image-check" / "image-check.json", {"schema": "sca-center-image-check/1", "tool_version": "t", "status": "OK",
                                                           "generated": "2026-11-03T00:00:00Z", "findings": [], "coverage": {"counts": {}}})
    write_json(base / "board-test" / "board-test.json", {
        "schema": "sca-center-board-test/1", "tool_version": "t", "generated": "2026-11-03T00:00:00Z", "findings": [], "notes": [],
        "runs": [{"stem": "board-test-exdev-20261103T000000Z", "kind": "board", "current": True, "time": "2026-11-03T00:00:00Z",
                  "archive": {"name": "board-test-exdev-20261103T000000Z.tar.gz", "sha256": "0" * 64}, "files": [], "notes": []},
                 {"stem": "board-net-192.0.2.2-20261103T000000Z", "kind": "network", "current": True, "time": "2026-11-03T00:00:00Z",
                  "archive": {"name": "board-net-192.0.2.2-20261103T000000Z.tar.gz", "sha256": "0" * 64}, "files": [], "notes": []}]})
    return base


@pytest.fixture
def env(tmp_path):
    return make_project(tmp_path / "proj"), make_scan(tmp_path / "scan")


def row_of(rows, rid, comp=None):
    got = [r for r in rows if r["id"] == rid and (comp is None or r["component"] == comp)]
    assert len(got) == 1, (rid, comp, got)
    return got[0]


# ---------- 設定 ----------

def test_example_config_valid_and_complete():
    errors, warnings = cr.validate(EXAMPLE)
    assert errors == [] and warnings == []
    assert not [v for v in cr.report_fields(EXAMPLE).values() if isinstance(v, cr.Missing)]


def test_example_config_valid_with_jsonschema():
    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.Draft202012Validator.check_schema(cr.SCHEMA)
    jsonschema.validate(EXAMPLE, cr.SCHEMA)
    jsonschema.validate(cr.SCHEMA["properties"]["vulnerability_policy"]["default"], cr.SCHEMA["properties"]["vulnerability_policy"] | {"$defs": cr.SCHEMA["$defs"]})


@pytest.mark.parametrize("cfg,msg", [
    ({"schema_version": 1, "product": {"name": "x"}}, "manufacturer：必填"),
    ({"schema_version": 1, "manufacturer": {"name": ""}, "product": {"name": "x"}}, "manufacturer.name：必填"),
    (dict(MIN_CFG, product={"name": 3}), "product.name：型別應為 string"),
    (dict(MIN_CFG, support={"end_date": "2031-13"}), "support.end_date：格式不符"),
    (dict(MIN_CFG, schema_version=2), "schema_version：只能是"),
    (dict(MIN_CFG, scan={"mode": "git"}), "scan.mode：只能是"),
    (dict(MIN_CFG, vulnerability_policy={"tiers": {"p1": {"epss_percentile_min": 1.5}}}), "超出範圍"),
    (dict(MIN_CFG, vulnerability_policy={"tiers": {"p2": {"severities": ["SEVERE"]}}}), "severities[0]：只能是"),
])
def test_config_errors(cfg, msg):
    errors, _ = cr.validate(cfg)
    assert any(msg in e for e in errors), errors


def test_unknown_key_is_warning_not_error():
    errors, warnings = cr.validate(dict(MIN_CFG, product={"name": "x", "modle": "typo"}))
    assert errors == [] and warnings == ["product.modle：schema 沒有這個鍵（忽略；是否拼錯？）"]


def test_missing_required_fails_cli(tmp_path):
    proj = make_project(tmp_path / "proj", {"schema_version": 1, "product": {"name": "x"}})
    r, s, reports = run(proj, make_scan(tmp_path / "scan"))
    assert r.returncode == 1 and r.stdout.startswith("FAIL\t") and "manufacturer：必填" in r.stdout
    assert s["status"] == "FAIL" and not (reports / "risk-assessment.md").exists()


def test_missing_config_file_fails(tmp_path):
    (tmp_path / "proj").mkdir()
    r, s, _ = run(tmp_path / "proj", make_scan(tmp_path / "scan"))
    assert r.returncode == 1 and "找不到" in r.stdout and s["status"] == "FAIL"


def test_bad_args_exit_64(tmp_path):
    r = subprocess.run([sys.executable, "-I", str(CLI), "--project", str(tmp_path / "nope"), "--scan", str(tmp_path)],
                       capture_output=True, text=True)
    assert r.returncode == 64
    r = subprocess.run([sys.executable, "-I", str(CLI), "--project", str(tmp_path)], capture_output=True, text=True)
    assert r.returncode == 64


def test_optional_missing_marked_to_be_completed(tmp_path):
    proj = make_project(tmp_path / "proj", MIN_CFG)
    r, s, reports = run(proj, make_scan(tmp_path / "scan"))
    ui = (reports / "user-information.md").read_text(encoding="utf-8")
    assert "**TO BE COMPLETED** (`support.end_date`)" in ui and "**TO BE COMPLETED** (`instructions.disable_automatic_updates`)" in ui
    d = s["documents"]["user-information"]
    assert d["status"] == "GAP" and "support.end_date" in d["missing_fields"] and "manufacturer.name" not in d["missing_fields"]
    assert "sbom.availability" in s["missing_fields"] and r.returncode == 2
    assert "user-information GAP" in r.stdout


# ---------- 範本 ----------

def test_render_placeholders_lists_and_missing():
    ctx = {"a.b": "x", "l": ["one", "two"], "m": cr.Missing("m"), "n": 3}
    out, miss = cr.render("{{a.b}}|{{ n }}|{{ m }}\n{{ l }}", ctx, "t")
    assert out == "x|3|**TO BE COMPLETED** (`m`)\n- one\n- two" and miss == ["m"]


def test_unknown_placeholder_fails():
    with pytest.raises(cr.Fail, match="不認得的 placeholder：nope.x"):
        cr.render("ok {{ a }} {{ nope.x }}", {"a": 1}, "t")


def test_project_template_override(tmp_path):
    proj = make_project(tmp_path / "proj", templates={"sbom": "# Our SBOM\nProduct {{ product.name }} has {{ bom.packages }} packages.\n"})
    r, s, reports = run(proj, make_scan(tmp_path / "scan"))
    assert (reports / "sbom.md").read_text(encoding="utf-8") == f"# Our SBOM\nProduct {EXAMPLE['product']['name']} has 4 packages.\n"
    assert s["documents"]["sbom"]["template"] == "project" and s["documents"]["risk-assessment"]["template"] == "builtin"


def test_project_template_unknown_placeholder_fails_cli(tmp_path):
    proj = make_project(tmp_path / "proj", templates={"risk-assessment": "{{ product.nmae }}"})
    r, s, reports = run(proj, make_scan(tmp_path / "scan"))
    assert r.returncode == 1 and "product.nmae" in r.stdout and s["status"] == "FAIL"
    assert not (reports / "sbom.md").exists()      # 全部範本成功才寫檔


def test_builtin_templates_only_use_known_placeholders(env):
    proj, scan = env
    r, s, reports = run(proj, scan)
    for fn in cr.DOCS.values():
        assert "{{" not in (reports / fn).read_text(encoding="utf-8")


# ---------- 優先級、別名、去重 ----------

def rows_for(cfg=MIN_CFG, findings=FINDINGS, grype=GRYPE):
    idx, _ = cr.grype_index(grype)
    return cr.build_rows(findings, cr.policy_of(cfg), idx, grype is not None)


def test_kev_follows_the_cve_to_other_rows():
    """DT 只在 NVD／GitHub 的紀錄帶 isKev：同一個 CVE 在 Ubuntu 原始碼套件上的列（UBUNTU-CVE-…）也要算 KEV → P1，規則不套用。"""
    deb = finding("brotli", "1.1.0-2build2", "UBUNTU-CVE-2026-111497", "OSV", "CRITICAL", [{"cveId": "CVE-2026-111497"}], cvss=9.8,
                  purl="pkg:deb/ubuntu/brotli@1.1.0-2build2?arch=source&distro=ubuntu-24.04")
    other = finding("zlib", "1.3", "UBUNTU-CVE-2026-99999", "OSV", "LOW", [{"cveId": "CVE-2026-99999"}])
    rows = rows_for(findings=FINDINGS + [deb, other])
    d = next(r for r in rows if r["id"] == "CVE-2026-111497" and r["purl"].startswith("pkg:deb/"))
    assert d["kev"] is True and d.get("kev_by_cve") is True and d["tier"] == "p1"
    p = next(r for r in rows if r["id"] == "CVE-2026-111497" and r["purl"].startswith("pkg:pypi/"))
    assert p["kev"] is True and not p.get("kev_by_cve")
    assert row_of(rows, "CVE-2026-99999")["kev"] is False
    assert cr.kev_text(d) == "YES (same CVE)" and cr.kev_text(p) == "YES"
    # 一列併了兩個 CVE（GHSA 別名 A、B），只有 A 的 NVD 紀錄在 KEV：B 的其他列不能變成 KEV
    ghsa = finding("lib", "1.0", "GHSA-xxxx-yyyy-zzzz", "GITHUB", "HIGH", [{"cveId": "CVE-2026-0001"}, {"cveId": "CVE-2026-0002"}],
                   purl="pkg:pypi/lib@1.0")
    nvd = finding("lib", "1.0", "CVE-2026-0001", "NVD", "HIGH", kev=True, purl="pkg:pypi/lib@1.0")
    ub = finding("other", "2.0", "UBUNTU-CVE-2026-0002", "OSV", "LOW", [{"cveId": "CVE-2026-0002"}])
    rows = rows_for(findings=[ghsa, nvd, ub])
    assert next(r for r in rows if r["component"] == "other")["kev"] is False



def test_grype_kev_cves():
    g = {"matches": [
        {"vulnerability": {"id": "UBUNTU-CVE-2025-0102", "knownExploited": [{"cve": "CVE-2025-0102", "knownRansomwareCampaignUse": "Unknown"}]}},
        {"vulnerability": {"id": "CVE-2025-0300", "knownExploited": [{}]}},                     # 條目沒寫 cve → 比對的主編號
        {"vulnerability": {"id": "GHSA-aaaa-bbbb-cccc", "knownExploited": [{"vendorProject": "x"}]},
         "relatedVulnerabilities": [{"id": "CVE-2025-0301"}]},                                  # 再沒有才用 related
        {"vulnerability": {"id": "CVE-2025-0302", "knownExploited": []}, "relatedVulnerabilities": [{"id": "CVE-2025-0303"}]},
        {"vulnerability": {"id": "CVE-2025-0304"}},
        "not a match", {"vulnerability": None},
    ]}
    assert cr.grype_kev(g) == {"CVE-2025-0102", "CVE-2025-0300", "CVE-2025-0301"}
    assert cr.grype_kev(None) == set() and cr.grype_kev({"matches": None}) == set()


def test_kev_text_names_every_source():
    assert cr.kev_text({"kev": False}) == "no"
    assert cr.kev_text({"kev": True, "kev_sources": ["DT"]}) == "YES"
    assert cr.kev_text({"kev": True, "kev_sources": ["Grype"]}) == "YES (Grype)"
    assert cr.kev_text({"kev": True, "kev_sources": ["same CVE", "Grype"]}) == "YES (same CVE; Grype)"
    assert cr.kev_text({"kev": True, "kev_sources": ["DT", "Grype"]}) == "YES (DT; Grype)"
    assert cr.kev_text({"kev": True, "kev_by_cve": True}) == "YES (same CVE)"            # 舊的列（沒有 kev_sources）


def test_grype_kev_makes_a_dt_row_without_iskev_p1():
    """核心的 DT finding 是 OSV 的 UBUNTU-CVE-… 紀錄（沒有 isKev），Grype 的同一個 CVE 是 KEV → P1、計入未處理的 KEV。"""
    ub = finding("linux-nvidia-tegra", "6.8.0-1021.21", "UBUNTU-CVE-2025-0102", "OSV", "HIGH")
    g = {"matches": [{"vulnerability": {"id": "CVE-2025-0102", "knownExploited": [{"cve": "CVE-2025-0102"}]}}]}
    idx, _ = cr.grype_index(g)
    pol = cr.policy_of(MIN_CFG)
    r = cr.build_rows([ub], pol, idx, True)[0]
    assert (r["kev"], r["tier"]) == (False, "p2")                                       # 只看 DT：原本的錯誤
    r = cr.build_rows([ub], pol, idx, True, kev_more={c: {"Grype"} for c in cr.grype_kev(g)})[0]
    assert (r["kev"], r["tier"], r["kev_sources"], cr.kev_text(r)) == (True, "p1", ["Grype"], "YES (Grype)")
    assert not r.get("kev_by_cve") and cr.tally([r])["kev_open"] == 1


def test_alias_mapping_and_dedupe():
    rows = rows_for()
    b = row_of(rows, "CVE-2026-111497")
    assert b["source_ids"] == ["GITHUB:GHSA-9v8h-qqgm-4m35", "OSV:PYSEC-2026-4322"] and b["cves"] == ["CVE-2026-111497"]
    assert row_of(rows, "CVE-2026-61897")["source_ids"] == ["OSV:UBUNTU-CVE-2026-61897"]
    assert {r["version"] for r in rows if r["id"] == "CVE-2025-0003"} == {"3.0.13-0ubuntu3.11", "3.0.13-0ubuntu3.12"}
    assert row_of(rows, "CVE-2025-0006")["source_ids"] == ["NVD:CVE-2025-0006", "OSV:UBUNTU-CVE-2025-0006"]
    assert row_of(rows, "GHSA-aaaa-bbbb-cccc")["cves"] == []
    assert len(rows) == len(FINDINGS) - 2


def test_priority_tiers_default_policy():
    rows = rows_for()
    tiers = {(r["id"], r["version"]): r["tier"] for r in rows}
    assert tiers[("CVE-2026-111497", "1.1.0")] == "p1"              # KEV
    assert tiers[("CVE-2023-48795", "2.12.0")] == "p1"              # EPSS percentile 0.95
    assert tiers[("CVE-2026-61897", "23.13.9-2ubuntu6")] == "p2"    # HIGH
    assert tiers[("CVE-2025-0003", "3.0.13-0ubuntu3.11")] == "p3"   # LOW、EPSS 0.2
    assert tiers[("CVE-2025-0004", "1.0-1")] == "accepted"          # suppressed + NOT_AFFECTED
    assert tiers[("CVE-2025-0005", "2.0-1")] == "accepted"          # FALSE_POSITIVE（沒有 suppressed）
    assert tiers[("CVE-2025-0006", "3.0-1")] == "p2"                # 只有一筆 suppressed → 仍是未處理
    assert tiers[("GHSA-aaaa-bbbb-cccc", "0.1")] == "p3"            # UNASSIGNED


def test_priority_tiers_configurable():
    cfg = dict(MIN_CFG, vulnerability_policy={"tiers": {"p1": {"kev": False, "epss_percentile_min": 0.1, "label": "Now"},
                                                        "p2": {"severities": ["CRITICAL"], "cvss_min": 9.5}},
                                              "accepted": {"states": ["NOT_AFFECTED"], "include_suppressed": False}})
    tiers = {r["id"]: r["tier"] for r in rows_for(cfg) if r["version"] != "3.0.13-0ubuntu3.12"}
    assert tiers["CVE-2025-0003"] == "p1" and tiers["CVE-2026-61897"] == "p3"
    assert tiers["CVE-2025-0005"] == "p3" and tiers["CVE-2025-0004"] == "accepted" and tiers["CVE-2025-0006"] == "p3"
    pol = cr.policy_of(cfg)
    assert cr.rule_text("p1", pol) == "EPSS percentile ≥ 0.1" and pol["tiers"]["p1"]["action"]   # 沒寫的鍵沿用預設
    assert cr.rule_text("p2", pol) == "severity in {CRITICAL} OR CVSS base score ≥ 9.5"


def test_fix_versions_from_grype():
    rows = rows_for()
    assert row_of(rows, "CVE-2026-111497")["fix"] == "fixed in 1.2.1"
    assert row_of(rows, "CVE-2026-61897")["fix"] == "not-fixed"
    assert row_of(rows, "CVE-2025-0004")["fix"] == "unknown (not matched by Grype)"
    assert row_of(rows_for(grype=None), "CVE-2026-111497")["fix"] == "unknown (no Grype data)"


def test_risk_report_contents(env):
    proj, scan = env
    r, s, reports = run(proj, scan)
    md = (reports / "risk-assessment.md").read_text(encoding="utf-8")
    assert "**Vulnerability data status (section 8): ATTENTION**" in md and "All recorded data-source checks are OK." in md
    assert "Cross-check: Grype reports 3 advisories (3 unique CVEs), Dependency-Track 9 vulnerability rows (7 unique CVEs)" in md
    assert "1 Grype advisory has no counterpart in Dependency-Track (CVE-2025-9999)" in md
    assert "| EPSS percentile ≥ 0.9 |" not in md and "OR EPSS percentile ≥ 0.9 |" in md     # 規則寫進報告
    p1 = md.split("### 8.4 P1")[1].split("### 8.5")[0]
    assert "CVE-2026-111497" in p1 and "GITHUB:GHSA-9v8h-qqgm-4m35, OSV:PYSEC-2026-4322" in p1 and "| YES |" in p1
    app = md.split("## Appendix A.")[1]
    assert "CODE_NOT_REACHABLE" in app and "feature disabled" in app and "CVE-2025-0005" in app and "not recorded" in app
    c = s["counts"]
    # CVE-2025-9999 只有 Grype 有：成為一列（P3，Source IDs GRYPE:…），不再只是交叉核對的一個數字
    assert (c["findings_raw"], c["rows"], c["p1"], c["p2"], c["p3"], c["accepted"]) == (11, 10, 2, 2, 4, 2)
    assert (c["dt_unique_cves"], c["grype_unique_cves"], c["grype_only_cves"], c["kev_open"]) == (7, 3, 1, 1)
    assert (c["grype_only_advisories"], c["grype_advisories_without_dt"], c["grype_only_unlisted"]) == (1, 1, 0)
    p3 = md.split("### 8.6 P3")[1].split("### 8.7")[0]
    assert "| CVE-2025-9999 | CVE-2025-9999 | GRYPE:CVE-2025-9999 | libsrc-bin (found only by Grype) | 1.0 |" in p3 and "| wont-fix |" in p3
    assert "listed as 1 row found only by Grype (Source IDs `GRYPE:…`" in md and "Rows found only by Grype" in md
    assert s["documents"]["risk-assessment"]["status"] == "ATTENTION" and r.returncode == 2


# ---------- 資料不完整 ----------

@pytest.mark.parametrize("stages,expect", [
    ({"D-dt-data-sources": "GAP"}, "D-dt-data-sources is GAP"),
    ({"D-dt-findings": "GAP"}, "D-dt-findings is GAP"),
    ({"D-dt-kev-sources": "NOT_RUN"}, "D-dt-kev-sources is NOT_RUN"),
    ({"C-sbomgate": "GAP"}, "C-sbomgate is GAP"),
])
def test_incomplete_data_sources_gap(tmp_path, stages, expect):
    proj = make_project(tmp_path / "proj")
    r, s, reports = run(proj, make_scan(tmp_path / "scan", stages=stages))
    d = s["documents"]["risk-assessment"]
    assert d["status"] == "GAP" and expect in d["detail"]
    md = (reports / "risk-assessment.md").read_text(encoding="utf-8")
    assert "**The vulnerability list below is INCOMPLETE" in md and f"- {expect}" in md


def test_stage_absent_from_status_is_gap(tmp_path):
    scan = make_scan(tmp_path / "scan")
    (scan / "status.tsv").write_text("stage\tstatus\tdetail\nB-sbom-syft\tOK\tx\nC-sbomgate\tOK\tx\n", encoding="utf-8")
    r, s, _ = run(make_project(tmp_path / "proj"), scan)
    assert "D-dt-data-sources is NOT_RUN (not in status.tsv)" in s["documents"]["risk-assessment"]["detail"]


def test_no_status_tsv(tmp_path):
    r, s, reports = run(make_project(tmp_path / "proj"), make_scan(tmp_path / "scan", stages=False))
    assert s["documents"]["risk-assessment"]["status"] == "GAP" and s["documents"]["sbom"]["status"] == "GAP"
    assert "status.tsv not available: data-source status is UNKNOWN" in (reports / "risk-assessment.md").read_text(encoding="utf-8")
    assert not (reports / "scan-status.tsv").exists()


def test_no_findings_not_assessed(tmp_path):
    r, s, reports = run(make_project(tmp_path / "proj"), make_scan(tmp_path / "scan", findings=None))
    d = s["documents"]["risk-assessment"]
    assert d["status"] == "NOT_ASSESSED" and s["counts"]["findings_raw"] is None
    assert "**Vulnerability data status (section 8): NOT_ASSESSED**" in (reports / "risk-assessment.md").read_text(encoding="utf-8")


def test_empty_sbom_not_assessed(tmp_path):
    proj = make_project(tmp_path / "proj")
    (proj / "CRA" / "Reports").mkdir(parents=True)
    (proj / "CRA" / "Reports" / "sbom.cdx.json").write_text("{\"old\": 1}")
    r, s, reports = run(proj, make_scan(tmp_path / "scan", findings=[], sbom={"bomFormat": "CycloneDX", "components": [{"type": "file", "name": "/x"}]}))
    assert s["documents"]["sbom"]["status"] == "NOT_ASSESSED" and s["documents"]["risk-assessment"]["status"] == "NOT_ASSESSED"
    assert (reports / "sbom.cdx.json").exists()       # 有讀到 SBOM（雖然沒有套件）就照實複製


def test_no_sbom_removes_stale_copy(tmp_path):
    proj = make_project(tmp_path / "proj")
    (proj / "CRA" / "Reports").mkdir(parents=True)
    (proj / "CRA" / "Reports" / "sbom.cdx.json").write_text("{\"old\": 1}")
    r, s, reports = run(proj, make_scan(tmp_path / "scan", sbom=None))
    assert s["documents"]["sbom"]["status"] == "NOT_ASSESSED" and not (reports / "sbom.cdx.json").exists()


def test_no_grype_cross_check_not_possible(tmp_path):
    r, s, reports = run(make_project(tmp_path / "proj"), make_scan(tmp_path / "scan", grype=None))
    assert "Cross-check: not possible" in (reports / "risk-assessment.md").read_text(encoding="utf-8")
    assert s["counts"]["grype_unique_cves"] is None


def test_all_ok(tmp_path):
    findings = [finding("openssl", "3.0.13-0ubuntu3.11", "CVE-2025-0003", "NVD", "LOW")]
    grype = {"matches": [{"vulnerability": {"id": "CVE-2025-0003", "fix": {"state": "fixed", "versions": ["3.0.13-0ubuntu3.13"]}},
                          "artifact": {"name": "openssl", "version": "3.0.13-0ubuntu3.11", "type": "deb"}}]}
    # 安全測試也要有結果（2026-11-03 起：沒有安全測試時風險評估是 ATTENTION，見 test_security_testing.py）
    clean_security(tmp_path)
    r, s, _ = run(make_project(tmp_path / "proj"), make_scan(tmp_path / "scan", findings=findings, grype=grype))
    assert r.returncode == 0 and r.stdout.startswith("OK\t") and s["status"] == "OK"
    assert s["security_testing"]["status"] == "OK" and s["documents"]["security-findings"]["status"] == "OK"


# ---------- 輸入與輸出 ----------

def test_xz_inputs_and_outputs(tmp_path):
    plain = run(make_project(tmp_path / "p1"), make_scan(tmp_path / "s1"))[1]
    r, s, reports = run(make_project(tmp_path / "p2"), make_scan(tmp_path / "s2", xz=True))
    assert s["counts"] == plain["counts"] and s["inputs"]["dt/findings.json"]["file"] == "dt/findings.json.xz"
    assert s["inputs"]["sbom/sbom.cdx.json"]["sha256"] == plain["inputs"]["sbom/sbom.cdx.json"]["sha256"]   # 解壓後內容
    assert json.loads((reports / "sbom.cdx.json").read_text(encoding="utf-8"))["components"] == SBOM["components"]
    assert sorted(os.listdir(reports)) == ["confirmation-items.csv", "confirmation-items.md", "packages-without-vuln-data.csv", "risk-assessment.md", "sbom.cdx.json", "sbom.md", "scan-status.tsv", "security-findings.md",
                                           "summary.json", "technical-documentation.md", "user-information.md", "vex.cdx.json",
                                           "vex.openvex.json", "vulnerability-rows.json"]
    assert r.stdout.count("\n") == 1 and r.stdout.split("\t")[0] in cr.ORDER


def test_sbom_summary(env):
    proj, scan = env
    r, s, reports = run(proj, scan)
    md = (reports / "sbom.md").read_text(encoding="utf-8")
    assert "**Status: OK**" in md and "| library | 3 |" in md and "| deb | 1 |" in md and "| (no purl) | 2 |" in md
    assert "Scanner SBOM generator | syft 1.55.0" in md and "CycloneDX 1.6" in md and s["counts"]["sbom_packages"] == 4


def test_custom_out_dir(tmp_path):
    proj, out = make_project(tmp_path / "proj"), tmp_path / "elsewhere"
    r, _, _ = run(proj, make_scan(tmp_path / "scan"), "--out", str(out))
    assert (out / "summary.json").exists() and not (proj / "CRA" / "Reports").exists()


# ---------- --run-scan ----------

def test_scan_command(tmp_path):
    cmd = cr.scan_command(tmp_path, tmp_path / "o", EXAMPLE)
    assert cmd[0].endswith("tools/pilot/sca-scan") and cmd[1:3] == ["--image", EXAMPLE["scan"]["target"]]
    assert cmd[-1:] == ["--no-license"] and "--name" in cmd
    cmd = cr.scan_command(tmp_path, tmp_path / "o", dict(MIN_CFG, scan={"mode": "dir"}))
    assert cmd[1:3] == ["--dir", str(tmp_path.resolve())] and cmd[cmd.index("--name") + 1] == "EX-J100"
    with pytest.raises(cr.Fail):
        cr.scan_command(tmp_path, tmp_path / "o", dict(MIN_CFG, scan={"mode": "image"}))
    with pytest.raises(cr.Fail):
        cr.scan_command(tmp_path, tmp_path / "o", MIN_CFG)



# ---------- 產品 SBOM、技術文件、風險評估骨架 ----------

def test_product_sbom_identifies_product_and_manufacturer(env):
    proj, scan = env
    sb = dict(SBOM, metadata=dict(SBOM["metadata"], component={"type": "container", "bom-ref": "root-1", "name": "/tmp/x/image.tar"}),
              dependencies=[{"ref": "root-1", "dependsOn": ["a"]}])
    r, s, reports = run(proj, make_scan(scan, sbom=sb))
    b = json.loads((reports / "sbom.cdx.json").read_text(encoding="utf-8"))
    m = b["metadata"]
    assert m["component"]["name"] == EXAMPLE["product"]["name"] and m["component"]["version"] == EXAMPLE["product"]["version"]
    assert m["component"]["bom-ref"] == "root-1" and b["dependencies"] == sb["dependencies"]    # 依賴關係圖的根不變
    assert m["component"]["type"] == "firmware"                                                # 映像模式
    assert m["manufacturer"]["name"] == m["supplier"]["name"] == m["authors"][0]["name"] == "Example Co."
    props = {p["name"]: p["value"] for p in m["component"]["properties"]}
    assert props["sca-center:scanned-artifact"] == META["name"] and props["sca-center:source-sbom-serial"] == "urn:uuid:1"
    assert props["sca-center:source-sbom-sha256"] == s["inputs"]["sbom/sbom.cdx.json"]["sha256"]
    assert b["serialNumber"] != "urn:uuid:1" and b["serialNumber"].startswith("urn:uuid:") and b["version"] == 1
    assert {"type": "application", "name": "cra_report.py", "group": "sca-center"} in m["tools"]["components"]
    assert s["product_sbom"]["sha256"] == __import__("hashlib").sha256((reports / "sbom.cdx.json").read_bytes()).hexdigest()


def test_product_sbom_old_spec_uses_manufacture(tmp_path):
    r, s, reports = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s", sbom=dict(SBOM, specVersion="1.5")))
    m = json.loads((reports / "sbom.cdx.json").read_text(encoding="utf-8"))["metadata"]
    assert "manufacturer" not in m and m["manufacture"]["name"] == "Example Co." and "manufacturer" not in m["component"]


def test_technical_documentation_example_complete(env):
    proj, scan = env
    r, s, reports = run(proj, scan)
    md = (reports / "technical-documentation.md").read_text(encoding="utf-8")
    d = s["documents"]["technical-documentation"]
    assert d["missing_fields"] == [] and "**TO BE COMPLETED**" not in md
    assert d["status"] == "ATTENTION"            # 風險評估是 ATTENTION（P1 未處理）
    assert "| 1(c) | Hardware photographs or illustrations | `technical_documentation.hardware_illustrations` | Provided |" in md
    assert "| 3 | Cybersecurity risk assessment | Generated: `risk-assessment.md` | ATTENTION |" in md
    assert "EXJ100-HW-PHOTO" in md and EXAMPLE["vulnerability_contact"]["cvd_policy_url"] in md
    assert s["product_sbom"]["sha256"] in md


def test_technical_documentation_minimal_marks_owners(tmp_path):
    r, s, reports = run(make_project(tmp_path / "p", MIN_CFG), make_scan(tmp_path / "s"))
    md = (reports / "technical-documentation.md").read_text(encoding="utf-8")
    d = s["documents"]["technical-documentation"]
    assert d["status"] in ("GAP", "ATTENTION", "NOT_ASSESSED") and d["status"] != "OK"
    for f in ("technical_documentation.hardware_illustrations", "technical_documentation.standards", "intended_use.purpose"):
        assert f in d["missing_fields"]
    assert "| 1(c) | Hardware photographs or illustrations | `technical_documentation.hardware_illustrations` | **TO BE COMPLETED** |" in md
    assert "_Owner: hardware engineering._" in md and "**Overall status: GAP**" in md


def test_annex_i_applicability(tmp_path):
    cfg = dict(MIN_CFG, risk_assessment={"annex_i_applicability": {
        "b": {"applies": True, "measures": ["no default passwords", "factory reset"]},
        "g": {"applies": False, "justification": "the product processes no personal data"},
        "h": {"applies": True}}})
    r, s, reports = run(make_project(tmp_path / "p", cfg), make_scan(tmp_path / "s"))
    md = (reports / "risk-assessment.md").read_text(encoding="utf-8")
    sec = md.split("## 6. Applicability")[1].split("## 7.")[0]
    assert "| (a) | Made available without known exploitable vulnerabilities | Applies | Section 8" in sec
    assert "| (b) |" in sec and "no default passwords; factory reset" in sec
    assert "| Does not apply | the product processes no personal data |" in sec
    assert "`risk_assessment.annex_i_applicability.h` (measures)" in sec
    miss = s["documents"]["risk-assessment"]["missing_fields"]
    assert "risk_assessment.annex_i_applicability.h" in miss and "risk_assessment.annex_i_applicability.b" not in miss
    assert len([m for m in miss if ".annex_i_applicability." in m]) == 10   # c–f、h–m


def test_deb_source_package_shows_installed_binaries(tmp_path):
    src = "pkg:deb/ubuntu/freerdp3@3.5.1?arch=source&distro=ubuntu-24.04"
    grype = {"matches": [{"vulnerability": {"id": "CVE-2026-10001", "fix": {"state": "fixed", "versions": ["3.5.1-1ubuntu0.1"]}},
                          "relatedVulnerabilities": [], "artifact": {"name": "libwinpr3-3", "version": "3.5.1", "type": "deb"}}]}
    scan = make_scan(tmp_path / "s", findings=[finding("freerdp3", "3.5.1", "UBUNTU-CVE-2026-10001", "OSV", "HIGH", purl=src)], grype=grype)
    write_json(scan / "dt" / "deb-sources.json", {"added": [{"purl": src, "binaries": "libfreerdp3-3, libwinpr3-3"}]})
    r, s, reports = run(make_project(tmp_path / "p"), scan)
    md = (reports / "risk-assessment.md").read_text(encoding="utf-8")
    assert "freerdp3 (source package; installed as libfreerdp3-3, libwinpr3-3)" in md
    assert "fixed in 3.5.1-1ubuntu0.1" in md                       # 修補資訊從二進位套件的 Grype 紀錄取得
    assert "dt/deb-sources.json" in s["inputs"] and s["inputs"]["dt/deb-sources.json"]


def test_mapped_kernel_component_is_labelled(tmp_path):
    """C-kernel-l4t-map 加上的 Canonical 核心（只供比對）：元件欄寫出它是從哪個 nvidia-l4t-kernel 對應來的。"""
    canon = "pkg:deb/ubuntu/linux-nvidia-tegra@6.8.0-1021.21?arch=source&distro=ubuntu-24.04"
    l4t = "6.8.12-tegra-39.2.1-20260806224157"
    scan = make_scan(tmp_path / "s", findings=[finding("linux-nvidia-tegra", "6.8.0-1021.21", "UBUNTU-CVE-2024-1086", "OSV", "HIGH", purl=canon)],
                     stages={"C-kernel-l4t-map": "OK", "C-kernel-coverage": "OK"})
    write_json(scan / "scan" / "l4t-kernel-map.json", {"status": "OK", "release": "39.2.1",
                                                       "l4t_kernel": [{"name": "nvidia-l4t-kernel", "version": l4t}],
                                                       "map_entry": {"component": {"name": "linux-nvidia-tegra", "purl": canon}}})
    r, s, reports = run(make_project(tmp_path / "p"), scan)
    md = (reports / "kernel-vulnerabilities.md").read_text(encoding="utf-8")      # P2 的核心列只在完整清單（8.7 節只列 P1 與 accepted）
    assert f"linux-nvidia-tegra (Canonical kernel source used for matching; mapped from nvidia-l4t-kernel {l4t})" in md
    assert s["inputs"]["scan/l4t-kernel-map.json"]
    assert cr.kernel_map_index({"status": "GAP", "release": "39.2.1"}) == {}       # 沒有對應時不加註記


# ---------- 審查：缺資料不可變成 OK ----------

@pytest.mark.parametrize("stages,expect,status", [
    ({"C-kernel-coverage": "GAP"}, "C-kernel-coverage is GAP", "GAP"),
    ({"C-kernel-l4t-map": "GAP"}, "C-kernel-l4t-map is GAP", "GAP"),
    ({"D-dt-deb-sources": "FAIL"}, "D-dt-deb-sources is FAIL", "GAP"),
    ({"D-dt-bom-processing": "FAIL"}, "D-dt-bom-processing is FAIL", "GAP"),
    ({"C-grype": "FAIL"}, "C-grype is FAIL", "ATTENTION"),
])
def test_conditional_stages_not_ok(tmp_path, stages, expect, status):
    cfg = json.loads(json.dumps(EXAMPLE))
    findings = [f for f in FINDINGS if not f["vulnerability"].get("isKev") and (f["vulnerability"].get("epssPercentile") or 0) < 0.9]
    r, s, reports = run(make_project(tmp_path / "p", cfg), make_scan(tmp_path / "s", findings=findings, grype=None, stages=stages))
    d = s["documents"]["risk-assessment"]
    assert any(expect in x for x in d["detail"]) and cr.ORDER.index(d["status"]) <= cr.ORDER.index(status)
    assert r.returncode != 0


def test_conditional_stage_absent_is_not_a_gap(tmp_path):
    r, s, _ = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s"))
    assert not any("C-kernel-coverage" in x or "D-dt-deb-sources" in x for x in s["documents"]["risk-assessment"]["detail"])


def test_project_template_cannot_hide_missing_fields(tmp_path):
    cfg = json.loads(json.dumps(EXAMPLE))
    del cfg["technical_documentation"]["standards"], cfg["technical_documentation"]["hardware_illustrations"]
    proj = make_project(tmp_path / "p", cfg, templates={"technical-documentation": "{{ techdoc.status }}\n{{ tables.techdoc_checklist }}\n"})
    r, s, reports = run(proj, make_scan(tmp_path / "s"))
    d = s["documents"]["technical-documentation"]
    assert {"technical_documentation.standards", "technical_documentation.hardware_illustrations"} <= set(d["missing_fields"])
    assert d["status"] != "OK" and not (reports / "technical-documentation.md").read_text(encoding="utf-8").startswith("OK")


def test_fail_removes_previous_documents(tmp_path):
    proj, scan = make_project(tmp_path / "p"), make_scan(tmp_path / "s")
    run(proj, scan)
    reports = proj / "CRA" / "Reports"
    assert (reports / "risk-assessment.md").exists()
    write_json(proj / "CRA" / "Config" / "config.json", dict(EXAMPLE, support={"end_date": "2031-13"}))
    r, s, _ = run(proj, scan)
    assert r.returncode == 1 and s["status"] == "FAIL"
    assert sorted(os.listdir(reports)) == ["summary.json"]


def test_product_sbom_keeps_nested_components_and_no_fake_version(tmp_path):
    sb = dict(SBOM, metadata=dict(SBOM["metadata"], component={"type": "firmware", "bom-ref": "fw", "name": "vendor-fw", "version": "9.9",
                                                               "purl": "pkg:generic/vendor-fw@9.9",
                                                               "components": [{"type": "library", "bom-ref": "sub", "name": "sub", "version": "1"}]}),
              dependencies=[{"ref": "fw", "dependsOn": ["sub"]}])
    cfg = json.loads(json.dumps(MIN_CFG))
    cfg["sbom"] = {"component_type": "device"}
    r, s, reports = run(make_project(tmp_path / "p", cfg), make_scan(tmp_path / "s", sbom=sb))
    c = json.loads((reports / "sbom.cdx.json").read_text(encoding="utf-8"))["metadata"]["component"]
    assert c["bom-ref"] == "fw" and c["components"] == sb["metadata"]["component"]["components"] and c["type"] == "device"
    assert "version" not in c                                                    # 沒有 product.version：不拿掃描對象的 ID 代替
    orig = json.loads({p["name"]: p["value"] for p in c["properties"]}["sca-center:source-main-component"])
    assert orig == {"type": "firmware", "name": "vendor-fw", "version": "9.9", "purl": "pkg:generic/vendor-fw@9.9"}


def test_product_sbom_does_not_leak_scan_paths(tmp_path):
    sb = dict(SBOM, metadata=dict(SBOM["metadata"], component={"type": "file", "name": "/path/to/runner/x/.sca-scan-work.ab/image.tar"}))
    r, s, reports = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s", sbom=sb))
    text = (reports / "sbom.cdx.json").read_text(encoding="utf-8")
    assert ".sca-scan-work" not in text and "image.tar" in text


def test_missing_grype_file_is_attention(tmp_path):
    findings = [f for f in FINDINGS if not f["vulnerability"].get("isKev") and (f["vulnerability"].get("epssPercentile") or 0) < 0.9]
    r, s, _ = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s", findings=findings, grype=None))
    d = s["documents"]["risk-assessment"]
    assert d["status"] == "ATTENTION" and any("no scan/grype.json" in x for x in d["detail"]) and r.returncode == 2


# ---------- 公司共用設定 ----------

COMPANY = {"schema_version": 1,
           "manufacturer": {"name": "Acme Devices Ltd.", "address": "1 Acme Road", "email": "info@acme.example", "website": "https://acme.example"},
           "vulnerability_contact": {"contact": "security@acme.example", "cvd_policy_url": "https://acme.example/security"},
           "sbom": {"availability": "On request"},
           "risk_assessment": {"method": "Likelihood x impact"},
           "vulnerability_policy": {"status": "Approved 2026-11-01", "tiers": {"p2": {"label": "Soon"}}}}


def run_company(project, scan, company, *extra, env=None):
    p = project.parent / "company.json"
    write_json(p, company)
    r = subprocess.run([sys.executable, "-I", str(CLI), "--project", str(project), "--scan", str(scan), "--company", str(p), *extra],
                       capture_output=True, text=True, timeout=60, env=env or dict(os.environ, CRA_COMPANY_CONFIG="none"))
    reports = project / "CRA" / "Reports"
    return r, json.loads((reports / "summary.json").read_text(encoding="utf-8")), reports


@pytest.mark.parametrize("bad,msg", [
    ({"vulnerabilty_policy": {}}, "vulnerabilty_policy"),                       # 拼錯的段落
    ({"manufacturer": {"nmae": "x"}}, "manufacturer.nmae"),                    # 拼錯的鍵
    ({"vulnerability_policy": {"tiers": {"P1": {"kev": True}}}}, "tiers.P1"),  # 不認得的 tier
    ({"scan": {"mode": "dir", "target": "/"}}, "scan：不是公司層級"),
    ({"product": {"version": "9.9"}}, "product：不是公司層級"),
    ({"sbom": {"component_type": "device"}}, "sbom.component_type：每個產品不同"),
    ({"risk_assessment": {"risk_register": "x"}}, "risk_assessment.risk_register：每個產品不同"),
    ({"risk_assessment": {"annex_i_applicability": {"b": {"applies": False, "justification": "x"}}}}, "annex_i_applicability：每個產品不同"),
    ({"technical_documentation": {"hardware_illustrations": "x"}}, "hardware_illustrations：每個產品不同"),
    ({"vulnerability_policy": {"tiers": True}}, "tiers"),                     # 型別錯：FAIL，不是 traceback
])
def test_company_strict_check(tmp_path, bad, msg):
    p = tmp_path / "c.json"
    write_json(p, dict({"schema_version": 1}, **bad))
    r = subprocess.run([sys.executable, "-I", str(CLI), "--check-company", str(p)], capture_output=True, text=True)
    assert r.returncode == 1 and r.stdout.startswith("FAIL\t") and msg in r.stdout, r.stdout


def test_project_unknown_tier_fails_not_traceback(tmp_path):
    r, s, _ = run(make_project(tmp_path / "p", dict(MIN_CFG, vulnerability_policy={"tiers": {"P1": {"kev": True}}})), make_scan(tmp_path / "s"))
    assert r.returncode == 1 and r.stdout.startswith("FAIL\t") and "tiers.P1" in r.stdout and "Traceback" not in r.stderr


def test_company_empty_list_is_a_value_and_empty_string_is_not(tmp_path):
    comp = dict(COMPANY, vulnerability_policy={"status": "", "accepted": {"states": []}})
    cfg = dict(MIN_CFG, vulnerability_policy={"accepted": {"states": ["NOT_AFFECTED", "RESOLVED"]}})
    r, s, _ = run_company(make_project(tmp_path / "p", cfg), make_scan(tmp_path / "s"), comp)
    assert s["policy"]["accepted"]["states"] == [] and any("accepted.states" in w for w in s["config_warnings"])
    assert s["policy"]["status"].startswith("DRAFT")                     # 公司的空字串不會蓋掉草案標記


def test_company_default_path_unreadable_is_fail(tmp_path, monkeypatch):
    d = tmp_path / "locked"
    d.mkdir()
    d.chmod(0)
    try:
        monkeypatch.setattr(cr, "DEFAULT_COMPANY", d / "company.json")
        monkeypatch.delenv("CRA_COMPANY_CONFIG", raising=False)
        if os.geteuid() == 0:
            pytest.skip("root 讀得到任何資料夾")
        try:
            got = cr.company_file()
        except cr.Fail as e:
            assert "--no-company" in str(e)
        else:
            assert got is None                     # 較新的 Python：is_file() 回 False
        assert cr.company_file(disabled=True) is None
    finally:
        d.chmod(0o700)


def test_check_company_must_be_alone(tmp_path):
    p = tmp_path / "c.json"
    write_json(p, COMPANY)
    for extra in (["--project", str(tmp_path)], ["--no-company"], []):
        args = [sys.executable, "-I", str(CLI), "--check-company", str(p) if extra != [] else "", *extra]
        r = subprocess.run(args, capture_output=True, text=True)
        assert r.returncode == 64, (extra, r.stdout, r.stderr)


def test_company_example_is_valid_and_empty(tmp_path):
    """範例只有空白欄位（不會冒充已填）；製造商名稱是必填，填了才通過檢查。"""
    with pytest.raises(cr.Fail, match="manufacturer.name"):
        cr.load_company(HERE.parent / "company.example.json")
    ex = json.loads((HERE.parent / "company.example.json").read_text(encoding="utf-8"))
    assert all(v in ("", {}) or isinstance(v, (dict, int)) for v in ex.values())
    ex["manufacturer"]["name"] = "Acme"
    write_json(tmp_path / "c.json", ex)
    comp, warnings = cr.load_company(tmp_path / "c.json")
    assert warnings == [] and [k for k, v in cr.report_fields(comp).items() if not isinstance(v, cr.Missing)] == ["manufacturer.name"]


def test_missing_manufacturer_hint_points_to_admin(tmp_path):
    r, s, _ = run(make_project(tmp_path / "p", {"schema_version": 1, "product": {"name": "X1"}}), make_scan(tmp_path / "s"))
    assert r.returncode == 1 and "manufacturer：必填" in r.stdout and "管理員" in r.stdout


def test_company_fills_project_gaps(tmp_path):
    proj = make_project(tmp_path / "p", {"schema_version": 1, "manufacturer": {"name": ""}, "product": {"name": "X1"}})
    r, s, reports = run_company(proj, make_scan(tmp_path / "s"), COMPANY)
    ui = (reports / "user-information.md").read_text(encoding="utf-8")
    assert "Acme Devices Ltd." in ui and "security@acme.example" in ui and "https://acme.example/security" in ui
    assert s["company_config"]["sha256"] and "product.name" not in s["missing_fields"]
    assert "manufacturer.address" not in s["missing_fields"] and "risk_assessment.method" not in s["missing_fields"]
    assert s["policy"]["status"] == "Approved 2026-11-01" and s["policy"]["tiers"]["p2"]["label"] == "Soon"
    ra = (reports / "risk-assessment.md").read_text(encoding="utf-8")
    assert "Company-wide settings: `company.json` (SHA-256" in ra and str(tmp_path) not in ra    # 不寫 runner 上的絕對路徑


def test_company_locked_sections_win_with_warning(tmp_path):
    cfg = {"schema_version": 1, "manufacturer": {"name": "Wrong Name", "address": "Own address"}, "product": {"name": "X1"},
           "sbom": {"availability": "Published at https://x1.example/sbom"}}
    r, s, reports = run_company(make_project(tmp_path / "p", cfg), make_scan(tmp_path / "s"), COMPANY)
    ui = (reports / "user-information.md").read_text(encoding="utf-8")
    assert "Acme Devices Ltd." in ui and "Wrong Name" not in ui and "1 Acme Road" in ui
    assert "https://x1.example/sbom" in (reports / "sbom.md").read_text(encoding="utf-8")       # 不鎖定的段落：專案優先
    w = s["config_warnings"]
    assert any("manufacturer.name" in x and "公司" in x for x in w) and any("manufacturer.address" in x for x in w)
    assert sum("manufacturer.name" in x for x in w) == 1
    assert not any("sbom.availability" in x for x in w)


def test_company_locked_field_empty_in_company_project_may_fill(tmp_path):
    comp = dict(COMPANY, manufacturer={"name": "Acme Devices Ltd.", "address": ""})
    cfg = dict(MIN_CFG, manufacturer={"name": "Acme Devices Ltd.", "address": "Project address"})
    r, s, reports = run_company(make_project(tmp_path / "p", cfg), make_scan(tmp_path / "s"), comp)
    assert "Project address" in (reports / "user-information.md").read_text(encoding="utf-8") and s["config_warnings"] == []


def test_company_invalid_fails(tmp_path):
    r, s, reports = run_company(make_project(tmp_path / "p"), make_scan(tmp_path / "s"), dict(COMPANY, support={"end_date": "2031-13"}))
    assert r.returncode == 1 and "公司共用設定" in r.stdout and s["status"] == "FAIL"


def test_company_env_and_default_absent(tmp_path, monkeypatch):
    p = tmp_path / "c.json"
    write_json(p, COMPANY)
    monkeypatch.setenv("CRA_COMPANY_CONFIG", str(p))
    assert cr.company_file() == p and cr.company_file(disabled=True) is None
    monkeypatch.setenv("CRA_COMPANY_CONFIG", "none")
    assert cr.company_file() is None and cr.company_file(str(p)) == p
    monkeypatch.delenv("CRA_COMPANY_CONFIG")
    monkeypatch.setattr(cr, "DEFAULT_COMPANY", tmp_path / "absent" / "company.json")   # 不看主機上的 /etc/sca-gitlab
    assert cr.company_file() is None
    monkeypatch.setattr(cr, "DEFAULT_COMPANY", p)
    assert cr.company_file() == p
    assert cr.company_file(str(p)) == p


def test_check_company_cli(tmp_path):
    good, bad = tmp_path / "good.json", tmp_path / "bad.json"
    write_json(good, COMPANY)
    bad.write_text("{not json", encoding="utf-8")
    r = subprocess.run([sys.executable, "-I", str(CLI), "--check-company", str(good)], capture_output=True, text=True)
    assert r.returncode == 0 and r.stdout.startswith("OK\t")
    r = subprocess.run([sys.executable, "-I", str(CLI), "--check-company", str(bad)], capture_output=True, text=True)
    assert r.returncode == 1 and r.stdout.startswith("FAIL\t")



def test_company_empty_values_skipped_when_project_lacks_section(tmp_path):
    comp = dict(COMPANY, vulnerability_policy={"status": "", "tiers": {"p1": {"label": ""}}})
    r, s, reports = run_company(make_project(tmp_path / "p", MIN_CFG), make_scan(tmp_path / "s"), comp)
    assert s["policy"]["status"].startswith("DRAFT") and s["policy"]["tiers"]["p1"]["label"] == "Immediate"


@pytest.mark.parametrize("cfg", [[1, 2], dict(MIN_CFG, vulnerability_policy={"tiers": 5}), dict(MIN_CFG, vulnerability_policy={"tiers": "p1x"})])
def test_bad_types_fail_not_traceback(tmp_path, cfg):
    r, s, _ = run(make_project(tmp_path / "p", cfg), make_scan(tmp_path / "s"))
    assert r.returncode == 1 and r.stdout.startswith("FAIL\t") and "Traceback" not in r.stderr
    assert "tiers.p：" not in r.stdout


# ---------- 實際掃描公開專案發現的修正 ----------

def test_self_no_version_grype_match_not_counted(tmp_path):
    """sbomgate 判成 SELF_NO_VERSION（專案本身、沒有版本）的 Grype 比對，交叉核對不算「只有 Grype」。"""
    self_purl = "pkg:golang/github.com/example/tool"
    grype = {"matches": GRYPE["matches"][:2] + [
        {"vulnerability": {"id": "GHSA-self-0000-0001", "fix": {"state": "unknown"}}, "relatedVulnerabilities": [{"id": "CVE-2018-25059"}],
         "artifact": {"name": "github.com/example/tool", "version": "", "type": "go-module", "purl": self_purl}}]}
    findings = [f for f in FINDINGS if not f["vulnerability"].get("isKev") and (f["vulnerability"].get("epssPercentile") or 0) < 0.9]
    scan = make_scan(tmp_path / "s", findings=findings, grype=grype)
    write_json(scan / "scan" / "sbomgate.json", {"excluded_matches": [
        {"excluded_reason": "SELF_NO_VERSION", "id": "GHSA-self-0000-0001", "purl": self_purl, "version": None}]})
    r, s, reports = run(make_project(tmp_path / "p"), scan)
    assert s["counts"]["grype_unique_cves"] == 2                 # 交叉核對只算前兩筆；專案本身那筆不算進去
    md = (reports / "risk-assessment.md").read_text(encoding="utf-8")
    # 但要揭露：文件寫出 ID 與「沒有評估」，狀態至少 ATTENTION
    assert "GHSA-self-0000-0001 (CVE-2018-25059) on github.com/example/tool" in md and "NOT assessed" in md
    d = s["documents"]["risk-assessment"]
    assert d["status"] != "OK" and any("matches the product itself" in x for x in d["detail"])
    assert "dt/findings.json" in s["inputs"] and s["inputs"]["scan/sbomgate.json"]


def test_chinese_stage_details_not_in_english_documents(tmp_path):
    scan = make_scan(tmp_path / "s")
    st = (scan / "status.tsv").read_text(encoding="utf-8").replace("detail of D-dt-data-sources", "NVD COMPLETED（只表示最近一次 mirror 完成）")
    (scan / "status.tsv").write_text(st, encoding="utf-8")
    r, s, reports = run(make_project(tmp_path / "p"), scan)
    md = (reports / "risk-assessment.md").read_text(encoding="utf-8")
    assert "只表示" not in md and "| D-dt-data-sources | OK | NVD COMPLETED |" in md     # 去掉中文括號，英文部分保留
    assert "detail of D-dt-kev-sources" in md                   # 英文說明照樣保留


def test_namespaced_packages_get_grype_fix_and_full_name(tmp_path):
    """composer／npm scoped／maven：DT 的名稱只有最後一段，用 purl 對到 Grype 的修補版本，表格顯示完整名稱。"""
    findings = [finding("commonmark", "2.10.1", "GHSA-3q6v-r5mr-hxv8", "GITHUB", "HIGH", [{"cveId": "CVE-2026-105830"}],
                        purl="pkg:composer/league/commonmark@2.10.1"),
                finding("core", "7.0.0", "GHSA-scop-0000-0001", "GITHUB", "HIGH", [{"cveId": "CVE-2026-200001"}], purl="pkg:npm/%40babel/core@7.0.0"),
                finding("log4j-core", "2.14.1", "CVE-2021-44228", "NVD", "CRITICAL", purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")]
    grype = {"matches": [
        {"vulnerability": {"id": "GHSA-3q6v-r5mr-hxv8", "fix": {"state": "fixed", "versions": ["2.10.2"]}}, "relatedVulnerabilities": [{"id": "CVE-2026-105830"}],
         "artifact": {"name": "league/commonmark", "version": "2.10.1", "type": "php-composer", "purl": "pkg:composer/league/commonmark@2.10.1"}},
        {"vulnerability": {"id": "GHSA-scop-0000-0001", "fix": {"state": "fixed", "versions": ["7.0.1"]}}, "relatedVulnerabilities": [],
         "artifact": {"name": "@babel/core", "version": "7.0.0", "type": "npm", "purl": "pkg:npm/%40babel/core@7.0.0"}},
        {"vulnerability": {"id": "CVE-2021-44228", "fix": {"state": "fixed", "versions": ["2.15.0"]}}, "relatedVulnerabilities": [],
         "artifact": {"name": "log4j-core", "version": "2.14.1", "type": "java-archive", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}}]}
    r, s, reports = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s", findings=findings, grype=grype))
    md = (reports / "risk-assessment.md").read_text(encoding="utf-8")
    assert "| league/commonmark | 2.10.1 |" in md and "fixed in 2.10.2" in md
    assert "| @babel/core | 7.0.0 |" in md and "fixed in 7.0.1" in md
    assert "| org.apache.logging.log4j:log4j-core | 2.14.1 |" in md and "fixed in 2.15.0" in md
    assert "not matched by Grype" not in md


def test_product_sbom_has_no_runner_paths(tmp_path):
    work = "/builds/ci-runner/sca-scan/.sca-scan-work.FVUF2l/cdxgen-src/"
    sb = dict(SBOM, components=SBOM["components"] + [{"type": "library", "name": "flask", "version": "2.0.0", "purl": "pkg:pypi/flask@2.0.0",
              "properties": [{"name": "SrcFile", "value": work + "labs/xss/requirements.txt"}],
              "evidence": {"occurrences": [{"location": work + "requirements.txt"}]}}],
              metadata=dict(SBOM["metadata"], properties=[
                  {"name": "cdx:bom:componentSrcFiles", "value": work + "a/requirements.txt\n" + work + "b/requirements.txt\n" + work + "c.txt"},
                  {"name": "root", "value": work.rstrip("/")}]))
    r, s, reports = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s", sbom=sb))
    text = (reports / "sbom.cdx.json").read_text(encoding="utf-8")
    assert ".sca-scan-work" not in text and "ci-runner" not in text
    b = json.loads(text)
    flask = next(c for c in b["components"] if c["name"] == "flask")
    assert flask["properties"][0]["value"] == "labs/xss/requirements.txt" and flask["evidence"]["occurrences"][0]["location"] == "requirements.txt"
    props = {p["name"]: p["value"] for p in b["metadata"]["properties"]}
    assert props["cdx:bom:componentSrcFiles"] == "a/requirements.txt\nb/requirements.txt\nc.txt"      # 多個路徑都留著
    assert props["root"] == "."


def test_unresolved_dependencies_make_risk_gap(tmp_path):
    findings = [f for f in FINDINGS if not f["vulnerability"].get("isKev") and (f["vulnerability"].get("epssPercentile") or 0) < 0.9]
    r, s, _ = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s", findings=findings, stages={"B-toolchain": "GAP"}))
    d = s["documents"]["risk-assessment"]
    assert d["status"] == "GAP" and "B-toolchain is GAP" in d["detail"]


def test_pypi_names_displayed_consistently(tmp_path):
    findings = [finding("Pillow", "12.1.0", "CVE-2026-300001", "OSV", "MEDIUM", purl="pkg:pypi/pillow@12.1.0"),
                finding("pillow", "8.0.0", "CVE-2026-300002", "OSV", "MEDIUM", purl="pkg:pypi/pillow@8.0.0")]
    r, s, reports = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s", findings=findings))
    md = (reports / "risk-assessment.md").read_text(encoding="utf-8")
    assert "| pillow | 12.1.0 |" in md and "| pillow | 8.0.0 |" in md and "| Pillow |" not in md



def test_os_package_names_have_no_distro_prefix(tmp_path):
    r, s, reports = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s"))
    md = (reports / "risk-assessment.md").read_text(encoding="utf-8")
    assert "| openssl | 3.0.13-0ubuntu3.11 |" in md and "ubuntu/openssl" not in md



def test_en_keeps_english_part_and_names_keep_case(tmp_path):
    assert cr.en("320 matches（比對完成；不代表不存在其他弱點）") == "320 matches"
    assert cr.en("Built=2026-10-28T06:23:30Z（0 天）Status=valid") == "Built=2026-10-28T06:23:30Z Status=valid"
    assert cr.en("全部是中文") == "see scan-status.tsv"
    assert cr.display_name({"name": "Newtonsoft.Json", "purl": "pkg:nuget/Newtonsoft.Json@13.0.1"}) == "Newtonsoft.Json"
    assert cr.display_name({"name": "core", "purl": "pkg:npm/@babel/core@7.0.0"}) == "@babel/core"
    assert cr.purl_fullname("pkg:npm/@babel/core@7.0.0?x=1") == "@babel/core"


def test_same_short_name_different_groups_not_merged(tmp_path):
    findings = [finding("core", "1.0", "CVE-2026-400001", "NVD", "HIGH", purl="pkg:maven/org.a/core@1.0"),
                finding("core", "1.0", "CVE-2026-400001", "NVD", "HIGH", purl="pkg:maven/com.b/core@1.0")]
    r, s, reports = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s", findings=findings, grype={"matches": []}))
    md = (reports / "risk-assessment.md").read_text(encoding="utf-8")
    assert "| org.a:core |" in md and "| com.b:core |" in md and s["counts"]["rows"] == 2



@pytest.mark.parametrize("value,expect", [
    ("/x/.sca-scan-work.AB/srctar.txt", "srctar.txt"),
    ("/x/.sca-scan-work.AB/image.tar", "image.tar"),
    ("file:///x/.sca-scan-work.AB/cdxgen-src/a/b.txt", "a/b.txt"),
    ("/x/.sca-scan-work.AB/cdxgen-src", "."),
    ("pkg:npm/src@1.0", "pkg:npm/src@1.0"),
])
def test_strip_work_paths_edges(value, expect):
    assert cr.strip_work_paths({"v": value})["v"] == expect



def test_cross_check_by_ghsa_when_grype_has_no_cve(tmp_path):
    """實際掃描公開專案（filamentphp/demo）：Grype 只給 GHSA、DT 是 CVE＋GHSA 別名——兩邊其實是同一個，不能算成「只有 DT」。"""
    findings = [finding("commonmark", "2.10.1", "CVE-2026-105830", "GITHUB", "HIGH", [{"ghsaId": "GHSA-3q6v-r5mr-hxv8"}],
                        purl="pkg:composer/league/commonmark@2.10.1")]
    grype = {"matches": [{"vulnerability": {"id": "GHSA-3q6v-r5mr-hxv8", "fix": {"state": "fixed", "versions": ["2.10.2"]}},
                          "relatedVulnerabilities": [], "artifact": {"name": "league/commonmark", "version": "2.10.1", "type": "php-composer",
                                                                     "purl": "pkg:composer/league/commonmark@2.10.1"}}]}
    r, s, reports = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s", findings=findings, grype=grype))
    md = (reports / "risk-assessment.md").read_text(encoding="utf-8")
    assert "Grype reports 1 advisory (0 unique CVEs)" in md
    assert "0 Grype advisories have no counterpart in Dependency-Track, 0 Dependency-Track rows have no counterpart in Grype" in md
    c = s["counts"]
    assert (c["grype_advisories"], c["grype_only_advisories"], c["dt_only_rows"]) == (1, 0, 0)
    assert not any("not in the Dependency-Track list" in x for x in s["documents"]["risk-assessment"]["detail"])



def test_grype_match_without_any_id_does_not_crash(tmp_path):
    grype = {"matches": GRYPE["matches"] + [{"vulnerability": {}, "artifact": {"name": "x", "version": "1", "type": "npm"}}]}
    r, s, reports = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s", grype=grype))
    assert r.returncode in (0, 2) and "Traceback" not in r.stderr and (reports / "risk-assessment.md").exists()


def test_cve_only_in_grype_still_flagged_when_advisory_matched(tmp_path):
    """Grype 一筆 {GHSA-x, CVE-1, CVE-2}，DT 只有 CVE-1：公告算對上，但 CVE-2 仍要寫出來並 ATTENTION。"""
    findings = [finding("lib", "1.0", "CVE-2026-500001", "NVD", "MEDIUM", purl="pkg:npm/lib@1.0")]
    grype = {"matches": [{"vulnerability": {"id": "GHSA-xxxx-yyyy-zzzz", "fix": {"state": "unknown"}},
                          "relatedVulnerabilities": [{"id": "CVE-2026-500001"}, {"id": "CVE-2026-500002"}],
                          "artifact": {"name": "lib", "version": "1.0", "type": "npm", "purl": "pkg:npm/lib@1.0"}}]}
    r, s, reports = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s", findings=findings, grype=grype))
    md = (reports / "risk-assessment.md").read_text(encoding="utf-8")
    assert "1 CVE listed by Grype is not in the Dependency-Track list (CVE-2026-500002)" in md
    assert any("1 CVE not in the Dependency-Track list" in x for x in s["documents"]["risk-assessment"]["detail"])


# ---------- 作業系統核心：主清單以外的 8.7 節與 kernel-vulnerabilities.md ----------

CANON = "pkg:deb/ubuntu/linux-nvidia-tegra@6.8.0-1021.21?arch=source&distro=ubuntu-24.04"
L4T = "6.8.12-tegra-39.2.1-20260806224157"
KMAP = {"status": "OK", "release": "39.2.1", "l4t_kernel": [{"name": "nvidia-l4t-kernel", "version": L4T}],
        "map_entry": {"component": {"name": "linux-nvidia-tegra", "version": "6.8.0-1021.21", "purl": CANON}}}


def kfinding(vid, severity, **kw):
    return finding("linux-nvidia-tegra", "6.8.0-1021.21", f"UBUNTU-{vid}", "OSV", severity, purl=CANON, **kw)


def kmatch(cve, state, versions=()):
    return {"vulnerability": {"id": cve, "fix": {"state": state, "versions": list(versions)}}, "relatedVulnerabilities": [],
            "artifact": {"name": "linux-nvidia-tegra", "version": "6.8.0-1021.21", "type": "deb", "purl": CANON}}


KFINDINGS = [
    kfinding("CVE-2024-1086", "HIGH", kev=True),                                     # P1（KEV）、fixed
    kfinding("CVE-2025-0101", "MEDIUM", epss=0.95),                                  # P1（EPSS）、fixed
    kfinding("CVE-2025-0102", "HIGH"),                                               # P2、fixed 1100.100（全部修好所需的版本）
    kfinding("CVE-2025-0103", "LOW"),                                                # P3、fixed（兩個版本取最低的 1023.23）
    kfinding("CVE-2025-0104", "MEDIUM"),                                             # P3、not-fixed
    kfinding("CVE-2025-0105", "HIGH"),                                               # P2、wont-fix
    kfinding("CVE-2025-0106", "LOW"),                                                # P3、Grype 沒有比對到
    kfinding("CVE-2025-0107", "CRITICAL", analysis={"isSuppressed": True, "state": "NOT_AFFECTED",
                                                    "justification": "CODE_NOT_PRESENT", "details": "driver not built"}),   # accepted
    finding("openssl", "3.0.13-0ubuntu3.11", "CVE-2025-0003", "NVD", "LOW"),          # 其他元件
    finding("linux-libc-dev", "6.8.0-45.45", "CVE-2025-0200", "NVD", "MEDIUM"),       # 使用者空間標頭：不算核心
]
KGRYPE = {"matches": [
    kmatch("CVE-2024-1086", "fixed", ["6.8.0-1022.22"]),
    kmatch("CVE-2025-0101", "fixed", ["6.8.0-1030.30"]),
    kmatch("CVE-2025-0102", "fixed", ["6.8.0-1100.100"]),                 # 字串排序會以為 1030.30 比較大
    kmatch("CVE-2025-0103", "fixed", ["6.8.0-1200.200", "6.8.0-1023.23"]),
    kmatch("CVE-2025-0104", "not-fixed"),
    kmatch("CVE-2025-0105", "wont-fix"),
    kmatch("CVE-2025-0107", "not-fixed"),
    {"vulnerability": {"id": "CVE-2025-0003", "fix": {"state": "fixed", "versions": ["3.0.13-0ubuntu3.13"]}},
     "artifact": {"name": "openssl", "version": "3.0.13-0ubuntu3.11", "type": "deb"}},
    {"vulnerability": {"id": "CVE-2025-0200", "fix": {"state": "not-fixed", "versions": []}},
     "artifact": {"name": "linux-libc-dev", "version": "6.8.0-45.45", "type": "deb"}},
]}


def kernel_scan(d, findings=KFINDINGS, grype=KGRYPE, kmap=KMAP, stages=None):
    scan = make_scan(d, findings=findings, grype=grype, stages={"C-kernel-l4t-map": "OK", "C-kernel-coverage": "OK", **(stages or {})})
    if kmap is not None:
        write_json(scan / "scan" / "l4t-kernel-map.json", kmap)
    return scan


def section_87(md):
    # 到 VEX 小節（或第 9 節）為止
    return md.split("### 8.7 Operating system kernel")[1].split("## 9.")[0].split("\n\n### 8.8 Vulnerability status")[0]


def test_kernel_rows_in_own_section(tmp_path):
    r, s, reports = run(make_project(tmp_path / "p"), kernel_scan(tmp_path / "s"))
    md = (reports / "risk-assessment.md").read_text(encoding="utf-8")
    main = md.split("### 8.4 P1")[1].split("### 8.7")[0] + md.split("## Appendix A.")[1]
    assert "linux-nvidia-tegra" not in main and "CVE-2024-1086" not in main            # 主清單沒有核心的列
    assert "| openssl | 3.0.13-0ubuntu3.11 |" in main and "CVE-2025-0200" in main      # linux-libc-dev 留在主清單
    assert ("Rows for the operating system kernel (8: P1 2, P2 2, P3 3, accepted 1) are not listed in sections 8.4–8.6 or "
            "Appendix A") in md
    assert "### 8.4 P1 – Immediate (0)" in md and "## Appendix A. Not affected / accepted (0)" in md
    k = section_87(md)
    assert k.startswith(" (8)")
    assert "**linux-nvidia-tegra 6.8.0-1021.21**" in k and f"`nvidia-l4t-kernel {L4T}`" in k and "L4T 39.2.1" in k
    assert "matching-only" in k and "nvgpu, nvethernetrm, linux-nv-oot" in k and "NVIDIA SAUCE" in k
    for line in ("| Grype fix state: fixed | 4 |", "| Grype fix state: not-fixed | 2 |", "| Grype fix state: wont-fix | 1 |",
                 "| Grype fix state: no Grype data | 1 |", "| P1 – Immediate | 2 |", "| P2 – Next release | 2 |", "| P3 – Track | 3 |",
                 "| Not affected / accepted | 1 |", "| Open rows listed in a KEV catalogue | 1 |"):
        assert line in k, line
    assert "Grype fix state: unknown" not in k                                          # 0 筆時不列
    assert "4 rows are fixed in later Canonical kernel versions" in k
    assert "The lowest version that fixes all of them is **linux-nvidia-tegra 6.8.0-1100.100**" in k
    assert "move to a Jetson Linux (L4T) release whose kernel is based on linux-nvidia-tegra 6.8.0-1100.100 or later" in k
    assert "**Not fixed:** 2 rows" in k and "1 will not be fixed" in k
    table_part = k.split("#### Kernel rows in P1 (2)")[1]
    acc_part = table_part.split("#### Accepted kernel rows (1)")[1]
    for cve in ("CVE-2024-1086", "CVE-2025-0101", "CVE-2025-0107"):                     # P1 與 accepted，不管修補狀態
        assert cve in table_part
    assert "CODE_NOT_PRESENT" in acc_part and "driver not built" in acc_part             # accepted 的理由與說明照附錄 A 的寫法
    for cve in ("CVE-2025-0102", "CVE-2025-0103", "CVE-2025-0104", "CVE-2025-0105", "CVE-2025-0106"):
        assert cve not in table_part
    kev = next(x for x in table_part.splitlines() if "CVE-2024-1086" in x)
    assert "| P1 |" in kev and "| YES |" in kev and "| fixed | fixed in 6.8.0-1022.22 |" in kev
    assert "| NOT_AFFECTED | yes | CODE_NOT_PRESENT | driver not built |" in next(x for x in acc_part.splitlines() if "CVE-2025-0107" in x)
    assert "The remaining 5 kernel rows (P2 2, P3 3)" in k and "**Full list:** `kernel-vulnerabilities.md` (8 rows" in k
    # 8.2：總數、核心、其他元件三欄；層級與整體狀態仍算核心的列
    assert "| Metric | Total | OS kernel (section 8.7) | Other components |" in md
    assert "| Rows after de-duplication (vulnerability × component version) | 10 | 8 | 2 |" in md
    assert "| P1 – Immediate | 2 | 2 | 0 |" in md
    d = s["documents"]["risk-assessment"]
    assert d["status"] == "ATTENTION" and "2 open findings in tier P1 (Immediate); 2 of them for the operating system kernel (section 8.7)" in d["detail"]



def test_kernel_kev_only_in_grype_is_p1_and_counted(tmp_path):
    """實際資料：核心 CVE 在 Grype 是 KEV，DT 的 Ubuntu OSV 紀錄不是 → 以前是 P2、KEV 欄 no、不算未處理的 KEV。"""
    g = json.loads(json.dumps(KGRYPE))
    m = next(x for x in g["matches"] if x["vulnerability"]["id"] == "CVE-2025-0102")
    m["vulnerability"]["knownExploited"] = [{"cve": "CVE-2025-0102", "knownRansomwareCampaignUse": "Unknown"}]
    g["matches"].append({"vulnerability": {"id": "CVE-2025-0999", "fix": {"state": "not-fixed"}, "knownExploited": [{"cve": "CVE-2025-0999"}]},
                         "artifact": {"name": "libonlygrype", "version": "1.0"}})     # 只有 Grype 有的 KEV：成為一列，P1
    r, s, reports = run(make_project(tmp_path / "p"), kernel_scan(tmp_path / "s", grype=g))
    md = (reports / "risk-assessment.md").read_text(encoding="utf-8")
    p1 = section_87(md).split("#### Kernel rows in P1 (3)")[1]
    row = next(x for x in p1.splitlines() if "CVE-2025-0102" in x)
    assert "| P1 |" in row and "| YES (Grype) |" in row
    c = s["counts"]
    assert (c["p1"], c["p2"], c["kev_open"]) == (4, 1, 3) and (c["kernel"]["p1"], c["kernel"]["kev_open"]) == (3, 2)
    main = md.split("### 8.4 P1")[1].split("### 8.5")[0]
    row = next(x for x in main.splitlines() if "CVE-2025-0999" in x)
    assert "GRYPE:CVE-2025-0999" in row and "| libonlygrype (found only by Grype) |" in row and "| YES (Grype) |" in row
    d = s["documents"]["risk-assessment"]["detail"]
    assert not any("not in the risk table" in x for x in d) and s["counts"]["kev_grype_only_not_in_table"] == []
    assert (c["non_kernel"]["grype_only_rows"], c["kernel"]["grype_only_rows"]) == (1, 0)


def test_kernel_document_and_summary(tmp_path):
    r, s, reports = run(make_project(tmp_path / "p"), kernel_scan(tmp_path / "s"))
    kd = (reports / "kernel-vulnerabilities.md").read_text(encoding="utf-8")
    full = kd.split("## Full list (8)")[1]
    assert all(f"CVE-2025-01{i:02d}" in full for i in range(1, 8)) and "CVE-2024-1086" in full and "openssl" not in full
    assert "| # | Tier | ID | CVE | Source IDs | Component | Version | Type | Severity | Severity source | CVSS | EPSS probability (percentile) | KEV | Fix state (Grype) | Fix (Grype) | Analysis state |" in full
    tiers = [x.split(" | ")[1] for x in full.splitlines() if x.startswith("| ") and x[2].isdigit()]
    assert tiers == ["P1", "P1", "P2", "P2", "P3", "P3", "P3", "ACCEPTED"]               # 依層級排序
    assert "**Vulnerability data status: ATTENTION**" in kd and "6.8.0-1100.100" in kd
    assert "Full list:** `kernel-vulnerabilities.md`" not in kd                           # 摘要不指向自己
    assert "driver not built" in kd and "CODE_NOT_PRESENT" in kd
    assert "NOT_AFFECTED (suppressed)" in next(x for x in full.splitlines() if "CVE-2025-0107" in x)
    c = s["counts"]
    assert (c["rows"], c["p1"], c["p2"], c["p3"], c["accepted"], c["kev_open"]) == (10, 2, 2, 5, 1, 1)   # 原本的鍵：全部的列
    k, o = c["kernel"], c["non_kernel"]
    assert (k["rows"], k["p1"], k["p2"], k["p3"], k["accepted"], k["kev_open"], k["section"]) == (8, 2, 2, 3, 1, 1, "listed")
    assert k["fix_states"] == {"fixed": 4, "not-fixed": 2, "wont-fix": 1, "unknown": 0, "no Grype data": 1}
    assert k["fix_all"] == [{"component": "linux-nvidia-tegra", "mapped_from": f"nvidia-l4t-kernel {L4T}", "rows": 4,
                             "without_version": 0, "fix_all_version": "6.8.0-1100.100", "comparable": True}]
    assert k["risk_assessment_layout"] == "separate"
    assert (o["rows"], o["p3"], o["findings_raw"]) == (2, 2, 2) and k["findings_raw"] == 8
    kdoc = s["documents"]["kernel-vulnerabilities"]
    assert kdoc["file"] == "kernel-vulnerabilities.md" and kdoc["status"] == s["documents"]["risk-assessment"]["status"]
    assert kdoc["counts"]["rows"] == 8 and s["inputs"]["scan/l4t-kernel-map.json"]["sha256"]
    td = (reports / "technical-documentation.md").read_text(encoding="utf-8")
    assert ("Vulnerability rows (vulnerability × component version): 10 in total; 8 for the operating system kernel "
            "(`kernel-vulnerabilities.md`), 2 for other components.") in td
    assert "其中核心 8 列" in r.stdout


@pytest.mark.parametrize("stages,kmap,stage", [
    ({"C-kernel-l4t-map": "GAP", "C-kernel-coverage": "GAP"}, {"status": "GAP", "release": "39.9.9"}, "C-kernel-l4t-map"),
    ({"C-kernel-coverage": "GAP"}, None, "C-kernel-coverage"),
])
def test_kernel_present_not_matched_is_not_assessed(tmp_path, stages, kmap, stage):
    proj = make_project(tmp_path / "p")
    (proj / "CRA" / "Reports").mkdir(parents=True)
    (proj / "CRA" / "Reports" / "kernel-vulnerabilities.md").write_text("old", encoding="utf-8")
    scan = make_scan(tmp_path / "s", findings=KFINDINGS[8:], grype=None, stages=stages)
    if kmap:
        write_json(scan / "scan" / "l4t-kernel-map.json", kmap)
    if stage == "C-kernel-l4t-map":
        (scan / "status.tsv").write_text((scan / "status.tsv").read_text(encoding="utf-8").replace(
            "C-kernel-l4t-map\tGAP\tdetail of C-kernel-l4t-map", "C-kernel-l4t-map\tGAP\tL4T 39.9.9 沒有對應"), encoding="utf-8")
    r, s, reports = run(proj, scan)
    md = (reports / "risk-assessment.md").read_text(encoding="utf-8")
    k = section_87(md)
    assert k.startswith(" (0)") and "**Kernel not assessed.**" in k and f"`{stage}` GAP" in k and "NOT assessed" in k
    assert "No operating system kernel" not in k and "no known vulnerabilities" in k        # 「沒有列」不等於「沒有弱點」
    assert "沒有對應" not in md
    assert not (reports / "kernel-vulnerabilities.md").exists() and "kernel-vulnerabilities" not in s["documents"]
    assert s["documents"]["risk-assessment"]["status"] == "GAP" and s["counts"]["kernel"]["section"] == "not_assessed"
    assert s["counts"]["kernel"]["rows"] == 0 and s["counts"]["non_kernel"]["rows"] == 2


def test_no_kernel_scan_output_unchanged(env):
    """沒有核心的掃描：8.7 節只有一行，沒有多的檔案、8.2 仍是兩欄，主清單照舊。"""
    proj, scan = env
    r, s, reports = run(proj, scan)
    md = (reports / "risk-assessment.md").read_text(encoding="utf-8")
    assert section_87(md).strip() == ("(0)\n\nNo operating system kernel in the SBOM (sca-scan found no kernel component, "
                                      "Linux kernel CPE or kernel package).")
    assert "Rows for the operating system kernel" not in md and "| Metric | Value |" in md and "OS kernel (section 8.7)" not in md
    assert "CVE-2026-111497" in md.split("### 8.4 P1")[1].split("### 8.5")[0]
    assert not (reports / "kernel-vulnerabilities.md").exists() and "kernel-vulnerabilities" not in s["documents"]
    # 10 列：9 列 DT＋1 列只有 Grype（CVE-2025-9999）
    assert s["counts"]["kernel"]["section"] == "no_kernel" and s["counts"]["non_kernel"]["rows"] == s["counts"]["rows"] == 10
    assert "其中核心" not in r.stdout
    td = (reports / "technical-documentation.md").read_text(encoding="utf-8")
    assert "10 in total; 0 for the operating system kernel, 10 for other components." in td


def test_kernel_section_dir_scan_not_checked(tmp_path):
    r, s, reports = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s", meta=dict(META, mode="dir")))
    assert "Not checked: sca-scan only checks the operating system kernel for image and SBOM scans (scan mode dir)" in \
        (reports / "risk-assessment.md").read_text(encoding="utf-8")
    assert s["counts"]["kernel"]["section"] == "not_checked"


def test_kernel_matched_but_no_dt_findings(tmp_path):
    g = {"matches": KGRYPE["matches"][7:]}       # Grype 也沒有核心的比對
    r, s, reports = run(make_project(tmp_path / "p"), kernel_scan(tmp_path / "s", findings=KFINDINGS[8:], grype=g))
    k = section_87((reports / "risk-assessment.md").read_text(encoding="utf-8"))
    assert "was matched, but Dependency-Track reported no findings for it" in k and "`C-kernel-coverage` OK" in k
    assert s["counts"]["kernel"]["section"] == "no_findings"


def test_kernel_grype_only_rows_listed_like_other_kernel_rows(tmp_path):
    """DT 沒有核心的 finding、Grype 有：Grype 的核心比對成為只有 Grype 的列，在 8.7 節與 kernel-vulnerabilities.md（不是「沒有 finding」），
    元件是同一個對應的 Canonical 核心（mapped_from），修補狀態與「全部修好所需的版本」照常計算。"""
    r, s, reports = run(make_project(tmp_path / "p"), kernel_scan(tmp_path / "s", findings=KFINDINGS[8:]))
    k = section_87((reports / "risk-assessment.md").read_text(encoding="utf-8"))
    assert "Dependency-Track reported no findings" not in k and "7 kernel rows were found only by Grype" in k
    kc = s["counts"]["kernel"]
    assert (kc["section"], kc["rows"], kc["grype_only_rows"], kc["findings_raw"], kc["dt_unique_cves"]) == ("listed", 7, 7, 0, 0)
    assert kc["fix_all"][0]["mapped_from"] == f"nvidia-l4t-kernel {L4T}" and kc["fix_all"][0]["fix_all_version"] == "6.8.0-1100.100"
    full = (reports / "kernel-vulnerabilities.md").read_text(encoding="utf-8")
    row = next(x for x in full.splitlines() if "| CVE-2025-0104 |" in x)
    assert "GRYPE:CVE-2025-0104" in row and "Canonical kernel source used for matching" in row and "| not-fixed |" in row


@pytest.mark.parametrize("comp,expect", [
    ({"name": "linux-image-6.8.0-45-generic", "purl": "pkg:deb/ubuntu/linux-image-6.8.0-45-generic@6.8.0-45.45?arch=amd64"}, True),
    ({"name": "linux-modules-6.8.0-45-generic", "purl": "pkg:deb/ubuntu/linux-modules-6.8.0-45-generic@6.8.0-45.45"}, True),
    ({"name": "kernel-core", "purl": "pkg:rpm/redhat/kernel-core@5.14.0-427.el9"}, True),
    ({"name": "linux-lts", "purl": "pkg:apk/alpine/linux-lts@6.6.30-r0"}, True),
    ({"name": "linux-kernel", "purl": "pkg:generic/linux-kernel@6.8.12"}, True),
    ({"name": "x", "purl": "pkg:generic/x@1", "cpe": "cpe:2.3:o:linux:linux_kernel:6.8.12:*:*:*:*:*:*:*"}, True),
    ({"name": "linux", "purl": "pkg:deb/ubuntu/linux@6.8.0-45.45?arch=source", "installed_as": ["linux-image-6.8.0-45-generic"]}, True),
    ({"name": "linux", "purl": "pkg:deb/ubuntu/linux@6.8.0-45.45?arch=source", "installed_as": ["linux-libc-dev"]}, False),
    ({"name": "linux-libc-dev", "purl": "pkg:deb/ubuntu/linux-libc-dev@6.8.0-45.45"}, False),
    ({"name": "linux-headers-6.8.0-45-generic", "purl": "pkg:deb/ubuntu/linux-headers-6.8.0-45-generic@6.8.0-45.45"}, False),
    ({"name": "nvidia-l4t-kernel-headers", "purl": "pkg:deb/nvidia/nvidia-l4t-kernel-headers@6.8.12"}, False),
    ({"name": "kernel", "purl": "pkg:pypi/kernel@1.0"}, False),
    ({"name": "linux-firmware", "purl": "pkg:deb/ubuntu/linux-firmware@20240318"}, False),
])
def test_is_kernel_row(comp, expect):
    row = {"name": comp["name"], "version": "1", "purl": comp["purl"], "cpe": comp.get("cpe", ""), "installed_as": comp.get("installed_as", [])}
    assert cr.is_kernel_row(row) is expect


def test_is_kernel_row_matches_mapped_component_by_purl_or_name_version():
    kinfo = cr.kernel_map_info(KMAP)
    assert kinfo["purl"] == CANON.split("?")[0] and kinfo["release"] == "39.2.1"
    assert cr.is_kernel_row({"name": "x", "version": "1", "purl": "pkg:deb/ubuntu/linux-nvidia-tegra@6.8.0-1021.21", "installed_as": []}, kinfo)
    assert cr.is_kernel_row({"name": "linux-nvidia-tegra", "version": "6.8.0-1021.21", "purl": "", "installed_as": []}, kinfo)
    assert cr.kernel_map_info({"status": "GAP"}) is None


@pytest.mark.parametrize("a,b,expect", [
    ("1.0", "1.0", 0),
    ("0:1.0", "1.0", 0),                          # epoch 0 等於沒寫
    ("1:1.0", "2.0", 1),                          # epoch 優先
    ("1:0.1", "0:9.9", 1),
    ("1.0~rc1", "1.0", -1),                       # ~ 比結尾小
    ("1.0~~", "1.0~", -1),
    ("1.0~rc1", "1.0~rc2", -1),
    ("1.0", "1.0+b1", -1),                        # 符號比結尾大
    ("1.0a", "1.0+", -1),                         # 字母比符號小
    ("1.0-1", "1.0", 1),
    ("1.0-0", "1.0", 0),
    ("1.0-1", "1.0-1ubuntu1", -1),
    ("2.30-0ubuntu1~22.04", "2.30-0ubuntu1", -1),
    ("1.001", "1.1", 0),                          # 數字段不看前導 0
    ("1.2-3-4", "1.2-3-5", -1),                   # revision 是最後一個 - 之後
    ("6.8.0-1022.22", "6.8.0-1100.100", -1),      # 數值比較（字串排序會相反）
    ("6.8.0-1030.30", "6.8.0-1022.22", 1),
    ("6.8.0-100.100", "6.8.0-99.99", 1),
    ("10.0", "9.9", 1),
])
def test_deb_vercmp(a, b, expect):
    assert cr.deb_vercmp(a, b) == expect and cr.deb_vercmp(b, a) == -expect


def krow(fix_versions, state="fixed", ptype="deb", component="linux-nvidia-tegra", version="6.8.0-1021.21"):
    return {"fix_state": state, "component": component, "mapped_from": "m", "fix_versions": fix_versions, "ptype": ptype, "version": version}


def test_kernel_fix_all_uses_lowest_fix_per_row_and_debian_order():
    rows = [krow(v) for v in (["6.8.0-1022.22"], ["6.8.0-1100.100", "6.8.0-1030.30"], ["6.8.0-1099.99"], [])]
    g, = cr.kernel_fix_all(rows + [krow([], "not-fixed")])
    assert (g["rows"], g["without_version"], g["fix_all_version"], g["comparable"]) == (4, 1, "6.8.0-1099.99", True)


def test_kernel_fix_all_ignores_versions_not_above_installed():
    """Grype 的修補版本裡不比安裝版本新的（例如另一個版本線的舊修補）不算；都不比較新的列記在 without_version。"""
    g, = cr.kernel_fix_all([krow(["6.8.0-1008.8", "6.8.0-1025.25"]), krow(["6.8.0-1021.21"]), krow(["6.8.0-1022.22"])])
    assert (g["fix_all_version"], g["without_version"]) == ("6.8.0-1025.25", 1)


def test_kernel_fix_all_not_computed_for_non_deb(tmp_path):
    g, = cr.kernel_fix_all([krow(["5.14.0-500.el9"], ptype="rpm", component="kernel-core", version="5.14.0-427.el9")])
    assert (g["comparable"], g["fix_all_version"], g["rows"]) == (False, None, 1)
    rpm = "pkg:rpm/redhat/kernel-core@5.14.0-427.el9"
    findings = [finding("kernel-core", "5.14.0-427.el9", "CVE-2025-0301", "NVD", "HIGH", purl=rpm)]
    grype = {"matches": [{"vulnerability": {"id": "CVE-2025-0301", "fix": {"state": "fixed", "versions": ["5.14.0-500.el9"]}},
                          "artifact": {"name": "kernel-core", "version": "5.14.0-427.el9", "type": "rpm", "purl": rpm}}]}
    r, s, reports = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s", findings=findings, grype=grype,
                                                                stages={"C-kernel-coverage": "OK"}))
    k = section_87((reports / "risk-assessment.md").read_text(encoding="utf-8"))
    assert "only implemented for Debian packages" in k and "The lowest version that fixes all" not in k
    assert "Kernel components matched directly: kernel-core 5.14.0-427.el9 (1 row)." in k
    assert "No kernel row is in P1 or accepted; the 1 kernel row (P2 1, P3 0) is only counted here." in k
    assert "#### Kernel rows in P1 (0)" in k and "#### Accepted kernel rows (0)" in k


def test_project_template_without_kernel_section_keeps_kernel_rows_in_main_tables(tmp_path):
    tpl = "{{ risk.data_status_detail }}\n{{ tables.counts }}\n## P1\n{{ tables.p1 }}\n## P2\n{{ tables.p2 }}\n## P3\n{{ tables.p3 }}\n{{ tables.accepted }}\n"
    proj = make_project(tmp_path / "p", templates={"risk-assessment": tpl})
    r, s, reports = run(proj, kernel_scan(tmp_path / "s"))
    md = (reports / "risk-assessment.md").read_text(encoding="utf-8")
    assert "CVE-2024-1086" in md.split("## P1")[1].split("## P2")[0] and "driver not built" in md      # 核心的列沒有消失
    assert "section 8.7" not in md and "| Metric | Total | OS kernel (`kernel-vulnerabilities.md`) | Other components |" in md
    assert "the project's risk-assessment template has no kernel section" in md
    assert any("text.kernel_section" in w for w in s["config_warnings"]) and "text.kernel_section" in r.stderr
    assert s["counts"]["kernel"]["risk_assessment_layout"] == "main_tables" and (reports / "kernel-vulnerabilities.md").exists()
    assert "section 8, where the kernel rows are also listed" in (reports / "kernel-vulnerabilities.md").read_text(encoding="utf-8")
    # 範本有引用 text.kernel_section：照樣分開列
    proj2 = make_project(tmp_path / "p2", templates={"risk-assessment": tpl + "{{ text.kernel_section }}\n"})
    r, s, reports = run(proj2, kernel_scan(tmp_path / "s2"))
    md = (reports / "risk-assessment.md").read_text(encoding="utf-8")
    assert "CVE-2024-1086" not in md.split("## P1")[1].split("## P2")[0] and s["counts"]["kernel"]["risk_assessment_layout"] == "separate"
    assert not any("text.kernel_section" in w for w in s["config_warnings"])


def test_kernelcheck_load_error_is_clean_fail(tmp_path, monkeypatch):
    lib = tmp_path / "tools" / "pilot" / "lib"
    lib.mkdir(parents=True)
    (lib / "kernelcheck.py").write_text("raise RuntimeError('boom')\n", encoding="utf-8")
    monkeypatch.setattr(cr, "ROOT", tmp_path)
    monkeypatch.setattr(cr, "_KC", None)
    with pytest.raises(cr.Fail, match="kernelcheck.py.*RuntimeError"):
        cr.kernelcheck()
    (lib / "kernelcheck.py").unlink()
    with pytest.raises(cr.Fail, match="kernelcheck.py"):
        cr.kernelcheck()


def test_kernel_map_step_failed_text(tmp_path):
    r, s, reports = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s", findings=KFINDINGS[8:], stages={"C-kernel-l4t-map": "FAIL"}))
    k = section_87((reports / "risk-assessment.md").read_text(encoding="utf-8"))
    assert "kernel mapping step failed (`C-kernel-l4t-map` FAIL" in k and "The SBOM contains a Jetson Linux" not in k
    assert "NOT assessed" in k and s["counts"]["kernel"]["section"] == "not_assessed"


# ---------- 分級的嚴重度：供應商評級優先（NVIDIA 公告 → Ubuntu priority → DT／NVD） ----------

def sev_rows(findings, upri=None, gpri=None, nvun=None, sources=None, p2=None):
    cfg = json.loads(json.dumps(MIN_CFG))
    vp = cfg.setdefault("vulnerability_policy", {})
    if sources is not None:
        vp["severity_sources"] = sources
    if p2:
        vp.setdefault("tiers", {})["p2"] = p2
    idx, _ = cr.grype_index({"matches": []})
    return cr.build_rows(findings, cr.policy_of(cfg), idx, True, sev={"upri": upri, "gpri": gpri, "nvun": nvun})


def test_ubuntu_priority_before_nvd():
    """同一個 CVE：Ubuntu 是 medium、NVD 9.8 → MEDIUM、P3（記來源）；KEV 的 medium → P1；只有 NVD 的照 CVSS；untriaged → NVD。"""
    deb = DEB.format("openssl", "3.0.13-0ubuntu3.11")
    fs = [finding("openssl", "3.0.13-0ubuntu3.11", "CVE-2026-1001", "NVD", "CRITICAL", cvss=9.8, purl=deb),
          finding("openssl", "3.0.13-0ubuntu3.11", "CVE-2026-1002", "NVD", "CRITICAL", kev=True, cvss=9.8, purl=deb),
          finding("requests", "2.0", "CVE-2026-1003", "NVD", "HIGH", cvss=8.0, purl="pkg:pypi/requests@2.0"),
          finding("openssl", "3.0.13-0ubuntu3.11", "CVE-2026-1004", "NVD", "HIGH", cvss=8.0, purl=deb)]
    rows = sev_rows(fs, upri={"CVE-2026-1001": "medium", "CVE-2026-1002": "medium", "CVE-2026-1003": "low"})
    r = row_of(rows, "CVE-2026-1001")
    assert (r["severity"], r["severity_source"], r["severity_dt"], r["tier"]) == ("MEDIUM", "ubuntu-priority", "CRITICAL", "p3")
    assert cr.severity_text(r) == "Ubuntu priority (medium); Dependency-Track CRITICAL"
    assert (row_of(rows, "CVE-2026-1002")["severity"], row_of(rows, "CVE-2026-1002")["tier"]) == ("MEDIUM", "p1")      # KEV
    r = row_of(rows, "CVE-2026-1003")                         # PyPI：Ubuntu priority 不適用
    assert (r["severity"], r["severity_source"], r["tier"]) == ("HIGH", "nvd-cvss", "p2") and cr.severity_text(r) == "NVD"
    r = row_of(rows, "CVE-2026-1004")                         # untriaged（不在對應表）→ NVD
    assert (r["severity"], r["severity_source"], r["tier"]) == ("HIGH", "nvd-cvss", "p2")


def test_ubuntu_priority_falls_back_to_grype_and_policy_order():
    deb = DEB.format("zlib1g", "1.3")
    fs = [finding("zlib1g", "1.3", "UBUNTU-CVE-2026-2001", "OSV", "HIGH", [{"cveId": "CVE-2026-2001"}], cvss=7.5, purl=deb)]
    r = sev_rows(fs, gpri={"CVE-2026-2001": "negligible"})[0]
    assert (r["severity"], r["severity_source"], r["tier"]) == ("LOW", "ubuntu-priority-grype", "p3")
    assert cr.severity_text(r) == "Ubuntu priority (via Grype) (negligible); Dependency-Track HIGH"
    r = sev_rows(fs, upri={"CVE-2026-2001": "high"}, gpri={"CVE-2026-2001": "low"})[0]      # 鏡像優先於 Grype
    assert (r["severity"], r["severity_source"]) == ("HIGH", "ubuntu-priority")
    r = sev_rows(fs, upri={"CVE-2026-2001": "low"}, sources=["nvd"])[0]                     # 舊行為：只看 DT／NVD
    assert (r["severity"], r["severity_source"], r["tier"]) == ("HIGH", "other", "p2")
    # cvss_min 只在用 DT／NVD 的值時套用：Ubuntu priority 是 low 時 CVSS 7.5 不能把它拉回 P2
    p2 = {"label": "Next release", "severities": ["CRITICAL", "HIGH"], "cvss_min": 7.0}
    assert sev_rows(fs, upri={"CVE-2026-2001": "low"}, p2=p2)[0]["tier"] == "p3"
    assert sev_rows(fs, upri={"CVE-2026-2001": "low"}, sources=["nvd"], p2=dict(p2, severities=[]))[0]["tier"] == "p2"


def test_nvidia_bulletin_rating_first_unreviewed_only_shown():
    l4t = DEB.format("nvidia-l4t-kernel", "6.8.12-tegra-39.2.1")
    nv = finding("nvidia-l4t-kernel", "6.8.12-tegra-39.2.1", "CVE-2026-24154", "NVIDIA", "MEDIUM", [{"cveId": "CVE-2026-24154"}], purl=l4t)
    dt = finding("nvidia-l4t-kernel", "6.8.12-tegra-39.2.1", "CVE-2026-24154", "NVD", "CRITICAL", cvss=9.8, purl=l4t)
    r = sev_rows([nv, dt], upri={"CVE-2026-24154": "high"})[0]
    assert (r["severity"], r["severity_source"], r["tier"]) == ("MEDIUM", "nvidia-bulletin", "p3")
    # 對照表未審核的評級：只顯示，分級照下一個來源
    r = sev_rows([dt], nvun={"CVE-2026-24154": ["5797 LOW"]})[0]
    assert (r["severity"], r["severity_source"], r["tier"]) == ("CRITICAL", "nvd-cvss", "p2")
    assert cr.severity_text(r) == "NVD; NVIDIA bulletin not reviewed, not used: 5797 LOW"
    assert cr.nvidia_unreviewed({"unreviewed_would_match": [{"bulletin": "5797", "cve": "CVE-1", "severity": "low"}, {"cve": "CVE-2"}]}) \
        == {"CVE-1": ["5797 LOW"]}


def test_severity_source_helpers_and_policy_errors():
    g = {"matches": [
        {"vulnerability": {"id": "CVE-2026-9001", "namespace": "ubuntu:distro:ubuntu:24.04", "severity": "Medium"}},
        {"vulnerability": {"id": "CVE-2026-9001", "namespace": "ubuntu:distro:ubuntu:24.04", "severity": "High"}},     # 最嚴重的
        {"vulnerability": {"id": "CVE-2026-9002", "namespace": "ubuntu:distro:ubuntu:24.04", "severity": "Unknown"}},  # untriaged
        {"vulnerability": {"id": "CVE-2026-9003", "namespace": "nvd:cpe", "severity": "Critical"}},                   # 不是 Ubuntu
        {"vulnerability": {"id": "GHSA-x", "namespace": "github:language:python", "severity": "Low"}}]}
    assert cr.grype_ubuntu_severity(g) == {"CVE-2026-9001": "high"}
    assert cr.ubuntu_priority_map({"status": "OK", "cves": {"CVE-1": {"priority": "low"}, "CVE-2": {"priority": "untriaged"}}}) == {"CVE-1": "low"}
    assert cr.ubuntu_priority_map({"status": "NOT_RUN", "cves": {}}) is None and cr.ubuntu_priority_map(None) is None
    assert cr.policy_of({})["severity_sources"] == ["vendor", "distro", "nvd"]                  # 沒寫＝供應商評級優先
    for bad in (["vendor", "distro"], ["nvd", "vendor"], ["nvd", "nvd"]):
        assert cr.policy_errors({"vulnerability_policy": {"severity_sources": bad}}), bad
    assert not cr.policy_errors({"vulnerability_policy": {"severity_sources": ["distro", "nvd"]}})


def test_report_shows_severity_source(tmp_path):
    deb = DEB.format("openssl", "3.0.13-0ubuntu3.11")
    fs = [finding("openssl", "3.0.13-0ubuntu3.11", "CVE-2026-1001", "NVD", "CRITICAL", cvss=9.8, purl=deb),
          finding("requests", "2.0", "CVE-2026-1003", "NVD", "HIGH", cvss=8.0, purl="pkg:pypi/requests@2.0")]
    scan = make_scan(tmp_path / "s", findings=fs, grype={"matches": []})
    r, s, reports = run(make_project(tmp_path / "p"), scan)
    md = (reports / "risk-assessment.md").read_text(encoding="utf-8")
    assert "| Severity | Severity source | CVSS |" in md
    assert "Ubuntu priority NOT available from the Ubuntu OSV mirror (no `scan/ubuntu-priority.json` in the scan output)" in md
    assert s["counts"]["severity_sources"]["ubuntu_priority"] == "not_available" and s["counts"]["p2"] == 2
    write_json(scan / "scan" / "ubuntu-priority.json", {"schema": "sca-center-ubuntu-priority/1", "status": "OK",
                                                         "mirror": {"fetched_utc": "2026-11-04T00:00:00Z"},
                                                         "cves": {"CVE-2026-1001": {"priority": "medium", "record": "UBUNTU-CVE-2026-1001"}}})
    r, s, reports = run(make_project(tmp_path / "p2"), scan)
    md = (reports / "risk-assessment.md").read_text(encoding="utf-8")
    row = next(x for x in md.split("### 8.6")[1].splitlines() if "CVE-2026-1001" in x)
    assert "| MEDIUM | Ubuntu priority (medium); Dependency-Track CRITICAL |" in row
    assert "Ubuntu priority from the Ubuntu OSV mirror (`scan/ubuntu-priority.json`, mirror fetched 2026-11-04T00:00:00Z)" in md
    c = s["counts"]
    assert (c["p2"], c["p3"]) == (1, 1) and c["severity_sources"]["by_source"] == {"nvd-cvss": 1, "ubuntu-priority": 1}
    assert c["severity_sources"]["policy"] == ["vendor", "distro", "nvd"] and s["inputs"]["scan/ubuntu-priority.json"]["sha256"]


# ---------- 審查：高 1、中 1–4、低 ----------

def test_nvd_only_policy_keeps_nvidia_bulletin_rows():
    """高 1：["nvd"]（舊行為）或沒有 vendor 的順序時，只有 NVIDIA 公告 finding 的列照舊用公告的評級（以前是全部來源取最嚴重），不變成 UNASSIGNED。"""
    l4t = DEB.format("nvidia-l4t-kernel", "6.8.12-tegra-39.2.1")
    nv = finding("nvidia-l4t-kernel", "6.8.12-tegra-39.2.1", "CVE-2026-24154", "NVIDIA", "HIGH", [{"cveId": "CVE-2026-24154"}], purl=l4t)
    for src in (["nvd"], ["distro", "nvd"]):
        r = sev_rows([nv], sources=src)[0]
        assert (r["severity"], r["severity_source"], r["tier"]) == ("HIGH", "other", "p2"), src
    # cvss_min 也照舊套用在這種列
    p2 = {"label": "Next release", "severities": [], "cvss_min": 4.0}
    assert sev_rows([nv], sources=["nvd"], p2=p2)[0]["tier"] == "p2"
    assert sev_rows([nv])[0]["severity_source"] == "nvidia-bulletin"              # 預設順序：vendor


def test_ubuntu_priority_must_cover_every_cve_of_the_row():
    """中 1：GHSA 有兩個 CVE 別名、只有一個有 Ubuntu priority（low）→ 不能只用 low：取 low 與下一個來源（DT CRITICAL）較嚴重的。"""
    deb = DEB.format("openssl", "3.0.13-0ubuntu3.11")
    gh = finding("openssl", "3.0.13-0ubuntu3.11", "GHSA-aaaa-bbbb-cccc", "GITHUB", "CRITICAL",
                 [{"cveId": "CVE-2026-9010"}, {"cveId": "CVE-2026-9011"}], cvss=9.8, purl=deb)
    r = sev_rows([gh], upri={"CVE-2026-9010": "low"})[0]
    assert (r["severity"], r["severity_source"], r["tier"]) == ("CRITICAL", "other", "p2")
    assert r["severity_detail"]["ubuntu-priority-missing"] == ["CVE-2026-9011"]
    assert cr.severity_text(r) == "other; no Ubuntu priority for CVE-2026-9011, so the more severe next source is used (Ubuntu priority low)"
    # 兩個都有 → 只用 Ubuntu priority（取最嚴重的）；鏡像一個、Grype 一個也算都有
    r = sev_rows([gh], upri={"CVE-2026-9010": "low", "CVE-2026-9011": "medium"})[0]
    assert (r["severity"], r["severity_source"], r["tier"]) == ("MEDIUM", "ubuntu-priority", "p3")
    r = sev_rows([gh], upri={"CVE-2026-9010": "low"}, gpri={"CVE-2026-9011": "medium"})[0]
    assert (r["severity"], r["severity_source"]) == ("MEDIUM", "ubuntu-priority-grype")
    assert r["severity_detail"]["ubuntu-priority"] == "low" and r["severity_detail"]["ubuntu-priority-grype"] == "medium"
    # 沒涵蓋全部、但 Ubuntu priority 比較嚴重 → 仍用 Ubuntu priority
    low = finding("openssl", "3.0.13-0ubuntu3.11", "GHSA-dddd-eeee-ffff", "GITHUB", "LOW",
                  [{"cveId": "CVE-2026-9012"}, {"cveId": "CVE-2026-9013"}], cvss=3.0, purl=deb)
    r = sev_rows([low], upri={"CVE-2026-9012": "high"})[0]
    assert (r["severity"], r["severity_source"], r["tier"]) == ("HIGH", "ubuntu-priority", "p2")
    assert cr.severity_text(r) == "Ubuntu priority (high); no Ubuntu priority for CVE-2026-9013; Dependency-Track LOW"


def test_nvidia_debs_do_not_use_ubuntu_priority():
    """中 3：nvidia-l4t-* 與 publisher 是 NVIDIA 的 deb，purl 也是 pkg:deb/ubuntu/，但不是 Ubuntu 打包的 → 不用 Ubuntu priority。"""
    cuda = DEB.format("nvidia-l4t-cuda", "39.2.1-20260101")
    f = finding("nvidia-l4t-cuda", "39.2.1-20260101", "CVE-2026-9020", "NVD", "CRITICAL", cvss=9.8, purl=cuda)
    r = sev_rows([f], gpri={"CVE-2026-9020": "low"}, nvun={"CVE-2026-9020": ["5800 HIGH"]})[0]
    assert (r["severity"], r["severity_source"], r["tier"]) == ("CRITICAL", "nvd-cvss", "p2")
    assert "ubuntu-priority-grype" not in r["severity_detail"]
    trt = DEB.format("libnvinfer10", "10.3.0-1+cuda12.5")
    comps = [{"name": "libnvinfer10", "purl": trt, "publisher": "NVIDIA Corporation"},
             {"name": "openssl", "purl": DEB.format("openssl", "3.0.13"), "publisher": "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>"},
             {"name": "x", "purl": "pkg:pypi/x@1", "publisher": "NVIDIA"}]
    nvd = cr.nvidia_debs(comps)
    assert nvd == {trt.split("?", 1)[0]}
    g = finding("libnvinfer10", "10.3.0-1+cuda12.5", "CVE-2026-9021", "NVD", "HIGH", cvss=8.0, purl=trt)
    idx, _ = cr.grype_index({"matches": []})
    pol = cr.policy_of(MIN_CFG)
    r = cr.build_rows([g], pol, idx, True, sev={"gpri": {"CVE-2026-9021": "low"}, "nvdebs": nvd})[0]
    assert (r["severity"], r["severity_source"]) == ("HIGH", "nvd-cvss")
    r = cr.build_rows([g], pol, idx, True, sev={"gpri": {"CVE-2026-9021": "low"}})[0]                  # 沒有 SBOM 的資訊時（對照）
    assert r["severity_source"] == "ubuntu-priority-grype"
    # Ubuntu 套件裝的 Python 模組：看擁有它的 deb
    assert cr.ubuntu_packaged({"purl": "pkg:pypi/brotli@1.1.0", "deb_python": {"owner": {"purl": DEB.format("python3-brotli", "1.1.0"), "name": "python3-brotli"}}})
    assert not cr.ubuntu_packaged({"purl": "pkg:pypi/x@1", "deb_python": {"owner": {"purl": DEB.format("nvidia-l4t-x", "1"), "name": "nvidia-l4t-x"}}})
    assert not cr.ubuntu_packaged({"purl": "pkg:pypi/x@1"}) and not cr.ubuntu_packaged({"purl": "pkg:deb/debian/zlib1g@1.3"})


def test_grype_ubuntu_priority_kept_when_mirror_differs():
    """中 4：鏡像 low、Grype high：用鏡像的，但 Grype 的值記在 severity_detail，欄位寫出不一致。"""
    deb = DEB.format("zlib1g", "1.3")
    fs = [finding("zlib1g", "1.3", "UBUNTU-CVE-2026-2001", "OSV", "HIGH", [{"cveId": "CVE-2026-2001"}], cvss=7.5, purl=deb)]
    r = sev_rows(fs, upri={"CVE-2026-2001": "low"}, gpri={"CVE-2026-2001": "high"})[0]
    assert (r["severity"], r["severity_source"]) == ("LOW", "ubuntu-priority")
    assert r["severity_detail"]["ubuntu-priority-grype-differs"] == {"CVE-2026-2001": "high"}
    assert cr.severity_text(r) == "Ubuntu priority (low); Grype's Ubuntu priority differs: CVE-2026-2001 high; Dependency-Track HIGH"
    r = sev_rows(fs, upri={"CVE-2026-2001": "low"}, gpri={"CVE-2026-2001": "low"})[0]           # 一致 → 不多寫
    assert "ubuntu-priority-grype-differs" not in r["severity_detail"]


def test_report_names_default_or_legacy_severity_sources(tmp_path):
    """中 2：config 沒有 severity_sources → 8.3 與 summary.json 寫明用預設（供應商優先）；低 1：["nvd"] 寫明是舊的模式；
    低 2：沒有 ubuntu-priority.json 時依 Grype 的狀況寫。"""
    deb = DEB.format("openssl", "3.0.13-0ubuntu3.11")
    fs = [finding("openssl", "3.0.13-0ubuntu3.11", "CVE-2026-1001", "NVD", "CRITICAL", cvss=9.8, purl=deb)]
    g = {"matches": [{"vulnerability": {"id": "CVE-2026-1001", "namespace": "ubuntu:distro:ubuntu:24.04", "severity": "Medium"},
                      "artifact": {"name": "openssl", "version": "3.0.13-0ubuntu3.11", "type": "deb"}}]}
    r, s, reports = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s", findings=fs, grype=g))
    md = (reports / "risk-assessment.md").read_text(encoding="utf-8")
    assert "The configuration does not set `vulnerability_policy.severity_sources`, so the default order (vendor rating first) is used." in md
    assert "(no `scan/ubuntu-priority.json` in the scan output); Grype's Ubuntu matches were used instead." in md
    assert s["counts"]["severity_sources"]["configured"] is False
    r, s, reports = run(make_project(tmp_path / "p2"), make_scan(tmp_path / "s2", findings=fs, grype=None))
    assert "; there is no Grype result either (`scan/grype.json`)." in (reports / "risk-assessment.md").read_text(encoding="utf-8")
    cfg = json.loads(json.dumps(EXAMPLE))
    cfg.setdefault("vulnerability_policy", {})["severity_sources"] = ["nvd"]
    r, s, reports = run(make_project(tmp_path / "p3", cfg), make_scan(tmp_path / "s3", findings=fs, grype=g))
    md = (reports / "risk-assessment.md").read_text(encoding="utf-8")
    assert "as before the vendor-first order; the policy sets `severity_sources` to [\"nvd\"], so the Ubuntu priority is not used." in md
    assert "does not set `vulnerability_policy.severity_sources`" not in md
    assert s["counts"]["severity_sources"]["configured"] is True and s["counts"]["p2"] >= 1


# ---------- EPSS：機率、只顯示的其他來源（下一階段第 1 項；現行分級不變） ----------

def epss_finding(name, vid, prob, pct, source="NVD", severity="MEDIUM", aliases=(), purl=None):
    f = finding(name, "1.0", vid, source, severity, aliases, purl=purl or f"pkg:pypi/{name}@1.0")
    f["vulnerability"].update(epssScore=prob, epssPercentile=pct)
    return f


def test_grype_epss_per_cve():
    g = {"matches": [
        {"vulnerability": {"id": "GHSA-aaaa-bbbb-cccc", "epss": [{"cve": "CVE-2026-7001", "epss": 0.07, "percentile": 0.94, "date": "2026-10-20"}]}},
        {"vulnerability": {"id": "CVE-2026-7001", "epss": [{"cve": "CVE-2026-7001", "epss": 0.21, "percentile": 0.97, "date": "2026-10-21"}]}},
        {"vulnerability": {"id": "UBUNTU-CVE-2026-7002", "epss": [{"cve": "UBUNTU-CVE-2026-7002", "epss": 0.5}]}},     # 百分位沒有也收
        {"vulnerability": {"id": "X", "epss": [{"cve": "GHSA-xxxx", "epss": 0.9, "percentile": 0.99},                 # 不是 CVE
                                               {"cve": "CVE-2026-7003", "epss": 1.5, "percentile": 0.5},              # 機率超出 0–1
                                               {"cve": "CVE-2026-7004", "epss": True, "percentile": 0.5},             # bool 不是數字
                                               {"cve": "CVE-2026-7005", "epss": 0.1, "percentile": 2},                # 百分位超出
                                               "bad", {"epss": 0.3}]}},
        {"vulnerability": {"id": "Y", "epss": None}}, "not a match", {"vulnerability": None},
    ]}
    assert cr.grype_epss(g) == {"CVE-2026-7001": {"probability": 0.21, "percentile": 0.97, "date": "2026-10-21"},
                                "CVE-2026-7002": {"probability": 0.5, "percentile": None, "date": None}}
    assert cr.grype_epss(None) == {} and cr.grype_epss({"matches": None}) == {}


def test_epss_probability_rule_is_off_by_default():
    """預設政策沒有機率條件：機率 0.15、百分位 0.5 的 MEDIUM 照舊是 P3；設了 epss_probability_min 0.10 才是 P1。"""
    fs = [epss_finding("lib", "CVE-2026-7101", 0.15, 0.5), epss_finding("low", "CVE-2026-7102", 0.05, 0.95)]
    rows = rows_for(findings=fs)
    assert [(r["id"], r["tier"]) for r in rows] == [("CVE-2026-7102", "p1"), ("CVE-2026-7101", "p3")]
    cfg = dict(MIN_CFG, vulnerability_policy={"tiers": {"p1": {"epss_probability_min": 0.1}}})
    rows = rows_for(cfg=cfg, findings=fs)
    assert {r["id"]: r["tier"] for r in rows} == {"CVE-2026-7101": "p1", "CVE-2026-7102": "p1"}     # 百分位條件照留
    pol = cr.policy_of(cfg)
    assert cr.rule_text("p1", pol) == ("listed in a Known Exploited Vulnerabilities catalogue (CISA/ENISA KEV) OR EPSS percentile ≥ 0.9 "
                                       "OR EPSS probability ≥ 0.1")
    assert "probability" not in cr.rule_text("p1", cr.policy_of(MIN_CFG))


def test_epss_probability_min_must_be_0_to_1(tmp_path):
    cfg = json.loads(json.dumps(EXAMPLE))
    cfg.setdefault("vulnerability_policy", {}).setdefault("tiers", {}).setdefault("p1", {})["epss_probability_min"] = 10
    r, s, reports = run(make_project(tmp_path / "p", cfg), make_scan(tmp_path / "s"))
    assert r.returncode == 1 and s["status"] == "FAIL" and "epss_probability_min" in r.stdout


def test_epss_of_the_same_cve_elsewhere_is_shown_not_tiered():
    """DT 的 UBUNTU-CVE 紀錄沒有 EPSS，同一個 CVE 的 NVD 紀錄（別的元件）百分位 0.99：Ubuntu 那一列並列顯示，但分級照舊只看自己的 DT（P3）。
    使用者決定：新分級不用 EPSS，只顯示。"""
    ub = finding("linux", "6.8.0-1", "UBUNTU-CVE-2026-7201", "OSV", "LOW")
    nvd = epss_finding("linux-src", "CVE-2026-7201", 0.6, 0.99)
    rows = rows_for(findings=[ub, nvd])
    u = next(r for r in rows if r["component"] == "linux")
    assert (u["epss"], u["epss_pct"], u["tier"]) == (None, None, "p3")
    assert u["epss_other"] == [{"source": "same CVE", "cve": "CVE-2026-7201", "probability": 0.6, "percentile": 0.99, "date": None}]
    assert cr.epss_text(u) == "same CVE 0.6000 (p0.990) (other sources: not used for tiers)"
    n = next(r for r in rows if r["component"] == "linux-src")
    assert n["tier"] == "p1" and "epss_other" not in n and cr.epss_text(n) == "0.6000 (p0.990)"
    idx, _ = cr.grype_index(GRYPE)
    pol = cr.policy_of(MIN_CFG)
    # Grype 也有：兩個來源都並列，Grype 帶分數日期
    more = {"CVE-2026-7201": {"probability": 0.7, "percentile": 0.995, "date": "2026-10-20"}}
    u = next(r for r in cr.build_rows([ub, nvd], pol, idx, True, epss_more=more) if r["component"] == "linux")
    assert [x["source"] for x in u["epss_other"]] == ["same CVE", "Grype"] and u["tier"] == "p3"
    assert cr.epss_text(u) == "same CVE 0.6000 (p0.990); Grype 0.7000 (p0.995) [2026-10-20] (other sources: not used for tiers)"
    # 自己有、Grype 不同 → 並列；一樣 → 不寫
    own = epss_finding("lib", "CVE-2026-7202", 0.1, 0.5)
    r = cr.build_rows([own], pol, idx, True, epss_more={"CVE-2026-7202": {"probability": 0.2, "percentile": 0.95, "date": None}})[0]
    assert (r["epss"], r["epss_pct"], r["tier"]) == (0.1, 0.5, "p3")
    assert cr.epss_text(r) == "0.1000 (p0.500); Grype 0.2000 (p0.950) (other sources: not used for tiers)"
    r = cr.build_rows([own], pol, idx, True, epss_more={"CVE-2026-7202": {"probability": 0.1, "percentile": 0.5, "date": None}})[0]
    assert "epss_other" not in r
    # 一列有兩個 CVE 時寫是哪一個 CVE 的
    gh = finding("lib2", "1.0", "GHSA-gggg-gggg-gggg", "GITHUB", "LOW", [{"cveId": "CVE-2026-7203"}, {"cveId": "CVE-2026-7204"}], purl="pkg:pypi/lib2@1.0")
    r = cr.build_rows([gh], pol, idx, True, epss_more={"CVE-2026-7204": {"probability": 0.2, "percentile": None, "date": None}})[0]
    assert cr.epss_text(r) == "Grype 0.2000 for CVE-2026-7204 (other sources: not used for tiers)"


def test_epss_of_a_record_with_two_cves_is_not_spread():
    """GHSA 有兩個 CVE 別名：分不出分數是哪一個 CVE 的，不給其他列。"""
    ghsa = epss_finding("lib", "GHSA-aaaa-bbbb-cccc", 0.5, 0.99, "GITHUB", aliases=[{"cveId": "CVE-2026-7301"}, {"cveId": "CVE-2026-7302"}])
    ub = finding("linux", "6.8.0-1", "UBUNTU-CVE-2026-7302", "OSV", "LOW")
    one = epss_finding("x", "GHSA-dddd-eeee-ffff", 0.3, 0.9, "GITHUB", aliases=[{"cveId": "CVE-2026-7303"}])
    ub3 = finding("linux", "6.8.0-1", "UBUNTU-CVE-2026-7303", "OSV", "LOW")
    rows = rows_for(findings=[ghsa, ub, one, ub3])
    assert "epss_other" not in next(r for r in rows if r["id"] == "CVE-2026-7302" and r["component"] == "linux")
    r3 = next(r for r in rows if r["id"] == "CVE-2026-7303" and r["component"] == "linux")
    assert r3["epss_other"][0]["probability"] == 0.3 and r3["tier"] == "p3"


def test_epss_text_without_percentile():
    assert cr.epss_text({"epss": 0.05, "epss_pct": None}) == "0.0500"
    assert cr.epss_text({"epss": None, "epss_pct": None}) is None
    assert cr.epss_text({"epss": None, "epss_pct": 0.5}) == "— (p0.500)"


def test_report_explains_epss_and_counts_other_sources(tmp_path):
    ub = finding("accountsservice", "23.13.9-2ubuntu6", "UBUNTU-CVE-2026-61897", "OSV", "HIGH")
    g = json.loads(json.dumps(GRYPE))
    g["matches"].append({"vulnerability": {"id": "CVE-2026-61897", "epss": [{"cve": "CVE-2026-61897", "epss": 0.3, "percentile": 0.97,
                                                                            "date": "2026-10-20"}]},
                         "artifact": {"name": "accountsservice", "version": "23.13.9-2ubuntu6", "type": "deb"}})
    fs = [f for f in FINDINGS if f["vulnerability"]["vulnId"] != "UBUNTU-CVE-2026-61897"] + [ub]
    r, s, reports = run(make_project(tmp_path / "p", json.loads(json.dumps(EXAMPLE))), make_scan(tmp_path / "s", findings=fs, grype=g))
    md = (reports / "risk-assessment.md").read_text(encoding="utf-8")
    assert "| EPSS probability (percentile) |" in md
    row = next(x for x in md.splitlines() if "CVE-2026-61897" in x and x.startswith("| "))
    assert "| Grype 0.3000 (p0.970) [2026-10-20] (other sources: not used for tiers) |" in row
    # 照舊是 P2（HIGH）：Grype 的百分位 0.97 不拿來分級
    assert "CVE-2026-61897" in md.split("### 8.5")[1].split("### 8.6")[0]
    s83 = md.split("### 8.3")[1].split("### 8.4")[0]
    assert "the same percentile does not mean the same probability over time" in s83
    # openssl 3.0.13-0ubuntu3.12 的 CVE-2025-0003 沒有 EPSS、3.0.13-0ubuntu3.11 的有 → same CVE
    assert ("EPSS rules in the tiers: P1 percentile ≥ 0.9, evaluated on the EPSS of the row's own Dependency-Track findings" in s83)
    assert ("For 2 rows another source has a different EPSS for the same CVE (Grype 1, same CVE 1; Grype score date 2026-10-20; "
            "2 of these rows have no EPSS of their own): it is shown next to the row's value and is not used for the tiers.") in s83
    e = s["counts"]["epss"]
    assert (e["other_sources_shown"], e["only_other_sources"], e["by_source"]) == (2, 2, {"Grype": 1, "same CVE": 1})
    assert e["grype_score_dates"] == ["2026-10-20"]
    assert e["rules"] == {"p1": {"epss_probability_min": None, "epss_percentile_min": 0.9},
                          "p2": {"epss_probability_min": None, "epss_percentile_min": None}}


def test_grype_kev_on_a_ghsa_only_row(tmp_path):
    """審查（低）：DT 的列只有 GHSA（沒有 CVE 別名），Grype 同一個 GHSA 帶 KEV 的 CVE-Y → 那一列標 KEV，原因文字不說 CVE-Y「不在風險表」。"""
    gh = finding("lib", "1.0", "GHSA-kkkk-kkkk-kkkk", "GITHUB", "LOW", purl="pkg:pypi/lib@1.0")
    g = {"matches": [{"vulnerability": {"id": "GHSA-kkkk-kkkk-kkkk", "knownExploited": [{"cve": "CVE-2026-8801"}]},
                      "relatedVulnerabilities": [{"id": "CVE-2026-8801"}], "artifact": {"name": "lib", "version": "1.0", "type": "python"}}]}
    assert cr.grype_kev_map(g) == {"CVE-2026-8801": {"GHSA-KKKK-KKKK-KKKK"}} and cr.grype_kev(g) == {"CVE-2026-8801"}
    r, s, reports = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s", findings=FINDINGS + [gh], grype=g))
    md = (reports / "risk-assessment.md").read_text(encoding="utf-8")
    row = next(x for x in md.split("### 8.4")[1].split("### 8.5")[0].splitlines() if "GHSA-kkkk-kkkk-kkkk" in x)
    assert "| YES (Grype) |" in row
    assert "CVE-2026-8801" not in s["documents"]["risk-assessment"]["detail"] and s["counts"]["kev_grype_only_not_in_table"] == []


# ---------- 審查：中 1、低 1–4 ----------

def test_grype_kev_by_ghsa_id_only_for_rows_without_cve():
    """中 1 重現 1：DT 有 GHSA（別名 0301、0302）與 NVD 0302；Grype 同一個 GHSA 的 KEV 是 0301 → 只有 0301 那一列是 KEV，0302 不是。"""
    gh = finding("lib", "1.0", "GHSA-aaaa-bbbb-cccc", "GITHUB", "HIGH", [{"cveId": "CVE-2026-0301"}, {"cveId": "CVE-2026-0302"}],
                 purl="pkg:pypi/lib@1.0")
    nvd = finding("lib", "1.0", "CVE-2026-0302", "NVD", "HIGH", [{"ghsaId": "GHSA-aaaa-bbbb-cccc"}], purl="pkg:pypi/lib@1.0")
    g = {"matches": [{"vulnerability": {"id": "GHSA-aaaa-bbbb-cccc", "knownExploited": [{"cve": "CVE-2026-0301"}]},
                      "artifact": {"name": "lib", "version": "1.0", "type": "python"}}]}
    gm = cr.grype_kev_map(g)
    more = {c: {"Grype"} for c in gm} | {i: {"Grype"} for ids in gm.values() for i in ids}
    idx, _ = cr.grype_index(g)
    rows = cr.build_rows([gh, nvd], cr.policy_of(MIN_CFG), idx, True, kev_more=more)
    by = {r["id"]: r for r in rows}
    assert by["CVE-2026-0301"]["kev"] is True and by["CVE-2026-0301"]["kev_sources"] == ["Grype"]
    assert by["CVE-2026-0302"]["kev"] is False and by["CVE-2026-0302"]["kev_sources"] == []


def test_grype_kev_on_ghsa_row_with_another_cve_is_named_not_in_table(tmp_path):
    """中 1 重現 2：DT 的 GHSA 有別名 0311，Grype 同 GHSA 的 KEV 是 0312 → 0311 那一列不是 KEV，0312 點名「不在風險表」。"""
    gh = finding("lib", "1.0", "GHSA-dddd-eeee-ffff", "GITHUB", "LOW", [{"cveId": "CVE-2026-0311"}], purl="pkg:pypi/lib@1.0")
    g = {"matches": [{"vulnerability": {"id": "GHSA-dddd-eeee-ffff", "knownExploited": [{"cve": "CVE-2026-0312"}]},
                      "relatedVulnerabilities": [{"id": "CVE-2026-0312"}], "artifact": {"name": "lib", "version": "1.0", "type": "python"}}]}
    r, s, reports = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s", findings=FINDINGS + [gh], grype=g))
    md = (reports / "risk-assessment.md").read_text(encoding="utf-8")
    row = next(x for x in md.splitlines() if "CVE-2026-0311" in x and x.startswith("| "))
    assert "| no |" in row and "YES (Grype)" not in row
    assert s["counts"]["kev_grype_only_not_in_table"] == ["CVE-2026-0312"]


def test_dt_epss_out_of_range_or_nan_is_ignored():
    """低 1：DT 的 epssScore／epssPercentile 超出 0–1 或 NaN 不收（設了機率規則也不會因此變 P1）。"""
    cfg = dict(MIN_CFG, vulnerability_policy={"tiers": {"p1": {"epss_probability_min": 0.1}}})
    for bad in (1.5, -0.2, float("nan"), float("inf")):
        r = rows_for(cfg=cfg, findings=[epss_finding("lib", "CVE-2026-0401", bad, bad)])[0]
        assert (r["epss"], r["epss_pct"], r["tier"]) == (None, None, "p3"), bad
        assert cr.epss_text(r) is None
    # 一筆壞、一筆好：結果和順序無關
    good, badf = epss_finding("lib", "CVE-2026-0402", 0.05, 0.5), epss_finding("lib", "CVE-2026-0402", float("nan"), 0.99)
    for fs in ([good, badf], [badf, good]):
        r = rows_for(findings=fs)[0]
        assert (r["epss"], r["epss_pct"]) == (0.05, 0.99)


def test_nan_in_numbers_is_a_config_error():
    """低 2：config 的 NaN／Infinity（Python 的 JSON 讀得進來）要 FAIL，不能讓規則永遠不成立；所有數字欄位都一樣。"""
    for v in (float("nan"), float("inf"), float("-inf")):
        errs, _ = cr.validate(dict(MIN_CFG, vulnerability_policy={"tiers": {"p1": {"epss_probability_min": v}}}))
        assert errs == ["vulnerability_policy.tiers.p1.epss_probability_min：要是有限的數字（不能是 NaN 或 Infinity）"], v
        errs, _ = cr.validate(dict(MIN_CFG, supplier={"notification": {"exploited_hours": v}}))
        assert "supplier.notification.exploited_hours：要是有限的數字（不能是 NaN 或 Infinity）" in errs, v
    assert cr.validate(dict(MIN_CFG, vulnerability_policy={"tiers": {"p1": {"epss_probability_min": 0.1}}}))[0] == []


def test_own_findings_are_not_shown_as_same_cve():
    """低 3：一列有兩筆自己的 finding（機率高的那筆百分位低）：不把自己的值當成「same CVE」其他來源顯示。"""
    a = epss_finding("lib", "CVE-2026-0501", 0.3, 0.5, "NVD")
    b = epss_finding("lib", "GHSA-zzzz-zzzz-zzzz", 0.1, 0.9, "GITHUB", aliases=[{"cveId": "CVE-2026-0501"}])
    r = rows_for(findings=[a, b])[0]
    assert (r["epss"], r["epss_pct"]) == (0.3, 0.9) and "epss_other" not in r
    # 別的元件上同一個 CVE、同機率不同百分位：取百分位高的
    o1, o2 = epss_finding("x", "CVE-2026-0502", 0.2, 0.4), epss_finding("y", "CVE-2026-0502", 0.2, 0.8)
    ub = finding("linux", "6.8.0-1", "UBUNTU-CVE-2026-0502", "OSV", "LOW")
    u = next(r for r in rows_for(findings=[o1, o2, ub]) if r["component"] == "linux")
    assert u["epss_other"][0]["percentile"] == 0.8


def test_no_grype_gives_null_not_empty(tmp_path):
    """低 4：沒有 scan/grype.json 時是 None（不知道），不是 []（沒有）。"""
    r, s, reports = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s", grype=None))
    assert s["counts"]["kev_grype_only_not_in_table"] is None and s["counts"]["epss"]["grype_score_dates"] is None
    r, s, reports = run(make_project(tmp_path / "p2"), make_scan(tmp_path / "s2"))
    assert s["counts"]["kev_grype_only_not_in_table"] == [] and s["counts"]["epss"]["grype_score_dates"] == []


@pytest.mark.parametrize("stages,level,expect", [
    ({"C-grype-db": "GAP"}, "GAP", "C-grype-db is GAP"),
    ({"C-grype-db": "FAIL"}, "GAP", "C-grype-db is FAIL"),
    ({"C-grype-db": "ATTENTION"}, "ATTENTION", "C-grype-db is ATTENTION"),
    ({"C-mirror-freshness": "GAP"}, "GAP", "C-mirror-freshness is GAP"),
    ({"C-mirror-freshness": "NOT_RUN"}, "GAP", "C-mirror-freshness is NOT_RUN"),
    ({"C-mirror-freshness": "ATTENTION"}, "ATTENTION", "C-mirror-freshness is ATTENTION"),
    ({"C-grype-db-update": "FAIL"}, "GAP", "C-grype-db-update is FAIL"),
    ({"C-dt-feeds": "GAP"}, "GAP", "C-dt-feeds is GAP"),
])
def test_freshness_stages_reach_risk_status(tmp_path, stages, level, expect):
    proj = make_project(tmp_path / "proj")
    r, s, _ = run(proj, make_scan(tmp_path / "scan", stages=stages))
    d = s["documents"]["risk-assessment"]
    assert d["status"] == level and any(expect in x for x in d["detail"]), d


@pytest.mark.parametrize("stages,reason", [
    ({"C-grype-db-update": "NOT_RUN"}, None),        # GRYPE_DB_UPDATE=off：年齡由 C-grype-db 判斷
    ({"C-dt-feeds": "OK", "C-mirror-freshness": "OK", "C-grype-db-update": "OK"}, None),
])
def test_freshness_stages_not_gap_when_harmless(tmp_path, stages, reason):
    proj = make_project(tmp_path / "proj")
    meta = dict(META, dt_feeds_reason=reason) if reason else META
    r, s, _ = run(proj, make_scan(tmp_path / "scan", stages=stages, meta=meta))
    r0, s0, _ = run(make_project(tmp_path / "proj0"), make_scan(tmp_path / "scan0"))
    assert s["documents"]["risk-assessment"]["status"] == s0["documents"]["risk-assessment"]["status"], s["documents"]["risk-assessment"]


@pytest.mark.parametrize("reason", ["permission_denied", "no_data", None, "", "bogus"])
def test_dt_feeds_not_run_is_gap_unless_dt_was_not_used(tmp_path, reason):
    """M7b：C-dt-feeds 的 NOT_RUN 看 meta.json 的 dt_feeds_reason（不看說明文字）。金鑰沒權限、沒讀到資料源狀態、
    沒有原因代碼或代碼不認得 → GAP（D-043）。"""
    meta = dict(META)
    if reason is not None:
        meta["dt_feeds_reason"] = reason
    scan = make_scan(tmp_path / "scan", meta=meta)
    st = (scan / "status.tsv").read_text(encoding="utf-8") + "C-dt-feeds\tNOT_RUN\t（說明文字不影響判定）\n"
    (scan / "status.tsv").write_text(st, encoding="utf-8")
    r, s, _ = run(make_project(tmp_path / "proj"), scan)
    assert s["documents"]["risk-assessment"]["status"] == "GAP" and any("C-dt-feeds is NOT_RUN" in x for x in s["documents"]["risk-assessment"]["detail"])


def test_dt_feeds_detail_text_no_longer_matters(tmp_path):
    """舊做法看說明文字有沒有 SYSTEM_CONFIGURATION_READ；現在 dt_not_used 時就算說明文字含這個字，C-dt-feeds 也不列為原因
    （整體照樣因 D-dt-data-sources 不是 OK 而 GAP）。"""
    scan = make_scan(tmp_path / "scan", meta=dict(META, dt_feeds_reason="dt_not_used"), stages={"D-dt-data-sources": "NOT_RUN"})
    st = (scan / "status.tsv").read_text(encoding="utf-8") + "C-dt-feeds\tNOT_RUN\t金鑰沒有 SYSTEM_CONFIGURATION_READ\n"
    (scan / "status.tsv").write_text(st, encoding="utf-8")
    r, s, _ = run(make_project(tmp_path / "proj"), scan)
    assert not any("C-dt-feeds" in x for x in s["documents"]["risk-assessment"]["detail"])


@pytest.mark.parametrize("reason", ["dt_not_used", "dtsources_failed"])
def test_dt_feeds_not_downgraded_only_while_dt_data_sources_is_not_ok(tmp_path, reason):
    """#92 C0：dt_not_used／dtsources_failed 不降級的依據是 D-dt-data-sources 已經不是 OK（RISK_STAGES → GAP）。
    前提不成立（D-dt-data-sources 是 OK）時，C-dt-feeds 的 NOT_RUN 照樣 GAP，不只信 meta.json 的代碼。"""
    for dds, want_feeds_reason in (("FAIL", False), ("NOT_RUN", False), ("OK", True)):
        d = tmp_path / dds
        scan = make_scan(d / "scan", meta=dict(META, dt_feeds_reason=reason), stages={"D-dt-data-sources": dds})
        st = (scan / "status.tsv").read_text(encoding="utf-8") + "C-dt-feeds\tNOT_RUN\tx\n"
        (scan / "status.tsv").write_text(st, encoding="utf-8")
        r, s, _ = run(make_project(d / "proj"), scan)
        ra = s["documents"]["risk-assessment"]
        assert ra["status"] == "GAP", (dds, ra)                                   # 兩種情況整體都是 GAP
        assert any("C-dt-feeds is NOT_RUN" in x for x in ra["detail"]) == want_feeds_reason, (dds, ra["detail"])
        if dds != "OK":
            assert any(x.startswith("D-dt-data-sources is %s" % dds) for x in ra["detail"]), ra["detail"]


def test_sca_scan_writes_dt_data_sources_not_ok_with_both_not_downgraded_reasons():
    """sca-scan 寫 dt_not_used／dtsources_failed 的同一個分支，D-dt-data-sources 一定不是 OK（NOT_RUN／FAIL）。"""
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "pilot", "sca-scan"), encoding="utf-8").read()
    skip = next(l for l in src.splitlines() if "META[dt_feeds_reason]=dt_not_used" in l)
    assert "for s in C-dt-feeds D-dt-data-sources" in skip and 'status "$s" NOT_RUN' in skip
    fail = next(l for l in src.splitlines() if "META[dt_feeds_reason]=dtsources_failed" in l)
    assert 'status D-dt-data-sources FAIL' in fail


@pytest.mark.parametrize("st", ["FAIL", "GAP", "WEIRD"])
def test_dt_feeds_fail_or_unknown_is_at_least_gap(tmp_path, st):
    """#92 C0 驗證：C-dt-feeds 是 FAIL（dtsources 的 config_error：DT_FEEDS_MAX_AGE_HOURS 設錯）或不認得的狀態時，
    就算 D-dt-data-sources 是 OK 也至少 GAP（原本 FAIL 回 None，報告停在 ATTENTION）。"""
    scan = make_scan(tmp_path / "scan", meta=dict(META, dt_feeds_reason="config_error"))
    body = (scan / "status.tsv").read_text(encoding="utf-8") + f"C-dt-feeds\t{st}\tx\n"
    (scan / "status.tsv").write_text(body, encoding="utf-8")
    r, s, _ = run(make_project(tmp_path / "proj"), scan)
    ra = s["documents"]["risk-assessment"]
    assert ra["status"] == "GAP" and any(f"C-dt-feeds is {st}" in x for x in ra["detail"]), ra
