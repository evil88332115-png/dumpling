"""role supplier 的供應商資料包（supplier_package.py）。客戶名稱一律用代稱（Example Brand Co.），不用真實客戶。"""
import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import supplier_package as sp  # noqa: E402
from xlsx_min import read_xlsx  # noqa: E402
import cra_report as cr  # noqa: E402
from test_cra_report import MIN_CFG, clean_security, make_project, make_scan, run  # noqa: E402

FULL = dict(MIN_CFG, role="supplier",
            manufacturer={"name": "Example Co.", "address": "1 Example Road", "email": "security@example.com", "website": "https://example.com"},
            product={"name": "EX-J100", "model": "J100", "version": "1.0.0", "identification": "Label on the module"},
            vulnerability_contact={"contact": "security@example.com"}, support={"type": "Security updates", "end_date": "2031-12"},
            supplier={"customer": {"name": "Example Brand Co."}, "contract_reference": "SUPPLY-0001",
                      "security_update_delivery": "Signed image delivered to the customer portal",
                      "notification": {"exploited_hours": 8, "other_days": 14, "channel": "security mailing list"},
                      "integration": {"known_risks": ["Debug UART on J12"], "recommended_configuration": ["Disable USB device mode"],
                                      "manufacturer_responsibilities": ["Enable Secure Boot fuses"]},
                      "risks": [{"risk": "Unauthorised SSH access", "mitigation": "Key-only login", "residual": "Low"}]},
            risk_assessment={"annex_i_applicability": {k: {"applies": True, "measures": f"measure {k}"} for k in "bcdefghijklm"}})
STAMP = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ|\b[0-9a-f]{12,64}\b|urn:uuid:[0-9a-f-]+")   # 時間戳與由時間戳決定的雜湊、序號


def pkg(rep):
    return rep / sp.PKG


def texts(d):
    return {p.name: p.read_text(encoding="utf-8") for p in sorted(d.iterdir()) if p.is_file() and p.suffix != ".xlsx"}


def test_default_role_unchanged(tmp_path):
    """role 沒寫與 role manufacturer：輸出相同、沒有資料包。"""
    scan = make_scan(tmp_path / "scan")
    outs = []
    for name, cfg in (("a", MIN_CFG), ("b", dict(MIN_CFG, role="manufacturer"))):
        r, s, rep = run(make_project(tmp_path / name, cfg), scan)
        assert r.returncode in (0, 2), r.stdout + r.stderr
        assert not pkg(rep).exists() and (rep / "user-information.md").exists() and (rep / "technical-documentation.md").exists()
        outs.append({k: STAMP.sub("T", v) for k, v in texts(rep).items() if k not in ("summary.json", "sbom.cdx.json")})
    assert outs[0] == outs[1]
    assert "| Manufacturer | Example Co. |" in outs[0]["sbom.md"]


def test_supplier_minimal(tmp_path):
    r, s, rep = run(make_project(tmp_path / "p", dict(MIN_CFG, role="supplier")), make_scan(tmp_path / "scan"))
    assert r.returncode in (0, 2), r.stdout + r.stderr
    shipped = sorted(set(sp.FILES) - set(sp.OMITTABLE))          # 還有 TO BE COMPLETED 的三份文件不交
    assert sorted(p.name for p in pkg(rep).iterdir()) == shipped
    assert not (rep / "user-information.md").exists() and not (rep / "technical-documentation.md").exists()
    assert "user-information" not in s["documents"] and s["documents"]["supplier-package"]["status"] == "NOT_ASSESSED"   # 沒有安全測試
    t = texts(pkg(rep))
    assert "TO BE COMPLETED" in t["README.md"] and "| Supplier | Example Co. |" in (rep / "sbom.md").read_text(encoding="utf-8")
    # 未完成的文件不交，README 與 summary.json 列為未提供，狀態仍是 GAP（不能看起來像完成）
    for n in sp.OMITTABLE:
        assert n not in t and f"`{n}`" in t["README.md"] and "not included in this package" in t["README.md"]
        assert s["supplier_package"]["not_included"][n] == sp.NOT_PROVIDED
        assert f"{n} (not provided in this package)" in t["manufacturer-checklist.md"] or n not in t["manufacturer-checklist.md"]
    assert "Not included:" in t["README.md"] and s["supplier_package"]["company_fields"] == "TO BE COMPLETED"
    miss = s["supplier_package"]["missing_fields"]
    assert {"supplier.notification.exploited_hours", "supplier.customer.name", "support.end_date", "supplier.risks"} <= set(miss)
    assert s["supplier_package"]["notification_hours"] == "not decided"
    assert "12 hours" not in json.dumps(s["supplier_package"]) and not any("12 hours" in v for v in t.values())
    # DoC／CE 只在製造商待辦清單出現
    for n, x in t.items():
        if n not in ("manufacturer-checklist.md", "SHA256SUMS", "summary.json"):
            assert "declaration of conformity" not in x.lower() and "ce marking" not in x.lower(), n
    assert "EU declaration of conformity" in t["manufacturer-checklist.md"]
    # 沒有安全測試結果 → not assessed，不寫成沒有問題
    assert "**no (not assessed)**" in t["security-testing-summary.md"] and "No security test results" in t["security-testing-summary.md"]
    # 雜湊
    sums = dict(reversed(line.split("  ", 1)) for line in t["SHA256SUMS"].splitlines())
    assert set(sums) == set(shipped) - {"SHA256SUMS"}
    for n, h in sums.items():
        assert hashlib.sha256((pkg(rep) / n).read_bytes()).hexdigest() == h
    js = json.loads(t["summary.json"])
    assert {f["file"] for f in js["files"]} == set(shipped) - {"summary.json", "SHA256SUMS"}
    assert js["not_included"].keys() >= set(sp.OMITTABLE) and js["language_check"]["status"] == "OK"
    assert all(f["sha256"] == hashlib.sha256((pkg(rep) / f["file"]).read_bytes()).hexdigest() for f in s["supplier_package"]["files"])


def test_supplier_full(tmp_path):
    scan = make_scan(tmp_path / "res" / "scan")
    clean_security(scan.parent)
    r, s, rep = run(make_project(tmp_path / "p", FULL), scan)
    t = texts(pkg(rep))
    assert "Example Brand Co." in t["README.md"] and "SUPPLY-0001" in t["support-and-notification.md"]
    assert "8 hours" in t["support-and-notification.md"] and "12 hours" not in t["support-and-notification.md"]
    assert not [m for m in s["supplier_package"]["missing_fields"] if m.startswith(("supplier.", "support.", "risk_assessment."))]
    assert s["supplier_package"]["notification_hours"] == "configured"
    assert "Key-only login" in t["risk-summary.md"] and "measure m" in t["risk-summary.md"]
    assert "Disable USB device mode" in t["integration-and-configuration.md"]
    assert t["security-testing-summary.md"].count("| yes |") == 3 and "not assessed" not in t["security-testing-summary.md"]
    js = json.loads(t["summary.json"])
    assert js["security_testing"] == "OK" and js["company_fields"] == "OK" and js["vulnerability_data"] in ("OK", "ATTENTION", "GAP")
    assert "None open in the tests performed" in t["integration-and-configuration.md"]
    assert "not a statement of conformity" in t["risk-summary.md"] and "covered by" not in t["risk-summary.md"]
    # 客戶看的文件（.md）沒有內部用語與工具名稱；summary.json 的狀態代號是給工具讀的
    for n, x in ((n, x) for n, x in t.items() if n.endswith(".md")):
        for word in ("Release assessment", "image_check.py", "board-on-device.sh", "board-from-network.sh", "Overall result", "ATTENTION"):
            assert word not in x, (n, word)
    # 重跑：內容相同（時間戳除外）
    _, s2, _ = run(make_project(tmp_path / "p", FULL), scan)
    t2 = texts(pkg(rep))
    assert [x["file"] for x in s["supplier_package"]["files"]] == [x["file"] for x in s2["supplier_package"]["files"]]
    assert not list(rep.glob(".supplier-package.*"))
    norm = lambda x: {k: STAMP.sub("T", v) for k, v in x.items() if k not in ("summary.json", "SHA256SUMS", "sbom.cdx.json")}  # noqa: E731
    assert norm(t) == norm(t2)


def test_supplier_without_findings(tmp_path):
    r, s, rep = run(make_project(tmp_path / "p", FULL), make_scan(tmp_path / "scan", findings=None))
    t = texts(pkg(rep))
    assert "vex.cdx.json" not in t and "not included in this package" in t["README.md"]
    assert sp.NOT_ASSESSED in t["vulnerability-status.md"] and "None recorded as affected" not in t["vulnerability-status.md"]
    assert "Vulnerabilities: not assessed" in t["risk-summary.md"] and "0 rows recorded" not in t["risk-summary.md"]
    assert "vex.cdx.json" in s["supplier_package"]["not_included"]
    # 資料包的 summary.json 不能把「沒評估」寫成 OK
    js = json.loads(t["summary.json"])
    assert js["vulnerability_data"] == "NOT_ASSESSED" and js["security_testing"] == "NOT_ASSESSED" and js["status"] == "NOT_ASSESSED"


def test_role_switch_cleans_up(tmp_path):
    scan = make_scan(tmp_path / "scan")
    proj = make_project(tmp_path / "p", MIN_CFG)
    run(proj, scan)
    make_project(proj, dict(MIN_CFG, role="supplier"))
    _, _, rep = run(proj, scan)
    assert pkg(rep).is_dir() and not (rep / "user-information.md").exists()
    make_project(proj, MIN_CFG)
    run(proj, scan)
    assert not pkg(rep).exists() and (rep / "user-information.md").exists()


def test_role_typo_fails(tmp_path):
    r, s, rep = run(make_project(tmp_path / "p", dict(MIN_CFG, role="suplier")), make_scan(tmp_path / "scan"))
    assert r.returncode == 1 and "role" in r.stdout


def test_customer_name_only_in_package(tmp_path):
    """客戶名稱只來自產品設定檔，只出現在資料包；CRA/Reports 的其他文件沒有。"""
    scan = make_scan(tmp_path / "res" / "scan")
    _, _, rep = run(make_project(tmp_path / "p", FULL), scan)
    inside = [n for n, x in texts(pkg(rep)).items() if "Example Brand Co." in x]
    assert {"README.md", "manufacturer-checklist.md"} <= set(inside)
    assert not [n for n, x in texts(rep).items() if "Example Brand Co." in x]
    assert "Example Brand" not in (HERE.parent / "supplier_package.py").read_text(encoding="utf-8")


def test_gap_vulnerability_data_marked_incomplete(tmp_path):
    scan = make_scan(tmp_path / "scan", stages={"D-dt-osv-coverage": "GAP"})
    _, s, rep = run(make_project(tmp_path / "p", dict(MIN_CFG, role="supplier")), scan)
    t = texts(pkg(rep))
    assert "**Incomplete:**" in t["vulnerability-status.md"] and "| Completeness of the vulnerability data | incomplete |" in t["vulnerability-status.md"]


def test_vex_copy_drops_staff_names(tmp_path):
    bom = {"vulnerabilities": [{"id": "CVE-1", "properties": [{"name": "sca-center:annotation-author", "value": "Staff Name"},
                                                              {"name": "sca-center:vex-rule-author", "value": "Other Name"},
                                                              {"name": "sca-center:vex-rule", "value": "r1"}]}]}
    out = sp.scrub(bom)
    assert out["vulnerabilities"][0]["properties"] == [{"name": "sca-center:vex-rule", "value": "r1"}]


def test_notification_text_values(tmp_path):
    """B3：通知時限可以是文字（as agreed in the contract）；原文照寫，文件照樣產生，沒有數字建議值。"""
    assert sp.notice_time("as agreed in the contract", 8760, "hours") == "as agreed in the contract"
    assert sp.notice_time(" ", 8760, "hours") is None and sp.notice_time(None, 8760, "hours") is None
    assert sp.notice_time(8, 8760, "hours") == "8 hours" and sp.notice_time(14, 3650, "days") == "14 days"
    txt = "as agreed in the contract"
    cfg = dict(FULL, supplier=dict(FULL["supplier"], notification={"exploited_hours": txt, "other_days": txt, "channel": "mail"}))
    assert cr.validate(cfg)[0] == []
    scan = make_scan(tmp_path / "res" / "scan")
    clean_security(scan.parent)
    _, s, rep = run(make_project(tmp_path / "p", cfg), scan)
    t = texts(pkg(rep))
    assert t["support-and-notification.md"].count(txt) == 2 and s["supplier_package"]["notification_hours"] == "configured"
    assert s["supplier_package"]["language_check"]["status"] == "OK"


def test_tools_scope_note(tmp_path):
    """B4：隨原始碼交付的建置工具與主機端刷機工具不在產品 SBOM：sbom.tools_scope_note 為 true 時，客戶 sbom.md、PM sbom.md、技術文件都寫；
    沒設定、又不是刷機包掃描時不寫（輸出不變）。"""
    scan = make_scan(tmp_path / "res" / "scan")
    clean_security(scan.parent)
    _, _, rep0 = run(make_project(tmp_path / "p0", FULL), scan)
    assert "not installed on the product" not in texts(pkg(rep0))["sbom.md"] and "not installed on the product" not in (rep0 / "sbom.md").read_text(encoding="utf-8")
    cfg = dict(FULL, sbom=dict(FULL.get("sbom") or {}, tools_scope_note=True))
    assert cr.validate(cfg)[0] == []
    _, s, rep = run(make_project(tmp_path / "p1", cfg), scan)
    assert sp.TOOLS_SCOPE_NOTE in texts(pkg(rep))["sbom.md"] and sp.TOOLS_SCOPE_NOTE in (rep / "sbom.md").read_text(encoding="utf-8")
    assert s["supplier_package"]["language_check"]["status"] == "OK"
    mcfg = dict(MIN_CFG, sbom=dict(MIN_CFG.get("sbom") or {}, tools_scope_note=True))
    _, _, rep2 = run(make_project(tmp_path / "p2", mcfg), scan)
    assert sp.TOOLS_SCOPE_NOTE in (rep2 / "technical-documentation.md").read_text(encoding="utf-8")


def test_odd_notification_values_and_partial_fields(tmp_path):
    for bad in (float("nan"), float("inf"), 10 ** 400, True, "8"):
        assert sp.number(bad, 8760) is None
    assert sp.number(1000000, 8760) is None and sp.number(12, 8760) == "12" and sp.number(1.25, 8760) == "1.25"
    cfg = dict(FULL, supplier=dict(FULL["supplier"], notification={"exploited_hours": 4}, risks=[{"risk": "x"}]))
    _, s, rep = run(make_project(tmp_path / "p", cfg), make_scan(tmp_path / "scan"))
    miss = s["supplier_package"]["missing_fields"]
    assert {"supplier.notification.other_days", "supplier.notification.channel", "supplier.risks[0]"} <= set(miss)
    # 欄位沒填完的文件不交（不是交半成品）：列為未提供，公司欄位狀態仍是 TO BE COMPLETED
    t = texts(pkg(rep))
    assert "support-and-notification.md" not in t and "risk-summary.md" not in t
    assert {"support-and-notification.md", "risk-summary.md"} <= set(s["supplier_package"]["not_included"])
    st = {f["file"]: f["status"] for f in s["supplier_package"]["files"]}
    assert "support-and-notification.md" not in st and st["manufacturer-checklist.md"] == "OK"
    assert s["supplier_package"]["company_fields"] == "TO BE COMPLETED"
    f = sp.Fields()
    ctx = {"product": "P", "supplier": "S", "now": "T", "artifact": {}, "absent_reason": {}, "customer": "C"}
    assert "4 hours" in sp.support(cfg, f, ctx, sp_table)


def test_fail_removes_package(tmp_path):
    scan = make_scan(tmp_path / "scan")
    proj = make_project(tmp_path / "p", dict(MIN_CFG, role="supplier"))
    _, _, rep = run(proj, scan)
    assert pkg(rep).is_dir()
    (proj / "CRA" / "Config" / "vex-annotations.json").write_text("{not json", encoding="utf-8")
    r, s, _ = run(proj, scan)
    assert r.returncode == 1 and not pkg(rep).exists() and not list(rep.glob(".supplier-package.*"))


def test_stale_temp_dirs_cleaned_in_supplier_mode(tmp_path):
    scan = make_scan(tmp_path / "scan")
    proj = make_project(tmp_path / "p", dict(MIN_CFG, role="supplier"))
    stale = proj / "CRA" / "Reports" / ".supplier-package.killed"
    stale.mkdir(parents=True)
    (stale / "x").write_text("x")
    _, _, rep = run(proj, scan)
    assert pkg(rep).is_dir() and not stale.exists()


def test_alias_cve_statements_reach_customer_text():
    """一列併了多個 CVE 別名時，別名 CVE 自己的判定（vex_extra）也要出現在 vulnerability-status.md 與風險摘要。"""
    row = {"id": "CVE-2026-0001", "component": "libx", "version": "1.0", "kev": False, "vex": {"state": "not_affected"},
           "vex_extra": [{"id": "CVE-2026-0002", "component": "libx", "version": "1.0", "kev": True,
                          "vex": {"state": "exploitable", "response": ["update"]}, "fix": "1.1", "fix_state": "fixed", "fix_versions": ["1.1"]}]}
    summary = {"vex": {"gate": {"verdict": "ATTENTION", "counts": {"total": {"not_affected": 1}}, "assessment": {"complete": True}}}}
    ctx = {"product": "P", "supplier": "S", "now": "T", "artifact": {"data_status": "OK"}, "absent_reason": {}}
    md = sp.vulnerability_status(summary, [row], ctx, sp_table)
    assert f"| CVE-2026-0002 | libx | 1.0 | {sp.FIXED_OUTLOOK} | Fix available in 1.1. |" in md and "None recorded as affected" not in md
    assert "| Affected | 1 |" in md and "| Not affected | 1 |" in md and "Update planned" not in md
    kev_part = md.split("## Reported as actively exploited and not resolved")[1]
    assert "CVE-2026-0002" in kev_part and "None." not in kev_part.split("##")[0]
    rs = sp.risk_summary({}, {"tests": [], "findings": []}, summary, [row], sp.Fields(), ctx, sp_table)
    assert "1 rows affected" in rs and "exploitable" not in rs


def sp_table(head, rows):
    return "\n".join(["| " + " | ".join(head) + " |", "|" + "---|" * len(head)] + ["| " + " | ".join(str(x) for x in r) + " |" for r in rows])


def test_supplier_risk_assessment_does_not_point_to_technical_documentation(tmp_path):
    """role supplier 不產生技術文件：風險評估（含第 9 節安全測試）不再指向 technical-documentation.md，改指向供應商資料包；
    role manufacturer 的文字不變。"""
    scan = make_scan(tmp_path / "scan")
    _, _, rep = run(make_project(tmp_path / "s", dict(MIN_CFG, role="supplier")), scan)
    ra = (rep / "risk-assessment.md").read_text(encoding="utf-8")
    assert "technical-documentation.md" not in ra and "becomes part of the technical documentation" not in ra
    assert "The technical documentation, point 2(b)" not in ra
    assert "(`supplier-package/risk-summary.md`)" in ra and "(`supplier-package/security-testing-summary.md`)" in ra
    assert "The supplier information package (`supplier-package/`)" in ra
    for p in pkg(rep).iterdir():
        if p.is_file() and p.suffix != ".xlsx" and p.name not in ("manufacturer-checklist.md", "SHA256SUMS", "summary.json"):
            assert "technical-documentation.md" not in p.read_text(encoding="utf-8"), p.name
    _, _, rep = run(make_project(tmp_path / "m", MIN_CFG), scan)
    ra = (rep / "risk-assessment.md").read_text(encoding="utf-8")
    assert "Article 13; it becomes part of the technical documentation (Annex VII point 3). The CRA does not" in ra
    assert ("The technical documentation, point 2(b), lists the SBOM, the coordinated vulnerability disclosure policy and\n"
            "the reporting contact.") in ra
    assert "the reports are part of the technical documentation (Annex VII point 6, see `technical-documentation.md`)" in ra
    assert "supplier-package/" not in ra


def test_supplier_old_project_template_warns(tmp_path):
    """專案自己的舊版風險評估範本（沒有 role.* 的兩個 placeholder）：supplier 時警告；manufacturer 時不警告。"""
    tpl = (HERE.parent / "templates" / "risk-assessment.md").read_text(encoding="utf-8")
    old = (tpl.replace("{{ role.risk_assessment_use }}", "it becomes part of the technical documentation (Annex VII point 3)")
              .replace("{{ role.part_ii_evidence }}", "The technical documentation, point 2(b), lists the SBOM."))
    assert old != tpl
    scan = make_scan(tmp_path / "scan")
    _, s, _ = run(make_project(tmp_path / "s", dict(MIN_CFG, role="supplier"), {"risk-assessment": old}), scan)
    assert any("role.risk_assessment_use" in w for w in s["config_warnings"]), s["config_warnings"]
    _, s, _ = run(make_project(tmp_path / "m", MIN_CFG, {"risk-assessment": old}), scan)
    assert not any("role.risk_assessment_use" in w for w in s["config_warnings"])
    _, s, _ = run(make_project(tmp_path / "b", dict(MIN_CFG, role="supplier")), scan)          # 內建範本：不警告
    assert not any("role.risk_assessment_use" in w for w in s["config_warnings"])


# ---- vulnerabilities.xlsx ----
CTX = {"product": "P 1.0", "supplier": "S", "now": "2026-11-11T00:00:00Z", "artifact": {"data_status": "OK"}, "absent_reason": {}}
SUMM = {"vex": {"gate": {"verdict": "ATTENTION", "counts": {}, "assessment": {"complete": True}}}}
XROWS = [
    {"id": "CVE-2026-0010", "component": "libna", "version": "1.0", "kev": False, "cvss_score": 5.5,
     "vex": {"state": "not_affected", "justification": "code_not_present", "detail": "The affected code is not built. (bulk rule R8: x)"}},
    {"id": "CVE-2026-0011", "component": "libaff", "version": None, "kev": False, "fix_state": "not-fixed", "vex": {"state": "exploitable"}},
    {"id": "CVE-2026-0012", "component": "libfix", "version": "2.0", "kev": False, "cvss_score": 7.5, "fix_state": "fixed", "fix_versions": ["2.1"],
     "vex": {"state": "resolved"}},
    {"id": "CVE-2026-0013", "component": "libtri", "version": "3.0", "kev": False, "cvss_score": 9.8, "vex": {"state": "in_triage"}},
    {"id": "CVE-2026-0014", "component": "libkev", "version": "4.0", "kev": True, "cvss_score": 6.0, "vex": {"state": "resolved"}, "fix_state": "fixed",
     "fix_versions": ["4.1"],
     "vex_extra": [{"id": "CVE-2026-0015", "component": "libkev", "version": "4.0", "kev": False, "vex": {"state": "untriaged"}}]},
    {"id": "CVE-2026-0016", "component": "libssl 3.0.1 (copy in uefi/)", "version": "3.0.1", "kev": False, "fix_state": "fixed",
     "fix_versions": ["3.0.9"], "bundled_in": "uefi copy", "vex": {"state": "exploitable"}},
]


def make_xlsx(tmp_path, rows=XROWS, summ=SUMM):
    f = tmp_path / "v.xlsx"
    sp.vulnerabilities_xlsx(f, summ, rows, CTX)
    return f, read_xlsx(f)


def test_xlsx_columns_order_and_values(tmp_path):
    f, x = make_xlsx(tmp_path)
    assert list(x) == ["Vulnerabilities", "Notes"]
    rows = x["Vulnerabilities"]
    hi = next(i for i, r in enumerate(rows) if r[:1] == ["Vulnerability"])
    assert rows[hi] == sp.XLSX_HEADER == ["Vulnerability", "Component", "Version", "Status", "Known exploited", "Severity", "Severity note",
                                          "Response", "Fix", "Justification"]
    body = {r[0]: r for r in rows[hi + 1:]}
    assert [r[0] for r in rows[hi + 1:]] == ["CVE-2026-0014", "CVE-2026-0011", "CVE-2026-0016", "CVE-2026-0013", "CVE-2026-0015",
                                             "CVE-2026-0012", "CVE-2026-0010"]
    assert body["CVE-2026-0011"][2] == "unknown" and body["CVE-2026-0011"][5] == "" and body["CVE-2026-0011"][6] == "No CVSS score"
    assert body["CVE-2026-0012"][5] == 7.5 and body["CVE-2026-0012"][6] == ""
    assert body["CVE-2026-0012"][3] == "Fixed" and body["CVE-2026-0013"][3] == "Under assessment"
    # Not affected 的列也在，Justification 是客戶版句子（去掉內部後綴）
    assert body["CVE-2026-0010"][3] == "Not affected" and body["CVE-2026-0010"][9] == "The affected code is not built."
    assert all(r[9] == "" for k, r in body.items() if k != "CVE-2026-0010")
    # 與 vulnerability-status.md 同一套用語
    assert body["CVE-2026-0011"][7] == sp.customer_response(XROWS[1]) and body["CVE-2026-0011"][8] == sp.customer_fix(XROWS[1])
    assert body["CVE-2026-0010"][8] == "—" and body["CVE-2026-0012"][8] == "Fixed in 2.1."
    # 狀態是 Affected 但有修補版本（不在這個版本）→ Fix available in …；Fixed／Not affected 不變
    aff = {"id": "CVE-2026-0020", "component": "libaf", "version": "1.0", "kev": False, "fix_state": "fixed", "fix_versions": ["1.1"],
           "vex": {"state": "exploitable"}}
    row = sp.xlsx_rows([aff])[0]
    assert row[3] == "Affected" and row[8] == "Fix available in 1.1."
    assert sp.xlsx_rows([dict(aff, vex={"state": "resolved"})])[0][8] == "Fixed in 1.1."
    assert sp.xlsx_rows([dict(aff, vex={"state": "in_triage"})])[0][8] == "Fix available in 1.1."
    # 客戶 VEX 的說明文字：還沒修好的列不寫 Fixed in，Fixed 的列照舊
    d_ = "Fixed in libaf 1.1 (installed 1.0)."
    assert sp.customer_text(d_, "affected") == sp.customer_text(d_, "under_investigation") == "Fix available in libaf 1.1 (installed 1.0)."
    assert sp.customer_text(d_, "fixed") == d_
    assert sp.affected_fix("Fixed in 1.1.") == "Fix available in 1.1." and sp.affected_fix("No fix available yet.") == "No fix available yet."
    assert sp.affected_fix("Fixed in the Ubuntu package x 1 (installed 0).") == "Fix available in the Ubuntu package x 1 (installed 0)."
    # UEFI 內建函式庫的提示
    assert "Rebuild the UEFI" in body["CVE-2026-0016"][8] or "rebuild the UEFI with" in body["CVE-2026-0016"][8]
    assert "an apt upgrade does not apply" in body["CVE-2026-0016"][8]
    # 別名列（vex_extra）也在
    assert body["CVE-2026-0015"][3] == "Under assessment"


def test_xlsx_sort_known_exploited_first(tmp_path):
    _, x = make_xlsx(tmp_path)
    rows = x["Vulnerabilities"]
    hi = next(i for i, r in enumerate(rows) if r[:1] == ["Vulnerability"])
    body = rows[hi + 1:]
    assert body[0][0] == "CVE-2026-0014" and body[0][4] == "Yes" and all(r[4] == "No" for r in body[1:])
    rest = [r[3] for r in body[1:]]
    assert rest == sorted(rest, key=lambda s_: sp.STATUS_RANK[s_])
    assert [r[0] for r in body[1:] if r[3] == "Affected"] == ["CVE-2026-0011", "CVE-2026-0016"]


def test_xlsx_counts_match_status_md(tmp_path):
    _, x = make_xlsx(tmp_path)
    md = sp.vulnerability_status(SUMM, XROWS, CTX, sp_table)
    rows = x["Vulnerabilities"]
    summ = next(r[0] for r in rows if str(r[0]).startswith("Rows per status:"))
    counts = {k: int(v) for k, v in (kv.split(": ") for kv in summ.split(": ", 1)[1].split("; "))}
    for k, n in counts.items():
        assert f"| {k} | {n} |" in md, (k, n)
    hi = next(i for i, r in enumerate(rows) if r[:1] == ["Vulnerability"])
    seen = {}
    for r in rows[hi + 1:]:
        seen[r[3]] = seen.get(r[3], 0) + 1
    assert seen == {k: n for k, n in counts.items() if n}
    assert any("including aliases" in str(r[0]) for r in rows[:hi])


def test_xlsx_no_frozen_panes_and_filter(tmp_path):
    f, _ = make_xlsx(tmp_path)
    with zipfile.ZipFile(f) as z:
        for n in ("xl/worksheets/sheet1.xml", "xl/worksheets/sheet2.xml"):
            assert b"<pane" not in z.read(n)
        assert b"<autoFilter" in z.read("xl/worksheets/sheet1.xml")


def test_xlsx_notes_sheet(tmp_path):
    _, x = make_xlsx(tmp_path)
    notes = " ".join(r[0] for r in x["Notes"][1:])
    assert "Not affected" in notes and "vex.cdx.json" in notes and "automated analysis" in notes
    assert not sp.check_customer_text("vulnerabilities.xlsx", notes) and not re.search(r"\bdays?\b|\bhours?\b", notes)


def test_xlsx_not_assessed_is_explicit(tmp_path):
    _, x = make_xlsx(tmp_path, rows=[], summ={})
    text = " ".join(str(c) for r in x["Vulnerabilities"] for c in r)
    assert "Not assessed" in text and "does not mean that there are no vulnerabilities" in text
    assert len(x["Vulnerabilities"]) > 2
    _, x = make_xlsx(tmp_path, rows=[])           # 評估過但沒有列：也要明說
    assert "None recorded" in " ".join(str(c) for r in x["Vulnerabilities"] for c in r)


def test_xlsx_language_check_catches_forbidden_word(tmp_path):
    d_ = tmp_path / "pk"
    d_.mkdir()
    bad = [dict(XROWS[1], fix="Grype says upgrade; will be included in the next image /home" "/x/y 中文")]
    sp.vulnerabilities_xlsx(d_ / "vulnerabilities.xlsx", SUMM, [dict(bad[0], fix_state=None)], CTX)
    found = sp.language_check(d_)
    assert found["status"] == "GAP"
    kinds = " ".join(found["findings"])
    assert "CJK" in kinds and "internal term" in kinds and "commitment wording" in kinds and "local path" in kinds
    good = tmp_path / "ok"
    good.mkdir()
    make_xlsx(good)
    sp.vulnerabilities_xlsx(good / "vulnerabilities.xlsx", SUMM, XROWS, CTX)
    assert sp.language_check(good) == {"status": "OK", "findings": []}


def test_xlsx_in_package_readme_summary_sums(tmp_path):
    scan = make_scan(tmp_path / "res" / "scan")
    clean_security(scan.parent)
    r, s, rep = run(make_project(tmp_path / "p", FULL), scan)
    pk = pkg(rep)
    x = pk / "vulnerabilities.xlsx"
    assert x.is_file()
    h = hashlib.sha256(x.read_bytes()).hexdigest()
    assert "`vulnerabilities.xlsx`" in (pk / "README.md").read_text(encoding="utf-8") and f"`{h}`" in (pk / "README.md").read_text(encoding="utf-8")
    assert f"{h}  vulnerabilities.xlsx" in (pk / "SHA256SUMS").read_text(encoding="utf-8")
    js = json.loads((pk / "summary.json").read_text(encoding="utf-8"))
    assert {"file": "vulnerabilities.xlsx", "sha256": h, "status": "OK"} in js["files"]
    assert js["language_check"]["status"] == "OK", js["language_check"]
    for line in (pk / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        hh, n = line.split("  ")
        assert hashlib.sha256((pk / n).read_bytes()).hexdigest() == hh, n
    # 資料包裡的列數與 vulnerability-status.md 的摘要一致
    md = (pk / "vulnerability-status.md").read_text(encoding="utf-8")
    rows = read_xlsx(x)["Vulnerabilities"]
    hi = next(i for i, rr in enumerate(rows) if rr[:1] == ["Vulnerability"])
    seen = {}
    for rr in rows[hi + 1:]:
        seen[rr[3]] = seen.get(rr[3], 0) + 1
    for k, n in seen.items():
        assert f"| {k} | {n} |" in md, (k, n)


def test_xlsx_package_without_findings_says_not_assessed(tmp_path):
    r, s, rep = run(make_project(tmp_path / "p", FULL), make_scan(tmp_path / "scan", findings=None))
    x = read_xlsx(pkg(rep) / "vulnerabilities.xlsx")
    assert "Not assessed" in " ".join(str(c) for rr in x["Vulnerabilities"] for c in rr)


def test_xlsx_fixed_and_not_affected_never_claim_no_fix(tmp_path):
    rows = [dict(XROWS[0], fix_state="not-fixed"), dict(XROWS[0], id="CVE-2026-0020", fix_state="wont-fix"),
            {"id": "CVE-2026-0021", "component": "libr", "version": "1", "vex": {"state": "resolved"}, "fix_state": "not-fixed"},
            {"id": "CVE-2026-0024", "component": "pil", "version": "1", "vex": {"state": "resolved"}, "fix_state": "fixed",
             "fix_versions": ["12.3.0"],
             "deb_python": {"owner": None, "candidates": ["python3-pil 1", "python3-pil.imagetk 1"], "pypi_fix": ["12.3.0"]}},
            {"id": "CVE-2026-0022", "component": "libr", "version": "1", "vex": {"state": "resolved"}},
            {"id": "CVE-2026-0023", "component": "libr", "version": "1", "vex": {"state": "false_positive"}, "fix_state": "unknown"}]
    _, x = make_xlsx(tmp_path, rows=rows + XROWS)
    r_ = x["Vulnerabilities"]
    hi = next(i for i, r in enumerate(r_) if r[:1] == ["Vulnerability"])
    n = 0
    for r in r_[hi + 1:]:
        if r[3] in ("Not affected", "Fixed"):
            n += 1
            assert not re.search(r"(?i)no fix|not available|not fixed|will not fix|insufficient|installed by|check which", r[8]), r
            if r[3] == "Not affected":
                assert r[8] == "—"
    assert n >= 8
