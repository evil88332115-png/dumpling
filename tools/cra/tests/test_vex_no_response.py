"""批次規則的 exploitable 不寫 response（上游還沒有修補、發行版 won't fix、資料不足）：
- 規則驗證不擋；CycloneDX VEX 不輸出 response；OpenVEX 的 affected 有說明；CSAF 選對 remediation 類別、不寫成「供應商不能修」；
- 舊設定檔的 can_not_fix／will_not_fix 照常通過；
- 客戶的 vulnerability-status.md：Response、Fix 欄用客戶看得懂的英文（沒有工具名稱），Ubuntu 打包的 Python 套件以 Ubuntu 的狀態為準。
全部是合成資料。"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import supplier_package as sp  # noqa: E402
import vex_export as vx  # noqa: E402
from test_vex_export import PBOM, row  # noqa: E402
from test_vex_rules import assess, doc, gate, rule  # noqa: E402

TOOL_WORDS = ("Grype", "Dependency-Track", "not matched", "no Grype", "DT ")


def rules_no_response():
    d = doc(rule("R2", response=(), detail="No fix is available yet for {component} (installed {installed_version}); tracked.", fix_state=["not-fixed"]),
            rule("R7", response=(), detail="The distribution marked {component} as will not fix.", fix_state=["wont-fix"]),
            rule("R8", response=(), detail="Insufficient data for {component}; treated as affected.", fix_state=["unknown"]))
    vx.check_rules(d)
    return vx.effective_rules(d)


def rows3():
    return [row("CVE-2026-0001", "liba", "1.0", fix_state="not-fixed", fix_versions=[]),
            row("CVE-2026-0002", "libb", "1.0", fix_state="wont-fix", fix_versions=[]),
            row("CVE-2026-0003", "libc", "1.0", fix_state="unknown", fix_versions=[])]


def exported():
    allr, conf, info = assess(rows3(), rules_no_response(), ctx={"kernel_fix_all": {}})
    cdx, _ = vx.cdx_vex(allr, PBOM, {"finished": "2026-11-02T02:43:55Z", "name": "img"}, {"name": "P"}, "ATTENTION")
    return allr, conf, cdx


def test_rule_without_response_is_valid_and_old_values_still_pass():
    vx.check_rules(doc(rule("R2", response=(), detail="x", fix_state=["not-fixed"])))
    vx.check_rules(doc(rule("R2", response=("can_not_fix",), detail="x"), rule("R7", response=("will_not_fix",), detail="x")))


def test_cyclonedx_has_no_response_and_openvex_has_action_statement():
    allr, conf, cdx = exported()
    assert [r["vex"]["state"] for r in allr] == ["exploitable"] * 3 and not conf
    assert all("response" not in v["analysis"] for v in cdx["vulnerabilities"])
    for v in cdx["vulnerabilities"]:
        props = {p["name"]: p["value"] for p in v["properties"]}
        assert props["openvex:action_statement"].strip() and props["sca-center:fix-state"] in ("not-fixed", "wont-fix", "unknown")
    ov = vx.openvex(cdx, "Example Co.", vx.purl_by_bomlink(PBOM))
    assert len(ov["statements"]) == 3
    for st in ov["statements"]:
        assert st["status"] == "affected" and st["action_statement"].strip()
        assert "No action statement provided" not in st["action_statement"]


def test_gate_does_not_complain_about_rule_rows_without_response():
    allr, conf, _ = assess(rows3(), rules_no_response(), ctx={"kernel_fix_all": {}})
    g = gate(allr, conf)
    assert g["exploitable_without_response"] == 0
    assert not any("without a response" in r for r in g["reasons"])
    assert g["open_affected"]["by_response"] == {"none": 3}




# ---------- 客戶的 vulnerability-status.md ----------

def sp_table(head, rows):
    return "\n".join(["| " + " | ".join(head) + " |", "|" + "---|" * len(head)] + ["| " + " | ".join(str(x) for x in r) + " |" for r in rows])


def status_md(rows):
    summary = {"vex": {"gate": {"verdict": "ATTENTION", "counts": {"total": {"exploitable": len(rows)}}, "assessment": {"complete": True}}}}
    ctx = {"product": "P", "supplier": "S", "now": "T", "artifact": {"data_status": "OK"}, "absent_reason": {}}
    return sp.vulnerability_status(summary, rows, ctx, sp_table)


def xrow(cve, comp, ver, fs, response=(), fix_raw="", **kw):
    vex = {"state": "exploitable", "source": "rule"}
    if response:
        vex["response"] = list(response)
    return {"id": cve, "component": comp, "version": ver, "kev": False, "vex": vex, "fix_state": fs, "fix_versions": kw.pop("fix_versions", []),
            "fix": fix_raw, **kw}


def test_customer_table_three_cases_in_plain_english():
    md = status_md([
        xrow("CVE-1", "liba", "1.0", "not-fixed", fix_raw="not-fixed"),
        xrow("CVE-2", "libb", "1.0", "wont-fix", fix_raw="wont-fix"),
        xrow("CVE-3", "libc", "1.0", "unknown", fix_raw="unknown (not matched by Grype)")])
    line = {ln.split("|")[1].strip(): ln for ln in md.splitlines() if ln.startswith("| CVE-")}
    assert "No fix available yet; a fix may be included in a future release, depending on availability" in line["CVE-1"]
    assert "will not fix; under review" in line["CVE-2"]
    assert "Insufficient data (version unknown or no fix information); treated as affected" in line["CVE-3"]
    assert "Fix information not available." in line["CVE-3"]
    table = md.split("## Affected vulnerabilities")[1].split("## Reported as actively exploited")[0]
    assert not any(w in table for w in TOOL_WORDS) and "can_not_fix" not in md and "will_not_fix" not in md


def test_customer_table_legacy_can_not_fix_is_not_read_as_supplier_cannot():
    md = status_md([xrow("CVE-1", "liba", "1.0", "not-fixed", response=("can_not_fix",)),
                    xrow("CVE-2", "libb", "1.0", "wont-fix", response=("will_not_fix",))])
    assert "can_not_fix" not in md and "will_not_fix" not in md
    assert "No fix available yet; a fix may be included" in md and "will not fix; under review" in md


def test_customer_fix_prefers_distribution_state_over_pypi_fix():
    raw = ("update the Ubuntu package python3-pil (installed 10.2.0-1ubuntu1.2), not pip; Ubuntu fix state: not-fixed (note)"
           "; the PyPI fix 13.0.0 does not apply to the distribution package")
    r = xrow("CVE-4", "pillow", "10.2.0", "not-fixed", response=("can_not_fix",), fix_raw="fixed in 13.0.0; installed in /usr/lib/python3/dist-packages",
             deb_python={"owner": {"name": "python3-pil", "version": "10.2.0-1ubuntu1.2"}, "pypi_fix": ["13.0.0"]})
    r["fix"] = raw
    md = status_md([r])
    assert ("No fix from Ubuntu yet for python3-pil (installed 10.2.0-1ubuntu1.2); the upstream PyPI fix 13.0.0 "
            "does not apply to the distribution package.") in md
    assert "dist-packages" not in md and "not pip" not in md and "fix state:" not in md
    r2 = dict(r, fix_state="fixed", fix_versions=["10.2.0-1ubuntu1.3"])
    assert "Fixed in the Ubuntu package python3-pil 10.2.0-1ubuntu1.3 (installed 10.2.0-1ubuntu1.2)" in sp.customer_fix(r2)
    assert "will not fix" in sp.customer_fix(dict(r, fix_state="wont-fix"))


def test_customer_wording_does_not_touch_raw_row():
    r = xrow("CVE-5", "libx", "1", "unknown", fix_raw="unknown (not matched by Grype)")
    status_md([r])
    assert r["fix"] == "unknown (not matched by Grype)" and r["fix_state"] == "unknown"

# ---------- 修補版本已有（fixed）但沒有 response；擁有者不明或不只一個 ----------

def test_customer_fixed_without_response_is_not_insufficient_data():
    r = xrow("CVE-6", "libz", "1.0", "fixed", fix_versions=["1.2"], fix_raw="fixed in 1.2")
    md = status_md([r])
    assert sp.FIXED_OUTLOOK in md and "Insufficient data" not in md
    assert "Fix available in 1.2." in md
    legacy = xrow("CVE-7", "libz", "1.0", "fixed", response=("can_not_fix",), fix_versions=["1.2"])
    assert sp.customer_response(legacy) == sp.FIXED_OUTLOOK


def test_customer_fix_for_python_module_with_ambiguous_or_unknown_owner():
    amb = xrow("CVE-8", "pillow", "10.2.0", "fixed", fix_versions=["13.0.0"],
               deb_python={"owner": None, "candidates": ["python3-pil 10.2.0-1", "python3-pil.imagetk 10.2.0-1"], "pypi_fix": ["13.0.0"]})
    t = sp.customer_fix(amb)
    assert t == ("Installed by a distribution package (python3-pil or python3-pil.imagetk); the upstream PyPI fix 13.0.0 "
                 "may not apply — check which package installed it.")
    assert "Insufficient data" not in status_md([amb]) and "Fixed in 13.0.0" not in status_md([amb])
    none = xrow("CVE-9", "pillow", "10.2.0", "fixed", fix_versions=["13.0.0"], deb_python={"owner": None, "candidates": [], "pypi_fix": ["13.0.0"]})
    assert sp.customer_fix(none).startswith("Installed by a distribution package; the upstream PyPI fix 13.0.0 may not apply")


