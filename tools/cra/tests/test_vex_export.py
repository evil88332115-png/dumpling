"""vex_export.py 的測試：各來源的對映、優先順序與衝突、輸出穩定、發行閘門、人工判定檔的範圍、CycloneDX／OpenVEX 的形狀，
以及 cra_report.py 的整合（VEX 小節、VEX status 欄、summary.json 的 vex、沒有 Debian 或核心的掃描）。"""
import copy
import json
import os
import random
import re
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import vex_export as vx  # noqa: E402
from test_cra_report import (FINDINGS, META, SBOM, finding, make_project, make_scan, run, write_json)  # noqa: E402
from test_cra_distro import EXTRA, OSSL, recheck_doc  # noqa: E402

CLI = HERE.parent / "vex_export.py"
DEB = "pkg:deb/ubuntu/{}@{}?arch=arm64&distro=ubuntu-24.04"


def row(rid, comp="openssl", ver=OSSL, purl=None, tier="p2", kernel=False, analysis=None, source_ids=None, **kw):
    r = {"id": rid, "cves": [rid] if rid.startswith("CVE-") else [], "all_ids": [rid], "key": [rid, f"ubuntu/{comp}", ver],
         "component": comp, "name": comp, "version": ver, "purl": purl or DEB.format(comp, ver), "tier": tier, "kernel": kernel,
         "analysis": analysis or [{"state": "", "suppressed": False, "justification": "", "response": "", "details": ""}],
         "source_ids": source_ids or [f"NVD:{rid}"], "installed_as": [], "mapped_from": None, "kev": False, "epss_pct": None,
         "severity": "HIGH"}
    r.update(kw)
    return r


def dt(state, justification="", response="", details="", suppressed=False):
    return [{"state": state, "suppressed": suppressed, "justification": justification, "response": response, "details": details}]


def ann(cve, state="not_affected", **kw):
    a = {"cve": cve, "state": state, "detail": "checked by hand", "author": "Alice", "date": "2026-11-01"}
    if state == "not_affected":
        a["justification"] = "code_not_reachable"
    if state == "exploitable":
        a["response"] = ["update"]
    a.update(kw)
    return a


def typed(allr, typ="source", loc="synthetic evidence"):
    """D-035：測試用。給每一筆沒有依據的排除補上依據類型（只動 evidence_basis），讓測試只看它原本要看的東西
    （沒有類型的排除會算進 untriaged_for_gate 並擋閘門）。D-035 本身的測試在 test_vex_evidence_basis.py。"""
    for r in allr:
        for x in [r] + (r.get("vex_extra") or []):
            if vx.is_exclusion(x.get("vex")) and not x["vex"].get("evidence_basis"):
                x["vex"]["evidence_basis"] = [{"type": typ, "location": loc}]
    return allr


def kcfg(results, status="OK"):
    return {"schema": "sca-center-kernel-config/1", "status": status, "detail": "x",
            "kernel": {"version": "6.8.12-1021-tegra", "config_source": "/boot/config", "config_sha256": "ab" * 32},
            "component": {"name": "linux-nvidia-tegra", "version": "6.8.0-1021.21",
                          "purl": "pkg:deb/ubuntu/linux-nvidia-tegra@6.8.0-1021.21?arch=source&distro=ubuntu-24.04"},
            "results": results, "counts": {}}


NVB = {"jetson_linux": {"version": "39.2.1", "line": "39", "build_date": "2026-08-06",
                        "anchor": {"name": "nvidia-l4t-core", "version": "39.2.1-20260806224157",
                                   "purl": "pkg:deb/ubuntu/nvidia-l4t-core@39.2.1-20260806224157?arch=arm64&distro=ubuntu-24.04"}},
       "presumed_included": [{"bulletin": "5321", "cve": "CVE-2021-34401", "bulletin_date": "2022-03-08", "lines_named": ["32"]},
                             {"bulletin": "5400", "cve": "CVE-2022-1111", "bulletin_date": "2022-05-01", "lines_named": ["35"]}],
       "needs_vendor_confirmation": [{"bulletin": "5500", "cve": "CVE-2026-2222", "reason": "line_not_named", "lines_named": ["36"]},
                                     {"bulletin": "5401", "cve": "CVE-2022-1111", "reason": "line_not_named", "lines_named": ["38"]}],
       "findings": []}


# ---------- 各來源的對映 ----------

def test_dt_human_analysis_mapping_keeps_text():
    rs = [row("CVE-1", analysis=dt("NOT_AFFECTED", "CODE_NOT_REACHABLE", "", "feature disabled")),
          row("CVE-2", analysis=dt("EXPLOITABLE", "", "WORKAROUND_AVAILABLE", "set foo=off")),
          row("CVE-3", analysis=dt("FALSE_POSITIVE", "CODE_NOT_PRESENT")), row("CVE-4", analysis=dt("RESOLVED")), row("CVE-5", analysis=dt("IN_TRIAGE")),
          row("CVE-6", analysis=dt("NOT_SET", suppressed=True)), row("CVE-7")]
    allr, conf, info = vx.assess(rs)
    v = {r["id"]: r["vex"] for r in allr}
    assert v["CVE-1"] == {"source": "dt", "state": "not_affected", "justification": "code_not_reachable", "detail": "feature disabled"}
    assert v["CVE-2"]["state"] == "exploitable" and v["CVE-2"]["response"] == ["workaround_available"] and v["CVE-2"]["detail"] == "set foo=off"
    assert v["CVE-3"] == {"source": "dt", "state": "false_positive", "justification": "code_not_present",
                          "detail": "Assessed as FALSE_POSITIVE (code_not_present) in Dependency-Track; no details were included in the "
                                    "Dependency-Track findings export."}
    assert v["CVE-4"]["state"] == "resolved" and v["CVE-5"]["state"] == "in_triage"
    assert v["CVE-6"] is None and "suppressed in Dependency-Track without an analysis state" in allr[5]["vex_note"]
    assert v["CVE-7"] is None and info["sources"]["dt"] == 5 and info["suppressed_without_state"] == 1 and conf == []


def test_dt_findings_disagree_within_row_takes_conservative():
    r = row("CVE-1", analysis=dt("NOT_AFFECTED", "CODE_NOT_PRESENT") + dt("EXPLOITABLE", response="UPDATE") + dt(""))
    allr, conf, info = vx.assess([r])
    assert allr[0]["vex"]["state"] == "exploitable" and info["dt_partial"] == 1
    assert conf == [{"id": "CVE-1", "component": "openssl", "version": OSSL, "used": "dt:exploitable", "other": "dt:not_affected", "human": True}]


def test_distro_fixed_maps_to_resolved_with_detail():
    drc = recheck_doc()
    rs = [row("CVE-2024-6119"), row("CVE-2026-63076"),                                           # 已修補、仍受影響
          row("CVE-2026-3000", source_ids=["GITHUB:GHSA-3000-aaaa-bbbb", "NVD:CVE-2026-3000"]),      # 列裡有 recheck 沒看過的 finding
          row("CVE-2026-4000", "linux-image-6.8.0-1021-nvidia-tegra", "6.8.0-1021.21", kernel=True)]
    allr, conf, info = vx.assess(rs, drc=drc)
    v = {r["id"]: r["vex"] for r in allr}
    assert v["CVE-2024-6119"]["state"] == "resolved" and v["CVE-2024-6119"]["source"] == "distro"
    assert v["CVE-2024-6119"]["detail"].startswith(f"fixed by Ubuntu 24.04 (noble) in 3.0.13-0ubuntu3.4 (UBUNTU-CVE-2024-6119); installed {OSSL}.")
    assert v["CVE-2026-63076"] is None and v["CVE-2026-3000"] is None and v["CVE-2026-4000"] is None
    # status 不是 OK 時一列都不用
    allr, _, _ = vx.assess([row("CVE-2024-6119")], drc=recheck_doc("GAP"))
    assert allr[0]["vex"] is None


def test_kernel_config_not_affected_only_for_kernel_rows_and_status_ok():
    k = kcfg([{"cve": "CVE-2025-1", "decision": "not_affected", "justification": "vulnerable_code_not_present",
               "detail": "only built with CONFIG_FOO; not set"},
              {"cve": "CVE-2025-2", "decision": "affected"}, {"cve": "CVE-2025-3", "decision": "unknown"}])
    rs = [row("CVE-2025-1", "linux-nvidia-tegra", "6.8.0-1021.21", kernel=True), row("CVE-2025-2", "linux-nvidia-tegra", "6.8.0-1021.21", kernel=True),
          row("CVE-2025-3", "linux-nvidia-tegra", "6.8.0-1021.21", kernel=True), row("CVE-2025-1", "libfoo", "1.0")]
    allr, _, info = vx.assess(rs, kcfg=k)
    v = [r["vex"] for r in allr]
    assert v[0]["state"] == "not_affected" and v[0]["justification"] == "code_not_present" and v[0]["source"] == "kconfig"
    assert "only built with CONFIG_FOO; not set" in v[0]["detail"] and "/boot/config" in v[0]["detail"]
    assert v[1] is None and v[2] is None and v[3] is None          # affected／unknown 不加；不是核心的列不套用
    assert info["kernel_config"] == {"status": "OK", "not_affected": 1, "used": True}
    for bad in (kcfg(k["results"], "GAP"), dict(k, schema="other/1")):
        assert vx.assess([row("CVE-2025-1", "linux-nvidia-tegra", "6.8.0-1021.21", kernel=True)], kcfg=bad)[0][0]["vex"] is None


def test_nvidia_presumed_is_in_triage_and_confirmation_is_untriaged():
    allr, _, info = vx.assess([row("CVE-2025-9")], nvb=NVB)
    extra = {r["id"]: r for r in allr if r.get("tier") == "nvidia_bulletin"}
    assert sorted(extra) == ["CVE-2021-34401", "CVE-2022-1111", "CVE-2026-2222"]
    p = extra["CVE-2021-34401"]["vex"]
    assert p["state"] == "in_triage" and p["source"] == "nvidia" and "presumed to be included" in p["detail"] and "not confirmed" in p["detail"]
    # 同一個 CVE 另有公告要原廠確認 → 不推定；需原廠確認 → 沒有判定
    assert extra["CVE-2022-1111"]["vex"] is None and extra["CVE-2026-2222"]["vex"] is None
    assert extra["CVE-2021-34401"]["component"] == "nvidia-l4t-core" and info["nvidia_extra_rows"] == 3
    # 已有 nvidia-l4t 元件上同一個 CVE 的列 → 套用到那一列，不另加
    r = row("CVE-2021-34401", "nvidia-l4t-core", "39.2.1-20260806224157", source_ids=["NVIDIA:CVE-2021-34401"])
    allr, _, _ = vx.assess([r], nvb=NVB)
    assert allr[0]["vex"]["state"] == "in_triage" and "CVE-2021-34401" not in [x["id"] for x in allr[1:]]
    assert all(s["state"] not in ("resolved", "not_affected") for s in (x["vex"] for x in allr) if s)


# ---------- 優先順序與衝突 ----------

def test_precedence_human_wins_and_conflicts_logged():
    drc = recheck_doc()
    rs = [row("CVE-2024-6119", analysis=dt("EXPLOITABLE", response="UPDATE", details="our build reverts the patch")),
          row("CVE-2026-45447"), row("CVE-2026-1000")]
    anns = [ann("CVE-2026-45447", "exploitable", detail="vendor patch not applied"),
            ann("CVE-2026-1000", "resolved", detail="fixed")]
    allr, conf, info = vx.assess(rs, drc=drc, annotations=anns)
    v = {r["id"]: r["vex"] for r in allr}
    assert v["CVE-2024-6119"]["source"] == "dt" and v["CVE-2024-6119"]["state"] == "exploitable"
    assert v["CVE-2026-45447"]["source"] == "annotation" and v["CVE-2026-45447"]["author"] == "Alice"
    assert v["CVE-2026-1000"]["source"] == "annotation"                     # 判定一樣（resolved）→ 不是衝突
    assert [(c["id"], c["used"], c["other"], c["human"]) for c in conf] == [
        ("CVE-2024-6119", "dt:exploitable", "distro:resolved", False), ("CVE-2026-45447", "annotation:exploitable", "distro:resolved", False)]
    # DT 與 annotation 不同 → 人工判定衝突，取較保守的（具名的 exploitable 註記不被舊的 DT not_affected 蓋過），閘門 ATTENTION
    allr, conf, _ = vx.assess([row("CVE-9", analysis=dt("NOT_AFFECTED", "CODE_NOT_PRESENT"))], annotations=[ann("CVE-9", "exploitable")])
    assert allr[0]["vex"]["source"] == "annotation" and allr[0]["vex"]["state"] == "exploitable"
    assert conf[0]["human"] is True and conf[0]["used"] == "annotation:exploitable" and conf[0]["other"] == "dt:not_affected"
    g = vx.gate(allr, conf, grype_checked=True, not_assessed=[])
    assert g["verdict"] == "ATTENTION" and g["human_conflicts"] == 1 and any("conflicting human decisions" in x for x in g["reasons"])


def test_annotation_scope_matching_and_specificity():
    src = row("CVE-1", "openssl", OSSL, purl="pkg:deb/ubuntu/openssl@" + OSSL + "?arch=source&distro=ubuntu-24.04", installed_as=["libssl3t64"])
    other = row("CVE-1", "openssl", "3.0.13-0ubuntu3.12")
    lib = row("CVE-1", "libfoo", "1.0")
    m = vx.annotation_matches
    assert m(ann("CVE-1"), src) and m(ann("cve-1"), lib)                                  # 只有 CVE：任何元件
    assert m(ann("CVE-1", purl="pkg:deb/ubuntu/openssl"), other) and not m(ann("CVE-1", purl="pkg:deb/ubuntu/openssl"), lib)
    assert m(ann("CVE-1", purl=f"pkg:deb/ubuntu/openssl@{OSSL}"), src) and not m(ann("CVE-1", purl=f"pkg:deb/ubuntu/openssl@{OSSL}"), other)
    assert m(ann("CVE-1", version=OSSL), src) and not m(ann("CVE-1", version=OSSL), other)
    assert m(ann("CVE-1", purl="pkg:deb/ubuntu/libssl3t64"), src)                         # DT 的原始碼套件 → 安裝的二進位套件
    assert not m(ann("CVE-2"), src)
    assert m(ann("GHSA-aaaa-bbbb-cccc"), row("GHSA-aaaa-bbbb-cccc", "tool", "0.1", purl="pkg:golang/example.com/tool@0.1"))
    anns = [ann("CVE-1", "exploitable"), ann("CVE-1", "not_affected", purl="pkg:deb/ubuntu/openssl"),
            ann("CVE-1", "resolved", purl="pkg:deb/ubuntu/openssl", version=OSSL), ann("CVE-7")]
    allr, conf, info = vx.assess([copy.deepcopy(src), copy.deepcopy(other), copy.deepcopy(lib)], annotations=anns)
    assert [r["vex"]["state"] for r in allr] == ["resolved", "not_affected", "exploitable"]   # 越精確越優先
    assert conf == [] and info["annotations_used"] == 3 and info["annotations_unused"] == [3]


def test_annotation_file_validation(tmp_path):
    good = {"schema": vx.ANN_SCHEMA, "annotations": [ann("CVE-1"), ann("CVE-1", purl="pkg:deb/ubuntu/openssl")]}
    assert len(vx.check_annotations(good)) == 2
    bad = [({"schema": "x", "annotations": []}, "schema"),
           ({"schema": vx.ANN_SCHEMA, "annotations": [ann("CVE-1", justification=None)]}, "not_affected 一定要寫理由"),
           ({"schema": vx.ANN_SCHEMA, "annotations": [ann("CVE-1", "exploitable", response=[])]}, "exploitable 一定要寫處理方式"),
           ({"schema": vx.ANN_SCHEMA, "annotations": [ann("CVE-1", state="fixed")]}, "state：只能是"),
           ({"schema": vx.ANN_SCHEMA, "annotations": [ann("CVE-1", date="1.11.2026")]}, "YYYY-MM-DD"),
           ({"schema": vx.ANN_SCHEMA, "annotations": [ann("CVE-1", author="")]}, "author：必填"),
           ({"schema": vx.ANN_SCHEMA, "annotations": [ann("CVE-1", purl="openssl")]}, "不是 purl"),
           ({"schema": vx.ANN_SCHEMA, "annotations": [ann("CVE-1", comment="x")]}, "不認得的鍵"),
           ({"schema": vx.ANN_SCHEMA, "annotations": [ann("CVE-1"), ann("CVE-1", "resolved")]}, "範圍相同")]
    for doc, msg in bad:
        with pytest.raises(vx.VexInputError, match=msg):
            vx.check_annotations(doc)
    assert vx.load_annotations(tmp_path) == ([], None)


def annotate(proj, *args):
    return subprocess.run([sys.executable, "-I", str(CLI), "annotate", "--project", str(proj), *args], capture_output=True, text=True, timeout=30)


def test_annotate_cli_appends_safely(tmp_path):
    proj = tmp_path / "p"
    proj.mkdir()
    r = annotate(proj, "--cve", "CVE-2024-6119", "--state", "not_affected", "--justification", "code_not_reachable",
                 "--detail", "TLS server code not used", "--author", "Alice", "--date", "2026-11-01", "--purl", "pkg:deb/ubuntu/openssl")
    assert r.returncode == 0 and r.stdout.startswith("OK\t"), r.stdout + r.stderr
    f = proj / vx.ANN_REL
    doc = json.loads(f.read_text(encoding="utf-8"))
    assert doc["schema"] == vx.ANN_SCHEMA and doc["annotations"] == [
        {"cve": "CVE-2024-6119", "state": "not_affected", "detail": "TLS server code not used", "author": "Alice", "date": "2026-11-01",
         "purl": "pkg:deb/ubuntu/openssl", "justification": "code_not_reachable"}]
    before = f.read_bytes()
    # 同一範圍再加 → 拒絕、檔案不變；不合規則（not_affected 沒有理由）→ 拒絕、檔案不變
    r = annotate(proj, "--cve", "CVE-2024-6119", "--state", "resolved", "--detail", "x", "--author", "Bob", "--purl", "pkg:deb/ubuntu/openssl")
    assert r.returncode == 1 and "--replace" in r.stdout and f.read_bytes() == before
    r = annotate(proj, "--cve", "CVE-2025-1", "--state", "not_affected", "--detail", "x", "--author", "Bob")
    assert r.returncode == 1 and "理由" in r.stdout and f.read_bytes() == before
    r = annotate(proj, "--cve", "CVE-2025-1", "--state", "exploitable", "--response", "update", "--detail", "upgrade in 2.4", "--author", "Bob")
    assert r.returncode == 0
    r = annotate(proj, "--cve", "CVE-2024-6119", "--state", "resolved", "--detail", "x", "--author", "Bob", "--purl", "pkg:deb/ubuntu/openssl",
                 "--replace")
    assert r.returncode == 0 and "取代" in r.stdout
    doc = json.loads(f.read_text(encoding="utf-8"))
    assert [(a["cve"], a["state"]) for a in doc["annotations"]] == [("CVE-2024-6119", "resolved"), ("CVE-2025-1", "exploitable")]
    assert not [p for p in f.parent.iterdir() if p.name.startswith(".vex-annotations.") and not p.name.endswith(".lock")]  # 沒有留下暫存檔
    # 檔案已壞 → 不覆寫
    f.write_text("{broken", encoding="utf-8")
    r = annotate(proj, "--cve", "CVE-2025-2", "--state", "resolved", "--detail", "x", "--author", "Bob")
    assert r.returncode == 1 and f.read_text(encoding="utf-8") == "{broken"
    r = subprocess.run([sys.executable, "-I", str(CLI), "check", "--project", str(proj)], capture_output=True, text=True, timeout=30)
    assert r.returncode == 1 and r.stdout.startswith("FAIL")
    r = subprocess.run([sys.executable, "-I", str(CLI), "annotate", "--project", str(proj), "--cve", "X"], capture_output=True, text=True, timeout=30)
    assert r.returncode == 64


# ---------- 發行閘門 ----------

def test_gate_verdicts():
    def g(rs, **kw):
        allr, conf, _ = vx.assess(rs)
        typed(allr)           # 因 D-035 而變：DT 的排除沒有依據類型會擋閘門；這裡要看的是其他規則，所以補上類型
        return vx.gate(allr, conf, **{"grype_checked": True, "not_assessed": [], **kw})
    ok = g([row("CVE-1", analysis=dt("NOT_AFFECTED", "CODE_NOT_PRESENT")), row("CVE-2", "linux", "6.8", kernel=True, analysis=dt("RESOLVED")),
            row("CVE-3", analysis=dt("IN_TRIAGE")), row("CVE-4", analysis=dt("EXPLOITABLE", response="UPDATE"))])
    # 每一列都有判定，但 CVE-4 仍受影響（exploitable）：評估完整、要有人做出貨決定 → ATTENTION，永遠不是 OK
    assert ok["verdict"] == "ATTENTION" and ok["in_triage"] == 1 and ok["assessment"]["complete"] is True
    assert ok["reasons"] == ["assessment complete; 1 affected rows (exploitable; 0 by bulk rules) need a release decision by a person "
                             "(fixed before placing on the market, or a documented risk-based justification): by response update 1"]
    assert ok["open_affected"] == {"rows": 1, "by_response": {"update": 1}, "by_rule": 0, "individual": 1}
    assert ok["counts"]["kernel"] == {"rows": 1, "resolved": 1, "not_affected": 0, "exploitable": 0, "in_triage": 0, "untriaged": 0}
    assert ok["counts"]["non_kernel"]["rows"] == 3 and ok["counts"]["total"]["exploitable"] == 1
    assert g([row("CVE-1", analysis=dt("NOT_AFFECTED", "CODE_NOT_PRESENT")), row("CVE-3", analysis=dt("IN_TRIAGE"))])["verdict"] == "OK"
    a = g([row("CVE-1", tier="p3"), row("CVE-2", tier="p1", kev=True), row("CVE-3", tier="p2", epss_pct=0.5),
           row("CVE-4", analysis=dt("EXPLOITABLE"))])
    assert a["verdict"] == "ATTENTION" and a["exploitable_without_response"] == 1 and a["untriaged_high"] == 2
    assert a["reasons"][:2] == ["3 untriaged (P1 1, P2 1, P3 1, other 0)", "1 exploitable without a response"]
    assert [x["id"] for x in a["top_untriaged"]] == ["CVE-2", "CVE-3", "CVE-1"]
    b = a["untriaged_breakdown"]
    assert b["groups"] == [{"type": "deb", "fix_state": "none", "rows": 3, "tiers": {"p1": 1, "p2": 1, "p3": 1}}]
    assert b["components"] == [{"component": "openssl", "type": "deb", "rows": 3, "fix_states": {"none": 3},
                                "tiers": {"p1": 1, "p2": 1, "p3": 1}}] and b["components_total"] == 1
    b = g([row("CVE-1", fix_state="not-fixed"), row("CVE-2", fix_state="not-fixed"), row("CVE-3", "zlib1g", "1.3", fix_state="wont-fix"),
           row("CVE-4", "linux", "6.8", kernel=True, fix_state="not-fixed", tier="p3"),
           row("GHSA-x", "requests", "2.0", purl="pkg:pypi/requests@2.0", fix_state="fixed"), row("CVE-5", fix_state="fixed", analysis=dt("RESOLVED"))]
          )["untriaged_breakdown"]
    assert [(x["type"], x["fix_state"], x["rows"]) for x in b["groups"]] == [
        ("deb", "not-fixed", 2), ("deb", "wont-fix", 1), ("kernel", "not-fixed", 1), ("pypi", "fixed", 1)]
    assert [(x["component"], x["rows"]) for x in b["components"]] == [("openssl", 2), ("linux", 1), ("requests", 1), ("zlib1g", 1)]
    assert g([row("CVE-1", analysis=dt("RESOLVED"))], grype_only=2)["verdict"] == "ATTENTION"
    gap = g([row("CVE-1", analysis=dt("RESOLVED"))], data_status="GAP")
    assert gap["verdict"] == "GAP" and "incomplete" in gap["reasons"][0]
    assert g([], have_findings=False)["verdict"] == "NOT_ASSESSED"
    assert g([])["verdict"] == "OK"                                # 有 findings、0 列（沒有比對到弱點）


# ---------- 文件 ----------

PBOM = {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79", "version": 1,
        "metadata": {"component": {"type": "firmware", "bom-ref": "root", "name": "EX-J100", "version": "2.3.0"}},
        "components": [{"bom-ref": "pkg:deb/ubuntu/openssl@3.0.13?id=1", "type": "library", "name": "openssl", "version": OSSL,
                        "purl": DEB.format("openssl", OSSL)},
                       {"bom-ref": "libssl", "type": "library", "name": "libssl3t64", "version": OSSL, "purl": DEB.format("libssl3t64", OSSL)},
                       {"bom-ref": "l4t-k", "type": "library", "name": "nvidia-l4t-kernel", "version": "5.15-39.2.1",
                        "purl": DEB.format("nvidia-l4t-kernel", "5.15-39.2.1")}]}


def is_na(v):
    """CycloneDX 的 vulnerability 是不是「沒有評估」的陳述（M7c-1，A4／D-057：in_triage 加 dumpling:assessment＝NOT_ASSESSED）。"""
    return {"name": "dumpling:assessment", "value": "NOT_ASSESSED"} in (v.get("properties") or [])


def assessed(cdx):
    """只留有判定的陳述。沒有判定的列從 A4（M7c-1）起也會寫進 VEX，這些測試要確認的是有判定的那幾條。"""
    return [v for v in cdx["vulnerabilities"] if not is_na(v)]


def sample_rows():
    return [row("CVE-2024-6119"), row("CVE-1", analysis=dt("NOT_AFFECTED", "CODE_NOT_PRESENT", details="not built")),
            row("CVE-2", "openssl", OSSL, purl=f"pkg:deb/ubuntu/openssl@{OSSL}?arch=source&distro=ubuntu-24.04", installed_as=["libssl3t64"],
                analysis=dt("EXPLOITABLE", response="UPDATE", details="fix in 2.4")),
            row("CVE-3", "linux-nvidia-tegra", "6.8.0-1021.21", kernel=True, mapped_from="nvidia-l4t-kernel 5.15-39.2.1",
                purl="pkg:deb/ubuntu/linux-nvidia-tegra@6.8.0-1021.21", analysis=dt("FALSE_POSITIVE", "PROTECTED_AT_PERIMETER")),
            row("CVE-4", "notinsbom", "1", analysis=dt("IN_TRIAGE")), row("CVE-5")]


def build(rows):
    allr, conf, _ = vx.assess(rows, drc=recheck_doc())
    cdx, st = vx.cdx_vex(allr, PBOM, {"finished": "2026-11-02T02:43:55Z", "name": "img"}, {"name": "EX-J100"}, "ATTENTION")
    return cdx, st, vx.openvex(cdx, "Example Co.", vx.purl_by_bomlink(PBOM))


def test_cyclonedx_shape():
    cdx, st, _ = build(sample_rows())
    assert cdx["bomFormat"] == "CycloneDX" and cdx["specVersion"] == "1.6" and cdx["version"] == 1
    assert re.match(r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", cdx["serialNumber"])
    assert cdx["metadata"]["timestamp"] == "2026-11-02T02:43:55Z" and cdx["metadata"]["component"]["name"] == "EX-J100"
    v = {x["id"]: x for x in cdx["vulnerabilities"]}
    # M7c-1（A4／D-057）起沒有判定的 CVE-5 也寫（in_triage 加 dumpling:assessment＝NOT_ASSESSED）；以前這裡是五條、不含 CVE-5
    assert sorted(v) == ["CVE-1", "CVE-2", "CVE-2024-6119", "CVE-3", "CVE-4", "CVE-5"]
    assert v["CVE-5"]["analysis"]["state"] == "in_triage" and {"name": "dumpling:assessment", "value": "NOT_ASSESSED"} in v["CVE-5"]["properties"]
    assert "dumpling:assessment" not in json.dumps(v["CVE-4"])         # CVE-4 是 DT 的 IN_TRIAGE（有判定）：沒有標記
    refs = {c["bom-ref"] for c in PBOM["components"]}
    for x in cdx["vulnerabilities"]:
        assert x["bom-ref"] and x["analysis"]["state"] in vx.CDX_STATES and x["analysis"]["detail"]
        for a in x["affects"]:
            if a["ref"] in {c["bom-ref"] for c in cdx.get("components") or []}:
                continue
            m = re.match(r"^urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1#(.+)$", a["ref"])
            assert m and (m.group(1) in refs | {"root"} or m.group(1).replace("%3F", "?") in refs), a["ref"]
    assert v["CVE-1"]["analysis"] == {"state": "not_affected", "justification": "code_not_present", "detail": "not built"}
    assert v["CVE-2"]["analysis"]["response"] == ["update"] and v["CVE-2"]["affects"] == [{"ref": "urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1#libssl"}]
    assert v["CVE-3"]["affects"][0]["ref"].endswith("#l4t-k")                        # 核心：對應來源的 nvidia-l4t-kernel
    # 不在產品 SBOM 的元件：列在 VEX 自己的 components，affects 指向它（不擴大成整個產品）
    assert st["components_not_in_sbom"] == 1 and len(cdx["components"]) == 1
    c = cdx["components"][0]
    assert v["CVE-4"]["affects"] == [{"ref": c["bom-ref"]}] and c["purl"] == DEB.format("notinsbom", "1") and c["name"] == "notinsbom"
    assert not any(a["ref"].endswith("#root") for x in cdx["vulnerabilities"] for a in x["affects"])
    assert v["CVE-2024-6119"]["analysis"]["state"] == "resolved"
    assert len({x["bom-ref"] for x in cdx["vulnerabilities"]}) == len(cdx["vulnerabilities"])


def test_openvex_shape():
    _, _, ov = build(sample_rows())
    assert ov["@context"] == "https://openvex.dev/ns/v0.2.0" and ov["@id"].startswith("urn:uuid:") and ov["author"] == "Example Co."
    assert ov["timestamp"] == "2026-11-02T02:43:55Z" and ov["version"] == 1
    s = {x["vulnerability"]["name"]: x for x in ov["statements"]}
    assert s["CVE-2024-6119"]["status"] == "fixed" and s["CVE-2024-6119"]["status_notes"].startswith("fixed by Ubuntu 24.04")
    assert s["CVE-1"]["status"] == "not_affected" and s["CVE-1"]["justification"] == "vulnerable_code_not_present"
    assert s["CVE-2"]["status"] == "affected" and s["CVE-2"]["action_statement"] == "Planned response: update. fix in 2.4"
    assert s["CVE-3"]["status"] == "not_affected" and s["CVE-4"]["status"] == "under_investigation"
    assert s["CVE-3"]["justification"] == "vulnerable_code_cannot_be_controlled_by_adversary"     # protected_at_perimeter
    assert s["CVE-3"]["impact_statement"].startswith("[cyclonedx:justification=protected_at_perimeter]")
    assert s["CVE-4"]["products"] == [{"@id": DEB.format("notinsbom", "1"), "identifiers": {"purl": DEB.format("notinsbom", "1")}}]
    assert s["CVE-2"]["products"] == [{"@id": DEB.format("libssl3t64", OSSL), "identifiers": {"purl": DEB.format("libssl3t64", OSSL)}}]
    for x in ov["statements"]:
        assert x["products"] and all(p.get("@id") for p in x["products"])
    assert vx.openvex({"vulnerabilities": []}, "x", {}) is None


def test_output_is_deterministic_and_order_independent():
    a = build(sample_rows())
    rs = sample_rows()
    random.Random(4).shuffle(rs)
    b = build(rs)
    assert vx.dumps(a[0]) == vx.dumps(b[0]) and vx.dumps(a[2]) == vx.dumps(b[2])
    c = build(sample_rows()[:-2])                         # 內容不同 → 序號不同
    assert c[0]["serialNumber"] != a[0]["serialNumber"]


OV_SCHEMA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "openvex", "openvex_json_schema.json")


def test_official_schemas():
    jsonschema = pytest.importorskip("jsonschema")
    from cdx_schema import cdx_validator
    cdx, _, ov = build(sample_rows())
    errs = list(cdx_validator().iter_errors(cdx))
    assert not errs, [e.message for e in errs[:3]]
    errs = list(jsonschema.Draft202012Validator(json.load(open(OV_SCHEMA)),
                                                format_checker=jsonschema.FormatChecker()).iter_errors(ov))
    assert not errs, [e.message for e in errs[:3]]


# ---------- cra_report 整合 ----------

def ra(rep):
    return (rep / "risk-assessment.md").read_text(encoding="utf-8")


def test_report_integration(tmp_path):
    proj = make_project(tmp_path / "p")
    write_json(proj / vx.ANN_REL, {"schema": vx.ANN_SCHEMA, "annotations": [
        ann("CVE-2026-61897", detail="accountsservice is not installed in the product image", purl="pkg:deb/ubuntu/accountsservice")]})
    sc = make_scan(tmp_path / "s", findings=FINDINGS + EXTRA, stages={"D-distro-recheck": "OK"}, meta=dict(META, finished="2026-11-02T02:43:55Z"))
    write_json(sc / "scan" / "distro-recheck.json", recheck_doc())
    r, s, rep = run(proj, sc)
    assert r.returncode in (0, 2), r.stdout + r.stderr
    md = ra(rep)
    assert "## 8. Known vulnerabilities: candidates from automated matching and their assessment" in md
    assert "Known exploitable vulnerabilities" not in md and "**candidate vulnerabilities**" in md
    assert "### 8.9 Vulnerability status (VEX) and release gate" in md       # 8.8 是發行版已修補（沒有 NVIDIA）
    p1 = md.split("### 8.4 P1")[1].split("### 8.5")[0]
    assert "| VEX status |" in p1 and "| untriaged |" in p1
    p2 = md.split("### 8.5 P2")[1].split("### 8.6")[0]
    # VEX 判定不受影響的列移到 accepted（風險評估的層級和 VEX 一致），附錄 A 列出判定的來源與說明
    assert "CVE-2026-61897" not in p2 and s["counts"]["accepted_by_vex"] == {"annotation": 1}
    assert "VEX not_affected (annotation" in next(x for x in md.splitlines() if "CVE-2026-61897" in x and "not installed" in x)
    v = s["vex"]
    assert v["files"]["vex.cdx.json"]["statements"] == v["files"]["vex.openvex.json"]["statements"] > 0
    # libbar1 的 FALSE_POSITIVE 沒有理由 → 不採用，閘門點名
    assert v["sources"]["distro"] == 4 and v["sources"]["annotation"] == 1 and v["sources"]["dt"] == 1
    assert v["gate"]["dt_without_justification"] == [{"id": "CVE-2025-0005", "component": "libbar1", "version": "2.0-1", "states": ["FALSE_POSITIVE"]}]
    assert any(x.startswith("1 Dependency-Track analyses without justification") for x in v["gate"]["reasons"])
    assert v["annotations"]["count"] == 1 and v["annotations"]["used"] == 1 and v["section"] == "8.9"
    assert v["gate"]["verdict"] == "ATTENTION" and v["gate"]["counts"]["total"]["rows"] == s["counts"]["rows"]
    for n in ("vex.cdx.json", "vex.openvex.json"):
        import hashlib
        assert hashlib.sha256((rep / n).read_bytes()).hexdigest() == v["files"][n]["sha256"]
    cdx = json.loads((rep / "vex.cdx.json").read_text(encoding="utf-8"))
    prod = json.loads((rep / "sbom.cdx.json").read_text(encoding="utf-8"))
    local = {c["bom-ref"] for c in cdx.get("components") or []}
    assert all(a["ref"].startswith("urn:cdx:" + prod["serialNumber"][9:] + "/1#") or a["ref"] in local
               for x in cdx["vulnerabilities"] for a in x["affects"])
    assert not any(a["ref"].endswith("#" + prod["metadata"]["component"]["bom-ref"]) for x in cdx["vulnerabilities"] for a in x["affects"])
    td = (rep / "technical-documentation.md").read_text(encoding="utf-8")
    assert "Vulnerability status (VEX) and release gate: `risk-assessment.md`, section 8.9; release gate **ATTENTION**" in td
    assert "release gate ATTENTION, see the subsection on vulnerability status (VEX)" in md     # Annex I (a)
    # 第二次執行：VEX 檔案相同（輸出穩定）
    r2, s2, rep2 = run(proj, sc)
    assert s2["vex"]["files"] == v["files"] and v["timestamp_source"] == "meta.finished"
    # 沒有掃描時間時用原始 SBOM 的時間；都沒有才用現在（記在 timestamp_source）
    s3 = run(make_project(tmp_path / "p3"), make_scan(tmp_path / "s3", sbom=dict(SBOM, metadata=dict(SBOM["metadata"], timestamp="2026-10-30T01:02:03Z"))))[1]
    assert s3["vex"]["timestamp_source"] == "source SBOM timestamp"
    assert run(make_project(tmp_path / "p4"), make_scan(tmp_path / "s4"))[1]["vex"]["timestamp_source"].startswith("generated")


def test_report_kernel_table_has_vex_column_and_kconfig(tmp_path):
    from test_cra_report import kernel_scan
    sc = kernel_scan(tmp_path / "s")
    write_json(sc / "scan" / "kernel-config.json", kcfg([{"cve": "CVE-2025-0102", "decision": "not_affected", "detail": "CONFIG_X not set"}]))
    r, s, rep = run(make_project(tmp_path / "p"), sc)
    full = (rep / "kernel-vulnerabilities.md").read_text(encoding="utf-8")
    assert "| VEX status |" in full and any("CVE-2025-0102" in x and "| not_affected (kconfig) |" in x for x in full.splitlines())
    assert any("CVE-2025-0102" in x and "VEX not_affected (kconfig)" in x for x in full.splitlines())    # accepted 表
    assert "| VEX status |" in ra(rep).split("#### Kernel rows in P1")[1]
    # 風險評估只寫 VEX 判定的數量（核心設定可能上千列），逐列在 kernel-vulnerabilities.md
    assert "CVE-2025-0102" not in ra(rep).split("#### Accepted kernel rows")[1].split("####")[0]
    assert "1 by kconfig" in ra(rep) and s["counts"]["accepted_by_vex"] == {"kconfig": 1}
    # 核心的 not_affected：kconfig 1 列＋DT 已判定的 accepted 1 列
    assert s["vex"]["gate"]["counts"]["kernel"]["not_affected"] == 2 and s["vex"]["sources"]["kconfig"] == 1
    assert s["vex"]["kernel_config"]["used"] is True


def test_non_debian_scan_and_no_findings(tmp_path):
    pyf = [finding("requests", "2.0", "GHSA-xxxx-yyyy-zzzz", "GITHUB", "HIGH", [{"cveId": "CVE-2024-35195"}], purl="pkg:pypi/requests@2.0")]
    sbom = dict(SBOM, components=[{"type": "library", "name": "requests", "version": "2.0", "purl": "pkg:pypi/requests@2.0", "bom-ref": "r"}])
    r, s, rep = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s", findings=pyf, grype={"matches": []}, sbom=sbom, meta=dict(META, mode="dir")))
    assert s["vex"]["gate"]["verdict"] == "ATTENTION" and s["vex"]["gate"]["counts"]["total"]["untriaged"] == 1
    # A4（M7c-1）：沒有判定的那一列也寫進 VEX（in_triage／under_investigation 加 NOT_ASSESSED）。以前這裡是 0 條陳述、OpenVEX 不寫
    f = s["vex"]["files"]
    assert f["vex.cdx.json"]["statements"] == 1 and f["vex.cdx.json"]["not_assessed"] == 1
    assert f["vex.openvex.json"]["statements"] == 1 and f["vex.openvex.json"]["not_assessed"] == 1
    assert s["vex"]["statements_assessed"] == 0 and s["vex"]["statements_not_assessed"] == 1
    assert (rep / "vex.cdx.json").exists() and (rep / "vex.openvex.json").exists()
    assert "`vex.openvex.json` (1 statements, 1 of them not assessed, SHA-256 " in ra(rep)
    # 沒有 DT findings：不寫 VEX、刪掉上一次的、閘門 NOT_ASSESSED
    proj = make_project(tmp_path / "p2")
    run(proj, make_scan(tmp_path / "s2"))
    r, s, rep = run(proj, make_scan(tmp_path / "s3", findings=None))
    assert s["vex"]["gate"]["verdict"] == "NOT_ASSESSED" and not (rep / "vex.cdx.json").exists() and not (rep / "vex.openvex.json").exists()


def test_bad_annotation_file_fails_and_removes_vex(tmp_path):
    proj = make_project(tmp_path / "p")
    sc = make_scan(tmp_path / "s")
    run(proj, sc)
    assert (proj / "CRA" / "Reports" / "vex.cdx.json").exists()
    write_json(proj / vx.ANN_REL, {"schema": vx.ANN_SCHEMA, "annotations": [{"cve": "CVE-1", "state": "not_affected"}]})
    r, s, rep = run(proj, sc)
    assert r.returncode == 1 and s["status"] == "FAIL" and "VEX 人工判定檔有錯" in s["error"]
    assert not (rep / "vex.cdx.json").exists()


def test_dt_readback_supplies_justification(tmp_path):
    f = finding("libbar1", "2.0-1", "CVE-2025-0005", "NVD", "HIGH", analysis={"isSuppressed": False, "state": "NOT_AFFECTED"})
    sc = make_scan(tmp_path / "s", findings=[f])
    write_json(sc / "dt" / "analysis.json", [{"vuln": "CVE-2025-0005", "source": "NVD", "component": "libbar1@2.0-1",
                                              "purl": f["component"]["purl"], "analysis_http": 200,
                                              "analysis": {"analysisState": "NOT_AFFECTED", "analysisJustification": "REQUIRES_CONFIGURATION",
                                                           "analysisResponse": "NOT_SET", "analysisDetails": "needs bar=on", "isSuppressed": False}}])
    r, s, rep = run(make_project(tmp_path / "p"), sc)
    cdx = json.loads((rep / "vex.cdx.json").read_text(encoding="utf-8"))
    assert cdx["vulnerabilities"][0]["analysis"] == {"state": "not_affected", "justification": "requires_configuration", "detail": "needs bar=on"}
    assert s["vex"]["gate"]["verdict"] in ("OK", "ATTENTION") and s["vex"]["gate"]["counts"]["total"]["not_affected"] == 1


def test_project_template_without_vex_section_warns(tmp_path):
    tpl = (HERE.parent / "templates" / "risk-assessment.md").read_text(encoding="utf-8").replace("{{ text.vex_section }}", "")
    r, s, rep = run(make_project(tmp_path / "p", templates={"risk-assessment": tpl}), make_scan(tmp_path / "s"))
    assert any("text.vex_section" in w for w in s["config_warnings"]) and (rep / "vex.cdx.json").exists()
    assert "### 8.8 Vulnerability status" not in ra(rep) and "| VEX status |" in ra(rep)


def test_annotate_requires_purl_for_not_affected_resolved_false_positive(tmp_path):
    proj = tmp_path / "p"
    proj.mkdir()
    f = proj / vx.ANN_REL
    for args in (["--state", "not_affected", "--justification", "code_not_present"], ["--state", "resolved"],
                 ["--state", "false_positive", "--justification", "code_not_present"],
                 ["--state", "resolved_with_pedigree"], ["--state", "not_affected", "--justification", "code_not_present", "--version", "1.0"]):
        r = annotate(proj, "--cve", "CVE-2025-1", *args, "--detail", "x", "--author", "Bob")
        assert r.returncode == 1 and "--purl" in r.stdout and not f.exists(), (args, r.stdout)
    for args in (["--state", "in_triage"], ["--state", "exploitable", "--response", "update"]):
        r = annotate(proj, "--cve", f"CVE-2025-{len(args)}", *args, "--detail", "x", "--author", "Bob")
        assert r.returncode == 0, r.stdout
    r = annotate(proj, "--cve", "CVE-2025-9", "--state", "resolved", "--purl", "pkg:deb/ubuntu/openssl", "--detail", "x", "--author", "Bob")
    assert r.returncode == 0 and len(json.loads(f.read_text(encoding="utf-8"))["annotations"]) == 3


def test_unscoped_annotations_in_file_are_ignored_with_warning(tmp_path):
    proj = make_project(tmp_path / "p")
    write_json(proj / vx.ANN_REL, {"schema": vx.ANN_SCHEMA, "annotations": [
        ann("CVE-2026-61897"),                                                        # not_affected、沒有 purl → 不採用
        ann("CVE-2025-0003", "resolved", version="3.0.13-0ubuntu3.11"),               # 只有版本也不行
        ann("CVE-2023-48795", "in_triage", detail="vendor asked"),                    # in_triage 只寫 CVE 可以
        ann("CVE-2025-0003", "resolved", purl="pkg:deb/ubuntu/openssl", detail="fixed")]})
    anns, info = vx.load_annotations(proj)
    assert len(anns) == 2 and info["ignored"] == ["CVE-2026-61897 not_affected", "CVE-2025-0003 resolved (version 3.0.13-0ubuntu3.11)"]
    r, s, rep = run(proj, make_scan(tmp_path / "s"))
    assert r.returncode in (0, 2) and sum("沒有限定套件（purl），不採用" in w for w in s["config_warnings"]) == 2
    v = s["vex"]
    assert v["annotations"]["ignored"] == info["ignored"] and "warnings" not in v["annotations"] and v["sources"]["annotation"] == 3
    md = ra(rep)
    assert "2 ignored because a `not_affected`, `false_positive` or `resolved` decision must name a package (purl)" in md
    assert "| untriaged |" in next(x for x in md.splitlines() if "CVE-2026-61897" in x and "accountsservice" in x)


# ---------- 審查後補的情境 ----------

def two_cve_row(**kw):
    """GHSA 同時是 CVE-2026-0001 與 CVE-2026-0002：cra_report 把它列在 CVE-2026-0001（第一個 CVE）。"""
    return row("CVE-2026-0001", cves=["CVE-2026-0001", "CVE-2026-0002"], all_ids=["CVE-2026-0001", "CVE-2026-0002", "GHSA-xxxx-yyyy-zzzz"], **kw)


def test_annotation_for_other_cve_in_grouped_row_does_not_apply():
    P = "pkg:deb/ubuntu/openssl"
    m = vx.annotation_matches
    assert not m(ann("CVE-2026-0002", purl=P), two_cve_row())                 # 另一個 CVE 不能變成 CVE-2026-0001 的陳述
    assert not m(ann("GHSA-xxxx-yyyy-zzzz", purl=P), two_cve_row())           # 別名涵蓋兩個 CVE 時也不行
    assert m(ann("CVE-2026-0001", purl=P), two_cve_row())
    one = row("CVE-2026-0001", all_ids=["CVE-2026-0001", "GHSA-xxxx-yyyy-zzzz", "CVE-2026-0009"], cves=["CVE-2026-0001"])
    assert m(ann("GHSA-xxxx-yyyy-zzzz", purl=P), one)                         # 只有一個 CVE：非 CVE 的別名可以
    assert not m(ann("CVE-2026-0009", purl=P), one)                           # 別名是 CVE 但不是這一列的編號 → 不行
    # 第二個 CVE 的判定變成它自己的陳述（vex_extra），不是 CVE-2026-0001 的
    allr, _, info = vx.assess([two_cve_row()], annotations=[ann("CVE-2026-0002", purl=P)])
    assert allr[0]["vex"] is None and info["annotations_unused"] == []
    assert [(x["id"], x["vex"]["state"]) for x in allr[0]["vex_extra"]] == [("CVE-2026-0002", "not_affected")]
    # GHSA 的判定在拆出來的 CVE 上也不採用
    allr, _, info = vx.assess([two_cve_row()], annotations=[ann("GHSA-xxxx-yyyy-zzzz", purl=P)])
    assert allr[0]["vex"] is None and allr[0]["vex_extra"][0]["vex"] is None and info["annotations_unused"] == [0]


def test_dt_analysis_attributed_only_to_its_own_cve():
    def a(vid, cves, state="NOT_AFFECTED"):
        return {"state": state, "suppressed": False, "justification": "CODE_NOT_PRESENT", "response": "", "details": "",
                "vuln_id": vid, "cves": cves}
    ok = [a("CVE-2026-0001", ["CVE-2026-0001"]), a("UBUNTU-CVE-2026-0001", ["CVE-2026-0001"]), a("GHSA-x", ["CVE-2026-0001"])]
    for x in ok:
        assert vx.assess([row("CVE-2026-0001", analysis=[x])])[0][0]["vex"]["state"] == "not_affected", x
    bad = [a("CVE-2026-0002", ["CVE-2026-0001", "CVE-2026-0002"]), a("GHSA-x", ["CVE-2026-0001", "CVE-2026-0002"])]
    for x in bad:
        allr, _, info = vx.assess([two_cve_row(analysis=[x])])
        assert allr[0]["vex"] is None and info["dt_other_vulnerability"] == 1, x
    # 非 CVE 的列（只有 GHSA）：分析的 finding 編號要相同
    g = row("GHSA-aaaa-bbbb-cccc", "tool", "0.1", purl="pkg:golang/example.com/tool@0.1")
    assert vx.assess([dict(g, analysis=[a("GHSA-aaaa-bbbb-cccc", [])])])[0][0]["vex"] is not None
    assert vx.assess([dict(g, analysis=[a("GO-2026-1", [])])])[0][0]["vex"] is None


def test_nvidia_presumed_only_for_row_id():
    nvb = copy.deepcopy(NVB)
    r = row("CVE-2021-34400", "nvidia-l4t-core", "39.2.1-20260806224157", cves=["CVE-2021-34400", "CVE-2021-34401"])
    allr, _, _ = vx.assess([r], nvb=nvb)
    assert allr[0]["vex"] is None                                               # CVE-2021-34400 本身沒有推定


def test_kernel_config_requires_matching_component():
    k = kcfg([{"cve": "CVE-2025-1", "decision": "not_affected", "detail": "CONFIG_FOO unset"}])
    tegra = row("CVE-2025-1", "linux-nvidia-tegra", "6.8.0-1021.21", kernel=True,
                purl="pkg:deb/ubuntu/linux-nvidia-tegra@6.8.0-1021.21?arch=source&distro=ubuntu-24.04")
    generic = row("CVE-2025-1", "linux-image-6.8.0-90-generic", "6.8.0-90.91", kernel=True)
    image = row("CVE-2025-1", "linux-image-6.8.12-1021-tegra", "6.8.12-1021.21", kernel=True)
    other_ver = row("CVE-2025-1", "linux-nvidia-tegra", "6.8.0-1030.30", kernel=True)
    allr, _, _ = vx.assess([tegra, generic, image, other_ver], kcfg=k)
    assert [bool(r["vex"]) for r in allr] == [True, False, True, False]
    nocomp = dict(k)
    del nocomp["component"]
    assert vx.assess([copy.deepcopy(tegra)], kcfg=nocomp)[0][0]["vex"] is None


def test_dt_without_justification_is_not_a_statement_and_blocks_gate():
    rs = [row("CVE-1", analysis=dt("NOT_AFFECTED")), row("CVE-2", analysis=dt("NOT_AFFECTED", details="feature removed")),
          row("CVE-3", analysis=dt("FALSE_POSITIVE", details="wrong product")), row("CVE-4", analysis=dt("RESOLVED"))]
    allr, conf, info = vx.assess(rs)
    v = {r["id"]: r for r in allr}
    assert v["CVE-1"]["vex"] is None and "without justification" in v["CVE-1"]["vex_note"]
    assert v["CVE-2"]["vex"] == {"source": "dt", "state": "not_affected", "detail": "feature removed"}
    assert v["CVE-3"]["vex"] is None                                            # false_positive 不替人編理由
    assert info["dt_without_justification"] == 2
    g = vx.gate(allr, conf, grype_checked=True, not_assessed=[])
    assert g["verdict"] == "ATTENTION" and [x["id"] for x in g["dt_without_justification"]] == ["CVE-1", "CVE-3"]
    assert any("CVE-1 on openssl" in x for x in g["reasons"])
    # OpenVEX：not_affected 只有說明時只有 impact_statement，沒有編出來的 justification
    cdx, _ = vx.cdx_vex([v["CVE-2"]], PBOM, {"finished": "2026-11-02T00:00:00Z"}, {"name": "x"}, "x")
    st = vx.openvex(cdx, "Co", vx.purl_by_bomlink(PBOM))["statements"][0]
    assert "justification" not in st and st["impact_statement"] == "feature removed"
    md = vx.section("8.8", g, info, conf, [("vex.cdx.json", None, "x"), ("vex.openvex.json", None, "x")], "P", lambda h, r: "", None)
    assert "2 rows have a Dependency-Track analysis without justification" in md


def test_dt_partial_is_reported_in_section():
    r = row("CVE-1", analysis=dt("NOT_AFFECTED", "CODE_NOT_PRESENT") + dt(""))
    allr, conf, info = vx.assess([r])
    assert info["dt_partial"] == 1 and allr[0]["vex"]["state"] == "not_affected"
    md = vx.section("8.8", vx.gate(allr, conf, grype_checked=True, not_assessed=[]), info, conf, [("vex.cdx.json", None, "x"), ("vex.openvex.json", None, "x")], "P",
                    lambda h, r: "", None)
    assert "In 1 rows only some of the merged Dependency-Track findings have a usable analysis" in md


def test_annotation_purl_qualifiers_must_match():
    arm = row("CVE-1", "openssl", OSSL)                                               # ?arch=arm64&distro=ubuntu-24.04
    amd = row("CVE-1", "openssl", OSSL, purl=f"pkg:deb/ubuntu/openssl@{OSSL}?arch=amd64&distro=ubuntu-24.04")
    a = ann("CVE-1", purl="pkg:deb/ubuntu/openssl?arch=arm64")
    assert vx.annotation_matches(a, arm) and not vx.annotation_matches(a, amd)
    assert not vx.annotation_matches(ann("CVE-1", purl="pkg:deb/debian/openssl"), arm)   # namespace 不同
    # qualifiers 不同的兩筆不算同一範圍；有 qualifiers 的比較精確
    anns = vx.check_annotations({"schema": vx.ANN_SCHEMA, "annotations": [ann("CVE-1", purl="pkg:deb/ubuntu/openssl"), a]})
    allr, _, _ = vx.assess([arm, amd], annotations=[dict(anns[0], state="exploitable", justification=None, response=["update"]), anns[1]])
    assert [r["vex"]["state"] for r in allr] == ["not_affected", "exploitable"]


def test_annotate_keeps_file_mode_and_locks(tmp_path):
    proj = tmp_path / "p"
    proj.mkdir()
    f = proj / vx.ANN_REL
    old = os.umask(0o022)
    try:
        r = annotate(proj, "--cve", "CVE-1", "--state", "in_triage", "--detail", "x", "--author", "A")
        assert r.returncode == 0 and (f.stat().st_mode & 0o777) == 0o644
        os.chmod(f, 0o640)
        assert annotate(proj, "--cve", "CVE-2", "--state", "in_triage", "--detail", "x", "--author", "A").returncode == 0
        assert (f.stat().st_mode & 0o777) == 0o640
    finally:
        os.umask(old)
    # 同時加 6 筆：鎖住讀改寫，一筆都不會被蓋掉
    procs = [subprocess.Popen([sys.executable, "-I", str(CLI), "annotate", "--project", str(proj), "--cve", f"CVE-9-{i}", "--state",
                               "in_triage", "--detail", "x", "--author", "A"], stdout=subprocess.PIPE, stderr=subprocess.PIPE) for i in range(6)]
    assert all(p.wait(timeout=60) == 0 for p in procs)
    assert len(json.loads(f.read_text(encoding="utf-8"))["annotations"]) == 8


def test_product_bom_ref_is_deterministic():
    import cra_report as cr
    cfg = {"manufacturer": {"name": "M"}, "product": {"name": "P", "version": "1"}}
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {}, "components": [{"bom-ref": "product", "name": "x"}]}
    a = cr.product_bom(bom, cfg, {}, "2026-11-02T00:00:00Z", "ab")
    b = cr.product_bom(bom, cfg, {}, "2026-11-03T00:00:00Z", "ab")
    assert a["metadata"]["component"]["bom-ref"] == b["metadata"]["component"]["bom-ref"] == "product-2"
    assert a["serialNumber"] == b["serialNumber"]


def test_report_grouped_alias_row_end_to_end(tmp_path):
    """cra_report 端到端：GHSA 同時是兩個 CVE，人在 DT 對 GHSA 設 NOT_AFFECTED、在判定檔對第二個 CVE 寫判定 → 都不變成第一個 CVE 的陳述；
    第二個 CVE 的判定是它自己的陳述。"""
    f = finding("libz", "1.0-1", "GHSA-zzzz-zzzz-zzzz", "GITHUB", "HIGH", [{"cveId": "CVE-2026-0001"}, {"cveId": "CVE-2026-0002"}],
                analysis={"isSuppressed": False, "state": "NOT_AFFECTED", "justification": "CODE_NOT_PRESENT", "details": "x"})
    proj = make_project(tmp_path / "p")
    write_json(proj / vx.ANN_REL, {"schema": vx.ANN_SCHEMA, "annotations": [ann("CVE-2026-0002", purl="pkg:deb/ubuntu/libz")]})
    # Grype 的比對都不在這個 DT 清單裡（會成為只有 Grype 的列）：這裡只看別名併列，不給 Grype 的比對
    r, s, rep = run(proj, make_scan(tmp_path / "s", findings=[f], grype={"matches": []}))
    cdx = json.loads((rep / "vex.cdx.json").read_text(encoding="utf-8"))
    assert [v["id"] for v in assessed(cdx)] == ["CVE-2026-0002"] and s["vex"]["gate"]["counts"]["total"]["untriaged"] == 1
    assert s["vex"]["gate"]["verdict"] != "OK"


# ---------- 第二次審查後補的情境 ----------

def test_report_alias_second_cve_without_statement_blocks_gate(tmp_path):
    """DT 有 GHSA（別名 CVE-A、CVE-B）與 NVD 的 CVE-A，併成 CVE-A 一列；CVE-A 有人工判定，CVE-B 沒有 → 閘門不能 OK。
    再對 CVE-B 加判定（CVE-B＋purl）→ CVE-B 有自己的陳述，閘門不再點名它。"""
    na = {"isSuppressed": False, "state": "NOT_AFFECTED", "justification": "CODE_NOT_PRESENT", "details": "x"}
    fs = [finding("libz", "1.0-1", "GHSA-zzzz-zzzz-zzzz", "GITHUB", "HIGH", [{"cveId": "CVE-2026-0001"}, {"cveId": "CVE-2026-0002"}]),
          finding("libz", "1.0-1", "CVE-2026-0001", "NVD", "HIGH", analysis=na)]
    proj = make_project(tmp_path / "p")
    r, s, rep = run(proj, make_scan(tmp_path / "s", findings=fs))
    g = s["vex"]["gate"]
    assert g["verdict"] != "OK" and g["extra_cves_untriaged"] == 1
    assert any("CVE-2026-0002 (row CVE-2026-0001)" in x for x in g["reasons"])
    write_json(proj / vx.ANN_REL, {"schema": vx.ANN_SCHEMA, "annotations": [ann("CVE-2026-0002", purl="pkg:deb/ubuntu/libz")]})
    r, s, rep = run(proj, make_scan(tmp_path / "s2", findings=fs))
    g = s["vex"]["gate"]
    assert g["extra_cves_untriaged"] == 0 and not any("further CVEs" in x for x in g["reasons"])
    cdx = json.loads((rep / "vex.cdx.json").read_text(encoding="utf-8"))
    assert sorted(v["id"] for v in assessed(cdx)) == ["CVE-2026-0001", "CVE-2026-0002"]
    assert len({v["bom-ref"] for v in cdx["vulnerabilities"]}) == len(cdx["vulnerabilities"])


def test_extra_cve_dt_finding_for_that_cve_is_used():
    """一列裡另一個 CVE 自己的 DT finding（vuln_id 就是那個 CVE）有判定 → 變成那個 CVE 的陳述，不是這一列的。"""
    a = {"state": "NOT_AFFECTED", "suppressed": False, "justification": "CODE_NOT_PRESENT", "response": "", "details": "",
         "vuln_id": "CVE-2026-0002", "cves": ["CVE-2026-0002"]}
    allr, _, _ = vx.assess([two_cve_row(analysis=[a])])
    assert allr[0]["vex"] is None and allr[0]["vex_extra"][0]["vex"]["state"] == "not_affected"
    assert "CVE-2026-0002: not_affected" in vx.label(allr[0])


def test_gate_without_grype_cross_check_is_not_ok():
    allr, conf, _ = vx.assess([row("CVE-2026-0001", analysis=dt("NOT_AFFECTED", "CODE_NOT_PRESENT"))])
    typed(allr)                                                                  # 因 D-035 而變：補上依據類型
    assert vx.gate(allr, conf, grype_checked=True, not_assessed=[])["verdict"] == "OK"
    assert vx.gate(allr, conf)["verdict"] == "ATTENTION"                       # 預設偏保守：呼叫端要明確說 Grype 有跑
    g = vx.gate(allr, conf, grype_checked=False)
    assert g["verdict"] == "ATTENTION" and any("Grype cross-check not run" in x for x in g["reasons"]) and g["grype_cross_check"] is False


def test_report_without_grype_gate_is_not_ok(tmp_path):
    na = {"isSuppressed": False, "state": "NOT_AFFECTED", "justification": "CODE_NOT_PRESENT", "details": "x"}
    fs = [finding("libz", "1.0-1", "CVE-2026-0001", "NVD", "HIGH", analysis=na)]
    for i, kw in enumerate(({"grype": None}, {"stages": {"C-grype": "FAIL"}})):
        r, s, rep = run(make_project(tmp_path / f"p{i}"), make_scan(tmp_path / f"s{i}", findings=fs, **kw))
        g = s["vex"]["gate"]
        assert g["verdict"] != "OK" and any("Grype cross-check not run" in x for x in g["reasons"]), kw


def test_refs_for_name_version_fallback_keeps_ecosystem():
    pbom = {"serialNumber": "urn:uuid:00000000-0000-0000-0000-000000000000", "version": 1,
            "components": [{"bom-ref": "py", "name": "foo", "version": "1.0", "purl": "pkg:pypi/foo@1.0"},
                           {"bom-ref": "nop", "name": "bar", "version": "2.0"}]}
    idx = vx.ref_index(pbom)
    assert vx.refs_for({"purl": "pkg:npm/foo@1.0", "name": "foo", "version": "1.0"}, idx) == []
    assert vx.refs_for({"purl": "pkg:pypi/foo@1.0?x=1", "name": "foo", "version": "1.0"}, idx) == ["py"]
    assert vx.refs_for({"purl": "pkg:npm/bar@2.0", "name": "bar", "version": "2.0"}, idx) == ["nop"]   # SBOM 沒有 purl：照舊以名稱對


def test_check_reports_ignored_annotations(tmp_path):
    proj = tmp_path / "p"
    write_json(proj / vx.ANN_REL, {"schema": vx.ANN_SCHEMA, "annotations": [ann("CVE-2026-0001"), ann("CVE-2026-0002", purl="pkg:deb/ubuntu/x")]})
    r = subprocess.run([sys.executable, "-I", str(CLI), "check", "--project", str(proj)], capture_output=True, text=True, timeout=60)
    assert r.returncode == 1 and "WARN\t" in r.stdout and "CVE-2026-0001" in r.stdout and "其他 1 筆可用" in r.stdout


# ---------- 第三次審查後補的情境 ----------

def test_extra_cve_with_own_row_is_not_split_again():
    """GHSA(A,B)＋NVD A 併成 A 列，NVD B 自己一列（同一個元件版本）。A 列 distro_fixed、DT 在 B 列設 EXPLOITABLE：
    B 只能有 B 列那一條陳述（exploitable），不能再從 A 列拆出一條 resolved（兩條互相矛盾、不記衝突、閘門卻 OK）。"""
    A, B = "CVE-2026-0001", "CVE-2026-0002"
    ra_ = row(A, comp="libz", ver="1.0-1", cves=[A, B], all_ids=[A, B, "GHSA-zzzz-zzzz-zzzz"],
              source_ids=["GITHUB:GHSA-zzzz-zzzz-zzzz", f"NVD:{A}"])
    rb_ = row(B, comp="libz", ver="1.0-1", analysis=[{"state": "EXPLOITABLE", "suppressed": False, "justification": "",
                                                      "response": "UPDATE", "details": "fix in next release",
                                                      "vuln_id": B, "cves": [B]}])
    drc = {"status": "OK", "rows": [{"key": ra_["key"], "decision": "distro_fixed", "source_ids": ra_["source_ids"],
                                     "release": {"distro": "Ubuntu", "version": "24.04"}, "evidence": [{"fixed_version": "1.0-0", "record": "UBUNTU-CVE"}]}]}
    allr, conf, info = vx.assess([ra_, rb_], drc=drc)
    a, b = allr
    assert a["vex_extra"] == [] and a["vex"]["state"] == "resolved" and b["vex"]["state"] == "exploitable"
    g = vx.gate(allr, conf, grype_checked=True, not_assessed=[])
    # B 仍受影響（exploitable）：評估完整，但要有人做出貨決定 → 不是 OK
    assert g["verdict"] == "ATTENTION" and g["extra_cves"] == 0 and g["extra_cves_untriaged"] == 0
    assert g["reasons"][0].startswith("assessment complete; 1 affected rows") and g["open_affected"]["rows"] == 1
    pbom = {"serialNumber": "urn:uuid:00000000-0000-0000-0000-000000000000", "version": 1, "metadata": {"component": {"name": "P"}},
            "components": [{"bom-ref": "z", "name": "libz", "version": "1.0-1", "purl": a["purl"]}]}
    cdx, _ = vx.cdx_vex(allr, pbom, {}, {"name": "P"}, g["verdict"])
    ids = [(v["id"], v["analysis"]["state"]) for v in cdx["vulnerabilities"]]
    assert sorted(ids) == [(A, "resolved"), (B, "exploitable")]
    assert len({v["bom-ref"] for v in cdx["vulnerabilities"]}) == len(cdx["vulnerabilities"])


def test_cdx_vex_refuses_duplicate_statements():
    r1 = row("CVE-2026-0001", analysis=dt("NOT_AFFECTED", "CODE_NOT_PRESENT"))
    r2 = dict(r1, analysis=dt("EXPLOITABLE", response="UPDATE"))
    allr, _, _ = vx.assess([r1, r2])
    pbom = {"serialNumber": "urn:uuid:00000000-0000-0000-0000-000000000000", "version": 1, "metadata": {}, "components": []}
    with pytest.raises(vx.VexInputError, match="多條 VEX 陳述"):
        vx.cdx_vex(allr, pbom, {}, {"name": "P"}, "OK")


def test_extra_cve_source_ids_only_its_own():
    allr, _, _ = vx.assess([two_cve_row(source_ids=["GITHUB:GHSA-xxxx-yyyy-zzzz", "NVD:CVE-2026-0001", "UBUNTU:UBUNTU-CVE-2026-0002"])])
    assert allr[0]["vex_extra"][0]["source_ids"] == ["GITHUB:GHSA-xxxx-yyyy-zzzz", "UBUNTU:UBUNTU-CVE-2026-0002"]


def test_report_alias_with_own_row_end_to_end(tmp_path):
    """GHSA(A,B)＋NVD A＋NVD B（libz 1.0-1）：B 自己一列有 DT 判定 → 閘門不點名 B、VEX 沒有重複的陳述與 bom-ref。"""
    na = {"isSuppressed": False, "state": "NOT_AFFECTED", "justification": "CODE_NOT_PRESENT", "details": "x"}
    ex = {"isSuppressed": False, "state": "EXPLOITABLE", "response": "UPDATE", "details": "fix planned"}
    fs = [finding("libz", "1.0-1", "GHSA-zzzz-zzzz-zzzz", "GITHUB", "HIGH", [{"cveId": "CVE-2026-0001"}, {"cveId": "CVE-2026-0002"}]),
          finding("libz", "1.0-1", "CVE-2026-0001", "NVD", "HIGH", analysis=na),
          finding("libz", "1.0-1", "CVE-2026-0002", "NVD", "HIGH", analysis=ex)]
    proj = make_project(tmp_path / "p")
    r, s, rep = run(proj, make_scan(tmp_path / "s", findings=fs))
    g = s["vex"]["gate"]
    assert s is not None and g["extra_cves_untriaged"] == 0 and not any("further CVEs" in x for x in g["reasons"])
    cdx = json.loads((rep / "vex.cdx.json").read_text(encoding="utf-8"))
    vs = cdx["vulnerabilities"]
    assert sorted((v["id"], v["analysis"]["state"]) for v in assessed(cdx)) == [("CVE-2026-0001", "not_affected"), ("CVE-2026-0002", "exploitable")]
    assert len({v["bom-ref"] for v in vs}) == len(vs)


# ---------- 合併前審查後補的情境 ----------

def test_report_self_no_version_match_blocks_gate(tmp_path):
    """sbomgate 的 SELF_NO_VERSION（Grype 比對到產品本身、沒有版本）沒有評估、不在任何一列：每一列都有判定也不能 OK。"""
    from test_cra_report import GRYPE
    self_purl = "pkg:golang/github.com/example/tool"
    # brotli 的 KEV finding 拿掉了：它的 Grype 比對會成為只有 Grype 的列（沒有判定），所以只留 accountsservice 的比對
    grype = {"matches": GRYPE["matches"][1:2] + [
        {"vulnerability": {"id": "GHSA-self-0000-0001", "fix": {"state": "unknown"}}, "relatedVulnerabilities": [{"id": "CVE-2018-25059"}],
         "artifact": {"name": "github.com/example/tool", "version": "", "type": "go-module", "purl": self_purl}}]}
    findings = [dict(f, analysis={"isSuppressed": False}) for f in FINDINGS
                if not f["vulnerability"].get("isKev") and (f["vulnerability"].get("epssPercentile") or 0) < 0.9]
    proj = make_project(tmp_path / "p")
    # 每一列都有判定（DT 的分析拿掉，避免和判定檔衝突）（只寫 CVE 的 in_triage 允許、不擋閘門）
    ids = sorted({a["cveId"] for f in findings for a in f["vulnerability"]["aliases"] if a.get("cveId")}
                 | {re.sub(r"^[A-Z]+-(?=CVE-)", "", f["vulnerability"]["vulnId"]) for f in findings})   # 列的編號是 CVE-…（UBUNTU-CVE-… 去前綴）
    write_json(proj / vx.ANN_REL, {"schema": vx.ANN_SCHEMA, "annotations": [ann(i, "in_triage") for i in ids]})
    scan = make_scan(tmp_path / "s", findings=findings, grype=grype)
    write_json(scan / "scan" / "sbomgate.json", {"excluded_matches": [
        {"excluded_reason": "SELF_NO_VERSION", "id": "GHSA-self-0000-0001", "purl": self_purl, "version": None}]})
    r, s, rep = run(proj, scan)
    g = s["vex"]["gate"]
    assert g["counts"]["total"]["untriaged"] == 0, g["reasons"]
    assert g["verdict"] != "OK" and g["not_assessed"] and "GHSA-self-0000-0001" in g["not_assessed"][0]
    assert any("not assessed" in x and "GHSA-self-0000-0001" in x for x in g["reasons"])


def test_gate_not_assessed_default_is_fail_safe():
    allr, conf, _ = vx.assess([row("CVE-2026-0001", analysis=dt("NOT_AFFECTED", "CODE_NOT_PRESENT"))])
    typed(allr)                                                                  # 因 D-035 而變：補上依據類型
    assert vx.gate(allr, conf, grype_checked=True, not_assessed=[])["verdict"] == "OK"
    g = vx.gate(allr, conf, grype_checked=True)                                  # 呼叫端沒說 → 不知道
    assert g["verdict"] == "ATTENTION" and g["not_assessed"] is None
    assert vx.gate(allr, conf, grype_checked=True, not_assessed=["X on p"])["verdict"] == "ATTENTION"


def test_gate_kev_row_resolved_only_by_distro_needs_human():
    allr, conf, _ = vx.assess([row("CVE-2024-6119", kev=True)], drc=recheck_doc())
    assert allr[0]["vex"]["source"] == "distro"
    g = vx.gate(allr, conf, grype_checked=True, not_assessed=[])
    assert g["verdict"] == "ATTENTION" and g["kev_without_human_decision"] == 1
    # 人的判定在前 → 不擋
    a = ann("CVE-2024-6119", "resolved", purl="pkg:deb/ubuntu/openssl")
    allr, conf, _ = vx.assess([row("CVE-2024-6119", kev=True)], drc=recheck_doc(), annotations=[a])
    assert vx.gate(allr, conf, grype_checked=True, not_assessed=[])["kev_without_human_decision"] == 0


def test_report_two_rows_share_extra_cve_split_once(tmp_path):
    """GHSA-1（CVE-1、CVE-3）與 GHSA-2（CVE-2、CVE-3）在同一個元件版本、CVE-3 沒有自己一列：CVE-3 只拆一次；
    照閘門指示補 CVE-3 的判定後只有一條陳述、文件不 FAIL。"""
    fs = [finding("libz", "1.0-1", "GHSA-1111-1111-1111", "GITHUB", "HIGH", [{"cveId": "CVE-2026-0001"}, {"cveId": "CVE-2026-0003"}]),
          finding("libz", "1.0-1", "GHSA-2222-2222-2222", "GITHUB", "HIGH", [{"cveId": "CVE-2026-0002"}, {"cveId": "CVE-2026-0003"}])]
    proj = make_project(tmp_path / "p")
    r, s, rep = run(proj, make_scan(tmp_path / "s", findings=fs))
    g = s["vex"]["gate"]
    assert g["extra_cves_untriaged"] == 1 and [x["id"] for x in g["extra_cves_untriaged_list"]] == ["CVE-2026-0003"]
    assert g["extra_cves_untriaged_list"][0]["row"] == "CVE-2026-0001, CVE-2026-0002"
    P = "pkg:deb/ubuntu/libz"
    write_json(proj / vx.ANN_REL, {"schema": vx.ANN_SCHEMA, "annotations": [ann(c, purl=P) for c in ("CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003")]})
    r, s, rep = run(proj, make_scan(tmp_path / "s2", findings=fs))
    assert not r.stdout.startswith("FAIL") and (rep / "vex.cdx.json").exists(), r.stdout + r.stderr
    cdx = json.loads((rep / "vex.cdx.json").read_text(encoding="utf-8"))
    assert sorted(v["id"] for v in assessed(cdx)) == ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"]
    assert s["vex"]["gate"]["extra_cves_untriaged"] == 0


def test_annotations_unused_or_without_author_are_named_in_gate(tmp_path):
    """判定一筆都沒對到（purl 寫錯）或負責人是代稱：閘門點名、狀態行顯示，不會悄悄失效。"""
    proj = make_project(tmp_path / "p")
    write_json(proj / vx.ANN_REL, {"schema": vx.ANN_SCHEMA, "annotations": [
        ann("CVE-2026-61897", detail="not installed", purl="pkg:deb/ubuntu/no-such-package"),
        dict(ann("CVE-2026-61897", detail="not installed", purl="pkg:deb/ubuntu/accountsservice"), author="專案負責人")]})
    r, s, rep = run(proj, make_scan(tmp_path / "s", findings=FINDINGS + EXTRA))
    g = s["vex"]["gate"]
    assert g["annotations_unused"] == ["CVE-2026-61897 (pkg:deb/ubuntu/no-such-package)"]
    assert g["annotations_without_author"] == ["CVE-2026-61897 (pkg:deb/ubuntu/accountsservice)"] and g["verdict"] != "OK"
    assert any("match no row" in x for x in g["reasons"]) and any("without a named author" in x for x in g["reasons"])
    assert "判定沒有對到任何列 1 筆" in r.stdout and "判定沒有負責人 1 筆" in r.stdout
    assert "author: TO BE COMPLETED" in next(x for x in ra(rep).splitlines() if "CVE-2026-61897" in x and "VEX not_affected" in x)


def test_retier_needs_every_merged_cve_and_no_partial_dt(tmp_path):
    """一列併了兩個 CVE：只有一個判不受影響（另一個受影響或沒判定）不移；DT 只分析了部分 finding 的列不移（tier_of 管）；
    KEV 的列要有具名負責人的人工判定。"""
    from test_cra_report import finding
    two = [finding("libz", "1.0-1", "GHSA-1111-1111-1111", "GITHUB", "HIGH", [{"cveId": "CVE-2026-0001"}, {"cveId": "CVE-2026-0002"}])]
    for i, extra in enumerate(([], [ann("CVE-2026-0002", "exploitable", purl="pkg:deb/ubuntu/libz")],
                               [ann("CVE-2026-0002", purl="pkg:deb/ubuntu/libz")])):
        proj = make_project(tmp_path / f"p{i}")
        write_json(proj / vx.ANN_REL, {"schema": vx.ANN_SCHEMA, "annotations": [ann("CVE-2026-0001", purl="pkg:deb/ubuntu/libz")] + extra})
        s = run(proj, make_scan(tmp_path / f"s{i}", findings=two))[1]
        assert (s["counts"]["accepted"], s["counts"]["p2"]) == ((1, 0) if i == 2 else (0, 1)), i
    part = [finding("libq", "1.0-1", "CVE-2026-0009", "NVD", "HIGH",
                    analysis={"isSuppressed": False, "state": "NOT_AFFECTED", "justification": "CODE_NOT_REACHABLE", "details": "x"}),
            finding("libq", "1.0-1", "UBUNTU-CVE-2026-0009", "OSV", "HIGH")]
    s = run(make_project(tmp_path / "pq"), make_scan(tmp_path / "sq", findings=part))[1]
    assert s["counts"]["p2"] == 1 and s["counts"]["accepted_by_vex"] == {}
    kev = [finding("libk", "1.0-1", "CVE-2026-0010", "NVD", "HIGH", kev=True)]
    for i, who in enumerate(("專案負責人", "Alice")):
        proj = make_project(tmp_path / f"pk{i}")
        write_json(proj / vx.ANN_REL, {"schema": vx.ANN_SCHEMA, "annotations": [dict(ann("CVE-2026-0010", purl="pkg:deb/ubuntu/libk"), author=who)]})
        s = run(proj, make_scan(tmp_path / f"sk{i}", findings=kev))[1]
        assert s["counts"]["p1"] == (1 if i == 0 else 0), who


# ---------- Ubuntu 打包的 Python 模組沿用 deb 列的判定 ----------
def pydeb(rid, owner="python3-urllib3", source="python-urllib3", over="2.0.7-1ubuntu0.1", **kw):
    """Debian／Ubuntu 打包的 Python 模組的列（cra_report.apply_deb_python 之後的形狀）。"""
    return row(rid, comp="urllib3", ver="2.0.7", purl="pkg:pypi/urllib3@2.0.7", ptype="pypi",
               deb_python={"path": "/usr/lib/python3/dist-packages/urllib3", "candidates": [],
                           "owner": {"name": owner, "source": source, "version": over}, "row": None, "pypi_fix": []}, **kw)


def debrow(rid, comp="python3-urllib3", ver="2.0.7-1ubuntu0.1", **kw):
    return row(rid, comp=comp, ver=ver, ptype="deb", **kw)


def test_deb_python_inherits_deb_row_decision():
    c = "CVE-2026-7001"
    deb = debrow(c, analysis=dt("NOT_AFFECTED", "CODE_NOT_REACHABLE", details="proxy code unused"))
    allr, conf, info = vx.assess([deb, pydeb(c)])
    py = next(r for r in allr if r.get("ptype") == "pypi")
    assert py["vex"]["state"] == "not_affected" and py["vex"]["source"] == "dt"
    assert py["vex"]["inherited_from"] == {"id": c, "component": "python3-urllib3", "version": "2.0.7-1ubuntu0.1"}
    assert py["vex"]["detail"].startswith("inherited from the decision on the Ubuntu package python3-urllib3 2.0.7-1ubuntu0.1, which installed")
    assert deb["vex"].get("inherited_from") is None and info["deb_python_inherited"] == 1 and conf == []
    # 原始碼套件（arch=source）的列、annotation 也沿用；exploitable 也沿用（保守）
    allr, _, _ = vx.assess([debrow(c, comp="python-urllib3", purl="pkg:deb/ubuntu/python-urllib3@2.0.7-1ubuntu0.1?arch=source&distro=ubuntu-24.04"), pydeb(c)],
                           annotations=[ann(c, "exploitable", purl="pkg:deb/ubuntu/python-urllib3")])
    py = next(r for r in allr if r.get("ptype") == "pypi")
    assert py["vex"]["source"] == "annotation" and py["vex"]["state"] == "exploitable" and py["vex"]["author"] == "Alice"
    assert "the Ubuntu source package python-urllib3 2.0.7-1ubuntu0.1, from which python3-urllib3" in py["vex"]["detail"]
    # CycloneDX 註明沿用自哪一列
    cdx, _ = vx.cdx_vex(allr, PBOM, {"finished": "2026-11-02T02:43:55Z", "name": "img"}, {"name": "EX-J100"}, "ATTENTION")
    stm = [v for v in cdx["vulnerabilities"] if any(p["name"] == "sca-center:vex-inherited-from" for p in v.get("properties") or [])]
    assert len(stm) == 1 and {"name": "sca-center:component-purl", "value": "pkg:pypi/urllib3@2.0.7"} in stm[0]["properties"]


def test_deb_python_does_not_inherit_when_unsafe():
    c = "CVE-2026-7002"

    def py_vex(rows, **kw):
        allr, _, info = vx.assess(rows, **kw)
        return next(r for r in allr if r.get("ptype") == "pypi"), info
    na = dt("NOT_AFFECTED", "CODE_NOT_REACHABLE", details="x")
    # 版本不同（deb 列是別的版本）、名稱不同、編號不同 → 不沿用
    for deb in (debrow(c, ver="2.0.7-1", analysis=na), debrow(c, comp="python3-requests", analysis=na), debrow("CVE-2026-9", analysis=na)):
        py, info = py_vex([deb, pydeb(c)])
        assert py["vex"] is None and not info.get("deb_python_inherited")
    # 擁有者不明 → 不沿用
    p = pydeb(c)
    p["deb_python"]["owner"] = None
    assert py_vex([debrow(c, analysis=na), p])[0]["vex"] is None
    # 這一列自己在 DT 有人設的分析（缺理由，不採用）或 suppress → 不沿用
    assert py_vex([debrow(c, analysis=na), pydeb(c, analysis=[dict(dt("NOT_AFFECTED")[0], vuln_id=c, cves=[c])])])[0]["vex"] is None
    assert py_vex([debrow(c, analysis=na), pydeb(c, analysis=dt("", suppressed=True))])[0]["vex"] is None
    # 這一列自己的判定優先
    py, _ = py_vex([debrow(c, analysis=na), pydeb(c, analysis=dt("EXPLOITABLE", response="UPDATE", details="y"))])
    assert py["vex"]["state"] == "exploitable" and not py["vex"].get("inherited_from")
    # 批次規則的判定不沿用（規則只會寫 exploitable／in_triage，但仍是批次，不是逐筆證據）
    deb = debrow(c)
    deb_rule = dict(deb)
    allr, _, _ = vx.assess([deb_rule, pydeb(c)])
    deb_rule["vex"] = vx.stmt("rule", "in_triage", "batch")
    assert not vx.inherit_deb_python([deb_rule, next(r for r in allr if r.get("ptype") == "pypi")])
    # 二進位與原始碼套件兩列判定分類不同 → 不沿用、註明
    py, info = py_vex([debrow(c, analysis=na), debrow(c, comp="python-urllib3", purl="pkg:deb/ubuntu/python-urllib3@2.0.7-1ubuntu0.1?arch=source&distro=ubuntu-24.04", analysis=dt("EXPLOITABLE", response="UPDATE", details="z")),
                       pydeb(c)])
    assert py["vex"] is None and "disagree" in py["vex_note"] and info["deb_python_inherit_conflict"] == 1


def test_deb_python_inheritance_excludes_lookalikes_kev_and_distro():
    c = "CVE-2026-7003"
    na = dt("NOT_AFFECTED", "CODE_NOT_REACHABLE", details="the CLI is never run")

    def py_of(rows, **kw):
        allr, _, info = vx.assess(rows, **kw)
        return next(r for r in allr if r.get("ptype") == "pypi"), info
    # 名稱和原始碼套件相同、但不是 arch=source 的二進位套件（例如 brotli 指令工具）→ 不是裝這個模組的套件，不沿用
    py, _ = py_of([debrow(c, comp="python-urllib3", analysis=na), pydeb(c)])
    assert py["vex"] is None
    # KEV 的列不沿用，註明 deb 列有判定、要人判定這一列
    py, info = py_of([debrow(c, analysis=na, kev=True), pydeb(c, kev=True)])
    assert py["vex"] is None and "KEV" in py["vex_note"] and info["deb_python_kev_not_inherited"] == 1
    # 發行版已修補（distro）不沿用（證據只對 deb 列檢查過）
    deb = debrow(c)
    deb["vex"] = vx.stmt("distro", "resolved", "fixed by Ubuntu")
    p = pydeb(c)
    p["vex"] = None
    assert not vx.inherit_deb_python([deb, p]) and p["vex"] is None


# ---------- G3-2：判定衝突時取最保守的，衝突仍列出 ----------

def test_conflict_picks_most_conservative_and_keeps_the_conflict_listed():
    # 舊的 DT not_affected ＋ 較新的具名 in_triage 註記 → in_triage
    allr, conf, _ = vx.assess([row("CVE-9", analysis=dt("NOT_AFFECTED", "CODE_NOT_PRESENT"))], annotations=[ann("CVE-9", "in_triage", detail="re-checking")])
    assert allr[0]["vex"]["state"] == "in_triage" and allr[0]["vex"]["source"] == "annotation"
    assert [(c["used"], c["other"], c["human"]) for c in conf] == [("annotation:in_triage", "dt:not_affected", True)]
    g = vx.gate(allr, conf, grype_checked=True, not_assessed=[])
    assert g["verdict"] == "ATTENTION" and g["human_conflicts"] == 1
    # 反過來：DT exploitable ＋ 註記 not_affected → 仍是 exploitable（取較保守的），衝突列出
    allr, conf, _ = vx.assess([row("CVE-8", analysis=dt("EXPLOITABLE", response="UPDATE", details="open"))], annotations=[ann("CVE-8", "not_affected")])
    assert allr[0]["vex"]["state"] == "exploitable" and allr[0]["vex"]["source"] == "dt" and len(conf) == 1
    # 同樣是「關閉」（resolved／not_affected）時維持來源順序：人的（DT、註記）在自動來源（distro）前面
    allr, conf, _ = vx.assess([row("CVE-2026-1000")], drc=recheck_doc(), annotations=[ann("CVE-2026-1000", "not_affected", purl="pkg:deb/ubuntu/openssl")])
    assert allr[0]["vex"]["source"] == "annotation"


def test_exploited_row_is_never_closed_by_an_automatic_source_over_a_human_candidate():
    drc = recheck_doc()
    for kw in ({"kev": True}, {"exploited_sources": ["manual: vendor advisory, 2026-11-01"]}, {"exploited_sources": ["EUVD (CISA KEV)"]}):
        # distro 說 resolved、人（註記）說 exploitable／in_triage → 人的
        for st in ("exploitable", "in_triage"):
            allr, conf, _ = vx.assess([row("CVE-2024-6119", **kw)], drc=drc, annotations=[ann("CVE-2024-6119", st, purl="pkg:deb/ubuntu/openssl")])
            assert allr[0]["vex"]["source"] == "annotation" and allr[0]["vex"]["state"] == st, kw
            assert conf and conf[0]["other"] == "distro:resolved"
        # 只有自動來源時照舊是 distro:resolved，而且閘門點名（kev_without_human_decision）——人工證據的列也算
        allr, conf, _ = vx.assess([row("CVE-2024-6119", **kw)], drc=drc)
        assert allr[0]["vex"]["source"] == "distro"
        g = vx.gate(allr, conf, grype_checked=True, not_assessed=[])
        assert g["kev_without_human_decision"] == 1 and g["verdict"] == "ATTENTION", kw
    # 沒有被利用的列：不點名
    allr, conf, _ = vx.assess([row("CVE-2024-6119")], drc=drc)
    assert vx.gate(allr, conf, grype_checked=True, not_assessed=[])["kev_without_human_decision"] == 0


# ---------- G3-10：NVIDIA 公告列的 KEV／EUVD ----------

def test_nvidia_bulletin_row_exploited_is_p1_with_real_source():
    src = {"CVE-2021-34401": ["EUVD (CISA KEV)"]}
    allr, _, info = vx.assess([row("CVE-2025-9")], nvb=NVB, rule_ctx={"exploited": ["cve-2021-34401"], "exploited_sources": src})
    extra = {r["id"]: r for r in allr if r.get("nvidia_bulletin")}
    k = extra["CVE-2021-34401"]
    # 真正的證據來源；只有 EUVD／人工證據時不寫成 KEV（kev 欄不設）
    assert k["tier"] == "p1" and k["kev"] is False and k["exploited_sources"] == ["EUVD (CISA KEV)"]
    assert vx.exploited_row(k) and k["vex"]["state"] == "in_triage" and k["vex"]["source"] == "nvidia"
    # 沒有記錄來源時照實寫
    allr, _, _ = vx.assess([row("CVE-2025-9")], nvb=NVB, rule_ctx={"exploited": ["CVE-2021-34401"]})
    assert next(r for r in allr if r["id"] == "CVE-2021-34401")["exploited_sources"] == ["exploited (source not recorded)"]
    # 沒標示的公告列照舊
    assert extra["CVE-2022-1111"]["tier"] == "nvidia_bulletin" and extra["CVE-2022-1111"]["kev"] is False
    assert vx.priority_key(k) < vx.priority_key(extra["CVE-2022-1111"])
    assert all(r["vex"]["state"] not in ("resolved", "not_affected") for r in allr if r.get("vex"))
    assert info["nvidia_extra_rows"] == 3


# ---------- M-1：自動的 NVIDIA 推定 in_triage 不蓋過人的關閉結論 ----------

def l4t_row(**kw):
    return row("CVE-2021-34401", "nvidia-l4t-core", "39.2.1-20260806224157", source_ids=["NVIDIA:CVE-2021-34401"], **kw)


@pytest.mark.parametrize("kw,anns,src,state", [
    ({"analysis": dt("NOT_AFFECTED", "CODE_NOT_PRESENT")}, [], "dt", "not_affected"),
    ({"analysis": dt("RESOLVED", details="fixed by update")}, [], "dt", "resolved"),
    ({}, [ann("CVE-2021-34401", "not_affected", purl="pkg:deb/ubuntu/nvidia-l4t-core")], "annotation", "not_affected"),
    ({"kev": True, "analysis": dt("NOT_AFFECTED", "CODE_NOT_PRESENT")}, [], "dt", "not_affected"),
])
def test_presumed_nvidia_in_triage_never_overrides_human_closure(kw, anns, src, state):
    allr, conf, _ = vx.assess([l4t_row(**kw)], nvb=NVB, annotations=anns)
    assert allr[0]["vex"]["source"] == src and allr[0]["vex"]["state"] == state
    assert any(c["other"] == "nvidia:in_triage" for c in conf)       # 衝突照舊列出


def test_presumed_nvidia_still_applies_without_human_decision_and_human_exploitable_wins():
    allr, _, _ = vx.assess([l4t_row()], nvb=NVB)
    assert allr[0]["vex"]["source"] == "nvidia" and allr[0]["vex"]["state"] == "in_triage"
    allr, _, _ = vx.assess([l4t_row(analysis=dt("EXPLOITABLE", response="UPDATE", details="open"))], nvb=NVB,
                           annotations=[ann("CVE-2021-34401", "not_affected", purl="pkg:deb/ubuntu/nvidia-l4t-core")])
    assert allr[0]["vex"]["source"] == "dt" and allr[0]["vex"]["state"] == "exploitable"     # 人的之間仍取較保守的


def test_nvidia_bulletin_row_without_kev_stays_nvidia_bulletin():
    allr, _, _ = vx.assess([row("CVE-2025-9")], nvb=NVB, rule_ctx={"exploited": ["CVE-2099-1"]})
    assert {r["tier"] for r in allr if r.get("nvidia_bulletin")} == {"nvidia_bulletin"}
