"""M7c-1（A4／D-057）：沒有判定的列也輸出到 VEX（CycloneDX in_triage 加 dumpling:assessment＝NOT_ASSESSED，OpenVEX under_investigation
加 status_notes「dumpling: not assessed」），只在輸出階段加，assess 的結果與發行閘門不變；dt_writeback 與客戶版的處理另見
test_dt_writeback.py、test_customer_package_wording.py。"""
import copy
import json
import os
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import vex_export as vx  # noqa: E402
from test_cra_distro import recheck_doc  # noqa: E402
from test_cra_report import make_project, make_scan, run  # noqa: E402
from test_vex_export import PBOM, assessed, dt, is_na, row, sample_rows, two_cve_row, typed  # noqa: E402
from vex_gate_scenarios import d035_unexplained  # noqa: E402

MARK = {"name": "dumpling:assessment", "value": "NOT_ASSESSED"}
NOTE = "dumpling: not assessed"
OV_SCHEMA = os.path.join(HERE, "data", "openvex", "openvex_json_schema.json")
GOLDEN = HERE / "data" / "vex_gate_before_a4.json"


def build(rows, **kw):
    allr, conf, _ = vx.assess(rows, drc=recheck_doc())
    cdx, st = vx.cdx_vex(allr, PBOM, {"finished": "2026-11-02T02:43:55Z", "name": "img"}, {"name": "EX-J100"}, "ATTENTION")
    return allr, conf, cdx, st, vx.openvex(cdx, "Example Co.", vx.purl_by_bomlink(PBOM))


def untriaged_rows(n):
    return [row(f"CVE-2030-{i:04d}", "openssl", "3.0.13-0ubuntu3.11") for i in range(n)]


def test_n_unassessed_rows_give_n_in_triage_statements_and_n_under_investigation():
    N = 4
    rows = untriaged_rows(N) + [row("CVE-1", analysis=dt("NOT_AFFECTED", "CODE_NOT_PRESENT", details="not built")),
                                row("CVE-2", analysis=dt("EXPLOITABLE", response="UPDATE", details="fix in 2.4")),
                                row("CVE-3", analysis=dt("IN_TRIAGE"))]            # 人在 DT 設的 in_triage：有判定，沒有標記
    allr, _, cdx, st, ov = build(rows)
    na = [v for v in cdx["vulnerabilities"] if is_na(v)]
    assert len(na) == N and all(v["analysis"]["state"] == "in_triage" for v in na) and all(MARK in v["properties"] for v in na)
    assert len(cdx["vulnerabilities"]) == N + 3 and len(assessed(cdx)) == 3
    assert not any(is_na(v) for v in cdx["vulnerabilities"] if v["id"] in ("CVE-1", "CVE-2", "CVE-3"))
    assert (st["statements"], st["statements_assessed"], st["statements_not_assessed"]) == (N + 3, 3, N)
    # detail 寫明是沒有評估，不是調查中
    assert all("Not assessed" in v["analysis"]["detail"] and "does not mean" in v["analysis"]["detail"] for v in na)
    ovs = [s for s in ov["statements"] if s["status"] == "under_investigation" and s.get("status_notes") == NOTE]
    assert len(ovs) == N and len(ov["statements"]) == N + 3
    # 人設的 in_triage 轉成 under_investigation、但不是 not assessed
    assert vx.not_assessed_count(cdx, "vex.cdx.json") == N == vx.not_assessed_count(ov, "vex.openvex.json")
    # 每一條都有指向元件（SBOM 的 bom-ref 或這份 VEX 自己的 components）
    assert all(v["affects"] for v in cdx["vulnerabilities"]) and all(s["products"] for s in ov["statements"])


def test_assessed_statements_are_identical_with_and_without_unassessed_rows():
    base = [row("CVE-1", analysis=dt("NOT_AFFECTED", "CODE_NOT_PRESENT", details="not built")),
            row("CVE-2", analysis=dt("EXPLOITABLE", response="UPDATE", details="fix in 2.4"))]
    a = build(base)[2]
    b = build(base + untriaged_rows(3))[2]
    assert assessed(b) == a["vulnerabilities"] and a["serialNumber"] != b["serialNumber"]


def test_unassessed_statement_does_not_claim_a_source_rule_or_author():
    _, _, cdx, _, _ = build(untriaged_rows(1))
    v = cdx["vulnerabilities"][0]
    names = {p["name"] for p in v["properties"]}
    assert "dumpling:assessment" in names and not names & {"sca-center:vex-source", "sca-center:vex-rule", "sca-center:annotation-author",
                                                            "openvex:action_statement"}
    assert {"justification", "response"}.isdisjoint(v["analysis"])


def test_unassessed_alias_cve_in_vex_extra_is_written_too():
    from test_vex_export import ann
    allr, _, _ = vx.assess([two_cve_row()], annotations=[ann("CVE-2026-0001", purl="pkg:deb/ubuntu/openssl")])
    assert allr[0]["vex"] and allr[0]["vex_extra"][0]["vex"] is None
    cdx, _ = vx.cdx_vex(allr, PBOM, {}, {"name": "P"}, "ATTENTION")
    ov = vx.openvex(cdx, "Example Co.", vx.purl_by_bomlink(PBOM))
    by = {v["id"]: v for v in cdx["vulnerabilities"]}
    assert not is_na(by["CVE-2026-0001"]) and is_na(by["CVE-2026-0002"])         # 別名 CVE-B 沒有判定
    assert len({v["bom-ref"] for v in cdx["vulnerabilities"]}) == 2
    assert {s["vulnerability"]["name"]: s["status"] for s in ov["statements"]} == {"CVE-2026-0001": "not_affected", "CVE-2026-0002": "under_investigation"}


def test_duplicate_unassessed_rows_and_assessed_wins():
    r1 = row("CVE-5")
    r2 = dict(r1)                                                                # 同一個 (編號, purl, 版本) 的重複列
    r3 = row("CVE-6", analysis=dt("NOT_AFFECTED", "CODE_NOT_PRESENT", details="x"))
    r4 = row("CVE-6")                                                            # 和有判定的陳述同一個 key：以判定為準
    allr, _, _ = vx.assess([r1, r2, r3])
    allr.append(dict(r4, vex=None, vex_extra=[]))
    cdx, st = vx.cdx_vex(allr, PBOM, {}, {"name": "P"}, "OK")
    ids = sorted((v["id"], is_na(v)) for v in cdx["vulnerabilities"])
    assert ids == [("CVE-5", True), ("CVE-6", False)] and st["not_assessed_duplicates_skipped"] == 2
    assert len({v["bom-ref"] for v in cdx["vulnerabilities"]}) == 2
    # 有判定的重複陳述照舊拒絕（test_cdx_vex_refuses_duplicate_statements）：沒判定的重複不會讓它失敗，也不會掩蓋它
    pbom = {"serialNumber": "urn:uuid:00000000-0000-0000-0000-000000000000", "version": 1, "metadata": {}, "components": []}
    d1 = row("CVE-7", analysis=dt("NOT_AFFECTED", "CODE_NOT_PRESENT"))
    d2 = dict(d1, analysis=dt("EXPLOITABLE", response="UPDATE"))
    al, _, _ = vx.assess([d1, d2])
    with pytest.raises(vx.VexInputError, match="多條 VEX 陳述"):
        vx.cdx_vex(al, pbom, {}, {"name": "P"}, "OK")


def test_unassessed_row_for_component_not_in_sbom_is_scoped_to_its_own_component():
    _, _, cdx, st, _ = build([row("CVE-8", "notinsbom", "1")])
    v = cdx["vulnerabilities"][0]
    assert st["components_not_in_sbom"] == 1 and v["affects"] == [{"ref": cdx["components"][0]["bom-ref"]}]
    assert not any(a["ref"].endswith("#root") for a in v["affects"])           # 不擴大成整個產品


def test_output_with_unassessed_rows_is_deterministic_and_order_independent():
    import random
    a = build(sample_rows() + untriaged_rows(3))
    rs = sample_rows() + untriaged_rows(3)
    random.Random(7).shuffle(rs)
    b = build(rs)
    assert vx.dumps(a[2]) == vx.dumps(b[2]) and vx.dumps(a[4]) == vx.dumps(b[4])


def test_official_schemas_with_unassessed_statements():
    jsonschema = pytest.importorskip("jsonschema")
    from cdx_schema import cdx_validator
    _, _, cdx, _, ov = build(sample_rows() + untriaged_rows(3))
    assert sum(1 for v in cdx["vulnerabilities"] if is_na(v)) >= 4
    errs = list(cdx_validator().iter_errors(cdx))
    assert not errs, [e.message for e in errs[:3]]
    errs = list(jsonschema.Draft202012Validator(json.load(open(OV_SCHEMA)), format_checker=jsonschema.FormatChecker()).iter_errors(ov))
    assert not errs, [e.message for e in errs[:3]]


def test_roundtrip_through_vexconv_keeps_the_marker_both_ways():
    vc = vx._vexconv()
    N = 3
    _, _, cdx, _, ov = build(untriaged_rows(N) + [row("CVE-1", analysis=dt("NOT_AFFECTED", "CODE_NOT_PRESENT", details="not built"))])
    # cdx → openvex → cdx
    back = vc.to_cdx(ov)
    assert sum(1 for v in back["vulnerabilities"] if MARK in (v.get("properties") or [])) == N
    # openvex → cdx → openvex（每條的狀態與說明都回得來）
    again = vc.to_openvex(back, lenient=True)
    assert [(s["vulnerability"]["name"], s["status"], s.get("status_notes")) for s in again["statements"]] == \
           [(s["vulnerability"]["name"], s["status"], s.get("status_notes")) for s in ov["statements"]]
    # vexconv 自己直接轉 vex_export 的 CDX（不經過 vex_export.openvex）也一樣
    assert sum(1 for s in vc.to_openvex(cdx, lenient=True)["statements"] if s.get("status_notes") == NOTE) == N


# ---------- 發行閘門不變 ----------

def gate_rows():
    return sample_rows() + [row("CVE-9", "zlib1g", "1.3", tier="p1", kev=True), row("CVE-10", "linux", "6.8", kernel=True, tier="p3"),
                            row("CVE-11", analysis=dt("EXPLOITABLE", response="UPDATE")), row("CVE-12", "libfoo", "2", analysis=dt("RESOLVED")),
                            two_cve_row()]


def test_gate_is_identical_before_and_after_the_a4_output():
    """gate 看的是 r["vex"]，輸出階段不改列：cdx_vex 前後 gate 全等；列本身（含 vex_extra）也沒有被改。"""
    allr, conf, _ = vx.assess(gate_rows(), drc=recheck_doc())
    before_rows = copy.deepcopy(allr)
    g0 = vx.gate(allr, conf, grype_checked=True, not_assessed=[])
    vx.cdx_vex(allr, PBOM, {}, {"name": "P"}, g0["verdict"])
    assert allr == before_rows
    assert vx.gate(allr, conf, grype_checked=True, not_assessed=[]) == g0
    c = g0["counts"]["total"]
    assert c["untriaged"] == 4 and c["in_triage"] == 1          # 沒有判定的列在閘門仍是 untriaged，不是 in_triage


def test_gate_equals_the_output_recorded_before_a4(tmp_path):
    """改動之前（main a1fe821）同一份輸入的 gate（單元：assess＋gate；端對端：cra_report 的 summary.json vex.gate）全等。
    data/vex_gate_before_a4.json 是在改動前的程式碼上產生的，不隨這次改動重生。"""
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    allr, conf, _ = vx.assess(gate_rows(), drc=recheck_doc())
    # 因 D-035 而變：這份輸入有 DT 的排除（DT 沒有放依據類型的欄位，D-057），新程式碼把它們算進 untriaged_for_gate。
    # 原本是「閘門輸出全等」；現在分兩段：(1) 沒有補依據時，差異只有 D-035 的效果（d035_unexplained 逐項核對）；
    # (2) 在補上依據類型的輸入下（typed），新程式碼的閘門輸出與舊基準全等（連新欄位 exclusions_without_evidence 都是 0 之外沒有差別）。
    g0 = vx.gate(allr, conf, grype_checked=True, not_assessed=[])
    n_dt = g0["assessment"]["exclusions_without_evidence"]
    assert n_dt == sum(1 for x in allr if vx.is_exclusion(x.get("vex")) and x["vex"]["source"] == "dt") > 0     # distro 的那筆有類型（vendor-statement）
    assert d035_unexplained(golden["unit"], json.loads(json.dumps(g0, sort_keys=True, ensure_ascii=False))) == []
    typed(allr)
    g = vx.gate(allr, conf, grype_checked=True, not_assessed=[])
    new = json.loads(json.dumps(g, sort_keys=True, ensure_ascii=False))
    assert new["assessment"].pop("exclusions_without_evidence") == 0
    assert new == golden["unit"]
    r, s, rep = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s"))
    e2e = json.loads(json.dumps(s["vex"]["gate"], sort_keys=True, ensure_ascii=False))
    assert e2e["assessment"]["exclusions_without_evidence"] == 1                  # 端對端的那一筆 DT 排除
    assert d035_unexplained(golden["e2e"], e2e) == []
    # 同一份輸入，VEX 多了沒有判定的陳述，但閘門的分類與 verdict 沒有因此改變
    cdx = json.loads((rep / "vex.cdx.json").read_text(encoding="utf-8"))
    assert sum(1 for v in cdx["vulnerabilities"] if is_na(v)) == golden["e2e"]["counts"]["total"]["untriaged"]


# ---------- cra_report 端到端 ----------

def test_report_end_to_end_statement_counts_and_text(tmp_path):
    r, s, rep = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s"))
    assert s["status"] != "FAIL", r.stdout + r.stderr
    v = s["vex"]
    cdx = json.loads((rep / "vex.cdx.json").read_text(encoding="utf-8"))
    ov = json.loads((rep / "vex.openvex.json").read_text(encoding="utf-8"))
    n_na = v["gate"]["counts"]["total"]["untriaged"]
    assert n_na > 0
    # statements＝檔案裡的陳述總數（含沒有評估的）；有判定的陳述數與沒有評估的陳述數各有欄位
    assert v["statements"] == len(cdx["vulnerabilities"]) == len(ov["statements"])
    assert v["statements_not_assessed"] == n_na and v["statements_assessed"] == v["statements"] - n_na
    assert v["files"]["vex.cdx.json"] == dict(v["files"]["vex.cdx.json"], statements=v["statements"], not_assessed=n_na)
    assert v["files"]["vex.openvex.json"]["not_assessed"] == n_na and v["files"]["vex.openvex.json"]["statements"] == v["statements"]
    assert sum(1 for x in ov["statements"] if x["status"] == "under_investigation" and x.get("status_notes") == NOTE) == n_na
    t = (rep / "risk-assessment.md").read_text(encoding="utf-8")
    assert "`dumpling:assessment` = `NOT_ASSESSED`" in t and "does not mean that anyone is investigating it" in t
    assert f"{v['statements']} statements, {n_na} of them not assessed, SHA-256" in t
    assert "NOT_ASSESSED" in (rep / "technical-documentation.md").read_text(encoding="utf-8")


def test_templates_say_not_assessed_rows_are_written_as_in_triage():
    tpl = HERE.parent / "templates"
    for name in ("risk-assessment.md", "technical-documentation.md"):
        t = " ".join((tpl / name).read_text(encoding="utf-8").split())
        assert "NOT_ASSESSED" in t and "does not mean that anyone is investigating" in t, name
