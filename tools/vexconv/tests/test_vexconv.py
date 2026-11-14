import json, os, sys, copy, subprocess
import pytest
jsonschema = pytest.importorskip("jsonschema")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import vexconv as vc

# 上游 schema 放在 tools/cra/tests/data/（來源與 SHA-256 見各資料夾的 README.md）；不需要網路
DATA = os.path.join(os.path.dirname(os.path.dirname(HERE)), "cra", "tests", "data")
CDX_SCHEMA = json.load(open(f"{DATA}/cyclonedx-1.5/bom-1.5.schema.json"))
OV_SCHEMA = json.load(open(f"{DATA}/openvex/openvex_json_schema.json"))

def _cdx_validator():
    from referencing import Registry, Resource
    reg = Registry()
    for n in ("spdx.schema.json", "jsf-0.82.schema.json"):
        d = json.load(open(f"{DATA}/cyclonedx-1.6.1/{n}"))
        reg = reg.with_resource(d.get("$id", n), Resource.from_contents(d))
        reg = reg.with_resource(n, Resource.from_contents(d))
    return jsonschema.Draft7Validator(CDX_SCHEMA, registry=reg)

def valid_cdx(d):
    errs = list(_cdx_validator().iter_errors(d))
    assert not errs, [e.message for e in errs[:3]]

def valid_ov(d):
    errs = list(jsonschema.Draft202012Validator(OV_SCHEMA, format_checker=jsonschema.FormatChecker()).iter_errors(d))
    assert not errs, [e.message for e in errs[:3]]

P1 = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
P2 = "pkg:npm/lodash@4.17.20"
def ov_doc(stmts):
    return {"@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://ex.org/vex/1",
            "author": "me", "timestamp": "2026-01-01T00:00:00Z", "version": 1, "statements": stmts}

OV = ov_doc([
    {"vulnerability": {"name": "CVE-2021-44228", "aliases": ["GHSA-jfh8-c2jp-5v3q"]},
     "products": [{"@id": P1}], "status": "not_affected",
     "justification": "vulnerable_code_not_in_execute_path", "impact_statement": "JndiLookup never called"},
    {"vulnerability": {"name": "CVE-2022-0001"}, "products": [{"@id": P2}], "status": "not_affected",
     "justification": "component_not_present"},
    {"vulnerability": {"name": "CVE-2022-0002"}, "products": [{"@id": P2}, {"@id": P1}], "status": "affected",
     "action_statement": "Upgrade to 4.17.21"},
    {"vulnerability": {"name": "CVE-2022-0003"}, "products": [{"@id": P1}], "status": "under_investigation"},
    {"vulnerability": {"name": "CVE-2022-0004"}, "products": [{"@id": P1}], "status": "fixed"},
])

def key(ov):
    return sorted((s["vulnerability"]["name"], s["status"], s.get("justification"),
                   tuple(sorted(p["@id"] for p in s["products"]))) for s in ov["statements"])

def test_ov_fixture_valid(): valid_ov(OV)
def test_to_cdx_schema(): valid_cdx(vc.to_cdx(OV))
def test_to_openvex_schema():
    valid_ov(vc.to_openvex(vc.to_cdx(OV)))

def test_roundtrip_ov_cdx_ov():
    out = vc.to_openvex(vc.to_cdx(OV))
    assert key(out) == key(OV)

@pytest.mark.parametrize("j", ["component_not_present", "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path", "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist"])
def test_each_ov_justification_roundtrips(j):
    d = ov_doc([{"vulnerability": {"name": "CVE-1"}, "products": [{"@id": P1}], "status": "not_affected", "justification": j}])
    assert vc.to_openvex(vc.to_cdx(d))["statements"][0]["justification"] == j

def test_action_statement_roundtrip():
    out = vc.to_openvex(vc.to_cdx(OV))
    s = [x for x in out["statements"] if x["vulnerability"]["name"] == "CVE-2022-0002"][0]
    assert s["action_statement"] == "Upgrade to 4.17.21"

def test_aliases_roundtrip():
    out = vc.to_openvex(vc.to_cdx(OV))
    assert out["statements"][0]["vulnerability"]["aliases"] == ["GHSA-jfh8-c2jp-5v3q"]

CDX = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
       "metadata": {"timestamp": "2026-01-01T00:00:00Z"},
       "vulnerabilities": [
    {"id": "CVE-2021-44228", "affects": [{"ref": P1}],
     "analysis": {"state": "not_affected", "justification": "code_not_reachable", "detail": "unused"}},
    {"id": "CVE-2022-0001", "affects": [{"ref": P2}],
     "analysis": {"state": "not_affected", "justification": "code_not_present"}},
    {"id": "CVE-2022-0002", "affects": [{"ref": P2}],
     "analysis": {"state": "exploitable", "response": ["update"], "detail": "upgrade"}},
    {"id": "CVE-2022-0003", "affects": [{"ref": P1}], "analysis": {"state": "in_triage"}},
    {"id": "CVE-2022-0004", "affects": [{"ref": P1}], "analysis": {"state": "resolved"}}]}

def ckey(c):
    return sorted((v["id"], v["analysis"]["state"], v["analysis"].get("justification"),
                   tuple(sorted(a["ref"] for a in v["affects"]))) for v in c["vulnerabilities"])

def test_cdx_fixture_valid(): valid_cdx(CDX)
def test_cdx_to_ov_schema(): valid_ov(vc.to_openvex(CDX, lenient=True))
def test_roundtrip_cdx_ov_cdx():
    assert ckey(vc.to_cdx(vc.to_openvex(CDX, lenient=True))) == ckey(CDX)

@pytest.mark.parametrize("j", ["code_not_present", "code_not_reachable", "requires_configuration",
    "requires_dependency", "requires_environment", "protected_by_compiler", "protected_at_runtime",
    "protected_at_perimeter", "protected_by_mitigating_control"])
def test_each_cdx_justification_roundtrips(j):
    c = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "vulnerabilities": [
        {"id": "CVE-1", "affects": [{"ref": P1}], "analysis": {"state": "not_affected", "justification": j}}]}
    back = vc.to_cdx(vc.to_openvex(c))["vulnerabilities"][0]["analysis"]["justification"]
    assert back == j

@pytest.mark.parametrize("st", ["false_positive", "resolved_with_pedigree"])
def test_cdx_state_roundtrips(st):
    a = {"state": st}
    if st == "false_positive": a["justification"] = "code_not_present"
    c = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "vulnerabilities": [
        {"id": "CVE-1", "affects": [{"ref": P1}], "analysis": a}]}
    assert vc.to_cdx(vc.to_openvex(c))["vulnerabilities"][0]["analysis"]["state"] == st

def test_stale_property_does_not_override_edited_justification():
    # DT user edits justification after an OV->CDX conversion
    c = vc.to_cdx(ov_doc([{"vulnerability": {"name": "CVE-1"}, "products": [{"@id": P1}],
        "status": "not_affected", "justification": "component_not_present"}]))
    c["vulnerabilities"][0]["analysis"]["justification"] = "code_not_reachable"
    assert vc.to_openvex(c)["statements"][0]["justification"] == "vulnerable_code_not_in_execute_path"

def test_empty_cdx_is_rejected_because_openvex_requires_a_statement():
    # OpenVEX 0.2.0 schema: statements has minItems 1
    with pytest.raises(vc.VexError):
        vc.to_openvex({"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1})

def test_cdx_missing_id_is_vexerror():
    with pytest.raises(vc.VexError):
        vc.to_openvex({"bomFormat": "CycloneDX", "vulnerabilities": [{"analysis": {"state": "in_triage"}}]})

def test_cdx_affects_without_ref_is_vexerror():
    with pytest.raises(vc.VexError):
        vc.to_openvex({"bomFormat": "CycloneDX", "vulnerabilities": [{"id": "X", "affects": [{}], "analysis": {"state": "in_triage"}}]})

def test_string_vulnerability_rejected_or_object():
    d = ov_doc([{"vulnerability": "CVE-1", "products": [{"@id": P1}], "status": "fixed"}])
    # OpenVEX schema requires an object; the converter accepts a bare string silently
    with pytest.raises(vc.VexError):
        vc.to_cdx(d)

def test_statement_notes_preserved():
    d = ov_doc([{"vulnerability": {"name": "CVE-1"}, "products": [{"@id": P1}], "status": "under_investigation",
                 "status_notes": "waiting for vendor"}])
    assert vc.to_openvex(vc.to_cdx(d))["statements"][0].get("status_notes") == "waiting for vendor"

def test_notaffected_status_notes_not_turned_into_impact():
    d = ov_doc([{"vulnerability": {"name": "CVE-1"}, "products": [{"@id": P1}], "status": "not_affected",
                 "justification": "component_not_present", "status_notes": "checked by A"}])
    s = vc.to_openvex(vc.to_cdx(d))["statements"][0]
    assert "impact_statement" not in s and s.get("status_notes") == "checked by A"

def test_affected_without_action_not_fabricated_in_cdx_to_ov():
    c = {"bomFormat": "CycloneDX", "vulnerabilities": [{"id": "X", "affects": [{"ref": P1}], "analysis": {"state": "exploitable"}}]}
    with pytest.raises(vc.VexError):
        vc.to_openvex(c)                       # strict mode refuses to invent an action
    assert vc.to_openvex(c, lenient=True)["statements"][0]["action_statement"] != "See vendor advisory."

def test_ov_affected_without_action_rejected():
    d = ov_doc([{"vulnerability": {"name": "X"}, "products": [{"@id": P1}], "status": "affected"}])
    with pytest.raises(vc.VexError):
        vc.to_cdx(d)

# error cases
def test_unknown_status():
    with pytest.raises(vc.VexError):
        vc.to_cdx(ov_doc([{"vulnerability": {"name": "X"}, "products": [], "status": "bogus"}]))
def test_unknown_cdx_state():
    with pytest.raises(vc.VexError):
        vc.to_openvex({"bomFormat": "CycloneDX", "vulnerabilities": [{"id": "X", "analysis": {"state": "bogus"}}]})
def test_missing_vuln_name():
    with pytest.raises(vc.VexError):
        vc.to_cdx(ov_doc([{"vulnerability": {}, "products": [{"@id": P1}], "status": "fixed"}]))
def test_unknown_justification():
    with pytest.raises(vc.VexError):
        vc.to_cdx(ov_doc([{"vulnerability": {"name": "X"}, "products": [{"@id": P1}], "status": "not_affected", "justification": "nope"}]))
def test_ov_not_affected_without_justification_rejected():
    d = ov_doc([{"vulnerability": {"name": "X"}, "products": [{"@id": P1}], "status": "not_affected"}])
    with pytest.raises(vc.VexError):
        vc.to_cdx(d)
def test_cdx_not_affected_without_justification_or_detail():
    with pytest.raises(vc.VexError):
        vc.to_openvex({"bomFormat": "CycloneDX", "vulnerabilities": [{"id": "X", "affects": [{"ref": P1}], "analysis": {"state": "not_affected"}}]})
def test_not_openvex_doc():
    with pytest.raises(vc.VexError):
        vc.to_cdx({"foo": 1})


# ---- M7c-1（A4／D-057）：沒有評估的陳述（in_triage 加 dumpling:assessment＝NOT_ASSESSED ↔ under_investigation 加固定的 status_notes）

def na_cdx(n=3, extra=()):
    vs = [{"id": f"CVE-2026-{i:04d}", "affects": [{"ref": P1}],
           "analysis": {"state": "in_triage", "detail": vc.DETAIL_NOT_ASSESSED},
           "properties": [{"name": vc.PROP_ASSESSMENT, "value": vc.NOT_ASSESSED}]} for i in range(n)]
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "vulnerabilities": vs + list(extra)}

def na_count_cdx(c):
    return sum(1 for v in c["vulnerabilities"] if {"name": vc.PROP_ASSESSMENT, "value": vc.NOT_ASSESSED} in v.get("properties", []))

def na_count_ov(o):
    return sum(1 for s in o["statements"] if s["status"] == "under_investigation" and s.get("status_notes") in vc.NOT_ASSESSED_NOTES)

def test_not_assessed_constants():
    assert (vc.PROP_ASSESSMENT, vc.NOT_ASSESSED, vc.NOTE_NOT_ASSESSED) == ("dumpling:assessment", "NOT_ASSESSED", "dumpling: not assessed")
    assert vc.NOTE_NOT_ASSESSED_CUSTOMER == "Not yet assessed by the manufacturer" and "dumpling" not in vc.NOTE_NOT_ASSESSED_CUSTOMER.lower()
    assert "not mean that anyone is investigating" in vc.DETAIL_NOT_ASSESSED      # 寫明是沒評估，不是調查中

def test_not_assessed_cdx_to_openvex_n_statements():
    ov = vc.to_openvex(na_cdx(3))
    assert len(ov["statements"]) == 3 and na_count_ov(ov) == 3
    assert {s["status_notes"] for s in ov["statements"]} == {"dumpling: not assessed"}
    assert all(s["status"] == "under_investigation" and "impact_statement" not in s for s in ov["statements"])
    valid_ov(ov)

def test_not_assessed_cdx_ov_cdx_keeps_marker():
    c = vc.to_cdx(vc.to_openvex(na_cdx(3)))
    assert na_count_cdx(c) == 3 and all(v["analysis"]["state"] == "in_triage" for v in c["vulnerabilities"])
    assert all(v["analysis"]["detail"] == vc.DETAIL_NOT_ASSESSED for v in c["vulnerabilities"])
    valid_cdx(c)

def test_not_assessed_ov_cdx_ov_keeps_note_internal_and_customer_sentence():
    for note in vc.NOT_ASSESSED_NOTES:       # 內部的句子與客戶版的中性英文，轉兩輪都不變
        d = ov_doc([{"vulnerability": {"name": "CVE-1"}, "products": [{"@id": P1}], "status": "under_investigation", "status_notes": note}])
        c = vc.to_cdx(d)
        assert na_count_cdx(c) == 1 and c["vulnerabilities"][0]["analysis"]["state"] == "in_triage"
        out = vc.to_openvex(c)
        assert out["statements"][0]["status_notes"] == note and out["statements"][0]["status"] == "under_investigation"
        assert na_count_cdx(vc.to_cdx(out)) == 1

def test_customer_cdx_without_marker_but_neutral_detail_stays_not_assessed():
    # 客戶版 CDX 照白名單不帶 dumpling:assessment，說明是中性句子：轉 OpenVEX 再轉回來，標記仍補回去
    c = {"bomFormat": "CycloneDX", "version": 1, "vulnerabilities": [
        {"id": "CVE-1", "affects": [{"ref": P1}], "analysis": {"state": "in_triage", "detail": vc.NOTE_NOT_ASSESSED_CUSTOMER}}]}
    o = vc.to_openvex(c)
    assert o["statements"][0]["status_notes"] == vc.NOTE_NOT_ASSESSED_CUSTOMER
    assert na_count_cdx(vc.to_cdx(o)) == 1

def test_other_under_investigation_gets_no_marker():
    d = ov_doc([{"vulnerability": {"name": "CVE-1"}, "products": [{"@id": P1}], "status": "under_investigation"},
                {"vulnerability": {"name": "CVE-2"}, "products": [{"@id": P1}], "status": "under_investigation", "status_notes": "waiting for vendor"}])
    c = vc.to_cdx(d)
    assert na_count_cdx(c) == 0
    # 一般的 in_triage（有人在調查）轉 OpenVEX 不會變成「沒評估」
    o = vc.to_openvex({"bomFormat": "CycloneDX", "vulnerabilities": [{"id": "X", "affects": [{"ref": P1}], "analysis": {"state": "in_triage", "detail": "looking"}}]})
    assert o["statements"][0]["status_notes"] == "looking" and na_count_ov(o) == 0

def test_not_assessed_mixed_with_assessed_keeps_each_statement():
    real = {"id": "CVE-9", "affects": [{"ref": P2}], "analysis": {"state": "exploitable", "response": ["update"]},
            "properties": [{"name": vc.PROP_ACTION, "value": "Upgrade"}]}
    c = na_cdx(2, [real])
    ov = vc.to_openvex(c)
    assert [s["status"] for s in ov["statements"]] == ["under_investigation", "under_investigation", "affected"]
    back = vc.to_cdx(ov)
    assert na_count_cdx(back) == 2 and back["vulnerabilities"][2]["analysis"]["state"] == "exploitable"

def test_empty_cdx_still_rejected_but_not_assessed_rows_count_as_statements():
    with pytest.raises(vc.VexError):
        vc.to_openvex({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "vulnerabilities": []})
    with pytest.raises(vc.VexError):          # 沒有 analysis.state、沒有標記的列照舊不是陳述
        vc.to_openvex({"bomFormat": "CycloneDX", "vulnerabilities": [{"id": "X", "affects": [{"ref": P1}]}]})
    assert len(vc.to_openvex(na_cdx(1))["statements"]) == 1
