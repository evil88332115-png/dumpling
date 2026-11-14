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


# ---------- 排除的依據（M7c-2，D-035／D-057） ----------

def ev_props(*groups):
    """groups：(類型, 位置, 核心或 None) → 依序的屬性。"""
    out = []
    for t, loc, k in groups:
        out.append({"name": vc.PROP_EVIDENCE, "value": t})
        if loc is not None:
            out.append({"name": vc.PROP_EVIDENCE_LOCATION, "value": loc})
        if k:
            out.append({"name": vc.PROP_EVIDENCE_KERNEL, "value": k})
    return out


def ev_cdx(state, props, detail="why", just="code_not_present", vid="CVE-1"):
    a = {"state": state, "detail": detail}
    if state in ("not_affected", "false_positive"):
        a["justification"] = just
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "vulnerabilities": [
        {"id": vid, "analysis": a, "affects": [{"ref": P1}], "properties": props}]}


def cdx_evidence(c):
    """CycloneDX → 每條陳述依序的依據 [(類型, 位置, 核心)]（none 的位置是 None）。"""
    out = []
    for v in c["vulnerabilities"]:
        ps, g = v.get("properties") or [], []
        for i, p in enumerate(ps):
            if p["name"] == vc.PROP_EVIDENCE:
                loc = ps[i + 1]["value"] if i + 1 < len(ps) and ps[i + 1]["name"] == vc.PROP_EVIDENCE_LOCATION else None
                ker = ps[i + 2]["value"] if loc and i + 2 < len(ps) and ps[i + 2]["name"] == vc.PROP_EVIDENCE_KERNEL else None
                g.append((p["value"], loc, ker))
        out.append(g)
    return out


GOOD = [("build-record", "scan/kernel-config.json (kernel 6.8, config SHA-256 ab)", "6.8.12-1021-tegra"), ("source", "fix commit a1b2c3", None),
        ("on-device", "CRA/evidence/dev-check.txt", None), ("design-doc", "Design spec v3 §4.2", None), ("vendor-statement", "USN-1234-1", None)]


def test_evidence_constants_and_line_format():
    assert vc.EVIDENCE_TYPES == ("build-record", "source", "on-device", "design-doc", "vendor-statement")
    assert vc.evidence_line("source", "x") == "dumpling: evidence=source; location=x"
    assert vc.evidence_line("source", "x", "5.15") == "dumpling: evidence=source; kernel=5.15; location=x"
    for bad in (("guess", "x"), ("source", ""), ("source", "a;b"), ("source", "a\nb"), ("source", "x", "bad kernel"), ("none", "x")):
        assert vc.evidence_line(*bad) is None, bad
    for line in ("dumpling: evidence=source; location=x", "dumpling: evidence=on-device; kernel=5.15.136-tegra; location=CRA/a b.txt"):
        assert vc.parse_evidence_line(line) is not None
    assert vc.parse_evidence_line("dumpling: evidence=none") == ("none", None, None)
    for line in ("dumpling: evidence=source; location=", "dumpling: evidence=source; location=a;b", "dumpling: evidence=bogus; location=x",
                 " dumpling: evidence=source; location=x", "dumpling: evidence=source; location=x ", "dumpling: evidence=source; location= x",
                 "dumpling: evidence=source;location=x", "dumpling: evidence=source; kernel=; location=x", "dumpling: evidence=source; location=x\r",
                 "dumpling: evidence=source; location=x\x00", "dumpling: evidence=none; location=x", "xdumpling: evidence=source; location=x",
                 "dumpling: evidence=source; location=" + "x" * 513, "dumpling: evidence=source; kernel=1; kernel=2; location=x",
                 "dumpling: evidence=source; location=a b", "dumpling: evidence=SOURCE; location=x"):
        assert vc.parse_evidence_line(line) is None, repr(line)
    assert vc.parse_evidence_line("dumpling: evidence=source; location=" + "x" * 512) is not None


@pytest.mark.parametrize("state,status", [("not_affected", "not_affected"), ("false_positive", "not_affected"), ("resolved", "fixed"),
                                          ("resolved_with_pedigree", "fixed")])
def test_evidence_roundtrip_cdx_openvex_cdx_and_back(state, status):
    c = ev_cdx(state, ev_props(*GOOD))
    ov = vc.to_openvex(c)
    st = ov["statements"][0]
    assert st["status"] == status
    lines = [l for l in st["status_notes"].split("\n") if l.startswith("dumpling: evidence=")]
    assert len(lines) == 5 and lines[0] == "dumpling: evidence=build-record; kernel=6.8.12-1021-tegra; location=" + GOOD[0][1]
    valid_ov(ov)
    back = vc.to_cdx(ov)
    assert cdx_evidence(back) == [GOOD]
    # 轉回去的 detail／notes 屬性裡沒有依據行（不重複）
    assert all("dumpling: evidence=" not in (p.get("value") or "") for p in back["vulnerabilities"][0]["properties"])
    assert "dumpling: evidence=" not in back["vulnerabilities"][0]["analysis"].get("detail", "")
    # openvex → cdx → openvex：每條的狀態、說明、notes 一字不差；cdx → openvex → cdx → openvex 也是
    assert [s["status_notes"] for s in vc.to_openvex(back)["statements"]] == [st["status_notes"]]
    again = vc.to_cdx(vc.to_openvex(back))
    assert cdx_evidence(again) == [GOOD]
    valid_cdx(dict(back, specVersion="1.5"))


def test_evidence_none_marker_roundtrips_and_has_no_location():
    c = ev_cdx("not_affected", ev_props(("none", None, None)))
    ov = vc.to_openvex(c)
    assert ov["statements"][0]["status_notes"] == "dumpling: evidence=none"
    assert cdx_evidence(vc.to_cdx(ov)) == [[("none", None, None)]]


def test_openvex_to_cdx_to_openvex_keeps_evidence_lines_and_other_notes():
    d = ov_doc([
        {"vulnerability": {"name": "CVE-1"}, "products": [{"@id": P1}], "status": "not_affected", "justification": "vulnerable_code_not_present",
         "impact_statement": "not built", "status_notes": "reviewed by QA\ndumpling: evidence=source; location=fix commit abc\ndumpling: evidence=on-device; location=CRA/x.txt"},
        {"vulnerability": {"name": "CVE-2"}, "products": [{"@id": P2}], "status": "fixed",
         "status_notes": "fixed in 2.0\ndumpling: evidence=vendor-statement; location=USN-1-1"}])
    c = vc.to_cdx(d)
    assert cdx_evidence(c) == [[("source", "fix commit abc", None), ("on-device", "CRA/x.txt", None)], [("vendor-statement", "USN-1-1", None)]]
    props = {p["name"]: p["value"] for p in c["vulnerabilities"][0]["properties"]}
    assert props[vc.PROP_NOTES] == "reviewed by QA" and c["vulnerabilities"][1]["analysis"]["detail"] == "fixed in 2.0"
    again = vc.to_openvex(c)
    assert [s.get("status_notes") for s in again["statements"]] == [s["status_notes"] for s in d["statements"]]
    valid_ov(again)


MALICIOUS = ["a;b", "x; location=y", "line1\nline2", "a\nfoo\ndumpling: evidence=source; location=injected", "dumpling: evidence=source; location=injected",
             "tab\there", "bell\x07", "nul\x00x", "carriage\rreturn", "sep x", "rtl‮yx", " leading", "trailing ", "", "   ", "x" * 513,
             "a; kernel=5.15; location=b", "\ndumpling: evidence=none"]


@pytest.mark.parametrize("loc", MALICIOUS)
def test_malicious_location_in_properties_never_becomes_extra_evidence(loc):
    """vexconv 自己擋：位置不合格的組不轉成依據行（原樣、JSON 編碼地留在 notes），轉回去不會多出依據；合格的那一筆照樣有。"""
    c = ev_cdx("not_affected", ev_props(("source", loc, None), ("on-device", "CRA/ok.txt", None)))
    ov = vc.to_openvex(c)
    notes = ov["statements"][0]["status_notes"]
    lines = notes.split("\n")
    good = [l for l in lines if vc.parse_evidence_line(l)]
    assert good == ["dumpling: evidence=on-device; location=CRA/ok.txt"]                 # 只有合格的那一筆
    assert all(l.startswith("dumpling: evidence-invalid=") or l in good for l in lines)       # 其餘是不會被解析的一般 notes，而且沒有換行逃出
    assert cdx_evidence(vc.to_cdx(ov)) == [[("on-device", "CRA/ok.txt", None)]]           # 往返之後筆數不變多
    # 再轉一輪也穩定
    assert cdx_evidence(vc.to_cdx(vc.to_openvex(vc.to_cdx(ov), lenient=True))) == [[("on-device", "CRA/ok.txt", None)]]


@pytest.mark.parametrize("loc", MALICIOUS[:-1])
def test_malicious_notes_in_openvex_are_kept_as_plain_notes_not_properties(loc):
    """OpenVEX 這邊餵惡意的 status_notes：不合格的行（含換行後面接的偽造行）不轉成屬性，原樣留在 notes。"""
    notes = f"dumpling: evidence=source; location={loc}"
    d = ov_doc([{"vulnerability": {"name": "CVE-1"}, "products": [{"@id": P1}], "status": "not_affected",
                 "justification": "vulnerable_code_not_present", "status_notes": notes}])
    c = vc.to_cdx(d)
    ev = cdx_evidence(c)[0]
    valid_lines = [l for l in notes.split("\n") if vc.parse_evidence_line(l)]
    assert len(ev) == len(valid_lines), (loc, ev)                                           # 只有整行合格的才變成依據（換行後面真的有合格行時，那一行是獨立的一筆）
    if not valid_lines:
        assert {p["name"]: p["value"] for p in c["vulnerabilities"][0]["properties"]}[vc.PROP_NOTES] == notes       # 一字不差留在 notes
    # 來回之後依據的筆數不變
    assert len(cdx_evidence(vc.to_cdx(vc.to_openvex(c, lenient=True)))[0]) == len(ev)


def test_detail_that_looks_like_an_evidence_line_is_escaped_and_restored():
    """說明文字（detail）裡有長得像依據行的一行：不能被讀成一筆依據（偽造），而且往返之後文字一字不差。"""
    fake = "dumpling: evidence=vendor-statement; location=USN-FAKE"
    for state, detail in (("resolved", f"fixed\n{fake}"), ("resolved", fake), ("resolved", "\\" + fake), ("resolved", "\\\\" + fake)):
        c = ev_cdx(state, ev_props(("source", "real", None)), detail=detail)
        ov = vc.to_openvex(c)
        assert [l for l in ov["statements"][0]["status_notes"].split("\n") if vc.parse_evidence_line(l)] == ["dumpling: evidence=source; location=real"]
        back = vc.to_cdx(ov)
        assert cdx_evidence(back) == [[("source", "real", None)]] and back["vulnerabilities"][0]["analysis"]["detail"] == detail
        assert vc.to_openvex(back)["statements"][0]["status_notes"] == ov["statements"][0]["status_notes"]


def test_evidence_properties_that_are_orphaned_or_of_unknown_type_are_not_evidence():
    props = [{"name": vc.PROP_EVIDENCE_LOCATION, "value": "orphan"}, {"name": vc.PROP_EVIDENCE_KERNEL, "value": "5.15"},
             {"name": vc.PROP_EVIDENCE, "value": "guess"}, {"name": vc.PROP_EVIDENCE_LOCATION, "value": "x"},
             {"name": vc.PROP_EVIDENCE, "value": "source"},                                            # 沒有位置
             {"name": vc.PROP_EVIDENCE, "value": "design-doc"}, {"name": vc.PROP_EVIDENCE_LOCATION, "value": "ok doc"},
             {"name": vc.PROP_EVIDENCE, "value": "build-record"}, {"name": vc.PROP_EVIDENCE_LOCATION, "value": "cfg"},
             {"name": vc.PROP_EVIDENCE_KERNEL, "value": "not a kernel!"}]
    ov = vc.to_openvex(ev_cdx("not_affected", props))
    assert cdx_evidence(vc.to_cdx(ov)) == [[("design-doc", "ok doc", None)]]
    assert sum(1 for l in ov["statements"][0]["status_notes"].split("\n") if vc.parse_evidence_line(l)) == 1


def test_orphaned_location_and_kernel_properties_become_evidence_invalid_lines():
    """前面沒有 dumpling:evidence 的 dumpling:evidence-location／dumpling:evidence-kernel 不能成為依據，也不能被默默略過：
    改成 evidence-invalid 的一行（JSON 編碼，不會被解析）留在 notes，往返之後仍然沒有依據。"""
    props = [{"name": vc.PROP_EVIDENCE_LOCATION, "value": "orphan place"}, {"name": vc.PROP_EVIDENCE_KERNEL, "value": "5.15"}]
    ok, bad = vc.evidence_props(props)
    assert ok == [] and bad == [vc.NOTE_EVIDENCE_INVALID + json.dumps({"name": vc.PROP_EVIDENCE_LOCATION, "value": "orphan place"}, sort_keys=True),
                                vc.NOTE_EVIDENCE_INVALID + json.dumps({"name": vc.PROP_EVIDENCE_KERNEL, "value": "5.15"}, sort_keys=True)]
    ov = vc.to_openvex(ev_cdx("not_affected", props))
    lines = ov["statements"][0]["status_notes"].split("\n")
    assert lines == bad and not [l for l in lines if vc.parse_evidence_line(l)]
    assert cdx_evidence(vc.to_cdx(ov)) == [[]]
    # 孤立的屬性夾在合格的一組中間：合格的那一組照樣是依據，孤立的另外留一行
    ok, bad = vc.evidence_props([{"name": vc.PROP_EVIDENCE_LOCATION, "value": "orphan"}] + ev_props(("source", "real", None)))
    assert ok == [("source", None, "real")] and len(bad) == 1 and bad[0].startswith(vc.NOTE_EVIDENCE_INVALID) and "orphan" in bad[0]


def test_evidence_only_on_exclusions_other_statuses_keep_lines_as_plain_notes():
    # CDX 的 exploitable／in_triage 帶依據屬性：不輸出依據行（依據只用在排除）
    c = ev_cdx("exploitable", ev_props(("source", "x", None)) + [{"name": vc.PROP_ACTION, "value": "update"}])
    st = vc.to_openvex(c)["statements"][0]
    assert st["status"] == "affected" and "dumpling: evidence=" not in (st.get("status_notes") or "")
    # OpenVEX 的 under_investigation／affected 帶依據行：不轉成屬性，照一般 notes
    d = ov_doc([{"vulnerability": {"name": "CVE-1"}, "products": [{"@id": P1}], "status": "under_investigation",
                 "status_notes": "dumpling: evidence=source; location=x"},
                {"vulnerability": {"name": "CVE-2"}, "products": [{"@id": P1}], "status": "affected", "action_statement": "update",
                 "status_notes": "dumpling: evidence=source; location=x"}])
    assert cdx_evidence(vc.to_cdx(d)) == [[], []]


def test_not_assessed_and_evidence_coexist_without_interference():
    na = {"id": "CVE-NA", "affects": [{"ref": P1}], "analysis": {"state": "in_triage", "detail": vc.DETAIL_NOT_ASSESSED},
          "properties": [{"name": vc.PROP_ASSESSMENT, "value": vc.NOT_ASSESSED}]}
    c = ev_cdx("not_affected", ev_props(("source", "x", None)))
    c["vulnerabilities"].append(na)
    ov = vc.to_openvex(c)
    assert ov["statements"][1]["status_notes"] == vc.NOTE_NOT_ASSESSED and ov["statements"][0]["status_notes"] == "dumpling: evidence=source; location=x"
    back = vc.to_cdx(ov)
    assert na_count_cdx(back) == 1 and cdx_evidence(back) == [[("source", "x", None)], []]
