"""csaf_advisory.py：兩版 VEX 比對 → CSAF 2.0 修補公告（輸入是程式產生的小型 vex.cdx.json；輸出用 OASIS CSAF 2.0 schema 驗證）。"""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import csaf_advisory as ca  # noqa: E402

NOW = "2026-11-03T00:00:00Z"
DEB = "pkg:deb/ubuntu/{}@{}?arch=arm64&distro=ubuntu-24.04"
CFG = {"manufacturer": {"name": "Acme Boards Ltd.", "website": "https://acme-boards.test", "email": "security@acme-boards.test"},
       "csaf": {"tracking_id_prefix": "ACME-SA-", "advisory_url_base": "https://acme-boards.test/security/advisories"}}


def stmt(vid, comp, ver, state, response=None):
    a = {"state": state, "detail": f"{state} detail"}
    if response:
        a["response"] = response
    return {"bom-ref": f"vex-{vid}-{comp}", "id": vid, "analysis": a, "affects": [{"ref": "x"}],
            "properties": [{"name": "sca-center:component", "value": f"{comp} {ver}"},
                           {"name": "sca-center:component-purl", "value": DEB.format(comp, ver)}]}


def vex(version, stmts):
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": "urn:uuid:1", "version": 1,
            "metadata": {"component": {"type": "firmware", "bom-ref": "product", "name": "ACME-X100", "version": version},
                         "properties": [{"name": "sca-center:product-sbom-serial", "value": f"urn:uuid:sbom-{version}"}]},
            "vulnerabilities": stmts}


GATE_OK = {"grype_only_advisories": 0, "grype_cross_check": True, "not_assessed": []}


def pair(d):
    """summary.json 記下這次的 vex.cdx.json、sbom.cdx.json 的 sha256（cra_report 產生時就是這樣）；測試改了檔案後要再叫一次。"""
    sha = lambda f: hashlib.sha256((d / f).read_bytes()).hexdigest() if (d / f).exists() else None   # noqa: E731
    s = json.loads((d / "summary.json").read_text(encoding="utf-8"))
    s.setdefault("vex", {})["files"] = {"vex.cdx.json": {"file": "vex.cdx.json", "sha256": sha("vex.cdx.json")}}
    if sha("sbom.cdx.json"):
        s["product_sbom"] = {"file": "sbom.cdx.json", "sha256": sha("sbom.cdx.json")}
    (d / "summary.json").write_text(json.dumps(s), encoding="utf-8")


def reports(d, version, stmts, untriaged=0, sbom_comps=None, sbom_status="OK", verdict="ATTENTION", serial=None, gate=None):
    d.mkdir(parents=True)
    (d / "vex.cdx.json").write_text(json.dumps(vex(version, stmts)), encoding="utf-8")
    g = {"verdict": verdict, "assessment": {"untriaged_for_gate": untriaged}, **GATE_OK, **(gate or {})}
    (d / "summary.json").write_text(json.dumps({"documents": {"sbom": {"status": sbom_status}}, "vex": {"gate": g}}), encoding="utf-8")
    if sbom_comps is not None:
        (d / "sbom.cdx.json").write_text(json.dumps({"bomFormat": "CycloneDX", "serialNumber": serial or f"urn:uuid:sbom-{version}", "components": [
            {"type": "library", "name": c, "version": v, "purl": DEB.format(c, v)} for c, v in sbom_comps]}), encoding="utf-8")
    pair(d)
    return d


OLD = [stmt("CVE-2026-0001", "openssl", "3.0.13-1", "exploitable", ["update"]),      # → 新版 resolved：fixed
       stmt("CVE-2026-0002", "libfoo", "1.0", "in_triage"),                           # → 新版 exploitable：still
       stmt("CVE-2026-0003", "libgone", "2.0", "exploitable"),                        # → 新版 SBOM 沒有這個元件：fixed（removed）
       stmt("CVE-2026-0004", "libbar", "1.0", "exploitable"),                         # → 新版沒判定、元件還在：not_stated
       stmt("CVE-2026-0005", "libbaz", "1.0", "not_affected")]                        # → 新版 resolved：changed
NEW = [stmt("CVE-2026-0001", "openssl", "3.0.13-2", "resolved"),
       stmt("CVE-2026-0002", "libfoo", "1.1", "exploitable", ["update"]),
       stmt("CVE-2026-0005", "libbaz", "1.1", "resolved"),
       stmt("GHSA-aaaa-bbbb-cccc", "tool", "0.2", "exploitable"),                     # 新增，沒有 CVE
       stmt("CVE-2026-0006", "libnew", "1.0", "not_affected")]                        # 只有 not_affected：不放進公告
SBOM_NEW = [("openssl", "3.0.13-2"), ("libfoo", "1.1"), ("libbar", "1.1"), ("libbaz", "1.1"), ("tool", "0.2"), ("libnew", "1.0")]

SCHEMA_DIR = HERE.parent / "data" / "csaf-2.0"


def csaf_validator():
    """OASIS CSAF 2.0 JSON schema 與它引用的 FIRST CVSS schema（tools/cra/data/csaf-2.0，來源、SHA-256 與授權見 NOTICE.md）。"""
    jsonschema = pytest.importorskip("jsonschema")
    referencing = pytest.importorskip("referencing")
    rs = []
    for n, uri in (("cvss-v2.0.json", "https://www.first.org/cvss/cvss-v2.0.json"), ("cvss-v3.0.json", "https://www.first.org/cvss/cvss-v3.0.json"),
                   ("cvss-v3.1.json", "https://www.first.org/cvss/cvss-v3.1.json")):
        doc = json.loads((SCHEMA_DIR / n).read_text(encoding="utf-8"))
        spec = referencing.jsonschema.specification_with(doc.get("$schema", ""), default=referencing.jsonschema.DRAFT7)
        rs.append((uri, referencing.Resource.from_contents(doc, default_specification=spec)))
    main = json.loads((SCHEMA_DIR / "csaf_json_schema.json").read_text(encoding="utf-8"))
    reg = referencing.Registry().with_resources(rs)
    return jsonschema.Draft202012Validator(main, registry=reg, format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER)


def gen(tmp_path, cfg=CFG, old=OLD, new=NEW, sbom=SBOM_NEW, untriaged=3, **kw):
    o = reports(tmp_path / "old", "1.0.0", old)
    n = reports(tmp_path / "new", "1.1.0", new, untriaged, sbom, **kw)
    out = tmp_path / "out"
    st, detail, summ = ca.run(o, n, cfg, out, NOW)
    return st, detail, summ, out


def test_categories_and_schema(tmp_path):
    st, detail, summ, out = gen(tmp_path)
    cat = {r["id"]: r["category"] for r in summ["rows"]}
    assert cat == {"CVE-2026-0001": "fixed", "CVE-2026-0002": "still", "CVE-2026-0003": "fixed", "CVE-2026-0004": "not_stated",
                   "CVE-2026-0005": "changed", "GHSA-aaaa-bbbb-cccc": "new"}
    assert summ["counts"] == {"fixed": 2, "new": 1, "still": 1, "reassessed": 0, "changed": 1, "not_stated": 1}
    assert st == "ATTENTION"          # not_stated 與未評估的列
    doc = json.loads((out / "csaf.json").read_text(encoding="utf-8"))
    errs = sorted(csaf_validator().iter_errors(doc), key=lambda e: list(e.path))
    assert not errs, [f"{list(e.path)}: {e.message[:200]}" for e in errs[:5]]
    t = doc["document"]
    assert t["category"] == "csaf_security_advisory" and t["tracking"]["status"] == "draft" and t["tracking"]["id"] == "ACME-SA-ACME-X100-1.1.0"
    assert t["publisher"] == {"category": "vendor", "name": "Acme Boards Ltd.", "namespace": "https://acme-boards.test", "contact_details": "security@acme-boards.test"}
    v = {x.get("cve") or x["ids"][0]["text"]: x for x in doc["vulnerabilities"]}
    assert "CVE-2026-0006" not in v and v["GHSA-aaaa-bbbb-cccc"]["ids"] == [{"system_name": "GHSA", "text": "GHSA-aaaa-bbbb-cccc"}]
    rel = {r["full_product_name"]["product_id"]: r for r in doc["product_tree"]["relationships"]}
    fx = v["CVE-2026-0001"]
    assert {rel[p]["relates_to_product_reference"] for p in fx["product_status"]["fixed"]} == {"CSAFPID-NEW"}
    assert {rel[p]["relates_to_product_reference"] for p in fx["product_status"]["known_affected"]} == {"CSAFPID-OLD"}
    assert fx["remediations"][0]["category"] == "vendor_fix"
    assert v["CVE-2026-0002"]["remediations"][0]["category"] == "none_available" and "insufficient data" in v["CVE-2026-0002"]["remediations"][0]["details"]    # update response 但修補狀態不是 fixed：不寫「有修補」
    assert "3 in ACME-X100 1.1.0" in t["notes"][1]["text"]
    md = (out / "advisory.md").read_text(encoding="utf-8")
    assert "## Not assessed in the new version (not counted as fixed) (1)" in md and "libgone 2.0 (no longer included)" in md
    # 舊版元件用舊版的 purl，新版用新版的
    fpn = {p["product_id"]: p for p in doc["product_tree"]["full_product_names"]}
    old_ids = [rel[p]["product_reference"] for p in fx["product_status"]["known_affected"]]
    assert fpn[old_ids[0]]["product_identification_helper"]["purl"] == DEB.format("openssl", "3.0.13-1")


def test_missing_vex_fails_without_output(tmp_path):
    o = reports(tmp_path / "old", "1.0.0", OLD)
    n = tmp_path / "new"
    n.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    (out / "csaf.json").write_text("stale", encoding="utf-8")
    st, detail, summ = ca.run(o, n, CFG, out, NOW)
    assert st == "FAIL" and "沒有產生公告" in detail and not any((out / x).exists() for x in ca.OUTPUTS)
    (n / "vex.cdx.json").write_text(json.dumps({"bomFormat": "CycloneDX"}), encoding="utf-8")
    assert ca.run(o, n, CFG, out, NOW)[0] == "FAIL"


def test_no_changes_still_produced(tmp_path):
    same = [stmt("CVE-2026-0005", "libbaz", "1.0", "not_affected")]
    st, detail, summ, out = gen(tmp_path, old=same, new=same, sbom=[("libbaz", "1.0")], untriaged=0)
    doc = json.loads((out / "csaf.json").read_text(encoding="utf-8"))
    assert st == "OK" and "No changes" in doc["document"]["notes"][0]["text"] and "vulnerabilities" not in doc
    assert doc["document"]["category"] == "csaf_base"      # security advisory 的設定檔要求 vulnerabilities
    assert not list(csaf_validator().iter_errors(doc))


def test_company_fields_to_be_completed(tmp_path):
    st, detail, summ, out = gen(tmp_path, cfg={"manufacturer": {"name": "Acme Boards Ltd."}}, untriaged=0)
    doc = json.loads((out / "csaf.json").read_text(encoding="utf-8"))
    assert set(summ["missing_fields"]) == {"csaf.publisher_namespace", "csaf.tracking_id_prefix", "csaf.advisory_url_base"}
    assert doc["document"]["publisher"]["namespace"] == ca.TBC_URI and doc["document"]["tracking"]["id"].startswith("TBC-")
    assert "TO BE COMPLETED" in (out / "advisory.md").read_text(encoding="utf-8") and st == "ATTENTION"
    assert not list(csaf_validator().iter_errors(doc))


def test_without_new_sbom_absent_is_not_fixed(tmp_path):
    st, detail, summ, out = gen(tmp_path, sbom=None)
    cat = {r["id"]: r["category"] for r in summ["rows"]}
    assert cat["CVE-2026-0003"] == "not_stated" and cat["CVE-2026-0004"] == "not_stated"


def test_rerun_same_output(tmp_path):
    gen(tmp_path)
    a = {n: (tmp_path / "out" / n).read_text(encoding="utf-8") for n in ca.OUTPUTS}
    ca.run(tmp_path / "old", tmp_path / "new", CFG, tmp_path / "out", NOW)
    assert {n: (tmp_path / "out" / n).read_text(encoding="utf-8") for n in ca.OUTPUTS} == a


def test_cli(tmp_path):
    reports(tmp_path / "old", "1.0.0", OLD)
    reports(tmp_path / "new", "1.1.0", NEW, 0, SBOM_NEW)
    (tmp_path / "c.json").write_text(json.dumps(CFG), encoding="utf-8")
    r = subprocess.run([sys.executable, "-I", str(HERE.parent / "csaf_advisory.py"), "--old", str(tmp_path / "old"), "--new", str(tmp_path / "new"),
                        "--config", str(tmp_path / "c.json"), "--out", str(tmp_path / "out")], capture_output=True, text=True)
    assert r.returncode == 2 and r.stdout.startswith("CSAF\tATTENTION") and (tmp_path / "out" / "csaf.json").exists()
    r = subprocess.run([sys.executable, "-I", str(HERE.parent / "csaf_advisory.py"), "--old", "nope", "--new", "x", "--config", "y", "--out", "z"],
                       capture_output=True, text=True)
    assert r.returncode == 64


def cats(summ):
    return {(r["id"], r["component"]): r["category"] for r in summ["rows"]}


def test_empty_sbom_does_not_mean_removed(tmp_path):
    st, detail, summ, out = gen(tmp_path, sbom=[])
    assert cats(summ)[("CVE-2026-0003", "libgone 2.0")] == "not_stated" and st == "ATTENTION"
    assert any("no usable SBOM" in n for n in summ["notes"])


def test_reassessed_is_not_a_fix(tmp_path):
    old = [stmt("CVE-2026-0001", "openssl", "3.0.13-1", "exploitable")]
    new = [stmt("CVE-2026-0001", "openssl", "3.0.13-1", "not_affected")]
    st, detail, summ, out = gen(tmp_path, old=old, new=new, sbom=[("openssl", "3.0.13-1")], untriaged=0)
    assert summ["counts"]["reassessed"] == 1 and summ["counts"]["fixed"] == 0
    doc = json.loads((out / "csaf.json").read_text(encoding="utf-8"))
    v = doc["vulnerabilities"][0]
    assert "remediations" not in v and v["threats"][0]["category"] == "impact" and "not_affected detail" in v["threats"][0]["details"]
    assert not list(csaf_validator().iter_errors(doc))


def test_old_version_still_in_sbom_not_fixed(tmp_path):
    old = [stmt("CVE-2026-0001", "libx", "1", "exploitable")]
    new = [stmt("CVE-2026-0001", "libx", "2", "resolved")]
    _, _, summ, _ = gen(tmp_path, old=old, new=new, sbom=[("libx", "1"), ("libx", "2")], untriaged=0)
    assert summ["counts"]["fixed"] == 0 and summ["counts"]["not_stated"] == 1
    _, _, summ2, _ = gen(tmp_path / "b", old=old, new=new, sbom=[("libx", "2")], untriaged=0)
    assert summ2["counts"]["fixed"] == 1


def test_local_vex_component_not_called_removed(tmp_path):
    o = vex("1.0.0", [stmt("CVE-2026-0007", "srcpkg", "1.0", "exploitable")])
    o["vulnerabilities"][0]["affects"] = [{"ref": "vex-component-abc"}]
    o["components"] = [{"type": "library", "bom-ref": "vex-component-abc", "name": "srcpkg"}]
    od = tmp_path / "old"
    od.mkdir()
    (od / "vex.cdx.json").write_text(json.dumps(o), encoding="utf-8")
    nd = reports(tmp_path / "new", "1.1.0", [], 0, [("other", "1")])
    _, _, summ = ca.run(od, nd, CFG, tmp_path / "out", NOW)
    assert summ["counts"]["not_stated"] == 1 and summ["counts"]["fixed"] == 0


def test_missing_summary_and_bad_statements_attention(tmp_path):
    o = reports(tmp_path / "old", "1.0.0", OLD[:1])
    n = tmp_path / "new"
    n.mkdir()
    bad = vex("1.1.0", [stmt("CVE-2026-0001", "openssl", "3.0.13-1", "exploitable"), dict(stmt("CVE-2026-9", "x", "1", "EXPLOITABLE")),
                        {"id": "", "analysis": {"state": "exploitable"}}, "junk"])
    bad["vulnerabilities"][1]["analysis"]["state"] = "EXPLOITABLE"
    (n / "vex.cdx.json").write_text(json.dumps(bad), encoding="utf-8")
    st, detail, summ = ca.run(o, n, CFG, tmp_path / "out", NOW)
    assert st == "ATTENTION" and summ["untriaged_in_new"] is None
    assert summ["ignored"]["new"] == {"not_an_object": 1, "no_id": 1, "unknown_state": 1}
    assert any("unknown" in x for x in summ["notes"])


def test_remediation_categories_and_two_components(tmp_path):
    old = [stmt("CVE-2026-0001", "liba", "1", "exploitable"), stmt("CVE-2026-0001", "libb", "1", "exploitable")]
    new = [stmt("CVE-2026-0001", "liba", "1", "exploitable", ["workaround_available"]),
           stmt("CVE-2026-0001", "libb", "1", "exploitable", ["will_not_fix"]), stmt("CVE-2026-0002", "libc", "1", "in_triage")]
    _, _, summ, out = gen(tmp_path, old=old, new=new, sbom=[("liba", "1"), ("libb", "1"), ("libc", "1")], untriaged=0)
    doc = json.loads((out / "csaf.json").read_text(encoding="utf-8"))
    v = {x["cve"]: x for x in doc["vulnerabilities"]}
    assert len(doc["vulnerabilities"]) == 2                        # 同一個 CVE 只有一個項目（CSAF 6.1.23）
    assert sorted(r["category"] for r in v["CVE-2026-0001"]["remediations"]) == ["none_available", "workaround"]
    assert "remediations" not in v["CVE-2026-0002"]                # 調查中不寫「沒有修補」
    assert not list(csaf_validator().iter_errors(doc))


def test_legacy_can_not_fix_with_unknown_fix_state_is_not_cannot_fix(tmp_path):
    """舊設定檔的 can_not_fix／will_not_fix，修補狀態不明（空的、unknown、no Grype data）時，與沒有 response 的列同一句（資料不足、評估中），
    不寫「供應商不能修／不修」。"""
    for resp in ("can_not_fix", "will_not_fix"):
        old = [stmt("CVE-2026-0001", "liba", "1", "exploitable")]
        new = [stmt("CVE-2026-0001", "liba", "1", "exploitable", [resp])]
        _, _, _, out = gen(tmp_path / resp, old=old, new=new, sbom=[("liba", "1")], untriaged=0)
        doc = json.loads((out / "csaf.json").read_text(encoding="utf-8"))
        rem = doc["vulnerabilities"][0]["remediations"]
        assert [r["category"] for r in rem] == ["none_available"]
        assert "insufficient data; under assessment" in rem[0]["details"]
        text = json.dumps(doc) + (out / "advisory.md").read_text(encoding="utf-8")
        assert "supplier cannot fix" not in text and "supplier will not fix" not in text


def test_component_name_without_version():
    assert ca.comp_name("Linux kernel") == "Linux kernel" and ca.comp_name("openssl 3.0.13-1") == "openssl"


def test_incomplete_new_sbom_or_other_serial_no_removal(tmp_path):
    for i, kw in enumerate(({"sbom_status": "GAP"}, {"serial": "urn:uuid:other"})):
        st, _, summ, _ = gen(tmp_path / str(i), **kw)
        assert cats(summ)[("CVE-2026-0003", "libgone 2.0")] == "not_stated" and st == "ATTENTION"
        assert any("not treated as removed" in n for n in summ["notes"])


def test_gate_not_assessed_is_not_no_changes(tmp_path):
    same = [stmt("CVE-2026-0005", "libbaz", "1.0", "not_affected")]
    st, _, summ, out = gen(tmp_path, old=same, new=same, sbom=[("libbaz", "1.0")], untriaged=0, verdict="NOT_ASSESSED")
    doc = json.loads((out / "csaf.json").read_text(encoding="utf-8"))
    assert st == "ATTENTION" and "does not mean that nothing changed" in doc["document"]["notes"][0]["text"]
    assert not list(csaf_validator().iter_errors(doc))


def test_renamed_package_not_removed(tmp_path):
    old = [stmt("CVE-2026-0008", "python-dateutil", "2.8", "exploitable")]
    _, _, summ, _ = gen(tmp_path, old=old, new=[], sbom=[("python_dateutil", "2.8")], untriaged=0)
    assert summ["counts"]["fixed"] == 0 and summ["counts"]["not_stated"] == 1


def test_removed_marks_new_product_fixed(tmp_path):
    """元件移除、新版沒有未評估的列 → 新產品本身列 fixed；有未評估的列（或數量不明）→ 不列，漏洞的 notes 寫原因。"""
    for untriaged, listed in ((0, True), (5, False), (None, False)):
        _, _, _, out = gen(tmp_path / str(untriaged), untriaged=untriaged)
        doc = json.loads((out / "csaf.json").read_text(encoding="utf-8"))
        v = next(x for x in doc["vulnerabilities"] if x.get("cve") == "CVE-2026-0003")
        assert ("CSAFPID-NEW" in v["product_status"].get("fixed", [])) is listed, untriaged
        assert ("is not listed as fixed" in v["notes"][0]["text"]) is not listed
        assert not list(csaf_validator().iter_errors(doc))


def test_untriaged_removed_only_component(tmp_path):
    """留言板的重現：舊版 libgone exploitable、新版 SBOM 只有 libother、untriaged=5 → 新產品不列 fixed。"""
    old = [stmt("CVE-2026-0200", "libgone", "1.0", "exploitable")]
    _, _, _, out = gen(tmp_path, old=old, new=[], sbom=[("libother", "1.0")], untriaged=5)
    v = json.loads((out / "csaf.json").read_text(encoding="utf-8"))["vulnerabilities"][0]
    assert "CSAFPID-NEW" not in v["product_status"].get("fixed", [])


def test_resolved_old_version_gone_needs_usable_sbom(tmp_path):
    """新版 resolved（新版本）＋舊版本不在新 SBOM：SBOM 是 GAP 或序號不同時不能當證據 → not_stated、沒有 vendor_fix。"""
    for i, kw in enumerate(({}, {"sbom_status": "GAP"}, {"serial": "urn:uuid:other"})):
        _, _, summ, out = gen(tmp_path / str(i), **kw)
        c = cats(summ)[("CVE-2026-0001", "openssl 3.0.13-2")]
        doc = json.loads((out / "csaf.json").read_text(encoding="utf-8"))
        v = next(x for x in doc["vulnerabilities"] if x.get("cve") == "CVE-2026-0001")
        assert c == ("fixed" if i == 0 else "not_stated"), kw
        assert any(r["category"] == "vendor_fix" for r in v.get("remediations", [])) is (i == 0)


def test_incomplete_data_noted_in_csaf(tmp_path):
    """新版閘門不是 OK／ATTENTION 而且有差異：csaf.json 的 document.notes 寫明資料不完整（不只在 advisory.md）。"""
    for verdict, noted in (("ATTENTION", False), ("GAP", True)):
        _, _, _, out = gen(tmp_path / verdict, verdict=verdict)
        doc = json.loads((out / "csaf.json").read_text(encoding="utf-8"))
        assert any(n["title"] == "Incomplete vulnerability data" for n in doc["document"]["notes"]) is noted
        assert not list(csaf_validator().iter_errors(doc))


def test_two_old_versions_both_checked(tmp_path):
    """舊版 foo 1.0、1.1 都 exploitable（合成一筆）、新版 foo 2.0 resolved：1.1 還在新 SBOM → not_stated；兩個都不在 → fixed。"""
    old = [stmt("CVE-2026-0300", "foo", "1.0", "exploitable"), stmt("CVE-2026-0300", "foo", "1.1", "exploitable")]
    new = [stmt("CVE-2026-0300", "foo", "2.0", "resolved")]
    for sbom, want in (([("foo", "2.0"), ("foo", "1.1")], "not_stated"), ([("foo", "2.0")], "fixed")):
        _, _, summ, _ = gen(tmp_path / want, old=old, new=new, sbom=sbom, untriaged=0)
        assert [r["category"] for r in summ["rows"]] == [want]


def test_unhashable_values_do_not_crash(tmp_path):
    """state、affects 的 ref、components 的 bom-ref 是 list：略過（ignored），不 TypeError。"""
    bad = stmt("CVE-2026-0400", "libx", "1.0", "exploitable")
    bad["analysis"]["state"] = ["exploitable"]
    odd = stmt("CVE-2026-0401", "liby", "1.0", "exploitable")
    odd["affects"] = [{"ref": ["x"]}]
    o = reports(tmp_path / "old", "1.0.0", [bad, odd])
    v = json.loads((o / "vex.cdx.json").read_text(encoding="utf-8"))
    v["components"] = [{"bom-ref": ["x"]}, "nope"]
    (o / "vex.cdx.json").write_text(json.dumps(v), encoding="utf-8")
    pair(o)
    n = reports(tmp_path / "new", "1.1.0", [], 0, [("liby", "1.0")])
    st, _, summ = ca.run(o, n, CFG, tmp_path / "out", NOW)
    assert summ["ignored"]["old"] == {"unknown_state": 1} and st == "ATTENTION"


def test_namespace_with_space_is_missing(tmp_path):
    cfg = dict(CFG, csaf=dict(CFG["csaf"], publisher_namespace="https://a.com/x y"))
    _, _, summ, _ = gen(tmp_path, cfg=cfg)
    assert "csaf.publisher_namespace" in summ["missing_fields"]


@pytest.mark.parametrize("other_new", ["exploitable", "in_triage", None])
def test_removed_and_still_same_cve(tmp_path, other_new):
    """同一個 CVE：liba 從新版移除、libb 在新版還受影響（或沒有判定）→ 新產品本身不算已修，只有 liba 的舊版關係列 fixed。"""
    old = [stmt("CVE-2026-0100", "liba", "1.0", "exploitable"), stmt("CVE-2026-0100", "libb", "1.0", "exploitable")]
    new = [stmt("CVE-2026-0100", "libb", "1.1", other_new)] if other_new else []
    _, _, summ, out = gen(tmp_path, old=old, new=new, sbom=[("libb", "1.1")], untriaged=0)
    doc = json.loads((out / "csaf.json").read_text(encoding="utf-8"))
    v = doc["vulnerabilities"][0]
    assert "CSAFPID-NEW" not in v["product_status"].get("fixed", [])
    assert cats(summ)[("CVE-2026-0100", "liba 1.0")] == "fixed"
    assert not list(csaf_validator().iter_errors(doc))


def test_no_serial_numbers_no_removal(tmp_path):
    """新版 VEX 沒有 product-sbom-serial、SBOM 也沒有 serialNumber：不能確認是同一份 SBOM（None == None 不算相同）。"""
    o = reports(tmp_path / "old", "1.0.0", OLD)
    n = reports(tmp_path / "new", "1.1.0", NEW, 3, SBOM_NEW)
    for f, drop in (("vex.cdx.json", lambda d: d["metadata"].pop("properties")), ("sbom.cdx.json", lambda d: d.pop("serialNumber"))):
        d = json.loads((n / f).read_text(encoding="utf-8"))
        drop(d)
        (n / f).write_text(json.dumps(d), encoding="utf-8")
        pair(n)
    st, _, summ = ca.run(o, n, CFG, tmp_path / "out", NOW)
    assert cats(summ)[("CVE-2026-0003", "libgone 2.0")] == "not_stated" and st == "ATTENTION"
    assert any("no serial number" in x for x in summ["notes"])


def test_example_config_values_and_fp_noise(tmp_path):
    cfg = {"manufacturer": {"name": "Example Co.", "website": "https://www.example.com"}, "csaf": {"tracking_id_prefix": "X-"}}
    old = [stmt("CVE-2026-0005", "libbaz", "1.0", "not_affected")]
    new = [stmt("CVE-2026-0005", "libbaz", "1.0", "false_positive")]
    _, _, summ, _ = gen(tmp_path, cfg=cfg, old=old, new=new, sbom=[("libbaz", "1.0")], untriaged=0)
    assert {"csaf.publisher_name", "csaf.publisher_namespace"} <= set(summ["missing_fields"]) and summ["rows"] == []


def test_out_is_a_file_fails(tmp_path):
    o = reports(tmp_path / "old", "1.0.0", OLD)
    n = reports(tmp_path / "new", "1.1.0", NEW, 0, SBOM_NEW)
    f = tmp_path / "file"
    f.write_text("x", encoding="utf-8")
    st, detail, summ = ca.run(o, n, CFG, f, NOW)
    assert st == "FAIL" and summ is None


@pytest.mark.parametrize("verdict, listed", [("ATTENTION", True), ("OK", True), ("NOT_ASSESSED", False), ("GAP", False), ("FAIL", False)])
def test_product_fixed_needs_complete_data(tmp_path, verdict, listed):
    """untriaged=0 但閘門不是 OK／ATTENTION（例如沒有 DT findings）：產品層級不列 fixed，notes 寫原因。"""
    old = [stmt("CVE-2026-0500", "libgone", "1.0", "exploitable")]
    _, _, _, out = gen(tmp_path, old=old, new=[], sbom=[("libother", "1.0")], untriaged=0, verdict=verdict)
    doc = json.loads((out / "csaf.json").read_text(encoding="utf-8"))
    v = doc["vulnerabilities"][0]
    assert ("CSAFPID-NEW" in v["product_status"].get("fixed", [])) is listed
    assert ("vulnerability data" in v["notes"][0]["text"]) is not listed
    assert not list(csaf_validator().iter_errors(doc))


def test_skipped_new_statements_block_product_fixed(tmp_path):
    """新版 VEX 有讀不懂的陳述（state 大寫）：可能正是同一個漏洞 → 產品不列 fixed；csaf.json 的 Limitations 寫明。"""
    old = [stmt("CVE-2026-0501", "libgone", "1.0", "exploitable")]
    bad = stmt("CVE-2026-0501", "libother", "1.0", "exploitable")
    bad["analysis"]["state"] = "EXPLOITABLE"
    _, _, summ, out = gen(tmp_path, old=old, new=[bad], sbom=[("libother", "1.0")], untriaged=0)
    doc = json.loads((out / "csaf.json").read_text(encoding="utf-8"))
    v = doc["vulnerabilities"][0]
    assert "CSAFPID-NEW" not in v["product_status"].get("fixed", []) and "could not be read" in v["notes"][0]["text"]
    lim = [n for n in doc["document"]["notes"] if n["title"] == "Limitations"]
    assert lim and "1 statements in the new VEX could not be read" in lim[0]["text"]
    assert summ["ignored"]["new"] == {"unknown_state": 1}


def test_old_version_still_in_sbom_without_purl_or_encoded(tmp_path):
    """舊版 libx 1.0 exploitable → 新版 2.0 resolved：新 SBOM 還有沒有 purl 的 libx 1.0，或 purl 寫成 %2B → 不算已不在 SBOM。"""
    old = [stmt("CVE-2026-0502", "libx", "1.0+dfsg", "exploitable")]
    new = [stmt("CVE-2026-0502", "libx", "2.0", "resolved")]
    for i, extra in enumerate(({"type": "library", "name": "libx", "version": "1.0+dfsg"},
                               {"type": "library", "name": "renamed", "version": "9",
                                "purl": "pkg:deb/ubuntu/libx@1.0%2Bdfsg?arch=arm64"})):
        o = reports(tmp_path / str(i) / "old", "1.0.0", old)
        n = reports(tmp_path / str(i) / "new", "1.1.0", new, 0, [("libx", "2.0")])
        sb = json.loads((n / "sbom.cdx.json").read_text(encoding="utf-8"))
        sb["components"].append(extra)
        (n / "sbom.cdx.json").write_text(json.dumps(sb), encoding="utf-8")
        pair(n)
        st, _, summ = ca.run(o, n, CFG, tmp_path / str(i) / "out", NOW)
        assert [r["category"] for r in summ["rows"]] == ["not_stated"], extra
    # 兩者都沒有 → 已不在 SBOM → fixed（對照）
    _, _, summ, _ = gen(tmp_path / "ok", old=old, new=new, sbom=[("libx", "2.0")], untriaged=0)
    assert [r["category"] for r in summ["rows"]] == ["fixed"]


def test_property_name_not_string_and_namespace_uri():
    assert ca.props({"properties": [{"name": ["x"], "value": 1}, "nope", {"name": "a", "value": 2}]}) == {"a": 2}
    for u, ok in (("https://acme.test/csaf", True), ("https://[x", False), ("https://a.test/%zz", False), ("https://a.test:99999", False)):
        assert ca.uri_ok(u) is ok, u


@pytest.mark.parametrize("gate, why", [({"grype_only_advisories": 2}, "2 advisories found only by Grype"),
                                       ({"grype_cross_check": False}, "Grype cross-check was not done"),
                                       ({"not_assessed": ["CVE-1 on x"]}, "1 matches were not assessed"),
                                       ({"not_assessed": None}, "list of unassessed matches is unknown")])
def test_attention_gate_with_incomplete_candidates(tmp_path, gate, why):
    """閘門 ATTENTION、untriaged 0，但候選漏洞清單不完整（Grype 才有的公告、沒做交叉核對、沒評估的比對）→ 產品層級不列 fixed，寫原因。"""
    old = [stmt("CVE-2026-0600", "libgone", "1.0", "exploitable")]
    st, _, summ, out = gen(tmp_path, old=old, new=[], sbom=[("libother", "1.0")], untriaged=0, gate=gate)
    doc = json.loads((out / "csaf.json").read_text(encoding="utf-8"))
    v = doc["vulnerabilities"][0]
    assert "CSAFPID-NEW" not in v["product_status"].get("fixed", []) and why in v["notes"][0]["text"]
    assert any(why in n["text"] for n in doc["document"]["notes"] if n["title"] == "Incomplete vulnerability data")
    assert st == "ATTENTION" and any(why in n for n in summ["notes"])


def test_percent_encoded_purl_same_component(tmp_path):
    """舊版 VEX 寫 libstdc%2B%2B6、新版 SBOM 寫 libstdc++6（同版本還在）、新版沒有判定 → 不算移除（not_stated）。"""
    old = [stmt("CVE-2026-0601", "libstdc%2B%2B6", "14.2-1", "exploitable")]
    _, _, summ, out = gen(tmp_path, old=old, new=[], sbom=[("libstdc++6", "14.2-1")], untriaged=0)
    assert [(r["category"], r["removed"]) for r in summ["rows"]] == [("not_stated", False)]
    # 新版用 + 寫 exploitable：同一筆（still），不會同時是 fixed 與 new
    _, _, summ, _ = gen(tmp_path / "b", old=old, new=[stmt("CVE-2026-0601", "libstdc++6", "14.2-1", "exploitable")],
                        sbom=[("libstdc++6", "14.2-1")], untriaged=0)
    assert [r["category"] for r in summ["rows"]] == ["still"]


def test_lows_skipped_without_rows_bad_purl_and_versionless(tmp_path):
    # 略過的陳述、沒有差異列：csaf.json 仍有 Limitations
    bad = stmt("CVE-2026-0602", "x", "1", "exploitable")
    bad["analysis"]["state"] = "EXPLOITABLE"
    same = [stmt("CVE-2026-0603", "liby", "1.0", "not_affected")]
    _, _, _, out = gen(tmp_path / "a", old=same, new=same + [bad], sbom=[("liby", "1.0")], untriaged=0)
    doc = json.loads((out / "csaf.json").read_text(encoding="utf-8"))
    assert any(n["title"] == "Limitations" for n in doc["document"]["notes"]) and not list(csaf_validator().iter_errors(doc))
    # 不合 OASIS 樣式的 purl 不寫進 product_identification_helper
    odd = stmt("CVE-2026-0604", "z", "1", "exploitable")
    odd["properties"][1]["value"] = "pkg:generic@1.0"
    _, _, _, out = gen(tmp_path / "b", old=[odd], new=[odd], sbom=[("z", "1")], untriaged=0)
    doc = json.loads((out / "csaf.json").read_text(encoding="utf-8"))
    assert not list(csaf_validator().iter_errors(doc))
    # 新版 SBOM 有同名但沒有版本（也沒有 purl）的元件：不能說舊版本已不在
    o = reports(tmp_path / "c" / "old", "1.0.0", [stmt("CVE-2026-0605", "libw", "1.0", "exploitable")])
    n = reports(tmp_path / "c" / "new", "1.1.0", [stmt("CVE-2026-0605", "libw", "2.0", "resolved")], 0, [("libw", "2.0")])
    sb = json.loads((n / "sbom.cdx.json").read_text(encoding="utf-8"))
    sb["components"].append({"type": "library", "name": "libw"})
    (n / "sbom.cdx.json").write_text(json.dumps(sb), encoding="utf-8")
    pair(n)
    _, _, summ = ca.run(o, n, CFG, tmp_path / "c" / "out", NOW)
    assert [r["category"] for r in summ["rows"]] == ["not_stated"]


def test_version_order():
    assert ca.version_order("1.9", "1.10") == 1 and ca.version_order("1.10", "1.9") == -1
    assert ca.version_order("1.0", "1.0.1") == 1 and ca.version_order("1.0", "1.0") == 0
    assert ca.version_order("A", "1.0") is None and ca.version_order(None, "1.0") is None


@pytest.mark.parametrize("old, new, want", [
    ("1.0.0rc1", "1.0.0", 1), ("1.0.0", "1.0.0rc1", -1),            # 預發行在正式版之前
    ("2.0-rc1", "2.0-beta", -1), ("1.0.0", "1.0.0-beta", -1), ("1.0.0-alpha", "1.0.0-beta.2", 1),
    ("1.0rc1", "1.0.1", 1), ("1.0", "1.0.0rc1", -1),
    ("1.0.0", "1.0", 0), ("1.0", "1.0.0", 0), ("V1.0", "1.0", 0),  # 尾端補 0、開頭 v 視為相同
    ("2.3-4", "1:2.0-1", None), ("1:2.0", "2:1.0", None), ("1:2.0", "1:2.1", 1),   # epoch 不同 → 比不出來
    ("1.0a", "1.0b", None), ("1.0", "1.0+local", None),              # 沒有明確規則的字母段落
    ("1.0.0+5", "1.0.0+6", None), ("1.0.0+20", "1.0.0+3", None),      # build 中繼資料不排序
    ("1.0.0+5", "1.0.1+1", 1), ("1.0.1+9", "1.0.0", -1), ("1.0.0+5", "1.0.0+5", 0),
    ("1.0-1", "1.0.1", None),                                         # 段落相同但寫法不同 → 不當成同一版
    ("2.3-4", "2.3-5", 1), ("R35.4", "R35.5", 1),
])
def test_version_order_prerelease_epoch_trailing_zero(old, new, want):
    assert ca.version_order(old, new) == want


def test_product_name_ignores_case_space_dash():
    assert ca.name_key("ACME-X100 Pro") == ca.name_key("acme_x100  pro") != ca.name_key("ACME-X200 Pro")


def _edit(d, f, change):
    x = json.loads((d / f).read_text(encoding="utf-8"))
    change(x)
    (d / f).write_text(json.dumps(x), encoding="utf-8")
    pair(d)


@pytest.mark.parametrize("old_v, new_v, name, msg", [
    ("1.0.0", "1.1.0", "OTHER-PRODUCT", "不是同一個產品"),
    ("1.1.0", "1.1.0", None, "版本相同"),
    ("1.1.0", "V1.1", None, "版本相同"),
    ("1.0.0", "1.0.0rc1", None, "可能對調"),
    ("1.10.0", "1.9.0", None, "可能對調"),
])
def test_not_same_product_or_not_newer_fails(tmp_path, old_v, new_v, name, msg):
    out = tmp_path / "out"
    out.mkdir()
    (out / "csaf.json").write_text("{}", encoding="utf-8")         # 上一次的輸出要被刪掉
    o = reports(tmp_path / "old", old_v, OLD)
    n = reports(tmp_path / "new", new_v, NEW, 0, SBOM_NEW)
    if name:
        _edit(n, "vex.cdx.json", lambda x: x["metadata"]["component"].update(name=name))
    st, detail, summ = ca.run(o, n, CFG, out, NOW)
    assert st == "FAIL" and msg in detail and summ is None and not (out / "csaf.json").exists()


def test_version_order_unknown_is_attention(tmp_path):
    o = reports(tmp_path / "old", "A", OLD)
    n = reports(tmp_path / "new", "1.1.0", NEW, 0, SBOM_NEW)
    st, _, summ, = ca.run(o, n, CFG, tmp_path / "out", NOW)
    assert st == "ATTENTION" and any("cannot confirm that 1.1.0 is newer" in x for x in summ["notes"])


def test_summary_and_sbom_must_belong_to_the_vex(tmp_path):
    """summary.json 記的 vex.cdx.json sha256 不同（別次產生的）→ 不用它（閘門不明 → 不完整、不判斷移除）；
    sbom.cdx.json 和 summary 記的不同 → 不判斷移除。"""
    o = reports(tmp_path / "a" / "old", "1.0.0", OLD)
    n = reports(tmp_path / "a" / "new", "1.1.0", NEW, 0, SBOM_NEW)
    (n / "vex.cdx.json").write_text((n / "vex.cdx.json").read_text(encoding="utf-8") + " ", encoding="utf-8")   # 內容不變、sha 變
    st, _, summ = ca.run(o, n, CFG, tmp_path / "a" / "out", NOW)
    assert any("new summary.json belongs to another VEX file" in x for x in summ["notes"]) and st == "ATTENTION"
    assert cats(summ)[("CVE-2026-0003", "libgone 2.0")] == "not_stated"
    o = reports(tmp_path / "b" / "old", "1.0.0", OLD)
    n = reports(tmp_path / "b" / "new", "1.1.0", NEW, 0, SBOM_NEW)
    (n / "sbom.cdx.json").write_text((n / "sbom.cdx.json").read_text(encoding="utf-8") + " ", encoding="utf-8")
    st, _, summ = ca.run(o, n, CFG, tmp_path / "b" / "out", NOW)
    assert cats(summ)[("CVE-2026-0003", "libgone 2.0")] == "not_stated"
    assert any("not the one recorded in the new summary.json" in x for x in summ["notes"])


def test_end_to_end_with_cra_report_output(tmp_path):
    """cra_report.py 實際產生的兩版 CRA/Reports：summary.json 記的 sha256 對得上讀到的 vex.cdx.json、sbom.cdx.json（不會被當成別次的）。"""
    import shutil
    from test_cra_report import MIN_CFG, make_project, make_scan, run as cra_run
    dirs = []
    for v in ("1.0.0", "1.1.0"):
        proj = make_project(tmp_path / f"p{v}", dict(MIN_CFG, product={"name": "ACME-X100", "version": v}))
        r, s, rep = cra_run(proj, make_scan(tmp_path / f"s{v}"))
        assert r.returncode in (0, 2) and (rep / "vex.cdx.json").exists(), r.stdout + r.stderr
        keep = tmp_path / f"reports-{v}"
        shutil.copytree(rep, keep)
        dirs.append(keep)
    st, detail, summ = ca.run(dirs[0], dirs[1], CFG, tmp_path / "out", NOW)
    assert st != "FAIL", detail
    assert not any("summary.json" in x and ("another" in x or "not the one" in x or "does not record" in x) for x in summ["notes"]), summ["notes"]
    assert summ["new"]["verdict"] and summ["old"]["verdict"]          # 閘門有讀到（summary 沒被丟掉）
    assert summ["new"]["sbom_matches_summary"] is True and summ["new"]["sbom_sha256"]   # SBOM 也有配對成功


def test_references_tlp_and_contact_from_config(tmp_path):
    cfg = {"manufacturer": {"name": "Acme Boards Ltd.", "website": "https://acme-boards.test", "email": "info@acme-boards.test"},
           "csaf": {"tracking_id_prefix": "ACME-SA-", "advisory_url_base": "https://acme-boards.test/sa/", "tlp": "green",
                    "contact": "psirt@acme-boards.test"}}
    st, detail, summ, out = gen(tmp_path, cfg=cfg)
    doc = json.loads((out / "csaf.json").read_text(encoding="utf-8"))
    assert not list(csaf_validator().iter_errors(doc)) and "csaf.advisory_url_base" not in summ["missing_fields"]
    assert doc["document"]["references"] == [{"category": "self", "summary": "Canonical URL of this advisory (to be confirmed before publication)",
                                              "url": "https://acme-boards.test/sa/acme-sa-acme-x100-1.1.0.json"}]
    assert doc["document"]["distribution"] == {"tlp": {"label": "GREEN"}} and doc["document"]["publisher"]["contact_details"] == "psirt@acme-boards.test"


@pytest.mark.parametrize("base", [None, "", "http://acme-boards.test/sa", "https://www.example.com/x", "not a url"])
def test_bad_or_missing_url_base_is_to_be_completed(tmp_path, base):
    cfg = {"manufacturer": {"name": "Acme Boards Ltd.", "website": "https://acme-boards.test"}, "csaf": {"tracking_id_prefix": "X-", "tlp": "purple"}}
    if base is not None:
        cfg["csaf"]["advisory_url_base"] = base
    st, detail, summ, out = gen(tmp_path, cfg=cfg)
    doc = json.loads((out / "csaf.json").read_text(encoding="utf-8"))
    assert "csaf.advisory_url_base" in summ["missing_fields"] and st == "ATTENTION"
    assert doc["document"]["references"][0]["url"].startswith(ca.TBC_URI) and "distribution" not in doc["document"]      # 不認得的 TLP 不寫
    assert not list(csaf_validator().iter_errors(doc))


def test_resolve_reports_accepts_wizard_folder_and_rejects_others(tmp_path):
    reports(tmp_path / "wiz" / "cra-project" / "CRA" / "Reports", "1.0.0", OLD)
    assert ca.resolve_reports(tmp_path / "wiz") == tmp_path / "wiz" / "cra-project" / "CRA" / "Reports"
    assert ca.resolve_reports(tmp_path / "wiz" / "cra-project" / "CRA" / "Reports").name == "Reports"
    with pytest.raises(ca.InputError):
        ca.resolve_reports(tmp_path / "nothing")


# ---- dumpling：schema 驗證有沒有跑、內建的官方 schema、產生者名稱 ----
def test_bundled_schema_files_match_notice_and_load(monkeypatch):
    """tools/cra/data/csaf-2.0 的 4 個檔是官方原檔（SHA-256 和 NOTICE.md 的表一致），而且程式真的載得起來（CI 不會默默變成 NOT_RUN）。"""
    notice = (SCHEMA_DIR / "NOTICE.md").read_text(encoding="utf-8")
    for n in ("csaf_json_schema.json", "cvss-v2.0.json", "cvss-v3.0.json", "cvss-v3.1.json"):
        h = hashlib.sha256((SCHEMA_DIR / n).read_bytes()).hexdigest()
        assert f"| `{n}` |" in notice and f"`{h}`" in notice, n
    monkeypatch.setattr(ca, "_VALIDATOR", [])
    assert ca.schema_validator() is not None


def test_schema_not_run_is_recorded_not_passed(tmp_path, monkeypatch):
    monkeypatch.setattr(ca, "_VALIDATOR", [None])           # 沒有 jsonschema 的環境
    st, detail, summ, out = gen(tmp_path)
    assert summ["schema_validation"] == {"ran": False, "status": "NOT_RUN", "errors": []}
    assert any("full schema validation NOT_RUN" in n and "this is not a pass" in n for n in summ["notes"]) and st == "ATTENTION"
    assert summ["builtin_checks"]["ran"] is True


def test_schema_ran_is_ok_and_generator_is_dumpling(tmp_path):
    st, detail, summ, out = gen(tmp_path)
    assert summ["schema_validation"]["status"] == "OK" and summ["schema_validation"]["ran"] is True
    doc = json.loads((out / "csaf.json").read_text(encoding="utf-8"))
    tr = doc["document"]["tracking"]
    assert tr["status"] == "draft" and tr["generator"]["engine"]["name"] == "dumpling csaf_advisory.py"
    assert all("dumpling" in r["summary"] for r in tr["revision_history"])
    assert "sca-center csaf" not in json.dumps(doc)
