"""dt_writeback.py：VEX 寫回 DT、產品元件專案。全部是合成資料與假的 DT（模擬 DT 5.2 實測的行為：
VEX 的 affects.ref 只認 urn:cdx:<上傳 BOM 的 serialNumber>/<version>#<bom-ref>；workflow 回 COMPLETED 不代表分析被套用）。"""
import json
import sys
import uuid
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent.parent / "pilot" / "lib"))
import cra_report as cra  # noqa: E402
import dt_writeback as wb  # noqa: E402

SERIAL = "urn:uuid:11111111-1111-4111-8111-111111111111"
PSERIAL = "urn:uuid:22222222-2222-4222-8222-222222222222"
ROOT_UUID = "aaaaaaaa-0000-4000-8000-000000000001"


def comp(name, ver, purl=None, ref=None, **kw):
    c = {"type": "library", "bom-ref": ref or purl or f"{name}@{ver}", "name": name, "version": ver}
    if purl:
        c["purl"] = purl
    c.update(kw)
    return c


ROOTFS = [comp("openssl", "3.0.1", "pkg:deb/ubuntu/openssl@3.0.1?arch=arm64"),
          comp("zlib", "1.2.3", "pkg:deb/ubuntu/zlib@1.2.3?arch=arm64"),
          comp("curl", "7.0", "pkg:deb/ubuntu/curl@7.0?arch=arm64")]
EXTRAS = [comp("fw-blob", "2026-01-01", None, "sca-center:flash:fw", type="firmware",
               properties=[{"name": "sca-center:version-basis", "value": "file modification time (BSI ...)"}]),
          comp("edk-ssl", "3.4.1", "pkg:generic/edk-ssl@3.4.1", "uefi-source:ssl", cpe="cpe:2.3:a:x:y:3.4.1:*:*:*:*:*:*:*"),
          comp("tool.sh", None, "pkg:generic/tool.sh?checksum=sha256:00", "sca-center:own:tool.sh", type="application")]


def product_sbom():
    cs = []
    for c in ROOTFS:
        d = dict(c)
        d["bom-ref"] = c["bom-ref"] + "?package-id=x"
        cs.append(d)
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": "urn:uuid:99999999-9999-4999-8999-999999999999", "version": 1,
            "metadata": {"component": {"type": "firmware", "name": "P", "version": "1.0 (rootfs)"}}, "components": cs + [json.loads(json.dumps(e)) for e in EXTRAS]}


def vstmt(vid, comp_ref, state, source_ids, detail="why", just=None, extra_props=()):
    a = {"state": state, "detail": detail}
    if just:
        a["justification"] = just
    return {"bom-ref": f"vex-{vid}", "id": vid, "source": {"name": "NVD"}, "analysis": a,
            "affects": [{"ref": f"urn:cdx:99999999-9999-4999-8999-999999999999/1#{comp_ref}"}],
            "properties": [{"name": "sca-center:source-ids", "value": source_ids}, {"name": "sca-center:vex-rule", "value": "R1"},
                           {"name": "sca-center:vex-rule-author", "value": "tester"}, {"name": "sca-center:vex-source", "value": "rule"},
                           {"name": "sca-center:component", "value": "x"}] + list(extra_props)}


def finding(c_uuid, c, source, vid, aliases=(), analysis=None):
    return {"component": {"uuid": c_uuid, "name": c["name"], "version": c.get("version"), "purl": c.get("purl")},
            "vulnerability": {"uuid": str(uuid.uuid4()), "source": source, "vulnId": vid, "aliases": [{"cveId": a} for a in aliases]},
            "analysis": analysis or {"isSuppressed": False}}


class FakeDt:
    """DT 5.2 的行為（實測）：VEX 只在 ref 是 urn:cdx:<serial>/<ver>#<bom-ref> 時套用；token 是 workflow run id。"""

    def __init__(self, uploaded_boms, findings_by_project, wf_access=True, apply_vex=True, findings_detail=False, cross_apply=False):
        self.boms = uploaded_boms          # project uuid → 上傳的 BOM（serial、components）
        self.findings = findings_by_project
        self.projects = {ROOT_UUID: {"uuid": ROOT_UUID, "name": "P", "version": "1.0 (rootfs)"}}
        self.calls, self.wf_access, self.apply_vex, self.runs = [], wf_access, apply_vex, {}
        self.comp_counts = {}
        self.cross_apply = cross_apply   # DT 5.2 實測：同一個弱點兩個 finding 時，後面的陳述連另一個元件的 finding 一起套
        self.findings_detail = findings_detail   # False＝findings API 只回 state／isSuppressed（驗證者看到的形狀），detail 要走 /api/v1/analysis

    def json(self, method, path, obj=None):
        self.calls.append((method, path.split("?")[0]))
        if path.startswith("/api/v1/project/lookup"):
            from urllib.parse import parse_qs, urlparse
            q = parse_qs(urlparse(path).query)
            for p in self.projects.values():
                if p["name"] == q["name"][0] and p["version"] == q["version"][0]:
                    return 200, {}, p
            return 404, {}, None
        if method == "PUT" and path == "/api/v1/project":
            u = str(uuid.uuid4())
            self.projects[u] = {"uuid": u, "name": obj["name"], "version": obj["version"], "tags": obj.get("tags")}
            self.findings[u] = []
            return 201, {}, self.projects[u]
        if method == "GET" and path.startswith("/api/v1/project/"):
            return 200, {}, self.projects[path.rsplit("/", 1)[1]]
        if path.startswith("/api/v1/analysis?"):
            from urllib.parse import parse_qs, urlparse
            q = parse_qs(urlparse(path).query)
            for f in self.findings.get(q["project"][0], []):
                if f["component"]["uuid"] == q["component"][0] and f["vulnerability"]["uuid"] == q["vulnerability"][0]:
                    a = f["analysis"]
                    if not a.get("state"):
                        return 404, {}, None
                    return 200, {}, {"analysisState": a["state"], "analysisDetails": a.get("detail"), "isSuppressed": a.get("isSuppressed")}
            return 404, {}, None
        if path.startswith("/api/v2/internal/workflow-runs"):
            if not self.wf_access:
                return 403, {}, None
            if path.startswith("/api/v2/internal/workflow-runs/"):
                return 200, {}, {"status": "COMPLETED"}
            return 200, {}, {"items": [{"workflow_name": n, "status": "COMPLETED"} for n in ("import-bom", "vuln-analysis", "analyze-project")]}
        return 404, {}, None

    def pages(self, path):
        self.calls.append(("GET", path.split("?")[0]))
        pu = path.split("/")[5].split("?")[0]
        if "/finding/" in path:
            out = []
            for f in self.findings[pu]:
                g = json.loads(json.dumps(f))
                a = g["analysis"]
                g["analysis"] = {"isSuppressed": bool(a.get("isSuppressed")), "state": a.get("state") or "NOT_SET"}
                if self.findings_detail and a.get("detail") is not None:
                    g["analysis"]["detail"] = a["detail"]
                out.append(g)
            return out, None
        return [dict(c) for c in self.boms.get(pu, {}).get("components", [])][:], None

    def upload(self, path, fields, field, filename, data):
        self.calls.append(("POST", path))
        doc = json.loads(data)
        pu = fields["project"]
        if path == "/api/v1/bom":
            seen = set()
            comps = []
            for c in doc["components"]:   # DT 把 名稱＋版本＋purl（不含 qualifiers）相同的合成一個
                k = (c["name"], c.get("version"), (c.get("purl") or "").split("?")[0])
                if k not in seen:
                    seen.add(k)
                    comps.append(c)
            self.boms[pu] = {"serial": doc["serialNumber"], "version": doc.get("version", 1), "components": comps}
            return 200, {"token": str(uuid.uuid4())}
        if self.apply_vex:
            bom = self.boms[pu]
            refs = {wb.bomref_urn(bom.get("serial") or bom["serialNumber"], bom.get("version", 1), c["bom-ref"]): c for c in bom["components"]}
            for v in doc["vulnerabilities"]:
                for a in v["affects"]:
                    c = refs.get(a["ref"])
                    if not c:
                        continue
                    for f in self.findings[pu]:
                        if f["component"]["purl"] == c.get("purl") and f["component"]["name"] == c["name"] \
                           and f["vulnerability"]["source"] == v["source"]["name"] and f["vulnerability"]["vulnId"] == v["id"]:
                            targets_ = [f] + ([g for g in self.findings[pu] if g is not f and g["vulnerability"]["vulnId"] == v["id"]] if self.cross_apply else [])
                            for g in targets_:
                                g["analysis"] = {"state": v["analysis"]["state"].upper(), "detail": v["analysis"]["detail"],
                                                 "isSuppressed": v["analysis"]["state"] in ("not_affected", "resolved", "false_positive")}
        return 200, {"token": str(uuid.uuid4())}


def setup(tmp_path, stmts, findings=None, fake_kw=None):
    rep, scan = tmp_path / "Reports", tmp_path / "scan"
    (scan / "sbom").mkdir(parents=True)
    (scan / "dt").mkdir()
    rep.mkdir()
    (rep / "sbom.cdx.json").write_text(json.dumps(product_sbom()))
    (rep / "vex.cdx.json").write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "vulnerabilities": stmts}))
    (scan / "dt" / "project.json").write_text(json.dumps({"uuid": ROOT_UUID}))
    rbom = {"bomFormat": "CycloneDX", "serialNumber": SERIAL, "version": 1, "components": [dict(c) for c in ROOTFS]}
    (scan / "sbom" / "sbom.upload.cdx.json").write_text(json.dumps(rbom))
    fs = findings if findings is not None else [
        finding("u-ssl", ROOTFS[0], "OSV", "UBUNTU-CVE-1"), finding("u-zlib", ROOTFS[1], "NVD", "CVE-2"),
        finding("u-curl", ROOTFS[2], "GITHUB", "GHSA-x", aliases=["CVE-3"])]
    fake = FakeDt({ROOT_UUID: rbom}, {ROOT_UUID: fs}, **(fake_kw or {}))
    return rep, scan, fake


class A:
    def __init__(self, rep, scan, out, vex=False, prod=False, dry=False):
        self.reports, self.scan, self.out = str(rep), str(scan), str(out)
        self.vex, self.product_components, self.dry_run = vex, prod, dry
        self.wait, self.poll, self.max_unmatched_list = 5, 0, 200


def go(tmp_path, stmts, vex=True, prod=False, dry=False, **kw):
    rep, scan, fake = setup(tmp_path, stmts, **kw)
    out = tmp_path / "out"
    out.mkdir()
    import io
    from contextlib import redirect_stdout
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = wb.run(fake, A(rep, scan, out, vex, prod, dry), out)
    st = {}
    for line in buf.getvalue().splitlines():
        a, b, c = line.split("\t")
        st[a] = (b, c)
    return code, st, fake, out


def good_stmts():
    return [vstmt("CVE-1", "pkg:deb/ubuntu/openssl@3.0.1?arch=arm64?package-id=x", "not_affected", "OSV:UBUNTU-CVE-1", just="code_not_present"),
            vstmt("CVE-2", "pkg:deb/ubuntu/zlib@1.2.3?arch=arm64?package-id=x", "exploitable", "NVD:CVE-2"),
            vstmt("CVE-3", "pkg:deb/ubuntu/curl@7.0?arch=arm64?package-id=x", "in_triage", "NVD:CVE-9")]   # source-id 不在 DT；用 alias 對上


def test_no_flags_is_usage_error(tmp_path):
    assert wb.main(["--reports", str(tmp_path), "--scan", str(tmp_path), "--out", str(tmp_path / "o")]) == 64


def test_vex_applied_end_to_end(tmp_path):
    code, st, fake, out = go(tmp_path, good_stmts())
    assert code == 0
    assert st["D-dt-vex-build"][0] == "OK", st
    assert st["D-dt-vex-upload"][0] == "OK" and st["D-dt-vex-processing"][0] == "OK"
    assert st["D-dt-vex-applied"][0] == "OK" and "3 of 3" in st["D-dt-vex-applied"][1]
    doc = json.loads((out / "dt-vex.cdx.json").read_text())
    ids = {v["id"]: v for v in doc["vulnerabilities"]}
    # DT 的 (source, vulnId) 與 urn#bom-ref 的 ref，不是 VEX 原本的 CVE／產品 SBOM 的 ref
    assert ids["UBUNTU-CVE-1"]["source"]["name"] == "OSV"
    assert ids["UBUNTU-CVE-1"]["affects"][0]["ref"] == f"urn:cdx:{SERIAL[9:]}/1#pkg:deb/ubuntu/openssl@3.0.1?arch=arm64"
    assert ids["UBUNTU-CVE-1"]["analysis"]["state"] == "not_affected" and ids["UBUNTU-CVE-1"]["analysis"]["justification"] == "code_not_present"
    assert ids["UBUNTU-CVE-1"]["analysis"]["detail"].startswith("[sca-center:vex-writeback state=not_affected sha=") and "rule R1" in ids["UBUNTU-CVE-1"]["analysis"]["detail"]
    assert json.loads((out / "dt-writeback.json").read_text())["vex"]["basis"] == {"source-id": 2, "alias": 1}


def test_unmatched_is_attention_with_reasons(tmp_path):
    s = good_stmts() + [vstmt("CVE-7", "pkg:deb/ubuntu/zlib@1.2.3?arch=arm64?package-id=x", "exploitable", "GRYPE:CVE-7"),
                        vstmt("CVE-8", "pkg:deb/ubuntu/zlib@1.2.3?arch=arm64?package-id=x", "exploitable", "NVD:CVE-8")]
    code, st, fake, out = go(tmp_path, s)
    assert st["D-dt-vex-build"][0] == "ATTENTION"
    assert "5 of 5" not in st["D-dt-vex-build"][1] and "3 of 5 statements matched" in st["D-dt-vex-build"][1]
    rep = json.loads((out / "dt-writeback.json").read_text())["vex"]
    assert rep["unmatched"] == 2 and len(rep["unmatched_list"]) == 2
    assert set(rep["unmatched_by_reason"]) == {"only Grype/NVIDIA sources, no DT finding expected", "no DT finding for this component and vulnerability"}
    assert st["D-dt-vex-applied"][0] == "OK"   # 寫的都套用了；沒對上的另外在 build 列


def test_applied_fails_when_dt_ignores_vex(tmp_path):
    """DT 回 COMPLETED 但沒套用（ref 對不上）：upload、processing 都 OK，applied 要 FAIL，不能合併成一個 OK。"""
    code, st, fake, out = go(tmp_path, good_stmts(), fake_kw={"apply_vex": False})
    assert st["D-dt-vex-upload"][0] == "OK" and st["D-dt-vex-processing"][0] == "OK"
    assert st["D-dt-vex-applied"][0] == "FAIL" and "0 of 3" in st["D-dt-vex-applied"][1]
    assert code == 1


def test_processing_gap_without_workflow_permission(tmp_path):
    code, st, fake, out = go(tmp_path, good_stmts(), fake_kw={"wf_access": False})
    assert st["D-dt-vex-processing"][0] == "GAP"
    assert st["D-dt-vex-applied"][0] == "OK"   # 讀回仍確認


def test_does_not_overwrite_someone_elses_analysis(tmp_path):
    fs = [finding("u-ssl", ROOTFS[0], "OSV", "UBUNTU-CVE-1", analysis={"state": "FALSE_POSITIVE", "isSuppressed": True, "detail": "human"}),
          finding("u-zlib", ROOTFS[1], "NVD", "CVE-2")]
    code, st, fake, out = go(tmp_path, good_stmts()[:2], findings=fs)
    assert st["D-dt-vex-build"][0] == "ATTENTION" and "someone else" in st["D-dt-vex-build"][1]
    assert fs[0]["analysis"]["detail"] == "human"
    assert json.loads((out / "dt-writeback.json").read_text())["vex"]["existing_analysis_not_overwritten"] == 1


def test_rewrite_over_our_own_marker_is_allowed(tmp_path):
    fs = [finding("u-zlib", ROOTFS[1], "NVD", "CVE-2", analysis={"state": "IN_TRIAGE", "detail": wb.make_detail("in_triage", "old")})]
    code, st, fake, out = go(tmp_path, [good_stmts()[1]], findings=fs)
    assert st["D-dt-vex-applied"][0] == "OK" and fs[0]["analysis"]["state"] == "EXPLOITABLE"


def test_conflicting_statements_take_most_conservative(tmp_path):
    s = [vstmt("CVE-2", "pkg:deb/ubuntu/zlib@1.2.3?arch=arm64?package-id=x", "not_affected", "NVD:CVE-2", just="code_not_present"),
         vstmt("CVE-2", "pkg:deb/ubuntu/zlib@1.2.3?arch=arm64?package-id=x", "exploitable", "NVD:CVE-2")]
    code, st, fake, out = go(tmp_path, s, findings=[finding("u", ROOTFS[1], "NVD", "CVE-2")])
    rep = json.loads((out / "dt-writeback.json").read_text())["vex"]
    assert rep["conflicts"] == 1
    assert [v["analysis"]["state"] for v in json.loads((out / "dt-vex.cdx.json").read_text())["vulnerabilities"]] == ["exploitable"]
    assert st["D-dt-vex-build"][0] == "ATTENTION"


def test_binary_statement_maps_to_source_package_finding(tmp_path):
    src = comp("openssl-src", "3.0.1", "pkg:deb/ubuntu/openssl@3.0.1?arch=source", "sca-center-deb-source:x")
    rep, scan, fake = setup(tmp_path, [good_stmts()[0]], findings=[finding("u-src", src, "OSV", "UBUNTU-CVE-1")])
    # 上傳的 BOM 已含原始碼元件（sca-scan 的 deb_sources 補的）：直接放進上傳檔，deb-sources.json 只提供 二進位 → 原始碼套件 的對應
    rb = json.loads((scan / "sbom" / "sbom.upload.cdx.json").read_text())
    rb["components"].append(src)
    (scan / "sbom" / "sbom.upload.cdx.json").write_text(json.dumps(rb))
    (scan / "dt" / "deb-sources.json").write_text(json.dumps({"source_components_added": 0, "shared_sources": [
        {"purl": src["purl"], "binary_purls": [ROOTFS[0]["purl"]]}]}))
    fake.boms[ROOT_UUID] = rb
    out = tmp_path / "o2"
    out.mkdir()
    import io
    from contextlib import redirect_stdout
    buf = io.StringIO()
    with redirect_stdout(buf):
        wb.run(fake, A(rep, scan, out, vex=True), out)
    assert "D-dt-vex-applied\tOK" in buf.getvalue()


def test_dry_run_sends_nothing(tmp_path):
    code, st, fake, out = go(tmp_path, good_stmts(), prod=True, dry=True)
    assert all(m != "POST" for m, _ in fake.calls) and not any(m == "PUT" for m, _ in fake.calls)
    assert st["D-dt-vex-upload"][0] == "NOT_RUN" and st["D-dt-product-upload"][0] == "NOT_RUN"
    assert st["D-dt-vex-build"][1].count("3 of 3")


def test_missing_credentials_is_not_run(tmp_path):
    rep, scan, _ = setup(tmp_path, [])
    out = tmp_path / "o"
    assert wb.run(None, A(rep, scan, out, vex=True, prod=True), out) == 0


def test_product_components_separate_project_and_rule13(tmp_path):
    code, st, fake, out = go(tmp_path, [], vex=False, prod=True)
    assert code == 0
    assert st["D-dt-product-project"][0] == "OK" and st["D-dt-product-upload"][0] == "OK" and st["D-dt-product-processing"][0] == "OK"
    new = [p for u, p in fake.projects.items() if u != ROOT_UUID]
    assert len(new) == 1 and new[0]["version"] == "1.0 (product components)" and new[0]["name"] == "P"
    assert new[0]["tags"] == [{"name": wb.PRODUCT_TAG}]
    doc = json.loads((out / "product-components.cdx.json").read_text())
    byname = {c["name"]: c for c in doc["components"]}
    assert set(byname) == {"fw-blob", "edk-ssl", "tool.sh"}          # rootfs 的元件一個都不在
    assert "version" not in byname["fw-blob"]                           # 檔案時間不是版本（規則 13）
    assert any(p["name"] == "sca-pilot:version-removed" for p in byname["fw-blob"]["properties"])
    assert byname["edk-ssl"]["version"] == "3.4.1" and byname["edk-ssl"]["cpe"]
    # 沒有版本或 purl／CPE 的不能比對漏洞：ATTENTION，不是 OK
    assert st["D-dt-product-components"][0] == "ATTENTION" and "matchable" in st["D-dt-product-components"][1]
    # rootfs 專案沒被碰：它的 BOM 還是原本上傳的那份
    assert fake.boms[ROOT_UUID]["components"][0]["name"] == "openssl"


def test_product_components_deterministic_serial(tmp_path):
    a = wb.product_bom(product_sbom(), [dict(c) for c in EXTRAS], "1 (product components)")
    b = wb.product_bom(product_sbom(), [dict(c) for c in EXTRAS], "1 (product components)")
    assert a["serialNumber"] == b["serialNumber"]


def test_vex_covers_product_components_project(tmp_path):
    ssl_key = EXTRAS[1]
    stm = [vstmt("CVE-5", "uefi-source:ssl", "resolved", "NVD:CVE-5")]
    rep, scan, fake = setup(tmp_path, stm)
    out = tmp_path / "o"
    out.mkdir()
    # 上傳後，假 DT 要對 edk-ssl 有 finding：包一層，上傳 BOM 後插入 finding
    orig = fake.upload

    def upload(path, fields, field, filename, data):
        res = orig(path, fields, field, filename, data)
        if path == "/api/v1/bom":
            fake.findings[fields["project"]] = [finding("u-e", ssl_key, "NVD", "CVE-5")]
        return res
    fake.upload = upload
    import io
    from contextlib import redirect_stdout
    buf = io.StringIO()
    with redirect_stdout(buf):
        wb.run(fake, A(rep, scan, out, vex=True, prod=True), out)
    assert "D-dt-vex-applied\tOK" in buf.getvalue(), buf.getvalue()


def test_env_file_reads_only_two_keys(tmp_path):
    p = tmp_path / "e"
    p.write_text("DT_URL=http://x:1/api\nDT_API_KEY='abc'\nOTHER=secret\n")
    assert wb.read_env_file(p) == {"DT_URL": "http://x:1/api", "DT_API_KEY": "abc"}
    assert wb.Dt("http://x:1/api", "k").url == "http://x:1"


def test_cra_report_ignores_only_untouched_writeback_analysis():
    """寫回 DT 的分析下次掃描不能被當成人在 DT 的判定；但標記在、狀態或內容被人改過 → 當人工判定（M1）。"""
    det = wb.make_detail("not_affected", "rule R3")
    mine = {"analysis": {"state": "NOT_AFFECTED", "isSuppressed": True, "justification": "code_not_present", "detail": det}}
    a = cra.analysis_of(mine)
    assert a["state"] == "" and a["suppressed"] is False and a["writeback"] is True
    # 人把狀態改成 FALSE_POSITIVE 但標記還在
    h1 = {"analysis": {"state": "FALSE_POSITIVE", "isSuppressed": True, "detail": det}}
    assert cra.analysis_of(h1)["state"] == "FALSE_POSITIVE"
    # 人改了內容、狀態沒變（雜湊對不上）
    h2 = {"analysis": {"state": "NOT_AFFECTED", "isSuppressed": True, "detail": det + " and I checked it"}}
    assert cra.analysis_of(h2)["state"] == "NOT_AFFECTED" and cra.analysis_of(h2)["suppressed"] is True
    # 標記不在開頭
    h3 = {"analysis": {"state": "NOT_AFFECTED", "detail": "see " + det}}
    assert cra.analysis_of(h3)["state"] == "NOT_AFFECTED"
    human = {"analysis": {"state": "NOT_AFFECTED", "isSuppressed": True, "detail": "reviewed by a person"}}
    assert cra.analysis_of(human)["state"] == "NOT_AFFECTED"
    # 兩邊的標記解析一致
    assert cra.dt_writeback_state(det) == wb.parse_marker(det) == "not_affected"


def test_human_changed_state_but_kept_prefix_is_not_overwritten(tmp_path):
    det = wb.make_detail("exploitable", "old text")
    fs = [finding("u-zlib", ROOTFS[1], "NVD", "CVE-2", analysis={"state": "NOT_AFFECTED", "isSuppressed": True, "detail": det})]
    code, st, fake, out = go(tmp_path, [good_stmts()[1]], findings=fs)
    assert st["D-dt-vex-build"][0] == "ATTENTION" and "someone else" in st["D-dt-vex-build"][1]
    assert fs[0]["analysis"]["state"] == "NOT_AFFECTED" and fs[0]["analysis"]["detail"] == det


def test_not_set_is_no_analysis(tmp_path):
    """findings API 對沒有分析的 finding 回 state NOT_SET：不是別人的分析，要寫，也要讀回（H3）。"""
    fs = [finding("u-zlib", ROOTFS[1], "NVD", "CVE-2", analysis={"state": "NOT_SET", "isSuppressed": False})]
    code, st, fake, out = go(tmp_path, [good_stmts()[1]], findings=fs)
    assert st["D-dt-vex-applied"][0] == "OK", st
    assert fs[0]["analysis"]["state"] == "EXPLOITABLE"
    assert not wb.has_analysis({"state": "NOT_SET"}) and not wb.has_analysis({}) and wb.has_analysis({"state": "IN_TRIAGE"})


def test_detail_read_via_analysis_endpoint_when_findings_lack_it(tmp_path):
    """findings API 不回 detail（驗證者看到的形狀）：讀回走 /api/v1/analysis（analysisDetails）；回 detail 的也要能用（H2）。"""
    code, st, fake, out = go(tmp_path, good_stmts())
    assert st["D-dt-vex-applied"][0] == "OK"
    assert ("GET", "/api/v1/analysis") in fake.calls
    code, st, fake, out = go(tmp_path / "b", good_stmts(), fake_kw={"findings_detail": True})
    assert st["D-dt-vex-applied"][0] == "OK"
    assert ("GET", "/api/v1/analysis") not in fake.calls


def _shared_source_setup(tmp_path, judged_binaries):
    """一個原始碼套件的 finding，對應兩個二進位套件 b1、b2；只有 judged_binaries 有陳述。"""
    b1 = comp("b1", "1.0", "pkg:deb/ubuntu/b1@1.0?arch=arm64")
    b2 = comp("b2", "1.0", "pkg:deb/ubuntu/b2@1.0?arch=arm64")
    src = comp("srcpkg", "1.0", "pkg:deb/ubuntu/srcpkg@1.0?arch=source", "sca-center-deb-source:x")
    rep, scan, fake = setup(tmp_path, [], findings=[finding("u-src", src, "OSV", "UBUNTU-CVE-9")])
    pj = json.loads((rep / "sbom.cdx.json").read_text())
    pj["components"] += [dict(b1, **{"bom-ref": "b1"}), dict(b2, **{"bom-ref": "b2"})]
    (rep / "sbom.cdx.json").write_text(json.dumps(pj))
    stm = [vstmt("CVE-9", name, "not_affected", "OSV:UBUNTU-CVE-9", just="code_not_present") for name in judged_binaries]
    (rep / "vex.cdx.json").write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "vulnerabilities": stm}))
    rb = json.loads((scan / "sbom" / "sbom.upload.cdx.json").read_text())
    rb["components"].append(src)
    (scan / "sbom" / "sbom.upload.cdx.json").write_text(json.dumps(rb))
    (scan / "dt" / "deb-sources.json").write_text(json.dumps({"source_components_added": 0, "shared_sources": [
        {"purl": src["purl"], "binary_purls": [b1["purl"], b2["purl"]]}]}))
    fake.boms[ROOT_UUID] = rb
    out = tmp_path / "o"
    out.mkdir()
    import io
    from contextlib import redirect_stdout
    buf = io.StringIO()
    with redirect_stdout(buf):
        wb.run(fake, A(rep, scan, out, vex=True), out)
    lines = {l.split("\t")[0]: l.split("\t") for l in buf.getvalue().splitlines()}
    return lines, fake, out


def test_shared_source_finding_one_of_two_binaries_judged_is_in_triage(tmp_path):
    lines, fake, out = _shared_source_setup(tmp_path, ["b1"])
    f = fake.findings[ROOT_UUID][0]["analysis"]
    assert f["state"] == "IN_TRIAGE" and f["isSuppressed"] is False
    assert "b2" in f["detail"] and "not judged" in f["detail"]
    assert lines["D-dt-vex-build"][1] == "ATTENTION" and "in_triage because not every installed binary" in lines["D-dt-vex-build"][2]
    assert json.loads((out / "dt-writeback.json").read_text())["vex"]["partial_shared_list"][0]["unjudged"] == ["b2@1.0"]


def test_shared_source_finding_all_binaries_judged_is_not_affected(tmp_path):
    lines, fake, out = _shared_source_setup(tmp_path, ["b1", "b2"])
    assert fake.findings[ROOT_UUID][0]["analysis"]["state"] == "NOT_AFFECTED"
    assert "will be suppressed by DT" in lines["D-dt-vex-build"][2] and "1 (not_affected" in lines["D-dt-vex-build"][2]
    assert "suppressed 1 of them" in lines["D-dt-vex-applied"][2]


def test_statement_without_state_is_not_sent_and_counted(tmp_path):
    s = good_stmts() + [vstmt("CVE-2", "pkg:deb/ubuntu/zlib@1.2.3?arch=arm64?package-id=x", "", "NVD:CVE-2")]
    s[-1]["analysis"] = {"detail": "x"}
    code, st, fake, out = go(tmp_path, s)
    rep = json.loads((out / "dt-writeback.json").read_text())["vex"]
    assert rep["unmatched_by_reason"]["statement has no usable analysis state (not sent)"] == 1
    assert st["D-dt-vex-build"][0] == "ATTENTION"


def test_product_processing_gap_is_stated_in_applied(tmp_path):
    code, st, fake, out = go(tmp_path, good_stmts(), vex=True, prod=True, fake_kw={"wf_access": False})
    assert st["D-dt-product-processing"][0] == "GAP"
    assert "product-components project: processing status unknown" in st["D-dt-vex-applied"][1]


def test_unreadable_env_file_says_so(tmp_path, capsys):
    rep, scan, _ = setup(tmp_path, [])
    code = wb.main(["--reports", str(rep), "--scan", str(scan), "--out", str(tmp_path / "o"), "--env", str(tmp_path / "nope.env"), "--vex"])
    out = capsys.readouterr().out
    assert code == 0 and "NOT_RUN" in out and "env file unreadable" in out


def test_statuses_never_merge_upload_and_applied(tmp_path):
    code, st, fake, out = go(tmp_path, good_stmts(), vex=True, prod=True)
    for s in ("D-dt-vex-build", "D-dt-vex-upload", "D-dt-vex-processing", "D-dt-vex-applied",
              "D-dt-product-project", "D-dt-product-upload", "D-dt-product-processing", "D-dt-product-components"):
        assert s in st


def test_document_orders_closed_states_before_open_ones():
    an = {"not_affected": {"state": "not_affected", "detail": "a"}, "exploitable": {"state": "exploitable", "detail": "b"}, "in_triage": {"state": "in_triage", "detail": "c"}}
    ap = {("rootfs", "OSV", "V", f"r-{k}"): v for k, v in an.items()}
    doc = wb.dt_vex_document(ap)
    assert [v["analysis"]["state"] for v in doc["vulnerabilities"]] == ["not_affected", "in_triage", "exploitable"]


def test_cross_applied_statement_is_reported_and_errs_conservative(tmp_path):
    """DT 把後面那條陳述連另一個元件的同一弱點 finding 一起套：狀態對、detail 是別條 → ATTENTION 說明；
    一個 not_affected 一個 exploitable 時，蓋出來的是 exploitable（已解決那族排前面）。"""
    fs = [finding("u-zlib", ROOTFS[1], "NVD", "CVE-2"), finding("u-ssl", ROOTFS[0], "NVD", "CVE-2")]
    s = [vstmt("CVE-2", "pkg:deb/ubuntu/zlib@1.2.3?arch=arm64?package-id=x", "not_affected", "NVD:CVE-2", detail="zlib ok", just="code_not_present"),
         vstmt("CVE-2", "pkg:deb/ubuntu/openssl@3.0.1?arch=arm64?package-id=x", "exploitable", "NVD:CVE-2", detail="ssl bad")]
    code, st, fake, out = go(tmp_path, s, findings=fs, fake_kw={"cross_apply": True})
    assert {f["analysis"]["state"] for f in fs} == {"EXPLOITABLE"}        # 沒有因為蓋掉而變成 suppressed 的 not_affected
    assert st["D-dt-vex-applied"][0] == "ATTENTION" and "state differs 1" in st["D-dt-vex-applied"][1]
    s2 = [vstmt("CVE-2", "pkg:deb/ubuntu/zlib@1.2.3?arch=arm64?package-id=x", "exploitable", "NVD:CVE-2", detail="zlib bad"),
          vstmt("CVE-2", "pkg:deb/ubuntu/openssl@3.0.1?arch=arm64?package-id=x", "exploitable", "NVD:CVE-2", detail="ssl bad")]
    fs2 = [finding("u-zlib", ROOTFS[1], "NVD", "CVE-2"), finding("u-ssl", ROOTFS[0], "NVD", "CVE-2")]
    code, st, fake, out = go(tmp_path / "b", s2, findings=fs2, fake_kw={"cross_apply": True})
    assert st["D-dt-vex-applied"][0] == "ATTENTION" and "another statement" in st["D-dt-vex-applied"][1]


ZSTM = lambda: vstmt("CVE-2", "pkg:deb/ubuntu/zlib@1.2.3?arch=arm64?package-id=x", "not_affected", "NVD:CVE-2", detail="zlib ok", just="code_not_present")
SSTM = lambda: vstmt("CVE-2", "pkg:deb/ubuntu/openssl@3.0.1?arch=arm64?package-id=x", "not_affected", "NVD:CVE-2", detail="ssl ok", just="code_not_present")


def _sent_states(out):
    p = out / "dt-vex.cdx.json"
    return [v["analysis"]["state"] for v in json.loads(p.read_text())["vulnerabilities"]] if p.exists() else []


def test_cross_apply_human_exploitable_on_other_component_is_untouched(tmp_path):
    """A 有陳述、B 有人判的 EXPLOITABLE（B 的陳述被擋）：DT 會把 A 的 not_affected 連 B 一起套 → 這個弱點整個不送。"""
    human = {"state": "EXPLOITABLE", "isSuppressed": False, "detail": "human says bad"}
    fs = [finding("u-zlib", ROOTFS[1], "NVD", "CVE-2"), finding("u-ssl", ROOTFS[0], "NVD", "CVE-2", analysis=dict(human))]
    code, st, fake, out = go(tmp_path, [ZSTM(), SSTM()], findings=fs, fake_kw={"cross_apply": True})
    assert fs[1]["analysis"] == human and fs[0]["analysis"].get("state") is None   # 兩邊都沒動
    assert "not_affected" not in _sent_states(out) and ("POST", "/api/v1/vex") not in fake.calls
    assert st["D-dt-vex-build"][0] == "ATTENTION" and "withheld" in st["D-dt-vex-build"][1]
    rep = json.loads((out / "dt-writeback.json").read_text())["vex"]
    assert rep["withheld_shared_vuln"] == 1 and rep["withheld_shared_vuln_list"][0]["vuln"] == "CVE-2"
    assert "openssl (has an analysis)" in rep["withheld_shared_vuln_list"][0]["not_in_write_set"]
    assert st["D-dt-vex-applied"][0] == "NOT_RUN"


def test_cross_apply_other_component_without_statement_is_untouched(tmp_path):
    fs = [finding("u-zlib", ROOTFS[1], "NVD", "CVE-2"), finding("u-ssl", ROOTFS[0], "NVD", "CVE-2", analysis={"state": "IN_TRIAGE", "detail": "someone triaged"})]
    code, st, fake, out = go(tmp_path, [ZSTM()], findings=fs, fake_kw={"cross_apply": True})
    assert fs[1]["analysis"]["state"] == "IN_TRIAGE" and fs[0]["analysis"].get("state") is None
    assert _sent_states(out) == [] and st["D-dt-vex-build"][0] == "ATTENTION"
    # B 完全沒有分析、也沒有陳述：一樣不送（DT 會把 not_affected 套到 B，B 會被藏起來）
    fs = [finding("u-zlib", ROOTFS[1], "NVD", "CVE-2"), finding("u-ssl", ROOTFS[0], "NVD", "CVE-2")]
    code, st, fake, out = go(tmp_path / "b", [ZSTM()], findings=fs, fake_kw={"cross_apply": True})
    assert all(f["analysis"].get("state") is None for f in fs) and "withheld" in st["D-dt-vex-build"][1]


def test_both_findings_ours_still_written_under_cross_apply(tmp_path):
    fs = [finding("u-zlib", ROOTFS[1], "NVD", "CVE-2"), finding("u-ssl", ROOTFS[0], "NVD", "CVE-2")]
    code, st, fake, out = go(tmp_path, [ZSTM(), SSTM()], findings=fs, fake_kw={"cross_apply": True})
    assert {f["analysis"]["state"] for f in fs} == {"NOT_AFFECTED"} and "withheld" not in st["D-dt-vex-build"][1]


def test_readback_fails_when_a_human_analysis_changed_anyway(tmp_path, monkeypatch):
    """扣下檢查被繞過（這裡直接關掉）時，寫入前的快照與寫入後的讀回要抓到被改掉的人工分析 → FAIL。"""
    monkeypatch.setattr(wb, "withhold_shared_vulns", lambda targets, kept: (kept, []))
    human = {"state": "EXPLOITABLE", "isSuppressed": False, "detail": "human says bad"}
    fs = [finding("u-zlib", ROOTFS[1], "NVD", "CVE-2"), finding("u-ssl", ROOTFS[0], "NVD", "CVE-2", analysis=dict(human))]
    code, st, fake, out = go(tmp_path, [ZSTM()], findings=fs, fake_kw={"cross_apply": True})
    assert fs[1]["analysis"]["state"] == "NOT_AFFECTED"   # 假 DT 真的蓋掉了
    assert st["D-dt-vex-applied"][0] == "FAIL" and "CHANGED" in st["D-dt-vex-applied"][1] and "EXPLOITABLE -> NOT_AFFECTED" in st["D-dt-vex-applied"][1]
    assert code == 1
    # 原本沒有分析的 finding 被改 → ATTENTION，不是 OK
    fs = [finding("u-zlib", ROOTFS[1], "NVD", "CVE-2"), finding("u-ssl", ROOTFS[0], "NVD", "CVE-2")]
    code, st, fake, out = go(tmp_path / "b", [ZSTM()], findings=fs, fake_kw={"cross_apply": True})
    assert st["D-dt-vex-applied"][0] == "ATTENTION" and "did not intend" in st["D-dt-vex-applied"][1]

def test_vex_for_python_module_matches_finding_on_patched_purl(tmp_path):
    """產品 SBOM／VEX 是原始 SBOM（mpmath@0.0.0）；DT 收到 sca-scan C-pyver 改過的副本（mpmath@1.2.1）：用 sbom.pyver.cdx.json 的
    sca:original-version 把原始 purl 對到改過的 purl，陳述才對得上 finding。沒有這個檔案時對不上，要在 unmatched 列出（不靜默）。"""
    import py_dpkg_version as pv
    orig = comp("mpmath", "0.0.0", "pkg:pypi/mpmath@0.0.0", "pkg:pypi/mpmath@0.0.0?package-id=x")
    new = comp("mpmath", "1.2.1", "pkg:pypi/mpmath@1.2.1", "pkg:pypi/mpmath@1.2.1?package-id=x",
               properties=[{"name": "sca:original-version", "value": "0.0.0"}])
    assert pv.purl_pairs({"components": [new]}) == [("pkg:pypi/mpmath@0.0.0", "pkg:pypi/mpmath@1.2.1")]
    scan = tmp_path / "scan"
    (scan / "sbom").mkdir(parents=True)
    (scan / "sbom" / "sbom.pyver.cdx.json").write_text(json.dumps({"components": [new]}))
    keys = wb.deb_alt_keys(scan)
    assert keys[("purl", "pkg:pypi/mpmath@0.0.0")] == [("purl", "pkg:pypi/mpmath@1.2.1")]
    vex = {"vulnerabilities": [vstmt("CVE-2021-29063", orig["bom-ref"], "not_affected", "OSV:PYSEC-2021-427", just="code_not_present")]}
    product = {"components": [orig]}
    f = finding("u-mp", new, "OSV", "PYSEC-2021-427", aliases=["CVE-2021-29063"])
    targets = {"rootfs": {"findings": [f], "bomref_by_key": {wb.comp_key(new): new["bom-ref"]}, "serial": SERIAL, "version": 1}}
    applies, rep = wb.match_statements(vex, product, targets, keys)
    assert len(applies) == 1
    assert next(iter(applies))[3].endswith("#pkg:pypi/mpmath@1.2.1?package-id=x")
    # 沒有對照 → 對不上，而且列在 unmatched
    applies, rep = wb.match_statements(vex, product, targets, {})
    assert not applies and rep["unmatched"]


# ---- M7c-1（A4／D-057）：沒有評估的陳述（in_triage 加 dumpling:assessment＝NOT_ASSESSED）不是判定，不寫回 DT

NA_PROP = {"name": "dumpling:assessment", "value": "NOT_ASSESSED"}


def na_stmt(vid, comp_ref, source_ids):
    """vex_export.cdx_vex 為沒有判定的列輸出的樣子：in_triage、標記屬性、沒有 vex-source／規則。"""
    return {"bom-ref": f"vex-{vid}", "id": vid, "source": {"name": "NVD"},
            "analysis": {"state": "in_triage", "detail": "Not assessed: no VEX assessment has been recorded"},
            "affects": [{"ref": f"urn:cdx:99999999-9999-4999-8999-999999999999/1#{comp_ref}"}],
            "properties": [{"name": "sca-center:source-ids", "value": source_ids}, {"name": "sca-center:component", "value": "x"}, dict(NA_PROP)]}


def test_marker_constants_match_vexconv():
    import vex_export as vx
    vc = vx._vexconv()
    assert (wb.NOT_ASSESSED_PROP, wb.NOT_ASSESSED_VALUE) == (vc.PROP_ASSESSMENT, vc.NOT_ASSESSED)


def test_not_assessed_statements_are_never_written_back(tmp_path):
    """三個 finding：openssl 有判定（not_affected）、zlib 與 curl 的陳述是 NOT_ASSESSED（in_triage）。DT 只會收到 openssl 的那一條；
    zlib、curl 的 finding 沒有 analysis，寫回之後仍然沒有（沒有被改成 IN_TRIAGE）。"""
    stmts = [good_stmts()[0],
             na_stmt("CVE-2", "pkg:deb/ubuntu/zlib@1.2.3?arch=arm64?package-id=x", "NVD:CVE-2"),
             na_stmt("CVE-3", "pkg:deb/ubuntu/curl@7.0?arch=arm64?package-id=x", "NVD:CVE-9")]
    code, st, fake, out = go(tmp_path, stmts)
    assert code == 0 and st["D-dt-vex-applied"][0] == "OK", st
    assert _sent_states(out) == ["not_affected"]
    fs = fake.findings[ROOT_UUID]
    by = {f["vulnerability"]["vulnId"]: f["analysis"] for f in fs}
    assert by["UBUNTU-CVE-1"]["state"] == "NOT_AFFECTED"
    assert not by["CVE-2"].get("state") and not by["GHSA-x"].get("state")          # DT 的狀態沒有因為 NOT_ASSESSED 改變
    rep = json.loads((out / "dt-writeback.json").read_text())["vex"]
    assert rep["not_assessed_skipped"] == 2 and rep["statements"] == 1 and rep["unmatched"] == 0
    assert "1 of 1 statements matched" in st["D-dt-vex-build"][1]


def test_only_not_assessed_statements_write_nothing(tmp_path):
    stmts = [na_stmt("CVE-2", "pkg:deb/ubuntu/zlib@1.2.3?arch=arm64?package-id=x", "NVD:CVE-2")]
    code, st, fake, out = go(tmp_path, stmts)
    assert _sent_states(out) == [] and st["D-dt-vex-upload"][0] == "NOT_RUN"
    assert all(not f["analysis"].get("state") for f in fake.findings[ROOT_UUID])
    assert not any(c[0] == "POST" and c[1] == "/api/v1/vex" for c in fake.calls)


def test_not_assessed_does_not_touch_someone_elses_analysis_or_our_earlier_writeback(tmp_path):
    human = {"state": "FALSE_POSITIVE", "isSuppressed": True, "detail": "human"}
    fs = [finding("u-zlib", ROOTFS[1], "NVD", "CVE-2", analysis=dict(human))]
    code, st, fake, out = go(tmp_path, [na_stmt("CVE-2", "pkg:deb/ubuntu/zlib@1.2.3?arch=arm64?package-id=x", "NVD:CVE-2")], findings=fs)
    assert fs[0]["analysis"]["state"] == "FALSE_POSITIVE" and fs[0]["analysis"]["detail"] == "human" and _sent_states(out) == []
    # 沒有標記的 in_triage（人判的 in_triage 陳述）照舊會寫回：區別只在 dumpling:assessment
    fs2 = [finding("u-curl", ROOTFS[2], "GITHUB", "GHSA-x", aliases=["CVE-3"])]
    code, st, fake, out = go(tmp_path / "b", [good_stmts()[2]], findings=fs2)
    assert fs2[0]["analysis"]["state"] == "IN_TRIAGE"


def test_partial_shared_finding_is_unchanged_by_not_assessed_statements():
    """H1：原始碼套件的 finding 對應多個二進位套件，只有一部分有陳述時寫 in_triage。沒有評估的二進位套件算「沒有陳述」，結果與沒有那條陳述時相同。"""
    a = comp("libssl3", "3.0.1", "pkg:deb/ubuntu/libssl3@3.0.1?arch=arm64")
    b = comp("openssl", "3.0.1", "pkg:deb/ubuntu/openssl@3.0.1?arch=arm64")
    src = comp("openssl", "3.0.1", "pkg:deb/ubuntu/openssl@3.0.1?arch=source")
    product = {"components": [a, b]}
    f = finding("u-src", src, "NVD", "CVE-2")
    targets = {"rootfs": {"findings": [f], "bomref_by_key": {wb.comp_key(src): src["bom-ref"]}, "serial": SERIAL, "version": 1}}
    alt = {wb.comp_key(a): [wb.comp_key(src)], wb.comp_key(b): [wb.comp_key(src)]}
    judged = vstmt("CVE-2", a["bom-ref"], "not_affected", "NVD:CVE-2", just="code_not_present")
    na = na_stmt("CVE-2", b["bom-ref"], "NVD:CVE-2")
    with_na, rep1 = wb.match_statements({"vulnerabilities": [judged, na]}, product, targets, alt)
    without, rep2 = wb.match_statements({"vulnerabilities": [judged]}, product, targets, alt)
    assert with_na == without and [x["state"] for x in with_na.values()] == ["in_triage"]
    assert rep1["partial_shared"] == rep2["partial_shared"] == 1
    assert rep1["not_assessed_skipped"] == 1 and rep2["not_assessed_skipped"] == 0
    assert {k: v for k, v in rep1.items() if k != "not_assessed_skipped"} == {k: v for k, v in rep2.items() if k != "not_assessed_skipped"}
