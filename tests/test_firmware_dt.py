"""firmware_dt.py（prep／expected／report）的單元測試。不連網、不起 Docker、不需要 grype。"""
import copy
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("firmware_dt", os.path.join(ROOT, "pipeline", "lib", "firmware_dt.py"))
fd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fd)

YML = "kind: %s\nvendor: Acme\nmodel: Box 1\nstatus: %s\n%s"


def comp(name, ref=None, version="1.0", purl=None, cpe=None, va="NOT_ASSESSED", vs="OK"):
    c = {"type": "firmware", "name": name, "properties": [
        {"name": "dumpling:vuln-assessment", "value": va}, {"name": "dumpling:version-status", "value": vs},
        {"name": "sca-center:found-in", "value": "x.bin @0x0"}]}
    if ref:
        c["bom-ref"] = ref
    if version:
        c["version"] = version
    if purl:
        c["purl"] = purl
    if cpe:
        c["cpe"] = cpe
    return c


def bom(*comps, deps=None):
    d = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
         "metadata": {"tools": {"components": [{"type": "application", "name": "t"}]}}, "components": list(comps)}
    if deps is not None:
        d["dependencies"] = deps
    return d


class Base(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.tmp = self._td.name
        self.addCleanup(self._td.cleanup)

    def w(self, rel, text):
        p = os.path.join(self.tmp, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(text if isinstance(text, str) else json.dumps(text))
        return p

    def sample(self, slug="acme-box-1.2", kind="bios", status="ok", version="firmware_version: 1.2.3\n"):
        return self.w("firmware/%s/%s/firmware.yml" % (kind, slug), YML % (kind, status, version))

    def prep(self, doc, slug="acme-box-1.2", out="prep", **kw):
        s = self.sample(slug, **kw)
        b = self.w("in/%s.json" % slug, doc)
        o = os.path.join(self.tmp, out)
        return fd.prep(b, s, o), o


class PrepTests(Base):
    def test_normalize_keeps_components_and_properties(self):
        c1 = comp("Intel CSE", "r1", purl=None, cpe="cpe:2.3:o:intel:cse:1:*:*:*:*:*:*:*")
        c2 = comp("edk2", "r2", purl="pkg:github/tianocore/edk2@abc")
        doc = bom(c1, c2, deps=[{"ref": "r1", "dependsOn": ["r2"]}])
        before = copy.deepcopy(doc["components"])
        info, o = self.prep(doc)
        out = json.load(open(os.path.join(o, "sbom.cdx.json"), encoding="utf-8"))
        self.assertEqual(out["components"], before)            # 元件完全不變（含 dumpling:* property）
        self.assertEqual(out["dependencies"], doc["dependencies"])
        mc = out["metadata"]["component"]
        self.assertEqual((mc["type"], mc["name"], mc["version"]), ("firmware", "Box 1", "1.2.3"))
        self.assertIn("tools", out["metadata"])
        self.assertEqual(info["project_name"], "firmware-bios-acme-box-1.2")
        self.assertEqual(info["project_version"], "1.2.3")
        s = info["summary"]
        self.assertEqual((s["components"], s["with_purl"], s["with_cpe"]), (2, 1, 1))
        self.assertEqual(s["vuln_assessment"], {"NOT_ASSESSED": 2})
        self.assertEqual(s["purl_types"], ["github"])

    def test_no_guessed_purl_or_cpe(self):
        _, o = self.prep(bom(comp("a", "r1")))
        out = json.load(open(os.path.join(o, "sbom.cdx.json")))
        self.assertNotIn("purl", out["components"][0])
        self.assertNotIn("cpe", out["components"][0])

    def test_version_gap_counted_and_replaced_metadata_component(self):
        doc = bom(comp("a", "r1", version=None, vs="GAP"), comp("b", "r2"))
        doc["metadata"]["component"] = {"type": "application", "name": "old", "version": "9"}
        info, _ = self.prep(doc)
        self.assertEqual(info["summary"]["version_gap"], 1)
        self.assertEqual(info["summary"]["no_version"], 1)
        self.assertEqual(info["replaced_metadata_component"], {"name": "old", "version": "9"})

    def test_name_rules(self):
        self.assertEqual(fd.project_name("vbios", "x", True), "firmware-vbios-synthetic-x")
        self.assertEqual(fd.safe_version("1.0/2 beta:3"), "1.0_2 beta_3")
        self.assertEqual(fd.safe_version(None), "unknown")
        self.assertEqual(fd.safe_version("--"), "unknown")
        self.assertTrue(fd.VERSION_RE.match(fd.safe_version("x" * 300)))
        self.assertEqual(fd.safe_slug("a b/c;d"), "a-b-c-d")
        info, _ = self.prep(bom(comp("a", "r1")), slug="we ird;slug")
        self.assertEqual(info["project_name"], "firmware-bios-we-ird-slug")

    def test_synthetic_by_gap_status_and_by_filename(self):
        info, _ = self.prep(bom(comp("a", "r1")), kind="vbios", status="GAP", slug="standalone-x", version="")
        self.assertTrue(info["synthetic"])
        self.assertEqual(info["project_name"], "firmware-vbios-synthetic-standalone-x")
        self.assertEqual(info["project_version"], "unknown")
        c = comp("a", "r1")
        c["properties"].append({"name": "bsi:component:filename", "value": "Synthetic-Rom.rom"})
        info, _ = self.prep(bom(c), kind="vbios", status="ok", slug="y", version="firmware_version: 1\n", out="p2")
        self.assertTrue(info["synthetic"])

    def test_duplicate_bom_ref_and_bad_dependencies(self):
        with self.assertRaises(fd.DtError):
            self.prep(bom(comp("a", "r1"), comp("b", "r1")))
        with self.assertRaises(fd.DtError):
            self.prep(bom(comp("a", "r1"), deps=[{"ref": "nope", "dependsOn": []}]))
        with self.assertRaises(fd.DtError):
            self.prep(bom(comp("a", "r1"), deps=[{"ref": "r1", "dependsOn": ["nope"]}]))
        with self.assertRaises(fd.DtError):          # 與根元件的 bom-ref 撞名
            self.prep(bom(comp("a", "dumpling:fw-root:acme-box-1.2")))

    def test_nested_components_counted_and_checked(self):
        outer = comp("o", "r1")
        outer["components"] = [comp("i", "r1")]
        with self.assertRaises(fd.DtError):
            self.prep(bom(outer))
        outer["components"] = [comp("i", "r2")]
        info, _ = self.prep(bom(outer), out="p2")
        self.assertEqual(info["summary"]["components"], 2)

    def test_bad_inputs(self):
        s = self.sample()
        for text in ("not json", "[]", json.dumps({"bomFormat": "SPDX"}), json.dumps(bom()),
                     json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": {}}),
                     "[" * 5000 + "]" * 5000):
            b = self.w("bad.json", text)
            with self.assertRaises(fd.DtError, msg=text[:30]):
                fd.prep(b, s, os.path.join(self.tmp, "o"))
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "o", "sbom.cdx.json")))
        deep = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [comp("a")], "x": {}}
        cur = deep["x"]
        for _ in range(60):
            cur["n"] = {}
            cur = cur["n"]
        with self.assertRaises(fd.DtError):
            fd.prep(self.w("deep.json", deep), s, os.path.join(self.tmp, "o"))
        with self.assertRaises(fd.DtError):
            fd.prep(os.path.join(self.tmp, "missing.json"), s, os.path.join(self.tmp, "o"))
        with self.assertRaises(fd.DtError):           # 壞的 kind
            fd.prep(self.w("ok.json", bom(comp("a"))), self.w("firmware/x/y/firmware.yml", "kind: foo\n"), os.path.join(self.tmp, "o"))
        with self.assertRaises(fd.DtError):
            fd.prep(self.w("ok.json", bom(comp("a"))), self.w("firmware/x/z/firmware.yml", "- a\n"), os.path.join(self.tmp, "o"))

    def test_size_limit(self):
        old = fd.MAX_BYTES
        fd.MAX_BYTES = 100
        self.addCleanup(setattr, fd, "MAX_BYTES", old)
        with self.assertRaises(fd.DtError):
            fd.prep(self.w("big.json", bom(comp("a" * 200))), self.sample(), os.path.join(self.tmp, "o"))

    def test_symlink_rejected(self):
        b = self.w("real.json", bom(comp("a")))
        link = os.path.join(self.tmp, "link.json")
        os.symlink(b, link)
        with self.assertRaises(fd.DtError):
            fd.prep(link, self.sample(), os.path.join(self.tmp, "o"))


class ExpectedTests(Base):
    def test_two_formats(self):
        doc = bom(comp("cse", "r1", cpe="cpe:2.3:o:i:c:1:*:*:*:*:*:*:*"), comp("edk2", "r2", purl="pkg:github/t/e@1", va="NOT_ASSESSED"),
                  comp("mc", "r3"))
        _, o = self.prep(doc)
        exp, own = fd.expected(o)
        self.assertEqual(sorted(exp), sorted(["project_name", "project_version", "components", "min_findings_total",
                                              "min_findings_by_purl_type", "informational_purl_types"]))
        self.assertEqual((exp["components"], exp["min_findings_total"], exp["min_findings_by_purl_type"]), (3, 0, {}))
        self.assertEqual(exp["informational_purl_types"], ["github"])
        self.assertEqual(json.load(open(os.path.join(o, "expected.json"))), exp)
        names = {c["name"]: c["reason"] for c in own["no_data_components"]}
        self.assertEqual(set(names), {"cse", "mc"})
        self.assertTrue(names["cse"].startswith("no-purl-cpe-only"))
        self.assertEqual(names["mc"], "no-purl-no-cpe")
        self.assertEqual(own["components_total"], 3)
        self.assertEqual(own["not_assessed_count"], 3)
        self.assertTrue(os.path.isfile(os.path.join(o, "firmware-dt-expected.json")))

    def test_identical_components_merge_in_count(self):
        _, o = self.prep(bom(comp("a", "r1"), comp("a", "r2")))
        exp, own = fd.expected(o)
        self.assertEqual((exp["components"], own["components_total"]), (1, 2))

    def test_components_differing_only_by_hash_merge_like_dt(self):
        a, b = comp("fsp", "r1"), comp("fsp", "r2")
        a["hashes"] = [{"alg": "SHA-256", "content": "aa" * 32}]
        b["hashes"] = [{"alg": "SHA-256", "content": "bb" * 32}]
        _, o = self.prep(bom(a, b, comp("other", "r3")))
        exp, own = fd.expected(o)
        self.assertEqual((exp["components"], own["components_total"]), (2, 3))

    def test_tampered_prep_rejected(self):
        _, o = self.prep(bom(comp("a", "r1")))
        p = os.path.join(o, "dt-project.json")
        d = json.load(open(p))
        d["project_name"] = "../evil"
        json.dump(d, open(p, "w"))
        with self.assertRaises(fd.DtError):
            fd.expected(o)


class ReportTests(Base):
    def run_report(self, preps, dt=None):
        buf = io.StringIO()
        argv = ["report", "--prep"] + preps + ["--out", os.path.join(self.tmp, "rep")]
        if dt:
            argv += ["--dt-result", dt]
        with redirect_stdout(buf):
            rc = fd.main(argv)
        md = ""
        mp = os.path.join(self.tmp, "rep", "firmware-dt.md")
        if os.path.isfile(mp):
            with open(mp, encoding="utf-8") as fh:
                md = fh.read()
        return rc, buf.getvalue(), md

    def dt_sample(self, info, tsv_rows, summary=None, grype=None, root="dt"):
        d = os.path.join(root, info["project_name"])
        self.w("%s/scan/status.tsv" % d, "stage\tstatus\tdetail\n" + "".join("%s\t%s\t%s\n" % r for r in tsv_rows))
        if summary is not None:
            self.w("%s/summary.json" % d, summary)
        if grype is not None:
            self.w("%s/scan/scan/grype.json" % d, grype)
        return os.path.join(self.tmp, root)

    GOOD = [("D-dt-project", "OK", "x"), ("D-dt-upload", "OK", "x"), ("D-dt-bom-processing", "OK", "x"), ("C-grype", "OK", "3 matches")]
    SUMM = {"components": 2, "findings_total": 0, "checks": [{"name": "專案存在", "status": "OK", "detail": ""}]}

    def test_csme_cpe_and_advisory_properties_pass_through_prep(self):
        """prep 不加、不改、不拿掉 cpe 與 dumpling:advisory-*：Intel CSME 的 CPE（來源已查證）原樣上傳，並統計 advisory-match。"""
        cpe = "cpe:2.3:o:intel:converged_security_management_engine_firmware:14.0.47:*:*:*:*:*:*:*"
        me = comp("Intel CSE firmware", "r1", version="14.0.47.1558", cpe=cpe)
        me["properties"] += [{"name": "dumpling:advisory-match", "value": "NOT_ASSESSED"}, {"name": "dumpling:cpe-note", "value": "NVD incomplete"}]
        uc = comp("Intel CPU microcode 000806EC", "r2", version="0xF8")
        uc["properties"] += [{"name": "dumpling:advisory-match", "value": "affected-candidate"},
                             {"name": "dumpling:advisory-candidates", "value": "INTEL-SA-00898"}]
        doc = bom(me, uc)
        before = copy.deepcopy(doc["components"])
        info, o = self.prep(doc)
        out = json.load(open(os.path.join(o, "sbom.cdx.json"), encoding="utf-8"))
        self.assertEqual(out["components"], before)
        self.assertEqual(out["components"][0]["cpe"], cpe)
        self.assertEqual(info["summary"]["with_cpe"], 1)
        self.assertEqual(info["summary"]["advisory_match"], {"NOT_ASSESSED": 1, "affected-candidate": 1})
        self.assertEqual(info["summary"]["vuln_assessment"], {"NOT_ASSESSED": 2})          # 候選公告不改變漏洞比對狀態
        rc, _, md = self.run_report([o])
        self.assertIn("公告比對", md)
        self.assertIn("affected-candidate=1", md)
        self.assertIn("沒有任何一項代表沒有漏洞", md)

    def test_amd_components_are_counted_without_calling_them_intel(self):
        """AMD 的微碼、PSP、AGESA 元件的 advisory-match（NOT_ASSESSED）：摘要標籤中性，「怎麼讀」寫明 AMD 也是資料庫沒有資料。"""
        amd = []
        for i, name in enumerate(("AMD CPU microcode (equivalence id 0x8082)", "AMD PSP firmware SMU (type 0x08, subprogram 0)", "AMD AGESA")):
            c = comp(name, "a%d" % i, version="1.0")
            c["properties"] += [{"name": "dumpling:advisory-match", "value": "NOT_ASSESSED"}, {"name": "dumpling:advisory-basis", "value": "AMD-SB not matched"}]
            amd.append(c)
        info, o = self.prep(bom(*amd))
        self.assertEqual(info["summary"]["advisory_match"], {"NOT_ASSESSED": 3})
        rc, _, md = self.run_report([o])
        self.assertIn("公告比對（dumpling:advisory-match）：NOT_ASSESSED=3", md)
        self.assertNotIn("Intel 微碼與 ME", md)
        self.assertIn("AMD 的微碼、PSP 韌體、AGESA 元件也是 `advisory-match=NOT_ASSESSED`：資料庫沒有資料，以 AMD 公告為準", md)
        self.assertNotIn("PASS", md)

    def test_not_run_without_dt(self):
        _, o = self.prep(bom(comp("a", "r1")))
        rc, out, md = self.run_report([o])
        self.assertEqual(rc, 0)
        self.assertTrue(out.startswith("FIRMWARE-DT\tNOT_RUN\t"), out)
        self.assertIn("NOT_RUN", md)
        self.assertIn("0 筆不代表沒有漏洞", md)
        self.assertIn("NOT_ASSESSED", md)
        self.assertNotIn("PASS", md)
        self.assertNotIn("安全。", md.replace("沒有整體通過或安全的結論", ""))

    def test_untrusted_text_in_report_is_neutralized_once(self):
        info, o = self.prep(bom(comp("a", "r1")))
        rows = [r if r[0] != "D-dt-upload" else ("[evil](http://e)", "FAIL", "x") for r in self.GOOD]
        summ = dict(self.SUMM, checks=[{"name": "<img src=x>\u202e|檢查", "status": "FAIL", "detail": ""},
                                      {"name": "[nr](http://e)", "status": "NOT_RUN", "detail": ""}])
        rc, out, md = self.run_report([o], self.dt_sample(info, rows, summ, {"matches": []}))
        for text in (out, md):
            self.assertNotIn("](", text)
            self.assertNotIn("\u202e", text)
            self.assertNotRegex(text.replace("|", ""), r"(?<!\\)[<>\[\]]")
        self.assertIn("\\[evil\\]\\(http\\://e\\)", md)           # 跳脫一次（不是兩次）
        self.assertNotIn("\\\\[", md)
        self.assertIn("\\<img src=x\\>", md)

    def test_not_run_when_dt_dir_lacks_sample(self):
        _, o = self.prep(bom(comp("a", "r1")))
        os.makedirs(os.path.join(self.tmp, "dt"))
        rc, out, _ = self.run_report([o], os.path.join(self.tmp, "dt"))
        self.assertTrue(out.startswith("FIRMWARE-DT\tNOT_RUN\t"))

    def test_ok_and_attention(self):
        info, o = self.prep(bom(comp("a", "r1", purl="pkg:github/a/b@1", va="NONE"), comp("b", "r2", purl="pkg:github/a/c@1", va="NONE")))
        dt = self.dt_sample(info, self.GOOD, self.SUMM, {"matches": [{}, {}, {}]})
        rc, out, md = self.run_report([o], dt)
        self.assertEqual(rc, 0)
        self.assertTrue(out.startswith("FIRMWARE-DT\tOK\t"), out)
        self.assertIn("OK（3 筆）", md)
        info2, o2 = self.prep(bom(comp("a", "r1"), comp("b", "r2")), slug="other", out="prep2")
        dt = self.dt_sample(info2, self.GOOD, self.SUMM, {"matches": []}, root="dt2")
        rc, out, _ = self.run_report([o2], dt)
        self.assertTrue(out.startswith("FIRMWARE-DT\tATTENTION\t"), out)

    def test_fail_cases(self):
        info, o = self.prep(bom(comp("a", "r1")))
        bad_upload = [r if r[0] != "D-dt-upload" else ("D-dt-upload", "FAIL", "http=500") for r in self.GOOD]
        rc, out, _ = self.run_report([o], self.dt_sample(info, bad_upload, self.SUMM, {"matches": []}))
        self.assertEqual(rc, 1)
        self.assertTrue(out.startswith("FIRMWARE-DT\tFAIL\t"))
        summ = dict(self.SUMM, checks=[{"name": "元件數", "status": "FAIL", "detail": ""}])
        rc, out, _ = self.run_report([o], self.dt_sample(info, self.GOOD, summ, {"matches": []}, root="dt2"))
        self.assertEqual(rc, 1)
        self.assertIn("元件數", out)
        rc, out, _ = self.run_report([o], self.dt_sample(info, self.GOOD, self.SUMM, "{not json", root="dt3"))
        self.assertTrue(out.startswith("FIRMWARE-DT\tFAIL\t"))
        rc, out, _ = self.run_report([o], self.dt_sample(info, self.GOOD, "{broken", {"matches": []}, root="dt4"))
        self.assertTrue(out.startswith("FIRMWARE-DT\tFAIL\t"))

    def test_gap_when_wait_rc_3_or_grype_not_run(self):
        info, o = self.prep(bom(comp("a", "r1", purl="pkg:github/a/b@1", va="NONE")))
        dt = self.dt_sample(info, self.GOOD, self.SUMM, {"matches": []})
        self.w("dt/dt-wait.rc", "3\n")
        rc, out, md = self.run_report([o], dt)
        self.assertEqual(rc, 0)
        self.assertTrue(out.startswith("FIRMWARE-DT\tGAP\t"), out)
        self.assertIn("資料不完整", out)
        rows = [r if r[0] != "C-grype" else ("C-grype", "NOT_RUN", "資料庫不可用") for r in self.GOOD]
        dt = self.dt_sample(info, rows, self.SUMM, None, root="dt2")
        rc, out, _ = self.run_report([o], dt)
        self.assertTrue(out.startswith("FIRMWARE-DT\tGAP\t"), out)

    # ---- expected_dt（樣本宣告 DT 會拒收）：宣告／沒宣告 × 拒收／成功
    # DT 5.2.0 的實際回應（Actions run 43266687645 的 status.tsv；sca-scan 只留回應的前 200 bytes）
    REAL_400 = ('http=400 {"status":400,"title":"The uploaded BOM is invalid","detail":"Schema validation failed","errors":'
                '["/components/0/licenses/18/license: must be valid to one and only one schema, but 0 are valid","/compo')
    ED = 'expected_dt:\n  upload: rejected\n  reason: "供應商 SBOM 不符 schema"\n'
    PRE = [(x, "OK", "x") for x in fd.REJECT_PRE_OK if x != "D-dt-project"]
    REJ = PRE + [("D-dt-project", "OK", "x"), ("D-dt-upload", "FAIL", REAL_400),
                 ("D-dt-bom-processing", "NOT_RUN", "上傳失敗"), ("D-dt-vuln-analysis", "NOT_RUN", "上傳失敗")]
    REJ_SUMM = {"components": 0, "findings_total": 0, "checks": [
        {"name": "專案存在", "status": "OK", "detail": ""}, {"name": "弱點分析完成", "status": "FAIL", "detail": ""},
        {"name": "元件數", "status": "FAIL", "detail": ""}, {"name": "漏洞總數", "status": "OK", "detail": ""}]}

    def rej_case(self, declared, rows, summ, root):
        info, o = self.prep(bom(comp("a", "r1")), slug="sup-" + root, out="p-" + root, kind="sbom",
                            version=("firmware_version: 1.0\n" + (self.ED if declared else "")))
        return o, self.dt_sample(info, rows, summ, {"matches": []}, root=root)

    def test_declared_and_rejected_is_fail_but_accepted(self):
        o, dt = self.rej_case(True, self.REJ, self.REJ_SUMM, "d1")
        rc, out, md = self.run_report([o], dt)
        self.assertEqual(rc, 0)                                     # 與宣告一致：不讓 job 失敗
        self.assertTrue(out.startswith("FIRMWARE-DT\tFAIL\t"), out)  # 狀態照實寫
        self.assertIn("與 firmware.yml 宣告的 expected_dt 一致", out)
        self.assertIn("供應商 SBOM 不符 schema", out)
        self.assertIn("弱點分析完成、元件數", out)                      # 合併成一則說明
        self.assertNotIn("dt-verify FAIL", out)                       # 不重複報
        self.assertEqual(out.count("sca-scan FAIL 階段"), 0)

    def test_declared_rejected_with_unrelated_failures_is_not_accepted(self):
        bad_summ = dict(self.REJ_SUMM, checks=self.REJ_SUMM["checks"] + [{"name": "專案存在2", "status": "FAIL", "detail": ""}])
        o, dt = self.rej_case(True, self.REJ, bad_summ, "d2")
        rc, out, _ = self.run_report([o], dt)
        self.assertEqual(rc, 1)
        self.assertIn("專案存在2", out)
        self.assertIn("不放行", out)
        rows = [r if r[0] != "C-grype" else ("C-grype", "FAIL", "x") for r in self.REJ]
        o, dt = self.rej_case(True, rows, self.REJ_SUMM, "d3")
        self.assertEqual(self.run_report([o], dt)[0], 1)
        rows = [r for r in self.REJ if r[0] != "B-sandbox"] + [("B-sandbox", "GAP", "x")]       # 上傳之前的必要階段不是 OK
        o, dt = self.rej_case(True, rows, self.REJ_SUMM, "d4")
        rc, out, _ = self.run_report([o], dt)
        self.assertEqual(rc, 1)
        self.assertIn("B-sandbox", out)
        rows = self.REJ + [("C-sbomgate", "FAIL", "x")]                                         # 別的 FAIL 階段
        o, dt = self.rej_case(True, rows, self.REJ_SUMM, "d5")
        self.assertEqual(self.run_report([o], dt)[0], 1)

    def test_declared_but_uploaded_ok_is_mismatch(self):
        o, dt = self.rej_case(True, self.GOOD, self.SUMM, "d6")
        rc, out, _ = self.run_report([o], dt)
        self.assertEqual(rc, 1)
        self.assertTrue(out.startswith("FIRMWARE-DT\tMISMATCH\t"), out)
        self.assertIn("供應商可能修好了", out)

    def test_not_declared_and_rejected_is_plain_fail(self):
        o, dt = self.rej_case(False, self.REJ, self.REJ_SUMM, "d7")
        rc, out, _ = self.run_report([o], dt)
        self.assertEqual(rc, 1)
        self.assertTrue(out.startswith("FIRMWARE-DT\tFAIL\t"), out)
        self.assertIn("沒有宣告 expected_dt", out)
        self.assertNotIn("一致", out)

    def test_not_declared_and_ok_is_unchanged(self):
        o, dt = self.rej_case(False, self.GOOD, self.SUMM, "d8")
        rc, out, _ = self.run_report([o], dt)
        self.assertEqual(rc, 0)
        self.assertTrue(out.startswith("FIRMWARE-DT\tATTENTION\t"), out)

    def test_declared_non_400_failure_is_not_a_rejection(self):
        rows = [r if r[0] != "D-dt-upload" else ("D-dt-upload", "FAIL", "http=500 x") for r in self.REJ]
        o, dt = self.rej_case(True, rows, self.REJ_SUMM, "d9")
        rc, out, _ = self.run_report([o], dt)
        self.assertEqual(rc, 1)
        self.assertIn("不是 DT 的「BOM 不符 schema」拒收", out)

    def test_declared_other_400_is_not_a_rejection(self):
        # 驗證代理重現的情形：400 但原因是 dumpling 自己的參數錯誤，不能當成宣告的拒收放行
        others = ('http=400 {"title":"projectName must not be blank"}',
                  'http=400 {"status":400,"title":"Bad Request","detail":"The uploaded BOM is invalid"}',   # 字串出現在別的欄位
                  'http=400 x{"status":400,"title":"The uploaded BOM is invalid","detail":"Schema validation failed"}',
                  'http=400 {"status":400,"title":"The uploaded BOM is invalid","detail":"Schema validation failedX"}',
                  'http=4000 {"status":400,"title":"The uploaded BOM is invalid","detail":"Schema validation failed"}',
                  'http=400 ')
        for i, d in enumerate(others):
            rows = [r if r[0] != "D-dt-upload" else ("D-dt-upload", "FAIL", d) for r in self.REJ]
            o, dt = self.rej_case(True, rows, self.REJ_SUMM, "o%d" % i)
            rc, out, _ = self.run_report([o], dt)
            self.assertEqual(rc, 1, d)
            self.assertTrue(out.startswith("FIRMWARE-DT\tFAIL\t"), out)
            self.assertNotIn("一致", out, d)
            self.assertIn("不是 DT 的「BOM 不符 schema」拒收", out)
            o, dt = self.rej_case(False, rows, self.REJ_SUMM, "n%d" % i)                 # 沒宣告：一般 FAIL，不說「DT 拒收」
            rc, out, _ = self.run_report([o], dt)
            self.assertEqual(rc, 1, d)
            self.assertNotIn("BOM 不符 schema）；firmware.yml 沒有宣告", out)

    def test_declared_without_upload_result_fails(self):
        # 宣告了 expected_dt 卻沒有上傳結果（例如沒有 PILOT_ENV）：狀態照實 NOT_RUN／GAP，但 report 以 1 結束（與沒宣告的樣本一致）
        nr = [r for r in self.PRE] + [(x, "NOT_RUN", "沒有 PILOT_ENV") for x in ("D-dt-project", "D-dt-upload", "D-dt-bom-processing", "D-dt-vuln-analysis")]
        o, dt = self.rej_case(True, nr, None, "u1")
        rc, out, _ = self.run_report([o], dt)
        self.assertEqual(rc, 1)
        self.assertTrue(out.startswith("FIRMWARE-DT\tNOT_RUN\t"), out)
        self.assertIn("沒有上傳結果可核對宣告", out)
        info, o2 = self.prep(bom(comp("a", "r1")), slug="sup-u2", out="p-u2", kind="sbom", version="firmware_version: 1.0\n" + self.ED)
        os.makedirs(os.path.join(self.tmp, "empty-dt"))
        rc, out, _ = self.run_report([o2], os.path.join(self.tmp, "empty-dt"))      # 完全沒有這個樣本的 DT 結果
        self.assertEqual(rc, 1)
        self.assertIn("沒有上傳結果可核對宣告", out)
        o, dt = self.rej_case(False, nr, None, "u3")                                   # 沒宣告：report 本身不因 NOT_RUN 失敗（由 firmware-dt.sh 的必要階段檢查擋）
        self.assertEqual(self.run_report([o], dt)[0], 0)

    def test_expected_dt_validation(self):
        for bad in ("expected_dt: yes\n", "expected_dt:\n  upload: accepted\n  reason: x\n",
                    "expected_dt:\n  upload: rejected\n", "expected_dt:\n  upload: rejected\n  reason: x\n  extra: 1\n",
                    "expected_dt:\n  upload: rejected\n  reason: ''\n"):
            s = self.sample("bad-" + str(abs(hash(bad)) % 1000), kind="sbom", version="firmware_version: 1\n" + bad)
            b = self.w("in/b.json", bom(comp("a", "r1")))
            with self.assertRaises(fd.DtError, msg=bad):
                fd.prep(b, s, os.path.join(self.tmp, "pbad"))

    def test_multi_samples_one_line_each(self):
        _, o1 = self.prep(bom(comp("a", "r1")), slug="s1", out="p1")
        _, o2 = self.prep(bom(comp("a", "r1")), slug="s2", out="p2")
        rc, out, md = self.run_report([o1, o2])
        self.assertEqual(len(out.strip().splitlines()), 2)
        self.assertIn("s1", md)
        self.assertIn("s2", md)

    def test_bad_args_and_prep_dir(self):
        with redirect_stdout(io.StringIO()), open(os.devnull, "w") as dn:
            old = sys.stderr
            sys.stderr = dn
            try:
                self.assertEqual(fd.main([]), 64)
                self.assertEqual(fd.main(["prep", "--sbom", "a"]), 64)
            finally:
                sys.stderr = old
        rc, out, _ = self.run_report([os.path.join(self.tmp, "nope")])
        self.assertEqual(rc, 1)
        self.assertIn("FAIL", out)


class RealSbomTest(Base):
    """用合成 ROM 跑 pipeline/firmware-bios.sh 得到真的 SBOM，再走 prep → expected → report。"""

    def test_synthetic_vbios_end_to_end(self):
        rom = os.path.join(self.tmp, "synthetic-nvidia-option-rom.rom")
        subprocess.run([sys.executable, "-I", os.path.join(ROOT, "tools/cra/tests/synthetic_vbios.py"), "--out", rom],
                       check=True, capture_output=True)
        out = os.path.join(self.tmp, "fw")
        subprocess.run([os.path.join(ROOT, "pipeline/firmware-bios.sh"), rom, "--out", out], capture_output=True)
        sbom = os.path.join(out, "fw.cdx.json")
        if not os.path.isfile(sbom):
            self.skipTest("firmware-bios.sh 沒有產出 SBOM")
        yml = os.path.join(ROOT, "firmware/vbios/standalone-nvidia-option-rom/firmware.yml")
        res = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "pipeline/lib/firmware_dt.py"), "prep", "--sbom", sbom,
                              "--sample", yml, "--out", os.path.join(self.tmp, "p")], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        with open(os.path.join(self.tmp, "p", "dt-project.json")) as fh:
            info = json.load(fh)
        self.assertEqual(info["project_name"], "firmware-vbios-synthetic-standalone-nvidia-option-rom")
        self.assertTrue(info["synthetic"])
        self.assertEqual(info["summary"]["vuln_assessment"], {"NOT_ASSESSED": 1})
        fd.expected(os.path.join(self.tmp, "p"))


if __name__ == "__main__":
    unittest.main()
