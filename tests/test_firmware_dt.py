"""firmware_dt.py（prep／expected／report）的單元測試。不連網、不起 Docker、不需要 grype。"""
import copy
import hashlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import time
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
        self.assertEqual(info["replaced_metadata_component"], {"name": "old", "version": "9", "purl": None})
        doc["metadata"]["component"]["purl"] = "pkg:generic/old@9"
        info, _ = self.prep(doc)
        self.assertEqual(info["replaced_metadata_component"], {"name": "old", "version": "9", "purl": "pkg:generic/old@9"})
        doc["metadata"]["component"]["purl"] = ["not", "a", "string"]
        info, _ = self.prep(doc)
        self.assertIsNone(info["replaced_metadata_component"]["purl"])
        doc["metadata"]["component"].update(name=["x"], version=5)
        info, _ = self.prep(doc)
        self.assertEqual(info["replaced_metadata_component"], {"name": None, "version": None, "purl": None})
        doc["metadata"]["component"].update(name="n" * 1000, version="v" * 1000, purl="p" * 1000)
        info, _ = self.prep(doc)
        self.assertEqual(info["replaced_metadata_component"], {"name": "n" * 300, "version": "v" * 300, "purl": "p" * 300})

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


class ReportBase(Base):
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

    # sca-scan 的 11 個必要階段（和 firmware-dt.sh 的 need 清單相同，見 test_required_stages_match_firmware_dt_sh）
    GOOD = [(st, "OK", "3 matches" if st == "C-grype" else "x") for st in fd.REQUIRED_STAGES]
    CHECKS = [{"name": n, "status": "OK", "detail": ""} for n in fd.REQUIRED_VERIFY_CHECKS] + [{"name": "依生態系的漏洞數", "status": "OK", "detail": ""}]
    SUMM = {"components": 2, "findings_total": 0, "checks": CHECKS}


class ReportTests(ReportBase):
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

    def test_nvidia_vbios_advisory_match_is_counted_and_explained(self):
        """NVIDIA vBIOS 元件的 advisory-match（affected／fixed／NOT_ASSESSED）：計數照 property 值，「怎麼讀」寫明多數是 NOT_ASSESSED、fixed 不代表沒有其他漏洞。"""
        vs = []
        for i, m in enumerate(("NOT_ASSESSED", "affected", "fixed")):
            c = comp("NVIDIA VBIOS 24%02d" % i, "v%d" % i, version="94.04.5E.00.9%d" % i)
            c["properties"] += [{"name": "dumpling:advisory-match", "value": m}, {"name": "dumpling:advisory-basis", "value": "table row"}]
            vs.append(c)
        info, o = self.prep(bom(*vs), kind="vbios")
        self.assertEqual(info["summary"]["advisory_match"], {"NOT_ASSESSED": 1, "affected": 1, "fixed": 1})
        rc, _, md = self.run_report([o])
        self.assertIn("affected=1", md)
        self.assertIn("NVIDIA vBIOS 元件另有 `advisory-match`", md)
        self.assertIn("所以多數是 NOT_ASSESSED：資料庫沒有資料，以廠商公告為準", md)
        self.assertIn("fixed 不代表沒有其他漏洞，沒有任何一項代表沒有漏洞", md)
        self.assertNotIn("PASS", md)

    EVIL = "x|y\n# 標題\n[點我](http://evil.example/a)\n<b>z</b>"

    def test_supplier_sbom_advisory_match_is_not_trusted_and_not_injected(self):
        """供應商 SBOM（kind: sbom）自帶的 dumpling:advisory-match 不採信：不計入 advisory_match、不進報告；只記「供應商自帶標記」。"""
        for val in (self.EVIL, "up-to-date", "NOT_ASSESSED"):
            c = comp("a", "r1", version="1.0")
            c["properties"] += [{"name": "dumpling:advisory-match", "value": val}]
            info, o = self.prep(bom(c), kind="sbom", out="p-sup-%d" % len(val))
            self.assertEqual(info["summary"]["advisory_match"], {}, val)
            self.assertEqual(info["summary"]["supplier_markers"], 1, val)
            rc, out, md = self.run_report([o])
            self.assertNotIn("公告比對（dumpling:advisory-match）", md, val)
            self.assertNotIn("evil.example", md)
            self.assertNotIn("# 標題", md)
            self.assertNotIn("<b>", md)
            self.assertNotIn("evil.example", out)

    def test_own_sbom_unknown_advisory_match_value_is_not_injected(self):
        """本工具產的 SBOM（bios）的 advisory-match 只認四個固定值；其他值（含 markdown、換行、非字串、多個不同值）不原樣進報告。"""
        cases = [(self.EVIL, "(不認得的值)"), ("up-to-date ", "(不認得的值)"), ("", "(不認得的值)"), (None, "(不認得的值)")]
        for i, (val, want) in enumerate(cases):
            c = comp("a", "r1", version="1.0")
            c["properties"] += [{"name": "dumpling:advisory-match", "value": val}]
            info, o = self.prep(bom(c), kind="bios", out="p-own-%d" % i)
            self.assertEqual(info["summary"]["advisory_match"], {want: 1}, repr(val))
            rc, out, md = self.run_report([o])
            self.assertRegex(md, r"公告比對（dumpling:advisory-match）：\\\(不認得的值\\\)=1")      # 標籤經 _cell（括號會被跳脫）
            self.assertNotIn("evil.example", md)
            self.assertNotIn("# 標題", md)
            self.assertNotIn("<b>", md)
        c = comp("a", "r1", version="1.0")
        c["properties"] += [{"name": "dumpling:advisory-match", "value": "up-to-date"}, {"name": "dumpling:advisory-match", "value": "older-no-sa"}]
        info, _ = self.prep(bom(c), kind="bios", out="p-own-multi")
        self.assertEqual(info["summary"]["advisory_match"], {"(多個值)": 1})
        # 報告讀到被竄改的 dt-project.json（summary 的鍵含 markdown）時，仍經 _cell
        info, o = self.prep(bom(comp("b", "r2", version="1.0")), kind="bios", out="p-own-tamper")
        pj = os.path.join(o, "dt-project.json")
        d = json.load(open(pj, encoding="utf-8"))
        d["summary"]["advisory_match"] = {self.EVIL: 1}
        open(pj, "w", encoding="utf-8").write(json.dumps(d))
        rc, out, md = self.run_report([o])
        self.assertNotIn("](", md)                       # 連結語法被跳脫
        self.assertNotIn("\n# 標題", md)                  # 換行被取代，不會多出標題行
        self.assertNotIn("<b>", md)
        self.assertEqual(len([l for l in md.splitlines() if l.startswith("- 公告比對")]), 1)

    def test_supplier_sbom_own_affected_and_fixed_are_not_trusted(self):
        """kind: sbom（供應商 SBOM）自帶的 dumpling:advisory-match=affected／fixed 不採信、不進報告；其他 kind 的照計。"""
        for i, val in enumerate(("affected", "fixed", "Fixed", "affected-candidate")):
            c = comp("a", "r1", version="1.0")
            c["properties"] += [{"name": "dumpling:advisory-match", "value": val}, {"name": "dumpling:advisory-bulletins", "value": "9999"}]
            info, o = self.prep(bom(c), kind="sbom", out="s%d" % i)
            self.assertEqual(info["summary"]["advisory_match"], {}, val)
            rc, out, md = self.run_report([o])
            self.assertNotIn("affected=", md)
            self.assertNotIn("fixed=", md)
            self.assertNotIn("公告比對（dumpling:advisory-match）", md)
        c = comp("a", "r1", version="1.0")
        c["properties"] += [{"name": "dumpling:advisory-match", "value": "fixed"}, {"name": "dumpling:vuln-assessment", "value": "OK"}]
        info, _ = self.prep(bom(c), kind="sbom", out="s-mixed")
        self.assertEqual(info["summary"]["advisory_match"], {})
        self.assertIsNone(info["summary"]["vuln_assessment"].get("OK"))
        for kind in ("bios", "vbios"):
            c = comp("a", "r1", version="1.0")
            c["properties"] += [{"name": "dumpling:advisory-match", "value": "fixed"}]
            info, _ = self.prep(bom(c), kind=kind, out="own-" + kind)
            self.assertEqual(info["summary"]["advisory_match"], {"fixed": 1})

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
        dt = self.dt_sample(info, self.GOOD, self.SUMM, {"matches": []})
        rc, out, md = self.run_report([o], dt)
        self.assertEqual(rc, 0)
        self.assertTrue(out.startswith("FIRMWARE-DT\tOK\t"), out)
        self.assertIn("OK（0 筆）", md)
        # Grype 有比對結果就不能是 OK（需要人審）
        dt = self.dt_sample(info, self.GOOD, self.SUMM, {"matches": [{}, {}, {}]}, root="dt-g")
        rc, out, md = self.run_report([o], dt)
        self.assertEqual(rc, 0)
        self.assertTrue(out.startswith("FIRMWARE-DT\tATTENTION\t"), out)
        self.assertIn("Grype 有 3 筆比對結果", out)
        self.assertIn("OK（3 筆）", md)
        # DT 有漏洞也不能是 OK
        dt = self.dt_sample(info, self.GOOD, dict(self.SUMM, findings_total=2), {"matches": []}, root="dt-f")
        rc, out, _ = self.run_report([o], dt)
        self.assertTrue(out.startswith("FIRMWARE-DT\tATTENTION\t"), out)
        self.assertIn("DT 有 2 筆比對結果", out)
        info2, o2 = self.prep(bom(comp("a", "r1"), comp("b", "r2")), slug="other", out="prep2")
        dt = self.dt_sample(info2, self.GOOD, self.SUMM, {"matches": []}, root="dt2")
        rc, out, _ = self.run_report([o2], dt)
        self.assertTrue(out.startswith("FIRMWARE-DT\tATTENTION\t"), out)

    def test_supplier_like_sbom_is_not_ok(self):
        # 供應商 SBOM：沒有 dumpling:vuln-assessment 標記、purl 是 pkg:generic → 不能是 OK
        cs = [comp("a", "r1", purl="pkg:generic/a@1"), comp("b", "r2", purl="pkg:github/a/c@1")]
        for c in cs:
            c["properties"] = [x for x in c["properties"] if x["name"] != "dumpling:vuln-assessment"]
        info, o = self.prep(bom(*cs), slug="sup-like", out="p-sl")
        dt = self.dt_sample(info, self.GOOD, self.SUMM, {"matches": []}, root="dt-sl")
        rc, out, _ = self.run_report([o], dt)
        self.assertEqual(rc, 0)
        self.assertTrue(out.startswith("FIRMWARE-DT\tATTENTION\t"), out)
        self.assertIn("pkg:generic 的元件 1 個", out)
        self.assertIn("沒有 dumpling:vuln-assessment 標記的元件 2 個", out)

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


def clean(name="a", ref="r1", **kw):
    """所有欄位都乾淨的元件：有 purl（非 generic）、有 version、vuln-assessment＝NONE、version-status＝OK。"""
    kw.setdefault("purl", "pkg:github/a/b@1")
    kw.setdefault("va", "NONE")
    return comp(name, ref, **kw)


def raw_comp(**fields):
    """不經 comp() 的整理，直接指定欄位（可放壞型別）。"""
    c = {"type": "library", "name": "a", "version": "1"}
    c.update(fields)
    return c


class HardeningTests(ReportBase):
    """用合成輸入釘住「誤判成 OK」的情形：資料不完整、有疑點時一律不是 OK。"""
    n = 0

    def case(self, comps=None, summ=None, rows=None, grype=None, kind="bios", ver="firmware_version: 1.0\n"):
        HardeningTests.n += 1
        slug = "h%d" % HardeningTests.n
        info, o = self.prep(bom(*(comps if comps is not None else [clean()])), slug=slug, out="p-" + slug, kind=kind, version=ver)
        dt = self.dt_sample(info, rows if rows is not None else self.GOOD, self.SUMM if summ is None else summ,
                            {"matches": []} if grype is None else grype, root="dt-" + slug)
        rc, out, md = self.run_report([o], dt)
        return out.split("\t")[1], out, rc

    def status(self, *a, **kw):
        return self.case(*a, **kw)[0]

    def test_baseline_is_ok(self):
        st, out, rc = self.case()
        self.assertEqual((st, rc), ("OK", 0), out)

    # ---- 1. DT／Grype 的比對數
    def test_findings_total_must_be_a_count(self):
        for v in (-3, None, "-", "0", "?", True, False, 1.5, [], {}, float("nan"), float("inf"), "[x](http://e)"):
            st, out, _ = self.case(summ=dict(self.SUMM, findings_total=v))
            self.assertEqual(st, "ATTENTION", repr(v))
            self.assertIn("DT 比對數讀不到", out, repr(v))
            self.assertNotIn("](", out)
        summ = dict(self.SUMM)
        del summ["findings_total"]
        st, out, _ = self.case(summ=summ)
        self.assertEqual(st, "ATTENTION")
        self.assertIn("沒有這個欄位", out)
        self.assertEqual(self.status(summ=dict(self.SUMM, findings_total=0)), "OK")
        st, out, _ = self.case(summ=dict(self.SUMM, findings_total=2))
        self.assertEqual(st, "ATTENTION")
        self.assertIn("DT 有 2 筆", out)

    def test_attention_reasons_count_rule_for_dt_and_grype(self):
        s = fd.summarize([clean()])
        base = {"grype_matches": 0, "dt_findings": 0}
        self.assertEqual(fd.attention_reasons(s, base), [])
        for v in (-3, None, "-", "0", True, 1.5, [], float("nan")):
            for key, label in (("grype_matches", "Grype"), ("dt_findings", "DT")):
                r = dict(base, **{key: v})
                self.assertTrue(any("%s 比對數讀不到" % label in x for x in fd.attention_reasons(s, r)), (key, v))
        self.assertTrue(any("Grype 有 2 筆" in x for x in fd.attention_reasons(s, dict(base, grype_matches=2))))
        self.assertTrue(any("Grype 比對數讀不到" in x for x in fd.attention_reasons(s, {"dt_findings": 0})))      # 缺欄位也是讀不到

    def test_grype_matches_not_a_list_is_fail(self):
        for g in ({"matches": {}}, {"matches": None}, [], {}):
            self.assertEqual(self.status(grype=g), "FAIL", g)

    def _grype_variants(self, tag):
        """C-grype 是 OK 但 grype.json 讀不到或壞掉的各種情形：(名稱, 動作(grype.json 的路徑) → None)。"""
        def missing(p):
            if os.path.lexists(p):
                os.unlink(p)
        def directory(p):
            os.unlink(p)
            os.makedirs(p)
        def symlink(p):
            os.unlink(p)
            os.symlink(os.path.join(self.tmp, "elsewhere-" + tag), p)
        def broken(p):
            with open(p, "w") as fh:
                fh.write("{not json")
        def not_utf8(p):
            with open(p, "wb") as fh:
                fh.write(b'{"matches": [\xff]}')
        def empty(p):
            open(p, "w").close()
        return (("不存在", missing), ("是資料夾", directory), ("是符號連結", symlink), ("不是 JSON", broken), ("不是 UTF-8", not_utf8), ("空檔案", empty))

    def test_grype_json_unreadable_or_broken_is_fail(self):
        open(os.path.join(self.tmp, "elsewhere-g"), "w").write('{"matches": []}')
        for name, act in self._grype_variants("g"):
            HardeningTests.n += 1
            slug = "g%d" % HardeningTests.n
            info, o = self.prep(bom(clean()), slug=slug, out="p-" + slug, kind="bios", version="firmware_version: 1.0\n")
            dt = self.dt_sample(info, self.GOOD, self.SUMM, {"matches": []}, root="dt-" + slug)
            act(os.path.join(dt, info["project_name"], "scan", "scan", "grype.json"))
            rc, out, _ = self.run_report([o], dt)
            self.assertTrue(out.startswith("FIRMWARE-DT\tFAIL\t"), (name, out))
            self.assertEqual(rc, 1, name)
            self.assertIn("grype.json", out, name)

    def test_declared_rejection_with_broken_grype_json_is_not_accepted(self):
        # expected_dt 宣告的拒收只在「沒有別的失敗」時放行：C-grype 是 OK 但 grype.json 壞掉／讀不到，是別的失敗
        self.ED = ReportTests.ED
        open(os.path.join(self.tmp, "elsewhere-r"), "w").write('{"matches": []}')
        rows = ReportTests.REJ + [("C-grype", "OK", "0 matches")]
        o, dt = ReportTests.rej_case(self, True, rows, ReportTests.REJ_SUMM, "hg0")
        rc, out, _ = self.run_report([o], dt)
        self.assertEqual(rc, 0, out)                                      # 對照：grype.json 正常時仍與宣告一致
        self.assertIn("與 firmware.yml 宣告的 expected_dt 一致", out)
        for i, (name, act) in enumerate(self._grype_variants("r")):
            o, dt = ReportTests.rej_case(self, True, rows, ReportTests.REJ_SUMM, "hg%d" % (i + 1))
            with open(os.path.join(o, "dt-project.json"), encoding="utf-8") as fh:
                proj = json.load(fh)["project_name"]
            act(os.path.join(dt, proj, "scan", "scan", "grype.json"))
            rc, out, _ = self.run_report([o], dt)
            self.assertEqual(rc, 1, (name, out))
            self.assertTrue(out.startswith("FIRMWARE-DT\tFAIL\t"), (name, out))
            self.assertIn("不放行", out, name)
            self.assertNotIn("與 firmware.yml 宣告的 expected_dt 一致", out, name)

    # ---- 2. dt-verify 的 checks
    def test_required_checks_must_exist_and_be_ok(self):
        for n in fd.REQUIRED_VERIFY_CHECKS:
            checks = [c for c in self.CHECKS if c["name"] != n]
            st, out, _ = self.case(summ=dict(self.SUMM, checks=checks))
            self.assertEqual(st, "GAP", n)
            self.assertIn("缺少必要檢查：" + n, out)
        for n in fd.REQUIRED_VERIFY_CHECKS:
            checks = [dict(c, status="NOT_RUN") if c["name"] == n else c for c in self.CHECKS]
            st, out, rc = self.case(summ=dict(self.SUMM, checks=checks))
            self.assertEqual((st, rc), ("GAP", 0), n)
            self.assertIn("dt-verify NOT_RUN：" + n, out)
        # 不在必要清單的檢查也不能 NOT_RUN／不認得
        for bad in ("NOT_RUN", "WEIRD", "ok", " OK", "", None, 5):
            checks = self.CHECKS[:-1] + [{"name": "依生態系的漏洞數", "status": bad, "detail": ""}]
            self.assertEqual(self.status(summ=dict(self.SUMM, checks=checks)), "GAP", bad)

    def test_required_check_with_unknown_status_is_gap_not_ok(self):
        for bad in ("WEIRD", "ok", "PASS", "OK ", "GAP"):
            checks = [dict(c, status=bad) if c["name"] == "元件數" else c for c in self.CHECKS]
            st, out, _ = self.case(summ=dict(self.SUMM, checks=checks))
            self.assertEqual(st, "GAP", bad)
            self.assertIn("不認得的檢查狀態", out)

    def test_checks_malformed_is_gap(self):
        for checks in ([], "x", None, {}, 5, [None], ["x"], [{"name": "元件數"}], [{"status": "OK"}], [{"name": 5, "status": "OK"}]):
            st, out, _ = self.case(summ=dict(self.SUMM, checks=checks))
            self.assertEqual(st, "GAP", repr(checks))
        summ = dict(self.SUMM)
        del summ["checks"]
        self.assertEqual(self.status(summ=summ), "GAP")
        # 好的檢查後面多一個格式不對的項目：也不是 OK
        self.assertEqual(self.status(summ=dict(self.SUMM, checks=self.CHECKS + ["x"])), "GAP")

    def test_duplicate_check_names_any_bad_wins(self):
        checks = self.CHECKS + [{"name": "元件數", "status": "FAIL", "detail": ""}]
        st, out, rc = self.case(summ=dict(self.SUMM, checks=checks))
        self.assertEqual((st, rc), ("FAIL", 1), out)
        checks = self.CHECKS + [{"name": "元件數", "status": "NOT_RUN", "detail": ""}]
        self.assertEqual(self.status(summ=dict(self.SUMM, checks=checks)), "GAP")

    def test_dt_components_must_be_positive_int(self):
        for v in (0, -1, "x", "2", None, True, 1.5, [], {}):
            st, out, _ = self.case(summ=dict(self.SUMM, components=v))
            self.assertEqual(st, "GAP", repr(v))
            self.assertIn("元件數不是 >= 1 的整數", out)
        self.assertEqual(self.status(summ=dict(self.SUMM, components=1)), "OK")
        summ = dict(self.SUMM)
        del summ["components"]
        self.assertEqual(self.status(summ=summ), "GAP")

    def test_gap_and_fail_precedence(self):
        # FAIL 優先於 GAP；GAP 的資料不全仍讓 report 以 0 結束（和 wait 結束碼 3 一致，不讓 job 失敗）
        checks = [dict(c, status="FAIL") if c["name"] == "專案存在" else c for c in self.CHECKS][:-1]
        st, out, rc = self.case(summ=dict(self.SUMM, checks=checks))
        self.assertEqual((st, rc), ("FAIL", 1), out)
        self.assertEqual(self.case(summ=dict(self.SUMM, checks=[]))[2], 0)

    # ---- 3. sca-scan 的其他階段
    def test_other_stage_fail_is_fail(self):
        for stage in ("D-dt-vuln-analysis", "C-grype-db", "D-dt-findings", "C-sbomgate", "X-unknown-stage"):
            st, out, rc = self.case(rows=self.GOOD + [(stage, "FAIL", "x")])
            self.assertEqual((st, rc), ("FAIL", 1), stage)
            self.assertIn("sca-scan FAIL 階段：" + stage, out)

    def test_other_stage_not_ok_is_attention_with_reasons(self):
        extra = [("D-dt-data-sources", "GAP", "NVD 沒有 mirror"), ("C-sbomgate", "NOT_ASSESSED", "SBOM EMPTY"),
                 ("A-tools", "ATTENTION", "版本不同"), ("C-mirror-freshness", "NOT_RUN", "未檢查"), ("D-dt-vuln-analysis", "NOT_RUN", "x")]
        st, out, rc = self.case(rows=self.GOOD + extra)
        self.assertEqual((st, rc), ("ATTENTION", 0), out)
        for want in ("D-dt-data-sources GAP", "C-sbomgate NOT_ASSESSED", "A-tools ATTENTION", "C-mirror-freshness NOT_RUN", "D-dt-vuln-analysis NOT_RUN"):
            self.assertIn(fd._cell(want), out)            # 報告裡的不可信文字經 md_safe（底線會跳脫）
        for bad in ("", "WEIRD", "ok", " OK", "OK "):         # 空的、不認得的、前後有空白的狀態也不是 OK
            st, out, _ = self.case(rows=self.GOOD + [("C-x", bad, "x")])
            self.assertEqual(st, "ATTENTION", repr(bad))
            self.assertIn("C-x", out)

    def test_row_with_an_empty_stage_name_is_not_dropped(self):
        # 階段名稱是空的列：FAIL 就是 FAIL，其他非 OK 至少 ATTENTION，不能因為名稱空白被略過而得到 OK
        st, out, rc = self.case(rows=self.GOOD + [("", "FAIL", "boom")])
        self.assertEqual((st, rc), ("FAIL", 1), out)
        self.assertIn(fd._cell(fd.EMPTY_STAGE), out)
        for bad in ("GAP", "NOT_RUN", "ATTENTION", "WEIRD", ""):
            self.assertEqual(self.status(rows=self.GOOD + [("", bad, "x")]), "ATTENTION", repr(bad))
        self.assertEqual(self.status(rows=self.GOOD + [("", "OK", "x")]), "OK")
        p = self.w("empty-stage.tsv", "stage\tstatus\tdetail\n\tFAIL\tboom\nB\tOK\tz\n")
        self.assertEqual(fd.read_status_tsv(p), {fd.EMPTY_STAGE: ("FAIL", "boom"), "B": ("OK", "z")})

    def test_upload_stage_status_must_be_exactly_ok(self):
        for bad in (" OK", "ok", "OK "):
            rows = [r if r[0] != "D-dt-upload" else ("D-dt-upload", bad, "x") for r in self.GOOD]
            self.assertEqual(self.status(rows=rows), "GAP", repr(bad))

    def test_long_duplicate_key_pointer_is_capped(self):
        d = fd.DupKeys()
        k = "k" * 5000
        fd.load_json(self.w("longkey.json", '{"%s": {"a": 1, "a": 2}}' % k), fd.MAX_BYTES, "SBOM", d)
        self.assertEqual(len(d.events[0]["pointer"]), 300)

    def test_long_key_pointer_is_truncated_while_walking(self):
        # 長鍵名（祖先路徑）底下有很多個含重複鍵的物件：位置要一邊走一邊截斷，不能每筆事件都先組出完整路徑（時間 ∝ 鍵長 × 事件數）
        k = "k/~" * (1300 * 1024)                      # 約 3.9 MB 的鍵名；轉義後每個字元組 "k" "~1" "~0"
        inner = "[" + ",".join('{"a":1,"a":2}' for _ in range(fd.MAX_DUP_EVENTS)) + "]"
        path = self.w("longkey2.json", '{"x": {"%s": %s}}' % (k, inner))
        d = fd.DupKeys()
        t0 = time.monotonic()
        fd.load_json(path, fd.MAX_BYTES, "SBOM", d)
        took = time.monotonic() - t0
        self.assertLess(took, 2.0)
        self.assertEqual(d.total, fd.MAX_DUP_EVENTS)
        want = ("/x/" + "k~1~0" * 100)[:fd.POINTER_CAP - 1]
        want = (want[:-1] if want.endswith("~") else want) + fd.POINTER_MARK       # 截斷處加標記，不留半個轉義
        for ev in d.events:
            self.assertEqual(len(ev["pointer"]), len(want))
            self.assertLessEqual(len(ev["pointer"]), fd.POINTER_CAP)
            self.assertEqual(ev["pointer"], want)
        # 沒有長鍵名時完整保留（含索引與轉義）；根物件的位置是 "/"
        d2 = fd.DupKeys()
        fd.load_json(self.w("shortkey.json", '{"a": 1, "a": 2, "b/c": [{"d~": {"e": 1, "e": 2}}]}'), fd.MAX_BYTES, "SBOM", d2)
        self.assertEqual([ev["pointer"] for ev in d2.events], ["/b~1c/0/d~0", "/"])      # 內層物件先完成

    def test_truncated_pointer_has_marker_and_never_splits_an_escape(self):
        for n in range(280, 304):                                  # 讓截斷點落在各個位置（含轉義的中間）
            for ch in ("~", "/", "a"):
                key = "a" * n + ch + "b"
                d = fd.DupKeys()
                fd.load_json(self.w("trunc.json", '{%s: {"v": 1, "v": 2}}' % json.dumps(key)), fd.MAX_BYTES, "SBOM", d)
                ptr = d.events[0]["pointer"]
                self.assertLessEqual(len(ptr), fd.POINTER_CAP, (n, ch))
                if ptr.endswith(fd.POINTER_MARK):
                    body = ptr[:-1]
                    self.assertFalse(body.endswith("~"), (n, ch))
                    self.assertEqual(len(body) + 1 <= fd.POINTER_CAP, True)
                self.assertNotRegex(ptr.replace(fd.POINTER_MARK, ""), r"~(?![01])", (n, ch))      # 每個 ~ 後面都是 0 或 1
        # 沒超過上限的完整保留、沒有標記
        d = fd.DupKeys()
        fd.load_json(self.w("short2.json", '{"%s": [0, {"v": 1, "v": 2}]}' % ("a" * 100)), fd.MAX_BYTES, "SBOM", d)
        self.assertEqual(d.events[0]["pointer"], "/" + "a" * 100 + "/1")
        # 長度剛好 POINTER_CAP 的完整路徑不加標記
        key = "c" * (fd.POINTER_CAP - 1)
        d = fd.DupKeys()
        fd.load_json(self.w("exact.json", '{%s: {"v": 1, "v": 2}}' % json.dumps(key)), fd.MAX_BYTES, "SBOM", d)
        self.assertEqual(d.events[0]["pointer"], "/" + key)
        self.assertEqual(len(d.events[0]["pointer"]), fd.POINTER_CAP)

    def test_locate_memory_is_bounded_by_depth_not_by_array_size(self):
        # 重複鍵的物件在大陣列「之後」：走訪必須逐層用 iterator，不能把整個陣列的子節點一次推進堆疊（記憶體 ∝ 元素數）
        import tracemalloc
        n = 400000
        text = '{"%s": {"L": [%s0]}, "dup": {"x": 1, "x": 2}}' % ("k" * 290, "0," * n)
        d = fd.DupKeys()
        doc = json.loads(text, object_pairs_hook=d.hook)
        self.assertEqual(d.total, 1)
        tracemalloc.start()
        try:
            d.locate(doc)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertEqual(d.events[0]["pointer"], "/dup")
        self.assertLess(peak, 256 * 1024, peak)                  # 舊寫法約 30 MB（400000 個 tuple），這裡只有幾 KB
        # 大陣列裡每個元素都是容器時也一樣：記憶體不隨元素數增加
        text = '{"A": [%s{}], "dup": {"x": 1, "x": 2}}' % ("{}," * 100000)
        d = fd.DupKeys()
        doc = json.loads(text, object_pairs_hook=d.hook)
        tracemalloc.start()
        try:
            d.locate(doc)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertLess(peak, 256 * 1024, peak)
        self.assertEqual(d.events[0]["pointer"], "/dup")

    def test_expected_not_run_stages_are_ignored(self):
        # firmware-dt.sh 固定 --no-license（E 段 NOT_RUN），沒有 --kernel-build（C-kernel-* NOT_RUN）：這些不能讓乾淨樣本變 ATTENTION
        rows = self.GOOD + [("E-notice", "NOT_RUN", "--no-license"), ("E-files-scan", "NOT_RUN", "--no-license"),
                            ("C-kernel-config", "NOT_RUN", "沒給 --kernel-build"), ("C-kernel-module-map", "NOT_RUN", "沒給 --kernel-build")]
        self.assertEqual(self.status(rows=rows), "OK")
        # 但同一組階段不是 NOT_RUN（GAP／FAIL）就照常處理
        self.assertEqual(self.status(rows=self.GOOD + [("E-notice", "GAP", "x")]), "ATTENTION")
        self.assertEqual(self.status(rows=self.GOOD + [("C-kernel-config", "GAP", "x")]), "ATTENTION")
        self.assertEqual(self.status(rows=self.GOOD + [("E-notice", "FAIL", "x")]), "FAIL")

    def test_duplicate_stage_rows_keep_the_worst(self):
        for rows in (self.GOOD + [("D-dt-findings", "FAIL", "x"), ("D-dt-findings", "OK", "y")],
                     self.GOOD + [("D-dt-findings", "OK", "y"), ("D-dt-findings", "FAIL", "x")]):
            self.assertEqual(self.status(rows=rows), "FAIL")
        self.assertEqual(self.status(rows=[r for r in self.GOOD if r[0] != "D-dt-upload"] + [("D-dt-upload", "FAIL", "x"), ("D-dt-upload", "OK", "y")]), "FAIL")
        p = self.w("t.tsv", "stage\tstatus\tdetail\nA\tGAP\tx\nA\tOK\ty\nB\tOK\tz\n")
        self.assertEqual(fd.read_status_tsv(p), {"A": ("GAP", "x"), "B": ("OK", "z")})

    def test_required_stages_match_firmware_dt_sh(self):
        with open(os.path.join(ROOT, "pipeline", "firmware-dt.sh"), encoding="utf-8") as fh:
            m = re.search(r"^else need=\(([^)]*)\); fi$", fh.read(), re.M)
        self.assertIsNotNone(m)
        self.assertEqual(tuple(m.group(1).split()), fd.REQUIRED_STAGES)
        self.assertEqual(len(fd.REQUIRED_STAGES), 11)
        self.assertEqual([r[0] for r in self.GOOD], list(fd.REQUIRED_STAGES))
        self.assertEqual(self.status(), "OK")

    def test_missing_required_stage_row_is_gap_never_ok(self):
        for st in fd.REQUIRED_STAGES:
            rows = [r for r in self.GOOD if r[0] != st]
            s, out, rc = self.case(rows=rows)
            self.assertEqual((s, rc), ("GAP", 0), (st, out))
            self.assertIn("缺少階段 " + st.replace("_", "\\_"), out, st)
        # 只留四列（以前的 GOOD）也不是 OK；缺很多列時全部列出
        four = [r for r in self.GOOD if r[0] in ("D-dt-project", "D-dt-upload", "D-dt-bom-processing", "C-grype")]
        s, out, _ = self.case(rows=four)
        self.assertEqual(s, "GAP")
        for st in fd.REQUIRED_STAGES:
            if st not in ("D-dt-project", "D-dt-upload", "D-dt-bom-processing", "C-grype"):
                self.assertIn(st, out)
        # 階段名稱只差大小寫或空白，不算有這一列
        rows = [r if r[0] != "A-source" else ("a-source", "OK", "x") for r in self.GOOD]
        self.assertEqual(self.status(rows=rows), "GAP")
        rows = [r if r[0] != "A-source" else ("A-source ", "OK", "x") for r in self.GOOD]
        self.assertEqual(self.status(rows=rows), "GAP")
        # FAIL 仍比 GAP 重；其他階段的 ATTENTION 不會把缺列蓋成 ATTENTION
        rows = [r for r in self.GOOD if r[0] != "F-secret-scan"]
        self.assertEqual(self.status(rows=rows + [("C-euvd", "FAIL", "x")]), "FAIL")
        self.assertEqual(self.status(rows=rows + [("C-euvd", "GAP", "x")]), "GAP")
        # 宣告 expected_dt: rejected 且真的被拒收：只核對上傳之前的階段（上傳之後的階段本來就沒有），不因缺少上傳之後的階段而改變
        self.ED = ReportTests.ED
        o, dt = ReportTests.rej_case(self, True, ReportTests.REJ, ReportTests.REJ_SUMM, "hm1")
        rc, out, _ = self.run_report([o], dt)
        self.assertEqual(rc, 0, out)
        self.assertIn("與 firmware.yml 宣告的 expected_dt 一致", out)
        self.assertNotIn("缺少階段", out)
        rows = [r for r in ReportTests.REJ if r[0] != "F-secret-scan"]                           # 上傳之前的必要階段缺列：不放行
        o, dt = ReportTests.rej_case(self, True, rows, ReportTests.REJ_SUMM, "hm2")
        rc, out, _ = self.run_report([o], dt)
        self.assertEqual(rc, 1, out)
        self.assertIn("F-secret-scan", out)

    def test_exactly_one_match_needs_a_person(self):
        s = fd.summarize([clean()])
        self.assertEqual(fd.attention_reasons(s, {"grype_matches": 0, "dt_findings": 0}), [])
        self.assertEqual(fd.attention_reasons(s, {"grype_matches": 1, "dt_findings": 0}), ["Grype 有 1 筆比對結果，需要人審"])
        self.assertEqual(fd.attention_reasons(s, {"grype_matches": 0, "dt_findings": 1}), ["DT 有 1 筆比對結果，需要人審"])
        self.assertEqual(len(fd.attention_reasons(s, {"grype_matches": 1, "dt_findings": 1})), 2)
        self.assertEqual(self.status(grype={"matches": [{}]}), "ATTENTION")
        self.assertEqual(self.status(summ=dict(self.SUMM, findings_total=1)), "ATTENTION")
        self.assertEqual(self.status(grype={"matches": []}), "OK")

    def test_status_tsv_unreadable_without_summary_is_fail(self):
        for kind in ("huge-field", "dir", "dangling", "binary-nul"):
            HardeningTests.n += 1
            slug = "u%d" % HardeningTests.n
            info, o = self.prep(bom(clean()), slug=slug, out="p-" + slug, kind="bios", version="firmware_version: 1.0\n")
            root = "dt-" + slug
            tsv = os.path.join(self.tmp, root, info["project_name"], "scan", "status.tsv")
            os.makedirs(os.path.dirname(tsv))
            if kind == "huge-field":
                self.w(os.path.relpath(tsv, self.tmp), "stage\tstatus\tdetail\nA\tOK\t" + "x" * 200000 + "\n")
            elif kind == "dir":
                os.mkdir(tsv)
            elif kind == "dangling":
                os.symlink(os.path.join(self.tmp, "nowhere"), tsv)
            else:
                with open(tsv, "wb") as fh:
                    fh.write(b"stage\tstatus\tdetail\nA\tOK\t\x00\x00\n")
            rc, out, _ = self.run_report([o], os.path.join(self.tmp, root))
            if kind == "binary-nul":                       # NUL 位元組：csv 讀得動，但沒有必要階段 → 不是 OK
                self.assertNotIn("FIRMWARE-DT\tOK", out, kind)
                continue
            self.assertTrue(out.startswith("FIRMWARE-DT\tFAIL\t"), (kind, out))
            self.assertEqual(rc, 1, kind)

    def test_status_tsv_quote_characters_are_literal(self):
        # 開頭帶 " 的 detail 不能把後面的列吞掉（csv 預設會把引號當欄位界線）
        p = self.w("q.tsv", 'stage\tstatus\tdetail\nA-source\tOK\t"abc\nB-sandbox\tFAIL\tx\n"C-grype"\tGAP\ty\n')
        rows = fd.read_status_tsv(p)
        self.assertEqual(rows["A-source"], ("OK", '"abc'))
        self.assertEqual(rows["B-sandbox"], ("FAIL", "x"))
        self.assertEqual(rows['"C-grype"'], ("GAP", "y"))
        # 端到端：被吞掉的列是 FAIL 時，report 仍是 FAIL
        rows2 = [r if r[0] != "A-source" else ("A-source", "OK", '"abc') for r in self.GOOD] + [("C-euvd", "FAIL", "x")]
        self.assertEqual(self.status(rows=rows2), "FAIL")

    def test_result_files_with_duplicate_keys_are_not_trusted(self):
        # grype.json／summary.json 的同名鍵，後值會蓋掉前值：檔案的意思不明，一律 FAIL（不讓「前面是 FAIL／有比對、後面是 OK」變成 OK）
        st, out, _ = self.case(grype='{"matches": [{}], "matches": []}')
        self.assertEqual(st, "FAIL", out)
        self.assertIn("grype.json 有 1 個重複鍵", out)
        st, out, _ = self.case(summ='{"components": 2, "components": 2, "findings_total": 0, "checks": []}')
        self.assertEqual(st, "FAIL", out)
        self.assertIn("summary.json 有 1 個重複鍵", out)
        bad = json.dumps(self.SUMM)[:-1] + ', "findings_total": 0}'                 # 頂層 findings_total 重複
        st, out, _ = self.case(summ=bad)
        self.assertEqual(st, "FAIL", out)
        nested = json.dumps(self.SUMM).replace('"status": "OK", "detail": ""}', '"status": "FAIL", "status": "OK", "detail": ""}', 1)   # checks 裡的重複鍵
        st, out, _ = self.case(summ=nested)
        self.assertEqual(st, "FAIL", out)
        self.assertEqual(self.status(), "OK")                                       # 對照：沒有重複鍵

    def test_declared_expected_dt_without_a_comparable_result_exits_1(self):
        self.ED = ReportTests.ED
        # GAP（上傳階段 GAP）：狀態照實是 GAP，但宣告了卻沒有結果可核對 → report 以 1 結束
        rows = [r if r[0] != "D-dt-upload" else ("D-dt-upload", "GAP", "x") for r in self.GOOD]
        o, dt = ReportTests.rej_case(self, True, rows, ReportTests.SUMM, "hdg1")
        rc, out, _ = self.run_report([o], dt)
        self.assertTrue(out.startswith("FIRMWARE-DT\tGAP\t"), out)
        self.assertEqual(rc, 1, out)
        self.assertIn("宣告 expected_dt，但沒有上傳結果可核對宣告（狀態 GAP）", out)
        # 沒宣告的同一組結果：GAP 不讓 report 失敗
        o, dt = ReportTests.rej_case(self, False, rows, ReportTests.SUMM, "hdg2")
        rc, out, _ = self.run_report([o], dt)
        self.assertTrue(out.startswith("FIRMWARE-DT\tGAP\t"), out)
        self.assertEqual(rc, 0, out)
        # wait 結束碼 3 造成的 GAP 也一樣
        o, dt = ReportTests.rej_case(self, True, self.GOOD, ReportTests.SUMM, "hdg3")
        self.w("hdg3/dt-wait.rc", "3\n")
        rc, out, _ = self.run_report([o], dt)
        self.assertEqual(rc, 1, out)

    def test_duplicate_stage_rows_severity_order_all_pairs(self):
        order = ["OK", "ATTENTION", "NOT_ASSESSED", "NOT_RUN", "GAP", "FAIL"]       # 輕 → 重（測試自己寫死，不讀 fd._SEV）
        for i, a in enumerate(order):
            for j, b in enumerate(order):
                if i == j:
                    continue
                p = self.w("sev-%d-%d.tsv" % (i, j), "stage\tstatus\tdetail\nA\t%s\tfirst\nA\t%s\tsecond\n" % (a, b))
                self.assertEqual(fd.read_status_tsv(p)["A"][0], order[max(i, j)], (a, b))
        # 不認得的狀態比 OK 重、比 ATTENTION 輕；兩個都不認得時留後面那一列
        for first, second, want in (("OK", "weird", "weird"), ("weird", "OK", "weird"), ("weird", "ATTENTION", "ATTENTION"), ("ATTENTION", "weird", "ATTENTION")):
            p = self.w("sev-w.tsv", "stage\tstatus\tdetail\nA\t%s\tx\nA\t%s\ty\n" % (first, second))
            self.assertEqual(fd.read_status_tsv(p)["A"][0], want, (first, second))

    def test_duplicate_stage_rows_end_to_end_gap_and_attention(self):
        base = [r for r in self.GOOD if r[0] != "D-dt-upload"]
        for a, b in (("GAP", "OK"), ("OK", "GAP")):                                 # 上傳階段：GAP 不能被 OK 蓋掉
            self.assertEqual(self.status(rows=base + [("D-dt-upload", a, "x"), ("D-dt-upload", b, "y")]), "GAP", (a, b))
        for a, b in (("FAIL", "GAP"), ("GAP", "FAIL")):                              # FAIL 比 GAP 重
            self.assertEqual(self.status(rows=base + [("D-dt-upload", a, "x"), ("D-dt-upload", b, "y")]), "FAIL", (a, b))
        for a, b in (("ATTENTION", "OK"), ("OK", "ATTENTION")):                      # 其他階段：ATTENTION 也不能被 OK 蓋掉（OK 之前要有人看過）
            self.assertEqual(self.status(rows=self.GOOD + [("C-euvd", a, "x"), ("C-euvd", b, "y")]), "ATTENTION", (a, b))
        for a, b in (("GAP", "ATTENTION"), ("ATTENTION", "GAP"), ("NOT_RUN", "GAP")):
            st, out, _ = self.case(rows=self.GOOD + [("C-euvd", a, "x"), ("C-euvd", b, "y")])
            self.assertEqual(st, "ATTENTION", (a, b))
            self.assertIn("C-euvd GAP", out, (a, b))                                 # 留下的是比較重的那一列
        for a, b in (("FAIL", "OK"), ("OK", "FAIL"), ("GAP", "FAIL")):
            self.assertEqual(self.status(rows=self.GOOD + [("C-euvd", a, "x"), ("C-euvd", b, "y")]), "FAIL", (a, b))
        # C-grype：GAP／NOT_RUN 與 OK 同時出現時不算 OK（不讀 grype.json）
        base = [r for r in self.GOOD if r[0] != "C-grype"]
        for a, b in (("GAP", "OK"), ("OK", "GAP")):
            self.assertEqual(self.status(rows=base + [("C-grype", a, "x"), ("C-grype", b, "y")]), "GAP", (a, b))

    def test_wait_rc_only_zero_can_be_ok_and_every_other_value_is_gap(self):
        def run(rc, rows=None, summ=None):
            HardeningTests.n += 1
            slug = "w%d" % HardeningTests.n
            info, o = self.prep(bom(clean()), slug=slug, out="p-" + slug, kind="bios", version="firmware_version: 1.0\n")
            dt = self.dt_sample(info, rows if rows is not None else self.GOOD, self.SUMM if summ is None else summ, {"matches": []}, root="dt-" + slug)
            if rc is not None:
                self.w("dt-%s/dt-wait.rc" % slug, rc)
            r, out, md = self.run_report([o], dt)
            return out.split("\t")[1], out, r
        self.assertEqual(run(None)[0], "OK")                  # 沒有 dt-wait.rc（沒有 wait 的紀錄）：照其他資料判斷
        self.assertEqual(run("0\n")[0], "OK")
        self.assertEqual(run("00\n")[0], "OK")
        for v in ("1", "2", "4", "124", "137", "255", "256", "99999"):
            st, out, rc = run(v + "\n")
            self.assertEqual((st, rc), ("GAP", 0), (v, out))
            self.assertIn("dt-ephemeral wait 結束碼 %s" % int(v), out)
        st, out, _ = run("3\n")
        self.assertEqual(st, "GAP")
        self.assertIn("資料不完整", out)
        # 看不懂的內容是錯誤，不是 OK
        # 只認 ^[0-9]+$（ASCII）：+0、-0、-1、0_0、全形數字、阿拉伯數字、NBSP、數字中間有空白都不是整數（不能被當成 0）
        for v in ("", "x", "1.5", "0x0", "\n", "+0\n", "-0\n", "-1\n", "0_0\n", "\uff10\n", "\u0660\n", "\u00a00\n", "0\u00a0\n", "0 0\n", "0\n0\n", "\u20800\n", "\u00b2\n"):
            st, out, rc = run(v)
            self.assertEqual(rc, 1, (v, out))
            self.assertIn("dt-wait.rc 不是非負整數", out)
            self.assertNotIn("FIRMWARE-DT\tOK", out)
        # 前後的 ASCII 空白與換行可以有（echo 寫的檔案）
        self.assertEqual(run(" 0 \r\n")[0], "OK")
        # 路徑存在但不是一般檔案（斷掉的符號連結、資料夾、FIFO、指向真檔案的符號連結）：一律 FAIL，不當成「沒有 rc」
        for kind in ("dangling", "dir", "fifo", "symlink"):
            HardeningTests.n += 1
            slug = "wn%d" % HardeningTests.n
            info, o = self.prep(bom(clean()), slug=slug, out="p-" + slug, kind="bios", version="firmware_version: 1.0\n")
            dt = self.dt_sample(info, self.GOOD, self.SUMM, {"matches": []}, root="dt-" + slug)
            rcp = os.path.join(dt, "dt-wait.rc")
            if kind == "dangling":
                os.symlink(os.path.join(self.tmp, "nowhere"), rcp)
            elif kind == "dir":
                os.mkdir(rcp)
            elif kind == "fifo":
                os.mkfifo(rcp)
            else:
                open(os.path.join(self.tmp, "real-rc"), "w").write("0\n")
                os.symlink(os.path.join(self.tmp, "real-rc"), rcp)
            rc, out, _ = self.run_report([o], dt)
            self.assertEqual(rc, 1, (kind, out))
            self.assertIn("dt-wait.rc", out)
            self.assertNotIn("FIRMWARE-DT\tOK", out)
        # FAIL 仍然是 FAIL（結束碼不能把 FAIL 降成 GAP）
        for v in ("0", "1", "3", "124"):
            self.assertEqual(run(v + "\n", rows=self.GOOD + [("C-euvd", "FAIL", "x")])[0], "FAIL", v)

    def test_status_tsv_oversize_field_is_dt_error_not_crash(self):
        p = self.w("big.tsv", "stage\tstatus\tdetail\nA\tOK\t" + "x" * 200000 + "\n")
        with self.assertRaises(fd.DtError):
            fd.read_status_tsv(p)

    def test_declared_rejection_semantics_unchanged_by_other_stages(self):
        self.ED = ReportTests.ED
        o, dt = ReportTests.rej_case(self, True, ReportTests.REJ + [("C-euvd", "GAP", "x"), ("C-sbomgate", "NOT_ASSESSED", "x")],
                                     ReportTests.REJ_SUMM, "hx1")
        rc, out, _ = self.run_report([o], dt)
        self.assertEqual(rc, 0, out)                       # 非 FAIL 的其他階段不影響已宣告的拒收（宣告的拒收仍成立）
        self.assertIn("與 firmware.yml 宣告的 expected_dt 一致", out)
        # 拒收不是 BOM_INVALID 那種 400：不放行
        rows = [r if r[0] != "D-dt-upload" else ("D-dt-upload", "FAIL", "http=400 {}") for r in ReportTests.REJ]
        o, dt = ReportTests.rej_case(self, True, rows, ReportTests.REJ_SUMM, "hx2")
        self.assertEqual(self.run_report([o], dt)[0], 1)

    # ---- 4. 標記
    def test_vuln_assessment_only_exact_none_is_assessed(self):
        self.assertEqual(self.status(comps=[clean(va="NONE")]), "OK")
        for va in ("NOT_ASSESSED", "not_assessed", " NONE", "NONE ", "none", "None", "garbage", "OK", "ASSESSED", "NONE\n", "N0NE", ""):
            st, out, _ = self.case(comps=[clean(va=va)])
            self.assertEqual(st, "ATTENTION", repr(va))
        st, out, _ = self.case(comps=[clean(va="NOT_ASSESSED")])
        self.assertIn("NOT_ASSESSED 元件 1 個", out)
        st, out, _ = self.case(comps=[clean(va="garbage")])
        self.assertIn("不是 NONE／NOT_ASSESSED 的元件 1 個", out)
        st, out, _ = self.case(comps=[clean(va=" NONE")])
        self.assertIn("不是 NONE／NOT_ASSESSED 的元件 1 個", out)

    def test_vuln_assessment_non_string_or_missing_value(self):
        for prop in ({"name": "dumpling:vuln-assessment", "value": 5}, {"name": "dumpling:vuln-assessment", "value": None},
                     {"name": "dumpling:vuln-assessment"}, {"name": "dumpling:vuln-assessment", "value": ["NONE"]}):
            c = clean()
            c["properties"] = [prop, {"name": "dumpling:version-status", "value": "OK"}]
            self.assertEqual(self.status(comps=[c]), "ATTENTION", prop)

    def test_vuln_assessment_any_duplicate_marker_counts(self):
        def with_markers(*vals):
            c = clean()
            c["properties"] = [{"name": "dumpling:vuln-assessment", "value": v} for v in vals] + [{"name": "dumpling:version-status", "value": "OK"}]
            return c
        self.assertEqual(self.status(comps=[with_markers("NONE", "NONE")]), "OK")
        for vals in (("NONE", "NOT_ASSESSED"), ("NOT_ASSESSED", "NONE"), ("NONE", "garbage"), ("garbage", "NONE"), ("NONE", "NONE", " NONE")):
            self.assertEqual(self.status(comps=[with_markers(*vals)]), "ATTENTION", vals)
        s = fd.summarize([with_markers("NONE", "NOT_ASSESSED")])
        self.assertEqual(s["vuln_assessment"], {"NOT_ASSESSED": 1})
        s = fd.summarize([with_markers("NONE", "garbage")])
        self.assertEqual(s["vuln_assessment"], {fd.OTHER: 1})

    def test_marker_names_are_exact(self):
        for name in ("Dumpling:vuln-assessment", "dumpling:vuln-assessment ", "dumpling:vuln_assessment"):
            c = clean()
            c["properties"] = [{"name": name, "value": "NONE"}, {"name": "dumpling:version-status", "value": "OK"}]
            st, out, _ = self.case(comps=[c])
            self.assertEqual(st, "ATTENTION", name)
            self.assertIn("沒有 dumpling:vuln-assessment 標記的元件 1 個", out)

    def test_version_status_only_exact_ok_and_gap(self):
        self.assertEqual(self.status(comps=[clean(vs="OK")]), "OK")
        st, out, _ = self.case(comps=[clean(vs="GAP")])
        self.assertEqual(st, "ATTENTION")
        self.assertIn("版本 GAP 1 個", out)
        for vs in ("gap", " GAP", "GAP ", "ok", "OK ", "garbage", "Gap"):
            st, out, _ = self.case(comps=[clean(vs=vs)])
            self.assertEqual(st, "ATTENTION", repr(vs))
            self.assertIn("dumpling:version-status 不是 OK／GAP 的元件 1 個", out)
        c = clean()
        c["properties"] = [{"name": "dumpling:vuln-assessment", "value": "NONE"}] + [{"name": "dumpling:version-status", "value": v} for v in ("OK", "garbage")]
        st, out, _ = self.case(comps=[c])
        self.assertEqual(st, "ATTENTION")
        self.assertIn("version-status 不是 OK／GAP", out)

    def test_supplier_sbom_markers_are_not_trusted(self):
        # kind: sbom：供應商自己塞 NONE／OK／GAP 都不採信，當作沒標；另有一條原因
        cs = [clean("a", "r1"), clean("b", "r2", purl="pkg:github/a/c@1")]
        st, out, _ = self.case(comps=cs, kind="sbom")
        self.assertEqual(st, "ATTENTION")
        self.assertIn("沒有 dumpling:vuln-assessment 標記的元件 2 個", out)
        self.assertIn("供應商 SBOM 自帶 dumpling: 標記的元件 2 個", out)
        self.assertEqual(self.status(comps=cs, kind="bios"), "OK")          # 同樣的內容，本工具產的 SBOM（bios）才採信
        info, _ = self.prep(bom(*cs), slug="sup", out="p-sup", kind="sbom")
        s = info["summary"]
        self.assertEqual((s["vuln_assessment"], s["supplier_markers"], s["trust_markers"]), ({fd.UNSET: 2}, 2, False))
        c = clean(vs="GAP", version=None)
        s = fd.summarize([c], trust_markers=False)
        self.assertEqual((s["version_gap"], s["no_version_unmarked"]), (0, 1))     # 供應商的 GAP 標記不能替缺版本開脫
        self.assertEqual(fd.summarize([c])["no_version_unmarked"], 0)

    def test_expected_uses_the_same_marker_rules(self):
        c = clean(purl=None, va="NONE")
        info, o = self.prep(bom(c, clean("b", "r2", purl="x", va="not_none")), slug="ex", out="p-ex")
        _, own = fd.expected(o)
        self.assertEqual({d["name"]: d["vuln_assessment"] for d in own["no_data_components"]}, {"a": "NONE", "b": fd.OTHER})
        info, o = self.prep(bom(clean(purl=None)), slug="ex2", out="p-ex2", kind="sbom")
        _, own = fd.expected(o)
        self.assertEqual(own["no_data_components"][0]["vuln_assessment"], fd.UNSET)

    # ---- 4. purl
    def test_purl_recognition(self):
        generic = ["pkg:generic/x@1", "PKG:GENERIC/x@1", "pkg:Generic/x@1", " pkg:generic/x@1", "pkg:generic/x@1 \n", "pkg://generic/x@1", "pkg:/generic/x@1"]
        none = ["x", "generic/x", "pkg:generic", "pkg:", "pkg:/", "pkg:generic x/y", "pkg:ge neric/x", "xpkg:generic/x", "mypkg:generic/x"]
        for p in generic:
            self.assertEqual(fd.purl_type(p), "generic", repr(p))
            s = fd.summarize([raw_comp(purl=p)])
            self.assertEqual((s["with_purl"], s["generic_purl"], s["bad_purl"]), (1, 1, 0), repr(p))
        for p in none + ["", " ", "\t\n"]:
            self.assertIsNone(fd.purl_type(p), repr(p))
            s = fd.summarize([raw_comp(purl=p)])
            self.assertEqual((s["with_purl"], s.get("generic_purl", 0)), (0, 0), repr(p))
        for p in none:
            self.assertEqual(fd.summarize([raw_comp(purl=p)])["bad_purl"], 1, repr(p))
        for p in ("", " "):
            self.assertEqual(fd.summarize([raw_comp(purl=p)])["bad_purl"], 0)
        self.assertEqual(fd.purl_type("pkg:deb/ubuntu/x@1"), "deb")
        self.assertEqual(fd.purl_type("pkg:github/a/b"), "github")

    def test_purl_variants_report(self):
        for p in ("PKG:GENERIC/x@1", " pkg:generic/x@1", "pkg://generic/x@1"):
            st, out, _ = self.case(comps=[clean(purl=p)])
            self.assertEqual(st, "ATTENTION", p)
            self.assertIn("pkg:generic 的元件 1 個", out)
        for p in ("x", "generic/x", "pkg:generic", " "):
            st, out, _ = self.case(comps=[clean(purl=p)])
            self.assertEqual(st, "ATTENTION", repr(p))
            self.assertIn("沒有 purl 的元件 1 個", out)
        st, out, _ = self.case(comps=[clean(purl="x")])
        self.assertIn("purl 格式不合", out)

    # ---- 5. 沒有 version
    def test_no_version_without_marker_is_attention(self):
        for v in (None, "", "   "):
            c = clean(version=None, vs=None)
            c["properties"] = [p for p in c["properties"] if p["name"] != "dumpling:version-status"]
            if v is not None:
                c["version"] = v
            s = fd.summarize([c])
            self.assertEqual((s["no_version"], s["no_version_unmarked"]), (1, 1), repr(v))
            st, out, _ = self.case(comps=[c])
            self.assertEqual(st, "ATTENTION")
            self.assertIn("沒有 version、也沒有 version-status GAP 標記的元件 1 個", out)
        # 有 GAP 標記：由「版本 GAP」那條說明，不重複列
        st, out, _ = self.case(comps=[clean(version=None, vs="GAP")])
        self.assertEqual(st, "ATTENTION")
        self.assertIn("版本 GAP 1 個", out)
        self.assertNotIn("沒有 version、也沒有", out)
        # 標 OK 卻沒有 version：矛盾，要列
        self.assertIn("沒有 version、也沒有", self.case(comps=[clean(version=None, vs="OK")])[1])

    # ---- 6. summarize 的型別
    def test_summarize_bad_field_types_are_dt_error(self):
        for field, val in (("purl", 5), ("purl", ["pkg:generic/x"]), ("purl", {}), ("purl", True), ("cpe", 5), ("cpe", []), ("version", 1), ("version", 1.5),
                           ("name", {}), ("name", 7), ("group", True), ("properties", "x"), ("properties", 5), ("properties", {})):
            with self.assertRaises(fd.DtError, msg=(field, val)) as cm:
                fd.summarize([raw_comp(), raw_comp(**{field: val})])
            self.assertIn("第 2 個元件", str(cm.exception))
            self.assertIn(field, str(cm.exception))
        for field in ("purl", "cpe", "version", "name", "group", "properties"):
            fd.summarize([raw_comp(**{field: None})])               # null 等於沒有

    def test_prep_bad_field_types_fail_cleanly_and_write_nothing(self):
        for kind in ("bios", "sbom"):
            doc = bom(clean(), raw_comp(purl=5))
            doc["components"][0]["bom-ref"] = "r1"
            s = self.sample("bt-" + kind, kind=kind)
            b = self.w("in/bt.json", doc)
            o = os.path.join(self.tmp, "o-bt-" + kind)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = fd.main(["prep", "--sbom", b, "--sample", s, "--out", o])
            self.assertEqual(rc, 1)
            self.assertTrue(buf.getvalue().startswith("FIRMWARE-DT-PREP\tFAIL\t"), buf.getvalue())
            self.assertIn("purl 不是字串", buf.getvalue())
            self.assertFalse(os.path.exists(o), os.listdir(o) if os.path.isdir(o) else "")

    def test_nested_component_field_type_is_checked(self):
        outer = clean("o", "r1")
        outer["components"] = [raw_comp(cpe=["x"])]
        with self.assertRaises(fd.DtError):
            self.prep(bom(outer))

    # ---- 7. 重複鍵
    DUP = ('{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,'
           '"components":[{"type":"library","name":"first","name":"a","version":"1","purl":"pkg:github/a/b@1",'
           '"properties":[{"name":"dumpling:vuln-assessment","value":"NONE"},{"name":"dumpling:version-status","value":"OK"}]}],"version":2}')

    def test_duplicate_keys_detected_with_position_key_and_dropped_hash(self):
        d = fd.DupKeys()
        p = self.w("dup.json", self.DUP)
        doc, _ = fd.load_json(p, fd.MAX_BYTES, "SBOM", d)
        self.assertEqual((doc["version"], doc["components"][0]["name"]), (2, "a"))          # 後值取代前值（和標準庫一樣）
        self.assertEqual(d.total, 2)
        ev = {e["key_json"]: e for e in d.events}
        self.assertEqual(ev['"name"']["pointer"], "/components/0")
        self.assertEqual(ev['"name"']["dropped_value_sha256"], hashlib.sha256(b'"first"').hexdigest())
        self.assertEqual(ev['"version"']["pointer"], "/")
        self.assertEqual(ev['"version"']["dropped_value_sha256"], hashlib.sha256(b"1").hexdigest())
        self.assertLess(ev['"name"']["object_index"], ev['"version"']["object_index"])       # 內層物件先完成
        # 沒有重複鍵時完全不記
        d2 = fd.DupKeys()
        fd.load_json(self.w("nodup.json", bom(clean())), fd.MAX_BYTES, "SBOM", d2)
        self.assertEqual((d2.total, d2.events), (0, []))
        # 重複鍵在被丟掉的前值裡：計數、有 sha，但沒有位置
        d3 = fd.DupKeys()
        fd.load_json(self.w("nest.json", '{"x": {"k": 1, "k": 2}, "x": 3}'), fd.MAX_BYTES, "SBOM", d3)
        self.assertEqual(d3.total, 2)
        self.assertEqual(sorted(str(e["pointer"]) for e in d3.events), ["/", "None"])

    def test_duplicate_keys_in_supplier_sbom_are_recorded_and_not_silent(self):
        for kind in ("sbom", "bios"):
            s = self.sample("dup-" + kind, kind=kind)
            b = self.w("in/dup-%s.json" % kind, self.DUP)
            o = os.path.join(self.tmp, "o-dup-" + kind)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = fd.main(["prep", "--sbom", b, "--sample", s, "--out", o])
            self.assertEqual(rc, 0)
            self.assertIn("輸入 SBOM 有 2 個重複鍵", buf.getvalue())            # prep 的狀態行就看得到
            info = json.load(open(os.path.join(o, "dt-project.json"), encoding="utf-8"))
            self.assertEqual(info["duplicate_keys"]["count"], 2)
            self.assertEqual(info["summary"]["duplicate_keys"], 2)
            out_doc = json.load(open(os.path.join(o, "sbom.cdx.json"), encoding="utf-8"))
            self.assertEqual(out_doc["components"][0]["name"], "a")
            if kind == "sbom":
                norm = json.load(open(os.path.join(o, "normalize.json"), encoding="utf-8"))
                notes = "\n".join(norm["notes"])
                self.assertIn('鍵 "name"', notes)
                self.assertIn(hashlib.sha256(b'"first"').hexdigest(), notes)
                self.assertIn("第 ", notes)
                self.assertIn("/components/0", notes)
            else:
                self.assertFalse(os.path.exists(os.path.join(o, "normalize.json")))
            # report：乾淨的樣本也只能是 ATTENTION，說明有重複鍵
            info2 = info
            dt = self.dt_sample(info2, self.GOOD, self.SUMM, {"matches": []}, root="dt-dup-" + kind)
            rc, out, _ = self.run_report([o], dt)
            self.assertEqual(rc, 0)
            self.assertTrue(out.startswith("FIRMWARE-DT\tATTENTION\t") or kind == "sbom", out)
            self.assertIn("重複鍵", out)
            self.assertNotIn("\tOK\t", out)
        # 不是 ATTENTION 的狀態（NOT_RUN）重複鍵說明也不能消失
        o = os.path.join(self.tmp, "o-dup-bios")
        rc, out, _ = self.run_report([o])
        self.assertTrue(out.startswith("FIRMWARE-DT\tNOT_RUN\t"), out)
        self.assertIn("重複鍵", out)

    def test_duplicate_key_with_surrogate_name_is_recorded_as_ascii(self):
        # 鍵本身有單獨代理字元：事件以 ASCII 跳脫記錄，不會讓 normalize.json／dt-project.json 的序列化失敗
        d = fd.DupKeys()
        fd.load_json(self.w("dup-sur.json", '{"na\\ud800me": 1, "na\\ud800me": 2}'), fd.MAX_BYTES, "SBOM", d)
        self.assertEqual(d.total, 1)
        self.assertEqual(d.events[0]["key_json"], '"na\\ud800me"')
        fd.dumps_json(d.events, "events")

    # ---- 8. 單獨代理字元
    SUR = '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"library","name":"a\\ud800b","version":"1"}]}'

    def test_lone_surrogate_is_a_clean_fail_and_leaves_nothing(self):
        for kind in ("sbom", "bios"):
            s = self.sample("sur-" + kind, kind=kind)
            b = self.w("in/sur-%s.json" % kind, self.SUR)
            o = os.path.join(self.tmp, "o-sur-" + kind)
            with self.assertRaises(fd.DtError) as cm:
                fd.prep(b, s, o)
            self.assertIn("單獨代理字元", str(cm.exception))
            left = os.listdir(o) if os.path.isdir(o) else []
            self.assertEqual(left, [], kind)                 # 沒有 normalize.json、sbom.cdx.json、dt-project.json 任何一個
            res = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "pipeline/lib/firmware_dt.py"), "prep", "--sbom", b, "--sample", s, "--out", o],
                                 capture_output=True, text=True)
            self.assertEqual(res.returncode, 1, res.stderr)
            self.assertTrue(res.stdout.startswith("FIRMWARE-DT-PREP\tFAIL\t"), res.stdout)
            self.assertNotIn("Traceback", res.stderr)
            self.assertIn("單獨代理字元", res.stdout)

    def test_error_message_with_surrogate_does_not_crash_the_cli(self):
        # DtError 的訊息裡帶不可信文字（bom-ref 重複）：stdout 是 UTF-8 時，直接 print 單獨代理字元會 UnicodeEncodeError
        doc = '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"a","bom-ref":"x\\ud800"},{"type":"library","name":"b","bom-ref":"x\\ud800"}]}'
        s = self.sample("sur-msg")
        b = self.w("in/sur-msg.json", doc)
        res = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "pipeline/lib/firmware_dt.py"), "prep", "--sbom", b, "--sample", s, "--out", os.path.join(self.tmp, "o-sm")],
                             capture_output=True, env={"PYTHONIOENCODING": "utf-8", "PATH": os.environ.get("PATH", "")})
        self.assertEqual(res.returncode, 1, res.stderr)
        self.assertTrue(res.stdout.decode("utf-8").startswith("FIRMWARE-DT-PREP\tFAIL\t"))
        self.assertNotIn(b"Traceback", res.stderr)

    def test_unexpected_exception_is_a_fail_line_not_a_traceback(self):
        s = self.sample("boom")
        b = self.w("in/boom.json", bom(clean()))
        old = fd.summarize
        fd.summarize = lambda *a, **k: 1 / 0
        self.addCleanup(setattr, fd, "summarize", old)
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = fd.main(["prep", "--sbom", b, "--sample", s, "--out", os.path.join(self.tmp, "o-boom")])
        self.assertEqual(rc, 1)
        self.assertIn("FIRMWARE-DT-PREP\tFAIL\t非預期的錯誤 ZeroDivisionError", buf.getvalue())

    def test_write_failure_midway_removes_what_was_written(self):
        s = self.sample("wf", kind="sbom")
        b = self.w("in/wf.json", bom(clean()))
        o = os.path.join(self.tmp, "o-wf")
        real = fd.write_text

        def flaky(path, text):
            if os.path.basename(path) == "dt-project.json":
                raise fd.DtError("dt-project.json 寫不出去：模擬")
            real(path, text)
        fd.write_text = flaky
        self.addCleanup(setattr, fd, "write_text", real)
        with self.assertRaises(fd.DtError):
            fd.prep(b, s, o)
        self.assertEqual(os.listdir(o), [])

    # ---- 9. normalize.json 記原本有沒有這個鍵
    def test_normalize_records_original_shape(self):
        def shape(doc, ver="1.4"):
            doc["specVersion"] = ver
            doc["platform"] = "x"          # 讓正規化有事可做
            s = self.sample("os%d" % abs(hash(json.dumps(doc, sort_keys=True))), kind="sbom")
            o = os.path.join(self.tmp, "o-os%d" % abs(hash(json.dumps(doc, sort_keys=True))))
            fd.prep(self.w("in/os.json", doc), s, o)
            return json.load(open(os.path.join(o, "normalize.json"), encoding="utf-8"))["original_shape"]
        d = bom(clean())
        del d["metadata"]
        self.assertEqual(shape(d), {"metadata": "absent", "metadata.properties": "absent"})
        d = bom(clean())
        self.assertEqual(shape(d), {"metadata": "object", "metadata.properties": "absent"})
        d = bom(clean())
        d["metadata"]["properties"] = []
        self.assertEqual(shape(d), {"metadata": "object", "metadata.properties": "array"})
        d = bom(clean())
        d["metadata"]["properties"] = None
        self.assertEqual(shape(d), {"metadata": "object", "metadata.properties": "null"})
        d = bom(clean())
        d["metadata"] = None
        self.assertEqual(shape(d), {"metadata": "null", "metadata.properties": "absent"})



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
