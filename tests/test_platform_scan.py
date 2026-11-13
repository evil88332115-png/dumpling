"""pipeline/lib/platform_scan.py（平台無關的 scan 後處理）的單元測試：用一個和 Jetson 無關的假平台走完 collect。不連網。"""
import argparse
import json
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(ROOT, "pipeline", "lib"))
import platform_scan as ps  # noqa: E402


def w(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


class FakeHooks(ps.Hooks):
    rootfs = "root"
    package_purl_prefix = "pkg:rpm/"
    report_files = (("交給PM/VEX/vex.cdx.json", "vex-{p}-{v}{s}.json", "VEX{s}"),)

    def run_summary_fields(self, paths, status):
        return {"bootloader": status.get("B-bootloader", {}).get("status")}

    def scan_tail(self, ctx):
        return {"bootloader": ctx["main_run"].get("bootloader")}

    def notes_build(self, ctx):
        return ["## 平台段落", "", "- 假平台"]


class Generic(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dumpling-pscan-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def p(self, *a):
        return os.path.join(self.tmp, *a)

    def run_dir(self, name, rows):
        d = self.p(name)
        w(os.path.join(d, "scan", "root", "scan", "status.tsv"), "stage\tstatus\tdetail\nB-bootloader\tNOT_ASSESSED\tgeneric\nA-md5\tOK\tx\n")
        w(os.path.join(d, "cra-project", "CRA", "Reports", "vulnerability-rows.json"), json.dumps({"rows": rows}))
        w(os.path.join(d, "報告", "交給PM", "VEX", "vex.cdx.json"), "{}")
        return d

    def args(self, **kw):
        a = dict(out=self.p("rel"), project="p", version="v1", layers=None, build_json=None, assemble_json=None, scan_json=self.p("scan.json"),
                 run=[], official=False)
        a.update(kw)
        return argparse.Namespace(**a)

    def test_collect_without_layers_build_or_assemble(self):
        d = self.run_dir("w0", [{"id": "CVE-1", "tier": "p1"}, {"id": "CVE-2", "tier": "p3"}])
        scan = ps.collect(self.args(run=["=" + d]), FakeHooks())
        self.assertEqual(scan["vulnerabilities"]["full"]["rows_total"], 2)
        self.assertEqual(scan["bootloader"], "NOT_ASSESSED")
        self.assertEqual(scan["runs"][""]["bootloader"], "NOT_ASSESSED")
        self.assertEqual(scan["runs"][""]["stage_details"], {"A-md5": "x"})
        self.assertIsNone(scan["components"]["total"])        # 沒有分層：記 null，不推測
        names = [l.split("\t")[0] for l in open(self.p("rel", "manifest.tsv"), encoding="utf-8").read().splitlines()]
        self.assertEqual(names, ["report-p-v1.zip", "vex-p-v1.json", "scan-summary-p-v1.json"])
        notes = open(self.p("rel", "notes.md"), encoding="utf-8").read()
        self.assertIn("## 平台段落", notes)
        self.assertIn("scan-summary-*.json", notes)
        self.assertNotIn("kernel", notes.lower())             # 沒有任何 Jetson 的說明

    def test_hooks_default_is_empty_and_two_runs_are_named_by_suffix(self):
        d0, d1 = self.run_dir("w0", [{"id": "CVE-1", "tier": "p1", "layer": "bsp"}]), self.run_dir("w1", [])
        scan = ps.collect(self.args(run=["=" + d0, "-bsp=" + d1]))
        self.assertEqual(set(scan["vulnerabilities"]), {"full", "bsp"})
        self.assertEqual(scan["vulnerabilities"]["full"]["p1_rows"], 1)
        self.assertTrue(os.path.isfile(self.p("rel", "report-p-v1-bsp.zip")))

    def test_package_prefix_and_layers(self):
        lay = self.p("layers")
        w(os.path.join(lay, "layers.json"), json.dumps({"platform": "x", "os_responsibility": "ours", "components_total": 3,
                                                       "components": {"bsp": 1, "os": 2}, "unknown": {"by_reason": {}}}))
        sb = {"components": [{"purl": "pkg:rpm/a@1", "properties": [{"name": ps.LAYER_PROP, "value": "bsp"}]},
                             {"purl": "pkg:deb/b@1", "properties": [{"name": ps.LAYER_PROP, "value": "os"}]},
                             {"purl": "pkg:rpm/c@1", "properties": [{"name": ps.LAYER_PROP, "value": "os"}]}]}
        w(os.path.join(lay, "sbom.product.cdx.json"), json.dumps(sb))
        scan = ps.collect(self.args(layers=lay, run=["=" + self.run_dir("w0", [])]), FakeHooks())
        self.assertEqual((scan["components"]["deb_bsp"], scan["components"]["deb_os"]), (1, 1))      # 只算 rpm
        self.assertTrue(os.path.isfile(self.p("rel", "sbom-p-v1.cdx.json")))

    def test_site_config_takes_any_upstream_groups(self):
        ps.site_config(self.p("s.json"), "/r", "/w", "/o", "/p", "/g", {"grp": {"k": "/x"}}, "/py")
        self.assertEqual(json.load(open(self.p("s.json")))["upstream"], {"grp": {"k": "/x"}})

    def test_docstring_tells_other_platforms_how_to_call_it(self):
        for need in ("class MyHooks(ps.Hooks)", "ps.collect(args, MyHooks())", "newest_dir", "run_summary_fields"):
            self.assertIn(need, ps.__doc__)


if __name__ == "__main__":
    unittest.main()
