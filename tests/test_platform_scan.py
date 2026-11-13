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


class IndependentHooks(FakeHooks):
    def __init__(self, status, detail="x"):
        self.status, self.detail = status, detail

    def independent_version(self, ctx):
        return {"status": self.status, "rule": "r", "expected": "1", "found": [], "detail": self.detail}


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


class ProductVersionVsTag(Generic):
    """D-055 (3)：精靈覆寫後的 product.version 要和 Release tag 的版本一致，不一致 → collect 在輸出寫完之後丟 ProductVersionMismatch（各平台收集腳本都當 FAIL）。"""

    def with_config(self, name, version, supplier_version=False, **prod):
        d = self.run_dir(name, [])
        if version is not False:
            prod["version"] = version
        w(os.path.join(d, "cra-project", "CRA", "Config", "config.json"), json.dumps({"product": dict({"name": "X"}, **prod)}))
        if supplier_version is not False:
            w(os.path.join(d, "supplier", "cra-project", "CRA", "Config", "config.json"), json.dumps({"product": {"name": "X", "version": supplier_version}}))
        return d

    def test_matching_version_and_suffix_is_ok(self):
        for v in ("v1", "v1 (rootfs)", "v1 (rootfs)(gui)", " v1 "):
            scan = ps.collect(self.args(run=["=" + self.with_config("w", v)]), IndependentHooks("OK"))
            self.assertEqual(scan["product_version_check"]["status"], "OK", v)
            self.assertEqual(scan["product_version_check"]["tag_version"], "v1")

    def test_tag_only_is_gap_not_ok(self):
        """M7b：設定包等於 tag 只是 tag 和 tag 自己比；平台沒有和 tag 無關的來源 → GAP（D-043），不擋。"""
        scan = ps.collect(self.args(run=["=" + self.with_config("w", "v1")]))
        pvc = scan["product_version_check"]
        self.assertEqual((pvc["status"], pvc["independent"]["status"]), ("GAP", "GAP"))
        self.assertIn("沒有和 tag 無關的版本來源", pvc["independent"]["detail"])
        notes = open(self.p("rel", "notes.md"), encoding="utf-8").read()
        self.assertIn("版本核對（`product_version_check`）：**GAP**", notes)
        for st in ("GAP", "PASS", None):                                  # hook 給 GAP 或寫錯的狀態都不能變 OK
            self.assertEqual(ps.collect(self.args(run=["=" + self.with_config("w", "v1")]), IndependentHooks(st))["product_version_check"]["status"], "GAP", st)

    def test_independent_fail_fails_even_when_the_config_matches_the_tag(self):
        with self.assertRaises(ps.ProductVersionMismatch) as cm:
            ps.collect(self.args(run=["=" + self.with_config("w", "v1")]), IndependentHooks("FAIL", "掃到的是 2.0"))
        self.assertIn("和 tag 無關的版本核對不通過：掃到的是 2.0", str(cm.exception))
        sc = json.load(open(self.p("scan.json")))
        self.assertEqual((sc["product_version_check"]["status"], sc["product_version_check"]["independent"]["status"]), ("FAIL", "FAIL"))

    def test_not_set_still_wins_over_independent_ok(self):
        scan = ps.collect(self.args(run=["=" + self.with_config("w0", False)]), IndependentHooks("OK"))
        self.assertEqual(scan["product_version_check"]["status"], "NOT_SET")

    def test_mismatch_fails_after_everything_is_written(self):
        d = self.with_config("w0", "v0.9", supplier_version="v1")
        with self.assertRaises(ps.ProductVersionMismatch) as cm:
            ps.collect(self.args(run=["=" + d]))
        self.assertIsInstance(cm.exception, ValueError)                  # 各平台的收集腳本都 catch (OSError, ValueError) → FAIL、結束碼 1
        self.assertIn("'v0.9'", str(cm.exception))
        self.assertIn("'v1'", str(cm.exception))
        sc = json.load(open(self.p("scan.json")))                          # 附件與 scan.json 都寫了，可以查
        self.assertEqual(sc["product_version_check"]["status"], "FAIL")
        self.assertEqual([(c["role"], c["status"]) for c in sc["product_version_check"]["checked"]], [("manufacturer", "MISMATCH"), ("supplier", "OK")])
        self.assertTrue(os.path.isfile(self.p("rel", "notes.md")) and os.path.isfile(self.p("rel", "manifest.tsv")))

    def test_supplier_copy_and_every_layer_run_are_checked(self):
        ok = self.with_config("w0", "v1", supplier_version="v1")
        stale = self.with_config("w1", "v1", supplier_version="V0.5.0.1_a (rootfs)")
        with self.assertRaises(ps.ProductVersionMismatch) as cm:
            ps.collect(self.args(run=["=" + ok, "-bsp=" + stale]))
        self.assertIn("bsp 報告（supplier）", str(cm.exception))
        # ours：同一個後綴出現兩次，報告取後面那次——核對的也是後面那次
        ps.collect(self.args(run=["=" + self.with_config("a", "v0"), "=" + self.with_config("b", "v1")]))

    def test_not_set_and_not_found_do_not_block(self):
        scan = ps.collect(self.args(run=["=" + self.with_config("w0", False)]))             # 設定包沒有 product.version：精靈沒有東西可覆寫
        self.assertEqual(scan["product_version_check"]["status"], "NOT_SET")
        scan = ps.collect(self.args(run=["=" + self.run_dir("w1", [])]))                    # 沒有設定檔（沒有跑到報告）
        self.assertEqual((scan["product_version_check"]["status"], scan["product_version_check"]["checked"]), ("NOT_RUN", []))
        d = self.with_config("w2", "")
        self.assertEqual(ps.collect(self.args(run=["=" + d]))["product_version_check"]["status"], "NOT_SET")

    def test_unreadable_config_or_non_string_version_fails(self):
        for content in ("{not json", json.dumps([1]), json.dumps({"product": "x"}), json.dumps({"product": {"version": 1.5}})):
            d = self.run_dir("w", [])
            w(os.path.join(d, "cra-project", "CRA", "Config", "config.json"), content)
            with self.assertRaises(ps.ProductVersionMismatch, msg=content):
                ps.collect(self.args(run=["=" + d]))

    def test_jetson_scan_cli_turns_the_mismatch_into_exit_1(self):
        """scan.sh 看的是 jetson_scan.py collect 的結束碼（C4 的收集腳本一樣 catch ValueError）：版本不一致 → 1，不是 traceback。"""
        from unittest import mock
        import io
        import jetson_scan as js
        argv = ["collect", "--out", self.p("rel"), "--project", "p", "--version", "v1", "--layers", self.p("l"), "--build-json", self.p("b"),
                "--assemble-json", self.p("a"), "--scan-json", self.p("s"), "--run", "=" + self.p("w")]
        with mock.patch.object(js, "collect", side_effect=ps.ProductVersionMismatch("版本與 Release tag 不一致")), mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            self.assertEqual(js.main(argv), 1)
        self.assertIn("jetson_scan: FAIL（版本與 Release tag 不一致）", out.getvalue())

    def test_version_base_matches_what_the_wizard_keeps(self):
        """精靈 override_pack_version 保留非版本號的括號後綴；核對時要把同樣的後綴去掉才對得上 tag。"""
        import importlib.util
        spec = importlib.util.spec_from_file_location("cra_scan_wizard", os.path.join(ROOT, "tools", "wizard", "cra-scan.py"))
        wiz = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(wiz)
        for n, old in enumerate(("V1.0.0.1_a", "V1.0.0.1_a (rootfs)", "V1 (rootfs)(gui)  ", "1.0 (2.0.1)", "TO BE COMPLETED", "x (a (b))")):
            for tag in ("v39.2.1-demo1", "V2.0", "1.0.1"):
                f = self.p("c%d.json" % n)
                w(f, json.dumps({"product": {"name": "X", "version": old}}))
                wiz.override_pack_version(f, tag)
                self.assertEqual(ps.product_version_status(f, tag)[0], "OK", (old, tag, json.load(open(f))["product"]["version"]))
        self.assertEqual(ps.version_base("1.0 (2.0.1)"), "1.0 (2.0.1)")
        self.assertEqual(ps.version_base("v1 (rootfs)(gui)"), "v1")
        self.assertEqual(ps.product_version_status(self.p("nope.json"), "v1"), ("NOT_FOUND", None))




class JetsonIndependentVersion(Generic):
    """M7b：Jetson 的 tag → sources.yml 的 l4t_release → 必須等於刷機包 list.json 裡掃到的 L4T 版本。"""

    def setUp(self):
        super().setUp()
        import jetson_scan
        self.js = jetson_scan
        self.proj = self.p("proj")
        os.makedirs(self.proj)
        shutil.copy(os.path.join(ROOT, "projects", "orin-nano-demo", "sources.yml"), self.proj)

    def full_run(self, l4t=None, variant="rootfs", raw=None, name="w"):
        d = self.p(name)
        if raw is not None:
            w(os.path.join(d, "scan", "list.json"), raw)
        elif l4t is not False:
            l4t = l4t or {"release": "39.2.1", "status": "OK", "detail": "L4T 39.2.1",
                          "sources": {"nv_tegra_release": "39.2.1", "nvidia-l4t-core": "39.2.1", "nvidia-l4t-kernel": "39.2.1"}}
            w(os.path.join(d, "scan", "list.json"), json.dumps({"rootfs": [{"variant": variant, "prefix": "Linux_for_Tegra/rootfs", "l4t": l4t}]}))
        return d

    def iv(self, ver="v39.2.1-demo1", project_dir=True, runs=None):
        a = argparse.Namespace(project_dir=self.proj if project_dir else None, run=runs if runs is not None else ["=" + self.full_run()])
        return self.js.jetson_independent_version(a, ver)

    def test_matching_scanned_l4t_is_ok(self):
        r = self.iv()
        self.assertEqual((r["status"], r["expected"]), ("OK", "39.2.1"))
        self.assertIn({"source": "nv_tegra_release（Linux_for_Tegra/rootfs）", "value": "39.2.1"}, r["found"])

    def test_tag_typo_or_wrong_bsp_fails(self):
        """C0 的情境：tag 寫 v39.2.1-demo1，實際掃的是 39.2.0 的刷機包。"""
        d = self.full_run({"release": "39.2.0", "status": "OK", "sources": {"nv_tegra_release": "39.2.0"}})
        r = self.iv(runs=["=" + d])
        self.assertEqual(r["status"], "FAIL")
        self.assertIn("L4T 39.2.1", r["detail"])
        self.assertIn("L4T 39.2.0", r["detail"])
        self.assertEqual(self.iv("v39.2.0-demo1", runs=["=" + self.full_run()])["status"], "FAIL")     # 反過來也抓得到

    def test_inconsistent_or_unknown_scanned_version_fails(self):
        for l4t in ({"release": None, "status": "ATTENTION", "detail": "來源不一致：nv_tegra_release 39.2.1、nvidia-l4t-core 39.2.0",
                     "sources": {"nv_tegra_release": "39.2.1", "nvidia-l4t-core": "39.2.0"}},
                    {"release": None, "status": "GAP", "detail": "無法判斷 L4T 版本", "sources": {}}, "x"):
            self.assertEqual(self.iv(runs=["=" + self.full_run(l4t)])["status"], "FAIL", l4t)

    def test_inconsistent_scanned_sources_fail_the_whole_collect(self):
        """三個來源不一致：整體 FAIL（scan 步驟 FAIL），不只是 ATTENTION——就算設定包的版本等於 tag。"""
        d = self.full_run({"release": None, "status": "ATTENTION", "detail": "來源不一致：nv_tegra_release 39.2.1、nvidia-l4t-core 39.2.0",
                           "sources": {"nv_tegra_release": "39.2.1", "nvidia-l4t-core": "39.2.0"}})
        w(os.path.join(d, "cra-project", "CRA", "Config", "config.json"), json.dumps({"product": {"name": "X", "version": "v39.2.1-demo1"}}))
        a = self.args(version="v39.2.1-demo1", run=["=" + d], project_dir=self.proj)
        with self.assertRaises(ps.ProductVersionMismatch) as cm:
            ps.collect(a, self.js.JetsonHooks())
        self.assertIn("來源不一致", str(cm.exception))
        pvc = json.load(open(self.p("scan.json")))["product_version_check"]
        self.assertEqual((pvc["status"], pvc["independent"]["status"], [c["status"] for c in pvc["checked"]]), ("FAIL", "FAIL", ["OK"]))
        self.assertIn({"source": "nvidia-l4t-core（Linux_for_Tegra/rootfs）", "value": "39.2.0"}, pvc["independent"]["found"])

    def test_broken_list_or_missing_rootfs_fails(self):
        for raw in ("{not json", "[]", json.dumps({"rootfs": "x"}), json.dumps({"rootfs": []})):
            self.assertEqual(self.iv(runs=["=" + self.full_run(raw=raw)])["status"], "FAIL", raw)
        self.assertEqual(self.iv(runs=["=" + self.full_run(variant="rootfs_gui")])["status"], "FAIL")

    def test_missing_inputs_are_gap(self):
        self.assertEqual(self.iv(project_dir=False)["status"], "GAP")                         # 沒有 --project-dir
        self.assertEqual(self.iv(runs=["=" + self.full_run(False, name="w-plain")])["status"], "GAP")          # 不是刷機包的掃描
        self.assertEqual(self.iv(runs=[])["status"], "GAP")

    def test_sources_yml_problems_fail(self):
        self.assertEqual(self.iv("v9.9.9-x")["status"], "FAIL")                               # sources.yml 沒有這個版本
        w(os.path.join(self.proj, "sources.yml"), "schema: [")
        self.assertEqual(self.iv()["status"], "FAIL")

    def test_reads_the_full_scan_not_the_layer_rescans(self):
        full = self.full_run()
        other = self.p("w-bsp")
        w(os.path.join(other, "scan", "list.json"), json.dumps({"rootfs": [{"variant": "rootfs", "l4t": {"release": "1.0", "status": "OK"}}]}))
        self.assertEqual(self.iv(runs=["-bsp=" + other, "=" + full])["status"], "OK")

    def test_jetson_hooks_use_it(self):
        ctx = {"args": argparse.Namespace(project_dir=self.proj, run=["=" + self.full_run()]), "version": "v39.2.1-demo1"}
        self.assertEqual(self.js.JetsonHooks().independent_version(ctx)["status"], "OK")


if __name__ == "__main__":
    unittest.main()
