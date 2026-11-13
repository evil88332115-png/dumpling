"""match.py：基準、新的命中、不重複、消失、核心 CNA、公開檢查。Grype 以假結果替換（不跑真的 Grype）。合成資料。"""
import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import match  # noqa: E402

NOW1, NOW2, NOW3 = "2026-11-10T01:00:00Z", "2026-11-11T01:00:00Z", "2026-11-12T01:00:00Z"
LOG4J = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
REQ = "pkg:pypi/requests@2.19.0"


def sbom(comps):
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "components": [{"type": "library", "name": n, "version": v, "purl": p, "bom-ref": p} for n, v, p in comps]}


def gmatch(cve, name, ver, purl):
    return {"vulnerability": {"id": cve}, "relatedVulnerabilities": [],
            "artifact": {"name": name, "version": ver, "purl": purl, "type": "java-archive"}}


class Base(unittest.TestCase):
    def setUp(self):
        self.w = tempfile.mkdtemp(prefix="c3-match-", dir=os.environ.get("TMPDIR"))
        self.inv = os.path.join(self.w, "inv")
        os.makedirs(os.path.join(self.inv, "releases", "0"))
        comps = [("log4j-core", "2.14.1", LOG4J), ("requests", "2.19.0", REQ)]
        self.sb = os.path.join(self.inv, "releases", "0", "sbom-demo-v1-bsp.cdx.json")
        raw = json.dumps(sbom(comps)).encode()
        open(self.sb, "wb").write(raw)
        self.inventory = {"schema": "dumpling-watch-inventory/1", "status": "OK", "releases": [{
            "tag": "demo/v1", "kind": "release", "project": "demo", "version": "v1", "watch_version": "v1", "status": "shipped",
            "os_responsibility": "customer", "html_url": "https://github.com/o/r/releases/tag/demo/v1",
            "sboms": {"bsp": {"file": "releases/0/sbom-demo-v1-bsp.cdx.json", "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}},
            "kernel_versions": None, "problems": []}], "skipped": []}
        json.dump(self.inventory, open(os.path.join(self.inv, "inventory.json"), "w"))
        self.feeds = os.path.join(self.w, "feeds")
        os.makedirs(self.feeds)
        self.kev = ["CVE-2021-44228"]
        self.grype = [gmatch("CVE-2021-44228", "log4j-core", "2.14.1", LOG4J), gmatch("CVE-2018-18074", "requests", "2.19.0", REQ)]
        self.state = os.path.join(self.w, "state")
        os.makedirs(self.state)
        self.write_base(None, 0)
        m = match.mods()
        eg = m["eg"]
        self.saved = {k: getattr(eg, k) for k in ("prepare", "find_grype", "db_status", "sandbox_check")}
        test = self

        def prepare(p, spec, *a, **k):
            pkgs = [c for c in json.load(open(spec["sbom"]))["components"]]
            doc = {"matches": [x for x in test.grype]}
            return {"status": "OK", "why": None}, {"doc": doc, "pkgs": pkgs, "sha": spec["sha256"], "gate": None, "srcmap": None,
                                                   "kmap": None, "services": None, "annotations": []}
        eg.prepare = prepare
        eg.find_grype = lambda x=None: ("/bin/true", "fake")
        eg.db_status = lambda *a, **k: {"status": "OK", "usable": True, "built": "x", "detail": "fake db"}
        eg.sandbox_check = lambda: (True, "fake")

    def tearDown(self):
        eg = match.mods()["eg"]
        for k, v in self.saved.items():
            setattr(eg, k, v)
        shutil.rmtree(self.w, ignore_errors=True)

    def write_base(self, issue, n):
        json.dump({"issue": issue, "updated_at": "t" if issue else None, "body_sha256": "s" if issue else None, "watch_issues": n},
                  open(os.path.join(self.state, "state-base.json"), "w"))

    def run_once(self, now, mode="real", **kw):
        json.dump({"dateReleased": now, "vulnerabilities": [{"cveID": c, "vendorProject": "Apache", "product": "Log4j", "dateAdded": "2021-12-10"}
                                                            for c in self.kev]}, open(os.path.join(self.feeds, "cisa-kev.json"), "w"))
        out = os.path.join(self.w, "out-" + now[:10])
        a = argparse.Namespace(inventory=os.path.join(self.inv, "inventory.json"), state_dir=self.state, feeds=self.feeds, out=out, mode=mode,
                               kev_overlay=kw.get("overlay"), max_new_issues=kw.get("max_new", 20), run_url="https://github.com/o/r/actions/runs/1",
                               grype=None, grype_total_timeout=100, vendor_config=None, now=now)
        st, detail = match.run(a, kw.get("kernel_runner"))
        plan = json.load(open(os.path.join(out, "plan.json")))
        # 模擬 notify：把新狀態寫回 state-dir
        json.dump(plan["state"], open(os.path.join(self.state, "state.json"), "w"))
        self.write_base(7, len({x["key"] for x in plan["actions"] if x["op"] == "open"}) + 1)
        return st, detail, plan


class T(Base):
    def test_first_run_is_baseline(self):
        st, detail, plan = self.run_once(NOW1)
        self.assertEqual(plan["actions"], [])
        self.assertIn("建立基準", detail)
        self.assertTrue(all(e["baseline"] for e in plan["state"]["matches"].values()))
        self.assertEqual(len(plan["state"]["matches"]), 1)

    def test_new_kev_opens_one_issue_then_no_duplicate(self):
        self.run_once(NOW1)
        self.kev.append("CVE-2018-18074")                      # 合成的 KEV：把 requests 的 CVE 加進清單
        st, _, plan = self.run_once(NOW2)
        opens = [x for x in plan["actions"] if x["op"] == "open"]
        self.assertEqual(len(opens), 1)
        self.assertIn("CVE-2018-18074", opens[0]["title"])
        self.assertIn("shipped", opens[0]["labels"])
        self.assertIn("layer-bsp", opens[0]["labels"])
        self.assertEqual(st, "ATTENTION")
        st, _, plan = self.run_once(NOW3)
        self.assertEqual([x for x in plan["actions"] if x["op"] == "open"], [])

    def test_gone_comments(self):
        self.run_once(NOW1)
        self.kev.append("CVE-2018-18074")
        self.run_once(NOW2)
        self.grype = self.grype[:1]                             # requests 的比對消失
        _, _, plan = self.run_once(NOW3)
        self.assertEqual([x["op"] for x in plan["actions"]], ["comment"])

    def test_missing_state_with_issues_fails(self):
        self.write_base(None, 3)
        with self.assertRaises(match.Fail):
            self.run_once(NOW1)

    def test_overlay_only_in_drill(self):
        ov = os.path.join(self.w, "ov.json")
        json.dump({"vulnerabilities": [{"cveID": "CVE-2018-18074"}]}, open(ov, "w"))
        with self.assertRaises(match.Fail):
            self.run_once(NOW1, mode="real", overlay=ov)
        self.run_once(NOW1, mode="drill")
        _, _, plan = self.run_once(NOW2, mode="drill", overlay=ov)
        opens = [x for x in plan["actions"] if x["op"] == "open"]
        self.assertEqual(len(opens), 1)
        self.assertIn("演練", opens[0]["body"])

    def test_cap_makes_summary(self):
        self.run_once(NOW1)
        extra = [gmatch(f"CVE-2020-{1000 + i}", "requests", "2.19.0", REQ) for i in range(5)]
        self.grype += extra
        self.kev += [m["vulnerability"]["id"] for m in extra]
        _, _, plan = self.run_once(NOW2, max_new=2)
        opens = [x for x in plan["actions"] if x["op"] == "open"]
        self.assertEqual(len(opens), 3)
        self.assertIn("彙總", opens[-1]["title"])

    def test_kernel_cna(self):
        kv = os.path.join(self.inv, "releases", "0", "kernel-versions-demo-v1.json")
        json.dump({"schema": "sca-center-kernel-versions/2", "shipped": [{"version": "6.8.12-1-tegra", "upstream_version": "6.8.12", "upstream_basis": "source-makefile",
                                "upstream_note": "ok"}]}, open(kv, "w"))
        self.inventory["releases"][0]["kernel_versions"] = "releases/0/kernel-versions-demo-v1.json"
        json.dump(self.inventory, open(os.path.join(self.inv, "inventory.json"), "w"))
        self.run_once(NOW1, kernel_runner=lambda v, m: ({}, "fake"))
        self.kev.append("CVE-2024-99999")
        _, _, plan = self.run_once(NOW2, kernel_runner=lambda v, m: ({"CVE-2024-99999": "unknown"}, "fake"))
        opens = [x for x in plan["actions"] if x["op"] == "open"]
        self.assertEqual(len(opens), 1)
        self.assertIn("pkg:generic/linux@6.8.12", opens[0]["body"])
        self.assertIn(".config not judged", opens[0]["body"])

    def test_kernel_null_upstream_is_gap(self):
        kv = os.path.join(self.inv, "releases", "0", "kv.json")
        json.dump({"schema": "sca-center-kernel-versions/2", "shipped": [{"version": "6.1.0-rpi7", "upstream_version": None, "upstream_note": "對不上 Makefile"}]}, open(kv, "w"))
        self.inventory["releases"][0]["kernel_versions"] = "releases/0/kv.json"
        json.dump(self.inventory, open(os.path.join(self.inv, "inventory.json"), "w"))
        st, _, plan = self.run_once(NOW1)
        res = json.load(open(os.path.join(self.w, "out-" + NOW1[:10], "result.json")))
        self.assertTrue(any("對不上 Makefile" in g for g in res["gaps"]))
        self.assertEqual(res["per_sbom"]["dumpling:demo/v1#bsp"]["kernel_cna"], "GAP")

    def test_kernel_schema_v1_is_gap(self):
        kv = os.path.join(self.inv, "releases", "0", "kv.json")
        json.dump({"schema": "sca-center-kernel-versions/1", "shipped": ["6.8.12"]}, open(kv, "w"))
        self.inventory["releases"][0]["kernel_versions"] = "releases/0/kv.json"
        json.dump(self.inventory, open(os.path.join(self.inv, "inventory.json"), "w"))
        self.run_once(NOW1, kernel_runner=lambda v, m: self.fail("不應該呼叫核心 CNA"))
        res = json.load(open(os.path.join(self.w, "out-" + NOW1[:10], "result.json")))
        self.assertTrue(any("schema" in g and "sca-center-kernel-versions/2" in g for g in res["gaps"]))

    def test_state_has_no_paths(self):
        _, _, plan = self.run_once(NOW1)
        txt = json.dumps(plan["state"])
        self.assertNotIn(self.w, txt)
        self.assertNotIn("releases/0", txt)


if __name__ == "__main__":
    unittest.main()
