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
                               grype=None, grype_total_timeout=100, vendor_config=None, now=now, demo=kw.get("demo", False))
        st, detail = match.run(a, kw.get("kernel_runner"))
        plan = json.load(open(os.path.join(out, "plan.json")))
        # 模擬 notify：把新狀態寫回 state-dir
        json.dump(plan["state"], open(os.path.join(self.state, "state.json"), "w"))
        self.write_base(7, len({x["key"] for x in plan["actions"] if x["op"] == "open"}) + 1)
        return st, detail, plan


HEALTH_KEY = match.issue_key("real", "health")


def nohealth(plan):
    return [x for x in plan["actions"] if x["key"] != HEALTH_KEY]


class T(Base):
    def kev_key(self, plan, cve):
        e = next(e for e in plan["state"]["matches"].values() if e["cve"] == cve)
        return match.kev_group_key("real", e)

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
        opens = [x for x in nohealth(plan) if x["op"] == "open"]
        self.assertEqual(len(opens), 1)
        self.assertIn("CVE-2018-18074", opens[0]["title"])
        self.assertIn("shipped", opens[0]["labels"])
        self.assertIn("layer-bsp", opens[0]["labels"])
        self.assertEqual(st, "ATTENTION")
        st, _, plan = self.run_once(NOW3)
        self.assertEqual([x for x in nohealth(plan) if x["op"] == "open"], [])

    def test_gone_comments(self):
        self.run_once(NOW1)
        self.kev.append("CVE-2018-18074")
        self.run_once(NOW2)
        self.grype = self.grype[:1]                             # requests 的比對消失
        _, _, plan = self.run_once(NOW3)
        acts = nohealth(plan)
        self.assertEqual([x["op"] for x in acts], ["comment"])
        self.assertEqual(acts[0]["key"], self.kev_key(plan, "CVE-2018-18074"))

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
        self.assertEqual(len(opens), 1)                         # 超過上限：只有一個彙總 Issue
        self.assertIn("彙總", opens[0]["title"])
        self.assertIn("5 個新的命中群組", opens[0]["title"])

    def test_demo_marking(self):
        self.run_once(NOW1)
        self.kev.append("CVE-2018-18074")
        _, _, plan = self.run_once(NOW2, demo=True)
        o = [x for x in plan["actions"] if x["op"] == "open"][0]
        self.assertTrue(o["title"].startswith("[示範專案（公開 BSP）]"))
        self.assertIn("demo", o["labels"])
        self.assertIn("不是真的出貨產品", o["body"])

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

    def test_baseline_needs_grype(self):
        match.mods()["eg"].prepare = lambda *a, **k: ({"status": "NOT_RUN", "why": "fake down"}, None)
        with self.assertRaises(match.Fail):
            self.run_once(NOW1)

    def test_no_sbom_first_run_is_gap_without_plan(self):
        self.inventory["releases"] = []
        self.inventory["status"] = "GAP"
        json.dump(self.inventory, open(os.path.join(self.inv, "inventory.json"), "w"))
        json.dump({"dateReleased": NOW1, "vulnerabilities": [{"cveID": "CVE-2021-44228"}]}, open(os.path.join(self.feeds, "cisa-kev.json"), "w"))
        out = os.path.join(self.w, "out-empty")
        a = argparse.Namespace(inventory=os.path.join(self.inv, "inventory.json"), state_dir=self.state, feeds=self.feeds, out=out, mode="real",
                               kev_overlay=None, max_new_issues=20, run_url=None, grype=None, grype_total_timeout=100, vendor_config=None,
                               now=NOW1, demo=True)
        st, _ = match.run(a)
        self.assertEqual(st, "GAP")
        self.assertFalse(os.path.exists(os.path.join(out, "plan.json")))
        self.assertTrue(os.path.exists(os.path.join(out, "report.md")))

    def test_baseline_reappear_opens_issue(self):
        """預驗 E1：基準裡的比對消失後再出現 → 開 Issue（不再當基準）。"""
        self.run_once(NOW1)                                     # 基準含 log4j
        saved = self.grype
        self.grype = saved[1:]                                  # log4j 消失
        self.run_once(NOW2)
        self.grype = saved                                      # 再出現
        _, _, plan = self.run_once(NOW3)
        opens = [x for x in nohealth(plan) if x["op"] == "open"]
        self.assertEqual(len(opens), 1)
        self.assertIn("CVE-2021-44228", opens[0]["title"])

    def test_new_component_in_existing_group_notifies(self):
        """預驗 E2：已有 Issue 的群組出現新元件 → open_if_closed（原 Issue 留言，關閉了就開新的）。"""
        self.run_once(NOW1)
        self.kev.append("CVE-2018-18074")
        _, _, p2 = self.run_once(NOW2)
        self.grype.append(gmatch("CVE-2018-18074", "requests", "2.19.1", "pkg:pypi/requests@2.19.1"))
        _, _, plan = self.run_once(NOW3)
        acts = nohealth(plan)
        self.assertEqual([x["op"] for x in acts], ["open_if_closed"])
        self.assertEqual(acts[0]["key"], [x for x in p2["actions"] if x["op"] == "open"][0]["key"])
        self.assertIn("新增元件", acts[0]["body"])
        self.assertIn("requests@2.19.1", acts[0]["body"])

    def test_health_issue_after_two_degraded_runs(self):
        self.run_once(NOW1)                                     # 測試環境沒有 EUVD：每次都降級
        _, _, p2 = self.run_once(NOW2)
        self.assertEqual([x for x in p2["actions"] if x["key"] == HEALTH_KEY], [])     # 第 1 次降級：還不通知
        _, _, p3 = self.run_once(NOW3)
        h = [x for x in p3["actions"] if x["key"] == HEALTH_KEY]
        self.assertEqual(len(h), 1)
        self.assertIn("EUVD", h[0]["body"])
        _, _, p4 = self.run_once("2026-11-13T01:00:00Z")
        self.assertEqual([x for x in p4["actions"] if x["key"] == HEALTH_KEY], [])     # 7 天內不重複提醒

    def test_health_recovery_needs_two_ok_runs(self):
        h = {"dumpling": {"health": {"streak": 3, "since": NOW1, "notified_at": NOW2}}}
        now = match.parse_now(NOW3)
        self.assertEqual(match.health_actions("real", h, [], now, None), [])             # 第 1 次正常：不留言
        out = match.health_actions("real", h, [], now, None)
        self.assertEqual([x["op"] for x in out], ["comment"])                            # 連續第 2 次：恢復留言
        self.assertEqual(match.health_actions("real", h, [], now, None), [])             # 之後不再留言

    def test_events_over_cap_become_summary(self):
        self.run_once(NOW1)
        self.grype.append(gmatch("CVE-2020-1000", "requests", "2.19.0", REQ))
        self.kev += ["CVE-2018-18074", "CVE-2020-1000"]
        _, _, p2 = self.run_once(NOW2, max_new=2)                 # 兩個群組各開一個 Issue
        self.assertEqual(len([x for x in nohealth(p2) if x["op"] == "open"]), 2)
        for cve in ("CVE-2018-18074", "CVE-2020-1000"):          # 兩個群組都出現新元件
            self.grype.append(gmatch(cve, "requests", "2.19.1", "pkg:pypi/requests@2.19.1"))
        _, _, plan = self.run_once(NOW3, max_new=1)
        acts = nohealth(plan)
        self.assertEqual([x["op"] for x in acts], ["open"])
        self.assertIn("彙總", acts[0]["title"])
        self.assertIn("2 個群組有新的比對", acts[0]["title"])

    def test_kernel_cna_sticky_when_feed_missing(self):
        kv = os.path.join(self.inv, "releases", "0", "kv.json")
        json.dump({"schema": "sca-center-kernel-versions/2", "shipped": [{"version": "6.8.12-x", "upstream_version": "6.8.12"}]}, open(kv, "w"))
        self.inventory["releases"][0]["kernel_versions"] = "releases/0/kv.json"
        json.dump(self.inventory, open(os.path.join(self.inv, "inventory.json"), "w"))
        runner = lambda v, m: ({"CVE-2024-99999": "affected"}, "fake")
        self.run_once(NOW1, kernel_runner=runner)
        self.kev.append("CVE-2024-99999")
        self.run_once(NOW2, kernel_runner=runner)
        self.kev.remove("CVE-2024-99999")                       # 資料源這次沒有這個 CVE
        _, _, plan = self.run_once(NOW3, kernel_runner=runner)
        self.assertEqual([x for x in nohealth(plan) if x["op"] == "comment"], [])      # 不記成消失
        e = next(e for e in plan["state"]["matches"].values() if e["cve"] == "CVE-2024-99999")
        self.assertEqual(e["status"], "open")

    def test_release_version_dev_rejected(self):
        self.inventory["releases"][0]["watch_version"] = "dev"
        json.dump(self.inventory, open(os.path.join(self.inv, "inventory.json"), "w"))
        st, _ = match.run(argparse.Namespace(inventory=os.path.join(self.inv, "inventory.json"), state_dir=self.state, feeds=self.feeds,
                                             out=os.path.join(self.w, "o"), mode="real", kev_overlay=None, max_new_issues=20, run_url=None,
                                             grype=None, grype_total_timeout=100, vendor_config=None, now=NOW1, demo=False))
        self.assertEqual(st, "GAP")

    def test_state_has_no_paths(self):
        _, _, plan = self.run_once(NOW1)
        txt = json.dumps(plan["state"])
        self.assertNotIn(self.w, txt)
        self.assertNotIn("releases/0", txt)


if __name__ == "__main__":
    unittest.main()
