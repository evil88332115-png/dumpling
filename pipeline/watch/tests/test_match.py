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
        self.saved_euvd = m["euvd"].exploited_index
        self.euvd = {}              # EUVD 標示已遭利用的 CVE；None＝EUVD 不能用
        test = self

        def exploited_index(index_dir, max_age=None, kev_max_age=None, now=None):
            if test.euvd is None:
                return {"status": "GAP", "usable": False, "exploited": None, "meta": None, "detail": "fake EUVD unavailable"}
            return {"status": "OK", "usable": True, "meta": {}, "detail": "fake EUVD",
                    "exploited": {c: {"euvd_ids": [], "sources": ["cisa_kev"], "date_added": "2026-01-01"} for c in test.euvd}}
        m["euvd"].exploited_index = exploited_index

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
        match.mods()["euvd"].exploited_index = self.saved_euvd
        shutil.rmtree(self.w, ignore_errors=True)

    def write_base(self, issue, n):
        json.dump({"issue": issue, "updated_at": "t" if issue else None, "body_sha256": "s" if issue else None, "watch_issues": n},
                  open(os.path.join(self.state, "state-base.json"), "w"))

    def run_once(self, now, mode="real", **kw):
        vs = [{"cveID": c, "vendorProject": "Apache", "product": "Log4j", "dateAdded": "2021-12-10"} for c in self.kev]
        vs += getattr(self, "kev_extra", [])
        json.dump({"dateReleased": now, "vulnerabilities": vs}, open(os.path.join(self.feeds, "cisa-kev.json"), "w"))
        out = os.path.join(self.w, "out-" + now[:10])
        a = argparse.Namespace(inventory=os.path.join(self.inv, "inventory.json"), state_dir=self.state, feeds=self.feeds, out=out, mode=mode,
                               kev_overlay=kw.get("overlay"), max_new_issues=kw.get("max_new", 20), run_url="https://github.com/o/r/actions/runs/1",
                               grype=None, grype_total_timeout=100, vendor_config=kw.get("vendor_config"), now=now, demo=kw.get("demo", False),
                               allow_baseline=kw.get("allow_baseline", True), prev_schedule=kw.get("prev"), run_id="999")
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
                               now=NOW1, demo=True, allow_baseline=True, prev_schedule=None, run_id=None)
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
        self.run_once(NOW1)
        self.euvd = None                                        # 之後 EUVD 不能用：每次都降級
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
                                             grype=None, grype_total_timeout=100, vendor_config=None, now=NOW1, demo=False,
                                             allow_baseline=True, prev_schedule=None, run_id=None))
        self.assertEqual(st, "GAP")

    def test_baseline_needs_explicit_allow(self):
        """PR #28 建議 1：沒有狀態也沒有監控 Issue 時，不悄悄建基準（GAP、沒有 plan）。"""
        out = os.path.join(self.w, "out-noallow")
        json.dump({"dateReleased": NOW1, "vulnerabilities": [{"cveID": "CVE-2021-44228"}]}, open(os.path.join(self.feeds, "cisa-kev.json"), "w"))
        a = argparse.Namespace(inventory=os.path.join(self.inv, "inventory.json"), state_dir=self.state, feeds=self.feeds, out=out, mode="real",
                               kev_overlay=None, max_new_issues=20, run_url=None, grype=None, grype_total_timeout=100, vendor_config=None,
                               now=NOW1, demo=True, allow_baseline=False, prev_schedule=None, run_id=None)
        st, detail = match.run(a)
        self.assertEqual(st, "GAP")
        self.assertIn("baseline=true", detail)
        # #32 驗證 F4：real 時只開「還沒有基準」的提醒（state 是 null，不寫狀態）
        plan = json.load(open(os.path.join(out, "plan.json")))
        self.assertIsNone(plan["state"])
        self.assertIsNone(plan["state_base"])
        self.assertEqual([(x["op"], x["key"]) for x in plan["actions"]], [("open", match.issue_key("real", "no-baseline"))])
        self.assertIn("watch-health", plan["actions"][0]["labels"])
        # 提醒 Issue 存在時，下一次還是「沒有基準」，不會變成「沒有狀態卻有監控 Issue」的 FAIL
        json.dump({"issue": None, "updated_at": None, "body_sha256": None, "watch_issues": 1,
                   "watch_keys": [match.issue_key("real", "no-baseline")]}, open(os.path.join(self.state, "state-base.json"), "w"))
        st, _ = match.run(a)
        self.assertEqual(st, "GAP")
        # 之後建立基準：在提醒 Issue 留言
        _, _, plan = self.run_once(NOW1)
        self.assertIn(("comment", match.issue_key("real", "no-baseline")), [(x["op"], x["key"]) for x in plan["actions"]])

    def test_baseline_fails_when_euvd_unavailable(self):
        """PR #28 應修 1：第一次建基準時 EUVD 不能用 → FAIL。"""
        self.euvd = None
        with self.assertRaises(match.Fail) as cm:
            self.run_once(NOW1)
        self.assertIn("EUVD", str(cm.exception))

    def test_baseline_fails_when_release_has_problem(self):
        self.inventory["releases"][0]["problems"] = ["sbom-demo-v1-os.cdx.json 下載失敗（HTTP 502）"]
        json.dump(self.inventory, open(os.path.join(self.inv, "inventory.json"), "w"))
        with self.assertRaises(match.Fail) as cm:
            self.run_once(NOW1)
        self.assertIn("Release", str(cm.exception))

    def test_baseline_fails_when_kernel_cna_not_run(self):
        kv = os.path.join(self.inv, "releases", "0", "kv.json")
        json.dump({"schema": "sca-center-kernel-versions/2", "shipped": [{"version": "6.8.12-x", "upstream_version": "6.8.12"}]}, open(kv, "w"))
        self.inventory["releases"][0]["kernel_versions"] = "releases/0/kv.json"
        json.dump(self.inventory, open(os.path.join(self.inv, "inventory.json"), "w"))
        with self.assertRaises(match.Fail):
            self.run_once(NOW1, kernel_runner=lambda v, m: (None, "fake: mirror down"))

    def test_prune_gone_after_180_days(self):
        self.run_once(NOW1)
        self.kev.append("CVE-2018-18074")
        self.run_once(NOW2)
        self.grype = self.grype[:1]
        self.run_once(NOW3)                                     # requests 消失
        _, _, plan = self.run_once("2027-06-01T01:00:00Z")     # 超過 180 天
        self.assertFalse(any(e["cve"] == "CVE-2018-18074" for e in plan["state"]["matches"].values()))
        self.assertTrue(any(e["cve"] == "CVE-2021-44228" for e in plan["state"]["matches"].values()))

    def test_large_state_warns(self):
        self.run_once(NOW1)
        old = match.STATE_WARN_CHARS
        match.STATE_WARN_CHARS = 10
        try:
            _, _, plan = self.run_once(NOW2)
        finally:
            match.STATE_WARN_CHARS = old
        self.assertTrue(any("接近上限" in x["title"] for x in plan["actions"] if x["op"] == "open_if_closed"))

    def test_size_warning_is_attention_and_throttled(self):
        """#32 驗證 F1：大小警告讓整輪 ATTENTION，而且 7 天才提醒一次。"""
        self.run_once(NOW1)
        orig = match.state_size
        match.state_size = lambda st: 50000
        try:
            st, _, p2 = self.run_once(NOW2)
            _, _, p3 = self.run_once(NOW3)
            _, _, p9 = self.run_once("2026-11-19T01:00:00Z")
        finally:
            match.state_size = orig
        self.assertEqual(st, "ATTENTION")
        self.assertEqual(p2["status"], "ATTENTION")
        warn = lambda p: [x for x in p["actions"] if "接近上限" in x.get("title", "")]
        self.assertEqual(len(warn(p2)), 1)
        self.assertEqual(warn(p3), [])                       # 隔天不再留言
        self.assertEqual(len(warn(p9)), 1)                   # 7 天後再提醒

    def test_pruned_group_reappears_with_open_if_closed(self):
        """#32 驗證 F2：修剪過的群組再出現 → open_if_closed（舊 Issue 已關閉時會開新的，不會被「已有 Issue」跳過）。"""
        self.run_once(NOW1)
        self.kev.append("CVE-2018-18074")
        _, _, p2 = self.run_once(NOW2)
        key = [x for x in p2["actions"] if x["op"] == "open"][0]["key"]
        saved = self.grype
        self.grype = saved[:1]
        self.run_once(NOW3)                                   # 消失
        _, _, pp = self.run_once("2027-06-01T01:00:00Z")     # 181 天以上：修剪
        self.assertIn(key, pp["state"]["dumpling"]["pruned_keys"])
        self.grype = saved                                    # 再出現
        _, _, p = self.run_once("2027-06-02T01:00:00Z")
        acts = [x for x in nohealth(p) if x["key"] == key]
        self.assertEqual([x["op"] for x in acts], ["open_if_closed"])
        self.assertNotIn(key, p["state"]["dumpling"]["pruned_keys"])

    def test_baseline_fails_when_grype_db_stale(self):
        """#32 驗證 F3：Grype DB 過期不拿來建基準。"""
        match.mods()["eg"].db_status = lambda *a, **k: {"status": "GAP", "usable": True, "built": "x", "detail": "stale"}
        with self.assertRaises(match.Fail) as cm:
            self.run_once(NOW1)
        self.assertIn("Grype DB", str(cm.exception))

    def test_baseline_fails_when_l4t_map_gap(self):
        eg = match.mods()["eg"]
        inner = eg.prepare

        def prep(*a, **k):
            info, ctx = inner(*a, **k)
            info["kernel_map"] = {"status": "GAP", "detail": "L4T 39.9 不在對應檔"}
            return info, ctx
        eg.prepare = prep
        with self.assertRaises(match.Fail) as cm:
            self.run_once(NOW1)
        self.assertIn("L4T", str(cm.exception))

    def test_prev_schedule_cancelled_is_degraded(self):
        """C0／#32 驗證 F6：上一次排程被取消 → 報告 GAP，連續 2 次開健康 Issue。"""
        pv = os.path.join(self.w, "prev.json")
        json.dump({"runs": [{"id": 999, "status": "in_progress", "conclusion": None, "created_at": NOW3},
                            {"id": 5, "status": "completed", "conclusion": "cancelled", "created_at": "2026-11-11T01:17:00Z"}]}, open(pv, "w"))
        self.run_once(NOW1)
        self.run_once(NOW2, prev=pv)
        _, _, plan = self.run_once(NOW3, prev=pv)
        res = json.load(open(os.path.join(self.w, "out-" + NOW3[:10], "result.json")))
        self.assertTrue(any("cancelled" in g for g in res["gaps"]))
        h = [x for x in plan["actions"] if x["key"] == HEALTH_KEY]
        self.assertEqual(len(h), 1)
        self.assertIn("cancelled", h[0]["body"])

    def test_prev_schedule_too_old_and_ok(self):
        self.assertTrue(match.prev_schedule_check(None, None, match.parse_now(NOW3)) == ([], None))
        pv = os.path.join(self.w, "prev2.json")
        json.dump({"runs": [{"id": 7, "status": "completed", "conclusion": "success", "created_at": "2026-11-10T01:17:00Z"}]}, open(pv, "w"))
        bad, _ = match.prev_schedule_check(pv, "1", match.parse_now(NOW3))
        self.assertTrue(any("36 小時" in x for x in bad))
        bad, _ = match.prev_schedule_check(pv, "1", match.parse_now("2026-11-10T20:00:00Z"))
        self.assertEqual(bad, [])
        json.dump({"error": "API 失敗"}, open(pv, "w"))
        bad, _ = match.prev_schedule_check(pv, "1", match.parse_now(NOW3))
        self.assertTrue(bad)

    def test_issue_shows_release_results(self):
        self.inventory["releases"][0].update(report_status="ATTENTION", release_gate="FAIL")
        json.dump(self.inventory, open(os.path.join(self.inv, "inventory.json"), "w"))
        self.run_once(NOW1)
        self.kev.append("CVE-2018-18074")
        _, _, plan = self.run_once(NOW2)
        body = [x for x in plan["actions"] if x["op"] == "open"][0]["body"]
        self.assertIn("報告狀態（report_status）ATTENTION", body)
        self.assertIn("發行閘門（release_gate）FAIL", body)
        self.assertIn("流程結果 NOT_RUN", body)

    def test_issue_release_results_missing_is_not_run(self):
        self.run_once(NOW1)
        self.kev.append("CVE-2018-18074")
        _, _, plan = self.run_once(NOW2)
        body = [x for x in plan["actions"] if x["op"] == "open"][0]["body"]
        self.assertIn("報告狀態（report_status）NOT_RUN", body)
        self.assertIn("發行閘門（release_gate）NOT_RUN", body)

    def test_firmware_vendors_new_kev_opens_vendor_issue(self):
        """D-043 第 3 點：Intel／AMD／AMI／NVIDIA（BIOS／vBIOS 韌體）新的 KEV 一律提醒（廠商層級，沒有元件比對也提醒）。
        KEV 的 vendorProject 拼法：CISA 2026.11.10 實查 Intel、AMI；AMD、NVIDIA 目前沒有條目，以 exploited_vendor 的別名涵蓋常見拼法。"""
        cfg = os.path.join(os.path.dirname(__file__), "..", "vendor-watch.json")
        self.run_once(NOW1, vendor_config=cfg)
        self.kev_extra = [
            {"cveID": "CVE-2026-90001", "vendorProject": "AMI", "product": "Aptio V", "dateAdded": NOW2[:10]},
            {"cveID": "CVE-2026-90002", "vendorProject": "Advanced Micro Devices", "product": "AGESA", "dateAdded": NOW2[:10]},
            {"cveID": "CVE-2026-90003", "vendorProject": "NVIDIA Corporation", "product": "GPU Firmware", "dateAdded": NOW2[:10]},
            {"cveID": "CVE-2026-90004", "vendorProject": "Intel", "product": "CSME", "dateAdded": NOW2[:10]},
            {"cveID": "CVE-2026-90005", "vendorProject": "Contoso", "product": "Widget", "dateAdded": NOW2[:10]},   # 不在清單：不提醒
        ]
        _, _, plan = self.run_once(NOW2, vendor_config=cfg)
        vend = [x for x in plan["actions"] if x["op"] == "open" and "vendor-level" in x["labels"]]
        cves = sorted(__import__("re").search(r"CVE-\d{4}-\d+", t["title"]).group(0) for t in vend)
        self.assertEqual(cves, ["CVE-2026-90001", "CVE-2026-90002", "CVE-2026-90003", "CVE-2026-90004"])
        _, _, plan = self.run_once(NOW3, vendor_config=cfg)                 # 隔天不重複
        self.assertEqual([x for x in plan["actions"] if x["op"] == "open" and "vendor-level" in x["labels"]], [])

    def test_state_has_no_paths(self):
        _, _, plan = self.run_once(NOW1)
        txt = json.dumps(plan["state"])
        self.assertNotIn(self.w, txt)
        self.assertNotIn("releases/0", txt)


if __name__ == "__main__":
    unittest.main()
