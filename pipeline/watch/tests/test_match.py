"""match.py：基準、新的命中、不重複、消失、核心 CNA、公開檢查。Grype 以假結果替換（不跑真的 Grype）。合成資料。"""
import argparse
import hashlib
import html
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
        self.assertIn("[ATTENTION]", opens[0]["title"])         # D-040「標 ATTENTION」：標題與標籤
        self.assertIn("attention", opens[0]["labels"])

    def test_demo_marking(self):
        self.run_once(NOW1)
        self.kev.append("CVE-2018-18074")
        _, _, plan = self.run_once(NOW2, demo=True)
        o = [x for x in plan["actions"] if x["op"] == "open"][0]
        self.assertTrue(o["title"].startswith("[示範專案（公開 BSP）]"))
        self.assertIn("demo", o["labels"])
        self.assertIn("不是真的出貨產品", o["body"])
        self.assertIs(plan["demo"], True)                  # 狀態 Issue 也加 demo 標籤（issues.py apply 依這個）
        _, _, plan2 = self.run_once(NOW2)
        self.assertNotIn("demo", plan2)

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
        self.inventory["releases"][0].update(report_status="ATTENTION", release_gate="NOT_ASSESSED",
                                             reports=[{"report": "bsp", "report_status": "ATTENTION", "release_gate": "NOT_ASSESSED"},
                                                      {"report": "os", "report_status": "OK", "release_gate": "OK"}],
                                             attention=["核心 CVE 鏡像上游連不上，沿用 30 小時前的鏡像"])
        json.dump(self.inventory, open(os.path.join(self.inv, "inventory.json"), "w"))
        self.run_once(NOW1)
        self.kev.append("CVE-2018-18074")
        _, _, plan = self.run_once(NOW2)
        body = [x for x in plan["actions"] if x["op"] == "open"][0]["body"]
        self.assertIn("報告狀態（report_status）ATTENTION", body)
        self.assertIn("發行閘門（release_gate）NOT_ASSESSED", body)
        self.assertIn("bsp 報告 ATTENTION／閘門 NOT_ASSESSED", body)
        self.assertIn("os 報告 OK／閘門 OK", body)
        self.assertIn("流程結果（pipeline_result）NOT_RUN", body)
        self.assertIn("沿用 30 小時前的鏡像", body)

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


class FeedFallback(Base):
    """鏡像用了舊資料頂替（pipeline/lib/mirrors.sh 的 ATTENTION）：報告與 Issue 都寫出那一行；runner 的絕對路徑不進 Issue。"""
    RUNNER_PATH = "/home/runner/work/_temp/kcve-cache/kcve"

    def write_kcve_fallback(self):
        d = os.path.join(self.feeds, "kernel-cve")
        os.makedirs(d, exist_ok=True)
        open(os.path.join(d, "SOURCE"), "w", encoding="utf-8").write(
            "commit=0123456789abcdef0123456789abcdef01234567\nfetched_utc=2026-11-10T01:00:00Z\nfallback=yes\nfallback_utc=2026-11-11T01:00:00Z\n"
            f"fallback_note=上游連不上（clone 失敗：{self.RUNNER_PATH}/x），沿用 vulns.git 0123456789ab（下載於 2026-11-10T01:00:00Z，24 小時前；上限 48 小時）"
            "：這段時間新增的核心 CVE 不在清單裡\n")
        open(os.path.join(self.feeds, "kernel-cve.result"), "w").write(f"ATTENTION mirror={self.feeds}/kernel-cve manifest=x 上游連不上\n")

    def test_kernel_fallback_in_report_and_issue(self):
        self.run_once(NOW1)
        self.write_kcve_fallback()
        self.kev.append("CVE-2018-18074")
        st, _, plan = self.run_once(NOW2, demo=True)
        self.assertEqual(st, "ATTENTION")
        opens = [x for x in nohealth(plan) if x["op"] == "open"]
        self.assertEqual(len(opens), 1)
        self.assertIn("資料源用了舊資料頂替", opens[0]["body"])
        self.assertIn("核心 CVE 鏡像（Linux 核心 CNA）用了舊資料頂替", opens[0]["body"])
        self.assertIn("這段時間新增的核心 CVE 不在清單裡", opens[0]["body"])
        self.assertEqual(opens[0]["body"].count("這段時間新增的核心 CVE 不在清單裡"), 1)
        for x in plan["actions"]:
            self.assertNotIn("/home/runner", x["body"])
            self.assertNotIn(self.feeds, x["body"])
        out = os.path.join(self.w, "out-" + NOW2[:10])
        res = json.load(open(os.path.join(out, "result.json")))
        self.assertTrue(any("核心 CVE 鏡像" in x and "不在清單裡" in x for x in res["attention"]))
        self.assertIn("這段時間新增的核心 CVE 不在清單裡", open(os.path.join(out, "report.md"), encoding="utf-8").read())

    def test_fallback_does_not_block_baseline(self):
        self.write_kcve_fallback()
        st, detail, plan = self.run_once(NOW1)
        self.assertIn("建立基準", detail)
        self.assertEqual(plan["actions"], [])
        self.assertEqual(st, "ATTENTION")

    def test_euvd_attention_line(self):
        self.run_once(NOW1)
        open(os.path.join(self.feeds, "euvd.result"), "w").write("ATTENTION mirror=/tmp/x/euvd 用了上一份\n")
        self.kev.append("CVE-2018-18074")
        _, _, plan = self.run_once(NOW2)
        body = [x for x in nohealth(plan) if x["op"] == "open"][0]["body"]
        self.assertIn(match.md_text("EUVD 鏡像用了舊資料頂替：mirror=<路徑> 用了上一份：這段時間新增的 EUVD 紀錄不在清單裡"), body)

    def test_ok_result_adds_nothing(self):
        self.run_once(NOW1)
        open(os.path.join(self.feeds, "kernel-cve.result"), "w").write("OK commit=abc fetched_utc=2026-11-11T00:00:00Z\n")
        self.kev.append("CVE-2018-18074")
        _, _, plan = self.run_once(NOW2)
        self.assertFalse(any("舊資料頂替" in x["body"] for x in plan["actions"]))
        res = json.load(open(os.path.join(self.w, "out-" + NOW2[:10], "result.json")))
        self.assertFalse(any("舊資料頂替" in x for x in res["attention"]))


ENTITIES = ["&commat;everyone", "&#64;everyone", "&#x40;everyone", "&lbrack;x&rbrack;(https://evil.example)",
            "&excl;&lbrack;i&rbrack;(https://evil.example/a.png)"]
EVIL = "@everyone @someuser [x](https://evil.example) ![i](https://evil.example/a.png) #1 `tick`"


class Injection(Base):
    """公開 Issue：外部字串不能變成 @提及、連結、圖片、Issue 參照（#49 驗證應修 3）。"""

    def assert_safe(self, plan):
        for x in plan["actions"]:
            for field in ("title", "body"):
                t = match._CODE_SPAN.sub(" ", x.get(field, ""))
                self.assertNotRegex(t, r"(?<![\\\w])@(?!\u200b)[A-Za-z]", field)
                self.assertNotIn("](https://evil", t.replace("\\]\\(", ""), field)
                self.assertNotRegex(t, r"(?<!\\)!\[(?!\\)", field)
                self.assertNotRegex(t, r"#\d", field)
                self.assertNotRegex(t, r"&(?!amp;)(?:[A-Za-z][A-Za-z0-9]*;|#)", field)
            self.assertEqual(match.unsafe_markdown(x["body"]), [], x["body"])
            self.assertEqual(match.unsafe_actions([x]), [], x)

    def test_component_sources_and_meta_attention(self):
        self.inventory["releases"][0]["attention"] = ["@octocat [x](https://evil.example) ![i](https://evil.example/a.png)"]
        json.dump(self.inventory, open(os.path.join(self.inv, "inventory.json"), "w"))
        self.run_once(NOW1)
        evil_purl = "pkg:npm/%40types/node@1.0.0"
        self.grype.append({"vulnerability": {"id": "CVE-2018-18074"}, "relatedVulnerabilities": [],
                           "artifact": {"name": EVIL, "version": "1.0.0", "purl": evil_purl, "type": "npm"}})
        self.kev.append("CVE-2018-18074")
        _, _, plan = self.run_once(NOW2, demo=True)
        opens = [x for x in nohealth(plan) if x["op"] == "open"]
        self.assertEqual(len(opens), 1)
        body = opens[0]["body"]
        self.assertIn(match.md_code(EVIL + "@1.0.0"), body)    # 元件（名稱@版本）整格放進行內程式碼：原樣可複製、不解讀
        self.assertIn("`` @everyone", body)                     # 內容有反引號 → 分隔符號用兩個
        self.assertIn(match.md_text("@octocat [x](https://evil.example)"), body)
        self.assert_safe(plan)

    def test_vendor_body_and_gaps_escaped(self):
        e = {"cve": "CVE-2024-0001", "kev_vendor": "@acme [x](https://evil.example)", "kev_product": "![i](https://evil.example/a.png) #1",
             "project": "demo", "version": "v1", "vendor": "acme`x", "watch_via": ["@x"], "component_count": 1,
             "date_added": "2024-01-01", "source": "@src", "first_detected": NOW1}
        body = match.vendor_body("real", e, None, None, match.parse_now(NOW1))
        self.assertEqual(match.unsafe_markdown(body), [])
        self.assertNotIn("#1", body)
        p = {"layer": "bsp", "status": "shipped", "tag": "demo/v1", "gaps": ["upstream_note: @bob [x](https://evil.example)"]}
        body = match.kev_body("real", [{"cve": "CVE-2024-0001", "project": "demo", "version": "v1", "first_detected": NOW1,
                                         "component": "c", "purl": "p", "basis": "b", "sources": []}], p, [], None, match.parse_now(NOW1))
        self.assertEqual(match.unsafe_markdown(body), [])

    def test_unsafe_markdown_catches_unescaped(self):
        for raw in ("@everyone", "[x](https://evil.example)", "![i](https://evil.example/a.png)"):
            self.assertTrue(match.unsafe_markdown("前文 " + raw), raw)
            self.assertEqual(match.unsafe_markdown("前文 " + match.md_text(raw)), [], raw)
            self.assertEqual(match.unsafe_markdown("前文 " + match.md_code(raw)), [], raw)
        self.assertEqual(match.unsafe_markdown("purl ` pkg:maven/a/b@1.0 `"), [])   # 行內程式碼裡的 @ 不算

    def test_html_entities_not_decoded(self):
        # 具名實體與數字實體：GitHub 渲染時會解碼（&commat; → @、&lbrack; → [），所以 & 要先變成 &amp;（#49 複驗應修）
        for raw in ENTITIES:
            self.assertTrue(match.unsafe_markdown("前文 " + raw), raw)                 # 沒淨化的抓得到
            self.assertTrue(match.unsafe_actions([{"title": "x " + raw, "body": ""}]), raw)
            for fn in (match.md_text, match.md_code):
                out = fn(raw)
                self.assertEqual(match.unsafe_markdown("前文 " + out), [], (fn.__name__, out))
            out = match.md_text(raw)
            self.assertTrue(out.startswith("&amp;"), out)
            dec = html.unescape(out)                                                  # 渲染時解碼一層之後：還是原本的字面，不會變成 @ 或連結
            self.assertNotIn("@everyone", dec)
            self.assertNotRegex(dec, r"(?<!\\)\]\(")
            t = match.md_title(raw)
            self.assertEqual(match.unsafe_actions([{"title": t, "body": ""}]), [], t)
            self.assertEqual(html.unescape(t), t, t)                                  # 標題：& 後面插零寬空白，不是實體
        self.assertEqual(match.md_text("a & b"), "a &amp; b")
        self.assertEqual(match.unsafe_markdown("R&D、a & b、&amp;commat;"), [])       # 單獨的 & 與 &amp; 不算

    def test_entities_from_external_fields(self):
        # 外部資料進得來的欄位：KEV 的廠商／產品／來源、release-meta 的 attention、tag、html_url
        e = {"cve": "CVE-2024-0001", "kev_vendor": "&commat;everyone", "kev_product": "&lbrack;x&rbrack;(https://evil.example)",
             "project": "demo", "version": "v1", "vendor": "acme", "watch_via": ["&#64;x"], "component_count": 1,
             "date_added": "2024-01-01", "source": "&excl;&lbrack;i&rbrack;(https://evil.example/a.png)", "first_detected": NOW1}
        p = {"layer": "bsp", "status": "shipped", "tag": "&commat;everyone/v1", "html_url": "&lbrack;x&rbrack;(https://evil.example)",
             "release_version": "&commat;x", "gaps": ["&commat;bob &lbrack;x&rbrack;(https://evil.example)"]}
        for body in (match.vendor_body("real", e, p, None, match.parse_now(NOW1)),
                     match.kev_body("real", [{"cve": "CVE-2024-0001", "project": "demo", "version": "v1", "first_detected": NOW1,
                                              "component": "&commat;c", "purl": "p", "basis": "b", "sources": ["&#64;s"]}], p, [], None,
                                    match.parse_now(NOW1))):
            self.assertEqual(match.unsafe_markdown(body), [], body)
            self.assertIn(match.md_code("&commat;everyone/v1"), body)                 # tag 放進行內程式碼
        self.assertIn(match.md_code("&lbrack;x&rbrack;(https://evil.example)"), body)  # html_url 也是

    def test_meta_attention_entities_end_to_end(self):
        self.inventory["releases"][0]["attention"] = ENTITIES
        json.dump(self.inventory, open(os.path.join(self.inv, "inventory.json"), "w"))
        self.run_once(NOW1)
        self.grype.append({"vulnerability": {"id": "CVE-2018-18074"}, "relatedVulnerabilities": [],
                           "artifact": {"name": "&commat;everyone", "version": "1.0.0", "purl": "pkg:npm/x@1.0.0", "type": "npm"}})
        self.kev.append("CVE-2018-18074")
        _, _, plan = self.run_once(NOW2, demo=True)
        self.assertTrue([x for x in nohealth(plan) if x["op"] == "open"])
        self.assertTrue(any("&amp;commat;" in x["body"] for x in plan["actions"]))   # attention 有寫進 Issue，而且是跳脫過的
        self.assert_safe(plan)

    def test_md_code_keeps_text_copyable(self):
        self.assertEqual(match.md_code("pkg:npm/%40types/node@1.0.0"), "` pkg:npm/%40types/node@1.0.0 `")
        self.assertEqual(match.md_code("a|b"), "` a\\|b `")
        self.assertEqual(match.md_code(""), "—")
        self.assertEqual(match.md_code("x\ny\u202ez"), "` x y z `")


class SkippedReleases(Base):
    """被略過的 Release：格式壞掉、tag 不合、tag 重複 → 降級（ATTENTION）並列出；draft 只列出、不降級（#49 驗證應修 2）。"""

    def test_skipped_release_makes_attention(self):
        self.run_once(NOW1)
        self.inventory["skipped"] = [{"tag": "weird-tag", "why": "tag 格式不是 <專案>/<版本> 或 dev/<專案>"},
                                     {"tag": "p/v9", "why": "draft／prerelease 欄位不是布林"}]
        json.dump(self.inventory, open(os.path.join(self.inv, "inventory.json"), "w"))
        st, _, plan = self.run_once(NOW2)
        self.assertEqual(st, "ATTENTION")
        res = json.load(open(os.path.join(self.w, "out-" + NOW2[:10], "result.json")))
        self.assertTrue(any("weird-tag" in g and "tag 格式" in g for g in res["gaps"]), res["gaps"])
        self.assertTrue(any("p/v9" in g for g in res["serious"]), res["serious"])
        report = open(os.path.join(self.w, "out-" + NOW2[:10], "report.md"), encoding="utf-8").read()
        self.assertIn("weird-tag", report)

    def test_skipped_release_blocks_first_baseline(self):
        self.inventory["skipped"] = [{"tag": "weird-tag", "why": "tag 格式不是 <專案>/<版本> 或 dev/<專案>"}]
        json.dump(self.inventory, open(os.path.join(self.inv, "inventory.json"), "w"))
        with self.assertRaises(match.Fail):
            self.run_once(NOW1)

    def test_draft_is_listed_not_degraded(self):
        self.run_once(NOW1)
        self.inventory["drafts"] = ["demo/v2"]
        json.dump(self.inventory, open(os.path.join(self.inv, "inventory.json"), "w"))
        st, _, _ = self.run_once(NOW2)
        res = json.load(open(os.path.join(self.w, "out-" + NOW2[:10], "result.json")))
        self.assertFalse(any("demo/v2" in g for g in res["gaps"] + res["serious"]))
        self.assertTrue(any("draft" in n and "demo/v2" in n for n in res["notes"]), res["notes"])
        self.assertFalse(any("demo/v2" in a for a in res["attention"]))


if __name__ == "__main__":
    unittest.main()
