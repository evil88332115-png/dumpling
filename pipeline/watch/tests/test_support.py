"""support.py（M8 B2：支援期限與 EOL 的每日檢查）的測試。固定 --today；資料表用測試自己的（含 Debian 12，跟 C4 之後加進正式資料表的無關）。"""
import contextlib
import datetime as dt
import io
import json
import os
import re
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, HERE)
import issues  # noqa: E402
import match  # noqa: E402
import support  # noqa: E402
from test_issues import FakeGitHub, REPO  # noqa: E402

ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
DEMO_YML = os.path.join(ROOT, "projects", "orin-nano-demo", "project.yml")
D = dt.date.fromisoformat


def table(checked="2026-11-01"):
    return {"schema": "sca-center-support-lifecycle/1", "max_age_days": 180,
            "families": [{"name": "operating system", "match": {"type": "operating-system"}}],
            "entries": [
                {"id": "debian-12", "name": "Debian 12", "match": [{"type": "operating-system", "name": "debian", "version_prefix": "12"}],
                 "phases": [{"name": "Debian security", "end": "2026-06"}, {"name": "Debian LTS", "end": "2028-06", "requires": "Debian LTS"}],
                 "sources": ["https://www.debian.org/releases/bookworm/"], "checked": checked},
                {"id": "debian-13", "name": "Debian 13", "match": [{"type": "operating-system", "name": "debian", "version_prefix": "13"}],
                 "phases": [{"name": "Debian security", "end": "2035-06"}], "sources": ["https://www.debian.org/releases/trixie/"], "checked": checked}]}


class Base(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.dir = self._td.name
        self.addCleanup(self._td.cleanup)
        self.projects = os.path.join(self.dir, "projects")
        self.table = os.path.join(self.dir, "table.json")
        self.write_table(table())
        self.inv = None

    def write_table(self, t):
        with open(self.table, "w", encoding="utf-8") as f:
            json.dump(t, f)

    def project(self, name="p1", until="2031-12-31", status="development", name_text="Demo One", os_resp="customer", os_block=None,
                end_date=None):
        d = os.path.join(self.projects, name)
        os.makedirs(os.path.join(d, "CRA", "Config"), exist_ok=True)
        y = open(DEMO_YML, encoding="utf-8").read()
        y = re.sub(r"(?m)^support_until:.*$", 'support_until: "%s"' % until, y)
        y = re.sub(r"(?m)^status:.*$", 'status: "%s"' % status, y)
        y = re.sub(r"(?m)^product_name:.*$", 'product_name: "%s"' % name_text.replace('"', '\\"'), y)
        y = re.sub(r"(?m)^os_responsibility:.*$", 'os_responsibility: "%s"' % os_resp, y)
        if os_block:
            y += "\n" + os_block + "\n"
        open(os.path.join(d, "project.yml"), "w", encoding="utf-8").write(y)
        cfg = {"schema_version": 1, "manufacturer": {"name": "x"}, "product": {"name": name_text}}
        if until != "TO BE COMPLETED":
            cfg["support"] = {"end_date": end_date or until[:7]}
        json.dump(cfg, open(os.path.join(d, "CRA", "Config", "config.json"), "w"))
        return d

    def release(self, project="p1", version="v1.0.0", comps=(("debian", "12.5"),)):
        inv_dir = os.path.join(self.dir, "inv")
        os.makedirs(inv_dir, exist_ok=True)
        f = f"sbom-{project}-{version}-os.cdx.json"
        json.dump({"bomFormat": "CycloneDX", "components": [{"type": "operating-system", "name": n, "version": v} for n, v in comps]},
                  open(os.path.join(inv_dir, f), "w"))
        self.inv = os.path.join(inv_dir, "inventory.json")
        inv = json.load(open(self.inv)) if os.path.exists(self.inv) else {"schema": "dumpling-watch-inventory/1", "status": "OK", "releases": []}
        inv["releases"].append({"project": project, "watch_version": version, "version": version, "tag": f"{project}/{version}", "kind": "release",
                                "status": "shipped", "sboms": {"os": {"file": f}}})
        json.dump(inv, open(self.inv, "w"))

    def run_support(self, today="2026-11-14", demo=False):
        out = os.path.join(self.dir, "out")
        argv = ["--projects-dir", self.projects, "--table", self.table, "--today", today, "--out", out]
        if self.inv:
            argv += ["--inventory", self.inv]
        if demo:
            argv.append("--demo")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = support.main(argv)
        res = json.load(open(os.path.join(out, "result.json")))
        plan_p = os.path.join(out, "plan.json")
        plan = json.load(open(plan_p)) if os.path.exists(plan_p) else None
        return rc, res, plan, buf.getvalue()

    def titles(self, plan):
        return [a["title"] for a in (plan or {}).get("actions", [])]


class TestDeadline(unittest.TestCase):
    def test_thresholds(self):
        su = "2027-06-30"
        cases = {181: ("OK", None), 180: ("OK", 180), 91: ("OK", 180), 90: ("OK", 90), 31: ("OK", 90), 30: ("OK", 30), 0: ("OK", 30),
                 -1: ("EOL", "eol")}
        for days, (st, thr) in cases.items():
            today = D(su) - dt.timedelta(days=days)
            got = support.product_deadline(su, today)
            self.assertEqual((got[0], got[2]), (st, thr), days)
            self.assertEqual(got[1], days)

    def test_due_month(self):
        self.assertEqual(support.product_deadline("2027-06-30", D("2027-06-05"))[2], 30)    # 到期當月：30 天提醒

    def test_not_filled(self):
        self.assertEqual(support.product_deadline(None, D("2027-01-01")), ("NOT_ASSESSED", None, None))


class TestRun(Base):
    def test_far_future_ok_no_issue(self):
        self.project(until="2035-01-31")
        rc, res, plan, out = self.run_support()
        self.assertEqual(res["status"], "OK", res)
        self.assertIsNone(plan)
        self.assertIn("SUPPORT\tOK", out)

    def test_180_90_30_each_once_and_eol(self):
        self.project(until="2027-06-30")
        keys = set()
        for today, want in (("2026-12-31", None), ("2027-01-01", "180 天提醒"), ("2027-04-01", "90 天提醒"), ("2027-05-31", "30 天提醒"),
                            ("2027-06-30", "30 天提醒"), ("2027-07-01", "支援期已結束")):
            rc, res, plan, _ = self.run_support(today)
            t = [x for x in self.titles(plan) if "資料表" not in x]      # 2027 年時測試資料表也過期了，另外算
            if want is None:
                self.assertEqual(t, [], today)
            else:
                self.assertEqual(len(t), 1, (today, t))
                self.assertIn(want, t[0])
                keys.add(plan["actions"][0]["key"])
        self.assertEqual(len(keys), 4)                   # 180、90、30（到期當天同一個 key）、EOL
        self.assertEqual(res["status"], "ATTENTION")
        self.assertTrue(any(r[1] == "EOL" and "GAP" in r[2] for r in res["rows"]))

    def test_component_ends_before_product(self):
        # 合成專案的支援期限比 Debian 12 的維護期晚 → ATTENTION，列出 Debian 12
        self.project(until="2031-12-31")
        self.release()
        rc, res, plan, _ = self.run_support()
        self.assertEqual(rc, 2)
        self.assertEqual(res["status"], "ATTENTION")
        t = self.titles(plan)
        self.assertEqual(len(t), 1, t)
        self.assertIn("Debian 12", t[0])
        self.assertIn("比產品先停止維護", t[0])
        body = plan["actions"][0]["body"]
        self.assertIn("2026-06", body)
        self.assertIn("2031-12", body)

    def test_subscription_counts(self):
        self.project(until="2027-12-31")
        cfg_p = os.path.join(self.projects, "p1", "CRA", "Config", "config.json")
        cfg = json.load(open(cfg_p))
        cfg["support"]["subscriptions"] = ["Debian LTS"]
        json.dump(cfg, open(cfg_p, "w"))
        self.release()
        rc, res, plan, _ = self.run_support()
        self.assertEqual(res["status"], "OK", res)      # LTS 到 2028-06，涵蓋 2027-12

    def test_no_support_until_is_not_assessed(self):
        self.project(until="TO BE COMPLETED")
        self.release()
        rc, res, plan, _ = self.run_support()
        self.assertEqual(res["status"], "NOT_ASSESSED")
        self.assertNotEqual(rc, 0)

    def test_not_in_table_is_not_assessed_without_issue(self):
        self.project(until="2031-12-31")
        self.release(comps=(("alpine", "3.20"),))
        rc, res, plan, _ = self.run_support()
        self.assertEqual(res["status"], "NOT_ASSESSED")
        self.assertIsNone(plan)

    def test_our_os(self):
        self.project(until="2031-12-31", os_resp="ours", status="shipped", os_block='os:\n  distro: debian\n  release: "13"')
        rc, res, plan, _ = self.run_support()
        self.assertEqual(res["status"], "OK", res)
        self.project(until="2031-12-31", os_resp="ours", status="shipped", os_block='os:\n  distro: debian\n  release: "12"')
        rc, res, plan, _ = self.run_support()
        self.assertTrue(any("OS Debian 12" in t and "比產品先停止維護" in t for t in self.titles(plan)), self.titles(plan))
        self.project(until="2031-12-31", os_resp="ours", status="shipped", os_block='os:\n  distro: openmediavault\n  release: "8"')
        rc, res, plan, _ = self.run_support()
        self.assertEqual(res["status"], "ATTENTION")
        self.assertTrue(any("不在資料表" in t for t in self.titles(plan)), self.titles(plan))

    def test_stale_table_one_issue(self):
        self.write_table(table(checked="2026-01-01"))
        self.project(until="2035-01-31")
        rc, res, plan, _ = self.run_support()
        t = self.titles(plan)
        self.assertEqual(t, ["[支援期限] 資料表有 2 筆要重新查核"])
        self.assertEqual(res["status"], "ATTENTION")

    def test_bad_project_fails_but_others_still_checked(self):
        self.project(name="p1", until="2027-01-01")
        self.project(name="p2", until="2031-12-31", end_date="2030-01")     # support.end_date 和 support_until 月份不同 → load_project FAIL
        rc, res, plan, out = self.run_support()
        self.assertEqual(rc, 1)
        self.assertEqual(res["status"], "FAIL")
        self.assertTrue(any(r[0] == "p2" and r[1] == "FAIL" for r in res["rows"]))
        self.assertTrue(any("90 天提醒" in t for t in self.titles(plan)), self.titles(plan))      # p1（剩 48 天）照樣開提醒

    def test_unquoted_yaml_date(self):
        # support_until: 2027-01-31（沒加引號）→ YAML 讀成 date；project_config 接受，support.py 也要能用（預驗應修 2）
        d = self.project(until="2027-01-31")
        y = open(os.path.join(d, "project.yml"), encoding="utf-8").read().replace('support_until: "2027-01-31"', "support_until: 2027-01-31")
        open(os.path.join(d, "project.yml"), "w", encoding="utf-8").write(y)
        rc, res, plan, out = self.run_support()
        self.assertEqual(rc, 0, out)                       # 提醒不是 ATTENTION
        self.assertTrue(any("2027-01-31" in t and "提醒" in t for t in self.titles(plan)), self.titles(plan))

    def test_one_project_crash_does_not_stop_others(self):
        self.project(name="p1", until="2027-01-31")
        self.project(name="p2", until="2027-01-31")
        orig = support.product_deadline
        def boom(su, today):
            if boom.n == 0:
                boom.n += 1
                raise RuntimeError("x")
            return orig(su, today)
        boom.n = 0
        support.product_deadline = boom
        try:
            rc, res, plan, out = self.run_support()
        finally:
            support.product_deadline = orig
        self.assertEqual(rc, 1)
        self.assertTrue(any(r[0] == "p1" and r[1] == "FAIL" and "RuntimeError" in r[2] for r in res["rows"]), res["rows"])
        self.assertEqual(len(self.titles(plan)), 1)       # p2 照樣開

    def test_component_issue_once_per_project(self):
        # 同一個元件問題在兩個 Release：一個 Issue，列出兩個版本（舊 Release 不各開一堆，預驗建議 9）
        self.project(until="2031-12-31")
        self.release(version="v1.0.0")
        self.release(version="v1.1.0", comps=(("debian", "12.7"),))
        rc, res, plan, _ = self.run_support()
        t = self.titles(plan)
        self.assertEqual(len(t), 1, t)
        body = plan["actions"][0]["body"]
        self.assertIn("p1/v1.0.0", body)
        self.assertIn("p1/v1.1.0", body)
        self.release(version="v1.2.0", comps=(("debian", "12.8"),))
        rc, res, plan2, _ = self.run_support()
        self.assertEqual(plan2["actions"][0]["key"], plan["actions"][0]["key"])     # 新版本有同樣問題不重開

    def test_bad_table_fails(self):
        with open(self.table, "w") as f:
            f.write("{}")
        self.project()
        rc, res, plan, out = self.run_support()
        self.assertEqual(rc, 1)
        self.assertIn("SUPPORT\tFAIL", out)

    def test_table_names_sanitized_in_titles(self):
        # 元件與 OS 的 Issue 標題用 md_title（資料表的名稱也是外部字串）；少了 md_title，unsafe_actions 會擋下、整個 FAIL
        evil = "Debian 12 @everyone &commat;x"
        t = table()
        t["entries"][0]["name"] = evil
        self.write_table(t)
        self.project(name="p1", until="2031-12-31")
        self.release()
        self.project(name="p2", until="2031-12-31", os_resp="ours", status="shipped", os_block='os:\n  distro: debian\n  release: "12"')
        rc, res, plan, out = self.run_support()
        self.assertEqual(rc, 2, out)
        titles = self.titles(plan)
        self.assertTrue(any(f"：{match.md_title(evil)} 比產品先停止維護" in x for x in titles), titles)       # 元件（support.py 的元件標題）
        self.assertTrue(any(f"：OS {match.md_title(evil)} 比產品先停止維護" in x for x in titles), titles)    # ours 的 OS
        self.assertEqual(match.unsafe_actions(plan["actions"]), [])

    def test_injection_and_demo(self):
        self.project(until="2027-01-31", name_text="@everyone &commat;x [a](https://evil.example) #1")
        rc, res, plan, _ = self.run_support(demo=True)
        a = plan["actions"][0]
        self.assertEqual(match.unsafe_actions(plan["actions"]), [])
        self.assertIn("demo", a["labels"])
        self.assertTrue(a["title"].startswith(match.DEMO_TITLE))
        self.assertNotRegex(a["title"], r"@(?!​)e")
        self.assertNotIn("&commat;", a["body"].replace("&amp;commat;", ""))


class TestApplyStateless(Base):
    """stateless plan：已經有監控的狀態 Issue 也照樣套用（不做樂觀鎖、不寫狀態）；同一個 key 不重複開（含已關閉）。"""

    def test_apply_dedup_and_ignores_state_issue(self):
        self.project(until="2027-01-31")
        rc, res, plan, _ = self.run_support()
        plan_p = os.path.join(self.dir, "out", "plan.json")
        gh = FakeGitHub()
        gh.add_issue("<!-- dumpling-watch-state mode=real schema=1 -->\n{}", ["watch-state"])
        run = lambda: issues.main(["apply", "--repo", REPO, "--plan", plan_p, "--mode", "real"], api=gh)  # noqa: E731
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(run(), 0)
        opened = [i for i in gh.issues.values() if "support-period" in issues.label_names(i)]
        self.assertEqual(len(opened), 1)
        state = [i for i in gh.issues.values() if "watch-state" in issues.label_names(i)]
        self.assertEqual(state[0]["body"], "<!-- dumpling-watch-state mode=real schema=1 -->\n{}")     # 狀態 Issue 沒被改
        opened[0]["state"] = "closed"
        rc2, res2, plan2, _ = self.run_support()          # 第二天：同一個 key
        self.assertEqual(plan2["actions"][0]["key"], plan["actions"][0]["key"])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(run(), 0)
        self.assertEqual(len([i for i in gh.issues.values() if "support-period" in issues.label_names(i)]), 1)   # 關掉的也不重開

    def test_support_issue_not_counted_as_watch_issue(self):
        # 預驗應修 1：支援期限的 Issue 不能被 read-state 算成監控 Issue（沒有狀態 Issue 時會擋住第一次基準）
        self.project(until="2027-01-31")
        self.run_support()
        plan_p = os.path.join(self.dir, "out", "plan.json")
        gh = FakeGitHub()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(issues.main(["apply", "--repo", REPO, "--plan", plan_p, "--mode", "real"], api=gh), 0)
        iss = list(gh.issues.values())
        self.assertEqual(len(iss), 1)
        self.assertTrue(iss[0]["body"].startswith("<!-- dumpling-support key="))
        self.assertNotIn("dumpling-watch", issues.label_names(iss[0]))
        st = os.path.join(self.dir, "state")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(issues.main(["read-state", "--repo", REPO, "--mode", "real", "--out", st], api=gh), 0)
        base = json.load(open(os.path.join(st, "state-base.json")))
        self.assertEqual(base["watch_keys"], [])
        state, _, first = match.load_state(st)
        self.assertTrue(first)                            # 照樣可以建立第一次基準

    def stateless_plan(self, actions):
        p = {"schema": issues.PLAN_SCHEMA, "mode": "real", "stateless": True, "state_base": None, "state": None,
             "actions": actions, "status": "OK", "detail": ""}
        path = os.path.join(self.dir, "plan.json")
        json.dump(p, open(path, "w"))
        return path

    def test_stateless_only_open(self):
        # comment 與 open_if_closed（開過又關掉的會重新打開）都不行：支援期限的 Issue 關掉就是處理完了
        ok = {"op": "open", "key": "a" * 64, "title": "t", "body": "x", "labels": ["support-period"]}
        issues.load_plan(self.stateless_plan([ok]))
        for bad in ({"op": "comment", "key": "a" * 64, "body": "x"},
                    {"op": "open_if_closed", "key": "a" * 64, "title": "t", "body": "x", "labels": ["support-period"]}):
            with self.assertRaises(issues.Fail, msg=bad["op"]):
                issues.load_plan(self.stateless_plan([ok, bad]))

    def test_stateless_rejects_watch_label(self):
        act = {"op": "open", "key": "a" * 64, "title": "t", "body": "x", "labels": ["support-period", "dumpling-watch"]}
        with self.assertRaises(issues.Fail):
            issues.load_plan(self.stateless_plan([act]))

    def test_stateless_with_state_rejected(self):
        p = {"schema": issues.PLAN_SCHEMA, "mode": "real", "stateless": True, "state_base": None, "state": {"schema": 1},
             "actions": [], "status": "OK", "detail": ""}
        path = os.path.join(self.dir, "plan.json")
        json.dump(p, open(path, "w"))
        with self.assertRaises(issues.Fail):
            issues.load_plan(path)


if __name__ == "__main__":
    unittest.main()
