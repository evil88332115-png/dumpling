"""deadman.py 的單元測試（GITLAB-PORT T-12）：不連網，用記憶體裡的假 GitLab（覆寫 GitLabApi._raw）與假 GitHub（覆寫 Issue 層）。
只有假 API 的測試：沒有對真實 GitLab 驗證過；排程 API 的欄位依據官方文件 docs.gitlab.com/api/pipeline_schedules/。測資全部合成。"""
import contextlib
import datetime as dt
import importlib.util
import io
import json
import os
import re
import sys
import tempfile
import unittest
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
import deadman  # noqa: E402
import issues  # noqa: E402
import match  # noqa: E402

ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
PROJ = "7"
BASE = "https://gitlab.example.com/api/v4"
TOKEN = "glpat-SECRETTOKEN0123456789"
NOW = dt.datetime(2026, 11, 15, 12, 0, 0, tzinfo=dt.timezone.utc)
NOW_S = "2026-11-15T12:00:00Z"
BOT, DEV, REPORTER, GUEST, BLOCKED = 99, 10, 11, 12, 14
SECRET_VAR = "VARIABLE-VALUE-MUST-NOT-LEAK"
PRIVATE_IP = "10.20." + "30.40"                  # 公開檢查會擋的字串：測試裡拆開寫，原始碼才過 public-check
HOME_PATH = "/" + "home/alice/job.sh"
GL = ["--backend", "gitlab", "--gitlab-url", BASE, "--project", PROJ]


def ago(hours, now=NOW):
    return (now - dt.timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")


def state_body(last_at, mode="real", runs=True):
    st = {"schema": 1, "matches": {}, "runs": [{"at": last_at, "status": "OK", "mode": mode}] if runs else []}
    return issues.encode_state(st, mode, "s", urlsafe=True)


class FakeGitLab(issues.GitLabApi):
    def __init__(self):
        super().__init__(base=BASE, token=TOKEN, sleep=lambda d: None, clock=lambda: 0.0, wall=lambda: 1000)
        self.issues, self.notes, self.labels = {}, {}, {}
        self.n, self.nid, self.tick = 0, 0, 0
        self.me = BOT
        self.members = {BOT: (40, "active"), DEV: (30, "active"), REPORTER: (20, "active"), GUEST: (10, "active"), BLOCKED: (30, "blocked")}
        self.schedules = {}          # id -> {"row": 列表的欄位, "vars": [...]|None, "single": "ok"|"403"|"omit"}
        self.requests, self.creates, self.script = [], [], []
        self.now_s = NOW_S              # 新建 Issue 的 created_at（測試要讓時間往前走時改這個）

    def _ts(self):
        self.tick += 1
        return "2026-11-15T11:00:%02d.000Z" % (self.tick % 60)

    def add_issue(self, description, labels, state="opened", title="t", author=BOT, updated_at=None, created_at=None):
        self.n += 1
        self.issues[self.n] = {"id": 1000 + self.n, "iid": self.n, "title": title, "description": description, "state": state,
                               "labels": list(labels), "updated_at": updated_at or self._ts(), "created_at": created_at or self.now_s, "confidential": True,
                               "author": {"id": author, "username": "u%d" % author, "state": "active"}}
        return self.n

    def add_note(self, num, body, author=BOT, system=False):
        self.nid += 1
        self.notes.setdefault(num, []).append({"id": self.nid, "body": body, "system": system,
                                               "author": {"id": author, "username": "u%d" % author, "state": "active"}})

    def add_schedule(self, sid, watch=True, active=True, owner_state="active", next_run=None, single="ok", description="daily watch", extra_vars=None):
        row = {"id": sid, "description": description, "ref": "main", "cron": "0 3 * * *", "cron_timezone": "UTC",
               "next_run_at": next_run if next_run is not None else "2026-11-16T03:00:00.000Z", "active": active,
               "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z",
               "owner": {"name": "svc", "username": "svc-bot", "id": 5, "state": owner_state}}
        vs = ([{"key": "DUMPLING_JOB", "variable_type": "env_var", "value": "watch", "raw": False}] if watch
              else [{"key": "DUMPLING_JOB", "variable_type": "env_var", "value": "dev", "raw": False}]) + (extra_vars or [])
        self.schedules[sid] = {"row": row, "vars": vs, "single": single}

    def _raw(self, method, url, headers, body):
        u = urllib.parse.urlsplit(url)
        q = urllib.parse.parse_qs(u.query)
        self.requests.append((method, u.path))
        if self.script:
            return self.script.pop(0)
        data = json.loads(body) if body else None
        if u.path == "/api/v4/user" and method == "GET":         # token 自己的使用者（project access token 的 bot）
            return 200, {}, json.dumps({"id": self.me, "username": "bot", "bot": True}).encode()
        pre = "/api/v4/projects/%s/" % PROJ
        if not u.path.startswith(pre):
            return 404, {}, b'{"message":"404 Project Not Found"}'
        tail = u.path[len(pre):].split("/")
        ok = lambda rows: (200, {"x-next-page": ""}, json.dumps(rows).encode())          # noqa: E731
        if tail == ["pipeline_schedules"] and method == "GET":
            return ok([s["row"] for s in self.schedules.values()])
        if len(tail) == 2 and tail[0] == "pipeline_schedules" and method == "GET":
            s = self.schedules.get(int(tail[1]))
            if not s:
                return 404, {}, b'{"message":"404 Not found"}'
            if s["single"] == "403":
                return 403, {}, b'{"message":"403 Forbidden"}'
            d = dict(s["row"], last_pipeline={"id": 1, "sha": "abc", "ref": "main", "status": "success"})
            if s["single"] != "omit":
                d["variables"] = s["vars"]
            return 200, {}, json.dumps(d).encode()
        if tail == ["issues"] and method == "GET":
            lab, st = q["labels"][0], q.get("state", ["all"])[0]
            return ok([i for i in self.issues.values() if lab in i["labels"] and (st == "all" or i["state"] == st)])
        if tail == ["labels"] and method == "GET":
            return ok([{"name": n} for n in self.labels])
        if tail == ["labels"] and method == "POST":
            self.labels[data["name"]] = data["color"]
            return 201, {}, b"{}"
        if tail == ["issues"] and method == "POST":
            self.creates.append(data)
            names = data["labels"].split(",") if data["labels"] else []
            for l in names:
                assert l in self.labels, "標籤沒先建立"
            num = self.add_issue(data["description"], names, title=data["title"], author=self.me)
            self.issues[num]["confidential"] = data.get("confidential", False)
            return 201, {}, json.dumps(self.issues[num]).encode()
        if len(tail) == 2 and tail[0] == "issues" and method == "PUT":
            i = self.issues[int(tail[1])]
            for k, v in data.items():
                if k == "state_event":
                    i["state"] = {"close": "closed", "reopen": "opened"}[v]
                elif k == "description":
                    i["description"] = v
            return 200, {}, json.dumps(i).encode()
        if len(tail) == 3 and tail[0] == "issues" and tail[2] == "notes":
            n = int(tail[1])
            if method == "GET":
                return ok(self.notes.get(n, []))
            self.add_note(n, data["body"], author=self.me)
            return 201, {}, b"{}"
        if len(tail) == 3 and tail[:2] == ["members", "all"] and method == "GET":
            uid = int(tail[2])
            if uid not in self.members:
                return 404, {}, b'{"message":"404 Not found"}'
            lvl, st = self.members[uid]
            return 200, {}, json.dumps({"id": uid, "username": "u%d" % uid, "access_level": lvl, "state": st}).encode()
        return 404, {}, b'{"message":"404 Not Found"}'

    def deadman_issues(self):
        return {n: i for n, i in self.issues.items() if "watch-deadman" in i["labels"]}


class FakeGitHub(issues.Api):
    """記憶體裡的假 GitHub：只覆寫 Issue 層（deadman 與 apply 用到的部分）。"""

    def __init__(self):
        super().__init__(base="https://api.github.com", token=TOKEN, sleep=lambda d: None)
        self.issues, self.notes, self.labels, self.n = {}, {}, set(), 0

    def list_issues(self, repo, label, state="all"):
        return [dict(i) for i in self.issues.values() if label in i["labels"] and (state == "all" or i["state"] == state)]

    def create_issue(self, repo, title, body, labels):
        self.n += 1
        self.issues[self.n] = {"number": self.n, "title": title, "body": body, "state": "open", "labels": list(labels),
                               "updated_at": "2026-11-15T11:00:00Z", "user": {"login": "github-actions[bot]", "type": "Bot"}}
        return self.issues[self.n]

    def list_notes(self, repo, number):
        return self.notes.get(number, [])

    def create_note(self, repo, number, body):
        self.notes.setdefault(number, []).append({"id": len(self.notes.get(number, [])) + 1, "body": body,
                                                  "user": {"login": "github-actions[bot]", "type": "Bot"}, "author_association": "NONE"})

    def list_labels(self, repo):
        return list(self.labels)

    def create_label(self, repo, name, color):
        self.labels.add(name)


def run_main(mod, argv, api):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        rc = mod.main(argv, api=api)
    return rc, out.getvalue()


class Base(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.dir = self._td.name
        self.addCleanup(self._td.cleanup)
        self.gl = FakeGitLab()
        self.seq = 0

    def out(self):
        return os.path.join(self.dir, "out")

    def result(self):
        with open(os.path.join(self.out(), "result.json"), encoding="utf-8") as f:
            return json.load(f)

    def plan(self):
        with open(os.path.join(self.out(), "plan.json"), encoding="utf-8") as f:
            return json.load(f)

    def has_plan(self):
        return os.path.exists(os.path.join(self.out(), "plan.json"))

    def dm(self, *extra, now=NOW_S, api=None, base=GL):
        return run_main(deadman, list(base) + ["--out", self.out(), "--now", now, *extra], api or self.gl)

    def apply(self):
        return run_main(issues, ["apply", *GL, "--confidential", "--plan", os.path.join(self.out(), "plan.json")], self.gl)

    def set_state(self, last_at, mode="real", runs=True, **kw):
        """狀態 Issue（一個）：換內容。"""
        lab = "watch-state" if mode == "real" else "watch-state-drill"
        body = state_body(last_at, mode, runs)
        found = [n for n, i in self.gl.issues.items() if lab in i["labels"]]
        if found:
            self.gl.issues[found[0]]["description"] = body
            if "updated_at" in kw:
                self.gl.issues[found[0]]["updated_at"] = kw["updated_at"]
            return found[0]
        return self.gl.add_issue(body, [lab], **kw)

    def at(self, hours):
        return (NOW - dt.timedelta(hours=hours))


def last_line(out):
    return out.strip().splitlines()[-1].split("\t")


class TestKeyAndConstants(unittest.TestCase):
    def test_key_same_algorithm_as_match_issue_key(self):
        for mode in ("real", "drill"):
            for ident in ("state-stale:2026-11-14T00:00:00Z", "schedule:5:inactive", "schedule:none:missing"):
                for n in (1, 2, 10):
                    self.assertEqual(deadman.key_of(mode, ident, n), match.issue_key(mode, "deadman", ident, str(n)))
        self.assertNotEqual(deadman.key_of("real", "x", 1), deadman.key_of("real", "x", 2))

    def test_docs_do_not_describe_removed_behaviour(self):
        # 預驗發現文件和程式相反過：退回 updated_at、只列開著的 Issue 都不是現在的行為。文件不能再這樣寫
        for rel in ("docs/GITLAB-PORT.md", "docs/WATCH.md", "pipeline/watch/deadman.py"):
            with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
                text = f.read()
            for stale in ("沒有 runs 才用", "沒有 runs 才退回", "才退回 Issue 的 `updated_at`", "先列出開著、帶", "列出開著、帶 watch-deadman", "只對開著的 Issue 留言"):
                self.assertNotIn(stale, text, (rel, stale))

    def test_default_threshold_equals_dashboard_stale_hours(self):
        spec = importlib.util.spec_from_file_location("dashboard_build_for_test", os.path.join(ROOT, "pipeline", "dashboard", "build.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        self.assertEqual(deadman.DEFAULT_MAX_AGE_HOURS, mod.STALE_HOURS)
        self.assertEqual(deadman.DEFAULT_MAX_AGE_HOURS, 36)


class TestStateCheck(Base):
    def test_fresh_state_ok(self):
        self.set_state(ago(1))
        rc, out = self.dm()
        self.assertEqual(rc, 0, out)
        self.assertEqual(last_line(out)[:2], ["WATCH-DEADMAN", "OK"])
        r = self.result()
        self.assertEqual((r["status"], r["last_update"], r["max_age_hours"]), ("OK", ago(1), 36.0))
        self.assertAlmostEqual(r["age_hours"], 1.0)
        self.assertEqual([c["name"] for c in r["checks"]], ["state"])
        self.assertFalse(self.has_plan())

    def test_stale_alert_and_plan(self):
        last = ago(37)
        self.set_state(last)
        rc, out = self.dm()
        self.assertEqual(rc, 2, out)
        self.assertEqual(last_line(out)[1], "ALERT")
        self.assertEqual(self.result()["status"], "ALERT")
        p = self.plan()
        self.assertEqual((p["schema"], p["mode"], p["stateless"], p["stateless_kind"], p["state"], p["state_base"]),
                         (issues.PLAN_SCHEMA, "real", True, "deadman", None, None))
        self.assertEqual(len(p["actions"]), 1)
        a = p["actions"][0]
        self.assertEqual(a["op"], "open")
        self.assertEqual(a["key"], match.issue_key("real", "deadman", "state-stale:" + last, "1"))
        self.assertEqual(a["labels"], ["watch-health", "watch-deadman"])
        self.assertIn("超過 36 小時沒有結果", a["title"])
        self.assertIn(last, a["title"])
        for s in ("門檻：36 小時", "Take ownership", "watch:compute", "T-08", "Inactive", last):
            self.assertIn(s, a["body"])
        self.assertTrue(a["body"].startswith("<!-- dumpling-deadman-scope state -->"))

    def test_boundary_exactly_threshold_is_ok_one_second_over_is_alert(self):
        self.set_state(ago(36))
        rc, out = self.dm()
        self.assertEqual(rc, 0, out)
        self.set_state((NOW - dt.timedelta(hours=36, seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ"))
        rc, out = self.dm()
        self.assertEqual(rc, 2, out)

    def test_custom_max_age_hours(self):
        self.set_state(ago(13))
        self.assertEqual(self.dm("--max-age-hours", "12")[0], 2)
        self.assertEqual(self.dm("--max-age-hours", "14")[0], 0)
        rc, out = self.dm("--max-age-hours", "12")
        self.assertIn("超過 12 小時沒有結果", self.plan()["actions"][0]["title"])

    def test_last_update_comes_from_last_run_not_issue_updated_at(self):
        self.set_state(ago(50), updated_at=ago(1).replace("Z", ".000Z"))        # Issue 剛被改過，但最後一輪是 50 小時前
        self.assertEqual(self.dm()[0], 2)
        self.assertEqual(self.result()["last_update"], ago(50))

    def test_bad_runs_is_alert_and_never_falls_back_to_updated_at(self):
        # match.py 每輪都 append run：runs 不是非空 list 就是壞資料。Issue 的 updated_at 再新也不能拿來當「有在跑」
        fresh = ago(1).replace("Z", ".000Z")
        for label, st in (("garbage", {"schema": 1, "runs": "garbage"}), ("dict", {"schema": 1, "runs": {"at": ago(1)}}),
                          ("none", {"schema": 1, "runs": None}), ("missing", {"schema": 1}), ("empty", {"schema": 1, "runs": []}),
                          ("number", {"schema": 1, "runs": 5})):
            self.gl.issues.clear()
            self.gl.add_issue(issues.encode_state(st, "real", "s", urlsafe=True), ["watch-state"], updated_at=fresh)
            rc, out = self.dm()
            self.assertEqual(rc, 2, (label, out))
            self.assertEqual(self.plan()["actions"][0]["key"], deadman.key_of("real", "state:no-time", 1), label)
            self.assertIsNone(self.result()["last_update"], label)

    def test_no_state_issue_alert_with_reason(self):
        rc, out = self.dm()
        self.assertEqual(rc, 2, out)
        a = self.plan()["actions"][0]
        self.assertEqual(a["key"], deadman.key_of("real", "state:missing", 1))
        self.assertIn("找不到每日監控的狀態 Issue", a["title"])
        self.assertIn("找不到狀態 Issue", self.result()["checks"][0]["detail"])

    def test_undecodable_state_alert(self):
        self.gl.add_issue("<!-- dumpling-watch-state mode=real schema=1 -->\n```\n!!!!\n```\n", ["watch-state"])
        rc, out = self.dm()
        self.assertEqual(rc, 2, out)
        self.assertEqual(self.plan()["actions"][0]["key"], deadman.key_of("real", "state:undecodable", 1))
        self.assertIn("解不開", self.plan()["actions"][0]["title"])

    def test_unreadable_time_alerts(self):
        for runs in ([{"at": "yesterday"}], [{"status": "OK"}], ["x"], [{"at": "2026-11-14T10:00:00+00:00"}]):
            st = issues.encode_state({"schema": 1, "runs": runs}, "real", "s", urlsafe=True)
            self.gl.issues.clear()
            self.gl.add_issue(st, ["watch-state"])
            rc, out = self.dm()
            self.assertEqual(rc, 2, (runs, out))
            self.assertEqual(self.plan()["actions"][0]["key"], deadman.key_of("real", "state:no-time", 1), runs)

    def test_future_time_is_alert_not_silence(self):
        self.set_state((NOW + dt.timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ"))
        self.assertEqual(self.dm()[0], 2)
        self.assertEqual(self.plan()["actions"][0]["key"], deadman.key_of("real", "state:no-time", 1))
        self.set_state((NOW + dt.timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ"))       # 1 小時內的時鐘誤差不算
        self.assertEqual(self.dm()[0], 0)

    def test_api_failure_is_fail_and_result_written(self):
        self.gl.script = [(500, {}, b'{"message":"boom"}')]
        rc, out = self.dm()
        self.assertEqual(rc, 1, out)
        self.assertEqual(last_line(out)[1], "FAIL")
        r = self.result()
        self.assertEqual(r["status"], "FAIL")
        self.assertEqual(r["checks"][0]["name"], "state")
        self.assertEqual(r["checks"][0]["status"], "FAIL")
        self.assertFalse(self.has_plan())

    def test_two_state_issues_is_fail(self):
        self.gl.add_issue(state_body(ago(1)), ["watch-state"])
        self.gl.add_issue(state_body(ago(1)), ["watch-state"])
        rc, out = self.dm()
        self.assertEqual(rc, 1, out)
        self.assertEqual(self.result()["status"], "FAIL")

    def test_drill_mode(self):
        self.set_state(ago(40), mode="drill")
        rc, out = self.dm("--mode", "drill")
        self.assertEqual(rc, 2, out)
        a = self.plan()["actions"][0]
        self.assertEqual(self.plan()["mode"], "drill")
        self.assertEqual(a["labels"], ["watch-health", "watch-deadman", "drill"])
        self.assertEqual(a["key"], match.issue_key("drill", "deadman", "state-stale:" + ago(40), "1"))
        self.assertNotEqual(a["key"], match.issue_key("real", "deadman", "state-stale:" + ago(40), "1"))
        # real 模式看不到 drill 的狀態 Issue
        self.assertEqual(self.dm()[0], 2)
        self.assertEqual(self.plan()["actions"][0]["key"], deadman.key_of("real", "state:missing", 1))

    def test_stale_state_old_plan_removed_when_ok(self):
        self.set_state(ago(40))
        self.dm()
        self.assertTrue(self.has_plan())
        self.set_state(ago(1))
        self.dm()
        self.assertFalse(self.has_plan())          # 舊的 plan.json 不能留著被下一步誤用

    def test_github_backend_flow(self):
        gh = FakeGitHub()
        gh.create_issue("o/r", "狀態", state_body(ago(40)), ["watch-state"])
        gh.issues[1]["labels"] = ["watch-state"]
        rc, out = run_main(deadman, ["--repo", "o/r", "--out", self.out(), "--now", NOW_S], gh)
        self.assertEqual(rc, 2, out)
        rc, out = run_main(issues, ["apply", "--repo", "o/r", "--plan", os.path.join(self.out(), "plan.json")], gh)
        self.assertEqual(rc, 0, out)
        d = [i for i in gh.issues.values() if "watch-deadman" in i["labels"]]
        self.assertEqual(len(d), 1)
        self.assertTrue(d[0]["body"].startswith("<!-- dumpling-deadman key="))
        self.assertNotIn("support-period", d[0]["labels"])
        self.assertNotIn("dumpling-watch", d[0]["labels"])


class TestUsage(Base):
    def test_schedules_only_on_gitlab(self):
        gh = FakeGitHub()
        rc, out = run_main(deadman, ["--repo", "o/r", "--out", self.out(), "--schedules"], gh)
        self.assertEqual(rc, 64, out)
        self.assertIn("WATCH-DEADMAN\tFAIL", out)

    def test_usage_errors(self):
        for argv in ([], ["--out", "x"], ["--repo", "bad", "--out", "x"], ["--backend", "gitlab", "--out", "x"],
                     ["--backend", "gitlab", "--gitlab-url", "http://evil.example.com/api/v4", "--project", "7", "--out", "x"],
                     ["--backend", "gitlab", "--gitlab-url", BASE, "--project", "abc", "--out", "x"],
                     ["--backend", "gitlab", "--gitlab-url", BASE, "--project", "7", "--repo", "o/r", "--out", "x"],
                     ["--repo", "o/r", "--project", "7", "--out", "x"], ["--repo", "o/r", "--out", "x", "--max-age-hours", "0"],
                     ["--repo", "o/r", "--out", "x", "--max-age-hours", "abc"], ["--repo", "o/r", "--out", "x", "--mode", "x"],
                     ["--repo", "o/r", "--out", "x", "--now", "2026-11-15"], ["--repo", "o/r", "--out", "x", "--token", "t"]):
            rc, out = run_main(deadman, argv, FakeGitHub())
            self.assertEqual(rc, 64, argv)

    def test_gitlab_without_token_is_fail_not_traceback(self):
        old = os.environ.pop("GITLAB_TOKEN", None)
        try:
            rc, out = run_main(deadman, [*GL, "--out", self.out(), "--now", NOW_S], None)
        finally:
            if old is not None:
                os.environ["GITLAB_TOKEN"] = old
        self.assertEqual(rc, 1, out)
        self.assertIn("沒有 GITLAB_TOKEN", out)
        self.assertEqual(self.result()["status"], "FAIL")

    def test_schedule_endpoints_not_called_without_flag(self):
        self.set_state(ago(1))
        self.dm()
        self.assertFalse([p for m, p in self.gl.requests if "pipeline_schedules" in p])


class TestSchedules(Base):
    def setUp(self):
        super().setUp()
        self.set_state(ago(1))

    def sd(self, *extra, **kw):
        return self.dm("--schedules", *extra, **kw)

    def idents(self):
        return {a["ident"] for a in self.result()["alerts"]}

    def test_healthy_schedule_ok_summary_without_variable_values(self):
        self.gl.add_schedule(3, extra_vars=[{"key": "SOME_SECRET", "variable_type": "env_var", "value": SECRET_VAR, "raw": False}])
        self.gl.add_schedule(4, watch=False)
        rc, out = self.sd()
        self.assertEqual(rc, 0, out)
        r = self.result()
        self.assertEqual([c["name"] for c in r["checks"]], ["state", "schedules"])
        self.assertEqual(r["checks"][1]["status"], "OK")
        self.assertEqual({s["id"]: s["watch"] for s in r["schedules"]}, {3: True, 4: False})
        raw = open(os.path.join(self.out(), "result.json"), encoding="utf-8").read()
        self.assertNotIn(SECRET_VAR, raw)
        self.assertNotIn("SOME_SECRET", raw)
        self.assertFalse(self.has_plan())
        # 列表一次、單筆每個排程一次
        self.assertEqual([p.rsplit("/", 1)[-1] for m, p in self.gl.requests if "pipeline_schedules" in p], ["pipeline_schedules", "3", "4"])

    def test_no_schedules_at_all(self):
        rc, out = self.sd()
        self.assertEqual(rc, 2, out)
        self.assertEqual(self.idents(), {"schedule:none:missing"})
        self.assertEqual(self.plan()["actions"][0]["key"], match.issue_key("real", "deadman", "schedule:none:missing", "1"))

    def test_no_watch_schedule_among_others(self):
        self.gl.add_schedule(4, watch=False)
        self.assertEqual(self.sd()[0], 2)
        self.assertEqual(self.idents(), {"schedule:none:missing"})

    def test_inactive_schedule(self):
        self.gl.add_schedule(3, active=False, next_run="")           # 停用的排程 next_run_at 可能是空的：只報 inactive
        self.assertEqual(self.sd()[0], 2)
        self.assertEqual(self.idents(), {"schedule:3:inactive"})
        self.assertIn("Inactive", self.plan()["actions"][0]["title"])

    def test_inactive_non_watch_schedule_ignored(self):
        self.gl.add_schedule(3)
        self.gl.add_schedule(4, watch=False, active=False, owner_state="blocked")
        self.assertEqual(self.sd()[0], 0)

    def test_owner_not_active(self):
        for st in ("blocked", "deactivated", "banned"):
            self.gl.schedules.clear()
            self.gl.add_schedule(3, owner_state=st)
            self.assertEqual(self.sd()[0], 2, st)
            self.assertEqual(self.idents(), {"schedule:3:owner-not-active"}, st)
        self.gl.schedules[3]["row"]["owner"] = None
        self.assertEqual(self.sd()[0], 2)
        self.assertEqual(self.idents(), {"schedule:3:owner-not-active"})

    def test_next_run_stale_and_boundary(self):
        # 排程的容忍值是獨立的 2 小時（NEXT_RUN_SLACK_HOURS），不跟狀態的 36 小時走
        self.assertEqual(deadman.NEXT_RUN_SLACK_HOURS, 2)
        self.gl.add_schedule(3, next_run=ago(3).replace("Z", ".000Z"))
        self.assertEqual(self.sd()[0], 2)
        self.assertEqual(self.idents(), {"schedule:3:next-run-stale"})
        self.assertIn("2 小時", self.plan()["actions"][0]["title"] + self.plan()["actions"][0]["body"])
        self.gl.schedules[3]["row"]["next_run_at"] = ago(2).replace("Z", ".000Z")        # 剛好 2 小時：不算
        self.assertEqual(self.sd()[0], 0)
        self.gl.schedules[3]["row"]["next_run_at"] = (NOW - dt.timedelta(hours=2, seconds=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        self.assertEqual(self.sd()[0], 2)
        self.gl.schedules[3]["row"]["next_run_at"] = ago(1).replace("Z", ".000Z")
        self.assertEqual(self.sd()[0], 0)
        self.gl.schedules[3]["row"]["next_run_at"] = (NOW + dt.timedelta(hours=20)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        self.assertEqual(self.sd()[0], 0)
        # --max-age-hours 只管狀態，不影響排程的 2 小時
        self.gl.schedules[3]["row"]["next_run_at"] = ago(3).replace("Z", ".000Z")
        self.assertEqual(self.sd("--max-age-hours", "100")[0], 2)

    def test_next_run_unreadable_for_active_schedule(self):
        self.gl.add_schedule(3)
        self.gl.schedules[3]["row"]["next_run_at"] = None
        self.assertEqual(self.sd()[0], 2)
        self.assertEqual(self.idents(), {"schedule:3:next-run-unreadable"})

    def test_multiple_problems_one_issue_each_stable_keys(self):
        self.gl.add_schedule(3, active=False, owner_state="blocked")
        self.assertEqual(self.sd()[0], 2)
        self.assertEqual(self.idents(), {"schedule:3:inactive", "schedule:3:owner-not-active"})
        self.assertEqual(len(self.plan()["actions"]), 2)
        self.assertEqual(len({a["key"] for a in self.plan()["actions"]}), 2)

    def test_gap_when_variables_not_visible_403(self):
        self.gl.add_schedule(3, single="403")
        rc, out = self.sd()
        self.assertEqual(rc, 2, out)
        self.assertEqual(self.idents(), {"schedule:all:gap"})            # 不能當成「沒有排程」
        c = self.result()["checks"][1]
        self.assertEqual(c["status"], "ALERT")
        self.assertIn("GAP", c["detail"])
        self.assertIn("token 角色不夠，看不到排程的 variables", c["detail"])
        self.assertIn("token 角色不夠，看不到排程的 variables", self.plan()["actions"][0]["body"])
        self.assertNotIn("schedule:none:missing", self.idents())

    def test_gap_when_variables_field_missing(self):
        self.gl.add_schedule(3, single="omit")
        self.assertEqual(self.sd()[0], 2)
        self.assertEqual(self.idents(), {"schedule:all:gap"})

    def test_gap_plus_visible_watch_schedule_problem(self):
        self.gl.add_schedule(3, active=False)
        self.gl.add_schedule(4, single="403")
        self.assertEqual(self.sd()[0], 2)
        self.assertEqual(self.idents(), {"schedule:3:inactive", "schedule:all:gap"})

    def test_schedule_api_failure_is_fail(self):
        self.gl.add_schedule(3)
        self.gl.script = [(200, {"x-next-page": ""}, b'{"id":1,"state":"opened"}'), ]    # 列表回物件
        rc, out = self.sd()
        self.assertEqual(rc, 1, out)
        r = self.result()
        self.assertEqual(r["status"], "FAIL")
        self.assertIn("FAIL", [c["status"] for c in r["checks"]])
        # 單筆 500（不是權限）→ FAIL，不是 GAP
        self.gl.script = []
        self.gl.requests.clear()
        orig = self.gl._raw

        def boom(method, url, headers, body):
            if re.search(r"pipeline_schedules/3$", url):
                return 500, {}, b'{"message":"x"}'
            return orig(method, url, headers, body)
        self.gl._raw = boom
        rc, out = self.sd()
        self.assertEqual(rc, 1, out)
        self.assertEqual(self.result()["checks"][-1]["status"], "FAIL")

    def test_pagination_uses_get_all(self):
        for i in range(1, 4):
            self.gl.add_schedule(i)
        orig = self.gl._raw

        def paged(method, url, headers, body):
            u = urllib.parse.urlsplit(url)
            if u.path.endswith("/pipeline_schedules"):
                q = urllib.parse.parse_qs(u.query)
                p = int(q.get("page", ["1"])[0])
                rows = [s["row"] for s in self.gl.schedules.values()]
                return 200, {"x-next-page": str(p + 1) if p < 3 else ""}, json.dumps([rows[p - 1]]).encode()
            return orig(method, url, headers, body)
        self.gl._raw = paged
        self.assertEqual(self.sd()[0], 0)
        self.assertEqual({s["id"] for s in self.result()["schedules"]}, {1, 2, 3})


class TestSanitize(Base):
    def setUp(self):
        super().setUp()
        self.set_state(ago(1))

    def test_foreign_strings_are_sanitized_and_apply_succeeds(self):
        desc = "/close\n/assign @everyone [click](http://evil.example.com/x) ![i](http://e/x.png) <b>x</b> www.evil.example.com #123 GH-5 &amp;"
        self.gl.add_schedule(3, active=False, description=desc)
        self.gl.schedules[3]["row"]["owner"]["username"] = "/close @admin"
        self.gl.schedules[3]["row"]["ref"] = "@team/[x](http://e)"
        rc, out = self.dm("--schedules")
        self.assertEqual(rc, 2, out)
        a = self.plan()["actions"][0]
        self.assertEqual(match.unsafe_markdown(a["body"]), [])
        self.assertNotRegex(a["body"], r"(?m)^\s*/")
        self.assertNotIn("](http", a["body"])
        self.assertNotIn("@everyone", a["body"])
        self.assertNotIn("@admin", a["body"])
        self.assertNotRegex(a["body"], r"(?<![\\\w])@(?!​)[A-Za-z]")
        self.assertNotIn("<b>", a["body"])
        self.assertNotIn("#123", a["body"])
        self.assertIn("close", a["body"])               # 內容還在，只是被淨化
        rc, out = self.apply()                            # issues.py apply 的 quick action／公開檢查不報
        self.assertEqual(rc, 0, out)
        self.assertEqual(len(self.gl.deadman_issues()), 1)
        for line in self.gl.creates[0]["description"].splitlines():
            self.assertFalse(line.lstrip().startswith("/"), line)

    def test_public_check_hit_in_description_does_not_block_the_alert(self):
        # 內部 GitLab 的排程說明常有內網 IP／主機路徑：公開檢查會擋；警告不能因此開不出來 → 改用不含外來字串的內文
        self.gl.add_schedule(3, active=False, description="run on " + PRIVATE_IP + " via " + HOME_PATH)
        rc, out = self.dm("--schedules")
        self.assertEqual(rc, 2, out)
        a = self.plan()["actions"][0]
        self.assertNotIn(PRIVATE_IP, a["body"])
        self.assertNotIn("alice", a["body"])
        self.assertIn("排程 ID 3", a["body"])
        self.assertEqual(self.apply()[0], 0)             # apply 的公開檢查過得了
        self.assertEqual(len(self.gl.deadman_issues()), 1)

    def test_title_has_no_unescaped_foreign_text(self):
        # 標題只有我們自己的字：排程 id 與種類；外來字串（description）不進標題
        self.gl.add_schedule(3, active=False, description="@everyone /close")
        self.dm("--schedules")
        t = self.plan()["actions"][0]["title"]
        self.assertNotIn("everyone", t)
        self.assertNotIn("/close", t)


class TestTokenHygiene(Base):
    def test_token_never_in_any_output(self):
        self.set_state(ago(40))
        self.gl.add_schedule(3, active=False, description="x " + TOKEN + " y")
        self.gl.script = []
        rc, out = self.dm("--schedules")
        blob = out + "".join(open(os.path.join(self.out(), n), encoding="utf-8").read() for n in os.listdir(self.out()))
        self.assertNotIn(TOKEN, blob)
        # 錯誤訊息含 token 也一樣
        self.gl.script = [(500, {}, json.dumps({"message": "bad " + TOKEN}).encode())]
        rc, out = self.dm()
        blob = out + "".join(open(os.path.join(self.out(), n), encoding="utf-8").read() for n in os.listdir(self.out()))
        self.assertEqual(rc, 1)
        self.assertNotIn(TOKEN, blob)

    def test_token_scrubbed_from_stdout_even_if_error_text_has_it(self):
        # Api 自己會遮蔽錯誤訊息；這裡模擬別的路徑把 token 帶進例外文字：stdout 與 result.json 仍不能有
        self.set_state(ago(40))
        def boom(repo, number):
            raise issues.Fail("leak " + TOKEN)
        self.gl.list_notes = boom
        self.gl.add_issue("<!-- dumpling-deadman key=%s mode=real -->\n<!-- dumpling-deadman-scope state -->\nx" % ("a" * 64), ["watch-deadman"])
        self.set_state(ago(1))
        rc, out = self.dm()
        blob = out + "".join(open(os.path.join(self.out(), n), encoding="utf-8").read() for n in os.listdir(self.out()))
        self.assertIn("leak ***", blob)
        self.assertNotIn(TOKEN, blob)

    def test_token_not_in_argv_interface(self):
        rc, out = run_main(deadman, [*GL, "--out", self.out(), "--token", TOKEN], self.gl)
        self.assertEqual(rc, 64)
        self.assertNotIn(TOKEN, out)


class TestDedupAndRecovery(Base):
    def stall(self, last, now=NOW_S, *extra):
        self.set_state(last)
        rc, out = self.dm(*extra, now=now)
        self.assertEqual(rc, 2, out)
        rc, out = self.apply()
        self.assertEqual(rc, 0, out)

    def test_same_stall_same_key_one_issue(self):
        last = ago(40)
        self.stall(last)
        k1 = self.plan()["actions"][0]["key"]
        later = (NOW + dt.timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.stall(last, now=later)                  # 停擺持續好幾天
        self.assertEqual(self.plan()["actions"][0]["key"], k1)
        self.assertEqual(len(self.gl.deadman_issues()), 1)
        self.assertEqual(self.gl.notes, {})          # 停擺持續時不留言
        self.assertEqual(len(self.gl.creates), 1)

    def test_created_issue_shape(self):
        self.stall(ago(40))
        (n, i), = self.gl.deadman_issues().items()
        self.assertTrue(i["confidential"])
        self.assertEqual(set(i["labels"]), {"watch-health", "watch-deadman"})
        self.assertTrue(i["description"].startswith("<!-- dumpling-deadman key="))
        self.assertEqual(i["description"].splitlines()[1], "<!-- dumpling-deadman-scope state -->")

    def recover_state(self, hours_ago=1):
        self.set_state(ago(hours_ago))

    def test_recovery_comment_once_and_issue_stays_open(self):
        self.stall(ago(40))
        (n, i), = self.gl.deadman_issues().items()
        self.recover_state()
        rc, out = self.dm()
        self.assertEqual(rc, 0, out)
        p = self.plan()
        self.assertEqual([a["op"] for a in p["actions"]], ["comment"])
        self.assertEqual(p["actions"][0]["key"], self.result()["recovered"][0]["key"])
        body = p["actions"][0]["body"]
        self.assertTrue(body.startswith("<!-- dumpling-deadman-recovered key=%s -->" % p["actions"][0]["key"]))
        self.assertIn("已恢復，時間 " + NOW_S, body)
        self.assertIn(ago(1), body)                       # 恢復後的最後更新時間
        rc, out = self.apply()
        self.assertEqual(rc, 0, out)
        self.assertEqual(len(self.gl.notes[n]), 1)
        self.assertEqual(i["state"], "opened")            # 不自動關閉
        # 再跑一輪：不重複
        rc, out = self.dm()
        self.assertEqual(rc, 0, out)
        self.assertFalse(self.has_plan())
        self.assertEqual(len(self.gl.notes[n]), 1)
        self.assertEqual(self.result()["recovered"], [])

    def test_stall_again_after_recovery_opens_new_issue(self):
        self.stall(ago(40))
        self.recover_state()
        self.dm()
        self.apply()
        later = NOW + dt.timedelta(days=5)
        self.set_state((later - dt.timedelta(hours=60)).strftime("%Y-%m-%dT%H:%M:%SZ"))
        rc, out = self.dm(now=later.strftime("%Y-%m-%dT%H:%M:%SZ"))
        self.assertEqual(rc, 2, out)
        self.assertEqual([a["op"] for a in self.plan()["actions"]], ["open"])         # 舊的已經有恢復留言，不再留言
        self.apply()
        self.assertEqual(len(self.gl.deadman_issues()), 2)
        keys = {re.match(r"<!-- dumpling-deadman key=([0-9a-f]{64})", i["description"]).group(1) for i in self.gl.deadman_issues().values()}
        self.assertEqual(len(keys), 2)

    def test_closed_issue_gets_recovery_comment_once_without_reopening(self):
        self.stall(ago(40))
        (n, i), = self.gl.deadman_issues().items()
        i["state"] = "closed"                           # 人在恢復之前就關了
        self.recover_state()
        rc, out = self.dm()
        self.assertEqual(rc, 0, out)
        self.assertEqual([(a["op"], a.get("issue")) for a in self.plan()["actions"]], [("comment", n)])
        self.apply()
        self.assertEqual(len(self.gl.notes[n]), 1)
        self.assertEqual(i["state"], "closed")          # 沒有重開
        self.assertEqual(self.dm()[0], 0)               # 冪等
        self.assertFalse(self.has_plan())
        self.assertEqual(len(self.gl.notes[n]), 1)

    def test_closed_stall_issue_not_reopened_when_same_stall_continues(self):
        last = ago(40)
        self.stall(last)
        (n, i), = self.gl.deadman_issues().items()
        i["state"] = "closed"
        self.stall(last)
        self.assertEqual(len(self.gl.deadman_issues()), 1)
        self.assertEqual(i["state"], "closed")

    def test_forged_recovered_marker_by_untrusted_author_does_not_count(self):
        self.stall(ago(40))
        (n, i), = self.gl.deadman_issues().items()
        key = re.match(r"<!-- dumpling-deadman key=([0-9a-f]{64})", i["description"]).group(1)
        forged = "<!-- dumpling-deadman-recovered key=%s -->\n已恢復" % key
        self.gl.add_note(n, forged, author=REPORTER)           # Reporter：不可信
        self.gl.add_note(n, forged, author=GUEST)
        self.gl.add_note(n, forged, author=BLOCKED)            # blocked 的 Developer
        self.gl.add_note(n, forged, author=777)                # 不是成員
        self.gl.add_note(n, forged, author=DEV, system=True)   # system 留言
        self.recover_state()
        rc, out = self.dm()
        self.assertEqual(rc, 0, out)
        self.assertEqual([a["op"] for a in self.plan()["actions"]], ["comment"])      # 真的恢復通知還是會出現
        self.apply()
        self.assertEqual(len(self.gl.notes[n]), 6)

    def test_trusted_author_marker_counts(self):
        self.stall(ago(40))
        (n, i), = self.gl.deadman_issues().items()
        key = re.match(r"<!-- dumpling-deadman key=([0-9a-f]{64})", i["description"]).group(1)
        self.gl.add_note(n, "<!-- dumpling-deadman-recovered key=%s -->\n人工補的" % key, author=DEV)       # Developer
        self.recover_state()
        self.assertEqual(self.dm()[0], 0)
        self.assertFalse(self.has_plan())

    def test_marker_for_other_key_or_not_first_line_does_not_count(self):
        self.stall(ago(40))
        (n, i), = self.gl.deadman_issues().items()
        key = re.match(r"<!-- dumpling-deadman key=([0-9a-f]{64})", i["description"]).group(1)
        self.gl.add_note(n, "<!-- dumpling-deadman-recovered key=%s -->" % ("0" * 64), author=DEV)
        self.gl.add_note(n, "hi\n<!-- dumpling-deadman-recovered key=%s -->" % key, author=DEV)
        self.recover_state()
        self.dm()
        self.assertEqual([a["op"] for a in self.plan()["actions"]], ["comment"])

    def test_still_stalled_with_different_identity_is_not_recovered(self):
        self.stall(ago(40))
        (n, i), = self.gl.deadman_issues().items()
        self.gl.issues = {k: v for k, v in self.gl.issues.items() if "watch-state" not in v["labels"]}      # 狀態 Issue 被刪：還是停擺
        rc, out = self.dm()
        self.assertEqual(rc, 2, out)
        self.assertEqual([a["op"] for a in self.plan()["actions"]], ["open"])
        self.assertEqual(self.plan()["actions"][0]["key"], deadman.key_of("real", "state:missing", 1))

    def test_api_fail_never_recovers(self):
        self.stall(ago(40))
        self.recover_state()
        self.gl.script = [(500, {}, b"{}")]
        rc, out = self.dm()
        self.assertEqual(rc, 1)
        self.assertFalse(self.has_plan())

    def test_issue_without_scope_line_is_not_commented(self):
        self.gl.add_issue("<!-- dumpling-deadman key=%s mode=real -->\n舊格式" % ("a" * 64), ["watch-health", "watch-deadman"])
        self.recover_state()
        self.assertEqual(self.dm()[0], 0)
        self.assertFalse(self.has_plan())

    def test_other_mode_issue_not_touched(self):
        self.gl.add_issue("<!-- dumpling-deadman key=%s mode=drill -->\n<!-- dumpling-deadman-scope state -->\nx" % ("a" * 64), ["watch-deadman"])
        self.recover_state()
        self.assertEqual(self.dm()[0], 0)
        self.assertFalse(self.has_plan())

    def test_recovery_lookup_failure_does_not_hide_alert(self):
        self.set_state(ago(40))
        orig = self.gl.list_issues

        def bad(repo, label, state="all"):
            if label == "watch-deadman":
                raise issues.Fail("boom")
            return orig(repo, label, state)
        self.gl.list_issues = bad
        rc, out = self.dm()
        # 查不到歷史：已確定的警告仍然送出（plan 有 open），但結果是 FAIL（結束碼 1），不是 ALERT（2）
        self.assertEqual(rc, 1, out)
        self.assertEqual(last_line(out)[1], "FAIL")
        self.assertEqual(self.result()["status"], "FAIL")
        self.assertEqual([a["op"] for a in self.plan()["actions"]], ["open"])
        self.assertEqual([(c["name"], c["status"]) for c in self.result()["checks"]], [("state", "ALERT"), ("recovery", "FAIL")])
        # 沒有警告、只有恢復查詢失敗 → 一樣 FAIL，沒有 plan
        self.set_state(ago(1))
        self.assertEqual(self.dm()[0], 1)
        self.assertFalse(self.has_plan())

    def test_schedule_issue_recovery_scoped(self):
        self.set_state(ago(1))
        self.gl.add_schedule(3, active=False)
        self.assertEqual(self.dm("--schedules")[0], 2)
        self.apply()
        (n, i), = self.gl.deadman_issues().items()
        self.assertIn("<!-- dumpling-deadman-scope schedule:3 -->", i["description"])
        # 沒帶 --schedules：沒檢查排程，不能說恢復
        self.assertEqual(self.dm()[0], 0)
        self.assertFalse(self.has_plan())
        # 排程還沒好（看不到 variables：GAP）：不算恢復
        self.gl.schedules[3]["single"] = "403"
        self.assertEqual(self.dm("--schedules")[0], 2)
        self.assertEqual([a["op"] for a in self.plan()["actions"]], ["open"])
        self.apply()
        self.assertNotIn(n, self.gl.notes)
        # 排程恢復、GAP 也解除
        self.gl.schedules[3].update(single="ok")
        self.gl.schedules[3]["row"]["active"] = True
        rc, out = self.dm("--schedules")
        self.assertEqual(rc, 0, out)
        self.assertEqual({r["issue"] for r in self.result()["recovered"]}, {n, max(self.gl.deadman_issues())})
        self.apply()
        self.assertIn("排程 3 恢復正常", self.gl.notes[n][0]["body"])
        self.assertIn("variables", self.gl.notes[max(self.gl.deadman_issues())][0]["body"])
        self.assertEqual(self.dm("--schedules")[0], 0)
        self.assertFalse(self.has_plan())

    def test_schedule_one_fixed_other_still_broken(self):
        self.set_state(ago(1))
        self.gl.add_schedule(3, active=False)
        self.gl.add_schedule(4, owner_state="blocked")
        self.dm("--schedules")
        self.apply()
        self.gl.schedules[3]["row"]["active"] = True
        self.assertEqual(self.dm("--schedules")[0], 2)
        recs = self.result()["recovered"]
        self.assertEqual(len(recs), 1)          # 只有排程 3 的 Issue 恢復，排程 4 還沒（它的警告照舊在 plan 裡，apply 不會重複開）
        self.assertEqual(sorted(a["op"] for a in self.plan()["actions"]), ["comment", "open"])

    def test_none_issue_not_recovered_while_variables_are_hidden(self):
        self.set_state(ago(1))
        self.assertEqual(self.dm("--schedules")[0], 2)
        self.apply()
        self.gl.add_schedule(3, single="403")          # 排程出現了，但看不到 variables：不知道它是不是 watch 排程
        self.assertEqual(self.dm("--schedules")[0], 2)
        self.assertNotIn("comment", [a["op"] for a in self.plan()["actions"]])
        self.assertEqual(self.idents_of_plan(), {"schedule:all:gap"})

    def idents_of_plan(self):
        return {a["ident"] for a in self.result()["alerts"]}

    def test_no_watch_schedule_then_created(self):
        self.set_state(ago(1))
        self.assertEqual(self.dm("--schedules")[0], 2)
        self.apply()
        self.gl.add_schedule(3)
        self.assertEqual(self.dm("--schedules")[0], 0)
        self.assertEqual([a["op"] for a in self.plan()["actions"]], ["comment"])


class TestIncidentCount(Base):
    """停擺次數 n：恢復、人關閉之後同一種問題再發生要開新的 Issue；只認可信作者的 Issue（偽造的同 key Issue 吞不掉警告）。"""

    def k(self, base, n=1):
        return deadman.key_of("real", base, n)

    def forge(self, base, n=1, state="opened", author=REPORTER, scope="state", mode="real"):
        body = "<!-- dumpling-deadman key=%s mode=%s -->\n<!-- dumpling-deadman-scope %s -->\n偽造的" % (deadman.key_of(mode, base, n), mode, scope)
        return self.gl.add_issue(body, ["watch-health", "watch-deadman"], state=state, author=author)

    def real(self):
        """可信作者（BOT）的 deadman Issue：{編號: Issue}。"""
        return {n: i for n, i in self.gl.deadman_issues().items() if i["author"]["id"] == BOT}

    def tick(self, days=0):
        """時間往前走 days 天；狀態與排程都「剛跑過」（不是因為時間過去而變成停擺）。"""
        self.cur = NOW + dt.timedelta(days=days)
        self.set_state((self.cur - dt.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"))
        for sc in self.gl.schedules.values():
            sc["row"]["next_run_at"] = (self.cur + dt.timedelta(hours=12)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    def go(self):
        return self.dm("--schedules", now=self.cur.strftime("%Y-%m-%dT%H:%M:%SZ"))

    def cycle(self, break_it, fix_it, base):
        """開(n=1) → 恢復留言 → 人關閉 → 再發生 → 開新的(n=2)，持續好幾天不重複開；再恢復、再發生 → n=3。"""
        self.cur = NOW
        self.tick(0)
        self.gl.add_schedule(3)
        self.tick(0)
        break_it()
        self.assertEqual(self.go()[0], 2)
        self.assertEqual([(a["op"], a["key"]) for a in self.plan()["actions"]], [("open", self.k(base, 1))])
        self.apply()
        self.assertEqual(len(self.real()), 1)
        fix_it()
        rc, out = self.go()
        self.assertEqual(rc, 0, out)
        self.assertEqual([(a["op"], a["key"]) for a in self.plan()["actions"]], [("comment", self.k(base, 1))])
        self.apply()
        first = min(self.real())
        self.assertEqual(len(self.gl.notes[first]), 1)
        self.gl.issues[first]["state"] = "closed"            # 人確認後關閉
        self.assertEqual(self.go()[0], 0)                    # 恢復後的正常輪：什麼都不做
        self.assertFalse(self.has_plan())
        break_it()
        rc, out = self.go()
        self.assertEqual(rc, 2, out)
        a = self.plan()["actions"][0]
        self.assertEqual((a["op"], a["key"]), ("open", self.k(base, 2)))
        self.assertIn("第 2 次", a["title"])
        self.assertIn("第 2 次", a["body"])
        self.apply()
        self.assertEqual(len(self.real()), 2)
        self.assertEqual(self.gl.issues[first]["state"], "closed")          # 舊的不重開
        for days in (1, 2, 3):                               # 這次停擺持續好幾天：不再開新的
            self.tick(days)
            break_it()
            self.assertEqual(self.go()[0], 2)
            self.assertEqual(self.plan()["actions"][0]["key"], self.k(base, 2))
            self.apply()
            self.assertEqual(len(self.real()), 2)
        second = max(self.real())
        fix_it()
        self.go()
        self.assertEqual([(a["op"], a["key"]) for a in self.plan()["actions"]], [("comment", self.k(base, 2))])
        self.apply()
        self.assertEqual(len(self.gl.notes[second]), 1)
        self.assertEqual(len(self.gl.notes[first]), 1)          # 已關閉的舊 Issue 沒有再收到留言
        self.gl.issues[second]["state"] = "closed"
        break_it()
        self.go()
        self.assertEqual(self.plan()["actions"][0]["key"], self.k(base, 3))

    def cycle_closed_before_recovery(self, break_it, fix_it, base):
        """人在恢復之前就把 Issue 關了：恢復時已關閉的 Issue 也收到恢復留言（不重開），下次再發生開 n=2。"""
        self.cur = NOW
        self.tick(0)
        self.gl.add_schedule(3)
        self.tick(0)
        break_it()
        self.go()
        self.apply()
        first = min(self.real())
        self.gl.issues[first]["state"] = "closed"
        for _ in range(2):                               # 問題還在：不留言、不重開、不開新的
            self.assertEqual(self.go()[0], 2)
            self.assertEqual([(a["op"], a["key"]) for a in self.plan()["actions"]], [("open", self.k(base, 1))])
            self.apply()
            self.assertEqual((len(self.real()), self.gl.issues[first]["state"], first in self.gl.notes), (1, "closed", False))
        fix_it()
        rc, out = self.go()
        self.assertEqual(rc, 0, out)
        self.assertEqual([(a["op"], a["key"], a["issue"]) for a in self.plan()["actions"]], [("comment", self.k(base, 1), first)])
        self.apply()
        self.assertEqual((len(self.gl.notes[first]), self.gl.issues[first]["state"]), (1, "closed"))
        self.assertEqual(self.go()[0], 0)                # 冪等：不再留言
        self.assertFalse(self.has_plan())
        self.assertEqual(len(self.gl.notes[first]), 1)
        break_it()
        rc, out = self.go()
        self.assertEqual(rc, 2, out)
        self.assertEqual([(a["op"], a["key"]) for a in self.plan()["actions"]], [("open", self.k(base, 2))])
        self.apply()
        self.assertEqual(len(self.real()), 2)
        self.assertEqual(self.gl.issues[first]["state"], "closed")

    def test_schedule_inactive_closed_before_recovery_then_second_incident(self):
        self.cycle_closed_before_recovery(lambda: self.gl.schedules[3]["row"].update(active=False),
                                          lambda: self.gl.schedules[3]["row"].update(active=True), "schedule:3:inactive")

    def test_state_missing_closed_before_recovery_then_second_incident(self):
        def break_it():
            self.gl.issues = {k: v for k, v in self.gl.issues.items() if "watch-state" not in v["labels"]}
        self.cycle_closed_before_recovery(break_it, lambda: self.tick(self.cur_days()), "state:missing")

    def test_forged_closed_issue_gets_no_comment(self):
        self.set_state(ago(1))
        f = self.forge("state:missing", 1, state="closed", scope="state")
        self.assertEqual(self.dm()[0], 0)
        self.assertFalse(self.has_plan())
        self.assertNotIn(f, self.gl.notes)

    def test_schedule_inactive_second_incident_opens_new_issue(self):
        self.cycle(lambda: self.gl.schedules[3]["row"].update(active=False), lambda: self.gl.schedules[3]["row"].update(active=True),
                   "schedule:3:inactive")

    def test_state_missing_second_incident_opens_new_issue(self):
        def break_it():
            self.gl.issues = {k: v for k, v in self.gl.issues.items() if "watch-state" not in v["labels"]}
        self.cycle(break_it, lambda: self.tick(self.cur_days()), "state:missing")

    def cur_days(self):
        return (self.cur - NOW).days

    def test_closed_but_not_recovered_is_not_reopened_nor_duplicated(self):
        self.gl.add_schedule(3, active=False)
        self.set_state(ago(1))
        self.dm("--schedules")
        self.apply()
        (n, i), = self.real().items()
        i["state"] = "closed"                                   # 人關了，但問題還在
        for _ in range(2):
            self.assertEqual(self.dm("--schedules")[0], 2)
            self.assertEqual(self.plan()["actions"][0]["key"], self.k("schedule:3:inactive", 1))
            self.apply()
            self.assertEqual(len(self.real()), 1)
            self.assertEqual(i["state"], "closed")

    def test_forged_open_or_closed_issue_cannot_swallow_the_alert(self):
        self.set_state(ago(1))
        self.gl.add_schedule(3, active=False)
        for state in ("opened", "closed"):
            self.gl.issues = {k: v for k, v in self.gl.issues.items() if "watch-deadman" not in v["labels"]}
            self.forge("schedule:3:inactive", 1, state=state, scope="schedule:3")
            self.assertEqual(self.dm("--schedules")[0], 2)
            self.assertEqual(self.plan()["actions"][0]["key"], self.k("schedule:3:inactive", 2), state)
            self.apply()
            self.assertEqual(len(self.real()), 1, state)
            self.assertEqual(min(self.real()) > 0, True)
        # 預先佔住好幾個 key
        self.gl.issues = {k: v for k, v in self.gl.issues.items() if "watch-deadman" not in v["labels"]}
        self.forge("schedule:3:inactive", 1, scope="schedule:3")
        self.forge("schedule:3:inactive", 2, state="closed", scope="schedule:3")
        self.dm("--schedules")
        self.assertEqual(self.plan()["actions"][0]["key"], self.k("schedule:3:inactive", 3))

    def test_forged_issue_after_real_recovered_incident_is_skipped(self):
        self.set_state(ago(1))
        self.gl.add_schedule(3, active=False)
        self.dm("--schedules")
        self.apply()
        self.gl.schedules[3]["row"]["active"] = True
        self.dm("--schedules")
        self.apply()                                   # 恢復留言
        self.gl.schedules[3]["row"]["active"] = False
        self.forge("schedule:3:inactive", 2, scope="schedule:3")      # 有人搶先佔住 n=2
        self.dm("--schedules")
        self.assertEqual(self.plan()["actions"][0]["key"], self.k("schedule:3:inactive", 3))

    def test_forged_issue_never_gets_recovery_comment(self):
        self.set_state(ago(1))
        f = self.forge("state:missing", 1, scope="state")
        self.assertEqual(self.dm()[0], 0)
        self.assertFalse(self.has_plan())
        self.assertNotIn(f, self.gl.notes)

    def test_trusted_issue_wins_over_forged_copy_of_same_key(self):
        self.set_state(ago(40))
        self.dm()
        self.apply()
        (n, i), = self.real().items()
        self.forge("state-stale:" + ago(40), 1)                # 同 key 的偽造 Issue（編號比較大）
        self.set_state(ago(1))
        self.dm()
        self.assertEqual([(a["op"], a["key"]) for a in self.plan()["actions"]], [("comment", self.k("state-stale:" + ago(40), 1))])
        self.apply()
        self.assertEqual(len(self.gl.notes[n]), 1)

    def test_duplicate_trusted_issues_same_key_one_recovery_comment_on_highest(self):
        self.set_state(ago(1))
        body = "<!-- dumpling-deadman key=%s mode=real -->\n<!-- dumpling-deadman-scope state -->\nx" % self.k("state:missing", 1)
        a = self.gl.add_issue(body, ["watch-deadman"], author=DEV)
        b = self.gl.add_issue(body, ["watch-deadman"], author=BOT)
        self.dm()
        self.assertEqual([(x["op"], x["key"]) for x in self.plan()["actions"]], [("comment", self.k("state:missing", 1))])
        self.apply()
        self.assertEqual(sorted(self.gl.notes), [b])

    def test_token_bot_is_trusted_even_if_not_listed_as_member(self):
        self.gl.members.pop(BOT)                           # 成員查詢查不到 bot；只靠 GET /user
        self.set_state(ago(40))
        self.dm()
        self.apply()
        self.set_state(ago(1))
        self.dm()
        self.assertEqual([a["op"] for a in self.plan()["actions"]], ["comment"])
        self.apply()
        self.set_state(ago(100))
        self.dm()
        self.assertEqual([a["op"] for a in self.plan()["actions"]], ["open"])       # 新的 base（最後更新時間不同）
        self.gl.members[BOT] = (40, "active")

    def test_too_many_incidents_is_fail(self):
        old = deadman.MAX_N
        deadman.MAX_N = 3
        self.addCleanup(setattr, deadman, "MAX_N", old)
        self.set_state(ago(1))
        self.gl.add_schedule(3, active=False)
        for n in (1, 2, 3):
            self.forge("schedule:3:inactive", n, scope="schedule:3")
        rc, out = self.dm("--schedules")
        self.assertEqual(rc, 1, out)
        self.assertEqual(self.result()["status"], "FAIL")
        self.assertFalse(self.has_plan())
        self.assertIn("超過上限", out)

    def test_history_lookup_failure_still_reports_alert(self):
        self.set_state(ago(40))
        orig = self.gl.list_issues

        def bad(repo, label, state="all"):
            if label == "watch-deadman":
                raise issues.Fail("boom")
            return orig(repo, label, state)
        self.gl.list_issues = bad
        rc, out = self.dm()
        self.assertEqual(rc, 1, out)                 # 不是 2：不知道第幾次停擺時要看得出來
        self.assertEqual(self.plan()["actions"][0]["key"], self.k("state-stale:" + ago(40), 1))
        self.assertEqual(self.result()["status"], "FAIL")


class TestReminder(Base):
    """同一次停擺持續：每 7 天在原 Issue 留一則「仍在停擺」（T-08 寄信做好之前）。"""

    def start(self):
        self.last = ago(40)
        self.set_state(self.last)
        self.assertEqual(self.dm()[0], 2)
        self.apply()
        (self.n, self.issue), = self.gl.deadman_issues().items()
        self.key = re.match(r"<!-- dumpling-deadman key=([0-9a-f]{64})", self.issue["description"]).group(1)

    def at(self, days, **kw):
        now = (NOW + dt.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        rc, out = self.dm(now=now, **kw)
        self.assertEqual(rc, 2, out)
        return [a for a in self.plan()["actions"] if a["op"] == "comment"]

    def test_day_6_no_reminder_day_7_reminder_then_quiet(self):
        self.start()
        self.assertEqual(self.at(6), [])
        self.assertEqual(self.at(6.99), [])
        c = self.at(7)
        self.assertEqual(len(c), 1)
        self.assertEqual((c[0]["key"], c[0]["issue"]), (self.key, self.n))
        self.assertTrue(c[0]["body"].startswith("<!-- dumpling-deadman-reminder key=%s at=" % self.key))
        self.assertIn("仍在停擺（自 " + NOW_S, c[0]["body"])
        self.assertIn("T-08", c[0]["body"])
        self.assertEqual(self.dm(now=(NOW + dt.timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ"))[0], 2)
        self.apply()
        self.assertEqual(len(self.gl.notes[self.n]), 1)
        self.assertEqual(self.result()["reminded"], [{"key": self.key, "issue": self.n}])
        # 冪等：同一天再跑、之後 6 天都不再留；14 天再留一則
        self.assertEqual(self.at(7), [])
        self.assertEqual(self.at(13), [])
        c = self.at(14)
        self.assertEqual(len(c), 1)
        self.apply()
        self.assertEqual(len(self.gl.notes[self.n]), 2)
        self.assertEqual(len(self.gl.deadman_issues()), 1)            # 沒有開新的 Issue
        self.assertEqual(self.gl.issues[self.n]["state"], "opened")

    def test_forged_reminder_marker_does_not_count(self):
        self.start()
        forged = "<!-- dumpling-deadman-reminder key=%s at=%s -->\n偽造" % (self.key, (NOW + dt.timedelta(days=6)).strftime("%Y-%m-%dT%H:%M:%SZ"))
        for who in (REPORTER, GUEST, BLOCKED, 777):
            self.gl.add_note(self.n, forged, author=who)
        self.gl.add_note(self.n, forged, author=DEV, system=True)
        self.assertEqual(len(self.at(7)), 1)            # 真的提醒還是會出現
        # 可信作者（Developer）貼的有效標記才算
        self.gl.add_note(self.n, forged, author=DEV)
        self.assertEqual(self.at(7), [])
        # 別的 key 的標記不算
        self.gl.notes[self.n][-1]["body"] = forged.replace(self.key, "0" * 64)
        self.assertEqual(len(self.at(7)), 1)

    def test_no_reminder_for_closed_or_forged_or_recovered(self):
        self.start()
        self.issue["state"] = "closed"                  # 人關了：由人決定，不提醒
        self.assertEqual(self.at(30), [])
        self.issue["state"] = "opened"
        self.issue["author"] = {"id": REPORTER, "username": "u", "state": "active"}    # 作者不可信的 Issue 不提醒（也不算我們的 Issue）
        rc, out = self.dm(now=(NOW + dt.timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ"))
        self.assertEqual([a["op"] for a in self.plan()["actions"]], ["open"])
        self.assertNotEqual(self.plan()["actions"][0]["key"], self.key)       # 被不可信 Issue 佔用的 key 跳過，開新的

    def test_no_created_at_no_reminder(self):
        self.start()
        self.issue["created_at"] = None
        self.assertEqual(self.at(30), [])
        self.issue["created_at"] = "garbage"
        self.assertEqual(self.at(30), [])


class TestAsciiOnly(Base):
    def test_parse_ts_rejects_fullwidth_digits(self):
        self.assertIsNotNone(deadman.parse_ts("2026-11-15T12:00:00Z"))
        for bad in ("２０２６-11-15T12:00:00Z", "2026-１１-15T12:00:00Z", "2026-11-15T12:00:00.１Z", "2026-11-15T12:00:00+０８:00"):
            self.assertIsNone(deadman.parse_ts(bad), bad)

    def test_fullwidth_digits_in_state_time_is_alert(self):
        st = issues.encode_state({"schema": 1, "runs": [{"at": "２０２６-11-15T11:00:00Z"}]}, "real", "s", urlsafe=True)
        self.gl.add_issue(st, ["watch-state"])
        self.assertEqual(self.dm()[0], 2)
        self.assertEqual(self.plan()["actions"][0]["key"], deadman.key_of("real", "state:no-time", 1))

    def test_now_rejects_fullwidth_digits(self):
        rc, out = run_main(deadman, [*GL, "--out", self.out(), "--now", "２０２６-11-15T12:00:00Z"], self.gl)
        self.assertEqual(rc, 64, out)


if __name__ == "__main__":
    unittest.main()
