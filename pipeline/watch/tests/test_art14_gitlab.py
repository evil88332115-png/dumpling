"""art14.py 的 GitLab 後端單元測試（GITLAB-PORT T-10）：不連網，用記憶體裡的假 GitLab（覆寫 GitLabApi._raw）。
只有假 API 的測試：沒有對真實 GitLab 驗證過。端點與欄位的依據是官方文件（issues.py 的 GitLab 區塊註解）。測資全部合成。"""
import contextlib
import datetime as dt
import io
import json
import os
import sys
import tempfile
import unittest
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
import art14  # noqa: E402
import issues  # noqa: E402

PROJ = "7"
BASE = "https://gitlab.example.com/api/v4"
TOKEN = "glpat-SECRETTOKEN0123456789"
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
FIXTURE = os.path.join(ROOT, "tests", "fixtures", "watch", "art14-drill-match.json")
DEMO_PROJECT = os.path.join(ROOT, "projects", "orin-nano-demo")
NOW_S = "2026-11-13T06:00:00Z"
BOT = 99            # token 自己的使用者（project access token 的 bot 使用者），Maintainer
HUMAN = 10          # Developer
GITLAB_ARGS = ["--backend", "gitlab", "--gitlab-url", BASE, "--gitlab-project", PROJ]


class FakeGitLab(issues.GitLabApi):
    def __init__(self):
        super().__init__(base=BASE, token=TOKEN, sleep=lambda d: None, clock=lambda: 0.0, wall=lambda: 1000)
        self.issues, self.notes, self.labels = {}, {}, {}
        # user id -> (access_level, state)
        self.members = {BOT: (40, "active"), HUMAN: (30, "active"), 11: (20, "active"), 12: (10, "active"), 13: (50, "active"), 14: (30, "blocked")}
        self.n, self.nid, self.tick = 0, 0, 0
        self.writes, self.requests, self.creates = [], [], []
        self.script = []

    def _ts(self):
        self.tick += 1
        return "2026-01-01T00:00:%02d.000Z" % (self.tick % 60)

    def add_issue(self, description, labels, state="opened", title="t", author=HUMAN, confidential=True):
        self.n += 1
        self.issues[self.n] = {"id": 1000 + self.n, "iid": self.n, "title": title, "description": description, "state": state,
                               "labels": list(labels), "updated_at": self._ts(), "confidential": confidential,
                               "author": {"id": author, "username": "u%d" % author, "state": "active"}}
        return self.n

    def add_note(self, num, body, author=HUMAN, system=False):
        self.nid += 1
        self.notes.setdefault(num, []).append({"id": self.nid, "body": body, "system": system,
                                               "author": {"id": author, "username": "u%d" % author, "state": "active"}})
        return self.nid

    def _raw(self, method, url, headers, body):
        u = urllib.parse.urlsplit(url)
        q = urllib.parse.parse_qs(u.query)
        self.requests.append((method, u.path))
        if self.script:
            return self.script.pop(0)
        data = json.loads(body) if body else None
        if method != "GET":
            self.writes.append((method, u.path, data))
        pre = "/api/v4/projects/%s/" % PROJ
        if not u.path.startswith(pre):
            return 404, {}, b'{"message":"404 Project Not Found"}'
        tail = u.path[len(pre):].split("/")
        if tail == ["issues"] and method == "GET":
            lab, st = q["labels"][0], q.get("state", ["all"])[0]
            rows = [i for i in self.issues.values() if lab in i["labels"] and (st == "all" or i["state"] == st)]
            return 200, {"x-next-page": ""}, json.dumps(rows).encode()
        if tail == ["labels"] and method == "GET":
            return 200, {"x-next-page": ""}, json.dumps([{"name": n} for n in self.labels]).encode()
        if tail == ["labels"] and method == "POST":
            self.labels[data["name"]] = data["color"]
            return 201, {}, b"{}"
        if tail == ["issues"] and method == "POST":
            self.creates.append(data)
            names = data["labels"].split(",") if data["labels"] else []
            for l in names:
                assert l in self.labels, "標籤沒先建立"
            num = self.add_issue(data["description"], names, title=data["title"], author=BOT, confidential=data.get("confidential", False))
            return 201, {}, json.dumps(self.issues[num]).encode()
        if len(tail) == 2 and tail[0] == "issues" and method == "PUT":
            i = self.issues[int(tail[1])]
            for k, v in data.items():
                if k == "description":
                    i["description"] = v
                elif k == "labels":
                    i["labels"] = v.split(",") if v else []
                elif k == "state_event":
                    i["state"] = {"close": "closed", "reopen": "opened"}[v]
                elif k == "confidential":
                    i["confidential"] = v
                else:
                    raise AssertionError("不認得的欄位 " + k)
            i["updated_at"] = self._ts()
            return 200, {}, json.dumps(i).encode()
        if len(tail) == 3 and tail[0] == "issues" and tail[2] == "notes":
            n = int(tail[1])
            if method == "GET":
                return 200, {"x-next-page": ""}, json.dumps(self.notes.get(n, [])).encode()
            self.add_note(n, data["body"], author=BOT)
            return 201, {}, b"{}"
        if len(tail) == 4 and tail[0] == "issues" and tail[2] == "notes" and method == "PUT":
            for c in self.notes.get(int(tail[1]), []):
                if c["id"] == int(tail[3]):
                    c["body"] = data["body"]
                    return 200, {}, b"{}"
        if len(tail) == 3 and tail[:2] == ["members", "all"] and method == "GET":
            uid = int(tail[2])
            if uid not in self.members:
                return 404, {}, b'{"message":"404 Not found"}'
            lvl, st = self.members[uid]
            return 200, {}, json.dumps({"id": uid, "username": "u%d" % uid, "access_level": lvl, "state": st}).encode()
        return 404, {}, b'{"message":"404 Not Found"}'

    def label_set(self, n):
        return set(self.issues[n]["labels"])

    def member_gets(self):
        return [p for m, p in self.requests if m == "GET" and "/members/" in p]


def run(argv, api):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = art14.main(argv, api=api)
    return rc, out.getvalue() + err.getvalue()


def last(out):
    return out.strip().splitlines()[-1].split("\t")


def gl(*a):
    return list(a) + GITLAB_ARGS


class Base(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.dir = self._td.name
        self.addCleanup(self._td.cleanup)
        self.gl = FakeGitLab()

    def result(self, name="r.json"):
        return os.path.join(self.dir, name)

    def load(self, path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    def open_case(self, real, project=True, res=None):
        argv = ["open-real" if real else "open-drill", "--match", FIXTURE] + (["--project", DEMO_PROJECT] if project else []) \
            + (["--result", res] if res else []) + GITLAB_ARGS
        return run(argv, self.gl)

    def countdown(self, drill, now=NOW_S, res=None):
        argv = ["countdown", "--now", now] + (["--drill"] if drill else []) + (["--result", res] if res else []) + GITLAB_ARGS
        return run(argv, self.gl)

    def writes_since(self, k):
        return self.gl.writes[k:]


class TestDrillFlow(Base):
    def test_full_drill_flow(self):
        rc, out = self.open_case(False, res=self.result("1.json"))
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.load(self.result("1.json"))["result"], "opened")
        self.assertEqual(self.load(self.result("1.json"))["markets"], "eu-all")
        n = 1
        self.assertTrue(self.gl.creates[0]["confidential"] is True)
        self.assertIn("演練，不是真實通報", self.gl.issues[n]["description"])
        self.assertIn("art14-drill", self.gl.label_set(n))
        self.assertIn("demo", self.gl.label_set(n))
        # 倒數：時鐘未起算
        rc, out = self.countdown(True, res=self.result("2.json"))
        self.assertEqual(rc, 0, out)
        r = self.load(self.result("2.json"))
        self.assertEqual((r["count"], r["issues"][0]["clock"], r["issues"][0]["comment"], r["issues"][0]["hours_since_detected"]),
                         (1, "not_started", "created", 6))
        self.assertEqual(r["issues"][0]["stage_label"], "art14-24h")
        self.assertEqual(len(self.gl.notes[n]), 1)
        self.assertIn("演練，不是真實通報", self.gl.notes[n][0]["body"])
        self.assertEqual(r["leaks"], [])
        # 填知悉時間
        rc, out = run(gl("fill-drill-aware", "--at", "2026-11-13T00:00:00Z"), self.gl)
        self.assertEqual(rc, 0, out)
        self.assertIn("知悉時間（UTC）：2026-11-13T00:00:00Z", self.gl.issues[n]["description"])
        # 再倒數：同一則留言被編輯
        rc, out = self.countdown(True, res=self.result("4.json"))
        self.assertEqual(rc, 0, out)
        r = self.load(self.result("4.json"))["issues"][0]
        self.assertEqual((r["clock"], r["comment"]), ("started", "updated"))
        self.assertEqual((r["stages"]["24h"]["due"], r["stages"]["72h"]["due"], r["stages"]["final"]["due"]),
                         ("2026-11-14T00:00:00Z", "2026-11-16T00:00:00Z", None))
        self.assertEqual(len(self.gl.notes[n]), 1)
        issue_puts = [p for m, path, p in self.gl.writes if m == "PUT" and "/notes/" not in path]
        self.assertTrue(issue_puts and all(p["confidential"] is True for p in issue_puts))
        # 同樣的時間再跑：不寫留言
        k = len(self.gl.writes)
        rc, out = self.countdown(True, res=self.result("4b.json"))
        self.assertEqual(self.load(self.result("4b.json"))["issues"][0]["comment"], "unchanged")
        self.assertEqual(self.writes_since(k), [])
        # 不重複開
        rc, out = self.open_case(False, res=self.result("5.json"))
        self.assertEqual(self.load(self.result("5.json"))["result"], "skipped")
        self.assertEqual(len(self.gl.issues), 1)
        # 關閉
        rc, out = run(gl("close-drill", "--result", self.result("6.json")), self.gl)
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.gl.issues[n]["state"], "closed")
        self.assertEqual(self.gl.label_set(n), {"art14-drill-done", "demo"})
        self.assertEqual(self.gl.notes[n][-1]["body"], "演練結束，自動關閉")
        rc, out = self.countdown(True, res=self.result("7.json"))
        self.assertEqual(self.load(self.result("7.json"))["count"], 0)

    def test_drill_countdown_ignores_real_issue_and_vice_versa(self):
        self.open_case(False)
        self.open_case(True)
        self.assertEqual(len(self.gl.issues), 2)
        rc, out = self.countdown(True, res=self.result("a.json"))
        self.assertEqual([x["number"] for x in self.load(self.result("a.json"))["issues"]], [1])
        rc, out = self.countdown(False, res=self.result("b.json"))
        self.assertEqual([x["number"] for x in self.load(self.result("b.json"))["issues"]], [2])
        self.assertEqual(len(self.gl.notes[1]), 1)
        self.assertEqual(len(self.gl.notes[2]), 1)


class TestRealFlow(Base):
    def test_real_open_countdown_and_edit_same_note(self):
        rc, out = self.open_case(True, res=self.result("1.json"))
        self.assertEqual(rc, 0, out)
        self.assertEqual(last(out)[:2], ["ART14", "OK"])
        body = self.gl.issues[1]["description"]
        self.assertIn("mode=real", body.splitlines()[0])
        self.assertNotIn(art14.DRILL_LINE, body)       # 內文裡還有 fixture 的「演練用」字樣（合成命中），但沒有演練聲明與示範專案說明
        self.assertNotIn(art14.DEMO_LINE, body)
        self.assertNotIn("GitHub", body)
        self.assertIn("私密（confidential）", body)
        self.assertEqual(self.gl.label_set(1), {"art14", "art14-24h"})
        self.assertTrue(self.gl.creates[0]["confidential"] is True)
        rc, out = self.countdown(False, res=self.result("2.json"))
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.load(self.result("2.json"))["issues"][0]["clock"], "not_started")
        note = self.gl.notes[1][0]["body"]
        self.assertNotIn(art14.DRILL_LINE, note)
        self.assertNotIn(art14.DEMO_LINE, note)
        self.assertIn("GitLab 排程", note)
        # 負責人（Developer）填知悉時間
        aware = art14.F_AWARE
        self.gl.issues[1]["description"] = body.replace(f"- {aware}：未填", f"- {aware}：2026-11-13T00:00:00Z")
        rc, out = self.countdown(False, res=self.result("3.json"))
        r = self.load(self.result("3.json"))["issues"][0]
        self.assertEqual((r["clock"], r["comment"], r["stages"]["24h"]["due"]), ("started", "updated", "2026-11-14T00:00:00Z"))
        self.assertEqual(len(self.gl.notes[1]), 1)
        # 再開同一個命中：不重複
        rc, out = self.open_case(True, res=self.result("4.json"))
        self.assertEqual(self.load(self.result("4.json"))["result"], "skipped")
        self.assertEqual(len(self.gl.issues), 1)

    def test_real_case_is_not_touched_by_drill_commands(self):
        self.open_case(True)
        k = len(self.gl.writes)
        rc, out = run(gl("fill-drill-aware", "--at", "2026-11-13T00:00:00Z"), self.gl)
        self.assertEqual(rc, 1)
        rc, out = run(gl("close-drill"), self.gl)
        self.assertEqual(rc, 0)
        self.assertIn("關閉 0 個", out)
        self.assertEqual(self.writes_since(k), [])
        self.assertEqual(self.gl.issues[1]["state"], "opened")

    def test_github_refuses_open_real(self):
        class NoNet(issues.Api):
            def __init__(self):
                super().__init__(base="https://api.example.test", token="ghp_x", sleep=lambda d: None)
                self.calls = 0

            def _raw(self, *a):
                self.calls += 1
                raise AssertionError("不該有任何 API 呼叫")
        api = NoNet()
        rc, out = run(["open-real", "--repo", "octo/demo", "--match", FIXTURE], api)
        self.assertEqual(rc, 1)
        self.assertEqual(last(out)[:2], ["ART14", "FAIL"])
        self.assertIn("不開真實案件", out)
        self.assertEqual(api.calls, 0)

    def test_open_real_on_github_with_gitlab_flags_is_usage_error(self):
        rc, out = run(["open-real", "--repo", "octo/demo", "--gitlab-project", "7", "--match", FIXTURE], None)
        self.assertEqual(rc, 64)


class TestLeakAndTrust(Base):
    def real_body(self):
        _, _, body, _ = art14.render_issue(art14.apply_project(art14.load_match(FIXTURE), None), drill=False, gitlab=True)
        return body

    def test_non_confidential_art14_issue_fails_without_writing(self):
        good = self.gl.add_issue(self.real_body(), ["art14"])
        bad = self.gl.add_issue(self.real_body(), ["art14"], confidential=False)
        rc, out = self.countdown(False, res=self.result())
        self.assertEqual(rc, 1)
        self.assertEqual(last(out)[:2], ["ART14", "FAIL"])
        self.assertIn(f"[{bad}]", last(out)[2])
        self.assertIn("不是 confidential", last(out)[2])
        self.assertNotIn(bad, self.gl.notes)
        self.assertEqual(self.gl.label_set(bad), {"art14"})
        self.assertFalse(any(f"/issues/{bad}" in p for _, p, _ in self.gl.writes))
        # 其他案件照常處理
        self.assertEqual(len(self.gl.notes[good]), 1)
        r = self.load(self.result())
        self.assertEqual(r["leaks"], [bad])
        self.assertEqual([x["number"] for x in r["issues"]], [good])

    def test_non_confidential_drill_issue_not_written_by_any_command(self):
        _, _, body, labels = art14.render_issue(art14.apply_project(art14.load_match(FIXTURE), None))
        n = self.gl.add_issue(body, labels, confidential=False)
        for argv in (gl("countdown", "--drill", "--now", NOW_S), gl("fill-drill-aware", "--at", "2026-11-13T00:00:00Z"), gl("close-drill")):
            rc, out = run(argv, self.gl)
            self.assertEqual(rc, 1, out)
            self.assertIn("不是 confidential", out)
        self.assertEqual(self.gl.writes, [])
        self.assertEqual(self.gl.issues[n]["state"], "opened")

    def test_untrusted_authors_ignored(self):
        body = self.real_body()
        skipped = {}
        for uid in (11, 12, 14, 77):         # Reporter、Guest、blocked、不是成員
            skipped[uid] = self.gl.add_issue(body, ["art14"], author=uid)
        ok = self.gl.add_issue(body, ["art14"], author=13)    # Owner
        ok2 = self.gl.add_issue(body, ["art14"], author=HUMAN)    # Developer（30，剛好）
        rc, out = self.countdown(False, res=self.result())
        # 真實案件有被略過的 → FAIL（倒數停了不能靜默；T-10 驗證建議 3），可信的照樣處理
        self.assertEqual(rc, 1, out)
        self.assertIn("沒有倒數", out)
        r = self.load(self.result())
        self.assertEqual(sorted(x["number"] for x in r["issues"]), sorted([ok, ok2]))
        self.assertEqual(sorted(x["number"] for x in r["skipped"]), sorted(skipped.values()))
        for n in skipped.values():
            self.assertNotIn(n, self.gl.notes)
        self.assertFalse(any(f"/issues/{n}" in p for n in skipped.values() for _, p, _ in self.gl.writes))
        paths = self.gl.member_gets()        # 6 個不同作者，每個只查一次
        self.assertEqual(len(paths), 6)
        self.assertEqual(len(paths), len(set(paths)))

    def test_drill_untrusted_is_only_skipped(self):
        # 演練被略過不算失敗（只有真實案件要 FAIL）
        self.gl.add_issue(self.real_body().replace("mode=real", "mode=drill"), ["art14-drill"], author=11)
        rc, out = self.countdown(True)
        self.assertEqual(rc, 0, out)

    def test_member_api_error_404_by_status_not_message(self):
        # T-10 驗證建議 5：用狀態碼判斷 404；500 的訊息裡就算有「HTTP 404」字樣也不能當成「不是成員」
        orig = self.gl._raw
        def raw(method, url, headers, body):
            if "/members/all/" in url:
                return 500, {}, b'{"message":"upstream said HTTP 404"}'
            return orig(method, url, headers, body)
        self.gl._raw = raw
        with self.assertRaises(issues.Fail):
            self.gl.member_access("7", HUMAN)
        def raw404(method, url, headers, body):
            if "/members/all/" in url:
                return 404, {}, b'{"message":"404 Not found"}'
            return orig(method, url, headers, body)
        self.gl._raw = raw404
        self.assertIsNone(self.gl.member_access("7", HUMAN))

    def test_countdown_reports_leaks_of_the_other_label(self):
        # T-10 驗證建議 2：countdown --drill 也要報出不是 confidential 的真實案件（反過來也一樣），不寫入
        n_real = self.gl.add_issue(self.real_body(), ["art14"], confidential=False)
        k = len(self.gl.writes)
        rc, out = self.countdown(True, res=self.result())
        self.assertEqual(rc, 1, out)
        self.assertIn(n_real, self.load(self.result())["leaks"])
        n_drill = self.gl.add_issue(self.real_body().replace("mode=real", "mode=drill"), ["art14-drill"], confidential=False)
        rc, out = self.countdown(False, res=self.result())
        self.assertEqual(rc, 1, out)
        self.assertIn(n_drill, self.load(self.result())["leaks"])
        self.assertFalse(any(f"/issues/{n}" in p for n in (n_real, n_drill) for _, p, _ in self.writes_since(k)))

    def test_open_dedup_on_non_confidential_existing_fails(self):
        # T-10 驗證建議 1：同一個命中已經有、但不是 confidential → FAIL（外洩疑慮），不當成「不重複開」的 OK
        rc, out = self.open_case(real=True, res=self.result())
        self.assertEqual(rc, 0, out)
        n = self.load(self.result())["issue"]
        self.gl.issues[n]["confidential"] = False
        k = len(self.gl.writes)
        rc, out = self.open_case(real=True, res=self.result())
        self.assertEqual(rc, 1, out)
        self.assertIn("不是 confidential", out)
        self.assertEqual(self.load(self.result())["result"], "leak")
        self.assertEqual(self.writes_since(k), [])

    def test_member_lookup_cached(self):
        body = self.real_body()
        for _ in range(3):
            self.gl.add_issue(body, ["art14"], author=HUMAN)
        self.countdown(False)
        self.countdown(False)
        paths = self.gl.member_gets()
        self.assertEqual(paths.count("/api/v4/projects/7/members/all/10"), 2)    # 每次執行各一次（兩次 main），不是每個 Issue 一次
        self.assertEqual(paths.count("/api/v4/projects/7/members/all/99"), 1)    # 第二輪才有工具自己寫的留言；同一輪只查一次

    def test_system_notes_ignored(self):
        n = self.gl.add_issue(self.real_body(), ["art14"])
        self.gl.add_note(n, art14.COMMENT_MARK + "\n偽造的系統留言\n", author=HUMAN, system=True)
        rc, out = self.countdown(False, res=self.result())
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.load(self.result())["issues"][0]["comment"], "created")
        self.assertEqual(self.gl.notes[n][0]["body"], art14.COMMENT_MARK + "\n偽造的系統留言\n")     # 沒被編輯
        self.assertEqual(len(self.gl.notes[n]), 2)

    def test_forged_countdown_marker_by_untrusted_ignored(self):
        n = self.gl.add_issue(self.real_body(), ["art14"])
        self.gl.add_note(n, art14.COMMENT_MARK + "\n假的\n", author=11)       # Reporter
        self.gl.add_note(n, art14.COMMENT_MARK + "\n假的二\n", author=78)    # 不是成員
        rc, out = self.countdown(False, res=self.result())
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.load(self.result())["issues"][0]["comment"], "created")
        bodies = [c["body"] for c in self.gl.notes[n]]
        self.assertEqual(bodies[0], art14.COMMENT_MARK + "\n假的\n")
        self.assertEqual(bodies[1], art14.COMMENT_MARK + "\n假的二\n")
        self.assertEqual(len(bodies), 3)
        # 第二輪：工具自己的留言（bot 是 Maintainer）被認得、編輯而不是新增
        self.countdown(False, now="2026-11-13T07:00:00Z", res=self.result("2.json"))
        self.assertEqual(self.load(self.result("2.json"))["issues"][0]["comment"], "updated")
        self.assertEqual(len(self.gl.notes[n]), 3)

    def test_member_api_error_is_fail_closed(self):
        self.gl.add_issue(self.real_body(), ["art14"])
        self.gl.script = [(200, {"x-next-page": ""}, json.dumps([dict(self.gl.issues[1])]).encode()),
                          (500, {}, b'{"message":"boom"}')]
        rc, out = self.countdown(False)
        self.assertEqual(rc, 1)
        self.assertEqual(self.gl.writes, [])


class TestQuickActionAndSecrets(Base):
    def test_quick_action_in_title_refused_before_any_write(self):
        orig = art14.render_issue
        art14.render_issue = lambda m, drill=True, gitlab=False: ("k" * 64, "演練\n/close 標題", "<!-- x -->\n演練 正常內文\n", ["art14-drill"])
        try:
            rc, out = self.open_case(False)
        finally:
            art14.render_issue = orig
        self.assertEqual(rc, 1)
        self.assertIn("quick action", out)
        self.assertEqual(self.gl.writes, [])
        self.assertEqual(self.gl.creates, [])

    def test_quick_action_in_body_refused_before_any_write(self):
        orig = art14.render_issue
        art14.render_issue = lambda m, drill=True, gitlab=False: ("k" * 64, "標題", "<!-- x -->\n  /assign me\n", ["art14"])
        try:
            rc, out = self.open_case(True)
        finally:
            art14.render_issue = orig
        self.assertEqual(rc, 1)
        self.assertIn("quick action", out)
        self.assertEqual(self.gl.writes, [])

    def test_quick_action_in_existing_body_blocks_fill_and_countdown_comment(self):
        self.open_case(False)
        self.gl.issues[1]["description"] += "\n/close\n"
        k = len(self.gl.writes)
        rc, out = run(gl("fill-drill-aware", "--at", "2026-11-13T00:00:00Z"), self.gl)
        self.assertEqual(rc, 1)
        self.assertIn("quick action", out)
        self.assertEqual(self.writes_since(k), [])
        orig = art14.render_comment
        art14.render_comment = lambda ev, now, drill, gitlab=False: art14.COMMENT_MARK + "\n演練\n/close\n"
        try:
            rc, out = self.countdown(True)
        finally:
            art14.render_comment = orig
        self.assertEqual(rc, 1)
        self.assertEqual(self.writes_since(k), [])

    def test_real_internal_text_skips_public_check_but_not_quick_action(self):
        # 真實案件（GitLab 內部）不需要「演練」字樣，也不跑公開檢查
        art14.pre_write(self.gl, [("內文", "沒有那兩個字也可以")], False)
        with self.assertRaises(art14.Fail):
            art14.pre_write(self.gl, [("內文", "x\n/close\n")], False)
        # 演練仍然要有「演練」字樣
        with self.assertRaises(art14.Fail):
            art14.pre_write(self.gl, [("內文", "沒有字樣")], True)

    def test_token_never_in_output(self):
        self.open_case(False)
        outs = []
        for argv in (gl("countdown", "--drill", "--now", NOW_S), gl("close-drill")):
            outs.append(run(argv, self.gl)[1])
        self.gl.script = [(500, {}, ('{"message":"%s"}' % TOKEN).encode())]
        rc, out = run(gl("countdown", "--drill", "--now", NOW_S), self.gl)
        outs.append(out)
        self.assertEqual(rc, 1)
        for o in outs:
            self.assertNotIn(TOKEN, o)
        for rec in self.gl.writes:
            self.assertNotIn(TOKEN, json.dumps(rec))

    def test_missing_token_and_usage(self):
        old = os.environ.pop("GITLAB_TOKEN", None)
        try:
            rc, out = run(gl("countdown", "--drill"), None)
        finally:
            if old is not None:
                os.environ["GITLAB_TOKEN"] = old
        self.assertEqual(rc, 1)
        self.assertIn("GITLAB_TOKEN", out)
        for argv in (["countdown", "--backend", "gitlab", "--gitlab-project", "7"],
                     ["countdown", "--backend", "gitlab", "--gitlab-url", "http://evil.example.com/api/v4", "--gitlab-project", "7"],
                     ["countdown", "--backend", "gitlab", "--gitlab-url", BASE, "--gitlab-project", "a/b"],
                     ["countdown", "--backend", "gitlab", "--gitlab-url", BASE, "--gitlab-project", "7", "--repo", "o/r"]):
            self.assertEqual(run(argv, None)[0], 64, argv)


if __name__ == "__main__":
    unittest.main()
