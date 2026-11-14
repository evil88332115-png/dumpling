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
REG = 900            # 登錄 Issue 的 iid
GITLAB_ARGS = ["--backend", "gitlab", "--gitlab-url", BASE, "--gitlab-project", PROJ]


class FakeGitLab(issues.GitLabApi):
    def __init__(self):
        super().__init__(base=BASE, token=TOKEN, sleep=lambda d: None, clock=lambda: 0.0, wall=lambda: 1000)
        self.issues, self.notes, self.labels = {}, {}, {}
        # user id -> (access_level, state)
        self.me = BOT
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
        if u.path == "/api/v4/user" and method == "GET":         # token 自己的使用者（project access token 的 bot）
            if self.me is None:
                return 401, {}, b'{"message":"401 Unauthorized"}'
            return 200, {}, json.dumps({"id": self.me, "username": "bot", "bot": True}).encode()
        pre = "/api/v4/projects/%s/" % PROJ
        if not u.path.startswith(pre):
            return 404, {}, b'{"message":"404 Project Not Found"}'
        tail = u.path[len(pre):].split("/")
        if tail == ["issues"] and method == "GET":
            lab, st, srch = q.get("labels", [None])[0], q.get("state", ["all"])[0], q.get("search", [None])[0]
            # search：官方 List project issues 的 search 參數（比對標題與內文）；這裡用不分大小寫的子字串；labels 沒給就不依標籤篩
            rows = [i for i in self.issues.values() if (lab is None or lab in i["labels"]) and (st == "all" or i["state"] == st)
                    and (srch is None or srch.lower() in ((i["title"] or "") + "\n" + (i["description"] or "")).lower())]
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
            num = self.add_issue(data["description"], names, title=data["title"], author=self.me, confidential=data.get("confidential", False))
            return 201, {}, json.dumps(self.issues[num]).encode()
        if len(tail) == 2 and tail[0] == "issues" and method == "GET":
            if int(tail[1]) not in self.issues:
                return 404, {}, b'{"message":"404 Not found"}'
            return 200, {}, json.dumps(self.issues[int(tail[1])]).encode()
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
            self.add_note(n, data["body"], author=self.me)
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
        # 登錄 Issue（真實案件的 registry）：編號 900，不佔用測試用 Issue 的 1、2…；confidential、作者是 Developer
        self.gl.issues[REG] = {"id": 1900, "iid": REG, "title": "registry", "description": "", "state": "opened", "labels": [],
                               "updated_at": "2026-01-01T00:00:00.000Z", "confidential": True,
                               "author": {"id": HUMAN, "username": "u10", "state": "active"}}

    def result(self, name="r.json"):
        return os.path.join(self.dir, name)

    def load(self, path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    def open_case(self, real, project=True, res=None):
        argv = ["open-real" if real else "open-drill", "--match", FIXTURE] + (["--project", DEMO_PROJECT] if project else []) \
            + (["--result", res] if res else []) + GITLAB_ARGS + (["--registry-issue", str(REG)] if real else [])
        return run(argv, self.gl)

    def countdown(self, drill, now=NOW_S, res=None):
        argv = ["countdown", "--now", now] + (["--drill"] if drill else []) + (["--result", res] if res else []) + GITLAB_ARGS + ([] if drill else ["--registry-issue", str(REG)])
        return run(argv, self.gl)

    def real_case(self, body, labels=("art14",), register=True, **kw):
        """真實案件 Issue；預設同時由可信成員（HUMAN）貼登錄留言（t10c：沒登錄的案件 countdown 會補登錄並 FAIL，所以一般測試都先登錄）。"""
        n = self.gl.add_issue(body, list(labels), **kw)
        mk = art14.parse_marker(body)
        if register and mk:
            self.gl.add_note(REG, f"{art14.REGISTRY_HEAD}\n- 案件 #{n} key={mk[0]} kind={mk[1]}\n", author=HUMAN)
        return n

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
        self.assertEqual(len([x for x in self.gl.notes[n] if x["body"].startswith(art14.COMMENT_MARK)]), 1)   # 倒數留言一則（另有一則紀錄留言）
        self.assertEqual(len([x for x in self.gl.notes[n] if x["body"].startswith(art14.RECORD_HEAD)]), 1)
        issue_puts = [p for m, path, p in self.gl.writes if m == "PUT" and "/notes/" not in path]
        self.assertTrue(all(p["confidential"] is True for p in issue_puts))
        self.assertFalse([p for p in issue_puts if "description" in p])       # GitLab 上不改內文（知悉時間用紀錄留言）
        # 同樣的時間再跑：不寫留言
        k = len(self.gl.writes)
        rc, out = self.countdown(True, res=self.result("4b.json"))
        self.assertEqual(self.load(self.result("4b.json"))["issues"][0]["comment"], "unchanged")
        self.assertEqual(self.writes_since(k), [])
        # 不重複開
        rc, out = self.open_case(False, res=self.result("5.json"))
        self.assertEqual(self.load(self.result("5.json"))["result"], "skipped")
        self.assertEqual(len(self.gl.issues) - 1, 1)     # 扣掉登錄 Issue
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
        self.assertEqual(len(self.gl.issues), 3)
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
        # 負責人（Developer）用「art14 紀錄」留言填知悉時間（GitLab 上內文的時間不算數，#85 驗證應修 1）
        self.assertIn(art14.RECORD_HEAD, body)              # 內文寫明記錄方式
        self.gl.add_note(1, f"{art14.RECORD_HEAD}\n- {art14.F_AWARE}：2026-11-13T00:00:00Z", author=HUMAN)
        rc, out = self.countdown(False, res=self.result("3.json"))
        r = self.load(self.result("3.json"))["issues"][0]
        self.assertEqual((r["clock"], r["comment"], r["stages"]["24h"]["due"]), ("started", "updated", "2026-11-14T00:00:00Z"))
        self.assertEqual(len([n for n in self.gl.notes[1] if n["body"].startswith(art14.COMMENT_MARK)]), 1)
        # 再開同一個命中：不重複
        rc, out = self.open_case(True, res=self.result("4.json"))
        self.assertEqual(self.load(self.result("4.json"))["result"], "skipped")
        self.assertEqual(len(self.gl.issues) - 1, 1)     # 扣掉登錄 Issue

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
        paths = self.gl.member_gets()        # 6 個不同作者＋token 自己（檢查權限），每個只查一次
        self.assertEqual(len(paths), 7)
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
        self.assertEqual(paths.count("/api/v4/projects/7/members/all/99"), 2)    # token 自己：每輪開始前檢查權限一次（同一輪的留言者檢查共用快取）

    def test_system_notes_ignored(self):
        n = self.real_case(self.real_body(), ["art14"])
        self.gl.add_note(n, art14.COMMENT_MARK + "\n偽造的系統留言\n", author=HUMAN, system=True)
        rc, out = self.countdown(False, res=self.result())
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.load(self.result())["issues"][0]["comment"], "created")
        self.assertEqual(self.gl.notes[n][0]["body"], art14.COMMENT_MARK + "\n偽造的系統留言\n")     # 沒被編輯
        self.assertEqual(len(self.gl.notes[n]), 2)

    def test_forged_countdown_marker_by_untrusted_ignored(self):
        n = self.real_case(self.real_body(), ["art14"])
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


class TestRecordsAndHardening(Base):
    """#85 驗證的修正：倒數依據只取自可信成員的紀錄留言、逐案隔離、token 權限、真實案件格式錯 FAIL、存取等級邊界。"""

    def real_body(self):
        _, _, body, _ = art14.render_issue(art14.apply_project(art14.load_match(FIXTURE), None), drill=False, gitlab=True)
        return body

    def rec(self, *lines):
        return art14.RECORD_HEAD + "\n" + "\n".join(lines)

    def test_body_edit_by_anyone_cannot_fake_submission(self):
        # 應修 1：有人（例如 Reporter）把知悉時間與三個提交時間寫進內文 → 不算數（時鐘未起算、三階段都沒完成）
        body = self.real_body().replace(f"- {art14.F_AWARE}：未填", f"- {art14.F_AWARE}：2026-11-13T00:00:00Z")
        body = body.replace(f"- {art14.F_SUBMIT_AT}：未填", f"- {art14.F_SUBMIT_AT}：2026-11-13T01:00:00Z")
        n = self.gl.add_issue(body, ["art14"])
        rc, out = self.countdown(False, res=self.result())
        r = self.load(self.result())["issues"][0]
        self.assertEqual(r["clock"], "not_started")
        self.assertTrue(all(v["state"] != "done" for v in r["stages"].values()), r["stages"])
        # Reporter 寫的紀錄留言也不算，而且真實案件要 FAIL（請人處理）
        self.gl.add_note(n, self.rec(f"- {art14.F_AWARE}：2026-11-13T00:00:00Z", f"- 階段 1 {art14.F_SUBMIT_AT}：2026-11-13T01:00:00Z"), author=11)
        rc, out = self.countdown(False, res=self.result())
        self.assertEqual(rc, 1, out)
        r = self.load(self.result())["issues"][0]
        self.assertEqual(r["clock"], "not_started")
        self.assertTrue(any("不算數" in p for p in r["problems"]))

    def test_trusted_records_drive_countdown_latest_wins_and_blank_clears(self):
        n = self.real_case(self.real_body(), ["art14"])
        self.gl.add_note(n, self.rec(f"- {art14.F_AWARE}：2026-11-12T00:00:00Z"), author=HUMAN)
        self.gl.add_note(n, self.rec(f"- {art14.F_AWARE}：2026-11-13T00:00:00Z", "說明行不解析",
                                     f"- 階段 1 {art14.F_SUBMIT_NO}：SRP-1", f"- 階段 1 {art14.F_SUBMIT_AT}：2026-11-13T05:00:00Z"), author=13)
        rc, out = self.countdown(False, res=self.result())
        self.assertEqual(rc, 0, out)
        r = self.load(self.result())["issues"][0]
        self.assertEqual((r["clock"], r["stages"]["24h"]["due"], r["stages"]["24h"]["state"]), ("started", "2026-11-14T00:00:00Z", "done"))
        self.gl.add_note(n, self.rec(f"- 階段 1 {art14.F_SUBMIT_AT}：未填"), author=HUMAN)       # 寫 未填 就清掉
        rc, out = self.countdown(False, res=self.result())
        self.assertEqual(self.load(self.result())["issues"][0]["stages"]["24h"]["state"], "pending")

    def test_real_record_format_error_fails_but_comment_written(self):
        # 應修 4：真實案件的紀錄格式不對 → 倒數留言照樣更新（寫明問題），整體 FAIL
        n = self.gl.add_issue(self.real_body(), ["art14"])
        self.gl.add_note(n, self.rec(f"- {art14.F_AWARE}：昨天晚上"), author=HUMAN)
        rc, out = self.countdown(False, res=self.result())
        self.assertEqual(rc, 1, out)
        self.assertIn("紀錄有問題", out)
        self.assertTrue(any(x["body"].startswith(art14.COMMENT_MARK) for x in self.gl.notes[n]))
        self.gl.add_note(n, self.rec("- 不認得的欄位：x"), author=HUMAN)
        rc, out = self.countdown(False, res=self.result())
        self.assertEqual(rc, 1, out)

    def test_one_case_failure_isolated_and_result_written(self):
        # 應修 2：第一個案件寫留言失敗 → 記下來，第二個照常處理，result.json 照樣寫出，最後 FAIL
        a = self.gl.add_issue(self.real_body(), ["art14"])
        b = self.gl.add_issue(self.real_body(), ["art14"])
        orig = self.gl._raw
        def raw(method, url, headers, body):
            if method == "POST" and url.endswith(f"/issues/{a}/notes"):
                return 500, {}, b'{"message":"boom"}'
            return orig(method, url, headers, body)
        self.gl._raw = raw
        rc, out = self.countdown(False, res=self.result())
        self.assertEqual(rc, 1, out)
        r = self.load(self.result())
        self.assertEqual(r["failed"], [a])
        self.assertEqual([x["number"] for x in r["issues"]], [b])

    def test_token_without_developer_fails_before_anything(self):
        # 應修 3：token 看不到 confidential Issue 時不能是「沒有案件、OK」
        self.gl.add_issue(self.real_body(), ["art14"])
        for me, why in ((None, "GET /user"), (11, "Developer"), (12, "Developer"), (77, "Developer")):
            self.gl.me = me
            k = len(self.gl.writes)
            for cmd in (lambda: self.countdown(False), lambda: run(gl("fill-drill-aware", "--at", "2026-11-13T00:00:00Z"), self.gl),
                        lambda: run(gl("close-drill"), self.gl)):
                rc, out = cmd()
                self.assertEqual(rc, 1, (me, out))
                self.assertIn(why, out)
            self.assertEqual(self.writes_since(k), [])

    def test_min_level_boundaries(self):
        # 應修 5：15（Planner）、20（Reporter）、25（Security Manager）、29 不可信；30（Developer）可信
        self.gl.members.update({21: (15, "active"), 22: (20, "active"), 23: (25, "active"), 24: (29, "active"), 25: (30, "active")})
        body = self.real_body().replace("mode=real", "mode=drill")
        nums = {uid: self.gl.add_issue(body, ["art14-drill"], author=uid) for uid in (21, 22, 23, 24, 25)}
        rc, out = self.countdown(True, res=self.result())
        self.assertEqual(rc, 0, out)
        r = self.load(self.result())
        self.assertEqual([x["number"] for x in r["issues"]], [nums[25]])
        self.assertEqual(sorted(x["number"] for x in r["skipped"]), sorted(nums[u] for u in (21, 22, 23, 24)))
        self.assertEqual(art14.GITLAB_MIN_LEVEL, 30)

    def test_closed_real_cases_listed(self):
        n = self.gl.add_issue(self.real_body(), ["art14"], state="closed")
        rc, out = self.countdown(False, res=self.result())
        self.assertEqual(rc, 1, out)                     # 已關閉但階段沒做完 → FAIL（法定期限仍在跑）
        closed = self.load(self.result())["closed"]
        self.assertEqual(closed, [{"number": n, "undone": ["24h", "72h", "final"]}])
        self.assertIn("已關閉但還有未提交的階段", out)

    def test_close_drill_skips_untrusted_author(self):
        body = self.real_body().replace("mode=real", "mode=drill")
        bad = self.gl.add_issue(body, ["art14-drill"], author=11)
        good = self.gl.add_issue(body, ["art14-drill"], author=HUMAN)
        rc, out = run(gl("close-drill", "--result", self.result()), self.gl)
        self.assertEqual(rc, 0, out)
        r = self.load(self.result())
        self.assertEqual((r["numbers"], r["untrusted"]), ([good], [bad]))
        self.assertEqual(self.gl.issues[bad]["state"], "opened")


class TestRegistry(TestRecordsAndHardening):
    """T-10 後續：法定倒數不能靜默停掉。標籤、內文標記 Reporter／Planner 都能改，Planner 還能刪 Issue，
    所以「有哪些真實案件」以登錄 Issue 的可信留言為準（art14.py 的 load_registry 說明）。"""

    def reg_line(self, n, kind="vulnerability", key=None):
        _, _, body, _ = art14.render_issue(art14.apply_project(art14.load_match(FIXTURE), None), drill=False, gitlab=True)
        key = key or art14.parse_marker(body)[0]
        return f"{art14.REGISTRY_HEAD}\n- 案件 #{n} key={key} kind={kind}\n"

    def case(self, **kw):
        """已登錄的真實案件（登錄留言由 HUMAN 貼）。"""
        return self.real_case(self.real_body(), ["art14"], **kw)

    def unreg_case(self, **kw):
        """沒登錄的真實案件（例如 open-real 寫登錄失敗、或人工建的）。"""
        return self.real_case(self.real_body(), ["art14"], register=False, **kw)

    def registered(self):
        rc, out = self.countdown(False, res=self.result("reg.json"))
        self.assertEqual(rc, 0, out)
        return self.load(self.result("reg.json"))

    # --- 登錄的建立 ---
    def test_open_real_registers_and_countdown_reads_registry(self):
        rc, out = self.open_case(True)
        self.assertEqual(rc, 0, out)
        notes = self.gl.notes[REG]
        self.assertEqual(len(notes), 1)
        self.assertTrue(notes[0]["body"].startswith(art14.REGISTRY_HEAD + "\n- 案件 #1 key="))
        r = self.registered()
        self.assertEqual(r["registry"]["cases"][0]["number"], 1)
        self.assertEqual(r["registry"]["issue"], REG)

    def test_countdown_auto_registers_labelled_case_once_but_fails_that_run(self):
        # t10c：補登錄成功也 FAIL（請人確認為什麼上次沒登錄成功）；補登錄後下一輪就 OK、不重複登錄
        n = self.unreg_case()
        rc, out = self.countdown(False, res=self.result("reg.json"))
        self.assertEqual(rc, 1, out)
        self.assertIn(f"補登錄了 #{n}，上次沒有登錄成功", out)
        r = self.load(self.result("reg.json"))
        self.assertEqual([c["number"] for c in r["registry"]["cases"]], [n])
        self.assertEqual(r["registry"]["unregistered"], [{"number": n, "via": "label", "registered": True}])
        self.assertEqual([x["number"] for x in r["issues"]], [n])        # 倒數照樣更新
        self.assertEqual(len(self.gl.notes[REG]), 1)
        r = self.registered()
        self.assertEqual(r["registry"]["unregistered"], [])
        self.assertEqual(len(self.gl.notes[REG]), 1)        # 不重複登錄

    def test_registry_not_configured_fails_but_labelled_cases_still_counted(self):
        n = self.case()
        rc, out = run(["countdown", "--now", NOW_S, "--result", self.result()] + GITLAB_ARGS, self.gl)
        self.assertEqual(rc, 1, out)
        self.assertIn("登錄 Issue", out)
        r = self.load(self.result())
        self.assertEqual([x["number"] for x in r["issues"]], [n])        # 倒數照樣更新
        self.assertEqual(self.gl.notes[n][0]["body"].splitlines()[0], art14.COMMENT_MARK)
        # open-real 沒登錄 Issue 就不開
        k = len(self.gl.creates)
        rc, out = run(["open-real", "--match", FIXTURE] + GITLAB_ARGS, self.gl)
        self.assertEqual(rc, 1, out)
        self.assertEqual(len(self.gl.creates), k)

    def test_registry_env_variable_is_read(self):
        n = self.case()
        os.environ[art14.REGISTRY_ENV] = str(REG)
        try:
            rc, out = run(["countdown", "--now", NOW_S] + GITLAB_ARGS, self.gl)
        finally:
            del os.environ[art14.REGISTRY_ENV]
        self.assertEqual(rc, 0, out)
        self.assertEqual(len(self.gl.notes[REG]), 1)

    def test_registry_issue_missing_or_not_confidential_fails(self):
        self.case()
        self.gl.issues[REG]["confidential"] = False
        rc, out = self.countdown(False)
        self.assertEqual(rc, 1, out)
        self.assertIn("不是 confidential", out)
        del self.gl.issues[REG]
        rc, out = self.countdown(False, res=self.result())
        self.assertEqual(rc, 1, out)
        self.assertIn("登錄 Issue", out)
        self.assertEqual(self.load(self.result())["count"], 1)           # 別的案件照常倒數

    # --- Reporter／Planner 的各種手法 ---
    def test_label_removed_after_registration_fails_and_keeps_counting(self):
        n = self.case()
        self.registered()
        self.gl.issues[n]["labels"] = []                                 # Reporter 拿掉標籤
        rc, out = self.countdown(False, now="2026-11-13T07:00:00Z", res=self.result())
        self.assertEqual(rc, 1, out)
        self.assertIn("沒有 art14 標籤", out)
        r = self.load(self.result())
        self.assertEqual([x["number"] for x in r["issues"]], [n])        # 照登錄繼續倒數
        self.assertEqual(r["issues"][0]["comment"], "updated")

    def test_label_and_marker_both_tampered_still_counted_with_registered_kind(self):
        n = self.case()
        self.registered()
        self.gl.issues[n]["labels"] = []
        self.gl.issues[n]["description"] = "Reporter 把整份內文改掉了\n"
        self.gl.add_note(n, self.rec(f"- {art14.F_AWARE}：2026-11-13T00:00:00Z"), author=HUMAN)
        rc, out = self.countdown(False, res=self.result())
        self.assertEqual(rc, 1, out)
        r = self.load(self.result())
        self.assertEqual((r["issues"][0]["kind"], r["issues"][0]["clock"]), ("vulnerability", "started"))
        self.assertIn("標記", out)

    def test_marker_kind_edited_but_label_kept_uses_registered_kind_and_fails(self):
        n = self.case()
        self.registered()
        d = self.gl.issues[n]["description"]
        self.gl.issues[n]["description"] = d.replace("kind=vulnerability", "kind=incident", 1)      # 標記仍合法，但和登錄不符
        rc, out = self.countdown(False, res=self.result())
        self.assertEqual(rc, 1, out)
        self.assertIn("和登錄不符", out)
        self.assertEqual(self.load(self.result())["issues"][0]["kind"], "vulnerability")

    def test_issue_deleted_by_planner_fails(self):
        n = self.case()
        self.registered()
        del self.gl.issues[n]                                            # Planner 能刪任何 Issue（官方 permissions 頁）
        rc, out = self.countdown(False, res=self.result())
        self.assertEqual(rc, 1, out)
        self.assertIn(f"#{n}", out)
        self.assertIn("不見了", out)
        r = self.load(self.result())
        self.assertEqual((r["count"], r["failed"]), (0, [n]))
        self.assertEqual([c["number"] for c in r["registry"]["cases"]], [n])        # 快照還在，人工可以補回

    def test_made_public_and_unlabelled_is_a_leak_not_written(self):
        n = self.case()
        self.registered()
        self.gl.issues[n]["labels"] = []
        self.gl.issues[n]["confidential"] = False
        k = len(self.gl.writes)
        rc, out = self.countdown(False, res=self.result())
        self.assertEqual(rc, 1, out)
        self.assertIn("confidential", out)
        self.assertEqual(self.writes_since(k), [])
        self.assertEqual(self.load(self.result())["leaks"], [n])

    def test_untrusted_registry_note_cannot_add_or_remove(self):
        n = self.case()
        self.gl.add_note(REG, self.reg_line(555), author=11)             # Reporter 偽造登錄：不算（不會去追不存在的 #555）
        self.gl.add_note(REG, self.reg_line(556), author=78)
        # 但不可信的登錄留言要列成問題（真實模式 FAIL）：作者之後變成不可信時，登錄不能靜默消失（t10b 驗證應修 1）
        rc, out = self.countdown(False, res=self.result("reg.json"))
        self.assertEqual(rc, 1, out)
        r = self.load(self.result("reg.json"))
        self.assertEqual([c["number"] for c in r["registry"]["cases"]], [n])
        self.assertEqual(len([p for p in r["registry"]["problems"] if "作者不是 Developer" in p]), 2)
        self.assertEqual([x["number"] for x in r["issues"]], [n])        # 真的案件照常倒數

    def test_registry_author_becomes_untrusted_then_unlabel_is_not_silent(self):
        # t10b 驗證應修 1 的重現：登錄留言的作者（例如輪換掉的 token 的 bot）不再是成員，又有人拿掉案件標籤 → 不能是「沒有案件、OK」
        n = self.case()
        self.registered()
        for note in self.gl.notes[REG]:
            note["author"]["id"] = 4242                                    # 不是成員（404）
        self.gl.issues[n]["labels"] = []
        rc, out = self.countdown(False)
        self.assertEqual(rc, 1, out)
        self.assertIn("作者不是 Developer", out)

    def test_registry_unparsed_lines_reported(self):
        # t10b 驗證建議 3：標頭以外不是「- 案件 …」的非空白行都列成問題（打錯不能靜默漏登錄）
        n = self.case()
        self.registered()
        k = "c" * 64
        for bad in (f"* 案件 #{n} key={k} kind=vulnerability", f"案件 #{n} key={k} kind=vulnerability", "- 案件 #x"):
            self.gl.add_note(REG, f"{art14.REGISTRY_HEAD}\n{bad}", author=HUMAN)
        rc, out = self.countdown(False, res=self.result("reg.json"))
        self.assertEqual(rc, 1, out)
        r = self.load(self.result("reg.json"))
        self.assertEqual(len([p for p in r["registry"]["problems"] if "看不懂" in p]), 3)

    def test_record_list_style_fields_not_silently_ignored(self):
        # t10b 驗證應修 2：可信成員把欄位寫成 * …、> - …、1. …（看起來像清單）→ 列成問題（真實 FAIL），不能靜默 not_started
        for line in (f"* {art14.F_AWARE}：2026-11-13T00:00:00Z", f"> - {art14.F_AWARE}：2026-11-13T00:00:00Z",
                     f"1. {art14.F_AWARE}：2026-11-13T00:00:00Z", f"+ 階段 1 {art14.F_SUBMIT_AT}：2026-11-13T05:00:00Z",
                     "・知悉時間:2026-11-13T00:00:00Z", "1) 階段1 提交時間（UTC）：2026-11-13T05:00:00Z"):
            self.setUp()                     # 每一種寫法都用新的假 GitLab（含登錄 Issue）
            n = self.case()
            self.gl.add_note(n, f"{art14.RECORD_HEAD}\n{line}", author=HUMAN)
            rc, out = self.countdown(False, res=self.result("r.json"))
            self.assertEqual(rc, 1, (line, out))
            r = self.load(self.result("r.json"))["issues"][0]
            self.assertEqual(r["clock"], "not_started", line)
            self.assertTrue(any("沒有解析" in p for p in r["problems"]), (line, r["problems"]))
        self.assertFalse(art14.field_like("負責人確認後記錄", art14.RECORD_FIELDS0["vulnerability"]))     # 說明行不算

    def test_system_registry_note_ignored(self):
        n = self.case()
        self.gl.add_note(REG, self.reg_line(555), author=HUMAN, system=True)
        r = self.registered()
        self.assertEqual([c["number"] for c in r["registry"]["cases"]], [n])

    def test_registry_body_label_state_are_not_used(self):
        n = self.case()
        self.registered()
        ri = self.gl.issues[REG]
        ri["description"], ri["labels"], ri["state"] = "被改掉", ["art14"], "closed"       # 登錄 Issue 的內文、標籤、狀態都不看
        self.gl.issues[n]["labels"] = []
        rc, out = self.countdown(False)
        self.assertEqual(rc, 1, out)
        self.assertIn("沒有 art14 標籤", out)

    def test_registered_case_author_untrusted_is_still_counted(self):
        # t10c：已登錄案件的信任來自登錄（可信成員的登錄留言），不要求 Issue 作者現在還是可信成員（舊 bot 被刪、人員離職都一樣）
        for uid in (11, 12, 14, 77):                                 # Reporter、Guest、blocked、不是成員
            with self.subTest(uid):
                self.setUp()
                n = self.case(author=uid)
                rc, out = self.countdown(False, res=self.result())
                self.assertEqual(rc, 0, out)
                r = self.load(self.result())
                self.assertEqual([x["number"] for x in r["issues"]], [n])
                self.assertEqual(r["skipped"], [])
                self.assertEqual(self.gl.notes[n][0]["body"].splitlines()[0], art14.COMMENT_MARK)

    def test_registered_untrusted_author_still_checked_for_label_confidential_marker_and_404(self):
        n = self.case(author=77)
        self.registered()
        self.gl.issues[n]["labels"] = []
        rc, out = self.countdown(False)
        self.assertEqual((rc, "沒有 art14 標籤" in out, "作者不是專案成員" in out), (1, True, False))
        self.gl.issues[n]["confidential"] = False
        rc, out = self.countdown(False, res=self.result())
        self.assertEqual((rc, self.load(self.result())["leaks"]), (1, [n]))
        self.gl.issues[n].update(confidential=True, labels=["art14"], description="被改掉\n")
        rc, out = self.countdown(False)
        self.assertEqual((rc, "標記" in out), (1, True))
        del self.gl.issues[n]
        rc, out = self.countdown(False)
        self.assertEqual((rc, "不見了" in out), (1, True))

    def test_unregistered_untrusted_author_still_fails_and_points_to_repost(self):
        # 沒登錄（也沒有可信的登錄）、作者又不可信：不倒數、FAIL，訊息說明怎麼救
        n = self.unreg_case(author=77)
        rc, out = self.countdown(False, res=self.result())
        self.assertEqual(rc, 1, out)
        self.assertIn(f"#{n}", out)
        self.assertIn("登錄", out)
        self.assertIn("新的 bot", out)
        self.assertEqual(self.load(self.result())["count"], 0)

    def test_open_real_does_not_reopen_when_label_removed(self):
        self.assertEqual(self.open_case(True)[0], 0)
        self.gl.issues[1]["labels"] = []
        rc, out = self.open_case(True, res=self.result())
        self.assertEqual(rc, 0, out)
        r = self.load(self.result())
        self.assertEqual((r["result"], r["issue"], r["via"]), ("skipped", 1, "registry"))
        self.assertEqual(len(self.gl.creates), 1)
        del self.gl.issues[1]                                            # 被刪了：不悄悄重開，FAIL
        rc, out = self.open_case(True)
        self.assertEqual(rc, 1, out)
        self.assertEqual(len(self.gl.creates), 1)

    # --- 已關閉的案件 ---
    def test_closed_unlabelled_registered_case_with_unfinished_stages_fails(self):
        n = self.case()
        self.registered()
        self.gl.issues[n].update(state="closed", labels=[])
        rc, out = self.countdown(False, res=self.result())
        self.assertEqual(rc, 1, out)
        self.assertEqual(self.load(self.result())["closed"], [{"number": n, "undone": ["24h", "72h", "final"]}])

    def test_closed_case_with_all_stages_done_is_ok(self):
        n = self.case()
        self.registered()
        lines = [f"- {art14.F_AWARE}：2026-11-12T00:00:00Z", f"- {art14.F_MEASURE}：2026-11-12T01:00:00Z"]
        for k in (1, 2, 3):
            lines.append(f"- 階段 {k} {art14.F_SUBMIT_AT}：2026-11-12T0{k}:00:00Z")
        self.gl.add_note(n, self.rec(*lines), author=HUMAN)
        self.gl.issues[n]["state"] = "closed"
        rc, out = self.countdown(False, res=self.result())
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.load(self.result())["closed"], [{"number": n, "undone": []}])

    def test_closed_listing_isolated_per_case(self):
        a = self.gl.add_issue(self.real_body(), ["art14"], state="closed")
        b = self.gl.add_issue(self.real_body(), ["art14"], state="closed")
        orig = self.gl._raw

        def raw(method, url, headers, body):
            if method == "GET" and "/issues/%d/notes" % a in url:
                return 500, {}, b'{"message":"boom"}'
            return orig(method, url, headers, body)
        self.gl._raw = raw
        rc, out = self.countdown(False, res=self.result())
        self.assertEqual(rc, 1, out)
        r = self.load(self.result())
        self.assertEqual([c["number"] for c in r["closed"]], [a, b])
        self.assertIn(a, r["failed"])
        self.assertEqual(r["closed"][1]["undone"], ["24h", "72h", "final"])      # b 照常處理

    # --- 疑似紀錄 ---
    def near_cases(self):
        f = f"- {art14.F_AWARE}：2026-11-13T00:00:00Z"
        return {
            "leading space": f" {art14.RECORD_HEAD}\n{f}",
            "trailing space": f"{art14.RECORD_HEAD} \n{f}",
            "upper case": f"ART14 紀錄\n{f}",
            "code block": f"```\n{art14.RECORD_HEAD}\n{f}\n```",
            "tilde block": f"~~~\n{art14.RECORD_HEAD}\n{f}\n~~~",
            "quote": f"> {art14.RECORD_HEAD}\n> {f}",
            "zero width": f"\u200b{art14.RECORD_HEAD}\n{f}",
        }

    def test_near_match_records_are_reported_not_parsed_and_fail_for_real(self):
        for name, text in self.near_cases().items():
            with self.subTest(name):
                gl = FakeGitLab()
                self.gl = gl
                self.setUp_registry()
                n = gl.add_issue(self.real_body(), ["art14"])
                gl.add_note(n, text, author=HUMAN)
                rc, out = self.countdown(False, res=self.result())
                self.assertEqual(rc, 1, out)
                r = self.load(self.result())["issues"][0]
                self.assertEqual(r["clock"], "not_started")              # 沒有被解析
                self.assertTrue(any("疑似" in p and "沒有解析" in p for p in r["problems"]), r["problems"])
                self.assertIn("疑似", gl.notes[n][-1]["body"])            # 也寫在倒數留言裡

    def setUp_registry(self):
        self.gl.issues[REG] = {"id": 1900, "iid": REG, "title": "registry", "description": "", "state": "opened", "labels": [],
                               "updated_at": "2026-01-01T00:00:00.000Z", "confidential": True,
                               "author": {"id": HUMAN, "username": "u10", "state": "active"}}

    def test_near_match_in_drill_is_shown_but_does_not_fail(self):
        body = self.real_body().replace("mode=real", "mode=drill")
        n = self.gl.add_issue(body, ["art14-drill"])
        self.gl.add_note(n, self.near_cases()["code block"], author=HUMAN)
        rc, out = self.countdown(True, res=self.result())
        self.assertEqual(rc, 0, out)
        self.assertTrue(any("疑似" in p for p in self.load(self.result())["issues"][0]["problems"]))

    def test_near_match_by_untrusted_is_ignored(self):
        n = self.case()
        self.gl.add_note(n, self.near_cases()["leading space"], author=11)
        rc, out = self.countdown(False, res=self.result())
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.load(self.result())["issues"][0]["problems"], [])

    def test_fenced_and_indented_field_lines_never_parsed(self):
        f = f"- {art14.F_AWARE}：2026-11-13T00:00:00Z"
        for name, text in (("fenced", self.rec("```", f, "```")), ("indented", self.rec("  " + f)),
                           ("fenced stage", self.rec("```", f"- 階段 1 {art14.F_SUBMIT_AT}：2026-11-13T01:00:00Z", "```"))):
            with self.subTest(name):
                self.gl.notes.clear()
                self.gl.issues = {k: v for k, v in self.gl.issues.items() if k == REG}
                self.gl.n = 0
                n = self.case()
                self.gl.add_note(n, text, author=HUMAN)
                rc, out = self.countdown(False, res=self.result())
                self.assertEqual(rc, 1, out)
                r = self.load(self.result())["issues"][0]
                self.assertEqual(r["clock"], "not_started")
                self.assertTrue(all(v["state"] != "done" for v in r["stages"].values()))
                self.assertTrue(any("沒有解析" in p for p in r["problems"]), r["problems"])

    def test_text_after_closed_fence_is_parsed_again(self):
        n = self.case()
        self.gl.add_note(n, self.rec("```", "- 隨便", "```", f"- {art14.F_AWARE}：2026-11-13T00:00:00Z"), author=HUMAN)
        rc, out = self.countdown(False, res=self.result())
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.load(self.result())["issues"][0]["clock"], "started")

    # --- system 留言（突變：接受 system 留言要被測試抓到）---
    def test_system_note_is_not_a_record(self):
        n = self.case()
        self.gl.add_note(n, self.rec(f"- {art14.F_AWARE}：2026-11-13T00:00:00Z"), author=HUMAN, system=True)
        rc, out = self.countdown(False, res=self.result())
        self.assertEqual(rc, 0, out)                                     # 不是紀錄，也不是「疑似紀錄」問題
        r = self.load(self.result())["issues"][0]
        self.assertEqual((r["clock"], r["problems"]), ("not_started", []))
        vals, probs = art14.record_values("vulnerability", self.gl.list_notes(PROJ, n), art14.Trust(self.gl, PROJ))
        self.assertEqual((vals, probs), ({}, []))

    def test_system_near_record_and_system_countdown_comment_ignored(self):
        n = self.case()
        self.gl.add_note(n, self.near_cases()["code block"], author=HUMAN, system=True)
        self.gl.add_note(n, art14.COMMENT_MARK + "\nsystem\n", author=BOT, system=True)
        rc, out = self.countdown(False, res=self.result())
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.load(self.result())["issues"][0]["comment"], "created")
        self.assertEqual(self.gl.notes[n][1]["body"], art14.COMMENT_MARK + "\nsystem\n")

    def test_list_notes_maps_system_flag(self):
        n = self.case()
        self.gl.add_note(n, "a", author=HUMAN, system=True)
        self.gl.add_note(n, "b", author=HUMAN)
        self.assertEqual([x["system"] for x in self.gl.list_notes(PROJ, n)], [True, False])

    # --- token 檢查失敗也寫 result.json ---
    def test_token_check_failure_still_writes_result(self):
        self.case()
        self.gl.me = 11
        for cmd, extra in (("countdown", ["--now", NOW_S, "--registry-issue", str(REG)]), ("close-drill", []),
                           ("fill-drill-aware", ["--at", NOW_S]), ("open-real", ["--match", FIXTURE, "--registry-issue", str(REG)])):
            with self.subTest(cmd):
                rp = self.result(cmd + ".json")
                rc, out = run([cmd, "--result", rp] + extra + GITLAB_ARGS, self.gl)
                self.assertEqual(rc, 1, out)
                r = self.load(rp)
                self.assertEqual(r["result"], "token-check-failed")
                self.assertIn("Developer", r["error"])


class TestT10c(Base):
    """#93 驗證的修正：bot／token 輪換、不可信登錄被取代、疑似標頭、list／get 出錯也寫 result、登錄失敗與沒登錄的案件。
    （不繼承 TestRegistry，免得每個測試跑兩次。）"""
    BOT_B = 98

    def real_body(self):
        _, _, body, _ = art14.render_issue(art14.apply_project(art14.load_match(FIXTURE), None), drill=False, gitlab=True)
        return body

    def rec(self, *lines):
        return art14.RECORD_HEAD + "\n" + "\n".join(lines)

    def reg_text(self, n, key=None, kind="vulnerability"):
        key = key or art14.parse_marker(self.real_body())[0]
        return f"{art14.REGISTRY_HEAD}\n- 案件 #{n} key={key} kind={kind}\n"

    def setUp(self):
        super().setUp()
        self.gl.members[self.BOT_B] = (40, "active")

    def unreg_case(self, **kw):
        return self.real_case(self.real_body(), register=False, **kw)

    def cd(self, now=NOW_S, res="r.json"):
        rc, out = self.countdown(False, now=now, res=self.result(res))
        return rc, out, self.load(self.result(res))

    def fail_when(self, pred, status=500):
        orig = self.gl._raw

        def raw(method, url, headers, body):
            if pred(method, url):
                return status, {}, b'{"message":"boom"}'
            return orig(method, url, headers, body)
        self.gl._raw = raw

    # --- bot／token 輪換 ---
    def test_new_bot_user_end_to_end_repost_registry_recovers(self):
        rc, out = self.open_case(True)                                   # bot A（BOT）開案並登錄
        self.assertEqual(rc, 0, out)
        self.gl.add_note(1, self.rec(f"- {art14.F_AWARE}：2026-11-13T00:00:00Z"), author=HUMAN)      # 負責人的知悉時間
        rc, out, r = self.cd()
        self.assertEqual((rc, r["count"], r["issues"][0]["clock"], r["issues"][0]["comment"]), (0, 1, "started", "created"))
        a_note, a_registry = self.gl.notes[1][-1]["id"], self.gl.notes[REG][0]["id"]
        # 換成新的 project access token ＝ 新的 bot 使用者 B；舊 bot A 不再是成員
        del self.gl.members[BOT]
        self.gl.me = self.BOT_B
        k = len(self.gl.writes)
        rc, out, r = self.cd(now="2026-11-13T07:00:00Z", res="b1.json")
        self.assertEqual(rc, 1, out)                                     # 不靜默：FAIL，而且說明怎麼救
        self.assertIn("重貼", out)
        self.assertIn("新的 bot", out)
        self.assertIn(f"#1", out)
        self.assertEqual(r["count"], 0)
        self.assertEqual(self.writes_since(k), [])                       # 沒有亂寫
        self.assertTrue(any("作者不是 Developer" in p for p in r["registry"]["problems"]))
        # B 用新身分重貼登錄（內容取自舊登錄）→ 倒數恢復，人工紀錄（知悉時間）照常算
        self.gl.add_note(REG, self.gl.notes[REG][0]["body"], author=self.BOT_B)
        rc, out, r = self.cd(now="2026-11-13T07:00:00Z", res="b2.json")
        self.assertEqual(rc, 0, out)
        self.assertEqual(r["count"], 1)
        i = r["issues"][0]
        self.assertEqual((i["clock"], i["stages"]["24h"]["due"], i["stages"]["24h"]["state"]), ("started", "2026-11-14T00:00:00Z", "pending"))
        self.assertEqual(r["registry"]["problems"], [])                  # 舊 bot 的登錄被取代，不是問題
        self.assertEqual(r["registry"]["superseded_notes"], [a_registry])
        self.assertEqual(i["comment"], "created")                        # 舊 bot 的倒數留言不算（不可信）→ 新 bot 建一則新的
        self.assertEqual(self.gl.notes[1][[n["id"] for n in self.gl.notes[1]].index(a_note)]["body"].splitlines()[0], art14.COMMENT_MARK)
        # 之後穩定：同一則被編輯／不變，不再 FAIL
        rc, out, r = self.cd(now="2026-11-13T07:00:00Z", res="b3.json")
        self.assertEqual((rc, r["issues"][0]["comment"]), (0, "unchanged"))
        rc, out, r = self.cd(now="2026-11-13T08:00:00Z", res="b4.json")
        self.assertEqual((rc, r["issues"][0]["comment"]), (0, "updated"))
        self.assertEqual(len([n for n in self.gl.notes[1] if n["body"].startswith(art14.COMMENT_MARK) and n["author"]["id"] == self.BOT_B]), 1)

    def test_delete_old_registry_and_repost_as_new_bot_also_recovers(self):
        # 審查者重現的情況：換 bot、刪掉舊登錄 → 以前永遠 FAIL（count=0）。現在：沒有可信登錄時 FAIL 並說明；新身分登錄後恢復
        self.open_case(True)
        body = self.gl.notes[REG][0]["body"]
        del self.gl.members[BOT]
        self.gl.me = self.BOT_B
        self.gl.notes[REG] = []
        rc, out, r = self.cd()
        self.assertEqual((rc, r["count"]), (1, 0))
        self.assertIn("登錄", out)
        self.gl.add_note(REG, body, author=self.BOT_B)
        rc, out, r = self.cd(res="r2.json")
        self.assertEqual((rc, r["count"]), (0, 1))

    def test_same_bot_token_rotation_needs_nothing(self):
        # 輪換 token 保留同一個 bot 使用者（官方 project access tokens 頁）：什麼都不用做
        self.open_case(True)
        rc, out, r = self.cd()
        self.assertEqual((rc, r["issues"][0]["comment"]), (0, "created"))
        self.gl.token = "glpat-ROTATEDTOKEN0123456789"
        k = len(self.gl.writes)
        rc, out, r = self.cd(res="r2.json")
        self.assertEqual((rc, r["count"], r["issues"][0]["comment"], r["registry"]["problems"], r["registry"]["superseded_notes"]),
                         (0, 1, "unchanged", [], []))
        self.assertEqual(self.writes_since(k), [])

    # --- 不可信的登錄留言：被可信登錄完整涵蓋才算取代 ---
    def test_untrusted_registry_note_superseded_only_when_fully_covered(self):
        n = self.real_case(self.real_body())                             # 可信（HUMAN）的登錄涵蓋 #n
        key = art14.parse_marker(self.real_body())[0]
        other = "d" * 64
        cases = {
            "covered": (self.reg_text(n), 0),
            "covered twice": (self.reg_text(n) + f"- 案件 #{n} key={key} kind=vulnerability\n", 0),
            "adds a case": (self.reg_text(555), 1),
            "contradicts key": (self.reg_text(n, key=other), 1),
            "contradicts kind": (self.reg_text(n, kind="incident"), 1),
            "partly covered": (self.reg_text(n) + f"- 案件 #556 key={key} kind=vulnerability\n", 1),
            "covered plus junk line": (self.reg_text(n) + "隨便一行\n", 1),
            "no entries": (art14.REGISTRY_HEAD + "\n", 1),
        }
        for name, (text, want_rc) in cases.items():
            with self.subTest(name):
                self.gl.notes[REG] = [x for x in self.gl.notes[REG] if x["author"]["id"] == HUMAN]
                self.gl.add_note(REG, text, author=11)                   # Reporter（或舊 bot）寫的
                rc, out, r = self.cd(res=name.replace(" ", "_") + ".json")
                self.assertEqual(rc, want_rc, out)
                self.assertEqual(r["count"], 1)                          # 無論如何案件照常倒數
                if want_rc:
                    self.assertTrue(any("作者不是 Developer" in p for p in r["registry"]["problems"]))
                else:
                    self.assertEqual((r["registry"]["problems"], len(r["registry"]["superseded_notes"])), ([], 1))

    # --- 疑似標頭 ---
    RECORD_NEAR = ["art14紀錄", "art14 紀錄：", "art14 紀錄:", "art14 記錄", "[art14 紀錄]", "【art14 紀錄】", "ＡＲＴ１４　紀錄：", "ＡＲＴ１４記錄",
                   "Art14 紀錄 ", "> art14 記錄", "**art14 紀錄**", "（art14 紀錄）"]
    REGISTRY_NEAR = ["art14登錄", "art14 登錄：", "art14 登記", "art14登記", "【art14 登記】", "[art14 登錄]", "ＡＲＴ１４　登錄：", "ＡＲＴ１４登記", "`art14 登記`"]

    def test_head_kind_near_variants_and_non_near(self):
        for h in self.RECORD_NEAR:
            self.assertEqual(art14.head_kind({"body": h + "\n- x"}, art14.RECORD_HEAD), "near", h)
            self.assertIsNone(art14.head_kind({"body": h + "\n- x"}, art14.REGISTRY_HEAD), h)
        for h in self.REGISTRY_NEAR:
            self.assertEqual(art14.head_kind({"body": h + "\n- x"}, art14.REGISTRY_HEAD), "near", h)
            self.assertIsNone(art14.head_kind({"body": h + "\n- x"}, art14.RECORD_HEAD), h)
        self.assertEqual(art14.head_kind({"body": art14.RECORD_HEAD + "\n- x"}, art14.RECORD_HEAD), "exact")
        for h in ("art14 紀錄表", "art14 登記表", "art14", "art15 紀錄", "紀錄 art14", "art14 紀錄知悉時間"):
            self.assertIsNone(art14.head_kind({"body": h}, art14.RECORD_HEAD), h)
            self.assertIsNone(art14.head_kind({"body": h}, art14.REGISTRY_HEAD), h)
        self.assertIsNone(art14.head_kind({"body": "【art14 紀錄】", "system": True}, art14.RECORD_HEAD))

    def test_near_record_headers_fail_real_case_and_are_reported(self):
        for h in self.RECORD_NEAR:
            with self.subTest(h):
                self.setUp()
                n = self.real_case(self.real_body())
                self.gl.add_note(n, f"{h}\n- {art14.F_AWARE}：2026-11-13T00:00:00Z", author=HUMAN)
                rc, out, r = self.cd()
                self.assertEqual(rc, 1, out)
                i = r["issues"][0]
                self.assertEqual(i["clock"], "not_started")              # 沒有被解析
                self.assertTrue(any("疑似" in p and "沒有解析" in p for p in i["problems"]), i["problems"])
                self.assertIn("疑似", self.gl.notes[n][-1]["body"])

    def test_near_record_header_by_untrusted_is_ignored_and_in_drill_does_not_fail(self):
        n = self.real_case(self.real_body())
        self.gl.add_note(n, f"【art14 紀錄】\n- {art14.F_AWARE}：2026-11-13T00:00:00Z", author=11)
        rc, out, r = self.cd()
        self.assertEqual((rc, r["issues"][0]["problems"]), (0, []))
        d = self.gl.add_issue(self.real_body().replace("mode=real", "mode=drill"), ["art14-drill"])
        self.gl.add_note(d, "art14紀錄\n- x", author=HUMAN)
        rc, out = self.countdown(True, res=self.result("d.json"))
        self.assertEqual(rc, 0, out)
        self.assertTrue(any("疑似" in p for p in self.load(self.result("d.json"))["issues"][0]["problems"]))

    def test_near_registry_headers_fail_real_countdown(self):
        for h in self.REGISTRY_NEAR:
            with self.subTest(h):
                self.setUp()
                n = self.real_case(self.real_body())
                self.gl.add_note(REG, self.reg_text(777).replace(art14.REGISTRY_HEAD, h, 1), author=HUMAN)
                rc, out, r = self.cd()
                self.assertEqual(rc, 1, out)
                self.assertTrue(any("疑似登錄" in p for p in r["registry"]["problems"]), r["registry"]["problems"])
                self.assertEqual(r["count"], 1)
                self.assertNotIn(777, [c["number"] for c in r["registry"]["cases"]])    # 疑似的登錄不生效

    def test_near_registry_header_by_untrusted_is_ignored(self):
        self.real_case(self.real_body())
        self.gl.add_note(REG, self.reg_text(777).replace(art14.REGISTRY_HEAD, "【art14 登記】", 1), author=11)
        rc, out, r = self.cd()
        self.assertEqual((rc, r["registry"]["problems"]), (0, []))

    # --- list／get 出錯也寫 result.json ---
    def test_http_error_on_list_or_get_still_writes_error_result(self):
        self.open_case(False)
        self.open_case(True)
        cases = [
            ("countdown-real-list", lambda m, u: m == "GET" and "/issues?" in u and "labels=art14&" in u + "&", "countdown", ["--now", NOW_S, "--registry-issue", str(REG)]),
            ("countdown-drill-list", lambda m, u: m == "GET" and "labels=art14-drill" in u, "countdown", ["--now", NOW_S, "--drill"]),
            ("close-drill-list", lambda m, u: m == "GET" and "labels=art14-drill" in u, "close-drill", []),
            ("fill-drill-aware-list", lambda m, u: m == "GET" and "labels=art14-drill" in u, "fill-drill-aware", ["--at", NOW_S]),
            ("open-real-list", lambda m, u: m == "GET" and "labels=art14&" in u + "&", "open-real", ["--match", FIXTURE, "--registry-issue", str(REG)]),
        ]
        for name, pred, cmd, extra in cases:
            with self.subTest(name):
                gl = self.gl
                orig = gl._raw
                self.fail_when(pred)
                rp = self.result(name + ".json")
                rc, out = run([cmd, "--result", rp] + extra + GITLAB_ARGS, gl)
                gl._raw = orig
                self.assertEqual(rc, 1, out)
                r = self.load(rp)
                self.assertEqual((r["cmd"], r["result"], r["schema"]), (cmd, "error", art14.RESULT_SCHEMA))
                self.assertIn("500", r["error"])

    def test_registry_read_error_writes_normal_result_and_still_counts_cases(self):
        # 登錄讀不到（500）是 countdown 自己收成 errors 的，result 是正常版（其他案件照常倒數），不是 error 版
        self.real_case(self.real_body())
        for name, pred in (("get", lambda m, u: m == "GET" and u.endswith(f"/issues/{REG}")),
                           ("notes", lambda m, u: m == "GET" and f"/issues/{REG}/notes" in u)):
            with self.subTest(name):
                orig = self.gl._raw
                self.fail_when(pred)
                rc, out, r = self.cd(res=name + ".json")
                self.gl._raw = orig
                self.assertEqual((rc, r["cmd"], r["count"], r.get("result")), (1, "countdown", 1, None))

    def test_error_result_does_not_overwrite_a_result_written_earlier_in_the_run(self):
        # countdown 自己最後 FAIL（有寫完整的 result）時，不能被 error 版蓋掉
        self.unreg_case()
        rc, out, r = self.cd()
        self.assertEqual(rc, 1, out)
        self.assertEqual(r["count"], 1)
        self.assertNotEqual(r.get("result"), "error")

    # --- open-real 寫登錄失敗、沒登錄的案件 ---
    def test_open_real_registry_write_failure_fails_then_countdown_flags_it(self):
        orig = self.gl._raw
        self.fail_when(lambda m, u: m == "POST" and u.endswith(f"/issues/{REG}/notes"))
        rc, out = self.open_case(True, res=self.result("o.json"))
        self.assertEqual(rc, 1, out)
        r = self.load(self.result("o.json"))
        self.assertEqual((r["result"], r["issue"]), ("opened-unregistered", 1))
        self.assertIn("#1", out)
        self.assertIn("沒有登錄成功", out)
        self.assertEqual(self.gl.notes.get(REG, []), [])
        # 登錄還是寫不進去：countdown 補登錄也失敗 → FAIL，案件仍倒數
        rc, out, r = self.cd(res="c1.json")
        self.assertEqual((rc, r["count"]), (1, 1))
        self.assertIn("補登錄失敗", out)
        self.assertEqual(r["registry"]["unregistered"], [{"number": 1, "via": "label", "registered": False}])
        # 登錄能寫了：補登錄成功，但這一輪仍 FAIL；下一輪 OK
        self.gl._raw = orig
        rc, out, r = self.cd(res="c2.json")
        self.assertEqual(rc, 1, out)
        self.assertIn("補登錄了 #1，上次沒有登錄成功", out)
        self.assertEqual(len(self.gl.notes[REG]), 1)
        rc, out, r = self.cd(res="c3.json")
        self.assertEqual((rc, r["registry"]["unregistered"]), (0, []))

    def test_unlabelled_unregistered_real_case_found_by_search_fails_without_writes(self):
        n = self.unreg_case()
        self.gl.issues[n]["labels"] = []                                 # 標籤被拿掉、又沒登錄
        k = len(self.gl.writes)
        rc, out, r = self.cd()
        self.assertEqual(rc, 1, out)
        self.assertIn(f"#{n}", out)
        self.assertIn("沒登錄", out)
        self.assertEqual(r["registry"]["unregistered"], [{"number": n, "via": "search", "registered": False}])
        self.assertEqual(self.writes_since(k), [])                       # 不補登錄、不倒數、不寫
        self.assertEqual(r["count"], 0)
        # 人工補回標籤後：下一輪補登錄（FAIL 一次）、再下一輪 OK
        self.gl.issues[n]["labels"] = ["art14"]
        self.assertEqual(self.cd(res="r2.json")[0], 1)
        self.assertEqual(self.cd(res="r3.json")[0], 0)

    def test_search_only_lists_confidential_trusted_real_marker_not_in_registry(self):
        self.real_case(self.real_body())                                 # 已登錄的：不算「沒登錄」
        ok_tags = {
            "untrusted author": self.gl.add_issue(self.real_body(), [], author=11),
            "non member": self.gl.add_issue(self.real_body(), [], author=77),
            "drill marker": self.gl.add_issue(self.real_body().replace("mode=real", "mode=drill"), []),
            "no marker": self.gl.add_issue("dumpling-art14 只是提到而已\n", []),
            "marker not first line": self.gl.add_issue("說明\n" + self.real_body(), []),
        }
        rc, out, r = self.cd()
        self.assertEqual((rc, r["registry"]["unregistered"]), (0, []), (out, ok_tags))
        # 沒登錄、沒標籤、又不是 confidential：不列在「沒登錄」，而是當外洩疑慮（leaks）FAIL、不寫入
        pub = self.gl.add_issue(self.real_body(), [], confidential=False)
        k = len(self.gl.writes)
        rc, out, r = self.cd(res="pub.json")
        self.assertEqual((rc, r["registry"]["unregistered"], r["leaks"]), (1, [], [pub]))
        self.assertFalse(any(f"/issues/{pub}" in pth for _, pth, _ in self.writes_since(k)))

    def test_search_non_confidential_by_untrusted_author_is_a_leak(self):
        # #93 複驗應修：作者不可信（Reporter）、非 confidential、沒標籤、沒登錄、有 mode=real 標記 → 也要列進 leaks（先查 confidential）
        self.real_case(self.real_body())
        for author in (11, 77):                                          # Reporter、不是成員
            self.setUp()
            self.real_case(self.real_body())
            pub = self.gl.add_issue(self.real_body(), [], author=author, confidential=False)
            k = len(self.gl.writes)
            rc, out, r = self.cd(res="pub.json")
            self.assertEqual(rc, 1, out)
            self.assertIn(pub, r["leaks"], (author, out))
            self.assertEqual(r["registry"]["unregistered"], [])
            self.assertFalse(any(f"/issues/{pub}" in pth for _, pth, _ in self.writes_since(k)))

    def test_search_failure_fails_but_cases_still_counted(self):
        self.real_case(self.real_body())
        self.fail_when(lambda m, u: m == "GET" and "search=" in u)
        rc, out, r = self.cd()
        self.assertEqual((rc, r["count"]), (1, 1))
        self.assertIn("搜尋沒登錄的真實案件失敗", out)

    def test_search_issues_sends_search_param_only_for_real_countdown(self):
        urls = []
        orig = self.gl._raw

        def raw(method, url, headers, body):
            urls.append(url)
            return orig(method, url, headers, body)
        self.gl._raw = raw
        self.real_case(self.real_body())
        self.cd()
        self.assertEqual(len([u for u in urls if "search=dumpling-art14" in u]), 1)
        urls.clear()
        self.countdown(True)
        self.assertEqual([u for u in urls if "search=" in u], [])


class TestHelp(unittest.TestCase):
    def test_help_explains_project_vs_gitlab_project(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(art14.main(["--help"]), 0)
        t = out.getvalue()
        self.assertIn("--gitlab-project", t)
        self.assertIn("專案資料夾", t)
        self.assertIn("issues.py", t)


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
        # GitLab 的 fill-drill-aware 只新增紀錄留言、不改內文：內文裡的 /close 不會被重送
        rc, out = run(gl("fill-drill-aware", "--at", "2026-11-13T00:00:00Z"), self.gl)
        self.assertEqual(rc, 0, out)
        self.assertEqual([(m, p.rsplit("/", 1)[-1]) for m, p, _ in self.writes_since(k)], [("POST", "notes")])
        k = len(self.gl.writes)
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
