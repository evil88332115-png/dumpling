"""issues.py 的 GitLab 後端單元測試（GITLAB-PORT T-05）：不連網，用記憶體裡的假 GitLab（覆寫 GitLabApi._raw）。
只有假 API 的測試：沒有對真實 GitLab 驗證過。端點與欄位的依據是官方文件（見 issues.py 的 GitLab 區塊註解）。測資全部合成。"""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
import urllib.parse

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import issues  # noqa: E402

PROJ = "7"
BASE = "https://gitlab.example.com/api/v4"
K1 = "a" * 64
K2 = "b" * 64
TOKEN = "glpat-SECRETTOKEN0123456789"


class FakeGitLab(issues.GitLabApi):
    def __init__(self, page=100, next_mode="header", **kw):
        self.now = 0.0
        super().__init__(base=BASE, token=TOKEN, sleep=self._sleep, clock=lambda: self.now, wall=lambda: 1000, **kw)
        self.issues, self.labels, self.notes = {}, {}, {}
        self.n, self.tick, self.page, self.next_mode = 0, 0, page, next_mode
        self.writes, self.sleeps, self.requests, self.headers_seen, self.creates = [], [], [], [], []
        self.script = []

    def _sleep(self, d):
        self.sleeps.append(d)
        self.now += d

    def _ts(self):
        self.tick += 1
        return "2026-01-01T00:00:%02d.000Z" % self.tick

    def add_issue(self, description, labels, state="opened", title="t"):
        self.n += 1
        self.issues[self.n] = {"id": 1000 + self.n, "iid": self.n, "title": title, "description": description, "state": state,
                               "labels": list(labels), "updated_at": self._ts(), "confidential": True}
        return self.n

    edits_confidential = None
    create_confidential_reply = None     # 測試用：讓伺服器回應的 confidential 跟請求不同（模擬參數被忽略）

    def _raw(self, method, url, headers, body):
        if self.edits_confidential is None:
            self.edits_confidential = []
        self.headers_seen.append(headers)
        u = urllib.parse.urlsplit(url)
        q = urllib.parse.parse_qs(u.query)
        self.requests.append((method, u.path))
        if self.script:
            return self.script.pop(0)
        if method != "GET":
            self.writes.append((self.now, method, u.path))
        data = json.loads(body) if body else None
        pre = "/api/v4/projects/%s/" % PROJ
        if not u.path.startswith(pre):
            return 404, {}, b'{"message":"404 Project Not Found"}'
        tail = u.path[len(pre):].split("/")
        if tail == ["issues"] and method == "GET":
            lab, st = q["labels"][0], q.get("state", ["all"])[0]
            rows = [i for i in self.issues.values() if lab in i["labels"] and (st == "all" or i["state"] == st)]
            return self._page(rows, q, u.path)
        if tail == ["labels"] and method == "GET":
            return self._page([{"name": n} for n in self.labels], q, u.path)
        if tail == ["labels"] and method == "POST":
            assert data["color"].startswith("#") and len(data["color"]) == 7, data
            self.labels[data["name"]] = data["color"]
            return 201, {}, b"{}"
        if tail == ["issues"] and method == "POST":
            self.creates.append(data)
            names = data["labels"].split(",") if data["labels"] else []
            for l in names:
                assert l in self.labels, "標籤沒先建立"
            num = self.add_issue(data["description"], names, title=data["title"])
            self.issues[num]["confidential"] = data.get("confidential", False)
            if self.create_confidential_reply is not None:
                self.issues[num]["confidential"] = self.create_confidential_reply
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
                    self.edits_confidential.append(v)
                    i["confidential"] = v
                else:
                    raise AssertionError("不認得的欄位 " + k)
            i["updated_at"] = self._ts()
            return 200, {}, json.dumps(i).encode()
        if len(tail) == 3 and tail[0] == "issues" and tail[2] == "notes" and method == "POST":
            self.notes.setdefault(int(tail[1]), []).append(data["body"])
            self.issues[int(tail[1])]["updated_at"] = self._ts()
            return 201, {}, b"{}"
        return 404, {}, b'{"message":"404 Not Found"}'

    def _page(self, rows, q, path):
        p = int(q.get("page", ["1"])[0])
        chunk = rows[(p - 1) * self.page:p * self.page]
        h = {}
        if p * self.page < len(rows):
            nq = {k: v[0] for k, v in q.items()}
            nq["page"] = p + 1
            if self.next_mode == "header":
                h["x-next-page"] = str(p + 1)
            else:
                h["link"] = '<https://gitlab.example.com%s?%s>; rel="next"' % (path, urllib.parse.urlencode(nq))
        else:
            h["x-next-page"] = ""
        return 200, h, json.dumps(chunk).encode()


def mark(key, mode="real"):
    return f"<!-- dumpling-watch key={key} mode={mode} -->\nbody"


def run(argv, api):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        rc = issues.main(argv, api=api)
    return rc, out.getvalue()


class Base(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.dir = self._td.name
        self.addCleanup(self._td.cleanup)
        self.gl = FakeGitLab()

    def plan(self, actions, state=None, base=None, mode="real", name="plan.json", **extra):
        p = {"schema": issues.PLAN_SCHEMA, "mode": mode, "generated_at": "2026-01-02T00:00:00Z",
             "state_base": base, "state": state if state is not None else {"schema": 1, "matches": {}, "runs": []},
             "actions": actions, "status": "OK", "detail": ""}
        p.update(extra)
        path = os.path.join(self.dir, name)
        with open(path, "w") as f:
            json.dump(p, f)
        return path

    def argv(self, cmd, *extra):
        return [cmd, "--backend", "gitlab", "--gitlab-url", BASE, "--project", PROJ, *extra]

    def apply(self, path, *extra):
        return run(self.argv("apply", "--confidential", "--plan", path, *extra), self.gl)

    def open_act(self, key=K1, labels=("kev",), op="open", body="內容"):
        return {"op": op, "key": key, "title": "CVE-2026-0001 於 demo", "body": body, "labels": list(labels)}

    def names(self, i):
        return i["labels"]


class TestReadState(Base):
    def read(self, mode="real"):
        out = os.path.join(self.dir, "st")
        rc, so = run(self.argv("read-state", "--mode", mode, "--out", out), self.gl)
        return rc, so, out

    def test_no_state(self):
        self.gl.add_issue(mark(K1), ["dumpling-watch"])
        rc, so, out = self.read()
        self.assertEqual(rc, 0, so)
        with open(os.path.join(out, "state-base.json")) as f:
            b = json.load(f)
        self.assertEqual((b["issue"], b["watch_issues"], b["watch_keys"]), (None, 1, [K1]))
        self.assertFalse(os.path.exists(os.path.join(out, "state.json")))

    def test_with_state_maps_fields(self):
        st = {"schema": 1, "matches": {"x": 1}}
        n = self.gl.add_issue(issues.encode_state(st, "real", "s"), ["watch-state"])
        rc, so, out = self.read()
        self.assertEqual(rc, 0, so)
        with open(os.path.join(out, "state.json")) as f:
            self.assertEqual(json.load(f), st)
        with open(os.path.join(out, "state-base.json")) as f:
            b = json.load(f)
        self.assertEqual(b["issue"], n)                       # number ↔ iid
        self.assertEqual(b["updated_at"], self.gl.issues[n]["updated_at"])
        self.assertEqual(b["body_sha256"], issues.sha(self.gl.issues[n]["description"]))   # body ↔ description

    def test_state_filter_open_closed_mapping(self):
        self.gl.add_issue(mark(K1), ["dumpling-watch"], state="closed")
        idx = issues.watch_index(self.gl, PROJ, [])
        self.assertEqual(idx[K1][0]["state"], "closed")
        self.assertEqual(len(self.gl.list_issues(PROJ, "dumpling-watch", "open")), 0)
        self.assertEqual(len(self.gl.list_issues(PROJ, "dumpling-watch", "closed")), 1)

    def test_pagination_x_next_page_and_link(self):
        for mode in ("header", "link"):
            gl = FakeGitLab(page=2, next_mode=mode)
            for k in range(5):
                gl.add_issue(mark("%064x" % k), ["dumpling-watch"])
            self.assertEqual(len(gl.list_issues(PROJ, "dumpling-watch")), 5, mode)
            self.assertEqual(sum(1 for m, _ in gl.requests if m == "GET"), 3, mode)

    def test_two_state_issues_fail(self):
        self.gl.add_issue(issues.encode_state({"schema": 1}, "real", "s"), ["watch-state"])
        self.gl.add_issue(issues.encode_state({"schema": 1}, "real", "s"), ["watch-state"])
        self.assertEqual(self.read()[0], 1)


class TestApply(Base):
    def test_open_and_state_created_all_confidential(self):
        rc, out = self.apply(self.plan([self.open_act(), self.open_act(key=K2)]), "--mode", "real")
        self.assertEqual(rc, 0, out)
        self.assertEqual(len(self.gl.creates), 3)               # 2 個監控 Issue＋狀態 Issue
        for c in self.gl.creates:
            self.assertIs(c["confidential"], True)              # 每一次建立都帶 confidential=true
        self.assertTrue(all(i["confidential"] is True for i in self.gl.issues.values()))
        self.assertTrue(all(isinstance(c["labels"], str) for c in self.gl.creates))   # 逗號字串
        first = self.gl.issues[1]
        self.assertTrue(first["description"].startswith(f"<!-- dumpling-watch key={K1} mode=real -->"))
        self.assertEqual(sorted(first["labels"]), ["dumpling-watch", "kev"])
        self.assertEqual(self.gl.writes[-1][2].rsplit("/", 1)[-1], "issues")   # 狀態最後寫
        self.assertEqual(self.gl.labels["kev"], "#d73a4a")

    def test_confidential_cannot_be_turned_off(self):
        # 沒給 --confidential 也一樣 confidential；API 層沒有任何參數可以關掉
        rc, _ = run(self.argv("apply", "--plan", self.plan([self.open_act()])), self.gl)
        self.assertEqual(rc, 0)
        self.assertTrue(self.gl.creates and all(c["confidential"] is True for c in self.gl.creates))
        self.gl.create_issue(PROJ, "t", "b", [])
        self.assertIs(self.gl.creates[-1]["confidential"], True)

    def test_open_idempotent_and_comment(self):
        self.apply(self.plan([self.open_act()]), "--mode", "real")
        cur = self.gl.issues[2]
        base = {"issue": 2, "updated_at": cur["updated_at"], "body_sha256": issues.sha(cur["description"])}
        acts = [self.open_act(), {"op": "comment", "key": K1, "body": "新增留言"}]
        rc, out = self.apply(self.plan(acts, base=base), "--mode", "real")
        self.assertEqual(rc, 0, out)
        self.assertEqual(len(self.gl.issues), 2)
        self.assertEqual(self.gl.notes[1], ["新增留言"])

    def test_open_if_closed(self):
        self.gl.add_issue(mark(K1), ["dumpling-watch", "kev"], state="closed")
        rc, out = self.apply(self.plan([self.open_act(op="open_if_closed")]), "--mode", "real")
        self.assertEqual(rc, 0, out)
        self.assertEqual(len(self.gl.issues), 3)                # 新開一個＋狀態 Issue
        self.assertEqual(self.gl.issues[2]["state"], "opened")
        # 已有開著的：改留言
        rc, out = self.apply(self.plan([self.open_act(op="open_if_closed", body="再來一次")],
                                       base={"issue": 3, "updated_at": self.gl.issues[3]["updated_at"],
                                             "body_sha256": issues.sha(self.gl.issues[3]["description"])}), "--mode", "real")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.gl.notes[2], ["再來一次"])

    def test_comment_reopen_sends_state_event_only_when_closed(self):
        self.gl.add_issue(mark(K1), ["dumpling-watch"], state="closed")
        act = {"op": "comment", "key": K1, "body": "留言", "reopen_if_closed": True}
        self.assertEqual(self.apply(self.plan([act]), "--mode", "real")[0], 0)
        self.assertEqual(self.gl.issues[1]["state"], "opened")
        self.assertEqual(self.gl.notes[1], ["留言"])

    def test_state_update_does_not_send_reopen_for_open_issue(self):
        st = {"schema": 1, "matches": {}, "runs": []}
        n = self.gl.add_issue(issues.encode_state(st, "real", "s"), ["watch-state"])
        cur = self.gl.issues[n]
        base = {"issue": n, "updated_at": cur["updated_at"], "body_sha256": issues.sha(cur["description"])}
        sent = []
        orig = self.gl.request

        def spy(method, path, payload=None):
            sent.append((method, payload))
            return orig(method, path, payload)
        self.gl.request = spy
        self.assertEqual(self.apply(self.plan([], base=base), "--mode", "real")[0], 0)
        puts = [p for m, p in sent if m == "PUT"]
        self.assertEqual(len(puts), 1)
        self.assertNotIn("state_event", puts[0])
        self.assertIn("description", puts[0])
        self.assertIs(puts[0]["confidential"], True)        # 改既有的狀態 Issue 也確保 confidential（驗證 S4）

    def test_lock_mismatches(self):
        st = {"schema": 1, "matches": {}, "runs": []}
        n = self.gl.add_issue(issues.encode_state(st, "real", "s"), ["watch-state"])
        cur = self.gl.issues[n]
        good = {"issue": n, "updated_at": cur["updated_at"], "body_sha256": issues.sha(cur["description"])}
        for bad in (dict(good, updated_at="2020-01-01T00:00:00.000Z"), dict(good, body_sha256="0" * 64), dict(good, issue=99), None):
            rc, out = self.apply(self.plan([self.open_act()], base=bad), "--mode", "real")
            self.assertEqual(rc, 1, bad)
            self.assertIn("樂觀鎖", out)
        self.assertEqual(self.gl.creates, [])
        self.assertEqual(self.gl.notes, {})

    def test_stateless_plan_opens_support_issue_without_state(self):
        mk = "<!-- dumpling-support key=%s mode=real -->" % K1
        act = {"op": "open", "key": K1, "title": "支援期限", "body": "x", "labels": ["support-period"]}
        p = {"schema": issues.PLAN_SCHEMA, "mode": "real", "generated_at": "t", "state_base": None, "state": None,
             "stateless": True, "actions": [act], "status": "OK", "detail": ""}
        path = os.path.join(self.dir, "s.json")
        with open(path, "w") as f:
            json.dump(p, f)
        rc, out = self.apply(path, "--mode", "real")
        self.assertEqual(rc, 0, out)
        self.assertEqual(len(self.gl.issues), 1)
        self.assertTrue(self.gl.issues[1]["description"].startswith(mk))
        self.assertIs(self.gl.creates[0]["confidential"], True)

    def test_dry_run_writes_nothing(self):
        rc, out = self.apply(self.plan([self.open_act()]), "--mode", "real", "--dry-run")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.gl.writes, [])
        self.assertEqual(self.gl.issues, {})
        self.assertIn("would_open", out)

    def test_drill_labels(self):
        self.assertEqual(self.apply(self.plan([self.open_act()], mode="drill"), "--mode", "drill")[0], 0)
        self.assertIn("drill", self.gl.issues[1]["labels"])
        self.assertIn("watch-state-drill", self.gl.issues[2]["labels"])

    def test_quick_action_lines_refused(self):
        rc, out = self.apply(self.plan([self.open_act(body="說明\n/close\n")]), "--mode", "real")
        self.assertEqual(rc, 1)
        self.assertIn("quick action", out)
        self.assertEqual(self.gl.creates, [])
        # 路徑文字（/ 開頭但後面接 / 或其他字元）不算
        self.assertEqual(issues.GitLabApi._text("see /usr/lib/x and a/b", "x"), "see /usr/lib/x and a/b")

    def test_comma_in_label_refused(self):
        with self.assertRaises(issues.Fail):
            self.gl.create_issue(PROJ, "t", "b", ["a,b"])
        self.assertEqual([r for r in self.gl.requests if r[0] != "GET"], [])     # 逗號標籤：什麼都沒送（驗證 S2）
        with self.assertRaises(issues.Fail):
            self.gl.edit_issue(PROJ, 1, labels=["x", "a,b"])
        self.assertEqual([r for r in self.gl.requests if r[0] != "GET"], [])

    def test_quick_action_checked_before_any_write_and_in_dry_run(self):
        # 驗證 F1：第二個動作才有 quick action 行 → 第一個也不能先寫；dry-run 也要擋
        acts = [self.open_act(), self.open_act(key="b" * 64, body="說明\n  /close\n")]       # 縮排的也擋（驗證 S1）
        for extra in ((), ("--dry-run",)):
            rc, out = self.apply(self.plan(acts), "--mode", "real", *extra)
            self.assertEqual(rc, 1, (extra, out))
            self.assertIn("什麼都沒寫", out)
            self.assertEqual(self.gl.writes, [])

    def test_state_body_never_has_quick_action_line(self):
        # 驗證 F1：標準 base64 的行可能以 / 開頭（字母表有 /）。找一個這樣的狀態，GitLab 版寫出來的內文不能有 quick action 行、而且讀得回來
        # 驗證代理實測：隨機狀態約 1.5e-4 會中。這裡不靠碰運氣找，改測保證本身：URL-safe 的區塊裡根本沒有 /
        import random
        r = random.Random(7)
        for n in range(1500):
            st = {"schema": 1, "matches": {"k%d" % n: "".join(chr(r.randint(32, 0x2FFF)) for _ in range(r.randint(1, 300)))}, "runs": []}
            body = issues.encode_state(st, "real", "s", urlsafe=True)
            self.assertNotIn("/", body.split("```")[1])
            self.assertIsNone(issues.QUICK_ACTION_RE.search(body))
            self.assertEqual(issues.decode_state(body, "real"), st)
        hit = st
        self.assertEqual(issues.decode_state(issues.encode_state(hit, "real", "s"), "real"), hit)      # GitHub 格式（標準 base64）照舊讀得回來
        # 標準 base64 的行確實可能被當成 quick action（以 / 開頭、後面是字母）
        self.assertIsNotNone(issues.QUICK_ACTION_RE.search("```\nH4sIAAAA\n/AbCd\n```"))
        with self.assertRaises(issues.Fail):          # 兩種字母表混用的內文不收
            issues.decode_state("<!-- dumpling-watch-state mode=real schema=1 -->\ns\n\n```\nH4s+IA-A\n```\n", "real")
        # 實際 apply：GitLab 寫的狀態 Issue 一定是 URL-safe（挑一個標準 base64 會有 / 的狀態，兩種寫法才分得出來）
        hit = next(x for x in ({"schema": 1, "matches": {"k": "v%d" % i}, "runs": []} for i in range(5000))
                   if "/" in issues.encode_state(x, "real", "s").split("```")[1])
        rc, out = self.apply(self.plan([], state=hit), "--mode", "real")
        self.assertEqual(rc, 0, out)
        st_issue = [i for i in self.gl.issues.values() if "watch-state" in i["labels"]][0]
        summary = "最後執行：2026-01-02T00:00:00Z；比對數：1"
        self.assertEqual(st_issue["description"], issues.encode_state(hit, "real", summary, urlsafe=True))
        self.assertNotIn("/", st_issue["description"].split("```")[1])

    def test_create_must_come_back_confidential_and_edits_keep_it(self):
        self.gl.create_confidential_reply = False      # 伺服器忽略了 confidential
        rc, out = self.apply(self.plan([self.open_act()]), "--mode", "real")
        self.assertEqual(rc, 1)
        self.assertIn("不是 confidential", out)
        self.gl.create_confidential_reply = None
        self.gl.edit_issue(PROJ, 1, body="x")
        self.assertEqual(self.gl.edits_confidential[-1], True)     # 改既有 Issue 也送 confidential（驗證 S4）


class TestCloseDrill(Base):
    def test_only_drill_and_swaps_labels(self):
        a = self.gl.add_issue(mark(K1, "drill"), ["dumpling-watch", "drill"])
        b = self.gl.add_issue(mark(K2), ["dumpling-watch"])                                  # real：不碰
        c = self.gl.add_issue(issues.encode_state({"schema": 1}, "drill", "s"), ["watch-state-drill", "drill"])
        rc, out = run(self.argv("close-drill", "--confidential"), self.gl)
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.gl.issues[a]["state"], "closed")
        self.assertEqual(self.gl.issues[c]["state"], "closed")
        self.assertEqual(self.gl.issues[b]["state"], "opened")
        self.assertIn("dumpling-watch-drill-done", self.gl.issues[a]["labels"])
        self.assertNotIn("dumpling-watch", self.gl.issues[a]["labels"])
        self.assertEqual(self.gl.issues[b]["labels"], ["dumpling-watch"])
        self.assertEqual(self.gl.notes[a], ["演練結束，自動關閉"])


class TestTransport(Base):
    def test_headers_token_only_in_private_token(self):
        self.apply(self.plan([self.open_act()]), "--mode", "real")
        for h in self.gl.headers_seen:
            self.assertEqual(h["PRIVATE-TOKEN"], TOKEN)
            self.assertNotIn("Authorization", h)
            self.assertTrue(all(TOKEN not in v for k, v in h.items() if k != "PRIVATE-TOKEN"))
        self.assertTrue(all(TOKEN not in p for _, p in self.gl.requests))

    def test_token_not_in_output_or_errors(self):
        self.gl.script = [(500, {}, ('{"message":"boom %s"}' % TOKEN).encode())]
        rc, out = run(self.argv("close-drill"), self.gl)
        self.assertEqual(rc, 1)
        self.assertNotIn(TOKEN, out)
        self.assertIn("***", out)

    def test_token_from_env_not_argv(self):
        old = os.environ.get("GITLAB_TOKEN")
        os.environ["GITLAB_TOKEN"] = TOKEN
        try:
            self.assertEqual(issues.GitLabApi(base=BASE).token, TOKEN)
        finally:
            if old is None:
                del os.environ["GITLAB_TOKEN"]
            else:
                os.environ["GITLAB_TOKEN"] = old
        rc, out = run(self.argv("close-drill", "--token", TOKEN), None)
        self.assertEqual(rc, 64)

    def test_redirect_is_error(self):
        self.gl.script = [(302, {"location": "https://evil.example.test/x"}, b"")]
        rc, out = run(self.argv("close-drill"), self.gl)
        self.assertEqual(rc, 1)
        self.assertIn("轉址", out)
        self.assertEqual(len(self.gl.requests), 1)

    def test_foreign_next_link_refused(self):
        self.gl.script = [(200, {"link": '<https://evil.example.test/api/v4/projects/7/issues?page=2>; rel="next"'}, b"[]")]
        rc, out = run(self.argv("close-drill"), self.gl)
        self.assertEqual(rc, 1)
        self.assertIn("別的主機", out)
        self.assertEqual(len(self.gl.requests), 1)

    def test_other_host_url_refused(self):
        with self.assertRaises(issues.Fail):
            self.gl.request("GET", "https://evil.example.test/api/v4/projects/7/issues")
        self.assertEqual(self.gl.requests, [])

    def test_http_only_loopback_and_api_v4_suffix(self):
        with self.assertRaises(issues.Fail):
            issues.GitLabApi(base="http://gitlab.example.com/api/v4", token="t")
        issues.GitLabApi(base="http://127.0.0.1:9/api/v4", token="t")
        with self.assertRaises(issues.Fail):
            issues.GitLabApi(base="https://gitlab.example.com", token="t")

    def test_rate_limit_429_retry_after_and_reset(self):
        self.gl.script = [(429, {"retry-after": "5"}, b"Retry later")]
        rc, _ = run(self.argv("close-drill"), self.gl)
        self.assertEqual(rc, 0)
        self.assertEqual(self.gl.sleeps, [5])
        gl = FakeGitLab()
        gl.script = [(429, {"ratelimit-reset": "1007"}, b"Retry later")]
        self.assertEqual(run(self.argv("close-drill"), gl)[0], 0)
        self.assertEqual(gl.sleeps, [7])

    def test_rate_limit_gives_up_and_403_not_retried(self):
        self.gl.script = [(429, {"retry-after": "1"}, b"")] * 4
        self.assertEqual(run(self.argv("close-drill"), self.gl)[0], 1)
        gl = FakeGitLab()
        gl.script = [(403, {}, b'{"message":"rate limit"}')]
        self.assertEqual(run(self.argv("close-drill"), gl)[0], 1)
        self.assertEqual(gl.sleeps, [])

    def test_write_spacing(self):
        self.apply(self.plan([self.open_act(), self.open_act(key=K2)]), "--mode", "real")
        ts = [t for t, _, _ in self.gl.writes]
        self.assertTrue(all(b - a >= issues.WRITE_GAP for a, b in zip(ts, ts[1:])))

    def test_oversize_response(self):
        self.gl.script = [(200, {}, b"x" * (issues.MAX_RESPONSE + 1))]
        self.assertEqual(run(self.argv("close-drill"), self.gl)[0], 1)

    def test_malformed_issue_response(self):
        self.gl.script = [(200, {}, b'[{"number": 1}]')]
        self.assertEqual(run(self.argv("close-drill"), self.gl)[0], 1)


class TestCli(unittest.TestCase):
    def rc(self, argv):
        return run(argv, FakeGitLab())[0]

    def test_usage_errors_exit_64(self):
        out = os.path.join(tempfile.gettempdir(), "x")
        self.assertEqual(self.rc(["close-drill", "--backend", "gitlab", "--gitlab-url", BASE]), 64)             # 缺 --project
        self.assertEqual(self.rc(["close-drill", "--backend", "gitlab", "--project", "7"]), 64)                 # 缺 --gitlab-url
        self.assertEqual(self.rc(["close-drill", "--backend", "gitlab", "--gitlab-url", BASE, "--project", "a/b"]), 64)
        self.assertEqual(self.rc(["close-drill", "--backend", "gitlab", "--gitlab-url", BASE, "--project", "7", "--repo", "o/r"]), 64)
        self.assertEqual(self.rc(["close-drill", "--gitlab-url", BASE, "--repo", "o/r"]), 64)                   # github 不收 gitlab 旗標
        self.assertEqual(self.rc(["close-drill", "--backend", "other", "--repo", "o/r"]), 64)
        self.assertEqual(self.rc(["close-drill"]), 64)                                                           # github 仍要 --repo

    def test_help_mentions_backend(self):
        rc, out = run(["--help"], None)
        self.assertEqual(rc, 0)
        self.assertIn("--backend", out)

    def test_bad_gitlab_url_is_usage_error(self):
        # 驗證 S3：跟 collect.py 一樣在連線前擋下，結束碼 64
        for u in ("http://gitlab.example.com/api/v4", "https://u:p" + "@" + "gitlab.example.com/api/v4", "https://gitlab.example.com/api/v4?x=1",
                  "https://gitlab.example.com/api/v4#f", "https://gitlab.example.com/api", "ftp://gitlab.example.com/api/v4"):
            rc, out = run(["close-drill", "--backend", "gitlab", "--gitlab-url", u, "--project", "7"], None)
            self.assertEqual(rc, 64, u)
            self.assertIn("WATCH-ISSUES\tFAIL", out)
        self.assertIsNone(issues.gitlab_url_problem("https://gitlab.example.com:8443/gitlab/api/v4"))
        self.assertIsNone(issues.gitlab_url_problem("http://127.0.0.1:9/api/v4"))


if __name__ == "__main__":
    unittest.main()
