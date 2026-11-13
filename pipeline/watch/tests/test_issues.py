"""issues.py 單元測試：不連網，用記憶體裡的假 GitHub（覆寫 Api._raw）。測資全部合成。"""
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

REPO = "octo/demo"
K1 = "a" * 64
K2 = "b" * 64
K3 = "c" * 64
TOKEN = "ghp_SECRETTOKEN0123456789"
LOCAL_PATH = "/" + "home" + "/alice/secret/file"  # 執行時才組出本機路徑樣式，原始碼不含字面值


class FakeGitHub(issues.Api):
    def __init__(self, page=100, **kw):
        self.now = 0.0
        super().__init__(base="https://api.example.test", token=TOKEN, sleep=self._sleep, clock=lambda: self.now,
                         wall=lambda: 1000, **kw)
        self.issues, self.labels, self.comments = {}, {}, {}
        self.n, self.tick, self.page = 0, 0, page
        self.writes, self.sleeps, self.requests, self.headers_seen = [], [], [], []
        self.script = []  # 預先排好的回應 (status, headers, body)

    def _sleep(self, d):
        self.sleeps.append(d)
        self.now += d

    def _ts(self):
        self.tick += 1
        return "2026-01-01T00:00:%02dZ" % self.tick

    def add_issue(self, body, labels, state="open", pr=False, title="t"):
        self.n += 1
        i = {"number": self.n, "title": title, "body": body, "state": state, "updated_at": self._ts(),
             "labels": [{"name": x} for x in labels]}
        if pr:
            i["pull_request"] = {}
        self.issues[self.n] = i
        return self.n

    def _raw(self, method, url, headers, body):
        self.headers_seen.append(headers)
        u = urllib.parse.urlsplit(url)
        q = urllib.parse.parse_qs(u.query)
        self.requests.append((method, u.path))
        if self.script:
            return self.script.pop(0)
        if method != "GET":
            self.writes.append((self.now, method, u.path))
        data = json.loads(body) if body else None
        parts = u.path.split("/")  # '', repos, o, r, ...
        tail = parts[4:]
        if tail == ["issues"] and method == "GET":
            lab, st = q["labels"][0], q.get("state", ["open"])[0]
            rows = [i for i in self.issues.values() if any(l["name"] == lab for l in i["labels"])
                    and (st == "all" or i["state"] == st)]
            return self._page(rows, q, url)
        if tail == ["labels"] and method == "GET":
            return self._page([{"name": n} for n in self.labels], q, url)
        if tail == ["labels"] and method == "POST":
            self.labels[data["name"]] = data["color"]
            return 201, {}, b"{}"
        if tail == ["issues"] and method == "POST":
            for l in data["labels"]:
                assert l in self.labels, "標籤沒先建立"
            num = self.add_issue(data["body"], data["labels"], title=data["title"])
            return 201, {}, json.dumps(self.issues[num]).encode()
        if len(tail) == 2 and tail[0] == "issues" and method == "PATCH":
            i = self.issues[int(tail[1])]
            i.update({k: v for k, v in data.items() if k != "labels"})
            if "labels" in data:
                i["labels"] = [{"name": x} for x in data["labels"]]
            i["updated_at"] = self._ts()
            return 200, {}, json.dumps(i).encode()
        if len(tail) == 3 and tail[2] == "comments" and method == "POST":
            self.comments.setdefault(int(tail[1]), []).append(data["body"])
            self.issues[int(tail[1])]["updated_at"] = self._ts()
            return 201, {}, b"{}"
        return 404, {}, b'{"message":"nf"}'

    def _page(self, rows, q, url):
        p = int(q.get("page", ["1"])[0])
        chunk = rows[(p - 1) * self.page:p * self.page]
        h = {}
        if p * self.page < len(rows):
            nq = {k: v[0] for k, v in q.items()}
            nq["page"] = p + 1
            h["link"] = '<https://api.example.test%s?%s>; rel="next"' % (urllib.parse.urlsplit(url).path, urllib.parse.urlencode(nq))
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
        self.gh = FakeGitHub()

    def plan(self, actions, state=None, base=None, mode="real", name="plan.json"):
        p = {"schema": issues.PLAN_SCHEMA, "mode": mode, "generated_at": "2026-01-02T00:00:00Z",
             "state_base": base, "state": state if state is not None else {"schema": 1, "matches": {}, "runs": []},
             "actions": actions, "status": "OK", "detail": ""}
        path = os.path.join(self.dir, name)
        with open(path, "w") as f:
            json.dump(p, f)
        return path

    def apply(self, path, *extra):
        return run(["apply", "--repo", REPO, "--plan", path, *extra], self.gh)

    def open_act(self, key=K1, labels=("kev",), op="open"):
        return {"op": op, "key": key, "title": "CVE-2026-0001 於 demo", "body": "內容", "labels": list(labels)}


class TestPlanHardening(Base):
    """預驗第 7 項：notify 對 plan 的交叉核對。"""

    def test_mode_mismatch_fails_and_writes_nothing(self):
        rc, _ = self.apply(self.plan([self.open_act()], mode="drill"), "--mode", "real")
        self.assertEqual(rc, 1)
        self.assertEqual(self.gh.issues if isinstance(self.gh.issues, list) else list(self.gh.issues), [])

    def test_label_not_in_whitelist_fails(self):
        rc, _ = self.apply(self.plan([self.open_act(labels=("kev", "anything-else"))]), "--mode", "real")
        self.assertEqual(rc, 1)

    def test_too_many_actions_fails(self):
        acts = [self.open_act(key=("%064x" % i)) for i in range(issues.MAX_ACTIONS + 1)]
        rc, _ = self.apply(self.plan(acts), "--mode", "real")
        self.assertEqual(rc, 1)

    def test_state_mode_mismatch_fails(self):
        rc, _ = self.apply(self.plan([], state={"schema": 1, "matches": {}, "dumpling": {"mode": "drill"}}), "--mode", "real")
        self.assertEqual(rc, 1)

    def test_http_only_loopback(self):
        with self.assertRaises(issues.Fail):
            issues.Api(base="http://api.example.com", token="t")
        issues.Api(base="http://127.0.0.1:9", token="t")


class TestMarker(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(issues.parse_marker(mark(K1, "drill")), (K1, "drill"))

    def test_invalid(self):
        for b in ["<!-- dumpling-watch key=%s mode=real -->" % ("A" * 64),
                  "<!-- dumpling-watch key=%s mode=real -->" % ("a" * 63),
                  "<!-- dumpling-watch key=%s mode=other -->" % K1,
                  "x\n" + mark(K1), "", None,
                  "<!-- dumpling-watch key=%s mode=real --> extra" % K1,
                  " <!-- dumpling-watch key=%s mode=real -->" % K1]:
            self.assertIsNone(issues.parse_marker(b), b)


class TestListing(Base):
    def test_pagination_and_pr_filter(self):
        self.gh.page = 2
        for k in (K1, K2, K3):
            self.gh.add_issue(mark(k), ["dumpling-watch"])
        self.gh.add_issue(mark("d" * 64), ["dumpling-watch"], pr=True)
        probs = []
        idx = issues.watch_index(self.gh, REPO, probs)
        self.assertEqual(set(idx), {K1, K2, K3})
        self.assertGreaterEqual(sum(1 for r in self.gh.requests if r[1].endswith("/issues")), 2)

    def test_bad_marker_is_problem(self):
        self.gh.add_issue("no marker", ["dumpling-watch"])
        probs = []
        self.assertEqual(issues.watch_index(self.gh, REPO, probs), {})
        self.assertEqual(len(probs), 1)

    def test_duplicate_key_pick_and_problem(self):
        a = self.gh.add_issue(mark(K1), ["dumpling-watch"], state="closed")
        b = self.gh.add_issue(mark(K1), ["dumpling-watch"])
        c = self.gh.add_issue(mark(K1), ["dumpling-watch"])
        probs = []
        idx = issues.watch_index(self.gh, REPO, probs)
        self.assertEqual(issues.pick(idx[K1])["number"], c)
        self.assertTrue(probs)
        self.gh.issues[b]["state"] = self.gh.issues[c]["state"] = "closed"
        idx = issues.watch_index(self.gh, REPO, [])
        self.assertEqual(issues.pick(idx[K1])["number"], c)
        self.gh.issues[a]["state"] = "open"
        idx = issues.watch_index(self.gh, REPO, [])
        self.assertEqual(issues.pick(idx[K1])["number"], a)


class TestStateCodec(Base):
    def test_roundtrip_and_deterministic(self):
        st = {"b": 1, "a": "中文", "n": [1, 2]}
        b1 = issues.encode_state(st, "real", "摘要")
        self.assertEqual(b1, issues.encode_state(dict(reversed(list(st.items()))), "real", "摘要"))
        self.assertEqual(issues.decode_state(b1, "real"), st)
        self.assertTrue(all(len(l) <= 76 for l in b1.split("```")[1].strip().splitlines()))

    def test_limit(self):
        import random
        r = random.Random(1)
        big = {"x": "".join(r.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(80000))}
        with self.assertRaises(issues.Fail):
            issues.encode_state(big, "real", "s")
        ok = {"x": "".join(r.choice("0123456789abcdef") for _ in range(30000))}
        self.assertLessEqual(len(issues.encode_state(ok, "real", "s")), issues.MAX_BODY)

    def test_decode_failures(self):
        good = issues.encode_state({"a": 1}, "real", "s")
        for body in [good.replace("```\n", "```\n@@@", 1), good.replace("mode=real", "mode=drill"),
                     "<!-- dumpling-watch-state mode=real schema=1 -->\nnone", None]:
            with self.assertRaises(issues.Fail):
                issues.decode_state(body, "real")
        import base64
        bad = "<!-- dumpling-watch-state mode=real schema=1 -->\n```\n%s\n```\n" % base64.b64encode(b"notgzip").decode()
        with self.assertRaises(issues.Fail):
            issues.decode_state(bad, "real")


class TestReadState(Base):
    def test_no_state(self):
        self.gh.add_issue(mark(K1), ["dumpling-watch"])
        self.gh.add_issue(mark(K2, "drill"), ["dumpling-watch", "drill"])
        rc, out = run(["read-state", "--repo", REPO, "--mode", "real", "--out", self.dir], self.gh)
        self.assertEqual(rc, 0, out)
        base = json.load(open(os.path.join(self.dir, "state-base.json")))
        self.assertEqual(base, {"issue": None, "updated_at": None, "body_sha256": None, "watch_issues": 1})
        self.assertFalse(os.path.exists(os.path.join(self.dir, "state.json")))

    def test_with_state(self):
        n = self.gh.add_issue(issues.encode_state({"k": 1}, "real", "s"), ["watch-state"])
        rc, out = run(["read-state", "--repo", REPO, "--mode", "real", "--out", self.dir], self.gh)
        self.assertEqual(rc, 0)
        self.assertEqual(json.load(open(os.path.join(self.dir, "state.json"))), {"k": 1})
        base = json.load(open(os.path.join(self.dir, "state-base.json")))
        self.assertEqual(base["issue"], n)
        self.assertEqual(base["body_sha256"], issues.sha(self.gh.issues[n]["body"]))
        self.assertTrue(out.splitlines()[-1].startswith("WATCH-ISSUES\tOK\t"))

    def test_corrupt_state_fails_without_state_json(self):
        self.gh.add_issue("<!-- dumpling-watch-state mode=real schema=1 -->\n```\n!!!\n```", ["watch-state"])
        stale = os.path.join(self.dir, "state.json")
        open(stale, "w").write("{}")
        rc, out = run(["read-state", "--repo", REPO, "--mode", "real", "--out", self.dir], self.gh)
        self.assertEqual(rc, 1)
        self.assertIn("WATCH-ISSUES\tFAIL\t", out.splitlines()[-1])

    def test_two_state_issues_fail(self):
        for _ in range(2):
            self.gh.add_issue(issues.encode_state({}, "real", "s"), ["watch-state"])
        rc, _ = run(["read-state", "--repo", REPO, "--mode", "real", "--out", self.dir], self.gh)
        self.assertEqual(rc, 1)
        self.assertFalse(os.path.exists(os.path.join(self.dir, "state-base.json")))

    def test_drill_state_label(self):
        self.gh.add_issue(issues.encode_state({"d": 1}, "drill", "s"), ["watch-state-drill", "drill"])
        self.gh.add_issue(issues.encode_state({"r": 1}, "real", "s"), ["watch-state"])
        rc, _ = run(["read-state", "--repo", REPO, "--mode", "drill", "--out", self.dir], self.gh)
        self.assertEqual(rc, 0)
        self.assertEqual(json.load(open(os.path.join(self.dir, "state.json"))), {"d": 1})


class TestApply(Base):
    def test_plan_validation(self):
        good = self.open_act()
        cases = [
            {"schema": "x"}, {"mode": "other"}, {"actions": [dict(good, op="zap")]},
            {"actions": [dict(good, key="A" * 64)]}, {"actions": [dict(good, key="a" * 10)]},
            {"state_base": {"issue": "1", "updated_at": "x", "body_sha256": "y"}},
        ]
        for c in cases:
            path = self.plan([good])
            p = json.load(open(path))
            p.update(c)
            json.dump(p, open(path, "w"))
            rc, out = self.apply(path)
            self.assertEqual(rc, 1, c)
        self.assertEqual(self.gh.writes, [])

    def test_open_and_state_created(self):
        rc, out = self.apply(self.plan([self.open_act()], state={"schema": 1, "matches": {"m": 1}}))
        self.assertEqual(rc, 0, out)
        iss = [i for i in self.gh.issues.values() if "dumpling-watch" in [l["name"] for l in i["labels"]]]
        self.assertEqual(len(iss), 1)
        self.assertEqual(iss[0]["body"].splitlines()[0], "<!-- dumpling-watch key=%s mode=real -->" % K1)
        self.assertEqual([l["name"] for l in iss[0]["labels"]], ["kev", "dumpling-watch"])
        st = [i for i in self.gh.issues.values() if i["labels"] == [{"name": "watch-state"}]]
        self.assertEqual(len(st), 1)
        self.assertEqual(issues.decode_state(st[0]["body"], "real"), {"schema": 1, "matches": {"m": 1}})
        self.assertEqual(self.gh.labels["kev"], "d73a4a")
        res = json.load(open(os.path.join(self.dir, "apply-result.json")))
        self.assertEqual(res["actions"][0]["result"], "opened")
        self.assertTrue(out.splitlines()[-1].startswith("WATCH-ISSUES\tOK\t"))

    def test_state_written_last_and_write_spacing(self):
        self.apply(self.plan([self.open_act(K1), self.open_act(K2)]))
        paths = [w[2] for w in self.gh.writes]
        self.assertEqual(paths[-1], f"/repos/{REPO}/issues")
        times = [w[0] for w in self.gh.writes]
        self.assertTrue(all(b - a >= 1.0 for a, b in zip(times, times[1:])), times)
        self.assertEqual(len(self.gh.issues), 3)

    def test_open_idempotent(self):
        p = self.plan([self.open_act()])
        self.apply(p)
        base = self._base()
        p2 = self.plan([self.open_act()], base=base)
        rc, _ = self.apply(p2)
        self.assertEqual(rc, 0)
        self.assertEqual(sum(1 for i in self.gh.issues.values() if "dumpling-watch" in self.names(i)), 1)
        res = json.load(open(os.path.join(self.dir, "apply-result.json")))
        self.assertEqual(res["actions"][0]["result"], "skipped")

    def names(self, i):
        return [l["name"] for l in i["labels"]]

    def _base(self):
        si = [i for i in self.gh.issues.values() if "watch-state" in self.names(i)][0]
        return {"issue": si["number"], "updated_at": si["updated_at"], "body_sha256": issues.sha(si["body"])}

    def test_lock_mismatches(self):
        self.apply(self.plan([]))
        base = self._base()
        before = len(self.gh.writes)
        for bad in [None, dict(base, issue=base["issue"] + 5), dict(base, updated_at="zzz"), dict(base, body_sha256="0" * 64)]:
            rc, out = self.apply(self.plan([self.open_act(K3)], base=bad))
            self.assertEqual(rc, 1, bad)
        self.assertEqual(len(self.gh.writes), before)
        # state_base 有值但現在沒有狀態 Issue
        gh2 = FakeGitHub()
        rc, _ = run(["apply", "--repo", REPO, "--plan", self.plan([], base=base), ], gh2)
        self.assertEqual(rc, 1)
        self.assertEqual(gh2.writes, [])

    def test_publiccheck_blocks_everything(self):
        bad = dict(self.open_act(K2), body="路徑 " + LOCAL_PATH)
        rc, out = self.apply(self.plan([self.open_act(K1), bad]))
        self.assertEqual(rc, 1)
        self.assertEqual(self.gh.writes, [])
        self.assertEqual(self.gh.issues, {})
        rc, _ = self.apply(self.plan([self.open_act(K1)], state={"schema": 1, "p": LOCAL_PATH}))
        self.assertEqual(rc, 1)
        self.assertEqual(self.gh.writes, [])

    def test_comment_missing_is_problem_not_fail(self):
        a = {"op": "comment", "key": K1, "body": "再次出現", "reopen_if_closed": False}
        rc, out = self.apply(self.plan([a]))
        self.assertEqual(rc, 0, out)
        res = json.load(open(os.path.join(self.dir, "apply-result.json")))
        self.assertEqual(res["actions"][0]["result"], "problem")
        self.assertTrue(res["problems"])

    def test_comment_and_reopen(self):
        n = self.gh.add_issue(mark(K1), ["dumpling-watch"], state="closed")
        a = {"op": "comment", "key": K1, "body": "再次出現", "reopen_if_closed": False}
        self.apply(self.plan([a]))
        self.assertEqual(self.gh.issues[n]["state"], "closed")
        self.assertEqual(self.gh.comments[n], ["再次出現"])
        base = self._base()
        self.apply(self.plan([dict(a, reopen_if_closed=True)], base=base))
        self.assertEqual(self.gh.issues[n]["state"], "open")
        self.assertEqual(len(self.gh.comments[n]), 2)

    def test_open_if_closed(self):
        n1 = self.gh.add_issue(mark(K1), ["dumpling-watch"], state="closed")
        n2 = self.gh.add_issue(mark(K2), ["dumpling-watch"], state="open")
        n3 = self.gh.add_issue(mark(K3), ["dumpling-watch"], state="closed")  # 沒有 plan 動作，不應被動到
        acts = [self.open_act(K1, op="open_if_closed"), self.open_act(K2, op="open_if_closed"),
                self.open_act(K3[:-1] + "d", op="open_if_closed")]
        rc, out = self.apply(self.plan(acts))
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.gh.comments.get(n2), ["內容"])
        self.assertNotIn(n1, self.gh.comments)
        k1_issues = [i for i in self.gh.issues.values() if issues.parse_marker(i["body"]) and issues.parse_marker(i["body"])[0] == K1]
        self.assertEqual(len(k1_issues), 2)
        self.assertEqual(self.gh.issues[n1]["state"], "closed")
        res = json.load(open(os.path.join(self.dir, "apply-result.json")))
        self.assertEqual([r["result"] for r in res["actions"]], ["opened", "commented", "opened"])
        # 再跑一次：K1 現在有開著的 → 改留言，不再開
        before = len(self.gh.issues)
        self.apply(self.plan([self.open_act(K1, op="open_if_closed")], base=self._base()))
        self.assertEqual(len(self.gh.issues), before)

    def test_drill_labels(self):
        rc, out = self.apply(self.plan([self.open_act(labels=("vendor-level",))], mode="drill"))
        self.assertEqual(rc, 0, out)
        w = [i for i in self.gh.issues.values() if "dumpling-watch" in self.names(i)][0]
        self.assertEqual(self.names(w), ["vendor-level", "dumpling-watch", "drill"])
        self.assertIn("mode=drill", w["body"].splitlines()[0])
        st = [i for i in self.gh.issues.values() if "watch-state-drill" in self.names(i)][0]
        self.assertIn("drill", self.names(st))
        self.assertNotIn("dumpling-watch", self.names(st))
        self.assertEqual(self.gh.labels["drill"], "6e7781")

    def test_dry_run_writes_nothing(self):
        rc, out = self.apply(self.plan([self.open_act(), self.open_act()]), "--dry-run")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.gh.writes, [])
        self.assertIn("would_open", out)
        self.assertIn("skipped", out)  # 第二個同 key 視為已有

    def test_state_too_big_fails_before_write(self):
        import random
        r = random.Random(2)
        big = {"x": "".join(r.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(90000))}
        rc, _ = self.apply(self.plan([self.open_act()], state=big))
        self.assertEqual(rc, 1)
        self.assertEqual(self.gh.writes, [])


class TestCloseDrill(Base):
    def test_only_drill(self):
        d = self.gh.add_issue(mark(K1, "drill"), ["dumpling-watch", "drill"])
        r = self.gh.add_issue(mark(K2), ["dumpling-watch"])
        ds = self.gh.add_issue(issues.encode_state({}, "drill", "s"), ["watch-state-drill", "drill"])
        rs = self.gh.add_issue(issues.encode_state({}, "real", "s"), ["watch-state"])
        done = self.gh.add_issue(mark(K3, "drill"), ["dumpling-watch", "drill"], state="closed")
        rc, out = run(["close-drill", "--repo", REPO], self.gh)
        self.assertEqual(rc, 0, out)
        st = {n: self.gh.issues[n]["state"] for n in (d, r, ds, rs, done)}
        self.assertEqual(st, {d: "closed", r: "open", ds: "closed", rs: "open", done: "closed"})
        self.assertEqual(self.gh.comments[d], ["演練結束，自動關閉"])
        self.assertNotIn(r, self.gh.comments)
        self.assertNotIn(rs, self.gh.comments)
        self.assertNotIn(done, self.gh.comments)
        names = lambda n: [l["name"] for l in self.gh.issues[n]["labels"]]
        self.assertEqual(names(d), ["dumpling-watch-drill-done", "drill"])
        self.assertEqual(names(ds), ["watch-state-drill-done", "drill"])
        self.assertEqual(names(r), ["dumpling-watch"])
        self.assertEqual(names(rs), ["watch-state"])
        self.assertEqual(names(done), ["dumpling-watch", "drill"])

    def test_fresh_drill_after_close(self):
        plan = self.plan([self.open_act()], mode="drill")
        self.assertEqual(run(["apply", "--repo", REPO, "--plan", plan], self.gh)[0], 0)
        self.assertEqual(run(["close-drill", "--repo", REPO], self.gh)[0], 0)
        rc, _ = run(["read-state", "--repo", REPO, "--mode", "drill", "--out", self.dir], self.gh)
        self.assertEqual(rc, 0)
        with open(os.path.join(self.dir, "state-base.json")) as f:
            self.assertEqual(json.load(f), {"issue": None, "updated_at": None, "body_sha256": None, "watch_issues": 0})
        self.assertFalse(os.path.exists(os.path.join(self.dir, "state.json")))
        before = len(self.gh.issues)
        plan = self.plan([self.open_act()], mode="drill", name="p2.json")
        rc, _ = run(["apply", "--repo", REPO, "--plan", plan], self.gh)
        self.assertEqual(rc, 0)
        self.assertEqual(len(self.gh.issues), before + 2)  # 新的監控 Issue＋新的狀態 Issue


class TestTransport(Base):
    def test_redirect_is_error(self):
        self.gh.script = [(302, {"location": "https://evil.example.test/x"}, b"")]
        rc, out = run(["read-state", "--repo", REPO, "--mode", "real", "--out", self.dir], self.gh)
        self.assertEqual(rc, 1)
        self.assertIn("轉址", out)

    def test_foreign_next_link_refused(self):
        self.gh.script = [(200, {"link": '<https://other.example.test/x>; rel="next"'}, b"[]")]
        with self.assertRaises(issues.Fail):
            issues.list_issues(self.gh, REPO, "dumpling-watch")

    def test_token_only_in_header_and_not_in_output(self):
        self.gh.add_issue(mark(K1), ["dumpling-watch"])
        self.gh.script = [(500, {}, ("boom " + TOKEN).encode())]
        rc, out = run(["read-state", "--repo", REPO, "--mode", "real", "--out", self.dir], self.gh)
        self.assertEqual(rc, 1)
        self.assertNotIn(TOKEN, out)
        rc, out = run(["read-state", "--repo", REPO, "--mode", "real", "--out", self.dir], self.gh)
        self.assertNotIn(TOKEN, out)
        self.assertTrue(all(h.get("Authorization") == "Bearer " + TOKEN for h in self.gh.headers_seen))
        for f in os.listdir(self.dir):
            self.assertNotIn(TOKEN, open(os.path.join(self.dir, f)).read())

    def test_rate_limit_retry_then_ok(self):
        self.gh.script = [(403, {"retry-after": "5"}, b"{}"), (429, {"retry-after": "500"}, b"{}"),
                          (403, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1007"}, b"{}"),
                          (200, {}, b"[]")]
        self.assertEqual(issues.list_issues(self.gh, REPO, "dumpling-watch"), [])
        self.assertEqual(self.gh.sleeps, [5, 60, 7])

    def test_rate_limit_gives_up(self):
        self.gh.script = [(429, {"retry-after": "1"}, b"{}")] * 4
        rc, out = run(["read-state", "--repo", REPO, "--mode", "real", "--out", self.dir], self.gh)
        self.assertEqual(rc, 1)
        self.assertIn("rate limit", out)

    def test_plain_403_not_retried(self):
        self.gh.script = [(403, {}, b'{"message":"forbidden"}')]
        with self.assertRaises(issues.Fail):
            issues.list_issues(self.gh, REPO, "dumpling-watch")
        self.assertEqual(self.gh.sleeps, [])

    def test_oversize_response(self):
        self.gh.script = [(200, {}, b"x" * (issues.MAX_RESPONSE + 2))]
        with self.assertRaises(issues.Fail):
            issues.list_issues(self.gh, REPO, "dumpling-watch")

    def test_usage(self):
        self.assertEqual(run([], self.gh)[0], 64)
        self.assertEqual(run(["apply", "--repo", "bad"], self.gh)[0], 64)
        self.assertEqual(run(["read-state", "--repo", "a/b", "--mode", "x", "--out", "o"], self.gh)[0], 64)


if __name__ == "__main__":
    unittest.main()
