"""art14.py 單元測試：不連網，用記憶體裡的假 GitHub（覆寫 Api._raw）。測資全部合成。"""
import contextlib
import datetime as dt
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
import art14  # noqa: E402
import issues  # noqa: E402

REPO = "octo/demo"
TOKEN = "ghp_SECRETTOKEN0123456789"
FIXTURE = os.path.join(HERE, "..", "..", "..", "tests", "fixtures", "watch", "art14-drill-match.json")
UTC = dt.timezone.utc
NOW = dt.datetime(2026, 11, 13, 6, 0, 0, tzinfo=UTC)
NOW_S = "2026-11-13T06:00:00Z"


def T(*a):
    return dt.datetime(*a, tzinfo=UTC)


class FakeGitHub(issues.Api):
    def __init__(self):
        self.now = 0.0
        super().__init__(base="https://api.example.test", token=TOKEN, sleep=lambda d: None, clock=lambda: 0.0, wall=lambda: 1000)
        self.issues, self.comments, self.labels = {}, {}, set()
        self.n, self.cid, self.tick = 0, 0, 0
        self.writes, self.headers_seen = [], []

    def _ts(self):
        self.tick += 1
        return "2026-01-01T00:00:%02dZ" % (self.tick % 60)

    def add_issue(self, body, labels, state="open", assoc="OWNER", user=("alice", "User"), title="t"):
        self.n += 1
        self.issues[self.n] = {"number": self.n, "title": title, "body": body, "state": state, "updated_at": self._ts(),
                               "labels": [{"name": x} for x in labels], "author_association": assoc,
                               "user": {"login": user[0], "type": user[1]}}
        return self.n

    def add_comment(self, num, body, assoc="OWNER", user=("alice", "User")):
        self.cid += 1
        self.comments.setdefault(num, []).append({"id": self.cid, "body": body, "author_association": assoc,
                                                  "user": {"login": user[0], "type": user[1]}})
        return self.cid

    def _raw(self, method, url, headers, body):
        self.headers_seen.append(headers)
        u = urllib.parse.urlsplit(url)
        q = urllib.parse.parse_qs(u.query)
        data = json.loads(body) if body else None
        if method != "GET":
            self.writes.append((method, u.path, data))
        tail = u.path.split("/")[4:]
        if tail == ["issues"] and method == "GET":
            lab, st = q["labels"][0], q.get("state", ["open"])[0]
            rows = [i for i in self.issues.values() if any(l["name"] == lab for l in i["labels"]) and (st == "all" or i["state"] == st)]
            return 200, {}, json.dumps(rows).encode()
        if tail == ["labels"] and method == "GET":
            return 200, {}, json.dumps([{"name": n} for n in self.labels]).encode()
        if tail == ["labels"] and method == "POST":
            self.labels.add(data["name"])
            return 201, {}, b"{}"
        if tail == ["issues"] and method == "POST":
            for l in data["labels"]:
                assert l in self.labels, "標籤沒先建立"
            num = self.add_issue(data["body"], data["labels"], title=data["title"], user=("github-actions[bot]", "Bot"), assoc="NONE")
            return 201, {}, json.dumps(self.issues[num]).encode()
        if len(tail) == 2 and tail[0] == "issues" and method == "PATCH":
            i = self.issues[int(tail[1])]
            i.update({k: v for k, v in data.items() if k != "labels"})
            if "labels" in data:
                for l in data["labels"]:
                    assert l in self.labels or l in [x["name"] for x in i["labels"]], "標籤沒先建立"
                i["labels"] = [{"name": x} for x in data["labels"]]
            return 200, {}, json.dumps(i).encode()
        if len(tail) == 3 and tail[0] == "issues" and tail[2] == "comments":
            n = int(tail[1])
            if method == "GET":
                return 200, {}, json.dumps(self.comments.get(n, [])).encode()
            self.add_comment(n, data["body"], assoc="NONE", user=("github-actions[bot]", "Bot"))
            return 201, {}, b"{}"
        if len(tail) == 3 and tail[:2] == ["issues", "comments"] and method == "PATCH":
            cid = int(tail[2])
            for lst in self.comments.values():
                for c in lst:
                    if c["id"] == cid:
                        c["body"] = data["body"]
                        return 200, {}, b"{}"
        return 404, {}, b'{"message":"nf"}'

    def label_set(self, n):
        return {l["name"] for l in self.issues[n]["labels"]}


def run(argv, api):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        rc = art14.main(argv, api=api)
    return rc, out.getvalue()


def last(out):
    return out.strip().splitlines()[-1].split("\t")


class Base(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.dir = self._td.name
        self.addCleanup(self._td.cleanup)
        self.gh = FakeGitHub()

    def result(self, name="r.json"):
        return os.path.join(self.dir, name)

    def load(self, path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    def open_drill(self):
        rc, out = run(["open-drill", "--repo", REPO, "--match", FIXTURE], self.gh)
        self.assertEqual(rc, 0, out)
        return out

    def drill_body(self, kind="vulnerability"):
        m = art14.load_match(FIXTURE)
        if kind == "incident":
            m = incident_match()
        return art14.render_issue(m)

    def put_issue(self, body, labels=("art14-drill", "art14-24h"), **kw):
        self.gh.labels.update(labels)
        return self.gh.add_issue(body, labels, **kw)


def incident_match():
    return {"kind": "incident", "product": "drill-demo", "version": "v1.0.0", "description": "合成的嚴重事件（演練）",
            "first_detected": "2026-11-13T00:00:00Z", "incident_id": "INC-DRILL-1", "severity": None, "severity_source": "",
            "key_parts": ["drill-demo", "v1.0.0", "INC-DRILL-1"], "id": "INC-DRILL-1"}


def set_field(body, label, value):
    new, n = re.subn(r"^(- " + re.escape(label) + r"：).*$", lambda m: m.group(1) + value, body, count=1, flags=re.M)
    assert n == 1, label
    return new


class TestDeadlines(unittest.TestCase):
    def due(self, kind, aware, **kw):
        return {s["id"]: s for s in art14.deadlines(kind, aware, **kw)["stages"]}

    def test_vulnerability_24h_72h_14d(self):
        d = self.due("vulnerability", T(2026, 11, 13, 6, 30, 15), measure_at=T(2026, 11, 20, 1, 2, 3))
        self.assertEqual(d["24h"]["due"], T(2026, 11, 14, 6, 30, 15))
        self.assertEqual(d["72h"]["due"], T(2026, 11, 16, 6, 30, 15))
        self.assertEqual(d["final"]["due"], T(2026, 12, 4, 1, 2, 3))

    def test_no_measure_final_none_with_reason(self):
        d = self.due("vulnerability", T(2026, 11, 13))
        self.assertIsNone(d["final"]["due"])
        self.assertIn("措施可用時間未填", d["final"]["reason"])

    def test_no_aware_all_none(self):
        d = self.due("vulnerability", None, measure_at=T(2026, 11, 20))
        self.assertTrue(all(s["due"] is None and s["reason"] for s in d.values()))

    def test_incident_one_month_cases(self):
        def final(n):
            return self.due("incident", T(2026, 1, 1), notification_at=n)["final"]["due"]
        self.assertEqual(final(T(2026, 11, 13, 5, 6, 7)), T(2026, 12, 13, 5, 6, 7))
        self.assertEqual(final(T(2026, 10, 31, 12)), T(2026, 11, 30, 12))        # 跨月：沒有 11/31
        self.assertEqual(final(T(2028, 1, 31, 23, 59, 59)), T(2028, 2, 29, 23, 59, 59))  # 閏年
        self.assertEqual(final(T(2027, 1, 31)), T(2027, 2, 28))                  # 非閏年
        self.assertEqual(final(T(2026, 12, 15, 8)), T(2027, 1, 15, 8))           # 12 月跨年
        self.assertEqual(final(T(2026, 12, 31)), T(2027, 1, 31))

    def test_incident_no_notification(self):
        d = self.due("incident", T(2026, 1, 1))
        self.assertIsNone(d["final"]["due"])
        self.assertIn("事件通報送出時間未填", d["final"]["reason"])

    def test_leap_day_cross_month_hours(self):
        d = self.due("vulnerability", T(2028, 2, 28, 12))
        self.assertEqual(d["24h"]["due"], T(2028, 2, 29, 12))
        self.assertEqual(d["72h"]["due"], T(2028, 3, 2, 12))
        d = self.due("vulnerability", T(2026, 12, 31, 23), measure_at=T(2026, 12, 31, 23))
        self.assertEqual(d["72h"]["due"], T(2027, 1, 3, 23))
        self.assertEqual(d["final"]["due"], T(2027, 1, 14, 23))

    def test_timezone_converted_to_utc(self):
        tz = dt.timezone(dt.timedelta(hours=8))
        d = self.due("vulnerability", dt.datetime(2026, 11, 13, 8, 0, tzinfo=tz))
        self.assertEqual(d["24h"]["due"], T(2026, 11, 14, 0))
        self.assertEqual(d["24h"]["due"].utcoffset(), dt.timedelta(0))

    def test_naive_rejected(self):
        for kw in ({"aware_at": dt.datetime(2026, 1, 1)},):
            with self.assertRaises(art14.DeadlineError):
                art14.deadlines("vulnerability", **kw)
        with self.assertRaises(art14.DeadlineError):
            art14.deadlines("vulnerability", T(2026, 1, 1), measure_at=dt.datetime(2026, 1, 2))
        with self.assertRaises(art14.DeadlineError):
            art14.deadlines("incident", T(2026, 1, 1), notification_at=dt.datetime(2026, 1, 2))

    def test_measure_before_aware_is_error(self):
        with self.assertRaises(art14.DeadlineError):
            art14.deadlines("vulnerability", T(2026, 11, 13), measure_at=T(2026, 11, 12))
        with self.assertRaises(art14.DeadlineError):
            art14.deadlines("incident", T(2026, 11, 13), notification_at=T(2026, 11, 12))

    def test_bad_kind(self):
        with self.assertRaises(art14.DeadlineError):
            art14.deadlines("other", T(2026, 1, 1))


class TestParseAndEvaluate(Base):
    def test_unfilled_template(self):
        _, _, body, _ = self.drill_body()
        ev = art14.evaluate("vulnerability", body, NOW)
        self.assertFalse(ev["clock_started"])
        self.assertEqual(ev["hours_since_detected"], 6)
        self.assertEqual(ev["problems"], [])
        self.assertEqual(ev["next_stage"], "24h")
        self.assertTrue(all(s["state"] == "not_started" for s in ev["stages"]))

    def test_valid_filled(self):
        _, _, body, _ = self.drill_body()
        body = set_field(body, art14.F_AWARE, "2026-11-13T00:00:00Z")
        body = set_field(body, art14.F_MEASURE, "2026-11-14T00:00:00Z")
        ev = art14.evaluate("vulnerability", body, NOW)
        self.assertTrue(ev["clock_started"])
        st = {s["id"]: s for s in ev["stages"]}
        self.assertEqual(st["24h"]["due"], T(2026, 11, 14))
        self.assertEqual(st["72h"]["due"], T(2026, 11, 16))
        self.assertEqual(st["final"]["due"], T(2026, 11, 28))
        self.assertEqual({s["state"] for s in ev["stages"]}, {"pending"})

    def test_bad_formats_treated_as_blank_with_message(self):
        _, _, body, _ = self.drill_body()
        for bad in ("2026-11-13 00:00:00", "2026-11-13T00:00:00+08:00", "2026-13-40T00:00:00Z", "昨天", "2026-11-13T00:00:00Z 之後"):
            ev = art14.evaluate("vulnerability", set_field(body, art14.F_AWARE, bad), NOW)
            self.assertFalse(ev["clock_started"], bad)
            self.assertTrue(any("格式不對" in p and "知悉時間" in p for p in ev["problems"]), bad)

    def test_deleted_or_duplicated_field_is_bad(self):
        _, _, body, _ = self.drill_body()
        gone = re.sub(r"^- " + re.escape(art14.F_AWARE) + r"：.*\n", "", body, flags=re.M)
        self.assertFalse(art14.evaluate("vulnerability", gone, NOW)["clock_started"])
        self.assertTrue(art14.evaluate("vulnerability", gone, NOW)["problems"])
        dup = body + f"- {art14.F_AWARE}：2026-11-13T00:00:00Z\n"
        ev = art14.evaluate("vulnerability", dup, NOW)
        self.assertFalse(ev["clock_started"])
        self.assertTrue(any("格式不對" in p for p in ev["problems"]))

    def test_stage_done_late_and_overdue(self):
        _, _, body, _ = self.drill_body()
        body = set_field(body, art14.F_AWARE, "2026-11-10T00:00:00Z")
        # 階段 1 的欄位是第一個「提交時間」；用階段標題限定
        body = body.replace(f"- {art14.F_SUBMIT_AT}：未填", f"- {art14.F_SUBMIT_AT}：2026-11-10T20:00:00Z", 1)
        ev = art14.evaluate("vulnerability", body, NOW)
        st = {s["id"]: s for s in ev["stages"]}
        self.assertEqual(st["24h"]["state"], "done")
        self.assertFalse(st["24h"]["late"])
        self.assertEqual(st["72h"]["state"], "overdue")   # 2026-11-13T00:00 到期，現在 06:00
        self.assertEqual(ev["next_stage"], "72h")
        body2 = set_field(body, art14.F_SUBMIT_AT, "2026-11-12T00:00:00Z")  # set_field 改第一個（階段 1）：晚於期限
        ev2 = art14.evaluate("vulnerability", body2, NOW)
        self.assertTrue(ev2["stages"][0]["late"])

    def test_measure_before_aware_flagged_final_not_started(self):
        _, _, body, _ = self.drill_body()
        body = set_field(body, art14.F_AWARE, "2026-11-13T00:00:00Z")
        body = set_field(body, art14.F_MEASURE, "2026-11-01T00:00:00Z")
        ev = art14.evaluate("vulnerability", body, NOW)
        st = {s["id"]: s for s in ev["stages"]}
        self.assertEqual(st["24h"]["state"], "pending")
        self.assertEqual(st["final"]["state"], "not_started")
        self.assertIn("早於知悉時間", st["final"]["reason"])
        self.assertTrue(any("早於知悉時間" in p for p in ev["problems"]))

    def test_incident_final_from_notification(self):
        _, _, body, _ = self.drill_body("incident")
        body = set_field(body, art14.F_AWARE, "2026-11-13T00:00:00Z")
        body = set_field(body, art14.F_NOTIF, "2026-11-15T12:00:00Z")
        ev = art14.evaluate("incident", body, NOW)
        self.assertEqual({s["id"]: s["due"] for s in ev["stages"]}["final"], T(2026, 12, 15, 12))


class TestComment(Base):
    def render(self, body, now=NOW):
        return art14.render_comment(art14.evaluate("vulnerability", body, now), now, True)

    def test_not_started_shows_elapsed_hours(self):
        _, _, body, _ = self.drill_body()
        c = self.render(body)
        self.assertIn("時鐘未起算（待確認）", c)
        self.assertIn("已經過 6 小時", c)
        self.assertEqual(c.splitlines()[0], art14.COMMENT_MARK)
        self.assertIn("倒數只是輔助，GitHub 排程可能延遲，期限由負責人自己掌握", c)

    def test_started_remaining_and_overdue(self):
        _, _, body, _ = self.drill_body()
        body = set_field(body, art14.F_AWARE, "2026-11-12T12:00:00Z")
        c = self.render(body)
        self.assertIn("2026-11-13T12:00:00Z", c)
        self.assertIn("剩 6 小時 0 分", c)
        self.assertIn("2026-11-15T12:00:00Z", c)
        late = self.render(body, T(2026, 11, 13, 13, 30))
        self.assertIn("已逾期 1 小時 30 分", late)

    def test_done_stage_marked(self):
        _, _, body, _ = self.drill_body()
        body = set_field(body, art14.F_AWARE, "2026-11-12T12:00:00Z")
        body = set_field(body, art14.F_SUBMIT_AT, "2026-11-12T20:00:00Z")
        c = self.render(body)
        self.assertIn("完成（SRP 提交 2026-11-12T20:00:00Z）", c)
        self.assertIn("art14-72h", c)

    def test_bad_format_message(self):
        _, _, body, _ = self.drill_body()
        c = self.render(set_field(body, art14.F_AWARE, "明天"))
        self.assertIn("格式不對", c)
        self.assertIn("時鐘未起算", c)

    def test_span_format(self):
        self.assertEqual(art14.fmt_span(90061), "1 天 1 小時 1 分")
        self.assertEqual(art14.fmt_span(59), "0 分")


class TestOpenDrill(Base):
    def test_open_has_template_and_labels(self):
        out = self.open_drill()
        self.assertEqual(last(out)[:2], ["ART14", "OK"])
        i = self.gh.issues[1]
        self.assertEqual(self.gh.label_set(1), {"art14-drill", "art14-24h"})
        lines = i["body"].splitlines()
        self.assertRegex(lines[0], r"^<!-- dumpling-art14 key=[0-9a-f]{64} kind=vulnerability mode=drill -->$")
        self.assertEqual(lines[1], "演練，不是真實通報")
        self.assertIn("[演練]", i["title"])
        for needle in ("CVE-2018-18074", "drill-demo v1.0.0", "requests 2.19.0", "層：bsp", "嚴重度：待填", "GAP", "M7",
                       "階段 1", "階段 2", "階段 3", "SRP 沒有 API", "選擇協調 CSIRT", "CELEX:32024R2847", "2026-11-13",
                       "倒數只是輔助，GitHub 排程可能延遲，期限由負責人自己掌握", "不在公開 Issue 放任何機密"):
            self.assertIn(needle, i["body"], needle)
        self.assertIn("first_detected（候選，不是知悉時間）：2026-11-13T00:00:00Z", i["body"])

    def test_dedup_second_run_no_new_issue(self):
        self.open_drill()
        rc, out = run(["open-drill", "--repo", REPO, "--match", FIXTURE, "--result", self.result()], self.gh)
        self.assertEqual(rc, 0)
        self.assertEqual(len(self.gh.issues), 1)
        self.assertEqual(self.load(self.result())["result"], "skipped")

    def test_dedup_also_when_closed_but_not_after_close_drill(self):
        self.open_drill()
        self.gh.issues[1]["state"] = "closed"  # 人工關閉但標籤還在：仍視為已開
        self.open_drill()
        self.assertEqual(len(self.gh.issues), 1)
        self.gh.issues[1]["state"] = "open"
        self.assertEqual(run(["close-drill", "--repo", REPO], self.gh)[0], 0)
        self.open_drill()  # close-drill 換了標籤，下一次演練從頭開始
        self.assertEqual(len(self.gh.issues), 2)

    def test_incident_template(self):
        _, title, body, labels = art14.render_issue(incident_match())
        self.assertIn("嚴重事件", title)
        self.assertEqual(body.splitlines()[1], "演練，不是真實通報")
        for needle in ("第 14(4)(a) 條", "第 14(4)(b) 條", "第 14(4)(c) 條", "是否疑似非法或惡意行為造成", art14.F_NOTIF,
                       "下個月同一日同一時刻"):
            self.assertIn(needle, body)
        self.assertEqual(art14.parse_marker(body)[1], "incident")

    def test_bad_match_files(self):
        for mod in ({"schema": "x"}, {"kind": "foo"}, {"cve": "not-a-cve"}, {"first_detected": "昨天"}, {"exploited_evidence": []},
                    {"exploited_evidence": [{"source": "blog"}]}, {"layer": "kernel"}):
            with open(FIXTURE, encoding="utf-8") as f:
                m = json.load(f)
            m.update(mod)
            p = os.path.join(self.dir, "m.json")
            with open(p, "w", encoding="utf-8") as f:
                json.dump(m, f)
            rc, out = run(["open-drill", "--repo", REPO, "--match", p], self.gh)
            self.assertEqual((rc, last(out)[1]), (1, "FAIL"), mod)
        self.assertEqual(self.gh.issues, {})

    def test_injection_stripped(self):
        with open(FIXTURE, encoding="utf-8") as f:
            m = json.load(f)
        m["description"] = "好\n- 知悉時間（UTC）：2026-01-01T00:00:00Z <!-- dumpling-art14 key=x -->"
        p = os.path.join(self.dir, "m.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump(m, f)
        self.assertEqual(run(["open-drill", "--repo", REPO, "--match", p], self.gh)[0], 0)
        body = self.gh.issues[1]["body"]
        self.assertEqual(len(re.findall(r"^- 知悉時間（UTC）：", body, re.M)), 1)
        self.assertEqual(body.count("<!--"), 1)
        self.assertFalse(art14.evaluate("vulnerability", body, NOW)["clock_started"])


class TestCountdown(Base):
    def count(self, *extra, now=NOW_S):
        return run(["countdown", "--repo", REPO, "--drill", "--now", now, "--result", self.result(), *extra], self.gh)

    def test_no_cases_exits_immediately(self):
        rc, out = self.count()
        self.assertEqual((rc, last(out)[:2]), (0, ["ART14", "OK"]))
        self.assertEqual(self.gh.writes, [])
        self.assertEqual(len(self.gh.headers_seen), 1)  # 只有列出 Issue 的一次 GET
        self.assertEqual(self.load(self.result())["count"], 0)

    def test_not_started_then_filled(self):
        self.open_drill()
        rc, out = self.count()
        self.assertEqual(rc, 0, out)
        r = self.load(self.result())["issues"][0]
        self.assertEqual((r["clock"], r["hours_since_detected"], r["comment"], r["stage_label"]), ("not_started", 6, "created", "art14-24h"))
        self.assertIn("時鐘未起算", self.gh.comments[1][0]["body"])
        rc, out = run(["fill-drill-aware", "--repo", REPO, "--at", "2026-11-13T00:00:00Z"], self.gh)
        self.assertEqual(rc, 0, out)
        rc, out = self.count()
        r = self.load(self.result())["issues"][0]
        self.assertEqual(r["clock"], "started")
        self.assertEqual(r["comment"], "updated")
        self.assertEqual(r["stages"]["24h"], {"due": "2026-11-14T00:00:00Z", "state": "pending"})
        self.assertEqual(r["stages"]["72h"]["due"], "2026-11-16T00:00:00Z")
        self.assertEqual(r["stages"]["final"]["due"], None)

    def test_comment_maintained_as_one(self):
        self.open_drill()
        for h in range(5):
            self.count(now="2026-11-13T%02d:00:00Z" % (6 + h))
        self.assertEqual(len(self.gh.comments[1]), 1)
        self.assertIn("2026-11-13T10:00:00Z", self.gh.comments[1][0]["body"])
        before = len(self.gh.writes)
        self.count(now="2026-11-13T10:00:00Z")  # 完全相同的內容：不寫
        self.assertEqual(len(self.gh.writes), before)
        self.assertEqual(self.load(self.result())["issues"][0]["comment"], "unchanged")

    def test_forged_marker_comment_ignored(self):
        self.open_drill()
        self.gh.add_comment(1, art14.COMMENT_MARK + "\n偽造", assoc="NONE", user=("mallory", "User"))
        self.count()
        self.assertEqual(len(self.gh.comments[1]), 2)
        self.assertEqual(self.gh.comments[1][0]["body"], art14.COMMENT_MARK + "\n偽造")

    def test_stage_label_switching(self):
        self.open_drill()
        self.gh.labels.add("keep-me")
        self.gh.issues[1]["labels"].append({"name": "keep-me"})
        self.count()
        self.assertEqual(self.gh.label_set(1), {"art14-drill", "art14-24h", "keep-me"})
        body = set_field(self.gh.issues[1]["body"], art14.F_AWARE, "2026-11-13T00:00:00Z")
        body = body.replace(f"- {art14.F_SUBMIT_AT}：未填", f"- {art14.F_SUBMIT_AT}：2026-11-13T02:00:00Z", 1)
        self.gh.issues[1]["body"] = body
        self.count()
        self.assertEqual(self.gh.label_set(1), {"art14-drill", "art14-72h", "keep-me"})
        self.assertEqual(self.load(self.result())["issues"][0]["label_changed"], True)
        # 全部完成：階段標籤全拿掉
        for stage in (2, 3):
            body = re.sub(r"(## 階段 %d：.*?- %s：)未填" % (stage, re.escape(art14.F_SUBMIT_AT)), r"\g<1>2026-11-13T03:00:00Z",
                          self.gh.issues[1]["body"], count=1, flags=re.S)
            self.gh.issues[1]["body"] = body
        self.count()
        self.assertEqual(self.gh.label_set(1), {"art14-drill", "keep-me"})
        self.assertIsNone(self.load(self.result())["issues"][0]["stage_label"])

    def test_only_trusted_authors(self):
        _, _, body, _ = self.drill_body()
        for assoc in ("OWNER", "MEMBER", "COLLABORATOR"):
            self.put_issue(body, assoc=assoc)
        for assoc in ("NONE", "CONTRIBUTOR", "FIRST_TIMER", "FIRST_TIME_CONTRIBUTOR", "MANNEQUIN"):
            self.put_issue(body, assoc=assoc)
        self.put_issue(body, assoc="NONE", user=("mallory", "Bot"))  # 假冒的 Bot 名稱不算
        rc, out = self.count()
        self.assertEqual(rc, 0, out)
        res = self.load(self.result())
        self.assertEqual([i["number"] for i in res["issues"]], [1, 2, 3])
        self.assertEqual(sorted(s["number"] for s in res["skipped"]), [4, 5, 6, 7, 8, 9])
        for n in range(4, 10):
            self.assertNotIn(n, self.gh.comments)
        self.assertEqual(self.gh.label_set(4), {"art14-drill", "art14-24h"})

    def test_only_untrusted_cases_is_immediate_ok(self):
        _, _, body, _ = self.drill_body()
        self.put_issue(body, assoc="NONE")
        rc, out = self.count()
        self.assertEqual((rc, last(out)[1]), (0, "OK"))
        self.assertEqual(self.gh.writes, [])
        self.assertIn("立刻結束", out)

    def test_bad_marker_skipped(self):
        self.put_issue("沒有標記\n", assoc="OWNER")
        rc, out = self.count()
        self.assertEqual(rc, 0)
        self.assertEqual(self.gh.writes, [])
        self.assertEqual(self.load(self.result())["count"], 0)

    def test_without_drill_rejects_real_art14(self):
        _, _, body, _ = self.drill_body()
        n = self.put_issue(body.replace("mode=drill", "mode=real"), labels=("art14", "art14-24h"))
        before = json.dumps(self.gh.issues[n], sort_keys=True)
        rc, out = run(["countdown", "--repo", REPO, "--now", NOW_S], self.gh)
        self.assertEqual((rc, last(out)[1]), (1, "FAIL"))
        self.assertIn("不該有真實案件", out)
        self.assertEqual(self.gh.writes, [])
        self.assertEqual(json.dumps(self.gh.issues[n], sort_keys=True), before)

    def test_without_drill_no_art14_ok(self):
        rc, out = run(["countdown", "--repo", REPO, "--now", NOW_S], self.gh)
        self.assertEqual((rc, last(out)[1]), (0, "OK"))

    def test_drill_mode_never_touches_art14_issue(self):
        _, _, body, _ = self.drill_body()
        n = self.put_issue(body.replace("mode=drill", "mode=real"), labels=("art14",))
        self.count()
        self.assertEqual(self.gh.writes, [])
        self.assertEqual(self.gh.label_set(n), {"art14"})

    def test_bad_now(self):
        for a in (["countdown", "--repo", REPO, "--now", "2026-11-13"], ["countdown", "--repo", "bad"], ["countdown"], ["nope"], []):
            rc, out = run(a, self.gh)
            self.assertEqual(rc, 64, a)
            self.assertEqual(last(out)[:2], ["ART14", "FAIL"])

    def test_public_check_hit_not_written(self):
        _, _, body, _ = self.drill_body()
        # 留言會把讀不懂的欄位原文帶回去（截短）；原文含本機路徑時，留言不能寫
        body = set_field(body, art14.F_AWARE, "/home" + "/alice/secret")
        self.put_issue(body)
        rc, out = self.count()
        self.assertEqual((rc, last(out)[1]), (1, "FAIL"))
        self.assertEqual(self.gh.comments, {})
        self.assertEqual(self.gh.writes, [])


class TestIndexLag(unittest.TestCase):
    """依標籤列 Issue 剛關閉後有索引延遲（2026-11-13 實測 #37）：列表回傳了已關閉的 Issue 時不更新它。"""

    def test_closed_issue_in_open_listing_is_skipped(self):
        orig = art14.issues.list_issues
        art14.issues.list_issues = lambda api, repo, label, state="all": [
            {"number": 9, "state": "closed", "body": "x", "author_association": "OWNER", "user": {"login": "a", "type": "User"}}]
        try:
            ok, skipped = art14.find_drill_issues(None, "o/r", "open")
        finally:
            art14.issues.list_issues = orig
        self.assertEqual(ok, [])
        self.assertEqual(skipped[0][0], 9)
        self.assertIn("已關閉", skipped[0][1])


class TestFillAndClose(Base):
    def test_fill_only_drill_issue(self):
        _, _, body, _ = self.drill_body()
        n = self.put_issue(body.replace("mode=drill", "mode=real"), labels=("art14",))
        rc, out = run(["fill-drill-aware", "--repo", REPO, "--at", "2026-11-13T00:00:00Z"], self.gh)
        self.assertEqual((rc, last(out)[1]), (1, "FAIL"))
        self.assertEqual(self.gh.writes, [])
        self.assertEqual(self.gh.issues[n]["body"], body.replace("mode=drill", "mode=real"))

    def test_fill_rejects_bad_time_and_untrusted(self):
        self.open_drill()
        self.assertEqual(run(["fill-drill-aware", "--repo", REPO, "--at", "2026-11-13 00:00"], self.gh)[0], 64)
        self.gh.issues[1]["author_association"] = "NONE"
        self.gh.issues[1]["user"] = {"login": "mallory", "type": "User"}
        self.assertEqual(run(["fill-drill-aware", "--repo", REPO, "--at", "2026-11-13T00:00:00Z"], self.gh)[0], 1)

    def test_close_drill_swaps_labels_and_closes(self):
        self.open_drill()
        self.gh.labels.add("keep-me")
        self.gh.issues[1]["labels"].append({"name": "keep-me"})
        other = self.put_issue("普通 Issue", labels=("bug",))
        rc, out = run(["close-drill", "--repo", REPO, "--result", self.result()], self.gh)
        self.assertEqual((rc, last(out)[1]), (0, "OK"))
        self.assertEqual(self.gh.issues[1]["state"], "closed")
        self.assertEqual(self.gh.label_set(1), {"art14-drill-done", "keep-me"})
        self.assertEqual(self.gh.issues[other]["state"], "open")
        self.assertEqual(self.load(self.result())["closed"], 1)
        self.assertEqual(run(["countdown", "--repo", REPO, "--drill", "--now", NOW_S], self.gh)[0], 0)
        self.assertEqual(self.gh.comments[1][-1]["body"], "演練結束，自動關閉")


class TestGuardsAndSecurity(Base):
    def test_drill_text_must_say_drill(self):
        with self.assertRaises(issues.Fail):
            art14.guard_text([("內文", "沒有那兩個字")], True)
        art14.guard_text([("內文", "演練，不是真實通報")], True)

    def test_template_always_says_drill(self):
        for m in (art14.load_match(FIXTURE), incident_match()):
            _, title, body, _ = art14.render_issue(m)
            self.assertIn("演練", title)
            self.assertEqual(body.splitlines()[1], "演練，不是真實通報")
        _, _, body, _ = self.drill_body()
        ev = art14.evaluate("vulnerability", body, NOW)
        self.assertIn("演練，不是真實通報", art14.render_comment(ev, NOW, True))

    def test_template_without_drill_wording_blocked(self):
        m = art14.load_match(FIXTURE)
        _, title, body, _ = art14.render_issue(m, drill=False)  # 真實版範本不含「演練」
        with self.assertRaises(issues.Fail):
            art14.guard_text([("標題", title), ("內文", body)], True)

    def test_public_check_blocks_open(self):
        with open(FIXTURE, encoding="utf-8") as f:
            m = json.load(f)
        m["description"] = "路徑 " + "/home" + "/alice/x 與 " + "admin" + "@" + "corp-internal.com"
        p = os.path.join(self.dir, "m.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump(m, f)
        rc, out = run(["open-drill", "--repo", REPO, "--match", p], self.gh)
        self.assertEqual((rc, last(out)[1]), (1, "FAIL"))
        self.assertEqual(self.gh.writes, [])

    def test_real_template_has_no_real_issue_command(self):
        # 沒有任何指令會開或改 art14（真實案件）Issue：open-drill 只開 art14-drill
        self.open_drill()
        self.assertTrue(all(("art14" not in l["name"]) or l["name"].startswith("art14-") for l in self.gh.issues[1]["labels"]))
        self.assertNotIn("art14", self.gh.label_set(1))

    def test_token_not_in_output_or_files(self):
        self.open_drill()
        outs = []
        for argv in (["countdown", "--repo", REPO, "--drill", "--now", NOW_S, "--result", self.result()],
                     ["close-drill", "--repo", REPO]):
            outs.append(run(argv, self.gh)[1])
        self.assertTrue(all(TOKEN not in o for o in outs))
        with open(self.result(), encoding="utf-8") as f:
            self.assertNotIn(TOKEN, f.read())
        self.assertTrue(all(TOKEN not in json.dumps(w) for w in self.gh.writes))
        self.assertTrue(any(h.get("Authorization") == "Bearer " + TOKEN for h in self.gh.headers_seen))

    def test_api_failure_is_scrubbed(self):
        gh = FakeGitHub()
        gh._raw = lambda *a: (_ for _ in ()).throw(RuntimeError(TOKEN))
        rc, out = run(["countdown", "--repo", REPO, "--drill"], gh)
        self.assertEqual(rc, 1)
        self.assertNotIn(TOKEN, out)


class TestCheck(Base):
    def test_expect(self):
        p = self.result()
        with open(p, "w", encoding="utf-8") as f:
            json.dump({"issues": [{"clock": "not_started", "stages": {"24h": {"due": None}}}], "ok": True}, f)
        ok = run(["check", "--result", p, "--expect", "issues.0.clock=not_started", "--expect", "issues.0.stages.24h.due=null",
                  "--expect", "ok=true"], None)
        self.assertEqual(ok[0], 0, ok)
        bad = run(["check", "--result", p, "--expect", "issues.0.clock=started", "--expect", "x.y=1"], None)
        self.assertEqual(bad[0], 1)
        self.assertIn("預期 started", bad[1])


if __name__ == "__main__":
    unittest.main()
