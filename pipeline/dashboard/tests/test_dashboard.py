"""儀表板測試：不連網。用假的 source（list_releases／fetch）與假的 issues api（list_issues）注入。測資全部合成。
涵蓋 docs/DASHBOARD.md 第 9 節：觸發條件、惡意字串、href 白名單、不認得的狀態值、沒有「安全」與 PASS、CSP、漏洞數附狀態、
draft 與演練 Issue 不列、附件抓不到是 GAP、全部來源失敗非 0、token 不進輸出、check_site 的突變。"""
import contextlib
import datetime
import io
import json
import os
import re
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
import build  # noqa: E402
import check_site  # noqa: E402
import render  # noqa: E402
import trigger  # noqa: E402
import watchlib  # noqa: E402

collect = watchlib.load("collect")
issues = watchlib.load("issues")

REPO = "octo/demo"
TOKEN = "ghp_SYNTHETICTOKEN0123456789"
NOW = datetime.datetime(2026, 11, 15, 6, 0, 0, tzinfo=datetime.timezone.utc)
HEX = "0123456789abcdef" * 2 + "01234567"
EVIL = ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>', "javascript:alert(1)", "@everyone",
        "A" * 100000, "x\x00y\x1b[31mz\x07\u202e\r\n\tend"]


def j(o):
    return json.dumps(o).encode()


# ---------------------------------------------------------------- 假資料來源

class FakeSource:
    def __init__(self, releases, files, boom=None):
        self.releases, self.files, self.boom = releases, files, boom

    def list_releases(self):
        if self.boom:
            raise self.boom
        return self.releases

    def fetch(self, asset, dest_dir, final_name):
        v = self.files.get(asset.handle)
        if isinstance(v, Exception):
            raise v
        if v is None:
            raise collect.AssetError("下載回 HTTP 404")
        with open(os.path.join(dest_dir, final_name), "wb") as f:
            f.write(v)
        return "0" * 64, len(v)


def rel(tag, prerelease=False, draft=False, names=None, published="2026-11-14T02:20:27Z", sizes=None):
    names = names or []
    assets = {n: [collect.Asset(n, (sizes or {}).get(n, 100), (tag, n))] for n in names}
    return {"tag": tag, "draft": draft, "prerelease": prerelease, "published_at": published, "html_url": None,
            "assets": assets, "malformed": None}


def meta(project="demo", version="v1.0", tag=None, kind="release", **over):
    m = {"schema": 1, "project": project, "version": version, "tag": tag or ("%s/%s" % (project, version)),
         "status": "development", "platform": "jetson", "commit": HEX, "built_at": "2026-11-13T02:33:37Z",
         "workflow_run": "4242", "report_status": "GAP", "release_gate": "GAP", "pipeline_result": "OK",
         "reports": [{"report": r, "report_status": "GAP", "release_gate": "GAP"} for r in ("full", "bsp", "os")]}
    m.update(over)
    return m


def run_entry(rs="GAP", gate="GAP", stages=None, tiers=None):
    return {"stages": stages or {"A-tools": "OK", "C-sbomgate": "GAP", "E-notice": "NOT_RUN"}, "report_status": rs, "release_gate": gate,
            "build_record_status": "OK", "upstream_source": {"status": "ATTENTION"},
            "vulnerabilities": {"rows_total": 10, "cves_total": 9, "tiers": tiers or {"p1": 1, "p2": 2, "p3": 3, "accepted": 4}}}


def scan(**over):
    d = {"runs": {"": run_entry(), "-bsp": run_entry(), "-os": run_entry()}, "components": {"total": 10, "bsp": 4, "os": 5, "unknown": 1}}
    d.update(over)
    return d


def vex(vulns=None):
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "vulnerabilities": vulns if vulns is not None else [
        {"id": "CVE-2020-0001", "analysis": {"state": "not_affected", "justification": "code_not_present"}},
        {"id": "CVE-2020-0002", "analysis": {"state": "not_affected", "justification": "code_not_present"}},
        {"id": "CVE-2020-0003", "analysis": {"state": "in_triage"}}]}


def release_set(tag="demo/v1.0", project="demo", version="v1.0", prerelease=False, meta_over=None, scan_obj=None, vex_obj=None,
                extra_names=(), drop=()):
    """一個完整的 Release：回 (rel dict, files dict)。drop：不附的檔名。"""
    base = "%s-%s" % (project, version)
    files = {
        "release-meta.json": j(meta(project, version, tag, **(meta_over or {}))),
        "scan-summary-%s.json" % base: j(scan_obj if scan_obj is not None else scan()),
        "vex-%s.cdx.json" % base: j(vex_obj if vex_obj is not None else vex()),
        "vex-%s-bsp.cdx.json" % base: j(vex()),
        "vex-%s-os.cdx.json" % base: j(vex([])),
        "report-%s.zip" % base: b"zip",
    }
    for n in extra_names:
        files[n] = b"x"
    for n in drop:
        files.pop(n, None)
    r = rel(tag, prerelease=prerelease, names=list(files), sizes={n: len(v) for n, v in files.items()})
    return r, {(tag, n): v for n, v in files.items()}


class FakeApi:
    def __init__(self, by_label=None, fail=None):
        self.by_label, self.fail = by_label or {}, fail or {}

    def list_issues(self, repo, label, state="all"):
        if label in self.fail:
            raise self.fail[label]
        return self.by_label.get(label, [])


def issue(n, title="t", state="open", labels=("dumpling-watch",), body="", created="2026-11-14T00:00:00Z"):
    return {"number": n, "title": title, "state": state, "body": body, "created_at": created,
            "labels": [{"name": x} for x in labels]}


def state_body():
    st = {"schema": 1, "dumpling": {"baseline_at": "2026-11-15T04:29:16Z", "mode": "real", "issues": {}}, "matches": {"a": {}, "b": {}},
          "vendor_matches": {"c": {}}, "runs": [{"at": "2026-11-15T04:29:16Z", "status": "OK", "detail": "d",
                                                 "run_url": "https://github.com/%s/actions/runs/777" % REPO}]}
    return issues.encode_state(st, "real", "summary")


def projects_loader(rows=None):
    rows = rows if rows is not None else [("demo", "projects/demo", {"product_name": "Demo 產品", "status": "development",
                                                                        "support_until": "2031-12-31"}, None)]
    return lambda d: rows


def write_watch(d, created="2026-11-15T04:28:30Z", plan=None, support=None, with_report=True):
    os.makedirs(os.path.join(d, "watch-plan-real-1"))
    os.makedirs(os.path.join(d, "watch-support-real-1"))
    with open(os.path.join(d, "run.json"), "w") as f:
        json.dump({"id": 555, "created_at": created, "event": "schedule", "conclusion": "success"}, f)
    with open(os.path.join(d, "watch-plan-real-1", "result.json"), "w", encoding="utf-8") as f:
        json.dump(plan or {"status": "OK", "detail": "1 份 SBOM", "per_sbom": {"u1": {
            "uuid": "u1", "tag": "demo/v1.0", "layer": "bsp", "grype": "OK", "why": None, "report_status": "GAP", "release_gate": "GAP",
            "kernel_map": "OK", "exploited": 5, "kernel_cna": "OK"}}, "notes": ["n1"], "attention": [], "gaps": [], "stats": {"opened": 0}}, f)
    if with_report:
        with open(os.path.join(d, "watch-plan-real-1", "report.md"), "w", encoding="utf-8") as f:
            f.write("# x\n\n## 每日沒有涵蓋的項目\n\n- DT：每天沒有重跑（NOT_RUN）\n\n## 說明\n\n- zzz\n")
    with open(os.path.join(d, "watch-support-real-1", "result.json"), "w", encoding="utf-8") as f:
        json.dump(support or {"status": "OK", "detail": "d", "today": "2026-11-15", "rows": [["demo", "OK", "支援期限 2031-12-31"]]}, f)


class Env:
    """一次完整的 build_data：建立暫存 watch 資料夾。"""

    def __init__(self, tc, releases=None, files=None, api=None, watch=True, loader=None, watch_kw=None, source=None, now=NOW):
        self.tmp = tempfile.TemporaryDirectory()
        tc.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name
        wd = os.path.join(self.dir, "watch")
        os.makedirs(wd)
        if watch:
            write_watch(wd, **(watch_kw or {}))
        if releases is None:
            r, f = release_set()
            releases, files = [r], f
        self.source = source or FakeSource(releases, files or {})
        self.api = api or FakeApi()
        self.data, self.oks = build.build_data(self.source, self.api, REPO, "projects", wd if watch else None, now, HEX,
                                               loader or projects_loader())
        self.html = render.render(self.data)


def visible(html_text):
    """ext 以外的文字（頁面自己的字）。"""
    return re.sub(r"<[^>]*>", " ", re.sub(r'<span class="ext">.*?</span>', " ", html_text, flags=re.S))


# ---------------------------------------------------------------- 觸發條件（DASHBOARD.md 第 5、9 節）

def wr(name, event, branch, repo=REPO, conclusion="success"):
    return {"workflow_run": {"name": name, "event": event, "head_branch": branch, "conclusion": conclusion,
                             "head_repository": {"full_name": repo}}}


class TestTrigger(unittest.TestCase):
    def go(self, event_name="workflow_run", event=None, ref="refs/heads/main"):
        return trigger.decide(event_name, event or {}, REPO, ref)[0]

    def test_watch_dev_on_main_update(self):
        for name in ("watch", "dev"):
            for ev in ("schedule", "workflow_dispatch", "push"):
                self.assertTrue(self.go(event=wr(name, ev, "main")), (name, ev))

    def test_watch_dev_other_branch_skipped(self):
        for name in ("watch", "dev"):
            for br in ("feature/x", "wp2/dashboard", "", None, "dev", "dev/", "dev/../main", "xdev/a"):
                self.assertFalse(self.go(event=wr(name, "push", br)), (name, br))
        self.assertFalse(self.go(event=wr("watch", "push", "dev/orin-nano-demo")))          # dev/** 只收 dev workflow

    def test_dev_branch_push_updates(self):
        """C0 決定：dev.yml 在 dev/** 分支 push 時也會更新滾動的開發版 → 也更新頁面；只收 push、同一個 repo。"""
        for br in ("dev/orin-nano-demo", "dev/rpi-lite-demo", "dev/a/b"):
            self.assertTrue(self.go(event=wr("dev", "push", br)), br)
        for ev in ("schedule", "workflow_dispatch", "pull_request", None):
            self.assertFalse(self.go(event=wr("dev", ev, "dev/orin-nano-demo")), ev)
        self.assertFalse(self.go(event=wr("dev", "push", "dev/orin-nano-demo", repo="evil/fork")))
        self.assertFalse(self.go(event=wr("dev", "push", "dev/orin-nano-demo", conclusion="cancelled")))

    def test_watch_dev_other_event_skipped(self):
        for ev in ("pull_request", "workflow_run", "release", None):
            self.assertFalse(self.go(event=wr("watch", ev, "main")), ev)

    def test_release_tag_push_updates(self):
        self.assertTrue(self.go(event=wr("release", "push", "orin-nano-demo/v39.2.1-demo1")))

    def test_release_dispatch_skipped(self):
        self.assertFalse(self.go(event=wr("release", "workflow_dispatch", "orin-nano-demo/v39.2.1-demo1")))
        self.assertFalse(self.go(event=wr("release", "workflow_dispatch", "main")))

    def test_release_branch_not_tag_format_skipped(self):
        for br in ("main", "feature/x", "dev/orin-nano-demo", "a/b/c", "UPPER/v1", "", None, "orin-nano-demo/"):
            self.assertFalse(self.go(event=wr("release", "push", br)), br)

    def test_release_uses_collect_classify(self):
        # 判定來自 collect.classify(tag, False)，不是 pages 自己的一份正規式
        for tag in ("orin-nano-demo/v39.2.1-demo1", "dev/orin-nano-demo", "main", "x/y/z", "a b/c"):
            self.assertEqual(self.go(event=wr("release", "push", tag)), collect.classify(tag, False)[0] == "release", tag)

    def test_fork_skipped_for_all_three(self):
        for name, ev, br in (("watch", "schedule", "main"), ("dev", "push", "main"), ("release", "push", "orin-nano-demo/v39.2.1-demo1")):
            self.assertFalse(self.go(event=wr(name, ev, br, repo="evil/demo")), name)
            self.assertFalse(self.go(event=wr(name, ev, br, repo=REPO + "x")), name)

    def test_missing_head_repository_skipped(self):
        e = wr("watch", "schedule", "main")
        del e["workflow_run"]["head_repository"]
        self.assertFalse(self.go(event=e))
        e["workflow_run"]["head_repository"] = None
        self.assertFalse(self.go(event=e))

    def test_cancelled_skipped_failure_updates(self):
        for name, ev, br in (("watch", "schedule", "main"), ("dev", "push", "main"), ("release", "push", "orin-nano-demo/v39.2.1-demo1")):
            self.assertFalse(self.go(event=wr(name, ev, br, conclusion="cancelled")), name)
            self.assertTrue(self.go(event=wr(name, ev, br, conclusion="failure")), name)

    def test_unknown_workflow_skipped(self):
        self.assertFalse(self.go(event=wr("pipeline", "push", "main")))
        self.assertFalse(self.go(event=wr(None, "push", "main")))

    def test_dispatch_only_on_main(self):
        self.assertTrue(self.go("workflow_dispatch", {}, "refs/heads/main"))
        self.assertFalse(self.go("workflow_dispatch", {}, "refs/heads/wp2/dashboard"))
        self.assertFalse(self.go("workflow_dispatch", {}, "refs/tags/x"))

    def test_other_events_skipped(self):
        for n in ("pull_request", "push", "schedule", ""):
            self.assertFalse(self.go(n, wr("watch", "schedule", "main")), n)

    def test_garbage_event_does_not_raise(self):
        for e in (None, [], "x", {"workflow_run": "x"}, {"workflow_run": {"name": ["watch"], "head_repository": {"full_name": ["x"]}}}):
            self.assertFalse(self.go(event=e))

    def test_cli_output(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "event.json")
            with open(p, "w") as f:
                json.dump(wr("release", "push", "orin-nano-demo/v39.2.1-demo1"), f)
            env = {"GITHUB_EVENT_NAME": "workflow_run", "GITHUB_EVENT_PATH": p, "GITHUB_REPOSITORY": REPO, "GITHUB_REF": "refs/heads/main"}
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.assertEqual(trigger.main(env), 0)
            lines = buf.getvalue().splitlines()
            self.assertEqual(lines[0], "go=true")
            self.assertTrue(lines[1].startswith("reason="))
            env["GITHUB_EVENT_PATH"] = os.path.join(d, "nope.json")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                trigger.main(env)
            self.assertTrue(buf.getvalue().startswith("go=false\n"))

    def test_reason_has_no_event_content(self):
        evil = "<script>alert(1)</script>"
        _go, reason = trigger.decide("workflow_run", wr("release", "push", evil), REPO, "refs/heads/main")
        self.assertNotIn(evil, reason)
        self.assertNotIn("\n", reason)


# ---------------------------------------------------------------- 跳脫與連結

class TestEscHref(unittest.TestCase):
    def test_esc_strips_controls_truncates_escapes(self):
        out = render.esc("a\x00b\x1b[0m\u202ec\r\nd<&>\"'")
        self.assertNotRegex(out, r"[\x00-\x08\x0b-\x1f\u202e]")
        self.assertIn("&lt;&amp;&gt;&quot;&#x27;", out)
        self.assertLess(len(render.esc("A" * 100000)), 300)
        self.assertTrue(render.esc("A" * 1000, 50).startswith("A" * 50))

    def test_safe_href_whitelist(self):
        ok = ["https://github.com/octo/demo/releases/download/demo/v1.0/a-b_c.1.zip",
              "https://github.com/octo/demo/releases/download/dev/orin-nano-demo/release-meta.json",
              "https://github.com/octo/demo/issues/114", "https://github.com/octo/demo/actions/runs/43677154264",
              "style.css", "data.json", "#projects"]
        for u in ok:
            self.assertEqual(render.safe_href(u, REPO), u, u)
        bad = ["https://evil.example/octo/demo/issues/1", "https://github.com/octo/other/issues/1", "https://github.com/octo/demo/issues/1?x=1",
               "https://github.com/octo/demo/issues/1#a", "https://github.com/octo/demo/issues/abc", "https://github.com/octo/demo/issues/",
               "https://github.com/octo/demo/pull/1", "https://github.com/octo/demo/actions/runs/1/../2",
               "https://github.com/octo/demo/releases/download/x", "https://github.com/octo/demo/releases/download/a/../../x",
               "https://github.com/octo/demo/releases/download/a/%2e%2e/x", "https://github.com/octo/demo/releases/download/a/b c",
               "https://github.com/octo/demo/releases/download/a/b?x=1", "http://github.com/octo/demo/issues/1",
               "https://github.com.evil.example/octo/demo/issues/1", "https://user" + "@" + "github.com/octo/demo/issues/1",   # 組字串：原始碼不含像信箱的字面值
               "//evil.example/x", "javascript:alert(1)", "data:text/html,x", "vbscript:x", "/etc/passwd", "../x", "other.css", "#a b", "",
               None, 5, ["x"]]
        for u in bad:
            self.assertIsNone(render.safe_href(u, REPO), u)
        self.assertIsNone(render.safe_href("https://github.com/octo/demo/issues/1", "../x"))
        self.assertIsNone(render.safe_href("https://github.com/octo/demo/issues/1", ""))

    def test_asset_name_rule(self):
        self.assertIsNone(render.asset_url(REPO, "demo/v1", "a b.zip"))
        self.assertIsNone(render.asset_url(REPO, "demo/v1", "<script>.zip"))
        self.assertIsNone(render.asset_url(REPO, "demo/v1", "a" * 201))
        u = render.asset_url(REPO, "demo/v1.0+x", "a+b.zip")
        self.assertEqual(u, "https://github.com/octo/demo/releases/download/demo/v1.0%2Bx/a%2Bb.zip")
        self.assertEqual(render.safe_href(u, REPO), u)

    def test_cve_validation(self):
        self.assertIn('class="cve"', render.cve_text("CVE-2024-12345"))
        for bad in ("CVE-2024-123", "cve-2024-12345", "CVE-2024-12345<script>", "CVE-2024-12345 ", "x"):
            self.assertNotIn('class="cve"', render.cve_text(bad), bad)
        self.assertNotIn("<script>", render.cve_text("CVE-2024-12345<script>"))


# ---------------------------------------------------------------- 頁面內容

class TestPage(unittest.TestCase):
    def test_basic_sections_and_csp(self):
        e = Env(self, api=FakeApi({"watch-state": [issue(114, "狀態", labels=("watch-state",), body=state_body())]}))
        h = e.html
        self.assertIn('<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'self\'; img-src \'self\'; '
                      'base-uri \'none\'; form-action \'none\'">', h)
        for s in ("demo/v1.0", "Demo 產品", "#114", "基準時間", "2026-11-15T04:28:30Z", "run 555", "每日沒有涵蓋的項目", "DT：每天沒有重跑"):
            self.assertIn(s, h)
        self.assertEqual(check_site.check_html(h, REPO), [])
        self.assertNotIn("<script", h)
        self.assertNotRegex(h, r"\sstyle\s*=")
        self.assertEqual(e.oks, {"releases": True, "issues": True, "projects": True, "watch": True})

    def test_no_safe_word_no_pass_outside_ext(self):
        e = Env(self)
        self.assertNotRegex(visible(e.html), r"安全|(?i:\bPASS\b)")
        for bad in ("✓", "✔", "☑", "✅"):
            self.assertNotIn(bad, e.html)

    def test_vex_counts(self):
        e = Env(self)
        full = e.data["releases"]["rows"][0]["vex"]["full"]
        self.assertEqual(full["total"], 3)
        self.assertEqual(full["counts"], [["not_affected", "code_not_present", 2], ["in_triage", "—", 1]])
        self.assertEqual(e.data["releases"]["rows"][0]["vex"]["os"]["counts"], [])

    def test_vex_unknown_values_become_unknown(self):
        v = vex([{"analysis": {"state": "<script>", "justification": "javascript:alert(1)"}},
                 {"analysis": {"state": "not_affected", "justification": "made_up"}}, {"analysis": "x"}, "junk", {}])
        r, f = release_set(vex_obj=v)
        e = Env(self, [r], f)
        c = {tuple(x[:2]): x[2] for x in e.data["releases"]["rows"][0]["vex"]["full"]["counts"]}
        self.assertEqual(c[("不明", "不明")], 1)
        self.assertEqual(c[("not_affected", "不明")], 1)
        self.assertEqual(c[("（未填）", "—")], 3)
        self.assertNotIn("<script>", e.html)
        self.assertNotIn("made_up", e.html)

    def test_vex_kinds_by_filename(self):
        found = build.pick_vex({"vex-p-v1-bsp.cdx.json": 1, "vex-p-v1-os.cdx.json": 1, "vex-p-v1.cdx.json": 1, "vex-p-v1.json": 1, "other": 1})
        self.assertEqual(found, {"full": ["vex-p-v1.cdx.json"], "bsp": ["vex-p-v1-bsp.cdx.json"], "os": ["vex-p-v1-os.cdx.json"]})

    def test_vulnerability_numbers_always_have_status(self):
        e = Env(self, api=FakeApi())
        h = e.html
        cells = re.findall(r'<div class="vcell">(.*?)</div></div>', h, re.S)
        self.assertGreaterEqual(len(cells), 4)     # 3 份報告的漏洞統計＋每份 SBOM 的已遭利用命中數
        for c in cells:
            self.assertIn("release_gate", c)
            self.assertRegex(c, r"report_status|grype")
        # 沒有任何「單獨」的漏洞數：p1／CVE 總數只出現在 vcell 裡
        outside = re.sub(r'<div class="vcell">.*?</div></div>', "", h, flags=re.S)
        self.assertNotRegex(outside, r"CVE 總數|p1 \d|已遭利用（KEV）命中數 \d")
        # report_status 缺少時顯示成不明，不是消失
        s = scan()
        del s["runs"][""]["report_status"]
        r, f = release_set(scan_obj=s)
        e2 = Env(self, [r], f)
        self.assertIn('不明（<span class="ext">無值</span>）', e2.html)

    def test_unknown_status_shown_as_unknown_and_warned(self):
        for evil in EVIL:
            r, f = release_set(meta_over={"report_status": evil})
            e = Env(self, [r], f)
            self.assertIn("不明（", e.html)
            self.assertIn("狀態值不認得", e.html)
            self.assertNotIn("<script>", e.html)
            self.assertNotIn("<img", e.html)
            self.assertEqual(check_site.check_html(e.html, REPO), [], evil[:20])
        e = Env(self)
        self.assertNotIn("狀態值不認得", e.html)
        r, f = release_set(meta_over={"report_status": "PASS"})
        e = Env(self, [r], f)
        self.assertIn("不明（<span class=\"ext\">PASS</span>）", e.html)
        self.assertEqual(check_site.check_html(e.html, REPO), [])

    def test_status_values_only_from_fixed_list(self):
        ctx = render.Ctx(REPO)
        for s in render.STATUSES:
            self.assertIn("st-" + s, ctx.st(s))
        for bad in ("ok", "PASS", "SAFE", "", None, 5, ["OK"], "OK "):
            self.assertIn("st-unknown", ctx.st(bad), repr(bad))
        self.assertEqual(len(ctx.unknown), 8)       # 每個不同的不明值各記一次（頁首警告用）

    def test_draft_not_listed(self):
        r, f = release_set()
        d, df = release_set(tag="demo/v9.9-draft", version="v9.9-draft")
        d["draft"] = True
        e = Env(self, [r, d], {**f, **df})
        self.assertNotIn("v9.9-draft", e.html)
        self.assertNotIn("v9.9-draft", json.dumps(e.data))
        self.assertEqual([x["tag"] for x in e.data["releases"]["rows"]], ["demo/v1.0"])

    def test_release_and_dev_classification_and_skipped(self):
        r1, f1 = release_set()
        r2, f2 = release_set(tag="dev/demo", version="v1.0", prerelease=True, meta_over={})
        r3 = rel("something-else", names=[])
        r4 = rel("demo/v2.0", prerelease=True)         # 正式版格式卻是 prerelease：不合規則
        e = Env(self, [r1, r2, r3, r4], {**f1, **f2})
        kinds = {x["tag"]: x["kind"] for x in e.data["releases"]["rows"]}
        self.assertEqual(kinds, {"demo/v1.0": "release", "dev/demo": "dev"})
        self.assertEqual(len(e.data["releases"]["skipped"]), 2)
        self.assertIn("不合規則，沒有列入", e.html)
        p = e.data["projects"]["rows"][0]
        self.assertEqual((p["latest_release"], p["dev_release"]), ("demo/v1.0", "dev/demo"))

    def test_attachment_gap_cells_page_still_built(self):
        r, f = release_set()
        f[("demo/v1.0", "scan-summary-demo-v1.0.json")] = collect.AssetError("下載回 HTTP 404")
        f[("demo/v1.0", "vex-demo-v1.0-bsp.cdx.json")] = b"{not json"
        f[("demo/v1.0", "release-meta.json")] = b'{"schema": 2}'
        r2, f2 = release_set(tag="demo/v2.0", version="v2.0", drop=("vex-demo-v2.0.cdx.json", "scan-summary-demo-v2.0.json"))
        e = Env(self, [r, r2], {**f, **f2})
        rows = {x["tag"]: x for x in e.data["releases"]["rows"]}
        a, b = rows["demo/v1.0"], rows["demo/v2.0"]
        self.assertIn("schema", a["meta"]["gap"])
        self.assertIn("下載失敗", a["scan"]["gap"])
        self.assertIn("不是合法 JSON", a["vex"]["bsp"]["gap"])
        self.assertIsNone(a["vex"]["full"]["gap"])
        self.assertIn("沒有 scan-summary", b["scan"]["gap"])
        self.assertIn("沒有這份報告的 vex", b["vex"]["full"]["gap"])
        self.assertIsNone(b["meta"]["gap"])
        self.assertIn("GAP", e.html)
        self.assertEqual(check_site.check_html(e.html, REPO), [])

    def test_size_limits(self):
        r, f = release_set()
        r["assets"]["vex-demo-v1.0.cdx.json"][0].size = 33 * 1024 * 1024
        r["assets"]["scan-summary-demo-v1.0.json"][0].size = 9 * 1024 * 1024
        e = Env(self, [r], f)
        row = e.data["releases"]["rows"][0]
        self.assertIn("超過大小上限", row["vex"]["full"]["gap"])
        self.assertIn("超過大小上限", row["scan"]["gap"])

    def test_duplicate_scan_summary_is_gap(self):
        r, f = release_set(extra_names=["scan-summary-other.json"])
        e = Env(self, [r], f)
        self.assertIn("2 個 scan-summary", e.data["releases"]["rows"][0]["scan"]["gap"])

    def test_downloads_links_and_sizes(self):
        e = Env(self)
        h = e.html
        self.assertIn('href="https://github.com/octo/demo/releases/download/demo/v1.0/release-meta.json" rel="noopener noreferrer"', h)
        self.assertRegex(h, r"release-meta\.json</span></a> <span class=\"muted\">\d+ B")

    def test_issues_listing_state_drill_and_closed(self):
        api = FakeApi({
            "watch-state": [issue(114, "state", labels=("demo", "watch-state"), body=state_body())],
            "dumpling-watch": [issue(5, "[KEV] CVE-2024-12345 在 demo v1.0", labels=("kev",)),
                               issue(6, "closed one", state="closed", labels=("kev",)),
                               issue(7, "DRILL-ONE", labels=("dumpling-watch", "drill")),
                               issue(8, "DRILL-TWO", state="closed", labels=("dumpling-watch", "kev-drill-done")),
                               issue(9, "DRILL-THREE", labels=("dumpling-watch", "art14-drill"))],
            "support-period": [issue(20, "[支援期限] Demo 產品", labels=("support-period",))],
            "watch-health": []})
        e = Env(self, api=api)
        h = e.html
        self.assertIn('href="https://github.com/octo/demo/issues/5"', h)
        self.assertIn('<span class="cve">CVE-2024-12345</span>', h)
        self.assertIn("<details><summary>已關閉（1）</summary>", h)
        self.assertIn('href="https://github.com/octo/demo/issues/20"', h)
        for n in (7, 8, 9):
            self.assertNotIn("issues/%d\"" % n, h)
        self.assertNotIn("DRILL-", h)
        st = e.data["watch"]["state_issue"]
        self.assertEqual((st["number"], st["matches"], st["vendor_matches"], st["baseline_at"], st["last_run"]["run_id"]),
                         (114, 2, 1, "2026-11-15T04:29:16Z", "777"))
        self.assertEqual(e.data["projects"]["rows"][0]["open_issues"], 2)       # #5 標題含 demo、#20 含 Demo 產品

    def test_issue_api_failure_is_gap_for_that_group(self):
        api = FakeApi({"watch-state": [issue(114, "s", labels=("watch-state",), body="bad body")]},
                      fail={"support-period": issues.Fail("GET 失敗：HTTP 500")})
        e = Env(self, api=api)
        self.assertIn("Issues API 讀不到（support-period）", e.html)
        self.assertIn("狀態 Issue #114 解不開", e.html)
        self.assertEqual(e.oks["issues"], True)
        self.assertEqual(check_site.check_html(e.html, REPO), [])

    def test_stale_watch_warning(self):
        e = Env(self, watch_kw={"created": "2026-11-12T00:00:00Z"})
        self.assertIn("GAP：監控資料過期（超過 36 小時沒更新）", e.html)
        self.assertIn('<span class="st st-GAP">監控資料過期</span>', e.html)
        e = Env(self, watch_kw={"created": "2026-11-13T19:00:00Z"})            # 35 小時：還沒過期
        self.assertNotIn("監控資料過期", e.html)
        e = Env(self)
        self.assertNotIn("監控資料過期", e.html)
        e = Env(self, watch=False)
        self.assertIn("GAP：沒有找到最近一輪監控資料", e.html)
        self.assertIn("GAP", e.html)

    def test_watch_missing_pieces_are_gap(self):
        with tempfile.TemporaryDirectory() as d:
            write_watch(d, with_report=False)
            os.unlink(os.path.join(d, "watch-support-real-1", "result.json"))
            r, f = release_set()
            data, oks = build.build_data(FakeSource([r], f), FakeApi(), REPO, "projects", d, NOW, None, projects_loader())
            h = render.render(data)
            self.assertTrue(data["watch"]["support"]["gap"])
            self.assertIn("watch-support result.json", h)
            self.assertTrue(data["watch"]["coverage_gap"])
            self.assertTrue(oks["watch"])

    def test_project_errors_and_missing_support_row(self):
        rows = [("bad", "projects/bad", None, "project.yml 欄位錯誤：x<script>"), ("demo", "projects/demo", {
            "product_name": "D", "status": "weird", "support_until": "nonsense"}, None)]
        e = Env(self, loader=projects_loader(rows))
        self.assertIn("不明（", e.html)
        self.assertNotIn("<script>", e.html)
        self.assertEqual(check_site.check_html(e.html, REPO), [])

    def test_all_sources_failing_exits_nonzero_and_writes_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "site")

            def boom(_):
                raise RuntimeError("no yaml")
            fail = {k: issues.Fail("HTTP 500") for k in build.LABELS.values()}
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = build.run(["--repo", REPO, "--out", out, "--projects-dir", d, "--watch-dir", os.path.join(d, "nope")],
                               env={}, source=FakeSource([], {}, boom=collect.ApiError("API 回 HTTP 500")), api=FakeApi(fail=fail), load_projects=boom)
            self.assertEqual(rc, 1)
            self.assertFalse(os.path.exists(out))
            self.assertIn("Releases API 與 Issues API 都抓不到", buf.getvalue())

    def test_api_sources_failing_exits_nonzero_even_if_projects_ok(self):
        """預驗必修 1：CI 裡專案清單讀 checkout，一定成功；Releases 與 Issues 兩個 API 都抓不到就不能部署空頁。"""
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "site")
            fail = {k: issues.Fail("HTTP 500") for k in build.LABELS.values()}
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = build.run(["--repo", REPO, "--out", out, "--now", "2026-11-15T06:00:00Z"], env={},
                               source=FakeSource([], {}, boom=collect.ApiError("API 回 HTTP 500")), api=FakeApi(fail=fail),
                               load_projects=projects_loader())
            self.assertEqual(rc, 1)
            self.assertFalse(os.path.exists(out))
            self.assertIn("Releases API 與 Issues API 都抓不到", buf.getvalue())

    def test_partial_failure_still_builds(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "site")
            fail = {k: issues.Fail("HTTP 500") for k in build.LABELS.values()}
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = build.run(["--repo", REPO, "--out", out, "--now", "2026-11-15T06:00:00Z"], env={},
                               source=FakeSource([], {}, boom=collect.ApiError("API 回 HTTP 500")), api=FakeApi(fail=dict(list(fail.items())[:1])),
                               load_projects=projects_loader())
            self.assertEqual(rc, 0)       # Releases 抓不到、Issues 部分可讀 → 照常產生（那幾格 GAP）
            self.assertEqual(sorted(os.listdir(out)), ["data.json", "index.html", "style.css"])
            with open(os.path.join(out, "index.html"), encoding="utf-8") as f:
                h = f.read()
            self.assertIn("Releases API 讀不到", h)
            self.assertEqual(check_site.check_html(h, REPO), [])
            with open(os.path.join(out, "data.json"), encoding="utf-8") as f:
                self.assertEqual(json.load(f)["schema"], build.SCHEMA)

    def test_token_never_in_output(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "site")
            r, f = release_set()
            leak = "Bearer " + TOKEN
            fail = {"support-period": issues.Fail("GET 失敗 " + leak)}
            api = FakeApi({"dumpling-watch": [issue(5, "title has " + TOKEN)]}, fail=fail)
            f[("demo/v1.0", "vex-demo-v1.0-bsp.cdx.json")] = collect.AssetError("下載失敗 " + TOKEN)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = build.run(["--repo", REPO, "--out", out, "--now", "2026-11-15T06:00:00Z"], env={"GITHUB_TOKEN": TOKEN},
                               source=FakeSource([r], f), api=api, load_projects=projects_loader())
            self.assertEqual(rc, 0)
            for name in os.listdir(out):
                with open(os.path.join(out, name), encoding="utf-8") as fh:
                    self.assertNotIn(TOKEN, fh.read(), name)
            self.assertNotIn(TOKEN, buf.getvalue())
            self.assertEqual(build._SCRUB[0], TOKEN)     # run() 設定的；測試結束前清掉
            build._SCRUB[0] = ""

    def test_write_site_refuses_token(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(RuntimeError):
                build.write_site({"repo": REPO, "x": TOKEN}, os.path.join(d, "s"), TOKEN)

    def test_data_json_has_whitelist_fields_only(self):
        e = Env(self)
        self.assertEqual(sorted(e.data), ["commit", "firmware", "generated_at", "issues", "projects", "releases", "repo", "schema", "sources", "warnings", "watch"])
        text = json.dumps(e.data)
        for k in ("GITHUB_TOKEN", "Authorization", "browser_download_url"):
            self.assertNotIn(k, text)


# ---------------------------------------------------------------- 惡意字串

class TestMalicious(unittest.TestCase):
    def check(self, e, evil):
        h = e.html
        self.assertEqual(check_site.check_html(h, REPO), [], evil[:30])
        self.assertNotIn("<script", h.lower())
        self.assertNotIn("<img", h.lower())
        self.assertNotIn('"><img', h)
        self.assertNotRegex(h, r"[\x00-\x08\x0b-\x1f\u202e]")
        self.assertNotIn("A" * 1000, h)
        for m in re.finditer(r'href="([^"]*)"', h):
            self.assertIsNotNone(render.safe_href(m.group(1).replace("&amp;", "&"), REPO), m.group(1))
        self.assertNotIn("javascript:", re.sub(r'<span class="ext">.*?</span>', "", h, flags=re.S))
        return h

    def test_in_stage_names_and_status_and_notes(self):
        for evil in EVIL:
            stages = {evil: "GAP", "X-" + evil[:20]: evil}
            s = scan(runs={"": run_entry(stages=stages), "-bsp": run_entry(), "-os": run_entry()})
            r, f = release_set(scan_obj=s, meta_over={"platform": "p", "attention": [evil]})
            plan = {"status": evil, "detail": evil, "per_sbom": {"u": {"tag": evil, "layer": evil, "grype": evil, "why": evil,
                                                                       "report_status": evil, "release_gate": evil, "kernel_map": evil,
                                                                       "kernel_cna": evil, "exploited": evil}},
                    "notes": [evil], "attention": [evil], "gaps": [evil], "stats": {}}
            sup = {"status": evil, "detail": evil, "today": evil, "rows": [[evil, evil, evil]]}
            e = Env(self, [r], f, watch_kw={"plan": plan, "support": sup})
            self.check(e, evil)

    def test_in_issue_titles_and_labels(self):
        for evil in EVIL:
            api = FakeApi({"dumpling-watch": [issue(5, evil, labels=(evil, "kev")), issue(6, evil, state="closed")],
                           "support-period": [issue(7, evil)], "watch-health": [issue(8, evil)],
                           "watch-state": [issue(114, evil, labels=("watch-state",), body=evil)]})
            self.check(Env(self, api=api), evil)

    def test_in_tags_and_attachment_names(self):
        for evil in EVIL:
            bad_tag = rel(evil, names=[])
            bad_tag2 = rel("demo/" + evil, names=[])
            r, f = release_set(extra_names=["report-%s.zip" % evil, "vuln-list-%s.xlsx" % evil, evil])
            e = Env(self, [bad_tag, bad_tag2, r], f)
            h = self.check(e, evil)
            self.assertNotIn("/releases/download/" + evil, h)

    def test_in_project_names(self):
        for evil in EVIL:
            rows = [(evil, "d", {"product_name": evil, "status": evil, "support_until": evil}, None), ("e", "d", None, evil)]
            e = Env(self, loader=projects_loader(rows))
            self.check(e, evil)

    def test_in_warnings_and_repo(self):
        for evil in EVIL:
            data = {"repo": evil, "generated_at": evil, "commit": evil, "warnings": [evil], "projects": evil, "releases": evil,
                    "watch": evil, "issues": evil}
            h = render.render(data)
            self.check(type("E", (), {"html": h})(), evil)

    def test_garbage_data_does_not_raise(self):
        for data in (None, [], "x", 5, {}, {"releases": {"rows": ["x", None, 5, {"meta": "x", "scan": [], "vex": 5, "downloads": "x"}]}},
                     {"projects": {"rows": [None, {"support_check": 5}]}, "issues": {"kev": {"rows": [5, {"number": "x"}]}}}):
            h = render.render(data)
            self.assertEqual(check_site.check_html(h, REPO), [])

    def test_hrefs_only_whitelisted_in_normal_page(self):
        api = FakeApi({"dumpling-watch": [issue(5, "x")], "watch-state": [issue(114, "s", labels=("watch-state",), body=state_body())]})
        h = Env(self, api=api).html
        hrefs = re.findall(r'href="([^"]*)"', h)
        self.assertGreater(len(hrefs), 10)
        for u in hrefs:
            self.assertIsNotNone(render.safe_href(u, REPO), u)
        self.assertTrue(all('rel="noopener noreferrer"' in a or "href=\"#" in a or "style.css" in a or "data.json" in a
                            for a in re.findall(r"<a [^>]*>|<link [^>]*>", h)))

    def test_non_whitelisted_urls_shown_as_text_only(self):
        # 狀態 Issue 的 run_url 指到別的 repo：不出連結
        st = {"schema": 1, "dumpling": {"baseline_at": "x"}, "matches": {}, "vendor_matches": {},
              "runs": [{"at": "t", "status": "OK", "detail": "d", "run_url": "https://evil.example/octo/demo/actions/runs/1"}]}
        body = issues.encode_state(st, "real", "s")
        e = Env(self, api=FakeApi({"watch-state": [issue(114, "s", labels=("watch-state",), body=body)]}))
        self.assertIsNone(e.data["watch"]["state_issue"]["last_run"]["run_id"])
        self.assertNotIn("evil.example", e.html)


# ---------------------------------------------------------------- check_site

class TestCheckSite(unittest.TestCase):
    def setUp(self):
        self.html = Env(self, api=FakeApi({"dumpling-watch": [issue(5, "t")]})).html

    def test_clean_page_passes(self):
        self.assertEqual(check_site.check_html(self.html, REPO), [])

    def test_mutation_pass_outside_ext_fails(self):
        for word in ("PASS", "pass", "Pass"):
            mut = self.html.replace("<main>", "<main><p>%s</p>" % word, 1)
            self.assertTrue(check_site.check_html(mut, REPO), word)
        mut = self.html.replace("<main>", "<main><p>很安全</p>", 1)
        self.assertTrue(check_site.check_html(mut, REPO))

    def test_mutation_script_fails(self):
        mut = self.html.replace("</body>", "<script>alert(1)</script></body>")
        self.assertTrue(check_site.check_html(mut, REPO))
        mut = self.html.replace("<main>", "<main><SCRIPT src=x>", 1)
        self.assertTrue(check_site.check_html(mut, REPO))

    def test_mutation_event_handler_and_javascript_href_fail(self):
        self.assertTrue(check_site.check_html(self.html.replace("<main>", '<main onclick="x()">', 1), REPO))
        self.assertTrue(check_site.check_html(self.html.replace("<main>", '<a href="javascript:alert(1)">x</a><main>', 1), REPO))
        self.assertTrue(check_site.check_html(self.html.replace("<main>", '<p style="color:red"><main>', 1), REPO))

    def test_mutation_href_outside_whitelist_fails(self):
        mut = self.html.replace("<main>", '<main><a href="https://evil.example/" rel="noopener noreferrer">x</a>', 1)
        self.assertTrue(any("href 不在白名單" in p for p in check_site.check_html(mut, REPO)))
        mut = self.html.replace("<main>", '<main><a href="https://github.com/octo/demo/issues/1">x</a>', 1)
        self.assertTrue(any("rel" in p for p in check_site.check_html(mut, REPO)))

    def test_mutation_missing_or_changed_csp_fails(self):
        mut = re.sub(r'<meta http-equiv="Content-Security-Policy"[^>]*>', "", self.html)
        self.assertTrue(any("Content-Security-Policy" in p for p in check_site.check_html(mut, REPO)))
        mut = self.html.replace("default-src 'none'", "default-src *")
        self.assertTrue(check_site.check_html(mut, REPO))

    def test_ext_content_is_exempt(self):
        mut = self.html.replace("<main>", '<main><span class="ext">這很安全 PASS onerror=alert(1) javascript:x</span>', 1)
        self.assertEqual(check_site.check_html(mut, REPO), [])
        # ext 以外才檢查：把 ext 拆開（跳出 ext）會被抓
        mut = self.html.replace("<main>", '<main><span class="ext">x</span> PASS', 1)
        self.assertTrue(check_site.check_html(mut, REPO))

    def test_check_site_directory_and_cli(self):
        with tempfile.TemporaryDirectory() as d:
            build.write_site(Env(self).data, d)
            self.assertEqual(check_site.check_site(d, REPO), [])
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.assertEqual(check_site.main(["--repo", REPO, "--site", d]), 0)
            self.assertIn("CHECK-SITE\tOK", buf.getvalue())
            with open(os.path.join(d, "index.html"), "a", encoding="utf-8") as f:
                f.write("<script>1</script>")
            with open(os.path.join(d, "style.css"), "a", encoding="utf-8") as f:
                f.write("@import url(https://evil.example/x.css);")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.assertEqual(check_site.main(["--repo", REPO, "--site", d]), 1)
            self.assertIn("@import", buf.getvalue())
            os.unlink(os.path.join(d, "data.json"))
            self.assertTrue(any("缺少 data.json" in p for p in check_site.check_site(d, REPO)))

    def test_css_has_no_external_loads_and_dark_mode(self):
        with open(os.path.join(HERE, "..", "style.css"), encoding="utf-8") as f:
            css = f.read()
        self.assertEqual(check_site.check_css(css), [])
        self.assertIn("prefers-color-scheme: dark", css)
        self.assertIn("overflow-x: auto", css)
        self.assertIn("meta", self.html)
        self.assertIn('name="viewport"', self.html)


if __name__ == "__main__":
    unittest.main()


class PreVerifyFixes(unittest.TestCase):
    """wp2/dashboard 預驗（a9aa4c1）的必修 2 與建議 1、2、4、5。"""

    def test_ext_content_must_be_escaped(self):
        good = '<p><span class="ext">a &amp; b &lt;x&gt; &quot;q&quot; &#x27;</span></p>'
        self.assertEqual([p for p in check_site.check_html(good, REPO) if "ext 的內容" in p], [])
        for raw in ('"><img src=x onerror=alert(1)>', "<a href=//evil.example>x</a>", "<svg onload=1>", "&commat;bob", "it's"):
            with self.subTest(raw=raw):
                h = '<p><span class="ext">%s</span></p>' % raw
                self.assertTrue([p for p in check_site.check_html(h, REPO) if "ext 的內容" in p], raw)

    def test_esc_broken_is_caught_by_check_site(self):
        """突變：ext() 不跳脫時，只帶 <img onerror> 的敵意資料也要被 check_site 擋下（不能只靠單元測試）。"""
        orig = render.ext
        try:
            render.ext = lambda s, n=render.DEFAULT_LEN: '<span class="ext">%s</span>' % render.clean(s, n)
            h = render.ext('"><img src=x onerror=alert(1)>')
        finally:
            render.ext = orig
        self.assertTrue(check_site.check_html('<meta http-equiv="Content-Security-Policy" content="%s">%s'
                                              % (check_site.EXPECTED_CSP, h), REPO))

    def test_csp_hardcoded_in_check_site(self):
        self.assertEqual(check_site.EXPECTED_CSP, render.CSP)
        weak = check_site.EXPECTED_CSP.replace("style-src 'self'", "style-src 'self' 'unsafe-inline'")
        probs = check_site.check_html('<meta http-equiv="Content-Security-Policy" content="%s">' % weak, REPO)
        self.assertTrue([p for p in probs if "Content-Security-Policy" in p])

    def test_ping_and_srcset_rejected(self):
        for attr in ('<a href="#a" ping="https://evil.example/">x</a>', '<a href="#a" srcset="x 1x">x</a>'):
            with self.subTest(attr=attr):
                self.assertTrue([p for p in check_site.check_html(attr, REPO) if "屬性" in p])

    def test_clean_surrogates_invisible_and_huge_int(self):
        self.assertNotIn("\ud800", render.clean("a\ud800b"))
        "x".join([render.esc("a\ud800b")]).encode("utf-8")                    # 寫檔不會 UnicodeEncodeError
        for ch in ("\u061c", "\u00ad", "\u034f", "\u180e", "\U000e0041", "\u202e", "\u200b"):
            with self.subTest(ch=hex(ord(ch))):
                self.assertNotIn(ch, render.clean("a" + ch + "b"))
        import sys as _s
        if hasattr(_s, "set_int_max_str_digits"):
            self.assertEqual(render.clean(10 ** 5000), "（數值過大）")


class CountsWithStatus(unittest.TestCase):
    """C0 決定（2026-11-15）：數量旁邊要有狀態或時間，讓人知道數字新不新。"""

    def test_vex_counts_have_release_gate(self):
        e = Env(self)
        sec = e.html[e.html.index("VEX 判定統計"):]
        sec = sec[:sec.index("</table>")]
        rows = [r for r in sec.split("<tr>")[2:]]
        self.assertTrue(rows)
        for r in rows:
            self.assertRegex(r, r'<span class="st st-[A-Z_]+">', r)               # 每一列都附上該報告的 release_gate

    def test_state_issue_counts_and_project_open_issues_have_freshness(self):
        api = FakeApi({"watch-state": [issue(114, "s", labels=("watch-state",), body=state_body())]})
        e = Env(self, api=api)
        i = e.html.index("<dt>比對數</dt>")
        self.assertIn("最近一輪監控", e.html[i:i + 400])
        j = e.html.index("開著的監控 Issue")
        self.assertIn("最近一輪監控", e.html[j:j + 3000])
        self.assertEqual(check_site.check_html(e.html, REPO), [])


    def test_no_watch_run_counts_show_gap_not_blank(self):
        """C0：完全沒有監控 run（freshness 讀不到）→ 比對數與開著的 Issue 數旁邊寫「沒有最近一輪監控資料」（GAP），頁首也有 GAP 警告；不能空白或像 OK。"""
        api = FakeApi({"watch-state": [issue(114, "s", labels=("watch-state",), body=state_body())]})
        e = Env(self, api=api, watch=False)
        self.assertIn("GAP：沒有找到最近一輪監控資料", e.html[:e.html.index("</header>")])
        gap = '<span class="st st-GAP">GAP</span>（<span class="ext">沒有最近一輪監控資料</span>）'
        i = e.html.index("<dt>比對數</dt>")
        self.assertIn(gap, e.html[i:i + 600])
        j = e.html.index("開著的監控 Issue")
        self.assertIn(gap, e.html[j:j + 3000])
        self.assertNotIn("最近一輪監控 <span", e.html)                      # 沒有假的時間
        self.assertEqual(check_site.check_html(e.html, REPO), [])


class MissingDataIsGap(unittest.TestCase):
    """C0 獨立驗證（982c111）的應修與建議：缺資料不能看起來像沒事（硬性限制 5）。"""

    def env_scan(self, runs, meta_over=None):
        r, f = release_set(scan_obj={"runs": runs, "components": {"total": 1}}, meta_over=meta_over)
        return Env(self, releases=[r], files=f)

    def section(self, html, start, end="</article>"):
        i = html.index(start)
        return html[i:html.index(end, i)]

    def test_missing_stages_is_gap_not_all_ok(self):
        for bad in (None, [], "x", {}):
            with self.subTest(bad=bad):
                e1 = run_entry()
                e1["stages"] = bad
                if bad is None:
                    del e1["stages"]
                e = self.env_scan({"": e1, "-bsp": run_entry(), "-os": run_entry()})
                sec = self.section(e.html, "不是 OK 的階段", "漏洞統計")
                self.assertIn("沒有 stages", sec)
                self.assertNotIn("都是 OK", sec)
        e = self.env_scan({"": run_entry(stages={"A": "OK"}), "-bsp": run_entry(stages={"A": "OK"}), "-os": run_entry(stages={"A": "OK"})})
        self.assertIn("每份報告的階段都是 OK", e.html)           # 真的都有、都是 OK 才寫

    def test_tiers_missing_or_invalid_listed_as_gap(self):
        e = self.env_scan({"": run_entry(tiers={"p1": "5", "p2": 2, "p3": -1, "accepted": True}), "-bsp": run_entry(), "-os": run_entry()})
        sec = self.section(e.html, "漏洞統計（含該報告的狀態）", "</table>")
        full = sec[sec.index('<span class="ext">full</span>'):sec.index('<span class="ext">bsp</span>')]
        for k in ("p1", "p3", "accepted"):
            self.assertIn('%s <span class="st st-GAP">GAP</span>（格式不對）' % k, full)
        self.assertIn("p2 2", full)
        self.assertIn('nvidia_bulletin <span class="st st-GAP">GAP</span>（缺）', full)
        e1 = run_entry()
        e1["vulnerabilities"] = {"cves_total": 1}
        e = self.env_scan({"": e1, "-bsp": run_entry(), "-os": run_entry()})
        self.assertIn("沒有 tiers", e.html)
        self.assertNotIn("沒有分級計數", e.html)

    def test_meta_report_missing_in_scan_runs(self):
        e = self.env_scan({"": run_entry(), "-bsp": run_entry()})            # meta 有 full／bsp／os，scan 沒有 -os
        self.assertIn("scan-summary 的 runs 沒有這份報告（release-meta 有列）", e.html)
        self.assertIn("scan-summary 的 runs 沒有這份報告", self.section(e.html, "不是 OK 的階段", "漏洞統計"))

    def test_api_failure_in_header(self):
        e = Env(self, source=FakeSource([], {}, boom=collect.ApiError("API 回 HTTP 500")))
        self.assertIn("GAP：Releases API 讀不到", e.html[:e.html.index("</header>")])
        e = Env(self, api=FakeApi(fail={"support-period": issues.Fail("HTTP 500")}))
        self.assertIn("GAP：Issues API 讀不到（support-period）", e.html[:e.html.index("</header>")])

    def test_issue_null_title_created_and_bad_state(self):
        bad = issue(7, "x", state="weird")
        bad["title"], bad["created_at"] = None, None
        e = Env(self, api=FakeApi({"dumpling-watch": [bad]}))
        self.assertNotIn(">None<", e.html)
        self.assertNotIn('"ext">None', e.html)
        self.assertIn("沒有標題", e.html)
        self.assertIn("（沒有）", e.html)
        self.assertIn("state 不是 open／closed", e.html[:e.html.index("</header>")])
        self.assertEqual(check_site.check_html(e.html, REPO), [])

    def test_safe_href_other_host_same_length(self):
        self.assertEqual(len("https://gitlab.com/"), len(render.BASE))
        for u in ("https://gitlab.com/%s/issues/1" % REPO, "https://githuc.com/%s/issues/1" % REPO,
                  "https://github.com.evil.example/%s/issues/1" % REPO, "http://github.com/%s/issues/1" % REPO):
            with self.subTest(u=u):
                self.assertIsNone(render.safe_href(u, REPO))
        self.assertIsNotNone(render.safe_href("https://github.com/%s/issues/1" % REPO, REPO))

    def test_distro_fixed_unknown_tier_and_gap_note(self):
        """C0／C1：distro_fixed 也是已知分級；不認得的分級（"None"）標成不明；GAP 的原因寫在漏洞統計下方與頁尾。"""
        e = self.env_scan({"": run_entry(tiers={"p1": 1, "p2": 0, "p3": 2, "accepted": 3, "distro_fixed": 4, "nvidia_bulletin": 5, "None": 6}),
                           "-bsp": run_entry(), "-os": run_entry()})
        sec = self.section(e.html, "漏洞統計（含該報告的狀態）", "</table>")
        full = sec[sec.index('<span class="ext">full</span>'):sec.index('<span class="ext">bsp</span>')]
        self.assertIn("distro_fixed 4", full)
        self.assertIn("p2 0", full)
        self.assertIn('<span class="ext">None</span> 6', full)
        self.assertIn("不明", full)
        self.assertIn("產生端目前只寫有出現的分級，所以 GAP 可能代表 0", e.html)
        foot = e.html[e.html.index("<footer"):]
        self.assertIn("所以 GAP 可能代表 0", foot)
        self.assertIn("不認得的分級", e.html[:e.html.index("</header>")])     # 頁首的「不認得的狀態值」警告
        self.assertEqual(check_site.check_html(e.html, REPO), [])

    def test_new_tiers_format(self):
        """C1 的新格式：6 個 key 都寫（0 也寫）、清單外放 tiers_unknown。新格式缺 key 是真的異常；tiers_unknown 有值 → 不明＋頁首警告。"""
        full = {"p1": 0, "p2": 0, "p3": 2, "accepted": 0, "distro_fixed": 0, "nvidia_bulletin": 0}
        e1 = run_entry(tiers=dict(full))
        e1["vulnerabilities"]["tiers_unknown"] = {"None": 3}
        e1["vulnerabilities"]["rows_total"] = 5                                  # 2 ＋ 3（合計要一致）
        e2 = run_entry(tiers={k: v for k, v in full.items() if k != "accepted"})
        e2["vulnerabilities"]["tiers_unknown"] = {}
        e3 = run_entry(tiers=dict(full))
        e3["vulnerabilities"]["tiers_unknown"] = [1]
        e = self.env_scan({"": e1, "-bsp": e2, "-os": e3})
        sec = self.section(e.html, "漏洞統計（含該報告的狀態）", "</table>")
        rows = sec.split("<tr>")
        f = next(r for r in rows if '<span class="ext">full</span>' in r)
        b = next(r for r in rows if '<span class="ext">bsp</span>' in r)
        o = next(r for r in rows if '<span class="ext">os</span>' in r)
        self.assertIn("p1 0", f)
        self.assertNotIn("GAP", f.split("CVE 總數")[0].split("</div>", 1)[1])     # 新格式的 0 照寫，不是 GAP
        self.assertIn('<span class="ext">None</span> 3', f)
        self.assertIn('accepted <span class="st st-GAP">GAP</span>（缺（新格式不該缺））', b)
        self.assertIn("tiers_unknown 不是物件", o)
        self.assertIn("不認得的分級", e.html[:e.html.index("</header>")])
        self.assertEqual(check_site.check_html(e.html, REPO), [])

    def test_new_format_sum_matches_rows_total(self):
        full = {"p1": 1, "p2": 2, "p3": 3, "accepted": 0, "distro_fixed": 0, "nvidia_bulletin": 0}
        ok = run_entry(tiers=dict(full))
        ok["vulnerabilities"].update(tiers_unknown={"None": 4}, rows_total=10)
        bad = run_entry(tiers=dict(full))
        bad["vulnerabilities"].update(tiers_unknown={}, rows_total=10)
        e = self.env_scan({"": ok, "-bsp": bad, "-os": run_entry()})
        sec = self.section(e.html, "漏洞統計（含該報告的狀態）", "</table>")
        rows = sec.split("<tr>")
        self.assertNotIn("不一致", next(r for r in rows if '<span class="ext">full</span>' in r))
        self.assertIn("分級合計 6 與 rows_total 10 不一致", next(r for r in rows if '<span class="ext">bsp</span>' in r))



# ---------------------------------------------------------------- CSAF 使用者通知草稿（DASHBOARD.md 第 3 節 C、docs/WATCH.md 第 8 節）

def plan_with(drafts=None, missing=False):
    p = {"status": "ATTENTION", "detail": "1 份 SBOM", "per_sbom": {}, "notes": [], "attention": [], "gaps": [], "stats": {}}
    if not missing:
        p["csaf_drafts"] = drafts if drafts is not None else []
    return p


def draft(status="NOT_RUN", dir_=None, detail="development 的 dev Release：還沒上市，也沒有報告 zip", cves=("CVE-2026-0001",), **kw):
    return dict({"project": "demo", "version": "dev", "layer": "os", "cves": list(cves), "status": status, "detail": detail,
                 "reason": None, "dir": dir_, "issue": False}, **kw)


class CsafDrafts(unittest.TestCase):
    def section(self, h):
        i = h.index("CSAF 使用者通知草稿（第 14 條第 8 項）")
        return h[i:h.index("<h4>", i + 10)]

    def test_missing_field_is_not_run(self):
        e = Env(self, watch_kw={"plan": plan_with(missing=True)})
        sec = self.section(e.html)
        self.assertIn('<span class="st st-NOT_RUN">NOT_RUN</span>', sec)
        self.assertIn("沒有草稿紀錄", sec)
        self.assertIsNone(e.data["watch"]["plan"]["csaf_drafts"])

    def test_empty_list_says_zero_records(self):
        e = Env(self, watch_kw={"plan": plan_with([])})
        self.assertIn("共 0 筆紀錄", self.section(e.html))

    def test_records_counts_next_to_status_and_run_link(self):
        recs = [draft(), draft(), draft("ATTENTION", "csaf-drafts/01-0123abcd", "1 個 CVE、1 個元件", issue=True, version="v1", layer="bsp")]
        e = Env(self, watch_kw={"plan": plan_with(recs)})
        sec = self.section(e.html)
        self.assertIn('<span class="st st-NOT_RUN">NOT_RUN</span> 2 筆', sec)
        self.assertIn('<span class="st st-ATTENTION">ATTENTION</span> 1 筆', sec)
        self.assertIn("/actions/runs/555", sec)                                  # 連到那一輪 run（artifact 在那裡）
        self.assertIn("csaf-drafts/01-0123abcd", sec)
        self.assertIn("保留 90 天", sec)
        self.assertIn("不會自動重產", sec)
        self.assertEqual(check_site.check_html(e.html, REPO), [])

    def test_untrusted_fields_are_cleaned(self):
        recs = [draft("FAIL", "/home/runner/work/_temp/w/out/csaf-drafts/01-0123abcd", "<script>alert(1)</script> [x](http://evil.test)",
                      cves=("CVE-2026-0002", "<img src=x>"), project="demo<b>")]
        e = Env(self, watch_kw={"plan": plan_with(recs)})
        rec = e.data["watch"]["plan"]["csaf_drafts"][0]
        self.assertIsNone(rec["dir"])                                            # 不是 csaf-drafts/NN-hash 的值不收
        self.assertEqual(rec["cves"], ["CVE-2026-0002"])
        sec = self.section(e.html)
        self.assertNotIn("<script>", sec)
        self.assertNotIn("<img", sec)
        self.assertNotIn("/home/runner", e.html)
        self.assertEqual(check_site.check_html(e.html, REPO), [])

    def test_over_limit_is_gap_not_silent(self):
        recs = [draft() for _ in range(build.CSAF_MAX + 3)]
        e = Env(self, watch_kw={"plan": plan_with(recs)})
        self.assertEqual(len(e.data["watch"]["plan"]["csaf_drafts"]), build.CSAF_MAX)
        self.assertIn("另有 3 筆沒有列出", self.section(e.html))

    def test_review_note_on_kev_and_support_groups(self):
        e = Env(self)
        self.assertEqual(e.html.count("開著的 Issue 是待人審的清單（D-069）"), 2)

    def test_render_escapes_project_version_layer_and_dir_regex_is_anchored(self):
        recs = [draft(project='demo<b>x</b>&"', version="v1<script>", layer="os<i>", dir_="csaf-drafts/01-0123abcd\n/srv/x"),
                draft(dir_="csaf-drafts/01-0123abcdEXTRA")]
        e = Env(self, watch_kw={"plan": plan_with(recs)})
        recs_d = e.data["watch"]["plan"]["csaf_drafts"]
        self.assertEqual([r["dir"] for r in recs_d], [None, None])            # 正規式的 \Z：後面多了東西就不收
        sec = self.section(e.html)
        for raw in ("<b>x</b>", "<script>", "<i>"):
            self.assertNotIn(raw, sec)
        self.assertIn("demo&lt;b&gt;x&lt;/b&gt;&amp;", sec)
        self.assertIn("v1&lt;script&gt;", sec)
        self.assertIn("os&lt;i&gt;", sec)
        self.assertEqual(check_site.check_html(e.html, REPO), [])

    def test_wrong_type_is_gap_not_not_run_and_non_objects_are_counted(self):
        for bad in ("x", {"a": 1}, 3):
            e = Env(self, watch_kw={"plan": dict(plan_with([]), csaf_drafts=bad)})
            sec = self.section(e.html)
            self.assertIn("GAP", sec)
            self.assertIn("資料格式不對", sec)
            self.assertNotIn("NOT_RUN", sec)
        e = Env(self, watch_kw={"plan": plan_with([draft(), "junk", 7])})
        sec = self.section(e.html)
        self.assertIn("有 2 筆不是物件", sec)
        self.assertEqual(len(e.data["watch"]["plan"]["csaf_drafts"]), 1)
        e = Env(self, watch_kw={"plan": plan_with(["junk"])})
        sec = self.section(e.html)
        self.assertIn("有 1 筆不是物件", sec)
        self.assertNotIn("共 0 筆紀錄", sec)

    def test_missing_project_version_layer_show_placeholder_not_none(self):
        r = draft()
        for k in ("project", "version", "layer"):
            r.pop(k)
        e = Env(self, watch_kw={"plan": plan_with([r])})
        sec = self.section(e.html)
        self.assertNotIn(">None<", sec)
        self.assertNotIn("None", visible(sec))
        self.assertEqual(sec.count("（缺）"), 3)
