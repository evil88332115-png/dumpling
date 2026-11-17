"""release-meta.py --body-out：GitHub Release 的說明裡網址一律改成不會自動連結的寫法（Release 說明含網址時 POST /releases 回 403）。
notes.md 與報告不動。不連網。"""
import importlib.util
import os
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = os.path.join(ROOT, "pipeline", "release-meta.py")
BODY_CLI = os.path.join(ROOT, "pipeline", "release-body.py")
sys.path.insert(0, os.path.join(ROOT, "pipeline", "lib"))
_spec = importlib.util.spec_from_file_location("release_meta", CLI)
rm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rm)

SCHEME = re.compile(r"(?:https?|ftp|file)://", re.I)
LOCAL = re.compile(r"/home/|/tmp/|/Users/|/root/|/runner/|[A-Za-z]:\\\\")


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def autolinkable(text):
    """GitHub 會自動連結的寫法還在不在（code span／code block 以外的 scheme 網址或 www.）。"""
    out, fence = [], False
    for line in text.split("\n"):
        s = line.lstrip()
        if s.startswith(("```", "~~~")):
            fence = not fence
            continue
        if fence:
            continue
        out.append(re.sub(r"`[^`\n]*`", "", line))
    rest = "\n".join(out)
    return SCHEME.search(rest) or re.search(r"(?<![\w./@-])www\.[A-Za-z0-9-]+\.", rest)


class Defang(unittest.TestCase):
    def check(self, text, expect_n, keep=()):
        out, n = rm.defang_urls(text)
        self.assertEqual(n, expect_n, out)
        self.assertIsNone(SCHEME.search(out), out)                      # scheme 一個都不留（code 裡也去掉）
        self.assertFalse(autolinkable(out), out)
        self.assertFalse([ln for ln in out.split("\n") if "``" in ln and not ln.lstrip().startswith(("```", "~~~"))], out)   # 沒有包兩次（圍欄行除外）
        for k in keep:                                                   # 原本的意思保留（網域、路徑、連結文字）
            self.assertIn(k, out)
        self.assertEqual(rm.defang_urls(out), (out, 0))                  # 再跑一次不會再改
        return out

    def test_https_and_http(self):
        out = self.check("下載：https://www.example.org/download.html，或 http://example.org/a?b=1.", 2,
                         ("`www.example.org/download.html`", "`example.org/a?b=1`."))
        self.assertTrue(out.endswith("`example.org/a?b=1`."))             # 句尾的標點不算網址

    def test_bare_www(self):
        self.check("請看 www.example.com/path 這一頁；信箱 a@www.example.invalid 不動", 1, ("`www.example.com/path`", "a@www.example.invalid"))

    def test_markdown_link_and_autolink(self):
        self.check("見 [OMV 官網](https://www.example.org/) 與 <https://example.org/x>、[有標題](http://example.org/t \"標題\")", 3,
                   ("OMV 官網（`www.example.org/`）", "`example.org/x`", "有標題（`example.org/t`）"))

    def test_code_span_and_fenced_block_only_lose_the_scheme(self):
        out = self.check("指令 `curl https://example.org/x`\n```\nwget http://example.org/y\n```\n~~~\nftp://example.org/z\n~~~", 3,
                         ("`curl example.org/x`", "wget example.org/y", "example.org/z"))
        self.assertIn("```\nwget example.org/y\n```", out)

    def test_file_urls_never_leak_local_paths(self):
        out = self.check("檔案 file:///home/runner/work/x/image.tar、[記錄](file:///tmp/r.log)、`file:///Users/u/a`\n```\nfile:///root/b\n```", 4)
        self.assertIsNone(LOCAL.search(out), out)
        self.assertEqual(out.count(rm.LOCAL_PATH_NOTE), 4)

    def test_rewrite_adds_no_local_path(self):
        text = "https://example.org/a [b](https://example.org/b) www.example.org/c `http://example.org/d`"
        out, _ = rm.defang_urls(text)
        self.assertIsNone(LOCAL.search(out))
        self.assertFalse(set(re.findall(r"/[A-Za-z0-9_.-]+", out)) - set(re.findall(r"/[A-Za-z0-9_.-]+", text)))   # 沒有冒出原文沒有的路徑

    def test_urls_glued_to_cjk_underscore_or_file(self):
        """網址前面緊貼中文字或底線（\\w 會把它們當成字的一部分）也要改寫；file:// 緊貼也一樣省略。"""
        out = self.check("網址https://example.org/a、名稱_https://example.org/b、見file:///home/runner/x、路徑_file:///tmp/y、網站www.example.org/c", 5,
                         ("網址`example.org/a`", "名稱_`example.org/b`", "網站`www.example.org/c`"))
        self.assertIsNone(LOCAL.search(out), out)

    def test_url_inside_query_string(self):
        """查詢字串裡又有完整網址：scheme 全部去掉（只去第一個會留下 scheme，而且再跑一次不一樣）；夾帶的 file:// 也省略。"""
        self.check("見 https://a.example.org/x?u=https://b.example.org/y&v=http://c.example.org/z", 1,
                   ("`a.example.org/x?u=b.example.org/y&v=c.example.org/z`",))
        out = self.check("下載 https://a.example.org/?f=file:///home/runner/secret.tar", 1)
        self.assertIsNone(LOCAL.search(out), out)

    def test_autolink_brackets_are_removed(self):
        out = self.check("請看 <https://example.org/x> 與 <http://example.org/y>。", 2, ("`example.org/x`", "`example.org/y`"))
        self.assertNotIn("<", out)
        self.assertNotIn(">", out)

    def test_text_without_urls_is_unchanged(self):
        t = "**report_status OK**｜**release_gate GAP**｜**pipeline_result OK**\n\n| 步驟 | 狀態 |\n|---|---|\n| scan | OK |\n"
        self.assertEqual(rm.defang_urls(t), (t, 0))


class Cli(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="dumpling-body-")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.d, ignore_errors=True)

    def p(self, *a):
        return os.path.join(self.d, *a)

    def run_meta(self, *extra):
        steps = self.p("steps.tsv")
        if not os.path.exists(steps):
            with open(steps, "w", encoding="utf-8") as f:
                f.write("step\tstatus\trc\tdetail\nscan\tOK\t0\tscan: OK\n")
        return subprocess.run([sys.executable, "-I", CLI, "--project", "orin-nano-demo", "--version", "v39.2.1-demo1", "--commit", "a" * 40,
                               "--run-id", "1", "--steps", steps, *extra, "--out", self.p("m.json")], capture_output=True, text=True)

    def test_body_out_rewrites_urls_and_leaves_notes_alone(self):
        notes = self.p("notes.md")
        body = "# p v1\n\n**report_status OK**｜**release_gate OK**｜**pipeline_result OK**\n\n上游：https://www.example.org/download.html 與 [文件](https://example.org/doc)\n"
        with open(notes, "w", encoding="utf-8") as f:
            f.write(body)
        r = self.run_meta("--notes", notes, "--body-out", self.p("release-body.md"))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("Release 說明（release-body.md）改寫了 2 處網址", r.stdout)
        out = read(self.p("release-body.md"))
        self.assertIsNone(SCHEME.search(out))
        self.assertIn("`www.example.org/download.html`", out)
        self.assertIn("文件（`example.org/doc`）", out)
        notes_after = read(notes)
        self.assertIn("https://www.example.org/download.html", notes_after)          # notes.md 不改網址
        self.assertEqual(rm.defang_urls(notes_after)[0], out)                         # 說明＝（重寫 pipeline_result 之後的）notes.md 改網址

    def test_body_out_needs_notes(self):
        r = self.run_meta("--body-out", self.p("release-body.md"))
        self.assertEqual(r.returncode, 64, r.stdout)
        self.assertFalse(os.path.exists(self.p("m.json")) or os.path.exists(self.p("release-body.md")))

    def test_release_body_cli(self):
        """pipeline/release-body.py：給直接用 gh release create --notes-file 的流程（例如韌體）用，同一個函式。"""
        src, dst = self.p("notes.md"), self.p("body.md")
        with open(src, "w", encoding="utf-8") as f:
            f.write("韌體 https://example.org/fw 與 [說明](https://example.org/doc)\n")
        run = lambda *a: subprocess.run([sys.executable, "-I", BODY_CLI, *a], capture_output=True, text=True)
        r = run(src, dst)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(r.stdout.strip().splitlines()[-1], "release-body: OK（notes.md → body.md，改寫了 2 處網址）")
        self.assertIsNone(SCHEME.search(read(dst)))
        self.assertIn("https://example.org/fw", read(src))                                  # 輸入檔不改
        self.assertFalse(os.path.exists(dst + ".part"))
        self.assertEqual(run(src).returncode, 64)
        self.assertEqual(run(src, src).returncode, 1)                                       # 不覆蓋輸入
        with open(self.p("empty.md"), "w", encoding="utf-8") as f:
            f.write("  \n")
        for bad in (self.p("empty.md"), self.p("nope.md")):
            os.path.exists(self.p("out2.md")) and os.unlink(self.p("out2.md"))
            r = run(bad, self.p("out2.md"))
            self.assertEqual(r.returncode, 1, r.stdout)
            self.assertTrue(r.stdout.strip().startswith("release-body: FAIL"), r.stdout)
            self.assertFalse(os.path.exists(self.p("out2.md")))

    def test_release_workflow_checks_the_body_before_creating(self):
        t = read(os.path.join(ROOT, ".github", "workflows", "release.yml"))
        guard = t.index("[ -s release-body.md ]")
        self.assertLess(guard, t.index("gh release create"))
        self.assertLess(guard, t.index("ghx gh api"))                                       # 缺檔時不打任何 API、不重試

    def test_release_workflow_uses_the_rewritten_body(self):
        t = read(os.path.join(ROOT, ".github", "workflows", "release.yml"))
        call = t.split("pipeline/release-meta.py", 1)[1].split("manifest.tsv", 1)[0]
        self.assertIn('--body-out "$RUNNER_TEMP/result/release-body.md"', call)
        creates = [ln for ln in t.splitlines() if "gh release create" in ln]
        self.assertEqual(len(creates), 2)
        for ln in creates:
            self.assertIn("--notes-file release-body.md", ln)
            self.assertNotIn("--notes-file notes.md", ln)


if __name__ == "__main__":
    unittest.main()
