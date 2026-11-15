"""firmware_mdsafe（不可信文字進 markdown 前的共用清理）的單元測試。"""
import html
import importlib.util
import os
import re
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PATH = os.path.join(ROOT, "pipeline", "lib", "firmware_mdsafe.py")
spec = importlib.util.spec_from_file_location("firmware_mdsafe", PATH)
ms = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ms)


def _watch_match():
    """載入 C3 的 pipeline/watch/match.py（只在測試用；它會改 sys.path，載入後還原）。"""
    path = os.path.join(ROOT, "pipeline", "watch", "match.py")
    saved = list(sys.path)
    try:
        sp = importlib.util.spec_from_file_location("watch_match_for_mdsafe_test", path)
        mod = importlib.util.module_from_spec(sp)
        sp.loader.exec_module(mod)
        return mod
    except Exception:
        return None
    finally:
        sys.path[:] = saved


class MdSafeTest(unittest.TestCase):
    # 必須加反斜線跳脫的字元：寫死在測試裡（不從 ms.SPECIAL 取，否則從 SPECIAL 拿掉一個字元，這個測試也跟著少測一個）
    ESCAPED = "\\[]()<>!*_#~|`$"

    def test_every_special_char_escaped(self):
        self.assertEqual(len(self.ESCAPED), 15)
        for ch in self.ESCAPED:
            with self.subTest(ch=ch):
                self.assertEqual(ms.md_safe("a%sb" % ch), "a\\%sb" % ch)
        self.assertEqual(sorted(ms.SPECIAL), sorted(self.ESCAPED))      # 多一個少一個都要讓人看到：改 SPECIAL 要同時改這份清單與檔頭第 5 點
        self.assertNotIn("&", ms.SPECIAL)           # & 不加反斜線，改成 &amp;（見下面的實體測試）

    def test_link_image_html_neutralized(self):
        out = ms.md_safe("[click](https://evil.example/x) ![i](http://e/x.png) <img src=x onerror=alert(1)> <a href=//e>x</a>", 500)
        self.assertNotIn("](", out)
        self.assertNotRegex(out, r"(?<!\\)[\[\]<>]")
        self.assertNotRegex(out, r"(?<!\\)[()]")
        self.assertNotIn("https://", out)           # 裸網址也不會被 GitHub 自動變成連結
        self.assertNotIn("http://", out)

    def test_bare_url_and_www_defanged(self):
        self.assertEqual(ms.md_safe("https://evil.example/x"), "https\\://evil.example/x")
        self.assertEqual(ms.md_safe("see HTTP://a.b ftp://c.d"), "see HTTP\\://a.b ftp\\://c.d")
        self.assertEqual(ms.md_safe("www.evil.example"), "www\\.evil.example")
        self.assertEqual(ms.md_safe("foowww.bar"), "foowww.bar")          # 單字中間的 www 不是自動連結
        self.assertEqual(ms.md_safe("1.2.3 pkg:generic/a@1.0"), "1.2.3 pkg:generic/a@1.0")   # 一般版本與 purl 不被改動

    def test_scheme_colon_escaped_whatever_precedes_it(self):
        # 前面緊接 [A-Za-z0-9+.-] 時，渲染器仍會把 scheme:// 連結起來，所以不看前面的字元
        for raw in ("1.https://evil.example/x", "x-https://evil.example/x", "a+https://evil.example/x", "name.http://evil.example",
                    "-ftp://evil.example", "9https://e/x", "https://e", "file:///etc/x", "a://b", "x:://y"):
            with self.subTest(raw=raw):
                out = ms.md_safe(raw, 200)
                self.assertNotRegex(out, r"(?<!\\):(?=//)")                    # 每個 :// 的冒號前都有反斜線
                self.assertEqual(out.replace("\\:", ":"), raw)
        self.assertEqual(ms.md_safe("1.https://evil.example/x", 200), "1.https\\://evil.example/x")
        self.assertEqual(ms.md_safe("a:b c:d"), "a:b c:d")                       # 沒有 // 的冒號不動
        self.assertEqual(ms.md_safe("pkg:generic/a@1.0"), "pkg:generic/a@1.0")
        # 整份渲染（cmark-gfm、markdown-it）的檢查在 tests/test_c2_report_render.py（需要固定版本的渲染器套件）

    def test_html_entities_do_not_decode(self):
        # &lt; &#64; &#x40; &commat; 渲染時會解碼成 < @ @ @，繞過後面的跳脫：& 一律換成 &amp;，渲染結果是字面的實體文字
        for raw in ("&lt;", "&#64;", "&#x40;", "&#X40;", "&commat;", "&amp;", "&#91;", "&lbrack;", "&#0;", "&", "&&", "A&B", "R&D;", "&lt"):
            with self.subTest(raw=raw):
                out = ms.md_safe(raw, 100)
                self.assertEqual(out, re.sub(r"#(?=[0-9])", "#\u200b", raw.replace("&", "&amp;").replace("#", "\\#")))      # `#` 接數字另插零寬空白（Issue 參照，檔頭第 7 點）
                self.assertEqual(re.sub(r"\\(.)", r"\1", html.unescape(out)).replace("\u200b", ""), raw)     # 解碼實體再去反斜線，得回原文（不是 <、@ 本身）
                self.assertNotRegex(out, r"&(?!amp;)")                    # 沒有未編碼的 &
        out = ms.md_safe("&#64;user &#x5b;x&#x5d;&#40;http://e&#41; &lt;img src=x&gt;", 200)
        self.assertEqual(html.unescape(out).count("@"), 0)                # 解碼一次後仍沒有 @、<、[ 這些字元
        self.assertNotRegex(html.unescape(out), r"[<>]|(?<!\\)\[")

    def test_at_sign_defanged_unless_inside_word(self):
        z = ms.ZWSP
        self.assertEqual(ms.md_safe("@user"), "@" + z + "user")
        self.assertEqual(ms.md_safe("x @org/team (@u2)"), "x @" + z + "org/team \\(@" + z + "u2\\)")
        self.assertEqual(ms.md_safe("＠user"), "＠" + z + "user")            # 全形
        self.assertEqual(ms.md_safe("@@u"), "@" + z + z + "@" + z + "u")        # 第二個 @ 在同一串 email 字元裡有更早的 @：cmark-gfm 的 `.` 計數不歸零，照 email 形式前後都隔開
        self.assertEqual(ms.md_safe("\\@u"), "\\\\@" + z + "u")                # 反斜線不是英數字
        self.assertEqual(ms.md_safe("_@u"), "\\_@" + z + "u")                  # 底線也處理（比 \w 嚴）
        self.assertEqual(ms.md_safe("é@u"), "é@" + z + "u")
        self.assertEqual(ms.md_safe("&@u"), "&amp;@" + z + "u")
        self.assertEqual(ms.md_safe("@types/node"), "@" + z + "types/node")
        self.assertEqual(ms.md_safe("npm:@scope/pkg"), "npm:@" + z + "scope/pkg")
        # 前面是 ASCII 英數字：purl、版本、email 形式，不是提及，原樣保留
        for keep in ("pkg:generic/a@1.0", "name@host", "x9@y", "Z@q"):
            self.assertEqual(ms.md_safe(keep), keep)
        # 輸入裡的零寬空白會被濾掉，不能拿來假裝已經處理過
        self.assertNotIn("@user", ms.md_safe("@" + z + "user"))                       # 零寬空白被濾成空白：「@ user」不是提及
        self.assertEqual(ms.md_safe(" " + z + "@user"), "@" + z + "user")
        # 實體加 @ 的組合：&#64; 本身不再解碼，字面的 @ 另外處理
        self.assertEqual(ms.md_safe("&#64;user"), "&amp;\\#" + z + "64;user")

    def test_email_autolink_form_is_defanged_but_purl_is_not(self):
        z = ms.ZWSP
        # cmark-gfm 會連結成 mailto 的形式：@ 前後各插零寬空白（只插後面時，markdown-it 的 linkify 仍會把網域接起來）
        for raw, want in (("a@b.c", "a" + z + "@" + z + "b.c"), ("user@example.org", "user" + z + "@" + z + "example.org"),
                          ("pkg:deb/u/zlib@1.2.11.p", "pkg:deb/u/zlib" + z + "@" + z + "1.2.11.p"),
                          ("a@b.c-", "a" + z + "@" + z + "b.c-"),        # cmark-gfm 不連結，但 markdown-it 的 linkify 連結到 `-` 前為止
                          ("a@example.com_1", "a" + z + "@" + z + "example.com\\_1")):
            with self.subTest(raw=raw):
                self.assertEqual(ms.md_safe(raw), want)
        # 不會被連結的形式原樣（purl 與版本字串可以原樣複製）
        for keep in ("pkg:generic/zlib@1.2.11", "pkg:deb/ubuntu/zlib1g@1:1.2.11.dfsg-2ubuntu9?arch=amd64", "pkg:rpm/fedora/openssl@3.0.7-1.fc37",
                     "name@host", "x9@y", "a@1.0", "a@b.c1", "pkg:npm/%40scope/x@1.2.3"):
            with self.subTest(keep=keep):
                self.assertEqual(ms.md_safe(keep, 200), keep)
        # 第二個以後的 @：cmark-gfm 的 `.` 計數沒有歸零（x@y.z@Z 連結 y.z@Z），所以不要求 `.`
        self.assertEqual(ms.md_safe("x@y.z@Z"), "x" + z + "@" + z + "y.z" + z + "@" + z + "Z")
        # 前面不是英數字的 @：提及，只插後面；網域形式時前面也插
        self.assertEqual(ms.md_safe("@user"), "@" + z + "user")
        self.assertEqual(ms.md_safe("x @a.b"), "x " + z + "@" + z + "a.b")
        self.assertEqual(ms.md_safe("＠a.b"), "＠" + z + "a.b")                   # 全形：沒有渲染器當 email，只照提及處理
        self.assertEqual(ms.md_safe("a＠example.com"), "a＠example.com")

    def test_earlier_at_only_counts_within_the_same_run_of_email_characters(self):
        z = ms.ZWSP
        # 逗號、空白隔開後，前面的 @ 不影響後面的 @（cmark-gfm 的 `.` 計數只在同一串 email 字元裡不歸零）：後面這個沒有 `.`，原樣
        self.assertEqual(ms.md_safe("a@b.test,y@Z"), "a" + z + "@" + z + "b.test,y@Z")
        self.assertEqual(ms.md_safe("a@b.test y@Z"), "a" + z + "@" + z + "b.test y@Z")
        self.assertEqual(ms.md_safe("a@b.test-y@Z"), "a" + z + "@" + z + "b.test-y" + z + "@" + z + "Z")      # 同一串（`-` 是 email 字元）：照 email 形式
        self.assertEqual(ms.md_safe("WWW.example.test"), "WWW\\.example.test")                                  # www 不分大小寫

    def test_defang_at_is_the_function_used_by_md_safe(self):
        z = ms.ZWSP
        self.assertEqual(ms.defang_at("a@b.c @u pkg@1.0"), "a" + z + "@" + z + "b.c " + "@" + z + "u pkg@1.0")
        self.assertEqual(ms.defang_at(""), "")
        self.assertEqual(ms.md_safe("a@b.c @u pkg@1.0"), ms.defang_at("a@b.c @u pkg@1.0"))

    def test_mailto_and_xmpp_colon_escaped_and_followed_by_zero_width_space(self):
        z = ms.ZWSP
        # 冒號加反斜線之後再插零寬空白：cmark-gfm 先合併文字節點再做 autolink，只有反斜線擋不住 `xmpp:a@/.a` 這類形式
        self.assertEqual(ms.md_safe("mailto:a@example.com"), "mailto\\:" + z + "a" + z + "@" + z + "example.com")
        self.assertEqual(ms.md_safe("XMPP:a@example.com"), "XMPP\\:" + z + "a" + z + "@" + z + "example.com")
        self.assertEqual(ms.md_safe("xmpp:a/b@example.org"), "xmpp\\:" + z + "a/b" + z + "@" + z + "example.org")
        self.assertEqual(ms.md_safe("mailto:name@host"), "mailto\\:" + z + "name@host")          # 網域沒有 `.`：cmark-gfm 不連結，但 markdown-it 的 mailto: 會
        self.assertEqual(ms.md_safe("mailto:"), "mailto\\:" + z)
        for raw in ("xmpp:a@/.a", "xmpp:a@-/.a", "xmpp:1@a/.a", "xmpp:a@_/.a", "mailto:a@/.a", "MailTo:a@b/c.d"):
            out = ms.md_safe(raw, 200)
            self.assertEqual(out.replace(z, "").replace("\\", ""), raw, raw)
            self.assertRegex(out, r"(?i)^(mailto|xmpp)\\:" + z, raw)                              # 前綴與名稱之間一定隔著零寬空白
        self.assertEqual(ms.md_safe("a:b mail:x"), "a:b mail:x")
        self.assertEqual(ms.defang_links("mailto:x https://e www.e"), "mailto\\:" + z + "x https\\://e www\\.e")

    def test_no_lookback_limit_for_an_earlier_at_in_the_same_run(self):
        z = ms.ZWSP
        # `x@y.z` 接很多個 `1` 再接 `@Z`：同一串 email 字元，cmark-gfm 會連結 `y.z111…@Z`；不論多長，最後一個 @ 都要被隔開
        for n in (0, 1, 100, 251, 252, 253, 254, 255, 256, 257, 300, 1000, 5000):
            out = ms.md_safe("x@y.z" + "1" * n + "@Z", 100000)
            self.assertTrue(out.endswith("1" * n + z + "@" + z + "Z") if n else out.endswith("z" + z + "@" + z + "Z"), n)
        # 中間隔著空白或逗號就是另一串：後面的 @ 不受前面影響（見 test_earlier_at_only_counts_within_the_same_run_of_email_characters）
        out = ms.md_safe("x@y.z" + "1" * 300 + " q@Z", 100000)
        self.assertTrue(out.endswith(" q@Z"))
        self.assertEqual(ms._earlier_at("a@b"), [False, False, True])
        self.assertEqual(ms._earlier_at("a@b c"), [False, False, True, True, False])          # 空白隔開：重新計
        self.assertEqual(ms._earlier_at("a@b,c"), [False, False, True, True, False])          # 逗號不是 email 字元
        self.assertEqual(ms._earlier_at("a@b-c"), [False, False, True, True, True])           # `-` 是
        self.assertEqual(ms._earlier_at(""), [])

    def test_scans_are_linear(self):
        import time
        big = 100000
        cases = ["a@" + "_" * big, "a@" + "-" * big, "a@" + "-_" * (big // 2), "a@" + "a-" * (big // 2), "@" * big, "a@b." * (big // 4),
                 "x@y.z" + "1" * big + "@Z", "a@" + "a" * big, "mailto:" * (big // 7), "a@b.c " * (big // 6), "@a" * (big // 2), ("a@" + "_" * 1000 + " ") * (big // 1002)]
        for raw in cases:
            t0 = time.perf_counter()
            out = ms.md_safe(raw, 10 ** 6)
            dt = time.perf_counter() - t0
            self.assertLess(dt, 5.0, (raw[:20], len(raw), dt))      # 線性時約 0.05 秒；門檻放寬，免得忙碌的 runner 誤報
            self.assertGreaterEqual(len(out), 1)

    def test_email_like_domain_chars_and_local_chars(self):
        z = ms.ZWSP
        # 網域掃描要認得 `-`、`_`；同一串 email 字元要認得 `_`（cmark-gfm 會連結這些，實測）
        self.assertEqual(ms.md_safe("a@-.a"), "a" + z + "@" + z + "-.a")
        self.assertEqual(ms.md_safe("aa@_.a"), "aa" + z + "@" + z + "\\_.a")
        self.assertEqual(ms.md_safe("a@_.1@a"), "a@\\_.1" + z + "@" + z + "a")
        self.assertEqual(ms.md_safe("a@b_c.d"), "a" + z + "@" + z + "b\\_c.d")
        self.assertEqual(ms.md_safe("a@b-c.d"), "a" + z + "@" + z + "b-c.d")

    def test_is_blank(self):
        for blank in ("", " ", "\t\n", "\u00a0", "\u3000", "\u200b", "\u200b\u200d\u2060", "\ufeff", "\x00", "\x1b", "\u202e", "\u00ad", "\u180e", "\ufe0f", "\U000e0100",
                      "\u0301", "\u20dd", "\u034f", "\u115f", "\u1160", "\u3164", "\uffa0", "\u2800", "\u2028", "\ud800", " \u200b\u3164\u2800 "):
            with self.subTest(blank=repr(blank)):
                self.assertTrue(ms.is_blank(blank))
        for shown in ("a", "\u0903", "\u093e", "0", "_", ".", "-", "\u200ba", "\u3164a", "é", "中", "\u2603", "\ufffd", "\ufffc", "A-source"):
            with self.subTest(shown=repr(shown)):
                self.assertFalse(ms.is_blank(shown))
        self.assertFalse(ms.is_blank(None))             # str(None) 是 "None"

    def test_agrees_with_watch_unsafe_markdown(self):
        """C3（pipeline/watch/match.py）的 unsafe_markdown 是同一類風險的最後一道檢查；這裡的輸出不能被它挑出問題。
        match.py 的 md_text 與 md_safe 的差別（`#`、`@`、`$`）見 firmware_mdsafe.py 檔頭，這裡只核對共同的風險。"""
        w = _watch_match()
        if w is None:
            self.skipTest("載入不到 pipeline/watch/match.py")
        samples = ["@user", "x @org/team", "＠u", "&lt;b&gt;", "&#64;user", "&#x40;user", "&commat;user", "&amp;", "[a](http://e/x)", "![i](http://e/x.png)",
                   "\\[a](b)", "a_@u", "&", "R&D", "<a href=x>@u</a>", "https://e/x @u [x](y)", "pkg:generic/a@1.0", "&#64;&#64;"]
        for t in samples:
            with self.subTest(t=t):
                out = ms.md_safe(t, 300)
                self.assertEqual(w.unsafe_markdown(out), [], out)
        # 對照：md_text（C3 的純文字跳脫）對 & 的結果與這裡一樣
        for t in ("&lt;", "A&B", "&amp;"):
            self.assertEqual(ms.md_safe(t), w.md_text(t).replace("\\", ""), t)

    # Issue 參照（檔頭第 7 點）：寫死在測試裡的檢查式，不從 ms 取
    ISSUE_REF = re.compile(r"[#＃](?=[0-9０-９])")
    GH_REF = re.compile(r"(?i)(?<![A-Za-z0-9])gh(?=-[0-9])")
    ISSUE_SAMPLES = ["#1", "\\#1", "owner/repo#1", "owner/repo\\#1", "GH-1", "gh-12", "Gh-3 x", "＃1", "#１", "＃１", "a #12 b", "(#3)", "x/GH-9",
                     "##1", "fix #1, #2 and GH-3", "-GH-4", "_GH-5"]

    def test_issue_refs_defanged(self):
        for raw in self.ISSUE_SAMPLES:
            for out in (ms.md_safe(raw, 300), ms.defang_issue_refs(raw)):
                with self.subTest(raw=raw, out=out):
                    self.assertIsNone(self.ISSUE_REF.search(out))
                    self.assertIsNone(self.GH_REF.search(out))
                    self.assertEqual(out.replace("\u200b", "").replace("\\", ""), raw.replace("\u200b", "").replace("\\", ""))       # 可見文字不變

    def test_non_issue_refs_unchanged(self):
        for raw in ("#a", "C#", "GH-a", "aGH-1", "1GH-2", "GH1", "pkg:generic/a@1.0#sub/path", "# 1", "GH -1", "ghx-1"):
            with self.subTest(raw=raw):
                self.assertNotIn("\u200b", ms.defang_issue_refs(raw))

    def test_issue_refs_idempotent_and_used_by_defang_links(self):
        for raw in self.ISSUE_SAMPLES + ["#\u200b1", "GH\u200b-1"]:
            once = ms.defang_issue_refs(raw)
            self.assertEqual(ms.defang_issue_refs(once), once, raw)
        self.assertEqual(ms.defang_issue_refs("#\u200b1"), "#\u200b1")
        self.assertEqual(ms.defang_links("#1"), "#\u200b1")
        self.assertEqual(ms.defang_links("GH-1"), "GH\u200b-1")

    def test_issue_refs_agree_with_watch(self):
        """C3 的 match._issue_refs_off 是同一份 regex：md_safe 的輸出再經過它不會再改變（md_text 等於 md_safe 的結果）。"""
        w = _watch_match()
        if w is None or not hasattr(w, "_issue_refs_off"):
            self.skipTest("載入不到 pipeline/watch/match.py 的 _issue_refs_off")
        self.assertEqual((ms._ISSUE_REF.pattern, ms._GH_REF.pattern), (w._ISSUE_REF.pattern, w._GH_REF.pattern))
        for raw in self.ISSUE_SAMPLES + ["@user #1", "https://e/x#1", "[a](#1)"]:
            out = ms.md_safe(raw, 300)
            self.assertEqual(w._issue_refs_off(out), out, raw)
            self.assertEqual(w.md_text(raw, 300), out, raw)

    def test_c_category_and_line_separators_removed(self):
        raw = "a\x00b\x07c\x1bd\x7fe\x85f‮g​h i j﻿kl\ud800m\tn\no\rp"
        out = ms.md_safe(raw, 500)
        for ch in raw:
            if ord(ch) > 0x7e or ord(ch) < 0x20 or ch == "\x7f":
                self.assertNotIn(ch, out, hex(ord(ch)))
        self.assertEqual(out.replace(" ", ""), "abcdefghijklmnop")
        self.assertNotIn("\n", out)

    def test_whitespace_collapsed_and_nbsp_normalized(self):
        self.assertEqual(ms.md_safe("  a  　  b  "), "a b")

    def test_truncation_before_escape(self):
        out = ms.md_safe("[" * 100, 10)
        self.assertEqual(out, "\\[" * 9 + "…")
        self.assertEqual(ms.md_safe("x" * 10, 10), "x" * 10)
        self.assertTrue(ms.md_safe("x" * 11, 10).endswith("…"))

    def test_non_str_and_none(self):
        self.assertEqual(ms.md_safe(None), "None")
        self.assertEqual(ms.md_safe(12), "12")

    def test_cli_matches_function_and_is_locale_independent(self):
        for env_extra in ({}, {"LANG": "C", "LC_ALL": "C"}):
            env = {k: v for k, v in os.environ.items() if k not in ("LANG", "LC_ALL")}
            env.update(env_extra)
            r = subprocess.run([sys.executable, "-I", PATH, "--limit", "30", "--", "中文 [a](b) |x\nz"],
                               capture_output=True, env=env)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(r.stdout.decode("utf-8"), ms.md_safe("中文 [a](b) |x\nz", 30))

    def test_cli_used_by_summary_scripts_defangs_mentions_and_entities(self):
        # firmware-ci.sh、firmware-dt.sh 的 cell() 就是這個呼叫（--limit N -- 文字）
        for script, limit in (("firmware-ci.sh", "600"), ("firmware-dt.sh", "300")):
            with open(os.path.join(ROOT, "pipeline", script), encoding="utf-8") as fh:
                self.assertIn('firmware_mdsafe.py" --limit %s -- "$1"' % limit, fh.read(), script)
        raw = "ok @evil &#64;evil &lt;img&gt; a@b.c pkg:generic/x@1.0 | x"
        r = subprocess.run([sys.executable, "-I", PATH, "--limit", "600", "--", raw], capture_output=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        out = r.stdout.decode("utf-8")
        self.assertEqual(out, ms.md_safe(raw, 600))
        self.assertIn("@\u200bevil", out)
        self.assertNotIn("&#64;", out)
        self.assertNotIn("&lt;", out)
        self.assertIn("a\u200b@\u200bb.c pkg:generic/x@1.0", out)       # email 形式前後都插零寬空白；purl 原樣
        self.assertIn("\\|", out)

    def test_cli_usage_error_is_64(self):
        r = subprocess.run([sys.executable, "-I", PATH], capture_output=True)
        self.assertEqual(r.returncode, 64)


if __name__ == "__main__":
    unittest.main()
