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
    def test_every_special_char_escaped(self):
        for ch in ms.SPECIAL:
            with self.subTest(ch=ch):
                self.assertEqual(ms.md_safe("a%sb" % ch), "a\\%sb" % ch)
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

    def test_html_entities_do_not_decode(self):
        # &lt; &#64; &#x40; &commat; 渲染時會解碼成 < @ @ @，繞過後面的跳脫：& 一律換成 &amp;，渲染結果是字面的實體文字
        for raw in ("&lt;", "&#64;", "&#x40;", "&#X40;", "&commat;", "&amp;", "&#91;", "&lbrack;", "&#0;", "&", "&&", "A&B", "R&D;", "&lt"):
            with self.subTest(raw=raw):
                out = ms.md_safe(raw, 100)
                self.assertEqual(out, raw.replace("&", "&amp;").replace("#", "\\#"))
                self.assertEqual(re.sub(r"\\(.)", r"\1", html.unescape(out)), raw)     # 解碼實體再去反斜線，得回原文（不是 <、@ 本身）
                self.assertNotRegex(out, r"&(?!amp;)")                    # 沒有未編碼的 &
        out = ms.md_safe("&#64;user &#x5b;x&#x5d;&#40;http://e&#41; &lt;img src=x&gt;", 200)
        self.assertEqual(html.unescape(out).count("@"), 0)                # 解碼一次後仍沒有 @、<、[ 這些字元
        self.assertNotRegex(html.unescape(out), r"[<>]|(?<!\\)\[")

    def test_at_sign_defanged_unless_inside_word(self):
        z = ms.ZWSP
        self.assertEqual(ms.md_safe("@user"), "@" + z + "user")
        self.assertEqual(ms.md_safe("x @org/team (@u2)"), "x @" + z + "org/team \\(@" + z + "u2\\)")
        self.assertEqual(ms.md_safe("＠user"), "＠" + z + "user")            # 全形
        self.assertEqual(ms.md_safe("@@u"), "@" + z + "@" + z + "u")
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
        self.assertEqual(ms.md_safe("&#64;user"), "&amp;\\#64;user")

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

    def test_cli_usage_error_is_64(self):
        r = subprocess.run([sys.executable, "-I", PATH], capture_output=True)
        self.assertEqual(r.returncode, 64)


if __name__ == "__main__":
    unittest.main()
