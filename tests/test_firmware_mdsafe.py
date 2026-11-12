"""firmware_mdsafe（不可信文字進 markdown 前的共用清理）的單元測試。"""
import importlib.util
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PATH = os.path.join(ROOT, "pipeline", "lib", "firmware_mdsafe.py")
spec = importlib.util.spec_from_file_location("firmware_mdsafe", PATH)
ms = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ms)


class MdSafeTest(unittest.TestCase):
    def test_every_special_char_escaped(self):
        for ch in ms.SPECIAL:
            with self.subTest(ch=ch):
                self.assertEqual(ms.md_safe("a%sb" % ch), "a\\%sb" % ch)

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
