"""publiccheck.py：Issue 內文的公開檢查。合成資料。"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import publiccheck as pc  # noqa: E402


class T(unittest.TestCase):
    def test_clean(self):
        self.assertEqual(pc.check_text("CVE-2021-44228 pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1\n"), [])

    def test_runner_path_blocked(self):
        self.assertTrue(pc.check_text("sbom at " + "/home/" + "runner/work/x.json"))

    def test_private_ip_blocked(self):
        self.assertTrue(pc.check_text("host 192." + "168.1.10 down"))

    def test_email(self):
        self.assertEqual(pc.check_text("by 1+x@users.noreply.github.com"), [])
        self.assertTrue(pc.check_text("by someone@" + "corp.com"))

    def test_email_not_excused_by_allowed_line(self):
        pats, _ = pc.load_rules()
        allows = [__import__("re").compile(r"(^|[^A-Za-z0-9._%+@-])" + "allowed-token-xyz" + r"($|[^A-Za-z0-9._%+@-])")]
        self.assertTrue(pc.check_text("bob@" + "corp.com allowed-token-xyz", (pats, allows)))
        self.assertEqual(pc.check_text("10." + "1.2.3 allowed-token-xyz", (pats, allows)), [])

    def test_source_relative_path_ok(self):
        self.assertEqual(pc.check_text("drivers/media/usb/x.c"), [])


if __name__ == "__main__":
    unittest.main()
