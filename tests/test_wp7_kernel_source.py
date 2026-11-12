"""WP7：Debian 核心原始碼（orig ＋ debian/patches 依序套用，D-035）與 scan 的版本核對。合成資料、不連網。"""
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
KS = os.path.join(ROOT, "pipeline", "platforms", "_shared", "debian_kernel_source.py")
sys.path.insert(0, os.path.join(ROOT, "pipeline", "platforms", "_shared"))
import wp7_scan  # noqa: E402

PATCH_A = """--- a/Makefile
+++ b/Makefile
@@ -1,2 +1,2 @@
 VERSION = 6
-SUBLEVEL = 116
+SUBLEVEL = 116 # debian
"""
PATCH_B = """--- a/net/x.c
+++ b/net/x.c
@@ -1 +1 @@
-int x = 0;
+int x = 1; /* CVE fix backported */
"""


def tar_xz(path, members):
    with tarfile.open(path, "w:xz") as t:
        for name, data in members:
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))


class KernelSourceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wp7-ks-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.orig = os.path.join(self.tmp, "linux_6.12.116.orig.tar.xz")
        tar_xz(self.orig, [("linux-6.12.116/Makefile", b"VERSION = 6\nSUBLEVEL = 116\n"), ("linux-6.12.116/net/x.c", b"int x = 0;\n")])

    def debian(self, series, patches, changelog=b"linux (6.12.116-1) trixie-security; urgency=high\n"):
        p = os.path.join(self.tmp, "linux_6.12.116-1.debian.tar.xz")
        m = [("debian/changelog", changelog), ("debian/patches/series", series.encode())]
        m += [("debian/patches/" + n, d.encode()) for n, d in patches.items()]
        tar_xz(p, m)
        return p

    def run_ks(self, deb):
        out = os.path.join(self.tmp, "ks.tar.gz")
        js = os.path.join(self.tmp, "ks.json")
        p = subprocess.run([sys.executable, "-I", KS, "prepare", "--orig", self.orig, "--debian", deb, "--work", os.path.join(self.tmp, "w"),
                            "--out", out, "--json", js], capture_output=True, text=True)
        with open(js, encoding="utf-8") as f:
            doc = json.load(f)
        return p.returncode, p.stdout.strip().splitlines()[-1], doc, out

    def test_patches_applied_in_order(self):
        rc, line, doc, out = self.run_ks(self.debian("bugfix/a.patch\n# 註解\nbugfix/b.patch\n", {"bugfix/a.patch": PATCH_A, "bugfix/b.patch": PATCH_B}))
        self.assertEqual(rc, 0, line)
        self.assertEqual((doc["status"], doc["debian_version"], doc["patches_applied"]), ("OK", "6.12.116-1", 2))
        with tarfile.open(out) as t:
            self.assertIn(b"CVE fix backported", t.extractfile("linux-6.12.116/net/x.c").read())
            self.assertIn("linux-6.12.116/debian/changelog", t.getnames())
            self.assertTrue(all(m.uid == 0 and m.gid == 0 for m in t.getmembers()))
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "w")))          # 工作資料夾用完就刪

    def test_patch_that_does_not_apply_is_gap(self):
        bad = PATCH_B.replace("-int x = 0;", "-int y = 0;")
        rc, line, doc, out = self.run_ks(self.debian("a.patch\nb.patch\n", {"a.patch": PATCH_A, "b.patch": bad}))
        self.assertEqual(rc, 3, line)
        self.assertEqual(doc["status"], "GAP")
        self.assertIn("第 2 個 patch", doc["reason"])
        self.assertIn("只有上游", doc["basis"])
        self.assertFalse(os.path.exists(out))

    def test_series_with_options_or_escape_is_gap(self):
        for series in ("a.patch -p0\n", "../a.patch\n", "/etc/passwd\n", "missing.patch\n"):
            rc, line, doc, _out = self.run_ks(self.debian(series, {"a.patch": PATCH_A}))
            self.assertEqual(rc, 3, (series, line))
            self.assertEqual(doc["status"], "GAP")
            shutil.rmtree(os.path.join(self.tmp, "w"), True)

    def test_changelog_without_version_is_gap(self):
        rc, _line, doc, _out = self.run_ks(self.debian("a.patch\n", {"a.patch": PATCH_A}, changelog=b"garbage\n"))
        self.assertEqual(rc, 3)
        self.assertIn("changelog", doc["reason"])

    def test_unsafe_debian_tar_is_gap(self):
        p = os.path.join(self.tmp, "evil.debian.tar.xz")
        with tarfile.open(p, "w:xz") as t:
            ti = tarfile.TarInfo("debian/../../escape"); ti.size = 1; t.addfile(ti, io.BytesIO(b"x"))
        rc, _line, doc, _out = self.run_ks(p)
        self.assertEqual(rc, 3)
        self.assertEqual(doc["status"], "GAP")


class KernelSourceVerdictTest(unittest.TestCase):
    """scan.json 的 kernel_source：版本要對上映像裡 Debian 核心套件的版本。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wp7-ksv-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def files(self, ks, comps):
        a, b = os.path.join(self.tmp, "ks.json"), os.path.join(self.tmp, "sbom.json")
        with open(a, "w", encoding="utf-8") as f:
            json.dump(ks, f)
        with open(b, "w", encoding="utf-8") as f:
            json.dump({"bomFormat": "CycloneDX", "components": comps}, f)
        return a, b

    def test_match_partial_and_mismatch(self):
        img = [{"name": "linux-image-6.12.116+deb13-amd64", "version": "6.12.116-1"}, {"name": "linux-image-amd64", "version": "6.12.116-1"}]
        ok = {"status": "OK", "basis": "x", "debian_version": "6.12.116-1"}
        self.assertEqual(wp7_scan.kernel_source(*self.files(ok, img))["status"], "OK")
        self.assertEqual(wp7_scan.kernel_source(*self.files(dict(ok, status="GAP"), img))["status"], "PARTIAL")
        r = wp7_scan.kernel_source(*self.files(dict(ok, debian_version="6.12.115-1"), img))
        self.assertEqual(r["status"], "GAP")
        self.assertIn("不同", r["reason"])
        self.assertEqual(wp7_scan.kernel_source(*self.files(ok, []))["status"], "GAP")


if __name__ == "__main__":
    unittest.main()
