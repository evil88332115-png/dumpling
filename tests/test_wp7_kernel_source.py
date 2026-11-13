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


class KernelVersionsNotesTest(unittest.TestCase):
    """notes.md 的核心一節：kernel-versions.json 的清單是字串或物件（schema /1 的 not_judged、/2 的 shipped）都要能列出。"""

    def notes(self, kv):
        h = wp7_scan.Wp7Hooks({})
        ctx = {"asm": {}, "main_run": {"kernel_versions": kv}, "project": "p", "version": "v1"}
        return "\n".join(h.notes_build(ctx))

    def test_not_judged_objects_and_shipped_objects(self):
        kv = {"schema": "sca-center-kernel-versions/2", "shipped": [{"version": "6.18.50+rpt-rpi-2712"}, {"version": "6.18.50+rpt-rpi-v8"}],
              "requested": ["6.18.50+rpt-rpi-2712"], "judged": ["6.18.50+rpt-rpi-2712"],
              "not_judged": [{"version": "6.18.50+rpt-rpi-v8", "reason": "出貨但沒有列在 --kernel-version", "shipped": True}]}
        t = self.notes(kv)
        self.assertIn("已出貨、未判定（GAP）**：6.18.50+rpt-rpi-v8（出貨但沒有列在 --kernel-version）", t)
        self.assertIn("映像裡的核心：6.18.50+rpt-rpi-2712、6.18.50+rpt-rpi-v8", t)

    def test_product_status_is_listed_separately(self):
        h = wp7_scan.Wp7Hooks({})
        ctx = {"asm": {}, "main_run": {}, "runs": {"": {"report_status": "GAP", "release_gate": "GAP"},
                                                   "-bsp": {"report_status": "GAP", "release_gate": "GAP"}}}
        t = "\n".join(h.notes_build(ctx))
        self.assertIn("產品報告的狀態（不是流程步驟的結果）", t)
        self.assertIn("bsp：報告 **GAP**、發行閘門 **GAP**", t)

    def test_missing_file_is_gap(self):
        self.assertIn("讀不到 kernel-versions.json", self.notes(None))

    def test_full_report_note_depends_on_os_responsibility(self):
        h = wp7_scan.Wp7Hooks({})
        ours = "\n".join(h.notes_after_vulnerabilities({"layers": {"os_responsibility": "ours"}}))
        self.assertIn("分層**之後**", ours)
        self.assertNotIn("分層**之前**", ours)
        cust = "\n".join(h.notes_after_vulnerabilities({"layers": {"os_responsibility": "customer"}}))
        self.assertIn("分層**之前**", cust)


class OwnSoftwareTest(unittest.TestCase):
    def test_summary_and_missing_file(self):
        tmp = tempfile.mkdtemp(prefix="wp7-own-"); self.addCleanup(shutil.rmtree, tmp, True)
        p = os.path.join(tmp, "own-software.json")
        self.assertIsNone(wp7_scan.own_software_summary(p))          # 沒有檔：null，不推測
        with open(p, "w", encoding="utf-8") as f:
            json.dump({"status": "GAP", "files": [], "patterns": [{"pattern": "TO BE COMPLETED", "status": "GAP", "matched": 0, "reasons": ["x"]}]}, f)
        self.assertEqual(wp7_scan.own_software_summary(p),
                         {"status": "GAP", "patterns": [{"pattern": "TO BE COMPLETED", "status": "GAP", "matched": 0}], "files": 0})


class DocumentStatusTest(unittest.TestCase):
    def test_documents_and_missing_fields_from_summary(self):
        tmp = tempfile.mkdtemp(prefix="wp7-doc-"); self.addCleanup(shutil.rmtree, tmp, True)
        rep = os.path.join(tmp, "reports"); os.makedirs(rep)
        with open(os.path.join(rep, "summary.json"), "w", encoding="utf-8") as f:
            json.dump({"status": "GAP", "documents": {"user-information": {"status": "GAP", "detail": ["x"]}, "sbom": {"status": "OK"}},
                       "missing_fields": ["a", "b"], "vex": {"gate": {"verdict": "GAP"}}}, f)
        paths = {"rootfs": os.path.join(tmp, "r"), "scan": os.path.join(tmp, "s"), "reports": rep}
        r = wp7_scan.Wp7Hooks({}).run_summary_fields(paths, {})
        self.assertEqual(r["documents"], {"user-information": "GAP", "sbom": "OK"})
        self.assertEqual((r["missing_fields"], r["report_status"], r["release_gate"], r["own_software"]), (2, "GAP", "GAP", None))
        os.remove(os.path.join(rep, "summary.json"))
        r = wp7_scan.Wp7Hooks({}).run_summary_fields(paths, {})
        self.assertEqual((r["documents"], r["missing_fields"]), (None, None))     # 讀不到：null，不推測


class ExternalServicesTest(unittest.TestCase):
    def test_platform_without_list_is_not_assessed(self):
        r = wp7_scan.services("/nonexistent", "rockchip")
        self.assertEqual((r["status"], r["items"]), ("NOT_ASSESSED", []))

    def test_raspberrypi_lists_rpi_connect(self):
        tmp = tempfile.mkdtemp(prefix="wp7-svc-"); self.addCleanup(shutil.rmtree, tmp, True)
        p = os.path.join(tmp, "s.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump({"components": [{"name": "rpi-connect-lite", "version": "2.13.0", "properties": [{"name": "dumpling:layer", "value": "os"}]},
                                      {"name": "bash", "version": "5"}]}, f)
        r = wp7_scan.services(p, "raspberrypi")
        self.assertEqual(r["status"], "LISTED")
        self.assertEqual([(h["name"], h["layer"]) for h in r["items"]], [("rpi-connect-lite", "os")])


if __name__ == "__main__":
    unittest.main()
