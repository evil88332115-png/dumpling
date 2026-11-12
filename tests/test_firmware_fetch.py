"""firmware-fetch 的單元測試。不連網：下載動作用注入的假函式取代。"""
import glob
import hashlib
import importlib.util
import os
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location(
    "firmware_fetch", os.path.join(ROOT, "pipeline", "lib", "firmware_fetch.py"))
ff = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ff)

DATA = b"firmware-bytes" * 10


def sha(b):
    return hashlib.sha256(b).hexdigest()


def fake_download(content):
    def dl(url, dest, max_size):
        with open(dest, "wb") as fh:
            fh.write(content)
        return None
    return dl


def manifest_text(status="ok", content=DATA, size=None, sha_=None, extra=""):
    size = len(content) if size is None else size
    sha_ = sha(content) if sha_ is None else sha_
    return f"""kind: bios
vendor: V
model: M1
firmware_version: "1"
ibv: unknown
status: {status}
notes: n
license: {{name: L, url: "https://example.com/l", note: x}}
files:
  - name: a.bin
    url: https://example.com/a.bin
    sha256: {sha_}
    size: {size}
    role: image
{extra}"""


class FetchTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = os.path.join(self.tmp.name, "out")
        os.makedirs(os.path.join(self.tmp.name, "m", "slug"))
        self.mf = os.path.join(self.tmp.name, "m", "slug", "firmware.yml")

    def write(self, text):
        with open(self.mf, "w", encoding="utf-8") as fh:
            fh.write(text)

    def run_one(self, content=DATA):
        return ff.process(self.mf, self.out, fake_download(content))

    def dest(self):
        return os.path.join(self.out, "bios", "slug")

    def test_ok(self):
        self.write(manifest_text())
        st, model, _ = self.run_one()
        self.assertEqual((st, model), ("OK", "M1"))
        self.assertTrue(os.path.isfile(os.path.join(self.dest(), "a.bin")))
        self.assertEqual(os.listdir(self.dest()), ["a.bin"])

    def test_sha_mismatch_leaves_nothing(self):
        self.write(manifest_text(sha_="0" * 64))
        st, _, msg = self.run_one()
        self.assertEqual(st, "FAIL")
        self.assertIn("sha256", msg)
        self.assertEqual(os.listdir(self.dest()), [])

    def test_size_mismatch(self):
        self.write(manifest_text(size=len(DATA) + 1))
        st, _, msg = self.run_one()
        self.assertEqual(st, "FAIL")
        self.assertIn("大小", msg)
        self.assertEqual(os.listdir(self.dest()), [])

    def test_download_error(self):
        self.write(manifest_text())
        st, _, _ = ff.process(self.mf, self.out, lambda u, d, m: "網路錯誤")
        self.assertEqual(st, "FAIL")
        self.assertEqual(os.listdir(self.dest()), [])

    def test_symlink_refused(self):
        self.write(manifest_text())
        os.makedirs(self.dest())
        target = os.path.join(self.tmp.name, "victim")
        with open(target, "wb") as fh:
            fh.write(b"keep")
        os.symlink(target, os.path.join(self.dest(), "a.bin"))
        st, _, msg = self.run_one()
        self.assertEqual(st, "FAIL")
        self.assertIn("拒絕", msg)
        with open(target, "rb") as fh:
            self.assertEqual(fh.read(), b"keep")

    def test_symlink_part_file_refused(self):
        self.write(manifest_text())
        os.makedirs(self.dest())
        os.symlink("/nonexistent", os.path.join(self.dest(), ".a.bin.part"))
        st, _, _ = self.run_one()
        self.assertEqual(st, "FAIL")

    def test_existing_good_file_ok_without_download(self):
        self.write(manifest_text())
        os.makedirs(self.dest())
        with open(os.path.join(self.dest(), "a.bin"), "wb") as fh:
            fh.write(DATA)
        st, _, _ = ff.process(self.mf, self.out, lambda u, d, m: "不該下載")
        self.assertEqual(st, "OK")

    def test_gap_skipped(self):
        self.write("kind: vbios\nvendor: V\nmodel: G\nstatus: GAP\nnotes: |\n  沒有檔案\n")
        st, model, _ = ff.process(self.mf, self.out, lambda u, d, m: self.fail("GAP 不該下載"))
        self.assertEqual((st, model), ("GAP", "G"))
        self.assertFalse(os.path.exists(self.out))

    def test_missing_fields(self):
        self.write("kind: bios\nvendor: V\nmodel: M\nstatus: ok\nnotes: n\n")
        st, _, msg = self.run_one()
        self.assertEqual(st, "FAIL")
        self.assertIn("files", msg)

    def test_bad_manifest_values(self):
        for bad in (manifest_text(sha_="xyz"), manifest_text().replace("https://example.com/a.bin", "http://example.com/a.bin"),
                    manifest_text().replace("a.bin\n    url", "../a.bin\n    url")):
            self.write(bad)
            self.assertEqual(self.run_one()[0], "FAIL")

    def test_main_exit_code_and_line_format(self):
        self.write(manifest_text(sha_="0" * 64))
        import io
        import contextlib
        old = ff.curl_download
        buf = io.StringIO()
        try:
            ff.process.__defaults__ = (fake_download(DATA),)
            with contextlib.redirect_stdout(buf):
                rc = ff.main([self.mf, "--out", self.out])
        finally:
            ff.process.__defaults__ = (old,)
        self.assertEqual(rc, 1)
        parts = buf.getvalue().rstrip("\n").split("\t")
        self.assertEqual(parts[:3], ["FIRMWARE-FETCH", "FAIL", "M1"])


class RepoManifestsTest(unittest.TestCase):
    def test_all_manifests_valid(self):
        import yaml
        paths = glob.glob(os.path.join(ROOT, "firmware", "*", "*", "firmware.yml"))
        self.assertGreaterEqual(len(paths), 4)
        for p in paths:
            with open(p, encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
            self.assertEqual(ff.validate(doc), [], p)
            self.assertEqual(doc["kind"], os.path.basename(os.path.dirname(os.path.dirname(p))), p)
            self.assertIn("license", doc if doc["status"] == "ok" else {"license": 1}, p)
            for f in doc.get("files", []):
                self.assertRegex(f["sha256"], r"^[0-9a-f]{64}$", p)
                self.assertTrue(f["url"].startswith("https://"), p)


if __name__ == "__main__":
    unittest.main()
