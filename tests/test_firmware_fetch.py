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
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = ff.main([self.mf, "--out", self.out], downloader=fake_download(DATA))
        self.assertEqual(rc, 1)
        parts = buf.getvalue().rstrip("\n").split("\t")
        self.assertEqual(parts[:3], ["FIRMWARE-FETCH", "FAIL", "M1"])

    def test_main_ok_exit_code_zero(self):
        self.write(manifest_text())
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = ff.main([self.mf, "--out", self.out], downloader=fake_download(DATA))
        self.assertEqual(rc, 0)
        self.assertTrue(buf.getvalue().startswith("FIRMWARE-FETCH\tOK\tM1\t"))

    def test_curl_command_pins_https_and_size_cap(self):
        import unittest.mock as mock
        seen = []

        def fake_run(cmd, **kw):
            seen.append(cmd)
            return mock.Mock(returncode=0, stderr="")
        with mock.patch.object(ff.subprocess, "run", fake_run):
            self.assertIsNone(ff.curl_download("https://example.com/x.bin", "/dest/x.part", 1234))
        cmd = seen[0]
        self.assertEqual(cmd[0], "curl")
        i = cmd.index("--proto")
        self.assertEqual(cmd[i + 1], "=https")
        i = cmd.index("--proto-redir")
        self.assertEqual(cmd[i + 1], "=https")
        i = cmd.index("--max-filesize")
        self.assertEqual(cmd[i + 1], "1234")
        self.assertIn("--fail", cmd)
        self.assertEqual(cmd[-2:], ["--", "https://example.com/x.bin"])      # URL 在 -- 之後，不會被當成選項

    def test_curl_failure_message_has_exit_code(self):
        import unittest.mock as mock
        with mock.patch.object(ff.subprocess, "run", lambda cmd, **kw: mock.Mock(returncode=63, stderr="too big")):
            msg = ff.curl_download("https://example.com/x.bin", "/dest/x.part", 1)
        self.assertIn("63", msg)

    def test_existing_wrong_file_is_replaced(self):
        self.write(manifest_text())
        os.makedirs(self.dest())
        final = os.path.join(self.dest(), "a.bin")
        with open(final, "wb") as fh:
            fh.write(b"corrupt")
        st, _, _ = self.run_one()
        self.assertEqual(st, "OK")
        with open(final, "rb") as fh:
            self.assertEqual(fh.read(), DATA)
        self.assertEqual(os.listdir(self.dest()), ["a.bin"])

    def test_directory_in_the_way_of_output_file_fails(self):
        self.write(manifest_text())
        os.makedirs(os.path.join(self.dest(), "a.bin"))
        st, _, msg = ff.process(self.mf, self.out, lambda u, d, m: self.fail("不該下載"))
        self.assertEqual(st, "FAIL")
        self.assertIn("拒絕", msg)
        self.assertTrue(os.path.isdir(os.path.join(self.dest(), "a.bin")))

    def test_directory_in_the_way_of_part_file_fails(self):
        self.write(manifest_text())
        os.makedirs(os.path.join(self.dest(), ".a.bin.part"))
        st, _, msg = ff.process(self.mf, self.out, lambda u, d, m: self.fail("不該下載"))
        self.assertEqual(st, "FAIL")
        self.assertIn("拒絕", msg)

    def test_file_in_the_way_of_output_directory_fails(self):
        self.write(manifest_text())
        os.makedirs(self.out)
        with open(os.path.join(self.out, "bios"), "wb") as fh:          # 應該是資料夾的位置是個檔案
            fh.write(b"x")
        st, _, msg = ff.process(self.mf, self.out, lambda u, d, m: self.fail("不該下載"))
        self.assertEqual(st, "FAIL")
        self.assertIn("輸出目錄", msg)

    def test_symlinked_output_directory_fails(self):
        self.write(manifest_text())
        victim = os.path.join(self.tmp.name, "victim_dir")
        os.makedirs(victim)
        os.makedirs(os.path.join(self.out, "bios"))
        os.symlink(victim, os.path.join(self.out, "bios", "slug"))
        st, _, msg = ff.process(self.mf, self.out, lambda u, d, m: self.fail("不該下載"))
        self.assertEqual(st, "FAIL")
        self.assertIn("symlink", msg)
        self.assertEqual(os.listdir(victim), [])

    def test_malicious_file_names_fail_and_download_nothing(self):
        for bad in ("a/b", ".hid", "..", "../a.bin", "-rf", "a b", "a\\b", "/abs"):
            with self.subTest(name=bad):
                self.write(manifest_text().replace("name: a.bin", 'name: "%s"' % bad.replace("\\", "\\\\")))
                st, _, msg = ff.process(self.mf, self.out, lambda u, d, m: self.fail("不該下載"))
                self.assertEqual(st, "FAIL")
                self.assertIn("name 不合法", msg)

    def test_duplicate_file_names_fail(self):
        extra = """  - name: a.bin
    url: https://example.com/b.bin
    sha256: %s
    size: %d
    role: image
""" % (sha(DATA), len(DATA))
        self.write(manifest_text(extra=extra))
        st, _, msg = ff.process(self.mf, self.out, lambda u, d, m: self.fail("不該下載"))
        self.assertEqual(st, "FAIL")
        self.assertIn("重複", msg)

    def test_kind_sbom_accepted_and_fetched_under_sbom_dir(self):
        self.write(manifest_text().replace("kind: bios", "kind: sbom").replace("role: image", "role: sbom"))
        st, _, _ = self.run_one()
        self.assertEqual(st, "OK")
        self.assertTrue(os.path.isfile(os.path.join(self.out, "sbom", "slug", "a.bin")))

    def test_role_sbom_only_with_kind_sbom(self):
        self.write(manifest_text().replace("role: image", "role: sbom"))          # bios + sbom
        st, _, msg = ff.process(self.mf, self.out, lambda u, d, m: self.fail("不該下載"))
        self.assertEqual(st, "FAIL")
        self.assertIn("role: sbom", msg)
        self.write(manifest_text().replace("kind: bios", "kind: sbom"))           # sbom + image
        st, _, msg = ff.process(self.mf, self.out, lambda u, d, m: self.fail("不該下載"))
        self.assertEqual(st, "FAIL")
        self.assertIn("role: sbom", msg)

    def test_kind_escape_fails_and_creates_nothing_outside(self):
        for kind in ("../../x", "bios/../..", "/tmp", "firmware", ""):
            with self.subTest(kind=kind):
                self.write(manifest_text().replace("kind: bios", 'kind: "%s"' % kind))
                st, _, msg = ff.process(self.mf, self.out, lambda u, d, m: self.fail("不該下載"))
                self.assertEqual(st, "FAIL")
                self.assertIn("kind", msg)
        self.assertFalse(os.path.exists(self.out))
        self.assertFalse(os.path.exists(os.path.join(self.tmp.name, "x")))


class RepoManifestsTest(unittest.TestCase):
    def test_all_manifests_valid(self):
        import yaml
        paths = glob.glob(os.path.join(ROOT, "firmware", "*", "*", "firmware.yml"))
        self.assertGreaterEqual(len(paths), 6)
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
