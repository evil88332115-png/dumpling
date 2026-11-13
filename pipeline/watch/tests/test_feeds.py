"""feeds.sh：EUVD 與核心 CVE 經過 pipeline/lib/mirrors.sh。鏡像腳本換成替身（MIRRORS_SCRIPT_DIR），不連網。"""
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
FEEDS = os.path.join(ROOT, "pipeline", "watch", "feeds.sh")

EUVD_STUB = """#!/usr/bin/env bash
mkdir -p "$1"; printf 'x\\n' > "$1/index.tsv"; : > "$2"
echo "OK mirror=$1 manifest=$2"
"""
KCVE_STUB = """#!/usr/bin/env bash
echo "FB=${KERNEL_CVE_FALLBACK_FROM:-} RE=${KERNEL_CVE_REUSE_FROM:-}" >> "$STUB_LOG"
mkdir -p "$1"; : > "$2"
if [ "${STUB_KCVE:-ok}" = fail ]; then : > "$1/partial"; echo "clone 失敗"; exit 1; fi
if [ "${STUB_KCVE:-ok}" = attention ]; then
  printf 'fetched_utc=2026-11-10T01:00:00Z\\nfallback=yes\\nfallback_note=上游連不上：這段時間新增的核心 CVE 不在清單裡\\n' > "$1/SOURCE"
  echo "ATTENTION mirror=$1 manifest=$2 上游連不上"; exit 0
fi
printf 'fetched_utc=2026-11-11T01:00:00Z\\n' > "$1/SOURCE"
echo "OK commit=abc fetched_utc=2026-11-11T01:00:00Z"
"""
GRYPE_STUB = "#!/usr/bin/env bash\nexit 1\n"


class Feeds(unittest.TestCase):
    def setUp(self):
        self.w = tempfile.mkdtemp(prefix="c3-feeds-", dir=os.environ.get("TMPDIR"))
        self.stubs = os.path.join(self.w, "stubs")
        self.bin = os.path.join(self.w, "bin")
        os.makedirs(self.stubs)
        os.makedirs(self.bin)
        for d, name, body in ((self.stubs, "euvd.sh", EUVD_STUB), (self.stubs, "kernel-cve.sh", KCVE_STUB), (self.bin, "grype", GRYPE_STUB)):
            p = os.path.join(d, name)
            with open(p, "w") as f:
                f.write(body)
            os.chmod(p, 0o755)
        self.log = os.path.join(self.w, "stub.log")

    def tearDown(self):
        shutil.rmtree(self.w, ignore_errors=True)

    def run_feeds(self, kcve="ok", cache=None, extra=()):
        out = os.path.join(self.w, "out")
        env = dict(os.environ, MIRRORS_SCRIPT_DIR=self.stubs, MIRRORS_TRIES="1", MIRRORS_RETRY_DELAY="0", STUB_KCVE=kcve, STUB_LOG=self.log,
                   CISA_KEV_URL="https://127.0.0.1:9/kev.json", PATH=self.bin + os.pathsep + os.environ.get("PATH", ""))
        env.pop("KCVE_CACHE_DIR", None)
        if cache:
            env["KCVE_CACHE_DIR"] = cache
        r = subprocess.run(["bash", FEEDS, out, *extra], env=env, capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        rows = {}
        with open(os.path.join(out, "feeds.tsv"), encoding="utf-8") as f:
            for line in f:
                n, st, msg = line.rstrip("\n").split("\t")
                rows[n] = (st, msg)
        return out, rows, r.stdout

    def test_ok(self):
        out, rows, _ = self.run_feeds()
        self.assertEqual(rows["euvd"][0], "OK")
        self.assertEqual(rows["kernel-cve"][0], "OK")
        self.assertTrue(os.path.isfile(os.path.join(out, "kernel-cve", "SOURCE")))
        self.assertTrue(open(os.path.join(out, "kernel-cve.result")).read().startswith("OK"))
        self.assertEqual(rows["cisa-kev"][0], "GAP")          # 測試不連網
        self.assertEqual(rows["grype-db"][0], "GAP")

    def test_attention_row_and_warning(self):
        out, rows, stdout = self.run_feeds(kcve="attention")
        self.assertEqual(rows["kernel-cve"][0], "ATTENTION")
        self.assertIn("::warning::鏡像 kernel-cve 用了舊資料頂替", stdout)
        self.assertTrue(open(os.path.join(out, "kernel-cve.result")).read().startswith("ATTENTION"))

    def test_failure_removes_partial_mirror(self):
        out, rows, _ = self.run_feeds(kcve="fail")
        self.assertEqual(rows["kernel-cve"][0], "GAP")
        self.assertFalse(os.path.exists(os.path.join(out, "kernel-cve")))
        self.assertFalse(os.path.exists(os.path.join(out, "kernel-cve.result")))

    def test_cache_dir_passed_as_reuse_and_fallback(self):
        cache = os.path.join(self.w, "cache", "kcve")
        os.makedirs(cache)
        open(os.path.join(cache, "SOURCE"), "w").write("fetched_utc=2026-11-10T01:00:00Z\n")
        self.run_feeds(cache=cache)
        self.assertIn(f"FB={cache} RE={cache}", open(self.log).read())

    def test_cache_dir_without_source_not_used(self):
        cache = os.path.join(self.w, "cache", "kcve")
        os.makedirs(cache)
        self.run_feeds(cache=cache)
        self.assertIn("FB= RE=", open(self.log).read())

    def test_drill_flags(self):
        _, rows, _ = self.run_feeds(extra=("--no-kernel-cve", "--no-euvd"))
        self.assertEqual(rows["euvd"][0], "NOT_RUN")
        self.assertEqual(rows["kernel-cve"][0], "NOT_RUN")
        self.assertFalse(os.path.exists(self.log))


if __name__ == "__main__":
    unittest.main()
