"""pipeline/lib/mirrors.sh 的內部鏡像模式（T-06）與 tools/mirror/cisa-kev.sh。不連網：假的 curl／git／grype 放在 PATH 最前面，
被呼叫就留標記；每個情境都要確認標記資料夾是空的（沒有任何公開下載），不只是成功的情境。"""
import json
import datetime
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import internal_mirror_support as S  # noqa: E402

KEV_SH = os.path.join(S.REAL_SCRIPTS, "cisa-kev.sh")


class Base(unittest.TestCase):
    def setUp(self):
        self.e = S.Env()
        self.steps = os.path.join(self.e.w, "pipeline-steps.tsv")
        self.stublog = os.path.join(self.e.w, "stub.log")

    def tearDown(self):
        self.e.cleanup()

    def run_fn(self, call, stubs=True, **extra):
        kw = dict(INTERNAL_MIRROR_URL=self.e.url(), MIRRORS_STEPS=self.steps, STUB_LOG=self.stublog)
        kw.update(extra)
        env = self.e.env(**kw)
        if stubs:
            env["MIRRORS_SCRIPT_DIR"] = self.e.stubs
        for k in [k for k, v in env.items() if v is None]:
            del env[k]
        return subprocess.run(["bash", "-c", '. "%s"; %s' % (S.MIRROR_SH, call)], capture_output=True, text=True, env=env, timeout=120)

    def result(self, d):
        with open(os.path.join(self.e.out, d + ".result"), encoding="utf-8") as f:
            return f.read()

    def no_public(self):
        self.assertEqual(self.e.marked(), [], "有公開下載或 grype db update 的標記")


class Success(Base):
    def test_ok_copies_checks_and_never_downloads(self):
        self.e.stub("kernel-cve.sh")
        src = self.e.write_source("kernel-cve", hours_ago=2)
        r = self.run_fn("mirror kernel-cve.sh kcve; echo rc=$?")
        self.assertIn("rc=0", r.stdout, r.stdout + r.stderr)
        self.assertIn("鏡像 kcve：OK（OK source=internal kind=kernel-cve fetched_utc=", r.stdout)
        self.no_public()
        # 複本與來源一樣；資料夾名是呼叫端給的（kcve），種類由腳本名決定
        self.assertEqual(open(os.path.join(self.e.out, "kcve", "data.bin")).read(), "kernel-cve")
        self.assertTrue(os.path.isfile(os.path.join(src, "SOURCE")))
        res = self.result("kcve")
        self.assertTrue(res.startswith("OK source=internal kind=kernel-cve "), res)
        man = open(os.path.join(self.e.out, "kcve.manifest"), encoding="utf-8").read()
        self.assertIn("source=internal", man)
        self.assertIn("data.bin", man)
        for text in (res, man, r.stdout):                    # 不寫實際路徑
            self.assertNotIn(self.e.root, text)
        self.assertFalse(os.path.exists(self.steps))          # OK 不記列
        self.assertIn("check", open(self.stublog).read())

    def test_symlink_as_the_kind_folder_itself_is_accepted(self):
        # 同步腳本用連結換版：<根>/<種類> 本身可以是指向資料夾的連結，裡面不可以有連結
        self.e.stub("kernel-cve.sh")
        real = self.e.write_source("kernel-cve.v1", hours_ago=2)
        os.symlink(real, os.path.join(self.e.root, "kernel-cve"))
        r = self.run_fn("mirror kernel-cve.sh kcve; echo rc=$?")
        self.assertIn("rc=0", r.stdout, r.stdout + r.stderr)
        self.assertTrue(os.path.isfile(os.path.join(self.e.out, "kcve", "SOURCE")))
        self.assertFalse(os.path.islink(os.path.join(self.e.out, "kcve")))
        self.no_public()

    def test_every_kind_reads_its_own_folder(self):
        for name, writer in (("osv-distro", lambda: self.e.write_source("osv-distro")), ("nvidia-bulletins", lambda: self.e.write_source("nvidia-bulletins")),
                             ("euvd", self.e.write_euvd), ("grype-db", self.e.write_grype_db)):
            self.e.stub(name + ".sh")
            writer()
            r = self.run_fn("mirror %s.sh x-%s; echo rc=$?" % (name, name))
            self.assertIn("rc=0", r.stdout, name + r.stdout + r.stderr)
            self.assertIn("kind=" + name, self.result("x-" + name))
        self.no_public()

    def test_real_kernel_cve_check_and_real_kev_check(self):
        # 不用替身：真的 kernel-cve.sh --check、cisa-kev.sh --check
        self.e.write_real_kernel_cve(hours_ago=3)
        self.e.write_real_kev(hours_ago=3)
        r = self.run_fn("mirror kernel-cve.sh kcve; echo rc=$?; mirror cisa-kev.sh kev; echo rc=$?", stubs=False, KERNEL_CVE_MIN_RECORDS="1")
        self.assertEqual(r.stdout.count("rc=0"), 2, r.stdout + r.stderr)
        self.no_public()

    def test_internal_mode_ignores_kcve_cache_dir(self):
        self.e.stub("kernel-cve.sh")
        self.e.write_source("kernel-cve")
        cache = os.path.join(self.e.w, "cache")
        os.makedirs(cache)
        open(os.path.join(cache, "SOURCE"), "w").write("fetched_utc=2026-11-10T01:00:00Z\n")
        r = self.run_fn("mirror_kernel_cve kcve; echo rc=$?", KCVE_CACHE_DIR=cache)
        self.assertIn("rc=0", r.stdout, r.stdout + r.stderr)
        self.assertIn("REUSE= FALLBACK=", open(self.stublog).read())
        self.no_public()

    def test_fresh_copy_is_never_saved_back_to_cache(self):
        self.e.stub("kernel-cve.sh")
        self.e.write_source("kernel-cve")
        r = self.run_fn("mirror kernel-cve.sh kcve && mirror_is_fresh kcve; echo fresh=$?")
        self.assertIn("fresh=1", r.stdout, r.stdout + r.stderr)
        # 就算之後 INTERNAL_MIRROR_URL 不在了，.result 的 source=internal 也讓它不算新抓的
        r = self.run_fn("mirror_is_fresh kcve; echo fresh=$?", INTERNAL_MIRROR_URL=None)
        self.assertIn("fresh=1", r.stdout, r.stdout + r.stderr)
        self.no_public()


class Freshness(Base):
    def attention(self, hours, **extra):
        self.e.stub("kernel-cve.sh")
        self.e.write_source("kernel-cve", hours_ago=hours)
        r = self.run_fn("mirror kernel-cve.sh kcve; echo rc=$?", **extra)
        self.assertIn("rc=0", r.stdout, r.stdout + r.stderr)
        self.no_public()
        return r, self.result("kcve")

    def test_default_threshold_is_36_hours(self):
        _, res = self.attention(35)
        self.assertTrue(res.startswith("OK "), res)
        r, res = self.attention(37)
        self.assertTrue(res.startswith("ATTENTION source=internal kind=kernel-cve "), res)
        self.assertIn("36 小時", res)
        self.assertIn("::warning::", r.stdout)
        rows = open(self.steps, encoding="utf-8").read().splitlines()
        self.assertEqual(len(rows), 1)
        step, status, rc, detail = rows[0].split("\t")
        self.assertEqual((step, status, rc), ("pipeline-kernel-cve-mirror", "ATTENTION", "0"))
        self.assertTrue(detail.startswith("ATTENTION source=internal"))

    def test_threshold_can_be_changed(self):
        _, res = self.attention(40, INTERNAL_MIRROR_FRESH_HOURS="48")
        self.assertTrue(res.startswith("OK "), res)
        _, res = self.attention(5, INTERNAL_MIRROR_FRESH_HOURS="2.5")
        self.assertTrue(res.startswith("ATTENTION"), res)

    def test_fallback_data_inside_the_internal_mirror_is_attention(self):
        self.e.stub("kernel-cve.sh")
        self.e.write_source("kernel-cve", hours_ago=1, extra="fallback=yes\n")
        r = self.run_fn("mirror kernel-cve.sh kcve; echo rc=$?")
        self.assertIn("rc=0", r.stdout)
        self.assertTrue(self.result("kcve").startswith("ATTENTION"), self.result("kcve"))
        self.assertIn("fallback=yes", self.result("kcve"))
        self.no_public()

    def test_euvd_age_comes_from_index_header_and_grype_from_built(self):
        self.e.stub("euvd.sh")
        self.e.stub("grype-db.sh")
        self.e.write_euvd(hours_ago=50)
        self.e.write_grype_db(hours_ago=50)
        r = self.run_fn("mirror euvd.sh euvd; mirror grype-db.sh gdb; echo rc=$?")
        self.assertIn("rc=0", r.stdout, r.stdout + r.stderr)
        self.assertTrue(self.result("euvd").startswith("ATTENTION"))
        self.assertTrue(self.result("gdb").startswith("ATTENTION"))
        self.assertIn("built_utc=", self.result("gdb"))
        self.no_public()

    def test_real_check_limit_is_a_failure_not_attention(self):
        # 真的 kernel-cve.sh --check：超過 7 天上限 → 失敗（就算把 INTERNAL_MIRROR_MAX_HOURS 放寬）；60 小時（超過 36、沒到 72）→ ATTENTION
        self.e.write_real_kernel_cve(hours_ago=24 * 8)
        r = self.run_fn("mirror kernel-cve.sh kcve; echo rc=$?", stubs=False, KERNEL_CVE_MIN_RECORDS="1", INTERNAL_MIRROR_MAX_HOURS="1000")
        self.assertIn("rc=1", r.stdout, r.stdout + r.stderr)
        self.assertIn("過期", r.stdout)
        self.assertFalse(os.path.exists(os.path.join(self.e.out, "kcve")))
        self.assertFalse(os.path.exists(os.path.join(self.e.out, "kcve.result")))
        self.no_public()
        self.e.write_real_kernel_cve(hours_ago=60)
        r = self.run_fn("mirror kernel-cve.sh kcve; echo rc=$?", stubs=False, KERNEL_CVE_MIN_RECORDS="1")
        self.assertIn("rc=0", r.stdout, r.stdout + r.stderr)
        self.assertTrue(self.result("kcve").startswith("ATTENTION"))
        self.no_public()

    def test_default_failure_threshold_is_72_hours(self):
        # 沒超過腳本 --check 的上限（真的核心 7 天），但超過 INTERNAL_MIRROR_MAX_HOURS（預設 72）→ 失敗
        self.e.write_real_kernel_cve(hours_ago=71)
        r = self.run_fn("mirror kernel-cve.sh kcve; echo rc=$?", stubs=False, KERNEL_CVE_MIN_RECORDS="1")
        self.assertIn("rc=0", r.stdout, r.stdout + r.stderr)
        self.assertTrue(self.result("kcve").startswith("ATTENTION"))
        self.e.write_real_kernel_cve(hours_ago=73)
        r = self.run_fn("mirror kernel-cve.sh kcve; echo rc=$?", stubs=False, KERNEL_CVE_MIN_RECORDS="1")
        self.assertIn("rc=1", r.stdout, r.stdout + r.stderr)
        self.assertIn("INTERNAL_MIRROR_MAX_HOURS=72", r.stdout)
        self.assertFalse(os.path.exists(os.path.join(self.e.out, "kcve.result")))
        self.no_public()
        r = self.run_fn("mirror kernel-cve.sh kcve; echo rc=$?", stubs=False, KERNEL_CVE_MIN_RECORDS="1", INTERNAL_MIRROR_MAX_HOURS="100")
        self.assertIn("rc=0", r.stdout, r.stdout + r.stderr)

    def test_max_hours_is_stricter_than_a_lenient_check(self):
        # 替身 --check 一律通過，失敗門檻仍然擋住（兩者取較嚴的）
        self.e.stub("euvd.sh")
        self.e.write_euvd(hours_ago=80)
        r = self.run_fn("mirror euvd.sh euvd; echo rc=$?")
        self.assertIn("rc=1", r.stdout, r.stdout + r.stderr)
        self.no_public()

    def test_unreadable_time_fails(self):
        self.e.stub("kernel-cve.sh")
        d = self.e.source_dir("kernel-cve")
        open(os.path.join(d, "SOURCE"), "w").write("source=x\nfetched_utc=not-a-time\n")
        r = self.run_fn("mirror kernel-cve.sh kcve; echo rc=$?")
        self.assertIn("rc=1", r.stdout, r.stdout + r.stderr)
        self.assertIn("無法判斷新舊", r.stdout)
        self.no_public()

    def test_missing_or_naive_time_fails(self):
        """SOURCE 缺 fetched_utc、或時間沒有時區 → 判斷不了新舊 → 失敗（不能當成剛抓到的）。"""
        import datetime
        naive = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%S")   # 2 小時前、沒有時區
        for body in ("source=x\n", f"source=x\nfetched_utc={naive}\n", "source=x\nfetched_utc=\n"):
            with self.subTest(body=body):
                self.e.stub("kernel-cve.sh")
                d = self.e.source_dir("kernel-cve")
                open(os.path.join(d, "SOURCE"), "w").write(body)
                r = self.run_fn("mirror kernel-cve.sh kcve; echo rc=$?")
                self.assertIn("rc=1", r.stdout, r.stdout + r.stderr)
                self.assertNotIn("Traceback", r.stdout + r.stderr)
                self.no_public()

    def test_grype_db_without_usable_built_fails(self):
        """Grype 的 latest.json 缺 built、built 不是字串、沒有時區 → 失敗。"""
        import json
        import datetime
        naive = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%S")
        for built in (None, 1731830400, naive):
            with self.subTest(built=built):
                self.e.stub("grype-db.sh")
                d = self.e.write_grype_db()
                f = os.path.join(d, "v6", "latest.json")
                doc = json.load(open(f, encoding="utf-8"))
                if built is None:
                    doc.pop("built")
                else:
                    doc["built"] = built
                json.dump(doc, open(f, "w", encoding="utf-8"))
                r = self.run_fn("mirror grype-db.sh gdb; echo rc=$?")
                self.assertIn("rc=1", r.stdout, r.stdout + r.stderr)
                self.assertNotIn("Traceback", r.stdout + r.stderr)
                self.no_public()

    def test_future_time_fails(self):
        self.e.stub("kernel-cve.sh")
        self.e.write_source("kernel-cve", hours_ago=-48)
        r = self.run_fn("mirror kernel-cve.sh kcve; echo rc=$?")
        self.assertIn("rc=1", r.stdout, r.stdout + r.stderr)
        self.no_public()


class Failures(Base):
    """來源壞掉的各種情況：mirror 回傳 1、不留不完整的複本、沒有 .result、而且沒有任何公開下載。"""

    def fails(self, call="mirror kernel-cve.sh kcve", want=None, **extra):
        r = self.run_fn(call + "; echo rc=$?", **extra)
        self.assertIn("rc=1", r.stdout, r.stdout + r.stderr)
        if want:
            self.assertIn(want, r.stdout)
        self.assertFalse(os.path.exists(os.path.join(self.e.out, "kcve")))
        self.assertFalse(os.path.exists(os.path.join(self.e.out, "kcve.result")))
        self.assertIn("不改走公開網址", r.stdout)
        self.no_public()
        return r

    def test_missing_source_folder(self):
        self.e.stub("kernel-cve.sh")
        self.fails(want="沒有同步到 runner 主機")

    def test_missing_root(self):
        self.e.stub("kernel-cve.sh")
        os.rmdir(self.e.root)
        self.fails(want="根目錄不存在")

    def test_source_is_a_file_not_a_folder(self):
        self.e.stub("kernel-cve.sh")
        open(os.path.join(self.e.root, "kernel-cve"), "w").write("x")
        self.fails()

    def test_check_failure(self):
        self.e.stub("kernel-cve.sh")
        self.e.write_source("kernel-cve")
        self.fails(want="--check 失敗", STUB_CHECK="fail")

    def test_symlink_inside_source(self):
        self.e.stub("kernel-cve.sh")
        d = self.e.write_source("kernel-cve")
        outside = os.path.join(self.e.w, "outside.txt")
        open(outside, "w").write("secret")
        os.symlink(outside, os.path.join(d, "evil"))
        self.fails(want="evil")

    def test_symlink_in_nested_folder(self):
        self.e.stub("kernel-cve.sh")
        d = self.e.write_source("kernel-cve")
        os.makedirs(os.path.join(d, "sub"))
        os.symlink("/etc", os.path.join(d, "sub", "link"))
        self.fails(want="sub/link")

    def test_fifo_inside_source_does_not_hang(self):
        self.e.stub("kernel-cve.sh")
        d = self.e.write_source("kernel-cve")
        os.mkfifo(os.path.join(d, "pipe"))
        self.fails(want="pipe")

    def test_script_without_a_kind(self):
        self.e.stub("ubuntu-cve-status.sh")
        r = self.run_fn("mirror ubuntu-cve-status.sh x; echo rc=$?")
        self.assertIn("rc=1", r.stdout)
        self.no_public()

    def test_real_cisa_kev_check_failures(self):
        d, raw = self.e.write_real_kev()
        with open(os.path.join(d, "known_exploited_vulnerabilities.json"), "ab") as f:      # 改過內容：sha256 與 SOURCE 不符
            f.write(b" ")
        r = self.run_fn("mirror cisa-kev.sh kev; echo rc=$?", stubs=False)
        self.assertIn("rc=1", r.stdout, r.stdout + r.stderr)
        self.assertIn("sha256", r.stdout)
        self.no_public()


class UsageErrors(Base):
    BAD = ("https://mirror.example/x", "file://relative/x", "file:///a/../b", "file:///a?x=1", "file:///a#f", "file:///a b", "file:///a\tb",
           "file:///a\nb", "file://localhost/srv", "file:///", "file:////srv//x", "/srv/mirror", "srv/mirror", "FILE:///srv", "file:///srv/%2e%2e/x",
           "file:///srv/./x", " file:///srv", "http://x/y", "file:///srv/..", "file:///srv/a..b")

    def test_bad_values_are_usage_errors_and_never_public(self):
        self.e.stub("kernel-cve.sh")
        self.e.write_source("kernel-cve")
        for v in self.BAD:
            with self.subTest(value=v):
                r = self.run_fn("mirror kernel-cve.sh kcve; echo rc=$?", INTERNAL_MIRROR_URL=v)
                self.assertIn("rc=64", r.stdout, r.stdout + r.stderr)
                self.assertIn("用法錯誤", r.stderr)
                self.assertIn("不會改走公開網址", r.stderr)
                self.assertFalse(os.path.exists(os.path.join(self.e.out, "kcve")))
                self.no_public()

    def test_value_is_not_echoed(self):
        r = self.run_fn("mirror kernel-cve.sh kcve; echo rc=$?", INTERNAL_MIRROR_URL="https://user:hunter2@mirror.example/x")
        self.assertNotIn("hunter2", r.stdout + r.stderr)

    def test_require_without_url(self):
        self.e.stub("kernel-cve.sh")
        for url in (None, ""):
            with self.subTest(url=url):
                r = self.run_fn("mirror kernel-cve.sh kcve; echo rc=$?", INTERNAL_MIRROR_URL=url, DUMPLING_REQUIRE_INTERNAL_MIRROR="1")
                self.assertIn("rc=64", r.stdout, r.stdout + r.stderr)
                self.assertIn("INTERNAL_MIRROR_URL 沒設", r.stderr)
                self.no_public()

    def test_require_other_values_are_usage_errors(self):
        for v in ("true", "yes", "2"):
            with self.subTest(v=v):
                r = self.run_fn("mirror kernel-cve.sh kcve; echo rc=$?", DUMPLING_REQUIRE_INTERNAL_MIRROR=v)
                self.assertIn("rc=64", r.stdout, r.stdout + r.stderr)
        self.no_public()

    def test_bad_fresh_hours(self):
        self.e.stub("kernel-cve.sh")
        self.e.write_source("kernel-cve")
        for v in ("0", "0.0", "abc", "-1", "1e3", "36h"):
            with self.subTest(v=v):
                r = self.run_fn("mirror kernel-cve.sh kcve; echo rc=$?", INTERNAL_MIRROR_FRESH_HOURS=v)
                self.assertIn("rc=64", r.stdout, r.stdout + r.stderr)
        self.no_public()

    def test_bad_max_hours(self):
        self.e.stub("kernel-cve.sh")
        self.e.write_source("kernel-cve")
        for k, v in (("INTERNAL_MIRROR_MAX_HOURS", "0"), ("INTERNAL_MIRROR_MAX_HOURS", "abc"), ("INTERNAL_MIRROR_MAX_HOURS", "10"),   # 比新鮮門檻 36 小
                     ("INTERNAL_MIRROR_KEV_FILE_FRESH_DAYS", "0"), ("INTERNAL_MIRROR_KEV_FILE_FRESH_DAYS", "x")):
            with self.subTest(k=k, v=v):
                r = self.run_fn("mirror kernel-cve.sh kcve; echo rc=$?", **{k: v})
                self.assertIn("rc=64", r.stdout, r.stdout + r.stderr)
        self.no_public()

    def test_mirror_kernel_cve_and_grype_mode_also_fail_with_64(self):
        r = self.run_fn("mirror_kernel_cve kcve; echo rc=$?; grype_db_mode g; echo rc=$?", INTERNAL_MIRROR_URL="https://x/y")
        self.assertEqual(r.stdout.count("rc=64"), 2, r.stdout + r.stderr)
        self.assertNotIn("online", r.stdout)
        self.no_public()

    def test_empty_or_unset_without_require_is_the_public_mode(self):
        # 沒設（或空字串）= 公開模式：跑下載腳本（替身），行為和以前一樣
        self.e.stub("kernel-cve.sh")
        for url in (None, ""):
            with self.subTest(url=url):
                r = self.run_fn("mirror kernel-cve.sh kcve; echo rc=$?", INTERNAL_MIRROR_URL=url, DUMPLING_REQUIRE_INTERNAL_MIRROR=None)
                self.assertIn("rc=0", r.stdout, r.stdout + r.stderr)
                self.assertIn("鏡像 kcve：OK（OK mirror=", r.stdout)
                self.assertTrue(os.path.exists(os.path.join(self.e.marks, "download-ran")))
                os.remove(os.path.join(self.e.marks, "download-ran"))
        r = self.run_fn("mirror kernel-cve.sh kcve; echo rc=$?", INTERNAL_MIRROR_URL=None, DUMPLING_REQUIRE_INTERNAL_MIRROR="0")
        self.assertIn("rc=0", r.stdout)


class GrypeDbMode(Base):
    def test_public_mode_is_online(self):
        r = self.run_fn("grype_db_mode g; echo rc=$?", INTERNAL_MIRROR_URL=None)
        self.assertEqual(r.stdout.split(), ["online", "rc=0"], r.stdout + r.stderr)

    def test_internal_mode_imports_from_the_copy(self):
        self.e.stub("grype-db.sh")
        self.e.write_grype_db()
        r = self.run_fn("grype_db_mode g; echo rc=$?")
        lines = r.stdout.splitlines()
        self.assertEqual(lines[-1], "rc=0", r.stdout + r.stderr)
        self.assertEqual(lines[0], "import:" + os.path.join(self.e.out, "g", "v6", "vulnerability-db_v6.0.2_x.tar.zst"))
        self.assertTrue(os.path.isfile(lines[0][len("import:"):]))
        self.assertNotIn("online", r.stdout)
        self.no_public()

    def test_internal_mode_never_prints_online_when_the_mirror_is_unusable(self):
        self.e.stub("grype-db.sh")
        r = self.run_fn("grype_db_mode g; echo rc=$?")                              # 根目錄底下沒有 grype-db/
        self.assertEqual(r.stdout.split(), ["rc=1"], r.stdout + r.stderr)
        self.e.write_grype_db()
        r = self.run_fn("grype_db_mode g; echo rc=$?", STUB_CHECK="fail")           # --check 失敗
        self.assertEqual(r.stdout.split(), ["rc=1"], r.stdout + r.stderr)
        os.remove(os.path.join(self.e.root, "grype-db", "v6", "vulnerability-db_v6.0.2_x.tar.zst"))    # latest.json 指到的檔案不在
        r = self.run_fn("grype_db_mode g; echo rc=$?")
        self.assertEqual(r.stdout.split(), ["rc=1"], r.stdout + r.stderr)
        self.no_public()


class SubPaths(Base):
    """INTERNAL_MIRROR_PATH_<種類>：每種鏡像的子路徑可以改；必須是根目錄裡面的相對路徑。"""

    def test_override_reads_the_given_subpath_only_for_that_kind(self):
        self.e.stub("kernel-cve.sh")
        self.e.stub("euvd.sh")
        d = self.e.write_source("kernel-cve.default", hours_ago=2)           # 預設名稱的資料夾不存在；資料在別的（兩層）子路徑
        os.makedirs(os.path.join(self.e.root, "vendor"))
        os.rename(d, os.path.join(self.e.root, "vendor", "kcve2"))
        self.e.write_euvd()
        r = self.run_fn("mirror kernel-cve.sh kcve; echo rc=$?; mirror euvd.sh euvd; echo rc=$?", INTERNAL_MIRROR_PATH_KERNEL_CVE="vendor/kcve2/")
        self.assertEqual(r.stdout.count("rc=0"), 2, r.stdout + r.stderr)
        self.assertEqual(open(os.path.join(self.e.out, "kcve", "data.bin")).read(), "kernel-cve.default")
        self.no_public()

    def test_default_name_is_not_used_when_overridden(self):
        self.e.stub("kernel-cve.sh")
        self.e.write_source("kernel-cve")                                    # 預設位置有資料，但變數指到不存在的地方 → 失敗，不拿預設位置頂替
        r = self.run_fn("mirror kernel-cve.sh kcve; echo rc=$?", INTERNAL_MIRROR_PATH_KERNEL_CVE="elsewhere")
        self.assertIn("rc=1", r.stdout, r.stdout + r.stderr)
        self.no_public()

    def test_empty_value_means_default(self):
        self.e.stub("kernel-cve.sh")
        self.e.write_source("kernel-cve")
        r = self.run_fn("mirror kernel-cve.sh kcve; echo rc=$?", INTERNAL_MIRROR_PATH_KERNEL_CVE="")
        self.assertIn("rc=0", r.stdout, r.stdout + r.stderr)

    def test_bad_subpaths_are_usage_errors(self):
        self.e.stub("kernel-cve.sh")
        self.e.write_source("kernel-cve")
        for v in ("/abs/path", "../x", "a/../b", "a/..", "..", ".", "a/./b", "a b", "a\x01b", "a\nb", "a//b", "a?b", "a#b", "~/x", "a%2e%2eb"):
            with self.subTest(value=v):
                r = self.run_fn("mirror kernel-cve.sh kcve; echo rc=$?", INTERNAL_MIRROR_PATH_KERNEL_CVE=v)
                self.assertIn("rc=64", r.stdout, r.stdout + r.stderr)
                self.assertIn("INTERNAL_MIRROR_PATH_KERNEL_CVE", r.stderr)
                self.assertFalse(os.path.exists(os.path.join(self.e.out, "kcve")))
                self.no_public()

    def test_variable_names_use_upper_case_and_underscores(self):
        for kind in ("nvidia-bulletins", "osv-distro", "grype-db", "cisa-kev"):
            self.e.stub(kind + ".sh")
        self.e.write_source("nvidia-bulletins.x")
        os.rename(os.path.join(self.e.root, "nvidia-bulletins.x"), os.path.join(self.e.root, "nv"))
        r = self.run_fn("mirror nvidia-bulletins.sh nv; echo rc=$?", INTERNAL_MIRROR_PATH_NVIDIA_BULLETINS="nv")
        self.assertIn("rc=0", r.stdout, r.stdout + r.stderr)
        for kind in ("osv-distro", "grype-db", "cisa-kev"):                  # 變數名稱沒把 - 換成 _ 不會生效：用預設位置（不存在）→ 失敗
            r = self.run_fn("mirror %s.sh x; echo rc=$?" % kind, **{"INTERNAL_MIRROR_PATH_" + kind.upper(): "nope"})
            self.assertIn("rc=1", r.stdout)
        self.no_public()

    def test_symlink_escaping_the_root_is_a_usage_error(self):
        self.e.stub("kernel-cve.sh")
        outside = os.path.join(self.e.w, "outside")
        os.makedirs(outside)
        open(os.path.join(outside, "SOURCE"), "w").write("fetched_utc=%s\n" % S.utc(1))
        os.symlink(outside, os.path.join(self.e.root, "kernel-cve"))
        r = self.run_fn("mirror kernel-cve.sh kcve; echo rc=$?")
        self.assertIn("rc=64", r.stdout, r.stdout + r.stderr)
        self.assertIn("跳出", r.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.e.out, "kcve")))
        self.no_public()
        # 覆寫的子路徑指到根目錄之內的連結是可以的
        os.remove(os.path.join(self.e.root, "kernel-cve"))
        real = self.e.write_source("inside", hours_ago=1)
        os.symlink(real, os.path.join(self.e.root, "current"))
        r = self.run_fn("mirror kernel-cve.sh kcve; echo rc=$?", INTERNAL_MIRROR_PATH_KERNEL_CVE="current")
        self.assertIn("rc=0", r.stdout, r.stdout + r.stderr)


class KevSingleFile(Base):
    """cisa-kev 的子路徑指到單一 JSON 檔：沒有 SOURCE、沒有同步時間，只依 dateReleased（7 天 ATTENTION、14 天失敗）。"""
    PHRASE = "同步時間不明（單一檔案，只依 dateReleased）"

    def mirror(self, **extra):
        return self.run_fn("mirror cisa-kev.sh kev; echo rc=$?", stubs=False, INTERNAL_MIRROR_PATH_CISA_KEV="kevstore/kev.json", **extra)

    def put(self, **kw):
        return self.e.write_kev_file(os.path.join(self.e.root, "kevstore", "kev.json"), **kw)

    def test_ok_says_the_sync_time_is_unknown(self):
        rel = self.put(released_hours_ago=30)
        r = self.mirror()
        self.assertIn("rc=0", r.stdout, r.stdout + r.stderr)
        res = self.result("kev")
        self.assertTrue(res.startswith("OK source=internal kind=cisa-kev mode=file "), res)
        self.assertIn(self.PHRASE, res)
        self.assertIn("date_released=" + rel.replace(".000Z", "Z"), res)
        self.assertNotIn("fetched_utc", res)
        self.assertIn(self.PHRASE, open(os.path.join(self.e.out, "kev.manifest"), encoding="utf-8").read())
        self.assertTrue(os.path.isfile(os.path.join(self.e.out, "kev", "known_exploited_vulnerabilities.json")))
        self.assertFalse(os.path.exists(os.path.join(self.e.out, "kev", "SOURCE")))
        for text in (res, r.stdout):
            self.assertNotIn(self.e.root, text)
        self.no_public()

    def test_thresholds_7_days_attention_14_days_failure(self):
        self.put(released_hours_ago=24 * 6.5)
        self.assertTrue(self.result_of(self.mirror()).startswith("OK"))
        self.put(released_hours_ago=24 * 7.5)
        res = self.result_of(self.mirror())
        self.assertTrue(res.startswith("ATTENTION source=internal kind=cisa-kev mode=file"), res)
        self.assertIn(self.PHRASE, res)
        self.assertIn("::warning::", self.mirror().stdout)
        self.put(released_hours_ago=24 * 14.5)
        r = self.mirror()
        self.assertIn("rc=1", r.stdout, r.stdout + r.stderr)
        self.assertIn("內容太舊", r.stdout)
        self.assertFalse(os.path.exists(os.path.join(self.e.out, "kev.result")))
        self.assertFalse(os.path.exists(os.path.join(self.e.out, "kev")))
        self.no_public()

    def result_of(self, r):
        self.assertIn("rc=0", r.stdout, r.stdout + r.stderr)
        return self.result("kev")

    def test_thresholds_are_variables(self):
        self.put(released_hours_ago=24 * 3)
        self.assertTrue(self.result_of(self.mirror(INTERNAL_MIRROR_KEV_FILE_FRESH_DAYS="2")).startswith("ATTENTION"))
        r = self.mirror(CISA_KEV_MAX_RELEASE_AGE_DAYS="2")
        self.assertIn("rc=1", r.stdout, r.stdout + r.stderr)
        self.no_public()

    def test_mtime_is_never_used(self):
        # 檔案的 mtime 改成很新或很舊，結果都不能變（複製時 mtime 可能被改掉）
        import time
        p = os.path.join(self.e.root, "kevstore", "kev.json")
        for released, want in ((30, "OK"), (24 * 9, "ATTENTION")):
            self.put(released_hours_ago=released)
            outs = []
            for mtime in (time.time() + 86400 * 30, time.time() - 86400 * 400, time.time()):
                os.utime(p, (mtime, mtime))
                res = self.result_of(self.mirror())
                self.assertTrue(res.startswith(want), (released, mtime, res))
                outs.append(res.split(" age_hours=")[0])
            self.assertEqual(len(set(outs)), 1, outs)
        # 很舊的 dateReleased 配很新的 mtime：照樣失敗
        self.put(released_hours_ago=24 * 30)
        os.utime(p, None)
        self.assertIn("rc=1", self.mirror().stdout)
        self.no_public()

    def test_bad_files_fail(self):
        p = os.path.join(self.e.root, "kevstore", "kev.json")
        self.put(n=10)                                                      # 筆數少於下限
        self.assertIn("rc=1", self.mirror().stdout)
        self.put(released="not-a-date")                                    # dateReleased 讀不懂
        self.assertIn("rc=1", self.mirror().stdout)
        self.put(released="2999-01-01T00:00:00.000Z")                      # 在未來
        self.assertIn("rc=1", self.mirror().stdout)
        open(p, "w").write("not json")
        self.assertIn("rc=1", self.mirror().stdout)
        open(p, "w").write("[" * 200000)
        r = self.mirror()
        self.assertIn("rc=1", r.stdout)
        self.assertNotIn("Traceback", r.stdout + r.stderr)
        self.no_public()

    def test_file_pointing_outside_the_root_is_a_usage_error(self):
        outside = os.path.join(self.e.w, "outside.json")
        self.e.write_kev_file(outside)
        os.makedirs(os.path.join(self.e.root, "kevstore"))
        os.symlink(outside, os.path.join(self.e.root, "kevstore", "kev.json"))
        r = self.mirror()
        self.assertIn("rc=64", r.stdout, r.stdout + r.stderr)
        self.no_public()

    @staticmethod
    def naive_dates():
        """沒有時區的 dateReleased：去掉 Z 的時間（1 天前）、只有日期（今天）。都不能當成 UTC 算新。"""
        now = datetime.datetime.now(datetime.timezone.utc)
        return [(now - datetime.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S"), now.strftime("%Y-%m-%d")]

    def test_release_date_without_timezone_fails_single_file(self):
        for rel in self.naive_dates():
            with self.subTest(rel=rel):
                self.put(released=rel)
                r = self.mirror()
                self.assertIn("rc=1", r.stdout, r.stdout + r.stderr)
                self.assertIn("沒有時區", r.stdout)
                self.no_public()

    def test_release_date_without_timezone_fails_folder_mode(self):
        for rel in self.naive_dates():
            with self.subTest(rel=rel):
                self.e.write_real_kev(hours_ago=1, released=rel)
                r = self.run_fn("mirror cisa-kev.sh kev; echo rc=$?", stubs=False)
                self.assertIn("rc=1", r.stdout, r.stdout + r.stderr)
                self.assertIn("沒有時區", r.stdout)
                self.no_public()

    def test_release_date_in_the_future_fails_after_one_hour(self):
        """dateReleased 在未來：1 小時內容忍（時鐘誤差），超過就失敗（兩種模式都一樣）。"""
        self.put(released_hours_ago=-0.5)
        self.assertIn("rc=0", self.mirror().stdout)
        self.put(released_hours_ago=-3)
        r = self.mirror()
        self.assertIn("rc=1", r.stdout, r.stdout + r.stderr)
        self.e.write_real_kev(hours_ago=1, released_hours_ago=-3)
        r = self.run_fn("mirror cisa-kev.sh kev; echo rc=$?", stubs=False)
        self.assertIn("rc=1", r.stdout, r.stdout + r.stderr)
        self.assertIn("在未來", r.stdout)
        self.no_public()

    def test_only_cisa_kev_may_be_a_single_file(self):
        self.e.stub("kernel-cve.sh")
        open(os.path.join(self.e.root, "kernel-cve"), "w").write("{}")
        r = self.run_fn("mirror kernel-cve.sh kcve; echo rc=$?")
        self.assertIn("rc=1", r.stdout)
        self.no_public()

    def test_folder_mode_uses_fetched_utc_and_the_release_date_limit(self):
        # 資料夾（有 SOURCE）：同步時間走 36／72 小時；dateReleased 超過 14 天失敗（即使剛同步）
        self.e.write_real_kev(hours_ago=50)
        r = self.run_fn("mirror cisa-kev.sh kev; echo rc=$?", stubs=False)
        self.assertIn("rc=0", r.stdout, r.stdout + r.stderr)
        res = self.result("kev")
        self.assertTrue(res.startswith("ATTENTION source=internal kind=cisa-kev fetched_utc="), res)
        self.assertNotIn("同步時間不明", res)
        self.e.write_real_kev(hours_ago=1, released_hours_ago=24 * 15)
        r = self.run_fn("mirror cisa-kev.sh kev; echo rc=$?", stubs=False)
        self.assertIn("rc=1", r.stdout, r.stdout + r.stderr)
        self.assertIn("內容太舊", r.stdout)
        self.no_public()


class CisaKevScript(Base):
    """tools/mirror/cisa-kev.sh 本身（下載模式用真的 curl 讀 file://，不連網）。"""

    def kev_file(self, n=1200, **doc):
        p = os.path.join(self.e.w, "kev.json")
        self.rel, raw = self.e.kev_doc(n)
        d = json.loads(raw)
        d.update(doc)
        with open(p, "w") as f:
            json.dump(d, f)
        return p

    def sh(self, *args, **env):
        e = {k: v for k, v in os.environ.items() if k != "CISA_KEV_URL"}
        e.update(env)
        return subprocess.run(["bash", KEV_SH, *args], capture_output=True, text=True, env=e, timeout=120)

    def download(self, **env):
        dest = os.path.join(self.e.w, "m")
        return dest, self.sh(dest, dest + ".manifest", **env)

    def test_download_writes_source_and_manifest(self):
        url = "file://" + self.kev_file()
        dest, r = self.download(CISA_KEV_URL=url)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(r.stdout.splitlines()[-1].startswith("OK mirror="))
        src = dict(l.split("=", 1) for l in open(os.path.join(dest, "SOURCE")).read().splitlines())
        self.assertEqual(src["entries"], "1200")
        self.assertEqual(src["date_released"], self.rel)
        self.assertEqual(len(src["sha256"]), 64)
        self.assertRegex(src["fetched_utc"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertIn("known_exploited_vulnerabilities.json", open(dest + ".manifest").read())
        r = self.sh("--check", dest)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(r.stdout.startswith("OK fetched_utc="))

    def test_download_refuses_bad_url_and_existing_dest(self):
        for u in ("http://example.invalid/x", "ftp://example.invalid/x", "/etc/passwd"):
            dest, r = self.download(CISA_KEV_URL=u)
            self.assertEqual(r.returncode, 3, u)
        dest, r = self.download(CISA_KEV_URL="file://" + self.kev_file())
        self.assertEqual(r.returncode, 0)
        r = self.sh(dest, dest + ".manifest", CISA_KEV_URL="file://" + self.kev_file())
        self.assertEqual(r.returncode, 3)

    def test_download_rejects_unusable_files(self):
        bad = os.path.join(self.e.w, "bad.json")
        open(bad, "w").write("not json")
        dest, r = self.download(CISA_KEV_URL="file://" + bad)
        self.assertNotEqual(r.returncode, 0)
        small = "file://" + self.kev_file(n=10)
        dest2 = os.path.join(self.e.w, "m2")
        r = self.sh(dest2, dest2 + ".manifest", CISA_KEV_URL=small)
        self.assertEqual(r.returncode, 1)
        self.assertIn("< 1000", r.stdout)
        dest3 = os.path.join(self.e.w, "m3")
        r = self.sh(dest3, dest3 + ".manifest", CISA_KEV_URL=small, CISA_KEV_MIN_ENTRIES="5")       # 門檻可調
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def mirror_dir(self, hours_ago=1.0, **kw):
        d, _ = self.e.write_real_kev(hours_ago=hours_ago, **kw)
        return d

    def test_check_failures(self):
        d = self.mirror_dir()
        p = os.path.join(d, "known_exploited_vulnerabilities.json")
        good = open(p, "rb").read()
        src_good = open(os.path.join(d, "SOURCE")).read()
        # 內容被改（sha256）
        open(p, "wb").write(good + b" ")
        r = self.sh("--check", d)
        self.assertEqual(r.returncode, 1)
        self.assertIn("sha256", r.stdout)
        open(p, "wb").write(good)
        # 筆數少於下限
        r = self.sh("--check", d, CISA_KEV_MIN_ENTRIES="5000")
        self.assertEqual(r.returncode, 1)
        self.assertIn("5000", r.stdout)
        # SOURCE 的 entries 對不上
        open(os.path.join(d, "SOURCE"), "w").write(src_good.replace("entries=1200", "entries=1199"))
        self.assertIn("entries", self.sh("--check", d).stdout)
        open(os.path.join(d, "SOURCE"), "w").write(src_good)
        # 檔案太大
        r = self.sh("--check", d, CISA_KEV_MAX_BYTES="100")
        self.assertEqual(r.returncode, 1)
        # 缺 SOURCE
        os.rename(os.path.join(d, "SOURCE"), os.path.join(d, "SOURCE.x"))
        self.assertEqual(self.sh("--check", d).returncode, 1)
        os.rename(os.path.join(d, "SOURCE.x"), os.path.join(d, "SOURCE"))
        self.assertEqual(self.sh("--check", d).returncode, 0)

    def test_check_age_limit_is_three_days(self):
        d = self.mirror_dir(hours_ago=24 * 2.5)
        self.assertEqual(self.sh("--check", d).returncode, 0)
        d = self.mirror_dir(hours_ago=24 * 3.5)
        r = self.sh("--check", d)
        self.assertEqual(r.returncode, 1)
        self.assertIn("過期", r.stdout)
        self.assertEqual(self.sh("--check", d, CISA_KEV_MAX_AGE_DAYS="5").returncode, 0)

    def test_check_rejects_symlink_and_fifo_before_opening(self):
        d = self.mirror_dir()
        os.symlink("/etc/passwd", os.path.join(d, "evil"))
        r = self.sh("--check", d)
        self.assertEqual(r.returncode, 1)
        self.assertIn("evil", r.stdout)
        os.remove(os.path.join(d, "evil"))
        os.mkfifo(os.path.join(d, "pipe"))
        r = self.sh("--check", d)
        self.assertEqual(r.returncode, 1)
        self.assertIn("pipe", r.stdout)

    def test_check_treats_the_json_as_untrusted(self):
        d = self.mirror_dir()
        p = os.path.join(d, "known_exploited_vulnerabilities.json")
        import hashlib
        for body in (b"[" * 200000, b'{"vulnerabilities": "x"}', b"\xff\xfe"):
            open(p, "wb").write(body)
            src = open(os.path.join(d, "SOURCE")).read().splitlines()
            src = [l for l in src if not l.startswith(("sha256=", "entries="))] + ["sha256=" + hashlib.sha256(body).hexdigest(), "entries=0"]
            open(os.path.join(d, "SOURCE"), "w").write("\n".join(src) + "\n")
            r = self.sh("--check", d)
            self.assertEqual(r.returncode, 1, body[:20])
            self.assertNotIn("Traceback", r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
