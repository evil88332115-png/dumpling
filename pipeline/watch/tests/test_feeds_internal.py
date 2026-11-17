"""feeds.sh 的內部鏡像模式（T-06）：端到端記 OK、ATTENTION、GAP；任何情況都沒有公開下載（假的 curl／git／grype db update 都沒被呼叫）；
Grype 只 import、不 update，而且每次呼叫都帶 GRYPE_DB_AUTO_UPDATE=false。另外鎖住 match.py 比對階段不會觸發 grype 更新。不連網。"""
import os
import shutil
import subprocess
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
import internal_mirror_support as S  # noqa: E402
from .test_match import Base as _MatchBase  # noqa: E402

FEEDS = os.path.join(S.ROOT, "pipeline", "watch", "feeds.sh")
MATCH_PY = os.path.join(S.ROOT, "pipeline", "watch", "match.py")
PHRASE = "同步時間不明（單一檔案，只依 dateReleased）"


class FeedsInternal(unittest.TestCase):
    def setUp(self):
        self.e = S.Env()
        for n in ("euvd.sh", "kernel-cve.sh", "grype-db.sh"):
            self.e.stub(n)
        shutil.copy(os.path.join(S.REAL_SCRIPTS, "cisa-kev.sh"), os.path.join(self.e.stubs, "cisa-kev.sh"))
        self.out = os.path.join(self.e.w, "feeds-out")

    def tearDown(self):
        self.e.cleanup()

    def full_root(self, **hours):
        self.e.write_real_kev(hours_ago=hours.get("kev", 2))
        self.e.write_euvd(hours.get("euvd", 2))
        self.e.write_source("kernel-cve", hours.get("kcve", 2))
        self.e.write_grype_db(hours.get("grype", 2))

    def run_feeds(self, args=(), want_rc=0, **extra):
        kw = dict(INTERNAL_MIRROR_URL=self.e.url(), MIRRORS_SCRIPT_DIR=self.e.stubs, MIRRORS_TRIES="1", STUB_LOG=os.path.join(self.e.w, "stub.log"))
        kw.update(extra)
        env = self.e.env(**kw)
        for k in [k for k, v in env.items() if v is None]:
            del env[k]
        r = subprocess.run(["bash", FEEDS, self.out, *args], env=env, capture_output=True, text=True, timeout=300)
        self.assertEqual(r.returncode, want_rc, r.stdout + r.stderr)
        rows = {}
        with open(os.path.join(self.out, "feeds.tsv"), encoding="utf-8") as f:
            for line in f:
                n, st, msg = line.rstrip("\n").split("\t")
                rows[n] = (st, msg)
        return rows, r

    def no_public(self):
        self.assertEqual(self.e.marked(), [], "有公開下載或 grype db update 的標記")

    def test_all_ok_and_every_row_says_internal(self):
        self.full_root()
        rows, r = self.run_feeds()
        for n in ("cisa-kev", "euvd", "kernel-cve", "grype-db"):
            self.assertEqual(rows[n][0], "OK", rows)
            self.assertIn("source=internal", rows[n][1])
        self.no_public()
        with open(os.path.join(self.out, "cisa-kev.json"), "rb") as a, \
                open(os.path.join(self.e.root, "cisa-kev", "known_exploited_vulnerabilities.json"), "rb") as b:
            self.assertEqual(a.read(), b.read())
        self.assertTrue(os.path.isfile(os.path.join(self.out, "euvd", "index.tsv")))
        self.assertTrue(os.path.isfile(os.path.join(self.out, "kernel-cve", "SOURCE")))
        self.assertTrue(open(os.path.join(self.out, "kernel-cve.result")).read().startswith("OK source=internal"))
        self.assertNotIn(self.e.root, open(os.path.join(self.out, "feeds.tsv")).read())

    def test_grype_imports_and_never_updates(self):
        self.full_root()
        rows, _ = self.run_feeds(GRYPE_DB_AUTO_UPDATE="true")                 # 外面的環境說 true 也一樣
        calls = self.e.grype_calls()
        imports = [c for c in calls if c.startswith("args=db import ")]
        self.assertEqual(len(imports), 1, calls)
        self.assertIn(os.path.join(self.out, "grype-db", "v6", "vulnerability-db_v6.0.2_x.tar.zst"), imports[0])
        self.assertFalse([c for c in calls if "db update" in c], calls)
        self.assertTrue(calls and all("AUTO_UPDATE=false APP_UPDATE=false" in c for c in calls), calls)
        self.assertEqual(rows["grype-db"][0], "OK")
        self.assertIn("Built:", rows["grype-db"][1])
        self.assertFalse(os.path.exists(os.path.join(self.out, "grype-db")))     # 匯入完不留大檔
        self.no_public()

    def test_grype_import_failure_is_a_gap_not_an_update(self):
        self.full_root()
        rows, _ = self.run_feeds(FAKE_GRYPE_IMPORT="fail")
        self.assertEqual(rows["grype-db"][0], "GAP")
        self.assertIn("沒有改走公開網址", rows["grype-db"][1])
        self.assertFalse([c for c in self.e.grype_calls() if "db update" in c])
        self.no_public()

    def test_attention_when_older_than_36_hours(self):
        self.full_root(kcve=40)
        rows, r = self.run_feeds()
        self.assertEqual(rows["kernel-cve"][0], "ATTENTION")
        self.assertIn("source=internal", rows["kernel-cve"][1])
        self.assertIn("36 小時", rows["kernel-cve"][1])
        self.assertEqual(rows["euvd"][0], "OK")
        self.assertIn("::warning::鏡像 kernel-cve", r.stdout)
        self.assertTrue(open(os.path.join(self.out, "kernel-cve.result")).read().startswith("ATTENTION"))
        self.no_public()

    def test_gap_when_the_mirror_is_not_synced_yet(self):
        # 只有核心 CVE 同步到根目錄；euvd、grype-db、cisa-kev 還沒有 → 這三個記 GAP，沒有半份資料夾，沒有公開下載
        self.e.write_source("kernel-cve")
        rows, _ = self.run_feeds()
        self.assertEqual(rows["kernel-cve"][0], "OK")
        for n in ("cisa-kev", "euvd", "grype-db"):
            self.assertEqual(rows[n][0], "GAP", rows)
            self.assertIn("內部鏡像", rows[n][1])
            self.assertIn("沒有改走公開網址", rows[n][1])
        self.assertFalse(os.path.exists(os.path.join(self.out, "cisa-kev.json")))
        self.assertFalse(os.path.exists(os.path.join(self.out, "euvd")))
        self.assertFalse(os.path.exists(os.path.join(self.out, "grype-db")))
        self.assertEqual([c for c in self.e.grype_calls() if "import" in c or "update" in c], [])
        self.no_public()

    def test_gap_beyond_the_failure_limit_or_failed_check(self):
        self.full_root(euvd=80)                                              # 超過 72 小時
        rows, _ = self.run_feeds()
        self.assertEqual(rows["euvd"][0], "GAP")
        self.assertFalse(os.path.exists(os.path.join(self.out, "euvd")))
        shutil.rmtree(self.out)
        rows, _ = self.run_feeds(STUB_CHECK="fail")                          # 替身 --check 都失敗（cisa-kev 是真的腳本，仍然通過）
        self.assertEqual({rows[n][0] for n in ("euvd", "kernel-cve", "grype-db")}, {"GAP"})
        self.assertEqual(rows["cisa-kev"][0], "OK")
        self.no_public()

    def test_symlink_in_a_source_is_a_gap(self):
        self.full_root()
        os.symlink("/etc/passwd", os.path.join(self.e.root, "cisa-kev", "evil"))
        rows, _ = self.run_feeds()
        self.assertEqual(rows["cisa-kev"][0], "GAP")
        self.assertFalse(os.path.exists(os.path.join(self.out, "cisa-kev.json")))
        self.no_public()

    def test_kev_single_file(self):
        self.full_root()
        shutil.rmtree(os.path.join(self.e.root, "cisa-kev"))
        path = os.path.join(self.e.root, "other", "kev.json")
        rel = self.e.write_kev_file(path, released_hours_ago=30)
        rows, _ = self.run_feeds(INTERNAL_MIRROR_PATH_CISA_KEV="other/kev.json")
        self.assertEqual(rows["cisa-kev"][0], "OK")
        self.assertIn(PHRASE, rows["cisa-kev"][1])
        self.assertTrue(os.path.isfile(os.path.join(self.out, "cisa-kev.json")))
        shutil.rmtree(self.out)
        self.e.write_kev_file(path, released_hours_ago=24 * 8)
        rows, _ = self.run_feeds(INTERNAL_MIRROR_PATH_CISA_KEV="other/kev.json")
        self.assertEqual(rows["cisa-kev"][0], "ATTENTION")
        self.assertIn(PHRASE, rows["cisa-kev"][1])
        shutil.rmtree(self.out)
        self.e.write_kev_file(path, released_hours_ago=24 * 15)
        rows, _ = self.run_feeds(INTERNAL_MIRROR_PATH_CISA_KEV="other/kev.json")
        self.assertEqual(rows["cisa-kev"][0], "GAP")
        self.assertFalse(os.path.exists(os.path.join(self.out, "cisa-kev.json")))
        self.no_public()
        self.assertTrue(rel)

    def test_drill_flags_still_say_internal(self):
        self.full_root()
        rows, _ = self.run_feeds(args=("--no-euvd", "--no-kernel-cve"))
        self.assertEqual(rows["euvd"][0], "NOT_RUN")
        self.assertIn("內部鏡像", rows["euvd"][1])
        self.assertIn("內部鏡像", rows["kernel-cve"][1])
        self.no_public()

    def test_usage_errors_fail_with_64_and_never_go_public(self):
        self.full_root()
        cases = (dict(INTERNAL_MIRROR_URL="https://mirror.example/x"), dict(INTERNAL_MIRROR_URL="file://relative"),
                 dict(INTERNAL_MIRROR_URL="file:///a/../b"), dict(INTERNAL_MIRROR_URL=None, DUMPLING_REQUIRE_INTERNAL_MIRROR="1"),
                 dict(INTERNAL_MIRROR_URL="", DUMPLING_REQUIRE_INTERNAL_MIRROR="1"), dict(INTERNAL_MIRROR_PATH_EUVD="../x"),
                 dict(INTERNAL_MIRROR_PATH_EUVD="/etc"), dict(INTERNAL_MIRROR_MAX_HOURS="abc"))
        for extra in cases:
            with self.subTest(extra=extra):
                if os.path.exists(self.out):
                    shutil.rmtree(self.out)
                rows, r = self.run_feeds(want_rc=64, **extra)
                self.assertEqual({v[0] for v in rows.values()}, {"GAP"}, rows)
                self.assertIn("用法錯誤", r.stderr)
                self.assertFalse(os.path.exists(os.path.join(self.out, "cisa-kev.json")))
                self.assertEqual(self.e.grype_calls(), [])
                self.no_public()

    def test_subpath_escaping_the_root_is_gap_and_exit_64(self):
        self.full_root()
        outside = os.path.join(self.e.w, "outside")
        os.makedirs(outside)
        shutil.copytree(os.path.join(self.e.root, "euvd"), os.path.join(outside, "euvd"))
        shutil.rmtree(os.path.join(self.e.root, "euvd"))
        os.symlink(os.path.join(outside, "euvd"), os.path.join(self.e.root, "euvd"))
        rows, _ = self.run_feeds(want_rc=64)
        self.assertEqual(rows["euvd"][0], "GAP")
        self.assertEqual(rows["kernel-cve"][0], "OK")
        self.assertFalse(os.path.exists(os.path.join(self.out, "euvd")))
        self.no_public()

    def test_public_mode_is_unchanged(self):
        # 沒設變數：還是 curl 下載 KEV、grype db update（假的，會留標記）；不碰內部鏡像
        rows, r = self.run_feeds(INTERNAL_MIRROR_URL=None, CISA_KEV_URL="https://127.0.0.1:9/kev.json")
        self.assertEqual(rows["cisa-kev"][0], "GAP")
        self.assertIn("下載失敗", rows["cisa-kev"][1])
        self.assertIn("curl", self.e.marked())
        self.assertIn("grype-db-update", self.e.marked())
        self.assertEqual(rows["grype-db"][0], "GAP")
        self.assertIn("grype db update 失敗", rows["grype-db"][1])
        self.assertEqual(rows["euvd"][0], "OK")
        self.assertIn("download-ran", self.e.marked())            # 公開模式：下載腳本（替身）有被執行
        self.assertNotIn("source=internal", open(os.path.join(self.out, "feeds.tsv")).read())


class MatchDoesNotUpdateGrype(_MatchBase):
    """match.py 比對階段不會觸發 Grype 更新：db status 與比對都帶 GRYPE_DB_AUTO_UPDATE=false，沒有任何 db update。"""

    def setUp(self):
        super().setUp()
        self.fe = S.Env()
        self.addCleanup(self.fe.cleanup)
        self.eg = match_eg()
        gp = os.path.join(self.fe.bin, "grype")
        self.eg.find_grype = lambda x=None: (gp, "fake")
        self.eg.db_status = self.saved["db_status"]               # 這一組用真的 db_status（讀 grype db status），其餘照 test_match 的假替身
        patcher = mock.patch.dict(os.environ, {"MARK_DIR": self.fe.marks, "FAKE_GRYPE_LOG": self.fe.glog, "GRYPE_DB_AUTO_UPDATE": "true",
                                               "GRYPE_CHECK_FOR_APP_UPDATE": "true", "INTERNAL_MIRROR_URL": "file:///srv/mirror"})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_db_status_call_has_auto_update_off_even_if_the_environment_says_on(self):
        st, detail, plan = self.run_once("2026-11-10T01:00:00Z")
        calls = self.fe.grype_calls()
        self.assertTrue([c for c in calls if c.startswith("args=db status")], calls)
        self.assertTrue(all("AUTO_UPDATE=false APP_UPDATE=false" in c for c in calls), calls)
        self.assertFalse([c for c in calls if "update" in c.split("AUTO_UPDATE")[0]], calls)
        self.assertEqual(self.fe.marked(), [])

    def test_grype_env_forces_the_two_switches(self):
        env = self.eg.grype_env()
        self.assertEqual((env["GRYPE_DB_AUTO_UPDATE"], env["GRYPE_CHECK_FOR_APP_UPDATE"]), ("false", "false"))

    def test_run_grype_command_line_turns_auto_update_off_and_has_no_update(self):
        seen = {}

        def popen(cmd, **kw):
            seen["cmd"] = cmd
            raise OSError("stop")
        with mock.patch.object(self.eg.subprocess, "Popen", popen):
            self.eg.run_grype("/x/grype", self.eg.grype_env(), "/w/s.json", self.w, 5)
        cmd = seen["cmd"]
        self.assertIn("GRYPE_DB_AUTO_UPDATE=false", cmd)
        self.assertIn("GRYPE_CHECK_FOR_APP_UPDATE=false", cmd)
        after = cmd[cmd.index("/x/grype") + 1:]
        self.assertEqual(after[0], "sbom:/w/s.json")
        self.assertNotIn("update", after)
        self.assertNotIn("import", after)

    def test_match_source_never_runs_grype_db_update(self):
        import ast
        with open(MATCH_PY, encoding="utf-8") as f:
            tree = ast.parse(f.read())
        strs = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
        self.assertFalse([s for s in strs if "db update" in s or s in ("update", "import")], "match.py 不該有 grype db update／import")
        self.assertFalse([s for s in strs if "GRYPE_DB_AUTO_UPDATE=true" in s])


def match_eg():
    from . import test_match
    return test_match.match.mods()["eg"]


if __name__ == "__main__":
    unittest.main()
