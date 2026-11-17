"""T-06 PR-2：release scan 的 Grype DB 改用 grype_db_mode，以及弱點資料的來源與快照時間（pipeline/lib/data_sources.py →
scan.json、notes.md、release-meta.json 的 data_sources）。不連網：假的 curl／git／grype 放在 PATH 最前面，被呼叫就留標記
（pipeline/watch/tests/internal_mirror_support.py，和 PR-1 的測試同一套）。

scan.sh 的 Grype DB 那一段是從 jetson/scan.sh 與 _shared/scan-disk.sh 原樣取出來執行的（不是另寫一份），所以改了腳本、測試就跟著測到。"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(ROOT, "pipeline", "lib"))
sys.path.insert(0, os.path.join(ROOT, "pipeline", "watch", "tests"))
import data_sources as ds  # noqa: E402
import internal_mirror_support as S  # noqa: E402
import platform_scan as ps  # noqa: E402

JETSON = os.path.join(ROOT, "pipeline", "platforms", "jetson", "scan.sh")
SCAN_DISK = os.path.join(ROOT, "pipeline", "platforms", "_shared", "scan-disk.sh")
PIPELINE_YML = os.path.join(ROOT, ".github", "workflows", "pipeline.yml")
RELEASE_META = os.path.join(ROOT, "pipeline", "release-meta.py")
LOCAL_PATH = re.compile(r"(?:/home/|/tmp/|/mnt/|/var/|/opt/|/srv/|/builds/|file:)")


def read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


def w(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def grype_block(path):
    """scan 腳本裡 Grype DB 那一段（從註解「# Grype DB（T-06 PR-2」到 export DUMPLING_DATA_SOURCES 那一行）。"""
    m = re.search(r"^# Grype DB（T-06 PR-2.*?^export DUMPLING_DATA_SOURCES=\$dsrc\n", read(path), re.M | re.S)
    assert m, path
    return m.group(0)


class ScanScripts(unittest.TestCase):
    def test_both_scans_take_grype_mode_from_grype_db_mode(self):
        for p in (JETSON, SCAN_DISK):
            src = read(p)
            with self.subTest(p=os.path.basename(p)):
                self.assertNotIn("GRYPE_DB_UPDATE=online", src)              # 不再寫死 online
                self.assertEqual(src.count('export GRYPE_DB_UPDATE="$gm"'), 1)
                self.assertLess(src.index("gm=$(grype_db_mode gdb)"), src.index('export GRYPE_DB_UPDATE="$gm"'))
                self.assertLess(src.index('export GRYPE_DB_UPDATE="$gm"'), src.index('tools/wizard/cra-scan.py" --site-config'))   # 精靈之前就決定好

    def test_blocks_are_the_same_except_the_list(self):
        strip = lambda t: re.sub(r'^dsrc="[^"]*"', 'dsrc=""', t, flags=re.M)  # noqa: E731
        self.assertEqual(strip(grype_block(JETSON)), strip(grype_block(SCAN_DISK)))


class GrypeBlock(unittest.TestCase):
    """取出的那一段實際用 bash 跑：真的 mirrors.sh、替身 grype-db.sh（MIRRORS_SCRIPT_DIR）、假的 curl／git／grype。"""

    def setUp(self):
        self.e = S.Env()
        self.addCleanup(self.e.cleanup)
        self.e.stub("grype-db.sh")

    def run_block(self, path=JETSON, **extra):
        kw = dict(INTERNAL_MIRROR_URL=self.e.url(), MIRRORS_SCRIPT_DIR=self.e.stubs, STUB_LOG=os.path.join(self.e.w, "stub.log"))
        kw.update(extra)
        env = self.e.env(**kw)
        for k in [k for k, v in env.items() if v is None]:
            del env[k]
        env.pop("DUMPLING_DATA_SOURCES", None)
        sh = ('set -uo pipefail\nfail() { echo "scan: FAIL（$*）"; exit 1; }\nmkdir -p "$MIRRORS_DIR"\n. "%s"\n%s'
              'echo "GM=$gm"; echo "DS=$DUMPLING_DATA_SOURCES"\n') % (S.MIRROR_SH, grype_block(path))
        return subprocess.run(["bash", "-c", sh], capture_output=True, text=True, env=env, timeout=120)

    def test_internal_ok_imports_from_the_copy(self):
        self.e.write_grype_db(hours_ago=2)
        for path in (JETSON, SCAN_DISK):
            with self.subTest(p=os.path.basename(path)):
                r = self.run_block(path)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                gm = re.search(r"^GM=(.*)$", r.stdout, re.M).group(1)
                self.assertEqual(gm, "import:" + os.path.join(self.e.out, "gdb", "v6", "vulnerability-db_v6.0.2_x.tar.zst"))
                self.assertNotIn("online", r.stdout)
                self.assertIn("gdb=grype-db", re.search(r"^DS=(.*)$", r.stdout, re.M).group(1))
                self.assertTrue(read(os.path.join(self.e.out, "gdb.result")).startswith("OK source=internal kind=grype-db built_utc="))
                self.assertEqual(self.e.marked(), [], "有公開下載或 grype db update 的標記")
                self.assertEqual(self.e.grype_calls(), [])                   # 這一段不呼叫 grype；import 在 sca-scan 裡

    def test_internal_missing_grype_db_fails_without_public_fallback(self):
        for path in (JETSON, SCAN_DISK):
            with self.subTest(p=os.path.basename(path)):
                r = self.run_block(path)                                     # 根目錄底下沒有 grype-db/
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertEqual(r.stdout.strip().splitlines()[-1],
                                 "scan: FAIL（鏡像 grype-db.sh 失敗（內部鏡像不可用，不退回公開下載；弱點資料不完整，不當作沒有漏洞））")
                self.assertNotIn("GM=", r.stdout)
                self.assertEqual(self.e.marked(), [])
                self.assertEqual(self.e.grype_calls(), [])

    def test_internal_check_failure_fails(self):
        self.e.write_grype_db(hours_ago=2)
        for path in (JETSON, SCAN_DISK):
            with self.subTest(p=os.path.basename(path)):
                r = self.run_block(path, STUB_CHECK="fail")
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn("內部鏡像不可用，不退回公開下載", r.stdout)
                self.assertEqual(self.e.marked(), [])

    def test_internal_too_old_fails(self):
        self.e.write_grype_db(hours_ago=80)                                 # 超過失敗門檻 72 小時
        r = self.run_block()
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertEqual(self.e.marked(), [])

    def test_usage_errors_fail_64(self):
        self.e.write_grype_db(hours_ago=2)
        for kw in (dict(INTERNAL_MIRROR_URL="https://mirror.example.invalid/m"), dict(INTERNAL_MIRROR_URL="file://relative/x"),
                   dict(INTERNAL_MIRROR_URL=None, DUMPLING_REQUIRE_INTERNAL_MIRROR="1")):
            for path in (JETSON, SCAN_DISK):
                with self.subTest(p=os.path.basename(path), **{k: str(v) for k, v in kw.items()}):
                    r = self.run_block(path, **kw)
                    self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                    self.assertEqual(r.stdout.strip().splitlines()[-1],
                                     "scan: FAIL（Grype DB 的內部鏡像設定不合法（INTERNAL_MIRROR_URL 等，見上面的訊息；不退回公開下載））")
                    self.assertEqual(self.e.marked(), [])

    def test_unset_is_online_and_silent(self):
        self.e.write_grype_db(hours_ago=2)                                   # 有內部鏡像也不讀：沒設變數就是公開模式
        for path, spec in ((JETSON, "nvbul=nvidia-bulletins kcve=kernel-cve euvd=euvd osv=osv-distro"),
                           (SCAN_DISK, "kcve=kernel-cve euvd=euvd osv=osv-distro")):
            with self.subTest(p=os.path.basename(path)):
                r = self.run_block(path, INTERNAL_MIRROR_URL=None)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertEqual(r.stdout, "GM=online\nDS=%s\n" % spec)     # 和以前一樣只是 online，沒有多印東西
                self.assertEqual(r.stderr, "")
                self.assertFalse(os.path.exists(os.path.join(self.e.out, "gdb")))
                self.assertFalse(os.path.exists(os.path.join(self.e.out, "gdb.result")))


class KcveCacheStep(unittest.TestCase):
    """pipeline.yml 的「核心 CVE 鏡像是不是這次新抓的」那一步：內部複本（.result 有 source=internal）不存回 cache。
    那一步的 shell 沒有 INTERNAL_MIRROR_URL（scan 步驟的 env 不會帶過去），所以靠 .result 判斷。"""

    def step_script(self):
        src = read(PIPELINE_YML)
        m = re.search(r"id: kcve-fresh\n(?:.*\n)*?        run: \|\n((?:          .*\n|\n)+)", src)
        self.assertIsNotNone(m)
        return "\n".join(l[10:] for l in m.group(1).splitlines())

    def run_step(self, result_line, fallback=False):
        tmp = tempfile.mkdtemp(prefix="t06-kcve-")
        self.addCleanup(shutil.rmtree, tmp, True)
        mirrors = os.path.join(tmp, "out", "p", "v", "mirrors")
        w(os.path.join(mirrors, "kcve", "SOURCE"), "fetched_utc=2026-11-17T00:00:00Z\n" + ("fallback=yes\n" if fallback else ""))
        w(os.path.join(mirrors, "kcve.result"), result_line + "\n")
        gh_out = os.path.join(tmp, "gh-output")
        env = {k: v for k, v in os.environ.items() if not k.startswith(("INTERNAL_MIRROR_", "DUMPLING_REQUIRE_INTERNAL"))}
        env.update(DUMPLING_OUT_BASE=os.path.join(tmp, "out"), DUMPLING_IN_PROJECT="p", DUMPLING_IN_VERSION="v",
                   KCVE_CACHE_DIR=os.path.join(tmp, "cache", "kcve"), GITHUB_OUTPUT=gh_out)
        r = subprocess.run(["bash", "-c", self.step_script()], capture_output=True, text=True, env=env, cwd=ROOT, timeout=60)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return read(gh_out).strip(), os.path.exists(os.path.join(tmp, "cache", "kcve"))

    def test_internal_copy_is_not_saved(self):
        self.assertEqual(self.run_step("OK source=internal kind=kernel-cve fetched_utc=2026-11-17T00:00:00Z age_hours=1.0"), ("fresh=false", False))

    def test_public_fresh_copy_is_saved(self):                               # 對照：公開模式新抓的照舊存
        self.assertEqual(self.run_step("OK records=1"), ("fresh=true", True))


class Items(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="t06-ds-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def p(self, *a):
        return os.path.join(self.tmp, *a)

    def test_parse_spec_whitelist(self):
        self.assertEqual(ds.parse_spec("kcve=kernel-cve euvd=euvd bad=nope ../x=euvd kcve=euvd Gdb=grype-db osv=osv-distro"),
                         [("kcve", "kernel-cve"), ("euvd", "euvd"), ("osv", "osv-distro")])
        self.assertEqual(ds.parse_spec(None), [])

    def test_internal_result_is_parsed_without_copying_text(self):
        w(self.p("kcve.result"), "OK source=internal kind=kernel-cve fetched_utc=2026-11-17T01:02:03Z age_hours=2.0\n")
        w(self.p("gdb.result"), "ATTENTION source=internal kind=grype-db built_utc=2026-11-15T00:00:00Z age_hours=40.0 內部鏡像的資料已 40 小時\n")
        w(self.p("kev.result"), "OK source=internal kind=cisa-kev mode=file 同步時間不明（單一檔案，只依 dateReleased） date_released=2026-11-16T00:00:00.000Z age_hours=30\n")
        self.assertEqual(ds.mirror_item(self.tmp, "kcve", "kernel-cve"),
                         {"kind": "kernel-cve", "source": "internal", "status": "OK", "snapshot_field": "fetched_utc", "snapshot_utc": "2026-11-17T01:02:03Z"})
        self.assertEqual(ds.mirror_item(self.tmp, "gdb", "grype-db")["status"], "ATTENTION")
        self.assertEqual(ds.mirror_item(self.tmp, "gdb", "grype-db")["snapshot_field"], "built_utc")
        self.assertEqual(ds.mirror_item(self.tmp, "kev", "cisa-kev")["snapshot_utc"], "2026-11-16T00:00:00Z")

    def test_internal_kind_mismatch_is_unknown(self):
        w(self.p("kcve.result"), "OK source=internal kind=euvd fetched_utc=2026-11-17T01:02:03Z age_hours=2.0\n")
        it = ds.mirror_item(self.tmp, "kcve", "kernel-cve")
        self.assertEqual((it["status"], it["snapshot_utc"]), ("UNKNOWN", None))

    def test_public_reads_source_not_the_result_text(self):
        # 公開模式的 .result 有本機路徑（mirror=…）：不抄，時間讀 SOURCE／index.tsv
        w(self.p("nvbul.result"), "OK mirror=/home/runner/work/_temp/x/nvbul manifest=/home/runner/work/_temp/x/nvbul.manifest commit=abc\n")
        w(self.p("nvbul", "SOURCE"), "source=https://github.com/x/y\nfetched_utc=2026-11-17T03:00:00Z\n")
        w(self.p("euvd.result"), "OK mirror=/tmp/euvd\n")
        w(self.p("euvd", "index.tsv"), "# euvd-index 1\tfetched_utc=2026-11-17T04:00:00+00:00\tcves=1\n")
        w(self.p("kcve.result"), "ATTENTION 沿用上一份\n")
        w(self.p("kcve", "SOURCE"), "fetched_utc=2026-11-16T05:00:00Z\nfallback=yes\n")
        items = ds.collect(self.tmp, "nvbul=nvidia-bulletins euvd=euvd kcve=kernel-cve osv=osv-distro", None)
        self.assertEqual([(i["kind"], i["source"], i["status"], i["snapshot_utc"]) for i in items], [
            ("nvidia-bulletins", "public", "OK", "2026-11-17T03:00:00Z"), ("euvd", "public", "OK", "2026-11-17T04:00:00Z"),
            ("kernel-cve", "public", "ATTENTION", "2026-11-16T05:00:00Z"),
            ("osv-distro", None, "UNKNOWN", None),                          # 沒有 .result：不猜
            ("grype-db", None, "UNKNOWN", None)])                           # 沒有 meta.json
        self.assertNotIn("/home/", json.dumps(items))

    def test_naive_or_bad_times_are_dropped(self):
        w(self.p("kcve.result"), "OK x\n")
        for val in ("2026-11-17T01:00:00", "2026-11-17", "yesterday", ""):
            w(self.p("kcve", "SOURCE"), "fetched_utc=%s\n" % val)
            it = ds.mirror_item(self.tmp, "kcve", "kernel-cve")
            self.assertEqual((it["snapshot_field"], it["snapshot_utc"]), (None, None), val)

    def test_odd_dates_never_crash_or_pass(self):
        # 時區換算後超出 1～9999 年（OverflowError）、非 ASCII 數字、不存在的日期：都變成 null，不讓 collect 崩潰
        w(self.p("kcve.result"), "OK x\n")
        for val in ("0001-01-01T00:00:00+23:59", "9999-12-31T23:59:59-23:59"):
            w(self.p("kcve", "SOURCE"), "fetched_utc=%s\n" % val)
            self.assertIsNone(ds.mirror_item(self.tmp, "kcve", "kernel-cve")["snapshot_utc"], val)
        self.assertIsNone(ds.grype_item({"grype_db_update": "online", "grype_db_built": "0001-01-01T00:00:00+23:59"})["snapshot_utc"])
        base = {"kind": "euvd", "source": "internal", "status": "OK", "snapshot_field": "fetched_utc"}
        for bad in ("\u0662\u0660\u0662\u0666-\u0661\u0661-\u0661\u0667T\u0660\u0661:\u0660\u0662:\u0660\u0663Z", "9999-99-99T99:99:99Z", "2026-02-30T00:00:00Z"):
            self.assertIsNone(ds.clean([dict(base, snapshot_utc=bad)])[0]["snapshot_utc"], bad)
        self.assertEqual(ds.clean([dict(base, snapshot_utc="2026-02-28T00:00:00Z")])[0]["snapshot_utc"], "2026-02-28T00:00:00Z")

    def test_clean_rejects_unknown_snapshot_field_even_with_a_good_time(self):
        it = {"kind": "euvd", "source": "internal", "status": "OK", "snapshot_field": "/srv/mirror", "snapshot_utc": "2026-11-17T01:00:00Z"}
        self.assertEqual(ds.clean([it])[0], {"kind": "euvd", "source": "internal", "status": "OK", "snapshot_field": None, "snapshot_utc": None})

    def test_internal_grype_must_really_be_imported(self):
        # gdb 鏡像合格，但 sca-scan 實際走 online（或匯入失敗）：不能記成內部
        w(self.p("gdb.result"), "OK source=internal kind=grype-db built_utc=2026-11-17T00:00:00Z age_hours=1.0\n")
        for meta, src in (({"grype_db_update": "import:/x/db.tar.zst", "grype_db_update_status": "OK"}, "internal"),
                          ({"grype_db_update": "online", "grype_db_update_status": "OK"}, None),
                          ({"grype_db_update": "import:/x/db.tar.zst", "grype_db_update_status": "FAIL"}, None)):
            it = ds.collect(self.tmp, "gdb=grype-db", meta)[0]
            self.assertEqual(it["source"], src, meta)
            self.assertEqual(it["status"], "OK" if src else "UNKNOWN", meta)

    def test_public_grype_from_meta(self):
        it = ds.grype_item({"grype_db_update": "online", "grype_db_update_status": "OK", "grype_db_built": "2026-11-17T06:07:08Z"})
        self.assertEqual(it, {"kind": "grype-db", "source": "public", "status": "OK", "snapshot_field": "built_utc", "snapshot_utc": "2026-11-17T06:07:08Z"})
        it = ds.grype_item({"grype_db_update": "import:/home/runner/x.tar.zst", "grype_db_update_status": "FAIL"})
        self.assertEqual((it["source"], it["status"]), ("internal", "UNKNOWN"))
        self.assertNotIn("/home/", json.dumps(it))
        self.assertEqual(ds.grype_item(None)["source"], None)

    def test_no_list_means_not_recorded(self):
        self.assertIsNone(ds.collect(self.tmp, "", None))
        self.assertIsNone(ds.collect(None, "kcve=kernel-cve", None))
        self.assertIsNone(ds.summary(None))
        self.assertIsNone(ds.notes_line(None))

    def test_modes(self):
        mk = lambda *s: [{"kind": "euvd", "source": x, "status": "OK", "snapshot_field": None, "snapshot_utc": None} for x in s]  # noqa: E731
        self.assertEqual(ds.summary(mk("internal", "internal"))["mode"], "internal")
        self.assertEqual(ds.summary(mk("public"))["mode"], "public")
        self.assertEqual(ds.summary(mk("internal", "public"))["mode"], "mixed")
        self.assertEqual(ds.summary(mk("internal", None))["mode"], "unknown")
        self.assertEqual(ds.summary([])["mode"], "unknown")

    def test_clean_whitelists_fields_and_values(self):
        dirty = [{"kind": "kernel-cve", "source": "internal", "status": "OK", "snapshot_field": "fetched_utc", "snapshot_utc": "2026-11-17T01:02:03Z",
                  "path": "/home/runner/x", "url": "https://x.example.invalid/"},
                 {"kind": "euvd", "source": "file:///srv", "status": "BAD", "snapshot_field": "fetched_utc", "snapshot_utc": "/srv/mirror"},
                 {"kind": "../etc", "source": "internal"}, "string", None]
        self.assertEqual(ds.clean(dirty), [
            {"kind": "kernel-cve", "source": "internal", "status": "OK", "snapshot_field": "fetched_utc", "snapshot_utc": "2026-11-17T01:02:03Z"},
            {"kind": "euvd", "source": None, "status": "UNKNOWN", "snapshot_field": None, "snapshot_utc": None}])
        self.assertIsNone(ds.clean({"items": []}))

    def test_notes_line(self):
        line = ds.notes_line(ds.summary([
            {"kind": "kernel-cve", "source": "internal", "status": "OK", "snapshot_field": "fetched_utc", "snapshot_utc": "2026-11-17T01:02:03Z"},
            {"kind": "grype-db", "source": "internal", "status": "ATTENTION", "snapshot_field": "built_utc", "snapshot_utc": "2026-11-15T00:00:00Z"}]))
        self.assertEqual(line, "- 弱點資料來源：內部鏡像。快照時間（UTC）：kernel-cve 2026-11-17T01:02:03Z（內部鏡像）、grype-db 2026-11-15T00:00:00Z（內部鏡像，ATTENTION）。"
                               "Dependency-Track 的資料由 DT 自己的資料源提供，不在此列；機器可讀的版本在 `release-meta.json` 的 `data_sources`。")
        for bad in ("不受影響", "不適用", "安全", "PASS"):
            self.assertNotIn(bad, line)


class CollectAndReleaseMeta(unittest.TestCase):
    """collect（MIRRORS_DIR＋DUMPLING_DATA_SOURCES）→ scan.json 的 data_sources、notes.md 一行 → release-meta.json 的 data_sources。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="t06-collect-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.mir = self.p("mirrors")
        for d, kind, f in (("kcve", "kernel-cve", "fetched_utc"), ("euvd", "euvd", "fetched_utc"), ("osv", "osv-distro", "fetched_utc"),
                           ("gdb", "grype-db", "built_utc")):
            w(os.path.join(self.mir, d + ".result"), "OK source=internal kind=%s %s=2026-11-17T01:00:00Z age_hours=1.0\n" % (kind, f))
        self.w0 = self.p("w0")
        w(os.path.join(self.w0, "scan", "rootfs", "scan", "status.tsv"), "stage\tstatus\tdetail\nA-md5\tOK\tx\n")
        w(os.path.join(self.w0, "scan", "rootfs", "scan", "meta.json"),
          json.dumps({"grype_db_update": "import:" + self.p("mirrors", "gdb", "v6", "db.tar.zst"), "grype_db_update_status": "OK",
                      "grype_db_built": "2026-11-17T01:00:00Z"}))
        w(os.path.join(self.w0, "cra-project", "CRA", "Reports", "vulnerability-rows.json"), json.dumps({"rows": []}))
        w(os.path.join(self.w0, "報告", "x.txt"), "x")

    def p(self, *a):
        return os.path.join(self.tmp, *a)

    def collect(self, spec):
        import argparse
        a = argparse.Namespace(out=self.p("rel"), project="orin-nano-demo", version="v39.2.1-demo1", layers=None, build_json=None, assemble_json=None,
                               scan_json=self.p("scan.json"), run=["=" + self.w0], official=False, steps=None)
        old = {k: os.environ.get(k) for k in ("MIRRORS_DIR", "DUMPLING_DATA_SOURCES", "DUMPLING_OUT")}
        try:
            os.environ["MIRRORS_DIR"] = self.mir
            os.environ.pop("DUMPLING_OUT", None)
            if spec is None:
                os.environ.pop("DUMPLING_DATA_SOURCES", None)
            else:
                os.environ["DUMPLING_DATA_SOURCES"] = spec
            return ps.collect(a, ps.Hooks())
        finally:
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

    def release_meta(self):
        out = self.p("release-meta.json")
        r = subprocess.run([sys.executable, "-I", RELEASE_META, "--project", "orin-nano-demo", "--version", "v39.2.1-demo1", "--commit", "a" * 40,
                            "--run-id", "1", "--built-at", "2026-11-17T00:00:00Z", "--scan-summary", self.p("scan.json"), "--out", out],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return json.loads(read(out))

    def test_internal_end_to_end(self):
        scan = self.collect("kcve=kernel-cve euvd=euvd osv=osv-distro gdb=grype-db")
        self.assertEqual(scan["data_sources"]["mode"], "internal")
        self.assertEqual([i["kind"] for i in scan["data_sources"]["items"]], ["kernel-cve", "euvd", "osv-distro", "grype-db"])
        notes = read(self.p("rel", "notes.md"))
        self.assertIn("- 弱點資料來源：內部鏡像。快照時間（UTC）：kernel-cve 2026-11-17T01:00:00Z（內部鏡像）", notes)
        meta = self.release_meta()
        self.assertEqual(meta["data_sources"], scan["data_sources"])
        for text in (json.dumps(scan["data_sources"]), json.dumps(meta["data_sources"]), notes):
            self.assertIsNone(LOCAL_PATH.search(text), text[:300])
        self.assertNotIn(self.tmp, json.dumps(meta))

    def test_public_grype_comes_from_meta(self):
        for d in ("kcve", "euvd", "osv", "gdb"):
            os.remove(os.path.join(self.mir, d + ".result"))
        w(os.path.join(self.mir, "kcve.result"), "OK mirror=%s\n" % self.p("mirrors", "kcve"))
        w(os.path.join(self.mir, "kcve", "SOURCE"), "fetched_utc=2026-11-17T02:00:00Z\n")
        w(os.path.join(self.w0, "scan", "rootfs", "scan", "meta.json"),
          json.dumps({"grype_db_update": "online", "grype_db_update_status": "OK", "grype_db_built": "2026-11-16T22:00:00Z"}))
        scan = self.collect("kcve=kernel-cve")
        self.assertEqual(scan["data_sources"], {"mode": "public", "items": [
            {"kind": "kernel-cve", "source": "public", "status": "OK", "snapshot_field": "fetched_utc", "snapshot_utc": "2026-11-17T02:00:00Z"},
            {"kind": "grype-db", "source": "public", "status": "OK", "snapshot_field": "built_utc", "snapshot_utc": "2026-11-16T22:00:00Z"}]})
        self.assertIn("- 弱點資料來源：公開來源（掃描時下載）。", read(self.p("rel", "notes.md")))
        self.assertEqual(self.release_meta()["data_sources"]["mode"], "public")

    def test_without_list_nothing_is_written(self):
        scan = self.collect(None)
        self.assertIsNone(scan["data_sources"])
        self.assertNotIn("弱點資料來源", read(self.p("rel", "notes.md")))
        self.assertIsNone(self.release_meta()["data_sources"])

    def test_release_meta_rewhitelists_a_tampered_scan_summary(self):
        self.collect("kcve=kernel-cve")
        doc = json.loads(read(self.p("scan.json")))
        doc["data_sources"] = {"mode": "internal", "root": "file:///srv/mirror",
                               "items": [{"kind": "kernel-cve", "source": "internal", "status": "OK", "snapshot_field": "fetched_utc",
                                          "snapshot_utc": "2026-11-17T01:00:00Z", "path": "/srv/mirror/kernel-cve"}]}
        w(self.p("scan.json"), json.dumps(doc))
        meta = self.release_meta()
        self.assertEqual(meta["data_sources"], {"mode": "internal", "items": [
            {"kind": "kernel-cve", "source": "internal", "status": "OK", "snapshot_field": "fetched_utc", "snapshot_utc": "2026-11-17T01:00:00Z"}]})
        self.assertNotIn("/srv", json.dumps(meta))


if __name__ == "__main__":
    unittest.main()
