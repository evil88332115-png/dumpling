"""T-14：scan 的 DT 連線（pipeline/lib/dt-session.sh、dt_resident.py）。不起真的 DT、不碰 docker、不連外網。
- ephemeral（預設）：從 jetson/scan.sh 與 _shared/scan-disk.sh 取出 DT 那一段實際用 bash 執行（假的 dt-ephemeral.sh 與鏡像函式記下呼叫），
  命令順序、環境變數、FAIL 的說明都和 T-14 之前相同。
- resident：本機 127.0.0.1 的假常駐 DT（DUMPLING_DT_ALLOW_HTTP_LOCAL=1；只認正確的 X-Api-Key）；不呼叫 dt-ephemeral.sh；
  權限不足 → FAIL；沒有建立專案的權限 → pipeline-steps.tsv 那一列寫明「專案必須事先存在」；key 不出現在輸出與 $out 底下。
- GitHub workflow 沒有任何路徑設定常駐 DT；--official 只認這個 tag 的 push。"""
import http.server
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIB = os.path.join(ROOT, "pipeline", "lib")
SCAN_DISK = os.path.join(ROOT, "pipeline", "platforms", "_shared", "scan-disk.sh")
JETSON = os.path.join(ROOT, "pipeline", "platforms", "jetson", "scan.sh")
KEY = "odt_TESTKEY_0123456789abcdef"
ALL = ["BOM_UPLOAD", "VIEW_PORTFOLIO", "VIEW_VULNERABILITY", "PORTFOLIO_MANAGEMENT"]

FAKE_EPHEMERAL = r'''#!/usr/bin/env bash
echo "$1 ${2:-} OSV=${DT_OSV_ECOSYSTEMS:-} WAIT=${DT_WAIT_MIN:-}" >> "$FAKE_LOG"
case $1 in
  up) exit "${FAKE_UP_RC:-0}";;
  wait) exit "${FAKE_WAIT_RC:-0}";;
  env) [ "${FAKE_ENV_RC:-0}" = 0 ] || exit "$FAKE_ENV_RC"; printf 'DT_URL=http://127.0.0.1:1\nDT_API_KEY=eph\n' > "$2"; chmod 600 "$2";;
  down) ;;
esac
'''
FAKE_MIRRORS = r'''# shellcheck shell=bash
mirror() { echo "mirror $1 $2" >> "$FAKE_LOG"; mkdir -p "$MIRRORS_DIR/$2"; }
mirror_kernel_cve() { echo "mirror_kernel_cve $1" >> "$FAKE_LOG"; mkdir -p "$MIRRORS_DIR/$1"; }
'''


def read(p):
    with open(p, encoding="utf-8") as fh:
        return fh.read()


def dt_block(path):
    """scan 腳本的「1. DT 與鏡像」那一段（到下一節為止）。"""
    src = read(path)
    m = re.search(r"^# ---------- 1\..*?(?=^# ---------- 2\.|^# 要判定的核心)", src, re.M | re.S)
    return m.group(0)


class FakeDT(http.server.BaseHTTPRequestHandler):
    perms = list(ALL)       # /api/v1/user/self/permissions 的回應；None → 401（key 屬於團隊）
    team = None             # /api/v1/team/self 的權限；None → 401
    version_code = 200
    version = "5.2.0"
    pad = 0                 # 權限回應另外塞的位元組數（測回應上限）
    seen = []

    def log_message(self, *a):
        pass

    def send(self, code, body):
        b = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        FakeDT.seen.append((self.path, self.headers.get("X-Api-Key")))
        if self.path == "/api/version":
            return self.send(FakeDT.version_code, {"version": FakeDT.version})
        if self.headers.get("X-Api-Key") != KEY:
            return self.send(401, {})
        if self.path == "/api/v1/user/self/permissions":
            return self.send(401, {}) if FakeDT.perms is None else self.send(200, FakeDT.perms + ["X" * FakeDT.pad] if FakeDT.pad else FakeDT.perms)
        if self.path == "/api/v1/team/self":
            return self.send(401, {}) if FakeDT.team is None else self.send(200, {"name": "t", "permissions": [{"name": p} for p in FakeDT.team]})
        return self.send(404, {})


class QuietServer(http.server.ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        pass                # curl 收到上限就斷線（回應太大的測試），不印 BrokenPipe


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = QuietServer(("127.0.0.1", 0), FakeDT)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        FakeDT.perms, FakeDT.team, FakeDT.version_code, FakeDT.version, FakeDT.pad, FakeDT.seen = list(ALL), None, 200, "5.2.0", 0, []
        self.tmp = tempfile.mkdtemp(prefix="dumpling-dtsess-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.root = os.path.join(self.tmp, "root")
        os.makedirs(os.path.join(self.root, "pipeline", "lib"))
        for f in ("dt-session.sh", "dt_resident.py", "step_rows.py"):
            shutil.copy(os.path.join(LIB, f), os.path.join(self.root, "pipeline", "lib", f))
        self.w(os.path.join(self.root, "pipeline", "dt-ephemeral.sh"), FAKE_EPHEMERAL)
        self.w(os.path.join(self.root, "pipeline", "lib", "mirrors.sh"), FAKE_MIRRORS)
        self.out = os.path.join(self.tmp, "out")
        os.makedirs(self.out)
        self.pe = os.path.join(self.tmp, "pilot-env", "pilot.env")
        self.log = os.path.join(self.tmp, "calls.log")
        self.conn = os.path.join(self.tmp, "conn", "dt.conn")
        os.makedirs(os.path.dirname(self.conn))
        self.write_conn("DT_URL=http://127.0.0.1:%d\nDT_API_KEY=%s\nDT_FRONTEND_URL=http://127.0.0.1:%d\n" % (self.port, KEY, self.port))

    def w(self, p, text, mode=0o755):
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(p, mode)

    def write_conn(self, text, mode=0o600):
        if os.path.lexists(self.conn):
            os.remove(self.conn)
        self.w(self.conn, text, mode)

    def env(self, **kw):
        e = {k: v for k, v in os.environ.items() if not k.startswith(("GITHUB_", "DUMPLING_DT", "DT_", "CURL_CA", "MIRROR_REFRESH"))}
        e.update(FAKE_LOG=self.log, RUNNER_TEMP=self.tmp)
        e.update(kw)
        return e

    def run_sh(self, body, **envkw):
        sh = 'set -uo pipefail\nroot=%s; out=%s; PILOT_ENV=%s\nfail() { echo "scan: FAIL（$*）"; exit 1; }\n%s\n' % (
            self.root, self.out, self.pe, body)
        r = subprocess.run(["bash", "-c", sh], capture_output=True, text=True, timeout=120, env=self.env(**envkw))
        calls = read(self.log).splitlines() if os.path.exists(self.log) else []
        return r, calls

    def session(self, extra="", **envkw):
        return self.run_sh('. "$root/pipeline/lib/dt-session.sh"\ndt_begin A,B\ndt_ready "$PILOT_ENV"\n' + extra, **envkw)

    def resident(self, extra="", **envkw):
        kw = dict(DUMPLING_DT_MODE="resident", DUMPLING_DT_CONN=self.conn, DUMPLING_DT_ALLOW_HTTP_LOCAL="1")
        kw.update(envkw)
        return self.session(extra, **kw)

    def steps(self):
        p = os.path.join(self.out, "pipeline-steps.tsv")
        return read(p).splitlines() if os.path.exists(p) else []


class EphemeralUnchanged(Base):
    """ephemeral：命令順序、環境變數、FAIL 說明和 T-14 之前的 scan.sh 相同。"""

    def run_block(self, path, **envkw):
        body = dt_block(path)
        return self.run_sh('DUMPLING_PROJECT=p\n' + body + '\necho "MRS=${MIRROR_REFRESH_STATUS-unset}"', **envkw)

    def test_scan_disk_sequence(self):
        r, calls = self.run_block(SCAN_DISK)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(calls, [
            "up  OSV=Debian,PyPI,Go,npm,Maven WAIT=60",
            "mirror_kernel_cve kcve", "mirror euvd.sh euvd", "mirror osv-distro.sh osv",
            "wait  OSV=Debian,PyPI,Go,npm,Maven WAIT=60",
            "env %s OSV=Debian,PyPI,Go,npm,Maven WAIT=60" % self.pe,
            "down  OSV=Debian,PyPI,Go,npm,Maven WAIT=60"])
        self.assertEqual(read(self.pe).splitlines()[2:], ["KERNEL_CVE_MIRROR=%s/mirrors/kcve" % self.out,
                                                         "EUVD_MIRROR=%s/mirrors/euvd" % self.out, "OSV_DISTRO_MIRROR=%s/mirrors/osv" % self.out])
        self.assertEqual(r.stdout, "MRS=unset\n")       # 這一段不設 MIRROR_REFRESH_STATUS（在後面和 GRYPE_DB_UPDATE 同一行）
        self.assertEqual(self.steps(), [])               # 臨時 DT 不記額外的列

    def test_jetson_sequence(self):
        r, calls = self.run_block(JETSON)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual([c.split(" OSV=")[0].strip() for c in calls], [
            "up", "mirror nvidia-bulletins.sh nvbul", "mirror_kernel_cve kcve", "mirror euvd.sh euvd", "mirror osv-distro.sh osv",
            "wait", "env %s" % self.pe, "down"])
        self.assertTrue(all(c.endswith("OSV=Ubuntu,PyPI,Go,Maven WAIT=60") for c in calls if not c.startswith("mirror")), calls)

    def test_platform_default_wins(self):
        _, calls = self.run_block(SCAN_DISK, DT_OSV_ECOSYSTEMS="Debian", DT_WAIT_MIN="5")
        self.assertEqual(calls[0], "up  OSV=Debian WAIT=5")

    def test_fail_messages_unchanged(self):
        for kw, msg in ((dict(FAKE_UP_RC="1"), "scan: FAIL（臨時 DT up 失敗）"),
                        (dict(FAKE_WAIT_RC="3"), "scan: FAIL（臨時 DT 的鏡像逾時（GAP：弱點資料不完整））"),
                        (dict(FAKE_WAIT_RC="1"), "scan: FAIL（臨時 DT wait 失敗）"),
                        (dict(FAKE_ENV_RC="1"), "scan: FAIL（臨時 DT env 失敗）")):
            with self.subTest(**kw):
                if os.path.exists(self.log):
                    os.remove(self.log)
                r, calls = self.run_block(SCAN_DISK, **kw)
                self.assertEqual((r.returncode, r.stdout.strip().splitlines()[-1]), (1, msg))
                self.assertEqual(calls[-1].split()[0], "down")          # 失敗也會關掉臨時 DT

    def test_existing_exit_trap_is_kept(self):
        r, calls = self.run_sh('trap \'echo "prev $out" >> "$FAKE_LOG"\' EXIT\n. "$root/pipeline/lib/dt-session.sh"\ndt_begin A\n')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual([c.split(" OSV=")[0].strip() for c in calls], ["up", "prev %s" % self.out, "down"])

    def test_mirror_status_kept_in_ephemeral(self):
        r, _ = self.run_sh('. "$root/pipeline/lib/dt-session.sh"\nexport MIRROR_REFRESH_STATUS=""\ndt_mirror_status\necho "[${MIRROR_REFRESH_STATUS-unset}]"')
        self.assertEqual(r.stdout.strip(), "[]")

    def test_pilot_env_under_out_fails(self):
        r, calls = self.run_sh('. "$root/pipeline/lib/dt-session.sh"\ndt_begin A\ndt_ready "$out/pilot.env"')
        self.assertIn("PILOT_ENV 不能放在 DUMPLING_OUT 底下", r.stdout)
        self.assertNotIn("env", [c.split()[0] for c in calls])


class Resident(Base):
    def test_ok(self):
        r, calls = self.resident()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(calls, [])                                       # 沒有起或關臨時 DT
        self.assertEqual(stat.S_IMODE(os.stat(self.pe).st_mode), 0o600)
        self.assertEqual(sorted(l.split("=")[0] for l in read(self.pe).splitlines()), ["DT_API_KEY", "DT_FRONTEND_URL", "DT_URL"])
        rows = self.steps()
        self.assertEqual(len(rows), 1)
        f = rows[0].split("\t")
        self.assertEqual(f[:3], ["pipeline-dt-resident", "OK", "0"])
        self.assertIn("apiserver 5.2.0", f[3])
        self.assertIn("/api/v1/user/self/permissions", f[3])
        self.assertEqual([p for p, _ in FakeDT.seen], ["/api/version", "/api/v1/user/self/permissions"])
        self.assertIsNone(FakeDT.seen[0][1])                            # /api/version 不帶 key

    def test_key_not_in_output_or_out(self):
        r, _ = self.resident()
        self.assertNotIn(KEY, r.stdout + r.stderr)
        for d, _, fs in os.walk(self.out):
            for f in fs:
                self.assertNotIn(KEY, read(os.path.join(d, f)), f)
        leftovers = [d for d in os.listdir(self.tmp) if d.startswith("dumpling-dt.")]
        self.assertEqual(leftovers, [])                                   # 私用暫存資料夾（curl 設定檔、回應）結束時刪掉

    def test_curl_key_file_removed_right_after_use(self):
        r, _ = self.resident('ls "$_DT_TMP"')
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertNotIn("key.cfg", r.stdout)                             # 讀完權限就刪，不等到結束

    def test_key_only_via_curl_config_file(self):
        src = read(os.path.join(LIB, "dt-session.sh"))
        for line in src.splitlines():
            if re.search(r"\bcurl\b", line) and not line.lstrip().startswith("#"):
                self.assertNotIn("API_KEY", line)
                self.assertNotIn("X-Api-Key", line)

    def test_missing_required_permission_fails(self):
        for miss in ("BOM_UPLOAD", "VIEW_PORTFOLIO", "VIEW_VULNERABILITY"):
            with self.subTest(missing=miss):
                FakeDT.perms = [p for p in ALL if p != miss]
                r, _ = self.resident()
                self.assertEqual(r.returncode, 1)
                self.assertIn("缺少必要權限：%s" % miss, r.stdout)
                self.assertEqual(self.steps(), [])

    def assert_no_key_anywhere(self, r):
        self.assertNotIn(KEY, r.stdout + r.stderr)
        for d, _, fs in os.walk(self.out):
            for f in fs:
                self.assertNotIn(KEY, read(os.path.join(d, f)), f)

    def test_key_not_in_failure_output(self):
        cases = [("version 503", dict(version_code=503)), ("缺權限", dict(perms=["BOM_UPLOAD"])),
                 ("key 不屬於任何人", dict(perms=None, team=None)), ("權限格式不對", dict(perms={"x": 1})),
                 ("回應太大", dict(pad=2 * 1024 * 1024))]
        for name, kw in cases:
            with self.subTest(name):
                self.setUp()
                for k, v in kw.items():
                    setattr(FakeDT, k, v)
                r, _ = self.resident()
                self.assertEqual(r.returncode, 1, (name, r.stdout))
                self.assert_no_key_anywhere(r)

    def test_oversized_permission_response_fails(self):
        FakeDT.pad = 2 * 1024 * 1024
        r, _ = self.resident()
        self.assertEqual(r.returncode, 1)
        self.assertIn("常駐 DT 回應太大（/api/v1/user/self/permissions，超過 1048576 bytes）", r.stdout)   # 寫明是太大，不是連不上
        self.assertEqual(self.steps(), [])

    def test_long_version_string_is_truncated(self):
        FakeDT.version = "5.2.0" + "A" * (2 * 1024 * 1024)
        r, _ = self.resident()
        self.assertEqual(r.returncode, 1)
        self.assertIn("常駐 DT 回應太大（/api/version，超過 1048576 bytes）", r.stdout)   # 不會變成誤導的「寫不了 pipeline-steps.tsv」或「連不上」
        FakeDT.version = "5.2.0" + "B" * 100
        r, _ = self.resident()
        self.assertEqual(r.returncode, 0, r.stdout[-300:])
        row = self.steps()[0].split("\t")[3]
        self.assertIn("apiserver 5.2.0" + "B" * 59 + "）", row)   # 最多 64 字元

    def test_curlrc_is_ignored(self):
        home = os.path.join(self.tmp, "home")
        os.makedirs(home)
        self.w(os.path.join(home, ".curlrc"), "proxy = http://127.0.0.1:9\ninsecure\n", 0o644)   # 讀了就連不上
        r, _ = self.resident(HOME=home, CURL_HOME=home)
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_curl_calls_are_hardened(self):
        src = read(os.path.join(LIB, "dt-session.sh"))
        code = [l for l in src.splitlines() if not l.lstrip().startswith("#")]
        calls = [l for l in code if re.search(r"(^|[\s(;|&{])curl\s+-", l)]
        self.assertEqual(len(calls), 1, calls)                                  # 只有 _dt_curl 直接呼叫 curl
        self.assertRegex(calls[0], r"_dt_curl\(\) \{ curl -q -sS -m 30 --max-filesize ")
        for l in code:
            self.assertNotRegex(l, r"(\s-k\b|--insecure|--proxy-insecure|--ssl-no-revoke|-K\s*-)", l)
        self.assertEqual(sum(bool(re.search(r"\$\(_dt_http ", l)) for l in code), 3)                # 三個請求都經 _dt_http → _dt_curl
        self.assertIn('c=$(_dt_curl "$@"); rc=$?', src)

    def test_no_create_permission_is_written_in_steps(self):
        FakeDT.perms = ["BOM_UPLOAD", "VIEW_PORTFOLIO", "VIEW_VULNERABILITY"]
        r, _ = self.resident()
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("專案必須事先存在", self.steps()[0])

    def test_create_permission_variants(self):
        for create in ("PORTFOLIO_MANAGEMENT", "PORTFOLIO_MANAGEMENT_CREATE"):
            with self.subTest(create=create):
                FakeDT.perms = ["BOM_UPLOAD", "VIEW_PORTFOLIO", "VIEW_VULNERABILITY", create]
                os.path.exists(os.path.join(self.out, "pipeline-steps.tsv")) and os.remove(os.path.join(self.out, "pipeline-steps.tsv"))
                self.resident()
                self.assertNotIn("專案必須事先存在", self.steps()[0])

    def test_team_key_falls_back_to_team_self(self):
        FakeDT.perms, FakeDT.team = None, list(ALL)
        r, _ = self.resident()
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("/api/v1/team/self", self.steps()[0])

    def test_unknown_key_fails(self):
        FakeDT.perms, FakeDT.team = None, None
        r, _ = self.resident()
        self.assertEqual(r.returncode, 1)
        self.assertIn("讀不到 API key 的權限", r.stdout)

    def test_wrong_key_fails(self):
        self.write_conn("DT_URL=http://127.0.0.1:%d\nDT_API_KEY=wrong\n" % self.port)
        r, _ = self.resident()
        self.assertEqual(r.returncode, 1)
        self.assertIn("讀不到 API key 的權限", r.stdout)

    def test_version_unreachable_fails(self):
        FakeDT.version_code = 503
        r, _ = self.resident()
        self.assertEqual(r.returncode, 1)
        self.assertIn("常駐 DT 連不上：GET /api/version http=503", r.stdout)

    def test_no_conn_fails_without_fallback(self):
        r, calls = self.session(DUMPLING_DT_MODE="resident")
        self.assertEqual(r.returncode, 1)
        self.assertIn("需要 DUMPLING_DT_CONN", r.stdout)
        self.assertEqual(calls, [])

    def test_github_actions_refused(self):
        r, calls = self.resident(GITHUB_ACTIONS="true")
        self.assertEqual(r.returncode, 1)
        self.assertIn("不在 GitHub Actions 上用", r.stdout)
        self.assertEqual((calls, FakeDT.seen), ([], []))

    def test_github_test_switch_needs_both_conditions(self):
        """GitHub 上只有 dt-smoke.yml 的整合測試例外：DUMPLING_DT_TEST_RESIDENT=1 而且 GITHUB_WORKFLOW_REF 是這個 repo 的 dt-smoke.yml。"""
        ok_ref = "o/r/.github/workflows/dt-smoke.yml@refs/pull/7/merge"
        cases = [
            (dict(DUMPLING_DT_TEST_RESIDENT="1", GITHUB_REPOSITORY="o/r", GITHUB_WORKFLOW_REF=ok_ref), True),
            (dict(DUMPLING_DT_TEST_RESIDENT="1", GITHUB_REPOSITORY="o/r", GITHUB_WORKFLOW_REF="o/r/.github/workflows/dt-smoke.yml@refs/heads/main"), True),
            (dict(GITHUB_REPOSITORY="o/r", GITHUB_WORKFLOW_REF=ok_ref), False),                                   # 少了開關
            (dict(DUMPLING_DT_TEST_RESIDENT="1", GITHUB_REPOSITORY="o/r"), False),                                # 少了 workflow ref
            (dict(DUMPLING_DT_TEST_RESIDENT="true", GITHUB_REPOSITORY="o/r", GITHUB_WORKFLOW_REF=ok_ref), False),  # 只認 1
            (dict(DUMPLING_DT_TEST_RESIDENT="1", GITHUB_REPOSITORY="o/r", GITHUB_WORKFLOW_REF="o/r/.github/workflows/pipeline.yml@refs/heads/main"), False),
            (dict(DUMPLING_DT_TEST_RESIDENT="1", GITHUB_REPOSITORY="o/r", GITHUB_WORKFLOW_REF="o/r/.github/workflows/release.yml@refs/tags/p/v1"), False),
            (dict(DUMPLING_DT_TEST_RESIDENT="1", GITHUB_REPOSITORY="o/r", GITHUB_WORKFLOW_REF="x/y/.github/workflows/dt-smoke.yml@refs/heads/main"), False),  # 別的 repo
            (dict(DUMPLING_DT_TEST_RESIDENT="1", GITHUB_REPOSITORY="o/r", GITHUB_WORKFLOW_REF="o/r/.github/workflows/dt-smoke.yml@"), False),  # 沒有 ref
            (dict(DUMPLING_DT_TEST_RESIDENT="1", GITHUB_WORKFLOW_REF=ok_ref), False),                              # 沒有 GITHUB_REPOSITORY
            (dict(DUMPLING_DT_TEST_RESIDENT="1", GITHUB_REPOSITORY="o/r", GITHUB_WORKFLOW_REF="o/r/.github/workflows/xdt-smoke.yml@refs/heads/main"), False),
        ]
        for env, allowed in cases:
            with self.subTest(**env):
                if os.path.exists(os.path.join(self.out, "pipeline-steps.tsv")):
                    os.remove(os.path.join(self.out, "pipeline-steps.tsv"))
                r, calls = self.resident(GITHUB_ACTIONS="true", **env)
                if allowed:
                    self.assertEqual(r.returncode, 0, r.stdout)
                else:
                    self.assertEqual(r.returncode, 1, r.stdout)
                    self.assertIn("不在 GitHub Actions 上用", r.stdout)
                self.assertEqual(calls, [])

    def test_switch_does_nothing_outside_resident(self):
        # 開關只放行 resident 的 GitHub 防呆，不改 ephemeral 的行為
        r, calls = self.session(GITHUB_ACTIONS="true", DUMPLING_DT_TEST_RESIDENT="1", GITHUB_REPOSITORY="o/r",
                                GITHUB_WORKFLOW_REF="o/r/.github/workflows/dt-smoke.yml@refs/heads/main")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertEqual([c.split(" OSV=")[0].strip() for c in calls], ["up", "wait", "env %s" % self.pe, "down"])

    def test_unknown_mode_fails(self):
        r, calls = self.session(DUMPLING_DT_MODE="off")
        self.assertEqual(r.returncode, 1)
        self.assertIn("DUMPLING_DT_MODE 不認得", r.stdout)

    def test_mirror_status_removed(self):
        r, _ = self.resident('export MIRROR_REFRESH_STATUS=""\ndt_mirror_status\necho "[${MIRROR_REFRESH_STATUS-unset}]"')
        self.assertEqual(r.stdout.strip().splitlines()[-1], "[unset]")

    def test_existing_exit_trap_is_kept(self):
        r, _ = self.run_sh('trap \'echo prev >> "$FAKE_LOG"\' EXIT\n. "$root/pipeline/lib/dt-session.sh"\ndt_begin A\ndt_ready "$PILOT_ENV"',
                           DUMPLING_DT_MODE="resident", DUMPLING_DT_CONN=self.conn, DUMPLING_DT_ALLOW_HTTP_LOCAL="1")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertEqual(read(self.log).splitlines(), ["prev"])

    def test_ca_file_is_merged_with_system_bundle(self):
        ca = os.path.join(self.tmp, "corp-ca.pem")
        self.w(ca, "-----BEGIN CERTIFICATE-----\nCORPCA\n-----END CERTIFICATE-----\n", 0o644)
        r, _ = self.resident('cat "$CURL_CA_BUNDLE" > "$FAKE_LOG.ca"', DUMPLING_DT_CA_FILE=ca)
        if r.returncode == 1 and "找不到系統的 CA bundle" in r.stdout:
            self.skipTest("這台機器沒有系統 CA bundle")
        self.assertEqual(r.returncode, 0, r.stdout)
        merged = read(self.log + ".ca")
        self.assertTrue(merged.rstrip().endswith("CORPCA\n-----END CERTIFICATE-----"))
        self.assertGreater(merged.count("BEGIN CERTIFICATE"), 1)          # 系統的 CA 也在（不是只有公司 CA）

    def test_ca_file_not_pem_fails(self):
        ca = os.path.join(self.tmp, "x.pem")
        self.w(ca, "not a cert\n", 0o644)
        r, _ = self.resident(DUMPLING_DT_CA_FILE=ca)
        self.assertEqual(r.returncode, 1)
        self.assertIn("DUMPLING_DT_CA_FILE 不是 PEM", r.stdout)

    def test_pilot_env_under_out_fails(self):
        self.pe = os.path.join(self.out, "pilot.env")
        r, _ = self.resident()
        self.assertIn("PILOT_ENV 不能放在 DUMPLING_OUT 底下", r.stdout)
        self.assertFalse(os.path.exists(self.pe))


class ConnFile(Base):
    def check(self, text=None, mode=0o600, **envkw):
        if text is not None:
            self.write_conn(text, mode)
        e = self.env(**envkw)
        r = subprocess.run(["python3", "-I", os.path.join(LIB, "dt_resident.py"), "check", self.conn], capture_output=True, text=True, env=e)
        self.assertNotIn(KEY, r.stdout + r.stderr)
        return r.returncode, r.stdout.strip()

    def test_valid(self):
        self.assertEqual(self.check("# c\n\nDT_URL=https://dt.example/api/\nDT_API_KEY=%s\n" % KEY), (0, "OK"))
        for port in ("1", "443", "65535"):
            self.assertEqual(self.check("DT_URL=https://dt.example:%s/x\nDT_API_KEY=k\n" % port), (0, "OK"), port)

    def test_rejected(self):
        bad = {
            "其他鍵": "DT_URL=https://dt.example\nDT_API_KEY=k\nOTHER=1\n",
            "重複": "DT_URL=https://dt.example\nDT_API_KEY=k\nDT_API_KEY=k\n",
            "空值": "DT_URL=https://dt.example\nDT_API_KEY=\n",
            "缺 key": "DT_URL=https://dt.example\n",
            "http": "DT_URL=http://dt.example\nDT_API_KEY=k\n",
            "帳號密碼": "DT_URL=https://u:p@dt.example\nDT_API_KEY=k\n",
            "空白": "DT_URL=https://dt.example\nDT_API_KEY=a b\n",
            "引號": 'DT_URL=https://dt.example\nDT_API_KEY="k"\n',
            "不是 KEY=VALUE": "DT_URL=https://dt.example\nDT_API_KEY=k\nexport X\n",
            "前端 http": "DT_URL=https://dt.example\nDT_API_KEY=k\nDT_FRONTEND_URL=http://dt.example\n",
            "反斜線": "DT_URL=https://dt.example\nDT_API_KEY=k\\x\n",
            "埠 0": "DT_URL=https://dt.example:0\nDT_API_KEY=k\n",
            "埠 65536": "DT_URL=https://dt.example:65536\nDT_API_KEY=k\n",
            "路徑 ..": "DT_URL=https://dt.example/a/../api\nDT_API_KEY=k\n",
            "路徑 .": "DT_URL=https://dt.example/./api\nDT_API_KEY=k\n",
            "路徑結尾 ..": "DT_URL=https://dt.example/..\nDT_API_KEY=k\n",
        }
        for name, text in bad.items():
            with self.subTest(name):
                self.assertEqual(self.check(text)[0], 1)

    def test_reader_limits_response_size(self):
        """讀伺服器回應的那一端也有上限（伺服器沒給長度時 curl 可能收完才知道）。"""
        big = os.path.join(self.tmp, "big.json")
        with open(big, "w", encoding="utf-8") as fh:
            json.dump({"version": "5.2.0", "x": "A" * (1024 * 1024)}, fh)
        for args in (["version", big], ["perms", big, "user"]):
            r = subprocess.run(["python3", "-I", os.path.join(LIB, "dt_resident.py")] + args, capture_output=True, text=True)
            self.assertEqual(r.returncode, 1, args)
            self.assertIn("超過 1048576 bytes", r.stdout, args)

    def test_local_http_needs_flag_and_loopback(self):
        t = "DT_URL=http://127.0.0.1:8080\nDT_API_KEY=k\n"
        self.assertEqual(self.check(t)[0], 1)
        self.assertEqual(self.check(t, DUMPLING_DT_ALLOW_HTTP_LOCAL="1")[0], 0)
        for host in ("192.0.2.1", "localhost"):          # 只認 127.0.0.1（192.0.2.0/24 是文件用的位址）
            self.assertEqual(self.check("DT_URL=http://%s:8080\nDT_API_KEY=k\n" % host, DUMPLING_DT_ALLOW_HTTP_LOCAL="1")[0], 1, host)

    def test_permissions_and_symlink(self):
        rc, msg = self.check("DT_URL=https://dt.example\nDT_API_KEY=%s\n" % KEY, mode=0o640)
        self.assertEqual(rc, 1)
        self.assertIn("權限太寬", msg)
        real = self.conn + ".real"
        os.rename(self.conn, real)
        os.chmod(real, 0o600)
        os.symlink(real, self.conn)
        self.assertEqual(self.check(), (1, "連線檔不能是連結"))


class NoResidentInGithubWorkflows(unittest.TestCase):
    WF = os.path.join(ROOT, ".github", "workflows")

    def workflows(self):
        return {f: read(os.path.join(self.WF, f)) for f in sorted(os.listdir(self.WF)) if f.endswith((".yml", ".yaml"))}

    def test_only_dt_smoke_mentions_dumpling_dt(self):
        for f, t in self.workflows().items():
            names = set(re.findall(r"DUMPLING_DT_[A-Z_]+", t))
            if f == "dt-smoke.yml":
                self.assertEqual(names, {"DUMPLING_DT_TEST_RESIDENT"}, f)     # 其他變數在 pipeline/dt-resident-smoke.sh 裡設
            else:
                self.assertEqual(names, set(), f)

    def test_dt_smoke_is_not_reusable_and_not_called(self):
        # reusable workflow 的 GITHUB_WORKFLOW_REF 是呼叫端：dt-smoke.yml 不能有 workflow_call，也不能被別的 workflow 呼叫
        import yaml
        wfs = self.workflows()
        on = yaml.safe_load(wfs["dt-smoke.yml"]).get(True) or yaml.safe_load(wfs["dt-smoke.yml"]).get("on")
        self.assertNotIn("workflow_call", on if isinstance(on, (dict, list)) else [on])
        self.assertNotIn("workflow_call", wfs["dt-smoke.yml"])
        for f, t in wfs.items():
            self.assertNotRegex(t, r"uses:\s*\S*dt-smoke\.ya?ml", f)

    def test_switch_is_set_only_on_the_integration_step(self):
        import yaml
        d = yaml.safe_load(self.workflows()["dt-smoke.yml"])
        where = []
        for jn, job in (d.get("jobs") or {}).items():
            if "DUMPLING_DT_TEST_RESIDENT" in json.dumps(job.get("env") or {}):
                where.append((jn, "<job env>"))
            for st in job.get("steps") or []:
                if "DUMPLING_DT_TEST_RESIDENT" in json.dumps(st.get("env") or {}):
                    where.append((jn, st.get("name")))
                    self.assertIn("pipeline/dt-resident-smoke.sh", st.get("run", ""))
        self.assertEqual(len(where), 1, where)                                # 只有那一步，不是整個 job
        if "env" in d:
            self.assertNotIn("DUMPLING_DT_TEST_RESIDENT", json.dumps(d["env"]))


class OfficialOnlyForThisTagPush(unittest.TestCase):
    def line(self, path):
        return [l for l in read(path).splitlines() if l.startswith("official=();")][0]

    def official(self, path, **env):
        sh = 'DUMPLING_PROJECT=p; ver=v1\n%s\necho "${#official[@]}"' % self.line(path)
        e = {k: v for k, v in os.environ.items() if not k.startswith("GITHUB_")}
        e.update(env)
        return subprocess.run(["bash", "-c", sh], capture_output=True, text=True, env=e).stdout.strip() == "1"

    def test_both_scripts(self):
        for path in (SCAN_DISK, JETSON):
            with self.subTest(os.path.basename(os.path.dirname(path))):
                self.assertTrue(self.official(path, GITHUB_EVENT_NAME="push", GITHUB_REF_TYPE="tag", GITHUB_REF="refs/tags/p/v1"))
                self.assertFalse(self.official(path, GITHUB_EVENT_NAME="push", GITHUB_REF_TYPE="branch", GITHUB_REF="refs/heads/p/v1"))
                self.assertFalse(self.official(path, GITHUB_EVENT_NAME="push", GITHUB_REF_TYPE="branch", GITHUB_REF="refs/tags/p/v1"))  # 三個條件都要
                self.assertFalse(self.official(path, GITHUB_EVENT_NAME="push", GITHUB_REF_TYPE="tag", GITHUB_REF="refs/tags/p/v2"))
                self.assertFalse(self.official(path, GITHUB_EVENT_NAME="workflow_dispatch", GITHUB_REF_TYPE="branch", GITHUB_REF="refs/heads/main"))
                self.assertFalse(self.official(path))


if __name__ == "__main__":
    unittest.main()
