"""T-04：韌體上傳 DT 改用 pipeline/lib/dt-session.sh（pipeline/firmware-dt-session.sh）。不起真的 DT、不碰 docker、不連外網。
- 沒設 DUMPLING_DT_MODE：dt-ephemeral.sh 的呼叫順序、參數、環境變數和 T-04 之前 firmware.yml 分開寫的 up／wait／env／down 相同
  （OSV＝PyPI,npm,Ubuntu、WAIT＝40；wait 3 繼續並寫 dt-wait.rc；其他非 0 FAIL、不跑 firmware-dt.sh；down 一定執行）。
- resident：GitHub Actions 上一律 FAIL（firmware.yml 的情境下設了 DUMPLING_DT_TEST_RESIDENT 也一樣）；本機的假常駐 DT 可以用，不寫 dt-wait.rc。
- dt-session.sh 為韌體加的兩處：DT_WAIT_RC_FILE（沒設時 3 照樣 FAIL）、dt_end 的 down 失敗 WARNING。
假的 root 只放 dt-session.sh、dt_resident.py、step_rows.py、firmware-dt-session.sh，加上記錄呼叫的假 dt-ephemeral.sh 與假 firmware-dt.sh
（做法同 tests/test_wp7_dt_session.py；假常駐 DT 沿用那裡的 Base）。"""
import os
import shutil
import subprocess
import unittest

import test_wp7_dt_session as t14

ROOT = t14.ROOT
WRAPPER = os.path.join(ROOT, "pipeline", "firmware-dt-session.sh")
read = t14.read

FAKE_FWDT = r'''#!/usr/bin/env bash
pe=missing; [ -f "${PILOT_ENV:-}" ] && pe=present
echo "firmware-dt $* PILOT_ENV=$pe MRS=[${MIRROR_REFRESH_STATUS-unset}] RCFILE=$( [ -f "$FAKE_RESULT/dt-wait.rc" ] && tr -d '\n' < "$FAKE_RESULT/dt-wait.rc" || echo none )" >> "$FAKE_LOG"
exit "${FAKE_FWDT_RC:-0}"
'''


class Base(t14.Base):
    def setUp(self):
        super().setUp()
        shutil.copy(WRAPPER, os.path.join(self.root, "pipeline", "firmware-dt-session.sh"))
        self.w(os.path.join(self.root, "pipeline", "firmware-dt.sh"), FAKE_FWDT)
        self.result = os.path.join(self.tmp, "result")
        self.work = os.path.join(self.tmp, "work")
        self.rcfile = os.path.join(self.result, "dt-wait.rc")

    def wrap(self, *extra, **envkw):
        args = ["--work", self.work, "--result", self.result, "--sample", "a/firmware.yml", "a/fw.cdx.json", *extra]
        env = self.env(PILOT_ENV=self.pe, FAKE_RESULT=self.result, **envkw)
        r = subprocess.run(["bash", os.path.join(self.root, "pipeline", "firmware-dt-session.sh"), *args],
                           capture_output=True, text=True, timeout=120, env=env)
        calls = read(self.log).splitlines() if os.path.exists(self.log) else []
        return r, calls

    def result_steps(self):
        p = os.path.join(self.result, "pipeline-steps.tsv")
        return read(p).splitlines() if os.path.exists(p) else []

    def fwdt_line(self, rcfile="0", mrs="[]"):
        return "firmware-dt --work %s --result %s --sample a/firmware.yml a/fw.cdx.json PILOT_ENV=present MRS=%s RCFILE=%s" % (
            self.work, self.result, mrs, rcfile)


class DefaultModeUnchanged(Base):
    """沒設 DUMPLING_DT_MODE：和 T-04 之前 firmware.yml 的 up／wait／env／上傳／down 相同。"""

    def test_sequence_and_environment(self):
        for envkw in ({}, {"DT_OSV_ECOSYSTEMS": "PyPI,npm,Ubuntu"}):     # firmware.yml 的 job env 有設，沒設時預設相同
            with self.subTest(**envkw):
                if os.path.exists(self.log):
                    os.remove(self.log)
                shutil.rmtree(self.result, True)
                r, calls = self.wrap(**envkw)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertEqual(calls, [
                    "up  OSV=PyPI,npm,Ubuntu WAIT=40",
                    "wait  OSV=PyPI,npm,Ubuntu WAIT=40",
                    "env %s OSV=PyPI,npm,Ubuntu WAIT=40" % self.pe,
                    self.fwdt_line(),
                    "down  OSV=PyPI,npm,Ubuntu WAIT=40"])
                self.assertEqual(read(self.rcfile), "0\n")
                self.assertEqual(self.result_steps(), [])                # 臨時 DT 不記額外的列
                self.assertEqual(r.stderr, "")

    def test_caller_wait_minutes_are_kept(self):
        _, calls = self.wrap(DT_WAIT_MIN="5")
        self.assertEqual(calls[0], "up  OSV=PyPI,npm,Ubuntu WAIT=5")

    def test_wait_gap_continues_and_is_recorded(self):
        r, calls = self.wrap(FAKE_WAIT_RC="3")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual([c.split(" OSV=")[0].strip() for c in calls][:3], ["up", "wait", "env %s" % self.pe])
        self.assertEqual(calls[3], self.fwdt_line(rcfile="3"))              # firmware-dt.sh 看得到 3，report 會把所有樣本標 GAP
        self.assertEqual(calls[-1].split()[0], "down")
        self.assertIn("wait 結束碼 3", r.stdout)

    def test_wait_failure_stops_before_upload(self):
        for rc in ("1", "2", "4"):
            with self.subTest(rc=rc):
                if os.path.exists(self.log):
                    os.remove(self.log)
                r, calls = self.wrap(FAKE_WAIT_RC=rc)
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertEqual(r.stdout.strip().splitlines()[-1], "firmware-dt-session: FAIL（臨時 DT wait 失敗）")
                self.assertEqual([c.split()[0] for c in calls], ["up", "wait", "down"])   # 沒有 env、沒有上傳，down 照跑
                self.assertEqual(read(self.rcfile), rc + "\n")                         # 和之前一樣，失敗的結束碼也留在 dt-wait.rc

    def test_up_or_env_failure_stops_before_upload(self):
        for kw, seq, msg in ((dict(FAKE_UP_RC="1"), ["up", "down"], "臨時 DT up 失敗"),
                             (dict(FAKE_ENV_RC="1"), ["up", "wait", "env", "down"], "臨時 DT env 失敗")):
            with self.subTest(**kw):
                if os.path.exists(self.log):
                    os.remove(self.log)
                shutil.rmtree(self.result, True)
                r, calls = self.wrap(**kw)
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertEqual(r.stdout.strip().splitlines()[-1], "firmware-dt-session: FAIL（%s）" % msg)
                self.assertEqual([c.split()[0] for c in calls], seq)
                self.assertEqual(os.path.exists(self.rcfile), "wait" in seq)

    def test_firmware_dt_exit_code_is_passed_through_and_dt_is_closed(self):
        r, calls = self.wrap(FAKE_FWDT_RC="1")
        self.assertEqual(r.returncode, 1)
        self.assertEqual([c.split()[0] for c in calls], ["up", "wait", "env", "firmware-dt", "down"])

    def test_stale_wait_rc_is_removed(self):
        os.makedirs(self.result)
        with open(self.rcfile, "w") as fh:
            fh.write("3\n")
        r, calls = self.wrap(FAKE_UP_RC="1")
        self.assertEqual(r.returncode, 1)
        self.assertFalse(os.path.exists(self.rcfile))                       # 上一次的 3 不會留到這次

    def test_pilot_env_under_result_fails(self):
        r = subprocess.run(["bash", os.path.join(self.root, "pipeline", "firmware-dt-session.sh"), "--work", self.work, "--result", self.result,
                            "--sample", "a", "b"], capture_output=True, text=True, timeout=120,
                           env=self.env(PILOT_ENV=os.path.join(self.result, "pilot.env"), FAKE_RESULT=self.result))
        self.assertEqual(r.returncode, 1)
        self.assertIn("PILOT_ENV 不能放在 DUMPLING_OUT 底下", r.stdout)
        calls = read(self.log).splitlines()
        self.assertNotIn("env", [c.split()[0] for c in calls])
        self.assertNotIn("firmware-dt", [c.split()[0] for c in calls])

    def test_argument_errors(self):
        for args, envkw in (([], {"PILOT_ENV": self.pe}), (["--work", self.work], {"PILOT_ENV": self.pe}),
                            (["--work", self.work, "--result", self.result], {})):
            with self.subTest(args=args, env=envkw):
                r = subprocess.run(["bash", os.path.join(self.root, "pipeline", "firmware-dt-session.sh"), *args],
                                   capture_output=True, text=True, timeout=60, env=self.env(**envkw))
                self.assertEqual(r.returncode, 64, r.stdout + r.stderr)
                self.assertFalse(os.path.exists(self.log))                # 參數錯誤：沒有起 DT

    def test_down_failure_only_warns(self):
        fake = os.path.join(self.root, "pipeline", "dt-ephemeral.sh")
        self.w(fake, read(fake).replace("  down) ;;", "  down) exit 1;;"))
        r, calls = self.wrap()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)              # 結束碼照 firmware-dt.sh（runner 用完就丟）
        self.assertEqual(r.stderr.strip(), "dt-session: WARNING（臨時 DT down 失敗：容器或 volume 可能殘留）")
        self.assertEqual(calls[-1].split()[0], "down")


class ResidentMode(Base):
    def resident_env(self, **kw):
        e = dict(DUMPLING_DT_MODE="resident", DUMPLING_DT_CONN=self.conn, DUMPLING_DT_ALLOW_HTTP_LOCAL="1")
        e.update(kw)
        return e

    def test_github_actions_always_fails(self):
        cases = ({"GITHUB_ACTIONS": "true"},
                 # firmware.yml 的情境：就算設了 dt-smoke 用的測試開關，workflow 不是 dt-smoke.yml → 照樣 FAIL
                 {"GITHUB_ACTIONS": "true", "DUMPLING_DT_TEST_RESIDENT": "1",
                  "GITHUB_WORKFLOW_REF": "o/dumpling/.github/workflows/firmware.yml@refs/heads/main", "GITHUB_REPOSITORY": "o/dumpling"})
        for kw in cases:
            with self.subTest(**kw):
                t14.FakeDT.seen = []
                r, calls = self.wrap(**self.resident_env(**kw))
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn("firmware-dt-session: FAIL（常駐 DT 模式不在 GitHub Actions 上用", r.stdout)
                self.assertEqual(calls, [])                                 # 沒有起臨時 DT，也沒有跑 firmware-dt.sh
                self.assertEqual(t14.FakeDT.seen, [])                       # 沒有連常駐 DT
                self.assertFalse(os.path.exists(self.pe))
                self.assertFalse(os.path.exists(self.rcfile))

    def test_local_resident_runs_without_wait_rc(self):
        r, calls = self.wrap(**self.resident_env(DT_WAIT_RC_FILE=os.path.join(self.tmp, "x.rc")))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(calls, [self.fwdt_line(rcfile="none", mrs="[unset]")])   # 不起、不關臨時 DT；不設 MIRROR_REFRESH_STATUS
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "x.rc")))       # 呼叫端給的 DT_WAIT_RC_FILE 在 resident 不用
        self.assertEqual(len(self.result_steps()), 1)                               # pipeline-dt-resident 那一列寫在 --result 底下
        self.assertNotIn(t14.KEY, r.stdout + r.stderr)


class WaitRcFile(t14.Base):
    """dt-session.sh 的 DT_WAIT_RC_FILE：只有設了才寫檔、3 才繼續；沒設時和 scan 的行為相同。"""

    def test_unset_keeps_wait_gap_fatal(self):
        r, calls = self.session(FAKE_WAIT_RC="3")
        self.assertEqual((r.returncode, r.stdout.strip().splitlines()[-1]), (1, "scan: FAIL（臨時 DT 的鏡像逾時（GAP：弱點資料不完整））"))
        self.assertNotIn("env", [c.split()[0] for c in calls])

    def test_set_records_and_continues_on_0_and_3(self):
        p = os.path.join(self.tmp, "wait.rc")
        for rc in ("0", "3"):
            with self.subTest(rc=rc):
                r, calls = self.session(FAKE_WAIT_RC=rc, DT_WAIT_RC_FILE=p)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertEqual(read(p), rc + "\n")
                self.assertIn("env", [c.split()[0] for c in calls])

    def test_set_other_codes_fail_with_the_same_message(self):
        p = os.path.join(self.tmp, "wait.rc")
        r, calls = self.session(FAKE_WAIT_RC="1", DT_WAIT_RC_FILE=p)
        self.assertEqual((r.returncode, r.stdout.strip().splitlines()[-1]), (1, "scan: FAIL（臨時 DT wait 失敗）"))
        self.assertEqual(read(p), "1\n")
        self.assertNotIn("env", [c.split()[0] for c in calls])

    def test_unwritable_file_fails(self):
        r, calls = self.session(DT_WAIT_RC_FILE=os.path.join(self.tmp, "no", "such", "dir", "wait.rc"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("寫不了 DT_WAIT_RC_FILE", r.stdout)
        self.assertNotIn("env", [c.split()[0] for c in calls])

    def test_resident_does_not_write(self):
        p = os.path.join(self.tmp, "wait.rc")
        r, _ = self.resident(DT_WAIT_RC_FILE=p)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertFalse(os.path.exists(p))

    def test_down_success_is_silent_and_failure_warns(self):
        r, _ = self.session()
        self.assertEqual(r.stderr, "")
        fake = os.path.join(self.root, "pipeline", "dt-ephemeral.sh")
        self.w(fake, read(fake).replace("  down) ;;", "  down) exit 1;;"))
        r, _ = self.session()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(r.stderr.strip(), "dt-session: WARNING（臨時 DT down 失敗：容器或 volume 可能殘留）")


if __name__ == "__main__":
    unittest.main()
