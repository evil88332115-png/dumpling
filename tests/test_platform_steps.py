"""workflow 步驟的結果紀錄：pipeline/run-step.sh（結束碼規則）、step_rows、collect／release-meta／scan-status-check 對 GAP 與 FAIL 的處理。不連網。"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(ROOT, "pipeline", "lib"))
import platform_scan as ps  # noqa: E402
import step_rows as sr  # noqa: E402

RUN_STEP = os.path.join(ROOT, "pipeline", "run-step.sh")


class Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dumpling-steps-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def p(self, *a):
        return os.path.join(self.tmp, *a)


class RunStep(Tmp):
    @staticmethod
    def sub(path, old, new):
        with open(path, encoding="utf-8") as f:
            t = f.read()
        with open(path, "w", encoding="utf-8") as f:
            f.write(t.replace(old, new))

    def setUp(self):
        super().setUp()
        self.plats = self.p("plats")
        shutil.copytree(os.path.join(ROOT, "pipeline", "platforms", "example"), os.path.join(self.plats, "steps"))
        self.sub(os.path.join(self.plats, "steps", "platform.yml"), "platform: example", "platform: steps")
        # 每個步驟的腳本：印一行說明，結束碼取自環境變數 STEP_RC
        for step in ("build", "assemble", "scan"):
            open(os.path.join(self.plats, "steps", step + ".sh"), "w").write('#!/usr/bin/env bash\necho "前面的行"\necho "%s: 結果說明"\nexit "${STEP_RC:-0}"\n' % step)
        d = self.p("projects", "steps-demo")
        shutil.copytree(os.path.join(ROOT, "projects", "orin-nano-demo"), d)
        self.sub(os.path.join(d, "project.yml"), 'platform: "jetson"', 'platform: "steps"')
        self.proj = d
        self.out_base = self.p("out")

    def run_step(self, *args, rc=0):
        env = dict(os.environ, DUMPLING_PLATFORMS_DIR=self.plats, DUMPLING_OUT_BASE=self.out_base, STEP_RC=str(rc))
        env.pop("DUMPLING_OUT", None)
        return subprocess.run(["bash", RUN_STEP, *args], capture_output=True, text=True, env=env)

    def rows(self):
        return sr.read_rows(os.path.join(self.out_base, "steps-demo", "v39.2.1-demo1", "pipeline-steps.tsv"))

    def test_exit_code_rules(self):
        # (步驟腳本的結束碼, run-step 的結束碼, 記錄的狀態, 輸出裡的標記)
        for rc, want_exit, status, marker in ((0, 0, "OK", None), (3, 0, "GAP", "::warning::"), (4, 0, "NOT_RUN", "::notice::"),
                                              (1, 1, "FAIL", "::error::"), (64, 1, "FAIL", "::error::"), (7, 1, "FAIL", "::error::")):
            shutil.rmtree(self.out_base, ignore_errors=True)
            r = self.run_step("build", self.proj, "v39.2.1-demo1", rc=rc)
            self.assertEqual(r.returncode, want_exit, (rc, r.stdout, r.stderr))
            rows = self.rows()
            self.assertEqual(len(rows), 1, rc)
            self.assertEqual((rows[0]["step"], rows[0]["status"], rows[0]["exit"]), ("pipeline-build", status, rc))
            self.assertIn("build: 結果說明", rows[0]["detail"])          # 最後一行輸出
            if marker:
                self.assertIn(marker, r.stdout)
            else:
                self.assertNotIn("::", r.stdout)
            self.assertIn("前面的行", r.stdout)                              # 輸出照樣印出來

    def test_every_step_appends_a_row_in_order(self):
        for step in ("build", "assemble", "scan"):
            self.run_step(step, self.proj, "v39.2.1-demo1", rc=3 if step == "assemble" else 0)
        rows = self.rows()
        self.assertEqual([(r["step"], r["status"]) for r in rows], [("pipeline-build", "OK"), ("pipeline-assemble", "GAP"), ("pipeline-scan", "OK")])
        self.assertEqual(sr.overall(rows), "GAP")

    def test_validate_failure_and_usage(self):
        r = self.run_step("validate", os.path.join(self.tmp, "nope"), "v1")
        self.assertEqual(r.returncode, 1)
        self.assertEqual(self.run_step("build", self.proj).returncode, 64)                 # 少參數：用法錯誤
        self.assertEqual(self.run_step("--record", self.proj).returncode, 64)

    def test_record_mode_for_build_mode_none(self):
        r = self.run_step("--record", self.proj, "v39.2.1-demo1", "build", "NOT_RUN", "4", "build.mode: none")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        row = open(os.path.join(self.out_base, "steps-demo", "v39.2.1-demo1", "pipeline-steps.tsv"), encoding="utf-8").read()
        self.assertEqual(row, "pipeline-build\tNOT_RUN\t4\tbuild.mode: none\n")
        self.assertEqual(self.run_step("--record", self.proj, "v39.2.1-demo1", "build", "MAYBE", "4", "x").returncode, 1)     # 不認得的狀態

    def test_workflow_uses_run_step_for_every_platform_call(self):
        for f in ("pipeline.yml", "release.yml", "dev.yml"):
            t = open(os.path.join(ROOT, ".github", "workflows", f), encoding="utf-8").read()
            code = [l for l in t.splitlines() if "pipeline/platform.sh" in l and not l.lstrip().startswith("#")]
            self.assertEqual(code, [], f)                      # 所有步驟都經過 run-step.sh，結束碼規則與紀錄只有一份


class Rows(Tmp):
    def test_overall_and_format(self):
        f = self.p("s.tsv")
        sr.append_row(f, "fetch", "OK", 0, "ok\twith\ttabs")
        sr.append_row(f, "pipeline-build", "NOT_RUN", 4, "build.mode: none")
        rows = sr.read_rows(f)
        self.assertEqual(rows[0]["detail"], "ok with tabs")
        self.assertEqual(sr.overall(rows), "OK")                                    # NOT_RUN 不降低整體狀態，但會列出
        sr.append_row(f, "scan", "GAP", 3, "沒有標準答案")
        self.assertEqual(sr.overall(sr.read_rows(f)), "GAP")
        sr.append_row(f, "assemble", "FAIL", 1, "x")
        self.assertEqual(sr.overall(sr.read_rows(f)), "FAIL")
        self.assertEqual(sr.overall(None), "GAP")                                   # 沒有紀錄檔不能當成沒問題
        open(f, "a").write("壞掉的列\n")
        self.assertEqual(sr.read_rows(f)[-1]["status"], "FAIL")                     # 壞掉的列保留成 FAIL，不丟掉
        with self.assertRaises(ValueError):
            sr.append_row(f, "x", "MAYBE", 0, "")


class CollectShowsSteps(Tmp):
    def run_dir(self):
        d = self.p("w0")
        for rel, content in (("scan/rootfs/scan/status.tsv", "stage\tstatus\tdetail\n"),
                             ("cra-project/CRA/Reports/vulnerability-rows.json", json.dumps({"rows": []})),
                             ("報告/交給PM/VEX/vex.cdx.json", "{}")):
            os.makedirs(os.path.dirname(os.path.join(d, rel)), exist_ok=True)
            open(os.path.join(d, rel), "w", encoding="utf-8").write(content)
        return d

    def args(self, steps):
        return argparse.Namespace(out=self.p("rel"), project="p", version="v1", layers=None, build_json=None, assemble_json=None, scan_json=self.p("scan.json"),
                                  run=["=" + self.run_dir()], official=False, steps=steps, steps_md=self.p("steps.md"))

    def test_gap_row_shows_up_and_pulls_the_overall_status_down(self):
        f = self.p("steps.tsv")
        sr.append_row(f, "validate", "OK", 0, "validate: OK")
        sr.append_row(f, "assemble", "GAP", 3, "assemble: GAP（raw-sectors 沒有讀）")
        scan = ps.collect(self.args(f))
        self.assertEqual(scan["pipeline_status"], "GAP")
        self.assertEqual([r["status"] for r in scan["pipeline_steps"]], ["OK", "GAP"])
        notes = open(self.p("rel", "notes.md"), encoding="utf-8").read()
        self.assertIn("## 流程步驟", notes)
        self.assertIn("| pipeline-assemble | GAP | 3 | assemble: GAP（raw-sectors 沒有讀） |", notes)
        self.assertIn("整體狀態 **GAP**", notes)
        md = open(self.p("steps.md"), encoding="utf-8").read()                      # scan.sh 把它放進 summary.md
        self.assertIn("pipeline-assemble | GAP", md)
        self.assertIn("整體狀態 GAP", md)

    def test_all_ok_and_missing_file(self):
        f = self.p("ok.tsv")
        sr.append_row(f, "validate", "OK", 0, "ok")
        sr.append_row(f, "build", "NOT_RUN", 4, "build.mode: none")
        self.assertEqual(ps.collect(self.args(f))["pipeline_status"], "OK")
        scan = ps.collect(self.args(self.p("missing.tsv")))                          # 有指定卻讀不到紀錄：GAP，不是 OK
        self.assertEqual((scan["pipeline_status"], scan["pipeline_steps"]), ("GAP", None))

    def test_no_steps_argument_keeps_the_old_output(self):
        a = self.args(None)
        scan = ps.collect(a)
        self.assertNotIn("pipeline_status", scan)
        self.assertNotIn("流程步驟", open(self.p("rel", "notes.md"), encoding="utf-8").read())


class ReleaseMetaAndStatusCheck(Tmp):
    def test_release_meta_result_follows_the_rows(self):
        f = self.p("s.tsv")
        sr.append_row(f, "scan", "GAP", 3, "g")
        out = self.p("m.json")
        r = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "pipeline", "release-meta.py"), "--project", "orin-nano-demo", "--version", "v39.2.1-demo1",
                            "--commit", "a" * 40, "--run-id", "1", "--steps", f, "--out", out], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout)
        d = json.load(open(out))
        self.assertEqual((d["result"], d["steps"][0]["status"]), ("GAP", "GAP"))
        self.assertIn(d["status"], ("shipped", "development"))                       # status 仍是 project.yml 的值
        sr.append_row(f, "assemble", "FAIL", 1, "f")
        subprocess.run([sys.executable, "-I", os.path.join(ROOT, "pipeline", "release-meta.py"), "--project", "orin-nano-demo", "--version", "v39.2.1-demo1",
                        "--commit", "a" * 40, "--run-id", "1", "--steps", f, "--out", out], capture_output=True, text=True)
        self.assertEqual(json.load(open(out))["result"], "FAIL")

    def test_scan_status_check_takes_the_rows_into_account(self):
        st = self.p("status.tsv")
        need = "A B"
        open(st, "w").write("stage\tstatus\tdetail\nA\tOK\tx\nB\tOK\tx\n")
        steps = self.p("steps.tsv")
        sr.append_row(steps, "scan", "OK", 0, "ok")
        chk = os.path.join(ROOT, "pipeline", "scan-status-check.py")
        r = subprocess.run([sys.executable, "-I", chk, st, "A", "B", "--pipeline-steps", steps], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout)
        sr.append_row(steps, "assemble", "GAP", 3, "g")
        r = subprocess.run([sys.executable, "-I", chk, st, "A", "B", "--pipeline-steps", steps], capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        self.assertIn("GAP", r.stdout)
        self.assertEqual(need, "A B")


if __name__ == "__main__":
    unittest.main()
