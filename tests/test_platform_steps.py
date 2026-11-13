"""workflow 步驟的結果紀錄：pipeline/run-step.sh（結束碼規則）、step_rows、collect／release-meta／scan-status-check 對 GAP 與 FAIL 的處理。不連網。"""
import argparse
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
import platform_scan as ps  # noqa: E402
import step_rows as sr  # noqa: E402

RUN_STEP = os.path.join(ROOT, "pipeline", "run-step.sh")
MIRRORS_SH = os.path.join(ROOT, "pipeline", "lib", "mirrors.sh")


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


class AttentionStatus(Tmp):
    """ATTENTION：用了舊資料頂替（例如核心 CVE 鏡像上游連不上）。整體狀態不是 OK，但比 GAP 輕，也不是 FAIL。"""

    def test_overall_ranking(self):
        f = self.p("s.tsv")
        sr.append_row(f, "scan", "OK", 0, "ok")
        sr.append_row(f, "kernel-cve-mirror", "ATTENTION", 0, "ATTENTION mirror=/x 上游連不上")
        rows = sr.read_rows(f)
        self.assertEqual(sr.overall(rows), "ATTENTION")
        self.assertEqual(sr.attention_lines(rows), ["ATTENTION mirror=/x 上游連不上"])
        sr.append_row(f, "assemble", "GAP", 3, "g")
        self.assertEqual(sr.overall(sr.read_rows(f)), "GAP")                         # GAP 蓋過 ATTENTION
        sr.append_row(f, "build", "FAIL", 1, "f")
        self.assertEqual(sr.overall(sr.read_rows(f)), "FAIL")

    def test_collect_shows_attention_in_notes_and_summary(self):
        f = self.p("steps.tsv")
        sr.append_row(f, "validate", "OK", 0, "validate: OK")
        line = "ATTENTION mirror=/m/kcve 上游連不上…沿用 vulns.git abc123（提交時間 2026-11-12，下載於 2026-11-12T01:00:00Z，5 小時前）"
        sr.append_row(f, "kernel-cve-mirror", "ATTENTION", 0, line)
        helper = CollectShowsSteps(methodName="test_all_ok_and_missing_file")
        helper.tmp = self.tmp
        scan = ps.collect(helper.args(f))
        self.assertEqual(scan["pipeline_status"], "ATTENTION")
        self.assertEqual(scan["pipeline_attention"], [line])
        notes = open(self.p("rel", "notes.md"), encoding="utf-8").read()
        self.assertIn("**ATTENTION（用了舊資料頂替", notes)
        self.assertIn("> - " + line, notes)                                           # 那一行原文放在說明的最前面
        self.assertLess(notes.index("ATTENTION（用了舊資料頂替"), notes.index("## 元件與分層"))
        self.assertIn("整體狀態 **ATTENTION**", notes)
        self.assertIn("| pipeline-kernel-cve-mirror | ATTENTION | 0 |", notes)
        md = open(self.p("steps.md"), encoding="utf-8").read()
        self.assertIn("**ATTENTION**：" + line, md)
        self.assertIn("整體狀態 ATTENTION", md)

    def test_no_attention_keeps_notes_unchanged(self):
        f = self.p("ok.tsv")
        sr.append_row(f, "validate", "OK", 0, "ok")
        helper = CollectShowsSteps(methodName="test_all_ok_and_missing_file")
        helper.tmp = self.tmp
        scan = ps.collect(helper.args(f))
        self.assertEqual(scan["pipeline_attention"], [])
        self.assertNotIn("ATTENTION", open(self.p("rel", "notes.md"), encoding="utf-8").read())

    def test_release_meta_and_status_check(self):
        f = self.p("s.tsv")
        sr.append_row(f, "scan", "OK", 0, "ok")
        sr.append_row(f, "kernel-cve-mirror", "ATTENTION", 0, "ATTENTION mirror=/x 上游連不上")
        out = self.p("m.json")
        r = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "pipeline", "release-meta.py"), "--project", "orin-nano-demo", "--version", "v39.2.1-demo1",
                            "--commit", "a" * 40, "--run-id", "1", "--steps", f, "--out", out], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout)
        d = json.load(open(out))
        self.assertEqual((d["result"], d["attention"]), ("ATTENTION", ["ATTENTION mirror=/x 上游連不上"]))
        self.assertEqual([x["status"] for x in d["steps"]], ["OK", "ATTENTION"])
        st = self.p("status.tsv")
        open(st, "w").write("stage\tstatus\tdetail\nA\tOK\tx\n")
        r = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "pipeline", "scan-status-check.py"), st, "A", "--pipeline-steps", f], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout)                                  # ATTENTION 不擋上傳檢查

    def test_release_meta_without_attention_has_no_field(self):
        f = self.p("s.tsv")
        sr.append_row(f, "scan", "OK", 0, "ok")
        out = self.p("m.json")
        subprocess.run([sys.executable, "-I", os.path.join(ROOT, "pipeline", "release-meta.py"), "--project", "orin-nano-demo", "--version", "v39.2.1-demo1",
                        "--commit", "a" * 40, "--run-id", "1", "--steps", f, "--out", out], capture_output=True, text=True)
        d = json.load(open(out))
        self.assertEqual(d["result"], "OK")
        self.assertNotIn("attention", d)


class MirrorsLib(Tmp):
    """pipeline/lib/mirrors.sh：看腳本最後一行（OK／ATTENTION／其他）。"""

    def setUp(self):
        super().setUp()
        self.sd = self.p("mirror-scripts")
        os.makedirs(self.sd)
        self.mir = self.p("mirrors")
        self.steps = self.p("pipeline-steps.tsv")

    def script(self, name, body):
        with open(os.path.join(self.sd, name), "w", encoding="utf-8") as f:
            f.write("#!/usr/bin/env bash\ndest=$1; man=$2\n" + body)

    def run_fn(self, call, **env):
        e = dict(os.environ, MIRRORS_DIR=self.mir, MIRRORS_STEPS=self.steps, MIRRORS_SCRIPT_DIR=self.sd, MIRRORS_RETRY_DELAY="0")
        e.pop("KCVE_CACHE_DIR", None)
        e.update(env)
        return subprocess.run(["bash", "-c", '. "%s"; %s' % (MIRRORS_SH, call)], capture_output=True, text=True, env=e)

    def test_ok_line_is_success_and_adds_no_row(self):
        self.script("a.sh", 'mkdir -p "$dest"; echo hello > "$dest/f"; echo "OK mirror=$dest manifest=$man"\n')
        r = self.run_fn("mirror a.sh aa")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("鏡像 aa：OK", r.stdout)
        self.assertTrue(open(os.path.join(self.mir, "aa.result")).read().startswith("OK "))
        self.assertFalse(os.path.exists(self.steps))

    def test_attention_line_is_success_remembered_and_recorded(self):
        line = "ATTENTION mirror=$dest 上游連不上…沿用 vulns.git abc（提交時間 t，下載於 d，5 小時前）"
        self.script("kernel-cve.sh", 'mkdir -p "$dest"; printf "fallback=yes\\n" > "$dest/SOURCE"; echo "%s"\n' % line)
        r = self.run_fn("mirror kernel-cve.sh kcve")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("鏡像 kcve：ATTENTION", r.stdout)
        rows = sr.read_rows(self.steps)
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["step"], rows[0]["status"], rows[0]["exit"]), ("pipeline-kernel-cve-mirror", "ATTENTION", 0))
        self.assertIn("上游連不上…沿用 vulns.git abc", rows[0]["detail"])
        self.assertTrue(rows[0]["detail"].startswith("ATTENTION mirror="))             # 那一行的原文
        self.assertEqual(sr.overall(rows), "ATTENTION")
        self.assertTrue(open(os.path.join(self.mir, "kcve.result")).read().startswith("ATTENTION "))

    def test_long_attention_line_is_kept_whole(self):
        tail = "：這段時間新增的核心 CVE 不在清單裡"
        self.script("kernel-cve.sh", 'mkdir -p "$dest"; echo "ATTENTION mirror=$dest manifest=$man %s%s"\n' % ("上游連不上" * 40, tail))
        r = self.run_fn("mirror kernel-cve.sh kcve")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(sr.read_rows(self.steps)[0]["detail"].endswith(tail))

    def test_failure_and_unknown_last_line_are_fail(self):
        self.script("bad.sh", 'echo "FAIL 連不上" >&2; exit 1\n')
        self.script("odd.sh", 'mkdir -p "$dest"; echo "done"\n')                       # 結束碼 0，但最後一行不是 OK／ATTENTION
        for name in ("bad.sh", "odd.sh"):
            r = self.run_fn("mirror %s x; echo rc=$?" % name, MIRRORS_TRIES="2")
            self.assertIn("rc=1", r.stdout, name)
            self.assertNotIn("鏡像 x：OK", r.stdout)
        self.assertFalse(os.path.exists(self.steps))                                  # 失敗不記 ATTENTION

    def test_retries_then_ok(self):
        self.script("flaky.sh", 'c="%s/count"; n=$(cat "$c" 2>/dev/null || echo 0); echo $((n+1)) > "$c"\n'
                                '[ "$n" -ge 1 ] || { echo "timeout" >&2; exit 1; }\nmkdir -p "$dest"; echo "OK mirror=$dest"\n' % self.tmp)
        r = self.run_fn("mirror flaky.sh f")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("第 1 次失敗", r.stdout)
        self.assertIn("鏡像 f：OK", r.stdout)

    def test_kernel_cve_passes_the_previous_mirror_only_when_it_exists(self):
        self.script("kernel-cve.sh", 'mkdir -p "$dest"; echo "reuse=${KERNEL_CVE_REUSE_FROM:-} fallback=${KERNEL_CVE_FALLBACK_FROM:-}" > "$dest/env"\necho "OK mirror=$dest"\n')
        r = self.run_fn("mirror_kernel_cve kcve")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(open(os.path.join(self.mir, "kcve", "env")).read().strip(), "reuse= fallback=")
        cache = self.p("cache", "kcve")
        os.makedirs(cache)
        r = self.run_fn("mirror_kernel_cve kcve", KCVE_CACHE_DIR=cache)                # 資料夾在但沒有 SOURCE：不傳
        self.assertEqual(open(os.path.join(self.mir, "kcve", "env")).read().strip(), "reuse= fallback=")
        open(os.path.join(cache, "SOURCE"), "w").write("commit=abc\n")
        r = self.run_fn("mirror_kernel_cve kcve", KCVE_CACHE_DIR=cache)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(open(os.path.join(self.mir, "kcve", "env")).read().strip(), "reuse=%s fallback=%s" % (cache, cache))

    def test_only_fresh_data_may_be_saved_to_the_cache(self):
        self.script("kernel-cve.sh", 'mkdir -p "$dest"; printf "%s\\n" "$SRC" > "$dest/SOURCE"; echo "$LINE"\n')
        cases = (("OK mirror=x", "commit=abc\nfetched_utc=2026-11-12T00:00:00Z", True),
                 ("OK mirror=x", "commit=abc\nfallback=yes\nfallback_note=上游連不上", False),     # 腳本說 OK 但 SOURCE 標了頂替：不存
                 ("ATTENTION mirror=x 上游連不上", "commit=abc\nfallback=yes", False))
        for line, src, want in cases:
            r = self.run_fn("mirror kernel-cve.sh kcve && mirror_is_fresh kcve; echo fresh=$?", LINE=line, SRC=src.replace("\\n", "\n"))
            self.assertIn("fresh=0" if want else "fresh=1", r.stdout, (line, r.stdout, r.stderr))
        r = self.run_fn("mirror_is_fresh nothing; echo fresh=$?")
        self.assertIn("fresh=1", r.stdout)

    def test_scan_sh_and_workflow_use_the_shared_function(self):
        scan = open(os.path.join(ROOT, "pipeline", "platforms", "jetson", "scan.sh"), encoding="utf-8").read()
        self.assertNotIn("mirror() {", scan)                                          # 函式只有 pipeline/lib/mirrors.sh 一份
        self.assertIn("pipeline/lib/mirrors.sh", scan)
        wf = open(os.path.join(ROOT, ".github", "workflows", "pipeline.yml"), encoding="utf-8").read()
        uses = re.findall(r"uses:\s*(actions/cache/(?:restore|save))@(\S+)", wf)
        self.assertEqual(sorted(u for u, _ in uses), ["actions/cache/restore", "actions/cache/save"])
        for _, ref in uses:
            self.assertRegex(ref, r"^[0-9a-f]{40}$")                                  # 第三方 action 釘 commit SHA
        self.assertIn("restore-keys: kernel-cve-mirror-", wf)
        save = wf[wf.index("actions/cache/save@"):]
        self.assertIn("steps.kcve-fresh.outputs.fresh == 'true'", wf[wf.rindex("- name:", 0, wf.index("actions/cache/save@")):])
        self.assertIn("kernel-cve-mirror-${{ github.run_id }}-${{ github.run_attempt }}", save)


if __name__ == "__main__":
    unittest.main()
