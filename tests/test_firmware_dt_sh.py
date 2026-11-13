"""pipeline/firmware-dt.sh 的參數處理與流程、firmware_dt.py report 的 NVIDIA vBIOS 說明。不連網、不起 Docker。
流程測試在暫存的假 repo 根（複製 firmware-dt.sh 與 lib，tools/pilot/sca-scan、dt-verify.py、scan-status-check.py 用假的替身），
所以不依賴 C1 的檔案是否已經進這個分支。"""
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("firmware_dt", os.path.join(ROOT, "pipeline", "lib", "firmware_dt.py"))
fd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fd)


def sbom(n=2):
    comps = [{"type": "firmware", "name": "c%d" % i, "version": "1.0", "bom-ref": "r%d" % i,
              "properties": [{"name": "dumpling:vuln-assessment", "value": "NOT_ASSESSED"}]} for i in range(n)]
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": comps}


class Tmp(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.tmp = self._td.name
        self.addCleanup(self._td.cleanup)

    def w(self, rel, text, mode=None):
        p = os.path.join(self.tmp, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(text if isinstance(text, str) else json.dumps(text))
        if mode:
            os.chmod(p, mode)
        return p


class ReportNvidiaTests(Tmp):
    def prep(self, kind, slug):
        yml = self.w("firmware/%s/%s/firmware.yml" % (kind, slug), "kind: %s\nvendor: A\nmodel: M\nstatus: ok\nfirmware_version: 1.0\n" % kind)
        s = self.w("in/%s.json" % slug, sbom())
        o = os.path.join(self.tmp, "prep-" + slug)
        fd.prep(s, yml, o)
        return o

    def fake_root(self, body):
        self.w("fake/tools/pilot/lib/nvidia_bulletins.py", body)
        return os.path.join(self.tmp, "fake")

    def test_text_comes_from_c1_module(self):
        root = self.fake_root('VBIOS_NOT_ASSESSED = "測試用說明文字"\n')
        self.assertEqual(fd.vbios_assessment(root), ("NOT_ASSESSED", "測試用說明文字"))
        o = self.prep("vbios", "v1")
        lines, _ = fd.report([o], None, os.path.join(self.tmp, "rep"), root)
        self.assertIn("NVIDIA 公告對照：NOT_ASSESSED（測試用說明文字）", lines[0])
        with open(os.path.join(self.tmp, "rep", "firmware-dt.md"), encoding="utf-8") as fh:
            self.assertIn("NVIDIA 公告對照：NOT_ASSESSED", fh.read())

    def test_missing_or_broken_module_is_gap(self):
        for body in (None, "def broken(:\n", "X = 1\n", "VBIOS_NOT_ASSESSED = ''\n", "raise RuntimeError('x')\n"):
            root = os.path.join(self.tmp, "empty") if body is None else self.fake_root(body)
            st, text = fd.vbios_assessment(root)
            self.assertEqual(st, "GAP", body)
            self.assertIn("未評估", text)
        o = self.prep("vbios", "v2")
        lines, failed = fd.report([o], None, os.path.join(self.tmp, "rep"), os.path.join(self.tmp, "empty"))
        self.assertIn("NVIDIA 公告對照：GAP", lines[0])
        self.assertFalse(failed)

    def test_only_vbios_gets_the_line(self):
        root = self.fake_root('VBIOS_NOT_ASSESSED = "x"\n')
        lines, _ = fd.report([self.prep("bios", "b1"), self.prep("vbios", "v3"), self.prep("sbom", "s1")], None,
                             os.path.join(self.tmp, "rep"), root)
        self.assertEqual([("NVIDIA 公告對照" in l) for l in lines], [False, True, False])

    def test_real_c1_module_if_present(self):
        if not os.path.isfile(os.path.join(ROOT, "tools/pilot/lib/nvidia_bulletins.py")):
            self.skipTest("C1 的 nvidia_bulletins.py 還沒進這個分支")
        st, text = fd.vbios_assessment()
        self.assertEqual(st, "NOT_ASSESSED")
        self.assertIn("沒有對到公告不代表沒有漏洞", text)


class ScriptTests(Tmp):
    def setUp(self):
        super().setUp()
        self.r = os.path.join(self.tmp, "repo")
        os.makedirs(os.path.join(self.r, "pipeline"))
        shutil.copy(os.path.join(ROOT, "pipeline/firmware-dt.sh"), os.path.join(self.r, "pipeline/firmware-dt.sh"))
        shutil.copytree(os.path.join(ROOT, "pipeline/lib"), os.path.join(self.r, "pipeline/lib"))
        self.sh = os.path.join(self.r, "pipeline/firmware-dt.sh")

    def run_sh(self, *args, env=None):
        e = dict(os.environ, **(env or {}))
        p = subprocess.run(["bash", self.sh, *args], capture_output=True, text=True, env=e)
        return p.returncode, p.stdout, p.stderr

    def sample(self, slug, kind="bios"):
        y = self.w("firmware/%s/%s/firmware.yml" % (kind, slug), "kind: %s\nvendor: A\nmodel: M\nstatus: ok\nfirmware_version: 1.0\n" % kind)
        s = self.w("in/%s.json" % slug, sbom())
        return y, s

    def test_argument_errors_are_64(self):
        w, res = os.path.join(self.tmp, "w"), os.path.join(self.tmp, "res")
        y, s = self.sample("a")
        for args in ([], ["--work", w], ["--work", w, "--result", res],              # 沒有樣本
                     ["--work", w, "--result", res, "--sample", y],                   # --sample 少一個參數
                     ["--work", w, "--result", res, "--bogus"],
                     ["--work"], ["--result", res, "--sample", y, s]):
            rc, _, err = self.run_sh(*args)
            self.assertEqual(rc, 64, args)
            self.assertIn("用法", err)

    def test_without_sca_scan_is_not_run_not_pass(self):
        w, res = os.path.join(self.tmp, "w"), os.path.join(self.tmp, "res")
        y, s = self.sample("a")
        rc, out, _ = self.run_sh("--work", w, "--result", res, "--sample", y, s)
        self.assertEqual(rc, 0)
        self.assertIn("FIRMWARE-DT-STEP\tNOT_RUN\tfirmware-bios-a\t", out)
        self.assertIn("FIRMWARE-DT\tNOT_RUN\t", out)
        self.assertNotIn("PASS", out)
        self.assertTrue(os.path.isfile(os.path.join(res, "report", "firmware-dt.md")))

    def fakes(self, bad_slug=None):
        """假的 sca-scan（寫 status.tsv）、scan-status-check、dt-verify。bad_slug 的專案 dt-verify 失敗。"""
        self.w("repo/tools/pilot/sca-scan", """#!/usr/bin/env bash
while [ $# -gt 0 ]; do case $1 in --out) out=$2; shift 2;; --name) nm=$2; shift 2;; *) shift;; esac; done
echo "$nm" >> "$(dirname "$out")/../scan-names.txt"; mkdir -p "$out/scan"; echo '{"matches": []}' > "$out/scan/grype.json"
printf 'stage\\tstatus\\tdetail\\n' > "$out/status.tsv"
for s in A-source B-sandbox B-sandbox-secrets B-sbom-provided C-grype C-upload-sbom D-dt-project D-dt-upload D-dt-bom-processing D-dt-vuln-analysis F-secret-scan; do printf '%s\\tOK\\tx\\n' "$s" >> "$out/status.tsv"; done
exit 2
""", 0o755)
        self.w("repo/pipeline/scan-status-check.py", "import sys\nprint('上傳: 假的 need=' + ','.join(sys.argv[2:]))\n")
        bad = bad_slug or "@@"
        self.w("repo/pipeline/dt-verify.py", """import json, sys
exp = json.load(open(sys.argv[2])); out = sys.argv[3]
bad = %r in exp['project_name']
json.dump({'components': max(exp['components'], 1), 'findings_total': 0,
           'checks': [{'name': n, 'status': 'FAIL' if bad and n == '元件數' else 'OK'}
                      for n in ('專案存在', '弱點分析完成', '元件數', '漏洞總數', '依生態系的漏洞數')]}, open(out + '/summary.json', 'w'))
sys.exit(1 if bad else 0)
""" % bad)

    def test_flow_one_failure_does_not_stop_others(self):
        self.fakes(bad_slug="bad")
        w, res = os.path.join(self.tmp, "w"), os.path.join(self.tmp, "res")
        y1, s1 = self.sample("good")
        y2, s2 = self.sample("bad")
        y3, s3 = self.sample("also-good", kind="sbom")
        rc, out, _ = self.run_sh("--work", w, "--result", res, "--sample", y1, s1, "--sample", y2, s2, "--sample", y3, s3)
        self.assertEqual(rc, 1, out)
        lines = [l for l in out.splitlines() if l.startswith("FIRMWARE-DT\t")]
        self.assertEqual(len(lines), 3)
        by = {l.split("\t")[2].split("@")[0].split("DT 專案 ")[-1]: l.split("\t")[1] for l in lines}
        self.assertEqual(by["firmware-bios-good"], "ATTENTION")
        self.assertEqual(by["firmware-bios-bad"], "FAIL")
        self.assertEqual(by["firmware-sbom-also-good"], "ATTENTION")
        self.assertIn("FIRMWARE-DT-STEP\tFAIL\tfirmware-bios-bad\tdt-verify 結束碼 1", out)
        # 三個樣本都有被掃描，必要階段清單有帶到 scan-status-check，且不含 C-sbomgate
        with open(os.path.join(res, "scan-names.txt")) as fh:
            self.assertEqual(len(fh.read().split()), 3)
        self.assertIn("need=A-source,B-sandbox,B-sandbox-secrets,B-sbom-provided,C-grype,C-upload-sbom,"
                      "D-dt-project,D-dt-upload,D-dt-bom-processing,D-dt-vuln-analysis,F-secret-scan", out)
        self.assertNotIn("C-sbomgate", out)

    def test_all_good_exit_0_and_wait_rc_3_is_gap(self):
        self.fakes()
        w, res = os.path.join(self.tmp, "w"), os.path.join(self.tmp, "res")
        y, s = self.sample("good")
        self.w("res/dt-wait.rc", "3\n")
        rc, out, _ = self.run_sh("--work", w, "--result", res, "--sample", y, s)
        self.assertEqual(rc, 0, out)
        self.assertIn("FIRMWARE-DT\tGAP\t", out)

    def test_wait_rc_other_than_zero_is_gap_and_garbage_is_fail(self):
        for v, want in (("124\n", "GAP"), ("1\n", "GAP"), ("0\n", None)):
            self.fakes()
            w, res = os.path.join(self.tmp, "w" + v.strip()), os.path.join(self.tmp, "res" + v.strip())
            y, s = self.sample("good" + v.strip())
            self.w(os.path.join("res" + v.strip(), "dt-wait.rc"), v)
            rc, out, _ = self.run_sh("--work", w, "--result", res, "--sample", y, s)
            self.assertEqual(rc, 0, out)
            if want:
                self.assertIn("FIRMWARE-DT\t%s\t" % want, out, v)
            else:
                self.assertNotIn("FIRMWARE-DT\tGAP\t", out, v)
        self.fakes()
        w, res = os.path.join(self.tmp, "wg"), os.path.join(self.tmp, "resg")
        y, s = self.sample("goodg")
        self.w("resg/dt-wait.rc", "+0\n")
        rc, out, _ = self.run_sh("--work", w, "--result", res, "--sample", y, s)
        self.assertEqual(rc, 1, out)
        self.assertNotIn("FIRMWARE-DT\tOK", out)

    def test_supplier_sbom_normalization_record_goes_to_result_dir(self):
        self.fakes()
        w, res = os.path.join(self.tmp, "w"), os.path.join(self.tmp, "res")
        y, _ = self.sample("sup", kind="sbom")
        doc = sbom()
        doc["specVersion"] = "1.4"
        doc["platform"] = "Notebook X"
        s = self.w("in/sup.json", doc)
        rc, out, _ = self.run_sh("--work", w, "--result", res, "--sample", y, s)
        self.assertEqual(rc, 0, out)
        self.assertIn("已正規化 1 處（見 normalize.json", out)
        with open(os.path.join(res, "firmware-sbom-sup", "normalize.json"), encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["changes"][0]["from"], "/platform")
        # BIOS 樣本（本工具自己產的 SBOM）沒有這個檔
        y2, s2 = self.sample("bios1")
        self.assertEqual(self.run_sh("--work", w, "--result", res, "--sample", y2, s2)[0], 0)
        self.assertFalse(os.path.exists(os.path.join(res, "firmware-bios-bios1", "normalize.json")))

    def test_old_results_are_not_mixed(self):
        self.fakes()
        w, res = os.path.join(self.tmp, "w"), os.path.join(self.tmp, "res")
        y, s = self.sample("good")
        self.assertEqual(self.run_sh("--work", w, "--result", res, "--sample", y, s)[0], 0)
        rc, out, _ = self.run_sh("--work", w, "--result", res, "--sample", y, s)       # 同一個 --result 再跑一次
        self.assertEqual(rc, 1)
        self.assertIn("FIRMWARE-DT-STEP\tFAIL\tfirmware-bios-good\t結果資料夾已有舊結果", out)

    def test_declared_rejected_sample_does_not_fail_the_script_only_when_report_agrees(self):
        """假 sca-scan 對宣告 expected_dt 的樣本回 D-dt-upload FAIL（http=400）、結束碼 1，dt-verify 的兩項失敗。"""
        self.fakes()
        self.w("repo/tools/pilot/sca-scan", """#!/usr/bin/env bash
while [ $# -gt 0 ]; do case $1 in --out) out=$2; shift 2;; *) shift;; esac; done
mkdir -p "$out/scan"; echo '{"matches": []}' > "$out/scan/grype.json"
{ printf 'stage\\tstatus\\tdetail\\n'
  for s in A-source B-sandbox B-sandbox-secrets B-sbom-provided C-grype C-upload-sbom D-dt-project F-secret-scan; do printf '%s\\tOK\\tx\\n' $s; done
  printf 'D-dt-upload\\tFAIL\\thttp=400 {"status":400,"title":"The uploaded BOM is invalid","detail":"Schema validation failed","errors":[]}\\nD-dt-bom-processing\\tNOT_RUN\\tx\\nD-dt-vuln-analysis\\tNOT_RUN\\tx\\n'; } > "$out/status.tsv"
exit 1
""", 0o755)
        self.w("repo/pipeline/scan-status-check.py", "import sys\nprint('必要階段不是 OK')\nsys.exit(1)\n")
        self.w("repo/pipeline/dt-verify.py", """import json, sys
json.dump({'components': 0, 'findings_total': 0, 'checks': [
  {'name': '專案存在', 'status': 'OK'}, {'name': '弱點分析完成', 'status': 'FAIL'}, {'name': '元件數', 'status': 'FAIL'}]},
  open(sys.argv[3] + '/summary.json', 'w'))
sys.exit(1)
""")
        y = self.w("firmware/sbom/sup/firmware.yml", "kind: sbom\nvendor: A\nmodel: M\nstatus: ok\nfirmware_version: 1.0\n"
                   "expected_dt:\n  upload: rejected\n  reason: 供應商 SBOM 不符 schema\n")
        s = self.w("in/sup.json", sbom())
        rc, out, _ = self.run_sh("--work", os.path.join(self.tmp, "w"), "--result", os.path.join(self.tmp, "res"), "--sample", y, s)
        self.assertEqual(rc, 0, out)
        self.assertIn("FIRMWARE-DT-STEP\tEXPECTED\tfirmware-sbom-sup\t", out)
        self.assertIn("FIRMWARE-DT\tFAIL\t", out)
        self.assertIn("與 firmware.yml 宣告的 expected_dt 一致", out)
        # 同一份結果但沒有宣告：同樣的 SBOM 與假工具，腳本要失敗
        y2 = self.w("firmware/sbom/sup2/firmware.yml", "kind: sbom\nvendor: A\nmodel: M\nstatus: ok\nfirmware_version: 1.0\n")
        s2 = self.w("in/sup2.json", sbom())
        rc, out, _ = self.run_sh("--work", os.path.join(self.tmp, "w2"), "--result", os.path.join(self.tmp, "res2"), "--sample", y2, s2)
        self.assertEqual(rc, 1, out)
        self.assertIn("FIRMWARE-DT-STEP\tFAIL\tfirmware-sbom-sup2\t", out)

    def test_prep_failure_is_fail_but_others_continue(self):
        self.fakes()
        w, res = os.path.join(self.tmp, "w"), os.path.join(self.tmp, "res")
        y, s = self.sample("good")
        y2 = self.w("firmware/bios/broken/firmware.yml", "kind: bios\n")
        s2 = self.w("in/broken.json", "{not json")
        rc, out, _ = self.run_sh("--work", w, "--result", res, "--sample", y2, s2, "--sample", y, s)
        self.assertEqual(rc, 1)
        self.assertIn("FIRMWARE-DT-STEP\tFAIL\tbroken\t", out)
        self.assertIn("FIRMWARE-DT\tATTENTION\t", out)

    def test_synthetic_vbios_option(self):
        self.fakes()
        for rel in ("tools/cra/tests/synthetic_vbios.py", "pipeline/firmware-bios.sh", "tools/cra/x86_firmware.py"):
            os.makedirs(os.path.dirname(os.path.join(self.r, rel)), exist_ok=True)
            shutil.copy(os.path.join(ROOT, rel), os.path.join(self.r, rel))
        for extra in os.listdir(os.path.join(ROOT, "tools/cra")):   # x86_firmware.py 若 import 同資料夾的模組
            src = os.path.join(ROOT, "tools/cra", extra)
            if extra.endswith(".py") and not os.path.exists(os.path.join(self.r, "tools/cra", extra)):
                shutil.copy(src, os.path.join(self.r, "tools/cra", extra))
        y = self.w("firmware/vbios/standalone-nvidia-option-rom/firmware.yml", "kind: vbios\nvendor: NVIDIA\nmodel: M\nstatus: GAP\n")
        w, res = os.path.join(self.tmp, "w"), os.path.join(self.tmp, "res")
        rc, out, _ = self.run_sh("--work", w, "--result", res, "--synthetic-vbios", y)
        self.assertIn("FIRMWARE-DT\tATTENTION\t", out)
        self.assertIn("firmware-vbios-synthetic-standalone-nvidia-option-rom@", out)
        self.assertIn("NVIDIA 公告對照：GAP", out)       # 假 repo 沒有 C1 的 nvidia_bulletins.py


if __name__ == "__main__":
    unittest.main()
