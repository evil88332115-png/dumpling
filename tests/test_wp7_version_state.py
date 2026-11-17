"""WP7 的 scan（pipeline/platforms/_shared/scan-disk.sh，三個平台的 scan.sh 都 exec 它）的版本核對：
product_version_check 不是 OK → scan 步驟記 GAP（結束碼 3）；FAIL → FAIL（結束碼 1，不降成 GAP）；version-state 執行失敗 → GAP。
從 scan-disk.sh 取出那一段與最後的結束碼那一行，實際用 bash 執行（不只比對原始碼字串；做法同 tests/test_platform_scan.py 的 jetson 測試）。"""
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCAN_DISK = os.path.join(ROOT, "pipeline", "platforms", "_shared", "scan-disk.sh")
JETSON = os.path.join(ROOT, "pipeline", "platforms", "jetson", "scan.sh")
VS_RE = r"^vs=\$\(python3 -I \"\$root/pipeline/lib/platform_scan\.py\" version-state .*?\n^case \$\{vs%%.*?esac"


def read(p):
    with open(p, encoding="utf-8") as fh:
        return fh.read()


class VersionStateInScanDisk(unittest.TestCase):
    def setUp(self):
        src = read(SCAN_DISK)
        self.block = re.search(VS_RE, src, re.M | re.S).group(0)
        self.final = re.search(r"^case \$state in OK\).*?esac", src, re.M).group(0)
        self.src = src
        self.tmp = tempfile.mkdtemp(prefix="dumpling-wp7-vs-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def run_block(self, pvc, state="OK", root=ROOT):
        p = os.path.join(self.tmp, "scan.json")
        if pvc is not None:
            with open(p, "w", encoding="utf-8") as fh:
                json.dump({"product_version_check": pvc}, fh)
        elif os.path.exists(p):
            os.remove(p)
        sh = 'root=%s; out=%s; state=%s; msg=m\n%s\necho "$state|$msg"\n%s\n' % (root, self.tmp, state, self.block, self.final)
        r = subprocess.run(["bash", "-c", sh], capture_output=True, text=True, timeout=60)
        return r.returncode, r.stdout.strip()

    def test_ok_keeps_state(self):
        self.assertEqual(self.run_block({"status": "OK"}), (0, "OK|m"))

    def test_not_ok_is_gap_exit_3(self):
        # 三個平台現在都是這種：沒有和 tag 無關的版本來源（GAP）
        for pvc in ({"status": "GAP", "independent": {"detail": "沒有和 tag 無關的版本來源"}}, {"status": "NOT_SET"}, {"status": "NOT_RUN"}, None):
            rc, out = self.run_block(pvc)
            self.assertEqual(rc, 3, (pvc, out))
            self.assertTrue(out.startswith("GAP|m；"), out)

    def test_fail_is_fail_exit_1_not_downgraded(self):
        rc, out = self.run_block({"status": "FAIL", "failures": ["tag v1 與 os-release 的 v2 不一致"]})
        self.assertEqual((rc, out.split("|")[0]), (1, "FAIL"), out)
        self.assertIn("版本核對 FAIL", out)
        rc, out = self.run_block({"status": "GAP"}, state="FAIL")       # 已經是 FAIL：版本核對的 GAP 不會把它降成 GAP
        self.assertEqual((rc, out.split("|")[0]), (1, "FAIL"), out)

    def test_earlier_gap_stays_gap_when_version_ok(self):
        self.assertEqual(self.run_block({"status": "OK"}, state="GAP")[0], 3)

    def test_version_state_failure_is_gap(self):
        # platform_scan.py 找不到（執行失敗）→ GAP，不是 OK
        rc, out = self.run_block({"status": "OK"}, root=os.path.join(self.tmp, "no-such-root"))
        self.assertEqual(rc, 3, out)
        self.assertIn("version-state 執行失敗", out)

    def test_block_is_the_same_as_jetson(self):
        """照抄 jetson/scan.sh：兩段只差行尾註解。"""
        strip = lambda t: "\n".join(re.sub(r"\s+#.*$", "", l) for l in t.splitlines())
        jet = re.search(VS_RE, read(JETSON), re.M | re.S).group(0)
        self.assertEqual(strip(self.block), strip(jet))

    def test_check_runs_before_summary_and_exit(self):
        """版本核對要在寫 summary.md 與最後一行「scan: …」之前，狀態與說明才會一致。"""
        i = self.src.index(self.block)
        self.assertLess(i, self.src.index('} > "$out/summary.md"'))
        self.assertLess(i, self.src.index('echo "scan: $state'))
        self.assertTrue(self.src.rstrip("\n").splitlines()[-1].startswith("case $state in OK) exit 0;; FAIL) exit 1;;"))

    def test_three_platforms_use_scan_disk(self):
        for plat in ("raspberrypi", "rockchip", "ai-nas"):
            body = read(os.path.join(ROOT, "pipeline", "platforms", plat, "scan.sh"))
            self.assertIn('exec bash "${DUMPLING_ROOT:?}/pipeline/platforms/_shared/scan-disk.sh" "$@"', body, plat)


if __name__ == "__main__":
    unittest.main()
