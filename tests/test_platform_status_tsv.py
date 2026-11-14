"""status.tsv 同一階段多列的統一讀法（M7b）：pipeline/lib/status_tsv.py 與 tools/cra/cra_report.py 的 read_status 結果相同；
scan-status-check.py、platform_scan.read_status_tsv 用的是同一份 status_tsv。不連網。"""
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(ROOT, "pipeline", "lib"))
import status_tsv  # noqa: E402
import platform_scan  # noqa: E402

CASES = {
    "fail_then_ok": ("A\tFAIL\tx\nA\tOK\ty\n", {"A": ("FAIL", "x")}, {"A": 2}),
    "ok_then_gap": ("A\tOK\tx\nA\tGAP\ty\n", {"A": ("GAP", "y")}, {"A": 2}),
    "ok_twice": ("A\tOK\tx\nA\tOK\ty\n", {"A": ("ATTENTION", None)}, {"A": 2}),
    "unknown_beats_ok": ("A\tOK\tx\nA\tWEIRD\ty\n", {"A": ("WEIRD", "y")}, {"A": 2}),
    "not_run_vs_attention": ("A\tNOT_RUN\tx\nA\tATTENTION\ty\n", {"A": ("NOT_RUN", "x")}, {"A": 2}),
    "two_columns_kept": ("B\tFAIL\n", {"B": ("FAIL", "")}, {}),
    "single": ("C\tOK\tz\n", {"C": ("OK", "z")}, {}),
}


def load_cra():
    spec = importlib.util.spec_from_file_location("cra_report_for_status", os.path.join(ROOT, "tools", "cra", "cra_report.py"))
    m = importlib.util.module_from_spec(spec)
    sys.path.insert(0, os.path.join(ROOT, "tools", "cra"))
    spec.loader.exec_module(m)
    return m


class StatusTsv(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cra = load_cra()
        cls.tmp = tempfile.mkdtemp(prefix="dumpling-status-")

    def write(self, name, body):
        p = os.path.join(self.tmp, name + ".tsv")
        with open(p, "w", encoding="utf-8") as f:
            f.write("stage\tstatus\tdetail\n" + body)
        return p

    def test_rules_and_both_implementations_agree(self):
        for name, (body, want, dups) in CASES.items():
            p = self.write(name, body)
            rows, d = status_tsv.read(p)
            self.assertEqual(d, dups, name)
            for k, (st, detail) in want.items():
                self.assertEqual(rows[k][0], st, name)
                if detail is not None:
                    self.assertEqual(rows[k][1], detail, name)
            if name == "ok_twice":
                self.assertIn("status.tsv 有 2 列 A", rows["A"][1])
            self.assertEqual(self.cra.read_status(Path(p)), rows, name)                # cra_report 另寫的一份要一樣
            self.assertEqual({k: (v["status"], v["detail"]) for k, v in platform_scan.read_status_tsv(p).items()}, rows, name)
        self.assertEqual(self.cra.STATUS_SEVERITY, status_tsv.SEVERITY)

    def test_scan_flash_package_carry_pick_agrees(self):
        """scan-flash-package.sh 的 carry_row 挑列（PICK 那段，第四份實作）和 status_tsv 結果相同（#95 C0 驗證）。"""
        import re
        src = open(os.path.join(ROOT, "tools", "demo", "scan-flash-package.sh"), encoding="utf-8").read()
        pick = re.search(r"<<'PICK'\n(.*?)\nPICK\n", src, re.S).group(1)
        for name, (body, want, dups) in CASES.items():
            p = self.write("carry-" + name, body)
            rows, _ = status_tsv.read(p)
            for stage in set(rows) | {"NOPE"}:
                r = subprocess.run([sys.executable, "-I", "-c", pick, p, stage], capture_output=True, text=True, check=True)
                got = tuple(r.stdout.rstrip("\n").split("\t", 1)) if r.stdout else None
                self.assertEqual(got, rows.get(stage), (name, stage))

    def test_missing_file(self):
        self.assertEqual(status_tsv.read(os.path.join(self.tmp, "nope.tsv")), ({}, {}))
        self.assertEqual(platform_scan.read_status_tsv(os.path.join(self.tmp, "nope.tsv")), {})

    def test_scan_status_check_uses_worst_row(self):
        """必要階段前面 FAIL、後面 OK：原本後值蓋前值會通過，現在不通過，並列出重複列。"""
        p = self.write("check", "A-source\tFAIL\tx\nA-source\tOK\ty\n")
        r = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "pipeline", "scan-status-check.py"), p, "A-source"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("A-source=FAIL", r.stdout)
        self.assertIn("重複列：A-source×2", r.stdout)
        p = self.write("check2", "A-source\tOK\tx\nA-source\tOK\ty\n")
        r = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "pipeline", "scan-status-check.py"), p, "A-source"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 1, r.stdout)                                    # OK 兩列 → ATTENTION，不算 OK
        p = self.write("check3", "A-source\tOK\tx\n")
        r = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "pipeline", "scan-status-check.py"), p, "A-source"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout)


if __name__ == "__main__":
    unittest.main()
