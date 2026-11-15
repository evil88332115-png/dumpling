"""單顆核心、一個核心元件（Jetson 形狀）的輸出基準（M7d-1）：逐顆判定與核心列去重不可以改變這種輸入的輸出，逐位元組相同。

data/kernel_single_baseline/ 的檔案是用 M7d-1 之前的程式（main 4f64db7）對同一份合成輸入產生的：vulnerability-rows.json、vex.cdx.json、
vex.openvex.json、kernel-vulnerabilities.md、summary.json（時間與暫存路徑換成固定的佔位字）。這個測試用目前的程式再產生一次、逐位元組比對。
輸入：Jetson 型的核心 CVE（一個核心元件 linux-nvidia-tegra、一顆核心）、kernel-config.json（K1 排除與 affected）、kernel-module-map.json、
kernel-versions.json（舊的 schema /2，讀取端要照舊讀）。

重新產生基準（只在行為有意改變、而且評估過 Jetson 不受影響時）：
  KERNEL_BASELINE_CRA_DIR=<改前的 tools/cra 資料夾> KERNEL_BASELINE_WRITE=1 pytest tools/cra -k kernel_single_baseline
另外 KERNEL_BASELINE_CRA_DIR 單獨給（不寫檔）時，改成「改前的程式」對「目前的程式」逐位元組比對（開發時用 git worktree add 開一份改前的程式碼）。
"""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
from test_cra_report import KFINDINGS, KGRYPE, KMAP, kernel_scan, make_project, write_json  # noqa: E402
from test_vex_export import kcfg  # noqa: E402

DATA = HERE / "data" / "kernel_single_baseline"
FILES = ("vulnerability-rows.json", "vex.cdx.json", "vex.openvex.json", "kernel-vulnerabilities.md", "summary.json", "risk-assessment.md")
A = "6.8.12-1021-tegra"


def build_scan(tmp):
    scan = kernel_scan(tmp / "s")
    write_json(scan / "scan" / "kernel-config.json", kcfg([
        {"cve": "CVE-2025-0102", "decision": "not_affected", "detail": "CONFIG_X is not set", "files": [{"path": "drivers/x.c", "built": False}]},
        {"cve": "CVE-2025-0103", "decision": "affected", "detail": "built", "files": [{"path": "net/y.c", "built": True, "built_as": "builtin"}]},
        {"cve": "CVE-2025-0104", "decision": "unknown", "detail": "unclear"}]))
    write_json(scan / "scan" / "kernel-module-map.json", {
        "schema": "sca-center-kernel-module-map/1", "status": "OK", "kernel": {"version": A},
        "component": kcfg([])["component"], "cves": {"CVE-2025-0103": {"modules": [], "builtin": True}},
        "modules_order": [], "modules_builtin": []})
    write_json(scan / "scan" / "kernel-versions.json", {
        "schema": "sca-center-kernel-versions/2", "shipped": [{"version": A, "upstream_version": None, "upstream_basis": None, "upstream_note": "x"}],
        "requested": [], "judged": [A], "not_judged": [], "note": "x"})
    return scan


def run_cli(cra_dir, project, scan):
    env = dict(os.environ, CRA_COMPANY_CONFIG="none")
    p = subprocess.run([sys.executable, "-I", str(Path(cra_dir) / "cra_report.py"), "--project", str(project), "--scan", str(scan)],
                       capture_output=True, text=True, timeout=120, env=env)
    assert p.returncode in (0, 2), p.stdout + p.stderr
    return project / "CRA" / "Reports"


def normalized(reports, tmp):
    out = {}
    for name in FILES:
        t = (reports / name).read_text(encoding="utf-8")
        t = t.replace(str(tmp), "<TMP>")
        t = re.sub(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z", "<TIME>", t)
        t = re.sub(r"urn:uuid:[0-9a-f-]{36}", "urn:uuid:<UUID>", t)
        # 產生出來的檔案（產品 SBOM、VEX…）含產生時間或由內容算出的序號，它們的雜湊（summary.json 的 sha256）每次不同：不比雜湊
        # （檔案本身的內容在這個測試裡逐位元組比；輸入檔的雜湊由輸入決定，和程式無關）
        if name == "summary.json":
            t = re.sub(r'("sha256": ")[0-9a-f]{64}', r"\1<SHA>", t)
        if name == "risk-assessment.md":                  # 風險評估列出 VEX 檔案的雜湊（前 12 碼）
            t = re.sub(r"SHA-256 [0-9a-f]{12}\)", "SHA-256 <SHA12>)", t)
        out[name] = t
    return out


def current(tmp_path):
    scan = build_scan(tmp_path)
    return normalized(run_cli(HERE.parent, make_project(tmp_path / "p"), scan), tmp_path)


def test_single_kernel_output_matches_the_committed_baseline(tmp_path):
    base = os.environ.get("KERNEL_BASELINE_CRA_DIR")
    got = current(tmp_path)
    if base and os.environ.get("KERNEL_BASELINE_WRITE") == "1":
        other = tmp_path / "base"
        other.mkdir()
        want = normalized(run_cli(base, make_project(other / "p"), build_scan(other)), other)
        DATA.mkdir(parents=True, exist_ok=True)
        for k, v in want.items():
            (DATA / k).write_text(v, encoding="utf-8")
    if base and os.environ.get("KERNEL_BASELINE_WRITE") != "1":
        other = tmp_path / "base"
        other.mkdir()
        want = normalized(run_cli(base, make_project(other / "p"), build_scan(other)), other)
        assert got == want
    for name in FILES:
        assert got[name] == (DATA / name).read_text(encoding="utf-8"), name


def test_baseline_input_is_the_jetson_shape(tmp_path):
    """基準的輸入真的是「一個核心元件、一顆核心」：6 個不同 CVE、1 個核心元件，沒有重複，K1 的排除、affected、unknown 都在。"""
    scan = build_scan(tmp_path)
    rows = json.loads((run_cli(HERE.parent, make_project(tmp_path / "p"), scan) / "vulnerability-rows.json").read_text(encoding="utf-8"))["rows"]
    kernel = [r for r in rows if r["is_kernel"]]
    assert len(kernel) == len({r["id"] for r in kernel}) == 8 and {r["component"] for r in kernel} == {"linux-nvidia-tegra"}
    assert all("kernel_packages" not in r and "kernel_results" not in r for r in kernel)
    assert {r["id"]: (r["vex"] or {}).get("state") for r in kernel}["CVE-2025-0102"] == "not_affected"
    assert len(KFINDINGS) > 0 and KGRYPE and KMAP
