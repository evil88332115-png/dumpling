"""--kernel-in-other-report／SCA_KERNEL_IN_OTHER_REPORT（sca-scan）：分層時，沒有核心的那一層（-os）不跑核心階段。

sca-scan 的 kernelcheck 區段與核心區段從原文抽出來在 bash 裡真的執行（kernelcheck.py 是真的）；判定工具與 CNA 版本比對是假的，記下有沒有被呼叫。
映像是合成的 rootfs tar；SBOM 是合成的最小 CycloneDX。
"""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(__file__))
import test_kernel_config as tkc  # noqa: E402
import test_kernel_versions as tkv  # noqa: E402

PILOT, SRC, SCAN = tkv.PILOT, tkv.SRC, tkv.SCAN
A, B = tkv.A, tkv.B
OTHER = "demo-bsp"
STAGES = ("C-kernel-cve-list", "C-kernel-config", "C-kernel-module-map")

FAKE_CNA = """#!/usr/bin/env python3
import os, sys
open(os.environ["FAKE_LOG"], "a").write("kernel_cna_version.py " + " ".join(sys.argv[1:]) + "\\n")
sys.exit(1)
"""

NO_KERNEL_SBOM = {"components": [{"type": "library", "name": "openssl", "version": "3.0.13", "purl": "pkg:deb/ubuntu/openssl@3.0.13?distro=ubuntu-24.04",
                                  "properties": [{"name": "syft:package:type", "value": "deb"}]}]}
KERNEL_SBOM = {"components": [{"type": "library", "name": "linux-kernel", "version": A, "purl": f"pkg:generic/linux-kernel@{A}",
                               "cpe": f"cpe:2.3:o:linux:linux_kernel:{A}:*:*:*:*:*:*:*",
                               "properties": [{"name": "syft:package:type", "value": "linux-kernel"}]}]}


def block(start, end):
    i = SRC.index(start)
    return SRC[i:SRC.index(end, i)]


KC_BLOCK = block("KNONE=0 ", "# NVIDIA 安全公告")
K_BLOCK = tkv.block_text()


def layer_run(tmp_path, sbom, members, kother="", knotdistro="", kvers=()):
    root = tmp_path / "root"
    lib = root / "tools" / "pilot" / "lib"
    lib.mkdir(parents=True)
    for n in ("kernel_config.py", "kernel_module_map.py"):
        (lib / n).write_text(tkv.FAKE_TOOL)
    (lib / "kernel_cna_version.py").write_text(FAKE_CNA)
    for n in ("kernel_versions.py", "kernelcheck.py"):
        (lib / n).symlink_to(PILOT / "lib" / n)
    (lib / "data").symlink_to(PILOT / "lib" / "data")
    out = tmp_path / "out"
    (out / "scan").mkdir(parents=True)
    (out / "sbom").mkdir()
    (out / "dt").mkdir()
    (out / "sbom" / "sbom.cdx.json").write_text(json.dumps(sbom))
    gr = out / "scan" / "grype.json"
    gr.write_text('{"matches": []}')
    src = tkc.write_tar(tmp_path / "r.tar", members)
    log = tmp_path / "fake.log"
    kv = " ".join(f"'{v}'" for v in kvers)
    script = f"""set -uo pipefail
ROOT={root}; OUT={out}; ST=$OUT/status.tsv; printf 'stage\\tstatus\\tdetail\\n' > "$ST"
status(){{ printf '%s\\t%s\\t%s\\n' "$1" "$2" "${{3:-}}" >> "$ST"; }}
MODE=sbom; SBOM_OK=1; SBOM=$OUT/sbom/sbom.cdx.json; KBUILD={src}; KBUILD_PREFIX=; GR={gr}; KERNEL_CVE_MIRROR=/nonexistent-mirror; KERNEL_CVES=
SCA_KERNEL_VERSIONS=; KOTHER={kother!r}; KNOTDISTRO={knotdistro!r}
declare -A META=()
unset KERNEL_SOURCE_DIR
KVERS=({kv}); KUPS=()
{KC_BLOCK}
{K_BLOCK}
printf '%s' "${{META[kernel_in_other_report]:-}}" > "$OUT/meta-kother.txt"
echo done
"""
    pybin = Path(sys.executable).parent
    env = {**os.environ, "PATH": f"{pybin}:{os.environ['PATH']}", "FAKE_LOG": str(log), "FAKE_STATUS": "OK", "REAL_KERNEL_CONFIG": str(tkc.LIB)}
    p = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=120, env=env)
    assert "done" in p.stdout, p.stdout + p.stderr
    rows = {}
    for l in (out / "status.tsv").read_text(encoding="utf-8").splitlines()[1:]:
        a = l.split("\t")
        rows[a[0]] = (a[1], a[2])
    kvf = out / "scan" / "kernel-versions.json"
    return rows, kvf.exists(), (log.read_text() if log.exists() else ""), out


def test_no_kernel_sbom_with_option_writes_three_not_run_rows_and_runs_nothing(tmp_path):
    rows, kv_exists, log, out = layer_run(tmp_path, NO_KERNEL_SBOM, tkc.rootfs_members(kver=A), kother=OTHER)
    for st in STAGES:
        assert rows[st][0] == "NOT_RUN", rows
        assert "不適用" in rows[st][1] and "沒有作業系統核心" in rows[st][1] and f"核心在 {OTHER} 報告判定" in rows[st][1]
    assert log == ""                                         # 沒呼叫 kernel_config.py、kernel_module_map.py、CNA 版本比對
    assert "C-kernel-coverage" not in rows and not any(k.startswith("C-kernel-not-judged") for k in rows) and "C-kernel-versions" not in rows
    assert not kv_exists
    assert not (out / "scan" / "kernel-cve-list.txt").exists() and not (out / "scan" / "kernel-config.json").exists()
    assert (out / "meta-kother.txt").read_text() == OTHER                            # 結構上的標記：cra_report 只認這個決定三個 NOT_RUN 不降級


def test_pi_like_two_kernels_image_still_nothing_runs_and_no_not_judged_rows(tmp_path):
    """Raspberry Pi 型：映像有兩顆核心、平台給了 kernel_release；-os 層不判定、不記「出貨但沒判定」的 GAP。"""
    rows, kv_exists, log, out = layer_run(tmp_path, NO_KERNEL_SBOM, tkv.two_kernels(), kother=OTHER, kvers=(A,))
    assert [rows[s][0] for s in STAGES] == ["NOT_RUN"] * 3 and log == "" and not kv_exists
    assert not any(k.startswith("C-kernel-not-judged") for k in rows)
    assert [v[0] for k, v in rows.items()] == ["NOT_RUN"] * 3        # 沒有其他任何列


def test_kernel_sbom_with_option_behaves_like_without(tmp_path):
    def go(name, **kw):
        d = tmp_path / name
        d.mkdir()
        rows, kv_exists, log, out = layer_run(d, KERNEL_SBOM, tkc.rootfs_members(kver=A), **kw)
        norm = lambda t: t.replace(str(d), "<T>")           # noqa: E731  各自的暫存資料夾路徑不算差異
        return {k: (v[0], norm(v[1])) for k, v in rows.items()}, kv_exists, norm(log)
    with_opt, without = go("a", kother=OTHER), go("b")
    assert with_opt == without
    rows, kv_exists, log = with_opt
    assert rows["C-kernel-config"][0] == "OK" and rows["C-kernel-module-map"][0] == "OK" and "kernel_config.py" in log
    assert kv_exists                                          # 有核心：kernel-versions.json 照常寫


def test_no_kernel_sbom_without_option_is_unchanged(tmp_path):
    """沒給選項：不推定「SBOM 沒有核心就是別層有」；核心階段照舊執行（單一 SBOM 的廠商核心仍走 CNA 版本比對）。"""
    rows, kv_exists, log, out = layer_run(tmp_path, NO_KERNEL_SBOM, tkc.rootfs_members(kver=A))
    assert "kernel_config.py" in log and "kernel_module_map.py" in log
    assert not any("不適用" in v[1] for v in rows.values())
    assert kv_exists and (out / "meta-kother.txt").read_text() == ""


def test_coverage_not_run_row_is_not_written_and_option_without_kernelcheck_ok_does_not_apply(tmp_path):
    """kernelcheck 判定 NOT_RUN 才適用；有核心（OK／GAP）時不套用，即使給了選項。"""
    rows, kv_exists, log, out = layer_run(tmp_path, KERNEL_SBOM, tkc.rootfs_members(kver=A), kother=OTHER)
    assert rows["C-kernel-coverage"][0] == "GAP"
    assert not any("不適用" in v[1] for v in rows.values()) and "kernel_config.py" in log
    assert (out / "meta-kother.txt").read_text() == ""                               # 有核心：給了選項也不寫標記


def test_not_distro_declaration_reaches_kernelcheck(tmp_path):
    rows, _, _, out = layer_run(tmp_path, KERNEL_SBOM, tkc.rootfs_members(kver=A), knotdistro="廠商核心，版本字串看不出來")
    assert rows["C-kernel-coverage"][0] == "GAP" and "廠商核心，版本字串看不出來" in rows["C-kernel-coverage"][1]
    ev = json.loads((out / "scan" / "kernel-coverage.json").read_text(encoding="utf-8"))
    assert ev["not_distro_declared"] == "廠商核心，版本字串看不出來"
    # 沒有核心的 SBOM + 宣告：仍是 NOT_RUN（不寫列）
    (tmp_path / "n").mkdir()
    rows, _, _, _ = layer_run(tmp_path / "n", NO_KERNEL_SBOM, tkc.rootfs_members(kver=A), knotdistro="x", kother=OTHER)
    assert "C-kernel-coverage" not in rows and rows["C-kernel-config"][0] == "NOT_RUN"


# ---------- 參數 ----------

def fn(name):
    return tkv.fn(name)


def layer_args(mode, kother_cli=None, kd_cli=None, env=None, name=""):
    # 值經環境變數交給 bash（不用 repr：\t、\n 要是真的控制字元）
    cl = 'KOTHER="$T_KOTHER"; KOTHER_CLI=1; ' if kother_cli is not None else "KOTHER=; KOTHER_CLI=0; "
    cl += 'KNOTDISTRO="$T_KD"; KNOTDISTRO_CLI=1' if kd_cli is not None else "KNOTDISTRO=; KNOTDISTRO_CLI=0"
    script = f"""set -uo pipefail
MODE={mode}
NAME="$T_NAME"
{cl}
{fn('kernel_layer_args')}
(kernel_layer_args; echo "KOTHER=[$KOTHER] KNOTDISTRO=[$KNOTDISTRO]")
echo "rc=$?"
"""
    e = {k: v for k, v in os.environ.items() if not k.startswith("SCA_KERNEL_")}
    e.update(env or {})
    e.update(T_KOTHER=kother_cli or "", T_KD=kd_cli or "", T_NAME=name)
    p = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=e, timeout=30)
    m = re.search(r"KOTHER=\[(.*)\] KNOTDISTRO=\[(.*)\]", p.stdout)
    return int(re.search(r"rc=(\d+)", p.stdout).group(1)), (m.groups() if m else None), p.stderr


def test_args_valid_values_and_env():
    assert layer_args("sbom", OTHER, "理由")[:2] == (0, (OTHER, "理由"))
    assert layer_args("image", "a1.b_c+d-e")[:2] == (0, ("a1.b_c+d-e", ""))
    assert layer_args("sbom", None, None, {"SCA_KERNEL_IN_OTHER_REPORT": OTHER, "SCA_KERNEL_NOT_DISTRO": "env 理由"})[:2] == (0, (OTHER, "env 理由"))
    assert layer_args("sbom", "cli-name", None, {"SCA_KERNEL_IN_OTHER_REPORT": OTHER})[:2] == (0, ("cli-name", ""))   # 命令列優先
    assert layer_args("dir", None, None, {"SCA_KERNEL_IN_OTHER_REPORT": "a;b"})[:2] == (0, ("", ""))                # 其他模式不看環境變數


def test_args_pointing_at_itself_exit_64():
    """-bsp 層也給 <專案>-bsp（指向這份報告自己）：拒絕。SBOM 偵測不到核心時會把這份報告該做的核心判定（含 CNA 退回）壓掉。"""
    rc, _, err = layer_args("sbom", "demo-bsp", name="demo-bsp")
    assert rc == 64 and "指向這份報告自己" in err
    rc, _, err = layer_args("sbom", None, None, {"SCA_KERNEL_IN_OTHER_REPORT": "demo-bsp"}, name="demo-bsp")
    assert rc == 64 and "指向這份報告自己" in err
    assert layer_args("sbom", "demo-bsp", name="demo-os")[:2] == (0, ("demo-bsp", ""))


@pytest.mark.parametrize("bad", ["a;b", "a/b", "$(id)", "`id`", "a b", "-x", ".x", "é", "x" * 101, "a|b", "a\\b", ""])
def test_args_bad_report_name_exit_64(bad):
    rc, _, err = layer_args("sbom", bad)
    assert rc == 64 and "報告名稱只接受" in err
    if bad:
        rc, _, err = layer_args("sbom", None, None, {"SCA_KERNEL_IN_OTHER_REPORT": bad})
        assert rc == 64 and "報告名稱只接受" in err


@pytest.mark.parametrize("bad", ["", "   ", "a\tb", "a\nb", "x" * 301])
def test_args_bad_not_distro_exit_64(bad):
    rc, _, err = layer_args("sbom", None, bad)
    assert rc == 64 and "理由" in err


def test_args_only_for_image_or_sbom():
    assert layer_args("git", OTHER)[0] == 64 and layer_args("dir", None, "x")[0] == 64


def test_sca_scan_cli_exit_64(tmp_path):
    for args in (["--kernel-in-other-report", "a;b"], ["--kernel-in-other-report"], ["--kernel-not-distro", ""], ["--kernel-not-distro"]):
        p = tkv.sca(tmp_path, *args)
        assert p.returncode == 64, (args, p.stdout, p.stderr)
        assert "輸出資料夾已存在" not in p.stderr
    p = tkv.sca(tmp_path, env={"SCA_KERNEL_IN_OTHER_REPORT": "a b"})
    assert p.returncode == 64 and "報告名稱只接受" in p.stderr
    # 合法的值通過參數檢查，停在下一關（輸出資料夾不是空的）
    p = tkv.sca(tmp_path, "--kernel-in-other-report", OTHER, "--kernel-not-distro", "理由")
    assert p.returncode == 64 and "輸出資料夾已存在" in p.stderr
