"""scan-flash-package.sh 的 --kernel-version／SCA_KERNEL_VERSIONS：可重複、環境變數（空白或逗號分隔，命令列優先）、不合法 → exit 64，
並且原樣交給 sca-scan。用 --rescan-from 走到 sca-scan 那一步；sca-scan 換成只記下參數的假程式（複製一份工具樹，其餘用符號連結指到 repo）。
"""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "tools" / "pilot" / "tests"))
import test_kernel_config as tkc  # noqa: E402

SCRIPT = REPO / "tools" / "demo" / "scan-flash-package.sh"
A, B = "6.1.118", "6.1.120"          # 合成的核心版本

FAKE_SCA = """#!/bin/bash
printf '%s\\n' "$@" > "$ARGS_LOG"
out=; while [ $# -gt 0 ]; do case $1 in --out) out=$2;; esac; shift; done
mkdir -p "$out"; printf 'stage\\tstatus\\tdetail\\n' > "$out/status.tsv"
exit 0
"""


def tool_tree(tmp_path):
    """tmp/tools：scan-flash-package.sh 是複本（ROOT 由它的位置決定），tools/pilot/sca-scan 是假的，其餘指到 repo。"""
    t = tmp_path / "tree" / "tools"
    t.mkdir(parents=True)
    for d in ("cra", "e2e", "mirror", "sbomgate", "vexconv", "wizard"):
        (t / d).symlink_to(REPO / "tools" / d)
    for d in ("demo", "pilot"):
        (t / d).mkdir()
        for f in (REPO / "tools" / d).iterdir():
            (t / d / f.name).symlink_to(f)
    (t / "demo" / "scan-flash-package.sh").unlink()
    (t / "demo" / "scan-flash-package.sh").write_text(SCRIPT.read_text(encoding="utf-8"), encoding="utf-8")
    (t / "pilot" / "sca-scan").unlink()
    (t / "pilot" / "sca-scan").write_text(FAKE_SCA)
    (t / "pilot" / "sca-scan").chmod(0o755)
    return t / "demo" / "scan-flash-package.sh"


def run(tmp_path, *args, env=None, script=None):
    b = tmp_path / "bin"
    b.mkdir(exist_ok=True)
    for t in ("grype", "bwrap"):
        (b / t).write_text("#!/bin/sh\necho 'Version: 0.0.0'\n")
        (b / t).chmod(0o755)
    e = {k: v for k, v in os.environ.items() if k != "SCA_KERNEL_VERSIONS"}
    e.update(PATH=f"{b}:{os.environ['PATH']}", FLASHPKG_ALLOW_TMP_OUT="1", SCA_TOOLS_DIR=str(tmp_path / "none"),
             ARGS_LOG=str(tmp_path / "sca-args.txt"), **(env or {}))
    return subprocess.run(["bash", str(script or SCRIPT), *map(str, args)], capture_output=True, text=True, env=e, timeout=300)


def prev(tmp_path):
    a = tkc.write_tar(tmp_path / "product-a.tbz2", tkc.rootfs_members("product-a/Linux_for_Tegra/rootfs_no_gui/"), mode="w:bz2")
    return a, tkc.prev_result(tmp_path, a)


def sca_args(tmp_path):
    f = tmp_path / "sca-args.txt"
    return f.read_text(encoding="utf-8").splitlines() if f.exists() else None


def kv_of(args):
    return [args[i + 1] for i, x in enumerate(args) if x == "--kernel-version"]


def test_repeated_flag_passed_to_sca_scan(tmp_path):
    a, pv = prev(tmp_path)
    p = run(tmp_path, "--rescan-from", pv, "--archive", a, "--out", tmp_path / "res", "--no-upload", "--no-company",
            "--kernel-version", A, "--kernel-version", B, script=tool_tree(tmp_path))
    args = sca_args(tmp_path)
    assert args is not None, p.stdout + p.stderr
    assert kv_of(args) == [A, B] and "--sbom" in args


def test_env_var_and_cli_priority(tmp_path):
    a, pv = prev(tmp_path)
    sc = tool_tree(tmp_path)
    base = ["--rescan-from", pv, "--archive", a, "--no-upload", "--no-company"]
    p = run(tmp_path, *base, "--out", tmp_path / "r1", env={"SCA_KERNEL_VERSIONS": f"{A} {B},{A}"}, script=sc)
    assert kv_of(sca_args(tmp_path)) == [A, B], p.stdout + p.stderr                 # 空白或逗號分隔，重複的算一個
    (tmp_path / "sca-args.txt").unlink()
    run(tmp_path, *base, "--out", tmp_path / "r2", "--kernel-version", B, env={"SCA_KERNEL_VERSIONS": A}, script=sc)
    assert kv_of(sca_args(tmp_path)) == [B]                                           # 命令列優先
    (tmp_path / "sca-args.txt").unlink()
    run(tmp_path, *base, "--out", tmp_path / "r3", script=sc)                         # 都沒給：不加參數（和以前相同）
    assert "--kernel-version" not in sca_args(tmp_path)


@pytest.mark.parametrize("bad", ["a;b", "a/b", "$(id)", "`id`", "a b", "a|b", "-x", "é", "x" * 101])
def test_invalid_value_exit_64(tmp_path, bad):
    a, pv = prev(tmp_path)
    sc = tool_tree(tmp_path)
    p = run(tmp_path, "--rescan-from", pv, "--archive", a, "--out", tmp_path / "res", "--no-upload", "--no-company", "--kernel-version", bad, script=sc)
    assert p.returncode == 64 and "核心版本只接受" in p.stderr, p.stdout + p.stderr
    assert sca_args(tmp_path) is None
    if " " not in bad:
        p = run(tmp_path, "--rescan-from", pv, "--archive", a, "--out", tmp_path / "res2", "--no-upload", "--no-company",
                env={"SCA_KERNEL_VERSIONS": f"{A},{bad}"}, script=sc)
        assert p.returncode == 64 and "核心版本只接受" in p.stderr, p.stdout + p.stderr


def test_missing_value_exit_64(tmp_path):
    p = run(tmp_path, "--kernel-version")
    assert p.returncode == 64 and "--kernel-version 要給值" in p.stderr


def test_usage_mentions_kernel_version(tmp_path):
    p = run(tmp_path, "--help")
    assert p.returncode == 0 and "--kernel-version" in p.stdout and "SCA_KERNEL_VERSIONS" in p.stdout


def test_upstream_version_passed_to_sca_scan_and_invalid(tmp_path):
    a, pv = prev(tmp_path)
    sc = tool_tree(tmp_path)
    p = run(tmp_path, "--rescan-from", pv, "--archive", a, "--out", tmp_path / "res", "--no-upload", "--no-company",
            "--kernel-version", A, "--kernel-upstream-version", f"{A}=6.1.118", script=sc)
    args = sca_args(tmp_path)
    assert args is not None, p.stdout + p.stderr
    assert [args[i + 1] for i, x in enumerate(args) if x == "--kernel-upstream-version"] == [f"{A}=6.1.118"]
    (tmp_path / "sca-args.txt").unlink()
    for i, bad in enumerate(("6.1.118", f"{A}=6.1", "a;b=6.1.1", f"{A}=6.1.1 x")):
        p = run(tmp_path, "--rescan-from", pv, "--archive", a, "--out", tmp_path / f"bad{i}", "--no-upload", "--no-company",
                "--kernel-upstream-version", bad, script=sc)
        assert p.returncode == 64 and "--kernel-upstream-version" in p.stderr, (bad, p.stdout + p.stderr)
        assert sca_args(tmp_path) is None
