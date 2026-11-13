"""cra-scan.py 的 --kernel-version／SCA_KERNEL_VERSIONS：可重複、環境變數（命令列優先）、不合法 → exit 64，原樣交給 scan-flash-package.sh。
--plan-only 看 plan.json；掃描指令用換掉 run／取工具的方式攔下來看。"""
import importlib.util
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from test_wizard_plan import WIZ, add, run, site  # noqa: E402,F401  （site 是 fixture）

A, B = "6.1.118", "6.1.120"          # 合成的核心版本


def plan_of(out):
    return json.loads((next(out.iterdir()) / "plan.json").read_text(encoding="utf-8"))


def base(tmp, cfg, flash, src):
    return [str(tmp), "--site-config", str(cfg), "--archive", str(flash), "--source", str(src), "--role", "both", "--generic-rules", "no",
            "--yes", "--plan-only"]


def test_repeated_flag_in_plan(site):
    tmp, flash, src, out, cfg, _ = site
    r = run(base(tmp, cfg, flash, src) + ["--kernel-version", A, "--kernel-version", B, "--kernel-version", A])
    assert r.returncode == 0, r.stdout + r.stderr
    assert plan_of(out)["kernel_versions"] == [A, B]


def test_env_var_and_cli_wins(site):
    tmp, flash, src, out, cfg, _ = site
    r = run(base(tmp, cfg, flash, src), {"SCA_KERNEL_VERSIONS": f"{A} {B}"})
    assert r.returncode == 0 and plan_of(out)["kernel_versions"] == [A, B], r.stdout + r.stderr
    out2 = tmp / "out2"
    cfg2 = tmp / "wizard2.json"
    c = json.loads(cfg.read_text(encoding="utf-8"))
    c["outroot"] = str(out2)
    cfg2.write_text(json.dumps(c), encoding="utf-8")
    r = run(base(tmp, cfg2, flash, src) + ["--kernel-version", B], {"SCA_KERNEL_VERSIONS": f"{A},{B}"})
    assert r.returncode == 0 and plan_of(out2)["kernel_versions"] == [B], r.stdout + r.stderr


def test_default_is_empty_list(site):
    tmp, flash, src, out, cfg, _ = site
    r = run(base(tmp, cfg, flash, src))
    assert r.returncode == 0 and plan_of(out)["kernel_versions"] == []


@pytest.mark.parametrize("bad", ["a;b", "a/b", "$(id)", "`id`", "a b", "-x", "é", "x" * 101])
def test_invalid_exit_64(site, bad):
    tmp, flash, src, out, cfg, _ = site
    r = run(base(tmp, cfg, flash, src) + [f"--kernel-version={bad}"])
    assert r.returncode == 64 and "核心版本只接受" in r.stderr, r.stdout + r.stderr
    assert not out.exists() or not list(out.iterdir())              # 在任何輸入、輸出之前就停
    if " " not in bad:
        r = run(base(tmp, cfg, flash, src), {"SCA_KERNEL_VERSIONS": f"{A},{bad}"})
        assert r.returncode == 64 and "核心版本只接受" in r.stderr


def test_passed_to_scan_flash_package(site, monkeypatch, tmp_path):
    """掃描指令：每個版本一組 --kernel-version，原樣交給 scan-flash-package.sh。"""
    tmp, flash, src, out, cfg, _ = site
    spec = importlib.util.spec_from_file_location("cra_scan_mod", WIZ)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    pe = tmp / "pilot.env"
    pe.write_text("", encoding="utf-8")
    c = json.loads(cfg.read_text(encoding="utf-8"))
    c["pilot_env"] = str(pe)
    cfg.write_text(json.dumps(c), encoding="utf-8")
    seen = {}

    class Stop(Exception):
        pass

    def fake_run(cmd, log, env=None, cwd=None):
        seen["cmd"] = list(cmd)
        raise Stop

    monkeypatch.setattr(mod, "resolve_tools_rev", lambda repo, rev: ("0" * 40, {"requested": rev, "worktree_dirty": False}))
    monkeypatch.setattr(mod, "extract_tools", lambda repo, commit, dest: dest.mkdir(parents=True))
    monkeypatch.setattr(mod, "run", fake_run)
    monkeypatch.setattr(sys, "argv", ["cra-scan.py", "--site-config", str(cfg), "--archive", str(flash), "--source", str(src), "--role", "both",
                                      "--generic-rules", "no", "--yes", "--kernel-version", A, "--kernel-version", B])
    monkeypatch.setenv("SCA_KERNEL_VERSIONS", "9.9.9")           # 命令列優先
    with pytest.raises(Stop):
        mod.main()
    cmd = seen["cmd"]
    assert cmd[0] == "tools/demo/scan-flash-package.sh"
    assert [cmd[i + 1] for i, x in enumerate(cmd) if x == "--kernel-version"] == [A, B]


def test_upstream_version_in_plan_and_invalid(site):
    """--kernel-upstream-version <核心版本>=<X.Y.Z>：可重複、重複的算一個；格式不對或同一顆兩個值 → exit 64。"""
    tmp, flash, src, out, cfg, _ = site
    r = run(base(tmp, cfg, flash, src) + ["--kernel-upstream-version", f"{A}=6.1.118", "--kernel-upstream-version", f"{A}=6.1.118"])
    assert r.returncode == 0, r.stdout + r.stderr
    assert plan_of(out)["kernel_upstream_versions"] == [f"{A}=6.1.118"]
    for bad in ("6.1.118", f"{A}=6.1", f"{A}=x.y.z", "a;b=6.1.1", f"{A}=6.1.1;id"):
        r = run(base(tmp, cfg, flash, src) + [f"--kernel-upstream-version={bad}"])
        assert r.returncode == 64 and "--kernel-upstream-version" in r.stderr, bad
    r = run(base(tmp, cfg, flash, src) + ["--kernel-upstream-version", f"{A}=6.1.118", "--kernel-upstream-version", f"{A}=6.1.119"])
    assert r.returncode == 64


def test_upstream_version_passed_to_scan_flash_package(site, monkeypatch):
    tmp, flash, src, out, cfg, _ = site
    spec = importlib.util.spec_from_file_location("cra_scan_mod2", WIZ)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    pe = tmp / "pilot.env"
    pe.write_text("", encoding="utf-8")
    c = json.loads(cfg.read_text(encoding="utf-8"))
    c["pilot_env"] = str(pe)
    cfg.write_text(json.dumps(c), encoding="utf-8")
    seen = {}

    class Stop(Exception):
        pass

    def fake_run(cmd, log, env=None, cwd=None):
        seen["cmd"] = list(cmd)
        raise Stop

    monkeypatch.setattr(mod, "resolve_tools_rev", lambda repo, rev: ("0" * 40, {"requested": rev, "worktree_dirty": False}))
    monkeypatch.setattr(mod, "extract_tools", lambda repo, commit, dest: dest.mkdir(parents=True))
    monkeypatch.setattr(mod, "run", fake_run)
    monkeypatch.setattr(sys, "argv", ["cra-scan.py", "--site-config", str(cfg), "--archive", str(flash), "--source", str(src), "--role", "both",
                                      "--generic-rules", "no", "--yes", "--kernel-version", A, "--kernel-upstream-version", f"{A}=6.1.118"])
    with pytest.raises(Stop):
        mod.main()
    cmd = seen["cmd"]
    assert [cmd[i + 1] for i, x in enumerate(cmd) if x == "--kernel-upstream-version"] == [f"{A}=6.1.118"]
