"""--kernel-version／SCA_KERNEL_VERSIONS：映像出貨的核心哪些有判定（scan/kernel-versions.json，lib/kernel_versions.py）。

全部用合成資料：假的 rootfs tar（兩個 /usr/lib/modules/<版本>/）。sca-scan 的核心區段（含 kernel_versions_prepare／kernel_versions_finish）
從 sca-scan 原文抽出來在 bash 裡真的執行；判定工具（kernel_config.py、kernel_module_map.py）用假的，記下收到的參數；
列出出貨核心（kernel_config.py --list-kernel-versions）與 kernel_versions.py 是真的。
"""
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(__file__))
import test_kernel_config as tkc  # noqa: E402
import test_kernel_cna_version as tcv  # noqa: E402

PILOT = tkc.PILOT
ROOT = tkc.ROOT
SCAN = PILOT / "sca-scan"
KV = PILOT / "lib" / "kernel_versions.py"
sys.path.insert(0, str(PILOT / "lib"))
import kernel_versions as kvmod  # noqa: E402

A, B = "6.1.118", "6.1.120"          # 合成的核心版本


def jv(doc):
    """檔案內容的 judged（schema /3：物件清單；/1、/2：字串清單）→ 版本清單。"""
    return kvmod.judged_versions(doc)


def names(doc):
    """檔案內容的 shipped（schema /2：物件清單）→ 版本清單；null 維持 None。"""
    return None if doc["shipped"] is None else [x["version"] for x in doc["shipped"]]


def sub(tmp_path, name):
    d = tmp_path / name
    d.mkdir()
    return d


def two_kernels():
    return tkc.rootfs_members(kver=A) + [(f"usr/lib/modules/{B}/kernel/x.ko", b"x", None)]


# ---------- kernel_versions.py：規則 ----------

def test_plan_rules():
    p = kvmod.plan([A], [])                                  # 1 顆、沒指定：照舊判定它
    assert (names(p), p["requested"], jv(p), p["not_judged"]) == ([A], [], [A], [])
    assert p["schema"] == "sca-center-kernel-versions/2" and p["judged"] == [A]         # 1 顆：照舊 /2（judged 是字串清單）
    p = kvmod.plan([B, A], [])                               # 多顆、沒指定：全部逐顆判定（M7d-1，D-061 (1)）
    assert names(p) == [A, B] and jv(p) == [A, B] and p["not_judged"] == []
    assert {x["basis"] for x in p["judged"]} == {"auto-detected"}
    p = kvmod.plan([A, B], [A])                              # 指定 1 顆：判定它，另一顆 not_judged
    assert jv(p) == [A] and p["not_judged"] == [{"version": B, "reason": kvmod.REASON_OTHER_GIVEN, "shipped": True}]
    assert p["schema"] == "sca-center-kernel-versions/2" and p["judged"] == [A]
    p = kvmod.plan([A, B], [A, B, A])                        # 指定 2 顆（重複的算一顆）：逐顆判定
    assert p["requested"] == [A, B] and jv(p) == [A, B] and p["not_judged"] == []
    assert {x["basis"] for x in p["judged"]} == {"project-specified"} and p["schema"] == kvmod.SCHEMA
    p = kvmod.plan([A, B, "6.1.130"], [A, B])                # 只指定一部分：沒指定的出貨核心照舊 not_judged
    assert jv(p) == [A, B] and p["not_judged"] == [{"version": "6.1.130", "reason": kvmod.REASON_OTHER_GIVEN, "shipped": True}]
    p = kvmod.plan([A], ["6.9.9", A])                        # 指定的核心映像沒有：一樣交給判定工具（由工具回 GAP），不另記 not_judged
    assert jv(p) == ["6.9.9", A] and p["not_judged"] == []
    p = kvmod.plan(None, [A, B])                             # 出貨的核心讀不出來：指定的照樣判定
    assert p["shipped"] is None and jv(p) == [A, B] and p["not_judged"] == []
    p = kvmod.plan(None, [])
    assert p["shipped"] is None and p["judged"] == [] and p["not_judged"] == []


def test_plan_judged_results_schema_3():
    p = kvmod.plan([A, B], [], results={A: ("scan/kernels/a/kernel-config.json", "OK", "scan/kernels/a/kernel-module-map.json", "ATTENTION"),
                                       B: (None, "GAP", None, None)})
    assert p["schema"] == "sca-center-kernel-versions/3" and p["judged"][0] == {
        "version": A, "basis": "auto-detected", "config_file": "scan/kernels/a/kernel-config.json", "config_status": "OK",
        "module_map_file": "scan/kernels/a/kernel-module-map.json", "module_map_status": "ATTENTION"}
    assert p["judged"][1] == {"version": B, "basis": "auto-detected", "config_file": None, "config_status": "GAP", "module_map_file": None, "module_map_status": None}
    # 讀取端三種 schema 都收：/1、/2 的 judged 是字串清單
    assert kvmod.judged_versions({"schema": "sca-center-kernel-versions/2", "judged": [A, B]}) == [A, B]
    assert kvmod.judged_versions({"schema": "sca-center-kernel-versions/1", "judged": [A]}) == [A]
    assert kvmod.judged_versions(p) == [A, B] and kvmod.judged_versions(None) == [] and kvmod.judged_versions({"judged": [3, {"x": 1}]}) == []


def run_kv(tmp_path, *args):
    out = tmp_path / "kv.json"
    p = subprocess.run([sys.executable, "-I", str(KV), "--out", str(out), *args], capture_output=True, text=True, timeout=60)
    return p, (json.loads(out.read_text(encoding="utf-8")) if out.exists() else None)


def test_cli_writes_file_and_lines(tmp_path):
    p, doc = run_kv(tmp_path, "--shipped", A, "--shipped", B, "--requested", A)
    assert p.returncode == 0 and doc["schema"] == "sca-center-kernel-versions/2" and doc["judged"] == [A]      # 1 顆：照舊 /2
    assert f"KERNEL-NOT-JUDGED\t{B}\t{kvmod.REASON_OTHER_GIVEN}" in p.stdout and f"KERNEL-NOT-JUDGED\t{A}" not in p.stdout
    note = next(l for l in p.stdout.splitlines() if l.startswith("KERNEL-VERSIONS-NOTE\t"))
    assert B in note and "必須記錄證據" in note and "設計文件" in note
    # 沒指定、多顆：全部判定，沒有 not_judged 行（M7d-1）
    p, doc = run_kv(tmp_path, "--shipped", A, "--shipped", B)
    assert p.returncode == 0 and jv(doc) == [A, B] and doc["not_judged"] == [] and "KERNEL-NOT-JUDGED" not in p.stdout
    # --judged-result：每顆的結果檔與狀態
    p, doc = run_kv(tmp_path, "--shipped", A, "--shipped", B, "--judged-result", f"{A}|scan/kernels/{A}/kernel-config.json|OK|-|-")
    assert p.returncode == 0 and doc["judged"][0]["config_file"] == f"scan/kernels/{A}/kernel-config.json" and doc["judged"][0]["module_map_file"] is None
    assert doc["judged"][1]["config_file"] is None
    # 只判定 1 顆：結果檔與狀態不記（照舊 /2）
    p, doc = run_kv(tmp_path, "--shipped", A, "--judged-result", f"{A}|scan/kernel-config.json|OK|-|-")
    assert p.returncode == 0 and doc["schema"] == "sca-center-kernel-versions/2" and doc["judged"] == [A]
    for bad in (f"{A}|x|OK|y", f"a;b|x|OK|y|OK", f"{A}|../../etc|OK|-|-".replace("..", "a b")):
        p, _ = run_kv(tmp_path, "--shipped", A, "--judged-result", bad)
        assert p.returncode == 3 and p.stdout.startswith("KERNEL-VERSIONS-ERROR"), bad
    p, _ = run_kv(tmp_path, "--shipped", A, "--judged-result", f"{A}|-|-|-|-", "--judged-result", f"{A}|-|OK|-|-")      # 同一顆給兩次
    assert p.returncode == 3
    # 沒有東西可記：不寫檔
    (tmp_path / "kv.json").unlink()
    p, doc = run_kv(tmp_path)
    assert p.returncode == 0 and doc is None and p.stdout == ""
    # 1 顆、沒指定：寫檔但沒有 not_judged 行
    p, doc = run_kv(tmp_path, "--shipped", A)
    assert jv(doc) == [A] and doc["not_judged"] == [] and p.stdout == ""
    # 不合法的版本、兩種 shipped 同時給
    p, _ = run_kv(tmp_path, "--shipped", "a;b")
    assert p.returncode == 3 and p.stdout.startswith("KERNEL-VERSIONS-ERROR")
    p, _ = run_kv(tmp_path, "--shipped", A, "--shipped-unknown")
    assert p.returncode == 3


# ---------- kernel_config.py --list-kernel-versions ----------

def list_versions(tmp_path, members):
    src = tkc.write_tar(tmp_path / "l.tar", members)
    p = subprocess.run([sys.executable, "-I", str(tkc.LIB), "--list-kernel-versions", "--from", str(src)], capture_output=True, text=True, timeout=60)
    return p.returncode, p.stdout.strip().split("\t")


def test_list_kernel_versions(tmp_path):
    assert list_versions(tmp_path, tkc.rootfs_members(kver=A)) == (0, ["KERNEL-VERSIONS", "OK", A])
    assert list_versions(tmp_path, two_kernels()) == (0, ["KERNEL-VERSIONS", "OK", f"{A} {B}"])
    rc, got = list_versions(tmp_path, [("etc/passwd", b"root:x:0:0\n", None)])        # 沒有核心：空清單
    assert rc == 0 and got[:2] == ["KERNEL-VERSIONS", "OK"] and (len(got) == 2 or got[2] == "")
    p = subprocess.run([sys.executable, "-I", str(tkc.LIB), "--list-kernel-versions"], capture_output=True, text=True, timeout=60)
    assert p.returncode == 3 and p.stdout.startswith("KERNEL-VERSIONS\tGAP")


# ---------- sca-scan：參數 ----------

SRC = SCAN.read_text(encoding="utf-8")


def fn(name):
    i = SRC.index(name + "(){")
    return SRC[i:SRC.index("\n}\n", i) + 3]


def args_harness(mode, cli, env=None):
    """sca-scan 的 kernel_versions_args 單獨執行：cli 是 --kernel-version 給的值（None＝沒給）；結果印出 KVERS 與退出碼。"""
    cl = "KVERS_CLI=0; KVERS=()" if cli is None else "KVERS_CLI=1; KVERS=(" + " ".join(f"'{v}'" for v in cli) + ")"
    script = f"""set -uo pipefail
MODE={mode}
{cl}
{fn('kernel_versions_args')}
(kernel_versions_args; echo "KVERS=[${{KVERS[*]-}}] n=${{#KVERS[@]}}")
echo "rc=$?"
"""
    e = {k: v for k, v in os.environ.items() if k != "SCA_KERNEL_VERSIONS"}
    if env is not None:
        e["SCA_KERNEL_VERSIONS"] = env
    p = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=e, timeout=30)
    m = re.search(r"KVERS=\[(.*)\] n=(\d+)", p.stdout)
    rc = int(re.search(r"rc=(\d+)", p.stdout).group(1))
    return rc, (m.group(1) if m else None), p.stderr


def test_args_repeated_flag_and_dedupe():
    assert args_harness("image", [A, B]) == (0, f"{A} {B}", "")
    assert args_harness("sbom", [A, A, B])[:2] == (0, f"{A} {B}")
    assert args_harness("image", ["6.6.51+rpt-rpi-2712", "6.12.0~rc1-v8_x"])[:2] == (0, "6.6.51+rpt-rpi-2712 6.12.0~rc1-v8_x")
    assert args_harness("image", None)[:2] == (0, "")


def test_args_env_var_space_or_comma():
    assert args_harness("image", None, f"{A} {B}")[:2] == (0, f"{A} {B}")
    assert args_harness("sbom", None, f"{A},{B}")[:2] == (0, f"{A} {B}")
    assert args_harness("image", None, f" {A} ,, {B}\t{A} ")[:2] == (0, f"{A} {B}")
    assert args_harness("image", None, "*")[0] == 64                       # 不展開萬用字元，也不是合法版本


def test_args_cli_wins_over_env():
    assert args_harness("image", [A], f"{B}")[:2] == (0, A)
    assert args_harness("image", [A], "bad;value")[:2] == (0, A)          # 命令列有給就不看環境變數


@pytest.mark.parametrize("bad", ["a;b", "a/b", "../x", "$(id)", "`id`", "a b", "a|b", "a&b", "a>b", 'a"b', "a\\b", "-x", ".1", "a*", "a?b", "a(b)", "a{b}", "é", "x" * 101])
def test_args_reject_metacharacters(bad):
    rc, got, err = args_harness("image", [A, bad])
    assert rc == 64 and "核心版本只接受" in err
    if " " not in bad:
        assert args_harness("image", None, f"{A} {bad}")[0] == 64              # 環境變數同樣的檢查


def test_args_kernel_version_only_for_image_or_sbom():
    rc, _, err = args_harness("git", [A])
    assert rc == 64 and "只用於 --image 或 --sbom" in err
    assert args_harness("dir", None, f"{A} {B}")[:2] == (0, "")            # 環境變數在其他模式不看（沒有核心可判定）


def sca(tmp_path, *args, env=None):
    out = tmp_path / "out-exists"
    out.mkdir(exist_ok=True)
    (out / "x").write_text("x")
    bom = tmp_path / "b.json"
    bom.write_text("{}")
    e = {**{k: v for k, v in os.environ.items() if k != "SCA_KERNEL_VERSIONS"}, **(env or {})}
    return subprocess.run(["bash", str(SCAN), "--sbom", str(bom), "--out", str(out), *args], capture_output=True, text=True, env=e, timeout=60)


def test_sca_scan_cli_exit_64(tmp_path):
    # 不合法的值、沒給值、其他模式：exit 64（在掃描之前）
    for args in (["--kernel-version", "a;b"], ["--kernel-version", "a/b"], ["--kernel-version", "$(id)"], ["--kernel-version"]):
        p = sca(tmp_path, *args)
        assert p.returncode == 64, (args, p.stdout, p.stderr)
        assert "輸出資料夾已存在" not in p.stderr
    p = sca(tmp_path, env={"SCA_KERNEL_VERSIONS": "6.1.1;rm"})
    assert p.returncode == 64 and "核心版本只接受" in p.stderr
    p = subprocess.run(["bash", str(SCAN), "--dir", str(tmp_path), "--kernel-version", A], capture_output=True, text=True, timeout=60)
    assert p.returncode == 64 and "只用於 --image 或 --sbom" in p.stderr
    # 合法的值（重複給、環境變數）通過參數檢查，停在下一關（輸出資料夾不是空的）
    for args, env in ((["--kernel-version", A, "--kernel-version", B], None), ([], {"SCA_KERNEL_VERSIONS": f"{A},{B}"})):
        p = sca(tmp_path, *args, env=env)
        assert p.returncode == 64 and "輸出資料夾已存在" in p.stderr, (args, p.stderr)


# ---------- sca-scan：核心區段 ----------

FAKE_TOOL = """#!/usr/bin/env python3
import os, subprocess, sys
a = sys.argv[1:]
NAME = os.path.basename(sys.argv[0])
REAL = [sys.executable, "-I", os.environ["REAL_KERNEL_CONFIG"]]
if "--source-tree-version" in a:                  # 讀原始碼樹的版本：借真的
    os.execv(sys.executable, REAL + a)
if "--list-kernel-versions" in a:                 # 另外讀一次映像
    with open(os.environ["FAKE_LOG"], "a") as f:
        f.write("LIST\\n")
    os.execv(sys.executable, REAL + a)
with open(os.environ["FAKE_LOG"], "a") as f:
    f.write(NAME + " " + " ".join(a) + "\\n")
if "--also-list-kernel-versions" in a:            # 真的工具讀映像的同一趟順便印出貨的核心：這裡借真的列舉
    print(subprocess.run(REAL + ["--list-kernel-versions", "--from", a[a.index("--from") + 1]], capture_output=True, text=True).stdout.strip())
stage = "C-kernel-config" if NAME == "kernel_config.py" else "C-kernel-module-map"
out = a[a.index("--out") + 1]
status = os.environ.get("FAKE_STATUS", "OK")
if "--kernel-version" in a and os.environ.get("FAKE_STATUS_BY_VERSION"):
    import json
    status = json.loads(os.environ["FAKE_STATUS_BY_VERSION"]).get(a[a.index("--kernel-version") + 1], status)
open(out, "w").write("{}")
print(f"{stage}\\t{status}\\t判定完成（假的工具）")
"""


def block_text():
    i = SRC.index("KCF=$OUT/scan/kernel-config.json")
    return SRC[i:SRC.index("# ---- C-euvd", i)]


def kernel_run(tmp_path, members, kvers=(), fake_status="OK", source_dir=None, kups=(), fake_status_by_version=None, kernel_cves=None,
               real_tools=False, grype_doc=None, mirror=""):
    """sca-scan 的核心區段（C-kernel-config、C-kernel-module-map 與核心出貨清單）在 bash 裡執行；判定工具是假的。"""
    root = tmp_path / "root"
    lib = root / "tools" / "pilot" / "lib"
    lib.mkdir(parents=True)
    for n in ("kernel_config.py", "kernel_module_map.py"):
        if real_tools:                    # 真的判定工具（kernel_config.py 讀映像與 .config、kernel_module_map.py 對應模組）；--list-kernel-versions 也是真的
            (lib / n).symlink_to(PILOT / "lib" / n)
        else:
            (lib / n).write_text(FAKE_TOOL)
    (lib / "kernel_versions.py").symlink_to(PILOT / "lib" / "kernel_versions.py")
    out = tmp_path / "out"
    (out / "scan").mkdir(parents=True)
    (out / "dt").mkdir()
    gr = out / "scan" / "grype.json"
    gr.write_text("{}" if grype_doc is None else json.dumps(grype_doc))
    src = tkc.write_tar(tmp_path / "r.tar", members)
    log = tmp_path / "fake.log"
    kv = " ".join(f"'{v}'" for v in kvers)
    script = f"""set -uo pipefail
ROOT={root}; OUT={out}; ST=$OUT/status.tsv; printf 'stage\\tstatus\\tdetail\\n' > "$ST"
status(){{ printf '%s\\t%s\\t%s\\n' "$1" "$2" "${{3:-}}" >> "$ST"; }}
MODE=sbom; SBOM_OK=1; KBUILD={src}; KBUILD_PREFIX=; GR={gr}; KERNEL_CVE_MIRROR={mirror}; KERNEL_CVES={kernel_cves or ""}; SCA_KERNEL_VERSIONS=; KNONE=0; KOTHER=
{'KERNEL_SOURCE_DIR=' + str(source_dir) if source_dir else 'unset KERNEL_SOURCE_DIR'}
KVERS=({kv})
KUPS=({" ".join(f"'{v}'" for v in kups)})
{block_text()}
echo done
"""
    pybin = Path(sys.executable).parent
    env = {**os.environ, "PATH": f"{pybin}:{os.environ['PATH']}", "FAKE_LOG": str(log), "FAKE_STATUS": fake_status,
           "REAL_KERNEL_CONFIG": str(tkc.LIB)}
    if fake_status_by_version:
        env["FAKE_STATUS_BY_VERSION"] = json.dumps(fake_status_by_version)
    p = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=120, env=env)
    assert "done" in p.stdout, p.stdout + p.stderr
    rows = {}
    for l in (out / "status.tsv").read_text(encoding="utf-8").splitlines()[1:]:
        a = l.split("\t")
        rows[a[0]] = (a[1], a[2])
    kvf = out / "scan" / "kernel-versions.json"
    return rows, (json.loads(kvf.read_text(encoding="utf-8")) if kvf.exists() else None), (log.read_text() if log.exists() else ""), p


def test_one_kernel_unchanged(tmp_path):
    rows, doc, log, p = kernel_run(tmp_path, tkc.rootfs_members(kver=A))
    assert rows["C-kernel-config"][0] == "OK" and rows["C-kernel-module-map"][0] == "OK"
    assert not any(k.startswith("C-kernel-not-judged") for k in rows) and "C-kernel-versions" not in rows
    assert "--kernel-version" not in log                                  # 沒指定：不加參數，和以前相同
    assert "LIST" not in log and log.count("--also-list-kernel-versions") == 2     # 出貨的核心由判定工具讀映像的同一趟印出，不另外讀映像
    assert names(doc) == [A] and doc["requested"] == [] and jv(doc) == [A] and doc["not_judged"] == []
    # 只判定 1 顆：結果還是 scan/kernel-config.json 與 scan/kernel-module-map.json（不是 scan/kernels/）；檔案照舊是 schema /2、judged 是字串清單
    assert doc["schema"] == "sca-center-kernel-versions/2" and doc["judged"] == [A]
    assert (tmp_path / "out" / "scan" / "kernel-config.json").exists() and not (tmp_path / "out" / "scan" / "kernels").exists()
    # 指定的就是那一顆：判定它，工具收到 --kernel-version
    rows, doc, log, p = kernel_run(sub(tmp_path, "g"), tkc.rootfs_members(kver=A), [A])
    assert rows["C-kernel-config"][0] == "OK" and jv(doc) == [A] and doc["not_judged"] == []
    assert doc["schema"] == "sca-center-kernel-versions/2" and doc["judged"] == [A]
    assert log.count(f"--kernel-version {A}") == 2                        # kernel_config.py 與 kernel_module_map.py 都收到


def test_two_kernels_nothing_given_judges_all(tmp_path):
    """沒指定、映像有 2 顆（M7d-1，D-061 (1)）：全部逐顆判定，basis auto-detected。假的工具對每次呼叫都回 OK。"""
    rows, doc, log, p = kernel_run(tmp_path, two_kernels())
    assert names(doc) == [A, B] and doc["requested"] == [] and jv(doc) == [A, B] and doc["not_judged"] == []
    assert {x["basis"] for x in doc["judged"]} == {"auto-detected"}
    assert not any(k.startswith("C-kernel-not-judged") for k in rows)
    assert "LIST" not in log                                               # 不另外讀映像：出貨的核心來自第一次判定時順便列出的那一行
    lines = [l for l in log.splitlines() if l.startswith("kernel_")]
    # 第一次（沒指定、工具會 GAP）只跑 kernel_config.py；之後每顆各跑 kernel_config.py 與 kernel_module_map.py
    assert lines[0].startswith("kernel_config.py") and "--kernel-version" not in lines[0]
    assert sum(1 for l in lines if l.startswith("kernel_config.py") and f"--kernel-version {A}" in l) == 1
    assert sum(1 for l in lines if l.startswith("kernel_module_map.py") and f"--kernel-version {B}" in l) == 1
    assert len(lines) == 5 and not any(l.startswith("kernel_module_map.py") and "--kernel-version" not in l for l in lines)
    out = tmp_path / "out" / "scan"
    for v in (A, B):                                                        # 每顆各一份，不寫 scan/kernel-config.json
        assert (out / "kernels" / v / "kernel-config.json").exists() and (out / "kernels" / v / "kernel-module-map.json").exists()
        x = next(j for j in doc["judged"] if j["version"] == v)
        assert x["config_file"] == f"scan/kernels/{v}/kernel-config.json" and x["module_map_file"] == f"scan/kernels/{v}/kernel-module-map.json"
        assert (x["config_status"], x["module_map_status"]) == ("OK", "OK")
    assert not (out / "kernel-config.json").exists() and not (out / "kernel-module-map.json").exists()
    for stage in ("C-kernel-config", "C-kernel-module-map"):               # 兩個階段各一列，說明逐顆列出
        st, detail = rows[stage]
        assert st == "OK" and "逐顆判定 2 顆" in detail and "auto-detected" in detail and f"核心 {A}" in detail and f"核心 {B}" in detail
    assert len([l for l in (tmp_path / "out" / "status.tsv").read_text(encoding="utf-8").splitlines() if l.startswith("C-kernel-config\t")]) == 1


def test_two_kernels_status_is_the_worst_one(tmp_path):
    """逐顆判定的狀態取最差的一顆（FAIL > GAP > ATTENTION > OK），說明逐顆列出。"""
    rows, doc, log, p = kernel_run(tmp_path, two_kernels(), [A, B], fake_status_by_version={A: "OK", B: "GAP"})
    for stage in ("C-kernel-config", "C-kernel-module-map"):
        st, detail = rows[stage]
        assert st == "GAP" and f"核心 {A}：OK" in detail and f"核心 {B}：GAP" in detail and "project-specified" in detail
    assert [(x["version"], x["config_status"], x["module_map_status"]) for x in doc["judged"]] == [(A, "OK", "OK"), (B, "GAP", "GAP")]
    for order in ({A: "ATTENTION", B: "OK"}, {A: "OK", B: "ATTENTION"}):
        r2, d2, l2, p2 = kernel_run(sub(tmp_path, "o" + "".join(order.values())), two_kernels(), [A, B], fake_status_by_version=order)
        assert r2["C-kernel-config"][0] == "ATTENTION"
    r3, d3, l3, p3 = kernel_run(sub(tmp_path, "f"), two_kernels(), [A, B], fake_status_by_version={A: "FAIL", B: "GAP"})
    assert r3["C-kernel-config"][0] == "FAIL" and not (tmp_path / "f" / "out" / "scan" / "kernels" / A / "kernel-config.json").exists()


def test_two_kernels_one_missing_result_is_not_ok(tmp_path):
    """其中一顆沒有結果（工具 NOT_RUN；有 KERNEL_CVES 清單所以不再找清單來源），別顆有：整體至少 GAP，沒有結果不是 OK。"""
    cl = tmp_path / "cves.txt"
    cl.write_text("CVE-2024-0001\n")
    rows, doc, log, p = kernel_run(sub(tmp_path, "m"), two_kernels(), [A, B], fake_status_by_version={A: "OK", B: "NOT_RUN"}, kernel_cves=str(cl))
    assert rows["C-kernel-config"][0] == "GAP" and f"核心 {B}：沒有結果" in rows["C-kernel-config"][1]
    assert rows["C-kernel-module-map"][0] == "GAP"
    x = next(j for j in doc["judged"] if j["version"] == B)
    assert x["config_status"] is None and x["config_file"] is None
    # 全部都沒有結果（沒有核心 CVE）：不寫兩個階段的狀態列（和只判定 1 顆時相同）
    r2, d2, l2, p2 = kernel_run(sub(tmp_path, "n"), two_kernels(), [A, B], fake_status="NOT_RUN", kernel_cves=str(cl))
    assert "C-kernel-config" not in r2 and "C-kernel-module-map" not in r2


def test_two_kernels_cve_list_failure_judges_none(tmp_path):
    """沒有核心 CVE（Grype、DT 都沒有）又沒有清單來源：kernel_cve_list 寫 GAP 的狀態列（多顆時探測不出是哪一個），不逐顆判定、不寫 scan/kernels。"""
    rows, doc, log, p = kernel_run(sub(tmp_path, "z"), two_kernels(), [A, B], fake_status="NOT_RUN")
    assert rows["C-kernel-cve-list"][0] == "GAP" and rows["C-kernel-config"][0] == "GAP" and rows["C-kernel-module-map"][0] == "GAP"
    assert not any(l.startswith("kernel_module_map.py") for l in log.splitlines())


def test_two_kernels_one_given(tmp_path):
    rows, doc, log, p = kernel_run(tmp_path, two_kernels(), [A])
    assert names(doc) == [A, B] and doc["requested"] == [A] and jv(doc) == [A]
    assert "LIST" not in log
    assert doc["not_judged"] == [{"version": B, "reason": kvmod.REASON_OTHER_GIVEN, "shipped": True}]
    assert log.count(f"--kernel-version {A}") == 2 and B not in log        # 指定的那顆交給工具
    assert rows[f"C-kernel-not-judged-{B}"][0] == "GAP" and f"C-kernel-not-judged-{A}" not in rows
    for stage in ("C-kernel-config", "C-kernel-module-map"):               # 工具回 OK，但還有核心沒判定 → 至少 GAP
        st, detail = rows[stage]
        assert st == "GAP" and detail.startswith("判定完成（假的工具）") and "；映像出貨的核心" in detail and B in detail and "記錄證據" in detail


def test_two_kernels_two_given_judges_both(tmp_path):
    """指定 2 顆（M7d-1）：逐顆判定，不再是一顆都不判定。"""
    rows, doc, log, p = kernel_run(tmp_path, two_kernels(), [A, B])
    assert "LIST" not in log                                               # 出貨的核心來自判定工具讀映像的同一趟
    assert names(doc) == [A, B] and doc["requested"] == [A, B] and jv(doc) == [A, B] and doc["not_judged"] == []
    assert {x["basis"] for x in doc["judged"]} == {"project-specified"}
    for v in (A, B):
        assert log.count(f"--kernel-version {v}") == 2                     # kernel_config.py 與 kernel_module_map.py 各一次
        assert not any(k == f"C-kernel-not-judged-{v}" for k in rows)
    for stage in ("C-kernel-config", "C-kernel-module-map"):
        assert rows[stage][0] == "OK" and "project-specified" in rows[stage][1]


def test_two_given_plus_one_unspecified_is_not_judged(tmp_path):
    """只指定一部分（3 顆映像、指定 2 顆）：沒指定的出貨核心照舊 not_judged＋GAP，兩個階段至少 GAP。"""
    third = "6.1.130"
    members = two_kernels() + [(f"usr/lib/modules/{third}/kernel/x.ko", b"x", None)]
    rows, doc, log, p = kernel_run(tmp_path, members, [A, B])
    assert jv(doc) == [A, B] and [x["version"] for x in doc["not_judged"]] == [third]
    assert rows[f"C-kernel-not-judged-{third}"][0] == "GAP"
    for stage in ("C-kernel-config", "C-kernel-module-map"):
        st, detail = rows[stage]
        assert st == "GAP" and third in detail and "逐顆判定 2 顆" in detail


def test_two_kernels_requested_not_shipped(tmp_path):
    """指定的核心映像沒有：照樣交給工具（真的工具回 GAP，同指定 1 顆）。"""
    rows, doc, log, p = kernel_run(tmp_path, tkc.rootfs_members(kver=A), [A, "6.9.9"])
    assert jv(doc) == [A, "6.9.9"] and log.count("--kernel-version 6.9.9") == 2


def test_auto_detect_rejects_bad_version_names(tmp_path):
    """映像的模組資料夾名稱不合法（含 ; 之類）：不自動逐顆判定（版本會成為路徑的一段），kernel_versions.py 拒收，記 FAIL＋兩個階段至少 GAP。"""
    members = tkc.rootfs_members(kver=A) + [("usr/lib/modules/a;b/kernel/x.ko", b"x", None)]
    rows, doc, log, p = kernel_run(tmp_path, members)
    assert not (tmp_path / "out" / "scan" / "kernels").exists()
    assert rows["C-kernel-versions"][0] == "FAIL"
    assert rows["C-kernel-config"][0] == "GAP"


def test_per_kernel_dir_never_escapes_scan(tmp_path):
    """指定的版本字串含 / 或 .. 在 sca-scan 的參數檢查就被拒（exit 64）；這裡再確認 kernel_versions.py 與區段不接受。"""
    for bad in ("a/b", "../x", "a;b"):
        p, _ = run_kv(tmp_path, "--shipped", A, "--requested", bad)
        assert p.returncode == 3, bad


def test_rerun_removes_old_file():
    """同一個 --out 重跑：區段開頭先刪掉舊的 kernel-versions.json（這次沒有核心可記時不留上一次的）。"""
    assert 'rm -f "$KVF"' in block_text()


def test_no_kernel_module_dir_with_given_version(tmp_path):
    """映像沒有模組資料夾（只有指定的版本）：shipped 是空的，指定的照樣交給工具判定（由工具回 GAP）；沒有 not_judged。"""
    rows, doc, log, p = kernel_run(tmp_path, [("etc/passwd", b"x", None)], [A])
    assert doc["shipped"] == [] and jv(doc) == [A] and doc["not_judged"] == []
    assert log.count(f"--kernel-version {A}") == 2


def test_nothing_to_record_writes_no_file(tmp_path):
    rows, doc, log, p = kernel_run(tmp_path, [("etc/passwd", b"x", None)])
    assert doc is None and not any(k.startswith("C-kernel-not-judged") for k in rows)


# ---------- sca-scan：核心 CVE 清單（kernel_cve_list）指定 1 顆時不探測 ----------

def cve_list_harness(tmp_path, members, kvers, mirror):
    src = tkc.write_tar(tmp_path / "h.tar", members)
    out = tmp_path / "outc"
    (out / "scan").mkdir(parents=True)
    pybin = Path(sys.executable).parent
    kv = " ".join(f"'{v}'" for v in kvers)
    script = f"""set -u
ROOT={ROOT}
OUT={out}; ST=$OUT/status.tsv
status(){{ printf '%s\\t%s\\t%s\\n' "$1" "$2" "${{3:-}}" >> "$ST"; }}
KSRC=(--from {src}); KLABEL="rootfs tar"; KCVL=; KCVO=; KERNEL_CVES=
KERNEL_CVE_MIRROR={mirror}
KVERS=({kv}); KSHIP_OK=0; KSHIP=()
{fn('kernel_ship_from')}
{fn('kernel_cve_list')}
kernel_cve_list; echo "rc=$?"; echo "KCVO=$KCVO"
"""
    p = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=120, env={**os.environ, "PATH": f"{pybin}:{os.environ['PATH']}"})
    rows = {}
    if (out / "status.tsv").exists():
        for l in (out / "status.tsv").read_text(encoding="utf-8").splitlines():
            a = l.split("\t")
            rows[a[0]] = (a[1], a[2])
    return int(re.search(r"rc=(\d+)", p.stdout).group(1)), rows, p.stdout, p


def test_cve_list_uses_given_version_without_probe(tmp_path):
    mirror = tcv.make_mirror(tmp_path / "m")
    # 兩顆核心、沒指定：探測不出是哪一個 → GAP（不猜）
    rc, rows, out, p = cve_list_harness(tmp_path, two_kernels(), [], mirror)
    assert rc == 1 and rows["C-kernel-cve-list"][0] == "GAP" and "不猜" in rows["C-kernel-cve-list"][1]
    # 指定 1 顆：用它產生清單（說明裡的版本就是指定的那一顆）
    (tmp_path / "s").mkdir()
    rc, rows, out, p = cve_list_harness(tmp_path / "s", two_kernels(), [A], mirror)
    assert rc == 0, out + p.stderr
    assert A in rows["C-kernel-cve-list"][1] and "kernel-cna-version" in out and B not in rows["C-kernel-cve-list"][1]


# ---------- 讀映像的同一趟順便列出出貨的核心（--also-list-kernel-versions） ----------

def test_also_list_kernel_versions_in_the_same_pass(tmp_path):
    src = tkc.write_tar(tmp_path / "x.tar", two_kernels())
    cves = tmp_path / "cves.txt"
    cves.write_text("CVE-2024-0001\n")
    kmm = PILOT / "lib" / "kernel_module_map.py"
    want = f"KERNEL-VERSIONS\tOK\t{A} {B}"

    def run_tool(lib, *extra):
        p = subprocess.run([sys.executable, "-I", str(lib), "--from", str(src), "--cves", str(cves), "--out", str(tmp_path / "o.json"), *extra],
                           capture_output=True, text=True, timeout=120)
        return p.stdout.splitlines()
    for lib, stage in ((tkc.LIB, "C-kernel-config"), (kmm, "C-kernel-module-map")):
        plain = run_tool(lib)
        assert not any(l.startswith("KERNEL-VERSIONS") for l in plain) and any(l.startswith(stage + "\t") for l in plain)    # 沒給旗標：輸出和以前相同
        got = run_tool(lib, "--also-list-kernel-versions")
        assert want in got and [l for l in got if l != want] == plain
    p = subprocess.run([sys.executable, "-I", str(tkc.LIB), "--probe-kernel-version", "--also-list-kernel-versions", "--from", str(src)],
                       capture_output=True, text=True, timeout=60)
    assert want in p.stdout.splitlines() and any(l.startswith("KERNEL-VERSION\tGAP") for l in p.stdout.splitlines())


# ---------- 上游版本（schema /2 的 shipped 物件） ----------

def up(version, source, param=None):
    return kvmod.upstream_of(version, source, param)


def test_upstream_from_source_makefile():
    x = up("6.8.12-1021-tegra", ("OK", "6.8.12"))
    assert x == {"version": "6.8.12-1021-tegra", "upstream_version": "6.8.12", "upstream_basis": "source-makefile",
                 "upstream_note": "原始碼 Makefile 是 6.8.12，與出貨核心 6.8.12-1021-tegra 相符"}
    for v in ("6.8.12", "6.8.12+rpt-rpi-2712", "6.8.12-v8"):
        assert up(v, ("OK", "6.8.12"))["upstream_version"] == "6.8.12"
    for v in ("6.8.120", "6.8.1", "6.8.12.1", "6.8.12_x", "16.8.12", "6.1.0-rpi"):         # 前綴要接 -、+ 或結尾
        x = up(v, ("OK", "6.8.12"))
        assert x["upstream_version"] is None and x["upstream_basis"] is None
        assert f"原始碼 Makefile 是 6.8.12，出貨核心 {v} 不是它編的" == x["upstream_note"]


def test_upstream_never_guessed_from_the_version_string():
    x = up("6.8.12-1021-tegra", None)
    assert x["upstream_version"] is None and x["upstream_basis"] is None and x["upstream_note"] == "沒有核心原始碼（--kernel-source），不推測上游版本"
    x = up("6.8.12-1021-tegra", ("GAP", "原始碼樹最上層的 Makefile 讀不到"))
    assert x["upstream_version"] is None and "Makefile 讀不到" in x["upstream_note"] and "不推測" in x["upstream_note"]


def test_upstream_platform_param():
    mk = ("OK", "6.8.12")
    x = up("6.8.12-1021-tegra", mk, "6.8.12")                      # 一致
    assert (x["upstream_version"], x["upstream_basis"]) == ("6.8.12", "source-makefile+platform-param")
    x = up("6.8.12-1021-tegra", mk, "6.8.13")                      # 不一致：都不採用，note 寫兩個值
    assert x["upstream_version"] is None and x["upstream_basis"] is None and "6.8.12" in x["upstream_note"] and "6.8.13" in x["upstream_note"]
    x = up("6.8.12-1021-tegra", None, "6.8.12")                    # 沒有原始碼：填給的值
    assert (x["upstream_version"], x["upstream_basis"]) == ("6.8.12", "platform-param") and "沒有原始碼可核對" in x["upstream_note"]
    x = up("6.1.0-rpi", mk, "6.1.0")                               # Makefile 不是這顆核心的：同樣沒有可核對的原始碼
    assert (x["upstream_version"], x["upstream_basis"]) == ("6.1.0", "platform-param")
    assert "沒有原始碼可核對" in x["upstream_note"] and "6.8.12" in x["upstream_note"]
    x = up("6.1.0-rpi", mk, None)
    assert x["upstream_version"] is None


def test_plan_compares_each_shipped_kernel_separately():
    p = kvmod.plan(["6.8.12-v8", "6.1.0-rpi"], [], ("OK", "6.8.12"))
    by = {x["version"]: x for x in p["shipped"]}
    assert by["6.8.12-v8"]["upstream_version"] == "6.8.12" and by["6.8.12-v8"]["upstream_basis"] == "source-makefile"
    assert by["6.1.0-rpi"]["upstream_version"] is None and "6.8.12" in by["6.1.0-rpi"]["upstream_note"] and "6.1.0-rpi" in by["6.1.0-rpi"]["upstream_note"]
    assert p["schema"] == "sca-center-kernel-versions/3" and set(by["6.1.0-rpi"]) == {"version", "upstream_version", "upstream_basis", "upstream_note"}
    assert kvmod.plan(None, [A, B])["shipped"] is None                                    # 讀不出來：維持 null


def test_cli_upstream_arguments(tmp_path):
    p, doc = run_kv(tmp_path, "--shipped", "6.8.12-v8", "--shipped", "6.1.0-rpi", "--source-version", "6.8.12",
                    "--upstream-version", "6.1.0-rpi=6.1.0", "--upstream-version", "6.8.12-v8=6.8.12", "--upstream-version", "9.9.9-x=9.9.9")
    assert p.returncode == 0, p.stdout
    by = {x["version"]: x for x in doc["shipped"]}
    assert by["6.8.12-v8"]["upstream_basis"] == "source-makefile+platform-param"
    assert by["6.1.0-rpi"]["upstream_basis"] == "platform-param" and by["6.1.0-rpi"]["upstream_version"] == "6.1.0"
    assert "KERNEL-UPSTREAM-PARAM-UNUSED\t9.9.9-x" in p.stdout
    p, doc = run_kv(tmp_path, "--shipped", A, "--source-gap", "原始碼樹最上層的 Makefile 讀不到")
    assert doc["shipped"][0]["upstream_version"] is None and "讀不到" in doc["shipped"][0]["upstream_note"]
    p, doc = run_kv(tmp_path, "--shipped", A)
    assert doc["shipped"][0]["upstream_note"] == "沒有核心原始碼（--kernel-source），不推測上游版本"
    for bad in (["--source-version", "6.8"], ["--source-version", "6.8.12", "--source-gap", "x"], ["--upstream-version", "6.8.12"],
                ["--upstream-version", f"{A}=6.8"], ["--upstream-version", f"{A}=6.8.12", "--upstream-version", f"{A}=6.8.13"]):
        p, _ = run_kv(tmp_path, "--shipped", A, *bad)
        assert p.returncode == 3 and p.stdout.startswith("KERNEL-VERSIONS-ERROR"), bad


def test_source_tree_version_tool(tmp_path):
    def tree_ver(root):
        p = subprocess.run([sys.executable, "-I", str(tkc.LIB), "--source-tree-version", str(root)], capture_output=True, text=True, timeout=60)
        return p.returncode, p.stdout.strip().split("\t")
    t = sub(tmp_path, "t")
    (t / "Makefile").write_text("# SPDX\nVERSION = 6\nPATCHLEVEL = 8\nSUBLEVEL = 12\nEXTRAVERSION =\nNAME = x\n")
    assert tree_ver(t) == (0, ["KERNEL-TREE-VERSION", "OK", "6.8.12"])
    t2 = sub(tmp_path, "t2")
    (t2 / "Makefile").write_text("VERSION = 6\nPATCHLEVEL = 8\n")                      # 沒有 SUBLEVEL：讀不出 X.Y.Z
    assert tree_ver(t2)[1][:2] == ["KERNEL-TREE-VERSION", "GAP"]
    assert tree_ver(sub(tmp_path, "t3"))[1][:2] == ["KERNEL-TREE-VERSION", "GAP"]          # 沒有 Makefile
    t4 = sub(tmp_path, "t4")
    (t4 / "Makefile").symlink_to(t / "Makefile")                                          # 符號連結不跟隨
    assert tree_ver(t4)[1][:2] == ["KERNEL-TREE-VERSION", "GAP"]


MAKEFILE = "VERSION = 6\nPATCHLEVEL = 1\nSUBLEVEL = 118\nEXTRAVERSION =\n"


def test_sca_scan_fills_upstream_per_kernel(tmp_path):
    members = tkc.rootfs_members(kver="6.1.118-v8") + [("usr/lib/modules/6.1.0-rpi/kernel/x.ko", b"x", None)]
    tree = sub(tmp_path, "tree")
    (tree / "Makefile").write_text(MAKEFILE)
    rows, doc, log, p = kernel_run(sub(tmp_path, "a"), members, source_dir=tree)
    by = {x["version"]: x for x in doc["shipped"]}
    assert by["6.1.118-v8"]["upstream_version"] == "6.1.118" and by["6.1.118-v8"]["upstream_basis"] == "source-makefile"
    assert by["6.1.0-rpi"]["upstream_version"] is None and "原始碼 Makefile 是 6.1.118，出貨核心 6.1.0-rpi 不是它編的" == by["6.1.0-rpi"]["upstream_note"]
    # 沒有 --kernel-source：全部 null，不推測
    rows, doc, log, p = kernel_run(sub(tmp_path, "b"), members)
    assert all(x["upstream_version"] is None and x["upstream_note"] == "沒有核心原始碼（--kernel-source），不推測上游版本" for x in doc["shipped"])
    # 原始碼讀不出版本：null，note 寫原因
    (tree / "Makefile").write_text("nothing\n")
    rows, doc, log, p = kernel_run(sub(tmp_path, "c"), members, source_dir=tree)
    assert all(x["upstream_version"] is None and "讀不出" in x["upstream_note"] for x in doc["shipped"])
    # 一顆核心的映像（Jetson 型）：除了 shipped 的物件形式，其他欄位與狀態和以前相同
    (tree / "Makefile").write_text(MAKEFILE)
    rows, doc, log, p = kernel_run(sub(tmp_path, "d"), tkc.rootfs_members(kver="6.1.118-v8"), source_dir=tree)
    assert jv(doc) == ["6.1.118-v8"] and doc["not_judged"] == [] and doc["shipped"][0]["upstream_version"] == "6.1.118"
    assert rows["C-kernel-config"][0] == "OK" and not any(k.startswith("C-kernel-not-judged") for k in rows)


def test_sca_scan_passes_platform_upstream_version(tmp_path):
    """--kernel-upstream-version（KUPS）→ kernel_versions.py --upstream-version：和 Makefile 一致 → source-makefile+platform-param；不一致 → null。"""
    tree = sub(tmp_path, "tree")
    (tree / "Makefile").write_text(MAKEFILE)
    members = tkc.rootfs_members(kver="6.1.118-v8")
    rows, doc, log, p = kernel_run(sub(tmp_path, "a"), members, source_dir=tree, kups=("6.1.118-v8=6.1.118",))
    x = doc["shipped"][0]
    assert (x["upstream_version"], x["upstream_basis"]) == ("6.1.118", "source-makefile+platform-param")
    rows, doc, log, p = kernel_run(sub(tmp_path, "b"), members, source_dir=tree, kups=("6.1.118-v8=6.1.119",))
    assert doc["shipped"][0]["upstream_version"] is None and "不一致" in doc["shipped"][0]["upstream_note"]


# ---------- 逐顆判定：真的 kernel_config.py、kernel_module_map.py 對合成的兩顆核心（不同的 .config） ----------

RECORDS2 = dict(tkc.RECORDS, **{"CVE-2024-0006": ["drivers/bar/baz_main.c"]})        # CONFIG_BAZ 兩顆都沒開 → 兩顆都沒編進核心


RA, RB = "6.8.12-1021-tegra", "6.8.12-1099-tegra"          # 合成的 .config 標頭是 6.8.12：版本要對得上，工具才不 GAP


def two_real_kernels():
    """兩顆核心，各自有 /usr/lib/modules/<版本>/ 與 /usr/src/linux-headers-<版本>…/.config：B 的 CONFIG_FOO_A 開了（A 沒開）。"""
    ma = tkc.rootfs_members(kver=RA)
    mb = [(n, (tkc.CONFIG.replace("# CONFIG_FOO_A is not set", "CONFIG_FOO_A=y").encode() if n.endswith("/.config") else d), l)
          for n, d, l in tkc.rootfs_members(kver=RB)]
    return ma + mb


def real_run(tmp_path, kvers=(), members=None):
    mirror = tkc.make_mirror(tmp_path / "mirror", records=RECORDS2)
    return kernel_run(tmp_path, members or two_real_kernels(), kvers, real_tools=True, grype_doc=tkc.grype(list(RECORDS2)), mirror=str(mirror))


def per_kernel_results(tmp_path, v):
    d = tmp_path / "out" / "scan" / "kernels" / v
    return json.loads((d / "kernel-config.json").read_text(encoding="utf-8")), json.loads((d / "kernel-module-map.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("given", [(), (RA, RB)])
def test_real_tools_two_kernels_each_judged_with_its_own_config(tmp_path, given):
    """沒指定（映像自己列出，auto-detected）與指定 2 顆（project-specified）：每顆用自己的 .config，結果不同；kernel-versions.json 是 /3。"""
    rows, doc, log, p = real_run(tmp_path, given)
    assert names(doc) == [RA, RB] and jv(doc) == [RA, RB] and doc["not_judged"] == [] and doc["schema"] == kvmod.SCHEMA
    basis = "project-specified" if given else "auto-detected"
    assert [(x["version"], x["basis"], x["config_status"], x["module_map_status"]) for x in doc["judged"]] == [(RA, basis, "OK", "OK"), (RB, basis, "OK", "OK")]
    ca, ma = per_kernel_results(tmp_path, RA)
    cb, mb = per_kernel_results(tmp_path, RB)
    assert ca["kernel"]["version"] == RA and cb["kernel"]["version"] == RB
    assert ca["kernel"]["config_sha256"] != cb["kernel"]["config_sha256"] and ca["kernel"]["config_sha256"] == hashlib.sha256(tkc.CONFIG.encode()).hexdigest()
    da = {r["cve"]: r["decision"] for r in ca["results"]}
    db = {r["cve"]: r["decision"] for r in cb["results"]}
    assert da["CVE-2024-0001"] == "not_affected" and db["CVE-2024-0001"] == "affected"            # CONFIG_FOO_A：RA 沒開、RB 開了
    assert da["CVE-2024-0006"] == db["CVE-2024-0006"] == "not_affected"
    assert da["CVE-2024-0002"] == db["CVE-2024-0002"] == "affected"
    assert ma["kernel"]["version"] == RA and mb["kernel"]["version"] == RB
    for stage in ("C-kernel-config", "C-kernel-module-map"):
        st, detail = rows[stage]
        assert st == "OK" and basis in detail and f"核心 {RA}" in detail and f"核心 {RB}" in detail
    assert not (tmp_path / "out" / "scan" / "kernel-config.json").exists()
    assert not any(k.startswith("C-kernel-not-judged") for k in rows)
    # 讀取端（cra_report／vex_export）：每顆各自的結果合併，只有「兩顆都沒編進核心」的排除
    sys.path.insert(0, str(ROOT / "tools" / "cra"))
    import vex_export as vx
    docs = {v: per_kernel_results(tmp_path, v)[0] for v in (RA, RB)}
    merged = vx.kernel_multi_doc(docs, doc)
    got = {x["cve"]: x["decision"] for x in merged["results"]}
    assert got["CVE-2024-0001"] == "affected" and got["CVE-2024-0006"] == "not_affected" and got["CVE-2024-0002"] == "affected"
    assert {c for c, d in got.items() if d == "not_affected"} == {c for c in da if da[c] == db[c] == "not_affected"}


def test_real_tools_one_requested_of_two_keeps_the_other_not_judged(tmp_path):
    rows, doc, log, p = real_run(tmp_path, (RA,))
    assert jv(doc) == [RA] and [x["version"] for x in doc["not_judged"]] == [RB]
    assert doc["schema"] == "sca-center-kernel-versions/2" and doc["judged"] == [RA]      # 只判定 1 顆：照舊 /2、寫 scan/kernel-config.json
    assert (tmp_path / "out" / "scan" / "kernel-config.json").exists() and not (tmp_path / "out" / "scan" / "kernels").exists()
    assert rows[f"C-kernel-not-judged-{RB}"][0] == "GAP" and rows["C-kernel-config"][0] == "GAP"


def test_real_tools_single_kernel_files_are_unchanged(tmp_path):
    """只有 1 顆核心：寫 scan/kernel-config.json 與 scan/kernel-module-map.json（沒有 scan/kernels/），內容與直接執行工具相同。"""
    rows, doc, log, p = real_run(tmp_path, (), members=tkc.rootfs_members(kver=RA))
    out = tmp_path / "out" / "scan"
    assert (out / "kernel-config.json").exists() and (out / "kernel-module-map.json").exists() and not (out / "kernels").exists()
    assert doc["schema"] == "sca-center-kernel-versions/2" and doc["judged"] == [RA]
    direct = tmp_path / "direct.json"
    q = subprocess.run([sys.executable, "-I", str(tkc.LIB), "--grype", str(out / "grype.json"), "--mirror", str(tmp_path / "mirror"), "--from",
                        str(tmp_path / "r.tar"), "--out", str(direct)], capture_output=True, text=True, timeout=120)
    assert q.returncode == 0
    a, b = json.loads(direct.read_text(encoding="utf-8")), json.loads((out / "kernel-config.json").read_text(encoding="utf-8"))
    assert a == b


# ---------- 單顆核心時 kernel-versions.json 和改前（main 4f64db7）逐位元組相同 ----------

BASELINE = Path(__file__).resolve().parent / "data" / "kernel_versions_single_baseline"
# 名稱 → kernel_versions.py 的參數（judged 0 或 1 顆的各種情形；--out 另外給）
SINGLE_CASES = {
    "one-shipped": ["--shipped", A],
    "one-shipped-upstream": ["--shipped", A, "--source-version", "6.1.118", "--upstream-version", f"{A}=6.1.118"],
    "one-shipped-no-source": ["--shipped", A, "--source-gap", "原始碼樹最上層的 Makefile 讀不到"],
    "one-requested-of-two": ["--shipped", A, "--shipped", B, "--requested", A],
    "one-requested-not-shipped": ["--shipped", A, "--requested", "6.9.9"],
    "requested-shipped-unknown": ["--shipped-unknown", "--requested", A],
    "requested-only": ["--requested", A],
}


def test_single_kernel_file_is_byte_identical_to_main(tmp_path):
    """judged 0 或 1 顆時 kernel-versions.json 照舊寫 schema /2，和 M7d-1 之前（main 4f64db7）的輸出逐位元組相同；
    基準檔用改前的 kernel_versions.py 對同樣的參數產生（C4 的平台標準答案與 Release 附件都釘這個格式）。
    KERNEL_VERSIONS_BASE_PY 給改前的 kernel_versions.py 時，另外直接比對（開發用）。"""
    base = os.environ.get("KERNEL_VERSIONS_BASE_PY")
    for name, args in SINGLE_CASES.items():
        out = tmp_path / f"{name}.json"
        p = subprocess.run([sys.executable, "-I", str(KV), "--out", str(out), *args], capture_output=True, text=True, timeout=60)
        assert p.returncode == 0, (name, p.stdout)
        got = out.read_bytes()
        if base and os.environ.get("KERNEL_VERSIONS_WRITE") == "1":
            ref = tmp_path / f"{name}.base.json"
            q = subprocess.run([sys.executable, "-I", base, "--out", str(ref), *args], capture_output=True, text=True, timeout=60)
            assert q.returncode == 0 and q.stdout == p.stdout, name
            BASELINE.mkdir(parents=True, exist_ok=True)
            (BASELINE / f"{name}.json").write_bytes(ref.read_bytes())
            (BASELINE / f"{name}.stdout").write_text(q.stdout, encoding="utf-8")
        assert got == (BASELINE / f"{name}.json").read_bytes(), name
        assert p.stdout == (BASELINE / f"{name}.stdout").read_text(encoding="utf-8"), name           # stdout（KERNEL-NOT-JUDGED 等行）也相同
        assert json.loads(got)["schema"] == "sca-center-kernel-versions/2"
