"""--kernel-version／SCA_KERNEL_VERSIONS：映像出貨的核心哪些有判定（scan/kernel-versions.json，lib/kernel_versions.py）。

全部用合成資料：假的 rootfs tar（兩個 /usr/lib/modules/<版本>/）。sca-scan 的核心區段（含 kernel_versions_prepare／kernel_versions_finish）
從 sca-scan 原文抽出來在 bash 裡真的執行；判定工具（kernel_config.py、kernel_module_map.py）用假的，記下收到的參數；
列出出貨核心（kernel_config.py --list-kernel-versions）與 kernel_versions.py 是真的。
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
import test_kernel_cna_version as tcv  # noqa: E402

PILOT = tkc.PILOT
ROOT = tkc.ROOT
SCAN = PILOT / "sca-scan"
KV = PILOT / "lib" / "kernel_versions.py"
sys.path.insert(0, str(PILOT / "lib"))
import kernel_versions as kvmod  # noqa: E402

A, B = "6.1.118", "6.1.120"          # 合成的核心版本
NOTE_MULTI = "多顆核心逐一判定還沒實作（M2 之後）"


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
    assert (names(p), p["requested"], p["judged"], p["not_judged"]) == ([A], [], [A], [])
    p = kvmod.plan([B, A], [])                               # 多顆、沒指定：都不判定（不猜）
    assert names(p) == [A, B] and p["judged"] == [] and [x["version"] for x in p["not_judged"]] == [A, B]
    assert {x["reason"] for x in p["not_judged"]} == {"沒有指定 --kernel-version"}
    p = kvmod.plan([A, B], [A])                              # 指定 1 顆：判定它，另一顆 not_judged
    assert p["judged"] == [A] and p["not_judged"] == [{"version": B, "reason": kvmod.REASON_OTHER_GIVEN, "shipped": True}]
    p = kvmod.plan([A, B], [A, B, A])                        # 指定 2 顆（重複的算一顆）：一顆都不判定
    assert p["requested"] == [A, B] and p["judged"] == [] and len(p["not_judged"]) == 2
    assert {x["reason"] for x in p["not_judged"]} == {NOTE_MULTI}
    p = kvmod.plan([A], ["6.9.9", A])                        # 指定的核心映像沒有：照樣記，原因寫明
    assert any(x["version"] == "6.9.9" and x["shipped"] is False and "沒有這顆核心的模組目錄" in x["reason"] for x in p["not_judged"])
    p = kvmod.plan(None, [A, B])                             # 出貨的核心讀不出來
    assert p["shipped"] is None and p["judged"] == [] and all(x["shipped"] is None for x in p["not_judged"])


def run_kv(tmp_path, *args):
    out = tmp_path / "kv.json"
    p = subprocess.run([sys.executable, "-I", str(KV), "--out", str(out), *args], capture_output=True, text=True, timeout=60)
    return p, (json.loads(out.read_text(encoding="utf-8")) if out.exists() else None)


def test_cli_writes_file_and_lines(tmp_path):
    p, doc = run_kv(tmp_path, "--shipped", A, "--shipped", B)
    assert p.returncode == 0 and doc["schema"] == kvmod.SCHEMA
    assert f"KERNEL-NOT-JUDGED\t{A}\t沒有指定 --kernel-version" in p.stdout and f"KERNEL-NOT-JUDGED\t{B}\t" in p.stdout
    note = next(l for l in p.stdout.splitlines() if l.startswith("KERNEL-VERSIONS-NOTE\t"))
    assert A in note and B in note and "必須記錄證據" in note and "設計文件" in note
    # 沒有東西可記：不寫檔
    (tmp_path / "kv.json").unlink()
    p, doc = run_kv(tmp_path)
    assert p.returncode == 0 and doc is None and p.stdout == ""
    # 1 顆、沒指定：寫檔但沒有 not_judged 行
    p, doc = run_kv(tmp_path, "--shipped", A)
    assert doc["judged"] == [A] and doc["not_judged"] == [] and p.stdout == ""
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
open(out, "w").write("{}")
print(f"{stage}\\t{os.environ.get('FAKE_STATUS', 'OK')}\\t判定完成（假的工具）")
"""


def block_text():
    i = SRC.index("KCF=$OUT/scan/kernel-config.json")
    return SRC[i:SRC.index("# ---- C-euvd", i)]


def kernel_run(tmp_path, members, kvers=(), fake_status="OK", source_dir=None, kups=()):
    """sca-scan 的核心區段（C-kernel-config、C-kernel-module-map 與核心出貨清單）在 bash 裡執行；判定工具是假的。"""
    root = tmp_path / "root"
    lib = root / "tools" / "pilot" / "lib"
    lib.mkdir(parents=True)
    for n in ("kernel_config.py", "kernel_module_map.py"):
        (lib / n).write_text(FAKE_TOOL)
    (lib / "kernel_versions.py").symlink_to(PILOT / "lib" / "kernel_versions.py")
    out = tmp_path / "out"
    (out / "scan").mkdir(parents=True)
    (out / "dt").mkdir()
    gr = out / "scan" / "grype.json"
    gr.write_text("{}")
    src = tkc.write_tar(tmp_path / "r.tar", members)
    log = tmp_path / "fake.log"
    kv = " ".join(f"'{v}'" for v in kvers)
    script = f"""set -uo pipefail
ROOT={root}; OUT={out}; ST=$OUT/status.tsv; printf 'stage\\tstatus\\tdetail\\n' > "$ST"
status(){{ printf '%s\\t%s\\t%s\\n' "$1" "$2" "${{3:-}}" >> "$ST"; }}
MODE=sbom; SBOM_OK=1; KBUILD={src}; KBUILD_PREFIX=; GR={gr}; KERNEL_CVE_MIRROR=; KERNEL_CVES=; SCA_KERNEL_VERSIONS=; KNONE=0; KOTHER=
{'KERNEL_SOURCE_DIR=' + str(source_dir) if source_dir else 'unset KERNEL_SOURCE_DIR'}
KVERS=({kv})
KUPS=({" ".join(f"'{v}'" for v in kups)})
{block_text()}
echo done
"""
    pybin = Path(sys.executable).parent
    env = {**os.environ, "PATH": f"{pybin}:{os.environ['PATH']}", "FAKE_LOG": str(log), "FAKE_STATUS": fake_status,
           "REAL_KERNEL_CONFIG": str(tkc.LIB)}
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
    assert names(doc) == [A] and doc["requested"] == [] and doc["judged"] == [A] and doc["not_judged"] == []
    # 指定的就是那一顆：判定它，工具收到 --kernel-version
    rows, doc, log, p = kernel_run(sub(tmp_path, "g"), tkc.rootfs_members(kver=A), [A])
    assert rows["C-kernel-config"][0] == "OK" and doc["judged"] == [A] and doc["not_judged"] == []
    assert log.count(f"--kernel-version {A}") == 2                        # kernel_config.py 與 kernel_module_map.py 都收到


def test_two_kernels_nothing_given(tmp_path):
    # 真的工具遇到多顆核心沒指定會 GAP（不猜）；假的工具回 OK 時，區段也要把兩個階段至少升到 GAP
    rows, doc, log, p = kernel_run(tmp_path, two_kernels())
    assert names(doc) == [A, B] and doc["requested"] == [] and doc["judged"] == []
    assert [x["version"] for x in doc["not_judged"]] == [A, B] and {x["reason"] for x in doc["not_judged"]} == {"沒有指定 --kernel-version"}
    for v in (A, B):
        st, detail = rows[f"C-kernel-not-judged-{v}"]
        assert st == "GAP" and "出貨但沒有判定" in detail and "沒有指定 --kernel-version" in detail and "記錄證據" in detail
    for stage in ("C-kernel-config", "C-kernel-module-map"):
        st, detail = rows[stage]
        assert st == "GAP" and A in detail and B in detail and "記錄證據" in detail and "設計文件" in detail
    assert "--kernel-version" not in log
    # 工具自己已經 GAP：維持 GAP，說明接上沒判定的核心
    rows, doc, log, p = kernel_run(sub(tmp_path, "x"), two_kernels(), fake_status="GAP")
    assert rows["C-kernel-config"][0] == "GAP" and "判定完成（假的工具）" in rows["C-kernel-config"][1] and "；映像出貨的核心" in rows["C-kernel-config"][1] and B in rows["C-kernel-config"][1]


def test_two_kernels_one_given(tmp_path):
    rows, doc, log, p = kernel_run(tmp_path, two_kernels(), [A])
    assert names(doc) == [A, B] and doc["requested"] == [A] and doc["judged"] == [A]
    assert "LIST" not in log
    assert doc["not_judged"] == [{"version": B, "reason": kvmod.REASON_OTHER_GIVEN, "shipped": True}]
    assert log.count(f"--kernel-version {A}") == 2 and B not in log        # 指定的那顆交給工具
    assert rows[f"C-kernel-not-judged-{B}"][0] == "GAP" and f"C-kernel-not-judged-{A}" not in rows
    for stage in ("C-kernel-config", "C-kernel-module-map"):               # 工具回 OK，但還有核心沒判定 → 至少 GAP
        st, detail = rows[stage]
        assert st == "GAP" and detail.startswith("判定完成（假的工具）") and "；映像出貨的核心" in detail and B in detail and "記錄證據" in detail


def test_two_kernels_two_given_judges_none(tmp_path):
    rows, doc, log, p = kernel_run(tmp_path, two_kernels(), [A, B])
    assert log == "LIST\n"                                                 # 判定工具一次都沒執行；沒有別的工具讀映像，只補讀這一次出貨的核心
    assert names(doc) == [A, B]
    assert doc["requested"] == [A, B] and doc["judged"] == []
    assert [x["version"] for x in doc["not_judged"]] == [A, B] and {x["reason"] for x in doc["not_judged"]} == {NOTE_MULTI}
    for stage in ("C-kernel-config", "C-kernel-module-map"):
        st, detail = rows[stage]
        assert st == "GAP" and NOTE_MULTI in detail
    for v in (A, B):
        assert rows[f"C-kernel-not-judged-{v}"][0] == "GAP" and NOTE_MULTI in rows[f"C-kernel-not-judged-{v}"][1]


def test_rerun_removes_old_file():
    """同一個 --out 重跑：區段開頭先刪掉舊的 kernel-versions.json（這次沒有核心可記時不留上一次的）。"""
    assert 'rm -f "$KVF"' in block_text()


def test_no_kernel_module_dir_with_given_version(tmp_path):
    """映像沒有模組資料夾（只有指定的版本）：shipped 是空的，指定的照樣交給工具判定（由工具回 GAP）；沒有 not_judged。"""
    rows, doc, log, p = kernel_run(tmp_path, [("etc/passwd", b"x", None)], [A])
    assert doc["shipped"] == [] and doc["judged"] == [A] and doc["not_judged"] == []
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
    assert p["schema"] == "sca-center-kernel-versions/2" and set(by["6.1.0-rpi"]) == {"version", "upstream_version", "upstream_basis", "upstream_note"}
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
    assert doc["judged"] == ["6.1.118-v8"] and doc["not_judged"] == [] and doc["shipped"][0]["upstream_version"] == "6.1.118"
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
