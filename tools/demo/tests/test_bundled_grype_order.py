"""scan-flash-package.sh：UEFI／OP-TEE 內建函式庫的 Grype 比對（B-uefi-grype、B-tee-grype）在 sca-scan 之後才跑。
Grype 資料庫是 sca-scan 更新的（GRYPE_DB_UPDATE）；比對排在前面時，全新的機器（例如 CI）還沒有資料庫，完整掃描的比對一定 NOT_RUN，
分層重跑才有結果（兩份報告的列數對不上）。這裡用假的 sca-scan 模擬「更新資料庫」（寫一個標記檔），假的 grype 只有標記檔存在時
db status 才回報 valid：比對在 sca-scan 之前跑 → NOT_RUN，之後跑 → OK。
"""
import datetime
import os
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[1] / "cra" / "tests"))
import test_kernel_version_args as kva  # noqa: E402
import test_tee_source as tts  # noqa: E402

FAKE_SCA = """#!/bin/bash
out=; while [ $# -gt 0 ]; do case $1 in --out) out=$2;; esac; shift; done
mkdir -p "$out"; printf 'stage\\tstatus\\tdetail\\n' > "$out/status.tsv"
: > "$DB_MARKER"
exit 0
"""


def fake_grype(b, built):
    (b / "grype").write_text(f"""#!/bin/sh
case "$1" in
  db) [ -f "$DB_MARKER" ] || {{ echo 'Status: invalid'; exit 1; }}; printf 'Built: {built}\\nStatus: valid\\n';;
  sbom:*) echo '{{"matches": []}}';;
  *) echo 'Version: 0.0.0';;
esac
""")
    (b / "grype").chmod(0o755)


def uefi_tree(tmp_path):
    t = tmp_path / "uefi"
    ossl = t / "CryptoPkg" / "Library" / "OpensslLib" / "openssl"
    ossl.mkdir(parents=True)
    (ossl / "VERSION.dat").write_text("MAJOR=3\nMINOR=4\nPATCH=1\nPRE_RELEASE_TAG=\nBUILD_METADATA=\nRELEASE_DATE=\"1 Jan 2025\"\nSHLIB_VERSION=3\n")
    (t / "MdePkg").mkdir()
    (t / "MdePkg" / "MdePkg.dec").write_text("[Defines]\n")
    return t


def test_bundled_grype_runs_after_sca_scan_updates_the_database(tmp_path):
    script = kva.tool_tree(tmp_path)
    (Path(script).parents[1] / "pilot" / "sca-scan").write_text(FAKE_SCA)
    a, prev = kva.prev(tmp_path)
    tee = tts.tree(tmp_path / "tee")
    built = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    b = tmp_path / "bin"
    b.mkdir()
    fake_grype(b, built)
    (b / "bwrap").write_text("#!/bin/sh\necho 'Version: 0.0.0'\n")
    (b / "bwrap").chmod(0o755)
    e = {k: v for k, v in os.environ.items() if k != "SCA_KERNEL_VERSIONS"}
    e.update(PATH=f"{b}:{os.environ['PATH']}", FLASHPKG_ALLOW_TMP_OUT="1", SCA_TOOLS_DIR=str(tmp_path / "none"),
             DB_MARKER=str(tmp_path / "db-updated"))
    out = tmp_path / "r"
    args = ["--rescan-from", prev, "--archive", a, "--rootfs", "rootfs_no_gui", "--out", out, "--no-upload",
            "--uefi-source", uefi_tree(tmp_path), "--tee-source", tee]
    p = subprocess.run(["bash", str(script), *map(str, args)], capture_output=True, text=True, env=e, timeout=300)
    st = (out / "status.tsv").read_text()
    assert (tmp_path / "db-updated").exists(), st + p.stderr
    for k in ("uefi", "tee"):
        m = re.search(rf"^B-{k}-grype-rootfs_no_gui\t(\w+)\t(.*)$", st, re.M)
        assert m, f"B-{k}-grype missing:\n" + st + p.stderr
        assert m.group(1) == "OK", m.group(0)          # 排在 sca-scan 之前時這裡是 NOT_RUN（資料庫還沒更新）
        assert st.index(f"B-{k}-grype-rootfs_no_gui") > st.index("C-scan-rootfs_no_gui")
        assert st.index(f"B-{k}-source-rootfs_no_gui") < st.index("C-scan-rootfs_no_gui")    # 讀原始碼樹仍在 sca-scan 之前


def test_sca_scan_failure_still_writes_not_run(tmp_path):
    """sca-scan 失敗、資料庫沒更新：比對照樣跑，B-uefi-grype／B-tee-grype 記 NOT_RUN（資料庫不可用），不悄悄消失。"""
    script = kva.tool_tree(tmp_path)
    (Path(script).parents[1] / "pilot" / "sca-scan").write_text(FAKE_SCA.replace(': > "$DB_MARKER"\nexit 0', "exit 1"))
    a, prev = kva.prev(tmp_path)
    b = tmp_path / "bin"
    b.mkdir()
    fake_grype(b, "2026-01-01T00:00:00Z")
    (b / "bwrap").write_text("#!/bin/sh\necho 'Version: 0.0.0'\n")
    (b / "bwrap").chmod(0o755)
    e = {k: v for k, v in os.environ.items() if k != "SCA_KERNEL_VERSIONS"}
    e.update(PATH=f"{b}:{os.environ['PATH']}", FLASHPKG_ALLOW_TMP_OUT="1", SCA_TOOLS_DIR=str(tmp_path / "none"),
             DB_MARKER=str(tmp_path / "db-updated"))
    out = tmp_path / "r"
    args = ["--rescan-from", prev, "--archive", a, "--rootfs", "rootfs_no_gui", "--out", out, "--no-upload",
            "--uefi-source", uefi_tree(tmp_path), "--tee-source", tts.tree(tmp_path / "tee")]
    p = subprocess.run(["bash", str(script), *map(str, args)], capture_output=True, text=True, env=e, timeout=300)
    st = (out / "status.tsv").read_text()
    assert re.search(r"^C-scan-rootfs_no_gui\tFAIL\t", st, re.M), st + p.stderr
    for k in ("uefi", "tee"):
        assert re.search(rf"^B-{k}-grype-rootfs_no_gui\tNOT_RUN\tGrype database not usable", st, re.M), st


def test_import_failure_writes_not_run_for_both(tmp_path):
    """完整掃描 docker import 失敗（沒走到 sca-scan）：有讀原始碼樹的兩種比對都記 NOT_RUN，原因寫 sca-scan 沒有執行。"""
    import hashlib
    import test_flash_package as tfp
    a = str(tmp_path / "pkg.tbz2")
    tfp.make_archive(a, gui=False)
    (tmp_path / "pkg.tbz2.md5").write_text(f"{hashlib.md5(open(a, 'rb').read()).hexdigest()}  pkg.tbz2\n")
    out = tmp_path / "r"
    p = tfp.run_script(tmp_path, "--archive", a, "--rootfs", "rootfs_no_gui", "--name", "EX-J100", "--version", "V1", "--no-upload",
                       "--out", str(out), "--uefi-source", str(uefi_tree(tmp_path)), "--tee-source", str(tts.tree(tmp_path / "tee")))
    st = (out / "status.tsv").read_text()
    assert re.search(r"^B-import-rootfs_no_gui\tFAIL\t", st, re.M), st + p.stderr
    for k in ("uefi", "tee"):
        assert re.search(rf"^B-{k}-grype-rootfs_no_gui\tNOT_RUN\tdocker import 失敗，sca-scan 沒有執行", st, re.M), st
        assert not (out / "rootfs_no_gui" / f"{k}-source" / "grype-run.json").exists()


def test_full_scan_success_runs_grype_after_sca_scan(tmp_path):
    """完整掃描（不是 --rescan-from）成功的路徑：假 docker import 成功、假 sca-scan 寫標記檔（更新資料庫）。
    B-uefi-grype／B-tee-grype 各一列、OK，順序是 讀原始碼樹 → import → sca-scan → 比對。這條路徑就是完整報告少了 OP-TEE Mbed TLS 列的那條。"""
    import hashlib
    import test_flash_package as tfp
    script = kva.tool_tree(tmp_path)
    (Path(script).parents[1] / "pilot" / "sca-scan").write_text(FAKE_SCA)
    b = tmp_path / "bin"
    b.mkdir()
    fake_grype(b, datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    for t in ("syft", "bwrap"):
        (b / t).write_text("#!/bin/sh\necho 'Version: 0.0.0'\n")
    (b / "docker").write_text(f"#!/bin/sh\ncase \"$1\" in info) echo {tmp_path};; version) echo 0;; import) echo sha256:{'a' * 64};; "
                              "image) case \"$2\" in inspect) echo 'arm64 1 bytes';; *) exit 0;; esac;; *) exit 1;; esac\n")
    for f in b.iterdir():
        f.chmod(0o755)
    a = str(tmp_path / "pkg.tbz2")
    tfp.make_archive(a, gui=False)
    (tmp_path / "pkg.tbz2.md5").write_text(f"{hashlib.md5(open(a, 'rb').read()).hexdigest()}  pkg.tbz2\n")
    e = {k: v for k, v in os.environ.items() if k != "SCA_KERNEL_VERSIONS"}
    e.update(PATH=f"{b}:{os.environ['PATH']}", FLASHPKG_ALLOW_TMP_OUT="1", SCA_TOOLS_DIR=str(tmp_path / "none"),
             DB_MARKER=str(tmp_path / "db-updated"))
    out = tmp_path / "r"
    args = ["--archive", a, "--rootfs", "rootfs_no_gui", "--name", "EX-J100", "--version", "V1", "--no-upload", "--out", out,
            "--uefi-source", uefi_tree(tmp_path), "--tee-source", tts.tree(tmp_path / "tee")]
    p = subprocess.run(["bash", str(script), *map(str, args)], capture_output=True, text=True, env=e, timeout=300)
    st = (out / "status.tsv").read_text()
    assert re.search(r"^B-import-rootfs_no_gui\tOK\t", st, re.M) and (tmp_path / "db-updated").exists(), st + p.stderr
    for k in ("uefi", "tee"):
        r = re.findall(rf"^B-{k}-grype-rootfs_no_gui\t(\w+)\t", st, re.M)
        assert r == ["OK"], st                         # 一列、OK（排在 sca-scan 之前是 NOT_RUN；刪掉那行就沒有這一列）
        assert st.index(f"B-{k}-source-") < st.index("B-import-") < st.index("C-scan-") < st.index(f"B-{k}-grype-")
