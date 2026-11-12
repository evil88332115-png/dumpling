"""compare_expected.py（對照 tests/expected）與殼層腳本（共用函式、sca-scan 參數檢查）的測試。不需要 DT、DejaCode、網路或掃描工具。"""
import json
import subprocess

import pytest

from pilot_fixtures import ALL_OK, PILOT, ROOT, dfind, gmatch, load_module, make_out, run_report

EXPECTED = ROOT / "tests" / "expected"
PY = "pkg:pypi/requests@2.19.0"
































# ---------- 殼層：共用函式（real-projects.sh 搬出來的）與 sca-scan 參數 ----------

def bash(script, *args):
    return subprocess.run(["bash", "-c", script, "_", *args], capture_output=True, text=True, timeout=60)


LIB = str(PILOT / "lib" / "common.sh")




def test_lib_govuln_count_without_config_is_x(tmp_path):
    f = tmp_path / "g.json"
    f.write_text('{"finding":{"osv":"GO-1"}}')
    assert bash(f'. "{LIB}"; govuln_count "$1"', str(f)).stdout.strip() == "x"




def test_lib_sbom_status(tmp_path):
    (tmp_path / "e.json").write_text('{"components":[]}')
    (tmp_path / "f.json").write_text('{"components":[{"name":"a"}]}')
    s = f'. "{LIB}"; status(){{ echo "$1|$2|$3"; }}; sbom_status A 0 "$1"; sbom_status B 0 "$2"; sbom_status C 1 "$2"; sbom_status D 0 "$3"'
    out = bash(s, str(tmp_path / "e.json"), str(tmp_path / "f.json"), str(tmp_path / "missing.json")).stdout.splitlines()
    assert out[0].startswith("A|NOT_ASSESSED|") and out[1] == "B|OK|1 components" and out[2] == "C|FAIL|exit=1" and out[3].startswith("D|FAIL|")


def _fake_grype(tmp_path):
    """假的 grype：db update／db import 依 UPX／IMX 退出；db status 印 Built 與 Status；參數記到 calls.txt。"""
    fake = tmp_path / "grype"
    fake.write_text('#!/usr/bin/env bash\necho "$*" >> "$CALLS"\n'
                    '[ "$2" = update ] && exit "${UPX:-0}"\n[ "$2" = import ] && exit "${IMX:-0}"\n'
                    'echo "Built:     ${BUILT}"; echo "Status:    ${DBST:-valid}"\n')
    fake.chmod(0o755)
    return fake


def _utc(hours_ago):
    import datetime as dt
    return (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _db(tmp_path, fn, built, upx="0", dbst="valid", env=None, imx="0"):
    """在 common.sh 裡跑 fn（bash 片語）；回傳 (stdout, calls.txt)。"""
    fake = _fake_grype(tmp_path)
    calls = tmp_path / "calls.txt"
    calls.write_text("")
    e = {"PATH": "/usr/bin:/bin", "BUILT": built, "UPX": upx, "IMX": imx, "DBST": dbst, "CALLS": str(calls), **(env or {})}
    r = subprocess.run(["bash", "-c", f'. "{LIB}"; {fn}', "_", str(fake), str(tmp_path)], capture_output=True, text=True, env=e)
    return r.stdout, calls.read_text()


def test_lib_grype_db_check(tmp_path):
    """每日監控用的 grype_db_check：線上更新＋嚴格（更新失敗＝FAIL）；上限單位改為天×24 小時。"""
    def run(built, upx="0", dbst="valid"):
        return _db(tmp_path, 'grype_db_check "$1" "$2" 3', built, upx, dbst)[0].split("\t")[0]
    assert run(_utc(24)) == "OK"
    assert run(_utc(5 * 24)) == "GAP"
    assert run(_utc(24), upx="1") == "FAIL"
    assert run("0001-01-01T00:00:00Z", dbst="invalid") == "FAIL"


def test_grype_db_refresh_modes(tmp_path):
    ok = _db(tmp_path, 'grype_db_refresh "$1" "$2" online', _utc(1))
    assert ok[0].startswith("OK\t") and ok[1].split() == ["db", "update"]
    bad = _db(tmp_path, 'grype_db_refresh "$1" "$2" online', _utc(1), upx="1")
    assert bad[0].startswith("FAIL\t") and "exit=1" in bad[0]
    off = _db(tmp_path, 'grype_db_refresh "$1" "$2" off', _utc(1))
    assert off[0].startswith("NOT_RUN\t") and off[1] == ""          # off：什麼都不執行
    # 預設來自環境變數；沒設就是 online
    assert _db(tmp_path, 'grype_db_refresh "$1" "$2"', _utc(1))[1].split() == ["db", "update"]
    assert _db(tmp_path, 'grype_db_refresh "$1" "$2"', _utc(1), env={"GRYPE_DB_UPDATE": "off"})[0].startswith("NOT_RUN")
    # import：用 db import 並帶原本的參數（檔案或 URL），不跑 db update
    imp = _db(tmp_path, 'grype_db_refresh "$1" "$2" "import:/mirror/v6/vulnerability-db.tar.zst"', _utc(1))
    assert imp[0].startswith("OK\t") and imp[1].split() == ["db", "import", "/mirror/v6/vulnerability-db.tar.zst"]
    url = _db(tmp_path, 'grype_db_refresh "$1" "$2" "import:http://mirror.invalid/db.tar.zst"', _utc(1), env={})
    assert url[1].split() == ["db", "import", "http://mirror.invalid/db.tar.zst"]
    assert _db(tmp_path, 'grype_db_refresh "$1" "$2" "import:/m/x"', _utc(1), imx="1")[0].startswith("FAIL\t")
    for m in ("import:", "bogus", "ONLINE"):                         # 空的 import、不認得的值 → FAIL，且不執行任何 grype 指令
        o = _db(tmp_path, 'grype_db_refresh "$1" "$2" "$3"'.replace('"$3"', m), _utc(1))
        assert o[0].startswith("FAIL\t") and o[1] == "", m


def test_grype_db_eval_states_and_hours(tmp_path):
    def ev(hours, ust, strict="0", maxd="1"):
        return _db(tmp_path, f'grype_db_eval "$1" "$2" {maxd} {ust} {strict}', _utc(hours))[0].strip().split("\t")
    s, d = ev(5, "OK")
    assert s == "OK" and "5.0 小時" in d and "上限 24 小時" in d and "UTC" in d
    s, d = ev(47, "OK")                                              # 約 47 小時：顯示小時，不是被截成「1 天」
    assert s == "GAP" and "47.0 小時" in d and "1 天" not in d
    assert ev(47, "FAIL")[0] == "GAP"                                # 更新失敗＋過期 → GAP
    s, d = ev(5, "FAIL")                                             # 更新失敗＋在上限內 → ATTENTION
    assert s == "ATTENTION" and "更新失敗" in d
    assert ev(5, "FAIL", strict="1")[0] == "FAIL"                    # 每日監控的嚴格模式
    assert ev(5, "NOT_RUN")[0] == "OK"                               # off 且資料庫新 → C-grype-db OK（更新列另記 NOT_RUN）
    assert ev(47, "NOT_RUN")[0] == "GAP"
    assert ev(47, "OK", maxd="3")[0] == "OK"                         # 上限可用 GRYPE_DB_MAX_AGE_DAYS 放寬
    assert ev(30, "OK", maxd="1.5")[0] == "OK"
    out = _db(tmp_path, 'grype_db_eval "$1" "$2" 1 OK 0', _utc(1), dbst="invalid")[0]
    assert out.startswith("FAIL\t")


def test_sca_scan_wires_refresh_and_mirror_rows():
    """sca-scan 的接線：更新列、新鮮度列、預設 1 天、比對仍關掉 auto-update。"""
    t = (PILOT / "sca-scan").read_text(encoding="utf-8")
    assert 'grype_db_refresh grype "$OUT/scan"' in t and "status C-grype-db-update" in t
    assert 'GRYPE_DB_MAX_AGE_DAYS:-1}' in t and 'GRYPE_DB_MAX_AGE_DAYS:-3}' not in t
    assert "status C-mirror-freshness" in t and "MIRROR_REFRESH_STATUS-/var/lib/sca-gitlab/refresh-status.tsv" in t
    assert "GRYPE_DB_AUTO_UPDATE=false" in t and "GRYPE_DB_AUTO_UPDATE=true" not in t
    d = (ROOT / "tools" / "demo" / "scan-flash-package.sh").read_text(encoding="utf-8")
    assert "GRYPE_DB_MAX_AGE_DAYS:-3}" not in d and "GRYPE_DB_UPDATE=online" in d and "import:<鏡像檔案或 URL>" in d


mf = load_module("pilot_mirror_freshness", PILOT / "lib" / "mirror_freshness.py")


def _status_file(tmp_path, finished_hours=2, rows=None, name="refresh-status.tsv"):
    import datetime as dt
    now = dt.datetime.now(dt.timezone.utc)
    f = lambda h: (now - dt.timedelta(hours=h)).strftime("%Y-%m-%dT%H:%M:%SZ")
    names = ("nvd", "nvbul", "osv-distro", "kernel-cve", "euvd", "ubuntu-cve-status")
    rows = rows or {n: ("OK", 2, 3) for n in names}
    lines = ["# sca-nvd-refresh status 1", f"finished\t{f(finished_hours)}"]
    for n, (res, last_ok_h, lim) in rows.items():
        lines.append(f"mirror\t{n}\t{res}\t{f(finished_hours)}\t{'-' if last_ok_h is None else f(last_ok_h)}\t{lim}\tx")
    p = tmp_path / name
    p.write_text("\n".join(lines) + "\n")
    return str(p)


def test_mirror_freshness_cases(tmp_path):
    names = ("nvd", "nvbul", "osv-distro", "kernel-cve", "euvd", "ubuntu-cve-status")
    assert mf.check(_status_file(tmp_path))[0] == "OK"
    s, d = mf.check(_status_file(tmp_path, finished_hours=30))               # 狀態檔太舊
    assert s == "GAP" and "30.0 小時" in d
    rows = {n: ("OK", 2, 3) for n in names}
    rows["euvd"] = ("FAIL", 100, 3)                                         # 失敗且過期 → GAP，列名稱
    s, d = mf.check(_status_file(tmp_path, rows=rows))
    assert s == "GAP" and "euvd" in d
    rows["euvd"] = ("FAIL", 30, 3)                                          # 失敗但沿用的還在上限內 → ATTENTION
    s, d = mf.check(_status_file(tmp_path, rows=rows))
    assert s == "ATTENTION" and "euvd" in d
    rows["euvd"] = ("FAIL", None, 3)                                        # 從沒成功過 → GAP
    assert mf.check(_status_file(tmp_path, rows=rows))[0] == "GAP"
    rows = {n: ("OK", 2, 3) for n in names if n != "nvd"}                  # 少一個鏡像 → GAP
    s, d = mf.check(_status_file(tmp_path, rows=rows))
    assert s == "GAP" and "nvd" in d
    s, d = mf.check(str(tmp_path / "missing.tsv"))                          # 檔案不存在 → GAP，不是 OK
    assert s == "GAP"
    (tmp_path / "bad.tsv").write_text("not a status file\n")
    assert mf.check(str(tmp_path / "bad.tsv"))[0] == "GAP"
    assert mf.check("")[0] == "NOT_RUN"                                    # 空路徑 → NOT_RUN，不是 OK


def test_mirror_freshness_cli(tmp_path):
    def cli(*a):
        r = subprocess.run(["python3", "-I", str(PILOT / "lib" / "mirror_freshness.py"), *a], capture_output=True, text=True)
        return r.stdout.strip().split("\t")[0], r.returncode
    assert cli(_status_file(tmp_path)) == ("OK", 0)
    assert cli("") == ("NOT_RUN", 0)
    assert cli(str(tmp_path / "nope.tsv")) == ("GAP", 0)


SCAN = str(PILOT / "sca-scan")


@pytest.mark.parametrize("args,frag", [
    ([], "需要 --git"),
    (["--git", "https://example.invalid/x.git"], "完整 commit SHA"),
    (["--git", "https://example.invalid/x.git", "--ref", "main"], "完整 commit SHA"),
    (["--dir", "/nonexistent-dir-xyz"], "不是資料夾"),
    (["--image", "php@sha256:00", "--allow-network-resolve"], "只用於原始碼"),
    (["--dir", ".", "--ref", "a" * 40], "只用於 --git"),
    (["--bogus"], "不認得的參數"),
    (["--dir", ".", "--version", "1.0:evil"], "--version 只接受"),
    (["--dir", ".", "--version", ""], "--version 只接受"),
    (["--dir", ".", "--version", " leading-space"], "--version 只接受"),
    (["--dir", ".", "--version", "a/b"], "--version 只接受"),
    (["--dir", ".", "--version", "x" * 101], "--version 只接受"),
])
def test_sca_scan_rejects_bad_arguments(args, frag):
    r = subprocess.run(["bash", SCAN, *args], capture_output=True, text=True, timeout=60)
    assert r.returncode == 64 and frag in r.stderr


def test_sca_scan_refuses_non_empty_out(tmp_path):
    (tmp_path / "old.txt").write_text("x")
    r = subprocess.run(["bash", SCAN, "--dir", str(tmp_path), "--out", str(tmp_path)], capture_output=True, text=True, timeout=60)
    assert r.returncode == 64 and "不是空的" in r.stderr


@pytest.mark.parametrize("path", ["tools/pilot/sca-scan", "tools/pilot/lib/common.sh", "tools/e2e/sandbox.sh"])
def test_shell_syntax(path):
    assert subprocess.run(["bash", "-n", str(ROOT / path)], capture_output=True).returncode == 0


def test_sandbox_hide_is_backward_compatible():
    """SBX_HIDE 沒設定時，sbx 組出的 bwrap 參數與原本相同（不會多出遮蔽參數）。"""
    s = f'''. "{ROOT}/tools/e2e/sandbox.sh"; bwrap(){{ printf '%s\\n' "$@"; }}; sbx -- true'''
    out = bash(s).stdout.splitlines()
    ro = [out[i + 1] for i, x in enumerate(out) if x == "--ro-bind" and "/sbx-stubs." not in out[i + 1]]   # 替代檔是自動遮蔽的設定檔
    assert "--tmpfs" in out and "/" in ro and not any(r.startswith(("/tmp/", "/opt/")) for r in ro if r not in ("/", "/run/systemd/resolve"))
    s2 = f'''. "{ROOT}/tools/e2e/sandbox.sh"; bwrap(){{ printf '%s\\n' "$@"; }}; SBX_HIDE=("$1" "$2" /nonexistent); sbx -- true'''
    out2 = bash(s2, str(ROOT / "tools"), str(ROOT / "README.md")).stdout.splitlines()
    i = out2.index(str(ROOT / "tools"))
    assert out2[i - 1] == "--tmpfs"
    j = out2.index(str(ROOT / "README.md"))
    assert out2[j - 2] == "--ro-bind" and "/sbx-stubs." in out2[j - 1] and out2[j - 1].endswith("/empty")
    assert "/nonexistent" not in out2


def test_lib_runlog(tmp_path):
    log = tmp_path / "log.tsv"
    r = bash(f'LOG="$1"; . "{LIB}"; runlog lab "$2" "$3" sh -c "echo hi; exit 3"; echo "rc=$?"', str(log), str(tmp_path / "o"), str(tmp_path / "e"))
    assert "rc=3" in r.stdout
    f = log.read_text().split("\t")
    assert f[0] == "lab" and f[3] == "3"




def test_sca_scan_dt_feeds_wiring():
    t = (PILOT / "sca-scan").read_text(encoding="utf-8")
    assert "for s in C-dt-feeds D-dt-data-sources" in t and 'status C-dt-feeds NOT_RUN "dtsources.py 失敗"' in t


def test_grype_db_eval_future_built_and_bad_limits(tmp_path):
    s, d = _db(tmp_path, 'grype_db_eval "$1" "$2" 1 OK 0', _utc(-240))[0].strip().split("\t")
    assert s == "GAP" and "在未來" in d
    assert _db(tmp_path, 'grype_db_eval "$1" "$2" 1 OK 0', _utc(-0.05))[0].startswith("OK\t")   # 時鐘誤差內
    for bad in ("nan", "inf", "-1", "0", "abc"):
        o = _db(tmp_path, f'grype_db_eval "$1" "$2" {bad} OK 0', _utc(1))[0]
        assert o.startswith("FAIL\t") and "設定錯誤" in o, bad


def test_grype_db_refresh_rejects_option_like_import(tmp_path):
    for m in ("import:-h", "import:--config=/x", "import:/a b", "import:/a\tb"):
        o = _db(tmp_path, 'grype_db_refresh "$1" "$2" "$3"'.replace('"$3"', "$'" + m.replace("\t", "\\t") + "'"), _utc(1))
        assert o[0].startswith("FAIL\t") and o[1] == "", m


def test_mirror_freshness_future_and_bad_limit(tmp_path):
    import datetime as dt
    names = ("nvd", "nvbul", "osv-distro", "kernel-cve", "euvd", "ubuntu-cve-status")
    rows = {n: ("OK", 2, 3) for n in names}
    rows["nvd"] = ("OK", -100, 3)
    s, d = mf.check(_status_file(tmp_path, rows=rows))
    assert s == "GAP" and "nvd" in d and "在未來" in d
    s, d = mf.check(_status_file(tmp_path, finished_hours=-5, name="fut.tsv"))
    assert s == "GAP" and ("在未來" in d or "in the future" in d)
    for bad in (float("nan"), float("inf"), 0, -1):
        assert mf.check(_status_file(tmp_path), max_age_hours=bad)[0] == "FAIL"
