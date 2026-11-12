"""NVD 鏡像新鮮度（pilot.env 的 PILOT_NVD_MIRROR、NVD_MIRROR_MODIFIED）在掃描端的判定：dtsources.py、sca-scan、報告首頁。
規則：鏡像過期不能顯示 OK；鏡像模式但讀不到新鮮度 → GAP（寫明「鏡像模式，NVD 新鮮度未知」）。"""
import datetime
import json
import os
import subprocess

from pilot_fixtures import ALL_OK, PILOT, make_out, run_report

LIB = PILOT / "lib"
DONE = {"status": "COMPLETED", "started_at": 1792758628375, "completed_at": 1792758758509}


def iso_days_ago(days):
    t = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
    return t.strftime("%Y-%m-%dT%H:%M:%S.000") + "+00:00"   # NVD .meta 的 lastModifiedDate 格式


def run_sources(tmp_path, mirror=None, extra=(), env=None):
    args = []
    for k, n in (("vuln", "nvd"), ("vuln", "osv"), ("kev", "cisa"), ("kev", "enisa")):
        f = tmp_path / f"m-{k}-{n}.json"
        f.write_text(json.dumps(DONE), encoding="utf-8")
        args.append(f"{k}:{n}:200:{f}")
    if mirror is not None:
        args = ["--nvd-mirror", mirror, *args]
    out = tmp_path / "data-sources.json"
    e = dict(os.environ)
    e.pop("NVD_MAX_AGE_DAYS", None)
    e.update(env or {})
    r = subprocess.run(["python3", "-I", str(LIB / "dtsources.py"), str(out), *extra, *args], capture_output=True, text=True, check=True, env=e)
    rows = {ln.split("\t")[0]: ln.split("\t")[1:] for ln in r.stdout.splitlines()}
    return rows, json.loads(out.read_text(encoding="utf-8"))


def test_mirror_fresh_is_ok_and_reports_date(tmp_path):
    m = iso_days_ago(1)
    rows, ds = run_sources(tmp_path, f"1|{m}")
    st, d = rows["D-dt-data-sources"]
    assert st == "OK" and "內部鏡像" in d and m in d
    assert ds["nvd_mirror"]["status"] == "OK" and ds["nvd_mirror"]["modified"] == m and 0.9 <= ds["nvd_mirror"]["age_days"] <= 1.1


def test_mirror_stale_is_gap_even_if_dt_completed(tmp_path):
    rows, ds = run_sources(tmp_path, f"1|{iso_days_ago(10)}")
    st, d = rows["D-dt-data-sources"]
    assert st == "GAP" and "NVD 鏡像過期" in d and "10." in d
    assert ds["vuln_status"] == "GAP" and ds["nvd_mirror"]["status"] == "GAP"
    assert rows["D-dt-kev-sources"][0] == "OK"          # KEV 另外判定


def test_mirror_unknown_freshness_is_gap(tmp_path):
    for spec in ("1|", "1|not-a-date", "1"):
        rows, ds = run_sources(tmp_path, spec)
        st, d = rows["D-dt-data-sources"]
        assert st == "GAP" and "鏡像模式，NVD 新鮮度未知" in d, spec
        assert ds["nvd_mirror"]["status"] == "GAP"


def test_max_age_is_adjustable(tmp_path):
    spec = f"1|{iso_days_ago(5)}"
    assert run_sources(tmp_path, spec)[0]["D-dt-data-sources"][0] == "GAP"                                   # 預設 3 天
    assert run_sources(tmp_path, spec, env={"NVD_MAX_AGE_DAYS": "7"})[0]["D-dt-data-sources"][0] == "OK"      # 環境變數
    assert run_sources(tmp_path, spec, extra=["--nvd-max-age-days", "7"])[0]["D-dt-data-sources"][0] == "OK"  # 參數


def test_direct_mode_and_absent_do_not_change_verdict(tmp_path):
    rows, ds = run_sources(tmp_path, f"0|{iso_days_ago(30)}")
    assert rows["D-dt-data-sources"][0] == "OK" and "直接連 nvd.nist.gov" in rows["D-dt-data-sources"][1]
    rows, ds = run_sources(tmp_path, None)
    assert rows["D-dt-data-sources"][0] == "OK" and "nvd_mirror" not in ds


def test_stale_mirror_and_failed_source_both_named(tmp_path):
    nvd = tmp_path / "nvd-failed.json"
    nvd.write_text(json.dumps({"status": "FAILED", "failure_reason": "x"}), encoding="utf-8")
    osv = tmp_path / "osv.json"
    osv.write_text(json.dumps(DONE), encoding="utf-8")
    out = tmp_path / "ds.json"
    r = subprocess.run(["python3", "-I", str(LIB / "dtsources.py"), str(out), "--nvd-mirror", f"1|{iso_days_ago(9)}",
                        f"vuln:nvd:200:{nvd}", f"vuln:osv:200:{osv}"], capture_output=True, text=True, check=True)
    line = [ln for ln in r.stdout.splitlines() if ln.startswith("D-dt-data-sources")][0]
    assert "\tGAP\t" in line and "NVD FAILED" in line and "NVD 鏡像過期" in line


def test_report_front_page_shows_mirror_date(tmp_path):
    m = iso_days_ago(8)
    stages = [s for s in ALL_OK if s[0] != "D-dt-data-sources"] + [("D-dt-data-sources", "GAP", "弱點資料源不完整（NVD 鏡像）")]
    out = make_out(tmp_path, stages, grype=[], findings=[])
    ds = {"sources": [{"kind": "vuln", "name": "nvd", "label": "NVD", "status": "COMPLETED"}],
          "nvd_mirror": {"mode": "1", "modified": m, "age_days": 8.0, "max_age_days": 3, "status": "GAP", "detail": "NVD 鏡像過期"}}
    (out / "dt" / "data-sources.json").write_text(json.dumps(ds), encoding="utf-8")
    _, page = run_report(out)
    assert "NVD 來源：內部鏡像" in page and m in page and "8.0 天前" in page
    # 直接連外模式
    ds["nvd_mirror"] = {"mode": "0", "modified": None, "status": None, "detail": "x"}
    (out / "dt" / "data-sources.json").write_text(json.dumps(ds), encoding="utf-8")
    _, page = run_report(out)
    assert "DT 直接連 nvd.nist.gov" in page


def test_sca_scan_reads_mirror_keys_and_passes_them():
    s = (PILOT / "sca-scan").read_text(encoding="utf-8")
    assert "PILOT_NVD_MIRROR|NVD_MIRROR_MODIFIED|NVIDIA_BULLETINS_MIRROR|OSV_DISTRO_MIRROR|KERNEL_CVE_MIRROR|UBUNTU_CVE_STATUS_MIRROR) printf -v" in s
    assert '--nvd-mirror "$PILOT_NVD_MIRROR|$NVD_MIRROR_MODIFIED"' in s
    # 不是秘密：不加進 secret()（只有三個金鑰）
    assert 'secret "$DT_API_KEY"; secret "$DEJACODE_API_KEY"; secret "$SCANCODEIO_API_KEY"' in s
