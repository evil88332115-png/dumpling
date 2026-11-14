"""DT 資料源狀態（dtsources.py、compare_expected、報告首頁）與 ScanCode.io 上傳前轉換、失敗摘要（scio_prep.py、scio_diag.py）的測試。
資料形狀取自 sca-center 示範掃描的實機輸出：DT 5.2.0 mirror-runs/latest、Syft 的 php 映像 SBOM、ScanCode.io v38.1.0 load_sbom。"""
import json
import os
import shutil
import subprocess

from pilot_fixtures import ALL_OK, PILOT, ROOT, assert_no_conclusion, dfind, gmatch, make_out, run_report


from test_pilot_lock_sandbox import bwrap_args

LIB = PILOT / "lib"
NVD_FAILED = {"status": "FAILED", "started_at": 1792758642738, "completed_at": 1792759670333,
              "failure_reason": "Failed to download feed file from https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2026.json.gz"}
DONE = {"status": "COMPLETED", "started_at": 1792758628375, "completed_at": 1792758758509}


def run_sources(tmp_path, spec):
    """spec：{(類別, 名稱): (http 碼, 回應 dict 或 None)}。回傳（status 列 dict, data-sources.json）。"""
    args = []
    for (k, n), (code, body) in spec.items():
        f = tmp_path / f"mirror-{k}-{n}.json"
        f.write_text(json.dumps(body) if body is not None else '{"message":"not found"}', encoding="utf-8")
        args.append(f"{k}:{n}:{code}:{f}")
    out = tmp_path / "data-sources.json"
    r = subprocess.run(["python3", "-I", str(LIB / "dtsources.py"), str(out), *args], capture_output=True, text=True, check=True)
    rows = {ln.split("\t")[0]: ln.split("\t")[1:] for ln in r.stdout.splitlines()}
    return rows, json.loads(out.read_text(encoding="utf-8"))


ALL_DONE = {("vuln", "nvd"): ("200", DONE), ("vuln", "osv"): ("200", DONE), ("kev", "cisa"): ("200", DONE), ("kev", "enisa"): ("200", DONE)}


def test_dtsources_all_completed_ok(tmp_path):
    rows, ds = run_sources(tmp_path, ALL_DONE)
    assert rows["D-dt-data-sources"][0] == "OK" and rows["D-dt-kev-sources"][0] == "OK"
    assert ds["sources"][0]["completed_at"] == "2026-10-23T12:32:38Z"


def test_dtsources_nvd_failed_is_gap_and_names_source(tmp_path):
    rows, ds = run_sources(tmp_path, {**ALL_DONE, ("vuln", "nvd"): ("200", NVD_FAILED)})
    st, d = rows["D-dt-data-sources"]
    assert st == "GAP" and "NVD" in d.split("：")[0] and "nvdcve-2.0-2026" in d
    assert rows["D-dt-kev-sources"][0] == "OK"          # KEV 另外判定
    assert ds["vuln_status"] == "GAP"


def test_dtsources_404_running_and_forbidden(tmp_path):
    rows, _ = run_sources(tmp_path, {("vuln", "nvd"): ("404", None), ("vuln", "osv"): ("200", {"status": "RUNNING", "started_at": 1}),
                                     ("kev", "cisa"): ("403", None), ("kev", "enisa"): ("200", DONE)})
    st, d = rows["D-dt-data-sources"]
    assert st == "GAP" and "NVD" in d and "OSV RUNNING" in d and "沒有 mirror 紀錄" in d
    st, d = rows["D-dt-kev-sources"]
    assert st == "GAP" and "SYSTEM_CONFIGURATION_READ" in d


def test_dtsources_missing_query_is_gap(tmp_path):
    rows, _ = run_sources(tmp_path, {("vuln", "osv"): ("200", DONE), ("kev", "cisa"): ("200", DONE), ("kev", "enisa"): ("200", DONE)})
    assert rows["D-dt-data-sources"][0] == "GAP" and "沒有查詢：NVD" in rows["D-dt-data-sources"][1]


RUN_OSV_ECOS = ["PyPI", "npm", "Go", "Maven", "crates.io", "Packagist", "RubyGems", "NuGet"]   # 示範掃描時 DT 設定讀回的值


def run_coverage(tmp_path, code, cfg, purls):
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps({"components": [{"type": "library", "name": f"c{i}", "purl": p} for i, p in enumerate(purls)]}), encoding="utf-8")
    cf = tmp_path / "osv-config.json"
    cf.write_text(json.dumps({"config": cfg}) if cfg is not None else "{}", encoding="utf-8")
    nvd = tmp_path / "nvd.json"
    nvd.write_text(json.dumps(DONE), encoding="utf-8")
    out = tmp_path / "ds.json"
    r = subprocess.run(["python3", "-I", str(LIB / "dtsources.py"), str(out), "--osv-config", f"{code}:{cf}", "--sbom", str(sbom),
                        f"vuln:nvd:200:{nvd}", f"vuln:osv:200:{nvd}"], capture_output=True, text=True, check=True)
    rows = {ln.split("\t")[0]: ln.split("\t")[1:] for ln in r.stdout.splitlines()}
    return rows["D-dt-osv-coverage"], json.loads(out.read_text(encoding="utf-8"))


PHP_PURLS = ["pkg:deb/debian/libc6@2.36?arch=amd64&distro=debian-12"] * 3 + ["pkg:generic/php-cli@8.4.26"]


def test_osv_coverage_debian_not_enabled_is_gap(tmp_path):
    (st, d), ds = run_coverage(tmp_path, "200", {"enabled": True, "ecosystems": RUN_OSV_ECOS}, PHP_PURLS)
    assert st == "GAP" and "Debian（3 個元件）" in d and "generic 1 個" in d
    assert ds["osv_coverage"]["by_type"] == {"deb→Debian": 3, "generic→（沒有 OSV 生態系）": 1}


def test_osv_coverage_enabled_versioned_name_is_ok(tmp_path):
    (st, d), _ = run_coverage(tmp_path, "200", {"enabled": True, "ecosystems": RUN_OSV_ECOS + ["Debian:12"]}, PHP_PURLS)
    assert st == "OK" and "generic 1 個" in d           # pkg:generic 只能靠 NVD，註明但不判 GAP


def test_osv_coverage_disabled_or_unreadable(tmp_path):
    (tmp_path / "a").mkdir()
    (st, d), _ = run_coverage(tmp_path / "a", "200", {"enabled": False, "ecosystems": ["npm"]}, ["pkg:npm/lodash@4.17.15"])
    assert st == "GAP" and "OSV 資料源沒有啟用" in d
    (tmp_path / "b").mkdir()
    (st, d), _ = run_coverage(tmp_path / "b", "403", None, ["pkg:npm/lodash@4.17.15"])
    assert st == "GAP" and "SYSTEM_CONFIGURATION_READ" in d


def test_osv_coverage_source_project_ok(tmp_path):
    (st, _), _ = run_coverage(tmp_path, "200", {"enabled": True, "ecosystems": RUN_OSV_ECOS},
                              ["pkg:npm/lodash@4.17.15", "pkg:pypi/requests@2.19.0", "pkg:golang/golang.org/x/text@v0.3.0"])
    assert st == "OK"


def stages_with_sources(status, detail="弱點資料源不完整（NVD）：…"):
    return [s for s in ALL_OK if s[0] not in ("D-dt-data-sources", "D-dt-findings")] + [
        ("D-dt-data-sources", status, detail), ("D-dt-findings", "GAP" if status != "OK" else "OK", "讀取完成")]








def php_matches(version):
    return [gmatch("CVE-2026-109618", "php-cli", version, f"pkg:generic/php-cli@{version}", "binary"),
            gmatch("CVE-2026-109619", "php-cli", version, f"pkg:generic/php-cli@{version}", "binary")]




def test_report_homepage_lists_data_sources(tmp_path):
    out = make_out(tmp_path, stages_with_sources("GAP"), grype=[], findings=[])
    _, ds = run_sources(tmp_path, {**ALL_DONE, ("vuln", "nvd"): ("200", NVD_FAILED)})
    (out / "dt" / "data-sources.json").write_text(json.dumps(ds), encoding="utf-8")
    rep, page = run_report(out)
    assert rep["dt_data_sources"]["vuln_status"] == "GAP"
    home = page.split("<h2>弱點</h2>")[0]                         # 首頁（弱點區之前）
    assert "DT 弱點資料源（最近一次 mirror）" in home and "FAILED" in home and "nvdcve-2.0-2026" in home
    assert "弱點資料源不完整或狀態未知" in page
    assert_no_conclusion(page)


def test_report_without_data_sources_file_says_so(tmp_path):
    out = make_out(tmp_path, [("D-dt-data-sources", "NOT_RUN", "--no-upload")])
    _, page = run_report(out)
    assert "沒有資料源狀態" in page.split("<h2>弱點</h2>")[0]


# ---------- ScanCode.io ----------

def syft_like_sbom():
    long_path = "/usr/include/c++/14/ext/pb_ds/detail/cc_hash_table_map_/constructor_destructor_no_store_hash_fn_imps.hpp"
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {"component": {"type": "container", "name": "php"}},
            "components": [
                {"bom-ref": "pkg:deb/debian/libc6@2.36?arch=amd64&distro=debian-12&package-id=1", "type": "library", "name": "libc6",
                 "version": "2.36", "purl": "pkg:deb/debian/libc6@2.36?arch=amd64&distro=debian-12", "licenses": [{"license": {"name": "GPL-2+"}}]},
                {"bom-ref": "f1", "type": "file", "name": long_path},
                {"bom-ref": "f2", "type": "file", "name": "/etc/passwd"},
                {"bom-ref": "os", "type": "operating-system", "name": "debian", "version": "12"},
                {"bom-ref": "app", "type": "application", "name": "php", "version": "8.4.26", "purl": "pkg:generic/php@8.4.26",
                 "components": [{"bom-ref": "child", "type": "library", "name": "x", "version": "1", "purl": "pkg:generic/x@1"}]},
                {"bom-ref": "long", "type": "library", "name": "n" * 120, "version": "1", "purl": "pkg:generic/" + "n" * 120 + "@1"},
            ],
            "dependencies": [{"ref": "app", "dependsOn": ["f1", "child", "long"]}, {"ref": "f2", "dependsOn": []}]}


def run_prep(tmp_path, doc):
    src, dst, summ = tmp_path / "in.json", tmp_path / "out.json", tmp_path / "s.json"
    src.write_text(json.dumps(doc), encoding="utf-8")
    r = subprocess.run(["python3", "-I", str(LIB / "scio_prep.py"), str(src), str(dst), str(summ)], capture_output=True, text=True)
    return r, json.loads(dst.read_text(encoding="utf-8")) if dst.exists() else None, json.loads(summ.read_text(encoding="utf-8")) if summ.exists() else None








def test_report_license_chain(tmp_path):
    sbom = {"components": [{"type": "file", "name": "/f"}, {"type": "library", "name": "a", "purl": "pkg:npm/a@1",
                                                           "components": [{"type": "library", "name": "b", "purl": "pkg:npm/b@1"}]}]}
    comp = {"product": "demo:1", "packages": 2, "counts": {"pass": 2}, "rows": []}
    out = make_out(tmp_path, ALL_OK, sbom=sbom, comp=comp)
    (out / "dejacode" / "scio-prep.json").write_text(json.dumps({"components_in": 3, "components_out": 2, "removed_file_components": 1,
                                                                  "removed_too_long": []}), encoding="utf-8")
    (out / "dejacode" / "scio-summary.json").write_text(json.dumps({"packages": 2, "unique_purls": 2}), encoding="utf-8")
    rep, page = run_report(out)
    ch = rep["license_chain"]
    assert (ch["sbom_components"], ch["scio_upload"], ch["removed_file"], ch["removed_too_long"], ch["removed_other"],
            ch["scio_packages"], ch["dejacode_packages"]) == (3, 2, 1, 0, 0, 2, 2)
    text = page.split("<h2>授權（DejaCode）</h2>")[1]
    assert "原始 SBOM 元件 3 → 上傳 ScanCode.io 2（移除 file 1、過長 0、其他 0） → ScanCode.io 套件 2（唯一 purl 2） → DejaCode 產品套件 2" in text
    assert_no_conclusion(page)


def test_report_license_chain_missing_links(tmp_path):
    out = make_out(tmp_path, [("E-scancodeio-load-sbom", "FAIL", "x")], sbom={"components": [{"type": "library", "name": "a"}]})
    rep, page = run_report(out)
    assert rep["license_chain"]["scio_packages"] is None
    assert "原始 SBOM 元件 1 → 上傳 ScanCode.io ?（沒有轉換紀錄） → ScanCode.io 套件 ? → DejaCode 產品套件 ?" in page


def test_sandbox_does_not_tmpfs_system_dirs(tmp_path):
    # 遮蔽目標經 readlink -f 解析成系統層級資料夾時不整個蓋掉，記錄後略過
    root = tmp_path / "tool"
    root.mkdir()
    os.symlink("/etc", root / "etc")
    os.symlink("/usr", root / "conf")
    out, err = bwrap_args('SBX_RO=("$1"); SBX_HIDE=("$1/conf"); sbx -- true', {"SBX_TOOLS": "none"}, [str(root)])
    tm = [out[i + 1] for i, a in enumerate(out) if a == "--tmpfs"]
    assert "/etc" not in tm and "/usr" not in tm
    assert "不以 tmpfs 遮蔽系統資料夾 /etc" in err and "不以 tmpfs 遮蔽系統資料夾 /usr" in err








TRACEBACK = """Traceback (most recent call last):
  File "/opt/scancodeio/scanpipe/pipelines/__init__.py", line 140, in execute
    step(self)
  File "/opt/scancodeio/scanpipe/pipes/__init__.py", line 217, in update_or_create_package
    package = DiscoveredPackage.create_from_data(project, package_data)
  File "/usr/local/lib/python3.13/site-packages/django/db/backends/utils.py", line 105, in _execute
    return self.cursor.execute(sql, params)
django.db.utils.DataError: value too long for type character varying(100)
"""






def test_sandbox_hides_real_path_behind_symlinked_conf(tmp_path):
    # Debian 的 maven 套件：<MAVEN_HOME>/conf → /etc/maven。bwrap 0.9.0 對中間有符號連結的目的路徑掛不上（整個沙箱起不來），
    # 所以遮蔽要掛在實際路徑上（2026-10-23 本機重現：Can't create file at /usr/share/maven/conf/settings.xml）
    real = tmp_path / "etc-maven"
    real.mkdir()
    (real / "settings.xml").write_text("<settings><servers><server><password>tok</password></server></servers></settings>")
    mh = tmp_path / "maven"
    (mh / "bin").mkdir(parents=True)
    os.symlink(real, mh / "conf")
    out, _ = bwrap_args('SBX_RO=("$1"); sbx -- true', {"SBX_TOOLS": "none"}, [str(mh)])
    i = out.index(str((real / "settings.xml").resolve()))
    assert out[i - 2] == "--ro-bind" and out[i - 1].endswith("/settings.xml") and "/sbx-stubs." in out[i - 1]
    assert str(mh / "conf" / "settings.xml") not in out
    if shutil.which("bwrap") and subprocess.run(["bwrap", "--ro-bind", "/", "/", "true"], capture_output=True).returncode == 0:
        s = f'. "{ROOT}/tools/e2e/sandbox.sh"; SBX_RO=("$1"); sbx -- cat "$1/conf/settings.xml"'
        r = subprocess.run(["bash", "-c", s, "_", str(mh)], capture_output=True, text=True, env={**os.environ, "SBX_TOOLS": "none"}, timeout=60)
        assert r.returncode == 0, r.stderr
        assert r.stdout.strip() == "<settings/>"                 # 經由符號連結讀到的是替代檔


def test_sca_scan_wires_new_stages():
    s = (PILOT / "sca-scan").read_text(encoding="utf-8")
    assert "/api/v2/$k-data-sources/$n/mirror-runs/latest" in s and "dtsources.py" in s
    assert "scio_prep.py" in s and 'upload_file=@$SCIO_UP' in s and "/api/runs/$ru/" in s and "scio_diag.py" in s
    assert "D-dt-data-sources D-dt-kev-sources" in s and "E-scancodeio-prep E-scancodeio-load-sbom" in s   # 跳過時也列出


def _fresh(hours_ago, status="COMPLETED"):
    import time
    t = int((time.time() - hours_ago * 3600) * 1000)
    return {"status": status, "started_at": t - 60000, "completed_at": t}


def _fresh_all(hours_ago=3):
    return {k: ("200", _fresh(hours_ago)) for k in ALL_DONE}


def test_dt_feeds_fresh_is_ok(tmp_path):
    rows, ds = run_sources(tmp_path, _fresh_all())
    assert rows["C-dt-feeds"][0] == "OK" and "26 小時" in rows["C-dt-feeds"][1] and ds["feeds_freshness"]["status"] == "OK"


def test_dt_feeds_stale_failed_and_missing_are_gap_with_names(tmp_path):
    spec = _fresh_all()
    spec[("vuln", "osv")] = ("200", _fresh(40))
    st, d = run_sources(tmp_path, spec)[0]["C-dt-feeds"]
    assert st == "GAP" and "OSV" in d and "40." in d and "NVD" in d.split("其餘正常")[1]
    spec = _fresh_all()
    spec[("kev", "enisa")] = ("200", {"status": "FAILED", "started_at": 1, "completed_at": 2, "failure_reason": "boom"})
    st, d = run_sources(tmp_path, spec)[0]["C-dt-feeds"]
    assert st == "GAP" and "ENISA KEV" in d and "FAILED" in d
    spec = _fresh_all()
    spec[("vuln", "nvd")] = ("404", None)
    assert run_sources(tmp_path, spec)[0]["C-dt-feeds"][0] == "GAP"


def test_dt_feeds_forbidden_is_not_run_never_ok(tmp_path):
    spec = {k: ("403", None) for k in ALL_DONE}
    st, d = run_sources(tmp_path, spec)[0]["C-dt-feeds"]
    assert st == "NOT_RUN" and "SYSTEM_CONFIGURATION_READ" in d


def test_dt_feeds_limit_is_overridable(tmp_path):
    spec = _fresh_all(30)
    assert run_sources(tmp_path, spec)[0]["C-dt-feeds"][0] == "GAP"
    args = [f"{k[0]}:{k[1]}:200:{tmp_path}/mirror-{k[0]}-{k[1]}.json" for k in spec]
    r = subprocess.run(["python3", "-I", str(LIB / "dtsources.py"), str(tmp_path / "o.json"), "--feeds-max-hours", "48", *args], capture_output=True, text=True, check=True)
    assert "C-dt-feeds\tOK" in r.stdout
    r = subprocess.run(["python3", "-I", str(LIB / "dtsources.py"), str(tmp_path / "o.json"), *args], capture_output=True, text=True, check=True,
                       env={"PATH": "/usr/bin:/bin", "DT_FEEDS_MAX_AGE_HOURS": "48"})
    assert "C-dt-feeds\tOK" in r.stdout


def test_dt_feeds_future_and_bad_limit(tmp_path):
    st, d = run_sources(tmp_path, {k: ("200", _fresh(-100)) for k in ALL_DONE})[0]["C-dt-feeds"]
    assert st == "GAP" and "在未來" in d
    for bad in ("nan", "inf", "0", "-3", "abc"):
        spec = _fresh_all()
        args = []
        for (k, n), (code, body) in spec.items():
            f = tmp_path / f"m-{k}-{n}.json"
            f.write_text(json.dumps(body))
            args.append(f"{k}:{n}:200:{f}")
        r = subprocess.run(["python3", "-I", str(LIB / "dtsources.py"), str(tmp_path / "o.json"), "--feeds-max-hours", bad, *args],
                           capture_output=True, text=True, check=True)
        line = [x for x in r.stdout.splitlines() if x.startswith("C-dt-feeds")][0]
        assert line.split("\t")[1] == "FAIL" and "設定錯誤" in line, bad


def test_dt_feeds_reason_code_is_structured(tmp_path):
    """M7b：data-sources.json 的 feeds_freshness.reason（sca-scan 寫進 meta.json 的 dt_feeds_reason；cra_report 讀它，不看說明文字）。"""
    import importlib.util
    spec_ = importlib.util.spec_from_file_location("dtsources_m7b", LIB / "dtsources.py")
    ds = importlib.util.module_from_spec(spec_)
    spec_.loader.exec_module(ds)
    for n in "abc":
        (tmp_path / n).mkdir()
    assert run_sources(tmp_path / "a", _fresh_all())[1]["feeds_freshness"]["reason"] == "fresh"
    spec = _fresh_all()
    spec[("vuln", "osv")] = ("200", _fresh(40))
    assert run_sources(tmp_path / "b", spec)[1]["feeds_freshness"]["reason"] == "stale"
    assert run_sources(tmp_path / "c", {k: ("403", None) for k in ALL_DONE})[1]["feeds_freshness"]["reason"] == "permission_denied"
    assert ds.feeds_reason([], ds.feeds_freshness([])[0]) == "no_data"
    assert ds.feeds_reason([], ds.feeds_freshness([], max_hours=-1)[0]) == "config_error"
    assert set(ds.FEEDS_REASONS) == {"fresh", "stale", "permission_denied", "no_data", "config_error"}
