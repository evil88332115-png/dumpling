"""授權與版權缺口（docs/benchmarks/feature-parity-2026-10.md 第 1–5 項）的單元測試：
licexpr（OR 擇一）、pkgscan（等待、補 unknown、證據；假的 DejaCode 回應，欄位依 DejaCode v6.0.1 api.py）、
notice（NOTICE 草稿）、filescan（ScanCode.io v38.1.0 results 的 files[]）、report 的新段落、sca-scan 的接線。"""
import json
import os
import sys

import pytest

from pilot_fixtures import ALL_OK, PILOT, ROOT, assert_no_conclusion, make_out, run_report, visible_text

sys.path.insert(0, str(ROOT / "tools" / "e2e"))
sys.path.insert(0, str(PILOT / "lib"))
import filescan  # noqa: E402
import licexpr  # noqa: E402
import notice  # noqa: E402
import pkgscan  # noqa: E402

STATE = {"mit": "pass", "apache-2.0": "pass", "gpl-2.0": "error", "lgpl-2.1": "warning", "classpath-exception-2.0": "pass"}.get


def ch(expr):
    return licexpr.choice(licexpr.parse(licexpr.tokens(expr)), lambda k: STATE(k, "not_assessed"))


@pytest.mark.parametrize("expr,want", [
    ("mit OR gpl-2.0", "pass"),                      # 可以擇一
    ("gpl-2.0 OR lgpl-2.1", "warning"),              # 取最輕的
    ("mit AND gpl-2.0", "error"),
    ("(mit AND gpl-2.0) OR lgpl-2.1", "warning"),    # AND 先算
    ("mit AND gpl-2.0 OR lgpl-2.1", "warning"),      # 優先順序：AND ＞ OR
    ("x OR gpl-2.0", "not_assessed"),                # 未評估的選項可能比較輕：不下結論
    ("x OR mit", "pass"),
    ("mit AND x", "not_assessed"),
    ("gpl-2.0 WITH classpath-exception-2.0", "error"),   # WITH 保守處理：取最嚴重
    ("MIT or Apache-2.0".lower(), "pass"),
])
def test_or_choice(expr, want):
    assert ch(expr) == want


@pytest.mark.parametrize("bad", ["mit OR", "(mit", "mit gpl-2.0", "OR mit", "mit )"])
def test_parse_errors(bad):
    with pytest.raises(ValueError):
        licexpr.parse(licexpr.tokens(bad))


class FakeDJ:
    """模擬 DejaCode：imports 依呼叫次數改變；scans 先 running 後 success；PATCH 記錄下來。"""

    def __init__(self):
        self.calls, self.patches, self.n_imports = [], [], 0
        self.imports = [{"uuid": "old", "type": "LOAD_SBOMS", "status": "success", "created_date": "2026-10-01"}]
        self.scan_polls = 0

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url))
        assert headers["Authorization"] == "Token T"
        if method == "PATCH":
            self.patches.append((url, json.loads(body)))
            return 200, {}, b"{}"
        if url.endswith("/imports/"):
            self.n_imports += 1
            if self.n_imports == 2:
                self.imports.append({"uuid": "new", "type": "LOAD_SBOMS", "status": "importing", "created_date": "2026-10-26"})
            elif self.n_imports >= 3:
                self.imports[-1]["status"] = "success"
                self.imports[-1]["results"] = {"created": {}, "existing": {"package": ["a", "b"]}, "errors": {}}
            return 200, {}, json.dumps(self.imports).encode()
        if "/scans/" in url:
            self.scan_polls += 1
            cnt = {"running": 1, "success": 1, "not_scannable": 1} if self.scan_polls == 1 else {"success": 2, "not_scannable": 1}
            d = {"status_counts": cnt}
            if "summary_only" not in url:
                d["packages"] = [{"uuid": "u1", "purl": "pkg:npm/a@1", "scan_status": "success", "download_url": "https://r/a-1.tgz"},
                                 {"uuid": "u2", "purl": "pkg:npm/b@2", "scan_status": "success", "download_url": "https://r/b-2.tgz"},
                                 {"uuid": "u3", "purl": "pkg:apk/alpine/c@3", "scan_status": "not_scannable", "download_url": ""}]
            return 200, {}, json.dumps(d).encode()
        if url.endswith("/u1/scan_summary/"):
            return 200, {}, json.dumps(SUMMARY).encode()
        if url.endswith("/u2/scan_summary/"):
            return 200, {}, json.dumps({"declared_license_expression": None, "key_files": []}).encode()
        return 404, {}, b"{}"


# ScanCode.io make_results_summary 的形狀（toolkit summary＋key_files＋key_files_packages）
SUMMARY = {"declared_license_expression": "mit", "license_clarity_score": {"score": 90}, "declared_holder": "Jane Doe",
           "other_holders": [{"value": "ACME Inc.", "count": 1}, {"value": None, "count": 3}],
           "other_license_expressions": [{"value": "apache-2.0", "count": 1}],
           "key_files": [{"path": "a/LICENSE", "name": "LICENSE", "detected_license_expression": "mit", "detected_license_expression_spdx": "MIT",
                          "copyrights": [{"copyright": "Copyright (c) 2020 Jane Doe"}], "holders": [{"holder": "Jane Doe"}], "content": "MIT License ..."},
                         {"path": "a/NOTICE", "name": "NOTICE", "copyrights": [], "holders": [], "content": "This product includes software from ACME."},
                         {"path": "a/package.json", "name": "package.json", "copyrights": [], "content": "{}"}],
           "key_files_packages": [{"copyright": "Copyright (c) 2020 Jane Doe"}]}


def client(fake):
    c = pkgscan.Client("http://dj", "T", transport=fake, sleep=lambda s: None)
    return c


def test_wait_import_finds_new_entry_only(tmp_path):
    fake = FakeDJ(); c = client(fake)
    before = tmp_path / "b.json"
    assert pkgscan.cmd_imports(c, "P", str(before))[0] == "OK"          # 呼叫 1：只有 old
    st, d = pkgscan.cmd_wait_import(c, "P", str(before), 100, str(tmp_path / "i.json"), now=lambda: 0, sleep=lambda s: None)
    assert st == "OK" and "success" in d and "existing 2" in d and "created 0" in d   # 套件數，不是物件種類數
    assert json.load(open(tmp_path / "i.json"))["import"]["uuid"] == "new"


def test_wait_import_package_errors_need_attention(tmp_path):
    fake = FakeDJ(); c = client(fake)
    before = tmp_path / "b.json"
    pkgscan.cmd_imports(c, "P", str(before))
    real = fake.__call__

    def with_errors(m, u, h, b):
        st, hd, body = real(m, u, h, b)
        d = json.loads(body)
        if isinstance(d, list) and d and d[-1].get("results"):
            d[-1]["results"]["errors"] = {"package": ["Package with this ... already exists."]}
            body = json.dumps(d).encode()
        return st, hd, body
    c.t = with_errors
    st, d = pkgscan.cmd_wait_import(c, "P", str(before), 100, str(tmp_path / "i.json"), now=lambda: 0, sleep=lambda s: None)
    assert st == "ATTENTION" and "errors 1" in d


def test_wait_import_timeout_is_gap(tmp_path):
    fake = FakeDJ(); c = client(fake)
    before = tmp_path / "b.json"; before.write_text(json.dumps(fake.imports))
    t = iter([0, 0, 999, 999])
    st, d = pkgscan.cmd_wait_import(c, "P", str(before), 10, str(tmp_path / "i.json"), now=lambda: next(t), sleep=lambda s: None)
    assert st == "GAP" and "逾時" in d


def test_wait_scans_and_evidence(tmp_path):
    fake = FakeDJ(); c = client(fake)
    st, d = pkgscan.cmd_wait_scans(c, "P", 1000, str(tmp_path / "p.txt"), str(tmp_path / "s.json"), now=lambda: 0, sleep=lambda s: None)
    assert st == "GAP" and "not_scannable 1" in d and "success 2" in d   # 有套件沒掃到 → GAP
    assert "1 個沒有掃描成功" in d and "沒有掃描成功的套件" not in d
    assert (tmp_path / "p.txt").read_text().count("\n") == 2
    st, d = pkgscan.cmd_evidence(c, "P", str(tmp_path / "s.json"), str(tmp_path / "e.json"))
    assert st == "OK" and "有版權聲明 1" in d and "偵測到宣告授權 1" in d
    ev = json.load(open(tmp_path / "e.json"))["packages"]
    a = ev["pkg:npm/a@1"]
    assert a["copyrights"] == ["Copyright (c) 2020 Jane Doe"]           # 去重
    assert a["holders"] == ["ACME Inc.", "Jane Doe"] and a["other_license_expressions"] == ["apache-2.0"]
    assert [k["name"] for k in a["key_files"] if "content" in k] == ["LICENSE", "NOTICE"]   # package.json 不留內容
    assert ev["pkg:npm/b@2"]["copyrights"] == []


def test_wait_scans_all_success_ok(tmp_path):
    fake = FakeDJ(); fake.scan_polls = 5; c = client(fake)
    fake_scans = fake.__call__

    def only_success(m, u, h, b):
        st, hd, body = fake_scans(m, u, h, b)
        if "/scans/" in u:
            d = json.loads(body); d["status_counts"] = {"success": 3}; body = json.dumps(d).encode()
        return st, hd, body
    c.t = only_success
    assert pkgscan.cmd_wait_scans(c, "P", 10, str(tmp_path / "p"), str(tmp_path / "s"), now=lambda: 0, sleep=lambda s: None)[0] == "OK"


def test_wait_scans_flags_same_purl_twice(tmp_path):
    fake = FakeDJ(); fake.scan_polls = 5; c = client(fake)
    fake_scans = fake.__call__

    def dup(m, u, h, b):
        st, hd, body = fake_scans(m, u, h, b)
        if "/scans/" in u:
            d = json.loads(body); d["status_counts"] = {"success": 4}
            if "packages" in d:
                d["packages"] = [{**p, "scan_status": "success"} for p in d["packages"]] \
                    + [{"uuid": "u4", "purl": "pkg:npm/a@1", "scan_status": "success", "download_url": "https://old/a-1.tgz"}]
            body = json.dumps(d).encode()
        return st, hd, body
    c.t = dup
    st, d = pkgscan.cmd_wait_scans(c, "P", 10, str(tmp_path / "p"), str(tmp_path / "s"), now=lambda: 0, sleep=lambda s: None)
    assert st == "ATTENTION" and "同一個 purl 有多個套件 1（例如 pkg:npm/a@1" in d


def test_sync_unknown_patches_only_unknown_with_known_package_license(tmp_path):
    fake = FakeDJ(); c = client(fake)
    rows = [{"package": "a", "product_package_uuid": "pp1", "license_expression": "unknown", "package_declared_license_expression": "mit"},
            {"package": "b", "product_package_uuid": "pp2", "license_expression": "", "package_declared_license_expression": "mit"},   # 空白不動（同 DejaCode）
            {"package": "c", "product_package_uuid": "pp3", "license_expression": "unknown", "package_declared_license_expression": "unknown"},
            {"package": "d", "product_package_uuid": "pp4", "license_expression": "apache-2.0", "package_declared_license_expression": "mit"}]
    comp = tmp_path / "c.json"; comp.write_text(json.dumps({"rows": rows}))
    st, d = pkgscan.cmd_sync_unknown(c, "P", str(comp), str(tmp_path / "o.json"))
    assert st == "OK" and "1 個" in d
    assert fake.patches == [("http://dj/api/v2/product_packages/pp1/", {"license_expression": "mit"})]


def test_sync_os_patches_unknown_and_blank_from_copyright_files(tmp_path):
    fake = FakeDJ(); c = client(fake)
    rows = [{"package": "pkg:deb/ubuntu/a@1", "product_package_uuid": "pp1", "license_expression": "unknown"},
            {"package": "pkg:deb/ubuntu/b@1", "product_package_uuid": "pp2", "license_expression": ""},
            {"package": "pkg:deb/ubuntu/c@1", "product_package_uuid": "pp3", "license_expression": "unknown"},   # 版權檔沒掃到授權
            {"package": "pkg:deb/ubuntu/d@1", "product_package_uuid": "pp4", "license_expression": "gpl-2.0"},   # 已知的不動
            {"package": "pkg:npm/e@1", "product_package_uuid": "pp5", "license_expression": "unknown"}]        # 沒有版權檔證據
    comp = tmp_path / "c.json"; comp.write_text(json.dumps({"rows": rows}))
    ev = {"packages": {"pkg:deb/ubuntu/a@1": {"declared_license_expression": "mit"},
                       "pkg:deb/ubuntu/b@1": {"declared_license_expression": "gpl-2.0-plus AND bsd-new"},
                       "pkg:deb/ubuntu/c@1": {"declared_license_expression": None},
                       "pkg:deb/ubuntu/d@1": {"declared_license_expression": "mit"}}}
    evf = tmp_path / "e.json"; evf.write_text(json.dumps(ev))
    st, d = pkgscan.cmd_sync_os(c, "P", str(comp), str(evf), str(tmp_path / "o.json"))
    assert st == "OK" and "2 個" in d and "沒掃到授權 1 個" in d
    assert fake.patches == [("http://dj/api/v2/product_packages/pp1/", {"license_expression": "mit"}),
                            ("http://dj/api/v2/product_packages/pp2/", {"license_expression": "gpl-2.0-plus AND bsd-new"})]


def test_copyright_class():
    assert pkgscan.copyright_class({"copyrights": ["Copyright X"]}, "", "a") == "detected"
    assert pkgscan.copyright_class({"copyrights": [], "holders": ["X"]}, "", "a") == "holder_only"
    assert pkgscan.copyright_class({}, "Copyright a project contributors", "a") == "inferred"   # DejaCode 的推定值
    assert pkgscan.copyright_class({}, "", "a") == "none"
    assert pkgscan.copyright_class({}, "Copyright 2001 Someone", "a") == "dejacode_only"


def test_client_requires_env(monkeypatch):
    for k in ("DEJACODE_URL", "DEJACODE_API_TOKEN", "DJ_PRODUCT"):
        monkeypatch.delenv(k, raising=False)
    out = []
    monkeypatch.setattr("builtins.print", lambda *a, **k: out.append(a[0]))
    assert pkgscan.main(["imports", "x"]) == 0 and out[0].startswith("FAIL\t")


ROWS = [{"package": "pkg:npm/a@1", "name": "a", "version": "1", "license_expression": "mit", "copyright": "Copyright Jane Doe", "notice_text": ""},
        {"package": "pkg:npm/b@2", "name": "b", "version": "2", "license_expression": "mit OR gpl-2.0",
         "copyright": "Copyright b project contributors", "notice_text": ""},
        {"package": "pkg:npm/c@3", "name": "c", "version": "3", "license_expression": "unknown", "copyright": "", "notice_text": "Old notice"}]
LICS = {"mit": {"key": "mit", "name": "MIT License", "spdx_license_key": "MIT", "full_text": "Permission is hereby granted..."},
        "gpl-2.0": {"key": "gpl-2.0", "name": "GPL 2.0", "spdx_license_key": "GPL-2.0-only", "full_text": ""}}


def test_notice_build_marks_inferred_and_missing():
    ev = {"pkg:npm/a@1": pkgscan.summarize(SUMMARY)}
    text, s = notice.build(ROWS, ev, LICS, "demo:1")
    assert "Copyright (c) 2020 Jane Doe" in text and "This product includes software from ACME." in text   # 偵測到的版權與 NOTICE 檔
    assert "NOT DETECTED; DejaCode inferred value, not detected: Copyright b project contributors" in text   # 推定值不當作版權聲明
    assert "License: NOT DETERMINED" in text and "Old notice" in text
    assert "Permission is hereby granted" in text and "== MIT License (mit, SPDX: MIT) ==" in text
    assert s["copyright_class"] == {"detected": 1, "inferred": 1, "none": 1}
    assert s["missing_license"] == ["pkg:npm/c@3"] and s["licenses_without_text"] == ["gpl-2.0"]
    st, d = notice.verdict(s)
    assert st == "GAP" and "缺授權 1" in d and "沒有偵測到版權 2" in d and "gpl-2.0" in d


def test_notice_complete_is_ok():
    ev = {"pkg:npm/a@1": pkgscan.summarize(SUMMARY)}
    text, s = notice.build(ROWS[:1], ev, LICS)
    assert notice.verdict(s)[0] == "OK"
    assert notice.verdict({"packages": 0})[0] == "NOT_ASSESSED"


def test_notice_main_without_dejacode_is_gap(tmp_path, monkeypatch):
    monkeypatch.delenv("DEJACODE_URL", raising=False)
    comp = tmp_path / "c.json"; comp.write_text(json.dumps({"product": "p:1", "rows": ROWS[:1]}))
    out = []
    monkeypatch.setattr("builtins.print", lambda *a, **k: out.append(a[0]))
    notice.main([str(comp), "-", str(tmp_path / "N.txt"), str(tmp_path / "n.json")])
    assert out[0].startswith("GAP\t") and "授權全文沒有附上" in out[0] and (tmp_path / "N.txt").exists()


RESULTS = {"headers": [{"messages": [{"severity": "ERROR", "description": "boom in x"}, {"severity": "INFO", "description": "ok"}]}],
           "packages": [{"purl": "pkg:apk/alpine/openssl@1"}],
           "files": [{"path": "etc/ssl/misc/CA.pl", "type": "file", "detected_license_expression_spdx": "OpenSSL", "for_packages": [],
                      "copyrights": [{"copyright": "Copyright (c) The OpenSSL Project"}], "holders": [{"holder": "The OpenSSL Project"}]},
                     {"path": "usr/lib/libssl.so", "type": "file", "detected_license_expression_spdx": "OpenSSL", "for_packages": ["pkg:apk/alpine/openssl@1"],
                      "copyrights": [{"copyright": "Copyright (c) The OpenSSL Project"}]},
                     {"path": "etc", "type": "directory"}, {"path": "etc/motd", "type": "file"}]}


def test_filescan_summary(tmp_path):
    s = filescan.summarize(RESULTS, "analyze_docker_image")
    assert (s["files"], s["files_with_license"], s["loose_files_with_license"], s["files_with_copyright"]) == (3, 2, 1, 2)
    assert s["copyrights"][0] == {"copyright": "Copyright (c) The OpenSSL Project", "files": 2, "example_paths": ["etc/ssl/misc/CA.pl", "usr/lib/libssl.so"]}
    assert s["licenses"] == [("OpenSSL", 2)] and s["error_count"] == 1
    f = tmp_path / "r.json"; f.write_text(json.dumps(RESULTS))
    out = []
    import builtins
    orig = builtins.print
    builtins.print = lambda *a, **k: out.append(a[0])
    try:
        filescan.main([str(f), "analyze_docker_image", str(tmp_path / "s.json")])
        f.write_text(json.dumps({"files": []}))
        filescan.main([str(f), "scan_codebase", str(tmp_path / "s2.json")])
    finally:
        builtins.print = orig
    assert out[0].startswith("GAP\t") and "boom in x" in out[0]       # ScanCode.io error 訊息 → 部分沒掃完
    assert out[1].startswith("NOT_ASSESSED\t")


def test_report_shows_scan_copyright_notice_and_files(tmp_path):
    comp = {"product": "demo:1", "packages": 2, "counts": {"error": 1, "warning": 0, "pass": 1, "no_license": 0, "not_assessed": 0},
            "counts_or_choice": {"error": 0, "warning": 0, "pass": 2, "no_license": 0, "not_assessed": 0}, "or_choice_differs": 1,
            "rows": [{"package": "pkg:npm/b@2", "license_expression": "mit OR gpl-2.0", "verdict": "error", "or_choice_verdict": "pass"},
                     {"package": "pkg:npm/a@1", "license_expression": "mit", "verdict": "pass", "or_choice_verdict": "pass"}]}
    out = make_out(tmp_path, ALL_OK, grype=[], findings=[], comp=comp)
    (out / "dejacode" / "package-scans.json").write_text(json.dumps({"status_counts": {"success": 1, "no_scan": 1}}))
    (out / "dejacode" / "notice-summary.json").write_text(json.dumps({"packages": 2, "copyright_class": {"detected": 1, "inferred": 1},
                                                                       "missing_license": [], "missing_copyright": ["x"], "licenses_without_text": []}))
    (out / "scancode").mkdir()
    (out / "scancode" / "files-summary.json").write_text(json.dumps(filescan.summarize(RESULTS, "analyze_docker_image")))
    rep, page = run_report(out)
    assert rep["package_scans"] == {"success": 1, "no_scan": 1} and rep["licenses"]["or_choice"][0]["or_choice_verdict"] == "pass"
    t = visible_text(page)
    assert "擇一時等級不同：1 個" in t and "逐套件掃描" in t and "DejaCode 推定（不是偵測結果） 1" in t
    assert "dejacode/NOTICE.txt" in page and "不屬於任何套件的檔案中有授權 1" in t and "OpenSSL" in t
    assert_no_conclusion(page)


def test_sca_scan_wires_license_gap_stages():
    s = (PILOT / "sca-scan").read_text(encoding="utf-8")
    for x in ("load_sboms/", "scan_all_packages=true", "infer_download_urls=true", "update_existing_packages=true",
              "pkgscan.py", "wait-scans", "sync-unknown", "evidence", "notice.py", "filescan.py", "analyze_docker_image", "scan_codebase",
              "--no-package-scan", "--no-files-scan", "E-files-scan", "E-notice", "E-copyrights", "E-license-sync",
              '"$O/djsbom.json"', 'SCIO_UP=$SCIO_UP0; DJF=1', '[ -n "$DJF" ] && [ "$SCAN_ST" = OK ] && SCAN_ST=ATTENTION', "PACKAGE_SCAN_WAIT_SECONDS", "FILES_SCAN_WAIT_SECONDS"):
        assert x in s, x
    # 原始碼封存在 cdxgen（B 段）之前做
    assert s.index('SRC_TAR=$WORK/source.tar.gz') < s.index("# ---------- B. 沙箱與 SBOM")
    # 金鑰只放環境變數，不出現在指令列參數
    assert "DEJACODE_API_TOKEN=$DEJACODE_API_KEY DJ_PRODUCT=$PID python3" in s


def test_djread_or_choice_and_spdx_against_local_server(tmp_path):
    """djread.py 整支跑一次：本機假 DejaCode（欄位依 DejaCode v6.0.1 的 LicenseSerializer、UsagePolicy、ProductPackageSerializer）。"""
    import http.server
    import subprocess
    import threading
    lics = [{"key": "mit", "spdx_license_key": "MIT", "usage_policy": "ok"}, {"key": "gpl-2.0", "spdx_license_key": "GPL-2.0-only", "usage_policy": "bad"},
            {"key": "bsd-new", "spdx_license_key": "BSD-3-Clause", "usage_policy": "ok"}, {"key": "custom-x", "spdx_license_key": "", "usage_policy": "ok"}]
    pols = [{"label": "ok", "compliance_alert": ""}, {"label": "bad", "compliance_alert": "error"}]

    def pp(i, expr, decl):
        return {"uuid": f"pp{i}", "license_expression": expr,
                "package_abcd": {"uuid": f"p{i}", "package_url": f"pkg:npm/x{i}@1", "name": f"x{i}", "version": "1",
                                 "license_expression": decl, "declared_license_expression": decl, "copyright": "", "holder": "", "notice_text": ""}}
    pps = [pp(1, "mit OR gpl-2.0", "mit OR gpl-2.0"), pp(2, "(bsd-new AND custom-x)", "bsd-new AND custom-x"), pp(3, "unknown", "")]
    data = {"/api/v2/licenses/": lics, "/api/v2/usage_policies/": pols, "/api/v2/product_packages/": pps}

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            path = self.path.split("?")[0]
            body = json.dumps({"count": len(data[path]), "next": None, "results": data[path]}).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(body)

        def log_message(self, *a):
            pass
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        out = tmp_path / "c.json"
        r = subprocess.run([sys.executable, "-I", str(ROOT / "tools" / "e2e" / "djread.py"), f"http://127.0.0.1:{srv.server_port}", "demo", "1", str(out)],
                           capture_output=True, text=True, timeout=60, env={"DEJACODE_API_TOKEN": "T", "PATH": "/usr/bin:/bin",
                                                                **{k: v for k, v in os.environ.items() if k == "LD_LIBRARY_PATH"}})   # setup-python 的 python 要 libpython
    finally:
        srv.shutdown()
    assert r.returncode == 0, r.stderr
    d = json.loads(out.read_text())
    rows = {x["package"]: x for x in d["rows"]}
    a, b, c = rows["pkg:npm/x1@1"], rows["pkg:npm/x2@1"], rows["pkg:npm/x3@1"]
    assert (a["verdict"], a["or_choice_verdict"], a["has_or"]) == ("error", "pass", True)       # DejaCode 算法 vs OR 擇一
    assert a["license_expression_spdx"] == "MIT OR GPL-2.0-only"
    assert b["license_expression_spdx"] == "(BSD-3-Clause AND LicenseRef-scancode-custom-x)"   # 沒有 SPDX 鍵 → LicenseRef-scancode-
    assert b["verdict"] == b["or_choice_verdict"] == "pass" and c["verdict"] == "no_license"
    assert d["or_choice_differs"] == 1 and d["counts_or_choice"]["pass"] == 2 and d["counts"]["error"] == 1
    assert a["product_package_uuid"] == "pp1" and a["package_uuid"] == "p1"
    assert "OR 擇一時等級不同 1" in r.stdout


def test_load_sboms_is_the_only_importer_with_package_scan():
    """逐套件掃描時不先 import_from_scan（兩種匯入找既有套件的欄位不同，會重複建套件；pilot-run/12）。"""
    s = (PILOT / "sca-scan").read_text(encoding="utf-8")
    imp = s.index('IMP=import_from_scan')
    assert imp < s.index("if scan_trigger scan; then IMP=load_sboms") < s.index('/import_from_scan/"')
    assert 'case $IMP in' in s and 'c=$(djapi POST "/api/v2/products/$pid/import_from_scan/" "$O/import-$i.json"' in s
    assert "scio-results-import.json" not in s                       # 不再改 ScanCode.io 結果
    assert 'elif [ "$SCAN_ST" = FAIL ]; then' in s                    # load_sboms 失敗才退回 import_from_scan；逾時不退回


def test_scio_chunks(tmp_path):
    import scio_chunks
    data = {"headers": [{"tool_name": "scanpipe"}],
            "packages": [{"package_uid": f"u{i}", "purl": f"pkg:npm/p{i}@1"} for i in range(5)],
            "files": [{"path": "a", "for_packages": ["u0"]}, {"path": "b", "for_packages": ["u4"]}, {"path": "c", "for_packages": []}],
            "dependencies": [{"for_package_uid": "u1"}, {"for_package_uid": "u3"}]}
    src = tmp_path / "r.json"; src.write_text(json.dumps(data))
    assert scio_chunks.main([str(src), "2", str(tmp_path / "c")]) == 0
    parts = [json.loads((tmp_path / "c" / f"chunk-{n:04d}.json").read_text()) for n in (1, 2, 3)]
    assert [len(p["packages"]) for p in parts] == [2, 2, 1] and not (tmp_path / "c" / "chunk-0004.json").exists()
    assert sum((p["packages"] for p in parts), []) == data["packages"]            # 順序與內容不變
    assert all(p["headers"] == data["headers"] for p in parts)                    # 每批都有 headers（validate_headers）
    assert [f["path"] for f in parts[0]["files"]] == ["a"] and [f["path"] for f in parts[2]["files"]] == ["b"]
    assert parts[0]["dependencies"] == [{"for_package_uid": "u1"}] and parts[1]["dependencies"] == [{"for_package_uid": "u3"}]
    assert scio_chunks.main([str(src), "0", str(tmp_path / "d")]) == 64


def test_unknown_mark_goes_into_sbom_properties(tmp_path):
    import djsbom
    bom = {"components": [
        {"bom-ref": "r1", "purl": "pkg:npm/a@1"},                                            # 結果空白 → 標
        {"bom-ref": "r2", "purl": "pkg:npm/b@1", "licenses": [{"license": {"id": "MIT"}}]},   # 結果有授權 → 不標
        {"bom-ref": "r3", "purl": "pkg:npm/c@1", "components": [{"purl": "pkg:npm/d@1"}]},   # 巢狀、沒有 bom-ref → 以 purl 對應
        {"bom-ref": "r4", "purl": "pkg:npm/e@1",
         "properties": [{"name": "aboutcode:declared_license_expression", "value": "mit"}]}]}
    res = {"packages": [{"package_uid": "r1", "purl": "pkg:npm/a@1", "declared_license_expression": ""},
                        {"package_uid": "r2", "purl": "pkg:npm/b@1", "declared_license_expression": "mit"},
                        {"package_uid": "r3", "purl": "pkg:npm/c@1", "declared_license_expression": "apache-2.0"},
                        {"package_uid": "x", "purl": "pkg:npm/d@1", "declared_license_expression": None},
                        {"package_uid": "r4", "purl": "pkg:npm/e@1", "declared_license_expression": ""}]}
    (tmp_path / "bom.json").write_text(json.dumps(bom)); (tmp_path / "res.json").write_text(json.dumps(res))
    assert djsbom.main([str(tmp_path / "bom.json"), str(tmp_path / "res.json"), str(tmp_path / "out.json"), str(tmp_path / "m.json")]) == 0
    out = json.load(open(tmp_path / "out.json"))["components"]

    def marks(c):
        return [p["value"] for p in c.get("properties") or [] if p["name"] == "aboutcode:declared_license_expression"]
    assert marks(out[0]) == ["unknown"] and marks(out[1]) == [] and marks(out[2]) == []
    assert marks(out[2]["components"][0]) == ["unknown"] and marks(out[3]) == ["mit"]   # 已有的屬性不覆寫
    m = json.load(open(tmp_path / "m.json"))
    assert m["marked_unknown"] == 2 and m["blank_in_scio_results"] == 3 and len(m["original_sha256"]) == 64


def download_urls(bom):
    return [next((p["value"] for p in c.get("properties") or [] if p["name"] == "aboutcode:download_url"), None)
            for c in bom["components"]]


def test_djsbom_deb_urls():
    """deb：額外套件庫索引 → Launchpad（ubuntu）→ Debian pool（來源名稱、lib 前綴）→ 猜的；epoch 不進檔名。"""
    import djsbom, gzip, urllib.error
    idx = gzip.compress(b"Package: nvidia-l4t-core\nVersion: 39.2.1-1\nArchitecture: arm64\nFilename: pool/main/n/nvidia-l4t-core/nvidia-l4t-core_39.2.1-1_arm64.deb\n\n"
                        b"Package: nvidia-l4t-x\nVersion: 39.2.1-1\nArchitecture: all\nFilename: pool/main/n/nvidia-l4t-x/nvidia-l4t-x_39.2.1-1_all.deb\n")
    got = []

    def get(u):
        got.append(u)
        if u == "https://nv/jetson/som/dists/r39.2/main/binary-arm64/Packages.gz":
            return idx
        raise urllib.error.HTTPError(u, 404, "Not Found", {}, None)
    P = "pkg:deb/ubuntu/"
    bom = {"components": [
        {"bom-ref": "a", "purl": "pkg:deb/ubuntu/nvidia-l4t-x@39.2.1-1?arch=all&distro=ubuntu-24.04"},          # all：查 arm64 的索引
        {"bom-ref": "b", "purl": P + "nvidia-l4t-core@39.2.1-1?arch=arm64&distro=ubuntu-24.04"},
        {"bom-ref": "c", "purl": P + "libssl3t64@3.0.13-0ubuntu3.11?arch=arm64&upstream=openssl&distro=ubuntu-24.04"},
        {"bom-ref": "d", "purl": P + "bsdutils@1%3A2.39.3-9ubuntu6?arch=arm64&upstream=util-linux%402.39.3-9ubuntu6"},
        {"bom-ref": "e", "purl": "pkg:deb/debian/libgl1@1.6.0-1?arch=amd64&upstream=libglvnd&distro=debian-12"},
        {"bom-ref": "f", "purl": "pkg:deb/debian/tzdata@2024a-0%2Bdeb12u1?arch=all"},
        {"bom-ref": "g", "purl": "pkg:deb/kali/foo@1.0?arch=amd64"},
        {"bom-ref": "h", "purl": P + "noversion?arch=arm64"},
        {"bom-ref": "i", "purl": P + "keep@1?arch=arm64", "properties": [{"name": "aboutcode:download_url", "value": "https://x/keep.deb"}]},
    ]}
    off = json.loads(json.dumps(bom))
    assert djsbom.prepare(off, {"packages": []}, get=get)["deb"]["launchpad"] == 0 and off == bom   # 預設不改 deb（DEB_PACKAGE_SCAN）
    s = djsbom.prepare(bom, {"packages": []}, get=get, deb_extra=djsbom.deb_repos("https://nv/jetson/som r39.2 main; bad entry"), deb_urls=True)
    url = {c["bom-ref"]: next((p["value"] for p in c.get("properties", []) if p["name"] == "aboutcode:download_url"), None) for c in bom["components"]}
    assert url["a"] == "https://nv/jetson/som/pool/main/n/nvidia-l4t-x/nvidia-l4t-x_39.2.1-1_all.deb"
    assert url["b"] == "https://nv/jetson/som/pool/main/n/nvidia-l4t-core/nvidia-l4t-core_39.2.1-1_arm64.deb"
    assert url["c"] == "https://launchpad.net/ubuntu/+archive/primary/+files/libssl3t64_3.0.13-0ubuntu3.11_arm64.deb"
    assert url["d"] == "https://launchpad.net/ubuntu/+archive/primary/+files/bsdutils_2.39.3-9ubuntu6_arm64.deb"   # 去 epoch
    assert url["e"] == "https://deb.debian.org/debian/pool/main/libg/libglvnd/libgl1_1.6.0-1_amd64.deb"
    assert url["f"] == "https://deb.debian.org/debian/pool/main/t/tzdata/tzdata_2024a-0%2Bdeb12u1_all.deb"
    assert url["g"].startswith("https://deb.debian.org/debian/pool/main/f/foo/") and url["h"] is None and url["i"] == "https://x/keep.deb"
    d = s["deb"]
    assert (d["extra_repo"], d["launchpad"], d["debian_pool"]) == (2, 2, 2) and d["guessed"] == ["pkg:deb/kali/foo@1.0?arch=amd64"]
    assert d["no_url"] == [P + "noversion?arch=arm64"] and d["index_errors"] == []
    assert sorted(got) == ["https://nv/jetson/som/dists/r39.2/main/binary-amd64/Packages.gz",   # 每個架構的索引只讀一次；
                           "https://nv/jetson/som/dists/r39.2/main/binary-arm64/Packages.gz"]   # amd64 沒有（404）不算錯誤
    assert "deb 下載網址 7（額外套件庫 2、Launchpad 2、Debian pool 2（只有目前版本）、猜的 1）" in djsbom.summary(s)
    assert djsbom.deb_repos("ftp://x a b; https://y s c") == [("https://y", "s", "c")]


def test_djsbom_deb_extra_repo_unreachable():
    import djsbom
    bom = {"components": [{"purl": "pkg:deb/ubuntu/nvidia-l4t-core@39.2.1-1?arch=arm64"}]}
    s = djsbom.prepare(bom, {"packages": []}, get=lambda u: (_ for _ in ()).throw(OSError("down")), deb_extra=[("https://nv", "r39.2", "main")],
                       deb_urls=True)
    assert s["deb"]["launchpad"] == 1 and len(s["deb"]["index_errors"]) == 1     # 讀不到索引：退回 Launchpad，照實記下


def test_djsbom_nuget_uses_v3_flat_container_url():
    import djsbom
    bom = {"components": [{"purl": "pkg:nuget/Azure.Identity@1.6.1"}, {"purl": "pkg:nuget/Foo@01.2"},
                          {"purl": "pkg:nuget/Bar@1.0.0.0-Beta+meta"}, {"purl": "pkg:nuget/Baz@1.2.3.4"},
                          {"purl": "pkg:nuget/Keep@1.0", "properties": [{"name": "aboutcode:download_url", "value": "https://x"}]},
                          {"purl": "pkg:nuget/Odd@not-a-version"}, {"purl": "pkg:npm/a@1"}]}
    s = djsbom.prepare(bom, {"packages": []}, get=None)
    assert download_urls(bom) == [
        "https://api.nuget.org/v3-flatcontainer/azure.identity/1.6.1/azure.identity.1.6.1.nupkg",
        "https://api.nuget.org/v3-flatcontainer/foo/1.2.0/foo.1.2.0.nupkg",
        "https://api.nuget.org/v3-flatcontainer/bar/1.0.0-beta/bar.1.0.0-beta.nupkg",
        "https://api.nuget.org/v3-flatcontainer/baz/1.2.3.4/baz.1.2.3.4.nupkg",
        "https://x", None, None]
    assert s["nuget"]["download_url_set"] == 4 and s["nuget"]["unparsed_version"] == ["pkg:nuget/Odd@not-a-version"]


def test_djsbom_maven_without_license_scans_sources_jar():
    import djsbom
    have = {"https://repo.maven.apache.org/maven2/org/springframework/security/spring-security-web/5.4.9/spring-security-web-5.4.9-sources.jar"}
    checked = []

    def check(u):
        checked.append(u)
        return 200 if u in have else 404
    bom = {"components": [{"bom-ref": "a", "purl": "pkg:maven/org.springframework.security/spring-security-web@5.4.9"},
                          {"bom-ref": "b", "purl": "pkg:maven/g/no-sources@1"},
                          {"bom-ref": "c", "purl": "pkg:maven/g/has-license@1"},
                          {"bom-ref": "d", "purl": "pkg:maven/g/native@1?classifier=linux-x86_64"}]}
    res = {"packages": [{"package_uid": u, "purl": c["purl"], "declared_license_expression": "apache-2.0" if u == "c" else ""}
                        for u, c in zip("abcd", bom["components"])]}
    s = djsbom.prepare(bom, res, get=None, check=check)
    assert download_urls(bom) == [next(iter(have)), "https://repo.maven.apache.org/maven2/g/no-sources/1/no-sources-1.jar",
                                  None, None]          # 沒有 sources jar：寫出和 purl2url 一樣的二進位網址；有授權的、有 classifier 的不動
    assert s["maven"] == {"sources_jar": ["pkg:maven/org.springframework.security/spring-security-web@5.4.9"],
                          "binary_jar": 1, "unchecked": 0, "head_errors": 0}
    assert len(checked) == 2 and djsbom.summary(s) == "SBOM 補上 Maven 改掃 sources jar 1"


def test_djsbom_maven_head_retry_cache_and_give_up():
    import djsbom
    calls = []

    def check(u):
        calls.append(u)
        return 0                                     # 離線：每次都連不上
    names = ["a", "a", "b", "c", "d"]                # a 重複：同一個網址只檢查一次
    bom = {"components": [{"bom-ref": f"r{i}", "purl": f"pkg:maven/g/{n}@1"} for i, n in enumerate(names)]
           + [{"bom-ref": "q", "purl": "pkg:maven/g/e@1?repository_url=https://repo.example/m2"}]}
    res = {"packages": [{"package_uid": c["bom-ref"], "purl": c["purl"], "declared_license_expression": ""} for c in bom["components"]]}
    s = djsbom.prepare(bom, res, get=None, check=check, maven_base="https://mirror/m2")
    assert calls == ["https://mirror/m2/g/a/1/a-1-sources.jar"] * 2 + ["https://mirror/m2/g/b/1/b-1-sources.jar"] * 2 \
        + ["https://mirror/m2/g/c/1/c-1-sources.jar"] * 2          # 每個重試一次；連續 3 個連不上就不再檢查
    urls = download_urls(bom)
    assert urls[0] == urls[1] == "https://repo.maven.apache.org/maven2/g/a/1/a-1.jar"
    assert urls[-1] == "https://repo.example/m2/g/e/1/e-1.jar"     # repository_url 照 purl2url，但不對它送 HEAD
    assert s["maven"] == {"sources_jar": [], "binary_jar": 1, "unchecked": 5, "head_errors": 3}
    assert djsbom.summary(s) == "SBOM 補上 Maven 沒有檢查 sources jar 5（連不上或超過時限，用二進位 jar）"
    t = iter([0, 0, 1000, 1000])                    # 超過總時限之後也不再檢查（從第一次 HEAD 起算）
    fresh = [{"bom-ref": c["bom-ref"], "purl": c["purl"]} for c in bom["components"][2:4]]
    s = djsbom.prepare({"components": fresh}, res, get=None, check=lambda u: 200, check_seconds=300, now=lambda: next(t))
    assert len(s["maven"]["sources_jar"]) == 1 and s["maven"]["unchecked"] == 1


def test_djsbom_purl_edge_cases():
    import djsbom
    assert djsbom.parse_purl(5) is None and djsbom.parse_purl(None) is None
    assert djsbom.parse_purl("pkg:apk/alpine/a@1?Arch=x86_64")[4] == {"arch": "x86_64"}    # qualifier key 不分大小寫
    assert djsbom.nuget_url("Foo/../bar", "1.0") == "https://api.nuget.org/v3-flatcontainer/foo%2F..%2Fbar/1.0.0/foo%2F..%2Fbar.1.0.0.nupkg"
    assert djsbom.maven_urls("g", "a?x", "1", {}, "https://m") is None                      # 網址特殊字元：交給 DejaCode
    assert [djsbom.alpine_branch(d) for d in ("alpine-3.12.0", "Alpine-3.19.0_alpha20231219", "alpine-edge", "wolfi", None)] == \
        ["v3.12", "v3.19", "edge", None, None]
    assert djsbom.seconds("abc") == 300 and djsbom.seconds("5") == 5.0
    bom = {"components": [{"bom-ref": "f", "purl": "pkg:maven/g/a@1?repository_url=file:///etc"}]}
    s = djsbom.prepare(bom, {"packages": [{"package_uid": "f", "declared_license_expression": ""}]}, get=None,
                       check=lambda u: pytest.fail(f"不應該 HEAD {u}"))
    assert download_urls(bom) == ["file:///etc/g/a/1/a-1.jar"] and s["maven"]["binary_jar"] == 1   # 照 purl2url 寫，不送 HEAD
    s = djsbom.prepare({"components": [{"bom-ref": "n", "purl": "pkg:maven/g/b@1"}]},
                       {"packages": [{"package_uid": "n", "declared_license_expression": ""}]}, get=None, check=lambda u: None)
    assert s["maven"]["unchecked"] == 1                                       # 沒有狀態碼：當作連不上
    bom = {"components": [{"purl": 5}, {"purl": "pkg:nuget/A@1", "properties": [{"name": "aboutcode:download_url", "value": ""}]}]}
    djsbom.prepare(bom, {"packages": []}, get=None)
    assert download_urls(bom)[1] == "https://api.nuget.org/v3-flatcontainer/a/1.0.0/a.1.0.0.nupkg"   # 空值的屬性當作沒有


def apkindex(entries, alpine_format=True):
    import gzip, io, tarfile
    text = "\n\n".join(f"C:Q1x\nP:{n}\nV:{v}\nA:x86_64" for n, v in entries).encode() + b"\n"
    sig, idx = io.BytesIO(), io.BytesIO()
    with tarfile.open(fileobj=sig, mode="w") as t:
        ti = tarfile.TarInfo(".SIGN.RSA.x"); ti.size = 3; t.addfile(ti, io.BytesIO(b"sig"))
    with tarfile.open(fileobj=idx, mode="w") as t:
        ti = tarfile.TarInfo("APKINDEX"); ti.size = len(text); t.addfile(ti, io.BytesIO(text))
    # Alpine 的簽章段只有標頭和內容（沒有結尾的零區塊），一般 tar 也要讀得過
    return gzip.compress(sig.getvalue()[:1024] if alpine_format else sig.getvalue()) + gzip.compress(idx.getvalue())


def test_djsbom_apkindex_formats_and_caps(monkeypatch):
    import djsbom
    for fmt in (True, False):
        assert djsbom.parse_apkindex(apkindex([("musl", "1.1.24-r10")], alpine_format=fmt)) == {"musl": "1.1.24-r10"}
    monkeypatch.setattr(djsbom, "MAX_INDEX_RAW", 2048)              # 解壓後超過上限：不整個解開
    with pytest.raises(ValueError, match="解壓後超過"):
        djsbom.parse_apkindex(apkindex([("p%d" % i, "1") for i in range(200)]))

    class R:
        def __init__(self, n): self.n = n
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self, k): return b"x" * min(k, self.n)
    monkeypatch.setattr(djsbom, "MAX_INDEX", 10)
    monkeypatch.setattr(djsbom.urllib.request, "urlopen", lambda req, timeout: R(11))
    with pytest.raises(ValueError, match="超過 10 bytes"):
        djsbom.fetch("https://x/APKINDEX.tar.gz")


def test_djsbom_apk_download_url_from_branch_index():
    import djsbom
    seen = []

    def get(url):
        seen.append(url)
        if url.endswith("/v3.12/main/x86_64/APKINDEX.tar.gz"):
            return apkindex([("musl", "1.1.24-r10"), ("busybox", "1.31.1-r19")])
        if url.endswith("/v3.12/community/x86_64/APKINDEX.tar.gz"):
            return apkindex([("jq", "1.6-r1")])
        raise OSError("404")
    q = "?arch=x86_64&distro=alpine-3.12.0"
    bom = {"components": [{"purl": "pkg:apk/alpine/musl@1.1.24-r9" + q}, {"purl": "pkg:apk/alpine/busybox@1.31.1-r19" + q},
                          {"purl": "pkg:apk/alpine/jq@1.6-r1" + q}, {"purl": "pkg:apk/alpine/local-thing@1-r0" + q},
                          {"purl": "pkg:apk/alpine/x@1-r0?arch=aarch64&distro=alpine-3.12.0"},
                          {"purl": "pkg:apk/alpine/y@1-r0?arch=x86_64"},
                          {"purl": "pkg:apk/alpine/z@1-r0?arch=x86_64&repo=main&alpine_version=v3.12"},
                          {"purl": "pkg:apk/alpine/w@1-r0?arch=x86_64&repo=community&distro=alpine-3.12.0"},
                          {"purl": "pkg:apk/alpine/jq@1.6-r1?distro=alpine-3.12.0"}]}
    s = djsbom.prepare(bom, {"packages": []}, get=get, base="https://mirror")
    assert download_urls(bom) == [
        "https://mirror/v3.12/main/x86_64/musl-1.1.24-r9.apk", "https://mirror/v3.12/main/x86_64/busybox-1.31.1-r19.apk",
        "https://mirror/v3.12/community/x86_64/jq-1.6-r1.apk",
        "https://mirror/v3.12/main/x86_64/local-thing-1-r0.apk",          # 查不到 repo：猜 main（只讓這個套件掃描失敗，不讓整份匯入失敗）
        "https://mirror/v3.12/main/aarch64/x-1-r0.apk",                   # APKINDEX 讀不到：同上
        "https://mirror/edge/main/x86_64/y-1-r0.apk",                     # 推不出分支：猜 edge
        None,                                                             # 已有 qualifier 的交給 purl2url
        "https://mirror/v3.12/community/x86_64/w-1-r0.apk",               # purl 已有 repo：只查那個 repo，查不到也照用
        None]                                                             # 沒有 arch：組不出網址
    a = s["apk"]
    assert a["download_url_set"] == 7 and a["version_current"] == 2 and a["version_not_in_index"] == 1
    assert a["guessed"] == ["pkg:apk/alpine/local-thing@1-r0" + q, "pkg:apk/alpine/x@1-r0?arch=aarch64&distro=alpine-3.12.0",
                            "pkg:apk/alpine/y@1-r0?arch=x86_64", "pkg:apk/alpine/w@1-r0?arch=x86_64&repo=community&distro=alpine-3.12.0"]
    assert a["no_url"] == ["pkg:apk/alpine/jq@1.6-r1?distro=alpine-3.12.0"] and len(a["index_errors"]) == 2   # aarch64 的兩個 repo 都讀不到
    assert len(seen) == 4                                                                 # 每個分支、repo、arch 只讀一次
    assert djsbom.summary(s) == ("SBOM 補上 apk 下載網址 7（其中 2 個是分支目前的版本、4 個查不到 repo 或分支，用猜的）"
                                 "、apk 組不出網址 1（DejaCode 匯入會失敗）、APKINDEX 讀取失敗 2")


def test_wait_import_records_created_count(tmp_path):
    fake = FakeDJ(); c = client(fake)
    before = tmp_path / "b.json"
    pkgscan.cmd_imports(c, "P", str(before))
    pkgscan.cmd_wait_import(c, "P", str(before), 100, str(tmp_path / "i.json"), now=lambda: 0, sleep=lambda s: None)
    assert json.load(open(tmp_path / "i.json"))["created"] == 0    # sca-scan 依這個數字決定能不能改用 import_from_scan


def test_pkgscan_main_always_prints_a_status(monkeypatch):
    out = []
    monkeypatch.setattr("builtins.print", lambda *a, **k: out.append(a[0]))
    monkeypatch.setattr(pkgscan, "client", lambda: (_ for _ in ()).throw(AttributeError("x")))
    assert pkgscan.main(["imports", "x"]) == 0 and out[0].startswith("FAIL\tAttributeError")


def test_fallback_to_import_from_scan_only_when_nothing_was_created():
    s = (PILOT / "sca-scan").read_text(encoding="utf-8")
    np0 = s.index('np0=$(pkg count "$NAME:$DJV")')
    guard = s.index('elif [ "$SCAN_ST" = FAIL ] && ! { [ "$SCAN_STAGE" != wait ] && [ "${np0%%$\'\\t\'*}" = OK ] '
                    '&& [ "$(pkg count "$NAME:$DJV")" = "$np0" ]; }; then IMP=none')
    assert np0 < s.index("if scan_trigger scan; then IMP=load_sboms") < guard
    assert guard < s.index('elif [ "$SCAN_ST" = FAIL ]; then\n          status E-package-scan-submit FAIL "$SCAN_D（改用 import_from_scan')
    assert '[ "$(jget "$O/$1-import.json" timed_out)" = False ] && SCAN_STAGE=done' in s


def test_count_product_packages(tmp_path):
    seen = []

    class C:
        def get_json(self, path, what):
            seen.append(path)
            return {"count": 7, "results": []}
    assert pkgscan.cmd_count(C(), "P", "demo:1.0") == ("OK", "7")
    assert seen == ["/api/v2/product_packages/?product=demo%3A1.0&page_size=1"]


class FakeSCIO:
    """ScanCode.io v38.1.0 的 /api/projects/?names=…、/api/runs/<uuid>/delete_pipeline/、DELETE /api/projects/<uuid>/。"""
    def __init__(self, projects):
        self.projects = {p["uuid"]: p for p in projects}
        self.calls = []
        self.started = set()      # 讀清單之後才開始跑的 run：delete_pipeline 回 400
        self.gone = set()         # 已經不在的 run：delete_pipeline 回 404
        self.delete_fail = 0      # DELETE 專案回 503 的次數

    def __call__(self, method, url, headers, body, timeout=30):
        import urllib.parse as up
        u = up.urlsplit(url); q = up.parse_qs(u.query); self.calls.append((method, u.path))
        if method == "GET" and u.path == "/api/projects/":
            names = q["names"][0].split(",")
            res = [p for p in self.projects.values() if any(n in p["name"] for n in names)]
            return 200, {}, json.dumps({"results": res, "next": None}).encode()
        if method == "GET" and u.path.startswith("/api/projects/"):
            return 200, {}, json.dumps(self.projects[u.path.split("/")[3]]).encode()
        if method == "POST" and u.path.endswith("/delete_pipeline/"):
            ru = u.path.split("/")[3]
            if ru in self.started:
                return 400, {}, b'{"status": "Only non started or queued pipelines can be deleted."}'
            if ru in self.gone:
                return 404, {}, b""
            for p in self.projects.values():
                p["runs"] = [r for r in p["runs"] if r["uuid"] != ru]
            return 200, {}, b"{}"
        if method == "DELETE":
            if self.delete_fail:
                self.delete_fail -= 1
                return 503, {}, b"busy"
            self.projects.pop(u.path.split("/")[3], None)
            return 204, {}, b""
        return 404, {}, b""


def scio_project(uuid, url, status, pipeline="scan_single_package"):
    import scio_failures as sf
    return {"uuid": uuid, "name": f"{sf.url_hash(url)}.0123456789", "input_sources": [{"download_url": url}],
            "runs": [{"uuid": "r-" + uuid, "pipeline_name": pipeline, "status": status, "task_output": "", "log": ""}]}


def run_cancel(monkeypatch, tmp_path, fake, files):
    import policysync as ps
    import scio_cancel
    monkeypatch.setattr(ps, "default_transport", fake)
    monkeypatch.setattr(scio_cancel.time, "sleep", lambda s: None)
    monkeypatch.setenv("SCANCODEIO_URL", "http://scio")
    out = []
    monkeypatch.setattr("builtins.print", lambda *a, **k: out.append(a[0]))
    assert scio_cancel.main([str(tmp_path / "c.json"), *map(str, files)]) == 0
    return out, json.load(open(tmp_path / "c.json"))


def test_scio_cancel_deletes_queued_and_leaves_running_scans(monkeypatch, tmp_path):
    fake = FakeSCIO([scio_project("q", "https://x/q.tgz", "queued"), scio_project("r", "https://x/r.tgz", "running"),
                     scio_project("j", "https://x/j.tgz", "queued"),
                     scio_project("s", "https://x/s.tgz", "success"), scio_project("o", "https://x/other.tgz", "queued")])
    fake.started.add("r-j")                       # 讀清單之後才開始跑
    scans = tmp_path / "s.json"
    scans.write_text(json.dumps({"timed_out": True, "packages": [
        {"download_url": u, "scan_status": st} for u, st in
        (("https://x/q.tgz", "queued"), ("https://x/r.tgz", "running"), ("https://x/j.tgz", "queued"), ("https://x/s.tgz", "success"))]}))
    out, d = run_cancel(monkeypatch, tmp_path, fake, [scans])
    assert d["cancelled"] == 1 and set(fake.projects) == {"r", "j", "s", "o"}   # 執行中、剛開始跑、已完成、別的產品的網址都不動
    assert not any("stop_pipeline" in path for _, path in fake.calls)            # 不停止執行中的（會殺掉 worker 的子程序）
    assert {r["project"][:10]: r["result"] for r in d["rows"]} == {
        sf_hash("https://x/q.tgz"): "deleted", sf_hash("https://x/r.tgz"): "running", sf_hash("https://x/j.tgz"): "running"}
    assert out == ["逾時後取消 ScanCode.io 排隊中的工作 1 個，執行中的 2 個讓它跑完"]


def sf_hash(url):
    import scio_failures as sf
    return sf.url_hash(url)


def test_scio_cancel_mixed_runs_and_failures(monkeypatch, tmp_path):
    mixed = scio_project("m", "https://x/m.tgz", "queued")
    mixed["runs"].append({"uuid": "r-m2", "pipeline_name": "scan_single_package", "status": "running"})
    fake = FakeSCIO([mixed, scio_project("g", "https://x/g.tgz", "queued"), scio_project("d", "https://x/d.tgz", "queued")])
    fake.gone.add("r-g")
    fake.delete_fail = 2                          # d：重試一次仍失敗
    scans = tmp_path / "s.json"
    scans.write_text(json.dumps({"timed_out": True, "packages": [
        {"download_url": u, "scan_status": "queued"} for u in ("https://x/m.tgz", "https://x/g.tgz", "https://x/d.tgz")]}))
    out, d = run_cancel(monkeypatch, tmp_path, fake, [scans])
    res = {r["project"][:10]: (r["result"], r["detail"]) for r in d["rows"]}
    assert res[sf_hash("https://x/m.tgz")][0] == "running" and "m" in fake.projects   # 有 run 在跑：只刪排隊的 run
    assert res[sf_hash("https://x/g.tgz")] == ("failed", "刪除 run HTTP 404")         # 404 不當成「已開始」
    assert res[sf_hash("https://x/d.tgz")][0] == "failed" and "手動刪專案" in res[sf_hash("https://x/d.tgz")][1]
    assert out[0].startswith("逾時後取消 ScanCode.io 排隊中的工作 0 個，執行中的 1 個讓它跑完，2 個沒有取消成功")


def test_scio_cancel_running_import_is_left_with_note(monkeypatch, tmp_path):
    fake = FakeSCIO([scio_project("imp", "", "running", pipeline="load_sbom")])
    imp = tmp_path / "i.json"
    imp.write_text(json.dumps({"timed_out": True, "import": {"project_uuid": "imp", "status": "submitted"}}))
    out, d = run_cancel(monkeypatch, tmp_path, fake, [imp])
    assert d["cancelled"] == 0 and "imp" in fake.projects and "送出逐套件掃描" in out[0]


def test_scio_cancel_does_nothing_without_timeout(monkeypatch, tmp_path):
    fake = FakeSCIO([scio_project("q", "https://x/q.tgz", "queued")])
    scans = tmp_path / "s.json"
    scans.write_text(json.dumps({"timed_out": False, "packages": [{"download_url": "https://x/q.tgz", "scan_status": "queued"}]}))
    out, d = run_cancel(monkeypatch, tmp_path, fake, [scans])
    assert out == [] and d["cancelled"] == 0 and fake.calls == []


def test_scio_cancel_timed_out_import(monkeypatch, tmp_path):
    fake = FakeSCIO([scio_project("imp", "", "queued", pipeline="load_sbom")])
    imp = tmp_path / "i.json"
    imp.write_text(json.dumps({"timed_out": True, "import": {"project_uuid": "imp", "status": "submitted"}}))
    out, d = run_cancel(monkeypatch, tmp_path, fake, [imp])
    assert d["cancelled"] == 1 and fake.projects == {}


def test_scio_failures_finds_projects_by_url_hash(monkeypatch, tmp_path):
    import policysync as ps
    import scio_failures
    p = scio_project("f", "https://x/f.nupkg", "failure")
    p["runs"][0]["task_output"] = "ValidationError: ['Could not fetch: https://x/f.nupkg']"
    fake = FakeSCIO([p, scio_project("g", "https://x/g.tgz", "failure")])
    monkeypatch.setattr(ps, "default_transport", fake)
    monkeypatch.setenv("SCANCODEIO_URL", "http://scio")
    scans = tmp_path / "s.json"
    scans.write_text(json.dumps({"packages": [{"download_url": "https://x/f.nupkg", "scan_status": "failure"}]}))
    monkeypatch.setattr("builtins.print", lambda *a, **k: None)
    scio_failures.main([str(scans), str(tmp_path / "o.json")])
    d = json.load(open(tmp_path / "o.json"))
    assert d["found"] == 1 and d["projects"][0]["uuid"] == "f" and "Could not fetch" in d["projects"][0]["reason"]
    assert all("pipeline=" not in path for _, path in fake.calls)       # API 的 FilterSet 沒有 pipeline、status


def test_copy_dir_skips_work_and_out_inside_source(tmp_path):
    import subprocess
    src = tmp_path / "proj"; work = src / "sca-results" / ".sca-scan-work.X"
    (work / "secrets").mkdir(parents=True); (work / "secrets" / "dj.h").write_text("Authorization: Token T")
    (src / "a.txt").write_text("a"); (src / ".git").mkdir()
    (src / "sub" / ".sca-scan-work.X").mkdir(parents=True)               # 名稱相同、路徑不同的要留下（anchored）
    out = src / "sca-results" / "p[1]"; out.mkdir(); (out / "status.tsv").write_text("x")   # 萬用字元不展開
    dst = tmp_path / "dst"; dst.mkdir()
    r = subprocess.run(["bash", "-c", f'. "{PILOT / "lib" / "common.sh"}"; copy_dir "$1" "$2" "$3" "$4" /elsewhere', "_",
                        str(src), str(dst), str(work), str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    got = sorted(str(p.relative_to(dst)) for p in dst.rglob("*"))
    assert got == ["a.txt", "sca-results", "sub", "sub/.sca-scan-work.X"]
    assert 'copy_dir "$SRC" "$S" "$WORK" "$OUT"' in (PILOT / "sca-scan").read_text(encoding="utf-8")
