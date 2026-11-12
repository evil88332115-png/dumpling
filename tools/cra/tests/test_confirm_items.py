"""待確認事項表（confirm_items.py，cra_report.py 每次產生 CRA/Reports/confirmation-items.csv／.md）的測試。合成的輸入，不含產品資料。"""
import csv
import io
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import confirm_items as ci  # noqa: E402
from test_cra_report import (DEB, EXAMPLE, MIN_CFG, SBOM, finding, kernel_scan, make_project, make_scan, run,  # noqa: E402
                             write_json)

HEAD = ["編號", "類別", "掃描發現（為什麼要問）", "影響", "要問誰（建議）", "要確認的問題", "建議做法", "回答", "決定", "填寫人", "日期",
        "軟體部門後續"]


def read_csv(reports):
    raw = (reports / "confirmation-items.csv").read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")                           # UTF-8 BOM：Excel 直接開中文
    rows = list(csv.reader(io.StringIO(raw.decode("utf-8-sig"))))
    return rows[0], [dict(zip(rows[0], r)) for r in rows[1:]]


def body(x):
    """「掃描發現」去掉開頭的 [穩定鍵]。"""
    t = x["掃描發現（為什麼要問）"]
    assert t.startswith("[") and "] " in t, t
    return t.split("] ", 1)[1]


def keys(s):
    return [x["key"] for x in s["confirmation_items"]["items"]]


def pdpkg(name, deps="", source=None, priority="optional", ver="1.0-1"):
    lines = [f"Package: {name}", "Status: install ok installed", f"Priority: {priority}", "Architecture: arm64", f"Version: {ver}"]
    if source:
        lines.append(f"Source: {source}")
    if deps:
        lines.append(f"Depends: {deps}")
    return "\n".join(lines)


def write_pkgdb(d, paras, auto=()):
    d.mkdir(parents=True, exist_ok=True)
    (d / "dpkg-status").write_text("\n\n".join(paras) + "\n", encoding="utf-8")
    (d / "extended_states").write_text("\n\n".join(f"Package: {n}\nArchitecture: arm64\nAuto-Installed: 1" for n in auto) + "\n",
                                       encoding="utf-8")


# 沒有修補的 KEV：原始碼套件 libfoo 的 libfoo1，只被手動安裝的 foo-viewer 依賴
NOFIX = [finding("libfoo", "1.0-1", "CVE-2026-0001", "NVD", "HIGH", kev=True, purl=DEB.format("libfoo", "1.0-1").replace("arch=arm64", "arch=source"))]
NOFIX_GRYPE = {"matches": [{"vulnerability": {"id": "CVE-2026-0001", "fix": {"state": "not-fixed", "versions": []}},
                            "relatedVulnerabilities": [], "artifact": {"name": "libfoo1", "version": "1.0-1", "type": "deb"}}]}
NOFIX_SBOM = {**SBOM, "components": [{"type": "library", "name": "libfoo1", "version": "1.0-1", "purl": DEB.format("libfoo1", "1.0-1")}]}
DEB_SOURCES = {"added": [{"purl": "pkg:deb/ubuntu/libfoo@1.0-1", "binaries": "libfoo1"}]}


def nofix_scan(d):
    scan = make_scan(d, findings=NOFIX, grype=NOFIX_GRYPE, sbom=NOFIX_SBOM)
    write_json(scan / "dt" / "deb-sources.json", DEB_SOURCES)
    return scan


# ---------- 格式、決定性、summary.json ----------

def test_csv_md_and_summary(tmp_path):
    r, s, reports = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s"))
    assert r.returncode in (0, 2), r.stderr
    head, rows = read_csv(reports)
    assert head == HEAD
    c = s["confirmation_items"]
    assert c["status"] == "OK" and c["total"] == len(rows) > 0 and sum(c["by_ask"].values()) == c["total"]
    assert sum(c["by_category"].values()) == c["total"] and c["files"] == ["confirmation-items.csv", "confirmation-items.md"]
    assert [x["編號"] for x in rows] == [f"Q{i}" for i in range(1, len(rows) + 1)]
    # 給人填的四欄留空；其他欄都有內容
    assert all(x["回答"] == x["決定"] == x["填寫人"] == x["日期"] == "" for x in rows)
    assert all(x[h] for x in rows for h in HEAD if h not in ("回答", "決定", "填寫人", "日期"))
    md = (reports / "confirmation-items.md").read_text(encoding="utf-8")
    assert md.startswith("# 待確認事項表：") and "## 怎麼用" in md and "照建議做／不同意（理由寫在回答）／需要再討論" in md
    assert "vex_export.py annotate" in md and "| " + " | ".join(HEAD) + " |" in md
    assert md.count("\n| Q") == len(rows)
    assert f"待確認事項 {c['total']} 項" in r.stdout


def test_deterministic(tmp_path):
    proj, scan = make_project(tmp_path / "p"), make_scan(tmp_path / "s")
    run(proj, scan)
    reports = proj / "CRA" / "Reports"
    a = [(reports / n).read_bytes() for n in ("confirmation-items.csv", "confirmation-items.md")]
    s1 = json.loads((reports / "summary.json").read_text(encoding="utf-8"))["confirmation_items"]
    run(proj, scan)
    assert [(reports / n).read_bytes() for n in ("confirmation-items.csv", "confirmation-items.md")] == a
    assert json.loads((reports / "summary.json").read_text(encoding="utf-8"))["confirmation_items"] == s1


# ---------- 規則 1：被利用或 P1 的漏洞 ----------

def test_p1_rows_fixed_and_unknown(tmp_path):
    _, s, reports = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s"))
    _, rows = read_csv(reports)
    v = {body(x).split(" ", 1)[0]: x for x in rows if x["類別"] == "被利用或優先處理的漏洞"}
    # brotli：KEV、Grype 有修補 1.2.1 → 建議升級；paramiko：EPSS P1、Grype 沒有比對到 → 修補狀態不明
    assert set(v) == {"CVE-2026-111497", "CVE-2023-48795"}
    assert "KEV" in v["CVE-2026-111497"]["掃描發現（為什麼要問）"] and "升級到 1.2.1" in v["CVE-2026-111497"]["建議做法"]
    assert "EPSS" in v["CVE-2023-48795"]["掃描發現（為什麼要問）"] and "修補狀態不明" in v["CVE-2023-48795"]["建議做法"]
    # 被利用的排在前面
    assert keys(s).index("vuln:CVE-2026-111497:brotli") < keys(s).index("vuln:CVE-2023-48795:paramiko")


def test_decided_rows_disappear(tmp_path):
    proj = make_project(tmp_path / "p")
    write_json(proj / "CRA" / "Config" / "vex-annotations.json", {"schema": "sca-center-vex-annotations/1", "annotations": [
        {"cve": "CVE-2026-111497", "purl": "pkg:pypi/brotli", "state": "not_affected", "justification": "code_not_reachable",
         "detail": "Decoder not used.", "author": "王小明", "date": "2026-11-01"},
        {"cve": "CVE-2023-48795", "state": "exploitable", "response": ["update"], "detail": "Upgrade planned.", "author": "王小明",
         "date": "2026-11-01"}]})
    _, s, _ = run(proj, make_scan(tmp_path / "s"))
    assert not [k for k in keys(s) if k.startswith("vuln:")]
    # 受影響但沒有寫處理方式（調查中）→ 還是要問
    write_json(proj / "CRA" / "Config" / "vex-annotations.json", {"schema": "sca-center-vex-annotations/1", "annotations": [
        {"cve": "CVE-2023-48795", "state": "in_triage", "detail": "Looking.", "author": "王小明", "date": "2026-11-01"}]})
    _, s, reports = run(proj, make_scan(tmp_path / "s2"))
    assert "vuln:CVE-2023-48795:paramiko" in keys(s)
    _, rows = read_csv(reports)
    assert "調查中（人工判定檔）" in next(x for x in rows if body(x).startswith("CVE-2023-48795"))["掃描發現（為什麼要問）"]


def test_nofix_single_reverse_dependency_asks_pm(tmp_path):
    scan = nofix_scan(tmp_path / "r" / "scan")
    write_pkgdb(tmp_path / "r" / "pkgdb", [pdpkg("foo-viewer", "libfoo1 (>= 1.0)"), pdpkg("libfoo1", source="libfoo"),
                                           pdpkg("libc6", priority="required")], auto=["libfoo1"])
    _, s, reports = run(make_project(tmp_path / "p"), scan)
    _, rows = read_csv(reports)
    x = next(x for x in rows if x["類別"] == "被利用或優先處理的漏洞")
    assert x["要問誰（建議）"] == "產品工程師、內部窗口（PM）"
    assert "內部窗口：產品需要 foo-viewer 的功能嗎？" in x["要確認的問題"]
    assert "libfoo1 是被 foo-viewer 帶進來的" in x["建議做法"] and "not-fixed" in x["建議做法"]
    assert s["confirmation_items"]["pkgdb"] == "used" and "input:pkgdb" not in keys(s)


def test_nofix_base_package_no_pm_question(tmp_path):
    scan = nofix_scan(tmp_path / "r" / "scan")
    write_pkgdb(tmp_path / "r" / "pkgdb", [pdpkg("foo-viewer", "libfoo1"), pdpkg("libfoo1", source="libfoo", priority="required")],
                auto=["libfoo1"])
    _, _, reports = run(make_project(tmp_path / "p"), scan)
    x = next(x for x in read_csv(reports)[1] if x["類別"] == "被利用或優先處理的漏洞")
    assert x["要問誰（建議）"] == "產品工程師" and "系統基本套件" in x["建議做法"]


def test_nofix_manual_package_cases(tmp_path):
    # 直接指定安裝、沒有人需要它 → 問內部窗口 要不要這個套件本身
    scan = nofix_scan(tmp_path / "r" / "scan")
    write_pkgdb(tmp_path / "r" / "pkgdb", [pdpkg("libfoo1", source="libfoo")])
    _, _, reports = run(make_project(tmp_path / "p"), scan)
    x = next(x for x in read_csv(reports)[1] if x["類別"] == "被利用或優先處理的漏洞")
    assert "內部窗口：產品需要 libfoo1 嗎？" in x["要確認的問題"] and "直接指定安裝的，沒有別的套件需要它" in x["建議做法"]
    # 直接指定安裝、另外有套件需要它 → 不問內部窗口，寫出需要它的套件
    write_pkgdb(tmp_path / "r" / "pkgdb", [pdpkg("libfoo1", source="libfoo"), pdpkg("bar", "libfoo1")])
    _, _, reports = run(make_project(tmp_path / "p2"), scan)
    x = next(x for x in read_csv(reports)[1] if x["類別"] == "被利用或優先處理的漏洞")
    assert x["要問誰（建議）"] == "產品工程師" and "另外 bar 也需要它" in x["建議做法"]


def test_nofix_without_pkgdb_is_missing_input(tmp_path):
    scan = nofix_scan(tmp_path / "s")
    _, s, reports = run(make_project(tmp_path / "p"), scan)
    assert "input:pkgdb" in keys(s) and s["confirmation_items"]["pkgdb"] == "not_available"
    rows = read_csv(reports)[1]
    miss = next(x for x in rows if x["類別"] == "缺少輸入" and "pkgdb" in x["掃描發現（為什麼要問）"])
    assert "CVE-2026-0001 libfoo" in miss["掃描發現（為什麼要問）"]
    x = next(x for x in rows if x["類別"] == "被利用或優先處理的漏洞")
    assert "看不出是哪個套件把它帶進映像" in x["建議做法"] and "內部窗口" not in x["要問誰（建議）"] and "PM" not in x["要問誰（建議）"]


def test_pkgdb_option(tmp_path):
    write_pkgdb(tmp_path / "db", [pdpkg("foo-viewer", "libfoo1"), pdpkg("libfoo1", source="libfoo")], auto=["libfoo1"])
    scan = nofix_scan(tmp_path / "s")
    _, s, _ = run(make_project(tmp_path / "p"), scan, "--pkgdb", str(tmp_path / "db"))
    assert s["confirmation_items"]["pkgdb"] == "used" and "input:pkgdb" not in keys(s)
    r, _, _ = run(make_project(tmp_path / "p2"), scan, "--pkgdb", str(tmp_path / "nothing"))
    assert r.returncode == 64


def test_no_findings_is_missing_input(tmp_path):
    _, s, _ = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s", findings=None))
    k = keys(s)
    assert "input:findings" in k and not [x for x in k if x.startswith("vuln:")]


# ---------- 規則 2：安全測試 ----------

IMG = {"schema": "sca-center-image-check/1", "tool_version": "t", "status": "ATTENTION", "generated": "2026-11-03T00:00:00Z",
       "coverage": {"counts": {}}, "findings": [
           {"id": "accounts:password-in-image", "check": "accounts", "severity": "high", "title": "Login accounts have a password set",
            "text": "t", "annex": ["I-2b"], "evidence": ["user1"], "evidence_total": 1},
           {"id": "ssh:baked-host-keys", "check": "ssh", "severity": "high", "title": "SSH host keys baked in", "text": "t",
            "annex": ["I-2d"], "evidence": ["/etc/ssh/ssh_host_ed25519_key"], "evidence_total": 1},
           {"id": "service:ssh", "check": "services", "severity": "medium", "title": "SSH server enabled", "text": "t", "annex": [],
            "evidence": ["ssh.service"], "evidence_total": 1},
           {"id": "perm:world-writable", "check": "permissions", "severity": "medium", "title": "World-writable", "text": "t",
            "annex": [], "evidence": ["/opt/x"], "evidence_total": 1},
           {"id": "secrets:private-keys", "check": "secrets", "severity": "high", "title": "Private keys", "text": "t", "annex": [],
            "evidence": ["/opt/key.pem"], "evidence_total": 1},
           {"id": "elf:vendor", "check": "elf", "severity": "medium", "title": "Vendor ELF without hardening", "text": "t",
            "annex": [], "evidence": ["/opt/bin/a"], "evidence_total": 1},
           {"id": "secrets:example-config", "check": "secrets", "severity": "info", "title": "Example", "text": "t", "annex": [],
            "evidence": ["/usr/share/doc/x"], "evidence_total": 1}]}


def test_security_findings_items(tmp_path):
    proj = make_project(tmp_path / "p")
    scan = make_scan(tmp_path / "r" / "scan")
    write_json(tmp_path / "r" / "image-check" / "image-check.json", IMG)
    _, s, reports = run(proj, scan)
    k = keys(s)
    for x in ("sec:passwords", "sec:host-keys", "sec:services", "sec:world-writable", "sec:secrets", "sec:other", "input:security-tests"):
        assert x in k, x
    rows = {body(x).split("：", 1)[0]: x for x in read_csv(reports)[1] if x["類別"] == "安全測試"}
    assert rows["映像裡設好的密碼（每台相同的預設密碼）"]["要問誰（建議）"] == "內部窗口（PM）、產品工程師"
    assert "img:elf:vendor" in rows["其他沒有決定的 high／medium 安全測試項目"]["掃描發現（為什麼要問）"]
    assert not [x for x in rows.values() if "example-config" in x["掃描發現（為什麼要問）"]]      # info 不問
    miss = next(x for x in read_csv(reports)[1] if x["類別"] == "缺少輸入" and "安全測試" in x["掃描發現（為什麼要問）"])
    assert "板子上的檢查" in miss["掃描發現（為什麼要問）"] and "映像靜態檢查" not in miss["掃描發現（為什麼要問）"]
    # 有決定的項目不再問
    write_json(proj / "CRA" / "Config" / "security-findings.json", {"schema": "sca-center-security-findings/1", "decisions": [
        {"id": "img:ssh:baked-host-keys", "status": "accepted", "reason": "Regenerated at first boot.", "author": "王小明",
         "date": "2026-11-03"}]})
    _, s, _ = run(proj, scan)
    assert "sec:host-keys" not in keys(s) and "sec:passwords" in keys(s)


def test_security_not_run_at_all(tmp_path):
    _, s, reports = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s"))
    miss = next(x for x in read_csv(reports)[1] if x["類別"] == "缺少輸入" and "安全測試" in x["掃描發現（為什麼要問）"])
    assert "映像靜態檢查" in miss["掃描發現（為什麼要問）"] and not [x for x in keys(s) if x.startswith("sec:")]


# ---------- 規則 3：開發工具 ----------

def test_dev_tools(tmp_path):
    comps = [{"type": "library", "name": n, "version": "13.2-1", "purl": DEB.format(n, "13.2-1")} for n in ("gcc-13", "gdb", "libbar-dev")]
    dev = [finding("gcc-13", "13.2-1", "CVE-2026-0300", "NVD", "LOW")]
    _, s, reports = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s", findings=dev, sbom={**SBOM, "components": comps}))
    x = next(x for x in read_csv(reports)[1] if x["類別"] == "開發工具")
    assert x["要問誰（建議）"] == "內部窗口（PM）" and "gcc-13、gdb" in x["掃描發現（為什麼要問）"] and "未處理漏洞列 1 列" in x["影響"]
    # 沒有開發工具、-dev 不多 → 不問
    _, s, _ = run(make_project(tmp_path / "p2"), make_scan(tmp_path / "s2"))
    assert "dev:tools" not in keys(s)


# ---------- 規則 4：作業系統核心 ----------

def kcfg(build_record=None, status="OK"):
    k = {"version": "6.8.12-1021-tegra", "config_source": "/boot/config", "config_sha256": "ab" * 32}
    if build_record is not None:
        k["build_record"] = build_record
    return {"schema": "sca-center-kernel-config/1", "status": status, "detail": "x", "kernel": k,
            "component": {"name": "linux-nvidia-tegra", "version": "6.8.0-1021.21",
                          "purl": "pkg:deb/ubuntu/linux-nvidia-tegra@6.8.0-1021.21?arch=source&distro=ubuntu-24.04"},
            "results": [], "counts": {}}


def test_kernel_items(tmp_path):
    scan = kernel_scan(tmp_path / "s")
    _, s, reports = run(make_project(tmp_path / "p"), scan)
    k = keys(s)
    assert "kernel:config" in k and "kernel:build-record" in k and "kernel:not-assessed" not in k
    x = next(x for x in read_csv(reports)[1] if x["類別"] == "作業系統核心" and "建置紀錄" in x["掃描發現（為什麼要問）"])
    assert all(f in x["建議做法"] for f in (".config", ".*.cmd", "modules.order", "modules.builtin", "System.map"))
    # 核心的 KEV 列：建議換核心，不問內部窗口
    kv = next(x for x in read_csv(reports)[1] if body(x).startswith("CVE-2024-1086"))
    assert "核心" in kv["建議做法"] and kv["要問誰（建議）"] == "產品工程師"
    # 舊版 kernel-config.json（沒有 build_record）：設定比對有結果，但還是要建置紀錄
    write_json(scan / "scan" / "kernel-config.json", kcfg())
    _, s, _ = run(make_project(tmp_path / "p2"), scan)
    assert "kernel:config" not in keys(s) and "kernel:build-record" in keys(s)
    write_json(scan / "scan" / "kernel-config.json", kcfg({"status": "GAP", "reason": "no .cmd files"}))
    _, s, reports = run(make_project(tmp_path / "p3"), scan)
    assert "kernel:build-record" in keys(s)
    assert "no .cmd files" in next(x for x in read_csv(reports)[1] if x["類別"] == "作業系統核心")["掃描發現（為什麼要問）"]
    # kernel_config 草案的格式只有 status（沒有 used）：只有 status OK 才算用到
    write_json(scan / "scan" / "kernel-config.json", kcfg({"used": True, "files": ["System.map"]}))
    _, s, _ = run(make_project(tmp_path / "p4"), scan)
    assert "kernel:build-record" in keys(s)
    write_json(scan / "scan" / "kernel-config.json", kcfg({"status": "OK", "files": ["System.map"]}))
    _, s, _ = run(make_project(tmp_path / "p5"), scan)
    assert not [x for x in keys(s) if x.startswith("kernel:")]


def test_kernel_not_assessed(tmp_path):
    scan = make_scan(tmp_path / "s", stages={"C-kernel-coverage": "GAP"})
    _, s, reports = run(make_project(tmp_path / "p"), scan)
    assert "kernel:not-assessed" in keys(s)
    x = next(x for x in read_csv(reports)[1] if x["類別"] == "作業系統核心")
    assert "C-kernel-coverage GAP" in x["掃描發現（為什麼要問）"] and "不是 0 個" in x["影響"]


# ---------- 規則 5–7 ----------

def test_exposed_services(tmp_path):
    cfg = json.loads(json.dumps(EXAMPLE))
    cfg.setdefault("vulnerability_policy", {})["scheme"] = "exploitation"
    proj = make_project(tmp_path / "p", cfg)
    _, s, _ = run(proj, make_scan(tmp_path / "s"))
    assert "services:list" in keys(s)
    write_json(proj / "CRA" / "Config" / "exposed-services.json", {"schema": "sca-center-exposed-services/1", "collected": "2026-11-01",
                                                                   "services": []})
    _, s, _ = run(proj, make_scan(tmp_path / "s2"))
    assert "services:list" not in keys(s)
    _, s, _ = run(make_project(tmp_path / "p3"), make_scan(tmp_path / "s3"))      # current：不需要
    assert "services:list" not in keys(s)


def test_company_fields_grouped_by_owner(tmp_path):
    _, s, reports = run(make_project(tmp_path / "p", MIN_CFG), make_scan(tmp_path / "s"))
    k = keys(s)
    for o in ("PM", "PM＋法務", "老闆／產品主管", "QA／認證", "產品工程師"):
        assert f"fields:{o}" in k, o
    rows = {x["要問誰（建議）"]: x for x in read_csv(reports)[1] if x["類別"] == "公司與產品資料"}
    assert sorted(rows) == sorted(("內部窗口（PM）", "內部窗口（PM）＋法務", "老闆／產品主管", "QA／認證", "產品工程師"))
    # summary.json 的 by_ask 與格子的文字一致（穩定鍵 fields:<代號> 不跟著稱呼改）
    by_ask = s["confirmation_items"]["by_ask"]
    assert "PM" not in by_ask and "PM＋法務" not in by_ask and "內部窗口（PM）＋法務" in by_ask
    assert set(by_ask) == {x["要問誰（建議）"] for x in read_csv(reports)[1]}
    assert "vulnerability_contact.contact" in rows["內部窗口（PM）＋法務"]["掃描發現（為什麼要問）"]
    assert "support.end_date" in rows["老闆／產品主管"]["掃描發現（為什麼要問）"]
    assert "technical_documentation.standards" in rows["QA／認證"]["掃描發現（為什麼要問）"]
    assert "manufacturer.email" in rows["內部窗口（PM）"]["掃描發現（為什麼要問）"] and "公司共用設定" in rows["內部窗口（PM）"]["建議做法"]
    assert "經內部窗口找人回答、交回掃描負責人" in rows["內部窗口（PM）"]["建議做法"]
    assert "經內部窗口找人回答" in rows["內部窗口（PM）＋法務"]["建議做法"]
    # 產品工程師的欄位：直接問，不經內部窗口
    assert rows["產品工程師"]["建議做法"].startswith("產品工程師直接回覆掃描負責人") and "內部窗口" not in rows["產品工程師"]["建議做法"]
    # 每個缺的欄位剛好在一個事項裡
    miss = s["missing_fields"]
    text = " ".join(x["掃描發現（為什麼要問）"] for x in rows.values())
    assert all(f"（{m}）" in text for m in miss)
    # 範例設定是完整的：沒有欄位要問
    _, s, _ = run(make_project(tmp_path / "p2"), make_scan(tmp_path / "s2"))
    assert not [x for x in keys(s) if x.startswith("fields:")]


def test_supplier_fields(tmp_path):
    cfg = dict(MIN_CFG, role="supplier")
    _, s, _ = run(make_project(tmp_path / "p", cfg), make_scan(tmp_path / "s"))
    assert s["supplier_package"]["missing_fields"]
    by = {x["key"]: x for x in s["confirmation_items"]["items"]}
    assert "fields:PM＋法務" in by       # supplier.notification.*（通知時數）與弱點通報窗口
    md = (tmp_path / "p" / "CRA" / "Reports" / "confirmation-items.md").read_text(encoding="utf-8")
    assert "supplier.notification.exploited_hours" in md and "客戶（製造商）" in md


def test_shipping_record(tmp_path):
    _, s, _ = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s"))
    assert "shipping:record" in keys(s)
    cfg = json.loads(json.dumps(EXAMPLE))
    cfg["product"]["first_placing_on_market"] = "2026-12-01"
    _, s, _ = run(make_project(tmp_path / "p2", cfg), make_scan(tmp_path / "s2"))
    assert "shipping:record" not in keys(s)


def test_fail_removes_previous_table(tmp_path):
    proj = make_project(tmp_path / "p")
    scan = make_scan(tmp_path / "s")
    run(proj, scan)
    assert (proj / "CRA" / "Reports" / "confirmation-items.csv").exists()
    write_json(proj / "CRA" / "Config" / "config.json", {"schema_version": 1})      # 缺必填 → FAIL
    r, _, reports = run(proj, scan)
    assert r.returncode == 1 and not (reports / "confirmation-items.csv").exists() and not (reports / "confirmation-items.md").exists()


# ---------- 單元：不靠 cra_report ----------

def test_build_order_and_ids_unit():
    rows = [{"id": "CVE-2026-2", "component": "b", "version": "1", "tier": "p1", "kev": False, "epss_pct": 0.95, "fix_state": "fixed",
             "fix_versions": ["2"], "fix_next": "2", "ptype": "pypi", "purl": "pkg:pypi/b@1", "severity": "LOW"},
            {"id": "CVE-2026-1", "component": "a", "version": "1", "tier": "p1", "kev": True, "fix_state": "fixed",
             "fix_versions": ["2"], "fix_next": "2", "ptype": "pypi", "purl": "pkg:pypi/a@1", "severity": "HIGH"},
            {"id": "CVE-2026-3", "component": "c", "version": "1", "tier": "p3", "kev": False}]
    items = ci.build(rows=rows, sec={"ran": {"image": True, "board": True, "network": True}, "findings": []},
                     cfg={"product": {"first_placing_on_market": "2026-01-01"}})
    assert [(x["id"], x["key"]) for x in items] == [("Q1", "vuln:CVE-2026-1:a"), ("Q2", "vuln:CVE-2026-2:b")]
    assert ci.build(rows=list(reversed(rows)), sec={"ran": {"image": True, "board": True, "network": True}, "findings": []},
                    cfg={"product": {"first_placing_on_market": "2026-01-01"}}) == items


# ---------- #169 審查 ----------

def test_rejected_decision_stays(tmp_path):
    # KEV 列上沒有具名負責人（TBD）的 not_affected：cra_report 不採用（列還在 P1），表裡要留著並寫出原因
    proj = make_project(tmp_path / "p")
    write_json(proj / "CRA" / "Config" / "vex-annotations.json", {"schema": "sca-center-vex-annotations/1", "annotations": [
        {"cve": "CVE-2026-111497", "purl": "pkg:pypi/brotli", "state": "not_affected", "justification": "code_not_reachable",
         "detail": "Decoder not used.", "author": "TBD", "date": "2026-11-01"}]})
    _, s, reports = run(proj, make_scan(tmp_path / "s"))
    assert "vuln:CVE-2026-111497:brotli" in keys(s)
    x = next(x for x in read_csv(reports)[1] if body(x).startswith("CVE-2026-111497"))
    assert "判定沒有被採用（沒有具名負責人" in body(x)
    # 受影響＋處理方式，但負責人是代稱 → 也留著
    write_json(proj / "CRA" / "Config" / "vex-annotations.json", {"schema": "sca-center-vex-annotations/1", "annotations": [
        {"cve": "CVE-2026-111497", "state": "exploitable", "response": ["update"], "detail": "Upgrade.", "author": "TBD",
         "date": "2026-11-01"}]})
    _, s, _ = run(proj, make_scan(tmp_path / "s2"))
    assert "vuln:CVE-2026-111497:brotli" in keys(s)


def test_unit_decided_rules():
    ok = {"source": "annotation", "state": "exploitable", "response": ["update"], "author": "王小明"}
    assert ci.decided(ok, ("dt", "annotation"))
    assert not ci.decided(dict(ok, author="TBD"), ("dt", "annotation"))
    assert not ci.decided(dict(ok, response=[]), ("dt", "annotation"))
    assert not ci.decided(dict(ok, source="rule"), ("dt", "annotation"))
    assert not ci.decided(dict(ok, state="not_affected"), ("dt", "annotation"))     # 列還開著＝沒有被採用


def test_sbom_gap_item(tmp_path):
    _, s, reports = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s", stages={"B-npm-no-lockfile": "GAP"}))
    assert s["documents"]["sbom"]["status"] == "GAP" and "input:sbom-gap" in keys(s)
    x = next(x for x in read_csv(reports)[1] if body(x).startswith("SBOM 不完整"))
    assert "B-npm-no-lockfile is GAP" in body(x)
    _, s, _ = run(make_project(tmp_path / "p2"), make_scan(tmp_path / "s2"))
    assert "input:sbom-gap" not in keys(s) and "input:sbom" not in keys(s)


def test_table_write_error_does_not_break_report(tmp_path):
    proj, scan = make_project(tmp_path / "p"), make_scan(tmp_path / "s")
    run(proj, scan)
    rep = proj / "CRA" / "Reports"
    (rep / "confirmation-items.csv").unlink()
    (rep / "confirmation-items.csv").mkdir()          # 寫不進去，也刪不掉
    r, s, _ = run(proj, scan)
    assert r.returncode in (0, 2), r.stderr
    c = s["confirmation_items"]
    assert c["status"] == "FAIL" and c["total"] is None and "remove_error" in c
    assert not (rep / "confirmation-items.md").exists()
    assert (rep / "risk-assessment.md").exists() and "待確認事項表 FAIL" in r.stdout


def test_table_build_exception_in_process(tmp_path, monkeypatch):
    import cra_report as cr
    proj, scan = make_project(tmp_path / "p"), make_scan(tmp_path / "s")
    run(proj, scan)
    rep = proj / "CRA" / "Reports"
    cm = cr.confmod()

    def boom(*a, **k):
        raise RuntimeError("forced")
    monkeypatch.setattr(cm, "build", boom)
    monkeypatch.setenv("CRA_COMPANY_CONFIG", "none")
    rc = cr.main(["--project", str(proj), "--scan", str(scan)])
    s = json.loads((rep / "summary.json").read_text(encoding="utf-8"))
    assert rc in (0, 2) and s["confirmation_items"]["status"] == "FAIL" and "RuntimeError" in s["confirmation_items"]["error"]
    assert not (rep / "confirmation-items.csv").exists() and not (rep / "confirmation-items.md").exists()


def test_pkgdb_symlink_and_size_rejected(tmp_path, monkeypatch):
    import os
    pw = ci.pkgwhy()
    real = tmp_path / "real"
    write_pkgdb(real, [pdpkg("libfoo1", source="libfoo")])
    link = tmp_path / "link"
    link.mkdir()
    os.symlink(real / "dpkg-status", link / "dpkg-status")
    db, why = ci.load_pkgdb(link)
    assert db is None and "符號連結" in why
    fifo = tmp_path / "fifo"
    fifo.mkdir()
    os.mkfifo(fifo / "dpkg-status")
    db, why = ci.load_pkgdb(fifo)
    assert db is None and "不是一般檔案" in why
    monkeypatch.setattr(pw, "MAX_FILE", 10)
    db, why = ci.load_pkgdb(real)
    assert db is None and "太大" in why
    monkeypatch.undo()
    assert ci.load_pkgdb(real)[0] is not None
    # 跟 cra_report 一起：符號連結的 pkgdb 不用，事項照樣產生（看不出依賴）
    scan = nofix_scan(tmp_path / "r" / "scan")
    (tmp_path / "r" / "pkgdb").mkdir()
    os.symlink(real / "dpkg-status", tmp_path / "r" / "pkgdb" / "dpkg-status")
    _, s, _ = run(make_project(tmp_path / "p"), scan)
    assert s["confirmation_items"]["pkgdb"] == "not_available" and "input:pkgdb" in keys(s)


def test_csv_formula_escape_and_stable_key_prefix():
    x = {"id": "Q1", "category": "c", "key": "k:1", "finding": "f", "impact": "=HYPERLINK(1)", "ask": "@x", "question": "+q",
         "suggestion": "-s", "followup": "ok\r\nnext"}
    rows = list(csv.reader(io.StringIO(ci.csv_text([x])[1:])))
    assert rows[1][2] == "[k:1] f" and rows[1][3] == "'=HYPERLINK(1)" and rows[1][4] == "'@x" and rows[1][5] == "'+q"
    assert rows[1][6] == "'-s"
    assert "\r" not in ci.md_cell("a\r\nb")


def test_csv_formula_escape_tab_and_cr():
    assert ci.csv_safe("\t=1") == "'\t=1" and ci.csv_safe("\r=1") == "'\r=1"
    assert ci.csv_safe("a\t=1") == "a\t=1" and ci.csv_safe("") == "" and ci.csv_safe("ok") == "ok"
    x = {"id": "Q1", "category": "c", "key": "k:1", "finding": "f", "impact": "\t=cmd", "ask": "\r@x", "question": "q",
         "suggestion": "s", "followup": "f"}
    rows = list(csv.reader(io.StringIO(ci.csv_text([x])[1:], newline="")))
    assert rows[1][3] == "'\t=cmd" and rows[1][4] == "'\r@x"


def test_rejected_why_dt_clause_only_for_dt():
    human = ("dt", "annotation")
    row = lambda v: {"vex": v}       # noqa: E731
    exp = {"state": "exploitable", "response": ["update"]}
    dt = ci.rejected_why(row(dict(exp, source="dt")), human, ci.author_missing_default, False)
    assert dt == "沒有具名負責人（DT 的分析不帶負責人，要用 vex_export.py annotate 記具名的決定）"
    for a in (None, "", "TBD", " 專案負責人 "):
        ann = ci.rejected_why(row(dict(exp, source="annotation", author=a)), human, ci.author_missing_default, False)
        assert ann == "沒有具名負責人", a
    assert ci.rejected_why(row(dict(exp, source="annotation", author="王小明")), human, ci.author_missing_default, False) is None
    assert ci.rejected_why(row(dict(exp, source="rule")), human, ci.author_missing_default, False) is None


def test_state_text_with_and_without_response():
    assert ci.state_text({"state": "exploitable"}) == "受影響（還沒有處理方式）"
    assert ci.state_text({"state": "exploitable", "response": []}) == "受影響（還沒有處理方式）"
    assert ci.state_text({"state": "exploitable", "response": ["workaround_available", "update"]}) == \
        "受影響（已有處理方式：update、workaround_available）"
    assert ci.state_text({"state": "exploitable", "response": "update"}) == "受影響（已有處理方式：update）"
    assert ci.state_text({"state": "exploitable", "response": [" ", ""]}) == "受影響（還沒有處理方式）"
    assert ci.state_text({"state": "not_affected", "response": ["update"]}) == "不受影響"
    assert ci.state_text({"state": "weird"}) == "weird"
    # 事項的掃描發現：受影響＋處理方式、沒有具名負責人（annotation）→ 寫出處理方式，原因不帶 DT 的說明
    r = {"id": "CVE-2026-9", "component": "a", "version": "1", "tier": "p1", "kev": True, "fix_state": "fixed", "fix_versions": ["2"],
         "fix_next": "2", "ptype": "pypi", "purl": "pkg:pypi/a@1", "severity": "HIGH",
         "vex": {"source": "annotation", "state": "exploitable", "response": ["update"], "author": "TBD"}}
    items, _ = ci.vuln_items([r], ("dt", "annotation"), None, "沒有提供")
    f = items[0]["finding"]
    assert "目前的判定：受影響（已有處理方式：update）（人工判定檔）" in f and "還沒有處理方式" not in f
    assert "判定沒有被採用（沒有具名負責人）" in f and "DT 的分析不帶負責人" not in f
    items, _ = ci.vuln_items([dict(r, vex={"source": "dt", "state": "exploitable", "response": ["update"]})], ("dt", "annotation"),
                             None, "沒有提供")
    assert "（DT 的人工分析）" in items[0]["finding"] and "DT 的分析不帶負責人" in items[0]["finding"]


def test_pm_window_and_not_p1_wording(tmp_path):
    proj = make_project(tmp_path / "p")
    scan = make_scan(tmp_path / "r" / "scan")
    write_json(tmp_path / "r" / "image-check" / "image-check.json", IMG)
    _, _, reports = run(proj, scan)
    md = (reports / "confirmation-items.md").read_text(encoding="utf-8")
    # 出貨前（這張表）：掃描負責人和產品工程師直接處理，完成後交給內部窗口（PM）；只有需要別人的問題經過內部窗口
    assert ("掃描負責人和產品工程師直接一起處理這張表 → 工程師回覆、具名判斷、修好後 → 掃描負責人記錄並重掃 → "
            "完成後把六樣交付交給內部窗口（PM）") in md
    assert "只有需要別人（內部窗口／法務／老闆）的問題才經過內部窗口" in md
    assert "六樣交付：SBOM、漏洞清單、VEX、安全檢查結果、待確認事項表、客戶資料包（ODM 案）。" in md
    # 出貨後的路徑只寫一句當背景
    assert "掃描負責人 → 內部窗口（PM）→ 內部窗口通知產品工程師（修補），並轉給公司指定的人＋法務（要不要通報）" in md
    assert "PM（窗口）" not in md and "回覆交回 PM" not in md and "回覆交回內部窗口" not in md
    # 產品工程師的事項不經內部窗口
    for x in read_csv(reports)[1]:
        if x["要問誰（建議）"] == "產品工程師":
            assert "內部窗口" not in x["建議做法"] + x["軟體部門後續"], x
    for x in read_csv(reports)[1]:
        if x["類別"] in ("安全測試", "開發工具"):
            assert x["建議做法"].endswith("（非 P1：2027-12-11 前處理）"), x
        if x["類別"] == "被利用或優先處理的漏洞":
            assert "非 P1" not in x["建議做法"]


def test_two_kernels_item_and_warning(tmp_path):
    """C-kernel-boot（scan/kernel-boot.json）ATTENTION → 待確認事項請 RD 確認實際開機的核心，報告警告也列出；OK 不問。"""
    scan = kernel_scan(tmp_path / "s")
    kb = {"schema": "sca-center-kernel-boot/1", "status": "ATTENTION", "detail": "two different kernels in the package", "k1_kernel": "partition",
          "partition_image": {"sha256": "aa" * 32, "uts": "#1 SMP PREEMPT Wed Oct 28 11:08:26 CST 2026"},
          "rootfs_image": {"sha256": "bb" * 32, "uts": "#1 SMP PREEMPT Mon Jun 1 13:25:46 PDT 2026"},
          "extlinux": {"points_at": "rootfs/boot/Image"}, "config_diff": {"differences_total": 31}, "board": None}
    write_json(scan / "scan" / "kernel-boot.json", kb)
    out, s, reports = run(make_project(tmp_path / "p"), scan)
    assert "kernel:two-kernels" in keys(s)
    x = next(x for x in read_csv(reports)[1] if "kernel:two-kernels" in x["掃描發現（為什麼要問）"])
    assert any("C-kernel-boot ATTENTION" in w for w in s["config_warnings"])
    assert "rootfs/boot/Image" in x["掃描發現（為什麼要問）"] and "31" in x["掃描發現（為什麼要問）"]
    write_json(scan / "scan" / "kernel-boot.json", dict(kb, status="OK"))
    _, s, _ = run(make_project(tmp_path / "p2"), scan)
    assert "kernel:two-kernels" not in keys(s)


def test_two_kernels_item_wording_follows_the_facts(tmp_path):
    base = {"schema": "sca-center-kernel-boot/1", "status": "ATTENTION", "detail": "d", "k1_kernel": "partition",
            "partition_image": {"sha256": "aa" * 32, "uts": "#1 SMP A"}, "rootfs_image": {"sha256": "aa" * 32, "uts": "#1 SMP A"},
            "extlinux": {"present": True, "points_at": "rootfs/boot/Image"}, "config_diff": None, "build_record": None,
            "board": {"given": True, "parsed": True, "uname_v": "#9 SMP Z", "matches_partition_image": False, "matches_rootfs_image": False}}
    x = ci.boot_items(base)[0]            # 相同的兩顆核心、板子對不上
    assert "位元組相同" in x["finding"] and "兩顆不同" not in x["finding"] and "和兩顆核心都對不上" in x["finding"]
    assert x["ask"] == "RD" and "建置紀錄對應 kernel/Image" not in x["question"]
    y = ci.boot_items(dict(base, board=None, build_record={"matches_partition_image": False, "matches_rootfs_image": False}))[0]
    assert "BUILD-INFO" in y["finding"] and "建置紀錄是不是這版出貨" in y["question"]       # 相同的核心、建置紀錄對不上
    z = ci.boot_items(dict(base, status="GAP", detail="rootfs/boot/Image could not be read", partition_image={"uts": None}))[0]
    assert "無法比較" in z["finding"] and "None" not in z["finding"]
    d = ci.boot_items(dict(base, rootfs_image={"sha256": "bb" * 32, "uts": "#1 SMP B"}, board=None, extlinux={"present": False}))[0]
    assert "兩顆不同" in d["finding"] and "沒有 extlinux.conf" in d["finding"] and "指向 /boot/Image" not in d["finding"]
