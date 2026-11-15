"""cra_report.py：C-kernel-coverage 不是 OK 時，核心段落（risk-assessment.md 8.7 節、kernel-vulnerabilities.md）照實帶出限制（M7d-5，D-063）。

- 狀態列的說明原文（只顯示，不拿來判斷）；
- 「Kernel CVE list: N CVEs (source: …); listed as rows: M CVEs; the other N−M are not listed as rows」：N 讀 scan/kernel-config.json 的 results 與
  inputs.cves_origin（結構化欄位），只有 N 讀得到而且 N > M 時才寫。
- OK 時輸出逐位元組不變（data/kernel-ok-baseline.json 是改前的程式〔main 33da59c〕對同一份輸入的輸出）。
- 客戶版（supplier-package）沒有核心段落：不帶任何核心狀態文字。
判定不變：C-kernel-coverage 本來就在 COND_STAGES（不是 OK → 資料狀態 GAP）；這裡只補文字。
"""
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import cra_report as cr  # noqa: E402
from test_cra_report import KFINDINGS, KGRYPE, KMAP, MIN_CFG, kernel_scan, make_project, make_scan, run, section_87, write_json  # noqa: E402

BASELINE = HERE / "data" / "kernel-ok-baseline.json"
KERNEL_CVES = ["CVE-2024-1086"] + [f"CVE-2025-010{i}" for i in range(1, 8)]          # KFINDINGS 的 8 個核心 CVE
STAMP = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ|(?<=SHA-256 )[0-9a-f]{12}")      # 時間戳，與由時間戳決定的 VEX 檔雜湊（文件裡引用的前 12 碼）
ZH_DETAIL = "核心的比對只有上游版本範圍（NVD；generic 核心元件 3 筆），發行版核心套件 linux-image-x 沒有比對到發行版的安全資料，沒有用到發行版的修補（含回移）資訊：可能有誤報，也可能漏報"


def with_status_detail(scan, stage, detail):
    p = scan / "status.tsv"
    lines = [l if not l.startswith(stage + "\t") else f"{stage}\t{l.split(chr(9))[1]}\t{detail}" for l in p.read_text(encoding="utf-8").splitlines()]
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")


def kcfg(n_extra, origin="KERNEL_CVES（明確給的清單）", schema="sca-center-kernel-config/1", cves=None):
    cves = cves if cves is not None else KERNEL_CVES + [f"CVE-2023-9{i:03d}" for i in range(n_extra)]
    inputs = {"cves_origin": origin} if origin is not None else {}
    return {"schema": schema, "inputs": inputs, "results": [{"cve": c, "files": []} for c in cves]}


def gap_scan(d, **kw):
    scan = kernel_scan(d, stages={"C-kernel-coverage": "GAP"})
    with_status_detail(scan, "C-kernel-coverage", ZH_DETAIL)
    if kw.get("kcfg") is not None:
        write_json(scan / "scan" / "kernel-config.json", kw["kcfg"])
    return scan


def docs(tmp_path, **kw):
    r, s, reports = run(make_project(tmp_path / "p"), gap_scan(tmp_path / "s", **kw))
    assert r.returncode in (0, 2), r.stdout + r.stderr
    return s, (reports / "risk-assessment.md").read_text(encoding="utf-8"), (reports / "kernel-vulnerabilities.md").read_text(encoding="utf-8"), reports


# ---------- GAP：說明原文與 N／M ----------

def test_gap_shows_status_text_and_cve_list_counts_in_both_documents(tmp_path):
    s, ra, kd, _ = docs(tmp_path, kcfg=kcfg(4))
    line = ("Kernel CVE list: 12 CVEs (source: KERNEL_CVES explicit list, merged with the Grype and Dependency-Track kernel findings; "
            "`scan/kernel-config.json`); listed as rows: 8 CVEs; the other 4 are not listed as rows.")
    for text in (section_87(ra), kd):
        assert "**Kernel coverage limitation:** `C-kernel-coverage` is GAP. Status text as recorded by sca-scan:" in text
        assert f"> {ZH_DETAIL}" in text
        assert line in text
    assert "listed as rows: 8 CVEs" in kd.split("## Full list")[0]            # 摘要段（不是完整清單）
    # 判定不變：本來就是 GAP（COND_STAGES）；理由照舊
    assert s["documents"]["risk-assessment"]["status"] == "GAP"
    assert "C-kernel-coverage is GAP" in s["documents"]["risk-assessment"]["detail"]


@pytest.mark.parametrize("origin,source", [
    (None, "Grype and Dependency-Track kernel findings"),
    ("kernel-cna-version（核心 6.18.50）", "kernel CNA version comparison"),
    ("something else", "not recognised"),
])
def test_cve_list_source_comes_from_structured_origin(tmp_path, origin, source):
    s, ra, kd, _ = docs(tmp_path, kcfg=kcfg(2, origin=origin))
    assert f"(source: {source}; `scan/kernel-config.json`); listed as rows: 8 CVEs; the other 2 are not listed as rows." in kd


@pytest.mark.parametrize("name,cfg", [
    ("no file", None),
    ("N equals M", kcfg(0)),
    ("N smaller than M", kcfg(0, cves=KERNEL_CVES[:5])),
    ("wrong schema", kcfg(4, schema="something/1")),
    ("no results", {"schema": "sca-center-kernel-config/1", "inputs": {}}),
    ("results not a list", {"schema": "sca-center-kernel-config/1", "inputs": {}, "results": "x"}),
    ("empty results", kcfg(0, cves=[])),
])
def test_cve_list_line_not_written_when_n_unknown_or_not_larger(tmp_path, name, cfg):
    s, ra, kd, _ = docs(tmp_path, kcfg=cfg)
    for text in (section_87(ra), kd):
        assert "Kernel CVE list:" not in text
        assert f"> {ZH_DETAIL}" in text                                  # 說明原文照樣帶出


def test_listed_count_is_distinct_cves_of_kernel_rows_in_n(tmp_path):
    """M 只算清單 N 裡面有、而且在核心列的 CVE：核心列有清單以外的 CVE 時，N−M 才是真正沒成列的數量。"""
    cfg = kcfg(0, cves=KERNEL_CVES[:4] + ["CVE-2023-9001", "CVE-2023-9002"])         # 4 個有列＋2 個沒有；核心列另有 4 個不在清單
    s, ra, kd, _ = docs(tmp_path, kcfg=cfg)
    assert "Kernel CVE list: 6 CVEs" in kd and "listed as rows: 4 CVEs; the other 2 are not listed as rows." in kd


def test_text_helpers_are_structure_only():
    rows = [{"id": "CVE-2025-1", "cves": ["CVE-2025-1"]}, {"id": "GRYPE:CVE-2025-2", "cves": ["cve-2025-2"]}, {"id": "CVE-2025-1", "cves": []}]
    st = {"C-kernel-coverage": ("GAP", "任何文字，包括 N = 99")}
    cfg = kcfg(0, cves=["CVE-2025-1", "CVE-2025-2", "CVE-2025-3"])
    t = cr.kernel_gap_text(st, rows, cfg)
    assert "the other 1 are not listed as rows" in t and "任何文字，包括 N = 99" in t     # 說明文字裡的數字不影響 N
    assert cr.kernel_gap_text({"C-kernel-coverage": ("OK", "x")}, rows, cfg) == ""
    assert cr.kernel_gap_text({}, rows, cfg) == "" and cr.kernel_gap_text(None, rows, cfg) == ""
    assert cr.kernel_cve_list_info(None) is None and cr.kernel_cve_list_info({"schema": "sca-center-kernel-config/1"}) is None


def test_detail_with_markdown_and_newlines_stays_one_quoted_line(tmp_path):
    """說明原文只顯示：換行與多餘空白壓成一行，放在引用區塊裡。"""
    st = {"C-kernel-coverage": ("GAP", "第一行\n  第二行 | 表格字元")}
    t = cr.kernel_gap_text(st, [], None)
    assert "> 第一行 第二行 | 表格字元" in t and "\n> " in t and t.count("\n> ") == 1


# ---------- 沒有核心的列：不是「沒有弱點」，而且照樣帶出說明 ----------

def test_no_kernel_rows_case_also_shows_text_and_counts(tmp_path):
    scan = make_scan(tmp_path / "s", findings=KFINDINGS[8:], grype=None, stages={"C-kernel-coverage": "GAP"})
    with_status_detail(scan, "C-kernel-coverage", ZH_DETAIL)
    write_json(scan / "scan" / "kernel-config.json", kcfg(4))
    r, s, reports = run(make_project(tmp_path / "p"), scan)
    k = section_87((reports / "risk-assessment.md").read_text(encoding="utf-8"))
    assert "**Kernel not assessed.**" in k and "`C-kernel-coverage` GAP" in k and "NOT assessed" in k
    assert f"> {ZH_DETAIL}" in k and "listed as rows: 0 CVEs; the other 12 are not listed as rows." in k
    assert s["counts"]["kernel"]["section"] == "not_assessed" and not (reports / "kernel-vulnerabilities.md").exists()


# ---------- OK：逐位元組不變 ----------

def normalize_summary(text):
    d = json.loads(text)
    d.pop("scan_dir", None)
    return re.sub(r"\b[0-9a-f]{64}\b", "H", STAMP.sub("TS", json.dumps(d, sort_keys=True, ensure_ascii=False)))


def test_ok_output_is_byte_identical_to_pre_change(tmp_path):
    r, s, reports = run(make_project(tmp_path / "p"), kernel_scan(tmp_path / "s"))
    assert r.returncode in (0, 2)
    base = json.loads(BASELINE.read_text(encoding="utf-8"))
    got = {}
    for name in ("risk-assessment.md", "kernel-vulnerabilities.md"):
        got[name] = STAMP.sub("TS", (reports / name).read_text(encoding="utf-8"))
    assert got["kernel-vulnerabilities.md"] == base["kernel-vulnerabilities.md"]
    assert got["risk-assessment.md"] == base["risk-assessment.md"]
    sha = lambda t: hashlib.sha256(t.encode("utf-8")).hexdigest()                            # noqa: E731
    for name in ("vulnerability-rows.json", "vex.cdx.json", "vex.openvex.json"):
        assert sha(STAMP.sub("TS", (reports / name).read_text(encoding="utf-8"))) == base["sha256"][name], name
    assert sha(normalize_summary((reports / "summary.json").read_text(encoding="utf-8"))) == base["sha256"]["summary.json"]
    for text in got.values():
        assert "Kernel coverage limitation" not in text and "Kernel CVE list" not in text


def test_ok_with_kernel_config_present_adds_nothing(tmp_path):
    """OK 時即使有 kernel-config.json（N 比 M 大）也不寫 N／M 那行。"""
    scan = kernel_scan(tmp_path / "s")
    write_json(scan / "scan" / "kernel-config.json", kcfg(40))
    r, s, reports = run(make_project(tmp_path / "p"), scan)
    for name in ("risk-assessment.md", "kernel-vulnerabilities.md"):
        assert "Kernel CVE list" not in (reports / name).read_text(encoding="utf-8")


# ---------- 交付報告沒有內部里程碑用語 ----------

PILOT = HERE.parents[1] / "pilot"
sys.path.insert(0, str(PILOT / "tests"))
from pilot_fixtures import gmatch  # noqa: E402

RPT = "pkg:deb/debian/linux-image-6.18.50%2Brpt-rpi-v8@1%3A6.18.50-1%2Brpt1?arch=arm64&distro=debian-13"
GEN = "pkg:generic/linux-kernel@6.18.50"


def kernelcheck_line(tmp_path, comps, matches, extra=()):
    s = tmp_path / "kc-sbom.json"
    s.write_text(json.dumps({"components": comps}), encoding="utf-8")
    g = tmp_path / "kc-grype.json"
    g.write_text(json.dumps({"matches": matches}), encoding="utf-8")
    r = subprocess.run(["python3", "-I", str(PILOT / "lib" / "kernelcheck.py"), "--sbom", str(s), "--grype", str(g), "--out", str(tmp_path / "kc.json"), *extra],
                       capture_output=True, text=True)
    assert r.returncode == 0, r
    return r.stdout.strip().split("\t")


@pytest.mark.parametrize("shape", ["off_series", "generic_only", "both"])
def test_delivered_reports_have_no_internal_milestone_wording(tmp_path, shape):
    """真的用 kernelcheck.py 的輸出當 status.tsv 的說明：交付的 .md（含核心段落與階段表）不能出現「M7」「尚未實作」。"""
    deb = {"type": "library", "name": "linux-image-6.18.50+rpt-rpi-v8", "version": "1:6.18.50-1+rpt1", "purl": RPT,
           "properties": [{"name": "syft:package:type", "value": "deb"}]}
    if shape == "generic_only":      # 發行版樣子的核心 deb（沒有 epoch、沒有廠商後綴）：只有 generic 的比對
        deb = {"type": "library", "name": "linux-image-6.12.116-amd64", "version": "6.12.116-1", "properties": deb["properties"],
               "purl": "pkg:deb/debian/linux-image-6.12.116-amd64@6.12.116-1?arch=amd64&distro=debian-13"}
    gen = {"type": "library", "name": "linux-kernel", "version": "6.18.50", "purl": GEN, "properties": [{"name": "syft:package:type", "value": "linux-kernel"}]}
    matches = [gmatch("CVE-2025-0101", "linux-kernel", "6.18.50", GEN, "linux-kernel")]
    if shape == "off_series":
        matches = [gmatch("CVE-2025-0101", deb["name"], deb["version"], deb["purl"], "deb")]
    stage, st, detail = kernelcheck_line(tmp_path, [deb, gen], matches)
    assert st == "GAP" and "M7" not in detail and "尚未實作" not in detail
    scan = kernel_scan(tmp_path / "s", stages={"C-kernel-coverage": "GAP"})
    with_status_detail(scan, "C-kernel-coverage", detail)
    write_json(scan / "scan" / "kernel-config.json", kcfg(4))
    r, s, reports = run(make_project(tmp_path / "p"), scan)
    assert r.returncode in (0, 2)
    seen = 0
    for p in reports.rglob("*"):
        if p.is_file() and p.suffix in (".md", ".csv", ".tsv", ".json") and p.name != "scan-status.tsv":
            t = p.read_text(encoding="utf-8")
            assert "尚未實作" not in t and not re.search(r"\bM7[a-z0-9-]*\b", t), p.name
            seen += 1
    assert seen >= 5
    assert detail in (reports / "risk-assessment.md").read_text(encoding="utf-8")        # 原文確實帶出（檢查不是空轉）


# ---------- 客戶版：沒有核心段落，不帶任何核心狀態文字 ----------

def test_customer_package_has_no_kernel_section_and_no_internal_text(tmp_path):
    scan = gap_scan(tmp_path / "scan", kcfg=kcfg(4))
    r, s, rep = run(make_project(tmp_path / "p", dict(MIN_CFG, role="supplier")), scan)
    assert r.returncode in (0, 2), r.stdout + r.stderr
    pk = rep / "supplier-package"
    assert pk.is_dir()
    for p in pk.rglob("*"):
        if p.is_file() and p.suffix in (".md", ".json", ".txt", ".csv"):
            t = p.read_text(encoding="utf-8")
            for bad in ("C-kernel", "kernel-coverage", "scan-status", "Kernel CVE list", "Status text as recorded", "Kernel coverage limitation",
                        "上游", "核心"):
                assert bad not in t, (p.name, bad)
    t = (pk / "vulnerability-status.md").read_text(encoding="utf-8")
    assert "**Incomplete:**" in t and "| Completeness of the vulnerability data | incomplete |" in t     # 資料狀態 GAP 的一般說明照舊
