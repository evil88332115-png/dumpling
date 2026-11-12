"""cra_report.py 的「只經 NVD 比對到、發行版已修補」小節（scan/distro-recheck.json，tools/pilot/lib/distro_recheck.py 的輸出）。

distro_fixed 的列從 P1–P3 移出、另列一節並分開計數（刻意改變層級數量）；KEV 的列照樣移出但要點名；沒有檔案時一切照舊。
"""
import datetime
import hashlib
import json
import sys
import zipfile
from pathlib import Path

from test_cra_report import FINDINGS, OK_STAGES, clean_security, finding, make_project, make_scan, run, write_json

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools" / "pilot" / "lib"))
import cra_report as cr  # noqa: E402
import distro_recheck as dr  # noqa: E402

OSSL = "3.0.13-0ubuntu3.11"
EXTRA = [
    finding("openssl", OSSL, "CVE-2024-6119", "NVD", "HIGH", epss=0.99),            # P1（EPSS）→ 發行版已修補
    finding("openssl", OSSL, "CVE-2026-45447", "NVD", "HIGH"),                      # P2 → 已修補
    finding("openssl", OSSL, "CVE-2026-1000", "NVD", "LOW"),                        # P3 → 已修補
    finding("openssl", OSSL, "CVE-2026-63076", "NVD", "HIGH"),                      # P2，發行版仍受影響 → 不動
    finding("openssl", OSSL, "CVE-2026-2000", "NVD", "MEDIUM", kev=True),           # P1（KEV）→ 已修補，要點名
    finding("openssl", OSSL, "CVE-2026-3000", "NVD", "HIGH"),                       # 列裡另有 recheck 沒看過的 finding → 不動
    finding("openssl", OSSL, "GHSA-3000-aaaa-bbbb", "GITHUB", "HIGH", aliases=[{"cveId": "CVE-2026-3000"}]),
    finding("linux-image-6.8.0-1021-nvidia-tegra", "6.8.0-1021.21", "CVE-2026-4000", "NVD", "HIGH"),   # 核心 → 不動
]


def recheck_row(cve, comp, ver, decision="distro_fixed", fixed=None, source_ids=None, kev=False, record=None):
    return {"key": [cve, f"ubuntu/{comp}", ver], "cves": [cve], "ids": [cve], "source_ids": source_ids or [f"NVD:{cve}"],
            "component": comp, "version": ver, "purl": f"pkg:deb/ubuntu/{comp}@{ver}?arch=arm64&distro=ubuntu-24.04",
            "source_package": comp, "source_version": ver, "installed_as": [], "kev": kev,
            "release": {"distro": "Ubuntu", "version": "24.04", "codename": "noble"}, "decision": decision, "reason": "",
            "evidence": [{"record": record or f"UBUNTU-{cve}", "modified": "2026-10-17T12:55:37Z", "cve": cve, "ecosystem": "Ubuntu:24.04:LTS",
                          "package": comp, "installed_version": ver, "fixed_versions": [fixed or "3.0.13-0ubuntu3.4"],
                          "fixed_version": fixed or "3.0.13-0ubuntu3.4", "affected": decision != "distro_fixed", "no_fix": False}]}


def recheck_doc(status="OK", rows=None, mirror=None):
    rows = rows if rows is not None else [
        recheck_row("CVE-2024-6119", "openssl", OSSL, fixed="3.0.13-0ubuntu3.4"),
        recheck_row("CVE-2026-45447", "openssl", OSSL, fixed=OSSL),
        recheck_row("CVE-2026-1000", "openssl", OSSL, fixed="3.0.13-0ubuntu3.9"),
        recheck_row("CVE-2026-63076", "openssl", OSSL, "distro_affected", fixed="3.0.13-0ubuntu3.15"),
        recheck_row("CVE-2026-2000", "openssl", OSSL, fixed="3.0.13-0ubuntu3.7", kev=True, record="USN-8000-1"),
        recheck_row("CVE-2026-3000", "openssl", OSSL),                                           # recheck 只看到 NVD 那一筆
        recheck_row("CVE-2025-0004", "libfoo1", "1.0-1"),                                        # accepted → 不動
        recheck_row("CVE-2026-4000", "linux-image-6.8.0-1021-nvidia-tegra", "6.8.0-1021.21"),    # 核心 → 不動
    ]
    counts = {k: sum(1 for r in rows if r["decision"] == k) for k in dr.DECISIONS + dr.SKIPS + ("not_rechecked",)}
    return {"schema": "sca-distro-recheck/1", "stage": "D-distro-recheck", "status": status, "detail": "x",
            "mirror": mirror or {"path": "/m", "ok": status == "OK", "fetched_utc": "2026-11-02T00:00:00Z", "age_days": 0.1, "max_age_days": 3},
            "counts": dict(counts, rows=len(rows)), "rows": rows}


def scan_with(tmp_path, doc=None, stages=None, name="scan"):
    sc = make_scan(tmp_path / name, findings=FINDINGS + EXTRA, stages=stages)
    if doc is not None:
        write_json(sc / "scan" / "distro-recheck.json", doc)
    return sc


def ra(reports):
    return (reports / "risk-assessment.md").read_text(encoding="utf-8")


def section(text, head, nxt="\n### "):
    i = text.index(head)
    j = text.find(nxt, i + len(head))
    return text[i: j if j > 0 else None]


def test_moves_distro_fixed_rows_and_counts(tmp_path):
    p0 = make_project(tmp_path / "p0")
    r0, s0, rep0 = run(p0, scan_with(tmp_path, name="s0"))
    p1 = make_project(tmp_path / "p1")
    r1, s1, rep1 = run(p1, scan_with(tmp_path, recheck_doc(), stages={"D-distro-recheck": "OK"}, name="s1"))
    assert r0.returncode in (0, 2) and r1.returncode in (0, 2), r1.stdout + r1.stderr
    c0, c1 = s0["counts"], s1["counts"]
    # 移出 3 列：P1 1（EPSS）、P2 1、P3 1；accepted、核心、多一筆 finding 的列、已遭利用（KEV）的列不動
    assert (c0["p1"] - c1["p1"], c0["p2"] - c1["p2"], c0["p3"] - c1["p3"]) == (1, 1, 1)
    assert c1["distro_fixed"] == 3 and c0["distro_fixed"] is None and c1["rows"] == c0["rows"] and c1["accepted"] == c0["accepted"]
    assert c1["non_kernel"]["p1"] == c0["non_kernel"]["p1"] - 1
    d = c1["distro_recheck"]
    assert d["moved_from"] == {"p1": 1, "p2": 1, "p3": 1} and d["kev"] == [] and d["section"] == "listed"
    assert d["not_moved"] == {"accepted": 1, "kernel": 1, "other_findings": 1, "exploited": 1} and d["status"] == "OK"
    assert c1["kev_open"] == c0["kev_open"]                       # 已遭利用的列不自動移出：照樣算未處理
    assert "distro_recheck" not in c0                              # 沒有檔案時 summary.json 不多這一段
    assert "發行版已修補（backport，移出 P1–P3）3 列" in r1.stdout and "發行版已修補" not in r0.stdout
    t = ra(rep1)
    p1t, p2t = section(t, "### 8.4 P1"), section(t, "### 8.5 P2")
    assert "CVE-2024-6119" not in p1t and "CVE-2026-45447" not in p2t
    assert "CVE-2026-63076" in p2t and "CVE-2026-3000" in p2t                    # 受影響、有其他 finding：留著
    sec = section(t, "### 8.8 Reported only via NVD but fixed by the distribution (backported)", "\n## ")
    assert "CVE-2026-2000 | openssl | 3.0.13-0ubuntu3.11 | openssl | 3.0.13-0ubuntu3.7" not in sec.split("#### Moved rows")[1]   # 已遭利用：不在移出的表
    assert "| CVE-2024-6119 | openssl | 3.0.13-0ubuntu3.11 | openssl | 3.0.13-0ubuntu3.4 | UBUNTU-CVE-2024-6119 |" in sec
    assert "**Exploited rows with a distribution record that states a fix – not moved (1):** CVE-2026-2000 on openssl 3.0.13-0ubuntu3.11 (distribution record USN-8000-1, fix version 3.0.13-0ubuntu3.7)" in sec
    assert "they stay in P1 and leave it only by a decision of a named engineer" in sec
    assert "None of the moved rows is listed in a KEV catalogue." in sec
    assert "#### Moved rows (3)" in sec and "3 moved here from P1–P3; 4 not moved" in sec
    s82 = section(t, "### 8.2 Summary")
    assert "| Fixed by the distribution, reported only via NVD/GitHub (section 8.8; not in P1–P3) | 3 |" in s82
    assert "3 rows on Debian/Ubuntu packages that were reported only via NVD/GitHub are fixed by the distribution" in t
    assert "(P1 1, P2 1, P3 1)" in t and "this changes the tier counts by design" in t
    assert "| D-distro-recheck | OK |" in t
    # 已遭利用的列不移出：仍在 P1 表（附發行版紀錄當資訊），資料狀態仍是 ATTENTION（P1 有未處理的列）
    assert "CVE-2026-2000" in p1t
    assert s1["documents"]["risk-assessment"]["status"] in ("ATTENTION", "GAP", "NOT_ASSESSED")
    assert "Fixed according to a distribution advisory only" in sec
    # 沒有檔案：沒有這一節、8.2 不多列
    t0 = ra(rep0)
    assert "fixed by the distribution" not in t0 and "Fixed by the distribution" not in t0 and "CVE-2024-6119" in section(t0, "### 8.4 P1")


def test_kev_row_is_not_moved_by_distro_recheck(tmp_path):
    """G3-3：已遭利用的列（KEV）只能由具名的工程師離開 P1：發行版紀錄說已修補也不自動移出，只當資訊列出。"""
    clean_security(tmp_path)      # 安全測試有結果：文件狀態只看漏洞資料
    fs = [finding("openssl", OSSL, "CVE-2026-2000", "NVD", "MEDIUM", kev=True)]
    sb = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"type": "library", "name": "openssl", "version": OSSL,
                                                                        "purl": f"pkg:deb/ubuntu/openssl@{OSSL}?arch=arm64&distro=ubuntu-24.04"}]}
    grype = {"matches": []}
    base = make_scan(tmp_path / "s0", findings=fs, grype=grype, sbom=sb)
    r0, s0, _ = run(make_project(tmp_path / "p0"), base)
    assert s0["documents"]["risk-assessment"]["status"] == "ATTENTION" and s0["counts"]["p1"] == 1
    sc = make_scan(tmp_path / "s1", findings=fs, grype=grype, sbom=sb, stages={"D-distro-recheck": "OK"})
    write_json(sc / "scan" / "distro-recheck.json", recheck_doc(rows=[recheck_row("CVE-2026-2000", "openssl", OSSL, kev=True)]))
    r1, s1, rep1 = run(make_project(tmp_path / "p1"), sc)
    assert s1["counts"]["p1"] == 1 and s1["counts"]["distro_fixed"] == 0                 # 沒有移出
    assert s1["counts"]["distro_recheck"]["not_moved"] == {"exploited": 1}
    assert s1["documents"]["risk-assessment"]["status"] == "ATTENTION"
    assert "not moved (1):** CVE-2026-2000" in ra(rep1) and "UBUNTU-CVE-2026-2000" in ra(rep1)                      # 發行版紀錄當資訊
    # EUVD 與人工證據的列也一樣
    for tag, kw in (("euvd", {"exploited_sources": ["EUVD (CISA KEV)"]}), ("manual", {"exploited_sources": ["manual: vendor advisory, 2026-11-01"]})):
        rows = [{"key": ["CVE-X", "ubuntu/openssl", OSSL], **kw, "tier": "p1", "kernel": False, "kev": False, "source_ids": ["NVD:CVE-X"]}]
        moved, kept = cr.apply_distro(rows, recheck_doc(rows=[recheck_row("CVE-X", "openssl", OSSL, source_ids=["NVD:CVE-X"])]))
        assert moved == [] and kept["exploited"] == 1 and rows[0]["tier"] == "p1" and rows[0]["distro_info"], tag
    rows[0].pop("exploited_sources")
    moved, kept = cr.apply_distro(rows, recheck_doc(rows=[recheck_row("CVE-X", "openssl", OSSL, source_ids=["NVD:CVE-X"])]))
    assert len(moved) == 1 and not kept
    # 沒有 KEV 的列移出：不多這個理由
    write_json(sc / "scan" / "distro-recheck.json", recheck_doc(rows=[recheck_row("CVE-2026-2000", "openssl", OSSL)]))
    fs2 = [finding("openssl", OSSL, "CVE-2026-2000", "NVD", "MEDIUM", epss=0.99)]
    sc2 = make_scan(tmp_path / "s2", findings=fs2, grype=grype, sbom=sb, stages={"D-distro-recheck": "OK"})
    write_json(sc2 / "scan" / "distro-recheck.json", recheck_doc(rows=[recheck_row("CVE-2026-2000", "openssl", OSSL)]))
    r2, s2, _ = run(make_project(tmp_path / "p2"), sc2)
    assert s2["counts"]["p1"] == 0 and s2["documents"]["risk-assessment"]["status"] == "OK", s2["documents"]["risk-assessment"]


def test_absent_file_output_is_unchanged(tmp_path):
    """沒有 scan/distro-recheck.json：文件與先前的版本相同（範本多的兩個 placeholder 是空字串，不留空行）。"""
    p = make_project(tmp_path / "p")
    r, s, rep = run(p, scan_with(tmp_path))
    t = ra(rep)
    assert "{{" not in t and "Reported only via NVD" not in t and s["counts"]["distro_fixed"] is None
    # 8.3 的結尾就是核心那一行（text.distro_moved 是空的，不多空行）；8.7 之後直接是 VEX 小節（8.8），再來是第 9 節
    s83 = t.split("### 8.4")[0]
    assert s83.split("Severity used for the tiers:")[0].endswith("The counts in section 8.2 and the data status include them.\n\n")
    assert "Grype has no Ubuntu matches either.\n\nEPSS (FIRST's" in s83    # 嚴重度來源的說明（沒有 ubuntu-priority.json、Grype 也沒有 Ubuntu 比對），接著 EPSS
    assert s83.endswith("it is shown next to the row's value and is not used for the tiers.\n\n")
    assert "### 8.8 Vulnerability status (VEX) and release gate" in t
    assert section(t, "### 8.7", "\n### 8.8 Vulnerability status").rstrip().endswith("`kernel-vulnerabilities.md` (1 row; same columns as sections 8.4–8.6 plus tier, Grype fix state and analysis state).")


def test_gap_recheck_moves_nothing(tmp_path):
    doc = recheck_doc("GAP", mirror={"path": "/m", "ok": False, "fetched_utc": "2026-10-20T00:00:00Z", "age_days": 13.0, "max_age_days": 3})
    for r_ in doc["rows"]:
        r_["decision"] = "not_rechecked"
    base = run(make_project(tmp_path / "p0"), scan_with(tmp_path, name="s0"))[1]
    r, s, rep = run(make_project(tmp_path / "p"), scan_with(tmp_path, doc, stages={"D-distro-recheck": "GAP"}))
    c = s["counts"]
    assert c["distro_fixed"] == 0 and (c["p1"], c["p2"], c["p3"]) == (base["counts"]["p1"], base["counts"]["p2"], base["counts"]["p3"])
    t = ra(rep)
    sec = section(t, "### 8.8 Reported only via NVD", "\n## ")
    assert "**Not applied.** `D-distro-recheck` is GAP: the distribution OSV mirror is out of date (downloaded 2026-10-20T00:00:00Z, 13.0 days ago; limit 3 days)" in sec
    # 不影響資料狀態（只列在 8.1 的表，另寫一行 Note）
    assert s["documents"]["risk-assessment"]["status"] == base["documents"]["risk-assessment"]["status"]
    assert not any("D-distro-recheck" in x for x in s["documents"]["risk-assessment"]["detail"])
    assert "Note (does not affect the status): `D-distro-recheck` is GAP" in t and "| D-distro-recheck | GAP |" in t
    doc2 = recheck_doc("GAP", mirror={"path": None, "ok": False})
    t2 = ra(run(make_project(tmp_path / "p2"), scan_with(tmp_path, doc2, name="s2"))[2])
    assert "no distribution OSV mirror was configured (sca-scan reads its path from the PILOT_ENV key `OSV_DISTRO_MIRROR`)" in t2


def test_stage_without_file_and_numbering_after_nvidia(tmp_path):
    # D-distro-recheck 有這一列（例如 FAIL）卻沒有結果檔；C-nvidia-bulletins 也有列 → NVIDIA 是 8.8，這一節是 8.9
    r, s, rep = run(make_project(tmp_path / "p"), scan_with(tmp_path, stages={"D-distro-recheck": "FAIL", "C-nvidia-bulletins": "GAP"}))
    t = ra(rep)
    assert "### 8.8 NVIDIA security bulletins" in t and "### 8.9 Reported only via NVD but fixed by the distribution (backported)" in t
    assert "**Not rechecked.** `D-distro-recheck` is FAIL and there is no result file" in t
    assert s["counts"]["distro_fixed"] is None
    # 有結果檔時 8.2 指向 8.9
    r, s, rep = run(make_project(tmp_path / "p2"), scan_with(tmp_path, recheck_doc(), stages={"C-nvidia-bulletins": "GAP"}, name="s2"))
    assert "(section 8.9; not in P1–P3) | 3 |" in ra(rep)


def test_project_template_without_section_keeps_rows(tmp_path):
    tpl = (ROOT / "tools" / "cra" / "templates" / "risk-assessment.md").read_text(encoding="utf-8").replace("{{ text.distro_section }}", "")
    p = make_project(tmp_path / "p", templates={"risk-assessment": tpl})
    r, s, rep = run(p, scan_with(tmp_path, recheck_doc()))
    assert s["counts"]["distro_fixed"] == 0 and "CVE-2024-6119" in section(ra(rep), "### 8.4 P1")
    assert any("text.distro_section" in w for w in s["config_warnings"])


def test_end_to_end_with_distro_recheck(tmp_path):
    """distro_recheck.recheck 的輸出直接給 cra_report：鍵與 source_ids 對得上。"""
    m = tmp_path / "m"
    (m / "Ubuntu").mkdir(parents=True)
    with zipfile.ZipFile(m / "Ubuntu" / "all.zip", "w") as z:
        for cve, fixed in (("CVE-2024-6119", "3.0.13-0ubuntu3.4"), ("CVE-2026-45447", OSSL), ("CVE-2026-1000", "3.0.13-0ubuntu3.9"),
                           ("CVE-2026-63076", "3.0.13-0ubuntu3.15")):
            z.writestr(f"UBUNTU-{cve}.json", json.dumps({"id": f"UBUNTU-{cve}", "modified": "2026-10-17T00:00:00Z", "upstream": [cve], "affected": [
                {"package": {"name": "openssl", "ecosystem": "Ubuntu:24.04:LTS"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}]}))
    sha = hashlib.sha256((m / "Ubuntu" / "all.zip").read_bytes()).hexdigest()
    (m / "SOURCE").write_text(f"ecosystems=Ubuntu Debian\nfetched_utc={datetime.datetime.now(datetime.timezone.utc):%Y-%m-%dT%H:%M:%SZ}\nubuntu_sha256={sha}\n")
    fs = FINDINGS + EXTRA[:4]
    st, detail, doc = dr.recheck(fs, {"matches": []}, None, None, None, str(m), 3)
    assert st == "OK" and doc["counts"]["distro_fixed"] == 3 and doc["counts"]["distro_affected"] == 1
    sc = make_scan(tmp_path / "s", findings=fs, stages={"D-distro-recheck": st})
    write_json(sc / "scan" / "distro-recheck.json", doc)
    r, s, rep = run(make_project(tmp_path / "p"), sc)
    assert s["counts"]["distro_fixed"] == 3 and s["counts"]["distro_recheck"]["moved_from"] == {"p1": 1, "p2": 1, "p3": 1}
    assert "CVE-2026-63076" in section(ra(rep), "### 8.5 P2")
