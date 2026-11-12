"""cra_report.py／vex_export.py 讀 scan/euvd.json（C 線② PR-2；使用者決定：EUVD 是另一種被利用證據，不設 kev，只走 exploited_sources）。

- 兩種分級方式（current、exploitation）下，EUVD 標示已遭利用的列都是 P1；包括 DT 沒有標 isKev 的 CVE（例如 EUVD 只標 cisa_kev、
  當天的 CISA 檔沒有的 CVE-2026-69836 那種：D-dt-kev-sources 只記 NOTE，前提就是這裡讓它逐筆進 P1）。
- KEV 欄與 summary.json 分得出 DT／Grype 的 KEV 與 EUVD 寫的 CISA KEV、ENISA EU KEV。
- status 不是 OK、讀不到、沒有 status → 當作沒有 EUVD 資料、文件 GAP（理由只出現一次），不顯示成沒有被利用。
- 沒有 scan/euvd.json 時輸出和以前相同（逐位元組的比較在 PR 說明；這裡比 current 有沒有 EUVD 以外的差異）。
資料全部是合成的。"""
import json
import re

import pytest

from test_cra_exploitation import cfg_of, ra_text, setup
from test_cra_report import finding, run
import cra_report as cr
import vex_export as vx

PLACEHOLDER_NA = {"state": "not_affected", "justification": "code_not_reachable", "detail": "Not used.", "author": "專案負責人",
                  "date": "2026-11-01"}
FS = [
    finding("libkev1", "1.0-1", "CVE-2026-9101", "NVD", "MEDIUM", kev=True),     # DT KEV，EUVD 也標（CISA＋EU KEV）
    finding("libexample1", "2.0-1", "CVE-2026-69836", "NVD", "LOW"),             # EUVD 有（cisa_kev）、DT 沒有 isKev
    finding("libeu2", "1.0-1", "CVE-2026-9103", "NVD", "LOW"),                   # 只在 EU KEV（DT 的 eukev.json 停在 2026-08）
    finding("libplain1", "1.0-1", "CVE-2026-9104", "NVD", "LOW"),                # 沒有被利用的證據
    finding("libann1", "1.0-1", "CVE-2026-9105", "NVD", "LOW"),                  # EUVD＋沒有具名的人的 not_affected → 仍 P1
    finding("libann2", "1.0-1", "CVE-2026-9106", "NVD", "LOW"),                  # 沒有 EUVD＋同樣的判定 → accepted
]
EUVD = {"stage": "C-euvd", "status": "OK", "cves": {
    "CVE-2026-9101": {"exploited": "yes", "kev_sources": ["cisa_kev", "eukev_kev"], "euvd_ids": ["EUVD-2026-1"]},
    "CVE-2026-69836": {"exploited": "yes", "kev_sources": ["cisa_kev"], "euvd_ids": ["EUVD-2026-2"]},
    "CVE-2026-9103": {"exploited": "yes", "kev_sources": ["eukev_kev"], "euvd_ids": ["EUVD-2026-3"]},
    "CVE-2026-9104": {"exploited": "not_flagged", "kev_sources": [], "euvd_ids": ["EUVD-2026-4"]},
    "CVE-2026-9105": {"exploited": "yes", "kev_sources": ["cisa_kev"], "euvd_ids": ["EUVD-2026-5"]},
    "CVE-2026-9199": {"exploited": "yes", "kev_sources": ["eukev_kev"], "euvd_ids": ["EUVD-2026-9"]},   # 不在風險表
}}
ANNS = {"schema": "sca-center-vex-annotations/1", "annotations": [
    dict(PLACEHOLDER_NA, cve="CVE-2026-9105", purl="pkg:deb/ubuntu/libann1"),
    dict(PLACEHOLDER_NA, cve="CVE-2026-9106", purl="pkg:deb/ubuntu/libann2")]}


def go(tmp_path, scheme=None, euvd=EUVD, raw=None, name="p", **kw):
    proj, scan = setup(tmp_path, cfg=cfg_of(scheme=scheme), findings=FS, evidence=None, services=None, anns=ANNS,
                       euvd=None if raw is not None else euvd, name=name, **kw)
    if raw is not None:
        (scan / "scan" / "euvd.json").write_text(raw, encoding="utf-8")
    r, s, reports = run(proj, scan)
    assert s is not None, r.stdout + r.stderr
    return s, ra_text(reports)


def p1_section(t):
    a = re.search(r"^### [0-9.]+ P1 – ", t, re.M).start()
    return t[a:t.index("\n### ", a + 1)]


@pytest.mark.parametrize("scheme", [None, "exploitation"])
def test_euvd_rows_are_p1_in_both_schemes_with_separate_sources(tmp_path, scheme):
    s, t = go(tmp_path, scheme)
    tiers = {x["id"]: x["tier"] for x in s["euvd"]["list"]}
    assert tiers == {"CVE-2026-9101": "p1", "CVE-2026-69836": "p1", "CVE-2026-9103": "p1", "CVE-2026-9105": "p1"}
    p1 = p1_section(t)
    # EUVD 有、DT 沒有 isKev：逐筆一列在 P1（不是只有計數）；KEV 欄寫 DT 的 KEV（no）與 EUVD 寫的清單
    assert "| CVE-2026-69836 |" in p1 and "| no; exploited: EUVD (CISA KEV) |" in p1
    assert "| YES; exploited: EUVD (CISA KEV, ENISA EU KEV) |" in p1 and "| no; exploited: EUVD (ENISA EU KEV) |" in p1
    assert "CVE-2026-9104" not in p1 and "CVE-2026-9106" not in p1
    e = s["euvd"]
    assert (e["available"], e["file_status"], e["exploited_cves"], e["rows"], e["rows_not_kev"]) == (True, None, 5, 4, 3)
    assert e["by_catalogue"] == {"CISA KEV": 3, "ENISA EU KEV": 2} and e["kev_sources_on_euvd_rows"] == {"DT": 1}
    by = {x["id"]: x for x in e["list"]}
    assert by["CVE-2026-69836"]["kev"] is False and by["CVE-2026-69836"]["euvd"] == ["EUVD (CISA KEV)"]
    assert by["CVE-2026-9101"]["kev"] is True and by["CVE-2026-9101"]["kev_sources"] == ["DT"]
    # EUVD 不設 kev：KEV 的計數只有 DT／Grype 的
    assert s["counts"]["kev_open"] == 1
    # EUVD 標示、但不在風險表的 CVE 逐一點名
    assert e["not_in_table"] == ["CVE-2026-9199"]
    assert any("marked exploited by EUVD is not in the risk table" in d and "CVE-2026-9199" in d
               for d in s["documents"]["risk-assessment"]["detail"])
    if scheme is None:
        assert "or marked exploited by EUVD (`scan/euvd.json`: CISA KEV or ENISA EU KEV)" in t and "exploitation" not in s
    else:
        assert s["exploitation"]["p1_by_evidence"]["euvd"] == 4 and s["exploitation"]["euvd"]["exploited_cves"] == 5


@pytest.mark.parametrize("scheme", [None, "exploitation"])
def test_euvd_row_leaves_p1_only_by_a_named_person(tmp_path, scheme):
    """EUVD 的列和 KEV 一樣：沒有具名負責人的 not_affected 不讓它離開 P1；沒有被利用的列照舊 accepted（current 的 kev_of）。"""
    s, t = go(tmp_path, scheme)
    assert {x["id"]: x["tier"] for x in s["euvd"]["list"]}["CVE-2026-9105"] == "p1"
    acc = t[t.index("## Appendix A. Not affected / accepted"):]
    assert "| CVE-2026-9106 |" in acc and "CVE-2026-9105" not in acc and "| CVE-2026-9105 |" in p1_section(t)


@pytest.mark.parametrize("scheme", [None, "exploitation"])
@pytest.mark.parametrize("raw, why", [
    (json.dumps(dict(EUVD, status="GAP")), "status GAP"),
    (json.dumps({k: v for k, v in EUVD.items() if k != "status"}), "status missing (freshness unknown)"),
    ("{not json", "unreadable"),
    ('{"status": "OK", "cves": ["CVE-2026-69836"]}', "unreadable"),
])
def test_euvd_not_ok_is_no_data_and_gap_once(tmp_path, scheme, raw, why):
    s, t = go(tmp_path, scheme, raw=raw)
    detail = s["documents"]["risk-assessment"]["detail"]
    want = f"EUVD exploited list not available ({why}): EU-KEV entries added after 2026-08 may be missing"
    assert detail.count(want) == 1 and s["documents"]["risk-assessment"]["status"] == "GAP"
    # 不能用的 EUVD 不拿來分級，也不寫成「0 個 CVE」
    assert s["euvd"]["available"] is False and s["euvd"]["exploited_cves"] is None and s["euvd"]["rows"] == 0
    assert "exploited: EUVD" not in t and "| CVE-2026-69836 |" not in p1_section(t)
    assert any("scan/euvd.json" in w for w in s["config_warnings"])
    # 漏洞資料狀態（VEX 發行閘門用的）不因 EUVD 而變（和 exploitation 的使用者決定 EUVD ② 相同）
    assert not any("vulnerability data status is GAP" in x for x in s["vex"]["gate"]["reasons"])


def test_current_without_euvd_file_has_no_euvd_trace(tmp_path):
    """沒有 scan/euvd.json：current 不看 EUVD（沒有 euvd 鍵、沒有 GAP、規則文字照舊）。"""
    s, t = go(tmp_path, None, euvd=None)
    assert "euvd" not in s and "exploited: EUVD" not in t and "marked exploited by EUVD" not in t
    assert not any("EUVD" in d for d in s["documents"]["risk-assessment"]["detail"])
    assert "| CVE-2026-69836 |" not in p1_section(t)


def test_gate_counts_euvd_rows_like_kev_rows():
    """VEX 發行閘門：EUVD 標示已遭利用的列只靠自動來源判 not_affected／resolved → 點名（同 KEV 的列）。"""
    auto = {"source": "kconfig", "state": "not_affected", "justification": "code_not_present"}
    rows = [{"id": "CVE-2026-69836", "component": "linux", "version": "6.8", "tier": "p1", "kev": False,
             "exploited_sources": ["EUVD (CISA KEV)"], "vex": dict(auto)},
            {"id": "CVE-2026-9104", "component": "linux", "version": "6.8", "tier": "p3", "kev": False, "vex": dict(auto)}]
    g = vx.gate(rows, [], grype_checked=True, not_assessed=[])
    assert g["kev_without_human_decision"] == 1 and any("CVE-2026-69836 on linux 6.8 (kconfig)" in x for x in g["reasons"])


def test_euvd_catalogue_labels():
    assert cr.euvd_label(["cisa_kev"]) == "EUVD (CISA KEV)" and cr.euvd_label([]) == "EUVD"
    assert cr.euvd_label(["cisa_kev", "eukev_kev"]) == "EUVD (CISA KEV, ENISA EU KEV)"
    assert cr.euvd_catalogues({"cves": {"cve-2026-1234": {"exploited": "YES", "kev_sources": ["eukev_kev", 3]},
                                        "CVE-2026-1235": {"exploited": "no"}}}) == {"CVE-2026-1234": ["eukev_kev"]}
    assert cr.euvd_catalogues({"cves": []}) is None and cr.euvd_catalogues(None) is None


# ---------- 第二輪（獨立驗證 H1、H2、M1、M2、L1、L2） ----------

def status_line(scan, stage, st):
    with open(scan / "status.tsv", "a", encoding="utf-8") as f:
        f.write(f"{stage}\t{st}\tdetail of {stage}\n")


def go2(tmp_path, scheme=None, fs=None, euvd=EUVD, stage=None, name="q", anns=ANNS):
    proj, scan = setup(tmp_path, cfg=cfg_of(scheme=scheme), findings=fs or FS, evidence=None, services=None, anns=anns,
                       euvd=euvd, name=name)
    if stage:
        status_line(scan, "C-euvd", stage)
    r, s, reports = run(proj, scan)
    assert s is not None, r.stdout + r.stderr
    return s, ra_text(reports)


@pytest.mark.parametrize("analysis", [{"isSuppressed": True}, {"isSuppressed": False, "state": "NOT_AFFECTED"},
                                      {"isSuppressed": True, "state": "FALSE_POSITIVE"}])
def test_h1_current_euvd_row_does_not_leave_p1_by_suppression_or_unjustified_dt(tmp_path, analysis):
    """H1：current 下 EUVD 的列只因 DT 的 suppress、沒有 justification 的判定不離開 P1（和 exploitation 相同）；
    沒有 EUVD 的 KEV 列在 current 照舊（不改：main 的行為）。"""
    fs = [finding("libexample1", "2.0-1", "CVE-2026-69836", "NVD", "LOW", analysis=dict(analysis)),
          finding("libkev2", "1.0-1", "CVE-2026-9120", "NVD", "LOW", kev=True, analysis=dict(analysis))]
    s, t = go2(tmp_path, None, fs=fs, anns=None)
    assert {x["id"]: x["tier"] for x in s["euvd"]["list"]} == {"CVE-2026-69836": "p1"}
    assert "| CVE-2026-69836 |" in p1_section(t)
    acc = t[t.index("## Appendix A. Not affected / accepted"):]
    assert "| CVE-2026-9120 |" in acc and "CVE-2026-69836" not in acc


def test_h1_current_euvd_row_leaves_p1_by_justified_dt_decision(tmp_path):
    """有 justification 的 DT 判定（每一筆 finding）是人的判定：current 下 EUVD 的列也離開 P1。"""
    na = {"isSuppressed": False, "state": "NOT_AFFECTED", "justification": "CODE_NOT_REACHABLE", "details": "feature disabled"}
    s, t = go2(tmp_path, None, fs=[finding("libexample1", "2.0-1", "CVE-2026-69836", "NVD", "LOW", analysis=na)], anns=None)
    assert {x["id"]: x["tier"] for x in s["euvd"]["list"]} == {"CVE-2026-69836": "accepted"}


@pytest.mark.parametrize("scheme", [None, "exploitation"])
@pytest.mark.parametrize("stage", ["FAIL", "NOT_RUN", "GAP"])
def test_h2_c_euvd_not_ok_without_file_is_gap(tmp_path, scheme, stage):
    """H2：sca-scan 的 C-euvd 不是 OK 而且沒有寫 scan/euvd.json（FAIL、逾時會刪檔，NOT_RUN 不寫）→ current 也 GAP，理由只一次。"""
    s, t = go2(tmp_path, scheme, euvd=None, stage=stage)
    detail = s["documents"]["risk-assessment"]["detail"]
    want = f"EUVD exploited list not available (C-euvd {stage}, no scan/euvd.json): EU-KEV entries added after 2026-08 may be missing"
    assert detail.count(want) == 1 and s["documents"]["risk-assessment"]["status"] == "GAP", detail
    assert sum("EUVD exploited list not available" in d for d in detail) == 1
    assert s["euvd"]["available"] is False and s["euvd"]["file"] is None and s["euvd"]["stage_status"] == stage


def test_h2_old_scan_without_c_euvd_line_has_no_gap_in_current(tmp_path):
    s, t = go2(tmp_path, None, euvd=None)
    assert "euvd" not in s and not any("EUVD" in d for d in s["documents"]["risk-assessment"]["detail"])


@pytest.mark.parametrize("scheme", [None, "exploitation"])
def test_l1_gap_file_without_cves_is_reported_as_gap(tmp_path, scheme):
    """L1：沒有索引時 C-euvd 寫 status GAP、沒有 cves：理由寫 status GAP（不是 unreadable），file_status 是 GAP。"""
    s, t = go2(tmp_path, scheme, euvd={"stage": "C-euvd", "status": "GAP", "detail": "沒有設定 EUVD 鏡像"})
    detail = s["documents"]["risk-assessment"]["detail"]
    assert detail.count("EUVD exploited list not available (status GAP): EU-KEV entries added after 2026-08 may be missing") == 1
    assert s["euvd"]["file_status"] == "GAP" and "unreadable" not in " ".join(detail)
    if scheme:
        assert s["exploitation"]["euvd"]["file_status"] == "GAP" and "has status GAP" in t


@pytest.mark.parametrize("scheme", [None, "exploitation"])
def test_m1_untriaged_table_and_summary_show_euvd(tmp_path, scheme):
    """M1：VEX 小節的 untriaged 表與 summary 的 top_untriaged 分得出 EUVD（和風險表一致）。"""
    s, t = go2(tmp_path, scheme)
    top = {x["id"]: x for x in s["vex"]["gate"]["top_untriaged"]}
    assert top["CVE-2026-69836"]["kev"] is False and top["CVE-2026-69836"]["exploited_sources"] == ["EUVD (CISA KEV)"]
    assert "exploited_sources" not in top["CVE-2026-9104"]
    sec = t[t.index("#### Highest-priority untriaged rows"):]
    assert "| no; exploited: EUVD (CISA KEV) |" in sec and "| YES; exploited: EUVD (CISA KEV, ENISA EU KEV) |" in sec


def test_m2_summary_counts_name_euvd_rows(tmp_path):
    """M2：8.2 另一行算 EUVD 的列（KEV 的計數不變）。"""
    s, t = go2(tmp_path, None)
    assert s["counts"]["kev_open"] == 1 and s["counts"]["euvd_open"] == 4
    assert "| Open rows marked exploited by EUVD (CISA KEV / ENISA EU KEV via `scan/euvd.json`) | 4 |" in t


def test_l2_priority_key_ranks_euvd_with_kev():
    """L2：同一層裡被利用的列（KEV 或 EUVD）同一級，再依 EPSS 排；沒有 EUVD 時和以前一樣。"""
    kev = {"id": "CVE-1", "tier": "p1", "kev": True, "epss_pct": 0.1}
    eu = {"id": "CVE-2", "tier": "p1", "kev": False, "epss_pct": 0.9, "exploited_sources": ["EUVD (CISA KEV)"]}
    plain = {"id": "CVE-3", "tier": "p1", "kev": False, "epss_pct": 0.99}
    assert [r["id"] for r in sorted([kev, plain, eu], key=vx.priority_key)] == ["CVE-2", "CVE-1", "CVE-3"]
    man = {"id": "CVE-4", "tier": "p1", "kev": False, "epss_pct": 0.99, "exploited_sources": ["manual: x, 2026-10-01"]}
    assert [r["id"] for r in sorted([kev, man], key=vx.priority_key)] == ["CVE-1", "CVE-4"]


# ---------- 第三輪（L-a、L-b、L-c） ----------

@pytest.mark.parametrize("scheme", [None, "exploitation"])
@pytest.mark.parametrize("line, label", [("C-euvd\t\tdetail\n", "(no status)"), ("C-euvd\n", "(no status)"), ("C-euvd\tWEIRD\tx\n", "WEIRD")])
def test_la_c_euvd_line_without_or_with_unknown_status_is_gap(tmp_path, scheme, line, label):
    """L-a：status.tsv 有 C-euvd 這一行就算跑過（狀態欄空的、只有階段名、不認得的值都不是 OK）；沒有檔案 → GAP。"""
    proj, scan = setup(tmp_path, cfg=cfg_of(scheme=scheme), findings=FS, evidence=None, services=None, anns=ANNS, euvd=None)
    with open(scan / "status.tsv", "a", encoding="utf-8") as f:
        f.write(line)
    r, s, reports = run(proj, scan)
    detail = s["documents"]["risk-assessment"]["detail"]
    want = f"EUVD exploited list not available (C-euvd {label}, no scan/euvd.json): EU-KEV entries added after 2026-08 may be missing"
    assert detail.count(want) == 1 and s["documents"]["risk-assessment"]["status"] == "GAP", detail
    assert s["euvd"]["stage_status"] == label


def test_lb_current_without_kev_criteria_keeps_euvd_row_open(tmp_path):
    """L-b：current 的 p1、p2 都沒有 kev 條件時，EUVD 的列只有 DT suppress 也不進 accepted（照其他條件分到開放的層級）；
    KEV 的列照舊（suppress → accepted）。"""
    cfg = cfg_of(scheme=None)
    cfg["vulnerability_policy"] = {"tiers": {"p1": {"kev": False}, "p2": {"kev": False}}}
    fs = [finding("libexample1", "2.0-1", "CVE-2026-69836", "NVD", "LOW", analysis={"isSuppressed": True}),
          finding("libkev2", "1.0-1", "CVE-2026-9120", "NVD", "LOW", kev=True, analysis={"isSuppressed": True})]
    proj, scan = setup(tmp_path, cfg=cfg, findings=fs, evidence=None, services=None, anns=None, euvd=EUVD)
    r, s, reports = run(proj, scan)
    t = ra_text(reports)
    assert {x["id"]: x["tier"] for x in s["euvd"]["list"]} == {"CVE-2026-69836": "p3"}
    acc = t[t.index("## Appendix A. Not affected / accepted"):]
    assert "| CVE-2026-9120 |" in acc and "CVE-2026-69836" not in acc


def test_lc_risk_table_ranks_euvd_with_kev(tmp_path):
    """L-c：風險表裡同一層的被利用列（KEV 或 EUVD）同一級，再依 EPSS；人工證據不算（exploitation 下照舊排在 KEV 後面）。"""
    fs = [finding("libkev3", "1.0-1", "CVE-2026-9130", "NVD", "LOW", kev=True, epss=0.10),
          finding("libeu3", "1.0-1", "CVE-2026-69836", "NVD", "LOW", epss=0.50),
          finding("libman3", "1.0-1", "CVE-2026-9003", "NVD", "LOW", epss=0.95)]
    for scheme in (None, "exploitation"):
        proj, scan = setup(tmp_path, cfg=cfg_of(scheme=scheme), findings=fs, services=None, anns=None, euvd=EUVD,
                           name=f"lc-{scheme}")
        r, s, reports = run(proj, scan)
        p1 = p1_section(ra_text(reports))
        assert p1.index("CVE-2026-69836") < p1.index("CVE-2026-9130"), p1
        if scheme:
            assert p1.index("CVE-2026-9130") < p1.index("CVE-2026-9003")
    # 沒有 EUVD：和以前一樣只有 KEV 在前
    rows = cr.build_rows(fs, cr.policy_of(cfg_of(scheme=None)), cr.grype_index({"matches": []})[0], True)
    assert [r["id"] for r in rows][0] == "CVE-2026-9130"


# ---------- 審查（中 M1）：EUVD 不能用時不寫 0 ----------

KFS = FS + [finding("linux-kernel", "6.8.0", "CVE-2026-9140", "NVD", "LOW", purl="pkg:generic/linux-kernel@6.8.0")]
STALE = dict(EUVD, status="GAP", detail="EUVD 索引過期")     # 過期：C-euvd 照樣標註，但 status 是 GAP


@pytest.mark.parametrize("scheme", [None, "exploitation"])
@pytest.mark.parametrize("case, why", [("stale", "status GAP"), ("missing", "C-euvd FAIL, no scan/euvd.json"),
                                       ("not_ok", "status FAIL"), ("unreadable", "unreadable")])
def test_m1_unusable_euvd_counts_are_not_available_not_zero(tmp_path, scheme, case, why):
    """EUVD 不能用（過期、缺檔、status 不是 OK、讀不到）：8.2、8.7 的 EUVD 行寫 not available 與原因，counts.euvd_open 是 null，
    current 的 P1 規則文字不寫 EUVD（沒有套用）。"""
    euvd = {"stale": STALE, "missing": None, "not_ok": dict(EUVD, status="FAIL"), "unreadable": None}[case]
    proj, scan = setup(tmp_path, cfg=cfg_of(scheme=scheme), findings=KFS, evidence=None, services=None, anns=ANNS, euvd=euvd)
    if case == "missing":
        status_line(scan, "C-euvd", "FAIL")
    if case == "unreadable":
        (scan / "scan" / "euvd.json").write_text("{not json", encoding="utf-8")
    r, s, reports = run(proj, scan)
    t = ra_text(reports)
    na = f"not available: EUVD exploited list not available ({why}): EU-KEV entries added after 2026-08 may be missing"
    assert s["counts"]["euvd_open"] is None
    assert f"| {cr.EUVD_OPEN_LABEL} | {na} | {na} | {na} |" in t, t[t.index("### 8.2"):t.index("### 8.3")]
    k = t[t.index("Operating system kernel ("):]
    assert f"| {cr.EUVD_OPEN_LABEL} | {na} |" in k
    assert "| 0 |" not in "".join(l for l in t.splitlines() if "marked exploited by EUVD" in l)
    assert "or marked exploited by EUVD" not in t
    assert s["documents"]["risk-assessment"]["detail"].count(na[len("not available: "):]) == 1


@pytest.mark.parametrize("scheme", [None, "exploitation"])
def test_m1_usable_euvd_counts_and_rule_text(tmp_path, scheme):
    proj, scan = setup(tmp_path, cfg=cfg_of(scheme=scheme), findings=KFS, evidence=None, services=None, anns=ANNS, euvd=EUVD)
    r, s, reports = run(proj, scan)
    t = ra_text(reports)
    assert s["counts"]["euvd_open"] == 4 and f"| {cr.EUVD_OPEN_LABEL} | 4 | 0 | 4 |" in t
    assert ("or marked exploited by EUVD" in t) == (scheme is None)
