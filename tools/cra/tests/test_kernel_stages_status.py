"""cra_report：作業系統核心的判定階段（sca-scan 的 C-kernel-cve-list、C-kernel-config、C-kernel-module-map、C-kernel-versions、
C-kernel-not-judged-<版本>、C-kernel-cve-mirror）不是 OK 時，風險評估與整體狀態要降級（D-043：沒判定完不能顯示成沒問題）。
唯一的例外是 D-044 的分層報告：sca-scan --kernel-in-other-report 而且 SBOM 沒有核心時，三個核心階段是 NOT_RUN「不適用」——
只認 sca-scan 寫在 meta.json 的 kernel_in_other_report，不看說明文字。"""
import json

import pytest

import cra_report as cr
from test_cra_report import EXAMPLE, FINDINGS, META, make_project, make_scan, run

NA_TEXT = "不適用：這份報告的 SBOM 沒有作業系統核心，核心在 demo-bsp 報告判定"


def _report(tmp_path, stages=None, meta=None, details=None):
    findings = [f for f in FINDINGS if not f["vulnerability"].get("isKev") and (f["vulnerability"].get("epssPercentile") or 0) < 0.9]
    scan = make_scan(tmp_path / "s", findings=findings, meta=meta or META, stages=stages)
    if details:                                           # 說明文字（make_scan 寫的是 "detail of <階段>"）
        p = scan / "status.tsv"
        lines = p.read_text(encoding="utf-8").splitlines()
        p.write_text("\n".join(l if l.split("\t")[0] not in details else "\t".join(l.split("\t")[:2] + [details[l.split("\t")[0]]])
                               for l in lines) + "\n", encoding="utf-8")
    r, s, reports = run(make_project(tmp_path / "p", json.loads(json.dumps(EXAMPLE))), scan)
    assert s is not None, r.stdout + r.stderr
    return r, s, reports


def _risk(s):
    d = s["documents"]["risk-assessment"]
    return d["status"], d["detail"]


def test_baseline_without_kernel_stages(tmp_path):
    st, detail = _risk(_report(tmp_path)[1])
    assert not any(x.startswith("C-kernel-") for x in detail)


@pytest.mark.parametrize("stages", [
    {"C-kernel-cve-list": "NOT_RUN", "C-kernel-config": "NOT_RUN", "C-kernel-module-map": "NOT_RUN"},   # 沒有 CNA 鏡像（sca-scan:850）
    {"C-kernel-config": "NOT_RUN", "C-kernel-module-map": "NOT_RUN"},                                    # 沒給 --kernel-build
    {"C-kernel-cve-list": "GAP"},                                                                          # 核心版本讀不出來
    {"C-kernel-config": "FAIL"},                                                                           # kernel_config.py 失敗
    {"C-kernel-module-map": "GAP"},
    {"C-kernel-versions": "GAP"},
    {"C-kernel-not-judged-6.1.0-rpi7-rpi-2712": "GAP"},                                                   # 出貨但沒判定的核心
])
def test_kernel_stage_not_assessed_is_gap(tmp_path, stages):
    r, s, reports = _report(tmp_path, stages)
    st, detail = _risk(s)
    assert st == "GAP" or cr.ORDER.index(st) <= cr.ORDER.index("GAP"), (st, detail)
    for k, v in stages.items():
        assert f"{k} is {v}: the operating system kernel's CVEs were not fully assessed" in "\n".join(detail)
    assert cr.ORDER.index(s["status"]) <= cr.ORDER.index("GAP")             # 整體狀態（report_status）也降級
    assert r.returncode != 0
    ra = (reports / "risk-assessment.md").read_text(encoding="utf-8")
    assert all(k in ra for k in stages)                                        # 8.1 的資料狀態表也列出


def test_kernel_config_attention_stays_attention(tmp_path):
    base = _risk(_report(tmp_path / "b")[1])[0]
    st, detail = _risk(_report(tmp_path / "a", {"C-kernel-config": "ATTENTION", "C-kernel-cve-mirror": "ATTENTION"})[1])
    assert "C-kernel-config is ATTENTION" in detail and "C-kernel-cve-mirror is ATTENTION" in detail
    assert not any("not fully assessed" in x for x in detail)
    assert st == cr.worst([base, "ATTENTION"])


NA3 = {"C-kernel-cve-list": "NOT_RUN", "C-kernel-config": "NOT_RUN", "C-kernel-module-map": "NOT_RUN"}


def test_kernel_in_other_report_not_run_does_not_degrade(tmp_path):
    """D-044：meta.json 有 kernel_in_other_report（sca-scan 在 SBOM 沒有核心、給了 --kernel-in-other-report 時寫）→ 三個 NOT_RUN 不降級。"""
    base_st, base_detail = _risk(_report(tmp_path / "b")[1])
    meta = dict(META, kernel_in_other_report="demo-bsp")
    r, s, reports = _report(tmp_path / "a", NA3, meta=meta, details={k: NA_TEXT for k in NA3})
    st, detail = _risk(s)
    assert (st, detail) == (base_st, base_detail)
    assert "C-kernel-config" in (reports / "risk-assessment.md").read_text(encoding="utf-8")   # 照實列在表裡


def test_not_applicable_text_without_the_meta_marker_is_gap(tmp_path):
    """說明文字寫「不適用」但 meta.json 沒有 kernel_in_other_report：不信文字，照樣 GAP。"""
    st, detail = _risk(_report(tmp_path, NA3, details={k: NA_TEXT for k in NA3})[1])
    assert cr.ORDER.index(st) <= cr.ORDER.index("GAP")
    assert sum("not fully assessed" in x for x in detail) == 3


@pytest.mark.parametrize("stages", [
    {**NA3, "C-kernel-config": "FAIL"},                     # 標記只免除 NOT_RUN
    {**NA3, "C-kernel-versions": "GAP"},                    # 標記只涵蓋三個核心階段
    {**NA3, "C-kernel-not-judged-6.8.0": "GAP"},
])
def test_meta_marker_only_covers_the_three_not_run_stages(tmp_path, stages):
    meta = dict(META, kernel_in_other_report="demo-bsp")
    st, detail = _risk(_report(tmp_path, stages, meta=meta)[1])
    assert cr.ORDER.index(st) <= cr.ORDER.index("GAP")
    bad = [k for k, v in stages.items() if not (v == "NOT_RUN" and k in cr.KERNEL_OTHER_REPORT_NA)]
    assert all(any(x.startswith(f"{k} is ") for x in detail) for k in bad)
    assert not any(x.startswith(f"{k} is NOT_RUN") for k in cr.KERNEL_OTHER_REPORT_NA for x in detail)


def test_kernel_stage_level_rules():
    m = {"kernel_in_other_report": "x-bsp"}
    assert cr.kernel_stage_level("C-kernel-config", "OK", {}) is None
    assert cr.kernel_stage_level("C-kernel-config", "NOT_RUN", {}) == "GAP"
    assert cr.kernel_stage_level("C-kernel-config", "NOT_RUN", m) is None
    assert cr.kernel_stage_level("C-kernel-config", "NOT_RUN", {"kernel_in_other_report": ""}) == "GAP"
    assert cr.kernel_stage_level("C-kernel-versions", "NOT_RUN", m) == "GAP"
    assert cr.kernel_stage_level("C-kernel-config", "ATTENTION", m) == "ATTENTION"
    assert cr.kernel_stage_level("C-kernel-config", "NOT_ASSESSED", {}) == "GAP"
    assert cr.kernel_stage_keys({"C-kernel-not-judged-b": 1, "C-kernel-config": 1, "C-kernel-not-judged-a": 1, "C-kernel-boot": 1}) == \
        ["C-kernel-config", "C-kernel-not-judged-a", "C-kernel-not-judged-b"]
