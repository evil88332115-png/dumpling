"""scan/kernel-versions.json（sca-scan 的 --kernel-version；映像出貨但沒判定的核心）→ 待確認事項「作業系統核心」。合成資料。"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
import confirm_items as ci  # noqa: E402
from test_cra_report import kernel_scan, make_project, run, write_json  # noqa: E402
from test_confirm_items import keys, read_csv  # noqa: E402

A, B = "6.1.118", "6.1.120"          # 合成的核心版本
SCHEMA = "sca-center-kernel-versions/2"


def doc(shipped, requested, judged, not_judged):
    return {"schema": SCHEMA, "shipped": None if shipped is None else [{"version": v, "upstream_version": None, "upstream_basis": None, "upstream_note": "x"} for v in shipped], "requested": requested, "judged": judged, "not_judged": not_judged}


def test_item_lists_not_judged_kernels():
    d = doc([A, B], [A], [A], [{"version": B, "reason": "出貨但沒有列在 --kernel-version，這次只判定指定的核心", "shipped": True}])
    x = ci.kernel_versions_items(d)
    assert len(x) == 1 and x[0]["key"] == "kernel:not-judged" and x[0]["category"] == "作業系統核心" and x[0]["ask"] == "RD"
    assert "2 顆" in x[0]["finding"] and "1 顆沒有判定" in x[0]["finding"] and B in x[0]["finding"]
    assert f"（{A}）" in x[0]["impact"] and "GAP" in x[0]["impact"]
    assert "設計文件" in x[0]["suggestion"] and "記錄證據" in x[0]["suggestion"]
    # 全部沒判定（指定 2 顆以上）：判定過的核心「沒有」
    d = doc([A, B], [A, B], [], [{"version": A, "reason": "多顆核心逐一判定還沒實作（M2 之後）", "shipped": True},
                                  {"version": B, "reason": "多顆核心逐一判定還沒實作（M2 之後）", "shipped": True}])
    x = ci.kernel_versions_items(d)[0]
    assert "2 顆沒有判定" in x["finding"] and "多顆核心逐一判定還沒實作" in x["finding"] and "（沒有）" in x["impact"]


def test_no_item_when_everything_judged_or_bad_file():
    assert ci.kernel_versions_items(None) == [] and ci.kernel_versions_items([]) == []
    assert ci.kernel_versions_items(doc([A], [], [A], [])) == []                          # 只有一顆：不問
    assert ci.kernel_versions_items({"schema": "other/1", "not_judged": [{"version": B}]}) == []
    assert ci.kernel_versions_items(doc(None, [A, B], [], [{"version": A, "reason": "x", "shipped": None}]))   # 出貨的核心讀不出來也要問


def test_report_reads_the_file(tmp_path):
    """cra_report 讀 scan/kernel-versions.json：有沒判定的核心 → 待確認事項多一筆；沒有這個檔案 → 和以前相同。"""
    scan = kernel_scan(tmp_path / "s")
    _, s0, _ = run(make_project(tmp_path / "p0"), scan)
    assert "kernel:not-judged" not in keys(s0)
    write_json(scan / "scan" / "kernel-versions.json",
               doc([A, B], [A], [A], [{"version": B, "reason": "出貨但沒有列在 --kernel-version，這次只判定指定的核心", "shipped": True}]))
    _, s1, reports = run(make_project(tmp_path / "p1"), scan)
    assert "kernel:not-judged" in keys(s1)
    assert [k for k in keys(s1) if k != "kernel:not-judged"] == keys(s0)                   # 其他事項不變
    x = next(x for x in read_csv(reports)[1] if "kernel:not-judged" in x["掃描發現（為什麼要問）"])
    assert B in x["掃描發現（為什麼要問）"] and "記錄證據" in x["建議做法"]
    write_json(scan / "scan" / "kernel-versions.json", doc([A], [], [A], []))
    _, s2, _ = run(make_project(tmp_path / "p2"), scan)
    assert keys(s2) == keys(s0)


def test_schema_v1_file_is_still_read():
    d = dict(doc([A, B], [A], [A], [{"version": B, "reason": "x", "shipped": True}]), schema="sca-center-kernel-versions/1", shipped=[A, B])
    x = ci.kernel_versions_items(d)
    assert len(x) == 1 and "2 顆" in x[0]["finding"] and B in x[0]["finding"]
