"""ci_summary.py（e2e-pilot 工作摘要）與 lib/licverdict.py（DejaCode 授權判定）的測試。不需要 DT、DejaCode 或網路。"""
import json

from pilot_fixtures import PILOT, load_module

cs = load_module("pilot_ci_summary", PILOT / "ci_summary.py")
lv = load_module("pilot_licverdict", PILOT / "lib" / "licverdict.py")

DEPLOY_END = ("Z-secret-scan", "OK", "")
SCAN_END = ("Z-scan-done", "INFO", "跑完")


def tsv(tmp_path, name, rows, raw=None):
    p = tmp_path / name
    body = raw if raw is not None else "".join(f"{s}\t{t}\t{d}\n" for s, t, d in rows)
    p.write_text("stage\tstatus\tdetail\n" + body, encoding="utf-8")
    return str(p)


def part(name, path, *markers):
    return (name, path, list(markers))


def test_all_ok_is_complete_and_first_line(tmp_path):
    d = tsv(tmp_path, "d.tsv", [("C1-install", "OK", ""), ("C9-cleanup", "INFO", "保留"), DEPLOY_END])
    s = tsv(tmp_path, "s.tsv", [("scan-npm-lodash", "OK", "exit=0"), SCAN_END])
    overall, text = cs.summarize([part("部署", d, "Z-secret-scan"), part("掃描", s, "Z-scan-done")], "success")
    assert overall == "COMPLETE"
    assert text.splitlines()[0] == "# e2e-pilot 整體：COMPLETE"


def test_gap_or_attention_is_incomplete(tmp_path):
    s = tsv(tmp_path, "s.tsv", [("scan-x", "ATTENTION", "exit=2"), ("expect-dt-x", "GAP", "資料不完整"), SCAN_END])
    overall, text = cs.summarize([part("掃描", s, "Z-scan-done")])
    assert overall == "INCOMPLETE" and text.startswith("# e2e-pilot 整體：INCOMPLETE\n")
    assert "expect-dt-x" in text and "scan-x" in text


def test_fail_wins_and_sorted_first(tmp_path):
    d = tsv(tmp_path, "d.tsv", [("C2-status", "GAP", ""), ("C7-backup", "FAIL", "缺少 dt.dump"), DEPLOY_END])
    overall, text = cs.summarize([part("部署", d, "Z-secret-scan")])
    assert overall == "FAIL"
    assert text.index("C7-backup") < text.index("C2-status")


def test_transient_mirror_rows_not_counted(tmp_path):
    # 與 ci-deploy-check.sh 結束碼相同：子腳本的 mirror 狀態不計入，最終以 C4 為準
    d = tsv(tmp_path, "d.tsv", [("install1:D-mirror-nvd", "GAP", "還沒有紀錄"), ("status1:mirror-osv", "FAIL", "暫時"),
                                ("status2:kev-cisa", "GAP", ""), ("install2:D-mirror-nvd", "FAIL", ""),
                                ("C4-mirror-nvd", "OK", "COMPLETED"), ("install1:DT-osv", "OK", ""), DEPLOY_END])
    overall, text = cs.summarize([part("部署", d, "Z-secret-scan")], "success")
    assert overall == "COMPLETE"
    assert "| 部署 | 3 | 0 | 0 | 4 |" in text


def test_install_non_mirror_fail_is_counted(tmp_path):
    d = tsv(tmp_path, "d.tsv", [("install2:DT-osv", "FAIL", "讀回不符"), DEPLOY_END])
    assert cs.summarize([part("部署", d, "Z-secret-scan")])[0] == "FAIL"


def test_missing_marker_is_incomplete(tmp_path):
    # 逾時或中途結束：已寫入的列全 OK 也不能算完整
    d = tsv(tmp_path, "d.tsv", [("C1-install", "OK", ""), ("C2-status", "OK", "")])
    overall, text = cs.summarize([part("部署", d, "Z-secret-scan", "Z-workflow-secret-scan")], "success")
    assert overall == "INCOMPLETE" and "腳本沒跑完" in text


def test_either_marker_accepted(tmp_path):
    d = tsv(tmp_path, "d.tsv", [("Z-workflow-secret-scan", "FAIL", "命中")])
    assert cs.summarize([part("部署", d, "Z-secret-scan", "Z-workflow-secret-scan")])[0] == "FAIL"


def test_job_status_not_success_is_incomplete(tmp_path):
    d = tsv(tmp_path, "d.tsv", [("C1-install", "OK", ""), DEPLOY_END])
    overall, text = cs.summarize([part("部署", d, "Z-secret-scan")], "cancelled")
    assert overall == "INCOMPLETE" and "cancelled" in text


def test_only_info_rows_is_incomplete(tmp_path):
    s = tsv(tmp_path, "s.tsv", [SCAN_END])
    overall, text = cs.summarize([part("掃描", s, "Z-scan-done")], "success")
    assert overall == "INCOMPLETE" and "沒有任何計入的階段" in text


def test_missing_file_is_incomplete(tmp_path):
    d = tsv(tmp_path, "d.tsv", [("C1-install", "OK", ""), DEPLOY_END])
    overall, text = cs.summarize([part("部署", d, "Z-secret-scan"), part("掃描", str(tmp_path / "nope.tsv"), "Z-scan-done")], "success")
    assert overall == "INCOMPLETE" and "掃描：沒有 status.tsv" in text


def test_empty_stage_fail_counted(tmp_path):
    # ci-deploy-check.sh 的 awk 會把空 stage 的 FAIL 算進結束碼；摘要不可比它寬鬆
    d = tsv(tmp_path, "d.tsv", None, raw="\tFAIL\t某個失敗\nZ-secret-scan\tOK\t\n")
    overall, text = cs.summarize([part("部署", d, "Z-secret-scan")])
    assert overall == "FAIL" and "(空)" in text


def test_malformed_and_unknown_status_are_fail(tmp_path):
    d = tsv(tmp_path, "d.tsv", None, raw="只有一欄\nZ-secret-scan\tOK\t\n")
    assert cs.summarize([part("部署", d, "Z-secret-scan")])[0] == "FAIL"
    d2 = tsv(tmp_path, "d2.tsv", [("C1-install", "FIAL", ""), DEPLOY_END])
    overall, text = cs.summarize([part("部署", d2, "Z-secret-scan")])
    assert overall == "FAIL" and "不認得的狀態值" in text


def test_markdown_escaping(tmp_path):
    d = tsv(tmp_path, "d.tsv", [("C3-x", "GAP", "a\\|b <script> & `c`"), DEPLOY_END])
    _, text = cs.summarize([part("部署", d, "Z-secret-scan")])
    assert "a&#92;&#124;b &lt;script&gt; &amp; &#96;c&#96;" in text and "<script>" not in text


def test_main_args(tmp_path, capsys):
    d = tsv(tmp_path, "d.tsv", [("C1-install", "OK", ""), DEPLOY_END])
    assert cs.main(["--job-status", "success", "--part", "部署", d, "Z-secret-scan,Z-workflow-secret-scan"]) == 0
    assert capsys.readouterr().out.startswith("# e2e-pilot 整體：COMPLETE\n")
    assert cs.main([]) == 3
    assert cs.main(["--part", "部署"]) == 3
    assert cs.main(["--job-status", "success", "--part", "部署", d, ","]) == 3


def test_job_status_missing_is_incomplete(tmp_path):
    d = tsv(tmp_path, "d.tsv", [("C1-install", "OK", ""), DEPLOY_END])
    assert cs.summarize([part("部署", d, "Z-secret-scan")])[0] == "INCOMPLETE"
    assert cs.summarize([part("部署", d, "Z-secret-scan")], "")[0] == "INCOMPLETE"


# ---- licverdict ----

def counts(**kw):
    c = {"error": 0, "warning": 0, "pass": 0, "no_license": 0, "not_assessed": 0}
    c.update(kw)
    return c


def test_license_ok():
    assert lv.verdict(counts(**{"pass": 3}), 3)[0] == "OK"


def test_license_warning_is_attention():
    st, d = lv.verdict(counts(**{"pass": 2, "warning": 1}))
    assert st == "ATTENTION" and "warning 1" in d


def test_license_error_is_attention():
    st, d = lv.verdict(counts(error=1, warning=2))
    assert st == "ATTENTION" and "error 1" in d and "warning 2" in d


def test_license_unassessed_is_gap_and_mentions_warning():
    st, d = lv.verdict(counts(no_license=1, warning=1))
    assert st == "GAP" and "warning 1" in d
    assert lv.verdict(counts(not_assessed=2))[0] == "GAP"


def test_license_zero_packages_not_assessed():
    assert lv.verdict(counts(), 0)[0] == "NOT_ASSESSED"


def test_license_bad_counts_fail():
    assert lv.verdict({})[0] == "FAIL"
    assert lv.verdict(counts(error="x"))[0] == "FAIL"
    assert lv.verdict(counts(warning=-1))[0] == "FAIL"
    assert lv.verdict(counts(warning=True))[0] == "FAIL"
    assert lv.verdict(None)[0] == "FAIL"


def test_license_total_mismatch_gap():
    st, d = lv.verdict(counts(**{"pass": 2}), 3)
    assert st == "GAP" and "對不上" in d


def test_license_main_reads_file(tmp_path, capsys):
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"packages": 1, "counts": counts(warning=1)}), encoding="utf-8")
    assert lv.main([str(p)]) == 0
    assert capsys.readouterr().out.split("\t")[0] == "ATTENTION"


def test_license_main_bad_file(tmp_path, capsys):
    assert lv.main([str(tmp_path / "nope.json")]) == 0
    assert capsys.readouterr().out.startswith("FAIL\t")
    p = tmp_path / "c.json"
    p.write_text("[]", encoding="utf-8")
    assert lv.main([str(p)]) == 0
    assert capsys.readouterr().out.startswith("FAIL\t")
