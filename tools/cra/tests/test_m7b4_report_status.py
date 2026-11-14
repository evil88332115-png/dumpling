"""M7b-4 報告判定：B-bootloader-coverage（D-054）與 C-kernel-boot 進報告狀態（summary.json 的 status、documents.risk-assessment），
但不進漏洞資料狀態（risk_st），所以不擋 VEX 發行閘門（vex.gate）；非 OK 的列進待確認事項表。合成資料。"""
import json

import pytest

import cra_report as cr
from test_cra_report import EXAMPLE, FINDINGS, SBOM, make_project, make_scan, run
from test_confirm_items import keys, read_csv

V = "rootfs_no_gui"
BK = f"B-bootloader-coverage-{V}"
ADV = "the vendor's security advisories are authoritative for closed-source firmware"
KB_GAP = {"schema": "sca-center-kernel-boot/1", "status": "GAP", "detail": "rootfs/boot/Image could not be read (symlink)"}
KB_ATT = {"schema": "sca-center-kernel-boot/1", "status": "ATTENTION", "detail": "two different kernels, no board data to confirm",
          "partition_image": {"sha256": "a" * 64, "uts": "#1 SMP x"}, "rootfs_image": {"sha256": "b" * 64, "uts": "#1 SMP y"}}


def _report(tmp_path, flash_rows=None, list_json=True, sbom=None, kboot=None, stages=None, meta=None):
    """刷機包的結果資料夾：<res>/list.json、<res>/status.tsv（刷機包層），<res>/<rootfs>/scan（sca-scan 的輸出，kboot＝scan/kernel-boot.json）。"""
    res = tmp_path / "res"
    findings = [f for f in FINDINGS if not f["vulnerability"].get("isKev") and (f["vulnerability"].get("epssPercentile") or 0) < 0.9]
    kw = {"meta": meta} if meta else {}
    scan = make_scan(res / V / "scan", findings=findings, sbom=sbom or SBOM, stages=stages, **kw)
    if list_json:
        (res / "list.json").write_text(json.dumps({"rootfs": [{"variant": V, "prefix": f"x/{V}"}]}), encoding="utf-8")
    (res / "status.tsv").write_text("stage\tstatus\tdetail\n" + "".join(f"{k}\t{v}\tdetail of {k}\n" for k, v in (flash_rows or {}).items()),
                                    encoding="utf-8")
    if kboot is not None:
        (scan / "scan" if (scan / "scan").is_dir() else scan).joinpath("kernel-boot.json").write_text(
            kboot if isinstance(kboot, str) else json.dumps(kboot), encoding="utf-8")
    r, s, reports = run(make_project(tmp_path / "p", json.loads(json.dumps(EXAMPLE))), scan)
    assert s is not None, r.stdout + r.stderr
    return s, reports


def _ra(s):
    d = s["documents"]["risk-assessment"]
    return d["status"], d["detail"]


def _cmp(s):
    """報告狀態與發行閘門的比對用：documents 的狀態、整體狀態、漏洞資料狀態、閘門全文。"""
    return (s["status"], _ra(s)[0], s["vex"]["gate"], s["documents"]["kernel-vulnerabilities"]["status"]
            if "kernel-vulnerabilities" in s["documents"] else None)


def _vex(s):
    """summary.json 的 vex（檔案的 SHA-256 含產生時間，跨秒會不同：不比 files）。"""
    return {k: v for k, v in s["vex"].items() if k != "files"}


def _base(tmp_path):
    return _report(tmp_path / "base")[0]


def _vuln_status(reports):
    return next(l for l in (reports / "risk-assessment.md").read_text(encoding="utf-8").splitlines() if l.startswith("**Vulnerability data status"))


# ---------- A. B-bootloader-coverage（D-054）----------

@pytest.mark.parametrize("st,lv,text", [
    ("GAP", "GAP", f"{BK} is GAP (flash package scan): closed-source boot firmware was not scanned; {ADV}"),
    ("NOT_ASSESSED", "GAP", f"{BK} is NOT_ASSESSED (flash package scan): the boot chain was not assessed; {ADV}"),
    ("FAIL", "GAP", f"{BK} is FAIL (flash package scan): the boot firmware coverage was not determined, so closed-source boot firmware was not scanned; {ADV}"),
    ("NOT_RUN", "GAP", f"{BK} is NOT_RUN (flash package scan): the boot firmware coverage was not determined, so closed-source boot firmware was not scanned; {ADV}"),
    ("ATTENTION", "ATTENTION", f"{BK} is ATTENTION (flash package scan): the boot firmware coverage needs review; {ADV}"),
])
def test_bootloader_coverage_reaches_the_report_status(tmp_path, st, lv, text):
    base = _base(tmp_path)
    s, reports = _report(tmp_path / "a", {BK: st})
    ra_st, detail = _ra(s)
    assert text in detail
    assert ra_st == cr.worst([_ra(base)[0], lv]) and s["status"] == cr.worst([base["status"], lv])
    if lv == "GAP":
        assert ra_st == "GAP" and s["status"] == "GAP"            # 顯示 GAP，不是 ATTENTION
    md = (reports / "risk-assessment.md").read_text(encoding="utf-8")
    assert text in md and BK in md                                  # 文件裡寫明原因與「廠商公告為準」（8.1 的資料狀態與資料來源表）
    assert f"key={BK}" not in md and "[firmware:" not in md


@pytest.mark.parametrize("st,lv", [("GAP", "GAP"), ("NOT_ASSESSED", "GAP"), ("FAIL", "GAP"), ("ATTENTION", "ATTENTION")])
def test_bootloader_coverage_does_not_touch_the_release_gate(tmp_path, st, lv):
    """D-054：進報告狀態，不擋 VEX 發行閘門：閘門全文、漏洞資料狀態、核心文件的狀態都和沒有這一列時相同。"""
    base, base_reports = _report(tmp_path / "b")
    s, reports = _report(tmp_path / "a", {BK: st})
    assert s["vex"]["gate"] == base["vex"]["gate"]
    assert _cmp(s)[2:] == _cmp(base)[2:]
    assert _vex(s) == _vex(base)
    assert _vuln_status(reports) == _vuln_status(base_reports)
    for k in ("vulnerability_data_status",):
        assert s.get(k) == base.get(k)
    assert not any(BK in x for x in s["vex"]["gate"]["reasons"])


def test_control_other_flash_rows_still_block_the_gate(tmp_path):
    """對照：同一個位置的 B-initrd-coverage 進漏洞資料狀態，閘門會變 GAP；證明上面「閘門不變」不是因為測試走不到閘門。"""
    base = _base(tmp_path)
    s, _ = _report(tmp_path / "a", {f"B-initrd-coverage-{V}": "GAP"})
    assert s["vex"]["gate"]["verdict"] == "GAP" != base["vex"]["gate"]["verdict"]


def test_bootloader_gap_next_to_a_gating_row_keeps_the_gate_reason_of_the_gating_row_only(tmp_path):
    s, _ = _report(tmp_path, {BK: "GAP", f"B-initrd-coverage-{V}": "GAP"})
    assert s["vex"]["gate"]["verdict"] == "GAP"
    assert not any("bootloader" in x for x in s["vex"]["gate"]["reasons"])
    assert any("B-initrd-coverage" in x for x in _ra(s)[1]) and any(BK in x for x in _ra(s)[1])


@pytest.mark.parametrize("st", ["OK", "INFO"])
def test_bootloader_coverage_ok_info_and_missing_row_change_nothing(tmp_path, st):
    base, base_reports = _report(tmp_path / "b")
    s, reports = _report(tmp_path / "a", {BK: st})
    assert s["status"] == base["status"] and _ra(s) == _ra(base) and _vex(s) == _vex(base)
    assert keys(s) == keys(base)
    assert not any("bootloader" in x.lower() for x in _ra(s)[1])


def test_other_rootfs_and_non_flash_scans_are_not_read(tmp_path):
    base = _base(tmp_path)
    s, _ = _report(tmp_path / "a", {"B-bootloader-coverage-rootfs_gui": "GAP"})                    # 別的 rootfs 的列
    assert s["status"] == base["status"] and _ra(s) == _ra(base) and keys(s) == keys(base)
    s, _ = _report(tmp_path / "c", {BK: "GAP"}, list_json=False)                                    # 不是刷機包的掃描：不讀 <res>/status.tsv
    assert s["status"] == base["status"] and _ra(s) == _ra(base) and keys(s) == keys(base)


def test_os_layer_with_no_bsp_components_skips_it_but_a_bsp_layer_counts_it(tmp_path):
    """分層的 -os 報告（SBOM 沒有 bsp／unknown 元件，customer）：開機韌體是 BSP 的事，不算進這份（GAP、NOT_ASSESSED 都一樣）；有 bsp 元件的算。"""
    from test_layers_report import _layered_sbom
    base = _report(tmp_path / "b", sbom=_layered_sbom())[0]
    for st in ("GAP", "NOT_ASSESSED"):
        s, _ = _report(tmp_path / f"o-{st}", {BK: st}, sbom=_layered_sbom())
        assert s["status"] == base["status"] and _ra(s) == _ra(base) and keys(s) == keys(base)
        assert not any("bootloader" in x.lower() for x in _ra(s)[1])
    s, _ = _report(tmp_path / "bsp", {BK: "GAP"}, sbom=_layered_sbom("bsp"))
    assert s["status"] == "GAP" and any(BK in x for x in _ra(s)[1]) and f"firmware:{BK}" in keys(s)


def test_confirmation_items_have_the_firmware_item(tmp_path):
    base = _base(tmp_path)
    for st in ("GAP", "NOT_ASSESSED", "FAIL", "ATTENTION"):
        s, reports = _report(tmp_path / st, {BK: st})
        assert f"firmware:{BK}" in keys(s)
        assert [k for k in keys(s) if k != f"firmware:{BK}"] == keys(base)           # 其他事項不變（不會多出「漏洞資料不完整」）
        x = next(x for x in read_csv(reports)[1] if f"[firmware:{BK}]" in x["掃描發現（為什麼要問）"])
        assert x["類別"] == "開機韌體" and "廠商" in x["掃描發現（為什麼要問）"] and "廠商的安全公告" in x["建議做法"]
        assert "發行閘門不因此擋住" in x["影響"]
    s, _ = _report(tmp_path / "ok", {BK: "OK"})
    assert f"firmware:{BK}" not in keys(s)
    s, reports = _report(tmp_path / "na", {BK: "NOT_ASSESSED"})
    assert "開機鏈沒有評估" in next(x for x in read_csv(reports)[1] if f"[firmware:{BK}]" in x["掃描發現（為什麼要問）"])["掃描發現（為什麼要問）"]


def test_flash_stage_helpers():
    assert cr.flash_stage_is_firmware(BK) and cr.flash_stage_is_firmware("B-bootloader-coverage-x")
    assert not any(cr.flash_stage_is_firmware(k) for k in ("B-initrd-coverage-x", "B-rootfs-tar-x", "B-uefi-binary", "B-bootloader-coverage"))
    assert cr.FLASH_ROOTFS_STAGES["B-bootloader-coverage"] is True                    # BSP 專屬
    assert [cr.flash_stage_level(x) for x in ("OK", "INFO", "ATTENTION", "GAP", "NOT_ASSESSED", "FAIL", "NOT_RUN", "")] == \
        [None, None, "ATTENTION", "GAP", "GAP", "GAP", "GAP", "GAP"]


def test_flash_stage_status_reads_the_row(tmp_path):
    scan = make_scan(tmp_path / "res" / V / "scan")
    (tmp_path / "res" / "list.json").write_text(json.dumps({"rootfs": [{"variant": V}]}), encoding="utf-8")
    (tmp_path / "res" / "status.tsv").write_text(f"stage\tstatus\tdetail\n{BK}\tNOT_ASSESSED\tplatform not defined\n", encoding="utf-8")
    assert cr.flash_stage_status(scan) == {BK: ("NOT_ASSESSED", "platform not defined", True)}


# ---------- B. C-kernel-boot ----------

@pytest.mark.parametrize("kb,lv,frag", [(KB_GAP, "GAP", "the two kernels in the flash package could not be compared"),
                                        (KB_ATT, "ATTENTION", "which kernel actually boots has to be confirmed on a board")])
def test_kernel_boot_gap_and_attention_reach_the_report_status(tmp_path, kb, lv, frag):
    base = _base(tmp_path)
    s, reports = _report(tmp_path / "a", kboot=kb)
    ra_st, detail = _ra(s)
    assert any(x.startswith(f"C-kernel-boot is {lv}: ") and frag in x and kb["detail"] in x for x in detail), detail
    assert ra_st == cr.worst([_ra(base)[0], lv]) and s["status"] == cr.worst([base["status"], lv])
    assert any(x.startswith(f"C-kernel-boot {lv}：") for x in s["config_warnings"])               # 警告照留
    assert "kernel:two-kernels" in keys(s) and keys(s).count("kernel:two-kernels") == 1       # 待確認事項原本就有（不重複加）


@pytest.mark.parametrize("kb", [KB_GAP, KB_ATT])
def test_kernel_boot_does_not_touch_the_release_gate(tmp_path, kb):
    base, base_reports = _report(tmp_path / "b")
    s, reports = _report(tmp_path / "a", kboot=kb)
    assert _vex(s) == _vex(base) and _vuln_status(reports) == _vuln_status(base_reports)
    assert not any("C-kernel-boot" in x for x in s["vex"]["gate"]["reasons"])


@pytest.mark.parametrize("kb", [None, {"schema": "sca-center-kernel-boot/1", "status": "OK", "detail": "byte-identical"}])
def test_kernel_boot_ok_or_missing_file_changes_nothing(tmp_path, kb):
    """OK、沒有檔案（不是刷機包、或只有一顆核心）：不處理（不會變成別的狀態，也不會報錯）。"""
    base = _base(tmp_path)
    s, _ = _report(tmp_path / "a", kboot=kb)
    assert s["status"] == base["status"] and _ra(s) == _ra(base) and keys(s) == keys(base) and s["config_warnings"] == base["config_warnings"]


@pytest.mark.parametrize("kb", [{"schema": "sca-center-kernel-boot/1", "status": "NOT_RUN", "detail": "x"},
                                {"schema": "other/1", "status": "GAP", "detail": "x"}, {"status": "GAP"}, "{not json", "[]", "null"])
def test_kernel_boot_unusable_file_is_gap_without_touching_the_gate(tmp_path, kb):
    """C1 審查（D-043）：kernel-boot.json 存在卻讀不懂（不是 JSON、schema 或 status 不對）→ GAP，不當成沒事；發行閘門照舊不受影響。"""
    base = _base(tmp_path)
    s, _ = _report(tmp_path / "a", kboot=kb)
    assert s["status"] == "GAP" and any("kernel-boot.json exists but could not be read" in x for x in _ra(s)[1]), _ra(s)
    assert _vex(s) == _vex(base)


def test_kernel_boot_status_row_fail_is_gap_and_asks(tmp_path):
    """kernel_boot.py 失敗時 sca-scan 只寫 status.tsv 的 FAIL 列、不留 json：不能當成沒事。"""
    base = _base(tmp_path)
    s, _ = _report(tmp_path / "a", stages={"C-kernel-boot": "FAIL"})
    assert s["status"] == "GAP" and any(x.startswith("C-kernel-boot is FAIL: ") for x in _ra(s)[1])
    assert "kernel:two-kernels" in keys(s) and _vex(s) == _vex(base)
    for st in ("OK", "INFO"):
        s, _ = _report(tmp_path / st, stages={"C-kernel-boot": st})
        assert s["status"] == base["status"] and _ra(s) == _ra(base) and keys(s) == keys(base)
    s, _ = _report(tmp_path / "att", stages={"C-kernel-boot": "ATTENTION"})
    assert _ra(s)[0] == cr.worst([_ra(base)[0], "ATTENTION"]) and any(x.startswith("C-kernel-boot is ATTENTION: ") for x in _ra(s)[1])


def test_kernel_boot_row_and_json_do_not_double_count(tmp_path):
    s, _ = _report(tmp_path, kboot=KB_ATT, stages={"C-kernel-boot": "ATTENTION"})
    assert sum(x.startswith("C-kernel-boot") for x in _ra(s)[1]) == 1 and keys(s).count("kernel:two-kernels") == 1


def test_kernel_boot_is_not_counted_in_a_layer_whose_kernel_is_judged_elsewhere(tmp_path):
    base = _base(tmp_path)
    s, _ = _report(tmp_path / "a", kboot=KB_GAP, meta=dict(__import__("test_cra_report").META, kernel_in_other_report="demo-bsp"),
                   stages={"C-kernel-cve-list": "NOT_RUN", "C-kernel-config": "NOT_RUN", "C-kernel-module-map": "NOT_RUN"})
    assert not any(x.startswith("C-kernel-boot is") for x in _ra(s)[1])
    # 標記格式不對時照樣算
    s, _ = _report(tmp_path / "b", kboot=KB_GAP, meta=dict(__import__("test_cra_report").META, kernel_in_other_report="-x"))
    assert any(x.startswith("C-kernel-boot is GAP") for x in _ra(s)[1])


def test_kernel_boot_findings_unit():
    assert cr.kernel_boot_findings(None, None, None) == [] and cr.kernel_boot_findings(None, {}, {}) == []
    assert cr.kernel_boot_findings({"schema": "sca-center-kernel-boot/1", "status": "OK"}, {"C-kernel-boot": ("OK", "")}, {}) == []
    assert cr.kernel_boot_findings(KB_GAP, {}, {})[0][0] == "GAP" and cr.kernel_boot_findings(KB_ATT, {}, {})[0][0] == "ATTENTION"
    assert cr.kernel_boot_findings(KB_GAP, {}, {"kernel_in_other_report": "demo-bsp"}) == []
    assert cr.kernel_boot_findings(None, {"C-kernel-boot": ("FAIL", "boom")}, {})[0][0] == "GAP"
    assert cr.kernel_boot_findings(KB_ATT, {"C-kernel-boot": ("FAIL", "boom")}, {})[0][0] == "ATTENTION"      # json 優先，不重複


def test_kernel_boot_json_present_but_unreadable_is_gap():
    """C1 審查：kernel-boot.json 存在卻讀不懂 → GAP（D-043），不當成沒事；檔案不存在照舊不處理。"""
    for bad in (None, [], {"schema": "other/1", "status": "OK"}, {"schema": "sca-center-kernel-boot/1", "status": "WEIRD"}):
        f = cr.kernel_boot_findings(bad, {}, {}, present=True)
        assert [x[0] for x in f] == ["GAP"] and "could not be read" in f[0][1], bad
    assert cr.kernel_boot_findings(None, {}, {}, present=False) == []
    ok = {"schema": "sca-center-kernel-boot/1", "status": "OK"}
    assert cr.kernel_boot_findings(ok, {}, {}, present=True) == []
    assert cr.kernel_boot_findings([], {}, {"kernel_in_other_report": "demo-bsp"}, present=True) == []     # D-044：核心在另一份報告
