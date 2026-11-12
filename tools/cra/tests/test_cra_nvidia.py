"""cra_report.py 的 NVIDIA 安全公告（Jetson Linux）段落（風險評估 8.8 節）與 #105 複審的三點（附錄 A 的元件說明、版面說明不當成狀態理由、
英文單複數）。scan/nvidia-bulletins.json 由真的 nvidia_bulletins.match 產生：R39.2.1 的 Syft SBOM（tests/fixtures）＋預填的對照表。"""
import json
import lzma
import sys
from pathlib import Path

from test_cra_report import OK_STAGES, finding, kernel_scan, make_project, make_scan, run, write_json

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools" / "pilot" / "lib"))
import nvidia_bulletins as nb  # noqa: E402

TABLE = json.loads((ROOT / "tools" / "pilot" / "lib" / "nvidia-bulletins.json").read_text(encoding="utf-8"))
R39 = json.loads(lzma.open(ROOT / "tests" / "fixtures" / "jetson-r39.2.1-base.cdx.json.xz").read())


def fresh_mirror(table=TABLE):
    """mirror_state() 的形狀：鏡像裡正好是對照表上的公告（含 not_applicable），剛下載。"""
    bs = [{"id": b["id"], "year": b.get("year"), "title": b.get("title"), "current_release_date": b.get("current_release_date"),
           "selected": True} for b in table["bulletins"]]
    bs += [{"id": x["bulletin"], "current_release_date": x.get("current_release_date"), "selected": True} for x in table["not_applicable"]]
    return {"path": "/m", "ok": True, "reason": None, "commit": "6e340ebe15f405497868dcbdfb326c6d00d62b86",
            "fetched_utc": "2026-11-02T00:52:56Z", "age_days": 0.1, "max_age_days": 7, "bulletins": bs}


def nv_scan(d, nvb, stages=None, findings=None):
    st, detail = nvb.get("status"), nvb.get("detail")
    sc = make_scan(d, findings=findings, stages={"C-nvidia-bulletins": st, **(stages or {})}) if findings is not None else \
        make_scan(d, stages={"C-nvidia-bulletins": st, **(stages or {})})
    write_json(d / "scan" / "nvidia-bulletins.json", nvb)
    return sc


def section_88(md):
    return md.split("### 8.8 NVIDIA security bulletins (Jetson Linux)")[1].split("\n## ")[0]


def test_r39_presumed_included_and_flash_called_out(tmp_path):
    st, detail, nvb = nb.match(R39, TABLE, fresh_mirror(), "nvidia-bulletins.json")
    assert st == "OK" and not nvb["findings"] and not nvb["needs_vendor_confirmation"]
    n = len(nvb["presumed_included"])
    assert n == len({(b["id"], c) for b in TABLE["bulletins"] for c in b["cves"]})    # 沒有公告列出 39，全部早於 2026-08-06（依公告×CVE）
    r, s, reports = run(make_project(tmp_path / "p"), nv_scan(tmp_path / "s", nvb))
    md = (reports / "risk-assessment.md").read_text(encoding="utf-8")
    sec = section_88(md)
    assert "NVIDIA Jetson Linux **39.2.1**" in sec and "release build date 2026-08-06" in sec
    assert "`C-nvidia-bulletins` is **OK**." in sec
    # 狀態是 OK，但「公告列了哪些版本線」取自未審核的列：一定要看得到
    assert (f"**Not reviewed by a person:** the release lines each advisory names are taken from table rows that have not been "
            f"reviewed by a person (reviewed_until: not set). This applies to {n} of the {n} entries") in sec
    assert "the later of first publication and last revision" in sec
    assert "| Table rows for Jetson Linux 39 | 0 (0 not reviewed) |" in sec
    assert "| Table reviewed until | not set (no bulletin has been reviewed yet) |" in sec
    assert "commit 6e340ebe15f4, downloaded 2026-11-02T00:52:56Z" in sec
    assert f"#### Presumed included – not confirmed by NVIDIA ({n})" in sec and "#### Needs confirmation from NVIDIA (0)" in sec
    assert "presumed to be included in the release; NVIDIA has not confirmed this" in sec and "Neither case means that the release is not affected" in sec
    assert "| CVE-2026-24154 | 5797 | 2026-03-31 | 35, 36, 38 |" in sec
    assert "**Not visible in the SBOM:**" in sec and "CVE-2025-23270" in sec.split("**Not visible in the SBOM:**")[1]
    assert "flash (not visible in the SBOM)" in sec
    nv = s["counts"]["nvidia_bulletins"]
    assert (nv["section"], nv["status"], nv["presumed_included"], nv["findings"]) == ("listed", "OK", n, 0)
    assert "C-nvidia-bulletins is" not in " ".join(s["documents"]["risk-assessment"]["detail"])


def test_reviewed_finding_joins_rows_with_source_nvidia(tmp_path):
    table = json.loads(json.dumps(TABLE))
    r0 = next(x for x in table["rows"] if x["cve"] == "CVE-2026-24154" and x["line"] == "36")
    r0.update(reviewed=True, reviewed_by="王小明", reviewed_at="2026-11-02")
    sbom = {"components": [{"name": "nvidia-l4t-core", "version": "36.4.3-20250101000000",
                            "purl": "pkg:deb/ubuntu/nvidia-l4t-core@36.4.3-20250101000000?arch=arm64"},
                           {"name": "nvidia-l4t-initrd", "version": "36.4.3-20250101000000",
                            "purl": "pkg:deb/ubuntu/nvidia-l4t-initrd@36.4.3-20250101000000?arch=arm64"}]}
    st, detail, nvb = nb.match(sbom, table, fresh_mirror(table), "t.json")
    assert st == "ATTENTION" and [f["vulnerability"]["vulnId"] for f in nvb["findings"]] == ["CVE-2026-24154"]
    r, s, reports = run(make_project(tmp_path / "p"), nv_scan(tmp_path / "s", nvb))
    md = (reports / "risk-assessment.md").read_text(encoding="utf-8")
    assert "NVIDIA:CVE-2026-24154" in md and "nvidia-l4t-initrd" in md
    _, base, _ = run(make_project(tmp_path / "p0"), make_scan(tmp_path / "s0"))
    assert s["counts"]["rows"] == base["counts"]["rows"] + 1
    assert s["counts"]["dt_only_rows"] == base["counts"]["dt_only_rows"]     # NVIDIA 的列不算「只有 DT」
    assert "Dependency-Track 9 vulnerability rows" in md          # 交叉核對只算 DT 的列
    sec = section_88(md)
    assert "#### NVIDIA findings (1)" in sec and "`nvidia-l4t-initrd` (root file system)" in sec
    assert "C-nvidia-bulletins is ATTENTION" in s["documents"]["risk-assessment"]["detail"]
    assert s["documents"]["risk-assessment"]["status"] != "OK"


def test_gap_reason_in_english_and_data_status(tmp_path):
    st, detail, nvb = nb.match(R39, TABLE, None, "nvidia-bulletins.json")
    assert st == "GAP"
    r, s, reports = run(make_project(tmp_path / "p"), nv_scan(tmp_path / "s", nvb))
    md = (reports / "risk-assessment.md").read_text(encoding="utf-8")
    assert "**Vulnerability data status (section 8): GAP**" in md
    assert "no NVIDIA bulletin mirror was configured" in section_88(md) and "`NVIDIA_BULLETINS_MIRROR`" in section_88(md)
    stale = dict(fresh_mirror(), ok=False, fetched_utc="2026-10-01T00:00:00Z", age_days=32.0, reason="過期")
    st, detail, nvb = nb.match(R39, TABLE, stale, "t.json")
    r, s, reports = run(make_project(tmp_path / "p2"), nv_scan(tmp_path / "s2", nvb))
    assert "out of date (downloaded 2026-10-01T00:00:00Z, 32.0 days ago; limit 7 days)" in (reports / "risk-assessment.md").read_text(encoding="utf-8")


def test_stage_without_result_file_is_not_assessed(tmp_path):
    r, s, reports = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s", stages={"C-nvidia-bulletins": "FAIL"}))
    sec = section_88((reports / "risk-assessment.md").read_text(encoding="utf-8"))
    assert "**Not assessed.**" in sec and s["counts"]["nvidia_bulletins"]["section"] == "not_assessed"


def test_non_jetson_output_has_no_nvidia_section(tmp_path):
    r, s, reports = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s"))
    md = (reports / "risk-assessment.md").read_text(encoding="utf-8")
    assert "NVIDIA security bulletins" not in md and "### 8.8 NVIDIA" not in md
    # 範本裡的 placeholder 是空字串：8.7 節之後直接是 VEX 小節（8.8），再接 9.（安全測試）
    assert "\n\n### 8.8 Vulnerability status (VEX) and release gate" in md and "\n\n## 9. Security testing" in md and s["counts"]["nvidia_bulletins"] == {"section": "not_applicable"}


def test_project_template_without_nvidia_section_warns(tmp_path):
    st, detail, nvb = nb.match(R39, TABLE, fresh_mirror(), "t.json")
    tpl = "{{ risk.data_status_detail }}\n{{ tables.p1 }}\n{{ text.kernel_section }}\n"
    r, s, reports = run(make_project(tmp_path / "p", templates={"risk-assessment": tpl}), nv_scan(tmp_path / "s", nvb))
    md = (reports / "risk-assessment.md").read_text(encoding="utf-8")
    assert any("text.nvidia_section" in w for w in s["config_warnings"])
    assert "Note (layout, does not affect the status): the project's risk-assessment template has no NVIDIA bulletin section" in md
    assert not any("Note (layout" in x for x in s["documents"]["risk-assessment"]["detail"])


# ---------- #105 複審 ----------

def test_main_tables_layout_note_and_accepted_component_text(tmp_path):
    tpl = "{{ risk.data_status_detail }}\n## P1\n{{ tables.p1 }}\n## ACC\n{{ tables.accepted }}\n"
    r, s, reports = run(make_project(tmp_path / "p", templates={"risk-assessment": tpl}), kernel_scan(tmp_path / "s"))
    md = (reports / "risk-assessment.md").read_text(encoding="utf-8")
    acc = md.split("## ACC")[1]
    assert "driver not built" in acc and "mapped from nvidia-l4t-kernel" in acc          # 附錄 A 也註明是對應來的核心元件
    assert "- Note (layout, does not affect the status): the project's risk-assessment template has no kernel section" in md
    assert not any("kernel section" in x for x in s["documents"]["risk-assessment"]["detail"])   # 不是狀態的理由


def test_english_plurals():
    assert (cr_plural(1, "row"), cr_plural(2, "row"), cr_plural(1, "advisory", "advisories"), cr_plural(0, "CVE")) == \
        ("1 row", "2 rows", "1 advisory", "0 CVEs")


def cr_plural(*a):
    from test_cra_report import cr
    return cr.plural(*a)


def test_single_kernel_row_wording(tmp_path):
    rpm = "pkg:rpm/redhat/kernel-core@" "5.14.0-427.el9?arch=x86_64"
    r, s, reports = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s", findings=[finding("kernel-core", "5.14.0-427.el9", "CVE-2025-0301",
                                                                                                    "NVD", "HIGH", purl=rpm)],
                                                                 stages={"C-kernel-coverage": "OK", **dict.fromkeys(OK_STAGES, "OK")}))
    md = (reports / "risk-assessment.md").read_text(encoding="utf-8")
    assert "1 vulnerability row is for the operating system kernel. It is counted" in md and "but is not listed" in md
    assert " 1 rows" not in md and "1 Dependency-Track rows" not in md


def test_g3_10_only_exploited_cve_is_a_bulletin_cve(tmp_path):
    """G3-10／M-2：唯一被利用的 CVE 是 NVIDIA 公告的 CVE（沒有 DT finding）→ 它是真正的 P1 列：P1 計數、8.4 節、風險表、
    出貨關卡與「必須判斷但未判斷」都算它；VEX 是自動的 in_triage（未判斷）；沒有「不在風險表」的警告；來源寫 EUVD，不寫 KEV。"""
    from test_cra_exploitation import SERVICES, cfg_of, ra_text, setup
    st, detail, nvb = nb.match(R39, TABLE, fresh_mirror(), "nvidia-bulletins.json")
    cve = nvb["presumed_included"][0]["cve"]
    euvd = {"stage": "C-euvd", "status": "OK", "cves": {cve: {"exploited": "yes", "kev_sources": ["cisa_kev"], "euvd_ids": ["EUVD-2026-1"]}}}
    plain = [finding("libplain1", "1.0-1", "CVE-2026-9104", "NVD", "LOW")]

    def go(name, with_euvd):
        proj, sc = setup(tmp_path, cfg=cfg_of(), findings=plain, evidence=None, services=SERVICES, anns=None,
                         euvd=euvd if with_euvd else None, name=name)
        write_json(sc / "scan" / "nvidia-bulletins.json", nvb)
        r, s, rep = run(proj, sc)
        assert s is not None, r.stdout + r.stderr
        return s, ra_text(rep)

    s0, t0 = go("p0", False)
    s, t = go("p1", True)
    assert s["counts"]["p1"] == s0["counts"]["p1"] + 1
    g = s["exploitation"]["gate"]
    assert g["p1"] == s0["exploitation"]["gate"]["p1"] + 1 and g["p1"] >= 1
    assert g["not_assessed"] == (s0["exploitation"]["gate"]["not_assessed"] or 0) + 1     # 自動 in_triage 不算判斷過
    p1 = t[t.index("### 8.4 P1"):t.index("### 8.5")]
    assert f"| {cve} |" in p1 and "EUVD (CISA KEV)" in p1 and "NVIDIA:" in p1
    assert "is not in the risk table" not in t
    assert not any(cve in d and "not in the risk table" in d for d in s["documents"]["risk-assessment"]["detail"])
    row = next(x for x in s["euvd"]["list"] if x["id"] == cve)
    assert row["tier"] == "p1" and row["kev"] is False and row["euvd"] == ["EUVD (CISA KEV)"]
    # 沒有 EUVD 的標示：不是 P1 的列
    assert cve not in s0.get("euvd", {}).get("not_in_table", [])
