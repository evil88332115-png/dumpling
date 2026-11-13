"""韌體 SBOM 的 Intel 微碼公告比對：
- intel_ucode_releases.py：releasenote.md 的解析（合成資料；含看不懂的段落、表格變形、空資料）、固定來源的 sha256 核對、輸出穩定性。
- fw_advisory.py：每一種比對結果、sha256 不符、CPUID／platform 邊界、revision 比較（十六進位、前導零）。
- x86_firmware.py：結果進 SBOM property 與 fw-inventory.md 的「公告比對」，資料表不能用時的 GAP。
- 進 repo 的資料表：與程式固定的 sha256、來源常數一致；抽幾筆對 Intel 原始 release notes 的內容（人工核對過的值）。
全部不連網。"""
import hashlib
import json
import re
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import fw_advisory as fa  # noqa: E402
import intel_ucode_releases as ur  # noqa: E402
import x86_firmware as xf  # noqa: E402
from cdx_schema import cdx_validator  # noqa: E402
from test_x86_firmware import spi_image  # noqa: E402

DATA = HERE.parent / "data" / "intel-microcode-releases.json"
TAG = "https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files/releases/tag/"
SA_URL = "https://www.intel.com/content/www/us/en/security-center/advisory/"
TBL = "| Processor      | Stepping | F-M-S/PI    | Old Ver  | New Ver  | Products\n|:---------------|:---------|:------------|:---------|:---------|:---------\n"


def release(tag, body, title=None):
    return f"# Release Notes\n## [{title or tag}]({TAG}{tag})\n\n{body}\n"


def notes(*rels):
    return "\n\n".join(rels)


# ---------- 解析器 ----------

def test_parse_release_sections_security_and_rows():
    text = notes(
        release("microcode-20240101", f"""### Purpose

- Security updates for [INTEL-SA-01001]({SA_URL}intel-sa-01001.html)
- Update for functional issues. Refer to [Spec](https://example.invalid/x) for details.
- Update for functional issues. Refer to [Long](https://example.invalid/x?a=1
b=2) for details.

### New Platforms

{TBL}| ABC            | A0       | 06-aa-01/01 |          | 00000010 | Core Foo

### Updated Platforms

{TBL}| ABC            | B0       | 06-bb-02/E0 | 000000A0 | 000000A2 | Core Bar
| ABC            | B0       | 06-bb-02/e0 | 000000A2 | 000000A4 | Core Bar

### Removed Platforms

None
"""),
        release("microcode-20230101", "### Purpose\n\n- Update for functional issues. Refer to x for details.\n\n### New Platforms\n\nNone\n"))
    p = ur.parse(text)
    assert p["unparsed"] == []
    r0, r1 = p["releases"]
    assert [r["tag"] for r in p["releases"]] == ["microcode-20240101", "microcode-20230101"]
    assert (r0["date"], r1["date"]) == ("2024-01-01", "2023-01-01")
    assert r0["security"] == [{"id": "INTEL-SA-01001", "how": "security"}] and r0["functional_updates"] == 2
    assert r0["new"] == [["06-aa-01", "01", "", "00000010", "ABC", "A0"]]
    assert r0["updated"] == [["06-bb-02", "e0", "000000a0", "000000a2", "ABC", "B0"], ["06-bb-02", "e0", "000000a2", "000000a4", "ABC", "B0"]]   # 十六進位轉小寫
    assert r0["removed"] == [] and r1["security"] == [] and r1["functional_updates"] == 1


@pytest.mark.parametrize("bullet,ids,how,na", [
    (f"Security updates for [INTEL-SA-01379]({SA_URL}intel-sa-01379.html)", ["INTEL-SA-01379"], "security", False),
    (f"Security updates for [INTEL-SA-INTEL-SA-00972]({SA_URL}intel-sa-00972.html)", ["INTEL-SA-00972"], "security", False),     # 重複前綴
    (f"Security updates for [INTEL-SA-000617]({SA_URL}intel-sa-00617.html)", ["INTEL-SA-00617"], "security", False),             # 六位數
    (f"Updated security updates for INTEL-SA-01083 originally published on Aug 13, 2024 [INTEL-SA-01083]({SA_URL}INTEL-SA-01083.html)",
     ["INTEL-SA-01083"], "updated", False),
    ("Update to SA00270.", ["INTEL-SA-00270"], "update-to", False),                                                           # 沒有前綴
    ("Security updates for [INTEL-SA-NA]", [], "security", True),
    (f"Security updates for [INTEL-SA-01001]({SA_URL}intel-sa-01001.html).", ["INTEL-SA-01001"], "security", False),         # 句點結尾
])
def test_security_bullet_forms(bullet, ids, how, na):
    assert ur.security_bullet(bullet) == (how, ids, na)


def test_non_security_bullets_are_not_security():
    for b in ("Update for functional issues. Refer to INTEL-SA-99999 for details.", "Removed TGL/06-8c-01/80 due to functional issues",
              "Revert to previous versions due to reported system hang."):
        assert ur.security_bullet(b) is None


def test_parse_records_what_it_does_not_understand():
    text = release("microcode-2024xxxx", f"""### Purpose

- Security updates for [INTEL-SA-01001]({SA_URL}intel-sa-01002.html)
- Security updates for something without a number
- Something nobody planned for
- Update for functional issues. Refer to x for details.
# Note: INTEL-SA-01003 will be published later
Free text under purpose.

### Odd Heading

| Processor | Stepping | F-M-S/PI | Old Ver | New Ver | Products
|:--|:--|:--|:--|:--|:--
| ABC | A0 | 06-aa-01/01 | | 00000010 | x

### Updated Platforms0

{TBL}| ABC | B0 | 06-bb-02/e0 | 000000a0 | 000000a2
| ABC | B0 | 06-bb | 000000a0 | 000000a2 | x
| ABC | B0 | 06-bb-02/e0 | 0000a0 | 000000a2 | x
| ABC | B0 | 06-bb-02/e0 | 000000a0 | | x
| | B0 | 06-bb-02/e0 | 000000a0 | 000000a2 | x
| ABC | B0 | 06-bb-03/e0 | 000000a0 | 000000a2 | x
stray text in a table section

### Removed Platforms

{TBL}| ABC | B0 | 06-bb-04/e0 | 000000a0 | 000000a1 | x
""")
    p = ur.parse(text)
    r = p["releases"][0]
    assert r["date"] is None and r["security"][0]["id"] == "INTEL-SA-01001"       # 沒有日期的 tag 照記、標原因
    whys = "\n".join(u["why"] for u in p["unparsed"])
    for expect in ("沒有日期", "連結網址的編號不同", "讀不到 INTEL-SA 編號", "多了尾碼", "不認得的小標題", "有 5 欄", "不是 FF-MM-SS/PI",
                   "不是 8 位十六進位", "沒有 New Ver", "沒有 Processor 欄", "表格區段裡的非表格文字", "Purpose 裡的非項目文字", "Removed Platforms 的 New Ver 不是空的"):
        assert expect in whys, expect
    assert any("Something nobody planned for" in x for x in r["purpose_other"])          # 沒分類的項目原文保留
    assert any(u["text"].startswith("# Note: INTEL-SA-01003") for u in p["unparsed"]) and r["security"] == [{"id": "INTEL-SA-01001", "how": "security"}]   # 備註不算公告
    assert r["updated"] == [["06-bb-03", "e0", "000000a0", "000000a2", "ABC", "B0"]]    # 只有完整的列才收
    assert [u["section"] for u in p["unparsed"] if "不認得的小標題" in u["why"]] == [None]
    assert r["new"] == []                                                              # 不認得的小標題底下的表格不當成資料
    assert all(u["release"] == "microcode-2024xxxx" for u in p["unparsed"])
    assert [x["line"] for x in p["unparsed"]] == sorted(x["line"] for x in p["unparsed"])


def test_parse_heading_title_differs_from_tag_url_and_extra_headings():
    p = ur.parse(release("microcode-20220207", "### Purpose\n\n- Update for functional issues. x\n", title="microcode-2022027"))
    r = p["releases"][0]
    assert r["tag"] == "microcode-20220207" and r["heading"] == "microcode-2022027" and r["date"] == "2022-02-07"
    p = ur.parse(release("microcode-20240813", "## Update: Corrected the MCU file for 06-a5-03\n\n### Purpose\n\n- Update for functional issues. x\n"))
    assert p["releases"][0]["other"] == ["Update: Corrected the MCU file for 06-a5-03"] and p["unparsed"] == []
    p = ur.parse(release("microcode-20230512-rev2", "### Purpose\n") + release("microcode-20190514a", "### Purpose\n"))
    assert [r["date"] for r in p["releases"]] == ["2023-05-12", "2019-05-14"]


def test_parse_disclosure_table_and_text_removal_and_history():
    text = release("microcode-20260812", "### Purpose\n\n- Removed MTL/06-aa-04/c0 due to functional issues observed when loading the MCU.\n") + release(
        "microcode-20241112", f"""### Purpose

- Update for functional issues. x

### New Disclosures Updated in Prior Releases

{TBL}| ICL-D          | B0       | 06-6c-01/10 | 010002b0 | N/A      | Xeon D
| ICX-SP         | Dx/M1    | 06-6a-06/87 | 0d0003e7 | n/a      | Xeon

### Removed Platforms

{TBL}| SNR            | B0       | 06-86-04/01 | 0b00000f |          | Atom

### Change History
Corrected names.
""")
    p = ur.parse(text)
    a, b = p["releases"]
    assert a["removed"] == [["06-aa-04", "c0", "", "", "MTL", ""]]                                       # 只有文字的移除
    assert b["disclosed"][0] == ["06-6c-01", "10", "010002b0", "N/A", "ICL-D", "B0"] and b["disclosed"][1][3] == "N/A"
    assert b["removed"] == [["06-86-04", "01", "0b00000f", "", "SNR", "B0"]] and b["other"] == ["Corrected names."]
    assert b["updated"] == [] and p["unparsed"] == []
    # 表格已經有同一個 F-M-S／PI 就不重複補
    q = ur.parse(release("microcode-20260812", f"### Purpose\n\n- Removed TGL/06-8c-01/80 due to x\n\n### Removed Platforms\n\n{TBL}| TGL | B1 | 06-8c-01/80 | 00000068 | | y\n"))
    assert q["releases"][0]["removed"] == [["06-8c-01", "80", "00000068", "", "TGL", "B1"]]


def test_parse_empty_and_broken_inputs():
    with pytest.raises(ur.GenError):
        ur.parse("")
    with pytest.raises(ur.GenError):
        ur.parse("# Release Notes\nnothing here\n")
    p = ur.parse("intro text\n" + release("microcode-20240101", "### Purpose\n"))
    assert [u["why"] for u in p["unparsed"]] == ["第一個 release 標題之前的內容"]
    with pytest.raises(ur.GenError, match="重複"):
        ur.parse(release("microcode-20240101", "") + release("microcode-20240101", ""))
    p = ur.parse(release("microcode-20240101", f"{TBL}| ABC | A0 | 06-aa-01/01 | | 00000010 | x\n"))        # 區段之前的表格
    assert p["releases"][0]["new"] == [] and "不在" in p["unparsed"][0]["why"]
    p = ur.parse(release("microcode-20240101", "### New Platforms\n\n| ABC | A0 | 06-aa-01/01 | | 00000010 | x\n"))   # 沒有表頭
    assert p["releases"][0]["new"] == [] and "沒有認得的表頭" in p["unparsed"][0]["why"]
    p = ur.parse(release("microcode-20240101", "### Updated Platforms\n\n" + TBL))                       # 空表
    assert p["releases"][0]["updated"] == [] and p["unparsed"] == []
    with pytest.raises(ur.GenError, match="行數"):
        ur.parse("\n" * (ur.MAX_LINES + 1))


def test_order_check_and_tag_dates():
    rel = [{"tag": "microcode-20230101", "date": "2023-01-01"}, {"tag": "microcode-20240101", "date": "2024-01-01"}, {"tag": "x", "date": None}]
    assert "順序" in ur.check_order(rel)[0] and ur.check_order(rel[1:2] + rel[:1]) == []
    for tag, date in (("microcode-20230512-rev2", "2023-05-12"), ("microcode-20190514a", "2019-05-14"), ("microcode-2022027", None),
                      ("microcode-20231301", None), ("microcode-20230099", None), ("other-20230101", None)):
        assert ur.tag_date(tag) == date


def test_dump_collapses_rows_and_is_stable():
    doc = {"a": [1, 2], "rows": [["06-aa-01", "01", "", "00000010", "ABC", "A0"]], "s": {"k": [["x", "y"]]}}
    out = ur.dump(doc)
    assert '"rows": [\n  ["06-aa-01", "01", "", "00000010", "ABC", "A0"]\n ]' in out and json.loads(out) == doc and out == ur.dump(doc)


def test_read_source_pins_sha256_and_size(tmp_path, monkeypatch):
    f = tmp_path / "releasenote.md"
    f.write_text("# Release Notes\n", encoding="utf-8")
    with pytest.raises(ur.GenError, match="sha256"):
        ur.read_source(f)
    monkeypatch.setattr(ur, "SOURCE_SHA256", hashlib.sha256(f.read_bytes()).hexdigest())
    monkeypatch.setattr(ur, "SOURCE_BYTES", f.stat().st_size)
    assert ur.read_source(f) == "# Release Notes\n"
    link = tmp_path / "link.md"
    link.symlink_to(f)
    with pytest.raises(ur.GenError, match="一般檔案"):
        ur.read_source(link)
    with pytest.raises(ur.GenError):
        ur.read_source(tmp_path / "missing.md")
    f.write_bytes(b"\xff\xfe# Release Notes\n")
    monkeypatch.setattr(ur, "SOURCE_SHA256", hashlib.sha256(f.read_bytes()).hexdigest())
    monkeypatch.setattr(ur, "SOURCE_BYTES", f.stat().st_size)
    with pytest.raises(ur.GenError, match="UTF-8"):
        ur.read_source(f)
    monkeypatch.setattr(ur, "MAX_BYTES", 3)
    with pytest.raises(ur.GenError, match="上限"):
        ur.read_source(f)


def test_generate_and_verify_cli_reproduce_the_table(tmp_path, monkeypatch, capsys):
    src = tmp_path / "releasenote.md"
    src.write_text(notes(release("microcode-20240101", f"### Purpose\n\n- Security updates for [INTEL-SA-01001]({SA_URL}intel-sa-01001.html)\n\n### Updated Platforms\n\n{TBL}| ABC | B0 | 06-bb-02/e0 | 000000a0 | 000000a2 | x\n")), encoding="utf-8")
    monkeypatch.setattr(ur, "SOURCE_SHA256", hashlib.sha256(src.read_bytes()).hexdigest())
    monkeypatch.setattr(ur, "SOURCE_BYTES", src.stat().st_size)
    out = tmp_path / "t.json"
    assert ur.main(["generate", "--source", str(src), "--out", str(out), "--generated-at", "2026-01-01T00:00:00Z"]) == 0
    first = out.read_bytes()
    doc = json.loads(first)
    assert doc["schema"] == ur.SCHEMA and doc["generated_at"] == "2026-01-01T00:00:00Z" and doc["source"]["commit"] == ur.COMMIT
    assert doc["coverage"] == {"releases": 1, "newest": "microcode-20240101", "oldest": "microcode-20240101",
                               "rows": {"new": 0, "updated": 1, "removed": 0, "disclosed": 0}}
    assert ur.main(["generate", "--source", str(src), "--out", str(out), "--generated-at", "2026-01-01T00:00:00Z"]) == 0
    assert out.read_bytes() == first                                                       # 同一個來源 → 位元組相同
    assert ur.main(["verify", "--source", str(src), "--table", str(out)]) == 0
    doc["releases"][0]["updated"][0][3] = "000000ff"                                         # 改一個值 → verify 失敗
    out.write_text(json.dumps(doc), encoding="utf-8")
    assert ur.main(["verify", "--source", str(src), "--table", str(out)]) == 1
    src.write_text("changed", encoding="utf-8")                                                # 來源 sha256 不符 → 不產生
    out.unlink()
    assert ur.main(["generate", "--source", str(src), "--out", str(out)]) == 1 and not out.exists()
    assert "INTEL-UCODE-RELEASES\tFAIL" in capsys.readouterr().out


# ---------- 比對 ----------

def rel(tag, sa=(), new=(), updated=(), removed=(), disclosed=(), how="security"):
    def rows(x):
        return [[f, p, o, n, "PROC", "A0"] for f, p, o, n in x]
    return {"tag": tag, "date": None, "security": [{"id": s, "how": how} for s in sa], "security_na": False, "functional_updates": 0,
            "purpose_other": [], "other": [], "new": rows(new), "updated": rows(updated), "removed": rows(removed), "disclosed": rows(disclosed)}


def mk_table(*releases, sha="a" * 64):
    doc = {"schema": fa.SCHEMA, "source": {"repo": "https://github.com/intel/x", "tag": "microcode-30000101", "commit": "b" * 40,
                                            "path": "releasenote.md", "sha256": "c" * 64}, "releases": list(releases)}
    fa.validate(doc)
    return fa.Table(doc, sha)


FMS = "06-ba-02"                       # CPUID 000B06A2
CPU = "000B06A2"


def ucode(rev="0x10", pf="0xE0", cpuid=CPU, ext=()):
    return {"cpuid": cpuid, "platform_id": pf, "revision": rev, "extended_signatures": [{"cpuid": c, "platform_id": p} for c, p in ext]}


TABLE = mk_table(
    rel("microcode-20240301", sa=["INTEL-SA-00003"], updated=[(FMS, "e0", "00000030", "00000040")]),
    rel("microcode-20240201", updated=[(FMS, "e0", "00000020", "00000030")]),
    rel("microcode-20240101", sa=["INTEL-SA-00002", "INTEL-SA-00001"], how="security", updated=[(FMS, "e0", "00000010", "00000020")]),
    rel("microcode-20231201", sa=["INTEL-SA-00001"], new=[(FMS, "e0", "", "00000010")], updated=[("06-cc-01", "01", "00000001", "00000002")]),
)


def test_fms_of_cpuid():
    for cpuid, fms in (("000806EC", "06-8e-0c"), ("000a0671", "06-a7-01"), ("000906EA", "06-9e-0a"), ("00050654", "06-55-04"),
                       ("000306A9", "06-3a-09"), ("000B06A2", "06-ba-02"), ("00000F41", "0f-04-01"), ("00100F41", "10-04-01")):
        assert fa.fms_of(cpuid) == fms
    for bad in (None, "", "806EC", "000806EC0", "0x0806EC", "ZZZZZZZZ", 806, "000806EC "):
        assert fa.fms_of(bad) is None


def test_revision_and_platform_parsing():
    assert fa.rev_value("0xF8") == fa.rev_value("0xf8") == fa.rev_value("0X0F8") == fa.rev_value("0x000000F8") == 0xF8
    assert fa.rev_value("0x9") < fa.rev_value("0x10") < fa.rev_value("0xA0") < fa.rev_value("0x100")          # 數值比較，不是字串
    assert fa.rev_value("0xFFFFFFFF") == 0xFFFFFFFF
    for bad in (None, "", "F8", "0x", "0xG1", "0x1FFFFFFFF", "-0x1", "0xF8 ", 248):
        assert fa.rev_value(bad) is None
    assert fa.pf_value("0x94") == "94" and fa.pf_value("0X4") == "04" and fa.pf_value("0xE0") == "e0"
    for bad in (None, "", "94", "0x094", "0x", "0xZZ", 0x94):
        assert fa.pf_value(bad) is None


def test_affected_candidate_lists_newer_releases_security_union_and_caveat():
    r = fa.match_signature(TABLE, CPU, "0xE0", "0x10")
    assert r["match"] == "affected-candidate" and r["reason"] is None
    assert [c["id"] for c in r["candidates"]] == ["INTEL-SA-00001", "INTEL-SA-00002", "INTEL-SA-00003"]
    assert r["releases"] == ["microcode-20240101", "microcode-20240201", "microcode-20240301"]
    assert r["candidates"][0]["releases"] == ["microcode-20240101"] and r["candidates"][0]["how"] == ["security"]      # 0x10 自己的 release（20231201）不列
    assert (r["latest_revision"], r["latest_release"]) == ("0x00000040", "microcode-20240301")
    assert "listed in the table" in r["basis"] and "not per CPUID" in r["basis"] and "not confirmed findings" in r["basis"]
    mid = fa.match_signature(TABLE, CPU, "0xE0", "0x30")
    assert mid["match"] == "affected-candidate" and [c["id"] for c in mid["candidates"]] == ["INTEL-SA-00003"]
    assert mid["releases"] == ["microcode-20240301"]


def test_revision_in_between_or_older_than_the_table_is_still_candidates_with_a_note():
    r = fa.match_signature(TABLE, CPU, "0xE0", "0x15")                                   # 表裡沒有 0x15（BIOS 專用／OEM revision）
    assert r["match"] == "affected-candidate" and "not listed in the table" in r["basis"]
    assert r["releases"] == ["microcode-20240101", "microcode-20240201", "microcode-20240301"]
    r = fa.match_signature(TABLE, CPU, "0xE0", "0x1")                                    # 比表裡最舊的還舊
    assert r["match"] == "affected-candidate" and "not listed in the table" in r["basis"] and "table covers" in r["basis"]
    assert [c["id"] for c in r["candidates"]] == ["INTEL-SA-00001", "INTEL-SA-00002", "INTEL-SA-00003"]


def test_older_but_no_advisory_in_newer_releases():
    t = mk_table(rel("microcode-20240201", updated=[(FMS, "e0", "00000010", "00000020")]), rel("microcode-20240101", sa=["INTEL-SA-00001"], new=[(FMS, "e0", "", "00000010")]))
    r = fa.match_signature(t, CPU, "0xE0", "0x10")
    assert r["match"] == "older-no-sa" and r["candidates"] == [] and r["releases"] == ["microcode-20240201"]
    assert "none of the newer releases lists an INTEL-SA" in r["basis"] and "does not mean there are no vulnerabilities" in r["basis"]


def test_up_to_date_is_not_a_clean_bill():
    for rev in ("0x40", "0x00000040", "0X040"):
        r = fa.match_signature(TABLE, CPU, "0xE0", rev)
        assert r["match"] == "up-to-date" and r["candidates"] == [] and r["releases"] == []
        assert "no newer revision in the table" in r["basis"] and "does not mean there are no vulnerabilities" in r["basis"]
        assert r["latest_release"] == "microcode-20240301"


def test_revision_newer_than_table_is_not_assessed():
    r = fa.match_signature(TABLE, CPU, "0xE0", "0x41")
    assert r["match"] == "NOT_ASSESSED" and r["reason"] == "revision-newer-than-table" and "BIOS-only/OEM" in r["basis"]
    assert r["basis"].endswith(fa.NO_DATA) and r["latest_revision"] == "0x00000040"


def test_cpuid_and_platform_boundaries():
    r = fa.match_signature(TABLE, "000B06A3", "0xE0", "0x10")                              # F-M-S 06-ba-03 不在表裡
    assert r["match"] == "NOT_ASSESSED" and r["reason"] == "cpuid-not-in-table" and r["basis"].endswith(fa.NO_DATA)
    r = fa.match_signature(TABLE, CPU, "0x80", "0x10")                                      # CPUID 對到、platform 不同
    assert r["match"] == "NOT_ASSESSED" and r["reason"] == "platform-mismatch" and "only with platform mask(s) e0" in r["basis"]
    r = fa.match_signature(TABLE, CPU, "0xE1", "0x10")                                      # 遮罩要完全相同，不猜子集
    assert r["match"] == "NOT_ASSESSED" and r["reason"] == "platform-mismatch"
    assert fa.match_signature(TABLE, CPU, "0x0E0", "0x10")["reason"] == "platform-unreadable"
    assert fa.match_signature(TABLE, CPU, "0xE0", "F8")["reason"] == "revision-unreadable"
    assert fa.match_signature(TABLE, CPU, "0xE0", None)["reason"] == "revision-unreadable"
    assert fa.match_signature(TABLE, "12345", "0xE0", "0x10")["reason"] == "bad-cpuid"


def test_removed_ambiguous_and_disclosure_only_signatures_are_not_assessed():
    t = mk_table(rel("microcode-20240201", removed=[(FMS, "e0", "00000010", "")]), rel("microcode-20240101", sa=["INTEL-SA-00001"], new=[(FMS, "e0", "", "00000010")]))
    r = fa.match_signature(t, CPU, "0xE0", "0x10")
    assert r["match"] == "NOT_ASSESSED" and r["reason"] == "removed" and "microcode-20240201" in r["basis"]
    # 移除之後又出現新的 revision：以新的為準
    t = mk_table(rel("microcode-20240301", updated=[(FMS, "e0", "", "00000020")]), rel("microcode-20240201", removed=[(FMS, "e0", "00000010", "")]),
                 rel("microcode-20240101", new=[(FMS, "e0", "", "00000010")]))
    assert fa.match_signature(t, CPU, "0xE0", "0x10")["match"] in ("affected-candidate", "older-no-sa")
    t = mk_table(rel("microcode-20240101", updated=[(FMS, "e0", "00000010", "00000020"), (FMS, "e0", "00000011", "00000021")]))
    r = fa.match_signature(t, CPU, "0xE0", "0x10")
    assert r["match"] == "NOT_ASSESSED" and r["reason"] == "ambiguous" and "00000020" in r["basis"]
    t = mk_table(rel("microcode-20240101", disclosed=[(FMS, "e0", "00000010", "N/A")]))
    r = fa.match_signature(t, CPU, "0xE0", "0x10")
    assert r["match"] == "NOT_ASSESSED" and r["reason"] == "no-revision-history"


def test_reverted_revision_and_disclosure_note():
    t = mk_table(rel("microcode-20240201", updated=[(FMS, "e0", "00000020", "00000018")]),                        # 復原
                 rel("microcode-20240101", sa=["INTEL-SA-00001"], updated=[(FMS, "e0", "00000010", "00000020")]),
                 rel("microcode-20231201", disclosed=[(FMS, "e0", "00000010", "N/A")], sa=["INTEL-SA-00009"]))
    assert fa.match_signature(t, CPU, "0xE0", "0x18")["match"] == "up-to-date"
    assert fa.match_signature(t, CPU, "0xE0", "0x20")["reason"] == "revision-newer-than-table"                       # 被復原掉的版本：不猜
    r = fa.match_signature(t, CPU, "0xE0", "0x10")
    assert r["match"] == "affected-candidate" and r["releases"] == ["microcode-20240101", "microcode-20240201"]
    assert any("New Disclosures" in n and "INTEL-SA-00009" in n for n in r["notes"])


def test_updated_security_updates_keep_their_kind():
    t = mk_table(rel("microcode-20240101", sa=["INTEL-SA-00005"], how="updated", updated=[(FMS, "e0", "00000010", "00000020")]))
    assert fa.match_signature(t, CPU, "0xE0", "0x10")["candidates"][0]["how"] == ["updated"]


def test_extended_signatures_are_each_assessed_and_merged():
    t = mk_table(rel("microcode-20240101", sa=["INTEL-SA-00001"], updated=[(FMS, "e0", "00000010", "00000020"), ("06-bb-01", "01", "00000010", "00000020")]))
    only = fa.match_microcode(t, ucode("0x20"))
    assert only["match"] == "up-to-date" and len(only["signatures"]) == 1 and only["source"].startswith("intel/x ")
    mixed = fa.match_microcode(t, ucode("0x20", ext=[("000B06B1", "0x01"), ("000B06A2", "0xE0")]))           # 重複的 signature 只算一次
    assert [s["match"] for s in mixed["signatures"]] == ["up-to-date", "up-to-date"] and mixed["match"] == "up-to-date"
    notin = fa.match_microcode(t, ucode("0x20", ext=[("000B0699", "0x01")]))
    assert notin["match"] == "NOT_ASSESSED" and [s["match"] for s in notin["signatures"]] == ["up-to-date", "NOT_ASSESSED"]       # 有一個比不到就不能寫 up-to-date
    cand = fa.match_microcode(t, ucode("0x10", ext=[("000B0699", "0x01")]))
    assert cand["match"] == "affected-candidate" and [c["id"] for c in cand["candidates"]] == ["INTEL-SA-00001"] and "[000B06A2/0xE0]" in cand["basis"]


def test_counts_and_no_clean_wording_anywhere():
    results = [fa.match_microcode(TABLE, ucode(r)) for r in ("0x10", "0x40", "0x41", "0x20")]
    assert fa.counts(results) == {"affected-candidate": 2, "up-to-date": 1, "NOT_ASSESSED": 1}
    for r in results:
        text = r["basis"].lower()
        assert "not affected" not in text and "unaffected" not in text and "no vulnerabilities" not in text.replace("does not mean there are no vulnerabilities", "")
        assert "safe" not in text and "secure" not in text and "pass" not in text


# ---------- 資料表載入、sha256 ----------

def table_file(tmp_path, doc=None, raw=None):
    p = tmp_path / "t.json"
    data = raw if raw is not None else json.dumps(doc if doc is not None else {"schema": fa.SCHEMA, "source": {"repo": "r", "tag": "t", "commit": "c", "path": "p", "sha256": "s"},
                                                                         "releases": [rel("microcode-20240101", updated=[(FMS, "e0", "00000010", "00000020")])]}).encode()
    p.write_bytes(data)
    return p, hashlib.sha256(data).hexdigest()


def test_load_checks_sha256_and_structure(tmp_path):
    p, sha = table_file(tmp_path)
    assert fa.load(p, sha).sha256 == sha
    with pytest.raises(fa.TableError) as e:
        fa.load(p, "0" * 64)
    assert e.value.reason == "table-sha-mismatch"
    r = fa.match_microcode(e.value, ucode("0x10"))                                                           # 資料表不能用 → NOT_ASSESSED（GAP），不是「沒有候選」
    assert r["match"] == "NOT_ASSESSED" and r["reason"] == "table-sha-mismatch" and r["basis"].endswith(fa.NO_DATA) and r["candidates"] == [] and r["source"] is None
    for name, kw in (("not json", {"raw": b"{not json"}), ("not utf-8", {"raw": b"\xff\xfe"}), ("array", {"raw": b"[]"}),
                     ("wrong schema", {"doc": {"schema": "x", "source": {}, "releases": []}})):
        p2, sha2 = table_file(tmp_path, **kw)
        with pytest.raises(fa.TableError) as e:
            fa.load(p2, sha2)
        assert e.value.reason == "table-unreadable", name


@pytest.mark.parametrize("mutate", [
    lambda d: d["releases"].clear(),
    lambda d: d["releases"][0].update(tag="bad tag"),
    lambda d: d["releases"].append(dict(d["releases"][0])),                                                    # 重複 tag
    lambda d: d["releases"][0].update(security=[{"id": "INTEL-SA-1"}]),
    lambda d: d["releases"][0].update(updated=[["06-ba-02", "e0", "00000010"]]),                               # 欄數
    lambda d: d["releases"][0].update(updated=[["06-ba-02", "e0", "00000010", "0x20", "P", "A"]]),            # 版本格式
    lambda d: d["releases"][0].update(updated=[["06-BA-02", "e0", "00000010", "00000020", "P", "A"]]),        # 要小寫
    lambda d: d["releases"][0].update(updated=[["06-ba-02", "e0", "00000010", "", "P", "A"]]),               # updated 沒有 New Ver
    lambda d: d["releases"][0].pop("removed"),
    lambda d: d.pop("source"),
])
def test_validate_rejects_a_damaged_table(tmp_path, mutate):
    doc = {"schema": fa.SCHEMA, "source": {"repo": "r", "tag": "t", "commit": "c", "path": "p", "sha256": "s"},
           "releases": [rel("microcode-20240101", updated=[(FMS, "e0", "00000010", "00000020")])]}
    mutate(doc)
    p, sha = table_file(tmp_path, doc)
    with pytest.raises(fa.TableError) as e:
        fa.load(p, sha)
    assert e.value.reason == "table-unreadable"


def test_load_rejects_missing_symlink_and_oversized(tmp_path, monkeypatch):
    with pytest.raises(fa.TableError, match="not a regular file"):
        fa.load(tmp_path / "missing.json", "0" * 64)
    p, sha = table_file(tmp_path)
    link = tmp_path / "l.json"
    link.symlink_to(p)
    with pytest.raises(fa.TableError, match="not a regular file"):
        fa.load(link, sha)
    monkeypatch.setattr(fa, "MAX_TABLE", 10)
    with pytest.raises(fa.TableError, match="larger than limit"):
        fa.load(p, sha)


# ---------- 進 repo 的資料表 ----------

def test_committed_table_matches_pinned_sha256_and_generator_constants():
    t = fa.load()                                                                                            # 用程式固定的 sha256 載入
    assert hashlib.sha256(DATA.read_bytes()).hexdigest() == fa.TABLE_SHA256 == t.sha256
    s = t.source
    assert (s["repo"], s["tag"], s["commit"], s["path"], s["sha256"]) == (ur.REPO_URL, ur.TAG, ur.COMMIT, ur.PATH, ur.SOURCE_SHA256)
    assert s["url"] == ur.RAW_URL and ur.COMMIT in ur.RAW_URL and re.fullmatch(r"[0-9a-f]{40}", ur.COMMIT) and s["bytes"] == ur.SOURCE_BYTES
    doc = t.doc
    assert doc["generator"] == "tools/cra/intel_ucode_releases.py" and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", doc["generated_at"])
    assert doc["coverage"]["releases"] == len(doc["releases"]) == 45 and doc["coverage"]["newest"] == ur.TAG and doc["coverage"]["oldest"] == "microcode-20190312"
    assert [u["why"] for u in doc["unparsed"]] == ["表格區段裡的非表格文字", "Purpose 裡的非項目文字，原文記在 other", "小標題 `Updated Platforms0` 多了尾碼，當成 `Updated Platforms` 讀"] or \
        len(doc["unparsed"]) == 3                                                                          # 看不懂的段落都記著（目前 3 處），不是 0 也不是被吞掉
    assert doc["unparsed"], "unparsed 不該是空的：來源有看不懂的段落"


def test_committed_table_spot_checks_against_intel_release_notes():
    """人工對 Intel 原始 releasenote.md 核對過的值（commit d71fe4e2 的 releasenote.md）。"""
    t = fa.load()
    ev = {(e[4], e[1]): (e[2], e[3]) for e in t.events[("06-8e-0c", "94")]}                                 # AML/CML-Y42/WHL-U V0（Protectli 的 000806EC／0x94）
    assert ev[("microcode-20230808", "updated")] == ("000000f6", "000000f8") and ev[("microcode-20250512", "updated")] == ("000000fc", "00000100")
    assert t.sa_by_tag["microcode-20230808"] == ["INTEL-SA-00828", "INTEL-SA-00836", "INTEL-SA-00837"]
    assert t.sa_by_tag["microcode-20250812"] == ["INTEL-SA-01249", "INTEL-SA-01308", "INTEL-SA-01310", "INTEL-SA-01311", "INTEL-SA-01313", "INTEL-SA-01367"]
    assert t.sa_by_tag["microcode-20240312"] == ["INTEL-SA-00972", "INTEL-SA-00982", "INTEL-SA-00898", "INTEL-SA-00960", "INTEL-SA-01045"]
    assert t.sa_by_tag["microcode-20220510"] == ["INTEL-SA-00617"] and t.sa_by_tag["microcode-20230512"] == []                   # INTEL-SA-NA 不是公告
    assert ("microcode-20210608", "new") in {(e[4], e[1]) for e in t.events[("06-8c-02", "c2")]} and t.events[("06-aa-04", "c0")][0][1] == "removed"
    assert {e[4]: e[3] for e in t.events[("06-aa-04", "e6")] if e[1] == "updated"}["microcode-20260925"] == "0000002b"
    r = fa.match_signature(t, "000806EC", "0x94", "0xF8")
    assert r["match"] == "affected-candidate" and r["releases"] == ["microcode-20240312", "microcode-20240813", "microcode-20250512"]
    assert fa.match_signature(t, "000806C1", "0x80", "0xBE")["match"] == "up-to-date"
    assert fa.match_signature(t, "000806C1", "0x80", "0xBF")["reason"] == "revision-newer-than-table"


# ---------- x86_firmware.py：SBOM、報告、GAP ----------

def sbom_with(tmp_path, advisory):
    p = tmp_path / "in.bin"
    p.write_bytes(spi_image())
    inv = xf.inventory([p], advisory=advisory)
    st, detail = xf.status_of(inv)
    inv["status"], inv["detail"] = st, detail
    comps, deps = xf.components(inv)
    doc = xf.bom(comps, deps)
    assert not list(cdx_validator().iter_errors(doc))
    return inv, comps, xf.markdown(inv)


def props(c, name):
    return [p["value"] for p in c["properties"] if p["name"] == name]


def test_sbom_properties_and_report_section(tmp_path):
    # spi_image：CPUID 000B06A2／pf 0xE0／revision 0x4121（06-ba-02），000B0671／pf 0x32／revision 0x123（06-b7-01）
    t = mk_table(rel("microcode-20240101", sa=["INTEL-SA-00001"], updated=[(FMS, "e0", "00004121", "00004130")]))
    inv, comps, md = sbom_with(tmp_path, t)
    by = {c["name"]: c for c in comps if c["name"].startswith("Intel CPU microcode")}
    a, b = by["Intel CPU microcode 000B06A2"], by["Intel CPU microcode 000B0671"]
    assert props(a, "dumpling:advisory-match") == ["affected-candidate"] and props(a, "dumpling:advisory-candidates") == ["INTEL-SA-00001"]
    assert "microcode-20240101" in props(a, "dumpling:advisory-basis")[0] and props(a, "dumpling:advisory-latest-revision") == ["0x00004130 (microcode-20240101)"]
    assert "commit bbbbbbbbbbbb" in props(a, "dumpling:advisory-source")[0]
    assert props(b, "dumpling:advisory-match") == ["NOT_ASSESSED"] and not props(b, "dumpling:advisory-candidates") and "no data in the database" in props(b, "dumpling:advisory-basis")[0]
    for c in (a, b):                                                                                          # 狀態仍是 NOT_ASSESSED；不出現任何「沒有漏洞」的值
        assert props(c, "dumpling:vuln-assessment") == ["NOT_ASSESSED"] and props(c, "dumpling:vuln-assessment-note") == [xf.ASSESS_NOTES["intel-microcode"]]
    me = next(c for c in comps if c["name"] == "Intel CSE firmware")
    assert props(me, "dumpling:advisory-match") == ["NOT_ASSESSED"] and "cpe" in me
    assert inv["advisory"]["status"] == "OK" and inv["advisory"]["counts"] == {"affected-candidate": 1, "NOT_ASSESSED": 1}
    assert inv["advisory"]["source"]["commit"] == "b" * 40 and inv["advisory"]["source"]["table_sha256"] == "a" * 64
    sec = md[md.index("## 公告比對"):]
    assert sec.count("## 公告比對") == 1 and "affected-candidate" in sec and "INTEL-SA-00001" in sec and "資料庫沒有資料，以廠商公告為準" in sec
    assert "不一定影響這個 CPUID" in sec and "沒有任何一項代表「沒有漏洞」" in sec and "NVD 對 Intel CSME 的 CPE 與版本範圍資料不完整" in sec
    assert "PASS" not in sec and "不受影響" not in sec and "安全" not in sec


def test_unusable_table_is_gap_and_everything_is_not_assessed(tmp_path):
    err = fa.TableError("table-sha-mismatch", "table sha256 aaaaaaaaaaaaaaaa… differs from the pinned bbbbbbbbbbbbbbbb…")
    inv, comps, md = sbom_with(tmp_path, err)
    assert inv["advisory"]["status"] == "GAP" and inv["advisory"]["counts"] == {"NOT_ASSESSED": 2} and "table-sha-mismatch" in inv["advisory"]["gap"]
    assert inv["status"] == "ATTENTION" and "資料表不能用（GAP" in inv["detail"]
    for c in comps:
        if c["name"].startswith("Intel CPU microcode"):
            assert props(c, "dumpling:advisory-match") == ["NOT_ASSESSED"] and props(c, "dumpling:advisory-source") == ["advisory table not available"]
            assert "differs from the pinned" in props(c, "dumpling:advisory-basis")[0] and not props(c, "dumpling:advisory-candidates")
    assert "GAP（不能用）" in md and "資料庫沒有資料，以廠商公告為準" in md


def test_default_table_is_the_committed_one_and_missing_table_is_gap(tmp_path, monkeypatch):
    inv, comps, _ = sbom_with(tmp_path, None)                                                                # 預設：repo 內的資料表，離線
    assert inv["advisory"]["status"] == "OK" and inv["advisory"]["source"]["tag"] == ur.TAG and inv["advisory"]["microcodes"] == 2
    ba = next(c for c in comps if c["name"] == "Intel CPU microcode 000B06A2")
    assert props(ba, "dumpling:advisory-match") == ["affected-candidate"]                                    # 0x4121 比 06-ba-02/e0 最新的 revision 舊
    monkeypatch.setattr(fa, "TABLE_PATH", tmp_path / "gone.json")
    inv, _, _ = sbom_with(tmp_path, None)
    assert inv["advisory"]["status"] == "GAP" and inv["status"] == "ATTENTION"


def test_report_section_exists_without_microcode_or_bios(tmp_path):
    p = tmp_path / "in.bin"
    p.write_bytes(b"\x00" * 64)
    inv = xf.inventory([p], advisory=TABLE)
    inv["status"], inv["detail"] = "GAP", "x"
    md = xf.markdown(inv)
    assert "## 公告比對" in md and "沒有 BIOS 映像" in md and inv["advisory"]["microcodes"] == 0
