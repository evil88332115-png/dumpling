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
    assert any(x["kind"] == "other" for x in r["purpose_other"]) and all(set(x) == {"line", "kind"} for x in r["purpose_other"])     # 沒分類的項目只記行號與分類，不抄原文
    assert any(x["kind"] == "note" for x in r["other"]) and r["security"] == [{"id": "INTEL-SA-01001", "how": "security"}]          # 備註不算公告
    assert all(set(u) <= {"line", "release", "section", "why", "handled"} for u in p["unparsed"])                                     # 沒有原文欄位
    assert "INTEL-SA-01003" not in json.dumps(p) and "Something nobody planned for" not in json.dumps(p) and "nobody" not in json.dumps(p)
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
    assert p["releases"][0]["other"] == [{"line": 4, "kind": "update-note"}] and p["unparsed"] == []
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
    assert b["removed"] == [["06-86-04", "01", "0b00000f", "", "SNR", "B0"]] and b["other"] == [{"line": 29, "kind": "other"}]
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
    monkeypatch.setattr(ur, "PROSE_RULES", ())
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
    assert r["match"] == "affected-candidate" and r["releases"] == ["microcode-20231201", "microcode-20240101", "microcode-20240201"]      # 揭露表也算
    assert any("New Disclosures" in n and "INTEL-SA-00009" in n for n in r["notes"])
    assert {c["id"]: c["how"] for c in r["candidates"]} == {"INTEL-SA-00001": ["security"], "INTEL-SA-00009": ["disclosed"]}


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
    assert [(u["line"], u["release"]) for u in doc["unparsed"]] == [(346, "microcode-20250812"), (357, "microcode-20250512"),
                                                                    (1066, "microcode-20230512"), (1905, "microcode-20190618")]          # 看不懂的段落都記著（目前 4 處）
    assert doc["unparsed"][0]["handled"] == "prose_rules" and all("text" not in u for u in doc["unparsed"])
    blob = json.dumps(doc)
    assert "Security updates" not in blob and "Update for functional" not in blob and "Refer to" not in blob          # 來源的說明文字沒有抄進表（授權）
    assert all(set(x) == {"line", "kind"} for r in doc["releases"] for x in r["other"] + r["purpose_other"])
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


# ---------- 揭露表、散文對照、被取代的 platform 遮罩 ----------

def test_disclosure_table_rows_make_candidates_with_upper_bound_of_old_and_new():
    # Old 0x20 / New N/A（揭露表只有 Old）；Old 0x30 / New 0x40（取較大者 0x40）
    t = mk_table(rel("microcode-20240301", sa=["INTEL-SA-00005", "INTEL-SA-00006"], disclosed=[(FMS, "e0", "00000020", "N/A"), ("06-cc-01", "01", "00000030", "00000040")]),
                 rel("microcode-20240201", updated=[(FMS, "e0", "00000010", "00000030"), ("06-cc-01", "01", "00000030", "00000050")]))
    r = fa.match_signature(t, CPU, "0xE0", "0x20")                                   # 0x20 ≤ 揭露的 0x20 → 候選
    assert r["match"] == "affected-candidate" and {c["id"]: c["how"] for c in r["candidates"]} == {"INTEL-SA-00005": ["disclosed"], "INTEL-SA-00006": ["disclosed"]}
    assert "microcode-20240301" in r["releases"] and "disclosure table" in r["basis"]
    r = fa.match_signature(t, CPU, "0xE0", "0x30")                                   # 0x30 = 最新、高於揭露的 0x20 → 不用揭露表
    assert r["match"] == "up-to-date" and any("above that" in n for n in r["notes"])
    r = fa.match_signature(t, "000C06C1", "0x01", "0x40")                            # 06-cc-01：Old 0x30／New 0x40 → 上界 0x40
    assert r["match"] == "affected-candidate" and {c["id"] for c in r["candidates"]} >= {"INTEL-SA-00005", "INTEL-SA-00006"}
    r = fa.match_signature(t, "000C06C1", "0x01", "0x41")                           # 0x41 高於揭露的上界 0x40、低於最新 0x50（那個 release 沒有公告）
    assert r["match"] == "older-no-sa" and r["releases"] == ["microcode-20240201"]
    t2 = mk_table(rel("microcode-20240301", sa=["INTEL-SA-00005"], disclosed=[(FMS, "e0", "00000020", "N/A")]))
    r = fa.match_signature(t2, CPU, "0xE0", "0x10")                                  # 只有揭露表的鍵：revision ≤ 上界仍列候選，沒有最新 revision
    assert r["match"] == "affected-candidate" and r["latest_revision"] is None and "only disclosure" in r["basis"]
    assert fa.match_signature(t2, CPU, "0xE0", "0x21")["reason"] == "no-revision-history"


def test_disclosure_with_latest_revision_equal_to_the_bound_is_still_candidate():
    t = mk_table(rel("microcode-20240301", sa=["INTEL-SA-00005"], disclosed=[(FMS, "e0", "00000010", "00000020")]),
                 rel("microcode-20240101", updated=[(FMS, "e0", "00000010", "00000020")]))
    r = fa.match_signature(t, CPU, "0xE0", "0x20")
    assert r["match"] == "affected-candidate" and r["latest_revision"] == "0x00000020" and r["candidates"][0]["how"] == ["disclosed"]


def prose_table(ref_rows, extra_rows=(), with_gap=True):
    rules = [{"release": "microcode-20240301", "line": 7, "quote": "q", "interpretation": "i", "codes": ["ABC"], "ref_release": "microcode-20240201",
              "keys": [[FMS, "e0", "00000030", "row-in-ref-release"]],
              "gaps": [{"key": "06-bb-01/01", "why": "mixed"}, {"code": "XYZ", "why": "no table key has this processor code"}] if with_gap else []}]
    doc = {"schema": fa.SCHEMA, "source": {"repo": "https://github.com/intel/x", "tag": "microcode-30000101", "commit": "b" * 40, "path": "releasenote.md", "sha256": "c" * 64},
           "releases": [rel("microcode-20240301", sa=["INTEL-SA-00007", "INTEL-SA-00008"], updated=list(extra_rows)),
                        rel("microcode-20240201", updated=list(ref_rows)),
                        rel("microcode-20240101", updated=[(FMS, "e0", "00000010", "00000020"), ("06-bb-01", "01", "00000010", "00000020")])],
           "prose_rules": rules}
    fa.validate(doc)
    return fa.Table(doc, "a" * 64)


def test_prose_rule_adds_the_prose_release_for_revisions_below_the_reference():
    t = prose_table([(FMS, "e0", "00000020", "00000030")])
    r = fa.match_signature(t, CPU, "0xE0", "0x20")
    assert r["match"] == "affected-candidate" and {c["id"]: c["how"] for c in r["candidates"]} == {"INTEL-SA-00007": ["prose"], "INTEL-SA-00008": ["prose"]}
    assert "microcode-20240301" in r["releases"] and "prose, compiled by hand" in r["basis"] and "line 7" in r["basis"]
    r = fa.match_signature(t, CPU, "0xE0", "0x30")                                     # 等於基準：不加
    assert r["match"] == "up-to-date" and r["candidates"] == []
    g = fa.match_signature(t, CPU, "0xE0", "0x10")
    assert g["match"] == "affected-candidate"
    gap = fa.match_signature(t, "000B06B1", "0x01", "0x10")                            # 06-bb-01/01：對照有 GAP → 只加註，不推
    assert any("GAP in the hand-compiled prose mapping" in n and "mixed" in n for n in gap["notes"]) and not any(c["how"] == ["prose"] for c in gap["candidates"])


def test_prose_rule_in_the_real_table_covers_the_adl_examples():
    t = fa.load()
    r = fa.match_signature(t, "00090672", "0x07", "0x37")                              # ADL-S 06-97-02/07 在 20250211 的 revision
    ids = {c["id"] for c in r["candidates"]}
    assert {"INTEL-SA-01249", "INTEL-SA-01308", "INTEL-SA-01310", "INTEL-SA-01311", "INTEL-SA-01313", "INTEL-SA-01367"} <= ids
    assert "microcode-20250812" in r["releases"] and all(c["how"] == ["prose"] for c in r["candidates"] if c["id"] in {"INTEL-SA-01249", "INTEL-SA-01367"})
    ok = fa.match_signature(t, "00090672", "0x07", "0x3a")                             # 等於 20250512 的 revision：不靠散文，仍有 20251111／20260210 的候選
    assert "INTEL-SA-01249" not in {c["id"] for c in ok["candidates"]}
    rule = t.doc["prose_rules"][0]
    assert (rule["release"], rule["line"], rule["ref_release"]) == ("microcode-20250812", 346, "microcode-20250512") and len(rule["quote"]) < 120
    assert rule["gaps"] == [] and [g["key"] for g in rule["unlisted"]] == ["06-9a-04/40"]
    # 06-be-00/19：Processor 欄是 ADL-N 加 TWL，任一列屬於清單就納入；基準是 20250512 的 0x1d
    assert ["06-be-00", "19", "0000001d", "row-in-ref-release"] in rule["keys"]
    adl_n = fa.match_signature(t, "000B06E0", "0x19", "0x1c")
    assert {"INTEL-SA-01249", "INTEL-SA-01308", "INTEL-SA-01310", "INTEL-SA-01311", "INTEL-SA-01313", "INTEL-SA-01367"} <= {c["id"] for c in adl_n["candidates"]}
    assert "INTEL-SA-01249" not in {c["id"] for c in fa.match_signature(t, "000B06E0", "0x19", "0x1d")["candidates"]}      # 等於基準：不加
    # 06-9a-04/40（AZB，與 ADL 同 F-M-S）原文沒提到：不納入，加註
    azb = fa.match_signature(t, "000906A4", "0x40", "0x0b")
    assert not any(c["how"] == ["prose"] for c in azb["candidates"]) and any("not mentioned there" in n and "AZB" in n for n in azb["notes"])
    assert azb["match"] in ("affected-candidate", "older-no-sa") and "INTEL-SA-01249" not in {c["id"] for c in azb["candidates"]}


def test_superseded_platform_mask_is_not_up_to_date():
    t = fa.load()
    for cpuid, pf, rev in (("00090672", "0x03", "0x22"), ("000B06E0", "0x01", "0x10"), ("000B06E0", "0x11", "0x1a"), ("000C06C2", "0x90", "0x11b")):
        # 06-97-02/03、06-be-00/01 與 /11、06-cc-02/90：遮罩與較新的鍵有交集（0x90 & 0x94＝0x90）、而且那個鍵在之後還有更新
        r = fa.match_signature(t, cpuid, pf, rev)
        assert r["match"] == "NOT_ASSESSED" and r["reason"] == "superseded-platform-mask", (cpuid, pf)
        assert "overlaps" in r["basis"] and "releases after" in r["basis"] and r["basis"].endswith(fa.NO_DATA) and "INTEL-SA-" in r["basis"]
    assert int("90", 16) & int("94", 16) and not int("07", 16) & int("e0", 16)       # 核對過的遮罩關係
    # 互不相交（06-ba-02/07 對 e0）：結果不變，加註
    r = fa.match_signature(t, "000B06A2", "0x07", "0x4112")
    assert r["match"] == "up-to-date" and any("disjoint" in n and "other platform mask" in n for n in r["notes"])
    assert fa.match_signature(t, "00090672", "0x07", "0x3e")["match"] == "up-to-date"        # 最新的鍵本身不降級


def test_superseded_mask_candidates_are_also_listed_when_the_revision_is_older():
    t = mk_table(rel("microcode-20240301", sa=["INTEL-SA-00003"], updated=[(FMS, "07", "00000040", "00000050")]),
                 rel("microcode-20240201", updated=[(FMS, "03", "00000020", "00000030")]),
                 rel("microcode-20240101", sa=["INTEL-SA-00001"], new=[(FMS, "03", "", "00000020"), (FMS, "07", "", "00000040")]))
    old = fa.match_signature(t, CPU, "0x03", "0x20")
    assert old["match"] == "affected-candidate" and {c["id"] for c in old["candidates"]} == {"INTEL-SA-00003"} and old["candidates"][0]["how"] == ["superseded-mask"]
    cur = fa.match_signature(t, CPU, "0x03", "0x30")
    assert cur["match"] == "NOT_ASSESSED" and cur["reason"] == "superseded-platform-mask" and "INTEL-SA-00003" in cur["basis"]
    assert fa.match_signature(t, CPU, "0x07", "0x50")["match"] == "up-to-date"


def test_every_key_older_than_a_newer_overlapping_key_is_never_up_to_date_in_the_real_table():
    t = fa.load()
    bad = []
    for (fms, pf), ev in t.events.items():
        main = [e for e in ev if e[1] in ("new", "updated")]
        if not main:
            continue
        top = min(e[0] for e in main)
        inter, _ = fa._superseding(t, fms, pf, top)
        latest = sorted({e[3] for e in main if e[0] == top})[-1]
        f, m, st = (int(x, 16) for x in fms.split("-"))
        cpuid = "%08X" % ((((m >> 4) & 0xF) << 16) | (f << 8) | ((m & 0xF) << 4) | st)
        r = fa.match_signature(t, cpuid, "0x" + pf, "0x" + latest)
        if inter and r["match"] == "up-to-date":
            bad.append((fms, pf))
    assert bad == []


def test_revision_one_below_latest_is_never_up_to_date():
    for latest in (0x40, 0x100, 0x1, 0x10000000):
        t = mk_table(rel("microcode-20240101", updated=[(FMS, "e0", "00000000", "%08x" % latest)]))
        assert fa.match_signature(t, CPU, "0xE0", hex(latest - 1) if latest > 1 else "0x0")["match"] != "up-to-date"
        assert fa.match_signature(t, CPU, "0xE0", hex(latest))["match"] == "up-to-date"


def test_removed_and_updated_in_the_same_release():
    t = mk_table(rel("microcode-20240201", removed=[(FMS, "e0", "00000010", "")], updated=[(FMS, "e0", "00000010", "00000020")]),
                 rel("microcode-20240101", new=[(FMS, "e0", "", "00000010")]))
    r = fa.match_signature(t, CPU, "0xE0", "0x10")                       # 同一個 release 又 removed 又 updated：以 updated 為準（有新 revision）
    assert r["match"] in ("affected-candidate", "older-no-sa") and r["latest_revision"] == "0x00000020"
    assert fa.match_signature(t, CPU, "0xE0", "0x20")["match"] == "up-to-date"


def test_extended_signature_priority_and_candidate_union():
    t = mk_table(rel("microcode-20240301", sa=["INTEL-SA-00003"], updated=[("06-bb-01", "01", "00000010", "00000030")]),
                 rel("microcode-20240201", sa=["INTEL-SA-00002"], updated=[(FMS, "e0", "00000010", "00000020")]),
                 rel("microcode-20240101", updated=[("06-bb-02", "03", "00000010", "00000020")]))
    # 主 signature up-to-date、extended 是 older-no-sa（沒有公告的鍵）→ older-no-sa（不能是 up-to-date）
    t0 = mk_table(rel("microcode-20240201", updated=[("06-bb-01", "01", "00000010", "00000030")]), rel("microcode-20240101", updated=[(FMS, "e0", "00000010", "00000020")]))
    r = fa.match_microcode(t0, ucode("0x20", ext=[("000B06B1", "0x01")]))
    assert [s["match"] for s in r["signatures"]] == ["up-to-date", "older-no-sa"] and r["match"] == "older-no-sa"
    # 兩個 signature 各自的候選公告取聯集；how、releases 合併
    r = fa.match_microcode(t, ucode("0x10", ext=[("000B06B1", "0x01")]))
    assert r["match"] == "affected-candidate" and [c["id"] for c in r["candidates"]] == ["INTEL-SA-00002", "INTEL-SA-00003"]
    assert r["releases"] == ["microcode-20240201", "microcode-20240301"]
    # 其中一個 NOT_ASSESSED、另一個 up-to-date → NOT_ASSESSED；NOT_ASSESSED 與 older-no-sa → NOT_ASSESSED
    r = fa.match_microcode(t, ucode("0x20", ext=[("000B06B9", "0x01")]))
    assert r["match"] == "NOT_ASSESSED" and r["reason"] == "cpuid-not-in-table"


def test_cpuid_seven_digits_and_extended_model_family_f():
    assert fa.fms_of("0806EC") is None and fa.fms_of("00806EC") is None            # 7 位數不收
    assert fa.fms_of("00000F41") == "0f-04-01" and fa.fms_of("00200F41") == "11-04-01" and fa.fms_of("000F0F41") == "0f-f4-01"      # family 0xF：extended family 相加、extended model 併入
    assert fa.fms_of("000206A7") == "06-2a-07" and fa.fms_of("000306C3") == "06-3c-03"                     # family 6：extended model 併入
    assert fa.fms_of("00000450") == "04-05-00"                                                       # family 4：不併 extended model
    assert fa.fms_of("000F0450") == "04-05-00"
    r = fa.match_signature(TABLE, "000B06A", "0xE0", "0x10")
    assert r["reason"] == "bad-cpuid"


def test_report_wording_for_up_to_date_and_no_data(tmp_path):
    t = mk_table(rel("microcode-20240101", updated=[(FMS, "e0", "00004100", "00004121")]))
    _, _, md = sbom_with(tmp_path, t)                                                  # spi_image 的 000B06A2/0xE0/0x4121 ＝ 最新
    sec = md[md.index("## 公告比對"):]
    assert "up-to-date（資料表沒有更新的 revision；不代表沒有漏洞）" in sec and "資料庫沒有資料，以廠商公告為準" in sec
    assert "does not mean there are no vulnerabilities" in sec and "不受影響" not in sec


def test_table_gap_without_microcode_keeps_status_and_says_gap(tmp_path):
    p = tmp_path / "in.bin"
    p.write_bytes(b"\x00" * 64)
    err = fa.TableError("table-unreadable", "not a regular file")
    inv = xf.inventory([p], advisory=err)
    assert inv["advisory"]["status"] == "GAP" and inv["advisory"]["microcodes"] == 0
    st, _ = xf.status_of(inv)
    assert st == "GAP"                                                                 # 沒有 BIOS 結構的 GAP 不因資料表而變；資料表 GAP 只在有微碼時才讓狀態變 ATTENTION
    inv["status"], inv["detail"] = st, ""
    assert "GAP（不能用）" in xf.markdown(inv)


def test_advisory_errors_become_not_assessed_not_exceptions(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise KeyError("x")
    monkeypatch.setattr(fa, "match_microcode", boom)
    inv, comps, md = sbom_with(tmp_path, TABLE)
    assert inv["advisory"]["counts"] == {"NOT_ASSESSED": 2}
    u = next(c for c in comps if c["name"].startswith("Intel CPU microcode"))
    assert props(u, "dumpling:advisory-match") == ["NOT_ASSESSED"] and "KeyError" in props(u, "dumpling:advisory-basis")[0]
    assert "資料庫沒有資料，以廠商公告為準" in md


@pytest.mark.parametrize("mutate", [
    lambda d: d["releases"][0]["security"].append({"id": "INTEL-SA-00001", "how": "bogus"}),
    lambda d: d["releases"][0].update(date="2020-01-01"),                                                    # 順序要由新到舊
    lambda d: d["releases"][1].update(date="2025-01-01"),
    lambda d: d["releases"][0].update(date="Jan 1"),
    lambda d: d.update(prose_rules=[{"release": "nope"}]),
    lambda d: d.update(prose_rules="x"),
])
def test_validate_rejects_bad_how_order_and_prose_rules(mutate):
    doc = {"schema": fa.SCHEMA, "source": {"repo": "r", "tag": "t", "commit": "c", "path": "p", "sha256": "s"},
           "releases": [rel("microcode-20240201", updated=[(FMS, "e0", "00000020", "00000030")]), rel("microcode-20240101", updated=[(FMS, "e0", "00000010", "00000020")])]}
    doc["releases"][0]["date"], doc["releases"][1]["date"] = "2024-02-01", "2024-01-01"
    fa.validate(doc)
    mutate(doc)
    with pytest.raises(fa.TableError):
        fa.validate(doc)


def test_security_regex_is_linear_on_repeated_prefixes_and_long_lines():
    import time
    t0 = time.time()
    ur.security_bullet("Security updates for " + "INTEL-SA-" * 20000 + " [INTEL-SA-00001]")
    ur.security_bullet("Security updates for " + "(" * 50000)
    p = ur.parse(release("microcode-20240101", "### Purpose\n\n- " + "x" * (ur.MAX_LINE + 5) + "\n"))
    assert "沒有解析" in p["unparsed"][0]["why"]
    assert time.time() - t0 < 5
    assert ur.security_bullet("Security updates for INTEL-SA-INTEL-SA-00972") == ("security", ["INTEL-SA-00972"], False)




# ---------- 產生器的人工對照（resolve_rule）各分支 ----------

def prose_source():
    def row(proc, fms, old, new, st="A0"):
        return f"| {proc} | {st} | {fms} | {old} | {new} | x\n"
    rows = lambda *r: "### Updated Platforms\n\n" + TBL + "".join(r)
    return notes(
        release("microcode-20251111", rows(row("ADL", "06-aa-01/01", "00000030", "00000099"), row("ADL", "06-aa-06/01", "00000001", "00000002"))),
        release("microcode-20250812", "### Purpose\n\n### New Disclosures Updated in Prior Releases\n\nPatches were released earlier.\n\n" + rows(row("ADL", "06-aa-0b/01", "00000001", "00000002"))),
        release("microcode-20250512", "### New Platforms\n\n" + TBL + row("ADL", "06-aa-09/01", "", "00000040") + "\n" + rows(
            row("ADL", "06-aa-01/01", "00000020", "00000030"), row("AZB", "06-aa-01/02", "00000020", "00000030"),
            row("ADL", "06-aa-02/01", "00000020", "00000030"), row("ADL", "06-aa-02/01", "00000020", "00000031"),          # 基準有兩個不同的 New Ver → GAP
            row("adl-n", "06-aa-07/01", "00000010", "00000011"), row("TWL", "06-aa-07/01", "00000010", "00000011"),          # 小寫、同一個 key 還有清單外的代號 → 納入
            row("ADL2-X", "06-aa-0a/01", "00000001", "00000002"))),                                                         # 字詞只取字母
        release("microcode-20250211", rows(row("ADL", "06-aa-03/01", "00000010", "00000020"), row("ADL", "06-aa-04/01", "00000010", "00000020"),
                                           row("ADL", "06-aa-04/01", "00000010", "00000021"), row("ADL", "06-aa-0c/01", "00000001", "00000002"))),
        release("microcode-20250101", rows(row("ADL", "06-aa-03/01", "00000001", "00000010"), row("ADL", "06-aa-0c/01", "00000001", "00000002"),
                                           row("XYZ", "06-aa-05/01", "00000001", "00000002"))),
        release("microcode-20240101", "### Removed Platforms\n\n" + TBL + row("ADL", "06-aa-08/01", "00000001", "")))


def prose_line():
    return [i for i, x in enumerate(prose_source().splitlines(), 1) if x.strip() == "Patches were released earlier."][0]


def prose_rule(**kw):
    return dict({"release": "microcode-20250812", "line": prose_line(), "quote": "Patches were released earlier.", "interpretation": "i",
                 "codes": ["ADL", "MTL"], "ref_release": "microcode-20250512"}, **kw)


def test_resolve_rule_membership_reference_revisions_and_gaps():
    text = prose_source()
    pr = ur.parse(text, [prose_rule()])["prose_rules"][0]
    keys = {f"{k[0]}/{k[1]}": k[2:] for k in pr["keys"]}
    gaps = {g.get("key") or g.get("code"): g["why"] for g in pr["gaps"]}
    assert keys["06-aa-01/01"] == ["00000030", "row-in-ref-release"]          # 20251111 的 0x99 在人工對照的 release 之後，不看
    assert keys["06-aa-09/01"] == ["00000040", "row-in-ref-release"]          # New Platforms 的列也算
    assert keys["06-aa-07/01"] == ["00000011", "row-in-ref-release"]          # ADL-N（小寫）與 TWL 同一個 key：任一列屬於清單就納入
    assert keys["06-aa-0a/01"] == ["00000002", "row-in-ref-release"]          # ADL2-X → ADL
    assert keys["06-aa-03/01"][1] == "latest-before-ref-release"
    assert "microcode-20250512 lists different" in gaps["06-aa-02/01"]
    assert "latest release before" in gaps["06-aa-04/01"]
    assert "no revision as of" in gaps["06-aa-0b/01"]                          # 只在人工對照的 release 本身有列：沒有基準，不推
    assert gaps["MTL"] == "no table key has this processor code"
    assert "06-aa-08/01" not in keys and "06-aa-05/01" not in keys and "06-aa-06/01" not in keys     # removed 不算；XYZ 不在清單；新於人工對照的 release 不看
    assert "06-aa-06/01" not in gaps and "06-aa-08/01" not in gaps and "06-aa-05/01" not in gaps and all(u["key"] != "06-aa-06/01" for u in pr["unlisted"])
    assert [u["key"] for u in pr["unlisted"]] == ["06-aa-01/02"] and "AZB" in pr["unlisted"][0]["why"]
    assert "06-aa-0c/01" in keys and keys["06-aa-0c/01"] == ["00000002", "latest-before-ref-release"]


def test_resolve_rule_picks_the_newest_release_before_the_reference():
    pr = ur.parse(prose_source(), [prose_rule()])["prose_rules"][0]
    row = next(k for k in pr["keys"] if k[:2] == ["06-aa-03", "01"])
    assert row[2] == "00000020"                                               # 20250211 的 New Ver（比 20250101 的 0x10 新）


def test_resolve_rule_errors():
    text = prose_source()
    for kw, msg in (({"quote": "x"}, "與來源不符"), ({"line": 999}, "與來源不符"), ({"line": 0}, "與來源不符"), ({"release": "microcode-19990101"}, "不在來源裡"),
                    ({"ref_release": "microcode-19990101"}, "不在來源裡")):
        with pytest.raises(ur.GenError, match=msg):
            ur.parse(text, [prose_rule(**kw)])
    with pytest.raises(ur.GenError, match="不在 microcode-20250812 底下"):
        ur.parse(text, [prose_rule(line=1, quote="# Release Notes")])
    with pytest.raises(ur.GenError, match="不在 microcode-20250812 底下"):                   # 原文對、但那一行在別的 release 底下
        ur.parse(text, [prose_rule(line=1 + [i for i, x in enumerate(text.splitlines()) if "microcode-20250512" in x][0] + 1, quote=text.splitlines()[[i for i, x in enumerate(text.splitlines()) if "microcode-20250512" in x][0] + 3].strip())])
    stray = text.replace("### New Platforms\n", "### Purpose\n\nStray text under purpose.\n\n### New Platforms\n", 1)         # 20250512 底下有一行會進 unparsed 的文字
    n = [i for i, x in enumerate(stray.splitlines(), 1) if x == "Stray text under purpose."][0]
    assert any(u["line"] == n and u["release"] == "microcode-20250512" for u in ur.parse(stray)["unparsed"])
    with pytest.raises(ur.GenError, match="不在 microcode-20250812 底下"):                   # 原文對、而且在 unparsed 裡，但屬於別的 release
        ur.parse(stray, [prose_rule(line=n, quote="Stray text under purpose.")])
    assert ur.parse(text, [])["prose_rules"] == [] and ur.parse(text)["prose_rules"] == []
    assert ur.parse(text, [prose_rule()])["unparsed"][0]["handled"] == "prose_rules"


# ---------- 揭露表上界、散文基準的邊界、遮罩關係 ----------

def disclosure_table(old, new):
    return mk_table(rel("microcode-20240301", sa=["INTEL-SA-00005"], disclosed=[(FMS, "e0", old, new)]),
                    rel("microcode-20240101", updated=[(FMS, "e0", "00000010", "00000050")]))


@pytest.mark.parametrize("old,new,rev,hit", [
    ("00000020", "00000030", 0x30, True), ("00000020", "00000030", 0x31, False), ("00000020", "00000030", 0x25, True), ("00000020", "00000030", 0x20, True),
    ("00000030", "00000020", 0x30, True), ("00000030", "00000020", 0x31, False),          # Old 比 New 大：取較大者
    ("00000030", "N/A", 0x30, True), ("00000030", "N/A", 0x31, False), ("00000030", "N/A", 0x01, True),
    ("", "00000030", 0x30, True), ("", "00000030", 0x31, False),
])
def test_disclosure_bound_is_the_larger_of_old_and_new(old, new, rev, hit):
    r = fa.match_signature(disclosure_table(old, new), CPU, "0xE0", hex(rev))
    got = "INTEL-SA-00005" in {c["id"] for c in r["candidates"]}
    assert got == hit and (not hit or {c["id"]: c["how"] for c in r["candidates"]}["INTEL-SA-00005"] == ["disclosed"])
    if not hit:
        assert any("above that" in n for n in r["notes"])


@pytest.mark.parametrize("ref,rev,hit", [(0x30, 0x2f, True), (0x30, 0x30, False), (0x30, 0x31, False), (0x30, 0x01, True)])
def test_prose_boundary_reference_minus_one(ref, rev, hit):
    t = prose_table([(FMS, "e0", "00000020", "%08x" % ref)])
    got = "INTEL-SA-00007" in {c["id"] for c in fa.match_signature(t, CPU, "0xE0", hex(rev))["candidates"] if c["how"] == ["prose"]}
    assert got == hit


def overlap_table(mine, other, other_rel="microcode-20240301", same_release=False):
    """SBOM 的鍵 (FMS, mine) 最後一次更新在 20240201；另一個遮罩 other 在 other_rel 更新。"""
    rels = {"microcode-20240301": rel("microcode-20240301", sa=["INTEL-SA-00003"]), "microcode-20240201": rel("microcode-20240201", sa=["INTEL-SA-00002"]),
            "microcode-20240101": rel("microcode-20240101", sa=["INTEL-SA-00001"])}
    rels["microcode-20240201"]["updated"].append([FMS, mine, "00000010", "00000020", "P", "A"])
    rels[other_rel]["updated"].append([FMS, other, "00000010", "00000020", "P", "A"])
    return mk_table(*[rels[k] for k in sorted(rels, reverse=True)])


@pytest.mark.parametrize("mine,other,overlaps", [
    ("07", "03", True),            # 對方是我的子集
    ("03", "07", True),            # 我是對方的子集
    ("32", "1c", True),            # 部分重疊、互不為子集（0x32 & 0x1c = 0x10）
    ("e0", "e0", None),
    ("07", "e0", False), ("01", "02", False), ("32", "0d", False),
])
def test_mask_relations(mine, other, overlaps):
    if overlaps is None:
        return
    r = fa.match_signature(overlap_table(mine, other), CPU, "0x" + mine, "0x20")
    if overlaps:
        assert r["match"] == "NOT_ASSESSED" and r["reason"] == "superseded-platform-mask" and f"platform mask {other} (overlaps {mine})" in r["basis"]
        assert "INTEL-SA-00003" in r["basis"] and r["candidates"] == []
    else:
        assert r["match"] == "up-to-date" and any(f"another platform mask {other} (disjoint from {mine})" in n for n in r["notes"])


def test_other_mask_updated_in_the_same_or_an_earlier_release_does_not_supersede():
    same = fa.match_signature(overlap_table("07", "03", other_rel="microcode-20240201"), CPU, "0x07", "0x20")      # 同一個 release：不算「之後」
    assert same["match"] == "up-to-date" and same["notes"] == []
    earlier = fa.match_signature(overlap_table("07", "03", other_rel="microcode-20240101"), CPU, "0x07", "0x20")
    assert earlier["match"] == "up-to-date" and earlier["notes"] == []                                              # 只有更早的更新：沒有註記
    gone = mk_table(rel("microcode-20240301", removed=[(FMS, "03", "00000010", "")]), rel("microcode-20240201", updated=[(FMS, "07", "00000010", "00000020")]),
                    rel("microcode-20240101", new=[(FMS, "03", "", "00000010")]))
    assert fa.match_signature(gone, CPU, "0x07", "0x20")["match"] == "up-to-date"                                   # 另一個遮罩之後只有 removed：不算更新
    only_new = mk_table(rel("microcode-20240301", new=[(FMS, "03", "", "00000040")]), rel("microcode-20240201", updated=[(FMS, "07", "00000010", "00000020")]))
    assert fa.match_signature(only_new, CPU, "0x07", "0x20")["reason"] == "superseded-platform-mask"               # new 也算更新


def test_other_mask_latest_revision_in_the_reference_is_the_largest_of_its_release():
    t = mk_table(rel("microcode-20240301", updated=[(FMS, "03", "00000010", "00000040"), (FMS, "03", "00000011", "00000050")]),
                 rel("microcode-20240201", updated=[(FMS, "07", "00000010", "00000020")]))
    assert "latest 0x00000050" in fa.match_signature(t, CPU, "0x07", "0x20")["basis"]


def test_equal_revision_with_disclosure_candidates_and_an_overlapping_newer_mask():
    t = mk_table(rel("microcode-20240301", sa=["INTEL-SA-00003"], updated=[(FMS, "03", "00000010", "00000020")]),
                 rel("microcode-20240201", sa=["INTEL-SA-00002"], disclosed=[(FMS, "07", "00000010", "00000020")], updated=[(FMS, "07", "00000010", "00000020")]))
    r = fa.match_signature(t, CPU, "0x07", "0x20")                       # 等於最新、揭露表涵蓋、另一個重疊遮罩之後還有更新
    assert r["match"] == "affected-candidate"
    assert {c["id"]: c["how"] for c in r["candidates"]} == {"INTEL-SA-00002": ["disclosed"], "INTEL-SA-00003": ["superseded-mask"]}
    assert r["releases"] == ["microcode-20240201", "microcode-20240301"]
    old = fa.match_signature(mk_table(rel("microcode-20240301", sa=["INTEL-SA-00003"], updated=[(FMS, "03", "00000010", "00000020")]),
                                      rel("microcode-20240201", updated=[(FMS, "07", "00000010", "00000030")])), CPU, "0x07", "0x30")
    assert old["match"] == "NOT_ASSESSED" and old["reason"] == "superseded-platform-mask"      # 沒有 6.b 候選：不因 6.d 變成 affected-candidate


def test_revert_note_when_equal_to_the_latest_and_a_larger_revision_was_listed_before():
    t = fa.load()
    r = fa.match_signature(t, "000306E4", "0xED", "0x42e")                   # 06-3e-04/ed：20190514 的 0x42f，20190514a 退回 0x42e
    assert r["match"] == "up-to-date" and any("went back to this one: 0x0000042f (microcode-20190514)" in n for n in r["notes"])
    assert not fa.match_signature(TABLE, CPU, "0xE0", "0x40")["notes"]       # 一般的最新 revision：沒有註記


def test_validate_checks_ref_release_and_prose_key_revisions():
    base = lambda: {"schema": fa.SCHEMA, "source": {"repo": "r", "tag": "t", "commit": "c", "path": "p", "sha256": "s"},
                    "releases": [rel("microcode-20240101", updated=[(FMS, "e0", "00000010", "00000020")])],
                    "prose_rules": [{"release": "microcode-20240101", "ref_release": "microcode-20240101", "line": 1, "quote": "q", "interpretation": "i",
                                     "keys": [[FMS, "e0", "00000020", "row-in-ref-release"]], "gaps": [], "unlisted": [{"key": "06-bb-01/01", "why": "w"}]}]}
    fa.validate(base())
    for mutate in (lambda d: d["prose_rules"][0].update(ref_release="microcode-19990101"), lambda d: d["prose_rules"][0].update(release="microcode-19990101"),
                   lambda d: d["prose_rules"][0]["keys"][0].__setitem__(2, "0x20"), lambda d: d["prose_rules"][0]["keys"][0].__setitem__(2, "20"),
                   lambda d: d["prose_rules"][0]["keys"][0].__setitem__(1, "E0"), lambda d: d["prose_rules"][0]["keys"].append(["x"]),
                   lambda d: d["prose_rules"][0].update(unlisted=[{"why": "no key"}]), lambda d: d["prose_rules"][0].update(unlisted="x"),
                   lambda d: d["prose_rules"][0].update(gaps=[{"key": "bad", "why": "w"}]), lambda d: d["prose_rules"][0].update(line="1")):
        d = base()
        mutate(d)
        with pytest.raises(fa.TableError):
            fa.validate(d)


@pytest.mark.parametrize("exc", [KeyError("x"), ValueError("x"), TypeError("x"), IndexError("x"), AttributeError("x"), ZeroDivisionError("x"), RuntimeError("x")])
def test_advisory_section_catches_any_exception(tmp_path, monkeypatch, exc):
    def boom(*a, **k):
        raise exc
    monkeypatch.setattr(fa, "match_microcode", boom)
    inv, comps, _ = sbom_with(tmp_path, TABLE)
    assert inv["advisory"]["counts"] == {"NOT_ASSESSED": 2}
    u = next(c for c in comps if c["name"].startswith("Intel CPU microcode"))
    assert props(u, "dumpling:advisory-match") == ["NOT_ASSESSED"] and type(exc).__name__ in props(u, "dumpling:advisory-basis")[0]


def test_report_says_the_family_is_inferred_and_needs_human_review(tmp_path):
    _, comps, md = sbom_with(tmp_path, TABLE)
    assert "family 是由版本推定的（映像讀不出來），比對結果待人審。" in md
    me = next(c for c in comps if c["name"] == "Intel CSE firmware")
    assert props(me, "dumpling:cpe-basis") == ["inferred"] and "needs human review" in props(me, "dumpling:cpe-basis-note")[0]


# ---------- AMD ----------

def amd_inventory(tmp_path):
    from test_amd_psp import good_image, put
    img = good_image()
    put(img, 0x80000, b"AGESA!V9\x00ComboAM4v2PI 1.2.0.B\x00")
    p = tmp_path / "amd.bin"
    p.write_bytes(bytes(img))
    return xf.inventory([p], advisory=TABLE)


def test_amd_components_all_have_an_advisory_result_and_the_report_does_not_say_unparsed(tmp_path):
    inv = amd_inventory(tmp_path)
    comps, deps = xf.components(inv)
    assert not list(cdx_validator().iter_errors(xf.bom(comps, deps)))
    amd = [c for c in comps if c["name"].startswith(("AMD CPU microcode", "AMD PSP firmware", "AMD AGESA"))]
    assert len(amd) >= 6 and {c["name"].split(" (")[0] for c in amd} >= {"AMD CPU microcode", "AMD AGESA"}
    for c in amd:
        assert props(c, "dumpling:advisory-match") == ["NOT_ASSESSED"] and "AMD-SB" in props(c, "dumpling:advisory-basis")[0]
        assert "no data in the database" in props(c, "dumpling:advisory-basis")[0] and props(c, "dumpling:vuln-assessment") == ["NOT_ASSESSED"]
    n = len(inv["bios"][0]["amd"]["microcode"])
    assert n == 2
    md = xf.markdown(inv)
    sec = md[md.index("## 公告比對"):]
    assert f"AMD 微碼已解析 {n} 份" in sec and "沒有做公告比對" in sec and "以 AMD 公告為準" in sec and "沒有解析" not in sec and "不支援" not in sec


def test_amd_parser_not_run_is_a_gap_in_the_report(tmp_path):
    inv = amd_inventory(tmp_path)
    inv["bios"][0]["amd"] = None
    inv["status"], inv["detail"] = "ATTENTION", ""
    sec = xf.markdown(inv)
    sec = sec[sec.index("## 公告比對"):]
    assert "PSP 目錄解析沒有執行（GAP" in sec and "以 AMD 公告為準" in sec


# ---------- 多個 signature 的合併、note 與報告 ----------

def test_signature_merge_priority_not_assessed_beats_older_no_sa_and_loses_to_candidates():
    t = mk_table(rel("microcode-20240301", sa=["INTEL-SA-00003"], updated=[("06-bb-01", "01", "00000010", "00000030")]),
                 rel("microcode-20240201", updated=[(FMS, "e0", "00000010", "00000020")]))
    # 主 signature older-no-sa（0x10 → 0x20 的 release 沒有公告）、extended 在表裡找不到 → NOT_ASSESSED
    r = fa.match_microcode(t, ucode("0x10", ext=[("000B06B9", "0x01")]))
    assert [s["match"] for s in r["signatures"]] == ["older-no-sa", "NOT_ASSESSED"] and r["match"] == "NOT_ASSESSED" and r["reason"] == "cpuid-not-in-table"
    # extended 有候選公告 → affected-candidate（候選只有有公告的那個 signature 的）
    r = fa.match_microcode(t, ucode("0x10", ext=[("000B06B1", "0x01")]))
    assert [s["match"] for s in r["signatures"]] == ["older-no-sa", "affected-candidate"] and r["match"] == "affected-candidate"
    assert [c["id"] for c in r["candidates"]] == ["INTEL-SA-00003"]
    # NOT_ASSESSED 加 affected-candidate → affected-candidate；reason 不留（只有整份是 NOT_ASSESSED 時才有）
    r = fa.match_microcode(t, ucode("0x10", ext=[("000B06B1", "0x01"), ("000B06B9", "0x01")]))
    assert r["match"] == "affected-candidate" and r["reason"] is None and [s["match"] for s in r["signatures"]][-1] == "NOT_ASSESSED"


def test_duplicate_signatures_are_deduplicated_by_cpuid_and_platform_together():
    t = mk_table(rel("microcode-20240201", updated=[(FMS, "e0", "00000010", "00000020"), (FMS, "03", "00000010", "00000020")]))
    r = fa.match_microcode(t, ucode("0x20", "0xE0", ext=[(CPU, "0xE0"), (CPU.lower(), "0xe0"), (CPU, "0x03")]))
    assert [(s["cpuid"], s["platform_id"]) for s in r["signatures"]] == [(CPU, "0xE0"), (CPU, "0x03")]       # 重複的合併；同 CPUID 不同 platform 是另一個 signature
    assert [s["match"] for s in r["signatures"]] == ["up-to-date", "up-to-date"]
    r = fa.match_microcode(t, ucode("0x20", "0xE0", ext=[(CPU, "0x80")]))
    assert [s["match"] for s in r["signatures"]] == ["up-to-date", "NOT_ASSESSED"] and r["signatures"][1]["reason"] == "platform-mismatch"


def test_notes_reach_the_sbom_and_the_report_including_unlisted(tmp_path):
    doc = {"schema": fa.SCHEMA, "source": {"repo": "https://github.com/intel/x", "tag": "microcode-30000101", "commit": "b" * 40, "path": "releasenote.md", "sha256": "c" * 64},
           "releases": [rel("microcode-20240201", sa=["INTEL-SA-00009"], disclosed=[(FMS, "e0", "00004100", "00004121")]),
                        rel("microcode-20240101", updated=[(FMS, "e0", "00004100", "00004121")])],
           "prose_rules": [{"release": "microcode-20240201", "line": 5, "quote": "q", "interpretation": "i", "ref_release": "microcode-20240101", "codes": ["ABC"],
                            "keys": [], "gaps": [{"key": "%s/e0" % FMS, "why": "ambiguous reference"}], "unlisted": [{"key": "%s/e0" % FMS, "why": "AZB only"}]}]}
    fa.validate(doc)
    inv, comps, md = sbom_with(tmp_path, fa.Table(doc, "a" * 64))                     # spi_image 的 000B06A2／0xE0／0x4121 ＝ 06-ba-02/e0 的最新
    u = next(c for c in comps if c["name"] == "Intel CPU microcode 000B06A2")
    notes = props(u, "dumpling:advisory-note")
    assert len(notes) == 3 and any("GAP in the hand-compiled prose mapping" in n and "ambiguous reference" in n for n in notes)
    assert any("not mentioned there" in n and "AZB only" in n for n in notes) and any("New Disclosures" in n and "INTEL-SA-00009" in n for n in notes)
    sec = md[md.index("## 公告比對"):]
    for frag in ("GAP in the hand-compiled prose mapping", "not mentioned there", "New Disclosures"):
        assert any(line.startswith("  - ") and frag in line for line in sec.splitlines()), frag


def test_amd_report_counts_psp_microcode_and_agesa(tmp_path):
    inv = amd_inventory(tmp_path)
    a = inv["bios"][0]["amd"]
    md = xf.markdown(inv)
    sec = md[md.index("## 公告比對"):]
    assert f"AMD 微碼已解析 {len(a['microcode'])} 份、PSP 韌體 {len(a['psp_firmware'])} 項、AGESA 字串 {len(a['agesa']['values'])} 個" in sec
    assert len(a["agesa"]["values"]) == 1 and len(a["psp_firmware"]) >= 3
