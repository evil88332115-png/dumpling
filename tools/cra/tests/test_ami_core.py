"""AMI 核心版本（ami_core.py：Firmware ID 紀錄 `$FID`）：結構檢查、走訪（uefi_gfx.scan 的 ami_core）、規則表比對（fw_advisory_rules.cond_ami）、
SBOM 與報告、版本清單 ibv-core 核對。全部用測試自己組的合成資料（FV、FFS、section），不含任何真實映像的位元組。
欄位位置是從公開映像反推的（docs/notes/c2-ami-core.md）；測試只守「結構檢查會擋什麼、狀態怎麼分、規則表怎麼比」，不是 AMI 的規格。"""
import copy
import struct
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
import fw_advisory_rules as fr  # noqa: E402
import uefi_image as ui  # noqa: E402
import x86_firmware as xf  # noqa: E402
from cdx_schema import cdx_validator  # noqa: E402
from test_fw_advisory_rules import AMI_PDF, build, doc, invalid, ok, rule  # noqa: E402
from test_uefi_gfx import bios_with, ffs_g, lzma_sec, props, sbom_of, walk  # noqa: E402
from test_x86_firmware import comp, fv, sec, secs  # noqa: E402

ami = xf.load_sibling("ami_core")
SUB = ami.SUBTYPE_GUID
G1 = "A1B2C3D4-0000-4000-8000-0000000000A1"
G2 = "A1B2C3D4-0000-4000-8000-0000000000A2"
G3 = "A1B2C3D4-0000-4000-8000-0000000000A3"
TS = (2023, 10, 7, 1, 2, 3)


def make_fid(tag=b"A5090", core=(5, 17), project=(34, 4), ts=TS, rev=4, length=120, fields=None, filler=0):
    """120 位元組的 `$FID` 紀錄（欄位位置見 ami_core.py）；fields 可整段換掉 +32..+44 的版本欄位。"""
    r = bytearray(max(length, 120))
    r[0:4] = b"$FID"
    r[4] = rev
    struct.pack_into("<H", r, 5, length)
    r[7:16] = tag.ljust(9, b"\0")
    r[16:32] = bytes([filler]) * 16
    if fields is None:
        fields = b"".join(b"%02d\0" % n for n in (*core, *project))
    r[32:44] = fields
    struct.pack_into("<HBBBBB", r, 44, *ts)
    r[51:53] = b"\xff\xff"
    return bytes(r)


def fidt(rec, length=156):
    """ACPI 表頭（36 位元組，簽章 FIDT）＋紀錄。"""
    return b"FIDT" + struct.pack("<I", length) + b"\0" * 28 + rec


def ffs_fid(rec=None, guid=G1):
    return ffs_g(guid, sec(0x18, SUB + (rec if rec is not None else make_fid())), ftype=0x02)


def fidt_file(rec=None, guid=G2):
    return ffs_g(guid, sec(0x19, fidt(rec if rec is not None else make_fid())), ftype=0x01)


def summ(major=5, minor=17, status="read", product="Aptio V", complete=False):
    return {"status": status, "major": major, "minor": minor, "core": f"{major}.{minor}", "product": product, "complete": complete}


# ---------- 結構檢查（ami_core.parse_record） ----------

def test_valid_record_fields():
    r = ami.parse_record(make_fid(tag=b"1AWQH340", core=(5, 17), project=(3, 40)), 0)
    assert r["ok"] and r["tag"] == "1AWQH340" and r["core"] == [5, 17] and r["project"] == [3, 40] and r["build"] == "2023-10-07T01:02:03"
    assert len(r["sha256"]) == 64


@pytest.mark.parametrize("kw,why", [
    ({"rev": 3}, "structure version"), ({"rev": 5}, "structure version"), ({"rev": 0}, "structure version"),
    ({"length": 0}, "length field"), ({"length": 119}, "length field"), ({"length": 121}, "length field"), ({"length": 0xFFFF}, "length field"),
    ({"tag": b""}, "BIOS tag"), ({"tag": b"A5\x01"}, "BIOS tag"), ({"tag": b"A5\n"}, "BIOS tag"), ({"tag": b"A5090\n"}, "BIOS tag"),
    ({"tag": b" A"}, "BIOS tag"), ({"tag": "tagé".encode()}, "BIOS tag"),
    ({"fields": b"5x\0" + b"17\0" + b"34\0" + b"04\0"}, "two ASCII digits"),
    ({"fields": b"05" + b"17\0" + b"34\0" + b"04\0" + b"\0"}, "two ASCII digits"),           # 05 後面少一個 NUL
    ({"fields": b"05\x01" + b"17\0" + b"34\0" + b"04\0"}, "two ASCII digits"),
    ({"fields": b"005" + b"17\0" + b"34\0" + b"04\0"}, "two ASCII digits"),
    ({"fields": b"05\0" + b"1\0\0" + b"34\0" + b"04\0"}, "two ASCII digits"),
    ({"fields": "５".encode() + b"17\0" + b"34\0" + b"04\0"}, "two ASCII digits"),               # 全角數字：str.isdigit() 會收，位元組檢查不會
    ({"fields": b"05\0" + b"17\0" + b"34\0" + b"0\n\0"}, "two ASCII digits"),
])
def test_invalid_records_are_refused(kw, why):
    rec = make_fid(**kw)
    r = ami.parse_record(rec, 0)
    assert not r["ok"] and why in r["why"] and r["head"] == rec[:ami.MAX_HEAD].hex()


def test_tag_of_nine_printable_characters_is_refused_and_eight_is_accepted():
    assert not ami.parse_record(make_fid(tag=b"123456789"), 0)["ok"]
    assert ami.parse_record(make_fid(tag=b"12345678"), 0)["ok"]


def test_truncated_record_is_refused_not_an_error():
    r = ami.parse_record(make_fid()[:80], 0)
    assert not r["ok"] and "truncated" in r["why"]


def test_unreasonable_build_time_is_left_out_but_the_record_is_valid():
    r = ami.parse_record(make_fid(ts=(1, 13, 40, 99, 99, 99)), 0)
    assert r["ok"] and r["build"] is None


# ---------- find_fid：前導、常數、上限 ----------

def test_find_fid_needs_the_subtype_guid_or_a_fidt_header():
    rec = make_fid()
    c = ami.find_fid(b"\0" * 8 + SUB + rec, "m")
    assert [(x["form"], x["offset"], x["ok"]) for x in c] == [("ffs-section", 24, True)]
    c = ami.find_fid(fidt(rec) + b"tail", "m")
    assert [(x["form"], x["offset"], x["ok"]) for x in c] == [("fidt-acpi", 36, True)]


def test_fid_constant_in_code_is_not_a_record():
    code = b"MZ" + b"\x90" * 64 + b"$FID" + b"\x04\x78\x00" + b"\x90" * 200            # 比對用的常數：前面沒有前導
    assert ami.find_fid(code, "code") == []
    assert ami.find_fid(b"$FID", "m") == [] and ami.find_fid(b"", "m") == []
    assert ami.find_fid(b"x" * 20 + b"$FID" + make_fid()[4:], "m") == []


def test_fidt_with_unreasonable_length_is_a_bad_candidate():
    for length in (0, 100, 155, 4097, 0xFFFFFFFF):
        c = ami.find_fid(fidt(make_fid(), length), "m")
        assert len(c) == 1 and not c[0]["ok"] and "FIDT table length" in c[0]["why"]
    assert ami.find_fid(fidt(make_fid(), 156), "m")[0]["ok"] and ami.find_fid(fidt(make_fid(), 4096), "m")[0]["ok"]


def test_candidate_count_per_block_is_capped():
    body = (SUB + make_fid()) * (ami.MAX_PER_BLOCK + 5)
    c = ami.find_fid(body, "m")
    assert len(c) == ami.MAX_PER_BLOCK + 1 and c[-1].get("truncated")


def test_trailing_newline_never_makes_a_value_valid():
    assert not ami.VER_RE.fullmatch(b"05\n") and not ami.TAG_RE.fullmatch(b"A5090\n\0\0\0")
    assert not ami.ADVISORY_RE.fullmatch("AptioV_5.044\n") and not fr.AMI_FIXED_RE.fullmatch("AptioV_5.044\n")


# ---------- summarize：狀態 ----------

def entries(*recs, form="ffs-section"):
    out = {}
    for i, rec in enumerate(recs):
        for c in ami.find_fid(SUB + rec if form == "ffs-section" else fidt(rec), "m"):
            e = out.setdefault(ami.entry_key(c), {x: v for x, v in c.items() if x not in ("offset", "module")} | {"seen": 0, "found": []})
            e["seen"] += 1
            e["found"].append({"module": f"M{i}", "form": c["form"], "offset": c["offset"]})
    return list(out.values())


def test_summarize_read_product_and_advisory_form():
    s = ami.summarize(entries(make_fid(core=(5, 17)), make_fid(core=(5, 17), tag=b"OTHER")))
    assert s["status"] == "read" and s["core"] == "5.17" and s["core_fid"] == "05.17" and s["product"] == "Aptio V" and s["advisory_form"] == "AptioV_5.017"
    assert s["tags"] == ["A5090", "OTHER"] and s["projects"] == ["34.04"] and s["count"] == 2 and s["complete"] is True    # tag 不同但 Core 相同：不矛盾
    s = ami.summarize(entries(make_fid(core=(5, 7))))
    assert s["advisory_form"] == "AptioV_5.007"


def test_summarize_core_major_other_than_5_has_version_but_no_product():
    s = ami.summarize(entries(make_fid(core=(4, 6))))
    assert s["status"] == "read" and s["core"] == "4.6" and s["product"] is None and s["advisory_form"] is None


def test_summarize_conflict_picks_nothing():
    s = ami.summarize(entries(make_fid(core=(5, 17)), make_fid(core=(5, 26), tag=b"B")))
    assert s["status"] == "conflict" and "core" not in s and {c["core"] for c in s["candidates"]} == {"5.17", "5.26"}
    assert all(c["tag"] and c["project"] and c["found"] for c in s["candidates"]) and "no value is chosen" in s["gaps"][0]


def test_summarize_layout_unknown_keeps_head_bytes_and_valid_one_wins_with_a_note():
    bad = make_fid(rev=9)
    s = ami.summarize(entries(bad))
    assert s["status"] == "layout-unknown" and s["bad"][0]["head"] == bad[:64].hex() and "first bytes" in s["gaps"][0]
    s = ami.summarize(entries(bad, make_fid()))
    assert s["status"] == "read" and "did not pass the structure check" in s["note"]


def test_summarize_not_found_wording_depends_on_completeness():
    s = ami.summarize([])
    assert s["status"] == "not-found" and "may still be recorded somewhere else" in s["gaps"][0] and "not found does not mean absent" not in s["gaps"][0]
    s = ami.summarize([], incomplete=["3 UEFI parts were not decoded"])
    assert not s["complete"] and "not found does not mean absent" in s["gaps"][0]
    assert ami.summarize([], truncated=True)["complete"] is False


def test_not_searched_summary():
    s = ami.not_searched("because")
    assert s["status"] == "not-searched" and not s["performed"] and not s["complete"] and "because" in s["gaps"][0]


# ---------- 走訪（uefi_gfx.scan）：合成 FV ----------

def test_walk_reads_ffs_form_and_reports_module_form_and_offset():
    r = walk(fv([ffs_fid()]))
    a = r["ami_core"]
    assert a["status"] == "read" and a["core"] == "5.17" and a["count"] == 1 and a["complete"]
    assert a["found"] == [f"{G1} ffs-section +0x10"]                           # 16 位元組子類型 GUID 之後
    assert a["tags"] == ["A5090"] and a["projects"] == ["34.04"] and a["build_dates"] == ["2023-10-07T01:02:03"]
    assert a["evidence_sha256"] == [ami.parse_record(make_fid(), 0)["sha256"]]


def test_walk_reads_fid_inside_lzma_and_fidt_form_together():
    inner = fv([fidt_file()])
    r = walk(fv([ffs_fid(), ffs_g(G3, secs(lzma_sec(secs(sec(0x17, inner)))), ftype=0x0B)]))
    a = r["ami_core"]
    assert a["status"] == "read" and a["count"] == 2 and a["forms"] == {"ffs-section": 1, "fidt-acpi": 1}
    assert any("fidt-acpi +0x24" in w for w in a["found"])


def test_walk_backup_copy_is_counted_and_not_a_conflict():
    one = fv([ffs_fid()])
    one += b"\xff" * (-len(one) % 8)
    a = walk(one + one)["ami_core"]
    assert a["status"] == "read" and a["count"] == 2 and a["valid"] == 1


def test_walk_same_core_with_different_tags_is_one_version():
    a = walk(fv([ffs_fid(make_fid(tag=b"1AWQH340", filler=1), G1), ffs_fid(make_fid(tag=b"1AWQG340", filler=2), G2)]))["ami_core"]
    assert a["status"] == "read" and a["tags"] == ["1AWQG340", "1AWQH340"] and a["count"] == 2


def test_walk_conflict_when_cores_differ():
    a = walk(fv([ffs_fid(make_fid(core=(5, 17)), G1), fidt_file(make_fid(core=(5, 26)), G2)]))["ami_core"]
    assert a["status"] == "conflict" and len(a["candidates"]) == 2


def test_walk_layout_unknown_when_only_bad_records():
    a = walk(fv([ffs_fid(make_fid(rev=9))]))["ami_core"]
    assert a["status"] == "layout-unknown" and a["bad"][0]["found"]


def test_walk_ignores_fid_constant_in_code_module():
    pe = b"MZ" + b"\0" * 62 + b"$FID" + b"\x04\x78\x00" + b"A5090".ljust(9, b"\0") + b"\0" * 400
    a = walk(fv([ffs_g(G1, sec(0x10, pe))]))["ami_core"]
    assert a["status"] == "not-found" and a["complete"]


def test_walk_not_found_complete_vs_incomplete():
    a = walk(fv([ffs_g(G1, sec(0x10, b"MZ" + b"\0" * 30))]))["ami_core"]
    assert a["status"] == "not-found" and a["complete"] and a["valid"] == 0
    a = walk(fv([ffs_g(G1, secs(comp(1, b"\x33" * 40), sec(0x10, b"MZ" + b"\0" * 30)))]))["ami_core"]       # EFI 標準壓縮：沒解開
    assert a["status"] == "not-found" and not a["complete"] and "not found does not mean absent" in a["gaps"][0]


def test_walk_read_but_incomplete_still_reads_and_says_so():
    a = walk(fv([ffs_g(G1, secs(comp(1, b"\x33" * 40))), ffs_fid()]))["ami_core"]
    assert a["status"] == "read" and not a["complete"] and a["incomplete"]


def test_walk_limit_stop_is_incomplete(monkeypatch):
    monkeypatch.setattr(ui, "MAX_FILES", 2)
    a = walk(fv([ffs_g(G1, sec(0x10, b"MZ" + bytes(8))) for _ in range(5)]))["ami_core"]
    assert not a["complete"] and any("limit reached" in x for x in a["incomplete"])


def test_walk_candidate_cap_is_incomplete(monkeypatch):
    gfx = xf.load_sibling("uefi_gfx")
    monkeypatch.setattr(gfx, "MAX_FOUND", 2)
    a = walk(fv([ffs_fid(make_fid(filler=i), f"A1B2C3D4-0000-4000-8000-0000000001{i:02d}") for i in range(4)]))["ami_core"]
    assert a["valid"] == 2 and not a["complete"] and any("search limit" in x for x in a["incomplete"])


def test_walk_failure_to_load_ami_core_is_not_searched(monkeypatch):
    gfx = xf.load_sibling("uefi_gfx")
    real = gfx._sibling
    monkeypatch.setattr(gfx, "_sibling", lambda n: (_ for _ in ()).throw(ImportError("x")) if n == "ami_core" else real(n))
    r = walk(fv([ffs_fid()]))
    assert r["ami_core"]["status"] == "not-searched" and r["performed"]


def test_walk_cbfs_flag_makes_the_search_incomplete():
    a = walk(fv([ffs_fid()]), cbfs=True)["ami_core"]
    assert a["status"] == "read" and not a["complete"] and any("CBFS" in x for x in a["incomplete"])


# ---------- 規則表：cond_ami、evaluate、validate ----------

AMI_COND = {"component": "ami_core", "product": "Aptio V", "fixed_in": "AptioV_5.044"}


def cond(a, c=AMI_COND):
    return fr.evaluate_condition(None, c, {"ami": True, "ami_core": a})


def test_core_below_fixed_in_is_affected_with_the_three_statements():
    r = cond(summ(5, 17))
    assert r["result"] == "affected" and r["reason"] is None
    d = r["detail"]
    assert "base version" in d and "back-ported by the board vendor cannot be seen" in d                      # 1. 基底版本、回補看不出來
    assert "(A1)" in d and "not yet confirmed by AMI or the board vendor" in d                                # 2. A1 未確認
    assert "lead for the responsible unit" in d and "not a vulnerability determination" in d                  # 3. 線索不是判定
    assert "5.017 < 5.044" in d and "unsigned" in d


@pytest.mark.parametrize("minor", [44, 45, 99])
def test_core_not_below_fixed_in_is_always_not_assessed_never_not_affected(minor):
    for complete in (True, False):
        r = cond(summ(5, minor, complete=complete))
        assert (r["result"], r["reason"]) == ("NOT_ASSESSED", "ami-core-mapping-unverified")
        assert "not-affected" not in r["result"]


def test_core_minor_boundary_43_is_affected_44_is_not():
    assert cond(summ(5, 43))["result"] == "affected" and cond(summ(5, 44))["result"] == "NOT_ASSESSED"
    assert cond(summ(5, 0))["result"] == "affected"


@pytest.mark.parametrize("status,reason", [("not-found", "no-ami-core-version"), ("not-searched", "no-ami-core-version"),
                                           ("conflict", "ami-core-conflict"), ("layout-unknown", "ami-fid-layout-unknown")])
def test_status_other_than_read_is_not_assessed_with_the_status_reason(status, reason):
    r = cond({"status": status, "product": None})
    assert (r["result"], r["reason"]) == ("NOT_ASSESSED", reason)


def test_no_ami_core_data_is_the_old_behaviour():
    for comp_ in ({"ami": True}, {"ami": True, "ami_core": None}, {"ami": True, "ami_core": {}}, {"ami": True, "core_version": "AptioV_5.099"}):
        r = fr.evaluate_condition(None, AMI_COND, comp_)
        assert (r["result"], r["reason"]) == ("NOT_ASSESSED", "no-ami-core-version")


def test_no_product_is_not_assessed_even_when_the_number_is_low():
    r = cond(summ(4, 6, product=None))
    assert (r["result"], r["reason"]) == ("NOT_ASSESSED", "ami-product-unknown")


def test_cross_major_is_not_compared():
    r = cond(summ(4, 6))                                  # product 是 Aptio V（人為組合）、major 與 fixed_in 不同
    assert (r["result"], r["reason"]) == ("NOT_ASSESSED", "ami-core-line-differs")
    r = cond(summ(6, 1))
    assert r["reason"] == "ami-core-line-differs"


def test_product_is_normalized_and_other_product_is_out_of_scope():
    for p in ("AptioV", "aptio  v", "APTIO V", " Aptio V "):
        assert cond(summ(5, 17, product=p))["result"] == "affected"
    r = cond(summ(5, 17, product="Aptio IV"))
    assert r["result"] == fr.OUT
    r = cond(summ(5, 17), {"component": "ami_core", "product": "Other"})
    assert r["result"] == fr.OUT


def test_rule_without_fixed_in_is_not_assessed():
    r = cond(summ(5, 17), {"component": "ami_core", "product": "Aptio V"})
    assert (r["result"], r["reason"]) == ("NOT_ASSESSED", "rule-has-no-fixed-in")


@pytest.mark.parametrize("bad", ["AptioV_5.44", "AptioV_5.0440", "5.044", "AptioV_5.044\n", "aptiov_5.044", "AptioV_55.044", "AptioV_5.04a", "AptioV_5.044 "])
def test_validate_rejects_malformed_fixed_in(tmp_path, bad):
    invalid(tmp_path, doc(rule("AMI-SA-2026001", [{"component": "ami_core", "product": "Aptio V", "fixed_in": bad}], "AMI", url=AMI_PDF)))


def test_validate_accepts_the_three_digit_form(tmp_path):
    ok(tmp_path, doc(rule("AMI-SA-2026001", [{"component": "ami_core", "product": "Aptio V", "fixed_in": "AptioV_5.044"}], "AMI", url=AMI_PDF)))


@pytest.fixture(scope="module")
def table():
    t, err = fr.load_default()
    assert err is None
    return t


def test_evaluate_against_the_shipped_table_gives_affected_for_both_ami_rules(table):
    r = fr.evaluate(table, "ami_core", {"ami": True, "ami_core": summ(5, 17)})
    assert r["suggestion"] == "affected" and r["rule_ids"] == ["AMI-SA-2026001", "AMI-SA-2026002"] and r["state"] == "preliminary" and r["related"] == []
    assert "back-ported" in r["basis"] and "(A1)" in r["basis"] and "not a vulnerability determination" in r["basis"]
    r = fr.evaluate(table, "ami_core", {"ami": True, "ami_core": summ(5, 44)})
    assert r["suggestion"] == "NOT_ASSESSED" and r["reason"] == "ami-core-mapping-unverified" and r["rule_ids"] == [] and r["evidence"] == []
    assert not any(x["result"] == "not-affected" for x in r["results"])


def test_bios_image_does_not_compare_ami_rules_when_the_core_component_exists(table):
    base = {"file": "x.CAP", "declared_version": None, "ami": True}
    r = fr.evaluate(table, "bios_image", {**base, "ami_core": summ(5, 17), "ami_core_component": True})
    assert r["suggestion"] == "NOT_ASSESSED" and r["rule_ids"] == [] and r["related"] == [] and r["reason"] == "no-rule"
    r = fr.evaluate(table, "bios_image", {**base, "ami_core": {"status": "conflict"}, "ami_core_component": False})
    assert r["reason"] == "ami-core-conflict" and r["related"] == ["AMI-SA-2026001", "AMI-SA-2026002"]
    r = fr.evaluate(table, "bios_image", base)                         # 沒有核心資料：維持現狀
    assert r["reason"] == "no-ami-core-version" and r["related"] == ["AMI-SA-2026001", "AMI-SA-2026002"]


def test_table_file_is_unchanged_by_this_feature():
    import hashlib
    assert hashlib.sha256(fr.TABLE_PATH.read_bytes()).hexdigest() == fr.TABLE_SHA256


# ---------- SBOM 與報告（合成映像） ----------

def without_hint(data):
    """spi_image 的 BIOS 區域有 `ALASKA`（AMI 的線索）：換掉，得到沒有 AMI 線索的映像。"""
    return bytes(data).replace(b"ALASKA", b"XXXXXX")


def ami_comp(comps):
    return next((c for c in comps if c["name"] in (xf.AMI_NAME, xf.AMI_NAME_NO_PRODUCT)), None)


def test_sbom_has_the_core_component_under_the_bios_image_with_basis_and_suggestion(tmp_path):
    inv, comps, deps = sbom_of(tmp_path, bios_with(fv([ffs_fid(), fidt_file()])))
    c = ami_comp(comps)
    bios = next(x for x in comps if x["name"] == "BIOS.bin")
    assert c["name"] == "AMI Aptio V core" and c["version"] == "5.17" and c["type"] == "firmware" and c["manufacturer"] == {"name": "American Megatrends"}
    assert c["bom-ref"] in deps[bios["bom-ref"]] and "hashes" not in c
    p = lambda n: props(c, n)                                          # noqa: E731
    assert "self-declared by the image (no signature check)" in p("sca-center:version-basis")[0] and "inferred from public images" in p("sca-center:version-basis")[0]
    assert p("sca-center:ami-core-fid") == ["05.17"] and p("sca-center:ami-core-product") == ["Aptio V"] and "major version 5" in p("sca-center:ami-core-product-basis")[0]
    assert p("sca-center:ami-core-advisory-form") == ["AptioV_5.017"] and "A1" in p("sca-center:ami-core-advisory-form-basis")[0]
    assert p("sca-center:ami-fid-bios-tag") == ["A5090"] and p("sca-center:ami-fid-project-version") == ["34.04"] and p("sca-center:build-date") == ["2023-10-07T01:02:03"]
    assert p("sca-center:count") == ["2"] and len(p("sca-center:found-in")) == 2 and len(p("sca-center:evidence-sha256")) == 1
    assert p("dumpling:vuln-assessment") == ["NOT_ASSESSED"] and p("dumpling:version-status") == ["OK"]
    assert p("dumpling:vuln-assessment-note") == [xf.ASSESS_NOTES["ami"]]
    assert p("dumpling:advisory-rule-suggestion") == ["affected"] and p("dumpling:advisory-rule-ids") == ["AMI-SA-2026001, AMI-SA-2026002"]
    assert p("dumpling:advisory-rule-state") == ["preliminary"] and "not a vulnerability determination" in p("dumpling:advisory-rule-basis")[0]
    assert p("sca-center:incomplete") == []                           # 走訪完整時不寫
    assert props(bios, "sca-center:ami-core-search")[0].startswith("read: core 5.17 from 2 Firmware ID record(s)")
    assert props(bios, "dumpling:advisory-rule-related") == [] and props(bios, "dumpling:advisory-rule-suggestion") == ["NOT_ASSESSED"]
    assert not any(w in str(comps) for w in ("PASS", "安全", "不適用", "不受影響"))


def test_sbom_incomplete_walk_marks_the_component(tmp_path):
    inv, comps, _ = sbom_of(tmp_path, bios_with(fv([ffs_g(G3, secs(comp(1, b"\x33" * 40))), ffs_fid()])))
    c = ami_comp(comps)
    assert "the search was incomplete" in props(c, "sca-center:incomplete")[0] and "different core" in props(c, "sca-center:incomplete")[0]


def test_report_and_status_for_an_affected_core(tmp_path):
    inv, comps, _ = sbom_of(tmp_path, bios_with(fv([ffs_fid()])))
    st, detail = xf.status_of(inv)
    assert st == "ATTENTION" and "規則表建議 affected" in detail and "AMI-SA-2026001" in detail
    md = xf.markdown(inv)
    assert "### AMI 核心版本（Firmware ID 紀錄 `$FID`）" in md and "沒有簽章驗證" in md and "5.017" in md
    for s in ("基底版本，板廠回補的修正在映像裡看不出來", "（A1）尚未經 AMI 或板廠確認", "請負責單位對照板廠公告的線索，不是漏洞判定", "不輸出 not-affected"):
        assert s.replace("**", "") in md.replace("**", ""), s
    assert not any(w in md for w in ("不受影響", "不適用"))
    ra = inv["rules_advisory"]
    assert [x["rule_ids"] for x in ra["items"] if x["kind"] == "ami_core"] == [["AMI-SA-2026001", "AMI-SA-2026002"]]
    assert sum(1 for x in ra["items"] if x["suggestion"] == "affected") == 1            # 同一組規則不出兩個建議（bios_image 不重複比）


def test_core_not_below_fixed_in_gives_no_not_affected_anywhere(tmp_path):
    inv, comps, _ = sbom_of(tmp_path, bios_with(fv([ffs_fid(make_fid(core=(5, 44)))])))
    c = ami_comp(comps)
    assert c["version"] == "5.44" and props(c, "dumpling:advisory-rule-suggestion") == ["NOT_ASSESSED"]
    assert props(c, "dumpling:advisory-rule-reason") == ["ami-core-mapping-unverified"] and props(c, "dumpling:evidence") == []
    assert not any(p["value"] == "not-affected" for x in comps for p in x["properties"])
    assert inv["rules_advisory"]["counts"].get("not-affected") is None
    assert "ami-core-mapping-unverified" in xf.markdown(inv)


def test_core_major_other_than_5_has_no_product_name_and_not_assessed(tmp_path):
    inv, comps, _ = sbom_of(tmp_path, bios_with(fv([ffs_fid(make_fid(core=(4, 6)))])))
    c = ami_comp(comps)
    assert c["name"] == "AMI firmware core" and c["version"] == "4.6"
    assert props(c, "sca-center:ami-core-product") == [] and props(c, "sca-center:ami-core-advisory-form") == [] and "no product is assumed" in props(c, "sca-center:note")[0]
    assert props(c, "dumpling:advisory-rule-reason") == ["ami-product-unknown"]


def test_conflict_has_no_component_no_version_and_attention(tmp_path):
    inv, comps, _ = sbom_of(tmp_path, bios_with(fv([ffs_fid(make_fid(core=(5, 17)), G1), ffs_fid(make_fid(core=(5, 26)), G2)])))
    assert ami_comp(comps) is None
    bios = next(x for x in comps if x["name"] == "BIOS.bin")
    assert props(bios, "sca-center:ami-core-search")[0].startswith("conflict") and any("no value is chosen" in x for x in props(bios, "sca-center:gap"))
    assert props(bios, "dumpling:advisory-rule-reason") == ["ami-core-conflict"]
    st, detail = xf.status_of(inv)
    assert st == "ATTENTION" and "互相矛盾" in detail
    assert "5.17" in str(inv["bios"][0]["ami_core"]["candidates"]) and "5.26" in str(inv["bios"][0]["ami_core"]["candidates"])


def test_layout_unknown_has_no_component_and_a_gap_with_the_bytes(tmp_path):
    bad = make_fid(rev=9)
    inv, comps, _ = sbom_of(tmp_path, bios_with(fv([ffs_fid(bad)])))
    assert ami_comp(comps) is None
    bios = next(x for x in comps if x["name"] == "BIOS.bin")
    assert props(bios, "sca-center:ami-core-search")[0].startswith("layout-unknown") and any(bad[:64].hex() in x for x in props(bios, "sca-center:gap"))
    assert props(bios, "dumpling:advisory-rule-reason") == ["ami-fid-layout-unknown"]
    assert xf.status_of(inv)[0] == "ATTENTION"


def test_non_ami_image_not_found_has_the_search_property_but_no_gap_or_status_change(tmp_path):
    inv, comps, _ = sbom_of(tmp_path, without_hint(bios_with(fv([ffs_g(G1, sec(0x10, b"MZ" + b"\0" * 30))]))))
    bios = next(x for x in comps if x["name"] == "BIOS.bin")
    assert ami_comp(comps) is None and props(bios, "sca-center:ami-core-search")[0].startswith("not-found")
    assert not any("AMI core" in x for x in props(bios, "sca-center:gap"))
    assert "AMI" not in (inv["bios"][0]["ibv_hint"] or [])
    assert props(bios, "dumpling:advisory-rule-related") == []


def test_ami_hinted_image_without_a_core_gets_a_gap(tmp_path):
    inv, comps, _ = sbom_of(tmp_path, bios_with(fv([ffs_g(G1, sec(0x10, b"MZ" + b"\0" * 30))])))          # spi_image 有 ALASKA
    bios = next(x for x in comps if x["name"] == "BIOS.bin")
    assert "AMI" in inv["bios"][0]["ibv_hint"]
    assert any("AMI core version" in x and "not found" in x for x in props(bios, "sca-center:gap"))
    assert props(bios, "dumpling:advisory-rule-related") == ["AMI-SA-2026001, AMI-SA-2026002"]
    assert "AMI" not in xf.status_of(inv)[1]                          # 沒找到：缺口在 sca-center:gap，狀態說明沒有 AMI 專屬的項目


def test_image_without_firmware_volumes_is_not_searched():
    b = {"uefi": {"volumes": 0}, "evidence": ["uefi"], "gaps": [], "file": "x", "ibv_hint": ["AMI"]}
    xf.uefi_gfx_search(b, "x", b"", None, {}, [])
    assert b["ami_core"]["status"] == "not-searched" and any("AMI core version" in g for g in b["gaps"])
    b2 = {"uefi": {"volumes": 0}, "evidence": ["cbfs"], "gaps": [], "file": "x", "ibv_hint": []}
    xf.uefi_gfx_search(b2, "x", b"", None, {}, [])
    assert b2["ami_core"]["status"] == "not-searched" and not any("AMI core" in g for g in b2["gaps"])


def test_sbom_with_core_component_passes_the_cyclonedx_schema(tmp_path):
    for fvdata in (fv([ffs_fid()]), fv([ffs_fid(make_fid(core=(4, 6)))]), fv([ffs_fid(make_fid(rev=9))])):
        _, comps, deps = sbom_of(tmp_path, bios_with(fvdata))          # sbom_of 內含 cdx_validator 檢查
        refs = [c["bom-ref"] for c in comps]
        assert len(refs) == len(set(refs))


def test_json_inventory_is_serializable_and_has_the_summary(tmp_path):
    import json
    inv, _, _ = sbom_of(tmp_path, bios_with(fv([ffs_fid()])))
    json.dumps(inv)
    assert inv["bios"][0]["ami_core"]["status"] == "read"


# ---------- 版本清單 ibv-core 核對 ----------

def row(version, comp_="ibv-core"):
    return {"line": 2, "product": "p", "firmware": "f", "firmware_version": "1", "component": comp_, "identifier": "", "version": version, "date": "", "vendor": "", "note": ""}


def compare_for(tmp_path, rows, fvdata=None):
    inv, _, _ = sbom_of(tmp_path, bios_with(fvdata or fv([ffs_fid()])))
    return [c for c in xf.compare(inv, rows) if c["component"] == "ibv-core"]


@pytest.mark.parametrize("declared", ["Aptio V 5.17", "AptioV_5.017", "5.17", "Aptio V 5.017", "AptioV5.17"])
def test_ibv_core_list_entry_matches_in_integers(tmp_path, declared):
    r = compare_for(tmp_path, [row(declared)])
    assert [(c["result"], c["verifiable"]) for c in r] == [("match", True)] and r[0]["extracted"] == "5.17"


def test_ibv_core_mismatch_declared_only_and_extracted_only(tmp_path):
    r = compare_for(tmp_path, [row("Aptio V 5.27")])
    assert [c["result"] for c in r] == ["mismatch"] and r[0]["extracted"] == "5.17"
    r = compare_for(tmp_path, [row("Insyde H2O 5.2")])                            # 寫法讀不懂：不比、不算可核對（映像讀到的核心另列 extracted-only）
    assert [(c["result"], c["verifiable"]) for c in r] == [("declared-only", False), ("extracted-only", True)]
    r = compare_for(tmp_path, [row("Aptio V 5.17", "me")])                         # 清單沒有 ibv-core：只有映像
    assert [(c["result"], c["extracted"]) for c in r] == [("extracted-only", "5.17")]
    r = compare_for(tmp_path, [row("Aptio V 5.17")], fv([ffs_g(G1, sec(0x10, b"MZ" + bytes(8)))]))     # 映像讀不到
    assert [(c["result"], c["verifiable"]) for c in r] == [("declared-only", True)]
    r = compare_for(tmp_path, [row("不知道")])
    assert [c["result"] for c in r] == ["unknown"]


def test_ibv_core_comparison_is_not_made_for_conflicting_cores(tmp_path):
    r = compare_for(tmp_path, [row("Aptio V 5.17")], fv([ffs_fid(make_fid(core=(5, 17)), G1), ffs_fid(make_fid(core=(5, 26)), G2)]))
    assert [(c["result"], c["verifiable"]) for c in r] == [("declared-only", True)]


def test_parse_ibv_core_formats():
    assert xf.parse_ibv_core("Aptio V 5.27") == (5, 27) and xf.parse_ibv_core("AptioV_5.044") == (5, 44) and xf.parse_ibv_core("5.2") is None
    assert xf.parse_ibv_core("Aptio V 5.27\n") is None and xf.parse_ibv_core("InsydeH2O 5.27") is None and xf.parse_ibv_core(None) is None


# ---------- 混合條件、輸入型別、不完整的標註 ----------

def test_rule_with_an_ami_core_condition_never_gives_not_affected_from_another_condition(tmp_path):
    """同一筆規則有 ami_core 與 bios_image 條件：bios_image 條件單獨判出的 not-affected 也降成 NOT_ASSESSED，不帶 vendor-statement。"""
    r = rule("AMI-SA-2026001", [{"component": "ami_core", "product": "Aptio V", "fixed_in": "AptioV_5.044"},
                                {"component": "bios_image", "name_prefix": "PRIME", "fixed_in": "1.0"}], "AMI", url=AMI_PDF)
    t = build(tmp_path, doc(r))
    a = {"status": "read", "major": 5, "minor": 17, "product": "Aptio V", "complete": True}
    base = {"file": "PRIME.cap", "declared_version": "9.0", "ami": True, "ami_core": a}
    res = fr.evaluate(t, "bios_image", {**base, "ami_core_component": True})            # 有核心元件：bios_image 條件單獨比，宣告版本 9.0 不低於 1.0
    assert res["suggestion"] == "NOT_ASSESSED" and res["reason"] == "ami-core-mapping-unverified" and res["rule_ids"] == [] and res["evidence"] == []
    assert not any(x["result"] == "not-affected" for x in res["results"])
    res = fr.evaluate(t, "bios_image", {**base, "declared_version": "0.5", "ami_core_component": True})       # 宣告版本低於 1.0：affected 照舊
    assert res["suggestion"] == "affected" and res["rule_ids"] == ["AMI-SA-2026001"]
    res = fr.evaluate(t, "bios_image", {**base, "ami_core_component": False})
    assert res["suggestion"] == "affected"                                          # 沒有核心元件時 ami_core 條件的 affected 照舊
    res = fr.evaluate(t, "ami_core", {"ami": True, "ami_core": {**a, "minor": 50}})
    assert res["suggestion"] == "NOT_ASSESSED" and res["reason"] == "ami-core-mapping-unverified"
    # 沒有 ami_core 條件的規則：not-affected 照舊（保險只針對 AMI 規則）
    other = rule("AMD-SB-7014", [{"component": "bios_image", "name_prefix": "PRIME", "fixed_in": "1.0"}])
    res = fr.evaluate(build(tmp_path, doc(other), "o.json"), "bios_image", {"file": "PRIME.cap", "declared_version": "9.0"})
    assert res["suggestion"] == "not-affected"


@pytest.mark.parametrize("status", [None, 5, ["read"], {"read": 1}, b"read", 1.5, True, ("read",)])
def test_non_string_status_is_not_assessed_not_an_exception(status):
    r = cond({"status": status, "major": 5, "minor": 17, "product": "Aptio V"})
    assert (r["result"], r["reason"]) == ("NOT_ASSESSED", "no-ami-core-version")
    for bad in ({"status": "read"}, {"status": "read", "major": "5", "minor": 17, "product": "Aptio V"}, {"status": "read", "major": True, "minor": 1}):
        assert cond(bad)["result"] == "NOT_ASSESSED"


def test_affected_detail_says_when_the_search_was_incomplete():
    r = cond({**summ(5, 17, complete=False), "incomplete": ["2 UEFI parts were not decoded (x)"]})
    assert r["result"] == "affected" and "may hold records with a different core version" in r["detail"] and "2 UEFI parts were not decoded" in r["detail"]
    assert "different core version" not in cond(summ(5, 17, complete=True))["detail"]
    assert "no reason recorded" in cond(summ(5, 17, complete=False))["detail"]


def test_sbom_and_report_say_so_for_an_affected_core_when_the_walk_was_incomplete(tmp_path):
    inv, comps, _ = sbom_of(tmp_path, bios_with(fv([ffs_g(G3, secs(comp(1, b"\x33" * 40))), ffs_fid()])))
    c = ami_comp(comps)
    assert props(c, "dumpling:advisory-rule-suggestion") == ["affected"]
    assert "may hold records with a different core version" in props(c, "dumpling:advisory-rule-basis")[0]
    md = xf.markdown(inv)
    assert "沒解開的部分可能還有核心版本不同的紀錄" in md
    inv, comps, _ = sbom_of(tmp_path, bios_with(fv([ffs_fid()])), "clean.bin")
    assert "different core version" not in props(ami_comp(comps), "dumpling:advisory-rule-basis")[0]
    assert "沒解開的部分可能還有核心版本不同的紀錄" not in xf.markdown(inv)


def test_read_with_a_malformed_candidate_is_incomplete_and_says_so_in_the_basis(tmp_path):
    a = walk(fv([ffs_fid(make_fid(rev=3, core=(5, 50)), G1), ffs_fid(make_fid(), G2)]))["ami_core"]
    assert a["status"] == "read" and a["core"] == "5.17" and a["complete"] is False
    assert any("do not match the known layout" in x for x in a["incomplete"]) and "did not pass the structure check" in a["note"]
    inv, comps, _ = sbom_of(tmp_path, bios_with(fv([ffs_fid(make_fid(rev=3, core=(5, 50)), G1), ffs_fid(make_fid(), G2)])))
    c = ami_comp(comps)
    assert props(c, "dumpling:advisory-rule-suggestion") == ["affected"]
    assert "do not match the known layout" in props(c, "dumpling:advisory-rule-basis")[0]
    assert "do not match the known layout" in props(c, "sca-center:incomplete")[0]


def test_found_in_has_no_identical_lines(tmp_path):
    """位置相同、內容不同的紀錄（例如兩個備份 FV 的 16 位元組欄位不同）：位置只列一次，份數在 count，各份雜湊在 evidence-sha256。"""
    d = fv([ffs_fid(make_fid(tag=b"1AWQH340", filler=1), G1)])
    d += b"\xff" * (-len(d) % 8)
    d += fv([ffs_fid(make_fid(tag=b"1AWQG340", filler=2), G1)])
    a = walk(d)["ami_core"]
    assert a["count"] == 2 and len(a["evidence_sha256"]) == 2 and a["found"] == [f"{G1} ffs-section +0x10"]
    inv, comps, _ = sbom_of(tmp_path, bios_with(d))
    c = ami_comp(comps)
    f = props(c, "sca-center:found-in")
    assert len(f) == len(set(f)) == 1 and props(c, "sca-center:count") == ["2"] and len(props(c, "sca-center:evidence-sha256")) == 2
    md = xf.markdown(inv)
    assert md.count(f"{G1} ffs-section +0x10") == 1 or f"{G1} ffs-section +0x10、{G1}" not in md


def test_report_section_for_non_ami_image_is_not_a_gap_but_for_ami_hint_it_is(tmp_path):
    inv, _, _ = sbom_of(tmp_path, without_hint(bios_with(fv([ffs_g(G1, sec(0x10, b"MZ" + b"\0" * 30))]))))
    sec_ = xf.markdown(inv).split("### AMI 核心版本")[1].split("\n### ")[0]
    assert "not-found" in sec_ and "GAP" not in sec_ and "- 說明：" in sec_
    inv, _, _ = sbom_of(tmp_path, bios_with(fv([ffs_g(G1, sec(0x10, b"MZ" + b"\0" * 30))])), "hint.bin")
    sec_ = xf.markdown(inv).split("### AMI 核心版本")[1].split("\n### ")[0]
    assert "- GAP：" in sec_


# ---------- 變異測試存活項目 ----------

def test_complete_is_false_for_notes_parse_errors_cap_and_no_firmware_volume(monkeypatch):
    gfx = xf.load_sibling("uefi_gfx")
    real = ui.parse_fvs

    def with_note(data, sc, depth, *args, **kw):
        real(data, sc, depth, *args, **kw)
        sc.notes.append("synthetic structure note")
    monkeypatch.setattr(ui, "parse_fvs", with_note)
    a = walk(fv([ffs_fid()]))["ami_core"]
    assert a["status"] == "read" and a["complete"] is False and any("structure warnings" in x for x in a["incomplete"])
    monkeypatch.setattr(ui, "parse_fvs", real)

    def with_error(data, sc, depth, *args, **kw):
        real(data, sc, depth, *args, **kw)
        sc.parse_errors += 1
    monkeypatch.setattr(ui, "parse_fvs", with_error)
    a = walk(fv([ffs_fid()]))["ami_core"]
    assert a["status"] == "read" and a["complete"] is False and any("structure warnings" in x for x in a["incomplete"])
    monkeypatch.setattr(ui, "parse_fvs", real)
    monkeypatch.setattr(gfx, "MAX_INSPECT", 4096)
    a = walk(fv([ffs_g(G1, sec(0x10, bytes([i]) * 600)) for i in range(20)] + [ffs_fid()]))["ami_core"]
    assert a["complete"] is False and any("was not searched" in x for x in a["incomplete"])
    monkeypatch.undo()
    a = walk(b"\0" * 4096)["ami_core"]
    assert a["status"] == "not-found" and a["complete"] is False and any("no valid UEFI firmware volume" in x for x in a["incomplete"])
    assert walk(fv([ffs_fid()]))["ami_core"]["complete"] is True


def test_component_advisory_match_is_not_assessed(tmp_path):
    _, comps, _ = sbom_of(tmp_path, bios_with(fv([ffs_fid()])))
    c = ami_comp(comps)
    assert props(c, "dumpling:advisory-match") == ["NOT_ASSESSED"] and "AMI-SA" in props(c, "dumpling:advisory-basis")[0]


@pytest.mark.parametrize("junk", [b"\xc3\xa9\0", b"\xff\xfe\0", b"\xe0\xa5\0", b"\x80\x80\0"])
def test_version_field_of_two_non_ascii_bytes_and_nul_is_refused(junk):
    fields = b"05\0" + b"17\0" + b"34\0" + junk
    r = ami.parse_record(make_fid(fields=fields), 0)
    assert not r["ok"] and "two ASCII digits" in r["why"]
    fields = junk + b"17\0" + b"34\0" + b"04\0"
    assert not ami.parse_record(make_fid(fields=fields), 0)["ok"]


def test_conflict_and_layout_unknown_are_attention_even_without_an_ami_hint(tmp_path):
    for fvdata in (fv([ffs_fid(make_fid(core=(5, 17)), G1), ffs_fid(make_fid(core=(5, 26)), G2)]), fv([ffs_fid(make_fid(rev=9))])):
        inv, comps, _ = sbom_of(tmp_path, without_hint(bios_with(fvdata)), "x%d.bin" % len(fvdata))
        assert "AMI" not in (inv["bios"][0]["ibv_hint"] or [])
        st, detail = xf.status_of(inv)
        assert st == "ATTENTION" and ("互相矛盾" in detail or "結構不是已知的" in detail)
        bios = next(x for x in comps if x["name"].startswith("x"))
        assert any("AMI core version" in g for g in props(bios, "sca-center:gap"))
        assert "- GAP：" in xf.markdown(inv).split("### AMI 核心版本")[1].split("\n### ")[0]


def test_cbfs_flag_reaches_the_search_through_uefi_gfx_search():
    b = {"uefi": {"volumes": 1}, "evidence": ["uefi", "cbfs"], "gaps": [], "file": "x", "ibv_hint": ["AMI"], "cbfs": {"fsp": []}}
    xf.uefi_gfx_search(b, "x", fv([ffs_fid()]), None, {}, [])
    assert b["ami_core"]["status"] == "read" and b["ami_core"]["complete"] is False and any("CBFS" in x for x in b["ami_core"]["incomplete"])
    assert "ami_core" not in b["uefi_gfx"]
    b2 = {"uefi": {"volumes": 1}, "evidence": ["uefi"], "gaps": [], "file": "x", "ibv_hint": ["AMI"], "cbfs": None}
    xf.uefi_gfx_search(b2, "x", fv([ffs_fid()]), None, {}, [])
    assert b2["ami_core"]["complete"] is True


def test_result_does_not_depend_on_order_or_backup_copies():
    import itertools

    def sig(r):
        a = r["ami_core"]
        return (a["status"], a.get("core"), a["valid"], a["invalid"], a["count"], a["complete"], tuple(a.get("tags", [])), tuple(sorted(a.get("found", []))))
    files = [ffs_fid(make_fid(tag=b"T0"), G1), fidt_file(make_fid(tag=b"T1"), G2), ffs_fid(make_fid(tag=b"T2", filler=3), G3)]
    ref = sig(walk(fv(files)))
    assert ref[0] == "read" and ref[1] == "5.17"
    for perm in itertools.permutations(files):
        assert sig(walk(fv(list(perm)))) == ref
    one = fv(files)
    one += b"\xff" * (-len(one) % 8)
    back_first = walk(fv(list(reversed(files))) + b"\xff" * (-len(fv(list(reversed(files)))) % 8) + one)["ami_core"]
    assert back_first["status"] == "read" and back_first["core"] == "5.17" and back_first["valid"] == ref[2] and back_first["count"] == 2 * ref[4]
    # 不同核心不論順序都是 conflict
    a, b = fv([ffs_fid(make_fid(core=(5, 17)), G1)]), fv([ffs_fid(make_fid(core=(5, 44)), G2)])
    for d in (a + b"\xff" * (-len(a) % 8) + b, b + b"\xff" * (-len(b) % 8) + a):
        r = walk(d)["ami_core"]
        assert r["status"] == "conflict" and "core" not in r
