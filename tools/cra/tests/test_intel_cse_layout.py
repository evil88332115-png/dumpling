"""intel_cse_layout.py（CSE layout table → BPDT → FTPR／RBEP／NFTP 的 manifest）與 x86_firmware.me_info 的接線。
測資全部由測試當場合成（欄位依模組 docstring 列的公開格式說明），不含任何真實映像的位元組。"""
import random
import struct
import sys
import zlib
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import intel_cse_layout as cl  # noqa: E402
import x86_firmware as xf  # noqa: E402
from test_x86_firmware import me_region, spi_image, with_me  # noqa: E402

REGION = 0x6000           # spi_image 的 ME 區域 0x1000–0x6FFF
VER = (18, 0, 10, 2285)
VERS = "18.0.10.2285"


def mn2(ver=VER, date=0x20240714, vendor=0x8086, tag=b"$MN2"):
    h = bytearray(0x80)
    struct.pack_into("<I", h, 0x10, vendor)
    struct.pack_into("<I", h, 0x14, date)
    h[0x1C:0x20] = tag
    struct.pack_into("<4H", h, 0x24, *ver)
    return bytes(h)


def partition(name, ver=VER, hv=2, man=None, man_off=0x80, man_len=0x80, ent_off=None, raw_flags=0, cnt=None, ck="ok", pname=None, hl=None, tag=b"$CPD"):
    """`$CPD` 分割區：header＋項目表＋manifest。man＝manifest 項目的名稱（預設 <name>.man）。"""
    hl = hl or (0x10 if hv == 1 else 0x14)
    ents = [(man or f"{name}.man", (man_off if ent_off is None else ent_off) | (raw_flags << 25), man_len), ("other.bin", 0x100, 0x10)]
    n = len(ents) if cnt is None else cnt
    body = bytearray(0x200)
    body[0:4] = tag
    struct.pack_into("<I", body, 4, n)
    body[8], body[9], body[0x0A] = hv, 1, hl
    body[0x0C:0x10] = (pname or name).encode().ljust(4, b"\x00")
    for i, (en, off, ln) in enumerate(ents):
        o = hl + 0x18 * i
        body[o:o + 12] = en.encode().ljust(12, b"\x00")
        struct.pack_into("<III", body, o + 12, off, ln, 0)
    body[man_off:man_off + 0x80] = mn2(ver)
    tab = hl + 0x18 * len(ents)
    if hv == 1:
        body[0x0B] = 0
        body[0x0B] = (-sum(body[:tab])) & 0xFF
        if ck == "bad":
            body[0x0B] ^= 1
    else:
        body[0x10:0x14] = bytes(4)
        crc = zlib.crc32(bytes(body[:tab]))
        struct.pack_into("<I", body, 0x10, crc ^ (1 if ck == "bad" else 0))
    return bytes(body)


def bpdt(ents, version=2, count=None):
    """BPDT：表頭 0x18、項目 12 bytes（version 2：type u32；version 1：type u16＋flags u16）。"""
    h = struct.pack("<IHBBII4H", cl.BPDT_SIG, len(ents) if count is None else count, version, 0, 0, 0, *VER)
    for typ, off, size in ents:
        h += struct.pack("<III", typ, off, size) if version == 2 else struct.pack("<HHII", typ, 0, off, size)
    return h


def layout_table(layout, data, bps):
    """layout 1.7（0x58）或 1.6（只有 data、bp1、bp2）。bps＝[(相對 offset, size)]（沒有的補 0）。"""
    t = bytearray(b"\xff" * 16)
    if layout == "1.7":
        t += struct.pack("<HHI", 0x58, 0, 0x12345678)
        t += struct.pack("<II", *data)
        for o, s in (list(bps) + [(0, 0)] * 5)[:5]:
            t += struct.pack("<II", o, s)
        t += struct.pack("<IIII", 0x100000, 0x1000, 0, 0)
    else:
        t += struct.pack("<II", *data)
        for o, s in (list(bps) + [(0, 0)] * 2)[:2]:
            t += struct.pack("<II", o, s)
        t += bytes(0x18)
    return bytes(t)


def good_region(layout="1.7", size=REGION, main=None, bpv=2, hv=2, ver2=VER):
    """BP1（0x1000）有 RBEP、BP3（0x3000）有 NFTP 的新世代配置（沒有 FTPR）。"""
    r = bytearray(b"\xff" * size)
    lt = layout_table(layout, (0x5000, 0x1000), [(0x1000, 0x2000), (0, 0), (0x3000, 0x2000)] if layout == "1.7"
                      else [(0x1000, 0x2000), (0x3000, 0x2000)])
    r[0:len(lt)] = lt
    for bp, ents, parts in ((0x1000, [(1, 0x100, 0x200)], {0x100: partition("RBEP", VER, hv)}),
                            (0x3000, [(7, 0x100, 0x200)], {0x100: partition("NFTP", ver2, hv)})):
        b = bpdt(ents, bpv)
        r[bp:bp + len(b)] = b
        for o, p in parts.items():
            r[bp + o:bp + o + len(p)] = p
    return bytearray(r)


def put_bp(r, bp, ents, parts, bpv=2, count=None):
    b = bpdt(ents, bpv, count)
    r[bp:bp + 0x100] = b"\xff" * 0x100
    r[bp:bp + len(b)] = b
    for o, p in parts.items():
        r[bp + o:bp + o + len(p)] = p


def found(r, base=0):
    return cl.find_cse(bytes(r), base, base + len(r))


# ---------- 找得到 ----------

@pytest.mark.parametrize("layout,bpv,hv", [("1.7", 2, 2), ("1.6", 1, 1), ("1.7", 1, 1), ("1.6", 2, 2)])
def test_rbep_and_nftp_agree_without_ftpr(layout, bpv, hv):
    res = found(good_region(layout, bpv=bpv, hv=hv))
    assert res["status"] == "found" and res["version"] == VERS
    assert [(c["name"], c["lbp"]) for c in res["sources"]] == [("RBEP", "BP1"), ("NFTP", "BP2" if layout == "1.6" else "BP3")]
    assert res["offset"] == 0x1000 + 0x100 + 0x80 and f"layout table {layout}" in res["basis"] and "no FTPR partition" in res["basis"]
    assert res["date_raw"] == 0x20240714


def test_ftpr_alone_is_enough_and_is_preferred():
    r = good_region("1.6", bpv=1, hv=1)
    put_bp(r, 0x1000, [(2, 0x300, 0x200), (1, 0x100, 0x200)],
           {0x300: partition("FTPR", VER, 1), 0x100: partition("RBEP", VER, 1)}, 1)
    put_bp(r, 0x3000, [(9, 0, 0)], {}, 1)         # BP2 的 BPDT 沒有任何非空項目
    res = found(r)
    assert res["status"] == "found" and res["offset"] == 0x1000 + 0x300 + 0x80 and res["basis"].startswith("BPDT (CSE layout table 1.6): BP1 FTPR.man")
    assert "no FTPR partition" not in res["basis"]


def test_bpdt_at_the_region_start_without_layout_table():
    r = bytearray(b"\xff" * 0x3000)
    put_bp(r, 0, [(1, 0x100, 0x200), (7, 0x400, 0x200)], {0x100: partition("RBEP"), 0x400: partition("NFTP")})
    res = found(r)
    assert res["status"] == "found" and res["layout"] == "BPDT at the region start" and res["offset"] == 0x180


def test_erased_boot_partition_is_skipped_not_a_problem():
    r = good_region()
    put_bp(r, 0x3000, [(7, 0x100, 0x200)], {0x100: partition("NFTP")})
    lt = layout_table("1.7", (0x5000, 0x1000), [(0x1000, 0x2000), (0x4000, 0x1000), (0x3000, 0x1000)])   # BP2 指到被清成 0xFF 的地方
    r[0:len(lt)] = lt
    res = found(r)
    assert res["status"] == "found" and res["version"] == VERS
    # 全部都是空的 → gap（認得出配置、沒有內容）
    e = bytearray(b"\xff" * REGION)
    e[0:len(lt)] = lt
    res = found(e)
    assert res["status"] == "gap" and "erased" in res["note"]


def test_wiring_new_generation_found_through_bios_image():
    b = xf.bios_image(with_me(bytes(good_region())))
    assert b["me_status"] == "found" and b["me"]["version"] == VERS and b["me"]["date"] == "2024-07-14"
    assert b["me"]["offset"] == 0x1000 + 0x1000 + 0x100 + 0x80
    assert b["me"]["basis"].startswith("BPDT (CSE layout table 1.7): BP1 RBEP.man 18.0.10.2285") and b["me"]["family"] is None
    assert "see basis" in b["me_note"] and b["me_conflict"] is None


def test_wiring_end_to_end_sbom(tmp_path):
    from cdx_schema import cdx_validator
    p = tmp_path / "BIOS.bin"
    p.write_bytes(with_me(bytes(good_region())))
    inv = xf.inventory([p])
    comps, deps = xf.components(inv)
    me = [c for c in comps if c["name"] == "Intel CSE firmware"]
    assert [c["version"] for c in me] == [VERS]
    assert not list(cdx_validator().iter_errors(xf.bom(comps, deps)))
    props = {q["name"]: q["value"] for q in me[0]["properties"]}
    assert props["sca-center:me-status"] == "found" and props["sca-center:version-basis"].startswith("BPDT (CSE layout table 1.7)")
    assert "ME 版本 unknown" not in xf.status_of(inv)[1]


def test_standalone_region_file_with_layout_table_at_the_start():
    b = xf.bios_image(bytes(good_region()))
    assert not b["descriptor"] and b["me_status"] == "found" and b["me"]["version"] == VERS
    # 不在檔案開頭（例如 capsule 包著）：不處理，維持原本的結果（沒有 ME 結構 → no-me-region 或 unknown）
    b = xf.bios_image(b"\x00" * 0x1000 + bytes(good_region()))
    assert b["me"] is None and b["me_status"] in ("no-me-region", "unknown")


# ---------- 既有世代不變 ----------

def test_fpt_generation_is_not_touched_even_if_a_layout_exists():
    """$FPT 找得到 FTPR → 照舊（basis、版本不變）；區域裡另有不同版本的新配置也不影響，且不會去呼叫新模組。"""
    reg = bytearray(me_region("me11"))
    b = xf.bios_image(with_me(bytes(reg)))
    assert b["me"]["version"] == "16.1.30.2307" and b["me"]["basis"] == "FTPR partition ($FPT, $CPD FTPR.man)"
    lt = good_region()
    mixed = bytearray(me_region("me11", 0x10))          # $FPT 在 +0x10：區域開頭不是 layout table
    mixed[0x3000:0x3000 + 0x1000] = lt[0x1000:0x2000]    # BP 的內容放著也不影響
    b = xf.bios_image(with_me(bytes(mixed)))
    assert b["me"]["version"] == "16.1.30.2307" and b["me"]["basis"].startswith("FTPR partition ($FPT")


def test_no_layout_means_legacy_result_unchanged():
    assert cl.find_cse(b"\xff" * 0x6000, 0, 0x6000)["status"] == "none"
    assert cl.find_cse(bytes(0x6000), 0, 0x6000)["status"] == "none"
    for img in (with_me(b"\xff" * 0x6000), spi_image(), with_me(bytes(0x6000))):
        b = xf.bios_image(img)
        assert "CSE layout/BPDT" not in (b["me_note"] or "")
    assert xf.bios_image(with_me(b"\xff" * 0x6000))["me_status"] == "unknown"


# ---------- 名稱對但 manifest／目錄壞 ----------

@pytest.mark.parametrize("kw,why", [
    (dict(tag=b"XXXX"), "does not start with $CPD"),
    (dict(man="RBEP.mar"), "no RBEP.man entry"),
    (dict(raw_flags=1), "compression flags"),
    (dict(man_len=0x10), "outside the RBEP partition"),
    (dict(ent_off=0x10), "overlaps its $CPD entry table"),
    (dict(man_off=0x1F0), "outside the RBEP partition"),
    (dict(ver=(0, 0, 0, 0)), "version 0.0.0.0"),
    (dict(pname="NFTP"), "is named 'NFTP', expected 'RBEP'"),
    (dict(hv=2, hl=0x10), "header version 2"),
    (dict(hv=1, hl=0x14), "header version 1"),
    (dict(ck="bad", hv=2), "CRC-32 checksum mismatch"),
    (dict(ck="bad", hv=1), "8-bit checksum mismatch"),
    (dict(cnt=0), "declares 0 entries"),
    (dict(cnt=cl.MAX_CPD_ENTRIES + 1), "declares 257 entries"),
    (dict(cnt=0xFFFFFFFF), "declares 4294967295 entries"),
])
def test_named_partition_with_a_broken_directory_or_manifest_is_a_gap(kw, why):
    r = good_region()
    put_bp(r, 0x1000, [(1, 0x100, 0x200)], {0x100: partition("RBEP", **kw)})
    res = found(r)
    assert res["status"] == "gap" and why in res["note"] and "version" not in res
    b = xf.bios_image(with_me(bytes(r)))
    assert (b["me"], b["me_status"]) == (None, "unknown") and "CSE layout/BPDT:" in b["me_note"] and why in b["me_note"]


@pytest.mark.parametrize("mut", [lambda r: r.__setitem__(slice(0x1000 + 0x100 + 0x80 + 0x1C, 0x1000 + 0x100 + 0x80 + 0x20), b"XXXX"),
                                 lambda r: struct.pack_into("<I", r, 0x1000 + 0x100 + 0x80 + 0x10, 0x1234)])
def test_bad_mn2_tag_or_vendor_is_a_gap(mut):
    r = good_region()
    mut(r)
    res = found(r)
    assert res["status"] == "gap" and "not a valid $MN2 manifest" in res["note"]


# ---------- 矛盾的候選、只有一個來源 ----------

def test_rbep_and_nftp_disagree_is_not_guessed():
    res = found(good_region(ver2=(18, 0, 5, 2040)))
    assert res["status"] == "gap" and "disagree" in res["note"] and "18.0.10.2285" in res["note"] and "18.0.5.2040" in res["note"]
    b = xf.bios_image(with_me(bytes(good_region(ver2=(18, 0, 5, 2040)))))
    assert (b["me"], b["me_status"]) == (None, "unknown") and "disagree" in b["me_note"]


def test_ftpr_disagreeing_with_rbep_is_a_gap():
    r = good_region("1.6", bpv=1, hv=1)
    put_bp(r, 0x1000, [(2, 0x300, 0x200), (1, 0x100, 0x200)],
           {0x300: partition("FTPR", (18, 0, 1, 1), 1), 0x100: partition("RBEP", VER, 1)}, 1)
    assert found(r)["status"] == "gap"


def test_two_copies_of_rbep_in_different_boot_partitions_disagree():
    r = good_region()
    put_bp(r, 0x3000, [(1, 0x100, 0x200)], {0x100: partition("RBEP", (18, 0, 5, 2040))})
    res = found(r)
    assert res["status"] == "gap" and "disagree" in res["note"]
    put_bp(r, 0x3000, [(1, 0x100, 0x200)], {0x100: partition("RBEP", VER)})
    assert found(r)["status"] == "found"                 # 兩份相同 → 兩個獨立來源，採用


def test_single_main_manifest_without_ftpr_is_not_enough():
    r = good_region()
    put_bp(r, 0x3000, [(9, 0, 0)], {})
    res = found(r)
    assert res["status"] == "gap" and "only one other main-program manifest" in res["note"] and "version" not in res
    b = xf.bios_image(with_me(bytes(r)))
    assert b["me"] is None and b["me_status"] == "unknown"


def test_a_broken_sibling_makes_the_whole_result_a_gap():
    r = good_region()
    put_bp(r, 0x3000, [(7, 0x100, 0x200)], {0x100: partition("NFTP", tag=b"XXXX")})
    res = found(r)
    assert res["status"] == "gap" and "does not start with $CPD" in res["note"]


def test_duplicate_main_entries_in_one_bpdt():
    r = good_region()
    put_bp(r, 0x1000, [(1, 0x100, 0x200), (1, 0x400, 0x200)], {0x100: partition("RBEP"), 0x400: partition("RBEP")})
    assert "two non-empty RBEP entries" in found(r)["note"]


# ---------- 指標越界、循環、重疊、數量上限 ----------

@pytest.mark.parametrize("ents,why", [
    ([(1, 0x100, 0x2000)], "outside the boot partition"),                     # 超出 boot partition
    ([(1, 0xFFFFFF00, 0xFFFFFF00)], "outside the boot partition"),             # 32 位元加起來會繞回來的數字
    ([(1, 0x0, 0x200)], "overlaps the BPDT"),                                  # 指回 BPDT 自己（循環）
    ([(1, 0x10, 0x200)], "overlaps the BPDT"),
    ([(5, 0x100, 0x1000), (1, 0x400, 0x200)], "overlap"),                      # 與 S-BPDT 項目重疊
    ([(1, 0x100, 0x300), (7, 0x200, 0x100)], "overlap"),
])
def test_bpdt_entry_pointer_problems(ents, why):
    r = good_region()
    put_bp(r, 0x1000, ents, {0x100: partition("RBEP")})
    res = found(r)
    assert res["status"] == "gap" and why in res["note"]


def test_s_bpdt_entry_pointing_back_is_not_followed():
    """type 5（S-BPDT）項目指到另一個 BPDT（甚至指回 BP1 自己的開頭＋偏移）：不往下追，沒有遞迴。"""
    r = good_region()
    put_bp(r, 0x1000, [(5, 0x800, 0x100), (1, 0x100, 0x200)], {0x100: partition("RBEP"), 0x800: bpdt([(5, 0, 0x100)])})
    res = found(r)
    assert res["status"] == "found" and res["version"] == VERS


def test_bpdt_entry_count_cap_and_truncated_table():
    r = good_region()
    put_bp(r, 0x1000, [(1, 0x100, 0x200)], {0x100: partition("RBEP")}, count=cl.MAX_BPDT_ENTRIES + 1)
    assert "declares 49 entries" in found(r)["note"]
    put_bp(r, 0x1000, [(1, 0x100, 0x200)], {0x100: partition("RBEP")}, count=0)
    assert "declares 0 entries" in found(r)["note"]
    put_bp(r, 0x1000, [(1, 0x100, 0x200)], {0x100: partition("RBEP")}, count=0xFFFF)
    assert found(r)["status"] == "gap"
    put_bp(r, 0x1000, [(1, 0x100, 0x200)], {0x100: partition("RBEP")}, count=cl.MAX_BPDT_ENTRIES)
    assert found(r)["status"] == "gap"                   # 宣告 48 項但後面是 0xFF：項目是 0xFFFFFFFF 的越界值
    bad = bytearray(good_region())
    bad[0x1006] = 3
    assert "version 3" in found(bad)["note"]


def test_bpdt_signature_missing_where_the_layout_points():
    r = good_region()
    r[0x3000:0x3004] = b"\x00\x00\x00\x00"
    res = found(r)
    assert res["status"] == "gap" and "no BPDT signature at 0x3000" in res["note"]


@pytest.mark.parametrize("bps,why", [
    ([(0x1000, 0x2000), (0, 0), (0x2000, 0x2000)], "overlaps BP3"),                       # BP 互相重疊
    ([(0x1000, 0x2000), (0, 0), (0x3000, 0x4000)], "outside the region"),                 # 超出區域
    ([(0x1000, 0xFFFFFFFF), (0, 0), (0x3000, 0x2000)], "outside the region"),
    ([(0xFFFFF000, 0x2000), (0, 0), (0x3000, 0x2000)], "outside the region"),
    ([(0x1000, 0x2000), (0, 0), (0x30, 0x2000)], "overlaps the table"),
    ([(0x1000, 0x4800), (0, 0), (0x3000, 0x2000)], "overlaps BP3"),
    ([(0x1000, 0), (0, 0), (0x3000, 0x2000)], "outside the region"),
])
def test_layout_table_range_problems(bps, why):
    r = good_region()
    lt = layout_table("1.7", (0x5000, 0x1000), bps)
    r[0:len(lt)] = lt
    res = found(r)
    assert res["status"] == "gap" and why in res["note"], res


def test_layout_data_partition_overlapping_a_bp():
    r = good_region()
    lt = layout_table("1.7", (0x2000, 0x1000), [(0x1000, 0x2000), (0, 0), (0x3000, 0x2000)])
    r[0:len(lt)] = lt
    assert "overlaps" in found(r)["note"]


def test_layout_1_6_without_a_marker_is_silently_not_a_layout():
    r = bytearray(b"\xff" * 0x6000)
    r[0x10:0x30] = struct.pack("<8I", 0x100, 0x100, 0x100, 0x100, 0, 0, 0, 0)     # 重疊：1.6 沒有標記，不當成 layout table
    assert cl.find_cse(bytes(r), 0, 0x6000)["status"] == "none"


def test_truncated_region_and_every_truncation_point():
    r = bytes(good_region())
    assert cl.find_cse(r, 0, 0x2000)["status"] == "gap"
    for cut in range(0, len(r) + 1, 0x80):
        res = cl.find_cse(r[:cut], 0, len(r))             # 區域結尾比檔案長（截斷的檔案）
        assert res["status"] in ("none", "gap") or (cut >= 0x3300 and res["status"] == "found"), (cut, res)
        res = cl.find_cse(r[:cut], 0, cut)
        assert res["status"] in ("none", "gap", "found")


def test_random_corruption_never_reports_a_wrong_version():
    rnd = random.Random(20261113)
    base = bytes(good_region())
    for k in range(400):
        m = bytearray(base)
        for _ in range(rnd.choice((1, 1, 2, 4))):
            m[rnd.randrange(0, len(m))] = rnd.randrange(256)
        res = cl.find_cse(bytes(m), 0, len(m))
        assert res["status"] in ("none", "gap", "found")
        if res["status"] == "found":
            assert res["version"] == VERS, (k, res)
    for _ in range(100):                                  # 整段隨機也不能崩潰
        res = cl.find_cse(bytes(rnd.randrange(256) for _ in range(0x300)), 0, 0x300)
        assert res["status"] in ("none", "gap")


def test_budget_is_checked_and_work_is_bounded():
    class Counting:
        n = 0

        def check(self):
            Counting.n += 1

    assert cl.find_cse(bytes(good_region()), 0, REGION, Counting())["status"] == "found"
    assert 1 <= Counting.n <= cl.MAX_BP

    class Over(Exception):
        pass

    class Boom:
        def check(self):
            raise Over()

    with pytest.raises(Over):
        cl.find_cse(bytes(good_region()), 0, REGION, Boom())      # 超時要往外傳（和其他掃描一樣）


def test_large_file_is_not_scanned():
    """沒有全檔掃描：區域外的巨量 $CPD／$MN2 標記不影響，工作量只跟 BP／BPDT／目錄項目數有關。"""
    big = bytearray(good_region()) + b"$CPD$MN2" * 200000
    res = cl.find_cse(bytes(big), 0, REGION)
    assert res["status"] == "found"
    res = cl.find_cse(bytes(big), 0, len(big))
    assert res["status"] == "found"


def test_nonzero_region_base():
    img = b"\x00" * 0x800 + bytes(good_region())
    res = cl.find_cse(img, 0x800, len(img))
    assert res["status"] == "found" and res["offset"] == 0x800 + 0x1000 + 0x100 + 0x80


def test_stray_layout_size_field_in_a_file_without_me_is_not_an_me_region():
    """沒有 descriptor、沒有其他 ME 結構的檔案：+0x10 碰巧是 0x0058 也不改成 unknown。"""
    f = bytearray(spi_image(with_descriptor=False))
    for o in (0x1100, 0x2100, 0x3100):
        f[o:o + 0x80] = b"\xff" * 0x80
    f[0x2000:0x2010] = b"\xff" * 16
    assert xf.bios_image(bytes(f))["me_status"] == "no-me-region"
    f[0x10:0x12] = b"\x58\x00"
    assert cl.find_cse(bytes(f), 0, len(f))["status"] == "gap"
    b = xf.bios_image(bytes(f))
    assert b["me_status"] == "no-me-region" and "CSE layout/BPDT" not in (b["me_note"] or "")


def test_me_region_beyond_the_file_is_left_to_the_old_result():
    img = with_me(bytes(good_region()))
    b = xf.bios_image(img[:0x4000])                       # descriptor 說 ME 區域到 0x6FFF，檔案只有 0x4000
    assert b["me"] is None and b["me_status"] == "unknown" and "CSE layout/BPDT" not in (b["me_note"] or "")
    no_me = bytearray(img)
    struct.pack_into("<I", no_me, 0x48, 0x00007FFF)
    assert xf.bios_image(bytes(no_me))["me_status"] == "no-me-region"
