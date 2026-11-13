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
from test_x86_firmware import cpd, me_manifest, me_region, spi_image, with_me  # noqa: E402

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
    """BPDT：表頭 0x18、項目 12 bytes（version 2：type u32；version 1：type u16＋flags u16）。
    ents 的項目是 (type, offset, size) 或 (type, offset, size, flags)；flags 只用在 version 1（version 2 要在 type 裡自己放高位元）。"""
    h = struct.pack("<IHBBII4H", cl.BPDT_SIG, len(ents) if count is None else count, version, 0, 0, 0, *VER)
    for e in ents:
        typ, off, size = e[:3]
        h += struct.pack("<III", typ, off, size) if version == 2 else struct.pack("<HHII", typ, e[3] if len(e) > 3 else 0, off, size)
    return h


def layout_table(layout, data, bps, size=0x58, flags=0, bad_crc=False):
    """layout 1.7（Size 0x40／0x48／0x58／0x60，從 +0x10 起算；+0x14 是 CRC-32）或 1.6（0x48，BP1…BP5，+0x40 u64 checksum）。
    bps＝[(相對 offset, size)]（沒有的補 0）。"""
    t = bytearray(b"\xff" * 16)
    pairs = (list(bps) + [(0, 0)] * 5)[:5]
    if layout == "1.7":
        t += struct.pack("<HBBI", size, flags, 0, 0)
        t += struct.pack("<II", *data)
        for o, s in pairs:
            t += struct.pack("<II", o, s)
        t += struct.pack("<IIII", 0x100000, 0x1000, 0, 0)            # temp pages、external error log
        t = t[:0x10 + size].ljust(0x10 + size, b"\x00")
        crc = zlib.crc32(bytes(t[0x10:0x14]) + bytes(4) + bytes(t[0x18:0x10 + size]))
        struct.pack_into("<I", t, 0x14, crc ^ (1 if bad_crc else 0))
    else:
        t += struct.pack("<II", *data)
        for o, s in pairs:
            t += struct.pack("<II", o, s)
        t += struct.pack("<Q", 0x22)
    return bytes(t)


def good_region(layout="1.7", region_size=REGION, main=None, bpv=2, hv=2, ver2=VER, **lt_kw):
    """BP1（0x1000）有 RBEP、BP3（0x3000）有 NFTP 的新世代配置（沒有 FTPR）。"""
    r = bytearray(b"\xff" * region_size)
    lt = layout_table(layout, (0x5000, 0x1000), [(0x1000, 0x2000), (0, 0), (0x3000, 0x2000)], **lt_kw)
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

def build(layout, size, data, bps, bpv=2, hv=2, **lt_kw):
    """任意配置：bps＝[(相對 offset, size, BPDT 項目, {BP 內 offset: 分割區})]，None＝沒有這個 BP。"""
    r = bytearray(b"\xff" * size)
    lt = layout_table(layout, data, [(b[0], b[1]) if b else (0, 0) for b in bps], **lt_kw)
    r[0:len(lt)] = lt
    for b in bps:
        if b:
            put_bp(r, b[0], b[2], b[3], bpv)
    return r


@pytest.mark.parametrize("layout,bpv,hv,size", [("1.7", 2, 2, 0x58), ("1.7", 2, 2, 0x60), ("1.7", 2, 2, 0x48), ("1.7", 2, 2, 0x40), ("1.6", 1, 1, 0x58),
                                                ("1.7", 1, 1, 0x58), ("1.6", 2, 2, 0x58)])
def test_rbep_and_nftp_agree_without_ftpr(layout, bpv, hv, size):
    res = found(good_region(layout, REGION, None, bpv, hv, VER, size=size))
    assert res["status"] == "found" and res["version"] == VERS
    assert [(c["name"], c["lbp"]) for c in res["sources"]] == [("RBEP", "BP1"), ("NFTP", "BP3")]
    assert res["offset"] == 0x1000 + 0x100 + 0x80 and f"layout table {layout}" in res["basis"] and "no FTPR partition, RBEP and NFTP agree" in res["basis"]
    assert res["date_raw"] == 0x20240714


def test_ftpr_alone_is_enough_and_is_preferred():
    r = good_region("1.6", bpv=1, hv=1)
    put_bp(r, 0x1000, [(2, 0x300, 0x200), (1, 0x100, 0x200)],
           {0x300: partition("FTPR", VER, 1), 0x100: partition("RBEP", VER, 1)}, 1)
    put_bp(r, 0x3000, [(9, 0, 0)], {}, 1)         # BP3 的 BPDT 沒有任何非空項目
    res = found(r)
    assert res["status"] == "found" and res["offset"] == 0x1000 + 0x300 + 0x80 and res["basis"].startswith("BPDT (CSE layout table 1.6): BP1 FTPR.man")
    assert "no FTPR partition" not in res["basis"]


def test_ftpr_is_chosen_even_when_it_is_not_the_first_candidate():
    """cands 的順序是 BP1 的 RBEP、BP3 的 FTPR：取的是 FTPR（偏移不同），不是第一個。"""
    r = good_region()
    put_bp(r, 0x3000, [(2, 0x100, 0x200)], {0x100: partition("FTPR")})
    res = found(r)
    assert res["status"] == "found" and [c["name"] for c in res["sources"]] == ["RBEP", "FTPR"]
    assert res["offset"] == 0x3000 + 0x100 + 0x80 and res["basis"].startswith("BPDT (CSE layout table 1.7): BP1 RBEP.man") and "no FTPR" not in res["basis"]


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
    # 只有開頭（BPDT 表頭、項目表）是 0xFF、後面有內容 → 不算清除，是結構壞
    part = bytearray(r)
    part[0x4000:0x5000] = b"\xff" * 0x1000
    part[0x4800:0x4810] = b"\x01" * 16
    res = found(part)
    assert res["status"] == "gap" and "no BPDT signature at 0x4000" in res["note"]
    part[0x4000:0x4004] = b"\x00\x00\x00\x00"          # 表頭不是 0xFF 也不是 BPDT
    assert "no BPDT signature at 0x4000" in found(part)["note"]


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
    img = bytes(good_region())
    b = xf.bios_image(img)
    assert not b["descriptor"] and b["me_status"] == "found" and b["me"]["version"] == VERS
    assert b["fit"]["status"] == "not-applicable" and b["microcode"] == []          # standalone：沒有 BIOS 區域
    assert xf.me_info(img, None, None, [])["standalone"] is True
    full = with_me(bytes(good_region()))                                              # 有 descriptor 的完整映像
    regs, _, beyond = xf.descriptor(full)
    mi = xf.me_info(full, regs, next(r for r in regs if r["name"] == "me"), beyond)
    assert mi["status"] == "found" and mi["standalone"] is False
    assert xf.bios_image(full)["fit"]["status"] != "not-applicable"
    # 不在檔案開頭（例如 capsule 包著）：不處理，結果由第一條路決定（沒有 ME 結構 → no-me-region 或 unknown）
    b = xf.bios_image(b"\x00" * 0x1000 + bytes(good_region()))
    assert b["me"] is None and b["me_status"] in ("no-me-region", "unknown")


# ---------- 既有世代不變 ----------

def test_fpt_generation_result_is_unchanged():
    """$FPT 找得到 FTPR → basis 與版本照第一條路（$FPT 在區域開頭或 +0x10；新模組沒有 layout table 可看）。"""
    for off in (0, 0x10):
        b = xf.bios_image(with_me(bytes(me_region("me11", off))))
        assert b["me"]["version"] == "16.1.30.2307" and b["me"]["basis"] == "FTPR partition ($FPT, $CPD FTPR.man)" and b["me_note"] is None


def legacy_plus_layout():
    """區域開頭有一份有效的 layout table＋BPDT（RBEP、NFTP＝18.0.10.2285），區域後面另有名稱是 FTPR 的 $CPD（manifest 16.1.30.2307）：
    舊的做法（FTPR 的 $CPD）有結果。"""
    r = good_region()
    c = cpd([(b"FTPR.man", 0x80)], b"FTPR", 0x10)
    r[0x5000:0x5000 + len(c)] = c
    r[0x5080:0x5100] = me_manifest((16, 1, 30, 2307), 0x20230501)
    return r


def test_legacy_result_wins_over_a_valid_layout_in_the_same_region():
    r = legacy_plus_layout()
    assert found(r)["version"] == VERS                    # 新模組單獨看這個區域會給 18.0.10.2285
    b = xf.bios_image(with_me(bytes(r)))                  # 但舊的做法有結果：版本、basis、note 都是舊的
    assert (b["me_status"], b["me"]["version"], b["me"]["basis"]) == ("found", "16.1.30.2307", "FTPR partition manifest")
    assert "has no FTPR partition" in b["me_note"] or "no $FPT" in b["me_note"]
    assert "BPDT" not in b["me"]["basis"] and "BPDT" not in b["me_note"]
    b = xf.bios_image(bytes(r))                           # 沒有 descriptor 的檔案：同樣是舊的做法
    assert b["me_status"] == "found" and b["me"]["version"] == "16.1.30.2307" and b["me"]["basis"].startswith("FTPR $CPD FTPR.man")


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


def redundant(ver_copy=VER, nftp=True, rbep_copy=True):
    """redundancy（Flags bit 0）：BP2 是 BP1 的備份；BP3 是 NFTP。區域 0xA000。"""
    bps = [(0x1000, 0x2000, [(1, 0x100, 0x200)], {0x100: partition("RBEP")}),
           (0x3000, 0x2000, [(1, 0x100, 0x200)], {0x100: partition("RBEP", ver_copy)}) if rbep_copy else None,
           (0x5000, 0x2000, [(7, 0x100, 0x200)], {0x100: partition("NFTP")}) if nftp else None]
    return build("1.7", 0xA000, (0x9000, 0x1000), bps, flags=1)


def test_redundant_copy_of_the_same_type_is_not_an_independent_source():
    res = found(redundant())
    assert res["status"] == "found" and [c["name"] for c in res["sources"]] == ["RBEP", "RBEP", "NFTP"]
    res = found(redundant((18, 0, 5, 2040)))
    assert res["status"] == "gap" and "disagree" in res["note"] and "18.0.5.2040" in res["note"]
    # RBEP 有兩份、沒有 NFTP：兩份相同也不算（同一類型的拷貝不算獨立來源）
    res = found(redundant(nftp=False))
    assert res["status"] == "gap" and "no NFTP partition" in res["note"] and "version" not in res
    # NFTP 有兩份（BP2 是 NFTP 的拷貝）、沒有 RBEP
    nftp_twice = build("1.7", 0xA000, (0x9000, 0x1000),
                       [(0x1000, 0x2000, [(7, 0x100, 0x200)], {0x100: partition("NFTP")}),
                        (0x3000, 0x2000, [(7, 0x100, 0x200)], {0x100: partition("NFTP")}), None])
    res = found(nftp_twice)
    assert res["status"] == "gap" and "no RBEP partition" in res["note"]


def test_single_main_manifest_without_ftpr_is_not_enough():
    r = good_region()
    put_bp(r, 0x3000, [(9, 0, 0)], {})
    res = found(r)
    assert res["status"] == "gap" and "no NFTP partition" in res["note"] and "version" not in res
    b = xf.bios_image(with_me(bytes(r)))
    assert b["me"] is None and b["me_status"] == "unknown" and "RBEP and NFTP must both be present" in b["me_note"]


def test_layout_1_6_reads_bp3_to_bp5_into_the_contradiction_check():
    """1.6 的 BP1…BP5 都讀：BP4 放一份版本不同的 NFTP 也要發現（BP2 空著）。"""
    bps = [(0x1000, 0x2000, [(1, 0x100, 0x200)], {0x100: partition("RBEP", VER, 1)}),
           None,
           (0x3000, 0x2000, [(7, 0x100, 0x200)], {0x100: partition("NFTP", VER, 1)}),
           (0x5000, 0x2000, [(7, 0x100, 0x200)], {0x100: partition("NFTP", (18, 0, 5, 2040), 1)}),
           None]
    r = build("1.6", 0xA000, (0x9000, 0x1000), bps, bpv=1)
    res = found(r)
    assert res["status"] == "gap" and "BP4 NFTP.man 18.0.5.2040" in res["note"] and "disagree" in res["note"]
    bps[3] = (0x5000, 0x2000, [(7, 0x100, 0x200)], {0x100: partition("NFTP", VER, 1)})
    res = found(build("1.6", 0xA000, (0x9000, 0x1000), bps, bpv=1))
    assert res["status"] == "found" and [c["lbp"] for c in res["sources"]] == ["BP1", "BP3", "BP4"]
    bps[4] = (0x7000, 0x2000, [(1, 0x100, 0x200)], {0x100: partition("RBEP", (1, 2, 3, 4), 1)})        # BP5
    assert found(build("1.6", 0xA000, (0x9000, 0x1000), bps, bpv=1))["status"] == "gap"


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


# ---------- layout table 的 CRC-32、Size、1.6 的條件 ----------

def test_layout_17_crc_is_checked_over_the_documented_range():
    """CRC-32：d[+0x10:+0x14] ＋ 4 個 0 ＋ d[+0x18:+0x10+Size]。範圍內任何一個 byte 變了都不符（包含 Size 以內、欄位以外的部分），範圍外不影響。"""
    assert found(good_region())["status"] == "found"
    bad = found(good_region(bad_crc=True))
    assert bad["status"] == "gap" and "CRC-32 mismatch" in bad["note"]
    for at in (0x12, 0x18, 0x20, 0x44, 0x48, 0x50, 0x60, 0x67):                 # Size 0x58 → 範圍到 0x68
        r = good_region()
        r[at] ^= 0x01
        res = found(r)
        assert res["status"] == "gap" and "CRC-32 mismatch" in res["note"], (hex(at), res)
    for at in (0x00, 0x0F, 0x68, 0x80):                                                  # ROM bypass 與範圍之後：不入算
        r = good_region()
        r[at] ^= 0x01
        assert found(r)["status"] == "found", hex(at)
    r = good_region()                                                                    # checksum 欄位本身改成其他值 → 不符
    struct.pack_into("<I", r, 0x14, 0)
    assert "CRC-32 mismatch" in found(r)["note"]
    for at in (0x12, 0x18, 0x20, 0x44, 0x48, 0x50, 0x58, 0x68, 0x6F):                 # Size 0x60 → 範圍到 0x70（多出來的 8 bytes 也入算）
        r = good_region(size=0x60)
        r[at] ^= 0x01
        res = found(r)
        assert res["status"] == "gap" and "CRC-32 mismatch" in res["note"], (hex(at), res)
    for at in (0x00, 0x0F, 0x70, 0x80):
        r = good_region(size=0x60)
        r[at] ^= 0x01
        assert found(r)["status"] == "found", hex(at)
    for size in (0x40, 0x48):                                                            # 較短的 Size：範圍跟著縮短
        r = good_region(size=size)
        r[0x10 + size] ^= 0x01
        assert found(r)["status"] == "found"
        r[0x10 + size - 1] ^= 0x01
        assert "CRC-32 mismatch" in found(r)["note"]


def test_layout_17_wiring_crc_mismatch_is_unknown_with_the_reason():
    b = xf.bios_image(with_me(bytes(good_region(bad_crc=True))))
    assert (b["me"], b["me_status"]) == (None, "unknown") and "CRC-32 mismatch" in b["me_note"]


@pytest.mark.parametrize("size", [0, 0x3E, 0x44, 0x50, 0x57, 0x59, 0x5C, 0x64, 0x68, 0x70, 0x78, 0x80, 0xA0, 0x100, 0xFFFF])
def test_layout_17_unknown_sizes_are_not_recognised(size):
    r = bytearray(good_region())
    struct.pack_into("<H", r, 0x10, size)
    res = found(r)
    assert res["status"] in ("none", "gap")
    if res["status"] == "gap":
        assert "version" not in res
    assert res.get("status") != "found"


@pytest.mark.parametrize("size", [0x5C, 0x64, 0x68, 0x70, 0x78, 0x80, 0xA0, 0x100])
def test_layout_17_unknown_size_is_not_recognised_even_with_a_valid_crc(size):
    """Size 不在清單裡：就算 CRC 照同樣的算法算對、表是用該 Size 完整建出來的，也不認（none，維持原結果）；沒有「≥ 0x40 的 8 的倍數」這種放寬。"""
    r = good_region(size=0x58)
    t = layout_table("1.7", (0x5000, 0x1000), [(0x1000, 0x2000), (0, 0), (0x3000, 0x2000)], size=size)
    r[0:0x10 + size] = t
    assert found(r)["status"] == "none"
    b = xf.bios_image(with_me(bytes(r)))
    assert b["me"] is None and b["me_status"] != "found"


def test_layout_17_size_0x60_is_found_and_wired():
    """Size 0x60（表總長 0x70）：結構與 CRC 算法同 0x58，+0x58 起的 24 bytes 全 0。"""
    r = good_region(size=0x60)
    assert r[0x58:0x70] == bytes(0x18) and struct.unpack_from("<H", r, 0x10)[0] == 0x60
    res = found(r)
    assert res["status"] == "found" and res["version"] == VERS and res["layout"] == "CSE layout table 1.7"
    b = xf.bios_image(with_me(bytes(r)))
    assert b["me_status"] == "found" and b["me"]["version"] == VERS
    r = good_region(size=0x60, bad_crc=True)
    res = found(r)
    assert res["status"] == "gap" and "CRC-32 mismatch" in res["note"] and "version" not in res
    b = xf.bios_image(with_me(bytes(r)))
    assert (b["me"], b["me_status"]) == (None, "unknown")


def test_layout_17_size_0x60_truncated_is_not_found():
    """Size 0x60 的表被區域結尾截斷（表總長 0x70 超過區域）：CRC 無法驗 → 不採用（GAP，不報版本）；表之前就截斷也一樣。"""
    r = bytes(good_region(size=0x60))
    for end in (0x6F, 0x68, 0x58, 0x30, 0x21):
        res = cl.find_cse(r, 0, end)
        assert res["status"] in ("none", "gap") and "version" not in res, (hex(end), res)
    assert "goes past the end" in cl.find_cse(r, 0, 0x6F)["note"]
    for end in (0x6F, 0x68, 0x20, 0x10):
        assert cl.find_cse(r[:end], 0, 0x6000)["status"] in ("none", "gap")


def with_tail(size, tail_at=0x58, val=0x01, **kw):
    """good_region（Size＝size）的 +tail_at 改成 val，CRC 重算（所以 CRC 相符）。"""
    r = good_region(size=size, **kw)
    r[tail_at] = val
    struct.pack_into("<I", r, 0x14, zlib.crc32(bytes(r[0x10:0x14]) + bytes(4) + bytes(r[0x18:0x10 + size])))
    return r


def tail_raw(r, size):
    t = bytes(r[0x58:0x10 + size])
    return ", ".join(f"+0x{0x58 + i:x}: {t[i:i + 8].hex()}" for i in range(0, len(t), 8))


@pytest.mark.parametrize("size,at", [(0x58, 0x58), (0x58, 0x5F), (0x58, 0x67), (0x60, 0x58), (0x60, 0x67), (0x60, 0x68), (0x60, 0x6F)])
def test_layout_17_nonzero_tail_with_everything_else_valid_is_found_with_attention(size, at):
    """+0x58 之後（表尾）沒有公開欄位定義：不全為 0 但 CRC 相符、BP 都通過、RBEP＋NFTP 版本相同 → found＋attention（原始值，不解讀）。"""
    r = with_tail(size, at, 0xA5)
    res = found(r)
    last = 0x10 + size - 1
    assert res["status"] == "found" and res["version"] == VERS, res
    assert [a["code"] for a in res["attention"]] == ["layout-undocumented-fields"]
    txt = res["attention"][0]["text"]
    assert txt.startswith(f"layout table 有未公開欄位（+0x58～+0x{last:x}），未解讀") and tail_raw(r, size) in txt
    assert f"{0xA5:02x}" in txt and res["basis"].endswith(f"ATTENTION layout-undocumented-fields: {txt}")
    assert "no FTPR partition, RBEP and NFTP agree" in res["basis"]


@pytest.mark.parametrize("size", [0x48, 0x58, 0x60])
def test_layout_17_zero_tail_has_no_attention(size):
    res = found(good_region(size=size))
    assert res["status"] == "found" and res["attention"] == [] and "ATTENTION" not in res["basis"]


@pytest.mark.parametrize("size", [0x58, 0x60])
def test_layout_17_nonzero_tail_wiring_is_attention_in_status_sbom_and_report(size, tmp_path):
    img = with_me(bytes(with_tail(size, 0x58, 0x01)))
    b = xf.bios_image(img)
    assert b["me_status"] == "found" and b["me"]["version"] == VERS
    assert any(x.startswith("ME: layout-undocumented-fields: layout table 有未公開欄位") for x in b["incomplete"])
    assert "ATTENTION layout-undocumented-fields" in b["me"]["basis"]
    p = tmp_path / "BIOS.bin"
    p.write_bytes(img)
    inv = xf.inventory([p])
    assert xf.status_of(inv)[0] == "ATTENTION" and "layout-undocumented-fields" in xf.status_of(inv)[1]
    comps, deps = xf.components(inv)
    props = [(q["name"], q["value"]) for c in comps for q in c.get("properties", [])]
    assert any(n == "sca-center:incomplete" and "layout-undocumented-fields" in v for n, v in props)
    assert any(n == "sca-center:version-basis" and "layout-undocumented-fields" in v for n, v in props)
    assert "layout-undocumented-fields" in xf.markdown(inv)
    clean = xf.bios_image(with_me(bytes(good_region(size=size))))
    assert not any("layout-undocumented" in x for x in clean["incomplete"])


@pytest.mark.parametrize("size", [0x58, 0x60])
def test_layout_17_nonzero_tail_with_a_valid_ftpr_alone_is_found_with_attention(size):
    r = with_tail(size, 0x58, 0x01)
    put_bp(r, 0x3000, [(7, 0x100, 0x200)], {0x100: partition("NFTP")})
    put_bp(r, 0x1000, [(2, 0x100, 0x200)], {0x100: partition("FTPR")})
    res = found(r)
    assert res["status"] == "found" and [c["name"] for c in res["sources"]] == ["FTPR", "NFTP"] and res["attention"][0]["code"] == "layout-undocumented-fields"
    only = with_tail(size, 0x58, 0x01)
    put_bp(only, 0x1000, [(2, 0x100, 0x200)], {0x100: partition("FTPR")})
    only[0x3000:0x5000] = b"\xff" * 0x2000
    lt = layout_table("1.7", (0x5000, 0x1000), [(0x1000, 0x2000)], size=size)
    only[0:len(lt)] = lt
    only[0x58] = 1
    struct.pack_into("<I", only, 0x14, zlib.crc32(bytes(only[0x10:0x14]) + bytes(4) + bytes(only[0x18:0x10 + size])))
    res = found(only)
    assert res["status"] == "found" and [c["name"] for c in res["sources"]] == ["FTPR"] and res["attention"]


@pytest.mark.parametrize("size", [0x58, 0x60])
def test_layout_17_nonzero_tail_but_rbep_and_nftp_disagree_is_a_gap(size):
    r = with_tail(size, 0x58, 0x01, ver2=(18, 0, 10, 2286))
    res = found(r)
    assert res["status"] == "gap" and "disagree" in res["note"] and "version" not in res


@pytest.mark.parametrize("size", [0x58, 0x60])
def test_layout_17_nonzero_tail_with_a_missing_nftp_is_a_gap(size):
    r = with_tail(size, 0x58, 0x01)
    put_bp(r, 0x3000, [(7, 0x100, 0x200)], {})                       # NFTP 項目指到的不是 $CPD
    r[0x3100:0x3200] = b"\xff" * 0x100
    res = found(r)
    assert res["status"] == "gap" and "version" not in res


def recrc(r, size):
    struct.pack_into("<I", r, 0x14, zlib.crc32(bytes(r[0x10:0x14]) + bytes(4) + bytes(r[0x18:0x10 + size])))
    return r


@pytest.mark.parametrize("size", [0x58, 0x60])
@pytest.mark.parametrize("only,gone", [("RBEP", 0x30), ("NFTP", 0x20)])
def test_layout_17_nonzero_tail_with_a_single_main_partition_type_is_a_gap(size, only, gone):
    """表尾非 0 時仍要 FTPR，或 RBEP＋NFTP 兩種都在：只有 RBEP 或只有 NFTP → GAP、不報版本、沒有 attention。"""
    r = with_tail(size, 0x58, 0x01)
    struct.pack_into("<II", r, gone, 0, 0)                          # 0x30＝BP3（NFTP）、0x20＝BP1（RBEP）的指標拿掉
    recrc(r, size)
    res = found(r)
    assert res["status"] == "gap" and "version" not in res and "attention" not in res, res
    assert only in res["note"] or "no FTPR" in res["note"]


@pytest.mark.parametrize("size", [0x58, 0x60])
def test_layout_17_nonzero_tail_wiring_carries_the_complete_raw_values(size):
    """incomplete、SBOM 的 sca-center:incomplete 與 version-basis 都要有完整的原始值（逐 8 bytes 一組），不是只有開頭。"""
    r = good_region(size=size)
    n = 0x10 + size - 0x58
    r[0x58:0x58 + n] = bytes(range(0x11, 0x11 + n))
    recrc(r, size)
    raw = tail_raw(r, size)
    assert raw.count("+0x") == n // 8 and raw.split(", ")[-1].endswith(bytes(r[0x58 + n - 8:0x58 + n]).hex())
    img = with_me(bytes(r))
    b = xf.bios_image(img)
    want = f"ME: layout-undocumented-fields: layout table 有未公開欄位（+0x58～+0x{0x10 + size - 1:x}），未解讀；原始值（檔案順序的 bytes，8 bytes 一組）{raw}"
    assert want in b["incomplete"] and b["me"]["basis"].endswith(f"ATTENTION layout-undocumented-fields: {want[len('ME: layout-undocumented-fields: '):]}")
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "BIOS.bin"
        p.write_bytes(img)
        inv = xf.inventory([p])
        comps, _ = xf.components(inv)
    vals = [q["value"] for c in comps for q in c.get("properties", []) if q["name"] in ("sca-center:incomplete", "sca-center:version-basis")]
    assert want in vals and any(raw in v for v in vals if v.startswith("BPDT"))
    assert raw in xf.status_of(inv)[1] and raw in xf.markdown(inv)


def test_layout_16_never_has_an_attention():
    res = found(good_region("1.6", REGION, None, 1, 1))
    assert res["status"] == "found" and res["layout"] == "CSE layout table 1.6" and res["attention"] == [] and "ATTENTION" not in res["basis"]


@pytest.mark.parametrize("size", [0x58, 0x60])
def test_layout_17_bp_end_exactly_at_the_region_end_is_normal_and_one_byte_more_is_a_gap(size):
    def region(bp3_size):
        r = good_region(size=size)
        struct.pack_into("<II", r, 0x18, 0x100, 0x100)                       # data 移開，才不會壓到延長後的 BP3
        struct.pack_into("<II", r, 0x30, 0x3000, bp3_size)
        return recrc(r, size)
    ok = found(region(REGION - 0x3000))
    assert ok["status"] == "found" and ok["version"] == VERS
    over = found(region(REGION - 0x3000 + 1))
    assert over["status"] == "gap" and "outside the region" in over["note"] and "version" not in over


@pytest.mark.parametrize("size", [0x58, 0x60])
def test_layout_17_nonzero_tail_with_a_bad_crc_is_a_gap(size):
    r = with_tail(size, 0x58, 0x01)
    r[0x59] ^= 0x01                                                  # CRC 沒有跟著重算
    res = found(r)
    assert res["status"] == "gap" and "CRC-32 mismatch" in res["note"] and "version" not in res and "attention" not in res


@pytest.mark.parametrize("size", [0x58, 0x60])
def test_layout_17_nonzero_tail_with_a_failing_bp_is_a_gap(size):
    r = with_tail(size, 0x58, 0x01)
    r[0x3000:0x3004] = b"\x00\x00\x00\x00"                           # BP3 的 BPDT 簽章壞掉
    res = found(r)
    assert res["status"] == "gap" and "no BPDT signature" in res["note"] and "version" not in res
    r = with_tail(size, 0x58, 0x01)                                  # BP 超出區域
    struct.pack_into("<II", r, 0x30, 0x3000, REGION)
    struct.pack_into("<I", r, 0x14, zlib.crc32(bytes(r[0x10:0x14]) + bytes(4) + bytes(r[0x18:0x10 + size])))
    res = found(r)
    assert res["status"] == "gap" and "outside the region" in res["note"]


@pytest.mark.parametrize("size", [0x58, 0x60])
def test_layout_17_nonzero_tail_is_not_read_as_a_bp_pointer(size):
    """表尾只列原始值：就算看起來像 BP 指標（指到一個有效的 FTPR），也不採用它。"""
    r = with_tail(size, 0x58, 0x00)
    put_bp(r, 0x5000, [(2, 0x100, 0x200)], {0x100: partition("FTPR", (1, 2, 3, 4))})
    struct.pack_into("<II", r, 0x58, 0x5000, 0x1000)
    struct.pack_into("<I", r, 0x14, zlib.crc32(bytes(r[0x10:0x14]) + bytes(4) + bytes(r[0x18:0x10 + size])))
    res = found(r)
    assert res["status"] == "found" and res["version"] == VERS and res["attention"]


@pytest.mark.parametrize("size", [0x58, 0x60])
def test_layout_17_bp_pointer_inside_the_table_is_a_gap_and_at_the_end_is_checked_normally(size):
    """BP 指標落在表內（Size 0x60 時 < 0x70）→ GAP；剛好從表尾（0x10＋Size）起 → 走一般的 BPDT 檢查。"""
    for off in (0x58, 0x10 + size - 1):
        r = good_region(size=size)
        struct.pack_into("<II", r, 0x30, off, 0x100)
        struct.pack_into("<I", r, 0x14, zlib.crc32(bytes(r[0x10:0x14]) + bytes(4) + bytes(r[0x18:0x10 + size])))
        res = found(r)
        assert res["status"] == "gap" and "overlaps the table" in res["note"], (hex(off), res)
    r = good_region(size=size)
    lo = 0x10 + size
    put_bp(r, lo, [(7, 0x100, 0x200)], {0x100: partition("NFTP")})       # 剛好在表尾之後
    struct.pack_into("<II", r, 0x30, lo, 0x800)
    r[0x3000:0x3010] = b"\xff" * 0x10                                    # 原來的 BP3 內容不再被指到
    struct.pack_into("<I", r, 0x14, zlib.crc32(bytes(r[0x10:0x14]) + bytes(4) + bytes(r[0x18:0x10 + size])))
    res = found(r)
    assert "overlaps the table" not in res.get("note", ""), res
    assert res["status"] == "found" and [c["lbp"] for c in res["sources"]] == ["BP1", "BP3"]


@pytest.mark.parametrize("at", [0x50, 0x54, 0x57])
def test_layout_17_error_log_fields_do_not_affect_the_result(at):
    """external error log（+0x50…+0x57）與 temp pages 不讀：值是什麼都 found，而且沒有 attention。"""
    for size in (0x58, 0x60):
        r = good_region(size=size)
        r[at] = 0xEE
        struct.pack_into("<I", r, 0x14, zlib.crc32(bytes(r[0x10:0x14]) + bytes(4) + bytes(r[0x18:0x10 + size])))
        res = found(r)
        assert res["status"] == "found" and res["attention"] == [], (size, res)


@pytest.mark.parametrize("size", [0x44, 0x4C, 0x50, 0x54])
def test_layout_17_sizes_between_the_known_values_are_none_even_with_a_valid_crc(size):
    r = good_region(size=0x58)
    t = layout_table("1.7", (0x5000, 0x1000), [(0x1000, 0x2000), (0, 0), (0x3000, 0x2000)], size=size)
    r[0:0x10 + size] = t
    assert found(r)["status"] == "none"


def test_layout_17_flags_and_reserved_bits_do_not_matter():
    for flags in (0, 1, 0xFE, 0xFF):
        assert found(good_region(flags=flags))["status"] == "found"


def test_layout_16_checksum_is_not_verified_but_the_padding_is_required():
    r = good_region("1.6")
    struct.pack_into("<Q", r, 0x40, 0x1234)              # u64 checksum 的算法沒有確認：不驗證
    assert found(r)["status"] == "found"
    r = good_region("1.6")
    r[0x48] = 0x00                                        # 表後面到 0x1000 要全是 0xFF（1.6 沒有標記，靠這個條件）
    assert found(r)["status"] == "none"
    r = good_region("1.6")
    r[0xFFF] = 0x00
    assert found(r)["status"] == "none"


def test_layout_16_without_a_marker_and_with_bad_ranges_is_silently_not_a_layout():
    r = bytearray(b"\xff" * 0x6000)
    r[0x10:0x40] = struct.pack("<12I", 0x5000, 0x1000, 0x100, 0x100, 0x100, 0x100, 0, 0, 0, 0, 0, 0)     # 重疊
    assert cl.find_cse(bytes(r), 0, 0x6000)["status"] == "none"
    r[0x10:0x40] = struct.pack("<12I", 0x5000, 0x1000, 0x1000, 0xFFFFFFFF, 0, 0, 0, 0, 0, 0, 0, 0)      # 超出
    assert cl.find_cse(bytes(r), 0, 0x6000)["status"] == "none"


# ---------- BPDT 項目的 type 欄位寬度、`$CPD` 項目 offset 的位元數 ----------

def test_bpdt_v1_type_is_u16_with_separate_flags():
    r = good_region("1.7", bpv=1, hv=1)
    put_bp(r, 0x1000, [(1, 0x100, 0x200, 0x1234)], {0x100: partition("RBEP", VER, 1)}, 1)       # flags 非 0 不影響 type
    res = found(r)
    assert res["status"] == "found" and res["sources"][0]["name"] == "RBEP"


def test_bpdt_v2_type_is_u32_so_high_bits_make_it_a_different_type():
    r = good_region()
    put_bp(r, 0x1000, [(0x00010001, 0x100, 0x200)], {0x100: partition("RBEP")})                  # 低 16 位元是 1，但 type 不是 1
    res = found(r)
    assert res["status"] == "gap" and "no RBEP partition" in res["note"]
    put_bp(r, 0x1000, [(0x80000007, 0x100, 0x200)], {0x100: partition("NFTP")})
    assert found(r)["status"] == "gap"


def test_cpd_entry_offset_uses_25_bits_not_24():
    """`$CPD` 項目 offset 的低 25 bits；manifest 在分割區內 16 MiB 之後的位置（bit 24 有值）。"""
    off = 0x1000080
    size = 0x1204000
    rbep = partition("RBEP", ent_off=off, man_off=0x100)           # 分割區裡 +0x80 沒有 manifest（24 位元遮罩會讀到那裡）
    bps = [(0x1000, 0x1200000, [(1, 0x100, 0x1100000)], {0x100: rbep}),
           None,
           (0x1201000, 0x2000, [(7, 0x100, 0x200)], {0x100: partition("NFTP")})]
    r = build("1.7", size, (0x1203000, 0x1000), bps)
    at = 0x1000 + 0x100 + off
    r[at:at + 0x80] = mn2()
    res = found(r)
    assert res["status"] == "found" and res["offset"] == at and res["version"] == VERS
    # 同一個位置但帶壓縮旗標（bit 25）→ 拒絕
    bad = partition("RBEP", ent_off=off, man_off=0x100, raw_flags=1)
    r[0x1100:0x1100 + len(bad)] = bad
    assert "compression flags" in found(r)["note"]
