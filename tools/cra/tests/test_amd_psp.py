"""amd_psp.py：AMD EFS／PSP／BIOS 目錄、微碼、AGESA 的只讀解析。全部用測試自己組出來的假資料（不含任何產品映像，D-028）。

假映像是 1 MiB（視窗 W＝1 MiB，所以「映射在 4 GB 頂端」的位址是 0xFFF00000＋偏移）。EFS 放在 0x20000（EFS_OFFSETS 裡有）。
checksum 用測試自己的實作（逐字加總，和 amd_psp.fletcher32 刻意分開寫）。"""
import json
import lzma
import random
import struct
import sys
import time
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import amd_psp as ap  # noqa: E402
import x86_firmware as xf  # noqa: E402
from cdx_schema import cdx_validator  # noqa: E402
from test_x86_firmware import LZMA, ffs, fv, guided, sec, secs  # noqa: E402

SIZE = 0x100000
TOP = 0xFFF00000                        # 2^32 − 1 MiB：視窗 1 MiB 時，偏移 o 的實體位址是 TOP + o
EFS = 0x20000


def fl32(b):
    """獨立的測試實作：c0＝c1＝0xFFFF 起算，每個字加完就把高 16 位加回低 16 位（end-around carry），最後再折疊一次。"""
    c0 = c1 = 0xFFFF
    for i in range(0, len(b) - 1, 2):
        c0 += b[i] + (b[i + 1] << 8)
        c0 = (c0 & 0xFFFF) + (c0 >> 16)
        c1 += c0
        c1 = (c1 & 0xFFFF) + (c1 >> 16)
    c0 = (c0 & 0xFFFF) + (c0 >> 16)
    c1 = (c1 & 0xFFFF) + (c1 >> 16)
    return (c1 << 16) | c0


def ish_bytes(pl2, good=True, prio=0xFFFFFFFF, psp_id=0xBC0D0300):
    """Image Slot Header：checksum 是 fl32(+4..+0x20)。"""
    body = struct.pack("<IIIIIII", prio, 0xF, 0xFFFFFF00, pl2, psp_id, 0xFFFFFFFF, 0xFFFFFFFF)
    ck = fl32(body)
    return struct.pack("<I", ck ^ (0 if good else 1)) + body


def phys(o):
    return TOP + o


def psp_ent(typ, sub=0, size=0, addr=0, flags=0, mode=0):
    return struct.pack("<BBHIQ", typ, sub, flags, size, addr | (mode << 62))


def bhd_ent(typ, size=0, src=0, f1=0, f2=0, region=0, dest=(1 << 64) - 1, mode=0):
    return struct.pack("<BBBBIQQ", typ, region, f1, f2, size, src | (mode << 62), dest)


def directory(cookie, ents, info=0, num=None, bad_checksum=False):
    body = struct.pack("<II", len(ents) if num is None else num, info) + b"".join(ents)
    ck = fl32(body)
    if bad_checksum:
        ck ^= 0x1
    return cookie + struct.pack("<I", ck) + body


def combo(cookie, ents):
    """ents＝[(id, 位址)]。標頭 32 bytes：cookie、checksum、num、lookup、保留 16。"""
    body = struct.pack("<II", len(ents), 1) + b"\x00" * 16 + b"".join(struct.pack("<IIQ", 0, i, a) for i, a in ents)
    return cookie + struct.pack("<I", fl32(body)) + body


def psp_blob(typ, ver, size, fill=0xAA):
    """PSP 韌體：0x100 bytes 標頭（+0x60 版本、+0x6C size_total、+0x7C fw_type）加內容。"""
    b = bytearray([fill]) * size
    b[:0x100] = b"\x00" * 0x100
    b[0x10:0x14] = b"$PS1"
    b[0x60:0x64] = bytes(ver)
    struct.pack_into("<I", b, 0x6C, size)
    b[0x7C] = typ
    return bytes(b)


def patch(date=0x04162019, pid=0x0800820D, equiv=0x8082, size=0xC80):
    b = bytearray(size)
    struct.pack_into("<IIHBBIIIH", b, 0, date, pid, 0x8004, 0, 0, 0, 0, 0, equiv)
    return bytes(b)


def container(equiv_table, patches):
    """equiv_table＝[(CPUID, equiv id)]；patches＝[patch 位元組]。"""
    eq = b"".join(struct.pack("<IIIHH", cpu, 0, 0, e, 0) for cpu, e in equiv_table) + b"\x00" * 16
    out = b"DMA\x00" + struct.pack("<II", 0, len(eq)) + eq
    for p in patches:
        out += struct.pack("<II", 1, len(p)) + p
    return out


def put(img, off, b):
    img[off:off + len(b)] = b


def efs(img, new_psp=0, bios0=0, psp=0, extra=None, at=EFS):
    put(img, at, b"\xaa\x55\xaa\x55" + b"\x00" * 0x3C)
    for o, v in ((0x10, psp), (0x14, new_psp), (0x18, bios0), (0x1C, 0), (0x20, 0), (0x28, 0), (0x2C, 0)):
        struct.pack_into("<I", img, at + o, v)
    for o, v in (extra or {}).items():
        struct.pack_into("<I", img, at + o, v)


def good_image():
    """EFS → L1 PSP（bootloader、SMU、L2 指標、未知 type 0x77）→ L2 PSP（SMU2）；BIOS L1（raw patch、container、APCB）。"""
    img = bytearray(b"\xff" * SIZE)
    boot, smu, smu2 = psp_blob(1, (0x7F, 0, 9, 0), 0x300), psp_blob(8, (0, 0x56, 0x19, 0), 0x400), psp_blob(0x12, (3, 2, 1, 0), 0x200)
    put(img, 0x31000, boot)
    put(img, 0x32000, smu)
    put(img, 0x35000, smu2)
    put(img, 0x33000, b"\x11" * 0x40)
    put(img, 0x30000, directory(b"$PSP", [psp_ent(1, size=len(boot), addr=phys(0x31000)), psp_ent(8, size=len(smu), addr=phys(0x32000)),
                                          psp_ent(0x40, size=0x400, addr=phys(0x34000)), psp_ent(0x77, size=0x40, addr=phys(0x33000)),
                                          psp_ent(0x0B, size=0xFFFFFFFF, addr=1)]))
    put(img, 0x34000, directory(b"$PL2", [psp_ent(0x12, size=len(smu2), addr=phys(0x35000))]))
    uc1 = patch()
    cont = container([(0x00870F10, 0x8082), (0x00870F00, 0x8082), (0x00A20F10, 0xA210)], [patch(0x01152023, 0x0A20102B, 0xA210, 0x100)])
    put(img, 0x41000, uc1)
    put(img, 0x42000, cont)
    put(img, 0x43000, b"APCB" + b"\x00" * 0x100)
    put(img, 0x40000, directory(b"$BHD", [bhd_ent(0x66, len(uc1), phys(0x41000)), bhd_ent(0x66, len(cont), phys(0x42000), f1=0x10),
                                          bhd_ent(0x60, 0x104, phys(0x43000)), bhd_ent(0x61, 0, 0, dest=0xA200000)]))
    efs(img, new_psp=0x30000, bios0=phys(0x40000))
    return img


def run(img, **kw):
    return ap.analyze(bytes(img), **kw)


def codes(r):
    return {p["code"] for p in r["problems"]}


def dirs_by_kind(r):
    return {d["kind"]: d for d in r["directories"]}


# ---------- 正常的樣子 ----------

def test_normal_l1_l2_bios_and_microcode():
    r = run(good_image())
    json.dumps(r)
    assert [e["offset"] for e in r["efs"]] == [EFS] and r["efs"][0]["window_size"] == SIZE
    k = dirs_by_kind(r)
    assert set(k) == {"psp", "psp-l2", "bios"} and all(d["checksum_ok"] and d["trusted"] for d in k.values())
    assert k["psp-l2"]["reached_via"][0].startswith("PSP directory L1 @0x30000 entry 2")     # L1 的 0x40 指標往下走
    pf = {(p["type"], p["version"]) for p in r["psp_firmware"]}
    assert pf == {(1, "00.09.00.7f"), (8, "00.19.56.00"), (0x12, "00.01.02.03")}
    assert all(p["sha256"] and len(p["sha512"]) == 128 for p in r["psp_firmware"])
    # 0x77 不認得 → GAP；soft fuse（size 0xFFFFFFFF）是值，不是位置；L2 指標不算韌體條目
    assert "type-unknown" in codes(r) and any("0x77" in g for g in r["gaps"])
    ents = {e["type"]: e for e in k["psp"]["entries"]}
    assert ents[0x0B]["kind"] == "value" and ents[0x40]["kind"] == "directory-pointer" and ents[0x77]["type_name"] is None
    assert any(g.startswith("AMD: entries without a version") and "0x77" in g for g in r["gaps"])
    # 微碼：raw patch 只有 equivalence id（不猜 CPUID）；container 用自己的等價表對出 CPUID
    mc = {m["patch_id"]: m for m in r["microcode"]}
    assert mc["0x0800820d"]["equiv_id"] == "0x8082" and mc["0x0800820d"]["date"] == "2019-04-16" and mc["0x0800820d"]["cpuids"] is None
    assert mc["0x0800820d"]["form"] == "raw-patch"
    assert mc["0x0a20102b"]["cpuids"] == ["00A20F10"] and mc["0x0a20102b"]["form"] == "container" and mc["0x0a20102b"]["date"] == "2023-01-15"
    assert "ucode-cpuid" in codes(r) and any("equivalence id" in g and "not guessed" in g for g in r["gaps"])
    assert k["bios"]["entries"][3]["kind"] == "dest-only" and "entry-empty" not in codes(r)          # 只有 dest 的 APOB（有依據的非缺口）
    assert r["attention"] == []


def test_microcode_container_equivalence_table_maps_all_cpuids():
    img = good_image()
    cont = container([(0x00870F10, 0x8082), (0x00870F00, 0x8082)], [patch()])
    put(img, 0x42000, b"\xff" * 0x200)
    put(img, 0x42000, cont)
    put(img, 0x40000, directory(b"$BHD", [bhd_ent(0x66, len(cont), phys(0x42000))]))
    r = run(img)
    assert [m["cpuids"] for m in r["microcode"]] == [["00870F00", "00870F10"]]
    assert "ucode-cpuid" not in codes(r)


def test_combo_directory_and_cookie_variants():
    img = bytearray(b"\xff" * SIZE)
    boot = psp_blob(1, (1, 0, 0, 0), 0x200)
    put(img, 0x51000, boot)
    put(img, 0x50000, directory(b"$PSP", [psp_ent(1, size=len(boot), addr=phys(0x51000))]))
    put(img, 0x60000, directory(b"$BHD", [bhd_ent(0x66, 0xC80, phys(0x61000))]))
    put(img, 0x61000, patch())
    put(img, 0x30000, combo(b"2PSP", [(0xBC0A0000, phys(0x50000)), (0xBC090000, 0x50000)]))      # 兩種寫法（頂端位址、視窗內偏移）指到同一個目錄
    put(img, 0x30800, combo(b"2BHD", [(0xBC0A0000, 0x60000)]))
    efs(img, new_psp=0x30000, bios0=0x30800)
    r = run(img)
    k = dirs_by_kind(r)
    assert set(k) == {"combo-psp", "combo-bios", "psp", "bios"}
    assert [e["child"] for e in k["combo-psp"]["entries"]] == [0x50000, 0x50000] and len(r["directories"]) == 4
    assert [p["version"] for p in r["psp_firmware"]] == ["00.00.00.01"] and len(r["microcode"]) == 1
    assert len(k["psp"]["reached_via"]) == 2


def test_efs_shifted_by_a_capsule_header_is_found_only_if_pointers_resolve():
    img = good_image()
    shifted = bytearray(b"\xff" * 0x1000) + img[:SIZE - 0x1000]            # 前面加 4 KiB 標頭，其餘整體往後 0x1000（尾端截掉）
    shifted = bytearray(shifted)
    r = run(shifted)
    assert [(e["offset"], e["window_base"]) for e in r["efs"]] == [(EFS + 0x1000, 0x1000)]
    assert len(r["directories"]) == 3 and r["microcode"]
    # 同樣的簽章但指標都不指到目錄：不採用位移的解讀
    junk = bytearray(b"\xff" * SIZE)
    put(junk, 0x21000, b"\xaa\x55\xaa\x55" + b"\x00" * 0x10 + struct.pack("<I", 0x1234) + b"\x00" * 0x30)
    assert run(junk)["efs"] == []


# ---------- 看不懂、壞掉的輸入：都是 GAP，不猜 ----------

def test_bad_checksum_lists_entries_but_does_not_use_them():
    img = good_image()
    boot = psp_blob(1, (0x7F, 0, 9, 0), 0x300)
    put(img, 0x30000, directory(b"$PSP", [psp_ent(1, size=len(boot), addr=phys(0x31000))], bad_checksum=True))
    r = run(img)
    d = dirs_by_kind(r)["psp"]
    assert d["checksum_ok"] is False and d["trusted"] is False and len(d["entries"]) == 1
    assert "dir-checksum" in codes(r) and r["psp_firmware"] == []
    assert any("checksum" in a for a in r["attention"]) and any("checksum" in g for g in r["gaps"])
    # BIOS 目錄 checksum 錯：微碼不採用
    img = good_image()
    put(img, 0x40000, directory(b"$BHD", [bhd_ent(0x66, 0xC80, phys(0x41000))], bad_checksum=True))
    assert run(img)["microcode"] == []


def test_pointers_that_do_not_resolve():
    img = bytearray(b"\xff" * SIZE)
    efs(img, new_psp=0x70000, bios0=0xFFFFFFFE, psp=phys(0x1000))
    r = run(img)
    assert "pointer-unresolved" in codes(r) and "no-directory" in codes(r)
    assert any("no usable PSP/BIOS directory" in g for g in r["gaps"]) and any("not 'no microcode'" in g for g in r["gaps"])
    # 位址欄位大於 2^32（目錄的 address mode 0）；目錄是 mode 2（相對目錄）時才看項目自己的 mode：mode 3（相對 slot）不解，mode 2 可解
    img = good_image()
    put(img, 0x30000, directory(b"$PSP", [psp_ent(1, size=0x300, addr=1 << 40)]))
    r = run(img)
    assert "entry-address" in codes(r) and [e["kind"] for e in dirs_by_kind(r)["psp"]["entries"]] == ["unresolved"]
    img = good_image()
    boot = psp_blob(1, (1, 2, 3, 4), 0x300)
    put(img, 0x31000, boot)
    put(img, 0x30000, directory(b"$PSP", [psp_ent(8, size=0x300, addr=0x10, mode=3), psp_ent(1, size=0x300, addr=0x1000, mode=2)], info=2 << 29))
    r = run(img)
    assert [e["kind"] for e in dirs_by_kind(r)["psp"]["entries"]] == ["unresolved", "blob"] and "entry-address" in codes(r)
    assert [p["version"] for p in r["psp_firmware"]] == ["04.03.02.01"]


def test_pointer_loop_terminates_and_overlapping_pointers_are_reported():
    img = bytearray(b"\xff" * SIZE)
    put(img, 0x30000, directory(b"$PSP", [psp_ent(0x40, size=0x400, addr=phys(0x34000))]))
    put(img, 0x34000, directory(b"$PL2", [psp_ent(0x40, size=0x400, addr=phys(0x30000)), psp_ent(0x40, size=0x400, addr=phys(0x34000))]))      # 回到 L1、指到自己
    efs(img, new_psp=0x30000)
    r = run(img)
    assert "dir-loop" in codes(r) and len(r["directories"]) == 2
    # 同一個目錄內兩個條目的範圍部分重疊
    img = good_image()
    a, b = psp_blob(1, (1, 0, 0, 0), 0x300), psp_blob(8, (2, 0, 0, 0), 0x300)
    put(img, 0x31000, a)
    put(img, 0x31100, b)
    put(img, 0x30000, directory(b"$PSP", [psp_ent(1, size=0x300, addr=phys(0x31000)), psp_ent(8, size=0x300, addr=phys(0x31100))]))
    assert "entry-overlap" in codes(run(img)) and "overlapping" in " ".join(run(img)["attention"])
    # 不同目錄指到完全相同的範圍：正常（共用條目），不是重疊
    img = good_image()
    put(img, 0x36000, directory(b"$PSP", [psp_ent(1, size=0x300, addr=phys(0x31000))]))
    put(img, 0x30800, combo(b"2PSP", [(1, phys(0x30000)), (2, phys(0x36000))]))
    efs(img, new_psp=0x30800)
    assert "entry-overlap" not in codes(run(img))
    # 條目範圍蓋到目錄表
    img = good_image()
    put(img, 0x30000, directory(b"$PSP", [psp_ent(1, size=0x300, addr=phys(0x30010))]))
    assert "entry-overlap" in codes(run(img))


def test_entry_range_huge_sizes_and_truncation():
    img = good_image()
    put(img, 0x30000, directory(b"$PSP", [psp_ent(1, size=0x2000, addr=phys(SIZE - 0x100)), psp_ent(8, size=0xFFFFFFF0, addr=phys(0x32000)),
                                          psp_ent(1, size=0x300, addr=phys(0x31000))]))
    r = run(img)
    assert {"entry-range", "entry-size"} <= codes(r)
    assert [p["type"] for p in r["psp_firmware"]] == [1]             # 範圍外、巨大的條目不讀、不雜湊
    # 目錄的項目表超出檔案結尾（檔案被截斷）：dir-truncated，不丟例外
    img = good_image()
    put(img, SIZE - 0x20, b"$PSP" + struct.pack("<IIII", 0, 10, 0, 0) + b"\x00" * 0x10)
    efs(img, new_psp=SIZE - 0x20)
    r = run(img)
    assert "dir-truncated" in codes(r) and dirs_by_kind(r)["psp"]["parsed"] is False and r["psp_firmware"] == []
    # EFS 本身被截斷
    assert ap.analyze(bytes(img)[:EFS + 0x10])["efs"] == []
    for n in (0, 1, 4, 100):
        assert ap.analyze(bytes(img)[:n])["directories"] == []


def test_too_many_entries_and_total_limits(monkeypatch):
    img = good_image()
    put(img, 0x30000, directory(b"$PSP", [psp_ent(1, size=0x300, addr=phys(0x31000))], num=0xFFFFFF))
    r = run(img)
    assert "dir-too-many-entries" in codes(r) and dirs_by_kind(r)["psp"]["parsed"] is False and r["psp_firmware"] == []
    # 項目數剛好超過單一目錄上限
    put(img, 0x30000, directory(b"$PSP", [psp_ent(1, size=0x300, addr=phys(0x31000))] * 257))
    assert "dir-too-many-entries" in codes(run(img)) and ap.MAX_DIR_ENTRIES == 256
    put(img, 0x30000, directory(b"$PSP", [psp_ent(1, size=0x300, addr=phys(0x31000))] * 256))
    assert "dir-too-many-entries" not in codes(run(img))
    # 跨目錄的項目總數（各目錄都沒超過單一上限）
    monkeypatch.setattr(ap, "MAX_ENTRIES_TOTAL", 6)
    r = run(good_image())
    assert "dir-limit" in codes(r) and any("entries not parsed" in p["text"] for p in r["problems"] if p["code"] == "dir-limit")
    monkeypatch.setattr(ap, "MAX_ENTRIES_TOTAL", 4096)
    monkeypatch.setattr(ap, "MAX_DIRS", 2)
    assert "dir-limit" in codes(run(good_image()))
    monkeypatch.setattr(ap, "MAX_DIRS", 64)
    monkeypatch.setattr(ap, "MAX_DEPTH", 0)
    assert "dir-limit" in codes(run(good_image()))


def test_hash_budget_is_total_and_deduplicated(monkeypatch):
    img = good_image()
    r = run(img)
    n = r["stats"]["hashed_bytes"]
    assert n > 0
    # 同一段 offset＋size 在兩個目錄各出現一次：只算一次
    put(img, 0x36000, directory(b"$PSP", [psp_ent(1, size=0x300, addr=phys(0x31000))]))
    put(img, 0x30800, combo(b"2PSP", [(1, phys(0x30000)), (2, phys(0x36000))]))
    efs(img, new_psp=0x30800, bios0=phys(0x40000))
    assert run(img)["stats"]["hashed_bytes"] == n
    monkeypatch.setattr(ap, "MAX_HASH_TOTAL", 0x400)
    r = run(good_image())
    assert "hash-limit" in codes(r) and any(p["sha256"] is None for p in r["psp_firmware"] + r["microcode"])


def test_psp_version_needs_a_matching_header():
    img = good_image()
    smu = bytearray(psp_blob(8, (0, 0x56, 0x19, 0), 0x400))
    smu[0x7C] = 9                                   # fw_type 和目錄項目不符
    put(img, 0x32000, smu)
    assert 8 not in {p["type"] for p in run(img)["psp_firmware"]}
    smu[0x7C] = 8
    struct.pack_into("<I", smu, 0x6C, 0x4000)       # size_total 比項目大
    put(img, 0x32000, smu)
    assert 8 not in {p["type"] for p in run(img)["psp_firmware"]}
    smu[0x60:0x64] = b"\x00\x00\x00\x00"            # 欄位全 0
    struct.pack_into("<I", smu, 0x6C, 0x400)
    put(img, 0x32000, smu)
    assert 8 not in {p["type"] for p in run(img)["psp_firmware"]}
    smu[0x60:0x64] = b"\x00\x56\x19\x00"
    put(img, 0x32000, smu)
    assert 8 in {p["type"] for p in run(img)["psp_firmware"]}


def test_unrecognised_microcode_is_a_gap():
    for bad in (patch(date=0x13322019), patch(pid=0), patch(equiv=0), b"\x00" * 0xC80, container([(1, 2)], [b"\x00" * 0x40])):
        img = good_image()
        put(img, 0x41000, b"\xff" * 0x2000)
        put(img, 0x41000, bad)
        put(img, 0x40000, directory(b"$BHD", [bhd_ent(0x66, len(bad), phys(0x41000))]))
        r = run(img)
        assert r["microcode"] == [] and "ucode-unrecognised" in codes(r), bad[:8]
    # container 的等價表壞掉（大小不是 16 的倍數）／patch 區段比宣告的短
    bad = b"DMA\x00" + struct.pack("<II", 0, 7) + b"\x00" * 0x40
    img = good_image()
    put(img, 0x41000, bad)
    put(img, 0x40000, directory(b"$BHD", [bhd_ent(0x66, len(bad), phys(0x41000))]))
    assert "ucode-unrecognised" in codes(run(img))
    cont = container([(1, 0x8082)], [patch()])[:-0x100]                      # patch 區段比宣告的短
    put(img, 0x41000, cont)
    put(img, 0x40000, directory(b"$BHD", [bhd_ent(0x66, len(cont), phys(0x41000))]))
    r = run(img)
    assert "ucode-unrecognised" in codes(r) and r["microcode"] == []


def test_a_b_recovery_slot_header_leads_to_the_l2_directory():
    """0x48／0x4A（size 0 或 0x100）指到 Image Slot Header，裡面的 pl2_location 是 L2 目錄；checksum 對才採用；不能當成「沒有資料」。"""
    img = bytearray(b"\xff" * SIZE)
    smu = psp_blob(8, (0, 0x54, 0x4F, 0), 0x200)
    put(img, 0x52000, smu)
    put(img, 0x51000, directory(b"$PL2", [psp_ent(8, size=len(smu), addr=0x52000, mode=1)], info=1 << 29))
    put(img, 0x50120, ish_bytes(0x51000))
    put(img, 0x50140, ish_bytes(0xDEAD0000))                                          # pl2_location 不是目錄
    put(img, 0x50160, ish_bytes(0x51000, good=False))                                 # checksum 不符：不採用
    put(img, 0x50000, directory(b"$PSP", [psp_ent(0x48, size=0, addr=0x50120), psp_ent(0x4A, size=0x100, addr=0x50140), psp_ent(0x48, size=0, addr=0x50160),
                                          psp_ent(0x48, size=0, addr=SIZE - 8), psp_ent(0x4A, size=0x44, addr=0x50120)], info=1 << 29))
    efs(img, new_psp=0x50000)
    r = run(img)
    k = dirs_by_kind(r)
    assert set(k) == {"psp", "psp-l2"} and k["psp-l2"]["reached_via"][0].startswith("PSP directory L1 @0x50000 entry 0")
    ents = k["psp"]["entries"]
    assert [e["kind"] for e in ents] == ["ish", "ish", "ish", "unresolved", "unresolved"]
    assert ents[0]["child"] == 0x51000 and ents[0]["ish"]["checksum_verified"] is True and ents[2]["ish"]["checksum_verified"] is False and ents[2]["child"] is None
    assert [p["version"] for p in r["psp_firmware"]] == ["00.4f.54.00"]
    assert {"ish-checksum", "pointer-unresolved", "entry-address", "ish-size"} <= codes(r)
    assert any("image slot header checksum" in a for a in r["attention"])


def test_compressed_entries_are_range_checked_gap_and_never_parsed_as_plain_data():
    img = good_image()
    put(img, 0x41000, patch())
    ents = [bhd_ent(0x62, 0x400020, 0x80000, f1=0x0B),                       # 壓縮、size 超過檔尾：起點在檔案內，記 GAP，不算 entry-range
            bhd_ent(0x66, 0xC80, 0x41000, f1=0x08),                          # 壓縮的微碼：開頭剛好像明文 patch 也不能列成微碼
            bhd_ent(0x66, 0x100, SIZE - 0x10, f1=0x08),                      # 壓縮的微碼、起點接近檔尾
            bhd_ent(0x66, 0x100, SIZE + 0x1000, f1=0x08)]                    # 壓縮、起點在檔案外（目錄 address mode 1＝相對視窗）
    put(img, 0x40000, directory(b"$BHD", ents, info=1 << 29))
    r = run(img)
    assert r["microcode"] == [] and "ucode-unrecognised" not in codes(r)
    kinds = [e["kind"] for e in dirs_by_kind(r)["bios"]["entries"]]
    assert kinds == ["compressed", "compressed", "compressed", "unresolved"] and "entry-range" in codes(r)
    assert "entry-compressed" in codes(r) and "entry-overlap" not in codes(r)
    assert any("compressed entries" in g and "(3)" in g for g in r["gaps"])
    assert any("runs past the end" in p["text"] for p in r["problems"] if p["code"] == "entry-compressed")


def test_size_zero_entries_are_gaps_except_apob_with_a_destination():
    img = good_image()
    boot = psp_blob(1, (1, 2, 3, 4), 0x300)
    put(img, 0x31000, boot)
    put(img, 0x30000, directory(b"$PSP", [psp_ent(1, size=len(boot), addr=phys(0x31000)), psp_ent(8, size=0, addr=phys(0x32000)), psp_ent(0x12, size=0, addr=0)]))
    put(img, 0x40000, directory(b"$BHD", [bhd_ent(0x66, 0, phys(0x41000)), bhd_ent(0x61, 0, 0, dest=0xA200000), bhd_ent(0x61, 0, 0), bhd_ent(0x63, 0, 0)]))
    r = run(img)
    assert [e["kind"] for e in dirs_by_kind(r)["psp"]["entries"]] == ["blob", "empty", "empty"]
    assert [e["kind"] for e in dirs_by_kind(r)["bios"]["entries"]] == ["empty", "dest-only", "empty", "empty"]      # APOB 沒有 destination 或其他 type：缺口
    assert r["microcode"] == []
    gap = next(g for g in r["gaps"] if "entries with size 0" in g)
    assert "(5)" in gap


def test_unparsed_efs_pointers_are_reported():
    img = good_image()
    struct.pack_into("<I", img, EFS + 0x38, phys(0x50000))
    r = run(img)
    assert "efs-pointer-unparsed" in codes(r) and any("promontory19" in g for g in r["gaps"])


# ---------- AGESA ----------

def agesa_image(*strings, pad=b"\x00"):
    img = bytearray(b"\xff" * SIZE)
    o = 0x80000
    for s in strings:
        put(img, o, s)
        o += 0x1000
    return img


def test_agesa_string_is_read_and_multiple_values_are_all_listed():
    r = run(agesa_image(b"AGESA!V9\x00ComboAM4v2PI 1.2.0.B\x00\x00"))
    ag = r["agesa"]
    assert [(x["tag"], x["value"], x["count"]) for x in ag["values"]] == [("AGESA!V9", "ComboAM4v2PI 1.2.0.B", 1)]
    assert ag["values"][0]["found"][0]["where"].startswith("uefi:")        # FV 以外的位元組由走訪器當原始內容送進來；offset 是該塊內容裡的
    assert not any("more than one AGESA" in a for a in r["attention"]) and ag["complete"] is False       # 沒有 firmware volume：只搜了原始位元組
    assert any("no UEFI firmware volume" in p for p in ag["problems"]) and any("AGESA search" in g for g in r["gaps"])
    r = run(agesa_image(b"AGESA!V9\x00ComboAM4v2PI 1.2.0.B", b"AGESA!V9\x00ComboAM4v2PI 1.2.0.C", b"AGESA!V9 ComboAM4v2PI 1.2.0.B", b"AGESA!V4\x00RenoirPI-FP6 1.0.0.8"))
    assert [(x["tag"], x["value"], x["count"]) for x in r["agesa"]["values"]] == [
        ("AGESA!V4", "RenoirPI-FP6 1.0.0.8", 1), ("AGESA!V9", "ComboAM4v2PI 1.2.0.B", 2), ("AGESA!V9", "ComboAM4v2PI 1.2.0.C", 1)]
    assert any("more than one AGESA string" in a for a in r["attention"])


def test_agesa_marker_without_a_string_and_long_values():
    r = run(agesa_image(b"AGESA!V9\x00\x00\x00", b"AGESA!V\x00\xff\xff"))
    assert r["agesa"]["values"] == [] and sum("without a readable version string" in p for p in r["agesa"]["problems"]) == 2
    r = run(agesa_image(b"AGESA!V9\x00" + b"A" * 500))
    v = r["agesa"]["values"][0]
    assert len(v["value"]) == ap.AGESA_VALUE_LEN and v["truncated"] is True


def test_agesa_inside_a_compressed_uefi_section():
    """LZMA 壓縮的 section 裡的字串：原始位元組掃不到，走訪 firmware volume 解開後才找得到（模組 GUID 記在位置裡）。"""
    inner = secs(sec(0x10, b"MZ" + b"\x00" * 30 + b"AGESA!V9\x00ComboAM4v2PI 1.2.0.B\x00" + b"\x00" * 16))
    blob = fv([ffs(0x07, secs(guided(LZMA, lzma.compress(inner, format=lzma.FORMAT_ALONE))), k=3)])
    img = bytearray(b"\xff" * SIZE)
    put(img, 0x80000, blob)
    assert b"AGESA!V" not in bytes(img)
    r = run(img)
    ag = r["agesa"]
    assert ag["walk"] is True and ag["stats"]["fvs"] == 1 and ag["complete"] is True
    assert [x["value"] for x in ag["values"]] == ["ComboAM4v2PI 1.2.0.B"] and ag["values"][0]["found"][0]["where"].startswith("uefi:")
    # 解不開的壓縮 section（EFI 標準壓縮）：搜尋不完整，要說明
    blob = fv([ffs(0x07, secs(sec(0x01, struct.pack("<IB", 8, 1) + b"\x11" * 8)), k=3)])
    img = bytearray(b"\xff" * SIZE)
    put(img, 0x80000, blob)
    ag = run(img)["agesa"]
    assert ag["complete"] is False and any("not decoded" in p for p in ag["problems"])


def test_agesa_caps(monkeypatch):
    monkeypatch.setattr(ap, "MAX_AGESA_MARKERS", 50)
    img = bytearray(b"\xff" * SIZE)
    put(img, 0x1000, b"AGESA!V9\x00ComboAM4v2PI 1.2.0.B\x00" * 5000)
    t = time.monotonic()
    r = run(img)
    assert r["agesa"]["stats"]["markers"] == 50 and any("more than 50 AGESA markers" in p for p in r["agesa"]["problems"])
    assert time.monotonic() - t < 10
    monkeypatch.setattr(ap, "MAX_AGESA_MARKERS", 4096)
    monkeypatch.setattr(ap, "MAX_AGESA_VALUES", 3)
    img = bytearray(b"\xff" * SIZE)
    put(img, 0x1000, b"".join(b"AGESA!V9\x00PI 1.%d\x00" % i for i in range(20)))
    r = run(img)
    assert len(r["agesa"]["values"]) == 3 and any("more than 3 distinct AGESA" in p for p in r["agesa"]["problems"])


# ---------- 上限與不可信輸入：不爆、不放大 ----------

def test_many_efs_signatures_are_capped_and_fast(monkeypatch):
    img = bytearray(b"\xff" * SIZE)
    for i in range(0x1000, 0x80000, 0x10):
        img[i:i + 4] = b"\xaa\x55\xaa\x55"
    t = time.monotonic()
    r = run(img)
    assert time.monotonic() - t < 10 and r["efs"] == [] and "efs-limit" in codes(r)


def test_one_efs_per_16mib_window_and_the_efs_limit(monkeypatch):
    img = bytearray(b"\xff" * (0x2100000))
    for w in range(3):
        put(img, w * 0x1000000 + EFS, b"\xaa\x55\xaa\x55" + b"\x00" * 0x3C)
    r = run(img)
    assert [(e["offset"], e["window_base"], e["window_size"]) for e in r["efs"]] == [(EFS, 0, 1 << 24), (0x1000000 + EFS, 0x1000000, 1 << 24), (0x2000000 + EFS, 0x2000000, 0x100000)]
    assert codes(r) >= {"efs-no-pointer"}
    monkeypatch.setattr(ap, "MAX_EFS", 2)
    r = run(img)
    assert len(r["efs"]) == 2 and "efs-limit" in codes(r)


def test_numeric_fields_never_crash_random_mutations():
    base = bytes(good_image())
    rnd = random.Random(1234)
    spots = [EFS + o for o in range(0, 0x3C)] + [0x30000 + o for o in range(0, 0x70)] + [0x34000 + o for o in range(0, 0x20)] + \
            [0x40000 + o for o in range(0, 0xA0)] + [0x42000 + o for o in range(0, 0x80)] + [0x31000 + 0x60 + o for o in range(8)]
    for _ in range(400):
        m = bytearray(base)
        for _ in range(rnd.randint(1, 6)):
            m[rnd.choice(spots)] = rnd.choice((0x00, 0xFF, 0x7F, 0x80, rnd.randrange(256)))
        r = ap.analyze(bytes(m))
        json.dumps(r)
        assert isinstance(r["gaps"], list) and r["stats"]["directories"] <= ap.MAX_DIRS
    # 全 0、全 0xFF、隨機位元組
    for blob in (b"\x00" * SIZE, b"\xff" * SIZE, bytes(rnd.randrange(256) for _ in range(5000))):
        assert ap.analyze(blob)["directories"] == []


def test_soft_budget_exception_keeps_partial_results():
    class Over(Exception):
        pass

    class Budget:
        calls = 0

        def check(self):
            self.calls += 1
            if self.calls > 2:
                raise Over("time limit")
    r = ap.analyze(bytes(good_image()), Budget(), (Over,))
    assert isinstance(r["agesa"]["problems"], list) and any("stopped early" in p for p in r["agesa"]["problems"] + r["incomplete"])


def test_fletcher32_matches_the_independent_test_implementation():
    rnd = random.Random(5)
    for n in (0, 2, 8, 100, 6176):
        b = bytes(rnd.randrange(256) for _ in range(n))
        assert ap.fletcher32(b) == fl32(b)
    assert ap.fletcher32(b"\xff\xff" * 10) == fl32(b"\xff\xff" * 10)
    assert ap.bcd_date(0x04162019) == "2019-04-16" and ap.bcd_date(0x0416201A) is None and ap.bcd_date(0x13012019) is None
    assert ap.window_size(0x100000, 0) == 0x100000 and ap.window_size(33554432, 0) == 16 << 20 and ap.window_size(10, 0) == 16
    assert ap.to_offset(0xFF110400, 0, 16 << 20) == 0x110400 and ap.to_offset(0x110400, 0x1000, 16 << 20) == 0x111400 and ap.to_offset(1 << 32, 0, 1) is None


# ---------- x86_firmware.py 的接線 ----------

def test_wiring_into_inventory_sbom_status_and_markdown(tmp_path):
    p = tmp_path / "amd.bin"
    img = good_image()
    put(img, 0x80000, b"AGESA!V9\x00ComboAM4v2PI 1.2.0.B\x00")
    p.write_bytes(bytes(img))
    inv = xf.inventory([p])
    b = inv["bios"][0]
    assert b["platform"] == "amd" and b["amd"]["stats"]["directories"] == 3 and b["microcode"] == []
    json.dumps(inv)
    assert not any("AMD microcode (PSP directories) is not supported" in g for g in b["gaps"])
    comps, deps = xf.components(inv)
    assert not list(cdx_validator().iter_errors(xf.bom(comps, deps)))
    refs = [c["bom-ref"] for c in comps]
    assert len(refs) == len(set(refs))
    by = {c["name"]: c for c in comps}
    agesa = by["AMD AGESA"]
    assert agesa["version"] == "ComboAM4v2PI 1.2.0.B"
    mc = [c for c in comps if c["name"].startswith("AMD CPU microcode")]
    assert {c["version"] for c in mc} == {"0x0800820d", "0x0a20102b"}
    psp = [c for c in comps if c["name"].startswith("AMD PSP firmware")]
    assert {c["version"] for c in psp} == {"00.09.00.7f", "00.19.56.00", "00.01.02.03"}
    for c in agesa, *mc, *psp:
        assert [q["value"] for q in c["properties"] if q["name"] == "dumpling:vuln-assessment"] == ["NOT_ASSESSED"]
        assert [q["value"] for q in c["properties"] if q["name"] == "dumpling:vuln-assessment-note"] == [xf.ASSESS_NOTES["amd"]]
        assert [q["value"] for q in c["properties"] if q["name"] == "dumpling:version-status"] == ["OK"]
    assert all(ref in deps[next(iter(deps))] for ref in refs if ":amd-" in ref)
    img_comp = comps[0 if comps[0]["name"] == "amd.bin" else [c["name"] for c in comps].index("amd.bin")]
    assert any(q["name"] == "sca-center:gap" and q["value"].startswith("AMD: entries of unknown type") for q in img_comp["properties"])
    st, detail = xf.status_of(inv)
    assert st == "ATTENTION" and "AMD 平台（3 directories" in detail and "GAP" in detail
    md = xf.markdown(inv)
    assert "AMD PSP／BIOS 目錄、微碼與 AGESA" in md and "ComboAM4v2PI 1.2.0.B" in md and "0x0800820d" in md and "不支援" not in md
    # 沒有 microcode 的 PSP 解析結果也不能偽裝成完整
    assert "AMD 微碼" in md


def test_wiring_when_the_parser_cannot_run(tmp_path, monkeypatch):
    img = bytearray(b"\xff" * 0x21000)
    img[0x20000:0x20004] = xf.AMD_EFS_SIG
    img[0x20800:0x20810] = b"$PSP" + struct.pack("<III", 0, 5, 0)

    real = xf.load_sibling

    def boom(name):
        if name == "amd_psp":
            raise xf.Fail("cannot load amd_psp.py")
        return real(name)
    monkeypatch.setattr(xf, "load_sibling", boom)
    b = xf.bios_image(bytes(img))
    assert b["platform"] == "amd" and b["amd"] is None
    assert any("parser did not run" in g and "not 'no microcode'" in g for g in b["gaps"])


# ---------- 預驗抓到的問題：不丟例外、壓縮與 size 0 的缺口、位址座標、AGESA 的邊界 ----------

def test_analyze_never_raises_even_when_a_stage_or_an_entry_breaks(monkeypatch):
    # 壓縮的微碼條目起點靠近檔尾（patch_header 不能丟 struct.error）、一般條目的內容解析丟例外：只影響那個條目或階段
    img = good_image()
    put(img, 0x40000, directory(b"$BHD", [bhd_ent(0x66, 0x100, SIZE - 0x10, f1=0x08), bhd_ent(0x66, 0xC80, 0x41000)], info=1 << 29))
    r = run(img)
    assert [m["patch_id"] for m in r["microcode"]] == ["0x0800820d"] and "entry-compressed" in codes(r)
    real = ap.parse_ucode

    def boom(ctx, ent):
        raise ValueError("boom")
    monkeypatch.setattr(ap, "parse_ucode", boom)
    r = run(good_image())
    assert "entry-error" in codes(r) and r["psp_firmware"] and any("failed to parse" in g or "content parse failed" in g for g in r["gaps"])
    monkeypatch.setattr(ap, "parse_ucode", real)

    def boom2(ctx, amd):
        raise RuntimeError("boom")
    monkeypatch.setattr(ap, "collect_contents", boom2)
    r = run(good_image())
    assert "internal-error" in codes(r) and len(r["directories"]) == 3 and r["agesa"]["problems"] is not None
    assert any("internal-error" in a or "parse stages that failed" in a for a in r["attention"])
    monkeypatch.undo()

    def boom3(ctx, rec, i, e, where):
        raise struct.error("boom")
    monkeypatch.setattr(ap, "entry", boom3)
    r = run(good_image())
    assert "entry-error" in codes(r) and len(r["directories"]) >= 2 and all(e["kind"] == "unresolved" for d in r["directories"] for e in d["entries"])
    monkeypatch.undo()

    def boom4(data, budget=None, soft=()):
        raise OSError("boom")
    monkeypatch.setattr(ap, "agesa_search", boom4)
    r = run(good_image())
    assert r["agesa"]["complete"] is False and any("failed" in p for p in r["agesa"]["problems"]) and r["psp_firmware"]


def test_random_bios_entries_never_raise():
    rnd = random.Random(99)
    sizes = [0, 1, 0x10, 0x1A, 0x100, 0xC80, 0x1000, 0xFFFFFFFF, 0xFFFFFFF0, 0x4000000, 0x4000001, SIZE]
    addrs = [0, 1, 0x41000, SIZE - 0x10, SIZE - 1, SIZE, SIZE + 0x1000, 0xFFFFFFFF, 1 << 40, (1 << 62) - 1, phys(0x41000), phys(SIZE - 8)]
    for _ in range(300):
        img = good_image()
        put(img, 0x41000, rnd.choice([patch(), container([(1, 0x8082)], [patch()]), b"DMA\x00" + bytes(rnd.randrange(256) for _ in range(40))]))
        ents = [bhd_ent(rnd.choice([0x66, 0x66, 0x62, 0x61, 0x60, 0x70, 0x77]), rnd.choice(sizes), rnd.choice(addrs), f1=rnd.randrange(256), f2=rnd.randrange(256),
                        mode=rnd.randrange(4)) for _ in range(rnd.randrange(1, 8))]
        put(img, 0x40000, directory(b"$BHD", ents, info=rnd.choice([0, 1 << 29, 2 << 29, 3 << 29, (1 << 31) | (1 << 24), (1 << 31) | (2 << 24)])))
        r = run(img)
        json.dumps(r)
        assert isinstance(r["gaps"], list)


def two_readings_image(extra_pointer=None):
    """EFS 在 0x21000（視窗開頭 0x1000，位移）。new_psp 指標 0x30000：視窗座標是 0x31000、整個檔案的偏移是 0x30000，兩邊都有目錄（內容不同、checksum 都對）。"""
    img = bytearray(b"\xff" * (SIZE + 0x1000))
    a, b = psp_blob(1, (1, 1, 1, 1), 0x300), psp_blob(1, (2, 2, 2, 2), 0x300)
    put(img, 0x50000, a)
    put(img, 0x51000, b)
    put(img, 0x30000, directory(b"$PSP", [psp_ent(1, size=0x300, addr=0x50000, mode=1)], info=1 << 29))     # 檔案座標：基底 0 → 0x50000（a）
    put(img, 0x31000, directory(b"$PSP", [psp_ent(1, size=0x300, addr=0x50000, mode=1)], info=1 << 29))     # 視窗座標：基底 0x1000 → 0x51000（b）
    put(img, 0x60000, directory(b"$BHD", [bhd_ent(0x60, 0x104, 0x43000)]))               # 第二種 cookie：讓 x86_firmware 認得這是 AMD 平台（EFS 不在固定位置）
    efs(img, new_psp=0x30000, at=0x21000, extra=extra_pointer)
    return img


def test_pointer_readable_both_ways_lists_both_sides_and_uses_neither(tmp_path):
    img = two_readings_image()
    r = run(img)
    k = {d["offset"]: d for d in r["directories"]}
    assert sorted(k) == [0x30000, 0x31000] and all(d["checksum_ok"] and d["ambiguous"] for d in k.values())
    assert k[0x30000]["readings"] == ["0x31000"] and k[0x31000]["readings"] == ["0x30000"]
    assert "pointer-ambiguous" in codes(r) and "dir-ambiguous" in codes(r)
    assert r["psp_firmware"] == []                                                       # 兩邊的版本都不進 SBOM 用的清單
    assert sorted(p["version"] for p in r["ambiguous"]["psp_firmware"]) == ["01.01.01.01", "02.02.02.02"]
    assert any("this tool does not decide which one the hardware uses" in p["text"] for p in r["problems"] if p["code"] == "pointer-ambiguous")
    assert any(g.startswith("AMD: pointers readable as a directory in two ways") for g in r["gaps"]) and any(g.startswith("AMD: directories reachable only") for g in r["gaps"])
    assert any("in two ways" in a for a in r["attention"])
    md = "\n".join(ap.markdown_lines(r, str))
    assert md.count("**歧義**") >= 2 and "01.01.01.01" in md and "02.02.02.02" in md and "不進 SBOM" in md and "歧義目錄裡的版本" in md
    p = tmp_path / "amb.bin"
    p.write_bytes(bytes(img))
    inv = xf.inventory([p])
    st, detail = xf.status_of(inv)
    assert st == "ATTENTION" and "pointers readable as a directory in two ways" in detail
    md = xf.markdown(inv)
    assert "pointers readable as a directory in two ways" in md and "01.01.01.01" in md and "02.02.02.02" in md
    comps, deps = xf.components(inv)
    assert not [c for c in comps if c["name"].startswith("AMD PSP firmware")]           # SBOM 不能只放其中一邊
    bios = next(c for c in comps if c["name"] == "amb.bin")
    assert any(q["name"] == "sca-center:gap" and "two ways" in q["value"] for q in bios["properties"])


def test_directory_also_reached_by_an_unambiguous_pointer_is_definite_and_children_inherit():
    img = bytearray(b"\xff" * (SIZE + 0x1000))
    a, b = psp_blob(1, (1, 1, 1, 1), 0x300), psp_blob(1, (2, 2, 2, 2), 0x300)
    put(img, 0x50000, a)
    put(img, 0x51000, b)
    put(img, 0x34000, directory(b"$PL2", [psp_ent(1, size=0x300, addr=0x51000, mode=1)], info=1 << 29))
    put(img, 0x30000, directory(b"$PSP", [psp_ent(1, size=0x300, addr=0x50000, mode=1)], info=1 << 29))                          # 檔案偏移的讀法（基底 0）
    put(img, 0x31000, directory(b"$PSP", [psp_ent(1, size=0x300, addr=0x50000, mode=1), psp_ent(0x40, size=0x400, addr=0x33000, mode=1)], info=1 << 29))     # 視窗讀法（基底 0x1000）
    efs(img, new_psp=0x30000)                                                       # EFS#1（基底 0）：0x30000 只有檔案偏移讀法 0x30000 …… 視窗 0 + 0x30000，單一解讀
    efs(img, new_psp=0x30000, at=0x21000)                                           # EFS#2（基底 0x1000）：兩種讀法都有目錄
    r = run(img)
    k = {d["offset"]: d for d in r["directories"]}
    assert sorted(k) == [0x30000, 0x31000, 0x34000]
    assert [k[o]["ambiguous"] for o in (0x30000, 0x31000, 0x34000)] == [False, True, True]       # 0x34000 在歧義的 0x31000 底下
    assert [p["version"] for p in r["psp_firmware"]] == ["01.01.01.01"]
    assert sorted(p["version"] for p in r["ambiguous"]["psp_firmware"]) == ["02.02.02.02"]


def test_agesa_tag_separator_truncation_and_dedupe():
    r = run(agesa_image(b"AGESA!V9ComboAM4v2PI 1.2.0.B\x00"))
    ag = r["agesa"]
    assert ag["values"] == [] and any("no NUL or space after the tag" in p for p in ag["problems"])
    assert any("AMD: AGESA search" in g and "no NUL or space" in g for g in r["gaps"])
    r = run(agesa_image(b"AGESA!V\x00" + b"x"))                            # tag 是空的
    assert r["agesa"]["values"] == []
    r = run(agesa_image(b"AGESA!V9 ComboAM4v2PI 1.2.0.B\x00", b"AGESA!V9\x00ComboAM4v2PI 1.2.0.B\x00"))
    assert [(x["tag"], x["value"], x["count"]) for x in r["agesa"]["values"]] == [("AGESA!V9", "ComboAM4v2PI 1.2.0.B", 2)]
    # 超過長度上限：不是完整版本
    r = run(agesa_image(b"AGESA!V9\x00" + b"A" * 200 + b" 1.2.0.B\x00"))
    v = r["agesa"]["values"][0]
    assert v["truncated"] is True and len(v["value"]) == ap.AGESA_VALUE_LEN
    assert any("not used as a complete version" in p for p in r["agesa"]["problems"])
    assert any("no complete AGESA version string" in g for g in r["gaps"]) and r["attention"] == [] and r["stats"]["agesa_values"] == 0
    assert "被截斷" in "\n".join(ap.markdown_lines(r, str))
    # 剛好 64 個字元（沒有更多）不是截斷
    assert run(agesa_image(b"AGESA!V9\x00" + b"B" * ap.AGESA_VALUE_LEN + b"\x00"))["agesa"]["values"][0]["truncated"] is False
    assert run(agesa_image(b"AGESA!V9\x00" + b"B" * (ap.AGESA_VALUE_LEN + 1)))["agesa"]["values"][0]["truncated"] is True
    # 問題訊息不重複
    r = run(agesa_image(*([b"AGESA!V9\x00\x00\x00"] * 20)))
    ps = r["agesa"]["problems"]
    assert len(ps) == len(set(ps)) and len(ps) <= 4


def test_agesa_marker_in_raw_bytes_always_makes_the_search_incomplete_and_is_not_double_counted():
    """原始位元組裡只要有 AGESA 標記就不完整（沒有正式介面可以證明那個位置有被走訪搜尋過），包括走訪也找得到的原始 PE 內容；走訪結果裡已經有的值不重複計數，只在原始位元組裡有的值列出。"""
    M = b"AGESA!V9\x00ComboAM4v2PI 9.9.9.9\x00"
    for name, volume in (("ui", fv([ffs(0x07, secs(sec(0x15, M + b"\0" * 8)))])), ("pad", fv([ffs(0xF0, M + b"\0" * 8)])),
                         ("deleted", fv([ffs(0x07, secs(sec(0x10, M + b"\0" * 8)), state=0x00)])), ("pe", fv([ffs(0x07, secs(sec(0x10, b"MZ" + M + b"\0" * 8)))]))):
        img = bytearray(b"\xff" * SIZE)
        put(img, 0x80000, volume)
        ag = run(img)["agesa"]
        assert ag["complete"] is False and any("no formal interface" in p and "M7" in p for p in ag["problems"]), name
        assert [x["value"] for x in ag["values"]] == ["ComboAM4v2PI 9.9.9.9"], name
        where = [f["where"] for f in ag["values"][0]["found"]]
        if name == "ui":                             # UI section 的內容走訪不搜尋：只在原始位元組裡有，列成 image (raw bytes)
            assert where == ["image (raw bytes)"] and ag["values"][0]["count"] == 1, name
        else:                                        # 走訪也找到：只算走訪的那一次，不重複計數
            assert all(w.startswith("uefi:") for w in where) and ag["values"][0]["count"] == 1, name


def test_agesa_missed_by_the_walk_makes_it_incomplete(monkeypatch):
    """走訪看不到的位置（這裡用假的 uefi_image：什麼內容都不送）裡的標記：列出來、搜尋不完整。"""
    class FakeScan:
        fvs, files, parse_errors, notes, undecoded = 1, 1, 0, [], []

    class FakeUi:
        Scan = FakeScan

        class Stop(Exception):
            pass

        @staticmethod
        def parse_fvs(data, sc, depth):
            return None
    monkeypatch.setattr(ap, "_sibling", lambda name: FakeUi)
    ag = run(agesa_image(b"AGESA!V9\x00ComboAM4v2PI 9.9.9.9\x00"))["agesa"]
    assert ag["complete"] is False and [x["value"] for x in ag["values"]] == ["ComboAM4v2PI 9.9.9.9"]
    assert ag["values"][0]["found"][0]["where"] == "image (raw bytes)" and any("no formal interface" in p for p in ag["problems"])


def test_efs_offset_tables_depend_on_the_window_size():
    def with_efs(size, at):
        img = bytearray(b"\xff" * size)
        put(img, at, b"\xaa\x55\xaa\x55" + b"\x00" * 0x3C)
        return [e["offset"] for e in run(img)["efs"]]
    assert with_efs(8 << 20, 0x7A0000) == [0x7A0000]                 # 8 MiB 表
    assert with_efs(16 << 20, 0x7A0000) == []                         # 16 MiB 表沒有 0x7A0000：不是 EFS 的位置
    assert with_efs(16 << 20, 0xFA0000) == [0xFA0000] and with_efs(8 << 20, 0x3A0000) == []
    assert with_efs(4 << 20, 0x3A0000) == [0x3A0000] and with_efs(4 << 20, 0x1A0000) == []
    assert with_efs(1 << 20, 0x20000) == [0x20000] and with_efs(1 << 20, 0x30000) == []
    assert ap.efs_offsets(1 << 20) == ap.EFS_OFFSETS_4 and ap.efs_offsets(8 << 20) == ap.EFS_OFFSETS_8 and ap.efs_offsets(16 << 20) == ap.EFS_OFFSETS_16


def test_efs_shift_limit(monkeypatch):
    def shifted(shift):
        img = bytearray(b"\xff" * (SIZE + shift))
        inner = good_image()
        put(img, shift, inner[:SIZE])
        return [e["window_base"] for e in run(img)["efs"]]
    assert shifted(ap.MAX_SHIFT) == [ap.MAX_SHIFT] and shifted(ap.MAX_SHIFT + 0x1000) == []
    monkeypatch.setattr(ap, "MAX_SHIFT", 0x1000)
    assert shifted(0x1000) == [0x1000] and shifted(0x2000) == []
    assert shifted(0x1800) == []                           # 不是 4 KiB 的整數倍


def test_psp_bak_directory_pointer_and_directory_header_versions():
    img = bytearray(b"\xff" * SIZE)
    boot = psp_blob(1, (1, 2, 3, 4), 0x300)
    put(img, 0x31000, boot)
    put(img, 0x30000, directory(b"$PSP", [psp_ent(1, size=len(boot), addr=phys(0x31000))]))
    efs(img, extra={0x2C: phys(0x30000)})                            # 只有 psp_bak_directory（+0x2C）
    r = run(img)
    assert [d["reached_via"][0] for d in r["directories"]] == ["EFS@0x20000 psp_bak_directory"] and r["psp_firmware"]
    # 目錄標頭版本 1：address_mode 在位元 24–25；版本 0：在位元 29–30（互不混用）
    for info, mode in ((2 << 29, 2), ((1 << 31) | (2 << 24), 2), ((1 << 31) | (2 << 29), 0), ((1 << 31) | (1 << 24), 1), ((3 << 29), 3), (1 << 24, 0)):
        assert ap.dir_mode(info) == mode, hex(info)
    # 相對目錄（mode 2）的項目用項目自己的 mode 2：位置 = 目錄位置 + 值
    for info in (2 << 29, (1 << 31) | (2 << 24)):
        img = bytearray(b"\xff" * SIZE)
        put(img, 0x31000, boot)
        put(img, 0x30000, directory(b"$PSP", [psp_ent(1, size=len(boot), addr=0x1000, mode=2)], info=info))
        efs(img, new_psp=0x30000)
        assert [p["version"] for p in run(img)["psp_firmware"]] == ["04.03.02.01"], hex(info)
    # v1 標頭但 address_mode 位元（24–25）是 0：項目的 mode 2 被忽略，值 0x1000 當成視窗內偏移 → 讀到 0x1000 而不是 0x31000
    img = bytearray(b"\xff" * SIZE)
    put(img, 0x31000, boot)
    put(img, 0x30000, directory(b"$PSP", [psp_ent(1, size=len(boot), addr=0x1000, mode=2)], info=(1 << 31) | (2 << 29)))
    efs(img, new_psp=0x30000)
    assert run(img)["psp_firmware"] == []


def test_instance_and_flag_bit_positions():
    img = good_image()
    boot = psp_blob(1, (1, 2, 3, 4), 0x300)
    put(img, 0x31000, boot)
    put(img, 0x30000, directory(b"$PSP", [psp_ent(1, size=len(boot), addr=phys(0x31000), flags=(5 << 3) | (1 << 2) | 2)]))
    put(img, 0x40000, directory(b"$BHD", [bhd_ent(0x60, 0x104, phys(0x43000), f1=(7 << 4) | 0b0111, f2=5 | (2 << 3) | (1 << 5))]))
    r = run(img)
    p = dirs_by_kind(r)["psp"]["entries"][0]
    assert (p["instance"], p["writable"], p["rom_id"]) == (5, True, 2)
    b = dirs_by_kind(r)["bios"]["entries"][0]
    assert (b["instance"], b["reset"], b["copy"], b["read_only"], b["compressed"], b["subprogram"], b["rom_id"], b["writable"]) == (7, True, True, True, False, 5, 2, True)
    put(img, 0x40000, directory(b"$BHD", [bhd_ent(0x60, 0x104, phys(0x43000), f1=0b1000, f2=0), bhd_ent(0x60, 0x104, phys(0x43000), f2=0x20),
                                          bhd_ent(0x60, 0x104, phys(0x43000), f2=0x10)]))
    e = dirs_by_kind(run(img))["bios"]["entries"]
    assert (e[0]["instance"], e[0]["reset"], e[0]["compressed"], e[0]["writable"], e[0]["subprogram"]) == (0, False, True, False, 0)
    assert (e[1]["writable"], e[1]["rom_id"]) == (True, 0) and (e[2]["writable"], e[2]["rom_id"]) == (False, 2)
    put(img, 0x30000, directory(b"$PSP", [psp_ent(1, size=len(boot), addr=phys(0x31000), flags=1 << 2), psp_ent(1, size=len(boot), addr=phys(0x31000), flags=2),
                                          psp_ent(1, size=len(boot), addr=phys(0x31000), flags=1 << 7)]))
    e = dirs_by_kind(run(img))["psp"]["entries"]
    assert [(x["writable"], x["rom_id"], x["instance"]) for x in e] == [(True, 0, 0), (False, 2, 0), (False, 0, 0)]


def test_microcode_container_size_checks_and_date_range(monkeypatch):
    def run_ucode(blob):
        img = good_image()
        put(img, 0x41000, b"\xff" * 0x2000)
        put(img, 0x41000, blob)
        put(img, 0x40000, directory(b"$BHD", [bhd_ent(0x66, len(blob), phys(0x41000))]))
        return run(img)
    ok = container([(0x00870F10, 0x8082)], [patch()])
    eq24 = b"DMA\x00" + struct.pack("<II", 0, 24) + struct.pack("<IIIHH", 0x00870F10, 0, 0, 0x8082, 0) + b"\x00" * 8 + struct.pack("<II", 1, len(patch())) + patch()
    assert run_ucode(eq24)["microcode"] == []                                         # 等價表大小不是 16 的倍數
    assert [m["cpuids"] for m in run_ucode(ok)["microcode"]] == [["00870F10"]]
    bad_type = b"DMA\x00" + struct.pack("<II", 1, 32) + ok[12:]
    assert run_ucode(bad_type)["microcode"] == []
    bad_mod = b"DMA\x00" + struct.pack("<II", 0, 17) + ok[12:]
    assert run_ucode(bad_mod)["microcode"] == []
    huge = b"DMA\x00" + struct.pack("<II", 0, len(ok)) + ok[12:]                    # 等價表比項目還大
    assert run_ucode(huge)["microcode"] == []
    monkeypatch.setattr(ap, "MAX_EQUIV", 1)
    assert run_ucode(ok)["microcode"] == []                                           # 等價表有 2 個項目（含結尾的 0）：超過上限
    monkeypatch.setattr(ap, "MAX_EQUIV", 256)
    monkeypatch.setattr(ap, "MAX_PATCHES", 1)
    two = container([(1, 0x8082)], [patch(), patch(0x04162019, 0x08008210, 0x8082)])
    assert len(run_ucode(two)["microcode"]) == 1
    monkeypatch.undo()
    for date, good in ((0x01012000, True), (0x12312099, True), (0x01011999, False), (0x01012100, False), (0x00012019, False), (0x13012019, False), (0x01002019, False),
                       (0x01322019, False), (0x0101201A, False)):
        assert (ap.bcd_date(date) is not None) == good, hex(date)
        assert bool(run_ucode(patch(date=date))["microcode"]) == good, hex(date)
    # patch 的 patch_id／equivalence id 為 0 或全 1 不算
    for kw in ({"pid": 0}, {"pid": 0xFFFFFFFF}, {"equiv": 0}, {"equiv": 0xFFFF}):
        assert run_ucode(patch(**kw))["microcode"] == []


# ---------- 同一位置用不同基底讀、順序無關、APOB 條件 ----------

def norm(r):
    """結果的摘要（與處理順序無關的部分）。"""
    return (sorted((d["kind"], d["offset"], d["base"], d["ambiguous"], d["rejected"], d["checksum_ok"]) for d in r["directories"]),
            sorted((p["type"], p["version"]) for p in r["psp_firmware"]),
            sorted((p["type"], p["version"]) for p in r["ambiguous"]["psp_firmware"]),
            sorted(m["patch_id"] for m in r["microcode"]), sorted(codes(r)))


def same_offset_two_bases_image():
    """EFS 在 0x21000（視窗開頭 0x1000）。psp_directory=0x50000：視窗讀法 0x51000、檔案讀法 0x50000，兩邊都有目錄（歧義）；
    new_psp=0x4F000：只有視窗讀法（0x50000）有目錄 → 不歧義的邊，但 0x50000 也被用基底 0 讀過。條目位址（模式 1，相對視窗）依基底讀到不同的位置。"""
    img = bytearray(b"\xff" * (SIZE + 0x1000))
    put(img, 0x60000, psp_blob(1, (1, 1, 1, 1), 0x300))
    put(img, 0x61000, psp_blob(1, (2, 2, 2, 2), 0x300))
    put(img, 0x50000, directory(b"$PSP", [psp_ent(1, size=0x300, addr=0x60000, mode=1)], info=1 << 29))
    put(img, 0x51000, directory(b"$PSP", []))
    efs(img, at=0x21000, psp=0x50000, new_psp=0x4F000)
    return img


def test_same_offset_reached_with_different_bases_is_ambiguous_and_never_in_the_sbom():
    r = run(same_offset_two_bases_image())
    k = {(d["offset"], d["base"]): d for d in r["directories"]}
    assert sorted(k) == [(0x50000, 0), (0x50000, 0x1000), (0x51000, 0x1000)] and all(d["ambiguous"] for d in k.values())
    assert k[(0x50000, 0)]["other_bases"] == ["0x1000"] and k[(0x50000, 0x1000)]["other_bases"] == ["0x0"]
    assert r["psp_firmware"] == []                                                     # 同一個位置兩種基底都被讀到：不能把其中一種的版本放進 SBOM
    assert sorted(p["version"] for p in r["ambiguous"]["psp_firmware"]) == ["01.01.01.01", "02.02.02.02"]
    assert any("other window bases" in p["text"] for p in r["problems"] if p["code"] == "dir-ambiguous")
    md = "\n".join(ap.markdown_lines(r, str))
    assert "視窗開頭 0x0" in md and "視窗開頭 0x1000" in md


def test_results_do_not_depend_on_the_order_of_pointers_or_efs(monkeypatch):
    # 兩個 EFS：基底 0 的在 0x20000，基底 0x1000 的在 0x21000（結構互不重疊）
    two = two_readings_image()
    efs(two, new_psp=0x30000, at=EFS)
    third = bytearray(b"\xff" * (SIZE + 0x1000))
    put(third, 0x50000, psp_blob(1, (1, 1, 1, 1), 0x300))
    put(third, 0x30000, directory(b"$PSP", [psp_ent(1, size=0x300, addr=0x50000, mode=1)], info=1 << 29))
    put(third, 0x31000, directory(b"$PSP", [psp_ent(1, size=0x300, addr=0x50000, mode=1)], info=1 << 29))
    efs(third, new_psp=0x30000)
    efs(third, new_psp=0x30000, at=0x21000)
    images = [same_offset_two_bases_image(), two_readings_image(), two, third, bytearray(good_image())]
    before = [norm(run(i)) for i in images]
    monkeypatch.setattr(ap, "EFS_POINTERS", tuple(reversed(ap.EFS_POINTERS)))
    real = ap.find_efs
    monkeypatch.setattr(ap, "find_efs", lambda ctx: list(reversed(real(ctx))))
    after = [norm(run(i)) for i in images]
    assert before == after
    assert any(b[0] and any(d[3] for d in b[0]) for b in before) and any(b[0] and not any(d[3] for d in b[0]) for b in before)


def test_combo_entry_that_reads_both_ways_makes_its_children_ambiguous_under_a_definite_parent():
    img = bytearray(b"\xff" * (SIZE + 0x1000))
    a, b = psp_blob(1, (1, 1, 1, 1), 0x300), psp_blob(1, (2, 2, 2, 2), 0x300)
    put(img, 0x50000, a)
    put(img, 0x51000, b)
    put(img, 0x30000, directory(b"$PSP", [psp_ent(1, size=0x300, addr=0x50000, mode=1)], info=1 << 29))      # 檔案讀法
    put(img, 0x31000, directory(b"$PSP", [psp_ent(1, size=0x300, addr=0x50000, mode=1)], info=1 << 29))      # 視窗讀法
    put(img, 0x71000, combo(b"2PSP", [(0xBC0A0000, 0x30000)]))                                              # 視窗讀法 0x71000；檔案讀法 0x70000 沒有目錄
    efs(img, new_psp=0x70000, at=0x21000)
    r = run(img)
    k = {d["offset"]: d for d in r["directories"]}
    assert sorted(k) == [0x30000, 0x31000, 0x71000] and k[0x71000]["ambiguous"] is False
    assert k[0x30000]["ambiguous"] and k[0x31000]["ambiguous"]                  # 父目錄確定，但這條 combo 項目的指標有兩種讀法
    assert r["psp_firmware"] == [] and sorted(p["version"] for p in r["ambiguous"]["psp_firmware"]) == ["01.01.01.01", "02.02.02.02"]
    assert sorted(k[0x71000]["entries"][0]["children"]) == [0x30000, 0x31000]


def test_ambiguous_contents_are_listed_even_when_a_definite_directory_has_the_same_blob():
    """確定的目錄（單一讀法的 EFS 指標）和歧義的那一組讀法裡有同一份 blob：歧義那邊照實列出，不和確定的去重。
    歧義那一組要「都通過但內容不同」才會維持歧義（內容相同的讀法會都被採用），所以 0x31000 的讀法多一個條目。"""
    img = bytearray(b"\xff" * (SIZE + 0x1000))
    put(img, 0x50000, psp_blob(1, (1, 1, 1, 1), 0x300))
    put(img, 0x52000, psp_blob(8, (3, 3, 3, 3), 0x300))
    put(img, 0x30000, directory(b"$PSP", [psp_ent(1, size=0x300, addr=0x50000, mode=1)], info=1 << 29))
    put(img, 0x31000, directory(b"$PSP", [psp_ent(1, size=0x300, addr=0x4F000, mode=1), psp_ent(8, size=0x300, addr=0x51000, mode=1)], info=1 << 29))
    efs(img, new_psp=0x30000)
    efs(img, new_psp=0x30000, at=0x21000)
    r = run(img)
    k = {d["offset"]: d for d in r["directories"]}
    assert k[0x30000]["ambiguous"] is False and k[0x31000]["ambiguous"] is True
    assert [p["version"] for p in r["psp_firmware"]] == ["01.01.01.01"]
    assert [p["version"] for p in r["ambiguous"]["psp_firmware"]] == ["01.01.01.01", "03.03.03.03"]
    assert [x["directory"] for x in r["psp_firmware"][0]["locations"]] == ["PSP directory L1 @0x30000"]
    assert [x["directory"] for x in r["ambiguous"]["psp_firmware"][0]["locations"]] == ["PSP directory L1 @0x31000"]


def test_slot_header_and_directory_addresses_use_only_the_directorys_own_base():
    img = bytearray(b"\xff" * (SIZE + 0x1000))
    put(img, 0x55000, directory(b"$PL2", []))          # 視窗讀法的 pl2_location 0x54000 → 0x55000
    put(img, 0x54000, directory(b"$PL2", []))          # 檔案讀法 → 0x54000
    put(img, 0x53000, ish_bytes(0x54000))
    put(img, 0x51000, directory(b"$PSP", [psp_ent(0x48, size=0, addr=0x52000, mode=1)], info=1 << 29))     # 視窗：0x1000 + 0x52000 = 0x53000
    efs(img, new_psp=0x50000, at=0x21000)
    r = run(img)
    assert sorted(d["offset"] for d in r["directories"]) == [0x51000, 0x55000] and "pointer-ambiguous" not in codes(r)
    assert all(not d["ambiguous"] for d in r["directories"])


def test_agesa_only_in_decompressed_content_can_be_complete_but_any_raw_copy_is_not():
    import lzma
    M = b"AGESA!V9\x00ComboAM4v2PI 9.9.9.9\x00" + b"\x00" * 8

    def build(files):
        img = bytearray(b"\xff" * SIZE)
        put(img, 0x80000, fv(files))
        return run(img)["agesa"]
    pe = ffs(0x07, secs(sec(0x10, M)), k=0)
    ui = ffs(0x07, secs(sec(0x15, M)), k=1)
    comp = ffs(0x07, secs(guided(LZMA, lzma.compress(secs(sec(0x10, M)), format=lzma.FORMAT_ALONE))), k=2)
    ag = build([comp])                                # 標記只在解壓縮內容裡、原始位元組裡沒有 → 其他條件都滿足時可以完整
    assert ag["complete"] is True and [x["value"] for x in ag["values"]] == ["ComboAM4v2PI 9.9.9.9"] and not any("no formal interface" in p for p in ag["problems"])
    for files in ([pe], [pe, comp], [ui, comp], [comp, ui], [pe, ui, comp]):
        ag = build(files)
        assert ag["complete"] is False and any("no formal interface" in p for p in ag["problems"]), len(files)
        assert len(ag["values"]) == 1 and all(f["where"].startswith("uefi:") for f in ag["values"][0]["found"])     # 走訪結果裡已經有這個值：原始位元組那份只標不完整，不加進位置、不重複計數
    assert build([ui, comp])["values"][0]["count"] == 1 and build([pe, comp])["values"][0]["count"] == 2


def test_apob_exemption_needs_type_0x61_size_0_and_a_nonzero_destination():
    def kinds(*ents):
        img = good_image()
        put(img, 0x40000, directory(b"$BHD", list(ents)))
        return [e["kind"] for e in dirs_by_kind(run(img))["bios"]["entries"]]
    assert kinds(bhd_ent(0x61, 0, 0, dest=0xA200000)) == ["dest-only"]
    assert kinds(bhd_ent(0x61, 0, 0, dest=0), bhd_ent(0x61, 0, 0)) == ["empty", "empty"]
    assert kinds(bhd_ent(0x63, 0, 0, dest=0xA200000), bhd_ent(0x60, 0, 0, dest=0xA200000), bhd_ent(0x66, 0, 0, dest=0xA200000)) == ["empty"] * 3
    assert kinds(bhd_ent(0x61, 0x104, phys(0x43000), dest=0xA200000)) == ["blob"]                                  # 有資料的 APOB 照一般條目處理


def test_agesa_tag_is_at_most_four_characters():
    ok = run(agesa_image(b"AGESA!V1234\x00abc"))["agesa"]
    assert [(x["tag"], x["value"]) for x in ok["values"]] == [("AGESA!V1234", "abc")]
    bad = run(agesa_image(b"AGESA!V12345\x00abc"))["agesa"]
    assert bad["values"] == [] and any("no NUL or space after the tag" in p for p in bad["problems"])


def test_efs_is_found_at_every_offset_of_its_window_class():
    def with_efs(size, at):
        img = bytearray(b"\xff" * size)
        put(img, at, b"\xaa\x55\xaa\x55" + b"\x00" * 0x3C)
        return [e["offset"] for e in run(img)["efs"]]
    for size, offsets in ((4 << 20, ap.EFS_OFFSETS_4), (8 << 20, ap.EFS_OFFSETS_8), (16 << 20, ap.EFS_OFFSETS_16)):
        for o in offsets:
            assert with_efs(size, o) == [o], (size, hex(o))
    assert ap.EFS_OFFSETS_4 == (0x3A0000, 0x320000, 0x220000, 0x020000) and ap.EFS_OFFSETS_8 == (0x7A0000, 0x720000, 0x620000, 0x420000, 0x020000)
    assert ap.EFS_OFFSETS_16 == (0xFA0000, 0xF20000, 0xE20000, 0xC20000, 0x820000, 0x020000)


def test_directory_tables_that_partly_overlap_are_reported():
    img = good_image()
    put(img, 0x30000, directory(b"$PSP", [psp_ent(1, size=0x300, addr=phys(0x31000))] * 4))       # 表 0x30000–0x30050
    put(img, 0x30040, directory(b"$PL2", []))
    put(img, 0x40000, directory(b"$BHD", []))
    efs(img, new_psp=0x30000, bios0=phys(0x40000), extra={0x2C: phys(0x30040)})
    r = run(img)
    assert any(p["code"] == "entry-overlap" and p["where"] == "directory tables" for p in r["problems"])


def test_parse_ucode_direct_range_and_container_checks():
    data = bytes(b"\x00" * 0x100)
    ctx = ap.Ctx(data, None)
    assert ap.parse_ucode(ctx, {"offset": 0xF0, "size": 0x100}) == ([], "the entry extends past the end of the file")
    assert ap.parse_ucode(ctx, {"offset": -4, "size": 0x10})[1] == "the entry extends past the end of the file"
    cont = b"DMA\x00" + struct.pack("<II", 0, 32) + b"\x00" * 64                       # 等價表 32 bytes，但項目只有 40 bytes
    ctx = ap.Ctx(cont, None)
    assert "equivalence table is not valid" in ap.parse_ucode(ctx, {"offset": 0, "size": 40})[1]


def test_every_efs_directory_pointer_field_is_read():
    boot = psp_blob(1, (1, 2, 3, 4), 0x300)
    for off in (0x10, 0x14, 0x2C):                       # PSP 目錄指標：psp_directory、new_psp_directory、psp_bak_directory
        img = bytearray(b"\xff" * SIZE)
        put(img, 0x31000, boot)
        put(img, 0x30000, directory(b"$PSP", [psp_ent(1, size=len(boot), addr=phys(0x31000))]))
        efs(img, extra={off: phys(0x30000)})
        assert [p["version"] for p in run(img)["psp_firmware"]] == ["04.03.02.01"], hex(off)
    for off in (0x18, 0x1C, 0x20, 0x28):                 # BIOS 目錄指標：bios0–bios3
        img = bytearray(b"\xff" * SIZE)
        put(img, 0x41000, patch())
        put(img, 0x40000, directory(b"$BHD", [bhd_ent(0x66, 0xC80, phys(0x41000))]))
        efs(img, extra={off: phys(0x40000)})
        assert [m["patch_id"] for m in run(img)["microcode"]] == ["0x0800820d"], hex(off)


def test_agesa_decompressed_raw_fallback_content_does_not_cover_an_unsearched_copy():
    import lzma
    payload = b"AGESA!V9\x00ComboAM4v2PI 9.9.9.9\x00" + b"\x00" * 300                   # 不是 section 串（開頭三個 byte 當 size 太大）：解壓縮後整塊當原始內容送進搜尋
    comp = ffs(0x07, secs(guided(LZMA, lzma.compress(payload, format=lzma.FORMAT_ALONE))), k=2)
    ui = ffs(0x07, secs(sec(0x15, payload)), k=1)                                       # 同樣的位元組在 UI section 裡：沒有被搜尋
    img = bytearray(b"\xff" * SIZE)
    put(img, 0x80000, fv([ui, comp]))
    ag = run(img)["agesa"]
    assert ag["complete"] is False and any("no formal interface" in p for p in ag["problems"])


# ---------- 競爭的讀法依自己的結構檢查採用或不採用；AGESA 涵蓋不讀 uefi_image 的內部變數 ----------

def readings_image(a_ents, b_ents, bad_a=False, bad_b=False, blobs=True, extra=None):
    """EFS 在 0x21000（視窗開頭 0x1000），new_psp 指標 0x30000：檔案偏移讀法（基底 0）是 0x30000 的目錄 A，視窗讀法（基底 0x1000）是 0x31000 的目錄 B。
    條目位址用 mode 1（相對視窗開頭）：同一個原值在 A 讀到 +0，在 B 讀到 +0x1000。blob：0x50000 版本 1、0x51000 版本 2。第二種 cookie 讓 x86_firmware 認得這是 AMD 平台。"""
    img = bytearray(b"\xff" * (SIZE + 0x1000))
    if blobs:
        put(img, 0x50000, psp_blob(1, (1, 1, 1, 1), 0x300))
        put(img, 0x51000, psp_blob(1, (2, 2, 2, 2), 0x300))
    put(img, 0x30000, directory(b"$PSP", a_ents, info=1 << 29, bad_checksum=bad_a))
    put(img, 0x31000, directory(b"$PSP", b_ents, info=1 << 29, bad_checksum=bad_b))
    put(img, 0x60000, directory(b"$BHD", [bhd_ent(0x60, 0x104, 0x43000)]))
    for fn in (extra or ()):
        fn(img)
    efs(img, new_psp=0x30000, at=0x21000)
    return img


def one(addr, typ=1):
    return psp_ent(typ, size=0x300, addr=addr, mode=1)


def status_of_dirs(r):
    return {d["offset"]: d["status"] for d in r["directories"]}


def test_reading_with_a_bad_checksum_is_rejected_and_the_other_one_is_used(tmp_path):
    img = readings_image([one(0x50000)], [one(0x50000)], bad_a=True)
    r = run(img)
    assert status_of_dirs(r) == {0x30000: "rejected", 0x31000: "adopted"}
    a = next(d for d in r["directories"] if d["offset"] == 0x30000)
    assert a["rejected"] is True and a["ambiguous"] is False and any("does not match the computed" in x for x in a["rejected_because"])
    assert a["used_instead"] == ["PSP directory L1 @0x31000 (window base 0x1000)"]
    assert [p["version"] for p in r["psp_firmware"]] == ["02.02.02.02"]                       # 視窗讀法（B）讀到 0x51000 的版本 2
    assert r["ambiguous"]["psp_firmware"] == []                                              # 不採用的那一邊只列在目錄清單，不進任何版本清單
    assert "reading-rejected" in codes(r) and "pointer-ambiguous" not in codes(r) and "dir-ambiguous" not in codes(r)
    assert any("checksum" in p["text"] and "is not used" in p["text"] and "0x31000" in p["text"] for p in r["problems"] if p["code"] == "reading-rejected")
    assert any(g.startswith("AMD: directory readings not used") for g in r["gaps"]) and any("directory readings not used" in x for x in r["attention"])    # 報告不是乾淨的
    md = "\n".join(ap.markdown_lines(r, str))
    assert "未採用" in md and "02.02.02.02" in md and "01.01.01.01" not in md
    p = tmp_path / "rej.bin"
    p.write_bytes(bytes(img))
    inv = xf.inventory([p])
    st, _ = xf.status_of(inv)
    comps, _ = xf.components(inv)
    assert st == "ATTENTION"
    assert [c["version"] for c in comps if c["name"].startswith("AMD PSP firmware")] == ["02.02.02.02"]


def test_reading_with_an_entry_outside_the_image_is_rejected():
    far = psp_ent(1, size=0x300, addr=0x7FFFFFF0, mode=1)
    r = run(readings_image([far], [one(0x50000)]))
    assert status_of_dirs(r) == {0x30000: "rejected", 0x31000: "adopted"}
    a = next(d for d in r["directories"] if d["offset"] == 0x30000)
    assert a["checksum_ok"] is True and any("extends past the end of the file" in x for x in a["rejected_because"])
    assert [p["version"] for p in r["psp_firmware"]] == ["02.02.02.02"] and "reading-rejected" in codes(r)
    # 反過來：視窗那一邊超出、檔案偏移那一邊在範圍內
    r = run(readings_image([one(0x50000)], [far]))
    assert status_of_dirs(r) == {0x30000: "adopted", 0x31000: "rejected"}
    assert [p["version"] for p in r["psp_firmware"]] == ["01.01.01.01"]


def test_both_readings_pass_with_different_contents_stays_a_gap():
    r = run(readings_image([one(0x50000)], [one(0x50000)]))
    assert status_of_dirs(r) == {0x30000: "ambiguous", 0x31000: "ambiguous"}
    assert r["psp_firmware"] == [] and sorted(p["version"] for p in r["ambiguous"]["psp_firmware"]) == ["01.01.01.01", "02.02.02.02"]
    assert "pointer-ambiguous" in codes(r) and "reading-rejected" not in codes(r)
    assert any("their contents differ" in p["text"] for p in r["problems"] if p["code"] == "pointer-ambiguous")


def test_both_readings_fail_stays_a_gap():
    r = run(readings_image([one(0x50000)], [one(0x50000)], bad_a=True, bad_b=True))
    assert status_of_dirs(r) == {0x30000: "ambiguous", 0x31000: "ambiguous"}
    assert r["psp_firmware"] == [] and "pointer-ambiguous" in codes(r) and "reading-rejected" not in codes(r)
    assert any("none of the readings passes" in p["text"] for p in r["problems"] if p["code"] == "pointer-ambiguous")
    # 一邊壞 checksum、另一邊條目超出範圍：兩邊都沒通過，不選邊
    r = run(readings_image([psp_ent(1, size=0x300, addr=0x7FFFFFF0, mode=1)], [one(0x50000)], bad_b=True))
    assert status_of_dirs(r) == {0x30000: "ambiguous", 0x31000: "ambiguous"} and r["psp_firmware"] == []


def test_both_readings_pass_with_identical_contents_are_both_used():
    # B（基底 0x1000）的 0x4F000 讀到 0x50000：和 A 的條目指到同一份 blob，兩邊的解讀結果完全相同
    r = run(readings_image([one(0x50000)], [one(0x4F000)]))
    assert status_of_dirs(r) == {0x30000: "adopted", 0x31000: "adopted"}
    assert [p["version"] for p in r["psp_firmware"]] == ["01.01.01.01"] and len(r["psp_firmware"][0]["locations"]) == 2
    assert "reading-equivalent" in codes(r) and "pointer-ambiguous" not in codes(r) and "reading-rejected" not in codes(r)
    # 指到的是內容相同但位置不同的兩份 blob：雜湊相同 → 也算相同；內容不同 → 不算
    img = readings_image([one(0x50000)], [one(0x50000)], extra=[lambda i: put(i, 0x51000, psp_blob(1, (1, 1, 1, 1), 0x300))])
    assert status_of_dirs(run(img)) == {0x30000: "adopted", 0x31000: "adopted"}
    img = readings_image([one(0x50000)], [one(0x50000)], extra=[lambda i: put(i, 0x51000, psp_blob(1, (1, 1, 1, 1), 0x300, fill=0xBB))])
    assert status_of_dirs(run(img)) == {0x30000: "ambiguous", 0x31000: "ambiguous"}          # 版本欄位相同、內容不同


def l2_subtree_extra(img):
    """A（基底 0）的 0x40 條目 → 0x34000 的 L2（它的條目 → 0x60000 的版本 3）；B（基底 0x1000）的 0x40 → 0x35000 的 L2（條目 → 0x61000 的版本 4）。"""
    put(img, 0x60000, psp_blob(8, (3, 3, 3, 3), 0x300))
    put(img, 0x61000, psp_blob(8, (4, 4, 4, 4), 0x300))
    put(img, 0x34000, directory(b"$PL2", [psp_ent(8, size=0x300, addr=0x60000, mode=1)], info=1 << 29))
    put(img, 0x35000, directory(b"$PL2", [psp_ent(8, size=0x300, addr=0x60000, mode=1)], info=1 << 29))


def test_subdirectory_of_a_rejected_reading_is_not_used_and_the_adopted_ones_is():
    ents_a, ents_b = [one(0x50000), psp_ent(0x40, size=0x400, addr=0x34000, mode=1)], [one(0x50000), psp_ent(0x40, size=0x400, addr=0x34000, mode=1)]
    img = readings_image(ents_a, ents_b, bad_a=True, extra=[l2_subtree_extra, lambda i: put(i, 0x62000, b"")])
    r = run(img)
    k = {(d["offset"], d["base"]): d for d in r["directories"]}
    assert k[(0x30000, 0)]["status"] == "rejected" and k[(0x31000, 0x1000)]["status"] == "adopted"
    assert k[(0x34000, 0)]["status"] == "rejected" and k[(0x35000, 0x1000)]["status"] == "adopted"        # 子目錄沿用各自讀法的基底
    assert k[(0x34000, 0)]["rejected_because"] == ["reached only through readings that are not used"]
    versions = sorted(p["version"] for p in r["psp_firmware"])
    assert versions == ["02.02.02.02", "04.04.04.04"]                                                   # 版本 3（被拒絕讀法的子目錄）不在任何清單
    assert "03.03.03.03" not in str(r["ambiguous"]) and "03.03.03.03" not in str(r["psp_firmware"])
    assert sum(1 for p in r["problems"] if p["code"] == "reading-rejected") == 2


def test_subdirectory_of_contested_readings_is_ambiguous_not_rejected():
    ents = [one(0x50000), psp_ent(0x40, size=0x400, addr=0x34000, mode=1)]
    r = run(readings_image(ents, ents, extra=[l2_subtree_extra]))
    k = {(d["offset"], d["base"]): d["status"] for d in r["directories"]}
    assert k == {(0x30000, 0): "ambiguous", (0x31000, 0x1000): "ambiguous", (0x34000, 0): "ambiguous", (0x35000, 0x1000): "ambiguous"}
    assert r["psp_firmware"] == []


def test_same_offset_with_two_bases_adopts_the_one_that_passes():
    """兩個 EFS（基底 0 與 0x1000）各自指到 0x30000（基底 0 的 0x30000、基底 0x1000 的 0x2F000）：同一個位置兩種基底。同一個原值在視窗基底 0x1000 的讀法超出檔案。"""
    def build():
        img = bytearray(b"\xff" * (SIZE + 0x1000))
        put(img, 0xFFE00, psp_blob(1, (5, 5, 5, 5), 0x300))
        put(img, 0x30000, directory(b"$PSP", [psp_ent(1, size=0x300, addr=0xFFE00, mode=1)], info=1 << 29))
        put(img, 0x60000, directory(b"$BHD", [bhd_ent(0x60, 0x104, 0x43000)]))
        efs(img, new_psp=0x30000)
        efs(img, new_psp=0x2F000, at=0x21000)
        return img
    r = run(build())
    k = {(d["offset"], d["base"]): d for d in r["directories"]}
    assert sorted(k) == [(0x30000, 0), (0x30000, 0x1000)]
    assert k[(0x30000, 0)]["status"] == "adopted" and k[(0x30000, 0x1000)]["status"] == "rejected"
    assert k[(0x30000, 0x1000)]["other_bases"] == ["0x0"] and any("extends past the end of the file" in x for x in k[(0x30000, 0x1000)]["rejected_because"])
    assert [p["version"] for p in r["psp_firmware"]] == ["05.05.05.05"] and "reading-rejected" in codes(r) and "dir-ambiguous" not in codes(r)


def test_slot_header_checksum_and_combo_children_are_part_of_the_checks():
    # A/B 復原：基底 0 的讀法把 slot header 位址讀錯 → checksum 不符 → 不採用；基底 0x1000 的讀法 checksum 相符
    img = bytearray(b"\xff" * (SIZE + 0x1000))
    put(img, 0x54000, directory(b"$PL2", []))
    put(img, 0x53000, ish_bytes(0x53000))          # pl2_location 0x53000 + 基底 0x1000 → 0x54000
    put(img, 0x52000, b"\x11" * 0x20)                  # 基底 0 的讀法讀到這裡：不是 slot header（checksum 不符）
    put(img, 0x30000, directory(b"$PSP", [psp_ent(0x48, size=0, addr=0x52000, mode=1)], info=1 << 29))        # 基底 0：0x52000（空白）→ checksum 不符
    put(img, 0x31000, directory(b"$PSP", [psp_ent(0x48, size=0, addr=0x52000, mode=1)], info=1 << 29))        # 基底 0x1000：0x53000 → slot header
    put(img, 0x60000, directory(b"$BHD", [bhd_ent(0x60, 0x104, 0x43000)]))
    efs(img, new_psp=0x30000, at=0x21000)
    r = run(img)
    st = status_of_dirs(r)
    assert st[0x30000] == "rejected" and st[0x31000] == "adopted"
    assert any("slot header checksum" in x for d in r["directories"] if d["offset"] == 0x30000 for x in d["rejected_because"])
    # combo：基底 0 的讀法裡有項目沒指到目錄 → 不採用
    img = bytearray(b"\xff" * (SIZE + 0x1000))
    put(img, 0x40000, directory(b"$PSP", []))
    put(img, 0x70000, combo(b"2PSP", [(0xBC0A0000, 0x40000 - 0x1000)]))                # 基底 0x1000：0x40000；基底 0：0x3F000（沒有目錄）
    put(img, 0x71000, combo(b"2PSP", [(0xBC0A0000, 0x40000 - 0x1000)]))
    put(img, 0x60000, directory(b"$BHD", [bhd_ent(0x60, 0x104, 0x43000)]))
    efs(img, new_psp=0x70000, at=0x21000)
    r = run(img)
    k = {(d["kind"], d["offset"], d["base"]): d["status"] for d in r["directories"]}
    assert k[("combo-psp", 0x70000, 0)] == "rejected" and k[("combo-psp", 0x71000, 0x1000)] == "adopted"
    assert k[("psp", 0x40000, 0x1000)] == "adopted"


def test_directory_table_inside_its_own_entry_fails_the_check():
    # 條目 1 的範圍包住目錄表本身：這種讀法不成立（條目是韌體內容，不會包著自己的目錄表）
    img = readings_image([psp_ent(1, size=0x20000, addr=0x2F000, mode=1)], [one(0x50000)])
    r = run(img)
    a = next(d for d in r["directories"] if d["offset"] == 0x30000)
    assert a["status"] == "rejected" and any("lies inside the range" in x for x in a["rejected_because"])


def test_readings_outcome_does_not_depend_on_pointer_or_efs_order(monkeypatch):
    """EFS 與指標的處理順序顛倒。限制：程式在走訪與整理結果時自己用 sorted 排序，所以這個測試只證明「顛倒輸入順序」不影響結果；內部列舉順序被打亂的情況由
    test_resolution_does_not_depend_on_the_order_of_records_edges_and_groups（resolve 階段）與 test_walk_processes_a_level_in_sorted_order_whatever_the_insertion_order（走訪階段）檢查。"""
    sub = [one(0x50000), psp_ent(0x40, size=0x400, addr=0x34000, mode=1)]
    images = [readings_image([one(0x50000)], [one(0x50000)], bad_a=True), readings_image([psp_ent(1, size=0x300, addr=0x7FFFFFF0, mode=1)], [one(0x50000)]),
              readings_image([one(0x50000)], [one(0x50000)]), readings_image([one(0x50000)], [one(0x50000)], bad_a=True, bad_b=True),
              readings_image([one(0x50000)], [one(0x4F000)]), readings_image(sub, sub, bad_a=True, extra=[l2_subtree_extra]), readings_image(sub, sub, extra=[l2_subtree_extra]),
              same_offset_two_bases_image(), two_readings_image()]
    before = [norm(run(i)) for i in images]
    monkeypatch.setattr(ap, "EFS_POINTERS", tuple(reversed(ap.EFS_POINTERS)))
    real = ap.find_efs
    monkeypatch.setattr(ap, "find_efs", lambda ctx: list(reversed(real(ctx))))
    assert [norm(run(i)) for i in images] == before
    kinds = {d[3:5] for b in before for d in b[0]}
    assert (False, True) in kinds and (True, False) in kinds and (False, False) in kinds          # 三種結果都出現過（不是比較兩份空的）


# ---------- AGESA：不讀 uefi_image 呼叫端的內部變數；涵蓋只靠公開介面能證明的 ----------

def test_agesa_search_does_not_read_the_callers_frames_or_internals():
    import re
    src = Path(ap.__file__).read_text(encoding="utf-8")
    assert not re.search(r"_getframe|f_locals|f_back|\bimport inspect\b|\binspect\.|co_name|\.layers\b|\"layers\"", src)
    assert not hasattr(ap, "raw_origin") and not hasattr(ap, "AGESA_DERIVED_MAX") and not hasattr(ap, "MAX_AGESA_LEAVES")


def test_agesa_raw_only_value_is_listed_alongside_the_walked_one():
    """走訪搜尋到的值和只在原始位元組裡的值（例如 UI section 裡的另一個版本）都要列出；後者的位置是 image (raw bytes)，搜尋不完整。"""
    walked = ffs(0x07, secs(sec(0x10, b"AGESA!V9\x00ComboAM4v2PI 1.1.1.1\x00" + b"\x00" * 8)), k=0)
    hidden = ffs(0x07, secs(sec(0x15, b"AGESA!V9\x00ComboAM4v2PI 2.2.2.2\x00" + b"\x00" * 8)), k=1)
    img = bytearray(b"\xff" * SIZE)
    put(img, 0x80000, fv([walked, hidden]))
    r = run(img)
    ag = r["agesa"]
    vals = {x["value"]: [f["where"] for f in x["found"]] for x in ag["values"]}
    assert set(vals) == {"ComboAM4v2PI 1.1.1.1", "ComboAM4v2PI 2.2.2.2"} and vals["ComboAM4v2PI 2.2.2.2"] == ["image (raw bytes)"]
    assert vals["ComboAM4v2PI 1.1.1.1"][0].startswith("uefi:") and ag["complete"] is False
    assert any("more than one AGESA string" in a for a in r["attention"])


# ---------- 上限、工具限制、超時不是證據；走訪不依賴處理順序；各欄位與邊界 ----------

def dirs_image(a_dir, b_dir, extra=(), efs_kw=None):
    """readings_image 的通用版：A（0x30000，基底 0）與 B（0x31000，基底 0x1000）直接給目錄位元組。blob：0x50000 版本 1、0x51000 版本 2。"""
    img = bytearray(b"\xff" * (SIZE + 0x1000))
    put(img, 0x50000, psp_blob(1, (1, 1, 1, 1), 0x300))
    put(img, 0x51000, psp_blob(1, (2, 2, 2, 2), 0x300))
    put(img, 0x30000, a_dir)
    put(img, 0x31000, b_dir)
    put(img, 0x60000, directory(b"$BHD", [bhd_ent(0x60, 0x104, 0x43000)]))
    for fn in extra:
        fn(img)
    efs(img, at=0x21000, **(efs_kw or {"new_psp": 0x30000}))
    return img


def psp_dir(*ents, **kw):
    return directory(b"$PSP", list(ents), info=1 << 29, **kw)


def st3(r):
    return {(d["offset"], d["base"]): d["status"] for d in r["directories"]}


def test_a_limit_is_not_evidence_the_reading_that_was_not_parsed_does_not_let_the_other_one_be_used(monkeypatch):
    img = readings_image([one(0x50000)], [one(0x50000)], bad_a=True)
    assert [p["version"] for p in run(img)["psp_firmware"]] == ["02.02.02.02"]                 # 對照：沒有上限時 A 的 checksum 是證據
    monkeypatch.setattr(ap, "MAX_ENTRIES_TOTAL", 1)                                             # A（先解析，1 項）用掉全部額度；B 根本沒檢查
    r = run(readings_image([one(0x50000)], [one(0x50000)], bad_a=False))
    assert set(st3(r).values()) == {"ambiguous"} and r["psp_firmware"] == [] and "reading-rejected" not in codes(r) and "dir-limit" in codes(r)
    b = next(d for d in r["directories"] if d["base"] == 0x1000)
    assert b["parsed"] is False and b["unparsed"][0] == "limit" and b["reading_unknown"] and b["reading_fail"] == []
    monkeypatch.setattr(ap, "MAX_ENTRIES_TOTAL", 4096)
    monkeypatch.setattr(ap, "MAX_DIRS", 1)                                                      # B 沒被解析（沒有紀錄）
    r = run(readings_image([one(0x50000)], [one(0x50000)]))
    assert r["psp_firmware"] == [] and "reading-rejected" not in codes(r) and "pointer-ambiguous" in codes(r)
    monkeypatch.setattr(ap, "MAX_DIRS", 64)
    monkeypatch.setattr(ap, "MAX_DEPTH", -1)                                                    # 深度上限：什麼都沒解析
    assert run(readings_image([one(0x50000)], [one(0x50000)]))["directories"] == []


def test_too_many_entries_is_a_limit_but_a_table_past_the_end_of_the_file_is_evidence():
    many = directory(b"$PSP", [], info=1 << 29, num=ap.MAX_DIR_ENTRIES + 1)
    r = run(dirs_image(many, psp_dir(one(0x50000))))
    assert set(st3(r).values()) == {"ambiguous"} and r["psp_firmware"] == [] and "reading-rejected" not in codes(r)
    da = next(d for d in r["directories"] if d["base"] == 0)
    assert da["reading_fail"] == [] and da["reading_unknown"] and da["unparsed"][0] == "limit"          # 項目數上限是限制，不是證據
    # 項目數合理、但表超出檔案：結構上的證據 → 這一種不採用
    n = SIZE + 0x1000
    img = dirs_image(psp_dir(one(0x50000)), psp_dir(one(0x50000)))
    put(img, n - 0x30, directory(b"$PSP", [], info=1 << 29, num=10))       # 0x31000 的位置換成放在檔案尾端的表不行：用 EFS 指標指到尾端
    efs(img, at=0x21000, new_psp=n - 0x30 - 0x1000)                        # 視窗讀法 → 檔案尾端那張表（超出檔案）；檔案偏移讀法 → 沒有目錄
    r = run(img)
    d = [x for x in r["directories"] if x["offset"] == n - 0x30]
    assert len(d) == 1 and d[0]["parsed"] is False and d[0]["unparsed"][0] == "evidence" and "dir-truncated" in codes(r)


def test_tool_limits_are_unknown_not_evidence():
    """address mode 3、size 超過 MAX_BLOB、A/B 復原條目的 size 不合：工具不解，不是反證 → 整組維持歧義；位址超出檔案才是證據。"""
    ok = psp_dir(one(0x50000))
    for label, ent, info in (("size over MAX_BLOB", psp_ent(1, size=0x7000000, addr=0x50000, mode=1), 1 << 29), ("mode 3", psp_ent(1, size=0x300, addr=0x50000, mode=3), 2 << 29),
                             ("ish size", psp_ent(0x48, size=0x44, addr=0x50000, mode=1), 1 << 29)):
        a = directory(b"$PSP", [ent], info=info)
        r = run(dirs_image(a, ok))
        assert set(st3(r).values()) == {"ambiguous"} and "reading-rejected" not in codes(r) and r["psp_firmware"] == [], label
        da = next(d for d in r["directories"] if d["base"] == 0)
        assert da["reading_unknown"] and not da["reading_fail"], label
    r = run(dirs_image(psp_dir(psp_ent(1, size=0x300, addr=0x7FFFFFF0, mode=1)), ok))              # 對照：範圍超出檔案是證據
    assert st3(r) == {(0x30000, 0): "rejected", (0x31000, 0x1000): "adopted"}
    # 條目解析出錯（不該發生）也是無法判斷
    r = run(dirs_image(psp_dir(psp_ent(1, size=0x300, addr=0x50000, mode=1)), ok))
    assert set(st3(r).values()) == {"ambiguous"}


def test_a_timeout_in_the_middle_of_the_directory_stage_never_adopts_or_rejects():
    class Over(Exception):
        pass

    class Budget:
        def __init__(self, k):
            self.k, self.c = k, 0

        def check(self):
            self.c += 1
            if self.c > self.k:
                raise Over("time limit")
    bad = psp_ent(1, size=0x300, addr=0x7FFFFFF0, mode=1)
    img = dirs_image(psp_dir(bad, one(0x50000)), psp_dir(one(0x50000)))
    full = ap.analyze(bytes(img))
    assert set(st3(full).values()) == {"rejected", "adopted"}                                      # 沒有超時：A 有證據、B 被採用
    stopped = 0
    for k in range(0, 5):
        r = ap.analyze(bytes(img), Budget(k), (Over,))
        if any("directory parse stopped early" in x for x in r["incomplete"]):         # 目錄階段被打斷
            stopped += 1
            assert "rejected" not in st3(r).values() and "adopted" not in st3(r).values() and r["psp_firmware"] == [], k
    assert stopped >= 2
    # 單一紀錄沒解析完（complete=False）時 reading_state 回「無法判斷」
    rec = {"complete": False, "unparsed": None, "parsed": True, "checksum_ok": True, "entries": [], "kind": "psp", "size": 16, "offset": 0}
    ev, unk = ap.reading_state(rec)
    assert ev == [] and unk and "not fully parsed" in unk[0]


def loop_image():
    """兩個 L1 互相指到對方（L2 指標），加上競爭的讀法：有循環時所有競爭的讀法維持歧義。"""
    img = bytearray(b"\xff" * (SIZE + 0x1000))
    put(img, 0x50000, psp_blob(1, (1, 1, 1, 1), 0x300))
    put(img, 0x51000, psp_blob(1, (2, 2, 2, 2), 0x300))
    put(img, 0x30000, psp_dir(one(0x50000), psp_ent(0x40, size=0x400, addr=0x34000, mode=1)))
    put(img, 0x31000, psp_dir(one(0x4F000), psp_ent(0x40, size=0x400, addr=0x33000, mode=1)))        # 兩邊內容相同（都到 0x50000、子目錄都到 0x34000）
    put(img, 0x34000, directory(b"$PL2", [psp_ent(0x40, size=0x400, addr=0x30000, mode=1), one(0x4F000)], info=1 << 29))
    put(img, 0x60000, directory(b"$BHD", [bhd_ent(0x60, 0x104, 0x43000)]))
    efs(img, at=0x21000, new_psp=0x30000)
    return img


def test_a_loop_makes_every_competing_reading_ambiguous_and_is_order_independent(monkeypatch):
    img = loop_image()
    r = run(img)
    assert "dir-loop" in codes(r)
    comp = [d for d in r["directories"] if d["offset"] in (0x30000, 0x31000)]
    assert comp and all(d["status"] == "ambiguous" for d in comp)
    assert any("a directory loop was found" in p["text"] for p in r["problems"] if p["code"] == "pointer-ambiguous")
    before = norm(r)
    monkeypatch.setattr(ap, "EFS_POINTERS", tuple(reversed(ap.EFS_POINTERS)))
    assert norm(run(img)) == before


def test_each_record_is_parsed_at_its_shallowest_depth_whatever_the_pointer_order(monkeypatch):
    """同一個目錄可以從深度 1 或深度 3 到得了：深度上限（MAX_DEPTH）下一律用最淺的深度，所以不論先走哪條路都會被解析。"""
    img = bytearray(b"\xff" * SIZE)
    put(img, 0x50000, psp_blob(1, (7, 7, 7, 7), 0x300))
    put(img, 0x38000, directory(b"$PL2", [psp_ent(1, size=0x300, addr=phys(0x50000))]))                                  # 目標 T
    put(img, 0x37000, directory(b"$PL2", [psp_ent(0x40, size=0x400, addr=phys(0x38000))]))
    put(img, 0x36000, directory(b"$PL2", [psp_ent(0x40, size=0x400, addr=phys(0x37000))]))
    put(img, 0x35000, directory(b"$PL2", [psp_ent(0x40, size=0x400, addr=phys(0x36000))]))
    long_first = [psp_ent(0x40, size=0x400, addr=phys(0x35000)), psp_ent(0x40, size=0x400, addr=phys(0x38000))]
    monkeypatch.setattr(ap, "MAX_DEPTH", 1)
    results = []
    for ents in (long_first, long_first[::-1]):                                  # 長的路徑（深度 4）在前或在後
        put(img, 0x30000, directory(b"$PSP", ents))
        efs(img, new_psp=0x30000)
        results.append(run(img))
    assert norm(results[0]) == norm(results[1])
    offs = {d["offset"] for d in results[0]["directories"]}
    assert 0x38000 in offs and 0x35000 in offs and 0x36000 not in offs and "dir-limit" in codes(results[0])


def rand_image(seed):
    rnd = random.Random(seed)
    img = bytearray(b"\xff" * (SIZE + 0x1000))
    slots = [0x30000 + 0x1000 * i for i in range(10)]
    for b, v in zip((0x50000, 0x51000, 0x52000), (1, 2, 1)):
        put(img, b, psp_blob(1, (v,) * 4, 0x300))
    for s in slots:
        k = rnd.choice(["psp", "l2", "combo", "none", "psp"])
        if k == "none":
            continue
        if k == "combo":
            put(img, s, combo(rnd.choice([b"2PSP", b"2BHD"]), [(0xBC0A0000 + j, rnd.choice(slots) - rnd.choice([0, 0x1000])) for j in range(rnd.randrange(1, 4))]))
            continue
        ents = []
        for _ in range(rnd.randrange(1, 4)):
            r = rnd.random()
            tgt = max(rnd.choice([0x50000, 0x51000, 0x52000]) - rnd.choice([0, 0x1000]), 0)
            ents.append(psp_ent(1, size=0x300, addr=tgt, mode=1) if r < 0.5 else psp_ent(0x40, size=0x400, addr=max(rnd.choice(slots) - rnd.choice([0, 0x1000]), 0), mode=1) if r < 0.85
                        else psp_ent(1, size=0x300, addr=0x7FFFFFF0, mode=1))
        put(img, s, directory(b"$PSP" if k == "psp" else b"$PL2", ents, info=1 << 29, bad_checksum=rnd.random() < 0.15))
    for at in (0x20000, 0x21000):
        efs(img, at=at, new_psp=rnd.choice(slots) - rnd.choice([0, 0x1000]), extra={0x10: rnd.choice(slots) - rnd.choice([0, 0x1000]), 0x2C: rnd.choice(slots)})
    put(img, 0x60000, directory(b"$BHD", [bhd_ent(0x60, 0x104, 0x43000)]))
    return img


def strict_json(r):
    import json
    return json.dumps(r, sort_keys=True, default=str)


def test_random_images_with_loops_and_limits_give_identical_results_in_any_order(monkeypatch):
    """同上的限制：輸入順序被顛倒，內部排序不被打亂。含循環與各種上限。"""
    seen = {"loop": 0, "limit": 0, "adopted": 0, "rejected": 0}
    for lim in (None, ("MAX_ENTRIES_TOTAL", 9), ("MAX_DIRS", 5), ("MAX_DEPTH", 1)):
        with monkeypatch.context() as m:
            if lim:
                m.setattr(ap, lim[0], lim[1])
            for seed in range(40):
                img = rand_image(seed)
                base = strict_json(run(img))
                r0 = run(img)
                seen["loop"] += "dir-loop" in codes(r0)
                seen["limit"] += "dir-limit" in codes(r0)
                seen["adopted"] += any(d["status"] == "adopted" for d in r0["directories"])
                seen["rejected"] += any(d["status"] == "rejected" for d in r0["directories"])
                with m.context() as m2:
                    m2.setattr(ap, "EFS_POINTERS", tuple(reversed(ap.EFS_POINTERS)))
                    real = ap.find_efs
                    m2.setattr(ap, "find_efs", lambda ctx: list(reversed(real(ctx))))
                    assert strict_json(run(img)) == base, (lim, seed)
    assert all(seen.values()), seen                                  # 迴圈、上限、採用、不採用都真的出現過


def test_outputs_are_sorted_by_stable_keys_including_hash_and_offset():
    img = good_image()
    r = run(img)
    keys = [(p["type"], p["subprogram"], p["version"], p["sha256"] or "", p["size"]) for p in r["psp_firmware"]]
    assert keys == sorted(keys)
    assert [e["directories_found"] for e in r["efs"]] == [len(r["directories"])]          # 單一 EFS：到得了的紀錄數＝全部（不是處理順序算出來的計數）


def test_three_way_competition_needs_all_passers_to_agree():
    def build3(contents, bad=None):
        img = bytearray(b"\xff" * (SIZE + 0x3000))
        for i, v in enumerate(contents):
            put(img, 0x50000 + 0x1000 * i, psp_blob(1, (v,) * 4, 0x300))
        put(img, 0x30000, directory(b"$PSP", [psp_ent(1, size=0x300, addr=0x50000, mode=1)] + ([bad] if bad else []), info=1 << 29))
        put(img, 0x60000, directory(b"$BHD", [bhd_ent(0x60, 0x104, 0x43000)]))
        efs(img, new_psp=0x30000, at=0x20000)
        efs(img, new_psp=0x2F000, at=0x21000)
        efs(img, new_psp=0x2E000, at=0x22000)
        return run(img)
    r = build3([1, 1, 1])
    assert set(st3(r).values()) == {"adopted"} and [p["version"] for p in r["psp_firmware"]] == ["01.01.01.01"]
    for contents in ([1, 1, 2], [1, 2, 1], [2, 1, 1], [1, 2, 3]):                                 # 三個讀法裡只要有兩個不同，三個都不採用
        r = build3(contents)
        assert set(st3(r).values()) == {"ambiguous"} and r["psp_firmware"] == [], contents
    r = build3([1, 1, 1], bad=psp_ent(1, size=0x300, addr=0x7FFFFFF0, mode=1))                  # 三個都超出檔案 → 都沒通過 → 歧義，不是三個都不採用
    assert set(st3(r).values()) == {"ambiguous"} and "reading-rejected" not in codes(r)


def test_a_missing_hash_never_counts_as_the_same_content(monkeypatch):
    ctx = ap.Ctx(bytes(0x1000), None)
    ctx.hash_left = 0
    ent = {"kind": "blob", "index": 0, "type": 1, "size": 0x10, "offset": 0x100}
    assert ap.entry_sig(ctx, ent) is None
    rec = {"kind": "psp", "num_entries": 1, "entries": [ent]}
    assert ap.same_content(ctx, rec, dict(rec)) is False
    # 整張映像：雜湊上限用完 → 兩邊都通過、內容相同的讀法也不能被採用（不判斷）
    monkeypatch.setattr(ap, "MAX_HASH_TOTAL", 0x100)
    r = run(readings_image([one(0x50000)], [one(0x4F000)]))
    assert set(st3(r).values()) == {"ambiguous"} and "hash-limit" in codes(r) and "reading-equivalent" not in codes(r)


def bhd_dirs(a_ents, b_ents, extra=()):
    img = dirs_image(directory(b"$BHD", a_ents, info=1 << 29), directory(b"$BHD", b_ents, info=1 << 29), extra=extra, efs_kw={"bios0": 0x30000})
    return run(img)


def test_every_field_of_the_entry_interpretation_decides_whether_two_readings_are_the_same():
    same = psp_ent(1, size=0x300, addr=0x50000, mode=1)
    same_b = psp_ent(1, size=0x300, addr=0x4F000, mode=1)                                          # 基底 0x1000 → 同一份 blob
    assert set(st3(run(dirs_image(psp_dir(same), psp_dir(same_b)))).values()) == {"adopted"}      # 對照：完全相同
    for label, other in (("type", psp_ent(8, size=0x300, addr=0x4F000, mode=1)), ("subprogram", psp_ent(1, sub=1, size=0x300, addr=0x4F000, mode=1)),
                         ("instance flags", psp_ent(1, size=0x300, addr=0x4F000, mode=1, flags=0x8)), ("size", psp_ent(1, size=0x2F0, addr=0x4F000, mode=1))):
        r = run(dirs_image(psp_dir(same), psp_dir(other)))
        assert set(st3(r).values()) == {"ambiguous"}, label
    # 值型條目（size 0xFFFFFFFF）：位址欄位是值，不同就不同
    v1, v2 = psp_ent(0x0B, size=0xFFFFFFFF, addr=1), psp_ent(0x0B, size=0xFFFFFFFF, addr=2)
    assert set(st3(run(dirs_image(psp_dir(v1), psp_dir(v1)))).values()) == {"adopted"}
    assert set(st3(run(dirs_image(psp_dir(v1), psp_dir(v2)))).values()) == {"ambiguous"}
    # BIOS 目錄：destination、壓縮條目的位置
    d1, d2 = bhd_ent(0x61, 0, 0, dest=0xA200000), bhd_ent(0x61, 0, 0, dest=0xA300000)
    assert set(st3(bhd_dirs([d1], [d1])).values()) == {"adopted"}
    assert set(st3(bhd_dirs([d1], [d2])).values()) == {"ambiguous"}
    c_a, c_same, c_other = bhd_ent(0x62, 0x300, 0x50000, f1=0x08, mode=1), bhd_ent(0x62, 0x300, 0x4F000, f1=0x08, mode=1), bhd_ent(0x62, 0x300, 0x50000, f1=0x08, mode=1)
    assert set(st3(bhd_dirs([c_a], [c_same])).values()) == {"adopted"}                              # 同一個位置
    assert set(st3(bhd_dirs([c_a], [c_other])).values()) == {"ambiguous"}                           # 位置不同（內容雖然可能相同，壓縮內容不解讀）


def test_pointer_children_slot_headers_combo_ids_and_kinds_decide_sameness():
    # 目錄指標條目：子目錄的位置不同 → 不同；相同 → 相同
    def l2(img):
        put(img, 0x34000, directory(b"$PL2", [], info=1 << 29))
        put(img, 0x35000, directory(b"$PL2", [], info=1 << 29))
    p_a = psp_ent(0x40, size=0x400, addr=0x34000, mode=1)
    p_same = psp_ent(0x40, size=0x400, addr=0x33000, mode=1)       # 基底 0x1000 → 0x34000
    p_other = psp_ent(0x40, size=0x400, addr=0x34000, mode=1)       # 基底 0x1000 → 0x35000
    assert st3(run(dirs_image(psp_dir(p_a), psp_dir(p_same), extra=[l2])))[(0x30000, 0)] == "adopted"
    assert st3(run(dirs_image(psp_dir(p_a), psp_dir(p_other), extra=[l2])))[(0x30000, 0)] == "ambiguous"
    # 目錄種類不同（$PSP 與 $PL2）、其餘相同 → 不同
    k_a, k_b = directory(b"$PSP", [one(0x50000)], info=1 << 29), directory(b"$PL2", [one(0x4F000)], info=1 << 29)
    assert set(st3(run(dirs_image(k_a, k_b))).values()) == {"ambiguous"}
    # Image Slot Header：兩個讀法都有效、pl2 到同一個 L2，但 slot header 的內容（欄位值）不同 → 不同
    def ish_extra(img):
        put(img, 0x52000, ish_bytes(0x54000, prio=1))        # 基底 0 → 0x52000
        put(img, 0x53000, ish_bytes(0x53000, prio=2))        # 基底 0x1000 → 0x53000，pl2 0x53000 + 0x1000 → 0x54000
        put(img, 0x54000, directory(b"$PL2", [], info=1 << 29))
    i_ent = psp_ent(0x48, size=0, addr=0x52000, mode=1)
    r = run(dirs_image(psp_dir(i_ent), psp_dir(i_ent), extra=[ish_extra]))
    assert st3(r)[(0x30000, 0)] == "ambiguous" and all(not d["reading_fail"] for d in r["directories"] if d["offset"] in (0x30000, 0x31000))
    # combo：id 不同、子目錄不同 → 不同；都相同 → 相同
    def combo_dirs(a_id, a_addr, b_id, b_addr, also=()):
        def ex(img):
            for o in (0x40000, *also):
                put(img, o, directory(b"$PSP", [], info=1 << 29))
        return run(dirs_image(combo(b"2PSP", [(a_id, a_addr)]), combo(b"2PSP", [(b_id, b_addr)]), extra=[ex]))
    assert st3(combo_dirs(0xBC0A0000, 0x40000, 0xBC0A0000, 0x3F000))[(0x30000, 0)] == "adopted"      # 子目錄都是 0x40000
    assert st3(combo_dirs(0xBC0A0000, 0x40000, 0xBC0B0000, 0x3F000))[(0x30000, 0)] == "ambiguous"    # id 不同
    assert st3(combo_dirs(0xBC0A0000, 0x40000, 0xBC0A0000, 0x3E000, also=(0x3F000,)))[(0x30000, 0)] == "ambiguous"    # 子目錄不同（B 到 0x3F000，A 到 0x40000）


def test_directory_table_adjacent_to_its_own_entry_boundaries():
    """目錄表 [0x30000, 0x30020)（一個項目）。條目結束在表開頭、或起點在表結尾：不重疊；多一個 byte 就是證據。"""
    ok = psp_dir(one(0x50000))
    def probe(start, size):
        r = run(dirs_image(psp_dir(psp_ent(1, size=size, addr=start, mode=1)), ok))
        return st3(r)[(0x30000, 0)]
    assert probe(0x2FD00, 0x300) == "ambiguous"        # 結束在 0x30000：不重疊 → 通過，和 B 內容不同 → 歧義
    assert probe(0x30020, 0x300) == "ambiguous"        # 起點在表結尾：不重疊
    assert probe(0x2FD01, 0x300) == "rejected"          # 多進表 1 byte
    assert probe(0x2FD00, 0x301) == "rejected"          # 結束晚 1 byte（起點在表之前、結束在表裡）
    assert probe(0x3001F, 0x300) == "rejected"          # 起點在表的最後 1 byte 內
    assert probe(0x2FF00, 0x400) == "rejected"          # 整張表在條目裡


def test_slot_header_whose_pl2_does_not_lead_to_a_directory_is_evidence():
    def ex(img):
        put(img, 0x52000, ish_bytes(0x60000))              # 基底 0：有效的 slot header，但 pl2_location 0x60000 沒有目錄 cookie（0x60000 是 $BHD…改用別處）
        put(img, 0x53000, ish_bytes(0x53000))              # 基底 0x1000：pl2 → 0x54000 的 L2
        put(img, 0x54000, directory(b"$PL2", [], info=1 << 29))
        put(img, 0x60000, b"\x11" * 32)
    i_ent = psp_ent(0x48, size=0, addr=0x52000, mode=1)
    r = run(dirs_image(psp_dir(i_ent), psp_dir(i_ent), extra=[ex]))
    a = next(d for d in r["directories"] if d["offset"] == 0x30000)
    assert a["status"] == "rejected" and any("pl2_location" in x for x in a["rejected_because"])


def test_a_child_reached_from_a_rejected_and_an_ambiguous_parent_is_ambiguous():
    """C 同時在被拒絕的 Y1 和歧義的 X1 底下：只有所有進來的邊都是被拒絕的才算 rejected，這裡要是 ambiguous。"""
    img = bytearray(b"\xff" * (SIZE + 0x1000))
    put(img, 0x50000, psp_blob(1, (1, 1, 1, 1), 0x300))
    put(img, 0x51000, psp_blob(1, (2, 2, 2, 2), 0x300))
    put(img, 0x34000, directory(b"$PL2", [], info=1 << 29))
    c_ptr = psp_ent(0x40, size=0x400, addr=0x34000, mode=1)
    put(img, 0x30000, psp_dir(one(0x50000), c_ptr))                                   # X1：基底 0
    put(img, 0x31000, psp_dir(one(0x50000)))                                          # X2：基底 0x1000，內容不同 → X 組歧義
    put(img, 0x38000, psp_dir(c_ptr, psp_ent(1, size=0x300, addr=0x7FFFFFF0, mode=1)))  # Y1：基底 0，條目超出檔案 → 沒通過
    put(img, 0x39000, psp_dir(one(0x50000)))                                          # Y2：基底 0x1000，通過
    put(img, 0x60000, directory(b"$BHD", [bhd_ent(0x60, 0x104, 0x43000)]))
    efs(img, at=0x21000, new_psp=0x30000, psp=0x38000)
    r = run(img)
    s = st3(r)
    assert s[(0x38000, 0)] == "rejected" and s[(0x39000, 0x1000)] == "adopted" and s[(0x30000, 0)] == "ambiguous"
    assert s[(0x34000, 0)] == "ambiguous"
    # 兩個父目錄都被拒絕時才是 rejected
    put(img, 0x30000, psp_dir(one(0x50000), c_ptr, psp_ent(1, size=0x300, addr=0x7FFFFFF0, mode=1)))
    put(img, 0x31000, psp_dir(one(0x50000)))
    s = st3(run(img))
    assert s[(0x30000, 0)] == "rejected" and s[(0x34000, 0)] == "rejected"


def test_a_competing_reading_that_was_never_parsed_blocks_adoption(monkeypatch):
    """一組裡有讀法沒有紀錄（例如超過目錄數上限而沒解析）：另一邊即使通過也不能被採用。上限的全域保險關掉（只看這一道檢查）。"""
    img = readings_image([one(0x50000)], [one(0x50000)], bad_a=True)
    ctx_limit = ap.Ctx.limit
    monkeypatch.setattr(ap, "MAX_DIRS", 1)
    monkeypatch.setattr(ap.Ctx, "limit", lambda self, where, text, code="dir-limit": self.problem(code, where, text))
    r = run(img)
    assert "reading-rejected" not in codes(r) and r["psp_firmware"] == []
    monkeypatch.setattr(ap.Ctx, "limit", ctx_limit)


# ---------- AGESA：標記只在壓縮內容裡（原始位元組沒有）時，每一種「走訪沒走完」都要讓搜尋不完整 ----------

def agesa_lz():
    M = b"AGESA!V9\x00ComboAM4v2PI 9.9.9.9\x00" + b"\x00" * 8
    lz = lzma.compress(secs(sec(0x10, b"MZ" + b"\x00" * 30 + M)), format=lzma.FORMAT_ALONE)
    return lz, ffs(0x07, secs(guided(LZMA, lz)), k=2)


def agesa_with(blob, off=0x80000):
    img = bytearray(b"\xff" * SIZE)
    put(img, off, blob)
    assert b"AGESA!V" not in bytes(img)
    return run(img)["agesa"]


def test_agesa_only_in_compressed_content_each_incomplete_reason_makes_the_search_incomplete(monkeypatch):
    lz, comp = agesa_lz()
    ag = agesa_with(fv([comp]))
    assert ag["complete"] is True and [x["value"] for x in ag["values"]] == ["ComboAM4v2PI 9.9.9.9"]               # 對照
    ag = agesa_with(fv([ffs(0x07, secs(guided(LZMA, lz)) + b"\x00\x00\x00\x01", k=2)]))                            # 結構警告（notes）
    assert ag["complete"] is False and any("structure warnings" in p for p in ag["problems"])
    ui = ap._sibling("uefi_image")
    monkeypatch.setattr(ui, "MAX_FILES", 0)                                                                         # Stop
    ag = agesa_with(fv([comp]))
    assert ag["complete"] is False and any("reached a limit" in p for p in ag["problems"])
    monkeypatch.undo()
    monkeypatch.setattr(ap, "MAX_AGESA_INSPECT", 10)                                                                # 搜尋量上限
    ag = agesa_with(fv([comp]))
    assert ag["complete"] is False and any("bytes of UEFI content" in p for p in ag["problems"])
    monkeypatch.undo()
    monkeypatch.setattr(ap, "MAX_AGESA_MARKERS", 0)                                                                 # 標記數上限
    ag = agesa_with(fv([comp]))
    assert ag["complete"] is False and any("more than 0 AGESA markers" in p for p in ag["problems"])


def test_agesa_nonblank_bytes_outside_any_firmware_volume_make_the_search_incomplete():
    """FV 以外的非空白位元組只被當原始內容搜尋，裡面的 LZMA 串流不會被解開：不能算完整。"""
    lz, comp = agesa_lz()
    img = bytearray(b"\xff" * SIZE)
    put(img, 0x80000, fv([comp]))
    put(img, 0x40000, lz)
    ag = run(img)["agesa"]
    assert ag["complete"] is False and any("not decoded" in p for p in ag["problems"])
    assert agesa_with(fv([comp]))["complete"] is True


def test_an_unknown_reading_never_lets_a_failing_sibling_be_rejected_or_the_unknown_one_be_adopted():
    mode3 = directory(b"$PSP", [psp_ent(1, size=0x300, addr=0x50000, mode=3)], info=2 << 29)           # A：條目是工具不解的 address mode 3（無法判斷）
    r = run(dirs_image(mode3, psp_dir(one(0x50000), bad_checksum=True)))                                 # B：checksum 不符（證據）
    assert set(st3(r).values()) == {"ambiguous"} and "reading-rejected" not in codes(r) and r["psp_firmware"] == []
    r = run(dirs_image(mode3, psp_dir(psp_ent(1, size=0x300, addr=0x7FFFFFF0, mode=1))))                # B：範圍超出檔案（證據）
    assert set(st3(r).values()) == {"ambiguous"} and "reading-rejected" not in codes(r)


def test_the_reading_that_was_never_parsed_is_reported_and_blocks_adoption_without_a_crash(monkeypatch):
    img = readings_image([one(0x50000)], [one(0x50000)], bad_a=True)
    monkeypatch.setattr(ap, "MAX_DIRS", 1)
    monkeypatch.setattr(ap.Ctx, "limit", lambda self, where, text, code="dir-limit": self.problem(code, where, text))      # 全域保險關掉，只看這一道檢查
    r = run(img)
    assert "internal-error" not in codes(r) and "reading-rejected" not in codes(r) and r["psp_firmware"] == []
    assert any("was not parsed" in p["text"] for p in r["problems"] if p["code"] == "pointer-ambiguous")


def test_a_directory_stage_that_stops_after_every_record_was_parsed_still_adopts_nothing(monkeypatch):
    class Over(Exception):
        pass

    def boom(ctx):
        raise Over("time limit")
    monkeypatch.setattr(ap, "finish_walk", boom)
    r = ap.analyze(bytes(readings_image([one(0x50000)], [one(0x50000)], bad_a=True)), None, (Over,))
    assert len(r["directories"]) == 2 and all(d["complete"] for d in r["directories"]) and set(st3(r).values()) == {"ambiguous"}
    assert r["psp_firmware"] == [] and any("directory parse stopped early" in x for x in r["incomplete"])


def test_hash_limit_reached_while_comparing_makes_every_competing_group_ambiguous(monkeypatch):
    """兩組內容相同的讀法：雜湊額度只夠比第一組。哪一組被比到取決於順序 → 全部不判斷（不是第一組採用、第二組歧義）。"""
    img = dirs_image(psp_dir(one(0x50000)), psp_dir(one(0x4F000)), efs_kw={"new_psp": 0x30000, "psp": 0x32000},
                     extra=[lambda i: put(i, 0x52000, psp_blob(1, (3, 3, 3, 3), 0x300)), lambda i: put(i, 0x32000, psp_dir(psp_ent(1, size=0x300, addr=0x52000, mode=1))),
                            lambda i: put(i, 0x33000, psp_dir(psp_ent(1, size=0x300, addr=0x51000, mode=1)))])
    assert set(st3(run(img)).values()) == {"adopted"}                                                        # 額度夠：兩組都相同、都採用
    monkeypatch.setattr(ap, "MAX_HASH_TOTAL", 0x380)
    r = run(img)
    assert set(st3(r).values()) == {"ambiguous"} and "hash-limit" in codes(r)


def test_a_limit_anywhere_makes_unrelated_competing_readings_ambiguous_and_levels_are_processed_in_sorted_order(monkeypatch):
    many = directory(b"$PSP", [], info=1 << 29, num=ap.MAX_DIR_ENTRIES + 1)
    img = readings_image([one(0x50000)], [one(0x50000)], bad_a=True, extra=[lambda i: put(i, 0x38000, many)])
    base = run(img)
    assert st3(base)[(0x31000, 0x1000)] == "adopted"                                                           # 對照：沒有指到那張表時，B 被採用
    efs(img, at=0x21000, new_psp=0x30000, psp=0x38000 - 0x1000)                                                 # 另一個指標指到項目數太多的目錄
    r = run(img)
    assert "dir-too-many-entries" in codes(r) and st3(r)[(0x31000, 0x1000)] == "ambiguous" and "reading-rejected" not in codes(r)
    # 同一層依（位置，基底）排序：目錄數上限只夠一個時，解析的是位置最小的那個
    monkeypatch.setattr(ap, "MAX_DIRS", 1)
    r = run(readings_image([one(0x50000)], [one(0x50000)]))
    assert [(d["offset"], d["base"]) for d in r["directories"]] == [(0x30000, 0)] and "dir-limit" in codes(r)


def test_bios_entry_instance_decides_sameness():
    a, b = bhd_ent(0x62, 0x300, 0x50000, f1=0x00, mode=1), bhd_ent(0x62, 0x300, 0x4F000, f1=0x10, mode=1)         # 其餘相同、instance 不同（f1 的高 4 位）
    assert set(st3(bhd_dirs([a], [b])).values()) == {"ambiguous"}
    assert set(st3(bhd_dirs([a], [bhd_ent(0x62, 0x300, 0x4F000, f1=0x00, mode=1)])).values()) == {"adopted"}


def test_walk_processes_a_level_in_sorted_order_whatever_the_insertion_order(monkeypatch):
    img = dirs_image(psp_dir(one(0x50000)), psp_dir(one(0x50000)), extra=[lambda i: put(i, 0x32000, psp_dir(one(0x50000)))])
    monkeypatch.setattr(ap, "MAX_DIRS", 1)
    for order in ([(0x31000, 0), (0x30000, 0), (0x32000, 0)], [(0x32000, 0), (0x31000, 0), (0x30000, 0)], [(0x30000, 0), (0x32000, 0), (0x31000, 0)]):
        ctx = ap.Ctx(bytes(img), None)
        ctx.pending = {k: 0x100000 for k in order}
        ap.walk(ctx)
        assert [(r["offset"], r["base"]) for r in ctx.dirs] == [(0x30000, 0)] and ctx.uncertain, order


# ---------- 邊界、鏈、循環、AGESA 的 complete 路徑 ----------

N_IMG = SIZE + 0x1000                  # dirs_image／readings_image 的檔案大小


def test_a_loop_of_three_directories_is_found_by_following_edges_transitively():
    img = bytearray(b"\xff" * SIZE)
    put(img, 0x30000, directory(b"$PSP", [psp_ent(0x40, size=0x400, addr=phys(0x34000))]))
    put(img, 0x34000, directory(b"$PL2", [psp_ent(0x40, size=0x400, addr=phys(0x35000))]))
    put(img, 0x35000, directory(b"$PL2", [psp_ent(0x40, size=0x400, addr=phys(0x30000))]))
    efs(img, new_psp=0x30000)
    r = run(img)
    loops = [p for p in r["problems"] if p["code"] == "dir-loop"]
    assert len(loops) == 3 and {p["where"][-7:] for p in loops} == {"0x30000", "0x34000", "0x35000"}
    assert sorted(d["offset"] for d in r["directories"]) == [0x30000, 0x34000, 0x35000]


def test_a_rejected_chain_is_propagated_over_several_rounds():
    """被拒絕的 Rbad 底下：X1 → X2，Rbad 也直接指到 X2。X2（位置比 X1 小，先被檢查）要等 X1 被判不採用之後才能判不採用 → 需要第二輪。"""
    img = bytearray(b"\xff" * N_IMG)
    put(img, 0x50000, psp_blob(1, (1, 1, 1, 1), 0x300))
    put(img, 0x34000, directory(b"$PL2", [], info=1 << 29))                                   # X2
    put(img, 0x35000, directory(b"$PL2", [psp_ent(0x40, size=0x400, addr=0x34000, mode=1)], info=1 << 29))     # X1 → X2
    put(img, 0x30000, psp_dir(one(0x50000), psp_ent(0x40, size=0x400, addr=0x35000, mode=1), psp_ent(0x40, size=0x400, addr=0x34000, mode=1),
                              psp_ent(1, size=0x300, addr=0x7FFFFFF0, mode=1)))                # Rbad：基底 0，條目超出檔案
    put(img, 0x31000, psp_dir(one(0x50000)))                                                   # Rgood：基底 0x1000
    put(img, 0x60000, directory(b"$BHD", [bhd_ent(0x60, 0x104, 0x43000)]))
    efs(img, at=0x21000, new_psp=0x30000)
    s = st3(run(img))
    assert s[(0x30000, 0)] == "rejected" and s[(0x31000, 0x1000)] == "adopted"
    assert s[(0x35000, 0)] == "rejected" and s[(0x34000, 0)] == "rejected"


def test_range_boundaries_at_the_end_of_the_file_are_not_evidence():
    ok = psp_dir(one(0x50000))
    n = N_IMG
    for size, expect in ((0x300, "ambiguous"), (0x301, "rejected")):                           # 條目結尾剛好等於檔尾：通過；多 1 byte：證據
        r = run(dirs_image(psp_dir(psp_ent(1, size=size, addr=n - 0x300, mode=1)), ok))
        assert st3(r)[(0x30000, 0)] == expect, size
    for start, expect in ((n - 1, "ambiguous"), (n, "rejected")):                               # 壓縮條目的起點：檔尾前一個 byte 通過；等於檔尾是證據
        r = bhd_dirs([bhd_ent(0x62, 0x300, start, f1=0x08)], [bhd_ent(0x62, 0x300, 0x50000, f1=0x08, mode=1)])
        assert st3(r)[(0x30000, 0)] == expect, start


def test_a_directory_table_ending_exactly_at_the_end_of_the_file_is_not_truncated_but_one_byte_more_is_evidence():
    def build(num_b):
        img = bytearray(b"\xff" * N_IMG)
        put(img, 0x50000, psp_blob(1, (1, 1, 1, 1), 0x300))
        put(img, 0xFFFE0, directory(b"$PSP", [one(0x50000)], info=1 << 29))                                     # 檔案偏移讀法（基底 0）
        tail = directory(b"$PSP", [one(0x4F000)] if num_b else [], info=1 << 29, num=num_b)
        put(img, N_IMG - 0x20, tail[:0x20])                                                                     # 視窗讀法（基底 0x1000）：表剛好到檔尾
        put(img, 0x60000, directory(b"$BHD", [bhd_ent(0x60, 0x104, 0x43000)]))
        efs(img, at=0x21000, new_psp=0xFFFE0)
        return run(img)
    r = build(1)                                                                                                # 1 個項目：表 [n-0x20, n)
    b = next(d for d in r["directories"] if d["offset"] == N_IMG - 0x20)
    assert b["parsed"] is True and "dir-truncated" not in codes(r)
    r = build(2)                                                                                                # 2 個項目：超出檔案 → 證據
    b = next(d for d in r["directories"] if d["offset"] == N_IMG - 0x20)
    assert b["parsed"] is False and "dir-truncated" in codes(r)
    s = st3(r)
    assert s[(N_IMG - 0x20, 0x1000)] == "rejected" and s[(0xFFFE0, 0)] == "adopted"                              # 競爭組裡表超出檔案是證據：這邊被拒絕、另一邊被採用


def test_a_directory_whose_header_ends_exactly_at_the_end_of_the_file_is_still_a_directory():
    img = bytearray(b"\xff" * N_IMG)
    put(img, 0xFFFF0, directory(b"$PSP", [], info=1 << 29))                                                      # 檔案偏移讀法：16 bytes 的空目錄
    put(img, N_IMG - 0x10, directory(b"$PSP", [], info=1 << 29))                                                 # 視窗讀法：表在最後 16 bytes（cookie_at 的 off+16 == n）
    put(img, 0x60000, directory(b"$BHD", [bhd_ent(0x60, 0x104, 0x43000)]))
    efs(img, at=0x21000, new_psp=0xFFFF0)
    assert {(d["offset"], d["base"]) for d in run(img)["directories"]} == {(0xFFFF0, 0), (N_IMG - 0x10, 0x1000)}


def test_entry_total_limit_boundary_exactly_equal_is_not_a_limit(monkeypatch):
    img = readings_image([one(0x50000)], [one(0x50000)])
    monkeypatch.setattr(ap, "MAX_ENTRIES_TOTAL", 2)
    r = run(img)
    assert "dir-limit" not in codes(r) and all(d["parsed"] for d in r["directories"])
    monkeypatch.setattr(ap, "MAX_ENTRIES_TOTAL", 1)
    assert "dir-limit" in codes(run(img))


def test_competing_combo_with_empty_pointers_and_equal_contents_is_adopted():
    def ex(img):
        put(img, 0x40000, directory(b"$PSP", [], info=1 << 29))
    a = combo(b"2PSP", [(0xBC0A0000, 0), (0xBC0A0001, 0x40000)])
    b = combo(b"2PSP", [(0xBC0A0000, 0), (0xBC0A0001, 0x3F000)])
    r = run(dirs_image(a, b, extra=[ex]))
    assert st3(r)[(0x30000, 0)] == "adopted" and st3(r)[(0x31000, 0x1000)] == "adopted"
    assert all(not d["reading_fail"] for d in r["directories"] if d["kind"] == "combo-psp") and "reading-equivalent" in codes(r)


def test_entry_address_mode_follows_the_directory_unless_the_directory_is_relative():
    img = good_image()
    # 目錄 mode 1：條目自己的 mode 3 不看，照視窗開頭解
    put(img, 0x30000, directory(b"$PSP", [psp_ent(1, size=0x300, addr=0x31000, mode=3)], info=1 << 29))
    r = run(img)
    e = next(d for d in r["directories"] if d["offset"] == 0x30000)["entries"][0]
    assert e["kind"] == "blob" and e["offset"] == 0x31000
    # 目錄 mode 0：條目的 mode 2 也不看
    put(img, 0x30000, directory(b"$PSP", [psp_ent(1, size=0x300, addr=phys(0x31000), mode=2)], info=0))
    e = next(d for d in run(img)["directories"] if d["offset"] == 0x30000)["entries"][0]
    assert e["kind"] == "blob" and e["offset"] == 0x31000
    # 目錄 mode 2（相對目錄）：用條目自己的 mode；mode 3（相對 slot）不解（限制，不是證據）；目錄 mode 3 同
    put(img, 0x30000, directory(b"$PSP", [psp_ent(1, size=0x300, addr=0x1000, mode=2)], info=2 << 29))
    e = next(d for d in run(img)["directories"] if d["offset"] == 0x30000)["entries"][0]
    assert e["kind"] == "blob" and e["offset"] == 0x31000
    put(img, 0x30000, directory(b"$PSP", [psp_ent(1, size=0x300, addr=0x31000, mode=3)], info=3 << 29))
    e = next(d for d in run(img)["directories"] if d["offset"] == 0x30000)["entries"][0]
    assert e["kind"] == "unresolved" and e["limit"] is True


def test_known_entry_types_are_not_reported_as_unknown():
    r = run(good_image())
    unknown = [p for p in r["problems"] if p["code"] == "type-unknown"]
    assert unknown and all("0x77" in p["text"] for p in unknown)                                  # good_image 只有 0x77 不在清單
    assert all(e["type_name"] for d in r["directories"] for e in d["entries"] if e.get("type") in (0x01, 0x08, 0x12, 0x40, 0x0B, 0x66, 0x60, 0x61))


def test_only_one_passing_reading_never_adds_a_reading_equivalent_note():
    r = run(readings_image([one(0x50000)], [one(0x50000)], bad_a=True))
    assert "reading-equivalent" not in codes(r) and "reading-rejected" in codes(r)
    # 同一位置不同基底、恰好一種通過
    img = bytearray(b"\xff" * N_IMG)
    put(img, 0xFFE00, psp_blob(1, (5, 5, 5, 5), 0x300))
    put(img, 0x30000, directory(b"$PSP", [psp_ent(1, size=0x300, addr=0xFFE00, mode=1)], info=1 << 29))
    put(img, 0x60000, directory(b"$BHD", [bhd_ent(0x60, 0x104, 0x43000)]))
    efs(img, new_psp=0x30000)
    efs(img, new_psp=0x2F000, at=0x21000)
    r = run(img)
    assert st3(r)[(0x30000, 0x1000)] == "rejected" and "reading-equivalent" not in codes(r)


def test_resolution_does_not_depend_on_the_order_of_records_edges_and_groups(monkeypatch):
    """resolve_readings 的輸入（紀錄、邊、組）列舉順序被真的打亂：結果（整份 JSON，包含訊息與 used_instead）要相同。
    限制：走訪階段（walk／finish_walk）自己用 sorted 排序，這裡沒有辦法在不改程式的情況下打亂它的內部列舉；那一段只由「EFS 與指標順序顛倒」的測試與 walk 的單元測試間接檢查。"""
    real = ap.resolve_readings
    rng = random.Random(7)

    def shuffled(ctx):
        rng.shuffle(ctx.edges)
        rng.shuffle(ctx.groups)
        items = list(ctx.by_key.items())
        rng.shuffle(items)
        ctx.by_key = dict(items)
        rng.shuffle(ctx.dirs)
        real(ctx)
    images = [rand_image(s) for s in range(40)] + [loop_image(), readings_image([one(0x50000)], [one(0x50000)], bad_a=True)]
    base = [strict_json(run(i)) for i in images]
    monkeypatch.setattr(ap, "resolve_readings", shuffled)
    for _ in range(3):
        assert [strict_json(run(i)) for i in images] == base


# ---------- AGESA 的 complete=False 路徑與值上限 ----------

def test_agesa_values_cap_makes_the_search_incomplete_even_when_the_markers_are_only_in_compressed_content():
    ms = b"".join(b"AGESA!V9\x00ComboPI 1.0.0.%d\x00" % i for i in range(ap.MAX_AGESA_VALUES + 4))
    lz = lzma.compress(secs(sec(0x10, b"MZ" + b"\x00" * 30 + ms)), format=lzma.FORMAT_ALONE)
    ag = agesa_with(fv([ffs(0x07, secs(guided(LZMA, lz)), k=2)]))
    assert len(ag["values"]) == ap.MAX_AGESA_VALUES and ag["complete"] is False and any("distinct AGESA strings" in p for p in ag["problems"])


def test_agesa_incomplete_when_the_walk_is_interrupted_fails_or_finds_no_firmware_volume(monkeypatch):
    lz, comp = agesa_lz()
    img = bytearray(b"\xff" * SIZE)
    put(img, 0x80000, fv([comp]))

    class Over(Exception):
        pass

    class Budget:
        def __init__(self):
            self.c = 0

        def check(self):
            self.c += 1
            if self.c > 1:
                raise Over("time limit")
    ag = ap.analyze(bytes(img), Budget(), (Over,))["agesa"]                                          # 走訪途中超時（soft）
    assert ag["complete"] is False and any("stopped early" in p for p in ag["problems"])
    ui = ap._sibling("uefi_image")

    real_parse = ui.parse_fvs

    def boom(data, sc, depth, where="image"):
        real_parse(data, sc, depth, where)                                                          # 整個走完、找到值之後才丟例外：只剩這個例外讓搜尋不完整
        raise RuntimeError("boom")
    monkeypatch.setattr(ui, "parse_fvs", boom)                                                      # parse_fvs 丟一般例外
    ag = run(img)["agesa"]
    assert ag["complete"] is False and any("UEFI walk failed" in p for p in ag["problems"])
    monkeypatch.undo()
    ag = run(bytearray(b"\xff" * SIZE))["agesa"]                                                     # 沒有 FV，原始位元組也沒有標記
    assert ag["complete"] is False and any("no UEFI firmware volume" in p for p in ag["problems"]) and ag["values"] == []


# ---------- 自己的校驗沒通過的目錄：不算確定，也不替子目錄背書 ----------

def bad_l1_image():
    """good_image：L1 $PSP（0x30000）的 checksum 壞一個位元；它的 0x40 指標指到 L2（0x34000，自己的 checksum 正確，條目是 SMU2 版本 03.02.01.00）。"""
    img = good_image()
    img[0x30004] ^= 1
    return img


def test_a_directory_with_a_bad_checksum_is_not_definite_and_does_not_vouch_for_its_subdirectory(tmp_path):
    img = bad_l1_image()
    r = run(img)
    s = {d["offset"]: d for d in r["directories"]}
    assert s[0x30000]["status"] == "untrusted" and s[0x30000]["trusted"] is False and s[0x30000]["ambiguous"] is False and s[0x30000]["untrusted"] is True
    assert s[0x34000]["status"] == "untrusted-path" and s[0x34000]["checksum_ok"] is True
    assert "found only through a directory that failed validation" in s[0x34000]["untrusted_because"] and "PSP directory L1 @0x30000" in s[0x34000]["untrusted_because"]
    assert s[0x40000]["status"] == "adopted"                                                     # 另一條路（BIOS 目錄）不受影響
    assert r["psp_firmware"] == [] and r["ambiguous"]["psp_firmware"] == []                       # L1 的條目沒採用、L2 的版本也沒進任何清單
    assert "dir-untrusted-path" in codes(r) and "dir-checksum" in codes(r)
    assert any("failed" in a for a in r["attention"]) and any(g.startswith("AMD: directories found only through") for g in r["gaps"])
    assert [m["patch_id"] for m in r["microcode"]]                                               # BIOS 目錄的微碼照常確定
    md = "\n".join(ap.markdown_lines(r, str))
    assert "經由未通過校驗的上層目錄找到" in md and "checksum 不符，條目不採用" in md and "解讀依據" in md and "沒有簽章驗證" in md
    p = tmp_path / "ut.bin"
    p.write_bytes(bytes(img))
    inv = xf.inventory([p])
    comps, _ = xf.components(inv)
    assert not [c for c in comps if c["name"].startswith("AMD PSP firmware")]
    good = xf.components(xf.inventory([_write(tmp_path / "g.bin", good_image())]))[0]
    basis = [q["value"] for c in good if c["name"].startswith("AMD PSP firmware") for q in c["properties"] if q["name"] == "sca-center:version-basis"]
    assert basis and all("no signature verification" in b and "assume the image was not tampered with" in b for b in basis)


def _write(path, img):
    path.write_bytes(bytes(img))
    return path


def test_the_same_subdirectory_reached_by_a_trusted_path_too_is_definite():
    img = bad_l1_image()
    put(img, 0x36000, directory(b"$PSP", [psp_ent(0x40, size=0x400, addr=phys(0x34000))]))          # 另一個（checksum 正確的）L1 也指到同一個 L2
    efs(img, new_psp=0x30000, psp=0x36000)
    r = run(img)
    s = {d["offset"]: d["status"] for d in r["directories"]}
    assert s[0x30000] == "untrusted" and s[0x36000] == "adopted" and s[0x34000] == "adopted"
    assert [p["version"] for p in r["psp_firmware"]] == ["00.01.02.03"] and "dir-untrusted-path" not in codes(r)


def test_untrusted_status_propagates_over_several_levels_and_below_a_bad_combo():
    img = bytearray(b"\xff" * SIZE)
    put(img, 0x50000, psp_blob(8, (9, 9, 9, 9), 0x300))
    put(img, 0x36000, directory(b"$PL2", [psp_ent(8, size=0x300, addr=phys(0x50000))]))                                    # L3：自己的 checksum 正確
    put(img, 0x35000, directory(b"$PL2", [psp_ent(0x40, size=0x400, addr=phys(0x36000))]))                                # L2 → L3
    put(img, 0x34000, directory(b"$PSP", [psp_ent(0x40, size=0x400, addr=phys(0x35000))]))                                # L1 → L2
    c = bytearray(combo(b"2PSP", [(0xBC0A0000, phys(0x34000))]))
    c[4] ^= 1                                                                                                             # combo 的 checksum 壞
    put(img, 0x30000, bytes(c))
    efs(img, new_psp=0x30000)
    r = run(img)
    s = {d["offset"]: d for d in r["directories"]}
    assert s[0x30000]["status"] == "untrusted" and [s[o]["status"] for o in (0x34000, 0x35000, 0x36000)] == ["untrusted-path"] * 3
    assert all("2PSP" not in s[o]["untrusted_because"] and "PSP combo directory @0x30000" in s[o]["untrusted_because"] for o in (0x34000, 0x35000, 0x36000))
    assert r["psp_firmware"] == [] and sum(1 for p in r["problems"] if p["code"] == "dir-untrusted-path") == 3
    # 對照：combo 的 checksum 正確 → 全部確定
    c = combo(b"2PSP", [(0xBC0A0000, phys(0x34000))])
    put(img, 0x30000, c)
    r = run(img)
    assert {d["status"] for d in r["directories"]} == {"adopted"} and [p["version"] for p in r["psp_firmware"]] == ["09.09.09.09"]


def test_a_directory_that_was_not_fully_parsed_is_untrusted_too(monkeypatch):
    monkeypatch.setattr(ap, "MAX_DIR_ENTRIES", 0)                                                       # 任何有項目的目錄都超過上限：條目沒解析（限制）
    r = run(good_image())
    s = {d["offset"]: d for d in r["directories"]}
    assert s[0x30000]["status"] == "untrusted" and s[0x30000]["parsed"] is False and "not fully parsed" in s[0x30000]["untrusted_because"]
    assert r["psp_firmware"] == []


def untrusted_images():
    two = bad_l1_image()
    put(two, 0x36000, directory(b"$PSP", [psp_ent(0x40, size=0x400, addr=phys(0x34000))]))
    efs(two, new_psp=0x30000, psp=0x36000)
    return [bad_l1_image(), two, readings_image([one(0x50000)], [one(0x50000)], bad_a=True), loop_image()]


def test_untrusted_states_do_not_depend_on_the_processing_order(monkeypatch):
    images = untrusted_images() + [rand_image(s) for s in range(30)]
    base = [strict_json(run(i)) for i in images]
    monkeypatch.setattr(ap, "EFS_POINTERS", tuple(reversed(ap.EFS_POINTERS)))
    real_find = ap.find_efs
    monkeypatch.setattr(ap, "find_efs", lambda ctx: list(reversed(real_find(ctx))))
    real = ap.resolve_readings
    rng = random.Random(11)

    def shuffled(ctx):
        rng.shuffle(ctx.edges)
        rng.shuffle(ctx.groups)
        items = list(ctx.by_key.items())
        rng.shuffle(items)
        ctx.by_key = dict(items)
        real(ctx)
    monkeypatch.setattr(ap, "resolve_readings", shuffled)
    assert [strict_json(run(i)) for i in images] == base
    kinds = {d["status"] for b in images for d in run(b)["directories"]}
    assert {"untrusted", "untrusted-path", "adopted", "rejected"} <= kinds
