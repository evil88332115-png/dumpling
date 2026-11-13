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
    s1 = s2 = 0
    for i in range(0, len(b), 2):
        s1 = (s1 + b[i] + (b[i + 1] << 8)) % 65535
        s2 = (s2 + s1) % 65535
    return (s2 << 16) | s1


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


def efs(img, new_psp=0, bios0=0, psp=0, extra=None):
    put(img, EFS, b"\xaa\x55\xaa\x55" + b"\x00" * 0x3C)
    for o, v in ((0x10, psp), (0x14, new_psp), (0x18, bios0), (0x1C, 0), (0x20, 0), (0x28, 0), (0x2C, 0)):
        struct.pack_into("<I", img, EFS + o, v)
    for o, v in (extra or {}).items():
        struct.pack_into("<I", img, EFS + o, v)


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
    assert k["bios"]["entries"][3]["kind"] == "empty"          # 只有 dest 的 APOB
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
    put(img, 0x30000, directory(b"$PSP", [psp_ent(1, size=0x300, addr=phys(0x31000))] * (ap.MAX_DIR_ENTRIES + 1)))
    assert "dir-too-many-entries" in codes(run(img))
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
    """size 0 的 RECOVERYAB（0x48／0x4A）項目指到 Image Slot Header，裡面的 pl2_location 是 L2 目錄；不能當成「沒有資料」。"""
    img = bytearray(b"\xff" * SIZE)
    smu = psp_blob(8, (0, 0x54, 0x4F, 0), 0x200)
    put(img, 0x52000, smu)
    put(img, 0x51000, directory(b"$PL2", [psp_ent(8, size=len(smu), addr=0x52000, mode=1)], info=1 << 29))
    ish = struct.pack("<IIIIIIII", 0x12345678, 0xFFFFFFFF, 0xF, 0xFFFFFF00, 0x51000, 0xBC0D0300, 0xFFFFFFFF, 0xFFFFFFFF)
    put(img, 0x50120, ish)
    put(img, 0x50140, ish[:16] + struct.pack("<IIII", 0xDEAD0000, 0, 0, 0))            # pl2_location 不是目錄
    put(img, 0x50000, directory(b"$PSP", [psp_ent(0x48, size=0, addr=0x50120), psp_ent(0x4A, size=0, addr=0x50140), psp_ent(0x48, size=0, addr=SIZE - 8)], info=1 << 29))
    efs(img, new_psp=0x50000)
    r = run(img)
    k = dirs_by_kind(r)
    assert set(k) == {"psp", "psp-l2"} and k["psp-l2"]["reached_via"][0].startswith("PSP directory L1 @0x50000 entry 0")
    ents = k["psp"]["entries"]
    assert [e["kind"] for e in ents] == ["ish", "ish", "unresolved"] and ents[0]["child"] == 0x51000 and ents[0]["ish"]["checksum_verified"] is False
    assert [p["version"] for p in r["psp_firmware"]] == ["00.4f.54.00"]
    assert {"ish-unverified", "pointer-unresolved", "entry-address"} <= codes(r)


def test_bios_compressed_entry_has_no_trusted_extent():
    img = good_image()
    put(img, 0x40000, directory(b"$BHD", [bhd_ent(0x62, 0x400020, phys(0x80000), f1=0x0B)]))        # 壓縮：size 不是儲存範圍
    r = run(img)
    assert "entry-range" not in codes(r) and "entry-overlap" not in codes(r)
    assert "size_note" in dirs_by_kind(r)["bios"]["entries"][0]


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
