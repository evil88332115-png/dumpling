"""K1：樹外模組沒有 srcversion 時，用 ELF 區段比對驗證紀錄資料夾裡的 .ko 是同一份建置（kernel_oot_record.compare_ko_sections）。
全部用合成的小 ELF（測試裡組位元組）；不放任何真實的模組或路徑。"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(__file__))
import test_kernel_config as tkc  # noqa: E402
import test_kernel_k1_improve as tki  # noqa: E402

kc = tkc.kc
mod = kc.kernel_oot_record()
SHT_PROGBITS, SHT_NOBITS, SHT_RELA = 1, 8, 4


def elf(sections, machine=183, big=False, class32=False, xnum=False, overlap=0):
    """sections：[(名稱, 型別, 內容[, link, info])]（link／info 是這份清單的索引，第 0 個是空區段所以從 1 起算）。回傳 ELF64 little-endian 的
    ET_REL（aarch64）位元組；.shstrtab 自動加在最後。xnum：區段數放在區段 0 的 sh_size（e_shnum=0）。overlap：再加這麼多個指向同一段資料的 PROGBITS 區段。"""
    sections = list(sections) + [(f".ov{i}", SHT_PROGBITS, None) for i in range(overlap)]
    names = b"\0"
    offs = []
    for sec in sections:
        offs.append(len(names))
        names += sec[0].encode() + b"\0"
    st_name = len(names)
    names += b".shstrtab\0"
    body, cur, hdrs = b"", 64, []
    first = None
    for sec, no in zip(sections, offs):
        n, ty, data = sec[:3]
        link, info = (sec[3], sec[4]) if len(sec) > 3 else (0, 0)
        if data is None:                                   # 重疊：指向第一個區段的資料
            hdrs.append((no, ty, first[0], first[1], 0, 0))
            continue
        hdrs.append((no, ty, cur, len(data), link, info))
        if first is None:
            first = (cur, len(data))
        body += data
        cur += len(data)
    hdrs.append((st_name, 3, cur, len(names), 0, 0))
    body += names
    cur += len(names)
    nsec = len(hdrs) + 1
    h = bytearray(64)
    h[:4] = b"\x7fELF"
    h[4], h[5], h[6] = (1 if class32 else 2), (2 if big else 1), 1
    struct.pack_into("<HH", h, 0x10, 1, machine)
    struct.pack_into("<Q", h, 0x28, cur)
    if xnum:
        struct.pack_into("<HHH", h, 0x3A, 64, 0, 0xFFFF)
    else:
        struct.pack_into("<HHH", h, 0x3A, 64, nsec, nsec - 1)
    z = bytearray(64)
    if xnum:
        struct.pack_into("<Q", z, 0x20, nsec)
        struct.pack_into("<I", z, 0x28, nsec - 1)
    out = bytes(h) + body + bytes(z)
    for x in hdrs:
        b = bytearray(64)
        struct.pack_into("<II", b, 0, x[0], x[1])
        struct.pack_into("<QQ", b, 0x18, x[2], x[3])
        struct.pack_into("<II", b, 0x28, x[4], x[5])
        out += bytes(b)
    return out


def symtab(syms):
    """syms：[(名稱, info, shndx)] → (.symtab 位元組, .strtab 位元組)；第 0 個空符號自動加。"""
    st, tab = b"\0", bytes(24)
    for name, info, shndx in syms:
        no = len(st)
        st += name.encode() + b"\0"
        tab += struct.pack("<IBBHQQ", no, info, 0, shndx, 0, 0)
    return tab, st


def rela(entries):
    return b"".join(struct.pack("<QQq", off, (sym << 32) | ty, add) for off, ty, sym, add in entries)


def with_relocs(addend=0, strs=b"hello\0world\0", other_sym="callee"):
    """.text（1）、.rodata.str1.1（2）、.symtab（3）、.strtab（4）、.rela.text（5）：一個重定位指向字串區段的區段符號，一個指向 other_sym。"""
    tab, st = symtab([("", 3, 2), (other_sym, 0x10, 0)])
    return [(".text", SHT_PROGBITS, b"\x01\x02\x03\x04"), (".rodata.str1.1", SHT_PROGBITS, strs),
            (".symtab", 2, tab, 4, 1), (".strtab", 3, st), (".rela.text", SHT_RELA, rela([(0, 275, 1, addend), (8, 283, 2, 0)]), 3, 1)]


def base(text=b"\x01\x02\x03\x04", strs=b"hello\0world\0", extra=()):
    return [(".text", SHT_PROGBITS, text), (".rodata.str1.1", SHT_PROGBITS, strs), (".bss", SHT_NOBITS, b""),
            (".rela.text", SHT_RELA, b"r" * 8), (".modinfo", SHT_PROGBITS, b"license=GPL\0"),
            (".comment", SHT_PROGBITS, b"GCC 1\0"), (".debug_info", SHT_PROGBITS, b"dbg"), (".note.x", 7, b"n"),
            ("__versions", SHT_PROGBITS, b"v"), (".BTF", SHT_PROGBITS, b"btf"), *extra]


def cmp(a, b):
    return mod.compare_ko_sections(mod.ko_sections(a), mod.ko_sections(b))


def test_identical_code_and_data_ignoring_debug_notes_modinfo():
    a = elf(base())
    b = elf(base()[:2] + [(".modinfo", SHT_PROGBITS, b"license=GPL\0srcversion=X\0"), (".comment", SHT_PROGBITS, b"GCC 2\0"),
                          (".debug_info", SHT_PROGBITS, b"other"), (".BTF", SHT_PROGBITS, b"other"), ("__versions", SHT_PROGBITS, b"w")])
    lvl, why = cmp(a, b)
    assert lvl == "sections" and "identical" in why


def test_code_difference_is_not_verified():
    lvl, why = cmp(elf(base()), elf(base(text=b"\x01\x02\x03\x05")))
    assert lvl is None and ".text" in why


def test_extra_or_missing_data_section_is_not_verified():
    lvl, _ = cmp(elf(base()), elf(base(extra=[(".data", SHT_PROGBITS, b"d")])))
    assert lvl is None


def test_build_date_time_and_path_prefix_strings_are_masked():
    a = elf(base(strs=b"built Nov 11 2026 12:34:56\0/home/a/src/drv/foo/bar.c\0keep\0"))
    b = elf(base(strs=b"built Dec  3 2027 01:02:03\0/other/root/x/src/drv/foo/bar.c\0keep\0"))
    lvl, why = cmp(a, b)
    assert lvl == "sections_masked", why
    assert "build date/time" in why and "build path" in why and ".rodata.str1.1" in why


def test_build_banner_section_with_user_host_and_date_is_masked():
    ban = lambda who, when: [(".rodata.NV_ID", SHT_PROGBITS, f"drv  Release Build  ({who})  {when}\0".encode())]
    lvl, why = cmp(elf(base(extra=ban("root@host-a", "Wed Oct 28 11:18:21 AM CST 2026"))),
                   elf(base(extra=ban("bob@host-b", "Fri Nov  6 20:51:19 CST 2027"))))
    assert lvl == "sections_masked" and "builder user@host" in why, why
    lvl, _ = cmp(elf(base(extra=ban("root@a", "Wed Oct 28 11:18:21 AM CST 2026"))),
                 elf(base(extra=[(".rodata.NV_ID", SHT_PROGBITS, b"other  Release Build  (root@a)  Wed Oct 28 11:18:21 AM CST 2026\0")])))
    assert lvl is None
    # 二進位內容的 .rodata 區段不當字串區段
    lvl, _ = cmp(elf(base(extra=[(".rodata.tbl", SHT_PROGBITS, b"\x01\x02\0")])), elf(base(extra=[(".rodata.tbl", SHT_PROGBITS, b"\x01\x03\0")])))
    assert lvl is None


def test_alignment_padding_between_strings_may_differ():
    lvl, _ = cmp(elf(base(strs=b"/a/b/c/d.c\0\0\0\0keep\0")), elf(base(strs=b"/zz/yy/b/c/d.c\0keep\0")))
    assert lvl == "sections_masked"


def test_other_string_difference_is_not_masked():
    for x, y in ((b"/dev/nvhost-a\0", b"/dev/nvhost-b\0"),                      # 不是原始碼檔的路徑
                 (b"/a/src/drv/foo/bar.c\0", b"/b/src/drv/foo/baz.c\0"),         # 路徑的尾端不同
                 (b"version 1.2\0", b"version 1.3\0"),
                 (b"err %d\0", b"err %d\0extra\0")):                              # 字串數量不同
        lvl, why = cmp(elf(base(strs=x)), elf(base(strs=y)))
        assert lvl is None, (x, y, why)


def test_path_masking_needs_same_number_of_paths_and_tail():
    lvl, _ = cmp(elf(base(strs=b"/a/b/c/d/e.c\0")), elf(base(strs=b"/a/b/c/d/e.c and /x/y/z/w.h\0")))
    assert lvl is None
    lvl, _ = cmp(elf(base(strs=b"/p/q/r/s.c\0")), elf(base(strs=b"/zz/q/r/s.c\0")))        # 最後 3 層相同
    assert lvl == "sections_masked"
    lvl, _ = cmp(elf(base(strs=b"/p/q/r/s.c\0")), elf(base(strs=b"/p/Q/r/s.c\0")))
    assert lvl is None


def test_mask_applies_only_to_string_sections():
    a = elf(base(extra=[(".data", SHT_PROGBITS, b"Nov 11 2026")]))
    b = elf(base(extra=[(".data", SHT_PROGBITS, b"Dec 11 2026")]))
    assert cmp(a, b)[0] is None


def test_unsupported_or_broken_elf_is_not_verified():
    ok = elf(base())
    for bad in (b"", b"\x7fELF", elf(base(), big=True), elf(base(), class32=True), ok[:-10], b"MZ" + ok[2:]):
        assert cmp(bad, ok)[0] is None and cmp(ok, bad)[0] is None
    assert cmp(elf(base(), machine=62), ok)[0] is None


# --- kernel_config 整合：映像與紀錄的 .ko 都沒有 srcversion -----------------------------------------------------

def run_with(tmp_path, img_ko, rec_kos):
    root = tmp_path / "oot"
    for name, data in rec_kos.items():
        tki.oot_module(root, name, ko_bytes=data)
    img = [(f"usr/lib/modules/{tkc.KVER}/updates/nv/{n}.ko", d, None) for n, d in img_ko.items()]
    p, st, out = tki.oot_run(tmp_path, [], [root], extra_ko=img)
    return st, out, out["kernel"]["build_record"]["out_of_tree_records"]


def test_sections_identical_adopts_records_and_says_which_method(tmp_path):
    st, out, oo = run_with(tmp_path, {"foo": elf(base())}, {"foo": elf(base())})
    assert oo["used"] is True and oo["identity"] == {"srcversion": 0, "sections": 1, "sections_masked": 0, "name_only": 0}, oo
    assert tki.by_cve(out)["CVE-2024-1003"]["decision"] == "not_affected"
    assert "ELF 區段相同 1" in st[2] and "same build" not in st[2]
    assert "identical ELF code and data sections" in out["kernel"]["build_record"]["limitations"][-1]


def test_masked_level_is_labelled_and_listed(tmp_path):
    a = elf(base(strs=b"Nov 11 2026\0"))
    b = elf(base(strs=b"Dec 12 2027\0"))
    st, out, oo = run_with(tmp_path, {"foo": a}, {"foo": b})
    assert oo["used"] is True and oo["identity"]["sections_masked"] == 1 and oo["identity"]["sections"] == 0, oo
    assert "build date/time" in oo["masked_examples"][0] and "遮罩" in st[2]


def test_unverifiable_module_keeps_all_or_nothing(tmp_path):
    ok = elf(base())
    st, out, oo = run_with(tmp_path, {"foo": ok, "bar": ok}, {"foo": ok, "bar": elf(base(text=b"zzzz"))})
    assert oo["used"] is False and oo["covered"] == 1 and oo["uncovered"] == 1, oo
    assert oo["identity"]["sections"] == 1 and oo["uncovered_modules"] == ["bar.ko"]
    assert "ELF section comparison does not verify" in oo["uncovered_examples"][0]
    assert tki.by_cve(out)["CVE-2024-1003"]["decision"] == "unknown"


def test_srcversion_stays_first_and_a_mismatch_is_not_overridden_by_sections(tmp_path):
    # 兩邊都有 srcversion 而且不同 → 即使區段相同也不採用（srcversion 是第一個方法，不同就是不同份程式）
    img = tkc_ko_with_srcversion("AAAA")
    rec = tkc_ko_with_srcversion("BBBB")
    st, out, oo = run_with(tmp_path, {"foo": img}, {"foo": rec})
    assert oo["used"] is False and "srcversion" in oo["reason"], oo


def tkc_ko_with_srcversion(v):
    return elf(base()[:2] + [(".modinfo", SHT_PROGBITS, f"srcversion={v}\0".encode())])


def test_relocation_difference_is_not_verified():
    a = elf(with_relocs())
    assert cmp(a, a)[0] == "sections"
    assert cmp(a, elf(with_relocs(other_sym="other")))[0] is None            # 重定位指向不同的符號（符號表也不同）
    b = elf(with_relocs() + [])                                              # 相同
    assert cmp(a, b)[0] == "sections"
    tab, st = symtab([("", 3, 2), ("callee", 0x10, 0)])
    r2 = with_relocs()
    r2[4] = (".rela.text", SHT_RELA, rela([(0, 275, 1, 0), (16, 283, 2, 0)]), 3, 1)      # 偏移不同，其他都一樣
    assert cmp(a, elf(r2))[0] is None


def test_string_addend_may_differ_only_for_the_differing_string_section():
    a = elf(with_relocs(addend=0, strs=b"/a/b/c/d.c\0keep\0"))
    b = elf(with_relocs(addend=12, strs=b"/zz/yy/b/c/d.c\0keep\0"))
    lvl, why = cmp(a, b)
    assert lvl == "sections_masked" and "addends" in why, why
    # 指向別的符號的 addend 不同 → 不採用
    r = with_relocs(addend=12, strs=b"/zz/yy/b/c/d.c\0keep\0")
    r[4] = (".rela.text", SHT_RELA, rela([(0, 275, 1, 12), (8, 283, 2, 4)]), 3, 1)
    assert cmp(a, elf(r))[0] is None
    # 字串區段沒有差異時 addend 不同 → 不採用
    assert cmp(elf(with_relocs(addend=0)), elf(with_relocs(addend=4)))[0] is None


def test_time_date_masks_need_a_build_banner_context():
    for x, y in ((b"mac 00:11:22:33:44:55\0", b"mac 00:11:22:33:44:66\0"),
                 (b"timeout 10:20:30\0", b"timeout 10:20:31\0"),
                 (b"fw 2024-01-05\0", b"fw 2024-02-05\0"),
                 (b"at 12:34:56\0", b"at 01:02:03\0"),
                 (b"user (a@b) ok\0", b"user (c@d) ok\0")):
        assert cmp(elf(base(strs=x)), elf(base(strs=y)))[0] is None, (x, y)
    ok = cmp(elf(base(strs=b"build 2026-11-11 12:34:56 (a@b)\0")), elf(base(strs=b"build 2027-01-02 01:02:03 (c@d)\0")))
    assert ok[0] == "sections_masked"


def test_overlapping_sections_hit_the_hashing_limit():
    data = elf(base(text=b"x" * 2000), overlap=3000)
    r = mod.ko_sections(data)
    assert r["ok"] is False and "limit" in r["reason"]
    assert cmp(data, elf(base()))[0] is None


def test_needs_a_non_empty_code_or_data_section():
    only = elf([(".modinfo", SHT_PROGBITS, b"license=GPL\0"), (".rodata.str1.1", SHT_PROGBITS, b"x\0")])
    assert cmp(only, only)[0] is None
    empty = elf([(".text", SHT_PROGBITS, b""), (".rodata.str1.1", SHT_PROGBITS, b"x\0")])
    assert cmp(empty, empty)[0] is None


def test_extended_section_numbering():
    a = elf(base(), xnum=True)
    r = mod.ko_sections(a)
    assert r["ok"] is True and ".text" in r["digests"]
    assert cmp(a, elf(base()))[0] == "sections"
    assert cmp(a, elf(base(text=b"zzzz"), xnum=True))[0] is None
