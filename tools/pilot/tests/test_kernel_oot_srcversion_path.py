"""K1：樹外模組 srcversion 不同、但只差在建置路徑（kbuild 產生檔裡的絕對路徑，例如 *.dtb.S 的 .incbin）時，用重算的 srcversion 採用紀錄
（kernel_oot_record.verify_build_path_only）。已知答案（KAT）由核心自己的 scripts/mod/sumversion.c（kernel-jammy-src，5.15）編成的小程式算出，
不是用這裡的 Python 移植自己算的。全部用合成的檔案與 ELF；不放任何真實的模組或路徑。"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import test_kernel_config as tkc  # noqa: E402
import test_kernel_k1_improve as tki  # noqa: E402
import test_kernel_oot_sections as tos  # noqa: E402

kc = tkc.kc
mod = kc.kernel_oot_record()
SHT_PROGBITS = 1

# 核心 sumversion.c 的結果（m.c＝下面的內容；m.h＝"#define H 1 /* h */\n"，同一資料夾所以也算；/elsewhere/x.h 不在同一資料夾，不讀）
KAT = {
    b"": "5AB31060F7B6C241BF87451",
    b"a" * 55: "DCF45773674F90FCA13511A",
    b"b" * 56: "0C00AFB56C449DFC7DE477B",
    b"c" * 63: "FFCF5A60A10BA693B9B5CD0",
    b"d" * 64: "30363C0A4B7C868CD0426DC",
    bytes(range(33, 127)) + b"x" * 25: "521879B1AD8D10BB5077B1B",
    (b"q1w2e3" * 200)[:1000]: "FF845CF8189EDA7292D0AC2",
    b'/* c */ int  x = 1;\\\n\t"a  b\\" /* not */ "  y;\n/* unterminated': "0CDCBBCE16B2C6E9CB7C33E",
    b"abc\0def": "84F8512092D48362B60830C",
}


def kat_dir(d, content):
    d.mkdir(parents=True)
    (d / "m.c").write_bytes(content)
    (d / "m.h").write_bytes(b"#define H 1 /* h */\n")
    o = f"{d}/m.o"
    (d / ".m.o.cmd").write_text(f"savedcmd_{o} := gcc -c -o {o} {d}/m.c\n\nsource_{o} := {d}/m.c\n\ndeps_{o} := \\\n  {d}/m.h \\\n"
                                f"  /elsewhere/x.h \\\n\n{o}: $(deps_{o})\n\n$(deps_{o}):\n")
    (d / "m.mod").write_text(f"{o}\n")
    return d


def test_srcversion_matches_kernel_sumversion_c(tmp_path):
    for i, (content, want) in enumerate(KAT.items()):
        d = kat_dir(tmp_path / f"k{i}", content)
        rec = mod.read_oot_record(str(d), kc)
        assert rec.error is None, rec.error
        got, files, nswap = mod.recompute_srcversion([rec], kc, str(d), f"{d}/m.ko")
        assert (got, files, nswap) == (want, 2, 0), (content[:20], got, files)


# --- 整合：紀錄在 <tmp>/bld/sources 編，映像（RD）在 /rd/work/sources 編 ------------------------------------------

IMG_ROOT = "/rd/work/sources"


def build_tree(tmp_path, c_text=b"int foo(void) { return 1; }\n"):
    """建置資料夾（原始碼＋kbuild 產生的 foo.dtb.S）與紀錄資料夾。回傳 (紀錄根, 建置根, 模組資料夾)。"""
    broot = tmp_path / "bld" / "sources"
    src = broot / "foo"
    src.mkdir(parents=True)
    (src / "foo.c").write_bytes(c_text)
    (src / "foo.h").write_bytes(b"#define FOO 1\n")
    (src / "foo.dtb.S").write_text(f'.section .dtb.init.rodata,"a"\n.incbin "{src}/foo.dtb"\n')
    rec = tmp_path / "oot" / "foo"
    rec.mkdir(parents=True)
    o, dto, mo, ko = (f"{src}/{n}" for n in ("foo.o", "foo.dtb.o", "foo.mod.o", "foo.ko"))
    (rec / ".foo.o.cmd").write_text(tkc.cmd_text(o, f"{src}/foo.c", [f"{src}/foo.h", f"{tki.KDEP}/include/linux/module.h"]))
    (rec / ".foo.dtb.o.cmd").write_text(tkc.cmd_text(dto, f"{src}/foo.dtb.S", [f"{tki.KDEP}/include/linux/module.h"]))
    (rec / ".foo.dtb.S.cmd").write_text(f"savedcmd_{src}/foo.dtb.S := echo x > {src}/foo.dtb.S\n")
    (rec / ".foo.mod.o.cmd").write_text(tkc.cmd_text(mo, f"{src}/foo.mod.c", [f"{tki.KDEP}/include/linux/module.h"]))
    (rec / ".foo.ko.cmd").write_text(f"savedcmd_{ko} := ld -r -o {ko} {o} {dto} {mo}\n")
    (rec / "foo.mod").write_text(f"{o}\n{dto}\n")
    return tmp_path / "oot", broot, src


def expected_sv(src, root, c_text=None):
    """建置根換成 root 時（RD 的建置）的 srcversion：foo.c＋foo.h＋foo.dtb.S（路徑換掉）。"""
    buf = bytearray()
    mod.sumversion_feed(c_text if c_text is not None else (src / "foo.c").read_bytes(), buf)
    mod.sumversion_feed((src / "foo.h").read_bytes(), buf)
    mod.sumversion_feed((src / "foo.dtb.S").read_bytes().replace(str(src.parent).encode() + b"/", root.encode() + b"/"), buf)
    return mod.sumversion_md4(bytes(buf))[:23]


def ko(sv, strs):
    return tos.elf([(".text", SHT_PROGBITS, b"\x01\x02\x03\x04"), (".rodata.str1.1", SHT_PROGBITS, strs),
                    (".modinfo", SHT_PROGBITS, b"license=GPL\0srcversion=" + sv.encode() + b"\0")])


def run(tmp_path, root, img_sv, img_strs, rec_sv):
    (root / "foo" / "foo.ko").write_bytes(ko(rec_sv, b"x\0"))
    img = [(f"usr/lib/modules/{tkc.KVER}/updates/nv/foo.ko", ko(img_sv, img_strs), None)]
    p, st, out = tki.oot_run(tmp_path, [], [root], extra_ko=img)
    return st, out, out["kernel"]["build_record"]["out_of_tree_records"]


def test_build_path_only_difference_is_adopted(tmp_path):
    root, broot, src = build_tree(tmp_path)
    rec_sv, img_sv = expected_sv(src, str(broot)), expected_sv(src, IMG_ROOT)
    assert rec_sv != img_sv
    st, out, oo = run(tmp_path, root, img_sv, f"{IMG_ROOT}/foo/foo.c\0".encode(), rec_sv)
    assert oo["used"] is True and oo["identity"]["srcversion_build_path"] == 1, oo
    assert "only because of the build path" in oo["masked_examples"][0] and "replaced by /rd/work/ in 1 kbuild-generated" in oo["masked_examples"][0]
    assert tki.by_cve(out)["CVE-2024-1003"]["decision"] == "not_affected"
    assert "srcversion 只差建置路徑（重算核對）1" in st[2]


def test_real_source_difference_is_still_rejected(tmp_path):
    root, broot, src = build_tree(tmp_path)
    rec_sv = expected_sv(src, str(broot))
    img_sv = expected_sv(src, IMG_ROOT, c_text=b"int foo(void) { return 2; }\n")       # RD 的 foo.c 不一樣
    st, out, oo = run(tmp_path, root, img_sv, f"{IMG_ROOT}/foo/foo.c\0".encode(), rec_sv)
    assert oo["used"] is False and "the source differs" in oo["reason"], oo
    assert tki.by_cve(out)["CVE-2024-1003"]["decision"] == "unknown"


def test_source_changed_after_the_build_is_rejected(tmp_path):
    root, broot, src = build_tree(tmp_path)
    rec_sv, img_sv = expected_sv(src, str(broot)), expected_sv(src, IMG_ROOT)
    (src / "foo.c").write_bytes(b"int foo(void) { return 3; }\n")                       # 紀錄之後原始碼被改
    st, out, oo = run(tmp_path, root, img_sv, f"{IMG_ROOT}/foo/foo.c\0".encode(), rec_sv)
    assert oo["used"] is False and "changed after the build" in oo["reason"], oo


def test_no_build_path_in_image_strings_is_rejected(tmp_path):
    root, broot, src = build_tree(tmp_path)
    rec_sv, img_sv = expected_sv(src, str(broot)), expected_sv(src, IMG_ROOT)
    st, out, oo = run(tmp_path, root, img_sv, b"hello\0", rec_sv)
    assert oo["used"] is False and "build path is unknown" in oo["reason"], oo


def test_path_in_a_real_source_file_is_not_swapped(tmp_path):
    # 建置路徑寫在 foo.c（不是 kbuild 產生的檔）：RD 的 foo.c 有 RD 的路徑 → 原始碼本身不同，不能換
    tmp_c = b'const char *p = "%s/foo/x";\n'
    root, broot, src = build_tree(tmp_path, c_text=tmp_c.replace(b"%s", str(tmp_path / "bld" / "sources").encode()))
    rec_sv = expected_sv(src, str(broot))
    img_sv = expected_sv(src, IMG_ROOT, c_text=tmp_c.replace(b"%s", IMG_ROOT.encode()))
    st, out, oo = run(tmp_path, root, img_sv, f"{IMG_ROOT}/foo/foo.c\0".encode(), rec_sv)
    assert oo["used"] is False and "the source differs" in oo["reason"], oo


def test_prefixes_need_a_common_tail_and_one_answer():
    assert mod.build_path_prefixes(["/a/b/src/foo/foo.c"], {".rodata.str1.1": [b"/x/y/src/foo/foo.c\0"]})[0] == (b"/a/b/", b"/x/y/")
    assert mod.build_path_prefixes(["/a/b/foo/foo.c"], {".rodata.str1.1": [b"/x/y/foo/foo.c\0"]})[0] is None        # 只同 2 層
    two = {".rodata.str1.1": [b"/x/src/foo/foo.c\0/z/src/foo/foo.c\0"]}
    assert mod.build_path_prefixes(["/a/src/foo/foo.c"], two)[0] is None
    assert mod.build_path_prefixes(["/a/src/foo/foo.c"], {".s": [None]})[0] is None


def test_record_cannot_pass_a_real_source_off_as_generated(tmp_path):
    # 審查 Finding A：紀錄多放一個 .foo.c.cmd（echo 指令），想把 foo.c 冒充成產生檔來換路徑 → 只有 .dtb.S 能換，仍然不採用
    tmp_c = b'const char *p = "%s/foo/x";\n'
    root, broot, src = build_tree(tmp_path, c_text=tmp_c.replace(b"%s", str(tmp_path / "bld" / "sources").encode()))
    (root / "foo" / ".foo.c.cmd").write_text(f"savedcmd_{src}/foo.c := echo x > {src}/foo.c\n")
    rec_sv = expected_sv(src, str(broot))
    img_sv = expected_sv(src, IMG_ROOT, c_text=tmp_c.replace(b"%s", IMG_ROOT.encode()))
    st, out, oo = run(tmp_path, root, img_sv, f"{IMG_ROOT}/foo/foo.c\0".encode(), rec_sv)
    assert oo["used"] is False and "the source differs" in oo["reason"], oo


def test_swap_only_at_the_start_of_a_path():
    data, n = mod._sv_swap(b'.incbin "/a/x.dtb" /z/a/y', (b"/a/", b"/B/"))
    assert (data, n) == (b'.incbin "/B/x.dtb" /z/a/y', 1)


def test_special_paths_are_not_read_even_when_disguised():
    b = mod.SvBudget()
    for p in ("/proc/version", "/./sys/kernel/mm/transparent_hugepage/enabled", "//proc/self/status", "/x/../dev/null",
              "/./dev/null", "relative/x.c", "/run/x"):
        assert mod._sv_read(p, b) is None, p


def test_global_read_budget_is_shared_and_reported(tmp_path):
    root, broot, src = build_tree(tmp_path)
    rec = mod.read_oot_record(str(root), kc)
    b = mod.SvBudget(global_bytes=10)            # 比 foo.c 還小
    v, why, _ = mod.recompute_srcversion([rec], kc, str(root / "foo"), f"{src}/foo.ko", budget=b)
    assert v is None and "used up" in why


def test_content_verified_candidate_beats_name_only(tmp_path):
    # 同名的兩個候選：一個沒有 .ko（只比名稱），一個 ELF 區段只差建置日期 → 以內容驗證過的為準
    a, b = tos.elf(tos.base(strs=b"Nov 11 2026\0")), tos.elf(tos.base(strs=b"Dec 12 2027\0"))
    r1, r2 = tmp_path / "o1", tmp_path / "o2"
    tki.oot_module(r1, "foo", build="/build/one")
    tki.oot_module(r2, "foo", ko_bytes=b, build="/build/two")
    img = [(f"usr/lib/modules/{tkc.KVER}/updates/nv/foo.ko", a, None)]
    p, st, out = tki.oot_run(tmp_path, [], [r1, r2], extra_ko=img)
    oo = out["kernel"]["build_record"]["out_of_tree_records"]
    assert oo["used"] is True and oo["identity"]["sections_masked"] == 1 and oo["identity"]["name_only"] == 0, oo
    assert "build date/time" in oo["masked_examples"][0]
