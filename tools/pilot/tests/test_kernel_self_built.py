"""自編建置紀錄（--build-record-self-built）：release／.config／原始碼路徑核對、身分的各種情況、樹外模組、kernel_boot。合成資料。"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))
import test_kernel_config as tkc  # noqa: E402
import test_kernel_vendor_flow as tvf  # noqa: E402

kc = tkc.kc
FLAG = ["--build-record-self-built"]


def self_built_files(version="#9 SMP PREEMPT Mon Nov 10 02:00:00 UTC 2026", by="rebuilder"):
    f = tkc.identity_files(version=version, by=by)
    f["include/generated/compile.h"] = f["include/generated/compile.h"].replace(b"buildhost", b"otherhost")
    return f


def record_sources(members):
    out = set()
    for k, v in members.items():
        if k.endswith(".cmd"):
            out |= set(kc.parse_cmd(v.decode() if isinstance(v, bytes) else v)[1])
    return out


def run_sb(tmp_path, members, flag=True, tree=True, drop=(), extra_tree=None, image=True):
    """自編紀錄 + 出貨原始碼樹（含紀錄引用的每個非產生檔；drop：從樹裡拿掉的路徑）。"""
    files = dict(tvf.TREE_FILES)
    for p in record_sources(members):
        if not kc.GENERATED_SOURCE_RE.search(p) and p not in drop and not p.startswith("/"):
            files.setdefault(p, "")
    files.update(extra_tree or {})
    img = tkc.fake_image() + tkc.BANNER + b"\x00" * 64
    src = tkc.br_rootfs(tmp_path, extra=[("boot/Image", img, None)] if image else [], name="img.tar")
    args = ["--build-record", str(tkc.write_record_dir(tmp_path / "r", members))] + (FLAG if flag else [])
    if tree:
        args += ["--source-tree", str(tvf.write_tree(tmp_path / "tree", files))]
    mirror = tkc.make_mirror(tmp_path / "m", records=tkc.BR_RECORDS)
    return tkc.run(tmp_path, *args, grype_doc=tkc.grype(list(tkc.BR_RECORDS)), src=src, mirror=mirror)


def members(**kw):
    m = tkc.record_members(**kw)
    m.update(self_built_files())
    return m


def test_5_15_list_loads():
    assert "5.15" in kc.included_c_versions()


def test_self_built_accepted(tmp_path):
    p, st, out = run_sb(tmp_path, members())
    br = out["kernel"]["build_record"]
    assert br["status"] == "OK" and br["self_built"] is True, br
    assert br["identity"]["result"] == "self_built" and br["identity"]["config_compare"] == "same"
    assert br["identity"]["image_banner"].startswith("Linux version 6.8.12-1021-tegra (builder@buildhost)")
    assert set(br["identity"]["differences"]) == {"compile by/host", "version (UTS_VERSION)"}
    assert kc.SELF_BUILT_LIMITATION in br["limitations"] and kc.RECORD_NOT_TIED_LIMITATION not in br["limitations"]
    assert "NOT compared" in kc.SELF_BUILT_LIMITATION
    sc = br["self_built_source_check"]
    assert sc["missing"] == 0 and sc["checked"] > 0 and sc["contents_compared"] is False
    assert "自編" in st[2] and "沒有和映像綁定" not in st[2]                    # 自編採用時不能同時說「沒有和映像綁定」
    assert kc.RECORD_NOT_TIED_LIMITATION not in br["limitations"] and not br.get("identity_incomplete")


def test_self_built_other_release_rejected(tmp_path):
    m = members()
    m["include/config/kernel.release"] = b"6.8.12-other\n"
    br = run_sb(tmp_path, m)[2]["kernel"]["build_record"]
    assert br["status"] == "GAP" and "kernel.release" in br["reason"], br


def test_self_built_config_differs_rejected(tmp_path):
    m = tkc.record_members(config=tkc.CONFIG + "CONFIG_ZZ_NEW_OPTION=y\n")
    m.update(self_built_files())
    br = run_sb(tmp_path, m)[2]["kernel"]["build_record"]
    assert br["status"] == "GAP" and "not the configuration K1 judges with" in br["reason"], br


def test_flag_absent_keeps_old_mismatch_gap(tmp_path):
    br = run_sb(tmp_path, members(), flag=False)[2]["kernel"]["build_record"]
    assert br["status"] == "GAP" and "not the build that was shipped" in br["reason"], br
    assert not br.get("self_built") and br["identity"]["result"] == "mismatch"


def test_self_built_source_missing_from_shipped_tree_is_gap(tmp_path):
    m = members()
    gone = sorted(p for p in record_sources(m) if not kc.GENERATED_SOURCE_RE.search(p) and p.endswith(".c"))[0]
    br = run_sb(tmp_path, m, drop=(gone,))[2]["kernel"]["build_record"]
    assert br["status"] == "GAP" and gone in br["reason"] and "not in the shipped source tree" in br["reason"], br
    assert br["self_built_source_check"]["missing"] >= 1


def test_self_built_generated_sources_are_exempt(tmp_path):
    m = members()
    t = "drivers/foo/always.o"
    m[tkc.cmd_name("drivers/foo/zz.mod.o")] = tkc.cmd_text("drivers/foo/zz.mod.o", "drivers/foo/zz.mod.c", []).encode()
    br = run_sb(tmp_path, m)[2]["kernel"]["build_record"]
    assert br["status"] == "OK" and br["self_built_source_check"]["generated_exempt"] >= 1, br
    for g in ("a/b.mod.c", "crypto/x.asn1.c", "arch/arm64/boot/dts/y.dtb.S", ".vmlinux.export.c", "lib/raid6/neon8.c", "lib/raid6/int4.c", "arch/arm64/crypto/sha256-core.S", "arch/arm64/kvm/hyp/nvhe/hyp-reloc.S", "drivers/tty/vt/defkeymap.c"):
        assert kc.GENERATED_SOURCE_RE.search(g), g
    for g in ("drivers/foo/a.c", "lib/raid6/algos.c", "kernel/config.c"):
        assert not kc.GENERATED_SOURCE_RE.search(g), g


def test_self_built_without_source_tree_is_gap(tmp_path):
    br = run_sb(tmp_path, members(), tree=False)[2]["kernel"]["build_record"]
    assert br["status"] == "GAP" and "no shipped source tree" in br["reason"], br


def test_flag_without_identity_files_or_banner_keeps_old_not_tied(tmp_path):
    """識別檔沒有或 banner 讀不到：出貨紀錄的舊行為（採用、註明沒綁定），不走自編條件、不標自編。"""
    br = run_sb(tmp_path, tkc.record_members(), image=False)[2]["kernel"]["build_record"]
    assert br["status"] == "OK" and br["identity"]["result"] == "not_tied" and br["self_built"] is False, br
    assert kc.RECORD_NOT_TIED_LIMITATION in br["limitations"] and kc.SELF_BUILT_LIMITATION not in br["limitations"]
    assert br["identity_incomplete"] is True and kc.SELF_BUILT_INCOMPLETE_IDENTITY_LIMITATION in br["limitations"]


def test_release_only_identity_keeps_old_matched(tmp_path):
    br = run_sb(tmp_path, tkc.record_members())[2]["kernel"]["build_record"]          # 只有 kernel.release
    assert br["status"] == "OK" and br["identity"]["result"] == "matched" and br["self_built"] is False, br
    assert br["identity_incomplete"] is True and kc.SELF_BUILT_INCOMPLETE_IDENTITY_LIMITATION in br["limitations"]      # 沒比到 version／compiler


def test_uts_norm_fails_closed():
    assert kc.uts_norm("#1 SMP PREEMPT") is None and kc.uts_norm("#1 PREEMPT_RT") is None and kc.uts_norm(None) is None


@pytest.mark.parametrize("ver", ["#1 SMP PREEMPT_RT", "#1 PREEMPT_RT", "#9 SMP PREEMPT", "#9 SMP Mon Nov 10 02:00:00 UTC 2026"])
def test_self_built_uts_that_cannot_be_compared_or_differs_is_rejected(tmp_path, ver):
    m = tkc.record_members()
    f = tkc.identity_files(version=ver, by="rebuilder")
    f["include/generated/compile.h"] = f["include/generated/compile.h"].replace(b"buildhost", b"otherhost")
    m.update(f)
    br = run_sb(tmp_path, m)[2]["kernel"]["build_record"]
    assert br["status"] == "GAP" and "self-built conditions not met" in br["reason"], br


def test_raid6_pattern_needs_digits():
    assert not kc.GENERATED_SOURCE_RE.search("lib/raid6/neon.c") and kc.GENERATED_SOURCE_RE.search("lib/raid6/neon8.c")


def test_self_built_flag_but_identity_fully_matches_is_matched(tmp_path):
    m = tkc.record_members()
    m.update(tkc.identity_files())
    br = run_sb(tmp_path, m)[2]["kernel"]["build_record"]
    assert br["status"] == "OK" and br["identity"]["result"] == "matched" and br["self_built"] is False, br
    assert kc.SELF_BUILT_LIMITATION not in br["limitations"]


def test_oot_name_only_is_uncovered_in_self_built_mode(tmp_path):
    import test_kernel_k1_improve as t1
    root = tmp_path / "oot"
    t1.oot_module(root, "foo")                         # 紀錄裡沒有 foo.ko：只能靠名稱對上
    outs = {}
    for mode in ("shipped", "self"):
        sub = tmp_path / mode
        sub.mkdir()
        m = tkc.record_members()
        if mode == "self":
            m.update(self_built_files())
        else:
            m.update(tkc.identity_files())
        files = dict(tvf.TREE_FILES)
        for pth in record_sources(m):
            if not kc.GENERATED_SOURCE_RE.search(pth) and not pth.startswith("/"):
                files.setdefault(pth, "")
        ko = [(f"usr/lib/modules/{tkc.KVER}/updates/nv/foo.ko", b"\x7fELF", None), ("boot/Image", tkc.fake_image() + tkc.BANNER + b"\x00" * 64, None)]
        src = tkc.br_rootfs(sub, extra=ko, name="oot.tar")
        mirror = tkc.make_mirror(sub / "m", records=tkc.BR_RECORDS)
        args = ["--build-record", str(tkc.write_record_dir(sub / "r", m)), "--oot-build-record", str(root),
                "--source-tree", str(tvf.write_tree(sub / "tree", files))] + (FLAG if mode == "self" else [])
        outs[mode] = tkc.run(sub, *args, grype_doc=tkc.grype(list(tkc.BR_RECORDS)), src=src, mirror=mirror)[2]["kernel"]["build_record"]
    assert outs["shipped"]["out_of_tree_records"]["identity"]["name_only"] == 1 and outs["shipped"]["out_of_tree_records"]["used"] is True
    oo = outs["self"]["out_of_tree_records"]
    assert outs["self"]["self_built"] is True and oo["used"] is False and oo["uncovered"] == 1 and "name only" in oo["reason"], oo


def test_uts_norm():
    assert kc.uts_norm("#4 SMP PREEMPT Thu Aug  6 11:33:36 CST 2026") == "SMP PREEMPT"
    assert kc.uts_norm("#1 SMP PREEMPT Thu Nov 12 13:04:08 CST 2026") == "SMP PREEMPT"
    assert kc.uts_norm("#1 SMP PREEMPT_RT Thu Nov 12 13:04:08 CST 2026") == "SMP PREEMPT_RT"
    assert kc.uts_norm("garbage") is None


def test_self_built_other_compiler_is_rejected(tmp_path):
    m = tkc.record_members()
    f = self_built_files()
    f["include/generated/compile.h"] = f["include/generated/compile.h"].replace(b"gcc (GCC) 13.2.0", b"gcc (Other) 9.9.9")
    m.update(f)
    br = run_sb(tmp_path, m)[2]["kernel"]["build_record"]
    assert br["status"] == "GAP" and "compiler" in br["reason"], br


def test_self_built_other_uts_flags_is_rejected(tmp_path):
    m = tkc.record_members()
    m.update(self_built_files(version="#9 SMP PREEMPT_RT Mon Nov 10 02:00:00 UTC 2026"))
    br = run_sb(tmp_path, m)[2]["kernel"]["build_record"]
    assert br["status"] == "GAP" and "UTS_VERSION flags" in br["reason"], br


def hashes(m, tree_content, bad=None):
    import hashlib
    lines = []
    for p in sorted(record_sources(m)):
        if kc.GENERATED_SOURCE_RE.search(p) or p.startswith("/"):
            continue
        c = tree_content.get(p, "")
        h = hashlib.sha256(c.encode()).hexdigest()
        if p == bad:
            h = "0" * 64
        lines.append(f"{h}  {p}")
    return "\n".join(lines).encode() + b"\n"


def test_self_built_source_hashes_match_and_mismatch(tmp_path):
    m = members()
    m["SOURCE-HASHES"] = hashes(m, {})
    br = run_sb(tmp_path, m)[2]["kernel"]["build_record"]
    assert br["status"] == "OK" and br["self_built_source_check"]["contents_compared"] is True, br
    sh = br["self_built_source_check"]["source_hashes"]
    assert sh["compared"] > 0 and sh["skipped"] == sh["listed"] - sh["compared"] and sh["mismatched"] == 0
    assert kc.SELF_BUILT_HASHED_LIMITATION.format(compared=sh["compared"], listed=sh["listed"], skipped=sh["skipped"]) in br["limitations"]
    assert kc.SELF_BUILT_LIMITATION not in br["limitations"]
    assert any("自編建置紀錄（.config 已核對與出貨核心相同）" in x for x in br["limitations"])
    t2 = tmp_path / "second"
    t2.mkdir()
    bad = sorted(p for p in record_sources(m) if p.endswith(".c") and not kc.GENERATED_SOURCE_RE.search(p))[0]
    m["SOURCE-HASHES"] = hashes(m, {}, bad=bad)
    br = run_sb(t2, m)[2]["kernel"]["build_record"]
    assert br["status"] == "GAP" and bad in br["reason"] and "differ in content" in br["reason"], br
