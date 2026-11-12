"""C-kernel-boot（lib/kernel_boot.py）：刷機包的 kernel/Image 與 rootfs/boot/Image 不同時並列證據（資訊性），板子的 uname -v 確認；
板子只對上 rootfs/boot/Image 時 K1 才改用它（--prefer-rootfs-image），核心建置紀錄不適用。合成的 Image 與 extlinux.conf。"""
import hashlib
import json
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(__file__))
import test_kernel_config as tkc  # noqa: E402

sys.path.insert(0, str(tkc.PILOT / "lib"))
import kernel_boot as kb  # noqa: E402

kc = tkc.kc
L4T = tkc.L4T
UTS_A = "#1 SMP PREEMPT Wed Oct 28 11:08:26 CST 2026"          # RD 的（kernel/Image）
UTS_B = "#1 SMP PREEMPT Mon Jun  1 13:25:46 PDT 2026"          # NVIDIA 原廠的（rootfs/boot/Image）
EXT = (b"# comment\nTIMEOUT 30\nDEFAULT primary\n\nMENU TITLE L4T boot options\n\nLABEL primary\n   MENU LABEL primary kernel\n"
       b"   LINUX /boot/Image\n   INITRD /boot/initrd\n   APPEND ${cbootargs} root=/dev/mmcblk0p1 rw\n")


def image(uts, who="root@henry-desktop", config=tkc.CONFIG, seed=b"A"):
    banner = f"Linux version 6.8.12-1021-tegra ({who}) (aarch64-none-linux-gnu-gcc 13.2.0, GNU ld 2.40) {uts} ()\n".encode()
    tmpl = b"Linux version 6.8.12-1021-tegra (" + who.encode() + b") (gcc, GNU ld 2.40) # SMP PREEMPT  ()\n"      # 樣板那一份在前面
    return tmpl + b"\x00" * 16 + tkc.fake_image(config, seed=seed) + b"\x00" * 16 + banner


def members(kimg, rimg, ext=EXT):
    m = tkc.pkg_members(kernel_image=kimg, boot_image=rimg)
    if ext is not None:
        m.append((f"{L4T}/rootfs/boot/extlinux/extlinux.conf", ext, None))
    return m


def run(tmp_path, mem, *extra, capsys):
    tmp_path.mkdir(parents=True, exist_ok=True)
    a = tkc.write_tar(tmp_path / "p.tbz2", mem, mode="w:bz2")
    out = tmp_path / "kernel-boot.json"
    rc = kb.main(["--from", str(a), "--prefix", f"{L4T}/rootfs", "--out", str(out), *extra])
    line = capsys.readouterr().out.strip().split("\n")[-1].split("\t")
    return rc, line, (json.loads(out.read_text()) if out.exists() else None)


def board(tmp_path, uts, name="os.txt"):
    f = tmp_path / name
    f.write_text(f'PRETTY_NAME="Ubuntu 24.04"\n\nLinux tegra-ubuntu 6.8.12-1021-tegra {uts} aarch64 aarch64 aarch64 GNU/Linux\n')
    return str(f)


def test_parse_extlinux_default_labels_comments():
    c = kb.parse_extlinux(b"# x\nDEFAULT second\nLABEL first\n  LINUX /boot/A\nlabel second\n  linux ../Image\n  # LINUX /nope\n")
    assert c["selected"] == "second" and c["selected_how"] == "DEFAULT" and c["labels"]["second"]["linux"] == "../Image"
    assert c["labels"]["first"]["linux"] == "/boot/A" and c["order"] == ["first", "second"]
    c = kb.parse_extlinux(b"LABEL a\n LINUX /boot/A\nLABEL b\n MENU DEFAULT\n LINUX /boot/B\n")
    assert c["selected"] == "b" and c["selected_how"] == "MENU DEFAULT"
    c = kb.parse_extlinux(b"LABEL a\n LINUX /boot/A\n")
    assert c["selected"] == "a" and "assumed" in c["selected_how"]
    c = kb.parse_extlinux(b"DEFAULT nope\nLABEL a\n LINUX /boot/A\n")
    assert c["selected"] is None and c["problems"]


def test_resolve_rootfs_path_never_leaves_the_rootfs():
    assert kb.resolve_rootfs_path("/boot/Image") == ("boot", "Image")
    assert kb.resolve_rootfs_path("../Image") == ("boot", "Image")
    assert kb.resolve_rootfs_path("/../../../../etc/shadow") == ("etc", "shadow")
    assert kb.resolve_rootfs_path("../../../../../etc/passwd") == ("etc", "passwd")


def test_parse_board_uname():
    b = kb.parse_board_uname(f"x\nLinux tegra-ubuntu 6.8.12-1021-tegra {UTS_A} aarch64 aarch64 aarch64 GNU/Linux\n")
    assert b == {"host": "tegra-ubuntu", "release": "6.8.12-1021-tegra", "uts": UTS_A, "lines": 1}
    assert kb.parse_board_uname("nothing here") is None
    assert kb.uts_of_banner("Linux version 6 (a@b) (gcc) #1 SMP PREEMPT Mon Jun  1 13:25:46 PDT 2026 ()") == kb.norm(UTS_B)


def test_identical_is_ok(tmp_path, capsys):
    img = image(UTS_A)
    rc, ln, doc = run(tmp_path, members(img, img), capsys=capsys)
    assert rc == 0 and ln[:2] == ["C-kernel-boot", "OK"] and doc["k1_kernel"] == "partition" and "byte-identical" in doc["detail"]


def test_different_without_board_is_informational_attention(tmp_path, capsys):
    k, r = image(UTS_A, config=tkc.CONFIG_ON), image(UTS_B, "buildbrain@x", seed=b"B")
    rc, ln, doc = run(tmp_path, members(k, r), capsys=capsys)
    assert rc == 0 and ln[1] == "ATTENTION" and doc["k1_kernel"] == "partition"
    d = doc["detail"]
    assert hashlib.sha256(k).hexdigest()[:12] in d and hashlib.sha256(r).hexdigest()[:12] in d and UTS_A in d and kb.norm(UTS_B) in d
    assert "1 config difference" in d and "boots /boot/Image" in d and "cat /proc/version" in d and "UEFI" in d
    assert doc["config_diff"]["differences_total"] == 1 and doc["config_diff"]["shown"] == ["CONFIG_FOO_A"]
    assert doc["extlinux"]["points_at"] == "rootfs/boot/Image" and doc["extlinux"]["selected"] == "primary"


def test_missing_extlinux_is_reported_not_fatal(tmp_path, capsys):
    rc, ln, doc = run(tmp_path, members(image(UTS_A), image(UTS_B, seed=b"B"), ext=None), capsys=capsys)
    assert rc == 0 and ln[1] == "ATTENTION" and doc["extlinux"]["present"] is False and "no rootfs/boot/extlinux/extlinux.conf" in doc["detail"]


def test_extlinux_pointing_elsewhere(tmp_path, capsys):
    ext = b"DEFAULT x\nLABEL x\n  LINUX /boot/vmlinuz-other\n"
    rc, ln, doc = run(tmp_path, members(image(UTS_A), image(UTS_B, seed=b"B"), ext=ext), capsys=capsys)
    assert doc["extlinux"]["points_at"] == "other" and doc["extlinux"]["resolved"] == "/boot/vmlinuz-other" and ln[1] == "ATTENTION"
    assert "boots /boot/Image" not in doc["detail"]


def test_symlinked_rootfs_image_is_not_followed(tmp_path, capsys):
    mem = tkc.pkg_members(kernel_image=image(UTS_A)) + [(f"{L4T}/rootfs/boot/Image", None, "/etc/passwd"),
                                                         (f"{L4T}/rootfs/etc/passwd", b"root:x:0:0\n", None),
                                                         (f"{L4T}/rootfs/boot/extlinux/extlinux.conf", EXT, None)]
    rc, ln, doc = run(tmp_path, mem, capsys=capsys)
    assert rc == 0 and ln[1] == "GAP" and "could not be read" in ln[2]


def test_only_one_kernel_is_not_run(tmp_path, capsys):
    rc, ln, doc = run(tmp_path, members(image(UTS_A), None), capsys=capsys)
    assert rc == 0 and ln[1] == "NOT_RUN" and doc is None


def test_board_confirms_flashed_kernel(tmp_path, capsys):
    rc, ln, doc = run(tmp_path, members(image(UTS_A), image(UTS_B, seed=b"B")), "--board-os-txt", board(tmp_path, UTS_A), capsys=capsys)
    assert ln[1] == "OK" and doc["k1_kernel"] == "partition" and "board confirms the flashed kernel" in doc["detail"]
    assert doc["board"]["matches_partition_image"] and not doc["board"]["matches_rootfs_image"]


def test_board_runs_rootfs_kernel(tmp_path, capsys):
    rc, ln, doc = run(tmp_path, members(image(UTS_A), image(UTS_B, seed=b"B")), "--board-os-txt", board(tmp_path, UTS_B), capsys=capsys)
    assert ln[1] == "ATTENTION" and doc["k1_kernel"] == "rootfs" and "build record's exclusions are not applicable" in doc["detail"]


def test_board_runs_neither(tmp_path, capsys):
    rc, ln, doc = run(tmp_path, members(image(UTS_A), image(UTS_B, seed=b"B")), "--board-os-txt",
                      board(tmp_path, "#9 SMP PREEMPT Tue Jan  1 00:00:00 UTC 2030"), capsys=capsys)
    assert ln[1] == "ATTENTION" and doc["k1_kernel"] == "partition" and "different kernel than the package" in doc["detail"]


def test_board_file_without_uname_line(tmp_path, capsys):
    f = tmp_path / "bad.txt"
    f.write_text("PRETTY_NAME=x\n")
    rc, ln, doc = run(tmp_path / "r", members(image(UTS_A), image(UTS_B, seed=b"B")), "--board-os-txt", str(f), capsys=capsys)
    assert ln[1] == "ATTENTION" and "no uname line" in doc["detail"]


def test_build_info_sha_must_match_partition_image():
    k, r = image(UTS_A), image(UTS_B, seed=b"B")
    imgs = {"flashed": kc.ImageProbe("kernel/Image", sha256=hashlib.sha256(k).hexdigest(), size=len(k)),
            "rootfs": kc.ImageProbe("/boot/Image", sha256=hashlib.sha256(r).hexdigest(), size=len(r)), "extlinux": EXT}
    imgs["flashed"].banner = kc.find_banner(k)
    imgs["rootfs"].banner = kc.find_banner(r)
    assert kc.find_banner(k).endswith(UTS_A + " ()")          # 完整的 banner，不是 "# SMP PREEMPT  ()" 樣板
    ok = kb.evaluate(imgs, kc.config_diff, None, {imgs["flashed"].sha256})
    assert ok["build_record"]["matches_partition_image"] and "matches kernel/Image" in ok["detail"]
    bad = kb.evaluate(imgs, kc.config_diff, None, {imgs["rootfs"].sha256})
    assert bad["status"] == "ATTENTION" and "does not match kernel/Image" in bad["detail"] and bad["build_record"]["matches_rootfs_image"]


def test_build_info_read_from_record_top_level(tmp_path):
    sha = "ab" * 32
    p = tkc.write_tar(tmp_path / "rec.tar", [("BUILD-INFO.txt", f"packed_utc=x\nimage=arch/arm64/boot/Image sha256={sha}\n".encode(), None),
                                              ("kernel/.config", b"CONFIG_A=y\n", None)])
    assert kc.build_info_sha256s(kc.read_build_record(str(p))) == {sha}


# ---------- K1 的效果 ----------

def kcfg(tmp_path, mem, *extra):
    tmp_path.mkdir(parents=True, exist_ok=True)
    a = tkc.write_tar(tmp_path / "p.tbz2", mem, mode="w:bz2")
    return tkc.run_main(tmp_path / "k", a, "--prefix", f"{L4T}/rootfs", *extra)


def test_k1_uses_flashed_kernel_by_default_and_rootfs_only_when_asked(tmp_path):
    mem = members(image(UTS_A, config=tkc.CONFIG_ON), image(UTS_B, seed=b"B"))
    rc, doc = kcfg(tmp_path / "d", mem)
    assert rc == 0 and doc["kernel"]["config_source"] == "kernel/Image (IKCONFIG)"            # 預設：kernel/Image，和以前一樣
    rc, doc2 = kcfg(tmp_path / "r", mem, "--prefer-rootfs-image")
    assert rc == 0 and doc2["kernel"]["config_source"] != "kernel/Image (IKCONFIG)"
    assert doc2["kernel"]["config_check"]["image_source"].startswith("rootfs")


def test_prefer_rootfs_makes_the_build_record_not_applicable():
    imgs = {"flashed": kc.ImageProbe("kernel/Image", sha256="a" * 64), "rootfs": kc.ImageProbe("/boot/Image", sha256="b" * 64),
            "prefer_rootfs": True}
    info = SimpleNamespace(images=imgs)
    rec = SimpleNamespace(error=None, label="rec", rejected=0, ignored_links=0, files={("BUILD-INFO.txt",): b"image=x sha256=" + b"a" * 64 + b"\n"})
    out, judge = kc.check_build_record(rec, info, None, None)
    assert judge is None and out["status"] == "GAP" and "do not apply to the running kernel" in out["reason"]


def test_parse_board_uname_accepts_uname_v_and_proc_version_and_counts_lines():
    assert kb.parse_board_uname(UTS_A + "\n")["uts"] == UTS_A                                  # uname -v
    p = kb.parse_board_uname(f"Linux version 6.8.12-1021-tegra (root@henry-desktop) (gcc 13.2.0, GNU ld 2.40) {UTS_A}\n")   # cat /proc/version
    assert p["uts"] == UTS_A and p["release"] == "6.8.12-1021-tegra"
    two = kb.parse_board_uname(f"{UTS_A}\n{UTS_B}\n")
    assert two["uts"] == UTS_A and two["lines"] == 2
    assert kb.parse_board_uname("#1 is a comment line without a date\n") is None


def test_several_uname_lines_are_noted(tmp_path, capsys):
    f = tmp_path / "os.txt"
    f.write_text(f"{UTS_A}\n{UTS_B}\n")
    rc, ln, doc = run(tmp_path / "r", members(image(UTS_A), image(UTS_B, seed=b"B")), "--board-os-txt", str(f), capsys=capsys)
    assert ln[1] == "OK" and "2 uname lines; the first one is used" in doc["detail"]


def test_ubuntu_style_banner_number_is_found():
    t = b"Linux version 6.8.0 (buildd@x) (gcc) #21-Ubuntu SMP PREEMPT_DYNAMIC Fri Feb  9 13:32:52 UTC 2024 ()\n"
    assert kc.find_banner(b"Linux version 6.8.0 (a@b) (gcc) # SMP  ()\n\x00" + t) .startswith("Linux version 6.8.0 (buildd@x)")


def test_build_info_is_found_next_to_the_wizard_kernel_folder(tmp_path):
    """精靈把 pack-build-record 的壓縮檔解開後把 <解開>/kernel 當紀錄；BUILD-INFO.txt 在上一層。"""
    sha = "cd" * 32
    (tmp_path / "kernel").mkdir()
    (tmp_path / "kernel" / ".config").write_text("CONFIG_A=y\n")
    (tmp_path / "BUILD-INFO.txt").write_text(f"image=arch/arm64/boot/Image sha256={sha}\n")
    assert kc.build_info_sha256s(kc.read_build_record(str(tmp_path / "kernel"))) == {sha}
    (tmp_path / "BUILD-INFO.txt").unlink()
    (tmp_path / "BUILD-INFO.txt").symlink_to("/etc/hostname")           # 連結不跟隨
    assert kc.build_info_sha256s(kc.read_build_record(str(tmp_path / "kernel"))) == set()


def test_probe_kernel_version_and_module_map_honour_prefer_rootfs(tmp_path):
    a = tkc.write_tar(tmp_path / "p.tbz2", members(image(UTS_A), image(UTS_B, who="buildbrain@x", seed=b"B")), mode="w:bz2")
    ns = lambda pref: SimpleNamespace(from_=str(a), prefix=f"{L4T}/rootfs", kernel_version=None, prefer_rootfs_image=pref)  # noqa: E731
    st0, v0 = kc.probe_kernel_version(ns(False))
    assert st0 in ("OK", "GAP")
    col, _ = kc.collect(str(a), f"{L4T}/rootfs", images=True)
    imgs = kc.image_inputs(col)
    assert kc.primary_image(imgs).path.endswith("kernel/Image")
    imgs["prefer_rootfs"] = True
    assert kc.primary_image(imgs).path == "/boot/Image"


def test_wizard_extracts_only_os_txt_from_board_tarball(tmp_path):
    import importlib.util
    spec = importlib.util.spec_from_file_location("cra_scan_wizard", tkc.ROOT / "tools" / "wizard" / "cra-scan.py")
    w = importlib.util.module_from_spec(spec)
    sys.modules["cra_scan_wizard"] = w
    spec.loader.exec_module(w)
    good = tkc.write_tar(tmp_path / "board-test-x.tar.gz", [("board-test-x/os.txt", b"Linux h 6 " + UTS_A.encode() + b" aarch64 GNU/Linux\n", None),
                                                           ("board-test-x/accounts.txt", b"x", None)], mode="w:gz")
    out = w.extract_board_os_txt([good], tmp_path / "o" / "os.txt")
    assert out and UTS_A in out.read_text() and [p.name for p in (tmp_path / "o").iterdir()] == ["os.txt"]
    evil = tkc.write_tar(tmp_path / "board-test-y.tar.gz", [("../os.txt", b"x", None), ("os.txt", None, "/etc/passwd")], mode="w:gz")
    assert w.extract_board_os_txt([evil], tmp_path / "o2" / "os.txt") is None
