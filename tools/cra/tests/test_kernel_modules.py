"""kernel_modules.py（CRA/Config/kernel-modules.json，K2 的輸入）與 board_import.py --kernel-modules-from。

合成的 rootfs：L4T 的配置（/lib/modules/<版本>/ 與 /usr/lib/modules/<版本>/ 是兩個各自存在的資料夾，NVIDIA 的模組在後者的 updates/，
取自公開的 nvidia-l4t-kernel 39.2.1 解開後的樣子）、updates/ 與 extra/、壓縮的 .ko.zst／.ko.xz、映像裡的符號連結、modprobe.d 的同名檔覆蓋、
initramfs（early cpio＋gzip）。產生的檔案一律交給消費端 vex_export.check_kernel_modules 驗證（round trip）。
"""
import bz2
import gzip
import io
import json
import lzma
import os
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import kernel_modules as km  # noqa: E402
import vex_export as vx  # noqa: E402

BI = HERE.parent / "board_import.py"
KM = HERE.parent / "kernel_modules.py"
V = "6.8.12-1021-tegra"
IMG = "sha256:" + "ab" * 32
OWNER = "Test Owner Chen"


# 最小的 ELF 可重定位檔（核心模組的形狀）：e_ident（64 位元、little endian）＋e_type ET_REL（1）＋e_machine aarch64
ELF_REL = b"\x7fELF\x02\x01\x01" + b"\0" * 9 + (1).to_bytes(2, "little") + (183).to_bytes(2, "little") + b"\0" * 44


def ko_bytes(name="m.ko", body=ELF_REL):
    """名稱是 .ko* 的檔的內容：依副檔名壓縮（.ko.gz、.ko.xz、.ko.zst；沒有 zstd 時寫 zstd 的魔數＋垃圾，產生端判斷不了而照樣列）。"""
    if name.endswith(".gz"):
        return gzip.compress(body)
    if name.endswith(".xz"):
        return lzma.compress(body)
    if name.endswith(".zst"):
        if shutil.which("zstd"):
            return subprocess.run(["zstd", "-q", "-c"], input=body, capture_output=True, check=True).stdout
        return b"\x28\xb5\x2f\xfd" + b"x" * 16
    return body


def cpio(entries):
    """[(名稱, 內容 bytes 或 None＝資料夾)] → newc cpio（含 TRAILER!!!）。"""
    out = io.BytesIO()

    def one(name, data, mode):
        nb = name.encode() + b"\0"
        h = b"070701" + b"".join(b"%08X" % x for x in (1, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(nb), 0))
        out.write(h + nb)
        out.write(b"\0" * ((-(110 + len(nb))) % 4))
        out.write(data)
        out.write(b"\0" * ((-len(data)) % 4))
    for n, d in entries:
        one(n, d if d is not None else b"", 0o100644 if d is not None else 0o040755)
    one("TRAILER!!!", b"", 0)
    return out.getvalue()


def initrd_bytes(kind="gzip"):
    early = cpio([("kernel", None), ("kernel/x86/microcode/GenuineIntel.bin", b"ucode")])
    main = cpio([("usr", None), ("usr/lib/modules/" + V + "/kernel/drivers/nvme/initonly.ko", b"\x7fELF"),
                 ("usr/lib/modules/" + V + "/kernel/drivers/base/a.ko.zst", b"z"),
                 ("lib/modules/6.1.0-other/kernel/old.ko", b"o"), ("init", b"#!/bin/sh\n")])
    if kind == "gzip":
        return early + gzip.compress(main) + b"\0" * 512
    if kind == "xz":
        return early + lzma.compress(main)
    if kind == "zstd":
        return early + subprocess.run(["zstd", "-q", "-c"], input=main, capture_output=True, check=True).stdout
    if kind == "bzip2":
        return bz2.compress(main)
    if kind == "garbage":
        return early + b"\x89LZO\0" + b"x" * 100
    if kind == "truncated":
        return gzip.compress(main)[:-40]
    raise ValueError(kind)


def make_rootfs(root, initrd="gzip", versions=(V,)):
    """L4T 風格的 rootfs。回傳 root。"""
    root = Path(root)

    def w(rel, data=None):
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if data is None:
            data = ko_bytes(rel) if km.is_module_name(rel) else b"x"
        p.write_bytes(data if isinstance(data, bytes) else data.encode())

    for v in versions:
        # /lib/modules/<v>/：Canonical 核心的模組（真的資料夾）
        w(f"lib/modules/{v}/kernel/drivers/base/a.ko.zst")
        w(f"lib/modules/{v}/kernel/drivers/net/b.ko.xz")
        w(f"lib/modules/{v}/kernel/drivers/usb/storage/usb-storage.ko.zst")
        w(f"lib/modules/{v}/modules.builtin", "kernel/drivers/base/builtin1.ko\nkernel/fs/ext4/ext4.ko\n")
        w(f"lib/modules/{v}/modules.order", "kernel/drivers/base/a.ko\n")
        w(f"lib/modules/{v}/modules.dep", "")
        w(f"lib/modules/{v}/modules.softdep", km.SOFTDEP_HEADER + "\nsoftdep sd_mod pre: crc32\n")
        # /usr/lib/modules/<v>/：另一個真的資料夾（NVIDIA 的 updates/），和上面有一個同名路徑（去重）
        w(f"usr/lib/modules/{v}/updates/drivers/gpu/host1x/host1x.ko")
        w(f"usr/lib/modules/{v}/updates/nvgpu.ko")
        w(f"usr/lib/modules/{v}/extra/vendor-extra.ko.gz")
        w(f"usr/lib/modules/{v}/kernel/drivers/base/a.ko.zst")
        # 映像裡的連結：updates/oot -> /opt/vendor/mods（要跟隨，在映像裡解析）；build -> 建置樹（不走）
        w("opt/vendor/mods/vendor-oot.ko")
        os.symlink("/opt/vendor/mods", root / f"usr/lib/modules/{v}/updates/oot")
        w("usr/src/linux-headers/junk.ko")
        os.symlink("/usr/src/linux-headers", root / f"lib/modules/{v}/build")
        # 指到映像外（主機）的連結：不能跟到主機
        os.symlink("/../../../../etc", root / f"usr/lib/modules/{v}/extra/hostlink")
    # modprobe.d
    w("etc/modprobe.d/blk.conf", "# comment\nblacklist foo\n\n  install bar /bin/false\n")
    w("etc/modprobe.d/over.conf", "options snd_hda_intel power_save=1\n")
    w("usr/lib/modprobe.d/over.conf", "install baz /bin/false\n")           # 被 /etc 的同名檔蓋掉
    w("lib/modprobe.d/z.conf", "install qux    /bin/true\r\nblacklist   zed\n")              # CRLF：行尾的 CR 去掉
    os.symlink("/dev/null", root / "etc/modprobe.d/masked.conf")
    w("usr/lib/modprobe.d/masked.conf", "install m /bin/false\n")            # 被 /dev/null 遮蔽
    w("etc/modprobe.d/notes.txt", "install nope /bin/false\n")               # 不是 .conf
    w("etc/modprobe.d/.hidden.conf", "install hidden /bin/false\n")          # . 開頭
    w("usr/share/x/elsewhere.conf", "install elsewhere /bin/false\n")
    os.symlink("/usr/share/x/elsewhere.conf", root / "etc/modprobe.d/zz-link.conf")   # 連到沒收的位置：沒有行
    if initrd:
        w("boot/initrd", initrd_bytes(initrd))
    w("boot/Image", b"kernel")
    return root


def gen(tmp_path, src, **kw):
    out = tmp_path / "proj" / "CRA" / "Config" / "kernel-modules.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    kw.setdefault("owner", OWNER)
    kw.setdefault("image_sha256", IMG)
    st, detail = km.generate(out, str(src), **kw)
    return st, detail, out


def load(out):
    return json.loads(out.read_text(encoding="utf-8")), json.loads(out.with_name("kernel-modules.sources.json").read_text(encoding="utf-8"))


def to_tar(root, path, prefix=""):
    with tarfile.open(path, "w") as t:
        for p in sorted(Path(root).rglob("*")):
            t.add(p, arcname=prefix + str(p.relative_to(root)), recursive=False)
    return path


# ---------- 模組清單 ----------

def test_both_module_trees_updates_extra_symlinks_dedup(tmp_path):
    root = make_rootfs(tmp_path / "rootfs")
    st, detail, out = gen(tmp_path, root)
    assert st == "ATTENTION", detail                  # 沒有 lsmod、zz-link.conf 讀不到
    doc, src = load(out)
    rootfs_mods = [m for m in doc["modules_in_image"] if not m.startswith("initramfs:")]
    assert sorted(rootfs_mods) == sorted([
        "kernel/drivers/base/a.ko.zst",                # 兩個資料夾都有：只列一次
        "kernel/drivers/net/b.ko.xz", "kernel/drivers/usb/storage/usb-storage.ko.zst",     # 只在 /lib/modules
        "updates/drivers/gpu/host1x/host1x.ko", "updates/nvgpu.ko", "extra/vendor-extra.ko.gz",  # 只在 /usr/lib/modules
        "updates/oot/vendor-oot.ko"])                  # 映像裡的資料夾連結
    # build 不走；模組資料夾以外的 .ko 以絕對路徑列在 modules_outside_dirs（M2；不放進 modules_in_image）
    assert doc["modules_outside_dirs"] == ["/usr/src/linux-headers/junk.ko"]
    assert src["modules"]["outside_module_dirs"] == ["/usr/src/linux-headers/junk.ko"] and "模組資料夾以外" in detail
    assert src["modules"]["ignored_non_module_files"]["count"] == 0
    if shutil.which("zstd"):
        assert src["modules"]["unchecked_module_files"]["count"] == 0
    assert src["modules"]["roots"] == [f"/lib/modules/{V}", f"/usr/lib/modules/{V}"]
    assert (src["modules"]["updates"], src["modules"]["extra"]) == (3, 1)
    assert doc["modules_builtin"] == ["kernel/drivers/base/builtin1.ko", "kernel/fs/ext4/ext4.ko"]
    assert doc["kernel_version"] == V and doc["image_sha256"] == IMG and doc["owner"] == OWNER
    assert doc["loaded"] is None and doc["modules_disabled"] is None
    vx.check_kernel_modules(doc)                       # 消費端的驗證


def test_merged_usr_symlinked_lib(tmp_path):
    """Ubuntu 24.04 的 merged-usr：/lib -> usr/lib；同一個資料夾只走一次。"""
    root = tmp_path / "r"
    (root / "usr/lib/modules" / V / "kernel").mkdir(parents=True)
    (root / "usr/lib/modules" / V / "kernel/x.ko").write_bytes(ko_bytes())
    (root / "usr/lib/modules" / V / "modules.builtin").write_text("kernel/y.ko\n")
    os.symlink("usr/lib", root / "lib")
    st, detail, out = gen(tmp_path, root)
    doc, src = load(out)
    assert doc["modules_in_image"] == ["kernel/x.ko"] and doc["modules_builtin"] == ["kernel/y.ko"]
    assert src["modules"]["roots"] == [f"/lib/modules/{V} -> /usr/lib/modules/{V}", f"/usr/lib/modules/{V}"]
    vx.check_kernel_modules(doc)


# ---------- modprobe.d ----------

def test_modprobe_effective_lines_and_override(tmp_path):
    st, detail, out = gen(tmp_path, make_rootfs(tmp_path / "rootfs"))
    doc, src = load(out)
    # 依檔名排序：blk、masked（遮蔽）、over（/etc 的）、z（/lib 的）、zz-link（讀不到）
    # 原文（內部空白不動）、有效順序
    assert doc["modprobe_d"] == ["blacklist foo", "install bar /bin/false", "options snd_hda_intel power_save=1",
                                 "install qux    /bin/true", "blacklist   zed"]
    assert [x["file"] for x in src["modprobe_d"]["lines"]] == ["/etc/modprobe.d/blk.conf"] * 2 + ["/etc/modprobe.d/over.conf"] + \
        ["/lib/modprobe.d/z.conf"] * 2
    assert {(o["file"], o["by"]) for o in src["modprobe_d"]["overridden"]} == {
        ("/usr/lib/modprobe.d/over.conf", "/etc/modprobe.d/over.conf"), ("/usr/lib/modprobe.d/masked.conf", "/etc/modprobe.d/masked.conf")}
    status = {f["file"]: f["status"] for f in src["modprobe_d"]["files"]}
    assert status["/etc/modprobe.d/masked.conf"] == "masked" and status["/etc/modprobe.d/zz-link.conf"] == "unreadable"
    assert "zz-link.conf" in detail
    names = {"foo", "zed", "bar", "qux", "baz", "m", "nope", "hidden", "elsewhere"}
    blocked = km.consumer_blocked(vx, doc["modprobe_d"], doc.get("modules_softdep"), names)     # 消費端怎麼讀
    assert set(blocked) == {"bar", "qux"}      # baz（被蓋掉）、m（遮蔽）、nope、hidden、elsewhere 都不算；blacklist 不算擋


def test_modprobe_dir_linked_outside_is_gap(tmp_path):
    root = make_rootfs(tmp_path / "rootfs", initrd=None)
    shutil.rmtree(root / "etc/modprobe.d")
    (root / "srv/cfg").mkdir(parents=True)
    os.symlink("/srv/cfg", root / "etc/modprobe.d")
    st, detail, out = gen(tmp_path, root)
    assert st == "GAP" and "modprobe.d" in detail and not out.exists()


# ---------- 輸入不足 → 沒有檔案 ----------

def test_missing_modules_dir_is_gap_no_file(tmp_path):
    root = tmp_path / "r"
    (root / "etc").mkdir(parents=True)
    (root / "etc/os-release").write_text("x")
    st, detail, out = gen(tmp_path, root)
    assert st == "GAP" and "沒有核心模組資料夾" in detail and not out.exists()
    assert not out.with_name("kernel-modules.sources.json").exists()


def test_modules_dir_without_ko_is_gap(tmp_path):
    root = tmp_path / "r"
    (root / "lib/modules" / V).mkdir(parents=True)
    (root / "lib/modules" / V / "modules.builtin").write_text("kernel/a.ko\n")
    st, detail, out = gen(tmp_path, root)
    assert st == "GAP" and ".ko" in detail and not out.exists()


def test_several_kernels_need_kernel_version(tmp_path):
    root = make_rootfs(tmp_path / "rootfs", initrd=None, versions=(V, "6.8.0-31-generic"))
    st, detail, out = gen(tmp_path, root)
    assert st == "GAP" and "--kernel-version" in detail and not out.exists()
    st, detail, out = gen(tmp_path, root, kernel_version=V)
    assert st == "ATTENTION" and load(out)[0]["kernel_version"] == V
    st, detail, _ = gen(tmp_path, root, kernel_version="9.9.9", replace=True)
    assert st == "GAP"


def test_image_hash_from_scan_meta(tmp_path):
    root = make_rootfs(tmp_path / "rootfs", initrd=None)
    scan = tmp_path / "scan"
    scan.mkdir()
    iid = "sha256:" + "cd" * 32
    (scan / "meta.json").write_text(json.dumps({"image_id": iid, "version": iid, "content_sha256": None}))
    st, detail, out = gen(tmp_path, root, image_sha256=None, scan=scan)
    doc, src = load(out)
    assert doc["image_sha256"] == iid and "image_id" in src["image_sha256"]["from"]
    # 明確給的值要是 meta.json 裡的
    st, detail, _ = gen(tmp_path, root, image_sha256=IMG, scan=scan, replace=True)
    assert st == "GAP" and "不是這次掃描的映像" in detail
    st, detail, _ = gen(tmp_path, root, image_sha256=iid, scan=scan, replace=True)
    assert st in ("OK", "ATTENTION")
    # 沒有 meta.json、meta.json 沒有雜湊、都沒給 → GAP（不自己算）
    (scan / "meta.json").unlink()
    assert gen(tmp_path / "x", root, image_sha256=None, scan=scan)[0] == "GAP"
    (scan / "meta.json").write_text(json.dumps({"version": "dir-sha256-0123456789abcdef"}))
    assert gen(tmp_path / "y", root, image_sha256=None, scan=scan)[0] == "GAP"
    assert gen(tmp_path / "z", root, image_sha256=None)[0] == "GAP"


@pytest.mark.parametrize("owner", ["", "  ", "專案負責人", "(your name)", "TO BE COMPLETED", "<name>"])
def test_placeholder_owner_rejected(tmp_path, owner):
    with pytest.raises(km.InputError):
        gen(tmp_path, make_rootfs(tmp_path / "rootfs", initrd=None), owner=owner)
    assert not (tmp_path / "proj/CRA/Config/kernel-modules.json").exists()


def test_no_cra_project_is_gap(tmp_path):
    root = make_rootfs(tmp_path / "rootfs", initrd=None)
    st, detail = km.generate(tmp_path / "nope" / "kernel-modules.json", str(root), owner=OWNER, image_sha256=IMG)
    assert st == "GAP"


def test_existing_different_file_needs_replace(tmp_path):
    root = make_rootfs(tmp_path / "rootfs", initrd=None)
    gen(tmp_path, root)
    st, detail, out = gen(tmp_path, root)
    assert "沒有變更" in detail
    st, detail, out = gen(tmp_path, root, captured="2026-01-02")
    assert st == "ATTENTION" and "--replace" in detail and load(out)[0]["captured"] != "2026-01-02"
    gen(tmp_path, root, captured="2026-01-02", replace=True)
    assert load(out)[0]["captured"] == "2026-01-02"


# ---------- initramfs ----------

@pytest.mark.parametrize("kind", ["gzip", "xz", "bzip2", "zstd"])
def test_initramfs_modules(tmp_path, kind):
    if kind == "zstd" and not shutil.which("zstd"):
        pytest.skip("沒有 zstd（建立測試資料用）")
    st, detail, out = gen(tmp_path, make_rootfs(tmp_path / "rootfs", initrd=kind))
    doc, src = load(out)
    ir = [m for m in doc["modules_in_image"] if m.startswith("initramfs:")]
    assert ir == ["initramfs:boot/initrd:kernel/drivers/base/a.ko.zst", "initramfs:boot/initrd:kernel/drivers/nvme/initonly.ko"]
    rec = src["initramfs"][0]
    assert rec["status"] == "read" and rec["modules"] == 2 and rec["other_kernel_versions"] == ["6.1.0-other"]
    assert vx.norm_module(ir[1]) == "initonly"            # 消費端只比名稱
    vx.check_kernel_modules(doc)


@pytest.mark.parametrize("kind", ["garbage", "truncated"])
def test_unreadable_initramfs_is_gap_unless_accepted(tmp_path, kind):
    root = make_rootfs(tmp_path / "rootfs", initrd=kind)
    st, detail, out = gen(tmp_path, root)
    assert st == "GAP" and "initramfs" in detail and "--accept-unread-initramfs" in detail and not out.exists()
    st, detail, out = gen(tmp_path, root, accept_unread_initramfs=True)
    doc, src = load(out)
    assert st == "ATTENTION" and "LIMITATION: initramfs NOT read" in doc["source"] and "LIMITATION" in doc["$comment"]
    assert not any(m.startswith("initramfs:") for m in doc["modules_in_image"])
    vx.check_kernel_modules(doc)


def test_initramfs_selection(tmp_path, monkeypatch):
    root = make_rootfs(tmp_path / "rootfs", initrd=None)
    (root / "boot/initrd.img-6.8.0-31-generic").write_bytes(b"garbage")       # 別的核心的：不讀
    (root / f"boot/initrd.img-{V}").write_bytes(initrd_bytes("gzip"))
    os.symlink(f"initrd.img-{V}", root / "boot/initrd.img")
    (root / "boot/extlinux").mkdir()
    (root / "boot/extlinux/extlinux.conf").write_text("LABEL primary\n  LINUX /boot/Image\n  INITRD /boot/custom-initrd.img\n")
    st, detail, out = gen(tmp_path, root)
    assert st == "GAP" and "extlinux.conf INITRD /boot/custom-initrd.img" in detail      # extlinux 指的檔沒有收
    (root / "boot/extlinux/extlinux.conf").write_text("LABEL primary\n  LINUX /boot/Image\n  INITRD /boot/initrd.img\n")
    st, detail, out = gen(tmp_path, root)
    doc, src = load(out)
    assert [r["path"] for r in src["initramfs"]] == [f"/boot/initrd.img-{V}"]
    assert any("6.8.0-31-generic" in n for n in src["notes"])
    # zstd 沒有解壓程式 → 讀不了（GAP），不是當作沒有模組
    monkeypatch.setattr(km, "zstd_decoder", lambda: None)
    (root / f"boot/initrd.img-{V}").write_bytes(b"\x28\xb5\x2f\xfd" + b"\0" * 20)
    st, detail, _ = gen(tmp_path, root, replace=True)
    assert st == "GAP" and "zstd" in detail


# ---------- lsmod ----------

LSMOD = """Module                  Size  Used by
nvgpu                3866624  17
host1x                262144  6 nvgpu
usb_storage            81920  0
"""
PROC_MODULES = "nvgpu 3866624 17 - Live 0x0000000000000000 (O)\nhost1x 262144 6 nvgpu, Live 0x0000000000000000 (O)\n"


def test_parse_lsmod_formats():
    assert km.parse_lsmod(LSMOD) == (["host1x", "nvgpu", "usb_storage"], 0)
    assert km.parse_lsmod(PROC_MODULES) == (["host1x", "nvgpu"], 0)
    assert km.parse_lsmod("garbage line here\nok 12 0\n$(rm) 1 0\n") == (["ok"], 2)
    assert km.parse_lsmod("") == ([], 0)


def test_lsmod_loaded_and_contradiction(tmp_path):
    root = make_rootfs(tmp_path / "rootfs")
    f = tmp_path / "lsmod.txt"
    f.write_text(LSMOD)
    loaded, frm, notes = km.read_lsmod_file(f)
    st, detail, out = gen(tmp_path, root, loaded=loaded, loaded_from=frm, input_notes=notes)
    doc, _ = load(out)
    assert doc["loaded"] == ["host1x", "nvgpu", "usb_storage"]        # usb_storage ↔ usb-storage.ko.zst（- 與 _ 相同）
    vx.check_kernel_modules(doc)
    # 有載入、映像裡卻沒有 → GAP（消費端會 FAIL），不寫
    f.write_text(LSMOD + "not_in_image 4096 0\n")
    loaded, frm, notes = km.read_lsmod_file(f)
    st, detail, _ = gen(tmp_path, root, loaded=loaded, loaded_from=frm, replace=True)
    assert st == "GAP" and "not_in_image" in detail
    # 原本的檔（同一個映像）改名，K2 不再讀它（M3）
    assert not out.exists() and "stale-" in detail
    stale = sorted(out.parent.glob("kernel-modules.json.stale-*"))
    assert len(stale) == 1 and json.loads(stale[0].read_text())["loaded"] == ["host1x", "nvgpu", "usb_storage"]
    assert len(list(out.parent.glob("kernel-modules.sources.json.stale-*"))) == 1


# ---------- 輸入格式：tar、刷機包 tbz2＋前綴、CLI ----------

def test_rootfs_tar_and_flash_package_give_same_result(tmp_path):
    root = make_rootfs(tmp_path / "rootfs")
    _, _, out = gen(tmp_path / "d", root)
    ref = load(out)[0]
    tar = to_tar(root, tmp_path / "rootfs.tar")
    _, _, out2 = gen(tmp_path / "t", tar)
    tbz = tmp_path / "pkg.tbz2"
    with tarfile.open(tbz, "w:bz2") as t:
        t.add(tar, arcname="other/readme.tar")
        for p in sorted(root.rglob("*")):
            t.add(p, arcname="product-a/Linux_for_Tegra/rootfs_no_gui/" + str(p.relative_to(root)), recursive=False)
    _, _, out3 = gen(tmp_path / "p", tbz, prefix="product-a/Linux_for_Tegra/rootfs_no_gui")
    for o in (out2, out3):
        d = load(o)[0]
        for k in ("modules_in_image", "modules_builtin", "modprobe_d", "kernel_version"):
            assert d[k] == ref[k], k


def test_cli(tmp_path):
    root = make_rootfs(tmp_path / "rootfs", initrd=None)
    out = tmp_path / "Config" / "kernel-modules.json"
    out.parent.mkdir()
    r = subprocess.run([sys.executable, "-I", str(KM), "--from", str(root), "--image-sha256", IMG, "--owner", OWNER,
                        "--out", str(out), "--modules-disabled", "false"], capture_output=True, text=True, timeout=120)
    assert r.returncode == 2 and r.stdout.startswith("D-kernel-modules\tATTENTION\t"), r.stdout + r.stderr
    doc = json.loads(out.read_text())
    assert doc["modules_disabled"] is False
    vx.check_kernel_modules(doc)
    r = subprocess.run([sys.executable, "-I", str(KM), "--from", str(root), "--image-sha256", IMG, "--owner", "專案負責人",
                        "--out", str(tmp_path / "Config" / "k2.json")], capture_output=True, text=True, timeout=120)
    assert r.returncode == 1 and "FAIL" in r.stdout and not (tmp_path / "Config" / "k2.json").exists()


# ---------- board_import.py --kernel-modules-from ----------

def board_archive(tmp_path, stem, uname_ver, lsmod=LSMOD, modules_disabled="1"):
    files = {"summary.txt": "check\tstatus\tdetail\nos\tOK\tos.txt\n",
             "os.txt": f'PRETTY_NAME="Ubuntu 24.04"\n\nLinux board {uname_ver} #1 SMP PREEMPT aarch64 GNU/Linux\n',
             "sysctl.txt": f"kernel.randomize_va_space = 2\nkernel.modules_disabled = {modules_disabled}\n"}
    if lsmod is not None:
        files["lsmod.txt"] = lsmod
    a = tmp_path / f"{stem}.tar.gz"
    with tarfile.open(a, "w:gz") as t:
        for n, c in files.items():
            b = c.encode()
            ti = tarfile.TarInfo(f"{stem}/{n}")
            ti.size = len(b)
            t.addfile(ti, io.BytesIO(b))
    return a


def result_dir(tmp_path):
    rd = tmp_path / "res" / "rootfs_no_gui"
    (rd / "cra-project" / "CRA" / "Config").mkdir(parents=True)
    (rd / "scan").mkdir()
    (rd / "scan" / "meta.json").write_text(json.dumps({"image_id": IMG, "version": IMG}))
    return rd


def bi(*args):
    r = subprocess.run([sys.executable, "-I", str(BI), *map(str, args)], capture_output=True, text=True, timeout=180)
    lines = {ln.split("\t")[0]: ln.split("\t") for ln in r.stdout.splitlines() if "\t" in ln}
    return r, lines


def test_board_import_writes_kernel_modules(tmp_path):
    root = make_rootfs(tmp_path / "rootfs")
    rd = result_dir(tmp_path)
    a = board_archive(tmp_path, "board-test-dev1-20261105T010203Z", V)
    r, lines = bi("--result", rd, a, "--kernel-modules-from", root, "--owner", OWNER)
    assert "D-board-test" in lines and lines["D-kernel-modules"][1] == "ATTENTION", r.stdout + r.stderr
    out = rd / "cra-project/CRA/Config/kernel-modules.json"
    doc = json.loads(out.read_text())
    assert doc["image_sha256"] == IMG                                  # 取自 scan/meta.json
    assert doc["loaded"] == ["host1x", "nvgpu", "usb_storage"]         # 取自板子結果的 lsmod.txt
    assert doc["modules_disabled"] is True                             # 取自板子的 sysctl.txt
    assert "board-test/board-test-dev1-20261105T010203Z" in doc["source"]
    vx.check_kernel_modules(doc)
    # 新的板子結果跑的是別的核心：lsmod 不用（loaded null），要 --replace 才取代
    b = board_archive(tmp_path, "board-test-dev1-20261106T010203Z", "6.8.0-31-generic")
    r, lines = bi("--result", rd, b, "--kernel-modules-from", root, "--owner", OWNER, "--replace")
    doc = json.loads(out.read_text())
    assert doc["loaded"] is None and doc["modules_disabled"] is None
    assert "6.8.0-31-generic" in " ".join(json.loads(out.with_name("kernel-modules.sources.json").read_text())["notes"])
    vx.check_kernel_modules(doc)


def test_board_import_kernel_modules_args(tmp_path):
    rd = result_dir(tmp_path)
    r, _ = bi("--result", rd, "--owner", OWNER)
    assert r.returncode == 64                                          # --owner 要和 --kernel-modules-from 一起用
    r, _ = bi("--result", rd, "--kernel-modules-from", tmp_path)
    assert r.returncode == 64                                          # 沒有 --owner
    r, lines = bi("--result", rd, "--kernel-modules-from", tmp_path / "empty-nothing", "--owner", OWNER)
    assert lines["D-kernel-modules"][1] == "FAIL" and r.returncode == 1
    (tmp_path / "e").mkdir()
    r, lines = bi("--result", rd, "--kernel-modules-from", tmp_path / "e", "--owner", OWNER)
    assert lines["D-kernel-modules"][1] == "GAP" and r.returncode == 2
    assert not (rd / "cra-project/CRA/Config/kernel-modules.json").exists()


def test_board_on_device_collects_lsmod_and_modules_disabled():
    t = (HERE.parents[2] / "scripts" / "demo" / "board-on-device.sh").read_text(encoding="utf-8")
    assert "run lsmod lsmod.txt cat /proc/modules" in t and "kernel.modules_disabled" in t
    import board_import
    assert "lsmod.txt" in board_import.BOARD_FILES and "lsmod.txt" not in board_import.EXPECTED_BOARD


# ---------- 第二輪審查：讀不到的路徑、連結、模組資料夾以外、刷機包的 initrd、initramfs 的 modprobe.d ----------

def make_unreadable(path, monkeypatch):
    """資料夾讀不到（root 執行時 chmod 擋不住：改讓 os.scandir 對這個資料夾失敗）。"""
    os.chmod(path, 0)
    if os.geteuid() == 0:
        real, target = os.scandir, os.path.abspath(path)

        def fake(p="."):
            if os.path.abspath(p) == target:
                raise PermissionError(13, "Permission denied", p)
            return real(p)
        monkeypatch.setattr(os, "scandir", fake)


def test_unreadable_dir_in_module_tree_is_gap(tmp_path, monkeypatch):
    root = make_rootfs(tmp_path / "rootfs", initrd=None)
    st, _, out = gen(tmp_path, root)
    assert out.exists()
    locked = root / f"lib/modules/{V}/kernel/locked"
    locked.mkdir()
    (locked / "secret.ko").write_bytes(ko_bytes())
    make_unreadable(locked, monkeypatch)
    try:
        st, detail, out = gen(tmp_path, root)
    finally:
        os.chmod(locked, 0o755)
    assert st == "GAP" and "kernel/locked" in detail and not out.exists()          # 不是 OK、不是「已移除」
    assert "stale-" in detail                                                      # 原本的檔改名


@pytest.mark.parametrize("where", ["etc/modprobe.d", "boot", "usr/lib"])
def test_unreadable_modprobe_boot_or_parent_is_gap(tmp_path, monkeypatch, where):
    root = make_rootfs(tmp_path / "rootfs", initrd="gzip")
    make_unreadable(root / where, monkeypatch)
    try:
        st, detail, out = gen(tmp_path, root)
    finally:
        os.chmod(root / where, 0o755)
    assert st == "GAP" and where in detail and not out.exists()


def test_unreadable_elsewhere_is_attention_and_named(tmp_path, monkeypatch):
    root = make_rootfs(tmp_path / "rootfs", initrd=None)
    (root / "root/private").mkdir(parents=True)
    make_unreadable(root / "root", monkeypatch)
    try:
        st, detail, out = gen(tmp_path, root)
    finally:
        os.chmod(root / "root", 0o755)
    assert st == "ATTENTION" and "/root" in detail
    assert any(x.startswith("/root") for x in load(out)[1]["unreadable_paths"])


def test_ko_symlink_to_non_ko_file_and_outside_modules(tmp_path):
    root = make_rootfs(tmp_path / "rootfs", initrd=None)
    (root / "opt/blobs").mkdir(parents=True)
    (root / "opt/blobs/driver.bin").write_bytes(ELF_REL)
    os.symlink("/opt/blobs/driver.bin", root / f"usr/lib/modules/{V}/updates/linked.ko")       # M1
    (root / "opt/vendor/insmod/x.ko").parent.mkdir(parents=True)
    (root / "opt/vendor/insmod/x.ko").write_bytes(ko_bytes())                                         # M2
    (root / "lib/modules/6.1.0-old/kernel").mkdir(parents=True)
    (root / "lib/modules/6.1.0-old/kernel/old.ko").write_bytes(ko_bytes())                           # 別的核心：不列
    st, detail, out = gen(tmp_path, root, kernel_version=V)
    doc, src = load(out)
    # 連結指到名稱不是 .ko 的檔：資料夾輸入時回頭讀目標的開頭（ELF ET_REL → 列，不是 unchecked）
    assert "updates/linked.ko" in doc["modules_in_image"]
    assert not any(e["path"].endswith("updates/linked.ko") for e in src["modules"]["unchecked_module_files"]["examples"])
    # tar 輸入：目標的內容已經讀不到 → 判斷不了，照樣列（偏保守），記在 unchecked_module_files
    d2, s2 = load(gen(tmp_path, to_tar(root, tmp_path / "r.tar"), kernel_version=V, replace=True)[2])
    assert "updates/linked.ko" in d2["modules_in_image"]
    assert any(e["path"].endswith("updates/linked.ko") for e in s2["modules"]["unchecked_module_files"]["examples"])
    assert "/opt/vendor/insmod/x.ko" in doc["modules_outside_dirs"] and "/opt/vendor/insmod/x.ko" in detail
    assert "/opt/vendor/insmod/x.ko" not in doc["modules_in_image"]
    assert not any("old.ko" in m for m in doc["modules_in_image"] + doc["modules_outside_dirs"])
    assert src["modules"]["other_kernel_versions"] == 1
    assert {vx.norm_module(m) for m in doc["modules_in_image"]} >= {"linked"}
    vx.check_kernel_modules(doc)


def l4t_package(tmp_path, root, pkg_initrd):
    tbz = tmp_path / "pkg.tbz2"
    with tarfile.open(tbz, "w:bz2") as t:
        def add(name, data):
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
        if pkg_initrd is not None:
            add("product-a/Linux_for_Tegra/bootloader/l4t_initrd.img", pkg_initrd)
        add("product-a/Linux_for_Tegra/bootloader/other.bin", b"x")
        for p in sorted(root.rglob("*")):
            t.add(p, arcname="product-a/Linux_for_Tegra/rootfs_no_gui/" + str(p.relative_to(root)), recursive=False)
    return tbz


def recovery_initrd():
    return gzip.compress(cpio([("usr/lib/modules/" + V + "/kernel/drivers/mtd/recovery-only.ko", b"x"),
                              ("etc/modprobe.d/r.conf", b"blacklist rec\n")]))


def test_flash_package_l4t_initrd(tmp_path):
    root = make_rootfs(tmp_path / "rootfs", initrd=None)
    (root / "etc/nv_tegra_release").write_text("# R39 (release), REVISION: 2.0\n")
    tbz = l4t_package(tmp_path, root, recovery_initrd())
    st, detail, out = gen(tmp_path / "a", tbz, prefix="product-a/Linux_for_Tegra/rootfs_no_gui")
    doc, src = load(out)
    assert "initramfs:product-a/Linux_for_Tegra/bootloader/l4t_initrd.img:kernel/drivers/mtd/recovery-only.ko" in doc["modules_in_image"]
    rec = [r for r in src["initramfs"] if r["found_by"] == "flash package"][0]
    assert rec["status"] == "read" and rec["modprobe_d_files"] == 1
    # 解開的刷機包資料夾＋前綴：同樣讀到
    d = tmp_path / "unpacked"
    with tarfile.open(tbz) as t:
        t.extractall(d, filter="tar")
    st, detail, out = gen(tmp_path / "b", d, prefix="product-a/Linux_for_Tegra/rootfs_no_gui")
    assert any("recovery-only" in m for m in load(out)[0]["modules_in_image"])
    # 讀不了 → GAP（和 rootfs 的 initramfs 同樣的規則；N2）；--accept-unread-initramfs 才寫
    (tmp_path / "c").mkdir()
    tbz2 = l4t_package(tmp_path / "c", root, b"\x89LZO junk")
    st, detail, out = gen(tmp_path / "c", tbz2, prefix="product-a/Linux_for_Tegra/rootfs_no_gui")
    assert st == "GAP" and "l4t_initrd.img" in detail and not out.exists()
    st, detail, out = gen(tmp_path / "c", tbz2, prefix="product-a/Linux_for_Tegra/rootfs_no_gui", accept_unread_initramfs=True)
    assert st == "ATTENTION" and "l4t_initrd.img" in load(out)[0]["source"]
    # 輸入只有 rootfs（L4T）：沒有讀 l4t_initrd.img → 寫出來
    st, detail, out = gen(tmp_path / "e", root)
    assert "l4t_initrd.img" in " ".join(load(out)[1]["notes"])


def test_initramfs_modprobe_withholds_rootfs_block(tmp_path):
    """rootfs 擋住 bar，initramfs 有 bar.ko：initramfs 自己沒擋 → install bar 行不放；有擋 → 照放。"""
    def with_initrd(conf):
        entries = [("usr/lib/modules/" + V + "/kernel/drivers/x/bar.ko", b"x")]
        if conf is not None:
            entries.append(("etc/modprobe.d/blk.conf", conf))
        root = make_rootfs(tmp_path / f"r{conf is None}{bool(conf)}", initrd=None)
        (root / "boot/initrd").write_bytes(gzip.compress(cpio(entries)))
        return root
    st, detail, out = gen(tmp_path / "1", with_initrd(None))
    doc, src = load(out)
    assert "install bar /bin/false" not in doc["modprobe_d"] and "blacklist foo" in doc["modprobe_d"]
    assert src["modprobe_d"]["withheld"][0]["line"] == "install bar /bin/false" and "bar" in detail
    assert "bar" not in km.consumer_blocked(vx, doc["modprobe_d"], doc.get("modules_softdep"), {"bar"})
    st, detail, out = gen(tmp_path / "2", with_initrd(b"install bar /bin/false\n"))
    assert "install bar /bin/false" in load(out)[0]["modprobe_d"]


def test_alias_files_and_run_modprobe_ignored(tmp_path):
    root = make_rootfs(tmp_path / "rootfs", initrd=None)
    (root / "lib/modprobe.d/aliases.alias").write_text("alias net-pf-99 off\n")                 # L1
    (root / "run/modprobe.d").mkdir(parents=True)
    (root / "run/modprobe.d/rt.conf").write_text("install runtimeonly /bin/false\n")             # L2
    (root / "run/modprobe.d/over.conf").write_text("install baz2 /bin/false\n")
    st, detail, out = gen(tmp_path, root)
    doc, src = load(out)
    assert "alias net-pf-99 off" in doc["modprobe_d"]
    assert not any("runtimeonly" in x or "baz2" in x for x in doc["modprobe_d"])
    assert "options snd_hda_intel power_save=1" in doc["modprobe_d"]                  # /run 不蓋掉 /etc 的同名檔
    assert src["modprobe_d"]["runtime_not_read"] == ["/run/modprobe.d/over.conf", "/run/modprobe.d/rt.conf"]
    assert "/run/modprobe.d" in " ".join(src["notes"])


def test_no_initramfs_note_and_boot_symlink(tmp_path):
    root = make_rootfs(tmp_path / "rootfs", initrd=None)
    st, detail, out = gen(tmp_path / "a", root)
    assert "沒有 initrd" in " ".join(load(out)[1]["notes"])                             # L4
    shutil.move(str(root / "boot"), str(root / "bootpart"))
    (root / "bootpart/initrd").write_bytes(initrd_bytes("gzip"))
    os.symlink("bootpart", root / "boot")                                              # /boot 是連結：在映像裡解析
    st, detail, out = gen(tmp_path / "b", root)
    assert any(m.startswith("initramfs:bootpart/initrd:") for m in load(out)[0]["modules_in_image"])


def test_safe_target_checks_every_component(tmp_path):
    root = make_rootfs(tmp_path / "rootfs", initrd=None)
    rd = tmp_path / "res"
    (tmp_path / "elsewhere/CRA/Config").mkdir(parents=True)
    rd.mkdir()
    os.symlink(tmp_path / "elsewhere", rd / "cra-project")                            # L5：上層是連結
    with pytest.raises(km.InputError):
        km.generate(rd / "cra-project/CRA/Config/kernel-modules.json", str(root), owner=OWNER, image_sha256=IMG, base=rd)
    assert not (tmp_path / "elsewhere/CRA/Config/kernel-modules.json").exists()


def test_board_import_gap_moves_old_file_aside(tmp_path):
    root = make_rootfs(tmp_path / "rootfs", initrd=None)
    rd = result_dir(tmp_path)
    r, lines = bi("--result", rd, "--kernel-modules-from", root, "--owner", OWNER)
    out = rd / "cra-project/CRA/Config/kernel-modules.json"
    assert out.exists()
    r, lines = bi("--result", rd, "--kernel-modules-from", root, "--owner", OWNER, "--kernel-version", "9.9.9")
    assert lines["D-kernel-modules"][1] == "GAP" and "stale-" in lines["D-kernel-modules"][2] and not out.exists()


def test_kernel_config_collector_has_no_hooks():
    """K1（kernel_config.py 的 C-kernel-config）用的 Collected 沒有這些鉤子：collect、feed_tar 的行為和以前一樣。"""
    kc = km.kernel_config()
    assert not any(hasattr(kc.Collected(), h) for h in ("unreadable", "hardlink", "outside"))


# ---------- board-import.sh 挑 Python（H2） ----------

COMMON = HERE.parents[2] / "scripts" / "pilot" / "lib" / "common.sh"


# 自架 runner 的 setup-python 是動態連結 libpython，靠 LD_LIBRARY_PATH 才找得到；假的 python 用 sys.executable，所以要把它帶進去
LIBPATH = {k: os.environ[k] for k in ("LD_LIBRARY_PATH",) if k in os.environ}


def fake_python(d, name, ver):
    p = d / name
    p.write_text(f"#!/bin/sh\nexec {sys.executable} -c 'import sys; m=tuple(int(x) for x in sys.argv[1].split(\".\")); "
                 f"sys.exit(0 if {ver!r} >= m else 1)' \"$4\"\n")
    p.chmod(0o755)
    return p


def pick(tmp_path, env):
    r = subprocess.run([shutil.which("bash"), "-c", f'. "{COMMON}"; pick_python 3.12'], capture_output=True, text=True,
                       env={"PATH": str(tmp_path / "bin"), **LIBPATH, **env}, timeout=30)
    return r.returncode, r.stdout.strip()


def test_pick_python(tmp_path):
    (tmp_path / "bin").mkdir()
    (tmp_path / "tools/bin").mkdir(parents=True)
    fake_python(tmp_path / "bin", "python3", (3, 10))
    assert pick(tmp_path, {"SCA_TOOLS_DIR": str(tmp_path / "tools")}) == (1, "")          # 只有 3.10 → 沒有
    fake_python(tmp_path / "bin", "python3.12", (3, 12))
    assert pick(tmp_path, {"SCA_TOOLS_DIR": str(tmp_path / "tools")}) == (0, str(tmp_path / "bin/python3.12"))
    t = fake_python(tmp_path / "tools/bin", "python3", (3, 12))                              # /opt/sca-tools/bin 優先
    assert pick(tmp_path, {"SCA_TOOLS_DIR": str(tmp_path / "tools")}) == (0, str(t))
    s = fake_python(tmp_path, "mypy", (3, 13))
    assert pick(tmp_path, {"SCA_TOOLS_DIR": str(tmp_path / "tools"), "SCA_PYTHON": str(s)}) == (0, str(s))
    old = fake_python(tmp_path, "old", (3, 11))                                              # SCA_PYTHON 太舊 → 往下找
    assert pick(tmp_path, {"SCA_TOOLS_DIR": str(tmp_path / "tools"), "SCA_PYTHON": str(old)}) == (0, str(t))


def test_board_import_sh_fails_clearly_without_python312(tmp_path):
    (tmp_path / "bin").mkdir()
    fake_python(tmp_path / "bin", "python3", (3, 10))
    for tool in ("timeout", "readlink", "dirname", "sed"):
        if shutil.which(tool):
            os.symlink(shutil.which(tool), tmp_path / "bin" / tool)
    rd = result_dir(tmp_path)
    r = subprocess.run([shutil.which("bash"), str(HERE.parents[2] / "tools/demo/board-import.sh"), "--result", str(rd),
                        "--kernel-modules-from", str(tmp_path), "--owner", OWNER], capture_output=True, text=True, timeout=60,
                       env={"PATH": str(tmp_path / "bin"), "SCA_TOOLS_DIR": str(tmp_path / "none")})
    assert r.returncode == 1 and r.stdout.startswith("D-kernel-modules\tFAIL\t") and "SCA_PYTHON" in r.stdout


def test_symlink_to_unreadable_dir_in_module_tree_is_gap(tmp_path, monkeypatch):
    """N1：模組資料夾裡的連結指到讀不到的資料夾（kernel/vend -> /opt/locked2，裡面有 hidden.ko）→ GAP，不寫。"""
    root = make_rootfs(tmp_path / "rootfs", initrd=None)
    (root / "opt/locked2").mkdir(parents=True)
    (root / "opt/locked2/hidden.ko").write_bytes(ko_bytes())
    os.symlink("/opt/locked2", root / f"lib/modules/{V}/kernel/vend")
    st, _, out = gen(tmp_path, root)
    assert "kernel/vend/hidden.ko" in load(out)[0]["modules_in_image"]          # 讀得到時照樣列
    make_unreadable(root / "opt/locked2", monkeypatch)
    try:
        st, detail, out = gen(tmp_path, root)
    finally:
        os.chmod(root / "opt/locked2", 0o755)
    assert st == "GAP" and "/opt/locked2" in detail and not out.exists()


def test_accepted_unread_initramfs_withholds_all_blocks(tmp_path):
    """N3：--accept-unread-initramfs 時擋住的模組可能就在沒讀到的 initramfs 裡：install 擋住行全部不放。"""
    root = make_rootfs(tmp_path / "rootfs", initrd="garbage")
    st, detail, out = gen(tmp_path, root, accept_unread_initramfs=True)
    doc, src = load(out)
    assert not any(ln.startswith("install ") for ln in doc["modprobe_d"])
    assert km.consumer_blocked(vx, doc["modprobe_d"], doc.get("modules_softdep"), {"bar", "qux"}) == {}
    assert "blacklist foo" in doc["modprobe_d"]                                   # blacklist 不證明什麼（K3），照放
    assert {(w["line"], w["because"]) for w in src["modprobe_d"]["withheld"]} == {
        ("install bar /bin/false", "initramfs not read"), ("install qux    /bin/true", "initramfs not read")}
    vx.check_kernel_modules(doc)


# ---------- PR #158 的消費端：modules_softdep、所有目錄的檔依檔名排序、/run 的同名檔 ----------

def consumer158():
    """PR #158 的 vex_export（modules_softdep、install_block）：main 已經有就用 main 的；否則從 origin/cra/k2-modprobe-fnmatch 讀（git show，
    不複製進 repo）；都沒有 → None（呼叫端測舊版消費端的行為）。"""
    if hasattr(vx, "SOFTDEP_HEADER"):
        return vx
    r = subprocess.run(["git", "-C", str(HERE), "show", "origin/cra/k2-modprobe-fnmatch:tools/cra/vex_export.py"],
                       capture_output=True, timeout=30)
    if r.returncode != 0:
        return None
    d = Path(os.environ.get("TMPDIR", "/tmp")) / f"vex158-{os.getpid()}"
    d.mkdir(exist_ok=True)
    f = d / "vex_export.py"
    f.write_bytes(r.stdout)
    import importlib.util
    spec = importlib.util.spec_from_file_location("vex_export_158", f)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_modules_softdep_round_trip_with_pr158_consumer(tmp_path, monkeypatch):
    c = consumer158()
    root = make_rootfs(tmp_path / "rootfs", initrd=None)
    if c is None:
        # 舊版消費端（不認得 modules_softdep）：不寫這個欄位，寫原因
        st, detail, out = gen(tmp_path, root)
        doc, src = load(out)
        assert "modules_softdep" not in doc and "modules_softdep" in " ".join(src["notes"])
        return
    monkeypatch.setitem(km._mods, "vx", c)
    st, detail, out = gen(tmp_path, root)
    doc, src = load(out)
    assert doc["modules_softdep"] == [km.SOFTDEP_HEADER, "softdep sd_mod pre: crc32"]
    c.check_kernel_modules(doc)                                                    # PR #158 的驗證
    _, inst, soft = c.modprobe_state(doc["modprobe_d"])
    assert c.install_block("bar", inst, soft + [c.kmod_pattern("sd_mod")]) == "install bar /bin/false"
    # modules.softdep 沒有 → 不寫欄位、寫 note；消費端就不認 install 的擋住
    (root / f"lib/modules/{V}/modules.softdep").unlink()
    st, detail, out = gen(tmp_path, root, replace=True)
    doc, src = load(out)
    assert "modules_softdep" not in doc and any("modules.softdep" in n for n in src["notes"])
    c.check_kernel_modules(doc)
    assert km.consumer_blocked(c, doc["modprobe_d"], doc.get("modules_softdep"), {"bar", "qux"}) == {}
    # 標頭不對（貼錯檔）→ 不寫，note
    (root / f"lib/modules/{V}/modules.softdep").write_text("softdep x pre: y\n")
    st, detail, out = gen(tmp_path, root, replace=True)
    assert "modules_softdep" not in load(out)[0] and "標頭" in detail
    # softdep 讓 install 失效（kmod v34 以前）：模組有 softdep 就不算被擋
    (root / f"lib/modules/{V}/modules.softdep").write_text(km.SOFTDEP_HEADER + "\nsoftdep bar pre: crc32\n")
    st, detail, out = gen(tmp_path, root, replace=True)
    doc = load(out)[0]
    c.check_kernel_modules(doc)
    assert set(km.consumer_blocked(c, doc["modprobe_d"], doc["modules_softdep"], {"bar", "qux"})) == {"qux"}


def test_unreadable_softdep_is_gap(tmp_path, monkeypatch):
    root = make_rootfs(tmp_path / "rootfs", initrd=None)
    f = root / f"lib/modules/{V}/modules.softdep"
    f.write_bytes(b"#" * (km.MAX_SMALL + 10))                                       # 太大，沒讀內容
    st, detail, out = gen(tmp_path, root)
    assert st == "GAP" and "modules.softdep" in detail and not out.exists()
    if os.geteuid() != 0:
        f.write_text(km.SOFTDEP_HEADER + "\n")
        f.chmod(0)
        try:
            st, detail, out = gen(tmp_path, root)
        finally:
            f.chmod(0o644)
        assert st == "GAP" and "modules.softdep" in detail and not out.exists()


def test_modprobe_order_is_by_file_name_across_dirs(tmp_path):
    root = make_rootfs(tmp_path / "rootfs", initrd=None)
    for d in ("etc/modprobe.d", "usr/lib/modprobe.d", "lib/modprobe.d"):
        for f in list((root / d).iterdir()):
            f.unlink()
    (root / "etc/modprobe.d/b.conf").write_text("blacklist from-etc-b\n")
    (root / "usr/lib/modprobe.d/a.conf").write_text("blacklist from-usrlib-a\n")
    (root / "lib/modprobe.d/c.conf").write_text("blacklist from-lib-c\n")
    (root / "usr/local/lib/modprobe.d").mkdir(parents=True)
    (root / "usr/local/lib/modprobe.d/b.conf").write_text("blacklist from-local-b\n")      # /etc 的 b.conf 蓋過
    (root / "lib/modprobe.d/a.conf").write_text("blacklist from-lib-a\n")                  # /usr/lib 的 a.conf 蓋過
    st, detail, out = gen(tmp_path, root)
    doc, src = load(out)
    assert doc["modprobe_d"] == ["blacklist from-usrlib-a", "blacklist from-etc-b", "blacklist from-lib-c"]
    assert {(o["file"], o["by"]) for o in src["modprobe_d"]["overridden"]} == {
        ("/usr/local/lib/modprobe.d/b.conf", "/etc/modprobe.d/b.conf"), ("/lib/modprobe.d/a.conf", "/usr/lib/modprobe.d/a.conf")}


def test_run_same_name_file_makes_lower_blocks_unprovable(tmp_path):
    root = make_rootfs(tmp_path / "rootfs", initrd=None)
    (root / "run/modprobe.d").mkdir(parents=True)
    (root / "run/modprobe.d/z.conf").write_text("options x y=1\n")                       # 同名：/lib/modprobe.d/z.conf
    (root / "run/modprobe.d/blk.conf").write_text("\n")                                  # 同名但 /etc 優先：不影響
    st, detail, out = gen(tmp_path, root)
    doc, src = load(out)
    assert "install qux    /bin/true" not in doc["modprobe_d"] and "blacklist   zed" in doc["modprobe_d"]
    assert "install bar /bin/false" in doc["modprobe_d"]
    assert [(w["line"], w["file"]) for w in src["modprobe_d"]["withheld"]] == [("install qux    /bin/true", "/lib/modprobe.d/z.conf")]
    assert "/run/modprobe.d" in src["modprobe_d"]["withheld"][0]["because"] and "/lib/modprobe.d/z.conf" in " ".join(src["notes"])


def test_modprobe_d_elements_are_physical_lines(tmp_path):
    """每個 modprobe_d 元素是一個實體行：續行不接起來（反斜線照留，消費端因此不認 install 的擋住）、沒有 LF、沒有 CR。"""
    root = make_rootfs(tmp_path / "rootfs", initrd=None)
    (root / "etc/modprobe.d/cont.conf").write_text("install cont \\\n   /bin/false\n# comment \\\ninstall hid /bin/false\n")
    st, detail, out = gen(tmp_path / "a", root)
    doc, src = load(out)
    md = doc["modprobe_d"]
    assert all("\n" not in x and "\r" not in x for x in md)
    i = md.index("install cont \\")
    assert md[i + 1:i + 4] == ["/bin/false", "# comment \\", "install hid /bin/false"]
    for c in [x for x in (vx, consumer158()) if x is not None]:    # main 的消費端與 #158 的（有的話）
        c.check_kernel_modules(doc)
        b = km.consumer_blocked(c, md, doc.get("modules_softdep"), {"cont", "hid", "bar"})
        assert "cont" not in b                    # 續行：不算被擋（兩版的消費端都一樣）
        if hasattr(c, "install_block"):
            assert b == {}                        # #158：清單裡有反斜線 → install 一律不算被擋
    # 行中間的 CR：不輸出 CR（換成空白），擋住行全部不放
    (root / "etc/modprobe.d/cont.conf").write_text("install crx\r/bin/false\n")
    st, detail, out = gen(tmp_path / "b", root)
    doc, src = load(out)
    assert all("\r" not in x and "\n" not in x for x in doc["modprobe_d"]) and "install crx /bin/false" not in doc["modprobe_d"]
    assert not any(x.startswith("install ") and x.split()[-1] in vx.BLOCK_CMDS for x in doc["modprobe_d"])
    assert {w["because"] for w in src["modprobe_d"]["withheld"]} == {"a modprobe.d file has a carriage return inside a line"}
    vx.check_kernel_modules(doc)


# ---------- 第三輪審查：不放的行不能讓別的模組變成被擋（W） ----------

def w_rootfs(tmp_path, confs, run=None, initrd_mods=()):
    """只有 m1、n1、x1 三個模組與指定的 modprobe.d 的 rootfs（modules.softdep 只有標頭）。"""
    root = tmp_path / "w"
    for m in ("m1", "n1", "x1"):
        (root / f"lib/modules/{V}/kernel").mkdir(parents=True, exist_ok=True)
        (root / f"lib/modules/{V}/kernel/{m}.ko").write_bytes(ko_bytes())
    (root / f"lib/modules/{V}/modules.builtin").write_text("kernel/b.ko\n")
    (root / f"lib/modules/{V}/modules.softdep").write_text(km.SOFTDEP_HEADER + "\n")
    for rel, text in confs.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)
    for rel, text in (run or {}).items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)
    (root / "boot").mkdir()
    if initrd_mods:
        (root / "boot/initrd").write_bytes(gzip.compress(cpio([(f"usr/lib/modules/{V}/kernel/{m}.ko", b"x") for m in initrd_mods])))
    return root


def blocked_set(doc, lines=None):
    return set(km.consumer_blocked(vx, doc["modprobe_d"] if lines is None else lines, doc.get("modules_softdep"), {"m1", "n1", "x1"}))


def before_lines(src):
    """拿掉之前的 modprobe_d（留下的＋不放的，依來源檔名排序；同一個檔裡依原本的順序）。"""
    rows = src["modprobe_d"]["lines"] + [{"line": w["line"], "file": w["file"]} for w in src["modprobe_d"]["withheld"]]
    order = {}
    for f in src["modprobe_d"]["files"]:
        order[f["file"]] = f["file"].rsplit("/", 1)[-1]
    return [r["line"] for r in sorted(rows, key=lambda r: order.get(r["file"], r["file"]))]


def test_w1_uncertain_pattern_line_is_not_withheld(tmp_path):
    """a.conf install m1 /bin/true、b.conf install x[1] /bin/true、c.conf install n1 /bin/true；initrd 有 m1、沒擋。
    以前會連 x[1] 一起拿掉，n1 就變成被擋。"""
    root = w_rootfs(tmp_path, {"usr/lib/modprobe.d/a.conf": "install m1 /bin/true\n",
                               "usr/lib/modprobe.d/b.conf": "install x[1] /bin/true\n",
                               "usr/lib/modprobe.d/c.conf": "install n1 /bin/true\n"}, initrd_mods=("m1",))
    st, detail, out = gen(tmp_path, root)
    doc, src = load(out)
    vx.check_kernel_modules(doc)
    assert [w["line"] for w in src["modprobe_d"]["withheld"]] == ["install m1 /bin/true"]
    assert "install x[1] /bin/true" in doc["modprobe_d"]
    before = blocked_set(doc, before_lines(src))
    assert before == {"m1"} and blocked_set(doc) <= before and "n1" not in blocked_set(doc)


def test_w2_backslash_line_in_shadowed_file_is_not_withheld(tmp_path):
    root = w_rootfs(tmp_path, {"usr/lib/modprobe.d/r.conf": "install x\\y /bin/true\n",
                               "usr/lib/modprobe.d/s.conf": "install n1 /bin/true\n"},
                    run={"run/modprobe.d/r.conf": "options z a=1\n"})
    st, detail, out = gen(tmp_path, root)
    doc, src = load(out)
    vx.check_kernel_modules(doc)
    assert "install x\\y /bin/true" in doc["modprobe_d"] and src["modprobe_d"]["withheld"] == []
    assert blocked_set(doc, before_lines(src)) == set() and blocked_set(doc) == set()


def test_guard_falls_back_to_withholding_every_block():
    """逐模組拿掉後有模組變成被擋（假的消費端行為：以拿掉前後比較）→ 全部的擋住行都不放，寫 note。"""
    lines = ["install m1 /bin/true", "install n1 /bin/true"]
    src = [{"line": x, "file": "/etc/modprobe.d/a.conf"} for x in lines]

    class Fake:
        BLOCK_CMDS, norm_module = vx.BLOCK_CMDS, staticmethod(vx.norm_module)
        kmod_pattern = staticmethod(vx.kmod_pattern)

        @staticmethod
        def modprobe_state(ls):
            return set(), list(ls), []
    real = km.consumer_blocked
    try:
        # 拿掉前：只有 m1 被擋；拿掉 m1 的行之後：n1 被擋（模擬「新產生的擋住」）
        km.consumer_blocked = lambda c, ls, sd, names: ({"m1": "x"} if len(ls) == 2 else {"n1": "y"} if len(ls) == 1 else {})
        notes = []
        kl, ks, wh = km.guarded_withhold(lines, src, Fake, [km.SOFTDEP_HEADER], {"m1", "n1"}, notes, drop={"m1": "r"})
    finally:
        km.consumer_blocked = real
    assert kl == [] and {w["because"] for w in wh} == {km.GUARD_REASON} and notes


def test_withholding_never_creates_a_block_property():
    """隨機的小 modprobe_d 與隨機的 drop／file_reason／all_reason：拿掉之後被擋的模組 ⊆ 拿掉之前的（消費端自己的判定）。"""
    import random
    rnd = random.Random(158)
    pats = ["m1", "n1", "x1", "m*", "*1", "x[1]", "x\\y", "n?", "[mn]1", "m-1", "*"]
    cmds = ["/bin/true", "/bin/false", "/sbin/modprobe --ignore-install", "true", "/usr/bin/false"]
    names = {"m1", "n1", "x1", "m_1"}
    files = ["/etc/modprobe.d/a.conf", "/usr/lib/modprobe.d/b.conf", "/lib/modprobe.d/c.conf"]
    for _ in range(3000):
        lines, srcs = [], []
        for _ in range(rnd.randint(1, 6)):
            k = rnd.random()
            ln = (f"install {rnd.choice(pats)} {rnd.choice(cmds)}" if k < 0.75 else
                  f"softdep {rnd.choice(pats)} pre: crc32" if k < 0.85 else f"blacklist {rnd.choice(pats)}")
            lines.append(ln)
            srcs.append({"line": ln, "file": rnd.choice(files)})
        softdep = rnd.choice([None, [km.SOFTDEP_HEADER], [km.SOFTDEP_HEADER, "softdep m1 pre: crc32"]])
        drop = {m: "d" for m in names if rnd.random() < 0.3}
        fr = {f: "f" for f in files if rnd.random() < 0.3}
        allr = "a" if rnd.random() < 0.1 else None
        before = set(km.consumer_blocked(vx, lines, softdep, names))
        kl, ks, wh = km.guarded_withhold(lines, srcs, vx, softdep, names, [], drop, fr, allr)
        after = set(km.consumer_blocked(vx, kl, softdep, names))
        assert after <= before, (lines, drop, fr, allr, softdep, kl)
        assert len(kl) + len(wh) == len(lines)


# ---------- 只有 ELF 可重定位檔才算模組（真實的 Jetson 映像：文件的 COPYING.*.ko.gz、vim 的 tutor.ko） ----------

def add_non_modules(root):
    """真實映像裡名稱是 .ko* 卻不是模組的檔，與真的 ELF 模組（資料夾內、外）。"""
    root = Path(root)

    def w(rel, data):
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    doc = "usr/share/doc/nvidia-l4t-kernel-openrm/"
    w(doc + "COPYING.nvidia-uvm.ko.gz", gzip.compress(b"GNU GENERAL PUBLIC LICENSE\n" * 50))
    w(doc + "LICENSE.nvidia.ko.gz", gzip.compress(b"MIT License\n"))
    w(doc + "README.nvidia-drm.ko.gz", gzip.compress(b""))                         # 空的 gzip
    w("usr/share/vim/vim91/tutor/tutor.ko", "===== 빔 길잡이 =====\n".encode())      # vim 的韓文教學
    w("usr/share/x/so.ko", ELF_REL[:16] + (3).to_bytes(2, "little") + ELF_REL[18:])  # ELF 但是 ET_DYN
    w(f"usr/lib/modules/{V}/kernel/README.ko", b"not a module\n")                    # 模組資料夾裡的文字檔
    w(f"usr/lib/modules/{V}/kernel/foo.ko", ELF_REL)                                # 真的模組（未壓縮）
    w(f"usr/lib/modules/{V}/kernel/foo2.ko.gz", gzip.compress(ELF_REL + b"\0" * 4096))
    w(f"usr/lib/modules/{V}/kernel/be.ko.xz", lzma.compress(b"\x7fELF\x02\x02\x01" + b"\0" * 9 + (1).to_bytes(2, "big") + b"\0" * 46))
    w("opt/vendor/oot/vend.ko", ELF_REL)                                            # 模組資料夾以外的真模組
    return root


def test_non_elf_ko_files_are_ignored_and_noted(tmp_path):
    root = add_non_modules(make_rootfs(tmp_path / "rootfs", initrd=None))
    st, detail, out = gen(tmp_path, root)
    assert st == "ATTENTION", detail
    doc, src = load(out)
    allm = doc["modules_in_image"] + doc["modules_outside_dirs"]
    for bad in ("COPYING", "LICENSE", "README", "tutor", "so.ko"):
        assert not any(bad in m for m in allm), bad
    assert {"kernel/foo.ko", "kernel/foo2.ko.gz", "kernel/be.ko.xz"} <= set(doc["modules_in_image"])   # ELF ET_REL（含 big endian）
    assert doc["modules_outside_dirs"] == ["/opt/vendor/oot/vend.ko", "/usr/src/linux-headers/junk.ko"]
    ig = src["modules"]["ignored_non_module_files"]
    assert ig["count"] == 6 and ig["in_module_dirs"] == 1
    paths = {e["path"]: e["why"] for e in ig["examples"]}
    assert "/usr/share/vim/vim91/tutor/tutor.ko" in paths and "not ELF" in paths["/usr/share/vim/vim91/tutor/tutor.ko"]
    assert "ET_REL" in paths["/usr/share/x/so.ko"] and "e_type 3" in paths["/usr/share/x/so.ko"]
    assert f"/usr/lib/modules/{V}/kernel/README.ko" in paths
    assert "empty" in paths["/usr/share/doc/nvidia-l4t-kernel-openrm/README.nvidia-drm.ko.gz"]
    # 模組資料夾以外的（文件、tutor.ko）只寫進 info；模組資料夾裡的 README.ko 寫進 notes（ATTENTION）
    assert any("ignored_non_module_files" in n and "tutor.ko" in n for n in src["info"])
    assert not any("tutor.ko" in n for n in src["notes"])
    assert any("ignored_non_module_files" in n and "kernel/README.ko" in n for n in src["notes"])
    vx.check_kernel_modules(doc)


def test_non_module_files_outside_dirs_are_info_only(tmp_path):
    """模組資料夾以外不是模組的 .ko*：只是 info，不改變狀態（notes 與沒有這些檔時一樣）。"""
    base = make_rootfs(tmp_path / "a", initrd=None)
    st0, _, out0 = gen(tmp_path / "x", base)
    notes0 = load(out0)[1]["notes"]
    root = make_rootfs(tmp_path / "b", initrd=None)
    (root / "usr/share/doc/nvidia-l4t-kernel-openrm").mkdir(parents=True)
    (root / "usr/share/doc/nvidia-l4t-kernel-openrm/COPYING.nvidia-uvm.ko.gz").write_bytes(gzip.compress(b"GPL\n"))
    (root / "usr/share/vim/vim91/tutor").mkdir(parents=True)
    (root / "usr/share/vim/vim91/tutor/tutor.ko").write_bytes("빔\n".encode())
    st, _, out = gen(tmp_path / "y", root)
    doc, src = load(out)
    assert st == st0 and [n for n in src["notes"]] == [n.replace(str(tmp_path / "a"), str(tmp_path / "b")) for n in notes0]
    assert len(src["info"]) == 1 and "tutor.ko" in src["info"][0] and "COPYING.nvidia-uvm.ko.gz" in src["info"][0]
    assert src["modules"]["ignored_non_module_files"] == {"count": 2, "in_module_dirs": 0, "examples": [
        {"path": "/usr/share/doc/nvidia-l4t-kernel-openrm/COPYING.nvidia-uvm.ko.gz", "why": "not ELF (starts with 47504c0a)"},
        {"path": "/usr/share/vim/vim91/tutor/tutor.ko", "why": "not ELF (starts with " + "빔\n".encode().hex() + ")"}]}


def test_non_module_file_inside_module_dir_is_attention(tmp_path):
    root = make_rootfs(tmp_path / "rootfs", initrd=None)
    (root / f"usr/lib/modules/{V}/kernel/README.ko").write_bytes(b"text\n")
    st, detail, out = gen(tmp_path, root, loaded=["nvgpu"], loaded_from="lsmod file t")
    src = load(out)[1]
    assert st == "ATTENTION" and any("kernel/README.ko" in n for n in src["notes"]) and src["info"] == []
    assert "kernel/README.ko" not in load(out)[0]["modules_in_image"]


def test_ko_symlinks_outside_module_dirs(tmp_path):
    """模組資料夾以外名稱是 .ko* 的連結：目標是 ELF 模組 → 以連結的路徑列；目標不是模組 → 不列（info）；
    目標不在映像裡 → 判斷不了，照樣列（unchecked）；tar 輸入時目標名稱不是 .ko* → 判斷不了，照樣列。"""
    root = make_rootfs(tmp_path / "rootfs", initrd=None)
    v = root / "opt/v"
    v.mkdir(parents=True)
    (v / "blob.bin").write_bytes(ELF_REL)
    (v / "notes.txt").write_bytes(b"hello\n")
    os.symlink("blob.bin", v / "linked.ko")
    os.symlink("/opt/v/notes.txt", v / "text.ko")
    os.symlink("/nowhere/x.bin", v / "dangling.ko")
    os.symlink("/opt/v", root / "opt/dir.ko")                      # 名稱是 .ko 的資料夾連結：不是模組
    st, detail, out = gen(tmp_path, root)
    doc, src = load(out)
    od = doc["modules_outside_dirs"]
    assert "/opt/v/linked.ko" in od and "/opt/v/dangling.ko" in od
    assert "/opt/v/text.ko" not in od and "/opt/dir.ko" not in od
    un = {e["path"] for e in src["modules"]["unchecked_module_files"]["examples"]}
    assert "/opt/v/dangling.ko" in un and "/opt/v/linked.ko" not in un
    assert any("/opt/v/text.ko" in n for n in src["info"])
    vx.check_kernel_modules(doc)
    d2, s2 = load(gen(tmp_path, to_tar(root, tmp_path / "r.tar"), replace=True)[2])
    assert {"/opt/v/linked.ko", "/opt/v/text.ko", "/opt/v/dangling.ko"} <= set(d2["modules_outside_dirs"])
    assert {"/opt/v/linked.ko", "/opt/v/text.ko"} <= {e["path"] for e in s2["modules"]["unchecked_module_files"]["examples"]}


def test_non_elf_ko_files_ignored_in_tar_and_hardlinks(tmp_path):
    """tar（串流讀）也一樣；硬連結沿用目標的判斷。"""
    root = add_non_modules(make_rootfs(tmp_path / "rootfs", initrd=None))
    doc = root / "usr/share/doc/nvidia-l4t-kernel-openrm"
    os.link(doc / "COPYING.nvidia-uvm.ko.gz", doc / "COPYING.copy.ko.gz")
    os.link(root / "opt/vendor/oot/vend.ko", root / "opt/vendor/oot/vend-hl.ko")
    tar = to_tar(root, tmp_path / "rootfs.tar")
    st, detail, out = gen(tmp_path, tar)
    d, src = load(out)
    assert not any("COPYING" in m or "tutor" in m for m in d["modules_in_image"] + d["modules_outside_dirs"])
    assert {"/opt/vendor/oot/vend.ko", "/opt/vendor/oot/vend-hl.ko"} <= set(d["modules_outside_dirs"])
    assert "kernel/foo2.ko.gz" in d["modules_in_image"]
    assert src["modules"]["ignored_non_module_files"]["count"] == 7


def test_ko_verdict_unit():
    def op(b):
        return lambda: io.BytesIO(b)
    assert km.ko_verdict(op(ELF_REL), len(ELF_REL))[0] == "module"
    assert km.ko_verdict(op(gzip.compress(ELF_REL)), 0)[0] == "module"
    assert km.ko_verdict(op(lzma.compress(ELF_REL)), 0)[0] == "module"
    assert km.ko_verdict(op(b"hello"), 5)[0] == "not_module"
    assert km.ko_verdict(op(gzip.compress(b"text")), 0)[0] == "not_module"
    # 開頭在 1 MB 之後才出現的 gzip 輸出：只讀到上限，不解整個檔；判斷不了 → unknown
    big = b"\x1f\x8b" + b"\0" * (2 << 20)
    assert km.ko_verdict(op(big), len(big))[0] == "unknown"

    def boom():
        raise PermissionError(13, "Permission denied")
    assert km.ko_verdict(boom, 10) == ("unknown", "cannot open (Permission denied)")
    assert km.ko_verdict(None, 0)[0] == "unknown"
    # 解壓輸出有上限（KO_HEAD）：壓縮炸彈只解出開頭
    bomb = gzip.compress(ELF_REL + b"\0" * (64 << 20))
    assert km.ko_verdict(op(bomb), len(bomb))[0] == "module"


def test_undecompressable_or_unreadable_ko_stays_listed(tmp_path, monkeypatch):
    root = make_rootfs(tmp_path / "rootfs", initrd=None)
    md = root / "usr/lib/modules" / V / "kernel"
    md.mkdir(parents=True, exist_ok=True)
    (md / "broken.ko.gz").write_bytes(b"\x1f\x8b\x08\x00" + b"\xff" * 64)            # gzip 魔數，內容損毀
    (md / "trunc.ko.xz").write_bytes(lzma.compress(ELF_REL)[:20])                    # 截斷（還沒有輸出）
    (md / "nodec.ko.zst").write_bytes(ko_bytes("x.ko.zst"))
    (root / "opt/vendor").mkdir(parents=True, exist_ok=True)
    (root / "opt/vendor/broken-out.ko.gz").write_bytes(b"\x1f\x8b\x08\x00" + b"\xff" * 64)
    locked = md / "locked.ko"
    locked.write_bytes(b"not elf")
    os.chmod(locked, 0)
    monkeypatch.setattr(km, "zstd_decoder", lambda: None)          # 沒有 zstd 解壓程式
    try:
        st, detail, out = gen(tmp_path, root)
    finally:
        os.chmod(locked, 0o644)
    doc, src = load(out)
    for m in ("kernel/broken.ko.gz", "kernel/trunc.ko.xz", "kernel/nodec.ko.zst"):
        assert m in doc["modules_in_image"], m
    if os.geteuid() != 0:                                          # root 讀得到 0 權限的檔（內容不是 ELF → 不列）
        assert "kernel/locked.ko" in doc["modules_in_image"]
    assert "/opt/vendor/broken-out.ko.gz" in doc["modules_outside_dirs"]
    un = {e["path"]: e["why"] for e in src["modules"]["unchecked_module_files"]["examples"]}
    assert "zstd" in un[f"/usr/lib/modules/{V}/kernel/nodec.ko.zst"]
    assert f"/usr/lib/modules/{V}/kernel/broken.ko.gz" in un and f"/usr/lib/modules/{V}/kernel/trunc.ko.xz" in un
    assert st == "ATTENTION" and any("unchecked_module_files" in n for n in src["notes"])


def test_loaded_module_outside_dirs_is_not_a_contradiction(tmp_path):
    root = add_non_modules(make_rootfs(tmp_path / "rootfs", initrd=None))
    st, detail, out = gen(tmp_path, root, loaded=["vend", "nvgpu"], loaded_from="lsmod file t")
    assert st == "ATTENTION", detail
    doc = load(out)[0]
    assert doc["loaded"] == ["nvgpu", "vend"] and "/opt/vendor/oot/vend.ko" in doc["modules_outside_dirs"]
    vx.check_kernel_modules(doc)
    # tutor.ko（不是模組）有載入 → 矛盾（GAP）
    st, detail, _ = gen(tmp_path, root, loaded=["tutor"], loaded_from="lsmod file t", replace=True)
    assert st == "GAP" and "tutor" in detail
