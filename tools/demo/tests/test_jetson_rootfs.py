import io
import json
import lzma
import os
import shutil
import sys
import tarfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import jetson_rootfs as jr  # noqa: E402


def tar_bytes(entries, mode="w"):
    """entries: [(名稱, 內容 bytes | ('dir',) | ('sym', 目標) | ('lnk', 目標))]"""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as t:
        for name, v in entries:
            ti = tarfile.TarInfo(name)
            if isinstance(v, bytes):
                ti.size = len(v)
                t.addfile(ti, io.BytesIO(v))
                continue
            if v[0] == "dir":
                ti.type, ti.mode = tarfile.DIRTYPE, 0o755
            elif v[0] == "sym":
                ti.type, ti.linkname = tarfile.SYMTYPE, v[1]
            else:
                ti.type, ti.linkname = tarfile.LNKTYPE, v[1]
            t.addfile(ti)
    return buf.getvalue()


def ar(members):
    out = b"!<arch>\n"
    for name, data in members:
        h = f"{name:<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(data):<10}".encode() + b"`\n"
        out += h + data + (b"\n" if len(data) & 1 else b"")
    return out


def deb(pkg, ver, arch, files, data_comp="xz", multiarch=None):
    ctl = f"Package: {pkg}\nVersion: {ver}\nArchitecture: {arch}\nMaintainer: x <x@example.invalid>\n"
    if multiarch:
        ctl += f"Multi-Arch: {multiarch}\n"
    ctl += "Description: test\n long line\n"
    control = tar_bytes([("./", ("dir",)), ("./control", ctl.encode()), ("./md5sums", b"0  usr/bin/x\n")], "w:gz")
    data = tar_bytes(files)
    if data_comp == "xz":
        data, dname = lzma.compress(data), "data.tar.xz"
    elif data_comp == "zst":
        try:
            from compression import zstd  # Python 3.14
            data = zstd.compress(data)
        except ImportError:
            import subprocess
            data = subprocess.run(["zstd", "-q", "-c"], input=data, stdout=subprocess.PIPE, check=True).stdout
        dname = "data.tar.zst"
    else:
        dname = "data.tar"
    return ar([("debian-binary", b"2.0\n"), ("control.tar.gz", control), (dname, data)])


BASE_STATUS = (b"Package: libc6\nStatus: install ok installed\nArchitecture: arm64\nVersion: 2.39-0ubuntu8\n\n"
               b"Package: nvidia-l4t-core\nStatus: install ok installed\nArchitecture: arm64\nVersion: 0.0-old\n")


def rootfs(usrmerge=True):
    e = [("./", ("dir",)), ("./usr/", ("dir",)), ("./usr/lib/", ("dir",)), ("./usr/bin/", ("dir",)), ("./usr/sbin/", ("dir",)),
         ("./etc/", ("dir",)), ("./etc/conf", b"base\n"), ("./etc/os-release", b"ID=ubuntu\nVERSION_ID=\"24.04\"\n"),
         ("./etc/conf-link", ("lnk", "./etc/conf")), ("./usr/bin/sh", b"sh"), ("./usr/bin/sh2", ("lnk", "./usr/bin/sh")),
         ("./opt/", ("dir",)),
         ("./var/", ("dir",)), ("./var/lib/", ("dir",)), ("./var/lib/dpkg/", ("dir",)), ("./var/lib/dpkg/status", BASE_STATUS),
         ("./var/lib/dpkg/info/", ("dir",)), ("./var/lib/dpkg/info/nvidia-l4t-kernel.list", b"/old\n"),
         ("./var/lib/dpkg/info/nvidia-l4t-kernel.conffiles", b"/etc/old\n"), ("./var/lib/dpkg/info/libc6.list", b"/libc\n")]
    if usrmerge:
        e[1:1] = [("./bin", ("sym", "usr/bin")), ("./lib", ("sym", "usr/lib")), ("./sbin", ("sym", "usr/sbin"))]
    else:
        e[1:1] = [("./lib/", ("dir",))]
    return tar_bytes(e, "w:bz2")


def bsp(extra=()):
    core = deb("nvidia-l4t-core", "39.2.1-20260801", "arm64", [
        ("./", ("dir",)), ("./lib/", ("dir",)), ("./lib/firmware/", ("dir",)), ("./lib/firmware/nv.bin", b"fw"),
        ("./etc/", ("dir",)), ("./etc/conf", b"nvidia\n"), ("./usr/", ("dir",)), ("./usr/bin/", ("dir",)),
        ("./usr/bin/tool", b"tool"), ("./usr/bin/tool2", ("lnk", "./usr/bin/tool")), ("./usr/lib/libx.so", ("sym", "libx.so.1")),
        ("./usr/share/doc/nvidia-l4t-core/copyright", b"Copyright NVIDIA\n"), ("../evil", b"x"),
        ("./usr/bin/dangling", ("lnk", "./usr/bin/missing"))], multiarch="same")
    kern = deb("nvidia-l4t-kernel", "6.8.12-tegra-39.2.1", "arm64", [("./boot/", ("dir",)), ("./boot/Image", b"k")], data_comp="plain")
    host = deb("host-tool", "1", "amd64", [("./usr/bin/h", b"h")])
    return tar_bytes([("Linux_for_Tegra/nv_tegra/l4t_deb_packages/nvidia-l4t-core_39.2.1_arm64.deb", core),
                      ("Linux_for_Tegra/nv_tegra/l4t_deb_packages/host-tool_1_amd64.deb", host),
                      ("Linux_for_Tegra/kernel/nvidia-l4t-kernel_39.2.1_arm64.deb", kern),
                      ("Linux_for_Tegra/tools/ignored_1_arm64.deb", core),
                      ("Linux_for_Tegra/nv_tegra/l4t_deb_packages/sub/nested_1_arm64.deb", core),
                      *extra], "w:bz2")


def run(tmp_path, root=None, b=None):
    (tmp_path / "bsp.tbz2").write_bytes(b or bsp())
    (tmp_path / "rootfs.tbz2").write_bytes(root or rootfs())
    w = tmp_path / "w"
    w.mkdir()
    jr.main(["--bsp", str(tmp_path / "bsp.tbz2"), "--rootfs", str(tmp_path / "rootfs.tbz2"), "--work", str(w),
             "--out-base", str(tmp_path / "base.tar"), "--out-custom", str(tmp_path / "custom.tar"),
             "--report", str(tmp_path / "prep.json")])
    return json.loads((tmp_path / "prep.json").read_text(encoding="utf-8")), w


def contents(path):
    with tarfile.open(path) as t:
        names = [jr.norm(m.name) for m in t.getmembers()]
        files = {jr.norm(m.name): t.extractfile(m).read() for m in t.getmembers() if m.isfile()}
        kinds = {jr.norm(m.name): m.type for m in t.getmembers()}
    return names, files, kinds


def test_base_and_custom(tmp_path):
    rep, w = run(tmp_path)
    names, files, kinds = contents(tmp_path / "base.tar")
    assert len(names) == len(set(names)), "每個路徑只寫一次"
    assert files["usr/lib/firmware/nv.bin"] == b"fw"           # usrmerge：lib/ → usr/lib/
    assert not any(n.startswith("lib/") for n in names)
    assert kinds["lib"] == tarfile.SYMTYPE
    assert files["etc/conf"] == b"nvidia\n"                    # 套件取代 rootfs 的檔案
    assert files["usr/bin/tool2"] == b"tool"                   # 套件的硬連結改成一般檔案
    assert kinds["usr/lib/libx.so"] == tarfile.SYMTYPE
    assert "etc/conf-link" not in names                        # 硬連結的目標被取代：不寫
    assert kinds["usr/bin/sh2"] == tarfile.LNKTYPE             # 其他硬連結照舊
    assert "evil" not in names and not any(".." in n for n in names)
    st = files["var/lib/dpkg/status"].decode()
    assert "Package: nvidia-l4t-core\nStatus: install ok installed\n" in st
    assert "0.0-old" not in st and "Version: 39.2.1-20260801" in st and "Package: nvidia-l4t-kernel" in st
    assert "Package: libc6" in st and " long line" in st and "host-tool" not in st and "acme" not in st
    assert "var/lib/dpkg/info/nvidia-l4t-core:arm64.list" in files     # Multi-Arch: same
    assert b"/lib/firmware/nv.bin" in files["var/lib/dpkg/info/nvidia-l4t-core:arm64.list"]   # .list 記 deb 原本的路徑
    assert "var/lib/dpkg/info/nvidia-l4t-kernel.list" in files
    assert not any("acme" in n or "dist-info" in n for n in names)

    cnames, cfiles, _ = contents(tmp_path / "custom.tar")
    assert len(cnames) == len(set(cnames))
    assert set(names) - {"var/lib/dpkg/status"} <= set(cnames)
    cst = cfiles["var/lib/dpkg/status"].decode()
    assert "Package: acme-inspector" in cst and "Version: 39.2.1-20260801" in cst
    meta = [n for n in cfiles if n.endswith(".dist-info/METADATA")]
    assert meta and b"Version: 10.0.0" in cfiles[meta[0]]
    for n in cnames:  # 父資料夾都在
        if "/" in n:
            parent = n.rsplit("/", 1)[0]
            assert parent in cnames or parent.split("/")[0] in ("lib", "bin", "sbin"), n

    assert rep["dpkg_status"] == {"base_packages": 2, "replaced": 1, "added": 1, "custom_added": ["acme-inspector 1.0.0"]}
    assert [d["package"] for d in rep["debs"]] == ["nvidia-l4t-core", "nvidia-l4t-kernel"]
    assert rep["deb_skipped_arch"] == ["host-tool 1 amd64"]
    assert rep["rootfs_files_replaced_by_debs"] == 1
    assert any("../evil" in x for x in rep["skipped_members"])
    assert rep["usrmerge_links"]["lib"] == "usr/lib"
    assert rep["inputs"]["bsp"]["sha256"] and rep["outputs"]["custom"]["sha256"]
    assert os.listdir(w) == []                                 # 暫存清掉
    assert files["var/lib/dpkg/info/nvidia-l4t-kernel.list"] != b"/old\n"      # 舊的 dpkg 紀錄換掉
    assert "var/lib/dpkg/info/nvidia-l4t-kernel.conffiles" not in names and files["var/lib/dpkg/info/libc6.list"] == b"/libc\n"
    assert rep["rootfs_dpkg_info_replaced"] == 2
    assert "usr/bin/dangling" not in names and any("dangling" in x for x in rep["skipped_members"])


def test_not_usrmerge(tmp_path):
    with pytest.raises(SystemExit, match="usrmerge"):
        run(tmp_path, root=rootfs(usrmerge=False))
    assert not (tmp_path / "base.tar").exists() and not (tmp_path / "custom.tar").exists()   # 失敗時不留半成品
    assert os.listdir(tmp_path / "w") == []


def test_bad_package_name_and_ar_size(tmp_path):
    evil = deb("../../etc/evil", "1", "arm64", [("./x", b"x")])
    neg = ar([("debian-binary", b"2.0\n")]) + b"control.tar.gz  0           0     0     100644  -60       `\n"
    rep, _ = run(tmp_path, b=bsp(extra=[("Linux_for_Tegra/kernel/evil_1_arm64.deb", evil),
                                         ("Linux_for_Tegra/kernel/neg_1_arm64.deb", neg)]))
    errs = " ".join(rep["deb_errors"])
    assert "evil_1_arm64.deb" in errs and "不合法" in errs and "neg_1_arm64.deb: ar 成員大小不合理" in errs
    names, _, _ = contents(tmp_path / "base.tar")
    assert not any("evil" in n for n in names)


def test_no_debs(tmp_path):
    with pytest.raises(SystemExit, match="沒有可用"):
        run(tmp_path, b=tar_bytes([("Linux_for_Tegra/README", b"x")], "w:bz2"))


def test_bad_deb_recorded(tmp_path):
    rep, _ = run(tmp_path, b=bsp(extra=[("Linux_for_Tegra/kernel/broken_1_arm64.deb", b"not an ar file")]))
    assert rep["deb_errors"] and rep["deb_errors"][0].startswith("broken_1_arm64.deb")


@pytest.mark.skipif(not shutil.which("zstd") and sys.version_info < (3, 14), reason="沒有 zstd 指令，也不是 Python 3.14")
def test_zstd(tmp_path):
    z = deb("zz", "1", "all", [("./usr/share/zz", b"z")], data_comp="zst")
    rep, _ = run(tmp_path, b=bsp(extra=[("Linux_for_Tegra/kernel/zz_1_all.deb", z)]))
    _, files, _ = contents(tmp_path / "base.tar")
    assert files["usr/share/zz"] == b"z" and "zz" in [d["package"] for d in rep["debs"]]


def test_merge_status_and_norm():
    t, (r, n) = jr.merge_status("Package: a\nArchitecture: all\nVersion: 1\n", [[("Package", "a"), ("Architecture", "all"), ("Version", "2")],
                                                                              [("Package", "b"), ("Architecture", "all")]])
    assert (r, n) == (1, 1) and "Version: 2" in t and "Package: b" in t
    assert jr.norm("./a/./b/") == "a/b" and jr.norm("/x") == "x" and jr.norm("a/../b") is None and jr.norm("./") == ""
    assert jr.usr_rewrite("lib/x") == "usr/lib/x" and jr.usr_rewrite("lib") == "usr/lib" and jr.usr_rewrite("libfoo/x") == "libfoo/x"
