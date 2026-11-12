"""C-kernel-config（lib/kernel_config.py）、tools/mirror/kernel-cve.sh、deploy 的 kernel-cve-mirror.sh 與 mirror-sync.sh kernel-cve、
scan-flash-package.sh --rescan-from。

紀錄的形狀取自 2026-11-02 的 vulns.git（cve/published/2024/CVE-2024-26600.json：containers.cna.affected[].programFiles）；
Grype 與核心對應摘要的形狀取自 round14 Jetson R39.2.1 基礎版（run 41376872500）；headers 的配置（/usr/src/linux-headers-<版本>/3rdparty/
canonical/linux-noble/、/lib/modules/<版本>/build 連結）取自 NVIDIA 公開的 nvidia-l4t-kernel-headers 與 nvidia-l4t-kernel 39.2.1。
"""
import datetime
import getpass
import gzip
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

PILOT = Path(__file__).resolve().parents[1]
ROOT = PILOT.parents[1]
sys.path.insert(0, str(PILOT / "lib"))
import kernel_config as kc  # noqa: E402

LIB = PILOT / "lib" / "kernel_config.py"
MIRROR_SH = ROOT / "tools" / "mirror" / "kernel-cve.sh"
SYNC_SH = ROOT / "deploy" / "gitlab-runner" / "mirror-sync.sh"
KVER = "6.8.12-1021-tegra"
HDR = f"usr/src/linux-headers-{KVER}-ubuntu24.04_aarch64/3rdparty/canonical/linux-noble"
ORG = "f4215fc3-5b6b-47ff-a258-f7189bd81038"
TEGRA = {"name": "linux-nvidia-tegra", "version": "6.8.0-1021.21",
         "purl": "pkg:deb/ubuntu/linux-nvidia-tegra@6.8.0-1021.21?arch=source&distro=ubuntu-24.04"}


def now(days=0.0):
    return (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------- 假的核心樹 ----------

CONFIG = """#
# Automatically generated file; DO NOT EDIT.
# Linux/arm64 6.8.12 Kernel Configuration
#
CONFIG_ARM64=y
CONFIG_FOO=y
# CONFIG_FOO_A is not set
CONFIG_BAR=m
# CONFIG_BAZ is not set
CONFIG_COND=y
CONFIG_SUBST=m
CONFIG_MY=y
CONFIG_L1=y
# CONFIG_NET is not set
CONFIG_LOCALVERSION="-tegra"
"""

TREE = {
    "Kbuild": "obj-y += init/\nobj-y += arch/$(SRCARCH)/\nobj-y += drivers/\nobj-$(CONFIG_NET) += net/\nobj-y += $(ARCH_LIB)\n"
              "targets += kernel/bounds.s\n$(bounds-file): kernel/bounds.s FORCE\n\t$(call filechk,offsets)\n",
    "Makefile": "VERSION = 6\nifeq ($(KBUILD_EXTMOD),)\ncore-y :=\ndrivers-y :=\nlibs-y := lib/\nendif\ninclude $(srctree)/arch/$(SRCARCH)/Makefile\n",
    "arch/arm64/Makefile": "libs-y := arch/arm64/lib/ $(libs-y)\nlibs-$(CONFIG_EFI_STUB) += $(objtree)/drivers/firmware/efi/libstub/lib.a\n",
    "arch/arm64/Kbuild": "obj-y += kernel/\n",
    "arch/arm64/kernel/Makefile": "obj-y += setup.o\n",
    "arch/arm64/lib/Makefile": "lib-y += memcpy.o\n",
    "arch/x86/Kbuild": "obj-y += kernel/\n",
    "arch/x86/kernel/Makefile": "obj-y += x86only.o head_$(BITS).o\n",
    "init/Makefile": "obj-y := main.o\n",
    "drivers/Makefile": ("# comment obj-y += commented/\nobj-$(CONFIG_FOO) += foo/\nobj-y += bar/\nobj-$(CONFIG_WEIRD) += weird/\n"
                         "obj-y += opaque/ unres/\n"),
    "drivers/foo/Makefile": "obj-$(CONFIG_FOO_A) += a.o\nobj-y += always.o\n",
    "drivers/bar/Makefile": (
        "obj-$(CONFIG_BAR) += bar.o\nbar-y := core.o\nbar-$(CONFIG_BAR_EXTRA) += extra.o\n"
        "obj-$(CONFIG_BAZ) += baz.o\nbaz-objs := baz_main.o\n"
        "obj-m += modonly.o\n"
        "ifdef CONFIG_COND\nobj-y += cond.o\nelse\nobj-y += cond_else.o\nendif\n"
        "obj-$(subst m,y,$(CONFIG_SUBST)) += subst.o\n"
        "my-objs := $(addprefix sub/, x.o)\nobj-$(CONFIG_MY) += my.o\n"
        "lists-$(CONFIG_L1) += l1.o\nlists-$(CONFIG_L2) += l2.o\nobj-y += $(lists-y)\n"
        "unused-y += ghost.o\n"
        "CFLAGS_core.o := -I$(src)\n"
        "$(obj)/gen.o: FORCE\n\tobj-y += fake.o\n"
        "obj-$(CONFIG_X) += cont1.o \\\n\tcont2.o\n"),
    "drivers/weird/Makefile": "obj-y += $(shell echo w.o)\nobj-y += w.o\n",
    "drivers/opaque/Makefile": "include $(src)/missing.inc\nobj-$(CONFIG_OFF) += o.o\n",
    "drivers/unres/Makefile": "obj-y += $(call foo,bar).o\nobj-$(CONFIG_OFF) += u.o\n",
    "drivers/frag/Makefile": "obj-$(CONFIG_OFF) += f.o\n",
    "net/Makefile": "obj-y += core.o\n",
    "lib/Makefile": "lib-y += libthing.o\nobj-$(CONFIG_OFF) += liboff.o\n",
}
# 少於 50 個 Makefile／Kbuild 算 headers 不完整（GAP）：補空的
TREE.update({f"pad/p{i}/Makefile": "\n" for i in range(40)})


def model(tree=None, config=CONFIG):
    files = {tuple(k.split("/")): v.encode() for k, v in (tree or TREE).items()}
    return kc.Model(kc.BuildInfo(files, config, "/x/.config", KVER, {"label": "test"}))


@pytest.mark.parametrize("obj,want", [
    ("drivers/foo/a.o", False),             # obj-$(CONFIG_FOO_A)，未設定
    ("drivers/foo/always.o", True),         # obj-y，資料夾有編
    ("drivers/bar/core.o", True),           # 組合物件 bar-y，bar.o 是 =m
    ("drivers/bar/extra.o", False),         # bar-$(CONFIG_BAR_EXTRA)（.config 沒有這個符號）
    ("drivers/bar/baz_main.o", False),      # baz-objs，baz.o 的 CONFIG_BAZ 沒開
    ("drivers/bar/modonly.o", True),        # obj-m
    ("drivers/bar/cond.o", None),           # ifdef 區塊 → 不知道
    ("drivers/bar/cond_else.o", None),
    ("drivers/bar/subst.o", True),          # $(subst m,y,$(CONFIG_SUBST))
    ("drivers/bar/sub/x.o", True),          # $(addprefix sub/, x.o) 的組合物件
    ("drivers/bar/l1.o", True),             # $(lists-y) 展開成 lists-$(CONFIG_L1)…
    ("drivers/bar/l2.o", False),
    ("drivers/bar/ghost.o", None),          # unused-y：unused.o 沒被任何規則提到（可能由別的規則使用，例如 nVHE 的 hyp-obj-y）→ 不知道
    ("drivers/bar/fake.o", None),           # 規則的指令（tab）不算；沒有規則 → 不知道
    ("drivers/bar/cont2.o", False),         # 續行
    ("net/core.o", False),                  # 資料夾 net/ 的 CONFIG_NET 沒開
    ("net/new/x.o", None),                  # 這個核心沒有規則提到（可能是之後才加或搬過家）：上層沒編也不判
    ("arch/x86/new/y.o", False),            # 其他架構的路徑例外
    ("drivers/frag/f.o", None),             # 沒有規則進入的資料夾裡的 Makefile（可能是 include 的片段）不能證明沒編
    ("arch/x86/kernel/x86only.o", False),   # 其他架構（Makefile 裡看不懂的 head_$(BITS).o 不影響）
    ("arch/arm64/kernel/setup.o", True),    # arch/$(SRCARCH)/
    ("arch/arm64/lib/memcpy.o", True),      # libs-y（arch Makefile）→ $(ARCH_LIB)
    ("lib/libthing.o", True),               # 最上層 Makefile 的 libs-y := lib/（在條件區塊裡也算）
    ("lib/liboff.o", False),
    ("drivers/weird/w.o", False),           # 看不懂的項目，但資料夾一定沒編
    ("drivers/opaque/o.o", None),           # include 解析不了：這個 Makefile 不完整
    ("drivers/unres/u.o", None),            # 看不懂、可能是物件的項目
    ("drivers/newdir/n.o", None),           # 沒有規則、資料夾有編
    ("drivers/commented/c.o", None),        # 註解裡的規則不算
])
def test_makefile_rules(obj, want):
    assert model().obj_built(obj).value is want


def test_symbols_and_kbuild_precedence():
    m = model()
    r = m.obj_built("drivers/foo/a.o")
    assert r.syms == {"CONFIG_FOO_A"}
    r = m.obj_built("drivers/bar/core.o")
    assert r.value is True and "CONFIG_BAR" in r.syms and "drivers/bar/bar.ko" in r.modules
    # Kbuild 與 Makefile 同時存在時用 Kbuild
    t = dict(TREE, **{"drivers/foo/Kbuild": "obj-y += a.o\n"})
    assert model(t).obj_built("drivers/foo/a.o").value is True


def test_config_parse_and_arch():
    vals, hdr = kc.parse_config(CONFIG)
    assert vals["CONFIG_FOO_A"] == "n" and vals["CONFIG_BAR"] == "m" and vals["CONFIG_LOCALVERSION"] == "-tegra"
    assert hdr == ("arm64", "6.8.12") and kc.srcarch("x86_64", {}) == "x86" and kc.srcarch(None, {"CONFIG_ARM64": "y"}) == "arm64"


@pytest.mark.parametrize("path,kind", [("drivers/x/y.c", "object"), ("arch/arm64/kernel/entry.S", "object"), ("rust/kernel/lib.rs", "object"),
                                       ("include/linux/foo.h", "unknown"), ("drivers/x/y.h", "unknown"), ("drivers/x/Kconfig", "unknown"),
                                       ("tools/perf/x.c", "unknown"), ("Documentation/x.rst", "unknown"), ("scripts/mod/x.c", "unknown"),
                                       ("arch/arm64/kernel/vmlinux.lds.S", "unknown"), ("../etc/passwd", "unknown"), ("drivers/x/y.dts", "unknown")])
def test_classify_file(path, kind):
    assert kc.classify_file(path)[0] == kind


def test_decisions():
    m = model()
    dec, detail, files, vals = kc.judge_cve(m, ["drivers/foo/a.c", "drivers/bar/extra.c"], set())
    assert dec == "not_affected" and "CONFIG_FOO_A" in detail and "none of them is set" in detail
    assert files == [{"path": "drivers/foo/a.c", "configs": ["CONFIG_FOO_A"], "built": False, "built_as": None, "module": None},
                     {"path": "drivers/bar/extra.c", "configs": ["CONFIG_BAR_EXTRA"], "built": False, "built_as": None, "module": None}]
    assert vals == {"CONFIG_FOO_A": "n", "CONFIG_BAR_EXTRA": "unset"}
    assert kc.judge_cve(m, ["drivers/foo/a.c", "drivers/foo/always.c"], set())[0] == "affected"          # 一個有編
    assert kc.judge_cve(m, ["drivers/foo/a.c", "include/linux/foo.h"], set())[0] == "unknown"            # 標頭檔
    assert kc.judge_cve(m, ["drivers/foo/a.c", "drivers/newdir/n.c"], set())[0] == "unknown"             # 找不到規則
    assert kc.judge_cve(m, ["drivers/foo/always.c", "include/linux/foo.h"], set())[0] == "affected"      # 有編的優先
    d = kc.judge_cve(m, ["arch/x86/kernel/x86only.c"], set())
    assert d[0] == "not_affected" and "another architecture" in d[1]
    # =m：模組不在映像裡也算有編，只記在說明
    d1 = kc.judge_cve(m, ["drivers/bar/core.c"], {"kernel/drivers/bar/bar.ko.zst"})
    d2 = kc.judge_cve(m, ["drivers/bar/core.c"], set())
    assert d1[0] == d2[0] == "affected" and "present in /usr/lib/modules" in d1[1] and "no such .ko" in d2[1]


# ---------- CNA 鏡像、輸入 ----------

def record(cve, files):
    aff = [{"product": "Linux", "vendor": "Linux", "defaultStatus": "unaffected", **({"programFiles": files} if files is not None else {})}]
    return {"dataType": "CVE_RECORD", "cveMetadata": {"cveId": cve, "assignerOrgId": ORG, "state": "PUBLISHED"},
            "containers": {"cna": {"affected": aff}}}


RECORDS = {"CVE-2024-0001": ["drivers/foo/a.c"], "CVE-2024-0002": ["drivers/foo/always.c"], "CVE-2024-0003": ["include/linux/x.h"],
           "CVE-2025-0004": None, "CVE-2025-0005": ["drivers/bar/extra.c", "drivers/foo/a.c"]}


def make_mirror(d, records=RECORDS, fetched=None, pad=0):
    d.mkdir(parents=True, exist_ok=True)
    zp = d / "kernel-cves.zip"
    recs = dict(records)
    for i in range(pad):
        recs[f"CVE-2023-{9000 + i}"] = ["drivers/pad.c"]
    with zipfile.ZipFile(zp, "w", zipfile.ZIP_DEFLATED) as z:
        for cve, files in sorted(recs.items()):
            z.writestr(f"cve/published/{cve[4:8]}/{cve}.json", json.dumps(record(cve, files)))
    sha = hashlib.sha256(zp.read_bytes()).hexdigest()
    (d / "SOURCE").write_text(f"source=file:///test\nfetched_utc={fetched or now()}\nzip_sha256={sha}\nzip_bytes={zp.stat().st_size}\n"
                              f"commit={'a' * 40}\ncommit_date=2026-11-01T13:42:14+01:00\nrecords={len(recs)}\nunpacked_bytes=1\n")
    return d


def grype(cves, name="linux-nvidia-tegra"):
    return {"matches": [{"vulnerability": {"id": c, "fix": {"state": "not-fixed"}}, "relatedVulnerabilities": [],
                         "artifact": {"name": name, "version": "6.8.0-1021.21", "type": "deb",
                                      "purl": f"pkg:deb/ubuntu/{name}@6.8.0-1021.21?arch=source&distro=ubuntu-24.04"}} for c in cves]}


KMAP = {"schema": "sca-center-l4t-kernel-map/1", "release": "39.2.1",
        "map_entry": {"component": dict(TEGRA), "modules_kernel_version": KVER}}


def test_kernel_cves_only_kernel_component(tmp_path):
    g = grype(["CVE-2024-0001"])
    g["matches"] += grype(["CVE-2024-9999"], name="openssl")["matches"]
    f = [{"component": {"name": "linux-nvidia-tegra", "version": "6.8.0-1021.21", "purl": TEGRA["purl"]},
          "vulnerability": {"source": "OSV", "vulnId": "UBUNTU-CVE-2024-0002"}},
         {"component": {"name": "linux-firmware", "version": "1", "purl": "pkg:deb/ubuntu/linux-firmware@1?distro=ubuntu-24.04"},
          "vulnerability": {"source": "OSV", "vulnId": "UBUNTU-CVE-2024-7777"}}]
    (tmp_path / "c.txt").write_text("CVE-2025-0005\n# x\n")
    cves, comp, n = kc.kernel_cves(g, f, str(tmp_path / "c.txt"), KMAP)
    assert cves == ["CVE-2024-0001", "CVE-2024-0002", "CVE-2025-0005"] and comp == TEGRA and n == {"grype": 1, "dt": 1, "list": 1}


# ---------- rootfs tar、docker save、刷機包、資料夾 ----------

def add(t, name, data=None, link=None, kind=None):
    ti = tarfile.TarInfo(name)
    if link is not None:
        ti.type, ti.linkname = (tarfile.LNKTYPE if kind == "hard" else tarfile.SYMTYPE), link
        t.addfile(ti)
    elif data is None:
        ti.type, ti.mode = tarfile.DIRTYPE, 0o755
        t.addfile(ti)
    else:
        ti.size = len(data)
        t.addfile(ti, io.BytesIO(data))


def rootfs_members(prefix="", tree=None, with_build=True, kver=KVER):
    p = prefix
    hdr = HDR.replace(KVER, kver)
    m = [(f"{p}lib", None, "usr/lib"), (f"{p}usr/lib/modules/{kver}/kernel/drivers/bar/bar.ko.zst", b"\x28\xb5", None),
         (f"{p}usr/lib/modules/{kver}/modules.builtin", b"kernel/drivers/foo/always.ko\n", None),
         (f"{p}usr/lib/modules/{kver}/modules.order", b"kernel/drivers/bar/bar.ko\n", None),
         (f"{p}etc/passwd", b"root:x:0:0\n", None), (f"{p}usr/bin/huge", b"x" * 1000, None),
         (f"{p}{hdr}/.config", CONFIG.encode(), None),
         (f"{p}{hdr}/include/linux/foo.h", b"#define X\n", None),
         (f"{p}{hdr}/drivers/foo/foo.c", b"int x;\n", None),
         (f"{p}{hdr}/scripts/dtc/include-prefixes/arm64", None, "../../../arch/arm64/boot/dts")]
    if with_build:
        m.append((f"{p}usr/lib/modules/{kver}/build", None, f"/{hdr}"))
    for k, v in (tree or TREE).items():
        m.append((f"{p}{hdr}/{k}", v.encode(), None))
    return m


def write_tar(path, members, mode="w"):
    with tarfile.open(path, mode) as t:
        for name, data, link in members:
            add(t, name, data, link)
    return path


def test_tar_streaming_selects_only_build_files(tmp_path):
    p = write_tar(tmp_path / "rootfs.tar", rootfs_members("./"))
    col, src = kc.collect(str(p))
    assert src["label"] == "rootfs tar"
    names = {"/".join(k) for k in col.files}
    assert f"{HDR}/.config" in names and f"{HDR}/drivers/bar/Makefile" in names and f"{HDR}/Kbuild" in names
    assert not any(n.endswith((".h", ".c")) or n.startswith(("etc/", "usr/bin")) for n in names)     # 只留 .config 與 Makefile 類
    assert col.modules[KVER]["ko"] == {"kernel/drivers/bar/bar.ko.zst"} and col.modules[KVER]["build"] == f"/{HDR}"
    info, gap = kc.locate(col, src, None)
    assert gap is None and info.config_path == f"/{HDR}/.config" and ("drivers", "bar", "Makefile") in info.files
    assert not any(k[:3] == ("scripts", "dtc", "include-prefixes") for k in info.files)   # 樹內的資料夾連結不重複走
    # 壓縮的 rootfs tar 也可以（串流）
    pz = write_tar(tmp_path / "rootfs.tar.gz", rootfs_members(), mode="w:gz")
    col2, src2 = kc.collect(str(pz))
    assert set(col2.files) == set(col.files)


def test_locate_without_build_link_and_gaps(tmp_path):
    col, src = kc.collect(str(write_tar(tmp_path / "a.tar", rootfs_members(with_build=False))))
    info, gap = kc.locate(col, src, KVER)
    assert gap is None and info.config_path.endswith("linux-noble/.config")
    # 要的版本不在映像裡
    assert "沒有核心模組目錄" in kc.locate(col, src, "6.8.0-1-generic")[1]
    # 兩個模組目錄、沒指定版本
    m = rootfs_members() + [(f"usr/lib/modules/6.8.0-9-generic/kernel/x.ko", b"x", None)]
    col3, src3 = kc.collect(str(write_tar(tmp_path / "b.tar", m)))
    assert "2 個核心模組目錄" in kc.locate(col3, src3, None)[1]
    # 沒有 headers
    m = [x for x in rootfs_members() if not x[0].startswith("usr/src/")]
    col4, src4 = kc.collect(str(write_tar(tmp_path / "c.tar", m)))
    assert "nvidia-l4t-kernel-headers" in kc.locate(col4, src4, None)[1]


def test_ubuntu_split_headers_follow_link_outside_tree(tmp_path):
    """Ubuntu 的 linux-headers-<版本>-generic 只有 .config 與部分檔案，其他資料夾是連到 linux-headers-<版本>/ 的連結。"""
    kv = "6.8.0-45-generic"
    flav, common = f"usr/src/linux-headers-{kv}", "usr/src/linux-headers-6.8.0-45"
    m = [(f"usr/lib/modules/{kv}/kernel/a.ko", b"x", None), (f"usr/lib/modules/{kv}/build", None, f"/{flav}"),
         (f"{flav}/.config", CONFIG.encode(), None), (f"{flav}/Makefile", TREE["Makefile"].encode(), None),
         (f"{flav}/Kbuild", None, "../linux-headers-6.8.0-45/Kbuild")]
    for k, v in TREE.items():
        if k not in ("Makefile", "Kbuild"):
            m.append((f"{common}/{k}", v.encode(), None))
    m.append((f"{common}/Kbuild", TREE["Kbuild"].encode(), None))
    for top in ("arch", "drivers", "init", "lib", "net"):
        m.append((f"{flav}/{top}", None, f"../linux-headers-6.8.0-45/{top}"))
    col, src = kc.collect(str(write_tar(tmp_path / "u.tar", m)))
    info, gap = kc.locate(col, src, None)
    assert gap is None and ("drivers", "bar", "Makefile") in info.files and ("Kbuild",) in info.files
    assert kc.Model(info).obj_built("drivers/foo/a.o").value is False


def docker_save(tmp_path, layers):
    """layers：[[(name, data, link)]]（由下而上）→ docker save 格式的 tar。"""
    out = tmp_path / "image.tar"
    with tarfile.open(out, "w") as t:
        names = []
        for i, mem in enumerate(layers):
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w") as lt:
                for name, data, link in mem:
                    add(lt, name, data, link)
            raw = buf.getvalue()
            if i == 1:
                raw = gzip.compress(raw)            # 第二層用 gzip（OCI 的 blobs 可以是壓縮的）
            n = f"blobs/sha256/{hashlib.sha256(raw).hexdigest()}"
            add(t, n, raw)
            names.append(n)
        add(t, "manifest.json", json.dumps([{"Config": "c.json", "RepoTags": ["x:1"], "Layers": names}]).encode())
    return out


def test_docker_save_layers_and_whiteouts(tmp_path):
    base = rootfs_members()
    upper = [(f"{HDR}/drivers/foo/Makefile", b"obj-y += a.o\n", None),        # 上層換掉 Makefile
             (f"{HDR}/drivers/unres/.wh..wh..opq", b"", None),                   # 清空下層的資料夾
             (f"{HDR}/drivers/opaque/.wh.Makefile", b"", None)]                  # 刪掉一個檔案
    img = docker_save(tmp_path, [base, upper])
    col, src = kc.collect(str(img))
    assert src["label"] == "docker image" and src["layers"] == 2
    info, gap = kc.locate(col, src, None)
    assert gap is None
    assert info.files[("drivers", "foo", "Makefile")] == b"obj-y += a.o\n"
    assert ("drivers", "unres", "Makefile") not in info.files and ("drivers", "opaque", "Makefile") not in info.files
    assert kc.Model(info).obj_built("drivers/foo/a.o").value is True


def test_flash_archive_with_prefix_and_directory(tmp_path):
    pre = "product-a/Linux_for_Tegra/rootfs_no_gui/"
    a = write_tar(tmp_path / "pkg.tbz2", rootfs_members(pre) + [("product-a/Linux_for_Tegra/rootfs_gui/etc/x", b"x", None),
                                                                 ("product-a/Linux_for_Tegra/flash.sh", b"#!/bin/sh\n", None)], mode="w:bz2")
    col, src = kc.collect(str(a), "product-a/Linux_for_Tegra/rootfs_no_gui")
    assert src["label"] == "archive" and kc.locate(col, src, KVER)[0] is not None
    with pytest.raises(kc.InputError):
        kc.collect(str(a), "../etc")
    # 解開的 rootfs 資料夾（不跟隨連結）與核心原始碼樹本身
    d = tmp_path / "rootfs"
    with tarfile.open(write_tar(tmp_path / "r.tar", rootfs_members())) as t:
        t.extractall(d, filter="tar")
    col2, src2 = kc.collect(str(d))
    assert src2["label"] == "dir" and kc.locate(col2, src2, None)[0] is not None
    col3, src3 = kc.collect(str(d / HDR))
    assert col3 is None and src3.get("tree")


# ---------- 命令列 ----------

def run(tmp_path, *extra, grype_doc=None, kmap=KMAP, src=None, mirror=None, env=None):
    g = tmp_path / "grype.json"
    g.write_text(json.dumps(grype_doc if grype_doc is not None else grype(list(RECORDS) + ["CVE-2024-0404"])))
    km = tmp_path / "kmap.json"
    km.write_text(json.dumps(kmap))
    if src is None:
        src = write_tar(tmp_path / "rootfs.tar", rootfs_members())
    if mirror is None:
        mirror = make_mirror(tmp_path / "m")
    out = tmp_path / "kernel-config.json"
    args = ["--grype", str(g), "--kernel-map", str(km), "--out", str(out)] + (["--mirror", str(mirror)] if mirror is not False else [])
    args += ["--from", str(src)] if src else []
    p = subprocess.run([sys.executable, "-I", str(LIB), *args, *extra], capture_output=True, text=True, timeout=120,
                       env={**os.environ, **(env or {})})
    line = p.stdout.strip().splitlines()[-1] if p.stdout.strip() else ""
    st = line.split("\t")
    return p, st, (json.loads(out.read_text()) if out.exists() else None)


def test_cli_ok_contract(tmp_path):
    p, st, out = run(tmp_path)
    assert p.returncode == 0 and st[0] == "C-kernel-config" and st[1] == "OK", p.stdout + p.stderr
    assert out["schema"] == "sca-center-kernel-config/1" and out["status"] == "OK" and out["detail"] == st[2]
    assert out["kernel"]["version"] == KVER and out["kernel"]["config_source"] == f"/{HDR}/.config"
    assert out["kernel"]["config_sha256"] == hashlib.sha256(CONFIG.encode()).hexdigest() and out["kernel"]["source"] == "rootfs tar"
    assert out["kernel"]["makefiles"] >= 15 and out["component"] == TEGRA
    assert out["kernel"]["included_c_list"] == "6.8" and out["limitations"] == kc.LIMITATIONS
    assert out["cve_data"]["commit_or_date"].startswith("a" * 40)
    by = {r["cve"]: r for r in out["results"]}
    assert by["CVE-2024-0001"]["decision"] == "not_affected" and by["CVE-2024-0001"]["justification"] == "vulnerable_code_not_present"
    assert by["CVE-2024-0001"]["config_values"] == {"CONFIG_FOO_A": "n"}
    assert by["CVE-2024-0002"]["decision"] == "affected" and "justification" not in by["CVE-2024-0002"]
    assert by["CVE-2024-0003"]["decision"] == "unknown"                       # 標頭檔
    assert by["CVE-2025-0004"]["detail"] == "the CNA record lists no programFiles"
    assert by["CVE-2024-0404"]["detail"] == "no Linux kernel CNA record in the mirror"
    assert by["CVE-2025-0005"]["decision"] == "not_affected"
    assert out["counts"] == {"not_affected": 2, "affected": 1, "unknown": 3}
    assert set(out["results"][0]) <= {"cve", "decision", "justification", "detail", "files", "config_values"}


def test_cli_explicit_config_and_tree(tmp_path):
    t = tmp_path / "tree"
    for k, v in TREE.items():
        (t / k).parent.mkdir(parents=True, exist_ok=True)
        (t / k).write_text(v)
    (t / ".config").write_text(CONFIG)
    p, st, out = run(tmp_path, "--config", str(t / ".config"), "--makefiles-dir", str(t), src="")
    assert st[1] == "OK" and out["kernel"]["source"] == "explicit", p.stdout + p.stderr
    p, st, out = run(tmp_path, src=t)                          # --from 指到樹本身
    # 只有建置樹、沒有模組目錄：無法核對 out-of-tree 模組裡的複本 → 不判 not_affected
    by = {r["cve"]: r for r in out["results"]}
    assert st[1] == "OK" and out["counts"]["not_affected"] == 0 and out["counts"]["affected"] == 1
    assert by["CVE-2024-0001"]["decision"] == "unknown" and "no module directory" in by["CVE-2024-0001"]["detail"]


@pytest.mark.parametrize("what,msg", [("nomirror", "沒有設定 CNA 鏡像"), ("stale", "CNA 鏡像過期"), ("sha", "sha256"),
                                      ("noheaders", "沒有核心 6.8.12-1021-tegra 的建置設定"), ("version", "不是同一個核心"),
                                      ("fewmake", "headers 不完整")])
def test_cli_gaps(tmp_path, what, msg):
    mirror, src, kmap = None, None, KMAP
    if what == "nomirror":
        mirror = False
    elif what == "stale":
        mirror = make_mirror(tmp_path / "m", fetched=now(8))
    elif what == "sha":
        mirror = make_mirror(tmp_path / "m")
        with open(mirror / "kernel-cves.zip", "ab") as f:
            f.write(b"x")
    elif what == "noheaders":
        src = write_tar(tmp_path / "r.tar", [x for x in rootfs_members() if not x[0].startswith("usr/src/")])
    elif what == "version":
        src = write_tar(tmp_path / "r.tar", rootfs_members(kver="6.9.1-1-x"))
        kmap = dict(KMAP, map_entry={"component": dict(TEGRA), "modules_kernel_version": "6.9.1-1-x"})
    elif what == "fewmake":
        src = write_tar(tmp_path / "r.tar", rootfs_members(tree={k: v for k, v in TREE.items() if k.count("/") < 1}))
    if mirror is False:
        assert "不存在" in run(tmp_path, src=src, kmap=kmap, mirror=tmp_path / "nothere")[1][2]
    p, st, out = run(tmp_path, src=src, kmap=kmap, mirror=mirror)
    assert p.returncode == 0 and st[1] == "GAP" and msg in st[2], st
    assert out["status"] == "GAP" and out["results"] == [] and out["counts"] == {"not_affected": 0, "affected": 0, "unknown": 0}


def test_cli_not_run_and_bad_input(tmp_path):
    p, st, out = run(tmp_path, grype_doc=grype(["CVE-2024-0001"], name="openssl"))
    assert p.returncode == 0 and st[1] == "NOT_RUN" and out is None
    (tmp_path / "kernel-config.json").write_text("{}")             # 舊的輸出：失敗時也刪掉
    p, st, out = run(tmp_path, grype_doc={"matches": "x"})
    assert p.returncode == 3 and st[1] == "FAIL" and out is None and "Traceback" not in p.stderr
    p = subprocess.run([sys.executable, "-I", str(LIB), "--out", str(tmp_path / "o.json")], capture_output=True, text=True)
    assert p.returncode == 3 and "參數錯誤" in p.stdout
    p = subprocess.run([sys.executable, "-I", str(LIB), "--from", "x", "--config", "y", "--makefiles-dir", "z", "--out", "o"],
                       capture_output=True, text=True)
    assert p.returncode == 3


# ---------- 鏡像腳本 ----------

def git_repo(tmp_path, records):
    r = tmp_path / "vulns"
    for cve, files in records.items():
        p = r / "cve" / "published" / cve[4:8] / f"{cve}.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(record(cve, files)))
    (r / "cve" / "published" / "2024" / "CVE-2024-0001.mbox").write_text("mail")
    (r / "cve" / "rejected" / "2024").mkdir(parents=True)
    (r / "cve" / "rejected" / "2024" / "CVE-2024-0999.json").write_text("{}")
    (r / ".gitattributes").write_text("* export-subst\n")
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@x", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@x"}
    for c in (["init", "-q", "-b", "master"], ["add", "-A"], ["commit", "-q", "-m", "x"]):
        subprocess.run(["git", "-C", str(r), *c], check=True, env=env, capture_output=True)
    return r


def run_mirror(*args, env=None):
    e = {**os.environ, "KERNEL_CVE_MIN_RECORDS": "3", **(env or {})}
    return subprocess.run(["bash", str(MIRROR_SH), *map(str, args)], capture_output=True, text=True, timeout=120, env=e)


def test_mirror_script_builds_checks_and_reuses(tmp_path):
    repo = git_repo(tmp_path, RECORDS)
    url = repo.as_uri()
    r = run_mirror(tmp_path / "m", tmp_path / "man.txt", env={"KERNEL_CVE_GIT_URL": url})
    assert r.returncode == 0, r.stdout + r.stderr
    src = dict(l.split("=", 1) for l in (tmp_path / "m" / "SOURCE").read_text().splitlines())
    assert src["records"] == "5" and src["zip_sha256"] == hashlib.sha256((tmp_path / "m" / "kernel-cves.zip").read_bytes()).hexdigest()
    with zipfile.ZipFile(tmp_path / "m" / "kernel-cves.zip") as z:
        assert sorted(z.namelist()) == sorted(f"cve/published/{c[4:8]}/{c}.json" for c in RECORDS)      # 沒有 .mbox、rejected
    assert sorted(p.name for p in (tmp_path / "m").iterdir()) == ["SOURCE", "kernel-cves.zip"]
    assert not list(tmp_path.glob(".kernel-cve-clone.*"))
    assert "# commit=" in (tmp_path / "man.txt").read_text()
    c = run_mirror("--check", tmp_path / "m")
    assert c.returncode == 0 and c.stdout.startswith("OK commit=") and "records=5" in c.stdout
    assert run_mirror(tmp_path / "m", tmp_path / "man2.txt", env={"KERNEL_CVE_GIT_URL": url}).returncode == 3     # 拒絕覆蓋
    # 上游 HEAD 沒變：沿用上一份，不 clone
    r2 = run_mirror(tmp_path / "m2", tmp_path / "m2.man", env={"KERNEL_CVE_GIT_URL": url, "KERNEL_CVE_REUSE_FROM": str(tmp_path / "m")})
    assert r2.returncode == 0 and "沿用" in r2.stdout, r2.stdout + r2.stderr
    assert (tmp_path / "m2" / "kernel-cves.zip").read_bytes() == (tmp_path / "m" / "kernel-cves.zip").read_bytes()
    # kernel_config 讀得了這份鏡像
    p, st, out = run(tmp_path, mirror=tmp_path / "m")
    assert st[1] == "OK" and out["counts"]["not_affected"] == 2
    s = MIRROR_SH.read_text(encoding="utf-8")
    assert "core.hooksPath=/dev/null" in s and "--no-checkout" in s and "ulimit -f" in s and 'timeout "${KERNEL_CVE_GIT_TIMEOUT:-900}"' in s
    assert "cat-file" in s and "git archive" not in s.split("set -euo pipefail", 1)[1]


def test_mirror_script_url_and_caps(tmp_path):
    assert run_mirror(tmp_path / "x", tmp_path / "x.man", env={"KERNEL_CVE_GIT_URL": "ssh://evil/x"}).returncode == 3
    assert run_mirror(tmp_path / "x", tmp_path / "x.man", env={"KERNEL_CVE_GIT_URL": "file:///x", "KERNEL_CVE_MAX_RECORD_KB": "1;rm"}).returncode == 3
    repo = git_repo(tmp_path, RECORDS)
    r = run_mirror(tmp_path / "y", tmp_path / "y.man", env={"KERNEL_CVE_GIT_URL": repo.as_uri(), "KERNEL_CVE_MAX_RECORD_KB": "0"})
    assert r.returncode != 0 and "KERNEL_CVE_MAX_RECORD_KB" in r.stderr and not (tmp_path / "y.man").exists()


@pytest.mark.parametrize("what,msg", [("stale", "過期"), ("sha", "sha256"), ("few", "可能只下載到一部分"), ("nosource", "缺少 SOURCE"),
                                      ("member", "不是 cve/published"), ("org", "格式不是預期"), ("symlink", "一般檔案與資料夾以外"),
                                      ("fifo", "一般檔案與資料夾以外"), ("count", "records=")])
def test_mirror_check_failures(tmp_path, what, msg):
    m = make_mirror(tmp_path / "m", fetched=now(8) if what == "stale" else None)
    if what == "sha":
        with open(m / "kernel-cves.zip", "ab") as f:
            f.write(b"x")
    elif what == "nosource":
        (m / "SOURCE").unlink()
    elif what in ("member", "org"):
        with zipfile.ZipFile(m / "kernel-cves.zip", "a") as z:
            if what == "member":
                z.writestr("../../etc/passwd", "x")
        if what == "org":
            recs = {f"CVE-2024-{i:04d}": ["a.c"] for i in range(5)}
            m = make_mirror(tmp_path / "m2", records=recs)
            with zipfile.ZipFile(m / "kernel-cves.zip", "w") as z:
                for c in recs:
                    r = record(c, ["a.c"])
                    r["cveMetadata"]["assignerOrgId"] = "x"
                    z.writestr(f"cve/published/2024/{c}.json", json.dumps(r))
        s = (m / "SOURCE").read_text().splitlines()
        sha = hashlib.sha256((m / "kernel-cves.zip").read_bytes()).hexdigest()
        (m / "SOURCE").write_text("\n".join(l if not l.startswith("zip_sha256=") else f"zip_sha256={sha}" for l in s) + "\n")
    elif what == "symlink":
        os.symlink("/etc/passwd", m / "leak")
    elif what == "fifo":
        os.mkfifo(m / "hang")
    elif what == "count":
        s = (m / "SOURCE").read_text().replace("records=5", "records=6")
        (m / "SOURCE").write_text(s)
    c = run_mirror("--check", m, env={"KERNEL_CVE_MIN_RECORDS": "6" if what == "few" else "3"})
    assert c.returncode == 1 and msg in c.stdout, c.stdout


# ---------- 部署：常駐環境的更新與 GitLab runner 的複本 ----------

def test_kernel_cve_mirror_update_and_runner_sync(tmp_path):
    repo = git_repo(tmp_path, RECORDS)
    state = tmp_path / "state"
    state.mkdir()
    (state / "pilot.env").write_text("DT_URL=http://x\n", encoding="utf-8")
    env = {**os.environ, "PILOT_STATE_DIR": str(state), "PILOT_KERNEL_CVE_MIRROR_DIR": str(tmp_path / "persist" / "kcve"),
           "KERNEL_CVE_GIT_URL": repo.as_uri(), "KERNEL_CVE_MIN_RECORDS": "3"}
    sh = ROOT / "deploy" / "pilot" / "kernel-cve-mirror.sh"
    assert subprocess.run(["bash", str(sh), "check"], env=env, capture_output=True, text=True).returncode == 1
    (tmp_path / "persist" / "kcve" / "releases" / "20200101T000000Z").mkdir(parents=True)     # 上一次中斷留下的
    (tmp_path / "persist" / "kcve" / "releases" / ".kernel-cve-clone.abc").mkdir()
    u = subprocess.run(["bash", str(sh), "update"], env=env, capture_output=True, text=True, timeout=120)
    assert u.returncode == 0 and "RESULT OK" in u.stdout, u.stdout + u.stderr
    rel = tmp_path / "persist" / "kcve" / "releases"
    assert not (rel / "20200101T000000Z").exists() and not (rel / ".kernel-cve-clone.abc").exists()
    cur = tmp_path / "persist" / "kcve" / "current"
    assert f"KERNEL_CVE_MIRROR={cur}" in (state / "pilot.env").read_text()
    c = subprocess.run(["bash", str(sh), "check"], env=env, capture_output=True, text=True, timeout=60)
    assert c.returncode == 0 and c.stdout.splitlines()[-1].startswith("RESULT OK")
    s = subprocess.run(["bash", str(SYNC_SH), "kernel-cve", str(state / "pilot.env"), getpass.getuser(), str(tmp_path)],
                       env={**env, "KERNEL_CVE_SYNC_DEST": str(tmp_path / "runner" / "kernel-cve")}, capture_output=True, text=True, timeout=60)
    dst = tmp_path / "runner" / "kernel-cve"
    assert s.returncode == 0 and s.stdout.strip() == str(dst), s.stderr
    assert dst.is_symlink() and (dst / "kernel-cves.zip").is_file()
    p, st, out = run(tmp_path, mirror=dst)
    assert st[1] == "OK"
    # 大小上限
    s2 = subprocess.run(["bash", str(SYNC_SH), "kernel-cve", str(state / "pilot.env"), getpass.getuser(), str(tmp_path)],
                        env={**env, "KERNEL_CVE_SYNC_DEST": str(tmp_path / "runner2" / "kernel-cve"), "KERNEL_CVE_SYNC_MAX_MB": "0"},
                        capture_output=True, text=True, timeout=60)
    assert s2.returncode == 1 and "鏡像太大" in s2.stderr


# ---------- 接線 ----------

def test_sca_scan_wiring():
    s = (PILOT / "sca-scan").read_text(encoding="utf-8")
    i = s.index('kernel_config.py" "${ka[@]+"${ka[@]}"}" "${KSRC[@]}" --out "$KCF"')
    assert s.index('distro_recheck.py" --findings') < i < s.index("# ---------- E. ScanCode.io")    # D-dt-findings、D-distro-recheck 之後
    assert s.index('kernelcheck.py" --sbom') < i                                                      # C-kernel-coverage 之後
    assert s.rindex('rm -f "$KCF" "$KCF.xz"', 0, i) > s.index('distro_recheck.py" --findings')        # 先刪上一次的結果
    assert 'ka+=(--mirror "$KERNEL_CVE_MIRROR")' in s and 'NOT_RUN) rm -f "$KCF";;' in s
    # kernel_config.py 的 NOT_RUN（沒有核心的 CVE）不寫；--sbom 沒給 --kernel-build（沒有來源）明示 NOT_RUN
    # （另一個在 kernel_cve_list：Grype、DT 都沒有核心 CVE 又沒有清單來源時，核心存在而沒有評估也要寫狀態列）
    assert s.count("status C-kernel-config NOT_RUN") == 2
    j = s.rindex("status C-kernel-config NOT_RUN")
    assert s.rindex('elif [ "$MODE" = sbom ] && [ $SBOM_OK = 1 ] && [ ${#KSRC[@]} -eq 0 ]; then', 0, j) > i
    assert 'KSRC=(--from "$IMG_TAR")' in s and "timeout 3600 python3 -I" in s and 'ka+=(--findings "$OUT/dt/findings.json")' in s
    case = next(l for l in s.splitlines() if l.strip().startswith("case $k in DT_URL|"))
    assert "KERNEL_CVE_MIRROR" in case.split(" in ", 1)[1].split(")", 1)[0].split("|") and 'secret "$KERNEL_CVE_MIRROR"' not in s
    assert '--kernel-build) optval "$@"; KBUILD=' in s and '"--kernel-build 只用於 --image 或 --sbom"' in s


def test_sca_scan_kernel_build_argument_errors(tmp_path):
    sb = tmp_path / "s.cdx.json"
    sb.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}))
    for args in (["--dir", str(tmp_path), "--kernel-build", str(sb)], ["--sbom", str(sb), "--kernel-build", str(tmp_path / "nope")],
                 ["--sbom", str(sb), "--kernel-build", str(sb), "--kernel-build-prefix", "a/../../etc"]):
        p = subprocess.run(["bash", str(PILOT / "sca-scan"), *args, "--out", str(tmp_path / "o")], capture_output=True, text=True, timeout=60)
        assert p.returncode == 64, args


def test_deploy_wiring():
    inst = (ROOT / "deploy" / "pilot" / "install.sh").read_text(encoding="utf-8")
    assert '"$PILOT_DIR/kernel-cve-mirror.sh" check' in inst and 'kv_set "$PILOTENV" KERNEL_CVE_MIRROR "$kd/current"' in inst
    assert 'timeout 1800 "$PILOT_DIR/kernel-cve-mirror.sh" update' in inst
    gr = (ROOT / "deploy" / "gitlab-runner" / "install.sh").read_text(encoding="utf-8")
    assert 'timeout 300 bash "$APP/deploy/gitlab-runner/mirror-sync.sh" kernel-cve "$PILOTENV" "$OWNER" "$PERSIST"' in gr
    assert 'kv_set "$GENV" KERNEL_CVE_MIRROR "$kcm"' in gr and "G-kernel-cve" in gr
    ref = (ROOT / "deploy" / "gitlab-runner" / "nvd-refresh.sh").read_text(encoding="utf-8")
    assert 'timeout 1800 runuser -u "$U" --' in ref and 'kernel-cve-mirror.sh" update' in ref
    assert 'mirror-sync.sh" kernel-cve "$PILOTENV" "$U" "$P"' in ref and 'kv_set "$t4" KERNEL_CVE_MIRROR "$kcm"' in ref
    assert ref.index("NVD_MIRROR_MODIFIED NVD_MIRROR_RELEASE; do kv_set") < ref.index('kernel-cve-mirror.sh" update') < ref.rindex('exit "$x"')
    sync = SYNC_SH.read_text(encoding="utf-8")
    assert "kernel-cve) KEY=KERNEL_CVE_MIRROR" in sync and "MAXMB=${KERNEL_CVE_SYNC_MAX_MB:-200}" in sync
    wf = (ROOT / ".github" / "workflows" / "sca-persistent.yml").read_text(encoding="utf-8")
    assert 'PILOT_KERNEL_CVE_MIRROR_DIR="$HOME/.cache/sca-pilot-ci/kernel-cve"' in wf
    ci = (ROOT / "tools" / "mirror" / "ci-run.sh").read_text(encoding="utf-8")
    assert "kernelcve" in ci and "kernel-cve.sh" in ci
    for doc in ("docs/offline-mirrors.md", "docs/offline-egress.md"):
        assert "kernel-cve.sh" in (ROOT / doc).read_text(encoding="utf-8")


# ---------- scan-flash-package.sh --rescan-from ----------

FP_SCRIPT = ROOT / "tools" / "demo" / "scan-flash-package.sh"


def prev_result(tmp_path, archive, md5=None):
    """上一次 scan-flash-package.sh 的結果（只放 --rescan-from 會讀的檔案）。A-md5 記的是刷機包真正的 MD5（md5 給值時用它）。"""
    prev = tmp_path / "prev"
    v = prev / "rootfs_no_gui" / "scan"
    (v / "sbom").mkdir(parents=True)
    (v / "sbom" / "sbom.cdx.json").write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}))
    (v / "meta.json").write_text(json.dumps({"name": "product-a-OrinNano", "version": "V39.2.0.2_a (rootfs_no_gui)"}))
    lst = {"source": {"type": "archive", "file": archive.name}, "archive": {"file": archive.name, "bytes": archive.stat().st_size},
           "rootfs": [{"variant": "rootfs_no_gui", "prefix": "product-a/Linux_for_Tegra/rootfs_no_gui", "bytes": 10, "looks_like_rootfs": True,
                       "l4t": {"release": "39.2.1"}}], "ambiguous": {}}
    (prev / "list.json").write_text(json.dumps(lst))
    md5 = md5 or hashlib.md5(archive.read_bytes()).hexdigest()
    (prev / "status.tsv").write_text("stage\tstatus\tdetail\nA-md5\tOK\tx（x.md5）：md5 " + md5 + " 相符\n")
    return prev


def rescan(tmp_path, *args):
    b = tmp_path / "bin"
    b.mkdir(exist_ok=True)
    for t in ("grype", "bwrap"):
        (b / t).write_text("#!/bin/sh\necho 'Version: 0.0.0'\n")
        (b / t).chmod(0o755)
    env = dict(os.environ, PATH=f"{b}:{os.environ['PATH']}", FLASHPKG_ALLOW_TMP_OUT="1", SCA_TOOLS_DIR=str(tmp_path / "none"))
    return subprocess.run(["bash", str(FP_SCRIPT), *map(str, args)], capture_output=True, text=True, env=env, timeout=300)


def test_rescan_flow(tmp_path):
    a = write_tar(tmp_path / "product-a.tbz2", rootfs_members("product-a/Linux_for_Tegra/rootfs_no_gui/"), mode="w:bz2")
    prev = prev_result(tmp_path, a)
    cfg = prev / "rootfs_no_gui" / "cra-project" / "CRA" / "Config"
    cfg.mkdir(parents=True)
    (cfg / "vex-rules.json").write_text('{"schema": "x", "rules": []}')
    (cfg / "vex-annotations.json").write_text('{"schema": "y", "annotations": []}')
    (cfg / "config.json").write_text("{}")
    out = tmp_path / "res"
    p = rescan(tmp_path, "--rescan-from", prev, "--archive", a, "--out", out, "--no-upload", "--no-company")
    st = (out / "status.tsv").read_text()
    # 上一次的批次規則與人工判定帶過來（config.json 不帶：重新產生）
    assert "B-rescan-config-rootfs_no_gui\tOK\t沿用上一次的 vex-rules.json vex-annotations.json" in st, st
    oc = out / "rootfs_no_gui" / "cra-project" / "CRA" / "Config"
    assert (oc / "vex-rules.json").read_text() == '{"schema": "x", "rules": []}' and (oc / "vex-annotations.json").exists()
    assert "A-env\tINFO" in st and "重跑比對" in st and "B-rescan-rootfs_no_gui\tOK" in st and "核心建置設定從 product-a.tbz2 讀" in st, st + p.stderr
    assert "C-scan-rootfs_no_gui" in st and "E-summary\tOK" in st and "B-import" not in st
    md5 = hashlib.md5(a.read_bytes()).hexdigest()
    assert f"A-md5\tOK\tmd5 {md5}：沿用上一次核對過的值" in st and "這次重算 product-a.tbz2 相符" in st
    assert (out / "list.json").exists() and (out / "rootfs_no_gui" / "logs" / "sca-scan.txt").exists()
    meta = json.loads((out / "rootfs_no_gui" / "scan" / "meta.json").read_text())
    assert meta["name"] == "product-a-OrinNano" and meta["version"] == "V39.2.0.2_a (rootfs_no_gui)" and meta["mode"] == "sbom"
    # 上一次沒有映像的靜態安全檢查：從刷機包讀（rootfs 前綴）
    assert re.search(r"^B-image-check-rootfs_no_gui\t(OK|ATTENTION|GAP)\t", st, re.M), st
    assert (out / "rootfs_no_gui" / "image-check" / "image-check.json").is_file()
    # 不是上一次的刷機包：停止
    b = write_tar(tmp_path / "product-a.tbz2.other", rootfs_members("x/rootfs_no_gui/"), mode="w:bz2")
    out2 = tmp_path / "res2"
    rescan(tmp_path, "--rescan-from", prev, "--archive", b, "--out", out2, "--no-upload")
    assert "A-rescan\tFAIL" in (out2 / "status.tsv").read_text()
    # 沒給刷機包：只重跑比對
    out3 = tmp_path / "res3"
    rescan(tmp_path, "--rescan-from", prev, "--out", out3, "--no-upload", "--no-company")
    st3 = (out3 / "status.tsv").read_text()
    assert "沒有核心建置設定" in st3 and f"A-md5\tOK\tmd5 {md5}" in st3 and "沒有重算" in st3
    assert "B-image-check-rootfs_no_gui\tNOT_RUN" in st3
    # 從重跑的結果再重跑：MD5 帶過來了，照樣重算比對（不會靜默略過）
    out4 = tmp_path / "res4"
    # 重跑的結果要有 SBOM 才能再重跑（假的工具下 sca-scan 不一定寫出來）：放一份，讓後面的步驟（帶設定）照樣執行
    sb = out / "rootfs_no_gui" / "scan" / "sbom" / "sbom.cdx.json"
    if not sb.exists():
        sb.parent.mkdir(parents=True, exist_ok=True)
        sb.write_text((prev / "rootfs_no_gui" / "scan" / "sbom" / "sbom.cdx.json").read_text())
    rescan(tmp_path, "--rescan-from", out, "--archive", a, "--out", out4, "--no-upload", "--no-company")
    st4 = (out4 / "status.tsv").read_text()
    assert f"A-md5\tOK\tmd5 {md5}" in st4 and "這次重算 product-a.tbz2 相符" in st4, st4
    assert "沿用上一次的 rootfs_no_gui/image-check" in st4 and (out4 / "rootfs_no_gui" / "image-check" / "image-check.md").is_file(), st4
    assert "B-rescan-config-rootfs_no_gui\tOK" in st4 and (out4 / "rootfs_no_gui" / "cra-project" / "CRA" / "Config" / "vex-rules.json").exists()
    # 符號連結不帶過來，記 ATTENTION（不是靜默略過）
    oc4 = out4 / "rootfs_no_gui" / "cra-project" / "CRA" / "Config"
    (oc4 / "vex-annotations.json").unlink()
    (oc4 / "vex-annotations.json").symlink_to(tmp_path / "elsewhere.json")
    sb = out4 / "rootfs_no_gui" / "scan" / "sbom" / "sbom.cdx.json"
    if not sb.exists():
        sb.parent.mkdir(parents=True, exist_ok=True)
        sb.write_text((prev / "rootfs_no_gui" / "scan" / "sbom" / "sbom.cdx.json").read_text())
    out5 = tmp_path / "res5"
    rescan(tmp_path, "--rescan-from", out4, "--out", out5, "--no-upload", "--no-company")
    st5 = (out5 / "status.tsv").read_text()
    assert "B-rescan-config-rootfs_no_gui\tATTENTION\t上一次的 vex-annotations.json 是符號連結" in st5, st5
    assert "B-rescan-config-rootfs_no_gui\tOK\t沿用上一次的 vex-rules.json" in st5


def test_rescan_image_check_reuse_rules(tmp_path):
    """上一次的 image-check：FAIL 或不同版本不沿用（有刷機包就重跑，沒有就 NOT_RUN）；檢查逾時記 FAIL。"""
    a = write_tar(tmp_path / "product-a.tbz2", rootfs_members("product-a/Linux_for_Tegra/rootfs_no_gui/"), mode="w:bz2")
    prev = prev_result(tmp_path, a)
    ic = prev / "rootfs_no_gui" / "image-check"
    ic.mkdir(parents=True)
    cur = subprocess.run([sys.executable, "-I", str(ROOT / "tools" / "cra" / "image_check.py"), "--version"],
                         capture_output=True, text=True).stdout.split()
    (ic / "image-check.json").write_text(json.dumps({"schema": cur[0], "tool_version": cur[1], "status": "FAIL", "summary": "x"}))
    out = tmp_path / "res"
    rescan(tmp_path, "--rescan-from", prev, "--archive", a, "--out", out, "--no-upload", "--no-company")
    st = (out / "status.tsv").read_text()
    row = next(x for x in st.splitlines() if x.startswith("B-image-check-rootfs_no_gui\t"))
    assert "是 FAIL，不沿用" in row and "\tFAIL\t" not in row, st
    assert json.loads((out / "rootfs_no_gui" / "image-check" / "image-check.json").read_text())["tool_version"] == cur[1]
    (ic / "image-check.json").write_text(json.dumps({"schema": cur[0], "tool_version": "old", "status": "ATTENTION", "summary": "x"}))
    out2 = tmp_path / "res2"
    rescan(tmp_path, "--rescan-from", prev, "--out", out2, "--no-upload", "--no-company")
    st2 = (out2 / "status.tsv").read_text()
    assert re.search(r"^B-image-check-rootfs_no_gui\tNOT_RUN\t.*別的版本", st2, re.M), st2
    (ic / "image-check.json").unlink()
    out3 = tmp_path / "res3"
    os.environ["IMGCHECK_TIMEOUT"] = "0.001"
    try:
        rescan(tmp_path, "--rescan-from", prev, "--archive", a, "--out", out3, "--no-upload", "--no-company")
    finally:
        del os.environ["IMGCHECK_TIMEOUT"]
    st3 = (out3 / "status.tsv").read_text()
    assert re.search(r"^B-image-check-rootfs_no_gui\tFAIL\t.*逾時", st3, re.M), st3


def test_rescan_image_check_stops_on_group_term(tmp_path):
    """停止指令（kill -TERM -- -<PGID>）要立刻停得到 image_check 那一步（timeout 留在同一個行程群組）。"""
    import signal
    import time
    a = write_tar(tmp_path / "product-a.tbz2", rootfs_members("product-a/Linux_for_Tegra/rootfs_no_gui/"), mode="w:bz2")
    prev = prev_result(tmp_path, a)
    b = tmp_path / "bin"
    b.mkdir()
    for t in ("grype", "bwrap"):
        (b / t).write_text("#!/bin/sh\necho 'Version: 0.0.0'\n")
        (b / t).chmod(0o755)
    mark = tmp_path / "image-check-started"
    (b / "python3").write_text(f'#!/bin/sh\ncase "$*" in *image_check.py*--from*) : > "{mark}"; exec sleep 300;; esac\n'
                               f'exec "{sys.executable}" "$@"\n')
    (b / "python3").chmod(0o755)
    env = dict(os.environ, PATH=f"{b}:{os.environ['PATH']}", FLASHPKG_ALLOW_TMP_OUT="1", SCA_TOOLS_DIR=str(tmp_path / "none"),
               IMGCHECK_TIMEOUT="600")
    out = tmp_path / "res"
    p = subprocess.Popen(["bash", str(FP_SCRIPT), "--rescan-from", str(prev), "--archive", str(a), "--out", str(out), "--no-upload",
                          "--no-company"], env=env, start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        end = time.monotonic() + 120
        while not mark.exists() and p.poll() is None and time.monotonic() < end:
            time.sleep(0.2)
        assert mark.exists(), "image_check 那一步沒有開始"
        t0 = time.monotonic()
        os.killpg(p.pid, signal.SIGTERM)
        p.wait(timeout=30)
        assert time.monotonic() - t0 < 30
    finally:
        if p.poll() is None:
            os.killpg(p.pid, signal.SIGKILL)
            p.wait()
    st = (out / "status.tsv").read_text()
    assert "Z-interrupted\tFAIL" in st and "B-image-check-rootfs_no_gui" not in st, st


def test_rescan_md5_mismatch_stops(tmp_path):
    """檔名與大小相同，但和上一次核對過的 MD5 不同 → A-rescan FAIL（不重跑）。"""
    a = write_tar(tmp_path / "product-a.tbz2", rootfs_members("product-a/Linux_for_Tegra/rootfs_no_gui/"), mode="w:bz2")
    prev = prev_result(tmp_path, a, md5="a" * 32)
    out = tmp_path / "res"
    rescan(tmp_path, "--rescan-from", prev, "--archive", a, "--out", out, "--no-upload", "--no-company")
    st = (out / "status.tsv").read_text()
    assert "A-rescan\tFAIL" in st and "MD5" in st and "B-rescan-rootfs_no_gui" not in st, st


def test_rescan_without_previous_md5_is_attention(tmp_path):
    a = write_tar(tmp_path / "product-a.tbz2", rootfs_members("product-a/Linux_for_Tegra/rootfs_no_gui/"), mode="w:bz2")
    prev = prev_result(tmp_path, a)
    (prev / "status.tsv").write_text("stage\tstatus\tdetail\nA-md5\tNOT_RUN\t沒有 .md5\n")
    out = tmp_path / "res"
    rescan(tmp_path, "--rescan-from", prev, "--archive", a, "--out", out, "--no-upload", "--no-company")
    st = (out / "status.tsv").read_text()
    assert "A-rescan-md5\tATTENTION" in st and "A-md5\tOK" not in st and "B-rescan-rootfs_no_gui\tOK" in st, st


def test_rescan_argument_errors(tmp_path):
    a = write_tar(tmp_path / "product-a.tbz2", rootfs_members("product-a/Linux_for_Tegra/rootfs_no_gui/"), mode="w:bz2")
    prev = prev_result(tmp_path, a)
    assert rescan(tmp_path, "--rescan-from", tmp_path / "nothing").returncode == 64
    assert rescan(tmp_path, "--rescan-from", prev, "--md5", a).returncode == 64
    r = rescan(tmp_path, "--rescan-from", prev, "--md5")                       # 最後一個參數沒給值：不能無窮迴圈
    assert r.returncode == 64 and "--md5 要給值" in r.stderr
    s = FP_SCRIPT.read_text(encoding="utf-8")
    assert 'need="grype bwrap python3 curl"; [ -z "$RESCAN" ] && need="docker syft $need"' in s
    assert "TOOLS_DIR=${SCA_TOOLS_DIR:-/opt/sca-tools}" in s and "export PATH=$add:$PATH" in s
    assert '--kernel-build "${ARCHIVE:-$SRCDIR}" --kernel-build-prefix "$prefix"' in s


# ---------- PR #111 審查後補的情境（以 linux 6.8 的真實寫法為範本） ----------

REVIEW_TREE = dict(TREE)
REVIEW_TREE.update({
    "arch/arm64/Kbuild": "obj-y += kernel/ kvm/\n",
    # arch/arm64/kernel/Makefile：vdso 只在 subdir-（make clean 用）出現，實際經 vdso-wrap.o 的 incbin 編進核心
    "arch/arm64/kernel/Makefile": "obj-y += setup.o vdso-wrap.o\nsubdir- += vdso vdso32\n$(obj)/vdso-wrap.o: $(obj)/vdso/vdso.so\n",
    "arch/arm64/kernel/vdso/Makefile": ("obj-vdso := vgettimeofday.o note.o sigreturn.o\ntargets := $(obj-vdso) vdso.so\n"
                                        "obj-vdso := $(addprefix $(obj)/, $(obj-vdso))\n"),
    "arch/arm64/kvm/Makefile": "obj-y += hyp/\n",
    "arch/arm64/kvm/hyp/Makefile": "obj-y += nvhe/\n",
    # nVHE：hyp-obj-y 由自訂規則連成 kvm_nvhe.o，hyp-obj.o 沒有任何規則提到
    "arch/arm64/kvm/hyp/nvhe/Makefile": "hyp-obj-y := pkvm.o mem_protect.o\nobj-y := kvm_nvhe.o\n",
    # 條件區塊兩邊的 :=：另一邊的值也可能是實際的值
    "drivers/c2/Makefile": "ifdef CONFIG_Q\nEXTRA := x.o\nelse\nEXTRA :=\nendif\nobj-y += $(EXTRA)\nobj-$(CONFIG_NOPE) += x.o\n",
    "drivers/c3/Makefile": "define addobj\nobj-y += d.o\nendef\n$(eval $(call addobj))\nobj-$(CONFIG_NOPE) += d.o\n",
    "drivers/c4/Makefile": "$(eval obj-y += e.o)\nobj-$(CONFIG_NOPE) += e.o\n",
    "drivers/c5/Makefile": "obj-n += n.o\nobj- += empty.o\nsubdir-y += sy/\n",
    "drivers/c5/sy/Makefile": "obj-$(CONFIG_NOPE) += sy.o\n",
})
REVIEW_TREE["drivers/Makefile"] = TREE["drivers/Makefile"] + "obj-y += c2/ c3/ c4/ c5/\n"


@pytest.mark.parametrize("obj,want", [
    ("arch/arm64/kernel/vdso/vgettimeofday.o", None),   # subdir- 不算「沒編」；obj-vdso 不是 Kbuild 的後綴
    ("arch/arm64/kernel/vdso32/note.o", None),
    ("arch/arm64/kvm/hyp/nvhe/pkvm.o", None),           # hyp-obj-y：hyp-obj.o 沒被提到 → 不知道（不是「沒編」）
    ("arch/arm64/kernel/setup.o", True),
    ("drivers/c2/x.o", None),                           # 條件區塊裡的 := 合併
    ("drivers/c3/d.o", None),                           # define 區塊提到物件清單 → 看不懂
    ("drivers/c4/e.o", None),                           # $(eval …) 行
    ("drivers/c5/n.o", False),                          # obj-n、obj- 照舊是「沒編」
    ("drivers/c5/empty.o", False),
    ("drivers/c5/sy/sy.o", False),                      # subdir-y 照舊算進入資料夾
])
def test_review_makefile_patterns(obj, want):
    assert model(REVIEW_TREE).obj_built(obj).value is want


def test_suffix_atom_unknown_literal_suffix():
    assert kc.suffix_atom("vdso") is None and kc.suffix_atom("x") is None
    assert kc.suffix_atom("n").value is False and kc.suffix_atom("").value is False and kc.suffix_atom("y").value is True


def test_not_affected_cross_checks_shipped_modules():
    m = model()
    assert kc.judge_cve(m, ["drivers/foo/a.c"], set())[0] == "not_affected"
    # 模組目錄有同名的 .ko（例如 updates/ 底下 out-of-tree 的上游程式複本）→ 不知道
    d = kc.judge_cve(m, ["drivers/foo/a.c"], {"updates/nvidia-oot/a.ko"})
    assert d[0] == "unknown" and "same name" in d[1]
    # 組合物件的名稱也算：baz-objs := baz_main.o → baz.ko
    assert kc.judge_cve(m, ["drivers/bar/baz_main.c"], {"extra/baz.ko.zst"})[0] == "unknown"
    assert kc.judge_cve(m, ["drivers/bar/baz_main.c"], {"kernel/drivers/other/qux.ko"})[0] == "not_affected"
    # 樹內同一個組合模組（bar.ko 是 =m，extra.o 依 config 沒放進去）不算
    assert kc.judge_cve(m, ["drivers/bar/extra.c"], {"kernel/drivers/bar/bar.ko.zst"})[0] == "not_affected"
    assert kc.judge_cve(m, ["drivers/bar/extra.c"], {"updates/bar.ko"})[0] == "unknown"
    # 判定沒編的物件在模組目錄有自己的樹內模組：矛盾 → 不知道
    assert kc.judge_cve(m, ["drivers/foo/a.c"], {"kernel/drivers/foo/a.ko"})[0] == "unknown"
    # 沒有模組清單 → 無法核對 → 不知道
    assert kc.judge_cve(m, ["drivers/foo/a.c"], None)[0] == "unknown"


@pytest.mark.parametrize("path", ["lib/xz/xz_dec_bcj.c", "lib/decompress_unxz.c", "lib/lz4/lz4_decompress.c", "lib/xxhash.c",
                                  "fs/binfmt_elf.c"])
def test_files_included_by_other_sources_are_unknown(path):
    assert kc.classify_file(path)[0] == "unknown"


def test_value_options_without_value_exit_64(tmp_path):
    """要值的選項放在最後又沒給值：exit 64（以前 shift 2 失敗會無窮迴圈）。"""
    for script, opt in ((PILOT / "sca-scan", "--kernel-build"), (FP_SCRIPT, "--rescan-from"), (FP_SCRIPT, "--out")):
        p = subprocess.run(["bash", str(script), opt], capture_output=True, text=True, timeout=30)
        assert p.returncode == 64 and f"{opt} 要給值" in p.stderr, (script, opt)


# ---------- PR #111 第二次審查後補的情境 ----------

def test_non_object_variables_with_literal_suffix_do_not_poison_tree():
    """上游 6.8 根目錄 Kbuild 的 atomic-checks += $(addprefix …)、lib/Makefile 的 clean-files += …、init/ 的 build-version：
    不是物件清單，不能讓整棵樹變成不知道（第一次修正後 6.8 樹裡沒有任何 not_affected）。"""
    t = dict(TREE)
    t["Kbuild"] = TREE["Kbuild"] + ("atomic-checks += $(addprefix $(obj)/.checked-, atomic-arch-fallback.h atomic-instrumented.h)\n"
                                    "always-y += $(atomic-checks)\n")
    t["lib/Makefile"] = TREE["lib/Makefile"] + "clean-files += oid_registry_data.c\nhostprogs := gen_crc32table\n"
    t["init/Makefile"] = TREE["init/Makefile"] + "build-version = $(or $(KBUILD_BUILD_VERSION), $(build-version-auto))\n"
    t["drivers/c6/Makefile"] = "helper-list := h.o\nobj-$(CONFIG_NOPE) += h.o\n"     # 左邊不是 obj，但右邊是 .o：照樣不明
    t["drivers/Makefile"] = TREE["drivers/Makefile"] + "obj-y += c6/\n"
    m = model(t)
    assert m.obj_built("drivers/foo/a.o").value is False and m.obj_built("lib/liboff.o").value is False
    assert m.obj_built("drivers/c6/h.o").value is None
    assert kc.judge_cve(m, ["drivers/foo/a.c"], set())[0] == "not_affected"


def xe_tree(rule):
    t = dict(TREE)
    t["drivers/Makefile"] = TREE["drivers/Makefile"] + "obj-$(CONFIG_DRM_XE) += xe/\nobj-$(CONFIG_DRM_I915) += i915/\n"
    t["drivers/xe/Makefile"] = "obj-$(CONFIG_DRM_XE) += xe.o\nxe-y += xe_drv.o\n" + rule
    t["drivers/i915/Makefile"] = "obj-$(CONFIG_DRM_I915) += i915.o\ni915-y += display/intel_dp.o soc/intel_pch.o\n"
    return t


@pytest.mark.parametrize("rule", [
    "$(obj)/i915-display/%.o: $(srctree)/drivers/i915/display/%.c FORCE\n\t$(call if_changed_rule,cc_o_c)\n",   # xe 6.8 的寫法
    "$(obj)/i915-display/%.o: $(src)/../i915/display/%.c FORCE\n\t$(call if_changed_rule,cc_o_c)\n",
    "$(obj)/i915-display/intel_dp.o: $(srctree)/drivers/i915/display/intel_dp.c\n",
    "XE_I915 := $(srctree)/drivers/i915/display\n$(obj)/i915-display/%.o: $(XE_I915)/%.c\n",
])
def test_sources_compiled_by_another_directorys_rule(rule):
    """xe 的規則直接編譯 i915/display/*.c：i915 沒開也不能判 intel_dp.c 沒編（xe 有開時）。"""
    on = model(xe_tree(rule), CONFIG + "CONFIG_DRM_XE=m\n")
    r = on.obj_built("drivers/i915/display/intel_dp.o")
    assert r.value is None and "drivers/xe/Makefile has a rule that compiles" in r.why[0]
    assert on.obj_built("drivers/i915/soc/intel_pch.o").value is False            # 規則只涵蓋 display/
    off = model(xe_tree(rule))                                                      # xe 也沒開 → 照樣沒編
    assert off.obj_built("drivers/i915/display/intel_dp.o").value is False


def test_target_specific_variable_is_not_a_prerequisite():
    t = xe_tree("$(obj)/xe_drv.o: CFLAGS_EXTRA := $(srctree)/drivers/i915/display/%.c\n")
    assert model(t, CONFIG + "CONFIG_DRM_XE=m\n").obj_built("drivers/i915/display/intel_dp.o").value is False


def test_included_c_list_from_upstream():
    k, why = kc.classify_file("sound/pci/ens1370.c")                                # ens1371.c: #include "ens1370.c"
    assert k == "unknown" and "sound/pci/ens1371.c" in why
    assert kc.classify_file("lib/clz_ctz.c")[0] == "unknown"                         # arch/s390/boot 以 ../../../../lib/ include
    assert kc.classify_file("sound/pci/ens1371.c")[0] == "object"
    doc = json.loads((kc.INCLUDED_C_DATA / "kernel-included-c-6.8.json").read_text(encoding="utf-8"))
    assert doc["schema"] == kc.INCLUDED_C_SCHEMA and doc["kernel"] == "6.8" and len(doc["source"]["sha256"]) == 64


def test_included_c_list_missing_is_an_error(tmp_path, monkeypatch):
    monkeypatch.setattr(kc, "INCLUDED_C_DATA", tmp_path)
    kc.included_c.cache_clear()
    try:
        with pytest.raises(kc.InputError):
            kc.classify_file("drivers/foo/a.c")
        (tmp_path / "kernel-included-c-x.json").write_text('{"schema": "other", "files": {}}')
        with pytest.raises(kc.InputError):
            kc.included_c()
    finally:
        monkeypatch.undo()
        kc.included_c.cache_clear()


def test_included_c_generator(tmp_path):
    import io
    import tarfile
    src = tmp_path / "linux-x.tar.xz"
    members = {"linux-x/sound/pci/a.c": b'#include "b.c"\n', "linux-x/sound/pci/b.c": b"int b;\n",
               "linux-x/lib/z.c": b"int z;\n", "linux-x/arch/s390/boot/d.c": b'#include "../../../../lib/z.c"\n',
               "linux-x/tools/t.c": b'#include "../lib/y.c"\n', "linux-x/lib/y.c": b"int y;\n",
               "linux-x/drivers/g.c": b'#include "generated/none.c"\n'}
    with tarfile.open(src, "w:xz") as t:
        for n, data in members.items():
            ti = tarfile.TarInfo(n)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
        ln = tarfile.TarInfo("linux-x/sound/pci/link.c")
        ln.type, ln.linkname = tarfile.SYMTYPE, "/etc/passwd"
        t.addfile(ln)
    out = tmp_path / "out.json"
    gen = Path(kc.__file__).parent / "kernel_included_c.py"
    r = subprocess.run([sys.executable, "-I", str(gen), "--source", str(src), "--kernel", "x", "--out", str(out)],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    doc = json.loads(out.read_text())
    assert doc["files"] == {"lib/z.c": ["arch/s390/boot/d.c"], "sound/pci/b.c": ["sound/pci/a.c"]}   # tools/ 不算
    assert doc["unresolved"] == ["drivers/g.c: generated/none.c"] and doc["source"]["sha256_checked_against"] == "not checked"
    bad = subprocess.run([sys.executable, "-I", str(gen), "--source", str(src), "--kernel", "x", "--out", str(out),
                          "--source-sha256", "0" * 64], capture_output=True, text=True, timeout=60)
    assert bad.returncode == 1


def test_no_included_c_list_for_kernel_version_means_no_not_affected():
    """#include 的 .c 清單只有 6.8：其他主.次版本（例如 5.15）不判 not_affected，說明寫出缺清單；6.8 照常。"""
    assert kc.judge_cve(model(), ["drivers/foo/a.c"], set())[0] == "not_affected"
    old = model(config=CONFIG.replace("Linux/arm64 6.8.12 Kernel", "Linux/arm64 5.15.0 Kernel"))
    d = old.obj_built("drivers/foo/a.o")
    assert d.value is False                                   # Makefile 的判斷不變
    dec, detail, _, _ = kc.judge_cve(old, ["drivers/foo/a.c"], set())
    assert dec == "unknown" and "no list of #included .c files for kernel 5.15" in detail
    assert kc.judge_cve(old, ["drivers/foo/always.c"], set())[0] == "affected"   # 有編照樣是 affected
    assert kc.major_minor("6.8.12-1021-tegra") == "6.8" and "6.8" in kc.included_c_versions()


def test_rescan_provenance(tmp_path):
    """重跑：provenance.json 重算刷機包的 sha256；和上一次的不同 → A-rescan FAIL；沒給刷機包 → 沿用上一次的身分。"""
    a = write_tar(tmp_path / "product-a.tbz2", rootfs_members("product-a/Linux_for_Tegra/rootfs_no_gui/"), mode="w:bz2")
    prev = prev_result(tmp_path, a)
    sha = hashlib.sha256(a.read_bytes()).hexdigest()
    out, ev = tmp_path / "res", tmp_path / "evidence"
    ev.mkdir()
    rescan(tmp_path, "--rescan-from", prev, "--archive", a, "--out", out, "--no-upload", "--no-company", "--evidence-out", ev)
    st = (out / "status.tsv").read_text()
    pv = json.loads((out / "provenance.json").read_text())
    # --evidence-out：證據包記刷機包的 sha256 與掃描時的 commit（--no-upload 沒有秘密清單 → ATTENTION）
    assert re.search(r"^F-evidence\t(OK|ATTENTION)\t", st, re.M), st
    man = json.loads(next(ev.glob("*.manifest.json")).read_text())
    assert man["flash_package"]["sha256"] == sha and man["sca_center"]["scan_commit"] == pv["sca_center"]["commit"]
    assert man["flash_package"]["sha256_source"] == "computed"
    assert pv["source"]["sha256"] == sha and pv["carried_from"] is None and re.search(r"^A-provenance\t(OK|ATTENTION)\t", st, re.M), st
    assert f"A-md5\tOK\tmd5 {hashlib.md5(a.read_bytes()).hexdigest()}" in st and "這次重算 product-a.tbz2 相符" in st
    # 上一次記的 sha256 不同（同檔名、同大小、同 md5 也不算）：停止
    sb = out / "rootfs_no_gui" / "scan" / "sbom" / "sbom.cdx.json"
    if not sb.exists():
        sb.parent.mkdir(parents=True, exist_ok=True)
        sb.write_text((prev / "rootfs_no_gui" / "scan" / "sbom" / "sbom.cdx.json").read_text())
    bad = dict(pv, source=dict(pv["source"], sha256="0" * 64))
    (out / "provenance.json").write_text(json.dumps(bad))
    out2 = tmp_path / "res2"
    rescan(tmp_path, "--rescan-from", out, "--archive", a, "--out", out2, "--no-upload", "--no-company", "--evidence-out", tmp_path / "ev2")
    st2 = (out2 / "status.tsv").read_text()
    assert "A-provenance\tFAIL" in st2 and "A-rescan\tFAIL" in st2 and "C-scan" not in st2, st2
    assert "F-evidence\tNOT_RUN" in st2 and not (tmp_path / "ev2").exists()
    # 沒給刷機包：沿用上一次的身分（carried_from）
    (out / "provenance.json").write_text(json.dumps(pv))
    out3 = tmp_path / "res3"
    rescan(tmp_path, "--rescan-from", out, "--out", out3, "--no-upload", "--no-company")
    pv3 = json.loads((out3 / "provenance.json").read_text())
    assert pv3["source"]["sha256"] == sha and pv3["carried_from"] == "res"


# $( ) 裡的冒號（獨立審查 H1）：obj-$(CONFIG_X:m=y) 以前整行被略過，現在照常解析；不認得的寫法讓「沒編」降為不知道
COLON_TREE = dict(TREE, **{
    "drivers/foo/Makefile": TREE["drivers/foo/Makefile"] + "obj-$(CONFIG_BAR:m=y) += mapped.o\nobj-$(CONFIG_FOO_A:m=y) += mapped_off.o\n",
    "drivers/bar/Makefile": TREE["drivers/bar/Makefile"] + "bar-$(CONFIG_BAR:m=y) += member.o\nobj-$(CONFIG_BAZ:y=m) += odd.o\n",
})


@pytest.mark.parametrize("obj,want", [
    ("drivers/foo/mapped.o", True),        # CONFIG_BAR=m，:m=y → 編進核心（以前：沒有規則 → None）
    ("drivers/foo/mapped_off.o", False),   # CONFIG_FOO_A 沒開
    ("drivers/bar/member.o", True),        # 組合物件 bar 的成員
    ("drivers/bar/odd.o", None),           # 不認得的 $(CONFIG_X:…)：記成看不懂，不默默略過
    ("drivers/bar/extra.o", None),         # 同一個 Makefile 有看不懂的項目：原本「沒編」降為不知道
])
def test_colon_inside_variable_reference(obj, want):
    m = model(COLON_TREE)
    assert m.obj_built(obj).value is want
    a = kc.suffix_atom("$(CONFIG_BAR:m=y)")
    assert a.kind == "sym" and a.value == "CONFIG_BAR" and a.my is True
    assert kc.suffix_atom("$(subst m,y,$(CONFIG_BAR))").my is True and kc.suffix_atom("$(CONFIG_BAR)").my is False
    assert kc.colon_outside("a:b") and not kc.colon_outside("obj-$(CONFIG_X:m=y)")



# ---------- 第二次獨立審查（K2 負責人） ----------

def info_with_lists(order=b"", builtin=b"", ko=()):
    files = {tuple(k.split("/")): v.encode() for k, v in TREE.items()}
    mf = {}
    if order is not None:
        mf["modules.order"] = order
    if builtin is not None:
        mf["modules.builtin"] = builtin
    return kc.Model(kc.BuildInfo(files, CONFIG, "/x/.config", KVER, {"label": "t"}, {"ko": set(ko), "files": mf}))


def test_not_built_but_listed_in_module_lists_is_unknown():
    # H1：Kbuild 判沒編（CONFIG_FOO_A 沒開），映像的 modules.builtin 卻列了它 → 不判 not_affected
    m = info_with_lists(builtin=b"kernel/drivers/foo/a.ko\n")
    dec, detail, files, _ = kc.judge_cve(m, ["drivers/foo/a.c"], set())
    assert dec == "unknown" and "Kbuild says not built but modules.builtin/modules.order lists it" in detail
    assert files[0]["built"] is None
    m = info_with_lists(order=b"kernel/drivers/foo/a.ko\n")
    assert kc.judge_cve(m, ["drivers/foo/a.c"], set())[0] == "unknown"
    # 組合物件本身也沒編（baz-objs，CONFIG_BAZ 沒開）而清單有 baz.ko → unknown
    m = info_with_lists(builtin=b"kernel/drivers/bar/baz.ko\n")
    assert kc.judge_cve(m, ["drivers/bar/baz_main.c"], set())[0] == "unknown"
    # 組合物件有編（bar=m）、只是這個成員依 config 沒放進去：清單列 bar.ko 是正常的
    m = info_with_lists(order=b"kernel/drivers/bar/bar.ko\n", ko={"kernel/drivers/bar/bar.ko"})
    assert kc.judge_cve(m, ["drivers/bar/extra.c"], {"kernel/drivers/bar/bar.ko"})[0] == "not_affected"
    # 清單沒有擷取到：照舊（limitations 註明，見 CLI 測試）
    assert kc.judge_cve(info_with_lists(order=None, builtin=None), ["drivers/foo/a.c"], set())[0] == "not_affected"


def test_built_as_from_module_map():
    m = info_with_lists(order=b"kernel/drivers/bar/bar.ko\nkernel/drivers/bar/modonly.ko\n", builtin=b"kernel/drivers/foo/always.ko\n",
                        ko={"kernel/drivers/bar/bar.ko", "kernel/drivers/bar/modonly.ko"})
    km = kc.module_map()
    mf = m.info.modules["files"]
    mp = km.Mapper(m, m.info.modules["ko"], km.ModList(mf["modules.order"]), km.ModList(mf["modules.builtin"]))
    _, _, files, _ = kc.judge_cve(m, ["drivers/foo/always.c", "drivers/bar/core.c", "drivers/bar/modonly.c", "drivers/foo/a.c",
                                      "include/linux/x.h", "drivers/bar/cond.c"], m.info.modules["ko"], mp)
    assert [f["built_as"] for f in files] == ["builtin", "module", "module", None, None, None]
    assert [f["module"] for f in files] == [None, "bar", "modonly", None, None, None]
    assert [f["built"] for f in files] == [True, True, True, False, None, None]


def test_cli_built_as_and_missing_lists_limitation(tmp_path):
    p, st, out = run(tmp_path)
    by = {r["cve"]: r for r in out["results"]}
    assert by["CVE-2024-0002"]["files"] == [{"path": "drivers/foo/always.c", "configs": ["CONFIG_FOO"], "built": True, "built_as": "builtin",
                                                  "module": None}]
    assert out["limitations"] == kc.LIMITATIONS
    m = [x for x in rootfs_members() if not x[0].endswith(("modules.order", "modules.builtin"))]
    p, st, out = run(tmp_path, src=write_tar(tmp_path / "r2.tar", m))
    assert st[1] == "OK" and any("no modules.builtin / modules.order" in l for l in out["limitations"])


def test_docker_single_file_whiteout_and_linked_modules(tmp_path):
    # M2：上層的 .wh.<名稱>.ko 刪掉下層的一個 .ko；.ko 的符號連結與硬連結以連結的名稱算
    base = rootfs_members() + [(f"usr/lib/modules/{KVER}/kernel/drivers/x/gone.ko", b"x", None),
                               (f"usr/lib/modules/{KVER}/kernel/drivers/x/real.ko", b"x", None),
                               (f"usr/lib/modules/{KVER}/updates/dir/keep.ko", b"x", None)]
    upper = [(f"usr/lib/modules/{KVER}/kernel/drivers/x/.wh.gone.ko", b"", None),
             (f"usr/lib/modules/{KVER}/updates/.wh..wh..opq", b"", None),
             (f"usr/lib/modules/{KVER}/updates/new.ko", b"x", None),
             (f"usr/lib/modules/{KVER}/extra/sym.ko", None, "../kernel/drivers/x/real.ko"),
             (f"usr/lib/modules/{KVER}/extra/dangling.ko", None, "../kernel/drivers/x/gone.ko"),
             (f"usr/lib/modules/{KVER}/extra/outside.ko", None, "/opt/vendor/outside.ko")]
    col, src = kc.collect(str(docker_save(tmp_path, [base, upper])))
    info, gap = kc.locate(col, src, None)
    ko = info.modules["ko"]
    assert "kernel/drivers/x/gone.ko" not in ko and "kernel/drivers/x/real.ko" in ko
    assert "updates/dir/keep.ko" not in ko and "updates/new.ko" in ko
    assert "extra/sym.ko" in ko and "extra/outside.ko" in ko and "extra/dangling.ko" not in ko
    # 硬連結（rootfs tar）
    with tarfile.open(tmp_path / "h.tar", "w") as t:
        for name, data, link in rootfs_members():
            add(t, name, data, link)
        add(t, f"usr/lib/modules/{KVER}/extra/hard.ko", link=f"usr/lib/modules/{KVER}/kernel/drivers/bar/bar.ko.zst", kind="hard")
    col, src = kc.collect(str(tmp_path / "h.tar"))
    info, gap = kc.locate(col, src, None)
    assert "extra/hard.ko" in info.modules["ko"] and "kernel/drivers/bar/bar.ko.zst" in info.modules["ko"]



# ---------- 第三次審查（K2 負責人） ----------

COMP_TREE = dict(TREE, **{"drivers/foo/Makefile": TREE["drivers/foo/Makefile"] +
                          "obj-$(CONFIG_BAR) += cfoo.o\ncfoo-y := cmain.o\ncfoo-$(CONFIG_OFF) += cbar.o\n"})


def comp_model(order, builtin):
    files = {tuple(k.split("/")): v.encode() for k, v in COMP_TREE.items()}
    mf = {k: v for k, v in (("modules.order", order), ("modules.builtin", builtin)) if v is not None}
    return kc.Model(kc.BuildInfo(files, CONFIG, "/x/.config", KVER, {"label": "t"}, {"ko": {"kernel/drivers/foo/cfoo.ko"}, "files": mf}))


@pytest.mark.parametrize("order,builtin,want", [
    (b"kernel/drivers/foo/cfoo.ko\n", b"", "not_affected"),                                  # =m，清單一致
    (b"kernel/drivers/foo/cfoo.ko\n", b"kernel/drivers/foo/cfoo.ko\n", "unknown"),          # D：modules.builtin 也列了 cfoo
    (b"kernel/drivers/foo/other.ko\n", b"", "unknown"),                                      # E：modules.order 沒有 cfoo
    (b"kernel/drivers/other/cfoo.ko\n", b"", "unknown"),                                     # 路徑不同
    (None, None, "not_affected"),                                                              # 清單沒有擷取到：不核對
])
def test_configured_out_member_needs_consistent_composite(order, builtin, want):
    # N1：cbar.o 依 CONFIG_OFF 沒放進 cfoo（CONFIG_BAR=m 的組合模組）；組合模組本身要和映像的清單一致
    m = comp_model(order, builtin)
    dec, detail, files, _ = kc.judge_cve(m, ["drivers/foo/cbar.c"], {"kernel/drivers/foo/cfoo.ko"})
    assert dec == want, detail
    if want == "unknown":
        assert "configured-out member of the composite drivers/foo/cfoo.o" in detail


def test_builtin_composite_only_must_not_be_in_modules_order():
    # =y 的組合物件：modules.builtin 只列帶模組資訊的物件（bool 的 thermal_sys.o、acpi.o 不在裡面是正常的），只要求不在 modules.order
    cfg = CONFIG.replace("CONFIG_BAR=m", "CONFIG_BAR=y")
    files = {tuple(k.split("/")): v.encode() for k, v in COMP_TREE.items()}
    for order, builtin, want in ((b"", b"kernel/drivers/foo/cfoo.ko\n", "not_affected"),
                                 (b"", b"", "not_affected"),                                    # bool 組合物件，不在 modules.builtin
                                 (b"", b"kernel/drivers/other/x.ko\n", "not_affected"),
                                 (b"kernel/drivers/foo/cfoo.ko\n", b"", "unknown")):           # =y 卻在 modules.order
        m = kc.Model(kc.BuildInfo(files, cfg, "/x/.config", KVER, {"label": "t"},
                                  {"ko": set(), "files": {"modules.order": order, "modules.builtin": builtin}}))
        assert kc.judge_cve(m, ["drivers/foo/cbar.c"], set())[0] == want, (order, builtin)


def test_module_dir_directory_symlinks(tmp_path):
    # N2：模組目錄裡的資料夾連結（updates -> /opt/nv/updates）：底下的 .ko 以連結的路徑算；看不到目標 → present_gaps
    m = rootfs_members() + [(f"usr/lib/modules/{KVER}/updates", None, "/opt/nv/updates"),
                            ("opt/nv/updates/drivers/gpu/host1x.ko", b"x", None),
                            (f"usr/lib/modules/{KVER}/extra", None, "/opt/missing")]
    col, src = kc.collect(str(write_tar(tmp_path / "d.tar", m)))
    info, gap = kc.locate(col, src, None)
    assert "updates/drivers/gpu/host1x.ko" in info.modules["ko"]
    assert len(info.modules["present_gaps"]) == 1 and info.modules["present_gaps"][0].startswith("extra -> /opt/missing")


def test_cna_mirror_zip_sha256_recorded(tmp_path):
    p, st, out = run(tmp_path)
    src = dict(l.split("=", 1) for l in (tmp_path / "m" / "SOURCE").read_text().splitlines())
    assert out["cve_data"]["zip_sha256"] == src["zip_sha256"]


# ---------- 第四次審查（K2 負責人）：資料夾連結的目標 ----------

def kroot(tmp_path, extra, name="k.tar", hard=()):
    with tarfile.open(tmp_path / name, "w") as t:
        for n, data, link in rootfs_members() + list(extra):
            add(t, n, data, link)
        for n, target in hard:
            add(t, n, link=target, kind="hard")
    col, src = kc.collect(str(tmp_path / name))
    info, gap = kc.locate(col, src, KVER)
    assert gap is None
    return info.modules


def names(mods):
    return {os.path.basename(k).split(".ko")[0] for k in mods["ko"]}


def test_dir_link_target_with_symlinked_ko_is_a_gap(tmp_path):
    # 1：/opt/nv/updates/amod.ko 是符號連結（不跟隨）→ gap
    m = kroot(tmp_path, [(f"usr/lib/modules/{KVER}/updates", None, "/opt/nv/updates"), ("opt/nv/real/amod.ko", b"x", None),
                         ("opt/nv/updates/amod.ko", None, "../real/amod.ko")])
    assert "amod" in names(m) or m["present_gaps"], m["present_gaps"]
    assert m["present_gaps"] and "links that are not followed" in m["present_gaps"][0]


def test_dir_link_target_with_hardlinked_ko_lists_it(tmp_path):
    # 2：硬連結的 .ko 以名稱算
    m = kroot(tmp_path, [(f"usr/lib/modules/{KVER}/updates", None, "/opt/nv/updates"), ("opt/nv/real/x.ko", b"x", None)],
              hard=[("opt/nv/updates/amod.ko", "opt/nv/real/x.ko")])
    assert "amod" in names(m) and m["present_gaps"] == []


def test_dir_link_into_another_kernel_version(tmp_path):
    # 3：extra -> /usr/lib/modules/<另一個版本>/extra：列那個版本的 .ko；那裡面有連結 → gap
    other = "6.8.12-9999-tegra"
    m = kroot(tmp_path, [(f"usr/lib/modules/{KVER}/extra", None, f"/usr/lib/modules/{other}/extra"),
                         (f"usr/lib/modules/{other}/extra/amod.ko", b"x", None)])
    assert "amod" in names(m) and m["present_gaps"] == []
    m = kroot(tmp_path, [(f"usr/lib/modules/{KVER}/extra", None, f"/usr/lib/modules/{other}/extra"),
                         (f"usr/lib/modules/{other}/extra/bmod.ko", b"x", None),
                         (f"usr/lib/modules/{other}/extra/amod.ko", None, "/opt/amod.ko")], name="k2.tar")
    assert "bmod" in names(m) and m["present_gaps"] and f"kernel {other}" in m["present_gaps"][0]


def test_dir_link_target_containing_dir_link_is_a_gap(tmp_path):
    # 4：目標資料夾裡又有資料夾連結（sub -> /opt/real）
    m = kroot(tmp_path, [(f"usr/lib/modules/{KVER}/updates", None, "/opt/nv/updates"), ("opt/nv/updates/sub", None, "/opt/real"),
                         ("opt/real/amod.ko", b"x", None)])
    assert "amod" in names(m) or m["present_gaps"]
    assert m["present_gaps"]


def test_mutually_linked_dirs_are_fast(tmp_path):
    # R4-M1：d0..d6 彼此連結（每個資料夾裡都有連到其他資料夾的連結），以及 a -> b、b -> a 的循環
    import time
    n = 7
    ex = [(f"usr/lib/modules/{KVER}/d{i}/m{i}.ko", b"x", None) for i in range(n)]
    ex += [(f"usr/lib/modules/{KVER}/d{i}/to{j}", None, f"../d{j}") for i in range(n) for j in range(n) if i != j]
    ex += [(f"usr/lib/modules/{KVER}/a", None, "b"), (f"usr/lib/modules/{KVER}/b", None, "a")]
    t0 = time.monotonic()
    m = kroot(tmp_path, ex)
    assert time.monotonic() - t0 < 5
    assert {f"m{i}" for i in range(n)} <= names(m)
    assert any(g.startswith("a -> b") for g in m["present_gaps"]) and any(g.startswith("b -> a") for g in m["present_gaps"])


def test_path_index_cap_makes_dir_links_gaps(tmp_path, monkeypatch):
    # R4-L1：路徑索引超過上限 → 需要索引的資料夾連結記 gap
    monkeypatch.setattr(kc, "MAX_SEEN", 30)
    m = kroot(tmp_path, [(f"usr/lib/modules/{KVER}/updates", None, "/opt/nv/updates"), ("opt/nv/updates/amod.ko", b"x", None)])
    assert m["present_gaps"] and "path index" in m["present_gaps"][0]


def test_ko_link_to_regular_non_ko_file_counts(tmp_path):
    # R5-M1：kernel/a/foo.ko -> foo.ko.orig（一般檔案，名稱不是 .ko）：modprobe 會載入，算存在
    m = kroot(tmp_path, [(f"usr/lib/modules/{KVER}/kernel/a/foo.ko.orig", b"x", None),
                         (f"usr/lib/modules/{KVER}/kernel/a/foo.ko", None, "foo.ko.orig")])
    assert "foo" in names(m) and m["present_gaps"] == []


def test_ko_link_to_missing_target_is_a_gap(tmp_path):
    m = kroot(tmp_path, [(f"usr/lib/modules/{KVER}/kernel/a/gone.ko", None, "gone.ko.orig")])
    assert "gone" not in names(m) and m["present_gaps"] and m["present_gaps"][0].startswith("kernel/a/gone.ko -> gone.ko.orig")


# ---------- 燒錄的核心（kernel/Image）的內建設定（IKCONFIG） ----------
# 合成的 Image：一段假的二進位，中間放 IKCFG_ST＋gzip(config)＋IKCFG_ED（同 kernel/configs.c 的配置；讀法同 scripts/extract-ikconfig）

L4T = "product-a/Linux_for_Tegra"
CONFIG_ON = CONFIG.replace("# CONFIG_FOO_A is not set", "CONFIG_FOO_A=y")      # 廠商重編的核心：CONFIG_FOO_A 打開了
CONFIG_EXTRA = CONFIG + "CONFIG_VENDOR_ONLY=y\n"                                # 不影響任何判定的差異
KPKG, HPKG, KVERSION = "nvidia-l4t-kernel", "nvidia-l4t-kernel-headers", "5.15.148-tegra-39.2.1-20251201"


def fake_image(config=CONFIG, ikconfig=True, seed=b"A", gz=None):
    head = b"MZ\x00\x00ARM\x64" + bytes(range(256)) * 8 + seed * 64          # 假的 arm64 Image 開頭與程式
    if not ikconfig:
        return head + b"\x00" * 512 + b"IKCFG_ST but no gzip here" + b"\x00" * 64
    c = config if isinstance(config, bytes) else config.encode()
    return head + b"IKCFG_ST" + (gz if gz is not None else gzip.compress(c, mtime=0)) + b"IKCFG_ED" + b"\x00" * 512 + seed * 32


def md5(b):
    return hashlib.md5(b).hexdigest()


def dpkg_members(prefix="", image=None, kver=KVERSION, hver=KVERSION, kname=KPKG, image_path="boot/Image", headers=True, status=True,
                 md5sums=True, karch=None, hname=HPKG, hconfig=CONFIG.encode(), ksource=None, hsource=None):
    """rootfs 的 var/lib/dpkg（status 與 info/*.md5sums）。image：套件記的 /boot/Image 內容（md5 用）；hconfig：headers 套件記的
    .config 內容（md5 用）；ksource／hsource：status 的 Source 欄位。"""
    m = []
    if status:
        ks = f"Source: {ksource}\n" if ksource else ""
        hs = f"Source: {hsource}\n" if hsource else ""
        st = (f"Package: {kname}\nStatus: install ok installed\n{ks}Architecture: arm64\nVersion: {kver}\nDescription: kernel\n multi line\n\n"
              f"Package: {hname}\nStatus: install ok installed\n{hs}Architecture: arm64\nVersion: {hver}\n\n"
              f"Package: removed-thing\nStatus: deinstall ok config-files\nVersion: 1\n")
        m.append((f"{prefix}var/lib/dpkg/status", st.encode(), None))
    if md5sums:
        if image is not None:
            m.append((f"{prefix}var/lib/dpkg/info/{kname}{':' + karch if karch else ''}.md5sums",
                      f"{md5(b'x')}  usr/lib/modules/{KVER}/modules.order\n{md5(image)}  {image_path}\n".encode(), None))
        if headers:
            m.append((f"{prefix}var/lib/dpkg/info/{hname}:arm64.md5sums", f"{md5(hconfig)}  {HDR}/.config\nzz bad line\n".encode(), None))
        m.append((f"{prefix}var/lib/dpkg/info/other.md5sums", f"{md5(b'y')}  usr/bin/x\n".encode(), None))
    return m


def pkg_members(kernel_image=None, kernel_name="Image", boot_image=None, rootfs="rootfs", dpkg=None):
    m = rootfs_members(f"{L4T}/{rootfs}/") + [(f"{L4T}/flash.sh", b"#!/bin/sh\n", None)]
    if kernel_image is not None:
        m.append((f"{L4T}/kernel/{kernel_name}", kernel_image, None))
    if boot_image is not None:
        m.append((f"{L4T}/{rootfs}/boot/Image", boot_image, None))
    return m + [(f"{L4T}/{rootfs}/{n}", d, l) for n, d, l in (dpkg or [])]


def run_main(tmp_path, src, *extra):
    """kc.main 在同一個行程裡跑（可以 monkeypatch 上限）→ (退出碼, kernel-config.json)。"""
    tmp_path.mkdir(parents=True, exist_ok=True)
    g = tmp_path / "grype.json"
    g.write_text(json.dumps(grype(list(RECORDS) + ["CVE-2024-0404"])))
    km = tmp_path / "kmap.json"
    km.write_text(json.dumps(KMAP))
    mirror = make_mirror(tmp_path / "m")
    out = tmp_path / "kernel-config.json"
    rc = kc.main(["--grype", str(g), "--kernel-map", str(km), "--mirror", str(mirror), "--from", str(src), *extra, "--out", str(out)])
    return rc, (json.loads(out.read_text()) if out.exists() else None)


def run_pkg(tmp_path, members):
    tmp_path.mkdir(parents=True, exist_ok=True)
    a = write_tar(tmp_path / "p.tbz2", members, mode="w:bz2")
    return run_main(tmp_path, a, "--prefix", f"{L4T}/rootfs")


def baseline(tmp_path):
    (tmp_path / "base").mkdir()
    return run_main(tmp_path / "base", write_tar(tmp_path / "base" / "r.tar", rootfs_members()))[1]


def test_extract_ikconfig_raw_gzip_xz_and_missing():
    cfg, fmt, why, complete = kc.extract_ikconfig(fake_image())
    assert cfg == CONFIG.encode() and fmt == "raw" and why is None and complete is True
    cfg, fmt, why, complete = kc.extract_ikconfig(gzip.compress(fake_image()))   # Image 本身是 gzip（Image.gz）
    assert cfg == CONFIG.encode() and fmt == "gzip" and complete is True
    import lzma as _lzma
    cfg, fmt, why, _ = kc.extract_ikconfig(_lzma.compress(fake_image()))
    assert cfg == CONFIG.encode() and fmt == "xz"
    cfg, fmt, why, _ = kc.extract_ikconfig(fake_image(ikconfig=False))          # 沒開 CONFIG_IKCONFIG
    assert cfg is None and "no IKCONFIG" in why
    bad = fake_image().replace(b"IKCFG_ST\x1f\x8b\x08", b"IKCFG_ST\x1f\x8b\x08\xff\xff\xff\xff")
    cfg, fmt, why, _ = kc.extract_ikconfig(bad)                                 # 標記在、gzip 壞了：記原因，不中斷
    assert cfg is None and why.startswith("IKCONFIG:")
    nocfg = b"x" * 100 + b"IKCFG_ST" + gzip.compress(b"hello world\n") + b"IKCFG_ED"
    assert kc.extract_ikconfig(nocfg)[0] is None and "does not look like" in kc.extract_ikconfig(nocfg)[2]


def test_ikconfig_multi_member_gzip_is_read_whole():
    """多段 gzip：同 zcat 全部解開（只解第一段會抽到半份設定）。"""
    half = len(CONFIG) // 2
    gz = gzip.compress(CONFIG[:half].encode(), mtime=0) + gzip.compress(CONFIG[half:].encode(), mtime=0)
    cfg, fmt, why, complete = kc.extract_ikconfig(fake_image(gz=gz))
    assert cfg == CONFIG.encode() and complete is True and why is None
    # 第二段截斷、gzip 之後還有東西才到 IKCFG_ED、沒有 IKCFG_ED：不完整
    for g in (gz[:-30], gzip.compress(CONFIG.encode()) + b"junk"):
        cfg, _, why, complete = kc.extract_ikconfig(fake_image(gz=g))
        assert cfg is not None and complete is False and "incomplete" in why
    img = fake_image().replace(b"IKCFG_ED", b"XXXXXXXX")
    cfg, _, why, complete = kc.extract_ikconfig(img)
    assert cfg == CONFIG.encode() and complete is False and "IKCFG_ED" in why


def test_ikconfig_size_limits(monkeypatch):
    img = fake_image()
    monkeypatch.setattr(kc, "MAX_IKCONFIG", 100)                               # 解出來的 config
    cfg, _, why, _ = kc.extract_ikconfig(img)
    assert cfg is None and "limit" in why
    monkeypatch.setattr(kc, "MAX_IKCONFIG", 8 << 20)
    monkeypatch.setattr(kc, "MAX_IMAGE_UNPACKED", 1000)                         # 解壓後的 Image
    cfg, fmt, why, _ = kc.extract_ikconfig(gzip.compress(img))
    assert cfg is None and fmt == "gzip" and "limit" in why
    monkeypatch.setattr(kc, "MAX_IMAGE", 1000)                                  # 壓縮前的 Image：只算 sha256／md5
    r = kc.probe_stream("kernel/Image", io.BytesIO(img), len(img))
    assert r.config is None and "larger than" in r.reason and r.sha256 == hashlib.sha256(img).hexdigest() and r.md5 == md5(img)
    r = kc.probe_stream("kernel/Image", io.BytesIO(img), None)                  # 沒有宣告大小：讀的時候才超過
    assert r.config is None and "larger than" in r.reason and r.sha256 == hashlib.sha256(img).hexdigest()
    cfg, fmt, why, _ = kc.extract_ikconfig(gzip.compress(img)[:200])           # 壞掉的 gzip（Image.gz 截斷）
    assert cfg is None and fmt == "gzip" and "truncated" in why


def test_flash_package_ikconfig_same_as_headers(tmp_path):
    base = baseline(tmp_path)
    rc, out = run_pkg(tmp_path, pkg_members(fake_image(), boot_image=fake_image(seed=b"B")))
    assert rc == 0 and out["status"] == "OK"
    k = out["kernel"]
    assert k["config_source"] == f"/{HDR}/.config" and k["config_sha256"] == hashlib.sha256(CONFIG.encode()).hexdigest()
    c = k["config_check"]
    assert c["result"] == "same" and c["image_source"] == "flash package" and c["image"]["path"] == f"{L4T}/kernel/Image"
    assert c["image"]["ikconfig"] is True and c["image"]["ikconfig_complete"] is True and c["image_config_sha256"] == k["config_sha256"]
    assert c["rootfs_image"]["sha256"] == hashlib.sha256(fake_image(seed=b"B")).hexdigest()
    assert "相同" in out["detail"] and out["results"] == base["results"] and out["counts"] == base["counts"]


def test_flash_package_ikconfig_differs_uses_image_config(tmp_path):
    base = baseline(tmp_path)
    rc, out = run_pkg(tmp_path, pkg_members(fake_image(CONFIG_ON), boot_image=fake_image()))
    assert rc == 0 and out["status"] == "ATTENTION"
    assert out["detail"].startswith("headers .config 和燒錄的核心不同，已改用燒錄核心的內建設定（kernel/Image 的 IKCONFIG；差 1 個設定")
    k = out["kernel"]
    assert k["config_source"] == "kernel/Image (IKCONFIG)" and k["config_sha256"] == hashlib.sha256(CONFIG_ON.encode()).hexdigest()
    c = k["config_check"]
    assert c["result"] == "differs" and c["headers_config"] == {"path": f"/{HDR}/.config", "sha256": hashlib.sha256(CONFIG.encode()).hexdigest()}
    assert c["image_config_sha256"] == k["config_sha256"] and c["differences_total"] == 1 and c["differences_truncated"] is False
    assert c["differences"] == [{"name": "CONFIG_FOO_A", "headers": "n", "image": "y", "toolchain": False}] and c["image"]["ikconfig_complete"] is True
    by, bb = {r["cve"]: r for r in out["results"]}, {r["cve"]: r for r in base["results"]}
    # 判定的規則不變，只換設定：drivers/foo/a.c 在燒錄的核心有編
    assert bb["CVE-2024-0001"]["decision"] == "not_affected" and by["CVE-2024-0001"]["decision"] == "affected"
    assert by["CVE-2024-0002"] == bb["CVE-2024-0002"] and by["CVE-2024-0003"] == bb["CVE-2024-0003"]
    # 讀取端採用（完整的 IKCONFIG）：affected 也在 kconfig_all
    assert vex_export().kconfig_all(out)["CVE-2024-0001"] == "affected"


def kernel_row(cves):
    return {"kernel": True, "cves": cves, "purl": TEGRA["purl"], "name": TEGRA["name"], "version": TEGRA["version"]}


def test_reader_uses_complete_ikconfig_differs(tmp_path):
    """決定 1：differs、config_source 是 IKCONFIG、IKCONFIG 完整 → K1 照用（status 維持 ATTENTION），說明寫依燒錄核心的內建設定。"""
    rc, out = run_pkg(tmp_path, pkg_members(fake_image(CONFIG_EXTRA), boot_image=fake_image()))
    vx = vex_export()
    sha = hashlib.sha256(CONFIG_EXTRA.encode()).hexdigest()
    assert out["status"] == "ATTENTION" and out["kernel"]["config_check"]["image"]["ikconfig_complete"] is True
    idx = vx.kconfig_index(out)
    assert set(idx) == {"CVE-2024-0001", "CVE-2025-0005"} and vx.kconfig_usable(out)
    s = vx.from_kconfig(kernel_row(["CVE-2024-0001"]), idx, out)
    assert s["state"] == "not_affected" and f"based on the flashed kernel's built-in configuration (IKCONFIG sha {sha[:12]}); the headers .config differs from it in 1 option(s)" in s["detail"]
    ev = vx.ev_k1(kernel_row(["CVE-2024-0001"]), {"kidx": idx, "kcfg": out, "kcfg_sha": out["kernel"]["config_sha256"]})
    assert ev["decision"] == "not_affected" and "IKCONFIG sha" in ev["detail"] and ev["inputs"].startswith("kernel IKCONFIG SHA-256")
    # 其他原因的 ATTENTION、欄位對不上：不採用
    for bad in ({**out, "kernel": {**out["kernel"], "config_source": f"/{HDR}/.config"}},
                {**out, "kernel": {**out["kernel"], "config_sha256": "0" * 64}},
                {**out, "kernel": {k: v for k, v in out["kernel"].items() if k != "config_check"}},
                {**out, "kernel": {**out["kernel"], "config_check": {**out["kernel"]["config_check"], "result": "same"}}}):
        assert vx.kconfig_index(bad) == {} and vx.kconfig_all(bad) == {} and not vx.kconfig_usable(bad)
    # status OK 的輸出沒有這一句
    base = baseline(tmp_path)
    assert "IKCONFIG" not in vx.from_kconfig(kernel_row(["CVE-2024-0001"]), vx.kconfig_index(base), base)["detail"]


def test_reader_rejects_incomplete_ikconfig_differs(tmp_path):
    """differs 但 IKCONFIG 不完整（gzip 之後到 IKCFG_ED 之間還有東西）：K1、K2 都不用。"""
    gz = gzip.compress(CONFIG_EXTRA.encode(), mtime=0) + b"junk"
    members = pkg_members(fake_image(gz=gz), boot_image=fake_image())
    rc, out = run_pkg(tmp_path, members)
    c = out["kernel"]["config_check"]
    assert out["status"] == "ATTENTION" and c["result"] == "differs" and c["image"]["ikconfig_complete"] is False
    assert "IKCONFIG 不完整" in out["detail"]
    vx = vex_export()
    assert vx.kconfig_index(out) == {} and vx.kconfig_all(out) == {} and not vx.kconfig_usable(out)
    mrc, mm = run_module_map(tmp_path / "mm", tmp_path / "p.tbz2", "--prefix", f"{L4T}/rootfs")
    assert mm["status"] == "GAP" and "IKCONFIG 不完整" in mm["detail"] and mm["sources"]["config_check"]["ikconfig_complete"] is False


def test_non_utf8_ikconfig_sha256_from_raw_bytes(tmp_path):
    raw = CONFIG_EXTRA.encode() + b'CONFIG_NAME="t\xe9gra"\n'                    # latin-1，不是 UTF-8
    rc, out = run_pkg(tmp_path, pkg_members(fake_image(raw)))
    k = out["kernel"]
    assert out["status"] == "ATTENTION" and k["config_sha256"] == hashlib.sha256(raw).hexdigest() == k["config_check"]["image_config_sha256"]
    assert k["config_check"]["image"]["ikconfig_sha256"] == k["config_sha256"]


def run_module_map(tmp_path, src, *extra, kconfig=None, mirror=None):
    """mirror：和 kernel-config.json 同一份 CNA 鏡像（zip 有時間戳，另做一份 sha256 可能不同，對應表會 GAP）。"""
    import kernel_module_map as kmm
    tmp_path.mkdir(parents=True, exist_ok=True)
    g = tmp_path / "grype.json"
    g.write_text(json.dumps(grype(list(RECORDS))))
    km = tmp_path / "kmap.json"
    km.write_text(json.dumps(KMAP))
    out = tmp_path / "kernel-module-map.json"
    args = ["--grype", str(g), "--kernel-map", str(km), "--mirror", str(mirror or make_mirror(tmp_path / "m")), "--from", str(src), *extra,
            "--out", str(out)] + (["--kernel-config", str(kconfig)] if kconfig else [])
    rc = kmm.main(args)
    return rc, (json.loads(out.read_text()) if out.exists() else None)


def test_module_map_uses_the_same_config_source(tmp_path):
    """決定 2：C-kernel-module-map 用和 C-kernel-config 同一份設定（kc.settle_config），sources 記 config_source 與 sha。"""
    rc, out = run_pkg(tmp_path, pkg_members(fake_image(CONFIG_ON), boot_image=fake_image()))
    (tmp_path / "kc.json").write_text(json.dumps(out))
    mrc, mm = run_module_map(tmp_path / "mm", tmp_path / "p.tbz2", "--prefix", f"{L4T}/rootfs", kconfig=tmp_path / "kc.json", mirror=tmp_path / "m")
    assert mm["status"] == "OK", mm["detail"]
    assert mm["sources"]["config"] == "kernel/Image (IKCONFIG)" == mm["kernel"]["config_source"]
    assert mm["sources"]["config_sha256"] == out["kernel"]["config_sha256"] == hashlib.sha256(CONFIG_ON.encode()).hexdigest()
    sc = mm["sources"]["config_check"]
    assert sc["result"] == "differs" and sc["config_source"] == "kernel/Image (IKCONFIG)" and sc["differences_total"] == 1
    assert mm["cves"]["CVE-2024-0001"]["files"][0]["build"] == "builtin"          # CONFIG_FOO_A=y（燒錄的核心）
    # 兩邊的設定不同（例如 kernel-config.json 是另一次執行的）→ GAP
    other = dict(out, kernel=dict(out["kernel"], config_sha256="0" * 64))
    (tmp_path / "kc2.json").write_text(json.dumps(other))
    mrc, mm2 = run_module_map(tmp_path / "mm2", tmp_path / "p.tbz2", "--prefix", f"{L4T}/rootfs", kconfig=tmp_path / "kc2.json", mirror=tmp_path / "m")
    assert mm2["status"] == "GAP" and "不能並用" in mm2["detail"]
    # dpkg 驗證不成立（K1 GAP）→ 對應表也 GAP
    a = write_tar(tmp_path / "q.tbz2", pkg_members(fake_image(ikconfig=False), boot_image=fake_image(ikconfig=False, seed=b"Z")), mode="w:bz2")
    mrc, mm3 = run_module_map(tmp_path / "mm3", a, "--prefix", f"{L4T}/rootfs")
    assert mm3["status"] == "GAP" and "dpkg 驗證不成立" in mm3["detail"]


def test_config_diff_list_is_capped(tmp_path, monkeypatch):
    monkeypatch.setattr(kc, "MAX_CONFIG_DIFF", 3)
    monkeypatch.setattr(kc, "MAX_DIFF_VALUE", 10)
    extra = "".join(f"CONFIG_NEW{i}=y\n" for i in range(10)) + 'CONFIG_LONG="' + "x" * 50 + '"\n'
    rc, out = run_pkg(tmp_path, pkg_members(fake_image(CONFIG + extra)))
    c = out["kernel"]["config_check"]
    assert out["status"] == "ATTENTION" and c["differences_total"] == 11 and c["differences_truncated"] is True and len(c["differences"]) == 3
    assert c["differences"][0] == {"name": "CONFIG_LONG", "headers": None, "image": "x" * 10 + "…", "toolchain": False}


def test_flash_package_image_gz(tmp_path):
    rc, out = run_pkg(tmp_path, pkg_members(gzip.compress(fake_image(CONFIG_ON)), kernel_name="Image.gz"))
    k = out["kernel"]
    assert out["status"] == "ATTENTION" and k["config_source"] == "kernel/Image.gz (IKCONFIG)"
    assert k["config_check"]["image"]["format"] == "gzip" and k["config_check"]["rootfs_image"] is None


# ---- 讀不到 IKCONFIG：dpkg 驗證 ----

STOCK = fake_image(ikconfig=False)                       # 原廠核心（沒有 IKCONFIG）
REBUILT = fake_image(ikconfig=False, seed=b"R")          # 廠商重編、也沒有 IKCONFIG


DPKG_CASES = [
    ("stock", STOCK, STOCK, dict(image=STOCK), "OK", None),
    ("stock-arch-qualified", STOCK, STOCK, dict(image=STOCK, karch="arm64"), "OK", None),     # <套件>:<架構>.md5sums
    ("rebuilt-both", REBUILT, REBUILT, dict(image=STOCK), "GAP", "第 1 項不成立"),           # 重編的核心蓋了 /boot/Image 也蓋了 kernel/Image
    ("rebuilt-kernel-only", REBUILT, STOCK, dict(image=STOCK), "GAP", "第 2 項不成立"),       # product-a：rootfs 相符、kernel/Image 不符
    ("version", STOCK, STOCK, dict(image=STOCK, hver="5.15.148-tegra-39.2.0"), "GAP", "第 3 項不成立"),
    ("no-owner", STOCK, STOCK, dict(image=STOCK, image_path="boot/Image.old"), "GAP", "找不到擁有 boot/Image 的套件"),
    ("no-headers-owner", STOCK, STOCK, dict(image=STOCK, headers=False), "GAP", "找不到擁有 usr/src/"),
    ("no-md5sums", STOCK, STOCK, dict(image=STOCK, md5sums=False), "GAP", "讀不到 dpkg 的 md5sums"),
    ("no-status", STOCK, STOCK, dict(image=STOCK, status=False), "GAP", "讀不到 var/lib/dpkg/status"),
    ("no-boot-image", STOCK, None, dict(image=STOCK), "GAP", "rootfs 沒有 /boot/Image"),
    # 第三輪：headers 的 .config 被改過（md5 和 headers 套件記的不同），例如為了編 out-of-tree 模組複製進來的
    ("headers-config-modified", STOCK, STOCK, dict(image=STOCK, hconfig=b"CONFIG_OTHER=y\n"), "GAP", "第 3 項不成立：headers 的"),
    # 核心套件和 headers 套件不是同一組：/boot/Image 是 RT 核心的、headers 是一般核心的（同版本，設定不同，例如 PREEMPT_RT）
    ("rt-kernel-generic-headers", STOCK, STOCK, dict(image=STOCK, kname="nvidia-l4t-rt-kernel"), "GAP", "不是同一組"),
    ("rt-kernel-rt-headers", STOCK, STOCK, dict(image=STOCK, kname="nvidia-l4t-rt-kernel", hname="nvidia-l4t-rt-kernel-headers"), "OK", None),
    ("ubuntu-names", STOCK, STOCK, dict(image=STOCK, kname="linux-image-6.8.0-45-generic", hname="linux-headers-6.8.0-45-generic"), "OK", None),
    ("ubuntu-common-headers", STOCK, STOCK, dict(image=STOCK, kname="linux-image-6.8.0-45-generic", hname="linux-headers-6.8.0-45"),
     "GAP", "不是同一組"),
    ("same-source", STOCK, STOCK, dict(image=STOCK, kname="vendor-kernel", hname="vendor-kernel-hdr", ksource="vendor-linux",
                                       hsource="vendor-linux (1.0)"), "GAP", "Source 相同也不算"),   # RT／一般核心可能同一個 Source
    ("other-source", STOCK, STOCK, dict(image=STOCK, kname="vendor-kernel", hname="vendor-kernel-hdr", ksource="a", hsource="b"),
     "GAP", "不是同一組"),
]


@pytest.mark.parametrize("case,kernel,boot,dpkg,status,msg", DPKG_CASES, ids=[c[0] for c in DPKG_CASES])
def test_flash_package_without_ikconfig_dpkg(tmp_path, case, kernel, boot, dpkg, status, msg):
    base = baseline(tmp_path)
    rc, out = run_pkg(tmp_path, pkg_members(kernel, boot_image=boot, dpkg=dpkg_members(**dpkg)))
    k, c = out["kernel"], out["kernel"]["config_check"]
    assert rc == 0 and out["status"] == status, out["detail"]
    assert k["config_source"] == f"/{HDR}/.config" and c["image"]["ikconfig"] is False
    if status == "OK":
        kn = dpkg.get("kname", KPKG)
        assert c["result"] == "dpkg_verified" and c["dpkg"]["kernel_package"] == {
            "name": kn, "arch": dpkg.get("karch"), "version": KVERSION, "path": "boot/Image", "md5": md5(STOCK),
            "source": (dpkg.get("ksource") or kn)}
        hp = c["dpkg"]["headers_package"]
        assert hp["name"] == dpkg.get("hname", HPKG) and hp["arch"] == "arm64" and hp["md5"] == md5(CONFIG.encode())
        assert all(x["ok"] for x in c["dpkg"]["checks"]) and len(c["dpkg"]["checks"]) == 5
        assert c["dpkg"]["checks"][-1]["rule"]
        assert "dpkg 驗證通過" in out["detail"] and out["results"] == base["results"]
    else:
        # GAP：說明寫是哪一項；沒有任何判定（K1 不會給 not_affected）
        assert c["result"] == "dpkg_not_verified" and msg in c["dpkg"]["failed"]
        assert "燒錄的核心和 headers 可能不一致，無法確認設定" in out["detail"] and msg in out["detail"]
        assert out["results"] == [] and out["counts"] == {"not_affected": 0, "affected": 0, "unknown": 0}
        assert vex_export().kconfig_index(out) == {} and vex_export().kconfig_all(out) == {}


def test_rootfs_only_without_ikconfig_dpkg(tmp_path):
    """只有 rootfs、沒有 IKCONFIG：dpkg 驗證只有第 1、3 項。"""
    src = write_tar(tmp_path / "r.tar", rootfs_members() + [("boot/Image", STOCK, None)] + dpkg_members(image=STOCK))
    rc, out = run_main(tmp_path, src)
    c = out["kernel"]["config_check"]
    assert out["status"] == "OK" and c["result"] == "dpkg_verified" and len(c["dpkg"]["checks"]) == 4 and "rootfs_image" not in c
    assert "只有 rootfs，看不到實際燒錄的 kernel/Image" in out["detail"] and "kernel/Image is not visible" in c["note"]
    src = write_tar(tmp_path / "r2.tar", rootfs_members() + [("boot/Image", STOCK, None)] + dpkg_members(image=REBUILT))
    rc, out = run_main(tmp_path / "2", src)
    assert out["status"] == "GAP" and "第 1 項不成立" in out["detail"] and vex_export().kconfig_index(out) == {}


def test_dpkg_status_size_limit_and_docker_whiteout(tmp_path, monkeypatch):
    monkeypatch.setattr(kc, "MAX_DPKG_STATUS", 10)
    src = write_tar(tmp_path / "r.tar", rootfs_members() + [("boot/Image", STOCK, None)] + dpkg_members(image=STOCK))
    rc, out = run_main(tmp_path, src)
    assert out["status"] == "GAP" and "limit" in out["detail"]
    monkeypatch.setattr(kc, "MAX_DPKG_STATUS", 32 << 20)
    # 上層刪掉核心套件的 md5sums：找不到擁有者
    img = docker_save(tmp_path, [rootfs_members() + [("boot/Image", STOCK, None)] + dpkg_members(image=STOCK),
                                 [(f"var/lib/dpkg/info/.wh.{KPKG}.md5sums", b"", None)]])
    rc, out = run_main(tmp_path / "d", img)
    assert out["status"] == "GAP" and "找不到擁有 boot/Image 的套件" in out["detail"]


def test_dpkg_md5sums_parsing_is_normalized():
    got = kc.md5sums_lines(b"%s  /boot/Image\n%s  ./boot/./dtb/x.dtb\n%s  ../../boot/evil\n%s  usr/bin/x\n%s *usr/src/h/.config\nnot a line\n"
                           % tuple(md5(bytes([i])).encode() for i in range(5)))
    assert set(got) == {"boot/Image", "boot/dtb/x.dtb", "usr/src/h/.config"}
    v = kc.dpkg_status_versions(b"Package: a\nStatus: install ok installed\nVersion: 1\n\nPackage: b\nStatus: deinstall ok config-files\n"
                                b"Version: 2\n\nPackage: a\nStatus: install ok installed\nArchitecture: armhf\nVersion: 3\n")
    assert v == {"a": {(None, "1", "a"), ("armhf", "3", "a")}}
    assert kc.dpkg_version(v, "a", None)[0] is None and "多個版本" in kc.dpkg_version(v, "a", None)[1]


def test_flash_package_oversized_image_is_recorded_not_fatal(tmp_path, monkeypatch):
    monkeypatch.setattr(kc, "MAX_IMAGE", 1000)
    img = fake_image(CONFIG_ON)
    rc, out = run_pkg(tmp_path, pkg_members(img, boot_image=fake_image()))
    c = out["kernel"]["config_check"]
    assert rc == 0 and out["status"] == "GAP" and c["result"] == "dpkg_not_verified"
    assert "larger than" in c["image"]["reason"] and c["image"]["sha256"] == hashlib.sha256(img).hexdigest()


def test_unpacked_flash_package_directory(tmp_path):
    """解開的 Linux_for_Tegra 資料夾＋--prefix rootfs：kernel/Image 用 lstat／O_NOFOLLOW 讀，符號連結不跟隨。"""
    d = tmp_path / "pkg"
    with tarfile.open(write_tar(tmp_path / "p.tar", pkg_members(fake_image(CONFIG_ON)))) as t:
        t.extractall(d, filter="tar")
    rc, out = run_main(tmp_path, d / L4T, "--prefix", "rootfs")
    assert out["status"] == "ATTENTION" and out["kernel"]["config_source"] == "kernel/Image (IKCONFIG)"
    assert out["kernel"]["config_check"]["image"]["path"] == "kernel/Image"
    (d / L4T / "kernel" / "Image").unlink()
    (d / L4T / "kernel" / "Image").symlink_to(tmp_path / "p.tar")
    rc, out = run_main(tmp_path, d / L4T, "--prefix", "rootfs")
    c = out["kernel"]["config_check"]
    assert out["status"] == "GAP" and "not followed" in c["image"]["reason"] and c["image"]["sha256"] is None


@pytest.mark.parametrize("img,status,result", [(fake_image(), "OK", "same"), (fake_image(CONFIG_ON), "ATTENTION", "differs")],
                         ids=["same", "differs"])
def test_rootfs_only_boot_image(tmp_path, img, status, result):
    """只有 rootfs（不是刷機包）：讀 rootfs 的 /boot/Image。"""
    src = write_tar(tmp_path / "r.tar", rootfs_members() + [("boot/Image", img, None)])
    rc, out = run_main(tmp_path, src)
    k = out["kernel"]
    assert out["status"] == status and k["config_check"]["result"] == result and k["config_check"]["image_source"] == "rootfs"
    assert "rootfs_image" not in k["config_check"] and k["config_check"]["image"]["path"] == "/boot/Image"
    assert k["config_source"] == ("/boot/Image (IKCONFIG)" if status == "ATTENTION" else f"/{HDR}/.config")


@pytest.mark.parametrize("link,want", ids=["relative", "absolute", "dotdot", "dir-link", "hardlink"], argvalues=[
    (("Image-5.15", "sym"), "/boot/Image-5.15"),                       # 相對
    (("/boot/Image-5.15", "sym"), "/boot/Image-5.15"),                 # 絕對：以映像的根解開
    (("../../../../boot/Image-5.15", "sym"), "/boot/Image-5.15"),      # .. 不會超出映像的根
    (("cur/Image-5.15", "sym2"), "/boot/real/Image-5.15"),             # 經過 /boot 底下的資料夾連結
    (("boot/Image-5.15", "hard"), "/boot/Image-5.15"),                 # tar 的硬連結
])
def test_boot_image_links_resolved_inside_image(tmp_path, link, want):
    tgt, kind = link
    if kind == "sym2":
        extra = [("boot/real/Image-5.15", fake_image(CONFIG_ON), None), ("boot/cur", None, "real"), ("boot/Image", None, tgt)]
    else:
        extra = [("boot/Image-5.15", fake_image(CONFIG_ON), None)]
    p = tmp_path / "r.tar"
    with tarfile.open(p, "w") as t:
        for name, data, ln in rootfs_members() + extra:
            add(t, name, data, ln)
        if kind != "sym2":
            add(t, "boot/Image", link=tgt, kind="hard" if kind == "hard" else None)
    rc, out = run_main(tmp_path, p)
    c = out["kernel"]["config_check"]
    assert out["status"] == "ATTENTION" and c["image"]["path"] == "/boot/Image" and c["image"]["link_target"] == want
    assert out["kernel"]["config_source"] == "/boot/Image (IKCONFIG)"


def test_boot_image_link_outside_boot_is_not_read(tmp_path):
    src = write_tar(tmp_path / "r.tar", rootfs_members() + [("usr/lib/linux/Image", fake_image(CONFIG_ON), None),
                                                            ("boot/Image", None, "/usr/lib/linux/Image")])
    rc, out = run_main(tmp_path, src)
    c = out["kernel"]["config_check"]
    assert out["status"] == "GAP" and "was not read" in c["image"]["reason"] and c["image"]["sha256"] is None
    # 解開的資料夾：連結只在映像裡解開（指到主機上的檔案也不讀）
    d = tmp_path / "root"
    with tarfile.open(write_tar(tmp_path / "r2.tar", rootfs_members())) as t:
        t.extractall(d, filter="tar")
    (tmp_path / "host-Image").write_bytes(fake_image(CONFIG_ON))
    (d / "boot").mkdir()
    (d / "boot" / "Image").symlink_to(tmp_path / "host-Image")
    rc, out = run_main(tmp_path / "x", d)
    assert out["status"] == "GAP" and "was not read" in out["kernel"]["config_check"]["image"]["reason"]


def test_docker_whiteout_removes_boot_image(tmp_path):
    img = docker_save(tmp_path, [rootfs_members() + [("boot/Image", fake_image(CONFIG_ON), None)], [("boot/.wh.Image", b"", None)]])
    rc, out = run_main(tmp_path, img)
    assert out["status"] == "OK" and "config_check" not in out["kernel"]


def test_no_kernel_image_output_unchanged(tmp_path):
    """沒有 kernel/Image、也沒有 /boot/Image 的舊輸入：沒有 config_check，kernel 的欄位和以前一樣（與 main 逐位元組相同另以腳本核對）。"""
    rc, out = run_pkg(tmp_path, pkg_members(dpkg=dpkg_members(image=STOCK)))
    assert out["status"] == "OK" and list(out["kernel"]) == ["version", "config_source", "config_sha256", "makefiles", "source",
                                                             "config_header", "included_c_list", "modules"]
    assert "IKCONFIG" not in out["detail"] and "dpkg" not in out["detail"]


@pytest.mark.parametrize("files,want", [
    (["arch/x86/Kconfig"], "not_affected"),
    (["arch/x86/Makefile", "arch/x86/kernel/x86only.c"], "not_affected"),
    (["arch/x86/kvm/Kconfig", "arch/powerpc/Makefile.postlink"], "not_affected"),
    (["arch/x86/Kconfig", "drivers/foo/a.c"], "not_affected"),
    (["arch/x86/Kconfig", "drivers/foo/always.c"], "affected"),
    (["arch/arm64/Kconfig"], "unknown"),            # 這個核心自己的架構
    (["arch/Kconfig"], "unknown"),                  # arch/ 最上層的 Kconfig 每個架構都讀
    (["arch/x86/include/asm/x.h"], "unknown"),      # 只放寬 Makefile／Kbuild／Kconfig
    (["arch/x86/boot/x.dts"], "unknown"),
    (["arch/x86/Kconfig", "include/linux/foo.h"], "unknown"),
])
def test_other_arch_build_files(files, want):
    m = model()
    dec, detail, fl, vals = kc.judge_cve(m, files, set())
    assert dec == want, detail
    if want == "not_affected" and all(f.startswith("arch/x86/") or f.startswith("arch/powerpc/") for f in files) \
            and any(kc.classify_file(f)[1] == "build file" for f in files):
        assert "other architectures only" in detail and "the kernel is arm64" in detail
        assert all(x["built"] is False for x in fl)
    # 其他架構的 .c（原本的規則）說明不變
    if files == ["arch/x86/Makefile", "arch/x86/kernel/x86only.c"]:
        assert "arch/x86/kernel/x86only.c (arch/x86 is for another architecture (x86; the kernel is arm64))" in detail


def test_arch_rules_need_a_verified_srcarch():
    """標頭寫 Linux/aarch64（不是核心的 SRCARCH）：headers 沒有 arch/aarch64/Makefile → arch 規則不用，arch/arm64/ 不會判沒編。"""
    m = model(config=CONFIG.replace("Linux/arm64", "Linux/aarch64"))
    assert m.srcarch == "aarch64" and m.arch_rule is False
    for files in (["arch/arm64/kernel/setup.c"], ["arch/arm64/Kconfig"], ["arch/arm64/new/thing.c"], ["arch/x86/Kconfig"]):
        assert kc.judge_cve(m, files, set())[0] != "not_affected", files
    assert model().arch_rule is True


def test_arch_rules_off_for_uml():
    """UML（um）會用 arch/x86/ 的 Makefile.um 與 arch/x86/um/：arch 規則不用。"""
    t = dict(TREE, **{"arch/um/Makefile": "include $(srctree)/arch/x86/Makefile.um\n", "arch/um/Kbuild": "obj-y += kernel/\n"})
    m = model(t, config=CONFIG.replace("Linux/arm64", "Linux/um").replace("CONFIG_ARM64=y\n", ""))
    assert m.srcarch == "um" and m.arch_rule is False
    for files in (["arch/x86/Makefile.um"], ["arch/x86/um/Kconfig"], ["arch/x86/um/foo.c"]):
        assert kc.judge_cve(m, files, set())[0] == "unknown", files


def vex_export():
    import importlib.util as ilu
    spec = ilu.spec_from_file_location("sca_center_vex_export_t", ROOT / "tools" / "cra" / "vex_export.py")
    m = ilu.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


# ---- 第三輪 ----

def test_dpkg_package_pairing_rules():
    """核心套件與 headers 套件成對：Jetson 的 <X>／<X>-headers，Ubuntu 的 linux-image-<v>／linux-headers-<v>（有 flavour 的那一層）。"""
    p = kc.dpkg_paired
    assert p("nvidia-l4t-kernel", "nvidia-l4t-kernel-headers") and p("nvidia-l4t-rt-kernel", "nvidia-l4t-rt-kernel-headers")
    assert not p("nvidia-l4t-rt-kernel", "nvidia-l4t-kernel-headers") and not p("nvidia-l4t-kernel", "nvidia-l4t-rt-kernel-headers")
    assert p("linux-image-6.8.0-45-generic", "linux-headers-6.8.0-45-generic")
    assert p("linux-image-unsigned-6.8.0-1021-nvidia-tegra", "linux-headers-6.8.0-1021-nvidia-tegra")
    assert not p("linux-image-6.8.0-45-generic", "linux-headers-6.8.0-45")            # 共用的那一層
    assert not p("linux-image-6.8.0-45-generic", "linux-headers-6.8.0-45-lowlatency")
    assert not p("linux-image-", "linux-headers-")


def test_ikconfig_arch_differs_from_headers_is_gap(tmp_path):
    """IKCONFIG 標頭是 Linux/x86_64、headers 是 arm64：產生端 GAP，讀取端不採用。"""
    x86 = CONFIG.replace("Linux/arm64", "Linux/x86_64").replace("CONFIG_ARM64=y", "CONFIG_X86=y")
    rc, out = run_pkg(tmp_path, pkg_members(fake_image(x86), boot_image=fake_image()))
    c = out["kernel"]["config_check"]
    assert out["status"] == "GAP" and c["result"] == "differs_arch_mismatch" and "不是同一個架構" in out["detail"]
    assert c["config_header"] == {"headers": ["arm64", "6.8.12"], "image": ["x86_64", "6.8.12"]} and out["results"] == []
    assert out["kernel"]["config_source"] == f"/{HDR}/.config"
    vx = vex_export()
    assert vx.kconfig_index(out) == {} and not vx.kconfig_usable(out)
    # 讀取端再擋一次：ATTENTION、differs，但 config_header 的架構不同
    rc, good = run_pkg(tmp_path / "g", pkg_members(fake_image(CONFIG_EXTRA)))
    assert vx.kconfig_usable(good)
    for img_hdr, ok in ((["x86_64", "6.8.12"], False), (["arm64", "6.8.13"], True), ([None, None], False)):
        bad = json.loads(json.dumps(good))
        bad["kernel"]["config_check"]["config_header"] = {"headers": ["arm64", "6.8.12"], "image": img_hdr}
        assert vx.kconfig_usable(bad) is ok and (vx.kconfig_index(bad) != {}) is ok, img_hdr
    bad["kernel"]["config_check"]["config_header"] = "x"
    assert not vx.kconfig_usable(bad)


def test_incomplete_ikconfig_with_same_settings_is_not_same(tmp_path):
    """IKCONFIG 不完整、設定看起來和 headers 相同：不算 same，改走 dpkg 驗證。"""
    img = fake_image(gz=gzip.compress(CONFIG.encode(), mtime=0) + b"junk")
    rc, out = run_pkg(tmp_path, pkg_members(img, boot_image=img))
    c = out["kernel"]["config_check"]
    assert out["status"] == "GAP" and c["result"] == "dpkg_not_verified" and c["ikconfig_same_but_incomplete"] is True
    assert "IKCONFIG incomplete" in out["detail"] and vex_export().kconfig_index(out) == {}
    rc, out = run_pkg(tmp_path / "v", pkg_members(img, boot_image=img, dpkg=dpkg_members(image=img)))
    assert out["status"] == "OK" and out["kernel"]["config_check"]["result"] == "dpkg_verified"


def test_image_limitations_say_dpkg_is_only_a_consistency_check(tmp_path):
    rc, out = run_pkg(tmp_path, pkg_members(STOCK, boot_image=STOCK, dpkg=dpkg_members(image=STOCK)))
    lim = " ".join(out["kernel"]["config_check"]["limitations"])
    assert "same untrusted rootfs" in lim and "consistency check" in lim and "not protection against tampering" in lim


def test_flash_package_image_gz_without_ikconfig_compares_decompressed_md5(tmp_path):
    """kernel/Image.gz 沒有 IKCONFIG：第 2 項比解壓後的 md5（燒錄時寫成 /boot/Image 的是解壓後的內容）。"""
    gz = gzip.compress(STOCK, mtime=0)
    rc, out = run_pkg(tmp_path, pkg_members(gz, kernel_name="Image.gz", boot_image=STOCK, dpkg=dpkg_members(image=STOCK)))
    c = out["kernel"]["config_check"]
    assert out["status"] == "OK" and c["result"] == "dpkg_verified", out["detail"]
    assert c["image"]["md5"] == md5(gz) and c["image"]["unpacked_md5"] == md5(STOCK)
    assert c["dpkg"]["checks"][1] == {"check": "kernel/Image md5 == dpkg md5sums (decompressed)", "ok": True, "image_md5": md5(STOCK)}
    # 解壓後也不同 → GAP，說明寫「解壓後」
    rc, out = run_pkg(tmp_path / "r", pkg_members(gzip.compress(REBUILT), kernel_name="Image.gz", boot_image=STOCK,
                                                  dpkg=dpkg_members(image=STOCK)))
    assert out["status"] == "GAP" and "第 2 項不成立：Image.gz 的 md5" in out["detail"] and "（解壓後）" in out["detail"]
    # 第三輪驗證低 1：/boot/Image 和 dpkg 記的也是同一份 gzip（三者的檔案 md5 相同）→ 檔案本身的 md5 相同也算同一份
    rc, out = run_pkg(tmp_path / "g", pkg_members(gz, kernel_name="Image.gz", boot_image=gz, dpkg=dpkg_members(image=gz)))
    c = out["kernel"]["config_check"]
    assert out["status"] == "OK" and c["result"] == "dpkg_verified", out["detail"]
    assert c["dpkg"]["checks"][1] == {"check": "kernel/Image md5 == dpkg md5sums", "ok": True, "image_md5": md5(gz)}



# ---- 第四輪：沒有的設定算 n；只差工具鏈的設定 ----
# 形狀取自實測：公開版 R39.2.0 的原廠核心原始差 9 項、正規化後 4 項（AS_VERSION、LD_VERSION、CC_VERSION_TEXT、
# GCC_PLUGINS，全是工具鏈）；product-a 原始差 266 項、正規化後 35 項（含非工具鏈的設定）。

TC_UBUNTU = ('CONFIG_CC_VERSION_TEXT="aarch64-linux-gnu-gcc (Ubuntu 13.2.0-23ubuntu4) 13.2.0"\nCONFIG_GCC_VERSION=130200\n'
             "CONFIG_AS_VERSION=24200\nCONFIG_LD_VERSION=24200\nCONFIG_GCC_PLUGINS=y\n")
TC_CROSSTOOL = ('CONFIG_CC_VERSION_TEXT="aarch64-buildroot-linux-gnu-gcc.br_real (Buildroot 2022.08) 13.2.0"\nCONFIG_GCC_VERSION=130200\n'
                "CONFIG_AS_VERSION=24000\nCONFIG_LD_VERSION=24000\n# CONFIG_GCC_PLUGINS is not set\n")
NOT_SET_ONLY_IN_IMAGE = "# CONFIG_GCC_PLUGIN_LATENT_ENTROPY is not set\n# CONFIG_RANDSTRUCT_FULL is not set\n" + "".join(
    f"# CONFIG_PAD{i} is not set\n" for i in range(3))
HEADERS_PUB = CONFIG + TC_UBUNTU
IMAGE_PUB = CONFIG + TC_CROSSTOOL + NOT_SET_ONLY_IN_IMAGE
IMAGE_product-a = (CONFIG_ON + TC_CROSSTOOL + "".join(f"CONFIG_VENDOR{i}=y\n" for i in range(30))
              + "".join(f"# CONFIG_MISSING{i} is not set\n" for i in range(231)))


def pub_members(image, **kw):
    """headers 的 .config 是 HEADERS_PUB（Ubuntu 工具鏈重新產生的）的刷機包。"""
    m = [(n, HEADERS_PUB.encode(), l) if n.endswith(f"{HDR}/.config") else (n, d, l) for n, d, l in pkg_members(image, **kw)]
    assert any(n.endswith(f"{HDR}/.config") for n, _, _ in m)
    return m


def test_toolchain_option_names():
    t = kc.is_toolchain_option
    for n in ("CONFIG_CC_VERSION_TEXT", "CONFIG_AS_VERSION", "CONFIG_LD_VERSION", "CONFIG_GCC_VERSION", "CONFIG_CLANG_VERSION",
              "CONFIG_LLD_VERSION", "CONFIG_GCC_PLUGINS", "CONFIG_CC_IS_GCC", "CONFIG_CC_HAS_ASM_GOTO",
              "CONFIG_CC_CAN_LINK", "CONFIG_CC_NO_ARRAY_BOUNDS", "CONFIG_AS_IS_GNU", "CONFIG_AS_HAS_ARMV8_4", "CONFIG_LD_IS_BFD",
              "CONFIG_LD_HAS_X", "CONFIG_TOOLCHAIN_HAS_ZBB", "CONFIG_RUSTC_VERSION", "CONFIG_PAHOLE_VERSION", "CONFIG_BINDGEN_VERSION_TEXT"):
        assert t(n), n
    # 功能性的設定：名稱有 VERSION 也不算
    for n in ("CONFIG_MODVERSIONS", "CONFIG_LOCALVERSION", "CONFIG_LOCALVERSION_AUTO", "CONFIG_ARCH_FOO_VERSION", "CONFIG_ARM64_PA_VERSION",
              "CONFIG_SND_SOC_X_VERSION", "CONFIG_ASN1_VERSION", "CONFIG_FOO_A", "CONFIG_RANDSTRUCT_FULL", "CONFIG_LD_ORPHAN_WARN",
              "CONFIG_GCC_PLUGIN_STACKLEAK", "CONFIG_GCC_PLUGIN_LATENT_ENTROPY"):     # 加固功能：不算工具鏈
        assert not t(n), n


def test_missing_and_not_set_are_the_same(tmp_path):
    """「沒有這一項」和「# CONFIG_X is not set」都是 n：只差這種的算 same（照舊用 headers）。"""
    rc, out = run_pkg(tmp_path, pkg_members(fake_image(CONFIG + NOT_SET_ONLY_IN_IMAGE)))
    c = out["kernel"]["config_check"]
    assert out["status"] == "OK" and c["result"] == "same" and c["bytes_identical"] is False and c["raw_differences_total"] == 5
    assert out["kernel"]["config_source"] == f"/{HDR}/.config" and "沒有的設定算 n" in out["detail"]


def test_public_stock_kernel_differs_only_in_toolchain(tmp_path):
    """公開版：正規化後 4 項全是工具鏈 → same_except_toolchain、OK，K1／K2 用 IKCONFIG，判定不變。"""
    base = baseline(tmp_path)
    rc, out = run_pkg(tmp_path, pub_members(fake_image(IMAGE_PUB)))
    k, c = out["kernel"], out["kernel"]["config_check"]
    assert out["status"] == "OK" and c["result"] == "same_except_toolchain", out["detail"]
    assert c["raw_differences_total"] == 9 and c["differences_total"] == 4 == c["toolchain_differences_total"]
    assert {d["name"] for d in c["differences"]} == {"CONFIG_AS_VERSION", "CONFIG_LD_VERSION", "CONFIG_CC_VERSION_TEXT", "CONFIG_GCC_PLUGINS"}
    assert all(d["toolchain"] for d in c["differences"])
    assert k["config_source"] == "kernel/Image (IKCONFIG)" and k["config_sha256"] == hashlib.sha256(IMAGE_PUB.encode()).hexdigest()
    assert k["config_sha256"] == c["image_config_sha256"] and c["headers_config"]["sha256"] == hashlib.sha256(HEADERS_PUB.encode()).hexdigest()
    assert "只差工具鏈的 4 項" in out["detail"] and not out["detail"].startswith("headers .config 和燒錄的核心不同")
    assert [(r["cve"], r["decision"]) for r in out["results"]] == [(r["cve"], r["decision"]) for r in base["results"]]
    vx = vex_export()
    idx = vx.kconfig_index(out)
    assert set(idx) == {"CVE-2024-0001", "CVE-2025-0005"} and vx.kconfig_ikconfig(out) is None and vx.kconfig_toolchain_only(out)
    s = vx.from_kconfig(kernel_row(["CVE-2024-0001"]), idx, out)
    assert (f"based on the flashed kernel's built-in configuration (IKCONFIG sha {k['config_sha256'][:12]}; "
            "only toolchain options differ from the headers .config: 4)") in s["detail"]
    ev = vx.ev_k1(kernel_row(["CVE-2024-0001"]), {"kidx": idx, "kcfg": out, "kcfg_sha": k["config_sha256"]})
    assert ev["inputs"].startswith(f"kernel IKCONFIG SHA-256 {k['config_sha256'][:12]}")
    # 和實際用的設定對不上時不寫這一句（status OK 照樣採用）
    bad = json.loads(json.dumps(out))
    bad["kernel"]["config_sha256"] = c["headers_config"]["sha256"]
    assert vx.kconfig_toolchain_only(bad) is None
    assert "based on the flashed kernel" not in vx.from_kconfig(kernel_row(["CVE-2024-0001"]), idx, bad)["detail"]
    # K2：同一份設定
    (tmp_path / "kc.json").write_text(json.dumps(out))
    mrc, mm = run_module_map(tmp_path / "mm", tmp_path / "p.tbz2", "--prefix", f"{L4T}/rootfs", kconfig=tmp_path / "kc.json", mirror=tmp_path / "m")
    assert mm["status"] == "OK" and mm["sources"]["config"] == "kernel/Image (IKCONFIG)"
    assert mm["sources"]["config_check"]["result"] == "same_except_toolchain" and mm["sources"]["config_sha256"] == k["config_sha256"]


def test_product-a_shape_differs_after_normalisation(tmp_path):
    """product-a：原始 266 項、正規化後 35 項（含非工具鏈）→ differs、ATTENTION；數字都用正規化後的。"""
    rc, out = run_pkg(tmp_path, pub_members(fake_image(IMAGE_product-a)))
    c = out["kernel"]["config_check"]
    assert out["status"] == "ATTENTION" and c["result"] == "differs"
    assert c["raw_differences_total"] == 266 and c["differences_total"] == 35 and c["toolchain_differences_total"] == 4
    assert out["detail"].startswith("headers .config 和燒錄的核心不同，已改用燒錄核心的內建設定（kernel/Image 的 IKCONFIG；差 35 個設定，例如 CONFIG_FOO_A")
    assert [d["toolchain"] for d in c["differences"]] == [False] * 31 + [True] * 4         # 非工具鏈的排在前面
    vx = vex_export()
    s = vx.from_kconfig(kernel_row(["CVE-2025-0005"]), {"CVE-2025-0005": {"cve": "CVE-2025-0005", "detail": "x"}}, out)
    assert "the headers .config differs from it in 35 option(s)" in s["detail"]


@pytest.mark.parametrize("image", [CONFIG.replace('CONFIG_LOCALVERSION="-tegra"', 'CONFIG_LOCALVERSION="-vendor"') + TC_CROSSTOOL,
                                   CONFIG + "CONFIG_MODVERSIONS=y\n" + TC_CROSSTOOL], ids=["LOCALVERSION", "MODVERSIONS"])
def test_functional_version_options_are_not_toolchain(tmp_path, image):
    """只差 LOCALVERSION 或 MODVERSIONS（加上工具鏈）：不是 same_except_toolchain，照舊 differs＋ATTENTION。"""
    rc, out = run_pkg(tmp_path, pub_members(fake_image(image)))
    c = out["kernel"]["config_check"]
    assert out["status"] == "ATTENTION" and c["result"] == "differs" and c["differences_total"] == 5 and c["toolchain_differences_total"] == 4


def test_toolchain_only_but_incomplete_ikconfig_goes_to_dpkg(tmp_path):
    img = fake_image(gz=gzip.compress(IMAGE_PUB.encode(), mtime=0) + b"junk")
    rc, out = run_pkg(tmp_path, pub_members(img, boot_image=img))
    c = out["kernel"]["config_check"]
    assert out["status"] == "GAP" and c["result"] == "dpkg_not_verified" and c["ikconfig_same_but_incomplete"] is True


# ---------- 核心建置紀錄（--build-record）：只用假的建置資料夾（測試裡產生，不是真的產品資料） ----------

def cmd_name(target):
    target = os.path.normpath(target)          # kbuild 把 .cmd 寫在正規化後的位置（目標本身可以含 ..）
    d, n = target.rsplit("/", 1) if "/" in target else ("", target)
    return (d + "/" if d else "") + "." + n + ".cmd"


def cmd_text(target, source=None, deps=()):
    """kbuild 的 .cmd 形狀（6.8：savedcmd_、source_、deps_ 一行一個檔案，夾著 $(wildcard include/config/…)）。"""
    t = f"savedcmd_{target} := gcc -Wp,-MMD,{target}.d -c -o {target} {source or ''}\n\n"
    if source is not None:
        t += f"source_{target} := {source}\n\n"
        t += f"deps_{target} := \\\n" + "".join(f"  {d} \\\n    $(wildcard include/config/FOO) \\\n" for d in deps)
        t += f"\n{target}: $(deps_{target})\n\n$(deps_{target}):\n"
    return t


# 假核心實際編譯的物件（和 TREE、CONFIG 一致）：drivers/foo/always.o 會 #include drivers/foo/inc.c 與 include/linux/foo.h；
# bar.ko 的 bar.mod.o 讀 include/linux/module.h；scripts/ 與沒有副檔名的主機程式（lib/gen_table）不算核心
REC_OBJS = {
    "drivers/foo/always.o": ("drivers/foo/always.c", ["include/linux/kconfig.h", "include/linux/foo.h", "drivers/foo/inc.c"]),
    "drivers/bar/core.o": ("drivers/bar/core.c", ["include/linux/kconfig.h"]),
    "drivers/bar/bar.mod.o": ("drivers/bar/bar.mod.c", ["include/linux/module.h"]),
    "init/main.o": ("init/main.c", []),
    "arch/arm64/kernel/setup.o": ("arch/arm64/kernel/setup.c", []),
    "arch/arm64/kvm/../../../virt/kvm/kvm_main.o": ("arch/arm64/kvm/../../../virt/kvm/kvm_main.c", []),
    "scripts/mod/modpost.o": ("scripts/mod/modpost.c", ["include/linux/hostonly.h"]),
    "lib/gen_table": ("lib/gen_table.c", ["include/linux/hostonly2.h"]),
    # 不經 archive 直接列的物件：objcopy（pi）、ld -r＋objcopy（kvm nVHE）、strip（EFI libstub）、vDSO（.so，經 .incbin）
    "arch/arm64/kernel/pi/kaslr_early.o": ("arch/arm64/kernel/pi/kaslr_early.c", []),
    "arch/arm64/kvm/hyp/nvhe/mem_protect.nvhe.o": ("arch/arm64/kvm/hyp/nvhe/mem_protect.c", []),
    "drivers/firmware/efi/libstub/efi-stub-helper.o": ("drivers/firmware/efi/libstub/efi-stub-helper.c", []),
    "arch/arm64/kernel/vdso-wrap.o": ("arch/arm64/kernel/vdso-wrap.S", []),
    "arch/arm64/kernel/vdso/vgettimeofday.o": ("arch/arm64/kernel/vdso/vgettimeofday.c", []),
    "init/version-timestamp.o": ("init/version-timestamp.c", []),
    "vmlinux": ("scripts/link-vmlinux.sh", []),
}


def saved(target, cmd):
    return f"savedcmd_{target} := {cmd}\n".encode()


def archive_printf(target, d, members):
    """kbuild 6.x 的 built-in.a：printf "<資料夾>/%s " a.o b.o | xargs ar cDPrST <archive>。"""
    return saved(target, f'rm -f {target};  printf "{d}%s " {" ".join(members)} | xargs aarch64-linux-gnu-ar cDPrST {target}')


# 連結的關係（membership closure 要求每個成員都有 .cmd）：vmlinux.o → vmlinux.a → built-in.a → 各資料夾的 built-in.a → 物件；
# 模組 bar.ko：bar.o（@bar.mod 連結）、bar.mod（成員 core.o）、bar.ko
REC_LINKS = {
    "vmlinux.a": saved("vmlinux.a", "rm -f vmlinux.a; ar cDPrST vmlinux.a ./built-in.a  lib/lib.a; ar mPiT $$(ar t vmlinux.a | sed -n 1p) "
                                    "vmlinux.a $$(ar t vmlinux.a | grep -F -f ./scripts/head-object-list.txt)"),
    "built-in.a": archive_printf("built-in.a", "./", ["init/built-in.a", "drivers/built-in.a", "arch/arm64/built-in.a"]),
    "lib/lib.a": saved("lib/lib.a", "rm -f lib/lib.a; ar cDPrsT lib/lib.a"),
    "init/built-in.a": archive_printf("init/built-in.a", "init/", ["main.o"]),
    "drivers/built-in.a": archive_printf("drivers/built-in.a", "drivers/", ["foo/built-in.a", "bar/built-in.a"]),
    "drivers/foo/built-in.a": archive_printf("drivers/foo/built-in.a", "drivers/foo/", ["always.o"]),
    "drivers/bar/built-in.a": saved("drivers/bar/built-in.a", "rm -f drivers/bar/built-in.a; ar cDPrST drivers/bar/built-in.a"),
    "arch/arm64/built-in.a": archive_printf("arch/arm64/built-in.a", "arch/arm64/", ["kernel/built-in.a", "kvm/built-in.a"]),
    "arch/arm64/kernel/built-in.a": archive_printf("arch/arm64/kernel/built-in.a", "arch/arm64/kernel/",
                                                   ["setup.o", "vdso-wrap.o", "pi/built-in.a"]),
    "arch/arm64/kernel/pi/built-in.a": archive_printf("arch/arm64/kernel/pi/built-in.a", "arch/arm64/kernel/pi/", ["kaslr_early.pi.o"]),
    "arch/arm64/kernel/pi/kaslr_early.pi.o": saved("arch/arm64/kernel/pi/kaslr_early.pi.o", "aarch64-linux-gnu-objcopy --prefix-symbols=__pi_ "
                                                   "arch/arm64/kernel/pi/kaslr_early.o arch/arm64/kernel/pi/kaslr_early.pi.o"),
    "arch/arm64/kvm/built-in.a": archive_printf("arch/arm64/kvm/built-in.a", "arch/arm64/kvm/",
                                                ["../../../virt/kvm/kvm_main.o", "hyp/nvhe/built-in.a"]),
    "arch/arm64/kvm/hyp/nvhe/built-in.a": archive_printf("arch/arm64/kvm/hyp/nvhe/built-in.a", "arch/arm64/kvm/hyp/nvhe/", ["kvm_nvhe.o"]),
    "arch/arm64/kvm/hyp/nvhe/kvm_nvhe.o": saved("arch/arm64/kvm/hyp/nvhe/kvm_nvhe.o", "objcopy --prefix-symbols=__kvm_nvhe_ "
                                                "arch/arm64/kvm/hyp/nvhe/kvm_nvhe.rel.o arch/arm64/kvm/hyp/nvhe/kvm_nvhe.o"),
    "arch/arm64/kvm/hyp/nvhe/kvm_nvhe.rel.o": saved("arch/arm64/kvm/hyp/nvhe/kvm_nvhe.rel.o", "ld -EL  -r arch/arm64/kvm/hyp/nvhe/kvm_nvhe.tmp.o "
                                                    "-o arch/arm64/kvm/hyp/nvhe/kvm_nvhe.rel.o"),
    "arch/arm64/kvm/hyp/nvhe/kvm_nvhe.tmp.o": saved("arch/arm64/kvm/hyp/nvhe/kvm_nvhe.tmp.o", "ld -EL  -r -T arch/arm64/kvm/hyp/nvhe/hyp.lds "
                                                    "arch/arm64/kvm/hyp/nvhe/mem_protect.nvhe.o -o arch/arm64/kvm/hyp/nvhe/kvm_nvhe.tmp.o"),
    "drivers/firmware/efi/libstub/lib.a": saved("drivers/firmware/efi/libstub/lib.a", "rm -f drivers/firmware/efi/libstub/lib.a; ar cDPrsT "
                                                "drivers/firmware/efi/libstub/lib.a drivers/firmware/efi/libstub/efi-stub-helper.stub.o"),
    "drivers/firmware/efi/libstub/efi-stub-helper.stub.o": saved(
        "drivers/firmware/efi/libstub/efi-stub-helper.stub.o",
        "strip --strip-debug -o drivers/firmware/efi/libstub/efi-stub-helper.stub.o drivers/firmware/efi/libstub/efi-stub-helper.o; "
        "if objdump -r drivers/firmware/efi/libstub/efi-stub-helper.stub.o | grep R_AARCH64_ABS; then /bin/false; fi"),
    "arch/arm64/kernel/vdso/vdso.so": saved("arch/arm64/kernel/vdso/vdso.so", "objcopy -S  arch/arm64/kernel/vdso/vdso.so.dbg "
                                            "arch/arm64/kernel/vdso/vdso.so"),
    "arch/arm64/kernel/vdso/vdso.so.dbg": saved("arch/arm64/kernel/vdso/vdso.so.dbg", "ld -shared -T  arch/arm64/kernel/vdso/vdso.lds "
                                                "arch/arm64/kernel/vdso/vgettimeofday.o -o arch/arm64/kernel/vdso/vdso.so.dbg; if readelf -rW "
                                                "arch/arm64/kernel/vdso/vdso.so.dbg | grep -q R_AARCH64; then /bin/false; fi"),
    "drivers/bar/bar.o": saved("drivers/bar/bar.o", "ld -EL -r -o drivers/bar/bar.o @drivers/bar/bar.mod"),
    "drivers/bar/bar.mod": saved("drivers/bar/bar.mod", "printf '%s\\n'   core.o | awk '!x[$$0]++ { print(\"drivers/bar/\"$$0) }' "
                                                        "> drivers/bar/bar.mod"),
    "drivers/bar/bar.ko": saved("drivers/bar/bar.ko", "ld -r -o drivers/bar/bar.ko drivers/bar/bar.o drivers/bar/bar.mod.o"),
}


def record_members(config=CONFIG, release=KVER, pad=kc.MIN_RECORD_OBJECT_CMDS, order=b"drivers/bar/bar.o\n",
                   builtin=b"kernel/drivers/foo/always.ko\n", objs=None, link=True, src_prefix="", drop=(), dep_prefix=None):
    m = {".config": config.encode(), "System.map": b"ffff0000 T start\n", "Makefile": b"# generated\n"}
    if order is not None:
        m["modules.order"] = order
    if builtin is not None:
        m["modules.builtin"] = builtin
    if release is not None:
        m["include/config/kernel.release"] = (release + "\n").encode()
    for t, (s, d) in (REC_OBJS if objs is None else objs).items():
        pre = src_prefix if not s.endswith(".mod.c") else ""
        dpre = pre if dep_prefix is None or s.endswith(".mod.c") else dep_prefix
        m[cmd_name(t)] = cmd_text(t, pre + s, [dpre + x for x in d]).encode()
    for t, v in REC_LINKS.items():
        m[cmd_name(t)] = v
    for i in range(pad):
        t = f"pad/p{i}/x.o"
        m[cmd_name(t)] = cmd_text(t, f"{src_prefix}pad/p{i}/x.c", [f"{src_prefix}include/linux/kconfig.h", "/usr/lib/gcc/stddef.h"]).encode()
    if link:
        m[".vmlinux.o.cmd"] = saved("vmlinux.o", "ld -EL -r -o vmlinux.o  --whole-archive vmlinux.a --no-whole-archive --start-group "
                                                 "./drivers/firmware/efi/libstub/lib.a --end-group")
    for t in drop:
        del m[cmd_name(t)]
    return m


def write_record_dir(d, members):
    for k, v in members.items():
        p = d / k
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(v)
    return d


def write_record_tar(path, members, mode="w", root="", extra=()):
    with tarfile.open(path, mode) as t:
        for k, v in members.items():
            add(t, root + k, v)
        for name, data, link in extra:
            add(t, name, data, link)
    return path


BR_RECORDS = {
    "CVE-2024-1001": ["drivers/foo/a.c"],                 # Makefile：沒編；紀錄：不在任何物件裡 → not_affected
    "CVE-2024-1002": ["include/linux/foo.h"],             # 標頭檔在 always.o 的 deps → affected（沒有紀錄時 unknown）
    "CVE-2024-1003": ["include/linux/absent.h"],          # 標頭檔在 headers 裡、沒有物件讀它 → not_affected
    "CVE-2024-1004": ["drivers/foo/inc.c"],               # 被 always.c #include 的 .c（在它的 deps）→ affected
    "CVE-2024-1005": ["include/linux/gone.h"],            # 這個核心看不到這個檔案（可能之後才加或搬過家）→ unknown
    "CVE-2024-1006": ["drivers/bar/subst.c"],             # Makefile 判有編、紀錄沒有 → 矛盾 → unknown
    "CVE-2024-1007": ["drivers/bar/cond.c"],              # Makefile 的 ifdef 區塊（unknown）、紀錄沒有 → not_affected
    "CVE-2024-1008": ["include/linux/hostonly.h"],        # 只有主機程式（scripts/、lib/gen_table）讀它 → not_affected
    "CVE-2024-1009": ["include/linux/module.h"],          # bar.mod.o 讀它（連進 bar.ko）→ affected
    "CVE-2024-1010": ["drivers/foo/always.c"],            # 紀錄：compiled as → affected，built_as 沿用模組對應
    "CVE-2024-1011": ["virt/kvm/kvm_main.c"],             # 目標含 ..（arch/arm64/kvm/../../../virt/kvm/kvm_main.o）→ affected
    "CVE-2024-1012": ["arch/x86/kernel/x86only.c", "arch/x86/new/y.c"],   # 其他架構：兩邊都說沒編（不必另外證明檔案在）→ not_affected
}


def br_rootfs(tmp_path, extra=(), name="rootfs.tar"):
    m = rootfs_members() + [(f"{HDR}/include/linux/absent.h", b"#define A\n", None),
                            (f"{HDR}/include/linux/hostonly.h", b"#define H\n", None)] + list(extra)
    return write_tar(tmp_path / name, m)


def br_run(tmp_path, record=None, src=None, records=BR_RECORDS):
    mirror = make_mirror(tmp_path / "m", records=records)
    args = ["--build-record", str(record)] if record is not None else []
    return run(tmp_path, *args, grype_doc=grype(list(records)), src=src or br_rootfs(tmp_path), mirror=mirror)


def test_parse_cmd_and_cmd_root():
    t, src, deps, keys, _, has_deps = kc.parse_cmd(cmd_text("drivers/x/y.o", "drivers/x/y.c", ["include/linux/a.h", "drivers/x/inc.c"]))
    assert t == "drivers/x/y.o" and src == ["drivers/x/y.c"] and deps == ["include/linux/a.h", "drivers/x/inc.c"]
    assert keys == {"drivers/x/y.o"} and has_deps
    assert kc.cmd_root(("drivers", "x", ".y.o.cmd"), "drivers/x/y.o") == ()
    assert kc.cmd_root(("kernel-noble", "drivers", "x", ".y.o.cmd"), "drivers/x/y.o") == ("kernel-noble",)
    assert kc.cmd_root(("a", "b", "drivers", "x", ".y.o.cmd"), "drivers/x/y.o") is None           # 最多一層
    assert kc.cmd_root(("drivers", "z", ".y.o.cmd"), "drivers/x/y.o") is None                     # 位置對不上
    assert kc.cmd_root(("virt", "kvm", ".k.o.cmd"), "arch/arm64/kvm/../../../virt/kvm/k.o") == ()
    assert kc.cmd_root(("x", ".y.o.cmd"), "../x/y.o") is None and kc.cmd_root(("x", ".y.o.cmd"), "/x/y.o") is None
    assert [kc.host_target(x) for x in ("scripts/mod/modpost.o", "tools/objtool/x.o", "usr/include/linux/a.hdrtest", "lib/gen_table",
                                         "vmlinux", "drivers/x/y.o", "drivers/x/y.mod.o", "usr/initramfs_data.o")] == \
        [True, True, True, True, False, False, False, False]


def test_build_record_judgements(tmp_path):
    rec = write_record_tar(tmp_path / "rec.tar.gz", record_members(), "w:gz")
    p, st, out = br_run(tmp_path, rec)
    assert st[1] == "OK", p.stdout + p.stderr
    br = out["kernel"]["build_record"]
    assert br["status"] == "OK" and br["reason"] is None and br["root"] == "." and br["kernel_release"] == KVER
    assert br["config_sha256"] == hashlib.sha256(CONFIG.encode()).hexdigest() and br["config_compare"]["result"] == "same"
    assert br["object_cmd_files"] == kc.MIN_RECORD_OBJECT_CMDS + 20 and br["host_cmd_files"] == 2 and br["out_of_tree_modules"] == 0
    assert br["limitations"] == kc.BUILD_RECORD_LIMITATIONS + [kc.RECORD_NOT_TIED_LIMITATION] and br["source"] == "rec.tar.gz"
    assert br["identity"]["result"] == "not_tied" and br["identity"]["banner_read"] is False
    by = {r["cve"]: r for r in out["results"]}
    dec = {c: r["decision"] for c, r in by.items()}
    assert dec == {"CVE-2024-1001": "not_affected", "CVE-2024-1002": "affected", "CVE-2024-1003": "not_affected",
                   "CVE-2024-1004": "affected", "CVE-2024-1005": "unknown", "CVE-2024-1006": "unknown",
                   "CVE-2024-1007": "not_affected", "CVE-2024-1008": "not_affected", "CVE-2024-1009": "affected",
                   "CVE-2024-1010": "affected", "CVE-2024-1011": "affected", "CVE-2024-1012": "not_affected"}
    ev = {c: r["files"][0]["evidence"] for c, r in by.items()}
    assert ev["CVE-2024-1001"] == "build record: not in the source or deps of any compiled kernel object"
    assert ev["CVE-2024-1002"] == "build record: in the deps of drivers/foo/always.o"
    assert ev["CVE-2024-1004"] == "build record: in the deps of drivers/foo/always.o"
    assert ev["CVE-2024-1010"] == "build record: compiled as drivers/foo/always.o"
    assert ev["CVE-2024-1009"] == "build record: in the deps of drivers/bar/bar.mod.o"
    assert "do not show that include/linux/gone.h exists" in ev["CVE-2024-1005"]
    assert "Makefile rules say it is built (conflict, so unknown)" in ev["CVE-2024-1006"]
    assert by["CVE-2024-1001"]["justification"] == "vulnerable_code_not_present"
    assert by["CVE-2024-1001"]["detail"].startswith("the kernel build record shows that no compiled kernel object has any program file")
    assert by["CVE-2024-1001"]["files"][0]["configs"] == ["CONFIG_FOO_A"]                # Makefile 的結論相同時照記設定
    assert "drivers/foo/inc.c is built (build record: in the deps of drivers/foo/always.o)" in by["CVE-2024-1004"]["detail"]
    f10 = by["CVE-2024-1010"]["files"][0]
    assert f10["built"] is True and f10["built_as"] == "builtin"                            # Makefile 也判有編：沿用模組對應
    assert by["CVE-2024-1002"]["files"][0]["built_as"] is None                              # 標頭檔：不知道是哪一個
    assert br["counts_without_record"] == {"not_affected": 2, "affected": 2, "unknown": 8}
    assert br["decision_changes"] == {"affected->unknown": 1, "unknown->affected": 4, "unknown->not_affected": 3}
    assert br["file_judgements"]["conflict_makefile_built"] == 1 and br["file_judgements"]["not_shown_to_exist"] == 1
    assert out["counts"] == {"not_affected": 5, "affected": 5, "unknown": 2}
    assert [f["evidence"] for f in by["CVE-2024-1012"]["files"]] == ["build record: not in the source or deps of any compiled kernel object"] * 2
    assert "建置紀錄 rec.tar.gz 採用" in st[2] and "矛盾的檔案 1 個" in st[2]


def test_build_record_dir_and_nested_tar_and_plain_tar(tmp_path):
    base = br_run(tmp_path, write_record_tar(tmp_path / "a.tar.gz", record_members(), "w:gz"))[2]
    for rec in (write_record_dir(tmp_path / "recdir", record_members()),
                write_record_tar(tmp_path / "b.tar", record_members()),
                write_record_tar(tmp_path / "c.tar.xz", record_members(), "w:xz", root="kernel-noble/")):
        out = br_run(tmp_path, rec)[2]
        assert out["kernel"]["build_record"]["status"] == "OK", out["kernel"]["build_record"]
        assert out["results"] == base["results"]
    assert br_run(tmp_path, tmp_path / "c.tar.xz")[2]["kernel"]["build_record"]["root"] == "kernel-noble"


def test_build_record_out_of_tree_source_prefix(tmp_path):
    """O= 建置：source_／deps_ 是原始碼樹的絕對路徑，去掉前綴後比對；樹外的系統標頭不算。"""
    rec = write_record_dir(tmp_path / "o", record_members(src_prefix="/build/src/linux/"))
    out = br_run(tmp_path, rec)[2]
    assert out["kernel"]["build_record"]["source_tree_prefixes"] == 1
    by = {r["cve"]: r["decision"] for r in out["results"]}
    assert by["CVE-2024-1002"] == by["CVE-2024-1004"] == "affected" and by["CVE-2024-1003"] == "not_affected"


def test_build_record_unsafe_members_rejected(tmp_path):
    # ../ 與絕對路徑的成員不收；不需要的符號連結（source -> …）略過；需要的檔案是符號連結 → GAP
    extra = [("../evil/.x.o.cmd", cmd_text("evil/x.o", "include/linux/absent.h").encode(), None),
             ("/abs/.y.o.cmd", cmd_text("abs/y.o", "include/linux/absent.h").encode(), None),
             ("source", None, "/home" "/someone/linux")]
    out = br_run(tmp_path, write_record_tar(tmp_path / "r.tar", record_members(), extra=extra))[2]
    br = out["kernel"]["build_record"]
    assert br["status"] == "OK" and br["rejected_members"] == 2 and br["ignored_links"] == 1
    assert {r["cve"]: r["decision"] for r in out["results"]}["CVE-2024-1003"] == "not_affected"
    m = record_members()
    del m["drivers/foo/.always.o.cmd"]
    out = br_run(tmp_path, write_record_tar(tmp_path / "s.tar", m, extra=[("drivers/foo/.always.o.cmd", None, "/etc/passwd")]))[2]
    br = out["kernel"]["build_record"]
    assert br["status"] == "GAP" and "links or special files" in br["reason"] and "drivers/foo/.always.o.cmd" in br["reason"]
    # 資料夾：符號連結不跟隨
    d = write_record_dir(tmp_path / "ld", m)
    (d / "drivers" / "foo").mkdir(parents=True, exist_ok=True)
    (d / "drivers" / "foo" / ".always.o.cmd").symlink_to(tmp_path / "s.tar")
    assert br_run(tmp_path, d)[2]["kernel"]["build_record"]["status"] == "GAP"


def gap_cases():
    cfg = CONFIG.replace("# CONFIG_FOO_A is not set", "CONFIG_FOO_A=y")
    return {
        "config": (dict(config=cfg), "is not the configuration K1 judges with", "CONFIG_FOO_A"),
        "release": (dict(release="6.8.12-other"), "include/config/kernel.release is '6.8.12-other'", KVER),
        "incomplete-cmds": (dict(pad=5), "incomplete build record", "object .cmd files"),
        "incomplete-link": (dict(drop=("vmlinux",)), "incomplete build record", "missing the final link command (.vmlinux.cmd)"),
        "builtin": (dict(builtin=b"kernel/drivers/foo/always.ko\nkernel/drivers/x/extra.ko\n"), "modules.builtin differs from the image's",
                    "1 only in the record"),
        "closure-object": (dict(drop=("drivers/foo/always.o",)), "incomplete build record: 1 of", "drivers/foo/always.o (listed by drivers/foo/built-in.a)"),
        "closure-archive": (dict(drop=("arch/arm64/kvm/built-in.a",)), "have no .cmd file", "arch/arm64/kvm/built-in.a (listed by arch/arm64/built-in.a)"),
        "closure-module": (dict(drop=("drivers/bar/bar.mod", "drivers/bar/bar.ko")), "incomplete build record: 2 of", "drivers/bar/bar.mod (listed by"),
        "closure-module-member": (dict(drop=("drivers/bar/core.o",)), "incomplete build record", "drivers/bar/core.o (listed by drivers/bar/bar.mod)"),
        "closure-objcopy-pi": (dict(drop=("arch/arm64/kernel/pi/kaslr_early.o",)), "have no .cmd file",
                               "arch/arm64/kernel/pi/kaslr_early.o (listed by arch/arm64/kernel/pi/kaslr_early.pi.o)"),
        "closure-ld-r-nvhe": (dict(drop=("arch/arm64/kvm/hyp/nvhe/mem_protect.nvhe.o",)), "have no .cmd file",
                              "arch/arm64/kvm/hyp/nvhe/mem_protect.nvhe.o (listed by arch/arm64/kvm/hyp/nvhe/kvm_nvhe.tmp.o)"),
        "closure-ld-r-chain": (dict(drop=("arch/arm64/kvm/hyp/nvhe/kvm_nvhe.rel.o", "arch/arm64/kvm/hyp/nvhe/kvm_nvhe.tmp.o")),
                               "have no .cmd file", "arch/arm64/kvm/hyp/nvhe/kvm_nvhe.rel.o (listed by arch/arm64/kvm/hyp/nvhe/kvm_nvhe.o)"),
        "closure-strip-stub": (dict(drop=("drivers/firmware/efi/libstub/efi-stub-helper.o",)), "have no .cmd file",
                               "efi-stub-helper.o (listed by drivers/firmware/efi/libstub/efi-stub-helper.stub.o)"),
        "closure-vdso-member": (dict(drop=("arch/arm64/kernel/vdso/vgettimeofday.o",)), "have no .cmd file",
                                "arch/arm64/kernel/vdso/vgettimeofday.o (listed by arch/arm64/kernel/vdso/vdso.so.dbg)"),
        "closure-vdso-incbin": (dict(drop=("arch/arm64/kernel/vdso/vdso.so", "arch/arm64/kernel/vdso/vdso.so.dbg",
                                           "arch/arm64/kernel/vdso/vgettimeofday.o")), "have no .cmd file",
                                "arch/arm64/kernel/vdso/vdso.so (listed by arch/arm64/kernel/vdso-wrap.o (.incbin))"),
        "closure-link-stage-plus-real": (dict(link=False, drop=("init/version-timestamp.o", "drivers/foo/always.o")), "incomplete build record: 1 of",
                                         "drivers/foo/always.o (listed by drivers/foo/built-in.a)"),
    }


@pytest.mark.parametrize("case", list(gap_cases()))
def test_build_record_gap_falls_back_to_makefile(tmp_path, case):
    kw, msg, msg2 = gap_cases()[case]
    p0, st0, base = br_run(tmp_path)                                   # 沒有紀錄
    p, st, out = br_run(tmp_path, write_record_tar(tmp_path / "g.tar.gz", record_members(**kw), "w:gz"))
    br = out["kernel"]["build_record"]
    assert st[1] == st0[1] == "OK" and br["status"] == "GAP" and msg in br["reason"] and msg2 in br["reason"], br
    assert out["results"] == base["results"] and out["counts"] == base["counts"]       # 不用對不上的證據：結果和沒有紀錄相同
    assert "evidence" not in out["results"][0]["files"][0]
    assert st[2] == st0[2] + f"；建置紀錄 g.tar.gz 不採用（GAP：{br['reason']}），照舊依 Makefile 判定"


def test_build_record_link_stage_artifacts_without_cmd_are_exempt(tmp_path):
    """vmlinux.o／vmlinux.a／init/version-timestamp.o／.vmlinux.export.o 沒有 .cmd（product-c 5.15 的紀錄）：採用紀錄，證據列出豁免項，
    其他物件的判定不變；這些產物不產生任何來源檔判定。"""
    full = br_run(tmp_path, write_record_tar(tmp_path / "f.tar.gz", record_members(), "w:gz"))[2]
    m = record_members(link=False, drop=("init/version-timestamp.o",))
    out = br_run(tmp_path, write_record_tar(tmp_path / "e.tar.gz", m, "w:gz"))[2]
    br = out["kernel"]["build_record"]
    assert br["status"] == "OK", br
    ex = br["closure"]["exempted_link_stage_artifacts"]
    assert set(ex) <= set(kc.LINK_STAGE_NO_CMD) and "vmlinux.o" in ex and "init/version-timestamp.o" in ex
    assert "never used to judge any source file" in br["closure"]["exempted_note"]
    assert [(r["cve"], r["decision"]) for r in out["results"]] == [(r["cve"], r["decision"]) for r in full["results"]]


def test_build_record_toolchain_only_config_difference_is_ok(tmp_path):
    out = br_run(tmp_path, write_record_dir(tmp_path / "t", record_members(config=CONFIG + "CONFIG_GCC_VERSION=130200\n")))[2]
    br = out["kernel"]["build_record"]
    assert br["status"] == "OK" and br["config_compare"]["result"] == "same_except_toolchain"


def test_build_record_without_kernel_release_and_bad_inputs(tmp_path):
    out = br_run(tmp_path, write_record_dir(tmp_path / "nr", record_members(release=None)))[2]
    assert out["kernel"]["build_record"]["status"] == "OK" and out["kernel"]["build_record"]["kernel_release"] is None
    out = br_run(tmp_path, tmp_path / "missing.tar.gz")[2]
    assert out["kernel"]["build_record"]["status"] == "GAP" and "does not exist" in out["kernel"]["build_record"]["reason"]
    (tmp_path / "junk.tar.gz").write_bytes(b"\x1f\x8b\x08junk")
    out = br_run(tmp_path, tmp_path / "junk.tar.gz")[2]
    assert out["kernel"]["build_record"]["status"] == "GAP" and "cannot be read" in out["kernel"]["build_record"]["reason"]
    # 兩棵建置樹 → GAP
    m = record_members()
    two = {**m, **{"other/" + k: v for k, v in m.items()}}
    out = br_run(tmp_path, write_record_dir(tmp_path / "two", two))[2]
    assert "more than one build tree" in out["kernel"]["build_record"]["reason"]


def test_build_record_header_with_out_of_tree_modules_is_unknown(tmp_path):
    """模組目錄有 out-of-tree 模組（不在紀錄的 modules.order 裡）：它們另外以 headers 編譯，可能 include 這個標頭檔 → unknown。"""
    src = br_rootfs(tmp_path, extra=[(f"usr/lib/modules/{KVER}/updates/nvidia/oot.ko", b"\x7fELF", None)], name="oot.tar")
    out = br_run(tmp_path, write_record_dir(tmp_path / "r", record_members()), src=src)[2]
    br = out["kernel"]["build_record"]
    by = {r["cve"]: r for r in out["results"]}
    assert br["out_of_tree_modules"] == 1 and by["CVE-2024-1003"]["decision"] == "unknown"
    assert "1 out-of-tree module(s)" in by["CVE-2024-1003"]["files"][0]["evidence"]
    assert by["CVE-2024-1001"]["decision"] == "not_affected" and by["CVE-2024-1002"]["decision"] == "affected"


def test_build_record_stage_gap_records_not_run(tmp_path):
    p, st, out = run(tmp_path, "--build-record", str(tmp_path / "x"), mirror=False)
    assert st[1] == "GAP" and out["kernel"]["build_record"]["status"] == "NOT_RUN"


def test_no_build_record_output_unchanged(tmp_path):
    """沒給 --build-record：沒有 kernel.build_record、files 沒有 evidence（和以前逐位元組相同，由其他測試鎖住內容）。"""
    p, st, out = br_run(tmp_path)
    assert "build_record" not in out["kernel"] and all("evidence" not in f for r in out["results"] for f in r["files"])
    assert "建置紀錄" not in st[2]


def test_sca_scan_build_record_wiring():
    s = (PILOT / "sca-scan").read_text(encoding="utf-8")
    assert '[ -n "${KERNEL_BUILD_RECORD:-}" ] && KREC=(--build-record "$(readlink -m -- "$KERNEL_BUILD_RECORD")")' in s
    assert 'kernel_config.py" "${ka[@]+"${ka[@]}"}" "${KSRC[@]}" --out "$KCF" "${KREC[@]+"${KREC[@]}"}"' in s
    assert "KREC" not in s[s.index("kernel_module_map.py\" \"${ka"):s.index("kernel_module_map.py\" \"${ka") + 200]


def test_build_record_size_caps(tmp_path, monkeypatch):
    path = str(write_record_tar(tmp_path / "r.tar", record_members()))
    m = model()
    br, j = kc.check_build_record(kc.read_build_record(path), m.info, m, set())
    assert br["status"] == "OK" and j is not None and br["out_of_tree_modules"] == 0
    monkeypatch.setattr(kc, "MAX_RECORD_MEMBER", 100)                   # 單一檔案
    r = kc.read_build_record(path)
    br, j = kc.check_build_record(r, m.info, m, set())
    assert r.oversize and br["status"] == "GAP" and "larger than" in br["reason"] and j is None
    monkeypatch.setattr(kc, "MAX_RECORD_MEMBER", 16 << 20)
    monkeypatch.setattr(kc, "MAX_RECORD_TOTAL", 1000)                   # 讀進來的合計
    assert "larger than the limits" in kc.read_build_record(path).error
    monkeypatch.setattr(kc, "MAX_RECORD_TOTAL", 4 << 30)
    monkeypatch.setattr(kc, "MAX_RECORD_STREAM", 1000)                  # tar 全部成員（含不讀的）
    assert "add up to more than" in kc.read_build_record(path).error


def test_build_record_vdso_abspath_counts_as_built(tmp_path):
    """in-tree 建置裡 vdso 的 Makefile 用 $(abspath …)：lib/vdso/gettimeofday.c 只以絕對路徑出現在 deps。對不上樹的絕對路徑
    以 /<檔案> 結尾也算有編；即使映像的核心樹有這個檔案，也不能判沒編。"""
    objs = dict(REC_OBJS)
    objs["arch/arm64/kernel/setup.o"] = ("arch/arm64/kernel/setup.c", ["/home" "/builder/linux-6.8/lib/vdso/gettimeofday.c"])
    src = br_rootfs(tmp_path, extra=[(f"{HDR}/lib/vdso/gettimeofday.c", b"int v;\n", None)], name="vdso.tar")
    out = br_run(tmp_path, write_record_dir(tmp_path / "v", record_members(objs=objs)), src=src,
                 records={"CVE-2024-2001": ["lib/vdso/gettimeofday.c"]})[2]
    br = out["kernel"]["build_record"]
    r = out["results"][0]
    assert br["status"] == "OK" and br["unmapped_absolute_paths"] == 2 and br["source_tree_prefixes"] == 0   # 另一個是 pad 的系統標頭
    assert r["decision"] == "affected" and r["files"][0]["built"] is True
    assert "an absolute path in the deps of arch/arm64/kernel/setup.o ends with /lib/vdso/gettimeofday.c" in r["files"][0]["evidence"]
    assert "/home/builder" not in json.dumps(out)                 # 建置機器的路徑不寫進輸出
    assert br["file_judgements"]["built_by_unmapped_absolute_path"] == 1


def test_build_record_out_of_tree_symlink_vs_realpath(tmp_path):
    """O= 建置：source_ 用符號連結的路徑（/src/linux/…），deps 用實際的路徑（/data/linux-6.8/…）：deps 的檔案仍算有編。"""
    rec = write_record_dir(tmp_path / "o", record_members(src_prefix="/src/linux/", dep_prefix="/data/linux-6.8/"))
    out = br_run(tmp_path, rec)[2]
    br = out["kernel"]["build_record"]
    by = {r["cve"]: r["decision"] for r in out["results"]}
    assert br["status"] == "OK" and br["unmapped_absolute_paths"] > 0 and br["source_tree_prefixes"] == 1
    assert by["CVE-2024-1002"] == by["CVE-2024-1004"] == "affected"          # include/linux/foo.h、drivers/foo/inc.c 只在實際路徑
    assert by["CVE-2024-1010"] == "affected"


def test_build_record_without_kernel_release_needs_module_lists(tmp_path):
    out = br_run(tmp_path, write_record_dir(tmp_path / "a", record_members(release=None)))[2]
    br = out["kernel"]["build_record"]
    assert br["status"] == "OK" and br["kernel_release"] is None and br["kernel_release_checked"] is False
    assert kc.RECORD_RELEASE_LIMITATION in br["limitations"]
    full = br_run(tmp_path, write_record_dir(tmp_path / "b", record_members()))[2]["kernel"]["build_record"]
    assert full["kernel_release_checked"] is True and kc.RECORD_RELEASE_LIMITATION not in full["limitations"]
    # 映像沒有模組清單：沒有 kernel.release 就無法證明是這個核心的建置 → GAP
    m = [x for x in rootfs_members() if not x[0].endswith(("modules.order", "modules.builtin"))]
    src = write_tar(tmp_path / "nolists.tar", m)
    br = br_run(tmp_path, write_record_dir(tmp_path / "c", record_members(release=None)), src=src)[2]["kernel"]["build_record"]
    assert br["status"] == "GAP" and "no include/config/kernel.release" in br["reason"]
    br = br_run(tmp_path, write_record_dir(tmp_path / "d", record_members()), src=src)[2]["kernel"]["build_record"]
    assert br["status"] == "OK" and br["kernel_release_checked"] is True


def test_build_record_included_c_list_stays_a_safety_net(monkeypatch):
    m = model()
    j = kc.RecordJudge({}, {}, {"lib/xz/xz_dec.c"}, 0)
    r, ev = j.judge(m, "lib/xz/xz_dec.c", "lib/xz/xz_dec.o")                # 前綴清單（lib/xz/）、紀錄沒有 → unknown
    assert r.value is None and "#included by other sources" in ev
    monkeypatch.setattr(kc, "included_c", lambda: {"lib/liboff.c": ["lib/x.c"]})
    assert m.obj_built("lib/liboff.o").value is False
    r, ev = j.judge(m, "lib/liboff.c", "lib/liboff.o")                      # Makefile 判沒編也一樣（可能經 #include 編進別的物件）
    assert r.value is None and "safety net" in ev
    r, _ = kc.RecordJudge({"lib/liboff.c": ("lib/x.o", "deps")}, {}, None, 0).judge(m, "lib/liboff.c", "lib/liboff.o")
    assert r.value is True                                                    # 紀錄證明有編 → 有編


def test_build_record_examples_are_capped():
    e = kc.Examples()
    for i in range(50):
        e.add(f"x{i}")
    assert e.n == 50 and len(e.ex) == kc.MAX_RECORD_EXAMPLES and e.text().endswith(", …")


def test_cmd_members_formats():
    assert kc.cmd_members("drivers/x/built-in.a", 'rm -f drivers/x/built-in.a;  printf "drivers/x/%s " a.o ../y/b.o | xargs ar cDPrST '
                          "drivers/x/built-in.a") == ["drivers/x/a.o", "drivers/y/b.o"]
    assert kc.cmd_members("lib/lib.a", "rm -f lib/lib.a; /opt/bin/aarch64-ar cDPrsT lib/lib.a lib/a.o lib/b.o") == ["lib/a.o", "lib/b.o"]
    assert kc.cmd_members("m/x.mod", "printf '%s\\n'   a.o b.o | awk '!x[$$0]++ { print(\"m/\"$$0) }' > m/x.mod") == ["m/a.o", "m/b.o"]
    assert kc.cmd_members("m/x.o", "ld -r -o m/x.o @m/x.mod") == ["m/x.mod"]
    assert kc.cmd_members("m/x.o", "gcc -c -o m/x.o m/x.c") == []
    assert kc.cmd_members("m/x.mod", "{ echo m/a.o; } > m/x.mod") is None               # 看不懂的成員清單 → 格式不對（GAP）
    assert kc.cmd_members("m/built-in.a", "cp a b") is None
    assert kc.cmd_members("m/built-in.a", 'printf "m/%s " ../../../etc/x.o | xargs ar cDPrST m/built-in.a') is None


def test_cmd_members_link_commands():
    """沒有 source_ 的指令：指令裡每個樹內的 .o／.a／.so／.so.dbg 都要有 .cmd；archive 的成員有看不懂的 → 格式不對。"""
    assert kc.cmd_members("a/x.pi.o", "objcopy --prefix-symbols=__pi_ a/x.o a/x.pi.o") == ["a/x.o"]
    assert kc.cmd_members("a/k.rel.o", "ld -EL -r a/k.tmp.o a/r.o -o a/k.rel.o") == ["a/k.tmp.o", "a/r.o"]
    assert kc.cmd_members("a/s.stub.o", "strip --strip-debug -o a/s.stub.o a/s.o; if objdump -r a/s.stub.o | grep X; then "
                          "echo \"a/s.stub.o: bad\" >&2; /bin/false; fi") == ["a/s.o"]
    assert kc.cmd_members("v/vdso.so", "objcopy -S  v/vdso.so.dbg v/vdso.so") == ["v/vdso.so.dbg"]
    assert kc.cmd_members("v/vdso.so.dbg", "ld -shared -T v/vdso.lds v/a.o v/b.o -o v/vdso.so.dbg") == ["v/a.o", "v/b.o"]
    assert kc.cmd_members("m/x.o", "gcc -c -o m/x.o m/x.c", compile_cmd=True) == []
    assert kc.cmd_members("m/x.o", "/opt/cc/bin/ld -r -o m/x.o /usr/lib/gcc/libgcc.a m/y.o") == ["m/y.o"]     # 樹外的絕對路徑不要求
    assert kc.cmd_members("m/built-in.a", 'printf "m/%s " a.o weird.txt | xargs ar cDPrST m/built-in.a') is None
    assert kc.cmd_members("lib/lib.a", "rm -f lib/lib.a; ar cDPrsT lib/lib.a lib/a.o $(foo)") is None


def test_build_record_compile_cmd_without_deps_is_gap(tmp_path):
    m = record_members()
    m[cmd_name("init/main.o")] = b"savedcmd_init/main.o := gcc -c -o init/main.o init/main.c\n\nsource_init/main.o := init/main.c\n"
    br = br_run(tmp_path, write_record_dir(tmp_path / "t", m))[2]["kernel"]["build_record"]
    assert br["status"] == "GAP" and "do not match kbuild's format" in br["reason"] and "init/.main.o.cmd" in br["reason"]


def test_build_record_without_kernel_release_needs_identical_config(tmp_path):
    rec = record_members(release=None, config=CONFIG + "CONFIG_GCC_VERSION=130200\n")
    br = br_run(tmp_path, write_record_dir(tmp_path / "t", rec))[2]["kernel"]["build_record"]
    assert br["status"] == "GAP" and "no include/config/kernel.release" in br["reason"] and "same_except_toolchain" in br["reason"]
    rec = record_members(config=CONFIG + "CONFIG_GCC_VERSION=130200\n")              # 有 kernel.release：只差工具鏈照舊可以
    assert br_run(tmp_path, write_record_dir(tmp_path / "u", rec))[2]["kernel"]["build_record"]["status"] == "OK"


def truncated(m, target, before, drop=()):
    """target 的 .cmd 截在 before 之前（沒有結尾的換行），並拿掉被截掉的成員的 .cmd（看起來像少了它們的完整紀錄）。"""
    k = cmd_name(target)
    m[k] = m[k][:m[k].index(before.encode())]
    for t in drop:
        del m[cmd_name(t)]
    return m


@pytest.mark.parametrize("case", ["link-ld-r", "ar", "ko", "deps"])
def test_build_record_truncated_cmd_is_gap(tmp_path, case):
    """被截斷的 .cmd（連結指令的成員、ar 的成員、.ko 的連結、deps_ 清單）＋拿掉被截掉的成員的 .cmd：不能被當成完整的紀錄。"""
    m = record_members()
    if case == "link-ld-r":
        truncated(m, "arch/arm64/kvm/hyp/nvhe/kvm_nvhe.tmp.o", " arch/arm64/kvm/hyp/nvhe/mem_protect.nvhe.o",
                  drop=("arch/arm64/kvm/hyp/nvhe/mem_protect.nvhe.o",))
    elif case == "ar":
        truncated(m, "drivers/firmware/efi/libstub/lib.a", " drivers/firmware/efi/libstub/efi-stub-helper.stub.o",
                  drop=("drivers/firmware/efi/libstub/efi-stub-helper.stub.o", "drivers/firmware/efi/libstub/efi-stub-helper.o"))
    elif case == "ko":
        truncated(m, "drivers/bar/bar.ko", " drivers/bar/bar.mod.o", drop=("drivers/bar/bar.mod.o",))
    else:
        truncated(m, "drivers/foo/always.o", "  include/linux/foo.h")             # deps_ 截在 \\ 的那一行之後
    out = br_run(tmp_path, write_record_dir(tmp_path / "t", m))[2]
    br = out["kernel"]["build_record"]
    assert br["status"] == "GAP" and "do not match kbuild's format" in br["reason"], br
    base = br_run(tmp_path)[2]
    assert out["results"] == base["results"]                                    # 照舊只用 Makefile：沒有新的 not_affected


def test_cmd_complete_rules():
    good = cmd_text("d/x.o", "d/x.c", ["include/a.h"])
    assert kc.cmd_complete(good, "d/x.o", True, True)
    assert kc.cmd_complete(good + "#SYMVER foo 0x1\n", "d/x.o", True, True)        # 結尾兩行之後的 #SYMVER
    assert not kc.cmd_complete(good[:-1], "d/x.o", True, True)                     # 沒有結尾的換行
    assert not kc.cmd_complete(good.replace("$(deps_d/x.o):\n", ""), "d/x.o", True, True)
    assert kc.cmd_complete("savedcmd_d/x.a := ar cDPrsT d/x.a d/y.o\n\n", "d/x.a", False, False)
    assert not kc.cmd_complete("savedcmd_d/x.a := ar cDPrsT d/x.a d/y.o\nd/z.o\n", "d/x.a", False, False)
    assert not kc.cmd_complete("savedcmd_d/x.a := ar cDPrsT d/x.a d/y.o", "d/x.a", False, False)


def test_build_record_image_module_missing_from_record_is_adopted(tmp_path):
    """紀錄少了映像裡的一個 kernel/ 模組（modules.order 與 .cmd 都沒有），映像也沒有模組清單可以比：不整份拒收，紀錄照用；
    這個模組列在 image_modules_not_in_record（它的檔案不判沒編，見 test_kernel_vendor_flow.py）。"""
    m = [x for x in rootfs_members() if not x[0].endswith(("modules.order", "modules.builtin"))]
    src = write_tar(tmp_path / "nolists.tar", m)
    rec = record_members(order=b"", drop=("drivers/bar/bar.o", "drivers/bar/bar.mod", "drivers/bar/bar.ko"))
    br = br_run(tmp_path, write_record_dir(tmp_path / "t", rec), src=src)[2]["kernel"]["build_record"]
    assert br["status"] == "OK" and br["image_modules_not_in_record"]["count"] == 1
    assert br["image_modules_not_in_record"]["modules"][0]["module"] == "kernel/drivers/bar/bar.ko.zst"
    assert br["image_modules_not_in_record"]["modules"][0]["source"] == "in_tree"


def test_build_record_prefix_inference_needs_tree_prefix():
    rec = kc.BuildRecord("x")
    rec.add_cmd(("drivers", "x", ".y.o.cmd"), cmd_text("drivers/x/y.o", "odd/drivers/x/y.c", []))
    rec.add_cmd(("drivers", "x", ".z.o.cmd"), cmd_text("drivers/x/z.o", "../drivers/x/z.c", []))
    rec.add_cmd(("drivers", "x", ".w.o.cmd"), cmd_text("drivers/x/w.o", "/src/linux/drivers/x/w.c", []))
    assert rec.roots[()]["prefix"] == {"../": 1, "/src/linux/": 1}                # "odd/" 不當前綴


def test_product_token_with_leading_dot():
    assert kc.cmd_members("d/x.ko", "ld -r -o d/x.ko d/x.o d/x.mod.o .module-common.o") == [".module-common.o", "d/x.mod.o", "d/x.o"]


def cut_compile(m, target, keep_blank=False):
    """編譯的 .cmd 只留第一行（savedcmd_）＋換行（或再加一個空行）：看起來像只有一行的「其他指令」。"""
    k = cmd_name(target)
    first = m[k].split(b"\n", 1)[0]
    m[k] = first + (b"\n\n" if keep_blank else b"\n")
    return m


@pytest.mark.parametrize("target,blank", [("drivers/foo/always.o", False), ("drivers/foo/always.o", True),
                                          ("arch/arm64/kernel/vdso-wrap.o", False), ("init/main.o", True)])
def test_build_record_compile_cmd_cut_after_first_line_is_gap(tmp_path, target, blank):
    """編譯指令被截在 savedcmd_ 那一行之後：source_／deps_ 都不見了，不能當成完整的「其他指令」（依指令判斷是編譯）。"""
    m = cut_compile(record_members(), target, blank)
    out = br_run(tmp_path, write_record_dir(tmp_path / "t", m))[2]
    br = out["kernel"]["build_record"]
    assert br["status"] == "GAP" and "do not match kbuild's format" in br["reason"] and cmd_name(target) in br["reason"], br
    assert out["results"] == br_run(tmp_path)[2]["results"]


def test_cmd_kind_rules():
    assert not kc.cmd_kind_ok("d/x.o", "gcc -Wp,-MMD,d/.x.o.d -c -o d/x.o d/x.c", False)          # 編譯卻沒有 source_
    assert not kc.cmd_kind_ok("d/x.o", "gcc -c -o d/x.o d/x.c", False)                             # 沒有依賴旗標也不是連結
    assert not kc.cmd_kind_ok("d/x.lds", "gcc -E -Wp,-MMD,d/.x.lds.d -P -o d/x.lds d/x.lds.S", False)
    assert kc.cmd_kind_ok("d/x.o", "gcc -Wp,-MMD,d/.x.o.d -c -o d/x.o d/x.c", True)
    for cmd in ("ld -EL -r -o d/x.o @d/x.mod", "rm -f d/x.o; aarch64-linux-gnu-ld -r -o d/x.o d/a.o",
                "/opt/bin/aarch64-none-linux-gnu-objcopy --prefix-symbols=__pi_ d/a.o d/x.o", "llvm-strip --strip-debug -o d/x.o d/a.o",
                "ld.lld -r -o d/x.o d/a.o"):
        assert kc.cmd_kind_ok("d/x.o", cmd, False), cmd
    assert kc.cmd_kind_ok("lib/test_fortify/x.log", "sh scripts/test_fortify.sh lib/test_fortify/x.c lib/test_fortify/x.log gcc -Wp,-MMD", False)


def test_build_record_tar_cut_at_member_boundary_is_gap(tmp_path):
    full = write_record_tar(tmp_path / "r.tar", record_members())
    with tarfile.open(full) as t:
        last = t.getmembers()[-1]
    end = last.offset_data + (last.size + 511) // 512 * 512
    cut = tmp_path / "cut.tar"
    cut.write_bytes(full.read_bytes()[:end])                       # 沒有結尾的零區塊
    br = br_run(tmp_path, cut)[2]["kernel"]["build_record"]
    assert br["status"] == "GAP" and "no end-of-archive marker" in br["reason"]
    assert br_run(tmp_path, full)[2]["kernel"]["build_record"]["status"] == "OK"


BANNER = b"Linux version 6.8.12-1021-tegra (builder@buildhost) (gcc (GCC) 13.2.0, GNU ld (GNU Binutils) 2.42) #1 SMP PREEMPT Thu Nov  6 07:31:00 UTC 2026\n"


def identity_files(version="#1 SMP PREEMPT Thu Nov  6 07:31:00 UTC 2026", by="builder"):
    return {"include/generated/utsversion.h": f'#define UTS_VERSION "{version}"\n'.encode(),
            "include/generated/compile.h": (f'#define UTS_MACHINE "aarch64"\n#define LINUX_COMPILE_BY "{by}"\n'
                                            '#define LINUX_COMPILE_HOST "buildhost"\n'
                                            '#define LINUX_COMPILER "gcc (GCC) 13.2.0, GNU ld (GNU Binutils) 2.42"\n').encode()}


@pytest.mark.parametrize("files,release,want", [(identity_files(), KVER, "matched"), ({}, KVER, "matched"), ({}, None, "not_tied"),
                                                (identity_files(version="#2 SMP PREEMPT Fri Nov  7 01:00:00 UTC 2026"), KVER, "mismatch"),
                                                (identity_files(by="someone"), KVER, "mismatch"), ({}, "6.8.12-other", "release-gap")])
def test_build_record_identity_with_image_banner(tmp_path, files, release, want):
    """紀錄的 kernel.release／utsversion.h／compile.h 和映像 /boot/Image 的版本字串核對：對不上 → GAP；沒有識別檔 → 採用但註明沒綁定。"""
    img = fake_image() + BANNER + b"\x00" * 64
    src = br_rootfs(tmp_path, extra=[("boot/Image", img, None)], name="img.tar")
    m = record_members(release=release)
    m.update(files)
    p, st, out = br_run(tmp_path, write_record_dir(tmp_path / "r", m), src=src)
    br = out["kernel"]["build_record"]
    if want == "release-gap":                       # kernel.release 和判定的核心版本不同：在比 banner 之前就 GAP
        assert br["status"] == "GAP" and "kernel.release" in br["reason"]
        return
    assert br["identity"]["banner_read"] is True and br["identity"]["result"] == want, br
    if want == "mismatch":
        assert br["status"] == "GAP" and "do not match the version banner" in br["reason"]
    else:
        assert br["status"] == "OK"
        assert (kc.RECORD_NOT_TIED_LIMITATION in br["limitations"]) == (want == "not_tied")
        assert ("建置紀錄沒有和映像綁定" in st[2]) == (want == "not_tied")
    assert "banner" not in json.dumps(out["kernel"].get("config_check") or {})        # Image 的紀錄格式不變


def test_find_banner():
    assert kc.find_banner(b"xx\x00" + BANNER + b"\x00") == BANNER.decode().rstrip("\n")
    assert kc.find_banner(b"no banner here") is None
