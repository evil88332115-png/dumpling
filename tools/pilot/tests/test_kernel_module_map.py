"""C-kernel-module-map（lib/kernel_module_map.py）：Kbuild 規則 → 每個 programFile 編進的模組或核心本體。

假的核心樹與鏡像沿用 test_kernel_config.py 的做法（tar、CNA 紀錄、SOURCE 的形狀相同）；modules.order／modules.builtin 的形狀
（每行 kernel/<樹內路徑>.ko）取自 NVIDIA 公開的 nvidia-l4t-kernel 39.2.1。
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

PILOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PILOT / "lib"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import kernel_config as kc  # noqa: E402
import kernel_module_map as kmm  # noqa: E402
import test_kernel_config as tkc  # noqa: E402  共用 tar、鏡像、Grype 的產生器

LIB = PILOT / "lib" / "kernel_module_map.py"
KVER = tkc.KVER
HDR = tkc.HDR

CONFIG = """#
# Linux/arm64 6.8.12 Kernel Configuration
#
CONFIG_ARM64=y
CONFIG_SIMPLE=m
CONFIG_COMP=m
CONFIG_COMP_EXTRA=y
# CONFIG_COMP_OFF is not set
CONFIG_NETDIR=y
CONFIG_NETDRV=m
CONFIG_CORE=y
CONFIG_MISMATCH=m
CONFIG_BIC=y
CONFIG_BIC_M=m
CONFIG_MDIR=m
CONFIG_UNC=m
# CONFIG_OFF is not set
"""

TREE = {
    "Kbuild": "obj-y += drivers/\nobj-y += arch/$(SRCARCH)/\n",
    "Makefile": "VERSION = 6\n",
    "arch/arm64/Kbuild": "obj-y += kernel/\n",
    "arch/arm64/kernel/Makefile": "obj-y += setup.o\n",
    "drivers/Makefile": "obj-y += simple/ comp/ core/ unc/\nobj-$(CONFIG_NETDIR) += net/\nobj-$(CONFIG_MDIR) += mdir/\n",
    "drivers/simple/Makefile": "obj-$(CONFIG_SIMPLE) += simple.o\nobj-m += plain.o\n",
    "drivers/comp/Makefile": ("obj-$(CONFIG_COMP) += comp.o\ncomp-y := comp_main.o comp_util.o\ncomp-$(CONFIG_COMP_EXTRA) += comp_extra.o\n"
                              "comp-$(CONFIG_COMP_OFF) += comp_off.o\n"
                              "obj-$(CONFIG_BIC) += bic.o\nbic-y := bic_a.o\nbic-$(CONFIG_BIC_M) += bic_m.o\n"),
    "drivers/net/Makefile": "obj-y += eth/\n",
    "drivers/net/eth/Makefile": "obj-$(CONFIG_NETDRV) += my-dash-drv.o\nmy-dash-drv-objs := dash_main.o\n",
    "drivers/core/Makefile": ("obj-$(CONFIG_CORE) += core.o\nobj-$(CONFIG_MISMATCH) += mism.o\nobj-$(CONFIG_OFF) += off.o\n"
                              "obj-y += ydis.o\n"),
    "drivers/mdir/Makefile": "obj-$(CONFIG_MDIR) += mmod.o\nobj-y += orphan.o\n",
    "drivers/unc/Makefile": "obj-$(CONFIG_UNC) += unc.o\nobj-y += $(call foo,bar).o\n",
}
TREE.update({f"pad/p{i}/Makefile": "\n" for i in range(45)})

ORDER = ("kernel/drivers/simple/simple.ko\nkernel/drivers/simple/plain.ko\nkernel/drivers/comp/comp.ko\n"
         "kernel/drivers/net/eth/my_dash-drv.ko\nkernel/drivers/mdir/mmod.ko\nkernel/drivers/core/ydis.ko\nkernel/drivers/unc/unc.ko\n")
BUILTIN = "kernel/drivers/comp/bic.ko\n"
KO = ["kernel/drivers/simple/simple.ko.zst", "kernel/drivers/comp/comp.ko.zst", "kernel/drivers/net/eth/my-dash-drv.ko.zst",
      "kernel/drivers/mdir/mmod.ko", "kernel/drivers/unc/unc.ko"]          # plain.ko 不在映像裡


def model(tree=None, config=CONFIG):
    files = {tuple(k.split("/")): v.encode() for k, v in (tree or TREE).items()}
    return kc.Model(kc.BuildInfo(files, config, "/x/.config", KVER, {"label": "test"}))


def mapper(order=ORDER, builtin=BUILTIN, ko=KO, tree=None):
    return kmm.Mapper(model(tree), set(ko) if ko is not None else None, kmm.ModList(order.encode()) if order is not None else None,
                      kmm.ModList(builtin.encode()) if builtin is not None else None)


@pytest.mark.parametrize("path,build,module,module_path,in_image", [
    ("drivers/simple/simple.c", "module", "simple", "kernel/drivers/simple/simple.ko", True),        # obj-$(CONFIG_X)=m
    ("drivers/simple/plain.c", "module", "plain", "kernel/drivers/simple/plain.ko", False),         # obj-m；.ko 不在映像
    ("drivers/comp/comp_main.c", "module", "comp", "kernel/drivers/comp/comp.ko", True),            # 組合物件 comp-y
    ("drivers/comp/comp_util.c", "module", "comp", "kernel/drivers/comp/comp.ko", True),
    ("drivers/comp/comp_extra.c", "module", "comp", "kernel/drivers/comp/comp.ko", True),           # comp-$(CONFIG_Y)=y
    ("drivers/comp/comp_off.c", "not_built", None, None, None),                                     # comp-$(CONFIG_OFF) 沒開
    ("drivers/comp/bic_a.c", "builtin", "bic", "kernel/drivers/comp/bic.ko", True),                 # =y 組合，modules.builtin 有
    ("drivers/net/eth/dash_main.c", "module", "my_dash_drv", "kernel/drivers/net/eth/my_dash-drv.ko", True),   # 巢狀資料夾、- 與 _
    ("drivers/core/core.c", "builtin", None, None, None),                                           # =y，modules.builtin 沒列
    ("drivers/core/off.c", "not_built", None, None, None),
    ("drivers/mdir/mmod.c", "module", "mmod", "kernel/drivers/mdir/mmod.ko", True),                 # 資料夾以 =m 進入
])
def test_map_file(path, build, module, module_path, in_image):
    r = mapper().map_file(path)
    assert (r["build"], r["module"], r["module_path"], r["in_image"]) == (build, module, module_path, in_image), r
    assert r["reason"]


def test_kbuild_name_kept_and_normalized():
    r = mapper().map_file("drivers/net/eth/dash_main.c")
    assert r["module"] == "my_dash_drv" and r["module_kbuild"] == "my-dash-drv" and r["object"] == "drivers/net/eth/dash_main.o"
    assert r["links"][0]["object"] == "drivers/net/eth/my-dash-drv.o" and r["links"][0]["cross_check"] == "ok"


@pytest.mark.parametrize("path,why", [
    ("drivers/core/mism.c", kmm.DISAGREE),                      # =m，modules.order 沒有
    ("drivers/core/ydis.c", kmm.DISAGREE),                      # =y，modules.order 卻有
    ("drivers/comp/bic_m.c", "-m member of the built-in composite"),
    ("drivers/mdir/orphan.c", "entered only for modules"),      # obj-y 在只為模組進入的資料夾：不連進 vmlinux
    ("drivers/unc/unc.c", "unexpandable"),                      # 同一個 Makefile 有看不懂的項目：可能另外編進 vmlinux
    ("include/linux/x.h", "header file"),
    ("drivers/comp/Kconfig", "build file"),
    ("drivers/newdir/n.c", "no Makefile rule"),
])
def test_map_file_unknown(path, why):
    r = mapper().map_file(path)
    assert r["build"] == "unknown" and why in r["reason"], r


def test_object_in_obj_y_and_obj_m_is_builtin():
    # Kbuild：obj-m := $(filter-out $(obj-y),$(obj-m))。真實例子 drivers/ata/libahci.o（SATA_AHCI=y、AHCI_DWC=m 共用）
    t = dict(TREE, **{"drivers/core/Makefile": TREE["drivers/core/Makefile"] + "obj-$(CONFIG_CORE) += shared.o\nobj-$(CONFIG_SIMPLE) += shared.o\n"})
    r = mapper(tree=t, builtin=BUILTIN + "kernel/drivers/core/shared.ko\n").map_file("drivers/core/shared.c")
    assert r["build"] == "builtin" and r["module_path"] == "kernel/drivers/core/shared.ko" and r["in_image"] is True, r
    assert [e["kind"] for e in r["links"]] == ["builtin"]


def test_disagreement_never_picks_a_side():
    # modules.order 把 comp 放在別的路徑：Kbuild 與清單對不上 → unknown，而不是採用任何一邊
    r = mapper(order=ORDER.replace("kernel/drivers/comp/comp.ko", "kernel/drivers/other/comp.ko")).map_file("drivers/comp/comp_main.c")
    assert r["build"] == "unknown" and r["reason"].startswith(kmm.DISAGREE) and "kernel/drivers/other/comp.ko" in r["reason"]
    # Kbuild 說 =m、modules.builtin 卻列它
    r = mapper(builtin=BUILTIN + "kernel/drivers/simple/simple.ko\n").map_file("drivers/simple/simple.c")
    assert r["build"] == "unknown" and "modules.builtin lists" in r["reason"]


def test_modules_builtin_overrides_only_towards_builtin():
    # Kbuild 判斷不了（ifdef 區塊）但 modules.builtin 有列 → builtin；Kbuild 判沒編、清單卻有 → 對不上
    t = dict(TREE, **{"drivers/core/Makefile": TREE["drivers/core/Makefile"] + "ifdef CONFIG_CORE\nobj-y += cond.o\nendif\n"})
    m = mapper(builtin=BUILTIN + "kernel/drivers/core/cond.ko\nkernel/drivers/core/off.ko\n", tree=t)
    r = m.map_file("drivers/core/cond.c")
    assert r["build"] == "builtin" and r["module_path"] == "kernel/drivers/core/cond.ko" and "conditional block" in r["reason"]
    assert mapper(tree=t).map_file("drivers/core/cond.c")["build"] == "unknown"
    r = m.map_file("drivers/core/off.c")
    assert r["build"] == "unknown" and r["reason"].startswith(kmm.DISAGREE)
    # 沒編的組合成員：組合模組本身在 modules.order 不算對不上（同 kernel_config 的同名核對）
    assert m.map_file("drivers/comp/comp_off.c")["build"] == "not_built"


def test_missing_module_lists():
    m = mapper(order=None, builtin=None, ko=None)
    r = m.map_file("drivers/simple/simple.c")          # 名稱沒辦法和 modules.order 核對 → unknown（K2 只承認核對過的名稱）
    assert r["build"] == "unknown" and r["in_image"] is None and r["module_path"] is None and "no modules.order" in r["reason"]
    assert r["links"][0]["module"] == "simple" and r["links"][0]["cross_check"] == "unavailable"
    assert m.map_file("drivers/core/core.c")["build"] == "builtin"
    r = m.map_file("drivers/comp/comp_off.c")            # 沒有模組目錄：無法核對 out-of-tree 的複本（同 kernel_config）
    assert r["build"] == "unknown" and "no module directory" in r["reason"]


def test_out_of_tree_same_name():
    m = mapper(ko=KO + ["updates/comp.ko", "updates/comp_off.ko"])
    r = m.map_file("drivers/comp/comp_main.c")
    assert r["build"] == "module" and r["other_same_name"] == ["updates/comp.ko"]
    assert kmm.map_cve(m, ["drivers/comp/comp_main.c"])["shadowed_by"] == {"comp": ["updates/comp.ko"]}
    assert kmm.map_cve(mapper(), ["drivers/comp/comp_main.c"])["shadowed_by"] == {"comp": []}
    r = m.map_file("drivers/comp/comp_off.c")            # 判「沒編」前的同名模組核對（同 kernel_config.judge_cve）
    assert r["build"] == "unknown" and "same name" in r["reason"]


def test_no_included_c_list_for_version_blocks_module_and_not_built():
    cfg = CONFIG.replace("6.8.12", "9.9.1")
    m = kmm.Mapper(model(config=cfg), set(KO), kmm.ModList(ORDER.encode()), kmm.ModList(BUILTIN.encode()))
    assert m.map_file("drivers/simple/simple.c")["build"] == "unknown"
    assert m.map_file("drivers/core/off.c")["build"] == "unknown"
    assert m.map_file("drivers/core/core.c")["build"] == "builtin"


@pytest.mark.parametrize("files,builtin,all_mod,modules", [
    (["drivers/simple/simple.c"], False, True, ["simple"]),
    (["drivers/comp/comp_main.c", "drivers/comp/comp_util.c", "drivers/comp/comp_extra.c"], False, True, ["comp"]),
    (["drivers/comp/comp_main.c", "drivers/comp/comp_off.c"], False, False, ["comp"]),          # not_built＋module → false
    (["drivers/core/core.c", "drivers/simple/simple.c"], True, False, ["simple"]),
    (["drivers/comp/bic_a.c"], True, False, []),
    (["drivers/net/eth/dash_main.c", "drivers/simple/plain.c"], False, True, ["my_dash_drv", "plain"]),
    (["include/linux/x.h", "drivers/simple/simple.c"], None, False, ["simple"]),               # 標頭檔
    (["drivers/core/mism.c"], None, False, []),                                                  # 對不上
    (["drivers/core/core.c", "drivers/core/mism.c"], True, False, []),                          # 有 builtin 就是 true
])
def test_map_cve(files, builtin, all_mod, modules):
    r = kmm.map_cve(mapper(), files)
    assert r["builtin"] is builtin and r["all_in_modules"] is all_mod and r["modules"] == modules, r
    assert type(r["builtin"]) in (bool, type(None)) and type(r["all_in_modules"]) is bool
    assert [f["path"] for f in r["files"]] == files


def test_all_not_built_is_null_and_kept():
    r = kmm.map_cve(mapper(), ["drivers/core/off.c", "drivers/comp/comp_off.c"])
    assert r["builtin"] is None and r["reason"] == kmm.ALL_NOT_BUILT and r["modules"] == [] and not r["all_in_modules"]
    assert [f["build"] for f in r["files"]] == ["not_built", "not_built"] and all(f["configs"] for f in r["files"])
    assert r["hints"] == []


def test_header_hint_only_flags():
    r = kmm.map_cve(mapper(), ["include/linux/x.h", "drivers/core/off.c"])
    assert r["builtin"] is None and r["hints"] == ["header_only_with_unbuilt_c"]
    assert kmm.map_cve(mapper(), ["include/linux/x.h", "drivers/core/core.c"])["hints"] == []
    assert kmm.map_cve(mapper(), ["drivers/x/Kconfig", "drivers/core/off.c"])["hints"] == []


# ---------- 命令列 ----------

RECORDS = {"CVE-2024-0001": ["drivers/simple/simple.c"],
           "CVE-2024-0002": ["drivers/comp/comp_main.c", "drivers/comp/comp_off.c"],
           "CVE-2024-0003": ["drivers/core/core.c"],
           "CVE-2024-0004": ["drivers/core/off.c"],
           "CVE-2024-0005": ["include/linux/x.h", "drivers/core/off.c"],
           "CVE-2024-0006": ["drivers/core/mism.c"],
           "CVE-2025-0007": None}


def rootfs(tmp_path, order=True, builtin=True, kver=KVER, extra=()):
    hdr = HDR.replace(KVER, kver)
    m = [("lib", None, "usr/lib"), (f"usr/lib/modules/{kver}/build", None, f"/{hdr}"), (f"{hdr}/.config", CONFIG.encode(), None)]
    m += list(extra)
    m += [(f"usr/lib/modules/{kver}/{k}", b"\x28\xb5", None) for k in KO]
    if order:
        m.append((f"usr/lib/modules/{kver}/modules.order", ORDER.encode(), None))
    if builtin:
        m.append((f"usr/lib/modules/{kver}/modules.builtin", BUILTIN.encode(), None))
    m += [(f"{hdr}/{k}", v.encode(), None) for k, v in TREE.items()]
    return tkc.write_tar(tmp_path / "rootfs.tar", m)


def run(tmp_path, *extra, cves=None, src=None, mirror=None, records=RECORDS):
    g = tmp_path / "grype.json"
    g.write_text(json.dumps(tkc.grype(cves if cves is not None else list(records) + ["CVE-2024-0404"])))
    km = tmp_path / "kmap.json"
    km.write_text(json.dumps(tkc.KMAP))
    src = rootfs(tmp_path) if src is None else src
    mirror = tkc.make_mirror(tmp_path / "m", records=records) if mirror is None else mirror
    out = tmp_path / "kernel-module-map.json"
    args = ["--grype", str(g), "--kernel-map", str(km), "--mirror", str(mirror), "--out", str(out)]
    args += ["--from", str(src)] if src else []
    p = subprocess.run([sys.executable, "-I", str(LIB), *args, *extra], capture_output=True, text=True, timeout=120)
    st = (p.stdout.strip().splitlines() or [""])[-1].split("\t")
    return p, st, (json.loads(out.read_text()) if out.exists() else None)


def test_cli_ok_contract(tmp_path):
    p, st, out = run(tmp_path)
    assert p.returncode == 0 and st[0] == "C-kernel-module-map" and st[1] == "OK", p.stdout + p.stderr
    assert out["schema"] == "sca-center-kernel-module-map/1" and out["status"] == "OK" and out["detail"] == st[2]
    assert out["kernel"]["version"] == KVER and out["component"] == tkc.TEGRA and isinstance(out["method"], str) and out["method"]
    s = out["sources"]
    assert s["kernel_version"] == KVER and s["config"] == f"/{HDR}/.config" and s["modules_dir"] == f"/usr/lib/modules/{KVER}/"
    assert s["modules_order"]["sha256"] == kmm.hashlib.sha256(ORDER.encode()).hexdigest() and s["modules_order"]["entries"] == 7
    assert s["modules_builtin"]["sha256"] == kmm.hashlib.sha256(BUILTIN.encode()).hexdigest() and s["cna_mirror"]["ok"] is True
    assert s["modules_order_sha256"] == s["modules_order"]["sha256"] and s["modules_builtin_sha256"] == s["modules_builtin"]["sha256"]
    assert out["modules_order"] == ["comp", "mmod", "my_dash_drv", "plain", "simple", "unc", "ydis"] and out["modules_builtin"] == ["bic"]
    assert out["modules_present"] == ["comp", "mmod", "my_dash_drv", "simple", "unc"]           # plain.ko 不在映像
    assert all(set(v["shadowed_by"]) == set(v["modules"]) for v in out["cves"].values())
    # K2 只把 modules_order 裡的名稱當成模組：每個 CVE 的 modules 都要在裡面
    assert all(n in out["modules_order"] for v in out["cves"].values() for n in v["modules"])
    assert all(f["module"] in out["modules_order"] for v in out["cves"].values() for f in v["files"] if f["build"] == "module")
    assert out["limitations"] == kmm.LIMITATIONS
    c = out["cves"]
    assert sorted(c) == sorted(list(RECORDS) + ["CVE-2024-0404"])
    assert c["CVE-2024-0001"]["builtin"] is False and c["CVE-2024-0001"]["all_in_modules"] is True and c["CVE-2024-0001"]["modules"] == ["simple"]
    f = c["CVE-2024-0001"]["files"][0]
    assert {k: f[k] for k in ("build", "module", "module_kbuild", "module_path", "in_image")} == {
        "build": "module", "module": "simple", "module_kbuild": "simple", "module_path": "kernel/drivers/simple/simple.ko", "in_image": True}
    assert c["CVE-2024-0002"]["builtin"] is False and c["CVE-2024-0002"]["all_in_modules"] is False
    assert c["CVE-2024-0003"]["builtin"] is True
    assert c["CVE-2024-0004"]["builtin"] is None and c["CVE-2024-0004"]["reason"] == kmm.ALL_NOT_BUILT and c["CVE-2024-0004"]["files"]
    assert c["CVE-2024-0005"]["hints"] == ["header_only_with_unbuilt_c"]
    assert c["CVE-2024-0006"]["builtin"] is None and kmm.DISAGREE in c["CVE-2024-0006"]["files"][0]["reason"]
    assert c["CVE-2025-0007"]["reason"] == "the CNA record lists no programFiles" and c["CVE-2025-0007"]["builtin"] is None
    assert c["CVE-2024-0404"]["reason"] == "no Linux kernel CNA record in the mirror"
    assert out["counts"]["builtin"] == {"true": 1, "false": 2, "null": 5} and out["counts"]["all_in_modules"] == 1
    assert out["counts"]["files"] == {"builtin": 1, "module": 2, "not_built": 3, "unknown": 2}
    # 每個 CVE 的 builtin 一定是 JSON 的 true／false／null，不是 0／1（json 把 0／1 讀成 int，bool 才是 true／false）
    for v in c.values():
        assert type(v["builtin"]) in (bool, type(None)) and type(v["all_in_modules"]) is bool
        assert all(type(f["in_image"]) in (bool, type(None)) for f in v["files"])
        for f in v["files"]:              # K2 讀的欄位名稱（其他欄位是附加的證據）
            assert {"path", "build", "module", "module_path", "in_image", "reason"} <= set(f) and f["build"] in kmm.BUILDS
    assert [f["path"] for f in c["CVE-2024-0002"]["files"]] == RECORDS["CVE-2024-0002"]       # CNA 的 programFiles 原樣
    assert sum(f["build"] == "not_built" for v in c.values() for f in v["files"]) == out["counts"]["files"]["not_built"]
    raw = (tmp_path / "kernel-module-map.json").read_text()
    assert raw.count('"builtin": true') + raw.count('"builtin": false') + raw.count('"builtin": null') >= len(c)


def test_cli_missing_module_dir_is_gap_with_null_in_image(tmp_path):
    t = tmp_path / "tree"
    for k, v in TREE.items():
        (t / k).parent.mkdir(parents=True, exist_ok=True)
        (t / k).write_text(v)
    (t / ".config").write_text(CONFIG)
    p, st, out = run(tmp_path, src=t)
    assert st[1] == "GAP" and "沒有模組目錄" in st[2], p.stdout + p.stderr
    assert out["status"] == "GAP" and out["cves"] and out["sources"]["modules_order"] is None
    assert out["modules_order"] is None and out["modules_builtin"] is None and out["sources"]["modules_order_sha256"] is None
    assert out["modules_present"] is None
    assert all(v["modules"] == [] and v["builtin"] is not False for v in out["cves"].values())
    files = [f for v in out["cves"].values() for f in v["files"]]
    assert files and all(f["in_image"] is None for f in files)


def test_cli_missing_modules_order_is_gap(tmp_path):
    p, st, out = run(tmp_path, src=rootfs(tmp_path, order=False))
    assert st[1] == "GAP" and "modules.order" in st[2] and out["modules_order"] is None and out["modules_builtin"] == ["bic"]
    v = out["cves"]["CVE-2024-0001"]
    assert v["files"][0]["build"] == "unknown" and v["modules"] == [] and v["builtin"] is None


def test_cli_not_run_without_kernel_cves(tmp_path):
    (tmp_path / "kernel-module-map.json").write_text("{}")          # 上一次的輸出不留下
    p, st, out = run(tmp_path, cves=[])
    assert p.returncode == 0 and st[1] == "NOT_RUN" and out is None


@pytest.mark.parametrize("what,msg", [("stale", "CNA 鏡像過期"), ("nomirror", "不存在"), ("version", "不是同一個核心"),
                                      ("fewmake", "headers 不完整")])
def test_cli_gaps(tmp_path, what, msg):
    src, mirror = None, None
    if what == "stale":
        mirror = tkc.make_mirror(tmp_path / "m", records=RECORDS, fetched=tkc.now(8))
    elif what == "nomirror":
        mirror = tmp_path / "nothere"
    elif what == "version":
        src = rootfs(tmp_path, kver="6.9.1-1-x")
    elif what == "fewmake":
        hdr = HDR
        src = tkc.write_tar(tmp_path / "r.tar", [("lib", None, "usr/lib"), (f"usr/lib/modules/{KVER}/build", None, f"/{hdr}"),
                                                  (f"usr/lib/modules/{KVER}/modules.order", ORDER.encode(), None),
                                                  (f"{hdr}/.config", CONFIG.encode(), None), (f"{hdr}/Kbuild", b"obj-y += x/\n", None),
                                                  (f"{hdr}/Makefile", b"\n", None)])
    extra = ("--kernel-version", "6.9.1-1-x") if what == "version" else ()     # .config 的標頭是 6.8.12，模組目錄是 6.9.1
    p, st, out = run(tmp_path, *extra, src=src, mirror=mirror)
    assert p.returncode == 0 and st[1] == "GAP" and msg in st[2], st
    assert out["status"] == "GAP" and out["cves"] == {}


def test_cli_bad_input(tmp_path):
    p = subprocess.run([sys.executable, "-I", str(LIB), "--out", str(tmp_path / "o.json")], capture_output=True, text=True)
    assert p.returncode == 3 and "參數錯誤" in p.stdout
    g = tmp_path / "g.json"
    g.write_text('{"matches": "x"}')
    (tmp_path / "o.json").write_text("{}")
    p = subprocess.run([sys.executable, "-I", str(LIB), "--grype", str(g), "--from", str(tmp_path), "--out", str(tmp_path / "o.json")],
                       capture_output=True, text=True)
    assert p.returncode == 3 and "FAIL" in p.stdout and not (tmp_path / "o.json").exists() and "Traceback" not in p.stderr


def test_kernel_config_unchanged_by_m_atom():
    # obj-m 的原子值改成 "m"（給這裡分辨）；kernel_config 的判定與說明不變（=m 一律算有編，obj-m 不記模組）
    assert kc.suffix_atom("m").value == "m" and kc.Model.atom(None, kc.suffix_atom("m")).value is True
    r = model().obj_built("drivers/simple/plain.o")
    assert r.value is True and r.modules == set()


def test_sca_scan_wiring():
    s = (PILOT / "sca-scan").read_text(encoding="utf-8")
    i = s.index('kernel_config.py" "${ka[@]+"${ka[@]}"}" "${KSRC[@]}" --out "$KCF"')
    j = s.index('kernel_module_map.py" "${ka[@]+"${ka[@]}"}" "${KSRC[@]}" "${KPREF[@]+"${KPREF[@]}"}" "${kk[@]+"${kk[@]}"}" --out "$KMM"')
    assert 'kk=(); [ -s "$KCF" ] && kk=(--kernel-config "$KCF")' in s
    assert i < j < s.index("# ---------- E. ScanCode.io")
    assert s.index('distro_recheck.py" --findings') < s.index('rm -f "$KMM" "$KMM.xz"') < i     # 不論有沒有執行，先刪上一次的結果
    assert 'KMM=$OUT/scan/kernel-module-map.json' in s
    assert 'NOT_RUN) rm -f "$KMM";;' in s and s.count("status C-kernel-module-map NOT_RUN") == 2
    assert "grep -m1 $'^C-kernel-module-map\\t'" in s


# ---------- 獨立審查的修正 ----------

def adv(tree, config, order, files, builtin="", ko=None):
    t = {"Kbuild": "obj-y += drivers/\n", "Makefile": "VERSION = 6\n"}
    t.update({f"pad/p{i}/Makefile": "\n" for i in range(45)})
    t.update(tree)
    cfg = "#\n# Linux/arm64 6.8.12 Kernel Configuration\n#\nCONFIG_ARM64=y\n" + config
    m = kc.Model(kc.BuildInfo({tuple(k.split("/")): v.encode() for k, v in t.items()}, cfg, "/x/.config", KVER, {"label": "t"}))
    ko = set(ko if ko is not None else ["kernel/" + l.strip() for l in order.splitlines() if l.strip()])
    return kmm.map_cve(kmm.Mapper(m, ko, kmm.ModList(order.encode()), kmm.ModList(builtin.encode())), files)


@pytest.mark.parametrize("name,tree,config,order,want,why", [
    # M1：$(subst m,y,…) 與 :m=y 在 =m 時編進核心
    ("subst obj", {"drivers/Makefile": "obj-y += a/\n", "drivers/a/Makefile": "obj-$(subst m,y,$(CONFIG_X)) += foo.o\n"},
     "CONFIG_X=m\n", "kernel/drivers/a/other.ko\n", "builtin", "obj-y"),
    ("subst obj listed in modules.order", {"drivers/Makefile": "obj-y += a/\n",
                                           "drivers/a/Makefile": "obj-$(subst m,y,$(CONFIG_X)) += foo.o\n"},
     "CONFIG_X=m\n", "kernel/drivers/a/foo.ko\n", "unknown", kmm.DISAGREE),
    ("subst dir", {"drivers/Makefile": "obj-$(subst m,y,$(CONFIG_X)) += a/\n", "drivers/a/Makefile": "obj-y += foo.o\n"},
     "CONFIG_X=m\n", "", "builtin", "obj-y"),
    ("subst builtin composite", {"drivers/Makefile": "obj-y += a/\n", "drivers/a/Makefile":
                                 "obj-$(CONFIG_X) += bar.o\nbar-y := foo.o\nobj-$(subst m,y,$(CONFIG_X)) += stub.o\nstub-y := foo.o\n"},
     "CONFIG_X=m\n", "kernel/drivers/a/bar.ko\n", "builtin", "obj-y"),
    # H1：:m=y 不再被略過
    (":m=y obj next to a module composite", {"drivers/Makefile": "obj-y += a/\n", "drivers/a/Makefile":
                                             "obj-$(CONFIG_X) += bar.o\nbar-y := foo.o\nobj-$(CONFIG_X:m=y) += foo.o\n"},
     "CONFIG_X=m\n", "kernel/drivers/a/bar.ko\n", "builtin", "obj-y"),
    (":m=y member of a built-in composite", {"drivers/Makefile": "obj-y += a/\n", "drivers/a/Makefile":
                                             "obj-$(CONFIG_X) += bar.o\nbar-y := foo.o\nobj-y += stub.o\nstub-$(CONFIG_X:m=y) += foo.o\n"},
     "CONFIG_X=m\n", "kernel/drivers/a/bar.ko\n", "builtin", "obj-y"),
    # extra-y：另外建置的目標，可能由別的規則連進 vmlinux → 不說「只在模組」
    ("extra-y + obj-m", {"drivers/Makefile": "obj-y += a/\n", "drivers/a/Makefile": "obj-m += foo.o\nextra-y += foo.o\n"},
     "", "kernel/drivers/a/foo.ko\n", "unknown", "extra-"),
    ("always-y member + obj-m", {"drivers/Makefile": "obj-y += a/\n",
                                 "drivers/a/Makefile": "obj-m += mod.o\nmod-y := foo.o\nalways-y += mod.o\n"},
     "", "kernel/drivers/a/mod.ko\n", "unknown", "extra-"),
    # L3：巢狀組合物件的每一層 Makefile 都要看得懂（中間那層 d/ 有看不懂的項目）
    ("nested chain", {"drivers/Makefile": "obj-y += a/ b/ c/ d/\n", "drivers/a/Makefile": "\n",
                      "drivers/c/Makefile": "inner-y := ../a/leaf.o\n",
                      "drivers/d/Makefile": "mid-y := ../c/inner.o\nobj-y += $(call foo,bar).o\n",
                      "drivers/b/Makefile": "obj-m += outer.o\nouter-y := ../d/mid.o\n"},
     "", "kernel/drivers/b/outer.ko\n", "unknown", "drivers/d/Makefile has an unexpandable entry"),
    ("nested chain, readable", {"drivers/Makefile": "obj-y += a/ b/ c/ d/\n", "drivers/a/Makefile": "\n",
                                "drivers/c/Makefile": "inner-y := ../a/leaf.o\n", "drivers/d/Makefile": "mid-y := ../c/inner.o\n",
                                "drivers/b/Makefile": "obj-m += outer.o\nouter-y := ../d/mid.o\n"},
     "", "kernel/drivers/b/outer.ko\n", "module", "only in module(s) outer"),
])
def test_review_cases(name, tree, config, order, want, why):
    f = tree["drivers/a/Makefile"]
    path = "drivers/a/leaf.c" if "leaf" in str(tree) else "drivers/a/foo.c"
    r = adv(tree, config, order, [path])
    assert r["files"][0]["build"] == want and why in r["files"][0]["reason"], (name, r["files"][0], f)
    assert r["builtin"] is {"builtin": True, "module": False, "unknown": None}[want]


def test_other_same_name_keeps_directory_dashes():
    # 資料夾名稱有 - 的模組（drivers/media/v4l2-core/videodev）：自己的 .ko 不算「別的位置的同名模組」
    tree = {"drivers/Makefile": "obj-y += v4l2-core/\n", "drivers/v4l2-core/Makefile": "obj-m += videodev.o\nvideodev-y := v4l2-dev.o\n"}
    order = "kernel/drivers/v4l2-core/videodev.ko\n"
    r = adv(tree, "", order, ["drivers/v4l2-core/v4l2-dev.c"], ko=["kernel/drivers/v4l2-core/videodev.ko.zst"])
    assert r["builtin"] is False and r["files"][0]["other_same_name"] == [] and r["shadowed_by"] == {"videodev": []}
    r = adv(tree, "", order, ["drivers/v4l2-core/v4l2-dev.c"],
            ko=["kernel/drivers/v4l2-core/videodev.ko.zst", "updates/drivers/media/videodev.ko"])
    assert r["shadowed_by"] == {"videodev": ["updates/drivers/media/videodev.ko"]}



# ---------- 第二次獨立審查（K2 負責人） ----------

def test_method_is_short_with_detail(tmp_path):
    assert len(kmm.METHOD) < 160 and len(kmm.METHOD_DETAIL) > len(kmm.METHOD)
    p, st, out = run(tmp_path)
    assert out["method"] == kmm.METHOD and out["method_detail"] == kmm.METHOD_DETAIL


def test_modules_present_counts_symlinked_ko(tmp_path):
    ex = [(f"usr/lib/modules/{KVER}/extra/plain.ko", None, "../kernel/drivers/simple/simple.ko.zst"),   # 連到存在的 .ko
          (f"usr/lib/modules/{KVER}/extra/ghost.ko", None, "../kernel/nothere.ko")]                     # 懸空
    p, st, out = run(tmp_path, src=rootfs(tmp_path, extra=ex))
    assert "plain" in out["modules_present"] and "ghost" not in out["modules_present"], out["modules_present"]
    # plain.ko 在模組清單的路徑（kernel/drivers/simple/plain.ko）不在映像，但 extra/ 有同名的連結：K2 依名稱看 modules_present
    f = next(f for v in out["cves"].values() for f in v["files"] if f["path"] == "drivers/simple/simple.c")
    assert f["build"] == "module"


def test_links_depth_cap():
    lines = ["obj-m += l0.o"] + [f"l{i}-y := l{i + 1}.o" for i in range(kmm.MAX_NEST + 3)]
    tree = {"drivers/Makefile": "obj-y += a/\n", "drivers/a/Makefile": "\n".join(lines) + "\n"}
    r = adv(tree, "", "kernel/drivers/a/l0.ko\n", [f"drivers/a/l{kmm.MAX_NEST + 3}.c"])
    assert r["files"][0]["build"] == "unknown" and "nested deeper than" in r["files"][0]["reason"], r["files"][0]
    short = "\n".join(["obj-m += l0.o"] + [f"l{i}-y := l{i + 1}.o" for i in range(kmm.MAX_NEST)]) + "\n"   # 剛好在上限內
    r = adv(dict(tree, **{"drivers/a/Makefile": short}), "", "kernel/drivers/a/l0.ko\n", [f"drivers/a/l{kmm.MAX_NEST}.c"])
    assert r["files"][0]["build"] == "module" and r["modules"] == ["l0"], r["files"][0]


def test_not_built_composite_listed_is_disagreement():
    # 組合物件本身沒編（CONFIG_OFF 沒開）但 modules.order 列了它 → 對不上；組合物件有編時（comp_off）照舊是 not_built
    tree = {"drivers/Makefile": "obj-y += a/\n", "drivers/a/Makefile": "obj-$(CONFIG_OFF) += off.o\noff-y := part.o\n"}
    r = adv(tree, "", "kernel/drivers/a/off.ko\n", ["drivers/a/part.c"], ko=[])
    assert r["files"][0]["build"] == "unknown" and r["files"][0]["reason"].startswith(kmm.DISAGREE)
    r = adv(tree, "", "kernel/drivers/a/other.ko\n", ["drivers/a/part.c"], ko=[])
    assert r["files"][0]["build"] == "not_built"
    assert mapper().map_file("drivers/comp/comp_off.c")["build"] == "not_built"


def test_kernel_config_mirror_identity_must_match(tmp_path):
    mirror = tkc.make_mirror(tmp_path / "m", records=RECORDS)
    sha = dict(l.split("=", 1) for l in (mirror / "SOURCE").read_text().splitlines())["zip_sha256"]
    k1 = tmp_path / "kernel-config.json"
    for cd, want in (({"commit_or_date": "a" * 40 + " (2026-11-01T13:42:14+01:00)", "zip_sha256": sha}, "OK"),
                     ({"commit_or_date": "a" * 40 + " (2026-11-01T13:42:14+01:00)", "zip_sha256": "0" * 64}, "GAP"),   # 同 commit、不同 zip
                     ({"commit_or_date": "a" * 40 + " (2026-11-01T13:42:14+01:00)"}, "GAP"),                          # 沒有記錄 zip_sha256
                     ({"commit_or_date": None, "zip_sha256": None}, "GAP")):                                         # 兩邊都沒有不算相同
        k1.write_text(json.dumps({"cve_data": cd}))
        p, st, out = run(tmp_path, "--kernel-config", str(k1), mirror=mirror)
        assert st[1] == want, (cd, st)
        if want == "GAP":
            assert "不能證明是同一份" in st[2] and out["cves"] == {}
    assert out["sources"]["cna_mirror"]["zip_sha256"] == sha
    p, st, out = run(tmp_path, mirror=mirror)
    assert st[1] == "OK" and out["sources"]["kernel_config_cna_mirror"] is None


def test_composite_consistency_for_configured_out_member():
    # N1：comp 是 =m 的組合模組；comp_off.c 依 config 沒放進去。comp 和清單不一致時不說 not_built
    assert mapper().map_file("drivers/comp/comp_off.c")["build"] == "not_built"
    r = mapper(builtin=BUILTIN + "kernel/drivers/comp/comp.ko\n").map_file("drivers/comp/comp_off.c")      # D
    assert r["build"] == "unknown" and "configured-out member" in r["reason"] and "modules.builtin lists" in r["reason"]
    r = mapper(order=ORDER.replace("kernel/drivers/comp/comp.ko\n", "")).map_file("drivers/comp/comp_off.c")   # E
    assert r["build"] == "unknown" and "modules.order does not list it" in r["reason"]


def test_bool_builtin_composite_absent_from_modules_builtin():
    # =y 的 bool 組合物件（像 thermal_sys.o）不在 modules.builtin 也不在 modules.order：依 config 沒放進去的成員照舊是 not_built
    tree = {"drivers/Makefile": "obj-y += t/\n",
            "drivers/t/Makefile": "obj-$(CONFIG_CORE) += tsys.o\ntsys-y := tcore.o\ntsys-$(CONFIG_OFF) += tdebug.o\n"}
    r = adv(tree, "CONFIG_CORE=y\n", "", ["drivers/t/tdebug.c"], builtin="kernel/drivers/other/x.ko\n", ko=[])
    assert r["files"][0]["build"] == "not_built" and r["reason"] == kmm.ALL_NOT_BUILT, r["files"][0]
    r = adv(tree, "CONFIG_CORE=y\n", "kernel/drivers/t/tsys.ko\n", ["drivers/t/tdebug.c"], ko=[])    # =y 卻在 modules.order
    assert r["files"][0]["build"] == "unknown" and "modules.order lists" in r["files"][0]["reason"]


def test_modules_present_lists_names_and_gaps_for_directory_links(tmp_path):
    # R3-H1：看得到的名稱一律列出；只有指向資料夾的連結解不開或目標不存在才算 gaps；指向檔案的連結不算
    ex = [(f"usr/lib/modules/{KVER}/updates", None, "/opt/nv/updates"), ("opt/nv/updates/x/host1x.ko", b"x", None)]
    p, st, out = run(tmp_path, src=rootfs(tmp_path, extra=ex))                       # 讀得到的資料夾連結
    assert "host1x" in out["modules_present"] and out["modules_present_gaps"] == []
    ex = [(f"usr/lib/modules/{KVER}/updates", None, "/opt/nothere")]                  # 懸空的資料夾連結
    p, st, out = run(tmp_path, src=rootfs(tmp_path, extra=ex))
    assert out["modules_present"] == ["comp", "mmod", "my_dash_drv", "simple", "unc"]
    assert len(out["modules_present_gaps"]) == 1 and out["modules_present_gaps"][0].startswith("updates -> /opt/nothere")
    ex = [(f"usr/lib/modules/{KVER}/README", None, "/usr/share/doc/x"), ("usr/share/doc/x", b"doc\n", None)]   # 指向檔案
    p, st, out = run(tmp_path, src=rootfs(tmp_path, extra=ex))
    assert out["modules_present"] == ["comp", "mmod", "my_dash_drv", "simple", "unc"] and out["modules_present_gaps"] == []
    ex = [(f"usr/lib/modules/{KVER}/docs", None, "/usr/share/doc")]                   # 指向沒有 .ko 的資料夾
    p, st, out = run(tmp_path, src=rootfs(tmp_path, extra=ex + [("usr/share/doc/y", b"y", None)]))
    assert out["modules_present_gaps"] == []


def test_ko_link_through_directory_link(tmp_path):
    # R3-L1：extra/x.ko -> ../updates/x.ko，updates 本身是資料夾連結
    ex = [(f"usr/lib/modules/{KVER}/updates", None, "/opt/nv/updates"), ("opt/nv/updates/host1x.ko", b"x", None),
          (f"usr/lib/modules/{KVER}/extra/tegra-drm.ko", None, "../updates/host1x.ko")]
    p, st, out = run(tmp_path, src=rootfs(tmp_path, extra=ex))
    assert {"host1x", "tegra_drm"} <= set(out["modules_present"]) and out["modules_present_gaps"] == []


def test_wide_composite_tree_is_fast():
    # N5：很多成員、很多層的組合物件（memo）
    import time
    lines = ["obj-m += top.o"] + [f"top-y += m{i}.o" for i in range(60)] + [f"m{i}-y += leaf{j}.o" for i in range(60) for j in range(20)]
    tree = {"drivers/Makefile": "obj-y += a/\n", "drivers/a/Makefile": "\n".join(lines) + "\n"}
    t0 = time.monotonic()
    r = adv(tree, "", "kernel/drivers/a/top.ko\n", [f"drivers/a/leaf{j}.c" for j in range(20)])
    assert time.monotonic() - t0 < 5 and r["builtin"] is False and r["modules"] == ["top"]
