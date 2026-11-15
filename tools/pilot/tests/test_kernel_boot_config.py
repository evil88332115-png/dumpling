"""M7d-3a（adapter-gaps #23）：映像沒有 linux-headers 時，C-kernel-config／C-kernel-module-map 改讀出貨的 /boot/config-<版本>。
全部是合成資料（Debian 風格的 rootfs 資料夾：/boot/config-<版本>、dpkg 的 status 與 info/linux-image-<版本>.list／.md5sums、小的核心原始碼樹）。
  - 有原始碼樹（--source-tree）：依 /boot/config 判定；config_source、config_sha256、kernel.boot_config、依據的位置正確。
  - 沒有原始碼樹：GAP，說明是「有 /boot/config-<版本>（dpkg 驗證通過），但沒有 Makefile 來源…」。
  - 每一種驗證失敗都 GAP、不判定（md5 不同、沒有 dpkg 紀錄、擁有者不是 image 套件、符號連結、硬連結、超過上限、版本不同的 config）。
  - 有 headers 的路徑：輸出逐位元組不變（基準雜湊是改動前的程式在同一份輸入上的輸出）。
  - kernel_module_map.py 用同一份設定。"""
import gzip
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(__file__))
import test_kernel_config as tkc  # noqa: E402

kc = tkc.kc
ROOT = tkc.ROOT
sys.path.insert(0, str(ROOT / "tools" / "cra"))
import vex_export as vx  # noqa: E402

MAP_LIB = tkc.PILOT / "lib" / "kernel_module_map.py"
KVER = "6.8.12-1-amd64"
PKG = f"linux-image-{KVER}"
CFG = ("#\n# Automatically generated file; DO NOT EDIT.\n# Linux/x86 6.8.12 Kernel Configuration\n#\n"
       "CONFIG_X86=y\nCONFIG_X86_64=y\nCONFIG_FOO=y\n# CONFIG_FOO_A is not set\n").encode()
CFG_FOO_A = CFG.replace(b"# CONFIG_FOO_A is not set", b"CONFIG_FOO_A=y")
RECORDS = {"CVE-2024-0001": ["drivers/foo/a.c"], "CVE-2024-0002": ["drivers/foo/always.c"], "CVE-2024-0003": ["include/linux/x.h"]}
TREE_FILES = {"Makefile": "VERSION = 6\nPATCHLEVEL = 8\nSUBLEVEL = 12\nEXTRAVERSION =\n", "Kbuild": "obj-y += drivers/\n",
              "drivers/Makefile": "obj-$(CONFIG_FOO) += foo/\n", "drivers/foo/Makefile": "obj-$(CONFIG_FOO_A) += a.o\nobj-y += always.o\n"}
TREE_FILES.update({f"pad/p{i}/Makefile": "\n" for i in range(50)})      # 50 個以上的 Makefile 才像核心原始碼樹
GAP_NO_TREE = f"有 /boot/config-{KVER}（dpkg 驗證通過），但沒有 Makefile 來源（linux-headers 或 KERNEL_SOURCE_DIR）"
md5 = tkc.md5
sha = lambda b: hashlib.sha256(b).hexdigest()      # noqa: E731


def dpkg_status(pkgs):
    return "".join(f"Package: {n}\nStatus: {st}\nArchitecture: amd64\nVersion: 6.8.12-1\nDescription: kernel\n\n" for n, st in pkgs).encode()


def rootfs_files(config=CFG, owner=PKG, owner_md5=None, status=True, md5sums=True, cfg_name=None, extra_owners=(), installed="install ok installed",
                 modules=True):
    """Debian 風格的 rootfs：{相對路徑: bytes 或 ("link", 目標)}。owner：md5sums 記 /boot/config 的套件；owner_md5：它記的 md5。"""
    files = {}
    name = cfg_name or f"boot/config-{KVER}"
    if config is not None:
        files[name] = config
    if modules:
        files[f"usr/lib/modules/{KVER}/kernel/drivers/foo/foo.ko.xz"] = b"\xfd7zXZ"
        files[f"usr/lib/modules/{KVER}/modules.builtin"] = b"kernel/drivers/foo/always.ko\n"
        files[f"usr/lib/modules/{KVER}/modules.order"] = b"kernel/drivers/foo/foo.ko\n"
    files["etc/os-release"] = b"ID=debian\n"
    if status:
        files["var/lib/dpkg/status"] = dpkg_status([(owner, installed), ("other", "install ok installed")])
    if md5sums:
        files[f"var/lib/dpkg/info/{owner}.list"] = f"/boot\n/boot/config-{KVER}\n".encode()
        files[f"var/lib/dpkg/info/{owner}.md5sums"] = (
            f"{md5(b'x')}  usr/share/doc/{owner}/copyright\n{owner_md5 or md5(config or b'')}  boot/config-{KVER}\n").encode()
        for o in extra_owners:
            files[f"var/lib/dpkg/info/{o}.md5sums"] = f"{md5(config or b'')}  boot/config-{KVER}\n".encode()
        files["var/lib/dpkg/info/other.md5sums"] = f"{md5(b'y')}  usr/bin/x\n".encode()
    return files


def write_dir(d, files):
    d.mkdir(parents=True, exist_ok=True)
    for rel, v in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(v, tuple):
            os.symlink(v[1], p)
        else:
            p.write_bytes(v)
    return d


def tree(tmp_path, files=None, name="linux-6.8.12"):
    d = tmp_path / name
    for k, v in (files or TREE_FILES).items():
        (d / k).parent.mkdir(parents=True, exist_ok=True)
        (d / k).write_text(v)
    return d


def inputs(tmp_path):
    """共同的輸入：核心 CVE 清單、CNA 鏡像（固定的取得時間，輸出才可重複）、--max-age-days 放寬。"""
    cves = tmp_path / "cves.txt"
    cves.write_text("\n".join(RECORDS) + "\n")
    mirror = tmp_path / "m"
    if not (mirror / "SOURCE").exists():          # 同一個資料夾的兩個工具要讀同一份鏡像（zip 的 sha256 要相同）
        tkc.make_mirror(mirror, records=RECORDS, fetched="2026-11-01T00:00:00Z")
    return ["--cves", str(cves), "--mirror", str(mirror), "--max-age-days", "100000", "--kernel-version", KVER]


def run_tool(lib, tmp_path, src, *extra, name="out.json"):
    out = tmp_path / name
    p = subprocess.run([sys.executable, "-I", str(lib), *inputs(tmp_path), "--from", str(src), "--out", str(out), *extra],
                       capture_output=True, text=True, timeout=120)
    st = (p.stdout.strip().splitlines() or [""])[-1].split("\t")
    return p, st, (json.loads(out.read_text()) if out.exists() else None)


def k1(tmp_path, src, *extra):
    return run_tool(tkc.LIB, tmp_path, src, *extra, name="kernel-config.json")


def k2(tmp_path, src, *extra):
    return run_tool(MAP_LIB, tmp_path, src, *extra, name="kernel-module-map.json")


def by(out):
    return {r["cve"]: r["decision"] for r in out["results"]}


# ---------- 成立：有 /boot/config、dpkg 驗證通過、有原始碼樹 ----------

def test_boot_config_with_source_tree_judges(tmp_path):
    src = write_dir(tmp_path / "root", rootfs_files())
    p, st, out = k1(tmp_path, src, "--source-tree", str(tree(tmp_path)))
    assert p.returncode == 0 and st[1] == "OK", p.stdout + p.stderr
    k = out["kernel"]
    assert k["config_source"] == f"/boot/config-{KVER} (dpkg verified)" and k["config_sha256"] == sha(CFG)
    assert k["makefiles_from"] == "source-tree" and k["source_tree"]["version"] == "6.8.12" and k["source_tree"]["path_label"] == "linux-6.8.12"
    bc = k["boot_config"]
    assert bc["verified"] is True and bc["reason"] is None and bc["sha256"] == sha(CFG) and bc["md5"] == md5(CFG) and bc["size"] == len(CFG)
    assert bc["package"]["name"] == PKG and bc["package"]["version"] == "6.8.12-1" and bc["package"]["md5"] == md5(CFG)
    assert bc["owner_rule"] == "linux-image-{v}" and bc["makefiles_from"] == "source-tree" and all(c["ok"] for c in bc["checks"])
    assert by(out) == {"CVE-2024-0001": "not_affected", "CVE-2024-0002": "affected", "CVE-2024-0003": "unknown"}
    assert any("/boot/config-<version>" in x for x in out["limitations"]) and "config_check" not in k       # 沒有 Image：沒有核對
    assert f"/boot/config-{KVER}（dpkg 驗證通過" in st[2] and str(src) not in json.dumps(out)
    # 依據（D-035／D-057）：build-record，位置寫 /boot/config-<版本>、config 的 SHA-256 與原始碼樹的識別
    b = vx.kcfg_basis(out)
    assert b["type"] == "build-record" and b["kernel"] == KVER
    assert b["location"] == (f"scan/kernel-config.json (kernel {KVER}, config /boot/config-{KVER} SHA-256 {sha(CFG)}, "
                             "Makefile source tree linux-6.8.12 version 6.8.12)")
    assert vx._vexconv().location_problem(b["location"]) is None and len(b["location"]) <= 512


def test_boot_config_is_hashed_as_raw_bytes_and_other_kernel_tree_is_gap(tmp_path):
    cfg = CFG + b"# comment with a latin-1 byte \xe9\n"         # 不是 UTF-8：SHA-256 要用原始位元組算
    src = write_dir(tmp_path / "root", rootfs_files(config=cfg))
    p, st, out = k1(tmp_path, src, "--source-tree", str(tree(tmp_path)))
    assert st[1] == "OK" and out["kernel"]["config_sha256"] == sha(cfg) == out["kernel"]["boot_config"]["sha256"]
    # 原始碼樹的主.次版本和核心不同：照舊 GAP
    files = dict(TREE_FILES, Makefile=TREE_FILES["Makefile"].replace("PATCHLEVEL = 8", "PATCHLEVEL = 6"))
    p, st, out = k1(tmp_path / "x", write_dir(tmp_path / "x" / "root", rootfs_files()), "--source-tree", str(tree(tmp_path / "x", files)))
    assert st[1] == "GAP" and "主.次版本不同" in st[2] and out["results"] == []


@pytest.mark.parametrize("owner,rule", [(PKG, "linux-image-{v}"), (PKG + "-unsigned", "linux-image-{v}-unsigned"),
                                        (f"linux-image-unsigned-{KVER}", "linux-image-unsigned-{v}")])
def test_accepted_owner_names(tmp_path, owner, rule):
    src = write_dir(tmp_path / "root", rootfs_files(owner=owner))
    p, st, out = k1(tmp_path, src, "--source-tree", str(tree(tmp_path)))
    assert st[1] == "OK", st
    assert out["kernel"]["boot_config"]["owner_rule"] == rule and out["kernel"]["boot_config"]["package"]["name"] == owner


def test_without_source_tree_is_gap_with_the_new_reason(tmp_path):
    src = write_dir(tmp_path / "root", rootfs_files())
    p, st, out = k1(tmp_path, src)
    assert p.returncode == 0 and st[1] == "GAP" and GAP_NO_TREE in st[2], st
    assert out["results"] == [] and out["counts"] == {"not_affected": 0, "affected": 0, "unknown": 0}
    assert out["kernel"]["boot_config"]["verified"] is True and out["kernel"]["config_source"] == f"/boot/config-{KVER} (dpkg verified)"
    assert "makefiles_from" not in out["kernel"]
    # 舊的原因（沒有任何設定）不再出現在這種情況
    assert "要安裝核心 headers 套件" not in st[2]


# ---------- 每一種驗證失敗：GAP，不判定 ----------

def sym_files():
    f = rootfs_files(config=None)
    f["boot/real-config"] = CFG
    f[f"boot/config-{KVER}"] = ("link", "real-config")
    f["var/lib/dpkg/info/" + PKG + ".md5sums"] = f"{md5(CFG)}  boot/config-{KVER}\n".encode()
    f["var/lib/dpkg/status"] = dpkg_status([(PKG, "install ok installed")])
    return f


BIG = (b"# padding\n" * ((kc.MAX_BOOT_CONFIG // 10) + 2)) + CFG
FAILS = [
    ("md5_differs", lambda: rootfs_files(owner_md5=md5(b"another file")), "md5 不同"),
    ("md5_differs_content", lambda: rootfs_files(config=CFG_FOO_A, owner_md5=md5(CFG)), "md5 不同"),
    ("no_dpkg_at_all", lambda: rootfs_files(status=False, md5sums=False), "沒有 dpkg 紀錄"),
    ("no_owner_in_md5sums", lambda: dict(rootfs_files(), **{f"var/lib/dpkg/info/{PKG}.md5sums": f"{md5(b'x')}  usr/bin/y\n".encode()}),
     "沒有 dpkg 紀錄"),
    ("no_status", lambda: rootfs_files(status=False), "沒有 dpkg 紀錄"),
    ("not_installed", lambda: rootfs_files(installed="deinstall ok config-files"), "沒有 dpkg 紀錄"),
    ("owner_headers", lambda: rootfs_files(owner=f"linux-headers-{KVER}"), "不是這顆核心的 image 套件"),
    ("owner_other_package", lambda: rootfs_files(owner="some-other-package"), "不是這顆核心的 image 套件"),
    ("owner_modules_package", lambda: rootfs_files(owner=f"linux-modules-{KVER}"), "不是這顆核心的 image 套件"),
    ("owner_image_of_other_kernel", lambda: rootfs_files(owner="linux-image-6.8.12-2-amd64"), "不是這顆核心的 image 套件"),
    ("owner_dbg", lambda: rootfs_files(owner=PKG + "-dbg"), "不是這顆核心的 image 套件"),
    ("owner_prefix_only", lambda: rootfs_files(owner="linux-image-6.8.12"), "不是這顆核心的 image 套件"),
    ("two_owners", lambda: rootfs_files(extra_owners=("another-package",)), "擁有者不確定"),
    ("symlink", sym_files, "符號連結"),
    ("too_large", lambda: rootfs_files(config=BIG), "超過上限"),
    ("other_version_only", lambda: rootfs_files(config=None, md5sums=False) | {"boot/config-6.8.12-2-amd64": CFG}, "沒有 config-" + KVER),
    ("no_config_at_all", lambda: rootfs_files(config=None, md5sums=False), "要安裝核心 headers 套件"),
]


@pytest.mark.parametrize("name,files,why", FAILS, ids=[f[0] for f in FAILS])
def test_every_verification_failure_is_gap_and_judges_nothing(tmp_path, name, files, why):
    src = write_dir(tmp_path / "root", files())
    for sub, extra in (("with_tree", ["--source-tree", str(tree(tmp_path))]), ("no_tree", [])):         # 有原始碼樹也救不了
        d = tmp_path / sub
        d.mkdir()
        for tool in (k1, k2):
            p, st, out = tool(d, src, *extra)
            assert p.returncode == 0 and st[1] == "GAP" and why in st[2], (name, sub, tool.__name__, st)
            assert (out["results"] if tool is k1 else out["cves"]) in ([], {}), (name, sub, tool.__name__)
            if name != "no_config_at_all" and name != "other_version_only":
                assert out["kernel"]["boot_config"]["verified"] is False and why in out["kernel"]["boot_config"]["reason"]
                assert "dpkg verified" not in json.dumps(out["kernel"]["config_source"])


def test_hardlink_is_not_used(tmp_path):
    members = [(f"usr/lib/modules/{KVER}/kernel/x.ko", b"x"), (f"usr/lib/modules/{KVER}/modules.order", b"kernel/x.ko\n"),
               ("boot/real", CFG), ("var/lib/dpkg/status", dpkg_status([(PKG, "install ok installed")])),
               (f"var/lib/dpkg/info/{PKG}.md5sums", f"{md5(CFG)}  boot/config-{KVER}\n".encode())]
    with tarfile.open(tmp_path / "r.tar", "w") as t:
        for n, d in members:
            ti = tarfile.TarInfo(n)
            ti.size = len(d)
            t.addfile(ti, io.BytesIO(d))
        ti = tarfile.TarInfo(f"boot/config-{KVER}")
        ti.type, ti.linkname = tarfile.LNKTYPE, "boot/real"
        t.addfile(ti)
    p, st, out = k1(tmp_path, tmp_path / "r.tar", "--source-tree", str(tree(tmp_path)))
    assert st[1] == "GAP" and "硬連結" in st[2] and out["results"] == []
    assert out["kernel"]["boot_config"]["kind"] == "hardlink"


def test_docker_layers_whiteout_removes_boot_config():
    col = kc.ImageCollected()
    col.want_images = True
    col.feed(("boot", f"config-{KVER}"), "file", opener=lambda: io.BytesIO(CFG), size=len(CFG), layer=1)
    assert col.boot_cfg[("boot", f"config-{KVER}")][1] == "file"
    col.whiteout(("boot", f"config-{KVER}"), 2)
    assert ("boot", f"config-{KVER}") not in col.boot_cfg
    col.feed(("boot", f"config-{KVER}"), "file", opener=lambda: io.BytesIO(CFG), size=len(CFG), layer=1)
    col.feed(("boot", f"config-{KVER}"), "symlink", link="elsewhere", layer=2)           # 上層換成連結：不採用
    assert col.boot_cfg[("boot", f"config-{KVER}")] == (2, "symlink", "elsewhere")
    col.whiteout(("boot",), 3, opaque=True)
    assert col.boot_cfg == {}


def test_boot_config_count_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(kc, "MAX_BOOT_CONFIGS", 2)
    col = kc.ImageCollected()
    col.want_images = True
    for n in ("config-a", "config-b", "config-c"):
        col.feed(("boot", n), "file", opener=lambda: io.BytesIO(CFG), size=len(CFG))
    assert [v[1] for _, v in sorted(col.boot_cfg.items())] == ["file", "file", "skipped"]


# ---------- 有燒錄的 Image：照現有規則再核對一次 ----------

def image_files(image_config, owner_of_image=PKG, with_image_md5=True):
    img = tkc.fake_image(config=image_config) if image_config is not None else tkc.fake_image(ikconfig=False)
    f = rootfs_files()
    f["boot/Image"] = img
    if with_image_md5:
        cfg_line = f"{md5(CFG)}  boot/config-{KVER}\n" if owner_of_image == PKG else ""        # /boot/config 的擁有者只能有一個
        f[f"var/lib/dpkg/info/{owner_of_image}.md5sums"] = (cfg_line + f"{md5(img)}  boot/Image\n").encode()
        f["var/lib/dpkg/status"] = dpkg_status([(PKG, "install ok installed"), (owner_of_image, "install ok installed")])
    return f


def test_image_ikconfig_same_keeps_boot_config(tmp_path):
    p, st, out = k1(tmp_path, write_dir(tmp_path / "r", image_files(CFG)), "--source-tree", str(tree(tmp_path)))
    assert st[1] == "OK", st
    assert out["kernel"]["config_source"] == f"/boot/config-{KVER} (dpkg verified)" and out["kernel"]["config_check"]["result"] == "same"
    assert out["kernel"]["config_sha256"] == sha(CFG) and by(out)["CVE-2024-0001"] == "not_affected"


def test_image_ikconfig_differs_uses_ikconfig_like_headers(tmp_path):
    p, st, out = k1(tmp_path, write_dir(tmp_path / "r", image_files(CFG_FOO_A)), "--source-tree", str(tree(tmp_path)))
    assert st[1] == "ATTENTION", st
    assert out["kernel"]["config_source"] == "/boot/Image (IKCONFIG)" and out["kernel"]["config_check"]["result"] == "differs"
    assert out["kernel"]["config_sha256"] == sha(CFG_FOO_A) and by(out)["CVE-2024-0001"] == "affected"       # IKCONFIG 說 FOO_A 開著
    assert out["kernel"]["boot_config"]["verified"] is True
    p2, st2, out2 = k2(tmp_path / "m2", write_dir(tmp_path / "m2" / "r", image_files(CFG_FOO_A)), "--source-tree", str(tree(tmp_path / "m2")))
    assert out2["kernel"]["config_sha256"] == sha(CFG_FOO_A) and out2["kernel"]["config_source"] == "/boot/Image (IKCONFIG)"


def test_image_without_ikconfig_needs_same_image_package(tmp_path):
    ok = k1(tmp_path, write_dir(tmp_path / "r", image_files(None)), "--source-tree", str(tree(tmp_path)))
    assert ok[1][1] == "OK" and ok[2]["kernel"]["config_check"]["result"] == "dpkg_verified", ok[1]
    assert ok[2]["kernel"]["config_source"] == f"/boot/config-{KVER} (dpkg verified)"
    # /boot/Image 的擁有者是別的套件 → 燒錄的核心和 /boot/config 可能不一致 → GAP
    d = tmp_path / "other"
    d.mkdir()
    f = image_files(None, owner_of_image="vendor-kernel")
    p, st, out = k1(d, write_dir(d / "r", f), "--source-tree", str(tree(d)))
    assert st[1] == "GAP" and out["results"] == [] and out["kernel"]["config_check"]["result"] == "dpkg_not_verified"


# ---------- C-kernel-module-map：同一份設定 ----------

def test_module_map_uses_the_same_config(tmp_path):
    src = write_dir(tmp_path / "root", rootfs_files())
    t = str(tree(tmp_path))
    p1, st1, o1 = k1(tmp_path, src, "--source-tree", t)
    p2, st2, o2 = k2(tmp_path, src, "--source-tree", t, "--kernel-config", str(tmp_path / "kernel-config.json"))
    assert st1[1] == "OK" and st2[1] == "OK", (st1, st2, p2.stderr)
    assert o2["kernel"]["config_source"] == o1["kernel"]["config_source"] == f"/boot/config-{KVER} (dpkg verified)"
    assert o2["kernel"]["config_sha256"] == o1["kernel"]["config_sha256"] == sha(CFG) == o2["sources"]["config_sha256"]
    assert o2["sources"]["boot_config"] == {"path": f"/boot/config-{KVER}", "sha256": sha(CFG), "verified": True, "makefiles_from": "source-tree"}
    assert o2["kernel"]["boot_config"]["package"]["name"] == PKG
    assert o2["cves"]["CVE-2024-0001"]["files"][0]["build"] == "not_built"
    # 沒有原始碼樹：同一個原因
    p3, st3, o3 = k2(tmp_path / "n", write_dir(tmp_path / "n" / "root", rootfs_files()))
    assert st3[1] == "GAP" and GAP_NO_TREE in st3[2] and o3["cves"] == {}
    # 兩邊的設定不同（C-kernel-config 用的 sha256 對不上）→ 照舊 GAP
    bad = json.loads((tmp_path / "kernel-config.json").read_text())
    bad["kernel"]["config_sha256"] = "0" * 64
    (tmp_path / "bad.json").write_text(json.dumps(bad))
    p4, st4, o4 = k2(tmp_path, src, "--source-tree", t, "--kernel-config", str(tmp_path / "bad.json"))
    assert st4[1] == "GAP" and "不能並用" in st4[2]


# ---------- 有 headers 的路徑不變 ----------

def headers_rootfs(tmp_path, boot_config=None, owner=PKG):
    """Jetson 風格的 rootfs（headers 完整）；boot_config：另外放 /boot/config-<KVER>（有 headers 時不能被讀）。"""
    m = tkc.rootfs_members()
    if boot_config is not None:
        m += [(f"boot/config-{tkc.KVER}", boot_config, None),
              ("var/lib/dpkg/status", dpkg_status([(f"linux-image-{tkc.KVER}", "install ok installed")]), None),
              (f"var/lib/dpkg/info/linux-image-{tkc.KVER}.md5sums", f"{md5(boot_config)}  boot/config-{tkc.KVER}\n".encode(), None)]
    return tkc.write_tar(tmp_path / "rootfs.tar", m)


def canonical(out):
    out = json.loads(json.dumps(out))
    out.pop("cve_data", None)        # 鏡像的 zip 每次重寫時間戳不同，sha256 會變
    if isinstance(out.get("sources"), dict):
        out["sources"].pop("cna_mirror", None)           # C-kernel-module-map：同上
    return hashlib.sha256(json.dumps(out, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def run_headers(tmp_path, src, lib=tkc.LIB):
    cves = tmp_path / "cves.txt"
    cves.write_text("CVE-2024-0001\nCVE-2024-0002\nCVE-2024-0003\n")
    mirror = tkc.make_mirror(tmp_path / "m", fetched="2026-11-01T00:00:00Z")
    out = tmp_path / "o.json"
    p = subprocess.run([sys.executable, "-I", str(lib), "--cves", str(cves), "--mirror", str(mirror), "--max-age-days", "100000",
                        "--kernel-version", tkc.KVER, "--from", str(src), "--out", str(out)], capture_output=True, text=True, timeout=120)
    return p, p.stdout.strip().splitlines()[-1], json.loads(out.read_text())


# 改動前（main 4f64db7）的程式在 headers_rootfs 上的輸出（去掉 cve_data）的 SHA-256；改動後必須相同
BASELINE_K1 = "59827e06a922e1372f69fa7acdd4510c5e4df8bf7f3beccad6a4e748e9473118"
BASELINE_K1_LINE = "6464bce1461991177af03fdd79fdd69de145fb6a50dd98014bcdaab48d38e3a4"      # 狀態列（C-kernel-config<TAB>OK<TAB>說明）的 SHA-256
BASELINE_K2 = "297dd4168b955a94523420c0c1618668b0c5ddf8bafd94d0fb1c5fba61a80026"           # kernel_module_map.py 同一份輸入（去掉 sources.cna_mirror）
BASELINE_K2_LINE = "d0bb5c5ab5b2c52c6b9500c86f917d921d115a896bf0932b2204201dca3a6317"


def test_headers_path_output_is_unchanged(tmp_path):
    p, line, out = run_headers(tmp_path, headers_rootfs(tmp_path))
    assert p.returncode == 0 and out["status"] == "OK" and out["kernel"]["config_source"] == f"/{tkc.HDR}/.config"
    assert canonical(out) == BASELINE_K1, canonical(out)
    assert hashlib.sha256(line.encode()).hexdigest() == BASELINE_K1_LINE
    assert "boot_config" not in out["kernel"] and "boot_config" not in json.dumps(out)
    assert vx.kcfg_basis(out)["location"] == (f"scan/kernel-config.json (kernel {tkc.KVER}, config SHA-256 {sha(tkc.CONFIG.encode())})")


def test_headers_win_over_boot_config(tmp_path):
    """有 headers 時 /boot/config 完全不看（就算它是不同的設定，而且 dpkg 驗證通過）：輸出和沒有 /boot/config 時逐位元組相同。"""
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    base = run_headers(a, headers_rootfs(a))
    with_boot = run_headers(b, headers_rootfs(b, boot_config=tkc.CONFIG.encode().replace(b"CONFIG_FOO=y", b"# CONFIG_FOO is not set")))
    assert with_boot[1] == base[1] and canonical(with_boot[2]) == canonical(base[2]) == BASELINE_K1
    assert hashlib.sha256(with_boot[1].encode()).hexdigest() == BASELINE_K1_LINE
    assert with_boot[2]["kernel"]["config_source"] == f"/{tkc.HDR}/.config"


def test_module_map_headers_path_is_unchanged(tmp_path):
    p, line, out = run_headers(tmp_path, headers_rootfs(tmp_path, boot_config=CFG), lib=MAP_LIB)
    assert out["kernel"]["config_source"] == f"/{tkc.HDR}/.config" and "boot_config" not in json.dumps(out)
    assert out["kernel"]["config_sha256"] == sha(tkc.CONFIG.encode())
    assert canonical(out) == BASELINE_K2 and hashlib.sha256(line.encode()).hexdigest() == BASELINE_K2_LINE
