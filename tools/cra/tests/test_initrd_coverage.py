"""initrd_coverage.py 與 bootloader_coverage.py --not-assessed。全部用測試自己組出來的假 rootfs 與假 initrd，不含任何產品資料。"""
import gzip
import hashlib
import io
import json
import lzma
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import bootloader_coverage as bc  # noqa: E402
import initrd_coverage as ic  # noqa: E402

CLI = HERE.parent / "initrd_coverage.py"
BCLI = HERE.parent / "bootloader_coverage.py"

ELF_A = b"\x7fELF" + b"A" * 200
ELF_B = b"\x7fELF" + b"B" * 300
ELF_C = b"\x7fELF" + b"C" * 120      # 只在 initrd
ELF_D = b"\x7fELF" + b"D" * 90       # rootfs 有相同內容，但不屬於任何套件
SCRIPT = b"#!/bin/sh\necho hi\n"
DATA = b"just data, not ELF or script\n"


def sha(b):
    return hashlib.sha256(b).hexdigest()


def cpio(entries):
    """entries：(名稱, 內容 bytes｜None＝資料夾｜("link", 目標)[, nlink, ino])。→ newc cpio bytes。"""
    out = bytearray()
    ino = 1
    for e in entries:
        name, body = e[0], e[1]
        nlink, i = (e[2], e[3]) if len(e) > 2 else (1, ino)
        ino += 1
        if body is None:
            mode, data = 0o040755, b""
        elif isinstance(body, tuple):
            mode, data = 0o120777, body[1].encode()
        else:
            mode, data = 0o100755, body
        nb = name.encode() + b"\0"
        hdr = b"070701" + b"".join(b"%08x" % v for v in (i, mode, 0, 0, nlink, 0, len(data), 0, 0, 0, 0, len(nb), 0))
        out += hdr + nb + b"\0" * ((-(110 + len(nb))) % 4) + data + b"\0" * ((-len(data)) % 4)
    nb = b"TRAILER!!!\0"
    out += b"070701" + b"".join(b"%08x" % v for v in (0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, len(nb), 0)) + nb + b"\0" * ((-(110 + len(nb))) % 4)
    return bytes(out) + b"\0" * 512


def initrd_entries():
    return [(".", None), ("usr", None), ("usr/bin", None),
            ("usr/bin/tool", ELF_A), ("usr/lib", None), ("usr/lib/libx.so.1", ELF_B), ("usr/bin/mine", ELF_C),
            ("usr/bin/loose", ELF_D), ("init", SCRIPT), ("etc/readme", DATA), ("bin", ("link", "usr/bin")),
            ("/etc/evil", ELF_C), ("../up/evil2", ELF_C), ("usr/bin/tool2", b"", 2, 99), ("usr/bin/tool3", ELF_A, 2, 99)]


def make_rootfs(root, with_lists=True, initrd=None, initrd_name="initrd"):
    root = Path(root)
    files = {"usr/bin/tool": ELF_A, "usr/lib/libx.so.1": ELF_B, "usr/bin/loose": ELF_D, "usr/share/doc/note": DATA}
    for rel, b in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b)
    (root / "bin").symlink_to("usr/bin")
    info = root / "var/lib/dpkg/info"
    info.mkdir(parents=True)
    if with_lists:
        (info / "toolpkg.list").write_text("/.\n/usr\n/usr/bin\n/usr/bin/tool\n")
        (info / "libx1:arm64.list").write_text("/usr/lib/libx.so.1\n")
    (root / "var/lib/dpkg/status").write_text(
        "Package: toolpkg\nStatus: install ok installed\nVersion: 1.2-3\n\nPackage: libx1\nStatus: install ok installed\nVersion: 9.9\n"
        "Architecture: arm64\n\nPackage: gone\nStatus: deinstall ok config-files\nVersion: 0.1\n")
    if initrd is not None:
        (root / "boot").mkdir()
        (root / "boot" / initrd_name).write_bytes(initrd)
    return root


def run_cli(*args):
    p = subprocess.run([sys.executable, "-I", str(CLI), *args], capture_output=True, text=True)
    return p.returncode, p.stdout.strip(), p.stderr


def load(tmp_path):
    return json.loads((tmp_path / "o" / "initrd-coverage.json").read_text())


def by_path(it):
    return {f["path"]: f for f in it["files"]}


def test_gzip_initrd_copies_and_initrd_only(tmp_path):
    root = make_rootfs(tmp_path / "rootfs", initrd=gzip.compress(cpio(initrd_entries())))
    rc, out, _ = run_cli("--from", str(root), "--out", str(tmp_path / "o"))
    assert rc == 2 and out.startswith("B-initrd-coverage\tGAP\t")
    d = load(tmp_path)
    it = d["initrds"][0]
    f = by_path(it)
    assert f["usr/bin/tool"]["result"] == "package_copy" and f["usr/bin/tool"]["package"] == "toolpkg" and f["usr/bin/tool"]["version"] == "1.2-3"
    assert f["usr/lib/libx.so.1"]["package"] == "libx1" and f["usr/lib/libx.so.1"]["version"] == "9.9"
    assert f["usr/bin/mine"]["result"] == "initrd_only"
    assert f["usr/bin/loose"]["result"] == "initrd_only" and "not part of a dpkg package" in f["usr/bin/loose"]["reason"]
    assert f["init"]["kind"] == "script" and f["init"]["result"] == "initrd_only"
    assert "etc/readme" not in f                                        # 資料檔不是 ELF／腳本
    assert it["rejected"] == 2 and not {"etc/evil", "/etc/evil", "../up/evil2"} & set(f)
    assert it["symlinks"] == 1
    # cpio 硬連結：沒有資料的名稱跟著有資料的那一筆
    assert f["usr/bin/tool2"]["sha256"] == sha(ELF_A) and f["usr/bin/tool3"]["package"] == "toolpkg"
    assert d["summary"]["elf"] == it["elf"] and d["summary"]["script"] == 1
    assert d["summary"]["package_copies"] + d["summary"]["initrd_only"] == it["elf"] + it["script"]
    assert str(tmp_path) not in (tmp_path / "o" / "initrd-coverage.json").read_text()      # 沒有主機路徑
    assert "initrd-only" in (tmp_path / "o" / "initrd-coverage.md").read_text()


def test_all_covered_is_ok(tmp_path):
    ents = [("usr", None), ("usr/bin", None), ("usr/bin/tool", ELF_A), ("usr/lib/libx.so.1", ELF_B)]
    root = make_rootfs(tmp_path / "rootfs", initrd=gzip.compress(cpio(ents)))
    rc, out, _ = run_cli("--from", str(root), "--out", str(tmp_path / "o"))
    assert rc == 0 and out.split("\t")[1] == "OK"
    assert load(tmp_path)["summary"]["initrd_only"] == 0


def test_no_dpkg_lists_nothing_is_covered(tmp_path):
    root = make_rootfs(tmp_path / "rootfs", with_lists=False, initrd=gzip.compress(cpio([("usr/bin/tool", ELF_A)])))
    rc, out, _ = run_cli("--from", str(root), "--out", str(tmp_path / "o"))
    d = load(tmp_path)
    assert rc == 2 and d["dpkg_file_lists_available"] is False
    assert d["initrds"][0]["files"][0]["result"] == "initrd_only" and "dpkg file lists" in d["initrds"][0]["files"][0]["reason"]


def test_early_cpio_then_xz(tmp_path):
    early = cpio([("kernel", None), ("kernel/x86", None)])[:-512]       # 未壓縮的 early cpio（微碼），後面接壓縮的主 cpio
    main = lzma.compress(cpio([("usr/bin/tool", ELF_A)]), format=lzma.FORMAT_XZ)
    root = make_rootfs(tmp_path / "rootfs", initrd=early + main)
    rc, out, _ = run_cli("--from", str(root), "--out", str(tmp_path / "o"))
    it = load(tmp_path)["initrds"][0]
    assert rc == 0 and it["formats"] == ["cpio", "xz"] and it["package_copies"] == 1


def test_two_gzip_segments(tmp_path):
    data = gzip.compress(cpio([("usr/bin/tool", ELF_A)])) + gzip.compress(cpio([("usr/bin/mine", ELF_C)]))
    root = make_rootfs(tmp_path / "rootfs", initrd=data)
    run_cli("--from", str(root), "--out", str(tmp_path / "o"))
    it = load(tmp_path)["initrds"][0]
    assert it["formats"] == ["gzip", "gzip"] and it["package_copies"] == 1 and it["initrd_only"] == 1


@pytest.mark.parametrize("blob,why", [(b"\x00\x01garbage-not-an-archive" * 10, "unknown data format"),
                                      (gzip.compress(cpio([("usr/bin/tool", ELF_A)]))[:-40], "")])
def test_unreadable_initrd_is_not_assessed(tmp_path, blob, why):
    root = make_rootfs(tmp_path / "rootfs", initrd=blob)
    rc, out, _ = run_cli("--from", str(root), "--out", str(tmp_path / "o"))
    it = load(tmp_path)["initrds"][0]
    assert rc == 2 and out.split("\t")[1] == "GAP" and it["status"] == "NOT_ASSESSED" and why in it["note"]


def test_decompression_bomb_is_capped(monkeypatch):
    monkeypatch.setattr(ic, "OUT_MAX", 1 << 20)
    big = cpio([("big.bin", b"\x7fELF" + b"\0" * (4 << 20))])
    res = ic.read_initrd(gzip.compress(big))
    assert res["status"] == "NOT_ASSESSED" and "limit" in res["note"]


def test_no_initrd_is_info(tmp_path):
    root = make_rootfs(tmp_path / "rootfs")
    rc, out, _ = run_cli("--from", str(root), "--out", str(tmp_path / "o"))
    assert rc == 0 and out.split("\t")[1] == "INFO" and "nothing to assess" in out


def test_tar_source_with_prefix_and_flashing_initrd(tmp_path):
    root = make_rootfs(tmp_path / "rootfs", initrd=gzip.compress(cpio([("usr/bin/tool", ELF_A), ("usr/bin/mine", ELF_C)])))
    tarp = tmp_path / "pkg.tar.gz"
    flashing = b"flashing initrd bytes"
    with tarfile.open(tarp, "w:gz") as t:
        t.add(root, arcname="Flash/rootfs")
        ti = tarfile.TarInfo("Flash/bootloader/l4t_initrd.img")
        ti.size = len(flashing)
        t.addfile(ti, io.BytesIO(flashing))
    inv = tmp_path / "flash-inventory.json"
    inv.write_text(json.dumps({"bootloader": [{"path": "Flash/bootloader/l4t_initrd.img", "size": len(flashing), "sha256": sha(flashing)},
                                              {"path": "Flash/bootloader/other.bin", "size": 1, "sha256": "0" * 64}]}))
    rc, out, _ = run_cli("--from", str(tarp), "--prefix", "Flash/rootfs", "--inventory", str(inv), "--out", str(tmp_path / "o"))
    d = load(tmp_path)
    assert rc == 2 and d["source"]["type"] == "archive" and d["summary"]["package_copies"] == 1 and d["summary"]["initrd_only"] == 1
    assert [x["path"] for x in d["flashing_initrds"]] == ["Flash/bootloader/l4t_initrd.img"]
    assert "used during flashing only" in d["flashing_initrds"][0]["note"]
    assert "只在燒錄時使用" in (tmp_path / "o" / "initrd-coverage.md").read_text()


def test_bad_source_fails(tmp_path):
    rc, out, _ = run_cli("--from", str(tmp_path / "nope"), "--out", str(tmp_path / "o"))
    assert rc == 1 and out.split("\t")[1] == "FAIL"


def test_rejects_unsafe_names():
    assert ic.safe_name("/abs") is False and ic.safe_name("a/../b") is False and ic.safe_name("./a/b") == "a/b" and ic.safe_name(".") is None


# ---------- Rockchip 等沒有定義開機鏈的平台 ----------

def test_not_assessed_cli(tmp_path):
    p = subprocess.run([sys.executable, "-I", str(BCLI), "coverage", "--result", str(tmp_path), "--variant", "rootfs", "--not-assessed", "rockchip"],
                       capture_output=True, text=True)
    assert p.returncode == 2
    stage, st, detail = p.stdout.strip().split("\t")
    assert (stage, st) == ("X-bootloader-coverage", "NOT_ASSESSED") and "boot chain not defined for this platform" in detail
    cov = json.loads((tmp_path / "rootfs" / "bootloader-coverage.json").read_text())
    assert cov["schema"] == bc.SCHEMA and cov["status"] == "NOT_ASSESSED" and cov["total"] == 0 and cov["items"] == []
    assert not any(cov["counts"].values()) and cov["platform_not_defined"] is True
    assert "NOT_ASSESSED" in (tmp_path / "rootfs" / "bootloader-coverage.md").read_text()
    t = bc.customer_text(cov)
    assert "NOT_ASSESSED" in t and "not a statement that it has no vulnerabilities" in t


def test_normal_coverage_unchanged_without_flag():
    cov = bc.build_coverage({"bootloader": []}, [], None, None, "rootfs")
    assert cov["status"] == "GAP" and "platform_not_defined" not in cov
