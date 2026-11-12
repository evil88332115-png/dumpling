"""pack-build-record.sh：在合成的小資料夾上打包，檢查壓縮檔結構與警告。沒有任何產品資料。"""
import os
import subprocess
import tarfile

import pytest

SCRIPT = os.path.join(os.path.dirname(__file__), "..", "pack-build-record.sh")


def w(path, text=""):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


@pytest.fixture
def trees(tmp_path):
    k = tmp_path / "kbuild"
    w(k / ".config", "CONFIG_CC_VERSION_TEXT=\"gcc (test) 1.0\"\nCONFIG_X=y\n")
    w(k / "System.map", "0000 T start\n")
    w(k / "modules.order", "a.ko\n")
    w(k / "kernel/.x.o.cmd", "cmd\n")
    w(k / "kernel/x.o", "binary-not-packed")
    w(k / "arch/arm64/boot/Image", "img")
    o1 = tmp_path / "modA"
    w(o1 / ".y.o.cmd", "cmd\n")
    w(o1 / "y.ko", "ko")
    w(o1 / "y.c", "source-not-packed")
    o2 = tmp_path / "modB"          # 有 .cmd、沒有 .ko
    w(o2 / ".z.o.cmd", "cmd\n")
    o3 = tmp_path / "modC"          # 沒有 .cmd
    w(o3 / "c.c", "x")
    return tmp_path, k, o1, o2, o3


def pack(tmp, k, *oot):
    out = tmp / "rec.tar.gz"
    r = subprocess.run(["bash", SCRIPT, str(k), str(out), *map(str, oot)], capture_output=True, text=True)
    return r, out


def names(out):
    with tarfile.open(out) as t:
        return sorted(m.name for m in t.getmembers() if m.isfile())


def test_layout(trees):
    tmp, k, o1, *_ = trees
    r, out = pack(tmp, k, o1)
    assert r.returncode == 0, r.stderr
    n = names(out)
    assert "kernel/.config" in n and "kernel/System.map" in n and "kernel/modules.order" in n
    assert "kernel/kernel/.x.o.cmd" in n
    assert "oot1-modA/.y.o.cmd" in n and "oot1-modA/y.ko" in n
    assert "BUILD-INFO.txt" in n
    # 不打包原始碼或目的檔
    assert not any(x.endswith(("y.c", "x.o")) for x in n)
    assert "WARNING" not in r.stderr
    with tarfile.open(out) as t:
        info = t.extractfile("BUILD-INFO.txt").read().decode()
    assert "packed_utc=" in info and "image=arch/arm64/boot/Image sha256=" in info
    assert "CONFIG_CC_VERSION_TEXT" in info


def test_oot_without_ko_warns(trees):
    tmp, k, _, o2, _ = trees
    r, out = pack(tmp, k, o2)
    assert r.returncode == 0
    assert "has build commands but no .ko files" in r.stderr
    assert "oot1-modB/.z.o.cmd" in names(out)


def test_oot_without_cmd_warns(trees):
    tmp, k, _, _, o3 = trees
    r, _ = pack(tmp, k, o3)
    assert r.returncode == 0
    assert "has no build commands" in r.stderr


def test_numbering_and_skipped_dir(trees):
    tmp, k, o1, *_ = trees
    r, out = pack(tmp, k, tmp / "missing", o1)
    assert "skipped (not a directory)" in r.stderr
    assert "oot2-modA/y.ko" in names(out)


def test_not_a_kernel_dir(tmp_path):
    (tmp_path / "d").mkdir()
    r, out = pack(tmp_path, tmp_path / "d")
    assert r.returncode == 1
    assert "does not look like a kernel build directory" in r.stderr
    assert not out.exists()


def test_uefi_kconfig_and_buildlog(trees):
    tmp, k, o1, *_ = trees
    u = tmp / "uefi"
    w(u / "nvidia-config/t23x_general/config.dsc.inc", "CONFIG_X=y\n")
    w(u / "Build/BUILDLOG_t23x_general.txt", "log\n")
    w(u / "edk2/CryptoPkg/x.c", "source-not-packed")
    r, out = pack(tmp, k, f"--uefi={u}", o1)
    assert r.returncode == 0, r.stderr
    n = names(out)
    assert "uefi/nvidia-config/t23x_general/config.dsc.inc" in n and "uefi/Build/BUILDLOG_t23x_general.txt" in n
    assert "oot1-modA/y.ko" in n                      # --uefi does not shift the out-of-tree numbering
    assert not any(x.endswith("x.c") for x in n)
    assert "1 Kconfig file(s)" in r.stdout


def test_uefi_without_kconfig_warns(trees):
    tmp, k, o1, *_ = trees
    u = tmp / "uefi-empty"
    os.makedirs(u)
    r, out = pack(tmp, k, f"--uefi={u}")
    assert r.returncode == 0, r.stderr
    assert "no nvidia-config/*/config.dsc.inc" in r.stderr
    assert not any(x.startswith("uefi/") for x in names(out))
