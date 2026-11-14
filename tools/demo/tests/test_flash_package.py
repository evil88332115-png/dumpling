import bz2
import hashlib
import io
import json
import re
import os
import shutil
import subprocess
import sys
import tarfile

import pytest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, ".."))
import flash_package as fp  # noqa: E402

REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
SCRIPT = os.path.join(REPO, "tools", "demo", "scan-flash-package.sh")
TOP = "product-a_OrinNano/Linux_for_Tegra"
NV_REL = b"# R39 (release), REVISION: 2.1, GCID: 12345678, BOARD: generic, EABI: aarch64, DATE: Mon Jan 1 00:00:00 UTC 2026\n"
STATUS = (b"Package: libc6\nStatus: install ok installed\nArchitecture: arm64\nVersion: 2.39-0ubuntu8\n\n"
          b"Package: nvidia-l4t-core\nStatus: install ok installed\nArchitecture: arm64\nVersion: 39.2.1-20260101000000\n\n"
          b"Package: nvidia-l4t-kernel\nStatus: install ok installed\nArchitecture: arm64\nVersion: 6.8.12-tegra-39.2.1-20260101000000\n\n"
          b"Package: removed-pkg\nStatus: deinstall ok config-files\nArchitecture: arm64\nVersion: 1.0\n")
BOOT_A = b"bootloader A" * 10
BOOT_B = b"partition image"


def add(t, name, v, mode=None):
    """v：bytes（一般檔）| ('dir',) | ('sym', 目標) | ('lnk', 目標) | ('chr',) | ('fifo',)"""
    ti = tarfile.TarInfo(name)
    ti.uid, ti.gid, ti.uname, ti.gname = 1000, 1000, "builder", "builder"
    if isinstance(v, bytes):
        ti.size, ti.mode = len(v), mode or 0o644
        t.addfile(ti, io.BytesIO(v))
        return
    ti.mode = mode or 0o755
    if v[0] == "dir":
        ti.type = tarfile.DIRTYPE
    elif v[0] == "sym":
        ti.type, ti.linkname = tarfile.SYMTYPE, v[1]
    elif v[0] == "lnk":
        ti.type, ti.linkname = tarfile.LNKTYPE, v[1]
    elif v[0] == "chr":
        ti.type, ti.devmajor, ti.devminor = tarfile.CHRTYPE, 1, 3
    elif v[0] == "fifo":
        ti.type = tarfile.FIFOTYPE
    t.addfile(ti)


def rootfs_entries(r, gui=False):
    e = [(f"{r}/", ("dir",)), (f"{r}/etc/", ("dir",)), (f"{r}/etc/nv_tegra_release", NV_REL),
         (f"{r}/etc/os-release", b'PRETTY_NAME="Ubuntu 24.04.3 LTS"\nID=ubuntu\n'),
         (f"{r}/usr/", ("dir",)), (f"{r}/usr/lib/", ("dir",)), (f"{r}/usr/bin/", ("dir",)),
         (f"{r}/lib", ("sym", "usr/lib")),
         (f"{r}/etc/localtime", ("sym", "/usr/share/zoneinfo/Etc/UTC")),
         (f"{r}/usr/bin/su", b"su-binary"),
         (f"{r}/usr/bin/perl5.38", b"perl"),
         (f"{r}/usr/bin/perl", ("lnk", f"{r}/usr/bin/perl5.38")),
         (f"{r}/var/", ("dir",)), (f"{r}/var/lib/", ("dir",)), (f"{r}/var/lib/dpkg/", ("dir",)),
         (f"{r}/var/lib/dpkg/status", STATUS),
         (f"{r}/dev/", ("dir",)), (f"{r}/dev/null", ("chr",)), (f"{r}/run/initctl", ("fifo",)),
         (f"{r}/lib/evil.so", b"through a symlink"),
         (f"{r}/usr/bin/outside-link", ("lnk", f"{TOP}/flash.sh"))]
    if gui:
        e.append((f"{r}/usr/bin/Xorg", b"xorg"))
    return e


def make_archive(path, extra=(), gui=True):
    with tarfile.open(path, "w:bz2", format=tarfile.PAX_FORMAT) as t:
        for n, v in [(f"{TOP.split('/')[0]}/", ("dir",)), (f"{TOP}/", ("dir",)), (f"{TOP}/flash.sh", b"#!/bin/bash\n"),
                     (f"{TOP}/product-a.conf", b"source p3767.conf\n"), (f"{TOP}/bootloader/", ("dir",)),
                     (f"{TOP}/bootloader/a.bin", BOOT_A), (f"{TOP}/bootloader/sub/b.img", BOOT_B),
                     (f"{TOP}/kernel/Image", b"kernel image"), (f"{TOP}/rootfs/README.txt", b"placeholder")]:
            add(t, n, v)
        for n, v in rootfs_entries(f"{TOP}/rootfs_no_gui"):
            add(t, n, v, mode=0o4755 if n.endswith("/su") else None)
        if gui:
            for n, v in rootfs_entries(f"{TOP}/rootfs_gui", gui=True):
                add(t, n, v)
        add(t, f"{TOP}/rootfs_no_gui/../../escape.txt", b"traversal")
        add(t, f"/{TOP}/rootfs_no_gui/etc/absolute", b"absolute")
        for n, v in extra:
            add(t, n, v)
    return path


@pytest.fixture(params=["python", "external"])
def archive(request, tmp_path, monkeypatch):
    if request.param == "external":
        # 外部解壓的路徑：沒有 lbzip2／pbzip2 時以 bzip2 代替（同樣的 -d -c 介面）
        real = fp.shutil.which
        alt = real("lbzip2") or real("pbzip2") or real("bzip2")
        if not alt:
            pytest.skip("沒有 lbzip2／pbzip2／bzip2")
        monkeypatch.setattr(fp.shutil, "which", lambda n: alt if n in ("lbzip2", "pbzip2") else real(n))
    monkeypatch.setenv("FLASHPKG_PARALLEL", "1" if request.param == "external" else "0")
    return make_archive(str(tmp_path / "product-a_OrinNano_V1.0.1_a.tbz2"))


def names(tar_path):
    with tarfile.open(tar_path) as t:
        return {m.name: m for m in t.getmembers()}


# ---------- md5 ----------

def test_md5_ok_and_mismatch(tmp_path, capsys):
    a = make_archive(str(tmp_path / "x.tbz2"))
    h = hashlib.md5(open(a, "rb").read()).hexdigest()
    good = tmp_path / "x.tbz2.md5"
    good.write_text(f"{h}  x.tbz2\n")
    assert fp.main(["md5", "--archive", a, "--md5", str(good)]) == 0
    assert capsys.readouterr().out.startswith("OK\t")
    bad = tmp_path / "bad.md5"
    bad.write_text("0" * 32 + "  x.tbz2\n")
    assert fp.main(["md5", "--archive", a, "--md5", str(bad)]) == 1
    assert capsys.readouterr().out.startswith("FAIL\t")
    other = tmp_path / "other.md5"
    other.write_text(f"{h.upper()} *another.tbz2\n")
    assert fp.main(["md5", "--archive", a, "--md5", str(other)]) == 0
    assert capsys.readouterr().out.startswith("ATTENTION\t")
    empty = tmp_path / "empty.md5"
    empty.write_text("nothing here\n")
    assert fp.main(["md5", "--archive", a, "--md5", str(empty)]) == 1


def test_parse_md5_formats():
    h = "d41d8cd98f00b204e9800998ecf8427e"
    assert fp.parse_md5_file(h + "\n") == (h, None, "hash-only")
    assert fp.parse_md5_file(f"{h}  product-a.tbz2\n") == (h, "product-a.tbz2", "md5sum-text")
    assert fp.parse_md5_file(f"{h} *product-a.tbz2\n") == (h, "product-a.tbz2", "md5sum-binary")
    assert fp.parse_md5_file(f"MD5 (product-a.tbz2) = {h}\n") == (h, "product-a.tbz2", "bsd")


# ---------- list ----------

def test_list_finds_rootfs_inventory_and_release(archive, tmp_path):
    r = fp.do_list(str(tmp_path / "list.json"), str(tmp_path / "inv.json"), archive=archive, product_version="V1.0.1")
    by = {c["prefix"]: c for c in r["rootfs"]}
    assert set(by) == {f"{TOP}/rootfs_no_gui", f"{TOP}/rootfs_gui", f"{TOP}/rootfs"}
    ng = by[f"{TOP}/rootfs_no_gui"]
    assert ng["variant"] == "rootfs_no_gui"
    assert ng["files"] == 6 and ng["symlinks"] == 2 and ng["hardlinks"] == 2 and ng["devices"] == 1 and ng["fifos"] == 1
    assert ng["l4t"]["release"] == "39.2.1" and ng["l4t"]["status"] == "OK"
    assert ng["l4t"]["sources"] == {"nv_tegra_release": "39.2.1", "nvidia-l4t-core": "39.2.1", "nvidia-l4t-kernel": "39.2.1"}
    assert "39.2.1" in ng["l4t"]["note"] and ng["l4t"]["note"].startswith("注意")   # V1.0.1 不是 39.2.1
    assert ng["dpkg"]["installed_packages"] == 3
    assert ng["os_release"] == "Ubuntu 24.04.3 LTS"
    assert by[f"{TOP}/rootfs"]["looks_like_rootfs"] is False
    assert r["rejected_members_count"] == 2
    assert r["ambiguous"] == {}
    f = r["flash_package"]
    assert f["flash_sh"] == [f"{TOP}/flash.sh"] and f["board_configs"] == [f"{TOP}/product-a.conf"]
    assert f["bootloader_files"] == 2 and f["bootloader_bytes"] == len(BOOT_A) + len(BOOT_B)
    inv = json.load(open(tmp_path / "inv.json"))
    boot = {e["path"]: e for e in inv["bootloader"]}
    assert boot[f"{TOP}/bootloader/a.bin"]["sha256"] == hashlib.sha256(BOOT_A).hexdigest()
    assert boot[f"{TOP}/bootloader/sub/b.img"]["size"] == len(BOOT_B)
    paths = {e["path"] for e in inv["outside_rootfs"]}
    assert f"{TOP}/kernel/Image" in paths and not any("rootfs_no_gui" in p for p in paths)
    assert json.load(open(tmp_path / "list.json"))["rootfs"][0]["prefix"] == f"{TOP}/rootfs"


def test_release_detection_cases():
    assert fp.l4t_from_nv_release("# R36 (release), REVISION: 4.3, GCID: 1") == "36.4.3"
    assert fp.l4t_from_core("39.2.0-20260101") == "39.2.0"
    assert fp.l4t_from_kernel("6.8.12-tegra-39.2.0-20260101") == "39.2.0"
    r = fp.l4t_release("# R39 (release), REVISION: 2.0", {"nvidia-l4t-core": "39.2.1-1", "nvidia-l4t-kernel": None})
    assert r["status"] == "ATTENTION" and r["release"] is None
    assert fp.l4t_release("", None)["status"] == "GAP"
    r = fp.l4t_release("", {"nvidia-l4t-core": "39.2.0-2026", "nvidia-l4t-kernel": "6.8.12-tegra-39.2.0-2026"})
    assert r["status"] == "OK" and r["release"] == "39.2.0" and "nv_tegra_release" in r["detail"]
    assert fp.version_note("V39.2.0.7", "39.2.0") == "產品版本 V39.2.0.7 以 L4T 版本 39.2.0 開頭"
    assert fp.version_note("V39.2.0.7", "39.2.1").startswith("注意")


def test_pick_all_and_ambiguous(archive, tmp_path):
    r = fp.do_list(str(tmp_path / "l.json"), str(tmp_path / "i.json"), archive=archive)
    assert fp.variants_all(r) == ["rootfs_no_gui", "rootfs_gui"]
    assert fp.pick(r, "rootfs_gui") == f"{TOP}/rootfs_gui"
    a2 = make_archive(str(tmp_path / "dup.tbz2"), extra=[("backup/rootfs_gui/etc/nv_tegra_release", NV_REL)])
    r2 = fp.do_list(str(tmp_path / "l2.json"), str(tmp_path / "i2.json"), archive=a2)
    assert "rootfs_gui" in r2["ambiguous"]
    with pytest.raises(fp.Fail):
        fp.pick(r2, "rootfs_gui")
    assert fp.variants_all(r2) == ["rootfs_no_gui"]
    with pytest.raises(fp.Fail):
        fp.pick(r2, "nothing")


# ---------- rootfs-tar ----------

def test_rootfs_tar_reroots_and_filters(archive, tmp_path):
    before = set(os.listdir(tmp_path))
    out, rep = str(tmp_path / "no_gui.tar"), str(tmp_path / "rep.json")
    r, = fp.do_rootfs_tar([(f"{TOP}/rootfs_no_gui", out, rep)], archive=archive)
    assert set(os.listdir(tmp_path)) - before == {"no_gui.tar", "rep.json"}      # 沒有解開到主機
    m = names(out)
    assert set(m) == {"./etc", "./etc/nv_tegra_release", "./etc/os-release", "./usr", "./usr/lib", "./usr/bin", "./lib",
                      "./etc/localtime", "./usr/bin/su", "./usr/bin/perl5.38", "./usr/bin/perl", "./var", "./var/lib",
                      "./var/lib/dpkg", "./var/lib/dpkg/status", "./dev", "./usr/bin/outside-link"}
    assert "./dev/null" not in m and "./run/initctl" not in m           # 裝置檔、FIFO 略過
    assert "./lib/evil.so" not in m                                      # 經過符號連結
    # 硬連結的目標在 rootfs 以外（flash.sh）：第二次讀取取出內容，寫成一般檔案
    assert m["./usr/bin/outside-link"].isreg()
    assert not any("escape" in n or "absolute" in n or "Xorg" in n for n in m)
    assert m["./lib"].issym() and m["./lib"].linkname == "usr/lib"
    assert m["./etc/localtime"].linkname == "/usr/share/zoneinfo/Etc/UTC"   # 絕對連結原樣保留
    assert m["./usr/bin/perl"].islnk() and m["./usr/bin/perl"].linkname == "./usr/bin/perl5.38"
    assert m["./usr/bin/su"].mode == 0o4755                               # 權限原樣
    assert all(x.uid == 0 and x.gid == 0 and x.uname == "root" for x in m.values())
    with tarfile.open(out) as t:
        assert t.extractfile("./var/lib/dpkg/status").read() == STATUS
        assert t.extractfile("./usr/bin/perl").read() == b"perl"          # 硬連結可讀
    assert r["skipped_devices"] == 1 and r["skipped_fifos"] == 1
    assert r["skipped_hardlinks"] == 0 and r["hardlinks_from_second_pass"] == 1 and r["rejected_through_symlink"] == 1
    assert r["rejected"] == 2                                            # ../ 與絕對路徑
    assert r["setuid_setgid"] == 1
    assert r["written"]["hardlink"] == 1 and r["written"]["symlink"] == 2
    assert json.load(open(rep))["prefix"] == f"{TOP}/rootfs_no_gui"


def test_rootfs_tar_hardlink_to_dir_skipped(tmp_path):
    r = f"{TOP}/rootfs_no_gui"
    a = make_archive(str(tmp_path / "x.tbz2"), gui=False, extra=[(f"{r}/usr/bin/dirlink", ("lnk", f"{r}/usr/lib")),
                                                                  (f"{r}/usr/bin/late", ("lnk", f"{r}/usr/bin/not-yet"))])
    rep, = fp.do_rootfs_tar([(r, str(tmp_path / "o.tar"), str(tmp_path / "r.json"))], archive=a)
    assert rep["skipped_hardlinks"] == 2            # 指向資料夾、目標不存在（outside-link 由第二次讀取補上內容）
    assert rep["hardlinks_from_second_pass"] == 1
    assert "./usr/bin/dirlink" not in names(str(tmp_path / "o.tar"))


def test_rootfs_tar_missing_prefix_removes_output(archive, tmp_path):
    out = tmp_path / "x.tar"
    with pytest.raises(fp.Fail):
        fp.do_rootfs_tar([(f"{TOP}/rootfs_nothing", str(out), str(tmp_path / "r.json"))], archive=archive)
    assert not out.exists()
    with pytest.raises(fp.Fail):
        fp.do_rootfs_tar([("../x", str(out), str(tmp_path / "r.json"))], archive=archive)


def test_members_does_not_accumulate(tmp_path):
    a = make_archive(str(tmp_path / "x.tbz2"))
    with fp.open_stream(a) as t:
        seen = 0
        for _ in fp.members(t):
            seen += 1
            assert len(t.members) <= 1
    assert seen > 20


@pytest.mark.parametrize("parallel", ["0", "1"])
def test_corrupt_archive_fails(tmp_path, monkeypatch, parallel):
    if parallel == "1":
        alt = fp.shutil.which("bzip2")
        if not alt:
            pytest.skip("沒有 bzip2")
        monkeypatch.setattr(fp.shutil, "which", lambda n: alt)
    monkeypatch.setenv("FLASHPKG_PARALLEL", parallel)
    a = make_archive(str(tmp_path / "x.tbz2"))
    data = open(a, "rb").read()
    open(a, "wb").write(data[: len(data) // 2])
    assert fp.main(["list", "--archive", a, "--out", str(tmp_path / "l.json"), "--inventory", str(tmp_path / "i.json")]) == 1


# ---------- CRA 設定與摘要 ----------

def load_cra():
    import importlib.util
    spec = importlib.util.spec_from_file_location("cra_report", os.path.join(REPO, "tools", "cra", "cra_report.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_cra_config_validates(archive, tmp_path):
    r = fp.do_list(str(tmp_path / "l.json"), str(tmp_path / "i.json"), archive=archive)
    cra = load_cra()
    for with_company in (False, True):
        cfg = fp.cra_config(r, "rootfs_no_gui", "product-a-OrinNano", "V1.0.1", "ab" * 16, None if with_company else "ACME Inc.")
        assert cfg["product"]["version"] == "V1.0.1 (rootfs_no_gui)"
        assert "L4T) 39.2.1" in cfg["product"]["identification"] and "ab" * 16 in cfg["product"]["identification"]
        proj = tmp_path / f"p{int(with_company)}"
        (proj / "CRA" / "Config").mkdir(parents=True)
        (proj / "CRA" / "Config" / "config.json").write_text(json.dumps(cfg))
        if with_company:
            assert "manufacturer" not in cfg
            comp = tmp_path / "company.json"
            comp.write_text(json.dumps({"schema_version": 1, "manufacturer": {"name": "Example Co."}}))
            merged, _, info = cra.load_config(proj, comp)
            assert merged["manufacturer"]["name"] == "Example Co." and info
        else:
            assert cfg["manufacturer"]["name"] == "ACME Inc."
            merged, _, info = cra.load_config(proj, None)
            assert info is None


def test_summary(tmp_path):
    out = tmp_path / "out"
    (out / "rootfs_no_gui" / "scan").mkdir(parents=True)
    (out / "rootfs_no_gui" / "cra-project" / "CRA" / "Reports").mkdir(parents=True)
    (out / "list.json").write_text(json.dumps({"rootfs": [{"variant": "rootfs_no_gui", "prefix": "a/rootfs_no_gui",
                                                           "l4t": {"release": "39.2.1", "detail": "L4T 39.2.1", "note": None},
                                                           "dpkg": {"installed_packages": 3}, "os_release": "Ubuntu 24.04"}]}))
    (out / "rootfs_no_gui" / "scan" / "status.tsv").write_text(
        "stage\tstatus\tdetail\nC-grype\tOK\tx\nC-kernel-l4t-map\tGAP\tL4T 39.2.0 不在對應檔\nC-kernel-coverage\tGAP\ty\n"
        "D-dt-findings\tOK\tz\nE-dejacode-import\tNOT_RUN\t--no-license\n")
    (out / "rootfs_no_gui" / "scan" / "meta.json").write_text(json.dumps({"name": "product-a", "version": "sha256:" + "0" * 64}))
    (out / "rootfs_no_gui" / "cra-project" / "CRA" / "Reports" / "summary.json").write_text(json.dumps(
        {"status": "GAP", "documents": {"risk-assessment": {"status": "GAP"}},
         "counts": {"rows": 10, "p1": 1, "p2": 2, "p3": 7, "accepted": 0, "kev_open": 1, "sbom_packages": 1234,
                    "kernel": {"rows": 4, "section": "listed"}, "non_kernel": {"rows": 6}}}))
    assert fp.main(["summary", "--out-dir", str(out), "--variant", "rootfs_no_gui", "--variant", "rootfs_gui"]) == 0
    s = json.load(open(out / "summary.json"))
    assert s[0]["vuln_rows"]["kernel"] == 4 and s[0]["vuln_rows"]["non_kernel"] == 6 and s[0]["sbom_packages"] == 1234
    assert set(s[0]["stages"]) == {"C-grype", "C-kernel-l4t-map", "C-kernel-coverage", "D-dt-findings"}
    assert s[1]["stages"] == {} and s[1]["cra_status"] is None
    md = open(out / "summary.md").read()
    assert "L4T：39.2.1" in md and "核心 4" in md and "C-kernel-l4t-map | GAP" in md and "report.html" in md


# ---------- scan-flash-package.sh（不跑 docker、sca-scan：用假的工具，只測到 MD5） ----------

def stub_path(tmp_path):
    b = tmp_path / "bin"
    b.mkdir(exist_ok=True)
    for t in ("syft", "grype", "bwrap"):
        (b / t).write_text("#!/bin/sh\necho 'Version: 0.0.0'\n")
    (b / "docker").write_text(f"#!/bin/sh\ncase \"$1\" in info) echo {tmp_path};; version) echo 0;; import) echo 'stub: no import' >&2; exit 1;; "
                              "*) exit 1;; esac\n")
    for f in b.iterdir():
        f.chmod(0o755)
    return f"{b}:{os.environ['PATH']}"


def run_script(tmp_path, *args, env=None):
    e = dict(os.environ, PATH=stub_path(tmp_path), FLASHPKG_ALLOW_TMP_OUT="1", **(env or {}))
    return subprocess.run(["bash", SCRIPT, *args], capture_output=True, text=True, env=e, timeout=120)


def test_script_md5_mismatch_stops(tmp_path):
    a = make_archive(str(tmp_path / "product-a.tbz2"))
    (tmp_path / "product-a.tbz2.md5").write_text("0" * 32 + "  product-a.tbz2\n")
    out = tmp_path / "res"
    p = run_script(tmp_path, "--archive", a, "--rootfs", "rootfs_no_gui", "--name", "product-a", "--version", "V1", "--out", str(out), "--no-upload")
    assert p.returncode == 1, p.stdout + p.stderr
    st = (out / "status.tsv").read_text()
    assert "A-md5\tFAIL" in st and "Z-done" in st
    assert not (out / "list.json").exists() and not (out / ".work").exists()
    assert oct(out.stat().st_mode & 0o777) == "0o700"


def test_script_requires_pilot_env(tmp_path):
    a = make_archive(str(tmp_path / "product-a.tbz2"))
    out = tmp_path / "res"
    p = run_script(tmp_path, "--archive", a, "--rootfs", "all", "--name", "product-a", "--version", "V1", "--out", str(out),
                   env={"PILOT_ENV": str(tmp_path / "missing.env")})
    assert p.returncode == 1
    assert "A-env\tFAIL" in (out / "status.tsv").read_text()


def test_script_flow_until_import(tmp_path):
    """docker import 失敗（假的 docker）：清點、L4T、rootfs tar 都跑過，tar 與暫存區刪除，不執行 sca-scan。"""
    a = make_archive(str(tmp_path / "product-a.tbz2"))
    h = hashlib.md5(open(a, "rb").read()).hexdigest()
    (tmp_path / "product-a.tbz2.md5").write_text(f"{h}  product-a.tbz2\n")
    out = tmp_path / "res"
    p = run_script(tmp_path, "--archive", a, "--rootfs", "all", "--name", "product-a", "--version", "V1.0.1", "--out", str(out), "--no-upload")
    st = (out / "status.tsv").read_text()
    assert p.returncode == 1, st
    for row in ("A-md5\tOK", "B-list\tOK", "B-l4t-rootfs_no_gui\tATTENTION", "B-l4t-rootfs_gui\tATTENTION", "B-rootfs-tar-rootfs_no_gui\tATTENTION",
                "B-rootfs-tar-rootfs_gui\tATTENTION", "B-import-rootfs_no_gui\tFAIL", "E-summary\tOK"):
        assert row in st, row
    assert "C-scan" not in st and "注意：產品版本 V1.0.1" in st
    # 套件資料庫在 docker import 之前從自己寫的 rootfs tar 取出（import 失敗也留著；D-pkg-why 要等 CRA 文件）
    assert "B-pkgdb-rootfs_no_gui\tOK" in st and (out / "rootfs_no_gui" / "pkgdb" / "dpkg-status").is_file()
    # 映像的靜態安全檢查也在 import 之前從同一個 tar 讀
    assert "B-image-check-rootfs_no_gui\t" in st and "B-image-check-rootfs_no_gui\tFAIL" not in st, st
    assert (out / "rootfs_gui" / "image-check" / "image-check.json").is_file()
    assert not (out / ".work").exists()
    assert (out / "flash-inventory.json").exists() and (out / "rootfs_gui" / "rootfs-tar.json").exists()
    assert "rootfs_gui" in (out / "summary.md").read_text()
    # 刷機包身分與這次的程式版本：一次讀完算 md5 與 sha256，md5 核對用同一個值
    pv = json.loads((out / "provenance.json").read_text())
    data = open(a, "rb").read()
    assert pv["source"] == {"type": "archive", "file": "product-a.tbz2", "bytes": len(data), "md5": h, "sha256": hashlib.sha256(data).hexdigest()}
    assert re.fullmatch(r"[0-9a-f]{40}", pv["sca_center"]["commit"]) and pv["sca_center"]["from"] == "git"
    assert re.search(r"^A-provenance\t(OK|ATTENTION)\t", st, re.M) and "F-evidence" not in st
    # 沒有 --product-config：檢查不悄悄消失，B-own-software 記 GAP（沒有宣告自有軟體），own-software.json 只有宣告的結果
    assert re.search(r"^B-own-software-rootfs_gui\tGAP\t沒有產品設定：沒有宣告自有軟體", st, re.M), st
    assert json.loads((out / "rootfs_gui" / "own-software" / "own-software.json").read_text())["declaration"]["kind"] == "undeclared"


OWN_CFG = {"schema_version": 1, "manufacturer": {"name": "Example Co."}, "product": {"name": "EX-J100"},
           "sbom": {"own_software": ["/usr/bin/su", "/usr/bin/not-there"]}}


def own_run(tmp_path, cfg, *extra, out="res"):
    """刷機包（只有 rootfs_no_gui）＋產品設定 → scan-flash-package.sh（假的 docker：import 失敗前的步驟都跑）。"""
    a = str(tmp_path / "pkg.tbz2")
    if not os.path.exists(a):
        make_archive(a, gui=False)
        (tmp_path / "pkg.tbz2.md5").write_text(f"{hashlib.md5(open(a, 'rb').read()).hexdigest()}  pkg.tbz2\n")
    pc = tmp_path / f"product-{out}.json"
    pc.write_text(json.dumps(cfg))
    o = tmp_path / out
    args = list(extra) if extra else ["--archive", a, "--rootfs", "rootfs_no_gui"]
    p = run_script(tmp_path, *args, "--name", "EX-J100", "--version", "V1", "--out", str(o), "--no-upload", "--product-config", str(pc))
    return p, o, (o / "status.tsv").read_text(), a


def test_script_own_software_from_rootfs_tar(tmp_path):
    """--product-config 有 sbom.own_software：docker import 之前從 rootfs tar 算雜湊（B-own-software），列了但找不到 → GAP。"""
    p, out, st, _ = own_run(tmp_path, OWN_CFG)
    assert "B-own-software-rootfs_no_gui\tGAP\t2 個樣式、1 個檔案算了雜湊" in st, st + p.stderr
    assert st.index("B-own-software-rootfs_no_gui") < st.index("B-import-rootfs_no_gui")
    doc = json.loads((out / "rootfs_no_gui" / "own-software" / "own-software.json").read_text())
    assert [f["path"] for f in doc["files"]] == ["usr/bin/su"] and doc["files"][0]["sha256"] == hashlib.sha256(b"su-binary").hexdigest()
    assert "GAP\tusr/bin/not-there\t" in (out / "rootfs_no_gui" / "logs" / "own-software.txt").read_text()


def test_script_product_config_without_own_software(tmp_path):
    """有 --product-config 但沒有列 sbom.own_software：不算雜湊，但 B-own-software 記 GAP（沒有宣告），不可以悄悄消失。"""
    cfg = {k: v for k, v in OWN_CFG.items() if k != "sbom"}
    p, out, st, _ = own_run(tmp_path, cfg)
    assert "B-import-rootfs_no_gui" in st, st + p.stderr
    assert re.search(r"^B-own-software-rootfs_no_gui\tGAP\t沒有宣告自有軟體（sbom\.own_software）", st, re.M), st
    doc = json.loads((out / "rootfs_no_gui" / "own-software" / "own-software.json").read_text())
    assert doc["status"] == "GAP" and doc["declaration"]["kind"] == "undeclared" and "files" not in doc
    assert not (out / "rootfs_no_gui" / "logs" / "own-software.txt").exists()


def test_script_product_config_declares_no_own_software(tmp_path):
    """sbom.own_software: [] 加 own_software_none_reason：明確宣告沒有 → OK，說明寫理由（是宣告，掃描沒有驗證）。"""
    cfg = dict(OWN_CFG, sbom={"own_software": [], "own_software_none_reason": "Image contains only distribution packages"})
    p, out, st, _ = own_run(tmp_path, cfg)
    assert re.search(r"^B-own-software-rootfs_no_gui\tOK\t製造商宣告沒有自有軟體：Image contains only distribution packages（是宣告", st, re.M), st
    # 空陣列但沒有理由：仍然是沒有宣告
    cfg2 = dict(OWN_CFG, sbom={"own_software": []})
    p2, out2, st2, _ = own_run(tmp_path, cfg2, out="res2")
    assert re.search(r"^B-own-software-rootfs_no_gui\tGAP\t", st2, re.M), st2


def rescan_prev(tmp_path):
    """上一次的結果（完整掃描到 import 之前）＋一份假的 Syft SBOM（--rescan-from 要有）。"""
    p, prev, st, a = own_run(tmp_path, OWN_CFG, out="prev")
    sb = prev / "rootfs_no_gui" / "scan" / "sbom"
    sb.mkdir(parents=True)
    (sb / "sbom.cdx.json").write_text('{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}')
    return prev, a


def test_script_rescan_own_software_branches(tmp_path):
    """--rescan-from：有 --archive 就重讀；沒有時沿用上一次的 own-software.json（ATTENTION）；上一次沒有 → GAP；
    設定沒有 sbom.own_software → 不寫狀態列。"""
    prev, a = rescan_prev(tmp_path)
    old = (prev / "rootfs_no_gui" / "own-software" / "own-software.json").read_bytes()
    rs = ["--rescan-from", str(prev), "--rootfs", "rootfs_no_gui"]
    # 1) 有 --archive：重讀（帶 --prefix 讀刷機包），結果和上一次相同
    _, o1, st, _ = own_run(tmp_path, OWN_CFG, *rs, "--archive", a, out="r1")
    assert "B-own-software-rootfs_no_gui\tGAP\t2 個樣式、1 個檔案算了雜湊" in st, st
    d1 = json.loads((o1 / "rootfs_no_gui" / "own-software" / "own-software.json").read_text())
    assert d1["source"]["type"] == "archive" and d1["files"] == json.loads(old)["files"]
    # 2) 沒有 --archive／--dir：沿用上一次的
    _, o2, st, _ = own_run(tmp_path, OWN_CFG, *rs, out="r2")
    assert "B-own-software-rootfs_no_gui\tATTENTION\t沿用上一次的" in st, st
    assert (o2 / "rootfs_no_gui" / "own-software" / "own-software.json").read_bytes() == old
    # 3) 上一次沒有 own-software.json
    os.remove(prev / "rootfs_no_gui" / "own-software" / "own-software.json")
    _, o3, st, _ = own_run(tmp_path, OWN_CFG, *rs, out="r3")
    assert "B-own-software-rootfs_no_gui\tGAP\t上一次沒有" in st, st
    # 4) 設定沒有 sbom.own_software：沒給 --archive 也照樣寫宣告的結果（沒宣告 → GAP），不悄悄消失
    _, o4, st, _ = own_run(tmp_path, {k: v for k, v in OWN_CFG.items() if k != "sbom"}, *rs, out="r4")
    assert re.search(r"^B-own-software-rootfs_no_gui\tGAP\t沒有宣告自有軟體", st, re.M) and "B-rescan-rootfs_no_gui\tOK" in st, st


def test_script_rescan_carries_rootfs_tar_and_uefi_binary_rows(tmp_path):
    """M7b：重跑沒有重讀 rootfs、沒有重做 UEFI 對照時，上一次的 B-rootfs-tar-<v>、B-uefi-binary 原樣帶過來（原本沒帶，
    cra_report 讀不到就略過，-bsp／-os 會比原掃描樂觀），並記在 run-params.json 的 carried（結構化，不從說明文字推）。"""
    prev, a = rescan_prev(tmp_path)
    pst = (prev / "status.tsv").read_text()
    m = re.search(r"^B-rootfs-tar-rootfs_no_gui\t(\w+)\t", pst, re.M)
    assert m, pst
    prev_tar = m.group(1)
    pp = json.loads((prev / "run-params.json").read_text())
    assert pp["schema"] == "dumpling-flash-run-params/1" and pp["rescan"] is False and pp["carried"] == {} and pp["flash_source"] == "archive"
    # 上一次的 UEFI 對照是 GAP（有兩列時取最嚴重的那一列）
    (prev / "uefi-binary-check.json").write_text("{}")
    with open(prev / "status.tsv", "a") as f:
        f.write("B-uefi-binary\tOK\tfirst\nB-uefi-binary\tGAP\tUEFI 映像和原始碼不一致\n")
    _, o, st, _ = own_run(tmp_path, OWN_CFG, "--rescan-from", str(prev), "--rootfs", "rootfs_no_gui", out="r")
    assert re.search(r"^B-rootfs-tar-rootfs_no_gui\t%s\t沿用上一次（--rescan-from，這次沒有重做）：" % prev_tar, st, re.M), st
    assert re.search(r"^B-uefi-binary\tGAP\t沿用上一次（--rescan-from，這次沒有重做）：UEFI 映像和原始碼不一致", st, re.M), st
    rp = json.loads((o / "run-params.json").read_text())
    assert rp["rescan"] is True and rp["rescan_from"] == str(prev) and rp["no_upload"] is True
    assert rp["carried"] == {"B-rootfs-tar-rootfs_no_gui": prev_tar, "B-uefi-binary": "GAP"}
    # 上一次沒有那一列，但原掃描應該要有（有 rootfs 的 SBOM、有 uefi-binary-check.json）→ GAP，carried 記 MISSING（#95 C0）
    p2 = tmp_path / "prev2"
    shutil.copytree(prev, p2)
    (p2 / "status.tsv").write_text("".join(l for l in pst.splitlines(True) if not l.startswith("B-rootfs-tar-")))
    _, o2, st2, _ = own_run(tmp_path, OWN_CFG, "--rescan-from", str(p2), "--rootfs", "rootfs_no_gui", out="r2")
    assert re.search(r"^B-rootfs-tar-rootfs_no_gui\tGAP\t上一次（--rescan-from）沒有這一列，原掃描應該要有", st2, re.M), st2
    assert re.search(r"^B-uefi-binary\tGAP\t上一次（--rescan-from）沒有這一列，原掃描應該要有（上一次有 uefi-binary-check.json）", st2, re.M), st2
    assert json.loads((o2 / "run-params.json").read_text())["carried"] == {"B-rootfs-tar-rootfs_no_gui": "MISSING", "B-uefi-binary": "MISSING"}
    # 原掃描本來就沒做 UEFI 對照（沒有 uefi-binary-check.json、也沒有那一列）→ 不寫 B-uefi-binary（不推測）
    os.remove(p2 / "uefi-binary-check.json")
    _, o3, st3, _ = own_run(tmp_path, OWN_CFG, "--rescan-from", str(p2), "--rootfs", "rootfs_no_gui", out="r3")
    assert "B-uefi-binary" not in st3, st3
    assert json.loads((o3 / "run-params.json").read_text())["carried"] == {"B-rootfs-tar-rootfs_no_gui": "MISSING"}


def test_script_rescan_uefi_binary_survives_consecutive_rescans(tmp_path):
    """#95 C0 驗證 1：給 --uefi-source、不給 --archive 的重跑只寫 B-uefi-binary NOT_RUN（沒有 json）；從那次結果再重跑、再重跑，
    這一列都要沿用下來（原本以「上一次有 uefi-binary-check.json」為條件，第二次重跑這一列就消失，-bsp 會比原掃描樂觀）。"""
    prev, a = rescan_prev(tmp_path)
    tree = tmp_path / "uefi-tree"
    tree.mkdir()
    rs = ["--rootfs", "rootfs_no_gui"]
    _, r1, st1, _ = own_run(tmp_path, OWN_CFG, "--rescan-from", str(prev), *rs, "--uefi-source", str(tree), out="r1")
    m = re.search(r"^B-uefi-binary\t(\w+)\t", st1, re.M)
    assert m and m.group(1) != "OK" and not (r1 / "uefi-binary-check.json").exists(), st1
    assert json.loads((r1 / "run-params.json").read_text())["uefi_source_given"] is True
    first = m.group(1)
    last = r1
    for n in ("r2", "r3"):
        _, o, st, _ = own_run(tmp_path, OWN_CFG, "--rescan-from", str(last), *rs, out=n)
        assert re.search(r"^B-uefi-binary\t%s\t沿用上一次" % first, st, re.M), (n, st)
        assert st.count("B-uefi-binary\t") == 1, st                                   # uefibin_step 不再寫第二列
        assert json.loads((o / "run-params.json").read_text())["carried"]["B-uefi-binary"] == first
        last = o
    # 上一次給過 --uefi-source（run-params.json）卻沒有這一列 → GAP
    p4 = tmp_path / "p4"
    shutil.copytree(r1, p4)
    (p4 / "status.tsv").write_text("".join(l for l in (r1 / "status.tsv").read_text().splitlines(True) if not l.startswith("B-uefi-binary")))
    _, o4, st4, _ = own_run(tmp_path, OWN_CFG, "--rescan-from", str(p4), *rs, out="r4")
    assert re.search(r"^B-uefi-binary\tGAP\t上一次（--rescan-from）沒有這一列，原掃描應該要有（上一次給了 --uefi-source", st4, re.M), st4


def test_script_rescan_carry_takes_the_worst_row_not_the_last(tmp_path):
    """#95 C0 驗證 3：上一次同一列 GAP 在前、OK 在後 → 沿用 GAP（取最嚴重，不是取最後一列）；OK 兩列 → ATTENTION。"""
    prev, a = rescan_prev(tmp_path)
    (prev / "uefi-binary-check.json").write_text("{}")
    base = (prev / "status.tsv").read_text()
    (prev / "status.tsv").write_text(base + "B-uefi-binary\tGAP\tfirst\nB-uefi-binary\tOK\tlast\n")
    _, o, st, _ = own_run(tmp_path, OWN_CFG, "--rescan-from", str(prev), "--rootfs", "rootfs_no_gui", out="w1")
    assert re.search(r"^B-uefi-binary\tGAP\t沿用上一次（--rescan-from，這次沒有重做）：first", st, re.M), st
    (prev / "status.tsv").write_text(base + "B-uefi-binary\tOK\tfirst\nB-uefi-binary\tOK\tlast\n")
    _, o, st, _ = own_run(tmp_path, OWN_CFG, "--rescan-from", str(prev), "--rootfs", "rootfs_no_gui", out="w2")
    assert re.search(r"^B-uefi-binary\tATTENTION\t沿用上一次（--rescan-from，這次沒有重做）：status.tsv 有 2 列 B-uefi-binary", st, re.M), st


def ownsw_function(tmp_path, fake):
    """scan-flash-package.sh 的 ownsw_step 單獨執行：ROOT 指到假的 tools/cra/own_software.py（stdout 與退出碼照 fake）。"""
    text = open(SCRIPT, encoding="utf-8").read()
    fn = re.search(r"^ownsw_step\(\)\{.*?^\}$", text, re.M | re.S).group(0)
    st_fn = re.search(r"^status\(\)\{.*$", text, re.M).group(0)
    root = tmp_path / "root"
    (root / "tools" / "cra").mkdir(parents=True)
    (root / "tools" / "cra" / "own_software.py").write_text(
        "import sys\nif '--configured' in sys.argv: sys.exit(0)\n" + fake)
    out = tmp_path / "out"
    (out / "v" / "logs").mkdir(parents=True)
    (tmp_path / "pc.json").write_text("{}")
    sh = f"{st_fn}\n{fn}\nROOT={root}; OUT={out}; PCONF={tmp_path / 'pc.json'}; ST={out}/status.tsv\nownsw_step v /x\n"
    subprocess.run(["bash", "-c", sh], capture_output=True, text=True, timeout=60)
    return (out / "status.tsv").read_text()


@pytest.mark.parametrize("fake,want", [
    ("print('B-own-software\\tOK\\tsays ok'); sys.exit(3)", "FAIL\town_software.py 印出 OK 但 exit 3"),
    ("print('B-own-software\\tGAP\\tg'); sys.exit(0)", "FAIL\town_software.py 印出 GAP 但 exit 0"),
    ("print('B-own-software\\tOK\\tfine')", "OK\tfine"),
    ("print('B-own-software\\tGAP\\tg'); sys.exit(2)", "GAP\tg"),
    ("raise SystemExit(5)", "FAIL\town_software.py 失敗（exit 5）"),
])
def test_script_ownsw_status_must_match_exit(tmp_path, fake, want):
    """印出的狀態和退出碼對不上 → FAIL（同 cra_step：exit 1 一律 FAIL）。"""
    assert ownsw_function(tmp_path, fake).startswith("B-own-software-v\t" + want)


def test_script_evidence_out_without_scan(tmp_path):
    """--evidence-out：摘要之後凍結證據包（F-evidence）；沒有任何掃描結果（docker import 失敗）時 FAIL、什麼都不寫。"""
    a = make_archive(str(tmp_path / "product-a.tbz2"))
    (tmp_path / "product-a.tbz2.md5").write_text(f"{hashlib.md5(open(a, 'rb').read()).hexdigest()}  product-a.tbz2\n")
    out, ev = tmp_path / "res", tmp_path / "evidence" / "not-yet" / "product-a"     # 上層資料夾還不存在：照樣執行（不靜默略過）
    p = run_script(tmp_path, "--archive", a, "--rootfs", "rootfs_no_gui", "--name", "product-a", "--version", "V1", "--out", str(out),
                   "--no-upload", "--evidence-out", str(ev))
    st = (out / "status.tsv").read_text()
    assert "F-evidence\tFAIL\t結果資料夾裡沒有任何 <rootfs>/scan/status.tsv" in st and p.returncode == 1, st + p.stderr
    assert st.index("E-summary") < st.index("F-evidence") < st.index("Z-done") and not (ev.exists() and list(ev.iterdir()))


@pytest.mark.parametrize("args", [["--rootfs", "rootfs_no_gui", "--name", "x"],
                                  ["--rootfs", "bogus", "--name", "x", "--version", "1"],
                                  ["--rootfs", "all", "--prefix", "a/rootfs_gui", "--name", "x", "--version", "1"]])
def test_script_argument_errors(tmp_path, args):
    a = make_archive(str(tmp_path / "product-a.tbz2"))
    p = run_script(tmp_path, "--archive", a, *args)
    assert p.returncode == 64


# ---------- 一次讀取寫出多個 rootfs；交付資料夾的其他檔案 ----------

def test_rootfs_tar_all_in_one_pass(tmp_path, monkeypatch):
    a = make_archive(str(tmp_path / "x.tbz2"))
    opened = []
    real = fp.open_stream

    def counting(path):
        opened.append(path)
        return real(path)
    monkeypatch.setattr(fp, "open_stream", counting)
    reps = fp.do_rootfs_tar([(f"{TOP}/rootfs_no_gui", str(tmp_path / "ng.tar"), str(tmp_path / "ng.json")),
                             (f"{TOP}/rootfs_gui", str(tmp_path / "g.tar"), str(tmp_path / "g.json"))], archive=a)
    assert len(opened) == 2           # 第一次讀取寫出兩個 rootfs；第二次只為了 rootfs 以外的硬連結目標（flash.sh）
    assert all(r["hardlinks_from_second_pass"] == 1 for r in reps)
    assert "./usr/bin/Xorg" in names(str(tmp_path / "g.tar")) and "./usr/bin/Xorg" not in names(str(tmp_path / "ng.tar"))
    assert reps[0]["rejected"] == 2 and reps[1]["rejected"] == 0
    assert names(str(tmp_path / "g.tar"))["./usr/bin/perl"].linkname == "./usr/bin/perl5.38"
    with pytest.raises(fp.Fail):
        fp.do_rootfs_tar([(f"{TOP}/rootfs_gui", str(tmp_path / "1.tar"), str(tmp_path / "1.json")),
                          (f"{TOP}/rootfs_gui/", str(tmp_path / "2.tar"), str(tmp_path / "2.json"))], archive=a)


def test_list_other_deliverables(tmp_path):
    d = tmp_path / "deliv"
    d.mkdir()
    a = make_archive(str(d / "product-a.tbz2"))
    (d / "product-a.tbz2.md5").write_text("0" * 32 + "  product-a.tbz2\n")
    (d / "product-a_MCU_V2.zip").write_bytes(b"PK\x03\x04 not opened")
    (d / "ReleaseNote.pdf").write_bytes(b"%PDF")
    (d / "SourceCode").mkdir()
    (d / "SourceCode" / "big.c").write_text("int main;")
    r = fp.do_list(str(tmp_path / "l.json"), str(tmp_path / "i.json"), archive=a, deliverables_dir=str(d))
    o = {x["name"]: x for x in r["other_deliverables"]}
    assert set(o) == {"product-a_MCU_V2.zip", "ReleaseNote.pdf", "SourceCode"}
    assert o["product-a_MCU_V2.zip"]["sha256"] == hashlib.sha256(b"PK\x03\x04 not opened").hexdigest()
    assert o["SourceCode"] == {"name": "SourceCode", "type": "dir", "note": "not inventoried"}
    inv = json.load(open(tmp_path / "i.json"))
    assert len(inv["other_deliverables"]) == 3 and "沒有掃描" in inv["other_deliverables_note"]
    assert r["source"]["type"] == "archive" and r["source"]["reader"]


# ---------- 資料夾來源（--dir） ----------

def make_tree(base, unreadable=True):
    """解開的刷機包：符號連結、硬連結、FIFO、socket、讀不到的檔案與資料夾、指向外面的符號連結。"""
    top = base / "Linux_for_Tegra"
    (top / "bootloader").mkdir(parents=True)
    (top / "flash.sh").write_text("#!/bin/bash\n")
    (top / "product-a.conf").write_text("x\n")
    (top / "bootloader" / "a.bin").write_bytes(BOOT_A)
    for r in ("rootfs_no_gui", "rootfs_gui"):
        R = top / r
        for d in ("etc", "usr/lib", "usr/bin", "var/lib/dpkg", "run"):
            (R / d).mkdir(parents=True, exist_ok=True)
        (R / "etc" / "nv_tegra_release").write_bytes(NV_REL)
        (R / "var" / "lib" / "dpkg" / "status").write_bytes(STATUS)
        (R / "usr" / "bin" / "perl5.38").write_bytes(b"perl")
        os.link(R / "usr" / "bin" / "perl5.38", R / "usr" / "bin" / "perl")
        (R / "usr" / "bin" / "su").write_bytes(b"su")
        os.chmod(R / "usr" / "bin" / "su", 0o4755)
        os.symlink("usr/lib", R / "lib")
        os.symlink("/etc", R / "hostetc")                 # 指向主機的資料夾：不跟隨
        os.symlink("../../..", R / "escape")             # 指向外面：原樣保留，不跟隨
        os.mkfifo(R / "run" / "initctl")
        if unreadable:
            (R / "etc" / "shadow").write_text("root:*:")
            os.chmod(R / "etc" / "shadow", 0)
            (R / "root").mkdir()
            (R / "root" / "secret").write_text("x")
            os.chmod(R / "root", 0)
    deep = top / "source"
    for i in range(12):
        deep = deep / f"d{i}"
    deep.mkdir(parents=True)
    (deep / "deep.c").write_text("x")
    return top


def can_test_unreadable():
    return hasattr(os, "geteuid") and os.geteuid() != 0


@pytest.fixture
def tree(tmp_path):
    base = tmp_path / "deliv"
    top = make_tree(base, can_test_unreadable())
    yield base, top
    for r in ("rootfs_no_gui", "rootfs_gui"):     # 讓 pytest 清得掉
        for p in (top / r / "root",):
            if p.exists():
                os.chmod(p, 0o755)


def test_dir_list(tree, tmp_path):
    base, top = tree
    r = fp.do_list(str(tmp_path / "l.json"), str(tmp_path / "i.json"), directory=str(base), product_version="V1.0.2")
    by = {c["prefix"]: c for c in r["rootfs"]}
    ng = by["Linux_for_Tegra/rootfs_no_gui"]
    assert ng["l4t"]["release"] == "39.2.1" and ng["dpkg"]["installed_packages"] == 3
    assert ng["symlinks"] == 3 and ng["hardlinks"] == 1 and ng["fifos"] == 1
    if can_test_unreadable():
        assert ng["unreadable_dirs"] == 1
    assert fp.variants_all(r) == ["rootfs_no_gui", "rootfs_gui"]
    assert r["flash_package"]["bootloader_files"] == 1 and r["flash_package"]["board_configs"] == ["Linux_for_Tegra/product-a.conf"]
    assert r["flash_package"]["outside_rootfs_dirs_not_walked"] >= 1
    inv = json.load(open(tmp_path / "i.json"))
    assert not any(x["path"].endswith("deep.c") for x in inv["outside_rootfs"])     # 太深的原始碼不走
    assert r["source"]["type"] == "dir"


def test_dir_rootfs_tar(tree, tmp_path):
    base, top = tree
    reps = fp.do_rootfs_tar([("Linux_for_Tegra/rootfs_no_gui", str(tmp_path / "ng.tar"), str(tmp_path / "ng.json")),
                             ("Linux_for_Tegra/rootfs_gui", str(tmp_path / "g.tar"), str(tmp_path / "g.json"))], directory=str(base))
    m = names(str(tmp_path / "ng.tar"))
    # 依名稱排序走訪：perl 先出現（一般檔案），perl5.38 是指向它的硬連結
    assert m["./usr/bin/perl5.38"].islnk() and m["./usr/bin/perl5.38"].linkname == "./usr/bin/perl"
    assert m["./lib"].issym() and m["./lib"].linkname == "usr/lib"
    assert m["./escape"].linkname == "../../.." and m["./hostetc"].linkname == "/etc"
    assert not any(n.startswith("./hostetc/") or n.startswith("./escape/") for n in m)      # 沒有跟隨
    assert "./run/initctl" not in m and "./etc/shadow" not in m
    assert m["./usr/bin/su"].mode == 0o4755
    assert all(x.uid == 0 and x.gid == 0 for x in m.values())
    with tarfile.open(str(tmp_path / "ng.tar")) as t:
        assert t.extractfile("./var/lib/dpkg/status").read() == STATUS
        assert t.extractfile("./usr/bin/perl5.38").read() == b"perl"
    r = reps[0]
    assert r["skipped_fifos"] == 1 and r["written"]["hardlink"] == 1
    if can_test_unreadable():
        assert r["unreadable_files"] == 1 and r["unreadable_dirs"] == 1
        assert any("etc/shadow" in x for x in r["examples"]["unreadable"])
        assert "./root" in m and not any(n.startswith("./root/") for n in m)
    assert reps[1]["written"]["file"] == reps[0]["written"]["file"]


def test_dir_socket_skipped(tmp_path):
    import socket
    base = tmp_path / "d"
    R = base / "rootfs_no_gui"
    (R / "etc").mkdir(parents=True)
    (R / "etc" / "nv_tegra_release").write_bytes(NV_REL)
    s = socket.socket(socket.AF_UNIX)
    try:
        s.bind(str(R / "s.sock"))
    except OSError:
        pytest.skip("建立不了 socket（路徑太長）")
    finally:
        s.close()
    rep, = fp.do_rootfs_tar([("rootfs_no_gui", str(tmp_path / "o.tar"), str(tmp_path / "o.json"))], directory=str(base))
    assert rep["skipped_sockets"] == 1 and "./s.sock" not in names(str(tmp_path / "o.tar"))


def test_dir_size_change_padded(tmp_path):
    f = io.BytesIO(b"abc")
    s = fp.Sized(f, 5)
    assert io.BufferedReader(s).read() == b"abc\0\0" and s.changed
    s = fp.Sized(io.BytesIO(b"abcdef"), 3)
    assert io.BufferedReader(s).read() == b"abc" and s.changed
    s = fp.Sized(io.BytesIO(b"abc"), 3)
    assert io.BufferedReader(s).read() == b"abc" and not s.changed


def test_dir_md5_list(tree, tmp_path, capsys):
    base, top = tree
    h = hashlib.md5(BOOT_A).hexdigest()
    good = tmp_path / "ok.md5"
    good.write_text(f"{h}  Linux_for_Tegra/bootloader/a.bin\n{hashlib.md5((top / 'flash.sh').read_bytes()).hexdigest()} *Linux_for_Tegra/flash.sh\n")
    assert fp.main(["md5", "--dir", str(base), "--md5", str(good)]) == 0
    assert capsys.readouterr().out.startswith("OK\t2 個檔案")
    bad = tmp_path / "bad.md5"
    bad.write_text(f"{h}  ../outside\n{'0' * 32}  Linux_for_Tegra/flash.sh\n{h}  missing.bin\n")
    assert fp.main(["md5", "--dir", str(base), "--md5", str(bad)]) == 1
    out = capsys.readouterr().out
    assert out.startswith("FAIL\t") and "路徑不合法" in out
    only = tmp_path / "only.md5"
    only.write_text(h + "\n")
    assert fp.main(["md5", "--dir", str(base), "--md5", str(only)]) == 1


def test_split_name_rejects_traversal():
    assert fp.split_name("a/../b") is None and fp.split_name("/abs") is None
    assert fp.split_name("./a//b/.") == ("a", "b")


def test_script_dir_flow_until_import(tree, tmp_path):
    base, top = tree
    out = tmp_path / "res"
    p = run_script(tmp_path, "--dir", str(base), "--rootfs", "rootfs_gui", "--name", "product-a", "--version", "V1.0.2_a", "--out", str(out),
                   "--no-upload")
    st = (out / "status.tsv").read_text()
    assert p.returncode == 1, st
    for row in ("A-md5\tNOT_RUN", "B-list\tOK", "B-l4t-rootfs_gui\tATTENTION", "B-import-rootfs_gui\tFAIL"):
        assert row in st, row
    assert ("B-rootfs-tar-rootfs_gui\tATTENTION" if can_test_unreadable() else "B-rootfs-tar-rootfs_gui\tOK") in st
    assert "rootfs_no_gui" not in "".join(l for l in st.splitlines() if l.startswith("B-rootfs-tar"))


def test_script_version_validation(tmp_path):
    a = make_archive(str(tmp_path / "product-a.tbz2"))
    p = run_script(tmp_path, "--archive", a, "--rootfs", "all", "--name", "x", "--version", "1.0:bad")
    assert p.returncode == 64 and "--version" in p.stderr
    p = run_script(tmp_path, "--archive", a, "--dir", str(tmp_path), "--rootfs", "all", "--name", "x", "--version", "1")
    assert p.returncode == 64


# ---------- 審查：兩棵 rootfs 之間的硬連結、多段 bzip2、略過要說明 ----------

def cross_archive(path, multi=False):
    """cp -al 式的兩棵樹：GNU tar 把第二份存成指向第一份的硬連結，兩個方向都有；dpkg status 是硬連結；連結指向連結；
    資料夾後來變成符號連結，再有硬連結經過它；連結名稱含 ..。"""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as t:
        for v in ("rootfs_no_gui", "rootfs_gui"):
            for d in ("", "/etc", "/var", "/var/lib", "/var/lib/dpkg", "/usr", "/usr/bin"):
                add(t, f"L4T/{v}{d}", ("dir",))
        add(t, "L4T/rootfs_no_gui/etc/nv_tegra_release", NV_REL)
        add(t, "L4T/rootfs_no_gui/var/lib/dpkg/status", STATUS)
        add(t, "L4T/rootfs_gui/usr/bin/xorg", b"xorg-binary")                                   # gui 先出現
        add(t, "L4T/rootfs_gui/etc/nv_tegra_release", ("lnk", "L4T/rootfs_no_gui/etc/nv_tegra_release"))
        add(t, "L4T/rootfs_gui/var/lib/dpkg/status", ("lnk", "L4T/rootfs_no_gui/var/lib/dpkg/status"))
        add(t, "L4T/rootfs_no_gui/usr/bin/xorg", ("lnk", "L4T/rootfs_gui/usr/bin/xorg"))          # 反方向
        add(t, "L4T/rootfs_no_gui/usr/bin/xorg2", ("lnk", "L4T/rootfs_no_gui/usr/bin/xorg"))      # 連結指向連結
        add(t, "L4T/rootfs_no_gui/a", ("dir",))
        add(t, "L4T/rootfs_no_gui/a/b", b"under-a")
        add(t, "L4T/rootfs_no_gui/a", ("sym", "/etc"))
        add(t, "L4T/rootfs_no_gui/h", ("lnk", "L4T/rootfs_no_gui/a/b"))
        add(t, "L4T/rootfs_no_gui/h2", ("lnk", "L4T/rootfs_no_gui/../rootfs_no_gui/etc/nv_tegra_release"))
    raw = buf.getvalue()
    if multi:
        h = len(raw) // 2
        data = bz2.compress(raw[:h]) + bz2.compress(raw[h:])     # pbzip2 這種多段的 bzip2
    else:
        data = bz2.compress(raw)
    open(path, "wb").write(data)
    return path


def content(tar_path, name):
    with tarfile.open(tar_path) as t:
        return t.extractfile(name).read()


@pytest.mark.parametrize("multi", [False, True])
def test_cross_tree_hardlinks_both_selected(tmp_path, monkeypatch, multi):
    monkeypatch.setenv("FLASHPKG_PARALLEL", "0")
    a = cross_archive(str(tmp_path / "x.tbz2"), multi)
    opened = []
    real = fp.open_stream
    monkeypatch.setattr(fp, "open_stream", lambda p: (opened.append(p), real(p))[1])
    ng, g = fp.do_rootfs_tar([("L4T/rootfs_no_gui", str(tmp_path / "ng.tar"), str(tmp_path / "ng.json")),
                              ("L4T/rootfs_gui", str(tmp_path / "g.tar"), str(tmp_path / "g.json"))], archive=a)
    assert content(str(tmp_path / "g.tar"), "./var/lib/dpkg/status") == STATUS          # 目標在前面、在另一棵
    assert content(str(tmp_path / "g.tar"), "./etc/nv_tegra_release") == NV_REL
    assert content(str(tmp_path / "ng.tar"), "./usr/bin/xorg") == b"xorg-binary"       # 反方向
    m = names(str(tmp_path / "ng.tar"))
    assert m["./usr/bin/xorg2"].islnk() and m["./usr/bin/xorg2"].linkname == "./usr/bin/xorg"
    assert m["./h"].isreg() and content(str(tmp_path / "ng.tar"), "./h") == b"under-a"   # 經過後來變成連結的資料夾 → 寫成檔案
    assert ng["dropped_under_symlink"] == 1 and ng["hardlinks_from_second_pass"] == 1
    assert ng["skipped_hardlinks"] == 1 and "h2" in ng["examples"]["hardlinks_skipped"][0]    # 名稱含 ..
    assert g["hardlinks_materialized"] == 2 and ng["hardlinks_materialized"] == 1
    assert len(opened) == 2                       # 第一次讀取＋只為 h 的第二次


def test_cross_tree_hardlinks_one_selected_second_pass(tmp_path, monkeypatch):
    monkeypatch.setenv("FLASHPKG_PARALLEL", "0")
    a = cross_archive(str(tmp_path / "x.tbz2"))
    g, = fp.do_rootfs_tar([("L4T/rootfs_gui", str(tmp_path / "g.tar"), str(tmp_path / "g.json"))], archive=a)
    assert content(str(tmp_path / "g.tar"), "./var/lib/dpkg/status") == STATUS
    assert g["hardlinks_from_second_pass"] == 2 and g["skipped_hardlinks"] == 0
    ng, = fp.do_rootfs_tar([("L4T/rootfs_no_gui", str(tmp_path / "ng.tar"), str(tmp_path / "ng.json"))], archive=a)
    assert content(str(tmp_path / "ng.tar"), "./usr/bin/xorg") == b"xorg-binary"
    assert content(str(tmp_path / "ng.tar"), "./usr/bin/xorg2") == b"xorg-binary"   # 指向「也要第二次讀取」的連結：也寫成檔案
    assert ng["hardlinks_from_second_pass"] == 3 and ng["skipped_hardlinks"] == 1   # xorg、xorg2、h；h2 名稱含 ..


def test_list_reads_hardlinked_dpkg_status(tmp_path, monkeypatch):
    monkeypatch.setenv("FLASHPKG_PARALLEL", "0")
    a = cross_archive(str(tmp_path / "x.tbz2"), multi=True)
    r = fp.do_list(str(tmp_path / "l.json"), str(tmp_path / "i.json"), archive=a)
    g = next(c for c in r["rootfs"] if c["variant"] == "rootfs_gui")
    assert g["dpkg"]["installed_packages"] == 3 and g["l4t"]["release"] == "39.2.1" and g["looks_like_rootfs"]
    assert g["hardlinks_outside"] == 2
    assert fp.variants_all(r) == ["rootfs_no_gui", "rootfs_gui"]


def test_list_hardlink_to_other_name_second_pass(tmp_path, monkeypatch):
    monkeypatch.setenv("FLASHPKG_PARALLEL", "0")
    p = tmp_path / "x.tbz2"
    with tarfile.open(p, "w:bz2") as t:
        add(t, "backup/status-copy", STATUS)
        add(t, "rootfs_gui/var/lib/dpkg/status", ("lnk", "backup/status-copy"))
    r = fp.do_list(str(tmp_path / "l.json"), str(tmp_path / "i.json"), archive=str(p))
    assert r["rootfs"][0]["dpkg"]["installed_packages"] == 3


def test_pick_reports_excluded(tmp_path, capsys):
    p = tmp_path / "x.tbz2"
    with tarfile.open(p, "w:bz2") as t:
        add(t, "L4T/rootfs_no_gui/etc/nv_tegra_release", NV_REL)
        add(t, "L4T/rootfs_gui/usr/bin/x", b"x")                    # 沒有 dpkg status、nv_tegra_release
        add(t, "L4T/rootfs/README.txt", b"placeholder")
    fp.do_list(str(tmp_path / "l.json"), str(tmp_path / "i.json"), archive=str(p))
    assert fp.main(["pick", "--list", str(tmp_path / "l.json"), "--rootfs", "all"]) == 0
    lines = [x.split("\t") for x in capsys.readouterr().out.splitlines()]
    skip = {x[2]: x for x in lines if x[0] == "SKIP"}
    assert skip["rootfs_gui"][1] == "ATTENTION" and "不像完整的 rootfs" in skip["rootfs_gui"][4]
    assert skip["rootfs"][1] == "INFO"
    assert [x[0] for x in lines if x[0] != "SKIP"] == ["rootfs_no_gui"]


def test_dir_shared_inodes_between_trees(tmp_path):
    """cp -al：兩棵樹共用 inode。每個 rootfs 都要有真正的內容；同一棵樹裡的才寫成 tar 硬連結。"""
    base = tmp_path / "d"
    ng, g = base / "rootfs_no_gui", base / "rootfs_gui"
    (ng / "var" / "lib" / "dpkg").mkdir(parents=True)
    (ng / "var" / "lib" / "dpkg" / "status").write_bytes(STATUS)
    os.link(ng / "var" / "lib" / "dpkg" / "status", ng / "var" / "lib" / "dpkg" / "status-old")
    (g / "var" / "lib" / "dpkg").mkdir(parents=True)
    os.link(ng / "var" / "lib" / "dpkg" / "status", g / "var" / "lib" / "dpkg" / "status")
    r = fp.do_list(str(tmp_path / "l.json"), str(tmp_path / "i.json"), directory=str(base))
    assert all(c["dpkg"]["installed_packages"] == 3 for c in r["rootfs"])
    reps = fp.do_rootfs_tar([("rootfs_no_gui", str(tmp_path / "ng.tar"), str(tmp_path / "ng.json")),
                             ("rootfs_gui", str(tmp_path / "g.tar"), str(tmp_path / "g.json"))], directory=str(base))
    assert content(str(tmp_path / "g.tar"), "./var/lib/dpkg/status") == STATUS          # rootfs_gui 先走（名稱排序）
    m = names(str(tmp_path / "ng.tar"))
    assert m["./var/lib/dpkg/status"].isreg() and m["./var/lib/dpkg/status-old"].islnk()
    assert m["./var/lib/dpkg/status-old"].linkname == "./var/lib/dpkg/status"
    assert content(str(tmp_path / "ng.tar"), "./var/lib/dpkg/status") == STATUS
    assert reps[0]["skipped_hardlinks"] == 0 and reps[1]["skipped_hardlinks"] == 0


def test_md5_bom_and_multiline(tmp_path, capsys):
    a = make_archive(str(tmp_path / "product-a.tbz2"))
    h = hashlib.md5(open(a, "rb").read()).hexdigest()
    m = tmp_path / "x.md5"
    m.write_bytes(("﻿" + "0" * 32 + "  other.bin\n" + f"{h}  product-a.tbz2\n").encode("utf-8"))
    assert fp.main(["md5", "--archive", a, "--md5", str(m)]) == 0
    assert capsys.readouterr().out.startswith("OK\t")


def test_deliverables_skip_fifo_and_symlink(tmp_path):
    d = tmp_path / "deliv"
    d.mkdir()
    (d / "real.zip").write_bytes(b"zip")
    os.mkfifo(d / "pipe")
    os.symlink("/etc/passwd", d / "link.zip")
    o = {x["name"]: x for x in fp.deliverables(str(d))}
    assert o["real.zip"]["sha256"] == hashlib.sha256(b"zip").hexdigest()
    assert o["pipe"]["type"] == "other" and "sha256" not in o["pipe"]
    assert o["link.zip"] == {"name": "link.zip", "type": "symlink", "target": "/etc/passwd"}


def test_script_writes_pid_and_skip_rows(tmp_path):
    p = tmp_path / "product-a.tbz2"
    with tarfile.open(p, "w:bz2") as t:
        add(t, "L4T/rootfs_no_gui/etc/nv_tegra_release", NV_REL)
        add(t, "L4T/rootfs_gui/usr/bin/x", b"x")
    out = tmp_path / "res"
    r = run_script(tmp_path, "--archive", str(p), "--rootfs", "all", "--name", "product-a", "--version", "V39.2.1", "--out", str(out), "--no-upload")
    st = (out / "status.tsv").read_text()
    assert "B-skip-rootfs_gui\tATTENTION" in st and "B-rootfs-tar-rootfs_no_gui" in st and "B-rootfs-tar-rootfs_gui" not in st
    assert r.stdout.splitlines()[0] == f"OUT={out}"
    assert (out / "pid").read_text().strip().isdigit() and (out / "pgid").read_text().strip().isdigit()


def test_script_decisions_from(tmp_path):
    """--decisions-from（完整掃描）：上一次結果的 vex-rules／vex-annotations／security-findings 帶到這次（同一個產品名稱才帶）；
    名稱不同或沒有判定檔 → ATTENTION、不帶；和 --rescan-from 一起用 → 參數錯。"""
    a = make_archive(str(tmp_path / "product-a.tbz2"))
    (tmp_path / "product-a.tbz2.md5").write_text(f"{hashlib.md5(open(a, 'rb').read()).hexdigest()}  product-a.tbz2\n")

    def prev(d, name):
        (d / "list.json").parent.mkdir(parents=True)
        (d / "list.json").write_text("{}")
        (d / "rootfs_no_gui" / "scan").mkdir(parents=True)
        (d / "rootfs_no_gui" / "scan" / "meta.json").write_text(json.dumps({"name": name}))
        c = d / "rootfs_no_gui" / "cra-project" / "CRA" / "Config"
        c.mkdir(parents=True)
        (c / "vex-annotations.json").write_text('{"schema": "y", "annotations": [1]}')
        (c / "vex-rules.json").write_text('{"schema": "x", "rules": []}')
        return d

    p1 = prev(tmp_path / "prev", "product-a")
    out = tmp_path / "res"
    run_script(tmp_path, "--archive", a, "--rootfs", "rootfs_no_gui", "--name", "product-a", "--version", "V1", "--out", str(out),
               "--no-upload", "--decisions-from", str(p1))
    st = (out / "status.tsv").read_text()
    assert "B-decisions-rootfs_no_gui\tOK\t沿用 prev 的 vex-rules.json vex-annotations.json" in st, st
    oc = out / "rootfs_no_gui" / "cra-project" / "CRA" / "Config"
    assert (oc / "vex-annotations.json").read_text() == '{"schema": "y", "annotations": [1]}' and (oc / "vex-rules.json").exists()
    # 別的產品：不帶
    p2 = prev(tmp_path / "other", "XX99")
    out2 = tmp_path / "res2"
    run_script(tmp_path, "--archive", a, "--rootfs", "rootfs_no_gui", "--name", "product-a", "--version", "V1", "--out", str(out2),
               "--no-upload", "--decisions-from", str(p2))
    st2 = (out2 / "status.tsv").read_text()
    assert "B-decisions-rootfs_no_gui\tATTENTION\tother 的 rootfs_no_gui 是 XX99，不是 product-a" in st2, st2
    assert not (out2 / "rootfs_no_gui" / "cra-project" / "CRA" / "Config" / "vex-annotations.json").exists()
    # 沒有判定檔
    for f in ("vex-annotations.json", "vex-rules.json"):
        (p2 / "rootfs_no_gui" / "cra-project" / "CRA" / "Config" / f).unlink()
    (p2 / "rootfs_no_gui" / "scan" / "meta.json").write_text(json.dumps({"name": "product-a"}))
    out3 = tmp_path / "res3"
    run_script(tmp_path, "--archive", a, "--rootfs", "rootfs_no_gui", "--name", "product-a", "--version", "V1", "--out", str(out3),
               "--no-upload", "--decisions-from", str(p2))
    assert "B-decisions-rootfs_no_gui\tATTENTION\tother 的 rootfs_no_gui 沒有判定檔" in (out3 / "status.tsv").read_text()
    # 參數錯
    p = run_script(tmp_path, "--rescan-from", str(p1), "--decisions-from", str(p1), "--out", str(tmp_path / "res4"), "--no-upload")
    assert p.returncode == 64 and "只用於完整掃描" in p.stderr
    p = run_script(tmp_path, "--archive", a, "--rootfs", "rootfs_no_gui", "--name", "product-a", "--version", "V1", "--out", str(tmp_path / "res5"),
                   "--no-upload", "--decisions-from", str(tmp_path / "nothing"))
    assert p.returncode == 64 and "有 list.json" in p.stderr
    # meta.json 壞掉：另外講；符號連結的判定檔不帶
    (p1 / "rootfs_no_gui" / "scan" / "meta.json").write_text("[1, 2")
    out6 = tmp_path / "res6"
    run_script(tmp_path, "--archive", a, "--rootfs", "rootfs_no_gui", "--name", "product-a", "--version", "V1", "--out", str(out6),
               "--no-upload", "--decisions-from", str(p1))
    assert "B-decisions-rootfs_no_gui\tATTENTION\tprev 的 rootfs_no_gui 的 sca-scan meta.json 讀不出產品名稱" in (out6 / "status.tsv").read_text()
    (p1 / "rootfs_no_gui" / "scan" / "meta.json").write_text(json.dumps({"name": "product-a"}))
    c1 = p1 / "rootfs_no_gui" / "cra-project" / "CRA" / "Config"
    (c1 / "vex-annotations.json").unlink()
    (c1 / "vex-annotations.json").symlink_to(tmp_path / "elsewhere.json")
    out7 = tmp_path / "res7"
    run_script(tmp_path, "--archive", a, "--rootfs", "rootfs_no_gui", "--name", "product-a", "--version", "V1", "--out", str(out7),
               "--no-upload", "--decisions-from", str(p1))
    st7 = (out7 / "status.tsv").read_text()
    assert "B-decisions-rootfs_no_gui\tATTENTION\tprev 的 vex-annotations.json 是符號連結" in st7, st7
    assert "B-decisions-rootfs_no_gui\tOK\t沿用 prev 的 vex-rules.json" in st7
    assert not (out7 / "rootfs_no_gui" / "cra-project" / "CRA" / "Config" / "vex-annotations.json").exists()


def test_tool_commit_keeps_commit_when_status_times_out(monkeypatch, tmp_path):
    """git status 逾時：commit 照樣記，dirty 是 None（provenance 因此是 ATTENTION）。"""
    real = fp.subprocess.run

    def fake(cmd, *a, **k):
        if "status" in cmd:
            raise fp.subprocess.TimeoutExpired(cmd, 30)
        return real(cmd, *a, **k)
    root = fp.Path(__file__).resolve().parents[3]
    if not (root / ".git").exists():
        pytest.skip("不是 git 工作目錄")
    monkeypatch.setattr(fp.subprocess, "run", fake)
    tc = fp.tool_commit(root)
    assert re.fullmatch(r"[0-9a-f]{40}", tc["commit"]) and tc["from"] == "git" and tc["dirty"] is None


def test_script_uefi_source_runs_before_import_and_is_optional(tmp_path):
    """--uefi-source：docker import 之前 uefi_source.py 讀樹（B-uefi-source）。Grype 比對（B-uefi-grype）在 sca-scan 更新資料庫之後才跑
    （test_bundled_grype_order.py）；這裡的 docker import 是假的、一定失敗，沒有走到 sca-scan：沒有比對、沒有 grype-run.json，
    但 B-uefi-grype 照樣記 NOT_RUN（原因寫 sca-scan 沒有執行），不悄悄消失。
    沒給時不執行、不寫狀態列、不建資料夾；樹不是資料夾 → 退出碼 64。"""
    tree = tmp_path / "uefi"
    ossl = tree / "CryptoPkg" / "Library" / "OpensslLib" / "openssl"
    ossl.mkdir(parents=True)
    (ossl / "VERSION.dat").write_text("MAJOR=3\nMINOR=4\nPATCH=1\nPRE_RELEASE_TAG=\nBUILD_METADATA=\nRELEASE_DATE=\"1 Jan 2025\"\nSHLIB_VERSION=3\n")
    (tree / "MdePkg").mkdir()
    (tree / "MdePkg" / "MdePkg.dec").write_text("[Defines]\n")
    a = str(tmp_path / "pkg.tbz2")
    make_archive(a, gui=False)
    (tmp_path / "pkg.tbz2.md5").write_text(f"{hashlib.md5(open(a, 'rb').read()).hexdigest()}  pkg.tbz2\n")
    base = ["--archive", a, "--rootfs", "rootfs_no_gui", "--name", "EX-J100", "--version", "V1", "--no-upload"]
    p = run_script(tmp_path, *base, "--out", str(tmp_path / "r0"))
    st = (tmp_path / "r0" / "status.tsv").read_text()
    assert "B-uefi" not in st and not (tmp_path / "r0" / "rootfs_no_gui" / "uefi-source").exists()
    p = run_script(tmp_path, *base, "--out", str(tmp_path / "r1"), "--uefi-source", str(tree))
    st = (tmp_path / "r1" / "status.tsv").read_text()
    assert re.search(r"^B-uefi-source-rootfs_no_gui\tGAP\t.*OpenSSL 3\.4\.1", st, re.M), st + p.stderr     # edk2 版本不明 → GAP
    assert re.search(r"^B-uefi-grype-rootfs_no_gui\tNOT_RUN\tdocker import 失敗，sca-scan 沒有執行，沒有更新 Grype 資料庫：不比對", st, re.M), st
    assert "B-tee-grype" not in st                      # 沒給 --tee-source：不寫這一列
    assert st.index("B-uefi-source") < st.index("B-import-rootfs_no_gui") < st.index("B-uefi-grype-rootfs_no_gui")
    assert re.search(r"^B-import-rootfs_no_gui\tFAIL\t", st, re.M), st
    d = tmp_path / "r1" / "rootfs_no_gui" / "uefi-source"
    assert (d / "uefi-source.cdx.json").is_file() and not (d / "grype-run.json").exists()
    p = run_script(tmp_path, *base, "--out", str(tmp_path / "r2"), "--uefi-source", str(tmp_path / "nope"))
    assert p.returncode == 64


def test_script_uefi_binary_check_and_extra_deliverable(tmp_path):
    """--uefi-source＋刷機包：B-uefi-binary（映像的版本字串與內嵌路徑對照原始碼樹，MATCH → OK）；--extra-deliverable：B-extra-deliverable、
    清點檔的 extra_deliverables、extra-deliverables.json。沒給這兩個選項時清點檔沒有 extra_deliverables、也沒有這兩列。"""
    tree = tmp_path / "uefi"
    (tree / "edk2" / "MdePkg" / "Library").mkdir(parents=True)
    (tree / "edk2" / "MdePkg" / "Library" / "Base.c").write_text("//\n")
    (tree / "edk2-nvidia" / "Platform" / "NVIDIA" / "Tegra").mkdir(parents=True)
    (tree / "edk2-nvidia" / "Platform" / "NVIDIA" / "Tegra" / "PCP_FIRMWARE_VERSION_INFO").write_text("ACME_Board_R40.1.0\n3\n")
    img = b"\x01\xff" * 40 + b"\x00" + "ACME_Board_R40.1.0-3".encode("utf-16-le") + b"\x00\x00\x00" + b"/h/u/ws/uefi/edk2/MdePkg/Library/Base.c\x00"
    a = str(tmp_path / "pkg.tbz2")
    make_archive(a, extra=[(f"{TOP}/bootloader/uefi_t23x_general.bin", img)], gui=False)
    (tmp_path / "pkg.tbz2.md5").write_text(f"{hashlib.md5(open(a, 'rb').read()).hexdigest()}  pkg.tbz2\n")
    base = ["--archive", a, "--rootfs", "rootfs_no_gui", "--name", "EX-J100", "--version", "40.1.0.3", "--no-upload"]
    run_script(tmp_path, *base, "--out", str(tmp_path / "r0"))
    st0 = (tmp_path / "r0" / "status.tsv").read_text()
    assert "B-uefi-binary" not in st0 and "B-extra-deliverable" not in st0 and "bootloader-coverage" not in st0.replace("B-bootloader-coverage", "")
    assert "extra_deliverables" not in json.loads((tmp_path / "r0" / "flash-inventory.json").read_text())
    cap = tmp_path / "rd.Cap"
    cap.write_bytes(b"CAP\x00\x00\x00" + "Other_Board_R39.2.0-1".encode("utf-16-le") + b"\x00\x00")
    p = run_script(tmp_path, *base, "--out", str(tmp_path / "r1"), "--uefi-source", str(tree), "--extra-deliverable", str(cap))
    st = (tmp_path / "r1" / "status.tsv").read_text()
    assert re.search(r"^B-uefi-binary\tOK\t1 UEFI image\(s\): consistent with the source version 1", st, re.M), st + p.stderr
    assert st.index("B-uefi-binary") < st.index("B-import-rootfs_no_gui")
    assert re.search(r"^B-extra-deliverable\tATTENTION\t.*different version from this flash package", st, re.M), st
    inv = json.loads((tmp_path / "r1" / "flash-inventory.json").read_text())
    assert [x["name"] for x in inv["extra_deliverables"]] == ["rd.Cap"] and inv["extra_deliverables"][0]["sha256"] == hashlib.sha256(cap.read_bytes()).hexdigest()
    assert json.loads((tmp_path / "r1" / "uefi-binary-check.json").read_text())["counts"]["MATCH"] == 1
    assert str(tmp_path) not in (tmp_path / "r1" / "flash-inventory.json").read_text().replace(str(tmp_path / "r1"), "")
    # 符號連結、不存在、資料夾：拒絕（退出碼 64），不跟隨
    os.symlink(cap, tmp_path / "link.Cap")
    for bad in (str(tmp_path / "link.Cap"), str(tmp_path / "nope.Cap"), str(tmp_path)):
        p = run_script(tmp_path, *base, "--out", str(tmp_path / "rx"), "--extra-deliverable", bad)
        assert p.returncode == 64 and "--extra-deliverable" in p.stderr


# ---------- 成員名稱含控制字元（TAB／換行）：不可進入以 TAB 分隔的欄位與算術 ----------

CRAFTED = ["Linux_for_Tegra\ta[$(touch pwned)]+0\t0/rootfs/etc/x", "Linux_for_Tegra\nfoo/rootfs/etc/x",
           "Linux_for_Tegra\x01/rootfs/etc/x", "Linux_for_Tegra\x7f/rootfs/etc/x"]


@pytest.mark.parametrize("name", CRAFTED)
def test_list_rejects_control_chars_in_prefix(tmp_path, name):
    a = make_archive(str(tmp_path / "pkg.tbz2"), extra=[(name, b"x")], gui=False)
    with pytest.raises(fp.Fail, match="控制字元"):
        fp.do_list(str(tmp_path / "l.json"), str(tmp_path / "i.json"), archive=a)


def test_pick_rejects_control_chars_in_list_json():
    r = {"rootfs": [{"variant": "rootfs", "prefix": "x\ta[$(id)]+0\t0/rootfs", "bytes": 1}]}
    with pytest.raises(fp.Fail, match="控制字元"):
        fp.pick(r, "rootfs")


def test_script_crafted_member_name_is_not_executed(tmp_path):
    """重現：成員名稱含 TAB，多出來的欄位進 BYTES[$v] 被 $(( )) 當算式執行。修正後 B-list FAIL，什麼都不執行。"""
    a = make_archive(str(tmp_path / "pkg.tbz2"), extra=[(CRAFTED[0], b"x")], gui=False)
    (tmp_path / "pkg.tbz2.md5").write_text(f"{hashlib.md5(open(a, 'rb').read()).hexdigest()}  pkg.tbz2\n")
    work = tmp_path / "cwd"
    work.mkdir()
    e = dict(os.environ, PATH=stub_path(tmp_path), FLASHPKG_ALLOW_TMP_OUT="1")
    p = subprocess.run(["bash", SCRIPT, "--archive", a, "--rootfs", "all", "--name", "EX-J100", "--version", "V1",
                        "--out", str(tmp_path / "res"), "--no-upload"], capture_output=True, text=True, env=e, timeout=120, cwd=work)
    st = (tmp_path / "res" / "status.tsv").read_text()
    assert not (work / "pwned").exists(), "成員名稱裡的指令被執行了"
    assert re.search(r"^B-list\tFAIL\t.*控制字元", st, re.M), st + p.stderr


def bash_check(*args):
    fn = subprocess.run(["sed", "-n", "/^pick_fields_ok(){/,/^}/p", SCRIPT], capture_output=True, text=True).stdout
    assert fn.strip()
    return subprocess.run(["bash", "-c", fn + '\npick_fields_ok "$@"', "x", *args], capture_output=True, text=True).returncode


@pytest.mark.parametrize("args,ok", [
    (("rootfs_no_gui", "Linux_for_Tegra/rootfs_no_gui", "123"), True),
    (("rootfs", "a/b/rootfs"), True),
    (("rootfs", "rootfs", "a[$(touch pwned)]+0"), False),       # 算術注入
    (("rootfs", "rootfs", ""), False),
    (("rootfs", "rootfs", "1 2"), False),
    (("rootfs", "../x/rootfs", "1"), False),
    (("rootfs", "a/../rootfs", "1"), False),
    (("rootfs", "a\nb/rootfs", "1"), False),
    (("rootfs", "a$(id)/rootfs", "1"), False),
    (("rootfs", "/abs/rootfs", "1"), False),
    (("../evil", "rootfs", "1"), False),
    (("rootfs\nx", "rootfs", "1"), False),
    (("rootfs", "-rf/rootfs", "1"), False),                      # - 開頭（會被當成選項）
    (("rootfs", "a/-x/rootfs", "1"), False),
    (("rootfs", ".", "1"), False),
    (("rootfs", "./rootfs", "1"), False),
    (("rootfs", "rootfs", "\u0661\u0662"), False),              # 阿拉伯-印度數字不是 [0-9]
    (("rootfs", "caf\u00e9/rootfs", "1"), False),                # 非 ASCII 字母
])
def test_bash_pick_fields_whitelist(args, ok):
    assert (bash_check(*args) == 0) is ok
