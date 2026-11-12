"""upstream_baseline.py：刷機包與原始碼和 NVIDIA 原版的逐檔比對。全部用測試自己組的小型假資料。"""
import hashlib
import io
import json
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import upstream_baseline as ub  # noqa: E402

CLI = HERE.parent / "upstream_baseline.py"


def put(root, rel, data):
    p = Path(root) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data if isinstance(data, bytes) else data.encode())


def mk_tar(path, files, top=None, extra=None, mode="w:bz2"):
    """files: {相對路徑: bytes}；extra: [(TarInfo, fileobj or None)]"""
    with tarfile.open(path, mode) as t:
        for rel, data in files.items():
            ti = tarfile.TarInfo((top + "/" if top else "") + rel)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
        for ti, fo in extra or []:
            t.addfile(ti, fo)
    return Path(path)


BASE = {
    "bootloader/mb1_t234_prod.bin": b"MB1",
    "bootloader/bpmp_t234-TE990M-A1_prod.bin": b"BPMP",
    "bootloader/tos-optee_t234.img": b"TOS",
    "bootloader/uefi_bins/uefi_t23x_general.bin": b"UEFI-orig",
    "bootloader/tegra234-mb1-bct-x.dtsi": b"dtsi",
    "kernel/Image": b"IMG-orig",
    "tools/flash.sh": b"flash",
    "rootfs/etc/x": b"rootfs-up",
    "README": b"r",
}


def ours_dir(tmp, mod=None, add=None, drop=()):
    d = tmp / "ours" / "ACME_Flash"
    f = dict(BASE)
    f.update(mod or {})
    f.update(add or {})
    for k in drop:
        f.pop(k)
    for k, v in f.items():
        put(d, k, v)
    return d


def upstream_tar(tmp, extra=None, drop=()):
    f = dict(BASE)
    f.update(extra or {})
    for k in drop:
        f.pop(k)
    return mk_tar(tmp / "Jetson_Linux_R39.2.0_aarch64.tbz2", f, top="Linux_for_Tegra")


def run_art(tmp, ours, up, **kw):
    return ub.artifacts_run(str(ours), str(up), kw.get("exclude", ["rootfs/"]))


def test_all_classes_and_exclude(tmp_path):
    ours = ours_dir(tmp_path, mod={"kernel/Image": b"IMG-RD", "bootloader/uefi_bins/uefi_t23x_general.bin": b"UEFI-RD"},
                    add={"product-a.conf": b"c", "kernel/dtb/x.dtb": b"d"}, drop=["tools/flash.sh"])
    up = upstream_tar(tmp_path)
    d = run_art(tmp_path, ours, up)
    assert d["counts"] == {"same": 5, "modified": 2, "ours_only": 2, "upstream_only": 1}   # rootfs 不算
    assert [e["path"] for e in d["upstream_only"]] == ["tools/flash.sh"]
    assert {e["path"] for e in d["modified"]} == {"kernel/Image", "bootloader/uefi_bins/uefi_t23x_general.bin"}
    assert d["by_top"]["kernel"] == {"same": 0, "modified": 1, "ours_only": 1, "upstream_only": 0}
    assert d["by_top"]["(top)"]["same"] == 1
    # 閉源韌體全部相同（UEFI 與 dtsi 不算閉源）→ OK
    assert d["status"] == "OK", d
    assert d["closed_firmware"]["counts"]["same"] == 3
    assert "3 個檔案與 NVIDIA 原版相同" in d["detail"]
    assert all(not e["path"].startswith("rootfs/") for e in d["closed_firmware"]["files"])


def test_closed_firmware_modified_is_attention(tmp_path):
    ours = ours_dir(tmp_path, mod={"bootloader/mb1_t234_prod.bin": b"MB1-patched"})
    d = run_art(tmp_path, ours, upstream_tar(tmp_path))
    assert d["status"] == "ATTENTION"
    assert [e["path"] for e in d["closed_firmware"]["files"] if e["status"] == "modified"] == ["bootloader/mb1_t234_prod.bin"]


def test_closed_firmware_ours_only_is_attention(tmp_path):
    ours = ours_dir(tmp_path, add={"bootloader/spe_t234.bin": b"SPE"})
    d = run_art(tmp_path, ours, upstream_tar(tmp_path))
    assert d["status"] == "ATTENTION"


def test_closed_classification_is_shared_with_bootloader_coverage():
    import bootloader_coverage as bc
    names = ["mb2_t234.bin", "psc_bl1_t234_prod.bin", "tos_t234.img", "tos-optee_t234.img", "MB1_T234_PROD.BIN", "tsec_t234.bin",
             "uefi_t23x_general.bin", "BOOTAA64.efi", "tegra234-mb1-bct-x.dtsi", "x.dtb", "LICENSE.spe.bin", "l4t_initrd.img", "newfw_t234.bin"]
    for n in names:
        cls, lab = bc.classify({"type": "file", "path": "bootloader/" + n})
        assert (ub.closed_family("bootloader/" + n) is not None) == (cls == "vendor_firmware")
        assert ub.closed_family("bootloader/" + n) == (lab if cls == "vendor_firmware" else None)
    assert ub.closed_family("bootloader/mb2_t234.bin") and ub.closed_family("bootloader/tos_t234.img")
    assert ub.closed_family("bootloader/uefi_bins/mb1_t234_prod.bin") is None and ub.closed_family("kernel/mb1_t234_prod.bin") is None


def test_missing_upstream_is_gap(tmp_path):
    ours = ours_dir(tmp_path)
    d = run_art(tmp_path, ours, tmp_path / "nope.tbz2")
    assert d["status"] == "GAP" and "不存在" in d["detail"]


def test_corrupt_upstream_is_gap(tmp_path):
    ours = ours_dir(tmp_path)
    bad = tmp_path / "bad.tbz2"
    bad.write_bytes(b"this is not a tar")
    assert run_art(tmp_path, ours, bad)["status"] == "GAP"


def test_no_closed_firmware_found_is_gap_not_ok(tmp_path):
    d1 = tmp_path / "o" / "X"
    put(d1, "kernel/Image", b"a")
    up = mk_tar(tmp_path / "u.tbz2", {"kernel/Image": b"a"}, top="Linux_for_Tegra")
    d = run_art(tmp_path, d1, up)
    assert d["status"] == "GAP" and d["counts"]["same"] == 1


def test_ours_archive_and_upstream_dir(tmp_path):
    f = dict(BASE)
    ours = mk_tar(tmp_path / "ours.tbz2", f, top="product-aTool")
    up = tmp_path / "up"
    for k, v in f.items():
        put(up / "Linux_for_Tegra", k, v)
    d = run_art(tmp_path, ours, tmp_path / "up")     # 上層資料夾，裡面一個 Linux_for_Tegra
    assert d["status"] == "OK" and d["counts"]["modified"] == 0 and d["counts"]["same"] == 8
    assert d["ours"]["top_folder"] == "product-aTool" and len(d["ours"]["sha256"]) == 64


def test_upstream_identity_url_and_sha(tmp_path):
    ours = ours_dir(tmp_path)
    up = upstream_tar(tmp_path)
    sha = hashlib.sha256(up.read_bytes()).hexdigest()
    (tmp_path / "SOURCE").write_text(f"source=https://x/y/other.tbz2\nbsp=https://dl.example/r39/{up.name} fetched=2026-11-11\n")
    (tmp_path / "SHA256-BSP.txt").write_text(f"{sha}  {up.name}\n")
    d = run_art(tmp_path, ours, up)
    u = d["upstream"]
    assert u["file_name"] == up.name and u["size"] == up.stat().st_size and u["sha256"] == sha
    assert u["url"] == f"https://dl.example/r39/{up.name}" and u["sha256_matches_listed"] is True


def test_symlink_rejected_dir_and_tar(tmp_path):
    ours = ours_dir(tmp_path)
    (ours / "kernel" / "link").symlink_to("/etc/passwd")
    (ours / "kernel" / "dlink").symlink_to(tmp_path)
    ti = tarfile.TarInfo("Linux_for_Tegra/kernel/link")
    ti.type, ti.linkname = tarfile.SYMTYPE, "/etc/passwd"
    ti2 = tarfile.TarInfo("Linux_for_Tegra/kernel/hard")
    ti2.type, ti2.linkname = tarfile.LNKTYPE, "Linux_for_Tegra/kernel/Image"
    up = mk_tar(tmp_path / "u.tbz2", BASE, top="Linux_for_Tegra", extra=[(ti, None), (ti2, None)])
    d = run_art(tmp_path, ours, up)
    assert {r["reason"] for r in d["rejected"]["ours"]} == {"symlink"} and len(d["rejected"]["ours"]) == 2
    assert {r["reason"] for r in d["rejected"]["upstream"]} == {"symlink", "hardlink"}
    assert "kernel/link" not in {e["path"] for e in d["ours_only"]}
    assert d["counts"]["ours_only"] == 0 and d["status"] == "OK"


def test_unsafe_tar_paths_rejected(tmp_path):
    ours = ours_dir(tmp_path)
    ti = tarfile.TarInfo("/abs/evil")
    ti.size = 1
    p2 = tmp_path / "u2.tar"
    with tarfile.open(p2, "w") as t:
        t.addfile(ti, io.BytesIO(b"x"))
        ti3 = tarfile.TarInfo("a/../../b")
        ti3.size = 1
        t.addfile(ti3, io.BytesIO(b"x"))
    items = list(ub.iter_tar(open(p2, "rb")))
    assert [i[0] for i in items] == ["reject", "reject"] and {i[2] for i in items} == {"unsafe-path"}


def test_cli_stdout_files_exit(tmp_path):
    ours = ours_dir(tmp_path, mod={"bootloader/mb1_t234_prod.bin": b"x"})
    up = upstream_tar(tmp_path)
    out = tmp_path / "out"
    r = subprocess.run([sys.executable, "-I", str(CLI), "artifacts", "--ours", str(ours), "--upstream", str(up), "--out", str(out)],
                       capture_output=True, text=True)
    assert r.returncode == 2
    assert r.stdout.startswith("A0-artifacts\tATTENTION\t") and r.stdout.count("\n") == 1
    doc = json.loads((out / "upstream-baseline-artifacts.json").read_text())
    assert doc["schema"] == ub.SCHEMA_ARTIFACTS and doc["status"] == "ATTENTION"
    md = (out / "upstream-baseline-artifacts.md").read_text()
    assert "閉源開機韌體" in md and "bootloader/mb1_t234_prod.bin" in md
    r = subprocess.run([sys.executable, "-I", str(CLI), "artifacts", "--ours", str(ours), "--upstream", str(tmp_path / "none"), "--out", str(out)],
                       capture_output=True, text=True)
    assert r.stdout.startswith("A0-artifacts\tGAP\t") and r.returncode == 2


# ---------------------------------------------------------------- source
def make_public_sources(tmp, comps, name="public_sources.tbz2"):
    """comps: {成員檔名: {路徑: bytes}} → 外層 Linux_for_Tegra/source/<成員>。"""
    outer = tmp / name
    with tarfile.open(outer, "w:bz2") as t:
        for member, files in comps.items():
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w:bz2") as it:
                for rel, data in files.items():
                    ti = tarfile.TarInfo(rel)
                    ti.size = len(data)
                    it.addfile(ti, io.BytesIO(data))
            ti = tarfile.TarInfo("Linux_for_Tegra/source/" + member)
            ti.size = len(buf.getvalue())
            t.addfile(ti, io.BytesIO(buf.getvalue()))
        ti = tarfile.TarInfo("Linux_for_Tegra/source/gst-foo_src.tbz2")
        ti.size = 3
        t.addfile(ti, io.BytesIO(b"abc"))
    return outer


def src_fixture(tmp):
    up = {
        "kernel_src.tbz2": {"kernel/kernel-noble/a.c": b"a", "kernel/kernel-noble/b.c": b"b", "kernel/kernel-noble/only_up.c": b"u",
                            "kernel/kernel-noble/obj_up.o": b"ignored-up", "kernel/kernel-noble/include/generated/y.h": b"g",
                            "kernel/kernel-noble/both.o": b"u"},
        "kernel_oot_modules_src.tbz2": {"nvidia-oot/drivers/x.c": b"x", "hwpm/h.c": b"h", "nvgpu/drivers/gpu/nvgpu/n.c": b"n"},
        "nvidia_kernel_display_driver_source.tbz2": {"./nvdisplay/src/d.c": b"d"},
    }
    pub = make_public_sources(tmp, up)
    s = tmp / "sources"
    put(s, "kernel/kernel-noble/a.c", "a")                 # same
    put(s, "kernel/kernel-noble/b.c", "b-RD")              # modified
    put(s, "kernel/kernel-noble/new.c", "n")               # ours_only
    put(s, "kernel/kernel-noble/obj.o", "built")           # ignore
    put(s, "kernel/kernel-noble/both.o", "o")              # 兩邊都有：即使檔名像產物也要比（不同 → modified）
    put(s, "kernel/kernel-noble/built-in.a", "built")      # ignore
    put(s, "kernel/kernel-noble/.tmp_x", "built")          # ignore
    put(s, "kernel/kernel-noble/modules.order", "built")   # ignore
    put(s, "kernel/kernel-noble/include/generated/x.h", "gen-ours")   # ignore dir
    put(s, "nvidia-oot/drivers/x.c", "x")
    put(s, "nvidia-oot/modules.order", "m")
    put(s, "nvidia-oot/Module.symvers", "m")
    put(s, "hwpm/h.c", "h")
    put(s, "nvgpu/drivers/gpu/nvgpu/n.c", "n")
    put(s, "nvdisplay/src/d.c", "d")
    put(s, "uefi/edk2/readme", "u")
    put(s, "out/nvidia-conftest/y", "y")
    return s, pub


def test_source_classification_and_ignore(tmp_path):
    s, pub = src_fixture(tmp_path)
    d = ub.source_run(str(s), str(pub), [])
    c = {r["name"]: r for r in d["components"]}
    k = c["kernel"]
    assert k["status"] == "ASSESSED"
    assert k["counts"] == {"same": 1, "modified": 2, "ours_only": 1, "upstream_only": 1}
    assert {e["path"] for e in k["modified"]} == {"kernel/kernel-noble/b.c", "kernel/kernel-noble/both.o"}
    assert k["ours_only"][0]["path"] == "kernel/kernel-noble/new.c"
    assert k["upstream_only"][0]["path"] == "kernel/kernel-noble/only_up.c"
    # 忽略：ours 5 個（obj.o、built-in.a、.tmp_x、modules.order、generated/x.h），upstream 2 個
    assert k["ignored"]["ours_total"] == 5 and k["ignored"]["upstream_total"] == 2
    o = c["kernel_oot_modules"]
    assert o["counts"] == {"same": 3, "modified": 0, "ours_only": 0, "upstream_only": 0}     # modules.order／Module.symvers 忽略
    assert c["nvdisplay"]["counts"]["same"] == 1
    # 沒有對應的 → NOT_ASSESSED，不是 same
    assert c["uefi"]["status"] == "NOT_ASSESSED" and c["atf_t234"]["status"] == "NOT_ASSESSED" and c["unifiedgpudisp"]["status"] == "NOT_ASSESSED"
    assert d["status"] == "ATTENTION"
    assert "uefi" in d["uncovered_ours_dirs"] and "out" in d["uncovered_ours_dirs"] and "kernel" not in d["uncovered_ours_dirs"]
    assert {"member": "gst-foo_src.tbz2", "size": 3} in d["unmapped_upstream_members"]
    mf = ub.modified_files(d)
    assert mf["kernel"] == {"kernel/kernel-noble/b.c", "kernel/kernel-noble/both.o", "kernel/kernel-noble/new.c"} and mf["kernel_oot_modules"] == set()
    assert "uefi" not in mf


def test_source_custom_component_and_prefix(tmp_path):
    s, pub = src_fixture(tmp_path)
    put(s, "extra/e.c", "e")
    d = ub.source_run(str(s), str(pub), [ub.parse_component("extra=extra:nvidia_kernel_display_driver_source.tbz2:")])
    # "extra" 子路徑與 upstream 的 nvdisplay/src/d.c 路徑不同 → 只有我們 / 只有 NVIDIA
    ex = next(r for r in d["components"] if r["name"] == "extra")
    assert ex["status"] == "NOT_ASSESSED"
    with pytest.raises(ValueError):
        ub.parse_component("bad")


def test_source_missing_upstream_gap_and_symlink(tmp_path):
    s, pub = src_fixture(tmp_path)
    assert ub.source_run(str(s), str(tmp_path / "none.tbz2"), [])["status"] == "GAP"
    assert ub.source_run(str(tmp_path / "nodir"), str(pub), [])["status"] == "GAP"
    (s / "kernel" / "kernel-noble" / "sym.c").symlink_to("/etc/passwd")
    d = ub.source_run(str(s), str(pub), [])
    k = next(r for r in d["components"] if r["name"] == "kernel")
    assert any(r["reason"] == "symlink" for r in k["rejected"]["ours"])
    assert "kernel/kernel-noble/sym.c" not in {e["path"] for e in k["ours_only"]}


def test_source_upstream_dir_and_cli(tmp_path):
    s, pub = src_fixture(tmp_path)
    ud = tmp_path / "upx" / "Linux_for_Tegra" / "source"
    ud.mkdir(parents=True)
    with tarfile.open(pub) as t:
        for m in t:
            if m.isfile() and m.name.endswith(".tbz2") and ("kernel" in m.name or "display" in m.name):
                (ud / Path(m.name).name).write_bytes(t.extractfile(m).read())
    d = ub.source_run(str(s), str(tmp_path / "upx"), [])
    assert next(r for r in d["components"] if r["name"] == "kernel")["counts"]["same"] == 1
    out = tmp_path / "o"
    r = subprocess.run([sys.executable, "-I", str(CLI), "source", "--ours", str(s), "--upstream", str(pub), "--out", str(out)],
                       capture_output=True, text=True)
    assert r.returncode == 2 and r.stdout.startswith("A0-source\tATTENTION\t") and r.stdout.count("\n") == 1
    doc = json.loads((out / "upstream-baseline-source.json").read_text())
    assert doc["schema"] == ub.SCHEMA_SOURCE and "NOT_ASSESSED" in (out / "upstream-baseline-source.md").read_text()
    assert ub.modified_files(out / "upstream-baseline-source.json")["kernel"]
    r = subprocess.run([sys.executable, "-I", str(CLI), "source", "--ours", str(s), "--upstream", str(pub), "--out", str(out), "--component", "bad"],
                       capture_output=True, text=True)
    assert r.returncode == 64 and "FAIL" in r.stdout


# ---------------------------------------------------------------- cra_report 內部存檔的選用輸入
def test_report_copies_optional_baseline_files(tmp_path):
    sys.path.insert(0, str(HERE))
    from test_uefi_bundled import report  # noqa: E402
    res = tmp_path / "res"
    res.mkdir(parents=True)
    doc = {"tool": "upstream_baseline", "status": "OK", "detail": "d", "upstream": {"file_name": "Jetson_Linux_R39.2.0_aarch64.tbz2"},
           "closed_firmware": {"counts": {"same": 7, "modified": 0, "ours_only": 0, "upstream_only": 0}}}
    (res / "upstream-baseline-artifacts.json").write_text(json.dumps(doc))
    (res / "upstream-baseline-artifacts.md").write_text("# md\n")
    s, rep, _ = report(tmp_path)
    assert (rep / "upstream-baseline-artifacts.json").is_file() and (rep / "upstream-baseline-artifacts.md").is_file()
    assert not (rep / "upstream-baseline-source.json").exists()
    summ = json.loads((rep / "summary.json").read_text(encoding="utf-8"))
    assert summ["upstream_baseline"]["artifacts"]["line"] .startswith("NVIDIA 閉源開機韌體 7 個檔案與 NVIDIA r39.2.0 原版相同（ours：")
    assert "source" not in summ["upstream_baseline"]


def test_report_without_baseline_files_unchanged(tmp_path):
    sys.path.insert(0, str(HERE))
    from test_uefi_bundled import report  # noqa: E402
    s, rep, _ = report(tmp_path)
    assert "upstream_baseline" not in json.loads((rep / "summary.json").read_text(encoding="utf-8"))
    assert not list(rep.glob("upstream-baseline-*"))


def test_baseline_line_attention_and_gap():
    import cra_report as cr
    d = {"status": "ATTENTION", "upstream": {"file_name": "x_R39.2.0_y.tbz2"}, "closed_firmware": {"counts": {"modified": 2, "ours_only": 1}}}
    line = cr.upstream_baseline_line("upstream-baseline-artifacts", d)
    assert "需要 RD 判斷" in line
    g = cr.upstream_baseline_line("upstream-baseline-artifacts", {"status": "GAP", "detail": "upstream 不存在"})
    assert "（GAP）" in g


# ---------------------------------------------------------------- 驗證回合 1 的修正
def raw_tar(files, top="Linux_for_Tegra", extra=()):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for rel, data in files.items():
            ti = tarfile.TarInfo((top + "/" if top else "") + rel)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
        for ti, fo in extra:
            t.addfile(ti, fo)
    return buf.getvalue()


def write_bz2(path, data):
    import bz2
    Path(path).write_bytes(bz2.compress(data))
    return Path(path)


def test_ok_baseline(tmp_path):
    d = run_art(tmp_path, ours_dir(tmp_path), upstream_tar(tmp_path))
    assert d["status"] == "OK"


def test_firmware_only_under_other_dir_is_not_ok(tmp_path):
    base = {k: v for k, v in BASE.items() if not k.startswith("bootloader/")}
    f = {**base, "other/mb1_t234_prod.bin": b"MB1", "other/bpmp_t234-TE990M-A1_prod.bin": b"B"}
    ours = tmp_path / "o" / "X"
    for k, v in f.items():
        put(ours, k, v)
    up = mk_tar(tmp_path / "u.tbz2", f, top="Linux_for_Tegra")
    assert run_art(tmp_path, ours, up)["status"] == "GAP"
    # 上游在 bootloader/、我們放到 other/ → 上游有、我們沒有
    f2 = {**base, "other/mb1_t234_prod.bin": b"MB1", "bootloader/spe_t234.bin": b"S"}
    f3 = {**base, "bootloader/mb1_t234_prod.bin": b"MB1", "bootloader/spe_t234.bin": b"S"}
    ours2 = tmp_path / "o2" / "X"
    for k, v in f2.items():
        put(ours2, k, v)
    d = run_art(tmp_path, ours2, mk_tar(tmp_path / "u2.tbz2", f3, top="Linux_for_Tegra"))
    assert d["status"] == "ATTENTION" and d["closed_firmware"]["counts"]["upstream_only"] == 1


def test_flat_file_next_to_top_folder_and_misaligned_paths(tmp_path):
    ours = ours_dir(tmp_path)
    extra = tarfile.TarInfo("README.txt")
    extra.size = 1
    up = tmp_path / "u.tbz2"
    write_bz2(up, raw_tar(BASE, extra=[(extra, io.BytesIO(b"r"))]))
    d = run_art(tmp_path, ours, up)
    assert d["counts"]["same"] > 0 and d["status"] == "OK"      # 頂層資料夾仍被去掉，路徑對齊
    # 兩邊結構不同、完全沒有相同路徑 → GAP「沒有對齊」
    f = {"a/" + k: v for k, v in BASE.items()}
    up2 = mk_tar(tmp_path / "u2.tbz2", f, top="Linux_for_Tegra")
    d2 = run_art(tmp_path, ours, up2)
    assert d2["status"] == "GAP" and "沒有對齊" in d2["detail"]


def test_symlink_firmware_is_attention(tmp_path):
    ours = ours_dir(tmp_path, drop=["bootloader/bpmp_t234-TE990M-A1_prod.bin"])
    (ours / "bootloader" / "bpmp_t234-TE990M-A1_prod.bin").symlink_to(ours / "bootloader" / "mb1_t234_prod.bin")
    d = run_art(tmp_path, ours, upstream_tar(tmp_path))
    assert d["status"] == "ATTENTION" and d["closed_firmware"]["rejected_names"]


def test_hardlink_firmware_in_tar_is_attention(tmp_path):
    ours = ours_dir(tmp_path)
    ti = tarfile.TarInfo("Linux_for_Tegra/bootloader/spe_t234.bin")
    ti.type, ti.linkname = tarfile.LNKTYPE, "Linux_for_Tegra/bootloader/mb1_t234_prod.bin"
    up = mk_tar(tmp_path / "u.tbz2", BASE, top="Linux_for_Tegra", extra=[(ti, None)])
    d = run_art(tmp_path, ours, up)
    assert d["status"] == "ATTENTION" and any(r["reason"] == "hardlink" for r in d["closed_firmware"]["rejected_names"])


def test_case_different_firmware_name_is_attention(tmp_path):
    ours = ours_dir(tmp_path, drop=["bootloader/mb1_t234_prod.bin"], add={"bootloader/MB1_T234_PROD.BIN": b"MB1"})
    d = run_art(tmp_path, ours, upstream_tar(tmp_path))
    assert d["status"] == "ATTENTION"
    st = {e["path"]: e["status"] for e in d["closed_firmware"]["files"]}
    assert st["bootloader/MB1_T234_PROD.BIN"] == "ours_only" and st["bootloader/mb1_t234_prod.bin"] == "upstream_only"


def test_package_lacking_firmware_is_attention(tmp_path):
    ours = ours_dir(tmp_path, drop=["bootloader/tos-optee_t234.img"])
    d = run_art(tmp_path, ours, upstream_tar(tmp_path))
    assert d["status"] == "ATTENTION" and d["closed_firmware"]["counts"]["upstream_only"] == 1


def test_truncated_archive_is_gap(tmp_path):
    ours = ours_dir(tmp_path)
    data = raw_tar(BASE)
    full = write_bz2(tmp_path / "full.tbz2", data)
    assert run_art(tmp_path, ours, full)["status"] == "OK"
    # tar 在 512 位元組邊界被截掉（沒有結束區塊），但外面的 bz2 是完整的
    five = {k: BASE[k] for k in list(BASE)[:5]}
    cut = raw_tar(five)[: 5 * 1024]      # 每個成員 512（標頭）＋512（內容）：剛好停在成員邊界，沒有結束區塊
    d = run_art(tmp_path, ours, write_bz2(tmp_path / "cut1.tbz2", cut))
    assert d["status"] == "GAP" and "截斷" in d["detail"]
    d = run_art(tmp_path, ours, write_bz2(tmp_path / "cut2.tbz2", data[: 512 + 100]))
    assert d["status"] == "GAP"
    # 壓縮串流被截掉
    comp = full.read_bytes()
    (tmp_path / "cut3.tbz2").write_bytes(comp[: len(comp) // 2])
    assert run_art(tmp_path, ours, tmp_path / "cut3.tbz2")["status"] == "GAP"
    # gz 與 xz 的完整檔案仍可讀
    import gzip
    import lzma
    (tmp_path / "g.tgz").write_bytes(gzip.compress(data))
    (tmp_path / "x.txz").write_bytes(lzma.compress(data))
    assert run_art(tmp_path, ours, tmp_path / "g.tgz")["status"] == "OK"
    assert run_art(tmp_path, ours, tmp_path / "x.txz")["status"] == "OK"


def test_multistream_bz2_ok(tmp_path):
    import bz2
    data = raw_tar(BASE)
    half = len(data) // 2 // 512 * 512
    p = tmp_path / "m.tbz2"
    p.write_bytes(bz2.compress(data[:half]) + bz2.compress(data[half:]))
    assert run_art(tmp_path, ours_dir(tmp_path), p)["status"] == "OK"


def test_tos_pattern_and_other_binaries():
    assert ub.closed_family("bootloader/tos_t234.img") and ub.closed_family("bootloader/MB1_T234_PROD.BIN")
    assert ub.other_binary("bootloader/l4t_initrd.img") and ub.other_binary("bootloader/newfw_t234.bin")
    assert not ub.other_binary("bootloader/uefi_t23x_general.bin") and not ub.other_binary("bootloader/LICENSE.spe.bin")
    assert not ub.other_binary("bootloader/mb1_t234_prod.bin") and not ub.other_binary("bootloader/generic/x.bin")


def test_other_binary_listed_and_unknown_difference_is_attention(tmp_path):
    f = {**BASE, "bootloader/l4t_initrd.img": b"i", "bootloader/newfw_t234.bin": b"n"}
    up = mk_tar(tmp_path / "u.tbz2", f, top="Linux_for_Tegra")
    ours = ours_dir(tmp_path, add={"bootloader/l4t_initrd.img": b"RD", "bootloader/newfw_t234.bin": b"n"})
    d = run_art(tmp_path, ours, up)
    assert d["status"] == "OK"
    notes = {e["path"]: (e["status"], e["note"]) for e in d["other_binaries"]}
    assert notes["bootloader/l4t_initrd.img"][0] == "modified" and notes["bootloader/newfw_t234.bin"][0] == "same"
    ours2 = ours_dir(tmp_path / "x", add={"bootloader/l4t_initrd.img": b"RD", "bootloader/newfw_t234.bin": b"CHANGED"})
    assert run_art(tmp_path, ours2, up)["status"] == "ATTENTION"


def test_duplicate_members_not_same(tmp_path):
    ours = ours_dir(tmp_path)
    ti = tarfile.TarInfo("Linux_for_Tegra/bootloader/mb1_t234_prod.bin")
    ti.size = 3
    ti2 = tarfile.TarInfo("Linux_for_Tegra/./bootloader/mb1_t234_prod.bin")    # 正規化後同名
    ti2.size = 3
    up = mk_tar(tmp_path / "u.tbz2", BASE, top="Linux_for_Tegra", extra=[(ti, io.BytesIO(b"XXX")), (ti2, io.BytesIO(b"MB1"))])
    d = run_art(tmp_path, ours, up)
    assert d["status"] == "ATTENTION" and "bootloader/mb1_t234_prod.bin" in d["duplicates"]["upstream"]
    assert "bootloader/mb1_t234_prod.bin" not in {e["path"] for e in d["closed_firmware"]["files"]}
    assert d["closed_firmware"]["duplicate_paths"] == ["bootloader/mb1_t234_prod.bin"]


def test_source_duplicates_and_empty_component(tmp_path):
    s, pub = src_fixture(tmp_path)
    outer = tmp_path / "pubdup.tbz2"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:bz2") as it:
        for data in (b"a", b"zzz"):
            ti = tarfile.TarInfo("kernel/kernel-noble/a.c")
            ti.size = len(data)
            it.addfile(ti, io.BytesIO(data))
        ti = tarfile.TarInfo("kernel/kernel-noble/b.c")
        ti.size = 1
        it.addfile(ti, io.BytesIO(b"b"))
    with tarfile.open(outer, "w:bz2") as t:
        ti = tarfile.TarInfo("Linux_for_Tegra/source/kernel_src.tbz2")
        ti.size = len(buf.getvalue())
        t.addfile(ti, io.BytesIO(buf.getvalue()))
    put(s, "kernel/kernel-noble/b.c", "b")
    d = ub.source_run(str(s), str(outer), [])
    k = next(r for r in d["components"] if r["name"] == "kernel")
    assert k["duplicates"] == ["kernel/kernel-noble/a.c"] and d["status"] == "ATTENTION"
    assert "kernel/kernel-noble/a.c" not in {e["path"] for e in k["modified"]}
    # 0 對 0 不算已比對
    empty = tmp_path / "emp"
    (empty / "kernel" / "kernel-noble").mkdir(parents=True)
    d2 = ub.source_run(str(empty), str(pub), [])
    assert next(r for r in d2["components"] if r["name"] == "kernel")["status"] == "NOT_ASSESSED"


def test_source_truncated_upstream_is_gap(tmp_path):
    s, pub = src_fixture(tmp_path)
    raw = pub.read_bytes()
    cut = tmp_path / "cut.tbz2"
    cut.write_bytes(raw[: len(raw) // 2])
    assert ub.source_run(str(s), str(cut), [])["status"] == "GAP"


def test_source_ignored_paths_listed(tmp_path):
    s, pub = src_fixture(tmp_path)
    put(s, "kernel/kernel-noble/include/generated/z.h", "x")
    put(s, "kernel/kernel-noble/arch/x/foo.lds", "x")
    put(s, "kernel/kernel-noble/arch/x/bar.s", "x")
    d = ub.source_run(str(s), str(pub), [])
    ip = next(r for r in d["components"] if r["name"] == "kernel")["ignored"]["ours_paths"]
    assert "kernel/kernel-noble/include/generated/z.h" in ip["dir:generated"]
    assert ip["name:*.lds"] == ["kernel/kernel-noble/arch/x/foo.lds"] and ip["name:*.s"] == ["kernel/kernel-noble/arch/x/bar.s"]


def test_report_rejects_other_flash_package(tmp_path):
    sys.path.insert(0, str(HERE))
    from test_uefi_bundled import report  # noqa: E402
    res = tmp_path / "res"
    (res / "scan").mkdir(parents=True)
    doc = {"tool": "upstream_baseline", "status": "OK", "generated": "t", "upstream": {"file_name": "J_R39.2.0.tbz2", "path": "/u"},
           "ours": {"type": "archive", "file_name": "OTHER.tbz2", "sha256": "a" * 64, "path": "/o"},
           "closed_firmware": {"counts": {"same": 2, "modified": 0, "ours_only": 0, "upstream_only": 0}}}
    (res / "upstream-baseline-artifacts.json").write_text(json.dumps(doc))
    (res / "scan" / "provenance.json").write_text(json.dumps({"source": {"file": "PROD.tbz2", "sha256": "b" * 64}}))
    s, rep, _ = report(tmp_path)
    summ = json.loads((rep / "summary.json").read_text(encoding="utf-8"))
    assert summ["upstream_baseline"]["artifacts"]["same_package"] is False and not (rep / "upstream-baseline-artifacts.json").exists()


def test_line_clean_requires_zero_others():
    import cra_report as cr
    base = {"status": "OK", "upstream": {"file_name": "x_R39.2.0.tbz2", "path": "/u"}, "ours": {"path": "/o"}, "generated": "T"}
    ok = dict(base, closed_firmware={"counts": {"same": 3, "modified": 0, "ours_only": 0, "upstream_only": 0}})
    line = cr.upstream_baseline_line("upstream-baseline-artifacts", ok)
    assert "3 個檔案" in line and "/o" in line
    zero = dict(base, closed_firmware={"counts": {"same": 0, "modified": 0, "ours_only": 0, "upstream_only": 0}})
    assert "相同" not in cr.upstream_baseline_line("upstream-baseline-artifacts", zero)
    up_only = dict(base, closed_firmware={"counts": {"same": 3, "modified": 0, "ours_only": 0, "upstream_only": 1}})
    assert "3 個檔案" not in cr.upstream_baseline_line("upstream-baseline-artifacts", up_only)


def test_firmware_symlink_same_target_on_both_sides_is_accepted(tmp_path):
    ours = ours_dir(tmp_path)
    (ours / "bootloader" / "tos_t234.img").symlink_to("tos-optee_t234.img")
    ti = tarfile.TarInfo("Linux_for_Tegra/bootloader/tos_t234.img")
    ti.type, ti.linkname = tarfile.SYMTYPE, "tos-optee_t234.img"
    up = mk_tar(tmp_path / "u.tbz2", BASE, top="Linux_for_Tegra", extra=[(ti, None)])
    d = run_art(tmp_path, ours, up)
    assert d["status"] == "OK" and len(d["closed_firmware"]["symlinks_same"]) == 2 and not d["closed_firmware"]["rejected_names"]
    # 目標不同 → 不接受
    (ours / "bootloader" / "tos_t234.img").unlink()
    (ours / "bootloader" / "tos_t234.img").symlink_to("mb1_t234_prod.bin")
    assert run_art(tmp_path, ours, up)["status"] == "ATTENTION"


@pytest.mark.parametrize("mode", ["w:bz2", "w:gz", "w:xz"])
def test_highly_compressible_member_is_linear_and_bounded(tmp_path, mode):
    """全零的大成員（例如 rootfs 的 64 MiB .fd）：DecompReader 不能每次讀取都複製整個剩餘緩衝（平方時間），
    每批解壓輸出也要有上限（解壓炸彈）。128 MiB 的零在舊寫法要好幾分鐘；這裡限 60 秒。"""
    import time
    size = 128 << 20
    p = tmp_path / "z.tar"
    with tarfile.open(p, mode) as t:
        ti = tarfile.TarInfo("top/rootfs/zero.fd")
        ti.size = size
        t.addfile(ti, io.BytesIO(bytes(size)))
        ti2 = tarfile.TarInfo("top/bootloader/a.bin")
        ti2.size = 1
        t.addfile(ti2, io.BytesIO(b"A"))
    biggest = 0
    orig = ub.DecompReader._more

    def spy(self):
        nonlocal biggest
        b = orig(self)
        biggest = max(biggest, len(b))
        return b
    ub.DecompReader._more = spy
    try:
        t0 = time.time()
        got = {rel: (a, b) for k, rel, a, b in ub.iter_tar(ub.open_archive(p)) if k == "file"}
        dt = time.time() - t0
    finally:
        ub.DecompReader._more = orig
    assert got["top/rootfs/zero.fd"] == (size, hashlib.sha256(bytes(size)).hexdigest())
    assert got["top/bootloader/a.bin"][0] == 1
    assert biggest <= ub.MAX_OUT
    assert dt < 60, dt


def test_truncated_compressed_archive_still_detected_after_fix(tmp_path):
    p = mk_tar(tmp_path / "t.tar.bz2", {"a": b"x" * 100000})
    data = p.read_bytes()
    (tmp_path / "cut.tar.bz2").write_bytes(data[:len(data) // 2])
    with pytest.raises((tarfile.TarError, EOFError, OSError)):
        list(ub.iter_tar(ub.open_archive(tmp_path / "cut.tar.bz2")))
