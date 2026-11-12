"""bootloader_coverage.py：開機韌體涵蓋說明、UEFI 映像與原始碼的對照、另外交付的韌體。
全部用測試自己組出來的小型假資料（假的原始碼樹、假的映像位元組、假的 SBOM），不含任何產品資料。"""
import hashlib
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import bootloader_coverage as bc  # noqa: E402
import firmware_bom as fb  # noqa: E402
import supplier_package as sp  # noqa: E402

CLI = HERE.parent / "bootloader_coverage.py"
FP = HERE.parents[1] / "demo"
sys.path.insert(0, str(FP))
import flash_package as fp  # noqa: E402

VER = "ACME_Board_R40.1.0"
JOINED = VER + "-3"
BUILD_PREFIX = "/home" "/builder/ws/sources/uefi"


def w(p, text):
    p = Path(p)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def make_tree(root, version_lines=(VER, "3"), files=("MdePkg/Library/BaseLib/LShiftU64.c", "MdePkg/Library/BaseLib/Math.c")):
    for f in files:
        w(Path(root) / "edk2" / f, "// c\n")
    w(Path(root) / "edk2-nvidia/Platform/NVIDIA/Tegra/X.c", "// c\n")
    if version_lines:
        w(Path(root) / "edk2-nvidia/Platform/NVIDIA/Tegra/PCP_FIRMWARE_VERSION_INFO", "\n".join(version_lines) + "\n")
    return root


def image(version=JOINED, paths=(), noise=b"\x01\x02\xff\xfe" * 50, utf16=True):
    b = noise
    if version:
        b += (b"\x00" + version.encode("utf-16-le") + b"\x00\x00") if utf16 else (b"\x00" + version.encode() + b"\x00")
    for p in paths:
        b += b"\x00" + (BUILD_PREFIX + "/" + p).encode() + b"\x00\x07"
    return b + noise


GOOD = ["edk2/MdePkg/Library/BaseLib/LShiftU64.c", "edk2/MdePkg/Library/BaseLib/Math.c", "edk2-nvidia/Platform/NVIDIA/Tegra/X.c"]


def cands(tree):
    return bc.tree_candidates(str(tree))[0]


# ---------- 分類（項目 1） ----------

@pytest.mark.parametrize("path,cls", [
    ("T/bootloader/uefi_t23x_general.bin", "uefi"), ("T/bootloader/uefi_bins/uefi_t26x_minimal.bin", "uefi"),
    ("T/bootloader/mb1_t234_prod.bin", "vendor_firmware"), ("T/bootloader/bpmp_t234-X-A1_prod.bin", "vendor_firmware"),
    ("T/bootloader/tos-optee_t234.img", "vendor_firmware"), ("T/bootloader/pscfw_t234_prod.bin", "vendor_firmware"),
    ("T/bootloader/spe_t234.bin", "vendor_firmware"), ("T/bootloader/sc7_t234_prod.bin", "vendor_firmware"),
    ("T/bootloader/tegra234-bpmp.dtb", "data"), ("T/bootloader/x.bct", "data"), ("T/bootloader/y.dtbo", "data"),
    ("T/bootloader/zzz_unknown_t234.bin", "unclassified"), ("T/bootloader/l4t_initrd.img", "unclassified"),
    ("T/bootloader/flash.xml", "not_firmware"), ("T/bootloader/foo.py", "not_firmware"), ("T/bootloader/chkbdinfo", "not_firmware"),
    ("T/bootloader/LICENSE.mb1.bin", "not_firmware"), ("T/bootloader/pkg_arm64.deb", "packaged_firmware"), ("T/bootloader/standalone_x.pkg", "packaged_firmware"),
    ("T/bootloader/sb_bl1_t264_prod.bin", "vendor_firmware"), ("T/bootloader/sbfw_t264_prod.bin", "vendor_firmware"),
    ("T/bootloader/spvault-sb-oem-conf.bin", "data"), ("T/bootloader/SOURCE.tos-optee_t234.img", "not_firmware"),
])
def test_classify(path, cls):
    assert bc.classify({"path": path, "type": "file"})[0] == cls


def test_classify_non_file_and_labels():
    assert bc.classify({"path": "T/bootloader/uefi_t23x_general.bin", "type": "symlink"})[0] == "not_file"
    assert bc.classify({"path": "T/bootloader/mb1_t234_prod.bin", "type": "file"})[1].startswith("MB1")
    assert bc.classify({"path": "T/bootloader/uefi_t23x_general.bin", "type": "file"})[1] is None


def inv_of(names, extra=None):
    boot = [{"path": f"T/bootloader/{n}", "type": "file", "size": 3, "sha256": hashlib.sha256(n.encode()).hexdigest(),
             "sha512": hashlib.sha512(n.encode()).hexdigest(), "mtime": 1700000000} for n in names]
    boot.append({"path": "T/bootloader/link.img", "type": "symlink", "target": "x"})
    d = {"bootloader": boot, "outside_rootfs": [], "other_deliverables": []}
    d.update(extra or {})
    return d


NAMES = ["uefi_t23x_general.bin", "uefi_bins/uefi_t23x_general.bin", "mb1_t234_prod.bin", "mb2_t234.bin", "bpmp_t234.bin", "tos_x.img",
         "a.dtb", "b.bct", "weird_fw.bin", "flash.sh", "x.xml", "README.txt"]


def test_counts_add_up_to_inventory_total():
    cov = bc.build_coverage(inv_of(NAMES), [], None, None, "rootfs")
    c = cov["counts"]
    assert cov["total"] == len(NAMES) + 1 == sum(c.values()) and cov["counts_add_up"]
    assert c["uefi"] == 2 and c["vendor_firmware"] == 4 and c["data"] == 2 and c["unclassified"] == 1 and c["not_file"] == 1
    assert c["not_firmware"] == 3 and c["packaged_firmware"] == 0
    assert len(cov["items"]) == cov["total"]


def test_statuses_never_look_safe():
    cov = bc.build_coverage(inv_of(NAMES), [], None, None, "rootfs")
    assert cov["status"] == "GAP" and set(cov["gap_classes"]) == {"uefi", "vendor_firmware", "unclassified"}
    by = {i["path"].rsplit("/", 1)[-1]: i for i in cov["items"]}
    assert by["mb1_t234_prod.bin"]["status"] == "GAP" and "no component-level scan" in by["mb1_t234_prod.bin"]["coverage"]
    assert "NVIDIA security bulletins" in by["mb1_t234_prod.bin"]["coverage"]
    assert by["a.dtb"]["status"] == "NOT_ASSESSED" and "not vulnerability-scanned" in by["a.dtb"]["coverage"]
    assert by["weird_fw.bin"]["status"] == "GAP"
    assert by["uefi_t23x_general.bin"]["status"] == "GAP" and "no UEFI source" in by["uefi_t23x_general.bin"]["coverage"]


def test_uefi_with_source_and_check_results():
    check = {"status": "ATTENTION", "counts": {"MATCH": 1, "MISMATCH": 1, "NOT_ASSESSED": 0}, "detail": "d",
             "images": [{"path": "T/bootloader/uefi_t23x_general.bin", "result": "MATCH"},
                        {"path": "T/bootloader/uefi_bins/uefi_t23x_general.bin", "result": "MISMATCH", "detail": "different"}]}
    cov = bc.build_coverage(inv_of(NAMES), [], {"status": "GAP"}, check, "rootfs")
    u = {i["path"]: i for i in cov["items"] if i["class"] == "uefi"}
    assert u["T/bootloader/uefi_t23x_general.bin"]["status"] == "OK"
    assert "scanned from UEFI source" in u["T/bootloader/uefi_t23x_general.bin"]["coverage"]
    assert "consistent with being built from this source version" in u["T/bootloader/uefi_t23x_general.bin"]["coverage"]
    assert u["T/bootloader/uefi_bins/uefi_t23x_general.bin"]["status"] == "ATTENTION"
    # 有原始碼結果但沒做一致性檢查：GAP，明說沒做
    cov = bc.build_coverage(inv_of(NAMES), [], {"status": "OK"}, None, "rootfs")
    assert all(i["status"] == "GAP" and i["build_check"] == "NOT_RUN" for i in cov["items"] if i["class"] == "uefi")


# ---------- rootfs 的 TEGRA_BL_*.Cap ----------

def sbom(*names):
    return {"components": [{"type": "file", "name": n, "hashes": [{"alg": "SHA-1", "content": "a" * 40},
                                                                   {"alg": "SHA-256", "content": hashlib.sha256(n.encode()).hexdigest()}]}
                           for n in names] + [{"type": "library", "name": "opt/ota_package/t23x/TEGRA_BL_3767.Cap"}]}


def test_rootfs_capsules_mapping_and_owner_unknown():
    caps = bc.rootfs_capsules(sbom("/opt/ota_package/t23x/TEGRA_BL_3767.Cap", "/opt/ota_package/t23x/TEGRA_BL_3701_agx.Cap",
                                   "/opt/ota_package/t26x/TEGRA_BL_9999_x.Cap", "/opt/ota_package/t23x/BOOTAA64.efi", "/usr/lib/TEGRA_BL_3767.Cap"))
    assert [c["file"] for c in caps] == ["TEGRA_BL_3701_agx.Cap", "TEGRA_BL_3767.Cap", "TEGRA_BL_9999_x.Cap"] or len(caps) == 3
    by = {c["file"]: c for c in caps}
    assert by["TEGRA_BL_3767.Cap"]["module"] == "Jetson Orin NX/Nano module" and by["TEGRA_BL_3701_agx.Cap"]["module"] == "Jetson AGX Orin module"
    assert by["TEGRA_BL_9999_x.Cap"]["module"] == "not mapped" and by["TEGRA_BL_9999_x.Cap"]["module_id"] == "9999"
    assert all(c["dpkg_package"] == "unknown" and c["board_match"] == "NOT_ASSESSED" for c in caps)
    assert by["TEGRA_BL_3767.Cap"]["variant_suffix"] is None and by["TEGRA_BL_9999_x.Cap"]["variant_suffix"] == "x"
    assert by["TEGRA_BL_3767.Cap"]["soc_folder"] == "t23x" and len(by["TEGRA_BL_3767.Cap"]["sha256"]) == 64


def test_rootfs_capsules_owner_from_dpkg_lists_only():
    p = "/opt/ota_package/t23x/TEGRA_BL_3767.Cap"
    caps = bc.rootfs_capsules(sbom(p), {"some-pkg": ["opt/ota_package/t23x/TEGRA_BL_3767.Cap"], "other": ["usr/bin/x"]})
    assert caps[0]["dpkg_package"] == "some-pkg" and caps[0]["dpkg_package_note"] is None


# ---------- 項目 2：映像與原始碼 ----------

def test_candidates_join_version_info(tmp_path):
    t = make_tree(tmp_path / "t")
    w(t / "edk2-nvidia/Platform/NVIDIA/L4TLauncher/PCP_FIRMWARE_VERSION_INFO", f"{VER}\n3\n")      # 同內容的第二個檔：去重
    w(t / "images/buildid_x.txt", "BUILD-12345\n")
    cs = bc.tree_candidates(str(t))[0]
    vals = {(c["value"], c["kind"]) for c in cs}
    assert (JOINED, "joined") in vals and (VER, "base") in vals and ("BUILD-12345", "build-id") in vals
    assert len([c for c in cs if c["kind"] == "joined"]) == 1
    # 一行的版本檔：不接
    t2 = make_tree(tmp_path / "t2", version_lines=("SOLO_R1.2.3",))
    assert [c["value"] for c in cands(t2)] == ["SOLO_R1.2.3"]


def test_candidates_filter_noise_and_symlinks(tmp_path):
    t = make_tree(tmp_path / "t", version_lines=())
    uj = {"source_strings": [{"file": "a.dsc", "value": "2.7", "kind": "literal"}, {"file": "b.dsc", "value": "$(BUILDID_STRING)", "kind": "build-time macro"},
                             {"file": "c.dsc", "value": "Edk2 for Board 1.2", "kind": "literal"}]}
    assert [c["value"] for c in bc.tree_candidates(str(t), uj)[0]] == ["Edk2 for Board 1.2"]
    outside = tmp_path / "outside"
    w(outside / "X_VERSION_INFO", "LEAK_R9.9.9\n")
    os.symlink(outside, t / "linkdir")
    os.symlink(outside / "X_VERSION_INFO", t / "edk2" / "Y_VERSION_INFO")
    assert bc.tree_candidates(str(t))[0] == []


def test_check_image_match_utf16(tmp_path):
    t = make_tree(tmp_path / "t")
    r = bc.check_image(image(paths=GOOD), str(t), cands(t))
    assert r["result"] == "MATCH" and r["paths"] == {"total": 3, "matched": 3, "missing": 0, "missing_examples": [], "outside_components": 0}
    assert r["version_found"][0]["candidate"] == JOINED and r["version_found"][0]["encoding"] == "UTF-16LE" and r["version_found"][0]["exact"]
    assert "consistent with being built from this source version" in r["wording"] and "identical" not in json.dumps(r["detail"]).lower()
    assert r["build_prefix_examples"] == [BUILD_PREFIX]


def test_check_image_match_ascii(tmp_path):
    t = make_tree(tmp_path / "t")
    assert bc.check_image(image(paths=GOOD, utf16=False), str(t), cands(t))["result"] == "MATCH"


def test_check_image_different_version_is_mismatch(tmp_path):
    t = make_tree(tmp_path / "t")
    r = bc.check_image(image(version="ACME_Board_R39.9.0-1", paths=GOOD), str(t), cands(t))
    assert r["result"] == "MISMATCH" and r["other_versions_seen"] == ["ACME_Board_R39.9.0-1"] and "different version string" in r["detail"]


def test_check_image_base_only_is_not_exact(tmp_path):
    """第一行（基底）只出現在更長的詞裡、而完整字串（第一行-第二行）不是 → 不算相符。"""
    t = make_tree(tmp_path / "t")
    r = bc.check_image(image(version=VER + "-9", paths=GOOD), str(t), cands(t))
    assert r["result"] != "MATCH"
    assert not any(f["exact"] for f in r["version_found"]) and r["version_found"][0]["found"] == VER + "-9"


def test_check_image_thresholds(tmp_path):
    t = make_tree(tmp_path / "t", files=tuple(f"MdePkg/L/F{i}.c" for i in range(20)))
    ok = [f"edk2/MdePkg/L/F{i}.c" for i in range(20)]
    miss = [f"edk2/MdePkg/Gone/G{i}.c" for i in range(20)]
    # 18/20 = 90%：剛好達門檻 → MATCH
    assert bc.check_image(image(paths=ok[:18] + miss[:2]), str(t), cands(t))["result"] == "MATCH"
    # 17/20 = 85%：版本相符但很多路徑不存在 → MISMATCH
    r = bc.check_image(image(paths=ok[:17] + miss[:3]), str(t), cands(t))
    assert r["result"] == "MISMATCH" and "17 of 20" in r["detail"] and r["paths"]["missing_examples"]
    # 沒有版本字串：路徑夠多又幾乎都不存在 → MISMATCH；路徑都對但沒有版本字串 → NOT_ASSESSED（不憑路徑判一致）
    assert bc.check_image(image(version=None, paths=miss[:8]), str(t), cands(t))["result"] == "MISMATCH"
    assert bc.check_image(image(version=None, paths=ok[:8]), str(t), cands(t))["result"] == "NOT_ASSESSED"


def test_check_image_version_only_and_nothing_readable(tmp_path):
    t = make_tree(tmp_path / "t")
    r = bc.check_image(image(), str(t), cands(t))
    assert r["result"] == "MATCH" and "path evidence: none" in r["detail"]
    assert bc.check_image(image(version=None), str(t), cands(t))["result"] == "NOT_ASSESSED"
    no_cands = make_tree(tmp_path / "t3", version_lines=())
    assert bc.check_image(image(paths=GOOD), str(no_cands), [])["result"] == "NOT_ASSESSED"


def test_embedded_path_handling(tmp_path):
    t = make_tree(tmp_path / "t")
    ps = ["/x/y/edk2/../../etc/passwd.c", "/home" "/u/Build/Foo/DEBUG/AutoGen.c", "/a/b/edk2/MdePkg/Library/BaseLib/LShiftU64.c"]
    matched, missing, other, _ = bc.embedded_paths(["see " + p for p in ps], str(t))
    assert matched == ["edk2/MdePkg/Library/BaseLib/LShiftU64.c"] and missing == [] and other == 2     # 含 ".." 的路徑與建置輸出的路徑不在元件資料夾下


def test_embedded_paths_edk2_root_layout(tmp_path):
    root = tmp_path / "e"
    w(root / "MdePkg/Library/BaseLib/A.c", "x")
    matched, missing, other, _ = bc.embedded_paths(["/h/u/edk2/MdePkg/Library/BaseLib/A.c", "/h/u/edk2/MdePkg/Library/BaseLib/B.c"], str(root))
    assert matched == ["edk2/MdePkg/Library/BaseLib/A.c"] and missing == ["edk2/MdePkg/Library/BaseLib/B.c"]


def flash_dir(tmp_path, files):
    root = tmp_path / "pkg"
    for name, data in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    return root


def inv_for(files):
    return {"bootloader": [{"path": n, "type": "file", "size": len(d), "sha256": hashlib.sha256(d).hexdigest()} for n, d in files.items()
                           if "bootloader" in n.split("/")[:-1]]}


def test_cli_uefi_check_dir_and_archive(tmp_path):
    t = make_tree(tmp_path / "t")
    files = {"Tool/bootloader/uefi_a.bin": image(paths=GOOD), "Tool/bootloader/uefi_bins/uefi_b.bin": image(version="ACME_Board_R39.9.0-1", paths=GOOD),
             "Tool/bootloader/mb1.bin": b"x", "Tool/rootfs/etc/big": b"y" * 10}
    d = flash_dir(tmp_path, files)
    inv = tmp_path / "flash-inventory.json"
    inv.write_text(json.dumps(inv_for(files)))
    out = tmp_path / "chk.json"
    p = subprocess.run([sys.executable, "-I", str(CLI), "uefi-check", "--inventory", str(inv), "--dir", str(d), "--tree", str(t), "--out", str(out)],
                       capture_output=True, text=True)
    line = p.stdout.strip().split("\t")
    assert line[0] == "X-uefi-binary" and line[1] == "ATTENTION" and p.returncode == 2, p.stdout + p.stderr
    res = json.loads(out.read_text())
    assert {i["path"].rsplit("/", 1)[-1]: i["result"] for i in res["images"]} == {"uefi_a.bin": "MATCH", "uefi_b.bin": "MISMATCH"}
    # 同一份內容放進 tbz2：結果相同（串流讀取，不解開到磁碟）
    a = tmp_path / "pkg.tbz2"
    with tarfile.open(a, "w:bz2") as tf:
        tf.add(d / "Tool", arcname="Tool")
    out2 = tmp_path / "chk2.json"
    p = subprocess.run([sys.executable, "-I", str(CLI), "uefi-check", "--inventory", str(inv), "--archive", str(a), "--tree", str(t), "--out", str(out2)],
                       capture_output=True, text=True)
    assert p.returncode == 2 and json.loads(out2.read_text())["counts"] == res["counts"]
    # 所有映像都一致 → OK、退出碼 0
    inv2 = tmp_path / "inv2.json"
    inv2.write_text(json.dumps({"bootloader": [x for x in inv_for(files)["bootloader"] if x["path"].endswith("uefi_a.bin")]}))
    p = subprocess.run([sys.executable, "-I", str(CLI), "uefi-check", "--inventory", str(inv2), "--dir", str(d), "--tree", str(t), "--out", str(out)],
                       capture_output=True, text=True)
    assert p.returncode == 0 and p.stdout.split("\t")[1] == "OK"


def test_cli_uefi_check_unreadable_and_missing(tmp_path):
    t = make_tree(tmp_path / "t")
    d = tmp_path / "pkg"
    (d / "Tool/bootloader").mkdir(parents=True)
    (d / "Tool/bootloader/real").write_bytes(image(paths=GOOD))
    os.symlink("real", d / "Tool/bootloader/uefi_link.bin")
    inv = {"bootloader": [{"path": "Tool/bootloader/uefi_link.bin", "type": "file"}, {"path": "Tool/bootloader/uefi_gone.bin", "type": "file"}]}
    res = bc.run_uefi_check(inv, str(t), directory=str(d))
    assert [i["result"] for i in res["images"]] == ["NOT_ASSESSED", "NOT_ASSESSED"] and res["status"] == "GAP"
    assert "not a regular file" in res["images"][0]["detail"] and "not found" in res["images"][1]["detail"]
    # 沒有 UEFI 映像 → GAP，不是 OK
    assert bc.run_uefi_check({"bootloader": []}, str(t), directory=str(d))["status"] == "GAP"


def test_read_cap_truncates(tmp_path, monkeypatch):
    monkeypatch.setattr(bc, "MAX_BIN", 100)
    t = make_tree(tmp_path / "t")
    files = {"Tool/bootloader/uefi_a.bin": b"\x00" * 200 + image(paths=GOOD)}
    d = flash_dir(tmp_path, files)
    res = bc.run_uefi_check(inv_for(files), str(t), directory=str(d))
    assert res["images"][0]["result"] == "NOT_ASSESSED" and "only the first" in res["images"][0]["detail"]


# ---------- 項目 3：另外交付的韌體 ----------

def cap_bytes(version=JOINED):
    return b"CAPSULE\x00\x00\x00" + (version.encode("utf-16-le") if version else b"") + b"\x00\x00tail"


def test_extra_record_fields_and_hashes(tmp_path):
    t = make_tree(tmp_path / "t")
    f = tmp_path / "rd_capsule.Cap"
    data = cap_bytes()
    f.write_bytes(data)
    r = bc.extra_record(str(f), cands(t), "Prod", "40.1.0.3", "40.1.0")
    assert r["name"] == "rd_capsule.Cap" and r["size"] == len(data) and r["sha256"] == hashlib.sha256(data).hexdigest()
    assert r["sha512"] == hashlib.sha512(data).hexdigest() and r["version"] == JOINED and r["version_vs_flash_package"] == "consistent"
    assert r["status"] == "OK" and r["scanned"] is False and "not scanned" in r["note"]
    assert r["paired_with"] == {"name": "Prod", "version": "40.1.0.3", "jetson_linux": "40.1.0"}
    assert str(tmp_path) not in json.dumps(r)


def test_extra_record_different_unknown_and_generic(tmp_path):
    t = make_tree(tmp_path / "t")
    f = tmp_path / "old.Cap"
    f.write_bytes(cap_bytes("Other_Board_R39.2.0-1"))        # 原始碼樹的候選找不到，通用樣式找到
    r = bc.extra_record(str(f), cands(t), "Prod", "40.1.0.3", "40.1.0")
    assert r["version"] == "Other_Board_R39.2.0-1" and r["version_strings"][0]["basis"] == "generic version-like string"
    assert r["status"] == "ATTENTION" and "different version from this flash package" in r["note"] and "not scanned" in r["note"]
    f.write_bytes(cap_bytes(None))
    r = bc.extra_record(str(f), cands(t), "Prod", "40.1.0.3", "40.1.0")
    assert r["version"] is None and r["status"] == "NOT_ASSESSED" and "version unknown" in r["note"] and r["version_vs_flash_package"] == "unknown"


def test_compare_version():
    assert bc.compare_version("X_R40.1.0-3", "40.1.0.3", "40.1.0") == "consistent"
    assert bc.compare_version("X_R40.1.0", "40.1.0.3", "40.1.0") == "consistent"
    assert bc.compare_version("X_R40.1.0-4", "40.1.0.3", "40.1.0") == "different"
    assert bc.compare_version("X_R39.2.0-3", "40.1.0.3", None) == "different"
    assert bc.compare_version("nothing", "40.1.0.3", "40.1.0") == "unknown"
    assert bc.compare_version("X_R40.1.0-3", "vendor-build", None) == "unknown"


def test_extra_rejects_non_regular_files(tmp_path):
    f = tmp_path / "real.Cap"
    f.write_bytes(b"x")
    os.symlink(f, tmp_path / "link.Cap")
    (tmp_path / "adir").mkdir()
    for bad in ("link.Cap", "adir", "missing.Cap"):
        with pytest.raises(bc.Fail):
            bc.extra_record(str(tmp_path / bad), [], "P", "1.0", None)
    with pytest.raises(bc.Fail, match="same file name"):
        (tmp_path / "s").mkdir()
        (tmp_path / "s" / "real.Cap").write_bytes(b"y")
        bc.run_extra("x", [str(f), str(tmp_path / "s" / "real.Cap")], "P", "1.0", None)


def test_cli_extra_updates_inventory_and_sbom(tmp_path):
    t = make_tree(tmp_path / "t")
    f = tmp_path / "rd.Cap"
    f.write_bytes(cap_bytes("Other_Board_R39.2.0-1"))
    inv = tmp_path / "flash-inventory.json"
    inv.write_text(json.dumps(inv_of(["uefi_a.bin", "mb1_t234_prod.bin"])))
    before = json.loads(inv.read_text())
    p = subprocess.run([sys.executable, "-I", str(CLI), "extra", "--inventory", str(inv), "--deliverable", str(f), "--name", "Prod", "--version", "40.1.0.3",
                        "--l4t", "40.1.0", "--tree", str(t), "--out", str(tmp_path / "extra.json")], capture_output=True, text=True)
    assert p.returncode == 2 and p.stdout.startswith("X-extra-deliverable\tATTENTION\t"), p.stdout + p.stderr
    after = json.loads(inv.read_text())
    assert {k: v for k, v in after.items() if not k.startswith("extra_deliverables")} == before and len(after["extra_deliverables"]) == 1
    comps, deps, top, info = fb.build(after, None, "rootfs", None)
    ex = [c for c in comps if c["bom-ref"].endswith("extra-deliverables/rd.Cap")]
    assert len(ex) == 1 and ex[0]["type"] == "firmware" and ex[0]["bom-ref"] in top
    props = {p["name"]: p["value"] for p in ex[0]["properties"]}
    assert props["sca-center:paired-with"] == "Prod 40.1.0.3" and props["sca-center:version-string-found"] == "Other_Board_R39.2.0-1"
    assert props["sca-center:version-vs-flash-package"] == "different" and props["sca-center:scan-status"].startswith("not scanned")
    assert {h["alg"] for h in ex[0]["hashes"]} == {"SHA-256", "SHA-512"} and str(tmp_path) not in json.dumps(ex[0])
    assert any("extra deliverable rd.Cap" in n and "different version" in n for n in info["notes"])
    assert any(s["count"] == 1 and "extra deliverables" in s["source"] for s in info["sources"])


def test_firmware_bom_unchanged_without_extra_deliverables():
    """沒有 extra_deliverables 時，產品 SBOM 的韌體元件、依賴、來源表與以前相同（沒有新的屬性、來源列）。"""
    inv = inv_of(["uefi_a.bin", "mb1_t234_prod.bin", "a.dtb"], {"other_deliverables": [{"name": "DEV_MCU_V2.zip", "type": "file", "sha256": "a" * 64}]})
    comps, deps, top, info = fb.build(inv, None, "rootfs", None)
    text = json.dumps([comps, deps, top, info], sort_keys=True)
    assert "sca-center:extra-deliverable" not in text and "extra deliverables" not in text
    assert [s["source"] for s in info["sources"]][-1].startswith("MCU firmware")
    assert any(c["name"] == "DEV_MCU_V2.zip" for c in comps)
    # .Cap 不改變既有的 other_deliverables 行為（膠囊走 --extra-deliverable）
    inv["other_deliverables"].append({"name": "board_fw_update.Cap", "type": "file", "sha256": "b" * 64})
    assert not any(c["name"] == "board_fw_update.Cap" for c in fb.build(inv, None, "rootfs", None)[0])


# ---------- 涵蓋說明的組裝、客戶版文字、內部報告 ----------

def result_dir(tmp_path, with_uefi=True, with_check=True, with_sbom=True):
    res = tmp_path / "res"
    inv = inv_of(NAMES)
    res.mkdir()
    (res / "flash-inventory.json").write_text(json.dumps(inv))
    if with_sbom:
        w(res / "rootfs/scan/sbom/sbom.cdx.json", json.dumps(sbom("/opt/ota_package/t23x/TEGRA_BL_3767.Cap", "/opt/ota_package/t26x/TEGRA_BL_3834_agx.Cap")))
    if with_uefi:
        w(res / "rootfs/uefi-source/uefi-source.json", json.dumps({"status": "OK"}))
    if with_check:
        w(res / "uefi-binary-check.json", json.dumps({"schema": bc.CHECK_SCHEMA, "status": "OK", "counts": {"MATCH": 2, "MISMATCH": 0, "NOT_ASSESSED": 0},
                                                      "detail": "2 UEFI image(s)",
                                                      "images": [{"path": "T/bootloader/uefi_t23x_general.bin", "result": "MATCH"},
                                                                 {"path": "T/bootloader/uefi_bins/uefi_t23x_general.bin", "result": "MATCH"}]}))
    return res


def test_cli_coverage_writes_files_and_exit_code(tmp_path):
    res = result_dir(tmp_path)
    p = subprocess.run([sys.executable, "-I", str(CLI), "coverage", "--result", str(res), "--variant", "rootfs"], capture_output=True, text=True)
    assert p.returncode == 2 and p.stdout.startswith("X-bootloader-coverage\tGAP\t"), p.stdout + p.stderr
    cov = json.loads((res / "rootfs/bootloader-coverage.json").read_text())
    assert cov["counts_add_up"] and cov["total"] == 13 and cov["rootfs_capsules_board_match"] == "NOT_ASSESSED"
    assert [c["module_id"] for c in cov["rootfs_capsules"]] == ["3767", "3834"] and cov["rootfs_capsules"][1]["module"] == "not mapped"
    md = (res / "rootfs/bootloader-coverage.md").read_text()
    assert "TEGRA_BL_3767.Cap" in md and "NOT_ASSESSED" in md and "unknown" in md
    low = (md + json.dumps(cov)).lower()
    for word in ("unused", "remove", "not used", "delete"):
        assert word not in low
    u = [i for i in cov["items"] if i["class"] == "uefi"]
    assert all(i["status"] == "OK" for i in u)


def test_coverage_without_inputs_is_gap_not_safe(tmp_path):
    res = result_dir(tmp_path, with_uefi=False, with_check=False, with_sbom=False)
    cov = bc.run_coverage(res, "rootfs")
    assert cov["status"] == "GAP" and cov["rootfs_sbom_present"] is False and "rootfs SBOM was not available" in cov["detail"]
    assert all(i["status"] == "GAP" for i in cov["items"] if i["class"] == "uefi")
    assert bc.main(["coverage", "--result", str(tmp_path / "nope"), "--variant", "rootfs"]) == 1


def test_customer_text_is_neutral_and_passes_language_check(tmp_path):
    res = result_dir(tmp_path)
    cov = bc.run_coverage(res, "rootfs")
    cov["extra_deliverables"] = [{"name": "rd.Cap", "sha256": "a" * 64, "version": None, "status": "NOT_ASSESSED"}]
    text = bc.customer_text(cov)
    assert sp.check_customer_text("sbom.md", text) == []
    assert "/home" not in text and "builder" not in text and "/opt/" not in text
    assert "no component-level scan" in text and "Their content is not scanned" in text and "not assessed" in text
    assert "t23x/TEGRA_BL_3767.Cap" in text and "identical" not in text.lower()
    assert text.count("|") > 10 and "add up to 13" in text
    d = tmp_path / "pkgdir"
    d.mkdir()
    (d / "sbom.md").write_text("# x\n\n" + text + "\n")
    assert sp.language_check(d)["status"] == "OK"


def test_check_line_has_no_paths():
    line = bc.check_line({"counts": {"MATCH": 1, "MISMATCH": 2, "NOT_ASSESSED": 3}})
    assert "1" in line and "not a bit-for-bit comparison" in line and "/" not in line.replace("bit-for-bit", "")


def test_uefi_rows_carry_check_line():
    import uefi_bundled as ub
    info = {"libs": [{"purl": "pkg:generic/openssl@3.4.1", "label": "OpenSSL 3.4.1", "name": "openssl", "version": "3.4.1", "role": "edk2-submodule"}],
            "build_check": "line"}
    rows = [{"purl": "pkg:generic/openssl@3.4.1", "fix_versions": ["3.4.2"], "fix_state": "fixed"}]
    assert ub.relabel_rows(rows, info)[0]["uefi_build_check"] == "line"
    info.pop("build_check")
    rows = [{"purl": "pkg:generic/openssl@3.4.1", "fix_versions": ["3.4.2"], "fix_state": "fixed"}]
    assert "uefi_build_check" not in ub.relabel_rows(rows, info)[0]


def test_summary_unchanged_without_coverage_and_has_section_with(tmp_path):
    out = tmp_path / "o"
    (out / "rootfs/scan").mkdir(parents=True)
    (out / "list.json").write_text(json.dumps({"rootfs": [{"variant": "rootfs", "prefix": "p/rootfs", "l4t": {"release": "40.1.0"}}]}))
    res = fp.summarize(str(out), ["rootfs"])
    assert "bootloader_coverage" not in res[0] and "Bootloader" not in fp.summary_md(res)
    (out / "rootfs/bootloader-coverage.json").write_text(json.dumps({"status": "GAP", "detail": "992 entries", "counts": {"uefi": 1}}))
    res = fp.summarize(str(out), ["rootfs"])
    assert res[0]["bootloader_coverage"]["status"] == "GAP"
    md = fp.summary_md(res)
    assert "Bootloader 與韌體涵蓋：GAP" in md and "GAP" in md and "rootfs/bootloader-coverage.md" in md


def test_empty_inventory_is_gap():
    cov = bc.build_coverage({"bootloader": []}, [], None, None, "rootfs")
    assert cov["status"] == "GAP" and cov["total"] == 0 and "no bootloader entries" in cov["detail"]


def test_packaged_firmware_counts_toward_gap_and_wording():
    inv = inv_of(["x.deb", "y.pkg", "flash.sh"])
    cov = bc.build_coverage(inv, [], None, None, "rootfs")
    assert cov["counts"]["packaged_firmware"] == 2 and cov["counts_add_up"] and "packaged_firmware" in cov["gap_classes"]
    t = bc.customer_text(cov)
    assert "Packaged firmware (.deb, .pkg)" in t and "packages, tools" not in t and "add up to 4" in t


def test_mismatch_makes_coverage_attention():
    check = {"status": "ATTENTION", "counts": {"MATCH": 0, "MISMATCH": 1, "NOT_ASSESSED": 0},
             "images": [{"path": "T/bootloader/uefi_t23x_general.bin", "result": "MISMATCH"}]}
    cov = bc.build_coverage(inv_of(NAMES), [], {"status": "OK"}, check, "rootfs")
    assert cov["status"] == "ATTENTION"
    check["images"][0]["result"] = "NOT_ASSESSED"
    assert bc.build_coverage(inv_of(NAMES), [], {"status": "OK"}, check, "rootfs")["status"] == "GAP"


def test_all_not_found_gives_level_hint(tmp_path):
    t = make_tree(tmp_path / "t")
    d = tmp_path / "pkg"
    d.mkdir()
    res = bc.run_uefi_check({"bootloader": [{"path": "Tool/bootloader/uefi_a.bin", "type": "file"}]}, str(t), directory=str(d))
    assert "folder level may differ" in res["images"][0]["detail"]


def test_compare_version_conflicting_strings(tmp_path):
    t = make_tree(tmp_path / "t")
    f = tmp_path / "x.Cap"
    f.write_bytes(b"\x00\x00" + "Aaa_Board_R40.1.0-3".encode("utf-16-le") + b"\x00\x00\x00\x00" + b"Bbb_Board_R39.2.0-1\x00")
    r = bc.extra_record(str(f), [], "Prod", "40.1.0.3", "40.1.0")
    assert r["version_vs_flash_package"] == "conflict" and r["status"] == "ATTENTION" and "disagree" in r["note"]
    assert {x["vs_flash_package"] for x in r["version_strings"]} == {"consistent", "different"}
    assert bc.compare_version("X_R40.1.0-3", "40.1.0.3", "40.1.0") == "consistent"
    assert bc.compare_version("X_R40.1.0-2", "40.1.0", "40.1.0") == "unknown"
