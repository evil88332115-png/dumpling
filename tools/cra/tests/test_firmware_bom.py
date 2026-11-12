"""firmware_bom.py 的測試：刷機包韌體併進產品 SBOM、kernel 模組的 modinfo、BSI TR-03183-2 覆蓋率（合成的小型資料，不用 BSP 檔案）。"""
import io
import json
import lzma
import struct
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest
from cdx_schema import cdx_validator  # noqa: E402（共用的 CycloneDX 1.6.1 schema 驗證器，tools/cra/tests/cdx_schema.py）

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parents[1] / "demo"))
import firmware_bom as fb  # noqa: E402
import flash_package as fp  # noqa: E402
from test_cra_report import MIN_CFG, SBOM, make_project, make_scan, run, write_json  # noqa: E402

H256, H512 = "a" * 64, "b" * 128
MTIME = 1767225600          # 2026-01-01T00:00:00Z


def elf(modinfo, cls=2, le=True):
    """最小的 ELF（只有區段表：null、.modinfo、.shstrtab）。"""
    e = "<" if le else ">"
    shstr = b"\0.modinfo\0.shstrtab\0"
    hsz = 64 if cls == 2 else 52
    off_mi, off_ss = hsz, hsz + len(modinfo)
    shoff = off_ss + len(shstr)
    fmt, ent = (e + "IIQQQQIIQQ", 64) if cls == 2 else (e + "IIIIIIIIII", 40)
    sh = [struct.pack(fmt, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0), struct.pack(fmt, 1, 1, 0, 0, off_mi, len(modinfo), 0, 0, 1, 0),
          struct.pack(fmt, 10, 3, 0, 0, off_ss, len(shstr), 0, 0, 1, 0)]
    ident = b"\x7fELF" + bytes([cls, 1 if le else 2, 1]) + b"\0" * 9
    if cls == 2:
        h = ident + struct.pack(e + "HHIQQQIHHHHHH", 1, 183, 1, 0, 0, shoff, 0, 64, 0, 0, ent, 3, 2)
    else:
        h = ident + struct.pack(e + "HHIIIIIHHHHHH", 1, 40, 1, 0, 0, shoff, 0, 52, 0, 0, ent, 3, 2)
    return h + modinfo + shstr + b"".join(sh)


MODINFO = b"version=1.2.3\0license=GPL v2\0author=NVIDIA\0author=Someone\0srcversion=ABC\0vermagic=6.8.12-tegra SMP\0name=nvgpu\0parm=x:int\0"


# ---------- modinfo ----------

@pytest.mark.parametrize("cls,le", [(2, True), (1, False), (1, True), (2, False)])
def test_modinfo_elf_classes(cls, le):
    r = fb.module_info(elf(MODINFO, cls, le), "nvgpu.ko")
    assert r["modinfo"] == {"version": "1.2.3", "license": "GPL v2", "author": "NVIDIA; Someone", "srcversion": "ABC",
                            "vermagic": "6.8.12-tegra SMP", "name": "nvgpu"}


def test_modinfo_compressed_and_unreadable():
    assert fb.module_info(lzma.compress(elf(MODINFO)), "x.ko.xz")["modinfo"]["name"] == "nvgpu"
    zst = fb.module_info(b"\x28\xb5\x2f\xfd....", "x.ko.zst")
    assert zst["modinfo"] is None and "zstd" in zst["modinfo_note"]
    for data, why in ((b"not elf", "not an ELF"), (elf(MODINFO)[:70], "bad ELF section header"), (b"\x7fELF\x02\x01\x01" + b"\0" * 9, "truncated"),
                      (lzma.compress(b"x")[:5], "cannot decompress")):
        r = fb.module_info(data, "y.ko.xz" if why == "cannot decompress" else "y.ko")
        assert r["modinfo"] is None and why in r["modinfo_note"], r
    no_sec = elf(MODINFO).replace(b".modinfo\0", b".xxxxxxx\0")
    assert "no .modinfo" in fb.module_info(no_sec, "z.ko")["modinfo_note"]


def test_is_module_path():
    assert fb.is_module_path("usr/lib/modules/6.8.12-tegra/updates/drivers/gpu/nvgpu.ko")
    assert fb.is_module_path("lib/modules/6.8.12-tegra/updates/a b.ko.xz")
    assert not fb.is_module_path("usr/lib/modules/6.8.12-tegra/kernel/drivers/x.ko")     # 核心本身的模組（在 deb 裡）
    assert not fb.is_module_path("usr/lib/modules/6.8.12-tegra/updates/modules.dep")


# ---------- build ----------

def item(path, typ="file", sha512=True, **kw):
    x = {"path": path, "type": typ, "mode": "0o644"}
    if typ == "file":
        x.update(size=10, sha256=H256, mtime=MTIME, **({"sha512": H512} if sha512 else {}))
    x.update(kw)
    return x


LIST = {"rootfs": [{"variant": "rootfs_no_gui", "prefix": "product-a/Linux_for_Tegra/rootfs_no_gui",
                    "l4t": {"release": "39.2.1", "status": "OK", "sources": {"nv_tegra_release": "39.2.1", "nvidia-l4t-core": "39.2.1"}}}]}
P = "product-a/Linux_for_Tegra"
INV = {
    "bootloader": [item(f"{P}/bootloader/mb1_t234_prod.bin"), item(f"{P}/bootloader/uefi jetson.bin"),      # 路徑含空白
                   item(f"{P}/bootloader/tegra234-p3767.dtb"), item(f"{P}/bootloader/flash.xml"), item(f"{P}/bootloader/l4t_sign.py"),
                   item(f"{P}/bootloader/system.img"), item(f"{P}/bootloader/link.bin", "symlink", target="mb1_t234_prod.bin"),
                   item(f"{P}/bootloader/mb1_t234_prod.bin", size=11)],                                                   # 重複的路徑
    "outside_rootfs": [item(f"{P}/kernel/Image"), item(f"{P}/kernel/dtb/tegra234-p3768.dtbo"), item(f"{P}/flash.sh"),
                       item(f"{P}/kernel/kernel_headers.tbz2")],
    "kernel_modules": {f"{P}/rootfs_no_gui": [
        item("usr/lib/modules/6.8.12-tegra/updates/nvgpu.ko", modinfo={"name": "nvgpu", "version": "1.2.3", "license": "GPL v2",
                                                                        "vermagic": "6.8.12-tegra"}),
        item("usr/lib/modules/6.8.12-tegra/updates/zst mod.ko.zst", modinfo=None, modinfo_note="zstd-compressed module"),
        item("usr/lib/modules/6.8.12-tegra/updates/l.ko", "symlink", target="nvgpu.ko")]},
    "other_deliverables": [{"name": "MCU_FW_v1.2.zip", "type": "file", "size": 5, "sha256": H256, "sha512": H512, "mtime": MTIME},
                           {"name": "Release Note.pdf", "type": "file", "size": 5, "sha256": H256},
                           {"name": "SourceCode_tools.zip", "type": "file", "size": 5, "sha256": H256},      # 不是 MCU 韌體
                           {"name": "sdcard.img", "type": "file", "size": 5, "sha256": H256},
                           {"name": "SourceCode", "type": "dir", "note": "not inventoried"}],
}


def by_name(comps):
    return {c["name"]: c for c in comps}


def props(c):
    return {p["name"]: p["value"] for p in c["properties"]}


def test_build_components():
    comps, deps, top, info = fb.build(INV, LIST, "rootfs_no_gui", supplier_cfg={"name": "Vendor Ltd", "url": "https://vendor.example"})
    n = by_name(comps)
    assert set(n) == {"NVIDIA Jetson Linux", "mb1_t234_prod.bin", "uefi jetson.bin", "tegra234-p3767.dtb", "Image", "tegra234-p3768.dtbo",
                      "nvgpu", "zst mod", "MCU_FW_v1.2.zip"}
    l4t = n["NVIDIA Jetson Linux"]
    assert l4t["version"] == "39.2.1" and l4t["manufacturer"]["name"] == "NVIDIA Corporation" and props(l4t)[fb.P_LOGICAL] == "true"
    assert top == [l4t["bom-ref"], n["MCU_FW_v1.2.zip"]["bom-ref"]]
    assert sorted(deps[l4t["bom-ref"]]) == sorted(c["bom-ref"] for c in comps if c["name"] not in ("NVIDIA Jetson Linux", "MCU_FW_v1.2.zip"))
    mb1 = n["mb1_t234_prod.bin"]
    assert mb1["type"] == "firmware" and mb1["supplier"]["name"] == "Vendor Ltd" and "manufacturer" not in mb1
    assert [h["alg"] for h in mb1["hashes"]] == ["SHA-256", "SHA-512"] and mb1["version"] == "2026-01-01T00:00:00Z"
    assert props(mb1)["bsi:component:executable"] == "executable" and props(mb1)["bsi:component:structured"] == "unstructured"
    assert props(n["uefi jetson.bin"])["sca-center:flash-package-path"] == f"{P}/bootloader/uefi jetson.bin"
    assert "bsi:component:executable" not in props(n["tegra234-p3767.dtb"])                  # 資料檔不猜
    assert props(n["MCU_FW_v1.2.zip"])["bsi:component:archive"] == "archive"
    nv = n["nvgpu"]
    assert nv["type"] == "device-driver" and nv["version"] == "1.2.3" and nv["licenses"] == [{"license": {"name": "GPL v2", "acknowledgement": "declared"}}]
    assert props(nv)["sca-center:flash-package-path"] == f"{P}/rootfs_no_gui/usr/lib/modules/6.8.12-tegra/updates/nvgpu.ko"
    z = n["zst mod"]
    assert z["version"] == "2026-01-01T00:00:00Z" and "zstd" in props(z)["sca-center:modinfo"]
    assert info["duplicates"] == 1 and info["skipped"] == {"symbolic link or other non-file entry": 2, "not firmware (scripts, configuration, tools)": 3,
                                                           "root file system image": 1}
    assert [s["count"] for s in info["sources"]] == [3, 2, 2, 1, 1] and info["sources"][2]["no_modinfo"] == 1
    assert info["other_deliverables_not_added"] == ["Release Note.pdf", "SourceCode_tools.zip", "sdcard.img"]
    # 設定的樣式可以把其他交付檔加進來
    comps2, _, _, info2 = fb.build(INV, LIST, "rootfs_no_gui", firmware_patterns=["sdcard*.img"])
    assert "sdcard.img" in by_name(comps2) and "SourceCode_tools.zip" in info2["other_deliverables_not_added"]
    assert not info["notes"] and len({c["bom-ref"] for c in comps}) == len(comps)


def test_build_empty_inventory_and_old_format():
    comps, deps, top, info = fb.build({}, None, "rootfs_no_gui")
    assert comps == [] and top == [] and any("no kernel module list" in x for x in info["notes"])
    assert any("list.json has no root file system" in x for x in info["notes"])
    old = {"bootloader": [item(f"{P}/bootloader/a.bin", sha512=False)], "other_deliverables": None}
    comps, _, top, info = fb.build(old, LIST, "rootfs_no_gui")
    assert [h["alg"] for h in by_name(comps)["a.bin"]["hashes"]] == ["SHA-256"] and not info["inventory_has_sha512"]
    assert "supplier" not in by_name(comps)["a.bin"]
    text = fb.firmware_text(info, fb._table)
    assert "TO BE COMPLETED" in text and "no SHA-512" in text and "MCU firmware not in the SBOM" in text


def test_build_l4t_undetermined_and_ambiguous():
    lst = {"rootfs": [{"variant": "rootfs_no_gui", "prefix": "a/rootfs_no_gui", "l4t": {"release": None, "status": "ATTENTION", "detail": "x"}},
                      {"variant": "rootfs_no_gui", "prefix": "b/rootfs_no_gui", "l4t": {"release": "39.2.1"}}]}
    comps, _, top, info = fb.build({"bootloader": [item("a/bootloader/x.bin")]}, lst, "rootfs_no_gui")
    assert "appears 2 times" in info["notes"][0] and top == [comps[0]["bom-ref"]]
    comps, _, _, info = fb.build({"bootloader": [item("a/bootloader/x.bin")]}, lst, "rootfs_no_gui", prefix="a/rootfs_no_gui")
    assert "NVIDIA Jetson Linux" not in by_name(comps) and "L4T release not determined" in info["notes"][0]


def test_merge_and_clash():
    comps, deps, top, _ = fb.build(INV, LIST, "rootfs_no_gui")
    bom = {"components": [{"bom-ref": "x", "name": "x"}], "dependencies": [{"ref": "root", "dependsOn": ["x"]}]}
    fb.merge(bom, "root", comps, deps, top)
    d = {x["ref"]: x["dependsOn"] for x in bom["dependencies"]}
    assert d["root"] == ["x"] + top and all(c["bom-ref"] in d for c in comps)
    with pytest.raises(ValueError):
        fb.merge(bom, "root", comps, deps, top)


# ---------- TR-03183-2 ----------

def test_tr03183_coverage():
    comps, deps, top, _ = fb.build(INV, LIST, "rootfs_no_gui", supplier_cfg={"name": "V"})
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": "urn:uuid:1",
           "metadata": {"timestamp": "t", "manufacturer": {"name": "M", "url": ["https://m.example"]},
                        "component": {"bom-ref": "root", "name": "P", "version": "1"}},
           "components": [{"type": "library", "name": "openssl", "version": "3", "purl": "pkg:deb/ubuntu/openssl@3"},
                          {"type": "file", "name": "/etc/passwd"}]}
    fb.merge(bom, "root", comps, deps, top)
    tr = fb.tr03183(bom)
    f = {x["field"]: x for x in tr["fields"]}
    assert tr["status"] == "ATTENTION" and tr["components"] == 2 + len(comps) and tr["file_components_not_counted"] == 1
    assert f["Component creator"]["have"] == 1 and "openssl 3" in f["Component creator"]["missing"]
    # 檔案層級的欄位不算 L4T 邏輯元件
    assert f["Filename of the component"]["total"] == tr["components"] - 1
    assert f["Hash value of the deployable component (SHA-512)"]["have"] == len(comps) - 1
    assert "P 1" in f["Executable property"]["missing"] and "tegra234-p3767.dtb 2026-01-01T00:00:00Z" in f["Executable property"]["missing"]
    assert f["Dependencies on other components"]["missing"] == ["openssl 3"]
    rows = {r["field"]: r["ok"] for r in tr["sbom"]}
    assert rows["Format: CycloneDX 1.6 or higher (JSON)"] and not rows["Completeness of dependencies stated (compositions)"]
    md = fb.tr_text(tr, fb._table)
    assert "**Status: ATTENTION**" in md and "does not block release" in md
    assert fb.tr03183(None)["status"] == "NOT_ASSESSED"


def test_tr03183_all_present_ok():
    c = {"type": "firmware", "bom-ref": "c", "name": "c", "version": "1", "manufacturer": {"name": "x", "contact": [{"email": "a@b"}]},
         "hashes": [{"alg": "SHA-512", "content": H512}], "licenses": [{"license": {"id": "MIT", "acknowledgement": "concluded"}}],
         "properties": [{"name": "bsi:component:filename", "value": "c"}, {"name": "bsi:component:executable", "value": "executable"},
                        {"name": "bsi:component:archive", "value": "no archive"}, {"name": "bsi:component:structured", "value": "unstructured"}]}
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": "s", "compositions": [{"aggregate": "complete"}],
           "metadata": {"timestamp": "t", "manufacturer": {"name": "M", "url": ["u"]}}, "components": [c], "dependencies": [{"ref": "c"}]}
    assert fb.tr03183(bom)["status"] == "OK"
    bom["specVersion"] = "1.5"
    assert fb.tr03183(bom)["gaps"] == ["Format: CycloneDX 1.6 or higher (JSON)"]


def test_check_cli(tmp_path):
    p = tmp_path / "s.json"
    p.write_text(json.dumps(SBOM), encoding="utf-8")
    r = subprocess.run([sys.executable, "-I", str(HERE.parent / "firmware_bom.py"), "check", str(p)], capture_output=True, text=True)
    assert r.returncode == 2 and "BSI TR-03183-2 version 2.1.0" in r.stdout


# ---------- flash_package.py list：清點檔有 sha512、mtime、kernel 模組 ----------

def test_flash_package_inventory_modules(tmp_path):
    a = tmp_path / "pkg.tbz2"
    with tarfile.open(a, "w:bz2") as t:
        for name, data in ((f"{P}/bootloader/mb1.bin", b"fw"),
                           (f"{P}/rootfs_no_gui/etc/nv_tegra_release", b"# R39 (release), REVISION: 2.1, GCID: 1\n"),
                           (f"{P}/rootfs_no_gui/usr/lib/modules/6.8.12-tegra/updates/nv gpu.ko", elf(MODINFO)),
                           (f"{P}/rootfs_no_gui/usr/lib/modules/6.8.12-tegra/updates/b.ko.xz", lzma.compress(elf(b"name=b\0"))),
                           (f"{P}/rootfs_no_gui/usr/lib/modules/6.8.12-tegra/kernel/c.ko", elf(b"name=c\0"))):
            ti = tarfile.TarInfo(name)
            ti.size, ti.mtime = len(data), MTIME
            t.addfile(ti, io.BytesIO(data))
    fp.do_list(str(tmp_path / "list.json"), str(tmp_path / "inv.json"), archive=str(a))
    inv = json.loads((tmp_path / "inv.json").read_text(encoding="utf-8"))
    boot = inv["bootloader"][0]
    assert len(boot["sha512"]) == 128 and boot["mtime"] == MTIME
    mods = inv["kernel_modules"][f"{P}/rootfs_no_gui"]
    assert [m["path"].rsplit("/", 1)[-1] for m in mods] == ["b.ko.xz", "nv gpu.ko"]
    assert mods[0]["modinfo"] == {"name": "b"} and mods[1]["modinfo"]["version"] == "1.2.3" and len(mods[1]["sha512"]) == 128


# ---------- cra_report.py：刷機包的結果資料夾 ----------

def flash_result(tmp_path, inventory=True, cfg=None, sbom=SBOM):
    res = tmp_path / "res"
    scan = make_scan(res / "rootfs_no_gui" / "scan", sbom=sbom)
    write_json(res / "list.json", LIST)
    write_json(res / "rootfs_no_gui" / "rootfs-tar.json", {"prefix": f"{P}/rootfs_no_gui"})
    if inventory:
        write_json(res / "flash-inventory.json", INV)
    proj = make_project(tmp_path / "proj", cfg or dict(MIN_CFG, sbom={"flash_package_supplier": {"name": "Vendor Ltd"}}))
    return proj, scan


def test_cra_report_adds_flash_firmware(tmp_path):
    proj, scan = flash_result(tmp_path)
    r, s, rep = run(proj, scan)
    assert r.returncode in (0, 2), r.stdout + r.stderr
    bom = json.loads((rep / "sbom.cdx.json").read_text(encoding="utf-8"))
    names = {c["name"] for c in bom["components"]}
    assert {"mb1_t234_prod.bin", "NVIDIA Jetson Linux", "nvgpu", "MCU_FW_v1.2.zip"} <= names
    for c in bom["components"]:
        if str(c.get("bom-ref", "")).startswith(fb.REF) and c["name"] != "NVIDIA Jetson Linux":
            assert any(h["alg"] == "SHA-256" for h in c["hashes"]) and c["supplier"]["name"] == "Vendor Ltd"
    root = bom["metadata"]["component"]["bom-ref"]
    assert fb.REF + "l4t" in next(d["dependsOn"] for d in bom["dependencies"] if d["ref"] == root)
    pf = s["product_sbom"]
    assert pf["flash_firmware"]["components"] == 9 and pf["tr03183"]["status"] == "ATTENTION"
    md = (rep / "sbom.md").read_text(encoding="utf-8")
    assert "**9 components**" in md and "Vendor Ltd" in md and "BSI TR-03183-2 version 2.1.0" in md
    # TR-03183 的 ATTENTION 只回報：sbom 文件狀態不受影響（這個合成掃描沒有 sbomgate 以外的問題 → 與沒有韌體時相同）
    proj0, scan0 = make_project(tmp_path / "p0", MIN_CFG), make_scan(tmp_path / "s0")
    assert s["documents"]["sbom"]["status"] == run(proj0, scan0)[1]["documents"]["sbom"]["status"]
    # 重跑（同樣的輸入）→ 同樣的產品 SBOM 序號與元件
    bom1 = bom
    run(proj, scan)
    bom2 = json.loads((rep / "sbom.cdx.json").read_text(encoding="utf-8"))
    assert bom2["serialNumber"] == bom1["serialNumber"] and bom2["components"] == bom1["components"]


def test_cra_report_flash_without_inventory(tmp_path):
    proj, scan = flash_result(tmp_path, inventory=False)
    r, s, rep = run(proj, scan)
    assert (rep / "sbom.cdx.json").exists()
    md = (rep / "sbom.md").read_text(encoding="utf-8")
    assert "Flash firmware missing from the SBOM" in md
    assert s["product_sbom"]["flash_firmware"]["status"] == "ATTENTION"


def test_cra_report_not_flash_unchanged(tmp_path):
    proj, scan = make_project(tmp_path / "proj", MIN_CFG), make_scan(tmp_path / "scan")
    r, s, rep = run(proj, scan)
    bom = json.loads((rep / "sbom.cdx.json").read_text(encoding="utf-8"))
    assert not any(str(c.get("bom-ref", "")).startswith(fb.REF) for c in bom["components"])
    assert "Not a flash package scan" in (rep / "sbom.md").read_text(encoding="utf-8")


def test_cra_report_old_project_template_warns(tmp_path):
    proj, scan = flash_result(tmp_path)
    (proj / "CRA" / "templates").mkdir(parents=True)
    (proj / "CRA" / "templates" / "sbom.md").write_text("# SBOM {{ bom.status }}\n", encoding="utf-8")
    r, s, rep = run(proj, scan)
    assert any("text.sbom_firmware" in w for w in s["config_warnings"])


def test_explicit_flash_inventory_option(tmp_path):
    proj, scan = make_project(tmp_path / "proj", MIN_CFG), make_scan(tmp_path / "x" / "rootfs_no_gui" / "scan")
    d = tmp_path / "elsewhere"
    write_json(d / "flash-inventory.json", INV)
    write_json(d / "list.json", LIST)
    r, s, rep = run(proj, scan, "--flash-inventory", str(d / "flash-inventory.json"))
    assert s["product_sbom"]["flash_firmware"]["components"] == 9, r.stdout + r.stderr
    r, _, _ = run(proj, scan, "--flash-inventory", str(d / "nope.json"))
    assert r.returncode == 64


# ---------- 不可信的清點檔：怪異的格式不讓整份文件失敗，也不把非字串寫進 SBOM ----------

@pytest.mark.parametrize("inv,lst", [
    ({"bootloader": {"a": 1}}, LIST), ({"bootloader": "x", "outside_rootfs": 5}, LIST), ({"other_deliverables": 5}, LIST),
    ({"other_deliverables": [{"name": 5, "type": "file", "sha256": H256}]}, LIST), ({"kernel_modules": {f"{P}/rootfs_no_gui": 3}}, LIST),
    ({"kernel_modules": [1]}, LIST), (INV, {"rootfs": 3}), (INV, {"rootfs": [{"variant": "rootfs_no_gui", "l4t": "R36"}]}),
    (INV, {"rootfs": [{"variant": "rootfs_no_gui", "prefix": ["x"], "l4t": {"release": 36, "sources": [1]}}]}), ("x", ["y"]),
    ({"bootloader": [{"path": ["a"], "type": "file"}, {"path": "a/bootloader/b.bin", "type": "file", "sha256": 5, "mtime": "x"}]}, LIST),
])
def test_build_malformed_shapes(inv, lst):
    comps, deps, top, info = fb.build(inv, lst, "rootfs_no_gui")
    for c in comps:
        assert all(isinstance(c.get(k), str) for k in ("name", "bom-ref")) and isinstance(c.get("version", ""), str)
    fb.tr03183({"components": comps, "dependencies": [{"ref": ["x"]}], "metadata": []})


def test_build_non_string_modinfo_and_l4t():
    inv = {"kernel_modules": {f"{P}/rootfs_no_gui": [item("usr/lib/modules/v/updates/m.ko", modinfo={"name": ["x"], "version": 3,
                                                                                                     "license": {"a": 1}})]}}
    lst = {"rootfs": [{"variant": "rootfs_no_gui", "prefix": f"{P}/rootfs_no_gui", "l4t": {"release": 36}}]}
    comps, _, _, info = fb.build(inv, lst, "rootfs_no_gui")
    m = by_name(comps)["m"]
    assert m["version"] == "2026-01-01T00:00:00Z" and "licenses" not in m and "NVIDIA Jetson Linux" not in by_name(comps)


def test_tr03183_malformed_sbom():
    tr = fb.tr03183({"components": [{"name": "a", "components": 5, "bom-ref": ["x"], "hashes": 3, "licenses": "x", "properties": 1,
                                     "externalReferences": 2, "manufacturer": {"url": 5, "contact": "x"}}],
                     "dependencies": [{"ref": ["x"]}, 5], "compositions": 4, "metadata": {"manufacturer": []}})
    assert tr["status"] == "ATTENTION" and tr["components"] == 1


def test_build_older_cyclonedx_spec():
    comps, _, _, _ = fb.build(INV, LIST, "rootfs_no_gui", spec="1.4")
    n = by_name(comps)
    assert n["NVIDIA Jetson Linux"]["type"] == "operating-system" and "manufacturer" not in n["NVIDIA Jetson Linux"]
    assert n["NVIDIA Jetson Linux"]["publisher"] == "NVIDIA Corporation"
    assert n["nvgpu"]["type"] == "library" and n["nvgpu"]["licenses"] == [{"license": {"name": "GPL v2"}}]
    comps, _, _, _ = fb.build(INV, LIST, "rootfs_no_gui", spec="1.5")
    assert by_name(comps)["NVIDIA Jetson Linux"]["type"] == "platform" and by_name(comps)["nvgpu"]["type"] == "device-driver"


def test_flash_package_module_links(tmp_path):
    a = tmp_path / "pkg.tar"
    d = f"{P}/rootfs_no_gui/usr/lib/modules/6.8.12-tegra/updates"
    with tarfile.open(a, "w") as t:
        data = elf(MODINFO)
        ti = tarfile.TarInfo(f"{d}/a.ko")
        ti.size = len(data)
        t.addfile(ti, io.BytesIO(data))
        out = f"{P}/rootfs_no_gui/usr/lib/modules/6.8.12-tegra/kernel/o.ko"         # updates/ 以外的檔案
        ti = tarfile.TarInfo(out)
        od = elf(b"name=outside\0version=9\0")
        ti.size = len(od)
        t.addfile(ti, io.BytesIO(od))
        for name, kind, target in ((f"{d}/h.ko", tarfile.LNKTYPE, f"{d}/a.ko"), (f"{d}/s.ko", tarfile.SYMTYPE, "a.ko"),
                                   (f"{d}/x.ko", tarfile.LNKTYPE, out)):
            ti = tarfile.TarInfo(name)
            ti.type, ti.linkname = kind, target
            t.addfile(ti)
    fp.do_list(str(tmp_path / "list.json"), str(tmp_path / "inv.json"), archive=str(a))
    mods = {m["path"].rsplit("/", 1)[-1]: m for m in json.loads((tmp_path / "inv.json").read_text())["kernel_modules"][f"{P}/rootfs_no_gui"]}
    assert mods["h.ko"]["type"] == "hardlink" and mods["h.ko"]["target"].endswith("a.ko") and mods["s.ko"]["type"] == "symlink"
    inv = json.loads((tmp_path / "inv.json").read_text())
    comps, _, _, info = fb.build(inv, LIST, "rootfs_no_gui")
    # 硬連結到 updates/ 以外（x.ko → kernel/o.ko）：第二次讀取補上內容，成為元件；updates/ 裡互相連結的（h.ko → a.ko）不重複
    assert mods["x.ko"]["modinfo"] == {"name": "outside", "version": "9"} and len(mods["x.ko"]["sha512"]) == 128
    assert sorted(c["name"] for c in comps if c["type"] == "device-driver") == ["nvgpu", "outside"]
    assert info["skipped"] == {"hard link (content recorded under another path)": 1, "symbolic link or other non-file entry": 1}


def test_rescan_old_inventory_stable(tmp_path):
    """舊的清點檔（沒有 kernel_modules、sha512）：照用、註明，重跑序號相同。"""
    old = {"bootloader": [item(f"{P}/bootloader/mb1.bin", sha512=False)], "outside_rootfs": [], "other_deliverables": None}
    proj, scan = flash_result(tmp_path)
    write_json(scan.parent.parent / "flash-inventory.json", old)
    _, s1, rep = run(proj, scan)
    _, s2, _ = run(proj, scan)
    assert s1["product_sbom"]["serial"] == s2["product_sbom"]["serial"]
    md = (rep / "sbom.md").read_text(encoding="utf-8")
    assert "no kernel module list" in md and "no SHA-512" in md


def test_unrelated_list_json_not_flash(tmp_path):
    proj = make_project(tmp_path / "proj", MIN_CFG)
    scan = make_scan(tmp_path / "res" / "x" / "scan")
    write_json(tmp_path / "res" / "list.json", [1, 2])
    _, s, _ = run(proj, scan)
    assert s["product_sbom"]["flash_firmware"]["flash_package"] is False


def test_corrupt_inventory_does_not_fail_report(tmp_path):
    proj, scan = flash_result(tmp_path)
    (scan.parent.parent / "flash-inventory.json").write_text("{not json", encoding="utf-8")
    r, s, rep = run(proj, scan)
    assert r.returncode in (0, 2) and s["product_sbom"]["flash_firmware"]["status"] == "ATTENTION"


def test_xz_memory_limit(monkeypatch):
    monkeypatch.setattr(fb, "LZMA_MEMLIMIT", 1 << 16)
    r = fb.module_info(lzma.compress(elf(MODINFO)), "big.ko.xz")
    assert r["modinfo"] is None and "cannot decompress" in r["modinfo_note"]


def test_product_sbom_valid_cyclonedx_1_6(tmp_path):
    """刷機包掃描的產品 SBOM 整份通過 CycloneDX 1.6 schema（含模組的 license.acknowledgement）。"""
    sbom = json.loads(json.dumps(SBOM))       # Syft 的 tools 有 type（共用的假 SBOM 省略了）
    sbom["metadata"]["tools"]["components"][0]["type"] = "application"
    proj, scan = flash_result(tmp_path, sbom=sbom)
    run(proj, scan)
    bom = json.loads((proj / "CRA" / "Reports" / "sbom.cdx.json").read_text(encoding="utf-8"))
    errs = sorted(cdx_validator().iter_errors(bom), key=lambda e: list(e.path))
    assert not errs, [f"{list(e.path)}: {e.message[:200]}" for e in errs[:5]]
    v = cdx_validator()
    bad = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
        {"type": "library", "name": "x", "licenses": [{"license": {"name": "GPL"}, "acknowledgement": "declared"}]}]}
    assert list(v.iter_errors(bad)), "舊的錯誤形狀應該被拒收"


def test_unreadable_and_unwalked_make_attention(tmp_path):
    """讀不到雜湊而略過的韌體、清點時讀不到的檔案、沒走進去的資料夾 → notes，flash_firmware 狀態 ATTENTION。"""
    inv = {"bootloader": [item(f"{P}/bootloader/mb1.bin"), {"path": f"{P}/bootloader/mb2.bin", "type": "file", "size": 1, "error": "讀不到"}],
           "kernel_modules": {}, "other_deliverables": []}
    lst = dict(LIST, flash_package={"outside_rootfs_unreadable": 2, "outside_rootfs_unreadable_examples": [f"{P}/bootloader/x.bin"],
                                    "outside_rootfs_dirs_not_walked": 1})
    comps, _, _, info = fb.build(inv, lst, "rootfs_no_gui")
    text = " ".join(info["notes"])
    assert "1 flash file(s) could not be read" in text and "2 file(s) outside the root file system could not be read" in text
    assert f"{P}/bootloader/x.bin" in text and "1 folder(s) outside the root file system were deeper" in text
    proj, scan = flash_result(tmp_path)
    write_json(scan.parent.parent / "flash-inventory.json", inv)
    write_json(scan.parent.parent / "list.json", lst)
    _, s, rep = run(proj, scan)
    assert s["product_sbom"]["flash_firmware"]["status"] == "ATTENTION"
    assert "could not be read" in (rep / "sbom.md").read_text(encoding="utf-8")
