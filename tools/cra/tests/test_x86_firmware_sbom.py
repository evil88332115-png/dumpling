"""x86_firmware.py 的 SBOM 補充：漏洞比對狀態（NOT_ASSESSED）、版本狀態（OK／GAP）、Intel CSME 的 CPE，以及
pipeline/firmware-bios.sh 的狀態行與退出碼。全部用 test_x86_firmware.py 的假資料（不含任何產品映像）。"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import x86_firmware as xf  # noqa: E402
from cdx_schema import cdx_validator  # noqa: E402
from test_x86_firmware import MANIFEST, csme12_image, me_region, option_image, spi_image, vbios_rom, with_me  # noqa: E402

REPO = HERE.parents[2]
SCRIPT = REPO / "pipeline" / "firmware-bios.sh"

INTEL_NOTE = xf.ASSESS_NOTES["intel"]
UCODE_NOTE = xf.ASSESS_NOTES["intel-microcode"]
NVIDIA_NOTE = xf.ASSESS_NOTES["nvidia-vbios"]
CSME_CPE_16 = "cpe:2.3:o:intel:converged_security_management_engine_firmware:16.1.30:*:*:*:*:*:*:*"        # 16.1.30.2307 的前三段（NVD 沒有 build 號）


def props(c, name):
    return [p["value"] for p in c["properties"] if p["name"] == name]


def sbom(tmp_path, data, manifest=None):
    p = tmp_path / "in.bin"
    p.write_bytes(data)
    comps, deps = xf.components(xf.inventory([p], manifest))
    doc = xf.bom(comps, deps)
    assert not list(cdx_validator().iter_errors(doc))
    return comps


def manifest_with(tmp_path, *rows):
    m = tmp_path / "m.csv"
    m.write_text(MANIFEST.splitlines()[0] + "\n" + "\n".join(rows) + "\n", encoding="utf-8")
    return m


# ---------- 漏洞比對狀態 ----------

def test_every_component_is_not_assessed_with_a_reason(tmp_path):
    comps = sbom(tmp_path, spi_image() + vbios_rom(0x2489, "94.04.5E.00.92"))
    assert len(comps) >= 8
    for c in comps:
        assert props(c, "dumpling:vuln-assessment") == ["NOT_ASSESSED"], c["name"]
        assert len(props(c, "dumpling:vuln-assessment-note")) == 1, c["name"]
        assert props(c, "dumpling:version-status") in (["OK"], ["GAP"]), c["name"]
    by = {c["name"]: c for c in comps}
    assert props(by["Intel CSE firmware"], "dumpling:vuln-assessment-note") == [INTEL_NOTE]
    for c in comps:
        if c["name"].startswith("Intel CPU microcode"):
            assert props(c, "dumpling:vuln-assessment-note") == [UCODE_NOTE]          # 微碼：候選公告在 dumpling:advisory-*，狀態仍是 NOT_ASSESSED
    vb = next(c for c in comps if c["name"].startswith("NVIDIA VBIOS"))
    assert props(vb, "dumpling:vuln-assessment-note") == [NVIDIA_NOTE]
    # BIOS 映像與非 ME 的區域：這一層沒有漏洞比對，也不套用 Intel 的說明
    for name in ("in.bin", "descriptor region", "bios region"):
        assert props(by[name], "dumpling:vuln-assessment-note") == [xf.ASSESS_NOTES["image"]]


def test_nothing_says_assessed_or_secure(tmp_path):
    comps = sbom(tmp_path, spi_image())
    text = json.dumps(comps).lower()
    assert "not_assessed" in text and "pass" not in text and "secure" not in text


# ---------- 版本狀態 ----------

def test_version_status_ok_when_read_gap_when_omitted(tmp_path):
    comps = sbom(tmp_path, spi_image() + vbios_rom(0x2489, "94.04.5E.00.92"))
    by = {c["name"]: c for c in comps}
    for name in ("Intel CSE firmware", "Intel CPU microcode 000B06A2", "Intel CPU microcode 000B0671"):
        assert props(by[name], "dumpling:version-status") == ["OK"] and by[name]["version"]
    vb = next(c for c in comps if c["name"].startswith("NVIDIA VBIOS"))
    assert vb["version"] == "94.04.5E.00.92" and props(vb, "dumpling:version-status") == ["OK"]
    # 沒有版本清單：BIOS 映像和區域都沒有版本 → 省略 version（不留空字串、不猜），標 GAP
    for name in ("in.bin", "descriptor region", "bios region"):
        assert "version" not in by[name] and props(by[name], "dumpling:version-status") == ["GAP"]


def test_declared_bios_version_makes_status_ok(tmp_path):
    m = manifest_with(tmp_path, "MB-1,BIOS,1.05,bios,,1.05,,,")
    c = next(c for c in sbom(tmp_path, spi_image(), m) if c["name"] == "in.bin")
    assert c["version"] == "1.05" and props(c, "dumpling:version-status") == ["OK"]


def test_vbios_without_version_has_no_version_and_gap(tmp_path):
    rom = option_image(0x10DE, 0x2489, 2, 0, False) + option_image(0x10DE, 0x2489, 1, 3, True)    # 沒有 XX.XX.XX.XX.XX 字串
    vb = next(c for c in sbom(tmp_path, rom) if c["name"].startswith("NVIDIA VBIOS"))
    assert "version" not in vb and props(vb, "dumpling:version-status") == ["GAP"]
    assert props(vb, "dumpling:vuln-assessment") == ["NOT_ASSESSED"]


def test_me_region_without_manifest_is_gap_and_has_no_cpe(tmp_path):
    img = bytearray(spi_image())
    img[0x1000:0x7000] = b"\xff" * 0x6000                       # ME 區域在、裡面沒有任何 manifest
    me = next(c for c in sbom(tmp_path, bytes(img)) if c["name"] == "me region")
    assert "version" not in me and "cpe" not in me
    assert props(me, "dumpling:version-status") == ["GAP"] and props(me, "dumpling:vuln-assessment-note") == [INTEL_NOTE]


# ---------- CPE ----------

def test_cpe_family_rules_and_basis(tmp_path):
    img = with_me(me_region("me11"))
    # 版本清單沒有、映像分不出 family：major 16 ≥ 11，推定為 CSME（NVD 的 part o 只有 CSME 有 11 以上的版本），推定寫在 basis
    me = next(c for c in sbom(tmp_path, img) if c["name"] == "Intel CSE firmware")
    assert me["version"] == "16.1.30.2307" and me["cpe"] == CSME_CPE_16
    assert props(me, "dumpling:cpe-basis") == ["inferred"]                                                                   # 值固定是 listed／inferred
    note = props(me, "dumpling:cpe-basis-note")[0]
    assert "inferred from the version" in note and "major 16 is in 11..30" in note and "dropped" in note and "needs human review" in note
    assert "TXE" in note and "SPS" in note and "below 11" in note and "AMT" in note and "different product" in note     # NVD 上的依據照實寫
    assert "temporary Dependency-Track" in props(me, "dumpling:cpe-note")[0]
    assert props(me, "dumpling:cpe-note") == [xf.CPE_NOTE] and not props(me, "dumpling:cpe-gap")
    # 清單寫 TXE：不同的 product → 不帶 CPE，寫 gap
    m = manifest_with(tmp_path, "MB-1,BIOS,1.05,me,TXE,16.1.30.2307,,Intel,")
    me = next(c for c in sbom(tmp_path, img, m) if c["name"] == "Intel CSE firmware")
    assert "cpe" not in me and "TXE" in props(me, "dumpling:cpe-gap")[0] and not props(me, "dumpling:cpe-basis") and not props(me, "dumpling:cpe-basis-note")
    # 清單寫 CSME：照清單
    m = manifest_with(tmp_path, "MB-1,BIOS,1.05,me,CSME,16.1.30.2307,,Intel,")
    me = next(c for c in sbom(tmp_path, img, m) if c["name"] == "Intel CSE firmware")
    assert me["cpe"] == CSME_CPE_16 and props(me, "dumpling:cpe-basis") == ["listed"]
    assert props(me, "dumpling:cpe-basis-note")[0].startswith("family CSME is declared in the version list") and "inferred" not in props(me, "dumpling:cpe-basis-note")[0]
    assert all("cpe" not in c for c in sbom(tmp_path, img, m) if c is not me and not c["name"].startswith("Intel CSE"))
    assert props(me, "dumpling:advisory-match") == ["NOT_ASSESSED"] and "no data in the database" in props(me, "dumpling:advisory-basis")[0]


def test_csme_major_bounds_for_the_inferred_family():
    assert xf.csme_cpe({"family": None, "version": "11.0.0.1"}) and xf.csme_cpe({"family": None, "version": "30.9.9"})
    assert xf.csme_cpe({"family": None, "version": "10.9.9"}) is None and xf.csme_cpe({"family": None, "version": "31.0.0"}) is None
    assert "above 30" in xf.csme_cpe_info({"family": None, "version": "31.0.0"})[2] and "< 11" in xf.csme_cpe_info({"family": None, "version": "10.0.0"})[2]
    assert xf.csme_cpe({"family": "CSME", "version": "31.0.0"})                        # 版本清單明寫 CSME：照清單，不看上限


def test_cpe_for_standalone_me_image_without_region(tmp_path):
    m = manifest_with(tmp_path, "MB-1,ME,12.0.90,me,CSME,12.0.90.2072,,Intel,")
    me = next(c for c in sbom(tmp_path, csme12_image(), m) if c["name"] == "Intel CSE firmware")
    assert me["cpe"].endswith("converged_security_management_engine_firmware:12.0.90:*:*:*:*:*:*:*")
    assert props(me, "dumpling:vuln-assessment") == ["NOT_ASSESSED"]


@pytest.mark.parametrize("version,cpe_version", [("16.1.30.2307", "16.1.30"), ("14.0.47.1558", "14.0.47"), ("11.8.50", "11.8.50"),
                                                   ("11.8.50.3425", "11.8.50"), ("011.08.050.1", "11.8.50")])
def test_csme_cpe_format_drops_the_build_number(version, cpe_version):
    for fam in ("CSME", None):                       # 清單寫 CSME，或映像分不出 family 但 major ≥ 11
        assert xf.csme_cpe({"family": fam, "version": version}) == \
            f"cpe:2.3:o:intel:converged_security_management_engine_firmware:{cpe_version}:*:*:*:*:*:*:*"


@pytest.mark.parametrize("me", [None, {"family": None, "version": "10.0.55.1000"}, {"family": None, "version": "4.0.10.1"},
                                {"family": "TXE", "version": "4.0.10.1"}, {"family": "SPS", "version": "5.0.4.12"},
                                {"family": "ME", "version": "16.1.30.2307"}, {"family": "TXE", "version": "16.1.30.2307"},
                                {"family": "CSME", "version": ""}, {"family": "CSME", "version": "16.1:30"},
                                {"family": "CSME", "version": "unknown"}, {"family": "CSME", "version": "16.1.30.2307:*"},
                                {"family": "CSME", "version": "16.1"}, {"family": None, "version": "16"},
                                {"family": "CSME", "version": "16.1.30.2307.5"}, {"family": "CSME", "version": "-16.1.30"},
                                {"family": None, "version": "31.0.0.1"}, {"family": None, "version": "258.32888.0.16720"}])
def test_csme_cpe_not_filled_when_unsure(me):
    assert xf.csme_cpe(me) is None
    cpe, basis, gap = xf.csme_cpe_info(me)
    assert cpe is None and basis is None and (gap is None) == (me is None)         # 沒有 ME 以外，都要寫沒有 CPE 的原因（GAP）
    assert (xf.cpe_props(me) == []) == (me is None)


def test_microcode_and_vbios_have_no_invented_cpe_or_purl(tmp_path):
    for c in sbom(tmp_path, spi_image() + vbios_rom(0x2489, "94.04.5E.00.92")):
        if c["name"] != "Intel CSE firmware":
            assert "cpe" not in c and "purl" not in c, c["name"]


# ---------- pipeline/firmware-bios.sh ----------

def run_pipeline(*args):
    return subprocess.run(["bash", str(SCRIPT), *map(str, args)], capture_output=True, text=True, timeout=120)


def status_line(r):
    lines = r.stdout.splitlines()
    assert len(lines) == 1, r.stdout + r.stderr
    tag, status, detail = lines[0].split("\t", 2)
    assert tag == "FIRMWARE-BIOS" and detail
    return status


def test_pipeline_attention_without_manifest_and_writes_sbom(tmp_path):
    (tmp_path / "in").mkdir()
    (tmp_path / "in" / "BIOS.bin").write_bytes(spi_image())
    r = run_pipeline(tmp_path / "in", "--out", tmp_path / "out")
    assert status_line(r) == "ATTENTION" and r.returncode == 2       # 沒有版本清單、沒有 flash descriptor 以外的核對
    assert "沒有版本清單" in r.stdout
    doc = json.loads((tmp_path / "out" / "fw.cdx.json").read_text(encoding="utf-8"))
    assert doc["specVersion"] == "1.6" and not list(cdx_validator().iter_errors(doc))
    assert (tmp_path / "out" / "fw-inventory.json").exists()
    assert "PASS" not in r.stdout and "安全" not in r.stdout


def test_pipeline_options_in_any_order_and_manifest(tmp_path):
    f = tmp_path / "BIOS.bin"
    f.write_bytes(spi_image())
    m = manifest_with(tmp_path, "MB-1,BIOS,1.05,me,CSME,16.1.30.2307,,Intel,")
    r = run_pipeline("--out", tmp_path / "out", "--manifest", m, f)
    assert status_line(r) in ("ATTENTION", "OK")
    doc = json.loads((tmp_path / "out" / "fw.cdx.json").read_text(encoding="utf-8"))
    assert any(c.get("cpe") == CSME_CPE_16 for c in doc["components"])


def test_pipeline_multiple_inputs_vbios(tmp_path):
    a, b = tmp_path / "a.rom", tmp_path / "b.rom"
    a.write_bytes(vbios_rom(0x2489, "94.04.5E.00.92"))
    b.write_bytes(vbios_rom(0x2504, "94.06.2F.00.01"))
    r = run_pipeline(a, b, "--out", tmp_path / "out")
    assert status_line(r) in ("ATTENTION", "OK") and "vBIOS 2 個" in r.stdout
    doc = json.loads((tmp_path / "out" / "fw.cdx.json").read_text(encoding="utf-8"))
    assert len([c for c in doc["components"] if c["name"].startswith("NVIDIA VBIOS")]) == 2


def test_pipeline_gap_when_nothing_found(tmp_path):
    (tmp_path / "in").mkdir()
    (tmp_path / "in" / "readme.txt").write_text("nothing", encoding="utf-8")
    r = run_pipeline(tmp_path / "in", "--out", tmp_path / "out")
    assert status_line(r) == "GAP" and r.returncode == 2


def test_pipeline_fail_on_missing_input_and_removes_old_outputs(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    (out / "fw.cdx.json").write_text("{}", encoding="utf-8")
    r = run_pipeline(tmp_path / "nope.bin", "--out", out)
    assert status_line(r) == "FAIL" and r.returncode == 1
    assert not (out / "fw.cdx.json").exists()


def test_pipeline_fail_on_bad_manifest(tmp_path):
    f = tmp_path / "BIOS.bin"
    f.write_bytes(spi_image())
    r = run_pipeline(f, "--out", tmp_path / "out", "--manifest", tmp_path / "nope.csv")
    assert status_line(r) == "FAIL" and r.returncode == 1


@pytest.mark.parametrize("args", [(), ("--out", "x"), ("in.bin",), ("in.bin", "--out"), ("in.bin", "--manifest"), ("in.bin", "--out", "x", "--bogus")])
def test_pipeline_argument_errors_are_fail_64(tmp_path, args):
    r = run_pipeline(*args)
    assert status_line(r) == "FAIL" and r.returncode == 64
