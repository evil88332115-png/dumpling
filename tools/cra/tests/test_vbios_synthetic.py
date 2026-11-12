"""合成 NVIDIA option ROM（synthetic_vbios.py）：結構正確，而且整條流程
（合成 ROM → pipeline/firmware-bios.sh → x86_firmware.py → CycloneDX）讀得出版本與雜湊、標 NOT_ASSESSED、通過 schema。
合成 ROM 不是任何真實產品的 vBIOS，檔名與內容都有 SYNTHETIC 字樣。"""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import synthetic_vbios as sv  # noqa: E402
import x86_firmware as xf  # noqa: E402
from cdx_schema import cdx_validator  # noqa: E402

REPO = HERE.parents[2]
SCRIPT = REPO / "pipeline" / "firmware-bios.sh"
GENERATOR = HERE / "synthetic_vbios.py"
NAME = "synthetic-nvidia-option-rom.rom"


def props(c, name):
    return [p["value"] for p in c["properties"] if p["name"] == name]


def test_rom_structure_matches_what_the_parser_reads():
    rom = sv.synthetic_rom()
    assert len(rom) == 2 * sv.IMAGE_SIZE
    [r] = xf.option_roms(rom)
    assert r["vendor"] == "10de" and r["device"] == "fffe" and r["class"] == "030000"
    assert [i["code_type"] for i in r["images"]] == [0, 3]                    # legacy x86 + EFI
    assert [i["length_basis"] for i in r["images"]] == ["NPDE", "NPDE"]        # NPDE 有被採用
    assert r["terminated"] == "last-flag" and r["length"] == len(rom)
    assert r["version"] == sv.DEFAULT_VERSION
    assert xf.is_vbios(r)
    assert r["sha256"] == hashlib.sha256(rom).hexdigest()


def test_legacy_image_checksum_is_zero_and_efi_header_fields():
    rom = sv.synthetic_rom()
    assert sum(rom[:sv.IMAGE_SIZE]) % 256 == 0                                 # legacy option ROM 的 checksum 規則
    efi = rom[sv.IMAGE_SIZE:]
    assert efi[:2] == b"\x55\xaa" and efi[4:8] == b"\xf1\x0e\x00\x00" and efi[0x0A:0x0C] == b"\x64\x86"
    assert b"SYNTHETIC" in rom[:sv.IMAGE_SIZE] and b"SYNTHETIC" in efi          # 內容明說是合成的
    assert b"MZ" not in rom                                                    # 沒有 PE／可執行內容


def test_options_and_validation():
    only_legacy = sv.synthetic_rom("12.34.56.78.9A", 0x1234, efi=False)
    [r] = xf.option_roms(only_legacy)
    assert r["version"] == "12.34.56.78.9A" and r["device"] == "1234" and [i["code_type"] for i in r["images"]] == [0]
    assert r["terminated"] == "last-flag"
    for bad in ("1.2.3.4.5", "00.00.00.00.0g", "00-00-00-00-01", "00.00.00.00.01.", "aa.00.00.00.01"):
        with pytest.raises(ValueError):
            sv.synthetic_rom(bad)
    with pytest.raises(ValueError):
        sv.synthetic_rom(device=0x10000)
    assert sv.synthetic_rom() == sv.synthetic_rom()                            # 決定性：同樣的參數同樣的位元組


def test_generator_cli(tmp_path):
    out = tmp_path / NAME
    r = subprocess.run([sys.executable, "-I", str(GENERATOR), "--out", str(out)], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0 and "合成樣本" in r.stdout, r.stdout + r.stderr
    assert out.read_bytes() == sv.synthetic_rom()
    bad = subprocess.run([sys.executable, "-I", str(GENERATOR), "--out", str(tmp_path / "x.rom"), "--version", "bad"],
                         capture_output=True, text=True, timeout=60)
    assert bad.returncode == 64 and not (tmp_path / "x.rom").exists()
    link = tmp_path / "link.rom"
    link.symlink_to(tmp_path / "target.rom")
    r = subprocess.run([sys.executable, "-I", str(GENERATOR), "--out", str(link)], capture_output=True, text=True, timeout=60)
    assert r.returncode == 1 and not (tmp_path / "target.rom").exists()        # 不跟隨 symlink 寫檔


def test_pipeline_end_to_end_synthetic_rom_to_valid_cyclonedx(tmp_path):
    rom_file = tmp_path / "in" / NAME
    rom_file.parent.mkdir()
    rom_file.write_bytes(sv.synthetic_rom("0A.1B.2C.3D.4E"))
    out = tmp_path / "out"
    r = subprocess.run(["bash", str(SCRIPT), str(rom_file), "--out", str(out)], capture_output=True, text=True, timeout=120)
    # 沒有版本清單可核對 → ATTENTION（退出碼 2）；不是整體 PASS，也不是「安全」
    assert r.returncode == 2 and r.stdout.startswith("FIRMWARE-BIOS\tATTENTION\t"), r.stdout + r.stderr
    assert "vBIOS 1 個" in r.stdout and "PASS" not in r.stdout and "安全" not in r.stdout
    doc = json.loads((out / "fw.cdx.json").read_text(encoding="utf-8"))
    assert not list(cdx_validator().iter_errors(doc))
    [c] = doc["components"]
    assert c["name"] == "NVIDIA VBIOS fffe" and c["version"] == "0A.1B.2C.3D.4E"
    rom = rom_file.read_bytes()
    assert {h["alg"]: h["content"] for h in c["hashes"]} == {"SHA-256": hashlib.sha256(rom).hexdigest(),
                                                              "SHA-512": hashlib.sha512(rom).hexdigest()}
    assert props(c, "dumpling:vuln-assessment") == ["NOT_ASSESSED"]
    assert props(c, "dumpling:vuln-assessment-note") == [xf.ASSESS_NOTES["nvidia-vbios"]]
    assert props(c, "dumpling:version-status") == ["OK"]
    assert props(c, "sca-center:rom-images") == ["x86, EFI"]
    # 看得出是合成的：輸入檔名（bsi:component:filename 與 found-in）
    assert props(c, "bsi:component:filename") == [NAME]
    assert all(NAME in v for v in props(c, "sca-center:found-in")) and "synthetic" in NAME
    assert not {"sca-center:incomplete", "sca-center:rom-terminated"} & {p["name"] for p in c["properties"]}
    inv = json.loads((out / "fw-inventory.json").read_text(encoding="utf-8"))
    assert inv["vbios"][0]["version"] == "0A.1B.2C.3D.4E" and inv["status"] == "ATTENTION"
