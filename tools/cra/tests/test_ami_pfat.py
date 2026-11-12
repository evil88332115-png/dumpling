"""ami_pfat.py（AMI BIOS Guard／PFAT 解封裝）與 x86_firmware.py 的 PFAT hook。

封裝全部由測試自己組（結構依 ami_pfat.py 檔頭的說明），不含任何真實映像。
測試涵蓋：多 block／多檔案組回、flash 順序索引、簽章區長度（2048／3072／推算）、缺 block、截斷（每個長度）、超大宣告長度、
header 欄位矛盾、巢狀深度，以及經 x86_firmware 產出的 inventory／SBOM（通過 CycloneDX schema）。"""
import json
import struct
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import ami_pfat as ap  # noqa: E402
import x86_firmware as xf  # noqa: E402
from cdx_schema import cdx_validator  # noqa: E402
from test_x86_firmware import spi_image  # noqa: E402

TOOL = HERE.parent / "x86_firmware.py"


# ---------- 組假 PFAT ----------

OPS_BEGIN = b"\x01" + b"\x00" * 7
OPS_END = b"\xff" + b"\x00" * 7


def signature(kind=1):
    """簽章區：8 位元組標頭（第 1 個 u32＝kind）＋ RSA 結構（kind 1＝2048；2、3＝3072；其他由呼叫端指定長度）。"""
    rsa = {1: 256 + 4 + 256, 2: 384 + 4 + 384, 3: 384 + 4 + 384}[kind]
    return struct.pack("<II", kind, 1) + b"\xa5" * rsa


def block(data, script=OPS_BEGIN + b"\x02" + b"\x00" * 7 + OPS_END, sfam=True, plat=b"TIGERLAKE", ver=(2, 0), sig=None,
          script_size=None, data_size=None):
    bg = struct.pack("<HH16sIHHIIIII", ver[0], ver[1], plat.ljust(16, b"\x00"), 1 if sfam else 0, 2, 0,
                     len(script) if script_size is None else script_size, len(data) if data_size is None else data_size, 0x5000, 1, 0)
    assert len(bg) == ap.BG_HDR_LEN
    return bg + script + data + ((sig if sig is not None else signature(1)) if sfam else b"")


def header_text(files, order=None):
    title = "AMI_BIOS_GUARD_FLASH_CONFIGURATIONS" + ("II" + "".join(f"{i:04X}" for i in order) if order else "")
    return "\r\n".join([title] + [f"1 /{n.upper()} {c} ;{n}" for n, c in files]) + "\r\n"


def pfat(files, order=None, trailing=b"", sfam=True, sig=None, counts=None, pre=b"", plat=b"TIGERLAKE"):
    """files: [(name, [block 資料, …])]。counts：覆蓋標頭宣告的 block 數（測試矛盾用）。"""
    decl = [(n, (counts[i] if counts else len(bs))) for i, (n, bs) in enumerate(files)]
    text = header_text(decl, order).encode()
    size = ap.HDR_LEN + len(text)
    head = struct.pack("<II", size, 0xACDE) + ap.TAG + b"c" + text
    body = b"".join(block(d, sfam=sfam, sig=sig, plat=plat) for _, bs in files for d in bs)
    return pre + head + body + trailing


def three_files():
    return [("NVRAM", [b"N" * 100]), ("FV_MAIN", [b"M" * 4096, b"m" * 4096, b"x" * 17]), ("FV_BB", [b"B" * 64, b"b" * 64])]


# ---------- 組回 ----------

def test_blocks_are_reassembled_in_order_with_hashes():
    pf = ap.unwrap(pfat(three_files(), trailing=b"\xff" * 33))
    assert pf["ok"] and pf["error"] is None
    expected = b"N" * 100 + b"M" * 4096 + b"m" * 4096 + b"x" * 17 + b"B" * 64 + b"b" * 64 + b"\xff" * 33
    assert pf["image"] == expected
    assert [f["name"] for f in pf["files"]] == ["NVRAM", "FV_MAIN", "FV_BB"]
    assert [f["blocks"] for f in pf["files"]] == [1, 3, 2] and pf["files"][1]["size"] == 8209
    assert pf["files"][1]["signed_blocks"] == 3
    assert pf["info"]["blocks"] == 6 and pf["info"]["oob_size"] == 33 and pf["info"]["platform_id"] == "TIGERLAKE"
    assert pf["info"]["bg_version"] == "2.0" and pf["info"]["signature_bits"] == [2048]


def test_signature_is_not_verified_and_says_so():
    pf = ap.unwrap(pfat(three_files()))
    assert pf["signature_verified"] is False and ap.SIG_NOTE in pf["notes"] and "未驗證" in ap.SIG_NOTE
    # 簽章內容隨便改也一樣解得開（沒有驗證）
    assert ap.unwrap(pfat(three_files(), sig=signature(1)[:8] + b"\x00" * 516))["ok"]


def test_original_and_reassembled_hashes_differ_and_are_correct():
    import hashlib
    raw = pfat(three_files())
    pf = ap.unwrap(raw)
    assert pf["orig_sha256"] == hashlib.sha256(raw).hexdigest()
    assert pf["image_sha256"] == hashlib.sha256(pf["image"]).hexdigest() != pf["orig_sha256"]


def test_not_pfat_returns_none():
    assert ap.unwrap(b"\xff" * 4096) is None
    assert ap.unwrap(b"_AMIPFAT") is None
    assert ap.unwrap(b"") is None


def test_pfat_after_capsule_prefix_is_found():
    pre = b"\x00" * 0x200
    pf = ap.unwrap(pfat(three_files(), pre=pre))
    assert pf["ok"] and pf["info"]["offset"] == 0x200 and pf["image"].startswith(b"N" * 100)


def test_flash_order_index_reorders_files():
    files = [("A", [b"a" * 8]), ("B", [b"b" * 8]), ("C", [b"c" * 8])]
    pf = ap.unwrap(pfat(files, order=[2, 0, 1]))
    assert pf["ok"] and pf["image"] == b"b" * 8 + b"c" * 8 + b"a" * 8
    assert [f["flash_index"] for f in pf["files"]] == [2, 0, 1]
    pf = ap.unwrap(pfat(files, order=[0, 1, 2]))
    assert pf["image"] == b"a" * 8 + b"b" * 8 + b"c" * 8


def test_unsigned_blocks_have_no_signature_area():
    pf = ap.unwrap(pfat(three_files(), sfam=False))
    assert pf["ok"] and pf["files"][0]["signed_blocks"] == 0 and pf["info"]["signature_bits"] == []


@pytest.mark.parametrize("kind,bits", [(1, 2048), (2, 3072), (3, 3072)])
def test_signature_sizes(kind, bits):
    pf = ap.unwrap(pfat(three_files(), sig=signature(kind)))
    assert pf["ok"] and pf["info"]["signature_bits"] == [bits]


def test_unknown_signature_kind_length_inferred_from_next_header():
    sig = struct.pack("<II", 9, 9) + b"\x5a" * 516          # 標頭值不認得，但長度是 2048 的
    pf = ap.unwrap(pfat([("X", [b"1" * 10, b"2" * 10])], sig=sig))
    assert pf["ok"] and pf["image"] == b"1" * 10 + b"2" * 10
    bad = struct.pack("<II", 9, 9) + b"\x5a" * 100          # 長度不是 2048 也不是 3072 → 錯誤
    pf = ap.unwrap(pfat([("X", [b"1" * 10, b"2" * 10])], sig=bad))
    assert not pf["ok"] and "簽章" in pf["error"]


def test_script_without_begin_end_is_a_note_not_a_failure():
    raw = pfat([("X", [b"1" * 10])])
    # 改掉 script 的 end opcode
    i = raw.index(OPS_END)
    pf = ap.unwrap(raw[:i] + b"\x07" + raw[i + 1:])
    assert pf["ok"] and any("begin／end" in n for n in pf["notes"])


# ---------- 壞輸入：不崩潰、回傳原因 ----------

def test_every_truncation_is_an_error_without_exception():
    raw = pfat(three_files())
    n_ok = 0
    for cut in range(0, len(raw)):
        pf = ap.unwrap(raw[:cut])
        if pf is None:
            continue
        # 截在最後一個 block 之後的尾端資料之內不會發生（沒有尾端）；任何截斷都要是錯誤，除非剛好少一個完整的最後 block 之後
        assert pf["ok"] is False and pf["error"] and pf["image"] is None, cut
        n_ok += 1
    assert n_ok > 100


def test_truncation_error_reasons_are_specific():
    raw = pfat(three_files())
    assert "不夠放 header" in ap.unwrap(raw[:300])["error"]                  # 標頭完整、block 不夠
    assert "標頭長度" in ap.unwrap(raw[:60])["error"]                         # 截在標頭文字中間
    pf = ap.unwrap(raw[:-5])         # 少最後一個簽章區的尾端
    assert not pf["ok"] and "簽章區" in pf["error"]


def test_missing_block_is_an_error():
    pf = ap.unwrap(pfat(three_files(), counts=[1, 4, 2]))     # 宣告 FV_MAIN 4 個 block，實際只有 3 個
    assert not pf["ok"]
    pf = ap.unwrap(pfat([("A", [b"a" * 4])], counts=[3]))
    assert not pf["ok"] and ("截斷" in pf["error"] or "不夠" in pf["error"])


def test_extra_block_is_left_in_trailing_data_not_in_files():
    pf = ap.unwrap(pfat(three_files(), counts=[1, 2, 2]))      # 宣告比實際少：多的 block 變成尾端資料，不混進檔案
    assert pf["ok"] and pf["files"][1]["blocks"] == 2 and pf["info"]["oob_size"] > 0


def test_huge_declared_lengths_are_rejected_without_allocating():
    raw = pfat([("A", [b"a" * 16])])
    # 直接改第一個 block header 的 ScriptSize／DataSize
    off = int.from_bytes(raw[:4], "little")
    for field, pos in (("script", off + 0x1C), ("data", off + 0x20)):
        bad = bytearray(raw)
        struct.pack_into("<I", bad, pos, 0xFFFFFFFF)
        pf = ap.unwrap(bytes(bad))
        assert not pf["ok"] and "超出" in pf["error"], field


def test_huge_header_size_and_block_count():
    raw = bytearray(pfat([("A", [b"a" * 16])]))
    struct.pack_into("<I", raw, 0, 0xFFFFFFF0)
    assert "標頭長度" in ap.unwrap(bytes(raw))["error"]
    struct.pack_into("<I", raw, 0, 5)
    assert "標頭長度" in ap.unwrap(bytes(raw))["error"]
    pf = ap.unwrap(pfat([("A", [b"a" * 16])], counts=[10 ** 9]))
    assert not pf["ok"] and "block 數" in pf["error"]
    pf = ap.unwrap(pfat([("A", [b"a" * 16])], counts=[ap.MAX_BLOCKS]))
    assert not pf["ok"]                                            # 宣告的 block 比檔案放得下的多


def test_too_many_files_declared():
    files = [(f"F{i}", [b"x"]) for i in range(ap.MAX_FILES + 1)]
    pf = ap.unwrap(pfat(files))
    assert not pf["ok"] and "檔案數" in pf["error"]


def test_assembled_size_cap(monkeypatch):
    monkeypatch.setattr(ap, "MAX_IMAGE", 100)
    pf = ap.unwrap(pfat([("A", [b"a" * 60, b"b" * 60])]))
    assert not pf["ok"] and "上限" in pf["error"]


def pfat_with_text(text):
    """標頭文字直接指定（測文字內容矛盾）；後面接一個正常的 block。"""
    head = struct.pack("<II", ap.HDR_LEN + len(text), 0) + ap.TAG + b"c" + text
    return head + block(b"n" * 8)


@pytest.mark.parametrize("text,why", [
    (b"AMI_BIOS_GUARD_FLASH_CONFIGURATIONS\r\n1 /N 1 ;NV\xff\xfe\r\n", "UTF-8"),
    (b"AMI_BIOS_GUARD_FLASH_CONFIGURATIONS\r\nnot a file line;\r\n", "格式"),
    (b"AMI_BIOS_GUARD_FLASH_CONFIGURATIONS\r\n1 /N x ;NVRAM\r\n", "格式"),
    (b"AMI_BIOS_GUARD_FLASH_CONFIGURATIONS\r\n1 /N 1 ;\r\n", "格式"),
    (b"AMI_BIOS_GUARD_FLASH_CONFIGURATIONSII00\r\n1 /N 1 ;NVRAM\r\n", "索引"),
])
def test_header_text_contradictions(text, why):
    pf = ap.unwrap(pfat_with_text(text))
    assert pf is not None and not pf["ok"] and why in pf["error"], pf and pf["error"]


def test_header_text_baseline_is_accepted():
    assert ap.unwrap(pfat_with_text(b"AMI_BIOS_GUARD_FLASH_CONFIGURATIONS\r\n1 /N 1 ;NVRAM\r\n"))["ok"]


def test_flash_index_count_must_match_files():
    pf = ap.unwrap(pfat([("A", [b"a"]), ("B", [b"b"])], order=[0]))
    assert not pf["ok"] and "索引" in pf["error"]


def test_blocks_with_different_platform_are_contradictory():
    good = pfat([("A", [b"a" * 8, b"b" * 8])])
    # 第二個 block 的平台 ID 改掉
    first = block(b"a" * 8)
    i = good.index(first) + len(first)
    bad = good[:i + 4] + b"OTHERPLATFORM\x00\x00\x00" + good[i + 20:]
    pf = ap.unwrap(bad)
    assert not pf["ok"] and "矛盾" in pf["error"]


def test_empty_file_list_and_zero_blocks():
    assert "沒有列出" in ap.unwrap(pfat([]))["error"]
    pf = ap.unwrap(pfat([("A", [])]))
    assert not pf["ok"]


# ---------- 巢狀 ----------

def nested(depth):
    """depth 層：最內層是一般資料，每往外一層就把內層整包放進 FV 檔案。"""
    inner = b"INNER" * 20
    for i in range(depth):
        inner = pfat([(f"L{i}", [inner])])
    return inner


def test_nested_pfat_is_unwrapped():
    pf = ap.unwrap(nested(2))
    assert pf["ok"] and pf["info"]["nested"] == 1 and pf["image"] == b"INNER" * 20 and not pf["unparsed"]


def test_nested_beyond_depth_limit_is_recorded_not_unwrapped():
    pf = ap.unwrap(nested(ap.MAX_DEPTH + 3))
    assert pf["ok"] and pf["unparsed"] and "深度上限" in pf["unparsed"][0]
    assert pf["image"] != b"INNER" * 20 and ap.find(pf["image"]) is not None         # 最深解開的那層還是 PFAT，沒有假裝解完


def test_nested_at_exactly_the_limit_is_fully_unwrapped():
    pf = ap.unwrap(nested(ap.MAX_DEPTH + 1))
    assert pf["ok"] and not pf["unparsed"] and pf["image"] == b"INNER" * 20


def test_broken_nested_pfat_is_recorded():
    inner = pfat([("I", [b"i" * 8])])[:-3]                       # 截斷的內層
    pf = ap.unwrap(pfat([("OUT", [inner])]))
    assert pf["ok"] and pf["unparsed"] and "解不開" in pf["unparsed"][0] and pf["image"] == inner


def test_trailing_pfat_is_unwrapped():
    pf = ap.unwrap(pfat([("A", [b"a" * 8])], trailing=pfat([("B", [b"b" * 8])])))
    assert pf["ok"] and pf["image"] == b"a" * 8 + b"b" * 8


def test_time_budget_is_checked_per_block():
    class Over(Exception):
        pass

    class Budget:
        n = 0

        def check(self):
            self.n += 1
            if self.n > 2:
                raise Over()
    with pytest.raises(Over):
        ap.unwrap(pfat(three_files()), Budget())


# ---------- x86_firmware 整合 ----------

def split_blocks(img, n=4):
    step = -(-len(img) // n)
    return [img[i:i + step] for i in range(0, len(img), step)]


def pfat_from_spi(**kw):
    img = spi_image()
    return img, pfat([("BIOS_REGION", split_blocks(img))], **kw)


def inv_of(tmp_path, data, name="PATGL357.0059.CAP", manifest=None):
    p = tmp_path / name
    p.write_bytes(data)
    return xf.inventory([p], manifest)


def test_x86_firmware_reads_descriptor_me_microcode_from_pfat(tmp_path):
    img, raw = pfat_from_spi()
    inv = inv_of(tmp_path, raw)
    assert len(inv["bios"]) == 1 and not inv["partial"] and not inv["skipped"]
    b = inv["bios"][0]
    assert b["descriptor"] and b["me"]["version"] == "16.1.30.2307"
    assert {(u["cpuid"], u["revision"]) for u in b["microcode"]} == {("000B06A2", "0x4121"), ("000B0671", "0x123")}
    assert b["ibv_hint"] == ["AMI"] and b["sha256"] == xf.hashes(img)["sha256"] and b["size"] == len(img)
    p = b["pfat"]
    assert p["container_sha256"] == xf.hashes(raw)["sha256"] and p["image_sha256"] == b["sha256"]
    assert p["signature_verified"] is False and any("未驗證" in n for n in p["notes"])
    assert p["info"]["blocks"] == 4


def test_pfat_same_image_as_plain_file_is_one_bios_entry(tmp_path):
    img, raw = pfat_from_spi()
    (tmp_path / "plain.bin").write_bytes(img)
    (tmp_path / "wrapped.cap").write_bytes(raw)
    inv = xf.inventory([tmp_path / "plain.bin", tmp_path / "wrapped.cap"])
    assert len(inv["bios"]) == 1 and sorted(inv["bios"][0]["locations"]) == ["plain.bin", "wrapped.cap"]


def test_non_pfat_file_is_unchanged(tmp_path):
    inv = inv_of(tmp_path, spi_image(), "in.bin")
    assert "pfat" not in inv["bios"][0]


def test_sbom_has_pfat_properties_and_validates(tmp_path):
    img, raw = pfat_from_spi()
    inv = inv_of(tmp_path, raw)
    comps, deps = xf.components(inv)
    doc = xf.bom(comps, deps)
    assert not list(cdx_validator().iter_errors(doc))
    c = next(c for c in comps if c["name"] == "PATGL357.0059.CAP")
    props = {p["name"]: p["value"] for p in c["properties"]}
    assert props["dumpling:unwrapped-from"] == "AMI PFAT (AMI BIOS Guard)"
    assert props["dumpling:container-sha256"] == xf.hashes(raw)["sha256"]
    assert props["dumpling:unwrapped-image-sha256"] == xf.hashes(img)["sha256"]
    assert props["dumpling:pfat-signature"] == "not verified"
    assert "not an SPI address map" in props["dumpling:pfat-layout"]
    assert props["sca-center:ibv-hint"] == "AMI"
    assert {h["alg"]: h["content"] for h in c["hashes"]}["SHA-256"] == xf.hashes(img)["sha256"]
    for comp in comps:                       # 既有規則仍然成立
        pp = {p["name"]: p["value"] for p in comp["properties"]}
        assert pp["dumpling:vuln-assessment"] == "NOT_ASSESSED" and pp["dumpling:version-status"] in ("OK", "GAP")
    me = next(c for c in comps if c["name"] == xf.ME_NAME)
    assert me["version"] == "16.1.30.2307"


def test_markdown_has_a_pfat_line(tmp_path):
    _, raw = pfat_from_spi()
    inv = inv_of(tmp_path, raw)
    md = xf.markdown(inv)
    assert "AMI PFAT (AMI BIOS Guard) 封裝" in md and "BIOS Guard 簽章未驗證" in md and "AMI（" in md


def test_broken_pfat_is_partial_attention_with_reason(tmp_path):
    img, raw = pfat_from_spi()
    inv = inv_of(tmp_path, raw[:-100])
    assert any("AMI PFAT 解封裝失敗" in x["reason"] for x in inv["partial"])
    st, detail = xf.status_of(inv)
    assert st in ("GAP", "ATTENTION") and "只解析了一部分" in detail
    # 沒有被當成成功：沒有假的 BIOS 映像
    assert not any(b.get("pfat") for b in inv["bios"])


def test_nested_beyond_limit_goes_to_partial(tmp_path):
    img = spi_image()
    raw = pfat([("OUT", [nested(ap.MAX_DEPTH + 2) + img])])
    inv = inv_of(tmp_path, raw)
    assert any("深度上限" in x["reason"] for x in inv["partial"])
    assert xf.status_of(inv)[0] == "ATTENTION"


def test_pfat_inside_zip_is_found(tmp_path):
    import zipfile
    _, raw = pfat_from_spi()
    z = tmp_path / "bios.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("pkg/BIOS.CAP", raw)
        zf.writestr("pkg/BIOS2.CAP", raw)
    inv = xf.inventory([z])
    assert len(inv["bios"]) == 1 and inv["bios"][0]["pfat"] and len(inv["bios"][0]["locations"]) == 2


def test_total_budget_counts_the_reassembled_image(tmp_path):
    img, raw = pfat_from_spi()
    p = tmp_path / "a.cap"
    p.write_bytes(raw)
    budget = xf.Budget(max_total=len(raw) + 10)         # 原檔放得下，組回的映像放不下
    inv = xf.inventory([p], None, budget)
    assert any("總量上限" in x["reason"] for x in inv["partial"])
    assert not any(b.get("pfat") for b in inv["bios"])


def test_cli_with_isolated_python_loads_the_module_and_outputs(tmp_path):
    _, raw = pfat_from_spi()
    (tmp_path / "in.cap").write_bytes(raw)
    out = tmp_path / "out"
    r = subprocess.run([sys.executable, "-I", str(TOOL), "inventory", "--in", str(tmp_path / "in.cap"), "--out", str(out)],
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 2, r.stderr           # ATTENTION（沒有版本清單）
    assert r.stdout.startswith("FW-INVENTORY\tATTENTION")
    doc = json.loads((out / "fw.cdx.json").read_text(encoding="utf-8"))
    assert not list(cdx_validator().iter_errors(doc))
    assert any(p["name"] == "dumpling:unwrapped-from" for c in doc["components"] for p in c.get("properties", []))
