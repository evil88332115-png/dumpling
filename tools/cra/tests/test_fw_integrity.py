"""x86_firmware.py 的程式碼完整性結構證據（integrity）：FIT 的每個項目、Boot Guard 結構（KM、BPM、startup ACM）、除錯政策項目（type 0x2F）。
全部用測試自己組出來的假映像（不含任何產品映像）。重點：

- not-found 只在整張 FIT 完整讀完時成立；FIT 指標壞掉或找不到、映像是封裝或不是完整 SPI 映像、項目位址落在映像外、表的長度或 checksum 不合，一律是 GAP。
- 生效與否固定 NOT_ASSESSED，而且不影響 status_of() 的結果。
- 報告與 SBOM 不出現「已啟用」「已簽章」這類結論。
"""
import json
import re
import struct
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import x86_firmware as xf  # noqa: E402
from cdx_schema import cdx_validator  # noqa: E402
from test_ami_pfat import inv_of, pfat, split_blocks  # noqa: E402
from test_x86_firmware import me_region, spi_image  # noqa: E402

KM_AT, BPM_AT, ACM_AT, DBG_AT, UCODE_AT = 0xD000, 0xD400, 0xD800, 0xD900, 0xB000      # spi_image 的 BIOS 區域是 0x8000–0xFFFF
OBSERVED, NOT_FOUND, GAP, NA = "observed", "not-found", "GAP", "NOT_ASSESSED"
IDS = ["CI-01", "CI-01.km", "CI-01.bpm", "CI-01.acm", "CI-02", "CI-07", "CI-07.lock"]


def fit_image(entries, *, img=None, fit_off=0xE000, cv=True, bad_sum=False, count=None, ver=0x0100, ptr=None, ids=True):
    """在映像（預設 spi_image，檔尾對到 4 GB）放 FIT。entries：(type, 檔案位置｜("raw", 位址)［, 大小欄位］)。
    ids：在 KM、BPM 的位置寫入 8 bytes 的結構字串。cv：表頭 C_V 位元，有設就把 checksum 補成整張表加總為 0（bad_sum 時故意差 1）。"""
    b = bytearray(img if img is not None else spi_image())
    n = len(b)

    def addr(o):
        return o[1] if isinstance(o, tuple) else (1 << 32) - (n - o)
    t = bytearray(b"_FIT_   " + (len(entries) + 1 if count is None else count).to_bytes(3, "little") + b"\x00"
                  + struct.pack("<HBB", ver, 0x80 if cv else 0, 0))
    for e in entries:
        typ, tgt, size = e[0], e[1], (e[2] if len(e) > 2 else 0)
        t += struct.pack("<Q", addr(tgt)) + size.to_bytes(3, "little") + b"\x00" + struct.pack("<HBB", 0x0100, typ, 0)
        if ids and typ in (0x0B, 0x0C) and not isinstance(tgt, tuple) and tgt + 8 <= n:
            b[tgt:tgt + 8] = {0x0B: b"__KEYM__", 0x0C: b"__ACBP__"}[typ]
    if cv:
        t[15] = (-sum(t)) & 0xFF if count is None else 0
        if bad_sum:
            t[15] = (t[15] + 1) & 0xFF
    b[fit_off:fit_off + len(t)] = t
    struct.pack_into("<Q", b, n - 0x40, addr(fit_off) if ptr is None else ptr)
    return bytes(b)


FULL = [(0x01, UCODE_AT), (0x02, ACM_AT), (0x0B, KM_AT, 0x35), (0x0C, BPM_AT, 0x39)]


def items(b):
    return {x["id"]: x for x in b["integrity"]["items"]}


def states(b):
    return {k: v["state"] for k, v in items(b).items()}


def only(b, **kw):
    """CI-02 與 CI-07.lock 固定 NOT_ASSESSED；其餘項目的狀態用 kw（id 的 . 換成 _）指定，沒指定的不比。"""
    s = states(b)
    assert s["CI-02"] == NA and s["CI-07.lock"] == NA
    for k, v in kw.items():
        assert s[k.replace("_", ".").replace("CI.", "CI-")] == v, (k, s)


def reasons(b):
    return {k: v["reason"] for k, v in items(b).items()}


# ---------- FIT 的每個項目 ----------

def test_every_fit_entry_is_recorded_with_type_address_size_and_in_image():
    img = fit_image(FULL + [(0x10, ("raw", 0x12345678)), (0x2F, DBG_AT), (0x55, DBG_AT), (0x1F, 0), (0x7F, 0)])
    b = xf.bios_image(img)
    es = b["integrity"]["fit"]["entries"]
    assert [e["type"] for e in es] == ["0x01", "0x02", "0x0b", "0x0c", "0x10", "0x2f", "0x55", "0x1f", "0x7f"]
    assert [e["name"] for e in es] == ["microcode update", "startup ACM", "key manifest", "boot policy manifest", "CSE secure boot", "JMP $ debug policy",
                                       "platform manufacturer use", "reserved or unknown", "unused entry (skip)"]
    km = es[2]
    assert (km["entry"], km["offset"], km["in_image"], km["size_field"], km["id_string"], km["checksum_valid_bit"]) == (3, KM_AT, True, 0x35, "__KEYM__", False)
    assert km["address"] == f"0x{(1 << 32) - (len(img) - KM_AT):08x}" and km["version"] == "0x0100"
    assert es[3]["id_string"] == "__ACBP__" and "id_string" not in es[1]
    assert es[4]["in_image"] is False and es[4]["offset"] is None and es[4]["address"] == "0x12345678"
    assert es[8]["in_image"] is None                       # type 0x7F（skip）的位址沒有意義
    assert b["integrity"]["fit"]["complete"] and b["integrity"]["fit"]["checksum"] == "valid"
    assert (b["integrity"]["fit"]["declared_entries"], b["integrity"]["fit"]["read_entries"]) == (9, 9)


def test_fit_output_and_microcode_behaviour_are_unchanged():
    """fit 物件本身的鍵與內容照舊（新資料只在 integrity）；微碼的 in_fit、incomplete 照舊。"""
    b = xf.bios_image(fit_image(FULL + [(0x01, 0xC000)]))
    assert set(b["fit"]) == {"status", "offset", "entries", "microcode", "note"}
    assert (b["fit"]["status"], b["fit"]["offset"], b["fit"]["entries"], b["fit"]["note"]) == ("found", 0xE000, 5, None)
    assert [(e["entry"], e["offset"], e["valid"]) for e in b["fit"]["microcode"]] == [(1, UCODE_AT, True), (5, 0xC000, False)]
    assert any("FIT entry 5" in x and "no valid microcode header" in x for x in b["incomplete"])
    assert not any("integrity" in x.lower() or "CI-" in x for x in b["incomplete"] + b["gaps"])
    assert [(u["cpuid"], u["in_fit"]) for u in b["microcode"]] == [("000B06A2", False), ("000B0671", True)]


# ---------- Boot Guard 結構 ----------

def test_key_manifest_boot_policy_and_acm_observed_enforcement_not_assessed():
    b = xf.bios_image(fit_image(FULL))
    s = states(b)
    assert s == {"CI-01": OBSERVED, "CI-01.km": OBSERVED, "CI-01.bpm": OBSERVED, "CI-01.acm": OBSERVED, "CI-02": NA, "CI-07": NOT_FOUND, "CI-07.lock": NA}
    assert [x["id"] for x in b["integrity"]["items"]] == IDS
    r = reasons(b)
    assert r["CI-01"] == r["CI-01.km"] == "ci-structure-observed-enforcement-unknown" and r["CI-02"] == r["CI-07.lock"] == "ci-needs-fuse-state"
    assert r["CI-07"] == "ci-not-found-parse-complete"
    km = items(b)["CI-01.km"]["evidence"]
    assert "type 0x0b" in km and f"file offset 0x{KM_AT:x}" in km and "__KEYM__ (seen)" in km
    assert "__ACBP__ (seen)" in items(b)["CI-01.bpm"]["evidence"]
    assert b["integrity"]["statement"] == ("structure observed: CI-01.km, CI-01.bpm, CI-01.acm; no entry in a completely read FIT "
                                           "(one FIT only; a top-swap second table is not read): CI-07; enforcement not assessed")
    for x in b["integrity"]["items"]:
        assert set(x) == {"id", "state", "evidence", "basis", "reason"}


def test_every_value_is_declared_by_the_image_and_says_so():
    b = xf.bios_image(fit_image(FULL))
    for x in b["integrity"]["items"]:
        if x["id"] in ("CI-02", "CI-07.lock"):
            assert "fuses" in x["basis"] and "image does not contain" in x["basis"]
        else:
            assert x["basis"].startswith("self-declared by the image") and "no signature was verified" in x["basis"] \
                and "assumes the image was not modified" in x["basis"]


def test_structure_strings_are_only_observations_not_state():
    """位址開頭沒有 __KEYM__：狀態還是 observed（看 FIT 項目），證據寫明沒看到；有字串但 FIT 沒有項目：不會變成 observed。"""
    b = xf.bios_image(fit_image([(0x01, UCODE_AT), (0x0B, KM_AT, 0x35)], ids=False))
    assert states(b)["CI-01.km"] == OBSERVED and "__KEYM__ not seen at the address" in items(b)["CI-01.km"]["evidence"]
    assert b["integrity"]["fit"]["entries"][1]["id_string"] == "........"           # 位址開頭是 0xFF，不是可印字元
    img = bytearray(fit_image([(0x01, UCODE_AT)]))
    img[KM_AT:KM_AT + 8] = b"__KEYM__"
    img[BPM_AT:BPM_AT + 8] = b"__ACBP__"
    b = xf.bios_image(bytes(img))
    assert states(b)["CI-01.km"] == NOT_FOUND and states(b)["CI-01.bpm"] == NOT_FOUND and states(b)["CI-01"] == NOT_FOUND


def test_microcode_only_fit_is_not_found_because_the_table_was_read_completely():
    b = xf.bios_image(fit_image([(0x01, UCODE_AT), (0x01, 0xA000)]))
    only(b, CI_01=NOT_FOUND, CI_01_km=NOT_FOUND, CI_01_bpm=NOT_FOUND, CI_01_acm=NOT_FOUND, CI_07=NOT_FOUND)
    assert set(reasons(b)[k] for k in ("CI-01", "CI-01.km", "CI-01.bpm", "CI-01.acm", "CI-07")) == {"ci-not-found-parse-complete"}
    assert "read completely (2 entries, header checksum valid)" in items(b)["CI-01.km"]["evidence"]
    assert "read completely (1 entry, header checksum valid)" in items(xf.bios_image(fit_image([(0x01, UCODE_AT)])))["CI-01.km"]["evidence"]
    assert items(b)["CI-01"]["evidence"].endswith("enforcement not assessed (CI-02)") and "structure observed" not in items(b)["CI-01"]["evidence"]
    assert b["integrity"]["fit"]["complete"] is True


def test_one_manifest_is_enough_for_ci_01_and_the_other_stays_separate():
    only(xf.bios_image(fit_image([(0x01, UCODE_AT), (0x0B, KM_AT, 4)])), CI_01=OBSERVED, CI_01_km=OBSERVED, CI_01_bpm=NOT_FOUND)
    only(xf.bios_image(fit_image([(0x01, UCODE_AT), (0x0C, BPM_AT, 4)])), CI_01=OBSERVED, CI_01_km=NOT_FOUND, CI_01_bpm=OBSERVED)
    # 只有 startup ACM：不算 Boot Guard 的 manifest
    only(xf.bios_image(fit_image([(0x01, UCODE_AT), (0x02, ACM_AT)])), CI_01=NOT_FOUND, CI_01_acm=OBSERVED)


def test_debug_policy_entry_type_0x2f_and_lock_state():
    b = xf.bios_image(fit_image([(0x01, UCODE_AT), (0x2F, DBG_AT)]))
    only(b, CI_07=OBSERVED, CI_01=NOT_FOUND)
    assert items(b)["CI-07"]["reason"] == "ci-structure-observed-enforcement-unknown" and "type 0x2f" in items(b)["CI-07"]["evidence"]
    assert items(b)["CI-07.lock"]["reason"] == "ci-needs-fuse-state"
    only(xf.bios_image(fit_image([(0x01, UCODE_AT)])), CI_07=NOT_FOUND)


def test_other_and_unknown_types_do_not_change_the_four_items():
    b = xf.bios_image(fit_image([(0x01, UCODE_AT), (0x10, ("raw", 0x12345678)), (0x2D, DBG_AT), (0x55, DBG_AT), (0x1F, 0), (0x7F, 0)]))
    only(b, CI_01=NOT_FOUND, CI_01_acm=NOT_FOUND, CI_07=NOT_FOUND)
    assert [e["type"] for e in b["integrity"]["fit"]["entries"]] == ["0x01", "0x10", "0x2d", "0x55", "0x1f", "0x7f"]


# ---------- GAP：不能寫 not-found 的情況 ----------

def assert_all_gap(b, reason, fixed=True):
    s = states(b)
    for k in ("CI-01", "CI-01.km", "CI-01.bpm", "CI-01.acm", "CI-07"):
        assert s[k] == GAP and reasons(b)[k] == reason, (k, s, reasons(b))
    if fixed:
        assert s["CI-02"] == NA and s["CI-07.lock"] == NA


def test_fit_pointer_pointing_outside_or_not_at_a_fit_is_gap():
    assert_all_gap(xf.bios_image(fit_image([(0x01, UCODE_AT)], ptr=(1 << 32) - 0x20000)), "ci-not-found-parse-incomplete")     # 對到映像前面
    b = xf.bios_image(fit_image([(0x01, UCODE_AT)], ptr=(1 << 32) - 0x1000))                                                  # 指到的位置不是 FIT 表頭
    assert b["fit"]["status"] == "invalid" and "no _FIT_ header" in items(b)["CI-01.km"]["evidence"]
    assert_all_gap(b, "ci-not-found-parse-incomplete")


def test_missing_fit_pointer_is_gap_never_not_found():
    # 完整 SPI 映像（有 descriptor 與 BIOS 區域）：指標位置是 0xFF → GAP，原因是「讀不到」，不是容器問題
    b = xf.bios_image(spi_image())
    assert b["fit"]["status"] == "not-found"
    assert_all_gap(b, "ci-not-found-parse-incomplete")
    assert "cannot be told apart" in items(b)["CI-01.km"]["evidence"]
    # 沒有 descriptor（capsule、只有 BIOS 區域的檔案、其他非完整 SPI 映像）：GAP，原因是容器
    b = xf.bios_image(spi_image(with_descriptor=False))
    assert b["fit"]["status"] == "not-found" and not b["descriptor"]
    assert_all_gap(b, "ci-container-unsupported")
    assert "capsule" in items(b)["CI-01.km"]["evidence"]


def test_capsule_file_is_gap_container_unsupported_not_not_found(tmp_path):
    """UEFI／廠商 capsule 檔（前面有標頭、檔尾不是 4 GB 對齊）：整個檔案掃得到 microcode，但 FIT 指標不在檔尾 → GAP。"""
    cap = b"\x00" * 0x400 + spi_image(with_descriptor=False)[0x8000:] + b"\x00" * 0x123
    p = tmp_path / "BIOS.CAP"
    p.write_bytes(cap)
    inv = xf.inventory([p])
    b = inv["bios"][0]
    assert not b["descriptor"] and b["fit"]["status"] == "not-found"
    assert_all_gap(b, "ci-container-unsupported")
    props = {x["name"]: x["value"] for c in xf.components(inv)[0] if c.get("type") == "firmware" and c["name"] == "BIOS.CAP" for x in c["properties"]}
    assert props["dumpling:integrity-ci-01"] == GAP and props["dumpling:integrity-ci-01-km"] == GAP and props["dumpling:integrity-ci-02"] == NA


def test_image_assembled_from_a_container_is_gap_even_with_a_valid_fit(tmp_path):
    """AMI PFAT 組回的映像：位移不是 SPI 位址。裡面剛好有合法的 FIT 也不能當證據。"""
    img = fit_image(FULL)
    inv = inv_of(tmp_path, pfat([("BIOS_REGION", split_blocks(img))]))
    b = inv["bios"][0]
    assert b["pfat"] and b["fit"]["status"] == "found"
    assert_all_gap(b, "ci-container-unsupported")
    assert "AMI PFAT" in items(b)["CI-01.km"]["evidence"] and "SPI address map" in items(b)["CI-01.km"]["evidence"]
    assert xf.bios_image(img, container=None)["integrity"]["items"][0]["state"] == OBSERVED          # 同一份內容不經封裝就是 observed
    assert xf.bios_image(img, container="AMI PFAT")["integrity"]["items"][0]["state"] == GAP


def test_standalone_me_update_has_no_fit_items_but_gap():
    b = xf.bios_image(me_region("me11", 0x10))
    assert b["fit"]["status"] == "not-applicable"
    assert_all_gap(b, "ci-container-unsupported")


def test_amd_platform_gets_no_intel_fit_items():
    img = bytearray(b"\xff" * 0x21000)
    img[0x20000:0x20004] = xf.AMD_EFS_SIG
    img[0x20800:0x20810] = b"$PSP" + struct.pack("<III", 0, 5, 0)
    b = xf.bios_image(bytes(img))
    assert b["platform"] == "amd" and b["integrity"]["items"] == [] and b["integrity"]["fit"] is None and "AMD platform" in b["integrity"]["note"]
    assert xf.integrity_props(b["integrity"]) == []


def test_entry_address_outside_the_image_is_gap_not_not_found():
    # KM 的位址落在映像前面、BPM 在映像內：KM 是 GAP（不是 not-found），CI-01 因為 BPM observed 而 observed
    b = xf.bios_image(fit_image([(0x01, UCODE_AT), (0x0B, ("raw", 0xFF000000), 0x35), (0x0C, BPM_AT, 0x39)]))
    only(b, CI_01_km=GAP, CI_01_bpm=OBSERVED, CI_01=OBSERVED)
    assert "none with an address inside the image" in items(b)["CI-01.km"]["evidence"] and "(outside the image)" in items(b)["CI-01.km"]["evidence"]
    assert items(b)["CI-01.km"]["reason"] == "ci-not-found-parse-incomplete"
    # 兩個都在映像外：CI-01 也是 GAP
    b = xf.bios_image(fit_image([(0x01, UCODE_AT), (0x0B, ("raw", 0xFF000000)), (0x0C, ("raw", 0x1_0000_0000 + 0x1000))]))
    only(b, CI_01_km=GAP, CI_01_bpm=GAP, CI_01=GAP, CI_01_acm=NOT_FOUND)
    assert items(b)["CI-01"]["reason"] == "ci-not-found-parse-incomplete"
    # 位址在映像內、但大小欄位從位址起算超出映像末端：同樣不能當成 observed
    b = xf.bios_image(fit_image([(0x01, UCODE_AT), (0x0C, 0xFF00, 0x100)]))
    only(b, CI_01_bpm=GAP)
    assert xf.bios_image(fit_image([(0x01, UCODE_AT), (0x0C, 0xFF00, 0x0F)]))["integrity"]["items"][2]["state"] == OBSERVED
    # 類型 0x2F 與 0x02 一樣規則
    b = xf.bios_image(fit_image([(0x01, UCODE_AT), (0x2F, ("raw", 0xFF000000)), (0x02, ("raw", 0xFF000000))]))
    only(b, CI_07=GAP, CI_01_acm=GAP)


def test_entry_count_over_the_limit_is_gap_for_what_was_not_read(monkeypatch):
    monkeypatch.setattr(xf, "MAX_FIT_ENTRIES", 2)
    b = xf.bios_image(fit_image([(0x02, ACM_AT), (0x7F, 0), (0x7F, 0), (0x0B, KM_AT, 0x35)]))
    f = b["integrity"]["fit"]
    assert f["complete"] is False and (f["declared_entries"], f["read_entries"]) == (4, 2) and any("only the first 2" in x for x in f["issues"])
    only(b, CI_01_acm=OBSERVED, CI_01_km=GAP, CI_01_bpm=GAP, CI_01=GAP, CI_07=GAP)         # 讀到的照樣 observed；沒讀到的不能 not-found
    assert "not 'not-found'" in items(b)["CI-01.km"]["evidence"] and items(b)["CI-01.km"]["reason"] == "ci-not-found-parse-incomplete"
    # 剛好等於上限：讀完了
    monkeypatch.setattr(xf, "MAX_FIT_ENTRIES", 4)
    only(xf.bios_image(fit_image([(0x02, ACM_AT), (0x7F, 0), (0x7F, 0), (0x0B, KM_AT, 0x35)])), CI_01_km=OBSERVED, CI_01_bpm=NOT_FOUND)


def test_table_checksum_length_and_version_mismatch_are_gap():
    # C_V 有設但整張表加總不是 0
    b = xf.bios_image(fit_image([(0x01, UCODE_AT), (0x02, ACM_AT)], bad_sum=True))
    assert b["integrity"]["fit"]["checksum"] == "invalid" and b["integrity"]["fit"]["complete"] is False
    only(b, CI_01_acm=OBSERVED, CI_01_km=GAP, CI_01_bpm=GAP, CI_01=GAP, CI_07=GAP)
    assert "checksum-valid bit set" in items(b)["CI-01.km"]["evidence"]
    # 沒設 C_V：checksum 不要求（Intel FIT 規格），長度與版本對就讀得完
    b = xf.bios_image(fit_image([(0x01, UCODE_AT)], cv=False))
    assert b["integrity"]["fit"]["checksum"] == "not-set" and b["integrity"]["fit"]["complete"] is True
    only(b, CI_01=NOT_FOUND)
    # 表頭的長度欄位是 0
    b = xf.bios_image(fit_image([(0x01, UCODE_AT)], count=0))
    assert b["fit"]["status"] == "found" and b["integrity"]["fit"]["complete"] is False
    assert_all_gap(b, "ci-not-found-parse-incomplete")
    # 長度欄位宣告得比區域還長
    b = xf.bios_image(fit_image([(0x01, UCODE_AT)], count=0x2000))
    assert any("go past the end of the BIOS region" in x for x in b["integrity"]["fit"]["issues"])
    assert_all_gap(b, "ci-not-found-parse-incomplete")
    # 版本不是 0x0100
    b = xf.bios_image(fit_image([(0x01, UCODE_AT)], ver=0x0200))
    assert any("version 0x0200" in x for x in b["integrity"]["fit"]["issues"])
    assert_all_gap(b, "ci-not-found-parse-incomplete")


def test_truncated_image_is_gap_even_with_a_readable_fit():
    img = fit_image([(0x01, 0xB000), (0x02, 0xB800)], img=spi_image()[:0xC000], fit_off=0xB900)
    b = xf.bios_image(img)
    assert any("beyond the end of the file" in x for x in b["incomplete"])
    f = b["integrity"]["fit"]
    assert f["status"] == "found" and f["complete"] is False and any(x.startswith("image truncated") for x in f["issues"])
    only(b, CI_01_acm=OBSERVED, CI_01_km=GAP, CI_01=GAP, CI_07=GAP)


# ---------- 報告、SBOM、狀態 ----------

FORBIDDEN = [r"\benabled\b", r"\benforced\b", r"\bprotected\b", r"\bsigned\b", r"\bverified boot\b", r"\bpass(ed)?\b", r"\bis active\b",
             r"\btrusted\b", r"安全", r"不適用", r"不受影響", r"已簽章", r"已啟用", r"驗證開機已"]


def all_strings(x):
    if isinstance(x, str):
        yield x
    elif isinstance(x, dict):
        for k, v in x.items():
            yield from all_strings(k)
            yield from all_strings(v)
    elif isinstance(x, list):
        for v in x:
            yield from all_strings(v)


def inv_for(tmp_path, img, name="BIOS.bin"):
    p = tmp_path / name
    p.write_bytes(img)
    return xf.inventory([p])


@pytest.mark.parametrize("img", [fit_image(FULL + [(0x2F, DBG_AT)]), fit_image([(0x01, UCODE_AT)]), spi_image(), fit_image(FULL, ptr=(1 << 32) - 0x20000)],
                         ids=["observed", "not-found", "gap-no-fit", "gap-bad-pointer"])
def test_report_and_sbom_never_state_enabled_or_signed(tmp_path, img):
    inv = inv_for(tmp_path, img)
    b = inv["bios"][0]
    comps, deps = xf.components(inv)
    assert not list(cdx_validator().iter_errors(xf.bom(comps, deps)))
    img_comp = next(c for c in comps if c["name"] == "BIOS.bin")
    props = {p["name"]: p["value"] for p in img_comp["properties"] if p["name"].startswith("dumpling:integrity-")}
    ids = [x["id"].lower().replace(".", "-") for x in b["integrity"]["items"]]
    assert set(props) == {"dumpling:integrity-" + i for i in ids} | {"dumpling:integrity-basis"}
    assert {k: v for k, v in props.items() if k != "dumpling:integrity-basis"} == {"dumpling:integrity-" + x["id"].lower().replace(".", "-"): x["state"] for x in b["integrity"]["items"]}
    assert props["dumpling:integrity-basis"] == f"{b['integrity']['statement']}; {xf.INTEGRITY_BASIS}"
    assert props["dumpling:integrity-basis"].startswith("structure observed: ") == (OBSERVED in {x["state"] for x in b["integrity"]["items"]})
    assert props["dumpling:integrity-ci-02"] == NA and props["dumpling:integrity-ci-07-lock"] == NA
    assert not [p for p in img_comp["properties"] if p["name"].startswith("sca-center:integrity")]
    texts = list(all_strings(b["integrity"]["items"])) + list(all_strings(b["integrity"]["statement"])) + [v for k, v in props.items()] + [xf.markdown(inv)]
    for t in texts:
        for pat in FORBIDDEN:
            assert not re.search(pat, t, re.I), (pat, t[:200])
    # 其他元件（ME、微碼）沒有 integrity property
    assert not [p for c in comps if c is not img_comp for p in c.get("properties", []) if "integrity" in p["name"]]
    json.dumps(inv)


def test_status_and_report_text_do_not_depend_on_integrity(tmp_path):
    """integrity 的 GAP／NOT_ASSESSED 不會讓 status_of() 或 fw-inventory.md 改變（接線另做）。"""
    for img in (fit_image(FULL), fit_image([(0x01, UCODE_AT)]), spi_image(), fit_image(FULL, ptr=(1 << 32) - 0x20000)):
        inv = inv_for(tmp_path, img)
        before = (xf.status_of(inv), xf.markdown(inv))
        for b in inv["bios"]:
            b.pop("integrity")
        assert (xf.status_of(inv), xf.markdown(inv)) == before
        assert "integrity" not in before[0][1].lower() and "CI-0" not in before[1] and "Boot Guard" not in before[1]
    # 結構 observed、生效 NOT_ASSESSED 的映像：狀態只由既有的欄位決定，不會因為 CI-02 的 NOT_ASSESSED 變成 ATTENTION
    inv = inv_for(tmp_path, fit_image(FULL))
    assert items(inv["bios"][0])["CI-02"]["state"] == NA
    assert "CI-02" not in xf.status_of(inv)[1] and "NOT_ASSESSED" not in xf.status_of(inv)[1]


def test_integrity_props_use_the_dumpling_namespace_and_one_per_item():
    sec = xf.bios_image(fit_image(FULL))["integrity"]
    ps = xf.integrity_props(sec)
    assert [p["name"] for p in ps] == ["dumpling:integrity-ci-01", "dumpling:integrity-ci-01-km", "dumpling:integrity-ci-01-bpm", "dumpling:integrity-ci-01-acm",
                                       "dumpling:integrity-ci-02", "dumpling:integrity-ci-07", "dumpling:integrity-ci-07-lock", "dumpling:integrity-basis"]
    assert xf.integrity_props(None) == [] and xf.integrity_props({"items": []}) == []


# ---------- statement 依狀態產生（驗證建議 1） ----------

ONE_FIT = "(one FIT only; a top-swap second table is not read)"


@pytest.mark.parametrize("img,want", [
    (fit_image([(0x01, UCODE_AT)]), f"no entry in a completely read FIT {ONE_FIT}: CI-01.km, CI-01.bpm, CI-01.acm, CI-07; enforcement not assessed"),
    (spi_image(), "structure not determined (GAP): CI-01.km, CI-01.bpm, CI-01.acm, CI-07; enforcement not assessed"),
    (fit_image(FULL, ptr=(1 << 32) - 0x20000), "structure not determined (GAP): CI-01.km, CI-01.bpm, CI-01.acm, CI-07; enforcement not assessed"),
    (fit_image([(0x01, UCODE_AT), (0x02, ACM_AT)]),
     f"structure observed: CI-01.acm; no entry in a completely read FIT {ONE_FIT}: CI-01.km, CI-01.bpm, CI-07; enforcement not assessed"),
    (fit_image([(0x01, UCODE_AT), (0x0B, KM_AT, 4)], bad_sum=True),
     "structure observed: CI-01.km; structure not determined (GAP): CI-01.bpm, CI-01.acm, CI-07; enforcement not assessed"),
], ids=["microcode-only", "no-fit", "bad-pointer", "acm-only", "km-table-incomplete"])
def test_statement_and_sbom_basis_follow_the_states(img, want):
    """「structure observed」只在有 observed 的項目時出現；not-found 與 GAP 各自照實寫，SBOM 的 basis 用同一句。"""
    sec = xf.bios_image(img)["integrity"]
    assert sec["statement"] == want
    basis = {p["name"]: p["value"] for p in xf.integrity_props(sec)}["dumpling:integrity-basis"]
    assert basis == f"{want}; {xf.INTEGRITY_BASIS}"
    assert ("structure observed" in basis) == (OBSERVED in states_of(sec))


def states_of(sec):
    return {x["state"] for x in sec["items"]}


def test_amd_statement_says_no_items_were_produced():
    sec = xf.integrity_section({"status": "not-found", "offset": None, "note": None}, [], None, amd=True)
    assert sec["items"] == [] and sec["statement"] == "no Intel FIT items produced; enforcement not assessed"
    assert "structure observed" not in sec["statement"] and xf.integrity_props(sec) == []


def test_not_found_evidence_says_only_one_fit_is_read():
    ev = items(xf.bios_image(fit_image([(0x01, UCODE_AT)])))["CI-01.km"]["evidence"]
    assert ev.endswith("has no entry of type 0x0b (Key Manifest); one FIT only; a top-swap second table is not read")


# ---------- 項目類型位元組的 C_V 位元、位址的高 32 位元（驗證建議 2、3） ----------

def test_entry_type_with_the_checksum_valid_bit_set_is_still_recognised():
    """類型位元組的最高位元是 C_V：0x8B、0x8C、0x82、0xAF 仍是 KM、BPM、startup ACM、0x2F，不能變成 not-found。"""
    b = xf.bios_image(fit_image([(0x01, UCODE_AT), (0x8B, KM_AT, 0x35), (0x8C, BPM_AT, 0x39), (0x82, ACM_AT), (0xAF, DBG_AT)]))
    only(b, CI_01=OBSERVED, CI_01_km=OBSERVED, CI_01_bpm=OBSERVED, CI_01_acm=OBSERVED, CI_07=OBSERVED)
    es = b["integrity"]["fit"]["entries"]
    assert [(e["type"], e["checksum_valid_bit"]) for e in es] == [("0x01", False), ("0x0b", True), ("0x0c", True), ("0x02", True), ("0x2f", True)]
    assert [e["name"] for e in es[1:]] == ["key manifest", "boot policy manifest", "startup ACM", "JMP $ debug policy"]


def test_entry_address_with_nonzero_high_32_bits_is_outside_the_image():
    """位址的高 32 位元不是 0：不在 4 GB 以下，不能只看低 32 位元對到映像（否則會誤判 observed）。"""
    n = len(spi_image())
    low = (1 << 32) - (n - KM_AT)                      # 低 32 位元剛好是 KM_AT 在映像裡的位址
    b = xf.bios_image(fit_image([(0x01, UCODE_AT), (0x0B, ("raw", (1 << 32) | low), 0x35)]))
    km = b["integrity"]["fit"]["entries"][1]
    assert (km["address"], km["offset"], km["in_image"]) == (f"0x00000001{low:08x}", None, False) and "id_string" not in km
    only(b, CI_01=GAP, CI_01_km=GAP, CI_01_bpm=NOT_FOUND)
    assert reasons(b)["CI-01.km"] == "ci-not-found-parse-incomplete" and "none with an address inside the image" in items(b)["CI-01.km"]["evidence"]


def test_nothing_recognised_gives_no_bios_entry_and_no_integrity():
    """只有壞掉的 FIT 指標、認不出任何結構：bios_image() 回 None，不產生 integrity（筆記 3.3）。"""
    assert xf.bios_image(bytes(0x10000 - 8) + struct.pack("<Q", (1 << 32) - 0x20000)) is None
