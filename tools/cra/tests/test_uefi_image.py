"""uefi_image.py：合成的 UEFI 映像（FV 標頭＋FFS 檔＋GUID-defined LZMA section＋假 PE），涵蓋 present／absent／not_assessed、
"embed" 誤判、解壓縮炸彈限制、標頭掃描退路；以及 uefi_bundled／cra_report／vex_export 對 UB1／UB2 的效果。沒有任何產品資料。"""
import json
import lzma
import os
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import bootloader_coverage as bc  # noqa: E402
import uefi_image as ui  # noqa: E402
import vex_export as vx  # noqa: E402
from test_cra_report import MIN_CFG, make_project, make_scan, run, write_json  # noqa: E402
from test_uefi_bundled import grype_json, make_uefi, put_grype  # noqa: E402

GUID = bytes(range(16))
CORR = {k: {"ok": True, "reason": "test", "dsc": ["P/Platform.dsc"], "evidence": ["P/Platform.dsc:1: OpensslLib|x"]} for k in ("openssl", "mbedtls")}


def an(data, corr=CORR):
    return ui.analyze(data, corr)


def section(typ, body):
    n = len(body) + 4
    return struct.pack("<I", n)[:3] + bytes([typ]) + body + b"\x00" * (-n % 4)


def pe(data):
    return section(0x10, data)


def uiname(name):
    return section(0x15, (name + "\x00").encode("utf-16le"))


def lzma_alone(raw, size=None):
    c = lzma.compress(raw, format=lzma.FORMAT_ALONE, filters=[{"id": lzma.FILTER_LZMA1, "dict_size": 1 << 20}])
    # Python 的編碼器寫「大小未知＋結束標記」；size 給了就改寫標頭的大小欄（測宣告的大小）
    return c if size is None else c[:5] + struct.pack("<Q", size) + c[13:]


def guided_lzma(inner, size=None, guid=None):
    stream = lzma_alone(inner, size)
    return section(0x02, (guid or ui.GUID_LZMA) + struct.pack("<HH", 24, 0x01) + stream)


def ffs(body, ftype=0x07, guid=GUID):
    n = 24 + len(body)
    return guid + b"\x00\x00" + bytes([ftype, 0]) + struct.pack("<I", n)[:3] + b"\xf8" + body + b"\xff" * (-n % 8)


def fv(files, pad=64):
    hdr = b"\x00" * 16 + ui.FFS2 + b"\x00" * 8 + b"_FVH" + struct.pack("<I", 0x4feff) + struct.pack("<HHHBB", 72, 0, 0, 0, 2) + \
        struct.pack("<II", 4, 0x1000) + b"\x00" * 8
    assert len(hdr) == 72, len(hdr)
    body = b"".join(files) + b"\xff" * pad
    total = len(hdr) + len(body)
    return hdr[:32] + struct.pack("<Q", total) + hdr[40:] + body


def image(inner_sections, name="TlsDxe"):
    """FV 內一個 DXE driver：UI 名稱＋GUID-defined LZMA section（裡面是 PE32）。"""
    return fv([ffs(uiname(name) + guided_lzma(inner_sections))])


OSSL = b"".join(b"ossl_%s_%d\x00" % (n, i) for i in range(4) for n in (b"rand", b"bn_alloc")) + b"ECDHE-RSA-AES128-GCM-SHA256\x00"
FILLER = bytes(range(32, 120)) * 50 + b"\x00"


def lib(res, name):
    return res["libraries"][name]["result"]


def test_present_openssl_inside_lzma_and_mbedtls_absent():
    res = an(image(pe(FILLER + OSSL + b"CryptoPkg/Library/OpensslLib/OpensslStub/rand_pool.c\x00")))
    assert res["method"] == "fv_parse" and res["complete"] and not res["undecoded"]
    assert lib(res, "openssl") == "present" and lib(res, "mbedtls") == "absent"
    assert res["libraries"]["openssl"]["distinct_paths"] == 1
    assert res["layers"] and res["layers"][0]["kind"] == "lzma" and res["decompressed_total"] > 0
    assert any(m["ui_name"] == "TlsDxe" for m in res["modules"])
    assert res["libraries"]["openssl"]["top_modules"][0] == "TlsDxe"


def test_present_mbedtls_by_strings_and_ciphersuite():
    mb = b"mbedtls_ssl_init\x00mbedtls_x509_crt_parse\x00MBEDTLS_ERR_SSL_WANT_READ\x00TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256\x00"
    res = an(image(pe(FILLER + mb)))
    assert lib(res, "mbedtls") == "present" and lib(res, "openssl") == "absent"


def test_embed_is_not_mbed():
    """不分大小寫的 "mbed" 會命中 asn1_item_embed_d2i、EmbeddedPkg：樣式前要求不是英文字母，所以不算。"""
    res = an(image(pe(FILLER + b"asn1_item_embed_d2i\x00EmbeddedPkg/Library/Foo.c\x00Embedded\x00")))
    assert lib(res, "mbedtls") == "absent" and res["libraries"]["mbedtls"]["strings"] == 0


def test_weak_evidence_is_not_absent_and_not_present():
    res = an(image(pe(FILLER + b"mbedtls_ssl_init\x00")))
    assert lib(res, "mbedtls") == "not_assessed" and "weak evidence" in res["libraries"]["mbedtls"]["reason"]


def test_undecodable_lzma_section_is_not_assessed_never_absent():
    img = bytearray(image(pe(FILLER)))
    i = img.index(lzma_alone(b"x")[:5])
    for k in range(i + 20, i + 60):
        img[k] ^= 0xFF
    res = an(bytes(img))
    assert not res["complete"] and res["undecoded"]
    assert lib(res, "openssl") == "not_assessed" and lib(res, "mbedtls") == "not_assessed"


def test_standard_compression_section_is_recorded_unsupported():
    comp = section(0x01, struct.pack("<IB", 100, 1) + b"\x00" * 20)
    res = an(fv([ffs(uiname("X") + comp)]))
    assert not res["complete"] and any("EFI_STANDARD_COMPRESSION" in u["reason"] for u in res["undecoded"])
    assert lib(res, "mbedtls") == "not_assessed"


def test_unknown_required_guid_section_is_not_assessed():
    sec = section(0x02, b"\x11" * 16 + struct.pack("<HH", 24, 0x01) + b"data")
    res = an(fv([ffs(sec)]))
    assert lib(res, "openssl") == "not_assessed"


def test_decompression_bomb_declared_size_over_limit(monkeypatch):
    monkeypatch.setattr(ui, "MAX_LAYER", 1 << 20)
    res = an(fv([ffs(guided_lzma(pe(b"\x00" * (4 << 20)), size=4 << 20))]))
    assert not res["complete"] and any("exceeds the limit" in u["reason"] for u in res["undecoded"])
    assert res["decompressed_total"] == 0 and lib(res, "mbedtls") == "not_assessed"


def test_decompression_bomb_lying_header_is_not_trusted():
    """標頭宣告很小、實際串流解出更多：用 max_length 截斷並判為未解開。"""
    res = an(fv([ffs(guided_lzma(pe(b"A" * 100000), size=1000))]))
    assert not res["complete"] and any("LZMA" in u["reason"] for u in res["undecoded"])


def test_total_budget_limit(monkeypatch):
    monkeypatch.setattr(ui, "MAX_TOTAL", 100000)
    blob = pe(bytes(range(256)) * 300)
    res = an(fv([ffs(guided_lzma(blob)), ffs(guided_lzma(blob), guid=b"\x01" * 16)]))
    assert not res["complete"] and res["undecoded"] and res["decompressed_total"] <= 100000


def test_depth_limit(monkeypatch):
    monkeypatch.setattr(ui, "MAX_DEPTH", 1)
    res = an(fv([ffs(section(0x17, fv([ffs(guided_lzma(pe(FILLER)))])))]))
    assert not res["complete"] and any("deeper" in u["reason"] for u in res["undecoded"])


def test_nested_fv_image_is_parsed():
    inner = fv([ffs(uiname("Inner") + guided_lzma(pe(FILLER + OSSL)))])
    res = an(fv([ffs(section(0x17, inner), ftype=0x0B)]))
    assert res["complete"] and res["fvs"] == 2 and lib(res, "openssl") == "present"


def test_fallback_header_scan_never_gives_absent():
    junk = b"not a firmware volume " * 10 + lzma_alone(FILLER + OSSL) + b"\x00" * 100
    res = an(junk)
    assert res["method"] == "header_scan" and not res["complete"] and lib(res, "openssl") == "present"
    assert lib(res, "mbedtls") == "not_assessed"
    res = an(b"\xff" * 4096)
    assert res["method"] == "header_scan" and lib(res, "openssl") == "not_assessed"


def test_blank_outside_fv_is_fine_but_data_outside_is_flagged():
    base = image(pe(FILLER))
    assert lib(an(base + b"\xff" * 512), "mbedtls") == "absent"
    res = an(base + os.urandom(512))
    assert not res["complete"] and lib(res, "mbedtls") == "not_assessed"


def test_combine_needs_every_image():
    a, p, n = [{"path": x, "libraries": {"openssl": {"result": r}, "mbedtls": {"result": r}}} for x, r in (("a", "absent"), ("p", "present"), ("n", "not_assessed"))]
    assert ui.combine([a, a])["mbedtls"]["result"] == "absent"
    assert ui.combine([a, p])["mbedtls"]["result"] == "present" and ui.combine([a, p])["mbedtls"]["present_in"] == ["p"]
    assert ui.combine([a, n])["mbedtls"]["result"] == "not_assessed"
    assert ui.combine([a, {"path": "x"}])["mbedtls"]["result"] == "not_assessed" and ui.combine([]) == {}


# ---------- bootloader_coverage.uefi-check 輸出 ----------

def test_uefi_check_records_libraries(tmp_path):
    d = tmp_path / "Tool" / "bootloader"
    d.mkdir(parents=True)
    (d / "uefi_a.bin").write_bytes(image(pe(FILLER + OSSL)))
    (d / "uefi_b.bin").write_bytes(image(pe(FILLER)))
    t = dsc_tree(tmp_path / "tree", "CryptoPkg/Library/OpensslLib/OpensslLib.inf")
    inv = {"bootloader": [{"path": f"Tool/bootloader/{n}", "type": "file"} for n in ("uefi_a.bin", "uefi_b.bin")]}
    res0 = bc.run_uefi_check(inv, str(t), directory=str(tmp_path))      # 沒給 DSC：Mbed TLS 沒有佐證，不能 absent
    assert res0["libraries"]["mbedtls"]["result"] == "not_assessed" and "no platform DSC" in res0["corroboration"]["mbedtls"]["reason"]
    res = bc.run_uefi_check(inv, str(t), directory=str(tmp_path), platform_dsc=["Platform.dsc"])
    assert res["libraries"]["openssl"]["result"] == "present" and res["libraries"]["mbedtls"]["result"] == "absent"
    assert res["corroboration"]["mbedtls"]["ok"] and "Platform.dsc:" in res["corroboration"]["mbedtls"]["evidence"][0]
    assert "capsules" in res["scope"]
    assert res["libraries"]["openssl"]["present_in"] == ["Tool/bootloader/uefi_a.bin"]
    assert all(i["bundled_libs"]["method"] == "fv_parse" for i in res["images"])


def dsc_tree(root, opensslinf=None, mbedinf=None):
    """假的 edk2 樹：Platform.dsc 把函式庫類別對應到指定的 INF（INF 檔也寫出來）。"""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    lines = ["[Defines]", "  PLATFORM_NAME = T", "[LibraryClasses]"]
    for cls, inf in (("OpensslLib", opensslinf), ("BaseCryptLib", "CryptoPkg/Library/BaseCryptLib/BaseCryptLib.inf"), ("MbedTlsLib", mbedinf)):
        if inf:
            lines.append(f"  {cls}|{inf}")
            (root / inf).parent.mkdir(parents=True, exist_ok=True)
            (root / inf).write_text("[Defines]\n  BASE_NAME = x\n")
    lines += ["[Components]", "  Foo/Foo.inf"]
    (root / "Foo").mkdir(exist_ok=True)
    (root / "Foo" / "Foo.inf").write_text("[LibraryClasses]\n  BaseCryptLib\n")
    (root / "Platform.dsc").write_text("\n".join(lines) + "\n")
    return root


def test_corroboration_from_dsc(tmp_path):
    t = dsc_tree(tmp_path / "a", "CryptoPkg/Library/OpensslLib/OpensslLib.inf")
    c = ui.corroborate(str(t), ["Platform.dsc"])
    assert c["mbedtls"]["ok"] and any("OpensslLib|" in e for e in c["mbedtls"]["evidence"]) and not c["openssl"]["ok"]
    t = dsc_tree(tmp_path / "b", "CryptoPkg/Library/OpensslLib/OpensslLib.inf", "CryptoPkg/Library/MbedTlsLib/MbedTlsLib.inf")
    assert not ui.corroborate(str(t), ["Platform.dsc"])["mbedtls"]["ok"]            # DSC 也把類別對應到 Mbed TLS
    assert not ui.corroborate(str(t), [])["mbedtls"]["ok"] and not ui.corroborate(str(t), ["Nope.dsc"])["mbedtls"]["ok"]
    t = dsc_tree(tmp_path / "c", None)                                               # 沒有任何類別對應到 OpenSSL：沒有佐證
    assert not ui.corroborate(str(t), ["Platform.dsc"])["mbedtls"]["ok"]


def test_absent_needs_corroboration_for_weak_markers():
    img = image(pe(FILLER))
    r = an(img, None)
    assert r["complete"] and lib(r, "mbedtls") == "not_assessed" and "corroboration" in r["libraries"]["mbedtls"]["reason"]
    r = an(img, {"mbedtls": {"ok": False, "reason": "DSC maps to MbedTls"}, "openssl": CORR["openssl"]})
    assert lib(r, "mbedtls") == "not_assessed" and "DSC maps to MbedTls" in r["libraries"]["mbedtls"]["reason"]
    r = an(img)
    assert lib(r, "mbedtls") == "absent" and r["libraries"]["mbedtls"]["corroboration"]["ok"]


# ---------- 結構壞掉 → 一定不能 absent（驗證者的反例） ----------

HIDDEN = guided_lzma(pe(FILLER + b"mbedtls_ssl_init\x00mbedtls_x509_crt_parse\x00MBEDTLS_ERR_SSL_WANT_READ\x00"))


def not_absent(img):
    r = an(img)
    assert not r["complete"], r["undecoded"]
    assert lib(r, "mbedtls") != "absent" and lib(r, "openssl") != "absent"
    return r


def test_counterexample_a_bad_extended_size_before_lzma_section():
    bad = GUID + b"\x00\x00" + bytes([0x07, 0x01]) + b"\x00\x00\x00" + b"\xf8" + struct.pack("<Q", 3)       # LARGE_FILE，擴充大小小於標頭
    not_absent(fv([bad, ffs(HIDDEN, guid=b"\x02" * 16)]))
    bad2 = GUID + b"\x00\x00" + bytes([0x07, 0x01]) + b"\x00\x00\x00" + b"\xf8"                              # 大檔標頭被截斷在 FV 尾端
    not_absent(fv([bad2], pad=0))


def test_counterexample_b_overstated_section_size():
    body = uiname("X") + HIDDEN
    body = body[:len(uiname("X"))] + struct.pack("<I", len(HIDDEN) + 4000)[:3] + body[len(uiname("X")) + 3:]       # LZMA section 的大小說謊
    not_absent(fv([ffs(body)]))


def test_counterexample_c_file_after_an_empty_header_gap():
    gap = b"\xff" * 24
    not_absent(fv([ffs(uiname("A") + pe(FILLER)), gap, ffs(HIDDEN, guid=b"\x03" * 16)]))


def test_counterexample_d_pad_file_with_content():
    not_absent(fv([ffs(lzma_alone(FILLER + b"mbedtls_ssl_init\x00mbedtls_x509_crt_parse\x00MBEDTLS_ERR_X\x00"), ftype=0xF0)]))
    r = an(fv([ffs(b"\xff" * 64, ftype=0xF0), ffs(uiname("A") + pe(FILLER))]))      # 空白的 PAD 檔沒問題
    assert r["complete"] and lib(r, "mbedtls") == "absent"


def test_counterexample_e_nested_fv_with_corrupt_signature():
    inner = fv([ffs(HIDDEN)]).replace(b"_FVH", b"_FVX", 1)
    not_absent(fv([ffs(section(0x17, inner), ftype=0x0B)]))


def test_counterexample_e2_nested_fv_followed_by_extra_bytes():
    inner = fv([ffs(uiname("In") + pe(FILLER))])
    not_absent(fv([ffs(section(0x17, inner + lzma_alone(FILLER + b"mbedtls_ssl_init\x00mbedtls_x509_crt_parse\x00MBEDTLS_ERR_X\x00")), ftype=0x0B)]))
    r = an(fv([ffs(section(0x17, inner), ftype=0x0B)]))
    assert r["complete"] and lib(r, "mbedtls") == "absent"


def test_fv_inside_lzma_layer_with_extra_bytes():
    inner = fv([ffs(uiname("In") + pe(FILLER))]) + lzma_alone(FILLER + b"mbedtls_x\x00")
    not_absent(fv([ffs(guided_lzma(section(0x17, inner)))]))


def test_trailing_bytes_after_last_section_are_not_clean():
    not_absent(fv([ffs(uiname("X") + pe(FILLER) + b"junk")]))


def test_analyze_never_raises_on_hostile_input(monkeypatch):
    r = ui.analyze(b"")
    assert not r["complete"] and lib(r, "mbedtls") == "not_assessed"
    monkeypatch.setattr(ui, "parse_fvs", lambda *a, **k: (_ for _ in ()).throw(OverflowError("x")))
    r = ui.analyze(image(pe(FILLER)), CORR)
    assert r["method"] == "header_scan" and lib(r, "mbedtls") == "not_assessed"
    monkeypatch.setattr(ui, "parse_fvs", lambda *a, **k: (_ for _ in ()).throw(TypeError("x")))
    assert ui.analyze(image(pe(FILLER)), CORR)["method"] == "header_scan"


def test_regex_patterns_are_linear_time():
    import time
    for blob in (b"1234/" * 20000, b"/" * 100000, b"TLS-RSA-" * 20000, b"mbedtls" * 20000, b"openssl/" * 20000, b"a1_" * 40000):
        t = time.time()
        sc = ui.Scan()
        sc.scan_bytes(blob)
        assert time.time() - t < 2.0, blob[:12]


def test_truncated_read_is_not_absent():
    r = bc.image_libs(image(pe(FILLER)), True)
    assert r["libraries"]["mbedtls"]["result"] == "not_assessed" and not r["complete"]


# ---------- VEX 效果（cra_report） ----------

def chk(result):
    lb = {"result": result, "distinct_strings": 136 if result == "present" else 0, "distinct_paths": 1 if result == "present" else 0,
          "strings": 5, "paths": 1, "reason": "r"}
    img = {"path": "bootloader/uefi_a.bin",
           "bundled_libs": {"method": "fv_parse", "complete": result != "not_assessed", "ffs_files": 193, "decompressed_total": 26935304,
                            "undecoded": [{"where": "image/x", "reason": "boom"}] if result == "not_assessed" else [], "libraries": {"openssl": lb}}}
    return {"schema": bc.CHECK_SCHEMA, "images": [img], "counts": {"MATCH": 1},
            "libraries": {"openssl": {"result": result, "images": 1, "present_in": [], "not_assessed_in": []}},
            "scope": bc.SCOPE_TEXT,
            "corroboration": {"openssl": {"ok": True, "reason": "r", "dsc": ["P/Platform.dsc"], "evidence": ["P/Platform.dsc:228: MbedTlsLib|x"]}}}


def rows_of(rep):
    d = json.loads((rep / "vulnerability-rows.json").read_text(encoding="utf-8"))
    return [r for r in d["rows"] if "bundled in UEFI" in (r.get("component") or "")]


def run_with_check(tmp_path, check, rules=None):
    u = make_uefi(tmp_path)
    put_grype(u, grype_json(ids=("CVE-2099-0001", "CVE-2099-0002")))
    proj, scan = make_project(tmp_path / "p", MIN_CFG), make_scan(tmp_path / "res" / "scan")
    os.replace(u, scan.parent / "uefi-source")
    if check is not None:
        write_json(scan.parent.parent / "uefi-binary-check.json", check)
    if rules:
        write_json(proj / "CRA" / "Config" / "vex-rules.json", {"schema": vx.RULES_SCHEMA, "rules": rules})
    r, s, rep = run(proj, scan)
    assert r.returncode in (0, 2), r.stdout + r.stderr
    return s, rep


R9M = {"id": "R9m", "description": "Bundled Mbed TLS (UEFI): built-in not confirmed", "author": "Alice", "date": "2026-11-02", "reason": "x",
       "match": {"scope": "all", "purl_prefix": ["pkg:generic/"]}, "set": {"state": "in_triage", "detail_template": "Under review ({cve})."}}


def decisions(rep):
    return [(r["id"], r["tier"], (r.get("vex") or {}).get("state"), (r.get("vex") or {}).get("rule"), (r.get("vex") or {}).get("detail")) for r in rows_of(rep)]


def test_absent_is_only_a_suggestion_ub1(tmp_path):
    """UB1 不改判定：沒有規則時列仍是未判定（tier 不變），有 R9m 時仍是 in_triage；只多一個 suggestion。"""
    s, rep = run_with_check(tmp_path / "a", chk("absent"))
    _, rep0 = run_with_check(tmp_path / "b", None)
    rows = rows_of(rep)
    assert len(rows) == 2 and [(x[1], x[2], x[3]) for x in decisions(rep)] == [(x[1], x[2], x[3]) for x in decisions(rep0)]
    for r in rows:
        assert r["uefi_image_check"]["result"] == "absent" and (r.get("vex") or {}).get("rule") != "UB1"
        sg = r["suggestion"]
        assert sg["rule"] == "UB1" and sg["state"] == "not_affected" and sg["justification"] == "code_not_present" and sg["needs"] == "RD confirmation"
        assert "contain no code or strings" in sg["detail"] and "fully decoded" in sg["detail"]
        assert "capsules" in sg["detail"] and "uefi_*.bin" in sg["detail"] and "P/Platform.dsc:228: MbedTlsLib|x" in sg["detail"]
    assert s["product_sbom"]["uefi_source"]["image_libs"]["openssl"]["result"] == "absent"


def test_absent_keeps_the_triage_rule_decision_and_adds_suggestion(tmp_path):
    s, rep = run_with_check(tmp_path / "a", chk("absent"), [R9M])
    s0, _ = run_with_check(tmp_path / "b", None, [R9M])
    for r in rows_of(rep):
        assert r["vex"]["rule"] == "R9m" and r["vex"]["state"] == "in_triage" and r["tier"] != "accepted"
        assert r["suggestion"]["rule"] == "UB1"
    rule = lambda sm: [x for x in sm["vex"]["rules"]["rules"] if x["id"] == "R9m"][0]["applied"]
    assert rule(s) == rule(s0)


def test_present_suggests_exploitable_only_for_built_in_not_confirmed(tmp_path):
    _, rep = run_with_check(tmp_path, chk("present"), [R9M])
    for r in rows_of(rep):
        assert r["vex"]["rule"] == "R9m" and r["vex"]["state"] == "in_triage"          # 判定不變
        assert r["suggestion"]["rule"] == "UB2" and r["suggestion"]["state"] == "exploitable" and r["suggestion"]["needs"] == "RD confirmation"


def test_present_without_that_rule_has_no_suggestion(tmp_path):
    r9 = dict(R9M, id="R9", set={"state": "exploitable", "response": ["update"], "detail_template": "Fixed in {fix_version}."})
    _, rep = run_with_check(tmp_path / "a", chk("present"), [r9])
    assert {r["vex"]["rule"] for r in rows_of(rep)} == {"R9"} and all("suggestion" not in r for r in rows_of(rep))
    _, rep = run_with_check(tmp_path / "b", chk("present"))
    assert all("suggestion" not in r for r in rows_of(rep))


def test_vex_files_and_customer_data_do_not_contain_suggestions(tmp_path):
    _, rep = run_with_check(tmp_path / "a", chk("absent"), [R9M])
    for name in ("vex.cdx.json", "vex.openvex.json"):
        t = (rep / name).read_text(encoding="utf-8")
        assert "UB1" not in t and "suggestion" not in t.lower() and "UEFI image check" not in t and "R9m" in t
    assert "suggestion" in (rep / "vulnerability-rows.json").read_text(encoding="utf-8")


def test_human_decision_still_wins_and_closed_rows_get_no_ub1_suggestion():
    row = {"id": "CVE-1", "uefi_image_check": {"result": "absent", "label": "Mbed TLS", "evidence": {}}}
    vx.uefi_image_suggestion(row, {"source": "annotation", "state": "not_affected"})
    assert "suggestion" not in row
    vx.uefi_image_suggestion(row, {"source": "annotation", "state": "exploitable"})
    assert row["suggestion"]["state"] == "not_affected"              # 人判斷受影響、映像檢查建議不受影響：只是建議，判定仍是人的
    vx.uefi_image_suggestion(dict(row, uefi_image_check={"result": "not_assessed"}), None)


def test_not_assessed_changes_nothing_and_says_why(tmp_path):
    s, rep = run_with_check(tmp_path, chk("not_assessed"), [R9M])
    for r in rows_of(rep):
        assert r["vex"]["rule"] == "R9m" and r["vex"]["state"] == "in_triage" and r["uefi_image_check"]["result"] == "not_assessed"
        assert "suggestion" not in r
    assert any("not_assessed" in a and "boom" in a for a in s["product_sbom"]["uefi_source"]["attention"])


def test_without_check_result_output_is_unchanged(tmp_path):
    """沒有 uefi-binary-check.json、或它沒有 libraries 欄：列沒有 uefi_image_check，判定照舊。"""
    _, rep0 = run_with_check(tmp_path / "a", None, [R9M])
    old = chk("absent")
    del old["libraries"]
    _, rep1 = run_with_check(tmp_path / "b", old, [R9M])
    r0, r1 = rows_of(rep0), rows_of(rep1)
    r1 = [{k: v for k, v in r.items() if k != "uefi_build_check"} for r in r1]      # 這個檢查結果檔本來就會加上 build check 一行
    assert r0 == r1 and all("uefi_image_check" not in r for r in r0) and all(r["vex"]["rule"] == "R9m" for r in r0)


def test_malformed_libraries_are_ignored(tmp_path):
    bad = chk("absent")
    bad["libraries"] = {"openssl": {"result": "safe"}, "x": 3}
    _, rep = run_with_check(tmp_path, bad, [R9M])
    assert all(r["vex"]["rule"] == "R9m" for r in rows_of(rep))


def test_ub2_only_for_built_in_not_confirmed_in_triage():
    row = {"id": "CVE-1", "uefi_image_check": {"result": "present", "label": "Mbed TLS", "evidence": {}}}
    other = {"source": "rule", "state": "in_triage", "rule": "R7", "detail": "Under review for another reason (bulk rule R7: x)"}
    vx.uefi_image_suggestion(row, other)
    assert "suggestion" not in row
    nc = {"source": "rule", "state": "in_triage", "rule": "R9m", "detail": "x (bulk rule R9m: Bundled Mbed TLS (UEFI): built-in not confirmed)"}
    vx.uefi_image_suggestion(row, nc)
    assert row["suggestion"]["rule"] == "UB2" and row["suggestion"]["state"] == "exploitable"
    vx.uefi_image_suggestion(row, {"source": "annotation", "state": "in_triage", "detail": "built-in not confirmed"})
    assert "suggestion" not in row                                   # 人的判定不建議


# ---------- DSC 佐證：未解析的 include ----------

OSSL_MAP = "[LibraryClasses]\n  OpensslLib|CryptoPkg/Library/OpensslLib/OpensslLib.inf\n"


def raw_tree(root, dsc_text, files=None):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    (root / "CryptoPkg/Library/OpensslLib").mkdir(parents=True, exist_ok=True)
    (root / "CryptoPkg/Library/OpensslLib/OpensslLib.inf").write_text("[Defines]\n  BASE_NAME = x\n")
    (root / "Platform.dsc").write_text(dsc_text)
    for name, text in (files or {}).items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)
    return root


def test_unresolved_build_time_include_blocks_corroboration(tmp_path):
    """驗證者的反例：先對應 OpensslLib，再 !include 一個建置時才產生的檔案（可能把 OpensslLib 改對應到 MbedTlsLib）。"""
    t = raw_tree(tmp_path / "a", OSSL_MAP + "!include $(GEN_DIR)/late.dsc.inc\n")
    c = ui.corroborate(str(t), ["Platform.dsc"])["mbedtls"]
    assert not c["ok"] and c["unresolved_includes_count"] == 1 and "late.dsc.inc" in c["reason"]
    r = an(image(pe(FILLER)), {"mbedtls": c, "openssl": c})
    assert lib(r, "mbedtls") == "not_assessed"
    t = raw_tree(tmp_path / "b", OSSL_MAP + "!include late.dsc.inc\n")                      # 檔案不存在
    assert not ui.corroborate(str(t), ["Platform.dsc"])["mbedtls"]["ok"]


def test_inactive_conditional_include_does_not_block(tmp_path):
    txt = OSSL_MAP + "!ifdef CONFIG_FMP_PROD\n!include $(CONFIG_FMP_PROD_PATH)\n!endif\n"
    t = raw_tree(tmp_path / "a", txt)
    assert not ui.corroborate(str(t), ["Platform.dsc"])["mbedtls"]["ok"]                    # 沒有 Kconfig 設定：條件算不出來 → 擋住
    cfg = tmp_path / "config.dsc.inc"
    cfg.write_text("# CONFIG_FMP_PROD is not set\nCONFIG_SOC_T23X=y\n")
    c = ui.corroborate(str(t), ["Platform.dsc"], [str(cfg)])["mbedtls"]
    assert c["ok"] and c["config_complete"] and c["defines_files"] == [cfg.parent.name + "/" + cfg.name] and c["unresolved_includes_count"] == 0
    cfg.write_text("CONFIG_FMP_PROD=y\nCONFIG_FMP_PROD_PATH=/dev/null\n")                      # 條件成立、路徑是 /dev/null：空的 include
    assert ui.corroborate(str(t), ["Platform.dsc"], [str(cfg)])["mbedtls"]["ok"]
    cfg.write_text("CONFIG_FMP_PROD=y\nCONFIG_FMP_PROD_PATH=certs/prod.inc\n")                 # 條件成立、檔案不存在：擋住
    assert not ui.corroborate(str(t), ["Platform.dsc"], [str(cfg)])["mbedtls"]["ok"]


def test_config_dsc_inc_in_the_tree_makes_conditions_definite(tmp_path):
    txt = OSSL_MAP + "!include config.dsc.inc\n!ifdef CONFIG_FMP_PROD\n!include $(CONFIG_FMP_PROD_PATH)\n!endif\n"
    t = raw_tree(tmp_path / "a", txt, {"nvidia-config/x/config.dsc.inc": "# CONFIG_FMP_PROD is not set\nCONFIG_SOC_T23X=y\n"})
    c = ui.corroborate(str(t), ["Platform.dsc"])["mbedtls"]
    assert c["ok"] and c["config_complete"]


def test_dsc_maps_to_mbedtls_through_included_file_is_found(tmp_path):
    t = raw_tree(tmp_path / "a", OSSL_MAP + "!include late.dsc.inc\n",
                 {"late.dsc.inc": "[LibraryClasses]\n  OpensslLib|CryptoPkg/Library/MbedTlsLib/MbedTlsLib.inf\n"})
    assert not ui.corroborate(str(t), ["Platform.dsc"])["mbedtls"]["ok"]


def test_missing_inf_is_a_caveat_not_a_blocker(tmp_path):
    t = raw_tree(tmp_path / "a", OSSL_MAP + "[Components]\n  Gone/Missing.inf\n")
    c = ui.corroborate(str(t), ["Platform.dsc"])["mbedtls"]
    assert c["ok"] and c["missing_inf_count"] == 1 and c["missing_inf_first"][0].startswith("Gone/Missing.inf (named at")
    detail = vx.uefi_image_detail({"result": "absent", "label": "Mbed TLS", "evidence": {"corroboration": dict(c, defines_files=[]), "images": 1}})
    assert "Caveat: 1 INF file(s)" in detail and "Missing.inf" in detail


def test_unresolved_includes_reach_the_json(tmp_path):
    t = raw_tree(tmp_path / "t", OSSL_MAP + "!include $(GEN_DIR)/late.dsc.inc\n")
    d = tmp_path / "Tool" / "bootloader"
    d.mkdir(parents=True)
    (d / "uefi_a.bin").write_bytes(image(pe(FILLER)))
    inv = {"bootloader": [{"path": "Tool/bootloader/uefi_a.bin", "type": "file"}]}
    res = bc.run_uefi_check(inv, str(t), directory=str(tmp_path), platform_dsc=["Platform.dsc"])
    assert res["libraries"]["mbedtls"]["result"] == "not_assessed" and res["corroboration"]["mbedtls"]["unresolved_includes_count"] == 1


def test_generated_config_include_is_covered_by_supplied_defines(tmp_path):
    """原始碼包裡沒有建置時產生的 config.dsc.inc：給了 Kconfig 設定檔（--platform-defines）就視為涵蓋；沒給就擋住。"""
    txt = OSSL_MAP + "!include config.dsc.inc\n!ifdef CONFIG_FMP_PROD\n!include $(CONFIG_FMP_PROD_PATH)\n!endif\n"
    t = raw_tree(tmp_path / "a", txt)
    assert not ui.corroborate(str(t), ["Platform.dsc"])["mbedtls"]["ok"]
    cfg = tmp_path / "cfg.dsc.inc"
    cfg.write_text("# CONFIG_FMP_PROD is not set\nCONFIG_SOC_T23X=y\n")
    assert ui.corroborate(str(t), ["Platform.dsc"], [str(cfg)])["mbedtls"]["ok"]
    assert not ui.corroborate(str(t), ["Platform.dsc"], [str(tmp_path / "nope")])["mbedtls"]["ok"]       # 設定檔讀不到 = 沒給
    t2 = raw_tree(tmp_path / "b", OSSL_MAP + "!include other.dsc.inc\n")
    assert not ui.corroborate(str(t2), ["Platform.dsc"], [str(cfg)])["mbedtls"]["ok"]               # 只有 config.dsc.inc 這個名字例外


# ---------- 報告：建議顯示在規則說明、漏洞清單備註、給 RD 的表 ----------

def test_report_package_shows_suggestions_without_changing_decisions():
    import report_package as rp
    base = {"id": "CVE-1", "component": "Mbed TLS 3.6.2 (bundled in UEFI)", "version": "3.6.2", "tier": "p3", "exposed": None, "fix_versions": [],
            "vex": {"state": "in_triage", "source": "rule", "rule": "R9m", "markers": []}}
    ub1 = dict(base, suggestion={"rule": "UB1", "state": "not_affected", "justification": "code_not_present", "detail": "Mbed TLS is absent (bulk rule UB1: x)",
                                 "needs": "RD confirmation"})
    ub2 = dict(base, id="CVE-2", suggestion={"rule": "UB2", "state": "exploitable", "detail": "present", "needs": "RD confirmation"})
    plain = dict(base, id="CVE-3")
    doc = {"rows": [ub1, ub2, plain], "have_findings": True}
    assert rp.rule_code(ub1) == "R9m"                                        # 判定仍是原本的規則
    row = rp.human_row(ub1, {}, (None, None, None))
    assert row[0] == rp.T_TRACK and "建議：不受影響（UEFI 映像裡沒有這個函式庫，見佐證）；需 RD 確認後才改判定" in row[15]
    assert "建議：受影響" in rp.human_row(ub2, {}, (None, None, None))[15] and "建議" not in rp.human_row(plain, {}, (None, None, None))[15]
    sh = rp.rules_sheet(doc, {})
    byrule = {r[0]: r for r in sh.rows}
    assert byrule["UB1"][2] == "建議（需 RD 確認）" and byrule["UB1"][7] == 1 and byrule["UB2"][2] == "建議（需 RD 確認）" and byrule["UB2"][7] == 1
    assert byrule["UB1"][1] == "（建議，不改初判）" and byrule["R9m"][1] == "判斷中－UEFI 內 Mbed TLS 待確認"
    assert byrule["R9m"][7] == 3
    lr = rp.list_row(ub1, {}, (None, None, None))                           # 有建議的列：初判不變，建議文字在依據與備註
    assert lr[0] == "判斷中－UEFI 內 Mbed TLS 待確認" and "建議：不受影響" in lr[10]
    ss = rp.suggestion_sheet(doc)
    assert ss.name == "建議（需 RD 確認）" and len(ss.rows) == 2 and ss.rows[0][1] == "CVE-1" and "評估中（R9m）" in ss.rows[0][3]
    assert "need" not in str(ss.rows[0][5]) and "bulk rule" not in ss.rows[0][5]
    assert rp.suggestion_sheet({"rows": [plain]}) is None
