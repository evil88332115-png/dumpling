"""UEFI 內建函式庫的後續：Mbed TLS 的兩個 CPE vendor、平台 DSC 判定「有沒有編進韌體」（uefi_dsc.py）、grype 結果的核對。
全部用假樹（只放需要的幾個檔案）與照 Grype 輸出形狀寫的假資料；沒有任何產品資料。"""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import uefi_bundled as ub  # noqa: E402
import uefi_dsc as ud  # noqa: E402
import uefi_source as us  # noqa: E402
from test_cra_report import MIN_CFG, make_project, make_scan, run, write_json  # noqa: E402
from test_uefi_bundled import fake_grype, grype_json, put_grype, report  # noqa: E402
from test_uefi_source import git, w  # noqa: E402

CLI = HERE.parent / "uefi_source.py"
SSL, MBED = "CryptoPkg/Library/OpensslLib/OpensslLib.inf", "CryptoPkg/Library/MbedTlsLib/MbedTlsLib.inf"


def inf(path, uses=(), provides=None):
    txt = "[Defines]\n  INF_VERSION = 1.27\n" + (f"  LIBRARY_CLASS = {provides}\n" if provides else "") + "[LibraryClasses]\n" + "".join(f"  {c}\n" for c in uses)
    return w(path[0], txt) if isinstance(path, tuple) else path, txt


def platform(root, dsc, files=None):
    """root：樹（edk2 的形狀，最上層有 MdePkg）。files：{路徑: 文字}（INF 與 DSC）。"""
    root = Path(root)
    w(root / "MdePkg" / "MdePkg.dec", "[Defines]\n")
    for rel, text in (files or {}).items():
        w(root / rel, text)
    w(root / "Platform" / "P.dsc", dsc)
    return root


INF = {
    SSL: "[Defines]\n  LIBRARY_CLASS = OpensslLib\n",
    "CryptoPkg/Library/BaseCryptLib/BaseCryptLib.inf": "[Defines]\n  LIBRARY_CLASS = BaseCryptLib\n[LibraryClasses]\n  OpensslLib\n",
    MBED: "[Defines]\n  LIBRARY_CLASS = MbedTlsLib\n",
    "CryptoPkg/Library/BaseCryptLibMbedTls/BaseCryptLib.inf": "[Defines]\n  LIBRARY_CLASS = BaseCryptLib\n[LibraryClasses]\n  MbedTlsLib\n",
    "App/App.inf": "[Defines]\n  BASE_NAME = App\n[LibraryClasses]\n  BaseCryptLib\n",
    "App/Plain.inf": "[Defines]\n  BASE_NAME = Plain\n[LibraryClasses]\n  DebugLib\n",
    "Lib/Debug.inf": "[Defines]\n  LIBRARY_CLASS = DebugLib\n",
}
DSC_OPENSSL = """[Defines]
  PLATFORM_NAME = P
[LibraryClasses]
  DebugLib|Lib/Debug.inf
  OpensslLib|CryptoPkg/Library/OpensslLib/OpensslLib.inf
  BaseCryptLib|CryptoPkg/Library/BaseCryptLib/BaseCryptLib.inf
[Components]
  App/App.inf
"""


def analyze(tmp_path, dsc, defines=None, known=False, files=None, dsc_rels=("Platform/P.dsc",)):
    t = platform(tmp_path / "t", dsc, {**INF, **(files or {})})
    return ud.analyze(us.Tree(str(t)), list(dsc_rels), defines, known)


# ---------- uefi_dsc.py ----------

def test_openssl_yes_with_evidence_chain_and_mbedtls_only_unknown(tmp_path):
    r = analyze(tmp_path, DSC_OPENSSL)
    o, m = r["libs"]["openssl"], r["libs"]["mbedtls"]
    assert o["state"] == "yes" and any("Platform/P.dsc:" in e and "App/App.inf" in e for e in o["evidence"])
    assert any("class OpensslLib" in e and "OpensslLib.inf" in e for e in o["evidence"])
    # 沒有走到不等於沒有編進去：沒有「no」，只有事實提示（reached=False）與原因
    assert m["state"] == "unknown" and m["reached"] is False
    assert "absence is not proven" in m["reasons"][0] and "No path to MbedTlsLib was found" in m["reasons"][0]
    assert m["evidence"][0].startswith("fact only, not a conclusion") and any("BaseCryptLib|" in e for e in m["evidence"])
    assert "none is under" not in " ".join(m["evidence"] + m["reasons"]) or "fact only" in m["evidence"][0]


def test_mbedtls_yes_when_the_platform_selects_the_mbedtls_crypto_lib(tmp_path):
    dsc = DSC_OPENSSL.replace("OpensslLib|CryptoPkg/Library/OpensslLib/OpensslLib.inf", f"MbedTlsLib|{MBED}") \
        .replace("BaseCryptLib|CryptoPkg/Library/BaseCryptLib/BaseCryptLib.inf", "BaseCryptLib|CryptoPkg/Library/BaseCryptLibMbedTls/BaseCryptLib.inf")
    r = analyze(tmp_path, dsc)
    assert r["libs"]["mbedtls"]["state"] == "yes" and r["libs"]["openssl"]["state"] == "unknown" and r["libs"]["openssl"]["reached"] is False


def test_module_that_does_not_use_crypto_is_still_only_unknown(tmp_path):
    r = analyze(tmp_path, DSC_OPENSSL.replace("App/App.inf", "App/Plain.inf"))
    assert {k: (v["state"], v["reached"]) for k, v in r["libs"].items()} == {"openssl": ("unknown", False), "mbedtls": ("unknown", False)}


def test_only_under_a_condition_is_unknown_without_macros_and_yes_with_them(tmp_path):
    dsc = DSC_OPENSSL.replace("[Components]\n  App/App.inf\n", "[Components]\n!ifdef CONFIG_TLS\n  App/App.inf\n!endif\n")
    unknown = analyze(tmp_path / "a", dsc)                                    # 巨集不知道 → maybe → 不下結論
    assert unknown["libs"]["openssl"]["state"] == "unknown" and "may or may not be active" in unknown["libs"]["openssl"]["reasons"][0]
    on = analyze(tmp_path / "b", dsc, {"CONFIG_TLS": "y"}, True)
    assert on["libs"]["openssl"]["state"] == "yes"
    off = analyze(tmp_path / "c", dsc, {}, True)                              # 巨集完整、沒定義 → 這行不生效 → 走不到，但仍只是 unknown
    assert off["libs"]["openssl"]["state"] == "unknown" and off["libs"]["openssl"]["reached"] is False


def test_if_expressions_else_and_defines_in_the_dsc(tmp_path):
    dsc = DSC_OPENSSL.replace("[Components]\n  App/App.inf\n", """DEFINE USE_TLS = FALSE
[Components]
!if $(TARGET) == RELEASE && $(USE_TLS) == TRUE
  App/App.inf
!elseif $(TARGET) == RELEASE
  App/Plain.inf
!else
  App/App.inf
!endif
""")
    a = analyze(tmp_path / "a", dsc, {"TARGET": "RELEASE"}, True)["libs"]["openssl"]
    assert a["state"] == "unknown" and a["reached"] is False
    assert analyze(tmp_path / "b", dsc, {"TARGET": "DEBUG"}, True)["libs"]["openssl"]["state"] == "yes"
    assert analyze(tmp_path / "c", dsc, {}, False)["libs"]["openssl"]["state"] == "unknown"       # TARGET 不知道
    garbage = DSC_OPENSSL.replace("[Components]\n  App/App.inf\n", "[Components]\n!if ((( @@\n  App/App.inf\n!endif\n")
    assert analyze(tmp_path / "d", garbage, {}, True)["libs"]["openssl"]["state"] == "unknown"     # 運算式看不懂 → maybe


def test_include_is_read_and_unresolved_include_is_listed(tmp_path):
    dsc = DSC_OPENSSL.replace("[Components]\n  App/App.inf\n", "[Components]\n!include more.dsc.inc\n")
    r = analyze(tmp_path / "a", dsc, files={"Platform/more.dsc.inc": "  App/App.inf\n"})
    assert r["libs"]["openssl"]["state"] == "yes" and r["files_read"] == 2
    r = analyze(tmp_path / "b", dsc.replace("more.dsc.inc", "missing.inc"))
    m = r["libs"]["mbedtls"]
    assert m["state"] == "unknown" and "unresolved item" in m["reasons"][0] and m["unresolved"]
    r = analyze(tmp_path / "c", dsc.replace("more.dsc.inc", "/dev/null"))
    assert r["libs"]["mbedtls"]["state"] == "unknown" and r["libs"]["mbedtls"]["reached"] is False


def test_missing_inf_is_listed_as_unresolved_only_when_used(tmp_path):
    dsc = DSC_OPENSSL.replace("[LibraryClasses]\n", "[LibraryClasses]\n  Unused|Nowhere/Unused.inf\n  Ghost|Nowhere/Ghost.inf\n")
    a = analyze(tmp_path / "a", dsc)["libs"]["mbedtls"]
    assert a["state"] == "unknown" and a["unresolved"] == []                                       # 沒有人用的類別：缺的 INF 不算
    used = {"App/App.inf": "[Defines]\n[LibraryClasses]\n  BaseCryptLib\n  Ghost\n"}
    r = analyze(tmp_path / "b", dsc, files=used)
    assert r["libs"]["mbedtls"]["state"] == "unknown" and "Ghost" in r["libs"]["mbedtls"]["reasons"][0]
    assert r["libs"]["openssl"]["state"] == "yes"                                                 # 有確定的鏈就是 yes


def test_inf_cap_is_recorded_as_a_problem(tmp_path, monkeypatch):
    monkeypatch.setattr(ud, "MAX_INFS", 2)
    r = analyze(tmp_path, DSC_OPENSSL)
    assert any("超過上限" in x for x in r["problems"])
    assert r["libs"]["mbedtls"]["state"] == "unknown" and "unresolved item" in r["libs"]["mbedtls"]["reasons"][0]


def test_analysis_never_returns_no(tmp_path):
    for i, dsc in enumerate((DSC_OPENSSL, DSC_OPENSSL.replace("App/App.inf", "App/Plain.inf"), "[Components]\n", DSC_OPENSSL.replace("Debug.inf", "Nope.inf"))):
        for known in (True, False):
            r = analyze(tmp_path / f"{i}{known}", dsc, {}, known)
            assert {v["state"] for v in r["libs"].values()} <= {"yes", "unknown"}
    assert {v["state"] for v in ud.analyze(us.Tree(str(tmp_path)), []).get("libs", {}).values()} == {"unknown"}


def test_ambiguous_class_mapping_is_not_sure(tmp_path):
    dsc = DSC_OPENSSL.replace("OpensslLib|CryptoPkg/Library/OpensslLib/OpensslLib.inf", "OpensslLib|CryptoPkg/Library/OpensslLib/OpensslLib.inf\n"
                              "!ifdef X\n  OpensslLib|Lib/Debug.inf\n!endif")
    assert analyze(tmp_path, dsc)["libs"]["openssl"]["state"] == "unknown"


def test_per_module_library_override_and_null_library(tmp_path):
    dsc = DSC_OPENSSL.replace("App/App.inf\n", "App/Plain.inf {\n    <LibraryClasses>\n      DebugLib|CryptoPkg/Library/BaseCryptLib/BaseCryptLib.inf\n  }\n")
    r = analyze(tmp_path, dsc)
    assert r["libs"]["openssl"]["state"] in ("unknown", "yes")      # 覆寫讓 DebugLib 對應兩個 INF → 不是 sure，也不是 no
    assert r["libs"]["openssl"]["state"] != "no"


def test_no_dsc_is_unknown(tmp_path):
    r = ud.analyze(us.Tree(str(platform(tmp_path / "t", DSC_OPENSSL, INF))), [])
    assert r["libs"]["openssl"]["state"] == "unknown" and r["libs"]["mbedtls"]["state"] == "unknown"


# ---------- uefi_source.py：--platform-dsc、建置記錄 ----------

def tree_with(tmp, dsc=DSC_OPENSSL, logs=None, mbed="3.6.2"):
    t = Path(tmp) / "t"
    w(t / "MdePkg" / "MdePkg.dec", "[Defines]\n")
    for rel, text in INF.items():
        w(t / rel, text)
    w(t / "Platform" / "P.dsc", dsc)
    w(t / us.OPENSSL_SUB / "VERSION.dat", 'MAJOR=3\nMINOR=4\nPATCH=1\nPRE_RELEASE_TAG=\nBUILD_METADATA=\nRELEASE_DATE="1 Jan 2025"\nSHLIB_VERSION=3\n')
    w(t / us.MBEDTLS_SUB / "include/mbedtls/build_info.h", f'#define MBEDTLS_VERSION_STRING         "{mbed}"\n')
    w(t / ".gitmodules", "".join(f'[submodule "{m}"]\n\tpath = {m}\n\turl = https://example.invalid/x\n' for m in (us.OPENSSL_SUB, us.MBEDTLS_SUB)))
    git(t, tags=["edk2-stable202502"])
    for name, text in (logs or {}).items():
        w(t / "Build" / name, text)
    return t


def source(tree, out, *extra):
    r = subprocess.run([sys.executable, "-I", str(CLI), "--tree", str(tree), "--out", str(out), *extra], capture_output=True, text=True)
    assert r.returncode in (0, 2), r
    return json.loads((Path(out) / "uefi-source.json").read_text()), json.loads((Path(out) / "uefi-source.cdx.json").read_text())


def props(c):
    out = {}
    for p in c.get("properties", []):
        out.setdefault(p["name"], []).append(p["value"])
    return out


def test_platform_dsc_option_adds_built_in_properties(tmp_path):
    t = tree_with(tmp_path)
    rep, cdx = source(t, tmp_path / "o", "--platform-dsc", "Platform/P.dsc")
    ssl = next(c for c in cdx["components"] if c["name"] == "openssl")
    mbed = next(c for c in cdx["components"] if c["name"] == "mbedtls")
    assert props(ssl)["sca-center:built-in"] == ["yes"] and any("App/App.inf" in e for e in props(ssl)["sca-center:built-in-evidence"])
    assert props(mbed)["sca-center:built-in"] == ["unknown"] and "absence is not proven" in props(mbed)["sca-center:built-in-reason"][0]
    assert rep["build_analysis"]["runs"][0]["dsc"] == "Platform/P.dsc"
    assert any("built-in: unknown" in a and "Mbed TLS" in a for a in rep["attention"])
    assert "Built into the firmware" in (tmp_path / "o" / "uefi-source.md").read_text()
    assert not any(p["value"] == "no" for c in cdx["components"] for p in c.get("properties", []) if p["name"] == "sca-center:built-in")


def test_without_dsc_no_built_in_property_and_report_unchanged(tmp_path):
    rep, cdx = source(tree_with(tmp_path), tmp_path / "o")
    assert rep["build_analysis"] is None
    assert not any("sca-center:built-in" in p["name"] for c in cdx["components"] for p in c.get("properties", []))
    assert all("built_in" not in c for c in rep["components"])


def test_unknown_built_in_is_attention_in_the_source_report(tmp_path):
    dsc = DSC_OPENSSL.replace("[Components]\n  App/App.inf\n", "[Components]\n!ifdef CONFIG_TLS\n  App/App.inf\n!endif\n")
    rep, cdx = source(tree_with(tmp_path, dsc), tmp_path / "o", "--platform-dsc", "Platform/P.dsc")
    ssl = next(c for c in cdx["components"] if c["name"] == "openssl")
    assert props(ssl)["sca-center:built-in"] == ["unknown"] and props(ssl)["sca-center:built-in-reason"]
    assert any("built-in: unknown" in a for a in rep["attention"]) and rep["status"] in ("ATTENTION", "GAP")


def test_platform_dsc_must_exist_and_be_inside_the_tree(tmp_path):
    t = tree_with(tmp_path)
    rep, cdx = source(t, tmp_path / "o1", "--platform-dsc", "Platform/Nope.dsc")
    assert any("不在樹裡" in a for a in rep["attention"]) and not any("sca-center:built-in" in p["name"] for c in cdx["components"] for p in c.get("properties", []))
    rep, cdx = source(t, tmp_path / "o2", "--platform-dsc", str(tmp_path / "outside.dsc"))
    assert any("不在樹裡" in a for a in rep["attention"])


LOG = "DEBUG - Edk2 build parameters are -p Platform/P.dsc -b RELEASE -t GCC -a AARCH64 -D CONFIG_TLS=y -D BUILD_NAME=t\nINFO - rest\n"


def test_build_log_names_the_platform_and_defines(tmp_path):
    dsc = DSC_OPENSSL.replace("[Components]\n  App/App.inf\n", "[Components]\n!ifdef CONFIG_TLS\n  App/App.inf\n!endif\n")
    t = tree_with(tmp_path, dsc, {"BUILDLOG_t.txt": LOG + "x" * 3_000_000})        # 建置記錄很大：只讀開頭
    (t / "Build" / "t").mkdir()
    rep, cdx = source(t, tmp_path / "o")
    run0 = rep["build_analysis"]["runs"][0]
    assert run0["dsc"] == "Platform/P.dsc" and run0["defines_known"] is True and "BUILDLOG_t.txt" in run0["source"]
    assert next(c for c in rep["components"] if c["kind"] == "openssl")["built_in"] == "yes"
    assert next(c for c in rep["components"] if c["kind"] == "mbedtls")["built_in"] == "unknown"


def test_unreadable_build_log_or_unlogged_build_folder_never_gives_no(tmp_path):
    """建置記錄讀不到：不知道還有哪些平台，不能因為讀到的平台沒用它就說 no。"""
    t = tree_with(tmp_path, DSC_OPENSSL.replace("App/App.inf", "App/Plain.inf"), {"BUILDLOG_t.txt": LOG, "BUILDLOG_other.txt": "garbage\n"})
    rep, _ = source(t, tmp_path / "o")
    assert next(c for c in rep["components"] if c["kind"] == "mbedtls")["built_in"] == "unknown"
    assert any("讀不到建置參數" in n for n in rep["build_analysis"]["notes"])
    t2 = tree_with(tmp_path / "x", DSC_OPENSSL.replace("App/App.inf", "App/Plain.inf"), {"BUILDLOG_t.txt": LOG})
    (t2 / "Build" / "unlogged").mkdir()
    rep, _ = source(t2, tmp_path / "o2")
    assert next(c for c in rep["components"] if c["kind"] == "openssl")["built_in"] == "unknown"


def test_explicit_dsc_without_log_treats_missing_macros_as_maybe(tmp_path):
    dsc = DSC_OPENSSL.replace("[Components]\n  App/App.inf\n", "[Components]\n!ifdef CONFIG_TLS\n  App/App.inf\n!endif\n")
    t = tree_with(tmp_path, dsc)
    rep, _ = source(t, tmp_path / "o1", "--platform-dsc", "Platform/P.dsc")
    assert next(c for c in rep["components"] if c["kind"] == "openssl")["built_in"] == "unknown"
    rep, _ = source(t, tmp_path / "o2", "--platform-dsc", "Platform/P.dsc", "--platform-define", "CONFIG_TLS=y")
    assert next(c for c in rep["components"] if c["kind"] == "openssl")["built_in"] == "yes"


# ---------- Mbed TLS の 2 つの CPE vendor ----------

def mbed_cdx(version="3.6.2", cpe=None):
    return {"components": [{"type": "library", "bom-ref": "m", "name": "mbedtls", "version": version, "purl": f"pkg:generic/mbedtls@{version}",
                            "cpe": cpe or f"cpe:2.3:a:arm:mbed_tls:{version}:*:*:*:*:*:*:*",
                            "properties": [{"name": "sca-center:uefi:role", "value": "edk2-submodule"}]}]}


def test_mbedtls_is_sent_with_both_cpe_vendors(tmp_path):
    body, purls = ub.grype_input(mbed_cdx())
    c = json.loads(body)["components"][0]
    assert c["cpe"].startswith("cpe:2.3:a:arm:mbed_tls:3.6.2:")
    assert [p["value"] for p in c["properties"] if p["name"] == "syft:cpe23"] == ["cpe:2.3:a:trustedfirmware:mbed_tls:3.6.2:*:*:*:*:*:*:*"]
    assert purls == {"pkg:generic/mbedtls@3.6.2"}
    # 主要 CPE 就是 trustedfirmware 時也收（別名不會倒過來亂加）
    body, _ = ub.grype_input(mbed_cdx(cpe="cpe:2.3:a:trustedfirmware:mbed_tls:3.6.2:*:*:*:*:*:*:*"))
    assert "properties" not in json.loads(body)["components"][0]
    # OpenSSL 沒有別名
    ssl = {"components": [{"type": "library", "bom-ref": "o", "name": "openssl", "version": "3.4.1", "purl": "pkg:generic/openssl@3.4.1",
                           "cpe": "cpe:2.3:a:openssl:openssl:3.4.1:*:*:*:*:*:*:*"}]}
    assert "properties" not in json.loads(ub.grype_input(ssl)[0])["components"][0]
    # 版本不同的 trustedfirmware CPE 不收
    assert ub.grype_input(mbed_cdx(cpe="cpe:2.3:a:trustedfirmware:mbed_tls:2.28.8:*:*:*:*:*:*:*"))[1] == set()


def test_product_sbom_component_carries_both_cpes(tmp_path):
    u = tmp_path / "u"
    u.mkdir()
    write_json(u / "uefi-source.cdx.json", mbed_cdx())
    info = ub.load(u)
    props_ = [p["value"] for c in info["comps"] for p in c["properties"] if p["name"] == "syft:cpe23"]
    assert props_ == ["cpe:2.3:a:trustedfirmware:mbed_tls:3.6.2:*:*:*:*:*:*:*"]


def test_duplicate_matches_by_cve_per_component_are_merged(tmp_path):
    g = grype_json(ids=("CVE-2099-0001", "CVE-2099-0001", "CVE-2099-0002"))
    assert len(ub.dedupe(g["matches"])) == 2
    u = tmp_path / "u"
    u.mkdir()
    write_json(u / "uefi-source.cdx.json", {"components": [{"type": "library", "bom-ref": "o", "name": "openssl", "version": "3.4.1",
                                                           "purl": "pkg:generic/openssl@3.4.1",
                                                           "cpe": "cpe:2.3:a:openssl:openssl:3.4.1:*:*:*:*:*:*:*"}]})
    exe, env = fake_grype(tmp_path, g)
    assert ub.run_grype(u, str(exe), 3, env)[0] == "OK"
    assert len(json.loads((u / "grype.json").read_text())["matches"]) == 2


@pytest.mark.parametrize("cpe", ["cpe:2.3:a:openssl:openssl:3.4.1:*:*:*:*:*:*", "cpe:2.3:a:openssl:openssl:3.4.1:*:*:*:*:*:*:*:*",
                                 "cpe:2.3:a:openssl:openssl:3.4.1"])
def test_cpe_must_have_exactly_13_fields(cpe):
    assert not ub._cpe_allowed(cpe, "3.4.1")
    assert ub._cpe_allowed("cpe:2.3:a:openssl:openssl:3.4.1:*:*:*:*:*:*:*", "3.4.1")


def test_allowed_purls_come_from_the_kept_components_only():
    """64 個之後的元件（即使 CPE 合格）不給 Grype、不在允許的 purl 裡：它的比對（如果 Grype 回了）不會變成沒有標示的列。"""
    filler = [{"type": "library", "bom-ref": f"f{i}", "name": f"lib{i}", "purl": f"pkg:generic/lib{i}"} for i in range(ub.MAX_COMPS)]
    late = mbed_cdx()["components"][0]
    cdx = {"components": filler + [late]}
    body, purls = ub.grype_input(cdx)
    assert purls == set() and json.loads(body)["components"] == []
    kept, skipped, over = ub.kept_components(cdx)
    assert len(kept) == ub.MAX_COMPS and over == 1 and skipped == 0


# ---------- grype.json の改ざん／差し替え ----------

def test_grype_json_replaced_after_the_run_is_not_used(tmp_path):
    u = tmp_path / "uefi-source"
    u.mkdir()
    write_json(u / "uefi-source.cdx.json", {"components": [{"type": "library", "bom-ref": "o", "name": "openssl", "version": "3.4.1",
                                                           "purl": "pkg:generic/openssl@3.4.1",
                                                           "cpe": "cpe:2.3:a:openssl:openssl:3.4.1:*:*:*:*:*:*:*"}]})
    exe, env = fake_grype(tmp_path, grype_json())
    assert ub.run_grype(u, str(exe), 3, env)[0] == "OK"
    run_ = json.loads((u / "grype-run.json").read_text())
    assert run_["grype_sha256"] == hashlib.sha256((u / "grype.json").read_bytes()).hexdigest()
    assert ub.load(u)["matches"] == 1 and not any("grype_sha256" in g or "input_sha256" in g for g in ub.load(u)["gaps"])
    write_json(u / "grype.json", {"matches": []})                       # 事後換成「沒有比對」
    info = ub.load(u)
    assert info["status"] == "GAP" and info["matches"] is None and any("grype_sha256" in g for g in info["gaps"])
    run_.pop("grype_sha256")
    write_json(u / "grype-run.json", run_)                              # 沒有雜湊 → 同樣不用
    assert any("grype_sha256" in g for g in ub.load(u)["gaps"]) and ub.load(u)["matches"] is None


# ---------- cra_report：built-in no → VEX not_affected，unknown → 照常 ----------

def uefi_dir(tmp_path, dsc, ver="3.6.2"):
    t = tree_with(tmp_path, dsc, mbed=ver)
    u = tmp_path / "uefi-source"
    r = subprocess.run([sys.executable, "-I", str(CLI), "--tree", str(t), "--out", str(u), "--platform-dsc", "Platform/P.dsc"], capture_output=True, text=True)
    assert r.returncode in (0, 2), r
    return u


def mbed_grype(cve="CVE-2099-0100", ver="3.6.2", vendor="trustedfirmware"):
    g = grype_json(version=ver)
    m = g["matches"][0]
    m["vulnerability"]["id"] = cve
    m["artifact"].update(name="mbedtls", purl=f"pkg:generic/mbedtls@{ver}")
    m["matchDetails"][0]["searchedBy"]["cpes"] = [f"cpe:2.3:a:{vendor}:mbed_tls:{ver}:*:*:*:*:*:*:*"]
    m["vulnerability"]["fix"] = {"versions": ["3.6.5"], "state": "fixed"}
    return g


def both_grype(tmp_path, u):
    g = grype_json()
    g["matches"] += mbed_grype()["matches"]
    put_grype(u, g)


def test_no_row_is_ever_excluded_by_the_built_in_analysis(tmp_path):
    """DSC 沒有走到 Mbed TLS：仍是 unknown、ATTENTION；列照常列出，沒有任何 VEX not_affected、沒有 uefi_build 標記、層級不變。"""
    u = uefi_dir(tmp_path, DSC_OPENSSL)
    both_grype(tmp_path, u)
    s, rep, bom = report(tmp_path, u)
    md = (rep / "risk-assessment.md").read_text(encoding="utf-8")
    info = s["product_sbom"]["uefi_source"]
    assert info["rows"] == 2 and info["status"] == "ATTENTION"
    vex = {v["id"]: v["analysis"]["state"] for v in json.loads((rep / "vex.cdx.json").read_text())["vulnerabilities"]}
    assert vex.get("CVE-2099-0001") != "not_affected" and vex.get("CVE-2099-0100") != "not_affected"
    assert "Mbed TLS 3.6.2 (bundled in UEFI)" in md and "OpenSSL 3.4.1 (bundled in UEFI)" in md
    assert "not built into the firmware" not in md and "code_not_present" not in (rep / "vex.cdx.json").read_text()
    assert {l["name"]: l["built_in"] for l in info["libs"] if l["name"] in ("openssl", "mbedtls")} == {"openssl": "yes", "mbedtls": "unknown"}
    assert any("built-in: unknown" in a and "Mbed TLS" in a for a in info["attention"])
    assert "absence is not proven" in (rep / "sbom.md").read_text(encoding="utf-8") or "it never excludes a row" in (rep / "sbom.md").read_text(encoding="utf-8")
    mbed_comp = next(c for c in bom["components"] if c["name"] == "mbedtls")
    assert {"name": "sca-center:built-in", "value": "unknown"} in mbed_comp["properties"]


def test_the_vex_feature_for_the_built_in_analysis_is_gone():
    import vex_export as vx
    assert not hasattr(vx, "from_uefi_build") and "uefi_build" not in vx.SRC_LABEL
    # row 上放 uefi_build 也不會讓列變 not_affected
    row = {"id": "CVE-2099-1", "cves": ["CVE-2099-1"], "all_ids": ["CVE-2099-1"], "key": ["CVE-2099-1", "mbedtls", "3.6.2"], "component": "x", "name": "mbedtls",
           "version": "3.6.2", "purl": "pkg:generic/mbedtls@3.6.2", "analysis": [], "kernel": False, "source_ids": [], "uefi_build": {"detail": "x"}}
    rows, _, _ = vx.assess([row])
    assert rows[0]["vex"] is None


def test_old_output_with_built_in_no_is_treated_as_unknown(tmp_path):
    u = uefi_dir(tmp_path, DSC_OPENSSL)
    p = u / "uefi-source.cdx.json"
    d = json.loads(p.read_text())
    for c in d["components"]:
        for q in c.get("properties", []):
            if q["name"] == "sca-center:built-in":
                q["value"] = "no"
    write_json(p, d)
    both_grype(tmp_path, u)
    s, rep, _ = report(tmp_path, u)
    info = s["product_sbom"]["uefi_source"]
    assert {l["name"]: l["built_in"] for l in info["libs"] if l["name"] in ("openssl", "mbedtls")} == {"openssl": "unknown", "mbedtls": "unknown"}
    vex = {v["id"]: v["analysis"]["state"] for v in json.loads((rep / "vex.cdx.json").read_text())["vulnerabilities"]}
    assert vex.get("CVE-2099-0100") != "not_affected"


def test_unknown_built_in_keeps_the_row_open_and_raises_attention(tmp_path):
    dsc = DSC_OPENSSL.replace("[Components]\n  App/App.inf\n", "[Components]\n!ifdef CONFIG_TLS\n  App/App.inf\n!endif\n")
    u = uefi_dir(tmp_path, dsc)
    both_grype(tmp_path, u)
    s, rep, _ = report(tmp_path, u)
    info = s["product_sbom"]["uefi_source"]
    assert info["status"] == "ATTENTION" and any("built-in: unknown" in a and "OpenSSL" in a for a in info["attention"])
    assert {l["name"]: l["built_in"] for l in info["libs"] if l["name"] in ("openssl", "mbedtls")} == {"openssl": "unknown", "mbedtls": "unknown"}
    vex = {v["id"]: v["analysis"]["state"] for v in json.loads((rep / "vex.cdx.json").read_text())["vulnerabilities"]}
    assert vex.get("CVE-2099-0001") != "not_affected" and vex.get("CVE-2099-0100") != "not_affected"
    assert "OpenSSL 3.4.1 (bundled in UEFI)" in (rep / "risk-assessment.md").read_text(encoding="utf-8")


def test_no_dsc_means_unknown_and_attention_not_no(tmp_path):
    u = tmp_path / "uefi-source"
    t = tree_with(tmp_path, DSC_OPENSSL)
    subprocess.run([sys.executable, "-I", str(CLI), "--tree", str(t), "--out", str(u)], capture_output=True, text=True)
    both_grype(tmp_path, u)
    s, rep, _ = report(tmp_path, u)
    info = s["product_sbom"]["uefi_source"]
    assert any("was NOT checked" in a and "built-in: unknown" in a for a in info["attention"])
    assert [l["built_in"] for l in info["libs"] if l["name"] in ("openssl", "mbedtls")] == ["unknown", "unknown"]
    vex = {v["id"]: v["analysis"]["state"] for v in json.loads((rep / "vex.cdx.json").read_text())["vulnerabilities"]}
    assert vex.get("CVE-2099-0001") != "not_affected" and vex.get("CVE-2099-0100") != "not_affected"


def test_kev_row_stays_open_whatever_the_built_in_result(tmp_path):
    u = uefi_dir(tmp_path, DSC_OPENSSL)
    g = mbed_grype()
    g["matches"][0]["vulnerability"]["knownExploited"] = [{"cve": "CVE-2099-0100", "knownRansomwareCampaignUse": "Unknown"}]
    put_grype(u, g)
    s, rep, _ = report(tmp_path, u)
    assert s["product_sbom"]["uefi_source"]["rows"] == 1
    md = (rep / "risk-assessment.md").read_text(encoding="utf-8")
    vex = {v["id"]: v["analysis"]["state"] for v in json.loads((rep / "vex.cdx.json").read_text())["vulnerabilities"]}
    assert "YES (Grype)" in md and vex.get("CVE-2099-0100") != "not_affected"


def test_a_requested_dsc_that_was_not_analysed_is_said_so(tmp_path):
    t = tree_with(tmp_path)
    rep, _ = source(t, tmp_path / "o", "--platform-dsc", "Platform/P.dsc", "--platform-dsc", "Platform/Missing.dsc")
    m = next(c for c in rep["components"] if c["kind"] == "mbedtls")
    assert m["built_in"] == "unknown" and any("was not analysed" in x for x in m["built_in_reasons"])
    assert any("Missing.dsc" in n for n in rep["build_analysis"]["notes"])
