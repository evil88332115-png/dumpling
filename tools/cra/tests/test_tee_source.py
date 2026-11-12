"""tee_source.py、tee_bundled.py、cra_report.py --tee-source、bootloader_coverage 的 tos-optee 說明。
全部用測試自己組出來的小型假資料（假的原始碼樹、假的映像位元組、照 Grype 實際輸出形狀寫的假結果；CVE-2099-… 不存在），不含任何產品資料。"""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import bootloader_coverage as bc  # noqa: E402
import tee_bundled as tb  # noqa: E402
import tee_source as ts  # noqa: E402
from test_cra_report import MIN_CFG, make_project, make_scan, run, write_json  # noqa: E402
from test_uefi_bundled import fake_grype  # noqa: E402

CLI = HERE.parent / "tee_source.py"


def w(p, text):
    p = Path(p)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def tree(d, tfa="2.13.0", optee=("4", "6", ""), mbed="3.6.5", mbed_parts=None, plat=True, hafnium=False, freertos=None,
         tfa_name="arm-trusted-firmware.t234"):
    d = Path(d)
    if tfa:
        a, b, c = tfa.split(".")
        w(d / "atf" / tfa_name / "Makefile", f"VERSION_MAJOR\t\t\t:= {a}\nVERSION_MINOR\t\t\t:= {b}\n\nVERSION_PATCH\t\t\t:= {c}\n")
    if optee:
        o = d / "src" / "optee" / "optee_os"
        w(o / "mk" / "config.mk", f"CFG_OPTEE_REVISION_MAJOR ?= {optee[0]}\nCFG_OPTEE_REVISION_MINOR ?= {optee[1]}\nCFG_OPTEE_REVISION_EXTRA ?={optee[2]}\n"
                                  "$(call force,CFG_TA_MBEDTLS,y)\n$(call force,CFG_CORE_MBEDTLS_MPI,y)\nCFG_CRYPTOLIB_NAME ?= tomcrypt\n")
        if plat:
            w(o / "core/arch/arm/plat-tegra/conf.mk", "# platform\nCFG_NUM_THREADS = 4\n")
        if mbed:
            p = mbed_parts or mbed.split(".")
            w(o / "lib/libmbedtls/mbedtls/include/mbedtls/build_info.h",
              f'#define MBEDTLS_VERSION_MAJOR  {p[0]}\n#define MBEDTLS_VERSION_MINOR  {p[1]}\n#define MBEDTLS_VERSION_PATCH  {p[2]}\n'
              f'#define MBEDTLS_VERSION_STRING         "{mbed}"\n')
    if hafnium:
        w(d / "hafnium" / "README.md", "x")
    if freertos:
        w(d / "spe" / "FreeRTOS" / "Source" / "include" / "task.h", f'#define tskKERNEL_VERSION_NUMBER "V{freertos}"\n')
    return d


def tee_image(optee="4.6", tfa="v2.13.0(release):d65e852"):
    b = b"\x00\x01\xff" * 20 + b"OP-TEE version: %s\x00"
    if optee:
        b += b"\xf7" + optee.encode() + b" (gcc version 13.2.0 (crosstool-NG 1.26.0)) #2 Mon\x00"
    if tfa:
        b += tfa.encode() + b"\x00"
    return b + b"\x00" * 20


def flash(tmp_path, images):
    root = tmp_path / "pkg"
    inv = {"bootloader": []}
    for name, data in images.items():
        p = root / "T" / "bootloader" / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        inv["bootloader"].append({"path": f"T/bootloader/{name}", "type": "file", "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    return root, inv


def scan(tmp_path, images=None, **kw):
    t = tree(tmp_path / "t", **kw)
    if images is None:
        return ts.scan(t)
    root, inv = flash(tmp_path, images)
    return ts.scan(t, inv, None, str(root))


def by_kind(comps):
    return {c["kind"]: c for c in comps}


# ---------- 讀版本 ----------

def test_versions_cpes_and_config_facts(tmp_path):
    rep, comps = scan(tmp_path)
    c = by_kind(comps)
    assert (c["tfa"]["version"], c["optee"]["version"], c["mbedtls"]["version"]) == ("2.13.0", "4.6", "3.6.5")
    assert c["optee"]["cpe"] == "cpe:2.3:a:linaro:op-tee:4.6:*:*:*:*:*:*:*"
    assert c["tfa"]["cpe"] == "cpe:2.3:a:trustedfirmware:trusted_firmware-a:2.13.0:*:*:*:*:*:*:*"
    assert c["mbedtls"]["cpe"] == "cpe:2.3:a:arm:mbed_tls:3.6.5:*:*:*:*:*:*:*"
    f = rep["build_config"]["facts"]
    assert f["CFG_CORE_MBEDTLS_MPI"]["value"] == "y" and f["CFG_TA_MBEDTLS"]["value"] == "y" and f["CFG_CRYPTOLIB_NAME"]["value"] == "tomcrypt"
    assert rep["build_config"]["note"].startswith(
        "OP-TEE build config: core CFG_CORE_MBEDTLS_MPI=y; TA library CFG_TA_MBEDTLS=y; crypto library tomcrypt; affectedness not assessed")
    assert "uses only" not in json.dumps(rep)
    assert rep["status"] == "OK" and not rep["gaps"]


def test_platform_conf_wins_over_defaults(tmp_path):
    t = tree(tmp_path / "t")
    w(t / "src/optee/optee_os/core/arch/arm/plat-tegra/conf.mk", "CFG_CRYPTOLIB_NAME = mbedtls\n")
    rep, _ = ts.scan(t)
    assert rep["build_config"]["facts"]["CFG_CRYPTOLIB_NAME"]["value"] == "mbedtls"
    assert "plat-tegra" in rep["build_config"]["facts"]["CFG_CRYPTOLIB_NAME"]["source"]


def test_nonempty_extra_suffix_keeps_base_version_with_attention(tmp_path):
    rep, comps = scan(tmp_path, optee=("4", "6", "-dev"))
    c = by_kind(comps)["optee"]
    assert c["version"] == "4.6" and c["cpe"].startswith("cpe:2.3:a:linaro:op-tee:4.6:")
    assert any("revision suffix present" in a and "-dev" in a for a in rep["attention"]) and rep["status"] == "ATTENTION"


@pytest.mark.parametrize("extra", ["$(shell git describe)", '"-dev"', "-dev; rm", "x y", "$(X)"])
def test_extra_suffix_that_is_not_plain_is_unknown_gap_without_cpe(tmp_path, extra):
    rep, comps = scan(tmp_path, optee=("4", "6", extra))
    c = by_kind(comps)["optee"]
    assert c["version"] is None and c["cpe"] is None and "@" not in c["purl"]
    assert rep["status"] == "GAP" and any("OP-TEE" in g for g in rep["gaps"])


@pytest.mark.parametrize("kw,kind", [({"mbed": "3.6.5", "mbed_parts": ["3", "6", "4"]}, "mbedtls"), ({"mbed": None}, "mbedtls"), ({"tfa": None}, "tfa")])
def test_conflicting_or_missing_version_is_unknown_gap_without_cpe(tmp_path, kw, kind):
    rep, comps = scan(tmp_path, **kw)
    c = by_kind(comps).get(kind)
    assert rep["status"] == "GAP" and rep["gaps"]
    if c:
        assert c["version"] is None and c["cpe"] is None and "@" not in c["purl"]


def test_two_tfa_copies_with_different_versions_conflict(tmp_path):
    t = tree(tmp_path / "t")
    w(t / "other" / "arm-trusted-firmware-x" / "Makefile", "VERSION_MAJOR := 2\nVERSION_MINOR := 12\nVERSION_PATCH := 1\n")
    rep, comps = ts.scan(t)
    assert by_kind(comps)["tfa"]["version"] is None and any("conflicting" in g for g in rep["gaps"])


def test_makefile_with_non_numeric_value_is_unknown(tmp_path):
    t = tree(tmp_path / "t")
    w(t / "atf/arm-trusted-firmware.t234/Makefile", "VERSION_MAJOR := $(shell x)\nVERSION_MINOR := 1\nVERSION_PATCH := 0\n")
    assert by_kind(ts.scan(t)[1])["tfa"]["cpe"] is None


def test_hafnium_without_version_file_and_freertos_with_one(tmp_path):
    rep, comps = scan(tmp_path, hafnium=True, freertos="10.4.3")
    c = by_kind(comps)
    assert c["hafnium"]["version"] is None and c["freertos"]["version"] == "10.4.3"
    assert c["hafnium"]["cpe"] is None and c["freertos"]["cpe"] is None       # 沒有 CPE 定義：不比對
    assert rep["status"] == "GAP" and any("Hafnium" in g for g in rep["gaps"]) and any("FreeRTOS" in g for g in rep["gaps"])


def test_not_listed_when_source_has_no_hafnium_or_freertos(tmp_path):
    _, comps = scan(tmp_path)
    assert set(by_kind(comps)) == {"tfa", "optee", "mbedtls"}


def test_symlinks_are_not_followed(tmp_path):
    t = tree(tmp_path / "t", mbed=None)
    real = tmp_path / "elsewhere"
    w(real / "build_info.h", '#define MBEDTLS_VERSION_STRING "9.9.9"\n')
    p = t / "src/optee/optee_os/lib/libmbedtls/mbedtls/include/mbedtls"
    p.mkdir(parents=True)
    (p / "build_info.h").symlink_to(real / "build_info.h")
    assert by_kind(ts.scan(t)[1])["mbedtls"]["version"] is None


# ---------- 映像對照 ----------

def test_image_consistent_different_not_assessed(tmp_path):
    rep, _ = scan(tmp_path, images={"tos-optee_t234.img": tee_image()})
    assert rep["image_check"]["counts"] == {"MATCH": 1, "MISMATCH": 0, "NOT_ASSESSED": 0} and rep["status"] == "OK"
    rep, _ = scan(tmp_path / "b", images={"tos-optee_t234.img": tee_image(optee="4.4", tfa="v2.12.0(release):abc")})
    assert rep["image_check"]["counts"]["MISMATCH"] == 1 and rep["status"] == "ATTENTION"
    rep, _ = scan(tmp_path / "c", images={"tos-optee_t234.img": tee_image(optee=None, tfa=None)})
    assert rep["image_check"]["counts"]["NOT_ASSESSED"] == 1 and rep["status"] == "GAP"
    assert "consistent with being built" in rep["image_check"]["wording"]


def test_image_other_soc_and_ambiguous_prefix_are_not_assessed(tmp_path):
    rep, _ = scan(tmp_path, images={"tos-optee_t264.img": tee_image(tfa=None)})
    im = rep["image_check"]["images"][0]
    assert im["tfa"]["result"] == "NOT_ASSESSED" and "t234" in im["tfa"]["why"]
    rep, _ = scan(tmp_path / "b", images={"tos-optee_t234.img": tee_image(optee="44.6")})
    assert rep["image_check"]["images"][0]["optee"]["result"] == "NOT_ASSESSED"


def test_image_unknown_source_version_is_not_assessed_not_mismatch(tmp_path):
    rep, _ = scan(tmp_path, images={"tos-optee_t234.img": tee_image()}, tfa=None)
    assert rep["image_check"]["images"][0]["tfa"]["result"] == "NOT_ASSESSED"


def test_no_image_in_inventory_is_gap(tmp_path):
    rep, _ = scan(tmp_path, images={"mb1_t234.bin": b"x"})
    assert rep["image_check"]["status"] == "GAP" and rep["status"] == "GAP"


def test_no_flash_package_is_not_run(tmp_path):
    rep, _ = scan(tmp_path)
    assert rep["image_check"]["status"] == "NOT_RUN"


def test_cli_outputs_and_exit_codes(tmp_path):
    t = tree(tmp_path / "t")
    out = tmp_path / "o"
    r = subprocess.run([sys.executable, "-I", str(CLI), "--tree", str(t), "--out", str(out)], capture_output=True, text=True)
    assert r.returncode == 0 and r.stdout.startswith("B-tee-source\tOK\t") and "Mbed TLS 3.6.5" in r.stdout
    cdx = json.loads((out / "tee-source.cdx.json").read_text())
    assert {c["name"] for c in cdx["components"]} == {"OP-TEE", "TF-A", "Mbed TLS"}
    deps = {d["ref"]: d["dependsOn"] for d in cdx["dependencies"]}
    assert deps["tee-optee"] == ["tee-mbedtls"]
    mb = next(c for c in cdx["components"] if c["name"] == "Mbed TLS")
    assert any(p["name"] == "sca-center:tee:config:CFG_CORE_MBEDTLS_MPI" for p in mb["properties"])
    r = subprocess.run([sys.executable, "-I", str(CLI), "--tree", str(tmp_path / "none"), "--out", str(out)], capture_output=True, text=True)
    assert r.returncode == 1 and "FAIL" in r.stdout
    r = subprocess.run([sys.executable, "-I", str(CLI), "--tree", str(t)], capture_output=True, text=True)
    assert r.returncode == 64
    inv = tmp_path / "bad.json"
    inv.write_text("nope")
    r = subprocess.run([sys.executable, "-I", str(CLI), "--tree", str(t), "--out", str(out), "--inventory", str(inv), "--dir", str(tmp_path)],
                       capture_output=True, text=True)
    assert r.returncode == 1


# ---------- Grype 與報告 ----------

def make_tee(tmp, **kw):
    out = Path(tmp) / "tee-source"
    r = subprocess.run([sys.executable, "-I", str(CLI), "--tree", str(tree(Path(tmp) / "t", **kw)), "--out", str(out)], capture_output=True, text=True)
    assert r.returncode in (0, 2) and r.stdout.startswith("B-tee-source\t"), r
    return out


def grype_json(version="3.6.5", fixed="3.6.6", ids=("CVE-2099-0101",), cpe_vendor="arm", name="mbed_tls", purl_name="mbedtls"):
    return {"matches": [{
        "vulnerability": {"id": i, "namespace": "nvd:cpe", "severity": "Low", "dataSource": "https://nvd.nist.gov/vuln/detail/" + i,
                          "fix": {"versions": [fixed], "state": "fixed"}, "cvss": [], "epss": []},
        "relatedVulnerabilities": [],
        "matchDetails": [{"type": "cpe-match", "matcher": "stock-matcher",
                          "searchedBy": {"namespace": "nvd:cpe", "cpes": [f"cpe:2.3:a:{cpe_vendor}:{name}:{version}:*:*:*:*:*:*:*"]}}],
        "artifact": {"id": "x", "name": purl_name, "version": version, "type": "UnknownPackage", "purl": f"pkg:generic/{purl_name}@{version}",
                     "cpes": [f"cpe:2.3:a:{cpe_vendor}:{name}:{version}:*:*:*:*:*:*:*"]}} for i in ids]}


def put_grype(d, g, status="OK"):
    write_json(d / "grype.json", g)
    run_ = {"schema": "sca-center-uefi-grype/1", "status": status, "detail": "database Built=2026-11-08T06:19:57Z (1 days)", "matches": len(g["matches"]),
            "grype_sha256": hashlib.sha256((d / "grype.json").read_bytes()).hexdigest(),
            "input_sha256": hashlib.sha256(tb.ub().grype_input(json.loads((d / "tee-source.cdx.json").read_text()))[0]).hexdigest()}
    write_json(d / "grype-run.json", run_)


def report(tmp_path, tee=None, *extra):
    proj, scan_ = make_project(tmp_path / "p", MIN_CFG), make_scan(tmp_path / "res" / "scan")
    if tee is not None:
        os.replace(tee, scan_.parent / "tee-source")
    r, s, rep = run(proj, scan_, *extra)
    assert r.returncode in (0, 2), r.stdout + r.stderr
    return s, rep, json.loads((rep / "sbom.cdx.json").read_text(encoding="utf-8"))


def test_run_grype_is_offline_and_sends_cpe_components_with_alias(tmp_path):
    t = make_tee(tmp_path)
    exe, env = fake_grype(tmp_path, grype_json())
    st, detail = tb.run_grype(t, str(exe), 3, env)
    assert st == "OK" and "1 matches" in detail
    log = (tmp_path / "log").read_text()
    assert "false false " in log and "db update" not in log
    sent = json.loads((t / "grype-input.cdx.json").read_text())
    names = {c["name"]: c for c in sent["components"]}
    assert set(names) == {"OP-TEE", "TF-A", "Mbed TLS"}
    assert names["Mbed TLS"]["properties"] == [{"name": "syft:cpe23", "value": "cpe:2.3:a:trustedfirmware:mbed_tls:3.6.5:*:*:*:*:*:*:*"}]


def test_unknown_version_component_is_not_sent_to_grype(tmp_path):
    t = make_tee(tmp_path, mbed=None)
    exe, env = fake_grype(tmp_path, grype_json())
    tb.run_grype(t, str(exe), 3, env)
    assert {c["name"] for c in json.loads((t / "grype-input.cdx.json").read_text())["components"]} == {"OP-TEE", "TF-A"}


def test_mbedtls_match_becomes_row_with_label_fix_and_note(tmp_path):
    t = make_tee(tmp_path)
    put_grype(t, grype_json())
    s, rep, bom = report(tmp_path, t)
    md = (rep / "risk-assessment.md").read_text(encoding="utf-8")
    assert "Mbed TLS 3.6.5 (bundled in OP-TEE)" in md and "CVE-2099-0101" in md
    assert "OP-TEE build config: core CFG_CORE_MBEDTLS_MPI=y; TA library CFG_TA_MBEDTLS=y; crypto library tomcrypt; affectedness not assessed" in md
    assert "uses only" not in md and "plat-tegra" not in md and "mk/config.mk" not in md
    assert "rebuild the tos-optee image with a fixed Mbed TLS (3.6.6 or later" in md
    names = {c["name"]: c for c in bom["components"]}
    assert names["Mbed TLS"]["cpe"].startswith("cpe:2.3:a:arm:mbed_tls:3.6.5:") and names["OP-TEE"]["version"] == "4.6" and names["TF-A"]["version"] == "2.13.0"
    deps = {d["ref"]: d["dependsOn"] for d in bom["dependencies"]}
    assert names["Mbed TLS"]["bom-ref"] in deps[names["OP-TEE"]["bom-ref"]]
    info = s["product_sbom"]["tee_source"]
    assert info["rows"] == 1 and info["matches"] == 1 and info["status"] == "OK" and info["auto_detected"] is True
    mb = next(c for c in bom["components"] if c["name"] == "Mbed TLS")
    assert not any("mk/config.mk" in p["value"] or ":" in p["value"] and p["name"].startswith("sca-center:tee:config:") for p in mb["properties"])
    sm = (rep / "sbom.md").read_text(encoding="utf-8")
    assert "vulnerability data coverage is limited; 0 matches does not mean no vulnerabilities" in sm and "CFG_CORE_MBEDTLS_MPI" in sm
    assert "picked up automatically" in sm
    rows = json.loads((rep / "vulnerability-rows.json").read_text(encoding="utf-8"))
    row = next(r for r in rows["rows"] if r["id"] == "CVE-2099-0101")
    assert row["tier"] == "p3" and "affectedness not assessed" in row["tee_note"]


def test_unknown_version_is_gap_in_report_not_clean(tmp_path):
    t = make_tee(tmp_path, mbed=None)
    put_grype(t, grype_json(ids=()))
    s, rep, bom = report(tmp_path, t)
    info = s["product_sbom"]["tee_source"]
    assert info["status"] == "GAP" and info["rows"] == 0 and any("Mbed TLS" in g for g in info["gaps"])


def test_grype_not_run_is_gap(tmp_path):
    t = make_tee(tmp_path)
    s, rep, _ = report(tmp_path, t)
    info = s["product_sbom"]["tee_source"]
    assert info["status"] == "GAP" and info["rows"] == 0 and any("NOT matched" in g for g in info["gaps"])


def test_stale_grype_result_is_not_used(tmp_path):
    t = make_tee(tmp_path)
    put_grype(t, grype_json())
    r = json.loads((t / "grype-run.json").read_text())
    r["input_sha256"] = "0" * 64
    write_json(t / "grype-run.json", r)
    s, _, _ = report(tmp_path, t)
    assert s["product_sbom"]["tee_source"]["rows"] == 0 and s["product_sbom"]["tee_source"]["status"] == "GAP"


def test_missing_or_broken_output_is_gap(tmp_path):
    t = make_tee(tmp_path)
    (t / "tee-source.cdx.json").write_text("{nope")
    s, _, _ = report(tmp_path, t)
    assert s["product_sbom"]["tee_source"]["status"] == "GAP"


def test_no_input_changes_nothing(tmp_path):
    s, rep, bom = report(tmp_path)
    assert "tee_source" not in s["product_sbom"]
    assert not any(c["name"] in ("OP-TEE", "TF-A", "Mbed TLS") for c in bom["components"])
    for f in rep.iterdir():
        if f.suffix in (".md", ".json"):
            assert "bundled in OP-TEE" not in f.read_text(encoding="utf-8")


def test_explicit_option_must_be_a_directory(tmp_path):
    proj, scan_ = make_project(tmp_path / "p", MIN_CFG), make_scan(tmp_path / "scan")
    r, _, _ = run(proj, scan_, "--tee-source", str(tmp_path / "nope"))
    assert r.returncode == 64
    t = make_tee(tmp_path)
    put_grype(t, grype_json())
    r, s, _ = run(proj, scan_, "--tee-source", str(t))
    assert r.returncode in (0, 2) and s["product_sbom"]["tee_source"]["rows"] == 1 and s["product_sbom"]["tee_source"]["auto_detected"] is False


def test_several_release_lines_note_in_fix(tmp_path):
    t = make_tee(tmp_path)
    g = grype_json()
    g["matches"][0]["vulnerability"]["fix"]["versions"] = ["2.28.10", "3.6.6"]
    put_grype(t, g)
    _, rep, _ = report(tmp_path, t)
    md = (rep / "risk-assessment.md").read_text(encoding="utf-8")
    assert "3.6.6 or later" in md and "Grype lists fixes for several release lines: 2.28.10, 3.6.6" in md


def test_coverage_uses_given_tee_json(tmp_path):
    res = tmp_path / "res"
    res.mkdir()
    write_json(res / "flash-inventory.json", inv_with(["tos-optee_t234.img"]))
    tee = {"schema": "sca-center-tee-source/1", "status": "OK", "versions": {}, "image_check": {"images": [{"path": "T/bootloader/tos-optee_t234.img", "result": "MATCH"}]}}
    write_json(tmp_path / "elsewhere.json", tee)
    cov = bc.run_coverage(res, "rootfs", None, tmp_path / "elsewhere.json")
    assert cov["items"][0]["coverage"].startswith("scanned from vendor public source")
    assert not bc.run_coverage(res, "rootfs")["items"][0]["coverage"].startswith("scanned from vendor")


# ---------- bootloader_coverage ----------

def inv_with(names):
    return {"bootloader": [{"path": f"T/bootloader/{n}", "type": "file", "size": 3, "sha256": hashlib.sha256(n.encode()).hexdigest()} for n in names]}


def test_coverage_describes_tos_optee_as_scanned_from_public_source():
    inv = inv_with(["tos-optee_t234.img", "mb1_t234_prod.bin", "tos_t234.img"])
    tee = {"schema": "sca-center-tee-source/1", "status": "OK", "versions": {"tfa": "2.13.0", "optee": "4.6", "mbedtls": "3.6.5"},
           "image_check": {"status": "OK", "detail": "1 tos-optee image(s): consistent 1",
                           "images": [{"path": "T/bootloader/tos-optee_t234.img", "result": "MATCH"}]}}
    cov = bc.build_coverage(inv, [], None, None, "rootfs", tee)
    it = {i["path"].rsplit("/", 1)[-1]: i for i in cov["items"]}
    assert it["tos-optee_t234.img"]["coverage"].startswith("scanned from vendor public source") and it["tos-optee_t234.img"]["status"] == "OK"
    assert it["mb1_t234_prod.bin"]["coverage"] == bc.COVER_VENDOR and it["tos_t234.img"]["coverage"] == bc.COVER_VENDOR
    assert sum(cov["counts"].values()) == 3 and cov["counts_add_up"]
    txt = bc.customer_text(cov)
    assert "vendor public source" in txt and "TF-A 2.13.0" in txt
    assert "廠商公開原始碼" in bc.markdown_zh(cov)


@pytest.mark.parametrize("res,st", [("MISMATCH", "ATTENTION"), ("NOT_ASSESSED", "GAP"), (None, "GAP")])
def test_coverage_status_follows_image_check(res, st):
    tee = {"schema": "sca-center-tee-source/1", "status": "GAP", "versions": {},
           "image_check": {"images": [{"path": "T/bootloader/tos-optee_t234.img", "result": res}] if res else []}}
    cov = bc.build_coverage(inv_with(["tos-optee_t234.img"]), [], None, None, "rootfs", tee)
    assert cov["items"][0]["status"] == st
    assert cov["items"][0]["build_check"] == (res or "NOT_RUN")


def test_coverage_unchanged_without_tee_source():
    inv = inv_with(["tos-optee_t234.img", "mb1_t234_prod.bin"])
    a = bc.build_coverage(inv, [], None, None, "rootfs")
    b = bc.build_coverage(inv, [], None, None, "rootfs", None)
    assert a == b and "tee_source" not in a
    assert all(i["coverage"] == bc.COVER_VENDOR for i in a["items"])
    assert "vendor public source" not in bc.customer_text(a)


def test_tfa_without_version_patch_is_major_minor_with_cpe_and_note(tmp_path):
    t = tmp_path / "t"
    w(t / "atf" / "arm-trusted-firmware" / "Makefile", "VERSION_MAJOR\t\t:= 2\nVERSION_MINOR\t\t:= 8\n")
    rep, comps = ts.scan(t)
    c = by_kind(comps)["tfa"]
    assert c["version"] == "2.8" and c["purl"].endswith("@2.8")
    assert c["cpe"] == "cpe:2.3:a:trustedfirmware:trusted_firmware-a:2.8:*:*:*:*:*:*:*"
    assert "沒有 VERSION_PATCH（TF-A 2.8 以前的寫法），版本記為 2.8" in c["basis"] and "LTS" in c["basis"]
    assert not any("TF-A" in g for g in rep["gaps"])


def test_tfa_with_version_patch_unchanged(tmp_path):
    rep, comps = ts.scan(tree(tmp_path / "t", tfa="2.12.1"))
    c = by_kind(comps)["tfa"]
    assert c["version"] == "2.12.1" and "VERSION_PATCH;" not in c["basis"] and "沒有" not in c["basis"]


@pytest.mark.parametrize("mk", [
    "VERSION_MAJOR := 2\nVERSION_MINOR := 8\nVERSION_PATCH := 1\nVERSION_PATCH := 2\n",   # PATCH 矛盾
    "VERSION_MAJOR := 2\nVERSION_MINOR := 8\nVERSION_PATCH := x\n",                      # PATCH 不是數字
    "VERSION_MAJOR := 2\nVERSION_MINOR := 7\nVERSION_MINOR := 8\n",                      # MINOR 矛盾
    "VERSION_MAJOR := 2\n",                                                              # 缺 MINOR
    "VERSION_MINOR := 8\n",                                                              # 缺 MAJOR
])
def test_tfa_contradictory_or_missing_major_minor_stays_gap(tmp_path, mk):
    t = tmp_path / "t"
    w(t / "atf" / "arm-trusted-firmware" / "Makefile", mk)
    rep, comps = ts.scan(t)
    c = by_kind(comps)["tfa"]
    assert c["version"] is None and c["cpe"] is None and rep["status"] == "GAP" and any("TF-A" in g for g in rep["gaps"])
