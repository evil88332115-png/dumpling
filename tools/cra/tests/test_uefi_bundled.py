"""uefi_bundled.py + cra_report.py --uefi-source：UEFI 內建函式庫併進產品 SBOM、Grype 的比對成為風險表的列。
假樹由 test_uefi_source.py 的 helper 組出來（真的跑 uefi_source.py），Grype 的結果是照 Grype 0.121.0 實際輸出的形狀寫的假資料
（CVE-2099-… 是不存在的編號）；沒有任何產品資料。"""
import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import uefi_bundled as ub  # noqa: E402
import uefi_source as us  # noqa: E402
from test_cra_report import MIN_CFG, make_project, make_scan, run, write_json  # noqa: E402
from test_uefi_source import git, w  # noqa: E402

CLI = HERE.parent / "uefi_source.py"


def vdat(major, minor, patch):
    return f'MAJOR={major}\nMINOR={minor}\nPATCH={patch}\nPRE_RELEASE_TAG=\nBUILD_METADATA=\nRELEASE_DATE="1 Jan 2025"\nSHLIB_VERSION=3\n'


def tree(d, openssl="3.4.1", submodule="ok"):
    """edk2 的假樹（OpenSSL submodule：ok＝VERSION.dat、conflict＝VERSION.dat 與 opensslv.h 不同、empty＝空資料夾、missing＝沒有資料夾）。"""
    d = Path(d)
    w(d / "MdePkg" / "MdePkg.dec", "[Defines]\n")
    w(d / ".gitmodules", f'[submodule "{us.OPENSSL_SUB}"]\n\tpath = {us.OPENSSL_SUB}\n\turl = https://example.invalid/x\n')
    o = d / us.OPENSSL_SUB
    if submodule in ("ok", "conflict"):
        w(o / "VERSION.dat", vdat(*openssl.split(".")))
    if submodule == "conflict":
        w(o / "include" / "openssl" / "opensslv.h", '# define OPENSSL_VERSION_TEXT "OpenSSL 3.0.15 3 Sep 2024"\n')
    if submodule == "empty":
        o.mkdir(parents=True)
    git(d, tags=["edk2-stable202411"])
    return d


def make_uefi(tmp, **kw):
    """假樹 → uefi_source.py → 輸出資料夾。"""
    out = Path(tmp) / "uefi-source"
    r = subprocess.run([sys.executable, "-I", str(CLI), "--tree", str(tree(Path(tmp) / "t", **kw)), "--out", str(out)],
                       capture_output=True, text=True)
    assert r.returncode in (0, 2) and r.stdout.startswith("X-uefi-source\t"), r
    return out


def grype_json(version="3.4.1", fixed="3.4.4", ids=("CVE-2099-0001",)):
    """Grype 0.121.0 對 pkg:generic 元件的輸出形狀：nvd:cpe、cpe-match、artifact type UnknownPackage。"""
    return {"matches": [{
        "vulnerability": {"id": i, "namespace": "nvd:cpe", "severity": "High", "dataSource": "https://nvd.nist.gov/vuln/detail/" + i,
                          "fix": {"versions": [fixed], "state": "fixed"}, "cvss": [], "epss": []},
        "relatedVulnerabilities": [],
        "matchDetails": [{"type": "cpe-match", "matcher": "stock-matcher",
                          "searchedBy": {"namespace": "nvd:cpe", "cpes": [f"cpe:2.3:a:openssl:openssl:{version}:*:*:*:*:*:*:*"]}}],
        "artifact": {"id": "x", "name": "openssl", "version": version, "type": "UnknownPackage", "purl": f"pkg:generic/openssl@{version}",
                     "cpes": [f"cpe:2.3:a:openssl:openssl:{version}:*:*:*:*:*:*:*"]}} for i in ids]}


def put_grype(uefi, g, status="OK", detail="database Built=2026-11-08T06:19:57Z (1 days)", sha=True):
    """grype.json＋grype-run.json（input_sha256＝現在的 uefi-source.cdx.json 該給 Grype 的 SBOM 的雜湊；sha=False 時不寫）。"""
    write_json(uefi / "grype.json", g)
    run_ = {"schema": "sca-center-uefi-grype/1", "status": status, "detail": detail, "db_built": "2026-11-08T06:19:57Z", "matches": len(g["matches"])}
    if sha:
        run_["grype_sha256"] = hashlib.sha256((uefi / "grype.json").read_bytes()).hexdigest()
        run_["input_sha256"] = hashlib.sha256(ub.grype_input(json.loads((uefi / "uefi-source.cdx.json").read_text()))[0]).hexdigest()
    write_json(uefi / "grype-run.json", run_)


def report(tmp_path, uefi=None, *extra):
    proj, scan = make_project(tmp_path / "p", MIN_CFG), make_scan(tmp_path / "res" / "scan")
    if uefi is not None:
        os.replace(uefi, scan.parent / "uefi-source")
    r, s, rep = run(proj, scan, *extra)
    assert r.returncode in (0, 2), r.stdout + r.stderr
    return s, rep, json.loads((rep / "sbom.cdx.json").read_text(encoding="utf-8"))


# ---------- 比對成列 ----------

def test_openssl3_match_becomes_row_and_component(tmp_path):
    u = make_uefi(tmp_path)
    put_grype(u, grype_json())
    s, rep, bom = report(tmp_path, u)
    md = (rep / "risk-assessment.md").read_text(encoding="utf-8")
    assert "OpenSSL 3.4.1 (bundled in UEFI)" in md and "CVE-2099-0001" in md
    assert "rebuild the UEFI with OpenSSL 3.4.4 or later" in md and "an apt upgrade does not apply" in md
    # 產品 SBOM：函式庫是元件，依賴掛在 UEFI 元件下，UEFI 元件掛在產品下
    o = next(c for c in bom["components"] if c["name"] == "openssl" and c["purl"].startswith("pkg:generic/"))
    assert o["purl"] == "pkg:generic/openssl@3.4.1" and o["version"] == "3.4.1" and o["cpe"].startswith("cpe:2.3:a:openssl:openssl:3.4.1:")
    deps = {d["ref"]: d["dependsOn"] for d in bom["dependencies"]}
    assert o["bom-ref"] in deps["uefi-source:edk2"] and "uefi-source:edk2" in deps[bom["metadata"]["component"]["bom-ref"]]
    u_ = s["product_sbom"]["uefi_source"]
    assert u_["rows"] == 1 and u_["matches"] == 1 and u_["status"] == "ATTENTION" and not u_["gaps"]      # edk2 是 NOT_ASSESSED（ATTENTION，不是 GAP）    
    assert "Libraries bundled in the UEFI" in (rep / "sbom.md").read_text(encoding="utf-8")


def test_row_is_in_the_risk_table_with_found_by_grype(tmp_path):
    u = make_uefi(tmp_path)
    put_grype(u, grype_json(ids=("CVE-2099-0001", "CVE-2099-0002")))
    s, rep, _ = report(tmp_path, u)
    assert s["product_sbom"]["uefi_source"]["rows"] == 2


def test_no_fixed_version_says_so(tmp_path):
    u = make_uefi(tmp_path)
    g = grype_json()
    g["matches"][0]["vulnerability"]["fix"] = {"versions": [], "state": "not-fixed"}
    put_grype(u, g)
    _, rep, _ = report(tmp_path, u)
    md = (rep / "risk-assessment.md").read_text(encoding="utf-8")
    assert "no fixed OpenSSL version known to Grype (not-fixed)" in md


# ---------- GAP ----------

@pytest.mark.parametrize("sub", ["conflict", "empty", "missing"])
def test_unknown_version_is_gap_not_clean(tmp_path, sub):
    """版本檔互相矛盾／submodule 空資料夾／沒有 submodule：版本不明 → 不比對、GAP／NOT_ASSESSED，不顯示成沒有弱點。"""
    u = make_uefi(tmp_path, submodule=sub)
    s, rep, bom = report(tmp_path, u)
    o = next(c for c in bom["components"] if c["name"] == "openssl" and c["purl"].startswith("pkg:generic/"))
    assert "version" not in o and "cpe" not in o
    info = s["product_sbom"]["uefi_source"]
    assert info["status"] == "GAP" and info["rows"] == 0
    assert any("openssl" in g.lower() and "NOT_ASSESSED" in g for g in info["gaps"])
    assert s["documents"]["sbom"]["status"] == "GAP"
    assert "version unknown" in (rep / "sbom.md").read_text(encoding="utf-8")


def test_known_version_but_grype_missing_is_gap(tmp_path):
    u = make_uefi(tmp_path)         # 沒有 grype.json／grype-run.json
    s, rep, _ = report(tmp_path, u)
    info = s["product_sbom"]["uefi_source"]
    assert info["rows"] == 0 and info["matches"] is None and info["status"] == "GAP"
    assert any("NOT matched against vulnerability data" in g for g in info["gaps"])
    assert "OpenSSL 3.4.1 (bundled in UEFI)" not in (rep / "risk-assessment.md").read_text(encoding="utf-8")


def test_grype_not_run_status_is_gap_even_with_old_matches_file(tmp_path):
    u = make_uefi(tmp_path)
    put_grype(u, grype_json(), status="NOT_RUN", detail="Grype database not usable")
    s, _, _ = report(tmp_path, u)
    assert s["product_sbom"]["uefi_source"]["rows"] == 0 and s["product_sbom"]["uefi_source"]["status"] == "GAP"


def test_stale_database_matches_are_rows_but_gap(tmp_path):
    u = make_uefi(tmp_path)
    put_grype(u, grype_json(), status="GAP", detail="database Built=2026-10-01, 40 days old (limit 3)")
    s, rep, _ = report(tmp_path, u)
    info = s["product_sbom"]["uefi_source"]
    assert info["rows"] == 1 and any("40 days old" in g for g in info["gaps"])


@pytest.mark.parametrize("mode", ["empty_dir", "garbage", "not_object"])
def test_missing_or_unreadable_uefi_output_is_gap(tmp_path, mode):
    u = tmp_path / "uefi-source"
    u.mkdir()
    if mode == "garbage":
        (u / "uefi-source.cdx.json").write_text("{not json")
    if mode == "not_object":
        write_json(u / "uefi-source.cdx.json", {"components": [3, "x", {"name": 1}]})
    s, rep, bom = report(tmp_path, u)
    info = s["product_sbom"]["uefi_source"]
    assert info["status"] == "GAP" and info["rows"] == 0 and info["libs"] == []
    assert s["documents"]["sbom"]["status"] == "GAP"
    assert "NOT_ASSESSED" in " ".join(info["gaps"])
    assert not any(c["purl"].startswith("pkg:generic/openssl") for c in bom["components"] if "purl" in c)


def test_cpe_version_differs_from_component_version_is_dropped(tmp_path):
    """Grype 用 CPE 的版本、不用元件的 version（實測）：兩者不同就不給 CPE，免得報告寫 3.4.1 卻是拿 1.1.1w 比對的。"""
    u = make_uefi(tmp_path)
    p = u / "uefi-source.cdx.json"
    d = json.loads(p.read_text())
    next(c for c in d["components"] if c["name"] == "openssl")["cpe"] = "cpe:2.3:a:openssl:openssl:1.1.1w:*:*:*:*:*:*:*"
    write_json(p, d)
    info = ub.load(u)
    o = next(c for c in info["comps"] if c["name"] == "openssl")
    assert "cpe" not in o and any("differs from the component version" in g for g in info["gaps"]) and info["status"] == "GAP"
    assert not next(l for l in info["libs"] if l["name"] == "openssl")["known"]


# ---------- 沒有輸入 ----------

def test_no_input_changes_nothing(tmp_path):
    s, rep, bom = report(tmp_path)
    assert "uefi_source" not in s["product_sbom"]
    assert not any("uefi" in json.dumps(c).lower() for c in bom["components"])
    for f in rep.iterdir():
        if f.suffix in (".md", ".json"):
            assert "bundled in UEFI" not in f.read_text(encoding="utf-8")


def test_explicit_option_must_be_a_directory(tmp_path):
    proj, scan = make_project(tmp_path / "p", MIN_CFG), make_scan(tmp_path / "scan")
    r, _, _ = run(proj, scan, "--uefi-source", str(tmp_path / "nope"))
    assert r.returncode == 64
    u = make_uefi(tmp_path)
    put_grype(u, grype_json())
    r, s, _ = run(proj, scan, "--uefi-source", str(u))
    assert r.returncode in (0, 2) and s["product_sbom"]["uefi_source"]["rows"] == 1


# ---------- grype 動作（假的 grype 執行檔） ----------

FAKE = """#!/bin/sh
echo "$GRYPE_DB_AUTO_UPDATE $GRYPE_CHECK_FOR_APP_UPDATE $GRYPE_DB_CACHE_DIR $*" >> "$FAKE_LOG"
if [ "$1" = db ]; then printf 'Status:    %s\\nBuilt:     %s\\n' "${FAKE_STATUS:-valid}" "$FAKE_BUILT"; exit 0; fi
if [ -n "$FAKE_OUT" ]; then cat "$FAKE_OUT"; exit 0; fi
echo boom >&2; exit 1
"""


def fake_grype(tmp_path, g=None, built="2999-01-01T00:00:00Z", status="valid"):
    exe = tmp_path / "grype"
    exe.write_text(FAKE)
    exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
    env = {"FAKE_LOG": str(tmp_path / "log"), "FAKE_BUILT": built, "FAKE_STATUS": status, "PATH": os.environ["PATH"], "HOME": str(tmp_path),
           **{k: os.environ[k] for k in ("LD_LIBRARY_PATH",) if k in os.environ}}   # CI 的 python 動態連結 libpython，要 LD_LIBRARY_PATH
    if g is not None:
        write_json(tmp_path / "g.json", g)
        env["FAKE_OUT"] = str(tmp_path / "g.json")
    return exe, env


def test_run_grype_is_offline_and_writes_result(tmp_path):
    u = make_uefi(tmp_path)
    exe, env = fake_grype(tmp_path, grype_json())
    st, detail = ub.run_grype(u, str(exe), 3, env)
    assert st == "OK" and "1 matches" in detail
    assert json.loads((u / "grype.json").read_text())["matches"][0]["artifact"]["name"] == "openssl"
    log = (tmp_path / "log").read_text()
    assert "false false " in log and f"sbom:{u / 'grype-input.cdx.json'} -o json" in log and "db update" not in log
    assert str(tmp_path / ".cache/grype/db") in log        # 預設資料庫位置同 sca-scan（$HOME/.cache/grype/db）
    info = ub.load(u)
    assert info["matches"] == 1 and info["grype_run"]["status"] == "OK"


def test_run_grype_stale_or_invalid_or_failing(tmp_path):
    u = make_uefi(tmp_path)
    exe, env = fake_grype(tmp_path, grype_json(), built="2020-01-01T00:00:00Z")
    assert ub.run_grype(u, str(exe), 3, env)[0] == "GAP"
    assert (u / "grype.json").exists()
    exe, env = fake_grype(tmp_path, grype_json(), status="invalid")
    assert ub.run_grype(u, str(exe), 3, env)[0] == "NOT_RUN" and not (u / "grype.json").exists()
    exe, env = fake_grype(tmp_path, None)
    assert ub.run_grype(u, str(exe), 3, env)[0] == "FAIL" and not (u / "grype.json").exists()
    assert ub.run_grype(u, str(tmp_path / "no-such-grype"), 3, env)[0] == "NOT_RUN"
    assert json.loads((u / "grype-run.json").read_text())["status"] == "NOT_RUN"


def test_run_grype_without_a_cpe_component_is_not_run(tmp_path):
    u = make_uefi(tmp_path, submodule="empty")
    d = json.loads((u / "uefi-source.cdx.json").read_text())
    for c in d["components"]:
        c.pop("cpe", None)          # edk2 的 upstream tag 也有 CPE；這裡要沒有任何 CPE
    write_json(u / "uefi-source.cdx.json", d)
    exe, env = fake_grype(tmp_path, grype_json())
    st, detail = ub.run_grype(u, str(exe), 3, env)
    assert st == "NOT_RUN" and "nothing Grype could match" in detail and not (tmp_path / "log").exists()


def test_cli_grype_line_and_exit_code(tmp_path):
    u = make_uefi(tmp_path)
    exe, env = fake_grype(tmp_path, grype_json())
    r = subprocess.run([sys.executable, "-I", str(HERE.parent / "uefi_bundled.py"), "grype", "--dir", str(u), "--grype", str(exe)],
                       capture_output=True, text=True, env=env)
    assert r.returncode == 0 and r.stdout.startswith("B-uefi-grype\tOK\t"), r


# ---------- edk2 不比對、Grype 的輸入、過期的結果、重用、截斷、副本 ----------

def test_edk2_is_not_matched_and_listed_not_assessed_with_reason(tmp_path):
    """edk2 的 CPE 不給 Grype（NVD 範圍沒有上界）；報告與 SBOM 寫 NOT_ASSESSED 與原因；只有這樣是 ATTENTION，不是 GAP。"""
    u = make_uefi(tmp_path)
    cdx = json.loads((u / "uefi-source.cdx.json").read_text())
    assert any(c["name"] == "edk2" and c.get("cpe") for c in cdx["components"])      # 來源有 edk2 的 CPE
    body, purls = ub.grype_input(cdx)
    sent = json.loads(body)
    assert [c["name"] for c in sent["components"]] == ["openssl"] and not any("edk2" in c["purl"] for c in sent["components"])
    put_grype(u, grype_json())
    s, rep, bom = report(tmp_path, u)
    info = s["product_sbom"]["uefi_source"]
    assert info["status"] == "ATTENTION" and info["gaps"] == []
    assert any("edk2" in a and "NOT_ASSESSED" in a and "no upper bound" in a and "NVIDIA" in a for a in info["attention"])
    e = next(c for c in bom["components"] if c["name"] == "edk2")
    assert "cpe" not in e and any(p["name"] == "sca-center:not-assessed" and "NOT_ASSESSED" in p["value"] for p in e["properties"])
    assert "no upper bound" in (rep / "sbom.md").read_text(encoding="utf-8")


def test_match_on_a_component_that_was_not_sent_is_dropped(tmp_path):
    """第二道防線：Grype 的比對對到不在允許清單的元件（例如 edk2）→ 丟掉，不成列。"""
    u = make_uefi(tmp_path)
    g = grype_json()
    bad = json.loads(json.dumps(g["matches"][0]))
    bad["vulnerability"]["id"] = "CVE-2014-4859"
    bad["artifact"].update(name="edk2", version="202411", purl="pkg:generic/edk2")
    g["matches"].append(bad)
    put_grype(u, g)
    info = ub.load(u)
    assert info["matches"] == 1 and [m["vulnerability"]["id"] for m in info["grype"]["matches"]] == ["CVE-2099-0001"]
    assert any("dropped" in a for a in info["attention"])
    s, rep, _ = report(tmp_path, u)
    assert s["product_sbom"]["uefi_source"]["rows"] == 1 and "CVE-2014-4859" not in (rep / "risk-assessment.md").read_text(encoding="utf-8")


def test_run_grype_filters_what_it_gets_back_and_what_it_sends(tmp_path):
    u = make_uefi(tmp_path)
    g = grype_json()
    bad = json.loads(json.dumps(g["matches"][0]))
    bad["artifact"].update(name="edk2", purl="pkg:generic/edk2")
    g["matches"].append(bad)
    exe, env = fake_grype(tmp_path, g)
    assert ub.run_grype(u, str(exe), 3, env)[0] == "OK"
    assert len(json.loads((u / "grype.json").read_text())["matches"]) == 1
    sent = json.loads((u / "grype-input.cdx.json").read_text())
    assert [c["name"] for c in sent["components"]] == ["openssl"]
    run_ = json.loads((u / "grype-run.json").read_text())
    assert run_["input_sha256"] == hashlib.sha256((u / "grype-input.cdx.json").read_bytes()).hexdigest()
    assert ub.load(u)["status"] == "ATTENTION"


def test_cpe_mismatch_component_is_not_sent_to_grype(tmp_path):
    u = make_uefi(tmp_path)
    p = u / "uefi-source.cdx.json"
    d = json.loads(p.read_text())
    next(c for c in d["components"] if c["name"] == "openssl")["cpe"] = "cpe:2.3:a:openssl:openssl:1.1.1w:*:*:*:*:*:*:*"
    write_json(p, d)
    body, purls = ub.grype_input(d)
    assert purls == set() and json.loads(body)["components"] == []
    exe, env = fake_grype(tmp_path, grype_json())
    assert ub.run_grype(u, str(exe), 3, env)[0] == "NOT_RUN" and not (tmp_path / "log").exists()


@pytest.mark.parametrize("how", ["changed_input", "no_hash"])
def test_stale_or_unhashed_grype_result_is_not_used(tmp_path, how):
    """grype-run.json 的 input_sha256 和現在的 uefi-source 不符、或沒有 → 比對結果不當成現行的使用（GAP）。"""
    u = make_uefi(tmp_path)
    put_grype(u, grype_json(), sha=(how != "no_hash"))
    if how == "changed_input":
        p = u / "uefi-source.cdx.json"
        d = json.loads(p.read_text())
        o = next(c for c in d["components"] if c["name"] == "openssl")
        o.update(version="3.4.2", purl="pkg:generic/openssl@3.4.2", cpe="cpe:2.3:a:openssl:openssl:3.4.2:*:*:*:*:*:*:*")
        write_json(p, d)
    s, rep, _ = report(tmp_path, u)
    info = s["product_sbom"]["uefi_source"]
    assert info["status"] == "GAP" and info["rows"] == 0 and info["matches"] is None
    assert any("not for the current uefi-source output" in g for g in info["gaps"])
    assert "CVE-2099-0001" not in (rep / "risk-assessment.md").read_text(encoding="utf-8")


def test_reused_output_is_visible(tmp_path):
    u = make_uefi(tmp_path)
    put_grype(u, grype_json())
    write_json(u / "reused.json", {"reused": True, "original_date": "2026-11-01T00:00:00Z"})
    s, rep, _ = report(tmp_path, u)
    info = s["product_sbom"]["uefi_source"]
    assert info["status"] == "ATTENTION" and any("NOT re-read in this run" in a and "2026-11-01" in a for a in info["attention"])
    assert "NOT re-read in this run" in (rep / "sbom.md").read_text(encoding="utf-8")
    assert "NOT re-read in this run" in (rep / "risk-assessment.md").read_text(encoding="utf-8")
    assert s["product_sbom"]["uefi_source"]["rows"] == 1


def test_truncation_and_skipped_components_are_gaps_with_counts(tmp_path):
    u = make_uefi(tmp_path)
    p = u / "uefi-source.cdx.json"
    d = json.loads(p.read_text())
    d["components"] += [3, {"bom-ref": "x"}, dict(d["components"][1])]                         # 非物件、沒有 name、重複的 bom-ref
    d["components"] += [{"type": "library", "bom-ref": f"extra:{i}", "name": f"lib{i}", "purl": f"pkg:generic/lib{i}"} for i in range(ub.MAX_COMPS)]
    write_json(p, d)
    info = ub.load(u)
    n = len(d["components"])
    assert any(f"{n - ub.MAX_COMPS} component(s)" in g and "beyond the limit" in g for g in info["gaps"])
    assert info["status"] == "GAP" and len(info["comps"]) <= ub.MAX_COMPS


def test_skipped_components_named_in_gap(tmp_path):
    u = make_uefi(tmp_path)
    p = u / "uefi-source.cdx.json"
    d = json.loads(p.read_text())
    d["components"] += [3, {"bom-ref": "x"}, dict(d["components"][1])]
    write_json(p, d)
    info = ub.load(u)
    assert any("3 component(s)" in g and "skipped" in g for g in info["gaps"]) and info["status"] == "GAP"


def test_other_copy_rows_do_not_say_bundled_and_fix_stays_on_the_release_line(tmp_path):
    u = make_uefi(tmp_path)
    p = u / "uefi-source.cdx.json"
    d = json.loads(p.read_text())
    o = next(c for c in d["components"] if c["name"] == "openssl")
    d["components"].append({"type": "library", "bom-ref": "uefi-source:openssl:other/copy", "name": "openssl", "version": "3.0.15",
                            "purl": "pkg:generic/openssl@3.0.15", "cpe": "cpe:2.3:a:openssl:openssl:3.0.15:*:*:*:*:*:*:*",
                            "properties": [{"name": "sca-center:uefi:role", "value": "other-copy"}, {"name": "sca-center:uefi:path", "value": "other/copy"}]})
    write_json(p, d)
    g = grype_json(version="3.0.15", fixed="3.0.19")
    g["matches"][0]["vulnerability"]["fix"]["versions"] = ["3.0.19", "3.3.6", "3.4.4"]
    g["matches"] += grype_json(version="3.4.1")["matches"]
    g["matches"][1]["vulnerability"]["id"] = "CVE-2099-0002"
    g["matches"][1]["vulnerability"]["fix"]["versions"] = ["3.0.19", "3.3.6", "3.4.4"]
    put_grype(u, g)
    s, rep, _ = report(tmp_path, u)
    md = (rep / "risk-assessment.md").read_text(encoding="utf-8")
    assert "OpenSSL 3.0.15 (copy in the UEFI source tree)" in md and "not confirmed to be built into the firmware" in md
    assert "OpenSSL 3.0.15 (bundled in UEFI)" not in md
    assert "OpenSSL 3.4.1 (bundled in UEFI)" in md and "rebuild the UEFI with OpenSSL 3.4.4 or later" in md
    assert "Grype lists fixes for several release lines: 3.0.19, 3.3.6, 3.4.4" in md


@pytest.mark.parametrize("st", ["GAP", "FAIL"])
def test_source_gap_without_reasons_is_not_ok(tmp_path, st):
    u = make_uefi(tmp_path)
    r = json.loads((u / "uefi-source.json").read_text())
    r.update(status=st, gaps=[], attention=[])
    write_json(u / "uefi-source.json", r)
    info = ub.load(u)
    assert info["status"] == "GAP" and any("without giving a reason" in g for g in info["gaps"])
