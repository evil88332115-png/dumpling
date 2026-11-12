"""NVIDIA 安全公告（Jetson Linux）的比對與待審清單（lib/nvidia_bulletins.py）、公告鏡像腳本（tools/mirror/nvidia-bulletins.sh）、
預填的對照表（lib/nvidia-bulletins.json）。
欄位格式取自真實資料：NVIDIA/product-security commit 6e340ebe 的 5797（CSAF 2.0、Markdown 表格）與
Jetson Linux R39.2.1 映像的 Syft 1.55.0 SBOM（tests/fixtures/jetson-r39.2.1-base.cdx.json.xz）。"""
import datetime
import hashlib
import io
import json
import lzma
import os
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

PILOT = Path(__file__).resolve().parents[1]
ROOT = PILOT.parents[1]
LIB = PILOT / "lib" / "nvidia_bulletins.py"
TABLE = PILOT / "lib" / "nvidia-bulletins.json"
MIRROR_SH = ROOT / "tools" / "mirror" / "nvidia-bulletins.sh"
FIXTURE = ROOT / "tests" / "fixtures" / "jetson-r39.2.1-base.cdx.json.xz"
sys.path.insert(0, str(PILOT / "lib"))
import nvidia_bulletins as nb  # noqa: E402

NOW = datetime.datetime.now(datetime.timezone.utc)
MD_5797 = """### Security Bulletin: NVIDIA Jetson and IGX Devices - March 2026

### Security Updates

| **CVE IDs Addressed** | **Affected Products** | **Platform or OS** | **Affected Versions** | **Updated Version** |
| --------------------- | --------------------- | ----------------- | --------------------- | ------------------- |
| CVE-2026-24148 | Jetson Xavier Series and Jetson Orin Series | Jetson Linux(35) | All versions prior to 35.6.4 | 35.6.4 |
| CVE-2026-24148 | Jetson Xavier Series and Jetson Orin Series | Jetson Linux(36) | All versions prior to 36.5 | 36.5 |
| CVE-2026-24154 | Jetson Xavier Series, Jetson Orin Series and Jetson Thor | Jetson Linux(38) | 38.2 | 38.4 |

### Notes
"""


def deb(name, ver):
    return {"type": "library", "name": name, "version": ver, "purl": f"pkg:deb/ubuntu/{name}@{ver}?arch=arm64&distro=ubuntu-24.04"}


def l4t_sbom(rel="36.4.3", ts="20250101000000", core=True, extra=()):
    comps = [deb("nvidia-l4t-kernel", f"5.15.148-tegra-{rel}-{ts}"), deb("nvidia-l4t-initrd", f"{rel}-{ts}"),
             deb("openssl", "3.0.13-0ubuntu3.5")]
    if core:
        comps.append(deb("nvidia-l4t-core", f"{rel}-{ts}"))
    return {"bomFormat": "CycloneDX", "components": comps + list(extra)}


def csaf_cves():
    return {"CVE-2026-24148": {"severity": "HIGH", "cvss_v3_score": 8.3, "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L",
                               "cwe": "CWE-1188", "description": "NVIDIA Jetson for JetPack contains a vulnerability in the system initialization logic",
                               "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-24148"]},
            "CVE-2026-24154": {"severity": "HIGH", "cvss_v3_score": 7.6, "cvss_v3_vector": "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                               "cwe": "CWE-78", "description": "NVIDIA Jetson Linux has vulnerability in initrd", "references": []}}


def row(cve, line, fixed=None, below=None, mx=None, reviewed=True, where="nvidia-l4t-initrd", bulletin="5797"):
    return {"bulletin": bulletin, "cve": cve, "line": line, "product_text": "Jetson Orin Series", "platform_text": f"Jetson Linux({line})",
            "affected_text": f"All versions prior to {below}" if below else (f"{mx} and earlier" if mx else ""), "fixed_text": fixed or "",
            "affected_below": below, "affected_max": mx, "fixed_in": fixed, "component": "initrd", "where_it_lives": where,
            "source": {"file": "2026/5797/5797.md", "row": f"| {cve} | ... |"},
            "reviewed": reviewed, "reviewed_by": "王小明" if reviewed else None, "reviewed_at": "2026-11-01" if reviewed else None, "note": ""}


def table(rows, reviewed_until="2026-03-31", na=()):
    return {"schema": nb.TABLE_SCHEMA, "reviewed_until": reviewed_until,
            "bulletins": [{"id": "5797", "year": "2026", "title": "Security Bulletin: NVIDIA Jetson and IGX Devices - March 2026",
                           "current_release_date": "2026-03-31T00:00:00Z", "url": "https://github.com/NVIDIA/product-security/blob/main/2026/5797/5797.md",
                           "cves": csaf_cves()}],
            "not_applicable": list(na), "rows": rows}


def make_mirror(d, bulletins=(("5797", "2026", "2026-03-31T00:00:00Z", "Security Bulletin: NVIDIA Jetson and IGX Devices - March 2026"),),
                fetched=None, md=MD_5797):
    d = Path(d)
    d.mkdir(parents=True)
    fetched = (fetched or NOW).strftime("%Y-%m-%dT%H:%M:%SZ")
    (d / "SOURCE").write_text(f"commit={'a' * 40}\nfetched_utc={fetched}\n", encoding="utf-8")
    idx = []
    for bid, year, date, title in bulletins:
        idx.append({"id": bid, "year": year, "title": title, "initial_release_date": date, "current_release_date": date,
                    "revision": "1.0.0", "csaf": True, "selected": True, "match": ["title"]})
        b = d / year / bid
        b.mkdir(parents=True)
        doc = {"document": {"title": title, "tracking": {"id": bid, "current_release_date": date}},
               "vulnerabilities": [{"cve": "CVE-2026-24148", "cwe": {"id": "CWE-1188"},
                                    "notes": [{"category": "summary", "text": "NVIDIA Jetson for JetPack contains a vulnerability in the system initialization logic"}],
                                    "scores": [{"cvss_v3": {"baseScore": 8.3, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/AV:N"}}],
                                    "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2026-24148"}]},
                                   {"cve": "CVE-2026-24154", "notes": [{"category": "summary", "text": "NVIDIA Jetson Linux has vulnerability in initrd"}]}]}
        (b / f"{bid}.json").write_text(json.dumps(doc), encoding="utf-8")
        (b / f"{bid}.md").write_text(md, encoding="utf-8")
    idx.append({"id": "5861", "year": "2026", "title": "NVIDIA GPU Display Driver", "selected": False, "match": []})
    (d / "index.json").write_text(json.dumps({"bulletins": idx}), encoding="utf-8")
    return d


def run(*args, env=None):
    r = subprocess.run(["python3", "-I", str(LIB), *map(str, args)], capture_output=True, text=True,
                       env={**os.environ, **(env or {})})
    lines = r.stdout.splitlines()
    assert len(lines) == 1, r
    stage, st, detail = lines[0].split("\t")
    assert "Traceback" not in r.stderr
    return r, stage, st, detail


def run_match(tmp_path, sbom, tbl, mirror=True, raw_sbom=None):
    s, t, o = tmp_path / "sbom.json", tmp_path / "table.json", tmp_path / "findings.json"
    s.write_text(raw_sbom if raw_sbom is not None else json.dumps(sbom), encoding="utf-8")
    if tbl is not None:
        t.write_text(tbl if isinstance(tbl, str) else json.dumps(tbl, ensure_ascii=False), encoding="utf-8")
    args = ["match", "--sbom", s, "--table", t, "--out", o]
    if mirror is True:
        mirror = make_mirror(tmp_path / "mirror")
    if mirror:
        args += ["--mirror", mirror]
    r, stage, st, detail = run(*args)
    assert stage == "C-nvidia-bulletins"
    out = json.loads(o.read_text(encoding="utf-8")) if r.returncode == 0 else None
    return r, st, detail, out


# ---------- 版本 ----------

def test_version_compare_dotted_ints():
    assert nb.cmp_version("35.6.2", "35.6.4") < 0
    assert nb.cmp_version("35.6.4", "36.5") < 0
    assert nb.cmp_version("36.5", "36.5.0") == 0
    assert nb.cmp_version("36.4", "36.4.3") < 0
    assert nb.cmp_version("36.10", "36.9") > 0      # 不是字串比較
    for bad in ("JP6", "36.5-rc1", "", None, "36..5"):
        with pytest.raises(ValueError):
            nb.vkey(bad)


@pytest.mark.parametrize("text,below,mx", [
    ("All versions prior to 36.5", "36.5", None),
    ("All versions prior to JP5.x: 35.6.2", "35.6.2", None),
    ("35.6.2 and earlier", None, "35.6.2"),
    ("All versions prior to and including 32.7.4", None, "32.7.4"),
    ("38.2", None, "38.2"),
    ("Versions 35.1 and 34.1.1", None, None),
    ("IGX 1.1.2 and earlier", None, "1.1.2"),
])
def test_parse_affected_free_text(text, below, mx):
    assert nb.parse_affected(text) == (below, mx)


def test_parse_fixed_and_line():
    assert nb.parse_fixed("35.6.3 and newer") == "35.6.3"
    assert nb.parse_fixed("Kernel SRU 1035 and newer") is None
    assert nb.infer_line("Jetson Linux(36)", "", ()) == ("36", "platform")
    assert nb.infer_line("Jetson Linux-35", "", ()) == ("35", "platform")
    assert nb.infer_line("Jetson Linux(JP6)", "", ()) == ("36", "platform_jetpack")
    assert nb.infer_line("Jetson Linux", "Jetson AGX Orin Series (rel35)", ()) == ("35", "product")
    assert nb.infer_line("IGX OS", "IGX Orin", ()) == ("IGX", "platform")
    assert nb.infer_line("Linux", "CUDA Toolkit", ("All versions prior to nvJPEG 25.03",)) == (None, None)


# ---------- 偵測 ----------

def test_detect_real_jetson_fixture():
    sbom = json.loads(lzma.open(FIXTURE).read())
    det = nb.detect_jetson(sbom)
    assert det["version"] == "39.2.1" and det["line"] == "39" and det["build"] == "20260806224157"
    assert det["basis"] == "nvidia-l4t-core" and det["anchor"]["name"] == "nvidia-l4t-core"
    assert det["anchor"]["purl"].startswith("pkg:deb/ubuntu/nvidia-l4t-core@39.2.1-")   # namespace 是 Syft 給的，第一階段不改
    assert det["other_versions"] == []
    assert det["packages"]["nvidia-l4t-kernel"]["version"] == "6.8.12-tegra-39.2.1-20260806224157"   # 核心套件的格式也認得
    assert det["l4t_packages"] > 50


def test_detect_without_core_uses_majority_and_ignores_non_deb():
    sbom = l4t_sbom(core=False, extra=[{"name": "nvidia-l4t-fake", "version": "35.1.0-20220101000000", "purl": "pkg:generic/nvidia-l4t-fake@x"}])
    det = nb.detect_jetson(sbom)
    assert det["version"] == "36.4.3" and "nvidia-l4t-core" in det["basis"] and det["other_versions"] == []


def test_not_jetson_is_not_run(tmp_path):
    r, st, detail, out = run_match(tmp_path, {"components": [deb("openssl", "3.0.13")]}, table([]))
    assert r.returncode == 0 and st == "NOT_RUN" and out["findings"] == []


# ---------- match ----------

def test_reviewed_row_gives_finding_unreviewed_does_not(tmp_path):
    rows = [row("CVE-2026-24154", "36", fixed="36.5", below="36.5"),
            row("CVE-2026-24154", "36", fixed="36.5", below="36.5", where="flash"),          # 同 CVE 另一列：不重複
            row("CVE-2026-24148", "36", fixed="36.5", below="36.5", reviewed=False)]
    r, st, detail, out = run_match(tmp_path, l4t_sbom("36.4.3"), table(rows))
    assert r.returncode == 0
    assert [f["vulnerability"]["vulnId"] for f in out["findings"]] == ["CVE-2026-24154"]
    f = out["findings"][0]
    assert f["component"] == {"name": "nvidia-l4t-initrd", "version": "36.4.3-20250101000000",
                              "purl": "pkg:deb/ubuntu/nvidia-l4t-initrd@36.4.3-20250101000000?arch=arm64&distro=ubuntu-24.04"}
    v = f["vulnerability"]
    assert v["source"] == "NVIDIA" and v["aliases"] == [{"cveId": "CVE-2026-24154"}] and v["severity"] == "HIGH"
    assert v["cvssV3BaseScore"] == 7.6 and v["cvssV3Vector"].startswith("CVSS:3.1/AV:P")
    assert v["references"][0].endswith("/2026/5797/5797.md")
    assert f["evidence"]["bulletin"] == "5797" and f["evidence"]["where_it_lives"] == "nvidia-l4t-initrd"
    assert f["evidence"]["source"]["row"].startswith("| CVE-2026-24154") and len(f["evidence"]["other_rows"]) == 1
    # 未審核的列：不產生發現，只計數，另列給審核的人
    assert out["table"]["unreviewed_rows"] == 1 and out["unreviewed_would_match"][0]["cve"] == "CVE-2026-24148"
    assert out["unreviewed_would_match"][0]["severity"] == "HIGH"          # 公告的評級（cra_report 只顯示、不拿來分級）
    assert st == "ATTENTION" and "1 列未審核" in detail and "發現 1 筆" in detail


def test_all_reviewed_and_fixed_is_ok(tmp_path):
    rows = [row("CVE-2026-24154", "36", fixed="36.5", below="36.5"), row("CVE-2026-24148", "36", fixed="36.5", below="36.5")]
    r, st, detail, out = run_match(tmp_path, l4t_sbom("36.5"), table(rows))
    assert st == "OK" and out["findings"] == [] and len(out["fixed_per_bulletin"]) == 2
    assert len(detail.encode()) < 480


def test_flash_row_uses_core_and_says_so(tmp_path):
    rows = [row("CVE-2026-24154", "36", fixed="36.5", where="flash"), row("CVE-2026-24148", "36", fixed="36.5")]
    r, st, detail, out = run_match(tmp_path, l4t_sbom("36.4.3"), table(rows))
    f = next(x for x in out["findings"] if x["vulnerability"]["vulnId"] == "CVE-2026-24154")
    assert f["component"]["name"] == "nvidia-l4t-core" and "flash" in f["evidence"]["version_basis"]
    assert st == "OK" and "發現 2 筆" in detail


def test_line_not_listed_needs_vendor_confirmation_not_safe(tmp_path):
    rows = [row("CVE-2026-24148", "35", fixed="35.6.4", below="35.6.4"), row("CVE-2026-24148", "36", fixed="36.5", below="36.5"),
            row("CVE-2026-24154", "38", fixed="38.4", mx="38.2")]
    sbom = json.loads(lzma.open(FIXTURE).read())
    t = table(rows)
    t["bulletins"][0]["current_release_date"] = "2026-09-01T00:00:00Z"     # 公告修訂在 R39.2.1 建置（2026-08-06）之後
    r, st, detail, out = run_match(tmp_path, sbom, t)
    assert r.returncode == 0 and st == "ATTENTION" and out["findings"] == [] and out["presumed_included"] == []
    nc = {x["cve"]: x for x in out["needs_vendor_confirmation"]}
    assert set(nc) == {"CVE-2026-24148", "CVE-2026-24154"}
    assert nc["CVE-2026-24148"]["reason"] == "line_not_named" and nc["CVE-2026-24148"]["lines_named"] == ["35", "36"]
    assert "不是「不受影響」" in nc["CVE-2026-24148"]["detail"] and "不晚於公告 2026-09-01" in nc["CVE-2026-24148"]["detail"]
    assert "需原廠確認 2；" in detail and "39" in detail
    assert out["fixed_per_bulletin"] == []          # 沒列出的版本線不能算「已修正」


def test_range_gap_needs_confirmation(tmp_path):
    # 5716：受影響「36.4.4 and earlier」、修正「36.4.6 and newer」；36.4.5 公告沒寫
    rows = [row("CVE-2026-24154", "36", fixed="36.4.6", mx="36.4.4"), row("CVE-2026-24148", "36", fixed="36.5", below="36.5")]
    r, st, detail, out = run_match(tmp_path, l4t_sbom("36.4.5"), table(rows))
    assert st == "ATTENTION"
    assert [(x["cve"], x["reason"]) for x in out["needs_vendor_confirmation"]] == [("CVE-2026-24154", "range_gap")]
    assert [f["vulnerability"]["vulnId"] for f in out["findings"]] == ["CVE-2026-24148"]


def test_multiple_l4t_versions_is_attention(tmp_path):
    rows = [row("CVE-2026-24154", "36", fixed="36.5"), row("CVE-2026-24148", "36", fixed="36.5")]
    sbom = l4t_sbom("36.4.3", extra=[deb("nvidia-l4t-camera", "36.3.0-20240101000000")])
    r, st, detail, out = run_match(tmp_path, sbom, table(rows))
    assert st == "ATTENTION" and "36.3.0" in detail and out["jetson_linux"]["version"] == "36.4.3"


@pytest.mark.parametrize("case", ["no_mirror", "stale_mirror", "pending", "no_table"])
def test_gap_cases(tmp_path, case):
    rows = [row("CVE-2026-24154", "36", fixed="36.5"), row("CVE-2026-24148", "36", fixed="36.5")]
    tbl, mirror = table(rows), True
    if case == "no_mirror":
        mirror = None
    elif case == "stale_mirror":
        mirror = make_mirror(tmp_path / "m", fetched=NOW - datetime.timedelta(days=30))
    elif case == "pending":
        mirror = make_mirror(tmp_path / "m", bulletins=(("5797", "2026", "2026-03-31T00:00:00Z", "Jetson"),
                                                        ("5900", "2026", "2026-10-30T00:00:00Z", "Security Bulletin: NVIDIA Jetson - October 2026")))
    else:
        tbl = None
    r, st, detail, out = run_match(tmp_path, l4t_sbom("36.4.3"), tbl, mirror=mirror)
    assert r.returncode == 0 and st == "GAP"
    want = {"no_mirror": "沒有指定 NVIDIA 公告鏡像（--mirror；sca-scan 取自 PILOT_ENV 的 NVIDIA_BULLETINS_MIRROR）",
            "stale_mirror": "公告鏡像過期（", "pending": "鏡像有 1 個 Jetson／IGX 公告對照表還沒有或已被修訂（5900", "no_table": "沒有 NVIDIA 公告對照表"}[case]
    assert want in detail
    if case != "no_table":
        assert len(out["findings"]) == 2           # 發現照算，只是不能當作完整
    if case == "pending":
        assert out["pending_bulletins"][0]["id"] == "5900"


@pytest.mark.parametrize("what", ["bad_sbom", "bad_schema", "reviewed_without_who", "bad_version", "unknown_bulletin", "no_subcommand"])
def test_bad_input_exit_3(tmp_path, what):
    sbom, tbl, raw = l4t_sbom(), table([row("CVE-2026-24154", "36", fixed="36.5")]), None
    if what == "bad_sbom":
        raw = "{not json"
    elif what == "bad_schema":
        tbl["schema"] = "x"
    elif what == "reviewed_without_who":
        tbl["rows"][0]["reviewed_by"] = None
    elif what == "bad_version":
        tbl["rows"][0]["fixed_in"] = "JP6.2"
    elif what == "unknown_bulletin":
        tbl["rows"][0]["bulletin"] = "9999"
    if what == "no_subcommand":
        r, stage, st, detail = run()
    else:
        r, st, detail, _ = run_match(tmp_path, sbom, tbl, raw_sbom=raw)
    assert r.returncode == 3 and st == "FAIL" and "輸入錯誤" in detail


# ---------- candidates ----------

def run_cand(tmp_path, tbl, mirror, draft=False):
    t = tmp_path / "table.json"
    t.write_text(json.dumps(tbl, ensure_ascii=False), encoding="utf-8")
    args = ["candidates", "--mirror", mirror, "--table", t, "--out", tmp_path / "cand.json"]
    if draft:
        args += ["--draft", tmp_path / "draft.json"]
    r, stage, st, detail = run(*args)
    assert stage == "C-nvidia-bulletins-db"
    return r, st, detail, json.loads((tmp_path / "cand.json").read_text(encoding="utf-8")) if r.returncode == 0 else None


def test_candidates_none_pending_is_ok(tmp_path):
    rows = [row("CVE-2026-24154", "36", fixed="36.5")]
    r, st, detail, out = run_cand(tmp_path, table(rows), make_mirror(tmp_path / "m"))
    assert r.returncode == 0 and st == "OK" and out["pending"] == []


def test_candidates_lists_new_revised_and_unreviewed(tmp_path):
    m = make_mirror(tmp_path / "m", bulletins=(("5797", "2026", "2026-04-15T00:00:00Z", "Jetson (revised)"),
                                               ("5900", "2026", "2026-10-30T00:00:00Z", "Security Bulletin: NVIDIA Jetson - October 2026"),
                                               ("5560", "2024", "2024-08-07T00:00:00Z", "Security Bulletin: NVIDIA CV-CUDA - August 2024")))
    tbl = table([row("CVE-2026-24154", "36", fixed="36.5", reviewed=False)], reviewed_until="2026-04-30",
                na=[{"bulletin": "5560", "current_release_date": "2024-08-07T00:00:00Z", "reason": "不是 Jetson Linux BSP",
                     "reviewed_by": "王小明", "reviewed_at": "2026-11-01"}])
    r, st, detail, out = run_cand(tmp_path, tbl, m)
    assert st == "ATTENTION" and "5797" in detail and "5900" in detail
    p = {x["id"]: x["reasons"] for x in out["pending"]}
    assert p == {"5797": ["revised", "unreviewed_rows"], "5900": ["not_in_table", "after_reviewed_until"]}   # 5560 已判定不適用
    assert "5900" in r.stderr


@pytest.mark.parametrize("how", ["missing", "stale"])
def test_candidates_mirror_missing_or_stale_is_gap(tmp_path, how):
    m = tmp_path / "none" if how == "missing" else make_mirror(tmp_path / "m", fetched=NOW - datetime.timedelta(days=8))
    r, st, detail, out = run_cand(tmp_path, table([]), m)
    assert r.returncode == 0 and st == "GAP"
    # 上限可調
    if how == "stale":
        r2, _, st2, _ = run("candidates", "--mirror", m, "--table", tmp_path / "table.json", env={"NVBUL_MAX_AGE_DAYS": "10"})
        assert st2 == "ATTENTION"


def test_candidates_draft_quotes_markdown_rows(tmp_path):
    r, st, detail, out = run_cand(tmp_path, table([], reviewed_until=None) | {"bulletins": []}, make_mirror(tmp_path / "m"), draft=True)
    d = json.loads((tmp_path / "draft.json").read_text(encoding="utf-8"))
    rows = {(x["cve"], x["line"]): x for x in d["rows"]}
    assert set(rows) == {("CVE-2026-24148", "35"), ("CVE-2026-24148", "36"), ("CVE-2026-24154", "38")}
    x = rows[("CVE-2026-24154", "38")]
    assert x["source"]["row"] == "| CVE-2026-24154 | Jetson Xavier Series, Jetson Orin Series and Jetson Thor | Jetson Linux(38) | 38.2 | 38.4 |"
    assert (x["affected_max"], x["fixed_in"], x["component"], x["where_it_lives"]) == ("38.2", "38.4", "initrd", "nvidia-l4t-initrd")
    assert all(not y["reviewed"] for y in d["rows"])
    assert d["bulletins"][0]["cves"]["CVE-2026-24148"]["cvss_v3_score"] == 8.3
    nb.validate_table({**d, "reviewed_until": None})     # 草稿可以直接併入對照表



BAD_VULNS = {
    "cwe_is_string": [{"cve": "CVE-2026-24148", "cwe": "CWE-1188"}],
    "score_not_object": [{"cve": "CVE-2026-24148", "scores": [1]}],
    "cvss_not_object": [{"cve": "CVE-2026-24148", "scores": [{"cvss_v3": "8.3"}]}],
    "base_score_string": [{"cve": "CVE-2026-24148", "scores": [{"cvss_v3": {"baseScore": "8.3"}}]}],
    "note_text_not_string": [{"cve": "CVE-2026-24148", "notes": [{"category": "summary", "text": 5}]}],
    "notes_not_list": [{"cve": "CVE-2026-24148", "notes": "summary"}],
    "reference_url_not_string": [{"cve": "CVE-2026-24148", "references": [{"url": 1}]}],
    "vulnerability_not_object": ["CVE-2026-24148"],
    "vulnerabilities_not_list": {"cve": "CVE-2026-24148"},
}


@pytest.mark.parametrize("kind", BAD_VULNS)
def test_csaf_structure_error_only_empties_that_bulletin(tmp_path, kind):
    """CSAF 欄位型別錯：只有那一則 cves={} 並記 csaf_note，其他公告與草稿列照常，candidates 不 FAIL。"""
    with pytest.raises(nb.CsafError):
        nb.csaf_cves({"vulnerabilities": BAD_VULNS[kind]})
    m = make_mirror(tmp_path / "m", bulletins=(("5797", "2026", "2026-03-31T00:00:00Z", "Security Bulletin: NVIDIA Jetson and IGX Devices - March 2026"),
                                               ("5798", "2026", "2026-04-30T00:00:00Z", "Security Bulletin: NVIDIA Jetson Devices - April 2026")))
    f = m / "2026/5798/5798.json"
    doc = json.loads(f.read_text(encoding="utf-8"))
    doc["vulnerabilities"] = BAD_VULNS[kind]
    f.write_text(json.dumps(doc), encoding="utf-8")
    r, st, detail, out = run_cand(tmp_path, table([], reviewed_until=None) | {"bulletins": []}, m, draft=True)
    assert r.returncode == 0 and st == "ATTENTION" and "5797" in detail and "5798" in detail
    d = json.loads((tmp_path / "draft.json").read_text(encoding="utf-8"))
    by = {b["id"]: b for b in d["bulletins"]}
    assert by["5798"]["cves"] == {} and by["5798"]["csaf_note"].startswith("CSAF 結構錯") and "5798" in r.stderr
    assert by["5797"]["cves"]["CVE-2026-24148"]["cvss_v3_score"] == 8.3 and "csaf_note" not in by["5797"]
    assert {x["bulletin"] for x in d["rows"]} == {"5797", "5798"}       # 草稿列照常從 Markdown 產生
    nb.validate_table({**d, "reviewed_until": None})


def test_csaf_cves_accepts_missing_optional_fields():
    assert nb.csaf_cves({}) == {} and nb.csaf_cves({"vulnerabilities": None}) == {}
    got = nb.csaf_cves({"vulnerabilities": [{"title": "沒有 CVE 編號"}, {"cve": "CVE-2026-0001", "cwe": None, "scores": [{"cvss_v2": {}}],
                                                                       "notes": [{"category": "details", "text": 1}]}]})
    assert got == {"CVE-2026-0001": {"severity": None, "cvss_v3_score": None, "cvss_v3_vector": None, "cwe": None,
                                  "description": None, "references": []}}


# ---------- 預填的對照表 ----------

def test_shipped_table_is_valid_and_unreviewed():
    t = nb.validate_table(json.loads(TABLE.read_text(encoding="utf-8")))
    assert t["reviewed_until"] is None
    assert sorted(b["id"] for b in t["bulletins"]) == ["5321", "5343", "5417", "5442", "5466", "5555", "5611", "5617", "5662", "5716", "5797"]
    assert t["rows"] and all(r["reviewed"] is False and r["reviewed_by"] is None for r in t["rows"])
    # 只是把 Jetson 列為平台的其他產品：預填在 not_applicable，同樣未審核
    assert [(x["bulletin"], x["reviewed"]) for x in t["not_applicable"]] == [("5560", False), ("5596", False), ("5661", False), ("5910", False)]
    for r in t["rows"]:
        assert r["source"]["row"].startswith(f"| {r['cve']} |") and r["affected_text"] in r["source"]["row"]
        assert r["where_it_lives"] in ("flash", "unknown") or r["where_it_lives"].startswith("nvidia-l4t-")
        assert "尚未人工審核" in r["note"]
    # 沒有任何公告列出 39，而且都早於 R39.2.1 的建置日（2026-08-06）：全部「推定已含修正」（不是「不受影響」）
    sbom = json.loads(lzma.open(FIXTURE).read())
    st, detail, out = nb.match(sbom, t, None, "nvidia-bulletins.json")
    assert st == "GAP" and out["findings"] == [] and out["needs_vendor_confirmation"] == []
    assert {(x["bulletin"], x["cve"]) for x in out["presumed_included"]} == {(b["id"], c) for b in t["bulletins"] for c in b["cves"]}


# ---------- 鏡像腳本（file:// 的假 tarball，不連網） ----------

def fake_repo_tar(path, tamper=False, extra=False, odd=False):
    files = {}
    if odd:                                             # 格式錯的 CSAF：標題不是字串、產品樹很深（不能讓整個鏡像失敗）
        files["2026/5907/5907.json"] = json.dumps({"document": {"title": 123, "tracking": {"id": "5907", "version": []}}}).encode()
        # 產品樹 300 層（字串拼，不用 json.dumps：3.10／3.11 的 json 在 600 層左右就 RecursionError；300 層各版本都讀得到）
        deep = '{"branches": [' * 300 + '{"name": "GeForce RTX 4090"}' + "]}" * 300
        files["2026/5908/5908.json"] = ('{"document": {"title": "NVIDIA Software", "tracking": {"id": "5908"}}, "product_tree": '
                                        + deep + "}").encode()
        files["2026/5909/5909.json"] = b'{"document": ' * 100000 + b"{}" + b"}" * 100000      # 各版本都 RecursionError、沒被選入
        files["2026/5910/5910.json"] = b'{"document": ' * 100000 + b"{}" + b"}" * 100000      # 同樣很深，但 CVE_index 把它選入
    md = MD_5797.encode()
    csaf = json.dumps({"document": {"title": "Security Bulletin: NVIDIA Jetson and IGX Devices - March 2026",
                                    "tracking": {"id": "5797", "current_release_date": "2026-03-31T00:00:00Z", "version": "1.0.0"}},
                       "product_tree": {"branches": [{"name": "Jetson Linux(36)"}]}, "vulnerabilities": []}).encode()
    files["2026/5797/5797.json"] = csaf
    files["2026/5797/5797.json.sha256"] = hashlib.sha256(b"x" if tamper else csaf).hexdigest().encode() + b"  5797.json\n"
    files["2026/5797/5797.md"] = md
    files["2026/5797/README.md"] = b"# Table of Contents"
    files["2026/5861/5861.json"] = json.dumps({"document": {"title": "NVIDIA GPU Display Driver", "tracking": {"id": "5861"}}}).encode()
    files["2026/CVE_index.csv"] = b"CVE;Bulletin;Affected Product\nCVE-2026-1;5861;GeForce\n" + (b"CVE-2026-2;5910;GeForce\n" if odd else b"")
    if extra:                                           # 選取群組：vBIOS、驅動（產品樹才有型號）、不能被選到的 DGX／BlueField 韌體
        for bid, title, prods in (("5901", "Security Bulletin: NVIDIA HGX and DGX VBIOS - May 2026", ["HGX H100 VBIOS"]),
                                  ("5902", "Security Bulletin: NVIDIA GPU firmware - June 2026", []),
                                  ("5903", "Security Bulletin: NVIDIA Software - July 2026", ["NVIDIA RTX Enterprise driver", "Quadro"]),
                                  ("5904", "Security Bulletin: NVIDIA DGX H100 BMC firmware - May 2026", ["DGX H100 BMC"]),
                                  ("5905", "Security Bulletin: NVIDIA BlueField firmware - May 2026", ["BlueField-3 firmware"])):
            files[f"2026/{bid}/{bid}.json"] = json.dumps({"document": {"title": title, "tracking": {"id": bid}},
                                                         "product_tree": {"branches": [{"name": x} for x in prods]}}).encode()
        # NVIDIA 改了檔案沒更新 .sha256（實際遇到 2024/5586）：只屬於 gpu 群組 → 不解出、記 integrity_error，鏡像照做
        files["2026/5906/5906.json"] = json.dumps({"document": {"title": "NVIDIA GPU firmware - August 2026", "tracking": {"id": "5906"}}}).encode()
        files["2026/5906/5906.json.sha256"] = b"0" * 64
    files["2026/5797/../../evil.json"] = b"{}"          # 路徑跳脫：不可解出
    with tarfile.open(path, "w:gz") as t:
        for name, data in files.items():
            ti = tarfile.TarInfo(f"product-security-{'b' * 40}/{name}")
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))


def run_sh(*args, env=None):
    return subprocess.run(["bash", str(MIRROR_SH), *map(str, args)], capture_output=True, text=True,
                          env={**os.environ, "NVBUL_COMMIT": "b" * 40, "NVBUL_COMMIT_DATE": "2026-10-27T12:23:43Z",
                               "NVBUL_MIN_BULLETINS": "1", **(env or {})})


def test_mirror_script_offline(tmp_path):
    tar = tmp_path / "repo.tar.gz"
    fake_repo_tar(tar)
    dest, man = tmp_path / "mirror", tmp_path / "manifest.txt"
    r = run_sh(dest, man, env={"NVBUL_ARCHIVE_URL": tar.as_uri()})
    assert r.returncode == 0, r.stdout + r.stderr
    assert "selected=2 (5797, 5861) jetson=1 gpu-firmware=0 gpu-driver=1" in r.stdout and "sha256_ok=1" in r.stdout
    assert (dest / "2026/5797/5797.md").is_file() and (dest / "2026/5861").is_dir() and not (tmp_path / "evil.json").exists()
    idx = json.loads((dest / "index.json").read_text(encoding="utf-8"))
    assert {b["id"]: b["groups"] for b in idx["bulletins"]} == {"5797": ["jetson"], "5861": ["gpu-driver"]}
    assert idx["bulletins"][1]["match_by_group"] == {"gpu-driver": ["title", "cve_index_product"]}
    m = man.read_text(encoding="utf-8")
    assert f"# commit: {'b' * 40}" in m and "./2026/5797/5797.json" in m and "# archive_sha256: " in m
    assert "# bulletin 2026/5797 groups=jetson\n" in m and "# bulletin 2026/5861 groups=gpu-driver\n" in m
    assert run_sh("--check", dest).returncode == 0
    # 鏡像能直接給 candidates 用
    r2, _, st, _ = run("candidates", "--mirror", dest, "--table", TABLE)
    assert st == "ATTENTION"
    # 拒絕覆蓋
    assert run_sh(dest, tmp_path / "m2.txt", env={"NVBUL_ARCHIVE_URL": tar.as_uri()}).returncode == 3
    # 過期
    src = (dest / "SOURCE").read_text(encoding="utf-8")
    (dest / "SOURCE").write_text(src.replace("fetched_utc=", "fetched_utc=2020-01-01T00:00:00Z\nold="), encoding="utf-8")
    c = run_sh("--check", dest)
    assert c.returncode == 1 and "過期" in c.stdout


def test_mirror_script_rejects_bad_sha256(tmp_path):
    tar = tmp_path / "repo.tar.gz"
    fake_repo_tar(tar, tamper=True)
    r = run_sh(tmp_path / "mirror", tmp_path / "manifest.txt", env={"NVBUL_ARCHIVE_URL": tar.as_uri()})
    assert r.returncode != 0 and "sha256 不符" in r.stdout + r.stderr
    assert not (tmp_path / "manifest.txt").exists()


# ---------- 第二階段：版本線沒有列出時的日期規則、未審核列只看同版本線 ----------

def dated_table(rows, initial="2026-03-31T00:00:00Z", **kw):
    t = table(rows, **kw)
    t["bulletins"][0]["initial_release_date"] = initial
    return t


@pytest.mark.parametrize("initial,want", [("2026-03-31T00:00:00Z", "presumed_included"),   # 建置 2026-08-06，晚於公告
                                          ("2026-08-06T00:00:00Z", "needs_confirmation"),  # 同一天
                                          ("2026-09-01T00:00:00Z", "needs_confirmation"),  # 建置早於公告
                                          (None, "needs_confirmation")])                   # 日期不明
def test_unnamed_line_date_rule(initial, want):
    assert nb.unnamed_line_policy(initial, "2026-08-06") == want
    assert nb.unnamed_line_policy("2026-03-31", None) == "needs_confirmation"


def test_r39_built_after_bulletins_is_ok_with_presumed_list(tmp_path):
    # 35／36／38 的列都未審核：只有掃描到的版本線（39）的未審核列才算 ATTENTION
    rows = [row("CVE-2026-24148", "35", fixed="35.6.4", below="35.6.4", reviewed=False),
            row("CVE-2026-24148", "36", fixed="36.5", below="36.5", reviewed=False),
            row("CVE-2026-24154", "38", fixed="38.4", mx="38.2", reviewed=False, where="flash")]
    r, st, detail, out = run_match(tmp_path, json.loads(lzma.open(FIXTURE).read()), dated_table(rows, reviewed_until=None))
    assert r.returncode == 0 and st == "OK", detail
    assert out["jetson_linux"]["build_date"] == "2026-08-06"
    assert {x["cve"] for x in out["presumed_included"]} == {"CVE-2026-24148", "CVE-2026-24154"} and out["needs_vendor_confirmation"] == []
    p = next(x for x in out["presumed_included"] if x["cve"] == "CVE-2026-24154")
    assert p["where_it_lives"] == ["flash"] and "推定已含修正，NVIDIA 未確認" in p["detail"] and "不是「不受影響」" in p["detail"]
    assert "推定已含修正 2（" in detail and out["table"]["same_line_unreviewed_rows"] == 0 and out["table"]["unreviewed_rows"] == 3
    assert out["policy"]["unnamed_line"] == "presume_included_if_built_after"


def test_r39_built_before_bulletin_needs_confirmation(tmp_path):
    rows = [row("CVE-2026-24148", "36", fixed="36.5", below="36.5", reviewed=False)]
    r, st, detail, out = run_match(tmp_path, json.loads(lzma.open(FIXTURE).read()), dated_table(rows, initial="2026-08-06T00:00:00Z"))
    assert st == "ATTENTION" and out["presumed_included"] == [] and out["needs_vendor_confirmation"][0]["reason"] == "line_not_named"


def test_policy_can_be_flipped_to_always_confirm(monkeypatch):
    monkeypatch.setattr(nb, "PRESUME_INCLUDED_IF_BUILT_AFTER", False)
    st, detail, out = nb.match(json.loads(lzma.open(FIXTURE).read()), dated_table([row("CVE-2026-24148", "36", fixed="36.5")]), None)
    assert out["presumed_included"] == [] and len(out["needs_vendor_confirmation"]) == 1
    assert out["policy"]["unnamed_line"] == "always_needs_confirmation"


def test_same_line_unreviewed_rows_are_attention(tmp_path):
    rows = [row("CVE-2026-24148", "39", fixed="39.3", reviewed=False)]
    r, st, detail, out = run_match(tmp_path, json.loads(lzma.open(FIXTURE).read()), dated_table(rows))
    assert st == "ATTENTION" and "39 版本線有 1 列未審核" in detail and out["findings"] == []
    assert out["unreviewed_would_match"][0]["cve"] == "CVE-2026-24148"


def test_unreviewed_rows_and_reviewed_until_are_not_staleness(tmp_path):
    # 表上都有、只是未審核或晚於 reviewed_until：不是 GAP（對照表沒有落後鏡像）
    rows = [row("CVE-2026-24148", "36", fixed="36.5", reviewed=False)]
    r, st, detail, out = run_match(tmp_path, l4t_sbom("36.5"), dated_table(rows, reviewed_until=None))
    assert st == "ATTENTION" and out["pending_bulletins"][0]["reasons"] == ["unreviewed_rows", "after_reviewed_until"]


def test_candidates_lists_unreviewed_not_applicable(tmp_path):
    m = make_mirror(tmp_path / "m", bulletins=(("5797", "2026", "2026-03-31T00:00:00Z", "Jetson"),
                                               ("5560", "2024", "2024-08-07T00:00:00Z", "Security Bulletin: NVIDIA CV-CUDA - August 2024")))
    tbl = table([row("CVE-2026-24154", "36", fixed="36.5")],
                na=[{"bulletin": "5560", "current_release_date": "2024-08-07T00:00:00Z", "reason": "預填", "reviewed": False}])
    r, st, detail, out = run_cand(tmp_path, tbl, m)
    assert st == "ATTENTION" and [(x["id"], x["reasons"]) for x in out["pending"]] == [("5560", ["unreviewed_not_applicable"])]
    tbl["not_applicable"][0].update(reviewed=True)          # 已審核卻沒寫是誰：輸入錯誤
    r, st, detail, out = run_cand(tmp_path, tbl, m)
    assert r.returncode == 3 and "not_applicable[0]" in detail


# ---------- sca-scan 與部署的接線 ----------

def test_sca_scan_wiring():
    s = (PILOT / "sca-scan").read_text(encoding="utf-8")
    i = s.index('nvidia_bulletins.py" match --sbom "$SBOM"')
    assert s.index('kernelcheck.py" --sbom "$SBOM"') < i < s.index("# 規則 11：依生態系判斷鎖定檔")       # 緊接在 C-kernel-coverage 之後
    block = s[s.rindex("\nif ", 0, i):i]
    assert 'if [[ "$MODE" =~ ^(image|sbom)$ ]] && [ $SBOM_OK = 1 ]' in block                       # 原始碼模式不寫這一列
    assert s.rindex('rm -f "$NVB"', 0, i) > s.index('kernelcheck.py" --sbom "$SBOM"')              # 先刪掉上一次的結果
    assert 'NVB=$OUT/scan/nvidia-bulletins.json' in s and '--out "$NVB"' in s
    assert 'NOT_RUN) rm -f "$NVB";;' in s and "C-nvidia-bulletins NOT_RUN" not in s                  # 不是 Jetson：沒有這一列
    assert 'na=(--mirror "$NVIDIA_BULLETINS_MIRROR")' in s and 'status C-nvidia-bulletins FAIL "nvidia_bulletins.py 失敗' in s
    # PILOT_ENV 只讀列出的鍵，NVIDIA_BULLETINS_MIRROR 是其中之一（不是秘密，不加進 secret）
    case = next(l for l in s.splitlines() if l.strip().startswith("case $k in DT_URL|"))
    assert "|NVIDIA_BULLETINS_MIRROR|" in case and 'secret "$NVIDIA_BULLETINS_MIRROR"' not in s


def test_report_html_mentions_nvidia_findings_only_when_present(tmp_path):
    from pilot_fixtures import ALL_OK, make_out, run_report
    table_ = dated_table([row("CVE-2026-24154", "36", fixed="36.5")])
    st, detail, nvb = nb.match(l4t_sbom("36.4.3"), table_, None, "t.json")
    out = make_out(tmp_path / "o", ALL_OK + [("C-nvidia-bulletins", st, detail)], grype=[])
    (out / "scan" / "nvidia-bulletins.json").write_text(json.dumps(nvb, ensure_ascii=False), encoding="utf-8")
    rep, page = run_report(out)
    assert rep["nvidia_bulletins"]["findings"] == ["CVE-2026-24154"] and "NVIDIA 安全公告（Jetson Linux 36.4.3）另有 1 筆發現" in page
    # 沒有發現（R39：全部推定已含修正）：只有階段表的那一列
    st, detail, nvb = nb.match(json.loads(lzma.open(FIXTURE).read()), dated_table([row("CVE-2026-24154", "36", fixed="36.5")]), None)
    out2 = make_out(tmp_path / "o2", ALL_OK + [("C-nvidia-bulletins", st, detail)], grype=[])
    (out2 / "scan" / "nvidia-bulletins.json").write_text(json.dumps(nvb, ensure_ascii=False), encoding="utf-8")
    rep, page = run_report(out2)
    assert "另有" not in page and "C-nvidia-bulletins" in page


# ---------- 複審：nvbul-sync.sh 以 root 執行，來源是別的帳號可寫的資料夾 ----------

def test_mirror_state_refuses_fifo_source(tmp_path):
    m = make_mirror(tmp_path / "m")
    (m / "SOURCE").unlink()
    os.mkfifo(m / "SOURCE")
    st = nb.mirror_state(str(m))        # 不會卡住
    assert not st["ok"] and "不是一般檔案" in st["reason"]


def test_date_rule_uses_later_of_initial_and_revised():
    assert nb.bulletin_date({"initial_release_date": "2025-02-25T00:00:00Z", "current_release_date": "2025-03-14T00:00:00Z"}) == "2025-03-14"
    assert nb.bulletin_date({"initial_release_date": "2025-02-25T00:00:00Z"}) == "2025-02-25" and nb.bulletin_date({}) is None
    t = dated_table([row("CVE-2026-24148", "36", fixed="36.5")], initial="2026-03-31T00:00:00Z")
    t["bulletins"][0]["current_release_date"] = "2026-09-01T00:00:00Z"        # 建置（2026-08-06）之後才修訂
    st, detail, out = nb.match(json.loads(lzma.open(FIXTURE).read()), t, None)
    assert out["presumed_included"] == [] and out["needs_vendor_confirmation"][0]["bulletin_date"] == "2026-09-01"


def test_igx_only_cve_is_never_presumed_for_jetson():
    t = dated_table([row("CVE-2026-24148", "IGX", fixed="1.1.2"), row("CVE-2026-24154", "36", fixed="36.5")])
    st, detail, out = nb.match(json.loads(lzma.open(FIXTURE).read()), t, None)
    assert [x["cve"] for x in out["presumed_included"]] == ["CVE-2026-24154"]
    nc = out["needs_vendor_confirmation"]
    assert [x["cve"] for x in nc] == ["CVE-2026-24148"] and "沒有任何 Jetson Linux 版本線" in nc[0]["detail"]
    assert nb.unnamed_line_policy("2020-01-01", "2026-08-06", {"IGX"}) == "needs_confirmation"


def test_jetpack7_line_left_for_human():
    line, why = nb.infer_line("Jetson Linux(JP7)", "Jetson Thor", ("All versions prior to 38.4",))
    assert line is None and "38 或 39" in why
    assert nb.infer_line("Jetson Linux(JP6)", "", ()) == ("36", "platform_jetpack")


def test_unreviewed_lines_caveat_in_detail(tmp_path):
    rows = [row("CVE-2026-24148", "36", fixed="36.5", reviewed=False)]
    st, detail, out = nb.match(json.loads(lzma.open(FIXTURE).read()), dated_table(rows, reviewed_until=None), None)
    assert out["lines_from_unreviewed_rows"] == 1 and out["presumed_included"][0]["lines_from_unreviewed_rows"] is True
    assert "注意：1 筆的「公告列了哪些版本線」取自未經人工審核的對照表列（reviewed_until：未設定）" in detail
    rows = [row("CVE-2026-24148", "36", fixed="36.5")]
    st, detail, out = nb.match(json.loads(lzma.open(FIXTURE).read()), dated_table(rows), None)
    assert out["lines_from_unreviewed_rows"] == 0 and "未經人工審核" not in detail


def test_mirror_script_size_cap(tmp_path):
    tar = tmp_path / "repo.tar.gz"
    fake_repo_tar(tar)
    r = run_sh(tmp_path / "m", tmp_path / "man.txt", env={"NVBUL_ARCHIVE_URL": tar.as_uri(), "NVBUL_MAX_UNPACKED_MB": "0"})
    assert r.returncode != 0 and "NVBUL_MAX_UNPACKED_MB" in r.stdout + r.stderr
    s = MIRROR_SH.read_text(encoding="utf-8")
    assert "timeout 120 git ls-remote" in s and "--connect-timeout 30 --max-time 300" in s and "--max-filesize" in s


# ---------- 複審 2：root 解到 0700 的容器裡，串流的「./」成員改不到外面看得到的權限 ----------

def crafted_stream(path, extra):
    import tarfile as tf
    with tf.open(path, "w", format=tf.GNU_FORMAT) as t:
        dot = tf.TarInfo("./")
        dot.type, dot.mode = tf.DIRTYPE, 0o777
        t.addfile(dot)
        for name, typ in extra:
            ti = tf.TarInfo(name)
            ti.type, ti.mode = typ, 0o666
            if typ == tf.CHRTYPE:
                ti.devmajor, ti.devminor = 1, 3
            t.addfile(ti)


# ---------- 公告鏡像的選取群組（jetson、gpu-firmware、gpu-driver） ----------

def test_groups_are_the_same_in_mirror_script_and_lib():
    import re
    sh = MIRROR_SH.read_text(encoding="utf-8")
    got = dict(re.findall(r'^\s+"([a-z-]+)": re\.compile\(r"(.+?)", re\.I\),$', sh, re.M))
    assert got == {g: rx.pattern for g, rx in nb.GROUPS.items()} and nb.JETSON_RE is nb.GROUPS["jetson"]


def test_mirror_script_groups_select_vbios_and_driver_not_dgx_or_bluefield(tmp_path):
    tar = tmp_path / "repo.tar.gz"
    fake_repo_tar(tar, extra=True)
    dest, man = tmp_path / "mirror", tmp_path / "manifest.txt"
    r = run_sh(dest, man, env={"NVBUL_ARCHIVE_URL": tar.as_uri()})
    assert r.returncode == 0, r.stdout + r.stderr
    idx = json.loads((dest / "index.json").read_text(encoding="utf-8"))
    assert {b["id"]: b["groups"] for b in idx["bulletins"]} == {
        "5797": ["jetson"], "5861": ["gpu-driver"], "5901": ["gpu-firmware"], "5902": ["gpu-firmware"], "5903": ["gpu-driver"],
        "5904": [], "5905": [], "5906": ["gpu-firmware"]}
    assert [b["id"] for b in idx["bulletins"] if b.get("integrity_error")] == ["5906"] and not (dest / "2026/5906").exists()
    assert "integrity_error=1" in r.stdout and "# bulletin 2026/5906 groups=gpu-firmware integrity_error" in man.read_text(encoding="utf-8")
    assert {b["id"]: b["match_by_group"] for b in idx["bulletins"] if b["id"] == "5903"} == {"5903": {"gpu-driver": ["csaf_product"]}}
    assert not (dest / "2026/5904").exists() and not (dest / "2026/5905").exists()
    c = run_sh("--check", dest)
    assert c.returncode == 0 and "jetson_igx=1 gpu_firmware=3 gpu_driver=2" in c.stdout and "integrity_error=1 (5906)" in c.stdout, c.stdout
    # Jetson 的結果不變：candidates／match 預設只看 jetson 群組
    assert [b["id"] for b in nb.mirror_state(str(dest))["bulletins"]] == ["5797"]
    assert [b["id"] for b in nb.mirror_state(str(dest), group="gpu-firmware")["bulletins"]] == ["5901", "5902", "5906"]
    tbl = tmp_path / "gpu-table.json"
    tbl.write_text(json.dumps({"schema": nb.TABLE_SCHEMA, "reviewed_until": None, "bulletins": [], "rows": [], "not_applicable": []}),
                   encoding="utf-8")
    out = tmp_path / "cand.json"
    _, stage, st, detail = run("candidates", "--mirror", dest, "--table", tbl, "--group", "gpu-firmware", "--out", out,
                               "--draft", tmp_path / "draft.json")
    assert stage == "C-nvidia-bulletins-db" and st == "ATTENTION" and "3 個 GPU 韌體（vBIOS） 公告待人工審核（5901, 5902, 5906）" in detail
    assert nb.VBIOS_NOT_ASSESSED in detail
    pend = {p["id"]: p for p in json.loads(out.read_text(encoding="utf-8"))["pending"]}
    assert "sha256_mismatch" in pend["5906"]["reasons"] and "sha256_mismatch" not in pend["5901"]["reasons"]


def test_old_mirror_has_only_jetson_group(tmp_path):
    """舊格式的鏡像（沒有 groups、selection 是字串）：jetson 照舊；問 gpu-firmware → GAP，不能當成「沒有公告」。"""
    d = make_mirror(tmp_path / "m")
    assert nb.mirror_state(str(d))["ok"] and [b["id"] for b in nb.mirror_state(str(d))["bulletins"]] == ["5797"]
    st = nb.mirror_state(str(d), group="gpu-firmware")
    assert not st["ok"] and "沒有選取 gpu-firmware 群組" in st["reason"]
    tbl = tmp_path / "t.json"
    tbl.write_text(json.dumps({"schema": nb.TABLE_SCHEMA, "reviewed_until": None, "bulletins": [], "rows": [], "not_applicable": []}),
                   encoding="utf-8")
    _, _, st, detail = run("candidates", "--mirror", d, "--table", tbl, "--group", "gpu-firmware")
    assert st == "GAP" and "GPU 韌體（vBIOS）" in detail


def test_gpu_only_bulletin_does_not_change_jetson_match(tmp_path):
    """鏡像多了只屬於 gpu-driver 的公告：Jetson 的 match 結果不變（不會變成對照表落後）。"""
    sbom = json.loads(lzma.open(FIXTURE).read())
    base = make_mirror(tmp_path / "a")
    st_a, det_a, _ = nb.match(sbom, table([row("CVE-2026-24154", "36", fixed="36.5")]), nb.mirror_state(str(base)), "t")
    more = make_mirror(tmp_path / "b")
    idx = json.loads((more / "index.json").read_text(encoding="utf-8"))
    for b in idx["bulletins"]:
        b["groups"] = ["jetson"] if b["selected"] else []
    idx["bulletins"].append({"id": "5990", "year": "2026", "title": "NVIDIA GPU Display Driver - October 2026", "selected": True,
                             "groups": ["gpu-driver"], "current_release_date": "2026-10-30T00:00:00Z", "match": ["title"]})
    idx["selection"] = {g: rx.pattern for g, rx in nb.GROUPS.items()}
    (more / "index.json").write_text(json.dumps(idx), encoding="utf-8")
    st_b, det_b, _ = nb.match(sbom, table([row("CVE-2026-24154", "36", fixed="36.5")]), nb.mirror_state(str(more)), "t")
    assert (st_a, det_a) == (st_b, det_b) and "5990" not in det_b


def test_mirror_script_odd_csaf_and_check_groups_consistency(tmp_path):
    tar = tmp_path / "repo.tar.gz"
    fake_repo_tar(tar, odd=True)
    dest, man = tmp_path / "mirror", tmp_path / "manifest.txt"
    r = run_sh(dest, man, env={"NVBUL_ARCHIVE_URL": tar.as_uri()})
    assert r.returncode == 0 and "Traceback" not in r.stderr, r.stdout + r.stderr
    idx = json.loads((dest / "index.json").read_text(encoding="utf-8"))
    by = {b["id"]: b for b in idx["bulletins"]}
    assert by["5907"]["title"] is None and by["5907"]["revision"] is None and by["5907"]["groups"] == []
    assert by["5908"]["groups"] == ["gpu-driver"] and by["5908"]["match_by_group"]["gpu-driver"] == ["csaf_product"]
    assert by["5909"]["csaf"] is False and by["5909"]["groups"] == []
    assert by["5910"]["csaf"] is False and by["5910"]["groups"] == ["gpu-driver"] and (dest / "2026/5910/5910.json").is_file()
    c = run_sh("--check", dest)                        # 被選入的深 CSAF：--check 不能 traceback、不能讓整份鏡像失敗
    assert c.returncode == 0 and "Traceback" not in c.stderr, c.stdout + c.stderr
    tbl = tmp_path / "t.json"
    tbl.write_text(json.dumps({"schema": nb.TABLE_SCHEMA, "reviewed_until": None, "bulletins": [], "rows": [], "not_applicable": []}),
                   encoding="utf-8")
    _, _, st, _ = run("candidates", "--mirror", dest, "--table", tbl, "--group", "gpu-driver", "--draft", tmp_path / "d.json")
    assert st == "ATTENTION" and "5910" in [b["id"] for b in json.loads((tmp_path / "d.json").read_text(encoding="utf-8"))["bulletins"]]
    by["5908"]["selected"] = False                      # groups 和 selected 不一致
    (dest / "index.json").write_text(json.dumps(idx), encoding="utf-8")
    c = run_sh("--check", dest)
    assert c.returncode == 1 and "不一致" in c.stdout
    by["5908"].update(selected=True, groups=["gpu-driver", "dgx"])
    (dest / "index.json").write_text(json.dumps(idx), encoding="utf-8")
    assert "不認得的群組" in run_sh("--check", dest).stdout
    by["5908"].update(groups=[["gpu-driver"]])            # 群組不是字串：清楚失敗，不 TypeError
    (dest / "index.json").write_text(json.dumps(idx), encoding="utf-8")
    c = run_sh("--check", dest)
    assert c.returncode == 1 and "不認得的群組" in c.stdout and "Traceback" not in c.stderr
    by["5908"].update(groups=["gpu-driver"])            # 認得的群組取自 index.json 的 selection
    idx["selection"] = {"jetson": "x"}
    (dest / "index.json").write_text(json.dumps(idx), encoding="utf-8")
    assert "不認得的群組" in run_sh("--check", dest).stdout


def test_check_counts_deep_non_jetson_csaf_instead_of_failing(tmp_path):
    """鏡像主機（3.12）讀得到、--check 的主機（3.10）讀不到的深 CSAF：非 Jetson 只計數；Jetson 照舊 FAIL。"""
    tar = tmp_path / "repo.tar.gz"
    fake_repo_tar(tar, odd=True)
    dest, man = tmp_path / "mirror", tmp_path / "manifest.txt"
    assert run_sh(dest, man, env={"NVBUL_ARCHIVE_URL": tar.as_uri()}).returncode == 0
    c = run_sh("--check", dest)
    assert c.returncode == 0 and "csaf_too_deep=0" in c.stdout, c.stdout
    idx = json.loads((dest / "index.json").read_text(encoding="utf-8"))
    by = {b["id"]: b for b in idx["bulletins"]}
    by["5910"]["csaf"] = True                          # 模擬鏡像主機讀得到（各版本 Python 在這裡都讀不到）
    (dest / "index.json").write_text(json.dumps(idx), encoding="utf-8")
    c = run_sh("--check", dest)
    assert c.returncode == 0 and c.stdout.startswith("OK ") and "csaf_too_deep=1 (5910)" in c.stdout, c.stdout + c.stderr
    deep = b'{"document": ' * 100000 + b"{}" + b"}" * 100000
    (dest / "2026/5797/5797.json").write_bytes(deep)    # Jetson 的 CSAF 讀不到：照舊是問題
    (dest / "2026/5797/5797.json.sha256").write_text(hashlib.sha256(deep).hexdigest() + "  5797.json\n", encoding="utf-8")
    c = run_sh("--check", dest)
    assert c.returncode == 1 and "5797: CSAF 無法讀取（RecursionError）" in c.stdout and "Traceback" not in c.stderr, c.stdout + c.stderr


# ---------- #147 審查：中 1、中 2、低 ----------

def test_check_counts_other_unreadable_non_jetson_csaf(tmp_path):
    """中 2：非 Jetson 公告（5861，gpu-driver）的 CSAF 其他結構錯也只計數；BOM、UTF-16 讀得懂；Jetson 的照舊 FAIL。"""
    tar = tmp_path / "repo.tar.gz"
    fake_repo_tar(tar)
    dest, man = tmp_path / "mirror", tmp_path / "manifest.txt"
    assert run_sh(dest, man, env={"NVBUL_ARCHIVE_URL": tar.as_uri()}).returncode == 0
    f = dest / "2026/5861/5861.json"
    ok = json.dumps({"document": {"title": "NVIDIA GPU Display Driver", "tracking": {"id": "5861"}}})
    for data in (b"\xef\xbb\xbf" + ok.encode(), ok.encode("utf-16")):              # 鏡像端讀得懂的，--check 也要讀得懂
        f.write_bytes(data)
        c = run_sh("--check", dest)
        assert c.returncode == 0 and "csaf_unreadable=0" in c.stdout, c.stdout + c.stderr
    for data, why in ((b'{"vulnerabilities": []}', "KeyError"), (b'{"document": {"tracking": []}}', "TypeError"),
                      (b'{"document": "x"}', "TypeError"), (b'[1]', "TypeError"), (b"not json", "JSONDecodeError"),
                      (json.dumps({"document": {"tracking": {"id": "9999"}}}).encode(), "tracking.id 不符")):
        f.write_bytes(data)
        c = run_sh("--check", dest)
        assert c.returncode == 0 and c.stdout.startswith("OK ") and f"csaf_unreadable=1 (5861:{why})" in c.stdout, (why, c.stdout + c.stderr)
        assert "Traceback" not in c.stderr
    (dest / "2026/5797/5797.json").write_bytes(b'{"vulnerabilities": []}')          # Jetson：照舊是問題（sha256 也不符）
    c = run_sh("--check", dest)
    assert c.returncode == 1 and "5797: CSAF 無法讀取（KeyError）" in c.stdout, c.stdout


def write_csaf(m, bid, data):
    (m / f"2026/{bid}/{bid}.json").write_bytes(data)


def test_draft_notes_unreadable_csaf_and_markdown(tmp_path):
    """中 1：index 說有 CSAF 卻讀不到、太深、根不是物件 → csaf_note（附例外類別），各版本 Python 一樣；BOM 讀得懂。
    低 1：Markdown 不是合法 UTF-8 → 只有那一則 md_note、沒有草稿列，整組不 FAIL。"""
    bul = (("5797", "2026", "2026-03-31T00:00:00Z", "Security Bulletin: NVIDIA Jetson and IGX Devices - March 2026"),
           ("5798", "2026", "2026-04-30T00:00:00Z", "Security Bulletin: NVIDIA Jetson Devices - April 2026"))
    deep = b'{"vulnerabilities": ' + b"[" * 100000 + b"]" * 100000 + b"}"
    for data, want in ((b"not json", "CSAF 無法讀取（JSONDecodeError）"), (deep, "CSAF 無法讀取（RecursionError）"),
                       (b"[]", "CSAF 結構錯（CSAF 的根是 list）")):
        m = make_mirror(tmp_path / f"m{len(data)}", bulletins=bul)
        write_csaf(m, "5798", data)
        r, st, detail, out = run_cand(tmp_path, table([], reviewed_until=None) | {"bulletins": []}, m, draft=True)
        assert r.returncode == 0 and st == "ATTENTION", r.stdout + r.stderr
        by = {b["id"]: b for b in json.loads((tmp_path / "draft.json").read_text(encoding="utf-8"))["bulletins"]}
        assert by["5798"]["cves"] == {} and by["5798"]["csaf_note"].startswith(want), (want, by["5798"])
        assert "csaf_note" not in by["5797"]
    m = make_mirror(tmp_path / "bom", bulletins=bul)
    f = m / "2026/5798/5798.json"
    f.write_bytes(b"\xef\xbb\xbf" + f.read_bytes())
    (m / "2026/5797/5797.md").write_bytes(b"\xff\xfe not utf-8")
    r, st, detail, out = run_cand(tmp_path, table([], reviewed_until=None) | {"bulletins": []}, m, draft=True)
    assert r.returncode == 0 and st == "ATTENTION", r.stdout + r.stderr
    d = json.loads((tmp_path / "draft.json").read_text(encoding="utf-8"))
    by = {b["id"]: b for b in d["bulletins"]}
    assert by["5798"]["cves"] and "csaf_note" not in by["5798"]
    assert by["5797"]["md_note"].startswith("Markdown 無法讀取（UnicodeDecodeError）") and {x["bulletin"] for x in d["rows"]} == {"5798"}


def test_csaf_cves_rejects_bad_scores_and_skips_bad_cve_ids():
    """低 2–5：baseScore 是 NaN／無限大／超出 0–10 → 結構錯；空的 url 不帶；cve 型別錯或格式不對 → 略過並記 notes；重複的 CVE 合併；根不是物件 → 結構錯。"""
    for score in (float("nan"), float("inf"), 11, -1):
        with pytest.raises(nb.CsafError, match="baseScore"):
            nb.csaf_cves({"vulnerabilities": [{"cve": "CVE-2026-0001", "scores": [{"cvss_v3": {"baseScore": score}}]}]})
    for root in ([], "x", 1):
        with pytest.raises(nb.CsafError, match="根"):
            nb.csaf_cves(root)
    notes = []
    got = nb.csaf_cves({"vulnerabilities": [
        {"cve": 1}, {"cve": {"x": 1}}, {"cve": True}, {"cve": ""}, {"cve": "garbage"}, {"cve": "CVE-1\n"}, {"cve": "CVE-2026-0002\n"},
        {"cve": "CVE-2026-0003", "references": [{"url": ""}, {"url": "https://a"}]},
        {"cve": "CVE-2026-0003", "cwe": {"id": "CWE-79"}, "references": [{"url": "https://a"}, {"url": "https://b"}],
         "scores": [{"cvss_v3": {"baseScore": 6.1}}]}]}, notes)
    assert list(got) == ["CVE-2026-0003"]
    assert got["CVE-2026-0003"]["cwe"] == "CWE-79" and got["CVE-2026-0003"]["cvss_v3_score"] == 6.1
    assert got["CVE-2026-0003"]["references"] == ["https://a", "https://b"]
    assert len(notes) == 8 and notes[-1] == "CVE-2026-0003 出現不只一次，合併" and all("略過" in n for n in notes[:7])
