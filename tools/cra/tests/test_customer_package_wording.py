"""客戶資料包的措辭與白名單輸出（合成資料）：UEFI 重建提示、客戶版 VEX 白名單、sbom.md 完整度數字、vulnerability-status.md 的表與用語、
語言檢查。判定（state、justification、response、affects、status）在客戶版前後必須一樣。"""
import copy
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import firmware_bom as fb  # noqa: E402
import supplier_package as sp  # noqa: E402
from test_cra_report import MIN_CFG, make_project, make_scan, run  # noqa: E402
from test_supplier_package import FULL, pkg, sp_table, texts  # noqa: E402

CJK = re.compile(r"[⺀-鿿豈-﫿＀-￯]")
FORBIDDEN = ("Grype", "Dependency-Track", "sca-center", "bulk rule", "IKCONFIG", "build record")


def prop(name, value):
    return {"name": name, "value": value}


def vuln(vid, state, detail, rule=None, justification=None, response=None, action=None, ref="pkg:deb/ubuntu/x@1"):
    a = {"state": state, "detail": detail}
    if justification:
        a["justification"] = justification
    if response:
        a["response"] = response
    props = [prop("sca-center:vex-source", "rule"), prop("sca-center:component", "x 1"), prop("sca-center:source-ids", "NVD:" + vid),
             prop("sca-center:vex-rule-author", "Staff Name"), prop("sca-center:vex-rule-evidence", "IKCONFIG sha cd2363 /mnt/data/x")]
    if rule:
        props.append(prop("sca-center:vex-rule", rule))
    if state == "exploitable":
        props.append(prop("sca-center:fix-state", "not-fixed"))
        props.append(prop("openvex:action_statement", action or "Track x; it is fixed when the distribution publishes a fix. (bulk rule R6: x)"))
    return {"bom-ref": f"vex-{vid}", "id": vid, "source": {"name": "NVD", "url": "https://nvd.nist.gov/vuln/detail/" + vid}, "analysis": a,
            "affects": [{"ref": ref}], "properties": props}


KERNEL = ("Kernel configuration check (kernel 6.8.12-1021-tegra, configuration kernel/Image (IKCONFIG), SHA-256 cd236345ab49): based on the "
          "flashed kernel's built-in configuration (IKCONFIG sha cd236345ab49); the kernel build record shows that no compiled kernel object has "
          "any program file of the fix (build record: not in the source)")
CDX = {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": "urn:uuid:1", "version": 1,
       "metadata": {"timestamp": "2026-01-01T00:00:00Z", "component": {"type": "firmware", "name": "P", "version": "1"},
                    "tools": {"components": [{"type": "application", "group": "sca-center", "name": "vex_export.py"}]},
                    "properties": [prop("sca-center:release-gate", "GAP")]},
       "vulnerabilities": [
           vuln("CVE-1", "not_affected", KERNEL, "K1", "code_not_present"),
           vuln("CVE-2", "exploitable", "Insufficient data: no fix information is available for fuse; treated as affected. "
                                        "(bulk rule R8: No fix information available: treated as affected, insufficient data)", "R8"),
           vuln("CVE-3", "in_triage", "人工分析顯示沒有編進 UEFI；工具無法確認 (bulk rule R9m: Bundled Mbed TLS (UEFI): built-in not confirmed)", "R9m"),
           vuln("CVE-4", "exploitable", "Fixed in curl 8.5 (installed 8.4). (bulk rule R3: Distribution package: newer fixed package available)",
                "R3", response=["update"], action="Fixed by updating curl to 8.5 or later in the next image. (bulk rule R3: x)"),
           vuln("CVE-5", "resolved", "fixed by Ubuntu 24.04 (noble) in 3.0.13-0ubuntu3.5 (UBUNTU-CVE-2024-1); installed 3.0.13-0ubuntu3.11. "
                                     "Reported only via NVD/GitHub data, which does not know the distribution's backported fix."),
           vuln("CVE-6", "not_affected", "Ubuntu CVE Tracker (commit 1234, 2026-01-01) for source package pkgconf in noble: CVE-6: not-affected",
                "U1", "code_not_present"),
           vuln("CVE-7", "exploitable", "Grype reports a match; Dependency-Track agrees", "R2"),
           vuln("CVE-8", "in_triage", "Version unknown: the SBOM reads 0.0.0, which is a placeholder. NOT_ASSESSED; no version is guessed "
                                      "(draft vulnerability-handling rule 10).")]}
OPENVEX = {"@context": "https://openvex.dev/ns/v0.2.0", "@id": "urn:uuid:2", "author": "Example Co.", "timestamp": "2026-01-01T00:00:00Z",
           "version": 1, "tooling": "sca-center vex_export.py",
           "statements": [
               {"vulnerability": {"name": "CVE-1"}, "products": [{"@id": "pkg:deb/x@1"}], "status": "not_affected",
                "justification": "vulnerable_code_not_present", "impact_statement": KERNEL},
               {"vulnerability": {"name": "CVE-2"}, "products": [{"@id": "pkg:deb/x@1"}], "status": "affected",
                "status_notes": "Insufficient data (bulk rule R8: x)", "action_statement": "Look for fix information at the next scan. (bulk rule R8: x)"},
               {"vulnerability": {"name": "CVE-3"}, "products": [{"@id": "pkg:deb/x@1"}], "status": "under_investigation",
                "status_notes": "人工分析顯示沒有編進 UEFI (bulk rule R9m: x)"},
               {"vulnerability": {"name": "CVE-7"}, "products": [{"@id": "pkg:deb/x@1"}], "status": "affected",
                "status_notes": "Grype match", "action_statement": "See Grype output. (bulk rule R2: x)"}]}


def decisions_cdx(bom):
    return [(v["id"], v["analysis"].get("state"), v["analysis"].get("justification"), v["analysis"].get("response"),
             json.dumps(v["affects"], sort_keys=True)) for v in bom["vulnerabilities"]]


def test_customer_cdx_whitelist_keeps_decisions_and_drops_internal():
    before = copy.deepcopy(CDX)
    out = sp.customer_cdx(CDX)
    assert CDX == before                                   # 內部版的輸入不動
    assert decisions_cdx(out) == decisions_cdx(CDX)        # 每一筆的狀態、justification、response、affects 前後一樣
    text = json.dumps(out, ensure_ascii=False)
    for w in FORBIDDEN + ("vex_export.py", "Staff Name", "/media/"):
        assert w not in text, w
    assert not CJK.search(text) and "sca-center:" not in text
    for v in out["vulnerabilities"]:
        assert set(v) - {"properties"} <= set(sp.CDX_VULN_KEYS)
        assert all(p["name"] == "openvex:action_statement" for p in v.get("properties", []))
    assert set(out["metadata"]) == {"timestamp", "component"}
    by = {v["id"]: v for v in out["vulnerabilities"]}
    assert by["CVE-1"]["analysis"]["detail"] == "The affected code is not built into the shipped kernel (kernel build configuration)."
    assert by["CVE-2"]["analysis"]["detail"].startswith("Insufficient data: no fix information is available for fuse")
    assert "bulk rule" not in by["CVE-2"]["analysis"]["detail"]
    assert by["CVE-3"]["analysis"]["detail"] == "Under assessment."
    assert by["CVE-4"]["properties"][0]["value"] == "Apply curl 8.5 or later when it is included in a release."
    assert "distribution has already fixed" in by["CVE-5"]["analysis"]["detail"] or "already contains the fix" in by["CVE-5"]["analysis"]["detail"]
    assert by["CVE-6"]["analysis"]["detail"] == sp.DISTRO_NOT_AFFECTED
    assert by["CVE-7"]["analysis"]["detail"] == sp.FALLBACK["affected"]          # 工具名稱 → 一般句子
    assert by["CVE-8"]["analysis"]["detail"] == sp.VERSION_UNKNOWN


def test_customer_openvex_whitelist_keeps_status_and_action_statement():
    before = copy.deepcopy(OPENVEX)
    out = sp.customer_openvex(OPENVEX)
    assert OPENVEX == before
    assert [(s["vulnerability"]["name"], s["status"], s.get("justification")) for s in out["statements"]] == \
           [(s["vulnerability"]["name"], s["status"], s.get("justification")) for s in OPENVEX["statements"]]
    assert "tooling" not in out
    text = json.dumps(out, ensure_ascii=False)
    for w in FORBIDDEN:
        assert w not in text, w
    assert not CJK.search(text)
    for s in out["statements"]:
        if s["status"] == "affected":
            assert s["action_statement"]                   # affected 一定有 action_statement
    assert out["statements"][0]["impact_statement"] == sp.KERNEL_NOT_BUILT
    # 原本沒有 action_statement 的 affected 陳述補一句一般句子（OpenVEX 要求），狀態不變
    bare = {"statements": [{"vulnerability": {"name": "CVE-9"}, "products": [], "status": "affected"}]}
    assert sp.customer_openvex(bare)["statements"][0] == {"vulnerability": {"name": "CVE-9"}, "products": [], "status": "affected",
                                                         "action_statement": sp.ACTION_FALLBACK}


def test_supplier_package_vex_state_identical_and_internal_vex_untouched(tmp_path):
    """端對端：客戶資料包的 VEX 與內部 Reports 的 VEX 每一筆狀態相同；內部版仍有 sca-center 屬性；客戶版沒有。"""
    scan = make_scan(tmp_path / "scan")
    _, _, rep = run(make_project(tmp_path / "p", dict(MIN_CFG, role="supplier")), scan)
    internal = json.loads((rep / "vex.cdx.json").read_text(encoding="utf-8"))
    customer = json.loads((pkg(rep) / "vex.cdx.json").read_text(encoding="utf-8"))
    assert decisions_cdx(customer) == decisions_cdx(internal) and customer["vulnerabilities"]
    assert "sca-center:" in json.dumps(internal) and "sca-center:" not in json.dumps(customer)
    iv = json.loads((rep / "vex.openvex.json").read_text(encoding="utf-8"))
    cv = json.loads((pkg(rep) / "vex.openvex.json").read_text(encoding="utf-8"))
    assert [(s["vulnerability"], s["status"], s.get("justification"), s["products"]) for s in cv["statements"]] == \
           [(s["vulnerability"], s["status"], s.get("justification"), s["products"]) for s in iv["statements"]]
    assert all(s.get("action_statement") for s in cv["statements"] if s["status"] == "affected")
    assert json.loads((pkg(rep) / "summary.json").read_text(encoding="utf-8"))["language_check"]["status"] == "OK"


def test_language_check_flags_cjk_paths_and_internal_terms():
    assert sp.check_customer_text("a.md", "plain English text") == []
    assert sp.check_customer_text("a.md", "說明") == ["a.md: CJK"]
    assert sp.check_customer_text("a.md", "see /mnt/data/work/x") == ["a.md: local path"]
    assert sp.check_customer_text("vex.cdx.json", '{"name":"sca-center:vex-rule"}') == ["vex.cdx.json: internal term"]
    assert sp.check_customer_text("vex.openvex.json", "matched by Grype") == ["vex.openvex.json: internal term"]
    assert sp.check_customer_text("a.md", "matched by Grype") == ["a.md: internal term"]        # .md 與 summary.json 也查工具名稱
    assert sp.check_customer_text("vex.cdx.json", '{"purl":"pkg:deb/ubuntu/libcurl@1"}') == []
    assert sp.check_customer_text("sbom.cdx.json", '{"name":"/opt/nvidia/ksz/ksz.sh"}') == []      # 映像裡的路徑


def test_language_check_in_package_marks_gap(tmp_path):
    cfg = dict(FULL, product=dict(FULL["product"], identification="貼在模組上的標籤"))
    _, s, rep = run(make_project(tmp_path / "p", cfg), make_scan(tmp_path / "scan"))
    lc = s["supplier_package"]["language_check"]
    assert lc["status"] == "GAP" and any("README.md" in x for x in lc["findings"])
    assert s["supplier_package"]["status"] in ("GAP", "FAIL", "NOT_ASSESSED")


# ---- Fix 欄：UEFI 內建函式庫的重建提示

def test_bundled_uefi_fix_keeps_rebuild_hint():
    row = {"id": "CVE-1", "component": "OpenSSL 3.4.1 (bundled in UEFI)", "version": "3.4.1", "bundled_in": "UEFI", "fix_state": "fixed",
           "fix_versions": ["3.4.3", "3.3.4", "3.2.5", "3.0.17"], "fix": "internal text with Grype"}
    fix = sp.customer_fix(row)
    assert fix == "Rebuild the UEFI with OpenSSL 3.4.3 or later (an apt upgrade does not apply)."
    assert "Grype" not in fix
    row.update(fix_state="not-fixed", fix_versions=[])
    assert "an apt upgrade does not apply" in sp.customer_fix(row) and "No fixed OpenSSL version" in sp.customer_fix(row)
    copy_row = dict(row, bundled_in="UEFI source tree (copy)", fix_state="fixed", fix_versions=["3.4.3"])
    assert "not confirmed to be built into the firmware" in sp.customer_fix(copy_row) and "apt upgrade does not apply" in sp.customer_fix(copy_row)
    deb = {"id": "CVE-1", "component": "openssl", "fix_state": "fixed", "fix_versions": ["3.0.13-1"]}
    assert sp.customer_fix(deb) == "Fixed in 3.0.13-1."          # 一般元件不受影響


# ---- vulnerability-status.md

def status_md(rows, complete=False):
    summary = {"vex": {"gate": {"verdict": "ATTENTION", "counts": {}, "assessment": {"complete": complete, "untriaged_for_gate": 3}}}}
    ctx = {"product": "P", "supplier": "S", "now": "T", "artifact": {"data_status": "OK"}, "absent_reason": {}}
    return sp.vulnerability_status(summary, rows, ctx, sp_table)


def row(vid, comp, state, **kw):
    return dict({"id": vid, "component": comp, "version": "1", "kev": False, "vex": {"state": state}}, **kw)


def test_exploited_table_includes_bulletin_rows_and_matches_text():
    rows = [row("CVE-1", "a", "untriaged", kev=True), row("CVE-1", "b", "untriaged", kev=True),
            row("CVE-2", "nvidia-l4t-core", "in_triage", tier="p1", nvidia_bulletin="presumed_included",
                exploited_sources=["EUVD (CISA KEV)"]),                      # NVIDIA 公告列：沒有 KEV 標記，只有 exploited_sources
            row("CVE-3", "c", "resolved", kev=True), row("CVE-4", "d", "exploitable", kev=True, fix_state="not-fixed")]
    md = status_md(rows)
    part = md.split("## Reported as actively exploited and not resolved")[1].split("##")[0]
    table_rows = [l for l in part.splitlines() if l.startswith("| CVE-")]
    assert len(table_rows) == 4 and "CVE-2" in part and "CVE-3" not in part
    assert "4 rows (3 vulnerabilities) are reported as actively exploited and are not resolved." in part      # 文字與表用同一份清單
    assert "| CVE-2 | nvidia-l4t-core | 1 | Under assessment |" in part and "| CVE-4 | d | 1 | Affected |" in part


def test_customer_status_words_in_status_md():
    rows = [row("CVE-1", "a", "exploitable", fix_state="fixed", fix_versions=["2"], kev=True), row("CVE-2", "b", "in_triage"),
            row("CVE-3", "c", "untriaged"), row("CVE-4", "d", "resolved"), row("CVE-5", "e", "not_affected")]
    md = status_md(rows)
    assert "| Affected | 1 |" in md and "| Under assessment | 2 |" in md and "| Fixed | 1 |" in md and "| Not affected | 1 |" in md
    for w in ("exploitable", "untriaged", "in triage", "in_triage", "Update planned", "awaiting assessment", "product engineer",
              "subject to legal review"):
        assert w not in md, w
    assert "Assessment complete: **no**" in md and "rows still under assessment" in md and "Dependency-Track" not in md and "Grype" not in md
    assert sp.FIXED_OUTLOOK in md and "is available from the distribution" in sp.FIXED_OUTLOOK


def test_ambiguous_owner_rows_have_one_response():
    base = {"id": "CVE-1", "component": "pillow", "version": "1", "vex": {"state": "exploitable"}, "fix_state": "fixed", "fix_versions": ["2"],
            "deb_python": {"candidates": ["python3-pil 1", "python3-pil.imagetk 1"], "pypi_fix": ["2"]}}
    with_resp = dict(base, vex={"state": "exploitable", "response": ["update"]})
    without = dict(base)
    legacy = dict(base, vex={"state": "exploitable", "response": ["can_not_fix"]})
    assert {sp.customer_response(x) for x in (with_resp, without, legacy)} == {sp.AMBIGUOUS_OWNER}
    owned = dict(base, deb_python=dict(base["deb_python"], owner={"name": "python3-pil", "version": "1"}))
    assert sp.customer_response(owned) == sp.FIXED_OUTLOOK


def test_readme_has_no_legal_review_wording(tmp_path):
    _, _, rep = run(make_project(tmp_path / "p", FULL), make_scan(tmp_path / "scan"))
    assert "legal review" not in (pkg(rep) / "README.md").read_text(encoding="utf-8")


def test_placeholder_documents_omitted_and_listed(tmp_path):
    _, s, rep = run(make_project(tmp_path / "p", dict(MIN_CFG, role="supplier")), make_scan(tmp_path / "scan"))
    t = texts(pkg(rep))
    sums = t["SHA256SUMS"]
    for n in sp.OMITTABLE:
        assert n not in t and n not in sums
        assert any(f["file"] == n for f in json.loads(t["summary.json"])["files"]) is False
        assert re.search(rf"`{re.escape(n)}`[^\n]*not included in this package", t["README.md"])
    # 沒有任何「全是佔位字」的 .md 留在資料包
    for n, x in t.items():
        if n.endswith(".md") and n != "README.md":
            assert x.count("TO BE COMPLETED") <= 1, n
    # 填完整的設定：三份都交
    _, s2, rep2 = run(make_project(tmp_path / "q", FULL), make_scan(tmp_path / "scan"))
    assert set(sp.OMITTABLE) <= set(texts(pkg(rep2)))


# ---- sbom.md 的完整度數字（firmware_bom）

def tr_bom(n_ok, n_unknown, n_empty, manufacturer):
    comps = ([{"type": "library", "name": f"ok{i}", "version": "1.0", "bom-ref": f"o{i}"} for i in range(n_ok)]
             + [{"type": "library", "name": f"unk{i}", "version": "UNKNOWN", "bom-ref": f"u{i}"} for i in range(n_unknown)]
             + [{"type": "library", "name": f"empty{i}", "bom-ref": f"e{i}"} for i in range(n_empty)])
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": "urn:uuid:1",
            "metadata": {"timestamp": "2026-01-01T00:00:00Z", "manufacturer": manufacturer, "component": {"type": "firmware", "name": "P", "version": "1"}},
            "components": comps}


def test_unknown_version_counts_as_missing_version():
    tr = fb.tr03183(tr_bom(5, 3, 1, {"name": "Example Co."}))
    f = {x["field"]: x for x in tr["fields"]}["Component version"]
    assert f["missing_count"] == 4 and f["have"] == f["total"] - 4                    # UNKNOWN 與空白都算沒有版本
    assert fb.version_missing({"version": "UNKNOWN"}) and fb.version_missing({"version": " unknown "}) and fb.version_missing({})
    assert not fb.version_missing({"version": "1.0"})


def test_coverage_never_rounds_up_to_100():
    assert fb.pct(2721, 2730) == "99.6%" and fb.pct(2730, 2730) == "100%"
    assert fb.pct(2729, 2730) == "99.9%" and fb.pct(1, 3192) == "<0.1%" and fb.pct(0, 5) == "0.0%" and fb.pct(0, 0) == "–"
    assert fb.pct(9999, 10000) == "99.9%"
    tr = fb.tr03183(tr_bom(2720, 0, 9, {"name": "Example Co."}))
    text = fb.tr_text(tr, lambda h, r: "\n".join(" | ".join(map(str, x)) for x in r))
    assert "2721 / 2730 | 99.6%" in text and "100%" not in text.split("Component version")[1].split("\n")[0]


def test_sbom_creator_value_does_not_contradict_present_column():
    tr = fb.tr03183(tr_bom(1, 0, 0, {"name": "Example Co."}))
    r = next(x for x in tr["sbom"] if x["field"].startswith("Creator of the SBOM"))
    assert r["ok"] is False and r["value"] == "Example Co. (name only; no URL or email address recorded)"
    tr = fb.tr03183(tr_bom(1, 0, 0, {"name": "Example Co.", "url": ["https://example.com"]}))
    r = next(x for x in tr["sbom"] if x["field"].startswith("Creator of the SBOM"))
    assert r["ok"] is True and r["value"] == "Example Co."
    tr = fb.tr03183(tr_bom(1, 0, 0, None))
    assert next(x for x in tr["sbom"] if x["field"].startswith("Creator of the SBOM"))["value"] is None


def test_sbom_md_counts_unknown_versions_in_product_sbom(tmp_path):
    """sbom.md 第 3 節的「沒有版本」數產品 SBOM，UNKNOWN 版本也算（不再是 0）。"""
    _, _, rep = run(make_project(tmp_path / "p", MIN_CFG), make_scan(tmp_path / "scan"))
    md = (rep / "sbom.md").read_text(encoding="utf-8")
    m = re.search(r"(\d+) components, of which (\d+) package components \(not `file`\); package components without a version "
                  r"\(empty or `UNKNOWN`\): (\d+);", md.split("Product SBOM (")[1])
    assert m, md
    bom = json.loads((rep / "sbom.cdx.json").read_text(encoding="utf-8"))
    comps = [c for c in fb.flatten(bom.get("components")) if c.get("type") != "file"]
    assert int(m.group(1)) == len(list(fb.flatten(bom.get("components")))) and int(m.group(2)) == len(comps)
    assert int(m.group(3)) == sum(1 for c in comps if fb.version_missing(c))
    assert "Scanner SBOM (" in md                                # 兩個 SBOM 的數字各自標明來源
