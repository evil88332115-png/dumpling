"""cra_report.py、report_package.py 的分層（bsp／os／host-tool／unknown）：三種 os_responsibility 與沒給時的 GAP、P1 判斷表、
ATTENTION 的計算、host-tool 不進產品漏洞清單、unknown 當待辦。資料全部是合成的。
沒有分層（SBOM 沒有 dumpling:layer）時輸出不變，由既有測試與下面的 test_untagged_* 守住。"""
import json
import re

import pytest

import cra_report as cr
import report_package as rp
import xlsx_min
from test_cra_exploitation import cfg_of
from test_cra_report import DEB, EXAMPLE, clean_security, finding, make_project, make_scan, run, write_json
from test_report_package import row, rows_doc, sheets

PYPI = "pkg:pypi/brotli@1.1.0"


def comp(name, ver, layer, purl=None, basis="package-name"):
    return {"type": "library", "name": name, "version": ver, "purl": purl or DEB.format(name, ver),
            "properties": [{"name": "dumpling:layer", "value": layer}, {"name": "dumpling:layer-basis", "value": basis}]}


def bom(resp=None, *comps):
    meta = {"tools": {"components": [{"name": "syft", "version": "1.55.0"}]}}
    if resp:
        meta["properties"] = [{"name": "dumpling:os-responsibility", "value": resp}]
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": "urn:uuid:1", "metadata": meta, "components": list(comps)}


BSP, OSP, UNK, HOST = "nvidia-l4t-core", "openssl", "brotli", "flashtool"
V = {BSP: "39.2.1", OSP: "3.0.13-0ubuntu3.11", UNK: "1.1.0", HOST: "1.0"}
TAGGED = [comp(BSP, V[BSP], "bsp"), comp(OSP, V[OSP], "os"), comp(UNK, V[UNK], "unknown", PYPI), comp(HOST, V[HOST], "host-tool")]


def fnd(name, vid, sev="MEDIUM", kev=False, purl=None):
    return finding(name, V[name], vid, "NVD", sev, kev=kev, purl=purl)


def grype_for(findings):
    """每個 finding 一筆 Grype 比對（有修補版本），讓交叉核對不產生 ATTENTION：這樣狀態只反映分層的影響。"""
    ms = []
    for f in findings:
        c, v = f["component"], f["vulnerability"]
        ms.append({"vulnerability": {"id": v["vulnId"], "fix": {"state": "fixed", "versions": ["9.9"]}}, "relatedVulnerabilities": [],
                   "artifact": {"name": c["name"], "version": c["version"], "type": "python" if "pypi" in c["purl"] else "deb"}})
    return {"matches": ms}


def scenario(tmp_path, findings, resp_in_sbom=None, comps=TAGGED, cfg=EXAMPLE, name="s", *args):
    clean_security(tmp_path / name)
    proj = make_project(tmp_path / f"proj-{name}", cfg)
    scan = make_scan(tmp_path / name / "scan", findings=findings, grype=grype_for(findings), sbom=bom(resp_in_sbom, *comps))
    return run(proj, scan, *args)


def rows_of(rep):
    return json.loads((rep / "vulnerability-rows.json").read_text(encoding="utf-8"))


# ------------------------------------------------------------ cra_report

def test_untagged_sbom_changes_nothing(tmp_path):
    """SBOM 沒有 dumpling:layer：--os-responsibility 沒有作用，輸出沒有任何分層的痕跡（既有流程不受影響）。"""
    fs = [fnd(OSP, "CVE-2026-0002", kev=True)]
    plain = [{k: v for k, v in c.items() if k != "properties"} for c in TAGGED]
    r1, s1, rep1 = scenario(tmp_path, fs, None, plain, name="a")
    r2, s2, rep2 = scenario(tmp_path, fs, None, plain, EXAMPLE, "b", "--os-responsibility", "customer")
    assert "layers" not in s1 and "layers" not in s2 and "layers" not in rows_of(rep1)
    assert all("layer" not in x for x in rows_of(rep1)["rows"])
    ra = rep1.joinpath("risk-assessment.md").read_text(encoding="utf-8")
    assert "Layers (BSP" not in ra and "| Layer |" not in ra and "text.layer_section" not in ra and "{{" not in ra
    # 時間與 VEX 檔的 SHA-256 不比：沒有掃描時間的情境 VEX 用現在時間（vex_export.doc_timestamp），跨秒時 SHA 就不同
    norm = lambda t: re.sub(r"SHA-256 [0-9a-f]{12,64}", "SHA-256 H", re.sub(r"\d{4}-\d\d-\d\dT[\d:]+Z", "T", t))   # noqa: E731
    assert norm(ra) == norm(rep2.joinpath("risk-assessment.md").read_text(encoding="utf-8"))
    assert s1["status"] == s2["status"] and s1["counts"] == s2["counts"]
    assert not any("text.layer_section" in w for w in s1["config_warnings"])


def test_customer_os_kev_is_not_our_attention_but_is_listed_for_the_customer(tmp_path):
    fs = [fnd(OSP, "CVE-2026-0002", "HIGH", kev=True), fnd(OSP, "CVE-2026-0003", "LOW")]
    r, s, rep = scenario(tmp_path, fs, "customer")
    ra = (rep / "risk-assessment.md").read_text(encoding="utf-8")
    assert s["status"] == "OK" and s["documents"]["risk-assessment"]["status"] == "OK", s["documents"]["risk-assessment"]["detail"]
    L = s["layers"]
    assert L["os_responsibility"] == "customer" and not L["os_responsibility_gap"]
    assert [(x["id"], x["tier"]) for x in L["notify_customer"]] == [("CVE-2026-0002", "p1")]
    assert L["rows"] == {"bsp": 0, "os": 2, "unknown": 0} and L["todo_rows"] == 0 and L["p1_rows"]["os"] == 1
    # 沒有列消失：OS 層的 P1 仍在 P1 表、計數與機器可讀資料裡
    assert s["counts"]["p1"] == 1 and s["counts"]["rows"] == 2
    rows = rows_of(rep)["rows"]
    assert {x["id"]: (x["layer"], x["layer_todo"]) for x in rows} == {"CVE-2026-0002": ("os", False), "CVE-2026-0003": ("os", False)}
    assert "### 8.9 Layers (BSP / OS / host tools)" in ra and "the customer's responsibility" in ra
    assert "**Customer notification** (exploited rows in the OS layer): 1 row." in ra
    assert "| CVE-2026-0002 | openssl | 3.0.13-0ubuntu3.11 | P1 | KEV (DT) |" in ra
    assert "| Layer |" in ra and "| OS |" in ra          # P1 表多一欄 Layer
    assert "not counted here" not in " ".join(s["documents"]["risk-assessment"]["detail"])      # 沒有 P1 理由（沒有我們的待辦）


def test_ours_os_kev_makes_us_attention(tmp_path):
    fs = [fnd(OSP, "CVE-2026-0002", "HIGH", kev=True)]
    r, s, rep = scenario(tmp_path, fs, "ours")
    d = s["documents"]["risk-assessment"]
    assert d["status"] == "ATTENTION" and any("1 open finding in tier P1" in x for x in d["detail"])
    assert s["layers"]["todo_rows"] == 1 and s["layers"]["notify_customer"] == []
    assert rows_of(rep)["rows"][0]["layer_todo"] is True
    assert "OS layer is part of the product we ship and maintain" in (rep / "risk-assessment.md").read_text(encoding="utf-8")


def test_upstream_vendor_same_as_customer_with_its_own_wording(tmp_path):
    r, s, rep = scenario(tmp_path, [fnd(OSP, "CVE-2026-0002", "HIGH", kev=True)], "upstream-vendor")
    assert s["documents"]["risk-assessment"]["status"] == "OK" and len(s["layers"]["notify_customer"]) == 1
    assert "upstream OS vendor" in (rep / "risk-assessment.md").read_text(encoding="utf-8")


def test_command_line_responsibility_overrides_the_sbom_property(tmp_path):
    r, s, rep = scenario(tmp_path, [fnd(OSP, "CVE-2026-0002", "HIGH", kev=True)], "customer", TAGGED, EXAMPLE, "o", "--os-responsibility", "ours")
    assert s["layers"]["os_responsibility"] == "ours" and s["documents"]["risk-assessment"]["status"] == "ATTENTION"
    assert run(make_project(tmp_path / "pp", EXAMPLE), tmp_path / "o" / "scan", "--os-responsibility", "nobody")[0].returncode == 64


def test_no_os_responsibility_is_a_gap_and_everything_is_our_todo(tmp_path):
    fs = [fnd(OSP, "CVE-2026-0002", "HIGH", kev=True), fnd(BSP, "CVE-2026-0001", "LOW")]
    r, s, rep = scenario(tmp_path, fs, None)
    d = s["documents"]["risk-assessment"]
    assert d["status"] == "GAP" and any("os_responsibility was not given (GAP)" in x for x in d["detail"])
    L = s["layers"]
    assert L["os_responsibility"] is None and L["os_responsibility_gap"] is True and L["todo_rows"] == 2
    assert all(x["layer_todo"] for x in rows_of(rep)["rows"])           # 不預設：OS 層照最保守的方式列入待辦
    assert "GAP: os_responsibility was not given" in (rep / "risk-assessment.md").read_text(encoding="utf-8")
    assert any("P1" in x for x in d["detail"])                       # OS 層的 KEV 照樣算我們的 P1


def test_bsp_p1_is_always_ours(tmp_path):
    r, s, rep = scenario(tmp_path, [fnd(BSP, "CVE-2026-0001", "HIGH", kev=True)], "customer")
    assert s["documents"]["risk-assessment"]["status"] == "ATTENTION"
    assert s["layers"]["p1_rows"] == {"bsp": 1, "os": 0, "unknown": 0}


def test_unknown_layer_is_our_todo_never_os(tmp_path):
    fs = [fnd(UNK, "CVE-2026-0004", "HIGH", kev=True, purl=PYPI)]
    r, s, rep = scenario(tmp_path, fs, "customer")
    assert s["documents"]["risk-assessment"]["status"] == "ATTENTION"
    L = s["layers"]
    assert L["rows"] == {"bsp": 0, "os": 0, "unknown": 1} and L["unknown"] == {"components": 1, "by_purl_type": {"pypi": 1}, "rows": 1,
                                                                                "handling": "treated as our to-do (not defaulted to OS)"}
    x = rows_of(rep)["rows"][0]
    assert (x["layer"], x["layer_todo"]) == ("unknown", True) and L["notify_customer"] == []
    ra = (rep / "risk-assessment.md").read_text(encoding="utf-8")
    assert "1 component (pypi 1) could not be assigned to a layer" in ra and "treated as our to-do" in ra


def test_host_tool_findings_are_not_in_the_product_list(tmp_path):
    fs = [fnd(HOST, "CVE-2026-0005", "CRITICAL", kev=True), fnd(HOST, "CVE-2026-0006", "LOW"), fnd(OSP, "CVE-2026-0003", "LOW")]
    r, s, rep = scenario(tmp_path, fs, "customer")
    assert s["documents"]["risk-assessment"]["status"] == "OK"                       # 主機端工具的 KEV 不讓產品變 ATTENTION
    assert {x["id"] for x in rows_of(rep)["rows"]} == {"CVE-2026-0003"} and s["counts"]["rows"] == 1 and s["counts"]["findings_raw"] == 1
    h = s["layers"]["host_tool"]
    assert h["count"] == 1 and h["findings_not_listed"] == 2 and h["grype_matches_not_listed"] == 2 and h["ids"] == ["CVE-2026-0005", "CVE-2026-0006"]
    assert h["components"] == [{"name": HOST, "version": "1.0", "purl": DEB.format(HOST, "1.0")}]
    ra = (rep / "risk-assessment.md").read_text(encoding="utf-8")
    assert "**Host tools (not running on the product)**: 1 component; 2 Dependency-Track findings and 2 Grype matches" in ra and "flashtool 1.0" in ra
    assert "CVE-2026-0005" not in ra.split("Host tools (not running")[0]            # 不在產品的漏洞表裡


def test_host_tool_component_shared_with_the_product_stays_in_the_list(tmp_path):
    """同一個 purl 在別的層也有（例如主機端和板子上都有 openssl）→ 不是 host-tool 專用，保守地留在產品清單。"""
    comps = [comp(OSP, V[OSP], "host-tool"), comp(OSP, V[OSP], "os")]
    r, s, rep = scenario(tmp_path, [fnd(OSP, "CVE-2026-0003", "LOW")], "customer", comps)
    assert s["counts"]["rows"] == 1 and s["layers"]["host_tool"]["findings_not_listed"] == 0


def test_exploitation_scheme_gate_follows_the_todo_set(tmp_path):
    """分級方式 exploitation：依日期的出貨關卡只看我們的待辦；OS 層（customer）的 KEV 不擋，ours 時擋。"""
    fs = [fnd(OSP, "CVE-2026-0002", "HIGH", kev=True)]
    cfg = cfg_of(market="2027-12-10")
    _, s_c, rep_c = scenario(tmp_path, fs, "customer", TAGGED, cfg, "c")
    _, s_o, _ = scenario(tmp_path, fs, "ours", TAGGED, cfg, "o")
    assert s_o["exploitation"]["gate"]["p1"] == 1 and s_o["exploitation"]["gate"]["verdict"] == "BLOCKED"
    assert s_c["exploitation"]["gate"]["p1"] == 0 and s_c["exploitation"]["gate"]["verdict"] == "OK"
    assert s_c["counts"]["p1"] == 1 and len(s_c["layers"]["notify_customer"]) == 1       # 列沒有消失


def test_rows_resolve_layers_by_owner_and_synthetic_kind(tmp_path):
    idx = cr.build_layer_index(bom(None, comp("nvidia-l4t-kernel", "1", "bsp"), comp("linux-libc-dev", "1", "os"), comp("python3-attrs", "1", "os")))
    # 原始碼套件列：看安裝的二進位套件（bsp 優先於 os）
    assert cr.layer_of_row({"purl": "pkg:deb/ubuntu/linux@1", "name": "linux", "version": "1", "installed_as": ["linux-libc-dev", "nvidia-l4t-kernel"]},
                           idx) == ("bsp", "owner-package")
    assert cr.layer_of_row({"purl": "pkg:deb/ubuntu/linux@1", "name": "linux", "version": "1", "installed_as": ["linux-libc-dev"]},
                           idx) == ("os", "owner-package")
    # C-kernel-l4t-map 加的 Canonical 核心：看它是從哪個 nvidia-l4t-kernel 對應來的
    assert cr.layer_of_row({"purl": "pkg:generic/x@1", "name": "x", "version": "1", "mapped_from": "nvidia-l4t-kernel"}, idx) == ("bsp", "owner-package")
    # Ubuntu 打包的 Python 模組：看擁有它的 deb
    assert cr.layer_of_row({"purl": PYPI, "name": "attrs", "version": "1", "deb_python": {"owner": {"name": "python3-attrs"}}}, idx) == ("os", "owner-package")
    # BSP 專屬輸入產生的列
    assert cr.layer_of_row({"found_by": cr.KERNEL_CNA}, idx) == ("bsp", "synthetic:kernel-cna")
    assert cr.layer_of_row({"bundled_in": "UEFI"}, idx) == ("bsp", "synthetic:bundled-library")
    assert cr.layer_of_row({"source_ids": ["NVIDIA:SB1", "NVIDIA:SB2"]}, idx) == ("bsp", "synthetic:nvidia-bulletin")
    # 都對不到：unknown，不猜
    assert cr.layer_of_row({"purl": "pkg:pypi/zzz@1", "name": "zzz", "version": "1"}, idx) == ("unknown", "unmatched")


def test_layer_precedence_is_conservative():
    idx = cr.build_layer_index(bom(None, comp("a", "1", "os"), comp("a", "1", "bsp"), comp("b", "1", "os"), comp("b", "1", "unknown", DEB.format("b", "1")),
                                   comp("c", "1", "host-tool"), comp("c", "1", "os")))
    f = lambda n: cr.layer_of_row({"purl": DEB.format(n, "1"), "name": n, "version": "1"}, idx)[0]      # noqa: E731
    assert (f("a"), f("b"), f("c")) == ("bsp", "unknown", "os")
    assert cr.host_only(DEB.format("c", "1"), "c", "1", idx) is False
    assert cr.layer_todo("os", None) and cr.layer_todo("os", "ours") and not cr.layer_todo("os", "customer") and not cr.layer_todo("os", "upstream-vendor")
    assert cr.layer_todo("bsp", "customer") and cr.layer_todo("unknown", "upstream-vendor")


def test_unknown_values_in_the_sbom_count_as_unknown():
    c = comp("x", "1", "bsp")
    c["properties"][0]["value"] = "weird"
    idx = cr.build_layer_index(bom("nobody", c, comp("y", "1", "os")))
    assert idx["counts"]["unknown"] == 1 and idx["resp"] is None


def test_synthetic_components_in_the_product_sbom_are_tagged_bsp(tmp_path):
    r, s, rep = scenario(tmp_path, [fnd(OSP, "CVE-2026-0003", "LOW")], "customer")
    pb = json.loads((rep / "sbom.cdx.json").read_text(encoding="utf-8"))
    lay = {c["name"]: next(p["value"] for p in c["properties"] if p["name"] == "dumpling:layer") for c in pb["components"]}
    assert lay == {BSP: "bsp", OSP: "os", UNK: "unknown", HOST: "host-tool"}       # 掃描 SBOM 的層原樣帶到產品 SBOM


def test_project_template_without_layer_placeholder_warns(tmp_path):
    fs = [fnd(OSP, "CVE-2026-0003", "LOW")]
    clean_security(tmp_path / "t")
    ra = (cr.HERE / "templates" / "risk-assessment.md").read_text(encoding="utf-8").replace("{{ text.layer_section }}", "")
    proj = make_project(tmp_path / "pt", EXAMPLE, {"risk-assessment": ra})
    scan = make_scan(tmp_path / "t" / "scan", findings=fs, grype=grype_for(fs), sbom=bom("customer", *TAGGED))
    r, s, rep = run(proj, scan)
    assert any("text.layer_section" in w for w in s["config_warnings"]) and "Layers (BSP" not in (rep / "risk-assessment.md").read_text(encoding="utf-8")
    assert s["layers"]["rows"]["os"] == 1            # summary.json 與 vulnerability-rows.json 照樣有


# ------------------------------------------------------------ report_package

def lrow(id_, layer, tier="p3", todo=None, comp_="libx", **kw):
    r = row(id_, tier, comp=comp_, **kw)
    r.update(layer=layer, layer_todo=(layer != "os") if todo is None else todo, layer_basis="package-name")
    return r


def layered_doc(rows, resp="customer", **kw):
    d = rows_doc(rows, **kw)
    d["layers"] = {"active": True, "os_responsibility": resp, "os_responsibility_gap": resp is None,
                   "components": {"bsp": 2, "os": 3, "unknown": 1, "host-tool": 1}, "rows": {}, "unknown": {"components": 1, "by_purl_type": {"pypi": 1}, "rows": 0},
                   "host_tool": {"count": 1, "findings_not_listed": 2, "grype_matches_not_listed": 0, "ids": [], "components": [{"name": "flashtool", "version": "1.0", "purl": ""}]}}
    return d


def package(tmp_path, rows, resp="customer", name="pk", args=()):
    p = tmp_path / name
    rep = p / "CRA" / "Reports"
    rep.mkdir(parents=True)
    (p / "CRA" / "Config").mkdir()
    write_json(p / "CRA" / "Config" / "config.json", {"product": {"name": "Prod", "version": "1.2"}})
    write_json(rep / rp.ROWS_FILE, layered_doc(rows, resp))
    write_json(rep / "summary.json", {"counts": {"kernel": {"fix_all": []}}})
    for n, t in (("sbom.cdx.json", "{}"), ("sbom.md", "# sbom"), ("vex.cdx.json", "{}"), ("security-findings.md", "# f"), ("risk-assessment.md", "# ra")):
        (rep / n).write_text(t, encoding="utf-8")
    (rep / "confirmation-items.csv").write_text("編號,類別\nQ1,缺少輸入\n", encoding="utf-8-sig")
    out = tmp_path / (name + "-out")
    code, msgs = rp.build(p, out, allow_tmp=True, **dict(args))
    return code, msgs, out


MIXED = [lrow("CVE-1", "bsp", "p1", exploited=True, exploitation_evidence=["KEV (DT)"], comp_="libb"),
         lrow("CVE-2", "os", "p1", exploited=True, exploitation_evidence=["KEV (DT)"], comp_="libo"),
         lrow("CVE-3", "unknown", "p1", exploited=True, exploitation_evidence=["EUVD (CISA KEV)"], comp_="libu"),
         lrow("CVE-4", "os", "p3", comp_="libo2"), lrow("CVE-5", "bsp", "p3", comp_="libb2"),
         lrow("CVE-6", "os", "accepted", rule="K1", comp_="libo3")]


def p1_cves(out):
    sh = sheets(out / "給RD" / "P1判斷表.xlsx")["P1 判斷表"]
    i = next(k for k, r in enumerate(sh) if r and r[0] == "編號")
    return [r[1] for r in sh[i + 1:] if r and str(r[1]).startswith("CVE-")], sh


def pm_sheets(out):
    return sheets(out / "交給PM" / "漏洞清單.xlsx")


def flat(sh):
    return " ".join(" ".join(map(str, r)) for r in sh)


def body(sh, first="層"):
    i = next(k for k, r in enumerate(sh) if r and r[0] == first)
    return sh[i], [r for r in sh[i + 1:] if r and r[0]]


def test_p1_sheet_customer_only_our_layers(tmp_path):
    code, msgs, out = package(tmp_path, MIXED, "customer")
    cves, sh = p1_cves(out)
    assert cves == ["CVE-1", "CVE-3"]                       # bsp 與 unknown；OS 層（CVE-2）不在
    txt = flat(sh)
    assert "這張表放的是我們的待辦：BSP、層未定（unknown）" in txt and "另有 1 列 P1 不在這張表" in txt and "通知客戶" in txt
    assert any(len(r) > 3 and r[3] == "層" for r in sh)          # 有「層」欄
    assert any(m.startswith("分層：BSP 2 列、unknown（層未定） 1 列、OS 3 列（我們的待辦 3 列；os_responsibility customer") for m in msgs)


def test_p1_sheet_ours_includes_os(tmp_path):
    rows = [dict(r, layer_todo=True) for r in MIXED]
    code, msgs, out = package(tmp_path, rows, "ours")
    cves, sh = p1_cves(out)
    assert cves == ["CVE-1", "CVE-2", "CVE-3"]
    assert "這張表放的是我們的待辦：BSP、層未定（unknown）、OS" in flat(sh)


def test_ours_os_p1_reaches_the_p1_sheet_end_to_end(tmp_path):
    """缺口 24：os_responsibility: ours 時 OS 層的 P1（例如已被利用的 openssh）是我們的待辦，cra_report → report_package 一路下來
    P1 判斷表一定要列出來（不能只有表頭）；customer 時不在這張表（在漏洞清單的 OS 工作表與「通知客戶」）。"""
    fs = [fnd(OSP, "CVE-2026-0002", "HIGH", kev=True)]
    for resp, want in (("ours", ["CVE-2026-0002"]), ("customer", [])):
        r, s, rep = scenario(tmp_path, fs, resp, name="e-" + resp)
        assert r.returncode in (0, 2), r.stdout + r.stderr
        assert [x["layer"] for x in rows_of(rep)["rows"]] == ["os"]
        out = tmp_path / ("e-" + resp + "-out")
        code, msgs = rp.build(rep.parent.parent, out, allow_tmp=True)
        assert code in (0, 2), msgs
        cves, sh = p1_cves(out)
        assert cves == want, (resp, cves)


def test_p1_sheet_without_responsibility_is_conservative(tmp_path):
    rows = [dict(r, layer_todo=True) for r in MIXED]
    code, msgs, out = package(tmp_path, rows, None)
    assert p1_cves(out)[0] == ["CVE-1", "CVE-2", "CVE-3"]
    assert any("未給（GAP，不預設，全部列入待辦）" in m for m in msgs)
    assert "GAP：沒有 os_responsibility" in " ".join(flat(sh) for sh in pm_sheets(out).values())


def test_p1_layers_option_overrides(tmp_path):
    code, msgs, out = package(tmp_path, MIXED, "customer", "ov", {"p1_layers": {"bsp"}})
    cves, sh = p1_cves(out)
    assert cves == ["CVE-1"] and "指定的層（BSP）" in flat(sh)
    code, msgs, out = package(tmp_path, MIXED, "customer", "ov2", {"p1_layers": {"bsp", "os"}})
    assert p1_cves(out)[0] == ["CVE-1", "CVE-2"]


def test_pm_workbook_customer_layout(tmp_path):
    code, msgs, out = package(tmp_path, MIXED, "customer")
    shs = pm_sheets(out)
    assert list(shs)[1:] == ["完整漏洞清單", "排除後剩下的", "範例 rootfs（給客戶參考）", "通知客戶", "分層摘要", "規則說明"]
    h, f = body(shs["完整漏洞清單"])
    assert h[:2] == ["層", "初判"] and len(f) == 6                      # 完整清單：全部的列（沒有消失），多一欄「層」
    assert [r[0] for r in f] == ["BSP", "BSP", "unknown（層未定）", "OS", "OS", "OS"]       # 依層排
    assert {r[2] for r in body(shs["排除後剩下的"])[1]} == {"CVE-1", "CVE-3", "CVE-5"}     # 排除後剩下的：只有我們的待辦
    assert {r[2] for r in body(shs["範例 rootfs（給客戶參考）"])[1]} == {"CVE-2", "CVE-4"}  # OS 層還要處理的
    assert [r[2] for r in body(shs["通知客戶"])[1]] == ["CVE-2"]                         # 只有已被利用的
    s = flat(shs["分層摘要"])
    assert "OS 層由客戶負責" in s and "主機端工具：1 個元件" in s and "flashtool 1.0" in s and "unknown＝判斷不了層" in s and "pypi 1" in s
    assert "總覽只含我們的待辦（另有 3 列在 OS 層" in flat(shs[next(iter(shs))])             # 總覽（第一張）只含我們的待辦


def test_sheet_names(tmp_path):
    code, msgs, out = package(tmp_path, MIXED, "upstream-vendor", "uv")
    assert list(pm_sheets(out))[1:] == ["完整漏洞清單", "排除後剩下的", "OS層（上游廠商負責）", "通知客戶", "分層摘要", "規則說明"]
    assert "我們只通知客戶" in flat(pm_sheets(out)["分層摘要"])
    code, msgs, out = package(tmp_path, [dict(r, layer_todo=True) for r in MIXED], "ours", "ours")
    assert list(pm_sheets(out))[1:] == ["完整漏洞清單", "排除後剩下的", "分層摘要", "規則說明"]       # ours：OS 也是待辦，不另開 OS 與通知客戶


def test_ours_open_list_includes_os_rows(tmp_path):
    code, msgs, out = package(tmp_path, [dict(r, layer_todo=True) for r in MIXED], "ours")
    assert {r[2] for r in body(pm_sheets(out)["排除後剩下的"])[1]} == {"CVE-1", "CVE-2", "CVE-3", "CVE-4", "CVE-5"}


def test_no_layers_block_keeps_the_old_layout(tmp_path):
    from test_report_package import project
    p = project(tmp_path, [row("CVE-1", "p1", exploited=True, exploitation_evidence=["KEV (DT)"]), row("CVE-2", "p3")], name="old")
    code, msgs = rp.build(p, tmp_path / "old-out", allow_tmp=True)
    shs = sheets(tmp_path / "old-out" / "交給PM" / "漏洞清單.xlsx")
    assert len(shs) == 4
    h, _ = body(shs["完整漏洞清單"], "初判")
    assert h == rp.LIST_HEADER and not any(m.startswith("分層：") for m in msgs)
    assert p1_cves(tmp_path / "old-out")[0] == ["CVE-1"]


def test_cli_p1_layers_validation(tmp_path):
    import subprocess
    import sys
    from test_report_package import project
    p = project(tmp_path, [row("CVE-1", "p1", exploited=True)], name="cli")
    r = subprocess.run([sys.executable, "-I", str(rp.CLI if hasattr(rp, "CLI") else rp.__file__), "--project", str(p), "--out", str(tmp_path / "cli-out"),
                        "--p1-layers", "bsp,nope"], capture_output=True, text=True)
    assert r.returncode == 64 and "--p1-layers" in r.stderr


def test_unknown_reason_counts_and_host_tool_note_are_reported(tmp_path):
    """D-030：unknown 附判斷不了的原因（依原因計數）；host-tool 一節說明它隨 BSP 提供給客戶、在客戶的主機上執行。"""
    fs = [fnd(UNK, "CVE-2026-0004", "HIGH", kev=True, purl=PYPI), fnd(HOST, "CVE-2026-0005", "LOW")]
    comps = []
    for c in TAGGED:
        c = dict(c)
        if c.get("name") == UNK:
            c["properties"] = list(c.get("properties") or []) + [{"name": "dumpling:unknown-reason", "value": "no-path"}]
        comps.append(c)
    r, s, rep = scenario(tmp_path, fs, "customer", comps)
    assert s["layers"]["unknown_by_reason"] == {"no-path": 1}
    ra = (rep / "risk-assessment.md").read_text(encoding="utf-8")
    assert "Why the layer could not be determined: no path and not a distribution package 1." in ra
    assert "Host tools are shipped to the customer with the BSP and run on the customer's host, not on the product." in ra


def test_l4t_kernel_map_rows_with_name_and_version_resolve_to_the_kernel_package_layer():
    """C-kernel-l4t-map 的 mapped_from 實際值是「名稱 版本」（例如 nvidia-l4t-kernel 6.8.12-tegra-39.2.1-…）：用名稱找層，核心列是 bsp，不是 unknown。"""
    idx = cr.build_layer_index(bom(None, comp("nvidia-l4t-kernel", "6.8.12-tegra-39.2.1", "bsp")))
    row = {"purl": "pkg:deb/ubuntu/linux-nvidia-tegra@6.8.0-1021.21", "name": "linux-nvidia-tegra", "version": "6.8.0-1021.21",
           "mapped_from": "nvidia-l4t-kernel 6.8.12-tegra-39.2.1"}
    assert cr.layer_of_row(row, idx) == ("bsp", "owner-package")
    assert cr.layer_of_row(dict(row, mapped_from=None), idx) == ("unknown", "unmatched")       # 沒有對應來源：不猜


# ------------------------------------------------------------ BSP 專屬的附加輸入在沒有 BSP 元件的分層報告不適用

def _layered_sbom(*layers):
    """test_cra_report.SBOM 的元件依序標上層（其餘標 os）；給 bsp 時多一個 bsp 元件。"""
    from test_cra_report import SBOM
    b = json.loads(json.dumps(SBOM))
    for c in cr.flatten(b["components"]):          # 巢狀元件也要標，沒標的算 unknown
        c.setdefault("properties", []).append({"name": "dumpling:layer", "value": "os"})
    b["metadata"]["properties"] = [{"name": "dumpling:os-responsibility", "value": "customer"}]
    if "bsp" in layers:
        b["components"].append(comp(BSP, V[BSP], "bsp"))
    if "unknown" in layers:
        b["components"].append(comp(UNK + "-x", "1", "unknown", "pkg:pypi/x@1"))
    return b


def _tee_layer_report(tmp_path, *layers, explicit=False):
    from test_cra_report import MIN_CFG
    from test_tee_source import grype_json, make_tee, put_grype
    t = make_tee(tmp_path)
    put_grype(t, grype_json())
    proj = make_project(tmp_path / "p", MIN_CFG)
    scan_ = make_scan(tmp_path / "res" / "scan", sbom=_layered_sbom(*layers))
    extra = ()
    if explicit:
        extra = ("--tee-source", str(t))
    else:
        import os
        os.replace(t, scan_.parent / "tee-source")      # 自動帶入（<scan>/../tee-source）
    r, s, rep = run(proj, scan_, *extra)
    assert r.returncode in (0, 2), r.stdout + r.stderr
    return s, rep, json.loads((rep / "sbom.cdx.json").read_text(encoding="utf-8")), rows_of(rep)


@pytest.mark.parametrize("explicit", [False, True])
def test_os_only_layer_report_skips_the_bsp_tee_libraries(tmp_path, explicit):
    s, rep, pb, rows = _tee_layer_report(tmp_path, explicit=explicit)
    assert not any(r["id"] == "CVE-2099-0101" for r in rows["rows"])            # 沒有 bsp 層的 Mbed TLS 列（在 bsp 報告）
    assert not {"OP-TEE", "TF-A", "Mbed TLS"} & {c["name"] for c in pb["components"]}
    assert "tee_source" not in s["product_sbom"]                                # 它的狀態不算進這份
    assert s["layers"]["bsp_inputs_not_applicable"]["skipped"] == ["tee-source"]
    assert rows["layers"]["bsp_inputs_not_applicable"]["skipped"] == ["tee-source"]
    assert not [r for r in rows["rows"] if r["layer"] == "bsp"]                  # 合成的掃描結果裡對不到元件的列是 unknown（不猜），bsp 一列都沒有


@pytest.mark.parametrize("layers", [("bsp",), ("unknown",)])
def test_layer_report_with_bsp_or_unknown_components_keeps_the_tee_libraries(tmp_path, layers):
    s, rep, pb, rows = _tee_layer_report(tmp_path, *layers)
    row = next(r for r in rows["rows"] if r["id"] == "CVE-2099-0101")
    assert row["layer"] == "bsp" and row["layer_basis"] == "synthetic:bundled-library"
    assert {"OP-TEE", "TF-A", "Mbed TLS"} <= {c["name"] for c in pb["components"]}
    assert s["product_sbom"]["tee_source"]["rows"] == 1
    assert "bsp_inputs_not_applicable" not in s["layers"]


def test_os_only_layer_report_skips_the_flash_firmware(tmp_path):
    from test_firmware_bom import flash_result
    proj, scan_ = flash_result(tmp_path, sbom=_layered_sbom())
    r, s, rep = run(proj, scan_)
    assert r.returncode in (0, 2), r.stdout + r.stderr
    pb = json.loads((rep / "sbom.cdx.json").read_text(encoding="utf-8"))
    assert not {"mb1_t234_prod.bin", "NVIDIA Jetson Linux", "nvgpu"} & {c["name"] for c in pb["components"]}
    assert {next(p["value"] for p in c["properties"] if p["name"] == "dumpling:layer") for c in pb["components"]} == {"os"}
    fw = s["product_sbom"]["flash_firmware"]
    assert fw["layer_not_applicable"] is True and "BSP layer's report" in fw["absent"]
    assert s["layers"]["bsp_inputs_not_applicable"]["skipped"] == ["flash-firmware"]
    assert "BSP layer's report" in (rep / "sbom.md").read_text(encoding="utf-8")
    # 同一個刷機包、分層 SBOM 有 bsp 元件 → 照舊加進去
    proj2, scan2 = flash_result(tmp_path / "b", sbom=_layered_sbom("bsp"))
    r2, s2, rep2 = run(proj2, scan2)
    pb2 = json.loads((rep2 / "sbom.cdx.json").read_text(encoding="utf-8"))
    assert {"mb1_t234_prod.bin", "NVIDIA Jetson Linux"} <= {c["name"] for c in pb2["components"]}
    assert s2["product_sbom"]["flash_firmware"]["components"] == 9 and "bsp_inputs_not_applicable" not in s2["layers"]
