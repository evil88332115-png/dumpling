"""總覽（儀表板）工作表與 xlsx_min 的 Canvas／圖表。資料全部是合成的。"""
import re
import subprocess
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest

import report_package as rp
import xlsx_min
from test_report_package import MIX, project, row, rows_doc, sheets

ROWS = MIX + [row("CVE-9", "p3", comp="libz", severity="CRITICAL", exposed=True, exposed_where="sshd (22/tcp)"),
              row("CVE-8", "p3", comp="libz", ver="2.0", severity=None, exposed=None),
              row("CVE-7", "p3", comp="libz", ver="3.0", severity="LOW", exposed=False,
                  suggestion={"rule": "UB1", "state": "not_affected", "justification": None, "detail": "d", "needs": "x"})]


def doc_of(rows, **kw):
    d = rows_doc(rows, **kw)
    d["_warnings"] = ["設定警告一則"]
    return d


def dash(rows, **kw):
    return rp.dashboard_sheet(doc_of(rows, **kw), {}, "Prod 1.2")


def grid(cv):
    """Canvas → {A1: 值}。"""
    return {f"{xlsx_min.col_name(c)}{r + 1}": v for (r, c), (v, _) in cv.cells.items() if v not in ("", None)}


def find(g, text):
    return next(k for k, v in g.items() if v == text)


def write(tmp_path, rows, name="a.xlsx", **kw):
    p = Path(tmp_path) / name
    d = doc_of(rows, **kw)
    xlsx_min.write_xlsx(p, [rp.dashboard_sheet(d, {}, "Prod 1.2"), rp.component_sheet(d, {}, "Prod 1.2")])
    return p


def test_kpi_equals_tier_counts():
    g = grid(dash(ROWS))
    tc = rp.tier_counts(doc_of(ROWS)["rows"])
    assert g["A1"] == "Prod 1.2 漏洞總覽"
    assert g["A5"] == len(ROWS) and g["C5"] == len({r["id"] for r in ROWS})
    assert g["E5"] == tc[rp.T_NOW][0] and g["G5"] == tc[rp.T_TRACK][0] and g["I5"] == tc[rp.T_OK][0]
    assert g["K5"] == sum(1 for r in ROWS if r["tier"] in rp.OPEN_TIERS and r["exposed"] is True)
    assert "2026-11-11 08:00" in g["A2"]          # 00:00 UTC → 台北 08:00
    assert "OK" in g["A2"] and "沒有列出的不代表沒有問題" not in g["A2"]


def test_subtitle_warns_when_status_not_ok():
    t = grid(dash(ROWS, status="GAP"))["A2"]
    assert "GAP" in t and t.count("沒有列出的不代表沒有問題") == 1


def test_totals_rows_and_open_tables():
    cv = dash(ROWS)
    g = grid(cv)
    r0 = int(find(g, "合計")[1:])
    assert [g[f"{c}{r0}"] for c in "BCDEFGHI"][0] == len(ROWS)
    # 分類表：各分類列數加起來 = 合計；嚴重度加起來 = 合計
    r_hdr = int(find(g, "佔比（列）")[1:])
    body = range(r_hdr + 1, r0)
    assert sum(g[f"B{r}"] for r in body) == len(ROWS)
    assert sum(g[f"{c}{r0}"] for c in "EFGHI") == len(ROWS)
    assert g[f"A{r_hdr + 1}"] == "立即處理" and g[f"A{r_hdr + 4}"] == "已修補"
    # 對外 × 嚴重度：合計列 = 還要處理列數，且各列相加
    op = [r for r in ROWS if r["tier"] in rp.OPEN_TIERS]
    a = find(g, "從網路碰得到")
    lh = int(a[1:]) - 1
    last = next(int(k[1:]) for k, v in g.items() if v == "合計" and k[0] == "A" and int(k[1:]) > lh)
    assert g[f"G{last}"] == len(op)
    assert sum(g[f"G{r}"] for r in range(lh + 1, last)) == len(op)
    assert [g[f"{c}{last}"] for c in "BCDEF"] == rp.sev_counts(op)
    assert g[find(g, "對外不明")[0] + str(int(find(g, "對外不明")[1:]))] == "對外不明"
    # 主要原因：合計 = 還要處理列數
    ri = [k for k, v in g.items() if v == "合計" and k[0] == "I"][0]
    assert g["L" + ri[1:]] == len(op)


def test_unknown_category_row_only_when_present():
    assert "未分類" not in grid(dash(ROWS)).values()
    g = grid(dash(ROWS + [row("CVE-X", "weird")]))
    assert "未分類" in g.values()


def test_no_exposure_data_shows_unknown_not_zero():
    cv = dash(ROWS, exposed_services_list=False)
    g = grid(cv)
    assert g["K5"] == "不明" and g["K5"] != 0
    assert "從網路碰得到" not in g.values()
    assert len(cv.charts) == 2
    assert any("沒有實機" in str(v) for v in g.values())
    assert len(dash(ROWS).charts) == 3


def test_not_assessed_does_not_show_zero():
    cv = dash([], have_findings=False, status="NOT_ASSESSED")
    g = grid(cv)
    assert [g[f"{c}5"] for c in "ACEGIK"] == ["NOT_ASSESSED"] * 6
    assert 0 not in g.values() and not cv.charts
    assert "NOT_ASSESSED" in g["A2"] and "不代表沒有弱點" in g[find(g, next(v for v in g.values() if str(v).startswith("NOT_ASSESSED：這次")))]
    assert not any("安全" in str(v) and "不" not in str(v) for v in g.values())


def test_human_judgement_block_and_notes():
    g = grid(dash(ROWS))
    p1 = next(k for k, v in g.items() if v == "P1（立即處理）")
    assert g["D" + p1[1:]] == "3 列"
    sg = next(k for k, v in g.items() if v == "建議（需 RD 確認）")
    assert g["D" + sg[1:]] == "1 筆"
    notes = " ".join(str(v) for v in g.values())
    for t in ("CVE × 元件", "不是公式", "設定警告一則", "沒對外"):
        assert t in notes


def test_top_components_match_component_sheet():
    d = doc_of(ROWS)
    exp = [x for x in rp.component_sheet(d, {}, "L").rows if x[2] + x[3] > 0][:10]
    g = grid(rp.dashboard_sheet(d, {}, "L"))
    r0 = int(find(g, "誰處理")[1:])
    for i, x in enumerate(exp, 1):
        assert [g[f"A{r0 + i}"], g[f"F{r0 + i}"], g[f"G{r0 + i}"], g.get(f"H{r0 + i}"), g[f"K{r0 + i}"]] == [x[0], x[2], x[3], x[6] or None, x[9]]


def test_sheet_order_in_package(tmp_path):
    p = project(tmp_path, ROWS)
    out = tmp_path / "out"
    rp.build(p, out, allow_tmp=True)
    wb = sheets(out / "交給PM" / "漏洞清單.xlsx")
    assert list(wb) == ["總覽", "完整漏洞清單", "排除後剩下的", "規則說明"]
    assert wb["總覽"][0][0].endswith("漏洞總覽")
    assert list(sheets(out / "給RD" / "P1判斷表.xlsx"))[0] == "P1 判斷表"
    cust = list(out.rglob("客戶資料包"))
    assert all("總覽" not in " ".join(sheets(x).keys()) for c in cust for x in c.rglob("*.xlsx"))


def test_every_part_is_wellformed_and_charts_reference_real_ranges(tmp_path):
    p = write(tmp_path, ROWS)
    with zipfile.ZipFile(p) as z:
        names = z.namelist()
        for n in names:
            ET.fromstring(z.read(n))
        charts = [n for n in names if n.startswith("xl/charts/chart")]
        assert len(charts) == 3 and "xl/drawings/drawing1.xml" in names and "xl/worksheets/_rels/sheet1.xml.rels" in names
        ct = z.read("[Content_Types].xml").decode()
        assert ct.count("drawingml.chart+xml") == 3 and "drawing+xml" in ct
        cv = rp.dashboard_sheet(doc_of(ROWS), {}, "Prod 1.2")
        wb = sheets(p)["總覽"]
        for n in charts:
            x = z.read(n).decode()
            refs = re.findall(r"<c:f>'總覽'!\$([A-Z]+)\$(\d+)(?::\$([A-Z]+)\$(\d+))?</c:f>", x)
            assert len(refs) == 2
            for c1, r1, c2, r2 in refs:
                for rr in range(int(r1), int(r2 or r1) + 1):
                    assert wb[rr - 1][xlsx_min.col_index(c1)] not in ("", None)
        rels = z.read("xl/drawings/_rels/drawing1.xml.rels").decode()
        assert all(f"../charts/chart{i}.xml" in rels for i in (1, 2, 3))
        assert len(cv.merges) > 10 and "<mergeCells" in z.read("xl/worksheets/sheet1.xml").decode()
        assert "<drawing " in z.read("xl/worksheets/sheet1.xml").decode()
    assert sheets(p)["依元件"][0]


def test_sheet_only_workbook_unchanged_styles(tmp_path):
    p = tmp_path / "s.xlsx"
    xlsx_min.write_xlsx(p, [xlsx_min.Sheet("a", ["x"], [[1]])])
    with zipfile.ZipFile(p) as z:
        assert z.read("xl/styles.xml").decode() == xlsx_min.STYLES
        assert not [n for n in z.namelist() if "chart" in n or "drawing" in n]


def test_canvas_validation():
    cv = xlsx_min.Canvas("c")
    cv.set("A1", "x")
    cv.merge("A1:B1")
    with pytest.raises(ValueError):
        cv.merge("B1:C1")
    with pytest.raises(ValueError):
        cv.set("1A", "x")
    with pytest.raises(ValueError):
        xlsx_min._Styles().get(xlsx_min.Style(fill="red"))
    cv.set("A3", "a")
    cv.set("A4", "b")          # 文字不能當圖表數值
    with pytest.raises(ValueError):
        xlsx_min._chart_xml(cv, xlsx_min.Chart("bar", "t", "A3:A3", "A4:A4", "A6:D10"))
    with pytest.raises(ValueError):
        xlsx_min.Chart("line", "t", "A1", "A2", "A1:B2")


def test_package_parts_consistent_and_libreoffice_opens_if_present(tmp_path):
    """結構檢查一定跑：每個部件是合法 XML，關聯與 content types 對得上。有 LibreOffice 才多轉一次 PDF（不用 skip：CI 的 DUMPLING_REQUIRE_TEST_DATA=1 不允許 skip）。"""
    p = write(tmp_path, ROWS)
    with zipfile.ZipFile(p) as z:
        names = set(z.namelist())
        for n in names:
            ET.fromstring(z.read(n))
        ct = z.read("[Content_Types].xml").decode()
        for n in names:
            if n.endswith(".xml") and n != "[Content_Types].xml" and "/_rels/" not in n and not n.startswith("_rels/"):
                assert f'PartName="/{n}"' in ct, n
        for n in names:
            if n.endswith(".rels"):
                base = n.replace("_rels/", "").rsplit(".rels", 1)[0]
                folder = base.rsplit("/", 1)[0] if "/" in base else ""
                for t in re.findall(r'Target="([^"]+)"', z.read(n).decode()):
                    path = "/".join(x for x in (folder + "/" + t).split("/") if x not in ("",))
                    parts = []
                    for x in path.split("/"):
                        parts.pop() if x == ".." else parts.append(x)
                    assert "/".join(parts) in names or t.endswith("workbook.xml") or "/".join(parts) in names, (n, t)
    soffice = "/usr/bin/soffice"
    if Path(soffice).exists():
        r = subprocess.run([soffice, "--headless", f"-env:UserInstallation=file://{tmp_path}/lo", "--convert-to", "pdf", "--outdir", str(tmp_path), str(p)],
                           capture_output=True, text=True, timeout=240)
        pdf = tmp_path / "a.pdf"
        assert pdf.exists() and pdf.stat().st_size > 5000, r.stderr


def test_manual_verdict_must_match_tier_class():
    a = row("C", "p3", source="annotation")
    a["vex"]["state"] = "not_affected"                      # 還要處理的列卻寫不受影響
    assert rp.verdict(a, {}) == "未分類－人工判定與分類對不上"
    b = row("C", "accepted", source="annotation")
    b["vex"]["state"] = "exploitable"                       # 排除的列卻寫受影響
    assert rp.verdict(b, {}) == "未分類－人工判定與分類對不上"


def test_p1_reason_listed_first_and_unclassified_in_pie():
    many = [row(f"CVE-{i}", "p3", rule=rule, comp=f"c{i}") for i, rule in enumerate(["R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9", "R9m"] * 3)]
    d = rp.dashboard_data(doc_of(many + [row("CVE-P", "p1")]), {}, "L")
    assert d["reasons"][0] == (rp.SHORT["P1"], 1) and len(d["reasons"]) == 9 and d["reasons"][-1][0] == "其他"
    cv = dash(ROWS + [row("CVE-X", "weird")])
    pie = cv.charts[0]
    vals = cv.range_values(pie.vals)
    assert len(vals) == 5 and sum(vals) == len(ROWS) + 1


def test_not_assessed_subtitle_wording():
    assert "下面的 0" not in rp.status_line({"have_findings": False})
