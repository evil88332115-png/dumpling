"""最小的 xlsx 寫入器（只用標準函式庫：zipfile + XML）。

工具用的 Python 沒有 openpyxl，也不能加依賴，所以自己寫一個夠用的：多個工作表、文字與數字儲存格（文字用 inline string）、
粗體表頭、凍結表頭列、欄寬、自動篩選、可換行。Excel 與 LibreOffice 都能開。

用法：
    write_xlsx(path, [Sheet("名稱", header=["欄1", "欄2"], rows=[["a", 1]], widths=[20, 10], top=[["一行說明"]])])

top：表頭前面的列（例如摘要數字）；表頭、凍結與篩選都從表頭那一列算。

自由版面（儀表板用）：Canvas(name) 逐格 set(ref, 值, Style(...))、merge("A1:L1")、height(列, 點數)、原生圖表 Chart；
write_xlsx 的工作表清單可以混用 Sheet 與 Canvas。沒有用到 Canvas 時，輸出與以前相同。
"""
import dataclasses
import math
import re
import zipfile
from xml.sax.saxutils import escape

MAX_CELL = 32000      # Excel 一格最多 32767 字元
_BAD = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f￾￿]")
_BAD_NAME = re.compile(r"[\[\]:*?/\\]")


def col_name(i):
    """0 → A, 25 → Z, 26 → AA。"""
    s = ""
    i += 1
    while i:
        i, r = divmod(i - 1, 26)
        s = chr(65 + r) + s
    return s


class Sheet:
    def __init__(self, name, header, rows, widths=None, top=None, bold_top=False, top_nowrap=False):
        name = _BAD_NAME.sub("-", str(name)).strip("'")[:31] or "Sheet"
        self.name, self.header, self.rows = name, list(header), [list(r) for r in rows]
        self.widths, self.top, self.bold_top = widths, [list(r) for r in (top or [])], bold_top
        self.top_nowrap = top_nowrap      # True：表頭前面的說明列不換行（長句向右延伸，不把列撐高）


def _cell(ref, v, style):
    s = f' s="{style}"' if style else ""
    if v is None or v == "":
        return f'<c r="{ref}"{s}/>' if style else ""
    if isinstance(v, bool):
        v = "是" if v else "否"
    if isinstance(v, (int, float)) and math.isfinite(v):
        return f'<c r="{ref}"{s}><v>{v}</v></c>'
    t = _BAD.sub("", str(v))
    if len(t) > MAX_CELL:
        t = t[:MAX_CELL] + "…（截斷）"
    return f'<c r="{ref}"{s} t="inlineStr"><is><t xml:space="preserve">{escape(t)}</t></is></c>'


def _sheet_xml(sh):
    ncol = max([len(sh.header)] + [len(r) for r in sh.rows] + [len(r) for r in sh.top] + [1])
    hdr_row = len(sh.top) + 1
    last = hdr_row + len(sh.rows)
    out = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
           '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">',
           f'<dimension ref="A1:{col_name(ncol - 1)}{max(last, 1)}"/>',
           # 不凍結窗格：工作表上方有說明列時，凍結會把整塊說明固定住（使用者回報不對）
           '<sheetViews><sheetView workbookViewId="0"/></sheetViews>',
           '<sheetFormatPr defaultRowHeight="15"/>']
    if sh.widths:
        out.append("<cols>" + "".join(f'<col min="{i}" max="{i}" width="{w}" customWidth="1"/>' for i, w in enumerate(sh.widths, 1)) + "</cols>")
    out.append("<sheetData>")
    n = 0
    for r in sh.top:
        n += 1
        out.append(f'<row r="{n}">' + "".join(_cell(f"{col_name(i)}{n}", v, 1 if sh.bold_top else (0 if sh.top_nowrap else 2)) for i, v in enumerate(r)) + "</row>")
    n += 1
    out.append(f'<row r="{n}">' + "".join(_cell(f"{col_name(i)}{n}", v, 1) for i, v in enumerate(sh.header)) + "</row>")
    for r in sh.rows:
        n += 1
        out.append(f'<row r="{n}">' + "".join(_cell(f"{col_name(i)}{n}", v, 2) for i, v in enumerate(r)) + "</row>")
    out.append("</sheetData>")
    if sh.header:
        out.append(f'<autoFilter ref="A{hdr_row}:{col_name(len(sh.header) - 1)}{max(last, hdr_row)}"/>')
    out.append("</worksheet>")
    return "".join(out)


# ---------------------------------------------------------------- 自由版面（Canvas）：樣式、合併儲存格、列高、原生圖表

@dataclasses.dataclass(frozen=True)
class Style:
    """一格的樣式。color／fill 是 6 位十六進位 RGB（例如 "1F4E78"）；border="thin" 是細框線；numfmt 例如 "0.0%"。"""
    size: float = 11
    bold: bool = False
    italic: bool = False
    color: str = None
    name: str = "Arial"
    fill: str = None
    border: str = None
    h: str = None          # left／center／right
    v: str = None          # top／center／bottom
    wrap: bool = False
    numfmt: str = None


_RGB = re.compile(r"^[0-9A-Fa-f]{6}$")
_REF = re.compile(r"^([A-Z]{1,3})([0-9]{1,7})$")


def col_index(letters):
    n = 0
    for ch in letters:
        n = n * 26 + ord(ch) - 64
    return n - 1


def parse_ref(ref):
    """"B3" → (列 0 起算, 欄 0 起算)。"""
    m = _REF.match(ref)
    if not m or int(m.group(2)) < 1:
        raise ValueError(f"儲存格位置不對：{ref!r}")
    return int(m.group(2)) - 1, col_index(m.group(1))


def parse_range(rng):
    a, _, b = rng.partition(":")
    r1, c1 = parse_ref(a)
    r2, c2 = parse_ref(b or a)
    if r2 < r1 or c2 < c1:
        raise ValueError(f"範圍不對：{rng!r}")
    return r1, c1, r2, c2


class Chart:
    """原生圖表。kind＝"pie"｜"bar"（直條）；cats／vals 是同一個 Canvas 上的範圍（例如 "A9:A12"）；anchor＝左上角與右下角儲存格（"A20:D36"）。
    colors：每個資料點一個 RGB（可省略）。"""
    def __init__(self, kind, title, cats, vals, anchor, series="列數", colors=None, labels=True):
        if kind not in ("pie", "bar"):
            raise ValueError(f"圖表種類不支援：{kind}")
        for c in (colors or []):
            if not _RGB.match(c):
                raise ValueError(f"顏色不對：{c!r}")
        self.kind, self.title, self.cats, self.vals, self.anchor, self.series, self.colors = kind, title, cats, vals, anchor, series, list(colors or [])
        self.labels = labels      # False：不在圖上標數字（小扇形會疊在一起；數字改放圖例文字）


class Canvas:
    """自由版面的工作表：set 逐格放值與樣式，merge 合併，height 設列高，charts 放圖表。數值是靜態值（不是公式）。"""
    def __init__(self, name, widths=None, landscape=True):
        self.name = _BAD_NAME.sub("-", str(name)).strip("'")[:31] or "Sheet"
        self.cells, self.merges, self.heights, self.charts = {}, [], {}, []
        self.widths, self.landscape = list(widths or []), landscape

    def set(self, ref, value, style=None):
        self.cells[parse_ref(ref)] = (value, style)

    def merge(self, rng, style=None):
        """合併範圍；左上角的值與樣式（或 style）套到整個範圍（框線與底色才會完整）。"""
        r1, c1, r2, c2 = parse_range(rng)
        if (r1, c1) == (r2, c2):
            return
        for m in self.merges:
            if not (r2 < m[0] or r1 > m[2] or c2 < m[1] or c1 > m[3]):
                raise ValueError(f"合併範圍重疊：{rng}")
        self.merges.append((r1, c1, r2, c2))
        v, st = self.cells.get((r1, c1), ("", None))
        st = style or st
        self.cells[(r1, c1)] = (v, st)
        for r in range(r1, r2 + 1):
            for c in range(c1, c2 + 1):
                if (r, c) != (r1, c1):
                    self.cells[(r, c)] = ("", st)

    def height(self, row, pts):
        """row 為 1 起算的列號。"""
        self.heights[row - 1] = pts

    def add_chart(self, chart):
        self.charts.append(chart)

    def range_values(self, rng):
        r1, c1, r2, c2 = parse_range(rng)
        return [self.cells.get((r, c), ("", None))[0] for r in range(r1, r2 + 1) for c in range(c1, c2 + 1)]


class _Styles:
    """樣式登記：0～2 號沿用舊的三種格式（Sheet 用），其後依序加入。"""
    BASE_FONTS, BASE_FILLS, BASE_BORDERS, BASE_XFS = 2, 3, 1, 3

    def __init__(self):
        self.fonts, self.fills, self.borders, self.numfmts, self.xfs, self.ids = [], [], [], [], [], {}

    def _idx(self, lst, item, base):
        if item not in lst:
            lst.append(item)
        return base + lst.index(item)

    def get(self, st):
        if st is None:
            return 2
        if st in self.ids:
            return self.ids[st]
        for c in (st.color, st.fill):
            if c is not None and not _RGB.match(c):
                raise ValueError(f"顏色不對：{c!r}")
        font = ('<font>' + ('<b/>' if st.bold else '') + ('<i/>' if st.italic else '') + f'<sz val="{st.size}"/>'
                + (f'<color rgb="FF{st.color.upper()}"/>' if st.color else '') + f'<name val="{escape(st.name)}"/></font>')
        fid = self._idx(self.fonts, font, self.BASE_FONTS)
        fill = (f'<fill><patternFill patternType="solid"><fgColor rgb="FF{st.fill.upper()}"/><bgColor indexed="64"/></patternFill></fill>'
                if st.fill else None)
        flid = self._idx(self.fills, fill, self.BASE_FILLS) if fill else 0
        bd = ('<border><left style="thin"><color rgb="FFBFBFBF"/></left><right style="thin"><color rgb="FFBFBFBF"/></right>'
              '<top style="thin"><color rgb="FFBFBFBF"/></top><bottom style="thin"><color rgb="FFBFBFBF"/></bottom><diagonal/></border>'
              if st.border == "thin" else None)
        bid = self._idx(self.borders, bd, self.BASE_BORDERS) if bd else 0
        nid = 0
        if st.numfmt:
            nid = 164 + self._idx(self.numfmts, st.numfmt, 0)
        al = ""
        if st.h or st.v or st.wrap:
            al = ("<alignment" + (f' horizontal="{st.h}"' if st.h else "") + (f' vertical="{st.v}"' if st.v else "")
                  + (' wrapText="1"' if st.wrap else "") + "/>")
        xf = (f'<xf numFmtId="{nid}" fontId="{fid}" fillId="{flid}" borderId="{bid}" xfId="0" applyFont="1"'
              + (' applyFill="1"' if flid else "") + (' applyBorder="1"' if bid else "") + (' applyNumberFormat="1"' if nid else "")
              + (' applyAlignment="1">' + al + "</xf>" if al else "/>"))
        self.xfs.append(xf)
        self.ids[st] = self.BASE_XFS + len(self.xfs) - 1
        return self.ids[st]

    def xml(self):
        if not self.xfs:
            return STYLES
        nf = (f'<numFmts count="{len(self.numfmts)}">' + "".join(f'<numFmt numFmtId="{164 + i}" formatCode="{escape(c, {chr(34): "&quot;"})}"/>'
                                                                 for i, c in enumerate(self.numfmts)) + "</numFmts>") if self.numfmts else ""
        return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">' + nf
                + f'<fonts count="{2 + len(self.fonts)}"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font>'
                + "".join(self.fonts) + "</fonts>"
                + f'<fills count="{3 + len(self.fills)}"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill>'
                '<fill><patternFill patternType="solid"><fgColor rgb="FFDDEBF7"/><bgColor indexed="64"/></patternFill></fill>' + "".join(self.fills) + "</fills>"
                + f'<borders count="{1 + len(self.borders)}"><border><left/><right/><top/><bottom/><diagonal/></border>' + "".join(self.borders) + "</borders>"
                '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
                f'<cellXfs count="{3 + len(self.xfs)}">'
                '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
                '<xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1" applyAlignment="1">'
                '<alignment vertical="top" wrapText="1"/></xf>'
                '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>'
                + "".join(self.xfs) + '</cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>')


def _canvas_xml(cv, reg, drawing_rid=None):
    rows = {}
    for (r, c), (v, st) in cv.cells.items():
        rows.setdefault(r, {})[c] = _cell(f"{col_name(c)}{r + 1}", v, reg.get(st) if st is not None else 0)
    last_r = max(list(rows) + list(cv.heights) + [0])
    last_c = max([c for r in rows.values() for c in r] + [0])
    ns = 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
    if drawing_rid:
        ns += ' xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"'
    out = [f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<worksheet {ns}>']
    if cv.landscape:
        out.append('<sheetPr><pageSetUpPr fitToPage="1"/></sheetPr>')
    out += [f'<dimension ref="A1:{col_name(last_c)}{last_r + 1}"/>',
            '<sheetViews><sheetView showGridLines="0" workbookViewId="0"/></sheetViews>', '<sheetFormatPr defaultRowHeight="15"/>']
    if cv.widths:
        out.append("<cols>" + "".join(f'<col min="{i}" max="{i}" width="{w}" customWidth="1"/>' for i, w in enumerate(cv.widths, 1)) + "</cols>")
    out.append("<sheetData>")
    for r in range(last_r + 1):
        ht = f' ht="{cv.heights[r]}" customHeight="1"' if r in cv.heights else ""
        out.append(f'<row r="{r + 1}"{ht}>' + "".join(rows.get(r, {})[c] for c in sorted(rows.get(r, {}))) + "</row>")
    out.append("</sheetData>")
    if cv.merges:
        out.append(f'<mergeCells count="{len(cv.merges)}">' + "".join(
            f'<mergeCell ref="{col_name(c1)}{r1 + 1}:{col_name(c2)}{r2 + 1}"/>' for r1, c1, r2, c2 in cv.merges) + "</mergeCells>")
    out.append('<pageMargins left="0.4" right="0.4" top="0.5" bottom="0.5" header="0.3" footer="0.3"/>')
    if cv.landscape:
        out.append('<pageSetup paperSize="9" orientation="landscape" fitToWidth="1" fitToHeight="0"/>')
    if drawing_rid:
        out.append(f'<drawing r:id="{drawing_rid}"/>')
    out.append("</worksheet>")
    return "".join(out)


C_NS = ('xmlns:c="http://schemas.openxmlformats.org/drawingml/2006/chart" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"')


def _abs_ref(sheet, rng):
    r1, c1, r2, c2 = parse_range(rng)
    a = f"${col_name(c1)}${r1 + 1}"
    b = f"${col_name(c2)}${r2 + 1}"
    nm = sheet.replace("'", "''")
    return f"'{nm}'!{a}" + (f":{b}" if (r1, c1) != (r2, c2) else "")


def _chart_xml(cv, ch):
    cats, vals = cv.range_values(ch.cats), cv.range_values(ch.vals)
    if not cats or len(cats) != len(vals):
        raise ValueError(f"圖表 {ch.title}：分類與數值的格數不同（{len(cats)} vs {len(vals)}）")
    if any(not isinstance(v, (int, float)) or isinstance(v, bool) for v in vals):
        raise ValueError(f"圖表 {ch.title}：數值範圍 {ch.vals} 有不是數字的格子")
    if any(v in ("", None) for v in cats):
        raise ValueError(f"圖表 {ch.title}：分類範圍 {ch.cats} 有空白格")
    cat = (f'<c:cat><c:strRef><c:f>{escape(_abs_ref(cv.name, ch.cats))}</c:f><c:strCache><c:ptCount val="{len(cats)}"/>'
           + "".join(f'<c:pt idx="{i}"><c:v>{escape(_BAD.sub("", str(v)))}</c:v></c:pt>' for i, v in enumerate(cats)) + "</c:strCache></c:strRef></c:cat>")
    val = (f'<c:val><c:numRef><c:f>{escape(_abs_ref(cv.name, ch.vals))}</c:f><c:numCache><c:formatCode>General</c:formatCode>'
           f'<c:ptCount val="{len(vals)}"/>' + "".join(f'<c:pt idx="{i}"><c:v>{v}</c:v></c:pt>' for i, v in enumerate(vals)) + "</c:numCache></c:numRef></c:val>")
    sp = lambda col: f'<c:spPr><a:solidFill><a:srgbClr val="{col.upper()}"/></a:solidFill><a:ln w="9525"><a:solidFill><a:srgbClr val="7F7F7F"/></a:solidFill></a:ln></c:spPr>'
    dpts = "".join(f'<c:dPt><c:idx val="{i}"/>' + ('<c:invertIfNegative val="0"/>' if ch.kind == "bar" else "") + f'<c:bubble3D val="0"/>{sp(col)}</c:dPt>'
                   for i, col in enumerate(ch.colors[:len(vals)]))
    lbl = ('<c:dLbls>' + ('<c:dLblPos val="outEnd"/>' if ch.kind == "bar" else '') + '<c:showLegendKey val="0"/><c:showVal val="1"/><c:showCatName val="0"/>'
           '<c:showSerName val="0"/><c:showPercent val="0"/><c:showBubbleSize val="0"/>' + ('<c:showLeaderLines val="1"/>' if ch.kind == "pie" else '') + '</c:dLbls>')
    lbl = lbl if ch.labels else ''
    ser = (f'<c:ser><c:idx val="0"/><c:order val="0"/><c:tx><c:v>{escape(ch.series)}</c:v></c:tx>'
           + ('<c:invertIfNegative val="0"/>' if ch.kind == "bar" else "") + dpts + lbl + cat + val + "</c:ser>")
    if ch.kind == "pie":
        plot = f'<c:pieChart><c:varyColors val="1"/>{ser}<c:firstSliceAng val="0"/></c:pieChart>'
    else:
        plot = (f'<c:barChart><c:barDir val="col"/><c:grouping val="clustered"/><c:varyColors val="0"/>{ser}<c:gapWidth val="80"/>'
                '<c:axId val="111111"/><c:axId val="222222"/></c:barChart>'
                '<c:catAx><c:axId val="111111"/><c:scaling><c:orientation val="minMax"/></c:scaling><c:delete val="0"/><c:axPos val="b"/>'
                '<c:majorTickMark val="none"/><c:minorTickMark val="none"/><c:tickLblPos val="nextTo"/><c:crossAx val="222222"/><c:crosses val="autoZero"/>'
                '<c:auto val="1"/><c:lblAlgn val="ctr"/><c:lblOffset val="100"/><c:noMultiLvlLbl val="0"/></c:catAx>'
                '<c:valAx><c:axId val="222222"/><c:scaling><c:orientation val="minMax"/></c:scaling><c:delete val="0"/><c:axPos val="l"/>'
                '<c:majorGridlines><c:spPr><a:ln w="6350"><a:solidFill><a:srgbClr val="D9D9D9"/></a:solidFill></a:ln></c:spPr></c:majorGridlines>'
                '<c:numFmt formatCode="General" sourceLinked="0"/><c:majorTickMark val="none"/><c:minorTickMark val="none"/><c:tickLblPos val="nextTo"/>'
                '<c:crossAx val="111111"/><c:crosses val="autoZero"/><c:crossBetween val="between"/></c:valAx>')
    title = ('<c:title><c:tx><c:rich><a:bodyPr/><a:p><a:pPr><a:defRPr sz="1200" b="1"/></a:pPr><a:r><a:rPr lang="zh-TW" sz="1200" b="1"/>'
             f'<a:t>{escape(_BAD.sub("", ch.title))}</a:t></a:r></a:p></c:rich></c:tx><c:overlay val="0"/></c:title>')
    legend = '<c:legend><c:legendPos val="r"/><c:overlay val="0"/></c:legend>' if ch.kind == "pie" else ""
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            f'<c:chartSpace {C_NS}><c:roundedCorners val="0"/><c:chart>{title}<c:autoTitleDeleted val="0"/><c:plotArea><c:layout/>{plot}</c:plotArea>'
            f'{legend}<c:plotVisOnly val="1"/><c:dispBlanksAs val="gap"/></c:chart></c:chartSpace>')


def _drawing_xml(cv, first_rid=1):
    out = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
           '<xdr:wsDr xmlns:xdr="http://schemas.openxmlformats.org/drawingml/2006/spreadsheetDrawing" '
           'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">']
    for i, ch in enumerate(cv.charts, 1):
        r1, c1, r2, c2 = parse_range(ch.anchor)
        out.append(f'<xdr:twoCellAnchor><xdr:from><xdr:col>{c1}</xdr:col><xdr:colOff>38100</xdr:colOff><xdr:row>{r1}</xdr:row><xdr:rowOff>38100</xdr:rowOff></xdr:from>'
                   f'<xdr:to><xdr:col>{c2 + 1}</xdr:col><xdr:colOff>0</xdr:colOff><xdr:row>{r2 + 1}</xdr:row><xdr:rowOff>0</xdr:rowOff></xdr:to>'
                   f'<xdr:graphicFrame macro=""><xdr:nvGraphicFramePr><xdr:cNvPr id="{i + 1}" name="Chart {i}"/><xdr:cNvGraphicFramePr/></xdr:nvGraphicFramePr>'
                   '<xdr:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/></xdr:xfrm><a:graphic>'
                   '<a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/chart">'
                   '<c:chart xmlns:c="http://schemas.openxmlformats.org/drawingml/2006/chart" '
                   f'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" r:id="rId{first_rid + i - 1}"/>'
                   '</a:graphicData></a:graphic></xdr:graphicFrame><xdr:clientData/></xdr:twoCellAnchor>')
    out.append("</xdr:wsDr>")
    return "".join(out)


STYLES = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
          '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
          '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts>'
          '<fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill>'
          '<fill><patternFill patternType="solid"><fgColor rgb="FFDDEBF7"/><bgColor indexed="64"/></patternFill></fill></fills>'
          '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
          '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
          '<cellXfs count="3">'
          '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
          '<xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1" applyAlignment="1">'
          '<alignment vertical="top" wrapText="1"/></xf>'
          '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>'
          '</cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>')


def write_xlsx(path, sheets):
    if not sheets:
        raise ValueError("至少要有一個工作表")
    names = [s.name for s in sheets]
    reg = _Styles()
    extra = {}                      # 檔名 → 內容（Canvas 的工作表、圖表、drawing 與關聯）
    ct_extra = []
    nchart = ndraw = 0
    sheet_xml = {}
    for i, s in enumerate(sheets, 1):
        if not isinstance(s, Canvas):
            continue
        rid = None
        if s.charts:
            ndraw += 1
            rid = "rId1"
            rels = []
            for k, ch in enumerate(s.charts, 1):
                nchart += 1
                extra[f"xl/charts/chart{nchart}.xml"] = _chart_xml(s, ch)
                ct_extra.append(f'<Override PartName="/xl/charts/chart{nchart}.xml" ContentType="application/vnd.openxmlformats-officedocument.drawingml.chart+xml"/>')
                rels.append(f'<Relationship Id="rId{k}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/chart" Target="../charts/chart{nchart}.xml"/>')
            extra[f"xl/drawings/drawing{ndraw}.xml"] = _drawing_xml(s)
            extra[f"xl/drawings/_rels/drawing{ndraw}.xml.rels"] = (
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                + "".join(rels) + "</Relationships>")
            ct_extra.append(f'<Override PartName="/xl/drawings/drawing{ndraw}.xml" ContentType="application/vnd.openxmlformats-officedocument.drawing+xml"/>')
            extra[f"xl/worksheets/_rels/sheet{i}.xml.rels"] = (
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                f'<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/drawing" Target="../drawings/drawing{ndraw}.xml"/>'
                "</Relationships>")
        sheet_xml[i] = _canvas_xml(s, reg, rid)
    if len({n.lower() for n in names}) != len(names):
        raise ValueError(f"工作表名稱重複：{names}")
    ct = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
          '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
          '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
          '<Default Extension="xml" ContentType="application/xml"/>'
          '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
          '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
          + "".join(f'<Override PartName="/xl/worksheets/sheet{i}.xml" '
                    'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' for i in range(1, len(sheets) + 1))
          + "".join(ct_extra) + "</Types>")
    rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
            'Target="xl/workbook.xml"/></Relationships>')
    wb = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
          '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
          'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>'
          + "".join(f'<sheet name="{escape(s.name, {chr(34): "&quot;"})}" sheetId="{i}" r:id="rId{i}"/>' for i, s in enumerate(sheets, 1))
          + "</sheets></workbook>")
    wbrels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
              '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
              + "".join(f'<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
                        f'Target="worksheets/sheet{i}.xml"/>' for i in range(1, len(sheets) + 1))
              + f'<Relationship Id="rId{len(sheets) + 1}" '
              'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>')
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", ct)
        z.writestr("_rels/.rels", rels)
        z.writestr("xl/workbook.xml", wb)
        z.writestr("xl/_rels/workbook.xml.rels", wbrels)
        z.writestr("xl/styles.xml", reg.xml())
        for i, s in enumerate(sheets, 1):
            z.writestr(f"xl/worksheets/sheet{i}.xml", sheet_xml[i] if i in sheet_xml else _sheet_xml(s))
        for fn, data in extra.items():
            z.writestr(fn, data)


def read_xlsx(path):
    """測試與核對用：讀回 {工作表名稱: [[儲存格文字或數字, …], …]}（只認這個寫入器寫的格式，不是通用讀取器）。"""
    import xml.etree.ElementTree as ET
    ns = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
          "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships"}
    with zipfile.ZipFile(path) as z:
        wb = ET.fromstring(z.read("xl/workbook.xml"))
        out = {}
        for i, sh in enumerate(wb.find("m:sheets", ns), 1):
            root = ET.fromstring(z.read(f"xl/worksheets/sheet{i}.xml"))
            rows = []
            for row in root.find("m:sheetData", ns):
                cells = {}
                for c in row:
                    ref = re.match(r"([A-Z]+)", c.get("r")).group(1)
                    idx = 0
                    for ch in ref:
                        idx = idx * 26 + ord(ch) - 64
                    t = c.find("m:is/m:t", ns)
                    v = c.find("m:v", ns)
                    cells[idx - 1] = t.text or "" if t is not None else (float(v.text) if v is not None else "")
                rows.append([cells.get(k, "") for k in range(max(cells) + 1)] if cells else [])
            out[sh.get("name")] = rows
        return out
