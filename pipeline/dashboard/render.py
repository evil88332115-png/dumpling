#!/usr/bin/env python3
"""render.py：data dict → HTML 字串（純函式，不連網、不讀檔、不讀環境變數）。docs/DASHBOARD.md 第 3、4 節。

安全規則（頁面的所有文字都當外來資料；沒有 JS）：
  - 每個字串都經過集中的 esc()：先去控制字元（含雙向控制字元）、再截斷、最後 html.escape(quote=True)。
  - 外來的自由文字（Issue 標題、notes、detail、說明、tag、附件名、元件名…）一律用 ext() 包成 <span class="ext">…</span>；
    check_site.py 對 ext 以外的文字檢查「安全」「PASS」，ext 內是原文照錄。
  - href 只能由 safe_href(url, repo) 產生：本 repo 的 releases/download、issues/<數字>、actions/runs/<數字>，
    以及本站的 style.css、data.json、頁內 #錨點。其他網址只顯示文字。
  - 狀態值只認 OK／GAP／ATTENTION／NOT_RUN／NOT_ASSESSED／FAIL；其他顯示「不明（原值）」並列入頁首警告。
  - 不輸出任何使用者可控的標籤名或屬性名（class 名稱只來自固定清單）。
  - 不顯示整體結論（不寫「安全」、整體 PASS、勾勾）：只照原值列狀態。漏洞數一律和該報告的 report_status／release_gate 寫在同一格。
GitLab 搬移時，這一層與平台無關，只有 safe_href／連結組裝（BASE）要換成內部 GitLab 的網址前綴。
"""
import html
import re
import urllib.parse

STATUSES = ("OK", "GAP", "ATTENTION", "NOT_RUN", "NOT_ASSESSED", "FAIL")
LIFECYCLES = ("development", "shipped")
CSP = "default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'"
BASE = "https://github.com/"
REPO_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}/[A-Za-z0-9._-]{1,100}\Z")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}\Z")
ASSET_RE = re.compile(r"^[A-Za-z0-9._+-]{1,200}\Z")
DOWNLOAD_SEG_RE = re.compile(r"^[A-Za-z0-9._~%+-]{1,300}\Z")
LOCAL_HREFS = ("style.css", "data.json")
ANCHOR_RE = re.compile(r"^#[a-z0-9-]{1,40}\Z")
CTRL_RE = re.compile("[\x00-\x1f\x7f-\x9f​-‏ -‮⁠-⁩﻿]")
DEFAULT_LEN = 200
# 另外拿掉的不可見字元：U+061C（ALM）、U+00AD、U+034F、U+180E、tag 字元 U+E0000–E007F（預驗建議 5）
INVISIBLE_RE = re.compile("[\u061c\u00ad\u034f\u180e\U000e0000-\U000e007f]")


def _to_str(v):
    try:
        return str(v)
    except ValueError:          # 超過 Python 的整數轉字串上限（4300 位）：不讓 build 當掉
        return "（數值過大）"

REPORTS = ("full", "bsp", "os")
STATUS_HELP = (
    ("OK", "這一項有跑、資料齊"),
    ("GAP", "資料缺或沒跑完整；缺什麼寫在旁邊"),
    ("ATTENTION", "需要人去看"),
    ("NOT_RUN", "沒有執行（原因寫在旁邊）"),
    ("NOT_ASSESSED", "還沒有評估"),
    ("FAIL", "執行失敗"),
)


# ---------------------------------------------------------------- 跳脫與連結

def clean(s, n=DEFAULT_LEN):
    """去控制字元（換行、tab 也換成空白）、不可見與雙向控制字元、孤立的 surrogate，再截斷。不是字串的值先轉成字串。"""
    s = s if isinstance(s, str) else _to_str(s)
    s = s.encode("utf-8", "replace").decode("utf-8")          # 孤立 surrogate → ?（寫檔不會 UnicodeEncodeError 卡住部署；預驗建議 4）
    s = CTRL_RE.sub(" ", s)
    s = INVISIBLE_RE.sub("", s)
    return s if len(s) <= n else s[:n] + "…"


def esc(s, n=DEFAULT_LEN):
    """所有字串輸出的唯一出口：去控制字元 → 截斷 → html.escape(quote=True)。"""
    return html.escape(clean(s, n), quote=True)


def ext(s, n=DEFAULT_LEN):
    """外來的自由文字（原文照錄）。"""
    return '<span class="ext">%s</span>' % esc(s, n)


def valid_repo(repo):
    return isinstance(repo, str) and bool(REPO_RE.match(repo)) and not any(p in (".", "..") for p in repo.split("/"))


def safe_href(url, repo):
    """回可以放進 href 的字串，或 None（不出連結）。只允許：
    本 repo 的 releases/download/<tag>/<附件>、issues/<數字>、actions/runs/<數字>；本站的 style.css、data.json、#錨點。"""
    if not isinstance(url, str) or len(url) > 700 or not valid_repo(repo):
        return None
    if url in LOCAL_HREFS or ANCHOR_RE.match(url):
        return url
    base = BASE + repo + "/"
    if not url.startswith(base):
        return None
    rest = url[len(base):]
    if re.fullmatch(r"issues/[0-9]{1,9}", rest) or re.fullmatch(r"actions/runs/[0-9]{1,19}", rest):
        return url
    if rest.startswith("releases/download/"):
        segs = rest[len("releases/download/"):].split("/")
        if len(segs) < 2 or not all(DOWNLOAD_SEG_RE.match(s) for s in segs):
            return None
        for s in segs:
            d = urllib.parse.unquote(s)
            if d in (".", "..") or re.search(r"[\x00-\x1f\x7f/\\]", d):
                return None
        return url
    return None


def asset_url(repo, tag, name):
    """附件下載網址（自己組，不用 API 回的網址）。名稱不合規則回 None。"""
    if not (isinstance(tag, str) and isinstance(name, str) and ASSET_RE.match(name) and valid_repo(repo)):
        return None
    return "%s%s/releases/download/%s/%s" % (BASE, repo, urllib.parse.quote(tag), urllib.parse.quote(name))


def issue_url(repo, number):
    if isinstance(number, int) and not isinstance(number, bool) and 0 < number < 10 ** 9 and valid_repo(repo):
        return "%s%s/issues/%d" % (BASE, repo, number)
    return None


def run_url(repo, run_id):
    rid = str(run_id) if isinstance(run_id, (int, str)) and not isinstance(run_id, bool) else ""
    if re.fullmatch(r"[0-9]{1,19}", rid) and valid_repo(repo):
        return "%s%s/actions/runs/%s" % (BASE, repo, rid)
    return None


class Ctx:
    """一次渲染的狀態：repo、不認得的狀態值（頁首警告用）。"""

    def __init__(self, repo):
        self.repo = repo
        self.unknown = []

    def a(self, url, inner_html):
        """inner_html 必須是已經跳脫過的 HTML。url 不在白名單就只回文字。"""
        h = safe_href(url, self.repo)
        if h is None:
            return inner_html
        rel = ' rel="noopener noreferrer"' if h.startswith("https://") else ""
        return '<a href="%s"%s>%s</a>' % (esc(h, 800), rel, inner_html)

    def st(self, v):
        """狀態值徽章。只認固定清單；其他（含缺少）顯示「不明（原值）」，並列入頁首警告。"""
        if isinstance(v, str) and v in STATUSES:
            return '<span class="st st-%s">%s</span>' % (v, v)
        raw = "無值" if v is None else clean(v, 60)
        if raw not in self.unknown and len(self.unknown) < 20:
            self.unknown.append(raw)
        return '<span class="st st-unknown">不明（%s）</span>' % ext(raw, 60)

    def life(self, v):
        if isinstance(v, str) and v in LIFECYCLES:
            return '<span class="st st-life">%s</span>' % v
        raw = "無值" if v is None else clean(v, 60)
        if raw not in self.unknown and len(self.unknown) < 20:
            self.unknown.append(raw)
        return '<span class="st st-unknown">不明（%s）</span>' % ext(raw, 60)

    def gap(self, reason):
        return '<span class="st st-GAP">GAP</span>（%s）' % ext(reason, 300)


def num(v):
    return str(v) if isinstance(v, int) and not isinstance(v, bool) else "—"


def size_text(n):
    if not isinstance(n, int) or isinstance(n, bool) or n < 0:
        return "大小不明"
    for unit, k in (("GiB", 1 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10)):
        if n >= k:
            return "%.1f %s" % (n / k, unit)
    return "%d B" % n


def cve_text(s):
    """CVE 編號通過 ^CVE-\\d{4}-\\d{4,}$ 才當識別字；不合格照文字跳脫顯示。"""
    if isinstance(s, str) and CVE_RE.match(s):
        return '<span class="cve">%s</span>' % esc(s, 40)
    return ext(s, 80)


def table(headers, rows, caption=None):
    """rows 的每格都是已經跳脫過的 HTML。寬表放在可橫向捲動的容器裡。"""
    out = ['<div class="scroll" role="region" tabindex="0" aria-label="%s">' % esc(caption or "表格", 80), "<table>"]
    out.append("<thead><tr>%s</tr></thead>" % "".join("<th scope=\"col\">%s</th>" % esc(h, 80) for h in headers))
    out.append("<tbody>")
    for r in rows:
        out.append("<tr>%s</tr>" % "".join("<td>%s</td>" % c for c in r))
    out.append("</tbody></table></div>")
    return "\n".join(out)


def section_gap(ctx, sec, what):
    """區塊資料不是 dict（或帶 gap）→ GAP 一行。回 None 表示資料可用。"""
    if not isinstance(sec, dict):
        return "<p>%s</p>" % ctx.gap("%s：沒有資料" % what)
    if sec.get("gap"):
        return "<p>%s</p>" % ctx.gap(sec["gap"])
    return None


def lst(v):
    return v if isinstance(v, list) else []


def dct(v):
    return v if isinstance(v, dict) else {}


# ---------------------------------------------------------------- 專案（A）

def fresh_html(ctx, data):
    """最近一輪監控的時間與狀態（數字旁邊用）。超過 36 小時沒更新 → 「監控資料過期」；讀不到 → GAP。"""
    f = dct(dct(data.get("watch")).get("freshness"))
    if not f.get("at"):
        return ctx.gap("沒有最近一輪監控資料")
    out = "最近一輪監控 %s %s" % (ext(f.get("at"), 40), ctx.st(f.get("status")))
    if f.get("stale") is True:
        out += ' <span class="st st-GAP">監控資料過期</span>'
    elif f.get("stale") is None:
        out += " " + ctx.gap("監控時間讀不出來")
    return out


def render_projects(ctx, data):
    sec = dct(data.get("projects"))
    g = section_gap(ctx, data.get("projects"), "專案清單")
    if g:
        return g
    rows = []
    for p in lst(sec.get("rows")):
        p = dct(p)
        if p.get("error"):
            rows.append(["%s（%s）" % (ext(p.get("product_name") or p.get("key")), ext(p.get("key"))), ctx.gap(p["error"]),
                         "—", "—", "—", "—", "—"])
            continue
        su = p.get("support_until")
        days = p.get("days_left")
        sup = ext(su, 40) if su else "—"
        if isinstance(days, int) and not isinstance(days, bool):
            sup += "（剩 %d 天）" % days if days >= 0 else "（已過期 %d 天）" % -days
        chk = p.get("support_check")
        if isinstance(chk, dict):
            chk_html = ctx.st(chk.get("status")) + " " + ext(chk.get("detail"), 300)
        else:
            chk_html = ctx.gap("支援期限檢查結果沒有資料")
        rows.append(["%s<br><span class=\"muted\">%s</span>" % (ext(p.get("product_name")), ext(p.get("key"))),
                     ctx.life(p.get("status")), sup, chk_html,
                     ext(p.get("latest_release")) if p.get("latest_release") else "—",
                     ext(p.get("dev_release")) if p.get("dev_release") else "—",
                     '%s<br><span class="muted">%s</span>' % (num(p.get("open_issues")), fresh_html(ctx, data))])
    if not rows:
        return "<p>%s</p>" % ctx.gap("沒有任何專案")
    return table(["產品名（專案鍵）", "專案狀態", "支援期限", "支援期限檢查", "最新正式版", "開發版", "開著的監控 Issue（標題含專案名）"],
                 rows, "專案")


# ---------------------------------------------------------------- 版本（B）

def render_downloads(ctx, rel):
    items = []
    for d in lst(rel.get("downloads")):
        d = dct(d)
        name = d.get("name")
        url = asset_url(ctx.repo, rel.get("tag"), name)
        label = ext(name, 220)
        items.append("<li>%s <span class=\"muted\">%s</span></li>" % (ctx.a(url, label) if url else label, esc(size_text(d.get("size")))))
    if not items:
        return "<p>%s</p>" % ctx.gap("沒有可列出的附件")
    return "<ul class=\"dl\">%s</ul>" % "".join(items)


def render_status_table(ctx, rel):
    meta = dct(rel.get("meta"))
    scan = dct(rel.get("scan"))
    sreports = dct(scan.get("reports")) if not scan.get("gap") else {}
    if meta.get("gap"):
        return "<p>%s</p>" % ctx.gap("release-meta：" + str(meta["gap"]))
    rows = []
    for r in lst(meta.get("reports")):
        r = dct(r)
        s = dct(sreports.get(r.get("report")))
        rows.append([ext(r.get("report"), 20), ctx.st(r.get("report_status")), ctx.st(r.get("release_gate")),
                     ctx.st(s.get("build_record_status")) if s.get("build_record_status") is not None else "—",
                     ctx.st(s.get("upstream_source_status")) if s.get("upstream_source_status") is not None else "—"])
    out = []
    out.append("<p>release-meta 整體：report_status %s、release_gate %s、pipeline_result %s</p>" % (
        ctx.st(meta.get("report_status")), ctx.st(meta.get("release_gate")), ctx.st(meta.get("pipeline_result"))))
    if rows:
        out.append(table(["報告", "report_status", "release_gate", "建置紀錄", "上游原始碼"], rows, "各報告的狀態"))
    else:
        out.append("<p>%s</p>" % ctx.gap("release-meta 沒有各報告的狀態"))
    att = [x for x in lst(meta.get("attention")) if isinstance(x, str)]
    if att:
        out.append("<ul class=\"notes\">%s</ul>" % "".join("<li>ATTENTION：%s</li>" % ext(x, 300) for x in att[:10]))
    return "\n".join(out)


def render_stages(ctx, rel):
    """scan-summary 裡不是 OK 的階段，逐一列出原值（階段 × 報告）。"""
    scan = dct(rel.get("scan"))
    if scan.get("gap"):
        return "<p>%s</p>" % ctx.gap("scan-summary：" + str(scan["gap"]))
    reports = dct(scan.get("reports"))
    names = [n for n in REPORTS if n in reports] + [n for n in reports if n not in REPORTS]
    stages = {}
    for n in names:
        for s, v in lst(dct(reports.get(n)).get("non_ok_stages")):
            stages.setdefault(s, {})[n] = v
    if not stages:
        return "<p>每份報告的階段都是 OK（只表示有跑完，不是對產品的保證）。</p>"
    rows = []
    for s in sorted(stages):
        rows.append([ext(s, 60)] + [ctx.st(stages[s][n]) if n in stages[s] else "—" for n in names])
    return table(["階段（只列不是 OK 的）"] + [clean(n, 20) for n in names], rows, "不是 OK 的階段")


def render_vulns(ctx, rel):
    """漏洞統計：數字一律和該報告的 report_status、release_gate 寫在同一格，不單獨顯示。"""
    scan = dct(rel.get("scan"))
    if scan.get("gap"):
        return "<p>%s</p>" % ctx.gap("scan-summary：" + str(scan["gap"]))
    reports = dct(scan.get("reports"))
    rows = []
    for n in [x for x in REPORTS if x in reports] + [x for x in reports if x not in REPORTS]:
        r = dct(reports[n])
        t = dct(r.get("tiers"))
        counts = "、".join("%s %s" % (k, num(t.get(k))) for k in ("p1", "p2", "p3", "accepted", "nvidia_bulletin") if k in t)
        cell = ('<div class="vcell"><div class="vstat">report_status %s／release_gate %s</div>'
                '<div class="vnum">%s；CVE 總數 %s</div></div>') % (
            ctx.st(r.get("report_status")), ctx.st(r.get("release_gate")), esc(counts or "沒有分級計數", 200), num(r.get("cves_total")))
        rows.append([ext(n, 20), cell])
    if not rows:
        return "<p>%s</p>" % ctx.gap("scan-summary 沒有漏洞統計")
    comp = dct(scan.get("components"))
    extra = ""
    if comp:
        extra = "<p class=\"muted\">元件數：%s</p>" % esc("、".join("%s %s" % (k, num(comp.get(k)))
                                                              for k in ("total", "bsp", "os", "unknown") if k in comp))
    return table(["報告", "漏洞統計（含該報告的狀態）"], rows, "漏洞統計") + extra


def render_vex(ctx, rel):
    vex = dct(rel.get("vex"))
    rows = []
    for n in REPORTS:
        v = vex.get(n)
        if not isinstance(v, dict):
            rows.append([ext(n, 20), ctx.gap("沒有資料"), "", ""])
            continue
        if v.get("gap"):
            rows.append([ext(n, 20), ctx.gap(v["gap"]), "", ""])
            continue
        cs = lst(v.get("counts"))
        g = gate_of(ctx, rel, n)
        if not cs:
            rows.append([ext(n, 20), "—", "—", "0（vulnerabilities 是空的）", g])
        for c in cs:
            if isinstance(c, (list, tuple)) and len(c) == 3:
                rows.append([ext(n, 20), ext(c[0], 40), ext(c[1], 40), num(c[2]), g])
    return table(["報告", "analysis.state", "justification", "數量", "該報告的 release_gate（vex.gate 結論）"], rows, "VEX 判定統計")


def gate_of(ctx, rel, report):
    """release-meta 裡這份報告的 release_gate（VEX 判定的數量旁邊要附上 vex.gate 的結論；C0 決定）。"""
    meta = dct(rel.get("meta"))
    if meta.get("gap"):
        return ctx.gap("release-meta：" + str(meta["gap"]))
    for r in lst(meta.get("reports")):
        r = dct(r)
        if r.get("report") == report:
            return ctx.st(r.get("release_gate"))
    return ctx.gap("release-meta 沒有這份報告的 release_gate")


def render_release(ctx, rel, i):
    rel = dct(rel)
    meta = dct(rel.get("meta"))
    kind = "正式版" if rel.get("kind") == "release" else "開發版" if rel.get("kind") == "dev" else "未分類"
    head = '<h3 id="rel-%d">%s <span class="kind">%s</span></h3>' % (i, ext(rel.get("tag"), 120), esc(kind))
    dl = []
    dl.append("<dt>發布時間</dt><dd>%s</dd>" % ext(rel.get("published_at"), 40))
    if isinstance(rel.get("prerelease"), bool):
        dl.append("<dt>prerelease</dt><dd>%s</dd>" % ("true" if rel["prerelease"] else "false"))
    if not meta.get("gap"):
        dl.append("<dt>release-meta status</dt><dd>%s</dd>" % ctx.life(meta.get("status")))
        dl.append("<dt>平台</dt><dd>%s</dd>" % ext(meta.get("platform"), 40))
        dl.append("<dt>commit</dt><dd>%s</dd>" % ext(str(meta.get("commit") or "")[:12], 12))
        dl.append("<dt>建置時間</dt><dd>%s</dd>" % ext(meta.get("built_at"), 40))
        wr = meta.get("workflow_run")
        link = run_url(ctx.repo, wr)
        dl.append("<dt>建置 run</dt><dd>%s</dd>" % (ctx.a(link, "run " + esc(wr, 20)) if link else ext(wr, 40)))
    parts = [head, '<dl class="kv">%s</dl>' % "".join(dl),
             "<h4>狀態</h4>", render_status_table(ctx, rel),
             "<h4>不是 OK 的階段</h4>", render_stages(ctx, rel),
             "<h4>漏洞統計</h4>", render_vulns(ctx, rel),
             "<h4>VEX 判定統計</h4>", render_vex(ctx, rel),
             "<h4>下載</h4>", render_downloads(ctx, rel)]
    for p in lst(rel.get("problems")):
        parts.append("<p>%s</p>" % ctx.gap(p))
    return '<article class="release">%s</article>' % "\n".join(parts)


def render_releases(ctx, data):
    sec = dct(data.get("releases"))
    g = section_gap(ctx, data.get("releases"), "Release 清單")
    if g:
        return g
    out = []
    rows = lst(sec.get("rows"))
    if not rows:
        out.append("<p>%s</p>" % ctx.gap("沒有已發布的 Release"))
    for i, r in enumerate(rows):
        out.append(render_release(ctx, r, i))
    skipped = lst(sec.get("skipped"))
    if skipped:
        items = "".join("<li>%s：%s</li>" % (ext(dct(s).get("tag"), 100), ext(dct(s).get("why"), 200)) for s in skipped[:50])
        out.append("<details><summary>已發布但不列入的 Release（%d）</summary><ul>%s</ul></details>" % (len(skipped), items))
    return "\n".join(out)


# ---------------------------------------------------------------- 每日監控（C）

def render_issue_rows(ctx, rows, with_cve):
    out = []
    for i in rows:
        i = dct(i)
        n = i.get("number")
        url = issue_url(ctx.repo, n)
        num_html = ctx.a(url, "#%s" % esc(n, 12)) if url else ext(n, 12)
        cells = [num_html]
        if with_cve:
            m = re.search(r"CVE-[0-9]{4}-[0-9]{4,}", str(i.get("title") or ""))
            cells.append(cve_text(m.group(0)) if m else "—")
        cells += [ext(i.get("title"), 300), esc(i.get("state") if i.get("state") in ("open", "closed") else "?", 10),
                  ext(i.get("created_at"), 40), " ".join(ext(x, 40) for x in lst(i.get("labels"))[:8])]
        out.append(cells)
    return out


def render_issue_group(ctx, data, key, title, with_cve=False):
    sec = dct(dct(data.get("issues")).get(key))
    head = "<h4>%s</h4>" % esc(title)
    if not sec or sec.get("gap"):
        return head + "<p>%s</p>" % ctx.gap(sec.get("gap") if sec else "沒有資料")
    rows = lst(sec.get("rows"))
    opened = [r for r in rows if dct(r).get("state") == "open"]
    closed = [r for r in rows if dct(r).get("state") != "open"]
    headers = ["編號"] + (["CVE"] if with_cve else []) + ["標題", "開／關", "建立時間", "標籤"]
    out = [head]
    if opened:
        out.append(table(headers, render_issue_rows(ctx, opened, with_cve), title + "（開著）"))
    else:
        out.append("<p>目前沒有開著的 Issue（共列出 %d 個）。</p>" % len(rows))
    if key == "support":
        out.append("<p class=\"muted\">支援期限的 Issue 是否真的開出，取決於 repo 變數 WATCH_REAL_ISSUES；沒開時只有上方的檢查結果，沒有 Issue。</p>")
    if closed:
        out.append("<details><summary>已關閉（%d）</summary>%s</details>" % (
            len(closed), table(headers, render_issue_rows(ctx, closed, with_cve), title + "（已關閉）")))
    return "\n".join(out)


def render_state_issue(ctx, w, data=None):
    s = w.get("state_issue")
    if not isinstance(s, dict) or s.get("gap"):
        return "<p>%s</p>" % ctx.gap(dct(s).get("gap") or "找不到狀態 Issue")
    n = s.get("number")
    url = issue_url(ctx.repo, n)
    last = dct(s.get("last_run"))
    dl = ["<dt>狀態 Issue</dt><dd>%s（%s）</dd>" % (ctx.a(url, "#%s" % esc(n, 12)) if url else ext(n, 12),
                                                  esc(s.get("state") if s.get("state") in ("open", "closed") else "?", 10)),
          "<dt>基準時間</dt><dd>%s</dd>" % ext(s.get("baseline_at"), 40),
          "<dt>比對數</dt><dd>KEV %s、廠商層級 %s；%s</dd>" % (num(s.get("matches")), num(s.get("vendor_matches")),
                                                         fresh_html(ctx, data or {"watch": w}))]
    if last:
        rl = run_url(ctx.repo, last.get("run_id"))
        dl.append("<dt>狀態裡最後一輪</dt><dd>%s %s %s %s</dd>" % (
            ext(last.get("at"), 40), ctx.st(last.get("status")), ext(last.get("detail"), 300), ctx.a(rl, "run") if rl else ""))
    else:
        dl.append("<dt>狀態裡最後一輪</dt><dd>%s</dd>" % ctx.gap("狀態裡沒有 runs"))
    return '<dl class="kv">%s</dl>' % "".join(dl)


def render_per_sbom(ctx, plan):
    rows = []
    for r in lst(plan.get("per_sbom")):
        r = dct(r)
        # 已遭利用的命中數：和該 SBOM 的 grype、report_status、release_gate 同一格，不單獨顯示
        cell = ('<div class="vcell"><div class="vnum">%s</div><div class="vstat">grype %s／report_status %s／release_gate %s</div></div>') % (
            num(r.get("exploited")), ctx.st(r.get("grype")), ctx.st(r.get("report_status")), ctx.st(r.get("release_gate")))
        rows.append([ext(r.get("tag"), 100), ext(r.get("layer"), 20), ctx.st(r.get("kernel_map")) if r.get("kernel_map") else "—",
                     ctx.st(r.get("kernel_cna")) if r.get("kernel_cna") else "—", cell, ext(r.get("why"), 200) if r.get("why") else ""])
    if not rows:
        return "<p>%s</p>" % ctx.gap("沒有各 SBOM 的監控狀態")
    return table(["Release", "層", "核心對應 kernel_map", "核心 CNA", "已遭利用（KEV）命中數（含狀態）", "說明"], rows, "每份 SBOM 的監控狀態")


def render_watch(ctx, data):
    w = dct(data.get("watch"))
    out = []
    run = w.get("run")
    if isinstance(run, dict):
        link = run_url(ctx.repo, run.get("id"))
        out.append('<dl class="kv"><dt>最近一輪 watch run</dt><dd>%s</dd><dt>時間</dt><dd>%s</dd><dt>event／conclusion</dt><dd>%s／%s</dd></dl>' % (
            ctx.a(link, "run " + esc(run.get("id"), 20)) if link else ext(run.get("id"), 30),
            ext(run.get("created_at"), 40), ext(run.get("event"), 30), ext(run.get("conclusion"), 30)))
    else:
        out.append("<p>%s</p>" % ctx.gap(w.get("run_gap") or "找不到最近一輪 watch run"))
    plan = w.get("plan")
    if isinstance(plan, dict) and not plan.get("gap"):
        out.append("<p>每日比對結果：%s %s</p>" % (ctx.st(plan.get("status")), ext(plan.get("detail"), 400)))
        out.append(render_per_sbom(ctx, plan))
        for key, title in (("gaps", "GAP"), ("attention", "ATTENTION"), ("notes", "說明")):
            xs = [x for x in lst(plan.get(key)) if isinstance(x, str)]
            if xs:
                out.append("<details><summary>%s（%d）</summary><ul class=\"notes\">%s</ul></details>" % (
                    esc(title), len(xs), "".join("<li>%s</li>" % ext(x, 600) for x in xs[:50])))
    else:
        out.append("<p>%s</p>" % ctx.gap("每日比對結果（watch-plan result.json）：" + str(dct(plan).get("gap") or "沒有資料")))
    cov = w.get("coverage")
    if isinstance(cov, list) and cov:
        out.append("<h4>每日沒有涵蓋的項目</h4><ul class=\"notes\">%s</ul>" % "".join(
            "<li>%s</li>" % ext(x, 400) for x in cov[:30] if isinstance(x, str)))
    else:
        out.append("<h4>每日沒有涵蓋的項目</h4><p>%s</p>" % ctx.gap(w.get("coverage_gap") or "沒有資料"))
    out.append("<p>%s</p>" % ctx.gap("CISA KEV、EUVD、核心 CVE、Grype DB 逐項的狀態與時間：result.json 沒有這個欄位，第一版不列（權威來源是 watch run 的 summary）"))
    out.append("<h4>監控狀態 Issue</h4>")
    out.append(render_state_issue(ctx, w, data))
    sup = w.get("support")
    out.append("<h4>支援期限與 EOL（最近一輪）</h4>")
    if isinstance(sup, dict) and not sup.get("gap"):
        rows = []
        for r in lst(sup.get("rows")):
            if isinstance(r, (list, tuple)) and len(r) == 3:
                rows.append([ext(r[0], 100), ctx.st(r[1]), ext(r[2], 400)])
        out.append("<p>檢查結果：%s %s（檢查日 %s）</p>" % (ctx.st(sup.get("status")), ext(sup.get("detail"), 200), ext(sup.get("today"), 20)))
        out.append(table(["對象", "結果", "說明"], rows, "支援期限檢查") if rows else "<p>%s</p>" % ctx.gap("沒有列"))
    else:
        out.append("<p>%s</p>" % ctx.gap("watch-support result.json：" + str(dct(sup).get("gap") or "沒有資料")))
    out.append(render_issue_group(ctx, data, "kev", "KEV／廠商層級（dumpling-watch）", with_cve=True))
    out.append(render_issue_group(ctx, data, "support", "支援期限（support-period）"))
    out.append(render_issue_group(ctx, data, "health", "監控健康（watch-health）"))
    return "\n".join(out)


# ---------------------------------------------------------------- 整頁

def render_header(ctx, data):
    gen = ext(data.get("generated_at"), 40)
    commit = data.get("commit")
    w = dct(data.get("watch"))
    run = w.get("run")
    run_html = "—"
    if isinstance(run, dict):
        link = run_url(ctx.repo, run.get("id"))
        run_html = "%s（%s）" % (ctx.a(link, "run " + esc(run.get("id"), 20)) if link else ext(run.get("id"), 30), ext(run.get("created_at"), 40))
    st = dct(w.get("state_issue"))
    sl = issue_url(ctx.repo, st.get("number"))
    st_html = (ctx.a(sl, "#%s" % esc(st.get("number"), 12)) if sl else "—")
    warns = ["<li>%s</li>" % ext(x, 300) for x in lst(data.get("warnings")) if isinstance(x, str)][:30]
    if ctx.unknown:
        warns.append("<li>%s：%s</li>" % (esc("狀態值不認得"), "、".join(ext(x, 60) for x in ctx.unknown)))
    legend = "".join("<dt>%s</dt><dd>%s</dd>" % (ctx.st(k), esc(v)) for k, v in STATUS_HELP)
    parts = ['<header>', "<h1>dumpling 供應鏈狀態儀表板</h1>",
             "<p class=\"lead\">狀態只說明有沒有跑、資料齊不齊，不是對產品的保證。</p>",
             '<dl class="kv"><dt>產生時間（UTC）</dt><dd>%s</dd><dt>產生用的 commit</dt><dd>%s</dd>'
             "<dt>監控資料</dt><dd>%s</dd><dt>狀態 Issue</dt><dd>%s</dd></dl>" % (
                 gen, ext(str(commit)[:12], 12) if commit else "—", run_html, st_html)]
    if warns:
        parts.append('<div class="warn" role="note"><strong>警告</strong><ul>%s</ul></div>' % "".join(warns))
    parts.append('<details><summary>狀態圖例</summary><dl class="kv legend">%s</dl></details>' % legend)
    parts.append('<nav aria-label="頁內導覽"><a href="#projects">專案</a> <a href="#releases">版本</a> <a href="#watch">每日監控</a> <a href="#about">說明</a></nav>')
    parts.append("</header>")
    return "\n".join(parts)


def render_footer(ctx):
    return "\n".join([
        '<footer id="about">',
        "<ul>",
        "<li>權威來源是 Release 附件與 Issue；這一頁只是把已公開的資料整理在一起，頁面上看不到的東西不代表不存在。</li>",
        "<li>本頁只列已發布的 Release（草稿不列）；演練用的 Issue 不列。</li>",
        "<li>本頁不保存歷史：每次都從來源重算，只留最新一次部署。</li>",
        "<li>OK 只表示該項有跑、資料齊；沒有命中時寫「這次比對沒有新的已遭利用命中」，不代表沒有風險。</li>",
        "<li>機器可讀版：%s（同一份資料，不含任何金鑰）。</li>" % ctx.a("data.json", "data.json"),
        "</ul>",
        "</footer>"])


def render(data):
    """data dict → 完整 HTML 字串。data 的任何欄位缺漏或型別不對都不丟例外，缺的地方寫 GAP。"""
    data = dct(data)
    repo = data.get("repo") if valid_repo(data.get("repo")) else ""
    ctx = Ctx(repo)
    body = [
        '<main>',
        '<section id="projects"><h2>專案</h2>%s</section>' % render_projects(ctx, data),
        '<section id="releases"><h2>版本</h2>%s</section>' % render_releases(ctx, data),
        '<section id="watch"><h2>每日監控</h2>%s</section>' % render_watch(ctx, data),
        "</main>"]
    head = render_header(ctx, data)         # 要等本文渲染完才知道有哪些不認得的狀態值
    foot = render_footer(ctx)
    return "\n".join([
        "<!doctype html>", '<html lang="zh-Hant">', "<head>", '<meta charset="utf-8">',
        '<meta http-equiv="Content-Security-Policy" content="%s">' % CSP,
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        '<meta name="referrer" content="no-referrer">',
        '<meta name="color-scheme" content="light dark">',
        "<title>dumpling 供應鏈狀態</title>", '<link rel="stylesheet" href="style.css">', "</head>", "<body>",
        head, "\n".join(body), foot, "</body>", "</html>", ""])
