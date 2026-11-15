#!/usr/bin/env python3
"""check_site.py：部署前對 site/ 的檢查（docs/DASHBOARD.md 第 4 節）。有命中就以非 0 結束。

用法：python3 -I pipeline/dashboard/check_site.py --repo <owner/repo> [--site site]

檢查（對 index.html）：
  1. 沒有 <script、沒有 on…= 事件屬性、沒有 javascript:（外來文字是原文照錄，它在 <span class="ext"> 裡，不在檢查範圍；
     ext 裡的文字已經跳脫，不可能變成標籤或屬性）。
  2. 沒有 <style、style=、<iframe、<object、<embed、<form、<base、<img 等不該有的標籤與屬性。
  3. Content-Security-Policy 的 meta 必須存在，而且內容就是設計規定的那一條。
  4. 每個 href 都要通過 render.safe_href（本 repo 的 releases/download、issues/<數字>、actions/runs/<數字>、本站的 style.css／data.json／#錨點）。
  5. 「安全」與 PASS（不分大小寫、整字）只檢查 <span class="ext">…</span> 以外的文字：頁面自己的字不能有總結字樣；
     外來文字是原文照錄，不受這一條限制。
另外檢查 style.css 沒有 @import、url(、expression(。
"""
import argparse
import html
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import render  # noqa: E402

EXT_RE = re.compile(r'<span class="ext">.*?</span>', re.S)
TAG_RE = re.compile(r"<[^>]*>", re.S)
HREF_RE = re.compile(r"""\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""", re.I)
CSP_RE = re.compile(r'<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]*)"\s*>', re.I)
BAD_TAGS = re.compile(r"<\s*(script|style|iframe|object|embed|form|base|img|svg|math|video|audio|source|input|button|frame|applet)\b", re.I)
SUMMARY_RE = re.compile(r"安全|(?<![A-Za-z0-9_])PASS(?![A-Za-z0-9_])", re.I)


# 設計規定的 CSP（寫死一份，不讀 render.CSP：只改 render.py 的常數也要被擋下；預驗建議 1）
EXPECTED_CSP = "default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'"
# ext 的內容必須是已跳脫的文字：不能有 < > " '，& 只能是這幾個實體（預驗必修 2：ext 豁免要有根據，esc 壞掉時這關要擋得住）
EXT_BODY_RE = re.compile(r'<span class="ext">(.*?)</span>', re.S)
EXT_BAD_RE = re.compile(r"""[<>"']|&(?!(?:amp|lt|gt|quot|#x27);)""")


def check_html(text, repo):
    """→ 問題清單（空＝通過）。"""
    probs = []
    for m in EXT_BODY_RE.finditer(text):
        bad = EXT_BAD_RE.search(m.group(1))
        if bad:
            probs.append("ext 的內容沒有跳脫（%r）：%s" % (bad.group(0), m.group(1)[:60]))
            break
    if re.search(r"<\s*script", text, re.I):
        probs.append("出現 <script")
    rest = EXT_RE.sub("<ext/>", text)               # ext 以外的部分
    for m in BAD_TAGS.finditer(rest):
        probs.append("出現不該有的標籤：" + m.group(0).strip()[:30])
    if re.search(r"http-equiv\s*=\s*[\"']?refresh", rest, re.I):
        probs.append("出現 meta refresh")
    if re.search(r"\bon[a-z0-9_-]+\s*=", rest, re.I):
        probs.append("出現 on…= 事件屬性")
    if re.search(r"j\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t\s*:", html.unescape(rest), re.I):
        probs.append("出現 javascript:")
    if re.search(r"\bstyle\s*=", rest, re.I):
        probs.append("出現 inline style")
    if re.search(r"\bsrcdoc\s*=|\bsrc\s*=|\bsrcset\s*=|\bformaction\s*=|\bxlink:href\s*=|\bping\s*=", rest, re.I):
        probs.append("出現 src／srcset／srcdoc／formaction／ping 屬性")
    meta = CSP_RE.search(text)
    if not meta:
        probs.append("沒有 Content-Security-Policy 的 meta")
    elif html.unescape(meta.group(1)) != EXPECTED_CSP:
        probs.append("Content-Security-Policy 內容不是設計規定的那一條")
    n_href = 0
    for m in HREF_RE.finditer(rest):
        n_href += 1
        v = html.unescape(next(g for g in m.groups() if g is not None))
        if render.safe_href(v, repo) is None:
            probs.append("href 不在白名單：" + v[:80])
    # 帶 href 的標籤只能是 <a>（對外連結要 rel="noopener noreferrer"）與 <link rel="stylesheet" href="style.css">
    for tag in TAG_RE.findall(rest):
        if re.search(r"\bhref\s*=", tag, re.I):
            low = tag.lower()
            if low.startswith("<a ") or low.startswith("<a\n"):
                hv = HREF_RE.search(tag)
                v = html.unescape(next(g for g in hv.groups() if g is not None)) if hv else ""
                if v.startswith("https://") and 'rel="noopener noreferrer"' not in tag:
                    probs.append("對外連結缺 rel=\"noopener noreferrer\"：" + v[:60])
            elif not (low.startswith("<link ") and 'rel="stylesheet"' in low and 'href="style.css"' in low):
                probs.append("href 出現在不該有的標籤：" + tag[:40])
    m = SUMMARY_RE.search(rest)
    if m:
        probs.append("ext 以外的文字出現總結字樣：" + m.group(0))
    return probs


def check_css(text):
    probs = []
    for pat, why in ((r"@import", "@import"), (r"url\s*\(", "url("), (r"expression\s*\(", "expression(")):
        if re.search(pat, text, re.I):
            probs.append("style.css 出現 " + why)
    return probs


def check_site(site, repo):
    probs = []
    for name in ("index.html", "style.css", "data.json"):
        if not os.path.isfile(os.path.join(site, name)):
            probs.append("缺少 " + name)
    if probs:
        return probs
    with open(os.path.join(site, "index.html"), encoding="utf-8") as f:
        probs += ["index.html：" + p for p in check_html(f.read(), repo)]
    with open(os.path.join(site, "style.css"), encoding="utf-8") as f:
        probs += check_css(f.read())
    return probs


def main(argv=None):
    ap = argparse.ArgumentParser(prog="check_site.py")
    ap.add_argument("--repo", required=True)
    ap.add_argument("--site", default="site")
    a = ap.parse_args(sys.argv[1:] if argv is None else argv)
    if not render.valid_repo(a.repo):
        sys.stderr.write("用法錯誤：--repo 格式要是 owner/repo\n")
        return 64
    probs = check_site(a.site, a.repo)
    for p in probs:
        print(p)
    print("CHECK-SITE\t%s\t%d 筆命中" % ("FAIL" if probs else "OK", len(probs)))
    return 1 if probs else 0


if __name__ == "__main__":
    sys.exit(main())
