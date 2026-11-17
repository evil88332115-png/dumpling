"""Release 說明的網址改寫：GitHub 對含網址的 Release 說明回 403（ai-nas 草稿 run 44040129677；拿掉網址後 run 44051748503 一次就成功），
所以送出去的說明一律把網址改成不會自動連結的寫法。release-meta.py --body-out 與 pipeline/release-body.py 都用這裡的 defang_urls。

defang_urls(text) → (新文字, 改了幾處)：
- https／http／ftp 網址：去掉 scheme 放進 code span（`www.example.org/a`）；查詢字串裡的網址也一起去掉 scheme。
- markdown 連結 [文字](網址)：留下文字，網址放進括號裡的 code span；<網址> 這種 autolink 去掉尖括號。
- www. 開頭的裸網址也包進 code span（a@www.… 這種信箱不動）。
- code span 與 fenced code block（``` 或 ~~~）裡：只去掉 scheme。
- file://：一律換成「本機路徑，已省略」，不把路徑帶進說明。
- 句尾標點與全形標點不算網址；再跑一次不會再改（冪等）。
- 最後對整份文字無條件再清一次：規則沒抓到的（ASCII 英數字緊貼，例如 abchttps://…）scheme 一律去掉、file://… 一律換成固定句，
  所以輸出一定沒有 http(s)://、ftp://、file://。拿掉之後可能拼出新的 scheme（hthttps://tps://x），所以重複到沒有命中為止，
  最多 FINAL_PASS_MAX（10）次，超過就丟 DefangError（release-meta.py、release-body.py 記 FAIL，不產生說明）。
"""
import re

# Release 說明的網址改寫（defang_urls）：GitHub 對含網址的 Release 說明回 403，所以一律改成不會自動連結的寫法
_CJK_STOP = "，、。；：！？（）「」『』【】《》〈〉"            # 全形標點不算網址的一部分
_URL_STOP = r"[^\s<>`'\"" + _CJK_STOP + r"]+"
_MD_LINK = re.compile(r"\[([^\]\n]*)\]\(\s*<?((?:https?|ftp|file)://[^)\s>]*)>?(?:\s+\"[^\"\n]*\")?\s*\)", re.I)
_AUTOLINK = re.compile(r"<((?:https?|ftp|file)://[^>\s]*)>", re.I)
# 前面只排除 ASCII 英數字（中文字、底線緊貼也要改寫；\w 會把中文與底線當成字的一部分而漏掉）
_BARE = re.compile(r"(?<![A-Za-z0-9])((?:https?|ftp|file)://" + _URL_STOP + r")", re.I)
_WWW = re.compile(r"(?<![A-Za-z0-9./@-])(www\.[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+" + r"[^\s<>`'\"" + _CJK_STOP + r"]*)", re.I)
_SCHEME = re.compile(r"(?:https?|ftp)://", re.I)
_FILE = re.compile(r"file://[^\s`<>'\"" + _CJK_STOP + r"]*", re.I)   # 不吃掉 code span 結尾的反引號與後面的全形標點
LOCAL_PATH_NOTE = "本機路徑，已省略"
FINAL_PASS_MAX = 10                 # 最後一道無條件清理最多重複幾次


class DefangError(ValueError):
    """最後一道清理重複 FINAL_PASS_MAX 次仍有 scheme：不產生說明（呼叫端記 FAIL）。"""


def _plain(url):
    """網址 → 不含 scheme 的文字；file:// → 「本機路徑，已省略」（不把路徑帶進說明）。結尾的標點不算網址。"""
    if url.lower().startswith("file://"):
        return LOCAL_PATH_NOTE, ""
    tail = ""
    while url and url[-1] in ".,;:!?。，；：！？":
        tail, url = url[-1] + tail, url[:-1]
    # 查詢字串裡可能又有完整的網址：scheme 全部去掉、file:// 一律省略（只去第一個會留下 scheme，而且再跑一次結果不同）
    return _FILE.sub(LOCAL_PATH_NOTE, _SCHEME.sub("", url)), tail


def _defang_text(seg):
    """code span／code block 以外的文字。→ (新文字, 改了幾處)"""
    n = 0
    def md(m):
        nonlocal n
        n += 1
        p, _ = _plain(m.group(2))
        return "%s（%s）" % (m.group(1), p if p == LOCAL_PATH_NOTE else "`%s`" % p) if m.group(1) else (p if p == LOCAL_PATH_NOTE else "`%s`" % p)
    def bare(m):
        nonlocal n
        n += 1
        p, tail = _plain(m.group(1))
        return (p if p == LOCAL_PATH_NOTE else "`%s`" % p) + tail
    def www(m):
        nonlocal n
        n += 1
        p, tail = _plain(m.group(1))
        return "`%s`" % p + tail
    seg = _MD_LINK.sub(md, seg)
    seg = _AUTOLINK.sub(bare, seg)
    seg = _BARE.sub(bare, seg)
    # www. 開頭的裸網址：只看還不在 code span 裡的部分（上面剛包好的不再包一次）
    parts = re.split(r"(`[^`\n]*`)", seg)
    for i in range(0, len(parts), 2):
        parts[i] = _WWW.sub(www, parts[i])
    return "".join(parts), n


def _defang_code(seg):
    """code span／code block 裡面：不會自動連結，但 scheme 一樣去掉（403 看的可能是文字本身）；file:// 照樣省略路徑。"""
    n = len(_SCHEME.findall(seg)) + len(_FILE.findall(seg))
    seg = _FILE.sub(LOCAL_PATH_NOTE, seg)
    return _SCHEME.sub("", seg), n


def defang_urls(text):
    """Markdown → (網址都改成不會自動連結的寫法的 Markdown, 改了幾處)。fenced code block（``` 或 ~~~）與行內 code span 裡只去掉 scheme。"""
    out, total, fence = [], 0, None
    for line in text.split("\n"):
        s = line.lstrip()
        if fence is None and (s.startswith("```") or s.startswith("~~~")):
            fence = s[:3]
            out.append(line)
            continue
        if fence is not None:
            if s.startswith(fence):
                fence = None
                out.append(line)
                continue
            line, k = _defang_code(line)
            total += k
            out.append(line)
            continue
        parts = re.split(r"(`+[^`\n]*`+)", line)
        for i, part in enumerate(parts):
            part, k = (_defang_code(part) if i % 2 else _defang_text(part))
            parts[i] = part
            total += k
        out.append("".join(parts))
    # 最後一道保險（無條件）：上面的規則沒抓到的（例如 ASCII 英數字緊貼 abchttps://…、v1https://…），整份文字裡剩下的
    # file://… 一律換成固定句、(https?|ftp):// 一律去掉；也算進計數。輸出因此一定沒有 http(s)://、ftp://、file://
    # 拿掉之後前後的字可能剛好拼出新的 scheme（hthttps://tps://x → https://x），所以重複到沒有命中為止；超過 FINAL_PASS_MAX 次就失敗
    text = "\n".join(out)
    for _ in range(FINAL_PASS_MAX):
        nf, ns = len(_FILE.findall(text)), len(_SCHEME.findall(text))
        if not nf and not ns:
            return text, total
        text = _SCHEME.sub("", _FILE.sub(LOCAL_PATH_NOTE, text))
        total += nf + ns
    raise DefangError("網址改寫重複了 %d 次仍有 scheme 留下（輸入可能是刻意拼出來的）" % FINAL_PASS_MAX)
