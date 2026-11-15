"""不可信文字進 markdown／GitHub 步驟摘要／終端機前的共用清理（只用標準庫）。

SBOM 裡的元件名稱、版本、檔名都是不可信資料；原樣寫進 markdown 會變成連結、圖片、HTML、提及（@）或假的表格欄。
md_safe(s, limit) 依序做：
  1. 轉成 str；用 unicodedata.category 把所有 C 類（Cc 含 C1 控制字元、Cf 如 U+202E 雙向覆寫與零寬字元、Cs 單獨代理、Co、Cn）
     與 Zl／Zp（U+2028／U+2029）換成空白；連續空白（含 NBSP 等 Zs）壓成一個，去頭尾。
  2. 截短到 limit 個字元（先截短再跳脫，不會把跳脫序列切一半；截斷時結尾加「…」）。
  3. `&` 換成 `&amp;`。要最先做：`&lt;`、`&#64;`、`&#x40;`、`&commat;` 這類 HTML 實體渲染時會解碼成 `<`、`@`、`[`，
     等於繞過後面的跳脫；換成 `&amp;` 之後渲染結果是字面的 `&lt;`，任何會解碼實體的渲染器結果都一樣（不靠反斜線規則）。
  4. `@`（含全形 `＠`）：前面不是 ASCII 英數字的，後面插零寬空白 U+200B，GitHub 才不會把 `@名稱` 當成提及而通知使用者或組織。
     前面緊接 ASCII 英數字的 `@` 不是提及，但可能是 email 自動連結（cmark-gfm 的擴充：`a@b.c`，渲染成 mailto 連結）：
     `@` 後面接的字元（英數字、`-`、`_`、後面接英數字的 `.`）構成一個含 `.`、只有一個 `@`、最後一個字元是英文字母的網域形式時，也在 `@` 後面插零寬空白（連結的網域部分會斷掉）；
     其他不會被連結的形式（`pkg:generic/zlib@1.2.11`、`name@host`、`x9@y` 這種 purl 與版本字串）原樣保留，可以原樣複製。
     網域最後一個字元是字母的 purl（例如版本 `1.2.11.dfsg`）符合 email 形式，會有一個看不見的零寬空白（複製時會帶著）：不插的話渲染器會連結它。
  4b. `mailto:`、`xmpp:`（不分大小寫）的冒號加反斜線，冒號後面再插一個零寬空白：markdown-it 的 linkify 認得 `mailto:` 後面接 `名稱@主機` 的形式（不要求網域有 `.`）；
     cmark-gfm 的 email 自動連結往回掃時，會把 `mailto:`、`xmpp:` 前綴吃進連結，而且 `xmpp:` 後面的 `名稱@網域/資源` 可以沒有 `.`（`xmpp:a@/.a` 會連結）；
     cmark-gfm 先合併文字節點再做 autolink，所以只加反斜線擋不住，要靠零寬空白讓前綴與名稱接不起來。
  5. 把 markdown 特殊字元 \\ [ ] ( ) < > ! * _ # ~ | ` $ 一律加反斜線跳脫（選跳脫、不換全形：純文字檢視時仍能讀出原字元）。
  6. 把會被 GitHub 自動變成連結的裸網址開頭 `scheme://` 與 `www.` 也在 `:`／`.` 前加反斜線。`://` 的 `:` 一律跳脫，不判斷前面的字元
     （`1.https://x`、`x-https://x`、`-ftp://x` 渲染器仍會連結，前面接的字元不能當作不是網址的理由）。
     email 自動連結與 `mailto:`／`xmpp:` 見第 4、4b 點；測試用 cmark-gfm（cmarkgfm 套件）與 markdown-it-py 的渲染結果核對（tests/test_c2_report_render.py）。
  7. Issue 參照：`#`／`＃` 後面接數字（含全形數字）時，在 `#` 後面插零寬空白；`GH-` 接數字（不分大小寫、前面不是英數字）時，在 `GH` 後面插零寬空白。
     GitHub 是對**渲染後的文字**比對 Issue 參照，反斜線只在 Markdown 那一層有效：`#1`、`\\#1`、`owner/repo#1`、`owner/repo\\#1`、`GH-1` 都會連到別的 Issue／PR，
     放在 Issue、PR、Release 說明時還會在對方的時間軸留下 cross-reference；`#<零寬>1`、`＃1`、`GH<零寬>-1` 不會（C3 用 GitHub 的 POST /markdown〔mode=gfm、context 是本 repo〕實測）。
     regex 與 pipeline/watch/match.py 的 `_issue_refs_off` 相同；處理是冪等的（已插過零寬空白的不會再插）。
結果可直接放進表格儲存格或清單項目，不含換行、tab、`|`、未跳脫的 `[`、`<`、未編碼的 `&`。
代價：stdout 與 log 裡的 `&` 會顯示成 `&amp;`、`@` 與 Issue 參照的 `#`、`GH` 後面有一個看不見的零寬空白。

和 pipeline/watch/match.py（C3）的對應：md_text 是 md_safe 的結果再經過 `_issue_refs_off`（第 7 點同一份 regex），所以兩邊對同一個輸入的結果相同。
  match.unsafe_markdown 的 `@` 檢查（前一個字元不是反斜線或單字字元的 `@`／`＠`，後面接英數字、底線或減號，而且後面不是零寬空白）也是第 4 點同一個判斷，這裡更嚴：前一個字元只有 ASCII 英數字才放行。
  md_title（Issue 標題，標題不解讀 Markdown）沒有對應：這個模組的輸出只放進表格、清單、狀態行，不放進標題。
這裡不直接 import match.py：這個模組要能在 `python3 -I` 下單獨當指令用（shell 腳本呼叫），而 match.py 很大，載入時會改 sys.path、依賴 tools/cra。
改由測試核對：tests/test_firmware_mdsafe.py 載入 match.py，用它的 unsafe_markdown 檢查 md_safe 的輸出，兩邊的規則不一致時測試會失敗。
時間：所有掃描都是單次線性（`@` 的判斷、網域掃描、同一串 email 字元裡有沒有更早的 `@`），沒有回看上限。
可見內容判斷：is_blank(s)＝每個字元都是空白、C 類（控制、格式、零寬）、Mn／Me（組合記號、變體選擇符），或是會顯示成空白的字元（Hangul filler U+115F／U+1160／U+3164／U+FFA0、U+2800）；
給「名稱只有看不見的字元要算空名稱」用（plain() 只換掉 C 類，Hangul filler 是 Lo 類，濾不掉）。
也可以當指令用：`python3 -I firmware_mdsafe.py [--limit N] [--] <文字>`（給 shell 腳本，印出清理後的一行）。
"""
import re
import sys
import unicodedata

SPECIAL = "\\[]()<>!*_#~|`$"          # 加反斜線跳脫的字元；`&` 另外換成 &amp;（見檔頭第 3 點）
_ESC = {ord(c): "\\" + c for c in SPECIAL}
ZWSP = "\u200b"
_AT = re.compile(r"[@＠]")
_ALNUM = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
_DOMAIN_RUN = re.compile(r"(?:[A-Za-z0-9_-]|\.(?=[A-Za-z0-9]))*")      # cmark-gfm 的 email 自動連結往 @ 後面掃的字元集（`.` 後面要接英數字；到下一個 @ 為止）
_LOCAL_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._+@-")      # email 名稱部分的字元（含 @：找同一串裡有沒有更早的 @）
_MAILTO = re.compile(r"(?i)(mailto|xmpp):")
_SCHEME = re.compile(r":(?=//)")        # 只要 `:` 後面接 `//` 一律跳脫：不看前面是什麼（`1.https://x`、`-ftp://x` 前面是 [A-Za-z0-9+.-] 也會被渲染器連結）
_WWW = re.compile(r"(?<![A-Za-z0-9])(www)(?=\.)", re.IGNORECASE)
_ISSUE_REF = re.compile(r"(\\?[#＃])(?=[0-9０-９])")              # 第 7 點：`#1`、`\#1`、`＃１`（與 match._issue_refs_off 相同）
_GH_REF = re.compile(r"(?i)(?<![A-Za-z0-9])(gh)(?=-[0-9])")        # 第 7 點：`GH-1`


def plain(s):
    """第 1 步：只濾字元、壓空白，不截短也不跳脫。"""
    s = str(s)
    s = "".join(" " if (unicodedata.category(ch)[0] == "C" or unicodedata.category(ch) in ("Zl", "Zp")) else ch for ch in s)
    return " ".join(s.split())


def _earlier_at(t):
    """每個位置：同一串 email 字元（_LOCAL_CHARS）裡，前面有沒有 @。一次線性掃過，不設回看上限（有上限的話，`x@y.z` 接 253 個以上的 `1` 再接 `@Z` 就繞得過去）。"""
    out, has = [], False
    for ch in t:
        out.append(has)
        has = (has or ch == "@") if ch in _LOCAL_CHARS else False
    return out


def _email_like(t, i, after_at):
    """t[i] 是 ASCII @：後面是不是會被連結成 email 的網域形式。after_at＝同一串 email 字元裡前面是否已有 @（見 _earlier_at）。
    @ 後面的字元（見 _DOMAIN_RUN，到下一個 @ 為止：下一個 @ 也會被處理）最後一個字元是英文字母，而且含 `.`；前面已經出現過 @ 時不要求 `.`
    （cmark-gfm 處理過前一個 @ 之後，`.` 的計數沒有歸零：`x@y.z@Z`、`x@y.z-@Z` 會連結 `y.z@Z`，空白隔開的 `x@y.z @Z` 不會，實測）。
    markdown-it 的 linkify 另外會在 `-`、`_` 之前截斷網域（`a@example.com_1` 連結 `a@example.com`）：
    所以「字母後面接 `-`、`_` 或網域結尾」的每個位置都當成可能的結尾。一次掃過網域，時間與長度成正比。"""
    j = _DOMAIN_RUN.match(t, i + 1).end()
    seen_dot = False
    for k in range(i + 1, j):
        c = t[k]
        if c == ".":
            seen_dot = True
        elif c.isalpha() and (k + 1 == j or t[k + 1] in "-_") and (seen_dot or after_at):      # 網域只有 ASCII 英數字、`-`、`_`、`.`
            return True
    return False


def _defang_at(t, i, earlier):
    """t[i] 是 @ 或 ＠：回傳 (前面要不要插零寬空白, 後面要不要插)。
    email 形式（見 _email_like）：前後都插。只插後面時，markdown-it 的 linkify 會把 `a@<零寬>b.com` 當成 IDN 網域連結；
    前面也隔開，名稱與網域都接不起來；零寬空白不是英數字，cmark-gfm 往回掃時也停在這裡。
    前面不是 ASCII 英數字的其他 @：可能是提及，只插後面。
    前面是 ASCII 英數字、也不是 email 形式的 @（`pkg:generic/zlib@1.2.11`、`name@host`）：不動，purl 與版本字串才能原樣複製。
    ＠（全形）沒有渲染器當 email；前面不是 ASCII 英數字時照提及處理，否則不動。"""
    prev_alnum = i > 0 and t[i - 1] in _ALNUM
    if t[i] == "@" and _email_like(t, i, earlier[i]):
        return True, True
    return False, not prev_alnum


_BLANK_EXTRA = frozenset([0x115F, 0x1160, 0x2800, 0x3164, 0xFFA0])      # 顯示成空白、但不是 C／Z／M 類的字元（Hangul filler 是 Lo、點字空白是 So）


def is_blank(s):
    """看不到任何內容：空字串，或每個字元都是空白、C 類（控制、格式、零寬）、Mn／Me（組合記號、變體選擇符）、_BLANK_EXTRA。"""
    for ch in str(s):
        cat = unicodedata.category(ch)
        if not (ch.isspace() or cat[0] in "CZ" or cat in ("Mn", "Me") or ord(ch) in _BLANK_EXTRA):
            return False
    return True


def _at_sub(t, m, earlier):
    before, after = _defang_at(t, m.start(), earlier)
    return (ZWSP if before else "") + m.group() + (ZWSP if after else "")


def defang_at(t):
    """`@`／`＠` 的處理（第 4 點）單獨拿出來：tools/cra/x86_firmware.py 的 md_esc 用同一份規則。t 要是已經把 & 換成 &amp; 的文字（& 不影響這裡的判斷）。"""
    earlier = _earlier_at(t)
    return _AT.sub(lambda m: _at_sub(t, m, earlier), t)


def defang_issue_refs(t):
    """Issue 參照（第 7 點）：`#`／`＃` 接數字時在後面插零寬空白，`GH-` 接數字時在 `GH` 後面插零寬空白。跳脫前後都可以用（`\\#1` 也處理）；冪等。"""
    t = _ISSUE_REF.sub(lambda m: m.group(1) + ZWSP, t)
    return _GH_REF.sub(lambda m: m.group(1) + ZWSP, t)


def defang_links(t):
    """裸網址（`scheme://`、`www.`）、`mailto:`／`xmpp:` 的自動連結與 Issue 參照的處理（第 6、4b、7 點）。t 要是已經跳脫過反斜線與特殊字元的文字。"""
    t = _SCHEME.sub(lambda m: "\\:", t)
    t = _MAILTO.sub(lambda m: m.group(1) + "\\:" + ZWSP, t)      # 冒號後面再插零寬空白：cmark-gfm 先合併文字節點再做 autolink，`\\:` 擋不住；零寬空白讓往回掃停在這裡
    return defang_issue_refs(_WWW.sub(lambda m: m.group(1) + "\\", t))


def md_safe(s, limit=80):
    t = plain(s)
    cut = len(t) > limit
    if cut:
        t = t[:max(limit - 1, 0)].rstrip()
    t = t.replace("&", "&amp;")                  # 最先做：之後加的反斜線與零寬空白都不含 &
    t = defang_at(t)                             # 在跳脫之前做：前後的字元看的是原文
    t = defang_links(t.translate(_ESC))
    return t + "…" if cut else t


def main(argv):
    limit = 80
    args = list(argv)
    if args[:1] == ["--limit"]:
        try:
            limit = int(args[1])
        except (IndexError, ValueError):
            print("用法：firmware_mdsafe.py [--limit N] <文字>", file=sys.stderr)
            return 64
        args = args[2:]
    if args[:1] == ["--"]:
        args = args[1:]
    if len(args) != 1:
        print("用法：firmware_mdsafe.py [--limit N] <文字>", file=sys.stderr)
        return 64
    sys.stdout.buffer.write(md_safe(args[0], limit).encode("utf-8"))     # 不靠 locale 決定輸出編碼
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
