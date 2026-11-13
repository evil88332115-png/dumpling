"""不可信文字進 markdown／GitHub 步驟摘要／終端機前的共用清理（只用標準庫）。

SBOM 裡的元件名稱、版本、檔名都是不可信資料；原樣寫進 markdown 會變成連結、圖片、HTML、提及（@）或假的表格欄。
md_safe(s, limit) 依序做：
  1. 轉成 str；用 unicodedata.category 把所有 C 類（Cc 含 C1 控制字元、Cf 如 U+202E 雙向覆寫與零寬字元、Cs 單獨代理、Co、Cn）
     與 Zl／Zp（U+2028／U+2029）換成空白；連續空白（含 NBSP 等 Zs）壓成一個，去頭尾。
  2. 截短到 limit 個字元（先截短再跳脫，不會把跳脫序列切一半；截斷時結尾加「…」）。
  3. `&` 換成 `&amp;`。要最先做：`&lt;`、`&#64;`、`&#x40;`、`&commat;` 這類 HTML 實體渲染時會解碼成 `<`、`@`、`[`，
     等於繞過後面的跳脫；換成 `&amp;` 之後渲染結果是字面的 `&lt;`，任何會解碼實體的渲染器結果都一樣（不靠反斜線規則）。
  4. `@`（含全形 `＠`）後面插零寬空白 U+200B，GitHub 才不會把 `@名稱` 當成提及而通知使用者或組織。
     前面緊接 ASCII 英數字的 `@`（`pkg:generic/a@1.0`、`name@host` 這種 purl 與 email 形式）不是提及，原樣保留，purl 與版本字串才能原樣複製。
  5. 把 markdown 特殊字元 \\ [ ] ( ) < > ! * _ # ~ | ` $ 一律加反斜線跳脫（選跳脫、不換全形：純文字檢視時仍能讀出原字元）。
  6. 把會被 GitHub 自動變成連結的裸網址開頭 `scheme://` 與 `www.` 也在 `:`／`.` 前加反斜線。`://` 的 `:` 一律跳脫，不判斷前面的字元
     （`1.https://x`、`x-https://x`、`-ftp://x` 渲染器仍會連結，前面接的字元不能當作不是網址的理由）。
     沒處理：email 自動連結（只會變成 mailto 連結）。
結果可直接放進表格儲存格或清單項目，不含換行、tab、`|`、未跳脫的 `[`、`<`、未編碼的 `&`。
代價：stdout 與 log 裡的 `&` 會顯示成 `&amp;`、`@` 後面有一個看不見的零寬空白。

和 pipeline/watch/match.py（C3，已合併）的 md_text／md_title 的對應：
  - `&`→`&amp;`：與 md_text 相同。
  - 跳脫字元：md_text 是 `\\ [ ] ( ) ! < > ` | * _ ~`；這裡多 `#`、`$`（輸出不只進 Issue，也進步驟摘要與表格），
    而且用反斜線而不是 md_text 的零寬空白處理 `#`（`\\#123` 不會連到別的 Issue，純文字檢視也讀得出 `#`）。
  - `@`：md_text 對每個 `@`（`＠`）都插零寬空白；這裡只放行前面是英數字的 `@`。match.unsafe_markdown 的檢查
    （前一個字元不是反斜線或單字字元的 `@`／`＠`，後面接英數字、底線或減號，而且後面不是零寬空白）也是同一個判斷，這裡更嚴：前一個字元只有 ASCII 英數字才放行（底線、非 ASCII 字母都照樣處理）。
  - md_title（Issue 標題，標題不解讀 Markdown）沒有對應：這個模組的輸出只放進表格、清單、狀態行，不放進標題。
這裡不直接 import match.py：這個模組要能在 `python3 -I` 下單獨當指令用（shell 腳本呼叫），而 match.py 很大，載入時會改 sys.path、依賴 tools/cra。
改由測試核對：tests/test_firmware_mdsafe.py 載入 match.py，用它的 unsafe_markdown 檢查 md_safe 的輸出，兩邊的規則不一致時測試會失敗。
也可以當指令用：`python3 -I firmware_mdsafe.py [--limit N] [--] <文字>`（給 shell 腳本，印出清理後的一行）。
"""
import re
import sys
import unicodedata

SPECIAL = "\\[]()<>!*_#~|`$"          # 加反斜線跳脫的字元；`&` 另外換成 &amp;（見檔頭第 3 點）
_ESC = {ord(c): "\\" + c for c in SPECIAL}
ZWSP = "\u200b"
_AT = re.compile(r"(?<![A-Za-z0-9])([@＠])")      # 前面不是 ASCII 英數字的 @：可能是 GitHub 的提及
_SCHEME = re.compile(r":(?=//)")        # 只要 `:` 後面接 `//` 一律跳脫：不看前面是什麼（`1.https://x`、`-ftp://x` 前面是 [A-Za-z0-9+.-] 也會被渲染器連結）
_WWW = re.compile(r"(?<![A-Za-z0-9])(www)(?=\.)", re.IGNORECASE)


def plain(s):
    """第 1 步：只濾字元、壓空白，不截短也不跳脫。"""
    s = str(s)
    s = "".join(" " if (unicodedata.category(ch)[0] == "C" or unicodedata.category(ch) in ("Zl", "Zp")) else ch for ch in s)
    return " ".join(s.split())


def md_safe(s, limit=80):
    t = plain(s)
    cut = len(t) > limit
    if cut:
        t = t[:max(limit - 1, 0)].rstrip()
    t = t.replace("&", "&amp;")                  # 最先做：之後加的反斜線與零寬空白都不含 &
    t = _AT.sub(lambda m: m.group(1) + ZWSP, t)  # 在跳脫之前做：前一個字元看的是原文
    t = t.translate(_ESC)
    t = _SCHEME.sub(lambda m: "\\:", t)
    t = _WWW.sub(lambda m: m.group(1) + "\\", t)
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
