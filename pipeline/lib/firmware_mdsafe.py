"""不可信文字進 markdown／GitHub 步驟摘要／終端機前的共用清理（只用標準庫）。

SBOM 裡的元件名稱、版本、檔名都是不可信資料；原樣寫進 markdown 會變成連結、圖片、HTML 或假的表格欄。
md_safe(s, limit) 依序做：
  1. 轉成 str；用 unicodedata.category 把所有 C 類（Cc 含 C1 控制字元、Cf 如 U+202E 雙向覆寫與零寬字元、Cs 單獨代理、Co、Cn）
     與 Zl／Zp（U+2028／U+2029）換成空白；連續空白（含 NBSP 等 Zs）壓成一個，去頭尾。
  2. 截短到 limit 個字元（先截短再跳脫，不會把跳脫序列切一半；截斷時結尾加「…」）。
  3. 把 markdown 特殊字元 \\ [ ] ( ) < > ! * _ # ~ | ` & $ 一律加反斜線跳脫（選跳脫、不換全形：純文字檢視時仍能讀出原字元）。
  4. 把會被 GitHub 自動變成連結的裸網址開頭 `scheme://` 與 `www.` 也在 `:`／`.` 前加反斜線。
     沒處理：email 自動連結（只會變成 mailto 連結）。
結果可直接放進表格儲存格、清單項目或標題，不含換行、tab、`|`、未跳脫的 `[`、`<`。
也可以當指令用：`python3 -I firmware_mdsafe.py [--limit N] [--] <文字>`（給 shell 腳本，印出清理後的一行）。
"""
import re
import sys
import unicodedata

SPECIAL = "\\[]()<>!*_#~|`&$"
_ESC = {ord(c): "\\" + c for c in SPECIAL}
_SCHEME = re.compile(r"(?<![A-Za-z0-9+.-])([A-Za-z][A-Za-z0-9+.-]{1,31}):(?=//)")
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
    t = t.translate(_ESC)
    t = _SCHEME.sub(lambda m: m.group(1) + "\\:", t)
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
