#!/usr/bin/env python3
"""把 Markdown 的 Release 說明改寫成網址不會自動連結的寫法（規則見 pipeline/lib/release_body.py）。

用法：python3 -I pipeline/release-body.py <輸入的 Markdown> <輸出檔>
- 給「直接用 gh release create --notes-file」建 Release 的流程用（例如韌體的 pipeline/firmware-release-publish.sh）：
  先 `python3 -I pipeline/release-body.py notes.md release-body.md`，再 `gh release create … --notes-file release-body.md`。
  GitHub 對含網址的 Release 說明回 403（ai-nas 草稿 run 44040129677／44051748503）。
- 一般 Release（release.yml）由 release-meta.py --body-out 產生，用的是同一個函式。
- 輸入檔不改。輸出檔寫完才換上（先寫暫存檔再 rename），失敗時不留半份。
最後一行：release-body: OK（改寫了 N 處網址）｜FAIL（原因）；結束碼 0 OK、1 FAIL、64 用法錯誤。
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
from release_body import DefangError, defang_urls  # noqa: E402


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2:
        print("用法：release-body.py <輸入的 Markdown> <輸出檔>")
        return 64
    src, dst = args
    if os.path.abspath(src) == os.path.abspath(dst):
        print("release-body: FAIL（輸入和輸出是同一個檔；輸入檔不改）")
        return 1
    try:
        with open(src, encoding="utf-8") as f:
            text = f.read()
    except (OSError, UnicodeDecodeError) as e:
        print("release-body: FAIL（讀不了 %s：%s）" % (os.path.basename(src), type(e).__name__))
        return 1
    if not text.strip():
        print("release-body: FAIL（%s 是空的：不產生空白的 Release 說明）" % os.path.basename(src))
        return 1
    try:
        out, n = defang_urls(text)
    except DefangError as e:
        print("release-body: FAIL（%s）" % e)
        return 1
    tmp = dst + ".part"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(out)
        os.replace(tmp, dst)
    except OSError as e:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        print("release-body: FAIL（寫不了 %s：%s）" % (os.path.basename(dst), type(e).__name__))
        return 1
    print("release-body: OK（%s → %s，改寫了 %d 處網址）" % (os.path.basename(src), os.path.basename(dst), n))
    return 0


if __name__ == "__main__":
    sys.exit(main())
