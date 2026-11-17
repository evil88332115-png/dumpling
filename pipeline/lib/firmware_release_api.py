"""韌體 Release 用的 GitHub API 回應處理（從 stdin 讀 JSON；回應是不可信資料，只取需要的欄位）。

  releases-plan --tag <tag>   stdin：`gh api repos/<repo>/releases --paginate` 的輸出（可能是好幾個 JSON 陣列接在一起）。
                              同一個 tag 已經有**非草稿**的 Release（正式版或 prerelease）→ 印 PUBLISHED、結束碼 3（呼叫端停下來，不覆蓋）。
                              否則每個同 tag 的**草稿**印一行 DRAFT <id>。永遠不會列出非草稿的 id。
  verify-assets --dir <資料夾>  stdin：單一 Release 的 JSON。附件的名稱、大小必須和資料夾裡的檔案完全一致，而且 state 都是 uploaded。
退出碼：0＝OK；1＝不符或輸入壞掉；3＝已有非草稿的 Release。
"""
import argparse
import json
import os
import re
import sys

ID_RE = re.compile(r"[0-9]{1,20}")


def parse_documents(text):
    """一串接在一起的 JSON 值（paginate 的輸出）→ 清單；壞掉丟 ValueError。"""
    dec, i, out = json.JSONDecoder(), 0, []
    text = text.strip()
    while i < len(text):
        obj, j = dec.raw_decode(text, i)
        out.append(obj)
        i = j
        while i < len(text) and text[i].isspace():
            i += 1
    return out


def plan(text, tag):
    """→ (published: bool, draft_ids: [str])。"""
    published, drafts = False, []
    for doc in parse_documents(text):
        items = doc if isinstance(doc, list) else [doc]
        for r in items:
            if not isinstance(r, dict) or r.get("tag_name") != tag:
                continue
            if r.get("draft") is True:
                rid = r.get("id")
                if isinstance(rid, int) and not isinstance(rid, bool) and ID_RE.fullmatch(str(rid)):
                    drafts.append(str(rid))
            else:
                published = True
    return published, drafts


def verify_assets(text, directory):
    """→ 問題清單。"""
    try:
        rel = json.loads(text)
    except ValueError:
        return ["Release 的回應不是 JSON"]
    assets = rel.get("assets") if isinstance(rel, dict) else None
    if not isinstance(assets, list):
        return ["Release 的回應沒有 assets"]
    remote = {}
    probs = []
    for a in assets:
        if not isinstance(a, dict) or not isinstance(a.get("name"), str):
            probs.append("附件項目格式不符")
            continue
        if a["name"] in remote:
            probs.append("附件名稱重複：%s" % a["name"][:80])
        remote[a["name"]] = a
    local = {n: os.path.getsize(os.path.join(directory, n)) for n in os.listdir(directory) if os.path.isfile(os.path.join(directory, n))}
    for n in sorted(set(local) - set(remote)):
        probs.append("沒有上傳：%s" % n)
    for n in sorted(set(remote) - set(local)):
        probs.append("多出來的附件：%s" % n[:80])
    for n in sorted(set(local) & set(remote)):
        if remote[n].get("size") != local[n]:
            probs.append("%s：大小不符（本機 %d、Release %s）" % (n, local[n], remote[n].get("size")))
        if remote[n].get("state") != "uploaded":
            probs.append("%s：state 不是 uploaded（%s）" % (n, str(remote[n].get("state"))[:20]))
    return probs


def main(argv=None):
    ap = argparse.ArgumentParser(allow_abbrev=False)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("releases-plan", allow_abbrev=False)
    p.add_argument("--tag", required=True)
    v = sub.add_parser("verify-assets", allow_abbrev=False)
    v.add_argument("--dir", required=True)
    a = ap.parse_args(argv)
    text = sys.stdin.read()
    try:
        if a.cmd == "releases-plan":
            published, drafts = plan(text, a.tag)
            if published:
                print("PUBLISHED")
                return 3
            for d in drafts:
                print("DRAFT %s" % d)
            return 0
        probs = verify_assets(text, a.dir)
    except ValueError:
        print("回應不是合法的 JSON")
        return 1
    for x in probs:
        print(x)
    return 1 if probs else 0


if __name__ == "__main__":
    sys.exit(main())
