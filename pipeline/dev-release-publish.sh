#!/usr/bin/env bash
# 發布開發版的滾動 Release（tag dev/<專案>），dev.yml 的 publish 工作用。
# 用法：pipeline/dev-release-publish.sh <tag> <說明文字檔> <附件…>
#       需要環境變數 GH_REPO（owner/repo）、GH_TOKEN、GITHUB_REF、GITHUB_SHA，以及 gh。
# 規則：
#   - main 或 dev/** 分支 → 公開的滾動 pre-release：
#       * 同一個 tag 已經有公開的 Release（不是草稿）→ 改說明、上傳附件（同名覆蓋）、刪掉這次沒有的舊附件。
#       * 只有草稿（功能分支留下的）→ 先依 id 刪掉同一個 tag 的草稿，再新建公開的 pre-release。
#         不把草稿直接轉成公開：草稿的標題與附件是功能分支的，轉過去會留下舊附件。
#       * 什麼都沒有 → 新建公開的 pre-release。
#   - 其他分支（例如功能分支上的手動測試）→ 只建草稿（不公開、不建 git tag）：先依 id 刪掉同一個 tag 的舊草稿再建。
#   - 刪除只用在草稿：API 回應的 draft 為 true、tag_name 相同才刪，依 id 刪；公開的 Release 不會被刪。
#     草稿用 tag 名稱查不到，所以一律列出 releases、依 id 處理。
#   - 每個 GitHub API 呼叫都用 ghx 重試（API 偶爾回 403 Resource not accessible by integration）。
# 退出碼：0＝已發布；1＝失敗；64＝參數錯誤。
set -euo pipefail
[ $# -ge 3 ] || { echo "用法：dev-release-publish.sh <tag> <說明文字檔> <附件…>"; exit 64; }
tag=$1; notes_file=$2; shift 2
files=("$@")
for v in GH_REPO GITHUB_REF GITHUB_SHA; do
  [ -n "${!v:-}" ] || { echo "dev-release: 缺少 $v"; exit 64; }
done
[ -f "$notes_file" ] || { echo "dev-release: 說明文字檔不存在"; exit 64; }
notes=$(cat "$notes_file")

# 每 GHX_SLEEP 秒（預設 30）重試、最多 GHX_TRIES 次（預設 8），仍失敗就印出回應標頭與本文當診斷
ghx() {
  local n=0
  until "$@"; do
    n=$((n+1))
    if [ "$n" -ge "${GHX_TRIES:-8}" ]; then
      echo "---- 診斷：$*"; gh api -i "repos/$GH_REPO/releases?per_page=1" 2>&1 | head -30
      return 1
    fi
    sleep "${GHX_SLEEP:-30}"
  done
}

tmp=$(mktemp -d "${TMPDIR:-/tmp}/dumpling-devrel.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

# 列出 releases（--paginate 會把各頁的陣列接在一起輸出）→ $tmp/releases.json
list_releases() { gh api "repos/$GH_REPO/releases" --paginate > "$tmp/releases.json"; }

# 從 $tmp/releases.json 取出同一個 tag 的 id：pick drafts → 草稿的 id（每行一個）；pick published → 公開 Release 的 id
pick() {
  python3 -I - "$1" "$tag" "$tmp/releases.json" << 'PY'
import json, sys
kind, tag, path = sys.argv[1:4]
text = open(path, encoding="utf-8").read()
dec, i, rels = json.JSONDecoder(), 0, []
while True:
    while i < len(text) and text[i].isspace():
        i += 1
    if i >= len(text):
        break
    page, i = dec.raw_decode(text, i)
    if not isinstance(page, list):
        sys.exit("releases 回應不是陣列")
    rels.extend(page)
for r in rels:
    if not isinstance(r, dict) or r.get("tag_name") != tag:
        continue
    rid = r.get("id")
    if not isinstance(rid, int) or isinstance(rid, bool):
        sys.exit("release 的 id 不是整數")
    if (kind == "drafts" and r.get("draft") is True) or (kind == "published" and r.get("draft") is False):
        print(rid)
PY
}

delete_drafts() {
  local ids id
  ids=$(pick drafts)
  for id in $ids; do
    ghx gh api -X DELETE "repos/$GH_REPO/releases/$id" > /dev/null
    echo "dev-release: 刪除草稿 $id（tag $tag）"
  done
}

ghx list_releases
if [ "$GITHUB_REF" = refs/heads/main ] || [[ "$GITHUB_REF" == refs/heads/dev/* ]]; then
  published=$(pick published)
  if [ -n "$published" ]; then
    [ "$(wc -l <<< "$published")" -eq 1 ] || { echo "dev-release: FAIL（$tag 有不只一個公開的 Release）"; exit 1; }
    ghx gh release edit "$tag" --prerelease --notes "$notes" --repo "$GH_REPO"
    # 先上傳（同名的覆蓋），成功後才刪舊版本留下的附件（檔名不同）：上傳失敗時舊的附件還在，滾動版不會變空
    ghx gh release upload "$tag" "${files[@]}" --clobber --repo "$GH_REPO"
    ghx gh api "repos/$GH_REPO/releases/$published" > "$tmp/release.json"
    names=$(python3 -I -c 'import json,sys; [print(a["name"]) for a in json.load(open(sys.argv[1]))["assets"]]' "$tmp/release.json")
    while IFS= read -r a; do
      [ -n "$a" ] || continue
      keep=0; for f in "${files[@]}"; do [ "$a" = "$(basename "$f")" ] && keep=1; done
      [ "$keep" = 1 ] || ghx gh release delete-asset "$tag" "$a" --yes --repo "$GH_REPO"
    done <<< "$names"
  else
    delete_drafts
    ghx gh release create "$tag" "${files[@]}" --prerelease --target "$GITHUB_SHA" --title "$tag（滾動的開發版）" --notes "$notes" --repo "$GH_REPO"
  fi
  echo "publish: OK（滾動 pre-release $tag，${#files[@]} 個附件）"
else
  delete_drafts
  ghx gh release create "$tag" "${files[@]}" --draft --target "$GITHUB_SHA" --title "$tag（草稿，非 main／dev 分支）" --notes "$notes" --repo "$GH_REPO"
  echo "publish: OK（draft $tag；$GITHUB_REF 不是 main 或 dev/**，不更新公開的滾動 pre-release）"
fi
