#!/usr/bin/env bash
# 建韌體 Release：先清掉同一個 tag 的殘留草稿，建草稿、核對附件、發布成正式版（不是 prerelease、不是 draft）。
# 用法：pipeline/firmware-release-publish.sh <tag> <附件資料夾> <說明文字檔>     需要環境變數 GH_REPO（owner/repo）、GH_TOKEN，以及 gh
#       pipeline/firmware-release-publish.sh --cleanup <tag>                       只清掉同一個 tag 的草稿（失敗後的收尾）
# 規則（照 release.yml 的做法）：
#   - 同一個 tag 已經有非草稿的 Release（正式版或 prerelease）→ 停下來，不刪、不覆蓋。刪除只用在草稿（API 回應的 draft 為 true、tag_name 相同），
#     依 id 刪；非草稿的 id 不會出現在待刪清單裡（firmware_release_api.py releases-plan）。
#   - 草稿用 tag 名稱查不到，所以用 API 依 id 找、刪。
#   - 每個 GitHub API 呼叫都用 ghx 重試（API 偶爾回 403）；建立草稿與核對是一組，失敗就整組重來（先清掉上一次留下的草稿）。
# 退出碼：0＝已發布；1＝失敗（可能留下草稿，下次執行會先清掉）；2＝同一個 tag 已有非草稿的 Release；64＝參數錯誤。
# shellcheck disable=SC2317  # plan、delete_drafts、attempt 由 ghx 當參數間接呼叫（重試）
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC1091  # 同資料夾的 firmware-ghx.sh（路徑在執行時才知道）
. "$here/firmware-ghx.sh"
api="$here/lib/firmware_release_api.py"
[ -n "${GH_REPO:-}" ] || { echo "firmware-release: 缺少 GH_REPO"; exit 64; }

tmp=$(mktemp -d "${TMPDIR:-/tmp}/dumpling-fwrel.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

# 列出 releases → 把同 tag 的草稿 id 寫進 $tmp/drafts；有非草稿的同 tag Release 回傳 3
plan() {
  gh api "repos/$GH_REPO/releases" --paginate > "$tmp/releases.json" || return 1
  python3 -I "$api" releases-plan --tag "$tag" < "$tmp/releases.json" > "$tmp/plan.txt"
  local rc=$?
  [ "$rc" -eq 3 ] && return 3
  [ "$rc" -eq 0 ] || return 1
  sed -n 's/^DRAFT \([0-9]\{1,20\}\)$/\1/p' "$tmp/plan.txt" > "$tmp/drafts"
}

delete_drafts() {
  plan || return $?
  local id
  while read -r id; do
    [ -n "$id" ] || continue
    gh api -X DELETE "repos/$GH_REPO/releases/$id" > /dev/null || return 1
    echo "firmware-release: 刪除草稿 $id（tag $tag）"
  done < "$tmp/drafts"
}

if [ "${1:-}" = "--cleanup" ]; then
  [ $# -eq 2 ] || { echo "用法：firmware-release-publish.sh --cleanup <tag>"; exit 64; }
  tag=$2
  ghx delete_drafts; rc=$?
  [ "$rc" -eq 0 ] || [ "$rc" -eq 3 ] || exit 1       # 3＝已經有非草稿的 Release：沒有草稿可清，不刪任何東西
  exit 0
fi
[ $# -eq 3 ] || { echo "用法：firmware-release-publish.sh <tag> <附件資料夾> <說明文字檔>"; exit 64; }
tag=$1; assets=$2; notes=$3
if [ ! -d "$assets" ] || [ ! -f "$notes" ]; then echo "firmware-release: 附件資料夾或說明文字檔不存在"; exit 64; fi
shopt -s nullglob
files=("$assets"/*)
[ ${#files[@]} -gt 0 ] || { echo "firmware-release: 附件資料夾是空的"; exit 64; }
for f in "${files[@]}"; do
  case $f in *.json) ;; *) echo "firmware-release: 附件只能是 JSON：$(basename "$f")"; exit 64 ;; esac
done

# 1. 先看有沒有非草稿的同 tag Release（有就停，不刪）
ghx plan; rc=$?
if [ "$rc" -eq 3 ]; then echo "firmware-release: FAIL（$tag 已經有非草稿的 Release，不覆蓋；同一天第二次請用 .2）"; exit 2; fi
[ "$rc" -eq 0 ] || { echo "firmware-release: FAIL（查不到現有的 Release 清單）"; exit 1; }

# 2. 建草稿並核對附件（整組重試；每次先清掉上一次留下的草稿）
attempt() {
  local r
  delete_drafts; r=$?; [ "$r" -eq 0 ] || return "$r"
  gh release create "$tag" "${files[@]}" --draft --verify-tag --latest=false --title "$tag" --notes-file "$notes" || return 1
  plan; r=$?; [ "$r" -eq 0 ] || return "$r"
  [ "$(wc -l < "$tmp/drafts")" -eq 1 ] || { echo "firmware-release: 找不到唯一的草稿"; return 1; }
  id=$(cat "$tmp/drafts")
  gh api "repos/$GH_REPO/releases/$id" > "$tmp/release.json" || return 1
  python3 -I "$api" verify-assets --dir "$assets" < "$tmp/release.json" || return 1
}
id=""
ghx attempt; rc=$?
if [ "$rc" -eq 3 ]; then echo "firmware-release: FAIL（$tag 已經有非草稿的 Release，不覆蓋）"; exit 2; fi
[ "$rc" -eq 0 ] || { echo "firmware-release: FAIL（草稿沒有建好；殘留的草稿下次執行會先清掉）"; exit 1; }

# 3. 發布成正式版（不是 prerelease、不是 draft；不成為 repo 的「最新 Release」）
ghx gh api -X PATCH "repos/$GH_REPO/releases/$id" -F draft=false -F prerelease=false -f make_latest=false > /dev/null \
  || { echo "firmware-release: FAIL（發布失敗；草稿 $id 留著，下次執行會先清掉）"; exit 1; }
echo "firmware-release: OK（正式 Release $tag，${#files[@]} 個附件）"
