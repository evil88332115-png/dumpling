#!/usr/bin/env bash
# 公開檢查：在某個 revision 的檔案（以及一段 commit 紀錄）裡找不能公開的內容。
#   - 通用規則：ci/public-patterns.txt（本機路徑、私有 IP）
#   - 信箱：只允許 noreply 類信箱與 example 網域
#   - 本機禁用字（--private，固定字串、不分大小寫；只在本機 pre-push hook 用，CI 沒有這份清單）
# 用法：ci/public-check.sh [--rev REV] [--range RANGE] [--patterns FILE] [--private FILE]
# 輸出：命中的每一行，最後一行是 "public-check: OK" 或 "public-check: FAIL（N 筆）"。
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
rev=HEAD
range=""
priv=""
patterns="$here/public-patterns.txt"
while [ $# -gt 0 ]; do
  case "$1" in
    --rev) rev=$2; shift 2 ;;
    --range) range=$2; shift 2 ;;
    --patterns) patterns=$2; shift 2 ;;
    --private) priv=$2; shift 2 ;;
    *) echo "public-check: 未知參數 $1" >&2; exit 2 ;;
  esac
done
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
grep -vE '^[[:space:]]*(#|$)' "$patterns" > "$tmp/pat"
path_allow='/home/runner/'
email_allow='(noreply@anthropic\.com|@users\.noreply\.github\.com|noreply@github\.com|@example\.(com|org|net)|git@github\.com)$'
hits=0

run() {
  local label=$1; shift
  "$@" > "$tmp/out" 2>/dev/null || true
  if [ -s "$tmp/out" ]; then
    echo "== $label"
    cat "$tmp/out"
    hits=$((hits + $(wc -l < "$tmp/out")))
  fi
}
c_generic() { git grep -nIiE -f "$tmp/pat" "$rev" -- . ':(exclude)ci/public-patterns.txt' | grep -vE "$path_allow"; }
c_email() { git grep -nIoE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' "$rev" -- . | grep -viE "$email_allow"; }
c_private() { git grep -nIiF -f "$priv" "$rev" -- .; }
# shellcheck disable=SC2086  # range 可以是 "A..B"
c_commit_email() { git log --format='%h author=%ae%n%h committer=%ce' $range | sort -u | grep -viE "$email_allow"; }
# shellcheck disable=SC2086
c_commit_private() { git log --format='%h %s%n%b' $range | grep -iF -f "$priv"; }

run "通用規則（本機路徑、私有 IP）" c_generic
run "檔案裡的信箱（只允許 noreply／example）" c_email
if [ -n "$range" ]; then
  run "commit 的作者／提交者信箱" c_commit_email
fi
if [ -n "$priv" ] && [ -s "$priv" ]; then
  run "本機禁用字（檔案）" c_private
  [ -n "$range" ] && run "本機禁用字（commit 訊息）" c_commit_private
fi

if [ "$hits" -gt 0 ]; then
  echo "public-check: FAIL（$hits 筆）"
  exit 1
fi
echo "public-check: OK"
