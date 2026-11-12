#!/usr/bin/env bash
# 公開檢查：在某個 revision 的檔案（以及一段 commit 紀錄）裡找不能公開的內容。
#   - 通用規則：ci/public-patterns.txt（本機路徑、私有 IP）
#   - 信箱：只允許 noreply 類信箱與 example 網域
#   - 本機禁用字（--private，固定字串、不分大小寫；只在本機 pre-push hook 用，CI 沒有這份清單）
#   - 白名單（--allow，預設 ci/public-allow.txt）：完整字串，命中行含白名單字串就不報；
#     只套用在通用規則與檔案裡的信箱，**不套用在本機禁用字與 commit 信箱**
#   - 壓縮檔（*.xz、*.gz、*.bz2、*.zst）：解壓後（每個最多 PUBLIC_CHECK_ZLIMIT 位元組，預設 64 MB）套用上面同一組檢查
# 用法：ci/public-check.sh [--rev REV] [--range RANGE] [--patterns FILE] [--private FILE] [--allow FILE]
# 輸出：命中的每一行，最後一行是 "public-check: OK" 或 "public-check: FAIL（N 筆）"。
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
rev=HEAD
range=""
priv=""
patterns="$here/public-patterns.txt"
allowf="$here/public-allow.txt"
while [ $# -gt 0 ]; do
  case "$1" in
    --rev) rev=$2; shift 2 ;;
    --range) range=$2; shift 2 ;;
    --patterns) patterns=$2; shift 2 ;;
    --private) priv=$2; shift 2 ;;
    --allow) allowf=$2; shift 2 ;;
    *) echo "public-check: 未知參數 $1" >&2; exit 2 ;;
  esac
done
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
grep -vE '^[[:space:]]*(#|$)' "$patterns" > "$tmp/pat"
# 白名單：每行「字串<TAB>原因」；# 開頭是註解。太短或只寫網域的項目會放行太多，直接拒絕。
: > "$tmp/allow"
if [ -f "$allowf" ]; then
  grep -vE '^[[:space:]]*(#|$)' "$allowf" | cut -f1 > "$tmp/allow" || true
  bad_allow=$(grep -nE '^.{0,5}$|^[@.]' "$tmp/allow" || true)
  if [ -n "$bad_allow" ]; then
    echo "public-check: 白名單有不允許的項目（少於 6 個字元，或以 @、. 開頭會放行整個網域）："
    echo "$bad_allow"
    exit 2
  fi
fi
[ -s "$tmp/allow" ] || echo "__dumpling_no_allow_entries__" > "$tmp/allow"
path_allow='/home/runner/'
email_allow='(noreply@anthropic\.com|@users\.noreply\.github\.com|noreply@github\.com|@example\.(com|org|net)|@([A-Za-z0-9-]+\.)*[A-Za-z0-9-]+\.(example|invalid|test|localhost)|git@github\.com)$'
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
c_generic() { git grep -nIiE -f "$tmp/pat" "$rev" -- . ':(exclude)ci/public-patterns.txt' ':(exclude)ci/public-allow.txt' | grep -vE "$path_allow" | grep -vF -f "$tmp/allow"; }
# 網域結尾後面還接英數字（例如 RPM 的 kernel-core@<版本>.el9）不算信箱
c_email() { git grep -nIoE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b' "$rev" -- . ':(exclude)ci/public-allow.txt' | grep -viE "$email_allow" | grep -vF -f "$tmp/allow"; }
c_private() { git grep -nIiF -f "$priv" "$rev" -- .; }
# shellcheck disable=SC2086  # range 可以是 "A..B"
c_commit_email() { git log --format='%h author=%ae%n%h committer=%ce' $range | sort -u | grep -viE "$email_allow"; }
# shellcheck disable=SC2086
c_commit_private() { git log --format='%h %s%n%b' $range | grep -iF -f "$priv"; }

# 壓縮檔（git grep 看不到內容）：rev 裡追蹤的 *.xz、*.gz、*.bz2、*.zst 解到暫存檔（每個最多 zlimit 位元組），
# 套用同一組檢查；命中顯示「路徑（解壓後）:行號:內容」。超過大小或解不開一律算命中（無法檢查＝不能公開）。
zlimit=${PUBLIC_CHECK_ZLIMIT:-67108864}
mkdir -p "$tmp/z"
: > "$tmp/zlist"
: > "$tmp/zerr"
zi=0
while IFS= read -r zp; do
  case $zp in
    *.xz) dec=(xz -dc) ;; *.gz) dec=(gzip -dc) ;; *.bz2) dec=(bzip2 -dc) ;; *) dec=(zstd -dc) ;;
  esac
  zi=$((zi + 1))
  if ! command -v "${dec[0]}" >/dev/null 2>&1; then
    echo "$zp: 無法檢查（沒有 ${dec[0]}）" >> "$tmp/zerr"; continue
  fi
  git cat-file blob "$rev:$zp" | "${dec[@]}" 2>/dev/null | head -c $((zlimit + 1)) > "$tmp/z/$zi"
  st=("${PIPESTATUS[@]}")
  zsize=$(wc -c < "$tmp/z/$zi")
  if [ "$zsize" -gt "$zlimit" ]; then
    echo "$zp: 無法檢查（解壓後超過 $zlimit 位元組）" >> "$tmp/zerr"
  elif [ "${st[1]}" -ne 0 ] && [ "${st[1]}" -ne 141 ]; then
    echo "$zp: 無法檢查（解壓失敗，exit ${st[1]}）" >> "$tmp/zerr"
  else
    printf '%s\t%s\n' "$zi" "$zp" >> "$tmp/zlist"
  fi
done < <(git ls-tree -r --name-only "$rev" | grep -E '\.(xz|gz|bz2|zst)$')
# $1：generic／email／private
zscan() {
  local i p
  while IFS=$'\t' read -r i p; do
    case $1 in
      generic) grep -naiE -f "$tmp/pat" "$tmp/z/$i" | grep -vE "$path_allow" | grep -vF -f "$tmp/allow" ;;
      email) grep -naoE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b' "$tmp/z/$i" | grep -viE "$email_allow" | grep -vF -f "$tmp/allow" ;;
      private) grep -naiF -f "$priv" "$tmp/z/$i" ;;
    esac | awk -v p="$p" '{ print p "（解壓後）:" $0 }'
  done < "$tmp/zlist"
}
c_zerr() { cat "$tmp/zerr"; }

run "通用規則（本機路徑、私有 IP）" c_generic
run "檔案裡的信箱（只允許 noreply／example）" c_email
run "壓縮檔：無法檢查" c_zerr
run "壓縮檔：通用規則（本機路徑、私有 IP）" zscan generic
run "壓縮檔：信箱（只允許 noreply／example）" zscan email
if [ -n "$range" ]; then
  run "commit 的作者／提交者信箱" c_commit_email
fi
if [ -n "$priv" ] && [ -s "$priv" ]; then
  run "本機禁用字（檔案）" c_private
  run "壓縮檔：本機禁用字" zscan private
  [ -n "$range" ] && run "本機禁用字（commit 訊息）" c_commit_private
fi

if [ "$hits" -gt 0 ]; then
  echo "public-check: FAIL（$hits 筆）"
  exit 1
fi
echo "public-check: OK"
