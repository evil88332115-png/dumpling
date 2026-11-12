#!/usr/bin/env bash
# 公開檢查：在某個 revision 的檔案（以及一段 commit 紀錄）裡找不能公開的內容。
#   - 通用規則：ci/public-patterns.txt（本機路徑、私有 IP）
#   - 信箱：只允許 noreply 類信箱與 example 網域
#   - 本機禁用字（--private，固定字串、不分大小寫；只在本機 pre-push hook 用，CI 沒有這份清單）
#   - 白名單（--allow，預設 ci/public-allow.txt）：完整字串，命中行含白名單字串就不報；
#     只套用在通用規則與檔案裡的信箱，**不套用在本機禁用字與 commit 信箱**
#   - 壓縮檔與封存檔（.xz .gz .bz2 .zst .tar 及 .tgz 等，不分大小寫）：解壓後（每個最多 PUBLIC_CHECK_ZLIMIT 位元組，
#     預設 64 MB）套用上面同一組檢查；.zip .7z 等不支援的格式、解不開、太大、缺工具一律算命中
#   - 白名單以完整字串比對（前後不能緊接 [A-Za-z0-9._%+@-]），不會放行「包含」白名單字串的更長信箱或路徑
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
# 白名單以「完整字串」比對：前後不能緊接信箱／主機名稱的字元（例如登記 a 開頭的短信箱，不會放行同網域、名稱以 a 結尾的其他信箱）。
# 每項轉成 ERE（跳脫特殊字元）並加前後邊界。
tok='A-Za-z0-9._%+@-'
sed -e 's/[][\.*^$+?(){}|]/\\&/g' -e "s/^/(^|[^$tok])/" -e "s/\$/(\$|[^$tok])/" "$tmp/allow" > "$tmp/allow.re"
allow_filter() { grep -avE -f "$tmp/allow.re"; }
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
c_generic() { git grep -nIiE -f "$tmp/pat" "$rev" -- . ':(exclude)ci/public-patterns.txt' ':(exclude)ci/public-allow.txt' | grep -vE "$path_allow" | allow_filter; }
# 網域結尾後面還接英數字（例如 RPM 的 kernel-core@<版本>.el9）不算信箱
c_email() { git grep -nIoE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b' "$rev" -- . ':(exclude)ci/public-allow.txt' | grep -viE "$email_allow" | allow_filter; }
c_private() { git grep -nIiF -f "$priv" "$rev" -- .; }
# shellcheck disable=SC2086  # range 可以是 "A..B"
c_commit_email() { git log --format='%h author=%ae%n%h committer=%ce' $range | sort -u | grep -viE "$email_allow"; }
# shellcheck disable=SC2086
c_commit_private() { git log --format='%h %s%n%b' $range | grep -iF -f "$priv"; }

# 壓縮檔與封存檔（git grep -I 看不到內容）：rev 裡追蹤的檔案依副檔名（不分大小寫）處理——
#   .xz .txz .lzma → xz；.gz .tgz → gzip；.bz2 .tbz .tbz2 → bzip2；.zst .tzst → zstd；.tar → 原樣（當二進位文字掃）
#   .zip .jar .7z .rar .lz4 .lz .z .cpio .iso → 不解，一律算命中（無法檢查）
# 解到暫存檔（每個最多 zlimit 位元組），套用同一組檢查；命中顯示「路徑（解壓後）:行號:內容」。
# 超過大小、解不開、缺工具一律算命中（無法檢查＝不能公開）。檔名用 -z 讀，非 ASCII 或含空白的路徑也不會漏。
zlimit=${PUBLIC_CHECK_ZLIMIT:-67108864}
mkdir -p "$tmp/z"
: > "$tmp/zidx"
: > "$tmp/zerr"
zi=0
while IFS= read -r -d '' zp; do
  lc=${zp,,}
  case $lc in
    *.xz|*.txz|*.lzma) dec=(xz -dc) ;;
    *.gz|*.tgz) dec=(gzip -dc) ;;
    *.bz2|*.tbz|*.tbz2) dec=(bzip2 -dc) ;;
    *.zst|*.tzst) dec=(zstd -dc) ;;
    *.tar) dec=(cat) ;;
    *.zip|*.jar|*.7z|*.rar|*.lz4|*.lz|*.z|*.cpio|*.iso)
      printf '%s: 無法檢查（不支援的封存格式，不能公開）\n' "$zp" >> "$tmp/zerr"; continue ;;
    *) continue ;;
  esac
  zi=$((zi + 1))
  if ! command -v "${dec[0]}" >/dev/null 2>&1; then
    printf '%s: 無法檢查（沒有 %s）\n' "$zp" "${dec[0]}" >> "$tmp/zerr"; continue
  fi
  # NUL 換成換行：tar 標頭與二進位內容裡的字串才能逐行比對（文字檔沒有 NUL，行號不變）
  git cat-file blob "$rev:$zp" | "${dec[@]}" 2>/dev/null | head -c $((zlimit + 1)) | tr '\000' '\n' > "$tmp/z/$zi"
  st=("${PIPESTATUS[@]}")
  zsize=$(wc -c < "$tmp/z/$zi")
  if [ "$zsize" -gt "$zlimit" ]; then
    printf '%s: 無法檢查（解壓後超過 %s 位元組）\n' "$zp" "$zlimit" >> "$tmp/zerr"
  elif { [ "${st[0]}" -ne 0 ] && [ "${st[0]}" -ne 141 ]; } || { [ "${st[1]}" -ne 0 ] && [ "${st[1]}" -ne 141 ]; }; then
    printf '%s: 無法檢查（解壓失敗，exit %s）\n' "$zp" "${st[1]}" >> "$tmp/zerr"
  else
    printf '%s' "$zp" > "$tmp/z/$zi.path"
    echo "$zi" >> "$tmp/zidx"
  fi
done < <(git ls-tree -r -z --name-only "$rev")
# $1：generic／email／private
zscan() {
  local i p
  while IFS= read -r i; do
    p=$(cat "$tmp/z/$i.path")
    case $1 in
      generic) grep -naiE -f "$tmp/pat" "$tmp/z/$i" | grep -avE "$path_allow" | allow_filter ;;
      email) grep -naoE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b' "$tmp/z/$i" | grep -aviE "$email_allow" | allow_filter ;;
      private) grep -naiF -f "$priv" "$tmp/z/$i" ;;
    esac | awk -v p="$p" '{ print p "（解壓後）:" $0 }'
  done < "$tmp/zidx"
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
