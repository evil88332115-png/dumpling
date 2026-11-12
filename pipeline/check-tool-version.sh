#!/usr/bin/env bash
# 核對已安裝的固定版本工具：執行檔回報的版本要等於 pipeline/lib/tools.lock 的 <工具>_version。用法：
#   pipeline/check-tool-version.sh <工具名> <執行檔>        例：pipeline/check-tool-version.sh sbomqs "$SBOMQS"
# 目前只認得 sbomqs 的 `version` 輸出（`GitVersion:    v2.1.3` 那一行）。
# 退出碼：0＝相符（印一行 TOOL-VERSION<TAB>OK）；1＝不符、讀不到版本、lock 沒有這個工具（印 TOOL-VERSION<TAB>FAIL）；64＝用法錯誤。
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
[ $# -eq 2 ] || { echo "用法：check-tool-version.sh <工具名> <執行檔>" >&2; exit 64; }
tool=$1; exe=$2
[[ $tool =~ ^[a-z0-9_-]+$ ]] || { echo "工具名不合法" >&2; exit 64; }
fail() { printf 'TOOL-VERSION\tFAIL\t%s\t%s\n' "$tool" "$1"; exit 1; }
lock="${TOOLS_LOCK:-$here/lib/tools.lock}"
want=$(sed -n "s/^${tool}_version=//p" "$lock" | head -n1)
[ -n "$want" ] || fail "tools.lock 沒有 ${tool}_version"
case $tool in
  sbomqs) got=$("$exe" version 2>&1 | sed -n 's/^GitVersion:[[:space:]]*//p' | head -n1) ;;
  *) fail "不認得 $tool 的版本輸出格式（要先在這個腳本加規則）" ;;
esac
got=${got%%[[:space:]]*}
[ -n "$got" ] || fail "執行檔沒有回報版本（找不到 GitVersion 行）"
[ "$got" = "$want" ] || fail "版本不符：執行檔是 $got，tools.lock 固定 $want"
printf 'TOOL-VERSION\tOK\t%s\t%s\n' "$tool" "$got"
