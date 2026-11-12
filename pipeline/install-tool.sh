#!/usr/bin/env bash
# 安裝 pipeline/lib/tools.lock 固定的工具：下載 → 核對 sha256 → 才解開，只取出一個成員。用法：
#   pipeline/install-tool.sh <工具名> <目的資料夾>        例：pipeline/install-tool.sh sbomqs "$RUNNER_TEMP/bin"
# 成功時最後一行印出執行檔路徑。sha256 不符就不解開、不安裝。
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
[ $# -eq 2 ] || { echo "用法：install-tool.sh <工具名> <目的資料夾>" >&2; exit 64; }
tool=$1; dest=$2
[[ $tool =~ ^[a-z0-9_-]+$ ]] || { echo "工具名不合法" >&2; exit 64; }
lock="$here/lib/tools.lock"
get() { sed -n "s/^${tool}_$1=//p" "$lock" | head -n1; }
url=$(get url); sha=$(get sha256); member=$(get member)
if [ -z "$url" ] || [ -z "$sha" ] || [ -z "$member" ]; then echo "tools.lock 沒有 $tool 的 url／sha256／member" >&2; exit 1; fi
[[ $sha =~ ^[0-9a-f]{64}$ ]] || { echo "tools.lock 的 sha256 格式錯誤" >&2; exit 1; }
[[ $member =~ ^[A-Za-z0-9._-]+$ ]] || { echo "tools.lock 的 member 不合法" >&2; exit 1; }
mkdir -p "$dest"
work=$(mktemp -d "$dest/.install.XXXXXX")
trap 'rm -rf "$work"' EXIT
curl --fail --location --proto '=https' --proto-redir '=https' --silent --show-error \
  --retry 2 --connect-timeout 30 --max-time 300 --max-filesize 104857600 --output "$work/pkg.tgz" -- "$url"
got=$(sha256sum "$work/pkg.tgz" | cut -d' ' -f1)
[ "$got" = "$sha" ] || { echo "$tool sha256 不符（實際 $got，預期 $sha）" >&2; exit 1; }
tar -xzf "$work/pkg.tgz" -C "$work" -- "$member"
if [ ! -f "$work/$member" ] || [ -L "$work/$member" ]; then echo "壓縮檔內的 $member 不是一般檔案" >&2; exit 1; fi
install -m 0755 "$work/$member" "$dest/$tool"
echo "$dest/$tool"
