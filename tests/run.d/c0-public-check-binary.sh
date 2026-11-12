#!/usr/bin/env bash
# public-check 的二進位檔規則（D-028）：沒登記的二進位檔算命中；登記且 sha256 相符才放行；內容改過就不符。
set -euo pipefail
top=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
git init -q
git config user.email 1+test@users.noreply.github.com
git config user.name test
mkdir ci
cp "$top/ci/public-patterns.txt" ci/
printf 'hello\n' > a.txt
printf '\x89PNG\r\n\x1a\n\x00\x00data' > logo.png
printf '\x00\x01firmware' > fw.bin
printf '\x00\xff' > "中文 名.bin"
: > empty.keep
printf 'x\n' | xz > d.txt.xz
printf 'logo.png\t%s\t測試用圖片\n' "$(sha256sum logo.png | cut -d' ' -f1)" > ci/public-binary-allow.txt
git add -A
git commit -qm t
fail=0
check() { bash "$top/ci/public-check.sh" --rev HEAD --patterns ci/public-patterns.txt --allow ci/public-allow.txt 2>&1 || true; }
out=$(check)
expect() {
  local found=no
  if printf '%s\n' "$out" | grep -qF -- "$2"; then found=yes; fi
  if [ "$found" = "$1" ]; then echo "ok: $3"; else echo "FAIL: $3"; fail=1; fi
}
expect yes 'fw.bin: 無法檢查' '沒登記的二進位檔算命中'
expect yes '中文 名.bin: 無法檢查' '非 ASCII 檔名的二進位檔也抓得到'
expect no 'logo.png' '登記且 sha256 相符的二進位檔放行'
expect no 'empty.keep' '空檔不算'
expect no 'd.txt.xz: 無法檢查' '壓縮檔交給解壓掃描，不重複報'
expect no 'a.txt' '文字檔不受影響'
printf 'changed' >> logo.png
git commit -qam t2
out=$(check)
expect yes 'logo.png: 無法檢查（二進位檔；ci/public-binary-allow.txt 登記的 sha256 與內容不符' '內容改過，登記的 sha256 不符就算命中'
if [ "$fail" -ne 0 ]; then echo "c0-public-check-binary: FAIL"; exit 1; fi
echo "c0-public-check-binary: OK"
