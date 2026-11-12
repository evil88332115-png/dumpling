#!/usr/bin/env bash
# ci/public-check.sh 的壓縮檔檢查：在暫存 git repo 裡放合成的 .xz／.gz／.bz2（／.zst，有 zstd 才測），
# 確認解壓後的本機路徑、私有 IP、信箱、本機禁用字都抓得到、白名單有效、乾淨的壓縮檔不誤報、太大的會被擋。
# 測資在這裡當場產生（全是合成字串），不進 git。最後一行：c1-public-check: OK／FAIL。
set -uo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
pc="$root/ci/public-check.sh"
work=$(mktemp -d "${TMPDIR:-/tmp}/dumpling-c1-pc.XXXXXX")
trap 'rm -rf "$work"' EXIT
fail=0
ok() { echo "ok: $*"; }
bad() { echo "FAIL: $*"; fail=1; }

repo="$work/repo"
mkdir -p "$repo/ci"
cp "$root/ci/public-patterns.txt" "$repo/ci/"
printf 'dumpling-pc-allow/opt\t合成的白名單項目（測試用）\n' > "$repo/ci/public-allow.txt"
printf 'zzsecretword\n' > "$work/private.txt"
g() { git -C "$repo" -c user.name=t -c user.email=t@example.com "$@"; }
g init -q
pc_run() { (cd "$repo" && bash "$pc" --rev HEAD --patterns ci/public-patterns.txt --allow ci/public-allow.txt "$@"); }

# 1) 乾淨的壓縮檔：不誤報
printf 'plain text\nmaintainer@example.com\nkernel-core@5.14.0-427.el9\n' | xz -c > "$repo/clean.json.xz"
g add -A && g commit -qm clean
out=$(pc_run --private "$work/private.txt"); rc=$?
if [ "$rc" -eq 0 ] && grep -q '^public-check: OK' <<< "$out"; then ok "乾淨的 .xz 不誤報"; else bad "乾淨的 .xz 被誤報：$out"; fi

# 2) 各種命中（每種壓縮格式一個）
printf 'line1\nwork dir /media/dumpling-pc-test/build\n' | xz -c > "$repo/a.json.xz"
printf 'x\ny\nhost 192.168.250.251 here\n' | gzip -nc > "$repo/b.txt.gz"
printf 'contact dev@pc-test-corp.com\n' | bzip2 -c > "$repo/c.txt.bz2"
printf 'one\nzzsecretword inside\n' | xz -c > "$repo/d.txt.xz"
printf 'allowed /media/dumpling-pc-allow/opt path\n' | gzip -nc > "$repo/e.txt.gz"
have_zstd=0
if command -v zstd >/dev/null 2>&1; then
  have_zstd=1
  printf 'zst 10.250.251.252 ip\n' | zstd -qc > "$repo/f.txt.zst"
fi
g add -A && g commit -qm hits
out=$(pc_run --private "$work/private.txt"); rc=$?
if [ "$rc" -eq 1 ]; then ok "有命中時 exit 1"; else bad "有命中時 exit 應為 1，實際 $rc"; fi
chk() { if grep -qF -- "$1" <<< "$out"; then ok "$2"; else bad "$2（找不到：$1）"; fi; }
chk 'a.json.xz（解壓後）:2:' ".xz 的本機路徑（含行號）"
chk 'b.txt.gz（解壓後）:3:' ".gz 的私有 IP（含行號）"
chk 'c.txt.bz2（解壓後）:1:dev@pc-test-corp.com' ".bz2 的信箱"
chk 'd.txt.xz（解壓後）:2:' ".xz 的本機禁用字"
if grep -qF 'e.txt.gz' <<< "$out"; then bad "白名單項目沒有放行：$(grep -F e.txt.gz <<< "$out")"; else ok "白名單對壓縮檔有效"; fi
if grep -qF 'clean.json.xz' <<< "$out"; then bad "乾淨的檔案被誤報"; else ok "乾淨的檔案仍不誤報"; fi
if [ "$have_zstd" = 1 ]; then chk 'f.txt.zst（解壓後）:1:' ".zst 的私有 IP"; else echo "NOT_RUN: .zst（runner 沒有 zstd）"; fi

# 3) 沒給 --private 時，禁用字那一段不跑（CI 的情況），其他照樣抓
out=$(pc_run); rc=$?
if [ "$rc" -eq 1 ] && ! grep -qF 'd.txt.xz' <<< "$out" && grep -qF 'a.json.xz（解壓後）' <<< "$out"; then ok "沒有私有清單時只跑通用規則與信箱"; else bad "沒有私有清單時的行為不對：$out"; fi

# 4) 解壓後太大：算命中（無法檢查）
g rm -q a.json.xz b.txt.gz c.txt.bz2 d.txt.xz e.txt.gz
[ "$have_zstd" = 1 ] && g rm -q f.txt.zst
head -c 4096 /dev/zero | xz -c > "$repo/big.bin.xz"
g add -A && g commit -qm big
out=$(cd "$repo" && PUBLIC_CHECK_ZLIMIT=1024 bash "$pc" --rev HEAD --patterns ci/public-patterns.txt --allow ci/public-allow.txt); rc=$?
if [ "$rc" -eq 1 ] && grep -qF 'big.bin.xz: 無法檢查（解壓後超過 1024 位元組）' <<< "$out"; then ok "超過大小上限算命中"; else bad "超過大小上限沒有被擋：$out"; fi

# 5) 壞掉的壓縮檔：算命中
printf 'not really xz' > "$repo/broken.txt.xz"
g add -A && g commit -qm broken
out=$(pc_run); rc=$?
if [ "$rc" -eq 1 ] && grep -qF 'broken.txt.xz: 無法檢查（解壓失敗' <<< "$out"; then ok "解不開的壓縮檔算命中"; else bad "解不開的壓縮檔沒有被擋：$out"; fi

if [ "$fail" -eq 0 ]; then echo "c1-public-check: OK"; else echo "c1-public-check: FAIL"; fi
exit "$fail"
