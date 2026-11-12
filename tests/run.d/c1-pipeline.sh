#!/usr/bin/env bash
# pipeline/ 的單元測試（不需要 Docker）
set -uo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
fail=0
chk() { if "$@" >/dev/null 2>&1; then echo "ok: $*"; else echo "FAIL: $*"; fail=1; fi; }
chk_rc() { local want=$1; shift; "$@" >/dev/null 2>&1; local rc=$?; if [ "$rc" = "$want" ]; then echo "ok: rc=$rc $*"; else echo "FAIL: rc=$rc（預期 $want）$*"; fail=1; fi; }
chk_rc 64 bash "$root/pipeline/dt-ephemeral.sh"
chk_rc 64 bash "$root/pipeline/dt-ephemeral.sh" bogus
chk_rc 1 env DT_EPH_DIR=/nonexistent-dt-eph bash "$root/pipeline/dt-ephemeral.sh" wait
# up：生態系清單格式不合要在碰 docker 之前就失敗（值會傳給 DT 的設定）
chk_rc 1 env DT_OSV_ECOSYSTEMS="PyPI';import os" bash "$root/pipeline/dt-ephemeral.sh" up
chk_int() { # 要同時看到退出碼 1 和「必須是正整數」（不是因為找不到狀態檔才失敗）
  local out; out=$(env "$1=$2" DT_EPH_DIR=/nonexistent-dt-eph bash "$root/pipeline/dt-ephemeral.sh" wait 2>&1); local rc=$?
  if [ "$rc" = 1 ] && grep -q "$1 必須是正整數" <<< "$out"; then echo "ok: $1=$2 被拒絕"; else echo "FAIL: $1=$2（rc=$rc）"; fail=1; fi
}
# 數字型環境變數不是正整數 → 在碰 docker 或進算術之前就失敗
for v in DT_PORT DT_UP_TIMEOUT_SEC DT_WAIT_MIN DT_OPTIONAL_GRACE_MIN DT_API_KEY_DAYS; do
  for bad in abc 0 -1 "1;id" "1 2" "\$(id)"; do
    chk_int "$v" "$bad"
  done
done
# down 的保護：只刪有標記檔的狀態資料夾（用假的 docker，不需要 Docker）
w=$(mktemp -d "${TMPDIR:-/tmp}/c1-pipeline.XXXXXX")
mkdir -p "$w/bin" "$w/marked" "$w/unmarked"
printf '#!/bin/sh\nexit 0\n' > "$w/bin/docker"; chmod +x "$w/bin/docker"
: > "$w/marked/.dumpling-dt-eph"; : > "$w/unmarked/keep.txt"
chk_rc 0 env PATH="$w/bin:$PATH" DT_EPH_DIR="$w/marked" bash "$root/pipeline/dt-ephemeral.sh" down
chk_rc 0 env PATH="$w/bin:$PATH" DT_EPH_DIR="$w/unmarked" bash "$root/pipeline/dt-ephemeral.sh" down
chk test ! -e "$w/marked"
chk test -f "$w/unmarked/keep.txt"
rm -rf "$w"
# scan-status-check：必要階段全 OK 才過；有 FAIL 或必要階段缺／NOT_RUN 都不過
t=$(mktemp -d "${TMPDIR:-/tmp}/c1-pipeline.XXXXXX")
need="A-source B-sandbox B-sandbox-secrets B-sbom-provided C-grype C-upload-sbom D-dt-project D-dt-upload D-dt-bom-processing D-dt-vuln-analysis F-secret-scan"
{ printf 'stage\tstatus\tdetail\n'; for s in $need; do printf '%s\tOK\tx\n' "$s"; done; printf 'E-notice\tNOT_RUN\t--no-license\n'; } > "$t/ok.tsv"
chk_rc 0 python3 -I "$root/pipeline/scan-status-check.py" "$t/ok.tsv"
sed 's/^D-dt-upload\tOK/D-dt-upload\tFAIL/' "$t/ok.tsv" > "$t/fail.tsv"
chk_rc 1 python3 -I "$root/pipeline/scan-status-check.py" "$t/fail.tsv"
sed 's/^C-grype\tOK/C-grype\tNOT_RUN/' "$t/ok.tsv" > "$t/notrun.tsv"
chk_rc 1 python3 -I "$root/pipeline/scan-status-check.py" "$t/notrun.tsv"
grep -v '^D-dt-bom-processing' "$t/ok.tsv" > "$t/missing.tsv"
chk_rc 1 python3 -I "$root/pipeline/scan-status-check.py" "$t/missing.tsv"
# 後來加的必要階段：缺任何一個、或不是 OK（GAP）都不過
for s in B-sandbox C-upload-sbom D-dt-vuln-analysis; do
  grep -v "^$s	" "$t/ok.tsv" > "$t/missing-$s.tsv"
  chk_rc 1 python3 -I "$root/pipeline/scan-status-check.py" "$t/missing-$s.tsv"
  sed "s/^$s	OK/$s	GAP/" "$t/ok.tsv" > "$t/gap-$s.tsv"
  chk_rc 1 python3 -I "$root/pipeline/scan-status-check.py" "$t/gap-$s.tsv"
done
rm -rf "$t"
printf "DT_URL=http://127.0.0.1:1\nDT_API_KEY=x\n" > "${TMPDIR:-.}/c1-pipeline.env"
chk_rc 64 env PILOT_ENV="${TMPDIR:-.}/c1-pipeline.env" python3 -I "$root/pipeline/dt-verify.py"
rm -f "${TMPDIR:-.}/c1-pipeline.env"
chk python3 -I -c "import json;[json.load(open('$root/tests/fixtures/sbom/'+f)) for f in ('smoke.cdx.json','smoke.expected.json')]"
if [ "$fail" -eq 0 ]; then echo "c1-pipeline: OK"; else echo "c1-pipeline: FAIL"; fi
exit "$fail"
