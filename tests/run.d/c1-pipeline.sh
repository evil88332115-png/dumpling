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
printf "DT_URL=http://127.0.0.1:1\nDT_API_KEY=x\n" > "${TMPDIR:-.}/c1-pipeline.env"
chk_rc 64 env PILOT_ENV="${TMPDIR:-.}/c1-pipeline.env" python3 -I "$root/pipeline/dt-verify.py"
rm -f "${TMPDIR:-.}/c1-pipeline.env"
chk python3 -I -c "import json;[json.load(open('$root/tests/fixtures/sbom/'+f)) for f in ('smoke.cdx.json','smoke.expected.json')]"
if [ "$fail" -eq 0 ]; then echo "c1-pipeline: OK"; else echo "c1-pipeline: FAIL"; fi
exit "$fail"
