#!/usr/bin/env bash
# 單元測試總入口（CI 的 unit-tests job 會執行）。
# 每個工作包在 tests/run.d/ 放自己的腳本（例如 c1-tools.sh、c2-firmware.sh），這裡依檔名順序全部執行。
# 不改這個檔案，只加自己的 run.d 腳本，避免多個對話改同一個檔。
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
shopt -s nullglob
suites=("$here"/run.d/*.sh)
if [ ${#suites[@]} -eq 0 ]; then
  echo "unit-tests: NOT_RUN（tests/run.d/ 還沒有測試）"
  exit 0
fi
fail=0
for s in "${suites[@]}"; do
  name=$(basename "$s" .sh)
  echo "::group::$name"
  if bash "$s"; then rc=0; else rc=$?; fi
  echo "::endgroup::"
  if [ "$rc" -eq 0 ]; then echo "suite $name: OK"; else echo "suite $name: FAIL（exit $rc）"; fail=1; fi
done
[ "$fail" -eq 0 ] && echo "unit-tests: OK（${#suites[@]} 組）" || echo "unit-tests: FAIL"
exit "$fail"
