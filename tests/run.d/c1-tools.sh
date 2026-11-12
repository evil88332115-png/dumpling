#!/usr/bin/env bash
# C1 工具（tools/）的單元測試：先檢查 PROVENANCE，再在 venv 裡跑 pytest。
# C2 的 test_x86_firmware*.py 由 c2-x86-firmware.sh 跑，這裡略過。
# 需要網路、Docker、bwrap 權限或外部測試資料的測試會自己 skip；這裡把 skip 當成 NOT_RUN 列出數量與原因，不算通過。
# venv 用 --system-site-packages（沿用系統的 PyYAML），pytest 等套件固定版本（tools/cra/tests/requirements.txt）。
# 最後一行：c1-tools: OK／FAIL（passed、failed、NOT_RUN 數）。
set -uo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$root" || exit 1

if ! bash ci/provenance-check.sh; then
  echo "c1-tools: FAIL（PROVENANCE 與 tools/ 不一致）"
  exit 1
fi

# 需要 Python 3.12 以上：程式用了 3.12 的語法（例如巢狀同引號的 f-string）。優先 python3.12，沒有才看 python3 的版本。
py=""
for c in python3.12 python3; do
  if command -v "$c" > /dev/null 2>&1 && "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' 2> /dev/null; then py=$c; break; fi
done
if [ -z "$py" ]; then
  echo "c1-tools: FAIL（找不到 Python 3.12 以上：tools/ 的程式用了 3.12 的語法；python3 是 $(python3 --version 2>&1)）"
  exit 1
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/dumpling-c1-tools.XXXXXX")
trap 'rm -rf "$work"' EXIT
"$py" -m venv --system-site-packages "$work/venv" || { echo "c1-tools: FAIL（建不起 venv）"; exit 1; }
"$work/venv/bin/python" -m pip install -q --disable-pip-version-check -r tools/cra/tests/requirements.txt \
  || { echo "c1-tools: FAIL（裝不起測試套件）"; exit 1; }

log="$work/pytest.log"
"$work/venv/bin/python" -m pytest tools -q -p no:cacheprovider -rs --basetemp="$work/pytest" \
  --ignore-glob='*/test_x86_firmware*.py' 2>&1 | tee "$log"
rc=${PIPESTATUS[0]}

summary=$(grep -E '^(=+ )?[0-9]+ (passed|failed|skipped|error)' "$log" | tail -1)
passed=$(grep -oE '[0-9]+ passed' <<< "$summary" | grep -oE '[0-9]+' || true)
failed=$(grep -oE '[0-9]+ (failed|error)' <<< "$summary" | awk '{s += $1} END {print s + 0}')
skipped=$(grep -oE '[0-9]+ skipped' <<< "$summary" | grep -oE '[0-9]+' || true)
echo "---- NOT_RUN（被 skip 的測試，依原因；數量 原因）----"
grep -E '^SKIPPED \[[0-9]+\]' "$log" | sed -E 's/^SKIPPED \[([0-9]+)\] [^:]+:[0-9]+: /\1\t/' \
  | awk -F'\t' '{c[$2] += $1} END {for (r in c) printf "%d\t%s\n", c[r], r}' | sort -rn | cut -c1-200
echo "----"
if [ "$rc" -eq 0 ]; then
  echo "c1-tools: OK（passed=${passed:-0}、NOT_RUN(skipped)=${skipped:-0}）"
  exit 0
fi
echo "c1-tools: FAIL（pytest exit $rc；passed=${passed:-0}、failed=${failed:-?}、NOT_RUN(skipped)=${skipped:-0}）"
exit 1
