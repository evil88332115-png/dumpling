#!/usr/bin/env bash
# gitlab/ 的規則檢查（C3，M5）：不連網，標準庫 unittest＋系統 python3 的 PyYAML（gitlab/tests/test_gitlab_ci.py）。
# 官方 CI JSON schema 驗證在 tests/run.d/c3-gitlab-schema.sh。
# DUMPLING_REQUIRE_TEST_DATA=1：缺 PyYAML 算失敗；沒設就印 NOT_RUN（不能印 OK）。
set -uo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
if ! ver=$(python3 -I -c 'import yaml; print(yaml.__version__)' 2>/dev/null); then
  if [ "${DUMPLING_REQUIRE_TEST_DATA:-}" = 1 ]; then echo "c3-gitlab: FAIL（沒有 PyYAML，且 DUMPLING_REQUIRE_TEST_DATA=1）"; exit 1; fi
  echo "c3-gitlab: NOT_RUN（系統 python3 沒有 PyYAML）"; exit 0
fi
echo "c3-gitlab: PyYAML $ver（系統 python3）"
bash -n "$root/gitlab/fetch-ci-schema.sh" || { echo "c3-gitlab: FAIL（fetch-ci-schema.sh 語法）"; exit 1; }
ut=$(python3 -I -m unittest discover -s "$root/gitlab/tests" -p 'test_*.py' -v 2>&1); rc=$?
echo "$ut" | tail -n 8
[ "$rc" -eq 0 ] || { echo "$ut" | tail -n 60; echo "c3-gitlab: FAIL"; exit 1; }
if echo "$ut" | grep -q "skipped"; then echo "c3-gitlab: 有測試被 skip（見上）"; fi
echo "c3-gitlab: OK（規則測試；官方 schema 驗證另見 c3-gitlab-schema）"
