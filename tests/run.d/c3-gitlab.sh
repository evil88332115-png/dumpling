#!/usr/bin/env bash
# gitlab/ 的檢查（C3，M5）：
#   1) 不連網的規則檢查與 release-payload 單元測試（gitlab/tests/test_gitlab_ci.py，標準庫 unittest＋PyYAML）
#   2) 官方 CI JSON schema 驗證：只有環境變數 GITLAB_CI_SCHEMA 指向「已核對 sha256」的 schema 檔才跑（用 gitlab/fetch-ci-schema.sh 取得），
#      沒有就印 NOT_RUN 與原因，不算失敗。需要 jsonschema（CI 裡用 pip install --require-hashes 安裝固定版本）。
set -uo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
fail=0
if ! python3 -I -c 'import yaml' 2>/dev/null; then
  if [ "${DUMPLING_REQUIRE_TEST_DATA:-}" = 1 ]; then echo "c3-gitlab: FAIL（沒有 PyYAML，且 DUMPLING_REQUIRE_TEST_DATA=1）"; exit 1; fi
  echo "c3-gitlab: NOT_RUN（沒有 PyYAML）"; exit 0
fi
ut=$(python3 -I -m unittest discover -s "$root/gitlab/tests" -p 'test_*.py' 2>&1); rc=$?
echo "$ut" | tail -n 5
[ "$rc" -eq 0 ] || { echo "FAIL: gitlab unittest"; echo "$ut" | tail -n 60; fail=1; }
bash -n "$root/gitlab/fetch-ci-schema.sh" || { echo "FAIL: fetch-ci-schema.sh 語法"; fail=1; }

schema=${GITLAB_CI_SCHEMA:-}
if [ -z "$schema" ]; then
  echo "c3-gitlab-schema: NOT_RUN（沒有設定 GITLAB_CI_SCHEMA；官方 schema 要由 gitlab/fetch-ci-schema.sh 下載並核對 sha256 後才能用，本機測試不連網）"
elif [ ! -f "$schema" ]; then
  echo "c3-gitlab-schema: FAIL（GITLAB_CI_SCHEMA 指向的檔案不存在）"; fail=1
else
  want=$(sed -n 's/^SCHEMA_SHA256=\([0-9a-f]*\).*/\1/p' "$root/gitlab/fetch-ci-schema.sh")
  got=$(sha256sum "$schema" | cut -d' ' -f1)
  if [ "$want" != "$got" ]; then
    echo "c3-gitlab-schema: FAIL（schema 的 sha256 與 fetch-ci-schema.sh 固定的值不符）"; fail=1
  else
    python3 -I "$root/gitlab/tests/validate_schema.py" "$schema" "$root/gitlab/.gitlab-ci.yml"; rc=$?
    case $rc in
      0) echo "c3-gitlab-schema: OK";;
      2) echo "c3-gitlab-schema: FAIL（缺 jsonschema 或 PyYAML；schema 已指定就必須能驗證）"; fail=1;;
      *) echo "c3-gitlab-schema: FAIL（.gitlab-ci.yml 不符官方 schema）"; fail=1;;
    esac
    # 反向測試：故意弄壞的檔案必須被擋下（確認驗證真的有作用）
    bad=$(mktemp "${TMPDIR:-/tmp}/c3-gitlab-bad.XXXXXX")
    printf 'stages: [a]\njob:\n  stage: a\n  scrpt: [echo]\n  rules: nope\n' > "$bad"
    if python3 -I "$root/gitlab/tests/validate_schema.py" "$schema" "$bad" >/dev/null 2>&1; then
      echo "c3-gitlab-schema: FAIL（壞檔案竟然通過）"; fail=1
    else
      echo "c3-gitlab-schema: 反向測試 OK（壞檔案被擋下）"
    fi
    rm -f "$bad"
  fi
fi
[ "$fail" -eq 0 ] && echo "c3-gitlab: OK" || echo "c3-gitlab: FAIL"
exit "$fail"
