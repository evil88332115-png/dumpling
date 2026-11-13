#!/usr/bin/env bash
# 下載 GitLab 官方的 CI JSON schema（固定 commit），核對 sha256 後才輸出檔案路徑。
#
#   gitlab/fetch-ci-schema.sh <輸出資料夾>
#   → 成功：最後一行印 schema 檔的路徑（給 GITLAB_CI_SCHEMA 用），結束碼 0
#   → sha256 不符或下載失敗：印 FAIL、刪掉檔案、結束碼 1（不使用未核對的檔案）
#
# 來源：gitlab-org/gitlab 的 app/assets/javascripts/editor/schema/ci.json，固定在下面的 commit。
# 換版本：三個值（SCHEMA_COMMIT、SCHEMA_SHA256、日期註解）一起改，commit 選發布至少兩週前的，改完要跑 tests/run.sh。
set -euo pipefail
SCHEMA_COMMIT=28aa2bf90771a11ecc2f86525bc8a70a49c4d810   # 2026-10-18 Allow empty tags array in CI schema
SCHEMA_SHA256=1c6eeb7d3a34c39996afbfe1ade220480eb05bbeae674e86d3c745dfeeded7fd
SCHEMA_URL="https://gitlab.com/gitlab-org/gitlab/-/raw/${SCHEMA_COMMIT}/app/assets/javascripts/editor/schema/ci.json"
out=${1:?用法：fetch-ci-schema.sh <輸出資料夾>}
mkdir -p "$out"
f="$out/ci.json"
rm -f "$f"
curl --fail --silent --show-error --location --max-time 120 --output "$f.part" "$SCHEMA_URL" || { rm -f "$f.part"; echo "fetch-ci-schema: FAIL（下載失敗）" >&2; exit 1; }
got=$(sha256sum "$f.part" | cut -d' ' -f1)
if [ "$got" != "$SCHEMA_SHA256" ]; then
  rm -f "$f.part"
  echo "fetch-ci-schema: FAIL（sha256 不符：預期 $SCHEMA_SHA256，實際 $got）" >&2
  exit 1
fi
mv "$f.part" "$f"
echo "fetch-ci-schema: OK（commit $SCHEMA_COMMIT，sha256 已核對）" >&2
echo "$f"
