#!/usr/bin/env bash
# 【只在更新 schema 時由人手動執行；測試不會呼叫它，也不連網】
# 下載 GitLab 官方 CI JSON schema 到暫存資料夾，核對 sha256，印出 repo 裡現有檔與新下載檔的 sha256。**不會覆蓋 repo 裡的檔。**
#
#   gitlab/fetch-ci-schema.sh [<commit>]
#   不帶 commit：下載 repo 目前固定的 commit，sha256 必須等於固定值（不符就 FAIL，結束碼 1）。
#   帶其他 commit：下載並印出新的 sha256 與路徑，由人決定要不要更新（更新步驟見 gitlab/tests/data/gitlab-ci-schema/SOURCE.md）。
#
# 更新時三個固定值一起改：這裡的 PIN_COMMIT／PIN_SHA256、tests/run.d/c3-gitlab-schema.sh 的 PIN_SHA256、SOURCE.md 與 docs/PROVENANCE.md。
# 另外要重新核對 LICENSE.md 與上游 NOTICE 有沒有變。
set -euo pipefail
PIN_COMMIT=28aa2bf90771a11ecc2f86525bc8a70a49c4d810   # 2026-10-18 Allow empty tags array in CI schema
PIN_SHA256=1c6eeb7d3a34c39996afbfe1ade220480eb05bbeae674e86d3c745dfeeded7fd
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_file="$here/tests/data/gitlab-ci-schema/ci.json"
commit=${1:-$PIN_COMMIT}
[[ $commit =~ ^[0-9a-f]{40}$ ]] || { echo "fetch-ci-schema: FAIL（commit 必須是 40 碼十六進位）" >&2; exit 64; }
tmp=$(mktemp -d "${TMPDIR:-/tmp}/fetch-ci-schema.XXXXXX")
base="https://gitlab.com/gitlab-org/gitlab/-/raw/${commit}/app/assets/javascripts/editor/schema"
curl --fail --silent --show-error --location --max-time 120 --output "$tmp/ci.json" "$base/ci.json" || { echo "fetch-ci-schema: FAIL（下載失敗）" >&2; exit 1; }
curl --fail --silent --show-error --location --max-time 120 --output "$tmp/NOTICE" "$base/NOTICE" || echo "fetch-ci-schema: 注意（上游沒有 NOTICE？）" >&2
new=$(sha256sum "$tmp/ci.json" | cut -d' ' -f1)
old=$(sha256sum "$repo_file" | cut -d' ' -f1)
echo "repo 裡的 ci.json  sha256: $old"
echo "新下載的 ci.json   sha256: $new（commit $commit）"
echo "暫存資料夾: $tmp"
if [ "$commit" = "$PIN_COMMIT" ] && [ "$new" != "$PIN_SHA256" ]; then
  echo "fetch-ci-schema: FAIL（固定 commit 的 sha256 不符：預期 $PIN_SHA256）" >&2
  exit 1
fi
[ "$new" = "$old" ] && echo "fetch-ci-schema: OK（與 repo 裡的檔相同，沒有變動）" || echo "fetch-ci-schema: DIFF（與 repo 裡的檔不同；沒有覆蓋，更新步驟見 SOURCE.md）"
