#!/usr/bin/env bash
# GitLab 範本 release:publish 的發布步驟（GITLAB-PORT T-21、T-17）：先全部驗完，再上傳附件，最後建 Release。
#
# 用法：bash gitlab/release-publish.sh <result 資料夾> <tag> <專案> <版本>
# 環境變數：CI_API_V4_URL、CI_PROJECT_ID、CI_JOB_TOKEN（GitLab 預先定義）；DUMPLING_RELEASE_DRY_RUN=1 時只驗證、不寫入。
#
# 順序（T-21）：
#   1. release-payload.py 驗 manifest：檔名安全、每個檔都在 result 資料夾、不是連結、不重複；產生 release.json。
#      驗不過 → FAIL，**一個檔都不上傳**，也不建 Release。
#   2. 上傳每個附件到 Generic Package Registry。
#   3. 用 Releases API 建 Release（assets links 指向剛上傳的檔）。
# dry run（T-17，代替 GitHub 的「只建 draft Release」）：只做第 1 步，列出「會上傳／會建立」的內容，
# **不呼叫任何寫入的 API**（不上傳 Package、不建 Release、不開 Issue）。
set -euo pipefail
res=${1:?result 資料夾}; tag=${2:?tag}; project=${3:?專案}; version=${4:?版本}
here=$(cd "$(dirname "$0")" && pwd)
dry=${DUMPLING_RELEASE_DRY_RUN:-0}
case $dry in 0|1) ;; *) echo "release: FAIL（DUMPLING_RELEASE_DRY_RUN 只能是 0 或 1）"; exit 1 ;; esac
: "${CI_API_V4_URL:?}" "${CI_PROJECT_ID:?}"

test -s "$res/manifest.tsv" || { echo "release: FAIL（scan 沒有產生 manifest.tsv）"; exit 1; }
# 1. 驗證（release-payload.py 會檢查每個附件都存在於 $res；驗不過就在這裡結束，後面的上傳不會執行）
# 上傳清單只用 release-payload.py 驗過、寫出來的那一份（release-files.txt）：bash 不再自己解析 manifest（#72 驗證應修 1）
rm -f release.json release-files.txt
python3 -I "$here/release-payload.py" --manifest "$res/manifest.tsv" --files-dir "$res" --tag "$tag" --project "$project" --version "$version" \
  --api-url "$CI_API_V4_URL" --project-id "$CI_PROJECT_ID" --notes "$res/notes.md" --out release.json --list-out release-files.txt
want=$(python3 -I -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["assets"]["links"]))' release.json)
have=$(grep -c . release-files.txt || true)
[ "$want" -ge 1 ] && [ "$have" = "$want" ] || { echo "release: FAIL（驗過的附件清單 $have 個，Release 連結 $want 個，不一致）"; exit 1; }

if [ "$dry" = 1 ]; then
  echo "release: DRY_RUN（DUMPLING_RELEASE_DRY_RUN=1：只驗證，沒有上傳 Package、沒有建立 Release）"
  while IFS= read -r f; do echo "  會上傳：$f"; done < release-files.txt
  echo "  會建立 Release：$tag（內容在 release.json）"
  exit 0
fi

: "${CI_JOB_TOKEN:?}"
# 2. 上傳（套件名稱＝專案，套件版本＝版本；tag 含斜線，不能直接當套件版本。套件名稱與版本的字元規則官方沒寫，待內部驗證）
# 清單每行都以換行結尾（release-payload.py 寫的）；|| [ -n "$f" ] 是多一層保險。上傳數要等於 Release 的連結數，才建 Release
n=0
while IFS= read -r f || [ -n "$f" ]; do
  curl --fail --silent --show-error --header "JOB-TOKEN: $CI_JOB_TOKEN" --upload-file "$res/$f" \
    "$CI_API_V4_URL/projects/$CI_PROJECT_ID/packages/generic/$project/$version/$f"
  n=$((n + 1))
done < release-files.txt
[ "$n" = "$want" ] || { echo "release: FAIL（上傳了 $n 個，Release 連結 $want 個，不建 Release）"; exit 1; }
# 3. 建 Release
curl --fail --silent --show-error --header "JOB-TOKEN: $CI_JOB_TOKEN" --header "Content-Type: application/json" \
  --data @release.json "$CI_API_V4_URL/projects/$CI_PROJECT_ID/releases"
echo
echo "release: OK（$tag）"
