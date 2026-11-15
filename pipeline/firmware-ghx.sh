# shellcheck shell=bash
# 供 source：ghx＝帶重試的指令（照 .github/workflows/release.yml 的做法）。
# GitHub API 偶爾回 403 Resource not accessible by integration（原因還沒查出來）：每 GHX_SLEEP 秒（預設 30）重試、最多 GHX_TRIES 次（預設 8），
# 仍失敗就印出 API 回應標頭與本文當診斷，回傳 1。用法：ghx gh api …；ghx 函式名稱 參數…（函式也可以）。
# 指令的結束碼 3 是確定的答案（不是暫時性的失敗），不重試，原樣回傳（gh 本身不用 3；firmware-release-publish.sh 用它表示「已有非草稿的 Release」）。
ghx() {
  local n=0 rc
  until "$@"; do
    rc=$?
    [ "$rc" -eq 3 ] && return 3
    n=$((n+1))
    if [ "$n" -ge "${GHX_TRIES:-8}" ]; then
      echo "---- 診斷：$*"
      gh api -i "repos/${GH_REPO:-${GITHUB_REPOSITORY:-}}/releases?per_page=1" 2>&1 | head -30
      return 1
    fi
    sleep "${GHX_SLEEP:-30}"
  done
}
