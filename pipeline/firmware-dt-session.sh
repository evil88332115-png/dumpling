#!/usr/bin/env bash
# 韌體 SBOM 上傳 DT 的外層（T-04）：DT 的起停交給 pipeline/lib/dt-session.sh（DUMPLING_DT_MODE，T-14），中間跑 firmware-dt.sh。
# 用法：pipeline/firmware-dt-session.sh <firmware-dt.sh 的參數…>     參數原樣轉給 firmware-dt.sh，其中的 --result 也是 dt-session 的 $out
#       需要環境變數 PILOT_ENV（pilot.env 的路徑；裡面有 API key，不能在 --result 底下，dt_ready 會擋）
# DUMPLING_DT_MODE 沒設（ephemeral）：dt-ephemeral.sh up → wait → env "$PILOT_ENV" → firmware-dt.sh → down（EXIT），
#   和 T-04 之前 firmware.yml 分開寫的 up／wait／env／down 相同：
#   - DT_OSV_ECOSYSTEMS 沒設時用 PyPI,npm,Ubuntu；DT_WAIT_MIN 沒設時用 40（dt-ephemeral.sh 的預設；dt_begin 自己的預設是 60）
#   - wait 的結束碼寫進 <結果>/dt-wait.rc（dt-session 的 DT_WAIT_RC_FILE）：0、3 繼續（3＝GAP，report 把所有樣本標 GAP），其他值 FAIL
#   - MIRROR_REFRESH_STATUS 設成空字串（臨時 DT 沒有常駐環境的鏡像狀態檔）
#   - down 失敗不改結束碼，只印 WARNING（dt_end；GitHub 的 runner 用完就丟）
# resident：dt_begin 檢查連線檔；GitHub Actions 上一律 FAIL（dt_begin 的檢查，這裡不另外放行）；不寫 dt-wait.rc；不設 MIRROR_REFRESH_STATUS。
# 退出碼：firmware-dt.sh 的退出碼；DT 沒有就緒（up 失敗、wait 不是 0／3、env 失敗、resident 的檢查）→ 1，不跑 firmware-dt.sh；參數錯誤 → 64。
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/.." && pwd)
fail() { echo "firmware-dt-session: FAIL（$*）"; exit 1; }

[ -n "${PILOT_ENV:-}" ] || { echo "firmware-dt-session: 缺少 PILOT_ENV" >&2; exit 64; }
out=""; args=("$@")
for i in "${!args[@]}"; do
  [ "${args[$i]}" = --result ] && out=${args[$((i + 1))]:-}       # 和 firmware-dt.sh 一樣：最後一個 --result 為準
done
[ -n "$out" ] || { echo "firmware-dt-session: 缺少 --result（用法同 firmware-dt.sh）" >&2; exit 64; }
mkdir -p "$out" || exit 64
rm -f "$out/dt-wait.rc"          # 不讓上一次的結束碼混進這次的 report（resident 不寫這個檔）

# shellcheck disable=SC1091 # 路徑用變數組（$root），shellcheck 跟不到
. "$root/pipeline/lib/dt-session.sh"
export DT_WAIT_MIN=${DT_WAIT_MIN:-40}
if [ "$(dt_mode)" = ephemeral ]; then export DT_WAIT_RC_FILE=$out/dt-wait.rc; else unset DT_WAIT_RC_FILE; fi
dt_begin PyPI,npm,Ubuntu
t0=$(date +%s)
dt_ready "$PILOT_ENV"
echo "firmware-dt-session: DT 就緒（$(dt_mode)；dt_ready 用時 $(( $(date +%s) - t0 )) 秒${DT_WAIT_RC_FILE:+；wait 結束碼 $(cat "$DT_WAIT_RC_FILE")}）"
export PILOT_ENV MIRROR_REFRESH_STATUS=""
dt_mirror_status
rc=0
"$here/firmware-dt.sh" "$@" || rc=$?
exit "$rc"
