#!/usr/bin/env bash
# M2 可行性試驗（spike）的量測函式，以 source 載入。只量測，不是正式流程。
# 提供：init_res、snap_df、timed <標籤> <指令…>、sampler_start/sampler_stop、report_md
# 紀錄放 $RES：steps.tsv（每個 timed 一列）、samples.tsv（背景取樣）。
RES=${RES:-${RUNNER_TEMP:-.}/m2res}
export RES
# 要一起看的第二個掛載點（/mnt 是 runner 的暫存碟）；沒有就只看 /
MNT=${MNT:-/mnt}

init_res() {
  mkdir -p "$RES"
  [ -f "$RES/steps.tsv" ] || printf 'label\tsecs\trc\troot_avail_before\troot_avail_after\tmnt_avail_before\tmnt_avail_after\tmem_avail_after\n' > "$RES/steps.tsv"
}

# 目錄所在檔案系統的可用位元組
avail_b() { df -B1 --output=avail "$1" 2> /dev/null | tail -1 | tr -d ' ' || echo NA; }
mem_avail_b() { awk '/^MemAvailable:/{print $2*1024}' /proc/meminfo; }

# 印出 df -B1、free -b 與（可選）du，標上標籤
snap_df() {
  echo "::group::snap $1"
  df -B1 / "$MNT" 2> /dev/null || df -B1 /
  free -b | sed -n '1,2p'
  echo "::endgroup::"
}

# timed <標籤> <指令…>：量時間與 / 、/mnt 可用空間（前後），記到 steps.tsv；回傳指令的退出碼
timed() {
  local label=$1; shift
  local r0 m0 t0 rc=0 r1 m1 t1
  r0=$(avail_b /); m0=$(avail_b "$MNT"); t0=$(date +%s.%N)
  echo "$label" > "$RES/cur-label"
  echo "::group::[$label]"
  "$@" || rc=$?
  echo "::endgroup::"
  t1=$(date +%s.%N); r1=$(avail_b /); m1=$(avail_b "$MNT")
  local dt; dt=$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.1f", b-a}')
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$label" "$dt" "$rc" "$r0" "$r1" "$m0" "$m1" "$(mem_avail_b)" >> "$RES/steps.tsv"
  echo "[$label] rc=$rc ${dt}s / 可用 ${r0}→${r1}（/mnt ${m0}→${m1}）"
  echo "-" > "$RES/cur-label"
  return "$rc"
}

# 背景取樣：每 $1 秒（預設 10）記 epoch、目前標籤、/ 與 /mnt 可用、MemAvailable、loadavg
sampler_start() {
  local iv=${1:-10}
  [ -f "$RES/samples.tsv" ] || printf 'epoch\tlabel\troot_avail\tmnt_avail\tmem_avail\tload1\n' > "$RES/samples.tsv"
  (
    while :; do
      printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$(date +%s)" "$(cat "$RES/cur-label" 2> /dev/null || echo -)" "$(avail_b /)" "$(avail_b "$MNT")" "$(mem_avail_b)" "$(cut -d' ' -f1 /proc/loadavg)" >> "$RES/samples.tsv"
      sleep "$iv"
    done
  ) &
  echo $! > "$RES/sampler.pid"
}
sampler_stop() { [ -f "$RES/sampler.pid" ] && kill "$(cat "$RES/sampler.pid")" 2> /dev/null; rm -f "$RES/sampler.pid"; return 0; }

gib() { awk -v b="$1" 'BEGIN{ if (b ~ /^-?[0-9]+$/) printf "%.2f", b/1073741824; else print b }'; }

# 把 steps.tsv 與取樣峰值做成 markdown（寫到 stdout）
report_md() {
  echo "### 各步驟（秒、可用空間 GiB：前→後；負的變化 = 用掉）"
  echo
  echo "| 步驟 | 秒 | rc | / 前 | / 後 | / 變化 | /mnt 前 | /mnt 後 | 後記憶體可用 |"
  echo "|---|---:|---:|---:|---:|---:|---:|---:|---:|"
  awk -F'\t' 'function g(b){ return sprintf("%.2f", b/1073741824) }
    NR>1 { printf "| %s | %s | %s | %s | %s | %s | %s | %s | %s |\n", $1, $2, $3, g($4), g($5), g($5-$4), g($6), g($7), g($8) }' "$RES/steps.tsv"
  if [ -f "$RES/samples.tsv" ]; then
    echo
    echo "### 背景取樣的最低可用空間／記憶體（GiB）與最高 load"
    echo
    echo "| 標籤 | 樣本數 | / 最低 | /mnt 最低 | 記憶體最低 | load 最高 |"
    echo "|---|---:|---:|---:|---:|---:|"
    awk -F'\t' 'function g(b){ return sprintf("%.2f", b/1073741824) }
      NR>1 { l=$2; n[l]++; if(!(l in r)||$3<r[l]) r[l]=$3; if(!(l in m)||$4<m[l]) m[l]=$4; if(!(l in e)||$5<e[l]) e[l]=$5; if($6>x[l]) x[l]=$6 }
      END { for (l in n) printf "| %s | %d | %s | %s | %s | %s |\n", l, n[l], g(r[l]), g(m[l]), g(e[l]), x[l] }' "$RES/samples.tsv" | sort
  fi
}
