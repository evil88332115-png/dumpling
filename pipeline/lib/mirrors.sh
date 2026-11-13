#!/usr/bin/env bash
# 弱點資料鏡像的共用函式（source 進來用；各平台的 scan.sh 共用，不要各寫一份）。
#
#   source pipeline/lib/mirrors.sh
#   MIRRORS_DIR=<鏡像的輸出資料夾> MIRRORS_STEPS=<pipeline-steps.tsv> mirror <tools/mirror 底下的腳本> <資料夾名>
#   mirror_kernel_cve <資料夾名>        （kernel-cve.sh；有 $KCVE_CACHE_DIR 就當作上一份鏡像：沒變就沿用、上游連不上就退而求其次）
#
# 環境變數：
#   MIRRORS_DIR          必填。鏡像放這裡：<資料夾名>/、<資料夾名>.manifest、<資料夾名>.log、<資料夾名>.result（腳本最後一行）
#   MIRRORS_STEPS        pipeline-steps.tsv 的路徑；沒設就不記列（單獨使用時）
#   MIRRORS_SCRIPT_DIR   鏡像腳本所在資料夾（預設是這個 repo 的 tools/mirror）
#   MIRRORS_TRIES        最多試幾次（預設 3，每次換新資料夾）；MIRRORS_RETRY_DELAY 兩次之間等幾秒（預設 60）
#   KCVE_CACHE_DIR       上一份 kernel-cve 鏡像（actions/cache 還原出來的資料夾，裡面有 kernel-cves.zip 與 SOURCE）
#
# 結果看腳本輸出的最後一行：
#   OK …         成功。
#   ATTENTION …  成功，但用了舊資料頂替（例如 git.kernel.org 連不上、沿用 48 小時內的上一份）：繼續往下走，並在 pipeline-steps.tsv 記一列
#                「pipeline-<腳本名>-mirror	ATTENTION	0	<那一行>」（整體狀態因此不是 OK，也不會 FAIL；報告、release-meta.json、Release 說明都看得到）。
#   其他（含結束碼不是 0）  這一次失敗；試完 MIRRORS_TRIES 次都失敗 → mirror 回傳 1（弱點資料不完整，不能當作沒有漏洞）。
# 回傳值：0＝成功（OK 或 ATTENTION）；1＝失敗。呼叫端自己決定怎麼 fail。成功時印一行「鏡像 <名>：OK｜ATTENTION（…）」。
_mirrors_lib=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

mirror() {  # <腳本> <資料夾名>
  local s=$1 d=$2 n ok=0 tries=${MIRRORS_TRIES:-3} last=""
  local mir=${MIRRORS_DIR:?MIRRORS_DIR 必填} sd=${MIRRORS_SCRIPT_DIR:-$_mirrors_lib/../../tools/mirror}
  mkdir -p "$mir" || return 1
  for n in $(seq 1 "$tries"); do
    rm -rf "${mir:?}/$d" "$mir/$d.manifest" "$mir/$d.result"
    if bash "$sd/$s" "$mir/$d" "$mir/$d.manifest" > "$mir/$d.log" 2>&1; then
      last=$(grep -v '^[[:space:]]*$' "$mir/$d.log" | tail -n 1)
      case $last in OK|OK\ *|ATTENTION|ATTENTION\ *) ok=1; break;; esac
      echo "鏡像 $d 第 $n 次：結束碼 0，但最後一行不是 OK 或 ATTENTION：$(printf '%s' "$last" | cut -c1-200)"
    else
      echo "鏡像 $d 第 $n 次失敗：$(tail -n 1 "$mir/$d.log" | cut -c1-200)"
    fi
    [ "$n" = "$tries" ] || sleep "${MIRRORS_RETRY_DELAY:-60}"
  done
  if [ $ok != 1 ]; then tail -n 5 "$mir/$d.log"; return 1; fi
  printf '%s\n' "$last" > "$mir/$d.result"
  case $last in
    ATTENTION*)
      echo "鏡像 $d：ATTENTION（$(printf '%s' "$last" | cut -c1-300)）"
      echo "::warning::鏡像 $d 用了舊資料頂替：$(printf '%s' "$last" | cut -c1-300)"
      if [ -n "${MIRRORS_STEPS:-}" ]; then
        python3 -I "$_mirrors_lib/step_rows.py" append "$MIRRORS_STEPS" "${s%.sh}-mirror" ATTENTION 0 "$last" || return 1
      fi;;
    *) echo "鏡像 $d：OK（$(printf '%s' "$last" | cut -c1-160)）";;
  esac
}

mirror_kernel_cve() {  # <資料夾名>
  if [ -n "${KCVE_CACHE_DIR:-}" ] && [ -f "$KCVE_CACHE_DIR/SOURCE" ]; then
    KERNEL_CVE_REUSE_FROM=$KCVE_CACHE_DIR KERNEL_CVE_FALLBACK_FROM=$KCVE_CACHE_DIR mirror kernel-cve.sh "$1"
  else
    mirror kernel-cve.sh "$1"
  fi
}

# 這一份鏡像是這次新抓的嗎（可以存進 cache）？OK 結果、SOURCE 沒有 fallback=yes 才算；沿用或頂替的舊資料不能當新的存回去。
mirror_is_fresh() {  # <資料夾名>
  local d=$1 mir=${MIRRORS_DIR:?}
  [ -f "$mir/$d/SOURCE" ] && [ -f "$mir/$d.result" ] || return 1
  case $(head -n 1 "$mir/$d.result") in OK|OK\ *) ;; *) return 1;; esac
  ! grep -q '^fallback=yes' "$mir/$d/SOURCE"
}
