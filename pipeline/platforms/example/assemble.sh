#!/usr/bin/env bash
# 示範：assemble 時呼叫選用掛點 raw-sectors，再把兩步的結果合成一行狀態。
here=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
bash "$here/platform.sh" raw-sectors "$1" "$2" > /dev/null || { echo "assemble: FAIL（raw-sectors 失敗）"; exit 1; }
echo "assemble: OK（example 平台 $DUMPLING_PROJECT $2）"
