#!/usr/bin/env bash
# 示範的原始磁區清點：寫一份空的 regions 清單到 $DUMPLING_OUT/raw-sectors.json。
printf '{"schema": 1, "platform": "example", "regions": []}\n' > "$DUMPLING_OUT/raw-sectors.json"
echo "raw-sectors: OK（0 個區段）"
