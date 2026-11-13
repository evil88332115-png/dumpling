#!/usr/bin/env bash
# C1 M2 J 軌（Jetson 轉接器：安全解壓、元件核對、patch 規則、刷機包組裝、標準答案比對、release-meta）的單元測試：不連網、不下載 BSP、不編譯。
# 另外檢查 workflow 的 YAML 語法與 pipeline 腳本的語法。最後一行：c1-m2-jetson: OK／FAIL。
set -uo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$root" || exit 1
if ! python3 -c 'import yaml' 2> /dev/null; then echo "c1-m2-jetson: FAIL（缺少 PyYAML：apt install python3-yaml）"; exit 1; fi
log=$(mktemp "${TMPDIR:-/tmp}/c1-m2-jetson.XXXXXX")
trap 'rm -f "$log"' EXIT
fail=0
for f in pipeline/platforms/jetson/*.sh; do bash -n "$f" || { echo "語法錯誤：$f"; fail=1; }; done
if ! python3 -I -c '
import sys, yaml
for f in ("pipeline", "release", "dev"):
    d = yaml.safe_load(open(".github/workflows/%s.yml" % f, encoding="utf-8"))
    assert d.get("jobs"), f
    for name, job in d["jobs"].items():
        assert "timeout-minutes" in job or "uses" in job, "%s/%s 沒有 timeout-minutes" % (f, name)
print("workflow YAML OK")
' >> "$log" 2>&1; then cat "$log"; echo "c1-m2-jetson: FAIL（workflow YAML）"; exit 1; fi
if python3 -B -W ignore::ResourceWarning -m unittest discover -s tests -p 'test_jetson_*.py' -v >> "$log" 2>&1; then
  n=$(grep -c ' ok$' "$log" || true)
  [ "$fail" = 0 ] && { echo "c1-m2-jetson: OK（$n 項，python $(python3 -c 'import sys;print("%d.%d" % sys.version_info[:2])')）"; exit 0; }
else
  tail -60 "$log"
fi
echo "c1-m2-jetson: FAIL"
exit 1
