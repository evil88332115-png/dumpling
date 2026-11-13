#!/usr/bin/env bash
# scan job 的「安裝工具」：依 platform.yml 的 scan.tools 裝掃描工具（版本固定在 tools/e2e/install-tools.sh）。
#
#   pipeline/install-scan-tools.sh <sbom-only|full> <版本紀錄檔>
#
#   sbom-only（預設）  install-tools.sh --sbom-only：Syft、Grype、bubblewrap。二進位裝到 $RUNNER_TEMP 再 install 進 /usr/local/bin
#                      （sca-scan 的沙箱遮蔽家目錄與 runner 目錄，工具不能在那裡）。
#   full               install-tools.sh 不帶旗標：Syft、Grype、cdxgen、govulncheck、guarddog、bubblewrap。git／dir 模式的 sca-scan（A-tools）
#                      檢查整套工具的版本，只裝一部分會讓 A-tools 回 ATTENTION 或 FAIL，所以不分項。
#                      裝在 /opt/dumpling-tools（沙箱只遮蔽家目錄與 runner 目錄，/opt 與 /usr/local 看得到）：
#                      syft、grype、govulncheck 用 install 進 /usr/local/bin；guarddog 在 /usr/local/bin 是符號連結，指向
#                      /opt/dumpling-tools/bin/guarddog，再指向 /opt/dumpling-tools/venv-guarddog（venv 不在家目錄裡）；
#                      cdxgen 是 npm 全域套件，沒在 /usr 或 /opt 底下就以符號連結放進 /usr/local/bin。
#   其他值             結束碼 64。
# full 裝完用和 sca-scan 沙箱一樣的遮蔽（家目錄與 runner 目錄蓋成空的 tmpfs）確認每個工具都跑得起來；任何一個看不到就失敗。
# 最後一行：install-scan-tools: OK（模式、工具）。
set -euo pipefail
mode=${1:-}; rec=${2:-}
case $mode in sbom-only|full) ;; *) echo "install-scan-tools: FAIL（模式必須是 sbom-only 或 full：$mode）"; exit 64;; esac
[ -n "$rec" ] || { echo "用法：install-scan-tools.sh <sbom-only|full> <版本紀錄檔>" >&2; exit 64; }
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/.." && pwd)
tmp=${RUNNER_TEMP:-${TMPDIR:-/tmp}}

if [ "$mode" = sbom-only ]; then
  bin=$tmp/tools/bin; mkdir -p "$tmp/tools"
  bash "$root/tools/e2e/install-tools.sh" "$bin" "$rec" --sbom-only
  # 放進 /usr/local/bin：sca-scan 的沙箱遮蔽家目錄與 runner 目錄，工具不能在那裡
  sudo install -m 0755 -t /usr/local/bin "$bin/syft" "$bin/grype"
  tools=(syft grype)
else
  bin=/opt/dumpling-tools/bin
  sudo install -d -o "$(id -u)" -g "$(id -g)" /opt/dumpling-tools
  bash "$root/tools/e2e/install-tools.sh" "$bin" "$rec"
  sudo install -m 0755 -t /usr/local/bin "$bin/syft" "$bin/grype" "$bin/govulncheck"
  [ -e "$bin/guarddog" ] || { echo "install-scan-tools: FAIL（沒有 $bin/guarddog）"; exit 1; }
  sudo ln -sf "$bin/guarddog" /usr/local/bin/guarddog              # 符號連結：指向 /opt 底下的 venv（不是家目錄）
  cdx=$(command -v cdxgen || true)
  [ -n "$cdx" ] || { echo "install-scan-tools: FAIL（npm 全域安裝後找不到 cdxgen）"; exit 1; }
  cdx=$(readlink -f "$cdx")
  case $cdx in /usr/*|/opt/*) [ -e /usr/local/bin/cdxgen ] || sudo ln -sf "$cdx" /usr/local/bin/cdxgen;; *) sudo ln -sf "$cdx" /usr/local/bin/cdxgen;; esac
  tools=(syft grype cdxgen govulncheck guarddog)
fi
cat "$rec"

# full 才檢查（sbom-only 的行為和以前完全一樣，不多加檢查）。沙箱看得到嗎：家目錄與 runner 目錄蓋成 tmpfs（同 tools/e2e/sandbox.sh），工具用絕對路徑 /usr/local/bin/<名稱> 呼叫
if [ "$mode" = sbom-only ]; then echo "install-scan-tools: OK（sbom-only：${tools[*]}）"; exit 0; fi
hide=(--tmpfs "$HOME")
case ${RUNNER_TEMP:-} in "$HOME"/*) ;; ?*) hide+=(--tmpfs "$RUNNER_TEMP");; esac
for t in "${tools[@]}"; do
  case $t in
    syft|grype) v=(version);; govulncheck) v=(-version);; *) v=(--version);;
  esac
  if ! bwrap --unshare-pid --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp "${hide[@]}" "/usr/local/bin/$t" "${v[@]}" > /dev/null 2>&1; then
    echo "install-scan-tools: FAIL（沙箱（家目錄遮蔽）裡跑不起 /usr/local/bin/$t：$(readlink -f "/usr/local/bin/$t")）"; exit 1
  fi
done
echo "install-scan-tools: OK（$mode：${tools[*]}；沙箱遮蔽家目錄後都看得到）"
