#!/usr/bin/env bash
# 在 GitHub Actions runner 安裝 0007 用過的同版本工具（連網環境；不是離線部署）。
# 用法：install-tools.sh <bin 目錄> <紀錄檔> [--sbom-only]
#   --sbom-only  只裝 `tools/pilot/sca-scan --sbom` 需要的：Syft、Grype（固定版本）與 bubblewrap（含放寬 userns 限制）；
#                不裝 cdxgen、govulncheck、guarddog（dt-smoke 用；原始碼掃描才需要那些）。
# 版本與 0007（tests/results/round7-real-projects-20261022/versions-and-state.txt）相同；
# 資料庫（Grype DB、Go vulndb、DT 的 OSV）在這裡是線上最新版，與 0007 的鏡像日期不同。
set -euo pipefail
BIN=${1:?bin 目錄}; REC=${2:?紀錄檔}; ONLY=${3:-}
[ -z "$ONLY" ] || [ "$ONLY" = --sbom-only ] || { echo "不認得的參數：$ONLY" >&2; exit 64; }
mkdir -p "$BIN"
SYFT=1.55.0 GRYPE=0.121.0 CDXGEN=12.8.7 GOVULNCHECK=v1.9.0 GUARDDOG=3.2.0
tmp=$(mktemp -d)

anchore() {  # 名稱 版本：從 GitHub release 下載，以同一 release 的 checksums 檔驗 sha256
  local n=$1 v=$2 f="${1}_${2}_linux_amd64.tar.gz"
  local base="https://github.com/anchore/$n/releases/download/v$v"
  curl -fsSL --retry 3 -o "$tmp/$f" "$base/$f"
  curl -fsSL --retry 3 -o "$tmp/${n}_${v}_checksums.txt" "$base/${n}_${v}_checksums.txt"
  (cd "$tmp" && grep -E "  $f\$" "${n}_${v}_checksums.txt" | sha256sum -c -)
  tar -xzf "$tmp/$f" -C "$BIN" "$n"
  echo "$n $v sha256=$(sha256sum "$tmp/$f" | cut -d' ' -f1)（與 release checksums 檔相符；checksums 檔本身未驗簽）" >> "$REC"
}
anchore syft "$SYFT"
anchore grype "$GRYPE"

# bubblewrap：Ubuntu 24.04 預設限制非特權 user namespace，bwrap 需要它（說明見下面）
install_bwrap() {
  sudo apt-get install -y -qq bubblewrap > /dev/null
  [ -e /proc/sys/kernel/apparmor_restrict_unprivileged_userns ] && sudo sysctl -q -w kernel.apparmor_restrict_unprivileged_userns=0 || true   # WSL 核心沒有 AppArmor
  echo "bubblewrap $(bwrap --version)" >> "$REC"
}
if [ "$ONLY" = --sbom-only ]; then
  install_bwrap
  rm -rf "$tmp"
  exit 0
fi

npm install -g --no-fund --no-audit "@cyclonedx/cdxgen@$CDXGEN" > "$tmp/npm.log" 2>&1 || { cat "$tmp/npm.log"; exit 1; }
echo "cdxgen $(cdxgen --version 2>/dev/null | tr -d '\033' | sed 's/\[[0-9;]*m//g' | head -1)" >> "$REC"

GOBIN="$BIN" GOTOOLCHAIN=local go install "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK"
echo "govulncheck $GOVULNCHECK（go install；模組校驗由 sum.golang.org）" >> "$REC"

python3.12 -m venv "$BIN/../venv-guarddog"
"$BIN/../venv-guarddog/bin/pip" install -q --disable-pip-version-check "guarddog==$GUARDDOG"
ln -sf "$(cd "$BIN/../venv-guarddog/bin" && pwd)/guarddog" "$BIN/guarddog"
echo "guarddog $("$BIN/guarddog" --version 2>&1 | tail -1)" >> "$REC"

install_bwrap
# java 與 Maven 不在這裡安裝：版本要固定，由 workflow 的 actions/setup-java（Temurin 17.0.20+8）與 tools/e2e/install-maven.sh
# （Maven 3.10.0，官方 .sha512 驗證）提供（deploy/versions.md）。缺的時候 real-projects.sh 記 B-toolchain FAIL。
# Ubuntu 24.04 預設限制非特權 user namespace，bwrap 需要它。這會改系統設定：代管 runner 每次都是新機器；自架 runner（WSL 專用發行版）會保留，屬已知取捨（deploy/runner-wsl/README.md）
echo "go $(go version)" >> "$REC"
echo "node $(node --version)、python3.12 $(python3.12 --version | cut -d' ' -f2)、python3 $(python3 --version | cut -d' ' -f2)" >> "$REC"
echo "java $(java -version 2>&1 | head -1)；$(mvn -v 2>/dev/null | head -1 | sed "s/\x1b\[[0-9;]*m//g")" >> "$REC"
rm -rf "$tmp"
