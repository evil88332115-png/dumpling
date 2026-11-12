#!/usr/bin/env bash
# 更新主機角色（需連網）：下載 Grype v6 弱點資料庫，產生內網可用的鏡像目錄（latest.json + 資料庫壓縮檔）與 manifest。
# 做法照 Grype v0.121.0 原始碼（不是猜的）：
#   grype/db/v6/distribution/client.go  預設 LatestURL=https://grype.anchore.io/databases，實際讀 <url>/v6/latest.json
#                                       （設定值若以 .json 結尾則直接使用）。
#   grype/db/v6/distribution/latest.go  latest.json 的 path 是「相對於 latest.json 的位置」，checksum 為 sha256:<hex>（整個壓縮檔）。
#   cmd/grype/cli/commands/db_import.go `grype db import <檔案或 URL>` 可直接匯入壓縮檔。
# 所以內網只要把 DEST 目錄原樣放上檔案伺服器（DEST/v6/latest.json 與壓縮檔同一層），掃描器設定
#   GRYPE_DB_UPDATE_URL=http://<內部伺服器>/<路徑>   （或直接 grype db import <壓縮檔>，離線環境規定用匯入方式）
#   GRYPE_DB_AUTO_UPDATE=false  GRYPE_CHECK_FOR_APP_UPDATE=false
# 用法：grype-db.sh <鏡像輸出資料夾（必須全新）> <manifest 輸出檔>
#       grype-db.sh --check <鏡像資料夾>      只做自我檢查（latest.json 可解析、壓縮檔 checksum 相符；有 grype 時另做匯入測試）
# 環境變數：GRYPE_MIRROR_SOURCE_URL  來源 latest.json（預設官方）；GRYPE_MAX_AGE_DAYS 資料庫建置時間上限（預設 3 天，超過就失敗）
set -euo pipefail
SRC_URL="${GRYPE_MIRROR_SOURCE_URL:-https://grype.anchore.io/databases/v6/latest.json}"
MAX_AGE_DAYS="${GRYPE_MAX_AGE_DAYS:-3}"

check() {
  local d="$1"
  [ -s "$d/v6/latest.json" ] || { echo "MISSING v6/latest.json" >&2; return 1; }
  python3 -I - "$d/v6" "$MAX_AGE_DAYS" <<'PY' || return 1
import datetime, hashlib, json, os, sys
d, max_age = sys.argv[1], float(sys.argv[2])
doc = json.load(open(os.path.join(d, "latest.json")))
path, cs, built = doc.get("path"), doc.get("checksum", ""), doc.get("built")
if not path or "/" in path or path.startswith("."):
    sys.exit(f"bad path in latest.json: {path!r}")
algo, _, want = cs.partition(":")
if algo != "sha256" or len(want) != 64:
    sys.exit(f"unexpected checksum format: {cs!r}")
f = os.path.join(d, path)
h = hashlib.sha256()
with open(f, "rb") as fh:
    for b in iter(lambda: fh.read(1 << 20), b""):
        h.update(b)
if h.hexdigest() != want:
    sys.exit(f"checksum mismatch: {h.hexdigest()} != {want}")
bt = datetime.datetime.fromisoformat(built.replace("Z", "+00:00"))
age = (datetime.datetime.now(datetime.timezone.utc) - bt).total_seconds() / 86400
print(f"schema={doc.get('schemaVersion')} built={built} age_days={age:.1f} archive={path} bytes={os.path.getsize(f)} status={doc.get('status')}")
if age > max_age:
    sys.exit(f"STALE: built {age:.1f} days ago (> {max_age})")
PY
  if command -v grype >/dev/null 2>&1; then
    local tmp; tmp="$(mktemp -d)"
    local arc; arc="$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1]))["path"])' "$d/v6/latest.json")"
    GRYPE_DB_CACHE_DIR="$tmp" GRYPE_CHECK_FOR_APP_UPDATE=false GRYPE_DB_AUTO_UPDATE=false grype db import "$d/v6/$arc"
    GRYPE_DB_CACHE_DIR="$tmp" GRYPE_CHECK_FOR_APP_UPDATE=false GRYPE_DB_AUTO_UPDATE=false grype db status
    rm -rf "$tmp"
  else
    echo "NOTE grype 不在 PATH，略過匯入測試" >&2
  fi
}
if [ "${1:-}" = "--check" ]; then check "${2:?缺少鏡像資料夾}"; exit $?; fi
DEST="${1:?用法見檔頭}"; MANIFEST="${2:?}"
for p in "$DEST" "$MANIFEST"; do [ ! -e "$p" ] || { echo "已存在，拒絕覆蓋：$p" >&2; exit 3; }; done
mkdir -p "$DEST/v6"
FETCHED="$(date -u +%FT%TZ)"
curl -fsSL --retry 3 -o "$DEST/v6/latest.json.src" "$SRC_URL"
REL="$(python3 -I -c 'import json,sys;p=json.load(open(sys.argv[1]))["path"];assert p and not p.startswith("/") and ".." not in p;print(p)' "$DEST/v6/latest.json.src")"
ARC_URL="${SRC_URL%/*}/$REL"; BASE="${REL##*/}"
curl -fSL --retry 3 -o "$DEST/v6/$BASE" "$ARC_URL"
# 內網版 latest.json：與來源相同，只把 path 改成同目錄的檔名（latest.go：path 相對於 latest.json）
python3 -I - "$DEST/v6/latest.json.src" "$DEST/v6/latest.json" "$BASE" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); d["path"] = sys.argv[3]
json.dump(d, open(sys.argv[2], "w"), indent=1)
PY
rm "$DEST/v6/latest.json.src"
check "$DEST"
{
  echo "# source: $SRC_URL"; echo "# archive_url: $ARC_URL"; echo "# fetched_utc: $FETCHED"
  echo "# files: $(find "$DEST" -type f | wc -l)  bytes: $(du -sb "$DEST" | cut -f1)"
  (cd "$DEST" && find . -type f -print0 | sort -z | xargs -0 sha256sum)
} > "$MANIFEST"
echo "OK mirror=$DEST manifest=$MANIFEST"
