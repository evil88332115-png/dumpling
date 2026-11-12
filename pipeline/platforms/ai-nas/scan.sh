#!/usr/bin/env bash
# AI NAS 的 scan：共用流程 _shared/scan-disk.sh，加上 NAS 應用（OpenMediaVault，sources.yml 固定的 commit）原始碼的 SBOM，
# 每個元件標來源與 commit 後併進產品 SBOM（D-025；原始碼與正式 deb 是否相同 NOT_ASSESSED）。
export WP7_AUGMENT=app-source
export DT_OSV_ECOSYSTEMS=${DT_OSV_ECOSYSTEMS:-Debian,PyPI,Go,npm,Packagist}
exec bash "${DUMPLING_ROOT:?}/pipeline/platforms/_shared/scan-disk.sh" "$@"
