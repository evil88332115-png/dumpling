#!/usr/bin/env bash
# Rockchip 的 scan：共用流程 _shared/scan-disk.sh，加上 assemble 清點的原始磁區開機程式（raw-sectors.json → firmware 元件，D-027、D-034）。
export WP7_AUGMENT=raw-sectors
export DT_OSV_ECOSYSTEMS=${DT_OSV_ECOSYSTEMS:-Debian,PyPI,Go,npm}
exec bash "${DUMPLING_ROOT:?}/pipeline/platforms/_shared/scan-disk.sh" "$@"
