#!/usr/bin/env bash
# Raspberry Pi 的 scan：共用流程 _shared/scan-disk.sh（官方 Raspberry Pi OS 映像原樣掃描；rpi-connect* 在摘要標成對外連線服務）。
export WP7_AUGMENT=none
export DT_OSV_ECOSYSTEMS=${DT_OSV_ECOSYSTEMS:-Debian,PyPI,Go,npm,Maven}
exec bash "${DUMPLING_ROOT:?}/pipeline/platforms/_shared/scan-disk.sh" "$@"
