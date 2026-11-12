# 平台公開示範資料清單（WP7）

Raspberry Pi、Rockchip、AI NAS 三個平台的公開示範資料：每個樣本一個資料夾，內有一個 `samples.yml`。
**二進位檔不進 git**；清單裡的 sha256 與大小是 C4 實際下載後算出來的（下載後就刪除，沒有解開、沒有執行）。

這是 M2 之前的暫時位置。C1 在 M2 定出開案範本的 `sources.yml` 格式後，這些清單會搬到各示範專案的
`projects/<專案>/sources.yml`。平台的分層與韌體檢查見 `docs/platforms-research.md`。

## 格式

`files[]` 沿用 `firmware/*/firmware.yml` 的欄位（`name`、`url`、`sha256`、`size`、`role`），
所以 `pipeline/lib/firmware_fetch.py` 的 `fetch_one()` 可以直接用來下載核對。另外每個檔案加了：

| 欄位 | 說明 |
|---|---|
| `version` | 這個檔案的版本（套件版本、映像日期、git commit） |
| `license_url` | 這個檔案的授權條款網址 |
| `note` | 選填；跟官方公布的雜湊核對的結果、限制 |

`role` 除了 `image`／`source`／`package`，多一個 `metadata`（官方附的套件清單、SBOM、manifest 這類小的文字檔）。
因為 `kind`、`role: metadata` 跟 `firmware_fetch.py` 的 `validate()` 不同，**不要**把這些檔案丟給 `pipeline/firmware-fetch.sh`；
共用的下載核對模組由 C1 在 M2 的平台介面裡定。

## 樣本

| 樣本 | 平台 | 為什麼挑 |
|---|---|---|
| `raspberrypi-os-lite-2026-10-06` | Raspberry Pi | 官方最新的 Lite arm64；核心原始碼有 Raspberry Pi apt 的原始碼包（雜湊固定）與 `raspberrypi/linux` tag；官方另附 SBOM |
| `radxa-rock-5b-rsdk-r6` | Rockchip（RK3588） | 板子廠商自己發行的映像，放在 GitHub Release（網址固定）；核心與 U-Boot 都能對到公開 commit |
| `debian-13-generic-amd64-20261111` | AI NAS（x86） | Debian 官方雲端映像（舊版本長期保留）；核心原始碼用 snapshot.debian.org 的固定網址；應用層用 OpenMediaVault 原始碼（固定 commit，D-025），不用安裝 ISO |
| `truenas-scale-25.10.8` | AI NAS（x86，參考二） | TrueNAS Community Edition 目前的穩定版；只做研究與樣本清單、不寫轉接器（D-026）。用 `.update` 更新檔（squashfs，不執行就能取出 rootfs），不用安裝 ISO；原始碼都有 `TS-25.10.8` tag |
