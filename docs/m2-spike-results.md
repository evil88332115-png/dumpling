# M2 可行性試驗（spike）結果

> 分支 `wp1/m2-spike`，**不合併**。只量測 runner 資源，不是正式流程。所有數字來自 2026-11-12 在 GitHub 內建 runner 上跑的 workflow `m2-spike`（`.github/workflows/m2-spike.yml`，只有 `workflow_dispatch`）。
> 沒跑、沒量到的標 NOT_RUN，缺資料標 GAP；本文件沒有整體 PASS。

## 0. 結論（先看這段）

| 問題 | 答案 |
|---|---|
| Jetson 的**編譯**能不能在一個 job 的 6 小時內完成？ | 能。arm64 runner 原生編核心＋全部樹外模組＋dtbs，整個 job（含 apt、解壓、打包建置紀錄）約 36 分鐘，其中 `nvbuild.sh` 約 33 分鐘（兩次：1998 秒、1985 秒） |
| 磁碟夠不夠？ | 夠，而且遠超過 PLAN 寫的 14 GB：兩種 runner 的 `/` 都是 145 GB 單一檔案系統，**清理前**可用 arm 106 GiB、x64 86 GiB。編譯整個 job 淨用 7.5 GiB 左右（建置資料夾 5.0 GiB＋原始碼 1.8 GiB 的一部分）。**不需要清理預裝工具**（清理可再多 26 GiB（arm）／45 GiB（x64），但這次用不到） |
| CPU／RAM | 4 核（Neoverse-N2）、15.6 GiB；編譯時 `make -j 4`，MemAvailable 最低 12.3～13.4 GiB（峰值使用約 3 GiB），load 峰值 6.3～6.7 |
| 掃描（BSP＋rootfs＋DT＋Grype）能不能同一個 job？ | **GAP：這次沒量掃描**。依 PLAN（下載約 3.3 GB、暫存約 20 GB）：磁碟綽綽有餘（編譯後還剩約 98 GiB）；時間為 編譯 36 分鐘＋掃描（未量），PLAN 估掃描加編譯共 1.5–3 小時，離 6 小時很遠。單一 job 可行；但建議分成兩個 job（理由與傳檔方式見第 5 節） |
| job 之間傳檔 | 交付與紀錄檔（Image、dtb、.ko、.config、System.map、.cmd…）壓縮後 **152 MB**，走 artifact（上傳 2 秒、下載 3 秒）；整個輸出資料夾壓縮後 **954 MB**，走 cache 也行（存 5 秒、還原 6 秒）。BSP／rootfs **不要傳**：重新從 NVIDIA 下載比 cache 還原還快 |

三個意外：(1) PLAN 的 runner 磁碟數字（14 GB）和實測不符；(2) 同一份原始碼編兩次，`Image` 的 SHA-256 **不同**（不可重現建置），建置紀錄與刷機包必須來自同一次編譯；(3) `public_sources.tbz2` **沒有** NVIDIA 公布的整包 SHA-1。

## 1. 執行紀錄（run 連結）

| 項目 | run | 結果 |
|---|---|---|
| 1 清理（arm＋x64） | https://github.com/evil88332115-png/dumpling/actions/runs/43242393210 | 兩個都成功 |
| 2 下載＋核對＋存 cache（首次） | https://github.com/evil88332115-png/dumpling/actions/runs/43243641230 | 成功 |
| 2 第二次觸發（cache 還原） | https://github.com/evil88332115-png/dumpling/actions/runs/43243981359 | 成功 |
| 2 inspect（解開檢視，建置腳本與 Makefile 以 artifact 取回） | https://github.com/evil88332115-png/dumpling/actions/runs/43245885575 | 成功（前兩次 43244278705 因 cache 路徑不同失敗、43244590813 成功但日誌吃掉部分行） |
| 3 編譯（第一次） | https://github.com/evil88332115-png/dumpling/actions/runs/43246860803 | 成功，`nvbuild.sh` 退出碼 0 |
| 3 編譯（第二次，加 handoff 量測） | https://github.com/evil88332115-png/dumpling/actions/runs/43254234938 | build、handoff 都成功 |
| 2 下載 39.2.0（記 SHA-256） | https://github.com/evil88332115-png/dumpling/actions/runs/43254242105 | 成功 |
| 探測 tar 成員（刷機包組裝注意事項） | https://github.com/evil88332115-png/dumpling/actions/runs/43261773829 | 成功 |

**NOT_RUN**：掃描（Syft／Grype／DT）、UEFI（edk2-nvidia）／OP-TEE／ATF 編譯（D-002 先用 BSP 內建成品）、刷機包組裝、Release、x64 runner 上的編譯、39.2.0 的編譯（只下載並記了雜湊）。

## 2. 第 1 件：runner 磁碟清理

兩種 runner：`/` 都是 `/dev/root` 145 GiB（154,894,188,544 bytes），**沒有獨立的 `/mnt`**（`/mnt` 與 `/` 是同一個檔案系統，可用空間相同）；有 3 GiB `/swapfile`；Docker 有 6 個預載映像（arm 2.54 GB、x64 2.49 GB）。

| | arm（`ubuntu-24.04-arm`） | x64（`ubuntu-24.04`） |
|---|---|---|
| CPU／RAM | 4 核 Neoverse-N2、15.6 GiB | 4 核 AMD EPYC 9V74、15.6 GiB |
| 清理前 `/` 可用 | 106.09 GiB（已用 39 G） | 85.80 GiB（已用 59 G） |
| 清理後 `/` 可用 | 132.23 GiB | 130.59 GiB |
| 全部清理騰出 | 26.14 GiB（刪除動作合計約 21 秒） | 44.80 GiB（合計約 114 秒） |

逐項（GiB，括號內是 `rm -rf` 秒數；`—` 表示那台沒有這項）：

| 項目 | arm | x64 |
|---|---:|---:|
| `/usr/local/lib/android` | — | 11.03（40.7 秒） |
| `/usr/share/dotnet` | 6.59（3.1） | 5.74（7.4） |
| `/opt/hostedtoolcache` | 3.35（5.7） | 5.21（22.8） |
| `/usr/local/.ghcup` | — | 3.66（2.0） |
| `/usr/share/swift` | 3.42（0.1） | 3.46（0.4） |
| Docker 預載映像（`docker image prune -af`） | 2.53（2.6） | 2.49（7.8） |
| `/swapfile`（`swapoff` 後刪除） | 3.00（0.0） | 3.00（0.0） |
| `/usr/local/share/powershell` | 1.33 | 1.33 |
| `/usr/lib/jvm` | 1.44 | 1.44 |
| `/usr/lib/google-cloud-sdk` | 0.83（2.7） | 0.83（9.1） |
| `/usr/share/miniconda` | — | 1.12（4.4） |
| `/opt/microsoft` | 0.18 | 0.82 |
| `/opt/az`、`/opt/pipx`、`/usr/local/lib/node_modules`、aws-cli 等小項 | 各 0.2～0.7 | 各 0.2～0.7 |
| `/usr/local/share/chromium`、`/opt/google` | — | 0.66、0.44 |
| `/opt/ghc`、`/usr/local/share/boost` | 不存在 | 不存在 |

觀察：
- arm 沒有 Android SDK、ghcup、chromium、miniconda，所以能騰出的比 x64 少 18 GiB。
- 掃描磁碟用量的 `du` 本身很慢（`du-top` 步驟 arm 159 秒、x64 184 秒），正式流程不要做。
- **PLAN 說「清理後約 30 GB」「14 GB SSD」與實測不符**：實際 106（arm）／86（x64）GiB 可用，不清理也夠。可只保留「刪 Android／dotnet／hostedtoolcache」這類便宜的動作當保險，或乾脆不清理；請 C1 決定是否改 PLAN。這可能與帳號／repo 類型有關（公開 repo），日後若 GitHub 調整規格要重量。

## 3. 第 2 件：下載、核對、快取

網址與雜湊：

| 檔案 | 網址 | NVIDIA 公布的 SHA-1 | SHA-256 | 大小 |
|---|---|---|---|---|
| `Jetson_Linux_R39.2.1_aarch64.tbz2` | `https://developer.download.nvidia.com/embedded/L4T/r39_Release_v2.1/release/` | `8fe9a3ac…bb47fb`（`tools/demo/jetson.sh` 寫死，本次再讀 `release_sha_hashes.txt` 相符） | `2e561908…dbe6b` | 1,287,223,769 |
| `Tegra_Linux_Sample-Root-Filesystem_R39.2.1_aarch64.tbz2` | 同上 | `9a991a4f…8c303` | `58a6485b…e66e` | 2,022,864,741 |
| `public_sources.tbz2`（39.2.1） | `https://developer.download.nvidia.com/embedded/L4T/r39_Release_v2.1/sources/public_sources.tbz2` | **無**（見下） | `8346f0371649a92c42293b2d4a7bf3d69e4dd1de23009e1463ea910994a81371`（首次下載記錄 2026-11-12） | 309,583,176；SHA-1（算出，非 NVIDIA 公布）`7efedf1c5587210d78bcb9d61463f2a29d56c8e4` |
| `public_sources.tbz2`（39.2.0） | `https://developer.download.nvidia.com/embedded/L4T/r39_Release_v2.0/sources/public_sources.tbz2` | **無** | `87d2e31ff55beaf2373e2f288538585995b231fd5745ec21f39a668e36efab2f`（首次下載記錄） | 309,505,238；SHA-1（算出）`31d518bebe9690a7055b90fe4f276cad2bb12217` |

完整雜湊與 39.2.0 的值見 `tools/spike/m2-release.sh`。

**`public_sources.tbz2` 的雜湊來源（GAP）**：它**不在** `release/release_sha_hashes.txt` 裡。NVIDIA 下載頁（Jetson Linux 39.2.1 的頁面）也沒列整包雜湊，只連到 `sources/public_sources_sha.txt`；那份檔案列的是**包內 43 個元件**（`kernel_src.tbz2`、`kernel_oot_modules_src.tbz2` 等）的 SHA-1。因此整包只能靠首次下載記錄的 SHA-256（信任首次下載），元件則可以逐一對 NVIDIA 另外公布的清單：解開後 43 個元件相符、1 個不符——不符的是 `public_sources_sha.txt` 列自己的那一行（自己的雜湊不可能寫在自己裡面，非問題）。編譯用的四個元件 SHA-1（39.2.1，對 NVIDIA 公布值相符）：`kernel_src` `9adff63a…`、`kernel_oot_modules_src` `f2d68964…`、`nvidia_kernel_display_driver_source` `7e3dabdc…`、`nvidia_unified_gpu_display_driver_source` `852e32a3…`。

時間（arm runner，單檔下載到磁碟＋SHA-1＋SHA-256）：

| 步驟 | 時間 | 備註 |
|---|---:|---|
| 下載 BSP 1.29 GB | 5.4 秒（另一次 14.9 秒） | NVIDIA CDN，約 240 MB/s 以上，波動大 |
| 下載 rootfs 2.02 GB | 27.1 秒（另一次 22.1 秒） | |
| 下載 public_sources 0.31 GB | 4.2 秒（3.9 秒） | |
| 三個檔案的 SHA-1＋SHA-256 核對（cache 還原後重做） | 約 9 秒 | |

actions/cache（key 帶檔名＋SHA-256，每個檔案一個 cache）：

| | 存（第一次，Post 步驟） | 還原（第二次） | cache 大小（壓縮後） |
|---|---:|---:|---:|
| BSP | 約 5 秒 | **16 秒** | 1.19 GiB |
| rootfs | 約 10 秒 | **22 秒** | 1.87～1.88 GiB |
| public_sources | 約 5 秒 | **1 秒** | 295 MiB |

- **cache 還原不比直接從 NVIDIA 下載快**（BSP 16 對 5 秒、rootfs 22 對 27 秒），而且還要佔配額。結論：BSP／rootfs **不必進 cache**；省的只是對 NVIDIA 的流量與可用性風險（NVIDIA 站掛了時有備援）。
- 3 個檔案合計 cache 約 3.4 GiB；兩個版本（39.2.0＋39.2.1）加一個傳檔 cache（0.9 GiB）共 7.87 GB，repo 上限是 10 GB（超過會自動逐出最舊的）。
- 解開後大小：`public_sources.tbz2` 解開 311 MB（87 個成員，43 個元件包）；`kernel_src` 1,413 MB（88,958 個成員）；`kernel_oot_modules_src` 182 MB（7,544）；`nvidia_unified_gpu_display_driver_source` 126 MB；`nvidia_kernel_display_driver_source` 31 MB；`kernel_nvgpu_src` 41 MB（獨立包，`nvbuild.sh` 不用）。
- BSP 解開（只讀清單，沒寫入）：1,682 個成員、1.52 GB、52 個符號連結，無裝置檔、無 setuid；Python 串流讀清單 86 秒。範例 rootfs：163,832 個成員、5.38 GB、38,858 個符號連結（其中 751 個是絕對路徑，rootfs 內正常）、41 個 setuid／setgid 檔、187 個擁有者非 root 的成員、12 個硬連結、無裝置檔；Python 串流讀清單 356 秒（改用 `tar -t` 應較快，未量）。

## 4. 第 3 件：原生編譯核心＋樹外模組

### 做法

直接用 NVIDIA 原始碼包附的 `nvbuild.sh`（`kernel_src.tbz2` 內，BSD-3-Clause；依 `nv_public_src_build.sh` 的做法把 `kernel_src`、`kernel_oot_modules_src`、`nvidia_kernel_display_driver_source`、`nvidia_unified_gpu_display_driver_source` 四包解到同一個資料夾，再 `./nvbuild.sh -o <輸出>`）。**執行前讀過內容**（`nvbuild.sh`、`nvcommon_build.sh`、`kernel_src_build_env.sh`、`generic_rt_build.sh`、`kernel/Makefile`、樹外模組的 `Makefile`）：
- 它只用 `rsync` 與 `make`；`-i`（install，會 `sudo`）不使用；aarch64 主機上不需要 `CROSS_COMPILE`（`IS_CROSS_COMPILATION` 只在 `uname -m` 含 x86 時為 1）。
- 設定：`KERNEL_SRC_DIR=kernel-noble`、`KERNEL_DEF_CONFIG=defconfig`、`KERNEL_MODULAR_BUILD=y`；樹外清單 `nvethernetrm nvgpu nvidia-oot hwpm hardware nvdisplay build/nvidia-public/devicetree unifiedgpudisp`。
- 順序：`make -C <輸出>/kernel`（`make -j $(nproc)`，核心 Image 與核心 modules）→ `make modules`（conftest、hwpm、nvidia-oot、nvgpu、nvidia-display、nvidia-gpu-display）→ `make dtbs`。
- 解壓用 `tools/spike/m2_safe_extract.py`（`python3 -I`；Python `tarfile` 的 `data` 過濾器；拒絕絕對路徑、`..`、裝置檔、FIFO、指向目的資料夾外的符號連結／硬連結；解完再走一遍檢查），不執行 BSP 或 rootfs 的任何東西（這次根本沒解開它們）。
- 注意：Actions 的日誌顯示會吃掉部分行（含縮排的程式碼行），要讀原始檔請另外用 artifact 取回，不要靠日誌。

### apt 相依（Ubuntu 24.04 arm64 runner，`--no-install-recommends`，裝 15～26 秒）

`build-essential bc bison flex libssl-dev libelf-dev rsync dwarves cpio kmod device-tree-compiler python3 xz-utils zstd lz4 libncurses-dev pkg-config perl`。實際版本：gcc 13.3.0（套件 `gcc 4:13.2.0-7ubuntu1`）、binutils 2.42-4ubuntu2.10、make 4.3-4.1build2、bison 3.8.2、flex 2.6.4、libssl-dev 3.0.13-0ubuntu3.16、libelf-dev 0.190-1.1ubuntu0.1、dwarves（pahole）1.25-0ubuntu3、bc 1.07.1、cpio 2.15、kmod 31+20240202-2ubuntu7.2、device-tree-compiler 1.7.0-2build1、rsync 3.2.7-1ubuntu1.5、python3 3.12.3、perl 5.38.2、zstd 1.5.5、lz4 1.9.4、xz-utils 5.6.1（完整清單見 run 43246860803 的 artifact `m2res-build/apt-versions.txt`，7 天後過期）。runner 映像：`ubuntu-24.04-arm` 20261111.182。其中 rsync、gcc、make 等 runner 本來就有；哪些是必要的沒有逐一刪減驗證（GAP）。

### 各步驟時間（arm，第二次 run 43254234938；第一次 run 43246860803 在 ±2% 內）

| 步驟 | 秒 | `/` 可用 GiB（前→後） |
|---|---:|---|
| apt 安裝 | 14.7（第一次 26.4） | 105.79→105.67 |
| 解 public_sources.tbz2 | 22.3 | 105.67→105.38 |
| 解 kernel_src（1.41 GB／88,958 個成員） | 52.4 | →103.85 |
| 解 oot＋nvdisplay＋unified | 6.1＋1.5＋4.9 | →103.51 |
| **`nvbuild.sh` 全部** | **1984.9**（第一次 1998.4） | 103.80→98.46（淨用 5.34 GiB） |
| `pack-build-record.sh`（真的打包，量用） | 14.1 | →98.30 |
| 估算：整個輸出資料夾 zstd -3 | 7.7 | — |
| 估算：只含交付與紀錄檔 zstd -3 | 1.5 | — |

`nvbuild.sh` 內各段（從日誌標記行，單位為開始後秒數，第二次 run）：

| 段 | 開始 → 結束 | 用時 |
|---|---|---:|
| 核心（`make -C kernel`：核心 Image 與全部核心 modules） | 5 → 1491 | 約 1486 秒（24.8 分） |
| 樹外 conftest | 1492 → 1503 | 11 |
| hwpm | 1503 → 1506 | 3 |
| nvidia-oot | 1506 → 1719 | 213 |
| nvgpu | 1719 → 1815 | 96 |
| nvidia-display（nvdisplay） | 1815 → 1861 | 46 |
| nvidia-gpu-display（unifiedgpudisp） | 1861 → 1980 | 119 |
| dtbs | 1980 → 1985 | 5 |

資源（背景 sampler 每 15 秒一筆，`nvbuild` 期間 132 筆）：
- `nproc` = 4，`make -j 4`（`kernel/Makefile` 的 `NPROC ?= $(shell nproc)`）。
- `/` 可用最低 98.55 GiB（整個 job 的起點是 105.79 GiB）；也就是**編譯期間峰值使用約 7～8 GiB**，沒有任何磁碟壓力。
- MemAvailable 最低 13.38 GiB（第一次 12.25 GiB）；load 峰值 6.28（第一次 6.74）。

結果：
- 核心 `Image` 52,484,608 bytes（50 MiB）；核心 `.ko` 1,352 個、樹外 `.ko` 184 個（含 `unifiedgpudisp/kernel-open/nvidia.ko`、`nvidia-drm.ko`、`nvidia-modeset.ko`、`nvidia-uvm.ko`、`nvidia-oot/…` 各驅動）、`.*.cmd` 19,424 個、`.dtb` 1,073 個。
- 輸出資料夾 5.34 GB（核心 4.27 GB；其餘樹外 1.08 GB）。
- **警告 23 行**（多為 `-Wmissing-prototypes`）；失敗訊息：無（唯一匹配的 `***` 是 Kconfig 的 "Default configuration is based on 'defconfig'" 提示）。
- **不可重現**：同一份原始碼編兩次，`Image` SHA-256 分別是 `88f298dfb66d105db91fa70c45c502e05e9e0ef8016300d1d211b5fecc951689` 與 `6f2bf2a694f38a6d301a6b0990a1f949d2074ff07262131b853c781c4071e314`。**建置紀錄和刷機包用的核心必須來自同一次編譯**；不能「在掃描 job 重編一次」或靠雜湊在 cache 命中。
- `pack-build-record.sh` 在完整輸出資料夾上成功：19,744 個檔案、tar.gz 169 MB（含 .ko 與 .cmd）；對只含交付與紀錄檔的重建資料夾、和對 cache 還原的完整資料夾，重新打包出的檔案清單**與編譯 job 完全相同**（排序後 SHA-256 `09ced9cb…c794`），Image SHA-256 也相符。BuildRecord 的 `BUILD-INFO.txt` 內有時間所以內容每次不同，但清單相同。路徑要與編譯時相同（`.cmd` 內有絕對路徑）。
- 沒有被 `pack-build-record.sh` 打包的：UEFI（`--uefi=` 沒給，D-002）。

## 5. job 拆法與傳檔建議

**單一 job 可行性**（以實測＋PLAN 估計）：編譯 36 分鐘＋掃描（GAP，PLAN 估 1.5–3 小時含編譯）＜ 350 分鐘；磁碟編譯後剩約 98 GiB，PLAN 的掃描暫存 20 GB 沒問題。**單一 job 能完成。**

仍建議拆成兩個 job，原因：掃描要起臨時 DT、時間不確定、失敗時只需重跑掃描；編譯產物很小，傳遞成本幾乎為零。

| job | runner | 做什麼 | 輸出 |
|---|---|---|---|
| `build`（約 40 分鐘） | `ubuntu-24.04-arm` | 下載 `public_sources.tbz2`＋核對 → 解壓 → 套 `patches/`（未量）→ `nvbuild.sh` → `pack-build-record.sh` →（組刷機包時）換核心 | artifact：BuildRecord（約 169 MB tar.gz）＋交付檔 `deliverables.tar.zst`（約 152 MB）＋ `Image` 的 SHA-256 |
| `scan` | arm 或 x64（皆可；未量） | 重新從 NVIDIA 下載 BSP／rootfs（共約 32 秒）→ 組刷機包（核心換成 `build` 的）→ 起 DT → 掃描 → Release | Release 附件 |

傳檔：
- **artifact**：實測 152 MB 的 `deliverables.tar.zst`（`compression-level: 0`）上傳 2 秒、下載 3 秒。配額 500 MB 是共用的（文件值）：BuildRecord＋交付檔約 320 MB，單次可行，但**多個 run 同時保留會超過**，所以 `retention-days: 1`，Release 發完就不需要。**這次沒有測到配額上限（GAP）**。
- **cache**：整個輸出資料夾 954 MB（zstd -3）存 5 秒、還原 6 秒；上限 10 GB 但每個 repo 共用且會逐出舊的。當作 artifact 配額不足時的備援，或需要完整 `.cmd`／原始碼樹時用（key 用 `github.run_id`，不要用內容雜湊——建置不可重現）。
- **不傳**：BSP（1.29 GB）、rootfs（2.02 GB，解開 5.4 GB）：超過 artifact 配額，且重下載（32 秒）比 cache 還原（38 秒）還快。
- 刷機包本身（BSP＋rootfs 解開後 7 GB 以上）不傳，在 `scan` job 現場組。注意：**rootfs 有 41 個 setuid／setgid 檔與 187 個非 root 擁有者的成員、751 個絕對符號連結**，要保留這些資訊就得用 root（`sudo tar -p --numeric-owner`）解開——只解開、不執行；若 `jetson_rootfs.py` 一樣直接讀 tar 不解開（現有做法），就沒有這個問題。

## 6. 風險與未解決

1. **掃描時間未量（GAP）**；PLAN 的估計是否準確要等 M2 全流程。
2. **`public_sources.tbz2` 沒有 NVIDIA 公布的整包雜湊**：整包 SHA-256 是信任首次下載（兩個版本都已記在 `tools/spike/m2-release.sh`）；元件層級可以對 NVIDIA 另外公布的 SHA-1 逐一核對（已做）。若 NVIDIA 之後更新檔案內容，正式流程會因 SHA-256 不符而停止（預期行為）。
3. **runner 規格可能變**：磁碟 145 GiB、4 核、15.6 GiB RAM 是 2026-11-12 對這個 repo 量到的，與 PLAN 引用的文件（14 GB SSD）不同，應標明量測日期。
4. **編譯時間隨 NVIDIA 原始碼與 runner 負載變**：兩次 1985～1998 秒，很穩定；有 10 倍以上餘裕。
5. **不可重現建置**（見上）：影響「Release 發布後別人重編得到相同 Image」的說法，也影響用雜湊當 cache key。
6. **UEFI／OP-TEE／ATF 沒編**（D-002）；`nv_public_src_build.sh` 會建置全部元件（含 gstreamer 等），這次**沒有用它**，只用 `nvbuild.sh`；若 M2 要編 TOS，需另外量。
7. **kernel 版本字串**這次沒從建置結果讀（GAP）；只知道原始碼目錄叫 `kernel-noble`。
8. 日誌顯示會吃掉部分行（含 NVIDIA 腳本的縮排行），寫 workflow 時不要用日誌比對腳本內容。
9. workflow 新檔不在預設分支時，`gh workflow run m2-spike.yml` 找不到；做法是先讓一次 `push` 事件登錄 workflow，之後用 workflow ID（`gh workflow run <ID> --ref wp1/m2-spike`）觸發。正式流程的 `release.yml` 在 main 上，沒有這個問題。
10. 上傳了 `m2res-*` artifact（保留 7 天）與 `m2-handoff-deliverables`（1 天）、數個 `m2spike-*` cache（合計 7.87 GB，7 天沒用會自動清除）；其中 BuildRecord 與 NVIDIA 腳本只在 artifact，沒有進 git。
