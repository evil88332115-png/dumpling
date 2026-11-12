# Jetson 轉接器（M2 J 軌）：編譯、組刷機包、掃描、Release

實作：`pipeline/platforms/jetson/{build,prepare-source,assemble,scan}.sh`、`pipeline/lib/{safe_extract,jetson_build,jetson_assemble,jetson_scan}.py`、
`pipeline/{check-expected,release-meta}.py`；workflow：`.github/workflows/{pipeline,release,dev}.yml`；測試：`tests/test_jetson_pipeline.py`（`tests/run.d/c1-m2-jetson.sh`）。
介面與結束碼見 `docs/PLATFORM-INTERFACE.md`，分層見 `docs/LAYERS.md`。

## 1. 流程

```
tag orin-nano-demo/v39.2.1-demo1 ─► release.yml
  info        project-info.py <tag>（驗證格式、專案與版本存在）
  pipeline    pipeline.yml（reusable；dev.yml 也呼叫它）
    build  (ubuntu-24.04-arm)  fetch → prepare-source → nvbuild.sh → pack-build-record.sh → artifact（1 天）
    scan   (ubuntu-24.04)      artifact → fetch（重新下載 BSP／rootfs）→ assemble → scan → artifact（7 天）
  release     只有這個 job 有 contents: write；手動觸發只建 draft（不建 git tag），tag push 才發正式 Release
```

| 步驟 | 做什麼 | 規則 |
|---|---|---|
| `fetch`（共用） | 讀 `sources.yml`，下載並核對 sha256（和 SHA-1）到 `$DUMPLING_OUT/downloads/` | 只下載，不解開、不執行 |
| `build` | `public_sources.tbz2` → 四個元件（`kernel_src`、`kernel_oot_modules_src`、兩個顯示驅動）SHA-1 對 NVIDIA 的 `public_sources_sha.txt` → 安全解壓到同一個資料夾 → 套這個版本的 patch → `nvbuild.sh`（`make -j 4`，約 33 分鐘）→ `pack-build-record.sh` | 只在 aarch64 原生編譯（x86 回報 NOT_RUN）；`nvbuild.sh` 只用 rsync 與 make、不用 sudo（執行前讀過）；UEFI 未自編（D-002） |
| `assemble` | BSP ＋ 範例 rootfs（`tools/demo/jetson_rootfs.py` 合併 NVIDIA 套件）→ 一個 `Linux_for_Tegra/` 形式的 tar；`kernel/Image`、`rootfs/boot/Image` 換成 CI 編的同一顆；NVIDIA 的核心模組整個不收，改放 CI 編的（樹內 `kernel/…`、樹外 `updates/…`）；CI 也編出同名 dtb（只有一個）時換 dtb | 只讀 tar／deb 結構，**不解開 BSP 或 rootfs、不執行任何東西、不跑 `apply_binaries.sh` 或 `flash.sh`**；是近似值（見第 4 節） |
| `scan` | 臨時 DT → 鏡像資料 → 精靈 `--yes`（完整掃描）→ `sbom-layers.py split` → 每層用 `--rescan-from` 重跑比對 → 收集 → 標準答案比對 | 見第 5 節 |

## 2. 為什麼這樣拆 job（M2 試驗的量測，2026-11-12）

- arm64 runner 原生編譯（不用交叉工具鏈）：核心＋全部樹外模組＋dtbs 約 33 分鐘，整個 job 約 36 分鐘；磁碟清理前可用約 106 GiB，不需要清理預裝工具；4 核、15.6 GiB RAM。
- 相依（`--no-install-recommends`）：`build-essential bc bison flex libssl-dev libelf-dev rsync dwarves cpio kmod device-tree-compiler python3 python3-yaml xz-utils zstd lz4 libncurses-dev pkg-config perl patch`。
- **建置不可重現**：同一份原始碼編兩次，`Image` 的 SHA-256 不同。所以建置紀錄與刷機包裡的核心必須來自同一次編譯：build 的結果用 artifact 傳給 scan，不在別的 job 重編，cache key 不能用雜湊。
  傳的是 BuildRecord（約 169 MB）和交付檔（Image、.ko、dtb），`compression-level: 0`、`retention-days: 1`。
- scan 在 x64 runner：Syft／Grype／臨時 DT 在 x64 已驗證（M1）；rootfs 是 arm64 的 tar，`docker import` 只匯入、不啟動容器，不會執行裡面的程式。
- BSP（1.29 GB）與 rootfs（2.02 GB）不傳，scan 重新從 NVIDIA 下載（約 32 秒，比 cache 還原快）。
- `.cmd` 有絕對路徑：scan 只讀 build 打包好的 BuildRecord，不在 scan 重新打包，所以不受路徑影響。

## 3. 雜湊的依據（D-029）

- BSP 與範例 rootfs：sha256 固定在 `sources.yml`，SHA-1 對 NVIDIA 的 `release_sha_hashes.txt`。
- `public_sources.tbz2`：**NVIDIA 沒有公布整包雜湊**，`sources.yml` 的 sha256 是**首次下載記錄（TOFU，2026-11-12）**，不是官方核對；Release 附件與報告都這樣寫。
- 包內元件的 SHA-1 才是「對照 NVIDIA 公布值」：NVIDIA 另外公布的 `public_sources_sha.txt` 列了 43 個元件的 SHA-1；這份清單本身也固定 sha256（`sources.yml`）。build 逐一核對，任何一個不符 = 失敗。
- 建置紀錄的摘要（`build-record-<專案>-<版本>.json`）記：Image 與 BuildRecord 的 SHA-256、核心版本字串、元件核對數、patch（含 sha256）、建置不可重現的說明、刷機包 SHA-256。

## 4. assemble 的限制（照實寫）

- `jetson_rootfs.py` 取代 `apply_binaries.sh`：把 BSP 裡 `nv_tegra/l4t_deb_packages`、`kernel` 的所有 arm64／all 套件併進範例 rootfs 與 dpkg 紀錄，**不依板子挑套件、沒有維護者腳本產生的檔案與設定**。結果是近似值，不是刷機後的系統。
- NVIDIA 的 dpkg 紀錄（`nvidia-l4t-kernel` 等）保留：真實出貨的刷機包也是裝了 NVIDIA 的核心套件，再換成 RD 自己編的核心。BSP 的 `kernel/*.deb` 也原樣在刷機包裡（裡面是 NVIDIA 的核心）。
- `.md5` 是組裝當下算的值，只防 assemble 到 scan 之間損壞；不是 NVIDIA 公布的值（NVIDIA 原始檔的核對在 fetch）。
- 模組放置：樹內 `.ko` 放 `usr/lib/modules/<核心版本>/kernel/<編譯樹相對路徑>`，樹外 `.ko` 放 `updates/<編譯輸出相對路徑>`；`modules.order`、`modules.builtin`、`modules.builtin.modinfo` 取自 CI 的核心建置資料夾。沒有執行 `depmod`（不產生 `modules.dep`）。

## 5. scan 的設計

1. **臨時 DT**（`pipeline/dt-ephemeral.sh up → wait → env`）：只開 OSV 與 KEV，關 NVD。OSV 生態系 `Ubuntu,PyPI,Go,Maven`：rootfs 的 Ubuntu deb（含 `nvidia-l4t-*` 以 deb 身分比對）、Python、Go 執行檔、Java jar。
   DT 鏡像進行的同時，下載其他資料鏡像（`tools/mirror/`：NVIDIA 公告、Linux 核心 CNA、EUVD、Ubuntu 的 OSV 發行版紀錄）寫進 `pilot.env`。**任何一個鏡像失敗 = FAIL**（弱點資料不完整，不當作沒有漏洞）。
   Grype 資料庫由 Grype 自己線上更新（`GRYPE_DB_UPDATE=online`）；`MIRROR_REFRESH_STATUS=""`（不檢查常駐環境的鏡像新鮮度）。
2. **精靈** `tools/wizard/cra-scan.py --yes`：站台設定檔（`SCA_WIZARD_CONFIG` 的替代：`--site-config`）由 `jetson_scan.py site-config` 產生；用 CI 的建置紀錄，不是自編模式；`--platform "$DUMPLING_PLATFORM"` 原樣傳下去，不從映像格式推測。
   `inputs.json` 的 `upstream_set` 與字樣依 `platform_params.l4t_release` 在複本裡改成該版本。SourceCode 是 assemble 重新做出來的、套好 patch 的原始碼樹（上游比對用）；OP-TEE／TF-A 原始碼（`atf_t234_src`、`nvidia-jetson-optee-source`）解開給 `--tee-source`。
3. **分層**（為什麼這樣接，D-030 前後的決定）：精靈內部已經用 Syft 掃了整個 rootfs（`scan-flash-package.sh` → `sca-scan --image`），完整 SBOM 在 `wizard-out/*/scan/rootfs/scan/sbom/sbom.cdx.json`。
   做法是**先產生完整 SBOM，再 `sbom-layers.py split`，再對 `layers.json` 的 `scan_plan` 每一項各跑一次精靈的重跑模式**：把完整掃描的 `scan/` 複製一份、換上該層的 SBOM，
   用新增的 `--rescan-from`（`tools/wizard/cra-scan.py`，原樣傳給 `scan-flash-package.sh --rescan-from`；沿用完整掃描的 A0 結果、不重算）。
   理由：改動最小（精靈只加一個選用參數，沒有拆開精靈的流程）；重跑模式本來就會用該 SBOM 重新跑 Grype、DT 上傳、核心判斷（建置紀錄、樹外模組紀錄、`C-kernel-config`）、`cra_report.py`、`report_package.py`，每一層得到完整、獨立的報告。
   代價：完整掃描那次也會上傳 DT 專案 `<名稱>` 並產生一份報告（當作「全部」的對照）；分層的 `<名稱>-bsp`、`<名稱>-os` 才是各自的待辦。customer 的 `orin-nano-demo` 有 `-bsp`、`-os` 兩個 DT 專案；`ours` 只有一項（空後綴）。
4. **收集**：附件檔名一律 ASCII（GitHub 會改掉非 ASCII 字元），中文名稱放在 manifest 的顯示標籤（`漏洞清單.xlsx`、`P1判斷表.xlsx`）。
5. **標準答案**（`tests/expected/<專案>/<版本>.json`，`pipeline/check-expected.py`）：scan 結束時比對；不符 = FAIL 並印出差在哪。
   元件數、核心版本、狀態用 `equals`（資料庫更新不會讓它們變）；**漏洞數會隨資料庫變動**，用範圍或下限，每一項都寫 `reason`。
6. 狀態：缺資料、沒跑、過期一律 GAP／NOT_RUN／NOT_ASSESSED；沒有整體 PASS。沒有標準答案 = GAP（scan 結束碼 3，結果照樣產生）。

## 6. workflow 注意事項

- 第三方 action 一律 commit SHA 固定＋版本註解；`defaults.run.shell: bash`；每個 job 有 `timeout-minutes`；有 `concurrency`；預設唯讀（D-012），只有 `release` 與 `dev` 的 `publish` job 有 `contents: write`。
- 新的 workflow 不在預設分支時 `gh workflow run <檔名>` 回 404：先用一次 push 觸發讓它登錄。`release.yml` 在 main 上沒有這個問題。
- `workflow_dispatch` 的 `stop_after=build` 只編譯；`reuse_build_run=<run id>` 沿用另一個 run 的 build artifact（artifact 只保留 1 天；開發除錯用，Release 的草稿會因此不是「同一個 run 編的」，見 `release-meta.json` 的 `workflow_run` 與 build.json）。
- `dev/<專案>` 滾動 pre-release 會建立 git tag `dev/<專案>`（`gh release create` 的行為）；不會觸發 `release.yml`（tag 樣式 `*/v*` 要求第二段以 v 開頭；專案名稱以 v 開頭時 `info` job 會因找不到專案立刻失敗，無害）。

## 7. 待確認（已採最保守做法，不阻擋）

1. **`public_sources.tbz2` 的整包 sha256 是首次下載記錄（TOFU）**：NVIDIA 沒有公布整包雜湊。若 NVIDIA 之後更新檔案，fetch 會因 sha256 不符而失敗（預期行為），要人工確認後才改 `sources.yml`。
2. **UEFI 未自編**（D-002）：刷機包裡的 UEFI、OP-TEE、MB1／MB2 以 BSP 原樣；A0 成品比對（`upstream-baseline-artifacts`）是否對得上 BSP 見第 8 節。
3. **assemble 是近似值**（第 4 節）：所有 arm64／all 的 NVIDIA 套件都併進 rootfs，不依板子挑；沒有維護者腳本產生的檔案。真實出貨的刷機包是 `apply_binaries.sh` 的結果。
4. **刷機包的 dtb**：CI 的 `make dtbs` 也編出同名 dtb 的（只有一個）換成 CI 的，其餘（`.dtbo` 疊加檔等）保留 BSP 的；換了哪些記在 `assemble.json` 的 `dtb_replaced`。dtb 目前沒有 CVE 資料，只記身分。
5. **映像裡的核心建置設定**：CI 的 `.config`、`Makefile`、`Module.symvers` 放在 `usr/lib/modules/<版本>/build/`（NVIDIA 的 headers 套件裡沒有掃描要的頂層 `.config`），讓 `C-kernel-config` 找得到出貨核心的設定；真實出貨的 headers 套件內容要由 RD 確認。
6. **NVD 沒開**（PLAN 已知卡點：NVD 第一次同步要 1–3 小時），`D-dt-data-sources`／`C-dt-feeds` 因此是 GAP；弱點資料來自 OSV、Grype、CISA／ENISA KEV、NVIDIA 公告、Linux 核心 CNA。ENISA EU KEV 的檔沒有發布日期（`D-dt-kev-sources` GAP）。
7. **完整掃描也會建一個 DT 專案與一份報告**（第 5 節第 3 點），分層後 `-bsp`／`-os` 才是各自的待辦；完整那份只當對照。DT 的專案階層（parent／child）沒用（見 `docs/LAYERS.md`）。
8. **標準答案的漏洞數用範圍**，因為資料庫每天變；元件數、核心版本、狀態用 equals。範圍是跑第一次的實際值上下抓寬鬆，之後資料庫變化讓範圍不符時，人工看過再改範圍並寫理由。
9. **L 軌的測試 `tools/cra/tests/test_layers_report.py::test_untagged_sbom_changes_nothing` 偶爾失敗**（比對兩次執行的風險評估文字時，VEX 的 SHA-256 摘要受時間影響；跨過整秒時才出現，再跑一次就過）。不是這次的改動造成的，尚未修。
