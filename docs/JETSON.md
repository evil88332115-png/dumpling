# Jetson 轉接器（M2 J 軌）：編譯、組刷機包、掃描、Release

實作：`pipeline/platforms/jetson/{build,prepare-source,assemble,scan}.sh`、`pipeline/lib/{safe_extract,jetson_build,jetson_assemble,jetson_scan,platform_scan}.py`（`platform_scan.py` 是各平台共用的 scan 後處理，其他平台怎麼呼叫見它的 docstring；`jetson_scan.py` 只剩 Jetson 特有的部分）、
`pipeline/{check-expected,release-meta}.py`；workflow：`.github/workflows/{pipeline,release,dev}.yml`；測試：`tests/test_jetson_pipeline.py`（`tests/run.d/c1-m2-jetson.sh`）。
介面與結束碼見 `docs/PLATFORM-INTERFACE.md`，分層見 `docs/LAYERS.md`。

## 1. 流程

```
tag orin-nano-demo/v39.2.1-demo1 ─► release.yml
  info        project-info.py <tag>（驗證格式、專案與版本存在）
  pipeline    pipeline.yml（reusable；dev.yml 也呼叫它；與平台無關，欄位來自 platform.yml）
    plan                       project-info.py 讀 platform.yml：build.mode／runner／apt、scan.runner／apt、arch
    build  (arm64 runner)      build.mode＝compile 才跑：fetch → prepare-source → nvbuild.sh → pack-build-record.sh → 整個 $DUMPLING_OUT/handoff/ 上傳成 artifact（1 天）
    scan   (amd64 runner)      handoff 放回同一個路徑 → fetch（重新下載 BSP／rootfs）→ assemble → scan → artifact（7 天）
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
   例外是核心 CVE 鏡像：git.kernel.org 有些 runner 連不上（TCP 約 133 秒後失敗，重試沒用），`kernel-cve.sh` 在上游連不上時會沿用 48 小時內、通過檢查的上一份（`actions/cache` 還原的 `kcve/`），最後一行是 `ATTENTION …`；`mirror` 算成功並記一列 `pipeline-kernel-cve-mirror ATTENTION`，**不擋 Release（正式 tag 也一樣），但 Release 說明、summary.md、release-meta.json 都標出來**。沒有可沿用的、或太舊 = 照舊 FAIL。實作在共用的 `pipeline/lib/mirrors.sh`（其他平台也用它），見 `docs/PLATFORM-INTERFACE.md`。
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

## 6b. build → scan 的交接（handoff）

`build.sh` 把交給 scan 的東西全放在 `$DUMPLING_OUT/handoff/`：`BuildRecord-<專案>-<版本>.tar.gz`、`deliverables.tar.zst`（Image、.ko、dtb、核心建置設定）、`kernel.release`、`kernel-subdir`、`build.json`、`nvbuild-tail.txt`、`build-summary.md`。
workflow 整個資料夾上傳、在 scan job 放回同一個路徑，**不指名個別檔案**（契約見 `docs/PLATFORM-INTERFACE.md`）；`assemble.sh`／`scan.sh` 從 `handoff/` 讀。

## 6c. 其他平台共用的部分（C4 之後的平台）

`platform.yml` 的 `arch`、`build.mode`／`runner`／`apt`、`scan.runner`／`apt`／`tools`、`pipeline/run-step.sh`（所有步驟同一個結束碼規則與 `pipeline-steps.tsv`）、`pipeline/install-scan-tools.sh`（`sbom-only`｜`full`）、
`pipeline/lib/platform_scan.py` 都與 Jetson 無關，契約見 `docs/PLATFORM-INTERFACE.md`。Jetson 沒設 `scan.tools`（預設 `sbom-only`），行為不變。
`scan.tools: full` 在 runner 上驗證過（Go 1.26 由 `actions/setup-go` 裝；Syft、Grype、cdxgen 12.8.7、govulncheck v1.9.0、guarddog 3.2.0 都在家目錄遮蔽的 bwrap 裡跑得起來；guarddog 的 venv 在 `/opt/dumpling-tools`，不在家目錄）。

## 7. 待確認（已採最保守做法，不阻擋）

1. **`public_sources.tbz2` 的整包 sha256 是首次下載記錄（TOFU）**：NVIDIA 沒有公布整包雜湊。若 NVIDIA 之後更新檔案，fetch 會因 sha256 不符而失敗（預期行為），要人工確認後才改 `sources.yml`。
2. **UEFI 未自編**（D-002）：刷機包裡的 UEFI、OP-TEE、MB1／MB2 以 BSP 原樣；A0 成品比對（`upstream-baseline-artifacts`）是否對得上 BSP 見第 8 節。
3. **assemble 是近似值**（第 4 節）：所有 arm64／all 的 NVIDIA 套件都併進 rootfs，不依板子挑；沒有維護者腳本產生的檔案。真實出貨的刷機包是 `apply_binaries.sh` 的結果。
4. **刷機包的 dtb**：CI 的 `make dtbs` 也編出同名 dtb 的（只有一個）換成 CI 的，其餘（`.dtbo` 疊加檔等）保留 BSP 的；換了哪些記在 `assemble.json` 的 `dtb_replaced`。dtb 目前沒有 CVE 資料，只記身分。
5. **映像裡的核心建置設定**：CI 的 `.config`、`Makefile`、`Module.symvers` 放在 `usr/lib/modules/<版本>/build/`（NVIDIA 的 headers 套件裡沒有掃描要的頂層 `.config`），讓 `C-kernel-config` 找得到出貨核心的設定；真實出貨的 headers 套件內容要由 RD 確認。
6. **NVD 沒開**（PLAN 已知卡點：NVD 第一次同步要 1–3 小時），`D-dt-data-sources`／`C-dt-feeds` 因此是 GAP；弱點資料來自 OSV、Grype、CISA／ENISA KEV、NVIDIA 公告、Linux 核心 CNA。ENISA EU KEV 的檔沒有發布日期（`D-dt-kev-sources` GAP）。
7. **完整掃描也會建一個 DT 專案與一份報告**（第 5 節第 3 點），分層後 `-bsp`／`-os` 才是各自的待辦；完整那份只當對照。DT 的專案階層（parent／child）沒用（見 `docs/LAYERS.md`）。
8. **標準答案的漏洞數用範圍**，因為資料庫每天變；元件數、核心版本、狀態用 equals。範圍是跑第一次的實際值上下抓寬鬆，之後資料庫變化讓範圍不符時，人工看過再改範圍並寫理由。
9. ~~L 軌的測試 `test_untagged_sbom_changes_nothing` 偶爾失敗~~：已修（測試比對風險評估文字時，VEX 檔的 SHA-256 也正規化；沒有掃描時間時 VEX 用現在時間，跨秒時 SHA 不同）。
10. **patch 版在報告上看不出差別**：v39.2.1 的 patch 修的是一個（示範用的）CVE，但報告沒有「patch → CVE」的對應，漏洞清單與 P1 判斷表裡那個 CVE 兩版都是「受影響－有編進核心」。patch 的效果只在上游比對（被修改的檔案 1）與建置紀錄看得到；要讓報告標成已修補，要另加 VEX 規則或 patch 的 CVE 對應（M2 之後）。
10b. **示範專案的 `vex-rules.json` 只留依證據的規則 K1、K2、U1**（C0 決定，2026-11-13）：範例的批次分流規則 R1～R5 作者只寫角色、日期是範例日期，會替大量的列寫進沒有人做過的 VEX 判斷（exploitable／in_triage 與處置建議），已拿掉。K1、K2、U1 要有具名作者才生效，示範專案沒有，所以實際上不判任何列。new-project.sh 不帶範例規則排在 M7。
    更正（驗收 run 43399785656、43399800268）：f11bfdb 的 commit 訊息與本條原文說 R1～R5「會把約 2990 列判成 accepted」是錯的——R1～R5 只設 exploitable／in_triage，不產生 accepted。bsp 報告的 accepted 2990 列拿掉前後都一樣，全部來自核心設定檢查（VEX `source: kconfig`、`code_not_present`：建置紀錄顯示修補的程式檔沒有編進任何核心物件），不靠 vex-rules。這類自動排除在 M7 照 D-035 補記依據類型 `build-record`。
11. **兩版 VEX 的產品版本字串相同**：`metadata.component.version` 取自 `CRA/Config/config.json` 的 `product.version`（示範專案兩版共用一份），只能靠檔名區分版本。真實專案每一版要更新 `product.version`。
12. **完整掃描的報告與 DT 專案含 host-tool**：完整掃描上傳的是拆分前的 SBOM；分層後的 `-bsp`／`-os` 不含 host-tool。Jetson 的 host-tool 是 0 個所以沒影響；其他平台以分層報告為準（完整那份只當對照，見第 7 點）。
13. **步驟表的 validate、fetch 各出現兩次**：build job 與 scan job 各執行一次，`pipeline-steps.tsv` 各記一列（Release 說明與 `release-meta.json` 的 steps 照列）。結果一致，只是重複。
14. **scan 回 NOT_RUN 時 `pipeline_result` 降成 GAP**（`step_rows`：說明不是「不適用」開頭的 NOT_RUN 至少 GAP；PR #42 之前不降級）。另外 scan 沒有執行時不會有 `notes.md`，Release 步驟會失敗，所以不會發出看起來正常的 Release。
15. **標準答案的範圍是第一次 CI 的實際值上下抓寬鬆**（第 8 點），不是獨立的依據；元件數、核心版本、狀態是 equals。

## 8. 跑通結果（2026-11-12；數字隨弱點資料庫變動，固定的部分在 `tests/expected/orin-nano-demo/*.json`）

| | `v39.2.0-demo1` | `v39.2.1-demo1`（套 patch） |
|---|---|---|
| 核心 | 6.8.12-1021-tegra | 6.8.12-1021-tegra |
| 建置紀錄狀態（`kernel.build_record.status`） | OK | OK |
| C-kernel-boot | OK | OK |
| 上游比對（原始碼）被修改的檔案 | **0** | **1**（`kernel/kernel-noble/net/ipv4/inet_connection_sock.c`） |
| 上游比對（成品）| OK（62 個閉源開機韌體與 NVIDIA 原版相同） | OK（同左） |
| 元件 | 115,170（bsp 22,890／os 87,518／unknown 4,762） | 115,943（bsp 22,893／os 88,263／unknown 4,787） |
| 漏洞列（完整／-bsp／-os） | 10,211／6,578／3,656 | 10,018／6,589／3,458 |
| P1 判斷表列數（bsp＋unknown） | 10 | 10 |
| nvbuild.sh | 1,899 秒 | 1,941 秒 |

- 兩個版本的差異報告（`tools/cra/report_diff.py` 對兩份 -bsp 報告）：新增 33 列、消失 22 列，分類／判定／修補資訊的改變都是 0；消失的列原因是 `nvidia-l4t-core 39.2.0-… → 39.2.1-…`（元件版本變了），沒有「原因未判定」以外的猜測。
- `C-kernel-config` 是 ATTENTION：映像的 headers `.config`（CI 編完後的 `.config`）和燒錄核心內建的 IKCONFIG 差 7 個設定（`CONFIG_CC_VERSION_TEXT` 等由編譯器決定的項目），掃描依設計改用燒錄核心的內建設定。
- 第一次實跑發現並修掉的問題：(1) assemble 寫 tar 時，PAX 格式的長路徑成員帶著舊的 `path` 標頭，改名後仍寫回沒有 `Linux_for_Tegra/rootfs/` 前綴的舊路徑（rootfs 少了 18,431 個檔案）——`jetson_assemble.py` 清掉讀進來的 `pax_headers`，並有測試；
  (2) 映像裡沒有核心的 `.config` 與 `Makefile`（NVIDIA 的 headers 套件沒有掃描要的頂層檔案）→ `C-kernel-config` GAP，建置紀錄沒被採用——assemble 把 CI 的建置設定放進 `usr/lib/modules/<版本>/build/`；
  (3) Syft 的檔案紀錄讓 unknown 變成 9 萬多個——用 dpkg `.list` 的擁有者分層（見 `docs/LAYERS.md`）；(4) l4t 核心對應列的 `mapped_from` 是「名稱 版本」，原本找不到層。
- Release 步驟的 403：第一次兩個完整的 run（build＋scan 共約 1.5 小時），最後的 `release` job 呼叫 GitHub API（列出 release）回 `403 Resource not accessible by integration`；同一個 job 重跑也一樣。同樣的步驟在新的 run（沿用 scan artifact）和獨立探測 workflow（包含 62 分鐘之後才呼叫）都成功，原因沒查出來（排除了 token 過期、事件類型、權限設定）；之後的完整 run 見第 9 節。

## 9. 最終驗證（handoff 與 run-step 版本的 workflow，2026-11-13）

兩個版本各做一次完整的 `release.yml` 手動觸發（build＋scan＋Release，不重用任何 artifact；手動觸發只建 draft，不建 git tag）：

| | `v39.2.0-demo1` | `v39.2.1-demo1` |
|---|---|---|
| run | 43331496725 | 43331490342 |
| build job | 約 34 分鐘 | 約 38 分鐘（`nvbuild.sh` 2,032 秒） |
| scan job | 約 40 分鐘 | 約 39 分鐘（scan 步驟 1,640 秒，assemble 504 秒） |
| 整個 run | 綠燈，含最後的 Release job（建 draft，19 個附件） | 同左（run 約 1 小時 17 分鐘，Release job 在 1 小時後照樣成功） |
| `pipeline-steps.tsv` 整體狀態／標準答案 | OK／23 項符合 | OK／23 項符合 |
| 建置紀錄、C-kernel-boot | OK、OK | OK、OK |
| 上游比對（原始碼）被修改的檔案 | 0 | 1 |

- Image 的 SHA-256 兩次建置都不同（建置不可重現）：v39.2.1 第一次 `d39b0e3a…`、`b220eaee…`，最終 `ce766751…`；v39.2.0 最終 `3167d1d6…`。
- 附件 19 個：`report-*.zip`×3（完整、-bsp、-os）、`sbom-*.cdx.json`×3、`vex-*.cdx.json`×3、`vuln-list-*.xlsx`×3、`p1-table-*.xlsx`×3、`layers.json`、`build-record-*.json`、`scan-summary-*.json`、`release-meta.json`。
- Release 的 403：最終的兩個完整 run 沒有再出現。中間有 3 次（含 dev.yml 的 publish）在列出 releases 時回 403，原因沒查出來；`release.yml` 與 `dev.yml` 的 API 呼叫現在每 30 秒重試、最多 8 次，仍失敗就印出回應標頭當診斷（`ghx`）。

合併 `origin/wp1/m2`（rpi 與原始碼的變更、K 軌 `--kernel-version`）、加入 `scan.tools` 與 `scan.runner` 之後，再各跑一次（沿用同一份 build 的 handoff，只重跑 scan）：`v39.2.0-demo1`（run 43347016848）綠燈、標準答案 23 項符合，與合併前的數字相同。

核心 CVE 鏡像的 cache 與 ATTENTION（C1 追加）之後的驗證（commit `b31f247`）：dev.yml 手動觸發（run 43360084178，v39.2.1，沿用 build，只跑 scan；非 main／dev 分支，所以只建 draft `dev/orin-nano-demo`，5 個附件）綠燈，cache 沒有命中，新抓的鏡像存進 `kernel-cve-mirror-43360084178-1`（35 MiB）；
release.yml 手動觸發（run 43365351840，v39.2.0）還原了那份 cache（`Cache restored from key: kernel-cve-mirror-43360084178-1`），鏡像 `kcve` 是 OK，標準答案 23 項符合，draft 19 個附件。ATTENTION（上游連不上、沿用舊的）在 runner 上沒有實際遇到，
用本機的 `file://` 來源加一個壞網址跑過真正的 `kernel-cve.sh`＋`mirrors.sh`：最後一行 `ATTENTION …`、`pipeline-steps.tsv` 多一列 `pipeline-kernel-cve-mirror`、整體狀態 ATTENTION、`mirror_is_fresh` 回 false（不會存回 cache）；單元測試涵蓋 OK、ATTENTION、FAIL 三種結果與 collect／release-meta 的整體狀態。
`dev.yml` 的 `concurrency` 是同一個 ref 後面的 run 取消前面的（`cancel-in-progress`），所以在同一個分支連續手動觸發兩次 dev，第一次會被取消。
Release 的 403 又出現兩次（run 43346232399 與 43346236827，commit `7f12e63`，重試 8 次加整個 job 重跑都失敗），在 `POST /releases` 回 403，同時間 `GET` 正常；同一個 commit 之後的 commit 重跑就成功，包括對舊 commit 的 run 重跑 Release job。原因仍不明，不是舊 commit 本身（舊 commit 的 run 重跑成功）、不是同時執行（單獨重跑也失敗）。

### M2 驗收 run（commit `9f1d2f0`，2026-11-13）

release-meta 的產品結論欄位、`kernel-versions` 附件、平台設定的核心上游版本加進來之後，兩個版本各做一次完整的 `release.yml` 手動觸發（從新的 build，不沿用 artifact；只建 draft）：

| | `v39.2.0-demo1` | `v39.2.1-demo1` |
|---|---|---|
| run | 43375548090 | 43375551920 |
| build job／scan job／整個 run | 33／40／74 分鐘 | 32／51／86 分鐘 |
| 附件 | 20 個（上面 19 個加 `kernel-versions-*.json`） | 20 個 |
| 標準答案 | 23 項符合 | 23 項符合 |
| 建置紀錄、C-kernel-boot | OK、OK | OK、OK |
| 上游比對（原始碼）被修改的檔案 | 0 | 1（`kernel/kernel-noble/net/ipv4/inet_connection_sock.c`，patch 版的那個 patch） |
| `release-meta.json` 的 report_status／release_gate／pipeline_result | GAP／GAP／OK | GAP／GAP／OK |
| `kernel-versions-*.json` | schema `/2`，出貨核心 1 顆，上游版本 6.8.12（`source-makefile`） | 同左 |

- report_status 與 release_gate 是 GAP：臨時 DT 關了 NVD（M1 的設計），cra_report 對沒有 NVD 的評分記 GAP；這是產品結論，和 workflow 步驟（pipeline_result OK）分開。
- 核心 CVE 鏡像：`wp1/m2` 還沒有自己的 cache（actions/cache 只還原同一個分支和預設分支的），兩個 run 都重新抓，成功後存成 `kernel-cve-mirror-<run>-1`。
- 之後的 `7dd351c`（scan_plan 改用 0x1F 分隔、collect 對同一後綴取後面那次）只影響 `os_responsibility: ours` 的路徑；這個專案是 customer，`-bsp`／`-os` 兩項的讀法與輸出不變，所以沒有重跑。
