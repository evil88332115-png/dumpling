## M2：Jetson 版本打 tag 全程跑通、產出 Release；平台介面與開案範本；SBOM／報告／DT 依層分開

PLAN「里程碑」M2：**打 tag 後 Jetson 版本全程跑通，產出 Release**，另含 C1 的平台介面與開案範本（給 C4）和依層分開（WP6）。依 D-020 做成一個 PR。

### 內容
- **Jetson 流程**（`pipeline/platforms/jetson/`、`.github/workflows/{release,dev,pipeline}.yml`）：validate → fetch（NVIDIA 公開 BSP、範例 rootfs、public_sources；sha256 核對，只下載不執行）→ build（arm runner 原生編核心與樹外模組，約 33 分鐘）→ assemble（組刷機包）→ scan（精靈完整掃描一次、分層後每層重跑一次）→ Release。build 與 scan 拆成兩個 job，交接只走 `$DUMPLING_OUT/handoff/`；每一步的結束碼經 `pipeline/run-step.sh`（OK 0／FAIL 1／GAP 3／NOT_RUN 4）記進 `pipeline-steps.tsv`。push tag 建正式 Release，手動觸發只建 draft；`dev.yml` 在 main／dev/** 發滾動 pre-release `dev/<專案>`。
- **Release 附件**（ASCII 檔名，中文名稱放 manifest 標籤）：每份報告（完整、-bsp、-os）的報告包 zip、SBOM、VEX、漏洞清單.xlsx（`vuln-list-*`）、P1判斷表.xlsx（`p1-table-*`），加 `layers.json`、`build-record-*.json`、`scan-summary-*.json`（標準答案比對用）、`kernel-versions-*.json`、`release-meta.json`。
- **release-meta.json 的結論欄位**：`status` 是生命週期（shipped／development），產品結論是 `report_status`（cra_report summary.json 的 status，分層時取最差）與 `release_gate`（VEX 發行閘門），workflow 步驟是 `pipeline_result`（原本的 `result` 改名）；Release 說明開頭依序印這三個。
- **平台介面與開案範本**（`pipeline/platform.sh`、`pipeline/new-project.sh`、`templates/project/`、`pipeline/lib/project_config.py`、`docs/PLATFORM-INTERFACE.md`）：`pipeline/platform.sh <validate|fetch|build|assemble|scan|raw-sectors> <專案> <版本>`；project.yml（`os_responsibility: ours|customer|upstream-vendor`）、sources.yml（`releases.<版本>.files[]`、`platform_params`）、platform.yml（分層的套件名稱清單、build／scan 的 runner 與 apt、`scan.platform_arg`、`scan.tools`）；平台無關的 scan 後處理在 `pipeline/lib/platform_scan.py`（C4 的 Raspberry Pi、Rockchip、AI NAS 已在用）。
- **依層分開**（`pipeline/sbom-layers.py`、`docs/LAYERS.md`）：SBOM 拆成 bsp（＋unknown）／os／host-tool（不上傳），cra_report 每列標 layer／layer_todo；customer／upstream-vendor 時 DT 兩個平行專案、兩份報告，P1 判斷表只放我們的待辦；ours 時一份報告、OS 也是待辦。
- **核心**：`--kernel-version`（可重複）與 `scan/kernel-versions.json`（出貨的核心、上游版本與依據、哪些有判定）；出貨但沒判定的核心各記 GAP；平台設定的核心上游版本（`platform_params.kernel_upstream_version`）和原始碼 Makefile 核對；分層的 -os 報告沒有核心時核心階段記 NOT_RUN「不適用」（`--kernel-in-other-report`）；核心不在發行版序列上（epoch、+rpt／+rpi、原始碼套件不是發行版的、平台明確宣告）時 C-kernel-coverage 記 GAP（D-044；真正的修法在 M7）。
- **核心 CVE 鏡像**：`tools/mirror/kernel-cve.sh` clone 重試；上游連不上時沿用 48 小時內的上一份（actions/cache；ATTENTION，不擋發佈）。
- **自有軟體**：沒有宣告 `sbom.own_software` 時 B-own-software 記 GAP（以前不執行、不寫狀態列）；`own_software: []` 加 `own_software_none_reason` 是明確宣告沒有。
- **標準答案**（`tests/expected/orin-nano-demo/*.json`，`pipeline/check-expected.py`）：24 項（元件數、核心版本、建置紀錄、C-kernel-boot、上游比對、各層漏洞數與 P1 列數、自有軟體）。
- **示範專案** `projects/orin-nano-demo/`：v39.2.0-demo1（對照）與 v39.2.1-demo1（套一個上游已修的核心 patch，上游比對顯示 1 個被修改的檔案）。CRA 設定只留必填欄位（不是真實產品，文件標 TO BE COMPLETED）。
- **`docs/PROVENANCE.md`**：M2 改到的 `tools/` 每個檔都在該列加了 M2 的改動說明（見下面的逐檔對照表）；新增資料檔的來源。
