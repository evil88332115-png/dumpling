# PROVENANCE：從 sca-center 複製的檔案

每個從 sca-center 複製進來的檔案記一列：dumpling 路徑、sca-center 原路徑、來源 commit、清理了什麼。
目錄對應規則（D-015）：sca-center 的 `scripts/<子目錄>/<檔名>` → dumpling 的 `tools/<子目錄>/<檔名>`；測試 `scripts/<子目錄>/tests/` → `tools/<子目錄>/tests/`。
各節只由負責的對話修改，避免衝突。

## C1 工具（WP1）

來源 commit 一律是 sca-center `25fa89a`（`origin/main`）。`pipeline/` 與 `ci/`、`tests/run.d/` 的檔案是 dumpling 自己寫的（做法參考對應的 sca-center 檔）。

| dumpling 路徑 | sca-center 原路徑 | 來源 commit | 清理內容 |
|---|---|---|---|
| `pipeline/dt-compose.yaml` | `scripts/e2e/dt-compose.yaml` | 25fa89a | 改名 e2e-dt→dumpling-dt；埠改成 `${DT_PORT:-8080}`；註解改寫；映像 digest 與其餘設定不變 |
| `pipeline/dt-ephemeral.sh` | `scripts/e2e/dtlib.sh`（做法參考，重寫） | 25fa89a | 改寫成 up／wait／env／down 四個子指令；狀態檔取代 sca-center 的 status／secret 函式；關 NVD、開 OSV 與 KEV、API key 流程沿用；新增 KEV 與 OSV 鏡像等待與逾時 GAP、`::add-mask::`；驗證代理審查後再改：admin 密碼改用權限 600 的 curl 設定檔（不在 `ps` 看得到的指令列）、`DT_OSV_ECOSYSTEMS` 驗證格式並以 argv 傳進 python（不內插進原始碼）、`down` 只刪有標記檔的狀態資料夾、`up` 設定後讀回確認（NVD 關、OSV 開且生態系一致、KEV 開）、`up` 觸發鏡像回 409 時 `wait` 只接受完成時間在觸發之後的鏡像（讀不到完成時間就在狀態行註明未核對）、`wait: OK` 改為「必要鏡像完成」 |
| `pipeline/scan-status-check.py` | （dumpling 自己寫） | — | 新增：檢查 `tools/pilot/sca-scan` 的 status.tsv，必要階段都要是 OK 且沒有 FAIL（dt-smoke 用） |
| `pipeline/dt-verify.py` | `scripts/e2e/dtread.py`（分頁與 X-Total-Count 核對的做法） | 25fa89a | 重寫：專案、元件數、依生態系漏洞數的驗證與摘要；另含直接上傳的後備模式 |
| `tests/fixtures/jetson-r39.2.1-base.cdx.json.xz` | `tests/fixtures/jetson-r39.2.1-base.cdx.json.xz` | 25fa89a | 清理（解壓後單行 JSON）：SBOM 內約 2900 個信箱改成 maintainer@example.com、掃描時的暫存路徑（含 runner 帳號資料夾與自架 runner 的工作目錄結構）改成 /path/to/work/.sca-scan-work.…/image.tar（metadata.component.name，僅此一處）、一個 package-id 雜湊改了一碼（避免和禁用字清單的偶然子字串相符）；其餘（Syft 1.55.0 對公開 Jetson rootfs 的 CycloneDX）原樣 |
| `tools/cra/board_import.py` | `scripts/cra/board_import.py` | 25fa89a | 路徑調整 2 處 |
| `tools/cra/bootloader_coverage.py` | `scripts/cra/bootloader_coverage.py` | 25fa89a | 路徑調整 2 處；**行為修改（M2）**：新增 `--unspecified`（沒指定平台時開機程式分類標 GAP「沒有指定平台，不推測」） |
| `tools/cra/company.example.json` | `scripts/cra/company.example.json` | 25fa89a | 原樣 |
| `tools/cra/config.example.json` | `scripts/cra/config.example.json` | 25fa89a | 原樣 |
| `tools/cra/config.schema.json` | `scripts/cra/config.schema.json` | 25fa89a | 路徑調整 4 處、清理 1 行（其他 1）、「內部窗口」→「專案負責人」、「老闆」→「核准人」（公開版不放公司內部稱呼）；「handoff 分支的內部文件路徑」改成「專案文件「供應商資料包規格」」；**新增欄位（M2）**：`sbom.own_software_none_reason`（產品沒有自有軟體的明確宣告）；`sbom.own_software` 的說明改成「沒寫或空陣列 → B-own-software GAP」 |
| `tools/cra/confirm_items.py` | `scripts/cra/confirm_items.py` | 25fa89a | 路徑調整 4 處、清理 26 行（其他 26）、「內部窗口」→「專案負責人」、「老闆」→「核准人」（公開版不放公司內部稱呼）；**行為修改（M2）**：`scan/kernel-versions.json` 有沒判定的核心時，待確認事項多一筆 `kernel:not-judged`（沒有檔案時輸出不變） |
| `tools/cra/cra_report.py` | `scripts/cra/cra_report.py` | 25fa89a | 路徑調整 42 處（說明文字與路徑字串）；「內部窗口」→「專案負責人」（公開版不放公司內部稱呼）；提到 CLAUDE.md 的說明與輸出字串改成「專案規則」／project rule（dumpling 沒有那個檔）；「Ubuntu Tracker deferred 當 not-fixed」那段註解原本引用內部某次實測的列數，改成引用 Ubuntu CVE Tracker 對 deferred 的公開定義（判定本身沒改）；註解：移除上游私有 repo 的編號與內部部署描述；**行為修改（M2 分層）**：新增 `--os-responsibility`；SBOM 元件帶 `dumpling:layer` 時才動作（沒有時輸出不變）：漏洞列加 `layer`／`layer_todo`／`layer_basis`、host-tool 元件的比對結果移出產品清單、整體狀態（ATTENTION）與依日期的出貨關卡只看我們的待辦（OS 層在 customer／upstream-vendor 時不算）、沒給 os_responsibility 標 GAP 並全部列入待辦、風險評估多一節「Layers」（通知客戶、unknown、host tools）、`summary.json` 與 `vulnerability-rows.json` 多 `layers`；發行閘門（vex_export）不變；**行為修改（M2 J 軌／D-030）**：unknown 附判斷不了的原因（SBOM 元件的 `dumpling:unknown-reason`，`summary.json` 的 `layers.unknown_by_reason`、風險評估 Layers 一節、`漏洞清單.xlsx` 分層摘要依原因計數）；host-tool 一節加一句「隨 BSP 提供給客戶，在客戶的主機上執行，不在產品上執行」；l4t 核心對應列的 `mapped_from`（「名稱 版本」）用名稱找層；沒有分層屬性的 SBOM 輸出不變；**行為修改（M2）**：沒有列自有軟體但有 `own_software.py --declaration` 寫的宣告檔時，SBOM 文件照樣標出來（沒宣告 → GAP；明確宣告沒有 → OK，sbom.md 寫理由與「掃描沒有驗證」）；沒有宣告檔的流程輸出不變；**行為修改（M2 分層，第三輪驗證）**：分層的 SBOM 沒有 bsp／unknown 元件時（-os），刷機包韌體、UEFI／OP-TEE 內建函式庫不加元件、不產生列、狀態不算進這份（`layers.bsp_inputs_not_applicable`），避免和 -bsp 報告重複計算；**行為修改（M2 後續：掃描層 NOT_RUN，PR #42 C0 驗證應修 2）**：新增 KERNEL_STAGES（C-kernel-cve-list／config／module-map／versions／cve-mirror 與 C-kernel-not-judged-*）——不是 OK 時風險評估資料狀態降成 GAP（ATTENTION 維持），只有 meta.json 有 kernel_in_other_report 時三個核心階段的 NOT_RUN 不降級（D-044，不看說明文字）；8.1 資料狀態表列出這些階段 |
| `tools/cra/data/support-lifecycle.json` | `scripts/cra/data/support-lifecycle.json` | 25fa89a | 原樣 |
| `tools/cra/dt_writeback.py` | `scripts/cra/dt_writeback.py` | 25fa89a | 原樣 |
| `tools/cra/evidence_bundle.py` | `scripts/cra/evidence_bundle.py` | 25fa89a | 路徑調整 2 處、說明文字：內部主機名稱改成「本機」（1 行）；**行為修改（M2）**：證據包多收 `scan/kernel-versions.json` |
| `tools/cra/exploited_grype.py` | `scripts/cra/exploited_grype.py` | 25fa89a | 路徑調整 10 處、清理 2 行（本機路徑換成中性路徑 1、其他 1）、提到 CLAUDE.md 的說明與輸出字串改成「專案規則」／project rule（dumpling 沒有那個檔）；註解：移除上游私有 repo 的編號與內部部署描述 |
| `tools/cra/exploited_vendor.py` | `scripts/cra/exploited_vendor.py` | 25fa89a | 清理 1 行（其他 1）、提到 CLAUDE.md 的說明與輸出字串改成「專案規則」／project rule（dumpling 沒有那個檔） |
| `tools/cra/exploited_watch.py` | `scripts/cra/exploited_watch.py` | 25fa89a | 路徑調整 11 處、清理 2 行（其他 2）、提到 CLAUDE.md 的說明與輸出字串改成「專案規則」／project rule（dumpling 沒有那個檔） |
| `tools/cra/firmware_bom.py` | `scripts/cra/firmware_bom.py` | 25fa89a | 路徑調整 2 處、說明文字：提到 CLAUDE.md 的說明與輸出字串改成「專案規則」／project rule（dumpling 沒有那個檔）；註解：移除上游私有 repo 的編號與內部部署描述 |
| `tools/cra/image_check.py` | `scripts/cra/image_check.py` | 25fa89a | 路徑調整 3 處、說明字串：systemd 樣板單元名稱的範例信箱樣式改成佔位文字（見「影響邏輯的替換」） |
| `tools/cra/initrd_coverage.py` | `scripts/cra/initrd_coverage.py` | 25fa89a | 原樣 |
| `tools/cra/kernel_modules.py` | `scripts/cra/kernel_modules.py` | 25fa89a | 路徑調整 7 處 |
| `tools/cra/no_vuln_data.py` | `scripts/cra/no_vuln_data.py` | 25fa89a | 路徑調整 1 處、清理 4 行（信箱換成 example／佔位 2、其他 1、去掉產品名或內部實測說明 1）、提到 CLAUDE.md 的說明與輸出字串改成「專案規則」／project rule（dumpling 沒有那個檔） |
| `tools/cra/nvidia_distro.py` | `scripts/cra/nvidia_distro.py` | 25fa89a | 原樣 |
| `tools/cra/own_software.py` | `scripts/cra/own_software.py` | 25fa89a | 原樣；**行為修改（M2）**：沒有列自有軟體時檢查不悄悄消失：`declaration()`（listed／none／undeclared／conflict）與 `--declaration`（寫只有宣告結果的 own-software.json、印 B-own-software：沒宣告 GAP，`own_software: []` 加 `own_software_none_reason` → OK）；列了又寫沒有的理由 → 設定錯誤 GAP；`--config` 只有 `--declaration` 可以不給；M2 第二輪驗證：設定矛盾（列了又寫沒有的理由）在 `entries()` 當設定錯誤，狀態列與 SBOM 文件都是 GAP |
| `tools/cra/pkg_why.py` | `scripts/cra/pkg_why.py` | 25fa89a | 路徑調整 2 處；註解：移除上游私有 repo 的編號與內部部署描述 |
| `tools/cra/py_dpkg_version.py` | `scripts/cra/py_dpkg_version.py` | 25fa89a | 路徑調整 1 處 |
| `tools/cra/report_diff.py` | `scripts/cra/report_diff.py` | 25fa89a | 路徑調整 1 處 |
| `tools/cra/report_package.py` | `scripts/cra/report_package.py` | 25fa89a | 路徑調整 1 處、清理 2 行（其他 2）、「內部窗口」→「專案負責人」、「老闆」→「核准人」（公開版不放公司內部稱呼）；**行為修改（M2 分層）**：`vulnerability-rows.json` 有 `layers` 區塊時才動作（沒有時輸出不變）：清單多「層」欄並依層排、P1 判斷表預設只放我們的待辦（可用 `--p1-layers` 覆寫）、OS 層（customer／upstream-vendor）另開工作表與「通知客戶」、新增「分層摘要」、總覽只含我們的待辦；**行為修改（M2 J 軌／D-030）**：unknown 附判斷不了的原因（SBOM 元件的 `dumpling:unknown-reason`，`summary.json` 的 `layers.unknown_by_reason`、風險評估 Layers 一節、`漏洞清單.xlsx` 分層摘要依原因計數）；host-tool 一節加一句「隨 BSP 提供給客戶，在客戶的主機上執行，不在產品上執行」；l4t 核心對應列的 `mapped_from`（「名稱 版本」）用名稱找層；沒有分層屬性的 SBOM 輸出不變 |
| `tools/cra/runtime_evidence.py` | `scripts/cra/runtime_evidence.py` | 25fa89a | 原樣；**行為修改（M2）**：kernel-config 帶 `scope_incomplete`（映像另有出貨但沒判定的核心）時不採用它的「沒編進核心」 |
| `tools/cra/security_findings.py` | `scripts/cra/security_findings.py` | 25fa89a | 路徑調整 6 處 |
| `tools/cra/supplier_package.py` | `scripts/cra/supplier_package.py` | 25fa89a | 清理 1 行（其他 1）、「handoff 分支的內部文件路徑」改成「專案文件「供應商資料包規格」」；客戶文字過濾用的正規表示式（含 CLAUDE\.md）沒動；註解：移除上游私有 repo 的編號與內部部署描述 |
| `tools/cra/support_check.py` | `scripts/cra/support_check.py` | 25fa89a | 路徑調整 1 處；註解：移除上游私有 repo 的編號與內部部署描述 |
| `tools/cra/tee_bundled.py` | `scripts/cra/tee_bundled.py` | 25fa89a | 原樣 |
| `tools/cra/tee_source.py` | `scripts/cra/tee_source.py` | 25fa89a | 原樣 |
| `tools/cra/templates/risk-assessment.md` | `scripts/cra/templates/risk-assessment.md` | 25fa89a | **行為修改（M2 分層）**：8.7 節 placeholder 串後面加 `{{ text.layer_section }}`（沒有分層時是空字串，輸出不變） |
| `tools/cra/templates/sbom.md` | `scripts/cra/templates/sbom.md` | 25fa89a | 原樣 |
| `tools/cra/templates/technical-documentation.md` | `scripts/cra/templates/technical-documentation.md` | 25fa89a | 原樣 |
| `tools/cra/templates/user-information.md` | `scripts/cra/templates/user-information.md` | 25fa89a | 原樣 |
| `tools/cra/tests/data/cyclonedx-1.5/`（bom-1.5.schema.json、README.md） | 不是 sca-center 的檔：CycloneDX/specification 的 `schema/bom-1.5.schema.json`（commit ad83dae2，Apache-2.0） | — | 官方檔案原樣下載，SHA-256 見 README.md。給 vexconv 測試用 |
| `tools/cra/tests/data/openvex/`（openvex_json_schema.json、README.md） | 不是 sca-center 的檔：openvex/spec 的 `openvex_json_schema.json`（commit 61b5f885，Apache-2.0） | — | 官方檔案原樣下載，SHA-256 見 README.md。取代 sca-center 的 `scripts/ci/fetch-test-data.sh` 連網取得 |
| `tools/cra/tests/test_bootloader_coverage.py` | `scripts/cra/tests/test_bootloader_coverage.py` | 25fa89a | 新增 `test_unspecified_platform_is_gap_not_guessed`（M2） |
| `tools/cra/tests/test_bootloader_report.py` | `scripts/cra/tests/test_bootloader_report.py` | 25fa89a | 原樣 |
| `tools/cra/tests/test_confirm_items.py` | `scripts/cra/tests/test_confirm_items.py` | 25fa89a | 清理 26 行（其他 26）、「內部窗口」→「專案負責人」、「老闆」→「核准人」（公開版不放公司內部稱呼）（斷言同步改）；註解：移除上游私有 repo 的編號與內部部署描述 |
| `tools/cra/tests/test_cra_deb_python_usn.py` | `scripts/cra/tests/test_cra_deb_python_usn.py` | 25fa89a | 原樣；註解：移除上游私有 repo 的編號與內部部署描述 |
| `tools/cra/tests/test_cra_distro.py` | `scripts/cra/tests/test_cra_distro.py` | 25fa89a | 路徑調整 3 處 |
| `tools/cra/tests/test_cra_euvd.py` | `scripts/cra/tests/test_cra_euvd.py` | 25fa89a | 原樣；註解：移除上游私有 repo 的編號與內部部署描述 |
| `tools/cra/tests/test_cra_exploitation.py` | `scripts/cra/tests/test_cra_exploitation.py` | 25fa89a | 刪段 7 行：讀 cra/README.md 的文件測試（README 沒帶）改成只保留 `KERNEL_NET_*` 常數斷言（`test_kernel_network_staging_list_constants`）；註解：移除上游私有 repo 的編號與內部部署描述 |
| `tools/cra/tests/test_cra_grype_only.py` | `scripts/cra/tests/test_cra_grype_only.py` | 25fa89a | 清理 3 行（皆為 CLAUDE.md 字樣）；提到 CLAUDE.md 的說明與輸出字串改成「專案規則」／project rule（dumpling 沒有那個檔）（斷言同步改） |
| `tools/cra/tests/test_cra_nvidia.py` | `scripts/cra/tests/test_cra_nvidia.py` | 25fa89a | 路徑調整 2 處；註解：移除上游私有 repo 的編號與內部部署描述 |
| `tools/cra/tests/test_cra_report.py` | `scripts/cra/tests/test_cra_report.py` | 25fa89a | 路徑調整 1 處、清理 8 行（私有 IP／近似 IP 的字串換成文件網段 2、本機路徑換成中性路徑 2、其他 1、路徑 1）、docstring 原本點名內部某次 e2e 的編號，改成中性說明；遮蔽路徑測試的輸入改用中性的 runner 路徑（不沿用 sca-center 自架 runner 的目錄結構），斷言意義不變；註解：移除上游私有 repo 的編號與內部部署描述 |
| `tools/cra/tests/test_cra_ubuntu_tracker_fix.py` | `scripts/cra/tests/test_cra_ubuntu_tracker_fix.py` | 25fa89a | 原樣 |
| `tools/cra/tests/test_cra_usn_fix.py` | `scripts/cra/tests/test_cra_usn_fix.py` | 25fa89a | 原樣 |
| `tools/cra/tests/test_customer_package_wording.py` | `scripts/cra/tests/test_customer_package_wording.py` | 25fa89a | 清理 2 行（本機路徑換成中性路徑 2） |
| `tools/cra/tests/test_dashboard_sheet.py` | `scripts/cra/tests/test_dashboard_sheet.py` | 25fa89a | 只有路徑調整與環境變數改名（`SCA_REQUIRE_TEST_DATA` → `DUMPLING_REQUIRE_TEST_DATA`，docstring 1 行） |
| `tools/cra/tests/test_dt_writeback.py` | `scripts/cra/tests/test_dt_writeback.py` | 25fa89a | 原樣 |
| `tools/cra/tests/test_evidence_bundle.py` | `scripts/cra/tests/test_evidence_bundle.py` | 25fa89a | 清理 3 行（產品代號換成中性代稱 2、本機路徑換成中性路徑 1） |
| `tools/cra/tests/test_exploited_vendor.py` | `scripts/cra/tests/test_exploited_vendor.py` | 25fa89a | 刪段 44 行、刪 4 個用到 alert_mail.py 的測試；移除 import alert_mail |
| `tools/cra/tests/test_exploited_watch.py` | `scripts/cra/tests/test_exploited_watch.py` | 25fa89a | 路徑調整 1 處；註解：移除上游私有 repo 的編號與內部部署描述 |
| `tools/cra/tests/test_exploited_watch_grype.py` | `scripts/cra/tests/test_exploited_watch_grype.py` | 25fa89a | 路徑調整 1 處、刪段 266 行、刪 11 個用到 alert_mail.py（compose／寄信）或 exploited-watch-daily.sh 的測試與 compose 輔助函式；註解：移除上游私有 repo 的編號與內部部署描述 |
| `tools/cra/tests/test_exploited_watch_refresh.py` | `scripts/cra/tests/test_exploited_watch_refresh.py` | 25fa89a | 路徑調整 2 處、刪段 323 行、刪 14 個用到 alert_mail.py、每日／備份腳本、deploy/ 安裝腳本的測試 |
| `tools/cra/tests/test_firmware_bom.py` | `scripts/cra/tests/test_firmware_bom.py` | 25fa89a | 清理 3 行（產品代號換成中性代稱 2、新增（資料／說明） 1）、刪段 15 行、schema 驗證改成 import 共用的 cdx_schema.cdx_validator（刪掉自己那份 SCHEMA_DIR／cdx_validator；D-017） |
| `tools/cra/tests/test_image_check.py` | `scripts/cra/tests/test_image_check.py` | 25fa89a | 清理 3 行（產品代號換成中性代稱 3）；註解：移除上游私有 repo 的編號與內部部署描述 |
| `tools/cra/tests/test_image_check_modules.py` | `scripts/cra/tests/test_image_check_modules.py` | 25fa89a | 原樣 |
| `tools/cra/tests/test_initrd_coverage.py` | `scripts/cra/tests/test_initrd_coverage.py` | 25fa89a | 原樣 |
| `tools/cra/tests/test_kernel_modules.py` | `scripts/cra/tests/test_kernel_modules.py` | 25fa89a | 路徑調整 2 處、清理 11 行（產品代號換成中性代稱 10、路徑 1）、刪段 5 行、刪 1 個測 board-on-device.sh 的測試；註解：移除上游私有 repo 的編號與內部部署描述；`consumer158()` 不再用 `git show` 讀上游另一個分支的 vex_export（dumpling 沒有那個分支，原本就回 None），直接回 None，測試行為不變 |
| `tools/cra/tests/test_kernel_scope.py` | （dumpling 自己寫） | — | 新增（M2）：映像另有出貨但沒判定的核心時，K1／K2 的排除不採用（vex_export、runtime_evidence、cra_report 的 VEX 檔案、風險評估與核心表的標記）；沒有限制時輸出相同 |
| `tools/cra/tests/test_kernel_versions_item.py` | （dumpling 自己寫） | — | 新增（M2）：`scan/kernel-versions.json`（出貨但沒判定的核心）→ 待確認事項 `kernel:not-judged`，沒有檔案時和以前相同。**`cra_report.py` 的行為修改（M2）記在這一列**：讀 `scan/kernel-versions.json` 交給待確認事項 |
| `tools/cra/tests/test_layers_report.py` | （dumpling 自己寫） | — | 新增（M2 分層）：cra_report／report_package 的分層測試：三種 os_responsibility 與沒給時的 GAP、ATTENTION 與出貨關卡的計算、host-tool 不進產品清單、unknown 當待辦、P1 判斷表與工作表；測資全部合成；M2：`test_untagged_sbom_changes_nothing` 比對時 VEX 檔的 SHA-256 也正規化（跨秒時間歇性失敗）；新增 ours 的端到端測試（OS 層的 P1 從 cra_report 一路到 P1 判斷表） |
| `tools/cra/tests/test_kernel_stages_status.py` | （dumpling 自己寫） | — | 新增（M2 後續：掃描層 NOT_RUN）：cra_report 的核心判定階段不是 OK → 風險評估與整體狀態 GAP（沒有 CNA 鏡像、沒給 --kernel-build、版本讀不出來、kernel_config 失敗、C-kernel-versions、C-kernel-not-judged-*）；ATTENTION 維持；meta.json 有 kernel_in_other_report 時三個 NOT_RUN 不降級、只有說明文字的「不適用」照樣 GAP、標記不免除 FAIL／GAP 與其他核心階段 |
| `tools/cra/tests/test_no_vuln_data.py` | `scripts/cra/tests/test_no_vuln_data.py` | 25fa89a | 清理 2 行（廠商信箱、免費信箱各改成已登記在 `ci/public-allow.txt` 的同網域信箱，判定只看網域）；libnvinfer 版本字串維持原值（登記在白名單，見「public-check 白名單」） |
| `tools/cra/tests/test_nvidia_distro.py` | `scripts/cra/tests/test_nvidia_distro.py` | 25fa89a | 原樣 |
| `tools/cra/tests/test_own_software.py` | `scripts/cra/tests/test_own_software.py` | 25fa89a | 原樣；新增（M2）：宣告的四種結果、`--declaration` 命令列、設定矛盾、cra_report 讀宣告檔；M2 第二輪驗證：設定矛盾時 build() 也是 GAP |
| `tools/cra/tests/test_pkg_why.py` | `scripts/cra/tests/test_pkg_why.py` | 25fa89a | 原樣 |
| `tools/cra/tests/test_py_dpkg_version.py` | `scripts/cra/tests/test_py_dpkg_version.py` | 25fa89a | 原樣 |
| `tools/cra/tests/test_report_diff.py` | `scripts/cra/tests/test_report_diff.py` | 25fa89a | 原樣 |
| `tools/cra/tests/test_report_package.py` | `scripts/cra/tests/test_report_package.py` | 25fa89a | 清理 4 行（環境變數改名 1、「內部窗口」→「專案負責人」3）（公開版不放公司內部稱呼）（斷言同步改） |
| `tools/cra/tests/test_runtime_evidence.py` | `scripts/cra/tests/test_runtime_evidence.py` | 25fa89a | 路徑調整 1 處、刪段 34 行、刪 2 個測板子端腳本 board-on-device.sh 的測試（腳本沒帶） |
| `tools/cra/tests/test_security_testing.py` | `scripts/cra/tests/test_security_testing.py` | 25fa89a | 路徑調整 1 處、清理 6 行（私有 IP／近似 IP 的字串換成文件網段 6）；註解：移除上游私有 repo 的編號與內部部署描述 |
| `tools/cra/tests/test_supplier_package.py` | `scripts/cra/tests/test_supplier_package.py` | 25fa89a | 清理 1 行（其他 1） |
| `tools/cra/tests/test_support_check.py` | `scripts/cra/tests/test_support_check.py` | 25fa89a | 原樣 |
| `tools/cra/tests/test_tee_source.py` | `scripts/cra/tests/test_tee_source.py` | 25fa89a | 原樣 |
| `tools/cra/tests/test_uefi_bundled.py` | `scripts/cra/tests/test_uefi_bundled.py` | 25fa89a | 原樣；註解：移除上游私有 repo 的編號與內部部署描述 |
| `tools/cra/tests/test_uefi_followup.py` | `scripts/cra/tests/test_uefi_followup.py` | 25fa89a | 原樣 |
| `tools/cra/tests/test_uefi_image.py` | `scripts/cra/tests/test_uefi_image.py` | 25fa89a | 原樣 |
| `tools/cra/tests/test_uefi_source.py` | `scripts/cra/tests/test_uefi_source.py` | 25fa89a | 路徑調整 1 處 |
| `tools/cra/tests/test_upstream_baseline.py` | `scripts/cra/tests/test_upstream_baseline.py` | 25fa89a | 清理 3 行（產品代號換成中性代稱 3） |
| `tools/cra/tests/test_vex_evidence.py` | `scripts/cra/tests/test_vex_evidence.py` | 25fa89a | 原樣；註解：移除上游私有 repo 的編號與內部部署描述 |
| `tools/cra/tests/test_vex_export.py` | `scripts/cra/tests/test_vex_export.py` | 25fa89a | 清理 8 行（其他 4、刪段 4）、刪段 2 行、CycloneDX 1.6 驗證改用 cdx_validator；OpenVEX schema 改讀 tests/data/openvex/（不再連網取得，也不再 skip）；註解：移除上游私有 repo 的編號與內部部署描述 |
| `tools/cra/tests/test_vex_no_response.py` | `scripts/cra/tests/test_vex_no_response.py` | 25fa89a | 刪段 30 行：刪 1 個用到 csaf_advisory.py 的測試，另 1 個只刪 CSAF 那一半（CDX／OpenVEX 那一半保留為 `test_legacy_responses_keep_cdx_and_openvex`）；移除對 test_csaf_advisory 的 import；註解：移除上游私有 repo 的編號與內部部署描述 |
| `tools/cra/tests/test_vex_rules.py` | `scripts/cra/tests/test_vex_rules.py` | 25fa89a | 清理 8 行（其他 4、刪段 4）、刪段 2 行、同 test_vex_export.py：cdx_validator＋tests/data/openvex/ |
| `tools/cra/tests/test_vex_u1_flag.py` | `scripts/cra/tests/test_vex_u1_flag.py` | 25fa89a | 路徑調整 4 處；註解：移除上游私有 repo 的編號與內部部署描述 |
| `tools/cra/tests/test_vex_u2.py` | `scripts/cra/tests/test_vex_u2.py` | 25fa89a | 原樣 |
| `tools/cra/uefi_bundled.py` | `scripts/cra/uefi_bundled.py` | 25fa89a | 清理 1 行（其他 1）、提到 CLAUDE.md 的說明與輸出字串改成「專案規則」／project rule（dumpling 沒有那個檔） |
| `tools/cra/uefi_dsc.py` | `scripts/cra/uefi_dsc.py` | 25fa89a | 原樣 |
| `tools/cra/uefi_image.py` | `scripts/cra/uefi_image.py` | 25fa89a | 清理 1 行（產品代號換成中性代稱 1） |
| `tools/cra/uefi_source.py` | `scripts/cra/uefi_source.py` | 25fa89a | 路徑調整 8 處 |
| `tools/cra/upstream_baseline.py` | `scripts/cra/upstream_baseline.py` | 25fa89a | 清理 1 行（產品代號換成中性代稱 1） |
| `tools/cra/vendor-watch.example.json` | `deploy/exploited-watch/vendor-watch.example.json` | 25fa89a | 原樣 |
| `tools/cra/vex-rules.example.json` | `scripts/cra/vex-rules.example.json` | 25fa89a | 路徑調整 1 處 |
| `tools/cra/vex_export.py` | `scripts/cra/vex_export.py` | 25fa89a | 路徑調整 4 處；註解：移除上游私有 repo 的編號與內部部署描述；**行為修改（M2）**：映像另有出貨但沒判定的核心（`scan/kernel-versions.json`）時，核心設定檢查（K1）與模組對應（K2）的排除不採用（`kernel_with_scope`、`kconfig_usable`、`module_map_of`），受影響的核心列加標記與說明；沒有限制時輸出不變 |
| `tools/cra/xlsx_min.py` | `scripts/cra/xlsx_min.py` | 25fa89a | 原樣 |
| `tools/demo/README.md` | `scripts/demo/README.md` | 25fa89a | 路徑調整 2 處；改寫 CI 分支流程與「已知限制」兩段（原本是 sca-center 的內部 CI 與執行編號，改成中性說明並指向 pipeline/） |
| `tools/demo/board-import.sh` | `scripts/demo/board-import.sh` | 25fa89a | 路徑調整 7 處 |
| `tools/demo/flash_package.py` | `scripts/demo/flash_package.py` | 25fa89a | 路徑調整 9 處；**移除 Android 支援**（不在範圍內）：刪掉 `amod()`、`android` 格式的偵測與讀取分支（`archive_format`、`open_stream`、`open_source`、`do_list`）；zip 一律視為 rockchip-zip；**行為修改（M2）**：boot 分割區選不出來時，ATTENTION 的說明帶上 `rpi_img` 的 `boot_why`（原本固定寫「沒有 FAT 的 boot 分割區」） |
| `tools/demo/jetson.sh` | `scripts/demo/jetson.sh` | 25fa89a | 路徑調整 4 處；改 1 行註解（內部 CI 分支名稱） |
| `tools/demo/jetson_lookup.py` | `scripts/demo/jetson_lookup.py` | 25fa89a | 原樣 |
| `tools/demo/jetson_rootfs.py` | `scripts/demo/jetson_rootfs.py` | 25fa89a | M2 J 軌：`--out-custom` 改為選填（不給就不寫模擬客製版）；其餘原樣 |
| `tools/demo/pack-build-record.sh` | `scripts/demo/pack-build-record.sh` | 25fa89a | 原樣 |
| `tools/demo/rockchip_img.py` | `scripts/demo/rockchip_img.py` | 25fa89a | 路徑調整 1 處；改 1 行註解（原本提到 `android_img.py`）。`ANDROID!` 開機映像標頭的辨識是 Rockchip 分割區內容的判斷，保留 |
| `tools/demo/rpi_img.py` | `scripts/demo/rpi_img.py` | 25fa89a | 路徑調整 1 處；**行為修改（M2）**：boot 分割區依內容選、不依順序（`_pick_boot`：FAT 根目錄或 `boot/` 有核心、`extlinux/`、`EFI/` 或 Raspberry Pi 韌體才算有開機檔；多個有開機檔時只在恰好一個是 EFI system 分割區時選它，否則不猜、`boot_why` 寫原因；只有 `config.txt` 不算）。原本固定取第一個 FAT，Radxa 等映像的第一個 FAT 是小的 config 分割區；只有一個 FAT 的映像（Raspberry Pi OS）結果不變 |
| `tools/demo/scan-flash-package.sh` | `scripts/demo/scan-flash-package.sh` | 25fa89a | 路徑調整 42 處、清理 7 行；**行為修改（M2）**：新增 `--platform`／`SCA_PLATFORM`，原始磁碟映像不再固定當成 raspberrypi，沒給平台標 GAP；**行為修改（M2 J 軌）**：`--platform generic`（沒有定義開機鏈：任何映像格式的開機程式分類走 `bootloader_coverage.py --not-assessed generic`，NOT_ASSESSED；空值仍是 GAP）、`--arch <arm64|amd64>`／環境變數 `SCA_ARCH`（`docker import --platform linux/<arch>`，預設 arm64，其他值結束碼 64）；**行為修改（M2 分層）**：新增 `--kernel-in-other-report <報告名稱>`／`SCA_KERNEL_IN_OTHER_REPORT` 與 `--kernel-not-distro <理由>`／`SCA_KERNEL_NOT_DISTRO`（格式不對 exit 64），原樣轉給 sca-scan；**行為修改（M2）**：沒有 `--product-config` 或設定沒有列 `sbom.own_software` 時，B-own-software-* 記 GAP（沒有宣告自有軟體；以前不執行、不寫狀態列），明確宣告沒有 → OK；M2 第二輪驗證：`--rescan-from` 沒給 `--archive`／`--dir` 而設定沒有列自有軟體時，照樣寫宣告的結果（不悄悄消失）；**行為修改（M2 第三輪驗收）**：UEFI／OP-TEE 內建函式庫的 Grype 比對（B-uefi-grype、B-tee-grype）從讀原始碼樹那一步拆出來，移到 sca-scan 之後（資料庫是 sca-scan 更新的；排在前面時全新機器的完整掃描一定 NOT_RUN），docker import 失敗時不比對，但有讀原始碼樹的那一種照樣寫 B-uefi-grype／B-tee-grype NOT_RUN（原因寫 sca-scan 沒有執行，D-043：沒做的不能悄悄消失）；測試 `tools/demo/tests/test_bundled_grype_order.py` |
| `tools/demo/tests/conftest.py` | `scripts/pilot/tests/conftest.py`（做法） | 25fa89a | 新寫（同 `tools/pilot/tests/conftest.py`）：以路徑載入 `tools/cra/tests/conftest.py` 的 hook，`DUMPLING_REQUIRE_TEST_DATA=1` 時 skip 算失敗 |
| `tools/demo/tests/test_flash_package.py` | `scripts/demo/tests/test_flash_package.py` | 25fa89a | 路徑調整 1 處、清理 52 行；註解：移除上游私有 repo 的編號與內部部署描述；M2：沒有產品設定或沒有列自有軟體時 B-own-software 記 GAP（改了原本「不寫狀態列」的斷言）、明確宣告沒有 → OK；M2 第二輪驗證：rescan 沒給 --archive 而沒有列自有軟體 → GAP；M2 第三輪驗收：`test_script_uefi_source_runs_before_import_and_is_optional` 改成 docker import 失敗時 B-uefi-grype 記 NOT_RUN、沒有 grype-run.json（比對移到 sca-scan 之後） |
| `tools/demo/tests/test_jetson_lookup.py` | `scripts/demo/tests/test_jetson_lookup.py` | 25fa89a | 原樣 |
| `tools/demo/tests/test_jetson_rootfs.py` | `scripts/demo/tests/test_jetson_rootfs.py` | 25fa89a | 原樣 |
| `tools/demo/tests/test_kernel_version_args.py` | （dumpling 自己寫） | — | 新增（M2）：`scan-flash-package.sh` 的 `--kernel-version`／`SCA_KERNEL_VERSIONS`（可重複、環境變數、不合法 exit 64、原樣交給 sca-scan；用假的 sca-scan 看收到的參數）。**該腳本的行為修改（M2）記在這一列**：新增 `--kernel-version`／`SCA_KERNEL_VERSIONS`，只轉給 sca-scan；另新增 `--kernel-upstream-version <核心版本>=<X.Y.Z>`（可重複，格式不對 exit 64），原樣轉給 sca-scan；**行為修改（M2）**：新增 `--kernel-in-other-report`／`--kernel-not-distro` 的測試（轉給 sca-scan、環境變數、命令列優先、不合法 exit 64、沒給時不加參數） |
| `tools/demo/tests/test_bundled_grype_order.py` | （dumpling 自己寫） | — | 新增（M2 第三輪驗收）：`scan-flash-package.sh` 的 B-uefi-grype／B-tee-grype 在 sca-scan 之後才跑（假的 sca-scan 寫標記檔模擬更新資料庫，假的 grype 只有標記檔存在時 db status 才 valid：比對在前 → NOT_RUN，在後 → OK）；讀原始碼樹仍在 sca-scan 之前 |
| `tools/demo/tests/test_pack_build_record.py` | `scripts/demo/tests/test_pack_build_record.py` | 25fa89a | 原樣 |
| `tools/demo/tests/test_rockchip_img.py` | `scripts/demo/tests/test_rockchip_img.py` | 25fa89a | 路徑調整 1 處、清理 2 行 |
| `tools/demo/tests/test_rpi_img.py` | `scripts/demo/tests/test_rpi_img.py` | 25fa89a | 原樣；新增（M2）4 個 boot 分割區選擇的測試（依內容不依順序、韌體與 `boot/` 子目錄、多個都像時不猜、只有一個 FAT 沒有開機檔仍用它；合成的映像） |
| `tools/demo/tests/test_wizard_kernel_version.py` | （dumpling 自己寫） | — | 新增（M2）：`cra-scan.py` 的 `--kernel-version`／`SCA_KERNEL_VERSIONS`（plan.json 的 `kernel_versions`、不合法 exit 64、掃描指令原樣傳給 scan-flash-package.sh）。**該腳本的行為修改（M2）記在這一列**：新增 `--kernel-version`／`SCA_KERNEL_VERSIONS`，原樣傳給 scan-flash-package.sh，plan.json 多一個 `kernel_versions`；另新增 `--kernel-upstream-version <核心版本>=<X.Y.Z>`（平台設定的上游版本，可重複，格式不對或同一顆兩個值 exit 64），原樣傳給 scan-flash-package.sh，plan.json 多一個 `kernel_upstream_versions`；**行為修改（M2）**：新增 `--kernel-in-other-report`／`--kernel-not-distro` 的測試（plan.json、環境變數與命令列優先、不合法 exit 64、交給 scan-flash-package.sh） |
| `tools/demo/tests/test_wizard_plan.py` | `scripts/demo/tests/test_wizard_plan.py` | 25fa89a | 平台範本清單去掉 `android.json`（1 處）；新增「工具版本」測試（`resolve_tools_rev`、`extract_tools`，約 60 行）；新增 `test_platform_is_explicit_and_never_guessed`（M2）；註解：移除上游私有 repo 的編號與內部部署描述 |
| `tools/e2e/dtread.py` | `scripts/e2e/dtread.py` | 25fa89a | 原樣 |
| `tools/e2e/install-tools.sh` | `scripts/e2e/install-tools.sh` | 25fa89a | 路徑調整 1 處；**行為修改**：新增第三個參數 `--sbom-only`（只裝 Syft、Grype 固定版本與 bubblewrap，給 dt-smoke 用；不裝 cdxgen、govulncheck、guarddog），bubblewrap 安裝與 userns 放寬抽成函式，完整安裝的行為不變；註解：移除上游私有 repo 的編號與內部部署描述 |
| `tools/e2e/sandbox.sh` | `scripts/e2e/sandbox.sh` | 25fa89a | 路徑調整 1 處；註解：移除上游私有 repo 的編號與內部部署描述 |
| `tools/mirror/euvd.sh` | `scripts/mirror/euvd.sh` | 25fa89a | 路徑調整 3 處 |
| `tools/mirror/grype-db.sh` | `scripts/mirror/grype-db.sh` | 25fa89a | 原樣；註解：移除上游私有 repo 的編號與內部部署描述 |
| `tools/mirror/kernel-cve.sh` | `scripts/mirror/kernel-cve.sh` | 25fa89a | 路徑調整 1 處；**行為修改（M2）**：clone 失敗時重試（`KERNEL_CVE_GIT_TRIES` 預設 3、`KERNEL_CVE_GIT_RETRY_DELAY` 30 秒起加倍、傳輸 60 秒低於 1 KB/s 放棄這一次）；上游連不上時可沿用 `KERNEL_CVE_FALLBACK_FROM` 的上一份鏡像（要通過 `--check`、sha256 與 SOURCE 相符、不是符號連結、`fetched_utc` 在 `KERNEL_CVE_FALLBACK_MAX_HOURS` 預設 48 小時內），SOURCE 另寫 `fallback=yes`／`fallback_utc`／`fallback_note`，最後一行印 ATTENTION（結束碼 0）；沒設定時行為不變 |
| `tools/mirror/nvidia-bulletins.sh` | `scripts/mirror/nvidia-bulletins.sh` | 25fa89a | 路徑調整 2 處 |
| `tools/mirror/osv-distro.sh` | `scripts/mirror/osv-distro.sh` | 25fa89a | 路徑調整 1 處 |
| `tools/mirror/ubuntu-cve-status.sh` | `scripts/mirror/ubuntu-cve-status.sh` | 25fa89a | 原樣 |
| `tools/pilot/README.md` | `scripts/pilot/README.md` | 25fa89a | 路徑調整 18 處、清理 2 行；內部掃描的執行編號改成「示範掃描」、「板子實測」依據說明改成設計預期（5 處）；註解：移除上游私有 repo 的編號與內部部署描述 |
| `tools/pilot/lib/common.sh` | `scripts/pilot/lib/common.sh` | 25fa89a | 路徑調整 4 處；註解：移除上游私有 repo 的編號與內部部署描述 |
| `tools/pilot/lib/data/distro-kernel-sources.json` | （dumpling 自己寫） | — | 新增（M2）：kernelcheck 規則 d 的來源套件清單（Debian 建核心的來源套件 `linux`、`linux-latest`、`linux-signed-{amd64,arm64,i386}`；永遠算 off-series 的 `linux-upstream`；Ubuntu 不套用其他來源），附出處（Debian package tracker 的標準頁面） |
| `tools/pilot/lib/data/kernel-included-c-6.1.json` | `scripts/pilot/lib/data/kernel-included-c-6.1.json` | 25fa89a | 路徑調整 1 處 |
| `tools/pilot/lib/data/kernel-included-c-6.8.json` | `scripts/pilot/lib/data/kernel-included-c-6.8.json` | 25fa89a | 路徑調整 1 處 |
| `tools/pilot/lib/deb_sources.py` | `scripts/pilot/lib/deb_sources.py` | 25fa89a | 路徑調整 1 處；註解裡的內部執行編號改成「Jetson R39.2.1 示範映像」（1 行） |
| `tools/pilot/lib/distro_recheck.py` | `scripts/pilot/lib/distro_recheck.py` | 25fa89a | 路徑調整 3 處；註解裡的內部執行編號改成「Jetson R39.2.1 示範映像」（1 行）；上限註解裡的「實測」數字改成概略估計（不留可能量自內部建置的精確數量，D-023），常數值不變 |
| `tools/pilot/lib/dtsources.py` | `scripts/pilot/lib/dtsources.py` | 25fa89a | 路徑調整 1 處；註解裡的內部執行編號改成「示範掃描」（1 行）；註解：移除上游私有 repo 的編號與內部部署描述 |
| `tools/pilot/lib/euvd.md` | `scripts/pilot/lib/euvd.md` | 25fa89a | 路徑調整 7 處、清理 1 行；註解：移除上游私有 repo 的編號與內部部署描述 |
| `tools/pilot/lib/euvd.py` | `scripts/pilot/lib/euvd.py` | 25fa89a | 路徑調整 6 處 |
| `tools/pilot/lib/kernel_boot.py` | `scripts/pilot/lib/kernel_boot.py` | 25fa89a | 清理 3 行 |
| `tools/pilot/lib/kernel_cna_version.py` | `scripts/pilot/lib/kernel_cna_version.py` | 25fa89a | 路徑調整 1 處；上限註解裡的「實測」數字改成概略估計（不留可能量自內部建置的精確數量，D-023），常數值不變 |
| `tools/pilot/lib/kernel_config.py` | `scripts/pilot/lib/kernel_config.py` | 25fa89a | 路徑調整 5 處、清理 1 行；另改 1 行說明（K1 預設 Image 的依據，見「影響邏輯的替換」）；上限註解裡的「實測」數字改成概略估計（不留可能量自內部建置的精確數量，D-023），常數值不變；**行為修改（M2）**：新增 `--list-kernel-versions`（只列出映像的核心模組目錄，不判定）與 `--also-list-kernel-versions`（讀映像的同一趟順便印出貨的核心）；`--source-tree-version`（只讀原始碼樹最上層 Makefile 的 X.Y.Z，沿用 `tree_version`） |
| `tools/pilot/lib/kernel_git_files.py` | `scripts/pilot/lib/kernel_git_files.py` | 25fa89a | 原樣 |
| `tools/pilot/lib/kernel_included_c.py` | `scripts/pilot/lib/kernel_included_c.py` | 25fa89a | 路徑調整 3 處（用法說明與輸出的 generator 欄位）；2026-11-12 補帶，讓 `lib/data/kernel-included-c-*.json` 可以重現 |
| `tools/pilot/lib/kernel_module_map.py` | `scripts/pilot/lib/kernel_module_map.py` | 25fa89a | 路徑調整 1 處；**行為修改（M2）**：新增 `--also-list-kernel-versions`（讀映像的同一趟順便印出貨的核心） |
| `tools/pilot/lib/kernel_oot_record.py` | `scripts/pilot/lib/kernel_oot_record.py` | 25fa89a | 原樣；上限註解裡的「實測」數字改成概略估計（不留可能量自內部建置的精確數量，D-023），常數值不變 |
| `tools/pilot/lib/kernel_versions.py` | （dumpling 自己寫） | — | 新增（M2）：映像出貨的核心哪些有判定（`scan/kernel-versions.json`：shipped、requested、judged、not_judged 與原因）；sca-scan 的 `--kernel-version` 用；schema `sca-center-kernel-versions/2`：`shipped` 每筆帶上游版本（`upstream_version`／`upstream_basis`／`upstream_note`，只認原始碼 Makefile，可用 `--upstream-version` 加平台設定的值核對） |
| `tools/pilot/lib/kernelcheck.py` | `scripts/pilot/lib/kernelcheck.py` | 25fa89a | 路徑調整 1 處；註解裡的內部執行編號改成「Jetson R39.2.1 示範映像」（1 行）；**行為修改（M2）**：新增「核心不在發行版的核心序列上」的判斷（`off_series`，規則 a 版本 epoch ≥ 1、b 廠商後綴 `+rpt`／`+rpi` 與名稱 `+rpt`／`-rpt-`、c `--not-distro-kernel <理由>`、d purl 的 `upstream=` 來源套件，清單在 `lib/data/distro-kernel-sources.json`；規則是「或」，所有成立的原因都記），成立時 `C-kernel-coverage` 是 GAP 即使 Grype 有核心比對；資料檔讀不到或格式不對 FAIL；`kernel-coverage.json` 新增 `off_series`、`not_distro_declared`；M2 第二輪驗證：規則 a 也看 purl 的 `epoch=` 限定詞；規則 d 的 Debian 含沒有版本號的 `distro=debian`；說明列出更多已知盲點 |
| `tools/pilot/lib/l4t-kernel-map.json` | `scripts/pilot/lib/l4t-kernel-map.json` | 25fa89a | 清理 2 個 `checked` 欄（原本引用廠商映像與內部 CI 執行編號，見資料來源） |
| `tools/pilot/lib/l4t_kernel.py` | `scripts/pilot/lib/l4t_kernel.py` | 25fa89a | 原樣；註解：移除上游私有 repo 的編號與內部部署描述 |
| `tools/pilot/lib/leakscan.py` | `scripts/pilot/lib/leakscan.py` | 25fa89a | 原樣 |
| `tools/pilot/lib/lockcheck.py` | `scripts/pilot/lib/lockcheck.py` | 25fa89a | 原樣；註解：移除上游私有 repo 的編號與內部部署描述 |
| `tools/pilot/lib/mirror_freshness.py` | `scripts/pilot/lib/mirror_freshness.py` | 25fa89a | 路徑調整 1 處 |
| `tools/pilot/lib/nvidia-bulletins.json` | `scripts/pilot/lib/nvidia-bulletins.json` | 25fa89a | 路徑調整 1 處 |
| `tools/pilot/lib/nvidia-bulletins-gpu-firmware.json` | （dumpling 自己寫） | — | 新增：`nvidia_bulletins.py candidates --group gpu-firmware` 用的空對照表（vBIOS；沒有已審核的列，所有 gpu-firmware 公告都列為待審）；格式同 `nvidia-bulletins.json` |
| `tools/pilot/lib/nvidia-bulletins.md` | `scripts/pilot/lib/nvidia-bulletins.md` | 25fa89a | 路徑調整 9 處；1 行改成不指向沒帶進來的 `scripts/ci/fast-check.sh` |
| `tools/pilot/lib/nvidia_bulletins.py` | `scripts/pilot/lib/nvidia_bulletins.py` | 25fa89a | 路徑調整 1 處 |
| `tools/pilot/lib/strip_versions.py` | `scripts/pilot/lib/strip_versions.py` | 25fa89a | 原樣 |
| `tools/pilot/lib/ubuntu_priority.py` | `scripts/pilot/lib/ubuntu_priority.py` | 25fa89a | 原樣 |
| `tools/pilot/lib/ubuntu_status.py` | `scripts/pilot/lib/ubuntu_status.py` | 25fa89a | 路徑調整 1 處；註解：移除上游私有 repo 的編號與內部部署描述 |
| `tools/pilot/lib/usn_cves.py` | `scripts/pilot/lib/usn_cves.py` | 25fa89a | 原樣 |
| `tools/pilot/report.py` | `scripts/pilot/report.py` | 25fa89a | 路徑調整 1 處；註解裡的內部執行編號改成「Jetson R39.2.1 示範映像」（1 行）；註解：移除上游私有 repo 的編號與內部部署描述；HTML 結尾的已知限制說明拿掉指向上游內部文件的參照（dumpling 沒有那份文件），其餘文字不變 |
| `tools/pilot/sca-scan` | `scripts/pilot/sca-scan` | 25fa89a | 路徑調整 82 處；**行為修改**：E 段（授權匯入）與 E2 段（檔案層級掃描）開始前檢查輔助程式（`scio_prep.py` 等，dumpling 沒帶）是否存在，缺就記 NOT_RUN 並寫出缺的檔名，不再因找不到檔案記 FAIL；註解：移除上游私有 repo 的編號與內部部署描述；metadata 的 network.note 拿掉指向上游內部文件的參照，其餘文字不變；**行為修改（M2）**：新增 `--kernel-version`／`SCA_KERNEL_VERSIONS`（出貨但沒判定的核心記 `C-kernel-not-judged-<版本>`、寫 `scan/kernel-versions.json`，指定 2 顆以上一顆都不判定；沒指定而且只有 1 顆核心時行為不變）；另新增 `--kernel-upstream-version <核心版本>=<X.Y.Z>`（只用於 --image、--sbom，轉成 kernel_versions.py `--upstream-version`，和原始碼 Makefile 核對；沒給時行為不變）；**行為修改（M2）**：CNA 鏡像的 SOURCE 有 `fallback=yes`（kernel-cve.sh 沿用舊鏡像）時記 `C-kernel-cve-mirror` ATTENTION，說明取 `fallback_note`；沒有時不記；**行為修改（M2 分層）**：新增 `--kernel-in-other-report <報告名稱>`／`SCA_KERNEL_IN_OTHER_REPORT`（格式不對 exit 64）：給了而且 kernelcheck 判定 SBOM 沒有核心時，`C-kernel-cve-list`、`C-kernel-config`、`C-kernel-module-map` 各記一列 NOT_RUN「不適用」，不執行 CNA 版本比對、`kernel_config.py`、`kernel_module_map.py`，不記 `C-kernel-not-judged-*`、不寫 `kernel-versions.json`；沒給或 SBOM 有核心時行為不變。新增 `--kernel-not-distro <理由>`／`SCA_KERNEL_NOT_DISTRO`（空的、有控制字元、超過 300 位元組 exit 64），交給 kernelcheck 的 `--not-distro-kernel`；M2 第二輪驗證：`--kernel-in-other-report` 指向這份報告自己（等於 `--name`）→ exit 64；**行為修改（M2 後續：掃描層 NOT_RUN）**：--kernel-in-other-report 而且 SBOM 沒有核心（KNONE）時，meta.json 多 `kernel_in_other_report: <名稱>`（cra_report 用這個結構標記判斷三個 NOT_RUN 是不適用） |
| `tools/pilot/tests/conftest.py` | `scripts/pilot/tests/conftest.py` | 25fa89a | 重寫（比照 D-017）：原檔載入 sca-center 的 `integration/conftest.py`，改成載入 `tools/cra/tests/conftest.py`（`DUMPLING_REQUIRE_TEST_DATA=1` 時 skip 算失敗）；沒有帶 `integration/` |
| `tools/pilot/tests/pilot_fixtures.py` | `scripts/pilot/tests/pilot_fixtures.py` | 25fa89a | 原樣 |
| `tools/pilot/tests/test_deb_sources.py` | `scripts/pilot/tests/test_deb_sources.py` | 25fa89a | 路徑調整 2 處 |
| `tools/pilot/tests/test_distro_recheck.py` | `scripts/pilot/tests/test_distro_recheck.py` | 25fa89a | 路徑調整 4 處；刪段：`deploy/` 鏡像更新、`mirror-sync.sh` 同步（11 個測試函式與輔助函式）、`deploy` 接線、`fast-check` 預期（見「刪掉的測試」）；註解內部執行編號改成中性 |
| `tools/pilot/tests/test_kernel_boot.py` | `scripts/pilot/tests/test_kernel_boot.py` | 25fa89a | 路徑調整 1 處 |
| `tools/pilot/tests/test_kernel_cna_branch.py` | `scripts/pilot/tests/test_kernel_cna_branch.py` | 25fa89a | 原樣 |
| `tools/pilot/tests/test_kernel_cna_version.py` | `scripts/pilot/tests/test_kernel_cna_version.py` | 25fa89a | 原樣 |
| `tools/pilot/tests/test_kernel_config.py` | `scripts/pilot/tests/test_kernel_config.py` | 25fa89a | 路徑調整 6 處、清理 30 行；另刪段 2 個測試函式（`deploy/` 鏡像更新與同步、`deploy` 接線）；測試映像常數改寫成合成值（見資料來源）；註解的內部執行編號改成中性；註解：移除上游私有 repo 的編號與內部部署描述；新增（M2）2 個 `tools/mirror/kernel-cve.sh` 的測試（clone 失敗重試、上游連不上時沿用上一份鏡像並標 ATTENTION；假的 git 與合成的鏡像） |
| `tools/pilot/tests/test_kernel_k1_improve.py` | `scripts/pilot/tests/test_kernel_k1_improve.py` | 25fa89a | 路徑調整 1 處 |
| `tools/pilot/tests/test_kernel_k1_review1.py` | `scripts/pilot/tests/test_kernel_k1_review1.py` | 25fa89a | 原樣；註解：移除上游私有 repo 的編號與內部部署描述 |
| `tools/pilot/tests/test_kernel_k1_undetermined.py` | `scripts/pilot/tests/test_kernel_k1_undetermined.py` | 25fa89a | 原樣 |
| `tools/pilot/tests/test_kernel_module_map.py` | `scripts/pilot/tests/test_kernel_module_map.py` | 25fa89a | 原樣 |
| `tools/pilot/tests/test_kernel_oot_sections.py` | `scripts/pilot/tests/test_kernel_oot_sections.py` | 25fa89a | 原樣（合成 ELF 字串裡的建置路徑登記在 `ci/public-allow.txt`） |
| `tools/pilot/tests/test_kernel_in_other_report.py` | （dumpling 自己寫） | — | 新增（M2 分層）：`--kernel-in-other-report`／`SCA_KERNEL_IN_OTHER_REPORT`：sca-scan 的 kernelcheck 區段與核心區段從原文抽出來在 bash 執行（kernelcheck 是真的，判定工具與 CNA 比對是假的）：沒有核心的 SBOM 加選項 → 三列 NOT_RUN 且什麼都沒呼叫（含 Pi 型兩顆核心的映像）、有核心的 SBOM 加選項與不加相同、沒給選項行為不變；參數檢查與 exit 64；`SCA_KERNEL_NOT_DISTRO` 到 kernelcheck；M2 第二輪驗證：指向自己 → exit 64；M2 後續：測試框架宣告 META，斷言 KNONE 時記 kernel_in_other_report、有核心或沒給選項時不記 |
| `tools/pilot/tests/test_kernel_off_series.py` | （dumpling 自己寫） | — | 新增（M2）：kernelcheck 的 off-series 規則 a／b／c／d（合成資料，名稱與版本只取公開的樣子）：epoch、`+rpt`／`+rpi`、名稱、明確宣告、purl 的 `upstream=`（含 Radxa 型、URL 編碼的 Raspberry Pi purl、Debian／Ubuntu／Jetson 不被標）、規則是「或」、資料檔壞了 FAIL；M2 第二輪驗證：purl 的 `epoch=` 限定詞、沒有版本號的 `distro=debian`、`raspbian-*` 的已知盲點 |
| `tools/pilot/tests/test_kernel_vendor_flow.py` | `scripts/pilot/tests/test_kernel_vendor_flow.py` | 25fa89a | 路徑調整 2 處；M2：`kernel_cve_list` 的測試外殼多抽出 `kernel_ship_from` |
| `tools/pilot/tests/test_kernel_versions.py` | （dumpling 自己寫） | — | 新增（M2）：`--kernel-version`／`SCA_KERNEL_VERSIONS` 的參數檢查，以及 sca-scan 核心區段在 1 顆／多顆沒指定／多顆指定 1 顆／指定 2 顆的狀態列與 `kernel-versions.json`（合成的 rootfs tar，判定工具用假的）；另測 sca-scan 把 `--kernel-upstream-version` 轉給 kernel_versions.py（和 Makefile 一致／不一致）；**行為修改（M2）**：核心區段的測試外殼補 `KNONE=0; KOTHER=`（sca-scan 的核心區段新增分層判斷用的變數） |
| `tools/pilot/tests/test_nvidia_bulletins.py` | `scripts/pilot/tests/test_nvidia_bulletins.py` | 25fa89a | 路徑調整 4 處；刪段：`deploy/` 鏡像更新與同步、`deploy` 接線（8 個測試函式與輔助函式；見「刪掉的測試」）；註解：移除上游私有 repo 的編號與內部部署描述 |
| `tools/pilot/tests/test_pilot_compare_and_scripts.py` | `scripts/pilot/tests/test_pilot_compare_and_scripts.py` | 25fa89a | 路徑調整 8 處、清理 5 行、刪段 129 行 |
| `tools/pilot/tests/test_pilot_euvd.py` | `scripts/pilot/tests/test_pilot_euvd.py` | 25fa89a | 路徑調整 3 處；註解：移除上游私有 repo 的編號與內部部署描述 |
| `tools/pilot/tests/test_pilot_kernel_coverage.py` | `scripts/pilot/tests/test_pilot_kernel_coverage.py` | 25fa89a | 原樣；註解內部執行編號改成「Jetson R39.2.1 示範映像」（1 行） |
| `tools/pilot/tests/test_pilot_l4t_kernel.py` | `scripts/pilot/tests/test_pilot_l4t_kernel.py` | 25fa89a | 路徑調整 1 處；刪段：`test_deb_sources_…` 去掉用 `scio_prep.py` 的一半（函式改名），保留 `deb_sources.py` 的檢查 |
| `tools/pilot/tests/test_pilot_lock_sandbox.py` | `scripts/pilot/tests/test_pilot_lock_sandbox.py` | 25fa89a | 路徑調整 15 處、刪段 75 行 |
| `tools/pilot/tests/test_pilot_nvd_mirror.py` | `scripts/pilot/tests/test_pilot_nvd_mirror.py` | 25fa89a | 原樣；註解：移除上游私有 repo 的編號與內部部署描述 |
| `tools/pilot/tests/test_pilot_report.py` | `scripts/pilot/tests/test_pilot_report.py` | 25fa89a | 原樣 |
| `tools/pilot/tests/test_pilot_sources_scio.py` | `scripts/pilot/tests/test_pilot_sources_scio.py` | 25fa89a | 路徑調整 1 處、清理 1 行、刪段 109 行；註解內部執行編號改成中性（2 行） |
| `tools/pilot/tests/test_pilot_utf8_truncation.py` | `scripts/pilot/tests/test_pilot_utf8_truncation.py` | 25fa89a | 路徑調整 1 處、清理 1 行；`shell_files()` 不再掃 `deploy/`，檔案數門檻 20 → 10（`tools/` 共 14 個 shell 檔） |
| `tools/pilot/tests/test_pyver_wiring.py` | `scripts/pilot/tests/test_pyver_wiring.py` | 25fa89a | 路徑調整 3 處 |
| `tools/pilot/tests/test_sca_scan_local_image.py` | `scripts/pilot/tests/test_sca_scan_local_image.py` | 25fa89a | 路徑調整 1 處 |
| `tools/pilot/tests/test_sca_scan_no_license_libs.py` | （dumpling 自己寫） | — | 新增：pilot.env 設了 DejaCode／ScanCode.io 網址、輔助程式沒帶進來時，E、E2 段記 NOT_RUN 而不是 FAIL |
| `tools/pilot/tests/test_ubuntu_cve_status.py` | `scripts/pilot/tests/test_ubuntu_cve_status.py` | 25fa89a | 路徑調整 3 處；`test_script_safety_and_docs` 去掉要 `ci-run.sh`、`docs/offline-mirrors.md`、`deploy/versions.md` 的斷言，改名 `test_script_safety` |
| `tools/pilot/tests/test_ubuntu_priority.py` | `scripts/pilot/tests/test_ubuntu_priority.py` | 25fa89a | 路徑調整 1 處 |
| `tools/pilot/tests/test_ubuntu_status.py` | `scripts/pilot/tests/test_ubuntu_status.py` | 25fa89a | 路徑調整 5 處；註解：移除上游私有 repo 的編號與內部部署描述 |
| `tools/pilot/tests/test_usn_cves.py` | `scripts/pilot/tests/test_usn_cves.py` | 25fa89a | 路徑調整 1 處 |
| `tools/sbomgate/sbomgate.py` | `integration/sbomgate/sbomgate.py` | 25fa89a | 說明文字：提到 CLAUDE.md 的說明與輸出字串改成「專案規則」／project rule（dumpling 沒有那個檔） |
| `tools/sbomgate/tests/test_sbomgate.py` | `integration/sbomgate/tests/test_sbomgate.py` | 25fa89a | 刪段 95 行、刪掉 RealEvidence 類與 6 個用到 tests/results、tests/projects（e2e 的真實輸出，不帶）的測試方法 |
| `tools/vexconv/tests/test_vexconv.py` | `integration/vexconv/tests/test_vexconv.py` | 25fa89a | 清理 7 行（其他 4、刪段 2、路徑 1）、schema 改讀 tools/cra/tests/data/{cyclonedx-1.5,openvex,cyclonedx-1.6.1}（不再連網取得，也不再 skip） |
| `tools/vexconv/vexconv.py` | `integration/vexconv/vexconv.py` | 25fa89a | 原樣 |
| `tools/wizard/README.md` | `scripts/wizard/README.md` | 25fa89a | 路徑調整 10 處；平台範本清單去掉 android；「取最新工具」改為取 HEAD 或 `--tools-rev` 的說明 |
| `tools/wizard/cra-scan.py` | `scripts/wizard/cra-scan.py` | 25fa89a | 路徑調整 10 處；**行為修改（M2）**：`--platform` 原樣傳給 scan-flash-package.sh，並寫進 plan.json；**行為修改**：工具版本改為預設目前 checkout 的 `HEAD`、可用 `--tools-rev`／`DUMPLING_TOOLS_REV` 覆寫，實際 commit 寫進 `<輸出>/tools-version.json`（見「影響邏輯的替換」）；平台說明去掉 android；**行為修改（M2 J 軌）**：新增選用的 `--rescan-from <scan 資料夾>`（原樣傳給 scan-flash-package.sh，並沿用該資料夾的 A0 結果、不重算），分層時對每一層只重跑比對用；沒給時行為不變；**行為修改（M2 分層）**：新增 `--kernel-in-other-report <報告名稱>`（環境變數 `SCA_KERNEL_IN_OTHER_REPORT`）與 `--kernel-not-distro <理由>`（`SCA_KERNEL_NOT_DISTRO`），格式不對 exit 64，plan.json 記 `kernel_in_other_report`、`kernel_not_distro`，原樣轉給 scan-flash-package.sh |
| `tools/wizard/inputs.example.json` | `scripts/wizard/inputs.example.json` | 25fa89a | 清理 1 行 |
| `tools/wizard/platforms/jetson.json` | `scripts/wizard/platforms/jetson.json` | 25fa89a | 清理 1 行 |
| `tools/wizard/platforms/raspberrypi.json` | `scripts/wizard/platforms/raspberrypi.json` | 25fa89a | 原樣 |
| `tools/wizard/platforms/rockchip.json` | `scripts/wizard/platforms/rockchip.json` | 25fa89a | 清理 1 行 |
| `tools/wizard/wizard.example.json` | `scripts/wizard/wizard.example.json` | 25fa89a | 原樣 |
| `tests/expected/orin-nano-demo/v39.2.0-demo1.json` | （dumpling 自己寫的） | — | 新增（M2 J 軌）：標準答案，2026-11-12 第一次在 CI 跑通後訂定（見 `docs/JETSON.md`） |
| `tests/expected/orin-nano-demo/v39.2.1-demo1.json` | （dumpling 自己寫的） | — | 新增（M2 J 軌）：標準答案（套 patch 的版本），同上 |

以下是 dumpling 自己寫的（不是複製）：`pipeline/lib/layers.py`、`pipeline/sbom-layers.py`、`tests/test_layers.py`、`tests/run.d/c1-m2-layers.sh`（M2 分層，見 `docs/LAYERS.md`）、`pipeline/lib/{safe_extract,jetson_build,jetson_assemble,jetson_scan,platform_scan}.py`、`pipeline/{check-expected,release-meta}.py`、`pipeline/run-step.sh`、`pipeline/install-scan-tools.sh`、`pipeline/lib/step_rows.py`、`pipeline/lib/mirrors.sh`、`tests/test_platform_steps.py`、`pipeline/platforms/jetson/*.sh`、`tests/test_jetson_pipeline.py`、`tests/test_platform_plan.py`、`tests/test_platform_scan.py`、`tests/run.d/c1-m2-jetson.sh`、`tests/expected/orin-nano-demo/v39.2.0-demo1.json`、`tests/expected/orin-nano-demo/v39.2.1-demo1.json`（標準答案，M2 J 軌）、`.github/workflows/{pipeline,release,dev}.yml`（M2 J 軌，見 `docs/JETSON.md`；`safe_extract.py` 取自 M2 試驗分支的 `m2_safe_extract.py`）、`ci/provenance-check.sh`、`tests/run.d/c1-tools.sh`、`tests/run.d/c1-public-check.sh`（`ci/public-check.sh` 壓縮檔檢查的測試，測資當場合成）；`ci/public-check.sh` 是 WP0 的檔，M1 加了壓縮檔解壓後檢查（C0 同意在 M1 修改）：涵蓋 .xz、.gz、.bz2、.zst、.tar 及 .tgz 等變體，副檔名不分大小寫；不支援的封存格式（.zip、.7z 等）一律算命中；白名單是完整字串比對。

### 改動類型說明

- 「原樣」：內容與 sca-center `25fa89a` 的同一檔完全相同。
- 「路徑調整」：只做路徑改名（`scripts/<子目錄>/` → `tools/<子目錄>/`，`integration/sbomgate`、`integration/vexconv` → `tools/sbomgate`、`tools/vexconv`，以及 `ROOT / "scripts" / …` 這種組路徑的程式碼），其餘原樣。處數是替換的次數。
- 「清理 N 行」：除了路徑調整，還有 N 行因為公開檢查（產品代號、本機路徑、私有 IP、個人信箱）或內部來源說明而改過。
- 「刪段 N 行」：整個測試函式或段落因為對應的程式沒有帶進來而移除（原因見下面「刪掉的測試」）。

### 沒帶進來的相依

下列工具在 sca-center 存在，但不在範圍內（或歸別的工作包），沒有複製。帶進來的程式走到它們時的行為寫在右欄。

| 沒帶進來的檔案 | 誰會呼叫 | 走到時的行為 |
|---|---|---|
| `scripts/pilot/lib/{djsbom,filescan,licverdict,notice,oscopyright,pkgscan,scio_cancel,scio_chunks,scio_diag,scio_failures,scio_prep}.py`、`scripts/e2e/{djread,licexpr}.py`、`integration/policysync/` | `sca-scan` 的 E 段（DejaCode 授權匯入）與 E2 段（ScanCode.io 檔案層級掃描） | `pilot.env` 沒有 `DEJACODE_URL`／`SCANCODEIO_URL`、或給 `--no-license`、`--no-upload` 時，這些階段記 NOT_RUN（程式碼原有的判斷）。**若 `pilot.env` 設了那些網址，sca-scan 也是記 NOT_RUN 並附原因（程式與 `test_sca_scan_no_license_libs.py` 的行為）**；dumpling 的 pipeline 不設它們 |
| `scripts/e2e/dt-compose.yaml`、`scripts/e2e/dtlib.sh` | 臨時 DT | 由 `pipeline/dt-ephemeral.sh`、`pipeline/dt-compose.yaml` 取代（見上面 pipeline 列） |
| `scripts/mirror/dt-feeds.sh` | `mirror/euvd.sh`（只有鏡像資料夾裡有 `dt-feeds/` 時才呼叫） | dumpling 的 EUVD 鏡像不會產生 `dt-feeds/`，不會走到 |
| `scripts/cra/alert_mail.py`、`exploited-watch-daily.sh`、`exploited-watch-backup.sh` | 每日監控的寄信與排程（公司環境） | `exploited_watch.py` 只是讀它們寫的狀態檔（`--grype-db-update`、`--backup-dir`、`--refresh-status` 都是選用參數，不給就不檢查）。dumpling 的 `watch.yml` 預計直接呼叫 `exploited_watch.py`、用 GitHub Issue 通知。**沒帶進來（C3 視需要帶回，含約 29 個被刪的寄信測試：test_exploited_vendor 4、test_exploited_watch_grype 11、test_exploited_watch_refresh 14）**；M1／M2 用不到 |
| `scripts/cra/csaf_advisory.py` | 沒有程式呼叫（獨立指令） | 不在範圍內 |
| `scripts/mirror/ci-run.sh`、`scripts/ci/fast-check.sh`、`scripts/e2e/{install-maven.sh,cdxgen_regression.py,real-projects.sh,license.sh}`、`docs/offline-mirrors.md`、`docs/offline-egress.md` | 只被說明文字與已刪掉的測試引用（sca-center 自己的 CI、鏡像排程與文件） | 帶進來的程式不呼叫它們；對應的測試斷言已刪（見「刪掉的測試」）。`tools/e2e/sandbox.sh`、`tools/pilot/lib/common.sh` 的檔頭說明仍提到 `real-projects.sh`、`license.sh`（只是說明文字） |
| `scripts/pilot/tests/data/euvd-dt-enisa-golden.json` | `test_euvd_dt_feed.py`（測 `deploy/` 的包裝腳本，整檔不帶） | 孤兒資料檔，不帶。內容是公開 CVE 的小型 EUVD 格式資料，不是內部來源 |
| `scripts/demo/android_img.py`、`scripts/demo/tests/test_android_img.py`、`scripts/wizard/platforms/android.json` | `flash_package.py`（`amod()`）、`cra-scan.py --platform android` | **不在範圍內，沒有帶進來**（C1 決定）。`flash_package.py` 已移除 android 格式的分支；沒有 `--platform android` 範本 |
| `scripts/demo/board-on-device.sh`、`board-from-network.sh`、`board-test.md` | 在板子上跑的收集腳本；`board_import.py`、`board-import.sh` 只讀它們的輸出檔 | 沒有板子結果檔時，精靈記 `board-import` NOT_RUN |
| `scripts/pilot/{ci_summary,compare_expected}.py`、`ci-*.sh`、`scripts/e2e/{real-projects,license,firmware,images,projects,summarize,…}.sh`／`.py`、`scripts/ci/`、`scripts/run-*.sh` | sca-center 自己的 CI 與 e2e | 與 dumpling 無關 |
| `scripts/cra/x86_firmware.py`、`test_x86_firmware.py`、`data/fw-manifest-template.csv`、BIOS 試掃原型 | 歸 C2（D-015） | 帶進來的程式沒有 import 它們 |
| `deploy/`（`gitlab-runner`、`gitlab-bot`、`pilot`、`exploited-watch/install.sh` 等）、`ci/gitlab/`、`integration/` 其他子目錄 | 公司的 GitLab 與常駐環境部署 | 帶進來的程式與測試裡仍有提到這些路徑的說明文字或預設值（例如 `deploy/pilot/state/pilot.env` 是 `PILOT_ENV` 沒設時的預設），dumpling 一律明確傳 `PILOT_ENV` |
| `scripts/cra/README.md`（288 KB）、`scripts/demo/flash-package.md` | 說明文件 | 內容含沒帶進來的工具與公司流程，清理成本高，沒帶；需要時另開 PR 重寫 |

### 影響邏輯的替換

這次所有「產品代號、主機名、本機路徑」的命中都在註解、說明文字、測試資料與預設路徑，**判定邏輯本身（`kernel_config.py`、`kernel_boot.py`、`upstream_baseline.py`、`cra_report.py`、`no_vuln_data.py` 等）沒有以公司產品代號當條件的程式碼**。實際改到行為（輸出字串或預設值）的有：

| 檔案 | 行為說明 | 換成 |
|---|---|---|
| `tools/demo/scan-flash-package.sh` | `--out` 預設的上層資料夾（`FLASHPKG_RESULTS`）與 `PILOT_ENV` 預設路徑，原本指向公司常駐環境的本機路徑 | `$HOME/sca-results`、`$HOME/.config/sca-scan/pilot.env`（只是預設值；pipeline 一律明確傳） |
| `tools/cra/exploited_grype.py` | 只有說明字串：`--results-root` 的例子路徑 | `$HOME/sca-results`；註解：移除上游私有 repo 的編號與內部部署描述 |
| `tools/demo/jetson_rootfs.py` | （已還原，原樣）模擬的客戶應用程式在 dpkg status 的 Maintainer 信箱是 `noreply@example.invalid`；D-022 之後 `.invalid` 結尾的信箱自動放行 | 無（值與 25fa89a 相同；`test_jetson_rootfs.py`、`test_kernel_k1_improve.py` 的 `@example.invalid` 也還原） |
| `tools/pilot/lib/kernel_boot.py`、`kernel_config.py`、`tools/demo/scan-flash-package.sh`、`tools/pilot/README.md` | 「預設用刷機包的 `kernel/Image`」的依據說明字串（輸出到報告備註與 JSON）原本點名某個廠商產品的板子實測。判定邏輯（預設用 `kernel/Image`、有 `KERNEL_BOARD_OS_TXT` 時以板子的 `uname -v` 為準）沒改 | 改成公開 BSP 的依據（見「資料檔與測試資料的來源」） |
| `tools/cra/image_check.py`、`tools/cra/no_vuln_data.py` | 只有說明字串裡的範例信箱（systemd 樣板單元名稱的範例、`dh_make` 預設信箱），公開檢查會把它們當信箱 | 把網域部分換成佔位文字；`DISTRO_DOMAINS` 等判定用的網域清單沒動 |
| 全部 `tools/*/tests/*.py` | 測試資料裡的信箱（例如 `@lists.debian.org`、`@nvidia.com`，`no_vuln_data` 的判定依網域）與 `/home/…` 路徑（`image_check` 的映像內路徑）若直接改字會改變測試意義，所以**維持原值**，登記在 `ci/public-allow.txt`（完整字串比對，每項附原因，見下一節）；其餘可改的信箱改成保留網域（`example.com`、`.invalid` 等） | 無（值不變） |
| `tools/cra/tests/test_security_testing.py`、`test_cra_report.py` | 測試資料裡板子網路掃描的 IP（私有 IP） | `192.0.2.20`、`192.0.2.2`（文件用網段）；註解：移除上游私有 repo 的編號與內部部署描述 |
| `tools/cra/tests/test_no_vuln_data.py` | 一個四段式套件版本字串（TensorRT 的 libnvinfer，後面接 cuda 標記）會被私有 IP 規則誤判 | 維持原值，登記在 `ci/public-allow.txt`（改版本號會改變測試資料） |
| `tools/wizard/**` 與 `tools/cra/tests/*` | 產品代號（`product-a`、`product-b`、`product-c` 是中性代稱，分別對應三個不公開的廠商產品名）出現在測試用的假刷機包名稱、`platforms/*.json` 的 `note` | `product-a` 等；不影響邏輯 |
| `tools/wizard/cra-scan.py` | **行為修改**（sca-center 原版：掃描前 `git fetch origin`，對 `origin/main` 做 `git archive` 放到 `<輸出>/wt/` 再執行 `wt/tools/…`，也就是跑遠端 main，在 CI 的 tag 或分支 checkout 上不是正在測的那個 commit）。dumpling：新增 `resolve_tools_rev()`／`extract_tools()`，預設對目前 checkout 的 `HEAD` 做 `git archive`（保留「從 git 取乾淨副本」，沒 commit 的修改不會混進去），`--tools-rev <rev>` 或環境變數 `DUMPLING_TOOLS_REV` 可指定其他版本（寫成 `origin/…` 才會 fetch）；實際用的完整 commit hash、要求的版本、工作目錄是否有沒 commit 的修改，寫進 `<輸出>/tools-version.json`，commit 也經 `SCA_CENTER_COMMIT` 進掃描的 `provenance.json`（原有機制）。測試：`tools/demo/tests/test_wizard_plan.py` 的 `test_tools_rev_*` | 預設 `HEAD`；找不到版本就停止並說明 |

### public-check 白名單（`ci/public-allow.txt`）

`tools/cra/` 的測試裡有些完整字串會被 `ci/public-check.sh` 當成個人信箱、本機路徑或私有 IP，但它們是**判定邏輯需要的真實公開網域、映像內部路徑、版本字串**，換掉會改變測試意義。這些登記在 `ci/public-allow.txt`（完整字串比對，每項附原因；依用途分三類：`tools/cra/` 的測試、`tools/pilot/` 的測試、`tests/run.d/c1-public-check.sh` 的合成測資，各項與數量以 `ci/public-allow.txt` 為準），測試值與 sca-center `25fa89a` 一致。`*.example`、`.invalid`、`.test`、`.localhost` 結尾的信箱由保留 TLD 規則直接放行，不在白名單裡。

| 完整字串 | 用途 |
|---|---|
| `nvd@nist.gov` | NVD 在 Grype／DT 資料裡的來源識別字串 |
| `ubuntu-devel-discuss@lists.ubuntu.com`、`pkg-foo@lists.debian.org`、`a@debian.org`、`b@lists.debian.org`、`chromium@packages.debian.org`、`pkg-openssl-devel@alioth-lists.debian.net`、`pkg-nvidia-devel@lists.alioth.debian.org` | 「維護者是不是發行版」看信箱網域（`DISTRO_DOMAINS`：debian.org、debian.net、ubuntu.com、canonical.com、launchpad.net，含子網域），測試要用真的發行版網域 |
| `joe@gmail.com` | 免費信箱（`FREEMAIL`）的案例：報告不可印出個人信箱 |
| `linux-tegra-bugs@nvidia.com` | `BUILTIN_VENDOR_DOMAINS` 是 nvidia.com：廠商網域可以印在報告 |
| `j@Rock-Chips.COM` | 測網域比對不分大小寫 |
| `ubuntu@ubuntu.localdomain` | `dh_make` 預設維護者信箱：名稱像 Ubuntu 但網域不是發行版 |
| `secret@github.com` | 測 git 遠端網址帶帳密要遮蔽，且 github.com/tianocore/edk2 是程式認得的上游 |
| `/home/x/test/id_rsa`、`/home/nvidia/.netrc` | 映像**內部**路徑：`image_check` 判斷 `/home` 底下的私鑰、.netrc 一律算真的 |
| `/home/builder/ws/sources/uefi`、`/home/u/Build/Foo/DEBUG/AutoGen.c` | 測建置機器路徑（含使用者名稱）要被偵測、報告不可出現 |
| `10.3.0.30-1+cuda12.5` | TensorRT（libnvinfer10）的套件版本字串，不是 IP |
| `tools/pilot/tests/` 的合成路徑（`test_kernel_config.py`、`test_kernel_oot_sections.py`） | 假的核心樹或 ELF 字串裡的建置機器路徑，是測試要偵測的內容 |
| `tests/run.d/c1-public-check.sh` 的合成測資 | 測 public-check 本身（私有 IP、不允許的信箱、白名單放行）；每項見 `ci/public-allow.txt` |

為了少登記，三處測試資料不是照原檔：`test_no_vuln_data.py` 裡另一個 gmail 位址與另一個 nvidia.com 位址，改成上表已登記的同網域位址（判定只看網域），`test_supplier_package.py` 的一個 `/home` 底下的假路徑改成 `/mnt` 底下（偵測的本機路徑樣式兩者都有）。

另外已經直接改掉、不需要白名單的：`example.invalid` 的 noreply 信箱 → `example.com`、systemd 樣板單元名稱與 `dh_make` 預設信箱的說明字串（改成佔位文字）、測試資料裡板子網路掃描的兩個私有 IP（換成 192.0.2.x 文件網段）。

### 資料檔與測試資料的來源

判定只有三種：**公開**（附來源，可以重現或查證）、**合成**（手寫或程式產生）、**內部**（從公司資料產生；內部的一律不帶，清掉禁用字也不行）。審查日期 2026-11-12，依據是 sca-center 的 git 紀錄、檔案說明與資料內容，並盡量實際重現。

**結論：`tools/pilot`、`tools/demo`、`tools/mirror`、`tools/wizard`、`tools/e2e` 與 `tests/fixtures/jetson-r39.2.1-base.cdx.json.xz` 沒有發現來源是內部資料的檔案。** 有幾處註解或欄位提到內部來源（廠商映像、板子實測、內部 CI 的執行編號），已改成中性或公開的說法（見下面「已改寫」）；沒有因為「來源是內部資料」而刪檔案。

| 檔案 | 來源 | 判定 |
|---|---|---|
| `tests/fixtures/jetson-r39.2.1-base.cdx.json.xz` | Syft 1.55.0 對「NVIDIA 公開的 Jetson Linux R39.2.1 BSP 加公開範例 rootfs」組出的映像（`tools/demo/jetson.sh` 的產物，sca-center 的示範掃描）產生的 CycloneDX；3851 個元件（Ubuntu 套件、NVIDIA L4T 套件 `39.2.1-20260806224157`、1468 個核心模組）。裡面的套件版本、模組與維護者都是 NVIDIA、Ubuntu 公開發行的內容 | 公開來源的掃描結果。清理：維護者信箱改成 example.com、掃描暫存路徑（`metadata.component.name`，原本是 runner 的本機路徑）改成 `/path/to/work/.sca-scan-work.…/image.tar`、一個 package-id 雜湊改了一碼。沒有公司產品的元件 |
| `tools/pilot/lib/data/kernel-included-c-{6.1,6.8}.json` | Linux 上游原始碼：6.8 是 kernel.org 的 `linux-6.8.tar.xz`（sha256 `c969dea4…` 與 kernel.org `sha256sums.asc` 相符），6.1 是 `v6.1.118`（commit `b67dc5c9…`）。**已實際重現**：用 `tools/pilot/lib/kernel_included_c.py` 對 kernel.org 的 `linux-6.8.tar.xz`、`linux-6.1.118.tar.xz` 重新產生，`files` 與 `unresolved` 與資料檔完全相同（2026-11-12） | 公開（上游原始碼推導）。重現：`python3 -I tools/pilot/lib/kernel_included_c.py --source linux-X.Y.tar.xz --kernel X.Y --out …` |
| `tools/pilot/lib/data/distro-kernel-sources.json` | Debian 建核心用的來源套件名稱（`linux`、`linux-latest`、`linux-signed-{amd64,arm64,i386}`）、`linux-upstream`（核心原始碼 `make deb-pkg` 的預設來源名稱）。dumpling 自己整理，只有公開的套件名稱；出處是 Debian package tracker 的標準頁面（`https://tracker.debian.org/pkg/<來源套件名稱>`），整理時沒有連網逐頁開啟核對（檔案裡的 `checked` 欄照實寫） | 合成（公開的套件名稱，無內部資料） |
| `tools/pilot/lib/nvidia-bulletins.json`（附 `.md`） | NVIDIA 公開安全公告 `https://github.com/NVIDIA/product-security`；`prefilled_from.mirror_commit` `6e340ebe…` 是該公開倉庫的 commit（GitHub API 查得到，2026-10-27）；其餘欄位（`reviewed` 等）是人工整理 | 公開來源、人工整理。`.md` 裡提到的 `deploy/` 腳本沒有帶進來（說明文字） |
| `tools/pilot/lib/nvidia-bulletins-gpu-firmware.json` | 手寫的空對照表（沒有任何公告資料） | 合成 |
| `tools/pilot/lib/l4t-kernel-map.json` | Jetson Linux 版本 → Canonical 核心原始碼套件的對照；證據是 NVIDIA 公開的 GitLab（`gitlab.com/nvidia/nv-tegra/3rdparty/canonical/linux-noble` 的 tag、changelog）與公開的 Ubuntu 套件版本 | 公開。已改寫兩個 `checked` 欄：改成只引用公開資料的說法，不含內部映像的套件版本字串與內部 CI 執行編號（無公開依據的部分改標為推論） |
| `tools/pilot/lib/*.md`、`README.md` 等說明文件 | 手寫的說明 | 合成。內部 CI 的執行編號與代號已改成中性說法（「Jetson R39.2.1 示範映像」「示範掃描」） |
| `tools/wizard/platforms/{jetson,rockchip,raspberrypi}.json`、`inputs.example.json`、`wizard.example.json` | 手寫的平台範本與範例（要檢查的輸入清單：刷機包、原始碼、建置紀錄、上游基準、板子檢查…） | 合成。`note` 欄原本寫「依某產品演練整理」，已改成「某平台的範本」 |
| `tools/demo/tests/*.py`、`tools/pilot/tests/*.py` 的假刷機包、映像、rootfs | 測試用 `tarfile`／程式現組的假檔案：`product-a_OrinNano/Linux_for_Tegra/…` 的結構是 NVIDIA 公開 BSP 的結構（`apply_binaries.sh`、`bootloader/`、`kernel/Image`、`rootfs/`…），`product-a` 是合成的名稱；Rockchip `update.img`、Raspberry Pi 磁碟映像、ext4／FAT 也都是測試程式組出來的。**合成，形狀參考內部觀察（廠商刷機包的交付結構），已確認無可識別資訊（D-023）**：沒有產品代號（`product-a`／`product-b` 是中性代稱）、沒有內部版本字串（vendor 風格的版本字串已改成合成值，例如 `V1.0.1`、`V1.0.2_a`；測 `version_note` 的測試用另編的值；測試通過）、沒有實際數量或雜湊（md5／sha256 都是測試當場算出或 `"ab" * 16`、`"0" * 32` 之類重複字元）、沒有真實路徑 | 合成（形狀參考內部觀察，已確認無可識別資訊） |
| `tools/pilot/tests/*.py` 的資料 | 測試自己組出來的假 SBOM、Grype／DT 輸出、核心 `.config`、IKCONFIG、Kbuild 樹、OSV zip、公告 Markdown。欄位格式取自公開工具（Syft、Grype、Dependency-Track、NVIDIA／Ubuntu／Debian／OSV 公開資料）的輸出形狀；CVE 編號與套件版本多為公開資料 | 合成 |
| `tools/pilot/tests/test_kernel_config.py` 的「第四輪」一段 | 測試映像常數 `IMAGE_VENDOR_REBUILT`（形狀參考內部觀察）**已改寫為合成值**：個數改成明顯合成的 10 與 100，斷言的差異數同步調整，測試通過，註明不對應任何實際產品。工具鏈那一組（Ubuntu 13.2.0 與 Buildroot 2022.08 的 `CC_VERSION_TEXT`）是 NVIDIA 公開的 Jetson 工具鏈字串。**合成，形狀參考內部觀察，已確認無可識別資訊（D-023）**：沒有產品代號、內部版本字串、實際數量或雜湊、真實路徑 | 合成（形狀參考內部觀察，已確認無可識別資訊）；註解：移除上游私有 repo 的編號與內部部署描述 |
| `kernel_boot.py`／`kernel_config.py`／`scan-flash-package.sh`／`pilot/README.md` 的「預設用 `kernel/Image`」 | 原本的依據是內部的板子實測。**已改成公開 BSP 的依據**（已下載 `Jetson_Linux_R39.2.1_aarch64.tbz2`，sha256 `2e561908…` 與 `tools/demo/jetson.sh` 寫死的值相符，2026-11-12 逐項核對）：`Linux_for_Tegra/apply_binaries.sh` 呼叫 `Linux_for_Tegra/nv_tools/scripts/nv_apply_kernel_files.sh`，該腳本第 41–44 行把 `kernel/Image` 以 `install … "${ROOTFS_DIR}/boot/Image"` 裝成 rootfs 的 `/boot/Image`；`Linux_for_Tegra/bootloader/extlinux.conf` 的 `LINUX /boot/Image`。判定邏輯沒改；UEFI 開機模式可改，所以說明仍寫「有板子的 `uname -v` 時以它為準」 | 公開（NVIDIA 公開 BSP 的檔案） |
| `tools/cra/data/support-lifecycle.json` | 元件維護期（EOL）資料：每筆的 `sources` 是發行版或廠商公開的維護期頁面（例如 `ubuntu.com/about/release-cycle`、`endoflife.date`），`checked` 是查核日期 | 公開（每筆附來源網址與查核日期） |
| `tools/cra/data/vex-rules.example.json`、`config.example.json`、`company.example.json`、`config.schema.json`、`templates/*.md` | 手寫的範例與範本 | 合成 |
| `tools/cra/vendor-watch.example.json` | 手寫範例（`deploy/exploited-watch/vendor-watch.example.json`） | 合成 |
| `tools/cra/tests/data/cyclonedx-1.6.1/`、`cyclonedx-1.5/`、`openvex/` | CycloneDX 與 OpenVEX 官方 JSON schema（來源網址與 SHA-256 見各資料夾的 `README.md`；1.6.1 由 C2 依 D-017 建立） | 公開 |
| `tests/fixtures/sbom/smoke.cdx.json`、`smoke.expected.json` | dt-smoke 用的手寫 CycloneDX（jinja2 2.10、lodash 4.17.15、Ubuntu openssl deb）與預期值，選擇理由見 `tests/fixtures/sbom/README.md` | 合成（公開套件） |
| `tests/run.d/c1-public-check.sh` 的壓縮測資 | 測試執行時在暫存 repo 當場產生，不進 git | 合成 |

**已移除的資料檔**：`tools/pilot/tests/data/euvd-dt-enisa-golden.json`（唯一使用它的 `test_euvd_dt_feed.py` 測的是 `deploy/` 的包裝腳本，沒有帶進來，所以這個檔案成了沒人用的孤兒；內容本身是公開 CVE 的小型 EUVD 格式資料，不是內部來源）。

**需要 C1／使用者確認的**：
- （已解決）「預設用 `kernel/Image`」的依據：公開 BSP 看得出來（見上表），不需要再確認。
- 測試裡以 `product-a_OrinNano` 命名的假刷機包（檔名結構取自廠商交付的格式，例如 `ReleaseNote.pdf`、`SourceCode`、`MCU_V2.zip` 這類交付物名稱）：我判定為合成，因為內容全是測試現組；如果「交付物的命名慣例」本身算內部資訊，需要再改成更通用的名稱。

### 刪掉的測試

測試所對應的程式或腳本沒有帶進來（見「沒帶進來的相依」），所以整個測試函式移除（「刪段」行數見上表）：

- `test_pilot_ci_summary.py`（`ci_summary.py`）、`test_oscopyright.py`、`test_pilot_license_scan.py`（授權段）、`test_pilot_ubuntu_status_mirror.py`、`test_euvd_dt_feed.py`（測 `deploy/pilot`、`deploy/gitlab-runner` 的包裝腳本）：整檔不帶。
- `test_distro_recheck.py`（11 個函式）、`test_kernel_config.py`（2 個）、`test_nvidia_bulletins.py`（8 個）：測 `deploy/pilot` 的鏡像更新腳本、`deploy/gitlab-runner/mirror-sync.sh`（常駐環境到 GitLab runner 的鏡像同步）與 `deploy` 安裝腳本接線、`fast-check.sh` 預期的函式整個刪除；`tools/mirror/*.sh` 本身的測試（下載、`--check`、重用、大小上限等）都保留。
- `test_ubuntu_cve_status.py::test_script_safety_and_docs` 改名 `test_script_safety`，去掉要 `ci-run.sh`、`docs/offline-mirrors.md`、`deploy/versions.md` 的斷言，腳本安全項目保留；`test_pilot_utf8_truncation.py` 不再掃 `deploy/`（門檻 20 → 10 個檔）；`test_pilot_l4t_kernel.py` 去掉用 `scio_prep.py` 的一半。
- `test_pilot_compare_and_scripts.py`、`test_pilot_lock_sandbox.py`、`test_pilot_sources_scio.py`：移除用到 `compare_expected.py`、`scio_prep.py`、`scio_diag.py`、`real-projects.sh`、`install-maven.sh`、`cdxgen_regression.py`、`tests/results` 的測試函式。
- `test_exploited_vendor.py`、`test_exploited_watch_grype.py`、`test_exploited_watch_refresh.py`：移除用到 `alert_mail.py`、每日／備份腳本、`deploy/` 安裝腳本的測試函式。
- `test_vex_no_response.py`：移除用到 `csaf_advisory.py` 的 CSAF 測試函式 1 個；另 1 個同時測 CSAF 與 CDX／OpenVEX 的函式，只刪 CSAF 的後半，CDX／OpenVEX 的斷言保留（改名 `test_legacy_responses_keep_cdx_and_openvex`）。
- `tools/sbomgate/tests/test_sbomgate.py`：移除 `RealEvidence` 類與 6 個測試方法，它們讀 sca-center 的 `tests/results/`（e2e 的真實掃描輸出）、`tests/projects/`（被掃描的開源專案原始碼）和 `tests/expected/`，這些不帶（硬性限制：不帶 `tests/results/`）。其餘 sbomgate 單元測試（合成 SBOM）都保留。
- `test_runtime_evidence.py`、`test_kernel_modules.py`：移除測板子端腳本 `board-on-device.sh` 的 3 個測試；`test_cra_exploitation.py`：讀 `cra/README.md` 的文件測試改成只留常數斷言（`KERNEL_NET_STAGING`、`KERNEL_NET_PREFIXES`），README 的內容核對未保留。
- 不帶：`test_alert_mail.py`、`test_csaf_advisory.py`、`test_customer_package_round2.py`、`test_customer_sbom_and_wording.py`（都 import `csaf_advisory`）、`test_gitlab_ci.py`、`test_gitlab_bot.py`、`test_gitlab_runner.py`、`demo/tests/test_board_test.py`、`test_x86_firmware.py`（歸 C2）。

## C2 韌體工具（WP3＋WP4）

| dumpling 路徑 | sca-center 原路徑 | 來源 commit | 清理內容 |
|---|---|---|---|
| `tools/cra/x86_firmware.py` | `scripts/cra/x86_firmware.py` | 25fa89a | 拿掉內部計畫編號與 issue／PR 參照、`CLAUDE.md` 參照、「main 也一樣」這類內部分支說明；範本路徑改成 `tools/cra/data/…`；「內部給的映像」改成「廠商或團隊提供的映像」；SBOM 的 tools 名稱 `sca-center x86_firmware.py` 改成 `dumpling x86_firmware.py`。**複製時解析邏輯沒改**；之後 dumpling 加的 CBFS、AMI PFAT、Intel legacy VBIOS 接線見 `docs/notes/c2-*.md`。新增（dumpling 的功能）：`dumpling:vuln-assessment`／`dumpling:vuln-assessment-note`／`dumpling:version-status` property、Intel CSME 的 `cpe`（family 確定是 CSME 才填；NVD 查證寫在程式註解）。SBOM property 命名空間 `sca-center:` 與 inventory 的 schema 名稱 `sca-center-fw-inventory/1` **維持不變**（C1 複製的報告工具可能依賴） |
| `tools/cra/tests/test_x86_firmware.py` | `scripts/cra/tests/test_x86_firmware.py` | 25fa89a | 拿掉審查輪次與 issue 編號的註解；`cdx_validator` 改從 `cdx_schema.py` import（原本從 `test_firmware_bom`，那個檔案歸 C1）。測試內容沒改 |
| `tools/cra/data/fw-manifest-template.csv` | `scripts/cra/data/fw-manifest-template.csv` | 25fa89a | 無需清理（全是假資料範例），原樣複製 |
| `tools/cra/tests/data/cyclonedx-1.6.1/`（README.md、bom-1.6.schema.json、jsf-0.82.schema.json、spdx.schema.json） | `scripts/cra/tests/data/cyclonedx-1.6.1/` | 25fa89a | 三個 schema 是 CycloneDX 官方檔案，bom 與 spdx 原樣複製；jsf-0.82.schema.json 只改了 `$comment` 裡作者的個人信箱（公開檢查不允許個人信箱；不影響驗證，SHA-256 與原檔的差異見該目錄 README.md）；README 只改了「用來驗證」那句的檔名參照。C1 之後的 cra 測試共用這個位置 |
| `tools/cra/tests/cdx_schema.py` | `scripts/cra/tests/test_firmware_bom.py` 約第 422–434 行（`SCHEMA_DIR`、`cdx_validator`） | 25fa89a | 只抽出這兩段，其餘 `test_firmware_bom.py` 歸 C1，不複製 |
| `tools/cra/tests/conftest.py` | `scripts/cra/tests/conftest.py` 與 `integration/conftest.py`（概念） | 25fa89a | 不複製 `integration/`。改寫成等效的最小版：環境變數 `DUMPLING_REQUIRE_TEST_DATA=1` 時任何 skip 都視為失敗（原本是 `SCA_REQUIRE_TEST_DATA`） |
| `tools/cra/coreboot_cbfs.py`、`tools/cra/tests/test_coreboot_cbfs.py` | BIOS 試掃原型（未進 sca-center git）：CBFS 列表／讀取、SELF payload 展開、FSP header 讀取四支評估用腳本 | 無（原型不在 git） | **依原型重寫，不是複製。** 沿用的做法：CBFS 檔頭（`LARCHIVE`、big endian 欄位、壓縮屬性 tag 0x42435a4c）、LZMA（alone 格式）、SELF segment 表（`>4sIIQII`）、`FSPH` header 欄位位置。新增：FMAP 定位、區域分開記、邊界與上限檢查、LZ4 解碼器、`revision`／`build_info`／`config`／`vbt.bin` 解析、SBOM 元件。測試資料全部是測試自己組的假資料 |
| `tools/cra/intel_vbt.py` 的 `parse_vbt()` | `tools/cra/coreboot_cbfs.py`（本 repo）的 `parse_vbt()` | 無（dumpling 內部搬移） | 原樣搬移，`coreboot_cbfs.py` 改成從 `intel_vbt` 取得並同名匯出；原本就是依 Linux i915 `intel_vbt_defs.h` 的欄位自己寫的，不是從 sca-center 複製 |

以下是 dumpling 自己寫的（不是複製）：`pipeline/firmware-bios.sh`、`tools/cra/intel_vbios.py`、`tools/cra/tests/synthetic_vbios.py`、`tools/cra/tests/test_vbios_synthetic.py`、`tools/cra/tests/test_vbios_intel.py`、`tools/cra/tests/test_x86_firmware_sbom.py`、`tools/cra/tests/requirements.txt`、`tests/run.d/c2-x86-firmware.sh`、`tools/cra/intel_cse_layout.py`、`tools/cra/tests/test_intel_cse_layout.py`、`tools/cra/ami_pfat.py`、`tools/cra/tests/test_ami_pfat.py`、`pipeline/firmware-expect.py`、`pipeline/firmware-ci.sh`、`pipeline/lib/firmware_plan.py`、`docs/notes/c2-ami-pfat.md`、`docs/notes/c2-csme-layout.md`、`docs/notes/c2-coreboot-cbfs.md`、`docs/notes/c2-vbios.md`、`docs/notes/c2-firmware-expect.md`、`pipeline/firmware-sbom-check.sh`、`pipeline/lib/firmware_sbom_check.py`、`pipeline/install-tool.sh`、`pipeline/lib/tools.lock`、`docs/notes/c2-supplier-sbom.md`、`tools/cra/uefi_gfx.py`、`tools/cra/tests/test_uefi_gfx.py`、`tools/cra/tests/test_uefi_image_contract.py`（`uefi_gfx.py` 子類別化 C1 的 `tools/cra/uefi_image.py` 的 `Scan`，不複製它的程式碼；依賴的內部名稱見 `docs/notes/c2-vbios.md`）（`ami_pfat.py` 的格式欄位核對自 platomav/BIOSUtilities 的 AMI PFAT 解開工具，只讀原始碼、沒有複製程式碼，出處與授權寫在該檔檔頭）。
以下是 dumpling 自己寫的（不是複製）：`tools/cra/amd_psp.py`、`tools/cra/tests/test_amd_psp.py`、`docs/notes/c2-amd-psp.md`、`firmware/bios/asus-prime-b550m-a-3404/firmware.yml`（AMD Embedded Firmware Structure、PSP／BIOS 目錄、AMD 微碼與 AGESA 字串的只讀解析；格式欄位與 type 編號核對自 coreboot `src/vendorcode/amd/psp/*.h`、`util/amdfwtool/amdfwtool.h`（GPL-2.0-only）、PSPTool 的 `entry.py`（GPL-3.0）與 Linux 核心 `arch/x86/kernel/cpu/microcode/amd.c`，只讀欄位位置、編號與行為說明，沒有複製程式碼；type 名稱沿用上游識別字；`PSP_TYPES`／`BIOS_TYPES` 是轉錄自公開 header 的事實性編號與名稱（出處見檔頭），沒有搬程式碼；出處寫在 `amd_psp.py` 檔頭與 `docs/notes/c2-amd-psp.md`）。
