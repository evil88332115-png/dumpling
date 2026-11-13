# STATUS

每個對話一節，**每做完一步就更新並推送**（`ci/status-update.sh`，見 main 的 `docs/HANDOFF.md`）。只改自己那節，`<!-- BEGIN/END -->` 標記不要動。

最後更新：2026-11-13 02:35 -0500（C2）

<!-- BEGIN C0 -->
## C0 協調（WP0）

- 目前在做：看 PR、合併、驗收，回覆 C1–C4
- 分支／PR／commit：main 26a6377。**M1（#9）、M3（#14）、M4（#28）＋修正 #32 已合併**；文件批次 #13、#15（D-029～D-033＋CRA 調查與提案）已合併；分支 `wp0/docs-batch-4`（已推送、未開 PR；D-034～D-043；D-039 使用者已確認、D-042／D-043 使用者已確認），M2 合併後開 PR
- 代理：無。PR #32 驗證代理完成：通過（應修 F1–F3，C3 併入 M2 後的監控 PR，開 real Issue 前必修）
- 各對話：C1 做 M2（wp1/m2：P 平台介面＋開案範本、L 依層分開已完成、J Jetson 編譯＋掃描＋release 進行中）；C2：wp3/supplier-normalize（dd54722）正規化已完成、CI 綠，另修 report 假 OK 路徑；等 M2 合併後加 fetch_verify 再開 PR；C4（WSL）等 M2 的 P 軌。C0 已請 C4 不等 M2 合併、以 wp1/m2（P 軌已完成）為基礎開始轉接器；C2 已完成 fetch_verify 切換（wp3/supplier-normalize 8a960c0，CI 綠），PR 等 M2 進 main。C4 已開 wp7/adapters，回報 3 處契約只適用 Jetson（pipeline.yml 交接寫死、scan-flash-package.sh 平台與架構寫死、jetson_scan.py 通用部分），C1 已同意全部在 M2 做（build.mode none／handoff 資料夾、--platform generic＋--arch、platform_scan.py），名稱已轉 C4；AI NAS 加掃 OMV 原始碼由 C4 在 scan.sh 內做（C0 同意）。C4 wp7/adapters 8e4ced9：三平台 platform.yml／示範專案／build／assemble／raw-sectors／sbom_augment 完成，EOL 資料 11 筆已交；已接 C1 新介面、scan.sh 完成，rpi-lite-demo 端對端 CI 進行中（C0 提醒：Debian 核心要套 debian.tar.xz 修補、標準答案先人工核對、kernel_source_file 若動到 C1 介面要協調）。D-034：廠商分支 U-Boot 給上游 CPE、結果待人審。C3 已在 WSL 那台開工 M4（wp2/watch）：每日監控不開 DT；C0 要求核心／開機程式比對要涵蓋或標 NOT_RUN、狀態不放分支（排程 job 不給 contents: write）。C3：F1–F6＋concurrency 在 wp2/watch-m2（b1b236e），等 M2 後接 mirrors.sh 再開 PR；M8 B1 不依賴 M7 的部分完成（wp2/art14 1346916，176 測試；開 PR 前要用暫時 push 觸發實跑 drill）。C4：rock-5b-demo 標準答案兩輪驗證定案（d50783d，68 項）；dthelper／libmraa 改歸 bsp（D-027）後重訂。C2 新工作 D-042：AMD PSP 目錄＋新世代 Intel CSME 解析（公開樣本、不提私有試跑）；D-043 韌體公告比對 (1)(2) 給 C2、(3) vendor-watch 給 C3。J 完成：wp1/m2 1bbcf69（C4 可併）；M2 PR 預計 4–5 小時後
- CI：無進行中（C0）。WATCH_REAL_ISSUES 尚未設定（流程：#32 合併 → M2 合併 → 手動 baseline → 排程 dry_run 一天 → C3 回報 → C0 設定）
- 下一步：C1 的 M2 驗收 run 已綠（43375548090、43375551920），C1 派驗證後開 PR → C0 另派獨立驗證 → 合併 → 問使用者何時打第一個正式 tag；M2 合併後：開文件批次 PR（D-034～D-043）、C2／C3／C4 併 main 後各自開 PR、排 M7（含 adapter-gaps #16）
- 給 C3 的交接：(1) M1 沒帶 `alert_mail.py`（寄信），exploited_* 寄信測試約 29 個已刪，要寄信時由 C3 帶回；(2) GitLab 階段「已被利用」的真實案件一定要用私有 Issue；(3) 每日監控讀 Release 附件 `sbom-<專案>-<版本>.cdx.json`＋`release-meta.json`，開發版讀滾動 pre-release `dev/<專案>`（D-029）；watch 自己的狀態檔（防 60 天停用）由 C3 設計；(4) GITLAB-PORT 待辦：DT parent／child 專案在常駐 DT 再評估（D-030）
- 給 PM／法務的待決定：VEX 發行閘門要不要分層（客戶負責 OS 時，OS 層未評估的 KEV 是否擋發行；目前保守：擋）（D-030）；附件 III／IV 分類、CVD 政策內容、單一聯絡窗口（D-032）
- M2 後要排進 M7 的（C4 adapter-gaps）：#16 cra_report 交付的 CRA 報告要寫 D-038 的「廠商核心、依上游版本列候選」說明（C1）；其他見 wp7/adapters 的 docs/references/adapter-gaps.md
- 卡住／等決定：無。D-041 已定（第二台每對話 4、整台 8、負載門檻 12）
<!-- END C0 -->

<!-- BEGIN C1 -->
## C1 流程核心（WP1＋WP6）

- 目前在做：M2（PLAN「里程碑」M2：打 tag 後 Jetson 版本全程跑通、產出 Release；含 C1 額外的平台介面與開案範本、依層分開）。M1 已合併（main 0e706cb，PR #9）
- 分支／PR／commit：
  - `wp1/m2`：M2 整合分支，1bbcf69＝J 併入＋main 26a6377（之前：6b70949，main b6d341a（含 C2 M3）＋P、L、K 軌＋gpu-firmware 空對照表＋rpi_img 依內容選 boot 分割區＋PROVENANCE 修正＋cra-scan 沒給 --source 時標 GAP）＋kernel-cve.sh clone 重試＋K 第二輪＋kernel-cve.sh 上游連不上時沿用 48 小時內的上一份鏡像（ATTENTION；sca-scan 記 C-kernel-cve-mirror）；CI tests run 43343147526（d12bf41 綠燈）
  - `wp1/m2-layers`：L 軌，已 fast-forward 併入 wp1/m2，worktree 已移除
  - `wp1/m2-platform`：P 軌，已 fast-forward 併入 wp1/m2，worktree 已移除
  - `wp1/m2-jetson`：J 軌，已 fast-forward 併入 wp1/m2（3e0190e），worktree 已移除；之後併了 main 26a6377（M4 每日監控），沒有衝突
  - `wp1/m2-spike`：試驗分支（4b8b7b8，不合併；量測在 `docs/m2-spike-results.md`），worktree 已移除
  - M1 的 worktree 與子分支（m1-dt、m1-fix、m1-tools-pilot、m1-tools）已清掉
- 代理：
  - 寫程式 S（M2 試驗）：完成。arm runner 單一 job 約 36 分鐘原生編完核心＋全部樹外模組（nvbuild.sh，make -j4），磁碟峰值約 8 GiB、RAM 約 3 GiB；run 43242393210（清理）、43246860803／43254234938（編譯＋傳檔）
  - 寫程式 P（平台介面與開案範本）：完成，CI run 43256946338 綠燈。契約見 `docs/PLATFORM-INTERFACE.md`：`pipeline/platform.sh <validate|fetch|build|assemble|scan|raw-sectors> <專案資料夾> <版本>`，結束碼 OK 0／FAIL 1／GAP 3／NOT_RUN 4／用法 64；project.yml 的 `os_responsibility: ours|customer|upstream-vendor`；sources.yml 是 `releases.<版本>.files[]`（gap、sha1、commit＋repo）；platform.yml 的 `layers`（bsp 套件名稱清單、host-tool 路徑、default os）；`pipeline/lib/project_config.py` 的 `classify_package`／`classify_path`；fetch_verify.py 簽名同 firmware_fetch；scan-flash-package.sh 改成明確 `--platform`、沒給就 GAP。待確認見該文件第 8 節（r39.2.0 public_sources.tbz2 的 sha256 尚未記錄＝gap）
  - 寫程式 L（依層分開）：完成，CI run 43265323496 綠燈。契約 `docs/LAYERS.md`：`pipeline/sbom-layers.py split <sbom> <平台> <專案資料夾> <輸出>` → sbom.bsp（bsp＋unknown）／os／host-tool（不上傳）／product＋layers.json（scan_plan）；cra_report `--os-responsibility`、漏洞列加 layer／layer_todo；P1 判斷表 customer／upstream-vendor 只放 bsp＋unknown、ours 含 os、沒給全部＋GAP；host-tool 不進清單；DT 兩個平行專案 `<名稱>-bsp`／`-os`；SBOM 沒有分層屬性時輸出與原本一致。Jetson fixture：bsp 1537、os 1975、unknown 339、host-tool 0
  - 寫程式 J（Jetson build／assemble／scan、release.yml、dev.yml、patch 版、標準答案測試、接上分層）：`wp1/m2-jetson`；Sonnet 5.5／high；**完成**（3e0190e）。兩個版本的完整 run 都綠燈，各 19 個附件的 draft，標準答案 23 項都符合；v39.2.1 上游被修改的檔案 1、v39.2.0 是 0；build record OK、C-kernel-boot OK；兩版 bsp 報告 diff 合理（+33／−22 列，只有元件版本變動）；cache 還原實測 OK；draft 測完已刪。未實測：runner 上的 fallback（ATTENTION）、main／dev/** 的滾動 pre-release。另記：Release POST 偶發 403（已加重試）。手動觸發只建 draft Release，測完刪 draft；不建 git tag。追加（C4 經 C0 提出，2026-11-12）：pipeline.yml 通用化（build.mode none 略過 build、交接只走 $DUMPLING_OUT/handoff/、build.apt／build.runner／scan.apt 由 plan job 讀）、scan-flash-package.sh 加 --platform generic 與 --arch（platform.yml arch，預設 arm64）、通用部分抽成 pipeline/lib/platform_scan.py；scan.runner（選填，預設 amd64，不隨 arch）；sources.yml role 加 metadata（官方清單／說明檔，只核對不掃描）；sha1 改由 fetch_one 核對；每步結束碼統一走 pipeline/run-step.sh（3 GAP／4 NOT_RUN 繼續），結果寫進 pipeline-steps.tsv 並列進摘要與 release-meta；（凍結例外，擋 C4）scan.tools: sbom-only|full（full＝install-tools.sh 完整模式，含 cdxgen／govulncheck／guarddog）；（凍結例外，擋 C4）kernel-cve 鏡像 actions/cache＋共用 pipeline/lib/mirrors.sh，退回時 pipeline-steps ATTENTION、Release 說明標示（不擋正式發佈，同 D-033）
  - 寫程式 K（核心版本參數，C4 經 C0 提出的第 6 件）：完成，已 fast-forward 併入 wp1/m2（d12bf41），worktree 已移除。三支入口加可重複的 `--kernel-version`／SCA_KERNEL_VERSIONS；`scan/kernel-versions.json`（shipped／requested／judged／not_judged）；未判定的出貨核心各列 GAP；指定多顆先標 GAP；有未判定的出貨核心時 K1／K2 的排除不採用（tools/cra/vex_export.py `kernel_with_scope`，VEX／報告／P1 表／runtime_evidence 都擋）；核心清單在判定工具讀映像的同一趟列出。本機全測 OK。逐一判定與合併在 M7（D-036）
  - 寫程式 K 第二輪（凍結例外，C3 需要）：完成，已 fast-forward 併入 wp1/m2（2cf0f23），worktree 已移除。kernel-versions.json schema `sca-center-kernel-versions/2`：shipped 每顆帶 upstream_version／upstream_basis（source-makefile／platform-param／source-makefile+platform-param）／upstream_note；Makefile 由 kernel_config.py `--source-tree-version` 讀；kernel_versions.py `--upstream-version <出貨>=<X.Y.Z>`；讀取端 /1、/2 都收。本機全測 OK。待做（J 併入後由我做）：Release 附件 `kernel-versions-<專案>-<版本>.json`（列進 release-meta）、platform_params.kernel_upstream_version 傳成 --upstream-version；release-meta.json 加 report_status（cra_report summary.json 整體 status，分層列每份）、release_gate（vex.gate），讀不到填 NOT_RUN，Release 說明開頭印出（C4 提、C0 轉，決定放 M2）；J 的 result 改名 pipeline_result；Release 說明開頭順序 report_status、release_gate、pipeline_result；status 仍是生命週期，文件寫清楚
- CI：手動觸發（`gh workflow run <wf> --ref <分支>`）
- M7 待辦（M2 合併後；判斷邏輯，一起驗證）：D-035 排除依據類型；D-036 逐顆核心判定與合併；D-039 核心可利用性三層判斷（從 sca-center 同步，PROVENANCE 更新來源 commit）與精靈以掃描版本覆寫 version／identification
- M2 範圍已凍結（D-036）：之後的缺口沒擋住 C4 就排到 M2 之後
- 我自己：release-meta.json 加 report_status／release_gate／pipeline_result（result 改名）／reports／kernel_versions、Release 說明開頭依序印出；附件 kernel-versions-<專案>-<版本>.json（dev 也發）；platform_params.kernel_upstream_version → `project-info.py --kernel-args` → 精靈 `--kernel-upstream-version` → sca-scan → kernel_versions.py `--upstream-version`。已推 wp1/m2 9f1d2f0；已通知 C0 轉 C3、C4。**驗收 run 全部綠燈**：release.yml v39.2.0 43375548090、v39.2.1 43375551920（從新的 build，draft，各 20 個附件），tests.yml 43375594174。兩份 draft：標準答案 23/23、build record OK、C-kernel-boot OK、上游被修改的檔案 v39.2.1＝1（inet_connection_sock.c）／v39.2.0＝0、kernel-versions 附件 schema /2（upstream 6.8.12，source-makefile）；report_status／release_gate 都是 GAP（NVD 沒開，已知），pipeline_result OK
  - C4 回報、C0 轉（2026-11-13）：scan.sh 讀 scan_plan 用 TAB 分隔，ours 的空後綴被吃掉。修法：`jetson_scan.py plan`（platform_scan.scan_plan_lines，格式驗證）每行用 0x1F 分隔；collect 同一後綴出現兩次取後面那次（ours 的產品 SBOM 重跑），kernel-versions 仍取完整掃描；LAYERS.md 加說明；測試 7 個（含舊寫法的反證）。本機全測進行中，跑完推送
- M2 設計備忘：
  - C4 平台研究：`wp7/platform-samples` 的 `docs/platforms-research.md`
  - `project.yml` 要有 OS 歸屬欄位（ours／customer／upstream-vendor；D-025、D-027：由角色決定，不寫死在平台設定）
  - bsp／os 分層：平台設定裡的「套件名稱清單」決定，不看版本字尾（同 nvidia-l4t-* 做法，D-027）
  - Rockchip 分割區外的開機程式：以原始磁區為準（D-027）；assemble／scan 留掛點
  - **平台一律由 project.yml 明確給定、一路傳到 scan，不從映像格式推測；沒給就把開機程式分類標 GAP**（C4 發現 scan-flash-package.sh 對所有 raw-disk-img 固定傳 raspberrypi；P 軌修）
  - 共用下載核對：P 新增 `pipeline/lib/fetch_verify.py`（行為與簽名同 firmware_fetch.py）；M2 合併後由 C2 把 firmware_fetch.py 改成 import（C0 會通知 C2）
  - D-028：看不到內容的二進位檔要登記在 `ci/public-binary-allow.txt`（路徑＋sha256＋原因）；M2 的二進位測資盡量當場產生
  - GitHub 動態封存檔：以 commit SHA 為準，sha256 不符時 clone＋checkout 再核對或標 GAP，不自動接受新的 sha256（D-025、D-027）
  - **試驗結果（D-029，以實測為準）**：runner `/` 145 GiB，清理前可用 arm 106 GiB、x64 86 GiB（不用清理）；`public_sources.tbz2` 沒有 NVIDIA 公布的整包雜湊——整包 SHA-256 寫「首次下載記錄（TOFU）」，元件 SHA-1 對 NVIDIA `public_sources_sha.txt`；核心建置不可重現——建置紀錄與刷機包的核心要同一次編譯
  - J 的 job 拆法：build（arm，約 40 分鐘）→ artifact（BuildRecord 約 169 MB＋交付與紀錄約 152 MB，compression 0、retention 1 天）→ scan（arm，重新下載 BSP／rootfs 約 32 秒，比 cache 快）→ release（只有它 contents: write）
  - **SBOM 存放（D-029）**：不提交 `sboms/`，Release 是正式來源；附件 `sbom-<專案>-<版本>.cdx.json`＋`release-meta.json`（project、version、tag、status、platform、os_responsibility、commit、built_at、workflow_run）；開發版發到滾動 pre-release `dev/<專案>`（只在 main 或 dev/** 發佈）
  - 新 workflow 不在預設分支時 `gh workflow run <檔名>` 回 404：先用一次 push 觸發登錄，之後改回（PR 裡不留 push 觸發）
- 對外介面約定（改之前先通知對方）：
  - C2 依賴 `tools/cra/uefi_image.py` 的內部名稱：`Scan`（子類別覆寫 `scan_bytes(data, module)` 接 GOP／VBT／legacy VBIOS）、`parse_fvs(data, sc, depth)`、`Stop`、`MAX_*` 常數（C2 有契約測試）
  - C2 依賴 `tools/pilot/lib/nvidia-bulletins-gpu-firmware.json`（路徑與檔名；`wp1/m2` fdabd22 新增的空表，M2 合併後生效；C2 在檔不存在時印 GAP）
  - C2 依賴臨時 DT 介面：`pipeline/dt-ephemeral.sh up|wait|env|down`、`tools/pilot/sca-scan --sbom`、`pipeline/scan-status-check.py`（預設 11 個必要階段）、`pipeline/dt-verify.py verify`
- 卡住／等決定：
  - （已定，D-030）unknown 保守算 BSP 待辦，J 校正時先用 Syft locations 套路徑規則，報告附「為什麼判斷不了」；NVIDIA 為平台提供的套件都算 bsp——J 依公開 BSP 的 apt 來源補 Jetson 的 bsp 名稱清單；VEX 發行閘門不分層（列入 C0 給 PM／法務的待決定清單）；DT 維持兩個平行專案（parent／child 留到 GitLab 階段，C3 的 GITLAB-PORT 待辦）；host-tool 不上傳 DT，報告那節加「隨 BSP 提供給客戶，在客戶主機上執行，不在產品上執行」
  - 等使用者（C0 轉問）：M1 PR 內歷史 WIP commit 含內部 CI 執行編號等（禁用字 0 命中）——選項只有接受或刪 repo 重建
  - （已定）public-check 反向規則：D-028（C0 做）；上游部署預設路徑保留；alert_mail.py 留給 C3
<!-- END C1 -->

<!-- BEGIN C2 -->
## C2 韌體（WP3＋WP4）

- 目前在做：M3 之後的收尾 PR（C0 同意合成一個）：(1) 供應商 SBOM 上傳前最小正規化（完成）；(2) `pipeline/lib/firmware_fetch.py` 改 import 共用的 `pipeline/lib/fetch_verify.py`（完成，C0 要我先併 `origin/wp1/m2` 做好，PR 等 M2 進 main）
- **M3 已完成**：PR #14 合併（main b6d341a）。已合併 PR：#7（樣本清單＋下載核對）、#8（x86_firmware → CycloneDX）、#14（M3）
  - M3 內容：coreboot CBFS、AMI PFAT、UEFI FV 的 Intel GOP／VBT／legacy VBIOS（`tools/cra/uefi_gfx.py`，子類別化 C1 的 `uefi_image.Scan`，契約測試 `test_uefi_image_contract.py`）、expected 驗收（新鍵 `intel_gop`、`intel_legacy_vbios`）、供應商 SBOM 品質檢查、`firmware-dt` job（臨時 DT＋Grype）
  - DT 結果（Actions）：Protectli 16→DT 14、NUC 8→6、OVMF 1、合成 vBIOS 1，都 ATTENTION；供應商 SBOM 被 DT 拒收（schema 不符），以 `expected_dt` 宣告，只放行 DT 的「BOM 不符 schema」400
  - 驗證：第一次不通過（issuecomment-6832127582：只看 http=400 太寬）→ 8f02635 修正（錨定 DT 回應開頭＋6 個反例），C0 複核後合併
- 分支 `wp3/supplier-normalize` 8a960c0（worktree `$AGENT_TMP/dumpling-wt-c2-norm`，從 main b6d341a；已併 `origin/wp1/m2` 54dbf48）
  - 8a960c0：firmware_fetch 刪掉自己的下載核對函式，改 import fetch_verify（名稱照舊匯出、`main(downloader=…)` 不變；清單仍要求 size）；新測試：共用函式身分、缺 size 仍 FAIL、`python3 -I` 從別的目錄執行。本機 c2-firmware 238、c2-x86-firmware 325、c1-m2-layers／c1-m2-platform／c1-pipeline／c1-public-check／c1-tools（3146）／c0-public-check-binary 都 OK。CI tests 43323859797、firmware 43323866206 綠：五個真樣本全 ATTENTION；NVIDIA「有表」路徑實跑 `C-nvidia-bulletins-db ATTENTION`（gpu-firmware 表 1 筆待人審 5674），不再印 GAP
- 代理：
  - 代理 M（寫程式，Sonnet 5.5 high）：`wp3/supplier-normalize` 84ea369，狀態：完成。`pipeline/lib/firmware_sbom_normalize.py`（1.4～1.6；頂層多出欄位→`dumpling:supplier-extra:*`、只有 url 的 license→`dumpling:supplier-license-url`；normalize.json 記每筆原 JSON Pointer＋值 sha256；上限；先規劃後套用）、CycloneDX 1.4 官方 schema（tag 1.4）、樣本拿掉 expected_dt。本機真 DT：Dasharo NS5x **DT 收下**，10 元件，verify 5 項 OK；原檔 1.4 schema 2 錯→副本 0 錯
  - 我補 38db74c：報告的 OK 太寬（Grype 36 筆、purl 全 pkg:generic、沒有評估標記仍標 OK）→ `attention_reasons()`，三種都 ATTENTION；用真 DT 結果重跑 report 確認。CI tests 43289059136、firmware 43289066571 已觸發
  - 預驗 38db74c（驗證，Sonnet 5.5 high），狀態：完成，**通過**。正規化：2 萬份隨機文件依紀錄還原全部相等；CycloneDX 官方 1.4／1.5／1.6 valid 範例 112 份零改動；schema sha256 重新下載一致；CI tests 43289059136、firmware 43289066571 綠，供應商 SBOM DT 收下（10 元件）、ATTENTION。建議（舊有）：report 仍有假 OK 路徑（DT 漏洞數 -3／null、dt-verify checks NOT_RUN／空、其他 sca-scan 階段 FAIL 不影響狀態、標記／purl 辨識太窄、供應商可自帶 dumpling: 標記、缺 version 不算）、重複鍵靜默、代理字元殘留檔
  - 代理 N（寫程式，Sonnet 5.5 high）：`wp3/supplier-normalize` dd54722，狀態：完成。假 OK 路徑都堵住：比對數只認 int≥0；dt-verify 必要檢查缺／NOT_RUN／未知→GAP；任何 sca-scan 階段 FAIL→FAIL（expected_dt 放行規則不變），其他非 OK 階段→ATTENTION；vuln-assessment 只認 NONE、供應商 SBOM 自帶 dumpling: 標記不採信；purl 格式嚴格；缺 version 列入；型別錯→prep FAIL；重複鍵偵測→ATTENTION＋紀錄；代理字元先序列化再寫檔。CI tests 43294331473、firmware 43294338722 綠，五個真樣本全 ATTENTION（無 OK、無 FAIL）；c2-firmware 235、c2-x86-firmware 325
  - 代理 O（寫程式，Sonnet 5.5 high）：`wp3/amd-psp` 41353d3，D-042 AMD 平台，狀態：完成。新模組 `tools/cra/amd_psp.py`（EFS → combo／L1／L2 的 PSP 與 BIOS 目錄、A/B 復原 slot header；Fletcher-32 checksum；PSP 韌體標頭版本；AMD 微碼 patch level／日期／equivalence id，CPUID 只在有等價表時；AGESA 字串，不同值全列＋ATTENTION；未知 type、Promontory、壓縮條目等都 GAP；各種上限跨巢狀累計）。公開樣本 ASUS PRIME B550M-A 3404（更新包標頭讓 EFS 不在固定位置、combo 目錄、L2）：17 個目錄、244 項、19 份微碼、AGESA ComboAM4v2PI 1.2.0.B；SBOM 99 元件。expected 新鍵 `amd_agesa`（ASUS release notes，我另用 ASUS API 核對相符）、`amd_microcode`（兩份 patch 與 linux-firmware c4586ffaac0c 位元組相同）。CI tests 43380211347、firmware 43380207352 綠（DT 99 元件）；本機 c2-x86-firmware 346、c2-firmware 168、c1-tools OK
  - 預驗 41353d3（驗證，Sonnet 5.5 high），狀態：完成，**不通過**。真樣本、expected 出處（ASUS API、linux-firmware 位元組比對與等價表）、Intel／OVMF 輸出不變、公開資料規則都過。應修：(1) 壓縮的 0x66 條目沒做範圍檢查 → analyze 丟 struct.error，整份 AMD 結果作廢（被 x86_firmware 接住、記 GAP，但不該發生）；(2) 兩種位址解讀都有目錄 cookie 時靜默選一邊（真樣本有 2 處）；(3) size 0 與壓縮條目沒有 GAP；(4) AGESA 截斷仍當完整版本。建議：Fletcher-32 初值照 coreboot、ISH checksum 有公開算法、AGESA 分隔、UI section、EFS 位置分表、額外驗證補來源、8 個存活變異 → 交回代理 O 修，狀態：進行中。C0 決定：(2) 兩種位址解讀都有目錄時一律 GAP、兩邊都列，不選邊；D-042 兩半合成一個 PR，開之前通知 C0（sca-center 端另做本機驗證）
  - 代理 P（寫程式，Sonnet 5.5 high）：`wp3/csme-new` 17072b5，D-042 新世代 CSME，狀態：完成。新模組 `tools/cra/intel_cse_layout.py`（CSE layout table 1.6／1.7 → BPDT v1／v2 → FTPR／RBEP／NFTP 的 `$CPD` v1／v2 → `.man` 版本；沒有 FTPR 時要 RBEP 與 NFTP 版本相同才採用，矛盾／單一來源／結構不一致→GAP；無全檔掃描、有上限）；x86_firmware.py 只在舊路徑沒結果時才試新模組。公開樣本 Dasharo NovaCustom V540TU v1.0.1（ME 區域開頭不是 `$FPT`、沒有 FTPR）：改動前 unknown → 18.0.10.2285，expected `intel_me` 依 release notes（我另外直接抓原始 HTML 核對相符）。CI firmware 43377248319、tests 43377252522 綠；本機 c2-x86-firmware 380、c2-firmware 167、c1-tools 3173
  - 預驗 17072b5（驗證，Sonnet 5.5 high），狀態：完成，**通過**。沒有錯誤版本、崩潰、違反 GAP 的問題（約 28 萬次 fuzz 零例外；Protectli／NUC／OVMF 新舊輸出逐位元相同；Nova 真樣本與 release notes 原始 HTML 重現 18.0.10.2285）。應修 1：layout 1.7 的 CRC-32 其實有公開定義（MEAnalyzer），文件寫成「沒查到」。建議：驗 layout CRC、沒有 FTPR 時要 RBEP＋NFTP 兩種類型（同類兩份是備份、不算獨立）、1.6 讀 BP1…BP5、「已清除」不能只看 4 bytes、補 6 個存活變異的測試、微碼的出處說法 → 交回代理 P 修，狀態：完成（70db3f6）：layout 1.7 驗 CRC-32（Size 從 +0x10 起算，認 0x40／0x48／0x58）、沒有 FTPR 要 RBEP＋NFTP 兩類型且版本相同、1.6 讀 BP1…BP5 並納入矛盾檢查（u64 checksum 算法不確定、不驗）、整個 BP 都是 0xFF 才算清除、16 個變異全殺；expected 加微碼 000A06A4／0xE6／0x25（Dasharo v1.0.1 release notes 與 Intel microcode-20250812 releasenote，我直接抓原始檔核對）。CI firmware 43382783573、tests 43382788001 綠；本機 c2-x86-firmware 403、c2-firmware 167、c1-tools 3197
  - 複驗 70db3f6（驗證，沿用 CSME 預驗代理），狀態：完成，**通過**，無應修（fuzz 共約 36 萬次零例外、44 個變異全殺、Protectli／NUC／OVMF 新舊輸出逐位元相同、Nova v1.0.0 另外驗證也相符）。建議的文件小修我補在 61e8ef7。**D-042 新世代 CSME 完成**（`wp3/csme-new` 61e8ef7）
  - 已完成：代理 A～L；預驗 cbfs、pfat、4183a96（不通過→已修）、7e40fe7（通過）
- 依賴 C1：`uefi_image.py` 的 Scan／scan_bytes／parse_fvs／Stop／MAX_*（C1 已記入對外介面約定）；`dt-verify` 檢查名稱「弱點分析完成」「元件數」；gpu-firmware 空對照表 `tools/pilot/lib/nvidia-bulletins-gpu-firmware.json` 隨 M2 進 main（之前 CI 印 GAP）
- 下一步（兩件分開進行）：
  - supplier-normalize：等 C1 M2 合併進 main → 併 origin/main（確定只剩自己的改動）→ 重跑 CI → 開一個 PR → 驗證（C0 派）→ C0 合併。現況：沒有任何真樣本能到 OK（韌體 C-sbomgate 一定 NOT_ASSESSED、沒有工具寫 vuln-assessment=NONE、C-mirror-freshness 在 CI NOT_RUN）——保守、符合原則，不放寬
  - D-042：擴充 AMD 平台／新世代 Intel CSME 的解析範圍（x86_firmware.py）。(1) AMD：解析 PSP 目錄（含 L2、BIOS 目錄）的條目類型與版本、AMD 微碼（patch level、CPUID）、AGESA 版本字串；(2) Intel：支援沒有 `$FPT`／FTPR `$CPD` 的分割區配置，找出對應分割區的 manifest 版本。看不懂、找不到一律 GAP。標準答案只用公開可下載的樣本（firmware/ 登記網址＋sha256，預期值附出處）。分支 `wp3/amd-psp`（worktree `$AGENT_TMP/dumpling-wt-c2-amd`）、`wp3/csme-new`（`$AGENT_TMP/dumpling-wt-c2-csme`），都從 main 26a6377；各派一個寫程式的代理，做完各自預驗，功能完成再開 PR
  - D-043（排在 D-042 後）：韌體 SBOM 的公告比對，只用公開資料。(1) 自動比對：NVIDIA vBIOS 用每日鏡像的 NVIDIA product-security CSAF 填 `nvidia-bulletins-gpu-firmware.json`，依 vBIOS 版本＋裝置 ID 判定受影響／已修補／NOT_ASSESSED；Intel 微碼用 intel/Intel-Linux-Processor-Microcode-Data-Files 的 release notes（固定 tag／commit＋sha256），SBOM 的 CPUID＋rev 比較舊就列出中間的 INTEL-SA，讀不到 GAP；Intel CSME 加 NVD CPE（converged_security_and_management_engine_firmware），註明 NVD 資料不完整。(2) 規則表（半自動，比照 D-039）：一個公告一筆（INTEL-SA、AMI-SA、AMD-SB），條件＝元件＋版本範圍，記出處、確認者（角色）、日期；結果只給建議，排除照 D-035 記 vendor-statement。(3) vendor-watch 由 C3 改，C2 不動。產出：每份韌體 SBOM 都有比對結果（受影響／不受影響／NOT_ASSESSED＋依據）寫進報告；比不到寫「資料庫沒有資料，以廠商公告為準」，不顯示成沒有漏洞。順序：D-042 → D-043 (1) → (2)，每段完成通知 C0
- 卡住／等決定：無。代理暫存資料夾 `$AGENT_TMP/dumpling-tmp-c2-cbfs`、`-pfat`、`-verify-cbfs`、`-verify-m3b`、`-supsbom`、`-sbomfix`、`-c1files`、`-dt`、`-gop`、`-expect`、`-norm`、`-norm2`、`-verify-norm` 被安全檢查擋下沒刪，要使用者手動刪
<!-- END C2 -->

<!-- BEGIN C3 -->
## C3 監控＋GitLab（WP2＋WP5）

- 目前在做：M4 已合併（PR #28）；PR #32（第一輪應修）驗證通過、C0 背景合併；**M2 之後的監控 PR 分支 `wp2/watch-m2` 已先做好 #32 驗證的 F1–F6 與 concurrency**，等 M2 合併後接 mirrors.sh 再開 PR；M5 第一版完成，等 M2 合併後核對指令再開 PR
- 架構（已合併）：每日不開 DT；Grype＋CISA KEV＋EUVD＋核心 CNA＋廠商層級；狀態放在 `watch-state` Issue；D-040（只開 KEV／廠商層級、超過 20 個併成彙總、示範專案＋demo、排程 real 預設 dry_run、不開 art14）
- 分支／PR／commit：
  - PR #32 已合併（main 26a6377），worktree 已移除
  - `wp2/watch-m2` f204260（已併 main 26a6377；worktree `$AGENT_TMP/dumpling-wt-c3-m2`，從 #32 head 開）：F1 大小警告算 ATTENTION、7 天一次；F2 修剪過的群組再出現用 open_if_closed（`dumpling.pruned_keys`）；F3 Grype DB 過期與 L4T 對應 GAP／FAIL 擋第一次基準；F4 有 Release 卻沒有基準 → 只開「還沒有基準」提醒 Issue（plan.state=null，不寫狀態、不算監控 Issue）；F5 演練三輪都可建基準；F6／concurrency：group 依 ref、compute 用 actions: read 查上一次排程 run（cancelled／失敗／超過 36 小時 → 降級）、keepalive 印最近 3 次排程。PR 未開（等 M2 的 mirrors.sh）
  - `wp5/gitlab` b0079fc（worktree `$AGENT_TMP/dumpling-wt-c3-gitlab`）
- M8 B1（第 14 條通報，C0 交辦：等 M2 期間先做不需要 M7 欄位的部分）：分支 `wp2/art14`（worktree `$AGENT_TMP/dumpling-wt-c3-art14`，從 main 26a6377），只推分支、M8 才開 PR。條文已核對：EUR-Lex CELEX:32024R2847（OJ L 2024/2847, 20.11.2024）第 14(1)–(4) 條、第 71 條（第 14 條自 2026-09-11 適用）；期間的法定計算規則未核對 → 工具算保守值、交法務。銷售市場欄位等 C1 的 M7 → GAP
- 代理（上限 D-041：4 個，寫程式 3、驗證 1）：
  - 寫程式 B1 art14（Sonnet high）：完成。`wp2/art14` e66f499（177 個測試）。**已在 GitHub 實跑 action=drill 六步兩次全綠**（run 43369037768、43369266378；暫時的分支 push 觸發已拿掉）；實跑發現依標籤列 Issue 有索引延遲 → 演練步驟重試、countdown 跳過已關閉的。ART14.md 已加 1182/71 參考（未核對、採較早保守值）與 Bot 例外理由。目前沒有代理在跑
- CI：wp2/watch-m2 b1b236e：演練 43365208989 綠、tests 43365156856 綠（132 個 c3-watch 測試）、real＋dry_run 43366085628 綠（GAP）。main：real＋dry_run 43362385127 綠
- 防 60 天停用：**下次人工檢查日期：2026-12-13**（`gh workflow view watch.yml`）
- 下一步：
  - M2 合併 → `wp2/watch-m2` 併 origin/main → 每日監控改用 `pipeline/lib/mirrors.sh`（kernel-cve 沿用舊鏡像時，報告與 Issue 寫出那行 ATTENTION）＋release-meta 的 `report_status`（報告整體狀態）與 `release_gate`（發行閘門）寫進 Issue 內文與報告，欄位不存在填 NOT_RUN（名稱 C1 已定案：report_status、release_gate、pipeline_result；已做在 7caa0f2；**M2 合併後依 C1 實際格式收斂成只剩一種讀法**（2026-11-13 查 origin/wp1/m2、m2-jetson 還沒有這些欄位）：report_status 只留實際的形狀、拿掉舊名 `result` 與沒用到的格式，其他形狀一律 NOT_RUN）→ 演練／real dry_run → 開 PR → 驗證 → 合併
  - 之後：手動 `mode=real`＋`baseline=true` 建第一次真實基準 → 排程 dry_run 跑一天 → 回報「打開會開哪些 Issue」→ C0 設 WATCH_REAL_ISSUES=on
  - M5：M2 合併後核對 gitlab/.gitlab-ci.yml 的指令（T-01）→ 重跑 CI → 驗證 → 開 PR
- B1 art14 的待辦（M8）：等 M7 的銷售市場欄位再一起開 M8 PR；銷售市場接 M7 的 project.yml 欄位；GitLab 版（私密 Issue、email、SRP）只列在 docs/ART14.md 第 10 節，M5／M8 再做。已實測：github-actions[bot] 開的 Issue 是 author_association=NONE（#21），所以程式接受 Bot 作者是必要的
- 卡住／等決定：等 M2 合併
<!-- END C3 -->

<!-- BEGIN C4 -->
## C4 其他平台（WP7）

- 目前在做：M6。rock 標準答案重訂（72 項，0ba1e8b；D-038 兩邊核對一致），差異核對中；rpi 跑通（43380656858，GAP：沒有標準答案），接著寫標準答案；ai-nas 修了兩個 bug（48d0405、9793e0b）重跑中
- 分支／PR／commit：`wp7/adapters`（最後 commit 見 git log；已併入 origin/wp1/m2 a957f90 與 origin/wp1/m2-jetson）；`wp7/platform-samples`（868f064）；`wp7/cra-survey`（122042c，已併進 PR #15，PR #15 合併後刪除）；PR 都尚未開（M6 完成才開，D-020）
- 代理：驗證代理 1 個（Sonnet 5.5，effort high，只讀；任務：rock-5b-demo 標準答案第 17 項與 D-038 兩邊核對的差異核對；狀態：進行中）
- CI：dev.yml 依序跑 rpi-lite-demo → rock-5b-demo（c00611b）；ai-nas 最近一次 43341204962 FAIL（cdxgen 沒裝，已由 C1 在 M2 處理）
- 已完成：`docs/platforms-research.md`；`platform-samples/` 四份清單；`docs/references/cra-github-survey.md`、`cra-plan-proposal.md`；三個 platform.yml（arch、AI NAS 用 generic）；三個示範專案（sources.yml 含 metadata 清單檔）；sbom_augment（原始磁區元件、D-034 U-Boot CPE、OMV 原始碼併入）；支援期資料表追加 11 筆（D-033）；63 項單元測試
- 下一步：看三個平台的結果；C1 的 D-036（--kernel-version）進來後再跑一次；標準答案逐項核對（官方 SBOM／manifest／.info）後由驗證代理獨立核對，PR 附核對紀錄；不擋路的缺口記在 docs/references/adapter-gaps.md；M6 完成開 PR
- 卡住／等決定：無（核心參數改用 project-info --kernel-args 等 C1 收尾）
<!-- END C4 -->
