# STATUS

每個對話一節，**每做完一步就更新並推送**（`ci/status-update.sh`，見 main 的 `docs/HANDOFF.md`）。只改自己那節，`<!-- BEGIN/END -->` 標記不要動。

最後更新：2026-11-12 13:23 -0500（C2）

<!-- BEGIN C0 -->
## C0 協調（WP0）

- 目前在做：看 PR、合併、驗收，回覆 C1–C4
- 分支／PR／commit：main cd62514（M1 #9、文件批次 #13 已合併）；本機累積分支 `wp0/docs-batch-3`（D-029 M2 試驗實測更正 PLAN＋SBOM 以 Release 附件為準、D-030 依層分開），還沒推，C3 開工前合併
- 代理：目前沒有 C0 代理在跑
- 各對話：C1 開工 M2（wp1/m2：P 平台介面＋開案範本進行中、L 依層分開、J Jetson 編譯＋掃描＋release；wp1/m2-spike 量測 runner 限制）；C2 做 M3 最後兩塊（wp3/m3-dt 上傳 DT、wp3/m3-gop），完成後開一個 PR；C4（另一台 WSL2）第一階段完成（wp7/platform-samples、wp7/cra-survey），等 M2 的 P 軌
- CI：無進行中（C0）
- 下一步：等 C2 的 M3 PR、C1 的 M2 PR；M2 跑通後開 C3（建議開在 WSL 那台）
- 給 C3 的交接：(1) M1 沒帶 `alert_mail.py`（寄信），exploited_* 寄信測試約 29 個已刪，要寄信時由 C3 帶回；(2) GitLab 階段「已被利用」的真實案件一定要用私有 Issue；(3) 每日監控讀 Release 附件 `sbom-<專案>-<版本>.cdx.json`＋`release-meta.json`，開發版讀滾動 pre-release `dev/<專案>`（D-029）；watch 自己的狀態檔（防 60 天停用）由 C3 設計；(4) GITLAB-PORT 待辦：DT parent／child 專案在常駐 DT 再評估（D-030）
- 給 PM／法務的待決定：VEX 發行閘門要不要分層（客戶負責 OS 時，OS 層未評估的 KEV 是否擋發行；目前保守：擋）（D-030）
- 卡住／等決定：使用者（1）舊 WIP commit 的低敏感內部資訊：接受或刪 repo 重建（C0 建議接受）；（2）C4 CRA 調查的建議採用範圍（C0 建議 A、B 全採用，C 只做文件骨架標 GAP）
<!-- END C0 -->

<!-- BEGIN C1 -->
## C1 流程核心（WP1＋WP6）

- 目前在做：M2（PLAN「里程碑」M2：打 tag 後 Jetson 版本全程跑通、產出 Release；含 C1 額外的平台介面與開案範本、依層分開）。M1 已合併（main 0e706cb，PR #9）
- 分支／PR／commit：
  - `wp1/m2`：M2 整合分支，4bc43b6（main cd62514＋P 軌＋gpu-firmware 空對照表＋L 軌）
  - `wp1/m2-layers`：L 軌，已 fast-forward 併入 wp1/m2，worktree 已移除
  - `wp1/m2-platform`：P 軌，已 fast-forward 併入 wp1/m2，worktree 已移除
  - `wp1/m2-jetson`：J 軌（從 wp1/m2 fdabd22 開）
  - `wp1/m2-spike`：試驗分支（4b8b7b8，不合併；量測在 `docs/m2-spike-results.md`），worktree 已移除
  - M1 的 worktree 與子分支（m1-dt、m1-fix、m1-tools-pilot、m1-tools）已清掉
- 代理：
  - 寫程式 S（M2 試驗）：完成。arm runner 單一 job 約 36 分鐘原生編完核心＋全部樹外模組（nvbuild.sh，make -j4），磁碟峰值約 8 GiB、RAM 約 3 GiB；run 43242393210（清理）、43246860803／43254234938（編譯＋傳檔）
  - 寫程式 P（平台介面與開案範本）：完成，CI run 43256946338 綠燈。契約見 `docs/PLATFORM-INTERFACE.md`：`pipeline/platform.sh <validate|fetch|build|assemble|scan|raw-sectors> <專案資料夾> <版本>`，結束碼 OK 0／FAIL 1／GAP 3／NOT_RUN 4／用法 64；project.yml 的 `os_responsibility: ours|customer|upstream-vendor`；sources.yml 是 `releases.<版本>.files[]`（gap、sha1、commit＋repo）；platform.yml 的 `layers`（bsp 套件名稱清單、host-tool 路徑、default os）；`pipeline/lib/project_config.py` 的 `classify_package`／`classify_path`；fetch_verify.py 簽名同 firmware_fetch；scan-flash-package.sh 改成明確 `--platform`、沒給就 GAP。待確認見該文件第 8 節（r39.2.0 public_sources.tbz2 的 sha256 尚未記錄＝gap）
  - 寫程式 L（依層分開）：完成，CI run 43265323496 綠燈。契約 `docs/LAYERS.md`：`pipeline/sbom-layers.py split <sbom> <平台> <專案資料夾> <輸出>` → sbom.bsp（bsp＋unknown）／os／host-tool（不上傳）／product＋layers.json（scan_plan）；cra_report `--os-responsibility`、漏洞列加 layer／layer_todo；P1 判斷表 customer／upstream-vendor 只放 bsp＋unknown、ours 含 os、沒給全部＋GAP；host-tool 不進清單；DT 兩個平行專案 `<名稱>-bsp`／`-os`；SBOM 沒有分層屬性時輸出與原本一致。Jetson fixture：bsp 1537、os 1975、unknown 339、host-tool 0
  - 寫程式 J（Jetson build／assemble／scan、release.yml、dev.yml、patch 版、標準答案測試、接上分層）：`wp1/m2-jetson`；Sonnet 5.5／high；進行中。手動觸發只建 draft Release，測完刪 draft；不建 git tag
- CI：手動觸發（`gh workflow run <wf> --ref <分支>`）
- 下一步：L、J 完成 → 併入 wp1/m2 → 整合分層（J 的 scan 呼叫 L 的拆分工具）→ 兩個版本 release.yml（draft）全程跑通 → 驗證 → PR → 通知 C0（正式 tag 由 C0 問使用者）
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

- 目前在做：**M3 PR #14（wp3/m3 8f02635）：第一次驗證不通過（issuecomment-6832127582，expected_dt 只看 http=400，其他 400 也會被放行）→ 8f02635 已修，等複驗**。M3＝（BIOS、vBIOS 各至少一個樣本產出 SBOM 並進 DT）。D-020：做到 M3 才開**一個** PR；過程只推分支，CI 用 `gh workflow run` 手動觸發
- 已合併：PR #7（樣本清單＋下載核對）、PR #8（x86_firmware → CycloneDX）
- **整合分支 `wp3/m3` 061ca75**（含 main cd62514、GOP 走訪、expect 新鍵；c2c5142 的 tests CI 43255179664 紅：新檔沒登記 PROVENANCE → 061ca75 補登，本機 c1-tools 3114 passed；重跑 tests 43258583501、firmware 43258591599）（worktree `$AGENT_TMP/dumpling-wt-c2-m3`），已含：
  - coreboot CBFS（FMAP、LZMA／LZ4、coreboot 版本／config、FSP、VBT、SELF payload）＋預驗修正 0f28182（ReDoS、掃描雜湊放大、解壓失敗計量、FSP ExtendedImageRevision）
  - AMI PFAT 解封裝＋預驗修正（清單數字欄位崩潰、MAX_TOTAL 跨巢狀、檔名截短）；fetch 測試補強、run.d venv 快取、firmware.yml pipefail 修正（綠 run 43229479139／故意 sha256 不符紅 run 43229520867）
  - 真實樣本 CI 驗收 `pipeline/firmware-expect.py`（綠 run 43231626732：Dasharo 11 項 OK、NUC 1 項 OK；改錯 ME 版本紅 run 43231826497）
  - vBIOS：NVIDIA DP 更新工具**沒有完整 vBIOS**（只有 3 組 GPU 家族 GOP 範本，佔位版本字串）；合成獨立 vBIOS（`tools/cra/tests/synthetic_vbios.py`）端到端產 SBOM；Intel legacy VBIOS 辨識（NUC 樣本 `Build Number: 1003 PC 14.34`）；`intel_vbt.py` 共用；`gop_driver()`（GOP 版本只讀得到 build 1070）待接 FV 走訪
  - 本機 c2 測試 279 passed、0 skip；Dasharo 16 個元件不變。CI：8688cd4 的 tests 43232541990／firmware 43232547319 綠；4183a96 的 tests 43233831760、firmware 43233837796 已觸發
  - 供應商 SBOM 品質檢查（a2ed40f，已併入）：3mdeb Dasharo SBOM 範例 → ATTENTION（10 元件、1 缺版本、5 缺 cpe、sbomqs v2.1.3 分數 4.3 僅供參考）；sbomqs 版本與 sha256 固定在 `pipeline/lib/tools.lock`。CI：firmware 43234922758、tests 43234916860 綠
  - 韌體 SBOM → DT 的準備（4781bc5，已併入）：`pipeline/lib/firmware_dt.py` prep／expected／report。專案名稱 `firmware-<kind>[-synthetic]-<slug>`、SBOM 正規化（metadata.component、bom-ref／dependencies 檢查）、expected 兩種（C1 dt-verify 格式＋介面無關的）；report 漏洞欄以 Grype（sca-scan C-grype）為主、DT 只收件留存。暫存試接 C1 pilot 分支：sca-scan A／B／C 階段 OK、C-sbomgate NOT_ASSESSED（firmware 不算套件，預期）、dt-verify 吃得懂 expected。workflow job 只有草稿（`docs/notes/c2-firmware-dt.md`），等 M1
- M3 剩下要做的（M1 已合併 main 0e706cb；代理 J、K 改用 main 上的正式檔）：
  - BIOS 成品端 UEFI FV 解開：用 `tools/cra/uefi_image.py`（D-016）→ 接 Intel GOP（`gop_driver()`）／AMI 映像裡的 VBT／legacy VBIOS
  - NVIDIA gpu-firmware 公告比對：用 C1 的 `tools/pilot/lib/nvidia_bulletins.py`，沒對到標 NOT_ASSESSED
  - 上傳臨時 DT＋Grype（BIOS SBOM、vBIOS SBOM、供應商 SBOM）
- 代理：
  - 代理 G（寫程式，Sonnet 5.5 medium）：`wp3/supplier-sbom`，狀態：完成
  - 代理 H（寫程式，Sonnet 5.5 medium）：`wp3/firmware-dt`，狀態：完成
  - 預驗 `wp3/m3` 4183a96（完成，不通過）：cbfs／pfat 的修正複驗都過；必修 1：我上一輪加的 FSP ExtendedImageRevision 讀錯偏移（+0x44 是 SiliconInit 入口，應為 +0x4C、header ≥ 0x50），Dasharo FSP-S 多出假 note；中等 1：Intel VBIOS 橫幅 regex 128 倍放大。**已在 7e40fe7 修好**（依 coreboot info_header.h 逐欄核對；橫幅改線性搜尋；PROVENANCE 措辭）
  - 預驗 `wp3/m3` 7e40fe7（完成，**通過**）：FSP 偏移（依 info_header.h 逐欄核對、Dasharo 與 4183a96 diff 只少了假 property）、find_banner（20 萬組隨機對照舊 regex 0 不一致、16 MiB 構造 <0.07 秒）、供應商 SBOM（sbomqs sha256 與 release 一致、sha 改錯不解開、不連外）。建議 B1～B8（Markdown 注入、巢狀過深靜默截斷、佔位值、記憶體放大等）交代理 I
  - 代理 I（寫程式，Sonnet 5.5 high）：`wp3/sbom-check-hardening` 7b67b1b，狀態：完成（已快轉併入 m3）。Markdown 注入共用 `md_safe`、巢狀過深 ATTENTION、佔位值當缺、上限 16 MiB＋物件數估計、O_NOFOLLOW、sbomqs 版本對 tools.lock、無樣本 NOT_RUN、用法錯誤 64。CI tests 43239787867（c2-firmware 143、c2-x86-firmware 283，0 skip）、firmware 43239795302 綠
  - 代理 J（寫程式，Sonnet 5.5 medium）：`wp3/m3-dt` 0f18fc7，狀態：完成（已併入 m3）。firmware-dt job＋`pipeline/firmware-dt.sh`；Actions run 43266687645 綠（約 18 分鐘，wait 257 秒）：Protectli 16→DT 14、NUC 8→6、OVMF 1、合成 vBIOS 1 皆 ATTENTION；供應商 SBOM DT 拒收（http=400，schema 不符）→ `expected_dt: {upload: rejected}` 宣告，只放行這一種，上傳成功反而 MISMATCH；sbom-check 加「DT 可能拒收」提示；NVIDIA gpu-firmware 沒有表時 GAP
  - 代理 K（寫程式，Sonnet 5.5 high）：`wp3/m3-gop` 24d3eb5，狀態：完成（已併入 m3）。`tools/cra/uefi_gfx.py`（uefi_image.Scan 子類別）＋契約測試 `test_uefi_image_contract.py`。NUC：GOP build 1070（FFS A0327FE0-…）、legacy VBIOS 1003 PC 14.34、獨立 VBT 3 份（$VBT TIGERLAKE、BDB 2.43），掛在 BIOS 映像下；走訪不完整（EFI 標準壓縮解不開 30 處）→ gap、ATTENTION。Dasharo、OVMF 無誤判
  - 代理 L（寫程式，Sonnet 5.5 medium）：`wp3/m3-expect` bb59fb2，狀態：完成（已併入 m3）。firmware-expect 新鍵 `intel_gop`、`intel_legacy_vbios`；NUC expected 加 GOP 1070（release notes 佐證 17.0.1070）；legacy VBIOS 1003 PC 14.34 release notes 沒有佐證，只寫註解；VBT 版本是表頭格式版本，不比對。三樣本 Dasharo 11 OK、NUC 2 OK；故意改錯 → MISMATCH
  - 已完成：代理 A～F；預驗 cbfs（不通過→已修）、預驗 pfat（不通過→已修）
- 下一步：等 PR #14 複驗（只看 expected_dt 放行條件）；通過後 C0 合併。之後：(1) 供應商 SBOM 上傳前最小正規化（頂層多出的欄位→metadata.properties、只有 url 的 license→元件 properties，不刪不猜；記錄每筆搬移與原檔 sha256；用 CycloneDX 1.4 官方 schema 驗證；做完拿掉 expected_dt）；(2) M2 合併後 firmware_fetch.py 改 import fetch_verify.py。C0 同意正規化方案，(1)(2) 在 M3 合併後合成一個 PR。C0 同意 expected_dt（條件：只放行拒收、狀態不可變 OK、PR 已知限制寫明供應商 SBOM 尚未進 DT——已補）
- 之後（M3 以外）：C1 M2 合併後，把 `pipeline/lib/firmware_fetch.py` 改成 import 共用的 `pipeline/lib/fetch_verify.py`（C0 會通知）；D-028 之後二進位測資要登記在 `ci/public-binary-allow.txt`（wp3/m3 目前沒有二進位檔，合成 ROM 都在測試裡當場產生）
- 等 C1 M2：gpu-firmware 空對照表 `tools/pilot/lib/nvidia-bulletins-gpu-firmware.json`（wp1/m2 fdabd22）。M2 前 CI 印 GAP（沒有表、不跑 candidates，不借 Jetson 表）；M2 後自動用它 → ATTENTION（公告全列待審）。不擋 M3
- 卡住／等決定：無。代理暫存資料夾 `$AGENT_TMP/dumpling-tmp-c2-cbfs`、`-pfat`、`-verify-cbfs`、`-verify-m3b`、`-supsbom`、`-sbomfix`（約 22 MB）等被安全檢查擋下沒刪，要使用者手動刪
<!-- END C2 -->

<!-- BEGIN C3 -->
## C3 監控＋GitLab（WP2＋WP5）

- 目前在做：尚未開始（開始條件：C1 的 M2）
- 分支／PR／commit：—
- 代理：無
- CI：無
- 下一步：等 M2
- 卡住／等決定：無
<!-- END C3 -->

<!-- BEGIN C4 -->
## C4 其他平台（WP7）

- 目前在做：WP7 第一階段完成；CRA 開源調查完成；M1 已 merge 進 `wp7/platform-samples`（只在自己的 worktree），已讀 tools/ 與 pipeline/ 結構。等 C1 的 M2
- 分支／PR／commit：`wp7/platform-samples`（最後 commit 868f064）、`wp7/cra-survey`（最後 commit 0ac8e30），兩支都已 merge main cd62514（D-028 反向規則下 public-check 通過；兩支都沒有二進位檔）；PR 都尚未開（D-020）
- 代理：無執行中（先前研究代理 1 個已完成）
- CI：無；本機背景工作：無
- 已完成：`docs/platforms-research.md`；`platform-samples/` 四份清單（Raspberry Pi、Radxa ROCK 5B、Debian 13＋OMV、TrueNAS 只研究）；`docs/references/cra-github-survey.md`
- 發現：`tools/demo/scan-flash-package.sh` 對所有磁碟映像（raw-disk-img*）都套 `--platform raspberrypi` → Rockchip GPT 映像會被誤分類；M2 平台介面要明確傳平台（已寫進研究文件；C0 已轉給 C1，P 軌處理：平台由 project.yml 給定，沒給標 GAP）
- 下一步：M2 後寫 Raspberry Pi、Rockchip、AI NAS 轉接器與示範專案；samples.yml 搬到 projects/<專案>/sources.yml
- 卡住／等決定：無。等 C1 的 M2 P 軌（平台介面、開案範本）完成後開始寫轉接器；rpi_img.py 讀 Radxa 分割區屆時實測
<!-- END C4 -->
