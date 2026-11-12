# STATUS

每個對話一節，**每做完一步就更新並推送**（`ci/status-update.sh`，見 main 的 `docs/HANDOFF.md`）。只改自己那節，`<!-- BEGIN/END -->` 標記不要動。

最後更新：2026-11-12 15:01 -0500（C0）

<!-- BEGIN C0 -->
## C0 協調（WP0）

- 目前在做：看 PR、合併、驗收，回覆 C1–C4
- 分支／PR／commit：main b6d341a。**M1（#9）、M3（#14）已合併**；文件批次 #13 已合併；本機累積分支 `wp0/docs-batch-3`（D-029、D-030），還沒推，C3 開工前合併
- 代理：PR #14 驗證代理已完成（第一輪不通過：expected_dt 只看 http=400；C2 修正 8f02635 由 C0 複驗通過）；目前沒有 C0 代理在跑
- 各對話：C1 做 M2（wp1/m2：P 平台介面＋開案範本、L 依層分開已完成、J Jetson 編譯＋掃描＋release 進行中）；C2：wp3/supplier-normalize（dd54722）正規化已完成、CI 綠，另修 report 假 OK 路徑；等 M2 合併後加 fetch_verify 再開 PR；C4（WSL）等 M2 的 P 軌
- CI：無進行中（C0）
- 下一步：等 C1 的 M2 PR → 驗證 → 合併 → 問使用者何時打第一個正式 tag；M2 合併後開 C3（建議 WSL 那台）、C4 開始寫轉接器
- 給 C3 的交接：(1) M1 沒帶 `alert_mail.py`（寄信），exploited_* 寄信測試約 29 個已刪，要寄信時由 C3 帶回；(2) GitLab 階段「已被利用」的真實案件一定要用私有 Issue；(3) 每日監控讀 Release 附件 `sbom-<專案>-<版本>.cdx.json`＋`release-meta.json`，開發版讀滾動 pre-release `dev/<專案>`（D-029）；watch 自己的狀態檔（防 60 天停用）由 C3 設計；(4) GITLAB-PORT 待辦：DT parent／child 專案在常駐 DT 再評估（D-030）
- 給 PM／法務的待決定：VEX 發行閘門要不要分層（客戶負責 OS 時，OS 層未評估的 KEV 是否擋發行；目前保守：擋）（D-030）
- 卡住／等決定：使用者（1）舊 WIP commit 的低敏感內部資訊：接受或刪 repo 重建（C0 建議接受）；（2）C4 CRA 調查的建議採用範圍（C0 建議 A、B 全採用，C 只做文件骨架標 GAP）
<!-- END C0 -->

<!-- BEGIN C1 -->
## C1 流程核心（WP1＋WP6）

- 目前在做：M2（PLAN「里程碑」M2：打 tag 後 Jetson 版本全程跑通、產出 Release；含 C1 額外的平台介面與開案範本、依層分開）。M1 已合併（main 0e706cb，PR #9）
- 分支／PR／commit：
  - `wp1/m2`：M2 整合分支，54dbf48（main b6d341a（含 C2 M3）＋P 軌＋gpu-firmware 空對照表＋L 軌；併 main 無衝突）
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

- 目前在做：M3 之後的收尾 PR（C0 同意合成一個）：(1) 供應商 SBOM 上傳前最小正規化；(2) C1 M2 合併後，`pipeline/lib/firmware_fetch.py` 改 import 共用的 `pipeline/lib/fetch_verify.py`
- **M3 已完成**：PR #14 合併（main b6d341a）。已合併 PR：#7（樣本清單＋下載核對）、#8（x86_firmware → CycloneDX）、#14（M3）
  - M3 內容：coreboot CBFS、AMI PFAT、UEFI FV 的 Intel GOP／VBT／legacy VBIOS（`tools/cra/uefi_gfx.py`，子類別化 C1 的 `uefi_image.Scan`，契約測試 `test_uefi_image_contract.py`）、expected 驗收（新鍵 `intel_gop`、`intel_legacy_vbios`）、供應商 SBOM 品質檢查、`firmware-dt` job（臨時 DT＋Grype）
  - DT 結果（Actions）：Protectli 16→DT 14、NUC 8→6、OVMF 1、合成 vBIOS 1，都 ATTENTION；供應商 SBOM 被 DT 拒收（schema 不符），以 `expected_dt` 宣告，只放行 DT 的「BOM 不符 schema」400
  - 驗證：第一次不通過（issuecomment-6832127582：只看 http=400 太寬）→ 8f02635 修正（錨定 DT 回應開頭＋6 個反例），C0 複核後合併
- 分支 `wp3/supplier-normalize` dd54722（worktree `$AGENT_TMP/dumpling-wt-c2-norm`，從 main b6d341a）
- 代理：
  - 代理 M（寫程式，Sonnet 5.5 high）：`wp3/supplier-normalize` 84ea369，狀態：完成。`pipeline/lib/firmware_sbom_normalize.py`（1.4～1.6；頂層多出欄位→`dumpling:supplier-extra:*`、只有 url 的 license→`dumpling:supplier-license-url`；normalize.json 記每筆原 JSON Pointer＋值 sha256；上限；先規劃後套用）、CycloneDX 1.4 官方 schema（tag 1.4）、樣本拿掉 expected_dt。本機真 DT：Dasharo NS5x **DT 收下**，10 元件，verify 5 項 OK；原檔 1.4 schema 2 錯→副本 0 錯
  - 我補 38db74c：報告的 OK 太寬（Grype 36 筆、purl 全 pkg:generic、沒有評估標記仍標 OK）→ `attention_reasons()`，三種都 ATTENTION；用真 DT 結果重跑 report 確認。CI tests 43289059136、firmware 43289066571 已觸發
  - 預驗 38db74c（驗證，Sonnet 5.5 high），狀態：完成，**通過**。正規化：2 萬份隨機文件依紀錄還原全部相等；CycloneDX 官方 1.4／1.5／1.6 valid 範例 112 份零改動；schema sha256 重新下載一致；CI tests 43289059136、firmware 43289066571 綠，供應商 SBOM DT 收下（10 元件）、ATTENTION。建議（舊有）：report 仍有假 OK 路徑（DT 漏洞數 -3／null、dt-verify checks NOT_RUN／空、其他 sca-scan 階段 FAIL 不影響狀態、標記／purl 辨識太窄、供應商可自帶 dumpling: 標記、缺 version 不算）、重複鍵靜默、代理字元殘留檔
  - 代理 N（寫程式，Sonnet 5.5 high）：`wp3/supplier-normalize` dd54722，狀態：完成。假 OK 路徑都堵住：比對數只認 int≥0；dt-verify 必要檢查缺／NOT_RUN／未知→GAP；任何 sca-scan 階段 FAIL→FAIL（expected_dt 放行規則不變），其他非 OK 階段→ATTENTION；vuln-assessment 只認 NONE、供應商 SBOM 自帶 dumpling: 標記不採信；purl 格式嚴格；缺 version 列入；型別錯→prep FAIL；重複鍵偵測→ATTENTION＋紀錄；代理字元先序列化再寫檔。CI tests 43294331473、firmware 43294338722 綠，五個真樣本全 ATTENTION（無 OK、無 FAIL）；c2-firmware 235、c2-x86-firmware 325
  - 已完成：代理 A～L；預驗 cbfs、pfat、4183a96（不通過→已修）、7e40fe7（通過）
- 依賴 C1：`uefi_image.py` 的 Scan／scan_bytes／parse_fvs／Stop／MAX_*（C1 已記入對外介面約定）；`dt-verify` 檢查名稱「弱點分析完成」「元件數」；gpu-firmware 空對照表 `tools/pilot/lib/nvidia-bulletins-gpu-firmware.json` 隨 M2 進 main（之前 CI 印 GAP）
- 下一步：等 C1 M2 合併（目前還沒開 PR）→ 加 fetch_verify 改動 → 開一個 PR → 驗證（C0 派）→ C0 合併。現況：沒有任何真樣本能到 OK（韌體 C-sbomgate 一定 NOT_ASSESSED、沒有工具寫 vuln-assessment=NONE、C-mirror-freshness 在 CI NOT_RUN）——保守、符合原則，不放寬
- 卡住／等決定：無。代理暫存資料夾 `$AGENT_TMP/dumpling-tmp-c2-cbfs`、`-pfat`、`-verify-cbfs`、`-verify-m3b`、`-supsbom`、`-sbomfix`、`-c1files`、`-dt`、`-gop`、`-expect` 被安全檢查擋下沒刪，要使用者手動刪
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
