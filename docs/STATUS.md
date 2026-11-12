# STATUS

每個對話一節，**每做完一步就更新並推送**（`ci/status-update.sh`，見 main 的 `docs/HANDOFF.md`）。只改自己那節，`<!-- BEGIN/END -->` 標記不要動。

最後更新：2026-11-12 09:08 -0500（C2）

<!-- BEGIN C0 -->
## C0 協調（WP0）

- 目前在做：看 PR、合併、驗收，回覆 C1–C4
- 分支／PR／commit：main d342a87（#12 白名單 D-022、#11 文件批次 D-019～D-021、C2 的 #7、#8 已合併）；沒有未推送的累積改動
- 代理：
  - 預審代理（Sonnet 5.5）：預審 wp1/m1-tools f9d0cee，狀態：完成（#9 留言：有必須修的項目——測試檔語法錯誤、scripts→tools 路徑沒改完、一處版本被改、5 處疑似內部實測資訊、缺少被引用的檔），已轉給 C1
- 代理總數（全部對話）：C1 寫程式 2＋驗證 1、C2 寫程式 2＋驗證 1，約 6／上限 8；C0 目前沒有代理在跑
- CI：無進行中
- 下一步：等 C1 修完 pilot／demo 的 37 個失敗 → M1 正式 PR（d1fd77b 起；cra 1734 passed；含 public-check 掃壓縮檔的擴充）→ C0 派獨立驗證代理 → 合併；C2 做到 M3
- 設定：main 分支保護不再要求分支最新（D-021，使用者同意）；auto-merge 因帳號沒有驗證過的信箱而無法使用，改由 C0 背景等 CI 後合併
- 給 C3 的交接：M1 沒帶 `alert_mail.py`（每日監控寄信），exploited_* 測試約 29 個寄信相關的已刪；watch.yml 要寄信時由 C3 帶回
- 卡住／等決定：使用者（1）「形狀參考內部觀察、數字合成」的測試資料能不能收；（2）C1／C2 是否搬到 WSL、sca-center 能否放到那台
<!-- END C0 -->

<!-- BEGIN C1 -->
## C1 流程核心（WP1＋WP6）

- 目前在做：M1（PLAN「里程碑」M1）——工具複製＋PROVENANCE、臨時 DT＋上傳測試 SBOM；D-020：M1 完成後一個 PR（#9 轉正式）
- 分支／PR／commit：
  - `wp1/m1-tools`：fb44881（C1 加：`ci/public-check.sh` 掃壓縮檔內容＋`tests/run.d/c1-public-check.sh`（C0 同意在 M1 改 ci/）；tools/ 全部清理完、PROVENANCE C1 節、白名單 18 項、provenance-check、c1-tools.sh（py3.12）；已併 m1-dt；C1 另清 Jetson fixture 與 test_cra_report 的自架 runner 路徑）；PR #9（draft）
  - `wp1/m1-tools-pilot`：從 bd7fa1b 開，pilot／demo／mirror／wizard／e2e 的收尾，做完由 C1 merge 回 `wp1/m1-tools`
  - `wp1/m1-dt`：62107c1（臨時 DT，已併入 m1-tools；PR #6 已關）
  - 來源：sca-center 25fa89a
- 代理：
  - 寫程式 A：`wp1/m1-tools`（cra／vexconv／sbomgate）；完成：1734 passed／0 failed（py3.12）。完整 c1-tools 還有 37 個失敗，全在 pilot／demo，交給 P
  - 寫程式 P：`wp1/m1-tools-pilot`，tools/pilot、demo、mirror、wizard、e2e；修失敗測試、資料來源審查（內部資料產生的剔除）、sca-scan 缺 scio_prep 時 NOT_RUN、wizard 改用目前 HEAD 取工具、dt-smoke 用 `sca-scan --sbom` 上傳；Sonnet 5.5／high；進行中
  - 驗證 V1：`wp1/m1-dt`（62107c1）臨時 DT 部分；完成，**不通過**（PR #9 留言 issuecomment-6825077261）：dt-smoke.yml 的 `| tee` 沒有 pipefail，會吃掉 wait／sca-scan 的結束碼。已交給 P 修（加 `shell: bash`，並實證失敗會紅），另附 6 項建議（admin 密碼不放命令列、生態系不內插、down 的 rm 防護、讀回確認 NVD 關閉、409 舊結果、wait 措辭）；修完再驗
  - 寫程式 B（臨時 DT）：完成
  - C0 預審（f9d0cee）完成，#9 issuecomment-6825088823：已對照 bd7fa1b 分派——A：libnvinfer 版本誤改、cra_report 內部實測說法、信箱改保留網域、內部稱呼、c1-tools.sh／tests.yml 改用 Python 3.12；P：殘留 scripts/ 路徑、l4t-kernel-map 等內部實測說法、帶入 kernel_included_c.py、缺檔改 NOT_RUN、拿掉 android
- CI：tests.yml 在 wp1/m1-tools 手動觸發中（預期 unit-tests 仍因 pilot 37 個失敗 FAIL）；手動觸發（`gh workflow run <wf> --ref <分支>`）；最近 dt-smoke（m1-dt）run 43225729729 綠燈
- 下一步：A、P 完成 → merge `wp1/m1-tools-pilot` 進 `wp1/m1-tools`、整合 PROVENANCE → tests＋dt-smoke 在 m1-tools 綠燈 → 驗證整個 M1 → #9 轉正式 PR（附逐檔對照、資料來源表）→ 通知 C0
- 卡住／等決定：
  - V1 的問題修完需要重驗 DT 部分
  - 已告知 C0：alert_mail.py 沒帶（PROVENANCE 已標「C3 視需要帶回」）；3 項「參考內部觀察的合成測試」C0 拿去問使用者；在那之前照 C1 判斷先做（kernel/Image 依據改用公開 BSP）
  - M1 合併前本機 hook 不掃壓縮檔：改了 *.xz 等要手動跑新版 public-check
<!-- END C1 -->

<!-- BEGIN C2 -->
## C2 韌體（WP3＋WP4）

- 目前在做：M3（BIOS、vBIOS 各至少一個樣本產出 SBOM 並進 DT）。D-020：做到 M3 才開**一個** PR；過程只推分支，CI 用 `gh workflow run` 手動觸發
- 已合併：PR #7（樣本清單＋下載核對）、PR #8（x86_firmware → CycloneDX）
- **整合分支 `wp3/m3` 4183a96**（worktree `$AGENT_TMP/dumpling-wt-c2-m3`），已含：
  - coreboot CBFS（FMAP、LZMA／LZ4、coreboot 版本／config、FSP、VBT、SELF payload）＋預驗修正 0f28182（ReDoS、掃描雜湊放大、解壓失敗計量、FSP ExtendedImageRevision）
  - AMI PFAT 解封裝＋預驗修正（清單數字欄位崩潰、MAX_TOTAL 跨巢狀、檔名截短）；fetch 測試補強、run.d venv 快取、firmware.yml pipefail 修正（綠 run 43229479139／故意 sha256 不符紅 run 43229520867）
  - 真實樣本 CI 驗收 `pipeline/firmware-expect.py`（綠 run 43231626732：Dasharo 11 項 OK、NUC 1 項 OK；改錯 ME 版本紅 run 43231826497）
  - vBIOS：NVIDIA DP 更新工具**沒有完整 vBIOS**（只有 3 組 GPU 家族 GOP 範本，佔位版本字串）；合成獨立 vBIOS（`tools/cra/tests/synthetic_vbios.py`）端到端產 SBOM；Intel legacy VBIOS 辨識（NUC 樣本 `Build Number: 1003 PC 14.34`）；`intel_vbt.py` 共用；`gop_driver()`（GOP 版本只讀得到 build 1070）待接 FV 走訪
  - 本機 c2 測試 279 passed、0 skip；Dasharo 16 個元件不變。CI：8688cd4 的 tests 43232541990／firmware 43232547319 綠；4183a96 的 tests 43233831760、firmware 43233837796 已觸發
- 進行中的分支：`wp3/supplier-sbom`（從 m3 開出，worktree `$AGENT_TMP/dumpling-wt-c2-supsbom`）：供應商 SBOM 品質檢查（3mdeb Dasharo SBOM 範例、固定版本 sbomqs、`pipeline/firmware-sbom-check.sh`）
- M3 剩下要做的（等 C1 M1，PR #9 仍是 draft）：
  - BIOS 成品端 UEFI FV 解開：用 `tools/cra/uefi_image.py`（D-016）→ 接 Intel GOP（`gop_driver()`）／AMI 映像裡的 VBT／legacy VBIOS
  - NVIDIA gpu-firmware 公告比對：用 C1 的 `tools/pilot/lib/nvidia_bulletins.py`，沒對到標 NOT_ASSESSED
  - 上傳臨時 DT＋Grype（BIOS SBOM、vBIOS SBOM、供應商 SBOM）
- 代理：
  - 代理 G（寫程式，Sonnet 5.5 medium）：`wp3/supplier-sbom`，狀態：進行中
  - 預驗代理（驗證，Sonnet 5.5 high）：`wp3/m3` 4183a96（複驗兩個修正＋vBIOS 部分），狀態：進行中
  - 已完成：代理 A～F；預驗 cbfs（不通過→已修）、預驗 pfat（不通過→已修）
- 下一步：預驗 m3 結果 → 有問題就修；代理 G 完成併入 m3；C1 M1 合併後做 UEFI／GOP／公告比對／DT 上傳；M3 開 PR、驗證、通知 C0
- 卡住／等決定：UEFI 解開、GOP、公告比對、DT 上傳等 C1 M1。代理暫存資料夾 `$AGENT_TMP/dumpling-tmp-c2-cbfs`、`dumpling-tmp-c2-pfat`、`dumpling-tmp-c2-verify-cbfs` 被安全檢查擋下沒刪，要使用者手動刪
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

- 目前在做：尚未開始（開始條件：C1 的 M2，平台介面與開案範本完成）
- 分支／PR／commit：—
- 代理：無
- CI：無
- 下一步：等 M2
- 卡住／等決定：無
<!-- END C4 -->
