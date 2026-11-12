# STATUS

每個對話一節，**每做完一步就更新並推送**（`ci/status-update.sh`，見 main 的 `docs/HANDOFF.md`）。只改自己那節，`<!-- BEGIN/END -->` 標記不要動。

最後更新：2026-11-12 08:13 -0500（C2）

<!-- BEGIN C0 -->
## C0 協調（WP0）

- 目前在做：看 PR、合併、驗收，回覆 C1–C4
- 分支／PR／commit：main 631646e（WP0 的 PR #1–#5、#10 已合併；#10＝D-018 本機路徑規則不誤擋 drivers/media/）；status 分支
- 代理：
  - 驗證代理（Sonnet 5.5）：驗 C2 的 PR #8（wp3/bios-sbom），結論貼在 PR 留言，狀態：進行中
- 代理總數（全部對話）：C1 寫程式 2、C2 寫程式 2＋驗證 1、C0 驗證 1，約 6／上限 8；負載 1.4
- CI：無進行中
- 下一步：PR #8 驗證通過 → update-branch → 合併 → 通知 C1 merge main（M1 需要 D-017 共用檔）；之後 C2 的 PR #7、C1 的 M1（draft #6、#9 → 正式 PR）
- 做法（使用者 11-12）：C0 自己的文件改動累積成批再開 PR，決定先用訊息生效
- 卡住／等決定：無
<!-- END C0 -->

<!-- BEGIN C1 -->
## C1 流程核心（WP1＋WP6）

- 目前在做：M1（PLAN「里程碑」M1、「可以沿用的東西」）——工具複製＋PROVENANCE、臨時 DT＋上傳測試 SBOM；依 D-014 合成一個 PR
- 分支／PR／commit：
  - `wp1/m1-tools`（工具複製＋PROVENANCE＋tests/run.d/c1-tools.sh；最後要合併的 PR）——draft PR #9，WIP 3121fd8
  - `wp1/m1-dt`（臨時 DT＋測試 SBOM＋dt-smoke workflow；只用 draft PR 跑 CI，最後併進 `wp1/m1-tools`，#6 之後關掉不合併）——draft PR #6，f88ebd6；dt-smoke 綠燈（run 43223829151，約 6 分鐘，OSV／CISA／ENISA 鏡像 318 秒；測試 SBOM 元件 3、漏洞 83）
  - 來源：sca-center `origin/main` 25fa89a
- 代理：
  - 寫程式 A：工具清理複製進 `tools/`＋`docs/PROVENANCE.md`＋單元測試，分支 `wp1/m1-tools`，Sonnet 5.5／high，進行中
  - 寫程式 B：`pipeline/dt-ephemeral.sh`＋`pipeline/dt-compose.yaml`＋`tests/fixtures/sbom/`＋`.github/workflows/dt-smoke.yml`，分支 `wp1/m1-dt`，Sonnet 5.5／medium，完成（尚未整合 tools/，`sca-scan --sbom` 待整合後實跑）
  - 驗證：尚未開（兩個寫程式代理完成、合併分支後開）
- CI：#6、#9 的 tests／dt-smoke（`gh pr checks 6`、`gh pr checks 9`）
- 下一步：等 A 完成 → 把 `wp1/m1-dt` 併進 `wp1/m1-tools`（同時調整：ENISA 鏡像未完成改報 GAP 不判失敗；deb 漏洞設保守下限 ≥1）→ 實跑 `sca-scan --sbom` → 開驗證代理 → 交 C0 合併 → M1 完成通知 C0（C2 的上傳 DT 等這個）
- 卡住／等決定：
  - 等 C2 的 PR 2a（`wp3/bios-sbom`）合併：M1 的 cra 測試要用它的 `cdx_schema.py`、CycloneDX schema、`conftest.py`（D-017，C0 決定先合併 2a；2a＝PR #8，C0 驗證中，合併後 A merge main）
  - （已解決）`/media/` 規則誤擋 `drivers/media/`：C0 已修（D-018，main 631646e），A merge main 後補推 `kernel-included-c-6.{1,8}.json`
<!-- END C1 -->

<!-- BEGIN C2 -->
## C2 韌體（WP3＋WP4）

- 目前在做：B 段。PR #7、#8 等合併；PR 2c（coreboot CBFS／FSP／VBT）由代理 C 在做
- 分支／PR／commit：
  - `wp3/firmware-samples`：PR #7（CI 三項綠燈，最後 commit 052039b；驗證：通過，等 C0 合併）
  - `wp3/bios-sbom`：PR #8（正式 PR，CI 兩項綠燈，最後 commit 5271d2c；本機 Dasharo 真實樣本 ME 14.0.47.1558、微碼 3 份 0xF8 符合驗收值）
  - `wp3/coreboot-cbfs`（PR 2c，從 `wp3/bios-sbom` 開出，#8 合併後 merge main；worktree `$AGENT_TMP/dumpling-wt-c2-cbfs`）
- 預定 PR（D-014，一個可測的功能一個 PR）：
  1. `wp3/firmware-samples`：樣本清單＋下載並核對 sha256（`pipeline/firmware-fetch.sh`、`tests/run.d/c2-firmware.sh`、`firmware.yml` workflow）
  2a. `wp3/bios-sbom`：複製 x86_firmware.py（D-015）→ `tools/cra/`；Intel ME／微碼、vBIOS 標 NOT_ASSESSED、讀不到版本標 GAP、確定的才填 CPE；`pipeline/firmware-bios.sh`；`tests/run.d/c2-x86-firmware.sh`
  2c. `wp3/coreboot-cbfs`：CBFS（FMAP、LZMA／LZ4）、coreboot 版本／config、FSP、VBT、SELF payload 身分 → SBOM 元件
  2b. BIOS 成品端 UEFI 解開（D-016：等 C1 M1 合併後用 `tools/cra/uefi_image.py`，不正式化 fv_walk.py）
  3. `wp4/vbios`：獨立 vBIOS＋BIOS 內 Intel GOP／VBT／legacy VBIOS，公告比對 NOT_ASSESSED
  4. `wp3/firmware-dt`：firmware workflow 上傳臨時 DT＋Grype、供應商 SBOM 匯入（等 C1 M1）
- 代理：
  - 代理 A（寫程式，Sonnet 5.5 medium）：PR 1，分支 `wp3/firmware-samples`，狀態：完成
  - 驗證代理（Sonnet 5.5 medium）：驗證 PR #7，狀態：完成（通過；4 條建議另開 PR 處理）
  - 代理 B（寫程式，Sonnet 5.5 high）：PR 2a，分支 `wp3/bios-sbom`，狀態：完成
  - 代理 C（寫程式，Sonnet 5.5 high）：PR 2c，分支 `wp3/coreboot-cbfs`，狀態：進行中
  - PR #8 的驗證：由 C0 派的驗證代理在做（C2 不重複派）
- CI：PR #8 綠燈（unit-tests 126 passed、0 skip）；PR #7 綠燈（firmware-fetch run 43223968481 真的下載 5 個樣本並核對 sha256）
- 下一步：等 PR #7、#8 合併（C0 會 update-branch）；接著做 PR 1 驗證的建議（補 fetch 測試案例）＋真實樣本的 CI 驗收（Dasharo 解析結果對 firmware.yml expected），以及 PR 3 vBIOS／GOP／VBT 的前置研究（NUC CAP 是 AMI PFAT）
- 卡住／等決定：PR 2b 等 C1 M1（uefi_image.py，D-016）；其他無
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
