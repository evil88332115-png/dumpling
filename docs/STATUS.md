# STATUS

每個對話一節，**每做完一步就更新並推送**（`ci/status-update.sh`，見 main 的 `docs/HANDOFF.md`）。只改自己那節，`<!-- BEGIN/END -->` 標記不要動。

最後更新：2026-11-12 08:08 -0500（C2）

<!-- BEGIN C0 -->
## C0 協調（WP0）

- 目前在做：WP0 完成；看 PR、合併、驗收，回覆 C1–C4
- 分支／PR／commit：main c7952d7（PR #1 README、#2 D-014、#3 共用骨架＋D-015、#4 D-016、#5 D-017，均已合併）；status 分支
- 已完成（WP0）：公開 repo（Apache-2.0，個人信箱外洩後已刪除重建）、docs（PLAN 公開版、DECISIONS、HANDOFF、STATUS 指標、PROVENANCE 骨架）、`status` 分支、CI tests.yml（public-check、unit-tests→tests/run.sh）、pre-push hook、main／status 分支保護、Actions 權限唯讀、fork PR 需核准
- 代理：無（C0）
- 代理總數（全部對話）：C1 寫程式 2、C2 寫程式 2，共 4／上限 8；主機負載 1.6
- CI：無進行中
- 下一步：等 C1 的 M1 PR（wp1/m1-tools，含 uefi_image.py）、C2 的 PR 1（wp3/firmware-samples）、PR 2a（wp3/bios-sbom）。各工作包自己的驗證代理留言後，C0 看 diff 與 CI；里程碑 PR（M1 起）C0 另派一個獨立驗證代理。合併用 `gh pr merge --squash --author-email <noreply>`
- 卡住／等決定：無
<!-- END C0 -->

<!-- BEGIN C1 -->
## C1 流程核心（WP1＋WP6）

- 目前在做：M1（PLAN「里程碑」M1、「可以沿用的東西」）——工具複製＋PROVENANCE、臨時 DT＋上傳測試 SBOM；依 D-014 合成一個 PR
- 分支／PR／commit：
  - `wp1/m1-tools`（工具複製＋PROVENANCE＋tests/run.sh；最後要開的 PR）——尚未推送
  - `wp1/m1-dt`（臨時 DT＋測試 SBOM＋dt-smoke workflow；只用 draft PR 跑 CI，最後併進 `wp1/m1-tools`）——尚未推送
  - 來源：sca-center `origin/main` 25fa89a
- 代理：
  - 寫程式 A：工具清理複製進 `tools/`＋`docs/PROVENANCE.md`＋單元測試，分支 `wp1/m1-tools`，Sonnet 5.5／high，進行中
  - 寫程式 B：`pipeline/dt-ephemeral.sh`＋`pipeline/dt-compose.yaml`＋`tests/fixtures/sbom/`＋`.github/workflows/dt-smoke.yml`，分支 `wp1/m1-dt`，Sonnet 5.5／medium，進行中
  - 驗證：尚未開（兩個寫程式代理完成、合併分支後開）
- CI：無（等代理開 draft PR）
- 下一步：等 A、B 推送 → 把 `wp1/m1-dt` 併進 `wp1/m1-tools` → 開驗證代理 → 交 C0 合併 → M1 完成通知 C0（C2 的上傳 DT 等這個）
- 卡住／等決定：無
<!-- END C1 -->

<!-- BEGIN C2 -->
## C2 韌體（WP3＋WP4）

- 目前在做：B 段。PR 1（公開樣本＋下載核對）與 PR 2a（x86_firmware 解析→CycloneDX）同時進行，各一個寫程式代理
- 分支／PR／commit：
  - `wp3/firmware-samples`：PR #7（ready，CI 三項綠燈，最後 commit 052039b）
  - `wp3/bios-sbom`（PR 2a，從 main 3f1c260 開出；worktree `$AGENT_TMP/dumpling-wt-c2-bios-sbom`）
- 預定 PR（D-014，一個可測的功能一個 PR）：
  1. `wp3/firmware-samples`：樣本清單＋下載並核對 sha256（`pipeline/firmware-fetch.sh`、`tests/run.d/c2-firmware.sh`、`firmware.yml` workflow）
  2a. `wp3/bios-sbom`：複製 x86_firmware.py（D-015）→ `tools/cra/`；Intel ME／微碼、vBIOS 標 NOT_ASSESSED、讀不到版本標 GAP、確定的才填 CPE；`pipeline/firmware-bios.sh`；`tests/run.d/c2-x86-firmware.sh`
  2b. BIOS 成品端 UEFI 解開（D-016：等 C1 M1 合併後用 `tools/cra/uefi_image.py`，不正式化 fv_walk.py）＋CBFS／FSP（BIOS 試掃原型）
  3. `wp4/vbios`：獨立 vBIOS＋BIOS 內 Intel GOP／VBT／legacy VBIOS，公告比對 NOT_ASSESSED
  4. `wp3/firmware-dt`：firmware workflow 上傳臨時 DT＋Grype、供應商 SBOM 匯入（等 C1 M1）
- 代理：
  - 代理 A（寫程式，Sonnet 5.5 medium）：PR 1，分支 `wp3/firmware-samples`，狀態：完成
  - 驗證代理（Sonnet 5.5 medium）：驗證 PR #7，狀態：進行中
  - 代理 B（寫程式，Sonnet 5.5 high）：PR 2a，分支 `wp3/bios-sbom`，狀態：進行中
- CI：PR #7 綠燈（firmware-fetch run 43223968481 真的下載 5 個樣本並核對 sha256）
- 下一步：PR 2a 開成正式 PR、綠燈後優先驗證並通知 C0（D-017，C1 M1 等它）；PR #7 驗證通過後通知 C0。PR #7 發現 NUC CAP 是 AMI PFAT 封裝、NVIDIA 更新工具裡的 PCIR 不完整，PR 3 要處理
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
