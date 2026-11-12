# STATUS

每個對話一節，**每做完一步就更新並推送**（`ci/status-update.sh`，見 main 的 `docs/HANDOFF.md`）。只改自己那節，`<!-- BEGIN/END -->` 標記不要動。

最後更新：2026-11-12 07:55 -0500（C1）

<!-- BEGIN C0 -->
## C0 協調（WP0）

- 目前在做：WP0 完成；接下來看 PR、合併、驗收，回覆 C1–C4
- 分支／PR／commit：main 3f1c260（PR #1 README、#2 D-014、#3 共用骨架＋D-015，均已合併）；status 分支
- 已完成（WP0）：公開 repo（Apache-2.0，個人信箱外洩後已刪除重建）、docs（PLAN 公開版、DECISIONS D-001～D-013、HANDOFF、STATUS 指標）、`status` 分支、CI tests.yml（public-check、unit-tests，main 綠燈）、pre-push hook（本機禁用字）、main／status 分支保護、Actions 權限唯讀、fork PR 需核准
- 代理：無
- CI：無進行中
- 下一步：C2 已報到（wp3/firmware-samples），已回覆 D-015 分工；等 C2 PR 1（樣本清單）送驗證；dumpling-c9 等使用者指派角色（預計 C1）。C1–C4 的 PR 由 C0 派獨立驗證代理驗證後合併（`gh pr merge --squash --author-email <noreply>`）
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

- 目前在做：B 段「公開樣本」——挑 BIOS／vBIOS 公開樣本（網址＋sha256＋授權），寫 `firmware/*/firmware.yml` 與下載核對腳本（PR 1／4）
- 分支／PR／commit：`wp3/firmware-samples`（剛從 main f39fbfe 開出，尚無 commit、尚無 PR）
- 預定 PR（D-014，一個可測的功能一個 PR）：
  1. `wp3/firmware-samples`：樣本清單＋下載並核對 sha256（`pipeline/firmware-fetch.sh`）
  2. `wp3/bios-sbom`：BIOS 解析→CycloneDX（x86_firmware.py 複製＋LZMA FV、CBFS、FSP、purl／CPE、Intel 部分 NOT_ASSESSED）
  3. `wp4/vbios`：獨立 vBIOS＋BIOS 內 Intel GOP／VBT／legacy VBIOS，公告比對 NOT_ASSESSED
  4. `wp3/firmware-dt`：firmware.yml workflow 上傳臨時 DT＋Grype、供應商 SBOM 匯入（等 C1 M1）
- 代理：
  - 代理 A（寫程式，Sonnet 5.5 medium）：PR 1 樣本清單＋firmware-fetch＋tests/run.sh＋firmware.yml workflow，分支 `wp3/firmware-samples`，狀態：進行中
- CI：無
- 下一步：等代理 A 開 draft PR；同時研究 PR 2（BIOS 解析）的範圍；等 C0 回覆工具複製分工
- 卡住／等決定：工具複製分工（已問 C0）
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
