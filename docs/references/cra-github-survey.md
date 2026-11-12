# CRA 相關開源專案與文件調查（給 dumpling 參考）

查詢日期：2026-11-12。調查者：C4 派出的研究代理（只讀研究）。

## 方法與規則

- 工具：WebSearch、WebFetch、`gh api`／`gh search repos`（只讀）。搜尋字串只用 CRA、SBOM、VEX、CSAF、Dependency-Track 等一般詞彙。
- 沒有 clone、下載執行、安裝任何程式；本檔不複製程式碼或文件內容，只放連結與自己的摘要。
- 授權／star／最後推送日取自 `gh api`（2026-11-12 查）。非 GitHub 的寫「—」。授權欄空白或 NOASSERTION 寫「未確認」。star 數為當日約略值。
- CRA 條文與期限以官方來源為準；二手網站（律所、顧問、獨立指南站）只當線索，標「二手」。
- 已知限制：WebFetch 摘要是小模型轉述，條文細節請回 EUR-Lex 原文核對。

「用處」欄標記：**可直接用**／**參考做法**／**背景知識**，並註明對應工作包（WP）或里程碑（M）。

---

## 一、CRA 合規工具與流程

### 1.1 SBOM 產生與品質檢查

| 名稱／網址 | 授權 | 維護狀況 | 做什麼 | 對 dumpling 的用處 |
|---|---|---|---|---|
| sbomqs — https://github.com/interlynk-io/sbomqs | Apache-2.0 | 約 320 star；2026-11-09 | SBOM 品質評分（0–10）與合規檢查，含 BSI TR-03183-2 設定檔（README 提到 v2.0 與 v2.1 的 hash 欄位）；支援 CycloneDX、SPDX | **可直接用**：WP1／M1 在臨時 DT 上傳前加「SBOM 品質閘門」；WP3 匯入供應商 BIOS SBOM 前檢查（PLAN B 段第二條路已提到）。BSI 設定檔實際涵蓋的版本與欄位，採用前要讀其原始碼／文件確認（未確認） |
| BSI TR-03183-2（SBOM 技術指引）— https://www.bsi.bund.de/dok/TR-03183-en | —（BSI 公開文件） | 目前版本 2.1.0（二手來源說 2025 年 8–9 月，未確認確切日期） | 德國 BSI 對 CRA 用 SBOM 的最低欄位與格式要求：CycloneDX 1.6+ 或 SPDX 3.0.1+；以「出貨項目」為範圍；指引本身不具強制力，也不能單獨宣稱符合 CRA（二手來源） | **參考做法**：WP1 產出的 CycloneDX 欄位對照表（製作者、元件名稱／版本／雜湊、授權、相依關係、可部署雜湊等）；WP3／WP4 韌體 SBOM 也要過同一份檢查。細節請讀 BSI 原始 PDF（本次沒讀） |
| CycloneDX 規格與 property taxonomy — https://github.com/CycloneDX/specification、https://github.com/CycloneDX/cyclonedx-property-taxonomy | Apache-2.0 | 規格約 580 star，2026-11-12；taxonomy 約 28 star，2026-11-09 | CycloneDX 規格；taxonomy 登錄自訂屬性命名空間，BSI 也用它放規格外欄位 | **參考做法**：WP3／WP4 韌體元件（ME、微碼、GOP、VBT、option ROM）要放自訂屬性（層欄位 bsp／os／host-tool、GAP 原因）時，沿用命名空間規範而不是自創 |
| CycloneDX sbom-utility — https://github.com/CycloneDX/sbom-utility | Apache-2.0 | 約 170 star，2026-11-06 | CycloneDX 驗證、查詢、diff、補充資料的 CLI | **可直接用**：WP6 標準答案測試（SBOM 差異、schema 驗證）；與 D-017 的 `cdx_schema.py` 互補 |
| CycloneDX cli — https://github.com/CycloneDX/cyclonedx-cli | Apache-2.0 | 約 560 star，2026-10-19 | CycloneDX 轉換、合併、簽章、驗證 | **參考做法**：WP1 合併 bsp／os 分層 SBOM、格式轉換 |
| cdxgen — https://github.com/cdxgen/cdxgen | Apache-2.0 | 約 1,100 star，2026-11-12（舊位置 CycloneDX/cdxgen 已轉到 cdxgen 組織） | 從原始碼／容器／相依檔產 CycloneDX SBOM（含 VEX 與 CBOM 相關功能） | **可直接用**：WP7 AI NAS 的應用原始碼掃描（PLAN 已有）。注意固定版本與新網址 |
| Syft — https://github.com/anchore/syft；Grype — https://github.com/anchore/grype；sbom-action — https://github.com/anchore/sbom-action；scan-action — https://github.com/anchore/scan-action | Apache-2.0；Apache-2.0；Apache-2.0；MIT | Syft 約 9.9k star（2026-11-09）；Grype 約 13.2k（2026-11-12）；sbom-action 約 265；scan-action 約 290 | PLAN 已採用的 SBOM／漏洞掃描主力與官方 Actions | **可直接用**：WP0／WP1 workflow 可參考官方 Action 的快取 Grype DB 做法；dumpling 已自裝固定版本，Action 只當範本。第三方 Action 一律照 D-012 用 commit SHA 固定 |
| Trivy — https://github.com/aquasecurity/trivy | Apache-2.0 | 約 39k star，2026-11-12 | 容器／檔案系統／IaC 掃描，輸出 SBOM、可吃 VEX | **背景知識**：第二掃描器交叉驗證（降低 Grype 漏報）；非必要 |
| Microsoft sbom-tool — https://github.com/microsoft/sbom-tool | MIT | 約 2.1k star，2026-09-21 | 產 SPDX 2.2 SBOM | **背景知識**：只輸出 SPDX 2.2，達不到 BSI 的 SPDX 3.0.1 要求，不建議 |
| sbomasm — https://github.com/interlynk-io/sbomasm | Apache-2.0 | 約 143 star，2026-11-09 | SBOM 合併、編輯、補欄位（同作者 sbomqs） | **參考做法**：WP1 把 BSP 層與 OS 層、韌體子元件組成「出貨項目 SBOM」 |
| sbomify-action — https://github.com/sbomify/sbomify-action | Apache-2.0 | 約 26 star，2026-11-11 | CI 裡產生／補強 SBOM 並上傳到 sbomify 平台 | **背景知識**：看它如何把 SBOM 補成 CRA 欄位；平台本身不用（sbomify 主專案授權 NOASSERTION，未確認） |

### 1.2 VEX、CSAF、漏洞資料來源

| 名稱／網址 | 授權 | 維護狀況 | 做什麼 | 對 dumpling 的用處 |
|---|---|---|---|---|
| OpenVEX 規格 — https://github.com/openvex/spec；vexctl — https://github.com/openvex/vexctl；go-vex — https://github.com/openvex/go-vex | CC0-1.0；Apache-2.0；Apache-2.0 | 規格約 200 star，2026-10-30；vexctl 約 220，2026-11-09；go-vex 約 73，2026-11-12 | OpenVEX 文件格式與產生／合併／套用工具；狀態 not_affected／affected／fixed／under_investigation | **可直接用**：WP1 的 `vex-rules.json` 輸出 OpenVEX 時對照其狀態與 justification；Grype 可吃 OpenVEX 做抑制（WP1、WP6 標準答案）。注意：OpenVEX 沒有「NOT_ASSESSED」，要用 under_investigation 並在說明寫原因，避免被誤讀為安全 |
| CSAF 2.0／2.1（OASIS）— https://github.com/oasis-tcs/csaf；規格頁 https://docs.oasis-open.org/csaf/ | 規格授權 NOASSERTION（未確認） | 約 230 star，2026-11-09。CSAF 2.0 已是 OASIS Standard，並獲 ISO/IEC 20153 核准（二手：OASIS 2025-05 新聞稿）；2.1 仍是委員會草案（CSD02 為 2026-02-25，另有二手來源稱 CSD03 為 2026-09-11，未確認） | 安全公告機器可讀格式，含 csaf_vex 設定檔 | **背景知識**：WP2 的廠商層級提醒、第 14 條通報附件可考慮輸出 CSAF VEX；目前不建議綁 2.1 草案。EUVD 也以 CSAF 提供資料 |
| gocsaf/csaf — https://github.com/gocsaf/csaf（原 csaf-poc/csaf_distribution） | 未確認 | 約 72 star，2026-11-12 | CSAF provider／aggregator／checker 的 Go 實作 | **參考做法**：WP2／WP5 若要對外公布 CSAF 公告（`.well-known` 目錄結構）才需要；現階段先放備忘 |
| Secvisogram — https://github.com/secvisogram/secvisogram；csaf-validator-lib — https://github.com/secvisogram/csaf-validator-lib | Apache-2.0 | 約 46 與 4 star，2026-11-12 | CSAF 文件編輯器與驗證函式庫 | **背景知識**：WP6 若產 CSAF 輸出，用它驗證 |
| Dependency-Track — https://github.com/DependencyTrack/dependency-track | Apache-2.0 | 約 4.4k star，2026-11-12 | PLAN 採用的 SBOM／漏洞管理平台，API 可上傳 BOM、匯出 VEX | **可直接用**：WP1 臨時 DT。注意：其子專案 Hyades（https://github.com/DependencyTrack/hyades，約 103 star）已封存（2026-05），不要拿來當依據 |
| DependencyTrack/gh-upload-sbom — https://github.com/DependencyTrack/gh-upload-sbom | Apache-2.0 | 約 69 star，2026-11-05 | GitHub Action：把 SBOM 上傳到 DT | **參考做法**：M1 的 SBOM 上傳步驟（dumpling 已有 `sca-scan` 自己上傳，可對照認證／專案建立流程） |
| CISA KEV 資料 — https://github.com/cisagov/kev-data；vulnrichment — https://github.com/cisagov/vulnrichment | kev-data 未確認；vulnrichment CC0-1.0 | 約 141／882 star，2026-11-10／2026-11-12 | KEV 目錄的 git 鏡像；CISA 對 CVE 記錄的補充（SSVC、CWE、CPE） | **可直接用**：WP2 每日監控可直接讀 git 鏡像，比打 API 更穩，也能偵測變更歷史。使用前確認授權（KEV 目錄本身是美國政府公開資料，授權欄為 NOASSERTION，未確認） |
| EUVD（ENISA 歐盟漏洞資料庫）— https://euvd.enisa.europa.eu；API 文件 https://euvd.enisa.europa.eu/apidoc；社群 API 說明 https://github.com/cku-heise/euvd-api-doc | —；社群說明庫授權未確認 | 2025-05 上線（二手）；API 有 lastvulnerabilities、exploitedvulnerabilities、vulnerabilities 等端點（二手） | EU 官方漏洞庫，並同步「EU KEV」已被利用清單；以 CSAF 提供 | **可直接用**：WP2 的 EUVD 監控。二手分析指出 API 回傳筆數少於網站、已利用清單多半是 CISA KEV 的子集，所以 **EUVD 不能取代 KEV**，兩個都要看，且 API 覆蓋缺口要在報告標註（未確認現況） |
| OSV — https://github.com/google/osv.dev、https://github.com/ossf/osv-schema、https://github.com/google/osv-scanner | Apache-2.0 | 約 3.1k／276／11.5k star，皆 2026-11-12 | OSV 資料庫、schema、掃描器 | **背景知識**：臨時 DT 開 OSV 的資料來源；osv-scanner 可當交叉檢查 |
| VulnerableCode — https://github.com/aboutcode-org/vulnerablecode | Apache-2.0 | 約 717 star，2026-11-10 | 彙整多來源漏洞並對應 purl 的資料庫／服務 | **背景知識**：WP3 韌體元件缺 CPE 時，purl 對應的另一條思路 |
| Vulnerability-Lookup — https://github.com/vulnerability-lookup/vulnerability-lookup | AGPL-3.0 | 約 605 star，2026-11-12 | CIRCL 開發的漏洞彙整服務，收 EUVD、KEV、GCVE 等多來源，提供 API | **背景知識**：另一個多來源交叉查詢管道；AGPL，只當服務使用，不要複製程式碼進 dumpling |

### 1.3 第 14 條通報、支援期限、CI 內的 CRA 檢查

| 名稱／網址 | 授權 | 維護狀況 | 做什麼 | 對 dumpling 的用處 |
|---|---|---|---|---|
| ENISA 單一通報平台 SRP — 入口 https://portal.cra-srp.enisa.europa.eu/；說明頁 https://www.enisa.europa.eu/topics/product-security-and-certification/cyber-resilience-act | —（官方） | 2026-09-11 上線（初始營運能力）；2026-11-04 升到 v1.3。ENISA 頁面**未提到公開 API 或技術規格**（未確認是否另有） | 製造商用網頁介面送 24 小時預警、72 小時通知、14 天／1 個月最終報告；同時送到製造商主要營業地的 CSIRT 與 ENISA | **背景知識＋流程設計**：WP2。因為沒有已知 API，dumpling 能做的是「偵測並開內部 Issue，附上預填欄位清單」，不能自動通報。要在 STATUS／文件明寫 |
| 歐盟執委會通報頁 — https://digital-strategy.ec.europa.eu/en/policies/cra-reporting | —（官方） | 2026-11 查閱 | 官方說明通報時程、對象、已發布的授權法規（CSIRT 因網路安全理由延後分送）與 FAQ | **背景知識**：WP2 Issue 範本的欄位與時鐘依據 |
| 執委會 CRA 指引（2026-07-27 通過）— https://digital-strategy.ec.europa.eu/en/library/commission-publishes-new-guidance-support-timely-cyber-resilience-act-implementation | —（官方，無法律拘束力） | 草案 2026-03-03，最終 2026-07-27（日期取自二手律所文章，已有官方連結，建議直接讀） | 對範圍、通報（含「知悉」如何解讀）、支援期限、開源、遠端資料處理等的詮釋 | **背景知識**：支援期限欄位（project.yml）、AI NAS 是否屬產品範圍、CI/CD 不算遠端資料處理等都靠它 |
| Bootlin sbom-cve-check — https://github.com/bootlin/sbom-cve-check；meta-sbom-cve-check — https://github.com/bootlin/meta-sbom-cve-check | GPL-2.0；MIT | 約 64 與 10 star，2026-11-04／2026-09-04 | 離線對 SBOM（SPDX）做 CVE 檢查，專為 Yocto 與 CRA 週期性評估設計；可吃 `CVE_STATUS` 並輸出 VEX | **參考做法**：WP7 若有 Yocto／Buildroot 平台；也可參考它如何處理「已評估、不受影響」的註記。GPL-2.0，只參考設計，不複製碼 |
| fwscan — https://github.com/mhmtkas/fwscan | Apache-2.0 | 約 3 star，2026-10-21（極小專案，品質未確認） | 對 rootfs（目錄、tar、squashfs）產 SBOM＋CVE 報告，並檢查該發行版是否還有安全更新 | **參考做法**：WP7 的 Debian／OpenMediaVault 映像「發行版是否已 EOL」檢查，與支援期限管理對應；dumpling 目前沒有「OS 是否已停止維護」的檢查項 |
| CRA 檢查型 CLI／Action（例如 craevidence/cli https://github.com/craevidence/cli、crawatch https://github.com/abinjohnson400-beep/crawatch.dev、cra-sbom-cli https://github.com/cra-compliance-lab/cra-sbom-cli） | MIT | 皆 5 star 以下，2026-05～2026-11 | 在 CI 內檢查 SBOM 欄位、對 KEV 失敗建置、簽章等 | **背景知識**：都是極小專案，成熟度未確認；只借「CI 檢查項目清單」的點子，不採用 |

## 二、文件與範本

| 名稱／網址 | 授權 | 維護狀況 | 做什麼 | 對 dumpling 的用處 |
|---|---|---|---|---|
| ORC WG cra-hub — https://github.com/orcwg/cra-hub | 未確認（有 LICENSE.md，內容未讀） | 約 176 star，2026-11-11 | Eclipse ORC 工作群的 CRA 知識庫：FAQ、資源清單、調和標準摘要（`standards.md`）、重要／關鍵產品定義、問卷 | **背景知識**：調和標準進度與 FAQ 的第一站；WP6 開案範本的欄位（產品分類）可對照其產品定義 |
| ORC WG 主 repo — https://github.com/orcwg/orcwg；Eclipse Cyber Resilience Practices 專案 — https://projects.eclipse.org/node/32506 | 未確認 | 約 36 star，2026-11-12 | ORC 工作群治理與任務小組；Cyber Resilience Practices 的第一份規格是「漏洞處理規格」，內容包含漏洞處理政策應含哪些項目 | **參考做法**：WP6 的 CVD／漏洞處理政策範本（`templates/project/`）以它的結構為骨架；規格全文本次沒讀 |
| OpenChain CRA-Compliance — https://github.com/OpenChain-Project/CRA-Compliance | CC-BY-4.0 | 約 25 star，2026-10-29 | 組織層級的 CRA 合規框架兼自我檢查表：治理、SBOM 品質、漏洞處理、通報、開源管理者義務、技術文件 | **參考做法**：WP6 的 CRA 檢查表欄位；也可當 STATUS 之外的「合規缺口總表」模板。CC-BY-4.0 需署名；原始檔未逐條讀 |
| OpenChain CRA Checklist RC1 — https://cra-compliance.openchainproject.org/CRA_Checklist_RC1.html | —（未確認） | 未確認 | 針對產品中開源元件的 CRA 檢查表（RC1） | **背景知識**：與上一項對照，看哪個較適合 |
| OpenSSF 漏洞揭露指引 — https://github.com/ossf/oss-vulnerability-guide；工作群 https://github.com/ossf/wg-vulnerability-disclosures | CC-BY-4.0；Apache-2.0 | 約 142 star，2026-08-19；約 228 star，2026-02-04 | 開源專案的 CVD 流程與 SECURITY.md 範本、角色分工 | **可直接用（需署名）**：WP6 CVD 範本；dumpling 本身 repo 的 SECURITY.md 也能參考 |
| OpenSSF Security Insights — https://github.com/ossf/security-insights | 未確認 | 約 84 star，2026-11-10 | 專案機器可讀的安全資訊檔（`security-insights.yml`），含支援狀態、聯絡人、政策連結 | **參考做法**：`project.yml` 的支援期限、聯絡窗口欄位可借其欄位名稱，之後方便對接 |
| Linux Foundation CRA 最佳實務指南 — https://bestpractices.linuxfoundation.org/cra/step-5-additional.html | —（網站） | 未確認 | 開源專案做 CRA 準備的步驟式指南；說明開源管理者不必主動維護附件 VII，但被要求時要提供 | **背景知識**：WP6 技術文件範本章節順序可參考 |
| OpenSSF Best Practices Badge — https://github.com/ossf/best-practices-badge；Scorecard — https://github.com/ossf/scorecard | MIT；Apache-2.0 | 約 1.4k／5.8k star，2026-11-12／2026-11-12 | 專案安全實務徽章與自動評分 | **參考做法**：WP0 對 dumpling 自己的 repo 跑 Scorecard（固定 SHA、最小權限，符合 D-012）；是「安全開發流程」證據之一 |
| 附件 VII／附件 II 原文 — https://eur-lex.europa.eu/eli/reg/2024/2847/oj | —（官方） | 官方 | 法規全文：附件 VII 技術文件內容、附件 II 用戶資訊、附件 I 基本要求 | **背景知識（必讀）**：WP6 的技術文件與用戶資訊範本只能以原文為準 |
| Awesome CRA 清單 — https://github.com/cra-compliance-lab/awesome-cra-compliance | 其他（未確認） | 約 56 star，2026-10-18 | 第三方整理的 CRA 資源連結 | **背景知識**：找資源時當索引，不當依據 |
| 非官方範本庫（zealience/Cyber-Resilience-Act https://github.com/zealience/Cyber-Resilience-Act、OpenCRA https://github.com/borisRadonic/OpenCRA） | 前者未標示；OpenCRA 為 MIT | 約 39／3 star | 個人整理的 CRA 範本與嵌入式文件 | **背景知識**：品質未確認，若用，內容要逐條對照法規原文 |

## 三、跟技術路線直接相關

| 名稱／網址 | 授權 | 維護狀況 | 做什麼 | 對 dumpling 的用處 |
|---|---|---|---|---|
| Yocto／OpenEmbedded SBOM（`create-spdx`、`vex`）— https://github.com/yoctoproject/poky、https://github.com/openembedded/openembedded-core；Yocto 文件 https://docs.yoctoproject.org | poky 授權欄空白；oe-core NOASSERTION（皆未確認，實際為 MIT／GPL 混合） | poky 約 480 star，2026-11-10 | Yocto 內建 SPDX 產生（Styhead 5.1 起預設 SPDX 3.0），`vex` 類別輸出 CVE 狀態。官方沒有 CRA 專屬流程（二手來源；未確認） | **參考做法**：WP7 若有 Yocto 平台，建置端 SBOM 比事後掃描準；WP1 的「建置紀錄」概念可與 Yocto 的建置端 SBOM 對照 |
| Buildroot — https://github.com/buildroot/buildroot | 授權欄 NOASSERTION（實際 GPL-2.0，未確認） | 約 3.7k star，2026-11-11 | 內建 `make legal-info`、`show-info` 等，可列出套件與授權 | **背景知識**：WP7 Rockchip／RPi 若有 Buildroot 版，是建置端清單來源 |
| UEFITool — https://github.com/LongSoft/UEFITool | BSD-2-Clause | 約 5.8k star，2026-10-27 | 解析 UEFI 映像（FV、FFS） | **可直接用**：WP3，PLAN 已列。固定版本、只解不執行 |
| MEAnalyzer／MCExtractor — https://github.com/platomav/MEAnalyzer、https://github.com/platomav/MCExtractor | BSD-2-Clause-Patent | 約 1.4k／0.9k star，2026-09 | 讀 Intel ME／CSME 版本；列出微碼 | **可直接用**：WP3，PLAN 已列 |
| coreboot — https://github.com/coreboot/coreboot | GPL-2.0 | 約 2.8k star，2026-11-12 | 開源韌體；`cbfstool` 可列 CBFS 內容 | **背景知識**：WP3 Dasharo 樣本的 CBFS 格式依據；coreboot 建置本身可輸出元件清單，值得查（未確認格式） |
| Dasharo 文件 — https://github.com/Dasharo/dasharo-docs | 未確認 | 未查 star | Dasharo（coreboot＋edk2）各機型的發行說明，含 ME／微碼狀況 | **背景知識**：WP3 驗收（ME 14.0.47.1558、微碼 rev 0xF8）的交叉來源 |
| fiano — https://github.com/linuxboot/fiano | BSD-3-Clause | 約 377 star，2026-10-20 | Go 寫的 UEFI／flash 映像解析與編輯工具 | **參考做法**：`uefi_image.py` 缺 AMI 巢狀壓縮時的另一個參考實作 |
| converged-security-suite — https://github.com/9elements/converged-security-suite | BSD-3-Clause | 約 77 star，2026-08-21 | 9elements 的韌體安全測試與 Intel 平台解析工具 | **背景知識**：WP3 讀 Intel flash 描述區／CSME 的另一參考 |
| fwupd — https://github.com/fwupd/fwupd；LVFS 資料庫 https://fwupd.org | LGPL-2.1 | 約 4.2k star，2026-11-12 | Linux 韌體更新服務，LVFS 有各廠商韌體的 metainfo（版本、發行說明、有時含 CVE） | **參考做法**：WP3／WP4 作為「某型號最新韌體版本是什麼」的公開來源，可補「過期」判斷；資料條款要另查（未確認） |
| CHIPSEC — https://github.com/chipsec/chipsec | GPL-2.0 | 約 3.3k star，2026-11-09 | 平台韌體安全設定檢查（需在實機執行） | **背景知識**：不適用 CI（要實機），僅列備忘 |
| FACT_core — https://github.com/fkie-cad/FACT_core | GPL-3.0 | 約 1.5k star，2026-11-12 | 韌體分析平台：解包、元件識別、CVE 對照 | **背景知識**：與 dumpling 重疊的商用外圍；GPL，不採用，但可對照元件識別結果（WP6 標準答案交叉驗證） |
| OSS Review Toolkit（ORT）— https://github.com/oss-review-toolkit/ort | Apache-2.0 | 約 2.1k star，2026-11-12 | 原始碼層級的相依分析、授權、漏洞、報告全流程 | **背景知識**：WP7 AI NAS 應用程式碼的另一條掃描路線；與 cdxgen 擇一即可 |
| GitHub attest-sbom／attest-build-provenance — https://github.com/actions/attest-sbom、https://github.com/actions/attest-build-provenance | MIT | 約 46／1.1k star，2026-09 | 為建置產物與 SBOM 產生簽章證明 | **可直接用**：WP1 Release 附件做簽章與來源證明，提高 10 年保存的可驗證性（PLAN 目前沒有簽章） |
| cosign／SLSA generator — https://github.com/sigstore/cosign、https://github.com/slsa-framework/slsa-github-generator | Apache-2.0 | 約 6.4k／610 star | 簽章與來源證明 | **參考做法**：WP5 搬到 GitLab 時，簽章不依賴 GitHub 專屬服務的做法 |

---

## CRA 時程與官方來源

| 項目 | 內容 | 官方連結 |
|---|---|---|
| 法規 | Regulation (EU) 2024/2847，OJ 2024-11-20 | https://eur-lex.europa.eu/eli/reg/2024/2847/oj |
| 第 14 條通報開始 | **2026-09-11**。製造商對已被積極利用的漏洞與嚴重事件須通報；時程為 24 小時早期預警、72 小時通知、修正措施可用後 14 天內最終報告（嚴重事件則於 72 小時通知後 1 個月內最終報告）。已過去兩個月，**現在就是適用狀態** | https://digital-strategy.ec.europa.eu/en/policies/cra-reporting |
| 通報管道 | ENISA 單一通報平台 SRP，2026-09-11 上線，2026-11-04 升 v1.3；通知送製造商主要營業地的協調 CSIRT，同時送 ENISA | https://www.enisa.europa.eu/topics/product-security-and-certification/cyber-resilience-act、https://portal.cra-srp.enisa.europa.eu/ |
| 開源管理者（steward）通報 | 2027-12-11 起適用（依執委會頁面） | 同上執委會通報頁 |
| 其他義務全面適用 | **2027-12-11**（二手來源一致；請核對法規第 71 條） | EUR-Lex 全文 |
| 合格評定機構章節 | 2026-06-11 起適用（法規第 71 條；本次未重新核對原文） | EUR-Lex 全文 |
| 執委會指引 | 草案 2026-03-03，最終 2026-07-27（二手）；無法律拘束力。含支援期限「原則至少 5 年，除非預期使用期更短」、CI/CD 不屬遠端資料處理等詮釋 | https://digital-strategy.ec.europa.eu/en/library/commission-publishes-new-guidance-support-timely-cyber-resilience-act-implementation |
| 調和標準 | 標準化請求 M/606 由 CEN／CENELEC 執行。二手來源（獨立指南站）：截至 2026-07 仍**沒有任何 CRA 調和標準刊登於歐盟公報**，因此第 27 條「推定符合」尚不可用；漏洞處理標準（prEN 40000-1-3）最接近刊登；期限有展延一案（2026-10-31／2026-12-31，是否生效未確認）。ORC cra-hub 的 `standards.md` 有整理。**官方確認請查 CEN-CENELEC 與執委會頁面（本次沒查到官方頁）** | https://github.com/orcwg/cra-hub（整理）、二手：https://www.cyberresilienceact.eu/news/cra-standardisation-deadlines-pushed-back-two-months.html |
| 重要／關鍵產品分類 | 附件 III、IV 與施行規則 (EU) 2025/2392（僅從二手 snippet 看到編號，內容**未確認**）。BIOS／開機管理員、作業系統、NAS 類產品是否落在 Class I／II，會決定是否需要第三方評定，建議逐項對照附件 III | EUR-Lex 全文 |
| 官方未取得的項目 | SRP 的 API／機器可讀介面（ENISA 頁面未提）；Annex VII 簡化格式（針對微型與小型企業的實施法案）最終版 | — |

## PLAN 可能漏掉的 CRA 要求

以下是對照 `docs/PLAN.md` 後的差距清單（條號請回 EUR-Lex 核對；我憑記憶與二手資料，標「核對」者尤需確認）。

1. **第 14 條通報時鐘本身**：PLAN 只提到 24／72 小時，但監控（WP2）只做到「開 Issue」。缺少：(a) 通報時鐘起算點（「知悉」何時成立）與 Issue 上的倒數欄位；(b) 24 小時預警、72 小時通知、14 天最終報告三階段範本；(c) 嚴重事件（非漏洞）通報；(d) 通知使用者（第 14 條，核對）。SRP 沒有已知 API，流程上要明寫人工步驟。
2. **支援期限管理**：`project.yml` 有支援期限欄位，但沒有：到期提醒、到期後狀態（EOL）、「支援期限至少 5 年除非預期使用更短」的理由欄位（第 13 條，核對）、支援期限需公開且寫在用戶資訊（附件 II）。另外：OS 層發行版（Debian、Ubuntu、OMV）自己的 EOL 日期要與產品支援期限比對，這是 PLAN 沒有的檢查（參考 fwscan 的想法）。
3. **安全更新提供期限**：安全更新須於支援期限內提供，且（第 13 條，核對）出貨後至少 10 年或支援期間較長者仍須留存／可取得；PLAN 只提「紀錄保存 10 年」，**沒提更新本身的可取得性**。
4. **紀錄保存的定義**：技術文件與 EU 符合性聲明的保存為「出貨後 10 年或支援期間，取較長者」（核對）；PLAN 的 90 天產出物與 Release 要明確區分哪些是正式紀錄。GitHub 階段無法滿足 10 年保存，需在 GITLAB-PORT 明寫。
5. **附件 I 第二部分的其他項目**：(2) 無延遲修補、(3) 定期測試與審查、(4) 修補後公開已修復漏洞資訊（含說明與嚴重度，核對）、(5) 協調式漏洞揭露（CVD）政策、(6) 分享漏洞資訊的聯絡窗口、(7) 安全更新的安全散布、(8) 安全更新免費且附公告。PLAN 只明確列了 (1) SBOM 與 (2) 持續處理。**CVD 政策與聯絡窗口（第 13 條的單一聯絡點）沒有對應工作包**；建議 WP6 範本加入。
6. **附件 I 第一部分（產品設計）**：安全預設設定、可還原、防未授權存取、資料最小化等。dumpling 做的是漏洞處理與 SBOM；沒有「設計層」檢查（例如是否可回復出廠、是否有預設密碼）。至少要在報告標 NOT_ASSESSED，避免被當成整體合規。
7. **風險評估與技術文件（第 13(2)–(3) 條、附件 VII）**：PLAN 沒有風險評估範本、技術文件目錄、EU 符合性聲明（附件 V）與 CE 標示流程。建議 WP6 範本產出空殼目錄，缺的項目標 GAP。
8. **用戶資訊與說明（附件 II）**：支援期限、聯絡點、SBOM 取得方式（附件 II 允許提供 SBOM 位置，核對）、安全更新方式。可讓 `project.yml` 產生草稿。
9. **第三方元件盡職調查（第 13(5)(6) 條）**：整合開源元件須做盡職調查，並把發現的元件漏洞回報給元件維護者（第 13(6)）。PLAN 有 vendor-level 提醒，但沒有「回報上游」的流程。
10. **重要／關鍵產品分類（附件 III、IV）與合格評定路徑**：決定是否內部控制（模組 A）還是需要公告機構；PLAN 沒有。BIOS／開機管理員與作業系統可能落入分類（核對）。
11. **SBOM 格式與品質要求**：PLAN 只有 sbomqs 品質檢查（針對匯入 SBOM）。建議對 dumpling 自己產的 SBOM 也跑；並以 BSI TR-03183-2 作為最低欄位檢查，格式為 CycloneDX 1.6+ 或 SPDX 3.0.1+。
12. **簽章與來源證明**：PLAN 沒有對 Release 報告／SBOM 簽章。CRA 不強制，但 10 年可驗證性與「安全更新完整性」的證據會受益。
13. **VEX 狀態語意**：OpenVEX 沒有「未評估」；NOT_ASSESSED 輸出成 VEX 時要選 under_investigation，避免被下游當成「已確認」。PLAN 目前沒有輸出格式對照表。
14. **漏洞資料來源完整性**：EUVD 已利用清單是 CISA KEV 子集（二手），API 覆蓋比 NVD 少（二手）。監控報告應註明資料來源覆蓋率限制，且 KEV／EUVD 未命中不等於安全（對照 PLAN 狀態規則）。
15. **GitHub 排程停用風險已有對策**，但**公開 Issue 的資安風險沒提**：公開 repo 開 Issue 通報「已被利用」漏洞，等於公開披露。第 14 條通報對象是 CSIRT／ENISA，不是公開頁面。示範專案用公開資料沒問題；搬到 GitLab 時 Issue 要私有。建議在 WP2 文件寫明。
16. **調和標準追蹤**：目前沒有任何對調和標準進度的追蹤；建議 STATUS 加一行（見上表資料來源）。

## 建議 dumpling 採用或補強的前 5 項

1. **把 sbomqs（BSI TR-03183-2 設定檔）接成 SBOM 品質閘門**
   - 理由：Apache-2.0、維護中，直接對應 CRA 常被引用的 SBOM 欄位要求；dumpling 的 SBOM 不論自己產或供應商給的，都能一致檢查，低分只標記不阻擋（符合 GAP 規則）。
   - 對應：WP1／M1（自產 SBOM）、WP3／M3（匯入供應商 BIOS SBOM）、WP6（標準答案）。
   - 工作量：約 0.5–1 天（固定版本安裝、CI 步驟、報告欄位）；BSI 設定檔版本涵蓋範圍先讀原始碼確認。

2. **WP2 加「第 14 條通報工作流程」，而不只是開 Issue**
   - 理由：通報義務自 2026-09-11 已適用；SRP 目前沒有已知 API，工具能做的是把「知悉時間、24／72／14 天倒數、預填欄位清單、人工提交 SRP 的檢查項」放進 Issue 範本。同時聲明公開 repo 只用於示範資料，真實案件不得走公開 Issue。
   - 對應：WP2／M4、WP5（GitLab 私有 Issue）。
   - 工作量：約 1–2 天（Issue 範本、倒數欄位、文件）。

3. **補「支援期限與 EOL」管理**（`project.yml` 欄位＋每日檢查）
   - 理由：PLAN 只有欄位沒有檢查。加上：支援期限到期倒數、OS 發行版 EOL 對照（WP7 的 Debian、Ubuntu、OMV）、報告顯示「已過期＝GAP」。參考 fwscan 的概念，自行實作。
   - 對應：WP6（欄位與範本）、WP7（OS 層 EOL 資料）、WP2（每日提醒）。
   - 工作量：約 2–3 天。

4. **WP6 開案範本擴充成「CRA 文件骨架」**：CVD 政策、風險評估、技術文件目錄（附件 VII）、用戶資訊（附件 II）、EU 符合性聲明空殼
   - 理由：這些是 CRA 實際查核會看的文件，PLAN 只涵蓋漏洞與 SBOM 面。可用 OpenSSF 漏洞揭露指南（CC-BY-4.0）、ORC／Eclipse 漏洞處理規格、OpenChain CRA-Compliance（CC-BY-4.0）作結構參考，全部對照 EUR-Lex 原文；缺的內容標 GAP。
   - 對應：WP6／M6。
   - 工作量：約 3–5 天（以空殼＋欄位為主，不寫實質內容）。

5. **Release 附件簽章與來源證明**（`actions/attest-sbom`、`attest-build-provenance`，並規劃 GitLab 階段的替代方案）
   - 理由：10 年保存與「更新完整性」都需要可驗證；成本低。固定 commit SHA（D-012）。
   - 對應：WP1／M2（Release）、WP5（GitLab 替代方案，如 cosign）。
   - 工作量：約 0.5–1 天（GitHub 階段）；GitLab 階段另計。

## 查不到或未確認的事項

- SRP 是否有 API／機器可讀介面：ENISA 頁面未提，未確認。
- 調和標準的官方進度與展延案是否生效：只有二手來源，未找到 CEN-CENELEC 或執委會官方頁。
- BSI TR-03183-2 v2.1.0 的欄位細節與發布日期、sbomqs BSI 設定檔實際涵蓋版本：只讀二手摘要。
- (EU) 2025/2392 的內容、各產品落在附件 III／IV 的分類：未確認。
- 條號（第 13、14、24、27、71 條及附件 I、II、V、VII）凡標「核對」者，皆須回 EUR-Lex 原文確認。
- cisagov/kev-data、ORC cra-hub、OpenChain 檢查表、LF 指南的授權：未確認。
- 部分日期（執委會指引 2026-07-27）取自律所文章；官方連結已附，請以官方頁為準。
