# 示範：Jetson Linux R39.2.1 的基礎版與模擬客製版

CRA 對照文件的「示範」一節：以 NVIDIA Jetson Linux R39.2.1（JetPack 7.2.1，Ubuntu 24.04）為例，示範賣客製版的廠商怎麼用 sca-center
管理「NVIDIA 的基礎版」和「自己的客製版」，以及公告出來時怎麼查出受影響的版本。

```
推送 demo-run/<N> 分支（demo-run/vuln-<N>：只做漏洞，sca-scan 加 --no-license，約一半時間；名稱含 r39.2.0，例如 demo-run/vuln-r39.2.0-1：改用 R39.2.0） → e2e-pilot（自架 runner，sca-heavy）：部署 CI 用的 DT 等服務（OSV 加 Ubuntu）→ tools/demo/jetson.sh
本機：OUT=<結果> WORK=<暫存> PILOT_ENV=<pilot.env> [JETSON_RELEASE=39.2.0] tools/demo/jetson.sh   # 需要 docker、syft、grype、bwrap；下載約 3.3 GB，暫存約 20 GB
```

## 流程
| 階段 | 做什麼 |
|---|---|
| `A-download-*` | 從 NVIDIA 下載 BSP 與範例根檔案系統，核對 NVIDIA 公布的 SHA-1（`release_sha_hashes.txt`，網址與值寫死在 `jetson.sh`），另記 SHA-256（`downloads.tsv`） |
| `B-prep` | `jetson_rootfs.py`：範例根檔案系統＋BSP 裡 `nv_tegra/l4t_deb_packages`、`kernel` 的 arm64／all 套件 → 基礎版 tar；再加模擬的客戶套件 → 客製版 tar（`prep.json`） |
| `B-import-*` | `docker import` 成本機映像（不啟動容器） |
| `C-scan-*` | `sca-scan --image <映像 ID> --no-package-scan --no-files-scan`（Syft、Grype、上傳 DT） |
| `G-*` | `jetson_lookup.py`：兩版的差異，以及 DT 上的三個查法（`lookup.json`、`summary.md`） |

## 安全與限制（照實寫）
- **下載即同意 NVIDIA 的軟體授權協議**（下載頁的說明）。使用者 2026-10-27 同意後才加入。
- 下載的檔案是不可信資料：`jetson_rootfs.py` 只讀 tar 與 deb（ar）的結構，**不解開到主機、不執行套件內容、不跑 `apply_binaries.sh`**。
  deb 的檔案直接寫進輸出的 tar，control 加上 `Status: install ok installed` 併進 dpkg status。映像是 arm64，runner 不會執行裡面的程式。
- **這是近似值，不是刷機後的系統**：`apply_binaries.sh` 依板子挑套件、維護者腳本產生的檔案與設定都沒有；這裡放進所有 arm64／all 的套件。
  `prep.json` 列出每個套件、被取代的根檔案系統檔案數、略過的成員。
- 模擬客製版的 `acme-inspector` 與 Pillow 10.0.0 是假的，只有中繼資料（Pillow 故意用舊版，讓客製版有自己的弱點）。
- 不做逐套件授權掃描（deb 的下載網址是已知限制，PR 2 的範圍）與檔案層級掃描（幾 GB 太久）。
- **已知限制（demo-run/1，run 40502222604）**：每個映像 3647 個套件（另有 11 萬多個檔案元件），DejaCode 的 `import_from_scan` 在 30 分鐘內沒有回應
  （`E-dejacode-import` FAIL，http=000），所以 `C-scan-*` 記 FAIL、示範的退出碼是 1。授權資料仍在 ScanCode.io（`E-scancodeio-load-sbom`）。
  PR 2 改成分批匯入（`DJ_IMPORT_CHUNK`，預設 1000；每批秒數在 `dejacode/import-chunks.tsv`）。demo-run/4（每批 500）：3647 個套件 8 批全部成功，共 3671 秒。
- DT 的 `component/identity?name=` 是部分比對，套件附帶的檔案（classifier FILE）也會出現；`G-lookup-component` 只算同名的套件。
- CI 的 DT 每次執行完就刪除：結果留在報告裡。實際使用時要上傳到長期運作的 DT（`sca-pilot`），新的弱點資料進來才會自動重新比對。
- 用這份資料開發的東西，不能拿同一份資料當之後準確度評估的驗收資料。

## 廠商的刷機包

廠商交付的 Jetson 刷機包（tbz2，裡面有 `rootfs_no_gui/`、`rootfs_gui/`）用 `scan-flash-package.sh` 掃描：步驟、掃描範圍與機密注意事項見 `flash-package.md`。
Rockchip 的 `update.img`（或裝著它的 zip）也用同一支腳本（`--rootfs rootfs`）：分割區表與 32 位元溢位的修正、ext4 的唯讀讀取、boot 分割區
的核心見 `flash-package.md` 的「Rockchip 的 update.img」與 `rockchip_img.py`。
資料或對照表更新後用 `--rescan-from <上一次的結果資料夾>` 只重跑比對（沿用上一次的 SBOM，不再解壓、不 docker import）。
