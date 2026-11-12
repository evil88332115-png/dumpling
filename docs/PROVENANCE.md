# PROVENANCE：從 sca-center 複製的檔案

每個從 sca-center 複製進來的檔案記一列：dumpling 路徑、sca-center 原路徑、來源 commit、清理了什麼。
目錄對應規則（D-015）：sca-center 的 `scripts/<子目錄>/<檔名>` → dumpling 的 `tools/<子目錄>/<檔名>`；測試 `scripts/<子目錄>/tests/` → `tools/<子目錄>/tests/`。
各節只由負責的對話修改，避免衝突。

## C1 工具（WP1）

來源 commit 一律是 sca-center `25fa89a`（`origin/main`）。`tools/` 以外的 pipeline 檔案是 dumpling 自己寫的（做法參考對應的 sca-center 檔）。總計 192 個複製進來的檔案。

| dumpling 路徑 | sca-center 原路徑 | 來源 commit | 清理內容 |
|---|---|---|---|
| `pipeline/dt-compose.yaml` | `scripts/e2e/dt-compose.yaml` | 25fa89a | 改名 e2e-dt→dumpling-dt；埠改成 `${DT_PORT:-8080}`；註解改寫；映像 digest 與其餘設定不變 |
| `pipeline/dt-ephemeral.sh` | `scripts/e2e/dtlib.sh`（做法參考，重寫） | 25fa89a | 改寫成 up／wait／env／down 四個子指令；狀態檔取代 sca-center 的 status／secret 函式；關 NVD、開 OSV 與 KEV、API key 流程沿用；新增 KEV 與 OSV 鏡像等待與逾時 GAP、`::add-mask::` |
| `pipeline/dt-verify.py` | `scripts/e2e/dtread.py`（分頁與 X-Total-Count 核對的做法） | 25fa89a | 重寫：專案、元件數、依生態系漏洞數的驗證與摘要；另含直接上傳的後備模式 |
| `tests/fixtures/jetson-r39.2.1-base.cdx.json.xz` | `tests/fixtures/jetson-r39.2.1-base.cdx.json.xz` | 25fa89a | 清理 1 行（SBOM 內的信箱改成 example.com、產品代號與本機路徑換成中性代稱） |
| `tools/cra/board_import.py` | `scripts/cra/board_import.py` | 25fa89a | 路徑調整 2 處 |
| `tools/cra/bootloader_coverage.py` | `scripts/cra/bootloader_coverage.py` | 25fa89a | 路徑調整 2 處 |
| `tools/cra/company.example.json` | `scripts/cra/company.example.json` | 25fa89a | 原樣 |
| `tools/cra/config.example.json` | `scripts/cra/config.example.json` | 25fa89a | 原樣 |
| `tools/cra/config.schema.json` | `scripts/cra/config.schema.json` | 25fa89a | 路徑調整 4 處 |
| `tools/cra/confirm_items.py` | `scripts/cra/confirm_items.py` | 25fa89a | 路徑調整 4 處 |
| `tools/cra/cra_report.py` | `scripts/cra/cra_report.py` | 25fa89a | 路徑調整 42 處、清理 1 行 |
| `tools/cra/data/support-lifecycle.json` | `scripts/cra/data/support-lifecycle.json` | 25fa89a | 原樣 |
| `tools/cra/dt_writeback.py` | `scripts/cra/dt_writeback.py` | 25fa89a | 原樣 |
| `tools/cra/evidence_bundle.py` | `scripts/cra/evidence_bundle.py` | 25fa89a | 路徑調整 2 處、清理 1 行 |
| `tools/cra/exploited_grype.py` | `scripts/cra/exploited_grype.py` | 25fa89a | 路徑調整 10 處、清理 1 行 |
| `tools/cra/exploited_vendor.py` | `scripts/cra/exploited_vendor.py` | 25fa89a | 原樣 |
| `tools/cra/exploited_watch.py` | `scripts/cra/exploited_watch.py` | 25fa89a | 路徑調整 11 處 |
| `tools/cra/firmware_bom.py` | `scripts/cra/firmware_bom.py` | 25fa89a | 路徑調整 2 處 |
| `tools/cra/image_check.py` | `scripts/cra/image_check.py` | 25fa89a | 路徑調整 3 處、清理 1 行 |
| `tools/cra/initrd_coverage.py` | `scripts/cra/initrd_coverage.py` | 25fa89a | 原樣 |
| `tools/cra/kernel_modules.py` | `scripts/cra/kernel_modules.py` | 25fa89a | 路徑調整 7 處 |
| `tools/cra/no_vuln_data.py` | `scripts/cra/no_vuln_data.py` | 25fa89a | 路徑調整 1 處、清理 3 行 |
| `tools/cra/nvidia_distro.py` | `scripts/cra/nvidia_distro.py` | 25fa89a | 原樣 |
| `tools/cra/own_software.py` | `scripts/cra/own_software.py` | 25fa89a | 原樣 |
| `tools/cra/pkg_why.py` | `scripts/cra/pkg_why.py` | 25fa89a | 路徑調整 2 處 |
| `tools/cra/py_dpkg_version.py` | `scripts/cra/py_dpkg_version.py` | 25fa89a | 路徑調整 1 處 |
| `tools/cra/report_diff.py` | `scripts/cra/report_diff.py` | 25fa89a | 路徑調整 1 處 |
| `tools/cra/report_package.py` | `scripts/cra/report_package.py` | 25fa89a | 路徑調整 1 處 |
| `tools/cra/runtime_evidence.py` | `scripts/cra/runtime_evidence.py` | 25fa89a | 原樣 |
| `tools/cra/security_findings.py` | `scripts/cra/security_findings.py` | 25fa89a | 路徑調整 6 處 |
| `tools/cra/supplier_package.py` | `scripts/cra/supplier_package.py` | 25fa89a | 原樣 |
| `tools/cra/support_check.py` | `scripts/cra/support_check.py` | 25fa89a | 路徑調整 1 處 |
| `tools/cra/tee_bundled.py` | `scripts/cra/tee_bundled.py` | 25fa89a | 原樣 |
| `tools/cra/tee_source.py` | `scripts/cra/tee_source.py` | 25fa89a | 原樣 |
| `tools/cra/templates/risk-assessment.md` | `scripts/cra/templates/risk-assessment.md` | 25fa89a | 原樣 |
| `tools/cra/templates/sbom.md` | `scripts/cra/templates/sbom.md` | 25fa89a | 原樣 |
| `tools/cra/templates/technical-documentation.md` | `scripts/cra/templates/technical-documentation.md` | 25fa89a | 原樣 |
| `tools/cra/templates/user-information.md` | `scripts/cra/templates/user-information.md` | 25fa89a | 原樣 |
| `tools/cra/tests/test_bootloader_coverage.py` | `scripts/cra/tests/test_bootloader_coverage.py` | 25fa89a | 清理 2 行 |
| `tools/cra/tests/test_bootloader_report.py` | `scripts/cra/tests/test_bootloader_report.py` | 25fa89a | 原樣 |
| `tools/cra/tests/test_confirm_items.py` | `scripts/cra/tests/test_confirm_items.py` | 25fa89a | 原樣 |
| `tools/cra/tests/test_cra_deb_python_usn.py` | `scripts/cra/tests/test_cra_deb_python_usn.py` | 25fa89a | 原樣 |
| `tools/cra/tests/test_cra_distro.py` | `scripts/cra/tests/test_cra_distro.py` | 25fa89a | 路徑調整 3 處 |
| `tools/cra/tests/test_cra_euvd.py` | `scripts/cra/tests/test_cra_euvd.py` | 25fa89a | 原樣 |
| `tools/cra/tests/test_cra_exploitation.py` | `scripts/cra/tests/test_cra_exploitation.py` | 25fa89a | 清理 3 行 |
| `tools/cra/tests/test_cra_grype_only.py` | `scripts/cra/tests/test_cra_grype_only.py` | 25fa89a | 清理 3 行 |
| `tools/cra/tests/test_cra_nvidia.py` | `scripts/cra/tests/test_cra_nvidia.py` | 25fa89a | 路徑調整 2 處、清理 1 行 |
| `tools/cra/tests/test_cra_report.py` | `scripts/cra/tests/test_cra_report.py` | 25fa89a | 路徑調整 1 處、清理 11 行 |
| `tools/cra/tests/test_cra_ubuntu_tracker_fix.py` | `scripts/cra/tests/test_cra_ubuntu_tracker_fix.py` | 25fa89a | 原樣 |
| `tools/cra/tests/test_cra_usn_fix.py` | `scripts/cra/tests/test_cra_usn_fix.py` | 25fa89a | 原樣 |
| `tools/cra/tests/test_customer_package_wording.py` | `scripts/cra/tests/test_customer_package_wording.py` | 25fa89a | 清理 2 行 |
| `tools/cra/tests/test_dashboard_sheet.py` | `scripts/cra/tests/test_dashboard_sheet.py` | 25fa89a | 清理 1 行 |
| `tools/cra/tests/test_dt_writeback.py` | `scripts/cra/tests/test_dt_writeback.py` | 25fa89a | 原樣 |
| `tools/cra/tests/test_evidence_bundle.py` | `scripts/cra/tests/test_evidence_bundle.py` | 25fa89a | 清理 3 行 |
| `tools/cra/tests/test_exploited_vendor.py` | `scripts/cra/tests/test_exploited_vendor.py` | 25fa89a | 清理 1 行、刪段 44 行 |
| `tools/cra/tests/test_exploited_watch.py` | `scripts/cra/tests/test_exploited_watch.py` | 25fa89a | 路徑調整 1 處 |
| `tools/cra/tests/test_exploited_watch_grype.py` | `scripts/cra/tests/test_exploited_watch_grype.py` | 25fa89a | 路徑調整 1 處、刪段 266 行 |
| `tools/cra/tests/test_exploited_watch_refresh.py` | `scripts/cra/tests/test_exploited_watch_refresh.py` | 25fa89a | 路徑調整 2 處、刪段 323 行 |
| `tools/cra/tests/test_firmware_bom.py` | `scripts/cra/tests/test_firmware_bom.py` | 25fa89a | 清理 2 行 |
| `tools/cra/tests/test_image_check.py` | `scripts/cra/tests/test_image_check.py` | 25fa89a | 清理 6 行 |
| `tools/cra/tests/test_image_check_modules.py` | `scripts/cra/tests/test_image_check_modules.py` | 25fa89a | 原樣 |
| `tools/cra/tests/test_initrd_coverage.py` | `scripts/cra/tests/test_initrd_coverage.py` | 25fa89a | 原樣 |
| `tools/cra/tests/test_kernel_modules.py` | `scripts/cra/tests/test_kernel_modules.py` | 25fa89a | 路徑調整 2 處、清理 12 行 |
| `tools/cra/tests/test_no_vuln_data.py` | `scripts/cra/tests/test_no_vuln_data.py` | 25fa89a | 清理 39 行 |
| `tools/cra/tests/test_nvidia_distro.py` | `scripts/cra/tests/test_nvidia_distro.py` | 25fa89a | 原樣 |
| `tools/cra/tests/test_own_software.py` | `scripts/cra/tests/test_own_software.py` | 25fa89a | 原樣 |
| `tools/cra/tests/test_pkg_why.py` | `scripts/cra/tests/test_pkg_why.py` | 25fa89a | 原樣 |
| `tools/cra/tests/test_py_dpkg_version.py` | `scripts/cra/tests/test_py_dpkg_version.py` | 25fa89a | 原樣 |
| `tools/cra/tests/test_report_diff.py` | `scripts/cra/tests/test_report_diff.py` | 25fa89a | 原樣 |
| `tools/cra/tests/test_report_package.py` | `scripts/cra/tests/test_report_package.py` | 25fa89a | 清理 1 行 |
| `tools/cra/tests/test_runtime_evidence.py` | `scripts/cra/tests/test_runtime_evidence.py` | 25fa89a | 路徑調整 1 處 |
| `tools/cra/tests/test_security_testing.py` | `scripts/cra/tests/test_security_testing.py` | 25fa89a | 路徑調整 1 處、清理 6 行 |
| `tools/cra/tests/test_supplier_package.py` | `scripts/cra/tests/test_supplier_package.py` | 25fa89a | 清理 1 行 |
| `tools/cra/tests/test_support_check.py` | `scripts/cra/tests/test_support_check.py` | 25fa89a | 原樣 |
| `tools/cra/tests/test_tee_source.py` | `scripts/cra/tests/test_tee_source.py` | 25fa89a | 原樣 |
| `tools/cra/tests/test_uefi_bundled.py` | `scripts/cra/tests/test_uefi_bundled.py` | 25fa89a | 原樣 |
| `tools/cra/tests/test_uefi_followup.py` | `scripts/cra/tests/test_uefi_followup.py` | 25fa89a | 原樣 |
| `tools/cra/tests/test_uefi_image.py` | `scripts/cra/tests/test_uefi_image.py` | 25fa89a | 原樣 |
| `tools/cra/tests/test_uefi_source.py` | `scripts/cra/tests/test_uefi_source.py` | 25fa89a | 路徑調整 1 處、清理 4 行 |
| `tools/cra/tests/test_upstream_baseline.py` | `scripts/cra/tests/test_upstream_baseline.py` | 25fa89a | 清理 3 行 |
| `tools/cra/tests/test_vex_evidence.py` | `scripts/cra/tests/test_vex_evidence.py` | 25fa89a | 原樣 |
| `tools/cra/tests/test_vex_export.py` | `scripts/cra/tests/test_vex_export.py` | 25fa89a | 清理 2 行 |
| `tools/cra/tests/test_vex_no_response.py` | `scripts/cra/tests/test_vex_no_response.py` | 25fa89a | 刪段 30 行 |
| `tools/cra/tests/test_vex_rules.py` | `scripts/cra/tests/test_vex_rules.py` | 25fa89a | 清理 2 行 |
| `tools/cra/tests/test_vex_u1_flag.py` | `scripts/cra/tests/test_vex_u1_flag.py` | 25fa89a | 路徑調整 4 處 |
| `tools/cra/tests/test_vex_u2.py` | `scripts/cra/tests/test_vex_u2.py` | 25fa89a | 原樣 |
| `tools/cra/uefi_bundled.py` | `scripts/cra/uefi_bundled.py` | 25fa89a | 原樣 |
| `tools/cra/uefi_dsc.py` | `scripts/cra/uefi_dsc.py` | 25fa89a | 原樣 |
| `tools/cra/uefi_image.py` | `scripts/cra/uefi_image.py` | 25fa89a | 清理 1 行 |
| `tools/cra/uefi_source.py` | `scripts/cra/uefi_source.py` | 25fa89a | 路徑調整 8 處 |
| `tools/cra/upstream_baseline.py` | `scripts/cra/upstream_baseline.py` | 25fa89a | 清理 1 行 |
| `tools/cra/vendor-watch.example.json` | `deploy/exploited-watch/vendor-watch.example.json` | 25fa89a | 原樣 |
| `tools/cra/vex-rules.example.json` | `scripts/cra/vex-rules.example.json` | 25fa89a | 路徑調整 1 處 |
| `tools/cra/vex_export.py` | `scripts/cra/vex_export.py` | 25fa89a | 路徑調整 4 處 |
| `tools/cra/xlsx_min.py` | `scripts/cra/xlsx_min.py` | 25fa89a | 原樣 |
| `tools/demo/README.md` | `scripts/demo/README.md` | 25fa89a | 路徑調整 2 處 |
| `tools/demo/android_img.py` | `scripts/demo/android_img.py` | 25fa89a | 路徑調整 3 處 |
| `tools/demo/board-import.sh` | `scripts/demo/board-import.sh` | 25fa89a | 路徑調整 7 處 |
| `tools/demo/flash_package.py` | `scripts/demo/flash_package.py` | 25fa89a | 路徑調整 9 處 |
| `tools/demo/jetson.sh` | `scripts/demo/jetson.sh` | 25fa89a | 路徑調整 4 處 |
| `tools/demo/jetson_lookup.py` | `scripts/demo/jetson_lookup.py` | 25fa89a | 原樣 |
| `tools/demo/jetson_rootfs.py` | `scripts/demo/jetson_rootfs.py` | 25fa89a | 清理 1 行 |
| `tools/demo/pack-build-record.sh` | `scripts/demo/pack-build-record.sh` | 25fa89a | 原樣 |
| `tools/demo/rockchip_img.py` | `scripts/demo/rockchip_img.py` | 25fa89a | 路徑調整 1 處 |
| `tools/demo/rpi_img.py` | `scripts/demo/rpi_img.py` | 25fa89a | 路徑調整 1 處 |
| `tools/demo/scan-flash-package.sh` | `scripts/demo/scan-flash-package.sh` | 25fa89a | 路徑調整 42 處、清理 7 行 |
| `tools/demo/tests/test_android_img.py` | `scripts/demo/tests/test_android_img.py` | 25fa89a | 路徑調整 1 處 |
| `tools/demo/tests/test_flash_package.py` | `scripts/demo/tests/test_flash_package.py` | 25fa89a | 路徑調整 1 處、清理 52 行 |
| `tools/demo/tests/test_jetson_lookup.py` | `scripts/demo/tests/test_jetson_lookup.py` | 25fa89a | 原樣 |
| `tools/demo/tests/test_jetson_rootfs.py` | `scripts/demo/tests/test_jetson_rootfs.py` | 25fa89a | 清理 1 行 |
| `tools/demo/tests/test_pack_build_record.py` | `scripts/demo/tests/test_pack_build_record.py` | 25fa89a | 原樣 |
| `tools/demo/tests/test_rockchip_img.py` | `scripts/demo/tests/test_rockchip_img.py` | 25fa89a | 路徑調整 1 處、清理 2 行 |
| `tools/demo/tests/test_rpi_img.py` | `scripts/demo/tests/test_rpi_img.py` | 25fa89a | 原樣 |
| `tools/demo/tests/test_wizard_plan.py` | `scripts/demo/tests/test_wizard_plan.py` | 25fa89a | 原樣 |
| `tools/e2e/dtread.py` | `scripts/e2e/dtread.py` | 25fa89a | 原樣 |
| `tools/e2e/install-tools.sh` | `scripts/e2e/install-tools.sh` | 25fa89a | 路徑調整 1 處 |
| `tools/e2e/sandbox.sh` | `scripts/e2e/sandbox.sh` | 25fa89a | 路徑調整 1 處 |
| `tools/mirror/euvd.sh` | `scripts/mirror/euvd.sh` | 25fa89a | 路徑調整 3 處 |
| `tools/mirror/grype-db.sh` | `scripts/mirror/grype-db.sh` | 25fa89a | 原樣 |
| `tools/mirror/kernel-cve.sh` | `scripts/mirror/kernel-cve.sh` | 25fa89a | 路徑調整 1 處 |
| `tools/mirror/nvidia-bulletins.sh` | `scripts/mirror/nvidia-bulletins.sh` | 25fa89a | 路徑調整 2 處 |
| `tools/mirror/osv-distro.sh` | `scripts/mirror/osv-distro.sh` | 25fa89a | 路徑調整 1 處 |
| `tools/mirror/ubuntu-cve-status.sh` | `scripts/mirror/ubuntu-cve-status.sh` | 25fa89a | 原樣 |
| `tools/pilot/README.md` | `scripts/pilot/README.md` | 25fa89a | 路徑調整 18 處、清理 2 行 |
| `tools/pilot/lib/common.sh` | `scripts/pilot/lib/common.sh` | 25fa89a | 路徑調整 4 處 |
| `tools/pilot/lib/data/kernel-included-c-6.1.json` | `scripts/pilot/lib/data/kernel-included-c-6.1.json` | 25fa89a | 路徑調整 1 處 |
| `tools/pilot/lib/data/kernel-included-c-6.8.json` | `scripts/pilot/lib/data/kernel-included-c-6.8.json` | 25fa89a | 路徑調整 1 處 |
| `tools/pilot/lib/deb_sources.py` | `scripts/pilot/lib/deb_sources.py` | 25fa89a | 原樣 |
| `tools/pilot/lib/distro_recheck.py` | `scripts/pilot/lib/distro_recheck.py` | 25fa89a | 路徑調整 3 處 |
| `tools/pilot/lib/dtsources.py` | `scripts/pilot/lib/dtsources.py` | 25fa89a | 路徑調整 1 處 |
| `tools/pilot/lib/euvd.md` | `scripts/pilot/lib/euvd.md` | 25fa89a | 路徑調整 7 處、清理 1 行 |
| `tools/pilot/lib/euvd.py` | `scripts/pilot/lib/euvd.py` | 25fa89a | 路徑調整 6 處 |
| `tools/pilot/lib/kernel_boot.py` | `scripts/pilot/lib/kernel_boot.py` | 25fa89a | 清理 3 行 |
| `tools/pilot/lib/kernel_cna_version.py` | `scripts/pilot/lib/kernel_cna_version.py` | 25fa89a | 路徑調整 1 處 |
| `tools/pilot/lib/kernel_config.py` | `scripts/pilot/lib/kernel_config.py` | 25fa89a | 路徑調整 5 處、清理 1 行 |
| `tools/pilot/lib/kernel_git_files.py` | `scripts/pilot/lib/kernel_git_files.py` | 25fa89a | 原樣 |
| `tools/pilot/lib/kernel_module_map.py` | `scripts/pilot/lib/kernel_module_map.py` | 25fa89a | 路徑調整 1 處、清理 1 行 |
| `tools/pilot/lib/kernel_oot_record.py` | `scripts/pilot/lib/kernel_oot_record.py` | 25fa89a | 原樣 |
| `tools/pilot/lib/kernelcheck.py` | `scripts/pilot/lib/kernelcheck.py` | 25fa89a | 路徑調整 1 處 |
| `tools/pilot/lib/l4t-kernel-map.json` | `scripts/pilot/lib/l4t-kernel-map.json` | 25fa89a | 原樣 |
| `tools/pilot/lib/l4t_kernel.py` | `scripts/pilot/lib/l4t_kernel.py` | 25fa89a | 原樣 |
| `tools/pilot/lib/leakscan.py` | `scripts/pilot/lib/leakscan.py` | 25fa89a | 原樣 |
| `tools/pilot/lib/lockcheck.py` | `scripts/pilot/lib/lockcheck.py` | 25fa89a | 原樣 |
| `tools/pilot/lib/mirror_freshness.py` | `scripts/pilot/lib/mirror_freshness.py` | 25fa89a | 路徑調整 1 處 |
| `tools/pilot/lib/nvidia-bulletins.json` | `scripts/pilot/lib/nvidia-bulletins.json` | 25fa89a | 路徑調整 1 處 |
| `tools/pilot/lib/nvidia-bulletins.md` | `scripts/pilot/lib/nvidia-bulletins.md` | 25fa89a | 路徑調整 9 處 |
| `tools/pilot/lib/nvidia_bulletins.py` | `scripts/pilot/lib/nvidia_bulletins.py` | 25fa89a | 路徑調整 1 處 |
| `tools/pilot/lib/strip_versions.py` | `scripts/pilot/lib/strip_versions.py` | 25fa89a | 原樣 |
| `tools/pilot/lib/ubuntu_priority.py` | `scripts/pilot/lib/ubuntu_priority.py` | 25fa89a | 原樣 |
| `tools/pilot/lib/ubuntu_status.py` | `scripts/pilot/lib/ubuntu_status.py` | 25fa89a | 路徑調整 1 處 |
| `tools/pilot/lib/usn_cves.py` | `scripts/pilot/lib/usn_cves.py` | 25fa89a | 原樣 |
| `tools/pilot/report.py` | `scripts/pilot/report.py` | 25fa89a | 路徑調整 1 處 |
| `tools/pilot/sca-scan` | `scripts/pilot/sca-scan` | 25fa89a | 路徑調整 82 處 |
| `tools/pilot/tests/data/euvd-dt-enisa-golden.json` | `scripts/pilot/tests/data/euvd-dt-enisa-golden.json` | 25fa89a | 原樣 |
| `tools/pilot/tests/pilot_fixtures.py` | `scripts/pilot/tests/pilot_fixtures.py` | 25fa89a | 原樣 |
| `tools/pilot/tests/test_deb_sources.py` | `scripts/pilot/tests/test_deb_sources.py` | 25fa89a | 路徑調整 2 處 |
| `tools/pilot/tests/test_distro_recheck.py` | `scripts/pilot/tests/test_distro_recheck.py` | 25fa89a | 路徑調整 4 處 |
| `tools/pilot/tests/test_kernel_boot.py` | `scripts/pilot/tests/test_kernel_boot.py` | 25fa89a | 路徑調整 1 處 |
| `tools/pilot/tests/test_kernel_cna_branch.py` | `scripts/pilot/tests/test_kernel_cna_branch.py` | 25fa89a | 原樣 |
| `tools/pilot/tests/test_kernel_cna_version.py` | `scripts/pilot/tests/test_kernel_cna_version.py` | 25fa89a | 原樣 |
| `tools/pilot/tests/test_kernel_config.py` | `scripts/pilot/tests/test_kernel_config.py` | 25fa89a | 路徑調整 6 處、清理 30 行 |
| `tools/pilot/tests/test_kernel_k1_improve.py` | `scripts/pilot/tests/test_kernel_k1_improve.py` | 25fa89a | 路徑調整 1 處、清理 2 行 |
| `tools/pilot/tests/test_kernel_k1_review1.py` | `scripts/pilot/tests/test_kernel_k1_review1.py` | 25fa89a | 原樣 |
| `tools/pilot/tests/test_kernel_k1_undetermined.py` | `scripts/pilot/tests/test_kernel_k1_undetermined.py` | 25fa89a | 原樣 |
| `tools/pilot/tests/test_kernel_module_map.py` | `scripts/pilot/tests/test_kernel_module_map.py` | 25fa89a | 清理 3 行 |
| `tools/pilot/tests/test_kernel_oot_sections.py` | `scripts/pilot/tests/test_kernel_oot_sections.py` | 25fa89a | 清理 1 行 |
| `tools/pilot/tests/test_kernel_vendor_flow.py` | `scripts/pilot/tests/test_kernel_vendor_flow.py` | 25fa89a | 路徑調整 2 處 |
| `tools/pilot/tests/test_nvidia_bulletins.py` | `scripts/pilot/tests/test_nvidia_bulletins.py` | 25fa89a | 路徑調整 4 處 |
| `tools/pilot/tests/test_pilot_compare_and_scripts.py` | `scripts/pilot/tests/test_pilot_compare_and_scripts.py` | 25fa89a | 路徑調整 8 處、清理 5 行、刪段 129 行 |
| `tools/pilot/tests/test_pilot_euvd.py` | `scripts/pilot/tests/test_pilot_euvd.py` | 25fa89a | 路徑調整 3 處 |
| `tools/pilot/tests/test_pilot_kernel_coverage.py` | `scripts/pilot/tests/test_pilot_kernel_coverage.py` | 25fa89a | 清理 1 行 |
| `tools/pilot/tests/test_pilot_l4t_kernel.py` | `scripts/pilot/tests/test_pilot_l4t_kernel.py` | 25fa89a | 路徑調整 1 處 |
| `tools/pilot/tests/test_pilot_lock_sandbox.py` | `scripts/pilot/tests/test_pilot_lock_sandbox.py` | 25fa89a | 路徑調整 15 處、刪段 75 行 |
| `tools/pilot/tests/test_pilot_nvd_mirror.py` | `scripts/pilot/tests/test_pilot_nvd_mirror.py` | 25fa89a | 原樣 |
| `tools/pilot/tests/test_pilot_report.py` | `scripts/pilot/tests/test_pilot_report.py` | 25fa89a | 原樣 |
| `tools/pilot/tests/test_pilot_sources_scio.py` | `scripts/pilot/tests/test_pilot_sources_scio.py` | 25fa89a | 路徑調整 1 處、清理 1 行、刪段 109 行 |
| `tools/pilot/tests/test_pilot_utf8_truncation.py` | `scripts/pilot/tests/test_pilot_utf8_truncation.py` | 25fa89a | 路徑調整 1 處、清理 1 行 |
| `tools/pilot/tests/test_pyver_wiring.py` | `scripts/pilot/tests/test_pyver_wiring.py` | 25fa89a | 路徑調整 3 處 |
| `tools/pilot/tests/test_sca_scan_local_image.py` | `scripts/pilot/tests/test_sca_scan_local_image.py` | 25fa89a | 路徑調整 1 處 |
| `tools/pilot/tests/test_ubuntu_cve_status.py` | `scripts/pilot/tests/test_ubuntu_cve_status.py` | 25fa89a | 路徑調整 3 處 |
| `tools/pilot/tests/test_ubuntu_priority.py` | `scripts/pilot/tests/test_ubuntu_priority.py` | 25fa89a | 路徑調整 1 處 |
| `tools/pilot/tests/test_ubuntu_status.py` | `scripts/pilot/tests/test_ubuntu_status.py` | 25fa89a | 路徑調整 5 處 |
| `tools/pilot/tests/test_usn_cves.py` | `scripts/pilot/tests/test_usn_cves.py` | 25fa89a | 路徑調整 1 處 |
| `tools/sbomgate/sbomgate.py` | `integration/sbomgate/sbomgate.py` | 25fa89a | 原樣 |
| `tools/sbomgate/tests/test_sbomgate.py` | `integration/sbomgate/tests/test_sbomgate.py` | 25fa89a | 原樣 |
| `tools/vexconv/tests/test_vexconv.py` | `integration/vexconv/tests/test_vexconv.py` | 25fa89a | 清理 3 行 |
| `tools/vexconv/vexconv.py` | `integration/vexconv/vexconv.py` | 25fa89a | 原樣 |
| `tools/wizard/README.md` | `scripts/wizard/README.md` | 25fa89a | 路徑調整 10 處 |
| `tools/wizard/cra-scan.py` | `scripts/wizard/cra-scan.py` | 25fa89a | 路徑調整 10 處 |
| `tools/wizard/inputs.example.json` | `scripts/wizard/inputs.example.json` | 25fa89a | 清理 1 行 |
| `tools/wizard/platforms/android.json` | `scripts/wizard/platforms/android.json` | 25fa89a | 原樣 |
| `tools/wizard/platforms/jetson.json` | `scripts/wizard/platforms/jetson.json` | 25fa89a | 清理 1 行 |
| `tools/wizard/platforms/raspberrypi.json` | `scripts/wizard/platforms/raspberrypi.json` | 25fa89a | 原樣 |
| `tools/wizard/platforms/rockchip.json` | `scripts/wizard/platforms/rockchip.json` | 25fa89a | 清理 1 行 |
| `tools/wizard/wizard.example.json` | `scripts/wizard/wizard.example.json` | 25fa89a | 原樣 |

以下是 dumpling 自己寫的（不是複製）：`ci/provenance-check.sh`、`tests/run.d/c1-tools.sh`。

### 改動類型說明

- 「原樣」：內容與 sca-center `25fa89a` 的同一檔完全相同。
- 「路徑調整」：只做路徑改名（`scripts/<子目錄>/` → `tools/<子目錄>/`，`integration/sbomgate`、`integration/vexconv` → `tools/sbomgate`、`tools/vexconv`，以及 `ROOT / "scripts" / …` 這種組路徑的程式碼），其餘原樣。處數是替換的次數。
- 「清理 N 行」：除了路徑調整，還有 N 行因為公開檢查（產品代號、本機路徑、私有 IP、個人信箱）或內部來源說明而改過。
- 「刪段 N 行」：整個測試函式或段落因為對應的程式沒有帶進來而移除（原因見下面「刪掉的測試」）。

### 沒帶進來的相依

下列工具在 sca-center 存在，但不在範圍內（或歸別的工作包），沒有複製。帶進來的程式走到它們時的行為寫在右欄。

| 沒帶進來的檔案 | 誰會呼叫 | 走到時的行為 |
|---|---|---|
| `scripts/pilot/lib/{djsbom,filescan,licverdict,notice,oscopyright,pkgscan,scio_cancel,scio_chunks,scio_diag,scio_failures,scio_prep}.py`、`scripts/e2e/{djread,licexpr}.py`、`integration/policysync/` | `sca-scan` 的 E 段（DejaCode 授權匯入）與 E2 段（ScanCode.io 檔案層級掃描） | `pilot.env` 沒有 `DEJACODE_URL`／`SCANCODEIO_URL`、或給 `--no-license`、`--no-upload` 時，這些階段記 NOT_RUN（程式碼原有的判斷）。**若 `pilot.env` 設了那些網址，會因為找不到檔案而記 FAIL**；dumpling 的 pipeline 不設它們 |
| `scripts/e2e/dt-compose.yaml`、`scripts/e2e/dtlib.sh` | 臨時 DT | 由 `pipeline/dt-ephemeral.sh`、`pipeline/dt-compose.yaml` 取代（見上面 pipeline 列） |
| `scripts/mirror/dt-feeds.sh` | `mirror/euvd.sh`（只有鏡像資料夾裡有 `dt-feeds/` 時才呼叫） | dumpling 的 EUVD 鏡像不會產生 `dt-feeds/`，不會走到 |
| `scripts/cra/alert_mail.py`、`exploited-watch-daily.sh`、`exploited-watch-backup.sh` | 每日監控的寄信與排程（公司環境） | `exploited_watch.py` 只是讀它們寫的狀態檔（`--grype-db-update`、`--backup-dir`、`--refresh-status` 都是選用參數，不給就不檢查）。dumpling 的 `watch.yml` 預計直接呼叫 `exploited_watch.py`、用 GitHub Issue 通知 |
| `scripts/cra/csaf_advisory.py` | 沒有程式呼叫（獨立指令） | 不在範圍內 |
| `scripts/demo/board-on-device.sh`、`board-from-network.sh`、`board-test.md` | 在板子上跑的收集腳本；`board_import.py`、`board-import.sh` 只讀它們的輸出檔 | 沒有板子結果檔時，精靈記 `board-import` NOT_RUN |
| `scripts/pilot/lib/kernel_included_c.py` | 產生 `lib/data/kernel-included-c-*.json` 的工具（`kernel_config.py` 只讀資料檔） | 資料檔有帶；要重新產生才需要它 |
| `scripts/pilot/{ci_summary,compare_expected}.py`、`ci-*.sh`、`scripts/e2e/{real-projects,license,firmware,images,projects,summarize,…}.sh`／`.py`、`scripts/ci/`、`scripts/run-*.sh` | sca-center 自己的 CI 與 e2e | 與 dumpling 無關 |
| `scripts/cra/x86_firmware.py`、`test_x86_firmware.py`、`data/fw-manifest-template.csv`、BIOS 試掃原型 | 歸 C2（D-015） | 帶進來的程式沒有 import 它們 |
| `deploy/`（`gitlab-runner`、`gitlab-bot`、`pilot`、`exploited-watch/install.sh` 等）、`ci/gitlab/`、`integration/` 其他子目錄 | 公司的 GitLab 與常駐環境部署 | 帶進來的程式與測試裡仍有提到這些路徑的說明文字或預設值（例如 `deploy/pilot/state/pilot.env` 是 `PILOT_ENV` 沒設時的預設），dumpling 一律明確傳 `PILOT_ENV` |
| `scripts/cra/README.md`（288 KB）、`scripts/demo/flash-package.md` | 說明文件 | 內容含沒帶進來的工具與公司流程，清理成本高，沒帶；需要時另開 PR 重寫 |

### 影響邏輯的替換

這次所有「產品代號、主機名、本機路徑」的命中都在註解、說明文字、測試資料與預設路徑，**判定邏輯本身（`kernel_config.py`、`kernel_boot.py`、`upstream_baseline.py`、`cra_report.py`、`no_vuln_data.py` 等）沒有以公司產品代號當條件的程式碼**。實際改到行為（輸出字串或預設值）的有：

| 檔案 | 行為說明 | 換成 |
|---|---|---|
| `tools/demo/scan-flash-package.sh` | `--out` 預設的上層資料夾（`FLASHPKG_RESULTS`）與 `PILOT_ENV` 預設路徑，原本指向公司常駐環境的本機路徑 | `$HOME/sca-results`、`$HOME/.config/sca-scan/pilot.env`（只是預設值；pipeline 一律明確傳） |
| `tools/cra/exploited_grype.py` | 只有說明字串：`--results-root` 的例子路徑 | `$HOME/sca-results` |
| `tools/demo/jetson_rootfs.py` | 模擬的客戶應用程式在 dpkg status 的 Maintainer 信箱（`example.invalid` 網域的 noreply）；公開檢查只允許 `@example.com|org|net` | `noreply@example.com`（測試 `test_jetson_rootfs.py` 同步改） |
| `tools/pilot/lib/kernel_boot.py`、`kernel_config.py`、`tools/demo/scan-flash-package.sh` | 「預設用刷機包的 `kernel/Image`」的證據說明字串（輸出到報告備註與 JSON）原本點名某個廠商產品的板子實測 | 「a board flashed from a vendor Jetson flash package」（中文：廠商 Jetson 刷機包的板子實測）。判定邏輯沒改 |
| `tools/cra/image_check.py`、`tools/cra/no_vuln_data.py` | 只有說明字串裡的範例信箱（systemd 樣板單元名稱的範例、`dh_make` 預設信箱），公開檢查會把它們當信箱 | 把網域部分換成佔位文字；`DISTRO_DOMAINS` 等判定用的網域清單沒動 |
| 全部 `tools/*/tests/*.py` | 測試資料裡的信箱（例如 `@lists.debian.org`、`@nvidia.com`，`no_vuln_data` 的判定依網域）與 `/home/…` 路徑（`image_check` 的映像內路徑）若直接改字會改變測試意義，所以改成「字串拼接」（`"a@" "debian.org"`）：執行時的值與原本完全相同，只是原始碼裡不出現完整信箱／路徑 | 無（值不變） |
| `tools/cra/tests/test_security_testing.py`、`test_cra_report.py` | 測試資料裡板子網路掃描的 IP（私有 IP） | `192.0.2.20`、`192.0.2.2`（文件用網段） |
| `tools/cra/tests/test_no_vuln_data.py` | 一個四段式套件版本字串（開頭是 10，後面接 cuda 標記）被私有 IP 規則誤判 | 把開頭的 10 改成 11 |
| `tools/wizard/**` 與 `tools/cra/tests/*` | 產品代號（`product-a`、`product-b`、`product-c` 是中性代稱，分別對應三個不公開的廠商產品名）出現在測試用的假刷機包名稱、`platforms/*.json` 的 `note` | `product-a` 等；不影響邏輯 |
| `wizard/cra-scan.py` | **未改**（路徑除外）。注意：它在掃描前用 `git archive origin/main` 取「最新工具」放到 `<輸出>/wt/` 再執行 `wt/tools/…`，也就是跑的是遠端 main 的版本，不是目前 checkout。CI 上要用目前 checkout 時需另外處理（C1 決定） | — |

### 資料檔與測試資料的來源

| 檔案 | 來源 | 判定 |
|---|---|---|
| `tests/fixtures/jetson-r39.2.1-base.cdx.json.xz` | Syft 1.55.0 對「公開 Jetson BSP 加範例 rootfs」組出的映像（`tools/demo/jetson.sh` 的產物）產生的 CycloneDX；Ubuntu 套件、NVIDIA L4T 套件與核心模組，3851 個元件 | 公開來源的掃描結果。清理內容見上表 |
| `tools/pilot/lib/data/kernel-included-c-{6.1,6.8}.json` | 由 Linux 上游原始碼樹產生（誰被別的檔案 `#include` 的 `.c` 清單） | 公開（上游原始碼推導） |
| `tools/pilot/lib/nvidia-bulletins.json`、`l4t-kernel-map.json` | NVIDIA 公開安全公告（`NVIDIA/product-security`）與 Jetson Linux 版本對照，人工整理 | 公開來源、人工整理 |
| `tools/cra/data/support-lifecycle.json`、`vex-rules.example.json`、`config.example.json`、`company.example.json`、`config.schema.json`、`templates/*.md` | 手寫的範例與範本 | 合成 |
| `tools/wizard/platforms/*.json`、`inputs.example.json`、`wizard.example.json` | 手寫的平台範本與範例 | 合成（`note` 欄位原本點名公司產品，已換成中性代稱） |
| `tools/cra/vendor-watch.example.json` | 手寫範例（`deploy/exploited-watch/vendor-watch.example.json`） | 合成 |
| 各測試檔內的資料（`tools/*/tests/*.py`） | 測試自己用程式組出來的假刷機包、假 rootfs、假 SBOM／Grype／DT 輸出；欄位格式取自公開工具（Syft、Grype、Dependency-Track、NVIDIA／Ubuntu／Debian 公開資料）的實際輸出形狀 | 合成。少數註解寫「形狀取自某次實測」，已改成中性說明；是否曾參考內部產品映像的實測形狀，見下面「待確認」 |
| `tools/pilot/tests/data/euvd-dt-enisa-golden.json` | 測試用的小型 EUVD／ENISA 格式資料 | 合成（格式取自公開的 EUVD 傾印） |

**待確認（請 C1／使用者判斷，我不猜）**：
- `test_kernel_config.py` 的「第四輪」一段（`IMAGE_PRODUCT_A`、`TC_*`）：數字（30 個 `CONFIG_VENDOR*`、231 個 `MISSING*`）是測試自己組的，但原本註解說「形狀取自某個內部產品映像的實測」，我已把註解改成「合成資料」；若形狀本身就算內部資料，這段測試要改寫。
- `test_flash_package.py`、`test_kernel_modules.py`、`test_image_check.py`、`test_firmware_bom.py`、`test_upstream_baseline.py` 的假刷機包以 `product-a_OrinNano/Linux_for_Tegra/…` 命名：檔案結構是 NVIDIA 公開 BSP 的結構，名稱是合成的，內容是測試用 `tarfile` 現組。
- `kernel_boot.py`／`kernel_config.py` 的預設「優先用 `kernel/Image`」是依據某廠商刷機包的板子實測；已去除產品名，但這個「結論」本身來自內部測試。

### 刪掉的測試

測試所對應的程式或腳本沒有帶進來（見「沒帶進來的相依」），所以整個測試函式移除（「刪段」行數見上表）：

- `test_pilot_ci_summary.py`（`ci_summary.py`）、`test_oscopyright.py`、`test_pilot_license_scan.py`（授權段）、`test_pilot_ubuntu_status_mirror.py`、`test_euvd_dt_feed.py`（測 `deploy/pilot`、`deploy/gitlab-runner` 的包裝腳本）：整檔不帶。
- `test_pilot_compare_and_scripts.py`、`test_pilot_lock_sandbox.py`、`test_pilot_sources_scio.py`：移除用到 `compare_expected.py`、`scio_prep.py`、`scio_diag.py`、`real-projects.sh`、`install-maven.sh`、`cdxgen_regression.py`、`tests/results` 的測試函式。
- `test_exploited_vendor.py`、`test_exploited_watch_grype.py`、`test_exploited_watch_refresh.py`：移除用到 `alert_mail.py`、每日／備份腳本、`deploy/` 安裝腳本的測試函式。
- `test_vex_no_response.py`：移除兩個用到 `csaf_advisory.py` 的測試函式。
- 不帶：`test_alert_mail.py`、`test_csaf_advisory.py`、`test_customer_package_round2.py`、`test_customer_sbom_and_wording.py`（都 import `csaf_advisory`）、`test_gitlab_ci.py`、`test_gitlab_bot.py`、`test_gitlab_runner.py`、`demo/tests/test_board_test.py`、`test_x86_firmware.py`（歸 C2）。

## C2 韌體工具（WP3＋WP4）

| dumpling 路徑 | sca-center 原路徑 | 來源 commit | 清理內容 |
|---|---|---|---|
| `tools/cra/x86_firmware.py` | `scripts/cra/x86_firmware.py` | 25fa89a | 拿掉內部計畫編號與 issue／PR 參照、`CLAUDE.md` 參照、「main 也一樣」這類內部分支說明；範本路徑改成 `tools/cra/data/…`；「內部給的映像」改成「廠商或團隊提供的映像」；SBOM 的 tools 名稱 `sca-center x86_firmware.py` 改成 `dumpling x86_firmware.py`。**解析邏輯沒改。** 新增（dumpling 的功能）：`dumpling:vuln-assessment`／`dumpling:vuln-assessment-note`／`dumpling:version-status` property、Intel CSME 的 `cpe`（family 確定是 CSME 才填；NVD 查證寫在程式註解）。SBOM property 命名空間 `sca-center:` 與 inventory 的 schema 名稱 `sca-center-fw-inventory/1` **維持不變**（C1 複製的報告工具可能依賴） |
| `tools/cra/tests/test_x86_firmware.py` | `scripts/cra/tests/test_x86_firmware.py` | 25fa89a | 拿掉審查輪次與 issue 編號的註解；`cdx_validator` 改從 `cdx_schema.py` import（原本從 `test_firmware_bom`，那個檔案歸 C1）。測試內容沒改 |
| `tools/cra/data/fw-manifest-template.csv` | `scripts/cra/data/fw-manifest-template.csv` | 25fa89a | 無需清理（全是假資料範例），原樣複製 |
| `tools/cra/tests/data/cyclonedx-1.6.1/`（README.md、bom-1.6.schema.json、jsf-0.82.schema.json、spdx.schema.json） | `scripts/cra/tests/data/cyclonedx-1.6.1/` | 25fa89a | 三個 schema 是 CycloneDX 官方檔案，bom 與 spdx 原樣複製；jsf-0.82.schema.json 只改了 `$comment` 裡作者的個人信箱（公開檢查不允許個人信箱；不影響驗證，SHA-256 與原檔的差異見該目錄 README.md）；README 只改了「用來驗證」那句的檔名參照。C1 之後的 cra 測試共用這個位置 |
| `tools/cra/tests/cdx_schema.py` | `scripts/cra/tests/test_firmware_bom.py` 約第 422–434 行（`SCHEMA_DIR`、`cdx_validator`） | 25fa89a | 只抽出這兩段，其餘 `test_firmware_bom.py` 歸 C1，不複製 |
| `tools/cra/tests/conftest.py` | `scripts/cra/tests/conftest.py` 與 `integration/conftest.py`（概念） | 25fa89a | 不複製 `integration/`。改寫成等效的最小版：環境變數 `DUMPLING_REQUIRE_TEST_DATA=1` 時任何 skip 都視為失敗（原本是 `SCA_REQUIRE_TEST_DATA`） |

以下是 dumpling 自己寫的（不是複製）：`pipeline/firmware-bios.sh`、`tools/cra/tests/test_x86_firmware_sbom.py`、`tools/cra/tests/requirements.txt`、`tests/run.d/c2-x86-firmware.sh`。
