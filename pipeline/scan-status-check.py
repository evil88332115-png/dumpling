#!/usr/bin/env python3
"""檢查 tools/pilot/sca-scan 的 status.tsv：必要階段都要是 OK，而且不能有 FAIL。
用法：python3 -I pipeline/scan-status-check.py <status.tsv> [必要階段 ...]
沒給必要階段時用 dt-smoke 的預設（--sbom、--no-license 上傳到臨時 DT）。
全部符合印一行「上傳: …」並以 0 結束；否則印原因並以 1 結束。其他階段（NOT_RUN、GAP、ATTENTION）不影響結果，
但不會被當成 OK：這裡只回答「必要的有沒有做到」。"""
import csv
import sys

DEFAULT_NEED = ["A-source", "B-sandbox", "B-sandbox-secrets", "B-sbom-provided", "C-grype", "C-upload-sbom",
                "D-dt-project", "D-dt-upload", "D-dt-bom-processing", "D-dt-vuln-analysis", "F-secret-scan"]


def main(argv):
    if not argv:
        print("用法：scan-status-check.py <status.tsv> [必要階段 ...]", file=sys.stderr)
        return 64
    with open(argv[0], encoding="utf-8") as f:
        rows = {r["stage"]: r for r in csv.DictReader(f, delimiter="\t")}
    need = argv[1:] or DEFAULT_NEED
    bad = [f"{s}={rows[s]['status'] if s in rows else '沒有這一列'}" for s in need if s not in rows or rows[s]["status"] != "OK"]
    fails = [s for s, r in rows.items() if r["status"] == "FAIL"]
    if bad or fails:
        print("上傳: sca-scan 必要階段不是 OK：" + ", ".join(bad) + "；FAIL：" + ", ".join(fails))
        return 1
    print("上傳: tools/pilot/sca-scan --sbom（必要階段全部 OK：" + "、".join(need) + "）")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
