#!/usr/bin/env python3
"""檢查 tools/pilot/sca-scan 的 status.tsv：必要階段都要是 OK，而且不能有 FAIL。
用法：python3 -I pipeline/scan-status-check.py <status.tsv> [必要階段 ...] [--pipeline-steps <pipeline-steps.tsv>]
沒給必要階段時用 dt-smoke 的預設（--sbom、--no-license 上傳到臨時 DT）。
全部符合印一行「上傳: …」並以 0 結束；否則印原因並以 1 結束。其他階段（NOT_RUN、GAP、ATTENTION）不影響結果，
但不會被當成 OK：這裡只回答「必要的有沒有做到」。"""
import csv
import os
import sys

DEFAULT_NEED = ["A-source", "B-sandbox", "B-sandbox-secrets", "B-sbom-provided", "C-grype", "C-upload-sbom",
                "D-dt-project", "D-dt-upload", "D-dt-bom-processing", "D-dt-vuln-analysis", "F-secret-scan"]


def main(argv):
    steps = None
    if "--pipeline-steps" in argv:       # 選用：pipeline/run-step.sh 寫的 pipeline-steps.tsv；有 FAIL 或 GAP 的列就不是 OK
        i = argv.index("--pipeline-steps")
        if i + 1 >= len(argv):
            print("--pipeline-steps 要給檔案", file=sys.stderr)
            return 64
        steps = argv[i + 1]
        argv = argv[:i] + argv[i + 2:]
    if not argv:
        print("用法：scan-status-check.py <status.tsv> [必要階段 ...]", file=sys.stderr)
        return 64
    with open(argv[0], encoding="utf-8") as f:
        rows = {r["stage"]: r for r in csv.DictReader(f, delimiter="\t")}
    need = argv[1:] or DEFAULT_NEED
    bad = [f"{s}={rows[s]['status'] if s in rows else '沒有這一列'}" for s in need if s not in rows or rows[s]["status"] != "OK"]
    fails = [s for s, r in rows.items() if r["status"] == "FAIL"]
    if steps is not None:
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
        import step_rows
        rs = step_rows.read_rows(steps)
        so = step_rows.overall(rs)
        if so != "OK":
            print("上傳: 流程步驟的整體狀態是 %s（不是 OK）：%s" % (so, "、".join("%s=%s" % (r["step"], r["status"]) for r in (rs or []) if r["status"] in ("GAP", "FAIL")) or "沒有 pipeline-steps.tsv"))
            return 1
    if bad or fails:
        print("上傳: sca-scan 必要階段不是 OK：" + ", ".join(bad) + "；FAIL：" + ", ".join(fails))
        return 1
    print("上傳: tools/pilot/sca-scan --sbom（必要階段全部 OK：" + "、".join(need) + "）")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
