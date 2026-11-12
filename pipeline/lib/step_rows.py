"""workflow 步驟的結果紀錄：$DUMPLING_OUT/pipeline-steps.tsv（沒有標題列）。每一步一列，TAB 分隔：
    pipeline-<步驟>   OK｜GAP｜NOT_RUN｜FAIL   <結束碼>   <最後一行輸出或說明>
由 pipeline/run-step.sh 寫；platform_scan.collect（summary、notes、scan.json）、release-meta.py（steps／result）、scan-status-check.py 讀。
整體狀態（overall）：有 FAIL → FAIL；沒有 FAIL 但有 GAP → GAP；其他 → OK。NOT_RUN 不降低整體狀態（例如 build.mode: none 的 build 本來就不跑），但會照實列出。
用法（python3 -I）：step_rows.py append <tsv> <步驟> <狀態> <結束碼> <說明>｜step_rows.py status <tsv>（印 OK｜GAP｜FAIL；檔案不存在印 GAP）
"""
import os
import sys

STATUSES = ("OK", "GAP", "NOT_RUN", "FAIL")
MAX_DETAIL = 300


def clean(text):
    return " ".join(str(text).replace("\t", " ").replace("\r", " ").replace("\n", " ").split())[:MAX_DETAIL]


def append_row(path, step, status, rc, detail):
    if status not in STATUSES:
        raise ValueError("狀態必須是 %s" % "／".join(STATUSES))
    step = clean(step)
    if not step.startswith("pipeline-"):
        step = "pipeline-" + step
    with open(path, "a", encoding="utf-8") as f:
        f.write("%s\t%s\t%d\t%s\n" % (step, status, int(rc), clean(detail)))


def read_rows(path):
    """→ [{step, status, exit, detail}]；檔案不存在回傳 None（呼叫端要當成「沒有紀錄」，不是「沒有問題」）。壞掉的列保留成 FAIL，不丟掉。"""
    try:
        with open(path, encoding="utf-8") as f:
            lines = [l.rstrip("\n") for l in f if l.strip()]
    except OSError:
        return None
    rows = []
    for l in lines:
        p = l.split("\t", 3)
        if len(p) == 4 and p[1] in STATUSES and p[2].lstrip("-").isdigit():
            rows.append({"step": p[0], "status": p[1], "exit": int(p[2]), "detail": p[3]})
        else:
            rows.append({"step": p[0] if p else "?", "status": "FAIL", "exit": -1, "detail": "pipeline-steps.tsv 的列格式不對：" + clean(l)[:100]})
    return rows


def overall(rows):
    """整體狀態；rows 是 None（沒有紀錄檔）→ GAP（不能當成沒問題）。"""
    if rows is None:
        return "GAP"
    sts = {r["status"] for r in rows}
    return "FAIL" if "FAIL" in sts else "GAP" if "GAP" in sts else "OK"


def markdown_table(rows):
    L = ["| 步驟 | 狀態 | 結束碼 | 說明 |", "|---|---|---:|---|"]
    for r in rows or []:
        L.append("| %s | %s | %s | %s |" % (r["step"], r["status"], r["exit"], r["detail"].replace("|", "／")))
    return L


def main(argv):
    try:
        if len(argv) == 6 and argv[0] == "append":
            append_row(argv[1], argv[2], argv[3], argv[4], argv[5])
            return 0
        if len(argv) == 2 and argv[0] == "status":
            print(overall(read_rows(argv[1])))
            return 0
    except (ValueError, OSError) as e:
        print("step_rows: FAIL（%s）" % e, file=sys.stderr)
        return 1
    print(__doc__, file=sys.stderr)
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
