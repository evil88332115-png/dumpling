"""workflow 步驟的結果紀錄：$DUMPLING_OUT/pipeline-steps.tsv（沒有標題列）。每一步一列，TAB 分隔：
    pipeline-<步驟>   OK｜ATTENTION｜GAP｜NOT_RUN｜FAIL   <結束碼>   <最後一行輸出或說明>   [recorded]
第 5 欄 recorded 只有 run-step.sh --record（workflow 自己記、不執行步驟的那一列）會寫；一般執行的列沒有第 5 欄（說明裡的 TAB 會被清掉，寫不出來）。
由 pipeline/run-step.sh 寫；platform_scan.collect（summary、notes、scan.json）、release-meta.py（steps／result）、scan-status-check.py 讀。
ATTENTION：這一步完成了，但用了舊資料頂替（例如弱點資料鏡像上游連不上、沿用 48 小時內的上一份；pipeline/lib/mirrors.sh 寫）。
整體狀態（overall）：有 FAIL → FAIL；沒有 FAIL 但有 GAP 或「沒能執行」的 NOT_RUN → GAP；沒有 GAP 但有 ATTENTION → ATTENTION（不是 OK，但比 GAP 輕；不擋 Release）；其他 → OK。
NOT_RUN 分兩類：有 recorded 標記（run-step.sh --record 寫的）且說明以「不適用」開頭＝這一步本來就不該做（例如 build.mode: none 的 build），不降低整體狀態；
其他 NOT_RUN＝該做卻沒做（平台沒有實作這一步、build 在非 aarch64 主機上等，run-step.sh 收到結束碼 4 時的最後一行；腳本自己印「不適用…」也算這一類），
整體降成 GAP（D-043：沒做的不能當成沒問題）。只看文字會被步驟輸出繞過，所以要 recorded 這個結構標記。兩類都照實列出。
用法（python3 -I）：step_rows.py append <tsv> <步驟> <狀態> <結束碼> <說明>｜step_rows.py record <tsv> <步驟> <狀態> <結束碼> <說明>（同 append，加 recorded；只給 run-step.sh --record 用）｜step_rows.py status <tsv>（印 OK｜GAP｜FAIL；檔案不存在印 GAP）
"""
import os
import sys

STATUSES = ("OK", "ATTENTION", "GAP", "NOT_RUN", "FAIL")
NOT_APPLICABLE = "不適用"        # recorded 的 NOT_RUN 說明以這個開頭＝這一步本來就不該做（不降低整體狀態）
RECORDED = "recorded"            # 第 5 欄：run-step.sh --record 寫的列
MAX_DETAIL = 800


def clean(text):
    return " ".join(str(text).replace("\t", " ").replace("\r", " ").replace("\n", " ").split())[:MAX_DETAIL]


def append_row(path, step, status, rc, detail, recorded=False):
    if status not in STATUSES:
        raise ValueError("狀態必須是 %s" % "／".join(STATUSES))
    step = clean(step)
    if not step.startswith("pipeline-"):
        step = "pipeline-" + step
    with open(path, "a", encoding="utf-8") as f:
        f.write("%s\t%s\t%d\t%s%s\n" % (step, status, int(rc), clean(detail), "\t" + RECORDED if recorded else ""))


def read_rows(path):
    """→ [{step, status, exit, detail}]；檔案不存在回傳 None（呼叫端要當成「沒有紀錄」，不是「沒有問題」）。壞掉的列保留成 FAIL，不丟掉。"""
    try:
        with open(path, encoding="utf-8") as f:
            lines = [l.rstrip("\n") for l in f if l.strip()]
    except OSError:
        return None
    rows = []
    for l in lines:
        p = l.split("\t")
        if len(p) in (4, 5) and p[1] in STATUSES and p[2].lstrip("-").isdigit() and (len(p) == 4 or p[4] == RECORDED):
            r = {"step": p[0], "status": p[1], "exit": int(p[2]), "detail": p[3]}
            if len(p) == 5:
                r["recorded"] = True
            rows.append(r)
        else:
            rows.append({"step": p[0] if p else "?", "status": "FAIL", "exit": -1, "detail": "pipeline-steps.tsv 的列格式不對：" + clean(l)[:100]})
    return rows


def not_applicable(row):
    """run-step.sh --record 寫的（recorded）NOT_RUN，且說明以「不適用」開頭：這一步本來就不該做。一般執行的列不看文字，一律不算。"""
    return row["status"] == "NOT_RUN" and row.get("recorded") is True and row["detail"].startswith(NOT_APPLICABLE)


def overall(rows):
    """整體狀態；rows 是 None（沒有紀錄檔）→ GAP（不能當成沒問題）。沒能執行的 NOT_RUN（不是「不適用」）→ 至少 GAP。"""
    if rows is None:
        return "GAP"
    sts = {r["status"] for r in rows}
    not_run = any(r["status"] == "NOT_RUN" and not not_applicable(r) for r in rows)
    return "FAIL" if "FAIL" in sts else "GAP" if "GAP" in sts or not_run else "ATTENTION" if "ATTENTION" in sts else "OK"


def attention_lines(rows):
    """ATTENTION 列的說明（鏡像頂替的那一行等），照原文；給 notes、summary、release-meta 用。"""
    return [r["detail"] for r in rows or [] if r["status"] == "ATTENTION"]


def markdown_table(rows):
    L = ["| 步驟 | 狀態 | 結束碼 | 說明 |", "|---|---|---:|---|"]
    for r in rows or []:
        L.append("| %s | %s | %s | %s |" % (r["step"], r["status"], r["exit"], r["detail"].replace("|", "／")))
    return L


def main(argv):
    try:
        if len(argv) == 6 and argv[0] in ("append", "record"):
            append_row(argv[1], argv[2], argv[3], argv[4], argv[5], recorded=argv[0] == "record")
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
