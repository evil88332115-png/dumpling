"""sca-scan／scan-flash-package.sh 的 status.tsv（stage<TAB>status<TAB>detail）的共用讀法（M7b）。

同一個階段出現多列時，各讀取者原本做法不一致：scan-status-check、platform_scan 取最後一列，firmware_dt 取最嚴重的一列。
現在統一成以下規則（tools/cra/cra_report.py 的 read_status 照同一套規則另寫一份：tools/ 不 import pipeline/；
tests/test_status_tsv.py 比對兩邊的結果）：
- 取最嚴重的一列（SEVERITY；不認得的狀態比 OK 嚴重）：前面的 FAIL 不能被後面的 OK 蓋掉。
- 取到的是 OK 而且有重複列 → 改成 ATTENTION（說明加上「status.tsv 有 N 列」）：sca-scan 每個階段只寫一列，
  重複列代表檔案被改過或寫檔有 bug，有人看過之前不能顯示 OK（同 firmware_dt 的 stage_anomaly_notes）。
- 只有兩欄的列也算（detail 是空字串），不丟掉；第一欄是 "stage" 的列是表頭。
"""

SEVERITY = {"OK": 0, "ATTENTION": 2, "NOT_ASSESSED": 3, "NOT_RUN": 4, "GAP": 5, "FAIL": 6}
UNKNOWN_SEVERITY = 1


def severity(st):
    return SEVERITY.get(st, UNKNOWN_SEVERITY)


def pick(lines):
    """lines：可疊代的「一行文字」（不含或含換行都可）。→ (rows, duplicates)：rows＝{stage: (status, detail)}，duplicates＝{stage: 列數}（只列 >1 的）。"""
    rows, count = {}, {}
    for line in lines:
        parts = line.rstrip("\r\n").split("\t", 2)
        if len(parts) < 2 or parts[0] == "stage":
            continue
        stage, new = parts[0], (parts[1], parts[2] if len(parts) > 2 else "")
        count[stage] = count.get(stage, 0) + 1
        old = rows.get(stage)
        if old is None or severity(new[0]) >= severity(old[0]):
            rows[stage] = new
    dups = {k: n for k, n in count.items() if n > 1}
    for k, n in dups.items():
        st, detail = rows[k]
        if st == "OK":
            rows[k] = ("ATTENTION", "status.tsv 有 %d 列 %s（取最嚴重的一列是 OK；重複列代表檔案被改過或寫檔有 bug，要有人看過）：%s" % (n, k, detail))
    return rows, dups


def read(path):
    """→ (rows, duplicates)；檔案讀不到 → ({}, {})。"""
    try:
        with open(path, encoding="utf-8", newline="") as f:
            return pick(f)
    except OSError:
        return {}, {}
