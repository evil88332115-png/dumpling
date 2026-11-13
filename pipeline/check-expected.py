#!/usr/bin/env python3
"""標準答案比對：把 scan.json（掃描結果的摘要）和固定的標準答案（tests/expected/<專案>/<版本>.json）逐項比，不符就失敗並印出差在哪。

用法：python3 -I pipeline/check-expected.py <標準答案.json> <scan.json>
標準答案格式：
  {"schema": 1, "project": …, "version": …, "note": "…",
   "checks": {"<scan.json 裡的點分路徑>": {"equals": 值} | {"min": 數字, "max": 數字} | {"in": [值…]}, "reason": "為什麼這樣訂（範圍的理由）"}}
規則：
- 路徑在 scan.json 裡找不到 = FAIL（不是略過）；值是 null 也 FAIL（除非 equals 就是 null）。
- 漏洞數會隨資料庫更新而變，所以用範圍或下限；元件數、核心版本、狀態用 equals（資料庫更新不會讓它們變）。
- 結束碼 0＝全部符合、1＝有不符、64＝用法或檔案格式錯誤。最後一行 `expected: OK｜FAIL（說明）`。
"""
import json
import sys


def lookup(doc, path):
    cur = doc
    for k in path.split("."):
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        else:
            return False, None
    return True, cur


def check_one(path, spec, actual_doc):
    found, val = lookup(actual_doc, path)
    if not found:
        return False, "scan.json 沒有 %s" % path
    ops = [k for k in ("equals", "min", "max", "in") if k in spec]
    if not ops:
        return False, "標準答案的 %s 沒有 equals／min／max／in" % path
    probs = []
    if "equals" in spec and val != spec["equals"]:
        probs.append("應為 %r，實際 %r" % (spec["equals"], val))
    if "in" in spec and val not in spec["in"]:
        probs.append("應為 %r 其中之一，實際 %r" % (spec["in"], val))
    if "min" in spec or "max" in spec:
        if isinstance(val, bool) or not isinstance(val, (int, float)):
            probs.append("應為數字，實際 %r" % (val,))
        else:
            if "min" in spec and val < spec["min"]:
                probs.append("實際 %s 低於下限 %s" % (val, spec["min"]))
            if "max" in spec and val > spec["max"]:
                probs.append("實際 %s 高於上限 %s" % (val, spec["max"]))
    return (not probs), "；".join(probs) if probs else "實際 %r" % (val,)


def run(expected, actual):
    """→ (全部符合?, [(路徑, 符合?, 說明)])。"""
    results = []
    for path, spec in sorted(expected["checks"].items()):
        ok, msg = check_one(path, spec, actual)
        results.append((path, ok, msg))
    return all(r[1] for r in results), results


def main(argv):
    if len(argv) != 2:
        print(__doc__)
        return 64
    try:
        expected = json.load(open(argv[0], encoding="utf-8"))
        actual = json.load(open(argv[1], encoding="utf-8"))
        if expected.get("schema") != 1 or not isinstance(expected.get("checks"), dict) or not expected["checks"]:
            raise ValueError("標準答案要有 schema: 1 與非空的 checks")
        for k, v in expected["checks"].items():
            if not isinstance(v, dict):
                raise ValueError("%s 的內容必須是物件" % k)
    except (OSError, ValueError) as e:
        print("expected: FAIL（讀不了檔案或格式不對：%s）" % e)
        return 64
    for key in ("project", "version"):
        if key in expected and expected[key] != actual.get(key):
            print("expected: FAIL（標準答案是 %s %r，掃描結果是 %r）" % (key, expected[key], actual.get(key)))
            return 1
    ok, results = run(expected, actual)
    for path, good, msg in results:
        print("  %s %s：%s" % ("符合" if good else "不符", path, msg))
    bad = [r[0] for r in results if not r[1]]
    if ok:
        print("expected: OK（%d 項都在允許範圍內）" % len(results))
        return 0
    print("expected: FAIL（%d 項不符：%s）" % (len(bad), "、".join(bad)))
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
