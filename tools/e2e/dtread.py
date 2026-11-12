"""從 DT 取回 finding（分頁、核對 X-Total-Count）或逐筆讀回 analysis。

用法：
  python3 -I dtread.py findings <專案 UUID> <輸出.json>
  python3 -I dtread.py readback <專案 UUID> <輸出.json>
環境變數 DT、DT_API_KEY。取不完整（筆數與 X-Total-Count 不同、任何 analysis 讀取不是 200/404）時退出碼 1，
輸出仍寫出已取得的部分，讓呼叫端記 FAIL 而不是當作完整。
"""
import json
import os
import sys
import urllib.error
import urllib.request

DT, KEY = os.environ["DT"], os.environ["DT_API_KEY"]


def get(path):
    req = urllib.request.Request(DT + path, headers={"X-Api-Key": KEY})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.status, r.headers, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, e.headers, None
    except (urllib.error.URLError, OSError, ValueError) as e:   # 逾時、連線錯誤、回應不是 JSON：當作不完整，不丟 traceback
        return f"錯誤 {type(e).__name__}", {}, None


def findings(pu):
    out, page, total = [], 1, None
    while True:
        st, hd, data = get(f"/api/v1/finding/project/{pu}?suppressed=true&pageSize=100&pageNumber={page}")
        if st != 200 or not isinstance(data, list):
            return out, f"HTTP {st}"
        try:
            total = int(hd.get("X-Total-Count", -1))
        except (TypeError, ValueError):
            return out, "X-Total-Count 不是數字"
        out += data
        if len(out) >= total or not data:
            break
        page += 1
    return out, None if len(out) == total else f"X-Total-Count={total} 但取得 {len(out)}"


mode, pu, path = sys.argv[1:4]
fs, err = findings(pu)
if mode == "findings":
    res = fs
else:
    res = []
    for f in fs:
        c, v = f["component"], f["vulnerability"]
        st, _, a = get(f"/api/v1/analysis?project={pu}&component={c['uuid']}&vulnerability={v['uuid']}")
        if st not in (200, 404):
            err = err or f"analysis HTTP {st}"
        res.append({"vuln": v["vulnId"], "source": v["source"], "component": f"{c['name']}@{c.get('version')}", "purl": c.get("purl"),
                    "analysis_http": st, "analysis": a, "finding_analysis": f.get("analysis")})
json.dump(res, open(path, "w"), indent=1, ensure_ascii=False)
print(f"{mode} {len(res)} 筆" + (f"；不完整：{err}" if err else ""))
sys.exit(1 if err else 0)
