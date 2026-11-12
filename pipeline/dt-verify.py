#!/usr/bin/env python3
"""臨時 DT 的驗證：專案存在、元件數、漏洞數（依 purl 類型），輸出 JSON 與 Markdown 摘要。

用法（環境變數 PILOT_ENV 指向 dt-ephemeral.sh env 產生的 pilot.env）：
  python3 -I pipeline/dt-verify.py upload <sbom.json> <名稱> <版本>      直接用 DT API 上傳（tools/pilot/sca-scan 還沒整合時的後備）
  python3 -I pipeline/dt-verify.py verify <expected.json> <輸出資料夾>    等弱點分析完成後驗證；有任何檢查不符 → 結束碼 1

不印也不寫 API key。沒做到的檢查標 NOT_RUN；不輸出整體 PASS 或「安全」。
"""
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


def load_env(path):
    env = {}
    for line in open(path, encoding="utf-8"):
        line = line.rstrip("\n")
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            env[k] = v
    return env


ENV = load_env(os.environ["PILOT_ENV"])
DT = ENV["DT_URL"].rstrip("/").removesuffix("/api")
KEY = ENV["DT_API_KEY"]


def call(method, path, body=None, headers=None):
    h = {"X-Api-Key": KEY}
    h.update(headers or {})
    req = urllib.request.Request(DT + path, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            raw = r.read()
            return r.status, r.headers, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        return e.code, e.headers, None
    except (urllib.error.URLError, OSError, ValueError) as e:
        return f"錯誤 {type(e).__name__}", {}, None


def upload(sbom, name, version):
    bom = base64.b64encode(open(sbom, "rb").read()).decode()
    body = json.dumps({"projectName": name, "projectVersion": version, "autoCreate": True, "bom": bom}).encode()
    st, _, data = call("PUT", "/api/v1/bom", body, {"Content-Type": "application/json"})
    print(f"upload: http={st}")
    return 0 if st == 200 else 1


def paged(path_fmt):
    out, page = [], 1
    while True:
        st, hd, data = call("GET", path_fmt.format(page=page))
        if st != 200 or not isinstance(data, list):
            return out, f"HTTP {st}"
        out += data
        try:
            total = int(hd.get("X-Total-Count", -1))
        except (TypeError, ValueError):
            return out, "X-Total-Count 不是數字"
        if len(out) >= total or not data:
            return out, None if len(out) == total else f"X-Total-Count={total} 但取得 {len(out)}"
        page += 1


def verify(expected_path, outdir):
    exp = json.load(open(expected_path, encoding="utf-8"))
    os.makedirs(outdir, exist_ok=True)
    checks = []  # (名稱, OK/FAIL/NOT_RUN, 說明)

    def add(name, st, detail):
        checks.append((name, st, detail))
        print(f"  {name}: {st}（{detail}）")

    q = urllib.parse.urlencode({"name": exp["project_name"], "version": exp["project_version"]})
    st, _, proj = call("GET", f"/api/v1/project/lookup?{q}")
    if st != 200 or not proj:
        add("專案存在", "FAIL", f"lookup http={st}")
        for n in ("元件數", "弱點分析完成", "漏洞總數", "依生態系的漏洞數"):
            add(n, "NOT_RUN", "專案不存在")
        return finish(exp, outdir, checks, None, {}, 0)
    uuid = proj["uuid"]
    add("專案存在", "OK", f"{exp['project_name']}@{exp['project_version']}")

    # 弱點分析是非同步的：等到專案有 lastVulnerabilityAnalysis（最多 10 分鐘）
    analysed = False
    for _ in range(120):
        st, _, p = call("GET", f"/api/v1/project/{uuid}")
        if st == 200 and p and p.get("lastVulnerabilityAnalysis"):
            analysed = True
            break
        time.sleep(5)
    add("弱點分析完成", "OK" if analysed else "FAIL", "專案有 lastVulnerabilityAnalysis" if analysed else "10 分鐘內分析未完成")

    comps, err = paged(f"/api/v1/component/project/{uuid}?pageSize=100&pageNumber={{page}}")
    n = len(comps)
    ok = err is None and n == exp["components"]
    add("元件數", "OK" if ok else "FAIL", f"預期 {exp['components']}，實際 {n}" + (f"；{err}" if err else ""))

    finds, err = paged(f"/api/v1/finding/project/{uuid}?suppressed=true&pageSize=100&pageNumber={{page}}")
    by_type, sources = {}, {}
    for f in finds:
        purl = (f.get("component") or {}).get("purl") or ""
        t = purl.split(":", 1)[-1].split("/", 1)[0] if purl.startswith("pkg:") else "unknown"
        by_type[t] = by_type.get(t, 0) + 1
        s = (f.get("vulnerability") or {}).get("source", "?")
        sources[s] = sources.get(s, 0) + 1
    total = len(finds)
    add("漏洞總數", "OK" if err is None and total >= exp["min_findings_total"] else "FAIL",
        f"至少 {exp['min_findings_total']}，實際 {total}；資料源 {sources}" + (f"；{err}" if err else ""))
    bad = [f"{t}: 至少 {m}，實際 {by_type.get(t, 0)}" for t, m in exp["min_findings_by_purl_type"].items() if by_type.get(t, 0) < m]
    add("依生態系的漏洞數", "FAIL" if bad else "OK", "；".join(bad) if bad else f"{by_type}（僅記錄：{exp.get('informational_purl_types', [])}）")
    json.dump(finds, open(os.path.join(outdir, "findings.json"), "w", encoding="utf-8"), ensure_ascii=False)
    return finish(exp, outdir, checks, proj, by_type, total, sources, n)


def finish(exp, outdir, checks, proj, by_type, total, sources=None, n=0):
    fails = [c for c in checks if c[1] == "FAIL"]
    summary = {
        "project": {"name": exp["project_name"], "version": exp["project_version"], "uuid_found": bool(proj)},
        "components": n, "findings_total": total, "findings_by_purl_type": by_type, "findings_by_source": sources or {},
        "checks": [{"name": a, "status": b, "detail": c} for a, b, c in checks],
    }
    json.dump(summary, open(os.path.join(outdir, "summary.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    with open(os.path.join(outdir, "summary.md"), "w", encoding="utf-8") as f:
        f.write("| 檢查 | 狀態 | 說明 |\n|---|---|---|\n")
        for a, b, c in checks:
            f.write(f"| {a} | {b} | {c} |\n")
    print(f"dt-verify: {len(checks) - len(fails)} 項 OK／{len(fails)} 項 FAIL／{sum(1 for c in checks if c[1] == 'NOT_RUN')} 項 NOT_RUN")
    return 1 if fails else 0


if __name__ == "__main__":
    a = sys.argv[1:]
    if len(a) == 4 and a[0] == "upload":
        sys.exit(upload(a[1], a[2], a[3]))
    if len(a) == 3 and a[0] == "verify":
        sys.exit(verify(a[1], a[2]))
    print(__doc__, file=sys.stderr)
    sys.exit(64)
