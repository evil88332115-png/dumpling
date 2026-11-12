"""Jetson 示範的比對與查詢：基礎版 vs 模擬客製版的差異，以及在 DT 上「哪些產品版本受影響」的三個查法。

用法：python3 -I jetson_lookup.py --scan base=<sca-scan 輸出> --scan custom=<sca-scan 輸出> --out <資料夾> [--pilot-env <pilot.env>]
輸出：<out>/lookup.json、<out>/summary.md；標準輸出每行一個階段（階段<TAB>狀態<TAB>說明），由 jetson.sh 寫進 status.tsv。

三個查法（都記 HTTP 狀態，查不到就照實寫，不推測）：
- G-lookup-component：NVIDIA 發公告時先知道的是套件名稱（例如 nvidia-l4t-core）→ DT 的 GET /api/v1/component/identity?name=…
  列出所有含這個套件的專案與版本。
- G-lookup-vuln-custom：客製版自己加的元件（模擬的 Pillow 舊版）的一個弱點 → GET /api/v1/vulnerability/source/<來源>/vuln/<ID>/projects，
  應該只有客製版。
- G-lookup-vuln-shared：基礎版的 Ubuntu 套件弱點（DT 有的話取 CVSS 最高的一筆）→ 同一個 API，應該兩版都有。
  DT 沒有任何 deb 的 finding（例如 OSV 沒有 Ubuntu 生態系或 mirror 沒完成）→ GAP，只列 Grype 的結果。
DT 金鑰從 pilot.env 讀（只讀 DT_URL、DT_API_KEY 兩個鍵，不 source），不出現在指令列與輸出。
"""
import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

NVIDIA_PKG = "nvidia-l4t-core"
CUSTOM_PY = "pillow"


def load(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def read_env(path):
    out = {}
    if not path or not os.path.isfile(path):
        return out
    for line in open(path, encoding="utf-8"):
        m = re.match(r"^\s*(?:export\s+)?(DT_URL|DT_API_KEY)=(.*)$", line.rstrip("\r\n"))
        if m:
            v = m.group(2)
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                v = v[1:-1]
            out[m.group(1)] = v
    url = out.get("DT_URL", "").rstrip("/")
    out["DT_URL"] = url[:-4] if url.endswith("/api") else url
    return out


class DT:
    def __init__(self, env):
        self.url, self.key = env.get("DT_URL", ""), env.get("DT_API_KEY", "")

    def ok(self):
        return bool(self.url and self.key)

    def get(self, path):
        req = urllib.request.Request(self.url + path, headers={"X-Api-Key": self.key, "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                return r.status, json.loads(r.read() or b"null")
        except urllib.error.HTTPError as e:
            return e.code, None
        except (urllib.error.URLError, OSError, ValueError) as e:
            return f"錯誤 {type(e).__name__}", None


def scan_facts(d):
    """sca-scan 輸出資料夾 → 元件、Grype 弱點、DT finding、DT 專案。"""
    sbom = load(os.path.join(d, "sbom", "sbom.cdx.json"), {}) or {}
    comps = {}
    stack = list(sbom.get("components") or [])
    while stack:
        c = stack.pop()
        stack.extend(c.get("components") or [])
        if c.get("type") == "file":
            continue
        purl = c.get("purl") or ""
        kind = purl[4:].split("/", 1)[0] if purl.startswith("pkg:") else "?"
        comps[(kind, c.get("name", ""), c.get("version", ""))] = purl
    grype = load(os.path.join(d, "scan", "grype.json"), {}) or {}
    gv = {}
    for m in grype.get("matches") or []:
        a, v = m.get("artifact") or {}, m.get("vulnerability") or {}
        gv.setdefault(v.get("id", ""), set()).add((a.get("type", ""), a.get("name", ""), a.get("version", "")))
    meta = load(os.path.join(d, "meta.json"), {}) or {}
    stages = {}
    try:
        for line in open(os.path.join(d, "status.tsv"), encoding="utf-8").read().splitlines()[1:]:
            f = line.split("\t")
            if len(f) >= 2:
                stages[f[0]] = f[1]
    except OSError:
        pass
    return {"stages": stages, "components": comps, "grype": gv, "dt_findings": load(os.path.join(d, "dt", "findings.json"), []) or [],
            "dt_project": meta.get("dt_project_uuid", ""), "name": meta.get("name", ""), "version": meta.get("version", "")}


def projects_of(rows):
    return sorted({(r.get("name", ""), r.get("version", "")) for r in rows if isinstance(r, dict)})


def cvss(f):
    v = f.get("vulnerability") or {}
    for k in ("cvssV3BaseScore", "cvssV4BaseScore", "cvssV2BaseScore"):
        try:
            return float(v[k])
        except (KeyError, TypeError, ValueError):
            continue
    return -1.0


def vuln_projects(dt, f):
    v = f.get("vulnerability") or {}
    src, vid = v.get("source", ""), v.get("vulnId", "")
    st, data = dt.get(f"/api/v1/vulnerability/source/{urllib.parse.quote(src)}/vuln/{urllib.parse.quote(vid)}/projects")
    return {"source": src, "vuln": vid, "component": (f.get("component") or {}).get("name", ""), "http": st,
            "projects": [list(p) for p in projects_of(data)] if st == 200 and isinstance(data, list) else None}


def run(scans, env_path):
    lines, res = [], {}
    st = lambda s, k, d: lines.append((s, k, d))  # noqa: E731
    base, cust = scans["base"], scans["custom"]
    who = {(x["name"], x["version"]): k for k, x in scans.items()}

    added = sorted(set(cust["components"]) - set(base["components"]))
    removed = sorted(set(base["components"]) - set(cust["components"]))
    gonly = sorted(set(cust["grype"]) - set(base["grype"]))
    res["diff"] = {"components_added": [list(x) for x in added], "components_removed": [list(x) for x in removed],
                   "grype_only_custom": {k: sorted(map(list, cust["grype"][k])) for k in gonly},
                   "counts": {k: {"components": len(x["components"]), "grype_ids": len(x["grype"]),
                                  "dt_findings": len(x["dt_findings"])} for k, x in scans.items()}}
    if not base["components"] or not cust["components"]:
        st("G-diff", "FAIL", "基礎版或客製版沒有 SBOM 元件，無法比對")
    else:
        st("G-diff", "OK", f"客製版多 {len(added)} 個元件、少 {len(removed)} 個；只在客製版出現的 Grype 弱點 ID {len(gonly)} 個")

    nv = {k: sorted(v for (t, n, v) in x["components"] if n == NVIDIA_PKG) for k, x in scans.items()}
    res["nvidia_versions_in_sbom"] = nv
    env = read_env(env_path)
    dt = DT(env)
    # sca-scan 沒有把 SBOM 上傳 DT 並讀回 finding（--no-upload、上傳失敗…）時，DT 查不到不代表沒有：不查，記 NOT_RUN
    notready = [f"{k} 的 D-dt-findings={x['stages'].get('D-dt-findings', '無')}" for k, x in scans.items()
                if x["stages"].get("D-dt-findings") not in ("OK", "GAP")]
    if not dt.ok() or notready:
        why = "沒有 pilot.env 或缺 DT_URL／DT_API_KEY" if not dt.ok() else f"DT 的上傳或分析沒有完成（{'、'.join(notready)}）"
        for s in ("G-lookup-component", "G-lookup-vuln-custom", "G-lookup-vuln-shared"):
            st(s, "NOT_RUN", why)
        return lines, res

    code, data = dt.get("/api/v1/component/identity?" + urllib.parse.urlencode({"name": NVIDIA_PKG}))
    rows = []
    if code == 200 and isinstance(data, list):
        for c in data:
            p = c.get("project") or {}
            rows.append({"project": p.get("name", ""), "project_version": p.get("version", ""), "name": c.get("name", ""),
                         "classifier": c.get("classifier", ""), "component_version": c.get("version", "")})
    # DT 的 name 是部分比對：套件附帶的檔案（/usr/share/doc/<套件>/…，classifier FILE）也會出現，只算同名的套件
    pkgs = [r for r in rows if r["name"] == NVIDIA_PKG and r["classifier"] != "FILE"]
    res["lookup_component"] = {"name": NVIDIA_PKG, "http": code, "rows": rows, "packages": pkgs}
    hit = {who.get((r["project"], r["project_version"])) for r in pkgs} - {None}
    if code != 200:
        st("G-lookup-component", "FAIL", f"component/identity http={code}")
    elif hit == {"base", "custom"}:
        st("G-lookup-component", "OK", f"{NVIDIA_PKG}：DT 找到 {len(pkgs)} 個同名套件（另有 {len(rows) - len(pkgs)} 筆是名稱相近的檔案），"
                                       f"含基礎版與客製版（版本 {', '.join(sorted({r['component_version'] for r in pkgs})) or '無'}）")
    else:
        st("G-lookup-component", "ATTENTION", f"{NVIDIA_PKG}：DT 找到的這次專案是 {sorted(hit) or '無'}（預期兩版都有；SBOM 裡 基礎版 {nv['base'] or '無'}、客製版 {nv['custom'] or '無'}）")

    cf = [f for f in cust["dt_findings"] if (f.get("component") or {}).get("name", "").lower() == CUSTOM_PY]
    if not cf:
        st("G-lookup-vuln-custom", "GAP", f"DT 在客製版沒有 {CUSTOM_PY} 的 finding（Grype 只在客製版的 ID：{len(gonly)} 個）")
    else:
        f = sorted(cf, key=lambda f: (-cvss(f), (f.get("vulnerability") or {}).get("vulnId", "")))[0]
        r = vuln_projects(dt, f)
        res["lookup_vuln_custom"] = r
        got = {who.get(tuple(p)) for p in r["projects"] or []} - {None}
        if r["projects"] is None:
            st("G-lookup-vuln-custom", "FAIL", f"{r['vuln']} 的 projects http={r['http']}")
        elif got == {"custom"}:
            st("G-lookup-vuln-custom", "OK", f"{r['vuln']}（{r['component']}）：受影響的只有客製版")
        else:
            st("G-lookup-vuln-custom", "ATTENTION", f"{r['vuln']}（{r['component']}）：DT 回傳這次的專案 {sorted(got) or '無'}（預期只有客製版）")

    bf = [f for f in base["dt_findings"] if (f.get("component") or {}).get("purl", "").startswith("pkg:deb/")]
    if not bf:
        n = sum(1 for k, s in base["grype"].items() if any(t == "deb" for t, _, _ in s))
        st("G-lookup-vuln-shared", "GAP", f"DT 在基礎版沒有任何 deb 套件的 finding（Grype 有 {n} 個 deb 弱點 ID）：DT 的 Ubuntu 弱點資料不可用或不完整")
    else:
        f = sorted(bf, key=lambda f: (-cvss(f), (f.get("vulnerability") or {}).get("vulnId", "")))[0]
        r = vuln_projects(dt, f)
        res["lookup_vuln_shared"] = r
        got = {who.get(tuple(p)) for p in r["projects"] or []} - {None}
        if r["projects"] is None:
            st("G-lookup-vuln-shared", "FAIL", f"{r['vuln']} 的 projects http={r['http']}")
        elif got == {"base", "custom"}:
            st("G-lookup-vuln-shared", "OK", f"{r['vuln']}（{r['component']}，CVSS {cvss(f) if cvss(f) >= 0 else '無'}）：基礎版與客製版都受影響")
        else:
            st("G-lookup-vuln-shared", "ATTENTION", f"{r['vuln']}（{r['component']}）：DT 回傳這次的專案 {sorted(got) or '無'}（預期兩版都有）")
    return lines, res


def summary(lines, res, scans, release="39.2.1"):
    c = res["diff"]["counts"]
    out = [f"# Jetson Linux R{release} 示範：基礎版與模擬客製版", "",
           "基礎版＝NVIDIA 範例根檔案系統＋BSP 的 NVIDIA 套件（只解開、登記，不執行）；客製版＝基礎版＋模擬的客戶套件。",
           "這是示範，不是實際刷機後的系統；細節見 prep.json。", "",
           "| | 基礎版 | 客製版 |", "|---|---|---|",
           f"| SBOM 元件 | {c['base']['components']} | {c['custom']['components']} |",
           f"| Grype 弱點 ID | {c['base']['grype_ids']} | {c['custom']['grype_ids']} |",
           f"| DT finding | {c['base']['dt_findings']} | {c['custom']['dt_findings']} |",
           f"| {NVIDIA_PKG} 版本 | {', '.join(res['nvidia_versions_in_sbom']['base']) or '無'} | {', '.join(res['nvidia_versions_in_sbom']['custom']) or '無'} |",
           "", "## 階段", "", "| 階段 | 狀態 | 說明 |", "|---|---|---|"]
    out += [f"| {s} | {k} | {d.replace('|', '／')} |" for s, k, d in lines]
    out += ["", "## 客製版多出的元件", ""]
    out += [f"- {t} {n} {v}" for t, n, v in res["diff"]["components_added"]] or ["- 無"]
    out += ["", "「沒找到」不等於沒有問題：查不到的原因寫在階段說明裡。", ""]
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--scan", action="append", required=True, help="base=<資料夾> 或 custom=<資料夾>")
    ap.add_argument("--out", required=True)
    ap.add_argument("--pilot-env", default="")
    ap.add_argument("--release", default="39.2.1", help="Jetson Linux 版本（只用在摘要標題）")
    a = ap.parse_args(argv)
    dirs = dict(s.split("=", 1) for s in a.scan)
    if set(dirs) != {"base", "custom"}:
        ap.error("需要 --scan base=… 與 --scan custom=…")
    scans = {k: scan_facts(v) for k, v in dirs.items()}
    lines, res = run(scans, a.pilot_env)
    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.out, "lookup.json"), "w", encoding="utf-8") as f:
        json.dump({"stages": lines, **res}, f, ensure_ascii=False, indent=1)
    with open(os.path.join(a.out, "summary.md"), "w", encoding="utf-8") as f:
        f.write(summary(lines, res, scans, a.release))
    for s, k, d in lines:
        print(f"{s}\t{k}\t{d}".replace("\n", " "))


if __name__ == "__main__":
    sys.exit(main())
