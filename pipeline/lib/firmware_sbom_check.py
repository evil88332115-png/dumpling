"""供應商 BIOS SBOM 的品質檢查（只讀；SBOM 檔案當不可信資料，不執行）。

用法：python3 -I firmware_sbom_check.py <sbom.json>... --out <資料夾>
環境變數 SBOMQS：sbomqs 執行檔路徑（預設 PATH 上的 sbomqs）。

每個 SBOM 印一行：FIRMWARE-SBOM<TAB>OK|ATTENTION|GAP|FAIL<TAB><檔名><TAB>說明
  FAIL      基本檢查失敗（讀不到、太大、不是合法 JSON、不是 CycloneDX／SPDX JSON）
  GAP       沒有元件，或全部元件都沒有版本（讀不到版本的元件不猜）
  ATTENTION 有元件缺版本，或缺 purl／cpe
  OK        基本檢查沒有發現缺漏（不代表安全；漏洞比對 NOT_RUN）
sbomqs 分數只寫在說明裡當參考，不影響狀態（門檻是政策問題，尚未決定）。
有 FAIL 就以非 0 結束。另寫 <out>/sbom-check.md 與 <out>/<檔名>.sbomqs.json。
"""
import argparse
import json
import os
import re
import stat
import subprocess
import sys

MAX_SIZE = 50 * 1024 * 1024
SBOMQS_TIMEOUT = 120
LIST_LIMIT = 5
NOT_RUN_VULN = "漏洞比對：NOT_RUN（上傳 DT 待臨時 DT 工具）"


def clean(s, limit=80):
    """去掉控制字元與分隔符，截短；檔案內容不可信，不原樣印出。"""
    s = re.sub(r"[\x00-\x1f\x7f|`]", " ", str(s)).strip()
    return s if len(s) <= limit else s[:limit - 1] + "…"


def load(path):
    """回傳 (資料, 錯誤)。"""
    try:
        st = os.lstat(path)
    except OSError as e:
        return None, "讀不到檔案（%s）" % (e.strerror or type(e).__name__)
    if not stat.S_ISREG(st.st_mode):
        return None, "不是一般檔案（拒絕）"
    if st.st_size > MAX_SIZE:
        return None, "檔案太大（%d 位元組，上限 %d）" % (st.st_size, MAX_SIZE)
    try:
        with open(path, "rb") as fh:
            raw = fh.read(MAX_SIZE + 1)
        if len(raw) > MAX_SIZE:
            return None, "檔案太大（上限 %d）" % MAX_SIZE
        return json.loads(raw.decode("utf-8")), None
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None, "不是合法的 JSON"
    except OSError as e:
        return None, "讀不到檔案（%s）" % (e.strerror or type(e).__name__)


def _walk_cdx(comps, out, depth=0):
    if not isinstance(comps, list) or depth > 50:
        return
    for c in comps:
        if isinstance(c, dict):
            out.append(c)
            _walk_cdx(c.get("components"), out, depth + 1)


def components_of(doc):
    """回傳 (格式, 規格版本, [{name, version, purl, cpe}])；不認得回 (None, None, None)。"""
    if not isinstance(doc, dict):
        return None, None, None
    if doc.get("bomFormat") == "CycloneDX" and isinstance(doc.get("specVersion"), str):
        raw = []
        _walk_cdx(doc.get("components"), raw)
        comps = [{"name": c.get("name"), "version": c.get("version"),
                  "purl": c.get("purl"), "cpe": c.get("cpe")} for c in raw]
        return "CycloneDX", doc["specVersion"], comps
    sv = doc.get("spdxVersion")
    if isinstance(sv, str) and sv.startswith("SPDX-"):
        pk = doc.get("packages")
        comps = []
        for p in pk if isinstance(pk, list) else []:
            if not isinstance(p, dict):
                continue
            purl = cpe = None
            for r in p.get("externalRefs") or []:
                if isinstance(r, dict):
                    t = r.get("referenceType")
                    if t == "purl":
                        purl = r.get("referenceLocator")
                    elif t in ("cpe22Type", "cpe23Type"):
                        cpe = r.get("referenceLocator")
            comps.append({"name": p.get("name"), "version": p.get("versionInfo"),
                          "purl": purl, "cpe": cpe})
        return "SPDX", sv, comps
    return None, None, None


def _has(v):
    return isinstance(v, str) and v.strip() != ""


def basic_check(doc):
    """回傳 dict：fmt、spec、count、no_version／no_purl／no_cpe（名稱清單）；格式不認得時 fmt 是 None。"""
    fmt, spec, comps = components_of(doc)
    if fmt is None:
        return {"fmt": None}
    label = lambda c: clean(c["name"]) if _has(c["name"]) else "(無名稱)"
    return {
        "fmt": fmt, "spec": spec, "count": len(comps),
        "no_version": [label(c) for c in comps if not _has(c["version"])],
        "no_purl": [label(c) for c in comps if not _has(c["purl"])],
        "no_cpe": [label(c) for c in comps if not _has(c["cpe"])],
    }


def judge(b):
    """依基本檢查結果回傳 (狀態, 說明)。不看 sbomqs 分數。"""
    if b["fmt"] is None:
        return "FAIL", "不是 CycloneDX 或 SPDX JSON（不認得的格式）"
    head = "%s %s，%d 個元件" % (b["fmt"], clean(b["spec"], 20), b["count"])
    if b["count"] == 0:
        return "GAP", head + "；沒有元件可檢查"
    nv, np_, nc = len(b["no_version"]), len(b["no_purl"]), len(b["no_cpe"])
    if nv == b["count"]:
        return "GAP", head + "；全部元件都沒有版本（不猜）"
    parts = []
    if nv:
        parts.append("%d 個元件缺版本（%s）" % (nv, _names(b["no_version"])))
    if np_:
        parts.append("%d 個缺 purl（%s）" % (np_, _names(b["no_purl"])))
    if nc:
        parts.append("%d 個缺 cpe（%s）" % (nc, _names(b["no_cpe"])))
    if parts:
        return "ATTENTION", head + "；" + "；".join(parts)
    return "OK", head + "；每個元件都有版本、purl 與 cpe"


def _names(lst):
    s = "、".join(lst[:LIST_LIMIT])
    return s + (" 等" if len(lst) > LIST_LIMIT else "")


def run_sbomqs(path, raw_out):
    """跑 sbomqs score --json；回傳 (摘要 dict 或 None, 錯誤或 None)。原始輸出寫到 raw_out。"""
    exe = os.environ.get("SBOMQS") or "sbomqs"
    env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR")}
    try:
        r = subprocess.run([exe, "score", "--json", "--", path], stdin=subprocess.DEVNULL,
                           capture_output=True, text=True, timeout=SBOMQS_TIMEOUT, env=env)
    except FileNotFoundError:
        return None, "找不到 sbomqs"
    except subprocess.TimeoutExpired:
        return None, "sbomqs 逾時"
    except OSError as e:
        return None, "sbomqs 無法執行（%s）" % (e.strerror or type(e).__name__)
    if r.returncode != 0:
        return None, "sbomqs 失敗（exit %d）" % r.returncode
    try:
        data = json.loads(r.stdout)
        f = data["files"][0]
        score = float(f["sbom_quality_score"])
        cats = []
        for c in f.get("comprehenssive") or f.get("comprehensive") or []:
            cats.append((clean(c.get("category"), 40), float(c.get("score"))))
        summary = {"score": score, "grade": clean(f.get("grade", ""), 4), "categories": cats,
                   "version": clean((data.get("creation_info") or {}).get("version", ""), 20)}
    except (ValueError, KeyError, IndexError, TypeError):
        return None, "sbomqs 輸出無法解讀"
    with open(raw_out, "w", encoding="utf-8") as fh:
        fh.write(r.stdout)
    return summary, None


def check_one(path, out_dir, used):
    """回傳 dict：file、status、msg、basic、qs、qs_err。"""
    name = clean(os.path.basename(path), 120) or "?"
    res = {"file": name, "basic": None, "qs": None, "qs_err": None}
    doc, err = load(path)
    if err:
        res.update(status="FAIL", msg=err)
        return res
    b = basic_check(doc)
    del doc
    res["basic"] = b
    status, msg = judge(b)
    res["status"] = status
    if b["fmt"] is not None:
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(path))[:100] or "sbom"
        n, base = used.get(safe, 0), safe
        used[safe] = n + 1
        if n:
            base = "%d-%s" % (n, safe)
        qs, qerr = run_sbomqs(path, os.path.join(out_dir, base + ".sbomqs.json"))
        res["qs"], res["qs_err"] = qs, qerr
        if qs:
            msg += "；sbomqs %s 分數 %.1f（%s，僅供參考）" % (qs["version"], qs["score"], qs["grade"])
        else:
            msg += "；sbomqs：NOT_RUN（%s）" % qerr
    res["msg"] = msg + "；" + NOT_RUN_VULN
    return res


def md_cell(s):
    return str(s).replace("|", "\\|").replace("\n", " ")


def write_md(results, path):
    lines = ["# 供應商 SBOM 品質檢查", "",
             "| 狀態 | 檔案 | 說明 |", "|---|---|---|"]
    for r in results:
        lines.append("| %s | %s | %s |" % (r["status"], md_cell(r["file"]), md_cell(r["msg"])))
    for r in results:
        lines += ["", "## " + r["file"], "", "- 狀態：%s" % r["status"]]
        b = r["basic"]
        if b and b["fmt"]:
            lines.append("- 格式：%s %s；元件數 %d" % (b["fmt"], clean(b["spec"], 20), b["count"]))
            for label, key in (("缺版本", "no_version"), ("缺 purl", "no_purl"), ("缺 cpe", "no_cpe")):
                lines.append("- %s：%d%s" % (label, len(b[key]),
                             "（" + _names(b[key]) + "）" if b[key] else ""))
        else:
            lines.append("- " + r["msg"].split("；")[0])
        if r["qs"]:
            q = r["qs"]
            lines += ["- sbomqs %s 分數 %.2f／10（等級 %s；僅供參考，不決定狀態）" % (q["version"], q["score"], q["grade"]), "",
                      "| sbomqs 類別 | 分數 |", "|---|---|"]
            lines += ["| %s | %.2f |" % (md_cell(n), s) for n, s in q["categories"]]
        elif b and b["fmt"]:
            lines.append("- sbomqs：NOT_RUN（%s）" % r["qs_err"])
        lines += ["", "- " + NOT_RUN_VULN]
    lines += ["", "_狀態只反映上述基本檢查；沒有整體通過或安全的結論。sbomqs 分數沒有設門檻（政策未定）。_", ""]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


def main(argv=None):
    ap = argparse.ArgumentParser(description="供應商 SBOM 品質檢查")
    ap.add_argument("sboms", nargs="+")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    os.makedirs(args.out, exist_ok=True)
    results, used = [], {}
    for p in args.sboms:
        r = check_one(p, args.out, used)
        results.append(r)
        print("FIRMWARE-SBOM\t%s\t%s\t%s" % (r["status"], r["file"], r["msg"].replace("\t", " ").replace("\n", " ")), flush=True)
    write_md(results, os.path.join(args.out, "sbom-check.md"))
    return 1 if any(r["status"] == "FAIL" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
