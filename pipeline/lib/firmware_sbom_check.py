"""供應商 BIOS SBOM 的品質檢查（只讀；SBOM 檔案當不可信資料，不執行）。

用法：python3 -I firmware_sbom_check.py <sbom.json>... --out <資料夾>
環境變數 SBOMQS：sbomqs 執行檔路徑（預設 PATH 上的 sbomqs）。

每個 SBOM 印一行：FIRMWARE-SBOM<TAB>OK|ATTENTION|GAP|FAIL<TAB><檔名><TAB>說明
  FAIL      基本檢查失敗（讀不到、太大、結構太多、不是合法 JSON、不是 CycloneDX／SPDX JSON）
  GAP       沒有元件，或全部元件都沒有版本（讀不到版本的元件不猜）
  ATTENTION 有元件缺版本，或缺 purl／cpe，或巢狀太深有一部分沒有檢查
  OK        基本檢查沒有發現缺漏（不代表安全；漏洞比對 NOT_RUN）
「缺」＝欄位不是字串，或去頭尾空白後（不分大小寫）是空字串或佔位值：NOASSERTION、NONE、N/A、UNKNOWN、NULL、-
（版本、purl、cpe 都一樣；SPDX 的 versionInfo: NOASSERTION 也算缺）。
sbomqs 分數只寫在說明裡當參考，不影響狀態（門檻是政策問題，尚未決定）。
結束碼：0＝沒有 FAIL（OK、ATTENTION、GAP 都是 0，跟 firmware-bios.sh 的「2＝ATTENTION／GAP」不同）；
        1＝至少一個 SBOM 是 FAIL；64＝用法錯誤（跟 repo 其他工具一致，不是 argparse 預設的 2）。
另寫 <out>/sbom-check.md 與 <out>/<檔名>.sbomqs.json。
SBOM 裡的文字（檔名、元件名稱、版本…）寫進 stdout 狀態行與 markdown 前一律經 firmware_mdsafe.md_safe。
"""
import argparse
import errno
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys

MAX_SIZE = 16 * 1024 * 1024      # 韌體 SBOM 通常只有幾十 KiB；json.loads 的記憶體約是檔案大小的幾十到上百倍
MAX_OBJECTS = 2_000_000          # 解析前用「{ 與 [ 的個數」估計物件數，超過就不解析（40 MiB 的 [{},{},…] 解析後曾用掉約 4.7 GB）
MAX_DEPTH = 50                   # CycloneDX 元件巢狀層數上限（頂層元件是第 1 層）；更深的不檢查，並標 ATTENTION
PLACEHOLDERS = frozenset(["noassertion", "none", "n/a", "unknown", "null", "-"])
SBOMQS_TIMEOUT = 120
LIST_LIMIT = 5
NOT_RUN_VULN = "漏洞比對：NOT_RUN（上傳 DT 待臨時 DT 工具）"


def _load_mdsafe():
    # python3 -I 不把腳本所在資料夾放進 sys.path，所以用路徑載入同資料夾的共用模組
    spec = importlib.util.spec_from_file_location(
        "firmware_mdsafe", os.path.join(os.path.dirname(os.path.abspath(__file__)), "firmware_mdsafe.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_mdsafe = _load_mdsafe()
clean = _mdsafe.md_safe            # clean(文字, 上限)：濾 C／Zl／Zp 類字元、markdown 特殊字元加反斜線、截短


def load(path):
    """回傳 (資料, 錯誤)。用 O_NOFOLLOW 開檔後對同一個 fd 做 fstat／讀取（沒有 lstat 到 open 之間的空窗）。"""
    try:
        # O_NONBLOCK：FIFO 沒有寫入端時 open 不會卡住（之後 fstat 會拒絕）；O_NOCTTY：不會因為開到終端機裝置而改變行程狀態
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY)
    except OSError as e:
        if e.errno == errno.ELOOP:
            return None, "不是一般檔案（符號連結，拒絕）"
        return None, "讀不到檔案（%s）" % (e.strerror or type(e).__name__)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None, "不是一般檔案（拒絕）"
        if st.st_size > MAX_SIZE:
            return None, "檔案太大（%d 位元組，上限 %d＝%d MiB）" % (st.st_size, MAX_SIZE, MAX_SIZE >> 20)
        with os.fdopen(fd, "rb", closefd=False) as fh:
            raw = fh.read(MAX_SIZE + 1)
    except OSError as e:
        return None, "讀不到檔案（%s）" % (e.strerror or type(e).__name__)
    finally:
        os.close(fd)
    if len(raw) > MAX_SIZE:
        return None, "檔案太大（上限 %d＝%d MiB）" % (MAX_SIZE, MAX_SIZE >> 20)
    n = raw.count(b"{") + raw.count(b"[")
    if n > MAX_OBJECTS:
        return None, "結構太多（{ 與 [ 共 %d 個，上限 %d；不解析，避免記憶體暴增）" % (n, MAX_OBJECTS)
    try:
        return json.loads(raw.decode("utf-8")), None
    except RecursionError:
        return None, "JSON 巢狀太深，無法解析"
    except (UnicodeDecodeError, ValueError):
        return None, "不是合法的 JSON"
    except MemoryError:
        return None, "解析時記憶體不足"


def _walk_cdx(comps, out):
    """攤平 CycloneDX 巢狀元件（不遞迴）；超過 MAX_DEPTH 層的不收，回傳 (第一個沒檢查的層數, 沒檢查的元件數) 或 None。"""
    skipped_from, skipped = None, 0
    stack = [(comps, 1)]
    while stack:
        lst, depth = stack.pop()
        if not isinstance(lst, list):
            continue
        items = [c for c in lst if isinstance(c, dict)]
        if depth > MAX_DEPTH:
            skipped_from = depth if skipped_from is None else min(skipped_from, depth)
            skipped += len(items)
            continue
        for c in items:
            out.append(c)
            if c.get("components"):
                stack.append((c.get("components"), depth + 1))
    return (skipped_from, skipped) if skipped_from is not None else None


def components_of(doc):
    """回傳 (格式, 規格版本, [{name, version, purl, cpe}], 備註清單)；不認得回 (None, None, None, [])。
    備註是「這份 SBOM 有一部分沒檢查」的說明（目前只有巢狀過深）。"""
    if not isinstance(doc, dict):
        return None, None, None, []
    if doc.get("bomFormat") == "CycloneDX" and isinstance(doc.get("specVersion"), str):
        raw, notes = [], []
        deep = _walk_cdx(doc.get("components"), raw)
        if deep:
            notes.append("巢狀過深，第 %d 層以下沒有檢查（至少 %d 個元件未計入）" % deep)
        comps = [{"name": c.get("name"), "version": c.get("version"),
                  "purl": c.get("purl"), "cpe": c.get("cpe")} for c in raw]
        return "CycloneDX", doc["specVersion"], comps, notes
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
        return "SPDX", sv, comps, []
    return None, None, None, []


def _has(v):
    """有值＝字串，且去頭尾空白後不是空字串或佔位值（PLACEHOLDERS，不分大小寫）。"""
    if not isinstance(v, str):
        return False
    t = _mdsafe.plain(v).casefold()      # plain：不可見字元（零寬空白等）換成空白再去頭尾，所以只有零寬字元的值也算缺
    return t != "" and t not in PLACEHOLDERS


def basic_check(doc):
    """回傳 dict：fmt、spec、count、no_version／no_purl／no_cpe（名稱清單）；格式不認得時 fmt 是 None。"""
    fmt, spec, comps, notes = components_of(doc)
    if fmt is None:
        return {"fmt": None}
    label = lambda c: clean(c["name"]) if _has(c["name"]) else "(無名稱)"
    return {
        "fmt": fmt, "spec": spec, "count": len(comps), "notes": notes,
        "no_version": [label(c) for c in comps if not _has(c["version"])],
        "no_purl": [label(c) for c in comps if not _has(c["purl"])],
        "no_cpe": [label(c) for c in comps if not _has(c["cpe"])],
    }


def judge(b):
    """依基本檢查結果回傳 (狀態, 說明)。不看 sbomqs 分數。"""
    if b["fmt"] is None:
        return "FAIL", "不是 CycloneDX 或 SPDX JSON（不認得的格式）"
    head = "%s %s，%d 個元件" % (b["fmt"], clean(b["spec"], 20), b["count"])
    extra = "".join("；" + n for n in b["notes"])     # 備註是固定文字，沒有 SBOM 內容
    if b["count"] == 0:
        return "GAP", head + "；沒有元件可檢查" + extra
    nv, np_, nc = len(b["no_version"]), len(b["no_purl"]), len(b["no_cpe"])
    if nv == b["count"]:
        return "GAP", head + "；全部元件都沒有版本（不猜）" + extra
    parts = list(b["notes"])
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
    # 不可信文字在進來之前已經過 clean（| 已跳脫成 \\|），這裡不能再跳脫一次；只保證沒有換行
    return str(s).replace("\r", " ").replace("\n", " ")


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


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        # argparse 預設用法錯誤是 2，會和別的工具的「2＝ATTENTION」混淆；改成 64（和 firmware-bios.sh、x86_firmware.py 一致）
        self.print_usage(sys.stderr)
        print("FIRMWARE-SBOM\tFAIL\t-\t用法錯誤：%s" % clean(message, 200), flush=True)
        self.exit(64)


def main(argv=None):
    ap = _Parser(description="供應商 SBOM 品質檢查", prog="firmware-sbom-check")
    ap.add_argument("sboms", nargs="+")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    try:
        os.makedirs(args.out, exist_ok=True)
    except OSError as e:
        print("FIRMWARE-SBOM\tFAIL\t-\t建不起輸出資料夾（%s）" % (e.strerror or type(e).__name__), flush=True)
        return 1
    results, used = [], {}
    for p in args.sboms:
        r = check_one(p, args.out, used)
        results.append(r)
        print("FIRMWARE-SBOM\t%s\t%s\t%s" % (r["status"], r["file"], r["msg"].replace("\t", " ").replace("\n", " ")), flush=True)
    write_md(results, os.path.join(args.out, "sbom-check.md"))
    return 1 if any(r["status"] == "FAIL" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
