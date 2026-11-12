#!/usr/bin/env python3
"""usn_cves.py：DT findings 裡沒有 CVE 別名的 Ubuntu 安全公告（OSV 的 USN-…），從 Ubuntu 的 OSV 鏡像查它列出的 CVE
（sca-scan 的 D-usn-cves）。寫 scan/usn-cves.json，並印一行 status：
  D-usn-cves<TAB>狀態<TAB>說明

用法：python3 -I usn_cves.py --findings <dt/findings.json[.xz]> [--mirror <OSV 發行版鏡像>] [--max-age-days N] --out <scan/usn-cves.json>
  --mirror 與 --max-age-days 和 distro_recheck.py 相同（PILOT_ENV 的 OSV_DISTRO_MIRROR；同一個 Mirror 類別，檢查 SOURCE 的新舊與 sha256）。
退出碼：0 已處理（OK／NOT_RUN）；3 輸入錯誤（同時印 FAIL 那一行）。原始的 findings 不改。

為什麼：DT 的 OSV 資料裡有些 USN 沒有 CVE 別名（例如 brotli 原始碼套件上的 OSV:USN-8956-1），同一個問題在同一個元件上
另有 CVE 的 finding，cra_report 原本把 USN 另列一列（多一列沒有判定的）。這裡只記「USN → CVE」的對應，cra_report.py 用它把 USN 的
finding 併進同一個元件版本上那個 CVE 的列（來源編號保留）。只用紀錄的 upstream 與 aliases，不用 related（distro_recheck.py 的說明：
213 個 USN 只在 related 列 CVE，多半是 regression 公告）。撤回的紀錄不用。
另記 fixed：{USN: [{ecosystem, package, fixed: [版本]}]}（紀錄的 affected 裡一般 Ubuntu 版本的原始碼套件與 ECOSYSTEM 範圍的 fixed；
沒有 CVE 的 USN 也記）。cra_report 用它推出自成一列的 USN 的修補狀態（apply_usn_fix：USN 是 Ubuntu 發布修補版本的公告）。
狀態：沒有不帶 CVE 的 USN → NOT_RUN（不寫檔案；sca-scan 不寫這一列）；有，但沒有鏡像、過期或不完整 → NOT_RUN 並寫檔案
（status NOT_RUN 與原因；cra_report 只用 status OK 的檔案，報告寫明對應不可用）；其他 → OK（鏡像沒有的 USN 列在 not_found）。
鏡像的資料不可信：只解析，單筆紀錄有大小上限（distro_recheck.MAX_RECORD），每個 USN 最多收 MAX_CVES 個 CVE、最多查 MAX_USNS 個 USN。
"""
import argparse
import datetime
import importlib.util
import json
import os
import re
import sys
from pathlib import Path

STAGE = "D-usn-cves"
SCHEMA = "sca-center-usn-cves/1"
HERE = Path(__file__).resolve().parent
MAX_USNS = 20000
MAX_CVES = 1000
MAX_FIXED = 200          # 每個 USN 最多收幾筆 (發行版, 套件) 的修補版本
UBUNTU_ECO = re.compile(r"^Ubuntu:\d+\.\d+(?::LTS)?$")     # 一般的 Ubuntu 版本（Ubuntu:Pro:… 的 ESM 不收）
PKG_NAME = re.compile(r"^[a-z0-9][a-z0-9.+-]{0,127}$")
VER_TEXT = re.compile(r"^[A-Za-z0-9.+~:-]{1,128}$")
CVE_IN = re.compile(r"^(?:UBUNTU-)?(CVE-\d{4}-\d{4,})$")


def line(st, detail):
    print(f"{STAGE}\t{st}\t" + re.sub(r"[\t\r\n]+", " ", str(detail))[:900])


def drc():
    """distro_recheck.py（Mirror、load、libs）：python3 -I 不把這個資料夾放進 sys.path，所以依路徑載入。"""
    spec = importlib.util.spec_from_file_location("sca_center_distro_recheck", HERE / "distro_recheck.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def fixed_of(d):
    """USN 的 OSV 紀錄 → [{ecosystem, package, fixed: [版本]}]：affected 裡一般 Ubuntu 版本（Ubuntu:24.04:LTS 等，Pro 不收）的原始碼套件
    與 ECOSYSTEM 範圍的 fixed 事件。格式不對的筆略過（鏡像資料不可信，只解析）；最多 MAX_FIXED 筆。"""
    out = {}
    for a in d.get("affected") or []:
        if not isinstance(a, dict) or not isinstance(a.get("package"), dict):
            continue
        eco, name = a["package"].get("ecosystem"), a["package"].get("name")
        if not isinstance(eco, str) or not UBUNTU_ECO.match(eco) or not isinstance(name, str) or not PKG_NAME.match(name):
            continue
        vs = {e["fixed"] for r in a.get("ranges") or [] if isinstance(r, dict) and r.get("type") == "ECOSYSTEM"
              for e in r.get("events") or [] if isinstance(e, dict) and isinstance(e.get("fixed"), str) and VER_TEXT.match(e["fixed"])}
        if vs:
            out.setdefault((eco, name), set()).update(vs)
    return [{"ecosystem": e, "package": n, "fixed": sorted(v)} for (e, n), v in sorted(out.items())][:MAX_FIXED]


def usn_cves(findings, mirror_path, max_age, dr=None):
    """回傳 (狀態, 說明, 輸出 JSON 或 None)。"""
    dr = dr or drc()
    cra = dr.libs()[0]
    if not isinstance(findings, list):
        raise dr.InputError("DT findings 不是清單")
    wanted = sorted(cra.usn_without_cve(findings))
    if not wanted:
        return "NOT_RUN", "沒有不帶 CVE 別名的 USN", None
    if len(wanted) > MAX_USNS:
        raise dr.InputError(f"不帶 CVE 的 USN 超過 {MAX_USNS} 個（{len(wanted)}）")
    mir = dr.Mirror(mirror_path, {"Ubuntu"}, max_age)
    out = {"schema": SCHEMA, "stage": STAGE, "generated": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "mirror": mir.state, "usns": {}, "fixed": {}, "not_found": [], "withdrawn": [], "no_cve": []}
    if not mir.state["ok"]:
        detail = f"不帶 CVE 別名的 USN {len(wanted)} 個沒有對到 CVE（{mir.state['reason']}），各自成列"
        out.update(status="NOT_RUN", detail=detail, counts={"usns": len(wanted)})
        return "NOT_RUN", detail, out
    for u in wanted:
        d = mir._read("Ubuntu", f"{u}.json")
        if d is None or str(d.get("id") or "").upper() != u:
            out["not_found"].append(u)
            continue
        if d.get("withdrawn"):
            out["withdrawn"].append(u)
            continue
        fx = fixed_of(d)
        if fx:
            out["fixed"][u] = fx
        cves = set()
        for x in (d.get("upstream") or []) + (d.get("aliases") or []):   # related 不算
            m = CVE_IN.match(str(x))
            if m:
                cves.add(m.group(1))
        if not cves:
            out["no_cve"].append(u)
            continue
        out["usns"][u] = {"cves": sorted(cves)[:MAX_CVES], "modified": str(d.get("modified") or "")[:40] or None}
    n = len(out["usns"])
    out["counts"] = {"usns": len(wanted), "mapped": n, "not_found": len(out["not_found"]), "withdrawn": len(out["withdrawn"]),
                     "no_cve": len(out["no_cve"]), "with_fixed": len(out["fixed"])}
    detail = (f"不帶 CVE 別名的 USN {len(wanted)} 個：對到 CVE {n}、鏡像沒有 {len(out['not_found'])}、撤回 {len(out['withdrawn'])}、"
              f"紀錄沒有 CVE {len(out['no_cve'])}（scan/usn-cves.json；鏡像 fetched_utc={mir.state.get('fetched_utc')}；原始 findings 不變）")
    out.update(status="OK", detail=detail)
    return "OK", detail, out


def main(argv=None):
    ap = argparse.ArgumentParser(description="沒有 CVE 別名的 USN → CVE（Ubuntu OSV 鏡像；D-usn-cves）")
    ap.add_argument("--findings", required=True)
    ap.add_argument("--mirror")
    ap.add_argument("--max-age-days", type=float, default=None)
    ap.add_argument("--out", required=True)
    try:
        a = ap.parse_args(argv)
    except SystemExit:
        line("FAIL", "usn_cves.py 參數錯誤")
        return 3
    try:
        dr = drc()
        max_age = a.max_age_days if a.max_age_days is not None else float(os.environ.get("OSV_DISTRO_MAX_AGE_DAYS") or 3)
        st, detail, out = usn_cves(dr.load(a.findings, "DT findings"), a.mirror, max_age, dr)
    except Exception as e:      # 含 InputError：記 FAIL，不讓掃描中斷、不印 traceback
        line("FAIL", f"usn_cves.py 無法處理（{e if type(e).__name__ == 'InputError' else type(e).__name__}）")
        return 3
    if out is not None:
        try:
            with open(a.out, "w", encoding="utf-8") as f:
                json.dump(out, f, ensure_ascii=False, indent=1)
        except OSError as e:
            line("FAIL", f"無法寫入 {a.out}（{type(e).__name__}）")
            return 3
    line(st, detail)
    return 0


if __name__ == "__main__":
    sys.exit(main())
