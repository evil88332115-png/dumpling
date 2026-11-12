#!/usr/bin/env python3
"""ubuntu_priority.py：Ubuntu 套件（含 Canonical 核心）上的 CVE，從 Ubuntu 的 OSV 鏡像讀 Ubuntu 自己的 priority
（sca-scan 的 D-ubuntu-priority）。寫 scan/ubuntu-priority.json，並印一行 status：
  D-ubuntu-priority<TAB>狀態<TAB>說明

用法：python3 -I ubuntu_priority.py --findings <dt/findings.json[.xz]> [--mirror <OSV 發行版鏡像>] [--max-age-days N] --out <scan/ubuntu-priority.json>
  --mirror 與 --max-age-days 和 distro_recheck.py 相同（PILOT_ENV 的 OSV_DISTRO_MIRROR；同一個 Mirror 類別，檢查 SOURCE 的新舊與 sha256）。
退出碼：0 已處理（OK／NOT_RUN）；3 輸入錯誤（同時印 FAIL 那一行）。原始的 findings 不改。

為什麼：CRA 風險評估的 P2 依嚴重度分級。DT 對 Ubuntu 的 OSV 紀錄（UBUNTU-CVE-…）的嚴重度取自紀錄裡的 CVSS（多半就是 NVD 的），
不是 Ubuntu 的 priority；用通用的 CVSS，一份實際映像核心以外 CRITICAL／HIGH 約四百多個，用 Ubuntu priority 只剩個位數。
分級政策（使用者決定，2026-11-04）：嚴重度依供應商評級優先——NVIDIA 公告 → Ubuntu priority → NVD 的 CVSS。
這裡只收 Ubuntu priority：每個 CVE 一筆的紀錄 UBUNTU-CVE-<CVE>.json 的 severity 裡 type 是 "Ubuntu" 的 score
（negligible、low、medium、high、critical；untriaged 或沒有 → 記在 untriaged，cra_report 往下一個來源）。priority 是整個 CVE 的。
撤回的紀錄不用。
狀態：DT findings 沒有 Ubuntu 套件上的 CVE → NOT_RUN（不寫檔案；sca-scan 不寫這一列）；有，但沒有鏡像、過期或不完整 → NOT_RUN 並寫檔案
（status NOT_RUN 與原因；cra_report 只用 status OK 的檔案，報告寫明 Ubuntu priority 不可用）；其他 → OK（鏡像沒有的 CVE 列在 not_found）。
鏡像的資料不可信：只解析，單筆紀錄有大小上限（distro_recheck.MAX_RECORD），最多查 MAX_CVES 個 CVE。
"""
import argparse
import datetime
import importlib.util
import json
import os
import re
import sys
from pathlib import Path

STAGE = "D-ubuntu-priority"
SCHEMA = "sca-center-ubuntu-priority/1"
HERE = Path(__file__).resolve().parent
MAX_CVES = 100000
PRIORITIES = ("negligible", "low", "medium", "high", "critical")
UBUNTU_PURL = re.compile(r"^pkg:deb/ubuntu/", re.I)


def line(st, detail):
    print(f"{STAGE}\t{st}\t" + re.sub(r"[\t\r\n]+", " ", str(detail))[:900])


def drc():
    """distro_recheck.py（Mirror、load、libs）：python3 -I 不把這個資料夾放進 sys.path，所以依路徑載入。"""
    spec = importlib.util.spec_from_file_location("sca_center_distro_recheck", HERE / "distro_recheck.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def wanted_cves(findings, cra):
    """DT findings 裡 Ubuntu 套件（pkg:deb/ubuntu/…，含 C-kernel-l4t-map 加上的 Canonical 核心）上的 CVE（含別名的 CVE、UBUNTU-CVE-X 的 X）。"""
    out = set()
    for f in findings:
        if not isinstance(f, dict):
            continue
        c, v = f.get("component") or {}, f.get("vulnerability") or {}
        if isinstance(c, dict) and isinstance(v, dict) and UBUNTU_PURL.match(str(c.get("purl") or "")):
            out |= cra.cves_of(cra.ids_of(v))
    return out


def priority_of(rec):
    """紀錄的 severity 裡 type 是 Ubuntu 的 score（小寫）；沒有 → None。"""
    for s in rec.get("severity") or []:
        if isinstance(s, dict) and str(s.get("type") or "").lower() == "ubuntu":
            return str(s.get("score") or "").strip().lower() or None
    return None


def ubuntu_priority(findings, mirror_path, max_age, dr=None):
    """回傳 (狀態, 說明, 輸出 JSON 或 None)。"""
    dr = dr or drc()
    cra = dr.libs()[0]
    if not isinstance(findings, list):
        raise dr.InputError("DT findings 不是清單")
    wanted = sorted(wanted_cves(findings, cra))
    if not wanted:
        return "NOT_RUN", "DT findings 沒有 Ubuntu 套件上的 CVE", None
    if len(wanted) > MAX_CVES:
        raise dr.InputError(f"Ubuntu 套件上的 CVE 超過 {MAX_CVES} 個（{len(wanted)}）")
    mir = dr.Mirror(mirror_path, {"Ubuntu"}, max_age)
    out = {"schema": SCHEMA, "stage": STAGE, "generated": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "mirror": mir.state, "cves": {}, "untriaged": [], "not_found": [], "withdrawn": []}
    if not mir.state["ok"]:
        detail = f"Ubuntu 套件上的 CVE {len(wanted)} 個沒有讀 Ubuntu priority（{mir.state['reason']}），嚴重度照 DT／NVD"
        out.update(status="NOT_RUN", detail=detail, counts={"cves": len(wanted)})
        return "NOT_RUN", detail, out
    for cve in wanted:
        rid = f"UBUNTU-{cve}"
        d = mir._read("Ubuntu", f"{rid}.json")
        if d is None or str(d.get("id") or "").upper() != rid:
            out["not_found"].append(cve)
            continue
        if d.get("withdrawn"):
            out["withdrawn"].append(cve)
            continue
        p = priority_of(d)
        if p not in PRIORITIES:                 # untriaged、空的或不認得的值：往下一個來源
            out["untriaged"].append(cve)
            continue
        out["cves"][cve] = {"priority": p, "record": rid, "modified": str(d.get("modified") or "")[:40] or None}
    n = len(out["cves"])
    by = {p: sum(1 for x in out["cves"].values() if x["priority"] == p) for p in PRIORITIES}
    out["counts"] = {"cves": len(wanted), "with_priority": n, "untriaged": len(out["untriaged"]), "not_found": len(out["not_found"]),
                     "withdrawn": len(out["withdrawn"]), "by_priority": by}
    detail = (f"Ubuntu 套件上的 CVE {len(wanted)} 個：有 Ubuntu priority {n}（"
              + "、".join(f"{p} {by[p]}" for p in reversed(PRIORITIES) if by[p]) + f"）、untriaged {len(out['untriaged'])}、"
              f"鏡像沒有 {len(out['not_found'])}、撤回 {len(out['withdrawn'])}（scan/ubuntu-priority.json；鏡像 fetched_utc="
              f"{mir.state.get('fetched_utc')}；原始 findings 不變）")
    out.update(status="OK", detail=detail)
    return "OK", detail, out


def main(argv=None):
    ap = argparse.ArgumentParser(description="Ubuntu 套件上的 CVE → Ubuntu priority（Ubuntu OSV 鏡像；D-ubuntu-priority）")
    ap.add_argument("--findings", required=True)
    ap.add_argument("--mirror")
    ap.add_argument("--max-age-days", type=float, default=None)
    ap.add_argument("--out", required=True)
    try:
        a = ap.parse_args(argv)
    except SystemExit:
        line("FAIL", "ubuntu_priority.py 參數錯誤")
        return 3
    try:
        dr = drc()
        max_age = a.max_age_days if a.max_age_days is not None else float(os.environ.get("OSV_DISTRO_MAX_AGE_DAYS") or 3)
        st, detail, out = ubuntu_priority(dr.load(a.findings, "DT findings"), a.mirror, max_age, dr)
    except Exception as e:      # 含 InputError：記 FAIL，不讓掃描中斷、不印 traceback
        line("FAIL", f"ubuntu_priority.py 無法處理（{e if type(e).__name__ == 'InputError' else type(e).__name__}）")
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
