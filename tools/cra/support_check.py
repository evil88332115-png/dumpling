#!/usr/bin/env python3
"""支援期檢查（計畫總表 #13，對應 M-3；Art 13(8)、Annex VII 第 4 點）。

產品的支援期（設定 support.end_date，YYYY-MM）比元件的維護期長時，產品在支援期後段會收不到那個元件的安全更新。
這裡用內建的資料表（tools/cra/data/support-lifecycle.json：Ubuntu、Jetson Linux、kernel 的維護期，每筆附來源網址與查核日期）
對照產品 SBOM 裡的元件，列出比產品先停止維護的元件。不連網；資料表要人工更新。

狀態：
- OK：每個對到的元件都維護到產品支援期結束或更晚。
- ATTENTION：有元件比產品先停止維護、元件的維護期沒有公開（end 是 null）、或資料表的查核日期超過 max_age_days 天。
- NOT_ASSESSED：沒有產品支援期（support.end_date）、沒有 SBOM、或 SBOM 裡沒有資料表認得的元件（「沒對到」不等於「沒問題」）。
- FAIL：資料表讀不到或格式不對。
資料表的 informational 項目（例如上游 kernel 分支）只列出，不影響狀態。
階段（phases）有 requires（例如 Ubuntu Pro）時，只有設定 support.subscriptions 有列的才算進維護期。

用法：python3 -I support_check.py --sbom <sbom.cdx.json> --config <config.json> [--table <json>] [--today YYYY-MM-DD]
輸出一行 `SUPPORT-CHECK<TAB>狀態<TAB>說明`，Markdown 印在後面。退出碼：OK 0、ATTENTION／NOT_ASSESSED 2、FAIL 1、參數錯誤 64。
"""
import argparse
import datetime
import hashlib
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TABLE = HERE / "data" / "support-lifecycle.json"
SCHEMA = "sca-center-support-lifecycle/1"
YM = re.compile(r"^\d{4}-(0[1-9]|1[0-2])$")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
MATCH_KEYS = {"type", "name", "name_regex", "version_prefix", "version_regex"}
ORDER = ("OK", "ATTENTION", "NOT_ASSESSED", "FAIL")


class TableError(Exception):
    pass


def regex_ok(m, where):
    for k in ("name_regex", "version_regex"):
        if k in m:
            try:
                re.compile(m[k])
            except re.error:
                raise TableError(f"{where}：{k} 不是正規表示式")


def load_table(path=TABLE):
    """資料表 → (dict, sha256)。格式不對 → TableError（說明哪一筆、哪個欄位）。"""
    p = Path(path)
    try:
        raw = p.read_bytes()
        t = json.loads(raw)
    except (OSError, ValueError) as e:
        raise TableError(f"讀不到資料表 {p.name}：{type(e).__name__}")
    if not isinstance(t, dict) or t.get("schema") != SCHEMA or not isinstance(t.get("entries"), list):
        raise TableError(f"{p.name}：schema 要是 {SCHEMA}，且有 entries 清單")
    if not isinstance(t.get("max_age_days"), int) or t["max_age_days"] < 1:
        raise TableError(f"{p.name}：max_age_days 要是正整數")
    fams = t.get("families", [])
    if not isinstance(fams, list) or not all(isinstance(f, dict) and isinstance(f.get("name"), str) and f["name"]
                                             and isinstance(f.get("match"), dict) and f["match"] and set(f["match"]) <= MATCH_KEYS
                                             and all(isinstance(v, str) and v for v in f["match"].values()) for f in fams):
        raise TableError(f"{p.name}：families 要是 {{name, match}} 的清單")
    for f in fams:
        regex_ok(f["match"], f"{p.name} families {f['name']}")
    ids = set()
    for i, e in enumerate(t["entries"]):
        w = f"{p.name} entries[{i}]"
        if not isinstance(e, dict) or not isinstance(e.get("id"), str) or not e["id"] or e["id"] in ids:
            raise TableError(f"{w}：id 要是不重複的文字")
        ids.add(e["id"])
        if not isinstance(e.get("name"), str) or not e["name"]:
            raise TableError(f"{w}：name 必填")
        if not isinstance(e.get("match"), list) or not e["match"] or not all(
                isinstance(m, dict) and m and set(m) <= MATCH_KEYS and all(isinstance(v, str) and v for v in m.values()) for m in e["match"]):
            raise TableError(f"{w}：match 要是條件清單（鍵只能是 {', '.join(sorted(MATCH_KEYS))}）")
        for m in e["match"]:
            regex_ok(m, w)
        if not isinstance(e.get("phases"), list) or not e["phases"]:
            raise TableError(f"{w}：phases 必填")
        for ph in e["phases"]:
            if not isinstance(ph, dict) or not isinstance(ph.get("name"), str) or not (ph.get("end") is None or
                                                                                      (isinstance(ph.get("end"), str) and YM.match(ph["end"]))):
                raise TableError(f"{w}：phases 每一段要有 name 與 end（YYYY-MM 或 null）")
            if "requires" in ph and not (isinstance(ph["requires"], str) and ph["requires"]):
                raise TableError(f"{w}：requires 要是文字")
        if not isinstance(e.get("sources"), list) or not e["sources"] or not all(isinstance(u, str) and u.startswith("https://")
                                                                                  for u in e["sources"]):
            raise TableError(f"{w}：sources 要有至少一個 https 網址")
        if "coverage" in e and not (isinstance(e["coverage"], str) and e["coverage"]):
            raise TableError(f"{w}：coverage 要是文字")
        if not isinstance(e.get("checked"), str) or not DATE.match(e["checked"]):
            raise TableError(f"{w}：checked 要是 YYYY-MM-DD")
        try:
            datetime.date.fromisoformat(e["checked"])
        except ValueError:
            raise TableError(f"{w}：checked 不是有效日期")
    return t, hashlib.sha256(raw).hexdigest()


def flatten(comps):
    for c in comps if isinstance(comps, list) else []:
        if isinstance(c, dict):
            yield c
            yield from flatten(c.get("components"))


def matches(c, m):
    name, ver = str(c.get("name") or ""), str(c.get("version") or "")
    return ((m.get("type") is None or c.get("type") == m["type"]) and (m.get("name") is None or name == m["name"])
            and (m.get("name_regex") is None or re.search(m["name_regex"], name) is not None)
            and (m.get("version_prefix") is None or ver.startswith(m["version_prefix"]))
            and (m.get("version_regex") is None or re.search(m["version_regex"], ver) is not None))


def relevant_end(entry, subscriptions):
    """可以算進維護期的最後一段的 (結束 YYYY-MM 或 None, 階段名稱)。階段依序疊加：從第一段開始，遇到 requires 不在 subscriptions 的
    那一段就停（例如 Legacy add-on 要先有 Ubuntu Pro）。任何算進去的階段 end 是 null（沒有公開）→ (None, 名稱)。"""
    ok = []
    for ph in entry["phases"]:
        if ph.get("requires") and ph["requires"] not in subscriptions:
            break
        ok.append(ph)
    if not ok:
        return None, None
    if any(ph["end"] is None for ph in ok):
        ph = next(ph for ph in ok if ph["end"] is None)
        return None, ph["name"]
    ph = max(ok, key=lambda ph: ph["end"])
    return ph["end"], ph["name"]


def check(bom, cfg, table, table_sha, today):
    """→ 結果 dict（status、reasons、product_end、entries、table）。today：datetime.date。"""
    sup = cfg.get("support") if isinstance(cfg.get("support"), dict) else {}
    raw_end = sup.get("end_date")
    pend = raw_end if isinstance(raw_end, str) and YM.match(raw_end) else None
    subs = [x for x in sup.get("subscriptions") or [] if isinstance(x, str)] if isinstance(sup.get("subscriptions"), list) else []
    comps = list(flatten(bom.get("components"))) if isinstance(bom, dict) else []
    res = {"status": "OK", "reasons": [], "today": today.isoformat(), "product_end": pend, "subscriptions": subs, "entries": [],
           "not_in_table": [], "table": {"file": TABLE.name, "sha256": table_sha, "max_age_days": table["max_age_days"],
                                         "entries": len(table["entries"]), "stale": [], "future": []}}
    covered = set()
    for e in table["entries"]:
        hit = [c for c in comps if any(matches(c, m) for m in e["match"])]
        if not hit:
            continue
        if not e.get("informational"):
            covered.update(id(c) for c in hit)
        end, phase = relevant_end(e, subs)
        info = bool(e.get("informational"))
        if pend is None:
            verdict = "not compared (no product support end date)"
        elif phase is None:
            verdict = "no maintenance phase applies (subscription not configured)"
        elif end is None:
            verdict = "end of maintenance not published"
        elif end < pend:
            verdict = "ends before the product support period"
        else:
            verdict = "covers the product support period"
        age = (today - datetime.date.fromisoformat(e["checked"])).days
        if age > table["max_age_days"]:
            res["table"]["stale"].append(e["id"])
        elif age < 0:
            res["table"]["future"].append(e["id"])      # 查核日期在未來（多半是打錯）
        res["entries"].append({"id": e["id"], "name": e["name"], "informational": info, "end": end, "phase": phase, "verdict": verdict,
                               "phases": e["phases"], "note": e.get("note"), "coverage": e.get("coverage"), "sources": e["sources"], "checked": e["checked"],
                               "matched": sorted({f"{c.get('name')} {c.get('version') or ''}".strip() for c in hit})[:5]})
    # 有這類元件（作業系統、Jetson Linux、kernel），卻沒有任何非 informational 的項目對到：版本不在資料表 → 沒有檢查
    for f in table.get("families", []):
        for c in comps:
            if id(c) not in covered and matches(c, f["match"]):
                label = f"{c.get('name')} {c.get('version') or ''}".strip()
                if label not in res["not_in_table"]:
                    res["not_in_table"].append(label)
    st = []
    if res["not_in_table"]:
        st.append("NOT_ASSESSED")
        res["reasons"].append("not in the support lifecycle table, so not checked: " + ", ".join(res["not_in_table"][:10]))
    known = {ph.get("requires") for e in table["entries"] for ph in e["phases"] if ph.get("requires")}
    unknown = [x for x in subs if x not in known]
    if unknown:
        st.append("ATTENTION")
        res["reasons"].append(f"support.subscriptions not used by any lifecycle entry (names must match exactly): {', '.join(unknown)}")
    if not isinstance(bom, dict):
        st.append("NOT_ASSESSED")
        res["reasons"].append("no SBOM")
    elif not res["entries"]:
        st.append("NOT_ASSESSED")
        res["reasons"].append("no component of the SBOM is in the support lifecycle table (this does not mean that all components are maintained)")
    if pend is None:
        st.append("NOT_ASSESSED")
        res["reasons"].append("product support end date (support.end_date) is TO BE COMPLETED" if raw_end in (None, "") else
                              f"product support end date (support.end_date) is not in YYYY-MM format: {str(raw_end)[:40]}")
    for x in res["entries"]:
        if x["informational"]:
            continue
        if x["verdict"] in ("ends before the product support period", "end of maintenance not published",
                            "no maintenance phase applies (subscription not configured)"):
            st.append("ATTENTION")
            res["reasons"].append(f"{x['name']}: {x['verdict']}" + (f" ({x['end']})" if x["end"] else ""))
    if res["table"]["stale"]:
        st.append("ATTENTION")
        res["reasons"].append(f"lifecycle data older than {table['max_age_days']} days, re-check the sources: {', '.join(res['table']['stale'])}")
    if res["table"]["future"]:
        st.append("ATTENTION")
        res["reasons"].append(f"lifecycle check date is in the future (typo?): {', '.join(res['table']['future'])}")
    res["status"] = max(st or ["OK"], key=ORDER.index)
    return res


def section(res, table):
    """技術文件第 4 節的內容（Markdown，英文）。table：cra_report.table。"""
    if res.get("status") == "FAIL":
        return f"**Support period check: FAIL** ({res['reasons'][0]})."
    out = [f"**Support period check: {res['status']}** (component maintenance compared with the product support period; "
           f"lifecycle table `{res['table']['file']}`, SHA-256 `{res['table']['sha256'][:12]}`, checked on {res['today']}). "
           "This result is reported separately and does not change the status of this document.", "",
           f"Scope: only components that are in the lifecycle table ({res['table']['entries']} entries) were compared; "
           "other components were not assessed.", ""]
    cov = [f"{x['name']}: {x['coverage']}" for x in res.get("entries") or [] if x.get("coverage")]
    if cov:      # 對到的項目只涵蓋一部分（例如 Ubuntu 只有 main／restricted）：放在表格前面，不讓讀者以為整個發行版都有維護
        out += ["What a match covers:", "", "\n".join(f"- {c}" for c in cov), ""]
    if res["reasons"]:
        out += ["\n".join(f"- {r}" for r in res["reasons"]), ""]
    if res["entries"]:
        out += [table(["Component", "Found in SBOM", "Maintained until", "Result", "Source (checked)"],
                      [[x["name"] + (" (for information)" if x["informational"] else ""), ", ".join(x["matched"]),
                        (f"{x['end']} ({x['phase']})" if x["end"] else ("not published" if x["phase"] else "—")),
                        x["verdict"], "; ".join(x["sources"]) + f" ({x['checked']})"] for x in res["entries"]]), ""]
        notes = [f"{x['name']}: {x['note']}" for x in res["entries"] if x.get("note")]
        if notes:
            out += ["\n".join(f"- {n}" for n in notes), ""]
        if res["subscriptions"]:
            out += [f"Maintenance phases counted with the subscriptions in the configuration (`support.subscriptions`): "
                    f"{', '.join(res['subscriptions'])}.", ""]
    return "\n".join(out).rstrip()


def run(bom, cfg, today, table_path=TABLE):
    """cra_report.py 的接點：資料表有錯不讓整份文件失敗，記 FAIL。"""
    try:
        t, sha = load_table(table_path)
    except TableError as e:
        return {"status": "FAIL", "reasons": [str(e)], "today": today.isoformat(), "product_end": None, "subscriptions": None, "entries": [],
                "not_in_table": [], "table": {"file": Path(table_path).name, "sha256": None, "max_age_days": None, "entries": None,
                                              "stale": [], "future": []}}
    return check(bom, cfg, t, sha, today)


def _table(head, rows):
    esc = lambda x: str(x).replace("|", "\\|").replace("\n", " ")   # noqa: E731
    return "\n".join(["| " + " | ".join(head) + " |", "|" + "---|" * len(head)] + ["| " + " | ".join(esc(x) for x in r) + " |" for r in rows])


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        print(f"參數錯誤：{message}", file=sys.stderr)
        sys.exit(64)


def main(argv=None):
    ap = Parser(description="支援期檢查：產品支援期 vs 元件維護期")
    ap.add_argument("--sbom", required=True)
    ap.add_argument("--config", required=True)
    ap.add_argument("--table", default=str(TABLE))
    ap.add_argument("--today", help="YYYY-MM-DD（預設今天，UTC）")
    a = ap.parse_args(argv)
    try:
        today = datetime.date.fromisoformat(a.today) if a.today else datetime.datetime.now(datetime.timezone.utc).date()
    except ValueError:
        ap.error("--today 要是 YYYY-MM-DD")
    try:
        bom = json.loads(Path(a.sbom).read_text(encoding="utf-8"))
        cfg = json.loads(Path(a.config).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        print(f"SUPPORT-CHECK\tFAIL\t讀不到輸入：{type(e).__name__}")
        return 1
    res = run(bom, cfg if isinstance(cfg, dict) else {}, today, a.table)
    print(f"SUPPORT-CHECK\t{res['status']}\t" + ("；".join(res["reasons"]) or "ok"))
    print(section(res, _table))
    return {"OK": 0, "FAIL": 1}.get(res["status"], 2)


if __name__ == "__main__":
    sys.exit(main())
