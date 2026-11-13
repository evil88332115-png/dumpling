#!/usr/bin/env python3
"""kernel_versions.py：映像出貨的核心，哪些有判定、哪些沒有（sca-scan 的 scan/kernel-versions.json）。

一個映像可以有不只一顆核心（例如 Raspberry Pi 有 Pi 5 與 Pi 4 兩個 /usr/lib/modules/<版本>/）。判定核心設定與模組對應的工具
（kernel_config.py、kernel_module_map.py）一次只看一顆；沒判定的核心不可以靜默不見，所以 sca-scan 把「映像出貨的」與「這次指定的」
放在一起算，結果寫成 scan/kernel-versions.json，cra_report 的確認事項讀它。

用法：python3 -I kernel_versions.py --out <kernel-versions.json> (--shipped <版本>… | --shipped-unknown) [--requested <版本>]…
                              [--source-version X.Y.Z | --source-gap <原因>] [--upstream-version <出貨版本>=<X.Y.Z>]…
  --shipped：映像出貨的核心（kernel_config.py --list-kernel-versions 的結果；可重複，也可以一個都沒有）
  --shipped-unknown：映像出貨的核心讀不出來（檔案的 shipped 是 null）
  --requested：呼叫端指定的核心（--kernel-version／SCA_KERNEL_VERSIONS；可重複）
  --source-version：核心原始碼樹最上層 Makefile 的 X.Y.Z（kernel_config.py --source-tree-version 的結果）。--source-gap：有給原始碼
    但讀不出版本（原因寫進 upstream_note）。兩個都沒給＝沒有核心原始碼（--kernel-source）。
  --upstream-version：平台設定（platform_params）給的上游版本，格式 <出貨版本>=<X.Y.Z>，可重複；和 Makefile 核對（見下）。

規則：
  - 指定剛好 1 顆：判定那一顆（和以前相同）；出貨但沒指定的核心記為 not_judged。
  - 沒指定：映像只有 1 顆 → 判定它（和以前相同）；有多顆 → 都不判定（不猜），全部 not_judged。
  - 指定 2 顆以上：多顆核心逐一判定還沒實作（M2 之後）→ 一顆都不判定，出貨的與指定的全部 not_judged。
  - shipped 的每一筆是 {"version", "upstream_version", "upstream_basis", "upstream_note"}（schema /2；shipped 是 null 時維持 null）。
    上游版本只認原始碼 Makefile 的 X.Y.Z（不從版本字串的數字推測）：出貨版本字串以 X.Y.Z 開頭、後面接 -、+ 或結尾才算是它編的 →
    upstream_basis "source-makefile"。不相符 → null，note 寫兩個值。一份原始碼與多顆出貨核心：逐顆比，只有相符的填。沒有原始碼 → null。
    --upstream-version 給的值：和（相符的）Makefile 一致 → basis "source-makefile+platform-param"；不一致 → null，note 寫兩個值；
    沒有可核對的 Makefile（沒給原始碼，或 Makefile 不是這顆核心的）→ 填給的值，basis "platform-param"，note 寫沒有原始碼可核對。
  judged 是「交給判定工具的核心」，不是判定的結果（結果看 scan/kernel-config.json 與 status.tsv 的 C-kernel-config）。

stdout：
  KERNEL-NOT-JUDGED<TAB>版本<TAB>原因   每一顆沒判定的核心一行
  KERNEL-VERSIONS-NOTE<TAB>說明           有沒判定的核心（或出貨的核心讀不出來）時一行：給 status.tsv 的 C-kernel-config／C-kernel-module-map
  KERNEL-VERSIONS-UNKNOWN<TAB>原因        出貨的核心讀不出來，而且有指定核心時一行
退出碼 0；參數錯誤 3（stdout 印 KERNEL-VERSIONS-ERROR 一行）。沒有核心可記（沒指定、映像也沒有核心）時不寫檔。
"""
import argparse
import json
import os
import re
import sys

SCHEMA = "sca-center-kernel-versions/2"
VER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+~-]{0,99}$")

REASON_NOT_GIVEN = "沒有指定 --kernel-version"
REASON_OTHER_GIVEN = "出貨但沒有列在 --kernel-version，這次只判定指定的核心"
REASON_MULTI = "多顆核心逐一判定還沒實作（M2 之後）"
REASON_MULTI_NOT_SHIPPED = REASON_MULTI + "；映像也沒有這顆核心的模組目錄"
NO_SOURCE_NOTE = "沒有核心原始碼（--kernel-source），不推測上游版本"
UP_RE = re.compile(r"^\d+\.\d+\.\d+$")
EXCLUDE_NOTE = ("要排除某顆核心必須記錄證據（例如設計文件寫明「這個板子不載入它」），沒有證據不能當作它不受影響")


def dedupe(items):
    out = []
    for x in items:
        if x not in out:
            out.append(x)
    return out


def matches(version, up):
    """出貨的版本字串以 X.Y.Z 開頭，後面接 -、+ 或結尾（6.8.1 不算 6.8.12 的前綴）。"""
    return version == up or version.startswith(up + "-") or version.startswith(up + "+")


def upstream_of(version, source, param):
    """一顆出貨的核心 → {"version", "upstream_version", "upstream_basis", "upstream_note"}。
    source：None（沒有核心原始碼）、("OK", "X.Y.Z")（Makefile 的版本）或 ("GAP", 原因)（有原始碼但讀不出版本）；param：平台設定給的 X.Y.Z 或 None。"""
    def out(up, basis, note):
        return {"version": version, "upstream_version": up, "upstream_basis": basis, "upstream_note": note}
    mk = source[1] if source and source[0] == "OK" else None
    applies = mk is not None and matches(version, mk)       # Makefile 是這顆核心的原始碼
    if source is None:
        why = NO_SOURCE_NOTE
    elif mk is None:
        why = f"核心原始碼的版本讀不出來（{source[1]}），不推測上游版本"
    elif not applies:
        why = f"原始碼 Makefile 是 {mk}，出貨核心 {version} 不是它編的"
    else:
        why = None
    if applies:
        if param is None:
            return out(mk, "source-makefile", f"原始碼 Makefile 是 {mk}，與出貨核心 {version} 相符")
        if param == mk:
            return out(mk, "source-makefile+platform-param", f"原始碼 Makefile 與平台設定都是 {mk}，與出貨核心 {version} 相符")
        return out(None, None, f"原始碼 Makefile 是 {mk}，平台設定 upstream_version 是 {param}，兩者不一致：不採用任何一個")
    if param is not None:
        return out(param, "platform-param", f"平台設定給的上游版本 {param}；沒有原始碼可核對（{why}）")
    return out(None, None, why)


def plan(shipped, requested, source=None, params=None):
    """出貨的核心（list，或 None＝讀不出來）與指定的核心（list）→ 檔案內容 dict。source、params：見 upstream_of。"""
    requested = dedupe(requested)
    ship = None if shipped is None else sorted(set(shipped))
    judged, nj = [], []
    if len(requested) >= 2:
        names = sorted(set(requested) | set(ship or []))
        for v in names:
            insh = None if ship is None else v in ship
            nj.append({"version": v, "reason": REASON_MULTI_NOT_SHIPPED if insh is False else REASON_MULTI, "shipped": insh})
    elif len(requested) == 1:
        judged = list(requested)
        for v in ship or []:
            if v != requested[0]:
                nj.append({"version": v, "reason": REASON_OTHER_GIVEN, "shipped": True})
    elif ship is not None:
        if len(ship) == 1:
            judged = list(ship)
        else:
            nj = [{"version": v, "reason": REASON_NOT_GIVEN, "shipped": True} for v in ship]
    params = params or {}
    shipped_out = None if ship is None else [upstream_of(v, source, params.get(v)) for v in ship]
    return {"schema": SCHEMA, "shipped": shipped_out, "requested": requested, "judged": judged, "not_judged": nj,
            "note": "judged 是交給判定工具的核心，不是判定的結果（結果看 scan/kernel-config.json 與 status.tsv 的 C-kernel-config）；"
                    "not_judged 是出貨（或被指定）但沒有判定的核心，不可以當作它們不受影響。" + EXCLUDE_NOTE}


def note_text(doc):
    """沒判定的核心 → 一句話（給 status.tsv 的說明欄）；沒有 → None。"""
    nj = doc["not_judged"]
    if not nj:
        return None
    names = [x["version"] for x in nj]
    shown = "、".join(names[:4]) + (f" 等 {len(names)} 顆" if len(names) > 4 else "")
    reasons = sorted({x["reason"] for x in nj})
    return f"映像出貨的核心 {shown} 沒有判定（{'；'.join(reasons)}）；{EXCLUDE_NOTE}"


def write(out, doc):
    tmp = out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
        f.write("\n")
    os.replace(tmp, out)


def main(argv=None):
    ap = argparse.ArgumentParser(description="映像出貨的核心哪些有判定（scan/kernel-versions.json）")
    ap.add_argument("--out")
    ap.add_argument("--shipped", action="append", default=[])
    ap.add_argument("--shipped-unknown", action="store_true")
    ap.add_argument("--requested", action="append", default=[])
    ap.add_argument("--source-version")
    ap.add_argument("--source-gap")
    ap.add_argument("--upstream-version", action="append", default=[])
    try:
        a = ap.parse_args(argv)
    except SystemExit:
        print("KERNEL-VERSIONS-ERROR\t參數錯誤")
        return 3
    if not a.out or (a.shipped and a.shipped_unknown):
        print("KERNEL-VERSIONS-ERROR\t要 --out；--shipped 與 --shipped-unknown 只能選一個")
        return 3
    bad = [v for v in a.shipped + a.requested if not VER_RE.match(v)]
    if bad:
        print("KERNEL-VERSIONS-ERROR\t核心版本不合法：" + re.sub(r"[^\x20-\x7e]", "?", bad[0])[:80])
        return 3
    if a.source_version is not None and (a.source_gap is not None or not UP_RE.match(a.source_version)):
        print("KERNEL-VERSIONS-ERROR\t--source-version 要是 X.Y.Z，而且不能和 --source-gap 一起給")
        return 3
    params = {}
    for x in a.upstream_version:
        v, sep, up = x.partition("=")
        if not sep or not VER_RE.match(v) or not UP_RE.match(up) or params.get(v, up) != up:
            print("KERNEL-VERSIONS-ERROR\t--upstream-version 要是 <出貨版本>=<X.Y.Z>（同一顆核心不能給兩個值）：" + re.sub(r"[^\x20-\x7e]", "?", x)[:80])
            return 3
        params[v] = up
    source = ("OK", a.source_version) if a.source_version is not None else \
        ("GAP", re.sub(r"\s+", " ", a.source_gap)[:200]) if a.source_gap is not None else None
    doc = plan(None if a.shipped_unknown else a.shipped, a.requested, source, params)
    if doc["shipped"] is None and not doc["requested"]:
        return 0                                  # 讀不出映像有什麼核心，也沒指定：沒有東西可記（和以前相同）
    if doc["shipped"] == [] and not doc["requested"]:
        return 0                                  # 映像沒有模組資料夾，也沒指定：沒有核心可記
    write(a.out, doc)
    for v in sorted(set(params) - {x["version"] for x in doc["shipped"] or []}):
        print(f"KERNEL-UPSTREAM-PARAM-UNUSED\t{v}\t--upstream-version 的核心不在映像出貨的核心裡，沒有採用")
    for x in doc["not_judged"]:
        print(f"KERNEL-NOT-JUDGED\t{x['version']}\t{x['reason']}")
    if doc["shipped"] is None:
        print("KERNEL-VERSIONS-UNKNOWN\t映像出貨的核心讀不出來：不知道有沒有其他核心沒有判定")
    nt = note_text(doc)
    if nt:
        print(f"KERNEL-VERSIONS-NOTE\t{nt}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
