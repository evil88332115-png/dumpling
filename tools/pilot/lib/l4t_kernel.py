#!/usr/bin/env python3
"""l4t_kernel.py：Jetson Linux（L4T）的核心加上對應的 Canonical 核心原始碼套件元件，只供弱點比對（sca-scan 的 C-kernel-l4t-map）。
寫輸出 SBOM 與摘要 JSON，並印一行 status：
  C-kernel-l4t-map<TAB>狀態<TAB>說明

用法：python3 -I l4t_kernel.py --sbom <CycloneDX JSON> --map <l4t-kernel-map.json> --out-sbom <輸出 SBOM> --summary <摘要 JSON>
退出碼：0 已判定；3 輸入錯誤（含對應檔格式錯誤；同時印 FAIL 那一行，不印 traceback）。

為什麼：L4T 的核心是 NVIDIA 的 deb 套件（nvidia-l4t-kernel@6.8.12-tegra-39.2.1-20260806224157，模組在
/usr/lib/modules/6.8.12-1021-tegra/），Ubuntu 的弱點資料沒有這個套件，Grype 與 DT 對核心都是 0 筆（C-kernel-coverage GAP，
見 kernelcheck.py）。L4T 的核心是從 Canonical 的 noble linux-nvidia-tegra 原始碼建的（NVIDIA 在上面另加自己的 commit），
所以加上那個原始碼套件元件（例如 pkg:deb/ubuntu/linux-nvidia-tegra@6.8.0-1021.21?arch=source&distro=ubuntu-24.04），
Grype 的 Ubuntu 資料與 DT 的 OSV Ubuntu 資料就會套用 Canonical 對這個版本的修補狀態（含 backport）。
每個 L4T 版本對應哪個 Canonical 版本、出處與核對紀錄都寫在 l4t-kernel-map.json，這裡不推算。
涵蓋範圍：只有 Canonical 的核心原始碼。NVIDIA 自己的 out-of-tree 模組（nvgpu、nvethernetrm、linux-nv-oot）與 NVIDIA SAUCE
修改不在對應內，它們的弱點仍未評估；L4T 若沒有跟上 Canonical 同版本的修補，結果也會偏少。

判定（明確比對，不用模糊比對）：
  1. L4T 核心：deb purl、名稱正好是 nvidia-l4t-kernel 的元件（-dtbs、-headers、-oot-modules 等不算）。版本要符合
     <核心版本>-tegra-<R>.<x>.<y>-<14 位數字的時間>（例如 6.8.12-tegra-39.2.1-20260806224157），L4T 版本＝<R>.<x>.<y>。
     沒有這個元件 → NOT_RUN（sca-scan 不寫這一列）。版本格式不符、或有多個不同版本 → GAP（不猜是哪一個）。
  2. 模組目錄：Syft 的 linux-kernel-module 元件所在的 /usr/lib/modules/<版本>/（沒有路徑時用 syft:metadata:kernelVersion），記為證據。
     對應項目的 modules_kernel_version（必填，例如 6.8.12-1021-tegra，其中 1021 是 Ubuntu 的 ABI 編號，和 Canonical 版本 6.8.0-1021.21 的
     1021 相同）：SBOM 有模組卻沒有這個目錄 → GAP：核心可能重新建置過或是其他版本，套用對應會錯。SBOM 沒有模組時不核對（說明註明）。
  3. 對應檔以 L4T 版本為鍵；沒有這個版本，或 component 的 version、purl 與 modules_kernel_version、evidence、checked 是空的或含
     TODO（不分大小寫）→ GAP（未對應）。沒有出處或沒有核對紀錄的對應不使用（CLAUDE.md：標準答案必須有出處）。
     對應檔錯誤 → FAIL：component 的 purl 不是 pkg:deb/ubuntu/…、名稱或版本和 name、version 不一致、qualifiers 沒有 arch=source
     或 distro=（Ubuntu 的弱點資料以原始碼套件與發行版記錄）、缺 modules_kernel_version。
  4. SBOM 已經有同名同版本的元件，或有 deb 套件是從這個原始碼套件同版本建的（syft:metadata:source／sourceVersion，或 purl 的
     upstream qualifier；例如映像另外裝了 Canonical 的 linux-image-*-nvidia-tegra）→ OK，不重複加（避免同一個核心算兩次）；
     否則加上元件 → OK。
加上的元件：對應檔的 name、version、purl、properties，另加屬性
  sca-center:kernel-mapped-from（原本 nvidia-l4t-kernel 的 purl）、sca-center:kernel-map-release（L4T 版本）、
  sca-center:matching-only＝true（只供比對的合成元件，不是安裝的套件；scio_prep.py 據此不送 ScanCode.io／DejaCode）。
原始 SBOM 不動；sca-scan 只把輸出給 Grype、sbomgate 與上傳 DT 的副本（$BOMW）。開始時先刪掉舊的輸出 SBOM 與摘要（FAIL 時不留
上一次的結果給 kernelcheck、cra_report 用）；非 OK 時不寫輸出 SBOM。
"""
import argparse
import collections
import json
import os
import re
import sys
import urllib.parse as up

STAGE = "C-kernel-l4t-map"
L4T_KERNEL = "nvidia-l4t-kernel"
# 6.8.12-tegra-39.2.1-20260806224157 → 核心版本 6.8.12、L4T 版本 39.2.1、時間 20260806224157
L4T_VERSION_RE = re.compile(r"^(?P<kver>\d+\.\d+(?:\.\d+)?)-tegra-(?P<release>\d+\.\d+\.\d+)-(?P<ts>\d{14})$")
DEB_PURL_RE = re.compile(r"^pkg:deb/([^/@?#]+)/([^@?#]+)@([^?#]+)(?:\?[^#]*)?$")
MODULE_PATH_RE = re.compile(r"^/(?:usr/)?lib/modules/([^/]+)/")
TODO = "TODO"
P_FROM, P_RELEASE, P_ONLY = "sca-center:kernel-mapped-from", "sca-center:kernel-map-release", "sca-center:matching-only"


class InputError(Exception):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, message):     # 參數錯誤也算輸入錯誤：印 FAIL 那一行、退出碼 3（argparse 預設是 2）
        line("FAIL", f"l4t_kernel.py 參數錯誤：{message}")
        sys.exit(3)


def walk(cs):
    if cs is None:
        return
    if not isinstance(cs, list):
        raise InputError("components 不是清單")
    for c in cs:
        if isinstance(c, dict):
            yield c
            yield from walk(c.get("components"))


def deb_purl(purl):
    """deb purl → (名稱, 版本)（已解碼）；不是 deb purl 回 None。"""
    m = DEB_PURL_RE.match(purl) if isinstance(purl, str) else None
    return (up.unquote(m.group(2)), up.unquote(m.group(3))) if m else None


def deb_parts(purl):
    """deb purl → (namespace, 名稱, 版本, qualifiers)（已解碼）；不是 deb purl 回 None。"""
    m = DEB_PURL_RE.match(purl) if isinstance(purl, str) else None
    if not m:
        return None
    q = dict(kv.split("=", 1) for kv in (purl.split("?", 1)[1] if "?" in purl else "").split("&") if "=" in kv)
    return (up.unquote(m.group(1)), up.unquote(m.group(2)), up.unquote(m.group(3)),
            {k.lower(): up.unquote(v) for k, v in q.items()})


def built_from(c):
    """deb 元件的原始碼套件 (名稱, 版本)：Syft 的 syft:metadata:source／sourceVersion，沒有時用 purl 的 upstream（<名稱>[@<版本>]）；
    都沒有時就是自己。版本沒寫時同二進位版本（dpkg 只在不同時才寫）。不是 deb 回 None。"""
    p = deb_parts(c.get("purl"))
    if not p:
        return None
    _, name, ver, q = p
    pr = props(c)
    src = (pr.get("syft:metadata:source") or [None])[0]
    sver = (pr.get("syft:metadata:sourceVersion") or [None])[0]
    if not src and q.get("upstream"):
        src, _, sver = q["upstream"].partition("@")
    return (src or name).strip(), ((sver or "").strip() or ver)


def props(c):
    out = collections.defaultdict(list)
    for p in c.get("properties") or []:
        if isinstance(p, dict) and isinstance(p.get("name"), str):
            out[p["name"]].append(p.get("value"))
    return out


def module_dir(c):
    """核心模組的目錄版本：路徑 /usr/lib/modules/<版本>/ 優先，沒有時用 syft:metadata:kernelVersion（同 kernelcheck.py）。"""
    pr = props(c)
    paths = [v for k, vs in pr.items() if k == "syft:metadata:path" or re.fullmatch(r"syft:location:\d+:path", k) for v in vs]
    for ev in ((c.get("evidence") or {}).get("occurrences") or []):
        if isinstance(ev, dict):
            paths.append(ev.get("location"))
    for p in paths:
        m = MODULE_PATH_RE.match(p) if isinstance(p, str) else None
        if m:
            return m.group(1)
    kv = (pr.get("syft:metadata:kernelVersion") or [None])[0]
    return kv.strip() if isinstance(kv, str) and kv.strip() else None


def detect(sbom):
    """回傳 (L4T 核心元件清單, 模組目錄計數)。L4T 核心元件：{name, version, purl, release, kernel_version, timestamp}。"""
    if not isinstance(sbom, dict):
        raise InputError("SBOM 不是 JSON 物件")
    l4t, mods = [], collections.Counter()
    for c in walk(sbom.get("components")):
        p = deb_purl(c.get("purl"))
        if p and p[0] == L4T_KERNEL:
            m = L4T_VERSION_RE.match(p[1])
            l4t.append({"name": p[0], "version": p[1], "purl": c.get("purl"), "release": m and m.group("release"),
                        "kernel_version": m and m.group("kver"), "timestamp": m and m.group("ts")})
        elif "linux-kernel-module" in (props(c).get("syft:package:type") or []):
            d = module_dir(c)
            if d:
                mods[d] += 1
    return l4t, mods


def has_todo(v):
    return not isinstance(v, str) or not v.strip() or TODO.lower() in v.lower()


def load_map(doc):
    if not isinstance(doc, dict) or not isinstance(doc.get("releases"), dict):
        raise InputError("對應檔沒有 releases 物件")
    for rel, e in doc["releases"].items():
        if not isinstance(e, dict) or not isinstance(e.get("component"), dict):
            raise InputError(f"對應檔 {rel} 沒有 component 物件")
        c = e["component"]
        if not isinstance(c.get("name"), str) or not c["name"]:
            raise InputError(f"對應檔 {rel} 的 component 沒有 name")
        if not isinstance(c.get("properties", []), list) \
                or not all(isinstance(p, dict) and isinstance(p.get("name"), str) for p in c.get("properties", [])):
            raise InputError(f"對應檔 {rel} 的 component.properties 格式不對")
        if not isinstance(e.get("modules_kernel_version"), str):
            raise InputError(f"對應檔 {rel} 缺 modules_kernel_version（字串，例如 6.8.12-1021-tegra）")
    return doc["releases"]


def entry_problem(rel, e):
    """對應項目不能用的原因（未對應 → GAP），可以用時回 None；purl 與 name、version 不一致 → InputError（對應檔錯誤）。"""
    if e is None:
        return f"l4t-kernel-map.json 沒有 L4T {rel}"
    c = e["component"]
    todo = [k for k in ("version", "purl") if has_todo(c.get(k))] \
        + [k for k in ("modules_kernel_version", "evidence", "checked") if has_todo(e.get(k))]
    if todo:
        return f"l4t-kernel-map.json 的 L4T {rel} 還沒填好（{'、'.join(todo)} 是空的或 TODO）"
    p = deb_parts(c["purl"])
    if not p or p[0] != "ubuntu" or p[1:3] != (c["name"], c["version"]):
        raise InputError(f"對應檔 {rel} 的 purl 不是 pkg:deb/ubuntu/…，或名稱、版本和 name、version 不一致")
    if p[3].get("arch") != "source" or not p[3].get("distro"):
        raise InputError(f"對應檔 {rel} 的 purl 要有 arch=source 與 distro=（Ubuntu 的弱點資料以原始碼套件與發行版記錄）")
    return None


def mapped_component(e, l4t):
    c = e["component"]
    return {"type": c.get("type") or "library", "bom-ref": f"sca-center-kernel-map:{c['purl']}", "name": c["name"], "version": c["version"],
            "purl": c["purl"],
            "properties": [dict(p) for p in c.get("properties", [])] + [
                {"name": P_FROM, "value": l4t["purl"]}, {"name": P_RELEASE, "value": l4t["release"]}, {"name": P_ONLY, "value": "true"}]}


def assess(sbom, releases):
    """回傳 (狀態, 說明, 摘要, 要加的元件或 None)。"""
    l4t, mods = detect(sbom)
    ev = {"schema": "sca-center-l4t-kernel-map/1", "l4t_kernel": l4t, "modules_kernel_versions": dict(mods.most_common()),
          "release": None, "map_entry": None, "added": None, "already_present": False}
    if not l4t:
        return "NOT_RUN", f"SBOM 沒有 {L4T_KERNEL}（不是 Jetson Linux 映像）", ev, None
    vers = sorted({x["version"] for x in l4t})
    if len(vers) > 1:
        return "GAP", f"SBOM 有 {len(vers)} 個不同版本的 {L4T_KERNEL}（{'、'.join(vers[:3])}），無法判斷是哪一個 L4T 版本，不加對應的核心元件", ev, None
    k = l4t[0]
    what = f"{L4T_KERNEL} {k['version']}"
    if not k["release"]:
        return "GAP", (f"{what} 的版本格式不認得（預期 <核心版本>-tegra-<R>.<x>.<y>-<時間>），無法判斷 L4T 版本，不加對應的核心元件；"
                       "核心的 CVE 未評估，見 C-kernel-coverage"), ev, None
    rel = ev["release"] = k["release"]
    e = releases.get(rel)
    ev["map_entry"] = e
    why = entry_problem(rel, e)
    mdirs = "、".join(mods) or "沒有"
    if why:
        return "GAP", (f"L4T {rel} 核心（{what}，模組目錄 {mdirs}）沒有對應的 Canonical 核心：{why}，不加可比對的核心元件；"
                       "核心的 CVE 未評估，見 C-kernel-coverage"), ev, None
    want = e.get("modules_kernel_version")
    if mods and want not in mods:
        return "GAP", (f"L4T {rel} 核心的模組目錄是 {mdirs}，對應檔預期 {want}（ABI 不同）：核心可能重新建置過或是其他版本，"
                       "不套用對應；核心的 CVE 未評估，見 C-kernel-coverage"), ev, None
    c = e["component"]
    target = f"{c['name']} {c['version']}"
    check = f"模組目錄 {want} 相符" if mods else "SBOM 沒有核心模組，未核對模組目錄"
    if len(mods) > 1:
        check += f"（另有 {len(mods) - 1} 個模組目錄）"
    if any(x.get("name") == c["name"] and x.get("version") == c["version"] for x in walk(sbom.get("components"))):
        ev["already_present"] = True
        return "OK", f"L4T {rel} 核心（{what}）對應 Canonical 核心 {target}；SBOM 已有這個元件，不重複加；{check}", ev, None
    bins = sorted({x.get("name") or "?" for x in walk(sbom.get("components")) if built_from(x) == (c["name"], c["version"])})
    if bins:
        ev["already_present"], ev["built_from_source"] = True, bins
        return "OK", (f"L4T {rel} 核心（{what}）對應 Canonical 核心 {target}；SBOM 已有從它建的套件（{'、'.join(bins[:3])}"
                      f"{f' 等 {len(bins)} 個' if len(bins) > 3 else ''}），不重複加；{check}"), ev, None
    comp = mapped_component(e, k)
    ev["added"] = comp
    return "OK", (f"L4T {rel} 核心（{what}）加上對應的 Canonical 核心 {target}，只供弱點比對（Grype、sbomgate、DT；原始 SBOM 不動）；"
                  f"{check}；NVIDIA 的 out-of-tree 模組與修改不在內"), ev, comp


def load(path, label):
    try:
        with open(path, encoding="utf-8-sig") as f:
            return json.load(f)
    except (OSError, ValueError, RecursionError) as e:
        raise InputError(f"{label} 無法讀取或解析（{type(e).__name__}）")


def line(st, detail):
    print(f"{STAGE}\t{st}\t" + detail.replace("\t", " ").replace("\n", " "))


def main(argv=None):
    ap = Parser(description="Jetson Linux 核心對應的 Canonical 核心元件（C-kernel-l4t-map）")
    ap.add_argument("--sbom", required=True)
    ap.add_argument("--map", required=True)
    ap.add_argument("--out-sbom", required=True)
    ap.add_argument("--summary", required=True)
    a = ap.parse_args(argv)
    for old in (a.out_sbom, a.summary):     # 不留上一次的輸出冒充這次的結果（FAIL 時 kernelcheck、cra_report 不會讀到舊摘要）
        try:
            os.remove(old)
        except FileNotFoundError:
            pass
        except OSError as e:
            line("FAIL", f"無法刪除舊的輸出（{type(e).__name__}）")
            return 3
    try:
        sbom = load(a.sbom, "SBOM")
        releases = load_map(load(a.map, "對應檔"))
        st, detail, ev, comp = assess(sbom, releases)
    except InputError as e:
        line("FAIL", f"l4t_kernel.py 輸入錯誤：{e}")
        return 3
    except Exception as e:   # 結構意外（例如欄位型別不對）：記 FAIL，不讓掃描中斷、不印 traceback
        line("FAIL", f"l4t_kernel.py 無法判定（{type(e).__name__}）")
        return 3
    ev["status"], ev["detail"], ev["map_file"] = st, detail, os.path.basename(a.map)
    try:
        if st == "OK":
            if comp:
                sbom.setdefault("components", []).append(comp)
            with open(a.out_sbom, "w", encoding="utf-8") as f:
                json.dump(sbom, f, ensure_ascii=False)
        with open(a.summary, "w", encoding="utf-8") as f:
            json.dump(ev, f, ensure_ascii=False, indent=1)
    except OSError as e:
        line("FAIL", f"無法寫入輸出（{type(e).__name__}）")
        return 3
    line(st, detail)
    return 0


if __name__ == "__main__":
    sys.exit(main())
