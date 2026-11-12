#!/usr/bin/env python3
"""kernelcheck.py：SBOM 裡有作業系統核心時，確認核心有沒有做漏洞比對（C-kernel-coverage），寫 kernel-coverage.json，並印一行 status：
  C-kernel-coverage<TAB>狀態<TAB>說明

用法：python3 -I kernelcheck.py --sbom <CycloneDX JSON> [--grype <grype.json>] [--dt-findings <DT findings.json>] [--kernel-map <l4t-kernel-map.json>]
                          --out <kernel-coverage.json>
  --grype：Grype JSON（sca-scan 在 C-grype 之後執行；Grype 沒有結果時不給）。
  --kernel-map：C-kernel-l4t-map 的摘要（lib/l4t_kernel.py）。--sbom 是原始 SBOM，沒有那個只供比對的 Canonical 核心元件
    （例如 linux-nvidia-tegra）；Grype 對它的比對照樣依名稱算進核心（KERNEL_PACKAGE_PATTERNS 的 linux-*-tegra*），
    這個參數只讓說明與證據寫出比對對象是對應的 Canonical 核心。
  --dt-findings：DT 的 finding 清單（tools/e2e/dtread.py 的輸出）。保留給之後在 D 段之後再判一次；sca-scan 目前不給。
判定：
  - SBOM 沒有核心 → NOT_RUN「SBOM 沒有作業系統核心」。
  - 有核心，Grype（或 DT）對核心至少 1 筆比對 → OK（只表示有做核心比對，不代表核心的弱點完整）。
  - 有核心，對核心 0 筆比對（或沒有 Grype 結果）→ GAP：核心的 CVE 未評估，0 筆不代表沒有。
退出碼：0 已判定；3 輸入錯誤（同時印 FAIL 那一行，不印 traceback）。

為什麼要有這個階段（證據）：Jetson Linux R39.2.1（Ubuntu 24.04 arm64）映像，Syft 1.55.0 的 SBOM 有 nvidia-l4t-kernel 等 deb 套件與
1468 個 linux-kernel-module（pkg:generic，版本多為 UNKNOWN，位於 /usr/lib/modules/6.8.12-1021-tegra/），但沒有 linux-kernel 元件；
Grype 與 DT 對核心都是 0 筆，報告看起來像核心沒有弱點（round14 run 40594937149）。

「SBOM 有核心」的判斷（明確列出，不用模糊比對）：
  1. 元件屬性 syft:package:type 是 linux-kernel 或 linux-kernel-module；或元件的 CPE 是 cpe:2.3:o:linux:linux_kernel（其他產生器）。
  2. deb、rpm、apk 套件（purl 類型；沒有 purl 時看 syft:package:type）名稱符合 KERNEL_PACKAGE_PATTERNS。
     名稱含 NOT_KERNEL_SEGMENTS（headers、tools…）的不算：這些套件不含執行中的核心。
     不算核心的還有 linux-libc-dev（使用者空間標頭；Grype 預設規則會忽略它以上游 linux 比對到的紀錄）、linux-firmware、linux-base、kerneloops。
「對核心的比對」：Grype 比對的 artifact 是 linux-kernel／linux-kernel-module，或 artifact／matchDetails 的 CPE 是 Linux 核心，
  或 artifact 是上面第 2 條的核心套件。DT finding 同理（元件 purl 或 CPE）。Grype 的 ignoredMatches 不算，只記數量。
核心版本的來源（依序）：linux-kernel 元件的版本 → 核心模組所在的 /usr/lib/modules/<版本>/（或 /lib/modules/）路徑，
  路徑沒有時用 Syft 的 syft:metadata:kernelVersion → 核心套件的版本。
"""
import argparse
import collections
import json
import re
import sys
from urllib.parse import unquote

STAGE = "C-kernel-coverage"
KERNEL_SYFT_TYPES = ("linux-kernel", "linux-kernel-module")
KERNEL_CPE_PREFIX = "cpe:2.3:o:linux:linux_kernel:"
PACKAGE_TYPES = ("deb", "rpm", "apk")
# 核心套件名稱（只用於 deb／rpm／apk）。每一條都要能說出是哪個發行版的核心套件。
KERNEL_PACKAGE_PATTERNS = (
    (r"linux-image(-.+)?", "Debian／Ubuntu 核心映像（linux-image-*，含 -unsigned）"),
    (r"linux-signed(-.+)?", "Ubuntu 簽章核心的中介套件（linux-signed-*）"),
    (r"linux-modules(-.+)?", "Ubuntu 核心模組（linux-modules-*、linux-modules-extra-*）"),
    (r"linux-(.+-)?tegra(-.+)?", "Ubuntu 的 NVIDIA Tegra 核心（linux-*-tegra*）"),
    (r"nvidia-l4t-kernel(-.+)?", "NVIDIA Jetson Linux（L4T）核心套件（nvidia-l4t-kernel、-dtbs、-oot-modules…）"),
    (r"kernel(-(core|modules|modules-core|modules-extra|default|rt|rt-core|64k|64k-core|uek|uek-core|lpae))?",
     "RHEL／Fedora／SUSE／Oracle Linux 核心（kernel、kernel-core、kernel-modules*、kernel-default、kernel-uek…）"),
    (r"linux-(lts|virt|edge|rpi)", "Alpine 核心（linux-lts、linux-virt、linux-edge、linux-rpi）"),
)
_PKG_RE = [re.compile(f"^{p}$") for p, _ in KERNEL_PACKAGE_PATTERNS]
# 名稱裡有這些段落的不算核心（不含執行中的核心）：例如 linux-headers-…-tegra、nvidia-l4t-kernel-headers、linux-tools-…-tegra
NOT_KERNEL_SEGMENTS = ("headers", "tools", "cloud-tools", "doc", "source", "buildinfo", "dbg", "dbgsym", "devel", "libc")
MODULE_PATH_RE = re.compile(r"^/(?:usr/)?lib/modules/([^/]+)/")


class InputError(Exception):
    pass


def purl_type_name(purl):
    """pkg:type/namespace/name@version?… → (type, name)（name 不含 namespace，已解碼）；不是 purl 回 (None, None)。"""
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return None, None
    body = purl[4:].split("#", 1)[0].split("?", 1)[0]
    if "/" not in body:
        return None, None
    typ, rest = body.split("/", 1)
    name = rest.rsplit("/", 1)[-1].split("@", 1)[0]
    return typ.lower(), unquote(name)


def is_kernel_package_name(name):
    if not isinstance(name, str) or not name:
        return False
    n = name.lower()
    if any(seg in n.split("-") for seg in NOT_KERNEL_SEGMENTS):
        return False
    return any(r.match(n) for r in _PKG_RE)


def props(c):
    out = collections.defaultdict(list)
    for p in c.get("properties") or []:
        if isinstance(p, dict) and isinstance(p.get("name"), str):
            out[p["name"]].append(p.get("value"))
    return out


def walk(cs):
    if cs is None:
        return
    if not isinstance(cs, list):
        raise InputError("components 不是清單")
    for c in cs:
        if isinstance(c, dict):
            yield c
            yield from walk(c.get("components"))


def is_kernel_cpe(cpe):
    return isinstance(cpe, str) and cpe.lower().startswith(KERNEL_CPE_PREFIX)


def classify_component(c):
    """回傳 'linux-kernel'、'linux-kernel-module'、'package' 或 None。"""
    pr = props(c)
    styp = (pr.get("syft:package:type") or [None])[0]
    if styp in KERNEL_SYFT_TYPES:
        return styp
    if is_kernel_cpe(c.get("cpe")):
        return "linux-kernel"
    typ, name = purl_type_name(c.get("purl"))
    if typ is None:
        typ, name = styp, c.get("name")
    if typ in PACKAGE_TYPES and is_kernel_package_name(name):
        return "package"
    return None


def module_version(c):
    """核心模組的核心版本：路徑 /usr/lib/modules/<版本>/ 優先，沒有時用 syft:metadata:kernelVersion。回傳 (版本, 來源) 或 (None, None)。"""
    pr = props(c)
    paths = [v for k, vs in pr.items() if k == "syft:metadata:path" or re.fullmatch(r"syft:location:\d+:path", k) for v in vs]
    for ev in ((c.get("evidence") or {}).get("occurrences") or []):
        if isinstance(ev, dict):
            paths.append(ev.get("location"))
    for p in paths:
        m = MODULE_PATH_RE.match(p) if isinstance(p, str) else None
        if m:
            return m.group(1), "modules_path"
    kv = (pr.get("syft:metadata:kernelVersion") or [None])[0]
    if isinstance(kv, str) and kv.strip():
        return kv.strip(), "module_metadata"
    return None, None


def brief(c):
    return {"name": c.get("name"), "version": c.get("version"), "purl": c.get("purl")}


def detect(sbom):
    if not isinstance(sbom, dict):
        raise InputError("SBOM 不是 JSON 物件")
    kernels, modules, packages = [], [], []
    mod_versions = collections.Counter()
    mod_sources = {}
    for c in walk(sbom.get("components")):
        k = classify_component(c)
        if k == "linux-kernel":
            kernels.append(brief(c))
        elif k == "linux-kernel-module":
            modules.append(brief(c))
            v, src = module_version(c)
            if v:
                mod_versions[v] += 1
                mod_sources.setdefault(v, src)
        elif k == "package":
            b = brief(c)
            b["purl_type"] = purl_type_name(c.get("purl"))[0] or (props(c).get("syft:package:type") or [None])[0]
            packages.append(b)
    versions = []
    for x in kernels:
        if x["version"] and x["version"] != "UNKNOWN":
            versions.append({"version": x["version"], "source": "linux_kernel_component", "from": x["name"] or x["purl"]})
    if not versions:
        for v, n in mod_versions.most_common():
            src = mod_sources[v]
            versions.append({"version": v, "source": src, "modules": n,
                             "from": f"/usr/lib/modules/{v}/" if src == "modules_path" else "syft:metadata:kernelVersion"})
    if not versions:
        seen = set()
        for x in packages:
            if x["version"] and x["version"] not in seen:
                seen.add(x["version"])
                versions.append({"version": x["version"], "source": "kernel_package", "from": x["name"]})
    return {"linux_kernel": kernels, "linux_kernel_modules": len(modules), "linux_kernel_module_sample": modules[:20],
            "kernel_packages": packages}, versions


def grype_artifact_is_kernel(a, details=()):
    if not isinstance(a, dict):
        return False
    if a.get("type") in KERNEL_SYFT_TYPES:
        return True
    cpes = list(a.get("cpes") or [])
    for d in details or []:
        if isinstance(d, dict):
            for part in ("searchedBy", "found"):
                x = d.get(part)
                if isinstance(x, dict):
                    cpes += x.get("cpes") or []
    if any(is_kernel_cpe(c) for c in cpes):
        return True
    typ, name = purl_type_name(a.get("purl"))
    if typ is None:
        typ, name = a.get("type"), a.get("name")
    return typ in PACKAGE_TYPES and is_kernel_package_name(name)


def grype_counts(grype):
    if not isinstance(grype, dict) or not isinstance(grype.get("matches"), list):
        raise InputError("Grype JSON 沒有 matches 清單")
    by = collections.Counter()
    for m in grype["matches"]:
        if isinstance(m, dict) and grype_artifact_is_kernel(m.get("artifact"), m.get("matchDetails")):
            a = m["artifact"]
            by[a.get("name") or "?"] += 1
    ignored_kernel, ignored_upstream_linux = 0, collections.Counter()
    for m in grype.get("ignoredMatches") or []:
        if not isinstance(m, dict):
            continue
        a = m.get("artifact") or {}
        if grype_artifact_is_kernel(a, m.get("matchDetails")):
            ignored_kernel += 1
        elif isinstance(a, dict) and any(isinstance(u, dict) and u.get("name") == "linux" for u in a.get("upstreams") or []):
            ignored_upstream_linux[a.get("name") or "?"] += 1
    return {"matches": sum(by.values()), "by_artifact": dict(by.most_common(50)), "ignored_kernel": ignored_kernel,
            "ignored_upstream_linux": dict(ignored_upstream_linux)}


def dt_counts(findings):
    if not isinstance(findings, list):
        raise InputError("DT findings 不是清單")
    n = 0
    for f in findings:
        c = (f.get("component") if isinstance(f, dict) else None) or {}
        if not isinstance(c, dict):
            continue
        typ, name = purl_type_name(c.get("purl"))
        if is_kernel_cpe(c.get("cpe")) or (typ in PACKAGE_TYPES and is_kernel_package_name(name)) \
                or (typ == "generic" and name == "linux-kernel"):
            n += 1
    return {"matches": n}


SOURCE_LABEL = {"linux_kernel_component": "linux-kernel 元件", "modules_path": "模組路徑",
                "module_metadata": "模組的 syft:metadata:kernelVersion", "kernel_package": "核心套件"}


def version_text(versions):
    """「版本 X（來源：…）」；status 說明欄只有 500 位元組，所以要短，完整證據在 json。"""
    if not versions:
        return "版本未知"
    v0 = versions[0]
    src = SOURCE_LABEL.get(v0["source"], v0["source"])
    if v0["source"] in ("modules_path", "kernel_package"):
        src += f" {v0['from']}"
    more = f"，另有 {len(versions) - 1} 個版本" if len(versions) > 1 else ""
    return f"版本 {v0['version']}（來源：{src}{more}）"


def what_text(comps):
    parts = []
    if comps["linux_kernel"]:
        parts.append(f"linux-kernel 元件 {len(comps['linux_kernel'])} 個")
    if comps["linux_kernel_modules"]:
        parts.append(f"模組 {comps['linux_kernel_modules']} 個")
    if comps["kernel_packages"]:
        first = sorted(p["name"] for p in comps["kernel_packages"] if p["name"])[:1]
        parts.append(f"核心套件 {len(comps['kernel_packages'])} 個" + (f"（{first[0]} 等）" if first else ""))
    return "、".join(parts)


def mapped_kernel(kmap):
    """C-kernel-l4t-map 摘要裡加上（或 SBOM 已有）的 Canonical 核心：{name, version, purl, release}；沒有對應時回 None。"""
    if kmap is None:
        return None
    if not isinstance(kmap, dict):
        raise InputError("--kernel-map 不是 JSON 物件")
    c = (kmap.get("map_entry") or {}).get("component") if kmap.get("status") == "OK" else None
    if not isinstance(c, dict):
        return None
    return {"name": c.get("name"), "version": c.get("version"), "purl": c.get("purl"), "release": kmap.get("release")}


def assess(sbom, grype=None, dt_findings=None, kmap=None):
    """回傳 (狀態, 說明, 證據)。輸入結構不對時丟 InputError。dt_findings 可省略（sca-scan 在 C-grype 之後、DT 之前執行）。"""
    comps, versions = detect(sbom)
    mk = mapped_kernel(kmap)
    present = bool(comps["linux_kernel"] or comps["linux_kernel_modules"] or comps["kernel_packages"])
    g = grype_counts(grype) if grype is not None else None
    d = dt_counts(dt_findings) if dt_findings is not None else None
    ev = {"schema": "sca-pilot-kernel-coverage/1", "kernel_present": present, "versions": versions,
          "version_source": versions[0]["source"] if versions else None, "components": comps,
          "matches": {"grype": g, "dt": d}, "possible_reasons": [], "not_counted": [], "mapped_kernel": mk,
          "rules": {"syft_types": list(KERNEL_SYFT_TYPES), "cpe_prefix": KERNEL_CPE_PREFIX, "package_types": list(PACKAGE_TYPES),
                    "package_patterns": [{"regex": f"^{p}$", "why": w} for p, w in KERNEL_PACKAGE_PATTERNS],
                    "not_kernel_segments": list(NOT_KERNEL_SEGMENTS)}}
    if not present:
        st, detail = "NOT_RUN", "SBOM 沒有作業系統核心（沒有 linux-kernel／linux-kernel-module 元件、Linux 核心 CPE 或核心套件）"
    else:
        vt, what = version_text(versions), what_text(comps)
        gn = g["matches"] if g else 0
        dn = d["matches"] if d else 0
        if gn + dn > 0:
            st = "OK"
            tools = f"Grype {gn}" + (f"、DT {dn}" if d is not None else "")
            via = f"；比對對象含 L4T {mk['release']} 對應的 Canonical 核心 {mk['name']} {mk['version']}（C-kernel-l4t-map）" if mk else ""
            detail = f"核心有比對，{gn + dn} 筆（{tools}）；核心{vt}；{what}{via}（只表示有做核心比對，不代表核心的弱點完整）"
        else:
            st = "GAP"
            why = ev["possible_reasons"]
            if mk:
                why.append(f"已加上 L4T {mk['release']} 對應的 Canonical 核心 {mk['name']} {mk['version']}（C-kernel-l4t-map），"
                           "對它仍 0 筆：確認 Grype 資料庫有這個 Ubuntu 原始碼套件的紀錄")
            if not comps["linux_kernel"]:
                why.append("Syft 沒有辨識出 linux-kernel 元件（核心執行檔），沒有可依版本比對的核心元件")
            if comps["kernel_packages"]:
                why.append("核心套件不在發行版的弱點資料裡（例如廠商的 nvidia-l4t-kernel），Grype 以套件名稱比對不到")
            if comps["linux_kernel_modules"]:
                why.append("核心模組是 pkg:generic、版本多為 UNKNOWN，沒有可比對的弱點資料")
            if g and g["ignored_upstream_linux"]:
                ev["not_counted"].append({"what": "Grype 預設規則忽略的比對（上游 linux 的使用者空間標頭，例如 linux-libc-dev；版本不是執行中的核心）",
                                          "counts": g["ignored_upstream_linux"]})
            head = "沒有 Grype 結果" if g is None and d is None else "對核心的比對 0 筆"
            detail = (f"偵測到作業系統核心，{vt}；{what}。{head}：核心沒有做漏洞比對，核心的 CVE 未評估（0 筆不代表沒有）；"
                      "原因與證據見 scan/kernel-coverage.json")
    ev["status"], ev["detail"] = st, detail
    return st, detail, ev


def load(path, label):
    try:
        with open(path, encoding="utf-8-sig") as f:
            return json.load(f)
    except (OSError, ValueError, RecursionError) as e:
        raise InputError(f"{label} 無法讀取或解析（{type(e).__name__}）")


def line(st, detail):
    print(f"{STAGE}\t{st}\t" + detail.replace("\t", " ").replace("\n", " "))


def main(argv=None):
    ap = argparse.ArgumentParser(description="作業系統核心的漏洞比對涵蓋（C-kernel-coverage）")
    ap.add_argument("--sbom", required=True)
    ap.add_argument("--grype")
    ap.add_argument("--dt-findings")
    ap.add_argument("--kernel-map")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    try:
        sbom = load(a.sbom, "SBOM")
        grype = load(a.grype, "Grype JSON") if a.grype else None
        dt = load(a.dt_findings, "DT findings") if a.dt_findings else None
        kmap = load(a.kernel_map, "核心對應摘要") if a.kernel_map else None
        st, detail, ev = assess(sbom, grype, dt, kmap)
    except InputError as e:
        line("FAIL", f"kernelcheck.py 輸入錯誤：{e}")
        return 3
    except Exception as e:   # 結構意外（例如欄位型別不對）：記 FAIL，不讓掃描中斷、不印 traceback
        line("FAIL", f"kernelcheck.py 無法判定（{type(e).__name__}）")
        return 3
    try:
        with open(a.out, "w", encoding="utf-8") as f:
            json.dump(ev, f, ensure_ascii=False, indent=1)
    except OSError as e:
        line("FAIL", f"無法寫入 {a.out}（{type(e).__name__}）")
        return 3
    line(st, detail)
    return 0


if __name__ == "__main__":
    sys.exit(main())
