#!/usr/bin/env python3
"""deb_sources.py：上傳 Dependency-Track 的 SBOM 補上 Debian／Ubuntu 的「原始碼套件」元件（sca-scan 的 D-dt-deb-sources）。

用法：python3 -I deb_sources.py <輸入 SBOM> <輸出 SBOM> <摘要 JSON>
stdout 印一行「狀態<TAB>說明」；退出碼 0（讀寫失敗時 1）。

為什麼：Ubuntu／Debian 的漏洞資料（OSV 的 Ubuntu、Debian 生態系）以「原始碼套件」名稱記錄，例如遠端桌面的漏洞記在 freerdp3，
映像裡裝的卻是 libfreerdp3-3、libfreerdp-client3-3 等二進位套件。DT 用元件的 purl 名稱比對，所以二進位名稱和原始碼名稱不同的套件
完全比對不到。Jetson R39.2.1 示範（demo-run/4）：Grype 有比對到的 619 個 Ubuntu 套件中，名稱不同的 537 個 DT 只比對到 1 個，
名稱相同的 82 個 DT 比對到 80 個；Grype 有、DT 沒有的 6593 筆裡 2441 筆是「Ubuntu 已修補、映像裡的版本還沒升級」。
Grype 用 Syft 記下的原始碼名稱（purl 的 upstream qualifier）比對，所以沒有這個問題。

做法：每個二進位名稱和原始碼名稱不同的 deb 元件，依 upstream qualifier（Syft 從 dpkg 的 Source 欄位填，格式 <名稱> 或 <名稱>@<版本>）
加一個原始碼套件元件：pkg:deb/<namespace>/<原始碼名稱>@<原始碼版本>?arch=source&distro=<同二進位>。原始碼版本取 upstream 裡的版本，
沒有時就是二進位版本（dpkg 只在不同時才寫）。同一個原始碼套件只加一次；SBOM 裡已經有同名同版本的 deb 元件時不加（已經比對得到）。
不加的還有：
- 原始碼名稱和二進位名稱相同、只有版本不同（binNMU，例如 foo@1.0-1+b1 的原始碼是 foo@1.0-1）：DT 已經用名稱比對得到，再加會重複計數。
- 核心原始碼套件：原始碼名稱就是 linux（例如 linux-libc-dev、bpftool、usbip，都會被當成整個核心比對），或原始碼與二進位名稱
  都是 linux- 開頭（核心的各種版本，例如 linux-nvidia-tegra 的 linux-image-*、linux-modules-*；-dkms 結尾的模組原始碼除外）。
  linux-libc-dev 是使用者空間標頭，不是執行中的核心，用上游 linux 比對會報出整個核心的漏洞（Grype 預設規則同樣忽略）。
  DT 因此不從二進位套件補核心；核心的涵蓋情況看 C-kernel-coverage（lib/kernelcheck.py，依 Grype 的結果判斷）。
  Jetson Linux 的核心另由 C-kernel-l4t-map（lib/l4t_kernel.py）加上對應的 Canonical 核心原始碼套件（例如 linux-nvidia-tegra，
  arch=source）；它的原始碼名稱就是自己的名稱，這裡照常保留、不重複加。
  原始碼不是 linux、二進位名稱也不是 linux- 開頭的照常補（例如 linux-atm 的 libatm1）。
只給 DT 用：ScanCode.io／DejaCode 收的 SBOM 不加（那些是沒有安裝的套件，不能出現在產品套件清單）。原始 SBOM 不動。
加上的元件帶屬性 sca-center:deb-source-of（來自哪些二進位套件）；摘要 JSON 的 added[].binary_purls 記二進位套件的完整 purl，
report.py 據此把 DT 對到原始碼套件的漏洞對回實際安裝的二進位套件，和 Grype 的紀錄合成一列。SBOM 裡已經有原始碼同名同版本的
套件時（例如 openssl 和 libssl3t64），不加元件，摘要的 shared_sources 記下同一原始碼的其他二進位套件，報告同樣把 DT 的紀錄對過去。
"""
import json
import re
import sys
import urllib.parse as up

PURL = re.compile(r"pkg:deb/([^/@?#]+)/([^@?#]+)@([^?#]*)(?:\?([^#]*))?")


def components(cs):
    for c in cs or []:
        yield c
        yield from components(c.get("components"))


def parse(purl):
    """deb purl → (namespace, name, version, qualifiers)；不是 deb purl 回傳 None。"""
    m = PURL.fullmatch(purl or "")
    if not m:
        return None
    q = {}
    for kv in (m.group(4) or "").split("&"):
        if "=" in kv:
            k, v = kv.split("=", 1)
            q[k.lower()] = up.unquote(v)
    return m.group(1), up.unquote(m.group(2)), up.unquote(m.group(3)), q


def source_of(name, version, q):
    """(原始碼名稱, 原始碼版本)；upstream 空白時就是二進位本身。"""
    u = (q.get("upstream") or "").strip()
    if not u:
        return name, version
    src, _, ver = u.partition("@")
    return src.strip() or name, (ver.strip() or version)


def is_kernel(name, src):
    return src == "linux" or (src.startswith("linux-") and name.startswith("linux-") and not name.endswith("-dkms"))


def add_sources(bom):
    have, sources, skipped, shared = set(), {}, set(), {}
    for c in components(bom.get("components")):
        p = parse(c.get("purl"))
        if p:
            have.add((p[0], p[1], p[2]))
    for c in components(bom.get("components")):
        p = parse(c.get("purl"))
        if not p:
            continue
        ns, name, ver, q = p
        src, sver = source_of(name, ver, q)
        if src == name:
            continue
        if is_kernel(name, src):
            skipped.add(name)
            continue
        if (ns, src, sver) in have:
            shared.setdefault((ns, src, sver), set()).add(c.get("purl"))
            continue
        k = (ns, src, sver, q.get("distro", ""))
        sources.setdefault(k, []).append((name, c.get("purl")))
    added = []
    for (ns, src, sver, distro), bins in sorted(sources.items()):
        qs = "arch=source" + (f"&distro={up.quote(distro, safe='')}" if distro else "")
        purl = f"pkg:deb/{up.quote(ns, safe='')}/{up.quote(src, safe='')}@{up.quote(sver, safe='')}?{qs}"
        added.append({"type": "library", "bom-ref": f"sca-center-deb-source:{purl}", "name": src, "version": sver, "purl": purl,
                      "properties": [{"name": "sca-center:deb-source-of", "value": ", ".join(sorted({b for b, _ in bins}))}],
                      "_binary_purls": sorted({p for _, p in bins})})
    bom.setdefault("components", []).extend(added)
    shared = [{"purl": f"pkg:deb/{up.quote(ns, safe='')}/{up.quote(src, safe='')}@{up.quote(sver, safe='')}", "binary_purls": sorted(bp)}
              for (ns, src, sver), bp in sorted(shared.items())]
    return added, sorted(skipped), shared


def main(argv=None):
    a = sys.argv[1:] if argv is None else argv
    try:
        bom = json.load(open(a[0], encoding="utf-8"))
        ndeb = sum(1 for c in components(bom.get("components")) if parse(c.get("purl")))
        added, skipped, shared = add_sources(bom)
        bps = [x.pop("_binary_purls") for x in added]
        json.dump(bom, open(a[1], "w", encoding="utf-8"))
        nbin = sum(len(x["properties"][0]["value"].split(", ")) for x in added)
        json.dump({"deb_components": ndeb, "source_components_added": len(added), "binaries_covered": nbin,
                   "kernel_binaries_skipped": skipped, "shared_sources": shared,
                   "added": [{"purl": x["purl"], "binaries": x["properties"][0]["value"], "binary_purls": bp} for x, bp in zip(added, bps)]},
                  open(a[2], "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    except (OSError, ValueError, IndexError) as e:
        print(f"FAIL\t{type(e).__name__}: {e}"[:300])
        return 1
    if not ndeb:
        print("NOT_RUN\tSBOM 沒有 deb 元件")
    else:
        print(f"OK\tdeb 元件 {ndeb} 個；加上原始碼套件元件 {len(added)} 個（對應 {nbin} 個名稱不同的二進位套件），只給 DT 比對 Ubuntu／Debian 漏洞資料"
              + (f"；核心套件 {len(skipped)} 個不補（不從二進位套件補核心，見 C-kernel-coverage）" if skipped else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
