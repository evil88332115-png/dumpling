#!/usr/bin/env python3
"""strip_versions.py：產生上傳 DT／ScanCode.io 用的 SBOM 副本，把版本未知的元件（規則 13，sbomgate 判定）的版本移除。

用法：python3 -I strip_versions.py <原始 SBOM> <sbomgate.json> <輸出 SBOM>
- 版本來自範圍下限（例如 requests>=2.0 被寫成 2.0）的元件，若原樣上傳，DT 會用那個不存在的版本比對出誤報。
- 只移除 version 欄位與 purl 的 @版本；保留名稱、其他 purl 部分（qualifiers、subpath）與 bom-ref（相依圖要用），
  並加屬性 sca-pilot:version-removed 記錄原值與原因。原始 SBOM 不動（另存原樣）。
- 對應方式：purl 完全相同；沒有 purl 時用 名稱＋版本。
印出「移除 N 個元件的版本」。退出碼：0 完成；3 輸入錯誤。
"""
import json
import sys


def strip_purl_version(purl):
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return purl
    tail = ""
    for sep in ("#", "?"):
        if sep in purl:
            i = purl.index(sep)
            purl, tail = purl[:i], purl[i:] + tail
    head, slash, last = purl.rpartition("/")
    if "@" in last:
        last = last.split("@", 1)[0]
    return head + slash + last + tail


def main(argv=None):
    a = sys.argv[1:] if argv is None else argv
    if len(a) != 3:
        print("用法：strip_versions.py <原始 SBOM> <sbomgate.json> <輸出 SBOM>", file=sys.stderr)
        return 3
    try:
        sbom = json.load(open(a[0], encoding="utf-8-sig"))
        gate = json.load(open(a[1], encoding="utf-8-sig"))
    except (OSError, ValueError) as e:
        print(f"輸入錯誤：{type(e).__name__}", file=sys.stderr)
        return 3
    by_purl, by_nv = {}, {}
    for c in gate.get("component_details") or []:
        if isinstance(c, dict) and c.get("class") != "RESOLVED":
            if c.get("purl"):
                by_purl[c["purl"]] = c
            else:
                by_nv[(c.get("name"), c.get("version"))] = c
    n, stack = 0, list(sbom.get("components") or [])
    while stack:
        c = stack.pop()
        if not isinstance(c, dict):
            continue
        stack.extend(c.get("components") or [])
        full = f"{c['group']}/{c.get('name')}" if c.get("group") else c.get("name")
        hit = by_purl.get(c.get("purl")) if c.get("purl") else (by_nv.get((full, c.get("version"))) or by_nv.get((c.get("name"), c.get("version"))))
        if not hit:
            continue
        old = c.pop("version", None)
        if c.get("purl"):
            c["purl"] = strip_purl_version(c["purl"])
        c.setdefault("properties", []).append({"name": "sca-pilot:version-removed",
                                               "value": f"{old}（{hit.get('class')}：版本未知，規則 13，未做弱點比對）"})
        n += 1
    with open(a[2], "w", encoding="utf-8") as f:
        json.dump(sbom, f, ensure_ascii=False)
    print(f"移除 {n} 個元件的版本")
    return 0


if __name__ == "__main__":
    sys.exit(main())
