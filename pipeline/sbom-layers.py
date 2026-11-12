#!/usr/bin/env python3
"""SBOM 依層標記與拆分（J 軌的 scan 步驟呼叫；規則與格式見 docs/LAYERS.md）。

用法（一律 `python3 -I`）：
  sbom-layers.py tag   <sbom> <平台> <專案資料夾> <輸出sbom>   [--os-responsibility X] [--platforms-dir D]
  sbom-layers.py split <sbom> <平台> <專案資料夾> <輸出資料夾> [--os-responsibility X] [--platforms-dir D]
  sbom-layers.py show  <標好層的sbom>

- 平台：pipeline/platforms/<平台>/platform.yml（也可給 platform.yml 的路徑）；專案資料夾：projects/<專案>/（讀 own_software 與
  os_responsibility；--os-responsibility 可覆寫專案的值）。
- tag：每個元件加 dumpling:layer／dumpling:layer-basis，metadata 加 dumpling:os-responsibility、dumpling:platform，寫一份新的 SBOM。
- split：先 tag，再依層拆成（輸出資料夾裡；沒有元件的檔案不產生）
    sbom.bsp.cdx.json        bsp 與 unknown 的元件（unknown 當我們的待辦，最保守）→ DT 專案 <名稱>-bsp
    sbom.os.cdx.json         os 的元件 → DT 專案 <名稱>-os
    sbom.host-tool.cdx.json  host-tool 的元件：不上傳 DT、不進產品漏洞清單（只留作記錄）
    sbom.product.cdx.json    bsp＋os＋unknown（沒有 host-tool），一份標好層的完整產品 SBOM → 單一 DT 專案
    layers.json              各層數量、掃描計畫（scan_plan）、unknown 的來源、丟掉的跨層依賴邊數、GAP
  輸出的 SBOM 都帶 dumpling:layer，cra_report.py 讀它把漏洞列分層。
最後一行：sbom-layers: OK｜GAP｜FAIL（說明）；結束碼 OK 0、FAIL 1、GAP 3、用法錯誤 64。
GAP＝沒有 os_responsibility（專案沒填又沒給 --os-responsibility）：不預設，掃描計畫退回單一專案、全部列入待辦。
unknown（判斷不了層）不是 GAP：列入我們的待辦並在 layers.json、最後一行寫出數量。
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "lib"))
import layers as ly  # noqa: E402
import project_config as pc  # noqa: E402

PRODUCT_FILE = "sbom.product.cdx.json"
FILES = {"bsp": "sbom.bsp.cdx.json", "os": "sbom.os.cdx.json", "host-tool": "sbom.host-tool.cdx.json"}


def usage(msg=None):
    if msg:
        print(msg, file=sys.stderr)
    print("用法：sbom-layers.py tag|split <sbom> <平台> <專案資料夾> <輸出> [--os-responsibility ours|customer|upstream-vendor] "
          "[--platforms-dir D] | show <標好層的sbom>", file=sys.stderr)
    return 64


def parse(argv):
    """→ (位置參數, 選項 dict)；選項不認得或缺值 → ValueError。"""
    pos, opts, i = [], {}, 0
    while i < len(argv):
        a = argv[i]
        if a in ("--os-responsibility", "--platforms-dir"):
            if i + 1 >= len(argv):
                raise ValueError("%s 要給值" % a)
            opts[a[2:]] = argv[i + 1]
            i += 2
        elif a.startswith("--"):
            raise ValueError("不認得的參數 " + a)
        else:
            pos.append(a)
            i += 1
    return pos, opts


def write_json(path, doc):
    tmp = path + ".part"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(doc)
    os.replace(tmp, path)


def setup(platform, project_dir, opts):
    """→ (平台設定, own_software 樣式, os_responsibility（可能是 None）)。"""
    pdir = opts.get("platforms-dir") or pc.PLATFORMS_DIR
    config = pc.load_platform_config(platform, pdir)
    project = pc.load_project(project_dir, pdir)
    resp = opts.get("os-responsibility") or project.get("os_responsibility")
    if resp not in pc.OS_RESPONSIBILITIES:
        raise pc.ConfigError("os_responsibility 必須是 %s" % "／".join(pc.OS_RESPONSIBILITIES))
    if project.get("platform") != config["platform"]:
        raise pc.ConfigError("專案的 platform 和指定的平台不同")
    return config, ly.own_patterns(project), resp


def scan_plan(resp, files):
    """依 os_responsibility 決定 scan 步驟要掃哪幾份（每份一個 DT 專案與一份報告）。"""
    def item(suffix, f, role):
        return {"name_suffix": suffix, "sbom": f, "report_role": role}
    if resp in ("customer", "upstream-vendor"):
        plan = []
        if "bsp" in files:
            plan.append(item("-bsp", files["bsp"], "bsp：我們的待辦"))
        if "os" in files:
            plan.append(item("-os", files["os"], "os：範例 rootfs，給客戶參考" if resp == "customer"
                             else "os：上游 OS 廠商負責，我們只通知客戶"))
        return plan
    # ours：OS 也是我們的待辦，一個專案、一份報告（層欄位照樣標）；沒給 os_responsibility：不預設，同樣全部列入待辦
    return [item("", PRODUCT_FILE, "product：bsp＋os（OS 也是我們的待辦）" if resp == "ours" else "product：全部列入待辦（沒有 os_responsibility）")]


def cmd_tag(pos, opts):
    if len(pos) != 4:
        return usage("tag 需要 4 個位置參數")
    sbom, platform, project_dir, out = pos
    config, own, resp = setup(platform, project_dir, opts)
    tagged, summary = ly.tag_sbom(ly.load_sbom(sbom), config, own, resp, config["platform"])
    write_json(out, ly.dumps(tagged))
    return report("tag", summary, resp)


def report(verb, summary, resp, extra=""):
    n = summary["layers"]
    gap = resp is None
    line = "bsp %d、os %d、host-tool %d、unknown %d（共 %d）" % (n["bsp"], n["os"], n["host-tool"], n["unknown"], summary["total"])
    if n["unknown"]:
        line += "；unknown 判斷不了層，列入我們的待辦"
    print("sbom-layers: %s（%s%s%s）" % ("GAP" if gap else "OK", line, "；沒有 os_responsibility，不預設，全部列入待辦" if gap else "", extra))
    return 3 if gap else 0


def cmd_split(pos, opts):
    if len(pos) != 4:
        return usage("split 需要 4 個位置參數")
    sbom, platform, project_dir, outdir = pos
    config, own, resp = setup(platform, project_dir, opts)
    tagged, summary = ly.tag_sbom(ly.load_sbom(sbom), config, own, resp, config["platform"])
    # bsp 檔＝bsp＋unknown（unknown 當我們的待辦）；product 檔＝除了 host-tool 以外全部
    parts, dropped = ly.split_sbom(tagged, {"bsp": "bsp", "unknown": "bsp", "os": "os", "host-tool": "host-tool"})
    product, _ = ly.split_sbom(tagged, {"bsp": "product", "unknown": "product", "os": "product"})
    parts.update(product)
    os.makedirs(outdir, exist_ok=True)
    files, info = {}, {}
    for key, part in parts.items():
        name = PRODUCT_FILE if key == "product" else FILES[key]
        write_json(os.path.join(outdir, name), ly.dumps(part))
        if key != "product":
            files[key] = name
        info[key] = {"file": name, "components": sum(1 for _ in ly.iter_components(part["components"])),
                     "layers": {k: v for k, v in ly.layer_counts(part).items() if v}}
    gaps = []
    if resp is None:
        gaps.append("沒有 os_responsibility：不預設，掃描計畫退回單一專案、全部列入待辦")
    doc = {"schema": ly.SCHEMA, "platform": config["platform"], "os_responsibility": resp, "os_responsibility_gap": resp is None,
           "components_total": summary["total"], "components": summary["layers"], "basis": summary["basis"],
           "unknown": {"count": summary["layers"]["unknown"], "by_purl_type": summary["unknown_by_purl_type"],
                       "by_reason": summary["unknown_by_reason"], "reasons": {k: v for k, v in ly.UNKNOWN_REASONS.items()},
                       "handling": "列入我們的待辦（bsp 檔與 DT 專案 -bsp），不歸成 os"},
           "own_software": summary["own_software"], "files": info, "upload_excludes": ["host-tool"],
           "scan_plan": scan_plan(resp, files), "dropped_dependency_edges": dropped, "gaps": gaps}
    write_json(os.path.join(outdir, "layers.json"), json.dumps(doc, ensure_ascii=False, indent=1) + "\n")
    return report("split", summary, resp, "；輸出 %s" % "、".join(sorted(v["file"] for v in info.values())))


def cmd_show(pos, opts):
    if len(pos) != 1:
        return usage("show 需要 1 個位置參數")
    bom = ly.load_sbom(pos[0])
    n = ly.layer_counts(bom)
    print(json.dumps({"layers": n, "total": sum(n.values()), "os_responsibility": ly.sbom_os_responsibility(bom)}, ensure_ascii=False))
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] not in ("tag", "split", "show"):
        return usage()
    try:
        pos, opts = parse(argv[1:])
    except ValueError as e:
        return usage(str(e))
    try:
        return {"tag": cmd_tag, "split": cmd_split, "show": cmd_show}[argv[0]](pos, opts)
    except (ly.LayerError, pc.ConfigError) as e:
        print("sbom-layers: FAIL（%s）" % e)
        return 1
    except OSError as e:
        print("sbom-layers: FAIL（檔案讀寫失敗：%s）" % type(e).__name__)
        return 1


if __name__ == "__main__":
    sys.exit(main())
