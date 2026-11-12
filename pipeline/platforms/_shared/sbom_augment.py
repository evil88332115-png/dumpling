#!/usr/bin/env python3
"""WP7：在分層（pipeline/sbom-layers.py split）之前，把映像掃描以外的元件併進產品 SBOM（CycloneDX JSON）。一律 `python3 -I`。

  sbom_augment.py raw-sectors  <sbom> <raw-sectors.json> <輸出 sbom>
  sbom_augment.py merge-source <sbom> <原始碼 sbom> <輸出 sbom> --label <名稱> --repo <https 網址> --commit <40 位 SHA>
最後一行 `sbom-augment: OK｜GAP｜FAIL（說明）`；結束碼 OK 0、FAIL 1、GAP 3、用法錯誤 64。輸入是不可信資料，只讀。

raw-sectors（Rockchip）：raw_sectors.py 清點出的每個區段 → 一個 type firmware 的元件（分層規則 2：firmware → bsp），
  雜湊是區段的 sha256；區段裡讀到的版本字串（U-Boot SPL、DDR 初始化、TF-A BL31、U-Boot）→ 子元件。
  - 版本讀不到 → 不填 version，property `dumpling:version-status` = GAP（不猜）。
  - 閉源成品（Rockchip DDR 初始化、rkbin 的 TF-A BL31）→ `dumpling:closed-source` = true、`dumpling:advisory-check` = GAP
    （沒有可機器比對的安全公告）。
  - U-Boot（廠商分支）不給 CPE／purl：`dumpling:advisory-check` = NOT_ASSESSED（不拿上游版本號去套漏洞資料）。
  - 每個元件都有 `dumpling:origin` = raw-sectors、起始 LBA、磁區數、佐證結果（一致／不一致／找不到）。
merge-source（AI NAS 的 OpenMediaVault 原始碼）：
  - 映像的元件（含子元件）都加 `dumpling:origin` = image（已經有的不改）。
  - 原始碼 SBOM 的元件與它的 metadata.component（應用本身）併進來，bom-ref 一律改成 `dumpling:src:<名稱>:<原本的 ref>`（不跟映像的撞），
    每個元件加 `dumpling:origin` = source、`dumpling:origin-repo`、`dumpling:origin-commit`；
    應用本身另加 `dumpling:source-vs-package` = NOT_ASSESSED（原始碼與正式 deb 是否完全相同沒有比對，D-025）。
  - dependencies 一起合併（ref 照樣改名）；兩端都在合併後元件裡的邊才保留，丟掉的邊數寫在 metadata 的 property。
  - 產品根元件（metadata.component）加一條依賴指到應用本身。
輸出是確定的（同樣輸入同樣位元組）。
"""
import argparse
import copy
import json
import lzma
import os
import re
import sys

MAX_SBOM = 1 << 30
OK, FAIL, GAP, USAGE = 0, 1, 3, 64
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")

CLOSED = {"Rockchip DDR init": "Rockchip DDR 初始化（rkbin 成品，閉源）",
          "TF-A BL31 (Rockchip rkbin)": "TF-A BL31（Rockchip rkbin 成品，閉源）"}
SLOT_NAMES = {"idbloader.img": "Rockchip idbloader（DDR 初始化＋U-Boot SPL）",
              "u-boot.itb": "U-Boot FIT 映像（U-Boot＋TF-A BL31）",
              "trust.img": "Rockchip trust 映像（TF-A／OP-TEE）"}


class AugError(Exception):
    pass


def read_json(path):
    if os.path.islink(path) or not os.path.isfile(path):
        raise AugError("%s 不是一般檔案" % path)
    if os.path.getsize(path) > MAX_SBOM:
        raise AugError("%s 太大" % path)
    with open(path, "rb") as f:
        raw = f.read(MAX_SBOM + 1)
    if path.endswith(".xz"):
        d = lzma.LZMADecompressor()
        raw = d.decompress(raw, max_length=MAX_SBOM + 1)
        if len(raw) > MAX_SBOM or not d.eof:
            raise AugError("%s 解壓後太大或不完整" % path)
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise AugError("%s 不是 JSON：%s" % (path, e))


def check_bom(doc, what):
    if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX":
        raise AugError("%s 不是 CycloneDX JSON" % what)
    if not isinstance(doc.get("components", []), list) or not isinstance(doc.get("dependencies", []), list):
        raise AugError("%s 的 components／dependencies 格式錯" % what)


def write_json(doc, path):
    tmp = path + ".part"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
        f.write("\n")
    os.replace(tmp, path)


def prop(c, name, value):
    ps = c.setdefault("properties", [])
    if not any(p.get("name") == name for p in ps if isinstance(p, dict)):
        ps.append({"name": name, "value": str(value)})


def walk(comps):
    for c in comps or []:
        if isinstance(c, dict):
            yield c
            yield from walk(c.get("components"))


def add_root_deps(doc, refs):
    root = (doc.get("metadata") or {}).get("component") or {}
    rref = root.get("bom-ref")
    if not rref:
        return False
    deps = doc.setdefault("dependencies", [])
    entry = next((d for d in deps if isinstance(d, dict) and d.get("ref") == rref), None)
    if entry is None:
        entry = {"ref": rref, "dependsOn": []}
        deps.append(entry)
    for r in refs:
        if r not in entry.setdefault("dependsOn", []):
            entry["dependsOn"].append(r)
    return True


def meta_prop(doc, name, value):
    md = doc.setdefault("metadata", {})
    ps = md.setdefault("properties", [])
    ps[:] = [p for p in ps if not (isinstance(p, dict) and p.get("name") == name)]
    ps.append({"name": name, "value": str(value)})


# ---------------------------------------------------------------- raw-sectors

def from_raw_sectors(doc, raw):
    if not isinstance(raw, dict) or raw.get("schema") != 1 or not isinstance(raw.get("regions"), list):
        raise AugError("raw-sectors.json 格式錯")
    new, gaps = [], []
    for r in raw["regions"]:
        slot, lba = r.get("slot"), r.get("start_lba")
        if not isinstance(lba, int) or not isinstance(r.get("sha256"), str):
            raise AugError("raw-sectors.json 的區段格式錯")
        ref = "dumpling:raw-sectors:%s@%d" % (slot or "unknown", lba)
        ident = r.get("identity") or {}
        c = {"bom-ref": ref, "type": "firmware", "name": SLOT_NAMES.get(slot, "分割區外的原始磁區（身分不明）"),
             "hashes": [{"alg": "SHA-256", "content": r["sha256"]}], "properties": []}
        versions = [v for v in ident.get("versions") or [] if isinstance(v, dict)]
        main = next((v["version"] for v in versions if v.get("component") in ("U-Boot", "U-Boot SPL")), None)
        if main:
            c["version"] = main
        else:
            prop(c, "dumpling:version-status", "GAP")
            gaps.append("LBA %d 讀不到版本" % lba)
        prop(c, "dumpling:origin", "raw-sectors")
        prop(c, "dumpling:raw-sectors:slot", slot or "unknown")
        prop(c, "dumpling:raw-sectors:start_lba", lba)
        prop(c, "dumpling:raw-sectors:sectors", r.get("sectors"))
        prop(c, "dumpling:raw-sectors:kind", ident.get("kind", "unknown"))
        for i, cb in enumerate(r.get("corroboration") or []):
            prop(c, "dumpling:raw-sectors:corroboration:%d" % i, "%s %s：%s" % (cb.get("source"), cb.get("file"), cb.get("state")))
        if not any((cb.get("state") == "一致") for cb in r.get("corroboration") or []):
            prop(c, "dumpling:raw-sectors:corroboration-status", "GAP")
            gaps.append("LBA %d 沒有佐證一致" % lba)
        subs, seen = [], set()
        for v in versions:
            comp, ver = v.get("component"), v.get("version")
            if comp in (None, "TF-A git describe") or (comp, ver) in seen:
                continue
            seen.add((comp, ver))
            s = {"bom-ref": "%s/%s@%s" % (ref, re.sub(r"[^A-Za-z0-9._-]+", "-", comp), ver), "type": "firmware",
                 "name": CLOSED.get(comp, comp), "version": ver, "properties": []}
            prop(s, "dumpling:origin", "raw-sectors")
            if comp in CLOSED:
                prop(s, "dumpling:closed-source", "true")
                prop(s, "dumpling:advisory-check", "GAP")
                desc = next((x["version"] for x in versions if x.get("component") == "TF-A git describe"), None)
                if comp.startswith("TF-A") and desc:
                    prop(s, "dumpling:tf-a-describe", desc)
            else:
                prop(s, "dumpling:advisory-check", "NOT_ASSESSED")
            subs.append(s)
        if subs:
            c["components"] = subs
        new.append(c)
        doc.setdefault("dependencies", []).append({"ref": ref, "dependsOn": [s["bom-ref"] for s in subs]})
    existing = {c.get("bom-ref") for c in walk(doc.get("components"))}
    dup = [c["bom-ref"] for c in new if c["bom-ref"] in existing]
    if dup:
        raise AugError("SBOM 裡已經有 %s（重複執行？）" % dup[0])
    doc.setdefault("components", []).extend(new)
    add_root_deps(doc, [c["bom-ref"] for c in new])
    meta_prop(doc, "dumpling:augment:raw-sectors", "%d 個區段" % len(new))
    if not new:
        gaps.append("raw-sectors.json 沒有任何區段")
    return len(new), gaps


# ---------------------------------------------------------------- merge-source

def merge_source(doc, src, label, repo, commit):
    for c in walk(doc.get("components")):
        prop(c, "dumpling:origin", "image")
    pre = "dumpling:src:%s:" % label
    mapping = {}

    def remap(c):
        c = copy.deepcopy(c)
        old = c.get("bom-ref")
        if old is not None:
            if not isinstance(old, str):
                raise AugError("原始碼 SBOM 的 bom-ref 不是字串")
            mapping[old] = pre + old
            c["bom-ref"] = pre + old
        else:
            c["bom-ref"] = pre + "anon-%d" % len(mapping)
            mapping[c["bom-ref"]] = c["bom-ref"]
        c["properties"] = [p for p in c.get("properties") or [] if isinstance(p, dict) and not str(p.get("name", "")).startswith("dumpling:origin")]
        prop(c, "dumpling:origin", "source")
        prop(c, "dumpling:origin-label", label)
        prop(c, "dumpling:origin-repo", repo)
        prop(c, "dumpling:origin-commit", commit)
        if c.get("components"):
            c["components"] = [remap(x) for x in c["components"] if isinstance(x, dict)]
        return c

    app = (src.get("metadata") or {}).get("component")
    merged = []
    app_ref = None
    if isinstance(app, dict):
        a = remap(app)
        a.setdefault("type", "application")
        prop(a, "dumpling:source-vs-package", "NOT_ASSESSED")
        app_ref = a["bom-ref"]
        merged.append(a)
    for c in src.get("components") or []:
        if isinstance(c, dict):
            merged.append(remap(c))
    existing = {c.get("bom-ref") for c in walk(doc.get("components"))}
    clash = [c["bom-ref"] for c in walk(merged) if c["bom-ref"] in existing]
    if clash:
        raise AugError("SBOM 裡已經有 %s（重複執行？）" % clash[0])
    doc.setdefault("components", []).extend(merged)
    allrefs = {c.get("bom-ref") for c in walk(doc["components"])}
    kept = dropped = 0
    for d in src.get("dependencies") or []:
        if not isinstance(d, dict) or not isinstance(d.get("ref"), str):
            dropped += 1
            continue
        ref = mapping.get(d["ref"])
        outs = []
        for x in d.get("dependsOn") or []:
            y = mapping.get(x) if isinstance(x, str) else None
            if y in allrefs:
                outs.append(y)
            else:
                dropped += 1
        if ref not in allrefs:
            dropped += len(outs) + (0 if outs else 1)
            continue
        doc.setdefault("dependencies", []).append({"ref": ref, "dependsOn": outs})
        kept += len(outs)
    if app_ref:
        add_root_deps(doc, [app_ref])
    meta_prop(doc, "dumpling:augment:source:%s" % label, "%s@%s：%d 個元件、%d 條依賴邊（丟掉 %d 條懸空的）"
              % (repo, commit, len(list(walk(merged))), kept, dropped))
    gaps = [] if app_ref else ["原始碼 SBOM 沒有 metadata.component（應用本身），無法標 source-vs-package"]
    return len(list(walk(merged))), kept, dropped, gaps


def main(argv=None):
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd")
    r = sub.add_parser("raw-sectors")
    r.add_argument("sbom"); r.add_argument("raw"); r.add_argument("out")
    m = sub.add_parser("merge-source")
    m.add_argument("sbom"); m.add_argument("src"); m.add_argument("out")
    m.add_argument("--label", required=True); m.add_argument("--repo", required=True); m.add_argument("--commit", required=True)
    try:
        a = ap.parse_args(argv)
    except SystemExit:
        print("sbom-augment: FAIL（參數錯誤）")
        return USAGE
    if a.cmd is None:
        print("sbom-augment: FAIL（要給子指令 raw-sectors 或 merge-source）")
        return USAGE
    if a.cmd == "merge-source":
        if not LABEL_RE.match(a.label) or not a.repo.startswith("https://") or not SHA1_RE.match(a.commit):
            print("sbom-augment: FAIL（--label、--repo（https）或 --commit（40 位小寫十六進位）不合法）")
            return USAGE
    try:
        doc = read_json(a.sbom)
        check_bom(doc, "SBOM")
        if a.cmd == "raw-sectors":
            n, gaps = from_raw_sectors(doc, read_json(a.raw))
            msg = "加入 %d 個原始磁區元件" % n
        else:
            src = read_json(a.src)
            check_bom(src, "原始碼 SBOM")
            n, kept, dropped, gaps = merge_source(doc, src, a.label, a.repo, a.commit)
            msg = "併入 %s 的 %d 個元件、%d 條依賴邊（丟掉 %d 條懸空的）" % (a.label, n, kept, dropped)
        write_json(doc, a.out)
    except AugError as e:
        print("sbom-augment: FAIL（%s）" % e)
        return FAIL
    if gaps:
        print("sbom-augment: GAP（%s；%s）" % (msg, "；".join(gaps)))
        return GAP
    print("sbom-augment: OK（%s）" % msg)
    return OK


if __name__ == "__main__":
    sys.exit(main())
