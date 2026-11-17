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
  - U-Boot 與 U-Boot SPL（廠商分支，D-034）：給上游的 CPE `cpe:2.3:a:denx:u-boot:<YYYY.MM>`，版本以磁區讀出的為準；
    `dumpling:vendor-branch`、`dumpling:vendor-commit` 記廠商分支與 commit；`dumpling:advisory-check` = ATTENTION 並註明
    上游 CVE 比對結果只是候選（廠商可能已回移修補），比對到的 CVE 進待人審（不設 VEX 判定，就是 untriaged），發行閘門照算。
    版本字串讀不出 YYYY.MM → 不給 CPE，`dumpling:advisory-check` = GAP。
  - 每個元件都有 `dumpling:origin` = raw-sectors、起始 LBA、磁區數、佐證結果（一致／不一致／找不到）。
merge-source（AI NAS 的 OpenMediaVault 原始碼）：
  - 映像的元件（含子元件）都加 `dumpling:origin` = image（已經有的不改）。
  - 原始碼 SBOM 的元件與它的 metadata.component（應用本身）併進來，bom-ref 一律改成 `dumpling:src:<名稱>:<原本的 ref>`（不跟映像的撞），
    每個元件加 `dumpling:origin` = source、`dumpling:origin-repo`、`dumpling:origin-commit`；
    應用本身另加 `dumpling:source-vs-package` = NOT_ASSESSED（原始碼與正式 deb 是否完全相同沒有比對，D-025）；
    給了 --app-name／--app-version 時，應用本身的名稱與版本改成這兩個值（原本的值記在 dumpling:source-root-name／-version），
    purl 改成 pkg:generic/<名稱>@<版本>?vcs_url=git+<repo>@<commit>（原本的 purl 記在 dumpling:source-root-purl）。
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
import urllib.parse

MAX_SBOM = 1 << 30
OK, FAIL, GAP, USAGE = 0, 1, 3, 64
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")

CLOSED = {"Rockchip DDR init": "Rockchip DDR 初始化（rkbin 成品，閉源）",
          "TF-A BL31 (Rockchip rkbin)": "TF-A BL31（Rockchip rkbin 成品，閉源）"}
UBOOT = ("U-Boot", "U-Boot SPL")
# 廠商分支的版本字串：<分支>-<YYYY.MM>-<修訂>-<commit>[-g<另一個 commit>]，或直接 <YYYY.MM>[...]
UBOOT_VER_RE = re.compile(r"^(?:(?P<branch>[A-Za-z0-9]+)-)?(?P<ym>20[0-9]{2}\.[0-9]{2})(?:-(?P<rev>[0-9]+))?(?:-(?P<commit>[0-9a-f]{7,40}))?")
UBOOT_NOTE = "上游 CVE 比對結果是候選：這是廠商分支，廠商可能已回移修補；比對到的 CVE 一律進待人審（D-034）"
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
            elif comp in UBOOT:
                m = UBOOT_VER_RE.match(ver or "")
                if m:
                    s["cpe"] = "cpe:2.3:a:denx:u-boot:%s:*:*:*:*:*:*:*" % m.group("ym")
                    prop(s, "dumpling:upstream-version", m.group("ym"))
                    if m.group("branch"):
                        prop(s, "dumpling:vendor-branch", m.group("branch"))
                    if m.group("commit"):
                        prop(s, "dumpling:vendor-commit", m.group("commit"))
                    prop(s, "dumpling:advisory-check", "ATTENTION")
                    prop(s, "dumpling:advisory-note", UBOOT_NOTE)
                else:
                    prop(s, "dumpling:advisory-check", "GAP")
                    gaps.append("%s 的版本 %s 讀不出上游版本，沒有給 CPE" % (comp, ver))
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

# 原始碼 SBOM（cdxgen）的檔案路徑是掃描當下的絕對路徑：sca-scan 把原始碼複製到 <WORK>/cdxgen-src 再交給 cdxgen，
# WORK＝mktemp -d "<--out 的上一層>/.sca-scan-work.XXXXXX"（在 /tmp、/run 底下時改用 $HOME/.cache/sca-scan/work.XXXXXX），
# 掃完 sca-scan 就把 WORK 刪掉，所以 WORK 只能由「實際的上一層資料夾（--work-parent）＋mktemp 的樣式」比對出來，不只比對字串片段。
# 同一個 WORK 可能以 abspath 與 realpath 兩種寫法出現（上一層是符號連結）：後綴相同就是同一個；後綴不同的兩個 WORK → FAIL（不猜）。
# 併入時，原始碼元件的每一個字串（包括 bom-ref、purl；依賴的 ref 用同一份對照表改，不會對不起來）：
#   1. <WORK>/cdxgen-src 底下 → 相對路徑（根目錄本身是 .）；file://<根目錄>/… 連 file:// 一起拿掉；<WORK> 底下的其他位置 → 相對於 <WORK>。
#      百分比編碼（purl 的 qualifier）與 \/ 跳脫的寫法也一樣處理。
#   2. 整個值就是一個絕對路徑（沒有空白）→ 只留檔名並計數；自由文字裡其他的斜線一律不碰（例如「/login」「10 /s」）。
#   3. 最後保險：改寫完，整份 SBOM 任何字串（含 purl、bom-ref；\/ 跳脫與百分比編碼都算）還出現 WORK 的任何寫法 → FAIL。
# Windows 路徑（C:\…）不處理：sca-scan 只在 Linux 上跑。
WHOLE_ABS_RE = re.compile(r"/[^\s]*[^\s/]")


def _strings(o):
    if isinstance(o, dict):
        for v in o.values():
            yield from _strings(v)
    elif isinstance(o, list):
        for v in o:
            yield from _strings(v)
    elif isinstance(o, str):
        yield o


def _variants(sv):
    r"""一個字串的幾種寫法：原樣、\/ 還原、百分比解碼（沒有 \/ 或 % 時只有原樣，省時間）。"""
    out = {sv}
    if "\\/" in sv:
        out.add(sv.replace("\\/", "/"))
    if "%" in sv:
        out |= {urllib.parse.unquote(x) for x in list(out)}
    return out


def _work_bases(work_parent):
    """→ {(上一層的寫法, WORK 名稱的正規式)}：--work-parent 的 abspath／realpath，以及 $HOME/.cache/sca-scan。"""
    bases = set()
    for x in (os.path.abspath(work_parent), os.path.realpath(work_parent)):
        bases.add((x.rstrip("/"), r"\.sca-scan-work\.[A-Za-z0-9]{6}"))
    home = os.environ.get("HOME")
    if home:
        for h in (os.path.abspath(home), os.path.realpath(home)):
            bases.add((os.path.join(h, ".cache", "sca-scan"), r"work\.[A-Za-z0-9]{6}"))
    return bases


def find_work(src, work_parent):
    """原始碼 SBOM 裡實際出現的 WORK → 它所有的寫法（長的在前）；沒有 → []。後綴不同的 WORK 兩個以上 → AugError。"""
    bases = _work_bases(work_parent)
    pats = [(base, name, re.compile(re.escape(base) + "/(" + name + ")(?=/|$)")) for base, name in bases]
    found = {}
    for sv in _strings(src):
        if "work" not in sv:
            continue
        for v in _variants(sv):
            for base, _, pat in pats:
                for m in pat.finditer(v):
                    found.setdefault(m.group(1), set()).add(base + "/" + m.group(1))
    if len(found) > 1:
        raise AugError("原始碼 SBOM 裡出現 %d 個不同的掃描暫存資料夾，不能判斷相對路徑" % len(found))
    if not found:
        return []
    suf, forms = next(iter(found.items()))
    forms |= {base + "/" + suf for base, name, _ in pats if re.fullmatch(name, suf)}    # 同一個後綴：每一種上一層的寫法都算
    return sorted(forms, key=len, reverse=True)


def _replacements(works):
    """→ (正規式, {要找的字串: 換成})，長的在前；含百分比編碼的寫法。沒有 WORK → None。"""
    pairs = []
    for w in works:
        root = w + "/cdxgen-src"
        for x, y in (("file://" + root + "/", ""), (root + "/", ""), ("file://" + root, "."), (root, "."),
                     ("file://" + w + "/", ""), (w + "/", ""), ("file://" + w, "."), (w, ".")):
            pairs.append((x, y))
            for q in (urllib.parse.quote(x, safe=""), urllib.parse.quote(x, safe="/")):
                if q != x:
                    pairs.append((q, y))
    if not pairs:
        return None
    table = {}
    for x, y in sorted(pairs, key=lambda t: len(t[0]), reverse=True):
        table.setdefault(x, y)
    return re.compile("|".join(re.escape(x) for x in table)), table


def fix_path_string(sv, reps, counts):
    """一個字串：WORK 的前綴拿掉（counts["relative"]）；整個值是絕對路徑時只留檔名（counts["basename"]）；其他文字不動。"""
    if reps:
        pat, table = reps
        if "\\/" in sv and pat.search(sv.replace("\\/", "/")):
            sv = sv.replace("\\/", "/")
        def sub(m):
            counts["relative"] += 1
            return table[m.group(0)]
        sv = pat.sub(sub, sv)
    if WHOLE_ABS_RE.fullmatch(sv):
        counts["basename"] += 1
        sv = os.path.basename(sv) or "."
    return sv


def relativize(o, reps, counts, skip=()):
    """o 裡每個字串交給 fix_path_string。原地改；skip 是 o（dict）最上層不處理的鍵。"""
    if isinstance(o, dict):
        for k, v in list(o.items()):
            if k in skip:
                continue
            if isinstance(v, str):
                o[k] = fix_path_string(v, reps, counts)
            else:
                relativize(v, reps, counts)
    elif isinstance(o, list):
        for i, v in enumerate(o):
            if isinstance(v, str):
                o[i] = fix_path_string(v, reps, counts)
            else:
                relativize(v, reps, counts)


MAX_UNQUOTE = 8          # 最後保險反覆百分比解碼的上限（多層編碼）


def _work_patterns(work_parent):
    """→ (整份 SBOM 都要檢查的正規式, 只檢查 metadata.component 以外的正規式)。不靠 find_work 有沒有找到 WORK。
    --work-parent（abspath／realpath）底下的 .sca-scan-work.XXXXXX：整份 SBOM。
    $HOME/.cache/sca-scan/work.XXXXXX：精靈那次掃描（映像）的 WORK 也可能在這裡，而它寫進 metadata.component.name 的路徑
    要到之後 sbom-layers.py tag 才換掉（#200），所以這個樣式略過 metadata.component，其他地方照樣檢查。"""
    whole, rest = [], []
    for base, name in _work_bases(work_parent) if work_parent else set():
        (whole if name.startswith(r"\.sca") else rest).append(re.escape(base) + "/" + name)
    home = os.environ.get("HOME")
    if home and not work_parent:
        for h in (os.path.abspath(home), os.path.realpath(home)):
            rest.append(re.escape(os.path.join(h, ".cache", "sca-scan")) + r"/work\.[A-Za-z0-9]{6}")
    comp = lambda xs: re.compile("|".join(sorted(set(xs)))) if xs else None
    return comp(whole), comp(rest)


def _decoded_forms(text):
    """序列化後的文字 → 它的幾種寫法：\\/ 與 \\\\/ 還原，再反覆百分比解碼到不變為止（最多 MAX_UNQUOTE 次）。"""
    t = text.replace("\\\\/", "/").replace("\\/", "/")
    out = [text, t]
    for _ in range(MAX_UNQUOTE):
        u = urllib.parse.unquote(t)
        if u == t:
            break
        out.append(u)
        t = u
    return out


def assert_no_work(doc, work_parent):
    r"""最後保險：改寫完，序列化後的整份 SBOM（鍵與值、purl、bom-ref；\/ 跳脫、多層百分比編碼都算）還出現掃描暫存資料夾 → AugError。
    直接用已知的上一層資料夾加 mktemp 的樣式比對，不靠 find_work 有沒有找到（根目錄只出現在鍵名、或藏在兩層編碼裡時，find_work 找不到）。"""
    whole, rest = _work_patterns(work_parent)
    if whole is None and rest is None:
        return
    text = json.dumps(doc, ensure_ascii=False)
    if whole is not None and any(whole.search(t) for t in _decoded_forms(text)):
        raise AugError("改寫後 SBOM 仍有掃描暫存資料夾的路徑（沒想到的寫法；不輸出）")
    if rest is not None:
        md = doc.get("metadata")
        mc = md.get("component") if isinstance(md, dict) else None
        if mc is not None:
            md = dict(md)
            md.pop("component")
        other = dict(doc)
        if mc is not None:
            other["metadata"] = md
        if any(rest.search(t) for t in _decoded_forms(json.dumps(other, ensure_ascii=False))):
            raise AugError("改寫後 SBOM 仍有掃描暫存資料夾的路徑（沒想到的寫法；不輸出）")


def merge_source(doc, src, label, repo, commit, app_name=None, app_version=None, work_parent=None):
    counts = {"relative": 0, "basename": 0}
    works = find_work(src, work_parent) if work_parent else []
    reps = _replacements(works)
    for c in walk(doc.get("components")):
        prop(c, "dumpling:origin", "image")
    pre = "dumpling:src:%s:" % label
    mapping = {}
    assigned = set()

    def remap(c):
        c = copy.deepcopy(c)
        old = c.get("bom-ref")
        if old is not None:
            if not isinstance(old, str):
                raise AugError("原始碼 SBOM 的 bom-ref 不是字串")
            ref = pre + fix_path_string(old, reps, counts)        # 路徑改寫後的 bom-ref；依賴的 ref 用同一份對照表
            if ref in assigned and mapping.get(old) != ref:
                raise AugError("路徑改寫後 bom-ref 重複（%s）" % ref[:120])
            assigned.add(ref)
            mapping[old] = ref
            c["bom-ref"] = ref
        else:
            c["bom-ref"] = pre + "anon-%d" % len(mapping)
            mapping[c["bom-ref"]] = c["bom-ref"]
        c["properties"] = [p for p in c.get("properties") or [] if isinstance(p, dict) and not str(p.get("name", "")).startswith("dumpling:origin")]
        relativize(c, reps, counts, skip=("components", "bom-ref"))   # purl 也改；bom-ref 在上面改；子元件在下面 remap 時各自處理
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
        # 應用本身的名稱與版本由專案明確給（cdxgen 給的根元件名稱通常是 clone 下來的資料夾名）：
        # 這樣 project.yml 的 own_software 與支援期資料表才對得到；原本的值留在屬性裡
        if app_name:
            prop(a, "dumpling:source-root-name", a.get("name"))
            a["name"] = app_name
        if app_version:
            prop(a, "dumpling:source-root-version", a.get("version"))
            a["version"] = app_version
        # 名稱或版本改了，cdxgen 原本的 purl（例如 pkg:npm/openmediavault-workbench@0.0.0）就不再描述這個元件：
        # 原值留在屬性，purl 改成 pkg:generic/<名稱>@<版本>，vcs_url 指到固定的 commit（不給 CPE：版本格式對不對得上 NVD 沒有核對，不猜）
        if app_name or app_version:
            if a.get("purl"):
                prop(a, "dumpling:source-root-purl", a["purl"])
            a["purl"] = "pkg:generic/%s@%s?vcs_url=%s" % (
                urllib.parse.quote(a.get("name") or "", safe=""), urllib.parse.quote(a.get("version") or "", safe=""),
                urllib.parse.quote("git+%s@%s" % (repo, commit), safe=""))
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
    assert_no_work(doc, work_parent)
    meta_prop(doc, "dumpling:augment:source:%s" % label, "%s@%s：%d 個元件、%d 條依賴邊（丟掉 %d 條懸空的）"
              % (repo, commit, len(list(walk(merged))), kept, dropped))
    meta_prop(doc, "dumpling:augment:source:%s:paths" % label, "改成相對路徑 %d 個；不在原始碼根目錄底下的絕對路徑只留檔名 %d 個"
              % (counts["relative"], counts["basename"]))

    gaps = ([] if app_ref else ["原始碼 SBOM 沒有 metadata.component（應用本身），無法標 source-vs-package"])
    return len(list(walk(merged))), kept, dropped, gaps, counts


def main(argv=None):
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd")
    r = sub.add_parser("raw-sectors")
    r.add_argument("sbom"); r.add_argument("raw"); r.add_argument("out")
    m = sub.add_parser("merge-source")
    m.add_argument("sbom"); m.add_argument("src"); m.add_argument("out")
    m.add_argument("--label", required=True); m.add_argument("--repo", required=True); m.add_argument("--commit", required=True)
    m.add_argument("--app-name"); m.add_argument("--app-version")
    m.add_argument("--work-parent", help="sca-scan --out 的上一層資料夾（掃描時的實際路徑）：用來比對原始碼根目錄，路徑改成相對")
    try:
        a = ap.parse_args(argv)
    except SystemExit:
        print("sbom-augment: FAIL（參數錯誤）")
        return USAGE
    if a.cmd is None:
        print("sbom-augment: FAIL（要給子指令 raw-sectors 或 merge-source）")
        return USAGE
    if a.cmd == "merge-source":
        if (not LABEL_RE.match(a.label) or not a.repo.startswith("https://") or not SHA1_RE.match(a.commit)
                or (a.app_name and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,99}", a.app_name))
                or (a.app_version and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+~:-]{0,99}", a.app_version))):
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
            n, kept, dropped, gaps, counts = merge_source(doc, src, a.label, a.repo, a.commit, a.app_name, a.app_version, a.work_parent)
            msg = "併入 %s 的 %d 個元件、%d 條依賴邊（丟掉 %d 條懸空的）；路徑：相對 %d、只留檔名 %d" % (
                a.label, n, kept, dropped, counts["relative"], counts["basename"])
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
