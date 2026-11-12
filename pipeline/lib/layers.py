"""SBOM 元件分層：bsp／os／host-tool／unknown（規則見 docs/LAYERS.md；平台設定格式見 docs/PLATFORM-INTERFACE.md）。

- classify_component(元件, 平台設定, own_software) → (層, 依據)
- tag_sbom(sbom, 平台設定, own_software, os_responsibility, platform) → (標好層的 SBOM, 摘要)
    每個元件加 property `dumpling:layer`（bsp｜os｜host-tool｜unknown）與 `dumpling:layer-basis`；SBOM 的 metadata 加
    `dumpling:os-responsibility`、`dumpling:platform`。cra_report 讀這些 property 把漏洞列分層。
- split_sbom(標好層的 SBOM) → {層: 只含該層元件的 SBOM}；依賴關係只留兩端都在同一份的，其餘計數（不丟元件）。

判斷順序（第一個成立的就是答案，不看版本字尾，D-027）：
  1. 自有軟體：cra 設定 sbom.own_software 產生的元件（bom-ref 以 `sca-center:own:` 開頭）、或專案 project.yml 的 own_software
     清單對到（含 `/` 的項目比路徑，其餘比元件名稱；fnmatch）→ bsp
  2. CycloneDX 型別 operating-system → os；firmware → bsp
  3. 發行版套件（purl 類型 deb／rpm／apk／alpm）→ 只看套件名稱：平台 layers.bsp.packages → bsp，layers.host-tool.packages →
     host-tool，其餘 os
  4. 有路徑的元件（Syft 的 syft:location:N:path、CycloneDX evidence.occurrences、型別 file 的名稱…）→ 平台 layers.bsp.paths → bsp，
     layers.host-tool.paths → host-tool，layers.os.paths → os；路徑沒有任何規則對得到 → unknown（不套 default: os）
  5. 其他（沒有套件身分也沒有路徑，例如只有 purl 的 Go／Python 套件）→ unknown
子元件（components 裡的 components）跟著上一層的父元件，依據標 inherited。
unknown 不是 os：判斷不了的一律標 unknown 並計數；報告端把它當我們的待辦（最保守，不漏報）。

只用標準函式庫＋PyYAML（經 project_config）。輸入 SBOM 是不可信資料：只讀、不執行，路徑含 .. 或 NUL 的不採用。
"""
import copy
import fnmatch
import json
import lzma
import os
import re
import sys
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
import project_config as pc  # noqa: E402

SCHEMA = "dumpling-layers/1"
LAYER_PROP = "dumpling:layer"
BASIS_PROP = "dumpling:layer-basis"
RESP_PROP = "dumpling:os-responsibility"
PLATFORM_PROP = "dumpling:platform"
PART_PROP = "dumpling:layer-part"
REASON_PROP = "dumpling:unknown-reason"
# unknown 判斷不了的原因（D-030）：沒有路徑也不是發行版套件｜有路徑但沒有任何規則對到
UNKNOWN_REASONS = {"no-path": "沒有路徑也不是發行版套件", "path-no-rule": "路徑沒有對到任何規則", "inherited": "子元件，跟著父元件",
                   "file-unowned": "檔案紀錄：沒有擁有它的套件，路徑也沒有對到任何規則"}

LAYERS = ("bsp", "os", "host-tool", "unknown")
# 同一個東西對到多個層時的優先順序（最保守：在產品上的、我們負責的優先；host-tool 最後，只有完全沒有別的證據才算）
PRECEDENCE = ("bsp", "unknown", "os", "host-tool")
DISTRO_PURL_TYPES = ("deb", "rpm", "apk", "alpm")
OWN_REF_PREFIX = "sca-center:own:"
OWN_SOURCE_PREFIX = "own software"
PATH_PROP_RE = re.compile(r"^syft:location:\d+:path$")
PATH_PROPS = ("syft:metadata:path", "syft:metadata:virtualPath", "sca-center:own-software-path", "sca-center:flash-package-path")
MAX_SBOM_BYTES = 512 << 20


class LayerError(Exception):
    """輸入或設定錯誤；str(e) 是給人看的訊息（不回顯輸入檔的內容）。"""


# ---------------------------------------------------------------- 讀 SBOM

def load_sbom(path):
    """讀 CycloneDX JSON（.xz 也可以）。回傳 dict；格式不對丟 LayerError。"""
    try:
        if os.path.getsize(path) > MAX_SBOM_BYTES:
            raise LayerError("SBOM 檔案過大")
        opener = lzma.open if str(path).endswith(".xz") else open
        with opener(path, "rb") as fh:
            doc = json.loads(fh.read(MAX_SBOM_BYTES + 1).decode("utf-8"))
    except LayerError:
        raise
    except (OSError, ValueError, lzma.LZMAError) as e:
        raise LayerError("讀不到 SBOM（%s）" % type(e).__name__)
    if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX" or not isinstance(doc.get("components", []), list):
        raise LayerError("不是 CycloneDX JSON 的 SBOM")
    return doc


def _props(c):
    out = {}
    for p in c.get("properties") or []:
        if isinstance(p, dict) and isinstance(p.get("name"), str) and isinstance(p.get("value"), str):
            out.setdefault(p["name"], p["value"])
    return out


def purl_type_name(purl):
    """'pkg:deb/ubuntu/openssl@3.0?arch=arm64' → ('deb', 'openssl')；看不懂 → (None, None)。名稱做百分比解碼。"""
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return None, None
    body = purl[4:].split("#", 1)[0].split("?", 1)[0]
    typ, _, rest = body.partition("/")
    if not typ or not rest:
        return (typ or None), None
    name = rest.rsplit("/", 1)[-1].split("@", 1)[0]
    return typ.lower(), (urllib.parse.unquote(name) or None)


def purl_key(purl):
    """比對用：不含 qualifiers（?arch=…）與 subpath 的 purl。"""
    return purl.split("#", 1)[0].split("?", 1)[0] if isinstance(purl, str) else ""


def _clean_path(p):
    """路徑 → 相對路徑（去開頭的 / 與 ./）；含 .. 或 NUL 或空 → None。"""
    if not isinstance(p, str) or "\x00" in p:
        return None
    p = p.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    p = p.lstrip("/")
    if not p or ".." in p.split("/"):
        return None
    return p


def component_paths(c):
    """元件在映像或 BSP 裡的路徑（相對路徑、去重、保持順序）。"""
    raw = []
    for p in c.get("properties") or []:
        if isinstance(p, dict) and isinstance(p.get("name"), str) and (PATH_PROP_RE.match(p["name"]) or p["name"] in PATH_PROPS):
            raw.append(p.get("value"))
    ev = c.get("evidence")
    if isinstance(ev, dict):
        for o in ev.get("occurrences") or []:
            if isinstance(o, dict):
                raw.append(o.get("location"))
    if c.get("type") == "file":
        raw.append(c.get("name"))
    out = []
    for p in raw:
        q = _clean_path(p)
        if q and q not in out:
            out.append(q)
    return out


# ---------------------------------------------------------------- 分類

def _match_any(value, patterns):
    return any(fnmatch.fnmatchcase(value, p) for p in patterns or [])


def own_patterns(project):
    """project.yml 的 own_software（字串清單）→ (名稱樣式, 路徑樣式, 略過的項目數)。
    含 `/` 的項目是路徑樣式；其餘要像套件名稱（小寫英數與 + . - _ 和 * ? []），否則略過（自由文字描述對不到元件，回報略過數）。"""
    names, paths, skipped = [], [], 0
    for e in (project or {}).get("own_software") or []:
        if not isinstance(e, str) or not e.strip() or e == pc.PLACEHOLDER:
            skipped += 1
            continue
        e = e.strip()
        if "/" in e:
            q = _clean_path(e)
            if q:
                paths.append(q)
            else:
                skipped += 1
        elif pc.PKG_PATTERN_RE.match(e):
            names.append(e)
        else:
            skipped += 1
    return names, paths, skipped


def path_layer(path, config):
    """一個相對路徑 → bsp｜host-tool｜os｜None。os 只在平台明確列了（layers.os.paths）時才是 os；沒有規則對到是 None。"""
    r = pc.classify_path(path, config)
    if r != "os":
        return r
    if _match_any(path, ((config.get("layers") or {}).get("os") or {}).get("paths")):
        return "os"
    return None


def pick(layers):
    """多個層 → 一個（PRECEDENCE 優先）。"""
    for l in PRECEDENCE:
        if l in layers:
            return l
    return "unknown"


def normalize_owner_path(p):
    """dpkg .list 的路徑 → 相對路徑，usrmerge（/bin、/sbin、/lib、/lib64 → /usr/…）；不合法回傳 None。"""
    q = _clean_path(p)
    if q and q.split("/", 1)[0] in ("bin", "sbin", "lib", "lib32", "lib64", "libx32"):
        q = "usr/" + q
    return q


def classify_component(c, config, own=((), (), 0), owners=None):
    """→ (層, 依據)。依據：own-software｜own-software-list｜component-type｜package-name｜file-owner｜path｜unresolved。
    owners：{相對路徑: 擁有它的套件名稱}（dpkg 的 .list）；型別 file 的元件（Syft 的檔案紀錄，沒有 purl）用它找擁有的套件，
    再用 classify_package 決定層（擁有者與路徑規則都有結果時取最保守的）。"""
    props = _props(c)
    ref = c.get("bom-ref") if isinstance(c.get("bom-ref"), str) else ""
    if ref.startswith(OWN_REF_PREFIX) or props.get("sca-center:source", "").startswith(OWN_SOURCE_PREFIX):
        return "bsp", "own-software"
    paths = component_paths(c)
    own_names, own_paths, _ = own
    name = c.get("name") if isinstance(c.get("name"), str) else ""
    if (name and _match_any(name, own_names)) or any(_match_any(p, own_paths) for p in paths):
        return "bsp", "own-software-list"
    typ = c.get("type")
    if typ == "operating-system":
        return "os", "component-type"
    if typ == "firmware":
        return "bsp", "component-type"
    ptype, pname = purl_type_name(c.get("purl"))
    if ptype in DISTRO_PURL_TYPES and pname:
        return pc.classify_package(pname, config), "package-name"
    if typ == "file" and owners and paths:
        pk = {owners[p] for p in paths if p in owners}
        if pk:
            found = {pc.classify_package(n, config) for n in pk} | {l for l in (path_layer(p, config) for p in paths) if l}
            return pick(found), "file-owner"
    if paths:
        found = {path_layer(p, config) or "unknown" for p in paths}
        return pick(found), ("path" if found != {"unknown"} else "unresolved")
    return "unknown", "unresolved"


def iter_components(comps):
    """所有元件（含子元件），先父後子。"""
    for c in comps or []:
        if isinstance(c, dict):
            yield c
            yield from iter_components(c.get("components"))


def _set_props(c, **kv):
    props = [p for p in (c.get("properties") or []) if not (isinstance(p, dict) and p.get("name") in kv)]
    props += [{"name": k, "value": v} for k, v in kv.items()]
    c["properties"] = props


def unknown_reason(c):
    """unknown 元件為什麼判斷不了：檔案紀錄（type=file）→ file-unowned；有路徑但沒有規則對到 → path-no-rule；沒有路徑（也不是發行版套件）→ no-path。"""
    if c.get("type") == "file":
        return "file-unowned"
    return "path-no-rule" if component_paths(c) else "no-path"


def _tag_tree(c, layer, basis, config, own, counts, owners=None):
    if layer == "unknown" and basis != "inherited":
        _set_props(c, **{LAYER_PROP: layer, BASIS_PROP: basis, REASON_PROP: unknown_reason(c)})
    else:
        _set_props(c, **{LAYER_PROP: layer, BASIS_PROP: basis})
    counts["layers"][layer] += 1
    counts["basis"][basis] = counts["basis"].get(basis, 0) + 1
    if layer == "unknown":
        t, _ = purl_type_name(c.get("purl"))
        k = t or ("(no purl)" if not c.get("purl") else "(other)")
        counts["unknown_by_purl_type"][k] = counts["unknown_by_purl_type"].get(k, 0) + 1
        r = unknown_reason(c) if basis != "inherited" else "inherited"
        counts["unknown_by_reason"][r] = counts["unknown_by_reason"].get(r, 0) + 1
    for ch in c.get("components") or []:
        if isinstance(ch, dict):
            _tag_tree(ch, layer, "inherited", config, own, counts, owners)


def new_counts():
    return {"layers": dict.fromkeys(LAYERS, 0), "basis": {}, "unknown_by_purl_type": {}, "unknown_by_reason": {}}


def tag_sbom(bom, config, own=((), (), 0), os_responsibility=None, platform=None, owners=None):
    """標每個元件的層。回傳 (新的 SBOM, 摘要)；不改傳入的 bom。owners：見 classify_component。"""
    if os_responsibility is not None and os_responsibility not in pc.OS_RESPONSIBILITIES:
        raise LayerError("os_responsibility 必須是 %s" % "／".join(pc.OS_RESPONSIBILITIES))
    b = copy.deepcopy(bom)
    counts = new_counts()
    for c in b.get("components") or []:
        if not isinstance(c, dict):
            continue
        layer, basis = classify_component(c, config, own, owners)
        _tag_tree(c, layer, basis, config, own, counts, owners)
    m = b.setdefault("metadata", {})
    if not isinstance(m, dict):
        raise LayerError("metadata 格式不對")
    kv = {}
    if os_responsibility:
        kv[RESP_PROP] = os_responsibility
    if platform:
        kv[PLATFORM_PROP] = platform
    if kv:
        _set_props(m, **kv)
    own_names, own_paths, skipped = own
    hit = sum(1 for c in iter_components(b.get("components")) if _props(c).get(BASIS_PROP) in ("own-software", "own-software-list"))
    summary = {"total": sum(counts["layers"].values()), "layers": counts["layers"], "basis": dict(sorted(counts["basis"].items())),
               "unknown_by_purl_type": dict(sorted(counts["unknown_by_purl_type"].items())),
               "unknown_by_reason": dict(sorted(counts["unknown_by_reason"].items())),
               "own_software": {"patterns": len(own_names) + len(own_paths), "ignored_entries": skipped, "matched_components": hit}}
    return b, summary


def component_layer(c):
    """標好層的元件 → 層；沒標、值不認得 → unknown（不丟）。"""
    v = _props(c).get(LAYER_PROP) if isinstance(c, dict) else None
    return v if v in LAYERS else "unknown"


def sbom_os_responsibility(bom):
    """標好層的 SBOM 的 metadata → os_responsibility（沒有或不合法 → None）。"""
    v = _props((bom or {}).get("metadata") or {}).get(RESP_PROP)
    return v if v in pc.OS_RESPONSIBILITIES else None


def has_layers(bom):
    """SBOM 有沒有任何標好層的元件。"""
    return any(LAYER_PROP in _props(c) for c in iter_components((bom or {}).get("components")))


def layer_counts(bom):
    """標好層的 SBOM → {層: 元件數}（含子元件；子元件算它自己標的層）。"""
    n = dict.fromkeys(LAYERS, 0)
    for c in iter_components((bom or {}).get("components")):
        n[component_layer(c)] += 1
    return n


# ---------------------------------------------------------------- 拆分

def _refs(comps):
    return {c["bom-ref"] for c in iter_components(comps) if isinstance(c.get("bom-ref"), str)}


def _edges(deps):
    return sum(len(d.get("dependsOn") or []) for d in deps or [] if isinstance(d, dict))


def _prune(part):
    """依賴關係只留兩端都在這一份裡的（compositions 同理）；回傳留下的邊數。"""
    here = _refs(part.get("components"))
    root = ((part.get("metadata") or {}).get("component") or {}).get("bom-ref")
    if isinstance(root, str):
        here.add(root)
    deps = []
    for d in part.get("dependencies") or []:
        if not isinstance(d, dict) or d.get("ref") not in here:
            continue
        nd = dict(d)
        if "dependsOn" in nd:
            nd["dependsOn"] = [x for x in nd["dependsOn"] or [] if x in here]
        deps.append(nd)
    if "dependencies" in part:
        part["dependencies"] = deps
    comps = []
    for cp in part.get("compositions") or []:
        if not isinstance(cp, dict):
            continue
        cp = dict(cp)
        for k in ("assemblies", "dependencies"):
            if isinstance(cp.get(k), list):
                cp[k] = [x for x in cp[k] if x in here]
        if cp.get("assemblies") or cp.get("dependencies"):
            comps.append(cp)
    if "compositions" in part:
        part["compositions"] = comps
    return _edges(deps)


def split_sbom(tagged, groups=None):
    """標好層的 SBOM → ({組: SBOM}, 丟掉的跨組依賴邊數)。groups：{層: 組名}，預設每層一組；對應到 None 的層不輸出（例如 host-tool）。
    每個頂層元件（連同它的子元件）只出現在一組；沒有元件的組不產生。沒標層的元件算 unknown，不會被丟掉。
    依賴邊只留兩端都在同一組裡的，其餘算進回傳的丟棄數（不是漏元件）。"""
    groups = groups or {l: l for l in LAYERS}
    buckets = {}
    for c in tagged.get("components") or []:
        g = groups.get(component_layer(c))
        if g is not None:
            buckets.setdefault(g, []).append(c)
    out, kept = {}, 0
    for g, comps in buckets.items():
        part = copy.deepcopy({k: v for k, v in tagged.items() if k != "components"})
        part["components"] = copy.deepcopy(comps)
        meta = part.setdefault("metadata", {})
        if isinstance(meta, dict):
            _set_props(meta, **{PART_PROP: g})
        kept += _prune(part)
        out[g] = part
    return out, max(0, _edges(tagged.get("dependencies")) - kept)


def dumps(doc):
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":")) + "\n"
