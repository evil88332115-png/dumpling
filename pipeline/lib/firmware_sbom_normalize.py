"""供應商 SBOM 上傳 DT 前的最小格式正規化（只改上傳用的副本；輸入一律當不可信資料）。

背景：Dependency-Track 上傳時會做 CycloneDX schema 驗證，不符就整份拒收（http=400）。供應商（例如 3mdeb 的 Dasharo SBOM）
的檔案有兩種已知的 schema 違規。本模組只處理這兩種，其他一律不碰（照原樣上傳，DT 拒收就照實報 FAIL）：

  1. 頂層出現該 specVersion 的 schema 沒有的欄位（CycloneDX 1.4 以後根物件 additionalProperties: false）
     → 移到 metadata.properties，名稱 `dumpling:supplier-extra:<原欄位名>`，值＝字串原值，或其他型別的 JSON 字串。
  2. components[].licenses[] 的項目是 {"license": {…}}，但 license 物件沒有 id 也沒有 name（schema 要求二選一）
     → 從 licenses 移除這一筆，在該元件的 properties 加 `dumpling:supplier-license-url`（url）；
        若這一筆還有其他欄位（text 等）或 url 不是字串，整個 license 物件以 JSON 字串存進 `dumpling:supplier-license-entry`。
        不把 url 填成 name、不猜授權。

  3. 供應商自帶、名稱以 `dumpling:` 開頭的 property（`metadata.properties` 與 components[] 含巢狀的 properties）
     → 就地改名成 `supplier:` + 原名（例如 `supplier:dumpling:normalized-changes`），值與位置不變。
     理由：`dumpling:` 是我們自己的命名空間（`dumpling:normalized-*`、`dumpling:supplier-*` 是這個模組寫的紀錄，`dumpling:vuln-assessment`、
     `dumpling:version-status`、`dumpling:advisory-match` 是 report 讀的標記）。供應商如果原本就有同名 property，會和我們加的混在一起，
     被誤當成我們的紀錄或評估結果；改名後副本裡所有 `dumpling:` 開頭的 property 都是我們寫的。改名不是違規修正，是命名空間隔離，所以不管 schema 驗不驗得過都做。
     只處理這兩處：report 只讀元件的 properties，我們只寫 `metadata.properties` 與元件的 properties；
     頂層 properties（1.5 起）、services、metadata.component（prep 已整個換成我們的根元件）、元件的 pedigree／evidence 底下的元件不動
     （沒有任何 dumpling 工具讀或寫那些位置；DT 5.2.0 也不用它們）。specVersion 不在支援範圍時整份不處理（見下），所以不改名。

原則：不刪資料（搬到 property）、不補猜的值、每一筆留紀錄、只處理已知的違規類型、不認得的違規不動。
紀錄（normalize 回傳值，寫成 normalize.json）：每筆有原 JSON Pointer、新位置、原值的 SHA-256
（原值的標準 JSON：sort_keys、分隔符 `,` `:`、ensure_ascii=False、UTF-8）。副本的 metadata.properties 另加
`dumpling:normalized-from-sha256`（原檔位元組的 SHA-256）與 `dumpling:normalized-changes`（筆數，含改名）。
沒有任何變更時不加這兩個 property、文件完全不動。

支援的 specVersion：1.4、1.5、1.6（頂層欄位表取自 CycloneDX/specification 對應 tag 的 bom-<版本>.schema.json 的 properties）。
1.2、1.3 的根物件允許額外欄位、1.7 以後沒有查證，一律不處理。

上限（超過就不搬，記成「無法正規化」；欄位照原樣留著，DT 拒收就照實 FAIL）：
  單一值 MAX_VALUE_BYTES、搬移的值合計 MAX_TOTAL_BYTES、變更筆數 MAX_CHANGES、元件巢狀 MAX_NEST 層、欄位名稱 MAX_NAME_LEN。
"""
import hashlib
import json

SCHEMA_ID = "firmware-sbom-normalize/1"
MAX_VALUE_BYTES = 8 * 1024
MAX_TOTAL_BYTES = 256 * 1024
MAX_CHANGES = 2000
MAX_UNNORMALIZED = 200
MAX_NEST = 100
MAX_NAME_LEN = 100

PROP_EXTRA = "dumpling:supplier-extra:"
PROP_LICENSE_URL = "dumpling:supplier-license-url"
PROP_LICENSE_ENTRY = "dumpling:supplier-license-entry"
PROP_FROM_SHA = "dumpling:normalized-from-sha256"
PROP_CHANGES = "dumpling:normalized-changes"
RESERVED_PREFIX = "dumpling:"            # 我們自己的 property 命名空間；供應商自帶的同開頭 property 一律改名
SUPPLIER_PREFIX = "supplier:"
RULE_RESERVED = "supplier-dumpling-property"
MAX_NAME_RECORD = 200                    # 紀錄裡的原名最多留這麼多字元（完整原值以 value_sha256 為準）

_COMMON = {"bomFormat", "components", "compositions", "dependencies", "externalReferences", "metadata",
           "serialNumber", "services", "specVersion", "version"}
# 取自各版本 bom-<v>.schema.json 的 properties（CycloneDX/specification tag 1.4、1.5、1.6）
TOP_KEYS = {
    "1.4": frozenset(_COMMON | {"$schema", "signature", "vulnerabilities"}),
    "1.5": frozenset(_COMMON | {"$schema", "signature", "vulnerabilities", "annotations", "formulation", "properties"}),
    "1.6": frozenset(_COMMON | {"$schema", "signature", "vulnerabilities", "annotations", "formulation", "properties",
                                "declarations", "definitions"}),
}


def pointer(*parts):
    """RFC 6901 JSON Pointer。"""
    return "".join("/" + str(p).replace("~", "~0").replace("/", "~1") for p in parts)


def key_state(d, key):
    """鍵在原檔裡的狀態：absent（沒有這個鍵）｜null｜array｜object｜其他型別名稱。副本一律寫成陣列，所以要記原本是哪一種。"""
    if not isinstance(d, dict) or key not in d:
        return "absent"
    v = d[key]
    return "null" if v is None else "array" if isinstance(v, list) else "object" if isinstance(v, dict) else type(v).__name__


def canonical_sha256(value):
    """原值的標準 JSON 的 SHA-256；無法序列化（例如遞迴太深）回 None。"""
    try:
        s = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(s.encode("utf-8", "surrogatepass")).hexdigest()
    except (TypeError, ValueError, RecursionError):
        return None


def _dump_limited(value, limit):
    """value → property 值字串（字串用原值，其他用標準 JSON）；超過 limit 位元組、含不能編碼的字元、無法序列化則回 None。"""
    try:
        if isinstance(value, str):
            s = value
            if len(s) > limit:
                return None
        else:
            parts, n = [], 0
            for chunk in json.JSONEncoder(sort_keys=True, separators=(",", ":"), ensure_ascii=False).iterencode(value):
                n += len(chunk)
                if n > limit:
                    return None
                parts.append(chunk)
            s = "".join(parts)
        s.encode("utf-8")        # 單獨代理字元（\ud800）寫不進 UTF-8 檔案
        return s if len(s.encode("utf-8")) <= limit else None
    except (TypeError, ValueError, RecursionError, UnicodeEncodeError, OverflowError):
        return None


def _name_ok(k):
    if not isinstance(k, str) or not k or len(k) > MAX_NAME_LEN:
        return False
    try:
        k.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return not any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in k)


def _license_candidate(entry):
    """licenses[] 的一項是否為已知違規：恰好只有 `license` 一個鍵、license 是物件、沒有 id 也沒有 name 這兩個鍵。"""
    return (isinstance(entry, dict) and set(entry) == {"license"} and isinstance(entry["license"], dict)
            and "id" not in entry["license"] and "name" not in entry["license"])


def reserved_indices(props):
    """properties 陣列裡名稱以 `dumpling:` 開頭的項目索引（項目是物件、name 是字串；區分大小寫，我們的流程也是完全相等才讀）。"""
    if not isinstance(props, list):
        return []
    return [i for i, p in enumerate(props) if isinstance(p, dict) and isinstance(p.get("name"), str) and p["name"].startswith(RESERVED_PREFIX)]


def _iter_components(doc, unnorm):
    """依文件順序走訪 components（含巢狀；不遞迴），產生 (指標前綴, 元件 dict)。"""
    stack = [("/components", doc.get("components"), 1)]
    seen_deep = False
    while stack:
        prefix, lst, depth = stack.pop()
        if not isinstance(lst, list):
            continue
        if depth > MAX_NEST:
            if not seen_deep:
                seen_deep = True
                unnorm.append({"rule": "nesting-too-deep", "at": prefix, "reason": "元件巢狀超過 %d 層，以下不處理" % MAX_NEST})
            continue
        for i, c in enumerate(lst):
            if isinstance(c, dict):
                yield "%s/%d" % (prefix, i), c
        for i in range(len(lst) - 1, -1, -1):       # 反向推入，彈出時維持文件順序
            c = lst[i]
            if isinstance(c, dict) and isinstance(c.get("components"), list):
                stack.append(("%s/%d/components" % (prefix, i), c["components"], depth + 1))


def normalize(doc, input_sha256):
    """就地正規化 doc（CycloneDX JSON 的 dict），回傳紀錄 dict。先完整規劃、通過才套用；規劃中出任何例外都不改 doc。

    紀錄：{schema, input_sha256, spec_version, applied, supported, changes: [...], unnormalized: [...], unnormalized_total, reserved_not_renamed, notes: [...]}。
    unnormalized_total＝無法正規化的真正筆數（unnormalized 清單最多留 MAX_UNNORMALIZED 筆，之後只有一筆「more」）；
    reserved_not_renamed＝供應商自帶的 dumpling: property 因為上限或無法序列化而沒有改名的個數（副本仍帶著它們）。
    changes[]（property、original_name 最多留 MAX_NAME_RECORD 字元，完整原值以 value_sha256 為準）: {rule, from, to[], property[], value_sha256}（每個搬移的項目一筆；to／property 是陣列，license 項目可能同時寫 url 與整個物件；
    license 項目另有 component_properties_before：元件的 properties 鍵原本是 absent／null／array，副本一律是陣列）；unnormalized[]: {rule, at, reason}（已知違規但無法搬移，欄位原樣保留）。
    """
    rec = {"schema": SCHEMA_ID, "input_sha256": input_sha256, "spec_version": None, "supported": False, "applied": False,
           "changes": [], "unnormalized": [], "unnormalized_total": 0, "reserved_not_renamed": 0, "notes": []}
    if not isinstance(doc, dict):
        rec["notes"].append("根物件不是 JSON 物件，不處理")
        return rec
    spec = doc.get("specVersion")
    rec["spec_version"] = spec if isinstance(spec, str) and len(spec) <= 20 else None
    if rec["spec_version"] not in TOP_KEYS:
        rec["notes"].append("specVersion 不在支援範圍（%s），不處理" % ", ".join(sorted(TOP_KEYS)))
        return rec
    rec["supported"] = True
    meta = doc.get("metadata")
    if meta is None:
        meta = {}
    if not isinstance(meta, dict) or not (meta.get("properties") is None or isinstance(meta.get("properties"), list)):
        rec["notes"].append("metadata 或 metadata.properties 型別不對，沒有地方放紀錄，整份不處理")
        return rec
    try:
        plan = _plan(doc, meta, rec["spec_version"])
    except Exception as e:                           # 惡意輸入造成的任何意外：放棄正規化，文件不動
        rec["notes"].append("規劃時發生 %s，整份不處理" % type(e).__name__)
        return rec
    rec["changes"], rec["unnormalized"] = plan["changes"], plan["unnormalized"]
    rec["unnormalized_total"], rec["reserved_not_renamed"] = plan["unnormalized_total"], plan["reserved_not_renamed"]
    if not plan["changes"]:
        return rec
    _apply(doc, meta, plan, input_sha256)
    rec["applied"] = True
    return rec


def _plan(doc, meta, spec):
    changes, unnorm = [], []
    top_moves = []       # (key, 值字串)
    meta_ren = []        # metadata.properties 要改名的索引
    comp_ren = []        # (元件 dict, 元件指標, [索引…])
    lic_moves = []       # (元件 dict, 元件指標, 要移除的 licenses 索引集合, [(name, value)…])
    budget = [MAX_TOTAL_BYTES]
    count = [0]
    base = len(meta.get("properties") or [])

    def room(n_new=1):
        return count[0] + n_new <= MAX_CHANGES

    stat = {"unnorm": 0, "reserved_left": 0}      # 真正的筆數（unnorm 清單最多留 MAX_UNNORMALIZED 筆，不能拿清單長度當筆數）

    def skip(rule, at, reason):
        stat["unnorm"] += 1
        if rule == RULE_RESERVED:
            stat["reserved_left"] += 1
        if len(unnorm) < MAX_UNNORMALIZED:
            unnorm.append({"rule": rule, "at": at, "reason": reason})
        elif len(unnorm) == MAX_UNNORMALIZED:
            unnorm.append({"rule": "more", "at": "", "reason": "無法正規化的項目超過 %d，以下不列" % MAX_UNNORMALIZED})

    # 規則 1：頂層多出的欄位
    allowed = TOP_KEYS[spec]
    for k in list(doc):
        if k in allowed:
            continue
        at = pointer(k) if isinstance(k, str) and len(k) <= MAX_NAME_LEN else "(欄位名稱過長或不是字串)"
        if not _name_ok(k):
            skip("top-level-extra-field", at, "欄位名稱不合格（空、過長或含控制字元）")
            continue
        val = _dump_limited(doc[k], MAX_VALUE_BYTES)
        sha = canonical_sha256(doc[k])
        if val is None or sha is None:
            skip("top-level-extra-field", at, "值超過 %d 位元組上限或無法序列化" % MAX_VALUE_BYTES)
            continue
        if not room() or budget[0] < len(val.encode("utf-8")):
            skip("top-level-extra-field", at, "超過搬移總量上限（%d 位元組或 %d 筆）" % (MAX_TOTAL_BYTES, MAX_CHANGES))
            continue
        budget[0] -= len(val.encode("utf-8"))
        count[0] += 1
        top_moves.append((k, val))
        changes.append({"rule": "top-level-extra-field", "from": at,
                        "property": [PROP_EXTRA + k], "value_sha256": sha, "_idx": len(top_moves) - 1})

    # 規則 3 的 metadata.properties 部分（先於 license 規則計入筆數：命名空間隔離比搬 license 重要）
    def plan_rename(plist, ptr_prefix):
        idxs = []
        for i in reserved_indices(plist):
            at = "%s/%d" % (ptr_prefix, i)
            entry = plist[i]
            sha = canonical_sha256(entry)
            if sha is None:
                skip(RULE_RESERVED, at, "無法序列化")
                continue
            if not room():
                skip(RULE_RESERVED, at, "超過變更筆數上限（%d 筆）" % MAX_CHANGES)
                continue
            count[0] += 1
            idxs.append(i)
            changes.append({"rule": RULE_RESERVED, "from": at, "to": [at], "property": [(SUPPLIER_PREFIX + entry["name"])[:MAX_NAME_RECORD]],
                            "original_name": entry["name"][:MAX_NAME_RECORD], "value_sha256": sha})
        return idxs

    meta_ren.extend(plan_rename(meta.get("properties"), pointer("metadata", "properties")))

    # 規則 2：license 物件沒有 id 也沒有 name；規則 3 的元件 properties 部分在同一個走訪裡
    for cptr, comp in _iter_components(doc, unnorm):
        ren = plan_rename(comp.get("properties"), cptr + "/properties")
        if ren:
            comp_ren.append((comp, cptr, ren))
        lic = comp.get("licenses")
        if not isinstance(lic, list):
            continue
        cands = [i for i, e in enumerate(lic) if _license_candidate(e)]
        if not cands:
            continue
        props = comp.get("properties")
        if props is not None and not isinstance(props, list):
            for i in cands:
                skip("license-without-id-or-name", "%s/licenses/%d" % (cptr, i), "元件的 properties 不是陣列，沒有地方放")
            continue
        pstate = key_state(comp, "properties")       # 元件的 properties 原本有沒有這個鍵（副本會是陣列）
        remove, adds = set(), []
        for i in cands:
            at = "%s/licenses/%d" % (cptr, i)
            entry = lic[i]
            lobj = entry["license"]
            sha = canonical_sha256(entry)
            only_url = set(lobj) == {"url"} and isinstance(lobj.get("url"), str)
            if only_url:
                items = [(PROP_LICENSE_URL, lobj["url"])]
            else:
                items = [(PROP_LICENSE_ENTRY, lobj)]       # 其他欄位（text…）或 url 不是字串：整個 license 物件留在 property
                if isinstance(lobj.get("url"), str):
                    items.insert(0, (PROP_LICENSE_URL, lobj["url"]))
            vals = [(n, _dump_limited(v, MAX_VALUE_BYTES)) for n, v in items]
            if sha is None or any(v is None for _, v in vals):
                skip("license-without-id-or-name", at, "值超過 %d 位元組上限或無法序列化" % MAX_VALUE_BYTES)
                continue
            need = sum(len(v.encode("utf-8")) for _, v in vals)
            if not room() or budget[0] < need:
                skip("license-without-id-or-name", at, "超過搬移總量上限（%d 位元組或 %d 筆）" % (MAX_TOTAL_BYTES, MAX_CHANGES))
                continue
            budget[0] -= need
            count[0] += 1
            remove.add(i)
            adds.append((at, sha, vals, pstate))
        if remove:
            lic_moves.append((comp, cptr, remove, adds))
    # 計算「新位置」的索引並組紀錄（改名的紀錄 to 就是 from，不在這裡處理）
    for ch in changes:
        if "_idx" in ch:
            ch["to"] = [pointer("metadata", "properties", base + ch.pop("_idx"))]
    for comp, cptr, remove, adds in lic_moves:
        pos = len(comp.get("properties") or [])
        for at, sha, vals, pstate in adds:
            tos = []
            for n, _ in vals:
                tos.append("%s/properties/%d" % (cptr, pos))
                pos += 1
            changes.append({"rule": "license-without-id-or-name", "from": at, "to": tos,
                            "property": [n for n, _ in vals], "value_sha256": sha, "component_properties_before": pstate})
    deep = sum(1 for u in unnorm if u["rule"] == "nesting-too-deep")       # 這種直接由 _iter_components 加進清單，不經 skip
    return {"changes": changes, "unnormalized": unnorm, "unnormalized_total": stat["unnorm"] + deep, "reserved_not_renamed": stat["reserved_left"], "top_moves": top_moves, "lic_moves": lic_moves,
            "meta_ren": meta_ren, "comp_ren": comp_ren}


def _renamed(plist, idxs):
    """新的 properties 陣列：idxs 的項目改名（新的物件，不動原物件；值與其他鍵照舊）。"""
    out = list(plist)
    for i in idxs:
        out[i] = dict(out[i], name=SUPPLIER_PREFIX + out[i]["name"])
    return out


def _apply(doc, meta, plan, input_sha256):
    for comp, _, idxs in plan["comp_ren"]:
        comp["properties"] = _renamed(comp["properties"], idxs)
    props = _renamed(list(meta.get("properties") or []), plan["meta_ren"])
    for k, val in plan["top_moves"]:
        props.append({"name": PROP_EXTRA + k, "value": val})
        del doc[k]
    for comp, cptr, remove, adds in plan["lic_moves"]:
        cprops = list(comp.get("properties") or [])
        for _, _, vals, _ in adds:
            for n, v in vals:
                cprops.append({"name": n, "value": v})
        comp["properties"] = cprops
        comp["licenses"] = [e for i, e in enumerate(comp["licenses"]) if i not in remove]
    props.append({"name": PROP_FROM_SHA, "value": input_sha256})
    props.append({"name": PROP_CHANGES, "value": str(len(plan["changes"]))})
    meta["properties"] = props
    doc["metadata"] = meta
