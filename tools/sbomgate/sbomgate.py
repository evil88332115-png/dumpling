#!/usr/bin/env python3
"""sbomgate：SBOM 與 Grype 結果的閘門（CLAUDE.md 規則 11–13）。

讀 CycloneDX SBOM、Grype JSON、（選用）清單檔，分層回報：
  sbom 層：OK / EMPTY / INCOMPLETE
  元件層：RESOLVED / VERSION_FROM_RANGE（範圍）/ NO_VERSION / UNIDENTIFIABLE（沒有可讀的名稱）
  弱點分析層：COMPLETE / PARTIAL / NOT_ASSESSED / NOT_RUN
版本未知的元件所對應的 Grype 比對不會被刪除，而是移到 excluded_matches 並寫明原因。
本程式永遠不輸出「安全」或 PASS；COMPLETE 只表示在這份 SBOM 與這份資料庫範圍內比對完成。

退出碼：0 COMPLETE；1 PARTIAL；2 NOT_ASSESSED / NOT_RUN；3 輸入錯誤；4 內部錯誤（不是 PARTIAL）。
"""
import argparse, json, re, sys
from urllib.parse import unquote
from datetime import datetime, timezone

# 目前只觀察到並驗證過的「版本來自範圍」標記（cdxgen 12.8.7，Python requirements.txt）。
# 另外，版本字串本身長得像範圍（>=、~、^、*、x、逗號、空白、latest 等）也視為範圍。
RANGE_MARKERS = ("cdx:pypi:versionSpecifiers",)
RANGE_VERSION_RE = re.compile(r"[<>=^*|,\s]|^~|^@|^dev-|(^|\.)\+$|(^|\.)[xX](\.|-|$)")   # Debian 的 1.0~rc1 是合法版本，所以 ~ 只在開頭算範圍
UNKNOWN_VERSIONS = {"unknown", "latest", "n/a", "none", "null", "release", "main", "master", "trunk", "head", "any", "stable", "current", "newest"}
PACKAGE_TYPES = {"library", "framework"}      # 其他類型（application、operating-system、container、file…）不算套件
# cdxgen 把 .github/workflows 裡用到的 GitHub Actions 記成 type=application、purl 類型 github，並帶 cdx:github:workflow:file 等屬性。
# 它們是 CI 的依賴，不是應用程式的執行期依賴；這是「範圍」決定（GHSA 有 GitHub Actions 生態系，Grype 也能比對），
# 所以另外計數並明示「未評估」，不讓應用程式的弱點分析降為 PARTIAL。三個條件都要符合，缺任何一個照舊降級。
CI_ACTION_PURL_TYPES = {"github"}
CI_ACTION_PROPS = {"cdx:github:workflow:file", "cdx:github:action:uses"}


def is_ci_action(c):
    props = {as_str(as_dict(p).get("name")) for p in as_list(c.get("properties"))}
    return c.get("type") == "application" and purl_eco(c.get("purl")) in CI_ACTION_PURL_TYPES and bool(props & CI_ACTION_PROPS)
NAME_FOLD_ECOS = {"pypi", "npm"}
EXIT = {"COMPLETE": 0, "PARTIAL": 1, "NOT_ASSESSED": 2, "NOT_RUN": 2}
STATEMENT = "COMPLETE 只表示在這份 SBOM 與這份資料庫範圍內比對完成，不代表沒有弱點或安全。"


class InputError(Exception):
    pass


# ---------- 安全存取：任何型別不對的欄位都不會讓程式當機，而是視為缺值 ----------

def as_str(x):
    return x if isinstance(x, str) else ""


def as_version(x):
    if isinstance(x, str):
        return x
    if isinstance(x, (int, float)) and not isinstance(x, bool):
        return str(x)
    return ""


def as_dict(x):
    return x if isinstance(x, dict) else {}


def as_list(x):
    return x if isinstance(x, list) else []


def is_num(x):
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def load_json(path, what):
    try:
        with open(path, encoding="utf-8-sig") as f:
            data = json.load(f)
    except OSError as e:
        raise InputError(f"讀不到 {what}：{path}（{e.strerror}）")
    except UnicodeDecodeError:
        raise InputError(f"{what} 不是 UTF-8 文字：{path}")
    except RecursionError:
        raise InputError(f"{what} 巢狀層數過深：{path}")
    except ValueError:
        raise InputError(f"{what} 不是合法的 JSON：{path}")
    if not isinstance(data, dict):
        raise InputError(f"{what} 的最上層不是物件：{path}")
    return data


def purl_eco(purl):
    m = re.match(r"pkg:([A-Za-z0-9.+-]+)/", as_str(purl))
    return m.group(1).lower() if m else None


def purl_name(purl):
    """purl 的 namespace/name 部分（已解碼），沒有 purl 或格式不符回 None。"""
    m = re.match(r"pkg:[A-Za-z0-9.+-]+/([^@?#]+)", as_str(purl))
    return unquote(m.group(1)) if m else None


def norm_name(name, eco):
    n = as_str(name).strip()
    if eco == "pypi":
        return re.sub(r"[-_.]+", "-", n.lower())
    if eco in NAME_FOLD_ECOS:
        return n.lower()
    return n


def comp_fullname(c, eco):
    g, n = as_str(c.get("group")), as_str(c.get("name"))
    if not n:
        return ""
    if not g:
        return n
    return f"{g}:{n}" if eco == "maven" else f"{g}/{n}"


def props(c):
    out = {}
    for p in as_list(c.get("properties")):
        if isinstance(p, dict) and isinstance(p.get("name"), str):
            out.setdefault(p["name"], p.get("value"))
    return out


def has_instrumentation_proof(c):
    """同一筆 identity 證據內，instrumentation 方法的信心值 >= 1 才算實際解析（不跨筆混用）。"""
    ev = as_dict(c.get("evidence"))
    ident = ev.get("identity")
    entries = [ident] if isinstance(ident, dict) else as_list(ident)
    for e in entries:
        if not isinstance(e, dict):
            continue
        for m in as_list(e.get("methods")):
            if not isinstance(m, dict) or m.get("technique") != "instrumentation":
                continue
            conf = m["confidence"] if is_num(m.get("confidence")) else e.get("confidence")
            if is_num(conf) and conf >= 1:
                return True
    return False


def classify_component(c):
    if not as_str(c.get("name")).strip():
        return "UNIDENTIFIABLE", "元件沒有可讀的名稱"
    ver = as_version(c.get("version")).strip()
    if not ver or ver.lower() in UNKNOWN_VERSIONS:
        return "NO_VERSION", "元件沒有版本或版本為未知值"
    if RANGE_VERSION_RE.search(ver):
        return "VERSION_FROM_RANGE", f"版本字串 {ver!r} 看起來是範圍或萬用字元"
    p = props(c)
    marked = [m for m in RANGE_MARKERS if m in p]
    if marked and not has_instrumentation_proof(c):
        return "VERSION_FROM_RANGE", f"帶有 {marked[0]}={p[marked[0]]!r}，且沒有『實際解析』的證據（instrumentation 且信心值 1）"
    return "RESOLVED", ""


def flatten(components, limit=200000):
    """展開巢狀 components（迭代，不遞迴）；超過上限就拒絕，不能靜默截斷。"""
    out, stack = [], list(reversed(as_list(components)))
    while stack:
        if len(out) >= limit:
            raise InputError(f"元件數超過上限 {limit}，拒絕（避免靜默截斷）")
        c = stack.pop()
        if not isinstance(c, dict):
            continue
        out.append(c)
        stack.extend(reversed(as_list(c.get("components"))))
    return out


def is_package(c):
    t = c.get("type")
    if isinstance(t, str):
        return t in PACKAGE_TYPES
    return bool(as_str(c.get("purl")))       # 沒有 type 時，有 purl 才算套件


# ---------- 清單檔 ----------

SKIP_OPTIONS = ("--hash", "--index-url", "-i ", "--extra-index-url", "--find-links", "-f ", "--trusted-host",
                "--only-binary", "--no-binary", "--prefer-binary", "--pre", "--require-hashes", "--no-index",
                "-c ", "--constraint", "--use-feature", "--no-deps")


def parse_requirements(text):
    """回傳 (宣告的套件, 空集合, 無法解析的項目數)。選項與 --hash 續行不算套件也不算無法解析；
    -r、-e、網址、路徑算無法解析（可能藏有套件）。"""
    names, unparsed = set(), 0
    joined, buf = [], ""
    for raw in text.splitlines():           # 先把反斜線續行接起來
        s = raw.rstrip()
        if s.endswith("\\"):
            buf += s[:-1] + " "
            continue
        joined.append(buf + s)
        buf = ""
    if buf:
        joined.append(buf)
    for raw in joined:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        line = re.split(r"\s+#", line, maxsplit=1)[0].strip()
        # 一行內的 --hash=... 選項去掉後再看
        line = re.sub(r"\s+--hash[= ]\S+", "", line).strip()
        if line.startswith(SKIP_OPTIONS) or line in ("-i", "-f", "-c"):
            continue
        if line.startswith(("-", "http://", "https://", "git+", ".", "/", "file:")):
            unparsed += 1
            continue
        m = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)", line)
        if m:
            names.add(norm_name(m.group(1), "pypi"))
        else:
            unparsed += 1
    return names, set(), unparsed


def parse_package_json(text):
    try:
        d = json.loads(text)
    except (ValueError, RecursionError):
        raise InputError("package.json 不是合法的 JSON")
    if not isinstance(d, dict):
        raise InputError("package.json 最上層不是物件")
    req, dev, unparsed = set(), set(), 0
    for k in ("dependencies", "optionalDependencies"):
        v = d.get(k)
        if isinstance(v, dict):
            req |= {norm_name(n, "npm") for n in v}
        elif v is not None:
            unparsed += 1
    v = d.get("devDependencies")
    if isinstance(v, dict):
        dev = {norm_name(n, "npm") for n in v}
    elif v is not None:
        unparsed += 1
    return req, dev, unparsed


def read_manifest(path):
    try:
        with open(path, encoding="utf-8-sig") as f:
            text = f.read()
    except OSError as e:
        raise InputError(f"讀不到清單檔：{path}（{e.strerror}）")
    except UnicodeDecodeError:
        raise InputError(f"清單檔不是 UTF-8 文字：{path}")
    base = path.replace("\\", "/").rsplit("/", 1)[-1]
    if base == "package.json":
        return ("npm",) + parse_package_json(text)
    if base.endswith(".txt") and "requirements" in base:
        return ("pypi",) + parse_requirements(text)
    raise InputError(f"不支援的清單檔：{base}（目前支援 package.json、requirements*.txt）")


# ---------- Grype 資料庫 ----------

def parse_time(s):
    try:
        t = datetime.fromisoformat(as_str(s).replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def db_info(grype, now, max_age_days):
    d = as_dict(as_dict(grype.get("descriptor")).get("db"))
    st = as_dict(d.get("status"))
    built = st.get("built") or d.get("built")
    t = parse_time(built) if built else None
    if t is None:
        return {"status": "UNKNOWN", "built": built if isinstance(built, str) else None, "age_days": None}
    age = (now - t).total_seconds() / 86400
    if age < -1:     # 資料庫日期在未來：時鐘或資料有問題，不信任
        return {"status": "UNKNOWN", "built": built, "age_days": round(age, 2)}
    return {"status": "STALE" if age > max_age_days else "OK", "built": built, "age_days": round(age, 2)}


# ---------- 主邏輯 ----------

def key_of(eco, name, version):
    return (eco, norm_name(name, eco), version)


def run(sbom, grype=None, manifest=None, tree="unknown", now=None, max_db_age_days=7.0, self_purls=(), self_hints=()):
    now = now or datetime.now(timezone.utc)
    if grype is not None and not isinstance(grype.get("matches"), list):
        raise InputError("Grype 輸出沒有 matches 清單（格式錯誤或被截斷）；0 筆比對的合法輸出應該是 \"matches\": []")
    raw = flatten(sbom.get("components"))
    pkgs = [c for c in raw if is_package(c)]
    ignored_types, ignored_with_purl, ci_actions = {}, 0, []
    for c in raw:
        if not is_package(c):
            t = c.get("type") if isinstance(c.get("type"), str) else "(無 type 且無 purl)"
            ignored_types[t] = ignored_types.get(t, 0) + 1
            if as_str(c.get("purl")):
                if is_ci_action(c):
                    ci_actions.append(as_str(c.get("purl")))
                else:
                    ignored_with_purl += 1

    items = []
    for c in pkgs:
        eco = purl_eco(c.get("purl"))
        cls, why = classify_component(c)
        full = comp_fullname(c, eco)
        ident = purl_name(c.get("purl")) or full      # 有 purl 時以 purl 的名稱為準（Maven、npm scope 的寫法才一致）
        items.append({"name": full, "version": as_version(c.get("version")), "purl": as_str(c.get("purl")),
                      "class": cls, "why": why, "_eco": eco, "_ident": ident,
                      "_key": key_of(eco, ident, as_version(c.get("version")))})
    # 同生態系、同名且已有 RESOLVED 的元件 → 其他版本未知的同名宣告視為被取代
    resolved_names = {(i["_eco"], norm_name(i["_ident"], i["_eco"])) for i in items if i["class"] == "RESOLVED"}
    for i in items:
        if i["class"] != "RESOLVED":
            i["superseded_by_resolved"] = (i["_eco"], norm_name(i["_ident"], i["_eco"])) in resolved_names

    reasons = []
    sbom_layer = {"status": "OK", "components_total": len(pkgs), "non_package_entries_ignored": ignored_types,
                  "non_package_entries_with_purl": ignored_with_purl,
                  "ci_workflow_actions_not_assessed": sorted(set(ci_actions))}
    if ignored_with_purl:
        reasons.append(f"{ignored_with_purl} 個非套件型別（application、operating-system 等）但帶有 purl 的元件被忽略，可能是漏看的套件")
    # manifest：單一 (eco, req, dev, unparsed[, 路徑]) 或多個的清單（--manifest 可重複）；每個清單檔各自核對
    manifests = [] if not manifest else ([manifest] if isinstance(manifest, tuple) else list(manifest))
    for idx, mf in enumerate(manifests):
        eco, req, dev, unparsed = mf[:4]
        mpath = mf[4] if len(mf) > 4 else None
        where = f"（{mpath}）" if mpath and len(manifests) > 1 else ""
        have = {norm_name(i["_ident"], eco) for i in items if i["_eco"] == eco or i["_eco"] is None}
        missing = sorted(n for n in req if n not in have)
        entry = {"ecosystem": eco, "declared": len(req), "declared_dev_only_not_required": len(dev),
                 "declared_missing_from_sbom": missing, "unparsed_entries": unparsed}
        if mpath:
            entry["path"] = mpath
        if idx == 0:
            sbom_layer["manifest"] = entry          # 相容：第一個清單檔仍放在 manifest
        if len(manifests) > 1:
            sbom_layer.setdefault("manifests", []).append(entry)
        if unparsed:
            sbom_layer["status"] = "INCOMPLETE"
            reasons.append(f"清單檔{where}有 {unparsed} 個無法解析的項目（-r/-e、網址、路徑或格式不符），無法確認宣告的套件是否都在 SBOM 內")
        if missing:
            sbom_layer["status"] = "INCOMPLETE"
            reasons.append(f"清單檔{where}宣告的 {len(missing)} 個套件不在 SBOM 內：{', '.join(missing)}")
    if not pkgs:
        sbom_layer["status"] = "EMPTY"
        reasons.insert(0, "SBOM 沒有任何套件元件（規則 12）")

    unknown = [i for i in items if i["class"] != "RESOLVED"]
    # 操作者以 --self 宣告的「專案本身」（例如 Go 的主模組；Syft 把它列成 version UNKNOWN 的元件）：
    # 版本未知時不算缺少的依賴，另外列出；有版本時照一般元件處理。比對只看生態系與名稱（不看版本）。
    def skey(s):
        return (purl_eco(s), norm_name(purl_name(s) or "", purl_eco(s)))
    # 操作者宣告的 --self：可豁免 components 裡同名、版本未知的元件，也可排除對它的無版本比對
    selfs = {skey(s) for s in self_purls if purl_eco(s) and purl_name(s)}
    # SBOM 的 metadata.component 來自 SBOM 產生器讀取的專案檔案（不可信）：只用來排除「對不上元件」的無版本比對，
    # 不豁免任何元件；若與任何元件同名，完全不採用（防止專案把自己命名成某個依賴，隱藏那個依賴的 GAP）
    meta_purl = as_str(as_dict(as_dict(sbom.get("metadata")).get("component")).get("purl"))
    comp_keys = {(i["_eco"], norm_name(i["_ident"], i["_eco"])) for i in items}
    meta_self = skey(meta_purl) if meta_purl and purl_eco(meta_purl) and purl_name(meta_purl) else None
    meta_rejected = bool(meta_self and meta_self in comp_keys)
    if meta_rejected:
        meta_self = None
    # --self-hint：和 metadata.component 一樣來自專案檔（例如根目錄 composer.json／package.json 的 name，不可信），規則也一樣：
    # 只排除「對不上元件」的無版本比對，不豁免任何元件；和任何元件同名的提示完全不採用
    hint_keys = {skey(h) for h in self_hints if purl_eco(h) and purl_name(h)}
    hints_rejected = sorted(f"{e}:{n}" for e, n in hint_keys & comp_keys)
    hint_selfs = hint_keys - comp_keys
    for i in unknown:
        i["self_component"] = (i["_eco"], norm_name(i["_ident"], i["_eco"])) in selfs
    unknown_alone = [i for i in unknown if not i.get("superseded_by_resolved") and not i.get("self_component")]
    comp_layer = {"RESOLVED": sum(i["class"] == "RESOLVED" for i in items),
                  "VERSION_FROM_RANGE": sum(i["class"] == "VERSION_FROM_RANGE" for i in items),
                  "NO_VERSION": sum(i["class"] == "NO_VERSION" for i in items),
                  "UNIDENTIFIABLE": sum(i["class"] == "UNIDENTIFIABLE" for i in items),
                  "unknown_without_resolved_counterpart": len(unknown_alone),
                  "self_components_unversioned": sorted({i["name"] for i in unknown if i.get("self_component")}),
                  "self_declared": {"--self": list(self_purls), "metadata.component": meta_purl or None,
                                    "metadata.component_rejected_same_name_as_component": meta_rejected,
                                    "--self-hint": list(self_hints), "--self-hint_rejected_same_name_as_component": hints_rejected},
                  "markers_checked": list(RANGE_MARKERS), "range_version_pattern": RANGE_VERSION_RE.pattern}

    vuln = {"status": "NOT_RUN", "reasons": [], "statement": STATEMENT}
    valid, excluded, unmapped, ignored = [], [], [], []
    db, src = None, None
    if grype is None:
        vuln["reasons"].append("沒有提供 Grype 結果")
        if not pkgs:
            vuln["status"] = "NOT_ASSESSED"
    else:
        db = db_info(grype, now, max_db_age_days)
        src = as_str(as_dict(grype.get("source")).get("target")) or None
        by_key = {}
        for i in items:
            cur = by_key.get(i["_key"])
            if cur is None or (cur["class"] != "RESOLVED" and i["class"] == "RESOLVED"):   # 與順序無關：RESOLVED 優先
                by_key[i["_key"]] = i
        for m in grype["matches"]:
            mm, a, v = as_dict(m), None, None
            a, v = as_dict(mm.get("artifact")), as_dict(mm.get("vulnerability"))
            eco = purl_eco(a.get("purl"))
            ver = as_version(a.get("version"))
            rec = {"id": as_str(v.get("id")) or None, "package": as_str(a.get("name")) or None, "version": ver or None,
                   "purl": as_str(a.get("purl")) or None}
            comp = by_key.get(key_of(eco, purl_name(a.get("purl")) or as_str(a.get("name")), ver))
            mkey = (eco, norm_name(purl_name(a.get("purl")) or as_str(a.get("name")), eco))
            if comp is None and not ver and (mkey in selfs or mkey == meta_self or mkey in hint_selfs):
                rec["excluded_reason"] = "SELF_NO_VERSION"      # 對專案本身、且沒有版本的比對（觀察到 Grype 會對沒有版本的 purl 套上該套件的公告）
                rec["self_source"] = "--self" if mkey in selfs else ("metadata.component" if mkey == meta_self else "--self-hint")
                excluded.append(rec)
            elif comp is None:
                unmapped.append(rec)
            elif comp["class"] != "RESOLVED":
                rec["excluded_reason"] = comp["class"]
                excluded.append(rec)
            else:
                valid.append(rec)
        for m in as_list(grype.get("ignoredMatches")):
            mm = as_dict(m)
            a, v = as_dict(mm.get("artifact")), as_dict(mm.get("vulnerability"))
            ignored.append({"id": as_str(v.get("id")) or None, "package": as_str(a.get("name")) or None,
                            "version": as_version(a.get("version")) or None, "appliedIgnoreRules": mm.get("appliedIgnoreRules")})
        if not pkgs:
            vuln["status"] = "NOT_ASSESSED"
            vuln["reasons"].append("SBOM 沒有套件元件，弱點結果 0 筆沒有意義")
        elif not comp_layer["RESOLVED"]:
            vuln["status"] = "NOT_ASSESSED"
            vuln["reasons"].append("所有元件版本都未知，沒有任何可比對的元件（規則 13）")
        else:
            vuln["status"] = "COMPLETE"
            if unknown_alone:
                vuln["status"] = "PARTIAL"
                vuln["reasons"].append(f"{len(unknown_alone)} 個元件版本未知且沒有解析後的同名元件，未比對（GAP）：" +
                                       ", ".join(sorted({i['name'] or '(無名稱)' for i in unknown_alone})))
            if sbom_layer["status"] == "INCOMPLETE" or ignored_with_purl:
                vuln["status"] = "PARTIAL"
            if tree != "full":
                vuln["status"] = "PARTIAL"
                vuln["reasons"].append("依賴樹完整性未被宣告為 full（規則 11）：" +
                                       ("操作者標示只有直接依賴" if tree == "direct-only" else "未提供 --tree full"))
            if unmapped:
                vuln["status"] = "PARTIAL"
                vuln["reasons"].append(f"{len(unmapped)} 筆 Grype 比對找不到對應的 SBOM 元件（生態系、名稱或版本不符），保留不丟棄")
            if db["status"] != "OK":
                vuln["status"] = "PARTIAL"
                vuln["reasons"].append("Grype 資料庫已過期" if db["status"] == "STALE" else "無法判斷 Grype 資料庫日期（缺少、格式錯誤或在未來）")
    if vuln["status"] in ("NOT_ASSESSED", "NOT_RUN", "PARTIAL"):
        for r in reversed(reasons):      # sbom 層的原因放最前面
            if r not in vuln["reasons"]:
                vuln["reasons"].insert(0, r)
    vuln["notes"] = []
    if meta_rejected:
        vuln["notes"].append(f"SBOM 的 metadata.component（{meta_purl}）與某個元件同名，不視為專案本身（可能被用來隱藏該元件的缺漏）")
    if comp_layer["self_components_unversioned"]:
        vuln["notes"].append(f"{len(comp_layer['self_components_unversioned'])} 個版本未知的元件是操作者以 --self 宣告的專案本身"
                             f"（{', '.join(comp_layer['self_components_unversioned'])}），不算缺少的依賴，也沒有被比對")
    if ci_actions:
        vuln["notes"].append(f"{len(set(ci_actions))} 個 GitHub Actions（CI 工作流程的依賴，type=application、purl 類型 github）未評估："
                             "不在應用程式弱點分析的範圍內，這個閘門不判斷它們是否被比對，『未評估』不代表沒有問題")
    ex_self = sum(1 for e in excluded if e.get("excluded_reason") == "SELF_NO_VERSION")
    if excluded and len(excluded) > ex_self:
        vuln["notes"].append(f"{len(excluded) - ex_self} 筆 Grype 比對針對版本未知（範圍下限）的元件，已排除；『有效 0 筆』不是沒有弱點的證據")
    if ex_self:
        srcs = "、".join(sorted({e["self_source"] for e in excluded if e.get("excluded_reason") == "SELF_NO_VERSION"}))
        vuln["notes"].append(f"{ex_self} 筆 Grype 比對針對專案本身且沒有版本（來源：{srcs}），已排除："
                             "沒有版本就無法判斷是否受影響；專案本身的弱點不在這個閘門的範圍內，『已排除』不代表沒有問題")
    if ignored:
        vuln["note_ignored_matches"] = f"Grype 另外忽略了 {len(ignored)} 筆（VEX 或忽略規則），原樣保留在 ignored_matches，未計入有效或排除"
    vuln.update({"valid_findings": len(valid), "excluded_findings": len(excluded), "unmapped_findings": len(unmapped),
                 "ignored_findings": len(ignored)})
    for i in items:
        i.pop("_key", None); i.pop("_eco", None); i.pop("_ident", None)
    return {"sbom": sbom_layer, "components": comp_layer, "vulnerability_analysis": vuln, "grype_db": db,
            "grype_source_target": src, "dependency_tree": tree, "component_details": items,
            "valid_matches": valid, "excluded_matches": excluded, "unmapped_matches": unmapped, "ignored_matches": ignored}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sbom", required=True)
    ap.add_argument("--grype")
    ap.add_argument("--manifest", action="append", default=[], help="package.json 或 requirements*.txt；可重複，每個各自核對")
    ap.add_argument("--tree", choices=("full", "direct-only", "unknown"), default="unknown",
                    help="操作者宣告依賴樹是否完整（有鎖定檔或沙箱內解析才可用 full）")
    ap.add_argument("--now", help="ISO 時間，測試用")
    ap.add_argument("--max-db-age-days", type=float, default=7.0)
    ap.add_argument("--out", help="報告 JSON 路徑")
    ap.add_argument("--self", dest="self_purls", action="append", default=[], metavar="PURL",
                    help="可重複；專案本身的 purl（版本可省略），例如 Go 主模組 pkg:golang/github.com/x/y。版本未知時不算 GAP")
    ap.add_argument("--self-hint", dest="self_hints", action="append", default=[], metavar="PURL",
                    help="可重複；專案檔宣告的專案名稱（不可信，例如 package.json 的 name）。只排除對不上元件的無版本比對，"
                         "不豁免元件；和任何元件同名時不採用")
    a = ap.parse_args(argv)
    try:
        sbom = load_json(a.sbom, "SBOM")
        grype = load_json(a.grype, "Grype 輸出") if a.grype else None
        manifest = [read_manifest(m) + (m,) for m in a.manifest] or None
        now = None
        if a.now:
            now = parse_time(a.now)
            if now is None:
                raise InputError("--now 不是合法的 ISO 時間")
        for s in a.self_purls:
            if not (purl_eco(s) and purl_name(s)):
                raise InputError(f"--self 不是合法的 purl：{s}")
        rep = run(sbom, grype, manifest, a.tree, now, a.max_db_age_days, a.self_purls, a.self_hints)
        text = json.dumps(rep, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        if a.out:
            try:
                with open(a.out, "w", encoding="utf-8") as f:
                    f.write(text)
            except OSError as e:
                raise InputError(f"寫不進報告檔：{a.out}（{e.strerror}）")
    except InputError as e:
        print(f"輸入錯誤：{e}", file=sys.stderr)
        return 3
    except Exception as e:   # 當機不可回 1（那是 PARTIAL）
        print(f"內部錯誤：{e.__class__.__name__}（結果不可信，請勿當成任何狀態）", file=sys.stderr)
        return 4
    v = rep["vulnerability_analysis"]
    print(f"SBOM：{rep['sbom']['status']}（套件元件 {rep['sbom']['components_total']}）")
    print(f"元件：{json.dumps({k: rep['components'][k] for k in ('RESOLVED','VERSION_FROM_RANGE','NO_VERSION','UNIDENTIFIABLE')}, ensure_ascii=False)}")
    print(f"弱點分析：{v['status']}　有效 {v['valid_findings']} 筆；排除 {v['excluded_findings']} 筆；對不上元件 {v['unmapped_findings']} 筆；Grype 忽略 {v['ignored_findings']} 筆")
    for r in v["reasons"]:
        print(f"  - {r}")
    for n in v["notes"]:
        print(f"  * 注意：{n}")
    print(v["statement"])
    return EXIT[v["status"]]


if __name__ == "__main__":
    sys.exit(main())
