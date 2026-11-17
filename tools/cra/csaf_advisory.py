#!/usr/bin/env python3
"""修補公告（CSAF 2.0）與版本差異（對應 CRA Annex I Part II(4)、II(8)）。

兩次 CRA 文件產生的結果（CRA/Reports：vex.cdx.json、summary.json、sbom.cdx.json）比對，產生：
- csaf.json：CSAF 2.0 security advisory（category csaf_security_advisory），document.tracking.status 一律 draft（發布要人改）；
- advisory.md：給人看的摘要（英文）；
- csaf-summary.json：分類的數量、缺的發布者欄位、輸入檔的 SHA-256。

用法：python3 -I csaf_advisory.py --old <舊版 CRA/Reports> --new <新版 CRA/Reports> --config <config.json> --out <資料夾>
輸出一行 `CSAF<TAB>OK|ATTENTION|FAIL<TAB>說明`。退出碼：OK 0、ATTENTION 2、FAIL 1、參數錯誤 64。

另一個子指令（CRA 第 14 條第 8 項：被積極利用的漏洞，修補還沒有時通知使用者；草稿，不發布）：
  python3 -I csaf_advisory.py exploited --report <CRA/Reports> --cve CVE-… [--cve …] [--config <config.json>] --out <資料夾>
  輸出 csaf-exploited-draft.json、csaf-exploited-summary.json，一行 `CSAF-EXPLOITED<TAB>狀態<TAB>說明`（警告印在 stderr）。見 exploited_run() 與 docs/CSAF.md。
兩種輸出都會用 CSAF 2.0 JSON schema 與 security_advisory 設定檔的必要欄位驗證，不符就 FAIL（不產生）。

規則：
- 只讀 vex.cdx.json 的輸出格式（不 import vex_export.py）。vex.cdx.json 只有「有判定」的列：沒有判定的列不在比較範圍，
  數量取自 summary.json（vex.gate.assessment），寫在公告的說明與摘要裡。
- 比對鍵：（漏洞 ID、元件 purl 去掉版本與限定詞；沒有 purl 用元件名稱）。分類（舊版 open＝affected／under investigation）：
  - fixed：舊版 open，新版判定 resolved，而且是同一個版本或舊版本已不在新版 SBOM；或新版沒有判定、而新版 SBOM 已經沒有這個元件
    （SBOM 沒有或是空的不判斷移除；只在 VEX 自己的元件清單、不在產品 SBOM 的元件也不判斷）。
  - reassessed：舊版 open，新版判定 not affected（重新評估，不是修補；不寫 vendor_fix）。
  - new：新版 open，舊版沒有這筆或舊版判定 not_affected。still：兩版都 open。changed：其他狀態改變。
  - not_stated：舊版 open，新版沒有判定而元件還在，或新版本已修但舊版本還在 SBOM（**不當成已修**）。
- 發布者資料（csaf.publisher_name、csaf.publisher_namespace、csaf.tracking_id_prefix；沒有時退回 manufacturer.name、manufacturer.website）
  缺的寫 TO BE COMPLETED（namespace 是 schema 要的 URI，用 https://to-be-completed.invalid），列在 csaf-summary.json，狀態 ATTENTION。
- 舊版或新版沒有 vex.cdx.json 或格式不對 → FAIL，不產生公告（並刪掉上一次的輸出）。沒有任何差異時照樣產生，寫「no changes」。
"""
import argparse
import datetime
import hashlib
import json
import lzma
import math
import re
import sys
import unicodedata
import urllib.parse
from pathlib import Path

TBC = "TO BE COMPLETED"
TBC_URI = "https://to-be-completed.invalid"
OUTPUTS = ("csaf.json", "advisory.md", "csaf-summary.json")
OPEN = ("exploitable", "in_triage")
CLOSED = ("resolved", "resolved_with_pedigree", "not_affected", "false_positive")
STATUS = {"exploitable": "known_affected", "in_triage": "under_investigation", "not_affected": "known_not_affected",
          "false_positive": "known_not_affected", "resolved": "fixed", "resolved_with_pedigree": "fixed"}
WORDS = {"exploitable": "affected", "in_triage": "under investigation", "not_affected": "not affected", "false_positive": "not affected",
         "resolved": "fixed", "resolved_with_pedigree": "fixed", None: "no statement"}
CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")


class InputError(Exception):
    pass


def d(v):
    return v if isinstance(v, dict) else {}


def lst(v):
    return [x for x in v if isinstance(x, dict)] if isinstance(v, list) else []


MAX_INPUT = 128 << 20      # 單一輸入檔的大小上限（vex／sbom 約 十幾～二十幾 MB）


def read_json(p, what, required=True):
    """讀 JSON 輸入：不跟隨符號連結（連結 → InputError，必要或選用都一樣：不默默當成沒有）、大小上限 MAX_INPUT。"""
    try:
        if p.is_symlink():
            raise InputError(f"{what}：{p} 是符號連結，不讀")
        if p.is_file() and p.stat().st_size > MAX_INPUT:
            raise InputError(f"{what}：{p} 超過大小上限（{MAX_INPUT >> 20} MiB），不讀")
        raw = p.read_bytes()
        return json.loads(raw), hashlib.sha256(raw).hexdigest()
    except FileNotFoundError:
        if required:
            raise InputError(f"{what}：沒有 {p}")
        return None, None
    except (OSError, ValueError, RecursionError) as e:      # RecursionError：巢狀太深的 JSON（不可信輸入），當成讀不到（dumpling）
        raise InputError(f"{what}：讀不到 {p}（{type(e).__name__}）")


def purl_base(purl):
    """pkg:type/namespace/name@version?qualifiers#subpath → pkg:type/namespace/name（不分大小寫比較用）。"""
    p = urllib.parse.unquote(str(purl or "").split("#", 1)[0].split("?", 1)[0])      # 解 %xx：libstdc%2B%2B6 ＝ libstdc++6
    return p.rsplit("@", 1)[0].lower() if "@" in p else p.lower()


def props(x):
    return {d(p)["name"]: d(p).get("value") for p in lst(d(x).get("properties")) if isinstance(d(p).get("name"), str)}


def comp_name(comp):
    """「名稱 版本」→ 名稱；最後一段不像版本（沒有數字）時整串都是名稱。"""
    parts = comp.rsplit(" ", 1)
    return parts[0] if len(parts) == 2 and re.search(r"\d", parts[1]) else comp


def statements(vex, what):
    """vex.cdx.json → ({鍵: 陳述}, 略過的筆數 dict)。鍵＝(漏洞 ID, 元件 purl 去版本或名稱)；同一個鍵多筆時保留最保守的（affected 優先）。
    陳述的 local：affects 指向 VEX 自己的 components（不在產品 SBOM 的元件，例如只用來比對的原始碼套件）。"""
    if not isinstance(vex, dict) or vex.get("bomFormat") != "CycloneDX" or not isinstance(vex.get("vulnerabilities"), list):
        raise InputError(f"{what}：不是 CycloneDX VEX（沒有 vulnerabilities 清單）")
    rank = {"exploitable": 0, "in_triage": 1, "resolved": 2, "resolved_with_pedigree": 2, "not_affected": 3, "false_positive": 3}
    local = {d(c).get("bom-ref") for c in lst(vex.get("components")) if isinstance(d(c).get("bom-ref"), str)}
    out, dropped = {}, {"not_an_object": 0, "no_id": 0, "unknown_state": 0, "merged_duplicates": 0}
    dropped["not_an_object"] = sum(1 for v in vex["vulnerabilities"] if not isinstance(v, dict))
    for v in lst(vex["vulnerabilities"]):
        vid = clean(v.get("id"), 120)        # dumpling：外部字串一律 clean（去控制字元與 Unicode 格式字元、截斷），和路徑 B 相同
        if not vid:
            dropped["no_id"] += 1
            continue
        a = d(v.get("analysis"))
        state = a.get("state") if isinstance(a.get("state"), str) and a.get("state") in rank else None
        if state is None:
            dropped["unknown_state"] += 1
            continue
        pp = props(v)
        purl = clean(pp.get("sca-center:component-purl"), 300)
        comp = clean(pp.get("sca-center:component"), 200)
        key = (vid.upper(), purl_base(purl) if purl else ("name:" + comp_name(comp).lower()))
        fs = clean(pp.get("sca-center:fix-state"), 40)
        st = {"id": vid, "state": state, "fix_state": fs, "component": comp or "?", "purl": purl, "detail": clean(a.get("detail"), 1000),
              "response": [clean(x, 40) for x in a.get("response") or [] if isinstance(x, str) and clean(x, 40)] if isinstance(a.get("response"), list) else [],
              "justification": clean(a.get("justification"), 80) or None,
              "local": any(isinstance(d(x).get("ref"), str) and d(x)["ref"] in local for x in lst(v.get("affects")))}
        purls = set(out[key]["purls"]) if key in out else set()
        purls.update([purl] if purl else [])
        if key in out:
            dropped["merged_duplicates"] += 1
        if key not in out or rank[state] < rank[out[key]["state"]]:
            out[key] = st
        out[key]["purls"] = sorted(purls)     # 同一個元件的每個版本（foo 1.0、1.1 合成一筆時，兩個都要檢查）
    return out, {k: n for k, n in dropped.items() if n}


def product_of(vex, summary):
    m = d(d(vex).get("metadata"))
    c = d(m.get("component"))
    gate = d(d(d(summary).get("vex")).get("gate"))
    u = d(gate.get("assessment")).get("untriaged_for_gate")
    docs = d(d(summary).get("documents"))
    # 閘門 ATTENTION 也可能是候選漏洞清單不完整（untriaged_for_gate 照樣是 0）：三項都讀得到、都沒問題才算完整
    gaps = []
    go = gate.get("grype_only_advisories")
    if not (isinstance(go, int) and not isinstance(go, bool) and go == 0):
        gaps.append(f"{go} advisories found only by Grype have no assessment" if isinstance(go, int) and not isinstance(go, bool)
                    else "the Grype-only advisory count is unknown")
    if gate.get("grype_cross_check") is not True:
        gaps.append("the Grype cross-check was not done")
    na = gate.get("not_assessed")
    if not (isinstance(na, list) and not na):
        gaps.append(f"{len(na)} matches were not assessed" if isinstance(na, list) else "the list of unassessed matches is unknown")
    return {"name": clean(c.get("name")) or None, "gaps": gaps, "version": clean(c.get("version"), 80) or None,
            "sbom_serial": clean(props(m).get("sca-center:product-sbom-serial"), 120) or None,
            "untriaged": u if isinstance(u, int) and not isinstance(u, bool) else None,
            "verdict": clean(gate.get("verdict"), 40) or None,
            "sbom_status": d(docs.get("sbom")).get("status") if isinstance(d(docs.get("sbom")).get("status"), str) else None}


def sbom_index(sbom):
    """產品 SBOM → {"bases": purl 去版本與名稱, "full": 完整 purl（小寫、去限定詞）}；沒有 SBOM 或沒有任何非 file 元件 → None
    （不能判斷元件是否移除；空的 SBOM 不能當成「元件都拿掉了」，CLAUDE.md 規則 12）。"""
    if not isinstance(sbom, dict):
        return None
    bases, full, names, nv, nover, n = set(), set(), set(), set(), set(), 0

    def walk(cs):
        nonlocal n
        for c in lst(cs):
            if c.get("type") != "file":
                n += 1
            if isinstance(c.get("purl"), str) and c["purl"]:
                bases.add(purl_base(c["purl"]))
                full.add(full_purl(c["purl"]))
                names.add(norm_name(purl_name(c["purl"])))
                nv.add(namever(purl_name(c["purl"]), purl_version(c["purl"])))
            if c.get("name"):
                bases.add("name:" + str(c["name"]).lower())
                names.add(norm_name(str(c["name"]).rsplit("/", 1)[-1]))
                nv.add(namever(c["name"], c.get("version")))   # 沒有 purl 的元件也用名稱＋版本比
                if not c.get("version") and not c.get("purl"):
                    nover.add(namever(c["name"], "")[0])       # 同名、沒有版本：不能說舊版本不在
            walk(c.get("components"))
    walk(sbom.get("components"))
    return {"bases": bases, "full": full, "names": names, "namever": nv, "nover": nover, "serial": sbom.get("serialNumber")} if n else None


def purl_name(purl):
    """pkg:type/namespace/name@… → name（解 %xx 前的原字串）。"""
    return purl_base(purl).rsplit("/", 1)[-1]


def norm_name(name):
    """套件名稱正規化（類似 PEP 503）：小寫，連續的 - _ . 換成 -。換寫法、換 namespace 或換 SBOM 產生器時才對得到。"""
    return re.sub(r"[-_.]+", "-", str(name).lower()).strip("-")


def full_purl(p):
    """完整 purl（去限定詞與 subpath、解 %xx、小寫）：`+` 與 `%2B` 視為相同。"""
    return urllib.parse.unquote(str(p or "").split("#", 1)[0].split("?", 1)[0]).lower()


def purl_version(p):
    base = str(p or "").split("#", 1)[0].split("?", 1)[0]
    return urllib.parse.unquote(base.rsplit("@", 1)[1]).lower() if "@" in base else ""


def namever(name, version):
    return (norm_name(urllib.parse.unquote(str(name)).rsplit("/", 1)[-1]), str(version or "").lower())


def gone(purl, idx):
    """這個版本已不在新版 SBOM：完整 purl（解碼後）對不到，而且名稱＋版本也對不到（沒有 purl 的元件、purl 寫法不同）。"""
    nv = namever(purl_name(purl), purl_version(purl))
    return full_purl(purl) not in idx["full"] and nv not in idx["namever"] and nv[0] not in idx["nover"]


def classify(old, new, idx, removal_ok=True):
    """分類（見模組說明）。fixed 只在有證據時：新版判定 resolved，而且（同一個版本，或新版 SBOM 已經沒有舊版本）；
    或新版沒有判定、而新版 SBOM 沒有這個元件（舊的判定是產品 SBOM 裡的元件）。"""
    rows = []
    for k in sorted(set(old) | set(new)):
        o, n = old.get(k), new.get(k)
        os_, ns = (o or {}).get("state"), (n or {}).get("state")
        # 舊版的每個版本：和新版判定的是同一個版本，或（新版 SBOM 可當證據時）已不在新版 SBOM；一個都不能漏
        opurls = (o.get("purls") or ([o["purl"]] if o["purl"] else [])) if o else []
        covered = bool(opurls) and all(
            (n and full_purl(p) == full_purl(n["purl"])) or (removal_ok and idx is not None and gone(p, idx)) for p in opurls)
        removed = False
        if os_ in OPEN and ns in ("resolved", "resolved_with_pedigree"):
            cat = "fixed" if covered else "not_stated"     # 新版本已修，但舊版本還在 SBOM 裡（或 SBOM 不能當證據）、沒有判定
        elif os_ in OPEN and ns in ("not_affected", "false_positive"):
            cat = "reassessed"                                             # 重新評估成 not_affected，不是修補
        elif os_ in OPEN and n is None:
            # 「消失」要能當證據：新版 SBOM 完整（removal_ok）、元件不在 SBOM（purl 與正規化名稱都對不到）、不是只在 VEX 自己的元件清單
            oname = norm_name(purl_name(o["purl"]) if o["purl"] else comp_name(o["component"]))
            removed = bool(removal_ok and idx is not None and not o["local"] and k[1] not in idx["bases"] and oname not in idx["names"])
            cat = "fixed" if removed else "not_stated"
        elif ns in OPEN and os_ in OPEN:
            cat = "still"
        elif ns in OPEN:
            cat = "new"
        elif o and n and os_ != ns and STATUS[os_] != STATUS[ns]:      # not_affected ↔ false_positive 都是 known_not_affected：不算改變
            cat = "changed"
        else:
            continue          # 兩版都是 not_affected，或只有一版有 not_affected 的判定：不放進公告
        rows.append({"key": list(k), "id": (n or o)["id"], "component": (n or o)["component"], "old_component": (o or {}).get("component"),
                     "purl": (n or {}).get("purl") or "", "old_purl": (o or {}).get("purl") or "", "old": os_, "new": ns, "category": cat,
                     "removed": removed, "response": (n or o)["response"], "fix_state": (n or o).get("fix_state") or "", "detail": (n or {}).get("detail") or "",
                     "justification": (n or {}).get("justification")})
    return rows


EXAMPLE_NAMES = {"Example Co.", "Example Co", "Example Company"}


def uri_ok(u):
    """CSAF publisher namespace：http(s) 的完整 URL（有主機、沒有空白、%xx 都合法）。schema 的 format: uri 在沒有 rfc3987 時不檢查。"""
    if not (isinstance(u, str) and re.fullmatch(r"https?://\S+", u)) or re.search(r"%(?![0-9A-Fa-f]{2})", u):
        return False
    try:
        p = urllib.parse.urlsplit(u)
        p.port                      # 埠號不合法時 ValueError
        return bool(p.hostname)
    except ValueError:
        return False


def company(cfg):
    """→ (publisher name, namespace, tracking 前綴, contact, 缺的欄位)。"""
    cs, m, vc = d(cfg.get("csaf")), d(cfg.get("manufacturer")), d(cfg.get("vulnerability_contact"))
    miss = []
    name = (cs.get("publisher_name") or m.get("name") or "").strip() if isinstance(cs.get("publisher_name") or m.get("name") or "", str) else ""
    if name in EXAMPLE_NAMES:
        name = ""                     # config.example.json 原樣的值不是真的發布者資料
    if not name:
        miss.append("csaf.publisher_name")
    ns = cs.get("publisher_namespace") or m.get("website") or ""
    if not uri_ok(ns) or re.match(r"^https?://([^/]*\.)?example\.(com|org|net)(/|$)", str(ns)):
        miss.append("csaf.publisher_namespace")
        ns = TBC_URI
    pre = cs.get("tracking_id_prefix")
    if not (isinstance(pre, str) and pre.strip()):
        miss.append("csaf.tracking_id_prefix")
        pre = "TBC-"
    contact = cs.get("contact") or vc.get("contact") or m.get("email")
    if not (isinstance(contact, str) and contact.strip()):
        miss.append("csaf.contact")     # dumpling：沒有聯絡方式時不寫 contact_details（不放預設值），列為要補的欄位
    return name or TBC, ns, pre.strip(), contact if isinstance(contact, str) and contact.strip() else None, miss


TLP_LABELS = ("WHITE", "GREEN", "AMBER", "RED")


def advisory_extras(cfg, tid):
    """→ (document.references, document.distribution 或 None, 缺的欄位)。
    references：一筆 self，網址＝csaf.advisory_url_base（https 網址）＋ "/" ＋ 小寫公告編號 ＋ ".json"；沒設定或不合格 → TBC_URI＋缺欄位。
    distribution：只在 csaf.tlp 是 WHITE／GREEN／AMBER／RED 時寫（不設定就不寫，也不算缺）。"""
    cs = d(d(cfg).get("csaf"))
    base, miss = cs.get("advisory_url_base"), []
    if uri_ok(base) and str(base).startswith("https://") and not re.match(r"^https?://([^/]*\.)?example\.(com|org|net)(/|$)", str(base)):
        url = f"{str(base).rstrip('/')}/{slug(tid).lower()}.json"
    else:
        url = f"{TBC_URI}/{slug(tid).lower()}.json"
        miss.append("csaf.advisory_url_base")
    refs = [{"category": "self", "summary": "Canonical URL of this advisory (to be confirmed before publication)", "url": url}]
    tlp = cs.get("tlp")
    tlp = tlp.strip().upper() if isinstance(tlp, str) else None
    return refs, ({"tlp": {"label": tlp}} if tlp in TLP_LABELS else None), miss


def slug(s):
    return re.sub(r"[^A-Za-z0-9._-]+", "-", s).strip("-") or "x"


def vuln_ids(vid):
    if CVE.match(vid.upper()):
        return {"cve": vid.upper()}
    sysname = vid.split("-", 1)[0].upper() if "-" in vid else "ID"
    return {"ids": [{"system_name": sysname, "text": vid}]}


REMEDIATION = {"can_not_fix": ("no_fix_planned", "The supplier cannot fix this vulnerability"),
               "will_not_fix": ("no_fix_planned", "The supplier will not fix this vulnerability"),
               "workaround_available": ("workaround", "A workaround is available; contact the supplier"),
               "update": ("none_available", "A fix is available from the distribution or upstream project and is not yet included in {new}"),
               "rollback": ("none_available", "Rolling back to an earlier version is an option for {new}")}
# 沒有 response 的 exploitable（批次規則）：依該列的修補狀態。不寫成「供應商不能修／不修」——沒有修補是上游的狀態，
# won't fix 是發行版的決定（處理方式由產品工程師定期檢討）
LEGACY = ("can_not_fix", "will_not_fix")
NO_RESPONSE = {"": ("none_available", "No fix information is available for {new} at this time (insufficient data; under assessment)"),
               "not-fixed": ("none_available", "No fix is available yet from the upstream project or distribution; a fix may be included "
                                               "in a future release of {new}, depending on availability"),
               "fixed": ("none_available", "A fix is available from the distribution or upstream project and is not yet included in {new}"),
               "wont-fix": ("no_fix_planned", "The distribution has marked this vulnerability as will not fix; how it is handled "
                                              "in {new} is under review")}
CATEGORIES = ("fixed", "new", "still", "reassessed", "changed", "not_stated")


PURL_OK = re.compile(r"^pkg:[A-Za-z.+-][A-Za-z0-9.+-]*/.+")


def incomplete_text(newp):
    parts = [] if newp["verdict"] in ("OK", "ATTENTION") else [f"release gate {newp['verdict'] or 'unknown'}"]
    return "; ".join(parts + newp["gaps"])


def build_csaf(rows, oldp, newp, cfg, now, incomplete=False, new_skipped=0, limits=()):
    """new_skipped：新版 VEX 被略過的陳述數（不是物件、沒有 ID、狀態不認得）；limits：寫進 csaf.json 的限制說明。"""
    pub, ns, pre, contact, miss = company(cfg)
    if not newp["name"]:
        miss.append("product.name")
    pname = newp["name"] or oldp["name"] or TBC
    if not oldp["version"]:
        miss.append("old product version (VEX metadata.component.version)")
    if not newp["version"]:
        miss.append("product.version")
    ov, nv = oldp["version"] or "(previous version)", newp["version"] or "(new version)"
    old_name, new_name = f"{oldp['name'] or pname} {ov}", f"{pname} {nv}"
    fpn = [{"product_id": "CSAFPID-OLD", "name": old_name}, {"product_id": "CSAFPID-NEW", "name": new_name}]
    comps, rels, relmap = {}, [], {}

    def comp_id(label, purl):
        k = (label, full_purl(purl) if purl else "")
        if k not in comps:
            cid = f"CSAFPID-C{len(comps) + 1:04d}"
            comps[k] = cid
            e = {"product_id": cid, "name": label}
            if purl and PURL_OK.match(purl) and not re.search(r"\s", purl):     # OASIS schema 的 purl 樣式；不合的不寫（名稱照樣有）
                e["product_identification_helper"] = {"purl": purl}
            fpn.append(e)
        return comps[k]

    def rel(label, purl, prod):
        cid = comp_id(label, purl)
        k = (cid, prod)
        if k not in relmap:
            rid = f"CSAFPID-R{len(relmap) + 1:04d}"
            relmap[k] = rid
            rels.append({"category": "default_component_of", "product_reference": cid, "relates_to_product_reference": prod,
                         "full_product_name": {"product_id": rid, "name": f"{label} as part of {old_name if prod == 'CSAFPID-OLD' else new_name}"}})
        return relmap[k]

    by_vuln = {}
    for r in rows:
        by_vuln.setdefault(r["id"].upper(), []).append(r)
    vulns = []
    for vid in sorted(by_vuln):
        ps, rem, threats, notes = {}, [], [], []
        for r in by_vuln[vid]:
            oid = nid = None
            if r["old"]:
                oid = rel(r["old_component"] or r["component"], r["old_purl"], "CSAFPID-OLD")    # 舊版元件用舊版的 purl
                ps.setdefault(STATUS[r["old"]], []).append(oid)
            if r["new"]:
                nid = rel(r["component"], r["purl"], "CSAFPID-NEW")
                ps.setdefault(STATUS[r["new"]], []).append(nid)
            if r["category"] == "fixed" and oid:
                rem.append({"category": "vendor_fix", "product_ids": [oid],
                            "details": f"Update to {new_name}" + (" (the component is no longer included)" if r["removed"] else "") + "."})
            if r["new"] == "exploitable" and nid:
                # 舊設定檔的 can_not_fix／will_not_fix 不照字面（會讀成供應商不能修／不修）：修補狀態已知時依修補狀態說，與客戶表格一致
                # 修補狀態不明（unknown、no Grype data、空的）時也不照字面：與沒有 response 的列相同，寫資料不足、評估中
                resp = [x for x in r["response"] if x not in LEGACY]
                # update／rollback 寫「有修補」，只在修補狀態是 fixed 時；其他狀態依修補狀態說（與客戶表格同一規則）
                resp = [x for x in resp if not (x in ("update", "rollback") and r["fix_state"] != "fixed")]
                cat, text = next((REMEDIATION[x] for x in resp if x in REMEDIATION),
                                 NO_RESPONSE.get(r["fix_state"]) or NO_RESPONSE[""])
                rem.append({"category": cat, "product_ids": [nid], "details": text.format(new=new_name) + "."})
            if r["new"] in ("not_affected", "false_positive") and nid:
                why = " ".join(x for x in (r["justification"] and f"Justification: {r['justification']}.", r["detail"]) if x)
                threats.append({"category": "impact", "product_ids": [nid], "details": why or "Assessed as not affected."})
            notes.append(f"{r['component']}: {WORDS[r['old']]} in {old_name}, {WORDS[r['new']]} in {new_name}"
                         + (" (component no longer included)" if r["removed"] else "") + f" [{r['category'].replace('_', ' ')}].")
        # 元件不在新版：只有這個漏洞的每一列都是 fixed 時，新產品本身才算已修（另一個元件還受影響、新出現或沒有判定時不算）
        # vex.cdx.json 不含未評估的列：新版有未評估的列（或數量不明）時，同一個漏洞可能還在別的元件上，產品層級的「已修」沒有證據
        # 閘門不是 OK／ATTENTION（資料不完整，untriaged 可能是 0 卻沒評估）、新版 VEX 有被略過的陳述（可能正是這個漏洞）時也不列
        if any(r["removed"] for r in by_vuln[vid]) and all(r["category"] == "fixed" for r in by_vuln[vid]):
            why = []
            if newp["untriaged"] != 0:
                why.append(f"{newp['untriaged'] if newp['untriaged'] is not None else 'an unknown number of'} rows in {new_name} "
                           "have no assessment and may include this vulnerability")
            if incomplete:
                why.append(f"the vulnerability data of {new_name} is incomplete ({incomplete_text(newp)})")
            if new_skipped:
                why.append(f"{new_skipped} statements in the VEX of {new_name} could not be read and may concern this vulnerability")
            if why:
                notes.append(f"{new_name} as a whole is not listed as fixed: " + "; ".join(why) + ".")
            else:
                ps.setdefault("fixed", []).append("CSAFPID-NEW")
        v = dict(vuln_ids(by_vuln[vid][0]["id"]))      # 原本的大小寫（GHSA 等不是全大寫）
        v["notes"] = [{"category": "summary", "text": " ".join(notes)}]
        v["product_status"] = {k: sorted(set(x)) for k, x in sorted(ps.items())}
        if rem:
            v["remediations"] = rem
        if threats:
            v["threats"] = threats
        vulns.append(v)
    counts = {c: sum(1 for r in rows if r["category"] == c) for c in CATEGORIES}
    scope = (f"Only vulnerabilities with a VEX statement are compared. Rows without an assessment are not included "
             f"({newp['untriaged'] if newp['untriaged'] is not None else 'unknown number'} in {new_name}).")
    summary_text = ("The vulnerability data of the new version is incomplete; no differences were found in the assessed vulnerabilities, "
                    "but this does not mean that nothing changed." if (incomplete and not rows) else
                    "No changes in the assessed vulnerabilities between the two versions." if not rows else
                    f"Compared with {old_name}: {counts['fixed']} fixed, {counts['new']} new, {counts['still']} still present, "
                    f"{counts['reassessed']} reassessed as not affected, {counts['changed']} with another status change, "
                    f"{counts['not_stated']} not assessed in {new_name}.")
    pubobj = {"category": "vendor", "name": pub, "namespace": ns}
    if contact:
        pubobj["contact_details"] = contact
    tid = f"{pre}{slug(pname)}-{slug(nv)}"
    refs, dist, xmiss = advisory_extras(cfg, tid)
    miss += xmiss
    # 沒有任何差異：用 csaf_base（security advisory 的設定檔要求 vulnerabilities）
    doc = {"document": {"category": "csaf_security_advisory" if vulns else "csaf_base", "csaf_version": "2.0", "lang": "en",
                        "title": f"{new_name}: security fixes compared with {ov}" if vulns else
                                 f"{new_name}: no {'known ' if incomplete else ''}changes in assessed vulnerabilities compared with {ov}",
                        "publisher": pubobj, "references": refs, **({"distribution": dist} if dist else {}),
                        "notes": [{"category": "summary", "title": "Summary", "text": summary_text},
                                  {"category": "general", "title": "Scope", "text": scope},
                                  *([{"category": "general", "title": "Incomplete vulnerability data",
                                      "text": f"The vulnerability data of {new_name} is incomplete ({incomplete_text(newp)}). "
                                              "Vulnerabilities that are not assessed are not in this "
                                              "advisory; the lists below are not complete."}] if incomplete and rows else []),
                                  *([{"category": "general", "title": "Limitations",
                                      "text": " ".join(x[0].upper() + x[1:] + "." for x in limits)}] if limits else []),
                                  {"category": "legal_disclaimer", "title": "Status",
                                   "text": "Draft generated from the supplier's vulnerability assessments; to be reviewed before publication."}],
                        "tracking": {"id": tid, "status": "draft", "version": "0",
                                     "initial_release_date": now, "current_release_date": now,
                                     "revision_history": [{"date": now, "number": "0", "summary": "Draft generated by dumpling csaf_advisory.py"}],
                                     "generator": {"engine": {"name": "dumpling csaf_advisory.py"}, "date": now}}},
           "product_tree": {"full_product_names": fpn, **({"relationships": rels} if rels else {})}}
    if vulns:
        doc["vulnerabilities"] = vulns
    return doc, counts, miss, scope, summary_text


def table(head, rows):
    esc = lambda x: str(x).replace("|", "\\|").replace("\n", " ")   # noqa: E731
    return "\n".join(["| " + " | ".join(head) + " |", "|" + "---|" * len(head)] + ["| " + " | ".join(esc(x) for x in r) + " |" for r in rows])


DRAFT_FIRST_LINE = "草稿：工具不發布，也不會自動放進客戶資料包"      # dumpling：advisory.md 與 PM 的 README 第一行（C0 #175 驗證）


def advisory_md(doc, rows, counts, miss, scope, summary_text, notes):
    t = doc["document"]
    out = [DRAFT_FIRST_LINE, "", f"# {t['title']}", "", f"Status: **draft** · Tracking ID: `{t['tracking']['id']}` · Generated: {t['tracking']['current_release_date']}", "",
           summary_text, "", scope, ""]
    if miss:
        out += ["Fields TO BE COMPLETED before publication: " + ", ".join(f"`{m}`" for m in miss) + ".", ""]
    if notes:
        out += ["\n".join(f"- Note: {n}." for n in notes), ""]
    titles = {"fixed": "Fixed", "new": "New", "still": "Still present", "reassessed": "Reassessed as not affected (not a fix)",
              "changed": "Other status changes", "not_stated": "Not assessed in the new version (not counted as fixed)"}
    for cat, title in titles.items():
        rs = [r for r in rows if r["category"] == cat]
        out += [f"## {title} ({len(rs)})", ""]
        out += [table(["Vulnerability", "Component", "Old status", "New status"],
                      [[r["id"], r["component"] + (" (no longer included)" if r["removed"] else ""), WORDS[r["old"]], WORDS[r["new"]]] for r in rs])
                if rs else "None.", ""]
    return "\n".join(out)


def write(out, files, names=None):
    out.mkdir(parents=True, exist_ok=True)
    for n in names or OUTPUTS:
        (out / n).unlink(missing_ok=True)
    for n, text in files.items():
        (out / n).write_text(text, encoding="utf-8")


# 預發行標記：排在同一版的正式版之前，彼此的先後只認這幾個（其他字母段落沒有一致的規則 → 比不出來）
PRERELEASE = {"dev": 0, "alpha": 1, "beta": 2, "rc": 3}


def version_key(v):
    """版本字串 → [(0, 數字) 或 (1, 小寫字母段)]；先去掉開頭的 v／V。"""
    v = re.sub(r"^[vV](?=\d)", "", str(v or "").strip())
    return [(0, int(t)) if t.isdigit() else (1, t.lower()) for t in re.findall(r"\d+|[A-Za-z]+", v)]


def _tail(rest):
    """較長那一版多出來的段落：先略過補的 0；接著是預發行標記 → 較長的在前（-1）；數字 → 較長的在後（1）；
    其他字母 → 比不出來（None）；什麼都沒有 → 相同（0）。"""
    rest = [t for t in rest]
    while rest and rest[0] == (0, 0):
        rest.pop(0)
    if not rest:
        return 0
    if rest[0][0] == 0:
        return 1
    return -1 if rest[0][1] in PRERELEASE else None


def version_order(old, new):
    """新版在後 → 1；相同（含尾端補 0、開頭 v）→ 0；新版在前 → -1；比不出來 → None。
    比不出來的情況：沒有版本；有 epoch（`1:`）而兩邊不同；同一位置一邊數字一邊字母（預發行標記除外）；
    兩個不同的字母段落而不是都屬於 dev／alpha／beta／rc；只差在 build 中繼資料（`+…`）。不硬排，交給呼叫端標 ATTENTION。"""
    o, n = (str(x or "").strip() for x in (old, new))
    eo, en = (re.match(r"^(\d+):", x) for x in (o, n))
    if eo or en:
        if not (eo and en) or int(eo.group(1)) != int(en.group(1)):
            return None
        o, n = o[eo.end():], n[en.end():]
    # semver 的 build 中繼資料（+ 之後）不參與排序：只差在 build → 比不出來；其他照去掉 build 的部分比
    (o, ob), (n, nb) = ((x.split("+", 1) + [""])[:2] for x in (o, n))
    if ob != nb and version_canon(o) == version_canon(n):
        return None
    a, b = version_key(o), version_key(n)
    if not a or not b:
        return None
    for i, (x, y) in enumerate(zip(a, b)):
        if x == y:
            continue
        if x[0] == y[0] == 0:
            return 1 if y[1] > x[1] else -1
        if x[0] == y[0] == 1:
            if x[1] in PRERELEASE and y[1] in PRERELEASE:
                return 1 if PRERELEASE[y[1]] > PRERELEASE[x[1]] else -1
            return None
        # 一邊數字、一邊字母：字母是預發行標記才排得出來（1.0rc1 < 1.0.1）
        alpha = x if x[0] == 1 else y
        if alpha[1] not in PRERELEASE:
            return None
        return 1 if alpha is x else -1
    if len(a) == len(b):
        t = 0
    else:
        t = _tail(b[len(a):]) if len(b) > len(a) else _tail(a[len(b):])
        t = t if t is None or len(b) > len(a) else -t
    # 段落相同但寫法不同（例如 1.0-1 和 1.0.1）不算同一版：只有開頭 v、尾端補 0 的差別才算相同
    return t if t != 0 or version_canon(o) == version_canon(n) else None


def version_canon(v):
    return re.sub(r"(?:[._-]0+)+$", "", re.sub(r"^[vV](?=\d)", "", str(v or "").strip())).lower()


def name_key(name):
    """產品名稱比對用：不分大小寫，內部的空白、-、_ 視為相同。"""
    return re.sub(r"[\s_-]+", " ", name).strip().casefold()


def same_product(ov, nv):
    """兩組輸入要是同一個產品、而且新版在後；不是就 FAIL（多半是資料夾給錯或 --old／--new 對調），不產生公告。"""
    on = str(d(d(d(ov).get("metadata")).get("component")).get("name") or "").strip()
    nn = str(d(d(d(nv).get("metadata")).get("component")).get("name") or "").strip()
    if on and nn and name_key(on) != name_key(nn):
        raise InputError(f"舊版與新版不是同一個產品（{on}／{nn}）")
    ov_, nv_ = (str(d(d(d(x).get("metadata")).get("component")).get("version") or "").strip() for x in (ov, nv))
    o = version_order(ov_, nv_)
    if ov_ and nv_ and (ov_ == nv_ or o == 0):
        raise InputError(f"舊版與新版的版本相同（{ov_}" + ("" if ov_ == nv_ else f"／{nv_}") + "）")
    if o == -1:
        raise InputError(f"新版 {nv_} 比舊版 {ov_} 舊（--old／--new 可能對調）")


def run(old_dir, new_dir, cfg, out, now=None):
    """→ (status, 說明, summary dict 或 None)。FAIL 時不寫公告。"""
    now = now or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        ov, osha = read_json(old_dir / "vex.cdx.json", "舊版")
        nv, nsha = read_json(new_dir / "vex.cdx.json", "新版")
        (old, odrop), (new, ndrop) = statements(ov, "舊版 vex.cdx.json"), statements(nv, "新版 vex.cdx.json")
        os_, _ = read_json(old_dir / "summary.json", "舊版", required=False)
        ns, _ = read_json(new_dir / "summary.json", "新版", required=False)
        nb, nbsha = read_json(new_dir / "sbom.cdx.json", "新版", required=False)
        same_product(ov, nv)
    except InputError as e:
        try:
            write(out, {})
        except OSError as w:
            return "FAIL", f"{e}；沒有產生公告；清除上一次的輸出也失敗（{w}），{out} 裡的舊檔不是這次的結果", None
        return "FAIL", f"{e}；沒有產生公告", None
    # summary.json 要是同一次產生的（記錄的 vex.cdx.json sha256 和讀到的相同），否則它的閘門、SBOM 狀態不能用
    pairing = []
    for what, smry, sha in (("old", os_, osha), ("new", ns, nsha)):
        if smry is None:
            continue
        rec = d(d(d(d(smry).get("vex")).get("files")).get("vex.cdx.json")).get("sha256")
        if rec != sha:
            pairing.append(f"the {what} summary.json " + ("does not record the VEX it was produced with" if not rec else
                                                        "belongs to another VEX file (sha256 differs)") + "; it is not used")
            if what == "old":
                os_ = None
            else:
                ns = None
    oldp, newp = product_of(ov, os_), product_of(nv, ns)
    idx = sbom_index(nb)
    rec = d(d(ns).get("product_sbom")).get("sha256") if ns is not None else None
    sbom_mismatch = idx is not None and ns is not None and rec != nbsha
    # 「元件從新版 SBOM 消失」只有在新版 SBOM 完整（sbom 文件 OK）、和 VEX 指的是同一份 SBOM（序號相同）時才能當證據
    why_not = []
    if newp["sbom_status"] != "OK":
        why_not.append(f"SBOM document status of the new version is {newp['sbom_status'] or 'unknown'}")
    if idx is not None and not (newp["sbom_serial"] and idx["serial"]):
        why_not.append("the new VEX or SBOM has no serial number, so they cannot be matched")
    elif idx is not None and newp["sbom_serial"] != idx["serial"]:
        why_not.append("the new SBOM is not the one the new VEX refers to (serial number differs)")
    if sbom_mismatch:
        why_not.append("the new sbom.cdx.json is not the one recorded in the new summary.json (sha256 differs or missing)")
    order = version_order(oldp["version"], newp["version"])
    rows = classify(old, new, idx, removal_ok=not why_not)
    incomplete = newp["verdict"] not in ("OK", "ATTENTION") or bool(newp["gaps"])
    skipped = sum(ndrop.get(k, 0) for k in ("not_an_object", "no_id", "unknown_state"))
    limits = []
    if why_not and idx is not None:
        limits.append("components missing from the new SBOM are not treated as removed: " + "; ".join(why_not))
    if idx is None:
        limits.append("no usable SBOM of the new version: removed components cannot be recognised")
    if skipped:
        limits.append(f"{skipped} statements in the new VEX could not be read (not an object, no ID or unknown state) and are not compared")
    doc, counts, miss, scope, stext = build_csaf(rows, oldp, newp, cfg, now, incomplete, skipped, limits)
    notes = list(pairing)
    errs, ran = validate_doc(doc)
    if errs:
        try:
            write(out, {})
        except OSError:
            pass
        return "FAIL", "產生的公告不符合 CSAF 2.0 schema 或 security_advisory 設定檔（程式問題）：" + "；".join(errs[:5]) + "；沒有產生公告", None
    if not ran:
        notes.append(SCHEMA_NOT_RUN_NOTE)
    if order is None:
        notes.append(f"cannot confirm that {newp['version'] or '(no version)'} is newer than {oldp['version'] or '(no version)'}")
    if incomplete:
        notes.append(f"vulnerability data of the new version is incomplete ({incomplete_text(newp)}): "
                     "missing differences do not mean that nothing changed")
    if why_not and idx is not None:
        notes.append("components missing from the new SBOM are not treated as removed: " + "; ".join(why_not))
    if newp["untriaged"] is None:
        notes.append("the number of unassessed rows in the new version is unknown (no readable summary.json)")
    elif newp["untriaged"]:
        notes.append(f"{newp['untriaged']} rows in the new version have no assessment and are not compared")
    if idx is None:
        notes.append("no usable SBOM of the new version (missing or without components): removed components cannot be recognised")
    for what, dr in (("old", odrop), ("new", ndrop)):
        if dr:
            notes.append(f"{what} VEX: statements ignored or merged: " + ", ".join(f"{k} {n}" for k, n in dr.items()))
    status = "ATTENTION" if (miss or counts["not_stated"] or notes) else "OK"
    summ = {"tool": "csaf_advisory", "generated": now, "status": status, "counts": counts, "missing_fields": miss, "notes": notes,
            "schema_validation": schema_status(ran), "builtin_checks": {"ran": True, "problems": [], "covers": list(BUILTIN_COVERS)},
            "untriaged_in_new": newp["untriaged"], "ignored": {"old": odrop, "new": ndrop},
            "old": dict(oldp, vex_sha256=osha),
            "new": dict(newp, vex_sha256=nsha, sbom_sha256=nbsha, sbom_matches_summary=bool(idx is not None and ns is not None and rec == nbsha)),
            "rows": rows}
    try:
        write(out, {"csaf.json": json.dumps(doc, ensure_ascii=False, indent=1) + "\n",
                    "advisory.md": advisory_md(doc, rows, counts, miss, scope, stext, notes),
                    "csaf-summary.json": json.dumps(summ, ensure_ascii=False, indent=1) + "\n"})
    except OSError as e:
        return "FAIL", f"寫不進 {out}（{type(e).__name__}）", None
    detail = stext + (f"；缺 {', '.join(miss)}" if miss else "") + ("；" + "；".join(notes) if notes else "")
    return status, detail, summ


# ---------------------------------------------------------------- 驗證（CSAF 2.0 JSON schema＋security_advisory 設定檔必要欄位）

SCHEMA_DIR = Path(__file__).resolve().parent / "data" / "csaf-2.0"      # OASIS／FIRST 官方檔，原樣（來源與授權見 data/csaf-2.0/NOTICE.md）
_VALIDATOR = []


def schema_validator():
    """OASIS CSAF 2.0 JSON schema 與它引用的 FIRST CVSS schema（data/csaf-2.0）；jsonschema、referencing 或 schema 檔不在 → None。"""
    if _VALIDATOR:
        return _VALIDATOR[0]
    v = None
    try:
        import jsonschema
        import referencing
        import referencing.jsonschema
        rs = []
        for n in ("cvss-v2.0.json", "cvss-v3.0.json", "cvss-v3.1.json"):
            doc = json.loads((SCHEMA_DIR / n).read_text(encoding="utf-8"))
            spec = referencing.jsonschema.specification_with(doc.get("$schema", ""), default=referencing.jsonschema.DRAFT7)
            rs.append((f"https://www.first.org/cvss/{n}", referencing.Resource.from_contents(doc, default_specification=spec)))
        main = json.loads((SCHEMA_DIR / "csaf_json_schema.json").read_text(encoding="utf-8"))
        v = jsonschema.Draft202012Validator(main, registry=referencing.Registry().with_resources(rs),
                                            format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER)
    except Exception:           # 沒裝 jsonschema／referencing、schema 檔不在或壞了：記成沒有跑，不假裝通過
        v = None
    _VALIDATOR.append(v)
    return v


STATUS_GROUPS = ("first_affected", "first_fixed", "fixed", "known_affected", "known_not_affected", "last_affected",
                 "recommended", "under_investigation")


EXCLUSIVE = ("known_affected", "known_not_affected", "fixed", "under_investigation")


def profile_problems(doc):
    """csaf_security_advisory 設定檔（CSAF 2.0 第 4 章）的必要欄位，加上產品 ID 都有定義、產品狀態互斥（schema 查不到的兩項）。"""
    out = []
    dd = d(d(doc).get("document"))
    if dd.get("category") != "csaf_security_advisory":
        return out
    if not lst(dd.get("notes")):
        out.append("profile: document.notes is required")
    if not lst(dd.get("references")):
        out.append("profile: document.references is required")
    pt = d(d(doc).get("product_tree"))
    defined = {d(x).get("product_id") for x in lst(pt.get("full_product_names"))}
    defined |= {d(d(x).get("full_product_name")).get("product_id") for x in lst(pt.get("relationships"))}
    if not defined - {None}:
        out.append("profile: product_tree is required")
    vs = lst(d(doc).get("vulnerabilities"))
    if not vs:
        out.append("profile: vulnerabilities is required")
    for i, v in enumerate(vs):
        w = f"vulnerabilities[{i}]"
        if not (v.get("cve") or v.get("ids")):
            out.append(f"profile: {w} needs cve or ids")
        if not lst(v.get("notes")):
            out.append(f"profile: {w}.notes is required")
        ps = d(v.get("product_status"))
        if not any(ps.get(g) for g in STATUS_GROUPS):
            out.append(f"profile: {w}.product_status is required")
        seen = {}
        for g in EXCLUSIVE:                        # 同一個產品不能同時在這幾組裡
            for pid in ps.get(g) or []:
                if pid in seen:
                    out.append(f"{w}: product {pid} is in both {seen[pid]} and {g}")
                seen[pid] = g
        used = {pid for g in STATUS_GROUPS for pid in ps.get(g) or []}
        for k in ("remediations", "threats", "scores"):
            for x in lst(v.get(k)):
                used |= set(x.get("product_ids") or x.get("products") or [])
        for pid in sorted(x for x in used if x not in defined):
            out.append(f"{w}: product {pid} is not defined in product_tree")
    return out


BUILTIN_COVERS = ("document 必要欄位（category、csaf_version、title、publisher、tracking 與 revision_history）", "tracking.status 與 publisher.category 的列舉值",
                  "security_advisory 設定檔必要欄位（document.notes、document.references、product_tree、vulnerabilities 至少一筆、每筆有 cve 或 ids、notes、product_status）",
                  "product_status、remediations、threats、scores 參照的 product_id 都定義在 product_tree", "同一產品不同時在 known_affected／known_not_affected／fixed／under_investigation")


def builtin_problems(doc):
    """不依賴 jsonschema 套件的內建檢查（BUILTIN_COVERS）；不取代完整 schema 驗證，沒裝 jsonschema 時至少擋掉結構性的錯誤。"""
    out = []
    dd = d(d(doc).get("document"))
    for k in ("category", "title"):
        if not (isinstance(dd.get(k), str) and dd[k].strip()):
            out.append(f"document.{k} is required")
    if dd.get("csaf_version") != "2.0":
        out.append("document.csaf_version must be 2.0")
    pub = d(dd.get("publisher"))
    if pub.get("category") not in ("coordinator", "discoverer", "other", "translator", "user", "vendor"):
        out.append("document.publisher.category is missing or not allowed")
    for k in ("name", "namespace"):
        if not (isinstance(pub.get(k), str) and pub[k].strip()):
            out.append(f"document.publisher.{k} is required")
    tr = d(dd.get("tracking"))
    for k in ("id", "version", "initial_release_date", "current_release_date"):
        if not (isinstance(tr.get(k), str) and tr[k].strip()):
            out.append(f"document.tracking.{k} is required")
    if tr.get("status") not in ("draft", "final", "interim"):
        out.append("document.tracking.status is missing or not allowed")
    rh = lst(tr.get("revision_history"))
    if not rh or not all(isinstance(x.get("date"), str) and isinstance(x.get("number"), str) and isinstance(x.get("summary"), str) for x in rh):
        out.append("document.tracking.revision_history needs entries with date, number and summary")
    return out + profile_problems(doc)


SCHEMA_NOT_RUN_NOTE = ("full schema validation NOT_RUN (jsonschema or the schema files are not available): only the built-in structural checks "
                       "were run (see builtin_checks); this is not a pass")


def schema_status(ran):
    """summary 的 schema_validation：沒跑時明寫 NOT_RUN（不是通過）。"""
    return {"ran": ran, "status": "OK" if ran else "NOT_RUN", "errors": []}


def validate_doc(doc):
    """→ (問題清單, 完整 schema 驗證有沒有跑)。問題清單＝schema 的錯誤（有跑時）＋內建檢查的問題（一定跑）。"""
    errs, v = [], schema_validator()
    if v is not None:
        errs += [f"schema {'/'.join(str(x) for x in e.path)}: {e.message[:200]}"
                 for e in sorted(v.iter_errors(doc), key=lambda e: [str(x) for x in e.path])[:20]]
    return errs + builtin_problems(doc), v is not None


def tbc_count(doc):
    """寫進文件的 TO BE COMPLETED（含網址佔位）數量。"""
    text = json.dumps(doc, ensure_ascii=False)
    return text.count(TBC) + text.count("to-be-completed.invalid")


def resolve_reports(path):
    """前一版：CRA/Reports 資料夾，或精靈的輸出資料夾（<資料夾>/cra-project/CRA/Reports），或專案資料夾（<資料夾>/CRA/Reports）。
    → Path（有 vex.cdx.json 的資料夾）；找不到 → InputError。不跟隨連結。"""
    p = Path(path)
    for c in (p, p / "CRA" / "Reports", p / "cra-project" / "CRA" / "Reports"):
        if c.is_dir() and not c.is_symlink() and (c / "vex.cdx.json").is_file():
            return c
    raise InputError(f"{path} 裡找不到 vex.cdx.json（要給 CRA/Reports、專案資料夾或精靈的輸出資料夾）")


# ---------------------------------------------------------------- 被利用漏洞的使用者通知草稿（CRA 第 14 條第 8 項）

EXPL_OUTPUTS = ("csaf-exploited-draft.json", "csaf-exploited-summary.json")
ROWS_FILE, ROWS_SCHEMA = "vulnerability-rows.json", "sca-center-vulnerability-rows/1"
# 報告列的 VEX 判定 → CSAF 產品狀態。沒有判定（None）＝還沒判斷（P1 未判）→ under_investigation；不認得的狀態也當成還沒判斷（不猜）
ROW_STATUS = {"exploitable": "known_affected", "in_triage": "under_investigation", "not_affected": "known_not_affected",
              "false_positive": "known_not_affected", "resolved": "fixed", "resolved_with_pedigree": "fixed"}
STATUS_RANK = {"known_affected": 0, "under_investigation": 1, "fixed": 2, "known_not_affected": 3}
STATUS_WORDS = {"known_affected": "affected", "under_investigation": "under investigation (not yet assessed)",
                "fixed": "fixed", "known_not_affected": "not affected"}
CVSS3 = re.compile(r"^CVSS:3\.[01]/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[HLN]/I:[HLN]/A:[HLN]$")
ID_OK = re.compile(r"^[A-Za-z][A-Za-z0-9]{0,15}-[A-Za-z0-9._:-]{1,80}$")
DATE_OK = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def clean(x, n=200):
    """外部資料進文件前：只收字串、去控制字元與 Unicode 格式字元（Cf：bidi、零寬）、截斷。"""
    if not isinstance(x, str):
        return ""
    # Cc（控制字元）、Zl／Zp（行／段落分隔）換成空白；Cf（格式字元：bidi 的 U+202E、零寬字元等）直接移除
    s = "".join(" " if unicodedata.category(ch) in ("Cc", "Zl", "Zp") else "" if unicodedata.category(ch) == "Cf" else ch for ch in x)
    return " ".join(s.split())[:n]


def _roundup31(x):
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (i // 10000 + 1) / 10.0


def cvss3_base(vec):
    """CVSS v3.0／v3.1 基本分數（由向量重算）；向量不是完整的 8 個基本指標 → None。"""
    if not (isinstance(vec, str) and CVSS3.match(vec)):
        return None
    m = dict(x.split(":") for x in vec.split("/")[1:])
    ch = m["S"] == "C"
    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
    ac = {"L": 0.77, "H": 0.44}[m["AC"]]
    pr = {"N": 0.85, "L": 0.68 if ch else 0.62, "H": 0.5 if ch else 0.27}[m["PR"]]
    ui = {"N": 0.85, "R": 0.62}[m["UI"]]
    w = {"H": 0.56, "L": 0.22, "N": 0.0}
    iss = 1 - (1 - w[m["C"]]) * (1 - w[m["I"]]) * (1 - w[m["A"]])
    imp = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if ch else 6.42 * iss
    if imp <= 0:
        return 0.0
    ex = 8.22 * av * ac * pr * ui
    raw = min(1.08 * (imp + ex), 10) if ch else min(imp + ex, 10)
    return _roundup31(raw) if vec.startswith("CVSS:3.1") else math.ceil(raw * 10 - 1e-9) / 10.0


def severity_of(score):
    return "NONE" if score == 0 else "LOW" if score < 4 else "MEDIUM" if score < 7 else "HIGH" if score < 9 else "CRITICAL"


def read_rows_doc(reports):
    p = Path(reports) / ROWS_FILE
    if p.is_symlink():
        raise InputError(f"{p} 是符號連結，不讀")
    doc, sha = read_json(p, "報告")
    if not isinstance(doc, dict) or doc.get("schema") != ROWS_SCHEMA or not isinstance(doc.get("rows"), list):
        raise InputError(f"報告：{p} 不是 {ROWS_SCHEMA} 格式")
    return doc, sha


def bounded_xz(raw, limit=None):
    """.xz 解壓，分段讀；解出來超過 limit 就停（ValueError），不把壓縮炸彈整個展開。"""
    limit = limit or MAX_INPUT
    dec, out, total, data = lzma.LZMADecompressor(), [], 0, raw
    while data or not dec.eof:
        chunk = dec.decompress(data, max_length=1 << 20)
        total += len(chunk)
        if total > limit:
            raise ValueError("decompressed size over the limit")
        out.append(chunk)
        data = b"" if not dec.needs_input else b""
        if dec.eof or (not chunk and dec.needs_input):
            break
    return b"".join(out)


def load_kev_dates(reports, euvd_file=None):
    """掃描輸出已經有的 KEV 日期：scan/euvd.json 的 kev_date_added（euvd_file 明確指定，或 Reports/summary.json 的 scan_dir 底下的 scan/euvd.json）。
    不連網，不讀其他檔。→ ({CVE: {"date": YYYY-MM-DD, "sources": [...]}}, {"file": 檔名, "sha256": …} 或 None, 說明或 None)。"""
    cands = [Path(euvd_file)] if euvd_file else []
    if not cands:
        try:
            sj, _ = read_json(Path(reports) / "summary.json", "summary", required=False)
            sd = d(sj).get("scan_dir")
        except InputError:
            sd = None
        if isinstance(sd, str) and sd:
            cands = [Path(sd) / "scan" / "euvd.json", Path(sd) / "scan" / "euvd.json.xz"]
    p = next((c for c in cands if c.is_file() and not c.is_symlink() and c.stat().st_size <= MAX_INPUT), None)
    if p is None:
        return {}, None, "no KEV/EUVD dates: the scan output's scan/euvd.json was not found (only the sources are stated)"
    try:
        raw = p.read_bytes()
        doc = json.loads((bounded_xz(raw) if p.suffix == ".xz" else raw).decode("utf-8"))
    except (OSError, ValueError, RecursionError, lzma.LZMAError):
        return {}, None, f"no KEV/EUVD dates: {p.name} could not be read"
    out = {}
    for cve, x in (d(doc).get("cves") or {}).items() if isinstance(d(doc).get("cves"), dict) else ():
        x = d(x)
        dt = x.get("kev_date_added")
        if isinstance(cve, str) and CVE.match(cve.upper()) and str(x.get("exploited")).lower() == "yes" and isinstance(dt, str) and DATE_OK.match(dt):
            out[cve.upper()] = {"date": dt, "sources": [z for z in x.get("kev_sources") or [] if isinstance(z, str) and re.fullmatch(r"[a-z0-9_]{1,30}", z)]}
    return out, {"file": p.name, "sha256": hashlib.sha256(raw).hexdigest()}, None


def statement_index(vex):
    """vex.cdx.json → {(CVE, purl 去版本): {"response": [...], "action": 文字}}；只用來取人寫的緩解措施。格式不對 → 空。"""
    out = {}
    if not isinstance(vex, dict):
        return out
    for v in lst(vex.get("vulnerabilities")):
        pp = props(v)
        purl = pp.get("sca-center:component-purl")
        a = d(v.get("analysis"))
        if isinstance(v.get("id"), str) and isinstance(purl, str):
            out[(v["id"].upper(), purl_base(purl))] = {"response": [x for x in a.get("response") or [] if isinstance(x, str)]
                                                       if isinstance(a.get("response"), list) else [],
                                                       "action": pp.get("openvex:action_statement") if isinstance(pp.get("openvex:action_statement"), str) else ""}
    return out


def product_identity(vex, sbom, cfg):
    """產品名稱與版本：VEX → SBOM → 設定檔（product.name、product.version）的順序；都沒有 → None（文件寫 TO BE COMPLETED）。"""
    for doc in (vex, sbom):
        c = d(d(d(doc).get("metadata")).get("component"))
        if clean(c.get("name")):
            return clean(c.get("name")), clean(c.get("version")) or None
    pr = d(d(cfg).get("product"))
    return clean(pr.get("name")) or None, clean(pr.get("version")) or None


def product_key(x):
    """產品名稱／版本 → (基底, 括號後綴序列)：基底小寫、去掉開頭的 v、空白 - _ 視為相同；後綴＝所有 "(…)"（小寫、去頭尾空白）依序。"""
    raw = str(x or "")
    suffixes = tuple(m.strip().lower() for m in re.findall(r"\(([^()]*)\)", raw))
    base = re.sub(r"\s*\([^()]*\)", "", raw).strip().lower()
    return re.sub(r"[\s_-]+", " ", re.sub(r"^v(?=\d)", "", base)).strip(), suffixes


def same_product_text(a, b):
    """兩個名稱（或版本）是不是同一個：基底相同，而且（只要有一邊完全沒有括號後綴就忽略後綴；兩邊都有時，後綴序列要完全相同）。
    "V1.0 (rootfs)" 對 "V1.0" 是同一個；"V1.0 (rootfs)" 對 "V1.0 (uefi)"、"(rootfs)(gui)" 對 "(rootfs)" 不是（同版號、不同產品）。"""
    (ba, sa), (bb, sb) = product_key(a), product_key(b)
    return bool(ba) and ba == bb and (not sa or not sb or sa == sb)


def exploited_run(reports, cves, cfg, out, now=None, detected=None, euvd_file=None, evidence=None, assume_exploited=None, expect_product=None):
    """→ (狀態, 說明, summary dict 或 None)。reports：CRA/Reports（要有 vulnerability-rows.json）；cves：要通知的 CVE 清單；
    detected：選用，{CVE: 工具第一次偵測時間（UTC）}，只記在 summary（內部），不進公告。
    evidence：選用，{CVE: {"sources": [來源字串], "date": YYYY-MM-DD 或 None}}：呼叫端（每日監控）手上的被利用證據；報告列還沒有證據（掃描早於 KEV 收錄）時也算證據。
    assume_exploited：選用，一段證據說明（例如廠商公告已被利用、報告還沒更新）：報告與 evidence 都沒有證據的 CVE 才會產生草稿，說明寫進 threats 與 notes。
    **關卡**：CVE 在報告裡沒有任何被利用證據（KEV、EUVD、Grype knownExploited、人工證據）、也沒有 evidence／assume_exploited → 不產生草稿，狀態 GAP。
    expect_product：選用，(名稱, 版本)：報告的產品（VEX／SBOM／設定檔）要和它相同（same_product_text），不同或看不出來 → FAIL。
    euvd_file：選用，掃描輸出的 scan/euvd.json（KEV 日期來源）；不給＝照 Reports/summary.json 的 scan_dir 找，找不到就只寫來源、不寫日期（不連網）。FAIL 時不寫任何檔（並刪掉上一次的輸出）。"""
    now = now or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    reports, out = Path(reports), Path(out)
    ids = []
    for c in cves or []:
        c = str(c).strip().upper()
        if not CVE.match(c):
            return "FAIL", f"不是 CVE 編號：{clean(c, 40)!r}", None
        if c not in ids:
            ids.append(c)
    if not ids:
        return "FAIL", "沒有指定 CVE", None

    def fail(msg):
        try:
            write(out, {}, EXPL_OUTPUTS)
        except OSError as w:
            return "FAIL", f"{msg}；清除上一次的輸出也失敗（{w}）", None
        return "FAIL", f"{msg}；沒有產生草稿", None
    try:
        rdoc, rsha = read_rows_doc(reports)
        vex, vsha = read_json(reports / "vex.cdx.json", "VEX", required=False)
        sbom, bsha = read_json(reports / "sbom.cdx.json", "SBOM", required=False)
    except InputError as e:
        return fail(str(e))
    pname, pver = product_identity(vex, sbom, cfg)
    if expect_product is not None:
        en, ev = expect_product
        if not (pname and pver) or not same_product_text(pname, en) or not same_product_text(pver, ev):
            return fail(f"報告的產品（{pname or '?'} {pver or '?'}）和要通知的版本（{clean(en, 80)} {clean(ev, 80)}）不符或看不出來")
    miss = []
    if not pname:
        miss.append("product.name")
    if not pver:
        miss.append("product.version")
    pname_, pver_ = pname or TBC, pver or TBC
    prod_name = f"{pname_} {pver_}"
    pub, ns, pre, contact, cmiss = company(cfg)
    miss = cmiss + miss
    stmts = statement_index(vex)
    warnings, notes = [], []
    kev, kev_file, kev_note = load_kev_dates(reports, euvd_file)
    if kev_note:
        notes.append(kev_note)
    rows = [r for r in rdoc["rows"] if isinstance(r, dict)]
    by_cve = {}
    for c in ids:
        sel = [r for r in rows if isinstance(r.get("id"), str) and (r["id"].upper() == c or
               c in {str(a).upper() for a in r.get("aliases") or [] if isinstance(a, str)})]
        if sel:
            by_cve[c] = sel
        else:
            warnings.append(f"{c}：這份報告沒有這個 CVE 的列，草稿不含它（沒找到不等於 not_affected；請確認 CVE 編號與版本）")
    if not by_cve:
        return fail("; ".join(warnings))

    # 關卡：報告沒有被利用證據的 CVE 不產生草稿（除非明確 --assume-exploited）。沒有證據不代表沒有被利用，要不要通知由人判斷（dumpling 改寫）
    assume = clean(assume_exploited, 300)
    ev_of, no_ev, assumed = {}, [], set()
    for c in list(by_cve):
        evid, dates = [], []
        for r in by_cve[c]:
            evid += [clean(x, 120) for x in r.get("exploitation_evidence") or [] if isinstance(x, str) and clean(x, 120)]
            for e in lst(r.get("exploited_evidence")):
                ok = isinstance(e.get("date"), str) and DATE_OK.match(e["date"])
                if ok:
                    dates.append(e["date"])
                evid.append(" ".join(x for x in (clean(e.get("source"), 60), e["date"] if ok else "") if x))
        if c in kev:
            evid.append("EUVD: listed in " + (", ".join(kev[c]["sources"]) or "a KEV catalogue") + f", added {kev[c]['date']}")
            dates.append(kev[c]["date"])
        hk = d((evidence or {}).get(c))
        srcs = [clean(x, 120) for x in hk.get("sources") or [] if isinstance(x, str) and clean(x, 120)] if isinstance(hk.get("sources"), list) else []
        if srcs:
            evid.append("Matched by the supplier's exploited-vulnerability monitoring: " + ", ".join(srcs[:6]))
        if isinstance(hk.get("date"), str) and DATE_OK.match(hk["date"]):
            dates.append(hk["date"])
            evid.append(f"listed in a KEV catalogue (date added {hk['date']})")
        evid = sorted({x for x in evid if x})[:10]
        if not evid and assume:
            evid = [f"Assumed to be actively exploited by the supplier; no exploitation evidence in the scan report. Supplier's statement: {assume}"]
            assumed.add(c)
            warnings.append(f"{c}：報告沒有被利用的證據，依 --assume-exploited 產生；證據說明：{assume}")
        if not evid:
            no_ev.append(c)
            del by_cve[c]
            warnings.append(f"{c}：報告裡沒有這個 CVE 被利用的證據，這次沒有產生使用者通知草稿；這不代表這個 CVE 沒有被利用，是否需要第 14(8) 條的通知由人判斷（若有報告以外的證據，例如廠商公告，請用 --assume-exploited \"<證據說明>\"）")
        else:
            ev_of[c] = (evid, dates)
    if not by_cve:
        try:
            write(out, {}, EXPL_OUTPUTS)
        except OSError:
            pass
        return "GAP", "；".join(warnings), None

    fpn = [{"product_id": "CSAFPID-PROD", "name": prod_name}]
    comps, rels, relmap = {}, [], {}

    def rel(label, purl):
        k = (label, full_purl(purl) if purl else "")
        if k not in relmap:
            cid = f"CSAFPID-C{len(comps) + 1:04d}"
            comps[k] = cid
            e = {"product_id": cid, "name": label}
            if purl and PURL_OK.match(purl) and not re.search(r"\s", purl):
                e["product_identification_helper"] = {"purl": purl}
            fpn.append(e)
            rid = f"CSAFPID-R{len(relmap) + 1:04d}"
            relmap[k] = rid
            rels.append({"category": "default_component_of", "product_reference": cid, "relates_to_product_reference": "CSAFPID-PROD",
                         "full_product_name": {"product_id": rid, "name": f"{label} as part of {prod_name}"}})
        return relmap[k]

    vulns, summ_cves = [], {}
    for c, sel in by_cve.items():
        info = {}                                            # 關係產品 ID → {"status", "row", "label"}
        unknown_states = set()
        evid, dates = ev_of[c]
        for r in sel:
            label = " ".join(x for x in (clean(r.get("component")) or "?", clean(r.get("version"))) if x)
            purl = clean(r.get("purl"), 300)
            rid = rel(label, purl)
            vx = d(r.get("vex"))
            state = vx.get("state") if isinstance(vx.get("state"), str) else None
            if state is not None and state not in ROW_STATUS:
                unknown_states.add(clean(state, 40))
            st = ROW_STATUS.get(state, "under_investigation")
            if rid not in info or STATUS_RANK[st] < STATUS_RANK[info[rid]["status"]]:
                info[rid] = {"status": st, "row": r, "label": label, "purl": purl}
        if unknown_states:
            warnings.append(f"{c}：判定狀態不認得（{', '.join(sorted(unknown_states))}），當成還沒判斷（under_investigation）")
        ps = {}
        for rid, i in info.items():
            ps.setdefault(i["status"], []).append(rid)
        closed = [rid for rid, i in info.items() if i["status"] in ("known_not_affected", "fixed")]
        if closed and len(closed) == len(info):
            kinds = sorted({STATUS_WORDS[info[x]["status"]] for x in closed})
            warnings.append(f"{c}：這個版本的判定全部是「{'、'.join(kinds)}」；可能不需要通知使用者（草稿仍已產生，請 RD／PM 確認是否真的要發）")
        elif closed:
            warnings.append(f"{c}：部分元件已判定為 not_affected 或已修補（{len(closed)} 個），草稿只把它們標成該狀態；請確認通知內容")
        v = {"cve": c}
        extra = sorted({clean(x, 90) for r in sel for x in [r.get("id")] + list(r.get("aliases") or [])
                        if isinstance(x, str) and ID_OK.match(clean(x, 90)) and clean(x, 90).upper() != c})[:10]
        if extra:
            v["ids"] = [{"system_name": x.split("-", 1)[0].upper(), "text": x} for x in extra]
        lines = []
        for rid, i in sorted(info.items()):
            line = f"{i['label']}: {STATUS_WORDS[i['status']]} in {prod_name}"
            r = i["row"]
            fx = clean(r.get("fix_next"), 80)
            if i["status"] in ("known_affected", "under_investigation") and r.get("fix_state") == "fixed" and fx:
                line += f"; the upstream project or distribution has a fixed version ({fx}) that is not included in this product version"
            lines.append(line + ".")
        v["notes"] = [{"category": "summary", "title": "Status in this product version",
                       "text": f"{c} is reported as actively exploited. " + " ".join(lines)}]
        v["product_status"] = {k: sorted(x) for k, x in sorted(ps.items())}
        # 分數：只收完整的 CVSS v3 向量；其他不寫（不猜）
        scores = {}
        for rid, i in info.items():
            cv = d(i["row"].get("cvss"))
            sc, vec = cv.get("score"), cv.get("vector")
            if isinstance(sc, (int, float)) and not isinstance(sc, bool) and 0 <= sc <= 10 and isinstance(vec, str) and CVSS3.match(vec):
                calc = cvss3_base(vec)
                if calc is not None and abs(calc - float(sc)) < 0.05:       # 記錄的分數要和向量重算的一致，否則不寫（不猜哪個對）
                    scores.setdefault((vec, float(sc)), []).append(rid)
                else:
                    notes.append(f"{c}: the recorded CVSS score {sc} does not match the vector {vec} (calculated {calc}); scores not written")
        if scores:
            v["scores"] = [{"products": sorted(p), "cvss_v3": {"version": vec[5:8], "vectorString": vec, "baseScore": sc, "baseSeverity": severity_of(sc)}}
                           for (vec, sc), p in sorted(scores.items())]
        open_ids = sorted(rid for rid, i in info.items() if i["status"] in ("known_affected", "under_investigation"))
        rem = []
        todo, fixnotes = [], []
        for rid in open_ids:
            i = info[rid]
            r = i["row"]
            stm = stmts.get((c, purl_base(i["purl"]))) if i["purl"] else None
            if stm and "workaround_available" in stm["response"] and clean(stm["action"], 600):
                rem.append({"category": "workaround", "product_ids": [rid], "details": clean(stm["action"], 600)})
            else:
                todo.append(rid)
            fx = clean(r.get("fix_next"), 80)
            if r.get("fix_state") == "fixed" and fx:
                # 上游有修補版本不等於這個產品已修補：不用 vendor_fix（機器讀者會當成有修補可用），用 none_available 並明寫尚未提供
                txt = (f"An upstream fix is available for {i['label']} (version {fx}); a fixed version of this product has not been released. "
                       f"Whether and when one is planned: {TBC} by RD.")
                rem.append({"category": "none_available", "product_ids": [rid], "details": txt})
                fixnotes.append(txt)
        if todo:
            rem.insert(0, {"category": "mitigation", "product_ids": todo,
                           "details": f"{TBC} by RD: describe the mitigation users can apply now (for example disable or restrict the affected service, "
                                      "limit network access), or state that no mitigation is known."})
        # 只有這一版判定 resolved 的元件才用 vendor_fix
        resolved = sorted(rid for rid, i in info.items() if i["status"] == "fixed")
        if resolved:
            rem.append({"category": "vendor_fix", "product_ids": resolved, "details": f"Fixed in {prod_name} (assessed as resolved for this product version)."})
        if fixnotes:
            v["notes"].append({"category": "details", "title": "Fix status", "text": " ".join(fixnotes)})
        if rem:
            v["remediations"] = rem
        threats = []
        evtext = ("Exploitation evidence: " + "; ".join(evid) + ".")
        t = {"category": "exploit_status", "details": evtext, "product_ids": sorted(info)}
        if dates:
            t["date"] = min(dates) + "T00:00:00Z"
        threats.append(t)
        for rid in sorted(closed):
            if info[rid]["status"] == "known_not_affected":
                dv = d(info[rid]["row"].get("vex"))
                why = " ".join(x for x in (dv.get("justification") and f"Justification: {clean(dv['justification'], 80)}.", clean(dv.get("detail"), 400)) if x)
                threats.append({"category": "impact", "details": why or "Assessed as not affected.", "product_ids": [rid]})
        v["threats"] = threats
        if c in assumed:
            v["notes"].append({"category": "details", "title": "Exploitation status (supplier's statement)", "text": evid[0]})
        vulns.append(v)
        summ_cves[c] = {"rows": len(sel), "status": {k: len(x) for k, x in sorted(ps.items())}, "exploitation_evidence": evid,
                        "first_detected_by_tool": (detected or {}).get(c)}

    cs_ids = ", ".join(by_cve)
    vstatus = clean(rdoc.get("vulnerability_data_status"), 40)
    incomplete = bool(vstatus) and vstatus != "OK"
    tid = f"{pre}{slug(pname_)}-{slug(pver_)}-EXPL-{now[:10].replace('-', '')}"
    refs, dist, xmiss = advisory_extras(cfg, tid)
    miss += xmiss
    pubobj = {"category": "vendor", "name": pub, "namespace": ns}
    if contact:
        pubobj["contact_details"] = contact
    dnotes = [{"category": "summary", "title": "Summary",
               "text": f"Notification to users of {prod_name}: the following vulnerabilities are reported as actively exploited: {cs_ids}. "
                       "The status and the remediation below are a draft until the supplier has reviewed and completed them."},
              {"category": "general", "title": "Scope",
               "text": "Generated from the supplier's vulnerability scan report of this product version; only the listed vulnerabilities are covered. "
                       "A vulnerability that is not listed is not thereby confirmed to be absent."}]
    if incomplete:
        dnotes.append({"category": "general", "title": "Incomplete vulnerability data",
                       "text": f"The vulnerability data of the source report is incomplete (status {vstatus}); other vulnerabilities may exist that this notification does not cover."})
    dnotes.append({"category": "legal_disclaimer", "title": "Status",
                   "text": "Draft generated from the supplier's scan report; to be reviewed and completed by the supplier before any publication."})
    doc = {"document": {"category": "csaf_security_advisory", "csaf_version": "2.0", "lang": "en",
                        "title": f"{prod_name}: actively exploited vulnerabilities ({cs_ids})", "publisher": pubobj,
                        "references": refs, **({"distribution": dist} if dist else {}), "notes": dnotes,
                        "tracking": {"id": tid, "status": "draft", "version": "0", "initial_release_date": now, "current_release_date": now,
                                     "revision_history": [{"date": now, "number": "0", "summary": "Draft generated by dumpling csaf_advisory.py exploited"}],
                                     "generator": {"engine": {"name": "dumpling csaf_advisory.py exploited"}, "date": now}}},
           "product_tree": {"full_product_names": fpn, "relationships": rels}, "vulnerabilities": vulns}
    errs, ran = validate_doc(doc)
    if errs:
        return fail("產生的草稿不符合 CSAF 2.0 schema 或 security_advisory 設定檔（程式問題）：" + "；".join(errs[:5]))
    if not ran:
        notes.append(SCHEMA_NOT_RUN_NOTE)
    ntbc = tbc_count(doc)
    if ntbc:
        notes.append(f"{ntbc} TO BE COMPLETED placeholder(s) remain in the draft")
    if incomplete:
        notes.append(f"the vulnerability data of the source report is incomplete (status {vstatus})")
    status = "ATTENTION" if (miss or notes or warnings or ntbc) else "OK"
    summ = {"tool": "csaf_advisory exploited", "generated": now, "status": status, "product": {"name": pname, "version": pver},
            "cves": summ_cves, "missing_fields": miss, "warnings": warnings, "notes": notes, "tbc_count": ntbc,
            "schema_validation": schema_status(ran),
            "builtin_checks": {"ran": True, "problems": [], "covers": list(BUILTIN_COVERS)}, "report_data_status": vstatus or None,
            "kev_dates_from": kev_file, "assumed_exploited": {c: assume for c in sorted(assumed)}, "no_evidence_excluded": no_ev, "inputs": {ROWS_FILE: {"sha256": rsha}, "vex.cdx.json": {"sha256": vsha}, "sbom.cdx.json": {"sha256": bsha}}}
    try:
        write(out, {EXPL_OUTPUTS[0]: json.dumps(doc, ensure_ascii=False, indent=1) + "\n",
                    EXPL_OUTPUTS[1]: json.dumps(summ, ensure_ascii=False, indent=1) + "\n"}, EXPL_OUTPUTS)
    except OSError as e:
        return "FAIL", f"寫不進 {out}（{type(e).__name__}）", None
    detail = f"{len(by_cve)} 個 CVE、{len(rels)} 個元件" + (f"；缺 {', '.join(miss)}" if miss else "") + "；" + "；".join(warnings + notes)
    return status, detail.rstrip("；"), summ


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        print(f"參數錯誤：{message}", file=sys.stderr)
        sys.exit(64)


def main_exploited(argv):
    ap = Parser(prog="csaf_advisory.py exploited", description="被積極利用的漏洞 → CSAF 2.0 使用者通知草稿（CRA 第 14 條第 8 項；草稿，不發布）")
    ap.add_argument("--report", required=True, help="這個產品版本的 CRA/Reports 資料夾（有 vulnerability-rows.json）")
    ap.add_argument("--cve", required=True, action="append", help="要通知的 CVE（可重複）")
    ap.add_argument("--config", help="產品設定 config.json（發布者資料：csaf.*、manufacturer.*）；沒給＝發布者欄位都是 TO BE COMPLETED")
    ap.add_argument("--assume-exploited", metavar="證據說明", help="報告沒有被利用證據的 CVE 預設不產生草稿（這不代表沒有被利用；是否需要第 14(8) 條的通知由人判斷）；"
                    "有報告以外的證據（例如廠商公告已被利用、報告還沒更新）時加這個，說明會寫進 threats 與 notes")
    ap.add_argument("--euvd", help="（選用）掃描輸出的 scan/euvd.json（KEV 日期來源）；不給＝照 Reports/summary.json 的 scan_dir 找，找不到就不寫日期")
    ap.add_argument("--out", required=True, help="輸出資料夾")
    a = ap.parse_args(argv)
    if not Path(a.report).is_dir():
        ap.error(f"--report 要是資料夾：{a.report}")
    cfg = {}
    if a.config:
        try:
            cfg = json.loads(Path(a.config).read_text(encoding="utf-8"))
        except (OSError, ValueError, RecursionError) as e:
            print(f"CSAF-EXPLOITED\tFAIL\t讀不到設定 {a.config}（{type(e).__name__}）")
            return 1
    status, detail, summ = exploited_run(Path(a.report), a.cve, cfg if isinstance(cfg, dict) else {}, Path(a.out), euvd_file=a.euvd, assume_exploited=a.assume_exploited)
    for w in (summ or {}).get("warnings", []):
        print(f"WARNING：{w}", file=sys.stderr)
    print(f"CSAF-EXPLOITED\t{status}\t{detail}")
    return {"OK": 0, "FAIL": 1, "GAP": 3}.get(status, 2)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "exploited":
        return main_exploited(argv[1:])
    if argv and argv[0] == "fix":
        argv = argv[1:]
    ap = Parser(description="兩版 CRA 文件的 VEX 比對 → CSAF 2.0 修補公告（草稿）。另有子指令 exploited：被積極利用漏洞的使用者通知草稿")
    ap.add_argument("--old", required=True, help="舊版的 CRA/Reports 資料夾")
    ap.add_argument("--new", required=True, help="新版的 CRA/Reports 資料夾")
    ap.add_argument("--config", required=True, help="新版的產品設定 config.json（發布者欄位：csaf.*、manufacturer.*）")
    ap.add_argument("--out", required=True, help="輸出資料夾")
    a = ap.parse_args(argv)
    for opt, v in (("--old", a.old), ("--new", a.new)):
        if not Path(v).is_dir():
            ap.error(f"{opt} 要是資料夾：{v}")
    try:
        cfg = json.loads(Path(a.config).read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as e:
        print(f"CSAF\tFAIL\t讀不到設定 {a.config}（{type(e).__name__}）")
        return 1
    status, detail, _ = run(Path(a.old), Path(a.new), cfg if isinstance(cfg, dict) else {}, Path(a.out))
    print(f"CSAF\t{status}\t{detail}")
    return {"OK": 0, "FAIL": 1}.get(status, 2)


if __name__ == "__main__":
    sys.exit(main())
