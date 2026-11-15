#!/usr/bin/env python3
"""dt_writeback.py：把我們自己的分析寫回 Dependency-Track（選用；預設不做）。

兩件事（--product-components、--vex，可同時；都不給就什麼都不做）：
  1. --product-components：產品 SBOM 裡 rootfs 以外的元件（刷機包韌體、UEFI 內建函式庫、產品自有軟體；cra_report 併進去的）
     上傳到另一個 DT 專案「<名稱> / <版本 (rootfs) 換成 (product components)>」。rootfs 專案完全不動（見 README「寫回 DT」的取捨）。
  2. --vex：把 CRA/Reports/vex.cdx.json（CycloneDX VEX）轉成 DT 對得上的 VEX，PUT/POST /api/v1/vex，
     讓 DT 的 finding 帶我們的 analysis（state、justification、response、detail）。

DT 5.2 實測（TEST 專案，2026-11-11）的 VEX 匹配規則，不能用文件推測：
  - affects[].ref 只有 `urn:cdx:<上傳那份 BOM 的 serialNumber>/<BOM version>#<那個元件的 bom-ref>` 對得上；
    DT 元件的 UUID（大小寫都試過）、單獨的 bom-ref 都不會套用，而且 workflow 仍回 COMPLETED、沒有任何錯誤。
    所以「VEX 上傳成功」「處理完成」都不代表分析被套用，一定要讀回 finding 確認（D-dt-vex-applied）。
  - 漏洞用 (source, id) 找：source 是 DT 自己記的來源（NVD、OSV、GITHUB…），id 是 DT 的 vulnId（Ubuntu 的是 UBUNTU-CVE-…），
    不是我們 VEX 合併後的 CVE 編號。我們的 VEX 每列的 `sca-center:source-ids`（來源:編號）正是那列併進去的 DT finding，
    所以以它對回 DT finding；沒有對到時才用 finding 的 aliases（記為 alias 比對）。
  - 回應的 token 是 import-vex workflow 的 run id：GET /api/v2/internal/workflow-runs/<token>（需 SYSTEM_CONFIGURATION(_READ)）。

安全規則：
  - 不覆蓋人在 DT 已經做的分析：finding 有 analysis state（NOT_SET 與空白算沒有）、而 detail 不是我們寫的、沒被改過的 → 略過並計數（ATTENTION）。
  - 寫回的 detail 一律以 `[sca-center:vex-writeback state=<狀態> sha=<內容雜湊>]` 開頭；標記的狀態等於 DT 現在的狀態、內容雜湊對得上才算「我們的」；cra_report.py 讀 DT 的 analysis 時看到標記就不當成人工判定
    （否則規則判的 not_affected 下次掃描會被當成 DT 上的人工決定，自己證明自己）。
  - 帶 dumpling:assessment＝NOT_ASSESSED 的陳述（沒有評估的列，vex.cdx.json 以 in_triage 輸出；M7c-1）不是判定，一律略過、不寫回；
    否則 DT 裡所有沒判定的 finding 都會被改成 IN_TRIAGE。略過的數量記在 dt-writeback.json 的 vex.not_assessed_skipped。
  - 同一個 DT finding 有多條不同狀態的陳述 → 取最保守的（exploitable > in_triage > resolved > not_affected）並計入 conflicts。
  - API key 只從環境（DT_API_KEY）或 --env 檔的 DT_API_KEY 讀，不印、不寫進輸出。
  - 規則 13：產品元件上傳到 DT 前，版本不是真版本的（file modification time、cdx:*:versionSpecifiers）移除版本，不猜。

輸出（--out 資料夾）：dt-writeback.json（計數與沒對上的清單）、dt-vex.cdx.json（實際送出的 VEX）、product-components.cdx.json（實際上傳的 SBOM）。
標準輸出：每行 `階段<TAB>狀態<TAB>說明`（OK、ATTENTION、GAP、NOT_RUN、FAIL）。上傳成功、處理完成、分析被套用各自一列，不合併。
退出碼：0 完成（含 ATTENTION、GAP）；1 有 FAIL；64 用法錯誤。
"""
import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
MARKER_PREFIX = "[sca-center:vex-writeback "
MARKER_RE = re.compile(r"^\[sca-center:vex-writeback state=([a-z_]+) sha=([0-9a-f]{12})\]")
CLOSED = {"not_affected", "false_positive", "resolved", "resolved_with_pedigree"}   # 在 DT 會變成 suppressed 的一族
PRODUCT_SUFFIX = "(product components)"
PRODUCT_TAG = "sca-center-product-components"
# 產品 SBOM 裡不是 rootfs 的元件：bom-ref 前綴（firmware_bom.REF、own_software.REF、uefi_source 的 uefi-source:）
EXTRA_REF_PREFIXES = ("sca-center:flash:", "sca-center:own:", "uefi-source:")
STATE_RANK = {"exploitable": 0, "in_triage": 1, "resolved": 2, "resolved_with_pedigree": 2, "false_positive": 3, "not_affected": 3}
JUSTIFICATIONS = {"code_not_present", "code_not_reachable", "requires_configuration", "requires_dependency", "requires_environment",
                  "protected_by_compiler", "protected_at_runtime", "protected_at_perimeter", "protected_by_mitigating_control"}
NON_DT_SOURCES = {"GRYPE", "NVIDIA"}
PAGE = 500
# 沒有評估的陳述（M7c-1，A4／D-057）：vex.cdx.json 把沒有判定的列寫成 in_triage 加這個屬性。那不是判定，不寫回 DT，
# 否則 DT 裡所有沒判定的 finding 都會被改成 IN_TRIAGE。與 tools/vexconv/vexconv.py 的 PROP_ASSESSMENT／NOT_ASSESSED 同值（測試核對）
NOT_ASSESSED_PROP, NOT_ASSESSED_VALUE = "dumpling:assessment", "NOT_ASSESSED"


class WbError(Exception):
    pass


def _load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


# ---------- DT 用戶端（測試換成假的） ----------

class Dt:
    def __init__(self, url, key, timeout=120):
        url = url.rstrip("/")
        self.url = url[:-4] if url.endswith("/api") else url
        self._key = key
        self.timeout = timeout

    def request(self, method, path, body=None, ctype=None, extra=None):
        h = {"X-Api-Key": self._key}
        if ctype:
            h["Content-Type"] = ctype
        req = urllib.request.Request(self.url + path, data=body, method=method, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                raw = r.read()
                return r.status, dict(r.headers), raw
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()[:500]
        except (urllib.error.URLError, OSError) as e:
            return 0, {}, type(e).__name__.encode()

    def json(self, method, path, obj=None):
        st, h, raw = self.request(method, path, None if obj is None else json.dumps(obj).encode(), "application/json" if obj is not None else None)
        try:
            return st, h, json.loads(raw) if raw else None
        except ValueError:
            return st, h, None

    def upload(self, path, fields, field, filename, data):
        bd = "----sca" + uuid.uuid4().hex
        b = b""
        for k, v in fields.items():
            b += f'--{bd}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode()
        b += f'--{bd}\r\nContent-Disposition: form-data; name="{field}"; filename="{filename}"\r\nContent-Type: application/json\r\n\r\n'.encode()
        b += data + f"\r\n--{bd}--\r\n".encode()
        st, h, raw = self.request("POST", path, b, f"multipart/form-data; boundary={bd}")
        try:
            return st, json.loads(raw) if raw else None
        except ValueError:
            return st, None

    def pages(self, path):
        """分頁讀取；回 (清單, 錯誤或 None)。筆數與 X-Total-Count 不同也算錯誤（不當作完整）。"""
        out, n, sep = [], 1, "&" if "?" in path else "?"
        while True:
            st, h, d = self.json("GET", f"{path}{sep}pageSize={PAGE}&pageNumber={n}")
            if st != 200 or not isinstance(d, list):
                return out, f"HTTP {st}"
            out += d
            tot = {k.lower(): v for k, v in h.items()}.get("x-total-count")
            try:
                tot = int(tot)
            except (TypeError, ValueError):
                return out, "X-Total-Count missing"
            if len(out) >= tot or not d:
                return out, None if len(out) == tot else f"X-Total-Count={tot} but got {len(out)}"
            n += 1


def read_env_file(path):
    """KEY=VALUE（不 source、不執行）；只回 DT_URL、DT_API_KEY。"""
    out = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        m = re.match(r"^(DT_URL|DT_API_KEY)=(.*)$", line.strip())
        if m:
            out[m.group(1)] = m.group(2).strip().strip("'\"")
    return out


# ---------- 元件與 purl ----------

def comp_key(c):
    """元件比對鍵：purl 完整字串；沒有 purl 用 (名稱, 版本)。"""
    p = c.get("purl")
    if isinstance(p, str) and p:
        return ("purl", p)
    return ("nv", c.get("name") or "", c.get("version") or "")


def ref_tail(ref):
    return ref.split("#", 1)[1] if isinstance(ref, str) and "#" in ref else ref


def bomref_urn(serial, version, bomref):
    return f"urn:cdx:{str(serial).removeprefix('urn:uuid:')}/{version}#{bomref}"


def prop(c, name):
    return [p.get("value") for p in c.get("properties") or [] if isinstance(p, dict) and p.get("name") == name]


# ---------- 產品元件（項目 2） ----------

def is_extra(c):
    r = c.get("bom-ref")
    return isinstance(r, str) and r.startswith(EXTRA_REF_PREFIXES)


def product_extras(product_sbom, rootfs_sbom=None):
    """產品 SBOM 裡的非 rootfs 元件（依 bom-ref 前綴）。回 (元件清單, 與 rootfs 上傳 SBOM 重複而略過的數量)。"""
    have = set()
    for c in (rootfs_sbom or {}).get("components") or []:
        if isinstance(c, dict) and c.get("purl"):
            have.add(c["purl"])
    out, dup = [], 0
    for c in product_sbom.get("components") or []:
        if not isinstance(c, dict) or not is_extra(c):
            continue
        if c.get("purl") and c["purl"] in have:
            dup += 1
            continue
        out.append(json.loads(json.dumps(c)))
    return out, dup


def version_is_not_real(c):
    """規則 13 的延伸：版本只是檔案時間、或來自範圍下限，不是真的版本。"""
    for p in c.get("properties") or []:
        n, v = str(p.get("name", "")), str(p.get("value", ""))
        if n == "sca-center:version-basis" and v.startswith("file modification time"):
            return "file modification time"
        if n.endswith("versionSpecifiers"):
            return "version range lower bound"
    return None


def sanitize_extras(comps):
    """上傳 DT 的副本：非真版本的元件移除版本（與 purl 的 @版本），原值記在屬性；不猜版本。回移除數。"""
    sv = _load_module(HERE.parent / "pilot" / "lib" / "strip_versions.py", "sca_center_strip_versions")
    n = 0
    for c in comps:
        why = version_is_not_real(c)
        if why and c.get("version"):
            c.setdefault("properties", []).append({"name": "sca-pilot:version-removed", "value": f"{c['version']} ({why})"})
            c.pop("version", None)
            if c.get("purl"):
                c["purl"] = sv.strip_purl_version(c["purl"])
            c.pop("cpe", None)   # CPE 帶版本，留著 DT 會用它猜
            n += 1
    return comps, n


def product_bom(product_sbom, comps, version):
    mc = dict(product_sbom.get("metadata", {}).get("component") or {})
    mc["version"] = version
    mc.setdefault("type", "firmware")
    body = {"bomFormat": "CycloneDX", "specVersion": product_sbom.get("specVersion") or "1.6", "version": 1,
            "metadata": {"component": mc, "properties": [{"name": "sca-center:purpose", "value": "product components outside the rootfs (firmware, UEFI-bundled libraries, own software)"}]},
            "components": comps}
    body["serialNumber"] = "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, hashlib.sha256(json.dumps(comps, sort_keys=True).encode()).hexdigest()))
    return body


# ---------- VEX 轉成 DT 對得上的樣子（項目 1） ----------

def split_source_ids(s):
    out = []
    for part in str(s or "").split(","):
        part = part.strip()
        if ":" in part:
            a, b = part.split(":", 1)
            out.append((a.strip().upper(), b.strip()))
    return out


def conservative(a, b):
    return a if STATE_RANK.get(a["state"], 9) <= STATE_RANK.get(b["state"], 9) else b


def make_detail(state, body):
    """寫回 DT 的 detail：開頭是標記（帶狀態與內容雜湊），後面是內容。標記的狀態與 DT 現在的狀態不同、或內容被改過 → 人改過。"""
    body = str(body or "").strip()
    sha = hashlib.sha256(body.encode("utf-8")).hexdigest()[:12]
    return f"{MARKER_PREFIX}state={state} sha={sha}] {body}".rstrip()


def parse_marker(detail):
    """回標記裡的狀態（小寫）；不是以標記開頭、格式不對、或內容雜湊對不上 → None。"""
    m = MARKER_RE.match(str(detail or ""))
    if not m:
        return None
    body = str(detail)[m.end():].lstrip(" ")
    if hashlib.sha256(body.strip().encode("utf-8")).hexdigest()[:12] != m.group(2):
        return None
    return m.group(1).lower()


NO_ANALYSIS = ("", "NOT_SET")


def has_analysis(cur):
    """DT 上這筆 finding 有沒有人（或誰）設過分析狀態：沒有 state、或 NOT_SET 都算沒有。"""
    return str((cur or {}).get("state") or "").upper() not in NO_ANALYSIS


def detail_of(cur):
    for k in ("detail", "details", "analysisDetails"):
        if cur.get(k) is not None:
            return cur[k]
    return None


def is_ours(cur):
    """DT 上現在的分析是不是我們寫回去、而且沒被改過：標記在開頭、雜湊對得上、標記的狀態等於 DT 現在的狀態。"""
    if not has_analysis(cur):
        return False
    return parse_marker(detail_of(cur)) == str(cur.get("state")).lower()


def statement_analysis(v):
    a = dict(v.get("analysis") or {})
    st = a.get("state")
    author = (prop(v, "sca-center:vex-rule-author") or prop(v, "sca-center:annotation-author") or [""])[0]
    rule = (prop(v, "sca-center:vex-rule") or [""])[0]
    how = (prop(v, "sca-center:vex-source") or [""])[0]
    bits = [x for x in (f"basis {how}" if how else "", f"rule {rule}" if rule else "", f"author {author}" if author else "") if x]
    body = f"{a.get('detail') or ''}".strip() + (f" ({'; '.join(bits)})" if bits else "")
    out = {"state": st, "detail": make_detail(st, body)}
    if a.get("justification") in JUSTIFICATIONS:
        out["justification"] = a["justification"]
    if isinstance(a.get("response"), list) and a["response"]:
        out["response"] = a["response"]
    return out


def build_targets_index(findings):
    """DT findings → {元件鍵: [finding…]}。"""
    by_key = {}
    for f in findings:
        by_key.setdefault(comp_key(f["component"]), []).append(f)
    return by_key


def key_label(k):
    if k and k[0] == "purl":
        return k[1].split("?", 1)[0].rsplit("/", 1)[-1]
    return str(k[1]) if k else "?"


def merge_into(d, k, an, counters):
    if k in d and d[k]["state"] != an["state"]:
        counters["conflicts"] += 1
        d[k] = conservative(d[k], an)
    elif k not in d:
        d[k] = an


def match_statements(vex, product_sbom, targets, alt_keys):
    """每條 VEX 陳述 × 它的 affects → 各 target 的 DT finding。
    targets：{名稱: {"findings": […], "bomref_by_key": {元件鍵: bom-ref}, "serial", "version"}}
    alt_keys：二進位元件鍵 → DT finding 實際掛的元件鍵（deb 原始碼套件、對應的核心元件）。
    finding 是經 alt_keys 到的時，它對應所有二進位套件：每一個二進位套件都有陳述、而且都是「已解決」那一族
    （not_affected／false_positive／resolved）才寫那一族的狀態；有任何一個沒有陳述就寫 in_triage 並在 detail 列出沒判的二進位（H1）。
    沒有可用 state 的陳述不送，計為沒對上（M3）。
    回 (applies, report)：applies[(target, DT source, vulnId, ref)] = {"state"…}；report 有計數與沒對上的清單。"""
    comp_by_ref = {c.get("bom-ref"): c for c in product_sbom.get("components") or [] if isinstance(c, dict)}
    idx = {t: build_targets_index(d["findings"]) for t, d in targets.items()}
    reverse = {}
    for b, lst in alt_keys.items():
        for k in lst:
            reverse.setdefault(k, set()).add(b)
    direct, viaalt, altmeta = {}, {}, {}
    cnt = {"conflicts": 0}
    matched, unmatched = 0, []
    basis = {"source-id": 0, "alias": 0}
    stmts = [v for v in vex.get("vulnerabilities") or [] if isinstance(v, dict)]
    # 沒有評估的陳述不是判定：整個略過（不算陳述、不算沒對上、不參與同一個 finding 的合併），DT 的狀態因此不會改變
    n_na = sum(1 for v in stmts if NOT_ASSESSED_VALUE in prop(v, NOT_ASSESSED_PROP))
    stmts = [v for v in stmts if NOT_ASSESSED_VALUE not in prop(v, NOT_ASSESSED_PROP)]
    for v in stmts:
        if (v.get("analysis") or {}).get("state") not in STATE_RANK:
            unmatched.append({"id": v.get("id"), "state": (v.get("analysis") or {}).get("state"), "component": (prop(v, "sca-center:component") or [""])[0],
                              "reason": "statement has no usable analysis state (not sent)"})
            continue
        sids = split_source_ids((prop(v, "sca-center:source-ids") or [""])[0])
        dt_ids = {(s, i) for s, i in sids if s not in NON_DT_SOURCES}
        only_other = bool(sids) and not dt_ids
        vid = v.get("id")
        keys = []
        for a in v.get("affects") or []:
            c = comp_by_ref.get(ref_tail(a.get("ref")))
            if c:
                keys.append((comp_key(c), a.get("ref")))
        if not keys:
            pu = (prop(v, "sca-center:component-purl") or [""])[0]
            if pu:
                keys.append((("purl", pu), None))
        if not keys:
            unmatched.append({"id": vid, "reason": "no component in the product SBOM for this statement", "state": (v.get("analysis") or {}).get("state")})
            continue
        an = statement_analysis(v)
        hit_any = False
        for ck, _ in keys:
            for tname, tidx in idx.items():
                for k in [ck] + alt_keys.get(ck, []):
                    for f in tidx.get(k, []):
                        vu = f["vulnerability"]
                        src = str(vu.get("source") or "").upper()
                        how = None
                        if (src, vu.get("vulnId")) in dt_ids:
                            how = "source-id"
                        elif vid and (vid == vu.get("vulnId") or vid in {x for al in vu.get("aliases") or [] if isinstance(al, dict) for x in al.values()}):
                            how = "alias"
                        if not how:
                            continue
                        br = targets[tname]["bomref_by_key"].get(comp_key(f["component"]))
                        if not br:
                            continue   # 上傳的 SBOM 裡找不到這個元件的 bom-ref：對不上
                        kk = (tname, vu.get("source"), vu.get("vulnId"), bomref_urn(targets[tname]["serial"], targets[tname]["version"], br))
                        if k == ck:
                            merge_into(direct, kk, dict(an), cnt)
                        else:
                            per = viaalt.setdefault(kk, {})
                            if ck in per:
                                merge_into(per, ck, dict(an), cnt)
                            else:
                                per[ck] = dict(an)
                            altmeta[kk] = k
                        basis[how] += 1
                        hit_any = True
        if hit_any:
            matched += 1
        else:
            unmatched.append({"id": vid, "state": (v.get("analysis") or {}).get("state"),
                              "component": (prop(v, "sca-center:component") or [""])[0],
                              "reason": "only Grype/NVIDIA sources, no DT finding expected" if only_other else "no DT finding for this component and vulnerability"})
    applies = dict(direct)
    partial = []
    for kk, per in viaalt.items():
        if kk in direct:   # 元件本身就有陳述：以它為準，經對應來的併進去取最保守
            for an in per.values():
                merge_into(applies, kk, dict(an), cnt)
            continue
        cons = None
        for an in per.values():
            if cons is None:
                cons = dict(an)
            elif cons["state"] != an["state"]:
                cnt["conflicts"] += 1
                cons = conservative(cons, an)
        bins = reverse.get(altmeta[kk]) or set(per)
        unjudged = sorted(key_label(b) for b in bins - set(per))
        if cons["state"] not in CLOSED or not unjudged:
            applies[kk] = cons
            continue
        judged = "; ".join(f"{key_label(b)} {a['state']}" for b, a in sorted(per.items(), key=lambda x: key_label(x[0])))
        body = (f"Shared finding on a source/kernel component built into {len(bins)} installed packages; only some have a judgement "
                f"({judged}). Not written as {cons['state']} because these packages are not judged: {', '.join(unjudged)}.")
        applies[kk] = {"state": "in_triage", "detail": make_detail("in_triage", body)}
        partial.append({"vuln": kk[2], "judged": sorted(key_label(b) for b in per), "unjudged": unjudged, "would_be": cons["state"]})
    return applies, {"statements": len(stmts), "not_assessed_skipped": n_na, "matched": matched, "unmatched": len(unmatched), "conflicts": cnt["conflicts"],
                     "basis": basis, "unmatched_list": unmatched, "partial_shared": len(partial), "partial_shared_list": partial[:200]}


def dt_vex_document(applies, serial_for_doc=None):
    """applies → CycloneDX VEX。同一 (source, id, state, justification, response, detail) 的 ref 併成一條 affects。"""
    groups = {}
    for (t, src, vid, ref), an in sorted(applies.items(), key=lambda kv: (kv[0][1] or "", kv[0][2] or "", kv[0][3])):
        gk = (src, vid, an["state"], an.get("justification"), json.dumps(an.get("response")), an["detail"])
        groups.setdefault(gk, []).append(ref)
    vulns = []
    # DT 5.2 實測：同一個弱點在同一個專案有兩個 finding 時（例如 bluez 與核心原始碼），後面那條陳述會連另一個元件的 finding 一起套用。
    # 所以已解決那一族（會被 DT 設成 suppressed）排前面、exploitable／in_triage 排最後：互相蓋掉時，蓋出來的是比較保守的狀態。
    order = sorted(groups.items(), key=lambda kv: (-STATE_RANK.get(kv[0][2], 9), kv[0][0] or "", kv[0][1] or ""))
    for (src, vid, st, just, resp, detail), refs in order:
        a = {"state": st, "detail": detail}
        if just:
            a["justification"] = just
        if resp != "null":
            a["response"] = json.loads(resp)
        vulns.append({"id": vid, "source": {"name": src}, "analysis": a, "affects": [{"ref": r} for r in sorted(set(refs))]})
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "serialNumber": "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, json.dumps(vulns, sort_keys=True))), "vulnerabilities": vulns}


def cur_map(t):
    """target 的 DT finding 現況：{(source, vulnId, affects ref): analysis}。"""
    out = {}
    for f in t["findings"]:
        br = t["bomref_by_key"].get(comp_key(f["component"]))
        if br:
            x = dict(f.get("analysis") or {})
            x.update(_c=f["component"].get("uuid"), _v=f["vulnerability"].get("uuid"), _p=t.get("uuid"))
            out[(f["vulnerability"].get("source"), f["vulnerability"].get("vulnId"), bomref_urn(t["serial"], t["version"], br))] = x
    return out


def fill_details(dt, items):
    """findings API 的 analysis 不一定帶 detail：有分析、但沒有 detail 欄位的，逐筆讀 /api/v1/analysis（analysisDetails）。
    讀不到的標 _detail_error（呼叫端當作不確定，不當作是我們的）。"""
    from concurrent.futures import ThreadPoolExecutor
    todo = [x for x in items if has_analysis(x) and detail_of(x) is None]

    def one(x):
        st, _, d = dt.json("GET", f"/api/v1/analysis?project={x['_p']}&component={x['_c']}&vulnerability={x['_v']}")
        if st == 200 and isinstance(d, dict):
            x["detail"] = d.get("analysisDetails") if d.get("analysisDetails") is not None else (d.get("details") if d.get("details") is not None else d.get("detail") or "")
        else:
            x["_detail_error"] = f"http={st}"
    with ThreadPoolExecutor(8) as ex:
        list(ex.map(one, todo))
    return len(todo)


def finding_ref(d, f):
    br = d["bomref_by_key"].get(comp_key(f["component"]))
    return bomref_urn(d["serial"], d["version"], br) if br else None


def withhold_shared_vulns(targets, kept):
    """DT 5.2 實測：同一個弱點（vulnId）在同一個專案有多個 finding 時，送給其中一個的分析會連其他的一起套（「後面的陳述蓋掉」）。
    所以某個弱點只要有任何一個 finding 不在我們這次的寫入集合裡（別人的分析、沒有陳述、被擋下），這個弱點的陳述（所有狀態）一律不送：
    送了會蓋掉那個 finding（例如人判的 exploitable 變成 suppressed 的 not_affected）。回 (剩下的 kept, 被扣下的清單)。"""
    out, withheld = dict(kept), []
    for t, d in targets.items():
        vids = {k[2] for k in kept if k[0] == t}
        by_vuln = {}
        for f in d["findings"]:
            by_vuln.setdefault(f["vulnerability"].get("vulnId"), []).append(f)
        for vid in sorted(v for v in vids if v):
            ours, others = [], []
            for f in by_vuln.get(vid, []):
                ref = finding_ref(d, f)
                (ours if ref and (t, f["vulnerability"].get("source"), vid, ref) in kept else others).append(f)
            if not others:
                continue
            for k in [k for k in out if k[0] == t and k[2] == vid]:
                del out[k]
            withheld.append({"target": t, "vuln": vid, "would_write": sorted({f["component"].get("name") or "?" for f in ours}),
                             "not_in_write_set": sorted({(f["component"].get("name") or "?") + (" (has an analysis)" if has_analysis(f.get("analysis")) else " (no statement or blocked)") for f in others})})
    return out, withheld


def take_snapshot(dt, targets, kept):
    """寫入前：與我們要送的弱點同名的所有「不在寫入集合」的 finding 的 state／detail。"""
    snap = {}
    for t, d in targets.items():
        vids = {k[2] for k in kept if k[0] == t}
        for f in d["findings"]:
            vu = f["vulnerability"]
            if vu.get("vulnId") not in vids:
                continue
            ref = finding_ref(d, f)
            if ref and (t, vu.get("source"), vu.get("vulnId"), ref) in kept:
                continue
            x = dict(f.get("analysis") or {})
            x.update(_c=f["component"].get("uuid"), _v=vu.get("uuid"), _p=d["uuid"], _name=f["component"].get("name"), _vid=vu.get("vulnId"))
            snap[(t, f["component"].get("uuid"), vu.get("uuid"))] = x
    fill_details(dt, list(snap.values()))
    return {k: {"state": norm_state(x), "detail": str(detail_of(x) or "").strip(), "human": has_analysis(x) and not is_ours(x),
                "name": x["_name"], "vuln": x["_vid"]} for k, x in snap.items()}


def norm_state(x):
    return str((x or {}).get("state") or "").upper().replace("NOT_SET", "")


def changed_since(dt, targets, snap, fs_by_target):
    """寫入後再讀：snapshot 裡的 finding 有沒有被改（狀態或 detail）。回改變的清單。"""
    now = {}
    for t, fs in fs_by_target.items():
        for f in fs:
            k = (t, f["component"].get("uuid"), f["vulnerability"].get("uuid"))
            if k in snap:
                x = dict(f.get("analysis") or {})
                x.update(_c=k[1], _v=k[2], _p=targets[t]["uuid"])
                now[k] = x
    fill_details(dt, list(now.values()))
    out = []
    for k, was in snap.items():
        if k not in now:
            continue
        x = now[k]
        if norm_state(x) != was["state"] or str(detail_of(x) or "").strip() != was["detail"]:
            out.append({"vuln": was["vuln"], "component": was["name"], "human": was["human"], "was": was["state"] or "NOT_SET", "now": norm_state(x) or "NOT_SET"})
    return out


# ---------- 流程 ----------

class Run:
    def __init__(self, dt, args, out):
        self.dt, self.a, self.out, self.lines, self.fail = dt, args, out, [], False
        self.report = {}
        self.prod_gap = False

    def status(self, stage, st, detail):
        d = re.sub(r"[\t\r\n]+", " ", str(detail))[:600]
        self.lines.append((stage, st, d))
        if st == "FAIL":
            self.fail = True
        print(f"{stage}\t{st}\t{d}")

    def wait_workflow(self, token, kind):
        """回 (狀態字串, 看得到嗎)。kind=bom：label bom_upload_token 的 import-bom、vuln-analysis；vex：run id 就是 token。"""
        t0, last = time.time(), None
        while time.time() - t0 <= self.a.wait:
            if kind == "vex":
                st, _, d = self.dt.json("GET", f"/api/v2/internal/workflow-runs/{token}")
                if st in (401, 403, 404):
                    return f"workflow-runs http={st}", False
                if st == 200 and isinstance(d, dict):
                    last = d.get("status")
                    if last in ("COMPLETED", "FAILED", "CANCELLED"):
                        return f"import-vex={last}", True
            else:
                st, _, d = self.dt.json("GET", f"/api/v2/internal/workflow-runs?label=bom_upload_token%3D{token}&limit=100")
                if st in (401, 403):
                    return f"workflow-runs http={st}", False
                if st == 200 and isinstance(d, dict):
                    s = {r.get("workflow_name"): r.get("status") for r in d.get("items") or []}
                    last = " ".join(f"{k}={v}" for k, v in sorted(s.items()))
                    if any(s.get(k) in ("FAILED", "CANCELLED") for k in ("import-bom", "vuln-analysis")):
                        return last, True
                    if s.get("import-bom") == "COMPLETED" and s.get("vuln-analysis") == "COMPLETED":
                        return last, True
            time.sleep(self.a.poll)
        return (last or "no status") + f" (timed out after {self.a.wait}s)", True

    def project(self, name, version, create, tags=()):
        q = urllib.parse.urlencode({"name": name, "version": version})
        st, _, d = self.dt.json("GET", f"/api/v1/project/lookup?{q}")
        if st == 200 and isinstance(d, dict) and d.get("uuid"):
            return d, "reused"
        if st != 404 or not create:
            return None, f"lookup http={st}"
        body = {"name": name, "version": version, "active": True, "classifier": "FIRMWARE", "tags": [{"name": t} for t in tags]}
        st, _, d = self.dt.json("PUT", "/api/v1/project", body)
        if st == 409:
            st, _, d = self.dt.json("GET", f"/api/v1/project/lookup?{q}")
        if st in (200, 201) and isinstance(d, dict) and d.get("uuid"):
            return d, "created"
        return None, f"create http={st}"

    def uploaded_rootfs(self):
        """rootfs 專案實際收到的 BOM（sca-scan 的 sbom.upload.cdx.json，加上 deb 原始碼元件 — 同 sca-scan 的做法重現）。"""
        p = Path(self.a.scan) / "sbom" / "sbom.upload.cdx.json"
        bom = json.loads(p.read_text(encoding="utf-8"))
        ds = Path(self.a.scan) / "dt" / "deb-sources.json"
        added = 0
        if ds.is_file():
            try:
                if json.loads(ds.read_text(encoding="utf-8")).get("source_components_added"):
                    mod = _load_module(HERE.parent / "pilot" / "lib" / "deb_sources.py", "sca_center_deb_sources")
                    a, _, _ = mod.add_sources(bom)
                    for x in a:
                        x.pop("_binary_purls", None)
                    added = len(a)
            except (OSError, ValueError):
                raise WbError("scan/dt/deb-sources.json unreadable: cannot rebuild the BOM that DT received")
        return bom, added


def deb_alt_keys(scan):
    """deb 二進位元件鍵 → 原始碼套件元件鍵（DT 以原始碼套件比對 Ubuntu 漏洞資料，finding 掛在原始碼套件上）。"""
    out = {}
    p = Path(scan) / "dt" / "deb-sources.json"
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pyver_alt_keys(scan, out)
        return kernel_alt_keys(scan, out)
    kernel_alt_keys(scan, out)
    pyver_alt_keys(scan, out)
    for x in d.get("added") or []:
        for b in x.get("binary_purls") or []:
            out.setdefault(("purl", b), []).append(("purl", x["purl"]))
    for x in d.get("shared_sources") or []:
        for b in x.get("binary_purls") or []:
            out.setdefault(("purl", b), []).append(("purl", x["purl"]))
    return out


def pyver_alt_keys(scan, out):
    """產品 SBOM／VEX 用原始 SBOM 的 purl（Python 模組 @0.0.0），DT 收到的是 sca-scan C-pyver 改過版本的副本（@1.2.1）：
    原始 purl → 改過的 purl（scan/sbom/sbom.pyver.cdx.json 的 sca:original-version 屬性），VEX 才對得上 DT 的 finding。
    沒有這個檔案（沒有 C-pyver）→ 什麼都不加。"""
    p = Path(scan) / "sbom" / "sbom.pyver.cdx.json"
    try:
        bom = json.loads(p.read_text(encoding="utf-8"))
        pv = _load_module(HERE / "py_dpkg_version.py", "sca_center_py_dpkg_version")
        pairs = pv.purl_pairs(bom)
    except (OSError, ValueError):
        return out
    for o, n in pairs:
        if ("purl", n) not in out.setdefault(("purl", o), []):
            out[("purl", o)].append(("purl", n))
    return out


def kernel_alt_keys(scan, out):
    """NVIDIA 的核心二進位套件 → C-kernel-l4t-map 加進上傳 SBOM 的對應核心元件（DT 的核心 finding 掛在那個元件上）。"""
    p = Path(scan) / "scan" / "l4t-kernel-map.json"
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return out
    tgt = ((d.get("map_entry") or {}).get("component") or {}).get("purl")
    if tgt:
        for k in d.get("l4t_kernel") or []:
            if k.get("purl"):
                out.setdefault(("purl", k["purl"]), []).append(("purl", tgt))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--reports", required=True, help="CRA/Reports（sbom.cdx.json、vex.cdx.json）")
    ap.add_argument("--scan", required=True, help="sca-scan 的輸出資料夾（dt/project.json、sbom/sbom.upload.cdx.json）")
    ap.add_argument("--out", required=True)
    ap.add_argument("--env", help="pilot.env（只讀 DT_URL、DT_API_KEY）")
    ap.add_argument("--vex", action="store_true")
    ap.add_argument("--product-components", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="只讀 DT 與比對，不建專案、不上傳（計數照樣輸出）")
    ap.add_argument("--wait", type=int, default=900)
    ap.add_argument("--poll", type=float, default=3)
    ap.add_argument("--max-unmatched-list", type=int, default=200)
    a = ap.parse_args(argv)
    if not (a.vex or a.product_components):
        print("沒有要做的事：加 --vex 或 --product-components", file=sys.stderr)
        return 64
    env = dict(os.environ)
    if a.env:
        try:
            env.update(read_env_file(a.env))
        except OSError:
            a.env_problem = f"env file unreadable ({a.env})"
    url, key = env.get("DT_URL"), env.get("DT_API_KEY")
    if not (url and key) and not getattr(a, "env_problem", None) and a.env:
        a.env_problem = "env file has no DT_URL or DT_API_KEY"
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    return run(Dt(url, key) if url and key else None, a, out)


def run(dt, a, out):
    r = Run(dt, a, out)
    stages = (["D-dt-product-project", "D-dt-product-upload", "D-dt-product-processing", "D-dt-product-components"] if a.product_components else []) + \
             (["D-dt-vex-build", "D-dt-vex-upload", "D-dt-vex-processing", "D-dt-vex-applied"] if a.vex else [])

    def rest(why, st="NOT_RUN"):
        done = {s for s, _, _ in r.lines}
        for s in stages:
            if s not in done:
                r.status(s, st, why)

    if dt is None:
        rest(getattr(a, "env_problem", None) or "DT_URL or DT_API_KEY missing (environment; no --env file given)")
        return 0
    rep = Path(a.reports)
    try:
        product = json.loads((rep / "sbom.cdx.json").read_text(encoding="utf-8"))
        vex = json.loads((rep / "vex.cdx.json").read_text(encoding="utf-8")) if a.vex else None
        pj = json.loads((Path(a.scan) / "dt" / "project.json").read_text(encoding="utf-8"))
        rootfs_bom, deb_added = r.uploaded_rootfs()
    except (OSError, ValueError, WbError) as e:
        rest(f"input unreadable: {type(e).__name__} {e if isinstance(e, WbError) else ''}".strip(), "FAIL")
        return 1
    root_uuid = pj.get("uuid")
    if not root_uuid:
        rest("scan/dt/project.json has no uuid (the rootfs upload did not create a DT project)")
        return 0
    st, _, rp = dt.json("GET", f"/api/v1/project/{root_uuid}")
    if st != 200 or not isinstance(rp, dict):
        rest(f"rootfs DT project not readable (http={st})", "FAIL")
        return 1

    targets = {}
    rootfs_refs = {}
    for c in rootfs_bom.get("components") or []:
        if isinstance(c, dict) and c.get("bom-ref"):
            rootfs_refs.setdefault(comp_key(c), c["bom-ref"])
    if not rootfs_bom.get("serialNumber"):
        rep_note = "the BOM uploaded to the rootfs project has no serialNumber: DT cannot match VEX refs"
    else:
        rep_note = None

    # ----- 項目 2：產品元件專案 -----
    prod_uuid = None
    if a.product_components:
        extras, dup = product_extras(product, rootfs_bom)
        extras, stripped = sanitize_extras(extras)
        base_v = re.sub(r"\s*\([^()]*\)\s*$", "", rp.get("version") or "").strip()
        pver = f"{base_v} {PRODUCT_SUFFIX}".strip()
        if not extras:
            for s in stages[:4]:
                r.status(s, "NOT_RUN", "the product SBOM has no components outside the rootfs")
        else:
            doc = product_bom(product, extras, pver)
            (out / "product-components.cdx.json").write_text(json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")
            if a.dry_run:
                for s_ in stages[:4]:
                    r.status(s_, "NOT_RUN", f"--dry-run: {len(extras)} product components prepared (version removed {stripped}, already in rootfs {dup}); nothing sent")
                r.report["product_components"] = {"dry_run": True, "prepared": len(extras), "version_removed": stripped, "skipped_duplicate_of_rootfs": dup}
                pr, how = {}, None
            else:
                pr, how = r.project(rp.get("name"), pver, True, (PRODUCT_TAG,))
            if pr == {}:
                pass
            elif not pr:
                r.status("D-dt-product-project", "FAIL", how)
                for s in stages[1:4]:
                    r.status(s, "NOT_RUN", "no DT project")
            else:
                prod_uuid = pr["uuid"]
                r.status("D-dt-product-project", "OK", f"{how} '{rp.get('name')}' @ '{pver}' ({prod_uuid}); separate from the rootfs project {root_uuid[:8]}…, which is not modified")
                code, d = dt.upload("/api/v1/bom", {"project": prod_uuid}, "bom", "product-components.cdx.json", json.dumps(doc, ensure_ascii=False).encode())
                tok = (d or {}).get("token") if isinstance(d, dict) else None
                if code != 200 or not tok:
                    r.status("D-dt-product-upload", "FAIL", f"http={code}")
                    r.status("D-dt-product-processing", "NOT_RUN", "upload failed")
                    r.status("D-dt-product-components", "NOT_RUN", "upload failed")
                    prod_uuid = None
                else:
                    r.status("D-dt-product-upload", "OK", f"http=200, {len(extras)} components uploaded (accepted by DT, not yet processed)")
                    ws, seen = r.wait_workflow(tok, "bom")
                    r.prod_gap = not seen
                    if not seen:
                        r.status("D-dt-product-processing", "GAP", f"{ws}: the key lacks SYSTEM_CONFIGURATION_READ, processing status unknown")
                    elif "import-bom=COMPLETED" in ws and "vuln-analysis=COMPLETED" in ws:
                        r.status("D-dt-product-processing", "OK", ws)
                    else:
                        r.status("D-dt-product-processing", "FAIL", ws)
                    comps, err = dt.pages(f"/api/v1/component/project/{prod_uuid}")
                    matchable = sum(1 for c in extras if c.get("version") and (c.get("purl") or c.get("cpe")))
                    nd = len(extras)
                    # DT 把 名稱＋版本＋purl（不含 qualifiers）相同的元件合成一個（實測 2026-11-11）：期望數是不重複的身分數
                    distinct = len({(c.get("name"), c.get("version"), (c.get("purl") or "").split("?", 1)[0]) for c in extras})
                    det = f"uploaded {nd} ({distinct} distinct by name, version and purl), in DT {len(comps)}; matchable against vulnerability data (version plus purl or CPE): {matchable}; version removed (rule 13: not a real version): {stripped}; not uploaded because already in the rootfs SBOM: {dup}"
                    if err:
                        r.status("D-dt-product-components", "FAIL", f"{det}; component list incomplete: {err}")
                    elif len(comps) != distinct:
                        r.status("D-dt-product-components", "ATTENTION", f"{det}; DT holds a different number than the distinct components uploaded")
                    else:
                        r.status("D-dt-product-components", "ATTENTION" if nd - matchable else "OK", det + ("; the rest are inventory only (DT cannot match vulnerabilities without a version and purl/CPE)" if nd - matchable else ""))
                    r.report["product_components"] = {"project": prod_uuid, "version": pver, "uploaded": nd, "distinct": distinct, "in_dt": len(comps), "matchable": matchable,
                                                      "version_removed": stripped, "skipped_duplicate_of_rootfs": dup}
                    if seen and ("vuln-analysis=COMPLETED" not in ws):
                        prod_uuid = None   # findings 還不能讀，VEX 不對這個專案做
    # ----- 項目 1：VEX -----
    if a.vex:
        build_vex(r, dt, a, out, product, vex, rootfs_bom, rootfs_refs, root_uuid, rep_note, prod_uuid, deb_added, targets)
    (out / "dt-writeback.json").write_text(json.dumps(r.report, ensure_ascii=False, indent=1), encoding="utf-8")
    return 1 if r.fail else 0


def build_vex(r, dt, a, out, product, vex, rootfs_bom, rootfs_refs, root_uuid, rep_note, prod_uuid, deb_added, targets):
    if rep_note:
        for s in ("D-dt-vex-build", "D-dt-vex-upload", "D-dt-vex-processing", "D-dt-vex-applied"):
            r.status(s, "GAP", rep_note)
        return
    fr, err = dt.pages(f"/api/v1/finding/project/{root_uuid}?suppressed=true")
    if err:
        r.status("D-dt-vex-build", "FAIL", f"rootfs findings incomplete ({err}): not matching against a partial list")
        for s in ("D-dt-vex-upload", "D-dt-vex-processing", "D-dt-vex-applied"):
            r.status(s, "NOT_RUN", "findings incomplete")
        return
    targets["rootfs"] = {"findings": fr, "bomref_by_key": rootfs_refs, "serial": rootfs_bom["serialNumber"], "version": rootfs_bom.get("version", 1), "uuid": root_uuid}
    if prod_uuid:
        pdoc = json.loads((out / "product-components.cdx.json").read_text(encoding="utf-8"))
        pf, perr = dt.pages(f"/api/v1/finding/project/{prod_uuid}?suppressed=true")
        if perr:
            r.status("D-dt-vex-build", "ATTENTION", f"product-components project findings incomplete ({perr}): statements on those components are not written")
        else:
            targets["product"] = {"findings": pf, "bomref_by_key": {comp_key(c): c["bom-ref"] for c in pdoc["components"] if c.get("bom-ref")},
                                  "serial": pdoc["serialNumber"], "version": 1, "uuid": prod_uuid}
    applies, rep = match_statements(vex, product, targets, deb_alt_keys(a.scan))
    # 不覆蓋別人的分析
    curs = {t: cur_map(d) for t, d in targets.items()}
    kept, skipped = {}, 0
    fill_details(dt, [curs[k[0]][k[1:]] for k in applies if k[1:] in curs[k[0]]])
    for k, an in applies.items():
        cur = curs[k[0]].get(k[1:]) or {}
        if has_analysis(cur) and not is_ours(cur):   # 別人（或我們寫了又被人改過）的分析：不覆蓋
            skipped += 1
            continue
        kept[k] = an
    kept, withheld = withhold_shared_vulns(targets, kept)
    rep["withheld_shared_vuln"] = len(withheld)
    rep["withheld_shared_vuln_list"] = withheld[:200]
    rep["dt_findings"] = {t: len(d["findings"]) for t, d in targets.items()}
    rep["dt_findings_without_statement"] = sum(len(curs[t]) for t in curs) - len({k for k in applies})
    rep["existing_analysis_not_overwritten"] = skipped
    rep["to_write"] = len(kept)
    um = rep.pop("unmatched_list")
    rep["unmatched_list"] = um[:a.max_unmatched_list]
    from collections import Counter
    rep["unmatched_by_reason"] = dict(Counter(x["reason"] for x in um))
    r.report["vex"] = rep
    problems = []
    if rep["unmatched"]:
        problems.append(f"{rep['unmatched']} of {rep['statements']} statements have no DT finding and are not written ({'; '.join(f'{n} {k}' for k, n in sorted(rep['unmatched_by_reason'].items()))})")
    if rep["dt_findings_without_statement"] > 0:
        problems.append(f"{rep['dt_findings_without_statement']} DT findings have no statement in our VEX")
    if withheld:
        problems.append(f"{len(withheld)} vulnerabilities withheld entirely: DT applies a statement to the other findings of the same vulnerability in the project, and at least one of them is not in our write set (someone else's analysis, no statement, or blocked), so nothing is sent for it (listed in dt-writeback.json)")
    if skipped:
        problems.append(f"{skipped} DT findings already carry someone else's analysis and were not overwritten")
    if rep["partial_shared"]:
        problems.append(f"{rep['partial_shared']} shared source-package/kernel findings are written as in_triage because not every installed binary package built from them has a statement")
    nsupp = sum(1 for an in kept.values() if an["state"] in CLOSED)
    rep["will_be_suppressed_in_dt"] = nsupp
    if rep["conflicts"]:
        problems.append(f"{rep['conflicts']} DT findings had statements with different states; the most conservative state is written")
    det = f"{rep['matched']} of {rep['statements']} statements matched {len(applies)} DT findings (by source-id {rep['basis']['source-id']}, by alias {rep['basis']['alias']}); {len(kept)} to write, of which {nsupp} (not_affected/resolved/false_positive) will be suppressed by DT itself and drop out of its default finding view and metrics"
    if not kept:
        r.status("D-dt-vex-build", "ATTENTION" if problems else "NOT_RUN", f"{det}; " + ("; ".join(problems) or "nothing to write"))
        for s in ("D-dt-vex-upload", "D-dt-vex-processing", "D-dt-vex-applied"):
            r.status(s, "NOT_RUN", "no DT finding to write an analysis to")
        return
    r.status("D-dt-vex-build", "ATTENTION" if problems else "OK", det + ("; " + "; ".join(problems) if problems else ""))
    if a.dry_run:
        for s_ in ("D-dt-vex-upload", "D-dt-vex-processing", "D-dt-vex-applied"):
            r.status(s_, "NOT_RUN", "--dry-run: nothing sent")
        (out / "dt-vex.cdx.json").write_text(json.dumps(dt_vex_document(kept), ensure_ascii=False), encoding="utf-8")
        return
    doc = dt_vex_document(kept)
    (out / "dt-vex.cdx.json").write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
    snap = take_snapshot(dt, targets, kept)
    # 一個 VEX 檔只能寫進一個專案；每個 target 各上傳一次（只含它的 ref）
    results = {}
    for t, d in targets.items():
        sub = {k: v for k, v in kept.items() if k[0] == t}
        if not sub:
            continue
        sdoc = dt_vex_document(sub)
        code, resp = dt.upload("/api/v1/vex", {"project": d["uuid"]}, "vex", "dt-vex.cdx.json", json.dumps(sdoc, ensure_ascii=False).encode())
        tok = (resp or {}).get("token") if isinstance(resp, dict) else None
        results[t] = (code, tok, sub)
    ok_up = {t: v for t, v in results.items() if v[0] == 200 and v[1]}
    bad_up = {t: v[0] for t, v in results.items() if not (v[0] == 200 and v[1])}
    if bad_up:
        r.status("D-dt-vex-upload", "FAIL", "; ".join(f"{t}: http={c}" for t, c in bad_up.items()))
    else:
        r.status("D-dt-vex-upload", "OK", "; ".join(f"{t}: http=200, {len(v[2])} analyses sent" for t, v in results.items()) + " (accepted by DT, not yet processed)")
    seen_all, texts, failed = True, [], False
    for t, (c, tok, sub) in ok_up.items():
        ws, seen = r.wait_workflow(tok, "vex")
        seen_all &= seen
        failed |= seen and "COMPLETED" not in ws
        texts.append(f"{t}: {ws}")
    if not ok_up:
        r.status("D-dt-vex-processing", "NOT_RUN", "upload failed")
        r.status("D-dt-vex-applied", "NOT_RUN", "upload failed")
        return
    if failed:
        r.status("D-dt-vex-processing", "FAIL", "; ".join(texts))
    elif not seen_all:
        r.status("D-dt-vex-processing", "GAP", "; ".join(texts) + " (the key lacks SYSTEM_CONFIGURATION_READ: status unknown, only the read-back below tells)")
    else:
        r.status("D-dt-vex-processing", "OK", "; ".join(texts) + " (workflow COMPLETED does not mean the analyses were applied)")
    # 讀回：每個寫入的 finding 的 analysis 是否是我們寫的狀態
    applied = mism = missing = 0
    rberr = None
    t0 = time.time()
    suppressed_now = 0
    mism_list = []
    while True:
        applied = mism = missing = suppressed_now = other = 0
        mism_list = []
        rberr = None
        fs_by_t = {}
        for t, (c, tok, sub) in ok_up.items():
            fs, e = dt.pages(f"/api/v1/finding/project/{targets[t]['uuid']}?suppressed=true")
            if e:
                rberr = e
                continue
            fs_by_t[t] = fs
            cur = cur_map(dict(targets[t], findings=fs))
            fill_details(dt, [cur[k[1:]] for k in sub if k[1:] in cur])
            for (tt, src, vid, ref), an in sub.items():
                x = cur.get((src, vid, ref)) or {}
                same_state = has_analysis(x) and str(x.get("state")).lower() == an["state"]
                same_detail = str(detail_of(x) or "").strip() == an["detail"].strip()
                if same_state and same_detail:
                    applied += 1
                    suppressed_now += bool(x.get("isSuppressed"))
                elif same_state:
                    other += 1   # 狀態對，但 detail 是同一個弱點在別的元件的另一條陳述（DT 把那條也套到這個 finding）
                    if len(mism_list) < 20:
                        mism_list.append({"vuln": vid, "kind": "state ok, detail of another statement", "state": an["state"]})
                elif has_analysis(x):
                    mism += 1
                    if len(mism_list) < 20:
                        mism_list.append({"vuln": vid, "kind": "state differs", "want_state": an["state"], "dt_state": x.get("state")})
                else:
                    missing += 1
        if rberr or not (mism or missing) or time.time() - t0 >= min(a.wait, 120):
            break
        time.sleep(a.poll)
    unint = changed_since(dt, targets, snap, fs_by_t) if snap and not rberr else []
    rep["unintended_changes"] = unint[:200]
    total = applied + mism + missing + other
    ot = f"; {other} carry the right state but the detail of another statement for the same vulnerability (DT applied that statement to this finding too)" if other else ""
    rep["applied"] = {"applied": applied, "state_differs": mism, "other_statement_applied": other, "not_applied": missing, "suppressed_in_dt": suppressed_now, "state_differs_sample": mism_list}
    gap_note = "; product-components project: processing status unknown (GAP, key lacks SYSTEM_CONFIGURATION_READ), so vulnerability-analysis completion was not confirmed and this read-back is the only confirmation" if (r.prod_gap and "product" in targets) else ""
    supp = f"; DT suppressed {suppressed_now} of them itself (not_affected/resolved are hidden from its default view and metrics)"
    if rberr:
        res = ("GAP", f"read-back incomplete ({rberr}): applied so far {applied}, state differs {mism}, not applied {missing} of {total}{ot}{gap_note}")
    elif applied == total and total:
        res = ("OK", f"{applied} of {total} DT findings now carry our analysis (state and detail read back){supp}{gap_note}")
    elif applied == 0:
        res = ("FAIL", f"0 of {total} applied: DT accepted and processed the VEX but no finding shows our analysis (state differs {mism}, missing {missing}{ot}); check the BOM serialNumber/version and bom-refs used in affects{gap_note}")
    else:
        res = ("ATTENTION", f"{applied} of {total} applied; state differs {mism}, not applied {missing}{ot}{supp}{gap_note}")
    if unint:
        hum = [u for u in unint if u["human"]]
        lst = "; ".join(f"{u['vuln']} on {u['component']}: {u['was']} -> {u['now']}" for u in unint[:10])
        if hum:
            res = ("FAIL", f"{len(hum)} findings with someone else's analysis CHANGED by the write-back (not intended; {lst}); " + res[1])
        else:
            res = ("ATTENTION" if res[0] == "OK" else res[0], f"{len(unint)} findings we did not intend to write changed ({lst}); " + res[1])
    r.status("D-dt-vex-applied", *res)


if __name__ == "__main__":
    sys.exit(main())
