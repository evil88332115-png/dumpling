#!/usr/bin/env python3
"""韌體 SBOM 上傳臨時 DT 前後的資料處理（只用標準庫與 PyYAML；輸入一律當不可信資料）。

子指令：
  prep     --sbom <fw.cdx.json> --sample <firmware.yml> --out <資料夾> [--synthetic]
           產出 <out>/sbom.cdx.json（要上傳的 SBOM）與 <out>/dt-project.json（DT 專案名稱、版本、摘要）。
  expected --prep <資料夾>
           在 prep 資料夾寫 expected.json（給 pipeline/dt-verify.py verify；格式依 C1 目前版本）與
           firmware-dt-expected.json（我們自己的、與 DT 工具介面無關的預期）。
  report   --prep <資料夾>... [--dt-result <資料夾>] --out <資料夾>
           寫 <out>/firmware-dt.md，每個樣本印一行 FIRMWARE-DT<TAB>OK|ATTENTION|GAP|NOT_RUN|FAIL<TAB>…

規則：不改元件內容、不加猜的 purl／cpe；缺資料、沒跑一律標 GAP／NOT_RUN；不顯示整體 PASS 或「安全」。
退出碼：0＝完成（report 有 FAIL 以 1 結束）；1＝輸入不合格或有 FAIL；64＝參數錯誤。
"""
import argparse
import csv
import hashlib
import json
import os
import re
import sys

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

MAX_BYTES = 50 * 1024 * 1024          # SBOM 與 firmware.yml 的大小上限
MAX_GRYPE_BYTES = 200 * 1024 * 1024   # Grype 輸出上限
MAX_DEPTH = 40                        # JSON 巢狀深度上限
MAX_COMPONENTS = 200000
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")            # sca-scan --name 會把其他字元換成「-」，這裡先保證不需要換
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._+~()-]{0,99}$")    # sca-scan --version 接受的字元
KINDS = ("bios", "vbios", "sbom")
STATUSES = ("OK", "ATTENTION", "GAP", "NOT_RUN", "FAIL")


class DtError(Exception):
    pass


def _read_limited(path, limit, what):
    try:
        if os.path.islink(path) or not os.path.isfile(path):
            raise DtError("%s 不是一般檔案：%s" % (what, os.path.basename(path)))
        if os.path.getsize(path) > limit:
            raise DtError("%s 超過 %d 位元組上限" % (what, limit))
        with open(path, "rb") as fh:
            return fh.read(limit + 1)
    except OSError as e:
        raise DtError("%s 讀不到：%s" % (what, e.strerror))


def _depth_ok(obj, limit=MAX_DEPTH):
    stack = [(obj, 1)]
    while stack:
        o, d = stack.pop()
        if d > limit:
            return False
        if isinstance(o, dict):
            stack.extend((v, d + 1) for v in o.values())
        elif isinstance(o, list):
            stack.extend((v, d + 1) for v in o)
    return True


def load_json(path, limit, what):
    raw = _read_limited(path, limit, what)
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError) as e:
        raise DtError("%s 不是合法 JSON（%s）" % (what, type(e).__name__))
    if not _depth_ok(doc):
        raise DtError("%s 的 JSON 巢狀超過 %d 層" % (what, MAX_DEPTH))
    return doc, raw


def load_sample(path):
    if yaml is None:
        raise DtError("缺少 PyYAML")
    raw = _read_limited(path, MAX_BYTES, "firmware.yml")
    try:
        doc = yaml.safe_load(raw.decode("utf-8"))
    except (yaml.YAMLError, UnicodeDecodeError) as e:
        raise DtError("firmware.yml 不是合法 YAML（%s）" % type(e).__name__)
    if not isinstance(doc, dict):
        raise DtError("firmware.yml 不是 mapping")
    return doc


def safe_slug(s):
    s = re.sub(r"[^A-Za-z0-9._-]", "-", str(s)).strip("-._")
    return s[:80]


def safe_version(v):
    """firmware_version → DT 專案版本（sca-scan --version 可接受的字元）；沒有版本就寫 unknown。"""
    if v is None or str(v).strip() == "":
        return "unknown"
    s = re.sub(r"[^A-Za-z0-9 ._+~()-]", "_", str(v).strip())
    s = re.sub(r"^[^A-Za-z0-9]+", "", s)[:100].rstrip()
    return s if VERSION_RE.match(s or "!") else "unknown"


def project_name(kind, slug, synthetic):
    """名稱：firmware-<kind>-<slug>；合成樣本：firmware-<kind>-synthetic-<slug>。"""
    n = "firmware-%s-%s%s" % (kind, "synthetic-" if synthetic else "", slug)
    n = n[:100].rstrip("-._")
    if not NAME_RE.match(n):
        raise DtError("無法產生安全的專案名稱：%s" % n)
    return n


def _walk_components(comps, path="components"):
    for i, c in enumerate(comps):
        if not isinstance(c, dict):
            raise DtError("%s[%d] 不是物件" % (path, i))
        yield c
        sub = c.get("components")
        if sub is not None:
            if not isinstance(sub, list):
                raise DtError("%s[%d].components 不是陣列" % (path, i))
            yield from _walk_components(sub, "%s[%d].components" % (path, i))


def _props(c):
    out = {}
    for p in c.get("properties") or []:
        if isinstance(p, dict) and isinstance(p.get("name"), str):
            out.setdefault(p["name"], str(p.get("value", "")))
    return out


def identity(c):
    """DT 合併元件的身分：group、name、version、purl、cpe。**不含 hashes**：本機端到端（DT 5.2.0）實測，
    只有雜湊不同的元件（例如同版本的兩個 FSP-M 映像）DT 仍合併成一個。"""
    return (c.get("group") or "", c.get("name") or "", c.get("version") or "", c.get("purl") or "", c.get("cpe") or "")


def purl_type(purl):
    m = re.match(r"^pkg:([A-Za-z0-9.+-]+)/", purl or "")
    return m.group(1).lower() if m else None


def summarize(comps):
    s = {"components": 0, "with_purl": 0, "with_cpe": 0, "distinct_identities": 0,
         "vuln_assessment": {}, "version_status": {}, "version_gap": 0, "no_version": 0, "purl_types": []}
    ids, types = set(), set()
    for c in comps:
        s["components"] += 1
        if c.get("purl"):
            s["with_purl"] += 1
            t = purl_type(c["purl"])
            if t:
                types.add(t)
        if c.get("cpe"):
            s["with_cpe"] += 1
        if not c.get("version"):
            s["no_version"] += 1
        ids.add(identity(c))
        p = _props(c)
        va = p.get("dumpling:vuln-assessment", "(未標)")
        s["vuln_assessment"][va] = s["vuln_assessment"].get(va, 0) + 1
        vs = p.get("dumpling:version-status")
        if vs is not None:
            s["version_status"][vs] = s["version_status"].get(vs, 0) + 1
        if vs == "GAP":
            s["version_gap"] += 1
    s["distinct_identities"] = len(ids)
    s["purl_types"] = sorted(types)
    return s


def check_refs(doc, root_ref, comps):
    refs = {}
    if root_ref:
        refs[root_ref] = "metadata.component"
    for c in comps:
        r = c.get("bom-ref")
        if r is None:
            continue
        if not isinstance(r, str) or not r:
            raise DtError("bom-ref 不是非空字串（元件 %s）" % c.get("name"))
        if r in refs:
            raise DtError("bom-ref 重複：%s" % r)
        refs[r] = c.get("name")
    deps = doc.get("dependencies")
    if deps is None:
        return
    if not isinstance(deps, list):
        raise DtError("dependencies 不是陣列")
    for i, d in enumerate(deps):
        if not isinstance(d, dict) or d.get("ref") not in refs:
            raise DtError("dependencies[%d].ref 指到不存在的 bom-ref：%s" % (i, d.get("ref") if isinstance(d, dict) else d))
        on = d.get("dependsOn") or []
        if not isinstance(on, list):
            raise DtError("dependencies[%d].dependsOn 不是陣列" % i)
        for r in on:
            if r not in refs:
                raise DtError("dependencies[%d].dependsOn 指到不存在的 bom-ref：%s" % (i, r))


def write_json(path, obj):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=1)
        fh.write("\n")


def prep(sbom_path, sample_path, out, synthetic=False):
    doc, raw = load_json(sbom_path, MAX_BYTES, "SBOM")
    if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX" or not doc.get("specVersion"):
        raise DtError("不是 CycloneDX JSON（沒有 bomFormat／specVersion）")
    comps_raw = doc.get("components")
    if not isinstance(comps_raw, list):
        raise DtError("components 不是陣列")
    sample = load_sample(sample_path)
    kind = sample.get("kind")
    if kind not in KINDS:
        raise DtError("firmware.yml 的 kind 必須是 %s" % "、".join(KINDS))
    slug = safe_slug(os.path.basename(os.path.dirname(os.path.abspath(sample_path))))
    if not slug:
        raise DtError("firmware.yml 所在資料夾名稱無法當 slug")
    comps = list(_walk_components(comps_raw))
    if len(comps) > MAX_COMPONENTS:
        raise DtError("元件數超過 %d" % MAX_COMPONENTS)
    if len(comps) == 0:
        raise DtError("SBOM 沒有元件")
    # 合成樣本：命令列指定、firmware.yml 不是 status: ok（GAP＝沒有真實檔案）、或元件記錄的來源檔名含 synthetic
    synth_reasons = []
    if synthetic:
        synth_reasons.append("命令列 --synthetic")
    if kind != "sbom" and sample.get("status") != "ok":
        synth_reasons.append("firmware.yml status 不是 ok")
    for c in comps:
        for k, v in _props(c).items():
            if k in ("bsi:component:filename", "sca-center:found-in") and "synthetic" in v.lower():
                synth_reasons.append("元件來源檔名含 synthetic")
                break
        else:
            continue
        break
    is_synth = bool(synth_reasons)
    name = project_name(kind, slug, is_synth)
    version = safe_version(sample.get("firmware_version"))
    root_ref = "dumpling:fw-root:%s" % slug
    old = (doc.get("metadata") or {}).get("component") if isinstance(doc.get("metadata"), dict) else None
    if doc.get("metadata") is not None and not isinstance(doc["metadata"], dict):
        raise DtError("metadata 不是物件")
    check_refs(doc, root_ref, comps)
    fw_name = str(sample.get("model") or slug)
    root = {"type": "firmware", "bom-ref": root_ref, "name": fw_name, "version": version,
            "properties": [{"name": "dumpling:sample-kind", "value": kind},
                           {"name": "dumpling:sample-slug", "value": slug},
                           {"name": "dumpling:synthetic", "value": "true" if is_synth else "false"}]}
    if sample.get("vendor"):
        root["supplier"] = {"name": str(sample["vendor"])}
    out_doc = dict(doc)
    meta = dict(doc.get("metadata") or {})
    meta["component"] = root
    out_doc["metadata"] = meta
    os.makedirs(out, exist_ok=True)
    sbom_out = os.path.join(out, "sbom.cdx.json")
    write_json(sbom_out, out_doc)
    with open(sbom_out, "rb") as fh:
        sha = hashlib.sha256(fh.read()).hexdigest()
    info = {
        "project_name": name, "project_version": version, "kind": kind, "slug": slug,
        "synthetic": is_synth, "synthetic_reasons": synth_reasons,
        "firmware_name": fw_name, "firmware_version": sample.get("firmware_version"),
        "sbom_file": "sbom.cdx.json", "sbom_sha256": sha, "input_sbom_sha256": hashlib.sha256(raw).hexdigest(),
        "replaced_metadata_component": ({"name": old.get("name"), "version": old.get("version")} if isinstance(old, dict) else None),
        "summary": summarize(comps),
    }
    write_json(os.path.join(out, "dt-project.json"), info)
    return info


# ---------- expected ----------

def load_prep(d):
    info, _ = load_json(os.path.join(d, "dt-project.json"), MAX_BYTES, "dt-project.json")
    if not isinstance(info, dict) or not all(k in info for k in ("project_name", "project_version", "summary")):
        raise DtError("dt-project.json 欄位不齊：%s" % os.path.basename(d.rstrip("/")))
    if not NAME_RE.match(str(info["project_name"])) or not VERSION_RE.match(str(info["project_version"])):
        raise DtError("dt-project.json 的名稱或版本不安全")
    return info


def expected(prep_dir):
    info = load_prep(prep_dir)
    doc, _ = load_json(os.path.join(prep_dir, info.get("sbom_file", "sbom.cdx.json")), MAX_BYTES, "SBOM")
    comps = list(_walk_components(doc.get("components") or []))
    s = info["summary"]
    # 依 C1 pipeline/dt-verify.py verify 目前的格式；介面改了要跟著改（見 docs/notes/c2-firmware-dt.md）。
    # 臨時 DT 只開 OSV、KEV；韌體漏洞比對以 Grype 為主，DT 只收件留存，所以重點是專案存在與元件數。
    # components 用「不同身分」的數量（group／name／version／purl／cpe 都相同的元件 DT 會合併成一個，雜湊不算；DT 5.2.0 實測）。
    # min_findings_*：韌體元件大多沒有 purl，DT（臨時 DT 只開 OSV、KEV）查不到，所以下限是 0，只記錄有哪些 purl 類型。
    dt_verify = {"project_name": info["project_name"], "project_version": info["project_version"],
                 "components": s["distinct_identities"], "min_findings_total": 0,
                 "min_findings_by_purl_type": {}, "informational_purl_types": s["purl_types"]}
    no_data = []
    for c in comps:
        if not c.get("purl"):
            reason = "no-purl-cpe-only（OSV 不比對 CPE；臨時 DT 關閉 NVD）" if c.get("cpe") else "no-purl-no-cpe"
            p = _props(c)
            no_data.append({"bom-ref": c.get("bom-ref"), "name": c.get("name"), "version": c.get("version"),
                            "reason": reason, "vuln_assessment": p.get("dumpling:vuln-assessment")})
    own = {"schema": "firmware-dt-expected/1", "project_name": info["project_name"],
           "project_version": info["project_version"], "synthetic": info.get("synthetic", False),
           "components_total": s["components"], "components_distinct": s["distinct_identities"],
           "meaning": "DT 漏洞數為 0 時，no_data_components 列出的元件是「DT 沒有資料可比對」，不是「沒有漏洞」",
           "no_data_components": no_data,
           "not_assessed_count": s["vuln_assessment"].get("NOT_ASSESSED", 0),
           "version_gap_count": s["version_gap"]}
    write_json(os.path.join(prep_dir, "expected.json"), dt_verify)
    write_json(os.path.join(prep_dir, "firmware-dt-expected.json"), own)
    return dt_verify, own


# ---------- report ----------

def _load_mdsafe():
    # python3 -I 不把腳本所在資料夾放進 sys.path，用路徑載入同資料夾的共用清理模組
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "firmware_mdsafe", os.path.join(os.path.dirname(os.path.abspath(__file__)), "firmware_mdsafe.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_MDSAFE = []


def _cell(s, limit=300):
    """寫進 markdown 或狀態行的不可信文字（dt-verify／sca-scan 的檢查名與階段名、錯誤訊息、樣本名…）：一律經共用的 md_safe。
    只在文字產生時呼叫一次（notes、verify_fail 存的就是清理過的），輸出 markdown 時不要再呼叫，否則會跳脫兩次。"""
    if not _MDSAFE:
        _MDSAFE.append(_load_mdsafe())
    return _MDSAFE[0].md_safe(s, limit)


def read_status_tsv(path):
    raw = _read_limited(path, MAX_BYTES, "status.tsv").decode("utf-8", "replace")
    rows = {}
    for r in csv.DictReader(raw.splitlines(), delimiter="\t"):
        if r.get("stage"):
            rows[r["stage"]] = (r.get("status") or "", r.get("detail") or "")
    return rows


def _worst(sts):
    for want in ("FAIL", "GAP", "NOT_RUN"):
        if want in sts:
            return want
    for s in sts:
        if s != "OK":
            return s
    return "OK"


UPLOAD_STAGES = ("D-dt-project", "D-dt-upload", "D-dt-bom-processing")


def sample_result(info, dt_dir, wait_rc):
    """回傳 dict：dt_components, dt_findings, upload, grype, grype_matches, status, notes。"""
    s = info["summary"]
    r = {"upload": "NOT_RUN", "dt_components": "-", "dt_findings": "-", "grype": "NOT_RUN", "grype_matches": "-",
         "notes": [], "verify_fail": []}
    sd = os.path.join(dt_dir, info["project_name"]) if dt_dir else None
    rows = None
    summ = None
    if sd and os.path.isdir(sd):
        st = os.path.join(sd, "scan", "status.tsv")
        if os.path.isfile(st):
            try:
                rows = read_status_tsv(st)
            except DtError as e:
                r["upload"] = "FAIL"; r["notes"].append(_cell(e))
        sj = os.path.join(sd, "summary.json")
        if os.path.isfile(sj):
            try:
                summ, _ = load_json(sj, MAX_BYTES, "summary.json")
            except DtError as e:
                r["notes"].append(_cell(e)); r["verify_fail"].append("summary.json 讀不到")
    if rows is None and summ is None and r["upload"] != "FAIL":
        r["notes"].append("沒有 DT 結果")
        r["status"] = "NOT_RUN"
        return r
    if rows is not None:
        r["upload"] = _worst([rows[x][0] if x in rows else "NOT_RUN" for x in UPLOAD_STAGES])
        fails = [k for k, v in rows.items() if v[0] == "FAIL"]
        if fails:
            r["notes"].append("sca-scan FAIL 階段：" + "、".join(_cell(x, 60) for x in sorted(fails)))
        g = rows.get("C-grype", ("NOT_RUN", ""))[0]
        r["grype"] = g
        gj = os.path.join(sd, "scan", "scan", "grype.json")   # sca-scan --out 是 <sd>/scan，Grype 結果在它的 scan/grype.json
        if g == "OK":
            try:
                gd, _ = load_json(gj, MAX_GRYPE_BYTES, "grype.json")
                m = gd.get("matches") if isinstance(gd, dict) else None
                if not isinstance(m, list):
                    raise DtError("grype.json 沒有 matches 陣列")
                r["grype_matches"] = len(m)
            except DtError as e:
                r["grype"] = "FAIL"; r["notes"].append(_cell(e))
    elif r["upload"] != "FAIL":
        r["notes"].append("沒有 scan/status.tsv：上傳狀態未知")
    if summ is not None:
        if isinstance(summ, dict):
            r["dt_components"] = summ.get("components", "?")
            r["dt_findings"] = summ.get("findings_total", "?")
            bad = [c.get("name") for c in summ.get("checks") or [] if isinstance(c, dict) and c.get("status") == "FAIL"]
            nr = [c.get("name") for c in summ.get("checks") or [] if isinstance(c, dict) and c.get("status") == "NOT_RUN"]
            r["verify_fail"] += [_cell(x, 60) for x in bad]
            if nr:
                r["notes"].append("dt-verify NOT_RUN：" + "、".join(_cell(x, 60) for x in nr))
        else:
            r["verify_fail"].append("summary.json 格式不對")
    else:
        r["notes"].append("沒有 dt-verify 的 summary.json")
    # 狀態
    if r["upload"] == "FAIL" or r["verify_fail"] or r["grype"] == "FAIL":
        st = "FAIL"
    elif wait_rc == 3 or "GAP" in (r["upload"], r["grype"]):
        st = "GAP"
    elif summ is None or rows is None or r["upload"] != "OK" or r["grype"] != "OK":
        st = "NOT_RUN" if r["upload"] == "NOT_RUN" else "GAP"
    elif s.get("version_gap") or s["with_purl"] < s["components"] or s["vuln_assessment"].get("NOT_ASSESSED"):
        st = "ATTENTION"
    else:
        st = "OK"
    if wait_rc == 3:
        r["notes"].append("dt-ephemeral wait 結束碼 3（資料不完整）：0 筆漏洞不能當成沒有漏洞")
    r["status"] = st
    return r


def vbios_assessment(root=None):
    """NVIDIA vBIOS 的公告對照說明：(狀態, 文字)。文字取自 C1 的 tools/pilot/lib/nvidia_bulletins.py（VBIOS_NOT_ASSESSED），不複製一份。
    載入失敗（檔案不存在、語法錯、沒有該常數）→ ("GAP", 原因)。載入的是本 repo 自己的程式（不是輸入資料）。"""
    import importlib.util
    base = root or os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
    path = os.path.join(base, "tools", "pilot", "lib", "nvidia_bulletins.py")
    try:
        if not os.path.isfile(path):
            return "GAP", "沒有 tools/pilot/lib/nvidia_bulletins.py（C1 的公告對照工具），NVIDIA 公告對照未評估"
        spec = importlib.util.spec_from_file_location("nvidia_bulletins_c1", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        text = getattr(mod, "VBIOS_NOT_ASSESSED", None)
        if not isinstance(text, str) or not text.strip():
            return "GAP", "nvidia_bulletins.py 沒有 VBIOS_NOT_ASSESSED 文字，NVIDIA 公告對照未評估"
        return "NOT_ASSESSED", text.strip()
    except Exception as e:   # 載入失敗一律寫 GAP，不讓報告中斷
        return "GAP", "無法載入 nvidia_bulletins.py（%s），NVIDIA 公告對照未評估" % type(e).__name__


def report(prep_dirs, dt_dir, out, nvidia_root=None):
    wait_rc = None
    if dt_dir:
        if not os.path.isdir(dt_dir):
            raise DtError("--dt-result 不是資料夾")
        p = os.path.join(dt_dir, "dt-wait.rc")
        if os.path.isfile(p):
            try:
                wait_rc = int(_read_limited(p, 64, "dt-wait.rc").decode().strip())
            except (ValueError, UnicodeDecodeError):
                raise DtError("dt-wait.rc 不是整數")
    lines, rows = [], []
    nv = None
    for d in prep_dirs:
        info = load_prep(d)
        res = sample_result(info, dt_dir, wait_rc)
        s = info["summary"]
        rows.append((info, res))
        va = "、".join("%s=%d" % kv for kv in sorted(s["vuln_assessment"].items()))
        detail = "DT 專案 %s@%s；元件 %d（purl %d、cpe %d）；上傳 %s；DT 元件 %s；漏洞 %s；Grype %s（%s）；NOT_ASSESSED 與版本 GAP：%s／%d" % (
            info["project_name"], info["project_version"], s["components"], s["with_purl"], s["with_cpe"], res["upload"],
            res["dt_components"], res["dt_findings"], res["grype"], res["grype_matches"], va, s["version_gap"])
        if info.get("kind") == "vbios":
            if nv is None:
                nv = vbios_assessment(nvidia_root)
            res["nvidia"] = "NVIDIA 公告對照：%s（%s）" % (nv[0], _cell(nv[1]))
            detail += "；" + res["nvidia"]
        if res["notes"]:
            detail += "；" + "；".join(res["notes"])
        if res["verify_fail"]:
            detail += "；dt-verify FAIL：" + "、".join(map(str, res["verify_fail"]))
        lines.append("FIRMWARE-DT\t%s\t%s" % (res["status"], detail.replace("\t", " ").replace("\n", " ")))
    os.makedirs(out, exist_ok=True)
    md = ["# 韌體 SBOM 上傳 DT 結果", "",
          "| 樣本 | DT 專案 | 元件數 | 上傳狀態 | DT 看到的元件數 | DT 漏洞數（參考） | Grype 比對（漏洞比對主要依據） | 狀態 |",
          "|---|---|---|---|---|---|---|---|"]
    for info, res in rows:
        g = res["grype"] if res["grype"] != "OK" else "OK（%s 筆）" % res["grype_matches"]
        md.append("| %s | %s@%s%s | %d | %s | %s | %s | %s | %s |" % (
            _cell(info["slug"]), _cell(info["project_name"]), _cell(info["project_version"]),
            "（合成）" if info.get("synthetic") else "", info["summary"]["components"], res["upload"],
            res["dt_components"], res["dt_findings"], g, res["status"]))
    md += ["", "## 怎麼讀", "",
           "- **漏洞數 0 筆不代表沒有漏洞。** 臨時 DT 只開 OSV、KEV（NVD 關閉），只比對有 purl 的元件，`pkg:github/...` 與只有 CPE 的元件在 DT 完全比對不到；"
           "DT 在這裡只負責收件與留存，韌體的漏洞比對以 Grype（sca-scan 的 C-grype）為主。沒有 purl 也沒有 CPE 的元件 Grype 也比對不到，"
           "但 C-grype 仍會顯示 OK（比對完成），所以要看每個元件的 `dumpling:vuln-assessment`：Intel（ME、微碼、FSP、GOP／VBT）與 NVIDIA 元件為 NOT_ASSESSED（公告無法機器比對，需公告對照）。",
           "- 上傳狀態 NOT_RUN＝沒有 DT 結果（沒起 DT 或沒跑到上傳）；GAP＝資料不完整（例如 DT 鏡像 wait 結束碼 3），不能當成沒有漏洞。",
           "- 狀態 OK 只表示：上傳與驗證都完成，且每個元件都有 purl、沒有版本 GAP、沒有 NOT_ASSESSED；ATTENTION 表示完成但仍有元件沒有資料可比對。這份報告沒有整體通過或安全的結論。",
           "", "## 每個樣本的摘要", ""]
    for info, res in rows:
        s = info["summary"]
        md.append("### %s" % _cell(info["slug"]))
        md.append("")
        md.append("- 元件 %d，有 purl %d，有 cpe %d，vuln-assessment：%s，version-status GAP %d" % (
            s["components"], s["with_purl"], s["with_cpe"],
            "、".join("%s=%d" % kv for kv in sorted(s["vuln_assessment"].items())) or "無", s["version_gap"]))
        if res.get("nvidia"):
            md.append("- " + res["nvidia"])   # 文字取自 C1 的 nvidia_bulletins.py，已經過 _cell
        for n in res["notes"]:
            md.append("- " + n)               # notes／verify_fail 在產生時已經過 _cell
        if res["verify_fail"]:
            md.append("- dt-verify FAIL：" + "、".join(res["verify_fail"]))
        md.append("")
    with open(os.path.join(out, "firmware-dt.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(md))
    return lines, any(r["status"] == "FAIL" for _, r in rows)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="firmware_dt.py", allow_abbrev=False)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("prep", allow_abbrev=False)
    p.add_argument("--sbom", required=True); p.add_argument("--sample", required=True); p.add_argument("--out", required=True)
    p.add_argument("--synthetic", action="store_true")
    e = sub.add_parser("expected", allow_abbrev=False)
    e.add_argument("--prep", required=True)
    r = sub.add_parser("report", allow_abbrev=False)
    r.add_argument("--prep", nargs="+", required=True); r.add_argument("--dt-result"); r.add_argument("--out", required=True)
    r.add_argument("--repo-root", help="找 tools/pilot/lib/nvidia_bulletins.py 的根資料夾（預設本檔往上兩層；測試用）")
    try:
        a = ap.parse_args(argv)
    except SystemExit as e:
        return 64 if e.code else 0
    try:
        if a.cmd == "prep":
            info = prep(a.sbom, a.sample, a.out, a.synthetic)
            s = info["summary"]
            print("FIRMWARE-DT-PREP\tOK\t%s@%s；元件 %d、purl %d、cpe %d、version-status GAP %d" % (
                info["project_name"], info["project_version"], s["components"], s["with_purl"], s["with_cpe"], s["version_gap"]))
        elif a.cmd == "expected":
            exp, _ = expected(a.prep)
            print("FIRMWARE-DT-EXPECTED\tOK\t%s@%s；元件 %d" % (exp["project_name"], exp["project_version"], exp["components"]))
        else:
            lines, failed = report(a.prep, a.dt_result, a.out, a.repo_root)
            print("\n".join(lines))
            return 1 if failed else 0
    except DtError as ex:
        print("FIRMWARE-DT-%s\tFAIL\t%s" % (a.cmd.upper(), str(ex).replace("\n", " ").replace("\t", " ")))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
