#!/usr/bin/env python3
"""韌體 SBOM 上傳臨時 DT 前後的資料處理（只用標準庫與 PyYAML；輸入一律當不可信資料）。

子指令：
  prep     --sbom <fw.cdx.json> --sample <firmware.yml> --out <資料夾> [--synthetic]
           產出 <out>/sbom.cdx.json（要上傳的 SBOM）與 <out>/dt-project.json（DT 專案名稱、版本、摘要）。
           kind: sbom（供應商 SBOM）另做上傳前的最小格式正規化（只改這份副本；規則見 firmware_sbom_normalize.py），
           紀錄寫在 <out>/normalize.json，report 會註明「已正規化 N 處」。
  expected --prep <資料夾>
           在 prep 資料夾寫 expected.json（給 pipeline/dt-verify.py verify；格式依 C1 目前版本）與
           firmware-dt-expected.json（我們自己的、與 DT 工具介面無關的預期）。
  report   --prep <資料夾>... [--dt-result <資料夾>] --out <資料夾>
           寫 <out>/firmware-dt.md，每個樣本印一行 FIRMWARE-DT<TAB>OK|ATTENTION|GAP|NOT_RUN|FAIL|MISMATCH<TAB>…

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
STATUSES = ("OK", "ATTENTION", "GAP", "NOT_RUN", "FAIL", "MISMATCH")
# firmware.yml 的 expected_dt：樣本自己宣告 DT 的預期結果（目前只有 upload: rejected＝DT 會拒收這份 SBOM，例如供應商 SBOM 不符 CycloneDX schema）
EXPECTED_DT_KEYS = ("upload", "reason")
# 宣告 rejected 且真的被拒收時，上傳之前的這些階段仍要是 OK（其餘階段都在上傳之後，被拒收就不會有結果）
# DT 對「BOM 不符 schema」的 400 回應開頭（DT 5.2.0 實測：sca-scan 的 D-dt-upload 說明是「http=400 」加回應的前 200 bytes）。
# 只有這個開頭才算 expected_dt 的拒收；其他 400（例如 projectName must not be blank，是 dumpling 自己的參數錯誤）一律一般 FAIL。
# DT 改了訊息時，這裡會比對不到 → 被拒收的樣本變成一般 FAIL（安全的方向），屆時依新回應更新。
BOM_INVALID_RE = re.compile(r'^http=400 \{"status":400,"title":"The uploaded BOM is invalid","detail":"Schema validation failed"[,}]')
REJECT_PRE_OK = ("A-source", "B-sandbox", "B-sandbox-secrets", "B-sbom-provided", "C-grype", "C-upload-sbom", "D-dt-project", "F-secret-scan")
# firmware-dt.sh 要求 sca-scan 產生而且是 OK 的 11 個階段（和該檔的 need 預設清單相同，測試核對）。report 的 OK 也要求每一列都存在：
# status.tsv 缺任何一列（階段沒跑、被刪）＝資料不完整，至少 GAP，不能因為「沒有看到不好的列」就是 OK。
REQUIRED_STAGES = ("A-source", "B-sandbox", "B-sandbox-secrets", "B-sbom-provided", "C-grype", "C-upload-sbom",
                   "D-dt-project", "D-dt-upload", "D-dt-bom-processing", "D-dt-vuln-analysis", "F-secret-scan")
# 被拒收的直接後果：dt-verify 這兩項（沒有上傳成功就沒有分析、沒有元件）；名稱取自 C1 的 dt-verify.py
REJECT_VERIFY_NAMES = ("弱點分析完成", "元件數")
# dt-verify 的檢查名（取自 C1 的 pipeline/dt-verify.py verify；介面改了要跟著改）。OK 之前這四項都要存在而且是 OK：
# 「依生態系的漏洞數」只在有下限時才有意義（我們的下限是 0），不列為必要；但它若 FAIL／NOT_RUN／狀態不認得，仍照下面的規則處理。
REQUIRED_VERIFY_CHECKS = ("專案存在", "弱點分析完成", "元件數", "漏洞總數")
VERIFY_STATUSES = ("OK", "FAIL", "NOT_RUN")        # dt-verify 只會寫這三種；其他值＝不認得
STAGE_STATUSES = ("OK", "ATTENTION", "GAP", "NOT_ASSESSED", "FAIL", "NOT_RUN")    # sca-scan status.tsv 的狀態（sca-scan 檔頭）
# sca-scan 的 NOT_RUN 階段，這幾類是 firmware-dt.sh 自己的呼叫方式造成的、與漏洞資料完整性無關，不列入「其他階段不是 OK」：
#   E-*（授權與版權：firmware-dt.sh 固定帶 --no-license，sca-scan 因此把整個 E 段記 NOT_RUN，detail 是 --no-license）、
#   C-kernel-config、C-kernel-module-map（沒給 --kernel-build：韌體 SBOM 沒有產品核心的 .config 可判定）。
# 其餘 NOT_RUN（C-mirror-freshness 沒檢查鏡像新鮮度、DT 的資料源／發現列、EUVD…）代表「該做的檢查沒做」，一律列入，不能顯示 OK。
EXPECTED_NOT_RUN_PREFIXES = ("E-",)
EXPECTED_NOT_RUN_STAGES = ("C-kernel-config", "C-kernel-module-map")
MAX_DUP_EVENTS = 1000                 # 重複鍵逐筆記錄（含前值的 sha256）的上限；超過只計數
MAX_DUP_NOTES = 50                    # 寫進 normalize.json notes 的重複鍵筆數上限
VA_KEY = "dumpling:vuln-assessment"
VS_KEY = "dumpling:version-status"
VA_NONE = "NONE"                      # 唯一放行值：已評估、沒有已知漏洞（現有的 dumpling 工具從不寫它：x86_firmware.assessed() 只寫 NOT_ASSESSED）
VA_NOT_ASSESSED = "NOT_ASSESSED"
UNSET = "(未標)"
OTHER = "(不認得的值)"


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


POINTER_CAP = 300       # 重複鍵事件的位置最多 300 字元（鍵名沒有長度上限）；超過時截斷並以 POINTER_MARK 結尾
POINTER_MARK = "…"


def _ptr_join(path, trunc, seg):
    """JSON Pointer（RFC 6901）接上一段，回傳 (新路徑, 是否已截斷)。已截斷就不再延伸；超過 POINTER_CAP 字元時留前 POINTER_CAP-1 字元
    （不把轉義切一半：結尾若是單獨的 "~" 就去掉）。每一段只轉義前 POINTER_CAP 字元，所以處理量不隨鍵長增加。路徑不含截斷標記（由呼叫端加）。"""
    if trunc:
        return path, True
    new = path + "/" + str(seg)[:POINTER_CAP].replace("~", "~0").replace("/", "~1")
    if len(new) <= POINTER_CAP:
        return new, False
    new = new[:POINTER_CAP - 1]
    if new.endswith("~"):                # 轉義的第一個字元；完整的轉義是 ~0／~1
        new = new[:-1]
    return new, True


class DupKeys:
    """json.loads 的 object_pairs_hook：偵測同一個物件裡的重複鍵（標準庫預設後值悄悄蓋掉前值）。
    只做偵測，回傳的物件和預設一樣（後值取代前值，鍵的順序是第一次出現的位置）。
    events：每筆 {object_index, key_json, dropped_value_sha256, pointer}（上限 MAX_DUP_EVENTS 筆），total：總數。
    object_index＝解析器「完成」物件的順序（從 1 起算；內層物件先完成）；pointer 在解析完成後由 locate() 補
    （被丟掉的前值裡的物件不在最終文件裡，找不到位置，留 None）。"""

    def __init__(self):
        self.n = 0
        self.total = 0
        self.events = []
        self._objs = []                # (dict, event)：保住物件，id 才不會被重用

    def hook(self, pairs):
        self.n += 1
        d = {}
        for k, v in pairs:
            if k in d:
                self.total += 1
                if len(self.events) < MAX_DUP_EVENTS:
                    ev = {"object_index": self.n, "key_json": json.dumps(k, ensure_ascii=True)[:130],
                          "dropped_value_sha256": _norm_mod().canonical_sha256(d[k]), "pointer": None}
                    self.events.append(ev)
                    self._objs.append((d, ev))
            d[k] = v
        return d

    def locate(self, doc):
        """補上每筆事件的物件在最終文件裡的 JSON Pointer。深度優先、用 iterator 逐層走（記憶體 O(深度)，不把整個陣列的子節點一次推進堆疊），
        位置字串只在走進容器時組一次、並邊走邊截斷（見 _ptr_join）；事件都找到了就停。深度已先檢查過（MAX_DEPTH）。"""
        if not self._objs:
            return
        want = {}
        for d, ev in self._objs:
            want.setdefault(id(d), []).append(ev)

        def enter(o, path, trunc):
            """走進一個容器：登記它的事件，回傳 (子節點 iterator, 路徑, 已截斷)。"""
            if isinstance(o, dict):
                for ev in want.pop(id(o), ()):
                    ev["pointer"] = (path or "/") + (POINTER_MARK if trunc else "")
                return iter(o.items()), path, trunc
            return enumerate(o), path, trunc

        stack = [enter(doc, "", False)] if isinstance(doc, (dict, list)) else []
        while stack and want:
            it, path, trunc = stack[-1]
            for key, child in it:
                if isinstance(child, (dict, list)):
                    cp, ct = _ptr_join(path, trunc, key)
                    stack.append(enter(child, cp, ct))
                    break
            else:
                stack.pop()


def load_json(path, limit, what, dups=None):
    raw = _read_limited(path, limit, what)
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=dups.hook if dups is not None else None)
    except (ValueError, RecursionError) as e:
        raise DtError("%s 不是合法 JSON（%s）" % (what, type(e).__name__))
    if not _depth_ok(doc):
        raise DtError("%s 的 JSON 巢狀超過 %d 層" % (what, MAX_DEPTH))
    if dups is not None:
        dups.locate(doc)
    return doc, raw


def load_json_nodup(path, limit, what):
    """讀 DT／Grype 的結果檔：同一個物件有重複鍵（後值蓋掉前值，檔案的意思不明）一律拒絕，不採信。"""
    dups = DupKeys()
    doc, raw = load_json(path, limit, what, dups)
    if dups.total:
        raise DtError("%s 有 %d 個重複鍵（同名的後值會蓋掉前值，不採信）" % (what, dups.total))
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
    return s if VERSION_RE.fullmatch(s or "!") else "unknown"


def project_name(kind, slug, synthetic):
    """名稱：firmware-<kind>-<slug>；合成樣本：firmware-<kind>-synthetic-<slug>。"""
    n = "firmware-%s-%s%s" % (kind, "synthetic-" if synthetic else "", slug)
    n = n[:100].rstrip("-._")
    if not NAME_RE.fullmatch(n):
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


def _prop_values(c, name):
    """元件 properties 裡所有名稱「完全等於」name 的值（同名可有多個）。值不是字串（含沒有 value 鍵）記成 None。"""
    props = c.get("properties")
    out = []
    if isinstance(props, list):
        for p in props:
            if isinstance(p, dict) and p.get("name") == name:
                v = p.get("value")
                out.append(v if isinstance(v, str) else None)
    return out


def _props(c):
    """名稱 → 第一個值（字串）。只給「值只有一種合理讀法」的用途（來源檔名等）；dumpling:* 標記用 _prop_values 全部檢查。"""
    out = {}
    props = c.get("properties")
    for p in props if isinstance(props, list) else []:
        if isinstance(p, dict) and isinstance(p.get("name"), str):
            out.setdefault(p["name"], str(p.get("value", "")))
    return out


def identity(c):
    """DT 合併元件的身分：group、name、version、purl、cpe。**不含 hashes**：本機端到端（DT 5.2.0）實測，
    只有雜湊不同的元件（例如同版本的兩個 FSP-M 映像）DT 仍合併成一個。"""
    return (c.get("group") or "", c.get("name") or "", c.get("version") or "", c.get("purl") or "", c.get("cpe") or "")


PURL_RE = re.compile(r"^pkg:/*([A-Za-z0-9.+-]+)/", re.I)     # 容許 pkg://generic/、pkg:/generic/（packageurl 規格的解析器會去掉 scheme 後的斜線）


def purl_type(purl):
    """purl 的類型（小寫）。先 strip；不是字串、或不符 `pkg:<type>/`（不分大小寫）回 None＝視同沒有 purl
    （例如 `x`、`generic/x`、`pkg:generic`、空白）。`PKG:GENERIC/x`、` pkg:generic/x`、`pkg://generic/x` 都是 generic。"""
    if not isinstance(purl, str):
        return None
    m = PURL_RE.match(purl.strip())
    return m.group(1).lower() if m else None


def classify_va(values):
    """dumpling:vuln-assessment 的值 → UNSET｜NONE｜NOT_ASSESSED｜OTHER。只有「所有」同名標記都完全等於 NONE 才是 NONE；
    其他任何值（not_assessed、前後有空白、garbage、OK、非字串）都不是放行值，同名有多個時只要任一個不是 NONE 就算。"""
    if not values:
        return UNSET
    if all(v == VA_NONE for v in values):
        return VA_NONE
    return VA_NOT_ASSESSED if any(v == VA_NOT_ASSESSED for v in values) else OTHER


def classify_vs(values):
    """dumpling:version-status 的值 → None（沒標）｜OK｜GAP｜OTHER。只認完全相同的 OK／GAP；同名多個時有 GAP 就 GAP，其餘只要有不是 OK 的就 OTHER。"""
    if not values:
        return None
    if any(v == "GAP" for v in values):
        return "GAP"
    return "OK" if all(v == "OK" for v in values) else OTHER


AM_KEY = "dumpling:advisory-match"
AM_VALUES = ("affected-candidate", "older-no-sa", "up-to-date", "NOT_ASSESSED", "affected", "fixed")     # x86_firmware.py 會寫的值（微碼；後兩個是 NVIDIA vBIOS）


def classify_am(values):
    """dumpling:advisory-match 的值 → None（沒標）｜AM_VALUES 之一｜(多個值)｜(不認得的值)。只用來計數顯示，不影響 OK／ATTENTION；
    不認得的值（含非字串、供應商或舊工具亂填）不原樣進報告。"""
    if not values:
        return None
    if len(set(values)) != 1:
        return "(多個值)"
    return values[0] if values[0] in AM_VALUES else "(不認得的值)"


def _nonblank(v):
    return isinstance(v, str) and v.strip() != ""


FIELD_STR = ("group", "name", "version", "purl", "cpe")


def check_component_types(comps):
    """元件欄位的型別檢查（fail-closed）：group／name／version／purl／cpe 必須是字串（或沒有／null），properties 必須是陣列（或沒有／null）。
    不符合 CycloneDX（DT 也會拒收），而且後面的計數與身分比對都假設是字串；不猜、不轉型，直接 DtError，訊息寫明第幾個元件、哪個欄位。"""
    for i, c in enumerate(comps, 1):
        if not isinstance(c, dict):
            raise DtError("第 %d 個元件不是物件" % i)
        for f in FIELD_STR:
            if c.get(f) is not None and not isinstance(c[f], str):
                raise DtError("第 %d 個元件（%s）的 %s 不是字串（型別 %s）" % (i, _cell(c.get("name"), 40), f, type(c[f]).__name__))
        if c.get("properties") is not None and not isinstance(c["properties"], list):
            raise DtError("第 %d 個元件（%s）的 properties 不是陣列（型別 %s）" % (i, _cell(c.get("name"), 40), type(c["properties"]).__name__))


def summarize(comps, trust_markers=True):
    """元件摘要。trust_markers=False（kind: sbom，供應商 SBOM）：不採信 SBOM 自帶的 dumpling: 標記（供應商可以自己塞），
    一律當作沒標，另記有多少元件帶了這些標記（supplier_markers）。"""
    check_component_types(comps)
    s = {"components": 0, "with_purl": 0, "bad_purl": 0, "with_cpe": 0, "distinct_identities": 0,
         "vuln_assessment": {}, "version_status": {}, "version_gap": 0, "version_status_other": 0,
         "no_version": 0, "no_version_unmarked": 0, "purl_types": [], "advisory_match": {}, "trust_markers": bool(trust_markers), "supplier_markers": 0}
    ids, types = set(), set()
    for c in comps:
        s["components"] += 1
        purl = c.get("purl")
        if _nonblank(purl):
            t = purl_type(purl)
            if t is None:
                s["bad_purl"] += 1            # 有 purl 欄位但格式不合：視同沒有 purl（不計入 with_purl）
            else:
                s["with_purl"] += 1
                types.add(t)
                if t == "generic":
                    s["generic_purl"] = s.get("generic_purl", 0) + 1
        if _nonblank(c.get("cpe")):
            s["with_cpe"] += 1
        ids.add(identity(c))
        va, vs, am = _prop_values(c, VA_KEY), _prop_values(c, VS_KEY), _prop_values(c, AM_KEY)
        if not trust_markers:
            if va or vs or am:
                s["supplier_markers"] += 1
            va, vs, am = [], [], []
        al = classify_am(am)
        if al is not None:
            s["advisory_match"][al] = s["advisory_match"].get(al, 0) + 1
        vl = classify_va(va)
        s["vuln_assessment"][vl] = s["vuln_assessment"].get(vl, 0) + 1
        sl = classify_vs(vs)
        if sl is not None:
            s["version_status"][sl] = s["version_status"].get(sl, 0) + 1
        if sl == "GAP":
            s["version_gap"] += 1
        elif sl == OTHER:
            s["version_status_other"] += 1
        if not _nonblank(c.get("version")):
            s["no_version"] += 1
            if sl != "GAP":              # 沒有 version 又沒有 GAP 標記：缺漏沒有被工具記錄下來
                s["no_version_unmarked"] += 1
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


_NORM = []


def _norm_mod():
    # python3 -I 不把腳本所在資料夾放進 sys.path，用路徑載入同資料夾的模組（和 firmware_mdsafe 一樣）；只載入一次
    if not _NORM:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "firmware_sbom_normalize", os.path.join(os.path.dirname(os.path.abspath(__file__)), "firmware_sbom_normalize.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _NORM.append(mod)
    return _NORM[0]


def dumps_json(obj, what):
    """序列化成要寫檔的文字，並確認能編碼成 UTF-8。單獨代理字元（\\ud800）json.dumps 不會失敗，但寫檔時才 UnicodeEncodeError——
    那時別的檔可能已經寫出去了。所以 prep 先把所有檔案序列化完，全部成功才寫；失敗變成 DtError（清楚的 FAIL 行），不留半套輸出。"""
    try:
        s = json.dumps(obj, ensure_ascii=False, indent=1) + "\n"
        s.encode("utf-8")
    except UnicodeEncodeError:
        raise DtError("%s 含不能編碼成 UTF-8 的字元（單獨代理字元，例如 \\ud800）：上傳副本無法寫出，整個樣本不上傳" % what)
    except (TypeError, ValueError, RecursionError) as e:
        raise DtError("%s 無法序列化（%s）" % (what, type(e).__name__))
    return s


def write_json(path, obj):
    write_text(path, dumps_json(obj, os.path.basename(path)))


def write_text(path, text):
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
    except OSError as e:
        raise DtError("%s 寫不出去：%s" % (os.path.basename(path), e.strerror))


def parse_expected_dt(v):
    """firmware.yml 的 expected_dt：None 或 {upload: rejected, reason: 非空字串}；其他一律 DtError（打錯字不能悄悄放行）。"""
    if v is None:
        return None
    if not isinstance(v, dict):
        raise DtError("expected_dt 必須是 mapping")
    for k in v:
        if k not in EXPECTED_DT_KEYS:
            raise DtError("expected_dt 有不認得的鍵 %s（可用：%s）" % (k, "、".join(EXPECTED_DT_KEYS)))
    if v.get("upload") != "rejected":
        raise DtError("expected_dt.upload 目前只能是 rejected")
    r = v.get("reason")
    if not isinstance(r, str) or not r.strip() or len(r) > 600:
        raise DtError("expected_dt.reason 必須是 1～600 字的依據說明")
    return {"upload": "rejected", "reason": r.strip()}


def dup_notes(dups):
    """重複鍵的說明（寫進 normalize.json 的 notes）：第幾個物件、哪個鍵、丟掉的前值的 sha256。"""
    out = []
    for ev in dups.events[:MAX_DUP_NOTES]:
        out.append("輸入 SBOM 有重複鍵：第 %d 個完成解析的物件%s，鍵 %s，被丟掉的前值 sha256=%s（後值取代前值；上傳副本只剩後值）" % (
            ev["object_index"], "（位置 %s）" % ev["pointer"] if ev["pointer"] else "（在被丟掉的前值裡，沒有位置）",
            ev["key_json"], ev["dropped_value_sha256"] or "無法計算"))
    if dups.total > MAX_DUP_NOTES:
        out.append("重複鍵共 %d 筆，以上只列前 %d 筆" % (dups.total, MAX_DUP_NOTES))
    return out


def renamed_count(norm):
    """正規化紀錄裡「供應商自帶的 dumpling: 開頭 property 被改名」的筆數。"""
    nm = _norm_mod()
    return sum(1 for c in norm["changes"] if c.get("rule") == nm.RULE_RESERVED)


def supplier_props_text(n, left=0, unprocessed=False):
    """供應商自帶 dumpling: 開頭的 property 的說明（固定文字加數字；`*`、`_` 的名稱放在行內程式碼裡，不被渲染成斜體）。
    n＝全部個數（已改名加沒改名），left＝因為超過變更筆數上限等原因沒改名、上傳副本仍帶著的個數；
    unprocessed＝整份 SBOM 沒有正規化（specVersion 不在支援範圍、metadata.properties 型別不對、規劃失敗），所以一個都沒有改名（left 等於 n）。"""
    ns = ("那是我們自己的命名空間：`dumpling:normalized-*`、`dumpling:supplier-*` 是正規化的紀錄，`dumpling:vuln-assessment` 等是評估標記；供應商可以自己塞")
    if unprocessed:
        return ("供應商 SBOM 自帶名稱以 dumpling: 開頭的 property %d 個：這份 SBOM 沒有正規化（specVersion 不在支援範圍、metadata.properties 型別不對或規劃失敗，原因見 normalize.json 的 notes），"
                "所以一個都沒有改名，上傳副本仍帶有這些 dumpling: 開頭的供應商 property（%s）" % (n, ns))
    if left > 0:
        return ("供應商 SBOM 自帶名稱以 dumpling: 開頭的 property %d 個：%d 個已改名成 `supplier:dumpling:…`、%d 個超過變更筆數上限沒有改名"
                "（上傳副本仍帶有 dumpling: 開頭的供應商 property；原名、位置與值的 SHA-256 見 normalize.json，沒改名的另見 unnormalized）（%s）" % (n, n - left, left, ns))
    return ("供應商 SBOM 自帶名稱以 dumpling: 開頭的 property %d 個（%s，所以上傳副本已改名成 `supplier:dumpling:…`，原名、位置與值的 SHA-256 見 normalize.json）" % (n, ns))


def dup_text(n):
    return ("輸入 SBOM 有 %d 個重複鍵（JSON 解析時後值取代前值，上傳的副本只剩後值；明細見 normalize.json 的 notes 或 dt-project.json 的 duplicate_keys）" % n)


def _short_str(v, n=300):
    """紀錄用：字串留前 n 字元，其他型別（含沒有）記 None。"""
    return v[:n] if isinstance(v, str) else None


def prep(sbom_path, sample_path, out, synthetic=False):
    # 重複鍵：標準庫的 json 預設悄悄用後值蓋掉前值；供應商可以用這個讓人看到的內容和上傳的內容不同，所以一律偵測、記錄，狀態至少 ATTENTION
    dups = DupKeys()
    doc, raw = load_json(sbom_path, MAX_BYTES, "SBOM", dups)
    if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX" or not doc.get("specVersion"):
        raise DtError("不是 CycloneDX JSON（沒有 bomFormat／specVersion）")
    comps_raw = doc.get("components")
    if not isinstance(comps_raw, list):
        raise DtError("components 不是陣列")
    sample = load_sample(sample_path)
    kind = sample.get("kind")
    expected_dt = parse_expected_dt(sample.get("expected_dt"))
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
    check_component_types(comps)
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
    # 供應商 SBOM（kind: sbom）上傳前的最小格式正規化：只改上傳用的副本，原檔不動；規則與紀錄格式見 firmware_sbom_normalize.py。
    # 其他 kind（本工具自己產的 SBOM）不處理；舊的 normalize.json 不能留著混進這次的 artifact。
    input_sha = hashlib.sha256(raw).hexdigest()
    # 摘要要在正規化之前算：正規化會把供應商自帶的 dumpling: 開頭的 property 改名（元件 dict 與原檔共用，改名後就數不到了）。
    # kind: sbom（供應商 SBOM）自帶的 dumpling: 標記不採信（trust_markers=False）：供應商可以自己塞，一律當作沒標
    summary = summarize(comps, trust_markers=(kind != "sbom"))
    summary["duplicate_keys"] = dups.total
    norm = None
    if kind == "sbom":
        nm = _norm_mod()
        norm = nm.normalize(out_doc, input_sha)
        # 副本的 metadata／metadata.properties 一律是物件／陣列；原檔「沒有這個鍵」「null」「空陣列」在副本裡分不出來，所以在這裡記原本的狀態
        # （prep 在呼叫前已把 metadata 換成含根元件的副本，所以從原始 doc 取）
        norm["original_shape"] = {"metadata": nm.key_state(doc, "metadata"),
                                  "metadata.properties": nm.key_state(doc.get("metadata"), "properties")}
        norm["notes"] = list(norm.get("notes") or []) + dup_notes(dups)
    if norm:
        summary["supplier_dumpling_props"] = renamed_count(norm) + norm["reserved_not_renamed"]     # 全部（已改名加沒改名）
        summary["supplier_dumpling_props_left"] = norm["reserved_not_renamed"]
        summary["supplier_dumpling_props_unprocessed"] = not norm["processed"]
    # 先把所有要寫的檔案序列化完（失敗就什麼都不寫，不會留下只有一半的輸出），全部成功才寫檔。
    sbom_text = dumps_json(out_doc, "上傳用 SBOM")
    sbom_sha = hashlib.sha256(sbom_text.encode("utf-8")).hexdigest()
    norm_text = dumps_json(norm, "normalize.json") if norm is not None else None
    info = {
        "project_name": name, "project_version": version, "kind": kind, "slug": slug,
        "synthetic": is_synth, "synthetic_reasons": synth_reasons, "expected_dt": expected_dt,
        "firmware_name": fw_name, "firmware_version": sample.get("firmware_version"),
        "sbom_file": "sbom.cdx.json", "sbom_sha256": sbom_sha, "input_sbom_sha256": input_sha,
        "normalize": ({"file": "normalize.json", "applied": norm["applied"], "changes": len(norm["changes"]),
                       "unnormalized": norm["unnormalized_total"], "renamed": renamed_count(norm),
                       "not_renamed": norm["reserved_not_renamed"], "processed": norm["processed"]} if norm else None),
        "duplicate_keys": ({"count": dups.total, "listed": len(dups.events),
                            "events": [{k: ev[k] for k in ("object_index", "pointer", "key_json", "dropped_value_sha256")} for ev in dups.events[:MAX_DUP_NOTES]]}
                           if dups.total else None),
        "replaced_metadata_component": ({"name": _short_str(old.get("name")), "version": _short_str(old.get("version")), "purl": _short_str(old.get("purl"))} if isinstance(old, dict) else None),
        "summary": summary,
    }
    info_text = dumps_json(info, "dt-project.json")
    try:
        os.makedirs(out, exist_ok=True)
    except OSError as e:
        raise DtError("輸出資料夾建不起來：%s" % e.strerror)
    norm_path = os.path.join(out, "normalize.json")
    if norm_text is None and os.path.lexists(norm_path):
        try:
            os.unlink(norm_path)
        except OSError as e:
            raise DtError("舊的 normalize.json 刪不掉：%s" % e.strerror)
    written = []
    try:
        # dt-project.json 最後寫：有它才算 prep 完成；中途失敗把已寫的檔清掉，不留半套
        for fname, text in (("normalize.json", norm_text), ("sbom.cdx.json", sbom_text), ("dt-project.json", info_text)):
            if text is not None:
                write_text(os.path.join(out, fname), text)
                written.append(os.path.join(out, fname))
    except DtError:
        for w in written:
            try:
                os.unlink(w)
            except OSError:
                pass
        raise
    return info


# ---------- expected ----------

def load_prep(d):
    info, _ = load_json(os.path.join(d, "dt-project.json"), MAX_BYTES, "dt-project.json")
    if not isinstance(info, dict) or not all(k in info for k in ("project_name", "project_version", "summary")):
        raise DtError("dt-project.json 欄位不齊：%s" % os.path.basename(d.rstrip("/")))
    if not NAME_RE.fullmatch(str(info["project_name"])) or not VERSION_RE.fullmatch(str(info["project_version"])):
        raise DtError("dt-project.json 的名稱或版本不安全")
    parse_expected_dt(info.get("expected_dt"))
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
    trust = s.get("trust_markers", True)      # 供應商 SBOM 自帶的 dumpling: 標記不採信（和 summarize 一致）
    for c in comps:
        if purl_type(c.get("purl")) is None:   # 格式不合的 purl 視同沒有 purl（和 summarize 一致）
            reason = "no-purl-cpe-only（OSV 不比對 CPE；臨時 DT 關閉 NVD）" if _nonblank(c.get("cpe")) else "no-purl-no-cpe"
            no_data.append({"bom-ref": c.get("bom-ref"), "name": c.get("name"), "version": c.get("version"),
                            "reason": reason, "vuln_assessment": classify_va(_prop_values(c, VA_KEY)) if trust else UNSET})
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


def _mdsafe():
    if not _MDSAFE:
        _MDSAFE.append(_load_mdsafe())
    return _MDSAFE[0]


def _cell(s, limit=300):
    """寫進 markdown 或狀態行的不可信文字（dt-verify／sca-scan 的檢查名與階段名、錯誤訊息、樣本名…）：一律經共用的 md_safe。
    只在文字產生時呼叫一次（notes、verify_fail 存的就是清理過的），輸出 markdown 時不要再呼叫，否則會跳脫兩次。"""
    return _mdsafe().md_safe(s, limit)


_SEV = {"OK": 0, "ATTENTION": 2, "NOT_ASSESSED": 3, "NOT_RUN": 4, "GAP": 5, "FAIL": 6}


def _sev(st):
    return _SEV.get(st, 1)       # 不認得的狀態：比 OK 嚴重


EMPTY_STAGE = "(空的階段名稱)"


def read_status_tsv_checked(path):
    """(rows, anomalies)。rows：stage → (status, detail)，同一個階段出現多列時留「最嚴重」的那一列（不是最後一列：前面的 FAIL 不能被後面的 OK 蓋掉）。
    anomalies：{"duplicates": {階段: 列數（>= 2）}, "empty_rows": 階段名稱看不到內容的列數（firmware_mdsafe.is_blank：空、空白、零寬字元、控制字元、Hangul filler 等）}。這兩種在 sca-scan 的正常輸出不會出現（每個階段一列、都有名稱），
    出現就代表檔案被改過或工具有 bug；即使採最嚴重那一列後狀態是 OK，report 也不能當作沒看到（見 stage_anomaly_notes）。"""
    raw = _read_limited(path, MAX_BYTES, "status.tsv").decode("utf-8", "replace")
    rows, count, empty = {}, {}, 0
    try:
        for r in csv.DictReader(raw.splitlines(), delimiter="\t", quoting=csv.QUOTE_NONE):
            stage = r.get("stage")
            if stage is None:
                continue
            if _mdsafe().is_blank(stage):   # 階段名稱看不到內容（空、只有空白、零寬字元、控制字元、Hangul filler…）的列不丟掉（不然空名稱的 FAIL 會被略過而得到 OK）：當成一個不認得的階段照常判定
                stage = EMPTY_STAGE
                empty += 1
            else:
                count[stage] = count.get(stage, 0) + 1
            new = (r.get("status") or "", r.get("detail") or "")       # 不 strip：" OK" 不是 OK（scan-status-check.py 也是完全相等才算）
            old = rows.get(stage)
            if old is None or _sev(new[0]) >= _sev(old[0]):
                rows[stage] = new
    except csv.Error as e:
        raise DtError("status.tsv 格式不對（%s）" % type(e).__name__)
    return rows, {"duplicates": {k: n for k, n in count.items() if n > 1}, "empty_rows": empty}


def read_status_tsv(path):
    return read_status_tsv_checked(path)[0]


def stage_anomaly_notes(an):
    """status.tsv 的重複列與空名稱列 → 說明文字（沒有就回空清單）。階段名稱是不可信文字，經 _cell。
    判定：這兩種不改變各階段的狀態（仍取最嚴重的一列），但狀態是 OK 時降成 ATTENTION（attention_reasons）；其他狀態只加這則說明。
    理由：sca-scan 每個階段只寫一列，重複列或沒有名稱的列代表檔案被改過或寫檔有 bug，有人看過之前不能顯示 OK。"""
    out = []
    dups = sorted((an or {}).get("duplicates", {}).items())
    if dups:
        out.append("status.tsv 有重複列：%s（同一階段多列時 report 只採最嚴重的一列；`scan-status-check.py` 是後值蓋前值，兩邊可能不一致）" % "、".join(
            "階段 %s %d 列" % (_cell(k, 60), n) for k, n in dups[:20]) + ("…另 %d 個階段" % (len(dups) - 20) if len(dups) > 20 else ""))
    if (an or {}).get("empty_rows"):
        out.append("status.tsv 有 %d 列的階段名稱是空的或看不到內容（只有空白、零寬字元、控制字元等；當成不認得的階段「%s」照常判定）" % (an["empty_rows"], _cell(EMPTY_STAGE, 60)))
    return out


def _worst(sts):
    for want in ("FAIL", "GAP", "NOT_RUN"):
        if want in sts:
            return want
    for s in sts:
        if s != "OK":
            return s
    return "OK"


UPLOAD_STAGES = ("D-dt-project", "D-dt-upload", "D-dt-bom-processing")


def _is_count(v):
    """讀得到的計數：真的 int（不含 bool）而且 >= 0。-3、null、字串、浮點數、NaN、bool 一律不算。"""
    return type(v) is int and v >= 0


def _verify_checks(summ):
    """dt-verify summary.json 的 checks → (FAIL 的檢查名, NOT_RUN 的檢查名, 資料不全的原因)。
    資料不全（→ GAP，同 dt-verify 的 NOT_RUN：該做的檢查沒有完成，不能當成通過）：checks 不是非空陣列、項目格式不對、
    出現不認得的狀態、必要檢查（REQUIRED_VERIFY_CHECKS）缺漏。FAIL 另外處理（→ FAIL）。"""
    checks = summ.get("checks")
    fails, notrun, gaps = [], [], []
    if not isinstance(checks, list) or not checks:
        return fails, notrun, ["dt-verify 的 checks 不是非空陣列（%s）" % _cell(type(checks).__name__, 20)]
    seen, odd, unknown = set(), 0, []
    for c in checks:
        if not isinstance(c, dict) or not isinstance(c.get("name"), str) or not isinstance(c.get("status"), str):
            odd += 1
            continue
        seen.add(c["name"])
        st = c["status"]
        if st == "FAIL":
            fails.append(c["name"])
        elif st == "NOT_RUN":
            notrun.append(c["name"])
        elif st != "OK":
            unknown.append("%s=%s" % (_cell(c["name"], 30), _cell(st, 20)))
    if odd:
        gaps.append("dt-verify 的 checks 有 %d 項格式不對（不是 name、status 都是字串的物件）" % odd)
    if unknown:
        gaps.append("dt-verify 有不認得的檢查狀態（只認 %s）：%s" % ("／".join(VERIFY_STATUSES), "、".join(unknown[:10])))
    missing = [n for n in REQUIRED_VERIFY_CHECKS if n not in seen]
    if missing:
        gaps.append("dt-verify 缺少必要檢查：" + "、".join(missing))
    return fails, notrun, gaps


def _stage_problems(rows):
    """sca-scan 全部階段 → (FAIL 的階段, 其他非 OK 的階段 [(階段, 狀態)])。
    「其他」不含上傳三階段與 C-grype（它們另有專屬判斷，不重複列），也不含預期的 NOT_RUN（EXPECTED_NOT_RUN_*）。"""
    fails, other = [], []
    for k, (st, _) in rows.items():
        if st == "FAIL":
            fails.append(k)
        elif st == "OK" or k in UPLOAD_STAGES or k == "C-grype":
            continue
        elif st == "NOT_RUN" and (k in EXPECTED_NOT_RUN_STAGES or k.startswith(EXPECTED_NOT_RUN_PREFIXES)):
            continue
        else:
            other.append((k, st))
    return sorted(fails), sorted(other)


def sample_result(info, dt_dir, wait_rc):
    """回傳 dict：dt_components, dt_findings, upload, grype, grype_matches, status, notes。"""
    s = info["summary"]
    r = {"upload": "NOT_RUN", "dt_components": "-", "dt_findings": "-", "grype": "NOT_RUN", "grype_matches": "-",
         "notes": [], "verify_fail": [], "verify_gap": [], "stage_attention": [], "status_anomalies": [], "missing_stages": [], "accepted": False, "unverified_declaration": False}
    exp_dt = info.get("expected_dt")
    rejected = False
    sd = os.path.join(dt_dir, info["project_name"]) if dt_dir else None
    rows = None
    summ = None
    fails = []
    if sd and os.path.isdir(sd):
        st = os.path.join(sd, "scan", "status.tsv")
        if os.path.lexists(st):        # 存在但不是一般檔案（資料夾、斷掉的符號連結…）也當作讀不到，不當成「沒有」
            try:
                rows, anomalies = read_status_tsv_checked(st)
                r["status_anomalies"] = stage_anomaly_notes(anomalies)
            except DtError as e:
                r["upload"] = "FAIL"; r["notes"].append(_cell(e))
        sj = os.path.join(sd, "summary.json")
        if os.path.lexists(sj):
            try:
                summ, _ = load_json_nodup(sj, MAX_BYTES, "summary.json")
            except DtError as e:
                r["notes"].append(_cell(e)); r["verify_fail"].append("summary.json 讀不到")
    if rows is None and summ is None and r["upload"] != "FAIL":
        r["notes"].append("沒有 DT 結果")
        r["status"] = "NOT_RUN"
        _unverified_declaration(r, exp_dt)
        return r
    if rows is not None:
        r["upload"] = _worst([rows[x][0] if x in rows else "NOT_RUN" for x in UPLOAD_STAGES])
        fails, other = _stage_problems(rows)
        up = rows.get("D-dt-upload", ("NOT_RUN", ""))
        rejected = up[0] == "FAIL" and bool(BOM_INVALID_RE.match(up[1]))   # 只認 DT 的「BOM 無效、schema 不符」；其他 400 是一般 FAIL
        if exp_dt and rejected:
            fails = [k for k in fails if k != "D-dt-upload"]              # 已宣告的拒收，不重複報 sca-scan 的這一列
        if fails:
            r["notes"].append("sca-scan FAIL 階段：" + "、".join(_cell(x, 60) for x in fails))
        if not (exp_dt and rejected):                 # 宣告並真的被拒收時，上傳之後的階段本來就沒有（上傳之前的必要階段由下面的 REJECT_PRE_OK 核對）
            r["missing_stages"] = [x for x in REQUIRED_STAGES if x not in rows]
            if r["missing_stages"]:
                r["notes"].append("缺少階段 " + "、".join(_cell(x, 60) for x in r["missing_stages"]) + "（status.tsv 沒有這一列，資料不完整）")
        r["stage_attention"] = ["%s %s" % (_cell(k, 60), _cell(st, 30) or "(空)") for k, st in other]
        g = rows.get("C-grype", ("NOT_RUN", ""))[0]
        r["grype"] = g
        gj = os.path.join(sd, "scan", "scan", "grype.json")   # sca-scan --out 是 <sd>/scan，Grype 結果在它的 scan/grype.json
        if g == "OK":
            try:
                gd, _ = load_json_nodup(gj, MAX_GRYPE_BYTES, "grype.json")
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
            dc, ft = summ.get("components"), summ.get("findings_total")
            r["dt_components"] = dc if _is_count(dc) else "?"          # 顯示用：只顯示讀得到的計數，其他值不原樣印進報告
            r["dt_findings"] = ft if _is_count(ft) else "?"
            if not _is_count(ft):
                r["dt_findings_raw"] = _cell("沒有這個欄位" if "findings_total" not in summ else repr(ft), 40)
            bad, nr, gaps = _verify_checks(summ)
            if exp_dt and rejected:
                # 拒收的直接後果（沒有上傳成功就沒有分析、沒有元件）：合併成一則說明，不重複報；其他 FAIL（例如專案存在）照報。
                # 這個分支的判斷維持原樣（不因 checks 缺漏或元件數而改變「與宣告一致」的核對）。
                consequence = [x for x in bad if x in REJECT_VERIFY_NAMES]
                bad = [x for x in bad if x not in REJECT_VERIFY_NAMES]
                if consequence:
                    r["notes"].append("dt-verify 的「%s」FAIL 是同一個原因（上傳被拒、DT 沒有分析也沒有元件），不另外計算" % "、".join(consequence))
                gaps = []
            elif not (type(dc) is int and dc >= 1):
                # 上傳成功的 SBOM 至少有一個元件（prep 擋掉沒有元件的 SBOM）；DT 回報的元件數不是 int 或小於 1＝DT 端資料有疑點
                gaps.append("dt-verify 的元件數不是 >= 1 的整數（%s）" % _cell("沒有這個欄位" if "components" not in summ else repr(dc), 40))
            r["verify_fail"] += [_cell(x, 60) for x in bad]
            r["notes"] += gaps
            r["verify_gap"] = list(gaps)
            if nr:
                r["notes"].append("dt-verify NOT_RUN：" + "、".join(_cell(x, 60) for x in nr))
                if not (exp_dt and rejected):
                    r["verify_gap"].append("NOT_RUN 的檢查不能當成通過")
        else:
            r["verify_fail"].append("summary.json 格式不對")
    else:
        r["notes"].append("沒有 dt-verify 的 summary.json")
    # 狀態
    if exp_dt and rejected:
        # 宣告 rejected 且真的被拒收：照實標 FAIL，只有「沒有別的失敗」時才算與宣告一致（不讓 job 失敗）
        pre = [x for x in REJECT_PRE_OK if rows is None or x not in rows or rows[x][0] != "OK"]
        others = [k for k, v in (rows or {}).items() if v[0] == "FAIL" and k != "D-dt-upload"]
        if pre:
            r["notes"].append("上傳之前的必要階段不是 OK：" + "、".join(_cell(x, 60) for x in pre))
        extra = bool(pre or others or r["verify_fail"] or r["grype"] == "FAIL")
        r["accepted"] = not extra
        r["notes"].insert(0, "DT 拒收上傳（http=400，BOM 不符 schema），%s：%s" % (
            "與 firmware.yml 宣告的 expected_dt 一致" if not extra else "firmware.yml 有宣告 expected_dt，但還有其他失敗，不放行",
            _cell(exp_dt["reason"], 400)))
        st = "FAIL"
    elif exp_dt and r["upload"] == "OK":
        st = "MISMATCH"
        r["notes"].append("MISMATCH：firmware.yml 宣告 DT 會拒收這份 SBOM（expected_dt），但上傳成功；供應商可能修好了，請更新樣本")
    elif r["upload"] == "FAIL" or r["verify_fail"] or r["grype"] == "FAIL" or fails:
        # fails：sca-scan 任何階段（不只上傳三階段）是 FAIL 都算 FAIL；宣告並真的被拒收的 D-dt-upload 那一列已在上面排除（只有上面那個分支放行）
        st = "FAIL"
        if rejected:
            r["notes"].append("DT 拒收上傳（http=400，BOM 不符 schema）；firmware.yml 沒有宣告 expected_dt")
        elif exp_dt:
            r["notes"].append("firmware.yml 宣告 expected_dt: rejected，但上傳失敗不是 DT 的「BOM 不符 schema」拒收（http=400 且回應為 The uploaded BOM is invalid／Schema validation failed）")
    elif (wait_rc is not None and wait_rc != 0) or "GAP" in (r["upload"], r["grype"]) or r["verify_gap"] or r["missing_stages"]:
        # verify_gap：dt-verify 的資料不全（checks 缺漏、NOT_RUN、不認得的狀態、元件數怪）＝驗證沒有完整做完，同 wait 結束碼 3 的語意（資料不完整）→ GAP
        st = "GAP"
    elif summ is None or rows is None or r["upload"] != "OK" or r["grype"] != "OK":
        st = "NOT_RUN" if r["upload"] == "NOT_RUN" else "GAP"
    else:
        why = attention_reasons(s, r)
        st = "ATTENTION" if why else "OK"
        r["notes"].extend(why)
        r["status_anomalies"] = []          # 已經在 attention_reasons 裡
    if wait_rc == 3:
        r["notes"].append("dt-ephemeral wait 結束碼 3（資料不完整）：0 筆漏洞不能當成沒有漏洞")
    elif wait_rc is not None and wait_rc != 0:
        r["notes"].append("dt-ephemeral wait 結束碼 %d（只認 0＝完成、3＝資料不完整）：看不懂的結束碼不能當成完成" % wait_rc)
    r["notes"].extend(r["status_anomalies"])      # 沒走到 attention_reasons 的狀態（FAIL、GAP…）：重複列與空名稱列也不能靜默
    r["status"] = st
    if st in ("NOT_RUN", "GAP"):
        _unverified_declaration(r, exp_dt)
    return r


def _normalize_note(info):
    """上傳副本做過格式正規化的說明（固定文字加數字；沒有正規化回空字串）。"""
    n = info.get("normalize")
    if not isinstance(n, dict):
        return ""
    ch, un = n.get("changes"), n.get("unnormalized")
    out = ""
    if n.get("processed") is False:
        out += "；這份 SBOM 沒有做正規化（specVersion 不在支援範圍、metadata.properties 型別不對或規劃失敗；原因見 normalize.json 的 notes；metadata.component 仍會換成本工具的根元件）"
    if isinstance(ch, int) and ch > 0:
        out += "；已正規化 %d 處（見 normalize.json；上傳的是正規化副本，原檔不變）" % ch
    if isinstance(un, int) and un > 0:
        out += "；另有 %d 處已知違規無法正規化（見 normalize.json；欄位原樣保留）" % un
    return out


def _left_count(s):
    """沒改名的供應商 dumpling: property 個數（不超過全部個數；讀不到當 0）。"""
    n, left = s.get("supplier_dumpling_props"), s.get("supplier_dumpling_props_left")
    return left if _is_count(left) and _is_count(n) and left <= n else 0


def _props_text(s):
    """供應商 dumpling: property 的說明（summary 讀不到個數時回空字串）。"""
    n = s.get("supplier_dumpling_props")
    if not (_is_count(n) and n > 0):
        return ""
    return supplier_props_text(n, _left_count(s), s.get("supplier_dumpling_props_unprocessed") is True)


def _dup_count(s):
    n = s.get("duplicate_keys", 0) if isinstance(s, dict) else 0
    return n if _is_count(n) else 0


def attention_reasons(s, r):
    """上傳與驗證都完成後，還需要人看的原因（空清單＝OK；OK 也不代表安全）。原則：資料不完整、有疑點、讀不到，一律不是 OK。
    除了版本 GAP、沒有 purl、NOT_ASSESSED 之外，下面幾種也不能是 OK：
      - Grype 或 DT 的比對數：只有真的 int 且 >= 0 才算讀到（-3、null、字串 "-" 都是「讀不到」，不是 0）；> 0 要人審。
      - dumpling:vuln-assessment 只有「完全等於 NONE」才是已評估沒有已知漏洞；沒標、NOT_ASSESSED、其他任何值都要人看。
        供應商 SBOM（kind: sbom）自帶的 dumpling: 標記不採信，一律當作沒標。
      - dumpling:version-status 只認完全相同的 OK／GAP；沒有 version 又沒有 GAP 標記的元件也要列出。
      - purl 是 pkg:generic：DT 與 OSV 沒有 generic 的漏洞資料，等於沒有 purl；格式不合的 purl 視同沒有。
      - sca-scan 其他階段（DT 資料源、sbomgate、EUVD…）不是 OK；SBOM 有重複鍵；status.tsv 有重複列或空名稱列。"""
    why = []
    if s.get("version_gap"):
        why.append("版本 GAP %d 個" % s["version_gap"])
    if s.get("version_status_other"):
        why.append("dumpling:version-status 不是 OK／GAP 的元件 %d 個（只認完全相同的 OK 或 GAP）" % s["version_status_other"])
    if s.get("no_version_unmarked"):
        why.append("沒有 version、也沒有 version-status GAP 標記的元件 %d 個（版本缺漏沒有被記錄）" % s["no_version_unmarked"])
    if s["with_purl"] < s["components"]:
        why.append("沒有 purl 的元件 %d 個%s" % (s["components"] - s["with_purl"],
                   "（其中 %d 個 purl 格式不合 pkg:<type>/，視同沒有）" % s["bad_purl"] if s.get("bad_purl") else ""))
    if s.get("generic_purl"):
        why.append("purl 是 pkg:generic 的元件 %d 個（DT／OSV 沒有 generic 的漏洞資料）" % s["generic_purl"])
    va = s.get("vuln_assessment") or {}
    if va.get(VA_NOT_ASSESSED):
        why.append("NOT_ASSESSED 元件 %d 個" % va[VA_NOT_ASSESSED])
    if va.get(OTHER):
        why.append("dumpling:vuln-assessment 不是 NONE／NOT_ASSESSED 的元件 %d 個（只有完全等於 NONE 才算已評估；其他值一律要人看）" % va[OTHER])
    if va.get(UNSET):
        why.append("沒有 dumpling:vuln-assessment 標記的元件 %d 個（不是 dumpling 產的 SBOM，評估狀態不明）" % va[UNSET])
    if s.get("supplier_markers"):
        why.append("供應商 SBOM 自帶 dumpling: 標記的元件 %d 個（供應商可以自己塞，不採信，一律當作沒標）" % s["supplier_markers"])
    for label, v in (("Grype", r.get("grype_matches")), ("DT", r.get("dt_findings"))):
        if not _is_count(v):
            raw = r.get("dt_findings_raw") if label == "DT" else None
            why.append("%s 比對數讀不到（%s）：不能當成 0 筆" % (label, raw or _cell(repr(v), 40)))
        elif v > 0:
            why.append("%s 有 %d 筆比對結果，需要人審" % (label, v))
    if r.get("stage_attention"):
        lst = r["stage_attention"]
        why.append("sca-scan 其他階段不是 OK（%d 個，OK 之前都要有人看過）：%s%s" % (
            len(lst), "、".join(lst[:20]), "…另 %d 個" % (len(lst) - 20) if len(lst) > 20 else ""))
    why.extend(r.get("status_anomalies") or [])
    if _props_text(s):
        why.append(_props_text(s))
    if _dup_count(s):
        why.append(dup_text(_dup_count(s)))
    return why


def _unverified_declaration(r, exp_dt):
    """宣告了 expected_dt，但沒有上傳結果可以核對（NOT_RUN／GAP）：狀態照實，但 report 以 1 結束。
    與沒宣告的樣本一致（沒宣告時 firmware-dt.sh 的必要階段檢查會失敗）；宣告不能讓「沒跑」變成 job 綠燈。"""
    if exp_dt:
        r["unverified_declaration"] = True
        r["notes"].append("firmware.yml 宣告 expected_dt，但沒有上傳結果可核對宣告（狀態 %s）；視為失敗" % r["status"])


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
        if os.path.lexists(p):         # 存在但不是一般檔案（斷掉的符號連結、資料夾、FIFO）：_read_limited 會拒絕 → FAIL，不當成「沒有 rc」
            raw = _read_limited(p, 64, "dt-wait.rc").strip(b" \t\r\n")
            if not re.fullmatch(rb"[0-9]+", raw):          # 只認 ASCII 數字：+0、-0、0_0、全形／阿拉伯數字、NBSP 都不是 0
                raise DtError("dt-wait.rc 不是非負整數（只認 ASCII 數字）")
            wait_rc = int(raw)
    lines, rows = [], []
    nv = None
    for d in prep_dirs:
        info = load_prep(d)
        res = sample_result(info, dt_dir, wait_rc)
        nn = _normalize_note(info)
        if nn:
            res["notes"].append(nn[1:])
        s = info["summary"]
        if _dup_count(s) and dup_text(_dup_count(s)) not in res["notes"]:
            res["notes"].append(dup_text(_dup_count(s)))      # 狀態不是 ATTENTION／OK 時 attention_reasons 沒跑到，這裡補上，重複鍵不能靜默
        if _props_text(s) and _props_text(s) not in res["notes"]:
            res["notes"].append(_props_text(s))      # 同上：不是 ATTENTION／OK 的狀態也不能靜默
        rows.append((info, res))
        va = "、".join("%s=%d" % (_cell(k, 40), v) for k, v in sorted(s["vuln_assessment"].items()))
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
        md.append("| %s | %s%s | %d | %s | %s | %s | %s | %s |" % (
            _cell(info["slug"]), _cell("%s@%s" % (info["project_name"], info["project_version"])),      # 整串一起過 md_safe：版本以字母結尾又含 `.` 時，name@version 是 email 形式
            "（合成）" if info.get("synthetic") else "", info["summary"]["components"], res["upload"],
            res["dt_components"], res["dt_findings"], g, res["status"]))
    md += ["", "## 怎麼讀", "",
           "- **漏洞數 0 筆不代表沒有漏洞。** 臨時 DT 只開 OSV、KEV（NVD 關閉），只比對有 purl 的元件，`pkg:github/...` 與只有 CPE 的元件在 DT 完全比對不到；"
           "DT 在這裡只負責收件與留存，韌體的漏洞比對以 Grype（sca-scan 的 C-grype）為主。沒有 purl 也沒有 CPE 的元件 Grype 也比對不到，"
           "但 C-grype 仍會顯示 OK（比對完成），所以要看每個元件的 `dumpling:vuln-assessment`：Intel（ME、微碼、FSP、GOP／VBT）與 NVIDIA 元件為 NOT_ASSESSED（公告無法機器比對，需公告對照）。Intel 微碼另有 `dumpling:advisory-match`（離線比對 Intel 公開的微碼發佈資料表：affected-candidate／older-no-sa／up-to-date／NOT_ASSESSED；候選公告列在 release 層級、不是確定受影響，up-to-date 與 NOT_ASSESSED 都不代表沒有漏洞）；ME 的 CPE 是 NVD 的 Intel CSME 資料，NVD 的資料不完整，比不到不代表沒有漏洞。AMD 的微碼、PSP 韌體、AGESA 元件也是 `advisory-match=NOT_ASSESSED`：資料庫沒有資料，以 AMD 公告為準（AMD-SB 的規則表還沒有做）。"
           "NVIDIA vBIOS 元件另有 `advisory-match`：用 vBIOS 版本與 option ROM 的 PCI 裝置 ID 查 repo 內的 NVIDIA 公告對照表（尚未經負責人確認時一律 NOT_ASSESSED）（affected／fixed／NOT_ASSESSED）；"
           "NVIDIA 對消費型顯卡的 vBIOS 幾乎沒有公開公告（主要管道是合作夥伴通知），所以多數是 NOT_ASSESSED：資料庫沒有資料，以廠商公告為準；版本是佔位字串或裝置 ID 讀不到也是 NOT_ASSESSED。"
           "affected、fixed 只是對照表裡已審核的列的比對結果，fixed 不代表沒有其他漏洞，沒有任何一項代表沒有漏洞。",
           "- firmware.yml 的 `expected_dt: {upload: rejected}` 是樣本自己宣告「DT 會拒收這份 SBOM」（供應商 SBOM 不符 schema，dumpling 不修改供應商的檔案）："
           "真的被拒收仍標 FAIL，但說明寫「與宣告一致」且不讓 job 失敗；宣告了卻上傳成功＝MISMATCH（job 失敗，請更新樣本）；沒宣告卻被拒收＝一般 FAIL。其他失敗不受宣告影響。",
           "- 上傳狀態 NOT_RUN＝沒有 DT 結果（沒起 DT 或沒跑到上傳）；GAP＝資料不完整（例如 DT 鏡像 wait 結束碼 3），不能當成沒有漏洞。",
           "- 狀態 OK 只表示：sca-scan 的 11 個必要階段（`REQUIRED_STAGES`）每一列都在，上傳與驗證都完成（dt-verify 的「專案存在」「弱點分析完成」「元件數」「漏洞總數」都在而且是 OK），每個元件都有 purl（不是 pkg:generic）、"
           "沒有版本缺漏、`dumpling:vuln-assessment` 都完全等於 NONE，Grype 與 DT 的比對數讀得到而且是 0，sca-scan 其他階段都是 OK（授權、核心設定那幾個預期的 NOT_RUN 除外），status.tsv 沒有重複列或空名稱列，輸入 SBOM 沒有重複鍵。"
           "ATTENTION 表示完成但仍有需要人看的原因（逐項列在說明裡）；GAP 表示資料不完整；FAIL 表示有階段或檢查失敗。這份報告沒有整體通過或安全的結論。",
           "", "## 每個樣本的摘要", ""]
    for info, res in rows:
        s = info["summary"]
        md.append("### %s" % _cell(info["slug"]))
        md.append("")
        md.append("- 元件 %d，有 purl %d，有 cpe %d，vuln-assessment：%s，version-status GAP %d" % (
            s["components"], s["with_purl"], s["with_cpe"],
            "、".join("%s=%d" % (_cell(k, 40), v) for k, v in sorted(s["vuln_assessment"].items())) or "無", s["version_gap"]))
        if s.get("advisory_match"):
            md.append("- 公告比對（dumpling:advisory-match）：%s；候選不是確定受影響，沒有任何一項代表沒有漏洞" % "、".join(
                "%s=%d" % (k if k in AM_VALUES else _cell(k, 40), v) for k, v in sorted(s["advisory_match"].items()) if _is_count(v)))      # 固定值原樣（不加反斜線），其餘經 _cell
        if res.get("nvidia"):
            md.append("- " + res["nvidia"])   # 文字取自 C1 的 nvidia_bulletins.py，已經過 _cell
        for n in res["notes"]:
            md.append("- " + n)               # notes／verify_fail 在產生時已經過 _cell
        if res["verify_fail"]:
            md.append("- dt-verify FAIL：" + "、".join(res["verify_fail"]))
        md.append("")
    with open(os.path.join(out, "firmware-dt.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(md))
    return lines, any((r["status"] in ("FAIL", "MISMATCH") and not r["accepted"]) or r["unverified_declaration"] for _, r in rows)


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
            print("FIRMWARE-DT-PREP\tOK\t%s@%s；元件 %d、purl %d、cpe %d、version-status GAP %d%s" % (
                info["project_name"], info["project_version"], s["components"], s["with_purl"], s["with_cpe"], s["version_gap"],
                _normalize_note(info) + ("；" + dup_text(s["duplicate_keys"]) if s.get("duplicate_keys") else "")))
        elif a.cmd == "expected":
            exp, _ = expected(a.prep)
            print("FIRMWARE-DT-EXPECTED\tOK\t%s@%s；元件 %d" % (exp["project_name"], exp["project_version"], exp["components"]))
        else:
            lines, failed = report(a.prep, a.dt_result, a.out, a.repo_root)
            print("\n".join(lines))
            return 1 if failed else 0
    except DtError as ex:
        print("FIRMWARE-DT-%s\tFAIL\t%s" % (a.cmd.upper(), _cell(ex, 600)))      # 訊息可能含不可信文字（含單獨代理字元，直接 print 會 UnicodeEncodeError）
        return 1
    except Exception as ex:      # 非預期的錯誤也要是清楚的 FAIL 行，不是 traceback（輸入是不可信資料；fail-closed）
        print("FIRMWARE-DT-%s\tFAIL\t非預期的錯誤 %s（輸入有問題或工具有 bug；這個樣本不上傳）" % (a.cmd.upper(), type(ex).__name__))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
