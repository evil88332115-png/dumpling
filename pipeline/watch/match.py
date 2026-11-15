#!/usr/bin/env python3
"""match.py：每日監控的比對（WATCH.md 3.2、3.3、3.5）。讀 inventory、資料源、狀態 → plan.json（要開的 Issue、新的狀態）＋report.md。

用法：
  python3 -I pipeline/watch/match.py --inventory <W/inventory.json> --state-dir <W/state> --feeds <W/feeds> --out <W/out>
        [--mode real|drill] [--kev-overlay <合成 KEV.json>（只限 drill）] [--max-new-issues 20] [--run-url <網址>]
        [--grype <執行檔>] [--grype-total-timeout 1500] [--vendor-config <vendor-watch.json>] [--now <UTC ISO>] [--demo] [--allow-baseline]
        [--firmware-rematch <firmware-rematch.sh 的輸出資料夾>]
  --state-dir：issues.py read-state 的輸出（state-base.json 必要；state.json 有狀態 Issue 時才有）。
  --feeds：feeds.sh 的輸出：cisa-kev.json（CISA KEV）、euvd/（EUVD 鏡像，index.tsv）、kernel-cve/（kernel-cve.sh 的輸出）。
    Grype DB 用環境變數 GRYPE_DB_CACHE_DIR（同 exploited_grype.grype_env）。
  --kev-overlay：{"vulnerabilities": [{"cveID", "vendorProject", "product", "dateAdded"}, …]}，併進 CISA KEV（演練用；real 模式拒絕）。

重用、不改的既有工具（WATCH.md 第 1 節）：
  exploited_grype.prepare／extract（Grype 重新比對，設定與 Release 相同；DT 的 findings 給空的 → 已遭利用的比對都是 basis grype_only）、
  exploited_grype.cisa_kev／db_status／find_grype／sandbox_check、exploited_watch.update_state／euvd_sticky／euvd_text、
  tools/pilot/lib/euvd.py exploited_index、exploited_vendor.load_config／run_vendor_watch、
  tools/pilot/lib/kernel_cna_version.py（以指令呼叫；核心上游版本取自 Release 附件 kernel-versions-<專案>-<版本>.json 的 upstream_version）。
專案鍵：project_uuid＝dumpling:<專案>/<監控版本>#<層>（開發版的監控版本固定是 dev）。

規則（WATCH.md 3.2）：
  - 沒有狀態、也沒有任何監控 Issue → 第一次：所有比對記 baseline，不開 Issue（全部 SBOM 的 Grype 都跑完、CISA KEV 可用才建，否則 FAIL）。沒有狀態、卻有監控 Issue → FAIL（不重建基準）。
  - 之後：新的比對群組（專案、監控版本、層、CVE）→ open；再出現 → open_if_closed（原 Issue 開著就留言）；
    群組全部消失 → comment（不自動關閉）。廠商層級：（專案、監控版本、層、CVE、廠商）一個 Issue；baseline 不開。
  - 一次新增超過 --max-new-issues（預設 20）個群組 → 全部併成一個彙總 Issue（ATTENTION；那些群組之後的事件都留言在彙總 Issue，D-040）。
  - 只開「已遭利用（KEV／EUVD）」與「廠商層級」兩種 Issue；一般 CVE 候選（核心 CNA 上千筆、U-Boot 候選）不開（D-040）。
  - 韌體（docs/FIRMWARE-WATCH.md，F2）：inventory 的 firmware.samples 每份樣本是一個監控單位（dumpling:firmware-demo/<slug>@<版本>#firmware，status development）。
    Grype＋KEV／EUVD＋廠商層級照板子；核心對應、核心 CNA 沒有這一項；沒有 purl／CPE 的 SBOM 不能寫 OK（NOT_ASSESSED）。
    公告重跑（--firmware-rematch，rematch-summary.json＋rematch-<slug>.json，不可信資料）的 affected／affected-candidate 開 firmware-advisory Issue
    （規則表、vBIOS：一則公告一個；Intel 微碼：一個 key 一個），基準與 #112 的規則同 KEV；同 slug 同版本 image_sha256 變了：不開新鍵，需注意＋既有 Issue 留言。
  - --demo（公開 repo）：標題與內文寫明「示範專案（公開 BSP）」、加 demo 標籤；不開 art14 Issue（第 14 條只做演練）。
輸出：stdout 一行 WATCH-MATCH<TAB>OK|ATTENTION|FAIL<TAB>說明；<out>/plan.json、report.md、result.json。
退出碼：OK 0、FAIL 1、ATTENTION 2、GAP 3、用法 64。FAIL 與 GAP 時不寫 plan.json（notify 跳過，不會動任何東西）。
  GAP：還沒有狀態、也沒有任何可監控的 SBOM（例如 M2 之前）→ 不建立空的基準。
"""
import argparse
import copy
import datetime
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "tools", "cra"))
import publiccheck  # noqa: E402

STAGE = "WATCH-MATCH"
EXIT = {"OK": 0, "FAIL": 1, "ATTENTION": 2, "GAP": 3}
KEY_PREFIX = "dumpling-watch/1"
KERNEL_CNA = os.path.join(ROOT, "tools", "pilot", "lib", "kernel_cna_version.py")
KV_SCHEMA = "sca-center-kernel-versions/2"
UPSTREAM_RE = re.compile(r"^[0-9]+\.[0-9]+(\.[0-9]+)?$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
RUNS_KEEP = 30
GRYPE_TOTAL = 1500
# 每日沒有跑的 Release 掃描項目（WATCH.md 第 2 節）：每個報告與 Issue 都列出，不悄悄漏掉
NOT_RUN_DAILY = [
    ("DT (OSV) matching", "每日監控不開 DT：OSV 那條路的比對每天沒有重跑（NOT_RUN）；Grype 與 CISA KEV／EUVD 有跑"),
    ("NVIDIA bulletins", "NVIDIA 公告比對每天沒有重跑（NOT_RUN）；廠商層級的 nvidia 有跑"),
    ("kernel .config judgment", "核心 .config 判定每天沒有跑（NOT_RUN）：核心 CNA 的 affected 與 unknown 都當候選"),
]
ART14_NOTE = ("偵測時間是這個工具第一次看到這筆比對的時間；工具偵測到不等於法律上的「知悉」。是否在本產品被利用、何時知悉、"
              "是否依 CRA 第 14 條通報，由負責人判斷。")
HANDLING = {"shipped": "已出貨：照內部 SOP 當天排查，交 PM。",
            "development": "開發中：直接交 RD 處理。"}

# ---- 韌體（docs/FIRMWARE-WATCH.md）----
FW_PROJECT = "firmware-demo"
FW_LAYER = "firmware"
FW_NO_ITEM = "沒有這一項"                                        # 韌體層沒有 L4T 核心對應、核心 CNA：不算 GAP、不降級
FW_GRYPE_NA = "NOT_ASSESSED（可比對元件 0：沒有 purl／CPE）"       # 不能寫 OK；Grype 空的不代表沒有漏洞
FW_SBOM_ADV = "NOT_ASSESSED（沒有 inventory，不重跑公告比對）"      # 供應商 SBOM（kind sbom）：設計上就不重跑，不是 NOT_RUN
FW_GRYPE_NOTE = "Grype 空的不代表沒有漏洞，以廠商公告為準"
FW_NVD_NOTE = "NVD 的 CSME 資料不完整"
FW_REMATCH_SCHEMA = "dumpling-firmware-rematch/1"
FW_SUMMARY_SCHEMA = "dumpling-firmware-rematch-summary/1"
FW_SUMMARY_MAX = 1 << 20                                         # 外來檔案的大小上限
FW_SAMPLE_MAX = 4 << 20
FW_MAX_RESULTS = 500
FW_KINDS = ("rule", "intel-microcode", "nvidia-vbios")
FW_RESULTS = {"rule": ("affected", "not-affected", "NOT_ASSESSED"),
              "intel-microcode": ("affected-candidate", "older-no-sa", "up-to-date", "NOT_ASSESSED"),
              "nvidia-vbios": ("affected", "fixed", "NOT_ASSESSED")}
FW_AFFECTED = {"rule": "affected", "intel-microcode": "affected-candidate", "nvidia-vbios": "affected"}
FW_TABLES = ("fw_advisory_rules", "intel_microcode", "nvidia_vbios")
FW_TABLE_OF = {"rule": "fw_advisory_rules", "intel-microcode": "intel_microcode", "nvidia-vbios": "nvidia_vbios"}
FW_ISSUE_LABELS = ["firmware-advisory", "development", "layer-firmware"]
FW_HISTORY_KEEP = 20
FW_WORD_PRELIM = "建議受影響（初步規則，待人審）"
FW_WORD_CONFIRMED = "建議受影響（規則已確認，待負責單位確認）"
FW_WORD_VBIOS = "建議受影響（依 NVIDIA 對照表，待人審）"
FW_WORD_UCODE = "版本比較的候選，待人審"
# rematch 的 key：不透明字串，只檢查字元集（C2 定的 A-Za-z0-9._=+-:/#）
FW_KEY_RE = re.compile(r"[A-Za-z0-9._=+\-:/#]{1,300}")
# rematch 拒絕 meta 條目的原因代碼（C2：只有這幾種，不帶輸入字串）
FW_REJECT_RE = re.compile(r"entry-not-object|invalid-slug \(type [a-z]{1,10}\)|invalid-slug \(length [0-9]{1,6}\)|reserved-slug|duplicate-slug")
FW_MAX_BULLETINS = 20      # 每筆結果的公告 ID 上限（C0 決定 2026-11-15）：超過就那份樣本 GAP，不截斷
FW_MAX_AFFECTED = 100       # 每個樣本存進狀態的 affected 上限（狀態 Issue 有 60000 字元上限；超過整份樣本 GAP）


class Fail(Exception):
    pass


def load_mod(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


_MODS = {}


def mods():
    """既有工具（以檔案路徑載入一次；測試可以替換其中的函式）。"""
    if not _MODS:
        _MODS["eg"] = load_mod("_w_eg", os.path.join(ROOT, "tools", "cra", "exploited_grype.py"))
        _MODS["ew"] = load_mod("_w_ew", os.path.join(ROOT, "tools", "cra", "exploited_watch.py"))
        _MODS["ev"] = load_mod("_w_ev", os.path.join(ROOT, "tools", "cra", "exploited_vendor.py"))
        _MODS["euvd"] = load_mod("_w_euvd", os.path.join(ROOT, "tools", "pilot", "lib", "euvd.py"))
    return _MODS


def utc(dt):
    return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_now(s):
    if not s:
        return datetime.datetime.now(datetime.timezone.utc)
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", s):
        raise Fail("--now 必須是 UTC ISO 8601（YYYY-MM-DDTHH:MM:SSZ）")
    return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)


def read_json(path, what):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        raise Fail(f"{what} 不存在")
    except (OSError, ValueError) as e:
        raise Fail(f"{what} 讀不到或不是 JSON（{type(e).__name__}）")


def issue_key(mode, kind, *parts):
    return hashlib.sha256("|".join((KEY_PREFIX, mode, kind) + tuple(parts)).encode("utf-8")).hexdigest()


def uuid_of(project, watch_version, layer):
    return f"dumpling:{project}/{watch_version}#{layer}"


# ---------- 輸入 ----------

def load_inventory(path, base):
    inv = read_json(path, "inventory.json")
    if not isinstance(inv, dict) or inv.get("schema") != "dumpling-watch-inventory/1" or not isinstance(inv.get("releases"), list):
        raise Fail("inventory.json 不是 dumpling-watch-inventory/1")
    if inv.get("status") == "FAIL":
        raise Fail(f"收集 Release 失敗：{inv.get('detail') or '?'}")
    projs, problems = [], []
    # 被略過的 Release（資料格式壞掉、tag 不合規則、tag 重複）：不是正常狀態，算 Release 問題（降級、ATTENTION、擋第一次基準）。
    # draft 是正常略過（還沒發布），由 run() 只列在「說明」（#49 驗證應修 2）
    for x in inv.get("skipped") or []:
        if isinstance(x, dict):
            problems.append(f"Release 被略過：{str(x.get('tag'))[:120]}：{str(x.get('why'))[:200]}")
    for r in inv["releases"]:
        if not isinstance(r, dict):
            continue
        name = f"{r.get('project')}@{r.get('watch_version')}"
        if r.get("problems"):
            problems.append(f"{r.get('tag')}: " + "；".join(str(x) for x in r["problems"])[:300])
        if r.get("status") not in ("shipped", "development") or not isinstance(r.get("sboms"), dict):
            continue
        if r.get("kind") != "dev" and r.get("watch_version") == "dev":
            problems.append(f"{r.get('tag')}: 正式版的版本字串是 dev，會跟開發版 dev/{r.get('project')} 的專案鍵相同：不比對")
            continue
        for layer, s in sorted(r["sboms"].items()):
            if layer not in ("bsp", "os", "product") or not isinstance(s, dict) or not isinstance(s.get("file"), str):
                continue
            rel = s["file"]
            if os.path.isabs(rel) or ".." in rel.split("/"):
                problems.append(f"{name}: SBOM 路徑不合法（{layer}）")
                continue
            projs.append({"uuid": uuid_of(r["project"], r["watch_version"], layer), "name": r["project"], "version": r["watch_version"],
                          "layer": layer, "status": r["status"], "tag": r.get("tag"), "kind": r.get("kind"),
                          "release_version": r.get("version"), "os_responsibility": r.get("os_responsibility"),
                          "html_url": r.get("html_url"), "sbom": os.path.join(base, rel), "sha256": s.get("sha256"),
                          "report_status": r.get("report_status") or "NOT_RUN", "release_gate": r.get("release_gate") or "NOT_RUN",
                          "pipeline_result": r.get("pipeline_result") or "NOT_RUN",
                          "reports": r.get("reports") or [], "meta_attention": r.get("attention") or [],
                          "kernel_versions": os.path.join(base, r["kernel_versions"]) if isinstance(r.get("kernel_versions"), str)
                          and not os.path.isabs(r["kernel_versions"]) and ".." not in r["kernel_versions"].split("/") else None})
    if isinstance(inv.get("firmware"), dict):
        projs += firmware_projs(inv["firmware"], base, problems, {p["uuid"] for p in projs})
    return inv, projs, problems


def firmware_projs(fw, base, problems, taken):
    """inventory 的 firmware.samples → 監控單位（FIRMWARE-WATCH.md §2、§5）。watch_version 與 sbom 都有的樣本才進；
    Release 與樣本的 problems 都列進 problems（報告看得到、降級、擋第一次基準）。
    status 固定 development：樣本是公開的示範測試資料，不是出貨品，不能走「已出貨」的 SOP。"""
    out = []
    tag = fw.get("tag") if isinstance(fw.get("tag"), str) else None
    for x in fw.get("problems") or []:
        problems.append(f"韌體 Release {str(tag)[:120]}: {str(x)[:300]}")
    for x in fw.get("not_watched") or []:
        # collect 自己判定不能監控的樣本（版本讀不到又沒有映像雜湊）才是 GAP；meta 列的（合成 vBIOS 等）只是說明，不降級
        if isinstance(x, dict) and x.get("source") == "collect":
            problems.append(f"韌體樣本 {str(x.get('slug'))[:64]}: 不監控：{str(x.get('why'))[:200]}")
    for s in fw.get("samples") or []:
        if not isinstance(s, dict) or not isinstance(s.get("slug"), str):
            continue
        slug = s["slug"]
        for x in s.get("problems") or []:
            problems.append(f"韌體樣本 {slug[:64]}: {str(x)[:300]}")
        wv, sb = s.get("watch_version"), s.get("sbom")
        if not isinstance(wv, str) or not isinstance(sb, dict):
            continue
        rel = sb.get("file")
        if not isinstance(rel, str) or os.path.isabs(rel) or ".." in rel.split("/"):
            problems.append(f"韌體樣本 {slug[:64]}: SBOM 路徑不合法")
            continue
        uuid = uuid_of(FW_PROJECT, wv, FW_LAYER)
        if uuid in taken:
            problems.append(f"韌體樣本 {slug[:64]}: 監控鍵重複（只收第一個）")
            continue
        taken.add(uuid)
        inv = s.get("inventory") if isinstance(s.get("inventory"), dict) else None
        out.append({"uuid": uuid, "name": FW_PROJECT, "version": wv, "layer": FW_LAYER, "status": "development", "tag": tag, "kind": "firmware",
                    "slug": slug, "sample_kind": s.get("kind"), "firmware_version": s.get("firmware_version"),
                    "image_sha256": s.get("image_sha256") if isinstance(s.get("image_sha256"), str) else None,
                    "inventory": inv, "meta_status": s.get("meta_status"), "expect": s.get("expect"),
                    "release_version": fw.get("version"), "os_responsibility": None, "html_url": fw.get("html_url"),
                    "sbom": os.path.join(base, rel), "sha256": sb.get("sha256"), "report_status": None, "release_gate": None,
                    "pipeline_result": None, "reports": [], "meta_attention": [], "kernel_versions": None})
    return out


def is_fw(p):
    return bool(p) and p.get("kind") == "firmware"


def sbom_matchable(path, limit=256 << 20):
    """SBOM 裡可以讓 Grype 比對的元件數（有 purl、CPE，或 syft:cpe23 屬性）；讀不到或不是 CycloneDX → None（交給 Grype 那一步報 NOT_RUN）。"""
    try:
        if os.path.getsize(path) > limit:
            return None
        with open(path, encoding="utf-8") as f:
            bom = json.load(f)
    except (OSError, ValueError, RecursionError, MemoryError):
        return None
    if not isinstance(bom, dict) or not isinstance(bom.get("components"), list):
        return None
    n, seen = 0, 0
    stack = list(bom["components"])
    while stack and seen < 2_000_000:
        c = stack.pop()
        seen += 1
        if not isinstance(c, dict):
            continue
        if isinstance(c.get("components"), list):
            stack.extend(c["components"])
        if c.get("type") == "file":
            continue
        if (isinstance(c.get("purl"), str) and c["purl"].strip()) or (isinstance(c.get("cpe"), str) and c["cpe"].strip()) or \
                any(isinstance(x, dict) and isinstance(x.get("name"), str) and x["name"].startswith("syft:cpe23") and isinstance(x.get("value"), str)
                    and x["value"].strip() for x in (c["properties"] if isinstance(c.get("properties"), list) else [])):
            n += 1
    return n


# ---------- 韌體公告重跑的輸出（不可信資料，docs/FIRMWARE-WATCH.md §4）----------

def _fw_str(x, lo=1, hi=300):
    return isinstance(x, str) and lo <= len(x) <= hi and not _MD_CTRL.search(x)


def _fw_read(path, limit):
    """外來的 JSON 檔：一般檔案（不跟隨連結）、有大小上限。→ (物件, None) 或 (None, 原因)。"""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None, "missing"
    except OSError as e:
        return None, f"讀不到（{type(e).__name__}）"
    import stat as _stat
    if not _stat.S_ISREG(st.st_mode):
        return None, "不是一般檔案（不跟隨連結）"
    if st.st_size > limit:
        return None, f"超過大小上限 {limit} 位元組"
    try:
        with open(path, encoding="utf-8") as f:
            return json.loads(f.read(limit + 1)), None
    except (OSError, ValueError, RecursionError) as e:
        return None, f"不是 JSON（{type(e).__name__}）"


def _fw_tables(t, where, errs):
    """表的識別（三張都要有）：字串與布林欄位；status 要是 OK／GAP、stale 要是布林。→ {表名: {欄位: 值}}。"""
    out = {}
    if not isinstance(t, dict):
        errs.append(f"{where}tables 不是物件")
        return out
    for name in FW_TABLES:
        v = t.get(name)
        if not isinstance(v, dict):
            errs.append(f"{where}tables 缺 {name}")
            continue
        row = {}
        for k, x in v.items():
            if not (isinstance(k, str) and re.fullmatch(r"[a-z0-9_]{1,40}", k)):
                continue
            if isinstance(x, bool):
                row[k] = x
            elif isinstance(x, str):
                row[k] = _plain(x, 100)
        if row.get("status") not in ("OK", "GAP"):
            errs.append(f"{where}tables.{name}.status 不是 OK／GAP")
        if not isinstance(row.get("stale"), bool):
            errs.append(f"{where}tables.{name}.stale 不是布林")
        out[name] = row
    return out


def _fw_bulletins(b, errs, where):
    if not isinstance(b, list) or len(b) > FW_MAX_BULLETINS or not all(_fw_str(x, 1, 80) for x in b):
        errs.append(f"{where}bulletins 不是字串陣列（最多 {FW_MAX_BULLETINS} 筆、每筆 1～80 字元）")
        return []
    return list(b)


def check_rematch_doc(doc, slug, tag, inv_sha):
    """rematch-<slug>.json → (整理過的內容, 問題清單)。slug、release_tag、inventory_sha256 要和 inventory 一致；
    schema 不符、欄位型別不對都是問題（呼叫端記 GAP，不用這份的任何內容）。"""
    if not isinstance(doc, dict) or doc.get("schema") != FW_REMATCH_SCHEMA:
        return None, [f"schema 不是 {FW_REMATCH_SCHEMA}"]
    errs = []
    if doc.get("slug") != slug:
        errs.append("slug 和 inventory 不一致")
    if doc.get("release_tag") != tag:
        errs.append("release_tag 和 inventory 不一致")
    if not (isinstance(inv_sha, str) and doc.get("inventory_sha256") == inv_sha):
        errs.append("inventory_sha256 和 inventory 不一致")
    if errs:
        return None, errs
    status = doc.get("status")
    if status not in ("OK", "ATTENTION", "GAP"):
        errs.append("status 不是 OK／ATTENTION／GAP")
    reasons = doc.get("reasons")
    if not isinstance(reasons, list) or len(reasons) > 20 or not all(_fw_str(x, 0, 300) for x in reasons):
        errs.append("reasons 不是字串陣列")
        reasons = []
    tables = _fw_tables(doc.get("tables"), "", errs)
    results, seen = [], set()
    rs = doc.get("results")
    if not isinstance(rs, list) or len(rs) > FW_MAX_RESULTS:
        errs.append(f"results 不是陣列或超過 {FW_MAX_RESULTS} 筆")
        rs = []
    for i, r in enumerate(rs):
        w = f"results[{i}]."
        if not isinstance(r, dict):
            errs.append(w + "不是物件")
            continue
        kind = r.get("kind")
        if kind not in FW_KINDS:
            errs.append(w + "kind 不是 rule／intel-microcode／nvidia-vbios")
            continue
        if r.get("result") not in FW_RESULTS[kind]:
            errs.append(w + f"result 不在 {kind} 認得的值裡")
            continue
        if not (isinstance(r.get("key"), str) and FW_KEY_RE.fullmatch(r["key"])) or r["key"] in seen:
            errs.append(w + "key 不是合規則的字串（A-Za-z0-9._=+-:/#，1～300 字元）或重複")
            continue
        seen.add(r["key"])
        if not _fw_str(r.get("component"), 0, 300):
            errs.append(w + "component 不是字串")
            continue
        if r.get("reason") is not None and not _fw_str(r.get("reason"), 0, 300):
            errs.append(w + "reason 不是字串或 null")
            continue
        if r.get("review") not in ("preliminary", "confirmed", None):
            errs.append(w + "review 不是 preliminary／confirmed／null")
            continue
        b = _fw_bulletins(r.get("bulletins"), errs, w)
        if r["result"] == FW_AFFECTED[kind] and not b:
            errs.append(w + f"{r['result']} 卻沒有公告 ID")
            continue
        results.append({"key": r["key"], "kind": kind, "component": r["component"], "result": r["result"], "bulletins": b,
                        "reason": r.get("reason"), "review": r.get("review")})
    n_aff = sum(1 for r in results if r["result"] == FW_AFFECTED[r["kind"]])
    if n_aff > FW_MAX_AFFECTED:
        errs.append(f"affected 超過 {FW_MAX_AFFECTED} 筆（{n_aff}）：狀態 Issue 有大小上限，這份樣本 GAP")
    changed = []
    cs = doc.get("changed")
    if not isinstance(cs, list) or len(cs) > FW_MAX_RESULTS:
        errs.append("changed 不是陣列")
        cs = []
    for i, c in enumerate(cs):
        w = f"changed[{i}]."
        ok = isinstance(c, dict) and isinstance(c.get("key"), str) and bool(FW_KEY_RE.fullmatch(c["key"])) and c.get("kind") in FW_KINDS
        sides = {}
        for side in ("before", "after"):
            x = c.get(side) if ok else None
            # before.result 可以是 null（Release 當時沒有這個元件的結果，C2 介面）；after 一定要有
            res_ok = isinstance(x, dict) and (_fw_str(x.get("result"), 1, 40) or (side == "before" and x.get("result") is None))
            if not res_ok or (x.get("reason") is not None and not _fw_str(x.get("reason"), 0, 300)) or \
                    x.get("review") not in ("preliminary", "confirmed", None):
                ok = False
                break
            sides[side] = {"result": x["result"], "bulletins": _fw_bulletins(x.get("bulletins") or [], errs, w + side + "."),
                           "reason": x.get("reason"), "review": x.get("review")}
        if not ok:
            errs.append(w + "格式不對")
            continue
        changed.append({"key": c["key"], "kind": c["kind"], **sides})
    if errs:
        return None, errs[:10]
    return {"status": status, "reasons": reasons, "tables": tables, "results": results, "changed": changed}, []


def load_rematch(dirpath, fw_projs):
    """--firmware-rematch 的資料夾 → {"adv": {uuid: {state, why, results, changed, reasons}}, "tables": {表: 識別}｜None,
    "table_flags": {表: [原因]}, "problems": [說明], "ran": bool}。
    state：OK／ATTENTION／GAP／NOT_RUN（bios 樣本）、FW_SBOM_ADV（供應商 SBOM，不重跑）。
    沒給資料夾、沒有 rematch-summary.json、不在總表裡的 bios 樣本 → NOT_RUN（不拿 Release 當時的結果頂替）；
    檔案不合格 → GAP（不用裡面的任何內容）。"""
    out = {"adv": {}, "tables": None, "table_flags": {}, "problems": [], "ran": False, "listed_unknown": [], "rejected": []}
    adv = out["adv"]
    bios = []
    for p in fw_projs:
        if p.get("sample_kind") == "sbom":
            adv[p["uuid"]] = {"state": FW_SBOM_ADV, "why": None, "results": None, "changed": [], "reasons": []}
        else:
            bios.append(p)

    def all_bios(state, why):
        for p in bios:
            adv[p["uuid"]] = {"state": state, "why": why, "results": None, "changed": [], "reasons": []}
        return out
    if not dirpath:
        return all_bios("NOT_RUN", "沒有給 --firmware-rematch：公告重跑沒有執行（Release 當時的結果不能頂替今天的）")
    doc, err = _fw_read(os.path.join(dirpath, "rematch-summary.json"), FW_SUMMARY_MAX)
    if doc is None:
        if err == "missing":
            return all_bios("NOT_RUN", "沒有 rematch-summary.json：公告重跑沒有輸出（Release 當時的結果不能頂替今天的）")
        return all_bios("GAP", f"rematch-summary.json {err}")
    tag = next((p["tag"] for p in fw_projs), None)
    errs = []
    if not isinstance(doc, dict) or doc.get("schema") != FW_SUMMARY_SCHEMA:
        errs.append(f"schema 不是 {FW_SUMMARY_SCHEMA}")
    else:
        if doc.get("release_tag") != tag:
            errs.append("release_tag 和 inventory 的韌體 Release 不一致")
        tables = _fw_tables(doc.get("tables"), "", errs)
        rows = doc.get("samples")
        if not isinstance(rows, list) or len(rows) > 1000:
            errs.append("samples 不是陣列")
        ms = doc.get("meta_status", "OK")
        if ms not in ("OK", "GAP"):
            errs.append("meta_status 不是 OK／GAP")
        elif ms == "GAP":       # rematch 入口讀不了 firmware-meta.json：samples 是空的，全部 bios 樣本 GAP（原因照錄）
            rs = [_plain(x, 200) for x in (doc.get("reasons") if isinstance(doc.get("reasons"), list) else [])[:5] if isinstance(x, str)]
            return all_bios("GAP", "公告重跑讀不了 firmware-meta.json（meta_status GAP）：" + ("；".join(rs) or "沒有寫原因"))
    if errs:
        return all_bios("GAP", "rematch-summary.json 不合格：" + "；".join(errs[:5]))
    out["ran"] = True
    out["tables"] = tables
    for name, t in tables.items():
        if t.get("status") != "OK":
            why = f"：{t['gap']}" if isinstance(t.get("gap"), str) and t["gap"] else ""
            out["table_flags"].setdefault(name, []).append(f"狀態 {t.get('status')}（表讀不到或驗證不過，那一類元件是 NOT_ASSESSED）{why}")
        if t.get("stale") is True:
            out["table_flags"].setdefault(name, []).append("過期（stale）：不開公告 Issue")
    by_slug = {}
    for r in rows:
        if isinstance(r, dict) and isinstance(r.get("slug"), str):
            by_slug.setdefault(r["slug"], []).append(r)
    known = {p["slug"] for p in fw_projs}
    out["listed_unknown"] = sorted(x[:64] for x in by_slug if x not in known)[:20]
    # rematch 丟掉的 firmware-meta 條目（C2 介面 4ec170b：一定有 rejected，沒有時是 []；代碼不帶輸入字串）。
    # meta 是 firmware.yml 產生的，有 rejected 就是產生端有問題 → GAP（整輪降級）。格式不對也是 GAP，不默默略過
    rj = doc.get("rejected", [])
    if not isinstance(rj, list) or len(rj) > 1000:
        out["rejected"].append("rematch-summary.json 的 rejected 不是陣列")
    else:
        for x in rj[:20]:
            ok = isinstance(x, dict) and isinstance(x.get("index"), int) and not isinstance(x.get("index"), bool) \
                and 0 <= x["index"] < 100000 and isinstance(x.get("reason"), str) and FW_REJECT_RE.fullmatch(x["reason"])
            out["rejected"].append(f"firmware-meta.json 第 {x['index']} 筆（從 0 起算）：{x['reason']}" if ok
                                   else "rejected 裡有格式不對的條目（不顯示內容）")
        if len(rj) > 20:
            out["rejected"].append(f"另有 {len(rj) - 20} 筆被拒絕（只列前 20 筆）")
    for p in bios:
        u, slug = p["uuid"], p["slug"]
        if not p.get("inventory"):
            adv[u] = {"state": "NOT_RUN", "why": "Release 沒有這份樣本的 inventory（collect 沒有收到）", "results": None, "changed": [], "reasons": []}
            continue
        lst = by_slug.get(slug)
        if not lst:
            adv[u] = {"state": "NOT_RUN", "why": "不在 rematch-summary.json 裡（沒有重跑；Release 當時的結果不能頂替今天的）",
                      "results": None, "changed": [], "reasons": []}
            continue

        def gap(why, reasons=()):
            adv[u] = {"state": "GAP", "why": why, "results": None, "changed": [], "reasons": list(reasons)}
        row = lst[0]
        rreasons = [_plain(x, 200) for x in (row.get("reasons") if isinstance(row.get("reasons"), list) else [])[:10] if isinstance(x, str)]
        if len(lst) > 1:
            gap("rematch-summary.json 同一個 slug 列了不只一筆", rreasons)
            continue
        if row.get("status") not in ("OK", "ATTENTION", "GAP"):
            gap("rematch-summary.json 的 status 不是 OK／ATTENTION／GAP", rreasons)
            continue
        if row.get("output") != f"rematch-{slug}.json" or "/" in slug or "\\" in slug or "\0" in slug:
            gap("rematch-summary.json 的 output 檔名不是 rematch-<slug>.json（不讀）", rreasons)
            continue
        sd, err = _fw_read(os.path.join(dirpath, row["output"]), FW_SAMPLE_MAX)
        if sd is None:
            gap(f"{row['output']} " + ("不存在" if err == "missing" else err), rreasons)
            continue
        clean, errs = check_rematch_doc(sd, slug, tag, p["inventory"].get("sha256"))
        if clean is None:
            gap(f"{row['output']} 不合格：" + "；".join(errs[:5]), rreasons)
            continue
        if clean["status"] != row["status"]:
            gap("rematch-summary.json 與樣本檔的 status 不一致", rreasons + clean["reasons"])
            continue
        for name, t in clean["tables"].items():
            if t.get("status") != "OK" or t.get("stale") is True:
                out["table_flags"].setdefault(name, []).append(
                    ("狀態 " + str(t.get("status")) if t.get("status") != "OK" else "過期（stale）") + f"（{slug} 的重跑結果）")
        adv[u] = {"state": clean["status"], "why": None, "results": clean["results"], "changed": clean["changed"],
                  "reasons": clean["reasons"] or rreasons}
    return out


def load_state(state_dir):
    base = read_json(os.path.join(state_dir, "state-base.json"), "state-base.json")
    if not isinstance(base, dict) or "watch_issues" not in base:
        raise Fail("state-base.json 格式不對")
    sp = os.path.join(state_dir, "state.json")
    if not os.path.exists(sp):
        if base.get("issue") is not None:
            raise Fail("狀態 Issue 存在，但 state.json 沒有產生（解碼失敗？）：不重建基準")
        n = int(base.get("watch_issues") or 0)
        if isinstance(base.get("watch_keys"), list):      # 「還沒有基準」的提醒 Issue 不算監控 Issue（它是在沒有狀態時開的）
            n = len(set(base["watch_keys"]) - {issue_key(m, "no-baseline") for m in ("real", "drill")})
        if n > 0:
            raise Fail(f"沒有狀態 Issue，卻已有 {base['watch_issues']} 個監控 Issue：不能重新建立基準（會吞掉新的命中），請先找回狀態 Issue")
        return {"schema": 1, "matches": {}, "runs": []}, base, True
    st = read_json(sp, "state.json")
    if not isinstance(st, dict) or st.get("schema") != 1 or not isinstance(st.get("matches"), dict):
        raise Fail("state.json 不是 schema 1 的狀態")
    st.setdefault("runs", [])
    return st, base, False


def load_cisa(eg, feeds, overlay, work, now):
    path = os.path.join(feeds, "cisa-kev.json")
    if overlay:
        doc = read_json(overlay, "--kev-overlay")
        add = doc.get("vulnerabilities") if isinstance(doc, dict) else None
        if not isinstance(add, list) or not all(isinstance(x, dict) and CVE_RE.match(str(x.get("cveID") or "")) for x in add):
            raise Fail("--kev-overlay 格式不對（要 {\"vulnerabilities\": [{\"cveID\": …}]}）")
        try:
            with open(path, encoding="utf-8") as f:
                basedoc = json.load(f)
        except (OSError, ValueError):
            basedoc = {"vulnerabilities": []}
        vs = [v for v in basedoc.get("vulnerabilities") or [] if isinstance(v, dict)]
        have = {v.get("cveID") for v in vs}
        vs += [v for v in add if v["cveID"] not in have]
        path = os.path.join(work, "cisa-kev.overlay.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"title": basedoc.get("title", "CISA KEV (drill overlay)"), "dateReleased": basedoc.get("dateReleased") or utc(now),
                       "vulnerabilities": vs}, f)
    return eg.cisa_kev(path if os.path.isfile(path) else None, None, now), path if os.path.isfile(path) else None


# ---------- 核心 CNA ----------

FEED_LABELS = (("kernel-cve", "核心 CVE 鏡像（Linux 核心 CNA）", "這段時間新增的核心 CVE 不在清單裡"),
               ("euvd", "EUVD 鏡像", "這段時間新增的 EUVD 紀錄不在清單裡"))
_ABS_PATH = re.compile(r"(?<![\w.:/])/[^\s，、；：）)」]+")


def _feed_text(s):
    """鏡像腳本的訊息 → 可以寫進公開 Issue 的一行：去掉控制字元與 <>、絕對路徑換成 <路徑>（runner 的暫存路徑不進 Issue）、限長。"""
    s = re.sub(r"[\x00-\x1f\x7f<>]", " ", str(s))
    return re.sub(r"\s+", " ", _ABS_PATH.sub("<路徑>", s)).strip()[:300]


def feed_attention(feeds):
    """鏡像用了舊資料頂替（pipeline/lib/mirrors.sh 的 ATTENTION；核心 CVE 是 SOURCE 的 fallback=yes）→ 報告與 Issue 要寫出的行。"""
    out = []
    for name, label, lag in FEED_LABELS:
        line = ""
        try:
            with open(os.path.join(feeds, name + ".result"), encoding="utf-8", errors="replace") as f:
                line = f.readline().strip()
        except OSError:
            pass
        src = {}
        try:
            with open(os.path.join(feeds, name, "SOURCE"), encoding="utf-8", errors="replace") as f:
                src = dict(x.split("=", 1) for x in f.read().splitlines() if "=" in x)
        except OSError:
            pass
        if src.get("fallback") == "yes":
            why = src.get("fallback_note") or f"沿用下載於 {src.get('fetched_utc') or '?'} 的上一份"
        elif line.startswith("ATTENTION"):
            why = line[len("ATTENTION"):].strip() or "鏡像腳本回報 ATTENTION"
        else:
            continue
        why = _feed_text(why)
        out.append(f"{label}用了舊資料頂替：{why}" + ("" if lag in why else f"：{lag}"))
    return out


def add_feed_note(actions, lines):
    """這次執行的資料源用了舊資料頂替：每個要開的 Issue、留言都寫出那幾行（報告另外列在「需注意」）。"""
    if not lines:
        return actions
    note = "\n\n> **這次執行的資料源用了舊資料頂替（ATTENTION）**\n" + "\n".join(f"> - {md_cell(x)}" for x in lines)
    for x in actions:
        x["body"] = x["body"] + note
    return actions


def kernel_upstreams(path):
    """kernel-versions-<專案>-<版本>.json → ([(upstream_version, 說明)], [GAP 說明])。"""
    if not path:
        return [], ["Release 沒有附 kernel-versions 附件（M2 之前的 Release？）：核心 CNA 沒有比對（GAP）"]
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError) as e:
        return [], [f"kernel-versions 附件讀不到（{type(e).__name__}）：核心 CNA 沒有比對（GAP）"]
    if not isinstance(doc, dict) or doc.get("schema") != KV_SCHEMA:
        got = doc.get("schema") if isinstance(doc, dict) else None
        return [], [f"kernel-versions 附件的 schema 是 {str(got)[:60]!r}，只接受 {KV_SCHEMA}（不猜格式）：核心 CNA 沒有比對（GAP）"]
    sh = doc.get("shipped")
    if sh is None:
        return [], ["kernel-versions 附件的 shipped 是 null（出貨的核心讀不出來）：核心 CNA 沒有比對（GAP）"]
    if not isinstance(sh, list):
        return [], ["kernel-versions 附件的 shipped 格式不對：核心 CNA 沒有比對（GAP）"]
    out, gaps = [], []
    for k in sh:
        if not isinstance(k, dict):
            gaps.append(f"核心 {str(k)[:40]} 沒有 upstream_version 欄位（舊格式）：核心 CNA 沒有比對（GAP）")
            continue
        v, note = k.get("upstream_version"), str(k.get("upstream_note") or "")[:200]
        rel = str(k.get("version") or k.get("release") or "?")[:60]
        if isinstance(v, str) and UPSTREAM_RE.match(v):
            out.append((v, rel, str(k.get("upstream_basis") or "")[:40]))
        else:
            gaps.append(f"核心 {rel} 的上游版本對不上（{note or '沒有說明'}）：核心 CNA 沒有比對（GAP）")
    return out, gaps


def run_kernel_cna(version, mirror, work, runner=None):
    """→ ({CVE: verdict}（affected／unknown）或 None, 說明)。"""
    if runner:
        return runner(version, mirror)
    if not os.path.isfile(KERNEL_CNA):
        return None, "tools/pilot/lib/kernel_cna_version.py 不存在（M2 合併前）：NOT_RUN"
    if not mirror or not os.path.isdir(mirror):
        return None, "沒有核心 CNA 鏡像：NOT_RUN"
    out, lst = os.path.join(work, f"kcna-{version}.json"), os.path.join(work, f"kcna-{version}.txt")
    try:
        r = subprocess.run([sys.executable, "-I", KERNEL_CNA, "--kernel-version", version, "--mirror", mirror, "--out", out, "--cves-out", lst],
                           stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=600, errors="replace")
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, f"kernel_cna_version.py 沒跑完（{type(e).__name__}）：NOT_RUN"
    line = next((x for x in r.stdout.splitlines() if x.startswith("KERNEL-CNA-VERSION\t")), "")
    if r.returncode != 0 or not os.path.isfile(out):
        return None, f"kernel_cna_version.py 失敗（exit={r.returncode}）：NOT_RUN"
    try:
        with open(out, encoding="utf-8") as f:
            doc = json.load(f)
        res = {c["cve"]: c["verdict"] for c in doc.get("cves") or [] if isinstance(c, dict) and c.get("verdict") in ("affected", "unknown")}
    except (OSError, ValueError, KeyError, TypeError) as e:
        return None, f"kernel_cna_version.py 的輸出讀不到（{type(e).__name__}）：NOT_RUN"
    return res, (line.split("\t", 2) + ["", ""])[2][:300]


def kernel_matches(p, upstreams, mirror, work, exploited_cves, eu, ew, runner=None):
    """→ ({鍵: 比對}, 完整跑完, 說明清單)。只對 bsp（或沒有分層時的 product）層。"""
    out, notes, ok = {}, [], True
    for v, rel, basis in upstreams:
        res, detail = run_kernel_cna(v, mirror, work, runner)
        notes.append(f"核心 {rel}（上游 {v}，依據 {basis or '?'}）：{detail}")
        if res is None:
            ok = False
            continue
        for cve, verdict in sorted(res.items()):
            if cve not in exploited_cves:
                continue
            purl = f"pkg:generic/linux@{v}"
            key = json.dumps([p["uuid"], cve, purl], ensure_ascii=False)
            ev = dict(eu[cve], listed_now=True) if cve in (eu or {}) else None
            srcs = [f"Linux kernel CNA ({verdict}; .config not judged)"] + [s for s in exploited_cves[cve]] + ([ew.euvd_text(ev)] if ev else [])
            out[key] = {"project": p["name"], "version": p["version"], "project_uuid": p["uuid"], "cve": cve, "purl": purl,
                        "component": f"linux@{v} ({rel})", "basis": "kernel_cna", "vuln_ids": [cve], "analysis": [], "refs": [],
                        "euvd": ev, "sources": srcs}
    return out, ok, notes


# ---------- 狀態 → Issue ----------

STATE_FIELDS = ("first_detected", "cve_first_detected", "assess_after", "status", "history", "gone_since", "last_seen", "baseline",
                "project", "version", "project_uuid", "cve", "purl", "component", "basis", "vuln_ids", "euvd", "sources", "first_included")
VENDOR_FIELDS = ("first_detected", "status", "baseline", "history", "gone_since", "last_seen", "project", "version", "project_uuid", "cve",
                 "vendor", "kev_vendor", "kev_product", "date_added", "kev_sources", "source", "vendor_from", "watch_via", "component_count")


PRUNE_DAYS = 180            # 消失超過這麼多天的比對從狀態移除（10 年保存是 GitLab 階段的內部儲存，不靠公開 Issue）
STATE_MAX_CHARS = 60000     # 同 issues.py MAX_BODY
STATE_WARN_CHARS = 45000


def state_size(st):
    """跟 issues.py encode_state 同樣的編碼（gzip＋base64，每 76 字元換行）估算長度。"""
    import base64
    import gzip
    raw = json.dumps(st, sort_keys=True, ensure_ascii=False).encode("utf-8")
    b = base64.b64encode(gzip.compress(raw, mtime=0))
    return len(b) + len(b) // 76 + 200


def prune_state(st, now):
    """消失超過 PRUNE_DAYS 天的比對（matches、vendor_matches）與沒有剩下任何比對、開了超過 PRUNE_DAYS 天的群組紀錄。回傳說明或空字串。
    被修剪的比對之後再出現時算新的（開新 Issue；偏保守）。"""
    cut = now - datetime.timedelta(days=PRUNE_DAYS)

    def old(t):
        try:
            return t and parse_now(t) < cut
        except Fail:
            return False
    n1 = n2 = n3 = 0
    for coll in ("matches", "vendor_matches"):
        d = st.get(coll) or {}
        for k in [k for k, e in d.items() if isinstance(e, dict) and e.get("status") == "gone" and old(e.get("gone_since"))]:
            del d[k]
            if coll == "matches":
                n1 += 1
            else:
                n2 += 1
    iss = (st.get("dumpling") or {}).get("issues") or {}
    mode = (st.get("dumpling") or {}).get("mode") or "real"
    live = {kev_group_key(mode, e) for e in (st.get("matches") or {}).values() if isinstance(e, dict) and "project_uuid" in e} | \
        {vendor_group_key(mode, e) for e in (st.get("vendor_matches") or {}).values() if isinstance(e, dict) and "vendor" in e} | \
        fw_live_keys(mode, st)
    pk = (st.get("dumpling") or {}).setdefault("pruned_keys", []) if st.get("dumpling") is not None else []
    for k in [k for k, r in iss.items() if k not in live and old((r or {}).get("opened_at"))]:
        del iss[k]
        if k not in pk:
            pk.append(k)          # 這個群組有過 Issue（可能已關閉）：之後再出現用 open_if_closed，不會被「已有 Issue」跳過（#32 驗證 F2）
        n3 += 1
    return f"比對 {n1}、廠商層級 {n2}、群組紀錄 {n3}（消失或開出超過 {PRUNE_DAYS} 天）" if n1 or n2 or n3 else ""


def sanitize_state(st):
    """只留公開欄位（WATCH.md 3.5：不放路徑、主機資訊）。"""
    out = {"schema": 1, "matches": {}, "vendor_matches": {}, "vendor_watch": {}, "runs": (st.get("runs") or [])[-RUNS_KEEP:],
           "dumpling": st.get("dumpling") or {}}
    for k, e in (st.get("matches") or {}).items():
        out["matches"][k] = {f: e[f] for f in STATE_FIELDS if f in e}
        if isinstance(e.get("grype"), dict):
            out["matches"][k]["grype"] = {x: e["grype"].get(x) for x in ("sbom_sha256", "component_version")}
    for k, e in (st.get("vendor_matches") or {}).items():
        out["vendor_matches"][k] = {f: e[f] for f in VENDOR_FIELDS if f in e}
    vw = st.get("vendor_watch") or {}
    out["vendor_watch"] = {"enabled_at": vw.get("enabled_at"), "watched": vw.get("watched") or {}}
    if "supplementary" in st:
        out["supplementary"] = st["supplementary"]
    if isinstance(st.get("firmware"), dict):
        out["firmware"] = sanitize_firmware(st["firmware"])
    return out


def sanitize_firmware(fw):
    """firmware 狀態：只留公開欄位、限制大小（WATCH.md 3.5）。tables：表的識別（字串、布林）；
    samples：{監控鍵: {image_sha256, image_sha256_history, advisory: {key: {kind, result, bulletins, component, review, baseline}}}}。"""
    out = {"tables": {}, "samples": {}}
    if isinstance(fw.get("size_stopped_at"), str):          # 韌體因狀態大小上限停止的時間（狀態 Issue 的摘要看得到）
        out["size_stopped_at"] = fw["size_stopped_at"][:40]
    for n, t in (fw.get("tables") or {}).items() if isinstance(fw.get("tables"), dict) else []:
        if n in FW_TABLES and isinstance(t, dict):
            out["tables"][n] = {k: v for k, v in t.items() if isinstance(k, str) and isinstance(v, (str, bool))}
    for u, x in (fw.get("samples") or {}).items() if isinstance(fw.get("samples"), dict) else []:
        if not isinstance(x, dict) or not isinstance(u, str):
            continue
        hist = x.get("image_sha256_history") if isinstance(x.get("image_sha256_history"), list) else []
        sm = {"image_sha256": x.get("image_sha256") if isinstance(x.get("image_sha256"), str) else None,
              "image_sha256_history": [{k: h.get(k) for k in ("at", "old", "new")} for h in hist
                                       if isinstance(h, dict) and all(isinstance(h.get(k), str) for k in ("at", "old", "new"))][-FW_HISTORY_KEEP:],
              "advisory": {}}
        adv = x.get("advisory") if isinstance(x.get("advisory"), dict) else {}
        for k, e in list(adv.items())[:FW_MAX_AFFECTED]:
            # 型別不對的紀錄丟掉（讀入的舊狀態可能被手改；fw_groups 不能因此當掉）
            if not (isinstance(k, str) and FW_KEY_RE.fullmatch(k) and isinstance(e, dict) and e.get("kind") in FW_KINDS
                    and isinstance(e.get("result"), str) and isinstance(e.get("bulletins"), list)
                    and len(e["bulletins"]) <= FW_MAX_BULLETINS and all(isinstance(b, str) and len(b) <= 80 for b in e["bulletins"])):
                continue        # 超過上限不截斷（截斷後看起來像完整的）：整筆丟掉
            rec = {"kind": e["kind"], "result": e["result"][:40], "bulletins": list(e["bulletins"])}
            if isinstance(e.get("component"), str):
                rec["component"] = e["component"][:300]
            if e.get("review") in ("preliminary", "confirmed", None) and "review" in e:
                rec["review"] = e["review"]
            if isinstance(e.get("baseline"), bool):
                rec["baseline"] = e["baseline"]
            sm["advisory"][k] = rec
        out["samples"][u] = sm
    return out


# ---------- 寫進公開 Issue 的外部字串（#49 驗證應修 3） ----------
# 元件名、purl、KEV 的廠商／產品、release-meta 的 attention、kernel-versions 的說明、鏡像訊息……都是外部資料：
# @ 會通知 GitHub 上的使用者或組織（例如 npm 的 @types/node），[x](url)、![i](url) 會變成連結或圖片，#123 會連到別的 Issue。
_MD_CTRL = re.compile(r"[\x00-\x1f\x7f\u200b-\u200f\u2028\u2029\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]")
ZWSP = "\u200b"


def _plain(x, limit):
    return re.sub(r"\s+", " ", _MD_CTRL.sub(" ", str(x if x is not None else ""))).strip()[:limit]


def _load_mdsafe():
    """C2 的 pipeline/lib/firmware_mdsafe.py（不可信文字進 Markdown 的共用規則，只用標準庫）。用檔案路徑載入，不改 sys.path。"""
    spec = importlib.util.spec_from_file_location(
        "firmware_mdsafe", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib", "firmware_mdsafe.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_MDSAFE = _load_mdsafe()


def md_text(x, limit=300):
    """外部字串 → Markdown 純文字。和 C2 的 firmware_mdsafe.md_safe 用同一套規則（C0 決定，2026-11-14）：
    去控制與格式字元（含單獨的代理字元、零寬字元、雙向覆寫）、& 先換成 &amp;、跳脫 \\ [ ] ( ) < > ! * _ # ~ | ` $、
    提及形式的 @ 與會被 cmark-gfm／markdown-it 自動連結的 email、scheme://、www. 都斷開（細節見 firmware_mdsafe 的檔頭）。
    以前的 md_text 擋不住 www.、email 自動連結與單獨的代理字元（C2 #96 驗證比對 3327 筆輸入，219 筆會變成連結）。
    超過 limit 截斷時結尾加「…」。表格儲存格也用這個。
    md_safe 之後再補一道 Issue 參照（只在進 Issue 的文字需要；C2 的韌體報告不進 Issue，firmware_mdsafe 不改）：
    `#`／`＃` 後面接數字時插零寬空白（`\\#123` 只在 Markdown 那一層有效：GitHub 在渲染後的文字比對 Issue 參照，
    2026-11-14 用 GitHub 的 POST /markdown 實測：`\\#1`、`owner/repo\\#1`、`GH-1` 都會變成 issue-link，`#`＋零寬空白＋`1`、`GH`＋零寬空白＋`-1` 不會），
    `GH-123` 在 `GH` 後面插零寬空白。"""
    return _issue_refs_off(_MDSAFE.md_safe("" if x is None else x, limit))


_ISSUE_REF = re.compile(r"(\\?[#＃])(?=[0-9０-９])")
_GH_REF = re.compile(r"(?i)(?<![A-Za-z0-9])(gh)(?=-[0-9])")


def _issue_refs_off(s):
    """`#123`、`owner/repo#123`、`\\#123`、`＃123`、`GH-123`：插零寬空白，GitHub 不會連到別的 Issue／PR，也不會在對方的時間軸留下 cross-reference。"""
    s = _ISSUE_REF.sub(lambda m: m.group(1) + ZWSP, s)
    return _GH_REF.sub(lambda m: m.group(1) + ZWSP, s)


md_cell = md_text


def md_code(x, limit=300):
    """外部的識別字（元件名、purl、CVE 來源）→ 行內程式碼：原樣可複製，裡面的 @、連結、圖片都不會被解讀。
    反引號：用比內容最長的連續反引號多一個的分隔符號；| 跳脫（GFM 表格在行內程式碼裡也要跳脫）。"""
    s = _plain(x, limit)
    if not s:
        return "—"
    s = s.replace("|", "\\|")
    fence = "`" * (max((len(r) for r in re.findall(r"`+", s)), default=0) + 1)
    return f"{fence} {s} {fence}"


def md_title(x, limit=200):
    """Issue 標題裡的外部字串：去控制字元，@ # & 後面插零寬空白（標題不解讀 Markdown 跳脫，所以不加反斜線；
    & 也不換成 &amp;，不然標題會照字面顯示 &amp;。& 後面有零寬空白就不會被當成 HTML 實體）。"""
    return _GH_REF.sub(lambda m: m.group(1) + ZWSP, re.sub(r"([@#＠＃&＆])", "\\1" + ZWSP, _plain(x, limit)))


_CODE_SPAN = re.compile(r"(`+)(?:(?!\1).)+?\1", re.S)
_UNSAFE = (re.compile(r"(?<![\\\w])[@＠](?!\u200b)[A-Za-z0-9_-]"), re.compile(r"(?<!\\)\]\("), re.compile(r"(?<!\\)!\[(?!\\)"),
           re.compile(r"&(?!amp;)(?:[A-Za-z][A-Za-z0-9]*;|#)"))       # HTML 實體（md_text 自己產生的 &amp; 除外）


def unsafe_markdown(text):
    """最後一道檢查：行內程式碼以外，還有沒有沒淨化的 @提及、](連結、![圖片、HTML 實體（&name; 與 &#）。回傳找到的片段（空＝沒有）。"""
    t = _CODE_SPAN.sub(" ", text)
    return [m.group(0) for rx in _UNSAFE for m in rx.finditer(t)][:3]


def unsafe_actions(actions):
    """所有動作的 unsafe_markdown 結果。標題不是 Markdown（] ( ! 照字面顯示），只算 @提及 與 HTML 實體。"""
    return [x for act in actions for x in unsafe_markdown(act.get("body", ""))
            + [y for y in unsafe_markdown(act.get("title", "")) if y[0] in "@＠&"]]


def kev_group_key(mode, e):
    return issue_key(mode, "kev", e["project_uuid"], e["cve"])


def vendor_group_key(mode, e):
    """廠商層級的群組：同一個廠商 × CVE 只開一個 Issue，內文列出受影響的版本（D-064 B，C0 決定 2026-11-15）。
    不含專案 UUID：原本一份 SBOM 一個，Intel 新 KEV 會對每個版本的 bsp／os 各開一個。狀態（vendor_matches 的鍵）不變。"""
    return issue_key(mode, "vendor", e["cve"], e["vendor"])


def pinfo_of(projs, uuid):
    return next((p for p in projs if p["uuid"] == uuid), None)


# ---------- 韌體公告 Issue 與狀態（docs/FIRMWARE-WATCH.md §5） ----------

def fw_entry_of(r, baseline):
    """一筆 affected／affected-candidate 的結果 → 狀態裡的紀錄（只存這兩種，控制大小）。"""
    # 公告 ID 超過 FW_MAX_BULLETINS 的結果在 check_rematch_doc 就讓整份樣本 GAP（results 是 None，走不到這裡）；這裡不再切片
    if len(r["bulletins"]) > FW_MAX_BULLETINS:
        raise Fail(f"內部錯誤：公告 ID 超過 {FW_MAX_BULLETINS} 筆的結果不該寫進狀態（{r.get('key')!r:.80}）")
    e = {"kind": r["kind"], "result": r["result"], "bulletins": list(r["bulletins"]), "component": _plain(r["component"], 120)}
    if r.get("review"):
        e["review"] = r["review"]
    if baseline:
        e["baseline"] = True
    return e


def fw_update(state, inv_fw, fw_projs, rm, first, ts):
    """這一輪的韌體狀態：每個監控鍵最近一次的 image_sha256（與變化的歷史）、affected 的公告比對結果、三張表的識別。
    → {"samples", "prev_samples", "tables", "changes", "evaluated", "rm", "projs"}（呼叫端把 samples、tables 寫進 state["firmware"]）。
    - 公告沒有重跑（NOT_RUN）或檔案不合格（GAP）的樣本：沿用上一次的紀錄（不當成「不再受影響」）。
    - 這次的韌體 Release 沒收到或有 problem（meta 壞掉）：整份沿用上一次；其餘不在這次清單裡的鍵才移除（樣本離開最新的 Release）。
    - image_sha256 是 null：不比、保留舊值。"""
    # 讀入的舊狀態也當外來資料（狀態 Issue 可能被手改）：先 sanitize，型別不對的紀錄丟掉，不能讓 match 當掉
    prev = sanitize_firmware(state["firmware"]) if isinstance(state.get("firmware"), dict) else {}
    ps_all = {u: x for u, x in (prev.get("samples") or {}).items() if isinstance(x, dict)} if isinstance(prev.get("samples"), dict) else {}
    carry_all = not isinstance(inv_fw, dict) or bool(inv_fw.get("problems"))
    listed = {uuid_of(FW_PROJECT, x["watch_version"], FW_LAYER) for x in ((inv_fw or {}).get("samples") or [])
              if isinstance(x, dict) and isinstance(x.get("watch_version"), str)}
    cur = {p["uuid"] for p in fw_projs}
    samples, changes, evaluated = {}, [], {}
    for u, x in ps_all.items():
        if u not in cur and (carry_all or u in listed):
            samples[u] = x
    for p in fw_projs:
        u = p["uuid"]
        old_s = ps_all.get(u) or {}
        hist = [h for h in old_s.get("image_sha256_history") or [] if isinstance(h, dict)][-FW_HISTORY_KEEP:]
        old, img = old_s.get("image_sha256"), p.get("image_sha256")
        if img is None:
            img = old if isinstance(old, str) else None
        elif isinstance(old, str) and old != img:
            hist = (hist + [{"at": ts, "old": old, "new": img}])[-FW_HISTORY_KEEP:]
            changes.append({"uuid": u, "slug": p["slug"], "old": old, "new": img})
        a = rm["adv"].get(u) or {}
        pa = old_s.get("advisory") if isinstance(old_s.get("advisory"), dict) else {}
        if a.get("results") is not None:
            now_adv, ev = {}, {}
            for r in a["results"]:
                ev[r["key"]] = r
                if r["result"] == FW_AFFECTED[r["kind"]]:
                    now_adv[r["key"]] = fw_entry_of(r, first or bool((pa.get(r["key"]) or {}).get("baseline")))
            evaluated[u] = ev
        else:
            now_adv = pa
        samples[u] = {"image_sha256": img, "image_sha256_history": hist, "advisory": now_adv}
    tables = rm["tables"] if rm["tables"] is not None else (prev.get("tables") if isinstance(prev.get("tables"), dict) else {})
    return {"samples": samples, "prev_samples": ps_all, "tables": tables, "changes": changes, "evaluated": evaluated, "rm": rm,
            "projs": fw_projs}


def fw_groups(mode, samples):
    """firmware.samples → {群組鍵: {"kind", "id", "members": {uuid: {key: 紀錄}}}}。
    規則表、vBIOS（result affected）：每個公告 ID 一個群組（issue_key(mode, "fwadv", 公告 ID)）；
    Intel 微碼（affected-candidate）：每個 rematch key 一個群組（issue_key(mode, "fwadv-ucode", key)，key 當不透明字串）。"""
    out = {}
    for u, sm in (samples or {}).items():
        for key, e in ((sm or {}).get("advisory") or {}).items():
            if not isinstance(e, dict):
                continue
            if e.get("kind") in ("rule", "nvidia-vbios") and e.get("result") == "affected":
                gks = [(issue_key(mode, "fwadv", b), "fwadv", b) for b in e.get("bulletins") or []]
            elif e.get("kind") == "intel-microcode" and e.get("result") == "affected-candidate":
                gks = [(issue_key(mode, "fwadv-ucode", key), "fwadv-ucode", key)]
            else:
                continue
            for gk, kind, gid in gks:
                out.setdefault(gk, {"kind": kind, "id": gid, "members": {}})["members"].setdefault(u, {})[key] = e
    return out


def fw_live_keys(mode, st):
    """狀態裡還有 affected 的公告群組鍵（prune_state 不能把它們的群組紀錄修剪掉）。"""
    fw = st.get("firmware") if isinstance(st.get("firmware"), dict) else {}
    return set(fw_groups(mode, fw.get("samples") if isinstance(fw.get("samples"), dict) else {}))


def fw_wording(entries):
    """用語（C0 決定）：規則表 preliminary → 初步規則，待人審；confirmed → 規則已確認，待負責單位確認；不能寫成確定受影響。"""
    if any(e.get("kind") == "rule" and e.get("review") != "confirmed" for e in entries):
        return FW_WORD_PRELIM
    if any(e.get("kind") == "nvidia-vbios" for e in entries):
        return FW_WORD_VBIOS
    return FW_WORD_CONFIRMED


def fw_tables_text(tables, names):
    out = []
    for n in names:
        t = (tables or {}).get(n)
        if isinstance(t, dict):
            out.append(f"  - {md_code(n)}：" + "、".join(f"{md_code(k)} = {md_code(str(v).lower() if isinstance(v, bool) else v)}" for k, v in sorted(t.items())))
        else:
            out.append(f"  - {md_code(n)}：沒有這次的識別")
    return out


def _fw_label(by_uuid, u):
    p = by_uuid.get(u)
    return (md_code(p["slug"]), md_text(p.get("firmware_version") if p.get("firmware_version") is not None else p.get("version"), 80),
            md_code(p.get("image_sha256") or "—")) if p else (md_code(u), "—", "—")


def fw_group_title(g, entries, by_uuid):
    n = len(g["members"])
    if g["kind"] == "fwadv-ucode":
        comp = next((e.get("component") for e in entries if e.get("component")), None) or g["id"]
        cands = {b for e in entries for b in e.get("bulletins") or []}
        return f"[韌體公告] Intel {md_title(comp)}：{len(cands)} 個候選公告（{FW_WORD_UCODE}）"
    slugs = sorted(by_uuid[u]["slug"] if u in by_uuid else u for u in g["members"])
    tail = md_title(slugs[0]) + (f" 等 {n} 份樣本" if n > 1 else "")
    return f"[韌體公告] {md_title(g['id'])} {fw_wording(entries)}：{tail}"


def fw_group_body(mode, g, entries, fw, by_uuid, p0, run_url, now, tables):
    ev = fw["evaluated"]
    lines = ["> **演練（合成資料）**：這是每日監控的演練 Issue，不是真的漏洞通知。", ""] if mode == "drill" else []
    ucode = g["kind"] == "fwadv-ucode"
    if ucode:
        cands = sorted({b for e in entries for b in e.get("bulletins") or []})
        lines += [f"Intel 微碼 **{md_text(next((e.get('component') for e in entries if e.get('component')), None) or g['id'])}**："
                  f"SBOM 的微碼 revision 比某個微碼 release 舊，就把那個 release 列的 INTEL-SA 都列成候選（{FW_WORD_UCODE}）。"
                  "這是 release 層級的版本比較，**不是確認受影響**；是否受影響由負責單位確認。", "",
                  f"- 候選公告（{len(cands)} 個）：{'、'.join(md_code(b) for b in cands)}"]
    else:
        lines += [f"**{md_text(g['id'])}**：韌體公告比對的結果是 **{fw_wording(entries)}**。"
                  "這是 repo 當下的比對表對韌體 inventory 的比對結果，**不是確定受影響**；是否受影響由負責單位確認。", ""]
    if p0:
        lines += [f"- 韌體 Release：{md_code(p0.get('tag'))}（{md_code(p0.get('html_url'))}）",
                  f"- 狀態：development（公開的示範樣本，不是出貨品）；{HANDLING['development']}"]
    kinds = sorted({e.get("kind") for e in entries})
    basis = {"rule": "規則表（fw-advisory-rules.json）；review 是 preliminary 的規則是初步的，要人審",
             "intel-microcode": "Intel 微碼發佈資料表（revision 的版本比較）",
             "nvidia-vbios": "NVIDIA vBIOS 對照表（對照表的列、裝置 ID、vBIOS 版本寫在下面的「依據」欄，表的 reviewed_until 在表的識別）"}
    lines += [f"- 比對依據：{'；'.join(basis[k] for k in kinds if k in basis)}",
              "- 表的識別（公告重跑的結果）："] + fw_tables_text(tables, sorted({FW_TABLE_OF[k] for k in kinds if k in FW_TABLE_OF}))
    lines += ["", f"受影響的樣本（{len(g['members'])} 份）：", "", "| 樣本 | 版本 | 元件 | key | 映像 sha256 | 依據 |", "|---|---|---|---|---|---|"]
    for u in sorted(g["members"], key=lambda x: (by_uuid[x]["slug"] if x in by_uuid else x)):
        slug, ver, img = _fw_label(by_uuid, u)
        for key, e in sorted(g["members"][u].items()):
            reason = (((ev.get(u) or {}).get(key) or {}).get("reason"))
            lines.append(f"| {slug} | {ver} | {md_code(e.get('component'))} | {md_code(key)} | {img} | "
                         f"{md_text(reason) if reason else md_text(e.get('review') or '—')} |")
    lines += ["", "限制：公告重跑只反映表的更新，不重新解析映像；比不到的元件是 NOT_ASSESSED（以廠商公告為準）。"
              "Issue 不會自動關閉，請負責單位確認後關閉。"]
    if run_url:
        lines += ["", f"執行紀錄：{run_url}"]
    return "\n".join(lines)


def fw_plan(mode, state, fw, projs, iss, target, ts, run_url, now):
    """→ (要新開的群組 pending 項目, 留言動作)。
    新開：群組有至少一筆不是基準的紀錄、還沒有 Issue、而且它那一類的表沒有過期或 GAP。
    已有 Issue 的群組：新的樣本 → open_if_closed（只列新的；原 Issue 關閉了就開新的）；樣本離開（不再 affected、變 NOT_ASSESSED、不在結果裡）、
    微碼的候選清單變了 → comment（不自動關閉）。image_sha256 變了：這個鍵每個開著的 KEV、廠商層級、公告群組 Issue 各留言一次。"""
    by_uuid = {p["uuid"]: p for p in projs}
    prev_g, cur_g = fw_groups(mode, fw["prev_samples"]), fw_groups(mode, fw["samples"])
    bad_tables = {n for n, v in fw["rm"]["table_flags"].items() if v}
    pending, acts = [], []
    p0 = next((p for p in fw["projs"]), None)
    for gk in sorted(set(cur_g) | set(prev_g), key=lambda k: ((cur_g.get(k) or prev_g[k])["kind"], (cur_g.get(k) or prev_g[k])["id"])):
        g, pg = cur_g.get(gk), prev_g.get(gk)
        if g is not None and gk not in iss:
            entries = [e for m in g["members"].values() for e in m.values()]
            if all(e.get("baseline") for e in entries):
                continue                                    # 基準：不開 Issue（比照 KEV）
            if any(FW_TABLE_OF.get(e.get("kind")) in bad_tables for e in entries):
                continue                                    # 表過期或 GAP：不開公告 Issue（需注意與狀態看得到）
            labels = list(FW_ISSUE_LABELS)
            pending.append((gk, "fwadv", fw_group_title(g, entries, by_uuid), fw_group_body(mode, g, entries, fw, by_uuid, p0, run_url, now, fw["tables"]),
                            labels, {"first_detected": ts}))
            continue
        t = target(gk)
        if not t:
            continue
        gm, pm = (g or {"members": {}})["members"], (pg or {"members": {}})["members"]
        new = [u for u in gm if u not in pm]
        left = [u for u in pm if u not in gm]
        lines = []
        entries = [e for m in gm.values() for e in m.values()] or [e for m in pm.values() for e in m.values()]
        kind_g = (g or pg)
        if new:
            lines += [f"新增受影響的樣本（{len(new)} 份）：", ""]
            for u in sorted(new, key=lambda x: (by_uuid[x]["slug"] if x in by_uuid else x)):
                slug, ver, img = _fw_label(by_uuid, u)
                for key, e in sorted(gm[u].items()):
                    lines.append(f"- {slug}（{ver}）：元件 {md_code(e.get('component'))}、key {md_code(key)}、映像 sha256 {img}")
        if kind_g["kind"] == "fwadv-ucode" and g is not None and pg is not None and gm and pm:
            pc = sorted({b for m in pm.values() for e in m.values() for b in e.get("bulletins") or []})
            cc = sorted({b for m in gm.values() for e in m.values() for b in e.get("bulletins") or []})
            if pc != cc:
                lines += ["", "候選公告清單變了：", f"- 之前（{len(pc)} 個）：{'、'.join(md_code(b) for b in pc) or '—'}",
                          f"- 現在（{len(cc)} 個）：{'、'.join(md_code(b) for b in cc) or '—'}"]
        if left:
            lines += ["", f"離開的樣本（{len(left)} 份；Issue 不會自動關閉）：", ""]
            for u in sorted(left, key=lambda x: (by_uuid[x]["slug"] if x in by_uuid else x)):
                slug, ver, img = _fw_label(by_uuid, u)
                for key in sorted(pm[u]):
                    r = (fw["evaluated"].get(u) or {}).get(key)
                    if u not in by_uuid:
                        why = "樣本不在這次監控的韌體 Release 裡"
                    elif r is not None:
                        why = f"這次的結果是 {md_code(r['result'])}" + (f"（公告 {'、'.join(md_code(b) for b in r['bulletins'])}）" if r["bulletins"] else "")
                    else:
                        why = "這個 key 不在這次的結果裡"
                    lines.append(f"- {slug}（{ver}）：key {md_code(key)}：{why}")
        if not lines:
            continue
        head = f"{md_text(kind_g['id'])} 的韌體公告比對有變化（{ts}）：" if kind_g["kind"] == "fwadv" else \
            f"Intel 微碼 {md_text(next((e.get('component') for e in entries if e.get('component')), None) or kind_g['id'])} 的候選有變化（{ts}）："
        body = "\n".join([head, ""] + lines + ["", "這是公告比對的建議，不是確定受影響；原 Issue 已關閉時會開新的 Issue。" + (f"執行紀錄：{run_url}" if run_url else "")])
        if new:
            gg = g
            acts.append({"op": "open_if_closed", "key": t, "title": fw_group_title(gg, entries, by_uuid) if gg else "[韌體公告] 新的樣本", "body": body,
                         "labels": list(FW_ISSUE_LABELS)})
        else:
            acts.append({"op": "comment", "key": t, "body": body, "reopen_if_closed": False})
    # image_sha256 變了：同 slug、同版本，內容卻不同。不開新鍵；這個鍵每個開著的 Issue 各留言一次
    for ch in fw["changes"]:
        u = ch["uuid"]
        targets = {}
        for e in state["matches"].values():
            if isinstance(e, dict) and e.get("project_uuid") == u and e.get("status") == "open" and "cve" in e:
                gk = kev_group_key(mode, e)
                if gk in iss:
                    targets.setdefault(target(gk), f"KEV {e['cve']}")
        for e in (state.get("vendor_matches") or {}).values():
            if isinstance(e, dict) and e.get("project_uuid") == u and e.get("status") == "open" and "vendor" in e:
                gk = vendor_group_key(mode, e)
                if gk in iss:
                    targets.setdefault(target(gk), f"廠商層級 {e['cve']}")
        for gk, g in cur_g.items():
            if u in g["members"] and gk in iss:
                targets.setdefault(target(gk), f"公告 {g['id']}")
        slug, ver, _ = _fw_label(by_uuid, u)
        for t in sorted(k for k in targets if k):
            acts.append({"op": "comment", "key": t, "reopen_if_closed": False,
                         "body": "\n".join([f"樣本 {slug}（{ver}）的映像 sha256 變了（{ts}）：", "",
                                           f"- 之前：{md_code(ch['old'])}", f"- 現在：{md_code(ch['new'])}", "",
                                           "同一個樣本、同一個版本，內容卻不同（廠商重新發布了檔案？）：監控鍵不變，沒有開新的 Issue，這個 Issue 的判斷要重新確認。"
                                           + (f"執行紀錄：{run_url}" if run_url else "")])})
    return pending, acts


def release_results(p):
    """Release 的結論（release-meta；缺少時 NOT_RUN）。status 是生命週期，這幾個才是掃描與發行的結論。"""
    if is_fw(p):
        return (f"韌體示範樣本（沒有 release-meta）；firmware-meta 的樣本狀態 {md_text(p.get('meta_status') or '—')}、"
                f"firmware.yml 的 expected 結果 {md_text(p.get('expect') or '—')}")
    if not p:
        return "報告狀態 NOT_RUN（找不到 Release 資訊）"
    reps = "、".join(f"{x['report']} 報告 {x['report_status']}／閘門 {x['release_gate']}" for x in p.get("reports") or [])
    out = (f"報告狀態（report_status）{p.get('report_status') or 'NOT_RUN'}；發行閘門（release_gate）{p.get('release_gate') or 'NOT_RUN'}"
           + (f"（各報告：{reps}）" if reps else "（各報告：release-meta 沒有 reports）")
           + f"；流程結果（pipeline_result）{p.get('pipeline_result') or 'NOT_RUN'}"
           "（取自 Release 的 release-meta.json；生命週期 shipped／development 不是掃描結論）")
    if p.get("meta_attention"):
        out += "；Release 建置時用了舊資料頂替：" + "；".join(md_text(x) for x in p["meta_attention"])
    return out


def layer_note(p):
    if not p:
        return ""
    if p["layer"] == "os" and p.get("os_responsibility") in ("customer", "upstream-vendor"):
        return "OS 層（範例 rootfs）：列入「通知客戶」，不是我們的修補待辦。"
    return {"bsp": "BSP 層：我們的待辦。", "os": "OS 層：我們的待辦（os_responsibility: ours）。",
            "product": "沒有分層 SBOM（整份產品）：當成我們的待辦。",
            "firmware": "韌體層（公開的示範樣本）：交 RD 與韌體負責人確認。"}.get(p["layer"], "")


def labels_for(p, kind):
    ls = ["kev"] if kind == "kev" else ["vendor-level"]
    if p:
        ls += [p["status"], f"layer-{p['layer']}"]
    return ls


def labels_for_many(ps, kind):
    """多個版本合成一個 Issue：狀態與分層標籤取聯集（順序固定）。"""
    ls = ["kev"] if kind == "kev" else ["vendor-level"]
    for p in ps:
        for x in labels_for(p, kind)[1:]:
            if x not in ls:
                ls.append(x)
    return ls


def vendor_rows(es, ps):
    """廠商層級受影響的版本：表格（每份 SBOM 一列）＋每個版本的 Release 結論。"""
    lines = ["| 專案 | 版本 | 分層 | 狀態 | Release | 監看來源 | 元件數 | 第一次偵測 |", "|---|---|---|---|---|---|---|---|"]
    for e, p in zip(es, ps):
        lines.append(f"| {md_cell(e.get('project'))} | {md_cell(e.get('version'))} | {md_cell(p['layer'] if p else '?')} | "
                     f"{md_cell(p['status'] if p else '?')} | {md_code(p.get('tag')) if p else '?'} | "
                     f"{md_cell(', '.join(str(x) for x in e.get('watch_via') or []))} | {md_cell(e.get('component_count'))} | "
                     f"{md_cell(e.get('first_detected'))} |")
    lines.append("")             # 表格與後面的清單之間空一行（不然清單會被當成表格的一部分）
    seen = set()
    for e, p in zip(es, ps):
        if not p or (p.get("tag"), p["layer"]) in seen:
            continue
        seen.add((p.get("tag"), p["layer"]))
        lines.append(f"- {md_text(e.get('project'))} {md_text(e.get('version'))}（{p['layer']} 層）：狀態 {p['status']}，"
                     f"{HANDLING.get(p['status'], '')}分層：{layer_note(p)} Release 的結論：{release_results(p)}")
    return lines


def kev_body(mode, entries, p, coverage, run_url, now):
    e0 = entries[0]
    lines = []
    if mode == "drill":
        lines.append("> **演練（合成資料）**：這是每日監控的演練 Issue，不是真的漏洞通知。")
        lines.append("")
    lines += [f"**{md_text(e0['cve'])}** 在已遭利用清單（KEV）上，比對到 **{md_text(e0['project'])} {md_text(e0['version'])}**（{p['layer'] if p else '?'} 層）。", ""]
    if p:
        lines += [f"- Release：{md_code(p.get('tag'))}（{md_code(p.get('html_url'))}）、Release 版本 {md_text(p.get('release_version') or '?')}",
                  f"- 狀態：{p['status']}；{HANDLING.get(p['status'], '')}", f"- 分層：{layer_note(p)}",
                  f"- Release 的結論：{release_results(p)}"]
    lines += [f"- 第一次偵測：{min(x.get('cve_first_detected') or x['first_detected'] for x in entries)}（這次執行 {utc(now)}）", "",
              "| 元件 | purl | 依據 | 來源 |", "|---|---|---|---|"]
    for e in entries:
        lines.append(f"| {md_code(e.get('component'))} | {md_code(e.get('purl'))} | {md_code(e.get('basis'))} | {md_code('; '.join(str(x) for x in e.get('sources') or []))} |")
    lines += ["", f"每日監控沒有涵蓋的項目（每次都列出）：", *[f"- {a}：{b}" for a, b in coverage]]
    if p and p.get("gaps"):
        lines += ["", "這個 Release 這次的 GAP：", *[f"- {md_cell(g)}" for g in p["gaps"]]]
    lines += ["", ART14_NOTE]
    if run_url:
        lines += ["", f"執行紀錄：{run_url}"]
    return "\n".join(lines)


def vendor_body(mode, es, ps, run_url, now):
    """es：同一個廠商 × CVE 的新命中（每份 SBOM 一筆）；ps：對應的 Release 資訊（可能是 None）。"""
    e = es[0]
    lines = []
    if mode == "drill":
        lines += ["> **演練（合成資料）**：這是每日監控的演練 Issue，不是真的漏洞通知。", ""]
    lines += [f"廠商層級、**可能相關**：{md_text(e['cve'])}（KEV 廠商 {md_text(e.get('kev_vendor') or '?')}、產品 {md_text(e.get('kev_product') or '?')}）"
              f"與下面 {len(es)} 份 SBOM 監看的廠商 {md_code(e.get('vendor'))} 相同，但沒有元件比對。", "",
              f"- KEV 加入日期：{md_text(e.get('date_added') or '?')}；來源：{md_text(e.get('source') or '?')}",
              f"- 這次執行：{utc(now)}", "", "受影響的版本（之後有新的版本也監看這個廠商時，會在這個 Issue 留言）：", ""]
    lines += vendor_rows(es, ps)
    lines += ["", "要人工確認：KEV 的受影響產品是不是在這些專案裡（廠商可能有很多產品）。", "", ART14_NOTE]
    if run_url:
        lines += ["", f"執行紀錄：{run_url}"]
    return "\n".join(lines)


DEMO_TITLE = "[示範專案（公開 BSP）]"
DEMO_BANNER = ("> **示範專案（公開 BSP）**：dumpling 公開 repo 的示範專案，以公開 BSP／公開資料建置；release-meta 的 shipped／development "
               "只是示範狀態，**不是真的出貨產品**。CRA 第 14 條通報在公開 repo 只做演練（art14-drill），這裡不開 art14 Issue。")


def mark_demo(actions):
    """公開 repo（D-040）：Issue 標題與內文寫明示範專案，加 demo 標籤；留言也加一行。"""
    for x in actions:
        if x["op"] in ("open", "open_if_closed"):
            x["title"] = f"{DEMO_TITLE} {x['title']}"
            x["labels"] = list(x.get("labels") or []) + ["demo"]
        x["body"] = DEMO_BANNER + "\n\n" + x["body"]
    return actions


def plan_issues(mode, state, projs, new, back, gone, vrep, baseline, coverage, run_url, now, max_new, fw=None):
    """→ (actions, 統計)。在 state["dumpling"]["issues"] 記下每個群組對應的 Issue（或彙總 Issue）。"""
    dd = state.setdefault("dumpling", {})
    dd["mode"] = mode
    iss = dd.setdefault("issues", {})
    ts = utc(now)
    if baseline:
        dd.setdefault("baseline_at", ts)
        for e in state["matches"].values():
            e["baseline"] = True
        for e in (state.get("vendor_matches") or {}).values():
            e["baseline"] = True
        return [], {"opened": 0, "summary": 0, "comments": 0, "baseline_matches": len(state["matches"]),
                    "baseline_vendor": len(state.get("vendor_matches") or {})}
    # 基準裡的比對消失後又出現、而且它的群組從來沒有 Issue → 不再算基準，當成新的開 Issue（預驗第 2 項）
    for k in back:
        e = state["matches"][k]
        if e.get("baseline") and kev_group_key(mode, e) not in iss:
            e["baseline"] = False
            e.setdefault("history", []).append({"event": "baseline_cleared_on_reappear", "at": ts})
    groups = {}
    for k, e in state["matches"].items():
        if e.get("status") == "open" and not e.get("baseline"):
            groups.setdefault(kev_group_key(mode, e), []).append(e)
    pending = []      # (key, kind, title, body, labels)
    for gk, es in sorted(groups.items(), key=lambda x: (x[1][0]["project_uuid"], x[1][0]["cve"])):
        if gk in iss:
            continue
        p = pinfo_of(projs, es[0]["project_uuid"])
        title = f"[KEV] {md_title(es[0]['cve'])} 在 {md_title(es[0]['project'])} {md_title(es[0]['version'])}（{p['layer'] if p else '?'} 層）"
        pending.append((gk, "kev", title, kev_body(mode, es, p, coverage, run_url, now), labels_for(p, "kev"), es[0]))
    vgroups = {}
    for e in (vrep or {}).get("new") or []:
        vgroups.setdefault(vendor_group_key(mode, e), []).append(e)
    vendor_events = {}          # 已有 Issue 的廠商群組又多了新的版本 → 留言（下面處理）
    for gk, es in sorted(vgroups.items(), key=lambda x: (x[1][0]["cve"], x[1][0]["vendor"])):
        es = sorted(es, key=lambda e: (str(e.get("project")), str(e.get("version")), e["project_uuid"]))
        if gk in iss:
            vendor_events[gk] = es
            continue
        ps = [pinfo_of(projs, e["project_uuid"]) for e in es]
        vers = sorted({f"{e.get('project')} {e.get('version')}" for e in es})
        who = md_title(vers[0]) + (f" 等 {len(vers)} 個版本" if len(vers) > 1 else "")
        title = f"[廠商層級] {md_title(es[0]['cve'])}（{md_title(es[0].get('vendor'))}）可能影響 {who}"
        pending.append((gk, "vendor", title, vendor_body(mode, es, ps, run_url, now), labels_for_many([p for p in ps if p], "vendor"),
                        min(es, key=lambda e: str(e.get("first_detected")))))
    fw_acts = []
    if fw is not None:      # 韌體公告群組與 image_sha256 變化的留言（用還沒加進這次新群組的 iss 判斷）
        fp, fw_acts = fw_plan(mode, state, fw, projs, iss, lambda k: ((iss[k].get("via_summary") or k) if k in iss else None), ts, run_url, now)
        pending += fp
    actions, opened = [], 0
    pruned_keys = dd.setdefault("pruned_keys", [])
    if len(pending) <= max_new:
        for gk, kind, title, body, labels, e in pending:
            op = "open_if_closed" if gk in pruned_keys else "open"     # 修剪過的群組：舊 Issue 可能已關閉，關閉的就開新的
            actions.append({"op": op, "key": gk, "title": title, "body": body, "labels": labels})
            iss[gk] = {"kind": kind, "first_detected": e.get("first_detected"), "opened_at": ts}
            if gk in pruned_keys:
                pruned_keys.remove(gk)
            opened += 1
    rest = pending if len(pending) > max_new else []
    if rest:        # 超過上限：全部併成一個彙總 Issue（不一筆一個，D-040）
        sk = issue_key(mode, "summary", ts[:10], str(len(rest)), rest[0][0])
        body = [f"這次執行有 {len(rest)} 個新的命中群組，超過一次 {max_new} 個的上限，全部列在這個彙總 Issue（ATTENTION），不逐一開 Issue。", "",
                "| 種類 | 標題 |", "|---|---|"] + [f"| {k} | {md_cell(t)} |" for _, k, t, _, _, _ in rest] + ["", ART14_NOTE]
        if mode == "drill":
            body.insert(0, "> **演練（合成資料）**\n")
        if run_url:
            body += ["", f"執行紀錄：{run_url}"]
        only_fw = all(k == "fwadv" for _, k, _, _, _, _ in rest)
        actions.append({"op": "open", "key": sk, "title": f"[{'韌體公告' if only_fw else 'KEV'}][ATTENTION] 彙總：{len(rest)} 個新的命中群組（{ts[:10]}）",
                        "body": "\n".join(body), "labels": ["firmware-advisory", "summary", "attention"] if only_fw else ["kev", "summary", "attention"]})
        for gk, kind, _, _, _, e in rest:
            iss[gk] = {"kind": kind, "first_detected": e.get("first_detected"), "opened_at": ts, "via_summary": sk}
            if gk in pruned_keys:
                pruned_keys.remove(gk)
    comments = 0
    just_opened = {gk for gk, *_ in pending}

    def target(gk):
        r = iss.get(gk)
        return (r.get("via_summary") or gk) if r else None
    # 已有 Issue 的群組：新出現的元件（同一個 CVE 的新 purl，例如 SBOM 重發、開發版元件版本變了）與再出現的比對
    # → 在那個 Issue 留言；Issue 已被關閉時開新的（open_if_closed）。（預驗第 1 項）
    events = {}
    for k in new:
        e = state["matches"][k]
        if not e.get("baseline"):
            events.setdefault(kev_group_key(mode, e), []).append(("新增元件", e))
    for k in back:
        e = state["matches"][k]
        if not e.get("baseline"):
            events.setdefault(kev_group_key(mode, e), []).append(("再出現", e))
    for gk, es in sorted(vendor_events.items()):
        t = target(gk)
        if not t or gk in just_opened:
            continue
        ps = [pinfo_of(projs, e["project_uuid"]) for e in es]
        lines = [f"{md_text(es[0]['cve'])}（廠商 {md_code(es[0].get('vendor'))}）又出現在 {len(es)} 份新的 SBOM（{ts}）：", ""] + \
            vendor_rows(es, ps) + ["", "原 Issue 已關閉時會開新的 Issue。" + (f"執行紀錄：{run_url}" if run_url else "")]
        actions.append({"op": "open_if_closed", "key": t,
                        "title": f"[廠商層級] {md_title(es[0]['cve'])}（{md_title(es[0].get('vendor'))}）：新的版本",
                        "body": "\n".join(lines), "labels": labels_for_many([p for p in ps if p], "vendor")})
        comments += 1
    for gk, evs in sorted(events.items()):
        t = target(gk)
        if not t or gk in just_opened:
            continue
        e0 = evs[0][1]
        lines = [f"{md_text(e0['cve'])} 在 {md_text(e0['project'])} {md_text(e0['version'])}（{ts}）："] + \
            [f"- {what}：{md_code(e.get('component'))}（{md_code(e.get('purl'))}）" for what, e in evs] + \
            ["", "原 Issue 已關閉時會開新的 Issue。" + (f"執行紀錄：{run_url}" if run_url else "")]
        actions.append({"op": "open_if_closed", "key": t, "title": f"[KEV] {md_title(e0['cve'])} 在 {md_title(e0['project'])} {md_title(e0['version'])}：新的比對",
                        "body": "\n".join(lines), "labels": ["kev"] + (labels_for(pinfo_of(projs, e0["project_uuid"]), "kev")[1:])})
        comments += 1
    ev_acts = [x for x in actions if x["op"] == "open_if_closed"]
    if len(ev_acts) > max_new:      # 事件太多（例如開發版每次重建都換 purl）：併成一個彙總，不逐一開
        actions = [x for x in actions if x["op"] != "open_if_closed"]
        ek = issue_key(mode, "events", ts[:10], str(len(ev_acts)), ev_acts[0]["key"])
        body = [f"這次執行有 {len(ev_acts)} 個已有 Issue 的群組出現新的比對（新增元件或再出現），超過 {max_new} 個的上限，全部列在這裡。", ""] + \
            [f"- {md_cell(x['title'])}" for x in ev_acts] + ([f"", f"執行紀錄：{run_url}"] if run_url else [])
        actions.append({"op": "open", "key": ek, "title": f"[KEV][ATTENTION] 彙總：{len(ev_acts)} 個群組有新的比對（{ts[:10]}）", "body": "\n".join(body),
                        "labels": ["kev", "summary", "attention"]})
        comments = comments - len(ev_acts) + 1
    seen_gone = set()
    for k in gone:
        e = state["matches"][k]
        gk = kev_group_key(mode, e)
        t = target(gk)
        still = any(x.get("status") == "open" and kev_group_key(mode, x) == gk for x in state["matches"].values())
        if t and not still and gk not in seen_gone:
            seen_gone.add(gk)
            actions.append({"op": "comment", "key": t, "body": f"{md_text(e['cve'])} 在 {md_text(e['project'])} {md_text(e['version'])} 這次沒有再比對到（{ts}）："
                            "可能已修補、元件移除，或 KEV 清單改變。Issue 不會自動關閉，請負責人確認後關閉。", "reopen_if_closed": False})
            comments += 1
    actions += fw_acts          # 韌體的留言不併進上面的事件彙總（每個都要列出樣本與 sha256）
    comments += len(fw_acts)
    return actions, {"opened": opened, "summary": len(rest), "comments": comments}


PREV_MAX_HOURS = 36         # 上一次排程超過這麼久 → 算沒跑（每天一次，多留 12 小時）
BAD_CONCLUSIONS = ("cancelled", "failure", "timed_out", "startup_failure", "action_required", "stale")


def prev_schedule_check(path, run_id, now):
    """watch-round 的 compute 查到的 watch.yml 最近幾次排程 run（GitHub API）→ (降級說明清單, 說明)。
    上一次排程（不算這一次）被取消、失敗、逾時，或超過 PREV_MAX_HOURS 小時沒有排程 → 降級（報告＋健康 Issue），不能沒有紀錄。"""
    if not path:
        return [], None
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError) as e:
        return [f"上一次排程的結果讀不到（{type(e).__name__}）"], None
    if not isinstance(doc, dict) or doc.get("error"):
        return [f"上一次排程的結果：{str((doc or {}).get('error') or '格式不對')[:120]}"], None
    runs = [r for r in doc.get("runs") or [] if isinstance(r, dict) and str(r.get("id")) != str(run_id or "")]
    if not runs:
        return [], "還沒有排程 run（第一次）"
    runs.sort(key=lambda r: str(r.get("created_at") or ""), reverse=True)
    last = runs[0]
    out = []
    note = f"上一次排程 run {last.get('id')}：{last.get('status')}／{last.get('conclusion') or '-'}（{last.get('created_at')}）"
    if last.get("status") == "completed" and last.get("conclusion") in BAD_CONCLUSIONS:
        out.append(f"上一次排程 run {last.get('id')} 是 {last.get('conclusion')}（{last.get('created_at')}）：那一輪沒有完成監控")
    try:
        t = datetime.datetime.strptime(str(last.get("created_at")), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
        if (now - t).total_seconds() > PREV_MAX_HOURS * 3600:
            out.append(f"上一次排程是 {last.get('created_at')}，超過 {PREV_MAX_HOURS} 小時：排程可能被停用或沒有觸發")
    except ValueError:
        out.append("上一次排程的時間讀不懂")
    return out, note


HEALTH_AFTER_RUNS = 2       # 連續幾次降級才通知
HEALTH_REPEAT_DAYS = 7      # 一直沒恢復時，隔幾天再提醒一次


def health_actions(mode, state, serious, now, run_url):
    """降級狀態（Grype NOT_RUN、資料源不能用或過期、L4T 核心對應失敗、核心 CNA NOT_RUN、已遭利用但版本未知）不只在報告：
    連續 HEALTH_AFTER_RUNS 次就在固定的健康 Issue 開／留言，之後每 HEALTH_REPEAT_DAYS 天提醒一次；恢復時留言一次。"""
    dd = state.setdefault("dumpling", {})
    h = dd.setdefault("health", {"streak": 0})
    key = issue_key(mode, "health")
    ts = utc(now)
    if not serious:
        h["ok_streak"] = int(h.get("ok_streak") or 0) + 1
        if h["ok_streak"] < HEALTH_AFTER_RUNS:          # 恢復也要連續 2 次正常，避免時好時壞時一直留言
            return []
        out = []
        if h.get("notified_at"):
            out.append({"op": "comment", "key": key, "body": f"監控已恢復正常（連續 {h['ok_streak']} 次，{ts}）。之前的降級從 {h.get('since')} 開始。",
                        "reopen_if_closed": False})
        dd["health"] = {"streak": 0, "ok_streak": h["ok_streak"]}
        return out
    h["ok_streak"] = 0
    h["streak"] = int(h.get("streak") or 0) + 1
    h.setdefault("since", ts)
    last = h.get("notified_at")
    due = h["streak"] >= HEALTH_AFTER_RUNS and (not last or (now - parse_now(last)).days >= HEALTH_REPEAT_DAYS)
    h["latest"] = sorted(set(serious))[:30]
    if not due:
        return []
    h["notified_at"] = ts
    body = [f"每日監控從 {h['since']} 起連續 {h['streak']} 次降級：下面這些項目沒有完整檢查，這段期間可能漏掉新的已遭利用漏洞（不能當成沒有新的）。", ""] + \
        [f"- {md_text(x)}" for x in h["latest"]] + ["", f"恢復時會在這裡留言；一直沒恢復時每 {HEALTH_REPEAT_DAYS} 天提醒一次。"] + \
        ([f"執行紀錄：{run_url}"] if run_url else [])
    return [{"op": "open_if_closed", "key": key, "title": "[監控降級] 每日監控有項目沒有完整檢查", "body": "\n".join(body), "labels": ["watch-health"]}]


# ---------- 一次執行 ----------

def run(a, kernel_runner=None):
    now = parse_now(a.now)
    if a.kev_overlay and a.mode != "drill":
        raise Fail("--kev-overlay 只能在 --mode drill 使用")
    m = mods()
    eg, ew, ev, euvd = m["eg"], m["ew"], m["ev"], m["euvd"]
    inv_base = os.path.dirname(os.path.abspath(a.inventory))
    inv, projs, inv_problems = load_inventory(a.inventory, inv_base)
    state, sbase, first = load_state(a.state_dir)
    if not first and (state.get("dumpling") or {}).get("mode") not in (None, a.mode):
        raise Fail(f"狀態 Issue 的 mode 是 {state['dumpling']['mode']}，這次是 {a.mode}：不混用")
    os.makedirs(a.out, exist_ok=True)
    for name in ("plan.json", "result.json", "report.md"):      # 不留上一次的輸出
        try:
            os.remove(os.path.join(a.out, name))
        except FileNotFoundError:
            pass
    if first and not projs:
        # 沒有任何可監控的 SBOM（例如 M2 之前只有舊格式或 draft Release）：不建立空的基準——
        # 空的基準會讓之後第一個真的 Release 裡既有的 KEV 全部變成「新的」。不產生 plan.json（notify 跳過、不寫狀態），GAP 不是 FAIL。
        detail = "沒有可監控的 Release／SBOM，還沒有狀態：不建立基準、不產生 plan（GAP）" + \
                 (f"；Release 問題：{'；'.join(inv_problems)[:300]}" if inv_problems else "")
        with open(os.path.join(a.out, "report.md"), "w", encoding="utf-8") as f:
            f.write(f"# 每日監控（{a.mode}）：GAP\n\n{detail}\n\n收集：{inv.get('status')}：{inv.get('detail') or ''}\n")
        with open(os.path.join(a.out, "result.json"), "w", encoding="utf-8") as f:
            json.dump({"status": "GAP", "detail": detail, "baseline": False, "plan": False}, f, ensure_ascii=False, indent=1)
        return "GAP", detail
    if first and not a.allow_baseline:
        # 狀態 Issue 與監控 Issue 都沒有：不悄悄重建基準（可能是有人誤刪了狀態 Issue，重建會吞掉之後的新命中）。
        # 第一次建立基準要人明確指定（watch.yml 手動觸發 baseline=true → --allow-baseline）；不是 FAIL，不亮紅燈。
        detail = ("還沒有狀態（沒有狀態 Issue、也沒有監控 Issue）：沒有指定 --allow-baseline，不建立基準、不產生 plan（GAP）。"
                  "第一次建立基準請手動觸發 mode=real、baseline=true；如果之前已經建過基準，請先找回狀態 Issue")
        with open(os.path.join(a.out, "report.md"), "w", encoding="utf-8") as f:
            f.write(f"# 每日監控（{a.mode}）：GAP\n\n{detail}\n")
        wrote_plan = False
        if a.mode == "real":
            # 有可監控的 Release 卻沒有基準：排程每天綠燈但什麼都沒監控 → 在固定的「沒有基準」健康 Issue 留下紀錄（#32 驗證 F4）。
            # plan 的 state 是 null：issues.py 只執行這個動作、不寫狀態（不會因此變成「已有狀態」）。op 是 open：已經有（含已關閉）就不重複。
            act = {"op": "open", "key": issue_key(a.mode, "no-baseline"), "title": "[監控降級] 每日監控還沒有基準，沒有在監控",
                   "body": detail + f"\n\n可監控的 SBOM：{len(projs)} 份（{', '.join(md_code(t) for t in sorted({p['tag'] or '?' for p in projs})[:20])}）。"
                   + "建立基準後這個 Issue 可以關閉。" + (f"\n\n執行紀錄：{a.run_url}" if a.run_url else ""), "labels": ["watch-health"]}
            if a.demo:
                mark_demo([act])
            probs = publiccheck.check_text(act["title"] + "\n" + act["body"])
            if probs:
                raise Fail(f"要寫進公開 Issue 的內容沒過公開檢查（{probs[0]}）")
            bad = unsafe_actions([act])
            if bad:
                raise Fail(f"要寫進公開 Issue 的內容有沒淨化的 Markdown（例如 {bad[0]!r}）：不產生 plan.json")
            plan = {"schema": "dumpling-watch-plan/1", "mode": a.mode, "generated_at": utc(now), "run_url": a.run_url, "state_base": None,
                    "state": None, "actions": [act], "status": "GAP", "detail": detail}
            with open(os.path.join(a.out, "plan.json"), "w", encoding="utf-8") as f:
                json.dump(plan, f, ensure_ascii=False, indent=1)
            wrote_plan = True
        with open(os.path.join(a.out, "result.json"), "w", encoding="utf-8") as f:
            json.dump({"status": "GAP", "detail": detail, "baseline": False, "plan": wrote_plan}, f, ensure_ascii=False, indent=1)
        return "GAP", detail
    work = tempfile.mkdtemp(prefix=".watch-", dir=a.out)
    attn, gaps, notes = [], [], []
    serious = [f"Release 問題：{x}"[:300] for x in inv_problems]     # 降級：連續發生要通知人（健康 Issue）
    if not projs:
        serious.append("沒有任何可監控的 Release／SBOM（已有狀態）")
    feed_attn = feed_attention(a.feeds)       # 鏡像用了舊資料頂替：整輪 ATTENTION，報告與 Issue 都寫出來（不擋基準：資料最多 48 小時舊）
    attn += feed_attn
    ps_bad, ps_note = prev_schedule_check(a.prev_schedule, a.run_id, now)
    serious += ps_bad
    gaps += ps_bad
    if ps_note:
        notes.append(ps_note)
    drafts = [str(x)[:120] for x in inv.get("drafts") or []]
    if drafts:      # draft 是還沒發布的 Release：正常略過，只列出、不降級（#49 驗證應修 2）
        notes.append(f"draft Release 略過 {len(drafts)} 個（還沒發布，正常，不降級）：{'、'.join(drafts[:10])}")
    try:
        cisa, cisa_path = load_cisa(eg, a.feeds, a.kev_overlay, work, now)
        if cisa["status"] != "OK":
            gaps.append(f"CISA KEV：{cisa['detail']}")
            serious.append(f"CISA KEV {'不能用' if not cisa['usable'] else '過期'}")
        eix = euvd.exploited_index(os.path.join(a.feeds, "euvd") if os.path.isdir(os.path.join(a.feeds, "euvd")) else None, now=now)
        if eix["status"] != "OK":
            gaps.append(f"EUVD：{eix['detail']}")
            serious.append(f"EUVD {'不能用' if not eix['usable'] else '過期'}")
        eu_now = eix["exploited"] if eix["usable"] else None
        exploited = {"cisa": cisa["cves"] if cisa["usable"] else None, "euvd": eu_now, "euvd_sticky": ew.euvd_sticky(state), "dt": set(),
                     "euvd_text": ew.euvd_text,
                     "sticky": {e["cve"] for e in state["matches"].values() if isinstance(e, dict) and e.get("basis") == "grype_only"}}
        if not cisa["usable"] and not eix["usable"]:
            raise Fail("CISA KEV 與 EUVD 都不能用：沒有已遭利用清單，不能比對（不能當成沒有新的）")
        # Grype
        gpath, gwhy = eg.find_grype(a.grype)
        genv = eg.grype_env()
        db = eg.db_status(gpath, genv, now, 3) if gpath else {"status": "NOT_RUN", "usable": False, "built": None, "detail": gwhy}
        if db["status"] != "OK":
            gaps.append(f"Grype DB：{db['detail']}")
            serious.append(f"Grype DB {db['status']}")
        sbx = eg.sandbox_check()
        budget = float(a.grype_total_timeout)
        matches, grype_ok, kernel_ok, per = {}, set(), set(), {}
        grype_na = set()        # 韌體：SBOM 沒有任何帶 purl／CPE 的元件：Grype 沒有東西可比，NOT_ASSESSED（不是 OK，也不算 Grype 沒跑完）
        for p in projs:
            if is_fw(p) and sbom_matchable(p["sbom"]) == 0:
                grype_na.add(p["uuid"])
                per[p["uuid"]] = {"uuid": p["uuid"], "tag": p["tag"], "layer": p["layer"], "grype": FW_GRYPE_NA, "why": None,
                                  "report_status": FW_NO_ITEM, "release_gate": FW_NO_ITEM, "kernel_map": FW_NO_ITEM, "exploited": 0,
                                  "version_unknown": 0, "kernel_cna": FW_NO_ITEM, "kind": "firmware"}
                continue
            spec = {"sbom": p["sbom"], "sha256": p["sha256"]}
            t0 = datetime.datetime.now()
            try:
                info, ctx = eg.prepare(p, spec, None, None, gpath, genv, db, sbx, work, min(eg.GRYPE_TIMEOUT, budget), [], now)
            except Exception as e:      # 不讓單一 SBOM 的意外拖垮整次：那個版本 NOT_RUN
                info, ctx = {"status": "NOT_RUN", "why": f"internal error ({type(e).__name__})"}, None
            budget -= (datetime.datetime.now() - t0).total_seconds()
            row = {"uuid": p["uuid"], "tag": p["tag"], "layer": p["layer"], "grype": info.get("status"), "why": info.get("why"),
                   "report_status": p.get("report_status"), "release_gate": p.get("release_gate"),
                   "kernel_map": (info.get("kernel_map") or {}).get("status"), "exploited": 0, "version_unknown": 0, "kernel_cna": None}
            if is_fw(p):        # 韌體 SBOM 沒有 Linux 核心：核心對應與核心 CNA「沒有這一項」，不算 GAP、不降級、不擋基準
                row.update(kind="firmware", report_status=FW_NO_ITEM, release_gate=FW_NO_ITEM, kernel_map=FW_NO_ITEM, kernel_cna=FW_NO_ITEM)
            if row["kernel_map"] in ("GAP", "FAIL"):
                # L4T 核心對應失敗：Grype 用原始 SBOM 比對，核心的 KEV 可能漏掉（Release 掃描這種情況也標 GAP；預驗第 3 項）
                g = f"{p['name']}@{p['version']}#{p['layer']}：L4T 核心對應 {row['kernel_map']}（{(info.get('kernel_map') or {}).get('detail') or ''}）：核心元件可能沒有比對"
                gaps.append(g[:400])
                p.setdefault("gaps", []).append(g[:400])
                serious.append(f"{p['uuid']} L4T 核心對應 {row['kernel_map']}")
            if ctx is not None:
                out, counts, unknown = eg.extract(p, ctx, [], exploited)
                matches.update(out)
                grype_ok.add(p["uuid"])
                row.update(exploited=len(out), version_unknown=len(unknown), grype_matches=counts["grype_matches"])
                if unknown:
                    gaps.append(f"{p['name']}@{p['version']}#{p['layer']}：{len(unknown)} 筆已遭利用的比對元件版本未知（規則 13，GAP，不開 Issue）")
                    serious.append(f"{p['uuid']}：已遭利用但元件版本未知 {len(unknown)} 筆（" +
                                   "、".join(sorted({c for u in unknown for c in u.get('cves') or []}))[:200] + "）")
            else:
                attn.append(f"{p['name']}@{p['version']}#{p['layer']}：Grype NOT_RUN（{info.get('why')}）")
                serious.append(f"{p['uuid']} Grype NOT_RUN")
            per[p["uuid"]] = row
        # 核心 CNA（bsp 層；沒有分層時 product）
        ex_cves = {}
        for c in (exploited["cisa"] or ()):
            ex_cves.setdefault(c, []).append("CISA KEV mirror")
        for c in (eu_now or {}):
            ex_cves.setdefault(c, [])
        for e in state["matches"].values():        # 之前算已遭利用的核心 CVE：這次資料源缺一時照樣算，不記成消失（同 extract 的 sticky；預驗第 6 項）
            if isinstance(e, dict) and e.get("basis") == "kernel_cna" and e.get("status") == "open" and e.get("cve") not in ex_cves:
                ex_cves[e["cve"]] = ["earlier run"]
        layers_by_rel = {}
        for p in projs:
            layers_by_rel.setdefault((p["name"], p["version"]), []).append(p)
        for (_, _), ps in sorted(layers_by_rel.items()):
            kp = next((p for p in ps if p["layer"] == "bsp"), None) or next((p for p in ps if p["layer"] == "product"), None)
            if kp is None:
                continue
            ups, kg = kernel_upstreams(kp["kernel_versions"])
            for g in kg:
                gaps.append(f"{kp['name']}@{kp['version']}：{g}")
                kp.setdefault("gaps", []).append(g)
                serious.append(f"{kp['uuid']} {g}"[:300])
            if not ups:
                per[kp["uuid"]]["kernel_cna"] = "GAP"
                continue
            km, ok, kn = kernel_matches(kp, ups, os.path.join(a.feeds, "kernel-cve"), work, ex_cves, eu_now, ew, kernel_runner)
            notes += [f"{kp['name']}@{kp['version']}：{x}" for x in kn]
            matches.update(km)
            per[kp["uuid"]]["kernel_cna"] = "OK" if ok and not kg else ("GAP" if ok else "NOT_RUN")
            if ok:
                kernel_ok.add(kp["uuid"])
            else:
                attn.append(f"{kp['name']}@{kp['version']}：核心 CNA NOT_RUN")
                serious.append(f"{kp['uuid']} 核心 CNA NOT_RUN")
        new, back, gone = ew.update_state(state, matches, kernel_ok, now, grype_ok)
        # 廠商層級
        vrep = None
        try:
            vcfg, vprob = ev.load_config(a.vendor_config, {}, None, None, explicit=bool(a.vendor_config))
            vprojs = [{"uuid": p["uuid"], "name": p["name"], "version": p["version"]} for p in projs]
            vread = {p["uuid"] for p in projs}
            vsboms = {p["uuid"]: {"sbom": p["sbom"], "sha256": p["sha256"]} for p in projs}
            vrep, vattn, vnotes = ev.run_vendor_watch(vprojs, vread, vsboms, None, vcfg, vprob, cisa, eix,
                                                      os.path.join(a.feeds, "euvd"), matches, state, now)
            attn += [x for x in vattn if "new vendor-level" not in x]
            notes += vnotes
        except Exception as e:
            attn.append(f"廠商層級 NOT_RUN（{type(e).__name__}）")
        # 韌體：公告重跑的結果、image_sha256 的變化、狀態（FIRMWARE-WATCH.md §4、§5）
        fw_projs = [p for p in projs if is_fw(p)]
        fwx = None
        fw_size_why = None
        if fw_projs or isinstance(inv.get("firmware"), dict) or isinstance(state.get("firmware"), dict):
            rm = load_rematch(getattr(a, "firmware_rematch", None), fw_projs)
            old_fw = copy.deepcopy(state["firmware"]) if isinstance(state.get("firmware"), dict) else None
            fwx = fw_update(state, inv.get("firmware"), fw_projs, rm, first, utc(now))
            state["firmware"] = {"tables": fwx["tables"], "samples": fwx["samples"]}
            fw_messages(inv, fw_projs, rm, fwx, per, attn, gaps, notes, serious)
            # 狀態大小（C0 裁定 (A)，2026-11-15）：加上韌體會超過狀態 Issue 的上限 → 只有韌體停下來（fail-closed），
            # KEV 照常（#28 的決定：漏掉 KEV 通知比重複留言嚴重）。韌體這一輪不寫進狀態（沿用上一輪）、不產生 fwadv 的動作、整份標 GAP
            size_fw = state_size(sanitize_state(state))
            if size_fw > STATE_MAX_CHARS:
                state["firmware"] = sanitize_firmware(old_fw) if old_fw is not None else {"tables": {}, "samples": {}}
                state["firmware"]["size_stopped_at"] = utc(now)
                why = (f"韌體因狀態大小上限停止：加上這一輪的韌體結果，狀態編碼後約 {size_fw} 字元，超過上限 {STATE_MAX_CHARS}；"
                       "這一輪的韌體結果不寫進狀態、不開公告 Issue（KEV 照常）")
                for p in fw_projs:
                    if p["uuid"] in per:
                        per[p["uuid"]].update(advisory="GAP", advisory_why=why)
                gaps.append(why)
                serious.append("韌體因狀態大小上限停止")
                fw_size_why = why
                fwx = None
            elif isinstance(state.get("firmware"), dict):
                state["firmware"].pop("size_stopped_at", None)
        if first:
            # 基準不完整會讓下一次把既有的命中全部當成新的：任何一項沒有完整跑完就 FAIL、不寫狀態（PR #28 驗證應修 1）
            why = []
            missing = [p["uuid"] for p in projs if p["uuid"] not in grype_ok and p["uuid"] not in grype_na]
            if missing:
                why.append(f"{len(missing)} 份 SBOM 的 Grype 沒跑完（例如 {missing[0]}）")
            if cisa["status"] != "OK":
                why.append(f"CISA KEV 不是 OK（{cisa['status']}）")
            if db["status"] != "OK":
                why.append(f"Grype DB 不是 OK（{db['status']}：過期的 DB 建出的基準，DB 更新後既有命中會被當成新的）")
            kmap_bad = [u for u, r in per.items() if r.get("kernel_map") in ("GAP", "FAIL")]
            if kmap_bad:
                why.append(f"{len(kmap_bad)} 份 SBOM 的 L4T 核心對應是 GAP／FAIL（核心元件沒有比對，基準會漏掉核心的 KEV）")
            if eix["status"] != "OK" and a.mode == "real":      # 演練刻意不下載 EUVD
                why.append(f"EUVD 不是 OK（{eix['status']}）")
            if inv_problems:
                why.append(f"Release 有 {len(inv_problems)} 個問題（例如 {inv_problems[0][:120]}）")
            knr = [u for u, r in per.items() if r.get("kernel_cna") == "NOT_RUN"]
            if knr:
                why.append(f"{len(knr)} 份 SBOM 的核心 CNA NOT_RUN")
            if vrep is None:
                why.append("廠商層級 NOT_RUN")
            if fwx is not None:
                fbad = [p["slug"] for p in fw_projs if fwx["rm"]["adv"][p["uuid"]]["state"] in ("NOT_RUN", "GAP")]
                if fbad:
                    why.append(f"{len(fbad)} 份韌體樣本的公告重跑是 NOT_RUN／GAP（例如 {str(fbad[0])[:60]}）：公告結果沒有納入基準")
                if fwx["rm"]["table_flags"]:
                    why.append("韌體的比對表過期或 GAP（" + "、".join(sorted(fwx["rm"]["table_flags"])) + "）：過期時的結果不能當基準")
            if why:
                raise Fail("第一次執行要建立基準，但沒有完整跑完：" + "；".join(why) + "。基準不完整會讓下一次把既有的命中全部當成新的，這次不寫狀態")
        coverage = list(NOT_RUN_DAILY)
        nb_key = issue_key(a.mode, "no-baseline")
        nb_actions = [{"op": "comment", "key": nb_key, "reopen_if_closed": False,
                       "body": f"已建立基準（{utc(now)}，{len(projs)} 份 SBOM）。每日監控開始比對，這個 Issue 可以關閉。"}] \
            if first and nb_key in (sbase.get("watch_keys") or []) else []
        actions, stats = plan_issues(a.mode, state, projs, new, back, gone, vrep, first, coverage, a.run_url, now, a.max_new_issues, fwx)
        actions += nb_actions
        if not first and a.mode == "real":      # 演練刻意不下載 EUVD／核心 CNA：不開健康 Issue
            actions += health_actions(a.mode, state, serious, now, a.run_url)
            if fw_size_why:          # 韌體因狀態大小上限停止：健康 Issue 當輪就看得到（7 天一次，同「狀態接近上限」）
                dd = state.setdefault("dumpling", {})
                last = dd.get("fw_size_warned_at")
                if not last or (now - parse_now(last)).days >= HEALTH_REPEAT_DAYS:
                    dd["fw_size_warned_at"] = utc(now)
                    actions.append({"op": "open_if_closed", "key": issue_key(a.mode, "health"), "title": "[監控降級] 韌體因狀態大小上限停止",
                                    "body": fw_size_why + "。請處理：修剪狀態、減少韌體樣本或改成分段存放（WATCH.md 3.5）。",
                                    "labels": ["watch-health"]})
        add_feed_note(actions, feed_attn)
        if a.demo:
            mark_demo(actions)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    gaps += inv_problems and [f"Release 有問題（不比對）：{x}" for x in inv_problems]
    if not projs:
        gaps.append("沒有可監控的 Release／SBOM")
    pruned = prune_state(state, now)
    if pruned:
        notes.append(f"修剪狀態：{pruned}")
    size = state_size(sanitize_state(state))
    if size > STATE_WARN_CHARS:      # 先處理大小再算整輪狀態（#32 驗證 F1）
        msg = f"狀態編碼後約 {size} 字元，接近狀態 Issue 的上限 {STATE_MAX_CHARS}（超過時狀態寫不進去，issues.py apply 會 FAIL）"
        attn.append(msg)
        dd = state.setdefault("dumpling", {})
        last = dd.get("size_warned_at")
        if not first and a.mode == "real" and (not last or (now - parse_now(last)).days >= HEALTH_REPEAT_DAYS):
            dd["size_warned_at"] = utc(now)        # 跟降級提醒一樣 7 天一次，不每天留言
            act = {"op": "open_if_closed", "key": issue_key(a.mode, "health"), "title": "[監控降級] 狀態接近上限",
                   "body": msg + "。請處理：修剪已消失很久的比對，或改成分段存放（WATCH.md 3.5 已知限制）。", "labels": ["watch-health"]}
            actions.append(mark_demo([act])[0] if a.demo else act)
    status = "ATTENTION" if (stats["opened"] or stats["summary"] or attn or gaps) else "OK"
    detail = (f"{'第一次執行：建立基準，' if first else ''}{len(projs)} 份 SBOM；KEV 比對 {len(matches)} 筆（新 {len(new)}、再出現 {len(back)}、消失 {len(gone)}）；"
              f"開 Issue {stats['opened']}、彙總 {stats['summary']}、留言 {stats['comments']}；GAP {len(gaps)}、需注意 {len(attn)}")
    state.setdefault("runs", []).append({"at": utc(now), "status": status, "run_url": a.run_url, "mode": a.mode, "detail": detail[:300]})
    clean = sanitize_state(state)
    plan = {"schema": "dumpling-watch-plan/1", "mode": a.mode, "generated_at": utc(now), "run_url": a.run_url,
            "state_base": None if sbase.get("issue") is None else {k: sbase.get(k) for k in ("issue", "updated_at", "body_sha256")},
            "state": clean, "actions": actions, "status": status, "detail": detail}
    if a.demo:
        plan["demo"] = True        # 公開 repo（D-040）：狀態 Issue 建立時也加 demo 標籤（標題與內文格式不變；C0 決定，2026-11-14）
    report = render_report(a.mode, detail, status, per, gaps, attn, notes, coverage, actions, first, vrep, fwx, inv.get("firmware"), projs)
    rules = publiccheck.load_rules()
    probs = publiccheck.check_text(json.dumps(clean, ensure_ascii=False, indent=0), rules) + \
        [x for act in actions for x in publiccheck.check_text(act.get("title", "") + "\n" + act.get("body", ""), rules)]
    if probs:
        raise Fail(f"要寫進公開 Issue 的內容沒過公開檢查（{len(probs)} 筆，例如 {probs[0]}）：不產生 plan.json")
    # 最後一道：外部字串都應該經過 md_text／md_code／md_title；還有沒淨化的 @提及、連結、圖片就不產生 plan（程式漏了某個欄位）
    bad = unsafe_actions(actions)
    if bad:
        raise Fail(f"要寫進公開 Issue 的內容有沒淨化的 Markdown（例如 {bad[0]!r}）：不產生 plan.json")
    result = {"status": status, "detail": detail, "per_sbom": per, "gaps": gaps, "attention": attn, "notes": notes, "serious": serious,
              "new": new, "back": back, "gone": gone, "stats": stats, "baseline": first}
    if fwx is not None:
        result["firmware"] = {"tables": fwx["tables"], "table_flags": fwx["rm"]["table_flags"], "image_sha256_changes": fwx["changes"],
                              "advisory": {u: {"state": x["state"], "why": x["why"], "reasons": x["reasons"], "changed": x["changed"]}
                                           for u, x in fwx["rm"]["adv"].items()}}
    for name, obj in (("plan.json", plan), ("result.json", result)):
        tmp = os.path.join(a.out, name + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=1)
        os.replace(tmp, os.path.join(a.out, name))
    with open(os.path.join(a.out, "report.md"), "w", encoding="utf-8") as f:
        f.write(report)
    return status, detail


def fw_messages(inv, fw_projs, rm, fwx, per, attn, gaps, notes, serious):
    """韌體的報告列與降級：公告重跑 NOT_RUN／GAP、表過期或 GAP、結果和 Release 當時不同、image_sha256 變了。
    NOT_RUN／GAP 讓整輪降級（連續兩次開健康 Issue）；供應商 SBOM 的 NOT_ASSESSED 是設計上不重跑，不降級。"""
    for p in fw_projs:
        u, a = p["uuid"], rm["adv"][p["uuid"]]
        row = per.get(u)
        if row is not None:
            row.update(advisory=a["state"], image_sha256=p.get("image_sha256"), advisory_why=a["why"], advisory_reasons=a["reasons"][:10])
        if a["state"] == "NOT_RUN":
            attn.append(f"{p['slug']}：韌體公告重跑 NOT_RUN（{a['why']}）")
            serious.append(f"{u} 韌體公告重跑 NOT_RUN")
        elif a["state"] == "GAP":
            gaps.append(f"{p['slug']}：韌體公告重跑 GAP（{a['why'] or '；'.join(a['reasons']) or '見重跑結果'}）")
            serious.append(f"{u} 韌體公告重跑 GAP")
        if a["changed"]:
            attn.append(f"{p['slug']}：{len(a['changed'])} 項公告比對結果和 Release 當時不同（列在報告的韌體一節）")
    for name, why in sorted(rm["table_flags"].items()):
        txt = "；".join(sorted(set(why))[:3])
        attn.append(f"韌體的比對表 {name}：{txt}")        # 過期（stale）只進需注意；狀態 GAP（表讀不到或驗證不過）另外是 GAP
        if any(x.startswith("狀態") for x in why):
            gaps.append(f"韌體的比對表 {name}：{txt}")
        serious.append(f"韌體的比對表 {name} 過期或 GAP")
    for ch in fwx["changes"]:
        attn.append(f"{ch['slug']}：同一個 slug、同一個版本，映像 sha256 變了：{ch['old']} → {ch['new']}（監控鍵不變，不開新的 Issue）")
    fw = inv.get("firmware") if isinstance(inv.get("firmware"), dict) else {}
    for x in (fw.get("not_watched") or [])[:30]:
        if isinstance(x, dict):
            notes.append(f"韌體不監控：{x.get('slug')}：{x.get('why')}")
    if inv.get("firmware_older"):
        notes.append("舊的韌體 Release 不比對（只監控最新的一個，第一階段示範的限制）：" + "、".join(str(x)[:60] for x in inv["firmware_older"][:10]))
    if rm.get("rejected"):
        gaps.append(f"公告重跑拒絕了 firmware-meta.json 的 {len(rm['rejected'])} 筆條目（firmware.yml 產生端有問題）：" + "；".join(rm["rejected"][:10]))
        serious.append("韌體公告重跑拒絕了 firmware-meta 的條目")
    if rm["listed_unknown"]:
        notes.append("rematch-summary.json 列了 inventory 沒有的樣本（略過）：" + "、".join(rm["listed_unknown"][:10]))


def render_firmware(per, fwx, inv_fw, projs):
    """報告的韌體一節：表的識別（status、stale）、每份樣本的 Grype 與公告比對、changed、映像 sha256 的變化。"""
    rm = fwx["rm"]
    L = ["", "## 韌體", "", f"韌體 Release：{md_code((inv_fw or {}).get('tag'))}（FIRMWARE-WATCH.md；樣本是公開的測試資料，不是出貨品）", "", "表的識別："]
    if rm["tables"] is not None:
        L += fw_tables_text(rm["tables"], FW_TABLES)
    else:
        L += ["  - 這次沒有公告重跑的結果（NOT_RUN／GAP）：沒有表的識別；狀態裡保留上一次的值"]
        old = fwx["tables"] if fwx["tables"] else {}
        if old:
            L += ["  - 上一次的識別："] + [f"  {x}" for x in fw_tables_text(old, FW_TABLES)]
    for name, why in sorted(rm["table_flags"].items()):
        L.append(f"  - 注意：{md_code(name)}：{md_text('；'.join(sorted(set(why))[:3]))}")
    L += ["", "| 樣本 | 監控鍵 | 種類 | Grype | 公告比對 | 映像 sha256 | 說明 |", "|---|---|---|---|---|---|---|"]
    for p in projs:
        if not is_fw(p):
            continue
        r = per.get(p["uuid"]) or {}
        why = "；".join(x for x in [r.get("why"), r.get("advisory_why")] + list(r.get("advisory_reasons") or []) if x)
        L.append(f"| {md_code(p['slug'])} | {md_cell(p['uuid'])} | {md_text(p.get('sample_kind') or '—')} | {md_cell(r.get('grype'))} | "
                 f"{md_cell(r.get('advisory'))} | {md_code(p.get('image_sha256') or '—')} | {md_text(why, 400)} |")
    chg = [(p, x) for p in projs if is_fw(p) for x in rm["adv"].get(p["uuid"], {}).get("changed") or []]
    if chg:
        L += ["", "結果和 Release 當時不同（changed）：", ""]
        for p, x in chg[:50]:
            def fmt(y):
                if y.get("result") is None:          # C2 介面：Release 當時沒有這個元件的結果
                    return "（Release 當時沒有這個元件的結果）"
                return (f"{md_code(y['result'])}" + (f"（{'、'.join(md_code(b) for b in y['bulletins'])}）" if y["bulletins"] else "")
                        + (f"［review {md_code(y['review'])}］" if y.get("review") else ""))
            L.append(f"- {md_code(p['slug'])}：{md_code(x['key'])}：{fmt(x['before'])} → {fmt(x['after'])}")
    if fwx["changes"]:
        L += ["", "映像 sha256 變了（同 slug、同版本）：", ""]
        L += [f"- {md_code(c['slug'])}：之前 {md_code(c['old'])}、現在 {md_code(c['new'])}" for c in fwx["changes"]]
    fws = [r for r in per.values() if r.get("kind") == "firmware"]
    if any(r.get("grype") == FW_GRYPE_NA for r in fws):
        L += ["", f"- {FW_GRYPE_NOTE}（沒有 purl／CPE 的樣本，Grype 是 NOT_ASSESSED，不是 OK）。"]
    if any(r.get("grype") not in (None, FW_GRYPE_NA) for r in fws):
        L += ["", f"- 有可比對元件的樣本照常比對；{FW_NVD_NOTE}。"]
    return L


def render_report(mode, detail, status, per, gaps, attn, notes, coverage, actions, first, vrep, fw=None, inv_fw=None, projs=None):
    L = [f"# 每日監控（{mode}）：{status}", "", detail, ""]
    if first:
        L += ["**第一次執行：只建立基準，不開 Issue。**", ""]
    L += ["## 各 SBOM", "", "| 專案鍵 | Release | 報告狀態 | 發行閘門 | Grype | 已遭利用 | 版本未知 | 核心 CNA | 說明 |",
          "|---|---|---|---|---|---|---|---|---|"]
    for r in per.values():
        L.append(f"| {md_cell(r['uuid'])} | {md_code(r['tag'])} | {r.get('report_status') or 'NOT_RUN'} | {r.get('release_gate') or 'NOT_RUN'} | "
                 f"{r['grype']} | {r['exploited']} | {r['version_unknown']} | {r['kernel_cna'] or '不適用'} | {md_cell(r['why'])} |")
    L += ["", "## 每日沒有涵蓋的項目", ""] + [f"- {x}：{y}" for x, y in coverage]
    if fw is not None:
        L += render_firmware(per, fw, inv_fw, projs or [])
    for title, xs in (("GAP", gaps), ("需注意", attn), ("說明", notes)):
        if xs:
            L += ["", f"## {title}", ""] + [f"- {md_cell(x)}" for x in xs]
    if vrep:
        L += ["", "## 廠商層級", "", md_cell(vrep.get("detail"))]
    L += ["", "## 要執行的 Issue 動作", ""] + ([f"- {x['op']}：{md_cell(x.get('title') or x['key'][:12])}" for x in actions] or ["- 無"])
    return "\n".join(L) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description="每日監控的比對（WATCH.md 3.2）")
    ap.add_argument("--inventory", required=True)
    ap.add_argument("--state-dir", required=True)
    ap.add_argument("--feeds", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--mode", choices=("real", "drill"), default="real")
    ap.add_argument("--kev-overlay")
    ap.add_argument("--max-new-issues", type=int, default=20)
    ap.add_argument("--run-url")
    ap.add_argument("--grype")
    ap.add_argument("--grype-total-timeout", type=float, default=GRYPE_TOTAL)
    ap.add_argument("--vendor-config", default=os.path.join(HERE, "vendor-watch.json"))
    ap.add_argument("--now")
    ap.add_argument("--demo", action="store_true", help="公開 repo：Issue 標明「示範專案（公開 BSP）」並加 demo 標籤（D-040）")
    ap.add_argument("--prev-schedule", help="watch.yml 最近幾次排程 run 的 JSON（workflow 用 actions: read 查）：上一次被取消或沒跑 → 降級")
    ap.add_argument("--run-id", help="這一次的 run id（從 --prev-schedule 排除）")
    ap.add_argument("--firmware-rematch", help="firmware-rematch.sh 的輸出資料夾（rematch-summary.json、rematch-<slug>.json；不可信資料）。沒給 → 韌體公告 NOT_RUN")
    ap.add_argument("--allow-baseline", action="store_true",
                    help="還沒有狀態時，允許建立第一次的基準（要人明確指定；沒給時回 GAP、不產生 plan）")
    try:
        a = ap.parse_args(argv)
    except SystemExit as e:
        return 64 if e.code else 0
    if a.max_new_issues < 1:
        print(f"{STAGE}\tFAIL\t--max-new-issues 至少 1")
        return 64
    try:
        st, detail = run(a)
    except Fail as e:
        print(f"{STAGE}\tFAIL\t{e}")
        return 1
    print(f"{STAGE}\t{st}\t{detail}")
    return EXIT[st]


if __name__ == "__main__":
    sys.exit(main())
