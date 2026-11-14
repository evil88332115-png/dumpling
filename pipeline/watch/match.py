#!/usr/bin/env python3
"""match.py：每日監控的比對（WATCH.md 3.2、3.3、3.5）。讀 inventory、資料源、狀態 → plan.json（要開的 Issue、新的狀態）＋report.md。

用法：
  python3 -I pipeline/watch/match.py --inventory <W/inventory.json> --state-dir <W/state> --feeds <W/feeds> --out <W/out>
        [--mode real|drill] [--kev-overlay <合成 KEV.json>（只限 drill）] [--max-new-issues 20] [--run-url <網址>]
        [--grype <執行檔>] [--grype-total-timeout 1500] [--vendor-config <vendor-watch.json>] [--now <UTC ISO>] [--demo] [--allow-baseline]
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
  - --demo（公開 repo）：標題與內文寫明「示範專案（公開 BSP）」、加 demo 標籤；不開 art14 Issue（第 14 條只做演練）。
輸出：stdout 一行 WATCH-MATCH<TAB>OK|ATTENTION|FAIL<TAB>說明；<out>/plan.json、report.md、result.json。
退出碼：OK 0、FAIL 1、ATTENTION 2、GAP 3、用法 64。FAIL 與 GAP 時不寫 plan.json（notify 跳過，不會動任何東西）。
  GAP：還沒有狀態、也沒有任何可監控的 SBOM（例如 M2 之前）→ 不建立空的基準。
"""
import argparse
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
    return inv, projs, problems


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
        {vendor_group_key(mode, e) for e in (st.get("vendor_matches") or {}).values() if isinstance(e, dict) and "vendor" in e}
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
    return out


# ---------- 寫進公開 Issue 的外部字串（#49 驗證應修 3） ----------
# 元件名、purl、KEV 的廠商／產品、release-meta 的 attention、kernel-versions 的說明、鏡像訊息……都是外部資料：
# @ 會通知 GitHub 上的使用者或組織（例如 npm 的 @types/node），[x](url)、![i](url) 會變成連結或圖片，#123 會連到別的 Issue。
_MD_CTRL = re.compile(r"[\x00-\x1f\x7f\u200b-\u200f\u2028\u2029\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]")
ZWSP = "\u200b"


def _plain(x, limit):
    return re.sub(r"\s+", " ", _MD_CTRL.sub(" ", str(x if x is not None else ""))).strip()[:limit]


def md_text(x, limit=300):
    """外部字串 → Markdown 純文字：& 先換成 &amp;（否則 &commat; 之類的 HTML 實體渲染時會解碼成 @、[ 等），
    再跳脫 \\ [ ] ( ) ! < > ` | * _ ~，@ 與 # 後面插零寬空白（不通知人、不連到 Issue）。表格儲存格也用這個。"""
    s = _plain(x, limit).replace("&", "&amp;").replace("\\", "\\\\")
    s = re.sub(r"([\[\]()!<>`|*_~])", r"\\\1", s)
    return re.sub(r"([@#＠＃])", "\\1" + ZWSP, s)


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
    return re.sub(r"([@#＠＃&＆])", "\\1" + ZWSP, _plain(x, limit))


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
    return issue_key(mode, "vendor", e["project_uuid"], e["cve"], e["vendor"])


def pinfo_of(projs, uuid):
    return next((p for p in projs if p["uuid"] == uuid), None)


def release_results(p):
    """Release 的結論（release-meta；缺少時 NOT_RUN）。status 是生命週期，這幾個才是掃描與發行的結論。"""
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
            "product": "沒有分層 SBOM（整份產品）：當成我們的待辦。"}.get(p["layer"], "")


def labels_for(p, kind):
    ls = ["kev"] if kind == "kev" else ["vendor-level"]
    if p:
        ls += [p["status"], f"layer-{p['layer']}"]
    return ls


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


def vendor_body(mode, e, p, run_url, now):
    lines = []
    if mode == "drill":
        lines += ["> **演練（合成資料）**：這是每日監控的演練 Issue，不是真的漏洞通知。", ""]
    lines += [f"廠商層級、**可能相關**：{md_text(e['cve'])}（KEV 廠商 {md_text(e.get('kev_vendor') or '?')}、產品 {md_text(e.get('kev_product') or '?')}）"
              f"與 **{md_text(e.get('project'))} {md_text(e.get('version'))}** 監看的廠商 {md_code(e.get('vendor'))} 相同，但沒有元件比對。", "",
              f"- 監看來源：{md_text(', '.join(str(x) for x in e.get('watch_via') or []))}；元件數 {md_text(e.get('component_count'))}",
              f"- KEV 加入日期：{md_text(e.get('date_added') or '?')}；來源：{md_text(e.get('source') or '?')}",
              f"- 第一次偵測：{md_text(e.get('first_detected'))}（這次執行 {utc(now)}）"]
    if p:
        lines += [f"- Release：{md_code(p.get('tag'))}；狀態：{p['status']}；{HANDLING.get(p['status'], '')}", f"- 分層：{layer_note(p)}",
                  f"- Release 的結論：{release_results(p)}"]
    lines += ["", "要人工確認：KEV 的受影響產品是不是在這個專案裡（廠商可能有很多產品）。", "", ART14_NOTE]
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


def plan_issues(mode, state, projs, new, back, gone, vrep, baseline, coverage, run_url, now, max_new):
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
    for e in (vrep or {}).get("new") or []:
        gk = vendor_group_key(mode, e)
        if gk in iss:
            continue
        p = pinfo_of(projs, e["project_uuid"])
        title = f"[廠商層級] {md_title(e['cve'])}（{md_title(e.get('vendor'))}）可能影響 {md_title(e.get('project'))} {md_title(e.get('version'))}"
        pending.append((gk, "vendor", title, vendor_body(mode, e, p, run_url, now), labels_for(p, "vendor"), e))
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
        actions.append({"op": "open", "key": sk, "title": f"[KEV][ATTENTION] 彙總：{len(rest)} 個新的命中群組（{ts[:10]}）", "body": "\n".join(body),
                        "labels": ["kev", "summary", "attention"]})
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
        for p in projs:
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
        if first:
            # 基準不完整會讓下一次把既有的命中全部當成新的：任何一項沒有完整跑完就 FAIL、不寫狀態（PR #28 驗證應修 1）
            why = []
            missing = [p["uuid"] for p in projs if p["uuid"] not in grype_ok]
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
            if why:
                raise Fail("第一次執行要建立基準，但沒有完整跑完：" + "；".join(why) + "。基準不完整會讓下一次把既有的命中全部當成新的，這次不寫狀態")
        coverage = list(NOT_RUN_DAILY)
        nb_key = issue_key(a.mode, "no-baseline")
        nb_actions = [{"op": "comment", "key": nb_key, "reopen_if_closed": False,
                       "body": f"已建立基準（{utc(now)}，{len(projs)} 份 SBOM）。每日監控開始比對，這個 Issue 可以關閉。"}] \
            if first and nb_key in (sbase.get("watch_keys") or []) else []
        actions, stats = plan_issues(a.mode, state, projs, new, back, gone, vrep, first, coverage, a.run_url, now, a.max_new_issues)
        actions += nb_actions
        if not first and a.mode == "real":      # 演練刻意不下載 EUVD／核心 CNA：不開健康 Issue
            actions += health_actions(a.mode, state, serious, now, a.run_url)
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
    report = render_report(a.mode, detail, status, per, gaps, attn, notes, coverage, actions, first, vrep)
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
    for name, obj in (("plan.json", plan), ("result.json", result)):
        tmp = os.path.join(a.out, name + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=1)
        os.replace(tmp, os.path.join(a.out, name))
    with open(os.path.join(a.out, "report.md"), "w", encoding="utf-8") as f:
        f.write(report)
    return status, detail


def render_report(mode, detail, status, per, gaps, attn, notes, coverage, actions, first, vrep):
    L = [f"# 每日監控（{mode}）：{status}", "", detail, ""]
    if first:
        L += ["**第一次執行：只建立基準，不開 Issue。**", ""]
    L += ["## 各 SBOM", "", "| 專案鍵 | Release | 報告狀態 | 發行閘門 | Grype | 已遭利用 | 版本未知 | 核心 CNA | 說明 |",
          "|---|---|---|---|---|---|---|---|---|"]
    for r in per.values():
        L.append(f"| {md_cell(r['uuid'])} | {md_code(r['tag'])} | {r.get('report_status') or 'NOT_RUN'} | {r.get('release_gate') or 'NOT_RUN'} | "
                 f"{r['grype']} | {r['exploited']} | {r['version_unknown']} | {r['kernel_cna'] or '不適用'} | {md_cell(r['why'])} |")
    L += ["", "## 每日沒有涵蓋的項目", ""] + [f"- {x}：{y}" for x, y in coverage]
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
