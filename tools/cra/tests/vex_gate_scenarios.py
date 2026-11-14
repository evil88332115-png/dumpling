"""M7c-2（D-035／D-057）閘門基準的輸入：同一組輸入分別用改動前（main bf92964）與改動後的程式碼跑 assess＋gate（單元）與 cra_report（端對端），
比對閘門輸出。這個檔案不是測試（不以 test_ 開頭），不 import 被測的程式以外的東西，也不自己插入 sys.path：呼叫端決定 vex_export 從哪裡來。

產生基準 data/vex_gate_before_d035.json 的方式（在改動前的程式碼上；基準不隨之後的改動重生）：
    git worktree add --detach <資料夾> bf92964                       # main，M7c-1b 合併後、M7c-2 之前
    cd <資料夾>/tools/cra/tests && PYTHONPATH=.:.. python3 -I -c "..."   # 見 generate_baseline 的 docstring
也就是：把改動前的 tools/cra/tests 與 tools/cra 放在 sys.path 前面，載入這個檔案，呼叫 generate_baseline(<暫存資料夾>)，把結果存成 JSON。
test_vex_evidence_basis.py 的 test_gate_baseline_before_d035 用同一組輸入跑新程式，逐項比對。
"""
import copy
import json
import re
import tempfile
from pathlib import Path

import vex_export as vx
from test_cra_distro import EXTRA, OSSL, recheck_doc
from test_cra_report import FINDINGS, make_project, make_scan, run, write_json
from test_vex_evidence import KCFG, KV, MMAP, erule, kmods, rules_of
from test_vex_export import DEB, NVB, ann, dt, row
from test_vex_rules import krow
from test_vex_u1_flag import UST as UBUNTU_U1
from test_vex_u2 import OWN_PURL, UST as UBUNTU_U2, prow

IMG = "sha256:" + "ab" * 32


def _ustatus():
    """U1（openssl）與 U2（python3-urllib3）兩份合成的 Ubuntu tracker 狀態併成一份。"""
    return dict(UBUNTU_U1, components=dict(UBUNTU_U1["components"], **UBUNTU_U2["components"]),
                entries=dict(UBUNTU_U1["entries"], **UBUNTU_U2["entries"]))


def scenarios():
    """名稱 → (assess 的參數, 說明)。每一組輸入都是合成資料；rows 每次呼叫重建（assess 會改列）。"""
    p = "pkg:deb/ubuntu/openssl"
    return {
        # 沒有任何排除（resolved、not_affected）：閘門的所有數字都不能因為 D-035 而變
        "no_exclusions": dict(
            rows=lambda: [row("CVE-N1"), row("CVE-N2", "linux", "6.8", kernel=True, tier="p3"), row("CVE-N3", tier="p1", kev=True),
                          row("CVE-N4", analysis=dt("EXPLOITABLE", response="UPDATE", details="fix in 2.4")),
                          row("CVE-N5", analysis=dt("IN_TRIAGE")), row("CVE-N6"),
                          row("CVE-2021-34401", "nvidia-l4t-core", "39.2.1-20260806224157"),
                          row("CVE-2026-0001", cves=["CVE-2026-0001", "CVE-2026-0002"],
                              all_ids=["CVE-2026-0001", "CVE-2026-0002", "GHSA-xxxx-yyyy-zzzz"])],
            kw=dict(annotations=[ann("CVE-N6", "exploitable", purl=p), ann("CVE-2026-0001", "in_triage", purl=p, detail="looking")], nvb=NVB)),
        # 人的判定（DT、annotation）的排除：沒有 evidence 欄位 → 沒有類型
        "dt_and_annotation": dict(
            rows=lambda: [row("CVE-D1", analysis=dt("NOT_AFFECTED", "CODE_NOT_PRESENT", details="not built")),
                          row("CVE-D2", analysis=dt("FALSE_POSITIVE", "CODE_NOT_PRESENT")),
                          row("CVE-D3", analysis=dt("RESOLVED", details="fixed")),
                          row("CVE-A1"), row("CVE-A2"), row("CVE-A3"), row("CVE-X1"),
                          row("CVE-2026-0001", cves=["CVE-2026-0001", "CVE-2026-0002"],
                              all_ids=["CVE-2026-0001", "CVE-2026-0002", "GHSA-xxxx-yyyy-zzzz"])],
            kw=dict(annotations=[ann("CVE-A1", "not_affected", purl=p), ann("CVE-A2", "resolved", purl=p),
                                 ann("CVE-A3", "false_positive", purl=p, justification="code_not_present"),
                                 ann("CVE-2026-0001", "not_affected", purl=p)])),
        # 自動的來源（發行版修補紀錄、核心設定檢查）
        "automatic_sources": dict(
            rows=lambda: [row("CVE-2024-6119"), row("CVE-2026-45447"), row("CVE-2026-2000", kev=True), row("CVE-2026-63076"),
                          krow("CVE-K1"), krow("CVE-K1B"), row("CVE-X2")],
            kw=dict(drc=recheck_doc(), kcfg=KCFG)),
        # 證據規則 K1、K2、U1、U2（rule_ctx 帶模組對應、映像模組清單、Ubuntu 狀態）
        "evidence_rules": dict(
            rows=lambda: [krow("CVE-K1"), krow("CVE-RM"), krow("CVE-BLK"), krow("CVE-LD"), row("CVE-U1"), row("CVE-U2"), row("CVE-U3"),
                          prow("CVE-P1"), prow("CVE-P3"), row("CVE-X3")],
            kw=dict(kcfg=KCFG, rules=rules_of(erule("K1", "K1"), erule("K2", "K2"), erule("U1", "U1"), erule("U2", "U2")),
                    rule_ctx=dict(image_ids=[IMG], today="2026-11-05", vercmp=_vercmp(), kernel_fix_all={}, module_map=MMAP,
                                  kernel_modules=kmods(), kernel_modules_info={"image": vx.norm_image(IMG), "sha256": "ef" * 32},
                                  ubuntu_status=_ustatus()))),
    }


def _vercmp():
    import cra_report
    return cra_report.deb_vercmp


def gate_json(g):
    return json.loads(json.dumps(g, sort_keys=True, ensure_ascii=False))


def run_unit(name, spec):
    allr, conf, _ = vx.assess(spec["rows"](), **{k: (copy.deepcopy(v) if k != "rule_ctx" else v) for k, v in spec["kw"].items()})
    return allr, conf, vx.gate(allr, conf, grype_checked=True, not_assessed=[])


def e2e_cases():
    """名稱 → (findings、distro 檢查、專案的 annotation)。端對端：cra_report 的 summary.json vex.gate。"""
    no_analysis = [dict(f, analysis={"isSuppressed": False}) if (f["analysis"] or {}).get("state") in ("NOT_AFFECTED", "FALSE_POSITIVE") else f
                   for f in FINDINGS]
    anns = {"schema": vx.ANN_SCHEMA, "annotations": [ann("CVE-2025-0003", "not_affected", purl="pkg:deb/ubuntu/openssl", version="3.0.13-0ubuntu3.11")]}
    return {"e2e_default": (FINDINGS, None, None),
            "e2e_no_exclusions": (no_analysis, None, None),
            "e2e_distro": (FINDINGS + EXTRA, recheck_doc(), None),
            "e2e_annotation_exclusion": (no_analysis, None, anns)}


def run_e2e(name, case, tmp):
    findings, drc, anns = case
    proj = make_project(Path(tmp) / name / "p")
    scan = make_scan(Path(tmp) / name / "s", findings=findings)
    if drc is not None:
        write_json(scan / "scan" / "distro-recheck.json", drc)
    if anns is not None:
        write_json(proj / vx.ANN_REL, anns)
    r, s, _ = run(proj, scan)
    assert s is not None and s["status"] != "FAIL", r.stdout + r.stderr
    return gate_json(s["vex"]["gate"])


def generate_baseline(tmp=None):
    """改動前的程式碼上呼叫：回傳 {"unit": {名稱: gate}, "e2e": {名稱: gate}}。"""
    tmp = tmp or tempfile.mkdtemp(prefix="vex-gate-baseline-")
    return {"unit": {n: gate_json(run_unit(n, spec)[2]) for n, spec in scenarios().items()},
            "e2e": {n: run_e2e(n, case, tmp) for n, case in e2e_cases().items()}}


def diff_paths(a, b, path=""):
    """兩份 JSON 值的差異路徑清單（空＝全等）。"""
    if isinstance(a, dict) and isinstance(b, dict):
        return [x for k in sorted(set(a) | set(b)) for x in diff_paths(a.get(k, "<missing>"), b.get(k, "<missing>"), f"{path}/{k}")]
    if isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        return [x for i, (u, v) in enumerate(zip(a, b)) for x in diff_paths(u, v, f"{path}[{i}]")]
    return [] if a == b else [f"{path}: {json.dumps(a, ensure_ascii=False)[:120]} -> {json.dumps(b, ensure_ascii=False)[:120]}"]


EXC_REASON = "{n} exclusions without evidence type"


def d035_unexplained(old, new):
    """改動前（old）與改動後（new）的閘門輸出，扣掉 D-035 的效果之後還剩的差異（空清單＝每一個變動的數字都能用「沒有類型的排除算進
    untriaged_for_gate」解釋）。D-035 的效果只有：assessment.exclusions_without_evidence（新欄位，n）、assessment.untriaged_for_gate 加 n、
    assessment.complete 在 n > 0 時變 false、reasons 多一條開頭是 "<n> exclusions without evidence type" 的理由（加上其他理由在沒有
    untriaged 時少了 "assessment complete; " 的開頭）、verdict 在 n > 0 而原本是 OK 時變 ATTENTION。其他任何差異都回報。"""
    a, exp = new["assessment"], copy.deepcopy(new)
    n = a["exclusions_without_evidence"]
    errs = []
    del exp["assessment"]["exclusions_without_evidence"]
    exp["assessment"]["untriaged_for_gate"] -= n
    if a["complete"] != (old["assessment"]["complete"] and n == 0):
        errs.append(f"assessment.complete: {old['assessment']['complete']} -> {a['complete']} with {n} exclusions without type")
    exp["assessment"]["complete"] = old["assessment"]["complete"]
    pref = EXC_REASON.format(n=n)
    mine = [r for r in new["reasons"] if r.startswith(pref)]
    if len(mine) != (1 if n else 0):
        errs.append(f"reasons: {len(mine)} reason(s) start with {pref!r}")
    rest = [r for r in new["reasons"] if not r.startswith(pref)]
    strip = (lambda rs: [re.sub(r"^assessment complete; ", "", r) for r in rs]) if n else (lambda rs: rs)
    exp["reasons"] = old["reasons"] if strip(rest) == strip(old["reasons"]) else rest
    if n and old["verdict"] == "OK" and new["verdict"] == "ATTENTION":
        exp["verdict"] = "OK"
    return errs + diff_paths(old, exp)
