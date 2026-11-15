"""vex_export.py 的證據規則 K1、K2（vex-rules.json 的 "evidence"）與標記 K3、K4：格式驗證；嚴重度／EPSS／層級永遠不是
not_affected 的輸入（結構與行為兩邊鎖住）；KEV／被利用的列永遠不套用；人的判定不被蓋過、被蓋過的記 shadowed；輸入改變（模組、映像、
核心設定、生效日、適用映像、責任人）時自動不套用；沒有生效的 K1 照舊讓核心設定檢查自動套用；照抄範例規則檔不改任何輸出；
K2 各種載入限制；cra_report 的整合（summary.json、風險評估、VEX 的屬性、rules check）與兩個收尾（counts.epss.dt_invalid、百分位 0.0）。
全部是合成資料。"""
import copy
import hashlib
import itertools
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import cra_report as cra  # noqa: E402
import vex_export as vx  # noqa: E402
from test_cra_report import FINDINGS, META, finding, kernel_scan, make_project, make_scan, run, write_json  # noqa: E402
from test_vex_export import dt, kcfg, row  # noqa: E402
from test_vex_rules import KVER, doc, krow, rule  # noqa: E402

CLI = HERE.parent / "vex_export.py"
IMG = "sha256:" + "ab" * 32
OTHER_IMG = "sha256:" + "cd" * 32
KV = "6.8.12-1021-tegra"


def erule(rid, ev, images=("*",), date="2026-11-01", author="Alice"):
    r = {"id": rid, "description": f"{ev} evidence", "date": date, "reason": "decided from product artifacts", "evidence": ev,
         "images": list(images)}
    if author is not None:
        r["author"] = author
    return r


def rules_of(*rs):
    d = doc(*rs)
    vx.check_rules(d)
    return vx.effective_rules(d)


BUILD_BUILTIN = ["builtin_mod"]


def mmap(cves, version=KV, order=None, builtin=None, **top):
    """order：這個建置的 modules.order（預設：cves 裡出現的模組，建置 modules.builtin 的除外）；"none" → null。"""
    if order is None:
        order = sorted({vx.norm_module(m) for e in cves.values() if isinstance(e, dict) and isinstance(e.get("modules"), list)
                        for m in e["modules"] if isinstance(m, str)} - set(BUILD_BUILTIN) | {"kept_mod"})
    return {"schema": vx.MODMAP_SCHEMA, "status": "OK", "kernel": {"version": version}, "component": kcfg([])["component"],
            "method": "synthetic Kbuild mapping", "modules_order": None if order == "none" else order,
            "modules_builtin": BUILD_BUILTIN if builtin is None else builtin,
            "sources": {"modules_order_sha256": "b" * 64}, "cves": cves,
            # 映像的模組資料夾裡所有 .ko 的名稱（預設：kmods() 的 modules_in_image；gone_mod 不在）
            **({} if "modules_present" in top else {"modules_present": sorted(vx.norm_module(m) for m in kmods()["modules_in_image"])}),
            **top}


def kmods(**kw):
    d = {"schema": vx.KMOD_SCHEMA, "image_sha256": IMG, "kernel_version": KV, "captured": "2026-11-04", "owner": "Bob",
         "source": "synthetic: find /usr/lib/modules, cat /etc/modprobe.d/*.conf, lsmod",
         "modules_in_image": ["kernel/drivers/x/kept_mod.ko.zst", "loaded-mod.ko", "blocked-mod.ko", "bl_only.ko", "dis_mod.ko"],
         "modules_builtin": ["kernel/drivers/y/builtin_mod.ko"], "modprobe_d": ["# comment", "blacklist bl_only", "install blocked-mod /bin/false"],
         "modules_softdep": [vx.SOFTDEP_HEADER], "modules_disabled": False, "loaded": ["loaded_mod"]}
    d.update(kw)
    return d


def ctx(**kw):
    c = {"image_ids": [IMG], "today": "2026-11-05", "vercmp": cra.deb_vercmp, "kernel_fix_all": {}}
    km = kw.pop("kernel_modules", None)
    if km is not None:
        c.update(kernel_modules=km, kernel_modules_info={"image": vx.norm_image(km["image_sha256"]), "sha256": "ef" * 32})
    c.update(kw)
    return c


def assess(rows, rules, kc=None, **kw):
    return vx.assess(copy.deepcopy(rows), kcfg=kc, rules=rules, rule_ctx=ctx(**kw), annotations=kw.pop("annotations", ()))


KCFG = kcfg([{"cve": "CVE-K1", "decision": "not_affected", "detail": "CONFIG_FOO is not set"},
             {"cve": "CVE-K1B", "decision": "affected"}])
MMAP = mmap({"CVE-RM": {"modules": ["gone_mod"], "builtin": False},
             "CVE-BLK": {"modules": ["blocked-mod"], "builtin": False},
             "CVE-LD": {"modules": ["loaded_mod"], "builtin": False},
             "CVE-BL": {"modules": ["bl_only"], "builtin": False},
             "CVE-DIS": {"modules": ["dis_mod"], "builtin": False},
             "CVE-BI": {"modules": [], "builtin": True},
             "CVE-MB": {"modules": ["builtin_mod"], "builtin": False},
             "CVE-MIX": {"modules": ["gone_mod", "blocked-mod"], "builtin": False},
             "CVE-BAD": {"modules": "gone_mod", "builtin": False}})
def by_id(allr):
    return {r["id"]: r for r in allr}


def summary_of(info, rid):
    return next(x for x in info["rules"] if x["id"] == rid)


# ---------- 格式 ----------

def test_evidence_rule_validation():
    assert len(rules_of(erule("K1", "K1"), erule("K2", "K2", images=[IMG]), erule("K2b", "K2", images=[IMG, OTHER_IMG.upper().replace("SHA256", "sha256")]))) == 3
    bad = [
        (dict(erule("E", "K1"), match={"scope": "kernel", "severity": ["LOW"]}), "嚴重度、EPSS"),
        (dict(erule("E", "K1"), set={"state": "not_affected"}), "不能有 match／set"),
        (dict(erule("E", "K1"), epss_percentile_max=0.1), "epss_percentile_max：不認得的鍵"),
        (dict(erule("E", "K1"), severity=["LOW"]), "severity：不認得的鍵"),
        (dict(erule("E", "K1"), tier=["p3"]), "tier：不認得的鍵"),
        (erule("E", "K9"), "evidence：只能是 "),
        ({k: v for k, v in erule("E", "K1").items() if k != "images"}, "images：必填"),
        (erule("E", "K1", images=[]), "images：必填"),
        (erule("E", "K1", images=["*", IMG]), "\"*\" 只能單獨寫"),
        (erule("E", "K1", images=["sha256:abc"]), "sha256:<64 個十六進位字元>"),
        (erule("E", "K1", date="2026-02-30"), "YYYY-MM-DD"),
        (dict(erule("E", "K1"), reason=""), "reason：必填"),
    ]
    for r, msg in bad:
        with pytest.raises(vx.VexInputError) as e:
            vx.check_rules(doc(r))
        assert msg in str(e.value), (msg, str(e.value))
    # match 規則照舊不能設 not_affected（只有證據規則可以，而且輸入固定）
    with pytest.raises(vx.VexInputError, match="規則不能設 not_affected"):
        vx.check_rules(doc(rule(state="not_affected", response=(), severity=["LOW"], epss_percentile_max=0.01)))


def test_kernel_modules_file_validation(tmp_path):
    proj = tmp_path / "p"
    assert vx.load_kernel_modules(proj) == (None, None)
    write_json(proj / vx.KMOD_REL, kmods())
    d, info = vx.load_kernel_modules(proj)
    assert info["image"] == "ab" * 32 and info["kernel_version"] == KV and len(info["sha256"]) == 64
    for bad, msg in ((kmods(modules_in_image=[]), "modules_in_image：要是不是空的文字清單"), (kmods(owner="專案負責人"), "owner：必填"),
                     (kmods(image_sha256="abc"), "image_sha256：必填"), (kmods(modules_disabled="1"), "modules_disabled"),
                     (kmods(loaded=[1]), "loaded"), (kmods(extra=1), "extra：不認得的鍵"), (kmods(captured="yesterday"), "captured")):
        write_json(proj / vx.KMOD_REL, bad)
        with pytest.raises(vx.VexInputError, match=msg):
            vx.load_kernel_modules(proj)


# ---------- 嚴重度與 EPSS 永遠不是 not_affected 的輸入 ----------

def test_evidence_functions_only_see_artifact_fields(monkeypatch):
    for k in ("severity", "severity_dt", "epss", "epss_pct", "epss_other", "cvss", "cvss_score", "tier", "tier_before", "kev", "fix_state",
              "sev_by_source", "exploited_sources"):
        assert k not in vx.EVIDENCE_VIEW_KEYS
    seen = []
    for code, f in list(vx.EVIDENCE_FUNCS.items()):
        monkeypatch.setitem(vx.EVIDENCE_FUNCS, code, lambda v, ec, f=f: (seen.append(set(v)), f(v, ec))[1])
    rows = [krow("CVE-K1", severity="CRITICAL", epss_pct=0.99, epss=0.9, cvss_score=9.8, tier="p1"),
            krow("CVE-RM", severity="LOW", epss_pct=0.01, tier="p3")]
    assess(rows, rules_of(erule("K1", "K1"), erule("K2", "K2")), KCFG, module_map=MMAP, kernel_modules=kmods())
    assert seen and all(s == set(vx.EVIDENCE_VIEW_KEYS) for s in seen)


def test_severity_epss_tier_never_change_a_not_affected_decision():
    rules = rules_of(erule("K1", "K1"), erule("K2", "K2"))
    base = [krow("CVE-K1"), krow("CVE-K1B"), krow("CVE-RM"), krow("CVE-BLK"), krow("CVE-LD"), krow("CVE-NOMAP"), row("CVE-RM")]
    want = None
    vals = itertools.product(("CRITICAL", "LOW", "UNASSIGNED"), (None, 0.0, 0.99), ("p1", "p2", "p3"), ("fixed", "not-fixed"))
    for sev, epss, tier, fs in vals:
        rows = [dict(r, severity=sev, epss_pct=epss, epss=epss, cvss_score=9.8 if sev == "CRITICAL" else 1.0, tier=tier, fix_state=fs)
                for r in base]
        allr, _, _ = assess(rows, rules, KCFG, module_map=MMAP, kernel_modules=kmods())
        got = [(r["id"], (r["vex"] or {}).get("state"), tuple(m["code"] for m in r.get("vex_markers") or [])) for r in allr]
        want = want or got
        assert got == want, (sev, epss, tier, fs)
    # P1 只因為 EPSS 高（current 分級）也照樣套用：EPSS 不能讓證據規則不套用
    assert want == [("CVE-K1", "not_affected", ()), ("CVE-K1B", None, ("K4",)), ("CVE-RM", "not_affected", ()), ("CVE-BLK", "not_affected", ()),
                    ("CVE-LD", None, ("K3",)), ("CVE-NOMAP", None, ("K4",)), ("CVE-RM", None, ())]


# ---------- KEV、被利用的列 ----------

def test_kev_and_exploited_rows_are_never_ruled():
    rules = rules_of(erule("K1", "K1"), erule("K2", "K2"))
    rows = [krow("CVE-K1", kev=True), krow("CVE-RM", kev=True),
            krow("CVE-RM", exploited_sources=["EUVD"], key=["CVE-RM", "other", KVER])]
    allr, _, info = assess(rows, rules, KCFG, module_map=MMAP, kernel_modules=kmods())
    assert all(r["vex"] is None for r in allr)
    assert [summary_of(info, x)["excluded_kev"] for x in ("K1", "K2")] == [1, 2]
    # scan/euvd.json／人工證據的 CVE（rule_ctx exploited）也一樣
    allr, _, info = assess([krow("CVE-K1")], rules, KCFG, exploited=["CVE-K1"])
    assert allr[0]["vex"] is None and summary_of(info, "K1")["excluded_kev"] == 1


# ---------- 人的判定不被蓋過；被蓋過的記 shadowed ----------

def test_human_decision_is_never_overwritten_and_shadowed_is_recorded():
    rules = rules_of(erule("K1", "K1"), erule("K2", "K2"))
    rows = [krow("CVE-K1", analysis=dt("EXPLOITABLE", response="update")), krow("CVE-RM"),
            krow("CVE-BLK", analysis=dt("", suppressed=True))]
    anns = [{"cve": "CVE-RM", "purl": "pkg:deb/ubuntu/linux-nvidia-tegra", "version": KVER, "state": "exploitable",
             "response": ["will_not_fix"], "detail": "the driver is used by the product", "author": "Carol", "date": "2026-11-03"}]
    allr, conf, info = vx.assess(copy.deepcopy(rows), kcfg=KCFG, annotations=anns, rules=rules,
                                 rule_ctx=ctx(module_map=MMAP, kernel_modules=kmods()))
    k, m, s = allr
    assert k["vex"]["source"] == "dt" and k["vex"]["state"] == "exploitable"
    assert m["vex"]["source"] == "annotation" and m["vex"]["state"] == "exploitable"
    assert s["vex"] is None                                           # suppress 不是判定，但人看過：規則不寫相反的陳述
    assert k["rule_shadowed"] == [{"rule": "K1", "evidence": "K1", "would_set": "not_affected", "decided_by": "dt", "state": "exploitable"}]
    assert m["rule_shadowed"][0]["decided_by"] == "annotation" and m["rule_shadowed"][0]["rule"] == "K2"
    assert summary_of(info, "K1")["shadowed"] == {"dt": 1} and summary_of(info, "K2")["shadowed"] == {"annotation": 1, "dt_suppressed": 1}
    assert info["rule_shadowed_rows"] == 3
    # 結論不同：照樣列為衝突（和原本的核心設定來源一樣），不覆蓋
    assert {(c["id"], c["used"], c["other"]) for c in conf} >= {("CVE-K1", "dt:exploitable", "rule:not_affected"),
                                                                ("CVE-RM", "annotation:exploitable", "rule:not_affected")}
    assert all(not c["human"] for c in conf if c["other"].startswith("rule:"))


# ---------- K1 ----------

def test_k1_takes_over_the_kernel_config_source():
    rows = [krow("CVE-K1"), krow("CVE-K1", kev=True, key=["CVE-K1", "k2", KV])]
    allr, _, info = vx.assess(copy.deepcopy(rows), kcfg=KCFG)
    assert [r["vex"]["source"] for r in allr] == ["kconfig", "kconfig"] and not info["kernel_config_via_rule"]
    allr, _, info = assess(rows, rules_of(erule("K1", "K1")), KCFG)
    a, b = allr
    assert a["vex"]["source"] == "rule" and a["vex"]["rule"] == "K1" and a["vex"]["evidence"] == "K1"
    assert a["vex"]["justification"] == "code_not_present" and "(bulk rule K1 [K1]: K1 evidence)" in a["vex"]["detail"]
    assert "CONFIG_FOO is not set" in a["vex"]["detail"] and a["vex"]["rule_inputs"] == "kernel .config SHA-256 abababababab"
    assert b["vex"] is None and info["kernel_config_via_rule"] and info["sources"]["kconfig"] == 0
    # 核心設定改了（同一個 CVE 現在 affected）→ 規則自動不套用
    allr, _, _ = assess(rows[:1], rules_of(erule("K1", "K1")), kcfg([{"cve": "CVE-K1", "decision": "affected"}]))
    assert allr[0]["vex"] is None


def test_inactive_k1_keeps_the_automatic_kernel_config_source():
    """沒有生效的 K1（責任人是佔位字、映像不符、還沒到生效日）：核心設定檢查照舊是自動的來源 (c)，KEV 的列也和以前一樣。"""
    rows = [krow("CVE-K1"), krow("CVE-K1", kev=True, key=["CVE-K1", "k2", KV])]
    base = vx.assess(copy.deepcopy(rows), kcfg=KCFG)[0]
    for r in (erule("K1", "K1", author="專案負責人"), erule("K1", "K1", images=[OTHER_IMG]), erule("K1", "K1", date="2026-12-01")):
        allr, _, info = assess(rows, rules_of(r), KCFG)
        assert [x["vex"] for x in allr] == [x["vex"] for x in base] and [x["vex"]["source"] for x in allr] == ["kconfig", "kconfig"]
        assert not info["kernel_config_via_rule"] and info["sources"]["kconfig"] == 2 and info["sources"]["rule"] == 0
        assert summary_of(info, "K1")["inactive_rows"] == 2 and summary_of(info, "K1")["applied"] == 0


# ---------- K2、K3、K4 ----------

def test_k2_module_states():
    rules = rules_of(erule("K2", "K2"))
    ids = ["CVE-RM", "CVE-BLK", "CVE-LD", "CVE-BL", "CVE-DIS", "CVE-BI", "CVE-MB", "CVE-MIX", "CVE-BAD", "CVE-NOMAP"]
    allr, _, info = assess([krow(i) for i in ids], rules, module_map=MMAP, kernel_modules=kmods())
    r = by_id(allr)
    assert r["CVE-RM"]["vex"]["justification"] == "code_not_present" and "removed from the image: gone_mod" in r["CVE-RM"]["vex"]["detail"]
    assert r["CVE-BLK"]["vex"]["justification"] == "code_not_reachable" and "blocked_mod (modprobe.d: install blocked-mod /bin/false; not loaded)" in r["CVE-BLK"]["vex"]["detail"]
    # 擋住的那一行原文也在 rule_inputs（排除清單用）
    assert r["CVE-BLK"]["vex"]["rule_inputs"].endswith("; blocking line(s): install blocked-mod /bin/false")
    assert r["CVE-MIX"]["vex"]["justification"] == "code_not_reachable"
    marks = {i: [m["code"] for m in r[i].get("vex_markers") or []] for i in ids}
    assert marks["CVE-LD"] == ["K3"] and "loaded_mod (loaded)" in r["CVE-LD"]["vex_markers"][0]["detail"]
    assert marks["CVE-BL"] == ["K3"] and "blacklisted only" in r["CVE-BL"]["vex_markers"][0]["detail"]
    assert marks["CVE-DIS"] == ["K3"]                                    # modules_disabled false
    assert marks["CVE-BI"] == [] and marks["CVE-MB"] == []               # 編進核心：受影響，不加標記
    assert marks["CVE-BAD"] == ["K4"] and marks["CVE-NOMAP"] == ["K4"] and r["CVE-NOMAP"]["vex_markers"][0]["gap"]
    s = summary_of(info, "K2")
    assert s["applied"] == 3 and s["markers"] == {"K3": 3, "K4": 2} and s["not_applied"] == {"built_in": 2}
    assert s["justification"] == {"code_not_present": 1, "code_not_reachable": 2}
    # modules_disabled=1 而且沒載入 → 禁止載入；沒有載入清單 → 證明不了，K3
    allr, _, _ = assess([krow("CVE-DIS")], rules, module_map=MMAP, kernel_modules=kmods(modules_disabled=True))
    assert allr[0]["vex"]["justification"] == "code_not_reachable" and "modules_disabled=1" in allr[0]["vex"]["detail"]
    allr, _, _ = assess([krow("CVE-DIS"), krow("CVE-BLK")], rules, module_map=MMAP, kernel_modules=kmods(modules_disabled=True, loaded=None))
    assert [r["vex"] for r in allr] == [None, None] and all(r["vex_markers"][0]["code"] == "K3" for r in allr)
    # install 後面不是什麼都不做的指令 → 不算禁止
    allr, _, _ = assess([krow("CVE-BLK")], rules, module_map=MMAP,
                        kernel_modules=kmods(modprobe_d=["install blocked_mod /sbin/modprobe --ignore-install blocked_mod"]))
    assert allr[0]["vex"] is None
    # 一列多個 CVE：每個都要對得到
    allr, _, _ = assess([krow("CVE-RM", cves=["CVE-RM", "CVE-NOMAP"])], rules, module_map=MMAP, kernel_modules=kmods())
    assert allr[0]["vex"] is None and allr[0]["vex_markers"][0]["code"] == "K4"


def test_k2_inputs_change_or_stale_stop_the_rule():
    rules = rules_of(erule("K2", "K2"))
    rm = [krow("CVE-RM")]
    assert assess(rm, rules, module_map=MMAP, kernel_modules=kmods())[0][0]["vex"]["state"] == "not_affected"
    # 模組放回映像 → K3
    a = assess(rm, rules, module_map=MMAP, kernel_modules=kmods(modules_in_image=["gone-mod.ko.xz"]))[0][0]
    assert a["vex"] is None and a["vex_markers"][0]["code"] == "K3"
    # 模組清單取自別的映像 → 過期，不用（K3：狀態不明）
    a = assess(rm, rules, module_map=MMAP, kernel_modules=kmods(image_sha256=OTHER_IMG))[0][0]
    assert a["vex"] is None and "not from the scanned image" in a["vex_markers"][0]["detail"]
    # 核心版本不同
    a = assess(rm, rules, module_map=MMAP, kernel_modules=kmods(kernel_version="6.8.12-9999-tegra"))[0][0]
    assert a["vex"] is None and "is for kernel 6.8.12-9999-tegra" in a["vex_markers"][0]["detail"]
    # 沒有對應表、格式不對、status 不是 OK → 全部 K4
    for m in (None, {"schema": "x"}, dict(MMAP, status="GAP")):
        a = assess(rm, rules, module_map=m, kernel_modules=kmods())[0][0]
        assert a["vex"] is None and a["vex_markers"][0]["code"] == "K4"
    # 別的核心元件
    a = assess([row("CVE-RM", "linux-other", "1.0", kernel=True)], rules, module_map=MMAP, kernel_modules=kmods())[0][0]
    assert a["vex"] is None and "another kernel component" in a["vex_markers"][0]["detail"]


# ---------- 規則生效的條件：適用映像、生效日、責任人 ----------

def test_images_effective_date_and_author_gate_the_rule(tmp_path):
    rows = [krow("CVE-RM")]

    def one(r, **kw):
        a, _, info = assess(rows, rules_of(r), module_map=MMAP, kernel_modules=kmods(), **kw)
        return a[0]["vex"], summary_of(info, r["id"])
    v, s = one(erule("K2", "K2", images=[IMG]))
    assert v["rule"] == "K2" and s["inactive"] == []
    v, s = one(erule("K2", "K2", images=[OTHER_IMG]))
    assert v is None and s["inactive_rows"] == 1 and s["inactive"] == ["the scanned image is not in the rule's images"]
    v, s = one(erule("K2", "K2", images=[IMG]), image_ids=[])
    assert v is None and s["inactive"] == ["the scan has no image hash (meta.json)"]
    v, s = one(erule("K2", "K2", date="2026-11-06"))
    assert v is None and s["inactive"] == ["effective from 2026-11-06"]
    v, s = one(erule("K2", "K2", author="(your name)"))
    assert v is None and s["inactive"] == ["no named author"]
    # 第一條不生效時，同種類的下一條照樣可以套用
    a, _, _ = assess(rows, rules_of(erule("K2old", "K2", images=[OTHER_IMG]), erule("K2new", "K2")), module_map=MMAP, kernel_modules=kmods())
    assert a[0]["vex"]["rule"] == "K2new"
    a, _, info = assess([krow("CVE-K1")], rules_of(erule("K1old", "K1", images=[OTHER_IMG]), erule("K1new", "K1")), KCFG)
    assert a[0]["vex"]["rule"] == "K1new" and info["kernel_config_via_rule"]
    # 沒有責任人的證據規則不列在閘門的「沒有責任人」（它沒有套用任何一列），另外列在 evidence_without_author
    r1 = {k: v for k, v in rule("R1", detail="d").items() if k != "author"}
    d = dict(doc(erule("K1", "K1", author=None), r1), author="專案負責人")
    write_json(tmp_path / vx.RULES_REL, d)
    info = vx.load_rules(tmp_path)[1]
    assert info["without_author"] == ["R1"] and info["evidence_without_author"] == ["K1"]


def test_evidence_rules_run_before_match_rules_and_shadow_them():
    rs = rules_of(rule("R2", "kernel", state="exploitable", response=("can_not_fix",), detail="affected {cve}"), erule("K1", "K1"))
    allr, _, info = assess([krow("CVE-K1"), krow("CVE-K1B")], rs, KCFG)
    assert [r["vex"]["rule"] for r in allr] == ["K1", "R2"]
    assert summary_of(info, "R2")["shadowed"] == {"rule": 1} and [x["id"] for x in info["rules"]] == ["K1", "R2"]


# ---------- 閘門、表格、VEX 的屬性 ----------

def test_gate_label_and_cdx_properties():
    rules = rules_of(erule("K2", "K2"))
    allr, conf, info = assess([krow("CVE-RM"), krow("CVE-NOMAP"), krow("CVE-LD")], rules, module_map=MMAP, kernel_modules=kmods())
    g = vx.gate(allr, conf, grype_checked=True, not_assessed=[])
    assert g["untriaged_markers"] == {"K3": 1, "K4": 1}
    assert any(x.startswith("1 untriaged kernel rows cannot be mapped to a kernel module (K4") for x in g["reasons"])
    r = by_id(allr)
    assert vx.label(r["CVE-NOMAP"]) == "untriaged [K4 GAP: no module mapping]" and vx.label(r["CVE-LD"]) == "untriaged [K3: module loadable]"
    assert vx.label(r["CVE-RM"]) == "not_affected (rule K2)"
    from test_vex_export import PBOM
    cdx, _ = vx.cdx_vex(allr, PBOM, {}, {"name": "EX"}, g["verdict"])
    # M7c-1（A4）：沒有判定的 CVE-LD、CVE-NOMAP 也寫成 in_triage 加 NOT_ASSESSED，所以不能再用「第一條」找 CVE-RM
    rm = next(v for v in cdx["vulnerabilities"] if v["id"] == "CVE-RM")
    assert sorted(v["id"] for v in cdx["vulnerabilities"]) == ["CVE-LD", "CVE-NOMAP", "CVE-RM"]
    assert all({"name": "dumpling:assessment", "value": "NOT_ASSESSED"} in v["properties"] and v["analysis"]["state"] == "in_triage"
               for v in cdx["vulnerabilities"] if v["id"] != "CVE-RM")
    props = {p["name"]: p["value"] for p in rm["properties"]}
    assert props["sca-center:vex-rule"] == "K2" and props["sca-center:vex-rule-evidence"] == "K2"
    assert props["sca-center:vex-rule-inputs"] == ("kernel-modules.json SHA-256 efefefefefef; module map SHA-256 ?; "
                                                   "modules.order SHA-256 bbbbbbbbbbbb")
    assert rm["analysis"] == {"state": "not_affected", "justification": "code_not_present", "detail": rm["analysis"]["detail"]}


# ---------- cra_report 的整合 ----------

def ev_env(tmp_path, rules, findings_extra=(), meta=None):
    from test_cra_report import KFINDINGS
    sc = kernel_scan(tmp_path / "s", findings=KFINDINGS + list(findings_extra))
    # finished：VEX 的時間取掃描結束時間（沒有時用現在，兩次執行的 VEX 就不同）
    write_json(sc / "meta.json", meta or dict(META, digest=IMG, finished="2026-11-05T01:02:03Z"))
    write_json(sc / "scan" / "kernel-config.json", kcfg([{"cve": c, "decision": "not_affected", "detail": "CONFIG_X is not set"}
                                                         for c in ("CVE-2024-1086", "CVE-2025-0101", "CVE-2025-0107")]
                                                        + [{"cve": "CVE-2025-0102", "decision": "affected"}]))
    write_json(sc / "scan" / "kernel-module-map.json", mmap({"CVE-2025-0104": {"modules": ["gone_mod"], "builtin": False},
                                                             "CVE-2025-0105": {"modules": ["loaded-mod"], "builtin": False}}))
    proj = make_project(tmp_path / "p")
    write_json(proj / vx.RULES_REL, doc(*rules))
    write_json(proj / vx.KMOD_REL, kmods())
    return proj, sc


def test_report_integration_with_evidence_rules(tmp_path):
    proj, sc = ev_env(tmp_path, [erule("K1", "K1", images=[IMG]), erule("K2", "K2")])
    r, s, rep = run(proj, sc)
    assert r.returncode in (0, 2), r.stdout + r.stderr
    v = s["vex"]
    rs = {x["id"]: x for x in v["rules"]["rules"]}
    # K1：0101（P1，只因 EPSS 高）套用；1086 在 KEV 不套用；0107 有 DT 的人工判定 → shadowed。
    # K2：0104 模組已移除 → 套用；0105 模組有載入 → K3；0102、0103、0106 對應表沒有 → K4
    assert rs["K1"]["applied"] == 1 and rs["K1"]["excluded_kev"] == 1 and rs["K1"]["shadowed"] == {"dt": 1}
    assert rs["K1"]["shadowed_sample"][0]["id"] == "CVE-2025-0107"
    assert rs["K2"]["applied"] == 1 and rs["K2"]["markers"] == {"K3": 1, "K4": 3}
    assert v["kernel_config_via_rule"] and v["sources"]["kconfig"] == 0
    assert v["markers"] == {"K3": 1, "K4": 3} and v["gate"]["untriaged_markers"] == {"K3": 1, "K4": 3}
    assert v["kernel_modules"]["file"] == "CRA/Config/kernel-modules.json" and v["evidence_inputs"]["kernel_modules"] == "OK"
    assert v["evidence_inputs"]["images"] == ["ab" * 32] and s["inputs"]["scan/kernel-module-map.json"]["sha256"]
    assert s["counts"]["accepted_by_vex"] == {"rule": 2}
    md = (rep / "risk-assessment.md").read_text(encoding="utf-8")
    assert "#### Evidence rules (not_affected from product artifacts)" in md and "Severity, EPSS and the tier are never inputs" in md
    assert "| K2 | K2 | K2 evidence | Alice | 2026-11-01 | all images of the project |" in md
    assert "K4 3 – the CVE cannot be mapped to a kernel module" in md
    cdx = json.loads((rep / "vex.cdx.json").read_text(encoding="utf-8"))
    ev = sorted(p["value"] for x in cdx["vulnerabilities"] for p in x["properties"] if p["name"] == "sca-center:vex-rule-evidence")
    assert ev == ["K1", "K2"]
    ov = json.loads((rep / "vex.openvex.json").read_text(encoding="utf-8"))
    assert {st["justification"] for st in ov["statements"] if st["status"] == "not_affected" and "bulk rule" in (st.get("impact_statement") or "")} \
        <= {"vulnerable_code_not_present", "vulnerable_code_not_in_execute_path"}
    # rules check 的乾跑印出證據規則
    out = subprocess.run([sys.executable, "-I", str(CLI), "rules", "check", "--project", str(proj), "--scan", str(sc)],
                         capture_output=True, text=True, timeout=60, env=dict(os.environ, CRA_COMPANY_CONFIG="none"))
    assert out.returncode == 0, out.stdout + out.stderr
    k2 = next(x for x in out.stdout.splitlines() if x.startswith("RULE\tK2"))
    assert "套用 1 列" in k2 and "標記：K3 1、K4 3" in k2
    # 輸入改變：模組清單取自別的映像 → K2 不再套用；規則的映像不是這個 → K1 沒有生效，核心設定檢查照舊自動套用
    write_json(proj / vx.KMOD_REL, kmods(image_sha256=OTHER_IMG))
    write_json(proj / vx.RULES_REL, doc(erule("K1", "K1", images=[OTHER_IMG]), erule("K2", "K2")))
    s2 = run(proj, sc)[1]
    rs2 = {x["id"]: x for x in s2["vex"]["rules"]["rules"]}
    assert rs2["K2"]["applied"] == 0 and rs2["K1"]["applied"] == 0 and rs2["K1"]["inactive_rows"] == 3
    assert not s2["vex"]["kernel_config_via_rule"] and s2["vex"]["sources"]["kconfig"] == 2
    assert s2["vex"]["evidence_inputs"]["kernel_modules"].startswith("CRA/Config/kernel-modules.json was taken from image")


def test_report_kernel_modules_file_errors(tmp_path):
    proj, sc = ev_env(tmp_path, [erule("K2", "K2")])
    write_json(proj / vx.KMOD_REL, kmods(modules_in_image=[]))
    r, s, _ = run(proj, sc)
    assert r.returncode == 1 and "核心模組清單有錯" in r.stdout and s["status"] == "FAIL"
    # 有檔案但沒有 K2 規則：只記警告
    write_json(proj / vx.KMOD_REL, kmods())
    write_json(proj / vx.RULES_REL, doc(erule("K1", "K1")))
    s = run(proj, sc)[1]
    assert any("只給 vex-rules.json 的證據規則 K2 用" in w for w in s["config_warnings"])


def test_report_without_rules_is_unchanged_by_evidence_inputs(tmp_path):
    """沒有證據規則時：核心設定照舊是來源 (c)，模組對應的檔案不改任何判定。"""
    proj, sc = ev_env(tmp_path, [])
    (proj / vx.RULES_REL).unlink()
    (proj / vx.KMOD_REL).unlink()
    s = run(proj, sc)[1]
    assert s["vex"]["sources"]["kconfig"] == 2 and s["vex"]["sources"]["rule"] == 0 and s["vex"]["markers"] == {}
    assert s["vex"]["evidence_inputs"] is None


# ---------- 照抄範例規則檔：證據規則（責任人是佔位字）不改任何輸出 ----------

def rules_independent(text):
    """去掉只描述規則檔本身的部分（規則數、SHA-256、證據規則表），其他要逐字相同。"""
    text = re.sub(r"#### Evidence rules \(not_affected from product artifacts\)\n\n.*?\n\n(?=####)", "", text, flags=re.S)
    text = re.sub(r"`CRA/Config/vex-rules.json`, \d+ rules", "`CRA/Config/vex-rules.json`, N rules", text)
    return re.sub(r"\(SHA-256 [0-9a-f]{12}\), \d+ rules\.", "(SHA-256 x), N rules.", text)


def example_noop(tmp_path, extra=None):
    """範例規則檔照抄 vs 同一個檔案拿掉證據規則：VEX 檔案逐位元組相同，文件除了規則檔的描述以外逐字相同，summary 的數字相同。"""
    ex = json.loads((HERE.parent / "vex-rules.example.json").read_text(encoding="utf-8"))
    assert any(r.get("evidence") for r in ex["rules"])
    outs = []
    for name, d in (("example", ex), ("without", dict(ex, rules=[r for r in ex["rules"] if not r.get("evidence")]))):
        proj, sc = ev_env(tmp_path / name, [])
        write_json(proj / vx.RULES_REL, d)
        if extra:
            extra(proj, sc)
        r, s, rep = run(proj, sc)
        assert r.returncode in (0, 2), r.stdout + r.stderr
        outs.append((s, {p.name: p.read_bytes() for p in rep.iterdir() if p.is_file()}))
    (s1, f1), (s2, f2) = outs
    assert sorted(f1) == sorted(f2)
    for n in ("vex.cdx.json", "vex.openvex.json"):
        assert f1[n] == f2[n], n
    # 產生時間（report.generated、產品 SBOM 的時間）每次執行不同，只把它換掉
    ts = lambda t: re.sub(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", "T", t)    # noqa: E731
    assert ts(f1["sbom.cdx.json"].decode()) == ts(f2["sbom.cdx.json"].decode())
    def norm(f, t):
        # 產品 SBOM 因為時間不同，SHA-256 也不同：換成同一個代號（其他雜湊照樣比，例如 VEX 檔案的）
        h = hashlib.sha256(f["sbom.cdx.json"]).hexdigest()
        return rules_independent(ts(t.replace(h, "SBOM-SHA").replace(h[:12], "SBOM-SHA")))
    for n in sorted(f1):
        if n.endswith(".md"):
            assert norm(f1, f1[n].decode()) == norm(f2, f2[n].decode()), n
    for k in ("counts", "vex"):
        a, b = copy.deepcopy(s1[k]), copy.deepcopy(s2[k])
        if k == "vex":
            for x in (a, b):
                x.pop("rules")
                x.pop("evidence_inputs")
        assert a == b, k
    assert s1["vex"]["sources"]["kconfig"] == 2 and not s1["vex"]["kernel_config_via_rule"]     # KEV 的列也照舊（1086）
    assert all(x["inactive"] == [f"images is still the placeholder {vx.IMAGE_PLACEHOLDER}", "no named author"]
               for x in s1["vex"]["rules"]["rules"] if x.get("evidence"))
    return s1


def test_example_rules_file_copied_as_is_changes_no_output(tmp_path):
    example_noop(tmp_path)


# ---------- 收尾：counts.epss.dt_invalid、百分位 0.0 ----------

def test_dt_epss_invalid_count_and_zero_percentile_tie(tmp_path):
    bad = [finding("libz1", "1.0-1", "CVE-2026-2001", "NVD"), finding("libz1", "1.0-1", "CVE-2026-2002", "NVD"),
           finding("libz1", "1.0-1", "CVE-2026-2003", "NVD")]
    bad[0]["vulnerability"].update(epssScore=1.5, epssPercentile=float("nan"))
    bad[1]["vulnerability"].update(epssScore="0.5", epssPercentile=0.4)
    bad[2]["vulnerability"].update(epssScore=float("inf"))
    assert cra.dt_epss_invalid(bad) == 4 and cra.dt_epss_invalid(None) == 0 and cra.dt_epss_invalid(FINDINGS) == 0
    r, s, rep = run(make_project(tmp_path / "p"), make_scan(tmp_path / "s", findings=FINDINGS + bad))
    assert s["counts"]["epss"]["dt_invalid"] == 4
    assert "4 EPSS values from Dependency-Track were not used" in (rep / "risk-assessment.md").read_text(encoding="utf-8")
    # 同機率時百分位 0.0 不能被當成沒有：0.0 勝過 None
    assert cra.pct_key(0.0) > cra.pct_key(None) and cra.pct_key(0.0) == 0.0
    tie = [finding("liba1", "1.0-1", "CVE-2026-3001", "NVD"), finding("libb1", "1.0-1", "CVE-2026-3001", "NVD"),
           finding("libc1", "1.0-1", "CVE-2026-3001", "NVD")]
    tie[0]["vulnerability"].update(epssScore=0.2, epssPercentile=0.0)
    tie[1]["vulnerability"].update(epssScore=0.2)
    pol = cra.policy_of(cra.load_config(make_project(tmp_path / "q"), None)[0])
    for order in (tie, list(reversed(tie[:2])) + tie[2:]):
        rows = cra.build_rows(copy.deepcopy(order), pol, {}, False)
        c = next(x for x in rows if x["component"] == "libc1")
        assert c["epss_other"] == [{"source": "same CVE", "cve": "CVE-2026-3001", "probability": 0.2, "percentile": 0.0, "date": None}]


def test_must_assess_scope_counts_evidence_rules_like_other_automatic_sources():
    ev = {"source": "rule", "state": "not_affected", "evidence": "K2", "detail": "x"}
    assert cra.assessed({"vex": ev, "kev": False}) is True
    assert cra.assessed({"vex": {"source": "rule", "state": "exploitable", "rule": "R3"}, "kev": False}) is False
    assert cra.assessed({"vex": {"source": "kconfig", "state": "not_affected"}, "kev": False}) is True
    assert cra.assessed({"vex": ev, "kev": True}) is False                                   # 被利用的列只算人的判定


# ---------- 驗證回饋的修正（M1、L1–L8） ----------

def test_k2_loaded_or_unproven_removal_is_never_not_affected():
    rules = rules_of(erule("K2", "K2"))
    # 有載入的模組一定是 K3，即使它不在模組清單（不經驗證直接給 rule_ctx 的矛盾輸入）
    a = assess([krow("CVE-RM")], rules, module_map=MMAP, kernel_modules=kmods(loaded=["gone_mod", "loaded_mod"]))[0][0]
    assert a["vex"] is None and a["vex_markers"][0]["code"] == "K3" and "gone_mod (loaded)" in a["vex_markers"][0]["detail"]
    # modules.builtin 沒有收（null）：不在模組清單不等於已移除（可能編進核心）
    a = assess([krow("CVE-RM")], rules, module_map=MMAP, kernel_modules=kmods(modules_builtin=None))[0][0]
    assert a["vex"] is None and "modules.builtin was not captured" in a["vex_markers"][0]["detail"]
    # 檔案本身：有載入卻不在映像 → FAIL；loaded 是 [] → FAIL（不知道要寫 null）；modules_builtin 是 [] 或沒寫 → FAIL
    for bad, msg in ((kmods(loaded=["gone_mod"]), "有載入，卻不在 modules_in_image"), (kmods(loaded=[]), "loaded：要是不是空的文字清單"),
                     (kmods(modules_builtin=[]), "modules_builtin：要是不是空的文字清單"),
                     ({k: v for k, v in kmods().items() if k != "modules_builtin"}, "modules_builtin：必填")):
        with pytest.raises(vx.VexInputError, match=msg):
            vx.check_kernel_modules(bad)
    assert vx.check_kernel_modules(kmods(modules_builtin=None, loaded=None))


def test_strict_booleans():
    for v in (1, 0, 1.0, "true"):
        with pytest.raises(vx.VexInputError, match="modules_disabled"):
            vx.check_kernel_modules(kmods(modules_disabled=v))
    rules = rules_of(erule("K2", "K2"))
    for b in (0, 1, 0.0, None, "false"):
        mm = mmap({"CVE-X": {"modules": ["gone_mod"], "builtin": b}})
        a = assess([krow("CVE-X")], rules, module_map=mm, kernel_modules=kmods())[0][0]
        assert a["vex"] is None and a["vex_markers"][0]["code"] == "K4", b
    # modules_disabled 是 1（不經驗證）也不算禁止載入
    a = assess([krow("CVE-DIS")], rules, module_map=MMAP, kernel_modules=kmods(modules_disabled=1))[0][0]
    assert a["vex"] is None


def test_markers_once_per_row_counted_by_rows_and_dropped_when_decided():
    allr, conf, info = assess([krow("CVE-NOMAP"), krow("CVE-LD")], rules_of(erule("K2a", "K2"), erule("K2b", "K2")),
                              module_map=MMAP, kernel_modules=kmods())
    assert [[m["code"] for m in r["vex_markers"]] for r in allr] == [["K4"], ["K3"]]
    g = vx.gate(allr, conf, grype_checked=True, not_assessed=[])
    assert g["untriaged_markers"] == info["markers"] == {"K3": 1, "K4": 1}
    assert summary_of(info, "K2a")["markers"] == {"K3": 1, "K4": 1} and summary_of(info, "K2b")["markers"] == {}
    # K2 在 K1 前面：K1 判定的列拿掉 K4 標記；match 規則判定的列拿掉 K3 標記。文件的句子、閘門、規則統計一致
    rs = rules_of(erule("K2", "K2"), erule("K1", "K1"), rule("R2", "kernel", state="exploitable", response=("can_not_fix",), detail="x {cve}",
                                                             fix_state=["not-fixed"]))
    allr, conf, info = assess([krow("CVE-K1"), krow("CVE-LD", fix_state="not-fixed"), krow("CVE-NOMAP")], rs, KCFG,
                              module_map=MMAP, kernel_modules=kmods())
    r = by_id(allr)
    assert r["CVE-K1"]["vex"]["rule"] == "K1" and not r["CVE-K1"]["vex_markers"]
    assert r["CVE-LD"]["vex"]["rule"] == "R2" and not r["CVE-LD"]["vex_markers"] and vx.label(r["CVE-LD"]) == "exploitable (rule R2)"
    assert info["markers"] == {"K4": 1} and summary_of(info, "K2")["markers"] == {"K4": 1}
    assert vx.gate(allr, conf, grype_checked=True, not_assessed=[])["untriaged_markers"] == {"K4": 1}


def test_effective_date_and_image_hash_are_required():
    rows = [krow("CVE-K1")]
    for c, why in (({"today": None}, "no report date: the effective date cannot be checked"),
                   ({"image_ids": []}, "the scan has no image hash (meta.json)")):
        a, _, info = assess(rows, rules_of(erule("K1", "K1")), KCFG, **c)
        assert summary_of(info, "K1")["inactive"] == [why] and a[0]["vex"]["source"] == "kconfig"      # 照舊是自動的來源 (c)
        assert not info["kernel_config_via_rule"]


def test_example_image_placeholder():
    ex = json.loads((HERE.parent / "vex-rules.example.json").read_text(encoding="utf-8"))
    assert all(r["images"] == [vx.IMAGE_PLACEHOLDER] for r in ex["rules"] if r.get("evidence"))
    vx.check_rules(ex)                                                    # 責任人是佔位字：格式正確（規則不生效）
    with pytest.raises(vx.VexInputError) as e:
        vx.check_rules(dict(ex, author="王小明"))
    assert f"還是範例的佔位字 {vx.IMAGE_PLACEHOLDER}" in str(e.value) and "rules[0].images" in str(e.value)
    with pytest.raises(vx.VexInputError, match="佔位字"):
        vx.check_rules(doc(dict(erule("K1", "K1"), images=[vx.IMAGE_PLACEHOLDER])))
    eff = vx.effective_rules(dict(ex, rules=[dict(ex["rules"][0], author="(your name)")]))
    assert vx.rule_inactive(eff[0], {"images": {"ab" * 32}, "today": "2026-11-05"})[0].startswith("images is still the placeholder")
    vx.check_rules(dict(ex, author="王小明", rules=[dict(r, images=["*"]) if r.get("evidence") else r for r in ex["rules"]]))


def test_empty_rules_file_keeps_the_old_block_and_evidence_only_file_shows_its_hash(tmp_path):
    proj, sc = ev_env(tmp_path / "a", [])
    md = run(proj, sc)[2] / "risk-assessment.md"
    t = md.read_text(encoding="utf-8")
    assert "Bulk triage rules: `CRA/Config/vex-rules.json`, 0 rules" in t and "#### Bulk triage rules\n\n`CRA/Config/vex-rules.json` (SHA-256 " in t
    assert "#### Evidence rules" not in t
    proj, sc = ev_env(tmp_path / "b", [erule("K2", "K2")])
    r, s, rep = run(proj, sc)
    t = (rep / "risk-assessment.md").read_text(encoding="utf-8")
    assert f"#### Evidence rules (not_affected from product artifacts)\n\n`CRA/Config/vex-rules.json` (SHA-256 {s['vex']['rules']['sha256'][:12]}), 1 rules." in t
    assert "#### Bulk triage rules" not in t


def test_manual_exploitation_evidence_excludes_rules_in_both_schemes(tmp_path):
    from test_cra_exploitation import cfg_of
    evd = {"schema": "sca-center-exploitation-evidence/1",
           "evidence": [{"cve": "CVE-2025-0104", "source": "vendor advisory", "date": "2026-10-20", "owner": "PSIRT lead", "note": "x"}]}
    for scheme in (None, "exploitation"):
        proj, sc = ev_env(tmp_path / str(scheme), [erule("K2", "K2")])
        if scheme:
            write_json(proj / "CRA" / "Config" / "config.json", cfg_of(scheme=scheme))
        write_json(proj / "CRA" / "Config" / "exploitation-evidence.json", evd)
        r, s, rep = run(proj, sc)
        assert r.returncode in (0, 2), r.stdout + r.stderr
        k2 = next(x for x in s["vex"]["rules"]["rules"] if x["id"] == "K2")
        assert k2["applied"] == 0 and k2["excluded_kev"] == 1, scheme                 # CVE-2025-0104：模組已移除，但有被利用的證據
        cdx = json.loads((rep / "vex.cdx.json").read_text(encoding="utf-8"))
        # 規則沒有套用 → 這一列沒有判定：沒有 not_affected 陳述；A4（M7c-1）起寫成 in_triage 加 NOT_ASSESSED（沒有評估）
        assert [(x["analysis"]["state"], "dumpling:assessment" in json.dumps(x)) for x in cdx["vulnerabilities"] if x["id"] == "CVE-2025-0104"] == [("in_triage", True)]


# ---------- 審查：M1（名稱要在建置的 modules.order）、L1、L2、L4、L6 ----------

def test_k2_removed_needs_the_name_in_the_builds_modules_order():
    rules = rules_of(erule("K2", "K2"))
    # 打錯字的模組名稱（不在 modules.order）：不能判「已移除」→ K4
    mm = mmap({"CVE-RM": {"modules": ["no_such_module_typo"], "builtin": False}}, order=["gone_mod", "kept_mod"])
    allr, _, info = assess([krow("CVE-RM")], rules, module_map=mm, kernel_modules=kmods())
    assert allr[0]["vex"] is None and [m["code"] for m in allr[0]["vex_markers"]] == ["K4"]
    assert "no_such_module_typo not in modules.order of this kernel build" in allr[0]["vex_markers"][0]["detail"]
    # 名稱在 modules.order、不在映像：已移除
    ok = mmap({"CVE-RM": {"modules": ["gone_mod"], "builtin": False}}, order=["gone_mod", "kept_mod"])
    assert assess([krow("CVE-RM")], rules, module_map=ok, kernel_modules=kmods())[0][0]["vex"]["justification"] == "code_not_present"
    # modules_order 是 null、沒有這個鍵、格式不對 → 一律 K4（被禁止載入、已載入的也一樣：名稱沒有確認）
    for order in ("none", ["ok", 3], "gone_mod"):
        for cve, mod in (("CVE-RM", "gone_mod"), ("CVE-BLK", "blocked-mod"), ("CVE-LD", "loaded_mod")):
            m = mmap({cve: {"modules": [mod], "builtin": False}}, order=order)
            a = assess([krow(cve)], rules, module_map=m, kernel_modules=kmods())[0][0]
            assert a["vex"] is None and [x["code"] for x in a["vex_markers"]] == ["K4"], (order, cve)
    m = mmap({"CVE-RM": {"modules": ["gone_mod"], "builtin": False}})
    del m["modules_order"]
    assert [x["code"] for x in assess([krow("CVE-RM")], rules, module_map=m, kernel_modules=kmods())[0][0]["vex_markers"]] == ["K4"]
    # 建置的 modules.builtin 有它：編進核心，不套用（不是 K4）
    m = mmap({"CVE-RM": {"modules": ["gone_mod"], "builtin": False}}, builtin=["gone_mod"])
    allr, _, info = assess([krow("CVE-RM")], rules, module_map=m, kernel_modules=kmods())
    assert allr[0]["vex"] is None and not allr[0].get("vex_markers") and summary_of(info, "K2")["not_applied"] == {"built_in": 1}


def test_k2_inputs_name_the_module_map_and_modules_order_hashes():
    rules = rules_of(erule("K2", "K2"))
    allr, _, _ = assess([krow("CVE-RM")], rules, module_map=MMAP, kernel_modules=kmods(), module_map_sha256="c" * 64)
    assert allr[0]["vex"]["rule_inputs"] == ("kernel-modules.json SHA-256 efefefefefef; module map SHA-256 cccccccccccc; "
                                             "modules.order SHA-256 bbbbbbbbbbbb")


def test_kev_row_shows_what_the_evidence_rule_would_set():
    rules = rules_of(erule("K1", "K1"))
    allr, _, info = assess([krow("CVE-K1", kev=True), krow("CVE-K1B")], rules, KCFG, exploited=["CVE-K1B"])
    r = by_id(allr)
    for i in ("CVE-K1",):
        assert r[i]["vex"] is None
        assert "evidence rule K1 [K1] would set not_affected: " in r[i]["vex_note"] and "CONFIG_FOO is not set" in r[i]["vex_note"]
        assert "decide by hand" in r[i]["vex_note"]
    s = summary_of(info, "K1")
    assert s["excluded_kev"] == 1 and s["excluded_kev_sample"][0]["id"] == "CVE-K1" and "CONFIG_FOO" in s["excluded_kev_sample"][0]["detail"]
    # 沒有被利用的列：沒有這段說明
    allr, _, info = assess([krow("CVE-K1")], rules, KCFG)
    assert allr[0]["vex"]["source"] == "rule" and not allr[0]["vex_note"] and summary_of(info, "K1")["excluded_kev_sample"] == []


def test_k2_removed_while_kernel_config_says_affected_is_a_conflict():
    rules = rules_of(erule("K2", "K2"))
    kc = kcfg([{"cve": "CVE-RM", "decision": "affected", "detail": "CONFIG_GONE=m"}])
    allr, conf, _ = assess([krow("CVE-RM")], rules, kc, module_map=MMAP, kernel_modules=kmods())
    assert allr[0]["vex"]["state"] == "not_affected" and allr[0]["vex"]["rule"] == "K2"
    assert conf == [{"id": "CVE-RM", "component": allr[0]["component"], "version": allr[0]["version"], "used": "rule:not_affected (K2)",
                     "other": "kernel_config:affected (CVE-RM: CONFIG_GONE=m)", "human": False}]
    # kernel-config 也說 not_affected，或沒有這個 CVE：沒有衝突
    assert assess([krow("CVE-RM")], rules, kcfg([]), module_map=MMAP, kernel_modules=kmods())[1] == []


def test_kernel_row_without_cve_gets_k4():
    rules = rules_of(erule("K2", "K2"))
    allr, _, _ = assess([krow("GHSA-xxxx-yyyy-zzzz", cves=[])], rules, module_map=MMAP, kernel_modules=kmods())
    assert allr[0]["vex"] is None and [m["code"] for m in allr[0]["vex_markers"]] == ["K4"]
    assert "no CVE ID" in allr[0]["vex_markers"][0]["detail"]


def test_exploited_rows_show_the_rule_evidence_in_the_report(tmp_path):
    """L1：被利用的列不套用規則，但風險評估列出規則找到的證據（驗證代理：vex_note 本身沒有任何輸出）。"""
    proj, sc = ev_env(tmp_path, [erule("K1", "K1", images=[IMG]), erule("K2", "K2")])
    r, s, rep = run(proj, sc)
    assert r.returncode in (0, 2), r.stdout + r.stderr
    k1 = next(x for x in s["vex"]["rules"]["rules"] if x["id"] == "K1")
    assert [e["id"] for e in k1["excluded_kev_rows"]] == ["CVE-2024-1086"] and "CONFIG_X is not set" in k1["excluded_kev_rows"][0]["detail"]
    md = (rep / "risk-assessment.md").read_text(encoding="utf-8")
    assert "Exploited rows (KEV, EUVD or manual evidence) that an evidence rule would set to `not_affected`" in md
    assert any(ln.startswith("| 1 | CVE-2024-1086 |") and "K1 [K1]" in ln and "CONFIG_X is not set" in ln for ln in md.splitlines())


def test_kernel_config_conflict_only_for_the_rows_own_cve():
    """L-1：併了兩個 CVE 的列，kernel-config 只對另一個 CVE 說 affected：衝突只在拆出來的那一列，不掛在這一列名下。"""
    rules = rules_of(erule("K2", "K2"))
    kc = kcfg([{"cve": "CVE-RM", "decision": "not_affected", "detail": "x"}, {"cve": "CVE-RM2", "decision": "affected", "detail": "CONFIG_G=m"}])
    mm = mmap({"CVE-RM": {"modules": ["gone_mod"], "builtin": False}, "CVE-RM2": {"modules": ["gone_mod"], "builtin": False}})
    _, conf, _ = assess([krow("CVE-RM", cves=["CVE-RM", "CVE-RM2"])], rules, kc, module_map=mm, kernel_modules=kmods())
    assert [(c["id"], c["other"]) for c in conf] == [("CVE-RM2", "kernel_config:affected (CVE-RM2: CONFIG_G=m)")]


def test_k2_same_named_ko_anywhere_in_the_module_tree_is_present():
    """B 線③：updates/、extra/ 底下同名的 .ko 也算還在。比名稱不比路徑；對應表的 modules_present 是第二道檢查。"""
    rules = rules_of(erule("K2", "K2"))
    # kernel-modules.json 的清單有 updates/ 底下同名的模組 → 還在（沒載入、也沒被擋 → K3）
    km = kmods(modules_in_image=kmods()["modules_in_image"] + ["updates/drivers/gpu/host1x/host1x.ko"])
    mm = mmap({"CVE-H": {"modules": ["host1x"], "builtin": False}})
    a = assess([krow("CVE-H")], rules, module_map=mm, kernel_modules=km)[0][0]
    assert a["vex"] is None and [m["code"] for m in a["vex_markers"]] == ["K3"]
    # 映像清單沒有，對應表的 modules_present 有 → 不判已移除（K3）
    mm = mmap({"CVE-H": {"modules": ["host1x"], "builtin": False}}, modules_present=["host1x", "kept_mod"])
    a = assess([krow("CVE-H")], rules, module_map=mm, kernel_modules=kmods())[0][0]
    assert a["vex"] is None and a["vex_markers"][0]["code"] == "K3" and "modules_present" in a["vex_markers"][0]["detail"]
    # modules_present 是清單、沒有它 → 判已移除
    mm = mmap({"CVE-H": {"modules": ["host1x"], "builtin": False}}, modules_present=sorted(vx.norm_module(x) for x in kmods()["modules_in_image"]))
    assert assess([krow("CVE-H")], rules, module_map=mm, kernel_modules=kmods())[0][0]["vex"]["justification"] == "code_not_present"
    # 第三輪 R3-H1：modules_present 是 null、沒有這個鍵、或 modules_present_gaps 不是空的 → 第二道檢查做不了，不判已移除（K3）
    for top in ({"modules_present": None}, {"modules_present": ["kept_mod"], "modules_present_gaps": ["updates -> /opt/nothere"]},
                {"modules_present": ["kept_mod"], "modules_present_gaps": "x"}):
        mm = mmap({"CVE-H": {"modules": ["host1x"], "builtin": False}}, **top)
        a = assess([krow("CVE-H")], rules, module_map=mm, kernel_modules=kmods())[0][0]
        assert a["vex"] is None and a["vex_markers"][0]["code"] == "K3" and "cannot confirm it is absent" in a["vex_markers"][0]["detail"], top
    mm = mmap({"CVE-H": {"modules": ["host1x"], "builtin": False}})
    del mm["modules_present"]
    assert assess([krow("CVE-H")], rules, module_map=mm, kernel_modules=kmods())[0][0]["vex_markers"][0]["code"] == "K3"
    mm = mmap({"CVE-H": {"modules": ["host1x"], "builtin": False}}, modules_present=sorted(vx.norm_module(x) for x in kmods()["modules_in_image"]), modules_present_gaps=[])
    assert assess([krow("CVE-H")], rules, module_map=mm, kernel_modules=kmods())[0][0]["vex"]["justification"] == "code_not_present"


def test_k2_detail_counts_not_built_files_from_the_map_evidence():
    """B 線③ 的逐檔證據（files）：混了 not_built 與 module 時，說明多一句「另有 N 個檔沒編進這個核心」；證據沒有或格式不對 → 不寫，判定不變。"""
    rules = rules_of(erule("K2", "K2"))

    def detail(files, **extra):
        e = {"modules": ["gone_mod"], "builtin": False, "all_in_modules": True, **extra}
        if files is not None:
            e["files"] = files
        a = assess([krow("CVE-X")], rules, module_map=mmap({"CVE-X": e}), kernel_modules=kmods())[0][0]
        assert a["vex"]["state"] == "not_affected"
        return a["vex"]["detail"]
    mixed = [{"path": "drivers/x/a.c", "build": "module", "module": "gone_mod", "module_path": "drivers/x/gone_mod.ko", "in_image": False,
              "reason": "obj-m"},
             {"path": "drivers/x/b.c", "build": "not_built", "reason": "CONFIG_B is not set"},
             {"path": "drivers/x/c.c", "build": "not_built", "reason": "CONFIG_C is not set"}]
    assert "2 more file(s) changed by the fix are not built into this kernel (kernel-config)." in detail(mixed)
    for bad in (None, "x", [], [{"path": "a.c"}], [{"build": "not_built"}], [mixed[1], "b.c"], mixed[:1]):
        assert "more file(s)" not in detail(bad), bad
    # 一列多個 CVE：同一個檔只算一次；有一個 CVE 的證據格式不對就不寫
    mm = mmap({"CVE-X": {"modules": ["gone_mod"], "builtin": False, "files": mixed},
               "CVE-Y": {"modules": ["gone_mod"], "builtin": False, "files": mixed[1:2] + [{"path": "drivers/x/d.c", "build": "not_built"}]}})
    a = assess([krow("CVE-X", cves=["CVE-X", "CVE-Y"])], rules, module_map=mm, kernel_modules=kmods())[0][0]
    assert "3 more file(s)" in a["vex"]["detail"]
    mm["cves"]["CVE-Y"]["files"] = "broken"
    a = assess([krow("CVE-X", cves=["CVE-X", "CVE-Y"])], rules, module_map=mm, kernel_modules=kmods())[0][0]
    assert a["vex"]["state"] == "not_affected" and "more file(s)" not in a["vex"]["detail"]
    # builtin null（不知道）→ 對不到（K4）
    a = assess([krow("CVE-X")], rules, module_map=mmap({"CVE-X": {"modules": ["gone_mod"], "builtin": None, "files": mixed}}),
               kernel_modules=kmods())[0][0]
    assert a["vex"] is None and a["vex_markers"][0]["code"] == "K4"


def test_k2_map_entry_whose_files_contradict_builtin_false_is_not_mapped():
    """逐檔證據有 builtin 或 unknown 的檔、卻寫 builtin: false：對應表自相矛盾 → 對不到（K4），不判已移除。"""
    rules = rules_of(erule("K2", "K2"))
    for b in ("builtin", "unknown", "NOT_BUILT", "Builtin"):
        mm = mmap({"CVE-RM": {"modules": ["gone_mod"], "builtin": False,
                              "files": [{"path": "drivers/x/gone.c", "build": "module", "module": "gone_mod"},
                                        {"path": "drivers/x/core.c", "build": b}]}})
        a = assess([krow("CVE-RM")], rules, module_map=mm, kernel_modules=kmods())[0][0]
        assert a["vex"] is None and [m["code"] for m in a["vex_markers"]] == ["K4"], b
        assert f"contradicts itself for CVE-RM (builtin false, but per-file build {b})" in a["vex_markers"][0]["detail"], b


def test_k2_install_follows_kmod_first_match_with_wildcards():
    """kmod：install 的模組名稱是 fnmatch 樣式，第一條符合的生效；- 與 _ 相同。"""
    rules = rules_of(erule("K2", "K2"))

    def state(lines):
        a = assess([krow("CVE-BLK")], rules, module_map=MMAP, kernel_modules=kmods(modprobe_d=lines))[0][0]
        return (a["vex"] or {}).get("justification") or [m["code"] for m in a.get("vex_markers") or []]
    assert state(["install blocked-mod /bin/false"]) == "code_not_reachable"
    assert state(["install blocked_mod /bin/true"]) == "code_not_reachable"                     # - 與 _ 相同
    assert state(["install blocked* /bin/false"]) == "code_not_reachable"                       # 萬用字元
    assert state(["install blocked* /sbin/real-loader", "install blocked-mod /bin/true"]) == ["K3"]   # 第一條符合的是真的指令
    assert state(["install blocked-mod /bin/false", "install blocked* /sbin/real-loader"]) == "code_not_reachable"
    assert state(["install other* /sbin/x", "install blocked-mod /bin/false"]) == "code_not_reachable"    # 不符合的不算
    assert state(["install blocked-mod /bin/false --quiet"]) == ["K3"]                         # 不是單純的 /bin/false
    assert state(["blacklist blocked-mod"]) == ["K3"]                                           # 只有 blacklist：K3
    assert vx.kmod_pattern("snd-x*") == "snd_x*" and vx.kmod_pattern("a?-b") == "a?_b"



def test_k2_install_block_needs_kmods_rules_softdep_continuation_and_certain_patterns():
    """驗證：會讓 K2 誤判「被擋」的輸入一律不算被擋（K3）。"""
    rules = rules_of(erule("K2", "K2"))

    def state(lines, **km):
        a = assess([krow("CVE-BLK")], rules, module_map=MMAP, kernel_modules=kmods(modprobe_d=lines, **km))[0][0]
        return (a["vex"] or {}).get("justification") or [m["code"] for m in a.get("vex_markers") or []]
    ok = ["install blocked-mod /bin/false"]
    assert state(ok) == "code_not_reachable"
    # softdep：kmod v34 以前有 softdep 的模組會略過 install（modprobe.d 的 softdep 行，或 depmod 的 modules.softdep）
    assert state(["softdep blocked-mod pre: crc32c"] + ok) == ["K3"]
    assert state(ok, modules_softdep=[vx.SOFTDEP_HEADER, "softdep blocked_mod pre: crc32c"]) == ["K3"]
    assert state(ok, modules_softdep=[vx.SOFTDEP_HEADER, "softdep other pre: crc32c"]) == "code_not_reachable"
    assert state(ok, modules_softdep=None) == ["K3"]                       # 沒有收 modules.softdep：不認 install 的「被擋」
    # 反斜線（續行、kmod 讀檔時的 \X → X、行尾的 \\、反斜線加 CR）：只要有，install 一律不算被擋
    R = "install blocked* /sbin/real"
    for lines in (["# disable usb \\", ok[0]], ["blacklist foo \\", ok[0]], ["install other /sbin/x \\", ok[0]],
                  ["install \\", "blocked-mod /sbin/real", ok[0]], ["install blocked-mod \\", "/bin/false"],
                  ["# c \\\\", R, ok[0]], ["# c \\\r", R, ok[0]], ["ins\\tall blocked* /sbin/real", ok[0]],
                  ["install\\ blocked* /sbin/real", ok[0]], ok + ["soft\\dep blocked-mod pre: x"]):
        assert state(lines) == ["K3"], lines
    assert state(ok, modules_softdep=[vx.SOFTDEP_HEADER, "soft\\dep blocked-mod pre: x"]) == ["K3"]
    # 一個元素裡夾了換行或 CR（行尾的 CR、CRLF 照常）
    for lines in (["# c\ninstall blocked* /sbin/real", ok[0]], ["blacklist foo\ninstall blocked* /sbin/real", ok[0]],
                  ["install blocked-mod\r /bin/false"]):
        assert state(lines) == ["K3"], lines
    assert state(["install blocked-mod /bin/false\r\n"]) == "code_not_reachable"
    # 直接給 rule_ctx、modules_softdep 不是 modules.softdep：不認
    allr, _, _ = vx.assess([krow("CVE-BLK")], rules=rules,
                           rule_ctx=ctx(module_map=MMAP, kernel_modules=kmods(modprobe_d=ok, modules_softdep=[])))
    assert allr[0]["vex"] is None
    # libc fnmatch 的跳脫字元、[^…]，以及 kmod 會整行拒收的中括號：不確定 → 之後的行也不算
    assert state(["install blocked\\_mod /sbin/real"] + ok) == ["K3"]
    assert state(["install blocked[^x]mod /sbin/real"] + ok) == ["K3"]
    assert state(["install blocked[]-]mod /bin/false"]) == ["K3"]
    # 中括號：Python 的 fnmatch 和 libc 不一致（POSIX 類別、反向範圍…，以真實 modprobe 對照過）→ 一律不確定
    for pat in ("blocked[-_]mod", "blocked[!x]mod", "blo[[:lower:]]ked-mod", "blocked[.--!a-z=]mod", "blocked[]_[=]mod"):
        assert state([f"install {pat} /bin/false"]) == ["K3"], pat
        assert state([f"install {pat} /sbin/real", ok[0]]) == ["K3"], pat
        assert state(ok, modules_softdep=[vx.SOFTDEP_HEADER, f"softdep {pat} pre: x"]) == ["K3"], pat
    # 欄位只用空白與 tab 分開（NBSP 不是分隔）
    assert state(["install\u00a0blocked-mod /bin/false"]) == ["K3"]
    assert state(["install\tblocked-mod\t/bin/false"]) == "code_not_reachable"
    for bad in ("snd-[a-z]-x*", "a[[]-b", "a]b", "a[b", "a\\b"):
        assert vx.kmod_pattern(bad) is None, bad


def test_kernel_modules_softdep_field_is_validated():
    vx.check_kernel_modules(kmods(modules_softdep=None))
    vx.check_kernel_modules(kmods(modules_softdep=[vx.SOFTDEP_HEADER, "softdep a pre: b"]))
    d = kmods()
    del d["modules_softdep"]
    vx.check_kernel_modules(d)
    import pytest
    for bad in ("softdep a pre: b", [], ["softdep a pre: b"], ["kernel/x/blocked-mod.ko: kernel/y/crc32c.ko"]):
        with pytest.raises(vx.VexInputError):
            vx.check_kernel_modules(kmods(modules_softdep=bad))


def test_k2_no_conflict_when_kernel_config_is_affected_only_as_that_module():
    """kernel-config 說 affected 的唯一理由是 =m（每個有編的檔 built_as module、module 就是 K2 判的那一個）→ 不列衝突；其他照樣列。"""
    rules = rules_of(erule("K2", "K2"))

    def conf(files):
        kc = kcfg([{"cve": "CVE-RM", "decision": "affected", "detail": "built as module gone_mod", "files": files}])
        allr, conf, _ = assess([krow("CVE-RM")], rules, kc, module_map=MMAP, kernel_modules=kmods())
        assert allr[0]["vex"]["state"] == "not_affected"
        return conf
    mod = {"path": "drivers/x/gone.c", "built": True, "built_as": "module", "module": "gone-mod"}     # - 與 _ 相同
    off = {"path": "drivers/x/off.c", "built": False, "built_as": None, "module": None}
    assert conf([mod]) == [] and conf([mod, off]) == []
    for bad in ([dict(mod, module="other_mod")], [dict(mod, built_as="builtin", module=None)], [dict(mod, built_as=None, module=None)],
                [dict(mod, module=None)], [mod, {"path": "drivers/x/core.c", "built": True, "built_as": "builtin", "module": None}],
                [off], [], None):
        c = conf(bad)
        assert len(c) == 1 and c[0]["other"].startswith("kernel_config:affected"), bad


def test_k2_reader_lows_from_162_review():
    rules = rules_of(erule("K2", "K2"))
    mod = {"path": "drivers/x/gone.c", "built": True, "built_as": "module", "module": "gone_mod"}
    # 低 1：files 格式不對（不是 dict、built 不是嚴格的布林／null）→ 照樣列衝突
    for files in ([mod, {"path": "c.c", "built": 1, "built_as": "builtin"}], [mod, {"path": "c.c", "built": "true"}], [mod, "c.c"]):
        kc = kcfg([{"cve": "CVE-RM", "decision": "affected", "detail": "x", "files": files}])
        assert len(assess([krow("CVE-RM")], rules, kc, module_map=MMAP, kernel_modules=kmods())[1]) == 1, files
    # 低 2：只比這一列自己 CVE 的模組（CVE-RM 對到 gone_mod，kernel-config 卻說 blocked_mod → 列衝突）
    kc = kcfg([{"cve": "CVE-RM", "decision": "affected", "detail": "x", "files": [dict(mod, module="blocked_mod")]}])
    conf = assess([krow("CVE-RM", cves=["CVE-RM", "CVE-BLK"])], rules, kc, module_map=MMAP, kernel_modules=kmods())[1]
    assert any(c["id"] == "CVE-RM" for c in conf)
    # 低 3：kernel-modules.json 有、modules_present 卻沒有的名稱 → 兩份清單矛盾，不判已移除
    for present in ([], ["gone_mod_other"]):
        mm = mmap({"CVE-RM": {"modules": ["gone_mod"], "builtin": False}}, modules_present=present)
        a = assess([krow("CVE-RM")], rules, module_map=mm, kernel_modules=kmods())[0][0]
        assert a["vex"] is None and a["vex_markers"][0]["code"] == "K3" and "modules_present lacks" in a["vex_markers"][0]["detail"], present


def test_k2_module_outside_the_modules_dir_blocks_removed_only_for_its_name():
    """modules_outside_dirs（模組資料夾以外的 ELF 模組，例如 /opt/vendor/x.ko）：同名的模組不判「已移除」（K3）；
    不參與和對應表 modules_present 的矛盾檢查（對應表只看模組資料夾），所以其他模組照樣可以判「已移除」。"""
    rules = rules_of(erule("K2", "K2"))
    km = kmods(modules_outside_dirs=["/opt/vendor/oot/gone-mod.ko", "/opt/vendor/oot/vend.ko"])
    vx.check_kernel_modules(km)
    a = assess([krow("CVE-RM")], rules, module_map=MMAP, kernel_modules=km)[0][0]
    assert a["vex"] is None and [m["code"] for m in a["vex_markers"]] == ["K3"]
    assert "a .ko with this name exists outside the modules directory: /opt/vendor/oot/gone-mod.ko" in a["vex_markers"][0]["detail"]
    # 別的模組（vend 不在 modules_present，但只在 modules_outside_dirs）：不算矛盾，gone_mod 照樣判已移除
    km = kmods(modules_outside_dirs=["/opt/vendor/oot/vend.ko"])
    a = assess([krow("CVE-RM")], rules, module_map=MMAP, kernel_modules=km)[0][0]
    assert a["vex"]["justification"] == "code_not_present" and "removed from the image: gone_mod" in a["vex"]["detail"]
    # 對照：同一個 .ko 放進 modules_in_image（舊的寫法）→ modules_present 沒有它 → 兩份清單矛盾，每一列都不判已移除
    km = kmods(modules_in_image=kmods()["modules_in_image"] + ["/opt/vendor/oot/vend.ko"])
    a = assess([krow("CVE-RM")], rules, module_map=MMAP, kernel_modules=km)[0][0]
    assert a["vex"] is None and "modules_present lacks vend" in a["vex_markers"][0]["detail"]
    # 有載入的模組只在 modules_outside_dirs：不是矛盾
    assert vx.check_kernel_modules(kmods(modules_outside_dirs=["/opt/vendor/oot/vend.ko"], loaded=["loaded_mod", "vend"]))
    with pytest.raises(vx.VexInputError, match="有載入，卻不在 modules_in_image"):
        vx.check_kernel_modules(kmods(modules_outside_dirs=["/opt/vendor/oot/vend.ko"], loaded=["other"]))


def test_modules_outside_dirs_format():
    assert vx.check_kernel_modules(kmods(modules_outside_dirs=None))
    assert vx.check_kernel_modules(kmods(modules_outside_dirs=[]))
    for bad, msg in (("x.ko", "要是文字清單"), ([3], "要是文字清單"), (["opt/x.ko"], "絕對路徑")):
        with pytest.raises(vx.VexInputError, match=msg):
            vx.check_kernel_modules(kmods(modules_outside_dirs=bad))
