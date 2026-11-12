#!/usr/bin/env python3
"""security_findings.py：安全測試的結果（映像靜態檢查、板子上的檢查、網路掃描）整理成 CRA 文件的內容，以及人工決定檔。

cra_report.py 以檔案路徑載入這個模組（evaluate、section、document、techdoc_text、annex_evidence），寫：
  - 風險評估第 9 節 Security testing（做了什麼、工具版本與日期、各嚴重度數量、findings 表）；
  - 技術文件第 6 項的報告檔清單（路徑、日期、sha256）；
  - security-findings.md（全部 findings 一次列完：穩定的 ID、嚴重度、來源、Annex I、證據、建議處理、狀態）。
輸入：<rootfs>/image-check/image-check.json（tools/cra/image_check.py）、<rootfs>/board-test/board-test.json（tools/cra/board_import.py）。
穩定的 ID：img:<image_check 的 id>、board:<規則>[:<對象>]、net:<規則>:<埠>（每次重測都一樣，人工決定才帶得到下一次）。

人工決定檔 CRA/Config/security-findings.json（和 vex-annotations.json 一樣每次產生文件都套用）：
  {"schema": "sca-center-security-findings/1", "decisions": [{"id": "board:ssh-password-auth", "status": "accepted",
    "reason": "…", "author": "…", "date": "YYYY-MM-DD"}]}
  status：fixed｜accepted｜false_positive；accepted、false_positive 一定要有 reason；格式錯 → cra_report FAIL。
  fingerprint（decide 自動寫）：決定當時 finding 的內容（嚴重度與證據，不含結果資料夾名稱）的雜湊。內容變了（多了新的 setuid 路徑、
  新的弱演算法、PermitRootLogin 從 prohibit-password 變成 yes…）→ 決定不套用，finding 回到 open，要重新決定。
  手寫沒有 fingerprint 的決定照樣套用，但狀態 ATTENTION（要用 decide 重新加一次，綁到現在的內容）。
  沒有決定的 finding 是 open；fixed 的 finding 這次還看得到 → 仍是 open（重測沒有確認修好）；
  對不上任何 finding 的決定列為 unused（fixed 的：會報它的測試這次有跑才算重測確認）。

用法（新增或取代一筆決定；先驗證整份檔案，持有 .security-findings.json.lock 的排他鎖，寫到暫存檔再換上）：
  python3 -I security_findings.py decide --project <專案> --id <ID> --status accepted --reason "…" --author "…" [--date YYYY-MM-DD] [--replace]
  python3 -I security_findings.py check --project <專案>
  python3 -I security_findings.py list --project <專案>      （列出最近一次 CRA 文件的 findings 與狀態，挑 ID 用）
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path

SCHEMA = "sca-center-security-findings/1"
DEC_REL = Path("CRA/Config/security-findings.json")
IMAGE_SCHEMA = "sca-center-image-check/1"
BOARD_SCHEMA = "sca-center-board-test/1"
STATUSES = ("fixed", "accepted", "false_positive")
DEC_KEYS = {"id", "status", "reason", "author", "date", "fingerprint"}
FP_RE = re.compile(r"^[0-9a-f]{16}$")
TEST_OF = {"img": ("image", "image static check"), "board": ("board", "on-device check"), "net": ("network", "network scan")}
ID_RE = re.compile(r"^(?:img|board|net):[A-Za-z0-9._:@+-]{1,200}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
PLACEHOLDER = {"專案負責人", "(your name)", "to be completed", "tbd"}
SEVS = ("high", "medium", "low", "info")
ORDER = ["FAIL", "NOT_ASSESSED", "GAP", "NOT_RUN", "ATTENTION", "OK"]
SOURCE_LABEL = {"image": "image", "board": "board", "network": "network"}
TESTS = (("image", "Image static check (`image_check.py`: services, SSH, accounts, permissions, keys, ELF hardening, kernel module names in scripts in the root file system image)"),
         ("board", "On-device check (`board-on-device.sh` on a flashed board: listening ports, sshd, accounts, sysctl, firewall, updates)"),
         ("network", "Network scan (`board-from-network.sh` from another host: nmap, ssh-audit, testssl.sh)"))
LIST_MAX = 10


class SecInputError(Exception):
    pass


def worst(sts):
    sts = list(sts)
    return min(sts, key=ORDER.index) if sts else "OK"


def md(s, n=400):
    """不可信的文字放進 Markdown：去掉控制字元、< 換成 &lt;（避免被當成 HTML），限制長度。"""
    s = re.sub(r"[\x00-\x1f\x7f]", " ", str(s if s is not None else "")).replace("<", "&lt;")
    return s if len(s) <= n else s[:n - 1] + "…"


def plural(n, w, many=None):
    return f"{n} {w if n == 1 else (many or w + 's')}"


# ---------- 人工決定檔 ----------

def validate_decision(d, where):
    if not isinstance(d, dict):
        return [f"{where}：要是物件"]
    errs = [f"{where}.{k}：不認得的鍵" for k in sorted(set(d) - DEC_KEYS)]
    for k in ("id", "status", "author", "date"):
        if not isinstance(d.get(k), str) or not d[k].strip():
            errs.append(f"{where}.{k}：必填（文字）")
    if isinstance(d.get("id"), str) and d["id"].strip() and not ID_RE.match(d["id"]):
        errs.append(f"{where}.id：要是 img:…、board:… 或 net:…（安全測試 findings 的 ID）")
    if d.get("status") is not None and d.get("status") not in STATUSES:
        errs.append(f"{where}.status：只能是 {', '.join(STATUSES)}")
    if d.get("status") in ("accepted", "false_positive") and not (isinstance(d.get("reason"), str) and d["reason"].strip()):
        errs.append(f"{where}.reason：{d['status']} 一定要寫理由")
    if d.get("fingerprint") is not None and not (isinstance(d["fingerprint"], str) and FP_RE.match(d["fingerprint"])):
        errs.append(f"{where}.fingerprint：要是 16 個小寫十六進位字元（security_findings.py decide 會自動寫）")
    if d.get("reason") is not None and not isinstance(d["reason"], str):
        errs.append(f"{where}.reason：要是文字")
    if isinstance(d.get("author"), str) and d["author"].strip().lower() in PLACEHOLDER:
        errs.append(f"{where}.author：要寫負責人的名字，不能是佔位字")
    if isinstance(d.get("date"), str) and d["date"].strip():
        try:
            if not DATE_RE.match(d["date"]):
                raise ValueError
            datetime.date.fromisoformat(d["date"])
        except ValueError:
            errs.append(f"{where}.date：要是 YYYY-MM-DD")
    return errs


def check_decisions(doc, path=str(DEC_REL)):
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA or not isinstance(doc.get("decisions"), list):
        raise SecInputError(f"{path}：要是 {{\"schema\": \"{SCHEMA}\", \"decisions\": [...]}}")
    extra = set(doc) - {"schema", "decisions", "$comment"}
    errs = [f"{path}：不認得的鍵 {', '.join(sorted(extra))}"] if extra else []
    seen = {}
    for i, d in enumerate(doc["decisions"]):
        e = validate_decision(d, f"decisions[{i}]")
        errs += e
        if not e:
            if d["id"] in seen:
                errs.append(f"decisions[{i}]：和 decisions[{seen[d['id']]}] 的 id 相同（{d['id']}）")
            seen.setdefault(d["id"], i)
    if errs:
        raise SecInputError(f"{path} 不符合格式：" + "；".join(errs))
    return doc["decisions"]


def load_decisions(project):
    """回傳 ({id: 決定}, {file, sha256, count} 或 None)。檔案不存在 → ({}, None)；格式錯 → SecInputError。"""
    p = Path(project) / DEC_REL
    if not p.is_file():
        return {}, None
    raw = p.read_bytes()
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        raise SecInputError(f"{DEC_REL} 不是 JSON：{e}")
    decs = check_decisions(doc)
    return {d["id"]: d for d in decs}, {"file": str(DEC_REL), "sha256": hashlib.sha256(raw).hexdigest(), "count": len(decs)}


# ---------- 輸入 ----------

def load_input(path, schema):
    """回傳 (文件, 錯誤)。沒有路徑 → (None, None)。"""
    if path is None:
        return None, None
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as e:
        return None, f"could not be read ({type(e).__name__})"
    if not isinstance(doc, dict) or doc.get("schema") != schema or not isinstance(doc.get("findings"), list):
        return None, f"is not a {schema} file"
    return doc, None


def sev_of(s):
    return s if s in SEVS else "high"     # 不認得的嚴重度不降級


def annex_list(a):
    return sorted({x for x in a if isinstance(x, str) and re.match(r"^I-\d[a-m]?$", x)}) if isinstance(a, list) else []


def strs(v):
    return [str(x) for x in v if isinstance(x, (str, int))] if isinstance(v, list) else []


def collect(img, brd):
    """兩份輸入的 findings → 一份清單（ID 唯一；同一個 ID 出現兩次時合併證據）。"""
    out = {}

    def add(f):
        g = out.get(f["id"])
        if g is None:
            out[f["id"]] = f
        else:
            g["evidence"] += [e for e in f["evidence"] if e not in g["evidence"]]
            g["evidence_total"] = max(g["evidence_total"], len(g["evidence"]))
            if SEVS.index(f["severity"]) < SEVS.index(g["severity"]):
                g["severity"] = f["severity"]
    for f in (img or {}).get("findings") or []:
        if isinstance(f, dict) and isinstance(f.get("id"), str) and f["id"]:
            add({"id": "img:" + f["id"], "source": "image", "severity": sev_of(f.get("severity")), "title": str(f.get("title") or f["id"]),
                 "text": str(f.get("text") or ""), "annex": annex_list(f.get("annex")), "evidence": strs(f.get("evidence")),
                 "evidence_total": f.get("evidence_total") if isinstance(f.get("evidence_total"), int) else len(strs(f.get("evidence"))),
                 "action": "", "confirm": str(f.get("confirm_on_board") or "")})
    for f in (brd or {}).get("findings") or []:
        if isinstance(f, dict) and isinstance(f.get("id"), str) and re.match(r"^(?:board|net):", f["id"]):
            add({"id": f["id"], "source": "network" if f["id"].startswith("net:") else "board", "severity": sev_of(f.get("severity")),
                 "title": str(f.get("title") or f["id"]), "text": str(f.get("text") or ""), "annex": annex_list(f.get("annex")),
                 "evidence": strs(f.get("evidence")),
                 "evidence_total": f.get("evidence_total") if isinstance(f.get("evidence_total"), int) else len(strs(f.get("evidence"))),
                 "action": str(f.get("action") or ""), "confirm": str(f.get("confirm") or "")})
    for f in out.values():
        f["fingerprint"] = fingerprint(f)
    return sorted(out.values(), key=lambda f: (SEVS.index(f["severity"]), f["id"]))


def fingerprint(f):
    """finding 內容的雜湊（嚴重度、證據、證據總數）：決定只對這個內容有效。證據開頭的結果資料夾名稱（<stem>/）去掉，
    重測（新的資料夾名稱）內容相同時雜湊不變。"""
    ev = sorted({re.sub(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,150}/(?=[a-z0-9-]+\.[a-z]+: )", "", e) for e in f["evidence"]})
    raw = json.dumps({"severity": f["severity"], "evidence": ev, "total": max(f["evidence_total"], len(f["evidence"]))},
                     ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def current_runs(brd):
    """board-test.json 裡用到的結果（current）；欄位型別不對時換成空的（不讓壞掉的檔案讓 cra_report 當掉）。"""
    runs = (brd or {}).get("runs")
    out = []
    for r in runs if isinstance(runs, list) else []:
        if isinstance(r, dict) and r.get("current") is True and r.get("kind") in ("board", "network"):
            out.append(dict(r, notes=r["notes"] if isinstance(r.get("notes"), list) else [],
                            checks=r["checks"] if isinstance(r.get("checks"), dict) else {},
                            info=r["info"] if isinstance(r.get("info"), dict) else {},
                            files=r["files"] if isinstance(r.get("files"), list) else [],
                            archive=r["archive"] if isinstance(r.get("archive"), dict) else {}))
    return out


def evaluate(img_path, brd_path, decisions, dec_info, rel=lambda p: Path(p).name):
    """回傳 dict：status、reasons、findings（含 decision、state）、counts、tests、files、decisions（used／unused）、annex。
    rel：路徑 → 文件裡顯示的相對路徑。"""
    img, img_err = load_input(img_path, IMAGE_SCHEMA)
    brd, brd_err = load_input(brd_path, BOARD_SCHEMA)
    findings = collect(img, brd)
    reasons, sts = [], []
    runs = current_runs(brd)
    allruns = (brd or {}).get("runs")
    superseded = sum(1 for r in allruns if isinstance(r, dict) and not r.get("current")) if isinstance(allruns, list) else 0
    ran = {"image": img is not None, "board": any(r["kind"] == "board" for r in runs), "network": any(r["kind"] == "network" for r in runs)}
    for p, err, what in ((img_path, img_err, "image static check"), (brd_path, brd_err, "board test results")):
        if err:
            sts.append("GAP")
            reasons.append(f"{what} `{rel(p)}` {err}: its results are not included")
    if not any(ran.values()):
        sts.append("ATTENTION")
        reasons.append("security testing NOT RUN: no image static check, on-device check or network scan results were found "
                       "(this does not mean the product is secure)")
    else:
        for k, label in (("image", "image static check"), ("board", "on-device check"), ("network", "network scan")):
            if not ran[k]:
                sts.append("ATTENTION")
                reasons.append(f"{label} NOT RUN")
    if img is not None:
        ist = img.get("status")
        if ist in ("FAIL", "GAP"):
            sts.append("GAP")
            reasons.append(f"image static check status is {ist}"
                           + (" (some checks failed: results incomplete)" if ist == "FAIL" else " (the input does not look like a root file system)"))
        cov = (img.get("coverage") or {}).get("counts") if isinstance(img.get("coverage"), dict) else None
        if isinstance(cov, dict) and cov:
            sts.append("ATTENTION")
            reasons.append("image static check incomplete: " + ", ".join(f"{md(k, 60)} {v}" for k, v in sorted(cov.items()))[:300])
    bnotes = [r for r in runs if r.get("notes")]
    if bnotes:
        sts.append("ATTENTION")
        reasons.append(f"{plural(sum(len(r['notes']) for r in bnotes), 'note')} in the board test results (failed or unreadable checks, "
                       "skipped archive members; see `board-test.json`)")
    used, stale, unconfirmed, nofp = set(), [], [], []
    for f in findings:
        d = decisions.get(f["id"])
        f["decision"], f["note"] = d, None
        f["state"] = "open"
        if not d:
            continue
        if d.get("fingerprint") and d["fingerprint"] != f["fingerprint"]:
            f["note"] = "changed"           # 內容和決定當時不同：不套用
            stale.append(f["id"])
        elif d["status"] == "fixed":
            f["note"] = "unconfirmed"       # 這次的結果還看得到：重測沒有確認修好
            unconfirmed.append(f["id"])
        else:
            f["state"] = d["status"]
            used.add(f["id"])
            if not d.get("fingerprint"):
                nofp.append(f["id"])
    if nofp:
        # 手寫、沒有 fingerprint 的決定照樣套用，但對任何內容都有效（和一類問題一個 ID 的問題相同）：要重新用 decide 綁到現在的內容
        sts.append("ATTENTION")
        reasons.append(f"decision without fingerprint: re-run `decide` to bind it to the current content "
                       f"({', '.join(md(i, 120) for i in nofp[:10])}{' …' if len(nofp) > 10 else ''})")
    if stale:
        sts.append("ATTENTION")
        reasons.append(f"{plural(len(stale), 'decision')} no longer {'matches' if len(stale) == 1 else 'match'} the finding content "
                       f"(the finding changed since the decision; decide again): {', '.join(md(i, 120) for i in stale[:10])}")
    open_ = {s: sum(1 for f in findings if f["state"] == "open" and f["severity"] == s) for s in SEVS}
    if open_["high"] or open_["medium"]:
        sts.append("ATTENTION")
        reasons.append(f"open findings: high {open_['high']}, medium {open_['medium']} (decide in `{DEC_REL}`: fixed, accepted or "
                       "false_positive, with a reason)")
    # fixed：標了 fixed 但這次的結果還看得到（仍算在 open 裡）；accepted、false_positive：套用的決定
    counts = {s: {"total": sum(1 for f in findings if f["severity"] == s),
                  **{st: sum(1 for f in findings if f["severity"] == s and f["state"] == st) for st in ("open", "accepted", "false_positive")},
                  "fixed": sum(1 for f in findings if f["severity"] == s and f.get("note") == "unconfirmed")} for s in SEVS}
    unused = sorted((i, d["status"]) for i, d in decisions.items() if i not in {f["id"] for f in findings})
    tests = []
    for k, label in TESTS:
        if k == "image":
            tests.append({"key": k, "label": label, "ran": img is not None,
                          "tool": f"image_check.py {md(img.get('tool_version'), 40)}" if img else None,
                          "date": md(img.get("generated"), 40) if img else None,
                          "status": md(img.get("status"), 20) if img else None})
        else:
            rs = [r for r in runs if r["kind"] == k]
            info = [r.get("info") or {} for r in rs]
            tool = []
            for i in info:
                if k == "board":
                    sysinfo = ", ".join(x for x in (md(i.get("os"), 60) if i.get("os") else "", f"L4T {md(i.get('l4t'), 20)}" if i.get("l4t") else "") if x)
                    tool.append("board-on-device.sh (script version not recorded)" + (f"; system tested: {sysinfo}" if sysinfo else "")
                                + (f"; Lynis {md(i.get('lynis_version'), 20)} (hardening index {i.get('lynis_hardening_index')})"
                                   if i.get("lynis_version") else ""))
                else:
                    tool.append(", ".join(x for x in (f"nmap {md(i.get('nmap_version'), 20)}" if i.get("nmap_version") else "nmap (version not recorded)",
                                                       "ssh-audit" if i.get("ssh_audit_ports") else "", "testssl.sh" if i.get("testssl_ports") else "") if x))
            fail = sorted({f"{md(c, 40)} {s}" for r in rs for c, s in (r.get("checks") or {}).items() if s != "OK"})
            miss = sorted({md(m, 60) for r in rs for m in (r["info"].get("missing") if isinstance(r["info"].get("missing"), list) else [])})
            tests.append({"key": k, "label": label, "ran": bool(rs), "runs": [md(r.get("stem"), 160) for r in rs],
                          "tool": "; ".join(t for t in tool if t) or (f"board_import.py {md(brd.get('tool_version'), 40)}" if rs else None),
                          "date": ", ".join(md(r.get("time"), 40) for r in rs) or None, "checks_not_ok": fail,
                          "missing": miss})
    for t in tests:
        n = {s: sum(1 for f in findings if f["source"] == t["key"] and f["severity"] == s) for s in SEVS}
        t["counts"] = n
    files = []
    if img is not None:
        files.append({"path": rel(img_path), "date": md(img.get("generated"), 40), "sha256": sha256(img_path)})
        mdp = Path(img_path).with_name("image-check.md")
        if mdp.is_file():
            files.append({"path": rel(mdp), "date": md(img.get("generated"), 40), "sha256": sha256(mdp)})
    if brd is not None:
        files.append({"path": rel(brd_path), "date": md(brd.get("generated"), 40), "sha256": sha256(brd_path)})
        base = rel(brd_path).rsplit("board-test.json", 1)[0]
        for r in runs:
            a = r.get("archive") if isinstance(r.get("archive"), dict) else {}
            files.append({"path": f"{base}{md(r.get('stem'), 160)}/",
                          "note": f"{'on-device check' if r['kind'] == 'board' else 'network scan'}, "
                                  f"{plural(len(r.get('files') or []), 'file')}; SHA-256 of the imported archive `{md(a.get('name'), 160)}`",
                          "date": md(r.get("time"), 40), "sha256": md(a.get("sha256"), 64) or "unknown"})
    annex = {}
    for f in findings:
        for a in f["annex"]:
            m = re.match(r"^I-2([b-m])$", a)
            if m:
                c = annex.setdefault(m.group(1), {"total": 0, **{st: 0 for st in ("open",) + STATUSES}})
                c["total"] += 1
                c[f["state"]] += 1
                c["fixed"] += f.get("note") == "unconfirmed"
    return {"status": worst(sts), "reasons": reasons, "findings": findings, "counts": counts, "open": open_, "ran": ran,
            "tests": tests, "files": files, "annex": annex, "superseded": superseded,
            "decisions": {"file": dec_info["file"] if dec_info else None, "sha256": dec_info["sha256"] if dec_info else None,
                          "count": len(decisions), "used": sorted(used), "unused": [i for i, _ in unused], "unused_detail": unused,
                          "changed": stale, "fixed_not_confirmed": unconfirmed, "without_fingerprint": nofp},
            "inputs": {"image_check": {"file": rel(img_path), "sha256": sha256(img_path), "status": md(img.get("status"), 20),
                                       "tool_version": md(img.get("tool_version"), 40), "generated": md(img.get("generated"), 40)} if img else
                       ({"file": rel(img_path), "error": img_err} if img_err else None),
                       "board_test": {"file": rel(brd_path), "sha256": sha256(brd_path), "tool_version": md(brd.get("tool_version"), 40),
                                      "generated": md(brd.get("generated"), 40), "runs": [md(r.get("stem"), 160) for r in runs],
                                      "superseded_runs": superseded}
                       if brd else ({"file": rel(brd_path), "error": brd_err} if brd_err else None)}}


def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


# ---------- 文件內容（英文） ----------

def state_text(f):
    d = f.get("decision")
    if not d:
        return "open"
    s = {"false_positive": "false positive"}.get(d["status"], d["status"])
    who = f"{md(d['author'], 60)}, {d['date']}"
    if f.get("note") == "changed":
        return (f"open – the decision ({s}, {who}) was made for different content (fingerprint {d['fingerprint']}, now "
                f"{f['fingerprint']}); review and decide again")
    if f.get("note") == "unconfirmed":
        return f"open – marked fixed ({who}) but still reported by these results: fix not confirmed by a re-test"
    extra = " (no fingerprint: applies to any content of this finding)" if not d.get("fingerprint") else ""
    return f"{s} ({who}){': ' + md(d['reason'], 300) if d.get('reason') else ''}{extra}"


def annex_text(f):
    return ", ".join(f"({a[3:]})" if a.startswith("I-2") else a for a in f["annex"]) or "—"


def short(f):
    return md(f["title"], 160)


def evidence_text(f):
    ev = [md(e, 200) for e in f["evidence"][:LIST_MAX]]
    more = max(f["evidence_total"], len(f["evidence"])) - len(ev)
    return "; ".join(f"`{e.replace('`', '')}`" for e in ev) + (f"; … {more} more" if more > 0 else "") if ev else "—"


def action_text(f):
    a = md(f["action"] or f["text"], 500)
    c = md(f["confirm"], 300)
    return a + (f" Verify: {c}" if c else "")


def tests_table(res, table):
    rows = []
    for t in res["tests"]:
        if not t["ran"]:
            rows.append([t["label"], "**NOT RUN**", "—", "—", "—"])
            continue
        n = t["counts"]
        result = ", ".join(f"{n[s]} {s}" for s in SEVS if n[s]) or "no findings"
        if t.get("status"):
            result = f"status {t['status']}; {result}"
        if t.get("checks_not_ok"):
            result += "; checks not OK: " + ", ".join(t["checks_not_ok"][:8])
        if t.get("missing"):
            result += "; files missing: " + ", ".join(t["missing"][:8]) + " (not checked)"
        ran = "yes" + (f" ({', '.join(t['runs'])})" if t.get("runs") else "")
        rows.append([t["label"], ran, t["tool"] or "not recorded", t["date"] or "not recorded", result])
    return table(["Test", "Run", "Tool and version", "Date (UTC)", "Result"], rows)


def counts_table(res, table):
    c = res["counts"]
    return table(["Severity", "Total", "Open", "of them marked fixed (not confirmed)", "Accepted", "False positive"],
                 [[s, c[s]["total"], c[s]["open"], c[s]["fixed"], c[s]["accepted"], c[s]["false_positive"]] for s in SEVS])


def unused_text(res):
    u = res["decisions"]["unused_detail"]
    if not u:
        return ""
    if not any(res["ran"].values()):
        return (f"{plural(len(u), 'decision')} in `{DEC_REL}` could not be checked because no security testing results were found.")
    ran = lambda i: res["ran"].get(TEST_OF.get(i.split(":", 1)[0], ("", ""))[0], False)
    fx = [i for i, s in u if s == "fixed" and ran(i)]
    fx_not = [i for i, s in u if s == "fixed" and not ran(i)]
    other = [f"{i} ({s})" for i, s in u if s != "fixed"]
    parts = []
    if fx:
        parts.append(f"Decisions marked fixed whose finding the latest test no longer reports (fix confirmed by this re-test): "
                     f"{', '.join(md(i, 120) for i in fx[:30])}" + (" …" if len(fx) > 30 else "") + ".")
    if fx_not:
        parts.append(f"Decisions marked fixed that could not be confirmed because the test that reports them did not run: "
                     f"{', '.join(md(i, 120) for i in fx_not[:30])}" + (" …" if len(fx_not) > 30 else "") + ".")
    if other:
        parts.append(f"Decisions that match no current finding (the finding is gone or the test did not run; remove them when no longer needed): "
                     f"{', '.join(md(x, 140) for x in other[:30])}" + (" …" if len(other) > 30 else "") + ".")
    return " ".join(parts)


def section(res, table, role="manufacturer"):
    """風險評估第 9 節的內容（標題在範本裡）。role supplier：不產生技術文件（cra_report.SUPPLIER_SKIP），報告改指向供應商資料包。"""
    where = ("the reports are part of the technical documentation (Annex VII point 6, see `technical-documentation.md`). "
             if role != "supplier" else
             "a summary of the results is given to the manufacturer that integrates the product "
             "(`supplier-package/security-testing-summary.md`), for their technical documentation (Annex VII point 6). ")
    intro = ("Security testing complements the known-vulnerability scan (section 8): it checks how the shipped image and a flashed "
             "board are configured. Annex I Part II point (3) requires effective and regular tests and reviews of the product's "
             "security; " + where +
             "These are basic automated checks, not a penetration test; a test marked NOT RUN was not done, which does not mean "
             "the product passed it.")
    head = f"**Security testing status: {res['status']}**"
    reasons = "\n".join(f"- {md(r, 500)}" for r in res["reasons"]) or "- no issue recorded (OK does not mean the product is secure)"
    parts = [intro, head, reasons, "#### Tests run", tests_table(res, table)]
    if res["superseded"]:
        parts.append(f"Only the latest result per board or network target is used; {plural(res['superseded'], 'older result')} "
                     f"{'is' if res['superseded'] == 1 else 'are'} kept in `board-test/` but not counted.")
    if any(res["ran"].values()):
        parts += ["#### Findings by severity", counts_table(res, table),
                  "#### Findings",
                  (f"Every finding has a stable ID that is the same in every re-test. Decisions (`fixed`, `accepted`, `false_positive`, "
                   f"with a reason, owner and date) are recorded in `{DEC_REL}` and carried to later releases; a finding without a "
                   "decision is open. The evidence and recommended action for each finding are in `security-findings.md`."),
                  table(["ID", "Severity", "Source", "Annex I", "Finding", "Status"],
                        [[f"`{f['id']}`", f["severity"], SOURCE_LABEL[f["source"]], annex_text(f), short(f), state_text(f)]
                         for f in res["findings"]])]
    u = unused_text(res)
    if u:
        parts.append(u)
    return "\n\n".join(parts)


def techdoc_text(res):
    """技術文件第 6 項的一段（清單項目，後面接報告檔）。"""
    head = (f"Security testing (image static check, on-device check, network scan): `risk-assessment.md`, section 9; status "
            f"**{res['status']}**; open findings: high {res['open']['high']}, medium {res['open']['medium']}, low {res['open']['low']} "
            "(full list: `security-findings.md`).")
    if not res["files"]:
        return head + " No security test reports were found (NOT RUN)."
    return head + " Reports:\n" + "\n".join(f"  - `{x['path']}`" + (f" ({x['note']})" if x.get("note") else "")
                                            + f", {x['date'] or 'date not recorded'}, SHA-256 `{x['sha256']}`" for x in res["files"])


def annex_evidence(res):
    """Annex I (b)–(m)：{字母: 一句證據}（只有有 findings 的項目）。"""
    out = {}
    for x, c in res["annex"].items():
        out[x] = (f"Security testing (section 9): {plural(c['total'], 'finding')} (open {c['open']}"
                  + (f", of them marked fixed but still reported {c['fixed']}" if c["fixed"] else "")
                  + f", accepted {c['accepted']}, false positive {c['false_positive']}); see `security-findings.md`.")
    return out


def document(res, product, generated, table):
    """security-findings.md 全文。"""
    parts = [f"# Security findings – {md(product, 200)}",
             (f"> DRAFT generated by sca-center tools/cra/cra_report.py on {generated}. Consolidated list of the findings of the "
              "security tests (Annex I Part II point (3); Annex VII point 6): the image static check, the on-device check and the "
              "network scan. Each finding is listed once with a stable ID. Record a decision (`fixed`, `accepted` or "
              f"`false_positive`, with a reason, owner and date) in `{DEC_REL}` (`tools/cra/security_findings.py decide`); "
              "a finding without a decision is open. Evidence lists file paths and ports only. Review before use."),
             f"**Status: {res['status']}**",
             "\n".join(f"- {md(r, 500)}" for r in res["reasons"]) or "- no issue recorded (OK does not mean the product is secure)",
             "## Tests", tests_table(res, table)]
    if res["files"]:
        parts.append("Result files: " + "; ".join(f"`{x['path']}`" for x in res["files"]) + ".")
    if not any(res["ran"].values()):
        parts.append("No security testing results were found, so there are no findings to list. This does not mean the product is "
                     "secure: run the image static check (`scan-flash-package.sh` does it) and the board checks "
                     "(`tools/demo/board-test.md`), then import the board results with `tools/demo/board-import.sh`.")
    else:
        op = [f for f in res["findings"] if f["state"] == "open"]
        parts.append(f"## Open findings ({len(op)})")
        for s in SEVS:
            fs = [f for f in op if f["severity"] == s]
            if not fs:
                continue
            parts += [f"### {s.capitalize()} ({len(fs)})",
                      table(["ID", "Source", "Annex I", "Finding", "Evidence", "Recommended action", "Status"],
                            [[f"`{f['id']}`", SOURCE_LABEL[f["source"]], annex_text(f), short(f) + ". " + md(f["text"], 500),
                              evidence_text(f), action_text(f), state_text(f)] for f in fs])]
        if not op:
            parts.append("_None._")
        dec = [f for f in res["findings"] if f["state"] != "open"]
        parts += [f"## Findings with a decision ({len(dec)})",
                  table(["ID", "Severity", "Source", "Annex I", "Finding", "Evidence", "Decision"],
                        [[f"`{f['id']}`", f["severity"], SOURCE_LABEL[f["source"]], annex_text(f), short(f), evidence_text(f), state_text(f)]
                         for f in dec])]
    u = unused_text(res)
    if u:
        parts += ["## Decisions without a matching finding", u]
    return "\n\n".join(parts) + "\n"


def summary(res):
    """summary.json 的 security_testing。"""
    return {"status": res["status"], "reasons": res["reasons"], "ran": res["ran"], "inputs": res["inputs"],
            "counts": res["counts"], "open": res["open"], "superseded_runs": res["superseded"],
            "decisions": {k: v for k, v in res["decisions"].items() if k != "unused_detail"},
            "findings": [{"id": f["id"], "severity": f["severity"], "source": f["source"], "annex": f["annex"], "status": f["state"],
                          "fingerprint": f["fingerprint"], **({"decision_note": f["note"]} if f.get("note") else {})}
                         for f in res["findings"]],
            "files": res["files"]}


# ---------- CLI ----------

class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        print(f"參數錯誤：{message}", file=sys.stderr)
        sys.exit(64)


def write_atomic(p, text):
    """寫到同資料夾的暫存檔再換上。權限沿用原檔；新檔依 umask。"""
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.exists():
        mode = stat.S_IMODE(p.stat().st_mode)
    else:
        um = os.umask(0)
        os.umask(um)
        mode = 0o666 & ~um
    fd, tmp = tempfile.mkstemp(prefix=f".{p.stem}.", dir=p.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, p)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def known_ids(project):
    """最近一次 CRA 文件（CRA/Reports/summary.json）的 findings：{id: status}；沒有時 None。"""
    p = Path(project) / "CRA" / "Reports" / "summary.json"
    try:
        s = json.loads(p.read_text(encoding="utf-8"))
        fs = s["security_testing"]["findings"]
        return {f["id"]: f for f in fs if isinstance(f, dict) and isinstance(f.get("id"), str)}
    except (OSError, ValueError, KeyError, TypeError):
        return None


def decide(a):
    import fcntl
    p = Path(a.project) / DEC_REL
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p.parent / f".{p.name}.lock", "a") as lk:
        fcntl.flock(lk, fcntl.LOCK_EX)
        return _decide(a, p)


def _decide(a, p):
    if p.is_file():
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, ValueError) as e:
            raise SecInputError(f"{p} 不是 JSON：{e}（沒有修改）")
        check_decisions(doc, str(p))
    else:
        doc = {"schema": SCHEMA, "decisions": []}
    new = {"id": a.id.strip(), "status": a.status, "author": a.author.strip(),
           "date": a.date or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")}
    if a.reason and a.reason.strip():
        new["reason"] = a.reason.strip()
    errs = validate_decision(new, "新的決定")
    if errs:
        raise SecInputError("；".join(errs) + "（沒有修改）")
    ids = known_ids(a.project)
    note = ""
    if ids is None:
        note = "；注意：沒有最近一次的 CRA/Reports/summary.json（或沒有 security_testing），沒有核對 ID 是否存在"
    elif new["id"] in ids and isinstance(ids[new["id"]].get("fingerprint"), str) and FP_RE.match(ids[new["id"]]["fingerprint"]):
        new["fingerprint"] = ids[new["id"]]["fingerprint"]     # 決定只對現在這個內容有效
    elif new["id"] not in ids:
        if not a.allow_unknown:
            raise SecInputError(f"{new['id']} 不在最近一次 CRA 文件的安全測試 findings（CRA/Reports/summary.json）；ID 拼錯？"
                                "確定要先記下（例如之後的測試才會出現）時加 --allow-unknown（沒有修改）")
        note = "；注意：這個 ID 不在最近一次的 findings"
    same = [i for i, x in enumerate(doc["decisions"]) if x["id"] == new["id"]]
    if same and not a.replace:
        x = doc["decisions"][same[0]]
        raise SecInputError(f"{new['id']} 已有決定（{x['status']}，{x['author']} {x['date']}）；要取代請加 --replace（沒有修改）")
    doc["decisions"] = sorted([x for i, x in enumerate(doc["decisions"]) if i not in same] + [new], key=lambda x: x["id"])
    check_decisions(doc, str(p))
    write_atomic(p, json.dumps(doc, ensure_ascii=False, indent=1) + "\n")
    return f"{'取代' if same else '新增'} {new['id']}（{new['status']}）；{p} 共 {len(doc['decisions'])} 筆{note}；重新產生 CRA 文件後生效"


def main(argv=None):
    ap = Parser(description="安全測試 findings 的人工決定（CRA/Config/security-findings.json）")
    sub = ap.add_subparsers(dest="cmd", required=True, parser_class=Parser)
    d = sub.add_parser("decide", help="新增（或用 --replace 取代）一筆決定")
    d.add_argument("--project", required=True)
    d.add_argument("--id", required=True, help="finding 的 ID（img:…、board:…、net:…；見 security-findings.md 或 list）")
    d.add_argument("--status", required=True, choices=STATUSES)
    d.add_argument("--reason", help="理由（英文，寫進 CRA 文件）；accepted、false_positive 必填")
    d.add_argument("--author", required=True, help="責任人")
    d.add_argument("--date", help="YYYY-MM-DD（預設今天，UTC）")
    d.add_argument("--replace", action="store_true", help="取代同一個 ID 已有的決定")
    d.add_argument("--allow-unknown", action="store_true", help="ID 不在最近一次 CRA 文件的 findings 也照樣記下")
    c = sub.add_parser("check", help="只檢查 security-findings.json 的格式")
    c.add_argument("--project", required=True)
    ls = sub.add_parser("list", help="列出最近一次 CRA 文件的安全測試 findings 與狀態")
    ls.add_argument("--project", required=True)
    a = ap.parse_args(argv)
    if not Path(a.project).is_dir():
        ap.error(f"不是資料夾：{a.project}")
    try:
        if a.cmd == "decide":
            print(f"OK\t{decide(a)}")
        elif a.cmd == "check":
            decs, info = load_decisions(a.project)
            print(f"OK\t{info['file']} 格式正確，{len(decs)} 筆" if info else f"OK\t沒有 {DEC_REL}（不需要）")
        else:
            ids = known_ids(a.project)
            if ids is None:
                print("FAIL\t沒有 CRA/Reports/summary.json 的 security_testing（先產生 CRA 文件）")
                return 1
            for i, f in ids.items():
                print(f"{i}\t{f.get('severity')}\t{f.get('source')}\t{f.get('status')}" + (f"\t{f['decision_note']}" if f.get("decision_note") else ""))
            print(f"OK\t{len(ids)} 筆")
    except (SecInputError, OSError) as e:
        print(f"FAIL\t{e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
