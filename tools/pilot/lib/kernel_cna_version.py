#!/usr/bin/env python3
"""kernel_cna_version.py：一個 Linux 核心版本（例如 6.1.118）受哪些 CVE 影響，只依 Linux 核心 CNA 紀錄的版本範圍判定。

用法：python3 -I kernel_cna_version.py --kernel-version <版本> (--mirror <tools/mirror/kernel-cve.sh 的輸出> [--max-age-days N] | --zip <kernel-cves.zip>)
                                      --out <結果.json> --cves-out <清單.txt> [--affected-only]
  --mirror：SOURCE＋kernel-cves.zip（vulns.git 的 cve/published/<年>/CVE-….json）。核對 SOURCE 的 zip_sha256（不符 → FAIL），
    新舊依 fetched_utc，上限 --max-age-days（預設 7；環境變數 KERNEL_CVE_MAX_AGE_DAYS，同 kernel-cve.sh --check 與 kernel_config.py）；過期 → GAP，照樣判定。
  --zip：直接給 zip（測試或手動用）；沒有 SOURCE，新舊與完整性無法核對 → GAP。
  --out：每個 CVE 的判定（affected／not_affected／unknown）、依據、programFiles（schema sca-center-kernel-cna-version/1）。
  --cves-out：每行一個 CVE，affected 與 unknown（不知道的不能從清單消失；--affected-only 只放 affected，unknown 的數量記在 gaps），
    可以直接給 kernel_config.py --cves。只有 CVE 編號，沒有註解
    （kernel_config.py 會把文字裡出現的任何 CVE 編號都當成清單）。
  stdout 一行：KERNEL-CNA-VERSION<TAB>狀態<TAB>說明。退出碼：0 已判定；3 輸入錯誤（同時印 FAIL 那一行，不寫輸出檔）。

判定（每筆紀錄只看 containers.cna.affected[] 裡 product 是 Linux 的項目；versionType 是 git 或 original_commit_for_fix 的不算 semver）：
  versionType 只認 semver 或沒有寫；status 不是 affected／unaffected 的 semver 項目涵蓋 v → unknown。
  每個 Linux 項目分開判斷，沒有任何 semver 版本的項目**整個不用**（例如只有 git commit 範圍、defaultStatus unaffected 的項目：
  用它的 defaultStatus 會變成「不受影響」，但那只是 git 範圍以外的預設值）。有 semver 版本的項目依序：
    1. 範圍：{version, lessThan, status}（version ≤ v < lessThan）、{version, lessThanOrEqual, status}（lessThanOrEqual 是 "6.1.*" 這種分支
       → 同一個分支而且 ≥ version；"*" → ≥ version；具體版本 → version ≤ v ≤ 它）。有符合的範圍：都一樣 → 那個狀態；不一樣 → unknown（矛盾）；
       不受影響的範圍裡有一個 ≤ v 的「從這版開始有問題」（例如問題被移植進穩定分支）→ unknown（矛盾）。
    2. {version, status: unaffected}（沒有範圍）：v 正好等於 version → not_affected。
    3. {version, status: affected}（沒有範圍）：問題從這個版本開始出現。v ≥ 其中任一個 → affected；v 比全部都小 → not_affected。
    4. 都沒有符合：defaultStatus（affected → affected、unaffected → not_affected、其他或沒有 → unknown）。
  幾個項目的結果：全部一樣 → 那個結果；有 affected 也有 not_affected → unknown（矛盾）；affected＋unknown → affected；
  not_affected＋unknown → unknown。沒有任何項目有 semver 資訊 → unknown（沒有 semver 資訊）。
  分支修補為準：一個項目只有範圍型（git）的受影響範圍、semver 沒有涵蓋 v（defaultStatus unaffected，單獨看是 unknown），另一個項目的 semver 明寫
  「X.Y.Z <= v <= X.Y.*：unaffected」（X.Y 等於 v 的主.次、X.Y.Z <= v）→ not_affected，理由「branch X.Y fixed in X.Y.Z」。兩邊真的矛盾（有 semver 項目判
  affected、不受影響範圍內有「從這版開始有問題」、另有其他 unknown 的原因）仍是 unknown。introduced_after()：K1 用來看「問題比核心新」。
  主線的修補（versionType original_commit_for_fix，例如 {"version": "6.12", "lessThanOrEqual": "*", "status": "unaffected"}）：
  semver 判 affected 時再看它——穩定分支從主線的 X.Y 分出來，主線修補版本 ≤ 產品核心的 主.次 版本（X.Y、X.Y.0、X.Y-rcN 都算，
  -rc 的修補 X.Y 正式版已含）→ not_affected（理由「mainline fixed in X.Y, before this branch」）；主線修補 > 主.次、分支沒有自己的修補紀錄 → 維持 affected
  （記 note）；修補版本解析不了（例如 X.Y.Z 的 Z>0）→ unknown；分支有比 v 新的修補紀錄卻說主線早就修好 → unknown（矛盾）。

限制（輸出的 limitations 也逐條列出）：
  - CNA 資料主要是 2024-02 以後核心團隊（kernel.org CNA）發的編號（含當時補發的舊年份編號）；更早由其他單位（MITRE、各發行版等）發的 CVE
    不在內，要另外用 NVD 補查。這支程式沒有補查 → 整體狀態一律 GAP。
  - 廠商核心（Android、晶片廠的 BSP 核心等）可能自己移植過修補，或沒有跟上分支的穩定版：這裡只看版本號。
  - 輸入版本的後綴（例如 -rockchip、+）不看，只取前面的數字；-rc 版本不支援（不猜它在分支的哪裡）；像發行版 ABI 的版本
    （5.15.0-125-generic、6.1.0-28-amd64）與 X.Y、X.Y.0 加後綴的版本（6.1.0-rpi7-rpi-v8：第三段不是上游的版本號）拒絕，要給上游版本。
  - 結果只對這份鏡像（commit、zip_sha256）有效；CNA 紀錄會修訂。
不可信輸入：zip 只讀進記憶體，不解開到磁碟；只收 cve/published/<年>/CVE-<年>-<數字>.json（年份要一致）的成員，路徑穿越、絕對路徑、
其他名稱、重複的名稱都拒絕並列出；單筆紀錄、全部紀錄合計、成員數都有上限，超過的拒絕並列出（也讓狀態是 GAP）。
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import stat
import sys
import zipfile

SCHEMA = "sca-center-kernel-cna-version/1"
LINUX_CNA_ORG = "f4215fc3-5b6b-47ff-a258-f7189bd81038"     # cveMetadata.assignerOrgId（kernel.org，同 kernel_config.py）
NAME_RE = re.compile(r"cve/published/(\d{4})/CVE-(\d{4})-(\d{4,})\.json")
CVE_RE = re.compile(r"CVE-(\d{4})-(\d{4,})")
MAX_RECORD = 8 << 20           # 單筆紀錄解壓後的上限（實測最大約 1 MB；同 kernel_config.py）
MAX_TOTAL = 1500 << 20         # 全部紀錄合計（同 kernel-cve.sh 的 KERNEL_CVE_MAX_UNPACKED_MB 預設）
MAX_MEMBERS = 200_000          # zip 成員數上限（2026-11 約 1.8 萬筆）
MAX_LISTED = 200               # 輸出裡每種清單最多列幾筆（數量另計）
VERSION_RE = re.compile(r"(\d{1,9})\.(\d{1,9})(?:\.(\d{1,9}))?(?:\.(\d{1,9}))?(.{0,200})", re.S)
SEMVER_TYPES = ("semver", None)  # versionType 只認 semver 或沒有寫（「從哪版開始」的項目沒有 versionType）；git、original_commit_for_fix、其他都不算
LIMITATIONS = [
    {"id": "pre-cna-cves", "status": "GAP",
     "text": "The Linux kernel CNA data mainly covers CVE IDs assigned by the kernel team (kernel.org CNA) since 2024-02, including "
             "older-year IDs it assigned at that time. CVEs assigned earlier by other organisations (MITRE, distributions, ...) are not "
             "in it and must be checked separately with NVD. This tool does not do that check, so the result is GAP."},
    {"id": "version-only", "status": "LIMIT",
     "text": "Only version numbers are compared. Vendor kernels (Android, SoC BSP kernels, ...) may carry backported fixes, or may not "
             "follow the stable branch; their real state can differ."},
    {"id": "git-ranges-ignored", "status": "LIMIT",
     "text": "Entries with versionType git are not used as semver. The mainline fix entry (original_commit_for_fix) is used only as "
             "follows when semver says affected: mainline fix <= the kernel's major.minor (including X.Y-rcN) -> not_affected (the "
             "stable branch forked from mainline after the fix); mainline fix after it and no fix record for the branch -> affected "
             "(with a note); fix version not understood -> unknown."},
    {"id": "mirror-snapshot", "status": "LIMIT",
     "text": "The result is valid only for this mirror snapshot (commit, zip_sha256); CNA records are revised over time."},
]


class InputError(Exception):
    pass


def vtuple(s):
    """'6.1.117' → (6, 1, 117, 0)；'0' → (0, 0, 0, 0)；不是數字版本 → None。"""
    if not isinstance(s, str):
        return None
    if re.fullmatch(r"\d{1,9}", s):
        return (int(s), 0, 0, 0)
    m = re.fullmatch(r"(\d{1,9})\.(\d{1,9})(?:\.(\d{1,9}))?(?:\.(\d{1,9}))?", s)
    if not m:
        return None
    return tuple(int(x) if x else 0 for x in m.groups())


def parse_query(s):
    """輸入的核心版本 → (tuple, 後綴)。-rc 與不像版本的 → InputError。"""
    m = VERSION_RE.fullmatch(s.strip()) if isinstance(s, str) else None
    if not m:
        raise InputError(f"--kernel-version 不像核心版本（要是 X.Y 或 X.Y.Z，例如 6.1.118）：{s!r}")
    suffix = m.group(5)
    if suffix and not re.match(r"[-+~_]", suffix):
        raise InputError(f"--kernel-version 的數字後面要是 - + ~ _ 開頭的後綴：{s!r}")
    if re.match(r"[-+~_]?rc\d*", suffix, re.I):
        raise InputError(f"不支援 -rc 版本（不猜它在分支的哪裡）：{s!r}")
    if re.match(r"-\d+([-.~+]|$)", suffix) or (suffix and not m.group(3)) or (suffix and m.group(3) and int(m.group(3)) == 0):
        raise InputError(f"像發行版的 ABI 版本（例如 Ubuntu 的 5.15.0-125-generic、Debian 的 6.1.0-28-amd64：第三段不是上游的版本號）：{s!r}；"
                         "請給上游的核心版本（例如 /proc/version_signature 或套件 changelog 裡的版本）。"
                         "X.Y 或 X.Y.0 加後綴（例如 Raspberry Pi 的 6.1.0-rpi7-rpi-v8）也一樣：第三段常常不是實際的穩定版號")
    return tuple(int(x) if x else 0 for x in m.groups()[:4]), suffix


def vstr(t):
    """(6, 12, 0, 0) → '6.12'；(6, 1, 117, 0) → '6.1.117'。"""
    p = list(t)
    while len(p) > 2 and p[-1] == 0:
        p.pop()
    return ".".join(str(x) for x in p)


def in_range(v, e):
    """範圍項目 → (符合與否, 說明) 或 None（範圍寫法看不懂）。"""
    start = vtuple(e.get("version"))
    if start is None:
        return None
    if "lessThan" in e:
        end = vtuple(e.get("lessThan"))
        if end is None:
            return None
        return start <= v < end, f"{e['version']} <= v < {e['lessThan']}"
    le = e.get("lessThanOrEqual")
    if le == "*":
        return v >= start, f"v >= {e['version']}"
    if isinstance(le, str) and le.endswith(".*"):
        pre = le[:-2]
        if not re.fullmatch(r"\d+(\.\d+){0,2}", pre):
            return None
        p = tuple(int(x) for x in pre.split("."))
        return v[:len(p)] == p and v >= start, f"{e['version']} <= v <= {le}"
    end = vtuple(le)
    if end is None:
        return None
    return start <= v <= end, f"{e['version']} <= v <= {le}"


STATUS = {"affected": "affected", "unaffected": "not_affected"}


GIT_DEFAULT_UNKNOWN = "defaultStatus unaffected, but the same entry has non-semver affected ranges that may cover v"


def branch_fix(v, a):
    """一個 Linux 項目裡的「分支修補」：{version: X.Y.Z, lessThanOrEqual: "X.Y.*", status: unaffected}，X.Y 等於 v 的主.次、X.Y.Z <= v
    → 回傳 X.Y.Z 字串；沒有 → None。這是 CNA 明寫「這個穩定分支從 X.Y.Z 起已修」的 semver 紀錄（不是範圍以外的預設值）。"""
    for e in a.get("versions") if isinstance(a.get("versions"), list) else []:
        if not isinstance(e, dict) or e.get("status") != "unaffected" or e.get("versionType") not in SEMVER_TYPES:
            continue
        le = e.get("lessThanOrEqual")
        t = vtuple(e.get("version"))
        if isinstance(le, str) and le == f"{v[0]}.{v[1]}.*" and t is not None and t[:2] == (v[0], v[1]) and t <= v:
            return e["version"]
    return None


def judge_block(v, a):
    """一個 Linux 項目 → (verdict 或 None（沒有 semver 資訊）, 依據清單, 被略過的主線修補版本 tuple 清單)。"""
    vers = a.get("versions") if isinstance(a.get("versions"), list) else []
    sem, mainline, other, nonsem_affected = [], [], [], False
    for e in vers:
        if not isinstance(e, dict):
            continue
        if e.get("versionType") not in SEMVER_TYPES:
            nonsem_affected = nonsem_affected or e.get("status") == "affected"
            if e.get("versionType") == "original_commit_for_fix" and e.get("status") == "unaffected":
                mainline.append(e.get("version"))          # 原文：judge() 解析（-rc 與解析不了的也要看到）
            continue
        if vtuple(e.get("version")) is None:
            continue
        (sem if e.get("status") in ("affected", "unaffected") else other).append(e)
    # status 不是 affected／unaffected（例如 unknown）的 semver 項目涵蓋 v → unknown（不能落到 defaultStatus）
    for e in other:
        r = in_range(v, e) if ("lessThan" in e or "lessThanOrEqual" in e) else (vtuple(e["version"]) == v, f"v == {e['version']}")
        if r is None or r[0]:
            return "unknown", [f"entry with status {e.get('status')!r} covers v ({r[1] if r else 'range not understood'})"], mainline
    if not sem:
        return None, [], mainline
    hits = []
    for e in sem:
        if "lessThan" in e or "lessThanOrEqual" in e:
            r = in_range(v, e)
            if r is None:       # 看不懂的範圍：不略過（略過可能落到錯的 defaultStatus）
                return "unknown", [f"range not understood: version {e.get('version')!r}, lessThan {e.get('lessThan')!r}, "
                                   f"lessThanOrEqual {e.get('lessThanOrEqual')!r}"], mainline
            if r[0]:
                hits.append((STATUS[e["status"]], f"{r[1]}: {e['status']}", e))
    singles = [e for e in sem if "lessThan" not in e and "lessThanOrEqual" not in e]
    intro = [vtuple(e["version"]) for e in singles if e["status"] == "affected"]
    if hits:
        got = {h[0] for h in hits}
        if len(got) > 1:
            return "unknown", ["conflicting ranges: " + "; ".join(h[1] for h in hits)], mainline
        # 不受影響的範圍裡有一個「從這版開始有問題」而且 ≤ v（例如問題被移植進穩定分支）→ 兩個說法矛盾，不判不受影響
        if got == {"not_affected"}:
            for h in hits:
                for t in intro:
                    rt = in_range(t, h[2])
                    if t <= v and rt and rt[0]:
                        return "unknown", [f"conflict: {h[1]}, but introduced in {vstr(t)} (<= v) inside that range"], mainline
        return got.pop(), [h[1] for h in hits], mainline
    for e in singles:
        if e["status"] == "unaffected" and vtuple(e["version"]) == v:
            return "not_affected", [f"v == {e['version']}: unaffected"], mainline
    if intro:
        lo = min(intro)
        if any(v >= t for t in intro):
            return "affected", [f"introduced in {vstr(min(t for t in intro if v >= t))}: affected"], mainline
        return "not_affected", [f"v < {vstr(lo)} (introduced in {vstr(lo)}): unaffected"], mainline
    d = a.get("defaultStatus")
    if STATUS.get(d) == "not_affected" and nonsem_affected:
        # 同一個項目裡有非 semver（git 等）的「受影響」範圍、semver 又沒有涵蓋 v：不能用 defaultStatus 判不受影響
        return "unknown", [GIT_DEFAULT_UNKNOWN], mainline
    return STATUS.get(d, "unknown"), [f"defaultStatus {d if isinstance(d, str) else 'missing'}"], mainline


def judge(v, record):
    """CNA 紀錄 → {verdict, reason, basis, programFiles, note?}。"""
    c = record.get("containers") if isinstance(record, dict) else None
    cna = c.get("cna") if isinstance(c, dict) else None
    aff = cna.get("affected") if isinstance(cna, dict) else None
    blocks = [a for a in aff if isinstance(a, dict) and a.get("product") == "Linux"] if isinstance(aff, list) else []
    files = []
    for a in blocks:
        for p in a.get("programFiles") if isinstance(a.get("programFiles"), list) else []:
            if isinstance(p, str) and p not in files:
                files.append(p)
    verdicts, basis, mainline, range_only, fixed_by = [], [], [], 0, None
    for a in blocks:
        r, b, ml = judge_block(v, a)
        mainline += ml
        if r is not None:
            verdicts.append(r)
            basis += b
            if r == "unknown" and b == [GIT_DEFAULT_UNKNOWN]:
                range_only += 1
            if r == "not_affected" and fixed_by is None:
                fixed_by = branch_fix(v, a)
    out = {"verdict": None, "reason": None, "basis": basis, "programFiles": files}
    if not blocks:
        out.update(verdict="unknown", reason="no affected[] entry with product Linux")
    elif not verdicts:
        out.update(verdict="unknown", reason="no semver information (only git or original_commit_for_fix entries)")
    else:
        s = set(verdicts)
        if s == {"affected"} or s == {"affected", "unknown"}:
            out.update(verdict="affected", reason="semver ranges")
        elif s == {"not_affected"}:
            out.update(verdict="not_affected", reason="semver ranges")
        elif s == {"not_affected", "unknown"} and range_only == verdicts.count("unknown") and fixed_by:
            # 一個項目只有非 semver 的範圍（semver 沒涵蓋 v、defaultStatus unaffected），另一個項目的 semver 分支紀錄明寫
            # 「X.Y.Z <= v <= X.Y.*：unaffected」→ 以分支紀錄為準。有矛盾就不會走到這裡：任何 semver 項目判 affected，
            # 或 unknown 有其他原因（範圍看不懂、status unknown 涵蓋 v）都照舊 unknown。
            br = f"{v[0]}.{v[1]}"
            out.update(verdict="not_affected", reason=f"branch {br} fixed in {fixed_by}",
                       basis=out["basis"] + [f"branch {br} fixed in {fixed_by} (semver unaffected {fixed_by} <= v <= {br}.*); the other entry "
                                             "only has non-semver ranges and no semver record covering v"])
        elif "affected" in s and "not_affected" in s:
            out.update(verdict="unknown", reason="entries disagree (affected and not affected)")
        else:
            out.update(verdict="unknown", reason="semver entries give no answer (defaultStatus unknown or missing)")
    if out["verdict"] == "affected" and mainline:
        out.update(mainline_rule(v, mainline, blocks, out))
    return out


def introduced_after(v, record):
    """只看 semver 的 affected 起點：所有 semver affected 版本的最小主.次都比 v 新（而且沒有項目判 v 受影響）→ (True, 最早的版本字串)；其他 → (False, None)。
    注意：這只是版本資訊，不能單獨證明「程式不在核心裡」（廠商可能移植過新程式）；K1 的規則 5-A 真正擋住誤判的是另一個條件：檔案不在出貨的原始碼樹。
    條件（全部成立）：沒有 Linux 項目判 v 受影響；每個項目不是 not_affected，就是只有 git 範圍（GIT_DEFAULT_UNKNOWN）；至少一個項目判 not_affected；
    所有 semver 的 affected 版本（「從這版開始」與 affected 範圍的起點）都有，而且最小的 主.次 比 v 的 主.次 新。看不懂的一律 (False, None)。"""
    c = record.get("containers") if isinstance(record, dict) else None
    cna = c.get("cna") if isinstance(c, dict) else None
    aff = cna.get("affected") if isinstance(cna, dict) else None
    blocks = [a for a in aff if isinstance(a, dict) and a.get("product") == "Linux"] if isinstance(aff, list) else []
    intros, any_na = [], False
    for a in blocks:
        r, b, _ = judge_block(v, a)
        if r == "affected" or (r == "unknown" and b != [GIT_DEFAULT_UNKNOWN]):
            return False, None
        any_na = any_na or r == "not_affected"
        for e in a.get("versions") if isinstance(a.get("versions"), list) else []:
            if isinstance(e, dict) and e.get("status") == "affected" and e.get("versionType") in SEMVER_TYPES:
                t = vtuple(e.get("version"))
                if t is not None:
                    intros.append(t)
    if not any_na or not intros:
        return False, None
    lo = min(intros)
    return ((lo[0], lo[1]) > (v[0], v[1])), (vstr(lo) if (lo[0], lo[1]) > (v[0], v[1]) else None)


MAINLINE_RE = re.compile(r"(\d{1,9})\.(\d{1,9})(?:\.0)?(?:-?rc\d+)?")


def mainline_fix(s):
    """主線修補的版本字串 → (主, 次)。接受 X.Y、X.Y.0、X.Y-rcN（修在 X.Y-rcN 的，X.Y 正式版已含）；其他（X.Y.Z 的 Z>0、看不懂）→ None。"""
    m = MAINLINE_RE.fullmatch(s.strip()) if isinstance(s, str) else None
    return (int(m.group(1)), int(m.group(2))) if m else None


def mainline_rule(v, mainline, blocks, out):
    """semver 判 affected 時再看主線的修補（original_commit_for_fix）。穩定分支是從主線的 X.Y 分出來的，主線在 ≤ 這個分支的 X.Y 修好的，
    分支本來就含修補 → not_affected。主線修補在這個分支之後、而且分支沒有自己的修補紀錄 → 維持 affected。修補版本解析不了 → unknown。
    分支自己有比 v 新的修補紀錄、卻又說主線早就修好 → 矛盾，unknown。"""
    branch = (v[0], v[1])
    fixes = [mainline_fix(x) for x in mainline]
    if any(f is None for f in fixes):
        return {"verdict": "unknown", "reason": "mainline fix version not understood (original_commit_for_fix)",
                "note": "original_commit_for_fix version(s) not understood: " + ", ".join(repr(x) for x in mainline[:3])}
    first = min(fixes)
    fx = f"{first[0]}.{first[1]}"
    if first <= branch:
        # 紀錄明寫「這個分支受影響」（semver 的 affected 範圍涵蓋 v，或從這個分支的某版開始受影響，例如 6.1.20 <= v <= 6.1.*）、
        # 分支又沒有自己的修補紀錄（有的話前面已判 not_affected）：問題是被移植進這個穩定分支的，主線早就修好不代表分支有修 → unknown
        for a in blocks:
            for e in a.get("versions") if isinstance(a.get("versions"), list) else []:
                if not isinstance(e, dict) or e.get("status") != "affected" or e.get("versionType") not in SEMVER_TYPES:
                    continue
                t = vtuple(e.get("version"))
                if t is None:
                    continue
                if "lessThan" in e or "lessThanOrEqual" in e:
                    r = in_range(v, e)
                    covers = bool(r and r[0])
                else:
                    covers = t[:2] == branch and t <= v
                if covers:
                    return {"verdict": "unknown",
                            "reason": "conflict: mainline fixed before this branch, but the record has an explicit affected entry for this branch and no fix for it",
                            "note": f"mainline fix in {fx}; affected entry {e.get('version')}"
                                    f"{' ..' + str(e.get('lessThan') or e.get('lessThanOrEqual')) if ('lessThan' in e or 'lessThanOrEqual' in e) else ''} "
                                    f"covers {vstr(v)} and there is no fix record for branch {branch[0]}.{branch[1]}"}
        for a in blocks:
            for e in a.get("versions") if isinstance(a.get("versions"), list) else []:
                le = e.get("lessThanOrEqual") if isinstance(e, dict) else None
                if (isinstance(e, dict) and e.get("status") == "unaffected" and e.get("versionType") in SEMVER_TYPES and isinstance(le, str)
                        and le == f"{v[0]}.{v[1]}.*" and (vtuple(e.get("version")) or (0,)) > v):
                    return {"verdict": "unknown", "reason": "conflict: mainline fixed before this branch, but the branch has a later fix record",
                            "note": f"mainline fix in {fx}; branch fix {e.get('version')} is after v"}
        return {"verdict": "not_affected", "reason": f"mainline fixed in {fx}, before this branch",
                "basis": out["basis"] + [f"mainline fixed in {fx} (original_commit_for_fix) <= branch {branch[0]}.{branch[1]}: the branch already has the fix"]}
    return {"note": f"mainline fix in {fx} (original_commit_for_fix) is after branch {branch[0]}.{branch[1]} and the record has no fix for this "
                    "branch: affected"}


# ---------- 讀鏡像 ----------

def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def open_source(mirror=None, zpath=None, max_age=7.0, now=None):
    """→ (zip 路徑, 鏡像資訊, 問題清單（造成 GAP）)。不能用 → InputError。"""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    info = {"name": None, "commit": None, "commit_date": None, "fetched_utc": None, "max_age_days": max_age,
            "zip_sha256": None, "source": None}      # 路徑只記名稱、不記年齡：同一份鏡像在別台主機、別的時間結果相同
    gaps = []
    if mirror:
        info["name"] = os.path.basename(os.path.abspath(mirror))
        sp, zp = os.path.join(mirror, "SOURCE"), os.path.join(mirror, "kernel-cves.zip")
        try:
            if not stat.S_ISREG(os.lstat(sp).st_mode):
                raise InputError("SOURCE 不是一般檔案")
            with open(sp, encoding="utf-8") as f:
                src = dict(l.split("=", 1) for l in f.read(1 << 16).splitlines() if "=" in l)
        except OSError:
            raise InputError(f"鏡像沒有 SOURCE：{mirror}")
        for k in ("commit", "commit_date", "fetched_utc", "source"):
            info[k] = src.get(k)
        try:
            if not stat.S_ISREG(os.lstat(zp).st_mode):
                raise InputError("kernel-cves.zip 不是一般檔案")
        except OSError:
            raise InputError(f"鏡像沒有 kernel-cves.zip：{mirror}")
        got = sha256_file(zp)
        if got != src.get("zip_sha256"):
            raise InputError("kernel-cves.zip 的 sha256 與 SOURCE 不符（下載不完整或被換掉）")
        info["zip_sha256"] = got
        try:
            t = datetime.datetime.fromisoformat(str(src.get("fetched_utc")).replace("Z", "+00:00"))
            if t.tzinfo is None:
                raise ValueError
            age = (now - t).total_seconds() / 86400
            if age > max_age:
                gaps.append(f"CNA mirror is stale: fetched {age:.1f} days ago > {max_age:g} days (fetched_utc={src.get('fetched_utc')})")
        except ValueError:
            gaps.append("SOURCE has no parsable fetched_utc: freshness unknown")
        return zp, info, gaps
    info["name"] = os.path.basename(zpath)
    try:
        if not stat.S_ISREG(os.lstat(zpath).st_mode):
            raise InputError(f"--zip 不是一般檔案：{zpath}")
    except OSError:
        raise InputError(f"--zip 讀不到：{zpath}")
    info["zip_sha256"] = sha256_file(zpath)
    gaps.append("--zip without SOURCE: mirror commit, freshness and integrity were not checked")
    return zpath, info, gaps


def read_records(zp, v):
    """zip → ({CVE: 判定}, 統計)。只讀進記憶體，每筆讀完就判定、只留結果（不留整份 JSON）；名稱、大小、數量不合的拒絕並列出。"""
    st = {"members": 0, "records": 0, "not_kernel_cna": 0, "not_published": 0, "rejected": 0, "rejected_examples": [],
          "unreadable": 0, "unreadable_examples": []}
    recs, total = {}, 0

    def reject(key, name, why):
        st[key] += 1
        if len(st[key + "_examples"]) < MAX_LISTED:
            st[key + "_examples"].append(f"{name!r}: {why}")
    try:
        zf = zipfile.ZipFile(zp)
    except (OSError, zipfile.BadZipFile) as e:
        raise InputError(f"kernel-cves.zip 無法讀取（{type(e).__name__}）")
    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_MEMBERS:
            raise InputError(f"zip 的成員超過 {MAX_MEMBERS} 個（{len(infos)}）：不像 kernel-cve.sh 的鏡像")
        seen = set()
        for i in infos:
            st["members"] += 1
            name = i.filename
            if i.is_dir():
                continue
            m = NAME_RE.fullmatch(name)
            if not m or m.group(1) != m.group(2):
                reject("rejected", name, "not cve/published/<year>/CVE-<year>-<n>.json (path traversal, absolute path or other name)")
                continue
            if name in seen:
                reject("rejected", name, "duplicate member name")
                if recs.pop(name.rsplit("/", 1)[1][:-5], None) is not None:
                    reject("rejected", name, "first copy of a duplicate name dropped")
                continue
            seen.add(name)
            if i.file_size > MAX_RECORD:
                reject("rejected", name, f"declared size {i.file_size} > {MAX_RECORD} bytes")
                continue
            if total + i.file_size > MAX_TOTAL:
                reject("rejected", name, f"total unpacked size would exceed {MAX_TOTAL >> 20} MB")
                continue
            try:
                with zf.open(i) as f:
                    data = f.read(MAX_RECORD + 1)
            except (OSError, zipfile.BadZipFile, EOFError, NotImplementedError, RuntimeError) as e:
                reject("unreadable", name, type(e).__name__)
                continue
            except Exception as e:          # zlib.error、lzma.LZMAError 等壞掉的壓縮資料
                reject("unreadable", name, type(e).__name__)
                continue
            if len(data) > MAX_RECORD:
                reject("rejected", name, f"unpacked size > {MAX_RECORD} bytes")
                continue
            total += len(data)
            cve = f"CVE-{m.group(2)}-{m.group(3)}"
            try:
                d = json.loads(data)
            except (ValueError, RecursionError):
                reject("unreadable", name, "not JSON")
                continue
            meta = d.get("cveMetadata") if isinstance(d, dict) else None
            if not isinstance(meta, dict) or meta.get("cveId") != cve:
                reject("unreadable", name, "cveMetadata.cveId does not match the file name")
                continue
            if meta.get("state", "PUBLISHED") != "PUBLISHED":
                st["not_published"] += 1
                continue
            if meta.get("assignerOrgId") != LINUX_CNA_ORG:
                st["not_kernel_cna"] += 1
                continue
            try:
                recs[cve] = judge(v, d)
            except (TypeError, ValueError, KeyError, AttributeError, RecursionError) as e:     # 形狀不對的紀錄：只影響這一筆
                reject("unreadable", name, f"record could not be judged ({type(e).__name__})")
            del d
    st["records"] = len(recs)
    return recs, st


def cve_key(c):
    m = CVE_RE.fullmatch(c)
    return int(m.group(1)), int(m.group(2))


def run(kernel_version, out, cves_out, mirror=None, zpath=None, max_age=7.0, affected_only=False, now=None):
    """→ (狀態, 說明)。輸入錯誤 → InputError（不寫輸出）。"""
    if os.path.abspath(out) == os.path.abspath(cves_out):
        raise InputError("--out 和 --cves-out 不能是同一個檔案")
    v, suffix = parse_query(kernel_version)
    zp, info, gaps = open_source(mirror, zpath, max_age, now)
    recs, st = read_records(zp, v)
    if not recs:
        raise InputError("zip 裡沒有任何可用的 Linux 核心 CNA 紀錄：沒有判定（不輸出空清單）")
    if st["rejected"] or st["unreadable"]:
        gaps.append(f"{st['rejected']} zip member(s) rejected and {st['unreadable']} unreadable: those CVEs were not judged")
    cves, counts = [], {"affected": 0, "not_affected": 0, "unknown": 0}
    for cve in sorted(recs, key=cve_key):
        r = recs[cve]
        counts[r["verdict"]] += 1
        cves.append({"cve": cve, **r})
    notes = list(LIMITATIONS)
    if suffix:
        notes = notes + [{"id": "suffix-ignored", "status": "LIMIT", "text": f"The version suffix {suffix!r} was ignored; only the numbers were compared."}]
    me = os.path.abspath(__file__)
    doc = {"schema": SCHEMA, "generated_utc": (now or datetime.datetime.now(datetime.timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "tool": {"name": "kernel_cna_version.py", "sha256": sha256_file(me)},
           "kernel_version": {"input": kernel_version, "compared": vstr(v), "suffix_ignored": suffix or None},
           "status": "GAP", "gaps": ["CVEs assigned before the kernel CNA (other organisations) were not checked with NVD"] + gaps,
           "mirror": info, "zip": st, "counts": counts, "limitations": notes,
           "cves_out": {"file": os.path.basename(cves_out), "includes": ["affected"] + ([] if affected_only else ["unknown"])},
           "cves": cves}
    if affected_only and counts["unknown"]:
        doc["gaps"].append(f"--affected-only: {counts['unknown']} unknown CVE(s) are not in {os.path.basename(cves_out)}")
    lst = [c["cve"] for c in cves if c["verdict"] == "affected" or (not affected_only and c["verdict"] == "unknown")]
    tmps = []
    try:                          # 兩個檔案都寫好才一起換上（中途失敗不會只留一個）
        for path, text in ((out, json.dumps(doc, ensure_ascii=False, indent=1) + "\n"), (cves_out, "".join(c + "\n" for c in lst))):
            tmp = f"{path}.tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(text)
            tmps.append((tmp, path))
        for tmp, path in tmps:
            os.replace(tmp, path)
    finally:
        for tmp, _ in tmps:
            if os.path.exists(tmp):
                os.remove(tmp)
    detail = (f"{vstr(v)}{'（後綴 ' + suffix + ' 不看）' if suffix else ''}：CNA 紀錄 {st['records']} 筆，affected {counts['affected']}、"
              f"not_affected {counts['not_affected']}、unknown {counts['unknown']}；{os.path.basename(cves_out)} {len(lst)} 個"
              f"{'（只有 affected，unknown ' + str(counts['unknown']) + ' 個沒有列）' if affected_only else '（affected＋unknown）'}；GAP：2024-02 以前其他單位發的 CVE 不在 CNA 資料裡，沒有用 NVD 補查")
    if doc["gaps"][1:]:
        detail += "；" + "；".join(doc["gaps"][1:])
    return "GAP", detail


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--kernel-version", required=True)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--mirror")
    g.add_argument("--zip")
    ap.add_argument("--max-age-days", type=float, default=None)
    ap.add_argument("--out", required=True)
    ap.add_argument("--cves-out", required=True)
    ap.add_argument("--affected-only", action="store_true", help="清單只放 affected（unknown 的數量記在 gaps）")
    a = ap.parse_args(argv)
    try:
        ma = a.max_age_days if a.max_age_days is not None else float(os.environ.get("KERNEL_CVE_MAX_AGE_DAYS") or 7)
    except ValueError:
        print("KERNEL-CNA-VERSION\tFAIL\tKERNEL_CVE_MAX_AGE_DAYS 不是數字")
        return 3
    try:
        st, msg = run(a.kernel_version, a.out, a.cves_out, a.mirror, a.zip, ma, a.affected_only)
    except InputError as e:
        print(f"KERNEL-CNA-VERSION\tFAIL\t{e}")
        return 3
    print(f"KERNEL-CNA-VERSION\t{st}\t{msg}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
