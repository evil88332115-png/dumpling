"""K1 の「規則判斷不了」を減らす 2 つの安全な規則（合成資料）：
  A 檔案不在出貨的核心原始碼樹、沒有 Makefile 規則提到它，而且 CNA 紀錄說問題比這個核心新 → 沒編（兩項證據缺一不可）；
  B arch/<其他架構>/ 底下被 #include 的 .c，#include 它的檔案也都在其他架構 → 沒編。
每項都附「不可以誤判成 not_affected」的反例。"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))
import test_kernel_config as tkc  # noqa: E402
import test_kernel_k1_improve as t1  # noqa: E402
import test_kernel_vendor_flow as tvf  # noqa: E402

kc = tkc.kc
kcv = kc.kernel_cna_version()
V = (6, 8, 12, 0)
SHA = "06a8fc78367d070720af960dcecec917d3ae5f3b"


def sem_block(intro, fixes=(), default="affected"):
    v = [{"version": intro, "status": "affected"}, {"version": "0", "lessThan": intro, "status": "unaffected", "versionType": "semver"}]
    v += [{"version": f, "lessThanOrEqual": f.rsplit(".", 1)[0] + ".*", "status": "unaffected", "versionType": "semver"} for f in fixes]
    return {"product": "Linux", "vendor": "Linux", "defaultStatus": default, "versions": v}


def range_only_block():
    return {"product": "Linux", "vendor": "Linux", "defaultStatus": "unaffected",
            "versions": [{"version": SHA, "lessThan": "5f092a4271f6dccf88fe0d132475a17b69ef71df", "status": "affected", "versionType": "git"}]}


def rec(blocks, files):
    for b in blocks:
        b["programFiles"] = files
    return {"dataType": "CVE_RECORD", "cveMetadata": {"cveId": "CVE-2024-1", "assignerOrgId": tkc.ORG, "state": "PUBLISHED"},
            "containers": {"cna": {"affected": blocks}}}


# ---------- introduced_after ----------

def test_introduced_after():
    assert kcv.introduced_after(V, rec([range_only_block(), sem_block("6.10", ["6.11.2"])], []))[0] is True
    assert kcv.introduced_after(V, rec([sem_block("6.10")], []))[1] == "6.10"
    # 6.8 之前就有的問題 → False（即使 6.8.12 已修好）
    assert kcv.introduced_after(V, rec([sem_block("6.1", ["6.8.5"])], []))[0] is False
    # 同一個核心分支「從這版開始」6.8.3 → 不是更新的
    assert kcv.introduced_after(V, rec([sem_block("6.8.3")], []))[0] is False
    # semver 項目說 v 受影響 → False
    aff = {"product": "Linux", "defaultStatus": "unaffected", "versions": [
        {"version": "6.8.1", "lessThan": "6.9", "status": "affected", "versionType": "semver"}]}
    assert kcv.introduced_after(V, rec([aff, sem_block("6.10")], []))[0] is False
    # 舊分支有受影響的範圍（問題在 5.15 就有）→ False
    old = {"product": "Linux", "defaultStatus": "unaffected", "versions": [
        {"version": "5.15.10", "lessThan": "5.15.50", "status": "affected", "versionType": "semver"}]}
    assert kcv.introduced_after(V, rec([old, sem_block("6.10")], []))[0] is False
    # 只有範圍型項目、沒有 not_affected 的項目 → False
    assert kcv.introduced_after(V, rec([range_only_block()], []))[0] is False
    # 沒有 semver 的受影響版本 → False；看不懂的紀錄 → False
    assert kcv.introduced_after(V, rec([{"product": "Linux", "defaultStatus": "unaffected", "versions": []}], []))[0] is False
    assert kcv.introduced_after(V, {"containers": 3})[0] is False and kcv.introduced_after(V, None)[0] is False
    # 看不懂的範圍 → False
    odd = sem_block("6.10")
    odd["versions"].append({"version": "6.11", "lessThan": "x", "status": "affected", "versionType": "semver"})
    assert kcv.introduced_after(V, rec([odd], []))[0] is False


# ---------- A：不在樹裡 ＋ 問題比核心新 ----------

NEW = "drivers/foo/newthing.c"             # 這棵樹沒有、Makefile 也沒有
TREE_PLUS = dict(tvf.TREE_FILES)


def new_code_run(tmp_path, recs, tree_files=None, link=None, sub_tree=True):
    tree = tvf.write_tree(tmp_path / "tree", tree_files or TREE_PLUS)
    if link:
        os.symlink("foo", tree / link)                                   # 資料夾連結：名稱清單不能證明連結底下沒有這個檔案
    mirror = t1.full_mirror(tmp_path / "gm", recs)
    rec_dir = tkc.write_record_dir(tmp_path / "rec", tkc.record_members())
    args = ["--build-record", str(rec_dir)] + (["--source-tree", str(tree)] if sub_tree else [])
    return tkc.run(tmp_path, *args, grype_doc=tkc.grype(list(recs)), src=tvf.thin_rootfs(tmp_path) if sub_tree else
                   tkc.write_tar(tmp_path / "full.tar", tkc.rootfs_members()), mirror=mirror)


def cna_rec(cve, blocks, files):
    r = rec(blocks, files)
    r["cveMetadata"]["cveId"] = cve
    return r


def test_file_absent_from_tree_and_problem_newer_than_kernel_is_not_built(tmp_path):
    recs = {"CVE-2024-3001": cna_rec("CVE-2024-3001", [range_only_block(), sem_block("6.10", ["6.11.2"])], [NEW]),
            # 問題在 6.1 就有：檔案可能搬過家 → unknown
            "CVE-2024-3002": cna_rec("CVE-2024-3002", [sem_block("6.1", ["6.11.2"])], [NEW]),
            # 新的問題，但檔案在樹裡（Makefile 的規則提到、沒編）→ 照 Makefile 與紀錄：not_affected（與這條規則無關）
            "CVE-2024-3003": cna_rec("CVE-2024-3003", [sem_block("6.10")], ["drivers/foo/a.c"]),
            # 新的問題 + 不在樹裡的檔案 + 在樹裡有編的檔案 → affected（有編就是有編）
            "CVE-2024-3004": cna_rec("CVE-2024-3004", [sem_block("6.10")], [NEW, "drivers/foo/always.c"]),
            # 新的問題 + 不在樹裡的標頭檔 → 標頭檔不用來宣告沒編（但不在樹裡：同一規則）
            "CVE-2024-3005": cna_rec("CVE-2024-3005", [sem_block("6.10")], ["include/linux/newthing.h"]),
            # 兩個不在樹裡的檔案，其中一個的記錄沒有版本證據（semver 說 v 受影響）→ affected 或 unknown，不是 not_affected
            "CVE-2024-3006": cna_rec("CVE-2024-3006", [{"product": "Linux", "defaultStatus": "affected", "versions": [
                {"version": "6.8.1", "status": "affected"}]}], [NEW])}
    p, st, out = new_code_run(tmp_path, recs)
    assert st[1] == "OK", st
    by = t1.by_cve(out)
    assert by["CVE-2024-3001"]["decision"] == "not_affected"
    ev = by["CVE-2024-3001"]["files"][0]["evidence"]
    assert "not in the shipped kernel source tree" in ev and "introduced in 6.10" in ev
    assert by["CVE-2024-3002"]["decision"] == "unknown" and "do not show that" in by["CVE-2024-3002"]["files"][0]["evidence"]
    assert by["CVE-2024-3003"]["decision"] == "not_affected"
    assert by["CVE-2024-3004"]["decision"] == "affected"
    assert by["CVE-2024-3005"]["decision"] in ("not_affected", "unknown")
    assert by["CVE-2024-3006"]["decision"] != "not_affected"
    br = out["kernel"]["build_record"]
    assert br["file_judgements"]["absent_new_code"] >= 1 and any(l == kc.NEW_CODE_LIMITATION for l in br["limitations"])


def test_new_code_rule_needs_complete_source_tree_and_no_link_above(tmp_path):
    recs = {"CVE-2024-3011": cna_rec("CVE-2024-3011", [sem_block("6.10")], [NEW])}
    # 沒有 --source-tree：檔案名稱只來自 headers（沒有 .c）→ 不能證明檔案不在 → unknown
    p, st, out = new_code_run(tmp_path, recs, sub_tree=False)
    assert t1.by_cve(out)["CVE-2024-3011"]["decision"] == "unknown"
    assert "absent_new_code" not in out["kernel"]["build_record"]["file_judgements"]
    # 檔案路徑在樹裡的資料夾連結底下 → unknown
    sub = tmp_path / "l"
    sub.mkdir()
    p, st, out = new_code_run(sub, {"CVE-2024-3012": cna_rec("CVE-2024-3012", [sem_block("6.10")], ["drivers/linkdir/newthing.c"])},
                              link="drivers/linkdir")
    assert t1.by_cve(out)["CVE-2024-3012"]["decision"] == "unknown"
    # 沒有建置紀錄：規則不啟用
    sub2 = tmp_path / "n"
    sub2.mkdir()
    tree = tvf.write_tree(sub2 / "tree", TREE_PLUS)
    p, st, out = tkc.run(sub2, "--source-tree", str(tree), grype_doc=tkc.grype(list(recs)), src=tvf.thin_rootfs(sub2),
                         mirror=t1.full_mirror(sub2 / "gm", recs))
    assert t1.by_cve(out)["CVE-2024-3011"]["decision"] == "unknown"


# ---------- B：其他架構被 #include 的 .c ----------

def test_other_arch_included_c(tmp_path):
    inc = kc.included_c()
    only_other = next(k for k, v in inc.items() if k.startswith("arch/") and k.split("/")[1] not in ("arm64", "arm", "x86")
                      and all(x.startswith("arch/") for x in v) and all(x.split("/")[1] != "arm64" for x in v))
    m = tkc.model()
    assert m.srcarch == "arm64"
    assert kc.other_arch_included_only(m, only_other) is True
    # 本架構（arm64）的 #include 對象不豁免；有非 arch 的 #include 者不豁免；非程式檔不豁免
    arm = next((k for k in inc if k.startswith("arch/arm64/")), None)
    if arm:
        assert kc.other_arch_included_only(m, arm) is False
    mixed = next((k for k, v in inc.items() if not k.startswith("arch/") or any(not x.startswith("arch/") for x in v)), None)
    assert mixed and kc.other_arch_included_only(m, mixed) is False
    assert kc.other_arch_included_only(m, "arch/x86/foo.h") is False and kc.other_arch_included_only(m, "arch/Kconfig") is False
    # 判定：Makefile 的路徑上是 not_affected；#include 者混了其他地方的不變
    assert kc.judge_cve(m, [only_other], set())[0] == "not_affected"
    assert kc.judge_cve(m, [only_other, "drivers/foo/always.c"], set())[0] == "affected"
    if mixed and not mixed.startswith("arch/"):
        assert kc.judge_cve(m, [mixed], set())[0] != "not_affected"
