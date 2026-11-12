"""kernel_cna_version.py：分支修補紀錄為準（CVE-2024-50302 的寫法：第一個項目只有範圍型的 commit 紀錄，defaultStatus unaffected；
第二個項目有 semver 的分支修補「X.Y.Z <= v <= X.Y.*：unaffected」）。紀錄是測試裡自己做的。"""
import importlib.util
import os

HERE = os.path.dirname(__file__)
spec = importlib.util.spec_from_file_location("kcv_branch", os.path.join(HERE, "..", "lib", "kernel_cna_version.py"))
kcv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kcv)
SHA = "06a8fc78367d070720af960dcecec917d3ae5f3b"
V118 = kcv.parse_query("6.1.118")[0]


def record(cve, blocks):
    return {"dataType": "CVE_RECORD", "cveMetadata": {"cveId": cve, "assignerOrgId": kcv.LINUX_CNA_ORG, "state": "PUBLISHED"},
            "containers": {"cna": {"affected": blocks}}}


def commit_only(default="unaffected"):
    return {"product": "Linux", "defaultStatus": default, "versions": [
        {"version": SHA, "lessThan": "5f092a4271f6dccf88fe0d132475a17b69ef71df", "status": "affected", "versionType": "git"},
        {"version": "3.10.16", "lessThan": "3.11", "status": "affected", "versionType": "semver"}]}


def branch_block(extra=(), fix="6.1.117"):
    return {"product": "Linux", "defaultStatus": "affected", "versions": [
        {"version": "3.12", "status": "affected"}, {"version": "0", "lessThan": "3.12", "status": "unaffected", "versionType": "semver"},
        {"version": fix, "lessThanOrEqual": "6.1.*", "status": "unaffected", "versionType": "semver"},
        {"version": "6.12", "lessThanOrEqual": "*", "status": "unaffected", "versionType": "original_commit_for_fix"}, *extra]}


def test_branch_fix_record_beats_commit_only_entry():
    r = kcv.judge(V118, record("CVE-2024-80100", [commit_only(), branch_block()]))
    assert r["verdict"] == "not_affected" and r["reason"] == "branch 6.1 fixed in 6.1.117"
    assert any("6.1.117" in b for b in r["basis"])
    # 剛好是修補的版本也算
    assert kcv.judge(kcv.parse_query("6.1.117")[0], record("CVE-2024-80100", [commit_only(), branch_block()]))["verdict"] == "not_affected"
    # 比修補版本舊 → 不套用這條規則（不可以判 not_affected）
    assert kcv.judge(kcv.parse_query("6.1.116")[0], record("CVE-2024-80100", [commit_only(), branch_block()]))["verdict"] != "not_affected"


def test_branch_fix_rule_counterexamples():
    # 另一個 semver 項目說 6.1.118 受影響（真的矛盾）→ unknown
    aff = {"product": "Linux", "defaultStatus": "unaffected", "versions": [
        {"version": "6.1.100", "lessThan": "6.1.200", "status": "affected", "versionType": "semver"}]}
    assert kcv.judge(V118, record("CVE-2024-80101", [aff, branch_block()]))["verdict"] == "unknown"
    # 同一個項目的不受影響範圍內有「從這版開始有問題」（移植進穩定分支）→ unknown
    mig = branch_block([{"version": "6.1.118", "status": "affected"}])
    assert kcv.judge(V118, record("CVE-2024-80102", [commit_only(), mig]))["verdict"] == "unknown"
    # 範圍型項目之外還有 status unknown 的 semver 項目涵蓋 v → unknown
    odd = {"product": "Linux", "defaultStatus": "unaffected", "versions": [
        {"version": "6.1.100", "lessThan": "6.1.200", "status": "unknown", "versionType": "semver"}]}
    assert kcv.judge(V118, record("CVE-2024-80103", [commit_only(), odd, branch_block()]))["verdict"] == "unknown"
    # 沒有這個分支的修補紀錄 → affected（維持）
    nob = {"product": "Linux", "defaultStatus": "affected", "versions": [
        {"version": "5.10", "status": "affected"}, {"version": "0", "lessThan": "5.10", "status": "unaffected", "versionType": "semver"}]}
    assert kcv.judge(V118, record("CVE-2024-80104", [commit_only(), nob]))["verdict"] == "affected"
    # 分支修補寫在別的分支 → 不適用於 6.1.118
    other = {"product": "Linux", "defaultStatus": "affected", "versions": [
        {"version": "3.12", "status": "affected"}, {"version": "6.6.61", "lessThanOrEqual": "6.6.*", "status": "unaffected", "versionType": "semver"}]}
    assert kcv.judge(V118, record("CVE-2024-80105", [commit_only(), other]))["verdict"] == "affected"
    # 只有範圍型項目、沒有任何分支修補 → 照舊 unknown
    assert kcv.judge(V118, record("CVE-2024-80106", [commit_only()]))["verdict"] == "unknown"
