"""kernel_cna_version.py：核心版本 → 受影響的 CVE（只看 Linux 核心 CNA 紀錄的 semver 範圍）。
紀錄是測試裡自己做的，格式照真實的 CNA 紀錄（例如 CVE-2024-50264：第一個 Linux 項目只有 git 範圍、defaultStatus unaffected；
第二個項目 defaultStatus affected，有「從哪版開始」、0 到那版 unaffected、各分支修好的版本、主線的 original_commit_for_fix）。"""
import datetime
import hashlib
import importlib.util
import json
import os
import re
import zipfile

import pytest

HERE = os.path.dirname(__file__)
spec = importlib.util.spec_from_file_location("kcv", os.path.join(HERE, "..", "lib", "kernel_cna_version.py"))
kcv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kcv)
ORG = kcv.LINUX_CNA_ORG
SHA = "06a8fc78367d070720af960dcecec917d3ae5f3b"


def git_block():
    return {"product": "Linux", "vendor": "Linux", "defaultStatus": "unaffected", "programFiles": ["net/x/a.c"],
            "versions": [{"version": SHA, "lessThan": "5f092a4271f6dccf88fe0d132475a17b69ef71df", "status": "affected", "versionType": "git"}]}


def sem_block(intro, fixes, mainline, files=("net/x/a.c",)):
    v = [{"version": intro, "status": "affected"}, {"version": "0", "lessThan": intro, "status": "unaffected", "versionType": "semver"}]
    v += [{"version": f, "lessThanOrEqual": f.rsplit(".", 1)[0] + ".*", "status": "unaffected", "versionType": "semver"} for f in fixes]
    if mainline:
        v.append({"version": mainline, "lessThanOrEqual": "*", "status": "unaffected", "versionType": "original_commit_for_fix"})
    return {"product": "Linux", "vendor": "Linux", "defaultStatus": "affected", "programFiles": list(files), "versions": v}


def record(cve, blocks, org=ORG, state="PUBLISHED"):
    return {"dataType": "CVE_RECORD", "cveMetadata": {"cveId": cve, "assignerOrgId": org, "state": state},
            "containers": {"cna": {"affected": blocks}}}


RECORDS = {
    # 6.1 分支在 6.1.117 修好 → 6.1.118 不受影響
    "CVE-2024-50264": record("CVE-2024-50264", [git_block(), sem_block("4.8", ["4.19.324", "5.10.230", "6.1.117", "6.6.61"], "6.12")]),
    # 6.1 分支 6.1.142 才修好 → 6.1.118 受影響
    "CVE-2025-38001": record("CVE-2025-38001", [git_block(), sem_block("5.4", ["5.15.180", "6.1.142", "6.6.95"], "6.16",
                                                                          files=("drivers/y/b.c", "include/y/b.h"))]),
    # 6.5 才有這個問題 → 6.1 不受影響
    "CVE-2024-26600": record("CVE-2024-26600", [git_block(), sem_block("6.5", ["6.6.20"], "6.8")]),
    # 沒有 semver 資訊（只有 git 範圍）→ unknown（不能用 git 項目的 defaultStatus unaffected）
    "CVE-2024-40000": record("CVE-2024-40000", [git_block()]),
    # 6.1 分支沒有修補（只有主線 6.12 修好）→ 6.1.118 受影響
    "CVE-2024-50999": record("CVE-2024-50999", [git_block(), sem_block("5.10", [], "6.12")]),
    # 不是核心 CNA 發的、或 REJECTED：不算
    "CVE-2023-1000": record("CVE-2023-1000", [sem_block("4.0", [], None)], org="8254265b-2729-46b6-b9e3-3dfca2d5bfca"),
    "CVE-2024-41111": record("CVE-2024-41111", [sem_block("4.0", [], None)], state="REJECTED"),
}


def make_zip(path, records=RECORDS, extra=()):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for cve, r in records.items():
            y = cve.split("-")[1]
            z.writestr(f"cve/published/{y}/{cve}.json", json.dumps(r))
        for name, data in extra:
            z.writestr(name, data)
    return str(path)


def make_mirror(d, records=RECORDS, fetched=None, sha=None, extra=()):
    d.mkdir()
    zp = make_zip(d / "kernel-cves.zip", records, extra)
    h = hashlib.sha256(open(zp, "rb").read()).hexdigest()
    fetched = fetched or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    (d / "SOURCE").write_text(f"source=file:///vulns.git\ncommit={'a' * 40}\ncommit_date=2026-11-08T00:00:00Z\n"
                              f"fetched_utc={fetched}\nzip_sha256={sha or h}\nrecords={len(records)}\n")
    return str(d)


def run(tmp_path, version, **kw):
    out, lst = tmp_path / "r.json", tmp_path / "cves.txt"
    st, msg = kcv.run(version, str(out), str(lst), **kw)
    return st, msg, json.loads(out.read_text()), lst.read_text().split()


def by_cve(doc):
    return {c["cve"]: c for c in doc["cves"]}


def test_branch_fixes_and_introduced(tmp_path):
    st, msg, doc, lst = run(tmp_path, "6.1.118", mirror=make_mirror(tmp_path / "m"))
    c = by_cve(doc)
    assert c["CVE-2024-50264"]["verdict"] == "not_affected" and "6.1.117 <= v <= 6.1.*" in c["CVE-2024-50264"]["basis"][0]
    assert c["CVE-2025-38001"]["verdict"] == "affected"
    assert c["CVE-2025-38001"]["programFiles"] == ["net/x/a.c", "drivers/y/b.c", "include/y/b.h"]      # 所有 Linux 項目的聯集
    assert c["CVE-2024-26600"]["verdict"] == "not_affected" and "0 <= v < 6.5" in c["CVE-2024-26600"]["basis"][0]
    assert c["CVE-2024-40000"]["verdict"] == "unknown" and "no semver" in c["CVE-2024-40000"]["reason"]
    assert c["CVE-2024-50999"]["verdict"] == "affected" and "after branch" in c["CVE-2024-50999"]["note"]
    assert "CVE-2023-1000" not in c and "CVE-2024-41111" not in c
    assert doc["zip"]["not_kernel_cna"] == 1 and doc["zip"]["not_published"] == 1
    # 清單：affected＋unknown（不知道的不能消失），依年份與編號排序，只有 CVE 編號（kernel_config.py --cves 用 CVE_RE.finditer 讀）
    assert lst == ["CVE-2024-40000", "CVE-2024-50999", "CVE-2025-38001"]
    assert doc["counts"] == {"affected": 2, "not_affected": 2, "unknown": 1}
    # 限制：一律 GAP（2024-02 以前其他單位發的 CVE 沒有用 NVD 補查），也列在輸出裡
    assert st == "GAP" and doc["status"] == "GAP" and "NVD" in msg
    assert {x["id"] for x in doc["limitations"]} >= {"pre-cna-cves", "version-only"}
    assert doc["mirror"]["commit"] == "a" * 40 and re.fullmatch(r"[0-9a-f]{64}", doc["mirror"]["zip_sha256"])
    assert doc["mirror"]["name"] == "m" and "path" not in doc["mirror"] and "age_days" not in doc["mirror"]


def test_fixed_version_boundaries(tmp_path):
    m = make_mirror(tmp_path / "m")
    for v, want in (("6.1.116", "affected"), ("6.1.117", "not_affected"), ("6.6.60", "affected"), ("6.6.61", "not_affected"),
                    ("4.7", "not_affected"), ("4.8", "affected"), ("5.10.229", "affected")):
        d = tmp_path / v
        d.mkdir()
        _, _, doc, _ = run(d, v, mirror=m)
        assert by_cve(doc)["CVE-2024-50264"]["verdict"] == want, v


def mainline_only(cve, intro, mainline, extra=()):
    """分支沒有自己的修補紀錄：只有「從哪版開始」和主線的修補。"""
    return {cve: record(cve, [git_block(), sem_block(intro, list(extra), mainline)])}


@pytest.mark.parametrize("fix,version,verdict,why", [
    ("5.0", "6.1.118", "not_affected", "mainline fixed in 5.0, before this branch"),        # 主線修補 < 主.次
    ("6.1", "6.1.118", "not_affected", "mainline fixed in 6.1, before this branch"),        # = 主.次
    ("6.1-rc3", "6.1.118", "not_affected", "mainline fixed in 6.1, before this branch"),    # 修在 6.1-rc3，6.1 正式版已含
    ("6.1.0", "6.1.118", "not_affected", "mainline fixed in 6.1, before this branch"),
    ("6.2-rc1", "6.1.118", "affected", None),                                                # 主線修補在分支之後、沒有分支紀錄
    ("6.12", "6.1.118", "affected", None),
    ("6.1.5", "6.1.118", "unknown", "mainline fix version not understood"),                  # 解析不了：不猜
    ("abc", "6.1.118", "unknown", "mainline fix version not understood"),
])
def test_mainline_fix_rule(tmp_path, fix, version, verdict, why):
    recs = mainline_only("CVE-2024-60001", "4.0", fix)
    _, _, doc, lst = run(tmp_path, version, mirror=make_mirror(tmp_path / "m", records=recs))
    c = by_cve(doc)["CVE-2024-60001"]
    assert c["verdict"] == verdict, c
    if why:
        assert why in c["reason"]
    if verdict == "affected":
        assert "after branch" in c["note"] and "CVE-2024-60001" in lst
    if verdict == "not_affected":
        assert "CVE-2024-60001" not in lst


def test_mainline_fix_does_not_override_branch_fix_record(tmp_path):
    """分支有自己的修補（6.1.142）而且比 v 新，卻說主線在 5.0 就修好：矛盾 → unknown，不判不受影響。"""
    recs = mainline_only("CVE-2024-60002", "4.0", "5.0", extra=["6.1.142"])
    _, _, doc, _ = run(tmp_path, "6.1.118", mirror=make_mirror(tmp_path / "m", records=recs))
    assert by_cve(doc)["CVE-2024-60002"]["verdict"] == "unknown"


def test_mainline_fix_after_branch_with_later_stable(tmp_path):
    """6.13.2 比主線的 6.12 新：6.13 從 6.12 之後的主線分出來，已含修補 → not_affected。"""
    _, _, doc, _ = run(tmp_path, "6.13.2", mirror=make_mirror(tmp_path / "m"))
    assert by_cve(doc)["CVE-2024-50264"]["verdict"] == "not_affected"


def test_affected_only_and_suffix(tmp_path):
    st, msg, doc, lst = run(tmp_path, "6.1.118-rockchip", zpath=make_zip(tmp_path / "k.zip"), affected_only=True)
    assert lst == ["CVE-2024-50999", "CVE-2025-38001"]
    assert any("1 unknown CVE(s) are not in" in g for g in doc["gaps"]) and "unknown 1 個沒有列" in msg
    assert doc["kernel_version"] == {"input": "6.1.118-rockchip", "compared": "6.1.118", "suffix_ignored": "-rockchip"}
    assert any(x["id"] == "suffix-ignored" for x in doc["limitations"])
    assert any("--zip without SOURCE" in g for g in doc["gaps"])


@pytest.mark.parametrize("bad", ["6", "6.1-rc3", "6.1.118+rc1", "latest", "6.1.118rc", "", "5.15.0-125-generic", "6.1.0-28-amd64",
                                 "9" * 5000 + ".1", "6.1.0-rpi7-rpi-v8", "6.1-vendor"])
def test_bad_versions(tmp_path, bad):
    with pytest.raises(kcv.InputError):
        kcv.run(bad, str(tmp_path / "r.json"), str(tmp_path / "c.txt"), zpath=make_zip(tmp_path / "k.zip"))
    assert not (tmp_path / "r.json").exists() and not (tmp_path / "c.txt").exists()


def test_zip_traversal_and_oversized_blocked(tmp_path, monkeypatch):
    """路徑穿越、絕對路徑、年份不一致、重複的名稱、超過上限的紀錄：拒絕並列出，不寫到磁碟；其他紀錄照樣判定，狀態 GAP。"""
    monkeypatch.setattr(kcv, "MAX_RECORD", 4096)
    big = json.dumps(record("CVE-2024-49999", [sem_block("4.0", [], None)]) | {"pad": "x" * 10000})
    extra = [("../../etc/evil.json", "{}"), ("/abs/CVE-2024-1.json", "{}"), ("cve/published/2024/../../../x/CVE-2024-2.json", "{}"),
             ("cve/published/2023/CVE-2024-3.json", "{}"), ("cve/published/2024/CVE-2024-49999.json", big),
             ("cve/published/2024/CVE-2024-50264.json", "{}")]
    st, msg, doc, lst = run(tmp_path, "6.1.118", mirror=make_mirror(tmp_path / "m", extra=extra))
    z = doc["zip"]
    assert z["rejected"] == 7, z["rejected_examples"]          # 重複的名稱兩份都算
    ex = "\n".join(z["rejected_examples"])
    assert "evil" in ex and "declared size" in ex and "duplicate" in ex
    assert "CVE-2024-49999" not in by_cve(doc) and "CVE-2024-50264" not in by_cve(doc)      # 重複的名稱：兩筆都不用
    assert not (tmp_path / "etc").exists() and not os.path.exists("/abs")
    assert st == "GAP" and any("7 zip member(s) rejected" in g for g in doc["gaps"])
    assert "CVE-2025-38001" in lst


def test_declared_size_lies(tmp_path, monkeypatch):
    """zip 標頭宣告的大小比實際小：讀的時候也以上限截斷，超過就拒絕（不信任標頭）。"""
    monkeypatch.setattr(kcv, "MAX_RECORD", 2048)
    zp = make_zip(tmp_path / "k.zip", {"CVE-2025-38001": RECORDS["CVE-2025-38001"]}, extra=[("cve/published/2024/CVE-2024-1.json", "x" * 5000)])
    data = bytearray(open(zp, "rb").read())
    name = b"cve/published/2024/CVE-2024-1.json"
    for pos in [m.start() for m in re.finditer(re.escape(name), bytes(data))]:
        if data[pos - 46:pos - 42] == b"PK\x01\x02":         # central directory：uncompressed size 在 +24
            data[pos - 46 + 24:pos - 46 + 28] = (100).to_bytes(4, "little")
        elif data[pos - 30:pos - 26] == b"PK\x03\x04":       # local header：uncompressed size 在 +22
            data[pos - 30 + 22:pos - 30 + 26] = (100).to_bytes(4, "little")
    open(zp, "wb").write(bytes(data))
    _, _, doc, _ = run(tmp_path, "6.1.118", zpath=zp)
    z = doc["zip"]
    assert z["rejected"] + z["unreadable"] == 1 and "CVE-2024-1" not in by_cve(doc)


def test_mirror_checks(tmp_path):
    with pytest.raises(kcv.InputError, match="sha256"):
        run(tmp_path, "6.1.118", mirror=make_mirror(tmp_path / "m1", sha="0" * 64))
    old = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    st, msg, doc, _ = run(tmp_path, "6.1.118", mirror=make_mirror(tmp_path / "m2", fetched=old))
    assert st == "GAP" and "stale" in msg and any("stale" in g for g in doc["gaps"])
    with pytest.raises(kcv.InputError, match="沒有任何可用"):
        run(tmp_path, "6.1.118", mirror=make_mirror(tmp_path / "m3", records={}))


def test_conflicts_and_unparsed_ranges():
    v = kcv.parse_query("6.1.118")[0]
    a = {"product": "Linux", "defaultStatus": "affected", "versions": [
        {"version": "6.1.100", "lessThan": "6.1.200", "status": "affected", "versionType": "semver"},
        {"version": "6.1.117", "lessThanOrEqual": "6.1.*", "status": "unaffected", "versionType": "semver"}]}
    r = kcv.judge(v, record("CVE-2024-1", [a]))
    assert r["verdict"] == "unknown" and "conflicting" in r["basis"][0]
    b = {"product": "Linux", "defaultStatus": "unaffected", "versions": [
        {"version": "6.1.0", "lessThanOrEqual": "6.1.x", "status": "affected", "versionType": "semver"}]}
    r = kcv.judge(v, record("CVE-2024-2", [b]))
    assert r["verdict"] == "unknown" and "not understood" in r["basis"][0]
    # 兩個 semver 項目一個說受影響、一個說不受影響 → unknown
    r = kcv.judge(v, record("CVE-2024-3", [sem_block("4.8", ["6.1.117"], None), sem_block("4.8", [], None)]))
    assert r["verdict"] == "unknown" and "disagree" in r["reason"]
    # 沒有 Linux 項目
    r = kcv.judge(v, record("CVE-2024-4", [{"product": "Other", "defaultStatus": "affected"}]))
    assert r["verdict"] == "unknown"


def test_cli_and_kernel_config_reads_list(tmp_path, capsys):
    m = make_mirror(tmp_path / "m")
    rc = kcv.main(["--kernel-version", "6.1.118", "--mirror", m, "--out", str(tmp_path / "r.json"), "--cves-out", str(tmp_path / "c.txt")])
    line = capsys.readouterr().out.strip()
    assert rc == 0 and line.startswith("KERNEL-CNA-VERSION\tGAP\t6.1.118：")
    # kernel_config.py 的 --cves 讀法：文字裡所有 CVE 編號
    text = (tmp_path / "c.txt").read_text()
    assert set(re.findall(r"CVE-\d{4}-\d{4,}", text)) == {"CVE-2024-40000", "CVE-2024-50999", "CVE-2025-38001"}
    rc = kcv.main(["--kernel-version", "6.1-rc1", "--mirror", m, "--out", str(tmp_path / "x.json"), "--cves-out", str(tmp_path / "x.txt")])
    assert rc == 3 and capsys.readouterr().out.startswith("KERNEL-CNA-VERSION\tFAIL\t")


def test_reproducible(tmp_path):
    """同一份鏡像、同一個版本：除了 generated_utc，輸出逐位元組相同。"""
    m = make_mirror(tmp_path / "m")
    now = datetime.datetime(2026, 11, 9, tzinfo=datetime.timezone.utc)
    outs = []
    for k in (1, 2):
        d = tmp_path / f"r{k}"
        d.mkdir()
        kcv.run("6.1.118", str(d / "r.json"), str(d / "c.txt"), mirror=m, now=now, max_age=10 ** 6)
        outs.append(((d / "r.json").read_bytes(), (d / "c.txt").read_bytes()))
    assert outs[0] == outs[1]


# ---------- 獨立審查找到的情況 ----------

def test_backported_introduction_inside_unaffected_range_is_unknown():
    """問題被移植進 6.1 穩定分支（6.1.80 開始有）：「0 到 6.6 不受影響」的範圍和它矛盾 → unknown，不是 not_affected。"""
    v = kcv.parse_query("6.1.118")[0]
    a = {"product": "Linux", "defaultStatus": "affected", "versions": [
        {"version": "6.6", "status": "affected"}, {"version": "6.1.80", "status": "affected"},
        {"version": "0", "lessThan": "6.6", "status": "unaffected", "versionType": "semver"},
        {"version": "6.6.30", "lessThanOrEqual": "6.6.*", "status": "unaffected", "versionType": "semver"}]}
    r = kcv.judge(v, record("CVE-2024-5", [a]))
    assert r["verdict"] == "unknown" and "introduced in 6.1.80" in r["basis"][0]
    assert kcv.judge(kcv.parse_query("6.1.50")[0], record("CVE-2024-5", [a]))["verdict"] == "not_affected"


def test_other_status_and_version_types():
    v = kcv.parse_query("6.1.118")[0]
    a = {"product": "Linux", "defaultStatus": "unaffected", "versions": [
        {"version": "6.0", "lessThan": "6.2", "status": "unknown", "versionType": "semver"}]}
    assert kcv.judge(v, record("CVE-2024-6", [a]))["verdict"] == "unknown"
    b = {"product": "Linux", "defaultStatus": "affected", "versions": [
        {"version": "6.1.117", "lessThanOrEqual": "6.1.*", "status": "unaffected", "versionType": "custom"}]}
    r = kcv.judge(v, record("CVE-2024-7", [b]))
    assert r["verdict"] == "unknown" and "no semver" in r["reason"]          # 不認得的 versionType 不當 semver


def test_malformed_records_do_not_crash(tmp_path):
    """形狀不對的紀錄（cna 是清單、5000 位數的版本）只影響那一筆：記 unreadable 或 unknown，其他照常、沒有 traceback。"""
    bad1 = {"cveMetadata": {"cveId": "CVE-2024-80008", "assignerOrgId": ORG}, "containers": {"cna": ["x"]}}
    bad2 = record("CVE-2024-80009", [{"product": "Linux", "defaultStatus": "affected",
                                  "versions": [{"version": "9" * 5000, "lessThan": "7", "status": "unaffected", "versionType": "semver"}]}])
    bad3 = record("CVE-2024-80010", [{"product": "Linux", "programFiles": "not-a-list", "versions": "nope", "defaultStatus": 3}])
    recs = dict(RECORDS, **{"CVE-2024-80008": bad1, "CVE-2024-80009": bad2, "CVE-2024-80010": bad3})
    st, msg, doc, lst = run(tmp_path, "6.1.118", mirror=make_mirror(tmp_path / "m", records=recs))
    c = by_cve(doc)
    assert c["CVE-2024-80008"]["verdict"] == "unknown" and c["CVE-2024-80010"]["verdict"] == "unknown"
    assert c["CVE-2024-80009"]["verdict"] == "unknown"          # 版本讀不出來的項目不算 semver
    assert c["CVE-2025-38001"]["verdict"] == "affected"


def test_out_files_must_differ(tmp_path):
    with pytest.raises(kcv.InputError, match="同一個檔案"):
        kcv.run("6.1.118", str(tmp_path / "x"), str(tmp_path / "x"), zpath=make_zip(tmp_path / "k.zip"))


def test_total_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(kcv, "MAX_TOTAL", 1500)
    st, msg, doc, _ = run(tmp_path, "6.1.118", zpath=make_zip(tmp_path / "k.zip"))
    assert doc["zip"]["rejected"] >= 1 and any("total unpacked size" in x for x in doc["zip"]["rejected_examples"])


def test_reproducible_member_order(tmp_path):
    """zip 裡成員的順序不同：結果相同（依 CVE 排序）。"""
    now = datetime.datetime(2026, 11, 9, tzinfo=datetime.timezone.utc)
    outs = []
    for k, recs in enumerate((RECORDS, dict(reversed(list(RECORDS.items()))))):
        d = tmp_path / f"r{k}"
        d.mkdir()
        z = make_zip(d / "kernel-cves.zip", recs)
        kcv.run("6.1.118", str(d / "r.json"), str(d / "c.txt"), zpath=z, now=now)
        doc = json.loads((d / "r.json").read_text())
        doc["mirror"].pop("zip_sha256")
        outs.append((doc["cves"], doc["counts"], (d / "c.txt").read_bytes()))
    assert outs[0] == outs[1]


def test_mixed_block_nonsemver_affected_not_default_unaffected():
    """同一個項目混了非 semver 的受影響範圍與 semver 的不受影響範圍、semver 沒有涵蓋 v：unknown，不是 defaultStatus unaffected。"""
    v = kcv.parse_query("6.1.118")[0]
    a = {"product": "Linux", "defaultStatus": "unaffected", "versions": [
        {"version": SHA, "lessThan": "5f092a4271f6dccf88fe0d132475a17b69ef71df", "status": "affected", "versionType": "git"},
        {"version": "6.6.30", "lessThanOrEqual": "6.6.*", "status": "unaffected", "versionType": "semver"}]}
    r = kcv.judge(v, record("CVE-2024-80011", [a]))
    assert r["verdict"] == "unknown" and "non-semver" in r["basis"][0]


@pytest.mark.parametrize("extra,version,verdict", [
    # 紀錄明寫 6.1.20 <= v <= 6.1.* 受影響、分支沒有修補紀錄，主線 5.0 早就修好 → unknown（不是 not_affected）
    ([{"version": "6.1.20", "lessThanOrEqual": "6.1.*", "status": "affected", "versionType": "semver"}], "6.1.118", "unknown"),
    ([{"version": "6.1.20", "lessThan": "6.1.200", "status": "affected", "versionType": "semver"}], "6.1.118", "unknown"),
    # 從這個分支的某版開始受影響（單一版本項目）
    ([{"version": "6.1.20", "status": "affected", "versionType": "semver"}], "6.1.118", "unknown"),
    # 明寫的受影響範圍不涵蓋 v（6.1.20..6.1.50，v = 6.1.118）：照舊走主線規則
    ([{"version": "6.1.20", "lessThan": "6.1.50", "status": "affected", "versionType": "semver"}], "6.1.118", "not_affected"),
    # 別的分支的 affected 項目不影響這個分支
    ([{"version": "5.15.20", "lessThanOrEqual": "5.15.*", "status": "affected", "versionType": "semver"}], "6.1.118", "not_affected"),
])
def test_mainline_fix_with_explicit_branch_affected_entry_is_unknown(tmp_path, extra, version, verdict):
    """G2-2：主線早於分支修好，但 CNA 紀錄明寫這個分支受影響、分支又沒有修補紀錄 → unknown，不靠主線判 not_affected。"""
    blk = sem_block("4.0", [], "5.0")
    blk["versions"] = blk["versions"][:2] + extra + blk["versions"][2:]
    recs = {"CVE-2024-60010": record("CVE-2024-60010", [git_block(), blk])}
    _, _, doc, lst = run(tmp_path, version, mirror=make_mirror(tmp_path / "m", records=recs))
    c = by_cve(doc)["CVE-2024-60010"]
    assert c["verdict"] == verdict, c
    if verdict == "unknown":
        assert "explicit affected entry" in c["reason"] and "no fix" in c["note"]
        assert "CVE-2024-60010" in lst            # unknown 的 CVE 照樣列出（不被當成排除）
