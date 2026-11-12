"""report_diff.py（兩份報告的差異）與 report_package.py --previous。資料全部是合成的。"""
import hashlib
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

import report_diff as rd
import report_package as rp
import supplier_package as sp
from test_report_package import project, row, rows_doc, walk
from test_cra_report import write_json

CLI = Path(rd.__file__)
TSV = ("stage\tstatus\tdetail\nA-tools\tOK\tgrype 0.121.0 syft 1.55.0\n"
       "C-grype-db\tOK\tBuilt={db}（UTC，3.7 小時，上限 24 小時）Status=valid\n"
       "D-ubuntu-status\tOK\tTracker commit abc123，fetched_utc={tr}；核心套件不在範圍\n")


def deb(id_, comp, ver, **kw):
    r = row(id_, comp=comp, ver=ver, **kw)
    r["purl"] = f"pkg:deb/ubuntu/{comp}@{ver}?arch=arm64&distro=ubuntu-24.04&upstream=src-{comp}"
    return r


def report(tmp, name, rows, db, tr="2026-11-10T19:43:46Z", sbom=None):
    d = Path(tmp) / name / "內部存檔"
    d.mkdir(parents=True)
    write_json(d / rd.ROWS_FILE, rows_doc(rows))
    write_json(d / "summary.json", {"generated": f"{db[:10]}T12:00:00Z"})
    (d / "scan-status.tsv").write_text(TSV.format(db=db, tr=tr), encoding="utf-8")
    if sbom is not None:
        (d.parent / "交給PM" / "SBOM").mkdir(parents=True)
        write_json(d.parent / "交給PM" / "SBOM" / "sbom.cdx.json", {"components": [{"name": n, "version": v} for n, v in sbom]})
    return d.parent


def mkdb(path, cve="CVE-9", pkg="src-libgone", state="not-affected", table="unaffected"):
    c = sqlite3.connect(path)
    c.executescript("""create table db_metadata(build_timestamp, model, revision, addition);
    insert into db_metadata values('2026-11-11 06:00:00+00:00',6,1,1);
    create table vulnerability_handles(id integer primary key, name, status, published_date, modified_date, withdrawn_date, provider_id, blob_id);
    create table operating_systems(id integer primary key, name, major_version);
    create table packages(id integer primary key, name);
    create table blobs(id integer primary key, value);
    create table affected_package_handles(id integer primary key, vulnerability_id, operating_system_id, package_id, blob_id);
    create table unaffected_package_handles(id integer primary key, vulnerability_id, operating_system_id, package_id, blob_id);
    insert into operating_systems values(1,'ubuntu','24'); insert into packages values(1,'%s');
    insert into vulnerability_handles values(1,'%s','active','2026-11-01','2026-11-11',NULL,'ubuntu',NULL);
    insert into blobs values(1,'{"ranges":[{"version":{"type":"dpkg"},"fix":{"state":"%s"}}]}');
    insert into %s_package_handles values(1,1,1,1,1);""" % (pkg, cve, state, table))
    c.commit()
    c.close()


def pair(tmp):
    prev = report(tmp, "prev", [deb("CVE-9", "libgone", "1.0"), deb("CVE-9", "libgone2", "1.0"), deb("CVE-1", "libgone", "1.0"),
                                deb("CVE-2", "libold", "1.0"), deb("CVE-3", "libx", "1.0", tier="p3"),
                                deb("CVE-4", "libgoneall", "1.0"), deb("CVE-5", "libfix", "1.0", rule="R8", fix_state="no Grype data")],
                  "2026-11-10T06:21:20Z", sbom=[("libgone", "1.0"), ("libgone2", "1.0"), ("libold", "1.0"), ("libx", "1.0"),
                                              ("libgoneall", "1.0"), ("libfix", "1.0")])
    cur = report(tmp, "cur", [deb("CVE-1", "libgone", "1.0"), deb("CVE-2", "libold", "2.0"),
                              deb("CVE-3", "libx", "1.0", tier="p1", exploited=True, exploitation_evidence=["KEV (DT, Grype)"]),
                              deb("CVE-6", "libnew", "1.0"), deb("CVE-7", "libx", "1.0"),
                              deb("CVE-5", "libfix", "1.0", rule="R6", fix_state="not-fixed")],
                 "2026-11-11T06:21:32Z", sbom=[("libgone", "1.0"), ("libgone2", "1.0"), ("libold", "2.0"), ("libx", "1.0"),
                                             ("libnew", "1.0"), ("libfix", "1.0")])
    return prev, cur


def by(items):
    return {(i["id"], i["component"]): i for i in items}


def test_categories_and_reasons_without_db(tmp_path):
    prev, cur = pair(tmp_path)
    d = rd.compute(prev, cur)
    assert d["counts"] == {"added": 3, "removed": 4, "tier_changed": 1, "vex_changed": 1, "fix_state_changed": 1, "newly_exploited": 1,
                           "no_longer_exploited": 0}
    rm = by(d["removed"])
    assert rm[("CVE-2", "libold")]["reason"] == "version_changed" and rm[("CVE-2", "libold")]["reason_params"] == {"old": "1.0", "new": "2.0"}
    assert rm[("CVE-4", "libgoneall")]["reason"] == "component_removed"
    # 元件與版本都沒變、又沒有資料庫可核對：只能說未判定，不可說「發行版改了」
    for k in (("CVE-9", "libgone"), ("CVE-9", "libgone2")):
        assert rm[k]["reason"] == "data_unknown"
    ad = by(d["added"])
    assert ad[("CVE-2", "libold")]["reason"] == "version_changed" and ad[("CVE-6", "libnew")]["reason"] == "component_new"
    assert ad[("CVE-7", "libx")]["reason"] == "data_unknown"
    assert d["tier_changes"][0]["from"] == "p3" and d["tier_changes"][0]["to"] == "p1"
    assert d["newly_exploited"][0]["id"] == "CVE-3"
    assert d["vex_changes"][0]["fix_info_also_changed"] is True
    assert d["previous"]["tools"] == {"grype": "0.121.0", "syft": "1.55.0"}
    assert d["previous"]["vuln_db_built"] == "2026-11-10T06:21:20Z" and d["current"]["vuln_db_built"] == "2026-11-11T06:21:32Z"
    assert d["previous"]["ubuntu_tracker_fetched"] == "2026-11-10T19:43:46Z"
    zh = rd.render(d, "zh")
    assert "原因未判定" in zh and "發行版狀態變更" not in zh


def test_db_evidence_only_with_flag(tmp_path):
    prev, cur = pair(tmp_path)
    db = tmp_path / "v.db"
    mkdb(db)
    d = rd.compute(prev, cur, db)
    rm = by(d["removed"])
    assert rm[("CVE-9", "libgone")]["reason"] == "db_not_affected" and rm[("CVE-9", "libgone")]["reason_params"]["os"] == "Ubuntu 24.04"
    assert rm[("CVE-9", "libgone2")]["reason"] == "data_unknown"    # 資料庫查不到這個套件 → 不講原因
    en = rd.render(rd.customer_view(d), "en")
    assert "the distribution now lists src-libgone on Ubuntu 24.04 as not affected" in en
    c = sqlite3.connect(f"file:{db}?mode=ro", uri=True)           # 唯讀：資料庫沒被改
    assert c.execute("select count(*) from vulnerability_handles").fetchone()[0] == 1


def test_db_affected_contradiction_kept(tmp_path):
    prev, cur = pair(tmp_path)
    db = tmp_path / "v.db"
    mkdb(db, state="wont-fix", table="affected")
    rm = by(rd.compute(prev, cur, db)["removed"])
    assert rm[("CVE-9", "libgone")]["reason"] == "db_still_affected"


def test_customer_english_passes_language_check(tmp_path):
    prev, cur = pair(tmp_path)
    d = rd.compute(prev, cur)
    out = tmp_path / "o"
    rd.write_outputs(d, out)
    en = (out / rd.OUT_EN).read_text(encoding="utf-8")
    assert sp.check_customer_text(rd.OUT_EN, en) == []
    assert "Grype" not in en and "R8" not in en and "grype" not in en and "KEV (DT" not in en
    assert (out / rd.OUT_JSON).is_file() and "消失的列" in (out / rd.OUT_ZH).read_text(encoding="utf-8")
    out2 = tmp_path / "o2"                                          # 同樣輸入，輸出一樣
    rd.write_outputs(rd.compute(prev, cur), out2)
    assert (out / rd.OUT_JSON).read_bytes() == (out2 / rd.OUT_JSON).read_bytes()


def test_cli_and_bad_input(tmp_path):
    prev, cur = pair(tmp_path)
    r = subprocess.run([sys.executable, "-I", str(CLI), "--previous", str(prev), "--current", str(cur), "--out", str(tmp_path / "o")],
                       capture_output=True, text=True)
    assert r.returncode == 0 and "removed=4" in r.stdout
    r = subprocess.run([sys.executable, "-I", str(CLI), "--previous", str(tmp_path), "--current", str(cur), "--out", str(tmp_path / "o3")],
                       capture_output=True, text=True)
    assert r.returncode == 1 and "FAIL" in r.stderr
    r = subprocess.run([sys.executable, "-I", str(CLI), "--previous", str(prev), "--current", str(cur), "--out", str(tmp_path / "o")],
                       capture_output=True, text=True)
    assert r.returncode == 1                       # 不覆蓋既有的輸出


def test_package_hook_and_default_unchanged(tmp_path):
    prev, _ = pair(tmp_path)
    p = project(tmp_path, [deb("CVE-1", "libgone", "1.0"), deb("CVE-7", "libx", "1.0")])
    sup = tmp_path / "sup"
    pk = sup / "CRA" / "Reports" / "supplier-package"
    pk.mkdir(parents=True)
    (pk / "README.md").write_text("customer", encoding="utf-8")
    write_json(pk / "summary.json", {"files": [], "status": "OK"})
    (pk / "SHA256SUMS").write_text("0" * 64 + "  summary.json\n", encoding="utf-8")
    a, b = tmp_path / "a", tmp_path / "b"
    assert rp.build(p, a, sup, allow_tmp=True)[0] == 0
    assert rp.build(p, b, sup, allow_tmp=True)[0] == 0
    assert walk(a) == walk(b) and not [f for f in walk(a) if "changes-since" in f]      # 沒給 --previous：沒有任何差異檔
    for f in walk(a):
        assert (a / f).read_bytes() == (b / f).read_bytes(), f
    c = tmp_path / "c"
    code, msgs = rp.build(p, c, sup, allow_tmp=True, previous=prev)
    assert code == 0, msgs
    files = set(walk(c))
    assert {"內部存檔/changes-since-previous.json", "內部存檔/changes-since-previous.zh.md", "交給PM/客戶資料包/changes-since-previous.md"} <= files
    assert "內部存檔/changes-since-previous.md" not in files
    for f in walk(a):                                               # 其餘檔案逐位元組相同
        if f.endswith(("summary.json", "SHA256SUMS", "SHA256SUMS.txt")):
            continue
        assert (a / f).read_bytes() == (c / f).read_bytes(), f
    pkg = c / "交給PM" / "客戶資料包"
    sums = {ln.split("  ", 1)[1]: ln.split("  ", 1)[0] for ln in (pkg / "SHA256SUMS").read_text(encoding="utf-8").splitlines()}
    assert sums["changes-since-previous.md"] == hashlib.sha256((pkg / "changes-since-previous.md").read_bytes()).hexdigest()
    assert sums["summary.json"] == hashlib.sha256((pkg / "summary.json").read_bytes()).hexdigest()
    assert any(f["file"] == "changes-since-previous.md" for f in json.loads((pkg / "summary.json").read_text(encoding="utf-8"))["files"])
    assert "內部存檔/changes-since-previous.json" in (c / "SHA256SUMS.txt").read_text(encoding="utf-8")


def test_package_bad_previous_leaves_nothing(tmp_path):
    p = project(tmp_path, [deb("CVE-1", "libgone", "1.0")])
    out = tmp_path / "out"
    with pytest.raises(rp.PackageError):
        rp.build(p, out, allow_tmp=True, previous=tmp_path / "nosuch")
    assert not out.exists()


def test_source_package_name_matches_sbom_binary_name(tmp_path):
    """列上是來源套件名 acl，SBOM 只有 libacl1（purl upstream=acl）：不可寫成「已從產品移除」。"""
    def sb(d, name, comps):
        (d / "交給PM" / "SBOM").mkdir(parents=True, exist_ok=True)
        write_json(d / "交給PM" / "SBOM" / "sbom.cdx.json", {"components": comps})
    lib = {"name": "libacl1", "version": "2.3.2-1", "purl": "pkg:deb/ubuntu/libacl1@2.3.2-1?arch=arm64&distro=ubuntu-24.04&upstream=acl"}
    prev = report(tmp_path, "p", [deb("CVE-1", "acl", "2.3.2-1"), deb("CVE-2", "acl", "2.3.2-1")], "2026-11-10T06:21:20Z")
    cur = report(tmp_path, "c", [deb("CVE-2", "acl", "2.3.2-1")], "2026-11-11T06:21:32Z")
    sb(prev, "", [lib])
    sb(cur, "", [lib])
    d = rd.compute(prev, cur)
    assert d["removed"][0]["reason"] == "data_unknown"          # acl 還在 SBOM（靠 upstream），不是 component_removed
    # 只靠 upstream 對到、版本不同：不下結論
    sb(cur, "", [dict(lib, version="2.3.2-2")])
    cur_rows = report(tmp_path, "c2", [deb("CVE-2", "other", "1")], "2026-11-11T06:21:32Z")
    sb(cur_rows, "", [dict(lib, version="2.3.2-2")])
    r = rd.compute(prev, cur_rows)["removed"]
    assert {x["reason"] for x in r if x["component"] == "acl"} == {"component_absent"}
    # 真的對不到時，客戶英文版也不寫「removed from the product」為結論
    cur3 = report(tmp_path, "c3", [deb("CVE-2", "other", "1")], "2026-11-11T06:21:32Z")
    sb(cur3, "", [{"name": "zzz", "version": "1"}])
    d3 = rd.compute(prev, cur3)
    assert d3["removed"][0]["reason"] == "component_removed"
    en = rd.render(rd.customer_view(d3), "en")
    assert "not determined" in en and "was removed from the product." not in en and "no longer in the new report" not in en


def test_customer_text_states_no_unproven_cause(tmp_path):
    prev, cur = pair(tmp_path)
    en = rd.render(rd.customer_view(rd.compute(prev, cur)), "en")
    for w in ("accordingly", "distribution or upstream fix information changed", "follows from"):
        assert w not in en


def test_group_key_keeps_status_differences(tmp_path):
    prev = report(tmp_path, "p", [deb("CVE-1", "a", "1", fix_state="wont-fix"), deb("CVE-1", "b", "1", fix_state="not-fixed")], "2026-11-10T06:21:20Z")
    cur = report(tmp_path, "c", [deb("CVE-9", "z", "1")], "2026-11-11T06:21:32Z")
    en = rd.render(rd.customer_view(rd.compute(prev, cur)), "en")
    assert "the distribution will not fix" in en and "no fix available" in en
    lines = [ln for ln in en.splitlines() if ln.startswith("| CVE-1 ")]
    assert len(lines) == 2


def test_failed_customer_check_leaves_no_folder(tmp_path):
    prev, cur = pair(tmp_path)
    d = rd.compute(prev, cur)
    d["removed"][0]["fix_state"] = "planned later release"       # 客戶檔案不可有的用語
    out = tmp_path / "never"
    with pytest.raises(rd.DiffError):
        rd.write_outputs(d, out)
    assert not out.exists()


def test_package_readme_lists_diff_file(tmp_path):
    prev, _ = pair(tmp_path)
    p = project(tmp_path, [deb("CVE-1", "libgone", "1.0")])
    sup = tmp_path / "sup"
    pk = sup / "CRA" / "Reports" / "supplier-package"
    pk.mkdir(parents=True)
    (pk / "README.md").write_text("# R\n\n| File | Purpose | SHA-256 |\n|---|---|---|\n| `summary.json` | x | see `SHA256SUMS` |\n", encoding="utf-8")
    write_json(pk / "summary.json", {"files": [{"file": "README.md", "sha256": "0", "status": "OK"}], "status": "OK"})
    (pk / "SHA256SUMS").write_text("0" * 64 + "  README.md\n" + "0" * 64 + "  summary.json\n", encoding="utf-8")
    c = tmp_path / "c"
    assert rp.build(p, c, sup, allow_tmp=True, previous=prev)[0] == 0
    pkg = c / "交給PM" / "客戶資料包"
    rm = (pkg / "README.md").read_text(encoding="utf-8")
    assert "| `changes-since-previous.md` |" in rm and rm.index("changes-since-previous.md") < rm.index("`summary.json`")
    sums = {ln.split("  ", 1)[1]: ln.split("  ", 1)[0] for ln in (pkg / "SHA256SUMS").read_text(encoding="utf-8").splitlines()}
    assert sums["README.md"] == hashlib.sha256((pkg / "README.md").read_bytes()).hexdigest()
    sj = json.loads((pkg / "summary.json").read_text(encoding="utf-8"))
    assert [f["sha256"] for f in sj["files"] if f["file"] == "README.md"] == [sums["README.md"]]
