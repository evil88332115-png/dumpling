"""nvidia_distro.py：NVIDIA 公告的 CVE 其實是發行版套件的 CVE 時，依發行版資料（合成的 Grype DB v6 樣子的 sqlite）判斷，
以及 vex_export.assess／report_package 的對應（規則 N1／N2、P1 列保留 KEV 標示）。資料全部是合成的。"""
import json
import sqlite3
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import cra_report as cr  # noqa: E402
import nvidia_distro as nd  # noqa: E402
import report_package as rp  # noqa: E402
import vex_export as vx  # noqa: E402
from test_vex_export import NVB, row  # noqa: E402

DEB = "pkg:deb/ubuntu/{}@{}?arch=arm64&distro=ubuntu-24.04&upstream={}"
POLKIT_VER = "124-2ubuntu1.24.04.3"


def comp(name, ver, src=None):
    return {"name": name, "version": ver, "purl": DEB.format(name, ver, src or name)}


def make_db(path, records, eol_old="2020-01-01", built="2026-11-11 06:21:32+00:00", model=6):
    """records：[(cve, kind, pkg, major, minor, ranges)]；kind＝affected／unaffected。provider＝ubuntu。"""
    Path(path).unlink(missing_ok=True)
    c = sqlite3.connect(path)
    c.executescript("""
    create table blobs (id integer primary key autoincrement, value text not null);
    create table db_metadata (build_timestamp text, model int, revision int, addition int);
    create table vulnerability_handles (id integer primary key autoincrement, name text, status text, published_date text,
        modified_date text, withdrawn_date text, provider_id text, blob_id integer);
    create table operating_systems (id integer primary key autoincrement, name text, release_id text, major_version text,
        minor_version text, label_version text, codename text, channel text, eol_date text, eoas_date text);
    create table packages (id integer primary key autoincrement, ecosystem text, name text);
    create table affected_package_handles (id integer primary key autoincrement, vulnerability_id int, operating_system_id int,
        package_id int, blob_id int);
    create table unaffected_package_handles (id integer primary key autoincrement, vulnerability_id int, operating_system_id int,
        package_id int, blob_id int);
    """)
    c.execute("insert into db_metadata values (?,?,1,1)", (built, model))
    ids = {}

    def get(table, key, sql, args):
        if (table, key) not in ids:
            ids[(table, key)] = c.execute(sql, args).lastrowid
        return ids[(table, key)]
    for cve, kind, pkg, major, minor, rng in records:
        v = get("v", cve, "insert into vulnerability_handles (name,status,provider_id) values (?,?,?)", (cve, "active", "ubuntu"))
        eol = eol_old if (major, minor) in (("14", "4"), ("16", "4")) else "2029-05-31"
        o = get("o", (major, minor), "insert into operating_systems (name,release_id,major_version,minor_version,channel,eol_date) "
                                     "values ('ubuntu','ubuntu',?,?,'',?)", (major, minor, eol))
        p = get("p", pkg, "insert into packages (ecosystem,name) values ('deb',?)", (pkg,))
        b = c.execute("insert into blobs (value) values (?)", (json.dumps({"ranges": rng}),)).lastrowid
        c.execute(f"insert into {kind}_package_handles (vulnerability_id,operating_system_id,package_id,blob_id) values (?,?,?,?)", (v, o, p, b))
    c.commit()
    c.close()
    return path


def fixed(v):
    return [{"version": {"type": "dpkg", "constraint": f"< {v}"}, "fix": {"version": v, "state": "fixed"}}]


WONT = [{"version": {"type": "dpkg"}, "fix": {"state": "wont-fix"}}]
NOTAFF = [{"version": {"type": "dpkg"}, "fix": {"state": "not-affected"}}]
POLKIT = [("CVE-2021-4034", "affected", "policykit-1", "20", "4", fixed("0.105-26ubuntu1.2")),
          ("CVE-2021-4034", "affected", "policykit-1", "22", "4", fixed("0.105-31ubuntu1")),
          ("CVE-2021-4034", "affected", "policykit-1", "16", "4", WONT)]       # 16.04 已 EOL 不修
SBOM = [comp("polkitd", POLKIT_VER, "policykit-1"), comp("libpolkit-gobject-1-0", POLKIT_VER, "policykit-1"),
        comp("nvidia-l4t-core", "39.2.0-2026", "nvidia-l4t-core"), comp("bash", "5.2", "bash")]


NOW = "2026-11-11T12:00:00Z"


def run(tmp_path, records, sbom=SBOM, cves=("CVE-2021-4034",), rootfs=None, info=False, **kw):
    db = make_db(str(tmp_path / "v.db"), records, **{k: kw.pop(k) for k in ("built", "model") if k in kw})
    res, inf = nd.remap(cves, sbom, db, cr.deb_vercmp, kw.pop("now", NOW), rootfs, **kw)
    return (res, inf) if info else res


def rootfs_with(tmp_path, pkexec):
    root = tmp_path / "rootfs"
    (root / "usr/bin").mkdir(parents=True, exist_ok=True)
    if pkexec:
        (root / "usr/bin/pkexec").write_text("x")
    return root


def test_binary_absent_closes_not_affected_with_version_as_supporting_text(tmp_path):
    r = run(tmp_path, POLKIT, rootfs=rootfs_with(tmp_path, False))["CVE-2021-4034"]
    assert r["state"] == "not_affected" and r["basis"] == "binary_absent" and r["justification"] == "code_not_present"
    assert r["package"] == "policykit-1" and r["binaries"] == ["libpolkit-gobject-1-0", "polkitd"]
    assert "Ubuntu 24.04 data has no record" in r["detail"] and "absent from the root file system: /usr/bin/pkexec" in r["detail"]
    assert "Ubuntu 20.04, Ubuntu 22.04" in r["detail"] and "backport numbers" in r["detail"]
    assert r["db"]["built"].startswith("2026-11-11") and r["db"]["model"] == 6 and r["db"]["source"] == "option"


def test_binary_present_or_unknown_does_not_close(tmp_path):
    for root in (rootfs_with(tmp_path, True), None):
        r = run(tmp_path, POLKIT, rootfs=root)["CVE-2021-4034"]
        assert r["state"] == "ambiguous" and r["basis"] == "no_release_record"
        assert "no positive evidence" in r["detail"]
    assert nd.binary_check("CVE-2021-4034", rootfs_with(tmp_path, True))[0] == "present"
    assert nd.binary_check("CVE-0000-0", rootfs_with(tmp_path, False)) == (None, None)


def test_verifier_counterexample_newer_version_in_other_line_is_not_closed(tmp_path):
    # 只有 22.04 處理過（修補 1.2.3-1ubuntu0.1），24.04 沒有記錄，安裝 1.4.0-1：版本線不同 → 不能關閉（舊規則會誤判 not_affected）
    sb = [comp("libfoo", "1.4.0-1", "foo")]
    r = run(tmp_path, [("CVE-2025-1", "affected", "foo", "22", "4", fixed("1.2.3-1ubuntu0.1"))], sbom=sb, cves=("CVE-2025-1",))["CVE-2025-1"]
    assert r["state"] == "ambiguous" and "1.2.3-1ubuntu0.1" in r["detail"]
    # Debian 式的不同線（0.105 對 124）也不行
    r = run(tmp_path, POLKIT)["CVE-2021-4034"]
    assert r["state"] == "ambiguous"


def test_other_release_fixes_never_close_even_on_the_same_upstream_line(tmp_path):
    # 驗證者的反例：Debian 修訂號、epoch、backport 都會讓「同一條上游版本線」的比較失真 → 一律 ambiguous
    cases = [("0.105-5", "0.105-31ubuntu0.1"),        # 同上游 0.105，但修訂號比修補的舊
             ("124-1", "124-2ubuntu1"),               # 同上游 124，修訂號較舊
             ("1.2.9-1", "1:1.2.3-1"),                # epoch 不同
             ("1.2.5-1", "1.2.3-1ubuntu0.1"),         # 同線較新，但修補可能其實在 1.2.9
             ("1.2.3-1", "1.2.3-1ubuntu0.1")]         # 上游相同
    for inst, fx in cases:
        r = run(tmp_path, [("CVE-2025-1", "affected", "foo", "22", "4", fixed(fx))], sbom=[comp("libfoo", inst, "foo")],
                cves=("CVE-2025-1",))["CVE-2025-1"]
        assert r["state"] == "ambiguous" and r["basis"] == "no_release_record", (inst, fx)
        assert fx in r["detail"] and "not compared" in r["detail"] and "justification" not in r
    assert not hasattr(nd, "_line") and not hasattr(nd, "_upstream")


def test_release_record_unaffected_fixed_and_affected(tmp_path):
    un = run(tmp_path, [("CVE-2021-4034", "unaffected", "policykit-1", "24", "4", NOTAFF)])["CVE-2021-4034"]
    assert un["state"] == "not_affected" and un["basis"] == "release_unaffected" and un["justification"] == "code_not_present"
    fx = run(tmp_path, [("CVE-2021-4034", "affected", "policykit-1", "24", "4", fixed("124-2ubuntu1.24.04.2"))])["CVE-2021-4034"]
    assert fx["state"] == "resolved" and fx["basis"] == "release_fixed" and fx["fixed"] == "124-2ubuntu1.24.04.2"
    af = run(tmp_path, [("CVE-2021-4034", "affected", "policykit-1", "24", "4", fixed("124-2ubuntu1.24.04.9"))])["CVE-2021-4034"]
    assert af["state"] == "affected" and af["basis"] == "release_affected" and "older" in af["detail"]
    nf = run(tmp_path, [("CVE-2021-4034", "affected", "policykit-1", "24", "4", [{"fix": {"state": "not-fixed"}, "version": {}}])])
    assert nf["CVE-2021-4034"]["state"] == "affected"
    # 這個發行版本自己有記錄時，不拿 binary 缺席去推翻 affected
    assert run(tmp_path, [("CVE-2021-4034", "affected", "policykit-1", "24", "4", fixed("124-9"))],
               rootfs=rootfs_with(tmp_path, False))["CVE-2021-4034"]["state"] == "affected"


def test_no_distro_data_or_package_not_in_rootfs_is_not_remapped(tmp_path):
    assert run(tmp_path, POLKIT, cves=("CVE-2099-1",)) == {}
    assert run(tmp_path, POLKIT, sbom=[comp("bash", "5.2"), comp("nvidia-l4t-core", "1")]) == {}
    res, inf = nd.remap(["CVE-2021-4034"], SBOM, None, cr.deb_vercmp)
    assert res == {} and inf["checked"] is False


def test_stale_unparsable_and_future_db_is_not_checked(tmp_path):
    res, inf = run(tmp_path, POLKIT, info=True, built="2026-11-01 00:00:00+00:00")
    assert res == {} and inf["checked"] is False and "older than 3 days" in inf["reason"] and "2026-11-01" in inf["reason"]
    res, inf = run(tmp_path, POLKIT, info=True, built="not a date")
    assert res == {} and inf["checked"] is False and "unparsable" in inf["reason"]
    res, inf = run(tmp_path, POLKIT, info=True, built="2026-12-25 00:00:00+00:00")
    assert inf["checked"] is False and "future" in inf["reason"]
    res, inf = run(tmp_path, POLKIT, info=True, built="2026-11-01 00:00:00+00:00", max_age_days=30)
    assert inf["checked"] is True and "CVE-2021-4034" in res


def test_unreadable_or_wrong_schema_db_is_not_checked(tmp_path):
    res, inf = run(tmp_path, POLKIT, info=True, model=5)
    assert res == {} and inf["checked"] is False and "not a Grype v6" in inf["reason"]
    bad = tmp_path / "bad.db"
    bad.write_text("this is not sqlite")
    res, inf = nd.remap(["CVE-2021-4034"], SBOM, bad, cr.deb_vercmp, NOW)
    assert res == {} and inf["checked"] is False and inf["reason"]
    other = tmp_path / "other.db"
    sqlite3.connect(other).execute("create table t (x)").connection.commit()
    assert nd.remap(["CVE-2021-4034"], SBOM, other, cr.deb_vercmp, NOW)[1]["checked"] is False


def test_find_db_explicit_never_falls_back_and_checks_v6(tmp_path):
    good = make_db(str(tmp_path / "vulnerability.db"), POLKIT)
    assert nd.find_db(None, {}) is None
    assert nd.find_db(str(tmp_path), {}) == (Path(good), "option")
    assert nd.find_db(None, {"GRYPE_DB_CACHE_DIR": str(tmp_path)}) == (Path(good), "env")
    # 明確給的路徑不存在：error，即使環境變數有好的資料庫
    with pytest.raises(nd.DbError):
        nd.find_db(str(tmp_path / "nope"), {"GRYPE_DB_CACHE_DIR": str(tmp_path)})
    v5 = tmp_path / "v5"
    v5.mkdir()
    make_db(str(v5 / "vulnerability.db"), POLKIT, model=5)
    with pytest.raises(nd.DbError):
        nd.find_db(str(v5), {})


def test_binaries_of_one_source_package_are_all_judged(tmp_path):
    # 資料庫用二進位名稱記錄：兩個二進位套件的記錄不同 → 不能只看第一個，混合 → ambiguous
    recs = [("CVE-2025-2", "unaffected", "libbar1", "24", "4", NOTAFF), ("CVE-2025-2", "affected", "libbar-dev", "24", "4", fixed("9-9"))]
    sb = [comp("libbar1", "1.0-1", "bar"), comp("libbar-dev", "1.0-1", "bar")]
    r = run(tmp_path, recs, sbom=sb, cves=("CVE-2025-2",))["CVE-2025-2"]
    assert r["state"] == "ambiguous" and r["basis"] == "mixed" and "libbar1" in r["detail"] and "libbar-dev" in r["detail"]


def test_release_labels_sorted_numerically(tmp_path):
    recs = [("CVE-2025-3", "affected", "foo", "8", "4", fixed("0.5-1")), ("CVE-2025-3", "affected", "foo", "22", "4", fixed("0.6-1")),
            ("CVE-2025-3", "affected", "foo", "16", "4", fixed("0.4-1"))]
    r = run(tmp_path, recs, sbom=[comp("foo", "9.9-1")], cves=("CVE-2025-3",))["CVE-2025-3"]
    assert "Ubuntu 8.04, Ubuntu 16.04, Ubuntu 22.04" in r["detail"]


def nv_row(cve="CVE-2021-4034", **kw):
    return row(cve, "nvidia-l4t-core", "39.2.0-2026", source_ids=[f"NVIDIA:{cve}"], tier="nvidia_bulletin", **kw)


NVB1 = dict(NVB, presumed_included=[{"bulletin": "5321", "cve": "CVE-2021-4034", "bulletin_date": "2022-03-08", "lines_named": ["32"]}],
            needs_vendor_confirmation=[])


def assess(tmp_path, records, rows=None, rootfs=True, **ctx):
    rm = run(tmp_path, records, rootfs=rootfs_with(tmp_path, False) if rootfs else None)
    allr, _, info = vx.assess(rows if rows is not None else [nv_row()], nvb=NVB1, rule_ctx=dict({"nvidia_distro": rm}, **ctx))
    return allr, info


def test_remap_is_a_suggestion_and_vex_is_unchanged(tmp_path):
    allr, _ = assess(tmp_path, POLKIT)
    v = allr[0]["vex"]
    # 判定不變：還是 NVIDIA 公告的推定（in_triage），沒有 remap 標記，justification 沒有
    assert v["state"] == "in_triage" and v["source"] == "nvidia" and "presumed to be included" in v["detail"]
    assert not v.get("remap") and not v.get("justification")
    sg = allr[0]["suggestion"]
    assert sg["rule"] == "N1" and sg["state"] == "not_affected" and sg["justification"] == "code_not_present"
    assert sg["basis"] == "binary_absent" and sg["needs"] == "RD confirmation"
    assert "distribution package policykit-1" in sg["detail"] and "not of NVIDIA code" in sg["detail"]
    assert set(sg) == {"rule", "state", "justification", "basis", "detail", "needs"}
    assert allr[0]["nvidia_distro"]["state"] == "not_affected"
    # VEX 匯出（CycloneDX／OpenVEX 用的 vex 陳述）和沒有 remap 時完全一樣
    base_rows, _, _ = vx.assess([nv_row()], nvb=NVB1)
    assert base_rows[0]["vex"] == v and "suggestion" not in base_rows[0]


def test_suggestion_resolved_when_release_record_is_fixed(tmp_path):
    allr, _ = assess(tmp_path, [("CVE-2021-4034", "affected", "policykit-1", "24", "4", fixed("124-2ubuntu1.24.04.2"))])
    sg = allr[0]["suggestion"]
    assert allr[0]["vex"]["state"] == "in_triage"
    assert sg["rule"] == "N1" and sg["state"] == "resolved" and sg["justification"] is None and "fixed in 124-2ubuntu1.24.04.2" in sg["detail"]


def test_suggestion_distro_affected_points_to_distro_row(tmp_path):
    allr, _ = assess(tmp_path, [("CVE-2021-4034", "affected", "policykit-1", "24", "4", fixed("124-9"))])
    sg = allr[0]["suggestion"]
    assert allr[0]["vex"]["state"] == "in_triage" and sg["rule"] == "N2" and sg["state"] == "affected"
    assert "see the row of policykit-1" in sg["detail"]


def test_ambiguous_has_no_suggestion_and_keeps_presumed(tmp_path):
    allr, _ = assess(tmp_path, [("CVE-2021-4034", "affected", "policykit-1", "16", "4", WONT)], rootfs=False)
    v = allr[0]["vex"]
    assert v["state"] == "in_triage" and "presumed to be included" in v["detail"] and "suggestion" not in allr[0]
    assert allr[0]["nvidia_distro"]["state"] == "ambiguous"


def test_no_remap_input_is_unchanged():
    allr, _, _ = vx.assess([nv_row()], nvb=NVB1)
    assert allr[0]["vex"]["state"] == "in_triage" and "nvidia_distro" not in allr[0] and "suggestion" not in allr[0]


def test_kev_row_keeps_flag_tier_and_state_and_gets_suggestion(tmp_path):
    # 公告的 CVE 沒有 DT 的列、已遭利用 → nvidia_extra 做成 p1 的列；判定不變（in_triage），建議另記
    allr, info = assess(tmp_path, POLKIT, rows=[], exploited=["CVE-2021-4034"], exploited_sources={"CVE-2021-4034": ["EUVD (CISA KEV)"]})
    r = allr[0]
    assert r["tier"] == "p1" and r["exploited_sources"] == ["EUVD (CISA KEV)"]
    assert r["vex"]["state"] == "in_triage" and r["suggestion"]["rule"] == "N1"


def rp_row(**kw):
    r = {"id": "CVE-2021-4034", "aliases": [], "component": "nvidia-l4t-core", "version": "39.2.0", "purl": None, "is_kernel": False,
         "tier": "p1", "vex": {"state": "in_triage", "source": "nvidia", "rule": None, "justification": None,
                               "detail": "presumed", "author": None, "date": None, "markers": []},
         "fix_state": "no Grype data", "fix_versions": [], "fix_next": None, "cvss": None, "ubuntu_priority": None, "severity": "UNASSIGNED",
         "exploited": True, "exploitation_evidence": ["EUVD (CISA KEV)"], "exposed": False, "exposed_where": None,
         "nvidia_distro": {"state": "not_affected", "package": "policykit-1", "version": POLKIT_VER, "basis": "binary_absent",
                           "db": {"built": "2026-11-11 06:21:32+00:00"},
                           "binary_note": "absent from the complete listing of the root file system (94832 entries): /usr/bin/pkexec"},
         "suggestion": {"rule": "N1", "state": "not_affected", "justification": "code_not_present", "basis": "binary_absent",
                        "detail": "d", "needs": "RD confirmation"}}
    r.update(kw)
    return r


def test_report_package_shows_suggestion_without_changing_decision():
    fa = {}
    p1 = rp_row()
    code, cls, concl, act, who, basis, bad = rp.wording(p1, fa)
    assert code == "P1" and cls == rp.T_NOW and bad is None                  # 分類、規則代號、判定者都不變
    cells = rp.human_row(p1, fa, (None, None, None))
    assert cells[10] == "是" and cells[0] == rp.T_NOW and cells[13] == "待 RD 判斷"
    note = cells[15]
    assert "建議（N1）：不受影響" in note and "發行版套件 policykit-1" in note and "有問題的執行檔不在映像裡" in note and "/usr/bin/pkexec" in note
    assert note.endswith("需 RD 確認後才改判定")
    # 非 P1 的公告列：也還是 NVIDIA 規則、持續追蹤
    nb = rp_row(tier="nvidia_bulletin", exploited=False, exploitation_evidence=[])
    assert rp.wording(nb, fa)[0] == "NVIDIA" and rp.wording(nb, fa)[1] == rp.T_TRACK
    assert "建議（N1）" in rp.human_row(nb, fa, (None, None, None))[15]
    # N2：建議受影響
    n2 = rp_row(suggestion={"rule": "N2", "state": "affected", "justification": None, "basis": "release_affected", "detail": "d", "needs": "x"},
                nvidia_distro=dict(rp_row()["nvidia_distro"], state="affected", basis="release_affected"))
    assert "建議（N2）：受影響" in rp.human_row(n2, fa, (None, None, None))[15]


def test_rules_sheet_and_suggestion_sheet_cover_n1_n2_and_ub(tmp_path):
    ub = {"rule": "UB1", "state": "not_affected", "justification": "code_not_present", "detail": "d", "needs": "RD confirmation"}
    doc = {"rows": [rp_row(), rp_row(id="CVE-2", tier="nvidia_bulletin", suggestion=None),
                    rp_row(id="CVE-3", component="uefi", nvidia_distro=None, suggestion=ub, tier="p3")], "have_findings": True}
    sh = rp.rules_sheet(doc, {})
    rules = {r[0]: r for r in sh.rows}
    for c in ("UB1", "UB2", "N1", "N2"):
        assert rules[c][2] == "建議（需 RD 確認）"
    assert rules["N1"][7] == 1 and rules["N2"][7] == 0 and rules["UB1"][7] == 1
    assert rules["P1"][7] == 1 and rules["NVIDIA"][7] == 1                    # 建議不改列的規則代號
    ss = rp.suggestion_sheet(doc)
    assert ss.name == "建議（需 RD 確認）" and len(ss.rows) == 2
    assert [r[1] for r in ss.rows] == ["CVE-3", "CVE-2021-4034"] or [r[1] for r in ss.rows] == ["CVE-2021-4034", "CVE-3"]
    n1 = next(r for r in ss.rows if r[1] == "CVE-2021-4034")
    assert "建議（N1）：不受影響" in n1[4] and "待" not in n1[3] and n1[3].startswith("評估中")


def test_one_row_can_carry_suggestions_from_both_sources():
    ub = {"rule": "UB1", "state": "not_affected", "justification": "code_not_present", "detail": "d", "needs": "RD confirmation"}
    n1 = {"rule": "N1", "state": "not_affected", "justification": "code_not_present", "detail": "d", "needs": "RD confirmation"}
    row_ = {"id": "CVE-1", "name": "nvidia-l4t-core", "cves": ["CVE-1"]}
    vx.set_suggestion(row_, ub, vx.UB_RULES)
    vx.set_suggestion(row_, n1, vx.N_RULES)
    assert row_["suggestion"] == ub and row_["suggestion_more"] == [n1]
    # 各自重算只換自己的，不動別人的
    vx.set_suggestion(row_, None, vx.UB_RULES)
    assert row_["suggestion"] == n1 and "suggestion_more" not in row_
    vx.set_suggestion(row_, ub, vx.UB_RULES)
    vx.set_suggestion(row_, None, vx.N_RULES)
    assert row_["suggestion"] == ub and "suggestion_more" not in row_
    both = rp_row(suggestion=ub, suggestion_more=[n1])
    txt = rp.suggestion_text(both)
    assert "UEFI 映像裡沒有這個函式庫" in txt and "建議（N1）" in txt
    assert len(rp.all_suggestions(both)) == 2


# ---------- cra_report.py 整合（summary.json 的 vex.nvidia_distro） ----------

def _report(tmp_path, db_args, env=None):
    import os
    import subprocess
    import test_cra_nvidia as tn
    from test_cra_report import make_project
    st, detail, nvb = tn.nb.match(tn.R39, tn.TABLE, tn.fresh_mirror(), "nvidia-bulletins.json")
    scan = tn.nv_scan(tmp_path / "s", nvb)
    proj = make_project(tmp_path / "p")
    e = {k: v for k, v in os.environ.items() if k != "GRYPE_DB_CACHE_DIR"}
    e.update(CRA_COMPANY_CONFIG="none", **(env or {}))
    r = subprocess.run([sys.executable, "-I", str(HERE.parent / "cra_report.py"), "--project", str(proj), "--scan", str(scan), *db_args],
                       capture_output=True, text=True, timeout=120, env=e)
    sm = proj / "CRA" / "Reports" / "summary.json"
    return r, (json.loads(sm.read_text(encoding="utf-8"))["vex"]["nvidia_distro"] if sm.exists() else None)


def _fresh():
    import datetime
    return (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S+00:00")


def test_report_summary_records_source_path_schema_and_build_time(tmp_path):
    db = make_db(str(tmp_path / "vulnerability.db"), POLKIT, built=_fresh())
    r, nvd = _report(tmp_path, ["--grype-db", db])
    assert nvd["checked"] is True and nvd["reason"] is None
    assert nvd["db"]["source"] == "option" and nvd["db"]["path"] == db and nvd["db"]["model"] == 6 and nvd["db"]["built"]
    r, nvd = _report(tmp_path / "e", [], env={"GRYPE_DB_CACHE_DIR": str(tmp_path)})
    assert nvd["checked"] is True and nvd["db"]["source"] == "env"


def test_report_stale_or_wrong_schema_db_is_checked_false(tmp_path):
    db = make_db(str(tmp_path / "vulnerability.db"), POLKIT, built="2020-01-01 00:00:00+00:00")
    r, nvd = _report(tmp_path, ["--grype-db", db])
    assert nvd["checked"] is False and "older than 3 days" in nvd["reason"] and "2020-01-01" in nvd["reason"] and nvd["remapped"] == {}
    v5 = make_db(str(tmp_path / "v5.db"), POLKIT, model=5, built=_fresh())
    r, nvd = _report(tmp_path / "x", ["--grype-db", v5])
    assert r.returncode == 64 and "not a Grype v6" in r.stderr and nvd is None
    # 環境變數指到不是 v6 的資料庫：報告照產生，checked=false 與原因
    (tmp_path / "envdir").mkdir()
    make_db(str(tmp_path / "envdir" / "vulnerability.db"), POLKIT, model=5, built=_fresh())
    r, nvd = _report(tmp_path / "y", [], env={"GRYPE_DB_CACHE_DIR": str(tmp_path / "envdir")})
    assert nvd["checked"] is False and "not a Grype v6" in nvd["reason"]


def test_report_explicit_missing_db_is_an_error_without_env_fallback(tmp_path):
    make_db(str(tmp_path / "vulnerability.db"), POLKIT, built=_fresh())
    r, nvd = _report(tmp_path / "m", ["--grype-db", str(tmp_path / "nope")], env={"GRYPE_DB_CACHE_DIR": str(tmp_path)})
    assert r.returncode == 64 and "no vulnerability.db found" in r.stderr and nvd is None
    r, nvd = _report(tmp_path / "n", [])
    assert nvd["checked"] is False and "no Grype DB given" in nvd["reason"]


# ---------- 沒有解開的 rootfs：用 pkgdb 的完整 dpkg 檔案擁有者清單 ----------

def write_owners(d, lines, partial=False):
    d.mkdir(parents=True, exist_ok=True)
    (d / "dpkg-file-owners").write_text(("#partial\n" if partial else "") + "\n".join(lines) + "\n", encoding="utf-8")
    return d


OWNER_LINES = ["polkitd\t/usr/lib/polkit-1/polkitd", "libpolkit-gobject-1-0\t/usr/lib/aarch64-linux-gnu/libpolkit-gobject-1.so.0",
               "bash\t/usr/bin/bash", "coreutils\t/bin/ls"]


def test_owner_list_alone_never_proves_absence(tmp_path):
    owners, why = nd.load_owners(write_owners(tmp_path / "pkgdb", OWNER_LINES))
    assert why is None and "/usr/bin/ls" in owners                       # /bin/ls 正規化成 /usr/bin/ls
    # 只有 dpkg 擁有者清單：狀態不明（None），dpkg 的證據留成備註
    st, note = nd.binary_check("CVE-2021-4034", None, None, owners, {"polkitd", "libpolkit-gobject-1-0"})
    assert st is None and "not listed by any installed package; non-package files not checked" in note and "/usr/bin/pkexec" in note
    assert nd.binary_check("CVE-2021-4034", None, None, owners, {"somethingelse"}) == (None, None)
    assert nd.binary_check("CVE-2021-4034", None, None, owners, None) == (None, None)
    owners2, _ = nd.load_owners(write_owners(tmp_path / "p2", OWNER_LINES + ["pkexec\t/usr/bin/pkexec"]))
    st, note = nd.binary_check("CVE-2021-4034", None, None, owners2, {"polkitd"})
    assert st == "present" and "pkexec" in note
    assert nd.binary_check("CVE-2021-4034", None, None, None, {"polkitd"}) == (None, None)


def write_listing(d, lines, header="#complete"):
    d.mkdir(parents=True, exist_ok=True)
    (d / "rootfs-files").write_text(header + "\n" + "\n".join(lines) + "\n", encoding="utf-8")
    return d


LISTING = ["dir\t/usr\t", "dir\t/usr/bin\t", "file\t/usr/bin/bash\t", "symlink\t/bin\tusr/bin", "file\t/usr/lib/polkit-1/polkitd\t"]


def test_complete_rootfs_listing_decides_presence_and_absence(tmp_path):
    files, why = nd.load_rootfs_files(write_listing(tmp_path / "a", LISTING))
    assert why is None
    st, note = nd.binary_check("CVE-2021-4034", None, files, None, None)
    assert st == "absent" and "complete listing of the root file system" in note and "/usr/bin/pkexec" in note
    # dpkg 沒有擁有、但清單裡有（RD 的映像建置放進去的）→ present，即使擁有者清單說沒有
    files2, _ = nd.load_rootfs_files(write_listing(tmp_path / "b", LISTING + ["file\t/usr/bin/pkexec\t"]))
    owners, _ = nd.load_owners(write_owners(tmp_path / "pkgdb", OWNER_LINES))
    st, note = nd.binary_check("CVE-2021-4034", None, files2, owners, {"polkitd"})
    assert st == "present" and "root file system listing" in note
    # 符號連結本身也算存在；上層資料夾是符號連結（/bin -> usr/bin 之外的地方）要解開
    files3, _ = nd.load_rootfs_files(write_listing(tmp_path / "c", ["symlink\t/usr/bin/pkexec\t/opt/x", "dir\t/usr/bin\t"]))
    assert nd.binary_check("CVE-2021-4034", None, files3, None, None)[0] == "present"
    files4, _ = nd.load_rootfs_files(write_listing(tmp_path / "d", ["symlink\t/usr\t/opt/real", "dir\t/opt/real\t", "dir\t/opt/real/bin\t",
                                                                   "file\t/opt/real/bin/pkexec\t"]))
    assert nd.binary_check("CVE-2021-4034", None, files4, None, None)[0] == "present"


def test_partial_or_missing_listing_is_unknown_not_absent(tmp_path):
    assert nd.load_rootfs_files(write_listing(tmp_path / "p", LISTING, header="#partial"))[0] is None
    assert nd.load_rootfs_files(tmp_path / "none")[0] is None
    assert nd.load_rootfs_files(write_listing(tmp_path / "e", []))[0] is None
    assert nd.load_rootfs_files(None)[0] is None
    assert nd.binary_check("CVE-2021-4034", None, None, None, None) == (None, None)


def test_partial_missing_or_empty_owner_list_is_unknown(tmp_path):
    assert nd.load_owners(write_owners(tmp_path / "a", OWNER_LINES, partial=True))[0] is None
    assert nd.load_owners(tmp_path / "nothing")[0] is None
    assert nd.load_owners(write_owners(tmp_path / "e", []))[0] is None
    assert nd.load_owners(None)[0] is None
    link = tmp_path / "l"
    link.mkdir()
    (link / "dpkg-file-owners").symlink_to(write_owners(tmp_path / "t", OWNER_LINES) / "dpkg-file-owners")
    assert nd.load_owners(link)[0] is None                                 # 不跟隨符號連結


def test_remap_with_listing_closes_but_owner_list_alone_does_not(tmp_path):
    owners, _ = nd.load_owners(write_owners(tmp_path / "pkgdb", OWNER_LINES))
    files, _ = nd.load_rootfs_files(write_listing(tmp_path / "l", LISTING))
    db = make_db(str(tmp_path / "v.db"), POLKIT)
    res, inf = nd.remap(["CVE-2021-4034"], SBOM, db, cr.deb_vercmp, NOW, None, owners=owners, files=files)
    r = res["CVE-2021-4034"]
    assert r["state"] == "not_affected" and r["basis"] == "binary_absent" and "complete listing" in r["detail"]
    # 只有 dpkg 擁有者清單 → ambiguous，備註保留 dpkg 的證據
    res, _ = nd.remap(["CVE-2021-4034"], SBOM, db, cr.deb_vercmp, NOW, None, owners=owners)
    r = res["CVE-2021-4034"]
    assert r["state"] == "ambiguous" and "non-package files not checked" in r["detail"] and "non-package files not checked" in r["binary_note"]
    # 都沒有 → ambiguous
    assert nd.remap(["CVE-2021-4034"], SBOM, db, cr.deb_vercmp, NOW, None)[0]["CVE-2021-4034"]["state"] == "ambiguous"
    # 解開的 rootfs 資料夾優先：存在 → present
    res, _ = nd.remap(["CVE-2021-4034"], SBOM, db, cr.deb_vercmp, NOW, rootfs_with(tmp_path, True), owners=owners, files=files)
    assert res["CVE-2021-4034"]["state"] == "ambiguous"
    # 清單裡有（非 dpkg 擁有的檔案）→ 不能關閉
    files2, _ = nd.load_rootfs_files(write_listing(tmp_path / "l2", LISTING + ["file\t/usr/bin/pkexec\t"]))
    assert nd.remap(["CVE-2021-4034"], SBOM, db, cr.deb_vercmp, NOW, None, owners=owners, files=files2)[0]["CVE-2021-4034"]["state"] == "ambiguous"


def test_report_uses_pkgdb_owner_list_when_no_rootfs_dir(tmp_path):
    # cra_report 把 <scan>/../pkgdb 的清單交給 nvidia_distro；沒有清單 → summary 記 unavailable（不是 absent）
    db = make_db(str(tmp_path / "vulnerability.db"), POLKIT, built=_fresh())
    r, nvd = _report(tmp_path, ["--grype-db", db])
    assert nvd["checked"] is True and nvd["file_list"].startswith("unavailable")
    r, nvd = _report(tmp_path / "rf", ["--grype-db", db, "--rootfs-dir", str(rootfs_with(tmp_path / "x", False))])
    assert nvd["file_list"] == "rootfs-dir"


def test_wizard_passes_grype_db_to_cra_report():
    src = (HERE.parents[1] / "wizard" / "cra-scan.py").read_text(encoding="utf-8")
    assert '"--grype-db", str(GRYPE_CACHE)' in src and "GRYPE_CACHE.exists()" in src and '"--pkgdb", str(rd / "pkgdb")' in src


def test_rootfs_dir_errors_other_than_missing_are_unknown_not_absent(tmp_path, monkeypatch):
    root = rootfs_with(tmp_path, False)
    assert nd.binary_check("CVE-2021-4034", root)[0] == "absent"
    real = nd.os.lstat

    def boom(p, *a, **k):
        if str(p).endswith("usr/bin/pkexec"):
            raise PermissionError(13, "denied")
        return real(p, *a, **k)
    monkeypatch.setattr(nd.os, "lstat", boom)
    st, note = nd.binary_check("CVE-2021-4034", root)
    assert st is None and "could not be checked" in note and "PermissionError" in note
    # remap：不明 → ambiguous，不是 not_affected
    r = run(tmp_path, POLKIT, rootfs=root)["CVE-2021-4034"]
    assert r["state"] == "ambiguous" and "PermissionError" in r["detail"]

    def boom2(p, *a, **k):
        if str(p).endswith("usr/bin/pkexec"):
            raise NotADirectoryError(20, "x")
        return real(p, *a, **k)
    monkeypatch.setattr(nd.os, "lstat", boom2)
    assert nd.binary_check("CVE-2021-4034", root)[0] == "absent"        # 路徑上層不是資料夾＝檔案不可能存在
