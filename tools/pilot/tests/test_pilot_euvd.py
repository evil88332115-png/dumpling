"""EUVD 鏡像（tools/mirror/euvd.sh）與 CVE 標註（lib/euvd.py，C-euvd）。
合成的小型原始檔，格式取自 2026-11-02 實際下載的 /api/dump/cve-euvd-mapping（CSV）與 /api/kev/dump（JSON）。
鏡像腳本以 file:// 網址（EUVD_API_URL）跑完整流程，不連網。"""
import datetime
import json
import lzma
import os
import subprocess

import pytest

from pilot_fixtures import PILOT, ROOT, dfind, gmatch

LIB = PILOT / "lib" / "euvd.py"
MIRROR = ROOT / "tools" / "mirror" / "euvd.sh"
TODAY = datetime.datetime.now(datetime.timezone.utc).date()
RECENT = (TODAY - datetime.timedelta(days=2)).isoformat()
NOW = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

MAPPING = ["euvd_id,cve_id",
           "EUVD-2024-16861,CVE-2024-1086",      # 在 KEV（核心，CISA）
           "EUVD-2025-11377,CVE-2025-22022",     # 在 EUVD、不在 KEV
           "EUVD-2025-5169,CVE-2025-21756",
           "EUVD-2023-54750,CVE-2023-4911",      # 在 KEV（CISA 與 EU KEV）
           "EUVD-2024-1,not-a-cve",              # 格式不符：只計數
           "EUVD-2024-2,CVE-2024-0002\tx"]       # 夾帶 tab：只計數
KEV = [{"cveId": "CVE-2024-1086", "euvdId": "EUVD-2024-16861", "dateAdded": "2024-05-30", "sources": ["cisa_kev"]},
       {"cveId": "CVE-2023-4911", "euvdId": "EUVD-2023-54750", "dateAdded": "2023-11-21", "sources": ["cisa_kev", "eukev_kev"]},
       {"cveId": "CVE-2026-118527", "dateAdded": RECENT, "sources": ["cisa_kev"]},   # 還沒有 EUVD 編號（實際資料有 1 筆）
       {"cveId": 12, "sources": "x"}]                                               # 不合格：只計數
SMALL = {"EUVD_MIN_MAPPING_ROWS": "1", "EUVD_MIN_KEV_ENTRIES": "1"}


def raw_dir(tmp_path, mapping=MAPPING, kev=KEV):
    d = tmp_path / "api"
    (d / "dump").mkdir(parents=True)
    (d / "kev").mkdir()
    (d / "dump" / "cve-euvd-mapping").write_text("\n".join(mapping) + "\n", encoding="utf-8")
    (d / "kev" / "dump").write_text(json.dumps(kev), encoding="utf-8")
    return d


def env(**kw):
    e = dict(os.environ, **SMALL)
    e.update(kw)
    return e


def mirror(tmp_path, **kw):
    api = raw_dir(tmp_path)
    m = tmp_path / "mirror"
    r = subprocess.run(["bash", str(MIRROR), str(m), str(tmp_path / "manifest")], capture_output=True, text=True,
                       env=env(EUVD_API_URL=f"file://{api}", **kw))
    assert r.returncode == 0, r
    return m


def build_index(tmp_path, fetched=NOW, kev=KEV):
    """不經 shell，直接用 build 產生（可指定下載時間）。"""
    api = raw_dir(tmp_path, kev=kev)
    m = tmp_path / "mirror"
    (m / "raw").mkdir(parents=True)
    (m / "raw" / "cve-euvd-mapping.csv").write_bytes((api / "dump" / "cve-euvd-mapping").read_bytes())
    (m / "raw" / "kev-dump.json").write_bytes((api / "kev" / "dump").read_bytes())
    r = subprocess.run(["python3", "-I", str(LIB), "build", "--raw", str(m / "raw"), "--fetched", fetched, "--out", str(m / "index.tsv")],
                       capture_output=True, text=True)
    assert r.returncode == 0, r
    return m


def annotate(tmp_path, index, *inputs, extra=(), **kw):
    out = tmp_path / "euvd.json"
    args = ["python3", "-I", str(LIB), "annotate", "--index", str(index), "--out", str(out), *extra]
    for p in inputs:
        args += ["--cves", str(p)]
    r = subprocess.run(args, capture_output=True, text=True, env=env(**kw))
    lines = r.stdout.splitlines()
    assert len(lines) == 1, r
    assert "Traceback" not in r.stderr
    stage, st, detail = lines[0].split("\t")
    assert stage == "C-euvd"
    ev = json.loads(out.read_text(encoding="utf-8")) if r.returncode == 0 else None
    return r.returncode, st, detail, ev


def cvefile(tmp_path, text, name="cves.txt"):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def no_false_negative(ev):
    """不在 EUVD 或沒有索引時，絕不寫成「沒有被利用」。"""
    for c, v in (ev.get("cves") or {}).items():
        if v["exploited"] == "unknown":
            assert v["exploited_text"].startswith("unknown"), (c, v)
            assert "not exploited" not in v["exploited_text"]


# ---------- 鏡像腳本 ----------

def test_mirror_builds_index_and_manifest(tmp_path):
    m = mirror(tmp_path)
    lines = (m / "index.tsv").read_text(encoding="utf-8").splitlines()
    assert lines[0].startswith("# euvd-index 1\t") and "mapping_bad=2" in lines[0] and "kev_bad=1" in lines[0]
    assert lines[1].split("\t") == ["cve", "euvd_ids", "exploited", "kev_date_added", "kev_sources"]
    rows = {x.split("\t")[0]: x.split("\t") for x in lines[2:]}
    assert set(rows) == {"CVE-2023-4911", "CVE-2024-1086", "CVE-2025-21756", "CVE-2025-22022", "CVE-2026-118527"}
    assert rows["CVE-2023-4911"] == ["CVE-2023-4911", "EUVD-2023-54750", "1", "2023-11-21", "cisa_kev,eukev_kev"]
    assert rows["CVE-2026-118527"] == ["CVE-2026-118527", "", "1", RECENT, "cisa_kev"]
    assert rows["CVE-2025-22022"][2] == "0"
    assert [x.split("\t")[0] for x in lines[2:]] == ["CVE-2023-4911", "CVE-2024-1086", "CVE-2025-21756", "CVE-2025-22022",
                                                     "CVE-2026-118527"]   # 依年份與號碼排序
    man = (tmp_path / "manifest").read_text(encoding="utf-8")
    assert "# source_mapping: file://" in man and "./index.tsv" in man and "./raw/kev-dump.json" in man
    r = subprocess.run(["bash", str(MIRROR), "--check", str(m)], capture_output=True, text=True, env=env())
    assert r.returncode == 0 and "FAIL" not in r.stdout, r


def test_mirror_refuses_overwrite(tmp_path):
    m = mirror(tmp_path)
    r = subprocess.run(["bash", str(MIRROR), str(m), str(tmp_path / "manifest2")], capture_output=True, text=True, env=env())
    assert r.returncode == 3 and "拒絕覆蓋" in r.stderr


@pytest.mark.parametrize("change,msg", [
    (lambda m: (m / "index.tsv").write_text((m / "index.tsv").read_text().replace("\t0\t", "\t1\t", 1)), "重建的結果不同"),
    (lambda m: (m / "raw" / "kev-dump.json").write_text("{}"), "頂層不是陣列"),
    (lambda m: (m / "raw" / "cve-euvd-mapping.csv").write_text("cve,euvd\n"), "表頭"),
    (lambda m: (m / "raw" / "kev-dump.json").unlink(), "缺少 kev-dump.json"),
])
def test_mirror_check_detects_tampering(tmp_path, change, msg):
    m = mirror(tmp_path)
    change(m)
    r = subprocess.run(["bash", str(MIRROR), "--check", str(m)], capture_output=True, text=True, env=env())
    assert r.returncode == 1 and "FAIL" in r.stdout and msg in r.stdout, r


def test_mirror_check_stale_and_too_small(tmp_path):
    m = build_index(tmp_path, fetched="2026-01-01T00:00:00Z")
    r = subprocess.run(["bash", str(MIRROR), "--check", str(m)], capture_output=True, text=True, env=env())
    assert r.returncode == 1 and "fetched_utc: 過期" in r.stdout
    r = subprocess.run(["bash", str(MIRROR), "--check", str(m)], capture_output=True, text=True,
                       env=env(EUVD_MAX_AGE_DAYS="100000", EUVD_MIN_MAPPING_ROWS="300000"))
    assert r.returncode == 1 and "可能下載不完整" in r.stdout and "過期" not in r.stdout


def test_mirror_check_kev_stale(tmp_path):
    kev = [dict(KEV[0])]   # 最新的 dateAdded 是 2024-05-30
    m = build_index(tmp_path, kev=kev)
    r = subprocess.run(["bash", str(MIRROR), "--check", str(m)], capture_output=True, text=True, env=env())
    assert r.returncode == 1 and "kev newest dateAdded: 過期" in r.stdout


# ---------- annotate ----------

def test_annotate_text_input(tmp_path):
    m = mirror(tmp_path)
    p = cvefile(tmp_path, "# 註解\nCVE-2024-1086, UBUNTU-CVE-2025-22022\nCVE-2099-0001  CVE-2026-118527\n\nCVE-2024-1086\n")
    rc, st, detail, ev = annotate(tmp_path, m, p)
    assert rc == 0 and st == "OK"
    assert "4 個 CVE" in detail and "1 個不在 EUVD" in detail and "不代表沒有被利用" in detail
    c = ev["cves"]
    assert c["CVE-2024-1086"]["euvd_ids"] == ["EUVD-2024-16861"] and c["CVE-2024-1086"]["exploited"] == "yes"
    assert c["CVE-2024-1086"]["links"] == ["https://euvd.enisa.europa.eu/vulnerability/EUVD-2024-16861"]
    assert c["CVE-2024-1086"]["kev_date_added"] == "2024-05-30" and c["CVE-2024-1086"]["kev_sources"] == ["cisa_kev"]
    assert c["CVE-2025-22022"]["exploited"] == "not_flagged" and c["CVE-2025-22022"]["in_euvd"] is True
    assert c["CVE-2099-0001"] == {"in_euvd": False, "euvd_ids": [], "exploited": "unknown", "exploited_text": "unknown (not in EUVD)",
                                  "kev_date_added": None, "kev_sources": [], "links": []}
    assert c["CVE-2026-118527"]["exploited"] == "yes" and c["CVE-2026-118527"]["euvd_ids"] == []
    assert ev["counts"] == {"cves": 4, "in_euvd": 3, "exploited": 2, "not_flagged": 1, "not_in_euvd": 1, "unknown_no_index": 0,
                            "non_cve_ids": 0}
    assert ev["source"]["fetched_utc"] and ev["source"]["age_days"] is not None
    no_false_negative(ev)


def test_annotate_dt_grype_and_xz_inputs(tmp_path):
    m = mirror(tmp_path)
    dt = [dfind("CVE-2024-1086", "linux", "6.8.0", "pkg:deb/ubuntu/linux@6.8.0", kev=True),
          dfind("UBUNTU-CVE-2025-21756", "linux", "6.8.0", "pkg:deb/ubuntu/linux@6.8.0", source="OSV"),
          dfind("GHSA-xxxx-yyyy-zzzz", "requests", "2.0", "pkg:pypi/requests@2.0", source="GITHUB",
                aliases=[{"ghsaId": "GHSA-xxxx-yyyy-zzzz", "cveId": "CVE-2023-4911"}])]
    grype = {"matches": [gmatch("CVE-2025-22022", "linux-image-tegra", "6.8", "pkg:deb/ubuntu/x", "deb"),
                         gmatch("GHSA-aaaa-bbbb-cccc", "x", "1", "pkg:npm/x@1", "npm", related=["CVE-2099-0002"])]}
    p1 = tmp_path / "findings.json"
    p1.write_text(json.dumps(dt), encoding="utf-8")
    p2 = tmp_path / "grype.json.xz"
    with lzma.open(p2, "wt", encoding="utf-8") as f:
        json.dump(grype, f)
    rc, st, _, ev = annotate(tmp_path, m, p1, p2)
    assert rc == 0 and st == "OK"
    assert set(ev["cves"]) == {"CVE-2024-1086", "CVE-2025-21756", "CVE-2023-4911", "CVE-2025-22022", "CVE-2099-0002"}
    assert ev["counts"]["non_cve_ids"] == 3   # 兩個 GHSA 的 vulnId 與一個 alias 的 ghsaId
    assert ev["cves"]["CVE-2023-4911"]["kev_sources"] == ["cisa_kev", "eukev_kev"]
    assert ev["inputs"] == [str(p1), str(p2)]


def test_annotate_json_string_list_and_object(tmp_path):
    m = mirror(tmp_path)
    rc, st, _, ev = annotate(tmp_path, m, cvefile(tmp_path, json.dumps(["CVE-2024-1086"]), "a.json"),
                             cvefile(tmp_path, json.dumps({"cves": ["CVE-2025-22022"]}), "b.json"))
    assert rc == 0 and st == "OK" and set(ev["cves"]) == {"CVE-2024-1086", "CVE-2025-22022"}


@pytest.mark.parametrize("damage,msg", [
    (None, "沒有 EUVD 鏡像資料夾"),
    (lambda m: (m / "index.tsv").unlink(), "沒有 index.tsv"),
    (lambda m: (m / "index.tsv").write_text("hello\n"), "第 1 行"),
    (lambda m: (m / "index.tsv").write_text("\n".join((m / "index.tsv").read_text().splitlines()[:-1]) + "\n"), "截斷"),
    (lambda m: (m / "index.tsv").write_text((m / "index.tsv").read_text().replace("EUVD-2024-16861", "<script>")), "格式錯誤"),
])
def test_annotate_unusable_index_is_gap_without_cves(tmp_path, damage, msg):
    """沒有可用的索引：GAP，而且輸出沒有 cves（讀取端不看 status，有 cves 就會算成「0 個已被利用」）。"""
    if damage is None:
        m = tmp_path / "nope"
    else:
        m = mirror(tmp_path)
        damage(m)
    rc, st, detail, ev = annotate(tmp_path, m, cvefile(tmp_path, "CVE-2024-1086 CVE-2025-22022\n"))
    assert rc == 0 and st == "GAP" and msg in detail and "不代表沒有被利用" in detail and "輸出不含 cves" in detail
    assert "cves" not in ev and ev["status"] == "GAP"
    assert ev["counts"]["unknown_no_index"] == 2 and ev["counts"]["cves"] == 2


def test_annotate_no_mirror_configured_is_gap_without_cves(tmp_path):
    rc, st, detail, ev = annotate(tmp_path, "", cvefile(tmp_path, "CVE-2024-1086\n"))
    assert rc == 0 and st == "GAP" and "沒有設定 EUVD 鏡像" in detail
    assert "cves" not in ev and ev["source"]["index_dir"] is None


def test_annotate_stale_index_is_gap_but_annotated(tmp_path):
    m = build_index(tmp_path, fetched="2026-01-01T00:00:00Z")
    rc, st, detail, ev = annotate(tmp_path, m, cvefile(tmp_path, "CVE-2024-1086\n"))
    assert rc == 0 and st == "GAP" and "過期" in detail and "2026-01-01T00:00:00Z" in detail
    assert ev["cves"]["CVE-2024-1086"]["exploited"] == "yes"
    rc, st, _, _ = annotate(tmp_path, m, cvefile(tmp_path, "CVE-2024-1086\n"), extra=["--max-age-days", "100000"])
    assert st == "OK"
    rc, st, _, _ = annotate(tmp_path, m, cvefile(tmp_path, "CVE-2024-1086\n"), EUVD_MAX_AGE_DAYS="100000", EUVD_KEV_MAX_AGE_DAYS="0")
    assert st == "GAP"


def test_annotate_no_cves_with_usable_index_is_ok(tmp_path):
    """輸入沒有 CVE、索引可用：OK（cves 是空的，真的沒有可標註的）；索引過期仍是 GAP。"""
    m = mirror(tmp_path)
    rc, st, detail, ev = annotate(tmp_path, m, cvefile(tmp_path, "# 沒有\n\n"))
    assert rc == 0 and st == "OK" and ev["cves"] == {} and "沒有任何 CVE" in detail
    rc, st, _, _ = annotate(tmp_path, m, cvefile(tmp_path, "[]", "e.json"))
    assert rc == 0 and st == "OK"
    m2 = build_index(tmp_path / "old", fetched="2026-01-01T00:00:00Z")
    rc, st, _, _ = annotate(tmp_path, m2, cvefile(tmp_path, "[]", "e.json"))
    assert st == "GAP"


@pytest.mark.parametrize("content,name,msg", [
    (None, "missing.txt", "無法讀取"),
    ("{not json", "bad.json", "不是合格的 JSON"),
    (json.dumps({"foo": 1}), "odd.json", "格式無法辨識"),
    (json.dumps([{"x": 1}]), "odd2.json", "格式無法辨識"),
    ("CVE-2024-1086\nsomething else\n", "bad.txt", "第 2 行不是 CVE 編號"),
    ("not xz", "bad.json.xz", "無法讀取"),
])
def test_annotate_bad_input_exit_3(tmp_path, content, name, msg):
    m = mirror(tmp_path)
    p = tmp_path / name
    if content is not None:
        p.write_text(content, encoding="utf-8")
    rc, st, detail, _ = annotate(tmp_path, m, p)
    assert rc == 3 and st == "FAIL" and msg in detail
    assert not (tmp_path / "euvd.json").exists()


def test_bad_arguments_and_unwritable_out_exit_3(tmp_path):
    r = subprocess.run(["python3", "-I", str(LIB), "annotate", "--index", str(tmp_path)], capture_output=True, text=True)
    assert r.returncode == 3 and r.stdout.startswith("C-euvd\tFAIL\t") and "Traceback" not in r.stderr
    r = subprocess.run(["python3", "-I", str(LIB)], capture_output=True, text=True)
    assert r.returncode == 3 and r.stdout.startswith("C-euvd\tFAIL\t")
    m = mirror(tmp_path)
    r = subprocess.run(["python3", "-I", str(LIB), "annotate", "--index", str(m), "--cves", str(cvefile(tmp_path, "CVE-2024-1086\n")),
                        "--out", str(tmp_path / "no" / "such" / "dir.json")], capture_output=True, text=True)
    assert r.returncode == 3 and "無法寫入" in r.stdout
    r = subprocess.run(["python3", "-I", str(LIB), "build", "--raw", str(m / "raw"), "--fetched", "yesterday", "--out", str(tmp_path / "i")],
                       capture_output=True, text=True)
    assert r.returncode == 3 and r.stdout.startswith("FAIL")


def test_annotate_nvidia_bulletins_input(tmp_path):
    """G3-10：scan/nvidia-bulletins.json 的 CVE（findings、presumed_included、needs_vendor_confirmation）也要查 EUVD／KEV；
    未審核列（unreviewed_would_match）不算。"""
    m = mirror(tmp_path)
    doc = {"schema": "sca-nvidia-bulletins-findings/2", "findings": [{"vulnerability": {"vulnId": "CVE-2024-1086"}}],
           "presumed_included": [{"bulletin": "1", "cve": "CVE-2023-4911"}],
           "needs_vendor_confirmation": [{"bulletin": "2", "cve": "CVE-2025-22022", "reason": "range_gap"}],
           "unreviewed_would_match": [{"bulletin": "3", "cve": "CVE-2099-0001"}]}
    p = cvefile(tmp_path, json.dumps(doc), "nvidia-bulletins.json")
    rc, st, _, ev = annotate(tmp_path, m, p)
    assert rc == 0 and st == "OK"
    assert set(ev["cves"]) == {"CVE-2024-1086", "CVE-2023-4911", "CVE-2025-22022"}
    assert ev["cves"]["CVE-2024-1086"]["exploited"] == "yes" and ev["cves"]["CVE-2023-4911"]["exploited"] == "yes"


def test_sca_scan_passes_nvidia_bulletins_to_euvd():
    t = (ROOT / "tools" / "pilot" / "sca-scan").read_text(encoding="utf-8")
    assert '[ -s "$NVB" ] && ea+=(--cves "$NVB")' in t
    assert t.index("NVB=$OUT/scan/nvidia-bulletins.json") < t.index('ea+=(--cves "$NVB")')    # C-nvidia-bulletins 先於 C-euvd
