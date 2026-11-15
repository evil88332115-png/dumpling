"""每天重跑韌體公告比對（fw_rematch.py、x86_firmware.py --rematch、pipeline/firmware-rematch.sh）：
- 輸入驗證：meta 壞掉（整份 GAP，只有總表）、sha256 不符、路徑穿越、符號連結、超過大小上限、不在 meta 裡的檔案、kind sbom 跳過；
  inventory 壞掉、缺鍵、型別不對（那一份 GAP，其他樣本照常）。
- 結果：key 唯一且穩定、舊結果清掉、表壞掉（GAP）、表過期、結果有變化（改過的合成規則表）、changed 讓狀態至少 ATTENTION。
- 一致性：同一份 inventory 用同樣的表重跑，results 與 SBOM（逐位元組）、inventory 的比對結果完全相同（合成映像、repo 內一份很小的真樣本、
  有設 DUMPLING_REMATCH_ART 時的 6 份真樣本）。
全部不連網、不讀映像（映像是合成的，只用來產生 inventory）。"""
import copy
import datetime
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
import fw_advisory as fa  # noqa: E402
import fw_advisory_rules as fr  # noqa: E402
import fw_rematch as fm  # noqa: E402
import nvidia_vbios_advisory as nva  # noqa: E402
import x86_firmware as xf  # noqa: E402
from cdx_schema import cdx_validator  # noqa: E402
from test_amd_psp import good_image, put  # noqa: E402
from test_fw_advisory_rules import INTEL, build as rules_build, doc as rules_doc, rule as rules_rule  # noqa: E402
from test_nvidia_vbios_advisory import doc as vb_doc, row as vb_row, write as vb_write  # noqa: E402
from test_x86_firmware import spi_image, vbios_rom  # noqa: E402

REPO = HERE.parents[2]
SCRIPT = REPO / "pipeline" / "firmware-rematch.sh"
SMALL = HERE / "data" / "rematch" / "ubuntu-ovmf-2024.02"
NOW_TEXT = "2026-11-21T02:00:00Z"
NOW = datetime.datetime(2026, 11, 21, 2, 0, tzinfo=datetime.timezone.utc)
RELEASE_NOW = datetime.datetime(2026, 11, 14, tzinfo=datetime.timezone.utc)
TAG = "firmware-demo/2026.11.20"


# ---------- 合成資料 ----------

def rules_table(tmp_path, fixed):
    """一條規則：Intel CSME 16.1 線、低於 fixed 的版本是 affected（合成的規則 ID）。"""
    r = rules_rule("INTEL-SA-00001", vendor="Intel", url=INTEL % "00001", match=[{"component": "intel_csme", "line": "16.1", "fixed_in": fixed}])
    return rules_build(tmp_path, rules_doc(r), name=f"rules-{fixed}.json")


def vbios_table(tmp_path, **row):
    return nva.load(vb_write(tmp_path, vb_doc(vb_row(devices=("2489",), **row)), name=f"vb-{len(list(tmp_path.glob('vb-*')))}.json"))


def inputs(tmp_path):
    (tmp_path / "board.bin").write_bytes(spi_image())                                    # ME 16.1.30.2307、兩份 Intel 微碼
    (tmp_path / "gpu.rom").write_bytes(vbios_rom(0x2489, "94.04.5E.00.92"))              # 一個 NVIDIA vBIOS
    return [tmp_path / "board.bin", tmp_path / "gpu.rom"]


def synthetic_inventory(tmp_path, rules, vbios, advisory=None):
    """Release 當時的 inventory（照 firmware.yml 的順序：inventory → status_of）。"""
    inv = xf.inventory(inputs(tmp_path), advisory=advisory, vbios_advisory=vbios, vbios_now=RELEASE_NOW, rules=rules)
    inv["status"], inv["detail"] = xf.status_of(inv)
    return inv


def attach(att, slug, inv, version="1.0", **over):
    """inventory 寫進附件資料夾，回 meta 的 samples[] 一項。"""
    name = f"fw-inventory-{slug}.json"
    data = (json.dumps(inv, ensure_ascii=False, indent=1) + "\n").encode("utf-8") if not isinstance(inv, bytes) else inv
    att.mkdir(exist_ok=True)
    (att / name).write_bytes(data)
    return {"slug": slug, "kind": "bios", "firmware_version": version, "inventory": name, "inventory_sha256": hashlib.sha256(data).hexdigest(), **over}


def write_meta(tmp_path, samples, **over):
    meta = {"schema": fm.META_SCHEMA, "tag": TAG, "samples": samples, **over}
    p = tmp_path / "firmware-meta.json"
    p.write_text(meta if isinstance(meta, str) else json.dumps(meta), encoding="utf-8")
    return p


def go(tmp_path, samples, tables, now=NOW_TEXT, meta=None, out="out", att=None):
    meta = meta or write_meta(tmp_path, samples)
    rc, lines = fm.run(xf, str(meta), str(att or tmp_path / "att"), now, str(tmp_path / out), tables)
    o = tmp_path / out
    summary = json.loads((o / "rematch-summary.json").read_text(encoding="utf-8")) if (o / "rematch-summary.json").exists() else None
    return rc, lines, o, summary


def load(o, slug):
    return json.loads((o / f"rematch-{slug}.json").read_text(encoding="utf-8"))


def tabs(rules, vbios, advisory=None):
    return {"rules": rules, "vbios_advisory": vbios, **({"advisory": advisory} if advisory is not None else {})}


@pytest.fixture
def tbl(tmp_path):
    """(Release 當時的規則表與 vBIOS 表, 今天的規則表與 vBIOS 表)：ME 與 vBIOS 的結果今天不同。"""
    then = (rules_table(tmp_path, "16.1.30.2000"), vbios_table(tmp_path, vbios_fixed_in="94.04.00.00.01"))
    today = (rules_table(tmp_path, "16.1.30.3000"), vbios_table(tmp_path, vbios_affected_below="94.04.6A.00.01", vbios_fixed_in="94.04.6A.00.01"))
    return then, today


def good_release(tmp_path, tbl_pair=None, slug="board-a"):
    """一個沒有變化的 Release：Release 當時與今天用同一組表。"""
    rules, vbios = rules_table(tmp_path, "16.1.30.2000"), vbios_table(tmp_path, vbios_fixed_in="94.04.00.00.01")
    inv = synthetic_inventory(tmp_path, rules, vbios)
    return attach(tmp_path / "att", slug, inv), inv, tabs(rules, vbios)


# ---------- 一致性：同一份 inventory 用同樣的表重跑，結果不變 ----------

def test_same_tables_give_identical_results_and_bytes(tmp_path):
    sample, inv, t = good_release(tmp_path)
    rc, lines, o, summary = go(tmp_path, [sample], t)
    doc = load(o, "board-a")
    assert doc["changed"] == [] and doc["schema"] == fm.REMATCH_SCHEMA and doc["now"] == NOW_TEXT and doc["release_tag"] == TAG
    assert doc["inventory_sha256"] == sample["inventory_sha256"] and doc["firmware_version"] == "1.0"
    # 重跑後的 inventory 整個（含每個元件的比對結果、三個區段、status、detail）與 Release 當時相同
    again = json.loads((tmp_path / "att" / sample["inventory"]).read_text(encoding="utf-8"))
    tables = fm.load_tables(xf, **t)
    info = fm.table_info(xf, tables, NOW)
    r = fm.rematch_inventory(xf, again, NOW, tables, info)
    assert r["changed"] == [] and again == json.loads(json.dumps(inv))
    comps, deps = xf.components(inv)
    assert (o / "fw-board-a.cdx.json").read_text(encoding="utf-8") == json.dumps(xf.bom(comps, deps), ensure_ascii=False, indent=1) + "\n"
    assert not list(cdx_validator().iter_errors(json.loads((o / "fw-board-a.cdx.json").read_text(encoding="utf-8"))))
    md = (o / "fw-inventory-board-a.md").read_text(encoding="utf-8")
    assert md.endswith(xf.markdown(inv)) and md.startswith("# 韌體公告重跑（2026-11-21T02:00:00Z）")


def test_amd_image_same_tables_same_bytes(tmp_path):
    img = good_image()
    put(img, 0x80000, b"AGESA!V9\x00" + b"ComboAM4v2PI 1.2.0.B" + b"\x00")
    p = tmp_path / "amd.bin"
    p.write_bytes(bytes(img))
    rules, vbios = rules_table(tmp_path, "16.1.30.2000"), vbios_table(tmp_path, vbios_fixed_in="94.04.00.00.01")
    inv = xf.inventory([p], vbios_advisory=vbios, vbios_now=RELEASE_NOW, rules=rules)
    inv["status"], inv["detail"] = xf.status_of(inv)
    assert inv["bios"][0]["amd"]["psp_firmware"] and inv["bios"][0]["amd"]["microcode"]
    sample = attach(tmp_path / "att", "amd-a", inv)
    rc, lines, o, summary = go(tmp_path, [sample], tabs(rules, vbios))
    doc = load(o, "amd-a")
    assert doc["changed"] == [] and {r["kind"] for r in doc["results"]} == {"rule"}
    keys = [r["key"] for r in doc["results"]]
    assert len(keys) == len(set(keys)) and any(k.startswith("rule:amd_psp:") for k in keys) and any(k.startswith("rule:amd_agesa:") for k in keys)
    comps, deps = xf.components(inv)
    assert (o / "fw-amd-a.cdx.json").read_text(encoding="utf-8") == json.dumps(xf.bom(comps, deps), ensure_ascii=False, indent=1) + "\n"


def tables_match_recorded(inv):
    """inventory 記的三張表的識別，是不是和 repo 當下的表相同（相同才能期待結果逐位元組相同）。"""
    t = fm.load_tables(xf)
    now = datetime.datetime(2026, 11, 15, tzinfo=datetime.timezone.utc)
    info = fm.table_info(xf, t, now)
    rec = (inv["rules_advisory"]["table"]["sha256"], inv["advisory"]["source"]["table_sha256"], inv["vbios_advisory"]["source"]["table_sha256"])
    cur = (info["fw_advisory_rules"]["sha256"], info["intel_microcode"]["table_sha256"], info["nvidia_vbios"]["sha256"])
    return rec == cur


def check_real_sample(inv_path, cdx_path):
    inv = json.loads(inv_path.read_text(encoding="utf-8"))
    original = copy.deepcopy(inv)
    tables = fm.load_tables(xf)
    info = fm.table_info(xf, tables, NOW)
    assert fm.inventory_problems(inv) == []
    r = fm.rematch_inventory(xf, inv, NOW, tables, info)
    if tables_match_recorded(original):                      # 表沒變：全部相同
        assert r["changed"] == [] and inv == original
        assert r["cdx"] == cdx_path.read_text(encoding="utf-8")
    else:                                                    # 表變了（Release 之後更新過）：只能是 changed 列出的差異，其餘結構不變
        assert fm.inventory_problems(inv) == []
        assert [c["key"] for c in r["changed"]] == sorted({c["key"] for c in r["changed"]}, key=[x["key"] for x in r["results"]].index)


def test_small_real_sample_same_tables_same_bytes():
    """repo 內一份很小的真樣本（Ubuntu OVMF 2024.02 的 fw-inventory.json 與 fw.cdx.json，CI 產物）。"""
    check_real_sample(SMALL / "fw-inventory.json", SMALL / "fw.cdx.json")


def test_real_samples_from_ci_artifacts():
    """DUMPLING_REMATCH_ART 指到一個資料夾（每個樣本一個子資料夾，裡面有 fw-inventory.json 與 fw.cdx.json）時，全部對照；沒設就不跑（檔案太大不進 repo）。"""
    art = os.environ.get("DUMPLING_REMATCH_ART")
    if not art:
        print("DUMPLING_REMATCH_ART 沒設：只跑 repo 內的小樣本")
        return
    dirs = sorted(p for p in Path(art).iterdir() if (p / "fw-inventory.json").exists())
    assert dirs, "DUMPLING_REMATCH_ART 底下沒有樣本"
    for d in dirs:
        check_real_sample(d / "fw-inventory.json", d / "fw.cdx.json")


# ---------- key ----------

def test_key_format_unique_and_stable(tmp_path):
    sample, inv, t = good_release(tmp_path)
    rc, lines, o, summary = go(tmp_path, [sample], t)
    doc = load(o, "board-a")
    img = inv["bios"][0]["sha256"][:16]
    keys = {r["key"]: r for r in doc["results"]}
    assert f"rule:bios_image:{img}:image" in keys and f"rule:intel_csme:{img}:me=16.1.30.2307" in keys
    assert "ucode:000B06A2/0xE0:0x4121" in keys and "ucode:000B0671/0x32:0x123" in keys
    assert f"vbios:10de:2489:{inv['vbios'][0]['sha256'][:16]}" in keys
    assert len(keys) == len(doc["results"]) == 5
    assert {r["kind"] for r in doc["results"]} == {"rule", "intel-microcode", "nvidia-vbios"}
    # 同一份 inventory 再跑一次，key 與順序不變
    rc, lines, o2, _ = go(tmp_path, [sample], t, out="out2")
    assert [r["key"] for r in load(o2, "board-a")["results"]] == [r["key"] for r in doc["results"]]
    assert load(o2, "board-a") == doc


def test_same_component_name_is_told_apart_by_content_then_ordinal(tmp_path):
    sample, inv, t = good_release(tmp_path)
    b = inv["bios"][0]
    # 兩個 FSP：同樣的版本、內容（stored_sha256）不同 → 用內容區分；兩個完全相同 → 加序號
    fsp = {"revision": "9.0.1.2", "stored_sha256": "a" * 64, "extended_image_revision": None, "file": "fspm.bin", "locations": []}
    b["cbfs"] = {"fsp": [fsp, {**fsp, "stored_sha256": "b" * 64}, fsp, fsp]}
    b["microcode"].append(copy.deepcopy(b["microcode"][0]))                                   # 同 CPUID／platform／revision、完全相同的內容
    b["microcode"].append({**copy.deepcopy(b["microcode"][0]), "sha256": "c" * 64})           # 同 CPUID／platform／revision、內容不同
    keys = [e["key"] for e in fm.collect(xf, json.loads(json.dumps(inv)))]
    assert len(keys) == len(set(keys))
    img = b["sha256"][:16]
    assert f"rule:intel_fsp:{img}:fsp=9.0.1.2:{'b' * 12}" in keys
    assert f"rule:intel_fsp:{img}:fsp=9.0.1.2:{'a' * 12}#1" in keys and f"rule:intel_fsp:{img}:fsp=9.0.1.2:{'a' * 12}#2" in keys and f"rule:intel_fsp:{img}:fsp=9.0.1.2:{'a' * 12}#3" in keys
    uc = [k for k in keys if k.startswith("ucode:000B06A2/0xE0:0x4121")]
    assert len(uc) == 3 and f"ucode:000B06A2/0xE0:0x4121:{'c' * 12}" in uc


def test_key_text_from_inventory_is_sanitized(tmp_path):
    sample, inv, t = good_release(tmp_path)
    inv["bios"][0]["me"]["version"] = "16.1 `x`|\n@a b#1"
    [k] = [e["key"] for e in fm.collect(xf, json.loads(json.dumps(inv))) if ":intel_csme:" in e["key"]]
    assert k.endswith(":me=16.1__x____a_b_1") and all(c not in k for c in " `|\n@#")


def test_uniquify():
    assert fm.uniquify([("a", None), ("b", None)]) == ["a", "b"]
    assert fm.uniquify([("a", lambda k: k + ":x"), ("a", lambda k: k + ":x")]) == ["a:x#1", "a:x#2"]
    assert fm.uniquify([("a", None), ("a", None), ("b", None)]) == ["a#1", "a#2", "b"]


# ---------- 舊結果清掉 ----------

def walk_keys(x, found=None):
    found = [] if found is None else found
    if isinstance(x, dict):
        for k, v in x.items():
            found.append(k)
            walk_keys(v, found)
    elif isinstance(x, list):
        for v in x:
            walk_keys(v, found)
    return found


def test_old_results_are_cleared_before_rematch(tmp_path):
    sample, inv, t = good_release(tmp_path)
    inv = json.loads(json.dumps(inv))
    b = inv["bios"][0]
    bogus_rule = {"suggestion": "affected", "reason": None, "rule_ids": ["OLD-RULE-9"], "state": "confirmed", "basis": "OLD-BASIS", "verification": {}, "results": [],
                  "evidence": [], "related": [], "source": "OLD-SOURCE"}
    b["rule_advisory"] = bogus_rule                                              # 有對應元件的位置：結果要被今天的蓋掉
    b["me"]["rule_advisory"] = bogus_rule
    b["fit"]["probe"] = {"nested": [{"rule_advisory": bogus_rule}]}              # 沒有元件會重寫的位置：只有清掉才不會留下
    b["microcode"][0]["advisory"] = {"match": "up-to-date", "reason": None, "basis": "OLD-BASIS", "candidates": [], "notes": ["OLD-NOTE"], "source": "OLD-SOURCE"}
    inv["vbios"][0]["advisory"] = {"match": "affected", "reason": None, "basis": "OLD-BASIS", "bulletins": ["9999"], "cves": [], "notes": [], "source": "OLD-SOURCE"}
    inv["advisory"] = {"status": "GAP", "gap": "OLD-GAP", "microcodes": 99, "counts": {"OLD": 1}}
    inv["vbios_advisory"] = {"status": "GAP", "gap": "OLD-GAP", "vbios": 99, "counts": {"OLD": 1}}
    inv["rules_advisory"] = {"status": "GAP", "gap": "OLD-GAP", "components": 99, "counts": {"OLD": 1}, "items": [], "errors": 0}
    inv["status"], inv["detail"] = "OK", "OLD-DETAIL"
    tables = fm.load_tables(xf, **t)
    info = fm.table_info(xf, tables, NOW)
    r = fm.rematch_inventory(xf, inv, NOW, tables, info)
    text = json.dumps(inv, ensure_ascii=False) + r["cdx"] + r["md"] + json.dumps(r["results"] + r["reasons"], ensure_ascii=False)
    assert "OLD-" not in text.replace("OLD-RULE-9", "") and inv["detail"] != "OLD-DETAIL"
    assert (inv["advisory"]["microcodes"], inv["vbios_advisory"]["vbios"], inv["rules_advisory"]["components"]) == (2, 1, 2)
    assert "OLD-RULE-9" not in json.dumps(r["results"]) and "OLD-RULE-9" not in r["cdx"]
    assert walk_keys(b["fit"]["probe"]) == ["nested"]
    assert inv["advisory"]["status"] == "OK" and inv["vbios_advisory"]["status"] == "OK" and inv["rules_advisory"]["status"] == "OK"
    # 舊的結果只留在 changed 的 before：Release 當時是 bogus，今天是真的
    by_key = {c["key"]: c for c in r["changed"]}
    uc = f"ucode:{b['microcode'][0]['cpuid']}/{b['microcode'][0]['platform_id']}:{b['microcode'][0]['revision']}"
    assert by_key[uc]["before"]["result"] == "up-to-date" and by_key[uc]["after"]["result"] == "affected-candidate"
    vk = next(k for k in by_key if k.startswith("vbios:"))
    assert by_key[vk]["before"] == {"result": "affected", "bulletins": ["9999"], "reason": None, "review": None} and by_key[vk]["after"]["result"] == "fixed"
    ik = next(k for k in by_key if ":intel_csme:" in k)
    assert by_key[ik]["before"] == {"result": "affected", "bulletins": ["OLD-RULE-9"], "reason": None, "review": "confirmed"}
    assert by_key[ik]["after"]["result"] == "not-affected"


def test_strip_results_keeps_everything_else():
    inv = {"bios": [{"file": "a", "rule_advisory": {"x": 1}, "me": {"version": "1", "rule_advisory": {}}, "microcode": [{"cpuid": "1", "advisory": {}, "keep": 1}]}],
           "vbios": [{"device": "2489", "advisory": {}, "keep": 2}], "advisory": {}, "vbios_advisory": {}, "rules_advisory": {}, "status": "OK", "detail": "d",
           "comparison": [1], "limits": {"a": 1}}
    fm.strip_results(inv)
    assert inv == {"bios": [{"file": "a", "me": {"version": "1"}, "microcode": [{"cpuid": "1", "keep": 1}]}], "vbios": [{"device": "2489", "keep": 2}],
                   "comparison": [1], "limits": {"a": 1}}


# ---------- 結果有變化 ----------

def test_changed_results_with_modified_tables(tmp_path, tbl):
    (r_then, v_then), (r_now, v_now) = tbl
    inv = synthetic_inventory(tmp_path, r_then, v_then)
    assert inv["bios"][0]["me"]["rule_advisory"]["suggestion"] == "not-affected" and inv["vbios"][0]["advisory"]["match"] == "fixed"
    sample = attach(tmp_path / "att", "board-a", inv)
    rc, lines, o, summary = go(tmp_path, [sample], tabs(r_now, v_now))
    doc = load(o, "board-a")
    assert doc["status"] == "ATTENTION" and rc == 2
    by = {c["key"]: c for c in doc["changed"]}
    me = next(k for k in by if ":intel_csme:" in k)
    vb = next(k for k in by if k.startswith("vbios:"))
    assert set(by) == {me, vb}
    assert by[me]["kind"] == "rule" and by[me]["before"] == {"result": "not-affected", "bulletins": ["INTEL-SA-00001"], "reason": None, "review": "preliminary"}
    assert by[me]["after"] == {"result": "affected", "bulletins": ["INTEL-SA-00001"], "reason": None, "review": "preliminary"}
    assert by[vb]["kind"] == "nvidia-vbios" and by[vb]["before"]["result"] == "fixed" and by[vb]["after"]["result"] == "affected" and by[vb]["after"]["bulletins"] == ["9001"]
    res = {r["key"]: r for r in doc["results"]}
    assert res[me]["result"] == "affected" and res[vb]["result"] == "affected"                 # results 是今天的結果
    assert any(x.startswith("changed since release: 2") for x in doc["reasons"])
    assert [s["status"] for s in summary["samples"]] == ["ATTENTION"]
    assert lines[0].startswith("FIRMWARE-REMATCH\tATTENTION\tboard-a\t") and "changed 2" in lines[0]
    md = (o / "fw-inventory-board-a.md").read_text(encoding="utf-8")
    assert "## 和 Release 當時不同的結果" in md and "not-affected" in md and "→ 今天 affected" in md
    cdx = json.loads((o / "fw-board-a.cdx.json").read_text(encoding="utf-8"))
    props = {c["name"]: {p["name"]: p["value"] for p in c["properties"]} for c in cdx["components"]}
    assert props["Intel CSE firmware"]["dumpling:advisory-rule-suggestion"] == "affected"
    assert all(p["dumpling:vuln-assessment"] == "NOT_ASSESSED" for p in props.values())


def test_review_state_change_alone_is_a_change(tmp_path):
    """結果和公告 ID 都沒變，只是規則從初審變成已確認：也列進 changed（議題用語不同）。"""
    vbios = vbios_table(tmp_path, vbios_fixed_in="94.04.00.00.01")
    then = rules_table(tmp_path, "16.1.30.3000")
    r = rules_rule("INTEL-SA-00001", vendor="Intel", url=INTEL % "00001", state="confirmed", match=[{"component": "intel_csme", "line": "16.1", "fixed_in": "16.1.30.3000"}])
    now = rules_build(tmp_path, rules_doc(r), name="rules-confirmed.json")
    sample = attach(tmp_path / "att", "board-a", synthetic_inventory(tmp_path, then, vbios))
    rc, lines, o, summary = go(tmp_path, [sample], tabs(now, vbios))
    [c] = load(o, "board-a")["changed"]
    assert c["before"]["result"] == c["after"]["result"] == "affected" and (c["before"]["review"], c["after"]["review"]) == ("preliminary", "confirmed")


def test_changed_makes_the_status_at_least_attention_even_if_the_inventory_is_ok(tmp_path, tbl, monkeypatch):
    (r_then, v_then), (r_now, v_now) = tbl
    monkeypatch.setattr(xf, "status_parts", lambda inv: ("OK", "stub", []))              # 沒有任何讓 status_of 變 ATTENTION 的原因
    inv = synthetic_inventory(tmp_path, r_then, v_then)
    sample = attach(tmp_path / "att", "board-a", inv)
    rc, lines, o, summary = go(tmp_path, [sample], tabs(r_now, v_now))
    assert load(o, "board-a")["status"] == "ATTENTION" and rc == 2 and load(o, "board-a")["changed"]
    rc, lines, o, summary = go(tmp_path, [sample], tabs(r_then, v_then), out="out2")           # 沒有變化 → 照 status_parts：OK
    assert load(o, "board-a")["status"] == "OK" and load(o, "board-a")["changed"] == [] and rc == 0 and load(o, "board-a")["reasons"] == []


def test_result_without_release_time_result_is_listed_as_changed(tmp_path):
    sample, inv, t = good_release(tmp_path)
    inv = json.loads(json.dumps(inv))
    del inv["bios"][0]["me"]["rule_advisory"]
    sample = attach(tmp_path / "att", "board-a", inv)
    rc, lines, o, summary = go(tmp_path, [sample], t)
    [c] = load(o, "board-a")["changed"]
    assert c["before"] == {"result": None, "bulletins": [], "reason": None, "review": None} and c["after"]["result"] == "not-affected"


# ---------- 表壞掉、表過期 ----------

@pytest.mark.parametrize("which", ["intel_microcode", "nvidia_vbios", "fw_advisory_rules"])
def test_broken_table_is_gap_and_its_components_are_not_assessed(tmp_path, which):
    sample, inv, t = good_release(tmp_path)
    broken = {"intel_microcode": ("advisory", fa.TableError("table-unreadable", "structure: releases")),
              "nvidia_vbios": ("vbios_advisory", nva.TableError("table-invalid", "validate_table: broken")),
              "fw_advisory_rules": ("rules", fr.TableError("table-invalid", "rules[0]: broken"))}[which]
    t = {**t, broken[0]: broken[1]}
    rc, lines, o, summary = go(tmp_path, [sample], t)
    doc = load(o, "board-a")
    assert doc["status"] == "GAP" and rc == 2 and lines[0].startswith("FIRMWARE-REMATCH\tGAP\tboard-a\t")
    tb = doc["tables"][which]
    assert tb["status"] == "GAP" and "gap" in tb and all(tb[k] is None for k in tb if k not in ("status", "stale", "gap")) and tb["stale"] is False
    assert [doc["tables"][n]["status"] for n in fm.TABLES if n != which] == ["OK", "OK"]
    kind = {"intel_microcode": "intel-microcode", "nvidia_vbios": "nvidia-vbios", "fw_advisory_rules": "rule"}[which]
    rs = [r for r in doc["results"] if r["kind"] == kind]
    assert rs and all(r["result"] == "NOT_ASSESSED" and r["reason"] and r["bulletins"] == [] for r in rs)
    assert any(f"{which}: table cannot be used (GAP)" in x for x in doc["reasons"])
    assert (o / "fw-board-a.cdx.json").exists()
    assert summary["tables"][which]["status"] == "GAP" and summary["samples"] == [{"slug": "board-a", "status": "GAP", "output": "rematch-board-a.json",
                                                                                  "reasons": doc["reasons"]}]


def test_broken_table_gap_even_without_components_of_that_class(tmp_path):
    inv = xf.inventory([_empty(tmp_path)])
    inv["status"], inv["detail"] = xf.status_of(inv)
    sample = attach(tmp_path / "att", "empty", inv)
    t = tabs(rules_table(tmp_path, "16.1.30.2000"), nva.TableError("table-invalid", "x"))
    rc, lines, o, summary = go(tmp_path, [sample], t)
    assert load(o, "empty")["status"] == "GAP"


def _empty(tmp_path):
    p = tmp_path / "empty.bin"
    p.write_bytes(b"\x00" * 64)
    return p


def test_stale_vbios_table_downgrades_fixed_and_is_attention(tmp_path, monkeypatch):
    """表過期（mirror 日期超過 90 天）：fixed 降成 NOT_ASSESSED（table-stale）、ATTENTION、tables 的 stale 是 true。"""
    rules, vbios = rules_table(tmp_path, "16.1.30.2000"), vbios_table(tmp_path, vbios_fixed_in="94.04.00.00.01")
    inv = synthetic_inventory(tmp_path, rules, vbios)
    monkeypatch.setattr(xf, "status_parts", lambda i: ("OK", "stub", []))              # 只看過期這一項帶來的 ATTENTION
    sample = attach(tmp_path / "att", "board-a", inv)
    rc, lines, o, summary = go(tmp_path, [sample], tabs(rules, vbios), now="2026-11-21T02:00:00Z")
    assert load(o, "board-a")["tables"]["nvidia_vbios"]["stale"] is False and load(o, "board-a")["status"] == "OK"
    monkeypatch.undo()
    rc, lines, o, summary = go(tmp_path, [sample], tabs(rules, vbios), now="2027-03-01T00:00:00Z", out="out2")       # 鏡像 2026-11-13，超過 90 天
    doc = load(o, "board-a")
    vk = next(r for r in doc["results"] if r["kind"] == "nvidia-vbios")
    assert doc["tables"]["nvidia_vbios"]["stale"] is True and doc["tables"]["nvidia_vbios"]["status"] == "OK"
    assert vk["result"] == "NOT_ASSESSED" and vk["reason"] == "table-stale"
    assert doc["status"] == "ATTENTION" and any("過期" in x for x in doc["reasons"])
    assert summary["tables"]["nvidia_vbios"]["stale"] is True
    ch = [c for c in doc["changed"] if c["key"] == vk["key"]]
    assert ch and ch[0]["before"]["result"] == "fixed" and ch[0]["after"]["result"] == "NOT_ASSESSED"


def test_stale_table_without_vbios_is_visible_in_tables_only(tmp_path, monkeypatch):
    (tmp_path / "board.bin").write_bytes(spi_image())
    inv = xf.inventory([tmp_path / "board.bin"], rules=rules_table(tmp_path, "16.1.30.2000"))
    inv["status"], inv["detail"] = xf.status_of(inv)
    assert inv["vbios"] == []
    sample = attach(tmp_path / "att", "board-a", inv)
    vbios = vbios_table(tmp_path, vbios_fixed_in="94.04.00.00.01")
    rc, lines, o, summary = go(tmp_path, [sample], tabs(rules_table(tmp_path, "16.1.30.2000"), vbios), now="2027-03-01T00:00:00Z")
    assert load(o, "board-a")["tables"]["nvidia_vbios"]["stale"] is True and summary["tables"]["nvidia_vbios"]["stale"] is True
    assert not any("過期" in x for x in load(o, "board-a")["reasons"])


# ---------- 輸入驗證：meta ----------

def only_summary(o):
    return sorted(p.name for p in o.iterdir()) == ["rematch-summary.json"]


@pytest.mark.parametrize("text", [
    "not json", "[]", "{}", json.dumps({"schema": "other/1", "tag": TAG, "samples": []}),
    json.dumps({"schema": fm.META_SCHEMA, "samples": []}), json.dumps({"schema": fm.META_SCHEMA, "tag": "../x", "samples": []}),
    json.dumps({"schema": fm.META_SCHEMA, "tag": TAG, "samples": "x"}), json.dumps({"schema": fm.META_SCHEMA, "tag": TAG, "samples": []}),
    json.dumps({"schema": fm.META_SCHEMA, "tag": TAG, "samples": [{"slug": "a-sbom", "kind": "sbom"}]}),
    '{"schema": "dumpling-firmware-meta/1", "schema": "dumpling-firmware-meta/1", "tag": "firmware-demo/2026.11.20", "samples": []}',
    '{"schema": "dumpling-firmware-meta/1", "tag": "firmware-demo/2026.11.20", "samples": [], "x": NaN}',
])
def test_bad_meta_is_gap_with_only_the_summary(tmp_path, text):
    sample, inv, t = good_release(tmp_path)
    rc, lines, o, summary = go(tmp_path, None, t, meta=_meta_text(tmp_path, text))
    assert rc == 2 and only_summary(o)
    assert summary["meta_status"] == "GAP" and summary["samples"] == [] and summary["reasons"][0].startswith("rematch-input-invalid: ")
    assert summary["schema"] == fm.SUMMARY_SCHEMA and summary["tables"]["intel_microcode"]["status"] == "OK" and summary["now"] == NOW_TEXT
    assert len(lines) == 1 and lines[0].startswith("FIRMWARE-REMATCH\tGAP\t-\t")


def _meta_text(tmp_path, text):
    p = tmp_path / "firmware-meta.json"
    p.write_text(text, encoding="utf-8")
    return p


def test_meta_over_the_size_limit_and_not_utf8(tmp_path, monkeypatch):
    sample, inv, t = good_release(tmp_path)
    p = write_meta(tmp_path, [sample])
    monkeypatch.setattr(fm, "MAX_META", p.stat().st_size - 1)
    rc, lines, o, summary = go(tmp_path, None, t, meta=p)
    assert only_summary(o) and "larger than the limit" in summary["reasons"][0]
    monkeypatch.undo()
    p.write_bytes(b'{"schema": "\xff"}')
    rc, lines, o, summary = go(tmp_path, None, t, meta=p, out="out2")
    assert only_summary(o) and summary["meta_status"] == "GAP"


def test_meta_missing_or_symlink(tmp_path):
    sample, inv, t = good_release(tmp_path)
    rc, lines, o, summary = go(tmp_path, None, t, meta=tmp_path / "nope.json")
    assert only_summary(o) and "file not found" in summary["reasons"][0]
    real = write_meta(tmp_path, [sample])
    link = tmp_path / "meta-link.json"
    link.symlink_to(real)
    rc, lines, o, summary = go(tmp_path, None, t, meta=link, out="out2")
    assert only_summary(o) and "symbolic link" in summary["reasons"][0]


def test_too_many_samples(tmp_path):
    sample, inv, t = good_release(tmp_path)
    rc, lines, o, summary = go(tmp_path, [sample] * (fm.MAX_SAMPLES + 1), t)
    assert only_summary(o) and "more than" in summary["reasons"][0]


# ---------- 輸入驗證：單一樣本（其他樣本照常） ----------

def with_good(tmp_path, bad_samples, t_inv=None):
    """一個好的樣本加上若干壞的：回 (rc, lines, o, summary)。"""
    good, inv, t = good_release(tmp_path, slug="good")
    return go(tmp_path, [good, *bad_samples], t) + (inv,)


def reasons_of(summary, slug):
    return next(s for s in summary["samples"] if s["slug"] == slug)


def assert_only_this_sample_is_gap(summary, o, lines, slug, text):
    assert [s["status"] for s in summary["samples"] if s["slug"] != slug] == ["ATTENTION"]
    s = reasons_of(summary, slug)
    assert s["status"] == "GAP" and s["output"] == f"rematch-{slug}.json" and text in s["reasons"][0] and s["reasons"][0].startswith("rematch-input-invalid: ")
    doc = load(o, slug)
    assert doc["status"] == "GAP" and doc["results"] == [] and doc["changed"] == [] and doc["reasons"] == s["reasons"]
    assert not (o / f"fw-{slug}.cdx.json").exists() and not (o / f"fw-inventory-{slug}.md").exists()
    assert (o / "fw-good.cdx.json").exists() and load(o, "good")["results"]
    assert any(x.startswith(f"FIRMWARE-REMATCH\tGAP\t{slug}\t") for x in lines)


def test_sha256_mismatch_is_gap_for_that_sample_only(tmp_path):
    good, inv, t = good_release(tmp_path, slug="good")
    bad = attach(tmp_path / "att", "bad", inv)
    data = (tmp_path / "att" / bad["inventory"]).read_bytes()
    (tmp_path / "att" / bad["inventory"]).write_bytes(data.replace(b'"schema"', b'"schema" ', 1))          # meta 之後被改過的附件
    rc, lines, o, summary = go(tmp_path, [good, bad], t)
    assert rc == 2
    assert_only_this_sample_is_gap(summary, o, lines, "bad", "inventory sha256 does not match firmware-meta.json")


def test_inventory_file_missing_directory_and_symlink(tmp_path):
    good, inv, t = good_release(tmp_path, slug="good")
    att = tmp_path / "att"
    missing = {"slug": "missing", "kind": "bios", "firmware_version": "1", "inventory": "fw-inventory-missing.json", "inventory_sha256": "0" * 64}
    adir = {"slug": "adir", "kind": "bios", "firmware_version": "1", "inventory": "fw-inventory-adir.json", "inventory_sha256": "0" * 64}
    (att / "fw-inventory-adir.json").mkdir()
    link = attach(tmp_path / "other", "linked", inv)
    (att / "fw-inventory-linked.json").symlink_to(tmp_path / "other" / "fw-inventory-linked.json")           # sha256 對得上的符號連結也不收
    rc, lines, o, summary = go(tmp_path, [good, missing, adir, link], t)
    st = {x["slug"]: x for x in summary["samples"]}
    assert rc == 2 and st["good"]["status"] == "ATTENTION" and (o / "fw-good.cdx.json").exists()
    assert "file not found" in st["missing"]["reasons"][0]
    assert "not a regular file" in st["adir"]["reasons"][0]
    assert "symbolic link" in st["linked"]["reasons"][0]
    assert sorted(p.name for p in o.glob("fw-*")) == ["fw-good.cdx.json", "fw-inventory-good.md"]


def test_attachment_directory_missing(tmp_path):
    good, inv, t = good_release(tmp_path, slug="good")
    rc, lines, o, summary = go(tmp_path, [good], t, att=tmp_path / "nope")
    assert summary["samples"][0]["status"] == "GAP" and "attachment directory cannot be opened" in summary["samples"][0]["reasons"][0]


def test_path_traversal_and_bad_slugs(tmp_path):
    good, inv, t = good_release(tmp_path, slug="good")
    (tmp_path / "outside.json").write_bytes(json.dumps(inv).encode())
    sha = hashlib.sha256((tmp_path / "outside.json").read_bytes()).hexdigest()
    base = {"kind": "bios", "firmware_version": "1", "inventory_sha256": sha}
    bad = [{**base, "slug": "a", "inventory": "../outside.json"},                                       # 附件名要是 fw-inventory-<slug>.json
           {**base, "slug": "b", "inventory": "fw-inventory-a.json"},
           {**base, "slug": "c", "inventory": "/etc/passwd"},
           {**base, "slug": "d", "inventory": None},
           {**base, "slug": "../outside", "inventory": "fw-inventory-../outside.json"},                   # slug 不合
           {**base, "slug": "UPPER", "inventory": "fw-inventory-UPPER.json"},
           {**base, "slug": "x" * 64, "inventory": f"fw-inventory-{'x' * 64}.json"},
           {**base, "slug": ".a", "inventory": "fw-inventory-.a.json"},
           {**base, "slug": "summary", "inventory": "fw-inventory-summary.json"},
           {**base, "slug": 7, "inventory": "fw-inventory-7.json"}, {**base, "inventory": "x"}, "x",
           {**base, "slug": "e", "inventory": "fw-inventory-e.json", "inventory_sha256": "ABC"},
           {**base, "slug": "f", "inventory": "fw-inventory-f.json", "kind": "other"},
           {**base, "slug": "g", "inventory": "fw-inventory-g.json", "firmware_version": 3},
           {**base, "slug": "h", "inventory": "fw-inventory-h.json", "firmware_version": "a\nb"}]
    rc, lines, o, summary = go(tmp_path, [good, *bad], t)
    assert rc == 2 and sorted(p.name for p in o.iterdir() if p.name.startswith("rematch-") and p.name != "rematch-summary.json") == sorted(
        f"rematch-{s}.json" for s in ("good", "a", "b", "c", "d", "e", "f", "g", "h"))
    assert sorted(p.name for p in o.glob("fw-*")) == ["fw-good.cdx.json", "fw-inventory-good.md"]
    st = {s["slug"]: s for s in summary["samples"]}
    assert set(st) == {"good", "a", "b", "c", "d", "e", "f", "g", "h"} and all(st[k]["status"] == "GAP" for k in st if k != "good")
    assert "not fw-inventory-<slug>.json" in st["a"]["reasons"][0] and "no inventory" in st["d"]["reasons"][0]
    assert sum("no valid slug" in x for x in lines) == 7 and all("\t-\t" in x for x in lines if "no valid slug" in x)
    # 不在 meta 裡的檔案不會被讀、也沒有輸出
    assert not (o / "rematch-outside.json").exists()


def test_duplicate_slug_is_gap_for_every_entry_with_it(tmp_path):
    good, inv, t = good_release(tmp_path, slug="good")
    rc, lines, o, summary = go(tmp_path, [good, good], t)
    assert rc == 2 and [s["status"] for s in summary["samples"]] == ["GAP"] and "more than once" in summary["samples"][0]["reasons"][0]


def test_file_not_listed_in_meta_is_not_read(tmp_path):
    good, inv, t = good_release(tmp_path, slug="good")
    attach(tmp_path / "att", "extra", inv)                                                                # 附件資料夾裡有、meta 沒列
    rc, lines, o, summary = go(tmp_path, [good], t)
    assert [s["slug"] for s in summary["samples"]] == ["good"] and not (o / "rematch-extra.json").exists()


def test_sbom_kind_is_skipped_without_output(tmp_path):
    good, inv, t = good_release(tmp_path, slug="good")
    sbom = {"slug": "ns5x", "kind": "sbom", "firmware_version": "v1.6.0", "sbom": "fw-ns5x.cdx.json", "inventory": None, "inventory_sha256": None}
    sbom2 = {"slug": "ns5x-2", "kind": "sbom", "inventory": "fw-inventory-ns5x-2.json", "inventory_sha256": "0" * 64}          # 即使列了、也不讀
    rc, lines, o, summary = go(tmp_path, [sbom, good, sbom2], t)
    assert [s["slug"] for s in summary["samples"]] == ["good"] and not list(o.glob("*ns5x*")) and len(lines) == 1


def test_inventory_over_the_size_limit(tmp_path, monkeypatch):
    good, inv, t = good_release(tmp_path, slug="good")
    monkeypatch.setattr(fm, "MAX_INVENTORY", (tmp_path / "att" / good["inventory"]).stat().st_size - 1)
    rc, lines, o, summary = go(tmp_path, [good], t)
    assert summary["samples"][0]["status"] == "GAP" and "larger than the limit" in summary["samples"][0]["reasons"][0]


@pytest.mark.parametrize("raw,text", [
    (b"not json", "not valid JSON"), (b"\xff\xfe", "not valid JSON"), (b"[]", "inventory is not an object"), (b"{}", f"schema is not {fm.INVENTORY_SCHEMA}"),
    (b'{"schema": "sca-center-fw-inventory/2"}', "schema is not"), (b'{"schema": "x", "schema": "x"}', "not valid JSON"),
    (b"[" * 100000, "not valid JSON"), (b'{"schema": "sca-center-fw-inventory/1", "x": Infinity}', "not valid JSON"),
])
def test_inventory_not_json_or_wrong_schema(tmp_path, raw, text):
    good, inv, t = good_release(tmp_path, slug="good")
    bad = attach(tmp_path / "att", "bad", raw)
    rc, lines, o, summary = go(tmp_path, [good, bad], t)
    assert_only_this_sample_is_gap(summary, o, lines, "bad", text)


def mutate(inv, path, value="DEL"):
    inv = json.loads(json.dumps(inv))
    x = inv
    for p in path[:-1]:
        x = x[p]
    if value == "DEL":
        del x[path[-1]]
    else:
        x[path[-1]] = value
    return inv


@pytest.mark.parametrize("path,value,text", [
    (["intel_vbios"], "DEL", "inventory.intel_vbios is missing"),                          # 舊版程式產生、缺新的鍵
    (["advisory"], "DEL", "inventory.advisory is missing"),
    (["vbios_advisory"], "DEL", "inventory.vbios_advisory is missing"),
    (["rules_advisory"], "DEL", "inventory.rules_advisory is missing"),
    (["bios"], {}, "inventory.bios has the wrong type"),
    (["vbios"], None, "inventory.vbios has the wrong type"),
    (["bios", 0, "microcode"], "DEL", "bios[0].microcode is missing"),
    (["bios", 0, "sha256"], "ABC", "bios[0].sha256 has the wrong type"),
    (["bios", 0, "size"], True, "bios[0].size has the wrong type"),
    (["bios", 0, "me", "version"], 5, "bios[0].me.version has the wrong type"),
    (["bios", 0, "microcode", 0, "cpuid"], 5, "bios[0].microcode[0].cpuid has the wrong type"),
    (["bios", 0, "regions", 0], "x", "bios[0].regions[0] is not an object"),
    (["vbios", 0, "images"], "DEL", "vbios[0].images is missing"),
    (["vbios", 0, "device"], None, "vbios[0].device has the wrong type"),
    (["bios", 0], 5, "bios[0] is not an object"),
])
def test_inventory_missing_or_wrong_keys_are_gap(tmp_path, path, value, text):
    good, inv, t = good_release(tmp_path, slug="good")
    bad = attach(tmp_path / "att", "bad", mutate(inv, path, value))
    rc, lines, o, summary = go(tmp_path, [good, bad], t)
    assert_only_this_sample_is_gap(summary, o, lines, "bad", text)


def test_unexpected_content_that_passes_the_shape_check_is_gap_not_an_exception(tmp_path):
    good, inv, t = good_release(tmp_path, slug="good")
    inv = json.loads(json.dumps(inv))
    inv["bios"][0]["microcode"][0]["extended_signatures"] = [5]                                  # 型別檢查只到「是 list」；內容怪到比對丟例外
    bad = attach(tmp_path / "att", "bad", inv)
    inv2 = json.loads(json.dumps(inv))
    inv2["bios"][0]["file"] = "a\ud800b"                                                          # 單獨的代理字元：寫不出 UTF-8
    inv2["bios"][0]["microcode"][0]["extended_signatures"] = []
    bad2 = attach(tmp_path / "att", "bad2", json.dumps(inv2, ensure_ascii=True).encode())
    rc, lines, o, summary = go(tmp_path, [good, bad, bad2], t)
    assert rc == 2 and all(s["status"] in ("GAP", "ATTENTION") for s in summary["samples"])
    for slug in ("bad", "bad2"):
        s = reasons_of(summary, slug)
        assert s["status"] == "GAP" and "inventory could not be processed" in s["reasons"][0], s
    assert reasons_of(summary, "good")["status"] == "ATTENTION"


def test_real_looking_text_in_inventory_does_not_reach_the_summary_lines(tmp_path):
    good, inv, t = good_release(tmp_path, slug="good")
    inv = json.loads(json.dumps(inv))
    inv["bios"][0]["file"] = "x.zip!a\tb\nFIRMWARE-REMATCH\tOK\tfake\tx"
    sample = attach(tmp_path / "att", "weird", inv)
    rc, lines, o, summary = go(tmp_path, [sample], t)
    assert len(lines) == 1 and lines[0].startswith("FIRMWARE-REMATCH\tATTENTION\tweird\t") and lines[0].count("\t") == 3 and "\n" not in lines[0]


# ---------- 輸出與參數 ----------

def test_summary_matches_the_interface_example(tmp_path, tbl):
    (r_then, v_then), (r_now, v_now) = tbl
    inv = synthetic_inventory(tmp_path, r_then, v_then)
    ok = attach(tmp_path / "att", "board-a", inv)
    bad = attach(tmp_path / "att", "board-b", inv, firmware_version="2024.02-2ubuntu0.10")
    bad["inventory_sha256"] = "d" * 64
    rc, lines, o, summary = go(tmp_path, [ok, bad], tabs(r_now, v_now))
    ex = json.loads((REPO / "pipeline" / "watch" / "tests" / "data" / "firmware-rematch-summary.example.json").read_text(encoding="utf-8"))
    assert set(summary) - {"meta_status"} == set(ex) - {"_note"}
    assert summary["schema"] == ex["schema"] and set(summary["tables"]) == set(ex["tables"])
    for name in summary["tables"]:
        assert set(ex["tables"][name]) <= set(summary["tables"][name])
    assert {k for s in summary["samples"] for k in s} <= {"slug", "status", "output", "reasons"}
    doc = load(o, "board-a")
    exd = json.loads((REPO / "pipeline" / "watch" / "tests" / "data" / "firmware-rematch.example.json").read_text(encoding="utf-8"))
    assert set(doc) == set(exd) - {"_note"}
    assert set(doc["results"][0]) == set(exd["results"][0]) and set(doc["changed"][0]) == set(exd["changed"][0]) and set(doc["tables"]) == set(exd["tables"])
    assert set(doc["changed"][0]["before"]) >= set(exd["changed"][0]["before"])


def test_summary_is_written_last_and_nothing_is_left_on_failure(tmp_path, monkeypatch):
    good, inv, t = good_release(tmp_path, slug="good")
    orig = fm.Writer.write

    def boom(self, name, text):
        if name == "rematch-summary.json":
            raise OSError(28, "No space left")
        return orig(self, name, text)
    monkeypatch.setattr(fm.Writer, "write", boom)
    rc, lines, o, summary = go(tmp_path, [good], t)
    assert rc == 1 and lines == ["FIRMWARE-REMATCH\tFAIL\t-\tcannot write to --out (OSError)"] and list(o.iterdir()) == []


def test_now_must_be_utc_with_hour_00_to_23(tmp_path):
    good, inv, t = good_release(tmp_path, slug="good")
    for bad in ("", "2026-11-21", "2026-11-21T24:00:00Z", "2026-11-21T02:00:00", "2026-11-21T02:00:00+00:00", "2026-11-21 02:00:00Z", "2026-11-21T02:60:00Z",
                "2026-13-21T02:00:00Z", "2026-02-30T02:00:00Z", "2026-11-21T02:00:00.5Z", "x" * 100, None):
        with pytest.raises(fm.ArgError):
            fm.run(xf, str(write_meta(tmp_path, [good])), str(tmp_path / "att"), bad, str(tmp_path / "o"), t)
        assert not (tmp_path / "o").exists()
    for ok in ("2026-11-21T00:00:00Z", "2026-11-21T23:59:59Z"):
        assert fm.run(xf, str(write_meta(tmp_path, [good])), str(tmp_path / "att"), ok, str(tmp_path / f"o{ok[11:13]}"), t)[0] == 2


def test_out_must_be_new_or_empty(tmp_path):
    good, inv, t = good_release(tmp_path, slug="good")
    meta = write_meta(tmp_path, [good])
    (tmp_path / "full").mkdir()
    (tmp_path / "full" / "x").write_text("x")
    for out in ("full", "meta"):
        (tmp_path / "meta").write_text("x") if out == "meta" else None
        with pytest.raises(fm.ArgError):
            fm.run(xf, str(meta), str(tmp_path / "att"), NOW_TEXT, str(tmp_path / out), t)
    (tmp_path / "link").symlink_to(tmp_path / "full")
    with pytest.raises(fm.ArgError):
        fm.run(xf, str(meta), str(tmp_path / "att"), NOW_TEXT, str(tmp_path / "link"), t)
    (tmp_path / "empty").mkdir()
    assert fm.run(xf, str(meta), str(tmp_path / "att"), NOW_TEXT, str(tmp_path / "empty"), t)[0] == 2
    assert (tmp_path / "full" / "x").read_text() == "x"


def test_no_forbidden_words_or_nested_not_run(tmp_path, tbl):
    (r_then, v_then), (r_now, v_now) = tbl
    inv = synthetic_inventory(tmp_path, r_then, v_then)
    sample = attach(tmp_path / "att", "board-a", inv)
    rc, lines, o, summary = go(tmp_path, [sample], tabs(r_now, v_now))
    for p in o.iterdir():
        text = p.read_text(encoding="utf-8")
        for w in ("不受影響", "不適用", "NOT_RUN", "PASS"):
            assert w not in text, (p.name, w)
    md = (o / "fw-inventory-board-a.md").read_text(encoding="utf-8")
    assert "安全" not in md


def test_report_strings_are_escaped(tmp_path):
    good, inv, t = good_release(tmp_path, slug="good")
    inv = json.loads(json.dumps(inv))
    inv["bios"][0]["file"] = "[x](http://e.example/)@someone<b>|\n# h.zip!a"
    sample = attach(tmp_path / "att", "weird", inv)
    rc, lines, o, summary = go(tmp_path, [sample], t)
    md = (o / "fw-inventory-weird.md").read_text(encoding="utf-8")
    assert "<b>" not in md and "](http" not in md and "@someone" not in md.replace("@​", "")


# ---------- 入口（shell 與 python -I） ----------

def run_script(args, tmp_path):
    return subprocess.run(["bash", str(SCRIPT), *args], capture_output=True, text=True, timeout=120, env={**os.environ, "TMPDIR": str(tmp_path)})


def test_script_end_to_end_with_the_committed_tables(tmp_path):
    inv = xf.inventory(inputs(tmp_path), vbios_now=RELEASE_NOW)                        # repo 內的三張表
    inv["status"], inv["detail"] = xf.status_of(inv)
    sample = attach(tmp_path / "att", "board-a", inv)
    meta = write_meta(tmp_path, [sample])
    out = tmp_path / "out"
    r = run_script(["--meta", str(meta), "--dir", str(tmp_path / "att"), "--now", NOW_TEXT, "--out", str(out)], tmp_path)
    assert r.returncode == 2 and r.stdout.count("\n") == 1 and r.stdout.startswith("FIRMWARE-REMATCH\tATTENTION\tboard-a\t"), r.stdout + r.stderr
    doc = load(out, "board-a")
    assert doc["changed"] == [] and doc["tables"]["fw_advisory_rules"]["sha256"] == fr.TABLE_SHA256 and doc["tables"]["intel_microcode"]["table_sha256"] == fa.TABLE_SHA256
    assert doc["tables"]["nvidia_vbios"]["sha256"] == hashlib.sha256(nva.TABLE_PATH.read_bytes()).hexdigest()
    assert sorted(p.name for p in out.iterdir()) == ["fw-board-a.cdx.json", "fw-inventory-board-a.md", "rematch-board-a.json", "rematch-summary.json"]


@pytest.mark.parametrize("args,rc", [
    ([], 64), (["--meta", "m"], 64), (["--meta", "m", "--dir", "d", "--out", "o"], 64), (["--meta", "m", "--dir", "d", "--now", "x"], 64),
    (["--meta", "m", "--dir", "d", "--now", "2026-11-21T24:00:00Z", "--out", "o"], 64), (["--bogus"], 64),
    (["--meta", "m", "--dir", "d", "--now", NOW_TEXT, "--out", "o", "--extra", "x"], 64),
])
def test_script_argument_errors(tmp_path, args, rc):
    r = run_script(args, tmp_path)
    assert r.returncode == rc and r.stdout.startswith("FIRMWARE-REMATCH\tFAIL\t-\t") and r.stdout.count("\n") == 1, r.stdout + r.stderr


def test_x86_firmware_rematch_flag_arg_errors(tmp_path, capsys):
    assert xf.main(["--rematch", "--meta", "m"]) == 64
    assert capsys.readouterr().out.startswith("FIRMWARE-REMATCH\tFAIL\t-\t")
    assert xf.main(["--rematch", "--meta", "m", "--dir", "d", "--now", "bad", "--out", str(tmp_path / "o")]) == 64
    assert not (tmp_path / "o").exists()
