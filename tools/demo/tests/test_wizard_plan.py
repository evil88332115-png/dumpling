"""cra-scan.py 精靈：用暫存資料夾裡的合成刷機包、原始碼壓縮檔與暫存站台設定跑 --plan-only，檢查 plan.json。不掃描。"""
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile

import pytest

WIZ = os.path.join(os.path.dirname(__file__), "..", "..", "wizard", "cra-scan.py")


def add(t, name, data=b""):
    ti = tarfile.TarInfo(name)
    ti.size = len(data)
    t.addfile(ti, io.BytesIO(data))


@pytest.fixture
def site(tmp_path):
    flash = tmp_path / "widget_V1.2.3.tbz2"
    flash.write_bytes(b"not-really-a-flash-package")
    src = tmp_path / "SourceCode"
    src.mkdir()
    with tarfile.open(src / "widget_source.tar.gz", "w:gz") as t:
        add(t, "work/linux/Makefile", b"VERSION = 6\nPATCHLEVEL = 8\nSUBLEVEL = 0\n")
        add(t, "work/linux/Kconfig")
        add(t, "work/linux/arch/arm64/Kconfig")
        add(t, "work/bootfw/uefi/readme", b"x")
    stable = tmp_path / "stable-6.8"
    stable.mkdir()
    out = tmp_path / "out"
    cfg = tmp_path / "wizard.json"
    cfg.write_text(json.dumps({"outroot": str(out), "root": str(tmp_path / "root"), "stable_git": {"6.8": str(stable)},
                               "repo": str(tmp_path / "repo")}), encoding="utf-8")
    return tmp_path, flash, src, out, cfg, stable


def run(args, env_extra=None):
    env = {"PATH": os.environ["PATH"], "HOME": args[0],
           **{k: os.environ[k] for k in ("LD_LIBRARY_PATH",) if k in os.environ}}   # CI 的 python 動態連結 libpython，要 LD_LIBRARY_PATH
    env.update(env_extra or {})
    return subprocess.run([sys.executable, "-I", WIZ, *args[1:]], capture_output=True, text=True, env=env)


def test_plan_only(site):
    tmp, flash, src, out, cfg, stable = site
    r = run([str(tmp), "--site-config", str(cfg), "--archive", str(flash), "--source", str(src), "--role", "both",
             "--generic-rules", "no", "--yes", "--plan-only"])
    assert r.returncode == 0, r.stdout + r.stderr
    dirs = list(out.iterdir())
    assert len(dirs) == 1 and dirs[0].name.startswith("widget-V1.2.3-")
    plan = json.loads((dirs[0] / "plan.json").read_text(encoding="utf-8"))
    assert plan["name"] == "widget" and plan["version"] == "V1.2.3"
    assert plan["kernel_version"] == "6.8"
    assert plan["kernel_source"].endswith("work/linux")
    assert plan["uefi_source"].endswith("work/bootfw/uefi")
    assert plan["stable_git"] == str(stable)
    assert plan["archive"] == str(flash)
    assert plan["role"] == "both" and plan["rootfs"] == "rootfs" and plan["generic_rules"] == "no"
    assert plan["config"] is None and plan["build_record"] is None and plan["oot"] == []
    assert "沒有 .md5 檔" in r.stdout          # 使用者可見訊息維持中文
    assert not (dirs[0] / "scan").exists()      # --plan-only 不掃描


def test_no_source_is_gap_not_cwd(site):
    # 沒給 --source：不去目前資料夾找（即使那裡剛好有原始碼壓縮檔），核心原始碼標 GAP，其他照跑
    tmp, flash, src, out, cfg, stable = site
    shutil.copy(src / "widget_source.tar.gz", tmp / "widget_source.tar.gz")
    env = {"PATH": os.environ["PATH"], "HOME": str(tmp), **{k: os.environ[k] for k in ("LD_LIBRARY_PATH",) if k in os.environ}}
    r = subprocess.run([sys.executable, "-I", WIZ, "--site-config", str(cfg), "--archive", str(flash), "--generic-rules", "no", "--yes",
                        "--plan-only"], capture_output=True, text=True, env=env, cwd=str(tmp))
    assert r.returncode == 0, r.stdout + r.stderr
    plan = json.loads((next(out.iterdir()) / "plan.json").read_text(encoding="utf-8"))
    assert plan["source_archive"] is None and plan["kernel_source"] is None and plan["kernel_version"] is None
    assert "沒有指定原始碼" in plan["source_note"] and "沒有指定原始碼" in r.stdout


def test_env_var_config_and_no_stable(site):
    tmp, flash, src, out, cfg, _ = site
    c = json.loads(cfg.read_text())
    c["stable_git"] = {}
    cfg.write_text(json.dumps(c))
    r = run([str(tmp), "--archive", str(flash), "--source", str(src), "--yes", "--plan-only", "--generic-rules", "no"],
            {"SCA_WIZARD_CONFIG": str(cfg)})
    assert r.returncode == 0, r.stdout + r.stderr
    plan = json.loads((next(out.iterdir()) / "plan.json").read_text(encoding="utf-8"))
    assert plan["stable_git"] is None


def test_missing_explicit_config_and_unknown_key(site):
    tmp, flash, src, out, cfg, _ = site
    r = run([str(tmp), "--site-config", str(tmp / "nope.json"), "--archive", str(flash), "--source", str(src), "--yes", "--plan-only"])
    assert r.returncode != 0 and "找不到站台設定檔" in r.stderr
    cfg.write_text(json.dumps({"outroot": str(out), "bogus": 1}))
    r = run([str(tmp), "--site-config", str(cfg), "--archive", str(flash), "--source", str(src), "--yes", "--plan-only"])
    assert r.returncode != 0 and "不認得的鍵" in r.stderr and "bogus" in r.stderr


def test_example_config_valid_and_placeholder_only():
    ex = os.path.join(os.path.dirname(WIZ), "wizard.example.json")
    d = json.load(open(ex))
    keys = {k for k in d if not k.startswith("_")}
    assert keys == {"repo", "root", "outroot", "python", "tools_bin", "pilot_env", "grype_seed", "grype_cache", "stable_git", "rules_template", "upstream"}
    assert "/media" not in json.dumps(d) and "/home" not in json.dumps(d)


def test_generic_rules_without_template_is_explicit(site):
    tmp, flash, src, out, cfg, _ = site
    r = run([str(tmp), "--site-config", str(cfg), "--archive", str(flash), "--source", str(src), "--generic-rules", "yes",
             "--yes", "--plan-only"])
    assert r.returncode == 0, r.stdout + r.stderr
    assert "沒有套用通用規則" in r.stdout and "無；套用通用規則" not in r.stdout
    plan = json.loads((next(out.iterdir()) / "plan.json").read_text(encoding="utf-8"))
    assert plan["generic_rules"] == "no" and plan["generic_rules_requested"] == "yes"


def test_scan_requires_pilot_env(site):
    tmp, flash, src, out, cfg, _ = site
    r = run([str(tmp), "--site-config", str(cfg), "--archive", str(flash), "--source", str(src), "--generic-rules", "no", "--yes"])
    assert r.returncode != 0 and "pilot_env" in r.stderr and "PILOT_ENV" in r.stderr
    assert not (next(out.iterdir()) / "wt").exists()      # 還沒取工具、沒掃描


# ---- 輸入清單（inputs.json／--platform）----
def _manifest(tmp, inputs, **kw):
    m = tmp / "inputs.json"
    m.write_text(json.dumps({"schema": 1, "platform": "t", "inputs": inputs, **kw}), encoding="utf-8")
    return m


def _inp(id, locate, required=True, **kw):
    return {"id": id, "label": f"項目{id}", "provider": "RD", "required": required, "kind": "other", "locate": locate,
            "affects": f"影響{id}", **kw}


def test_no_manifest_message(site):
    tmp, flash, src, out, cfg, _ = site
    r = run([str(tmp), "--site-config", str(cfg), "--archive", str(flash), "--source", str(src), "--generic-rules", "no", "--yes", "--plan-only"])
    assert r.returncode == 0, r.stdout + r.stderr
    assert "這個產品沒有輸入清單" in r.stdout
    d = next(out.iterdir())
    assert not (d / "inputs-check.json").exists()
    plan = json.loads((d / "plan.json").read_text(encoding="utf-8"))
    assert plan["inputs_check"] is None and plan["upstream_bsp"] is None and plan["upstream_source"] is None


def test_manifest_found_missing_and_yes(site):
    tmp, flash, src, out, cfg, _ = site
    up = tmp / "pub.tbz2"
    up.write_bytes(b"x")
    c = json.loads(cfg.read_text())
    c["upstream"] = {"set1": {"public_sources": str(up), "bsp": str(tmp / "no-such-bsp.tbz2")}}
    cfg.write_text(json.dumps(c))
    m = _manifest(tmp, [
        _inp("flash", {"plan": "archive", "companion": ".md5"}),
        _inp("kernel", {"plan": "kernel_source"}),
        _inp("br", {"plan": "build_record"}),
        _inp("glob_ok", {"glob": "*.tar.gz"}),
        _inp("glob_no", {"glob": "nothing*"}, required=False),
        _inp("ups", {"upstream": "public_sources"}),
        _inp("bsp", {"upstream": "bsp"}),
        _inp("board", {"manual": True}, required=False),
    ], upstream_set="set1")
    r = run([str(tmp), "--site-config", str(cfg), "--archive", str(flash), "--source", str(src), "--generic-rules", "no", "--yes",
             "--plan-only", "--inputs", str(m)])
    assert r.returncode == 0, r.stdout + r.stderr          # --yes：必要輸入缺也繼續
    assert "✗ 項目br" in r.stdout and "影響：影響br" in r.stdout and "✗ 項目bsp" in r.stdout
    assert "✓ 項目kernel" in r.stdout and "－ 項目board" in r.stdout
    d = next(out.iterdir())
    chk = json.loads((d / "inputs-check.json").read_text(encoding="utf-8"))
    st = {x["id"]: x for x in chk["inputs"] if x["kind"] != "step"}
    assert st["flash"]["status"] == "found" and ".md5" in st["flash"]["note"]
    assert st["br"]["status"] == "missing" and st["glob_ok"]["status"] == "found" and st["glob_no"]["status"] == "missing"
    assert st["ups"]["status"] == "found" and st["bsp"]["status"] == "missing" and st["board"]["status"] == "unchecked"
    assert chk["missing_required"] == ["br", "bsp"] and chk["missing_optional"] == ["glob_no"]
    assert chk["continued_with_missing_required"] is True
    plan = json.loads((d / "plan.json").read_text(encoding="utf-8"))
    assert plan["upstream_source"] == str(up) and plan["upstream_bsp"] is None
    assert plan["inputs_check"]["missing_required"] == ["br", "bsp"]


def test_manifest_from_config_pack_and_platform(site):
    tmp, flash, src, out, cfg, _ = site
    pack = tmp / "pack"
    pack.mkdir()
    (pack / "config.json").write_text("{}")
    _manifest(pack, [_inp("cfg", {"config_file": "config.json"}), _inp("x", {"config_file": "nope.json"}, required=False)])
    r = run([str(tmp), "--site-config", str(cfg), "--archive", str(flash), "--source", str(src), "--config", str(pack), "--yes", "--plan-only"])
    assert r.returncode == 0, r.stdout + r.stderr
    chk = json.loads((next(out.iterdir()) / "inputs-check.json").read_text(encoding="utf-8"))
    assert [x["status"] for x in chk["inputs"] if x["kind"] != "step"] == ["found", "missing"] and chk["missing_required"] == []
    r = run([str(tmp), "--site-config", str(cfg), "--archive", str(flash), "--source", str(src), "--name", "w2", "--generic-rules", "no",
             "--yes", "--plan-only", "--platform", "jetson"])
    assert r.returncode == 0, r.stdout + r.stderr
    d = next(p for p in out.iterdir() if p.name.startswith("w2-"))
    chk = json.loads((d / "inputs-check.json").read_text(encoding="utf-8"))
    assert chk["platform"] == "jetson" and "build_record" in chk["missing_required"] and "flash_package" not in chk["missing_required"]


def test_platform_templates_valid():
    plat = os.path.join(os.path.dirname(WIZ), "platforms")
    kinds = {"flash_package", "source_archive", "build_record", "extra_deliverable", "upstream_source", "upstream_bsp",
             "upstream_uefi", "vendor_bulletin", "board_test", "product_config", "other"}
    names = sorted(os.listdir(plat))
    assert names == ["jetson.json", "raspberrypi.json", "rockchip.json"]
    for n in names:
        d = json.load(open(os.path.join(plat, n), encoding="utf-8"))
        ids = [i["id"] for i in d["inputs"]]
        assert len(ids) == len(set(ids))
        for i in d["inputs"]:
            assert i["kind"] in kinds and len(set(i["locate"]) - {"companion", "base", "note"}) == 1 and i["label"] and "required" in i
        assert (n == "jetson.json") != d["draft"]
    assert len(json.load(open(os.path.join(plat, "jetson.json")))["inputs"]) == 12


def test_bad_manifest_stops(site):
    tmp, flash, src, out, cfg, _ = site
    m = _manifest(tmp, [{"id": "a", "label": "x", "kind": "bogus", "locate": {"manual": True}}])
    r = run([str(tmp), "--site-config", str(cfg), "--archive", str(flash), "--source", str(src), "--yes", "--plan-only", "--inputs", str(m)])
    assert r.returncode != 0 and "kind 不認得" in r.stderr


@pytest.mark.parametrize("bad_locate", [
    {"glob": "../outside/*"}, {"glob": "*/../../outside/*"}, {"glob": "/etc/passwd"}, {"glob": ""}, {"glob": 5},
    {"upstream": ["x"]}, {"plan": 3}, {"config_file": "../x"}, {"config_file": "/etc/passwd"}, {"glob": "a", "base": "elsewhere"},
    {"manual": "yes"}, {"plan": "archive", "companion": 1}])
def test_bad_locate_values_stop_cleanly(site, bad_locate):
    tmp, flash, src, out, cfg, _ = site
    m = _manifest(tmp, [_inp("bad", bad_locate)])
    r = run([str(tmp), "--site-config", str(cfg), "--archive", str(flash), "--source", str(src), "--yes", "--plan-only", "--inputs", str(m)])
    assert r.returncode != 0 and "bad" in r.stderr and "Traceback" not in r.stderr, r.stdout + r.stderr


def test_required_must_be_bool(site):
    tmp, flash, src, out, cfg, _ = site
    m = _manifest(tmp, [_inp("r", {"manual": True}, required="false")])
    r = run([str(tmp), "--site-config", str(cfg), "--archive", str(flash), "--source", str(src), "--yes", "--plan-only", "--inputs", str(m)])
    assert r.returncode != 0 and "required" in r.stderr and "Traceback" not in r.stderr


def test_glob_symlink_not_followed(site):
    tmp, flash, src, out, cfg, _ = site
    outside = tmp / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("x")
    (src / "lnk").symlink_to(outside)
    (src / "direct.txt").symlink_to(outside / "secret.txt")
    m = _manifest(tmp, [_inp("via_dir", {"glob": "lnk/*"}), _inp("via_file", {"glob": "direct.txt"}), _inp("real", {"glob": "*.tar.gz"})])
    r = run([str(tmp), "--site-config", str(cfg), "--archive", str(flash), "--source", str(src), "--generic-rules", "no", "--yes",
             "--plan-only", "--inputs", str(m)])
    assert r.returncode == 0, r.stdout + r.stderr
    chk = json.loads((next(out.iterdir()) / "inputs-check.json").read_text(encoding="utf-8"))
    st = {x["id"]: x["status"] for x in chk["inputs"] if x["kind"] != "step"}
    assert st == {"via_dir": "missing", "via_file": "missing", "real": "found"}


def test_required_manual_is_unconfirmed(site):
    tmp, flash, src, out, cfg, _ = site
    m = _manifest(tmp, [_inp("must_check", {"manual": True}), _inp("opt", {"manual": True}, required=False)])
    r = run([str(tmp), "--site-config", str(cfg), "--archive", str(flash), "--source", str(src), "--generic-rules", "no", "--yes",
             "--plan-only", "--inputs", str(m)])
    assert r.returncode == 0, r.stdout + r.stderr
    assert "未確認" in r.stdout
    chk = json.loads((next(out.iterdir()) / "inputs-check.json").read_text(encoding="utf-8"))
    assert chk["unconfirmed_required"] == ["must_check"] and chk["missing_required"] == []


def test_jetson_manual_notes_not_duplicated():
    d = json.load(open(os.path.join(os.path.dirname(WIZ), "platforms", "jetson.json"), encoding="utf-8"))
    assert all("無法自動檢查" not in i.get("note", "") for i in d["inputs"])


# ---- 接上既有工具：OP-TEE/TF-A、UEFI 平台設定、A0、板子結果、provenance commit ----
def _load_wizard():
    import importlib.util
    spec = importlib.util.spec_from_file_location("cra_scan_wizard", WIZ)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _tee_tree(root):
    (root / "atf" / "arm-trusted-firmware.t234").mkdir(parents=True)
    (root / "atf" / "arm-trusted-firmware.t234" / "Makefile").write_text("VERSION_MAJOR := 2\n")
    (root / "optee" / "optee_os" / "mk").mkdir(parents=True)
    (root / "optee" / "optee_os" / "mk" / "config.mk").write_text("CFG_OPTEE_REVISION_MAJOR ?= 4\n")


def _br_tar(path, members):
    with tarfile.open(path, "w:gz") as t:
        for name, kind, data in members:
            ti = tarfile.TarInfo(name)
            if kind == "file":
                ti.size = len(data)
                t.addfile(ti, io.BytesIO(data))
            elif kind == "sym":
                ti.type, ti.linkname = tarfile.SYMTYPE, "/etc/passwd"
                t.addfile(ti)
            elif kind == "hard":
                ti.type, ti.linkname = tarfile.LNKTYPE, "uefi/other"
                t.addfile(ti)
    return path


def test_extract_uefi_defines_regular_only(tmp_path):
    w = _load_wizard()
    good = "uefi/nvidia-config/p3768/config.dsc.inc"
    br = _br_tar(tmp_path / "BuildRecord-x.tar.gz", [
        (good, "file", b"CONFIG_X=1\n"),
        ("uefi/nvidia-config/evil/config.dsc.inc", "sym", b""),
        ("uefi/nvidia-config/hard/config.dsc.inc", "hard", b""),
        ("uefi/nvidia-config/../../escape/config.dsc.inc", "file", b"x"),
        ("uefi/Build/BUILDLOG_a.txt", "file", b"log"),
        ("kernel/Makefile", "file", b"x")])
    got, notes = w.extract_uefi_defines(br, tmp_path / "dest")
    assert [str(g.relative_to(tmp_path / "dest")) for g in got] == ["p3768/config.dsc.inc"]
    assert got[0].read_bytes() == b"CONFIG_X=1\n"
    assert sum("不是一般檔案" in n for n in notes) == 2
    assert not (tmp_path / "escape").exists() and not (tmp_path / "dest" / "evil").exists()


def test_extract_uefi_defines_oversize_and_missing(tmp_path, monkeypatch):
    w = _load_wizard()
    monkeypatch.setattr(w, "UEFI_DEFINES_MAX", 10)
    br = _br_tar(tmp_path / "a.tar.gz", [("uefi/nvidia-config/p/config.dsc.inc", "file", b"x" * 11)])
    got, notes = w.extract_uefi_defines(br, tmp_path / "d1")
    assert got == [] and any("超過" in n for n in notes)
    br2 = _br_tar(tmp_path / "b.tar.gz", [("kernel/Makefile", "file", b"x")])
    got, notes = w.extract_uefi_defines(br2, tmp_path / "d2")
    assert got == [] and any("沒有 uefi/nvidia-config" in n and "--uefi=" in n for n in notes)
    got, notes = w.extract_uefi_defines(tmp_path / "nope.tar.gz", tmp_path / "d3")
    assert got == [] and notes
    (tmp_path / "bad.tar.gz").write_bytes(b"not a tar")
    got, notes = w.extract_uefi_defines(tmp_path / "bad.tar.gz", tmp_path / "d4")
    assert got == [] and notes


def test_extract_uefi_defines_from_directory(tmp_path):
    w = _load_wizard()
    d = tmp_path / "BuildRecord"
    (d / "uefi" / "nvidia-config" / "p").mkdir(parents=True)
    (d / "uefi" / "nvidia-config" / "p" / "config.dsc.inc").write_text("A=1\n")
    (d / "uefi" / "nvidia-config" / "q").mkdir()
    (d / "uefi" / "nvidia-config" / "q" / "config.dsc.inc").symlink_to("/etc/passwd")
    got, notes = w.extract_uefi_defines(d, tmp_path / "x")
    assert [g.parent.name for g in got] == ["p"] and any("不是一般檔案" in n for n in notes)


def test_find_tee_tree(tmp_path):
    w = _load_wizard()
    ok, why = w.find_tee_tree(tmp_path)
    assert not ok and "TF-A" in why and "OP-TEE" in why
    _tee_tree(tmp_path)
    assert w.find_tee_tree(tmp_path) == (True, "")
    ok, why = w.find_tee_tree(tmp_path / "nope")
    assert not ok


def test_board_test_file_check(tmp_path):
    w = _load_wizard()
    f = tmp_path / "board-test-host-1.tar.gz"
    f.write_bytes(b"x")
    assert w.check_board_test_file(str(f)) is None
    (tmp_path / "other.tar.gz").write_bytes(b"x")
    assert "檔名" in w.check_board_test_file(str(tmp_path / "other.tar.gz"))
    (tmp_path / "board-net-l.tar.gz").symlink_to(f)
    assert w.check_board_test_file(str(tmp_path / "board-net-l.tar.gz"))
    assert w.check_board_test_file(str(tmp_path / "missing"))


def test_plan_has_new_steps_and_gaps_without_inputs(site):
    tmp, flash, src, out, cfg, _ = site
    r = run([str(tmp), "--site-config", str(cfg), "--archive", str(flash), "--source", str(src), "--generic-rules", "no", "--yes", "--plan-only"])
    assert r.returncode == 0, r.stdout + r.stderr          # 缺的輸入只記 GAP，不中止
    plan = json.loads((next(out.iterdir()) / "plan.json").read_text(encoding="utf-8"))
    assert plan["tee_source"] is None and "沒有廠商公開原始碼資料夾" in plan["tee_source_gap"]
    assert plan["uefi_platform_defines"] == [] and plan["board_test"] == []
    assert plan["a0_artifacts"] is False and plan["a0_source"] is False
    assert "GAP：沒有廠商公開原始碼資料夾" in r.stdout.replace("OP-TEE／TF-A 公開原始碼（--tee-source）：", "") or "OP-TEE／TF-A" in r.stdout
    assert "A0 上游基準" in r.stdout and "UEFI 平台設定" in r.stdout


def test_plan_with_tee_board_and_upstream(site):
    tmp, flash, src, out, cfg, _ = site
    pub = tmp / "pub"
    pub.mkdir()
    (pub / "public_sources.tbz2").write_bytes(b"x")
    (pub / "bsp.tbz2").write_bytes(b"x")
    _tee_tree(pub / "extract")           # 沒設定 public_sources_dir：由 public_sources 旁邊的 extract/ 推得
    bt = tmp / "board-test-h-1.tar.gz"
    bt.write_bytes(b"x")
    c = json.loads(cfg.read_text())
    c["upstream"] = {"set1": {"public_sources": str(pub / "public_sources.tbz2"), "bsp": str(pub / "bsp.tbz2")}}
    cfg.write_text(json.dumps(c))
    m = _manifest(tmp, [_inp("bt", {"manual": True}, required=False, kind="board_test")], upstream_set="set1")
    r = run([str(tmp), "--site-config", str(cfg), "--archive", str(flash), "--source", str(src), "--generic-rules", "no", "--yes",
             "--plan-only", "--inputs", str(m), "--board-test", str(bt)])
    assert r.returncode == 0, r.stdout + r.stderr
    d = next(out.iterdir())
    plan = json.loads((d / "plan.json").read_text(encoding="utf-8"))
    assert plan["tee_source"] == str(pub / "extract") and plan["tee_source_gap"] is None
    assert plan["board_test"] == [str(bt)] and plan["a0_artifacts"] is True and plan["a0_source"] is True
    chk = json.loads((d / "inputs-check.json").read_text(encoding="utf-8"))
    assert chk["inputs"][0]["status"] == "found"      # 舊清單把 board_test 標 manual：現在依 --board-test 判斷
    # 沒給 --board-test → missing（不是「無法檢查」更不是通過）
    r = run([str(tmp), "--site-config", str(cfg), "--archive", str(flash), "--source", str(src), "--generic-rules", "no", "--yes",
             "--plan-only", "--inputs", str(m), "--name", "second"])
    chk = json.loads((max(out.iterdir(), key=lambda p: p.stat().st_mtime) / "inputs-check.json").read_text(encoding="utf-8"))
    assert chk["inputs"][0]["status"] == "missing"


def test_bad_board_test_rejected(site):
    tmp, flash, src, out, cfg, _ = site
    (tmp / "x.tar.gz").write_bytes(b"x")
    r = run([str(tmp), "--site-config", str(cfg), "--archive", str(flash), "--source", str(src), "--generic-rules", "no", "--yes",
             "--plan-only", "--board-test", str(tmp / "x.tar.gz")])
    assert r.returncode != 0 and "board-test-" in r.stderr


def test_plan_uefi_defines_from_build_record(site):
    tmp, flash, src, out, cfg, _ = site
    br = _br_tar(tmp / "BuildRecord-w.tar.gz", [("uefi/nvidia-config/p/config.dsc.inc", "file", b"A=1\n"), ("kernel/Makefile", "file", b"x")])
    r = run([str(tmp), "--site-config", str(cfg), "--archive", str(flash), "--source", str(src), "--generic-rules", "no", "--yes",
             "--plan-only", "--build-record", str(br)])
    assert r.returncode == 0, r.stdout + r.stderr
    d = next(out.iterdir())
    plan = json.loads((d / "plan.json").read_text(encoding="utf-8"))
    assert len(plan["uefi_platform_defines"]) == 1 and plan["uefi_platform_defines"][0].endswith("p/config.dsc.inc")
    assert "建置紀錄裡有 1 份" in r.stdout


def test_provenance_uses_wizard_commit(tmp_path, monkeypatch):
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    import flash_package as fp
    plain = tmp_path / "wt"
    plain.mkdir()
    monkeypatch.delenv("SCA_CENTER_COMMIT", raising=False)
    assert fp.tool_commit(plain)["commit"] == "unknown"
    monkeypatch.setenv("SCA_CENTER_COMMIT", "a" * 40)
    assert fp.tool_commit(plain) == {"commit": "a" * 40, "from": "wizard-archive", "dirty": False}
    monkeypatch.setenv("SCA_CENTER_COMMIT", "not-a-hash")
    assert fp.tool_commit(plain)["commit"] == "unknown"


def test_board_import_status_exit2_is_not_failure(tmp_path):
    w = _load_wizard()
    log = tmp_path / "l.log"
    log.write_text("x\nD-board-test\tATTENTION\t3 findings\nD-kernel-modules\tGAP\tno lsmod\n")
    st, dt = w.board_import_status(2, log)
    assert st == "GAP" and "exit 2" in dt and "ATTENTION" in dt
    log.write_text("D-board-test\tOK\tfine\n")
    assert w.board_import_status(0, log)[0] == "OK"
    log.write_text("D-board-test\tFAIL\tbad\n")
    assert w.board_import_status(1, log)[0] == "FAIL"
    log.write_text("nothing useful\n")
    assert w.board_import_status(2, log)[0] == "FAIL"        # 沒有狀態行才當失敗
    assert w.board_import_status(0, tmp_path / "missing.log")[0] == "FAIL"


def test_merge_step_status_into_inputs_check(tmp_path):
    w = _load_wizard()
    (tmp_path / "inputs-check.json").write_text(json.dumps({"inputs": [{"id": "a", "kind": "other", "status": "found"}]}))
    w.merge_step_status(tmp_path, [{"id": "tee-source", "label": "L", "status": "GAP", "note": "n", "affects": "x"},
                                   {"id": "A0-source", "label": "L2", "status": "ATTENTION", "note": "d"}])
    w.merge_step_status(tmp_path, [{"id": "tee-source", "label": "L", "status": "FAIL", "note": "n2"}])      # 重複呼叫取代舊的 step 項
    d = json.loads((tmp_path / "inputs-check.json").read_text())
    assert [r["id"] for r in d["inputs"]] == ["a", "step:tee-source"] and d["inputs"][1]["status"] == "fail"
    w.merge_step_status(tmp_path / "newdir_missing_ok" if False else tmp_path, [{"id": "x", "label": "X", "status": "NOT_RUN"}])
    assert json.loads((tmp_path / "inputs-check.json").read_text())["inputs"][-1]["status"] == "not_run"


def test_plan_only_writes_step_gap_to_inputs_check(site):
    tmp, flash, src, out, cfg, _ = site
    c = json.loads(cfg.read_text())
    c["upstream"] = {"set1": {"public_sources": str(tmp / "nonexistent.tbz2")}}
    cfg.write_text(json.dumps(c))
    m = _manifest(tmp, [_inp("f", {"plan": "archive"})], upstream_set="set1")
    r = run([str(tmp), "--site-config", str(cfg), "--archive", str(flash), "--source", str(src), "--generic-rules", "no", "--yes",
             "--plan-only", "--inputs", str(m)])
    assert r.returncode == 0, r.stdout + r.stderr
    chk = json.loads((next(out.iterdir()) / "inputs-check.json").read_text(encoding="utf-8"))
    steps = {x["id"]: x for x in chk["inputs"] if x["kind"] == "step"}
    assert steps["step:tee-source"]["status"] == "gap" and steps["step:uefi-platform-defines"]["status"] == "gap"


def test_extract_uefi_defines_duplicates_dot_and_total_cap(tmp_path):
    w = _load_wizard()
    br = _br_tar(tmp_path / "d.tar.gz", [
        ("uefi/nvidia-config/p/config.dsc.inc", "file", b"OLD\n"),
        ("./uefi/nvidia-config/p/config.dsc.inc", "file", b"NEW\n"),
        ("uefi/nvidia-config/./config.dsc.inc", "file", b"DOT\n")])
    got, notes = w.extract_uefi_defines(br, tmp_path / "o")
    assert len(got) == 1 and got[0].read_bytes() == b"NEW\n" and any("重複成員" in n for n in notes)
    # 總量上限：全零的大成員讀到一半就停 → GAP，不採用任何一份
    big = _br_tar(tmp_path / "bomb.tar.gz", [("uefi/nvidia-config/p/config.dsc.inc", "file", b"A\n"), ("kernel/zero", "file", bytes(8 << 20))])
    got, notes = w.extract_uefi_defines(big, tmp_path / "o2", max_total=1 << 20)
    assert got == [] and any("上限" in n for n in notes)
    # 只收 .tar.gz／.tgz／.tar
    import lzma
    xz = tmp_path / "x.tar.xz"
    xz.write_bytes(lzma.compress(b"x"))
    got, notes = w.extract_uefi_defines(xz, tmp_path / "o3")
    assert got == [] and any(".tar.gz" in n for n in notes)


def test_extract_uefi_defines_folder_symlink_escape(tmp_path):
    w = _load_wizard()
    outside = tmp_path / "outside" / "nvidia-config" / "p"
    outside.mkdir(parents=True)
    (outside / "config.dsc.inc").write_text("X=1\n")
    d = tmp_path / "BuildRecord"
    (d / "uefi").mkdir(parents=True)
    (d / "uefi" / "nvidia-config").symlink_to(tmp_path / "outside" / "nvidia-config")
    got, notes = w.extract_uefi_defines(d, tmp_path / "x")
    assert got == [] and notes
    d2 = tmp_path / "BR2"
    (d2 / "uefi" / "nvidia-config").mkdir(parents=True)
    (d2 / "uefi" / "nvidia-config" / "p").symlink_to(outside)
    got, notes = w.extract_uefi_defines(d2, tmp_path / "x")
    assert got == []


# ---------- 工具版本：預設目前 checkout 的 HEAD，可覆寫，commit 寫進輸出 ----------

def _git(repo, *args):
    env = {**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_AUTHOR_NAME": "t",
           "GIT_AUTHOR_EMAIL": "t@example.invalid", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, env=env, check=True).stdout.strip()


@pytest.fixture
def toolrepo(tmp_path):
    """兩個 commit 的小 repo：v1 → v2（HEAD）；另有一個遠端 origin/main 停在 v1 之前沒有的內容（模擬「遠端 main 跟正在測的不同」）。"""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "work")
    (repo / "tool.txt").write_text("v1\n")
    _git(repo, "add", "."); _git(repo, "commit", "-q", "-m", "v1")
    v1 = _git(repo, "rev-parse", "HEAD")
    (repo / "tool.txt").write_text("v2\n")
    _git(repo, "commit", "-q", "-am", "v2")
    v2 = _git(repo, "rev-parse", "HEAD")
    # 假的遠端 main：另一條線上的 commit
    _git(repo, "checkout", "-q", "-b", "other", v1)
    (repo / "tool.txt").write_text("main-only\n")
    _git(repo, "commit", "-q", "-am", "remote main")
    remote_main = _git(repo, "rev-parse", "HEAD")
    _git(repo, "update-ref", "refs/remotes/origin/main", remote_main)
    _git(repo, "checkout", "-q", "work")
    return repo, v1, v2, remote_main


def test_tools_rev_defaults_to_checked_out_head_not_remote_main(toolrepo, tmp_path):
    repo, v1, v2, remote_main = toolrepo
    w = _load_wizard()
    commit, info = w.resolve_tools_rev(repo, None)
    assert commit == v2 != remote_main and info["requested"] == "HEAD" and info["commit"] == v2 and info["worktree_dirty"] is False
    w.extract_tools(repo, commit, tmp_path / "wt")
    assert (tmp_path / "wt" / "tool.txt").read_text() == "v2\n"           # 不是 origin/main 的內容
    assert not (tmp_path / "wt" / ".git").exists()


def test_tools_rev_override_and_dirty_worktree_is_not_included(toolrepo, tmp_path):
    repo, v1, v2, remote_main = toolrepo
    w = _load_wizard()
    (repo / "tool.txt").write_text("uncommitted\n")                        # 工作目錄的修改：不可混進去
    (repo / "untracked.txt").write_text("x\n")
    commit, info = w.resolve_tools_rev(repo, "HEAD")
    assert commit == v2 and info["worktree_dirty"] is True
    w.extract_tools(repo, commit, tmp_path / "wt")
    assert (tmp_path / "wt" / "tool.txt").read_text() == "v2\n" and not (tmp_path / "wt" / "untracked.txt").exists()
    # 覆寫：commit hash、分支名
    assert w.resolve_tools_rev(repo, v1)[0] == v1
    assert w.resolve_tools_rev(repo, "other")[0] == remote_main
    assert w.resolve_tools_rev(repo, "HEAD~1")[0] == v1


@pytest.mark.parametrize("bad", ["no-such-rev", "--output=x", "a b", "", "$(id)"])
def test_tools_rev_bad_values(toolrepo, bad):
    repo = toolrepo[0]
    w = _load_wizard()
    if bad == "":
        assert w.resolve_tools_rev(repo, bad)[0] == toolrepo[2]            # 空字串當作預設的 HEAD
        return
    with pytest.raises(w.ToolsRevError):
        w.resolve_tools_rev(repo, bad)


def test_tools_rev_not_a_git_checkout(tmp_path):
    w = _load_wizard()
    plain = tmp_path / "plain"
    plain.mkdir()
    with pytest.raises(w.ToolsRevError):
        w.resolve_tools_rev(plain, "HEAD")


def test_tools_rev_option_and_env_are_wired():
    s = open(WIZ, encoding="utf-8").read()
    assert '"--tools-rev"' in s and 'os.environ.get("DUMPLING_TOOLS_REV")' in s and 'or "HEAD")' in s
    body = s.split("== 1. 取工具 ==", 1)[1].split("== 2. 產品設定 ==", 1)[0]
    assert "tools-version.json" in body and 'rev-parse", "origin/main"' not in s


def test_platform_is_explicit_and_never_guessed(site):
    tmp, flash, src, out, cfg, stable = site
    base = [str(tmp), "--site-config", str(cfg), "--archive", str(flash), "--source", str(src), "--role", "both",
            "--generic-rules", "no", "--yes", "--plan-only"]
    r = run(base)
    assert r.returncode == 0, r.stdout + r.stderr
    assert json.loads((next(out.iterdir()) / "plan.json").read_text(encoding="utf-8"))["platform"] is None
    shutil.rmtree(out)      # 輸出資料夾名稱到分鐘，同一分鐘內重跑會被拒絕
    r = run(base + ["--platform", "rockchip"])
    assert r.returncode == 0, r.stdout + r.stderr
    assert json.loads((next(out.iterdir()) / "plan.json").read_text(encoding="utf-8"))["platform"] == "rockchip"
