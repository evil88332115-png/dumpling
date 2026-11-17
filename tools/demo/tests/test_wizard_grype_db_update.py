"""（dumpling 自己寫，T-06 PR-2）精靈交給 scan-flash-package.sh 的 GRYPE_DB_UPDATE：外面設了什麼就是什麼（內部鏡像的 import:<壓縮檔>、off），
沒設或空白才是 online。jetson/scan.sh、_shared/scan-disk.sh 用 grype_db_mode 設這個值，精靈不可以在中間蓋回 online
（2026-11-17 驗證時發現精靈寫死 online：內部模式照樣 grype db update；上游 sca-center 修正後同步）。
掃描指令用換掉 run／取工具的方式攔下來看實際的環境。"""
import importlib.util
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from test_wizard_plan import WIZ, site  # noqa: E402,F401  （site 是 fixture）


def scan_env(site, monkeypatch, name, value):
    tmp, flash, src, out, cfg, _ = site
    spec = importlib.util.spec_from_file_location(name, WIZ)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    pe = tmp / "pilot.env"
    pe.write_text("", encoding="utf-8")
    c = json.loads(cfg.read_text(encoding="utf-8"))
    c["pilot_env"] = str(pe)
    cfg.write_text(json.dumps(c), encoding="utf-8")
    seen = {}

    class Stop(Exception):
        pass

    def fake_run(cmd, log, env=None, cwd=None):
        seen["cmd"], seen["env"] = list(cmd), dict(env or {})
        raise Stop

    monkeypatch.setattr(mod, "resolve_tools_rev", lambda repo, rev: ("0" * 40, {"requested": rev, "worktree_dirty": False}))
    monkeypatch.setattr(mod, "extract_tools", lambda repo, commit, dest: dest.mkdir(parents=True))
    monkeypatch.setattr(mod, "run", fake_run)
    monkeypatch.setattr(sys, "argv", ["cra-scan.py", "--site-config", str(cfg), "--archive", str(flash), "--source", str(src), "--role", "both",
                                      "--generic-rules", "no", "--yes"])
    if value is None:
        monkeypatch.delenv("GRYPE_DB_UPDATE", raising=False)
    else:
        monkeypatch.setenv("GRYPE_DB_UPDATE", value)
    with pytest.raises(Stop):
        mod.main()
    assert seen["cmd"][0] == "tools/demo/scan-flash-package.sh"
    return seen["env"]


@pytest.mark.parametrize("value,want", [
    (None, "online"),
    ("", "online"),
    ("   ", "online"),
    ("off", "off"),
    ("online", "online"),
    ("import:/srv/mirror/gdb/v6/vulnerability-db_v6.1.10_x.tar.zst", "import:/srv/mirror/gdb/v6/vulnerability-db_v6.1.10_x.tar.zst"),
])
def test_scan_flash_package_gets_the_caller_setting(site, monkeypatch, value, want):
    env = scan_env(site, monkeypatch, "cra_scan_gdu_%d" % abs(hash(str(value))), value)
    assert env["GRYPE_DB_UPDATE"] == want
