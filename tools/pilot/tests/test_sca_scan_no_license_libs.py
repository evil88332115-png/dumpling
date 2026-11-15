"""pilot.env 設了 DejaCode／ScanCode.io 網址，但授權匯入的輔助程式（scio_prep.py 等）沒有帶進 dumpling 時：
E 段與 E2 段記 NOT_RUN（附原因），不能是 FAIL，也不能連到那些網址。"""
import json
import os
import subprocess

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
SBOM = os.path.join(ROOT, "tests", "fixtures", "sbom", "smoke.cdx.json")
E_STAGES = ["E-scancodeio-prep", "E-scancodeio-load-sbom", "E-dejacode-import", "E-package-scan-submit", "E-package-scans",
            "E-package-scan-update", "E-license-sync", "E-copyrights", "E-dejacode-licenses", "E-notice"]


# pilot.env 的金鑰用長而少見的值：sca-scan 收尾的秘密掃描（leakscan.py）會刪掉含有金鑰字串的輸出檔。以前用 "k1"／"k2"，
# 暫存路徑的亂數後綴剛好含 "k1" 時（例如 /tmp/dumpling-c1-tools.KQlk1F/…），記了路徑的 meta.json 被當成外洩刪掉 → 偶發 FileNotFoundError
K1 = "dumpling-test-dejacode-key-4f9c2a7e81"
K2 = "dumpling-test-scancodeio-key-b3d58e06c2"


def scan(tmp_path, env_text, extra=()):
    envf = tmp_path / "pilot.env"
    envf.write_text(env_text, encoding="utf-8")
    home = tmp_path / "home"
    home.mkdir()
    out = tmp_path / "out"
    env = {**os.environ, "PILOT_ENV": str(envf), "HOME": str(home), "GRYPE_DB_UPDATE": "off", "MIRROR_REFRESH_STATUS": ""}
    subprocess.run(["bash", os.path.join(ROOT, "tools/pilot/sca-scan"), "--sbom", SBOM, "--name", "t", "--out", str(out), *extra],
                   env=env, capture_output=True, timeout=300)
    rows = [l.split("\t") for l in (out / "status.tsv").read_text(encoding="utf-8").splitlines()[1:]]
    return {r[0]: (r[1], r[2]) for r in rows}


def test_missing_license_libs_are_not_run_not_fail(tmp_path):
    assert not os.path.exists(os.path.join(ROOT, "tools/pilot/lib/scio_prep.py")), "這個測試假設 scio_prep.py 沒帶進來"
    # 網址指向不會有人聽的埠：若程式真的去連，會變成 FAIL
    st = scan(tmp_path, "DEJACODE_URL=http://127.0.0.1:9\nDEJACODE_API_KEY=" + K1 + "\nSCANCODEIO_URL=http://127.0.0.1:9\nSCANCODEIO_API_KEY=" + K2 + "\n")
    for s in E_STAGES:
        assert st[s][0] == "NOT_RUN", (s, st[s])
        assert "沒有帶進 dumpling" in st[s][1] and "scio_prep.py" in st[s][1], (s, st[s])
    assert st["E-files-scan"][0] == "NOT_RUN"
    assert not [k for k, v in st.items() if k.startswith("E-") and v[0] in ("FAIL", "OK", "ATTENTION")]


def test_no_license_flag_keeps_original_reason(tmp_path):
    st = scan(tmp_path, "DEJACODE_URL=http://127.0.0.1:9\nDEJACODE_API_KEY=" + K1 + "\nSCANCODEIO_URL=http://127.0.0.1:9\n", extra=("--no-license",))
    assert st["E-scancodeio-prep"] == ("NOT_RUN", "--no-license")
    assert st["E-files-scan"][0] == "NOT_RUN"


def test_secret_values_do_not_collide_with_temp_paths(tmp_path):
    # 重現以前的偶發失敗：暫存資料夾的路徑含有金鑰字串時，記了路徑的輸出檔會被秘密掃描刪掉。這裡的金鑰不能是路徑的一部分
    assert K1 not in str(tmp_path) and K2 not in str(tmp_path) and len(K1) >= 20 and len(K2) >= 20


def test_meta_has_no_scancodeio_project(tmp_path):
    scan(tmp_path, "DEJACODE_URL=http://127.0.0.1:9\nDEJACODE_API_KEY=" + K1 + "\nSCANCODEIO_URL=http://127.0.0.1:9\n")
    st = (tmp_path / "out" / "status.tsv").read_text(encoding="utf-8")
    assert "\nF-secret-scan\tOK\t" in st, "秘密掃描刪了輸出檔（金鑰字串出現在輸出裡）"
    meta = json.loads((tmp_path / "out" / "meta.json").read_text(encoding="utf-8"))
    assert "scancodeio_project_uuid" not in meta and "scancodeio_files_project_uuid" not in meta
