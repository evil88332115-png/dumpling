"""說明欄截斷不可切壞 UTF-8。

GNU `cut -c` 依位元組截斷（coreutils 未實作多位元組字元），中文說明在第 500 位元組被切成半個字，
status.tsv 就不是合法 UTF-8，下游用 Python 讀取會 UnicodeDecodeError（2026-10-24 準確度第二次實機，rich 的計分）。
修正：截斷後接 `iconv -f UTF-8 -t UTF-8 -c` 丟掉不完整的位元組序列。
"""
import re
import subprocess

from pilot_fixtures import ROOT

CUT = re.compile(r"cut -[cb] ?1?-(\d+)\b")
STATUS_ONE_LINE = re.compile(r"^status\(\)\s*\{.*\}")


def shell_files():
    for base in ("scripts", "deploy"):
        for f in sorted((ROOT / base).rglob("*")):
            if f.is_file() and (f.suffix == ".sh" or f.name == "sca-scan") and "/tests/" not in str(f):
                yield f


def test_every_long_cut_is_followed_by_iconv():
    bad = []
    files = list(shell_files())
    assert len(files) > 20
    for f in files:
        for n, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            for m in CUT.finditer(line):
                if int(m.group(1)) < 100 or 'NAME=$(printf' in line:   # 雜湊前綴；專案名稱先經 tr -c 只留 ASCII
                    continue
                if not line[m.end():].startswith(" | iconv -f UTF-8 -t UTF-8 -c"):
                    bad.append(f"{f.relative_to(ROOT)}:{n}")
    assert not bad, bad


def test_one_line_status_functions_truncate_safely():
    """單行 status()：說明欄必須壓成一行並經過 iconv（real-projects.sh、firmware.sh 原本直接寫入多行說明）。"""
    bad = []
    for f in shell_files():
        for n, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            if STATUS_ONE_LINE.match(line) and ">>" in line and "${3:-}" in line:
                if not re.search(r"tr '[^']*\\n", line) or "iconv -f UTF-8 -t UTF-8 -c" not in line:
                    bad.append(f"{f.relative_to(ROOT)}:{n}")
    assert not bad, bad


def test_sca_scan_status_keeps_valid_utf8(tmp_path):
    src = (ROOT / "tools/pilot/sca-scan").read_text(encoding="utf-8")
    fn = next(l for l in src.splitlines() if l.startswith("status(){"))
    st = tmp_path / "status.tsv"
    detail = "a" + "說明" * 300          # 1 + 1800 位元組；第 500 位元組落在字的中間
    subprocess.run(["bash", "-c", f'{fn}\nstatus X-stage GAP "$1" >/dev/null', "_", detail],
                   env={"ST": str(st), "PATH": "/usr/bin:/bin"}, check=True)
    raw = st.read_bytes()
    text = raw.decode("utf-8")           # 不可丟例外
    stage, status, d = text.rstrip("\n").split("\t")
    assert (stage, status) == ("X-stage", "GAP")
    assert d.startswith("a說明") and len(d.encode()) <= 500 and len(d.encode()) >= 497
