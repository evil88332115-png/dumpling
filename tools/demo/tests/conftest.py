"""沿用 tools/cra/tests/conftest.py 的規則：DUMPLING_REQUIRE_TEST_DATA=1 時任何 skip 都視為失敗（CI 的判準）。

conftest 的 hook 只作用在所在資料夾，所以這裡以路徑載入同一份實作並以相同名稱註冊，不另寫一套（比照 D-017；不載入 sca-center 的 integration/conftest.py）。
"""
import importlib.util
from pathlib import Path

_src = Path(__file__).resolve().parents[2] / "cra" / "tests" / "conftest.py"
_spec = importlib.util.spec_from_file_location("_dumpling_cra_conftest", _src)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

pytest_runtest_makereport = _mod.pytest_runtest_makereport
pytest_make_collect_report = _mod.pytest_make_collect_report
