"""DUMPLING_REQUIRE_TEST_DATA=1 時，任何 skip 都視為失敗。

CI 的判準是「skip 數必須為 0」：缺 jsonschema、資料缺一份、路徑改錯之類，
都不能讓測試悄悄少跑卻顯示通過。本機沒設這個變數時維持原本行為（缺套件就跳過）。
"""
import os

import pytest

# 非空且不是 "0" 就算嚴格（"1"、"true" 都是）
_STRICT = os.environ.get("DUMPLING_REQUIRE_TEST_DATA", "").strip() not in ("", "0")


def _fail(rep, where):
    reason = rep.longrepr[2] if isinstance(rep.longrepr, tuple) else str(rep.longrepr)
    rep.outcome = "failed"
    rep.longrepr = f"DUMPLING_REQUIRE_TEST_DATA=1 不允許 skip（{where}）：{reason}"
    return rep


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    out = yield
    rep = out.get_result()
    if _STRICT and rep.skipped:
        out.force_result(_fail(rep, "test"))


@pytest.hookimpl(hookwrapper=True)
def pytest_make_collect_report(collector):   # 模組層級 skip / importorskip
    out = yield
    rep = out.get_result()
    if _STRICT and rep.skipped:
        out.force_result(_fail(rep, "collect"))


# NVIDIA vBIOS 的公告比對（x86_firmware.vbios_advisory_section）預設用牆上時鐘判斷對照表過期。測試不能隨時間變動：
# 沒有明確傳 now（inventory 的 vbios_now）的測試一律用這個固定時間（對照表的 mirror.fetched_utc 是 2026-11-13，這個時間之後 90 天內不算過期）。
# 只影響測試；正式執行（沒有這個 fixture）仍用現在時間。
import datetime  # noqa: E402

FIXED_VBIOS_NOW = datetime.datetime(2026, 11, 14, tzinfo=datetime.timezone.utc)


@pytest.fixture(autouse=True)
def _fixed_vbios_clock(monkeypatch):
    import sys
    xf = sys.modules.get("x86_firmware")
    if xf is None or not hasattr(xf, "vbios_advisory_section"):
        yield
        return
    orig = xf.vbios_advisory_section
    monkeypatch.setattr(xf, "vbios_advisory_section",
                        lambda inv, advisory=None, now=None: orig(inv, advisory, now if now is not None else FIXED_VBIOS_NOW))
    yield
