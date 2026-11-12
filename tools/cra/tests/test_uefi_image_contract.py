"""對 C1 的 tools/cra/uefi_image.py 的「介面契約」測試（C2 的 uefi_gfx.py 依賴這些內部名稱）。

**這支測試紅燈 = C1 的 uefi_image.py 改了 C2 依賴的介面。先通知 C2 和 C1，兩邊一起決定怎麼改（改 uefi_gfx.py，或讓 uefi_image 保持相容），
不要只改測試讓它變綠。** 依賴的名稱列表見 docs/notes/c2-vbios.md「依賴 C1 uefi_image.py 的內部名稱」。
全部用測試當場產生的最小合成 FV，沒有二進位檔。"""
import inspect
import struct
import sys
import uuid
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import uefi_image as ui  # noqa: E402

TELL = "【對 C1 uefi_image 的介面契約被破壞：先通知 C2 和 C1，再處理（uefi_gfx.py 依賴它）】"
G = "A1B2C3D4-0000-4000-8000-0000000000AA"


def raw_section(payload):
    return (4 + len(payload)).to_bytes(3, "little") + b"\x19" + payload


def minimal_fv(sections, guid=G):
    """FV 標頭（FFS2）＋一個 FFS 檔案（內容是 sections）。"""
    ffs = uuid.UUID(guid).bytes_le + b"\x00\x00" + bytes([0x01, 0]) + (0x18 + len(sections)).to_bytes(3, "little") + b"\xf8" + sections
    h = bytearray(0x48)
    h[0x10:0x20] = ui.FFS2
    body = ffs + b"\xff" * 0x40
    struct.pack_into("<Q", h, 0x20, 0x48 + len(body))
    h[0x28:0x2C] = b"_FVH"
    struct.pack_into("<IHHHBB", h, 0x2C, 0x800, 0x48, 0, 0, 0, 2)
    return bytes(h) + body


def params(fn):
    return [(p.name, p.default is not inspect.Parameter.empty) for p in inspect.signature(fn).parameters.values()]


def test_c1_interface_contract_scan_is_subclassable_and_scan_bytes_signature():
    assert inspect.isclass(ui.Scan), TELL
    assert params(ui.Scan.scan_bytes) == [("self", False), ("data", False), ("module", True)], TELL + " Scan.scan_bytes 要是 (self, data, module=None)"
    assert inspect.signature(ui.Scan.scan_bytes).parameters["module"].default is None, TELL
    assert len(inspect.signature(ui.Scan).parameters) == 0, TELL + " Scan() 要能無參數建立"
    sc = type("Sub", (ui.Scan,), {})()
    for attr, kind in (("undecoded", list), ("notes", list), ("modules", list), ("fvs", int), ("files", int), ("total", int), ("parse_errors", int)):
        assert isinstance(getattr(sc, attr), kind), TELL + f" Scan.{attr}"


def test_c1_interface_contract_parse_fvs_signature():
    ps = params(ui.parse_fvs)
    assert ps[:3] == [("data", False), ("sc", False), ("depth", False)], TELL + " parse_fvs 的前三個參數要是 (data, sc, depth)"
    assert all(has_default for _, has_default in ps[3:]), TELL + " parse_fvs 第 4 個以後的參數都要有預設值（uefi_gfx 只傳三個）"


def test_c1_interface_contract_stop_and_limits():
    assert inspect.isclass(ui.Stop) and issubclass(ui.Stop, Exception), TELL
    for name in ("MAX_DEPTH", "MAX_LAYER", "MAX_TOTAL", "MAX_FILES"):
        v = getattr(ui, name, None)
        assert isinstance(v, int) and not isinstance(v, bool) and v > 0, TELL + f" {name} 要存在、是正整數"


def test_c1_interface_contract_parse_fvs_calls_subclass_scan_bytes_with_leaf_content_and_module():
    calls = []

    class Spy(ui.Scan):
        def scan_bytes(self, data, module=None):
            calls.append((bytes(data), module))

    sc = Spy()
    payload = b"LEAF-CONTENT-" + b"x" * 40
    spans = ui.parse_fvs(minimal_fv(raw_section(payload)), sc, 0)
    assert len(spans) == 1 and sc.fvs == 1 and sc.files == 1, TELL
    assert (payload, G) in calls, TELL + f" 葉節點內容與 module（FFS GUID 字串）要傳進 scan_bytes；實際呼叫 {[(c[0][:12], c[1]) for c in calls]}"
    assert all(isinstance(d, bytes) for d, _ in calls), TELL + " scan_bytes 的 data 要是 bytes"


def test_c1_interface_contract_ui_name_in_modules_and_outside_fv_reason():
    name = (4 + 8).to_bytes(3, "little") + b"\x15" + "Nm\0\0".encode("utf-16-le")          # UI section：Nm
    sc = ui.Scan()
    ui.parse_fvs(b"\x00" * 16 + b"X" * 88 + minimal_fv(name), sc, 0)       # FV 要 8 bytes 對齊（FFS 的位置以整份資料的 offset 對齊）
    assert any(m.get("guid") == G and m.get("ui_name") == "Nm" for m in sc.modules), TELL + " sc.modules 要有 {guid, ui_name}"
    assert any(x.get("where") == "image" and "outside any valid firmware volume" in x.get("reason", "") for x in sc.undecoded), \
        TELL + " 最上層 FV 以外的非空白位元組，undecoded 的 where 要是 'image'、reason 要含 'outside any valid firmware volume'"


def test_c1_interface_contract_unsupported_compression_is_undecoded():
    comp = (4 + 5 + 8).to_bytes(3, "little") + b"\x01" + struct.pack("<IB", 8, 1) + b"\x33" * 8      # EFI_STANDARD_COMPRESSION
    sc = ui.Scan()
    ui.parse_fvs(minimal_fv(comp), sc, 0)
    assert sc.undecoded or sc.notes, TELL + " 解不開的壓縮要記進 sc.undecoded（uefi_gfx 靠它判斷搜尋不完整）"
