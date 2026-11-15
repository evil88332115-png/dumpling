#!/usr/bin/env python3
"""BIOS 映像（UEFI）裡的 Intel 顯示韌體：走訪 Firmware Volume，找 Intel GOP 驅動、獨立的 VBT、legacy VBIOS（option ROM）。
只依賴標準函式庫與同目錄的 uefi_image.py（C1）、intel_vbios.py、intel_vbt.py；只讀、不執行、不寫磁碟；輸入是不可信資料。

## 做法（不改 uefi_image.py，專案決定 D-016）
uefi_image.parse_fvs(data, sc, depth) 走訪 FV／FFS／section（GUID-defined LZMA、CRC32、壓縮 section、嵌套 FV 都由它解開），
每一塊葉節點內容（PE32 等 section 的內容、LZMA 解開後不是 section 串的內容、FV 外的位元組）都呼叫 sc.scan_bytes(data, module)。
這裡定義 uefi_image.Scan 的子類別，覆寫 scan_bytes：**不呼叫** super().scan_bytes（那是函式庫指紋掃描，這裡用不到，省下那份時間），
改成對內容跑 GOP／VBT／ROM 的辨識。依賴的 uefi_image 內部名稱（C1 改了要跟著改；tests/test_uefi_image_contract.py 會檢查）：
  Scan（可子類別化、無參數建構）、Scan.scan_bytes(self, data, module=None)、parse_fvs(data, sc, depth, where="image")、
  Stop（Exception 子類別）、MAX_DEPTH／MAX_LAYER／MAX_TOTAL／MAX_FILES（int），
  以及 Scan 的屬性 undecoded（list of {where, reason}）、notes（list）、modules（list of {guid, ui_name…}）、fvs、files、total、parse_errors；
  parse_fvs 對最上層 FV 以外位元組記的 undecoded 原因含 `outside any valid firmware volume`（where 是 "image"）。
同一次走訪也收 AMI 的 Firmware ID 紀錄（`$FID`，解析在 ami_core.py）：每塊內容只多一個 `b"$FID" in body` 的檢查，沿用同一份去重與上限。
scan_bytes 拿得到的位置資訊只有 module（FFS 檔的 GUID；FFS 內有 UI section 之後的內容是 UI 名稱）與內容本身：
FV offset、section 位置拿不到（要改 C1 的檔才有），所以 found-in 只寫 module 與「在 section 內容裡的 offset」。

## 完整性（GAP 的來源）
sc.undecoded（沒解開的部分，例如 EFI 標準壓縮 section）、sc.notes（結構警告）、Stop、其他例外、時間上限 → result["complete"]=False，
result["gaps"] 寫原因。**沒有找到 GOP／VBT 時，完整與否決定能不能說「在已解開的內容裡沒有」；不完整時只能說沒找到、不能說不存在。**

## 放大控制
- 同一份內容（長度＋BLAKE2b）只辨識一次（raw fallback、FV 外位元組、備份 FV 會重複送進來）。
- 去重後累計送進辨識的位元組有上限 MAX_INSPECT（超過就不再辨識，記 gap）。
- 辨識本身對輸入是線性的：GOP 先檢查 `MZ` 開頭才找名稱；VBT 先找 `$VBT `；ROM 先找 `PCIR` 才呼叫 find_roms。
- uefi_image 自己的 MAX_DEPTH／MAX_LAYER／MAX_TOTAL／MAX_FILES 照用（解壓縮炸彈由它擋）。
"""
import hashlib
import importlib.util
import re
import sys
from pathlib import Path

MAX_INSPECT = 1 << 30                  # 去重後送進辨識的位元組總量上限
MAX_REPROBE = 32 << 20                 # 重複的內容（含 PCIR）重跑 option ROM 搜尋以記新位置的總量上限
MAX_FOUND = 256                        # 各種元件各自最多記幾份（不同雜湊）
MAX_LOCATIONS = 32                     # 同一份內容最多記幾個位置
MAX_UNDECODED_SHOWN = 3                # gap 文字裡列幾個沒解開的原因
SUBTYPE_GUID_LEN = 16                  # FREEFORM_SUBTYPE_GUID section 的內容開頭是 16 bytes 的子類型 GUID
OUTSIDE_FV = "outside any valid firmware volume"      # uefi_image.parse_fvs 的 undec 原因文字；改了字就變成「不完整」（安全的方向）
GUID_RE = re.compile(r"[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}")


def _sibling(name):
    """同目錄的模組（python3 -I 不把腳本目錄放進 sys.path；測試 import 過就共用同一個）。找不到或載入失敗 → ImportError。"""
    mod = sys.modules.get(name)
    if mod is None:
        path = Path(__file__).resolve().with_name(name + ".py")
        try:
            spec = importlib.util.spec_from_file_location(name, path)
            mod = importlib.util.module_from_spec(spec)
            sys.modules[name] = mod
            spec.loader.exec_module(mod)
        except (OSError, ImportError, AttributeError, SyntaxError) as e:
            sys.modules.pop(name, None)
            raise ImportError(f"cannot load {name}.py ({type(e).__name__})")
    return mod


def clean(s, limit=80):
    """不可信字串（UI 名稱）→ 只留可列印 ASCII，其餘換成 ?。"""
    return re.sub(r"[^\x20-\x7e]", "?", str(s))[:limit]


def digests(b):
    return {"sha256": hashlib.sha256(b).hexdigest(), "sha512": hashlib.sha512(b).hexdigest()}


class Hits(list):
    """一塊內容找到的 GOP／VBT（table, 雜湊, 內容, offset）；probed＝跑過 option ROM 搜尋；fid＝這塊內容裡的 Firmware ID 候選。"""
    probed = False
    fid = ()


def make_scan_class(ui, state):
    """ui＝uefi_image 模組。回傳 Scan 的子類別；state＝scan() 的共用狀態（結果、去重集合、回呼）。"""

    class GfxScan(ui.Scan):
        def scan_bytes(self, data, module=None):    # noqa: D401 — 覆寫 uefi_image.Scan.scan_bytes，不呼叫 super（不做函式庫指紋）
            state["inspect"](data, module)

    return GfxScan


def scan(data, find_roms=None, budget=None, soft=(), cbfs=False):
    """BIOS 映像的位元組 → dict（可轉 JSON）：
    performed（有沒有走訪）、reason（沒走訪的原因）、complete、gop（Intel GOP 驅動清單）、vbt（獨立 VBT 清單）、gaps、stats、undecoded。
    find_roms(body, module)：呼叫端給的回呼，對含 `PCIR` 的內容找 legacy VBIOS option ROM（可丟 soft 裡的例外）。
    budget：有 check() 的物件（x86_firmware.Budget）；每塊內容檢查一次。
    soft：視為「提早停止、結果不完整」而不是失敗的例外型別（x86_firmware.OverBudget）。
    cbfs：映像有 coreboot CBFS（CBFS 檔案沒有解開）→ AMI 核心版本搜尋記為不完整。結果的 "ami_core" 是 ami_core.summarize 的結果。永遠回傳，不丟例外。"""
    r = {"performed": False, "reason": None, "complete": False, "gop": [], "vbt": [], "gaps": [], "ami_core": None,
         "stats": {"fvs": 0, "ffs_files": 0, "decompressed_total": 0, "inspected_bytes": 0, "inspected_blocks": 0, "duplicate_blocks": 0,
                   "rom_probes": 0, "reprobed_bytes": 0, "undecoded": 0, "notes": 0},
         "undecoded": [], "notes": [], "stopped": None}
    try:
        ui = _sibling("uefi_image")
        ig, vbt_mod = _sibling("intel_vbios"), _sibling("intel_vbt")
    except ImportError as e:
        r["reason"] = f"{e}; the Intel GOP / VBT / legacy VBIOS search inside UEFI firmware volumes was not performed"
        r["gaps"].append(r["reason"])
        r["ami_core"] = {"status": "not-searched", "performed": False, "complete": False, "incomplete": [r["reason"]], "reason": r["reason"], "count": 0,
                         "found": [], "valid": 0, "invalid": 0, "candidates": [], "bad": [],
                         "gaps": [f"AMI core version (Firmware ID record): not searched ({r['reason']})"]}
        return r
    try:
        ami = _sibling("ami_core")
    except ImportError:
        ami = None
    seen, gops, vbts = {}, {}, {}
    fids = {}                              # ami_core.entry_key → 項目（"seen"＝遇到幾次、"found"＝位置）

    def record(table, key, entry, where):
        e = table.get(key)
        if e is None:
            if len(table) >= MAX_FOUND:
                r["gaps"].append(f"more than {MAX_FOUND} distinct items of one kind; the rest are not listed")
                return
            e = table[key] = {**entry, "found": []}
        if len(e["found"]) < MAX_LOCATIONS and where not in e["found"]:
            e["found"].append(where)

    def record_fid(c, mod):
        """Firmware ID 候選 c（ami_core.find_fid 的一筆）→ fids；同一份紀錄合成一項（遇到幾次、各個位置）。"""
        if c.get("truncated"):
            state["fid_capped"] = True
            return
        k = ami.entry_key(c)
        e = fids.get(k)
        if e is None:
            if len(fids) >= MAX_FOUND:
                state["fid_capped"] = True
                return
            e = fids[k] = {x: v for x, v in c.items() if x not in ("offset", "module")}
            e.update(seen=0, found=[])
        e["seen"] += 1
        w = {"module": mod, "form": c["form"], "offset": c["offset"]}
        if len(e["found"]) < MAX_LOCATIONS and w not in e["found"]:
            e["found"].append(w)

    def inspect(body, module):
        if budget is not None:
            budget.check()
        n = len(body)
        if n == 0:
            return
        key = (n, hashlib.blake2b(body, digest_size=16).digest())
        mod = clean(module or "?")
        if key in seen:                       # 重複的內容不再辨識，但上次找到的東西要記這個新位置（備份 FV、同一個檔案放在兩處）
            r["stats"]["duplicate_blocks"] += 1
            for table, hkey, entry, off in seen[key]:
                record(table, hkey, entry, {"module": mod, "offset": off})
            for c in seen[key].fid:
                record_fid(c, mod)
            if find_roms is not None and seen[key].probed:        # option ROM 的位置：重跑一次，但重跑的總量有上限（big 重複內容不放大）
                if r["stats"]["reprobed_bytes"] + n <= MAX_REPROBE:
                    r["stats"]["reprobed_bytes"] += n
                    find_roms(body, mod)
                elif not state.get("reprobe_gap"):
                    state["reprobe_gap"] = True
                    r["gaps"].append("some duplicated content with option ROM markers was not searched again; their extra locations may be missing")
            return
        hits = seen[key] = Hits()
        if r["stats"]["inspected_bytes"] + n > MAX_INSPECT:
            if not state.get("capped"):
                state["capped"] = True
                r["gaps"].append(f"more than {MAX_INSPECT} bytes of distinct UEFI content; the rest was not searched")
            return
        r["stats"]["inspected_bytes"] += n
        r["stats"]["inspected_blocks"] += 1
        if ami is not None and b"$FID" in body:
            hits.fid = [{**c, "module": mod} for c in ami.find_fid(body, mod)]
            for c in hits.fid:
                record_fid(c, mod)
        # 內容可能前面有 16 bytes 的子類型 GUID（FREEFORM_SUBTYPE_GUID section）：兩種起點都試，辨識函式自己檢查開頭
        for off in (0, SUBTYPE_GUID_LEN):
            if body[off:off + 2] == b"MZ":
                pe = body[off:]
                g = ig.gop_driver(pe)
                if g is not None:
                    hk, ent = hashlib.sha256(pe).hexdigest(), {**g, **digests(pe)}
                    hits.append((gops, hk, ent, off))
                    record(gops, hk, ent, {"module": mod, "offset": off})
                break
        if b"$VBT " in body:
            for vo, v in vbt_mod.find_vbt(body):
                if vo in (0, SUBTYPE_GUID_LEN):          # 內容就是 VBT（獨立檔案）；嵌在別的內容裡（例如 legacy VBIOS）的不另列
                    raw = bytes(body[vo:vo + v["vbt_size"]])
                    hk, ent = hashlib.sha256(raw).hexdigest(), {**v, **digests(raw)}
                    hits.append((vbts, hk, ent, vo))
                    record(vbts, hk, ent, {"module": mod, "offset": vo})
        if find_roms is not None and b"PCIR" in body:
            r["stats"]["rom_probes"] += 1
            hits.probed = True
            find_roms(body, mod)

    state = {"inspect": inspect}
    sc = make_scan_class(ui, state)()
    r["performed"] = True
    try:
        ui.parse_fvs(bytes(data), sc, 0)
    except ui.Stop as e:
        r["stopped"] = f"limit reached: {e}"
    except soft as e:
        r["stopped"] = f"stopped early: {e}"
    except Exception as e:      # noqa: BLE001 — 輸入是不可信資料：任何例外都記成 gap，不能讓整個映像的解析失敗
        r["stopped"] = f"UEFI walk failed ({type(e).__name__})"
    st = r["stats"]
    # 最上層、FV 以外的位元組（descriptor、ME、微碼、NVRAM…）：uefi_image 當原始內容掃一次並記成未解開；顯示韌體不會放在那裡，
    # 所以不算「不完整」，只記數量（資訊）。巢狀層（LZMA 解開後）FV 以外的位元組、其他所有未解開的部分照常算不完整。
    top = [x for x in sc.undecoded if x["where"] == "image" and OUTSIDE_FV in x["reason"]]
    undec = [x for x in sc.undecoded if not (x["where"] == "image" and OUTSIDE_FV in x["reason"])]
    st["outside_fv_nonblank_bytes"] = sum(int(x["reason"].split()[0]) for x in top if x["reason"].split()[0].isdigit())
    st.update(fvs=sc.fvs, ffs_files=sc.files, decompressed_total=sc.total, undecoded=len(undec), notes=len(sc.notes))
    r["undecoded"] = [dict(x) for x in undec[:50]]
    r["notes"] = list(sc.notes[:20])
    # FFS 檔的 UI 名稱（UI section 通常在內容之後，scan_bytes 被呼叫時還不知道）：walk 結束後用 GUID 對回去（sc.modules 有上限 MAX_MODULES_LISTED）
    names = {}
    for m in getattr(sc, "modules", ()):
        if m.get("ui_name"):
            names.setdefault(m["guid"], set()).add(clean(m["ui_name"]))
    for table in (gops, vbts):
        for e in table.values():
            for w in e["found"]:
                if GUID_RE.fullmatch(w["module"]) and len(names.get(w["module"], ())) == 1:
                    w["ui_name"] = next(iter(names[w["module"]]))
    r["gop"] = sorted(gops.values(), key=lambda x: x["sha256"])
    r["vbt"] = sorted(vbts.values(), key=lambda x: x["sha256"])
    if r["stopped"]:
        r["gaps"].append(f"{r['stopped']}; the Intel GOP / VBT / legacy VBIOS search is incomplete (not found does not mean absent)")
    if undec:
        why = sorted({clean(x["reason"], 120) for x in undec})[:MAX_UNDECODED_SHOWN]
        r["gaps"].append(f"{len(undec)} UEFI parts were not decoded ({'; '.join(why)}); "
                         "the Intel GOP / VBT / legacy VBIOS search did not look inside them (not found does not mean absent)")
    if sc.notes or sc.parse_errors:
        r["gaps"].append(f"{len(sc.notes) + sc.parse_errors} UEFI structure warnings (e.g. {clean(sc.notes[0], 160) if sc.notes else 'FFS parse error'}); "
                         "content with unclear structure was only searched as raw bytes")
    if not sc.fvs and r["stopped"] is None:
        r["gaps"].append("no valid UEFI firmware volume found by the walker; the Intel GOP / VBT / legacy VBIOS search found nothing to look in")
    r["complete"] = not r["gaps"]       # 任何 gap（含沒解開、結構警告、上限）都不是完整
    if ami is None:
        r["ami_core"] = {"status": "not-searched", "performed": False, "complete": False, "incomplete": ["ami_core.py could not be loaded"],
                         "reason": "ami_core.py could not be loaded", "count": 0, "found": [], "valid": 0, "invalid": 0, "candidates": [], "bad": [],
                         "gaps": ["AMI core version (Firmware ID record): not searched (ami_core.py could not be loaded)"]}
        return r
    # AMI 核心版本的完整性：不含 GOP／VBT 專屬的 gap（option ROM 說明等），只看走訪本身有沒有走完
    why = []
    if r["stopped"]:
        why.append(r["stopped"])
    if undec:
        why.append(f"{len(undec)} UEFI parts were not decoded ({'; '.join(sorted({clean(x['reason'], 120) for x in undec})[:MAX_UNDECODED_SHOWN])})")
    if sc.notes or sc.parse_errors:
        why.append(f"{len(sc.notes) + sc.parse_errors} UEFI structure warnings")
    if state.get("capped"):
        why.append(f"more than {MAX_INSPECT} bytes of distinct UEFI content; the rest was not searched")
    if not sc.fvs and r["stopped"] is None:
        why.append("no valid UEFI firmware volume found by the walker")
    if cbfs:
        why.append("coreboot CBFS found: files inside the CBFS were not unpacked for this search")
    r["ami_core"] = ami.summarize(sorted(fids.values(), key=lambda e: (e["form"], e.get("sha256") or e.get("why", ""), e["found"][0]["module"], e["found"][0]["offset"])),
                                  incomplete=why, truncated=bool(state.get("fid_capped")))
    return r
