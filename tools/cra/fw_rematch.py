#!/usr/bin/env python3
"""每天重跑韌體公告比對：讀 Release 上的 fw-inventory-<slug>.json，用 repo 當下的三張表重新比對，重新產生狀態、SBOM 與報告。

用法（入口是 pipeline/firmware-rematch.sh，內部是 `python3 -I x86_firmware.py --rematch ...`）：
  python3 -I x86_firmware.py --rematch --meta <firmware-meta.json> --dir <附件資料夾> --now <YYYY-MM-DDTHH:MM:SSZ> --out <資料夾>

只吃 inventory：呼叫 x86_firmware 的 advisory_section（Intel 微碼）、vbios_advisory_section（NVIDIA 對照表）、rules_section（規則表）、
status_parts／status_of、components、bom、markdown；不讀映像、不連網、不重新解析。表只讀 repo 當下的三個檔案
（tools/cra/data/intel-microcode-releases.json、tools/pilot/lib/nvidia-bulletins-gpu-firmware.json、tools/cra/data/fw-advisory-rules.json），
載入與核對在 fw_advisory、nvidia_vbios_advisory、fw_advisory_rules：Intel 微碼表與規則表核對固定的 sha256 加結構；
NVIDIA 對照表只驗結構（沒有固定的 sha256，檔案的 sha256 記在 tables 的識別裡）。

輸入是不可信資料：
- firmware-meta.json：大小上限 MAX_META；schema 必須是 dumpling-firmware-meta/1；不跟隨符號連結。
- 附件：只收 meta 的 samples[] 列的 `fw-inventory-<slug>.json`（slug 要 fullmatch SLUG_RE，附件名要等於 `fw-inventory-<slug>.json`），
  用 O_NOFOLLOW 在 --dir 底下開檔（不跟隨符號連結、不接受路徑分隔符號與 ..、一定要是一般檔案），大小上限 MAX_INVENTORY，
  核對 meta 列的 inventory_sha256；沒列在 meta 的檔案不讀。kind 是 sbom 的樣本跳過（沒有 inventory，也不輸出）。
- meta 壞掉：整份 GAP，只輸出總表（rematch-summary.json）。meta 裡被丟掉的條目（沒有有效 slug 的、重複的 slug）列在總表的 rejected
  （index 加原因代碼，不帶輸入裡的字串）。單一樣本的 inventory 有問題（缺檔、sha256 不符、不是 JSON、schema 不對、
  必要的鍵缺了或型別不對）：那一份 GAP（`rematch-input-invalid`），其他樣本照常；不丟例外。
- inventory 是舊版程式產生、缺新的鍵時是 GAP，不猜預設值。數字、雜湊、版本、日期這類欄位另外檢查格式（FIELD_RULES）：不合那一份 GAP，
  作為報告跳脫（x86_firmware.markdown 每個插進報告的字串都經過 md_esc）之外的第二道防線。
- 處理時間：每份 inventory 最多 SAMPLE_LIMIT 秒、整次最多 TOTAL_LIMIT 秒（和 x86_firmware.TIME_LIMIT 同一個值，firmware-bios 的 Budget 預設）；超過的樣本 GAP。

重跑前清掉 inventory 裡舊的比對結果（advisory、vbios_advisory、rules_advisory、rule_advisory、status、detail），以免舊結果混進今天的結果；
舊結果先記下來，和今天的比（changed）。

輸出（--out；必須不存在或是空資料夾）：
  rematch-<slug>.json（dumpling-firmware-rematch/1）、fw-<slug>.cdx.json、fw-inventory-<slug>.md（GAP 的樣本只有 rematch-<slug>.json）、
  rematch-summary.json（dumpling-firmware-rematch-summary/1；最後才寫，是索引：沒列在裡面的樣本，呼叫端標 NOT_RUN）。
stdout：每個樣本一行 `FIRMWARE-REMATCH<TAB>OK|ATTENTION|GAP<TAB><slug>|-<TAB>說明`；寫不出輸出時一行 `FIRMWARE-REMATCH<TAB>FAIL<TAB>-<TAB>原因`。
退出碼：0＝每個樣本都是 OK；2＝有 ATTENTION 或 GAP（輸出照寫）；1＝FAIL（寫不出輸出或內部錯誤，已寫的輸出會刪掉）；64＝參數錯誤。
重跑不輸出 NOT_RUN（沒跑、沒有輸出由呼叫端標）。
rematch-<slug>.json 的 reasons 與 results 裡來自 inventory 的字串（檔名等）是 JSON 原值，下游渲染成 markdown 或 HTML 時要自己跳脫；fw-inventory-<slug>.md 已經跳脫。
"""
import argparse
import contextlib
import datetime
import errno
import hashlib
import json
import os
import re
import signal
import stat
import sys
import threading
import time
from collections import Counter
from pathlib import Path

META_SCHEMA = "dumpling-firmware-meta/1"
INVENTORY_SCHEMA = "sca-center-fw-inventory/1"
REMATCH_SCHEMA = "dumpling-firmware-rematch/1"
SUMMARY_SCHEMA = "dumpling-firmware-rematch-summary/1"
MAX_META = 1 << 20                     # firmware-meta.json 的大小上限
MAX_INVENTORY = 32 << 20               # 單一 fw-inventory-<slug>.json 的大小上限（目前最大約 0.4 MB）
MAX_SAMPLES = 64                       # meta 的 samples[] 筆數上限
MAX_PROBLEMS = 5                       # inventory 結構問題最多列幾項
SAMPLE_LIMIT = 300                     # 秒：每份 inventory 從讀檔到寫出結果的時間上限（超過 GAP）
TOTAL_LIMIT = 900                      # 秒：整次執行的上限（x86_firmware.TIME_LIMIT 同值）；用完之後剩下的樣本 GAP
SLUG_RE = re.compile(r"[a-z0-9][a-z0-9.-]{0,62}")
RESERVED_SLUGS = frozenset({"summary"})    # rematch-summary.json 的檔名
NOW_RE = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])Z")
HEX64_RE = re.compile(r"[0-9a-f]{64}")
TAG_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}")
VERSION_RE = re.compile(r"[ -~]{0,128}")
KEY_BAD = re.compile(r"[^A-Za-z0-9._=+-]")
KINDS = ("bios", "sbom")
TABLES = ("fw_advisory_rules", "intel_microcode", "nvidia_vbios")
OLD_RESULT_KEYS = ("advisory", "vbios_advisory", "rules_advisory", "rule_advisory", "status", "detail")


class InputError(Exception):
    """不可信輸入有問題：這一份（或整份 meta）GAP。訊息不帶輸入裡的字串。"""


class ArgError(Exception):
    pass


class TimeLimit(BaseException):
    """處理時間超過上限。繼承 BaseException：x86_firmware 的比對函式有 `except Exception`（那一個元件記成 match-error），不能把逾時吞掉。"""


@contextlib.contextmanager
def deadline(seconds):
    """seconds 秒後在主執行緒丟 TimeLimit（SIGALRM）。不在主執行緒或沒有 setitimer 時只在進入前檢查剩餘時間（沒有中斷的能力）。"""
    if seconds <= 0:
        raise TimeLimit()
    if not hasattr(signal, "setitimer") or threading.current_thread() is not threading.main_thread():
        yield
        return

    def fire(_sig, _frame):
        raise TimeLimit()
    old = signal.signal(signal.SIGALRM, fire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


# ---------- 讀不可信輸入 ----------

def read_file(name, cap, dir_fd=None):
    """一般檔案的內容（不跟隨最後一段的符號連結；大小上限 cap）。name 是 dir_fd 底下的檔名，沒給 dir_fd 就是路徑。"""
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(name, flags, dir_fd=dir_fd)
    except FileNotFoundError:
        raise InputError("file not found")
    except OSError as e:
        if e.errno == errno.ELOOP:
            raise InputError("file is a symbolic link")
        raise InputError(f"file cannot be opened ({errno.errorcode.get(e.errno, 'error')})")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise InputError("not a regular file")
        if st.st_size > cap:
            raise InputError(f"file is larger than the limit ({cap} bytes)")
        with os.fdopen(fd, "rb", closefd=False) as f:
            data = f.read(cap + 1)
    except OSError as e:
        raise InputError(f"file cannot be read ({errno.errorcode.get(e.errno, 'error')})")
    finally:
        os.close(fd)
    if len(data) > cap:
        raise InputError(f"file is larger than the limit ({cap} bytes)")
    return data


def _no_duplicates(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError("duplicate key")
        d[k] = v
    return d


def _no_constant(_name):
    raise ValueError("NaN or Infinity")


def parse_json(data):
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_no_duplicates, parse_constant=_no_constant)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise InputError("not valid JSON")


def is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


# ---------- firmware-meta.json ----------

def parse_meta(data):
    """→ (tag, [sample dict, ...])；meta 壞掉丟 InputError（整份 GAP）。樣本個別的問題在 plan_sample。"""
    meta = parse_json(data)
    if not isinstance(meta, dict):
        raise InputError("firmware-meta.json is not an object")
    if meta.get("schema") != META_SCHEMA:
        raise InputError(f"firmware-meta.json schema is not {META_SCHEMA}")
    tag = meta.get("tag")
    if not isinstance(tag, str) or not TAG_RE.fullmatch(tag):
        raise InputError("firmware-meta.json tag is missing or not a release tag")
    samples = meta.get("samples")
    if not isinstance(samples, list):
        raise InputError("firmware-meta.json samples is not a list")
    if len(samples) > MAX_SAMPLES:
        raise InputError(f"firmware-meta.json lists more than {MAX_SAMPLES} samples")
    return tag, samples


def plan_sample(entry, dup_slugs):
    """meta 的一個樣本 → ("skip", slug, None) ｜ ("reject", None, 原因代碼) ｜ ("gap", slug, 原因) ｜ ("run", slug, 資料 dict)。
    reject＝沒有可用的 slug（沒有檔名可寫），只出現在總表的 rejected；原因代碼不帶輸入裡的字串。"""
    if not isinstance(entry, dict):
        return "reject", None, "entry-not-object"
    slug, kind = entry.get("slug"), entry.get("kind")
    if not isinstance(slug, str):
        return "reject", None, f"invalid-slug (type {type(slug).__name__})"
    if slug in RESERVED_SLUGS:
        return "reject", None, "reserved-slug"
    if not SLUG_RE.fullmatch(slug):
        return "reject", None, f"invalid-slug (length {len(slug)})"
    if kind == "sbom":
        return "skip", slug, None
    if kind != "bios":
        return "gap", slug, "sample kind in firmware-meta.json is not bios or sbom"
    if slug in dup_slugs:
        return "gap", slug, "slug appears more than once in firmware-meta.json"
    version = entry.get("firmware_version")
    if version is not None and not (isinstance(version, str) and VERSION_RE.fullmatch(version)):
        return "gap", slug, "firmware_version in firmware-meta.json is not a printable string"
    name, sha = entry.get("inventory"), entry.get("inventory_sha256")
    if name is None:
        return "gap", slug, "firmware-meta.json lists no inventory for this bios sample"
    if name != f"fw-inventory-{slug}.json":
        return "gap", slug, "inventory file name in firmware-meta.json is not fw-inventory-<slug>.json"
    if not isinstance(sha, str) or not HEX64_RE.fullmatch(sha):
        return "gap", slug, "inventory_sha256 in firmware-meta.json is not a lowercase sha256"
    return "run", slug, {"firmware_version": version, "inventory": name, "inventory_sha256": sha}


# ---------- inventory 的結構檢查 ----------
# 型別寫法：「str|null」等；sha256 ＝ 64 位小寫十六進位字串；開頭的 ? ＝ 可以沒有這個鍵（程式用 .get 讀的，例如沒有 UEFI 結構的映像沒有 ami_core），有就要符合型別。只列重跑用得到的鍵（舊版程式產生、缺新的鍵 → GAP，不猜預設值）。

TOP_SPEC = {"schema": "str", "vbios": "list", "intel_vbios": "list", "other_roms": "list", "bios": "list", "skipped": "list", "partial": "list",
            "advisory": "dict", "vbios_advisory": "dict", "rules_advisory": "dict"}
BIOS_SPEC = {"file": "str", "sha256": "sha256", "sha512": "str", "size": "int", "locations": "list", "descriptor": "bool", "descriptor_note": "str|null",
             "regions": "list", "me": "dict|null", "me_status": "str", "me_note": "str|null", "me_conflict": "any", "microcode": "list", "fit": "dict",
             "platform": "str|null", "amd_markers": "list", "amd": "dict|null", "uefi": "dict", "cbfs": "dict|null", "ibv_hint": "list",
             "incomplete": "list", "gaps": "list", "evidence": "list", "ami_core": "?dict|null", "uefi_gfx": "?dict|null"}
REGION_SPEC = {"name": "str", "base": "int", "limit": "int", "sha256": "sha256", "sha512": "str"}
UCODE_SPEC = {"cpuid": "str", "platform_id": "str", "revision": "str", "date": "str", "sha256": "sha256", "sha512": "str", "offset": "int",
              "size": "int", "extended_signatures": "list", "in_fit": "bool|null"}
VBIOS_SPEC = {"vendor": "str", "device": "str", "class": "str|null", "version": "str|null", "length": "int", "images": "list", "terminated": "str",
              "sha256": "sha256", "sha512": "str", "locations": "list", "found_at": "list"}
FIT_SPEC = {"status": "str", "offset": "int|null"}
UEFI_SPEC = {"compressed": "dict", "guided_other": "dict"}
ME_SPEC = {"version": "str", "basis": "str", "offset": "int"}
AMD_SPEC = {"psp_firmware": "list", "microcode": "list", "agesa": "dict"}
CBFS_SPEC = {"fsp": "list"}
AMI_SPEC = {"status": "str"}
PSP_SPEC = {"type": "int", "version": "str|null"}
AMD_UCODE_SPEC = {"equiv_id": "any", "patch_id": "any"}
AGESA_SPEC = {"values": "list"}
FSP_SPEC = {"revision": "str|null"}
ROM_SPEC = {"device": "str"}
FILE_SPEC = {"file": "str"}


# 欄位格式（第二道防線；第一道是 markdown 的 md_esc）：路徑（清單索引寫成 *）→ 格式。None 一律可以（程式用 `or ''` 處理）。
# INT＝整數（不含 bool）；其他是 fullmatch 的字串格式。這些欄位會原樣進報告或 key，不合那一份 GAP。
_HEX = r"[0-9A-Fa-f]{1,128}"
_H0X = r"0x[0-9A-Fa-f]{1,16}"
_VER = r"[0-9A-Za-z]{1,8}(?:\.[0-9A-Za-z]{1,8}){0,6}"
_DATE = r"[0-9]{4}-[0-9]{2}-[0-9]{2}"
_TOK = r"[A-Za-z0-9._-]{1,40}"
FIELD_RULES = {
    "bios/*/amd/agesa/values/*/count": "INT", "bios/*/amd/directories/*/checksum": _H0X, "bios/*/amd/directories/*/entries/*/index": "INT",
    "bios/*/amd/directories/*/entries/*/instance": "INT", "bios/*/amd/directories/*/entries/*/subprogram": "INT", "bios/*/amd/directories/*/num_entries": "INT",
    "bios/*/amd/microcode/*/date": _DATE, "bios/*/amd/microcode/*/equiv_id": _H0X, "bios/*/amd/microcode/*/form": _TOK, "bios/*/amd/microcode/*/patch_id": _H0X,
    "bios/*/amd/microcode/*/sha256": _HEX, "bios/*/amd/microcode/*/sha512": _HEX, "bios/*/amd/psp_firmware/*/sha256": _HEX, "bios/*/amd/psp_firmware/*/sha512": _HEX,
    "bios/*/ami_core/count": "INT",
    "bios/*/cbfs/coreboot/*/config/sha256": _HEX, "bios/*/cbfs/coreboot/*/config/size": "INT", "bios/*/cbfs/fmap/areas": "INT", "bios/*/cbfs/fmap/version": _VER,
    "bios/*/cbfs/fsp/*/hash/sha256": _HEX, "bios/*/cbfs/fsp/*/stored_sha256": _HEX, "bios/*/cbfs/fsp/*/image_base": _H0X, "bios/*/cbfs/fsp/*/revision": _VER,
    "bios/*/cbfs/fsp/*/spec_version": _VER, "bios/*/cbfs/fsp/*/type": _TOK, "bios/*/cbfs/method": _TOK,
    "bios/*/cbfs/payloads/*/hash/sha256": _HEX, "bios/*/cbfs/payloads/*/length": "INT",
    "bios/*/cbfs/vbt/*/bdb_version": _VER, "bios/*/cbfs/vbt/*/vbt_size": "INT", "bios/*/cbfs/vbt/*/version": _VER,
    "bios/*/fit/entries": "INT", "bios/*/fit/status": _TOK, "bios/*/ibv_hint/*": r"[A-Za-z0-9 ._-]{1,40}",
    "bios/*/me/date": _DATE, "bios/*/me/other_versions/*": _VER, "bios/*/me/version": _VER,
    "bios/*/microcode/*/cpuid": r"[0-9A-Fa-f]{8}", "bios/*/microcode/*/date": _DATE, "bios/*/microcode/*/platform_id": _H0X, "bios/*/microcode/*/revision": _H0X,
    "bios/*/microcode/*/sha512": _HEX, "bios/*/sha512": _HEX,
    "bios/*/pfat/container_sha256": _HEX, "bios/*/pfat/container_size": "INT", "bios/*/pfat/image_sha256": _HEX, "bios/*/pfat/image_size": "INT",
    "bios/*/regions/*/name": _TOK, "bios/*/regions/*/sha256": _HEX, "bios/*/regions/*/sha512": _HEX,
    "bios/*/uefi/files": "INT", "bios/*/uefi/sections": "INT", "bios/*/uefi/volumes": "INT", "bios/*/uefi/volumes_other_fs": "INT",
    "bios/*/uefi_gfx/gop/*/sha256": _HEX, "bios/*/uefi_gfx/vbt/*/sha256": _HEX, "bios/*/uefi_gfx/vbt/*/version": _VER,
    "vbios/*/vendor": r"[0-9a-f]{4}", "vbios/*/device": r"[0-9a-f]{4}", "vbios/*/terminated": _TOK, "vbios/*/sha512": _HEX,
    "vbios/*/version": r"[0-9A-F]{2}(?:\.[0-9A-F]{2}){4}",
}
_FIELD_RE = {k: (v if v == "INT" else re.compile(v)) for k, v in FIELD_RULES.items()}
MAX_FIELD_DEPTH = 24


def field_problems(x, probs, path=(), depth=0):
    """FIELD_RULES 的格式檢查：walk 整份 inventory（深度上限 MAX_FIELD_DEPTH，更深的結構一律不合）。"""
    if len(probs) >= MAX_PROBLEMS:
        return
    if depth > MAX_FIELD_DEPTH:
        probs.append("inventory is nested too deeply")
        return
    if isinstance(x, dict):
        for k, v in x.items():
            field_problems(v, probs, path + (k,), depth + 1)
    elif isinstance(x, list):
        for v in x:
            field_problems(v, probs, path + ("*",), depth + 1)
    elif x is not None:
        rule = _FIELD_RE.get("/".join(path))
        if rule is not None and not (is_int(x) if rule == "INT" else isinstance(x, str) and rule.fullmatch(x)):
            probs.append("/".join(path) + " has an invalid format")


def _type_ok(v, t):
    if t == "any":
        return True
    for one in t.split("|"):
        if one == "null" and v is None:
            return True
        if one == "str" and isinstance(v, str):
            return True
        if one == "int" and is_int(v):
            return True
        if one == "bool" and isinstance(v, bool):
            return True
        if one == "list" and isinstance(v, list):
            return True
        if one == "dict" and isinstance(v, dict):
            return True
        if one == "sha256" and isinstance(v, str) and HEX64_RE.fullmatch(v):
            return True
    return False


def _check(obj, where, spec, probs):
    if not isinstance(obj, dict):
        probs.append(f"{where} is not an object")
        return False
    ok = True
    for k, t in spec.items():
        optional = t.startswith("?")
        t = t.lstrip("?")
        if k not in obj:
            if not optional:
                probs.append(f"{where}.{k} is missing")
                ok = False
        elif not _type_ok(obj[k], t):
            probs.append(f"{where}.{k} has the wrong type")
            ok = False
    return ok


def _check_list(items, where, spec, probs):
    for i, x in enumerate(items):
        if len(probs) >= MAX_PROBLEMS:
            return
        _check(x, f"{where}[{i}]", spec, probs)


def inventory_problems(inv):
    """inventory 的結構問題清單（最多 MAX_PROBLEMS 項，只寫鍵的路徑與索引，不帶 inventory 裡的字串）；空 ＝ 可以重跑。"""
    probs = []
    if not isinstance(inv, dict):
        return ["inventory is not an object"]
    if inv.get("schema") != INVENTORY_SCHEMA:
        return [f"inventory schema is not {INVENTORY_SCHEMA}"]
    if not _check(inv, "inventory", TOP_SPEC, probs):
        return probs[:MAX_PROBLEMS]
    _check_list(inv["skipped"], "skipped", FILE_SPEC, probs)
    _check_list(inv["partial"], "partial", FILE_SPEC, probs)
    _check_list(inv["other_roms"], "other_roms", ROM_SPEC, probs)
    _check_list(inv["intel_vbios"], "intel_vbios", {"sha256": "sha256", "sha512": "str", "locations": "list"}, probs)
    _check_list(inv["vbios"], "vbios", VBIOS_SPEC, probs)
    for i, v in enumerate(inv["vbios"]):
        if isinstance(v, dict) and isinstance(v.get("images"), list):
            _check_list(v["images"], f"vbios[{i}].images", {"code_type": "int"}, probs)
        if isinstance(v, dict) and isinstance(v.get("found_at"), list):
            _check_list(v["found_at"], f"vbios[{i}].found_at", {"file": "str", "offset": "int"}, probs)
    for i, b in enumerate(inv["bios"]):
        w = f"bios[{i}]"
        if len(probs) >= MAX_PROBLEMS:
            break
        if not _check(b, w, BIOS_SPEC, probs):
            continue
        _check_list(b["regions"], f"{w}.regions", REGION_SPEC, probs)
        _check_list(b["microcode"], f"{w}.microcode", UCODE_SPEC, probs)
        _check(b["fit"], f"{w}.fit", FIT_SPEC, probs)
        _check(b["uefi"], f"{w}.uefi", UEFI_SPEC, probs)
        if b["me"] is not None:
            _check(b["me"], f"{w}.me", ME_SPEC, probs)
        if b.get("ami_core") is not None:
            _check(b["ami_core"], f"{w}.ami_core", AMI_SPEC, probs)
        if b["cbfs"] is not None and _check(b["cbfs"], f"{w}.cbfs", CBFS_SPEC, probs):
            _check_list(b["cbfs"]["fsp"], f"{w}.cbfs.fsp", FSP_SPEC, probs)
        if b["amd"] is not None and _check(b["amd"], f"{w}.amd", AMD_SPEC, probs):
            _check_list(b["amd"]["psp_firmware"], f"{w}.amd.psp_firmware", PSP_SPEC, probs)
            _check_list(b["amd"]["microcode"], f"{w}.amd.microcode", AMD_UCODE_SPEC, probs)
            if _check(b["amd"]["agesa"], f"{w}.amd.agesa", AGESA_SPEC, probs):
                _check_list(b["amd"]["agesa"]["values"], f"{w}.amd.agesa.values", {"value": "str"}, probs)
    if not probs:
        field_problems({"bios": inv["bios"], "vbios": inv["vbios"]}, probs)
    return probs[:MAX_PROBLEMS]


# ---------- 元件、key 與結果 ----------

def _s(x, cap=64):
    """key 的一段：只留 [A-Za-z0-9._=+-]，其餘換成底線，最長 cap 個字元（inventory 的字串是不可信資料）。"""
    return KEY_BAD.sub("_", str(x))[:cap]


def rule_ident(kind, h):
    """規則表元件在映像內的識別（內容為主，不用位置）；同名的由 uniquify 加序號。"""
    if kind == "bios_image":
        return "image"
    if kind == "ami_core":
        return f"core={_s(h.get('core'))}"
    if kind == "intel_csme":
        return f"me={_s(h.get('version'))}"
    if kind == "amd_psp":
        return f"psp=0x{h['type']:02x}:{_s(h.get('version'))}:{_s(str(h.get('sha256') or '')[:12])}"
    if kind == "amd_microcode":
        return f"amdmc={_s(h.get('equiv_id'))}:{_s(h.get('patch_id'))}:{_s(str(h.get('sha256') or '')[:12])}"
    if kind == "amd_agesa":
        return f"agesa={_s(h.get('tag'))}:{_s(h.get('value'))}" + (":truncated" if h.get("truncated") else "")
    if kind == "intel_fsp":
        return f"fsp={_s(h.get('revision'))}:{_s(str(h.get('stored_sha256') or '')[:12])}"
    return _s(kind)


def review_of(state):
    """規則表的 state（preliminary、confirmed、兩者並列、None）→ preliminary｜confirmed｜None。有任何一條還是初審就是 preliminary。"""
    if not isinstance(state, str) or not state:
        return None
    return "preliminary" if "preliminary" in state else ("confirmed" if state == "confirmed" else None)


def _ids(xs):
    if not isinstance(xs, list) or not all(isinstance(x, str) for x in xs):
        return None
    return sorted(set(xs))


def _res(result, bulletins, reason, review):
    return {"result": result, "bulletins": bulletins, "reason": reason, "review": review}


def norm_rule(r):
    """規則表的結果（holder["rule_advisory"]）→ {result, bulletins, reason, review}；形狀不對 → None（Release 當時的結果不能讀）。"""
    if not isinstance(r, dict):
        return None
    ids, reason = _ids(r.get("rule_ids")), r.get("reason")
    if r.get("suggestion") not in ("affected", "not-affected", "NOT_ASSESSED") or ids is None or not (reason is None or isinstance(reason, str)):
        return None
    return _res(r["suggestion"], ids, reason, review_of(r.get("state")))


def norm_ucode(r):
    if not isinstance(r, dict) or not isinstance(r.get("candidates"), list) or not all(isinstance(c, dict) and isinstance(c.get("id"), str) for c in r["candidates"]):
        return None
    reason = r.get("reason")
    if r.get("match") not in ("affected-candidate", "older-no-sa", "up-to-date", "NOT_ASSESSED") or not (reason is None or isinstance(reason, str)):
        return None
    return _res(r["match"], sorted({c["id"] for c in r["candidates"]}), reason, None)


def norm_vbios(r):
    if not isinstance(r, dict):
        return None
    ids, reason = _ids(r.get("bulletins")), r.get("reason")
    if r.get("match") not in ("affected", "fixed", "NOT_ASSESSED") or ids is None or not (reason is None or isinstance(reason, str)):
        return None
    return _res(r["match"], ids, reason, None)


def uniquify(items):
    """items：[(base key, 細分函式或 None)] → 唯一的 key 清單。同一個 base 出現不只一次時先用細分函式（加雜湊）；還是重複的，整組加 `#序號`（依 inventory 的順序，
    sanitize 後的字元沒有 #，不會和一般的 key 撞）。"""
    cnt = Counter(b for b, _ in items)
    keys = [fine(b) if cnt[b] > 1 and fine else b for b, fine in items]
    cnt = Counter(keys)
    seen, out = Counter(), []
    for k in keys:
        if cnt[k] > 1:
            seen[k] += 1
            out.append(f"{k}#{seen[k]}")
        else:
            out.append(k)
    return out


def collect(xf, inv):
    """inventory → 元件清單（依 inventory 的順序）：每個元件一筆 {kind, key, component, res}；res 是目前記在 inventory 裡的比對結果（形狀不對 → None）。
    key 只由 inventory 的內容組成（不含比對結果）：
      rule:<元件種類>:<映像 sha256 前 16 碼>:<元件識別>   ucode:<cpuid>/<platform_id>:<revision>   vbios:<vendor>:<device>:<ROM sha256 前 16 碼>"""
    items, rows = [], []
    for b in inv["bios"]:
        img = b["sha256"][:16]
        for holder, kind, _comp, _img, label in xf._rules_targets({"bios": [b]}):
            items.append((f"rule:{kind}:{img}:{rule_ident(kind, holder)}", None))
            rows.append(("rule", label, norm_rule(holder.get("rule_advisory"))))
        for u in b["microcode"]:
            sha = u["sha256"][:12]
            items.append((f"ucode:{_s(u['cpuid'])}/{_s(u['platform_id'])}:{_s(u['revision'])}", lambda k, sha=sha: f"{k}:{sha}"))
            rows.append(("intel-microcode", f"microcode {u['cpuid']} rev {u['revision']}", norm_ucode(u.get("advisory"))))
    for v in inv["vbios"]:
        items.append((f"vbios:{_s(v['vendor'])}:{_s(v['device'])}:{v['sha256'][:16]}", None))
        rows.append(("nvidia-vbios", f"NVIDIA VBIOS {v['device']}" + (f" {v['version']}" if v["version"] else ""), norm_vbios(v.get("advisory"))))
    keys = uniquify(items)
    return [{"key": k, "kind": kind, "component": label, "res": res} for k, (kind, label, res) in zip(keys, rows)]


def strip_results(inv):
    """舊的比對結果全部清掉（今天的結果由三個 *_section 重新寫進來）：頂層的 advisory、vbios_advisory、rules_advisory、status、detail，
    微碼與 vBIOS 的 advisory，任何位置的 rule_advisory。"""
    for k in OLD_RESULT_KEYS:
        inv.pop(k, None)
    for b in inv["bios"]:
        for u in b["microcode"]:
            u.pop("advisory", None)
    for v in inv["vbios"]:
        v.pop("advisory", None)

    def walk(x, depth=0):
        if depth > 64:
            return
        if isinstance(x, dict):
            x.pop("rule_advisory", None)
            for y in x.values():
                walk(y, depth + 1)
        elif isinstance(x, list):
            for y in x:
                walk(y, depth + 1)
    walk(inv)


# ---------- 表的識別 ----------

def load_tables(xf, advisory=None, vbios_advisory=None, rules=None):
    """→ {name: Table 或 TableError}（三個 *_section 吃的形式）。給了就用給的（測試用）；沒給就載入 repo 內的表。"""
    out = {}
    for name, mod, given in (("intel_microcode", "fw_advisory", advisory), ("nvidia_vbios", "nvidia_vbios_advisory", vbios_advisory),
                             ("fw_advisory_rules", "fw_advisory_rules", rules)):
        if given is not None:
            out[name] = given
            continue
        table, err = xf.load_sibling(mod).load_default()
        out[name] = table if table is not None else err
    return out


def table_info(xf, tabs, now):
    """三張表的識別、狀態與是否過期（用沒有元件的 inventory 呼叫三個 *_section 取得）。GAP 時識別欄位是 null，另有 gap（原因）。"""
    probe = {"bios": [], "vbios": []}
    adv = xf.advisory_section(probe, tabs["intel_microcode"])
    va = xf.vbios_advisory_section(probe, tabs["nvidia_vbios"], now)
    ra = xf.rules_section(probe, tabs["fw_advisory_rules"])
    info = {}
    for name, sec, fields in (("fw_advisory_rules", ra, lambda s: {"sha256": s["table"]["sha256"], "table_updated": s["table"]["updated"]}),
                              ("intel_microcode", adv, lambda s: {"source_commit": s["source"]["commit"], "source_tag": s["source"]["tag"],
                                                                   "table_sha256": s["source"]["table_sha256"]}),
                              ("nvidia_vbios", va, lambda s: {"sha256": s["source"]["table_sha256"], "mirror_commit": s["source"]["mirror_commit"],
                                                              "reviewed_until": s["source"]["reviewed_until"]})):
        if sec["status"] == "OK":
            info[name] = {**fields(sec), "status": "OK", "stale": bool(sec.get("stale", False))}
        else:
            nulls = {"fw_advisory_rules": ("sha256", "table_updated"), "intel_microcode": ("source_commit", "source_tag", "table_sha256"),
                     "nvidia_vbios": ("sha256", "mirror_commit", "reviewed_until")}[name]
            info[name] = {**{k: None for k in nulls}, "status": "GAP", "stale": False, "gap": sec["gap"]}
    return info


# ---------- 一個樣本 ----------

def rematch_inventory(xf, inv, now, tabs, info):
    """檢查過結構的 inventory（會被改動）→ dict：status、reasons、results、changed、cdx（文字）、md（文字）。"""
    entries = collect(xf, inv)
    before = [e["res"] for e in entries]
    strip_results(inv)
    inv["advisory"] = xf.advisory_section(inv, tabs["intel_microcode"])
    inv["vbios_advisory"] = xf.vbios_advisory_section(inv, tabs["nvidia_vbios"], now)
    inv["rules_advisory"] = xf.rules_section(inv, tabs["fw_advisory_rules"])        # 要在 declared_version 與 ME family（inventory 內已有）之後
    st, base, att = xf.status_parts(inv)
    inv["status"], inv["detail"] = st, base + "".join("；" + x for x in att)
    comps, deps = xf.components(inv)
    cdx = json.dumps(xf.bom(comps, deps), ensure_ascii=False, indent=1) + "\n"
    md = xf.markdown(inv)
    entries_after = collect(xf, inv)
    if [e["key"] for e in entries_after] != [e["key"] for e in entries]:
        raise RuntimeError("component keys changed between the two passes")
    results, changed = [], []
    for e, old in zip(entries_after, before):
        new = e["res"]
        if new is None:
            raise RuntimeError("a component has no result after the rematch")
        results.append({"key": e["key"], "kind": e["kind"], "component": e["component"], **new})
        old = old or _res(None, [], None, None)
        if old != new:
            changed.append({"key": e["key"], "kind": e["kind"], "before": old, "after": new})
    reasons = []
    for name in TABLES:
        if info[name]["status"] == "GAP":
            reasons.append(f"{name}: table cannot be used (GAP): {info[name]['gap']}")
    if changed:
        reasons.append(f"changed since release: {len(changed)} result(s)")
    if st == "GAP":
        reasons.append(f"inventory: {base}")
    reasons += [f"inventory: {x}" for x in att]
    gap = st == "GAP" or any(info[n]["status"] == "GAP" for n in TABLES)
    status = "GAP" if gap else ("ATTENTION" if (st == "ATTENTION" or changed) else "OK")
    return {"status": status, "reasons": reasons, "results": results, "changed": changed, "cdx": cdx, "md": md}


def md_banner(xf, slug, tag, now_text, status, reasons, info, changed):
    e = xf.md_esc
    L = [f"# 韌體公告重跑（{e(now_text)}）", "",
         f"- 樣本：`{e(slug)}`（Release `{e(tag)}`）；狀態：**{status}**",
         "- 只用 repo 當下的三張公告表重跑 Release 當時的 inventory，不重新解析映像、不連網；解析器改進要重新打 Release 才會反映。"
         "下面「韌體清點」的內容是 inventory 的內容用今天的比對結果重新產生。",
         "- 表（status、是否過期；識別見 `rematch-<slug>.json` 的 tables）：" + "；".join(
             f"{n} {e(info[n]['status'])}" + ("、stale" if info[n]["stale"] else "") for n in TABLES), ""]
    if reasons:
        L += ["## 重跑的狀態原因", ""] + [f"- {e(x)}" for x in reasons] + [""]
    if changed:
        L += ["## 和 Release 當時不同的結果", ""]
        for c in changed:
            b, a = c["before"], c["after"]
            L.append(f"- `{e(c['key'])}`：Release 當時 {e(b['result'])}（{e(', '.join(b['bulletins']) or '-')}）→ 今天 {e(a['result'])}（{e(', '.join(a['bulletins']) or '-')}）")
        L.append("")
    return "\n".join(L) + "\n---\n\n"


def sample_doc(slug, version, tag, sha, now_text, status, reasons, info, results, changed):
    return {"schema": REMATCH_SCHEMA, "slug": slug, "firmware_version": version, "release_tag": tag, "inventory_sha256": sha, "now": now_text,
            "status": status, "reasons": reasons, "tables": info, "results": results, "changed": changed}


def process_sample(xf, slug, plan, dfd, tag, now, now_text, tabs, info, limit=None):
    """一個 bios 樣本 → (rematch dict, cdx 文字或 None, md 文字或 None)。輸入有問題、處理超過 limit 秒（沒給就用 SAMPLE_LIMIT）→ GAP（rematch-input-invalid），不丟例外。"""
    try:
        with deadline(SAMPLE_LIMIT if limit is None else limit):
            return _process_sample(xf, slug, plan, dfd, tag, now, now_text, tabs, info)
    except TimeLimit:
        r = sample_doc(slug, plan["firmware_version"], tag, plan["inventory_sha256"], now_text, "GAP", ["rematch-input-invalid: time limit exceeded"], info, [], [])
        return r, None, None


def _process_sample(xf, slug, plan, dfd, tag, now, now_text, tabs, info):
    sha_meta = plan["inventory_sha256"]

    def gap(why):
        r = sample_doc(slug, plan["firmware_version"], tag, sha_meta, now_text, "GAP", [f"rematch-input-invalid: {why}"], info, [], [])
        return r, None, None
    try:
        if dfd is None:
            raise InputError("attachment directory cannot be opened")
        data = read_file(plan["inventory"], MAX_INVENTORY, dfd)
        if hashlib.sha256(data).hexdigest() != sha_meta:
            raise InputError("inventory sha256 does not match firmware-meta.json")
        inv = parse_json(data)
        probs = inventory_problems(inv)
        if probs:
            raise InputError("inventory structure: " + "; ".join(probs))
    except InputError as e:
        return gap(str(e))
    try:
        r = rematch_inventory(xf, inv, now, tabs, info)
        doc = sample_doc(slug, plan["firmware_version"], tag, sha_meta, now_text, r["status"], r["reasons"], info, r["results"], r["changed"])
        md = md_banner(xf, slug, tag, now_text, r["status"], r["reasons"], info, r["changed"]) + r["md"]
        for text in (dump(doc), r["cdx"], md):
            text.encode("utf-8")            # 單獨的代理字元等寫不出去的字元（inventory 是不可信資料）：這一份 GAP，不讓整次執行失敗
    except Exception as e:                  # 形狀檢查沒擋到的異常內容：這一份 GAP，其他樣本照常
        return gap(f"inventory could not be processed ({type(e).__name__})")
    return doc, r["cdx"], md


# ---------- 整次執行 ----------

def one_line(xf, x, cap=400):
    return xf._plain(x)[:cap]


def summary_text(xf, doc):
    """stdout 的說明：結果數、changed 數、原因數（原因全文在 rematch-<slug>.json）；表不能用的原因直接寫出。"""
    head = f"結果 {len(doc['results'])} 項，changed {len(doc['changed'])}，原因 {len(doc['reasons'])} 項（見 rematch-{doc['slug']}.json）"
    shown = doc["reasons"][:1] if doc["status"] == "GAP" else [x for x in doc["reasons"] if "table cannot be used" in x]
    return one_line(xf, head + "".join("；" + x for x in shown))


def dump(doc):
    return json.dumps(doc, ensure_ascii=False, indent=1) + "\n"


class Writer:
    """--out 的輸出：先寫暫存檔再 os.replace；失敗時整批刪掉（不留新舊混合）。"""

    def __init__(self, out):
        self.out, self.done = Path(out), []

    def write(self, name, text):
        tmp = self.out / f".{name}.tmp"
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, self.out / name)
        self.done.append(name)

    def rollback(self):
        for name in self.done:
            try:
                (self.out / name).unlink(missing_ok=True)
            except OSError:
                pass
        for p in self.out.glob(".*.tmp"):
            try:
                p.unlink()
            except OSError:
                pass


def run(xf, meta_path, dir_path, now_text, out, tables=None):
    """→ (退出碼, stdout 的行)。tables：測試用，傳給 load_tables 的 {advisory、vbios_advisory、rules: Table 或 TableError}。"""
    m = NOW_RE.fullmatch(now_text or "")
    if not m:
        raise ArgError("--now must be UTC like 2026-11-21T02:00:00Z (hour 00-23)")
    try:
        now = datetime.datetime(*[int(x) for x in m.groups()], tzinfo=datetime.timezone.utc)
    except ValueError:
        raise ArgError("--now is not a valid date")
    outp = Path(out)
    if outp.is_symlink() or (outp.exists() and (not outp.is_dir() or any(outp.iterdir()))):
        raise ArgError("--out must not exist yet or be an empty directory")
    tabs = load_tables(xf, **(tables or {}))
    info = table_info(xf, tabs, now)
    lines, summary_samples, rc, gap_slugs, rejected = [], [], 0, set(), []
    t0 = time.monotonic()
    tag, meta_reasons, plans = None, [], []
    try:
        tag, samples = parse_meta(read_file(meta_path, MAX_META))
        slugs = Counter(s.get("slug") for s in samples if isinstance(s, dict) and isinstance(s.get("slug"), str))
        dups = {k for k, n in slugs.items() if n > 1}
        plans = [plan_sample(s, dups) for s in samples]
        if not any(p[0] != "skip" for p in plans):
            raise InputError("firmware-meta.json lists no bios sample to rematch")
    except InputError as e:
        meta_reasons = [f"rematch-input-invalid: {e}"]
    outp.mkdir(parents=True, exist_ok=True)
    w = Writer(outp)
    try:
        if meta_reasons:
            lines.append(f"FIRMWARE-REMATCH\tGAP\t-\t{one_line(xf, meta_reasons[0])}")
            rc = 2
            plans = []
        dfd = None
        if plans:
            try:
                dfd = os.open(dir_path, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0))
            except OSError:
                dfd = None
        try:
            for index, (kind, slug, data) in enumerate(plans):
                if kind == "skip":
                    continue
                if kind == "reject":                            # 沒有可用的 slug：沒有檔名可寫，只記在總表的 rejected
                    rejected.append({"index": index, "reason": data})
                    lines.append(f"FIRMWARE-REMATCH\tGAP\t-\tsample #{index} in firmware-meta.json rejected: {data}")
                    rc = 2
                    continue
                if kind == "gap":
                    if slug in gap_slugs:                       # 同一個 slug 重複：整組一份輸出，其餘記在 rejected
                        rejected.append({"index": index, "reason": "duplicate-slug"})
                        continue
                    why = f"rematch-input-invalid: {data}"
                    lines.append(f"FIRMWARE-REMATCH\tGAP\t{slug or '-'}\t{why}")
                    rc = 2
                    if slug:
                        gap_slugs.add(slug)
                        doc = sample_doc(slug, None, tag, None, now_text, "GAP", [why], info, [], [])
                        w.write(f"rematch-{slug}.json", dump(doc))
                        summary_samples.append({"slug": slug, "status": "GAP", "output": f"rematch-{slug}.json", "reasons": [why]})
                    continue
                doc, cdx, md = process_sample(xf, slug, data, dfd, tag, now, now_text, tabs, info, limit=min(SAMPLE_LIMIT, TOTAL_LIMIT - (time.monotonic() - t0)))
                w.write(f"rematch-{slug}.json", dump(doc))
                if cdx is not None:
                    w.write(f"fw-{slug}.cdx.json", cdx)
                    w.write(f"fw-inventory-{slug}.md", md)
                entry = {"slug": slug, "status": doc["status"], "output": f"rematch-{slug}.json"}
                if doc["status"] == "GAP":
                    entry["reasons"] = doc["reasons"]
                summary_samples.append(entry)
                lines.append(f"FIRMWARE-REMATCH\t{doc['status']}\t{slug}\t{summary_text(xf, doc)}")
                if doc["status"] != "OK":
                    rc = 2
        finally:
            if dfd is not None:
                os.close(dfd)
        summary = {"schema": SUMMARY_SCHEMA, "release_tag": tag, "now": now_text, "meta_status": "GAP" if meta_reasons else "OK",
                   **({"reasons": meta_reasons} if meta_reasons else {}), "tables": info, "samples": summary_samples, "rejected": rejected}
        w.write("rematch-summary.json", dump(summary))
    except Exception as e:                  # 寫不出輸出或內部錯誤：已寫的輸出全部刪掉（沒有 rematch-summary.json，呼叫端標 NOT_RUN）
        w.rollback()
        return 1, [f"FIRMWARE-REMATCH\tFAIL\t-\t{'cannot write to --out' if isinstance(e, OSError) else 'internal error'} ({type(e).__name__})"]
    return rc, lines


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ArgError(message)


def main(argv, xf=None):
    if xf is None:
        xf = sys.modules.get("x86_firmware")
        if xf is None:
            raise RuntimeError("run through x86_firmware.py --rematch")
    ap = Parser(prog="x86_firmware.py --rematch", allow_abbrev=False)
    for name in ("--meta", "--dir", "--now", "--out"):
        ap.add_argument(name, required=True)
    try:
        a = ap.parse_args(argv)
        rc, lines = run(xf, a.meta, a.dir, a.now, a.out)
    except ArgError as e:
        print(f"FIRMWARE-REMATCH\tFAIL\t-\t{one_line(xf, e)}")
        return 64
    except Exception as e:                  # 內部錯誤：不留半套輸出的責任在 run（OSError）；其餘一律 FAIL，呼叫端標 NOT_RUN
        print(f"FIRMWARE-REMATCH\tFAIL\t-\tinternal error ({type(e).__name__})")
        return 1
    for line in lines:
        print(line)
    return rc


if __name__ == "__main__":
    print("use pipeline/firmware-rematch.sh", file=sys.stderr)
    sys.exit(64)
