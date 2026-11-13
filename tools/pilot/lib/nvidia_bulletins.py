#!/usr/bin/env python3
"""nvidia_bulletins.py：用人工審核過的 NVIDIA 安全公告對照表，判斷 Jetson Linux（L4T）映像受哪些公告影響。

為什麼：NVIDIA 對 Jetson Linux 的公告只寫自由文字版本（「All versions prior to 36.5」「35.6.2 and earlier」「38.2」），
CSAF 的 CPE 格式不對、沒有 purl，Grype 與 DT 都比對不到；NVD 約 4 個月後才有 cpe:2.3:o:nvidia:jetson_linux 的範圍。
所以由人把公告整理成對照表（nvidia-bulletins.json），這裡只做「SBOM 的 Jetson Linux 版本 < 修正版本」的比較。
工作流程見同資料夾的 nvidia-bulletins.md。

子命令：
  match --sbom <CycloneDX JSON> --table <對照表> [--mirror <公告鏡像>] --out <findings.json>
      印一行「C-nvidia-bulletins<TAB>狀態<TAB>說明」。
  candidates --mirror <公告鏡像> --table <對照表> [--group jetson|gpu-firmware|gpu-driver] [--out <json>] [--draft <json>]
      印一行「C-nvidia-bulletins-db<TAB>狀態<TAB>說明」；待審公告另逐行印到 stderr。--draft 寫出待審公告的草稿列（reviewed=false）。
      --group 依產品類型選鏡像的選取群組（預設 jetson）：Jetson 產品 → jetson；顯卡 vBIOS → gpu-firmware；驅動、工具軟體 → gpu-driver。
      每個群組用自己的對照表。舊格式的鏡像（沒有 groups）只算 jetson；問其他群組 → GAP（鏡像沒有選這個群組）。
      gpu-firmware：NVIDIA 幾乎沒有公開消費型顯卡 vBIOS 的公告；「沒有待審公告」不代表 vBIOS 沒有漏洞（說明會寫明）。
      之後的 vBIOS 比對沒有對到公告時是 NOT_ASSESSED，不是 OK（VBIOS_NOT_ASSESSED）。
  match 只用 jetson 群組（Jetson Linux 的 SBOM）。
退出碼：0 已判定；3 輸入錯誤（同時印 FAIL 那一行，不印 traceback）。

match 的判定（依序，取第一個成立的）：
  NOT_RUN    SBOM 沒有 nvidia-l4t-* 的 deb 套件（不是 Jetson Linux）；呼叫端不寫這一列。
  GAP        對照表不存在；或沒給 --mirror、鏡像不存在、讀不到或過期（NVBUL_MAX_AGE_DAYS，預設 7 天），無法確認對照表涵蓋最新公告；
             或鏡像裡有對照表沒有的 Jetson／IGX 公告（不在表上，也不在 not_applicable），或 NVIDIA 修訂過表上的公告。
             發現仍照算、照寫，只是不能當作完整。
  ATTENTION  掃描到的版本線有未審核的列（其他版本線的未審核列不影響，只計數）；或有 CVE 需原廠確認（見下）；
             或同版本線的列落在「受影響範圍」與「修正版本」之間的空隙；或 SBOM 裡有多個 Jetson Linux 版本。
  OK         已比較完（有沒有發現都是 OK；發現數寫在說明與 findings.json）。
  未審核的列不產生發現，只計數；同版本線且版本落在範圍內的另列在 unreviewed_would_match 給審核的人看。
公告沒有列出掃描到的版本線（例如公告只寫 35／36／38，映像是 39）的 CVE：由 unnamed_line_policy() 決定（只有這一個函式，要改成
  「一律需原廠確認」只改它）。目前的規則（使用者 2026-11-02 決定）：映像的建置日期（nvidia-l4t-* 版本的 14 位時間戳）晚於公告的
  首次發布日 → presumed_included「推定已含修正，NVIDIA 未確認」，本身不造成 ATTENTION；同一天、較早或日期不明 → 需原廠確認（ATTENTION）。
  兩種都不是「不受影響」。

candidates 的判定：GAP＝鏡像不存在、讀不到或過期；ATTENTION＝有待審公告；OK＝沒有待審公告。
  待審公告＝鏡像選入、屬於 --group 群組（預設 Jetson／IGX）的公告中：不在對照表也不在 not_applicable、或公告日期晚於 reviewed_until、
  或鏡像的修訂日期比對照表記錄的新、或該公告還有未審核的列、或 not_applicable 的判定還沒審核。

版本：Jetson Linux 版本是點分整數（35.6.2 < 35.6.4 < 36.5；36.5 = 36.5.0）。SBOM 的 nvidia-l4t-* 版本是 <版本>-<14 位時間戳>，
核心套件是 <核心版本>-tegra-<版本>-<時間戳>。優先取 nvidia-l4t-core，沒有時取最多套件使用的版本。
不涵蓋：flash 裡的韌體（MB1／MB2、BPMP、QSPI 的 UEFI、OP-TEE 映像）不在 rootfs SBOM，只能用 rootfs 的版本推定；
客戶自己改過的 BSP；公告的自由文字版本由人判讀（這裡不猜）。
"""
import argparse
import collections
import datetime
import json
import math
import os
import re
import stat
import sys
from urllib.parse import unquote

STAGE = "C-nvidia-bulletins"
STAGE_DB = "C-nvidia-bulletins-db"
TABLE_SCHEMA = "sca-nvidia-bulletins-table/1"
# 公告鏡像的選取群組：與 tools/mirror/nvidia-bulletins.sh 的 GROUPS 相同（測試會比對）
GROUPS = {
    "jetson": re.compile(r"\b(jetson|igx|jetpack|l4t)\b", re.I),
    "gpu-firmware": re.compile(r"\b(vbios|gpu firmware)\b", re.I),
    "gpu-driver": re.compile(r"\b(gpu display driver|geforce|quadro|rtx)\b", re.I),
}
GROUP_LABEL = {"jetson": "Jetson／IGX", "gpu-firmware": "GPU 韌體（vBIOS）", "gpu-driver": "GPU 顯示驅動與工具軟體"}
JETSON_RE = GROUPS["jetson"]
# 顯卡 vBIOS：公開公告幾乎沒有（2026-11 公開鏡像 203 則裡標題有 VBIOS 的只有 1 則，而且是 HGX／DGX）。
# 比對沒有對到公告不能顯示成 OK：狀態 NOT_ASSESSED，說明用這段文字。
VBIOS_NOT_ASSESSED = ("NVIDIA 沒有公開這類 vBIOS 的公告；修補狀態要問顯卡團隊或 NVIDIA 的合作夥伴管道"
                      "（沒有對到公告不代表沒有漏洞）")
DEFAULT_MAX_AGE_DAYS = 7
# 公告沒有列出掃描到的版本線時，建置日期晚於公告就「推定已含修正」（unnamed_line_policy）；改成 False 就一律需原廠確認
PRESUME_INCLUDED_IF_BUILT_AFTER = True
REPO_URL = "https://github.com/NVIDIA/product-security"
L4T_VER = re.compile(r"^(\d+\.\d+(?:\.\d+)*)-(\d{14})$")
L4T_KVER = re.compile(r"^\d+\.\d+(?:\.\d+)*-tegra-(\d+\.\d+(?:\.\d+)*)-(\d{14})$")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
# vBIOS 列（line == "vbios"，C2 的 tools/cra/nvidia_vbios_advisory.py 比對；M7a2 與 C2 約定的格式）：
# 版本是 option ROM 的 XX.XX.XX.XX.XX，1～5 段、每段兩位十六進位（大小寫都收）；PCI ID 是 4 位小寫十六進位。
VBIOS_LINE = "vbios"
VBIOS_VER_RE = re.compile(r"^[0-9A-Fa-f]{2}(?:\.[0-9A-Fa-f]{2}){0,4}$")
VBIOS_VERSION_KEYS = ("vbios_affected_below", "vbios_affected_max", "vbios_fixed_in")
GENERIC_VERSION_KEYS = ("fixed_in", "affected_below", "affected_max")
HEX4_RE = re.compile(r"^[0-9a-f]{4}$")
# 公告編號：NVIDIA product-security 的公告是數字編號（例如 5797）；限制格式，避免公告欄位把 @、Markdown 等字元帶進報告（與 C2 同一套規則）
BULLETIN_ID_RE = re.compile(r"^[0-9]{1,8}$")
# 對照表頂層的 mirror：表是對哪一份公告鏡像審核的（鏡像的時間點；和 reviewed_until 分開記）
MIRROR_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
# 公告裡的 JetPack 主版本 → Jetson Linux 版本線（JetPack 4＝L4T 32、5＝35、6＝36）。
# JetPack 7 對應 38 與 39 兩條版本線，不能自動判斷：草稿列的 line 留 "?"，由人填。
JETPACK_LINE = {"4": "32", "5": "35", "6": "36"}
JETPACK_AMBIGUOUS = {"7": "38 或 39"}
# 草稿列的元件推測（依序第一個符合的；只是草稿，審核的人要確認）。where：rootfs 套件名稱、flash（SBOM 看不到）或 unknown。
COMPONENT_HINTS = (
    (r"\bUEFI\b", "UEFI", "flash"),
    (r"\binitrd\b", "initrd", "nvidia-l4t-initrd"),
    (r"\bNvMap\b", "NvMap（核心驅動）", "nvidia-l4t-kernel"),
    (r"\b(bootloader|MB1|MB2|BPMP|cboot|RCM)\b", "bootloader", "flash"),
    (r"\b(OP-?TEE|trusted application|TrustZone|TOS)\b", "OP-TEE／TA", "flash"),
    (r"\bkernel\b", "kernel", "nvidia-l4t-kernel"),
    (r"\bsystem initiali[sz]ation\b", "system init", "unknown"),
)
NOT_COVERED = [
    "flash 裡的韌體（MB1／MB2、BPMP 韌體、QSPI 的 UEFI、OP-TEE 映像）不在 rootfs SBOM；這類列的版本以 rootfs 的 Jetson Linux 版本推定，"
    "裝置實際刷的版本可能不同。",
    "客戶修改過的 BSP（自行編譯的核心、initrd、UEFI）：版本號仍是 NVIDIA 的，但內容不一定相同。",
    "公告的自由文字版本由人判讀成 fixed_in／affected_below／affected_max；對照表沒有審核的列不產生發現。",
    "IGX OS 的列不和 Jetson Linux 版本比較（IGX OS 版本無法從 SBOM 判斷）。",
]


class InputError(Exception):
    pass


# ---------- 版本 ----------

def vkey(s):
    """'35.6.2' → (35, 6, 2)；去掉尾端的 0（36.5 = 36.5.0）。不是點分整數時丟 ValueError。"""
    if not isinstance(s, str) or not re.fullmatch(r"\d+(\.\d+)*", s.strip()):
        raise ValueError(f"不是 Jetson Linux 版本：{s!r}")
    k = [int(x) for x in s.strip().split(".")]
    while len(k) > 1 and k[-1] == 0:
        k.pop()
    return tuple(k)


def cmp_version(a, b):
    ka, kb = vkey(a), vkey(b)
    return (ka > kb) - (ka < kb)


def versions_in(text):
    """自由文字裡的點分版本（'All versions prior to JP5.x: 35.6.2' → ['35.6.2']）。"""
    return re.findall(r"(?<![\w.])(\d+(?:\.\d+)+)(?![\w.])", text or "")


# ---------- SBOM ----------

def walk(cs):
    if cs is None:
        return
    if not isinstance(cs, list):
        raise InputError("components 不是清單")
    for c in cs:
        if isinstance(c, dict):
            yield c
            yield from walk(c.get("components"))


def purl_type_name(purl):
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return None, None
    body = purl[4:].split("#", 1)[0].split("?", 1)[0]
    if "/" not in body:
        return None, None
    typ, rest = body.split("/", 1)
    return typ.lower(), unquote(rest.rsplit("/", 1)[-1].split("@", 1)[0])


def detect_jetson(sbom):
    """SBOM 的 Jetson Linux 版本。回傳 None（沒有 nvidia-l4t-* deb）或 dict。"""
    if not isinstance(sbom, dict):
        raise InputError("SBOM 不是 JSON 物件")
    found = []
    for c in walk(sbom.get("components")):
        typ, name = purl_type_name(c.get("purl"))
        if typ is None:
            name = c.get("name")
        elif typ != "deb":
            continue
        ver = c.get("version")
        if not isinstance(name, str) or not name.startswith("nvidia-l4t-") or not isinstance(ver, str):
            continue
        m = L4T_VER.match(ver) or L4T_KVER.match(ver)
        if m:
            found.append({"name": name, "version": ver, "purl": c.get("purl"), "release": m.group(1), "build": m.group(2)})
    if not found:
        return None
    count = collections.Counter(vkey(x["release"]) for x in found)
    core = [x for x in found if x["name"] == "nvidia-l4t-core"]
    if core:
        anchor, basis = core[0], "nvidia-l4t-core"
    else:
        best = max(count, key=lambda k: (count[k], k))
        anchor = sorted((x for x in found if vkey(x["release"]) == best), key=lambda x: x["name"])[0]
        basis = f"最多 nvidia-l4t-* 套件使用的版本（{anchor['name']} 等 {count[best]} 個；沒有 nvidia-l4t-core）"
    rel = anchor["release"]
    others = sorted({x["release"] for x in found if vkey(x["release"]) != vkey(rel)}, key=vkey)
    b = anchor["build"]
    try:
        built = datetime.date(int(b[:4]), int(b[4:6]), int(b[6:8])).isoformat()
    except ValueError:
        built = None
    return {"version": rel, "line": str(vkey(rel)[0]), "build": b, "build_date": built, "basis": basis,
            "anchor": {"name": anchor["name"], "version": anchor["version"], "purl": anchor["purl"]},
            "packages": {x["name"]: {"name": x["name"], "version": x["version"], "purl": x["purl"]} for x in found},
            "l4t_packages": len(found), "other_versions": others}


# ---------- 對照表 ----------

def load_json(path, label):
    try:
        with open(path, encoding="utf-8-sig") as f:
            return json.load(f)
    except (OSError, ValueError, RecursionError) as e:
        raise InputError(f"{label} 無法讀取或解析（{type(e).__name__}）")


def _iso_with_tz(v):
    """帶時區的 ISO 8601 時間 → datetime；格式不對或沒有時區 → None。"""
    if not isinstance(v, str) or "T" not in v:
        return None
    try:
        d = datetime.datetime.fromisoformat(v[:-1] + "+00:00" if v.endswith("Z") else v)
    except ValueError:
        return None
    return d if d.tzinfo is not None else None


def _valid_date(v):
    if not (isinstance(v, str) and DATE_RE.match(v)):
        return False
    try:
        datetime.date.fromisoformat(v)
    except ValueError:
        return False
    return True


def _check_mirror(m):
    """對照表頂層 mirror 的格式（有寫才檢查；沒寫或 null 由 mirror_info 回 GAP）。日期在未來或過期是時間判斷，不在這裡擋。"""
    if not isinstance(m, dict):
        raise InputError("mirror 必須是物件（commit、commit_date、fetched_utc）")
    if not (isinstance(m.get("commit"), str) and MIRROR_COMMIT_RE.match(m["commit"])):
        raise InputError("mirror.commit 必須是 40 位小寫十六進位")
    cd = m.get("commit_date")
    if not (_valid_date(cd) or _iso_with_tz(cd)):
        raise InputError("mirror.commit_date 必須是 YYYY-MM-DD 或帶時區的 ISO 8601")
    if not _iso_with_tz(m.get("fetched_utc")):
        raise InputError("mirror.fetched_utc 必須是帶時區的 ISO 8601")


def mirror_info(t):
    """對照表是對哪一份公告鏡像審核的。沒有 mirror（或 null）→ GAP（不知道鏡像的時間點，不丟例外）；
    格式不對 → InputError（validate_table 也會擋）；其他 → OK。過期或在未來由呼叫端判斷。"""
    m = t.get("mirror") if isinstance(t, dict) else None
    if m is None:
        return {"status": "GAP", "commit": None, "commit_date": None, "fetched_utc": None,
                "reason": "對照表沒有 mirror：不知道審核時看的是哪一份公告鏡像"}
    _check_mirror(m)
    return {"status": "OK", "commit": m["commit"], "commit_date": m["commit_date"], "fetched_utc": m["fetched_utc"], "reason": None}


def _check_vbios_row(r, where):
    """line == "vbios" 的列（C2 約定）：版本欄位只用 vbios_*；版本格式不論是否已審核都檢查；PCI 欄位只在已審核的列檢查
    （草稿列可以是 null）；「pci_vendor 必須是 10de」由 C2 的比對端檢查。"""
    for k in GENERIC_VERSION_KEYS:
        if r.get(k) is not None:
            raise InputError(f"{where} 是 vbios 列，版本要寫在 vbios_*，不能寫 {k}")
    vers = {}
    for k in VBIOS_VERSION_KEYS:
        if r.get(k) is not None:
            if not (isinstance(r[k], str) and VBIOS_VER_RE.match(r[k])):
                raise InputError(f"{where} 的 {k} 不是 XX.XX.XX.XX.XX 版本（1～5 段、每段兩位十六進位）：{r[k]!r}")
            vers[k] = tuple(int(x, 16) for x in r[k].split("."))
    if not r["reviewed"]:
        return
    if not (isinstance(r.get("pci_vendor"), str) and HEX4_RE.match(r["pci_vendor"])):
        raise InputError(f"{where} 已審核但 pci_vendor 不是 4 位小寫十六進位")
    d = r.get("pci_devices")
    if not (isinstance(d, list) and d and all(isinstance(x, str) and HEX4_RE.match(x) for x in d)):
        raise InputError(f"{where} 已審核但 pci_devices 不是非空的 4 位小寫十六進位清單")
    if not vers:
        raise InputError(f"{where} 已審核但沒有任何可比較的版本（{'、'.join(VBIOS_VERSION_KEYS)}）")
    below, top, fixed = (vers.get(k) for k in VBIOS_VERSION_KEYS)
    if below and top:
        raise InputError(f"{where} 的 vbios_affected_below 與 vbios_affected_max 只能寫一個（mutually exclusive）")

    def pad(v, fill):
        return v + (fill,) * (5 - len(v))
    if fixed and below and pad(fixed, 0x00) < pad(below, 0x00):
        raise InputError(f"{where} 的 vbios_fixed_in 低於 vbios_affected_below（自相矛盾，contradictory row）")
    if fixed and top and pad(fixed, 0x00) <= pad(top, 0xFF):
        raise InputError(f"{where} 的 vbios_fixed_in 不高於 vbios_affected_max（自相矛盾，contradictory row）")


def validate_table(t):
    if not isinstance(t, dict) or t.get("schema") != TABLE_SCHEMA:
        raise InputError(f"對照表的 schema 不是 {TABLE_SCHEMA}")
    ru = t.get("reviewed_until")
    if ru is not None and not (isinstance(ru, str) and DATE_RE.match(ru)):
        raise InputError("reviewed_until 必須是 null 或 YYYY-MM-DD")
    if t.get("mirror") is not None:
        _check_mirror(t["mirror"])
    for k in ("bulletins", "rows", "not_applicable"):
        if not isinstance(t.get(k, []), list):
            raise InputError(f"{k} 不是清單")
    ids = set()
    for b in t.get("bulletins", []):
        if not isinstance(b, dict) or not isinstance(b.get("id"), str) or not isinstance(b.get("cves", {}), dict):
            raise InputError("bulletins 每一筆要有 id（字串）與 cves（物件）")
        if not BULLETIN_ID_RE.match(b["id"]):
            raise InputError(f"bulletins 的 id 必須是數字編號：{b['id']!r}")
        ids.add(b["id"])
    for i, r in enumerate(t.get("rows", [])):
        where = f"rows[{i}]"
        if not isinstance(r, dict):
            raise InputError(f"{where} 不是物件")
        for k in ("bulletin", "cve", "line"):
            if not isinstance(r.get(k), str) or not r[k]:
                raise InputError(f"{where} 缺少 {k}")
        if r["bulletin"] not in ids:
            raise InputError(f"{where} 的公告 {r['bulletin']} 不在 bulletins")
        if not CVE_RE.fullmatch(r["cve"]):
            raise InputError(f"{where} 的 cve 格式不對：{r['cve']!r}")
        if not isinstance(r.get("reviewed"), bool):
            raise InputError(f"{where} 的 reviewed 必須是 true 或 false")
        if r["line"] == VBIOS_LINE:
            _check_vbios_row(r, where)
        else:
            extra = sorted(k for k in r if (k.startswith("vbios_") or k.startswith("pci_")) and r[k] is not None)
            if extra:
                raise InputError(f"{where} 不是 vbios 列，不能有 {'、'.join(extra)}（會被忽略）")
        for k in GENERIC_VERSION_KEYS:
            if r.get(k) is not None:
                try:
                    vkey(r[k])
                except ValueError:
                    raise InputError(f"{where} 的 {k} 不是點分版本：{r[k]!r}")
        if r["reviewed"]:
            if not r.get("reviewed_by") or not (isinstance(r.get("reviewed_at"), str) and DATE_RE.match(r["reviewed_at"])):
                raise InputError(f"{where} 已審核但缺少 reviewed_by 或 reviewed_at（YYYY-MM-DD）")
            if r["line"].isdigit() and not (r.get("fixed_in") or r.get("affected_below") or r.get("affected_max")):
                raise InputError(f"{where} 已審核但沒有任何可比較的版本（fixed_in、affected_below、affected_max）")
    for i, x in enumerate(t.get("not_applicable", [])):
        if not isinstance(x, dict) or not isinstance(x.get("bulletin"), str):
            raise InputError(f"not_applicable[{i}] 要有 bulletin")
        if not BULLETIN_ID_RE.match(x["bulletin"]):
            raise InputError(f"not_applicable[{i}] 的 bulletin 必須是數字編號：{x['bulletin']!r}")
        if x.get("reviewed", True) is not False and not (x.get("reviewed_by") and isinstance(x.get("reviewed_at"), str)
                                                          and DATE_RE.match(x["reviewed_at"])):
            raise InputError(f"not_applicable[{i}] 要有 reviewed_by 與 reviewed_at（YYYY-MM-DD），還沒審核的寫 reviewed=false")
    return t


def evaluate(row, version):
    """'affected'（在受影響範圍）、'fixed'（≥ 修正版本）、'unknown'（範圍與修正版本之間的空隙，或沒有可比較的版本）。"""
    v = vkey(version)
    if row.get("fixed_in") and v >= vkey(row["fixed_in"]):
        return "fixed"
    if row.get("affected_below"):
        return "affected" if v < vkey(row["affected_below"]) else "unknown"
    if row.get("affected_max"):
        return "affected" if v <= vkey(row["affected_max"]) else "unknown"
    if row.get("fixed_in"):
        return "affected"
    return "unknown"


def bulletin_date(b):
    """公告的日期：首次發布日與最近修訂日中較晚的那一個（修訂過的公告以修訂日為準，比較保守）；都沒有時 None。"""
    ds = [x for x in (day(b.get("initial_release_date")), day(b.get("current_release_date"))) if x and DATE_RE.match(x)]
    return max(ds) if ds else None


def unnamed_line_policy(bulletin_date, build_date, lines_named=None):
    """公告沒有列出掃描到的版本線時怎麼看（唯一決定這件事的地方）。
    回傳 'presumed_included'（映像建置日期晚於公告日期〔bulletin_date()：首次發布與修訂中較晚的〕：推定已含修正，NVIDIA 未確認）
    或 'needs_confirmation'（同一天、較早、任一日期不明，或公告只列 IGX OS 等非 Jetson Linux 版本線）。兩者都不是「不受影響」。
    PRESUME_INCLUDED_IF_BUILT_AFTER=False 時一律 needs_confirmation。"""
    if lines_named is not None and not any(str(x).isdigit() for x in lines_named):
        return "needs_confirmation"     # 公告沒有任何 Jetson Linux 版本線（例如只列 IGX OS）：不能拿 Jetson 的建置日推定
    b, r = day(bulletin_date), day(build_date)
    if PRESUME_INCLUDED_IF_BUILT_AFTER and b and r and DATE_RE.match(b) and DATE_RE.match(r) and r > b:
        return "presumed_included"
    return "needs_confirmation"


# ---------- 鏡像 ----------

def bulletin_groups(b):
    """index.json 一則公告屬於哪些群組；舊格式（沒有 groups，只選 Jetson）→ ['jetson']。"""
    g = b.get("groups")
    return [x for x in g if isinstance(x, str)] if isinstance(g, list) else ["jetson"]


def mirror_state(d, max_age=None, group="jetson"):
    """鏡像的新舊與 index.json。回傳 dict：ok、reason、commit、fetched_utc、age_days、group、bulletins（選入、屬於 group 的）。"""
    if max_age is None:
        try:
            max_age = float(os.environ.get("NVBUL_MAX_AGE_DAYS", DEFAULT_MAX_AGE_DAYS))
        except ValueError:
            max_age = DEFAULT_MAX_AGE_DAYS
    st = {"path": d, "ok": False, "reason": None, "commit": None, "fetched_utc": None, "age_days": None,
          "max_age_days": max_age, "group": group, "bulletins": []}
    if not d or not os.path.isdir(d):
        st["reason"] = f"公告鏡像資料夾不存在（{d}）"
        return st
    for n in ("SOURCE", "index.json"):    # 先確認是一般檔案才開（FIFO 會讓讀取卡住，連結可能指到鏡像外）
        pth = os.path.join(d, n)
        if os.path.lexists(pth) and not stat.S_ISREG(os.lstat(pth).st_mode):
            st["reason"] = f"公告鏡像（{d}）的 {n} 不是一般檔案"
            return st
    try:
        with open(os.path.join(d, "SOURCE"), encoding="utf-8") as f:
            src = dict(l.split("=", 1) for l in f.read().splitlines() if "=" in l)
        fetched = datetime.datetime.fromisoformat(src["fetched_utc"].replace("Z", "+00:00"))
        if fetched.tzinfo is None:
            raise ValueError
        with open(os.path.join(d, "index.json"), encoding="utf-8") as f:
            idx = json.load(f)
        bs = [b for b in idx["bulletins"] if isinstance(b, dict) and b.get("selected") and isinstance(b.get("id"), str)
              and group in bulletin_groups(b)]
        sel = idx.get("selection")
        has_group = group in sel if isinstance(sel, dict) else group == "jetson"     # 舊格式的 selection 是 Jetson 的 regex 字串
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError) as e:
        st["reason"] = f"公告鏡像（{d}）的 SOURCE 或 index.json 缺少或無法讀取（{type(e).__name__}），不是 nvidia-bulletins.sh 產生的完整鏡像"
        return st
    age = (datetime.datetime.now(datetime.timezone.utc) - fetched).total_seconds() / 86400
    st.update(commit=src.get("commit"), fetched_utc=src["fetched_utc"], age_days=round(age, 1), bulletins=bs)
    if age > max_age:
        st["reason"] = f"公告鏡像過期（{src['fetched_utc']} 下載，{age:.1f} 天 > NVBUL_MAX_AGE_DAYS={max_age:g}）"
        return st
    if not has_group:
        st["reason"] = f"公告鏡像（{d}）沒有選取 {group} 群組（舊格式或舊版 nvidia-bulletins.sh 產生），無法判斷 {GROUP_LABEL[group]} 公告"
        return st
    st["ok"] = True
    return st


def day(s):
    return s[:10] if isinstance(s, str) and len(s) >= 10 else None


def pending_bulletins(mirror_bulletins, table):
    tb = {b["id"]: b for b in table.get("bulletins", [])}
    na = {x["bulletin"]: x for x in table.get("not_applicable", [])}
    rows = collections.defaultdict(list)
    for r in table.get("rows", []):
        rows[r["bulletin"]].append(r)
    ru = table.get("reviewed_until")
    out = []
    for b in mirror_bulletins:
        bid, cur = b["id"], day(b.get("current_release_date") or b.get("initial_release_date"))
        reasons = []
        known = tb.get(bid) or na.get(bid)
        if known is None:
            reasons.append("not_in_table")
        else:
            kd = day(known.get("current_release_date"))
            if cur and (kd is None or cur > kd):
                reasons.append("revised")
            if bid in tb and (not rows[bid] or any(not r["reviewed"] for r in rows[bid])):
                reasons.append("unreviewed_rows")
            if bid in na and bid not in tb and na[bid].get("reviewed", True) is False:
                reasons.append("unreviewed_not_applicable")
        if ru is None or (cur and cur > ru):
            reasons.append("after_reviewed_until")
        if b.get("integrity_error"):        # 鏡像沒有解出（NVIDIA 的 .sha256 不符）：要人去看原始倉庫
            reasons.append("sha256_mismatch")
        if reasons:
            out.append({"id": bid, "year": b.get("year"), "title": b.get("title"), "current_release_date": b.get("current_release_date"),
                        "match": b.get("match"), "reasons": reasons,
                        **({"integrity_error": b["integrity_error"]} if b.get("integrity_error") else {})})
    return out


# ---------- 草稿列（candidates --draft） ----------

def md_update_rows(md):
    """公告 Markdown 的「Security Updates」表格 → [(原始那一行, {欄名: 值})]。"""
    lines = (md or "").splitlines()
    for i, l in enumerate(lines):
        if l.lstrip().startswith("|") and re.search(r"CVE IDs? Addressed", l, re.I):
            head = [c.strip().strip("*").strip() for c in l.strip().strip("|").split("|")]
            out = []
            for row in lines[i + 2:]:
                if not row.lstrip().startswith("|"):
                    break
                cells = [c.strip() for c in row.strip().strip("|").split("|")]
                out.append((row.strip(), dict(zip(head, cells))))
            return out
    return []


def col(d, *keys):
    for k, v in d.items():
        if any(x in k.lower() for x in keys):
            return v
    return None


def infer_line(platform, product, vtexts):
    t, p = platform or "", product or ""
    if re.search(r"\bIGX\b", t) and not re.search(r"jetson", t, re.I):
        return "IGX", "platform"
    m = re.search(r"Jetson Linux\s*[-(]\s*(\d{2})\b", t)
    if m:
        return m.group(1), "platform"
    m = re.search(r"\bJP\s*(\d)\b", t)
    if m and m.group(1) in JETPACK_LINE:
        return JETPACK_LINE[m.group(1)], "platform_jetpack"
    if m and m.group(1) in JETPACK_AMBIGUOUS:
        return None, f"JetPack {m.group(1)}（對應 Jetson Linux {JETPACK_AMBIGUOUS[m.group(1)]}，需人工判斷）"
    m = re.search(r"\brel\s*(\d{2})\b", p, re.I)
    if m:
        return m.group(1), "product"
    if JETSON_RE.search(t) or JETSON_RE.search(p):   # 只在明寫 Jetson 的列上，用版本號的主版本推測（L4T 的主版本 28 以上）
        for x in vtexts:
            vs = versions_in(x)
            if vs and vkey(vs[0])[0] >= 28:
                return str(vkey(vs[0])[0]), "version_text"
    return None, None


def parse_affected(text):
    vs = versions_in(text)
    if not vs:
        return None, None
    if re.search(r"(and|or) (earlier|older|prior)|and including", text, re.I):   # 「X and earlier」「prior to and including X」含 X
        return None, vs[-1]
    if re.search(r"prior to|before|earlier than", text, re.I):
        return vs[-1], None
    if text.strip() == vs[0]:
        return None, vs[0]
    return None, None


def parse_fixed(text):
    vs = versions_in(text)
    return vs[0] if len(vs) == 1 else None


class CsafError(ValueError):
    """CSAF 的 vulnerabilities 結構不對（欄位型別錯）。只影響那一則公告：draft() 讓它 cves={} 並記 csaf_note。"""


def _opt(x, types, where):
    if x is not None and (not isinstance(x, types) or isinstance(x, bool)):
        raise CsafError(f"{where} 是 {type(x).__name__}")
    return x


def _items(v, key, where):
    xs = _opt(v.get(key), list, f"{where}.{key}") or []
    for i, x in enumerate(xs):
        _opt(x, dict, f"{where}.{key}[{i}]")
        if x is None:
            raise CsafError(f"{where}.{key}[{i}] 是 null")
    return xs


def csaf_cves(doc, notes=None):
    """CSAF 的 vulnerabilities → {cve: {severity, cvss_v3_score, cvss_v3_vector, cwe, description, references}}。
    欄位型別不對（例如 cwe 是字串、scores 的元素不是物件、baseScore 是 NaN 或不在 0–10）或根不是物件 → CsafError，不回傳半套資料。
    cve 不是合法的 CVE 編號（型別錯、空字串、格式不對）的弱點略過；同一個 CVE 出現兩次時合併（先出現的值優先，缺的欄位用後面的補）。
    略過與合併都記在 notes（清單；None 就不記）。"""
    if not isinstance(doc, dict):
        raise CsafError(f"CSAF 的根是 {type(doc).__name__}")
    out = {}
    vulns = _opt(doc.get("vulnerabilities"), list, "vulnerabilities") or []
    for i, v in enumerate(vulns):
        where = f"vulnerabilities[{i}]"
        if not isinstance(v, dict):
            raise CsafError(f"{where} 是 {type(v).__name__}")
        cve = v.get("cve")
        if cve is None:                                 # CSAF 允許沒有 CVE 編號的弱點
            continue
        if not isinstance(cve, str) or not CVE_RE.fullmatch(cve):
            if notes is not None:
                notes.append(f"{where}.cve 不是 CVE 編號（{cve!r:.40}），略過")
            continue
        desc = next((n.get("text") for n in _items(v, "notes", where) if n.get("category") == "summary"), None)
        cv = next((s.get("cvss_v3") for s in _items(v, "scores", where) if s.get("cvss_v3")), None)
        cv = _opt(cv, dict, f"{where}.scores[].cvss_v3") or {}
        cwe = _opt(v.get("cwe"), dict, f"{where}.cwe") or {}
        refs = [r.get("url") for r in _items(v, "references", where) if r.get("url") not in (None, "")]
        score = _opt(cv.get("baseScore"), (int, float), f"{where} 的 baseScore")
        if score is not None and not (math.isfinite(score) and 0 <= score <= 10):
            raise CsafError(f"{where} 的 baseScore 是 {score}（要是 0–10）")
        x = {"severity": _opt(cv.get("baseSeverity"), str, f"{where} 的 baseSeverity"),
             "cvss_v3_score": score,
             "cvss_v3_vector": _opt(cv.get("vectorString"), str, f"{where} 的 vectorString"),
             "cwe": _opt(cwe.get("id"), str, f"{where}.cwe.id"),
             "description": _opt(desc, str, f"{where} 的 summary text"),
             "references": [_opt(u, str, f"{where}.references[].url") for u in refs]}
        if cve in out:
            if notes is not None:
                notes.append(f"{cve} 出現不只一次，合併")
            old = out[cve]
            out[cve] = {k: (old[k] if old[k] not in (None, []) else x[k]) for k in old}
            out[cve]["references"] = old["references"] + [u for u in x["references"] if u not in old["references"]]
        else:
            out[cve] = x
    return out


def read_json_bytes(path):
    """讀 JSON（bytes：UTF-8 有沒有 BOM、UTF-16／32 都由 json 自己判斷，和 nvidia-bulletins.sh 的鏡像端一樣）。"""
    with open(path, "rb") as f:
        return json.loads(f.read())


def draft(mirror, b):
    """一個鏡像公告 → (bulletin 物件, 草稿列清單)。全部 reviewed=false；推測的欄位寫在 note。
    index 說有 CSAF（b["csaf"]）卻讀不到、太深、根不是物件或結構錯 → cves={}、csaf_note 寫原因（附例外類別），草稿列照常從 Markdown 產生；
    Markdown 讀不到或不是合法 UTF-8 → 沒有草稿列、md_note 寫原因。都只影響這一則，不會讓整個群組 FAIL。"""
    base = os.path.join(mirror, b.get("year") or "", b["id"])
    notes, csaf_note, md_note = [], None, None
    try:
        doc = read_json_bytes(os.path.join(base, b["id"] + ".json"))
    except (OSError, ValueError, RecursionError) as e:
        doc = None
        if b.get("csaf"):
            csaf_note = f"CSAF 無法讀取（{type(e).__name__}），沒有讀 CVSS、CWE 與描述，要看原始公告"
    try:
        with open(os.path.join(base, b["id"] + ".md"), encoding="utf-8-sig") as f:
            md = f.read()
    except FileNotFoundError:
        md = ""
    except (OSError, ValueError) as e:                 # UnicodeDecodeError 是 ValueError
        md, md_note = "", f"Markdown 無法讀取（{type(e).__name__}），沒有草稿列，要看原始公告"
    cves = {}
    if doc is not None:
        try:
            cves = csaf_cves(doc, notes)
        except (CsafError, RecursionError) as e:       # 只影響這一則：沒有 CVSS／描述，草稿列照常從 Markdown 產生
            cves, csaf_note = {}, (f"CSAF 結構錯（{e}），沒有讀 CVSS、CWE 與描述，要看原始公告" if isinstance(e, CsafError)
                                   else "CSAF 無法讀取（RecursionError），沒有讀 CVSS、CWE 與描述，要看原始公告")
    if notes and not csaf_note:
        csaf_note = "CSAF：" + "；".join(notes[:5]) + (f"（另 {len(notes) - 5} 則）" if len(notes) > 5 else "")
    for n in (csaf_note, md_note):
        if n:
            print(f"  {b['id']}\t{n}", file=sys.stderr)
    bul = {"id": b["id"], "year": b.get("year"), "title": b.get("title"), "initial_release_date": b.get("initial_release_date"),
           "current_release_date": b.get("current_release_date"), "revision": b.get("revision"),
           "url": f"{REPO_URL}/blob/main/{b.get('year')}/{b['id']}/{b['id']}.md", "cves": cves,
           **({"csaf_note": csaf_note} if csaf_note else {}), **({"md_note": md_note} if md_note else {})}
    rows = []
    for raw, d in md_update_rows(md):
        cell = (col(d, "cve") or "").translate({0x2010: "-", 0x2011: "-", 0x2013: "-"})
        product, platform = col(d, "product"), col(d, "platform")
        aff, fix = col(d, "affected version") or "", col(d, "updated version") or ""
        line, line_from = infer_line(platform, product, (aff, fix))
        below, mx = parse_affected(aff)
        fixed = parse_fixed(fix)
        for cve in CVE_RE.findall(cell):
            desc = (cves.get(cve) or {}).get("description") or ""
            comp, where, basis = "未寫明", "unknown", None
            for rx, c, w in COMPONENT_HINTS:
                m = re.search(rx, desc, re.I)
                if m:
                    comp, where, basis = c, w, m.group(0)
                    break
            notes = ["草稿：由 candidates --draft 從公告 Markdown 自動產生，必須人工核對後才能改 reviewed=true"]
            if line_from != "platform":
                notes.append(f"版本線推測自 {line_from or '（無法推測）'}")
            if line and line.isdigit() and not fixed:
                notes.append("修正版本不是單一點分版本，fixed_in 留空")
            if line and line.isdigit() and not (below or mx):
                notes.append("受影響版本無法判讀，affected_below／affected_max 留空")
            notes.append(f"元件推測自描述中的「{basis}」" if basis else "描述沒有寫元件")
            rows.append({"bulletin": b["id"], "cve": cve, "line": line or "?", "product_text": product, "platform_text": platform,
                         "affected_text": aff, "fixed_text": fix, "affected_below": below, "affected_max": mx, "fixed_in": fixed,
                         "component": comp, "where_it_lives": where,
                         "source": {"file": f"{b.get('year')}/{b['id']}/{b['id']}.md", "row": raw},
                         "reviewed": False, "reviewed_by": None, "reviewed_at": None, "note": "；".join(notes)})
    return bul, rows


# ---------- 輸出 ----------

def clip(detail, limit=470):
    b = detail.replace("\t", " ").replace("\n", " ").encode("utf-8")
    return detail if len(b) <= limit else b[:limit].decode("utf-8", "ignore") + "…"


def line(stage, st, detail):
    print(f"{stage}\t{st}\t{clip(detail)}")


def write_json(path, obj):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=1)
    except OSError as e:
        raise InputError(f"無法寫入 {path}（{type(e).__name__}）")


def finding(row, bul, det):
    info = (bul.get("cves") or {}).get(row["cve"]) or {}
    where = row.get("where_it_lives") or "unknown"
    comp = det["packages"].get(where) or det["anchor"]
    refs = [bul["url"]] if bul.get("url") else []
    refs += [u for u in info.get("references") or [] if u not in refs]
    v = {"vulnId": row["cve"], "source": "NVIDIA", "aliases": [{"cveId": row["cve"]}],
         "severity": str(info.get("severity") or "UNASSIGNED").upper(), "description": info.get("description"), "references": refs}
    if isinstance(info.get("cvss_v3_score"), (int, float)):
        v["cvssV3BaseScore"] = info["cvss_v3_score"]
    if info.get("cvss_v3_vector"):
        v["cvssV3Vector"] = info["cvss_v3_vector"]
    if info.get("cwe"):
        v["cwe"] = info["cwe"]
    basis = ("rootfs 套件版本" if comp is not det["anchor"] else
             "rootfs 的 Jetson Linux 版本（韌體在 flash，SBOM 看不到；裝置實際刷的版本可能不同）" if where == "flash" else
             "rootfs 的 Jetson Linux 版本")
    return {"component": dict(comp), "vulnerability": v,
            "evidence": {"bulletin": row["bulletin"], "bulletin_title": bul.get("title"), "line": row["line"],
                         "product_text": row.get("product_text"), "platform_text": row.get("platform_text"),
                         "jetson_linux_version": det["version"], "affected_text": row.get("affected_text"),
                         "fixed_text": row.get("fixed_text"), "fixed_in": row.get("fixed_in"),
                         "affected_below": row.get("affected_below"), "affected_max": row.get("affected_max"),
                         "source": row.get("source"), "component": row.get("component"), "where_it_lives": where,
                         "version_basis": basis, "reviewed_by": row.get("reviewed_by"), "reviewed_at": row.get("reviewed_at"),
                         "note": row.get("note")}}


def match(sbom, table, mirror, table_path=None):
    """回傳 (狀態, 說明, 輸出物件)。"""
    det = detect_jetson(sbom)
    out = {"schema": "sca-nvidia-bulletins-findings/2", "stage": STAGE, "jetson_linux": det, "table": None, "mirror": None,
           "findings": [], "needs_vendor_confirmation": [], "presumed_included": [], "unreviewed_would_match": [],
           "fixed_per_bulletin": [], "pending_bulletins": [], "not_covered": NOT_COVERED,
           "policy": {"unnamed_line": "presume_included_if_built_after" if PRESUME_INCLUDED_IF_BUILT_AFTER else "always_needs_confirmation"}}
    if det is None:
        return "NOT_RUN", "SBOM 沒有 nvidia-l4t-* 套件（不是 Jetson Linux）", out
    jl = (f"Jetson Linux {det['version']}（{'nvidia-l4t-core' if det['basis'] == 'nvidia-l4t-core' else 'nvidia-l4t-*'}，"
          f"建置 {det['build_date'] or '日期不明'}）")
    if table is None:
        return "GAP", f"沒有 NVIDIA 公告對照表（{table_path}）：{jl} 的 NVIDIA 公告未評估", out
    rows, buls = table.get("rows", []), {b["id"]: b for b in table.get("bulletins", [])}
    same = [r for r in rows if r["line"] == det["line"]]
    unrev_same = [r for r in same if not r["reviewed"]]
    out["table"] = {"path": table_path, "reviewed_until": table.get("reviewed_until"), "rows": len(rows),
                    "reviewed_rows": sum(1 for r in rows if r["reviewed"]), "unreviewed_rows": sum(1 for r in rows if not r["reviewed"]),
                    "same_line_rows": len(same), "same_line_unreviewed_rows": len(unrev_same),
                    "not_applicable": len(table.get("not_applicable", []))}
    for r in same:
        res = evaluate(r, det["version"])
        if not r["reviewed"]:
            if res == "affected":
                # severity：公告（CSAF）的評級，對照表這一列還沒審核：cra_report 只顯示、不拿來分級
                sev = ((buls.get(r["bulletin"]) or {}).get("cves") or {}).get(r["cve"]) or {}
                out["unreviewed_would_match"].append({"bulletin": r["bulletin"], "cve": r["cve"], "affected_text": r.get("affected_text"),
                                                      "fixed_text": r.get("fixed_text"), "where_it_lives": r.get("where_it_lives"),
                                                      "severity": str(sev.get("severity")).upper() if sev.get("severity") else None})
        elif res == "affected":
            # 同一 CVE 在同版本線有多列（例如 Xavier 與 Orin 各一列）：SBOM 分不出模組，只出一筆，其他列記在 evidence.other_rows
            prev = next((f for f in out["findings"] if f["vulnerability"]["vulnId"] == r["cve"]), None)
            if prev:
                prev["evidence"].setdefault("other_rows", []).append({"product_text": r.get("product_text"), "source": r.get("source")})
            else:
                out["findings"].append(finding(r, buls[r["bulletin"]], det))
        elif res == "fixed":
            out["fixed_per_bulletin"].append({"bulletin": r["bulletin"], "cve": r["cve"], "fixed_in": r.get("fixed_in")})
        else:
            out["needs_vendor_confirmation"].append({"bulletin": r["bulletin"], "cve": r["cve"], "reason": "range_gap",
                                                     "where_it_lives": r.get("where_it_lives"),
                                                     "detail": f"{det['version']} 不在公告寫的受影響範圍「{r.get('affected_text')}」內，"
                                                               f"但低於修正版本「{r.get('fixed_text')}」或沒有修正版本"})
    # 公告沒有列出這個版本線的 CVE：由 unnamed_line_policy() 分成「推定已含修正」與「需原廠確認」，都不是「不受影響」
    lines_by, where_by = collections.defaultdict(set), collections.defaultdict(set)
    reviewed_by = collections.defaultdict(list)
    for r in rows:
        lines_by[(r["bulletin"], r["cve"])].add(r["line"])
        where_by[(r["bulletin"], r["cve"])].add(r.get("where_it_lives") or "unknown")
        reviewed_by[(r["bulletin"], r["cve"])].append(r["reviewed"])
    for (bid, cve), ls in sorted(lines_by.items()):
        if det["line"] in ls:
            continue
        bdate = bulletin_date(buls[bid])
        pol = unnamed_line_policy(bdate, det["build_date"], ls)
        # 「公告列了哪些版本線」取自對照表的列：有未審核的列時，這個判斷本身也還沒經人確認
        e = {"bulletin": bid, "cve": cve, "reason": "line_not_named", "lines_named": sorted(ls), "bulletin_date": bdate,
             "release_build_date": det["build_date"], "where_it_lives": sorted(where_by[(bid, cve)]),
             "lines_from_unreviewed_rows": not all(reviewed_by[(bid, cve)])}
        if not any(x.isdigit() for x in ls):
            e["detail"] = (f"公告只列 {', '.join(sorted(ls))}，沒有任何 Jetson Linux 版本線；Jetson Linux {det['line']} 的狀態未知，"
                           "需原廠確認（不是「不受影響」）")
            out["needs_vendor_confirmation"].append(e)
        elif pol == "presumed_included":
            e["detail"] = (f"公告沒有列出 Jetson Linux {det['line']}（只列 {', '.join(sorted(ls))}）；映像建置日 {det['build_date']} 晚於公告 "
                           f"{day(bdate)}，推定已含修正，NVIDIA 未確認（不是「不受影響」）")
            out["presumed_included"].append(e)
        else:
            e["detail"] = (f"公告沒有列出 Jetson Linux {det['line']}（只列 {', '.join(sorted(ls))}）；映像建置日 {det['build_date'] or '不明'} "
                           f"不晚於公告 {day(bdate) or '（日期不明）'}，狀態未知，需原廠確認（不是「不受影響」）")
            out["needs_vendor_confirmation"].append(e)
    for k in ("needs_vendor_confirmation", "unreviewed_would_match", "fixed_per_bulletin"):   # 同一 CVE 的多列只留一筆
        seen, keep = set(), []
        for x in out[k]:
            key = (x["bulletin"], x["cve"], x.get("reason"))
            if key not in seen:
                seen.add(key)
                keep.append(x)
        out[k] = keep
    gaps = []
    if mirror is None:
        gaps.append("沒有指定 NVIDIA 公告鏡像（--mirror；sca-scan 取自 PILOT_ENV 的 NVIDIA_BULLETINS_MIRROR），無法確認對照表涵蓋最新公告")
    else:
        out["mirror"] = {k: v for k, v in mirror.items() if k != "bulletins"}
        if not mirror["ok"]:
            gaps.append(mirror["reason"] + "，無法確認對照表涵蓋最新公告")
        else:
            out["pending_bulletins"] = pending_bulletins(mirror["bulletins"], table)
            # 對照表落後鏡像：有表上沒有的公告，或 NVIDIA 修訂過。未審核、晚於 reviewed_until 只是審核進度，不算落後
            stale = [p for p in out["pending_bulletins"] if {"not_in_table", "revised"} & set(p["reasons"])]
            if stale:
                gaps.append(f"鏡像有 {len(stale)} 個 Jetson／IGX 公告對照表還沒有或已被修訂（{', '.join(p['id'] for p in stale[:8])}；"
                            "candidates 列出）")
    nf, nc, npi = len(out["findings"]), len(out["needs_vendor_confirmation"]), len(out["presumed_included"])
    nl = sum(1 for x in out["needs_vendor_confirmation"] if x["reason"] == "line_not_named")
    ng = sum(1 for x in out["needs_vendor_confirmation"] if x["reason"] == "range_gap")
    # status.tsv 的說明欄有長度上限：重要的放前面，數字精簡
    summary = (f"{jl}；{det['line']} 版本線 {len(same)} 列（未審核 {len(unrev_same)}）；發現 {nf} 筆；"
               f"公告沒列 {det['line']}（公告×CVE）：推定已含修正 {npi}（建置日晚於公告，NVIDIA 未確認）、需原廠確認 {nl}"
               + (f"；範圍空隙 {ng}" if ng else "")
               + (f"；未審核列會命中 {len(out['unreviewed_would_match'])} 筆（不算發現）" if out["unreviewed_would_match"] else ""))
    nur = sum(1 for x in out["presumed_included"] + out["needs_vendor_confirmation"] if x.get("lines_from_unreviewed_rows"))
    out["lines_from_unreviewed_rows"] = nur
    caveat = (f"注意：{nur} 筆的「公告列了哪些版本線」取自未經人工審核的對照表列（reviewed_until：{table.get('reviewed_until') or '未設定'}）"
              if nur else "")
    attention = []
    if unrev_same:
        attention.append(f"{det['line']} 版本線有 {len(unrev_same)} 列未審核")
    if nc:
        attention.append(f"{nc} 個 CVE 需原廠確認")
    if det["other_versions"]:
        attention.append(f"SBOM 另有 Jetson Linux 版本 {', '.join(det['other_versions'])}")
    if gaps:
        st, head = "GAP", "；".join(gaps)
    elif attention:
        st, head = "ATTENTION", "；".join(attention)
    else:
        st, head = "OK", "已比較"
    detail = f"{head}{'；' + caveat if caveat else ''}。{summary}；明細見 scan/nvidia-bulletins.json（flash 韌體以 rootfs 版本推定）"
    out["status"], out["detail"] = st, detail
    return st, detail, out


def cmd_match(a):
    sbom = load_json(a.sbom, "SBOM")
    table = None
    if os.path.exists(a.table):
        table = validate_table(load_json(a.table, "對照表"))
    mirror = mirror_state(a.mirror) if a.mirror else None
    st, detail, out = match(sbom, table, mirror, a.table)
    out["status"], out["detail"] = st, detail
    write_json(a.out, out)
    line(STAGE, st, detail)
    return 0


def cmd_candidates(a):
    table = validate_table(load_json(a.table, "對照表"))
    m = mirror_state(a.mirror, group=a.group)
    label = GROUP_LABEL[a.group]
    out = {"schema": "sca-nvidia-bulletins-candidates/1", "stage": STAGE_DB, "group": a.group,
           "mirror": {k: v for k, v in m.items() if k != "bulletins"},
           "reviewed_until": table.get("reviewed_until"), "pending": [], "table_only": []}
    if not m["ok"]:
        st, detail = "GAP", f"{m['reason']}；無法判斷有沒有新的 {label} 公告"
    else:
        out["pending"] = pending_bulletins(m["bulletins"], table)
        in_mirror = {b["id"] for b in m["bulletins"]}
        out["table_only"] = sorted(b["id"] for b in table.get("bulletins", []) if b["id"] not in in_mirror)
        tail = f"；對照表有 {len(out['table_only'])} 個公告不在鏡像（{', '.join(out['table_only'][:5])}）" if out["table_only"] else ""
        if out["pending"]:
            st = "ATTENTION"
            detail = (f"有 {len(out['pending'])} 個 {label} 公告待人工審核（{', '.join(p['id'] for p in out['pending'][:12])}"
                      f"{' 等' if len(out['pending']) > 12 else ''}）；reviewed_until={table.get('reviewed_until')}；"
                      f"鏡像 commit {str(m['commit'])[:12]}{tail}")
        else:
            st = "OK" if not out["table_only"] else "ATTENTION"
            detail = f"沒有待審的 {label} 公告（鏡像選入 {len(m['bulletins'])} 個，reviewed_until={table.get('reviewed_until')}）{tail}"
        if a.group == "gpu-firmware":
            detail += f"；{VBIOS_NOT_ASSESSED}"
        for p in out["pending"]:
            print(f"  {p['id']}\t{day(p['current_release_date']) or '?'}\t{','.join(p['reasons'])}\t{p['title']}", file=sys.stderr)
    out["status"], out["detail"] = st, detail
    if a.out:
        write_json(a.out, out)
    if a.draft:
        bs, rows = [], []
        for p in out["pending"]:
            b = next(x for x in m["bulletins"] if x["id"] == p["id"])
            bul, rs = draft(a.mirror, b)
            bs.append(bul)
            rows += rs
        write_json(a.draft, {"schema": TABLE_SCHEMA, "note": "草稿：全部 reviewed=false；核對後把需要的 bulletins 與 rows 併入對照表",
                             "mirror_commit": m.get("commit"), "bulletins": bs, "rows": rows})
    line(STAGE_DB, st, detail)
    return 0


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise InputError(f"參數錯誤：{message}")


def main(argv=None):
    ap = Parser(description="NVIDIA 安全公告（Jetson Linux）對照表的比對與待審清單")
    sub = ap.add_subparsers(dest="cmd", parser_class=Parser)
    m = sub.add_parser("match")
    m.add_argument("--sbom", required=True)
    m.add_argument("--table", required=True)
    m.add_argument("--mirror")
    m.add_argument("--out", required=True)
    c = sub.add_parser("candidates")
    c.add_argument("--mirror", required=True)
    c.add_argument("--table", required=True)
    c.add_argument("--out")
    c.add_argument("--draft")
    c.add_argument("--group", choices=list(GROUPS), default="jetson")
    args = argv if argv is not None else sys.argv[1:]
    stage = STAGE_DB if args[:1] == ["candidates"] else STAGE
    try:
        a = ap.parse_args(args)
        if a.cmd is None:
            raise InputError("缺少子命令（match 或 candidates）")
        return cmd_match(a) if a.cmd == "match" else cmd_candidates(a)
    except InputError as e:
        line(stage, "FAIL", f"nvidia_bulletins.py 輸入錯誤：{e}")
        return 3
    except Exception as e:   # 結構意外：記 FAIL，不讓掃描中斷、不印 traceback
        line(stage, "FAIL", f"nvidia_bulletins.py 無法判定（{type(e).__name__}）")
        return 3


if __name__ == "__main__":
    sys.exit(main())
