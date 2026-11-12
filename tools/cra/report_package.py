#!/usr/bin/env python3
"""把 cra_report.py 的輸出（<專案>/CRA/Reports/）整理成一包給一般人看的中文成果：一個指令。

用法：
    python3 -I tools/cra/report_package.py --project <製造商專案資料夾> [--supplier-project <供應商專案資料夾>]
        --out <新的空資料夾> [--name <產品名稱> --version <版本>]

輸出：
    交給PM/漏洞清單.xlsx        總覽、完整漏洞清單、排除後剩下的、規則說明
    交給PM/SBOM/、VEX/、安全檢查結果.md、待確認事項.xlsx、客戶資料包/（有給 --supplier-project 才有）
    給RD/P1判斷表.xlsx          只有立即處理（P1）：一個 CVE 一列
    內部存檔/                    Reports 裡的其他檔案（證據、機器可讀的 vulnerability-rows.json 等）
    SHA256SUMS.txt

規則：
- 只用標準函式庫。不覆蓋既有資料夾：--out 要不存在或是空的；不寫 /tmp。
- 缺輸入不會產生看起來「沒有弱點」的空清單：沒有 vulnerability-rows.json 直接失敗（退出碼 1）；其他輸入缺少時整包照做，
  缺的項目寫進「交給PM/未產生的項目.md」並以退出碼 2（GAP）結束；漏洞資料沒有評估時清單明寫 NOT_ASSESSED。
- 一「列」＝一個 CVE 在一個元件版本上的一筆（vulnerability-rows.json 的一筆）；全包只用這一個定義，「CVE 數」另標。
- 不放「先讀這個」之類的入口頁。
"""
import argparse
import collections
import csv
import datetime
import hashlib
import json
import os
import re
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from xlsx_min import Canvas, Chart, Sheet, Style, col_name, write_xlsx  # noqa: E402

ROWS_FILE = "vulnerability-rows.json"
ROWS_SCHEMA = "sca-center-vulnerability-rows/1"

PM, RD, ARCH = "交給PM", "給RD", "內部存檔"
T_NOW, T_TRACK, T_OK, T_OTHER = "立即處理", "持續追蹤", "經評估不受影響（含已修補）", "未分類"
SUGGEST = "建議（需 RD 確認）"
TIER_CLASS = {"p1": T_NOW, "p3": T_TRACK, "nvidia_bulletin": T_TRACK, "accepted": T_OK, "distro_fixed": T_OK}
TIER_ORDER = {"p1": 0, "p3": 1, "nvidia_bulletin": 2, "accepted": 3, "distro_fixed": 4}
OPEN_TIERS = ("p1", "p3", "nvidia_bulletin")
UNKNOWN = "未分類（請人工確認）"
ENG, SW, RD_ENG, NONE = "RD", "CRA掃描", "RD", "—"
ROLES = {"RD", SW, "PM", NONE}      # 誰處理只能是角色，不能是動作

# 規則代號 → (分類, 結論, 要做什麼, 誰處理, 依據的一句話)。{fix} 換成這一列的修補版本。來源：審視報告的「白話結論」表。
RULES = {
    "P1": (T_NOW, "已被攻擊者利用，且還沒有證據排除，需要 RD 確認",
           "RD 確認受不受影響；受影響就排修補", ENG, "已知被利用名單或人工證據顯示已被利用"),
    "K1": (T_OK, "有問題的程式碼沒有編進這個產品的核心，不受影響", "不用處理；核心設定改變時重掃", NONE,
           "核心設定檢查：修補的程式檔沒有編進這個產品的核心"),
    "K2": (T_OK, "受影響的模組已被移除或禁止載入", "不用處理；設定改變時重掃", NONE, "模組清單檢查：受影響的模組已移除或禁止載入"),
    "U1": (T_OK, "發行版官方標示這個版本不受影響", "不用處理", NONE, "發行版安全追蹤紀錄：這個版本標示不受影響"),
    "U2": (T_OK, "發行版已在目前安裝的版本修好", "不用處理", NONE, "發行版安全追蹤紀錄：目前安裝的版本已含修補"),
    "DISTRO": (T_OK, "發行版已修補（已修好）", "不用處理", NONE, "重新檢查發行版紀錄：已修補"),
    "R1": (T_TRACK, "受影響；發行版已有修補核心，換核心就修好", "下一版換到 {fix} 以上", RD_ENG,
           "發行版已有修補核心"),
    "R2": (T_TRACK, "受影響；程式碼有編進核心，還沒有修補版", "追蹤上游，有修補再更新", SW, "程式碼有編進核心，尚無修補"),
    "R3": (T_TRACK, "受影響；系統套件已有修補版", "下一版映像更新到 {fix} 以上", RD_ENG, "發行版已有修補套件"),
    "R4": (T_TRACK, "受影響；Python 套件上游已修補", "下一版更新到 {fix} 以上", RD_ENG, "Python 套件上游已有修補版"),
    "R5": (T_TRACK, "暫時當作受影響；判斷不了有沒有編進核心，也還沒有修補版", "追蹤上游；補上建置資料後重判", SW,
           "判斷不了有沒有編進核心，尚無修補"),
    "R5w": (T_TRACK, "同 R5，且發行版不打算修", "追蹤；需要時另想辦法；定期重看", ENG, "判斷不了有沒有編進核心，發行版不修"),
    "R6": (T_TRACK, "受影響；系統套件還沒有修補版", "追蹤上游，有修補再更新", SW, "發行版尚無修補套件"),
    "R7": (T_TRACK, "受影響；發行版決定不修（通常風險低）", "記錄；定期重看；若要處理由 PM 與 RD 討論", ENG, "發行版決定不修"),
    "R8": (T_TRACK, "資料不足，先當作受影響", "補資料（版本或修補資訊）後重判", SW, "缺版本或修補資訊"),
    "R9": (T_TRACK, "受影響；內建程式庫（例如 UEFI 內的 OpenSSL）有修補版", "重新編譯開機程式", RD_ENG, "內建程式庫已有修補版"),
    "R9m": (T_TRACK, "評估中：人工分析認為 UEFI 內的 Mbed TLS 沒編進去，工具確認不了", "等工具或證據確認", SW,
            "人工分析與工具結果不一致"),
    "NVIDIA": (T_TRACK, "NVIDIA 公告裡有，評估中", "等 NVIDIA 版本資訊", SW, "NVIDIA 安全公告列有此問題"),
    "人工": (None, None, None, None, None),     # 人工判定：依狀態決定（見 wording）
}
# UB1／UB2／N1／N2 是建議（row["suggestion"]；同一列有多個來源的建議時其餘在 row["suggestion_more"]），不是會套用的規則：不改判定、不在 RULES（判定用的對照表）裡；RD 確認後才用人工判定改（規則說明表列為「建議（需 RD 確認）」）
SUGGESTIONS = {
    "UB1": (SUGGEST, "建議：不受影響（UEFI 映像裡沒有這個函式庫，見佐證）；需 RD 確認後才改判定",
            "RD 確認；確認後用人工判定（vex-annotations.json 或 Dependency-Track）改判定", ENG,
            "UEFI 映像檢查：映像已完整解開，沒有這個函式庫的程式碼或字串，且平台 DSC 佐證；只檢查刷機包的 uefi_*.bin，未檢查 capsule"),
    "UB2": (SUGGEST, "建議：受影響（UEFI 映像裡確認有編進這個函式庫，見佐證）；需 RD 確認後才改判定",
            "RD 確認；確認後用人工判定改判定，並排重新編譯開機程式", ENG,
            "UEFI 映像檢查：映像裡找得到這個函式庫的程式碼或字串"),
    "N1": (SUGGEST, "建議：不受影響或已修補（NVIDIA 公告列的這個問題實際是發行版套件的漏洞，見佐證）；需 RD 確認後才改判定",
           "RD 確認；確認後用人工判定（vex-annotations.json 或 Dependency-Track）改判定", ENG,
           "發行版資料（Grype DB）與映像檔案清單的判斷"),
    "N2": (SUGGEST, "建議：受影響（NVIDIA 公告列的這個問題實際是發行版套件的漏洞，發行版資料顯示受影響）；需 RD 確認後才改判定",
           "看同一個 CVE 在該發行版套件的那一列；RD 確認", ENG,
           "發行版資料（Grype DB）的判斷"),
}
RULE_ORDER = ["P1", "K1", "K2", "U1", "U2", "DISTRO", "R1", "R2", "R3", "R4", "R5", "R5w", "R6", "R7", "R8", "R9", "R9m", "NVIDIA", "人工"]
MANUAL = {  # 人工判定（具名的 RD在 vex-annotations.json 或 Dependency-Track 做的）：依狀態
    T_OK: ("RD 判定不受影響或已修補", "不用處理；有新資訊時重判", NONE),
    T_TRACK: ("RD 判定受影響或仍在評估", "依判定排修補或追蹤", ENG),
    T_NOW: ("已被攻擊者利用，RD 已有判定", "依判定處理", ENG),
}
STATE_ZH = {"not_affected": "不受影響", "resolved": "已修補", "exploitable": "受影響", "in_triage": "評估中", "false_positive": "誤報"}
PRI_ZH = {"critical": "嚴重", "high": "高", "medium": "中", "low": "低", "negligible": "可忽略", "untriaged": "未分級"}

HEADER = ["分類", "結論", "要做什麼", "誰處理", "CVE", "元件", "版本", "修補版本", "嚴重度（分數）", "無評分原因", "已被積極利用", "對外服務",
          "依據", "判定者", "判定日期", "備註", "攻擊向量", "板子上使用情形", "核心模組狀態"]
WIDTHS = [16, 34, 30, 20, 18, 22, 18, 24, 12, 26, 10, 12, 44, 18, 12, 36, 10, 24, 24]
# 清單用的精簡欄位（完整漏洞清單、排除後剩下的）；第一欄「初判」＝結果－短理由
LIST_HEADER = ["初判", "CVE", "元件", "版本", "嚴重度（分數）", "已被積極利用", "對外服務", "修補版本", "要做什麼", "誰處理", "依據與備註", "判定者", "判定日期"]
LIST_WIDTHS = [34, 18, 22, 18, 12, 10, 10, 24, 30, 12, 70, 18, 12]
LIST_LEGEND = "初判＝結果－理由；「暫當受影響」是判斷不了時的保守做法，不是已確認受影響。"
# 規則代號 → 初判（短標籤）；長的結論文字留在 RULES（規則說明用）
SHORT = {
    "P1": "立即處理－已被利用，待 RD 判斷", "K1": "不影響－程式碼沒編進核心", "K2": "不影響－模組已移除或禁止載入",
    "U1": "不影響－發行版標示不受影響", "U2": "不影響－已修補", "DISTRO": "不影響－已修補", "R1": "受影響－換核心可修",
    "R2": "受影響－有編進核心，尚無修補", "R3": "受影響－更新套件可修", "R4": "受影響－更新 Python 套件可修",
    "R5": "暫當受影響－判斷不了有沒有編進核心", "R5w": "暫當受影響－判斷不了，發行版不修", "R6": "受影響－尚無修補",
    "R7": "受影響－發行版不修", "R8": "暫當受影響－資料不足", "R9": "受影響－重編開機程式可修", "R9m": "判斷中－UEFI 內 Mbed TLS 待確認",
    "NVIDIA": "判斷中－NVIDIA 公告，待版本資訊"}
SHORT_MANUAL = {"not_affected": "不影響－人工判定", "false_positive": "不影響－人工判定", "resolved": "不影響－已修補（人工）",
                "exploitable": "受影響－人工判定", "affected": "受影響－人工判定", "in_triage": "判斷中－人工"}
# 附加證據（runtime_evidence.py，只加資訊、不影響分類）：一台板子、一次量測的觀察；沒出現不代表沒用到
AV_ZH = {"N": "網路（N）", "A": "相鄰網路（A）", "L": "本機（L）", "P": "實體（P）", "unknown": "不明"}
RUNTIME_ZH = {"in use on the tested board": "板子上使用中", "not observed on the tested board": "板子上未觀察到（不代表沒用到）",
              "not measured": "未量測"}
MODULE_ZH = {"built-in": "內建於核心", "module, loaded on the tested board": "模組，板子上已載入",
             "module, not loaded on the tested board": "模組，板子上未載入（可隨需載入）", "module, load state not measured": "模組，載入狀態未量測",
             "unknown": "不明"}
NOT_AFFECTED_FIX = "—（不受影響）"
# 把內部部門名稱換成報告用的角色名稱（待確認事項、設定警告等從別的檔案來的文字也要換）
ROLE_WORDS = [(re.compile(r"專案負責人（PM）"), "PM"), (re.compile(r"專案負責人"), "PM"), (re.compile(r"軟體部門（[^）]*）"), "CRA掃描"),
              (re.compile(r"軟體部門"), "CRA掃描"), (re.compile(r"產品工程師"), "RD")]
# 掃描階段代號 → 一句白話（放在原文前面，原文的英文不動）
STAGE_WORDS = [("C-sbomgate", "SBOM 完整度"), ("B-sbom-", "SBOM 產生"), ("B-toolchain", "建置工具"),
               ("B-npm-no-lockfile", "npm 專案沒有鎖定檔"), ("NOT_ASSESSED", "未評估")]
UUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
NOT_RUN = "NOT_RUN"


class PackageError(Exception):
    pass


class Msgs(list):
    """訊息列表；.status 是最後一行要印的狀態（漏洞資料狀態不是 OK 時就是那個狀態，不印 OK）。"""
    status = "OK"


# ---------------------------------------------------------------- 讀取

def load_json(p):
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def read_rows(reports):
    p = reports / ROWS_FILE
    if not p.is_file():
        raise PackageError(f"缺 {p}：用有 vulnerability-rows.json 的工具版本重跑 cra_report.py。沒有它就不產生清單"
                           "（不產生看起來像「沒有弱點」的空清單）。")
    try:
        doc = load_json(p)
    except (OSError, ValueError) as e:
        raise PackageError(f"{p} 讀不了：{e}")
    if not isinstance(doc, dict) or doc.get("schema") != ROWS_SCHEMA or not isinstance(doc.get("rows"), list):
        raise PackageError(f"{p} 不是 {ROWS_SCHEMA} 格式")
    if doc.get("row_count") != len(doc["rows"]):
        raise PackageError(f"{p} 的 row_count {doc.get('row_count')} 與實際列數 {len(doc['rows'])} 不符")
    # 輸入順序不同，輸出也要一樣
    doc["rows"].sort(key=lambda r: (str(r.get("id")), str(r.get("component")), str(r.get("version")), str(r.get("tier"))))
    return doc


def read_rules_confirmation(project):
    """CRA/Config/vex-rules.json 最上層的選用欄位 confirmed_by／confirmed_date（規則整份的確認者與日期）；沒有 → (None, None)。"""
    p = Path(project) / "CRA" / "Config" / "vex-rules.json"
    try:
        d = load_json(p)
    except (OSError, ValueError):
        return None, None, None
    if not isinstance(d, dict):
        return None, None, None
    return d.get("confirmed_by"), d.get("confirmed_date"), d.get("author")


def product_label(project, name, version):
    n, v = name, version
    if not n or not v:
        try:
            p = load_json(Path(project) / "CRA" / "Config" / "config.json").get("product") or {}
        except (OSError, ValueError, AttributeError):
            p = {}
        n, v = n or p.get("name"), v or p.get("version")
    return " ".join(x for x in (n, v) if x) or "（產品名稱未設定）"


# ---------------------------------------------------------------- 一列 → 人讀欄位

def rule_code(r):
    v = r.get("vex") or {}
    t = r["tier"]
    if t == "p1":
        return "P1"
    if t == "nvidia_bulletin":
        return "NVIDIA"
    if v.get("source") == "rule" and v.get("rule"):
        return v["rule"]
    if t == "distro_fixed" or v.get("source") == "distro":
        return "DISTRO"
    if v.get("source") in ("annotation", "dt"):
        return "人工"
    return v.get("rule") or None


def fix_version(r, fix_all):
    """已有修補時的版本：核心寫「全部修好需要的版本」（這個 CVE 自己的修補版本比較舊，只換到它會留下其他 CVE）；沒有 → None。"""
    fx = r.get("fix_next") or ", ".join(r.get("fix_versions") or [])
    if r.get("fix_state") == "fixed" and fx:
        return (fix_all.get(r.get("component")) if r.get("is_kernel") else None) or fx
    return None


def deb_python_state(r):
    """Ubuntu 打包的 Python 模組：→ None（不是）／("owner", 套件名)／("ambiguous", [候選套件名])。"""
    dp = r.get("deb_python")
    if not isinstance(dp, dict):
        return None
    o = dp.get("owner")
    if isinstance(o, dict) and o.get("name"):
        return "owner", o["name"]
    return "ambiguous", list(dp.get("candidates") or [])


def deb_python_action(r):
    """這類列的「要做什麼」：更新 Ubuntu 套件（PyPI 的修補版本 apt 給不出來，不照 PyPI 版本寫）。不是這類列 → None。"""
    st = deb_python_state(r)
    if not st:
        return None
    if st[0] == "owner":
        pypi = (r.get("deb_python") or {}).get("pypi_fix") or []
        uv = ", ".join(r.get("fix_versions") or []) if r.get("fix_state") == "fixed" else ""
        return (f"更新 Ubuntu 套件 {st[1]}" + (f" 到 {uv} 以上" if uv else "")
                + (f"（PyPI 的 {', '.join(pypi)} 不適用於發行版套件）" if pypi else ""))
    return (f"由 Ubuntu 套件安裝（{' 或 '.join(st[1])}），先確認是哪個套件，再更新該套件" if st[1]
            else "由 Ubuntu 套件安裝（擁有的套件不明），先確認是哪個套件，再更新該套件")


def fix_text(r, fix_all):
    st_ = deb_python_state(r)
    if st_ and st_[0] == "ambiguous":
        return "依擁有的 Ubuntu 套件（待確認）"         # PyPI 的修補版本不適用於發行版套件
    v = fix_version(r, fix_all)
    if v:
        return f"需 {v} 以上" if v == fix_all.get(r.get("component")) and r.get("is_kernel") else v
    st = r.get("fix_state")
    return {"fixed": "有修補（版本不明）", "not-fixed": "尚無", "wont-fix": "發行版不修", "no Grype data": "無修補資料",
            "unknown": "不明", None: "不適用"}.get(st, str(st))


def plain(text):
    t = str(text)
    for rx, w in ROLE_WORDS:
        t = rx.sub(w, t)
    return t


def severity_cells(r):
    """→ (嚴重度（分數）：數字或空白, 無評分原因)。"""
    c = r.get("cvss")
    sc = c.get("score") if c else None
    if isinstance(sc, (int, float)) and not isinstance(sc, bool):
        return sc, ""
    p = r.get("ubuntu_priority")
    return "", (f"沒有 CVSS 分數；Ubuntu 評為「{PRI_ZH.get(p, p)}」" if p else "沒有 CVSS 分數，也沒有 Ubuntu 評級")


def exploit_text(r):
    ev = r.get("exploitation_evidence") or []
    out = []
    for e in ev:
        t = ("已列入已知被利用名單（KEV）" if e.startswith("KEV") else
             "歐盟漏洞資料庫（EUVD）標示已被利用" if e.startswith("EUVD") else
             "人工提供的被利用證據" if e.startswith("manual") else "有被利用證據")
        if t not in out:
            out.append(t)
    return "；".join(out)


def short_detail(s, n=70):
    s = UUID.sub("", str(s or ""))
    s = re.sub(r"\bGrype\b\s*", "", s)
    s = re.sub(r"\s+", " ", s).strip(" ;,.")
    return s if len(s) <= n else s[:n].rstrip() + "…"


BASIS_ZH = {"release_unaffected": "發行版資料標示這個發行版本不受影響",
            "release_fixed": "發行版資料顯示安裝的版本{version}已含修補（修補版本 {fixed}）",
            "binary_absent": "發行版資料對這個發行版本沒有記錄，但有問題的執行檔不在映像裡（{bin}）",
            "mixed": "同一個來源套件的各個二進位套件，發行版資料的結果不一致，維持評估中",
            "release_affected": "發行版資料顯示這個版本受影響，請看同一個 CVE 在該發行版套件的那一列",
            "no_release_record": "發行版資料對這個發行版本沒有記錄，也不足以用其他版本的記錄推論，維持評估中",
            "unreadable": "發行版資料讀不了，維持評估中"}


def distro_remap_text(r):
    """NVIDIA 公告列的 CVE 其實是發行版套件的（row["nvidia_distro"]）→ 一句中文（規則表依據、備註用）；沒有 → ""。"""
    d = r.get("nvidia_distro")
    if not isinstance(d, dict):
        return ""
    basis = BASIS_ZH.get(d.get("basis"), d.get("detail") or "")
    try:
        basis = basis.format(**{k: d.get(k) or "?" for k in ("version", "fixed", "fixed_max")}, bin=str(d.get("binary_note") or "?").split(": ")[-1])
    except (KeyError, IndexError, ValueError):
        pass
    t = (f"NVIDIA 公告列的這個 CVE 實際是發行版套件 {d.get('package')}（安裝 {d.get('version')}）的漏洞；依發行版資料判斷：{basis}"
         f"（資料庫建置 {str((d.get('db') or {}).get('built') or '?')[:10]}）")
    bn = d.get("binary_note")
    if bn and d.get("basis") != "binary_absent":
        t += "；補充證據（不影響判定）：有問題的執行檔" + bn.replace("absent from the root file system: ", "不在 rootfs 內：").replace(
            "present in the root file system: ", "在 rootfs 內：").replace("present in the root file system listing: ", "在 rootfs 內：").replace(
            "not listed by any installed package; non-package files not checked: ", "沒有任何已安裝套件列出（非套件檔案沒有檢查，所以不能說檔案不存在）：")
    return t


def wording(r, fix_all):
    """→ (規則代號或 None, 分類, 結論, 要做什麼, 誰處理, 依據, 未分類原因或 None)。分類一律用 tier；規則表和 tier 對不上就標未分類。"""
    cls = TIER_CLASS.get(r["tier"], T_OTHER)
    code = rule_code(r)
    fx = fix_text(r, fix_all)
    fxs = fix_version(r, fix_all) or "新版本"
    v = r.get("vex") or {}
    if code == "人工":
        c, a, w = MANUAL.get(cls, (None, None, None))
        if c is None:
            return code, UNKNOWN if cls == T_OTHER else cls, UNKNOWN, UNKNOWN, UNKNOWN, "", f"tier {r['tier']}"
        why = f"人工判定：{STATE_ZH.get(v.get('state'), v.get('state') or '?')}"
        d = short_detail(v.get("detail"))
        return code, cls, c, a, w, why + (f"；{d}" if d else ""), None
    ent = RULES.get(code)
    if ent is None or ent[0] is None or ent[0] != cls:
        why = "沒有對應的規則說明" if ent is None else f"規則 {code} 與分類（{r['tier']}）對不上"
        return code, cls if cls != T_OTHER else UNKNOWN, UNKNOWN, UNKNOWN, UNKNOWN, (f"規則 {code}" if code else "沒有規則或判定"), why
    _, concl, act, who, ev = ent
    if code == "P1":
        e = exploit_text(r)
        ev = e or ev
    if "{fix}" in act and deb_python_action(r):
        act = deb_python_action(r)
    return (code, cls, concl, act.replace("{fix}", fxs), who,
            (f"規則 {code}：{ev.replace('{fix}', fxs)}" if code not in ("P1", "DISTRO")
             else (f"{code}：{ev}" if code == "P1" else f"發行版已修補：{ev}")),
            None)


def judge(r, code, conf_by, conf_date, rules_author):
    """→ (判定者, 判定日期, 日期備註)。判定者不留空。"""
    v = r.get("vex") or {}
    t = r["tier"]
    if t == "p1":
        if v.get("source") in ("annotation", "dt") and v.get("author"):
            return v["author"], v.get("date") or "", None
        return "待 RD 判斷", "", None
    if t == "nvidia_bulletin":
        return "自動（NVIDIA 公告）", "", "自動判定，沒有人工日期"
    if v.get("source") == "rule" and v.get("rule") in ("UB1", "UB2"):
        return "自動（UEFI 映像檢查）", "", "自動判定，沒有人工日期"
    if v.get("source") == "rule":
        who = conf_by or v.get("author") or rules_author or "（規則責任人未設定）"
        if conf_date:
            return f"{who}（規則）", conf_date, None
        return f"{who}（規則）", "", "規則的確認日期尚未登錄（設定檔 confirmed_date）"
    if v.get("source") == "distro" or t == "distro_fixed":
        return "自動（發行版紀錄）", "", "自動判定，沒有人工日期"
    if v.get("source") in ("annotation", "dt"):
        return v.get("author") or "（判定者未記錄）", v.get("date") or "", None if v.get("date") else "判定日期未記錄"
    return "尚未判定", "", None


SUGGEST_STATE_ZH = {"not_affected": "不受影響", "resolved": "已修補", "affected": "受影響"}


def all_suggestions(r):
    """一列的所有建議：r["suggestion"]（主要的一筆）＋ r["suggestion_more"]（同一列另有別的來源的建議時；通常沒有）。"""
    out = [r["suggestion"]] if isinstance(r.get("suggestion"), dict) else []
    return out + [x for x in r.get("suggestion_more") or [] if isinstance(x, dict)]


def one_suggestion_text(r, sg):
    """一筆建議（{rule, state, justification, detail, needs, basis?}）→ 一句中文；不認得的規則 → None。建議不改判定。"""
    rule = sg.get("rule")
    if rule == "UB1":
        return "建議：不受影響（UEFI 映像裡沒有這個函式庫，見佐證）；需 RD 確認後才改判定"
    if rule == "UB2":
        return "建議：受影響（UEFI 映像裡確認有編進這個函式庫，見佐證）；需 RD 確認後才改判定"
    if rule in ("N1", "N2") and r.get("nvidia_distro"):
        return f"建議（{rule}）：{SUGGEST_STATE_ZH.get(sg.get('state'), sg.get('state'))}。{distro_remap_text(r)}；需 RD 確認後才改判定"
    return None


def suggestion_text(r):
    """一列所有建議的中文（以「；」接起來）；沒有建議 → None。"""
    parts = [t for t in (one_suggestion_text(r, sg) for sg in all_suggestions(r)) if t]
    return "；".join(parts) or None


def verdict(r, fix_all):
    """初判（結果－短理由）。分類仍以 tier 與 wording 為準；規則對不上就是未分類。建議不改初判。"""
    code, cls, concl, act, who, basis, bad = wording(r, fix_all)
    if bad is not None or code is None:
        return "未分類－" + (bad or "沒有規則或判定")
    if code == "人工":
        st = (r.get("vex") or {}).get("state")
        want = T_OK if st in ("not_affected", "false_positive", "resolved") else (T_TRACK if st in ("exploitable", "affected", "in_triage") else None)
        if want is not None and want != cls:
            return "未分類－人工判定與分類對不上"
        return SHORT_MANUAL.get(st, "未分類－人工判定的狀態不明（" + str(st) + "）")
    return SHORT.get(code) or "未分類－" + str(code)


def list_row(r, fix_all, conf):
    """清單的一列（LIST_HEADER）：由 human_row 合併欄位而來，內容不刪，只把依據、備註與附加證據併在「依據與備註」。"""
    h = dict(zip(HEADER, human_row(r, fix_all, conf)))
    parts = [h["依據"], h["備註"], ("無評分原因：" + h["無評分原因"]) if h["無評分原因"] else "",
             ("攻擊向量：" + h["攻擊向量"]) if h["攻擊向量"] else "", ("板子上使用情形：" + h["板子上使用情形"]) if h["板子上使用情形"] else "",
             ("核心模組狀態：" + h["核心模組狀態"]) if h["核心模組狀態"] else ""]
    return [verdict(r, fix_all), h["CVE"], h["元件"], h["版本"], h["嚴重度（分數）"], h["已被積極利用"], h["對外服務"], h["修補版本"], h["要做什麼"],
            h["誰處理"], "；".join(x for x in parts if x), h["判定者"], h["判定日期"]]


def human_row(r, fix_all, conf):
    code, cls, concl, act, who, basis, bad = wording(r, fix_all)
    jwho, jdate, dnote = judge(r, code, *conf)
    exposed = {True: "是", False: "否", None: "不明"}[r.get("exposed")]
    notes = [x for x in (("未分類原因：" + bad) if bad else None, dnote) if x]
    if r.get("nvidia_distro") and not any(sg.get("rule") in ("N1", "N2") for sg in all_suggestions(r)):
        notes.append(distro_remap_text(r))        # 判斷不了（維持評估中）的列：把發行版資料的證據放在備註
    mk = (r.get("vex") or {}).get("markers") or []
    if mk:
        notes.append("標記：" + "、".join(mk))
    if r.get("uefi_build_check"):
        notes.append("UEFI 映像與原始碼：" + r["uefi_build_check"])
    sg = suggestion_text(r)
    if sg:
        notes.append(sg)
    ic = r.get("uefi_image_check")
    if isinstance(ic, dict) and ic.get("result") == "not_assessed":
        notes.append("UEFI 映像檢查：映像沒有完整解開或證據不足，無法確認有沒有編進（not_assessed）")
    comp = r.get("component") or "?"
    sev, why_no = severity_cells(r)
    fix = NOT_AFFECTED_FIX if r["tier"] in ("accepted", "distro_fixed") else fix_text(r, fix_all)
    return [cls, concl, act, who, r["id"], comp, r.get("version") or "", fix, sev, why_no,
            "是" if r.get("exploited") else "否", exposed, basis, jwho, jdate, "；".join(notes),
            AV_ZH.get(r.get("attack_vector"), "") if r.get("attack_vector") else "",
            RUNTIME_ZH.get(r.get("runtime_observed"), "") if r.get("runtime_observed") else "",
            MODULE_ZH.get(r.get("module_state"), "") if r.get("module_state") else ""]


# ---------------------------------------------------------------- 統計與工作表

def tier_counts(rows):
    """→ {分類: (列數, 不重複 CVE 數)}（分類順序固定；沒有的分類是 0）。同一個 CVE 可在不同分類出現，所以 CVE 數不能相加。"""
    rcount, ids = collections.Counter(), collections.defaultdict(set)
    for r in rows:
        c = TIER_CLASS.get(r["tier"], T_OTHER)
        rcount[c] += 1
        ids[c].add(r["id"])
    return {c: (rcount[c], len(ids[c])) for c in (T_NOW, T_TRACK, T_OK, T_OTHER)}


def sort_key(r):
    sev = (r.get("cvss") or {}).get("score")
    return (TIER_ORDER.get(r["tier"], 9), not r.get("exploited"), r.get("exposed") is not True, -(sev if isinstance(sev, (int, float)) else -1),
            str(r.get("component")), str(r.get("version")), r["id"])


def status_line(doc):
    st = doc.get("vulnerability_data_status")
    if not doc.get("have_findings"):
        return "NOT_ASSESSED：這次掃描沒有弱點資料（Dependency-Track 的 findings 不存在），沒有資料不代表沒有弱點"
    if st and st != "OK":
        return f"漏洞資料狀態：{st}（資料不完整；沒有列出的不代表沒有問題）"
    return "漏洞資料狀態：OK（OK 不代表產品沒有弱點）"


SEV_ZH = (("CRITICAL", "嚴重"), ("HIGH", "高"), ("MEDIUM", "中"), ("LOW", "低"))
KERNEL_NET_BUCKET = "核心網路功能"
OPEN_TITLE = "還要處理的（立即處理＋持續追蹤）：依實機對外與嚴重度"
EXPOSED_TOP_N = 4


def _split_where(text):
    """exposed_where（以「, 」串接；括號內的逗號不切）→ 項目清單；核心網路項目併成同一個名稱。"""
    parts, depth, cur = [], 0, ""
    for i, ch in enumerate(text):
        depth += (ch == "(") - (ch == ")")
        if ch == "," and depth <= 0 and text[i + 1:i + 2] == " ":
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    parts.append(cur)
    return [KERNEL_NET_BUCKET if x.strip().startswith("kernel network") else x.strip() for x in parts if x.strip()]


def where_breakdown(rows):
    """對外的列 → 一行說明：各位置的列數（一列在同一位置只算一次），最多列前幾項，其餘併成「其他 N 列」。"""
    c = collections.Counter()
    for r in rows:
        if r.get("exposed") is True:
            for w in set(_split_where(r.get("exposed_where") or "")) or {"位置未記錄"}:
                c[w] += 1
    items = sorted(c.items(), key=lambda kv: (-kv[1], kv[0]))
    txt = "、".join(f"{w} {n} 列" for w, n in items[:EXPOSED_TOP_N])
    if items[EXPOSED_TOP_N:]:
        txt += f"、其他 {sum(n for _, n in items[EXPOSED_TOP_N:])} 列"
    return "　　其中：" + txt if txt else ""


def open_summary(doc):
    """還要處理的列（OPEN_TIERS）依對外與嚴重度的小表；回傳 top 區塊的列清單。"""
    op = [r for r in doc["rows"] if r["tier"] in OPEN_TIERS]

    def line(label, xs):
        return [label, len(xs), len({r["id"] for r in xs})]
    out = [[OPEN_TITLE], ["項目", "列數", "不重複 CVE 數"], line("合計", op)]
    if not doc.get("exposed_services_list"):
        out.append(line("沒有實機資料（對外與否不明）", op))
    else:
        out.append(line("從網路碰得到", [r for r in op if r.get("exposed") is True]))
        bd = where_breakdown(op)
        if bd:
            out.append([bd])
        out.append(line("實機上沒對外", [r for r in op if r.get("exposed") is False]))
        unk = [r for r in op if r.get("exposed") is None]
        if unk:
            out.append(line("沒有實機資料（對外與否不明，不是「沒對外」）", unk))
    known = {k for k, _ in SEV_ZH}
    for k, zh in SEV_ZH:
        out.append(line(f"嚴重度 {zh}（{k}）", [r for r in op if str(r.get("severity") or "").upper() == k]))
    out.append(line("嚴重度 未分級", [r for r in op if str(r.get("severity") or "").upper() not in known]))
    out.append(line("其中狀態還沒判定", [r for r in op if not (r.get("vex") or {}).get("state") or r["vex"]["state"] == "in_triage"]))
    out.append(["「沒對外」只用來排優先順序，不等於不能被利用（已登入的人、惡意檔案、USB、客戶自己開的服務仍可能）；結果只代表檢查那次的板子狀態。"])
    return out


def summary_top(doc, label):
    rows = doc["rows"]
    tc = tier_counts(rows)
    top = [[f"產品：{label}　　資料產生：{doc.get('generated')}"], [status_line(doc)],
           ["分類", "列數（CVE × 元件）", "不重複 CVE 數"]]
    for c, (a, b) in tc.items():
        if c != T_OTHER or a:
            top.append([c, a, b])
        if c == T_OK:
            for sub, tier in (("不受影響", "accepted"), ("已修補", "distro_fixed")):
                xs = [r for r in rows if r["tier"] == tier]
                top.append([f"　其中 {sub}", len(xs), len({r["id"] for r in xs})])
    top += [["合計", len(rows), len({r["id"] for r in rows})]]
    top += [["「列」＝一個 CVE 在一個元件版本上的一筆，全包都用這個單位。同一個 CVE 可出現在不同分類，所以 CVE 數不能相加。"]]
    top += [[f"產生報告時的設定警告：{plain(w)[:300]}"] for w in doc.get("_warnings") or []]
    top += [[]] + open_summary(doc) + [[]]
    return top


def exposure_note(doc):
    """對外服務欄的來源過期或不存在時的說明（沒有 → None）。"""
    ws = [w for w in doc.get("_warnings") or [] if "exposed-services" in w]
    if not doc.get("exposed_services_list") or any(r.get("exposed") is None for r in doc["rows"]):
        return "對外服務欄：沒有對外服務清單，「不明」代表不知道，不是「否」。"
    if ws:
        return "對外服務欄的來源（對外服務清單）可能比這次掃描舊：" + plain(ws[0])[:200]
    return None


def component_sheet(doc, fix_all, label):
    rows = doc["rows"]
    g = collections.defaultdict(list)
    for r in rows:
        g[(r.get("component") or "?", r.get("version") or "")].append(r)
    out = []
    for (comp, ver), xs in g.items():
        n = collections.Counter(TIER_CLASS.get(r["tier"], T_OTHER) for r in xs)
        openr = [r for r in xs if r["tier"] in OPEN_TIERS]
        others = [r for r in xs if r["tier"] not in TIER_CLASS]
        codes = collections.Counter(rule_code(r) or "?" for r in openr)
        if openr:
            order = sorted(codes, key=lambda c: (-codes[c], c))
            first = "P1" if codes.get("P1") else order[0]
            ex = next(r for r in openr if (rule_code(r) or "?") == first)
            _, _, concl, act, who, _, _ = wording(ex, fix_all)
            more = [c for c in order if c != first][:1]
            rest = len(codes) - 1 - len(more)
            why = concl + (f"（{codes[first]} 列）" if len(codes) > 1 else "") + "".join(
                f"；另有：{wording(next(r for r in openr if (rule_code(r) or '?') == c), fix_all)[2]}（{codes[c]} 列）" for c in more) + (
                f"；還有 {rest} 種情況，見完整漏洞清單" if rest > 0 else "")
            fxs = {r.get("fix_next") for r in openr if r.get("fix_state") == "fixed" and r.get("fix_next")}
            if xs[0].get("is_kernel") and fix_all.get(comp):
                fix = f"需 {fix_all[comp]} 以上"
            else:
                fix = (sorted(fxs)[0] if len(fxs) == 1 else "多個版本，見完整漏洞清單" if fxs else "尚無")
            if others:
                why += f"；另有 {len(others)} 列{UNKNOWN}"
        elif others:
            why, act, who, fix = f"{len(others)} 列{UNKNOWN}", UNKNOWN, UNKNOWN, ""
        else:
            why, act, who, fix = "全部經評估不受影響或已修補", "不用處理", NONE, ""
        out.append([comp, ver, n[T_NOW], n[T_TRACK], n[T_OK], n[T_OTHER], fix, why, act, who])
    out.sort(key=lambda x: (-x[2], -x[3], x[0], x[1]))
    return Sheet("依元件", ["元件", "版本", "立即處理", "持續追蹤", "經評估不受影響", "未分類", "修補版本", "主要原因", "要做什麼", "誰處理"], out,
                 widths=[26, 22, 10, 10, 14, 8, 24, 60, 30, 22], top=summary_top(doc, label))


# ---------------------------------------------------------------- 總覽（儀表板，第一個工作表）

DARK, LIGHT = "1F4E78", "D9E1F2"
FILL_NOW, FILL_TRACK, FILL_OK, FILL_FIXED, FILL_GREY = "F8CBAD", "FFE699", "C6E0B4", "E2EFDA", "F2F2F2"
DASH_NAME = "總覽"
DASH_WIDTHS = [16, 10, 10, 10, 10, 10, 10, 10, 14, 14, 14, 10]
SEV_KEYS = [k for k, _ in SEV_ZH]
SEV_HEAD = [zh for _, zh in SEV_ZH] + ["未分級"]


def taipei_time(generated):
    """UTC 的 ISO 時間 → 台北時間 YYYY-MM-DD HH:MM；讀不懂就原樣回傳。"""
    try:
        t = datetime.datetime.fromisoformat(str(generated).replace("Z", "+00:00"))
        if t.tzinfo is None:
            t = t.replace(tzinfo=datetime.timezone.utc)
        return t.astimezone(datetime.timezone(datetime.timedelta(hours=8))).strftime("%Y-%m-%d %H:%M")
    except (ValueError, TypeError):
        return str(generated)


def sev_bucket(r):
    k = str(r.get("severity") or "").upper()
    return SEV_KEYS.index(k) if k in SEV_KEYS else 4


def sev_counts(xs):
    c = [0] * 5
    for r in xs:
        c[sev_bucket(r)] += 1
    return c


def dashboard_data(doc, fix_all, label):
    """總覽用的數字（全部由 doc 算出來；分類用 tier_counts 與 wording，不另訂規則）。"""
    rows = doc["rows"]
    tc = tier_counts(rows)
    op = [r for r in rows if r["tier"] in OPEN_TIERS]
    has_exp = bool(doc.get("exposed_services_list"))
    cats = [(T_NOW, [r for r in rows if r["tier"] == "p1"], FILL_NOW), (T_TRACK, [r for r in rows if r["tier"] in ("p3", "nvidia_bulletin")], FILL_TRACK),
            ("不受影響", [r for r in rows if r["tier"] == "accepted"], FILL_OK), ("已修補", [r for r in rows if r["tier"] == "distro_fixed"], FILL_FIXED),
            ("未分類", [r for r in rows if r["tier"] not in TIER_CLASS], FILL_GREY)]
    expo = []
    if has_exp:
        expo = [("從網路碰得到", [r for r in op if r.get("exposed") is True]), ("實機上沒對外", [r for r in op if r.get("exposed") is False])]
        unk = [r for r in op if r.get("exposed") is None]
        if unk:
            expo.append(("對外不明", unk))
    else:
        expo = [("對外不明（沒有實機資料）", op)]
    why = collections.Counter(verdict(r, fix_all) for r in op)
    p1 = [(k, n) for k, n in why.items() if k == SHORT["P1"]]       # P1 一定單獨列在最前面
    ordered = sorted((kv for kv in why.items() if kv[0] != SHORT["P1"]), key=lambda kv: (-kv[1], kv[0]))
    keep = 8 - len(p1)
    reasons = p1 + ordered[:keep] + ([("其他", sum(n for _, n in ordered[keep:]))] if ordered[keep:] else [])
    comps = [x for x in component_sheet(doc, fix_all, label).rows if x[2] + x[3] > 0][:10]
    return {"tc": tc, "op": op, "has_exp": has_exp, "cats": cats, "expo": expo, "reasons": reasons, "comps": comps,
            "exposed_open": len([r for r in op if r.get("exposed") is True]),
            "suggestions": sum(1 for r in rows for sg in all_suggestions(r) if one_suggestion_text(r, sg)),
            "untriaged": len([r for r in op if not (r.get("vex") or {}).get("state") or r["vex"]["state"] == "in_triage"])}


def dashboard_sheet(doc, fix_all, label):
    """儀表板風格的第一個工作表（Canvas）：標題、數字方塊、分類統計、圖表、對外×嚴重度、主要原因、元件前 10、需要人判斷、說明。數字是靜態值，不是公式。"""
    rows = doc["rows"]
    cv = Canvas(DASH_NAME, widths=DASH_WIDTHS)
    st = lambda **k: Style(**k)
    title = st(size=18, bold=True, color="FFFFFF", fill=DARK, v="center")
    sub = st(size=10, italic=True, color=LIGHT, fill=DARK, v="center", wrap=True)
    head = st(size=10, bold=True, color="FFFFFF", fill=DARK, border="thin", h="center", v="center", wrap=True)
    h2 = st(size=13, bold=True, color=DARK)
    cell = st(size=10, border="thin", v="center", wrap=True)
    num = st(size=10, border="thin", h="center", v="center")
    note = st(size=9, color="595959", v="top", wrap=True)
    last = "L"
    cv.set("A1", f"{label} 漏洞總覽", title)
    cv.merge("A1:L1")
    cv.height(1, 34)
    gen = taipei_time(doc.get("generated"))
    sl = status_line(doc)
    ok_status = doc.get("have_findings") and (not doc.get("vulnerability_data_status") or doc.get("vulnerability_data_status") == "OK")
    cv.set("A2", f"資料產生（台北時間）{gen}｜{sl}" + ("" if ok_status or "沒有列出的不代表沒有問題" in sl else "｜沒有列出的不代表沒有問題"), sub)
    cv.merge("A2:L2")
    cv.height(2, 30)
    assessed = bool(doc.get("have_findings"))
    d = dashboard_data(doc, fix_all, label)
    tc = d["tc"]
    na = "NOT_ASSESSED"
    tiles = [("漏洞總數（列）", len(rows), "F2F2F2"), ("不重複 CVE", len({r["id"] for r in rows}), "F2F2F2"), ("立即處理", tc[T_NOW][0], FILL_NOW),
             ("持續追蹤", tc[T_TRACK][0], FILL_TRACK), ("經評估不受影響（含已修補）", tc[T_OK][0], FILL_OK),
             ("還要處理且從網路碰得到", d["exposed_open"] if d["has_exp"] else "不明", "F2F2F2")]
    for i, (lab, val, fill) in enumerate(tiles):
        c1, c2 = col_pair(i)
        cv.set(f"{c1}4", lab, st(size=10, bold=True, color=DARK, fill=LIGHT, h="center", v="center", wrap=True))
        cv.merge(f"{c1}4:{c2}4")
        cv.set(f"{c1}5", val if assessed else na, st(size=22 if assessed else 14, bold=True, color=DARK, fill=fill, h="center", v="center", border="thin"))
        cv.merge(f"{c1}5:{c2}6")
    cv.height(4, 30)
    cv.height(5, 24)
    cv.height(6, 24)
    r = 8
    if not assessed:
        cv.set(f"A{r}", "NOT_ASSESSED：這次掃描沒有弱點資料，沒有數字可以統計；上面不是 0，也不代表沒有弱點。", st(size=12, bold=True, color="C00000", wrap=True, v="center"))
        cv.merge(f"A{r}:L{r}")
        cv.height(r, 30)
        r += 2
        return finish_dashboard(cv, doc, d, r, h2, note, None)
    # --- 依分類統計
    cv.set(f"A{r}", "依分類統計", h2)
    r += 1
    for j, t in enumerate(["分類", "列數", "不重複 CVE", "佔比（列）", "嚴重", "高", "中", "低", "未分級"]):
        cv.set(f"{col_name(j)}{r}", t, head)
    cv.set(f"J{r}", "圖表標示", head)
    cv.merge(f"J{r}:L{r}")
    cv.height(r, 24)
    cat_first = r + 1
    shown = [c for c in d["cats"] if c[0] != "未分類" or c[1]]
    total = len(rows)
    for lab, xs, fill in shown:
        r += 1
        f = st(size=10, border="thin", fill=fill, v="center", bold=True)
        n = st(size=10, border="thin", fill=fill, h="center", v="center")
        vals = [lab, len(xs), len({x["id"] for x in xs}), (len(xs) / total if total else 0)] + sev_counts(xs)
        for j, v in enumerate(vals):
            cv.set(f"{col_name(j)}{r}", v, f if j == 0 else (st(size=10, border="thin", fill=fill, h="center", v="center", numfmt="0.0%") if j == 3 else n))
        cv.set(f"J{r}", f"{lab} {len(xs)}（{vals[3] * 100:.1f}%）", cell)
        cv.merge(f"J{r}:L{r}")
    cat_last = cat_first + len(shown) - 1
    r += 1
    tot = st(size=10, bold=True, border="thin", fill=LIGHT, h="center", v="center")
    allsev = sev_counts(rows)
    for j, v in enumerate(["合計", total, len({x["id"] for x in rows}), 1.0 if total else 0] + allsev):
        cv.set(f"{col_name(j)}{r}", v, st(size=10, bold=True, border="thin", fill=LIGHT, h="center", v="center", numfmt="0.0%") if j == 3 else tot)
    cv.merge(f"J{r}:L{r}", tot)
    r += 2
    # --- 圖表區（先留版面，圖表在表格建好後才知道範圍）
    cv.set(f"A{r}", "圖表", h2)
    chart_top = r + 1
    chart_bot = chart_top + 15
    r = chart_bot + 2
    # --- 對外 × 嚴重度（左）與主要原因（右）
    cv.set(f"A{r}", "還要處理的：對外 × 嚴重度", h2)
    cv.set(f"I{r}", "還要處理的：主要原因", h2)
    r += 1
    lh = r
    for j, t in enumerate(["對外"] + SEV_HEAD + ["合計"]):
        cv.set(f"{col_name(j)}{r}", t, head)
    cv.set(f"I{r}", "原因", head)
    cv.merge(f"I{r}:K{r}")
    cv.set(f"L{r}", "列數", head)
    cv.height(r, 24)
    el0 = r + 1
    for lab, xs in d["expo"]:
        r += 1
        sc = sev_counts(xs)
        fill = FILL_NOW if lab == "從網路碰得到" else (FILL_GREY if lab == "實機上沒對外" else FILL_TRACK)
        cv.set(f"A{r}", lab, st(size=10, border="thin", fill=fill, v="center", bold=True, wrap=True))
        for j, v in enumerate(sc + [len(xs)], 1):
            cv.set(f"{col_name(j)}{r}", v, st(size=10, border="thin", fill=fill, h="center", v="center"))
        cv.height(r, 28 if len(lab) > 8 else 20)
    el1 = r
    r += 1
    sc = sev_counts(d["op"])
    cv.set(f"A{r}", "合計", tot)
    for j, v in enumerate(sc + [len(d["op"])], 1):
        cv.set(f"{col_name(j)}{r}", v, tot)
    left_end = r
    rr = lh
    for k, (txt, n) in enumerate(d["reasons"]):
        rr += 1
        fill = "FFFFFF" if k % 2 == 0 else FILL_GREY
        cv.set(f"I{rr}", txt, st(size=10, border="thin", fill=fill, v="center", wrap=True))
        cv.merge(f"I{rr}:K{rr}")
        cv.set(f"L{rr}", n, st(size=10, border="thin", fill=fill, h="center", v="center"))
        cv.height(rr, 30 if len(txt) > 20 else 20)
    if not d["reasons"]:
        rr += 1
        cv.set(f"I{rr}", "（沒有還要處理的項目）", cell)
        cv.merge(f"I{rr}:K{rr}")
        cv.set(f"L{rr}", 0, num)
    rr += 1
    cv.set(f"I{rr}", "合計", tot)
    cv.merge(f"I{rr}:K{rr}")
    cv.set(f"L{rr}", len(d["op"]), tot)
    r = max(left_end, rr) + 2
    # --- 元件前 10
    cv.set(f"A{r}", "還要處理最多的元件（前 10；立即處理多的在前）", h2)
    r += 1
    for rng, t in (("A{r}:C{r}", "元件"), ("D{r}:E{r}", "版本"), ("F{r}:F{r}", "立即處理"), ("G{r}:G{r}", "持續追蹤"), ("H{r}:J{r}", "修補版本"), ("K{r}:L{r}", "誰處理")):
        a = rng.format(r=r)
        cv.set(a.split(":")[0], t, head)
        cv.merge(a)
    cv.height(r, 24)
    for k, x in enumerate(d["comps"]):
        r += 1
        fill = "FFFFFF" if k % 2 == 0 else FILL_GREY
        c_ = st(size=10, border="thin", fill=fill, v="center", wrap=True)
        n_ = st(size=10, border="thin", fill=fill, h="center", v="center")
        for a, v, sty in (("A", x[0], c_), ("D", x[1], c_), ("F", x[2], n_), ("G", x[3], n_), ("H", x[6], c_), ("K", x[9], c_)):
            cv.set(f"{a}{r}", v, sty)
        for m in (f"A{r}:C{r}", f"D{r}:E{r}", f"H{r}:J{r}", f"K{r}:L{r}"):
            cv.merge(m)
        cv.height(r, 30 if max(len(str(x[0])), len(str(x[1])) * 1.4, len(str(x[6])) * 1.2) > 22 else 20)
    if not d["comps"]:
        r += 1
        cv.set(f"A{r}", "（沒有還要處理的元件）", cell)
        cv.merge(f"A{r}:L{r}")
    r += 2
    # --- 需要人判斷
    cv.set(f"A{r}", "需要人判斷", h2)
    for lab, v, txt, fill in (("P1（立即處理）", f"{tc[T_NOW][0]} 列", "見 給RD/P1判斷表.xlsx；只有這類需要 RD 具名判斷", FILL_NOW),
                              ("建議（需 RD 確認）", f"{d['suggestions']} 筆", "只是建議，不改任何判定；RD 確認後才會變成判定", FILL_TRACK),
                              ("狀態還沒判定", f"{d['untriaged']} 列", "還要處理的列中沒有人工判定或仍在評估中", FILL_GREY)):
        r += 1
        cv.set(f"A{r}", lab, st(size=10, bold=True, border="thin", fill=fill, v="center"))
        cv.merge(f"A{r}:C{r}")
        cv.set(f"D{r}", v, st(size=10, bold=True, border="thin", fill=fill, h="center", v="center"))
        cv.merge(f"D{r}:E{r}")
        cv.set(f"F{r}", txt, st(size=10, border="thin", v="center", wrap=True))
        cv.merge(f"F{r}:L{r}")
        cv.height(r, 24)
    r += 2
    # --- 圖表
    pie = Chart("pie", "分類（列數）", f"J{cat_first}:J{cat_last}", f"B{cat_first}:B{cat_last}", f"A{chart_top}:D{chart_bot}", "列數",
                [FILL_NOW, FILL_TRACK, FILL_OK, "BDD7EE", "BFBFBF"][:cat_last - cat_first + 1], labels=False)
    cv.add_chart(pie)
    sevc = Chart("bar", "還要處理的：依嚴重度（列）", f"B{lh}:F{lh}", f"B{left_end}:F{left_end}", f"E{chart_top}:H{chart_bot}", "列數",
                 ["C00000", "ED7D31", "FFC000", "70AD47", "A6A6A6"])
    cv.add_chart(sevc)
    if d["has_exp"]:
        cv.add_chart(Chart("bar", "還要處理的：對外與否（列）", f"A{el0}:A{el1}", f"G{el0}:G{el1}", f"I{chart_top}:L{chart_bot}", "列數",
                           ["C00000", "A6A6A6", "FFC000"][:el1 - el0 + 1]))
    return finish_dashboard(cv, doc, d, r, h2, note, True)


def col_pair(i):
    return col_name(2 * i), col_name(2 * i + 1)


def finish_dashboard(cv, doc, d, r, h2, note, assessed):
    cv.set(f"A{r}", "說明", h2)
    items = ["「列」＝一個 CVE 在一個元件版本上的一筆（CVE × 元件），這份報告都用這個單位。同一個 CVE 可出現在不同分類，所以 CVE 數不能跨分類相加（分類表的合計列是整體去重後的數字）。",
             "「沒對外」只用來排優先順序，不等於不能被利用（已登入的人、惡意檔案、USB、客戶自己開的服務仍可能）；結果只代表檢查那次的板子狀態。"
             if d["has_exp"] else "沒有實機的對外服務清單，對外與否不明；上面「不明」不是「沒對外」。",
             "本頁數字由掃描產生，不是公式；細節與逐列證據見後面的工作表。",
             "沒有列出的不代表沒有問題；資料缺少或過期的項目標 NOT_ASSESSED 或 GAP，不是 0。"]
    items += [f"產生報告時的設定警告：{plain(w)[:300]}" for w in doc.get("_warnings") or []]
    for t in items:
        r += 1
        cv.set(f"A{r}", "．" + t, note)
        cv.merge(f"A{r}:L{r}")
        cv.height(r, 14 * max(1, -(-len(t) // 70)) + 4)
    return cv


def list_sheets(doc, fix_all, conf):
    """→ (完整漏洞清單：全部的列, 排除後剩下的：還要處理的列＋未分類)。兩張同樣的欄位，依 sort_key 排。"""
    allr = sorted(doc["rows"], key=sort_key)
    op = [r for r in allr if r["tier"] in OPEN_TIERS or r["tier"] not in TIER_CLASS]
    full, rest = [list_row(r, fix_all, conf) for r in allr], [list_row(r, fix_all, conf) for r in op]
    if not doc.get("have_findings"):
        full = rest = [["NOT_ASSESSED－沒有弱點資料", "", "", "", "", "", "", "", "重新掃描", SW, "清單是空的是因為沒有資料，不是沒有弱點", "", ""]]
    note = exposure_note(doc)
    top = [[LIST_LEGEND]] + ([[note]] if note else []) + [[]]
    return (Sheet("完整漏洞清單", LIST_HEADER, full, widths=LIST_WIDTHS, top=top, top_nowrap=True),
            Sheet("排除後剩下的", LIST_HEADER, rest, widths=LIST_WIDTHS, top=top, top_nowrap=True))


def rules_sheet(doc, fix_all):
    cnt = collections.Counter()
    for r in doc["rows"]:
        cnt[rule_code(r) or "（無）"] += 1
        for sg in all_suggestions(r):
            if isinstance(sg, dict) and sg.get("rule") in SUGGESTIONS:
                cnt["建議:" + sg["rule"]] += 1       # 建議的列數（這些列的判定不變，仍算在原本的規則裡），另計
    rows = []
    for c in RULE_ORDER:
        if c == "人工":
            rows.append(["人工", "依 VEX 狀態：不影響／受影響／判斷中－人工判定", "（依狀態）", "RD 的具名判定（vex-annotations.json 或 Dependency-Track）", "依判定", ENG,
                         "人工判定：狀態與理由", cnt.get(c, 0)])
            continue
        cls, concl, act, who, ev = RULES[c]
        rows.append([c, SHORT[c], cls, concl, act.replace("{fix}", "修補版本"), who, ev.replace("{fix}", "修補版本"), cnt.get(c, 0)])
    for c in SUGGESTIONS:
        cls, concl, act, who, ev = SUGGESTIONS[c]
        rows.append([c, "（建議，不改初判）", cls, concl, act, who, ev, cnt.get("建議:" + c, 0)])
    for c in sorted(c for c in cnt if c not in RULES and c not in SUGGESTIONS and not c.startswith("建議:")):
        rows.append([c, "未分類－沒有對應的規則說明", UNKNOWN, UNKNOWN, UNKNOWN, UNKNOWN, "", cnt[c]])
    top = [["三個分類"], [T_NOW, "已被攻擊者利用，且還沒有證據排除；需要 RD 確認"],
           [T_TRACK, "受影響或評估中，等修補或排進下一版"], [T_OK, "經評估不受影響，或發行版已修補；留紀錄、設定改變時重判"],
           [SUGGEST, "UB1／UB2／N1／N2 只是建議，不改任何判定；本次列數是有建議的列數（判定仍算在原本的規則）。RD 確認後才用人工判定改"], []]
    return Sheet("規則說明", ["規則代號", "初判", "分類", "結論", "要做什麼", "誰處理", "依據的一句話", "本次列數"], rows, widths=[12, 34, 22, 52, 36, 26, 40, 10], top=top)


def p1_sheet(doc, fix_all):
    p1 = [r for r in doc["rows"] if r["tier"] == "p1"]
    by = collections.defaultdict(list)
    for r in p1:
        by[r["id"]].append(r)
    head = ["編號", "CVE", "元件與版本", "修補版本", "被利用證據", "初判", "回答", "決定", "填寫人", "日期"]
    rows = []
    for i, cve in enumerate(sorted(by), 1):
        xs = sorted(by[cve], key=lambda r: (str(r.get("component")), str(r.get("version"))))
        comps = "；".join(f"{r.get('component')} {r.get('version') or ''}".strip() for r in xs)
        ft = [fix_text(r, fix_all) for r in xs]
        fixes = ft[0] if len(set(ft)) == 1 else "；".join(f"{r.get('component')} {r.get('version') or ''}：{t}".replace("  ", " ") for r, t in zip(xs, ft))
        ev = "；".join(dict.fromkeys(e for r in xs for e in (exploit_text(r).split("；") if exploit_text(r) else [])))
        rows.append([f"Q{i}", cve, comps, fixes, ev or "（沒有證據文字）", "", "", "", "", ""])
    if not rows:
        rows = [["", "（沒有立即處理的項目）" if doc.get("have_findings") else "NOT_ASSESSED：沒有弱點資料，不能當成沒有 P1",
                 "", "", "", "", "", "", "", ""]]
    return Sheet("P1 判斷表", head, rows, widths=[8, 18, 44, 36, 36, 20, 30, 16, 12, 12])


def suggestion_sheet(doc):
    """所有來源的建議（UB1／UB2 UEFI 映像檢查、N1／N2 NVIDIA 公告的 CVE 其實是發行版套件的）：給 RD 確認的表，一筆建議一列。沒有建議 → None。
    建議不改判定；RD 確認後用人工判定改（vex-annotations.json 或 Dependency-Track）。"""
    items = [(r, sg) for r in doc["rows"] for sg in all_suggestions(r) if one_suggestion_text(r, sg)]
    if not items:
        return None
    items.sort(key=lambda t: (t[1]["rule"], str(t[0].get("component")), str(t[0].get("version")), str(t[0]["id"])))
    head = ["編號", "CVE", "元件與版本", "目前判定", "建議", "佐證", "回答", "決定", "填寫人", "日期"]
    rows = []
    for i, (r, sg) in enumerate(items, 1):
        v = r.get("vex") or {}
        cur = f"{STATE_ZH.get(v.get('state'), v.get('state') or '未判定')}" + (f"（{rule_code(r)}）" if rule_code(r) else "")
        ev = re.sub(r"\s*\(bulk rule [^)]*\)\s*$", "", str(sg.get("detail") or ""))
        rows.append([f"S{i}", r["id"], f"{r.get('component')} {r.get('version') or ''}".strip(), cur, one_suggestion_text(r, sg), ev, "", "", "", ""])
    return Sheet("建議（需 RD 確認）", head, rows, widths=[8, 18, 36, 20, 44, 70, 30, 16, 12, 12])


INTERNAL_KEY = re.compile(r"\[[A-Za-z][\w-]*:[^\]]*\]\s*")


def stage_prefix(text):
    """文字裡有掃描階段代號（C-sbomgate 等）時，前面加一句白話；英文原文不動。"""
    hits = [w for code, w in STAGE_WORDS if code in text]
    return f"（{'；'.join(dict.fromkeys(hits))}）{text}" if hits else text


def confirmation_sheet(csv_path):
    """編號改成「確-01…」（避免和 P1判斷表的 Q1… 撞號；原 csv／md 在內部存檔，可對照）；[vuln:…]、[input:…] 內部鍵拿掉；
    部門名稱換成角色名稱（軟體部門→CRA掃描、產品工程師→RD、專案負責人→PM）；有掃描階段代號的格子前面加一句白話。
    「要問誰」只有 CRA掃描的題目（掃描自己的待辦）不放進這張表，編號依剩下的題目重排。"""
    with open(csv_path, encoding="utf-8-sig", newline="") as f:
        data = list(csv.reader(f))
    if not data:
        raise PackageError(f"{csv_path} 是空的")
    head = ["編號"] + [plain(h) for h in data[0][1:]]
    ask_col = next((j for j, h in enumerate(head) if h.startswith("要問誰")), None)
    out, n = [], 0
    for r in data[1:]:
        cells = [stage_prefix(plain(INTERNAL_KEY.sub("", c))) for c in r[1:]]
        # 只問 CRA掃描自己的題目（掃描階段沒完成等）是內部待辦，不放給 PM；原 csv／md 在內部存檔
        if ask_col is not None and len(cells) >= ask_col and cells[ask_col - 1].strip() == "CRA掃描":
            continue
        n += 1
        out.append([f"確-{n:02d}"] + cells)
    widths = [8, 12, 50, 30, 18, 36, 36, 16, 12, 12, 12, 20][:len(head)]
    return Sheet("待確認事項", head, out, widths=widths)


# ---------------------------------------------------------------- 打包

def check_out(out, allow_tmp=False):
    out = Path(out)
    res = out.resolve()
    if not allow_tmp and any(res == Path(p) or Path(p) in res.parents for p in ("/tmp", "/var/tmp")):
        raise PackageError(f"不寫 /tmp：{out}（/tmp 空間小、重開機會清掉）")
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise PackageError(f"輸出資料夾已存在且不是空的：{out}（不覆蓋；換一個新資料夾）")
    return out


def inside(path, parent):
    path, parent = Path(path).resolve(), Path(parent).resolve()
    return path == parent or parent in path.parents


def copy_file(src, dst):
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)


def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def build(project, out, supplier_project=None, name=None, version=None, allow_tmp=False, previous=None, diff_grype_db=None, inputs_check=None):
    """→ (退出碼, 訊息列表)。0＝完整；2＝有缺的輸入（GAP，記在未產生的項目.md）；PackageError＝失敗，沒有留下半成品。"""
    project = Path(project)
    reports = project / "CRA" / "Reports"
    if not reports.is_dir():
        raise PackageError(f"找不到 {reports}")
    for d in (project, supplier_project):
        if d and inside(out, d):
            raise PackageError(f"輸出資料夾不能在專案資料夾裡面：{out}（在 {d} 之下）；換一個專案以外的新資料夾")
    out = check_out(out, allow_tmp)
    doc = read_rows(reports)
    label = product_label(project, name, version)
    conf = read_rules_confirmation(project)
    fix_all = {}
    try:
        summ = load_json(reports / "summary.json")
        for g in (summ.get("counts", {}).get("kernel", {}).get("fix_all") or []):
            if g.get("fix_all_version"):
                fix_all[g["component"]] = g["fix_all_version"]
        doc["_warnings"] = [str(w) for w in summ.get("config_warnings") or []]
    except (OSError, ValueError, AttributeError):
        pass
    ic = None
    if inputs_check:       # 精靈的輸入清單檢查：缺的必要輸入進設定警告與「未產生的項目」（GAP）
        try:
            ic = load_json(Path(inputs_check))
        except (OSError, ValueError) as e:
            raise PackageError(f"讀不了 --inputs-check {inputs_check}（{e}）")
        if not isinstance(ic, dict) or not isinstance(ic.get("inputs"), list) or not all(isinstance(r, dict) for r in ic["inputs"]):
            raise PackageError(f"--inputs-check {inputs_check} 格式不對：最外層要是物件，且 inputs 要是物件清單")
        for r in ic["inputs"]:
            if r.get("status") == "missing" and r.get("required"):
                doc.setdefault("_warnings", []).append(f"必要輸入缺少（GAP）：{r.get('label')}；影響：{r.get('affects') or '未說明'}")
            elif r.get("status") in ("gap", "fail", "not_run") and r.get("kind") == "step":     # 精靈附加步驟（OP-TEE／UEFI 平台設定／A0／板子結果）沒做成
                doc.setdefault("_warnings", []).append(f"{r.get('label')}：{str(r.get('status')).upper()}（{r.get('note') or '未說明'}）；影響：{r.get('affects') or '未說明'}")
            elif r.get("status") == "unchecked" and r.get("required"):    # 警告，不算 GAP：只是沒辦法自動確認，不等於缺
                doc.setdefault("_warnings", []).append(f"必要輸入未確認（無法自動檢查，請人工確認）：{r.get('label')}；影響：{r.get('affects') or '未說明'}")
    created = not out.exists()
    out.mkdir(parents=True, exist_ok=True)
    msgs, missing = [], []
    try:
        pm, rd, arch = out / PM, out / RD, out / ARCH
        for d in (pm, rd, arch):
            d.mkdir()
        full, rest = list_sheets(doc, fix_all, conf)
        write_xlsx(pm / "漏洞清單.xlsx", [dashboard_sheet(doc, fix_all, label), full, rest, rules_sheet(doc, fix_all)])
        write_xlsx(rd / "P1判斷表.xlsx", [p1_sheet(doc, fix_all)] + ([suggestion_sheet(doc)] if suggestion_sheet(doc) else []))
        moved = {ROWS_FILE}

        def need(rel, dst, what):
            src = reports / rel
            if src.is_symlink():
                missing.append((what, f"Reports/{rel} 是符號連結，不複製"))
                return False
            if src.is_file():
                copy_file(src, dst)
                return True
            missing.append((what, f"Reports/{rel} 不存在"))
            return False

        need("sbom.cdx.json", pm / "SBOM" / "sbom.cdx.json", "SBOM（sbom.cdx.json）")
        need("sbom.md", pm / "SBOM" / "sbom.md", "SBOM 摘要（sbom.md）")
        need("vex.cdx.json", pm / "VEX" / "vex.cdx.json", "VEX（vex.cdx.json）")
        need("security-findings.md", pm / "安全檢查結果.md", "安全檢查結果（security-findings.md）")
        moved |= {"sbom.cdx.json", "sbom.md", "vex.cdx.json", "security-findings.md"}
        cs = reports / "confirmation-items.csv"
        if cs.is_symlink():
            missing.append(("待確認事項（confirmation-items.csv）", "Reports/confirmation-items.csv 是符號連結，不複製"))
        elif cs.is_file():
            write_xlsx(pm / "待確認事項.xlsx", [confirmation_sheet(cs)])
        else:
            missing.append(("待確認事項（confirmation-items.csv）", "Reports/confirmation-items.csv 不存在"))
        if supplier_project:
            sp = Path(supplier_project) / "CRA" / "Reports" / "supplier-package"
            if sp.is_symlink():
                missing.append(("客戶資料包（supplier-package）", f"{sp} 是符號連結，不複製"))
            elif sp.is_dir():
                shutil.copytree(sp, pm / "客戶資料包", symlinks=True)
            else:
                missing.append(("客戶資料包（supplier-package）", f"{sp} 不存在（供應商角色的專案要先跑 cra_report.py）"))
        else:
            msgs.append("客戶資料包：未產生（沒有給 --supplier-project）")
        # 內部存檔：Reports 裡的其他檔案與資料夾（供應商資料包已在 交給PM/客戶資料包）；vulnerability-rows.json 也在這裡
        for p in sorted(reports.iterdir()):
            if p.name.startswith(".") or p.name == "supplier-package":
                continue
            if p.name in moved - {ROWS_FILE}:
                continue
            if p.is_symlink():
                missing.append((f"內部存檔：{p.name}", "是符號連結，不複製"))
            elif p.is_dir():
                shutil.copytree(p, arch / p.name, symlinks=True)
            else:
                copy_file(p, arch / p.name)
        if ic is not None:
            copy_file(Path(inputs_check), arch / "inputs-check.json")
            for r in ic.get("inputs") or []:
                if r.get("status") == "missing" and r.get("required"):
                    missing.append((f"必要輸入：{r.get('label')}", f"沒有提供；影響：{r.get('affects') or '未說明'}"))
                elif r.get("kind") == "step" and r.get("status") in ("gap", "fail", "not_run"):
                    missing.append((f"附加步驟：{r.get('label')}（{str(r.get('status')).upper()}）", f"{r.get('note') or '未說明'}；影響：{r.get('affects') or '未說明'}"))
        if previous:
            add_diff(previous, reports, arch, pm / "客戶資料包", diff_grype_db)
        if missing:
            lines = [f"# 未產生的項目（{NOT_RUN}）", "", "下列輸入缺少，對應的檔案沒有產生；不要把缺少當成沒有問題。", ""]
            lines += [f"- {w}：{why}" for w, why in missing]
            (pm / "未產生的項目.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
            msgs += [f"{NOT_RUN}：{w}（{why}）" for w, why in missing]
        sums = [f"{sha256(p)}  {p.relative_to(out).as_posix()}" for p in sorted(out.rglob("*")) if p.is_file() and not p.is_symlink()]
        (out / "SHA256SUMS.txt").write_text("\n".join(sums) + "\n", encoding="utf-8")
    except BaseException:
        if created:
            shutil.rmtree(out, ignore_errors=True)
        else:
            for p in out.iterdir():
                shutil.rmtree(p, ignore_errors=True) if p.is_dir() else p.unlink(missing_ok=True)
        raise
    tc = tier_counts(doc["rows"])
    msgs.insert(0, "；".join(f"{c} {a} 列（{b} 個 CVE）" for c, (a, b) in tc.items() if c != T_OTHER or a) + f"；{status_line(doc)}")
    st = doc.get("vulnerability_data_status")
    if not doc.get("have_findings"):
        final = "NOT_ASSESSED"
    elif st and st != "OK":
        final = str(st)
    else:
        final = "GAP" if missing else "OK"
    msgs = Msgs(msgs)
    msgs.status = final
    return (0 if final == "OK" else 2), msgs


def add_diff(previous, reports, arch, customer_dir, grype_db=None):
    """--previous：和前一份報告比較，中文＋json 放內部存檔，英文版放客戶資料包（有客戶資料包才放）。沒給 --previous 時不呼叫。"""
    import report_diff
    try:
        d = report_diff.compute(previous, reports, grype_db)
        has_pkg = customer_dir.is_dir()
        report_diff.write_outputs(d, arch, internal=True, customer_dir=customer_dir if has_pkg else None)
        if has_pkg:
            report_diff.register_in_package(customer_dir, report_diff.OUT_EN)
    except report_diff.DiffError as e:
        raise PackageError(f"和前一份報告的比較失敗：{e}")


def main(argv=None):
    ap = argparse.ArgumentParser(description="把 CRA 報告輸出整理成給一般人看的中文成果包")
    ap.add_argument("--project", required=True, help="製造商專案資料夾（有 CRA/Reports/vulnerability-rows.json）")
    ap.add_argument("--supplier-project", help="供應商角色的專案資料夾（有 CRA/Reports/supplier-package/）；沒給就不放客戶資料包")
    ap.add_argument("--out", required=True, help="新的空資料夾")
    ap.add_argument("--name", help="產品名稱（預設取 config.json）")
    ap.add_argument("--version", help="產品版本（預設取 config.json）")
    ap.add_argument("--previous", help="（選用）同一產品前一份報告的資料夾；給了就產生和它的差異（內部存檔＋客戶資料包的英文版）")
    ap.add_argument("--diff-grype-db", help="（選用，要有 --previous）這一次用的 vulnerability.db，唯讀，用來核對發行版狀態")
    ap.add_argument("--inputs-check", help="（選用）精靈產生的 inputs-check.json；缺少的必要輸入會在報告標 GAP，檔案放內部存檔")
    try:
        a = ap.parse_args(argv)
    except SystemExit as e:
        return 64 if e.code else 0
    if a.diff_grype_db and not a.previous:
        print("FAIL\t--diff-grype-db 要和 --previous 一起給", file=sys.stderr)
        return 64
    try:
        code, msgs = build(a.project, a.out, a.supplier_project, a.name, a.version, previous=a.previous,
                           diff_grype_db=a.diff_grype_db, inputs_check=a.inputs_check)
    except PackageError as e:
        print(f"FAIL\t{e}", file=sys.stderr)
        return 1
    for m in msgs:
        print(m)
    print(f"{getattr(msgs, 'status', 'GAP' if code else 'OK')}\t{a.out}")
    return code


if __name__ == "__main__":
    sys.exit(main())
