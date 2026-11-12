#!/usr/bin/env python3
"""cra_report.py：歐盟網路韌性法（CRA，Regulation (EU) 2024/2847）文件草稿產生器（Markdown）。

用法：
  python3 -I cra_report.py --project <專案根目錄> --scan <sca-scan 輸出資料夾> [--out <資料夾>]
  python3 -I cra_report.py --project <專案根目錄> --run-scan <sca-scan 輸出資料夾>
    （只執行 sca-scan：參數取自 config.json 的 scan 段；PILOT_ENV 由環境變數傳給 sca-scan，這裡不讀；回傳 sca-scan 的退出碼）
設定：<專案>/CRA/Config/config.json，以同資料夾的 config.schema.json 驗證（只實作用到的子集，見 schema 的 description）。
  公司共用設定（選用）：--company <檔案>、環境變數 CRA_COMPANY_CONFIG，或 runner 上的 /etc/sca-gitlab/company.json（存在時）。
  --no-company 或 CRA_COMPANY_CONFIG=none：不用公司共用設定。公司共用設定只能有公司層級的段落（COMPANY_SECTIONS），
  拼錯的鍵、產品或掃描的段落 → FAIL（這份檔案影響所有專案，不能只給警告）。
  合併規則：鎖定的段落（COMPANY_LOCKED：製造商、弱點通報窗口、弱點處理規則）公司有填的值一律用公司的，專案寫的不同時記警告；
  其他欄位專案的值優先，專案沒有、或是空字串／空清單時用公司的值（物件逐層合併）。公司設定的檔案指定了卻讀不到或格式錯 → FAIL。
  python3 -I cra_report.py --check-company <檔案>：只檢查公司共用設定（給 deploy/gitlab-runner/install.sh --company 用）。
範本：<專案>/CRA/templates/<名稱>.md 存在就用，否則用內建 templates/<名稱>.md。語法 {{ 點路徑 }}；不認得的 placeholder → FAIL。
輸入（sca-scan 的輸出，.json 或 .json.xz 都可）：dt/findings.json、sbom/sbom.cdx.json、scan/grype.json、meta.json、status.tsv、
  dt/deb-sources.json（有的話：DT 以 Debian／Ubuntu 原始碼套件比對時，列出從它安裝的二進位套件）、
  scan/l4t-kernel-map.json（有的話：Jetson 核心對應的 Canonical 核心元件，元件欄註明它是從哪個 nvidia-l4t-kernel 對應來的）、
  scan/nvidia-bulletins.json（有的話：Jetson Linux 的 NVIDIA 安全公告比對，tools/pilot/lib/nvidia_bulletins.py；只有對照表已審核的列
  產生發現，source NVIDIA，和 DT 的發現一起進清單；風險評估 8.8 節列出對照表狀態、推定已含修正與需原廠確認的 CVE）、
  scan/distro-recheck.json（有的話：Debian／Ubuntu 套件上只經 NVD 等非發行版資料比對到的列，以發行版的 OSV 紀錄再判，
  tools/pilot/lib/distro_recheck.py；見下面「發行版已修補」）、
  scan/usn-cves.json（有的話：沒有 CVE 別名的 USN 列的 CVE，tools/pilot/lib/usn_cves.py；USN 併進同一個元件版本上那個 CVE 的列，build_rows）。
  scan/ubuntu-priority.json（有的話：Ubuntu 套件上 CVE 的 Ubuntu priority，tools/pilot/lib/ubuntu_priority.py；分級的嚴重度依
  vulnerability_policy.severity_sources＝供應商評級優先，pick_severity）。
Ubuntu 打包的 Python 模組（SBOM 的 pypi 元件在 /usr/lib/python3/dist-packages）：列保留，指向擁有它的 deb 套件，不給 pip 的修補建議，
  批次規則沿用擁有它的 deb 列的規則判定，或以擁有者的 deb 套用（deb_python_index、apply_deb_python、vex_export.deb_python_rules）。
輸出（預設 <專案>/CRA/Reports/）：risk-assessment.md（Article 13 風險評估的骨架；漏洞清單自動產生）、sbom.md、
  sbom.cdx.json（產品 SBOM：掃描的 SBOM 加上產品與製造商資料，見 product_bom）、user-information.md（Annex II）、
  technical-documentation.md（Annex VII，自動的部分填入、其他標 TO BE COMPLETED 與負責人）、
  scan-status.tsv（status.tsv 複本，當證據）、summary.json（每份文件的狀態、缺的欄位、數量、輸入檔 sha256）、
  kernel-vulnerabilities.md（作業系統核心的完整弱點清單；只在有核心的列時產生，見 kernel_rows_of）、
  vex.cdx.json／vex.openvex.json（每一列的 VEX 狀態，tools/cra/vex_export.py；判定來源依序是 DT 的人工分析與
  CRA/Config/vex-annotations.json、發行版已修補、scan/kernel-config.json、NVIDIA 推定、CRA/Config/vex-rules.json 的批次規則；風險評估另有 VEX 與發行閘門的小節）。
  批次規則裡的證據規則（K1／K2／U1）另讀 scan/kernel-module-map.json（CVE → 核心模組）、CRA/Config/kernel-modules.json（映像的模組與載入限制；
  格式錯 → FAIL）、scan/ubuntu-status.json（tools/pilot/lib/ubuntu_status.py，Ubuntu CVE Tracker 的狀態）與 meta.json 的映像雜湊；
  另標記可能誤報 distro_no_range_upstream_excludes（vex_export.upstream_exclusion_flags，只標記）。
  dt/analysis.json（有的話；tools/e2e/dtread.py readback）補上 DT findings API 沒有的 justification／response／details。
  confirmation-items.csv／.md（待確認事項表，tools/cra/confirm_items.py：工具判斷不了、直接問產品工程師、經專案負責人（PM）問法務／主管的事，從這次已有的資料列出；
  --pkgdb 或 <scan>/../pkgdb 給沒有修補的套件找出是誰帶進來的；summary.json 的 confirmation_items）。
  沒有漏洞資料的套件（tools/cra/no_vuln_data.py：廠商自己建置、發行版的漏洞資料可能不認得的 deb 套件，0 列不代表沒有漏洞）：
  風險評估 8.1 節的小節、summary.json 的 packages_without_vuln_data（NOT_ASSESSED 的數量與訊號）、待確認事項表每組一筆；不改層級與狀態。
作業系統核心（Jetson 的對應 Canonical 核心約 6000 列）：風險評估的主清單（8.4–8.6、附錄 A）不列核心的列，改在 8.7 節摘要
  （修補狀態、層級、修補全部所需的最低核心版本、只列 P1 與 accepted 的表格），完整清單寫 kernel-vulnerabilities.md。
  層級與整體狀態照樣算進核心的列（例如核心有未處理的 P1 → ATTENTION）。
stdout 印一行「狀態<TAB>說明」。退出碼：FAIL → 1；其他非 OK → 2；全部 OK → 0（仍不代表產品安全）；參數錯誤 → 64。

判定（專案驗收原則：缺資料不可顯示為安全）：
  - config.json 不存在、不是 JSON、必填欄位缺少或型別不符、範本有不認得的 placeholder → FAIL，不寫 Markdown（只寫 summary.json）。
  - 選填欄位缺少 → 文件內顯示 TO BE COMPLETED，該文件至少 GAP。
  - 風險評估：沒有 DT findings 或 SBOM 為空 → NOT_ASSESSED；status.tsv 缺、DT 資料源／KEV／OSV 涵蓋／弱點分析／findings、
    sbomgate、meta.json 任一不是 OK → GAP（清單不完整）；有條件才寫的階段（COND_STAGES）有這一列而且不是 OK → GAP；
    有未處理的 P1、Grype 有 DT 沒有的 CVE、C-grype 不是 OK 或沒有 Grype 結果 → ATTENTION。
  - Grype 有、DT 沒有的比對（交叉核對的同一個判斷）成為「只有 Grype」的列（grype_only_rows；Source IDs GRYPE:…，
    元件欄 found only by Grype），和其他列一樣分級、判斷、寫 VEX；DT 的列不變。
  - 缺的欄位以內建範本引用的欄位為準（專案範本少引用也算缺）。FAIL 時刪掉輸出資料夾裡上一次的文件，只寫 summary.json。
  - SBOM：沒有 SBOM 或沒有非 file 元件 → NOT_ASSESSED；SBOM 產生或 sbomgate 階段不是 OK → GAP。
優先級規則是草案（config.json 的 vulnerability_policy，預設值在 config.schema.json），由公司決定；報告列出實際使用的規則。
分級方式 exploitation（vulnerability_policy.scheme，選用；沒寫＝current，輸出不變）：P1＝已被利用（KEV、scan/euvd.json、
  CRA/Config/exploitation-evidence.json 的人工證據）且沒有判定不受影響，P2＝判斷為可被利用，P3＝其他；風險評估另有「出貨前要判斷的」
  小節（被利用的列＋CRA/Config/exposed-services.json 對外元件上 CVSS ≥ 7 且 AV:N／AV:A、或沒有 CVSS 而 Ubuntu priority high／critical 的列；沒有清單 → GAP）與依日期（2027-12-11）的出貨關卡，
  summary.json 的 exploitation（exploitation_section）。vex_export 的發行閘門不變。
EUVD（scan/euvd.json，兩種分級方式；沒有檔案時輸出不變）：EUVD 標示已遭利用的 CVE 是另一種被利用證據（不設 kev，exploited_sources），
  current 也進 P1（kev 條件）、只採用具名的人工判定；KEV 欄寫 EUVD 的清單（CISA KEV、ENISA EU KEV）；status 不是 OK 或讀不到 → 不用、
  文件 GAP（euvd_unavailable_reason）；summary.json 的 euvd。
發行版已修補（scan/distro-recheck.json 的 status 是 OK 時才用；檔案不存在時文件與 summary.json 的其他內容都不變）：
  判定 distro_fixed 的列（Debian／Ubuntu 套件上只有 NVD／GitHub 等非發行版資料的 finding，發行版的紀錄說安裝的版本已含 backport 的修補）
  從 P1–P3 移出，改列在風險評估的「Reported only via NVD but fixed by the distribution (backported)」小節（8.8 或 8.9，接在核心與 NVIDIA
  之後），附 CVE、元件、安裝版本、發行版修補版本與紀錄編號。這是刻意改變層級數量：P1–P3 與 summary.json 的 p1／p2／p3、kev_open
  不含這些列，另記 counts.distro_fixed；8.2 節多兩列（數量、其中 KEV 的數量）。KEV 的列照樣移出，但在小節裡逐筆點名並要求人工確認，
  資料狀態也加一個 ATTENTION 的理由（不能因為移出而變成 OK）。只有公告（USN／DSA／DLA）說已修補的列不移（distro_fixed_advisory_only）。
  只移出 P1–P3（accepted 不動）、不移核心的列；列裡有 distro_recheck 沒看到的 finding（例如 NVIDIA 公告）時不移。
  專案自己的風險評估範本沒有引用 text.distro_section 時不移（列不能從文件消失），並記警告。
分層（M2；SBOM 的元件帶 dumpling:layer 時才動作，由 pipeline/sbom-layers.py 標；沒有時輸出不變，--os-responsibility 也沒有作用；
  規則見 docs/LAYERS.md）：每一列有 layer（bsp｜os｜unknown）、layer_todo（算不算我們的待辦）、layer_basis。host-tool 元件上的 DT finding 與
  Grype 比對移出產品比對結果（不進清單、交叉核對與 P1；summary.json 的 layers.host_tool 記數量與身分）。layer_todo：bsp、unknown 一定算；
  os 只有 os_responsibility 是 ours 或沒給（保守，並讓風險評估文件 GAP）時算。整體狀態（ATTENTION）的 P1 理由、移出 P1–P3 的 KEV 理由、
  分級方式 exploitation 的出貨關卡都只看我們的待辦；OS 層（customer／upstream-vendor）的列照樣在表上，已被利用的另列「通知客戶」
  （風險評估 Layers 一節、summary.json 的 layers.notify_customer）。vex_export 的發行閘門不分層（不變）。
安全測試（tools/cra/security_findings.py；風險評估第 9 節、技術文件第 6 項、security-findings.md、summary.json 的 security_testing）：
  輸入是掃描資料夾旁邊的 <scan>/../image-check/image-check.json（image_check.py）與 <scan>/../board-test/board-test.json
  （board_import.py），或 --image-check／--board-test 指定的檔案。人工決定檔 CRA/Config/security-findings.json（格式錯 → FAIL）。
  沒有任何結果 → 第 9 節寫 NOT RUN、風險評估至少 ATTENTION；有沒有決定的 high／medium → ATTENTION。漏洞資料狀態（risk.data_status）
  與發行閘門不受影響；風險評估文件的狀態是兩者較差的那個。
"""
import argparse
import datetime
import functools
import hashlib
import importlib.util
import json
import lzma
import math
import os
import re
import shutil
import subprocess
import sys
import urllib.parse
import uuid
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SCHEMA = json.loads((HERE / "config.schema.json").read_text(encoding="utf-8"))
ORDER = ["FAIL", "NOT_ASSESSED", "GAP", "NOT_RUN", "ATTENTION", "OK"]
# 產生順序：technical-documentation 的檢查清單引用前三份的狀態，所以放最後
DOCS = {"risk-assessment": "risk-assessment.md", "sbom": "sbom.md", "user-information": "user-information.md",
        "technical-documentation": "technical-documentation.md"}
# 作業系統核心的完整清單：沒有範本（內容只有產生的表格），只在有核心的列時寫，否則刪掉上一次的檔案
KERNEL_DOC = ("kernel-vulnerabilities", "kernel-vulnerabilities.md")
SEC_DOC = ("security-findings", "security-findings.md")      # 安全測試的 findings 清單（沒有範本；security_findings.document）
# Annex I Part I point (2) 的 13 項（簡短標題；以官方公報原文為準）。(a) 由漏洞清單處理，其他從 config 的 risk_assessment.annex_i_applicability
ANNEX_I = [("a", "Made available without known exploitable vulnerabilities"),
           ("b", "Secure by default configuration, including the possibility to reset to the original state"),
           ("c", "Vulnerabilities can be addressed through security updates (where applicable automatic by default with an opt-out, "
                 "notification of available updates, option to postpone them temporarily)"),
           ("d", "Protection from unauthorised access (authentication, identity or access management); report on possible unauthorised access"),
           ("e", "Confidentiality of stored, transmitted or otherwise processed data (e.g. encryption)"),
           ("f", "Integrity of data, commands, programs and configuration; report on corruptions"),
           ("g", "Data minimisation"),
           ("h", "Availability of essential and basic functions, also after an incident (incl. denial-of-service resilience)"),
           ("i", "Minimise the negative impact on the availability of services provided by other devices or networks"),
           ("j", "Limit attack surfaces, including external interfaces"),
           ("k", "Reduce the impact of an incident using exploitation mitigation mechanisms and techniques"),
           ("l", "Record and monitor relevant internal activity (security information), with an opt-out for the user"),
           ("m", "Securely and easily remove all data and settings; secure transfer where data can be transferred")]
TBC = "**TO BE COMPLETED**"
NR = "NOT RECORDED"
SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNASSIGNED": 5}
CVE_RE = re.compile(r"^(?:[A-Z]+-)?(CVE-\d{4}-\d{4,})$")   # CVE-…、UBUNTU-CVE-…、DEBIAN-CVE-…
PH_RE = re.compile(r"\{\{\s*(.*?)\s*\}\}")
# 風險評估要看的 sca-scan 階段；缺任何一列都算資料狀態未知（GAP）
RISK_STAGES = ["D-dt-data-sources", "D-dt-kev-sources", "D-dt-osv-coverage", "D-dt-vuln-analysis", "D-dt-findings", "C-sbomgate"]
INFO_STAGES = ["C-grype-db", "C-grype"]
# 有條件才寫的階段：有這一列而且不是 OK → GAP（沒有這一列不算缺）。核心沒比對、DT 沒補原始碼套件、BOM 處理沒確認完成
# B-toolchain（Maven／Gradle 缺工具）、B-npm-no-lockfile（npm 沒有鎖定檔又不能連網）：依賴沒有解析出來，0 筆不代表沒有漏洞
COND_STAGES = ["C-kernel-l4t-map", "C-kernel-coverage", "C-nvidia-bulletins", "D-dt-deb-sources", "D-dt-bom-processing", "B-toolchain", "B-npm-no-lockfile"]
# 資料新鮮度的階段（sca-scan 掃描前寫的；有這一列才處理）：C-grype-db、C-mirror-freshness 不是 OK、C-grype-db-update FAIL → GAP（ATTENTION 維持 ATTENTION）；
# C-dt-feeds：GAP → GAP；NOT_RUN 只在原因是金鑰沒有權限（說明含 SYSTEM_CONFIGURATION_READ）時算 GAP——沒用 DT 的 NOT_RUN 已由 D-dt-data-sources 反映
FRESH_STAGES = ["C-grype-db-update", "C-grype-db", "C-mirror-freshness", "C-dt-feeds"]


def fresh_stage_level(k, st, detail):
    """新鮮度階段 → 風險狀態影響（GAP／ATTENTION／None）。"""
    if st == "OK":
        return None
    if st == "ATTENTION":
        return "ATTENTION"
    if k == "C-grype-db-update":
        return "GAP" if st == "FAIL" else None          # NOT_RUN（GRYPE_DB_UPDATE=off）：資料庫年齡由 C-grype-db 判斷
    if k == "C-dt-feeds":
        return "GAP" if st == "GAP" or (st == "NOT_RUN" and "SYSTEM_CONFIGURATION_READ" in (detail or "")) else None
    return "GAP"


# 只列出、不影響資料狀態的有條件階段（有這一列才列在 8.1 的表；不是 OK 時寫一行 Note）：
#   D-distro-recheck 只會把「發行版已修補」的列移出 P1–P3。它沒有執行、鏡像過期（GAP）或失敗時一列都不移，清單照樣完整，
#   只是 P1–P3 可能多了已經 backport 修好的誤報（保守的方向），所以不算 GAP；放 INFO_STAGES 會讓沒有 deb 套件的專案也列 NOT_RUN。
NOTE_STAGES = ["D-distro-recheck", "D-usn-cves", "D-ubuntu-priority", "D-ubuntu-status"]   # D-usn-cves：沒有 CVE 的 USN 對到 CVE（沒有時 USN 各自成列，清單照樣完整）；
# D-ubuntu-priority：Ubuntu priority（沒有時嚴重度照 Grype 的 Ubuntu 比對或 DT／NVD，偏保守）；
# D-ubuntu-status：Ubuntu CVE Tracker 的狀態（證據規則 U1 用；沒有時 U1 不套用，列照樣受影響）
DISTRO_STAGE = "D-distro-recheck"
OPEN_TIERS = ("p1", "p2", "p3")


class Fail(Exception):
    pass


class Missing(str):
    """缺少的報告欄位：顯示 TO BE COMPLETED 並記下路徑。"""
    def __new__(cls, path):
        s = super().__new__(cls, f"{TBC} (`{path}`)")
        s.path = path
        return s


def worst(statuses):
    return min(statuses, key=ORDER.index, default="OK")


# ---------- 設定：迷你 schema 驗證 ----------

def _type_ok(v, t):
    return {"object": isinstance(v, dict), "array": isinstance(v, list), "string": isinstance(v, str),
            "boolean": isinstance(v, bool), "integer": isinstance(v, int) and not isinstance(v, bool),
            "number": isinstance(v, (int, float)) and not isinstance(v, bool)}[t]


def _resolve(s):
    ref = s.get("$ref")
    if ref:
        node = SCHEMA
        for part in ref.lstrip("#/").split("/"):
            node = node[part]
        return node
    return s


def validate(obj, schema=SCHEMA, path=""):
    """回傳 (errors, warnings)。warnings：schema 沒有的鍵（多半是拼錯，該欄位會顯示 TO BE COMPLETED）。"""
    errors, warnings = [], []
    schema, where = _resolve(schema), path or "(root)"
    types = schema.get("type")
    if types:
        types = [types] if isinstance(types, str) else types
        if not any(_type_ok(obj, t) for t in types):
            return [f"{where}：型別應為 {'/'.join(types)}"], []
    if "enum" in schema and obj not in schema["enum"]:
        errors.append(f"{where}：只能是 {schema['enum']}")
    if isinstance(obj, str) and "pattern" in schema and obj and not re.search(schema["pattern"], obj):
        errors.append(f"{where}：格式不符 {schema['pattern']}")
    if _type_ok(obj, "number") and isinstance(obj, float) and not math.isfinite(obj):
        # NaN／Infinity：Python 的 JSON 讀得進來，minimum／maximum 的比較又擋不住 NaN（比較都是 False）
        errors.append(f"{where}：要是有限的數字（不能是 NaN 或 Infinity）")
    elif _type_ok(obj, "number"):
        if "minimum" in schema and obj < schema["minimum"] or "maximum" in schema and obj > schema["maximum"]:
            errors.append(f"{where}：超出範圍 {schema.get('minimum')}–{schema.get('maximum')}")
    if isinstance(obj, dict):
        props = schema.get("properties", {})
        for k in schema.get("required", []):
            if obj.get(k) in (None, "", [], {}):
                errors.append(f"{path + '.' if path else ''}{k}：必填")
        for k, v in obj.items():
            p = f"{path + '.' if path else ''}{k}"
            if k in props:
                e, w = validate(v, props[k], p)
                errors += e
                warnings += w
            else:
                warnings.append(f"{p}：schema 沒有這個鍵（忽略；是否拼錯？）")
    if isinstance(obj, list) and "items" in schema:
        for i, v in enumerate(obj):
            e, w = validate(v, schema["items"], f"{path}[{i}]")
            errors += e
            warnings += w
    return errors, warnings


DEFAULT_COMPANY = Path("/etc/sca-gitlab/company.json")   # deploy/gitlab-runner/install.sh --company 放的位置


def read_json_file(p):
    try:
        return json.loads(Path(p).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise Fail(f"找不到 {p}")
    except (OSError, ValueError) as e:
        raise Fail(f"{p} 讀不到或不是 JSON：{e}")


def company_file(arg=None, disabled=False):
    """公司共用設定的位置：--company ＞ CRA_COMPANY_CONFIG ＞ /etc/sca-gitlab/company.json（存在時）；都沒有或關閉 → None。"""
    import os
    env = os.environ.get("CRA_COMPANY_CONFIG")
    if disabled or (not arg and env == "none"):
        return None
    if arg:
        return Path(arg)
    if env:
        return Path(env)
    try:
        return DEFAULT_COMPANY if DEFAULT_COMPANY.is_file() else None
    except OSError as e:     # 資料夾沒有權限（Python 3.13 以前 is_file 會丟 PermissionError）
        raise Fail(f"讀不到 {DEFAULT_COMPANY}（{type(e).__name__}）：不在 gitlab-runner 群組時用 --no-company 或 --company <檔案>")


# 公司共用設定可以有的段落（值是 None 表示整段都可以；集合表示只能有這些鍵）。產品、掃描、用途等每個產品不同的段落不能放
# 每個產品不同的欄位（風險清單、資產、攻擊面、Annex I 逐項、架構、硬體照片、測試報告…）不能放：放了會讓沒做的產品顯示為已提供
COMPANY_SECTIONS = {"$comment": None, "schema_version": None, "manufacturer": None, "vulnerability_contact": None,
                    "vulnerability_policy": None, "sbom": {"availability"},
                    "technical_documentation": {"production_monitoring", "standards", "secure_update_distribution"},
                    "risk_assessment": {"method", "part_i_1_and_part_ii"}}


def load_company(p):
    """讀公司共用設定並檢查型別與格式（必填欄位不在這裡檢查：產品資料在專案）。回傳 (設定, 警告)。"""
    comp = read_json_file(p)
    if not isinstance(comp, dict):
        raise Fail(f"{p} 要是 JSON 物件")
    errors, warnings = validate(comp)
    # 拼錯的鍵在這裡是錯誤（這份檔案影響所有專案）
    errors = [e for e in errors if not e.endswith("：必填")] + [w.replace("（忽略；是否拼錯？）", "（是否拼錯？）") for w in warnings]
    for k, v in comp.items():
        if k not in COMPANY_SECTIONS:
            errors.append(f"{k}：不是公司層級的段落（只能有 {', '.join(sorted(x for x in COMPANY_SECTIONS if x != '$comment'))}）")
        elif COMPANY_SECTIONS[k] and isinstance(v, dict):
            errors += [f"{k}.{x}：每個產品不同，要寫在專案的 config.json" for x in v if x not in COMPANY_SECTIONS[k]]
    if not (isinstance(comp.get("manufacturer"), dict) and isinstance(comp["manufacturer"].get("name"), str) and comp["manufacturer"]["name"].strip()):
        errors.append("manufacturer.name：公司共用設定一定要有製造商名稱（所有專案的 CRA 文件都用它）")
    if errors:
        raise Fail(f"{p}（公司共用設定）不符合規則：" + "；".join(errors))
    return comp, []


def empty(v):
    return v in (None, "", [], {})


def unset(v):
    """鎖定段落裡「公司沒填」：只有 None 與空字串（空清單是有意義的值，例如 accepted.states: []）。"""
    return v is None or v == ""


# 整間公司只能有一個值的段落：公司共用設定有填時，專案不能覆寫（製造商的法律身分、對外的通報窗口、公司核准的處理規則）
COMPANY_LOCKED = ("manufacturer", "vulnerability_contact", "vulnerability_policy")


def merge_config(company, project, path="", locked=False, notes=None):
    """回傳合併後的設定（不改動輸入）。notes：被公司值取代的專案欄位（鎖定段落裡兩邊都有值而且不同）。"""
    out = json.loads(json.dumps(project))
    for k, v in company.items():
        p = f"{path}.{k}" if path else k
        lk = locked or (not path and k in COMPANY_LOCKED)
        if isinstance(v, dict) and (isinstance(out.get(k), dict) or empty(out.get(k))):
            # 專案沒有這一段時也逐層合併（不直接複製），公司的空值才會照樣被略過
            sub = merge_config(v, out[k] if isinstance(out.get(k), dict) else {}, p, lk, notes)
            if sub or isinstance(out.get(k), dict):
                out[k] = sub
        elif unset(v):
            continue                                    # 公司沒填：不帶進空值（例如 status: "" 會讓 DRAFT 標記消失）
        elif empty(out.get(k)):
            out[k] = json.loads(json.dumps(v))
        elif lk and out[k] != v:
            if notes is not None:
                notes.append(p)
            out[k] = merge_config(v, {}, p, lk) if isinstance(v, dict) else json.loads(json.dumps(v))   # 公司的空值照樣略過
    return out


def load_config(project, company=None):
    """回傳 (合併後的設定, 警告, 公司設定的 {path, sha256} 或 None)。"""
    p = project / "CRA" / "Config" / "config.json"
    cfg = read_json_file(p)
    comp_info, cwarn = None, []
    if company is not None:
        comp, cwarn = load_company(company)
        if isinstance(cfg, dict):
            notes = []
            cfg = merge_config(comp, cfg, notes=notes)
            cwarn += [f"專案的 {n} 和公司共用設定不同，改用公司的值（這個段落以公司為準）" for n in notes]
        comp_info = {"path": str(company), "file": Path(company).name, "sha256": hashlib.sha256(Path(company).read_bytes()).hexdigest()}
    errors, warnings = validate(cfg)
    errors += policy_errors(cfg)
    if errors:
        hint = ""
        if any(e.startswith("manufacturer") and e.endswith("必填") for e in errors):
            hint = ("。製造商（manufacturer.name）通常來自 runner 上的公司共用設定，這次沒有用到公司共用設定："
                    "請找 runner 的管理員（deploy/gitlab-runner/install.sh --company），或在專案的 config.json 寫 manufacturer.name")
        raise Fail(f"{p}{'（合併公司共用設定後）' if comp_info else ''} 不符合 config.schema.json：" + "；".join(errors) + hint)
    return cfg, cwarn + warnings, comp_info


def policy_errors(cfg):
    """vulnerability_policy.tiers 只能有 p1、p2、p3（schema 的 properties 也是；這裡讓錯誤變成 FAIL 而不是 KeyError）。"""
    vp = cfg.get("vulnerability_policy") if isinstance(cfg, dict) else None
    errs = []
    ss = vp.get("severity_sources") if isinstance(vp, dict) else None
    if isinstance(ss, list) and (len(set(map(str, ss))) != len(ss) or "nvd" not in ss or ss[-1] != "nvd"):
        errs.append("vulnerability_policy.severity_sources：不可重複，最後一個要是 nvd（DT／NVD 的值是最後的退路）")
    prod = cfg.get("product") if isinstance(cfg, dict) else None
    pm = prod.get("first_placing_on_market") if isinstance(prod, dict) else None
    if isinstance(pm, str) and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", pm):
        try:
            datetime.date.fromisoformat(pm)
        except ValueError:
            errs.append(f"product.first_placing_on_market：{pm} 不是真的日期")
    tiers = vp.get("tiers") if isinstance(vp, dict) else None
    if not isinstance(tiers, dict):
        return errs                   # 型別錯誤由 validate 報
    return errs + [f"vulnerability_policy.tiers.{t}：只能是 p1、p2、p3" for t in tiers if t not in ("p1", "p2", "p3")]


def report_fields(cfg, schema=SCHEMA, prefix=""):
    """schema 裡的報告欄位 → {點路徑: 值}；缺少或空白的是 Missing。"""
    out = {}
    for k, s in schema.get("properties", {}).items():
        if s.get("x-report") is False:
            continue
        v = cfg.get(k) if isinstance(cfg, dict) else None
        if "properties" in s:
            out.update(report_fields(v or {}, s, f"{prefix}{k}."))
        else:
            out[prefix + k] = v if v not in (None, "", []) else Missing(prefix + k)
    return out


def policy_of(cfg):
    pol = json.loads(json.dumps(SCHEMA["properties"]["vulnerability_policy"]["default"]))
    user = cfg.get("vulnerability_policy") or {}
    pol["status"] = user.get("status", pol["status"])
    for t, v in (user.get("tiers") or {}).items():
        pol["tiers"][t].update(v)
    pol["accepted"].update(user.get("accepted") or {})
    pol["severity_sources"] = list(user.get("severity_sources") or pol["severity_sources"])
    pol["severity_sources_configured"] = bool(user.get("severity_sources"))
    # 分級方式：只有設定檔寫了才放進 pol（沒寫時 summary.json 的 policy 和以前完全一樣）；scheme_of 讀它
    if user.get("scheme"):
        pol["scheme"] = user["scheme"]
    return pol


def scheme_of(pol):
    """分級方式：current（沒寫，現行 tiers 的條件）或 exploitation（依被利用狀態，選用；tier_of、exploitation_section）。"""
    return pol.get("scheme") or "current"


# ---------- 範本 ----------

def template_text(project, name):
    p = project / "CRA" / "templates" / f"{name}.md"
    src = "project" if p.is_file() else "builtin"
    p = p if src == "project" else HERE / "templates" / f"{name}.md"
    return p.read_text(encoding="utf-8"), src, p


def render(text, ctx, name):
    """{{ 點路徑 }} 換成 ctx 的值；陣列輸出成 Markdown 清單。回傳 (文字, 用到的缺少欄位)。"""
    missing, unknown = set(), set()

    def sub(m):
        k = m.group(1)
        if k not in ctx:
            unknown.add(k)
            return ""
        v = ctx[k]
        if isinstance(v, Missing):
            missing.add(v.path)
        if isinstance(v, list):
            return "\n".join(f"- {x}" for x in v)
        return str(v)
    out = PH_RE.sub(sub, text)
    if unknown:
        raise Fail(f"範本 {name} 有不認得的 placeholder：{', '.join(sorted(unknown))}")
    return out, sorted(missing)


def cell(x):
    return str(x).replace("|", "\\|").replace("\n", " ").strip() if x not in (None, "") else "—"


def table(head, rows):
    if not rows:
        return "_None._"
    return "\n".join(["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
                     + ["| " + " | ".join(cell(c) for c in r) + " |" for r in rows])


# ---------- 輸入 ----------

def find(scan, rel):
    for p in (scan / rel, scan / (rel + ".xz")):
        if p.is_file():
            return p
    return None


def open_text(p):
    return lzma.open(p, "rt", encoding="utf-8") if p.suffix == ".xz" else open(p, encoding="utf-8")


def load_json(p):
    if p is None:
        return None
    try:
        with open_text(p) as f:
            return json.load(f)
    except (OSError, ValueError, lzma.LZMAError):
        return None


def stage_line(p, stage):
    """status.tsv 有沒有這個階段的一行（不看值）：None＝沒有；有 → 狀態欄的值，空的寫成 "(no status)"（只有階段名、狀態欄空白）。"""
    if p is None:
        return None
    with open_text(p) as f:
        for line in f:
            parts = line.rstrip("\r\n").split("\t", 2)
            if parts[0] == stage:
                return (parts[1].strip() if len(parts) > 1 else "") or "(no status)"
    return None


def read_status(p):
    if p is None:
        return None
    rows = {}
    with open_text(p) as f:
        for line in f:
            parts = line.rstrip("\r\n").split("\t", 2)
            if len(parts) >= 2 and parts[0] != "stage":
                rows[parts[0]] = (parts[1], parts[2] if len(parts) > 2 else "")
    return rows


def open_bin(p):
    return lzma.open(p, "rb") if p.suffix == ".xz" else open(p, "rb")


def sha256(p):
    """內容的 sha256（.xz 為解壓後的內容，與 Reports 裡的複本一致）。"""
    h = hashlib.sha256()
    with open_bin(p) as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def num(x):
    return float(x) if isinstance(x, (int, float)) and not isinstance(x, bool) else None


def pct_key(p):
    """同機率時比百分位用：沒有百分位（None）排最後；0.0 是有效的值（審查：`or -1` 把 0.0 當成沒有）。"""
    return -1.0 if p is None else p


def dt_epss_invalid(findings):
    """DT finding 裡有寫、但不收的 EPSS 值（epssScore、epssPercentile 各算一個）：超出 0–1、NaN、Infinity、不是數字（unit 回 None）。
    審查 L1：丟掉的值要計數（counts.epss.dt_invalid），不能靜默消失。"""
    n = 0
    for f in findings if isinstance(findings, list) else []:
        v = (f.get("vulnerability") or {}) if isinstance(f, dict) else {}
        if isinstance(v, dict):
            n += sum(1 for k in ("epssScore", "epssPercentile") if v.get(k) is not None and unit(v.get(k)) is None)
    return n


def unit(x):
    """0–1 的有限數字（EPSS 的機率、百分位）；超出範圍、NaN、不是數字 → None（不收，不讓壞資料變成 P1）。"""
    v = num(x)
    return v if v is not None and math.isfinite(v) and 0 <= v <= 1 else None


# ---------- 弱點 ----------

def ids_of(v):
    ids = {v["vulnId"]} if isinstance(v.get("vulnId"), str) and v["vulnId"] else set()
    for a in v.get("aliases") or []:
        if isinstance(a, dict):
            ids |= {x for x in a.values() if isinstance(x, str) and x}
    return ids


def cves_of(ids):
    return {m.group(1) for m in map(CVE_RE.match, ids) if m}


DT_WRITEBACK_RE = re.compile(r"^\[sca-center:vex-writeback state=([a-z_]+) sha=([0-9a-f]{12})\]")   # tools/cra/dt_writeback.py make_detail


def dt_writeback_state(detail):
    """寫回 DT 的 detail 開頭的標記狀態（小寫）；不是以標記開頭、或內容雜湊對不上（有人改過內容）→ None。"""
    d = str(detail or "")
    m = DT_WRITEBACK_RE.match(d)
    if not m or hashlib.sha256(d[m.end():].lstrip(" ").strip().encode("utf-8")).hexdigest()[:12] != m.group(2):
        return None
    return m.group(1)


def analysis_of(f):
    a = f.get("analysis") or {}
    cur = str(a.get("state") or a.get("analysisState") or "").lower()
    if cur and dt_writeback_state(a.get("details") or a.get("analysisDetails") or a.get("detail")) == cur:
        # 這筆分析是我們自己的 VEX 寫回去的（dt_writeback.py），標記的狀態等於 DT 現在的狀態、內容沒被改：不是人在 DT 上做的判定，不採用
        # （否則規則判的 not_affected 下次掃描會被當成 DT 上的人工決定，自己證明自己）。標記在、但狀態或內容被人改過 → 當人工判定。
        return {"state": "", "suppressed": False, "justification": "", "response": "", "details": "", "writeback": True}
    return {"state": str(a.get("state") or a.get("analysisState") or "").upper(), "suppressed": bool(a.get("isSuppressed")),
            "justification": a.get("justification") or a.get("analysisJustification") or "",
            "response": a.get("response") or a.get("analysisResponse") or "",
            "details": a.get("details") or a.get("analysisDetails") or ""}


def merge_readback(findings, readback):
    """dt/analysis.json（tools/e2e/dtread.py readback 的輸出，有的話）：DT 的 findings API 的 analysis 多半只有 state 與
    isSuppressed，readback 有完整的 analysisState／Justification／Response／Details。以（source、vulnId、purl）對回 finding，
    readback 的值優先。對不上的 finding 不變。"""
    if not isinstance(findings, list) or not isinstance(readback, list):
        return findings
    idx = {}
    for x in readback:
        if isinstance(x, dict) and isinstance(x.get("analysis"), dict):
            idx[(x.get("source"), x.get("vuln"), x.get("purl"))] = x["analysis"]
    out = []
    for f in findings:
        if isinstance(f, dict):
            v, c = f.get("vulnerability") or {}, f.get("component") or {}
            ra = idx.get((v.get("source"), v.get("vulnId"), c.get("purl")))
            if ra:
                a = dict(f.get("analysis") or {})
                for k, rk in (("state", "analysisState"), ("justification", "analysisJustification"),
                              ("response", "analysisResponse"), ("details", "analysisDetails"), ("isSuppressed", "isSuppressed")):
                    if ra.get(rk) not in (None, "", "NOT_SET") or k == "isSuppressed" and rk in ra:
                        a[k] = ra[rk]
                f = dict(f, analysis=a)
        out.append(f)
    return out


def drop_self_matches(grype, gate):
    """sbomgate 把「對專案本身、沒有版本」的 Grype 比對移到 excluded_matches（SELF_NO_VERSION）。交叉核對不算它們
    （否則會多出「只有 Grype」的 CVE），但不能讓它們消失：回傳 (剩下的 grype, 被排除的比對清單)，由呼叫端在文件裡揭露。"""
    if not isinstance(grype, dict) or not isinstance(gate, dict):
        return grype, []
    excl = {(x.get("id"), x.get("purl")) for x in gate.get("excluded_matches") or []
            if isinstance(x, dict) and x.get("excluded_reason") == "SELF_NO_VERSION" and not x.get("version")}
    if not excl:
        return grype, []
    keep, dropped = [], []
    for m in grype.get("matches") or []:
        a, v = (m.get("artifact") or {}, m.get("vulnerability") or {}) if isinstance(m, dict) else ({}, {})
        if isinstance(m, dict) and not a.get("version") and (v.get("id"), a.get("purl")) in excl:
            ids = {v.get("id")} | {r.get("id") for r in m.get("relatedVulnerabilities") or [] if isinstance(r, dict)}
            dropped.append({"id": v.get("id"), "cves": sorted(cves_of(ids - {None})), "package": a.get("name") or "?"})
        else:
            keep.append(m)
    return dict(grype, matches=keep), dropped


def plural(n, word, many=None):
    """英文的單複數：1 row、2 rows（many 給不規則的複數）。"""
    return f"{n} {word if n == 1 else (many or word + 's')}"


def verb(n, one, many):
    return one if n == 1 else many


def en(detail):
    """英文文件裡的階段說明：sca-scan 的 status.tsv 說明多半是中文。先去掉全形括號裡的中文補充（常見的寫法），
    剩下是英文就保留（例如 NVD COMPLETED、Built=… Status=valid），否則寫 see scan-status.tsv。"""
    d = re.sub(r" {2,}", " ", re.sub(r"（[^）]*）", " ", str(detail))).strip(" ；;")
    return d if d and d.isascii() else "see scan-status.tsv"


def purl_path(purl):
    """purl 的 namespace/name（解碼）；npm scoped 沒編碼的 @scope/x 也能處理。"""
    if not isinstance(purl, str) or not purl.startswith("pkg:") or "/" not in purl:
        return ""
    body = purl[4:].split("#", 1)[0].split("?", 1)[0].split("/", 1)[1]
    at = body.rfind("@")
    return urllib.parse.unquote(body[:at] if at > 0 else body)


def purl_fullname(purl):
    """purl 的 namespace/name（小寫）：composer 的 league/commonmark、npm 的 @scope/x、maven 的 group/artifact。"""
    return purl_path(purl).lower()


def display_name(c):
    """表格裡的元件名稱：有 namespace 時顯示完整名稱（DT 的 name 只有最後一段，例如 commonmark 看不出是 league/commonmark）。"""
    purl = c.get("purl") or ""
    path = purl_path(purl)
    if re.match(r"^pkg:(deb|rpm|apk|alpm)/", purl) or not path:
        return c.get("name") or "?"                  # 作業系統套件的 namespace 是發行版（ubuntu、debian），不是套件名稱的一部分
    if "/" not in path:
        # pypi 用 purl 的正規化名稱（Pillow 和 pillow 不會各寫各的）；其他保留原本的大小寫（例如 nuget 的 Newtonsoft.Json）
        return path.lower() if purl.startswith("pkg:pypi/") else (c.get("name") or path)
    ns, _, name = path.rpartition("/")
    return f"{ns}:{name}" if purl.startswith("pkg:maven/") else f"{ns}/{name}"


def grype_match_ids(m):
    """一筆 Grype 比對的編號集合（主編號、relatedVulnerabilities，加上從中取出的 CVE）；沒有任何編號 → 空集合。"""
    v = (m.get("vulnerability") or {}) if isinstance(m, dict) else {}
    v = v if isinstance(v, dict) else {}
    ids = {v.get("id")} | {r.get("id") for r in (m.get("relatedVulnerabilities") or [] if isinstance(m, dict) else []) if isinstance(r, dict)}
    ids = {i for i in ids if isinstance(i, str) and i}
    return frozenset(ids | cves_of(ids))


def grype_idsets(grype):
    """每筆 Grype 比對的編號集合（grype_match_ids）。"""
    out = []
    for m in (grype or {}).get("matches") or []:
        if isinstance(m, dict):
            ids = grype_match_ids(m)
            if ids:                                   # 沒有任何編號的比對不能代表任何公告（也避免 min() 空集合）
                out.append(ids)
    return out


def dt_rows_of(rows):
    """交叉核對用的 DT 列：有 NVIDIA 公告以外的來源、而且不是只有 Grype 的列（grype_only_rows 加的）。"""
    return [r for r in rows if not r.get("found_by") and any(not x.startswith("NVIDIA:") for x in r["source_ids"])]


# Grype（Syft）的 artifact.type → purl 類型（沒有 purl 的比對只能和同一個類型、或同樣沒有 purl 的 DT 元件對上）
GRYPE_PTYPE = {"python": "pypi", "deb": "deb", "rpm": "rpm", "apk": "apk", "alpm": "alpm", "npm": "npm", "java-archive": "maven",
               "jenkins-plugin": "maven", "go-module": "golang", "rust-crate": "cargo", "gem": "gem", "php-composer": "composer",
               "dotnet": "nuget", "hex": "hex", "pub": "pub", "conan": "conan", "cocoapods": "cocoapods", "swift": "swift",
               "portage": "ebuild", "binary": "generic"}


def comp_idents(purl, name, version, ptype=None):
    """一個元件的身分 token（比對 DT 的列與 Grype 的比對是不是同一個元件用）：
      - deb：("deb", 套件名稱)：dpkg 同一個名稱只能裝一個版本，不比版本（DT 以原始碼套件比對時版本是原始碼的版本）；另加
        ("debsrc", 原始碼套件)：purl 的 upstream qualifier（Syft 寫的），沒有時就是套件名稱。同一個原始碼套件編出來的二進位套件是同一份
        程式碼（DT 在 bluez、Grype 在 libbluetooth3 上的同一個 CVE 是同一個弱點，修補也是同一個原始碼套件的更新）；
      - 其他有 purl 的：(類型, namespace/名稱（pypi 依 PEP 503、npm 小寫；其他照 purl_split 的小寫）, 版本)：同名不同版本（pip 另裝的、
        vendored 的、兩個版本並存）是不同的元件；
      - 沒有 purl：("name", "", 名稱小寫, 版本)（對沒有 purl 的 DT 元件），ptype（Grype 的 artifact.type，GRYPE_PTYPE）知道時另加
        ("name", purl 類型, 名稱, 版本)（對同一個類型的 DT 元件；不跨生態系：npm 的 foo 1.0 不是 pypi 的 foo 1.0），deb 時再加 ("deb", 名稱)。"""
    out = set()
    base, pv = vexmod().purl_split(purl)
    ver = str(version or pv or "")
    if base:
        typ, _, path = base[4:].partition("/")
        if typ == "deb":
            q = urllib.parse.parse_qs(purl.split("#", 1)[0].partition("?")[2])
            up = urllib.parse.unquote((q.get("upstream") or [""])[0]).split("@", 1)[0].strip().lower()
            out |= {("deb", path.rpartition("/")[2]), ("debsrc", up or path.rpartition("/")[2])}
        else:
            out.add((typ, pep503(path) if typ == "pypi" else path, ver))
    elif isinstance(name, str) and name:
        t = GRYPE_PTYPE.get(str(ptype or "").lower(), "")
        out |= {("name", "", name.lower(), ver)} | ({("name", t, name.lower(), ver)} if t else set())
        if t == "deb":
            out |= {("deb", name.lower()), ("debsrc", name.lower())}
    return out


def row_idents(r, dpy=None):
    """DT 列的身分 token：元件本身（comp_idents，含 deb 的原始碼套件），名稱＋版本（給沒有 purl 的 Grype 比對），DT 以原始碼套件比對時
    安裝的二進位套件（installed_as），對應的核心套件（mapped_from），
    Ubuntu 打包的 Python 模組的擁有者（dpy＝deb_python_index；同一份安裝的程式）。"""
    purl, ver = r.get("purl") or "", r.get("version") or ""
    out = comp_idents(purl, r.get("name"), ver)
    # 名稱＋版本的 token 帶這一列的 purl 類型（沒有 purl 時是 ""）：沒有 purl 的 Grype 比對只對同一個類型（或同樣沒有 purl）的列
    rt = vexmod().purl_type(purl) or ""
    names = {str(r.get("name") or "").lower(), purl_path(purl).rpartition("/")[2].lower(), purl_fullname(purl)} - {""}
    out |= {("name", rt, n, ver) for n in names}
    for b in r.get("installed_as") or []:
        out |= {("deb", str(b).lower()), ("name", "deb", str(b).lower(), ver)}
    if r.get("mapped_from"):
        n, _, v = str(r["mapped_from"]).partition(" ")
        out |= {("deb", n.lower()), ("name", "deb", n.lower(), v)}
    o = ((dpy or {}).get(purl.split("#", 1)[0].split("?", 1)[0]) or {}).get("owner") if purl.startswith("pkg:pypi/") else None
    if o:
        out.add(("deb", str(o["name"]).lower()))
    return out


def match_idents(m, dpy=None):
    """Grype 比對的身分 token：artifact（comp_idents），deb 的 upstreams（("debsrc", 原始碼套件)），Ubuntu 打包的 Python 模組的擁有者。"""
    a = m.get("artifact") if isinstance(m.get("artifact"), dict) else {}
    purl = a.get("purl") if isinstance(a.get("purl"), str) else ""
    out = comp_idents(purl, a.get("name"), a.get("version") if isinstance(a.get("version"), str) else "", a.get("type"))
    if purl.startswith("pkg:deb/") or (not purl and str(a.get("type") or "").lower() == "deb"):
        ups = {str(u["name"]).lower() for u in a.get("upstreams") or [] if isinstance(u, dict) and isinstance(u.get("name"), str)}
        out |= {("debsrc", u) for u in ups}
    o = ((dpy or {}).get(purl.split("#", 1)[0].split("?", 1)[0]) or {}).get("owner") if purl.startswith("pkg:pypi/") else None
    if o:
        out.add(("deb", str(o["name"]).lower()))
    return out


def grype_coverage(grype, dt_rows, dpy=None, exposed=None):
    """交叉核對的對應（每個元件分開比）：一筆 Grype 比對和一列 DT 列對上＝兩邊有共同的編號（主編號、relatedVulnerabilities、其中的 CVE，
    不分大小寫；Grype 對 composer 等生態系常只給 GHSA，DT 的同一個弱點是 CVE＋GHSA 別名，算對上）**而且**是同一個元件（match_idents 與
    row_idents 有共同的 token）。同一個 CVE 在別的元件上（例如 deb 的 python3-urllib3 與 pip 另裝的 urllib3、vendored 的副本、
    同一個套件的另一個版本）不算對上。
    只經過原始碼套件（("debsrc", …)）對上的 deb 比對（例如 DT 在 isc-dhcp-client、Grype 在 isc-dhcp-server 上，兩個都是 isc-dhcp 編的）：
    版本和 DT 列相同、而且這個二進位套件不對外時算對上，Grype 的這個二進位套件只寫在那一列的元件欄（grype_binaries，attach；不給
    VEX 的 affects、不算對外，沒有人評估過它）；**對外**（exposed(二進位套件) 是真，對外服務清單上有它，例如 isc-dhcp-server）或版本不同時
    不算對上，自成一列只有 Grype 的列（沒有沿用的判定；DT 在 client 上的 NOT_AFFECTED 不變成對外 server 的 not_affected）。
    回傳 (沒有對上的比對 [(比對, 編號集合)]（檔案順序；沒有編號的比對不算）, 沒有對上的 DT 列, [(DT 列, {name, version, purl})])。"""
    by_id = {}
    for r in dt_rows:
        t = row_idents(r, dpy)
        for i in r["all_ids"]:
            by_id.setdefault(str(i).upper(), []).append((r, t))
    out, hit, attach = [], set(), []
    for m in (grype or {}).get("matches") or [] if isinstance(grype, dict) else []:
        ids = grype_match_ids(m) if isinstance(m, dict) else frozenset()
        if not ids:
            continue
        mt = match_idents(m, dpy)
        hits = {}
        for i in {x.upper() for x in ids}:
            for r, t in by_id.get(i, ()):
                if t & mt:
                    hits.setdefault(id(r), (r, set()))[1].update(t & mt)
        if any(any(k[0] != "debsrc" for k in common) for _, common in hits.values()):
            hit.update(hits)
            continue
        a = m.get("artifact") if isinstance(m.get("artifact"), dict) else {}
        aver = a.get("version") if isinstance(a.get("version"), str) else ""
        same = [r for r, _ in hits.values() if str(r.get("version") or "") == aver]
        b = {"name": str(a.get("name") or purl_path(a.get("purl")).rpartition("/")[2]), "version": aver,
             "purl": a.get("purl") if isinstance(a.get("purl"), str) else ""}
        # 同一個原始碼套件、同一個版本：DT 那幾列在 Grype 有對應（交叉核對不算「DT 列沒有對應」），不論這個二進位套件是否對外另成一列
        hit.update(id(r) for r in same)
        if not same or (exposed is not None and exposed(b)):
            out.append((m, ids))         # 沒有對上、只有同一個原始碼套件但版本不同、或這個二進位套件對外：自成一列
            continue
        attach += [(r, b) for r in same]
    return out, [r for r in dt_rows if id(r) not in hit], attach


def grype_uncovered(grype, dt_rows, dpy=None, exposed=None):
    """grype_coverage 的「DT 沒有」的比對。"""
    return grype_coverage(grype, dt_rows, dpy, exposed)[0]


def binary_exposed(services):
    """grype_coverage 的 exposed：一個 Grype 二進位套件（{name, version, purl}）在對外服務清單上（exposed_hits，和其他列同一個比法）。
    沒有清單（current 分級方式不用清單）→ None（不判斷）。"""
    if not services:
        return None
    return lambda b: bool(exposed_hits({"purl": b["purl"], "name": b["name"]}, services))


def attach_grype_binaries(attach):
    """grype_coverage 的 attach：只經過原始碼套件對上的 Grype 二進位套件記在 DT 列的 grype_binaries（依名稱排序、不重複；這一列自己的名稱
    或 installed_as 已有的不記）。只有有這種套件的列才有這個鍵（其他 DT 列不變）。"""
    for r, b in attach:
        own = {str(r.get("name") or "").lower(), purl_path(r.get("purl") or "").rpartition("/")[2].lower()} | \
              {str(x).lower() for x in r.get("installed_as") or []}
        if b["name"].lower() in own:
            continue
        cur = r.setdefault("grype_binaries", [])
        if not any((x["name"], x["version"], x["purl"]) == (b["name"], b["version"], b["purl"]) for x in cur):
            cur.append(b)
            cur.sort(key=lambda x: (x["name"], x["version"], x["purl"]))


def grype_version_unknown(gate):
    """scan/sbomgate.json 的 excluded_matches 中版本未知的元件（VERSION_FROM_RANGE、NO_VERSION、UNIDENTIFIABLE；不含 SELF_NO_VERSION，
    那些由 drop_self_matches 處理）→ {(編號大寫, purl 或名稱): 原因}。專案規則 13：版本來自範圍下限或不知道的元件不做弱點比對。"""
    out = {}
    for x in (gate.get("excluded_matches") or []) if isinstance(gate, dict) else []:
        if isinstance(x, dict) and isinstance(x.get("id"), str) and x.get("excluded_reason") not in (None, "SELF_NO_VERSION"):
            out[(x["id"].upper(), x.get("purl") or x.get("package") or "")] = str(x["excluded_reason"])
    return out


def grype_index(grype):
    """{(ID, 套件名小寫, 版本): (fix 狀態集合, fix 版本集合)} 與 Grype 的 CVE 集合（含 relatedVulnerabilities）。"""
    idx, cves = {}, set()
    for m in (grype or {}).get("matches") or []:
        if not isinstance(m, dict):
            continue
        v, a = m.get("vulnerability") or {}, m.get("artifact") or {}
        ids = {v.get("id")} | {r.get("id") for r in m.get("relatedVulnerabilities") or [] if isinstance(r, dict)}
        ids.discard(None)
        cves |= cves_of(ids)
        fix = v.get("fix") or {}
        # 用名稱和 purl 的完整名稱都建索引：DT 的元件名稱只有最後一段（commonmark），Grype 是 league/commonmark
        names = {(a.get("name") or "").lower(), purl_fullname(a.get("purl"))} - {""}
        for i in ids:
            for n in names:
                st, vers = idx.setdefault((i, n, a.get("version") or ""), (set(), set()))
                if fix.get("state"):
                    st.add(fix["state"])
                vers.update(x for x in fix.get("versions") or [] if isinstance(x, str))
    return idx, cves


def grype_kev(grype):
    """Grype 標為 KEV 的 CVE（vulnerability.knownExploited，Grype DB 的 CISA KEV）。每筆比對取 knownExploited 條目自己的 cve；
    條目沒寫時取比對的主編號（CVE-…、UBUNTU-CVE-…）的 CVE，再沒有才取 relatedVulnerabilities 的 CVE。"""
    return set(grype_kev_map(grype))


def grype_kev_map(grype):
    """grype_kev 的 CVE → 標 KEV 的比對的非 CVE 主編號（例如 GHSA-…）集合。DT 那一列只有 GHSA、沒有 CVE 別名時，以這個編號對到那一列。"""
    out = {}
    for m in (grype or {}).get("matches") or []:
        v = (m.get("vulnerability") or {}) if isinstance(m, dict) else {}
        ke = v.get("knownExploited") if isinstance(v, dict) else None
        if not ke:
            continue
        own = cves_of({e["cve"] for e in ke if isinstance(e, dict) and isinstance(e.get("cve"), str)} if isinstance(ke, list) else set())
        own = own or cves_of({v["id"]} if isinstance(v.get("id"), str) else set())
        own = own or cves_of({r.get("id") for r in m.get("relatedVulnerabilities") or [] if isinstance(r, dict) and isinstance(r.get("id"), str)})
        mid = {v["id"].upper()} if isinstance(v.get("id"), str) and not cves_of({v["id"]}) else set()
        for c in own:
            out.setdefault(c, set()).update(mid)
    return out


def grype_epss(grype):
    """Grype 的 EPSS（vulnerability.epss：[{cve, epss, percentile, date}]，Grype DB 建置時的分數）→ {CVE: {probability, percentile, date}}；
    同一個 CVE 有多筆時取機率最高的。機率或百分位不是 0–1 的數字就不收。"""
    out = {}
    for m in (grype or {}).get("matches") or []:
        v = (m.get("vulnerability") or {}) if isinstance(m, dict) else {}
        for e in (v.get("epss") if isinstance(v, dict) and isinstance(v.get("epss"), list) else []):
            cs = cves_of({e["cve"]}) if isinstance(e, dict) and isinstance(e.get("cve"), str) else set()
            pr, pc = (num(e.get("epss")), num(e.get("percentile"))) if cs else (None, None)
            if len(cs) != 1 or pr is None or not 0 <= pr <= 1 or (pc is not None and not 0 <= pc <= 1):
                continue
            c = next(iter(cs))
            if c not in out or pr > out[c]["probability"]:
                out[c] = {"probability": pr, "percentile": pc, "date": str(e.get("date") or "")[:10] or None}
    return out


def deb_source_map(deb_sources):
    """dt/deb-sources.json（tools/pilot/lib/deb_sources.py）→ {原始碼套件 purl: 二進位套件名稱清單}。"""
    out = {}
    added = deb_sources.get("added") if isinstance(deb_sources, dict) else None
    for x in added or []:
        if isinstance(x, dict) and isinstance(x.get("purl"), str):
            out[x["purl"].split("?", 1)[0]] = [b.strip() for b in str(x.get("binaries") or "").split(",") if b.strip()]
    return out


USN_RE = re.compile(r"^USN-\d+-\d+$")
CVE_ONLY = re.compile(r"^CVE-\d{4}-\d{4,}$")


def usn_map(doc):
    """scan/usn-cves.json（tools/pilot/lib/usn_cves.py）→ {USN 編號: [CVE]}；status 不是 OK、格式不對 → None（不併，照舊）。
    只收 USN-數字-數字 的鍵與 CVE-年-編號 的值（鏡像資料不可信，只解析）。"""
    if not isinstance(doc, dict) or doc.get("status") != "OK" or not isinstance(doc.get("usns"), dict):
        return None
    out = {}
    for k, x in doc["usns"].items():
        cves = x.get("cves") if isinstance(x, dict) else None
        if isinstance(k, str) and USN_RE.match(k.upper()) and isinstance(cves, list):
            ok = sorted({c.upper() for c in cves if isinstance(c, str) and CVE_ONLY.match(c.upper())})
            if ok:
                out[k.upper()] = ok
    return out


def usn_without_cve(findings):
    """沒有 CVE 別名的 USN finding 的編號（OSV 來源；usn-cves.json 要對應的就是這些）。"""
    out = set()
    for f in findings if isinstance(findings, list) else []:
        v = (f.get("vulnerability") or {}) if isinstance(f, dict) else {}
        vid = str(v.get("vulnId") or "").upper()
        if USN_RE.match(vid) and not cves_of(ids_of(v)):
            out.add(vid)
    return out


# Debian／Ubuntu 打包的 Python 模組裝在這裡（pip 裝在 /usr/local/lib/python3.*/dist-packages 或 venv）
DEB_PY_DIR = re.compile(r"^/?usr/lib/python3(?:\.\d+)?/dist-packages/")


def pep503(name):
    return re.sub(r"[-_.]+", "-", str(name or "")).lower()


LOC_PATH = re.compile(r"^syft:location:\d+:path$")


def location_paths(c):
    """Syft 的 CycloneDX 屬性 syft:location:N:path（套件中繼資料檔的位置）。"""
    return [p["value"] for p in c.get("properties") or []
            if isinstance(p, dict) and LOC_PATH.match(str(p.get("name") or "")) and isinstance(p.get("value"), str)]


def deb_python_index(comps, pyres=None):
    """SBOM → {pypi purl（不含 qualifiers）: 擁有它的 deb 套件}，只收所有位置（syft:location:N:path）都在 DEB_PY_DIR 的 pypi 元件。
    同一個 purl 也有不在那裡的元件（例如 pip 另裝了一份）→ 不算（照舊當 pip 套件），記在 mixed。
    擁有者用名稱對（Syft 的 CycloneDX 沒有 dpkg 的檔案清單）：先找二進位套件 python3-<PEP 503 名稱>，沒有時找 purl 的 upstream
    （原始碼套件）是 <名稱>、python-<名稱> 或 python3-<名稱> 的 python3-* 套件；剛好一個才算，多個記 candidates（不猜），沒有記 None。
    多個候選都來自同一個原始碼套件、同一個版本時另記 source_owner（名稱最短的當代表；owner 照舊是 None）。
    版本也要對得上（version_matches；pypi 版本是 0.0.0 或空的不比）：名稱對到的套件版本都不同（例如有人用 pip 把 requests 2.32.3
    裝進 /usr/lib/python3/dist-packages，旁邊是 python3-requests 2.31.0+dfsg-1ubuntu1）→ 不是那個 deb 裝的，照舊當 pip 套件，記在 version_mismatch。
    pyres（py_dpkg_version.by_path：tools/cra/py_dpkg_version.py 從映像讀出的結果，{metadata 檔路徑: 判定}）：pypi 版本是佔位值（0.0.0…）時，
    以 dpkg 的 .list 找到的擁有者為準（RESOLVED：擁有者＝那個 deb 套件，真正的版本＝它的上游版本）；DISAGREE（與 __version__ 不同）、
    NOT_OWNED 不改擁有者的判斷，只在 version_resolution 記下結果（版本仍然未知）。
    回傳 ({purl: {path, owner, candidates, version_resolution}}, {"mixed": [purl], "version_mismatch": [purl]})。"""
    debs, py = [], {}
    for c in comps:
        purl = c.get("purl") if isinstance(c, dict) else None
        if not isinstance(purl, str):
            continue
        base = purl.split("#", 1)[0].split("?", 1)[0]
        if purl.startswith("pkg:deb/"):
            q = urllib.parse.parse_qs(purl.split("#", 1)[0].partition("?")[2])
            up = urllib.parse.unquote((q.get("upstream") or [""])[0]).split("@", 1)[0].lower()
            name = purl_path(purl).rpartition("/")[2].lower()
            ver = c.get("version") or urllib.parse.unquote(base.rpartition("@")[2])
            debs.append({"name": name, "version": ver, "source": up or name, "purl": purl})
        elif purl.startswith("pkg:pypi/"):
            py.setdefault(base, []).append(location_paths(c))
    out, mixed, mismatch = {}, [], []
    for base, copies in sorted(py.items()):
        deb_paths = [p for ps in copies for p in ps if DEB_PY_DIR.match(p)]
        if not deb_paths:
            continue
        if any(not ps or not all(DEB_PY_DIR.match(p) for p in ps) for ps in copies):
            mixed.append(base)
            continue
        n = pep503(purl_path(base))
        exact = [d for d in debs if d["name"] == f"python3-{n}"]
        by_src = [d for d in debs if d["name"].startswith("python3-") and d["source"] in (n, f"python-{n}", f"python3-{n}")]
        cands = exact or by_src
        pyver = urllib.parse.unquote(base.rpartition("@")[2]) if "@" in base else ""
        vres = next((pyres[x] for ps in copies for x in ps if x in (pyres or {})), None)
        if vres and vres.get("state") == "RESOLVED":
            # dpkg 的 .list 說這個 metadata 檔屬於這個 deb 套件：擁有者以檔案所有權為準（不靠名稱），版本是它的上游版本
            dn, dv = vres["dpkg"]["name"], vres["dpkg"]["version"]
            own = next((d for d in debs if d["name"] == dn and d["version"] == dv), None) or \
                {"name": dn, "version": dv, "source": dn, "purl": None}
            out[base] = {"path": sorted(deb_paths)[0], "owner": own, "candidates": [], "version_resolution": vres}
            if vres.get("version") and vres["version"] != pyver:
                # 比對與上傳 DT 用的是改過版本的 SBOM（sca-scan C-pyver）：DT／Grype 的列 purl 帶真正的版本，這裡的 SBOM 是原始的（佔位值）→ 兩個 purl 都指向同一個擁有者
                out[(base.rpartition("@")[0] if "@" in base else base) + "@" + vres["version"]] = out[base]
            continue
        if cands and not any(version_matches(pyver, d["version"]) for d in cands):
            mismatch.append(base)
            continue
        uniq = {(d["name"], d["version"]): d for d in cands if version_matches(pyver, d["version"])}
        out[base] = {"path": sorted(deb_paths)[0], "owner": next(iter(uniq.values())) if len(uniq) == 1 else None,
                     "candidates": sorted(f"{a} {b}" for a, b in uniq) if len(uniq) > 1 else [], "version_resolution": vres}
        if len(uniq) > 1 and len({(d["source"], d["version"]) for d in uniq.values()}) == 1:
            # 候選都來自同一個原始碼套件、同一個版本（例如 pillow 的 python3-pil 與 python3-pil.imagetk）：source_owner＝名稱最短的
            # （同長度依名稱排序）。只用在 Ubuntu 的修補狀態與批次規則（source_owner_fix、vex_export.deb_python_rules）；
            # owner 照舊是 None：嚴重度、層級、人工判定的沿用、修補欄都和擁有者不明時一樣。原始碼套件或版本不同 → 沒有 source_owner
            out[base]["source_owner"] = min(uniq.values(), key=lambda d: (len(d["name"]), d["name"]))
    return out, {"mixed": mixed, "version_mismatch": mismatch}


_PYV = None


def pyver_mod():
    """tools/cra/py_dpkg_version.py（python3 -I 不會把這個資料夾放進 sys.path，所以依路徑載入）。"""
    global _PYV
    if _PYV is None:
        spec = importlib.util.spec_from_file_location("sca_center_py_dpkg_version", HERE / "py_dpkg_version.py")
        _PYV = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(_PYV)
    return _PYV


def deb_upstream_version(v):
    """deb 版本 → 上游版本（小寫）：去掉 epoch、Debian revision，與 +dfsg／+ds／+repack／~ 之後的部分。"""
    v = str(v or "")
    if re.match(r"^\d+:", v):
        v = v.split(":", 1)[1]
    if "-" in v:
        v = v.rpartition("-")[0]
    return re.split(r"[+~]", v, 1)[0].lower()


def version_matches(pyver, debver):
    """pypi 元件的版本和 deb 的上游版本相同（結尾的 .0 不計）；pypi 版本是 0.0.0 或空的（Debian 的 egg-info 常見）→ 不比，算相同。"""
    if pyver in ("", "0.0.0"):
        return True
    trim = lambda x: re.sub(r"(?:\.0)+$", "", x)    # noqa: E731
    return trim(pyver.lower()) == trim(deb_upstream_version(debver))


def owner_fix(r, o, debrows, gidx, have_grype):
    """擁有者 o 的 Ubuntu 修補狀態：同一個 CVE 在擁有它的套件（二進位或原始碼套件，或從那個原始碼安裝成它）上的列，否則 Grype 對 o 的結果。
    → (狀態, 修補版本, 那一列的說明或 None)。"""
    names = {o["name"], o["source"]}
    ids = set(r["cves"]) or {r["id"]}
    hit = sorted((d for d in debrows if (set(d["cves"]) or {d["id"]}) & ids
                  and ((d.get("name") or "").lower() in names or o["name"] in [b.lower() for b in d.get("installed_as") or []])),
                 key=lambda d: (d["version"] not in (o["version"],), d["id"], d["component"], d["version"]))
    if hit:
        d = hit[0]
        return d["fix_state"], list(d["fix_versions"]), f"{d['id']} on {d['component']} {d['version']}"
    gs, gv = fix_lookup(ids | set(r["all_ids"]), [o["name"]], o["version"], gidx)
    return fix_state(gs, gv, have_grype), sorted(gv), None


def apply_deb_python(rows, dpy, gidx, have_grype):
    """Debian／Ubuntu 打包的 Python 模組（deb_python_index）的列：不是 pip 管理的，修補要靠更新 Ubuntu 套件。列不刪；
    加上 row["deb_python"]（位置、擁有的 deb 套件與版本），修補欄改指向 Ubuntu 套件：同一個 CVE 在擁有它的套件（二進位或原始碼套件，
    或從那個原始碼安裝成它）上有列時用那一列的 Grype 修補狀態並註明那一列，否則以擁有的 deb 套件查 Grype（Ubuntu 的資料）；
    PyPI 的修補版本只註明「不適用」。找不到擁有者（或不只一個）時 PyPI 的修補資料照留，只註明位置與擁有者不明，不說「不是 pip」。
    pypi 的版本是 0.0.0 或空的（Debian 的 egg-info 常見）時，版本欄改顯示 deb 的版本。
    VEX 的批次規則不以 pypi 套用在這些列（vex_export.apply_rules：excluded_deb_python），改由 vex_export.deb_python_rules 沿用擁有它的
    deb 列的規則判定或以擁有者套用。回傳改了的列。"""
    done = []
    debrows = [r for r in rows if r["ptype"] == "deb"]
    for r in rows:
        x = dpy.get((r.get("purl") or "").split("#", 1)[0].split("?", 1)[0]) if r["ptype"] == "pypi" else None
        if not x:
            continue
        o = x["owner"]
        upstream = r["fix_versions"] if r["fix_state"] == "fixed" else []
        info = {"path": x["path"], "owner": o, "candidates": x["candidates"], "row": None, "pypi_fix": upstream,
                "version_resolution": x.get("version_resolution")}
        so = x.get("source_owner") if not o else None
        if so:
            # 候選都來自同一個原始碼套件：Ubuntu 的修補狀態只記在 deb_python（批次規則用，vex_export.deb_python_rules），這一列的欄位照舊
            st, vers, row = owner_fix(r, so, debrows, gidx, have_grype)
            info["source_owner"] = so
            info["source_owner_fix"] = {"fix_state": st, "fix_versions": vers, "row": row,
                                        "fix_next": next_fix({"fix_state": st, "fix_versions": vers, "ptype": "deb", "version": so["version"]})}
        if o:
            st, vers, info["row"] = owner_fix(r, o, debrows, gidx, have_grype)
            r["fix_state"], r["fix_versions"] = st, vers
            r["fix_next"] = next_fix({"fix_state": st, "fix_versions": vers, "ptype": "deb", "version": o["version"]})
            ufix = ("; fixed in " + ", ".join(vers)) if st == "fixed" and vers else f"; Ubuntu fix state: {st}"
            r["fix"] = (f"update the Ubuntu package {o['name']} (installed {o['version']}), not pip{ufix}"
                        + (f" (row {info['row']})" if info["row"] else " (Grype on the deb package)" if st != "no Grype data" else ""))
        else:
            # 擁有者不明：PyPI 的修補資料照留（不知道它是不是 deb 裝的），只註明位置與擁有者不明
            r["fix"] += (f"; installed in {x['path'].rsplit('/dist-packages/', 1)[0]}/dist-packages (normally by a distribution package), "
                         "owning deb package " + (f"ambiguous ({', '.join(x['candidates'])})" if x["candidates"] else "not found in the SBOM")
                         + ": check which package installed it before following the PyPI fix")
        if upstream and o:
            r["fix"] += f"; the PyPI fix {', '.join(upstream)} does not apply to the distribution package"
        r["deb_python"] = info
        done.append(r)
    return done


def kernel_map_index(kmap):
    """scan/l4t-kernel-map.json（tools/pilot/lib/l4t_kernel.py）→ {對應的核心元件 purl（不含 qualifiers）: 原本的 nvidia-l4t-kernel 名稱與版本}。"""
    if not isinstance(kmap, dict) or kmap.get("status") != "OK":
        return {}
    c = (kmap.get("map_entry") or {}).get("component")
    k = (kmap.get("l4t_kernel") or [None])[0]
    if not isinstance(c, dict) or not isinstance(c.get("purl"), str) or not isinstance(k, dict):
        return {}
    return {c["purl"].split("?", 1)[0]: f"{k.get('name')} {k.get('version')}"}


def kernel_map_info(kmap):
    """C-kernel-l4t-map 的摘要 → 對應的 Canonical 核心 {purl（不含 qualifiers）, name, version, release, l4t}；沒有對應時 None。"""
    if not kernel_map_index(kmap):
        return None
    c, k = kmap["map_entry"]["component"], kmap["l4t_kernel"][0]
    base = c["purl"].split("?", 1)[0]
    return {"purl": base, "name": c.get("name") or "", "version": c.get("version") or urllib.parse.unquote(base.rpartition("@")[2]),
            "release": kmap.get("release") or NR, "l4t": f"{k.get('name')} {k.get('version')}"}


_KC = None


def kernelcheck():
    """作業系統核心的判斷沿用 tools/pilot/lib/kernelcheck.py（sca-scan 的 C-kernel-coverage 用的同一份規則，只用標準函式庫）。
    python3 -I 不會把那個資料夾放進 sys.path，所以依路徑載入；找不到 → FAIL（安裝不完整，不能把核心的列混進主清單）。"""
    global _KC
    if _KC is None:
        p = ROOT / "tools" / "pilot" / "lib" / "kernelcheck.py"
        try:
            spec = importlib.util.spec_from_file_location("sca_center_kernelcheck", p)
            m = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(m)
        except Exception as e:     # 找不到、語法錯誤、載入時丟出的任何錯誤：FAIL，不印 traceback
            raise Fail(f"無法載入 {p}（核心的判斷規則；{type(e).__name__}）")
        _KC = m
    return _KC


_VEX = None
_RT = None
_SG = None


def sbomgatemod():
    """tools/sbomgate/sbomgate.py（規則 13 的元件分類 classify_component；sca-scan 的 C-sbomgate 用的同一份規則），依路徑載入；
    找不到 → FAIL。只在掃描輸出沒有可讀的 scan/sbomgate.json 時用（sbom_version_unknown）。"""
    global _SG
    if _SG is None:
        p = ROOT / "tools" / "sbomgate" / "sbomgate.py"
        try:
            spec = importlib.util.spec_from_file_location("sca_center_sbomgate", p)
            m = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(m)
        except Exception as e:
            raise Fail(f"無法載入 {p}（規則 13 的元件分類；{type(e).__name__}）")
        _SG = m
    return _SG


def sbom_version_unknown(pkgs):
    """沒有可讀的 scan/sbomgate.json 時的規則 13 退路：SBOM 元件以 sbomgate 的 classify_component 分類（cdxgen 的
    cdx:pypi:versionSpecifiers 而沒有實際解析的證據、版本字串像範圍、沒有版本…）→ {purl: 分類}（RESOLVED 以外；沒有 purl 的不收）。"""
    sg = sbomgatemod()
    out = {}
    for c in pkgs:
        if isinstance(c, dict) and isinstance(c.get("purl"), str) and c["purl"]:
            cls = sg.classify_component(c)[0]
            if cls != "RESOLVED":
                out[c["purl"]] = cls
    return out


def rtmod():
    """tools/cra/runtime_evidence.py（板子執行中使用的證據；只加欄位）。載入失敗回傳 None（欄位寫 not measured，不擋文件）。"""
    global _RT
    if _RT is None:
        p = HERE / "runtime_evidence.py"
        try:
            spec = importlib.util.spec_from_file_location("sca_center_runtime_evidence", p)
            m = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(m)
        except Exception:      # noqa: BLE001 — 附加證據，不能擋住其他文件
            return None
        _RT = m
    return _RT


_NVDIST = None
NVD_OPTS = {}        # main() 填入：grype_db（--grype-db）、rootfs（--rootfs-dir）；其他呼叫端不給 → 用環境變數、不查檔案


def nvdistro_mod():
    """tools/cra/nvidia_distro.py（NVIDIA 公告 CVE 的發行版套件判斷；依路徑載入，理由同 vexmod）。"""
    global _NVDIST
    if _NVDIST is None:
        p = HERE / "nvidia_distro.py"
        try:
            spec = importlib.util.spec_from_file_location("sca_center_nvidia_distro", p)
            m = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(m)
        except Exception as e:
            raise Fail(f"無法載入 {p}（NVIDIA 公告的發行版套件判斷；{type(e).__name__}）")
        _NVDIST = m
    return _NVDIST


def vexmod():
    """tools/cra/vex_export.py（VEX 與發行閘門；python3 -I 不會把這個資料夾放進 sys.path，所以依路徑載入）。"""
    global _VEX
    if _VEX is None:
        p = HERE / "vex_export.py"
        try:
            spec = importlib.util.spec_from_file_location("sca_center_vex_export", p)
            m = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(m)
        except Exception as e:
            raise Fail(f"無法載入 {p}（VEX 匯出；{type(e).__name__}）")
        _VEX = m
    return _VEX


_SEC = None
_FW = None


def fwmod():
    """tools/cra/firmware_bom.py（刷機包韌體併進 SBOM、BSI TR-03183-2 覆蓋率；同 vexmod 依路徑載入）。"""
    global _FW
    if _FW is None:
        p = HERE / "firmware_bom.py"
        try:
            spec = importlib.util.spec_from_file_location("sca_center_firmware_bom", p)
            m = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(m)
        except Exception as e:
            raise Fail(f"無法載入 {p}（韌體 SBOM；{type(e).__name__}）")
        _FW = m
    return _FW


def flash_firmware(scan, cfg, spec, inventory=None):
    """刷機包掃描（<結果>/<rootfs>/scan，結果資料夾有 list.json）→ firmware_bom.build() 的 (元件, 依賴, 頂層, info)；
    不是刷機包的掃描 → (None, None, None, {"absent": 說明})。inventory：--flash-inventory（預設 <結果>/flash-inventory.json）。"""
    fw = fwmod()
    res = Path(inventory).parent if inventory else scan.parent.parent
    inv_p, list_p = Path(inventory) if inventory else res / "flash-inventory.json", res / "list.json"
    lst = load_json(list_p)
    if not inventory and not (isinstance(lst, dict) and isinstance(lst.get("rootfs"), list)):
        return None, None, None, {"absent": "Not a flash package scan (no flash package `list.json` next to the scan result): "
                                  "no flash firmware was added.", "flash_package": False}
    variant, prefix = scan.parent.name, None
    rt = load_json(scan.parent / "rootfs-tar.json")
    if isinstance(rt, dict) and isinstance(rt.get("prefix"), str):
        prefix = rt["prefix"]
    inv = load_json(inv_p)
    if not isinstance(inv, dict):
        why = "missing" if not inv_p.exists() else "not readable"
        return None, None, None, {"absent": f"**Flash firmware missing from the SBOM:** the flash package inventory (`{inv_p.name}`) is {why}. "
                                  "Boot and flash firmware, the Jetson Linux release, NVIDIA kernel modules and MCU firmware are not in "
                                  "the product SBOM.", "flash_package": True, "status": "ATTENTION"}
    try:     # 清點檔是不可信資料：格式怪異時不讓整份 CRA 文件失敗
        comps, deps, top, info = fw.build(inv, lst if isinstance(lst, dict) else None, variant, prefix,
                                          (cfg.get("sbom") or {}).get("flash_package_supplier"), spec,
                                          (cfg.get("sbom") or {}).get("deliverable_firmware") or ())
    except Exception as e:      # noqa: BLE001
        return None, None, None, {"absent": f"**Flash firmware missing from the SBOM:** `{inv_p.name}` could not be processed "
                                  f"({type(e).__name__}).", "flash_package": True, "status": "ATTENTION"}
    info["flash_package"] = True
    info["status"] = "OK" if comps and not info["notes"] else "ATTENTION"
    return comps, deps, top, info


_OWN = None


def ownmod():
    """tools/cra/own_software.py（產品自有軟體併進 SBOM；同 vexmod 依路徑載入）。"""
    global _OWN
    if _OWN is None:
        p = HERE / "own_software.py"
        try:
            spec = importlib.util.spec_from_file_location("sca_center_own_software", p)
            m = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(m)
        except Exception as e:
            raise Fail(f"無法載入 {p}（自有軟體 SBOM；{type(e).__name__}）")
        _OWN = m
    return _OWN


_BOOT = None


UPSTREAM_BASELINE_STEMS = ("upstream-baseline-artifacts", "upstream-baseline-source")


def upstream_baseline_line(stem, doc):
    """upstream_baseline.py 輸出 json 的一行中文說明（內部用；不寫「安全」，GAP／ATTENTION 照實寫）。
    只有「閉源韌體相同數 > 0、其他類別都是 0」才寫「相同」；其餘照 json 的 detail。附上比對的路徑與時間。"""
    st = doc.get("status")
    m = re.search(r"R?(\d+\.\d+\.\d+)", str((doc.get("upstream") or {}).get("file_name") or ""))
    ver = f"NVIDIA r{m.group(1)} 原版" if m else "NVIDIA 原版"
    where = f"（ours：{(doc.get('ours') or {}).get('path')}；NVIDIA：{(doc.get('upstream') or {}).get('path')}；{doc.get('generated')}）"
    if stem.endswith("artifacts"):
        cf = (doc.get("closed_firmware") or {}).get("counts") or {}
        clean = (st == "OK" and cf.get("same", 0) > 0 and not any(cf.get(k, 0) for k in ("modified", "ours_only", "upstream_only"))
                 and not (doc.get("closed_firmware") or {}).get("rejected_names"))
        if clean:
            return f"NVIDIA 閉源開機韌體 {cf['same']} 個檔案與 {ver}相同" + where
        if st == "ATTENTION":
            return f"與 {ver}的成品比對有需要 RD 判斷的項目：{doc.get('detail', '')}" + where
        return f"與 {ver}的成品比對未完成或無法確認（{st}）：{doc.get('detail', '')}" + where
    t = doc.get("totals") or {}
    if st in ("OK", "ATTENTION"):
        return (f"原始碼與 {ver}逐檔比對：相同 {t.get('same', 0)}、RD 改過 {t.get('modified', 0)}、只有我們有 {t.get('ours_only', 0)}"
                f"（{doc.get('detail', '')}）" + where)
    return f"原始碼與 {ver}的比對未完成（{st}）：{doc.get('detail', '')}" + where


def same_flash_package(scan, doc):
    """artifacts 的 json 是不是這份掃描的刷機包：scan/provenance.json 的 source.file／sha256 對 json 的 ours。
    回傳 True／False／None（None＝無法確認，例如 ours 是資料夾或沒有 provenance.json）。"""
    prov = load_json(scan / "provenance.json")
    src = (prov or {}).get("source") if isinstance(prov, dict) else None
    ours = doc.get("ours") or {}
    if not isinstance(src, dict) or ours.get("type") != "archive":
        return None
    if src.get("sha256") and ours.get("sha256"):
        return src["sha256"] == ours["sha256"]
    if src.get("file") and ours.get("file_name"):
        return src["file"] == ours["file_name"]
    return None


def copy_upstream_baseline(scan, out):
    """<scan>/../upstream-baseline-{artifacts,source}.{json,md}（upstream_baseline.py 的輸出，選用）複製進輸出資料夾，
    之後 report_package 會把它們放進內部存檔。沒有的檔案不留舊的複本。
    artifacts 的 json 指的不是這份掃描的刷機包時不複製（記 mismatch）。回傳 {stem: {status, line, same_package}}。"""
    info = {}
    for stem in UPSTREAM_BASELINE_STEMS:
        doc = load_json(scan.parent / f"{stem}.json")
        ok = isinstance(doc, dict) and doc.get("tool") == "upstream_baseline"
        same = same_flash_package(scan, doc) if ok and stem.endswith("artifacts") else None
        use = ok and same is not False
        for ext in ("json", "md"):
            src, dst = scan.parent / f"{stem}.{ext}", out / f"{stem}.{ext}"
            if use and src.is_file() and not src.is_symlink():
                shutil.copyfile(src, dst)
            else:
                dst.unlink(missing_ok=True)
        if use:
            info[stem.rsplit("-", 1)[1]] = {"status": doc.get("status"), "line": upstream_baseline_line(stem, doc), "same_package": same}
        elif ok:
            info[stem.rsplit("-", 1)[1]] = {"status": "NOT_ASSESSED", "same_package": False,
                                            "line": "upstream-baseline 的結果指的不是這份掃描的刷機包，未採用"}
    return info


def bootmod():
    """tools/cra/bootloader_coverage.py（開機韌體涵蓋說明、UEFI 映像與原始碼的一致性；同 vexmod 依路徑載入）。"""
    global _BOOT
    if _BOOT is None:
        p = HERE / "bootloader_coverage.py"
        try:
            spec = importlib.util.spec_from_file_location("sca_center_bootloader_coverage", p)
            m = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(m)
        except Exception as e:
            raise Fail(f"無法載入 {p}（開機韌體涵蓋說明；{type(e).__name__}）")
        _BOOT = m
    return _BOOT


_TEE = None


def teemod():
    """tools/cra/tee_bundled.py（tos-optee 的 OP-TEE、TF-A、內建 Mbed TLS 併進產品 SBOM、Grype 比對成列；同 uefimod 依路徑載入）。"""
    global _TEE
    if _TEE is None:
        p = HERE / "tee_bundled.py"
        try:
            spec = importlib.util.spec_from_file_location("sca_center_tee_bundled", p)
            m = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(m)
        except Exception as e:
            raise Fail(f"無法載入 {p}（tos-optee 內建元件；{type(e).__name__}）")
        _TEE = m
    return _TEE


_UEFI = None


def uefimod():
    """tools/cra/uefi_bundled.py（UEFI 內建函式庫併進產品 SBOM、Grype 比對成列；同 vexmod 依路徑載入）。"""
    global _UEFI
    if _UEFI is None:
        p = HERE / "uefi_bundled.py"
        try:
            spec = importlib.util.spec_from_file_location("sca_center_uefi_bundled", p)
            m = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(m)
        except Exception as e:
            raise Fail(f"無法載入 {p}（UEFI 內建函式庫；{type(e).__name__}）")
        _UEFI = m
    return _UEFI


def own_software(scan, cfg, spec, fwc, fw_info, path=None):
    """設定 sbom.own_software（產品自有軟體）→ own_software.build() 的 (元件, 頂層 ref, info, 刷機包的元件)；
    沒有設定 → (None, None, None, fwc)：什麼都不做，輸出和沒有這個功能時逐位元組相同。
    path：--own-software（預設 <scan>/../own-software/own-software.json）。同一個檔案已經是刷機包的 kernel 模組（fwc）時不重複列，
    改在那個元件上標記（在複本上改，成功才換掉 fwc；處理失敗時刷機包的元件維持原樣）。"""
    if not ownmod().configured(cfg):
        return None, None, None, fwc
    p = Path(path) if path else scan.parent / "own-software" / "own-software.json"
    doc = load_json(p)
    fw2 = json.loads(json.dumps(fwc)) if fwc else fwc
    try:     # own-software.json 是不可信資料：格式怪異時不讓整份 CRA 文件失敗
        comps, top, info = ownmod().build(doc, cfg, spec, fw2, fw_info.get("prefix") if isinstance(fw_info, dict) else None, p.name)
    except Exception as e:      # noqa: BLE001
        comps, top, info = ownmod().build(None, cfg, spec, None, None, p.name)
        info["gaps"][:] = [f"`{p.name}` could not be processed ({type(e).__name__}): the manufacturer's own software is missing from the SBOM"]
        fw2 = fwc
    if isinstance(doc, dict):
        try:
            info["sha256"] = hashlib.sha256(p.read_bytes()).hexdigest()
        except OSError:
            pass
    return comps, top, info, fw2


_SP = None
SUPPLIER_SKIP = ("user-information", "technical-documentation")   # role supplier：只有製造商能出的文件（Annex II、Annex VII、DoC）


def spmod():
    """tools/cra/supplier_package.py（role supplier 的資料包；同 vexmod 依路徑載入）。"""
    global _SP
    if _SP is None:
        p = HERE / "supplier_package.py"
        try:
            spec = importlib.util.spec_from_file_location("sca_center_supplier_package", p)
            m = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(m)
        except Exception as e:
            raise Fail(f"無法載入 {p}（供應商資料包；{type(e).__name__}）")
        _SP = m
    return _SP


_SUP = None


def supmod():
    """tools/cra/support_check.py（支援期檢查；同 vexmod 依路徑載入）。"""
    global _SUP
    if _SUP is None:
        p = HERE / "support_check.py"
        try:
            spec = importlib.util.spec_from_file_location("sca_center_support_check", p)
            m = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(m)
        except Exception as e:
            raise Fail(f"無法載入 {p}（支援期檢查；{type(e).__name__}）")
        _SUP = m
    return _SUP


def secmod():
    """tools/cra/security_findings.py（安全測試的整理與人工決定檔；同 vexmod 依路徑載入）。"""
    global _SEC
    if _SEC is None:
        p = HERE / "security_findings.py"
        try:
            spec = importlib.util.spec_from_file_location("sca_center_security_findings", p)
            m = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(m)
        except Exception as e:
            raise Fail(f"無法載入 {p}（安全測試；{type(e).__name__}）")
        _SEC = m
    return _SEC


_CONF = None


def confmod():
    """tools/cra/confirm_items.py（待確認事項表；同 vexmod 依路徑載入）。"""
    global _CONF
    if _CONF is None:
        p = HERE / "confirm_items.py"
        try:
            spec = importlib.util.spec_from_file_location("sca_center_confirm_items", p)
            m = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(m)
        except Exception as e:
            raise Fail(f"無法載入 {p}（待確認事項表；{type(e).__name__}）")
        _CONF = m
    return _CONF


_NVD = None


def nvdmod():
    """tools/cra/no_vuln_data.py（可能沒有漏洞資料的 deb 套件；同 vexmod 依路徑載入）。"""
    global _NVD
    if _NVD is None:
        p = HERE / "no_vuln_data.py"
        try:
            spec = importlib.util.spec_from_file_location("sca_center_no_vuln_data", p)
            m = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(m)
        except Exception as e:
            raise Fail(f"無法載入 {p}（沒有漏洞資料的套件；{type(e).__name__}）")
        _NVD = m
    return _NVD


def is_kernel_row(row, kinfo=None):
    """這一列是不是作業系統核心（依序，任一符合）：
      1. C-kernel-l4t-map 加上的 Canonical 核心：purl（不含 qualifiers）相同，或名稱與版本相同；
      2. kernelcheck.py 的規則：元件 CPE 是 Linux 核心；pkg:generic/linux-kernel；deb／rpm／apk 套件名稱是核心套件
         （KERNEL_PACKAGE_PATTERNS，不含 headers、tools、linux-libc-dev 等）；
      3. DT 以 Debian／Ubuntu 原始碼套件比對時（dt/deb-sources.json），從它安裝的二進位套件有核心套件
         （例如原始碼套件 linux 安裝成 linux-image-…；只裝了 linux-libc-dev 的不算）。"""
    purl = row.get("purl") or ""
    if kinfo and (purl.split("?", 1)[0] == kinfo["purl"] or (row.get("name"), row.get("version")) == (kinfo["name"], kinfo["version"])):
        return True
    kc = kernelcheck()
    if kc.is_kernel_cpe(row.get("cpe")):
        return True
    typ, name = kc.purl_type_name(purl)
    if typ == "generic" and name == "linux-kernel":
        return True
    return typ in kc.PACKAGE_TYPES and (kc.is_kernel_package_name(name) or any(kc.is_kernel_package_name(b) for b in row.get("installed_as") or []))


SEVERITY_SOURCES = ("vendor", "distro", "nvd")
UBUNTU_SEVERITY = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "negligible": "LOW"}
SEV_SOURCE_TEXT = {"nvidia-bulletin": "NVIDIA bulletin", "ubuntu-priority": "Ubuntu priority",
                   "ubuntu-priority-grype": "Ubuntu priority (via Grype)",
                   "nvd-cvss": "NVD", "other": "other", "none": "none"}


def ubuntu_priority_map(doc):
    """scan/ubuntu-priority.json（tools/pilot/lib/ubuntu_priority.py）→ {CVE: priority（小寫）}；status 不是 OK、格式不對 → None。"""
    if not isinstance(doc, dict) or doc.get("status") != "OK" or not isinstance(doc.get("cves"), dict):
        return None
    return {c: x["priority"] for c, x in doc["cves"].items()
            if isinstance(c, str) and isinstance(x, dict) and x.get("priority") in UBUNTU_SEVERITY}


def grype_ubuntu_severity(grype):
    """Grype 以 Ubuntu 資料（namespace ubuntu:…）比對到的 CVE → priority（小寫；Grype 的 Ubuntu severity 就是 Ubuntu 的 priority）。
    同一個 CVE 有多筆時取最嚴重的；Unknown（untriaged）不算。"""
    out = {}
    for m in (grype or {}).get("matches") or []:
        v = (m.get("vulnerability") or {}) if isinstance(m, dict) else {}
        if not isinstance(v, dict) or not str(v.get("namespace") or "").lower().startswith("ubuntu:"):
            continue
        p = str(v.get("severity") or "").lower()
        if p not in UBUNTU_SEVERITY:
            continue
        for c in cves_of({v["id"]} if isinstance(v.get("id"), str) else set()):
            if c not in out or SEV_RANK.get(UBUNTU_SEVERITY[p], 9) < SEV_RANK.get(UBUNTU_SEVERITY[out[c]], 9):
                out[c] = p
    return out


def nvidia_unreviewed(nvb):
    """scan/nvidia-bulletins.json 的 unreviewed_would_match → {CVE: [「<公告> <評級>」]}（對照表還沒審核：只顯示，不拿來分級）。"""
    out = {}
    for x in (nvb.get("unreviewed_would_match") or []) if isinstance(nvb, dict) else []:
        if isinstance(x, dict) and isinstance(x.get("cve"), str) and isinstance(x.get("severity"), str):
            out.setdefault(x["cve"], []).append(f"{x.get('bulletin')} {x['severity'].upper()}")
    return out


def most_severe(sevs):
    return min(sevs, key=lambda s: SEV_RANK.get(s, 9)) if sevs else None


def nvidia_debs(comps):
    """SBOM 裡 NVIDIA 自己出的 deb（Syft 的 publisher＝dpkg 的 Maintainer 含 NVIDIA，例如 L4T 的 nvidia-l4t-*）的 purl（不含 qualifiers）。
    這些套件的 purl 也是 pkg:deb/ubuntu/…，但不是 Ubuntu 打包的，Ubuntu priority 不適用（Ubuntu 對 nvidia-graphics-drivers 的評級是它自己打包的驅動）。"""
    return {c["purl"].split("#", 1)[0].split("?", 1)[0] for c in comps or []
            if isinstance(c, dict) and isinstance(c.get("purl"), str) and c["purl"].startswith("pkg:deb/")
            and "nvidia" in str(c.get("publisher") or "").lower()}


def ubuntu_packaged(row, nvdebs=None):
    """這一列的元件是 Ubuntu 打包的（distro 來源適用）：purl 是 pkg:deb/ubuntu/…、不是 NVIDIA 出的 deb（publisher 或名稱 nvidia-l4t-*）；
    或是 Ubuntu 套件裝進 dist-packages 的 Python 模組（apply_deb_python 找到的擁有者是這樣的 deb）。"""
    def ok(purl, name):
        return (purl.lower().startswith("pkg:deb/ubuntu/") and not name.lower().startswith("nvidia-l4t-")
                and purl.split("#", 1)[0].split("?", 1)[0] not in (nvdebs or ()))
    o = (row.get("deb_python") or {}).get("owner")
    if o:
        return ok(o.get("purl") or "", o.get("name") or "")
    return ok(row.get("purl") or "", row.get("name") or purl_path(row.get("purl") or "").rpartition("/")[2])


def pick_severity(row, order, upri=None, gpri=None, nvun=None, nvdebs=None):
    """依政策的來源順序決定這一列分級用的嚴重度。回傳 (嚴重度, 來源, 各來源的值)。
      vendor：這一列的 NVIDIA 公告 finding（對照表已審核的列，source NVIDIA）的評級；
      distro：Ubuntu 打包的元件（ubuntu_packaged）上 CVE 的 Ubuntu priority：每個 CVE 先用 scan/ubuntu-priority.json，沒有再用 Grype 的
              Ubuntu 比對，取最嚴重的。**一列的每個 CVE 都有 priority** 才只用 distro；有 CVE 沒有 priority 時取 distro 與順序裡下一個
              有值的來源中較嚴重的（沒有 priority 的 CVE 不能因為別的 CVE 有而被壓低）。鏡像與 Grype 的值都記在 detail（不一致時並列）；
      nvd：DT 的值（有 NVD 的 finding 是這個值時記 nvd-cvss，否則 other）。順序裡有 vendor 時不含 NVIDIA 公告的 finding；
           沒有 vendor 時（例如 ["nvd"]）和以前一樣含全部來源，NVIDIA 公告的列不會變成 UNASSIGNED。
    沒有值（UNASSIGNED、untriaged、沒有資料）的來源跳過。nvd 一定是最後的退路（政策沒寫也一樣）。"""
    by = row["sev_by_source"]
    vals = {}
    nv = by.get("NVIDIA")
    if nv and nv != "UNASSIGNED":
        vals["vendor"] = ("nvidia-bulletin", nv, nv)
    detail = {}
    if ubuntu_packaged(row, nvdebs):
        mir = {c: upri[c] for c in row["cves"] if upri and c in upri}
        gry = {c: gpri[c] for c in row["cves"] if gpri and c in gpri}
        gonly = {c: x for c, x in gry.items() if c not in mir}  # 每個 CVE：鏡像優先，沒有才用 Grype
        worst_p = lambda m: min(m.values(), key=lambda x: SEV_RANK.get(UBUNTU_SEVERITY[x], 9))     # noqa: E731
        for src, m in (("ubuntu-priority", mir), ("ubuntu-priority-grype", gonly)):
            if m:
                detail[src] = worst_p(m)
        diff = {c: gry[c] for c in mir if c in gry and gry[c] != mir[c]}
        if diff:
            detail["ubuntu-priority-grype-differs"] = diff      # 矛盾並列保留（用的是鏡像的）
        per = {**gonly, **mir}
        if per:
            raw = worst_p(per)
            src = "ubuntu-priority" if raw in mir.values() else "ubuntu-priority-grype"
            vals["distro"] = (src, UBUNTU_SEVERITY[raw], raw)
            missing = sorted(set(row["cves"]) - set(per))
            if missing:
                detail["ubuntu-priority-missing"] = missing
    dt = most_severe([x for k, x in by.items() if (k != "NVIDIA" or "vendor" not in order) and x != "UNASSIGNED"])
    if dt:
        vals["nvd"] = ("nvd-cvss" if by.get("NVD") == dt else "other", dt, dt)
    for k in vals:
        if k != "distro":
            detail[vals[k][0]] = vals[k][2]
    un = sorted({x for c in row["cves"] for x in (nvun or {}).get(c, ())})
    if un:
        detail["nvidia-bulletin-unreviewed"] = un
    seq = [k for k in list(order) + ["nvd"] if k in vals]
    if not seq:
        return "UNASSIGNED", "none", detail
    k = seq[0]
    if k == "distro" and detail.get("ubuntu-priority-missing"):
        nxt = next((x for x in seq[1:] if x != "distro"), None)
        if nxt and SEV_RANK.get(vals[nxt][1], 9) < SEV_RANK.get(vals["distro"][1], 9):
            k = nxt
    return vals[k][1], vals[k][0], detail


def severity_text(r):
    """表格的 Severity source 欄。"""
    src = r.get("severity_source") or "nvd-cvss"
    d = r.get("severity_detail") or {}
    t = SEV_SOURCE_TEXT.get(src, src)
    go = r.get("found_by") == GRYPE_ONLY

    def grype_label(sev):
        # 只有 Grype 的列沒有 DT 的 finding：嚴重度來自 Grype 的哪個 namespace（sev_by_source 的鍵：NVD、UBUNTU、GITHUB…）
        ns = sorted(k.lower() for k, x in (r.get("sev_by_source") or {}).items() if x == sev)
        return f"Grype ({'/'.join(ns) or '?'})"
    if go and src in ("nvd-cvss", "other"):
        t = grype_label(r["severity"])
    if src.startswith("ubuntu-priority"):
        t += f" ({d.get(src)})"
    if d.get("ubuntu-priority-grype-differs"):
        t += "; Grype's Ubuntu priority differs: " + ", ".join(f"{c} {x}" for c, x in sorted(d["ubuntu-priority-grype-differs"].items()))
    if d.get("ubuntu-priority-missing"):
        t += f"; no Ubuntu priority for {', '.join(d['ubuntu-priority-missing'])}"
        up = d.get("ubuntu-priority") or d.get("ubuntu-priority-grype")
        if not src.startswith("ubuntu-priority") and up:
            t += f", so the more severe next source is used (Ubuntu priority {up})"
    dt = d.get("nvd-cvss") or d.get("other")
    if src in ("nvidia-bulletin", "ubuntu-priority", "ubuntu-priority-grype") and dt and dt != r["severity"]:
        t += f"; {grype_label(dt) if go else 'Dependency-Track'} {dt}"
    if d.get("nvidia-bulletin-unreviewed"):
        t += f"; NVIDIA bulletin not reviewed, not used: {', '.join(d['nvidia-bulletin-unreviewed'])}"
    return t


def build_rows(findings, pol, gidx, have_grype, srcmap=None, kmap=None, usn=None, kev_more=None, sev=None, epss_more=None):
    """去重：一列＝（CVE；沒有 CVE 別名時用排序後最小的 ID）＋（元件名稱、版本）。合併的 finding 取最嚴重的值，原始 ID 全保留。
    usn：{USN 編號: [CVE]}（scan/usn-cves.json，status OK 時；usn_map）。沒有 CVE 別名的 USN finding，只在它列出的**每一個** CVE
    在同一個元件版本上都已經在某一列（任何 finding 的 CVE，含 GHSA 等的別名）時，併進排序最前的那個 CVE 的列（優先用以它為編號的列），
    來源編號照樣保留；否則照舊自成一列，記下清單列的 CVE。這樣併進去不會讓清單上的任何 CVE 從文件消失（每個都有自己的列或在別列裡）。
    不把 USN 的 CVE 加進這一列的 CVE（公告的 CVE 清單涵蓋整份公告，不一定是這個套件的），所以不會多拆 vex_extra。
    KEV 以 CVE 為鍵合併所有來源：DT 的 isKev（這一列自己的 finding，或同一個 CVE 在別的元件／別的紀錄上）與 kev_more
    （{CVE: 來源名稱集合}，例如 Grype 的 knownExploited）。任一來源是 KEV 就是 KEV；row["kev_sources"] 記來源。
    嚴重度（分級用）依 pol["severity_sources"] 的順序（pick_severity；sev＝{"upri": Ubuntu priority, "gpri": Grype 的 Ubuntu priority,
    "nvun": 未審核的 NVIDIA 評級}）；DT 原本的值留在 severity_dt。
    EPSS：epss（機率）、epss_pct（百分位）是這一列自己的 DT finding 的，分級與排序只用這兩個（現行行為不變；使用者決定新分級不用 EPSS）。
    同一個 CVE 的其他來源（別筆 DT 紀錄＝same CVE、epss_more＝{CVE: {probability, percentile, date}}，例如 Grype 的）和自己的值不同時，
    記在 epss_other（每個來源取機率最高的一筆，含 CVE 與日期），只並列顯示、不拿來分級。GHSA 等有多個 CVE 別名的 DT 紀錄分不出分數屬於
    哪個 CVE，不給別的列。"""
    groups, kev_cves, pre, dt_epss = {}, set(), [], {}
    for f in findings:
        if not isinstance(f, dict):
            continue
        c, v = f.get("component") or {}, f.get("vulnerability") or {}
        ids = ids_of(v) or {"?"}
        cves = sorted(cves_of(ids))
        # 用 purl 的完整名稱分組：org.a:core 和 com.b:core 不會被併成一列
        pre.append((c, v, f, ids, cves, (cves[0] if cves else min(ids), purl_fullname(c.get("purl")) or (c.get("name") or "?").lower(),
                                         c.get("version") or "")))
    have = {}       # (CVE, 元件, 版本) → 含這個 CVE 的列；以這個 CVE 為編號的列優先
    for *_, cves, k in pre:
        for x in cves:
            if x == k[0] or (x, *k[1:]) not in have:
                have[(x, *k[1:])] = k
    usn_of = {}
    for c, v, f, ids, cves, key in pre:
        listed = (usn or {}).get(str(v.get("vulnId") or "").upper()) if not cves else None
        acves = cves
        if listed:
            hit = [have[(x, *key[1:])] for x in sorted(listed)] if all((x, *key[1:]) in have for x in listed) else []
            # 併進 CVE 的列時，分析的對象：USN 只列一個 CVE 時就是那個 CVE（VEX 可採用 DT 對這筆 USN 的分析）；
            # 多個時和 GHSA 多個別名一樣不採用（dt_attributable）
            acves = sorted(listed) if hit else cves
            key = hit[0] if hit else key
            usn_of.setdefault(key, {})[v["vulnId"]] = (sorted(listed), bool(hit))
        # 每筆 finding 的分析另記它自己的弱點編號與 CVE：VEX 只在分析的對象就是這一列的 CVE 時採用（同一列可能併了別名不同的 finding）
        groups.setdefault(key, []).append((c, v, dict(analysis_of(f), vuln_id=v.get("vulnId") or "", cves=acves), ids))
        if v.get("isKev") is True:
            # 只取帶 isKev 的這筆紀錄自己的 CVE（vulnId 是 CVE 就只用它，否則用它的 CVE 別名），不取同一列併進來的其他 CVE
            own = cves_of({v["vulnId"]}) if isinstance(v.get("vulnId"), str) else set()
            kev_cves |= own or set(cves)
        pr = unit(v.get("epssScore"))
        if pr is not None:
            # 同 KEV：紀錄自己的 CVE；GHSA 等有多個 CVE 別名的紀錄分不出是哪一個的分數，不收。
            # 依列（key）分開記：顯示「same CVE」時不拿這一列自己的 finding 來比
            own = cves_of({v["vulnId"]}) if isinstance(v.get("vulnId"), str) else set()
            own = own or (set(cves) if len(cves) == 1 else set())
            e = {"probability": pr, "percentile": unit(v.get("epssPercentile")), "date": None}
            for x in own:
                old = dt_epss.setdefault(x, {}).get(key)
                if old is None or (pr, pct_key(e["percentile"])) > (old["probability"], pct_key(old["percentile"])):
                    dt_epss[x][key] = e
    rows = []
    for (rid, lname, ver), fs in groups.items():
        c0 = fs[0][0]
        ids = set().union(*(x[3] for x in fs))
        vs = [x[1] for x in fs]
        cvss = [(num(v.get(k)), tag) for v in vs for k, tag in (("cvssV3BaseScore", "v3"), ("cvssV4Score", "v4"), ("cvssV2BaseScore", "v2"))]
        cvss = max((x for x in cvss if x[0] is not None), default=None) or (None, None)
        row = {"id": rid, "key": [rid, lname, ver], "all_ids": sorted(ids | cves_of(ids)), "cves": sorted(cves_of(ids)), "source_ids": sorted({f"{v.get('source') or '?'}:{v.get('vulnId') or '?'}" for v in vs}),
               "component": display_name(c0), "version": ver, "purl": c0.get("purl") or "",
               "ptype": (c0.get("purl") or "").partition(":")[2].partition("/")[0] or "?",
               "severity": min((str(v.get("severity") or "UNASSIGNED").upper() for v in vs), key=lambda s: SEV_RANK.get(s, 9)),
               "sev_by_source": {src: most_severe([str(v.get("severity") or "UNASSIGNED").upper() for v in vs
                                                   if str(v.get("source") or "?").upper() == src])
                                 for src in sorted({str(v.get("source") or "?").upper() for v in vs})},
               "cvss_score": cvss[0], "cvss": f"{cvss[0]:.1f} ({cvss[1]})" if cvss[0] is not None else None,
               "epss": max((unit(v.get("epssScore")) for v in vs if unit(v.get("epssScore")) is not None), default=None),
               "epss_pct": max((unit(v.get("epssPercentile")) for v in vs if unit(v.get("epssPercentile")) is not None), default=None),
               "kev": any(v.get("isKev") is True for v in vs), "analysis": [x[2] for x in fs],
               "installed_as": (srcmap or {}).get((c0.get("purl") or "").split("?", 1)[0], []),
               "mapped_from": (kmap or {}).get((c0.get("purl") or "").split("?", 1)[0]),
               "name": c0.get("name") or "", "cpe": c0.get("cpe") or "", "n_findings": len(fs)}
        if (rid, lname, ver) in usn_of:
            # usn_merged：併進這一列的 USN；usn_listed：自成一列的 USN 清單上的 CVE（不是每一個在同一個元件版本上都有列）
            u = usn_of[(rid, lname, ver)]
            row["usn_merged"] = {k: x[0] for k, x in sorted(u.items()) if x[1]}
            row["usn_listed"] = sorted({c for x in u.values() if not x[1] for c in x[0]})
        # DT 以原始碼套件比對時，Grype 的修補資訊記在安裝的二進位套件上（版本通常與原始碼相同）
        st, vers = fix_lookup(ids | set(row["cves"]), [lname, (c0.get("name") or "").lower(), purl_fullname(c0.get("purl"))]
                              + [b.lower() for b in row["installed_as"]], ver, gidx)
        row["fix"] = fix_text(st, vers, have_grype)
        row["fix_state"], row["fix_versions"] = fix_state(st, vers, have_grype), sorted(vers)
        row["fix_next"] = next_fix(row)
        row["severity_dt"] = row["severity"]
        row["severity"], row["severity_source"], row["severity_detail"] = pick_severity(
            row, pol.get("severity_sources", SEVERITY_SOURCES), **(sev or {}))
        row["tier"] = tier_of(row, pol)
        rows.append(row)
    # KEV 是「這個 CVE 已知被利用」：同一個 CVE 在別的元件或別的資料來源（例如 Ubuntu 的 UBUNTU-CVE-… 紀錄，DT 不帶 isKev）
    # 的列也算 KEV（P1、批次規則不套用、第 14 條的評估）；kev_by_cve 記下是經 CVE 對到的
    # 其他來源（Grype 的 knownExploited）同樣以 CVE 對：核心的 DT finding 多半是 OSV 的 UBUNTU-CVE-… 紀錄（沒有 isKev），
    # DT 的 KEV 掛在 NVD 的 CVE-… 紀錄上，產品裡不一定有那筆 finding
    for r in rows:
        src = ["DT"] if r["kev"] else []
        if not r["kev"] and kev_cves.intersection(r["cves"]):
            src.append("same CVE")
            r["kev_by_cve"] = True
        # kev_more 的鍵可以是 CVE 或其他編號：其他編號（GHSA 等）只在這一列沒有任何 CVE 別名時才用，
        # 否則 Grype 對同一個 GHSA 的 KEV 會擴散到這個 GHSA 的其他 CVE（審查中 1）
        keys = set(r["cves"]) if r["cves"] else {i.upper() for i in r["all_ids"]}
        src += sorted({x for c in keys for x in (kev_more or {}).get(c, ())})
        r["kev_sources"] = src
        if src and not r["kev"]:
            r["kev"] = True
            r["tier"] = tier_of(r, pol)
        # EPSS 是每個 CVE 的分數：DT 的 UBUNTU-CVE-… 紀錄常常不帶 EPSS，同一個 CVE 的 NVD 紀錄或 Grype 有。只並列顯示（標來源與日期）
        other = {}
        rkey = tuple(r["key"])
        same = {c: max((e for k, e in dt_epss.get(c, {}).items() if k != rkey),
                       key=lambda e: (e["probability"], pct_key(e["percentile"])), default=None) for c in r["cves"]}
        for src, m in (("same CVE", same), ("Grype", epss_more or {})):
            for c in r["cves"]:
                e = m.get(c)
                if e and (e["probability"], e.get("percentile")) != (r["epss"], r["epss_pct"]) \
                        and (src not in other or e["probability"] > other[src]["probability"]):
                    other[src] = {"source": src, "cve": c, "probability": e["probability"], "percentile": e.get("percentile"), "date": e.get("date")}
        if other:
            r["epss_other"] = [other[k] for k in ("same CVE", "Grype") if k in other]
    rows.sort(key=row_order)
    return rows


def dt_same_cve(findings):
    """DT findings 每個 CVE 的被利用資料（只有 Grype 的列用：和 build_rows 給 DT 列的「same CVE」同一個規則）→ (KEV 的 CVE 集合,
    {CVE: {probability, percentile, date}})。KEV：isKev 的紀錄自己的 CVE（vulnId 是 CVE 就只用它，否則它的 CVE 別名）；EPSS：紀錄自己的 CVE，
    或只有一個 CVE 別名的紀錄（GHSA 等有多個 CVE 別名的分不出是哪一個的分數，不收），同一個 CVE 取機率最高的。"""
    kev, epss = set(), {}
    for f in findings if isinstance(findings, list) else []:
        v = (f.get("vulnerability") or {}) if isinstance(f, dict) else {}
        if not isinstance(v, dict):
            continue
        cves = sorted(cves_of(ids_of(v)))
        own = cves_of({v["vulnId"]}) if isinstance(v.get("vulnId"), str) else set()
        if v.get("isKev") is True:
            kev |= own or set(cves)
        pr = unit(v.get("epssScore"))
        if pr is not None:
            e = {"probability": pr, "percentile": unit(v.get("epssPercentile")), "date": None}
            for c in own or (set(cves) if len(cves) == 1 else set()):
                old = epss.get(c)
                if old is None or (pr, pct_key(e["percentile"])) > (old["probability"], pct_key(old["percentile"])):
                    epss[c] = e
    return kev, epss


GRYPE_SEVERITY = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "negligible": "LOW", "info": "INFO"}
GRYPE_ONLY = "grype only"


def grype_source(ns):
    """Grype 紀錄的 namespace → 嚴重度來源名稱（和 DT 的 finding source 同一種寫法）：nvd:cpe → NVD、github:language:python → GITHUB、
    ubuntu:distro:ubuntu:24.04 → UBUNTU；沒有 namespace → GRYPE。"""
    return str(ns or "").split(":", 1)[0].strip().upper() or "GRYPE"


def grype_component(a):
    """Grype 的 artifact → DT finding 的 component 形狀（名稱、版本、purl、第一個 CPE）。purl 和名稱都沒有 → None（沒有元件身分，不能成列）。"""
    if not isinstance(a, dict) or not (isinstance(a.get("purl"), str) and a["purl"] or isinstance(a.get("name"), str) and a["name"]):
        return None
    cpes = a.get("cpes") if isinstance(a.get("cpes"), list) else []
    cpe = next((c if isinstance(c, str) else c.get("cpe") for c in cpes
                if isinstance(c, str) or (isinstance(c, dict) and isinstance(c.get("cpe"), str))), "")
    return {"name": a.get("name") if isinstance(a.get("name"), str) else "", "version": a.get("version") if isinstance(a.get("version"), str) else "",
            "purl": a.get("purl") if isinstance(a.get("purl"), str) else "", "cpe": cpe or ""}


def grype_only_rows(grype, rows, pol, gidx, have_grype, srcmap=None, kmap=None, kev_more=None, sev=None, epss_more=None,
                    dpy=None, version_unknown=None, services=None, dt_same=None):
    """Grype 有、DT 沒有的比對（交叉核對的同一個判斷：grype_coverage，同一個元件上沒有共同編號的 DT 列）也成為風險表的列（專案規則：不同工具的結果並列保留，不靜默丟掉）。
    每筆比對轉成 DT finding 的形狀（source GRYPE，vulnId＝Grype 的主編號，aliases＝relatedVulnerabilities，沒有 DT 分析），交給 build_rows
    另外建列（不和 DT 的 finding 一起建：DT 的列逐字不變；usn 不用），所以分組（CVE 或最小的編號 × purl 的完整名稱 × 版本）、
    KEV（kev_more＝Grype 的 knownExploited）、修補狀態（gidx）、installed_as／mapped_from、嚴重度的來源順序和 DT 的列相同。
    列的值取自 Grype：嚴重度每個 namespace 一個來源（NVD、UBUNTU、GITHUB…，negligible 算 LOW，unknown 不算；pick_severity 照政策的順序選，
    Ubuntu priority 仍由 sev 的 gpri 給），CVSS 每個來源只取最新版（grype_cvss_entries）中最高的，EPSS 是這筆比對的（機率最高的一筆）。
    元件以 Grype artifact 的 purl 識別（Grype 讀的就是同一份 SBOM，所以和 SBOM 元件、VEX 的 bom-ref 對得上）。
    標記：found_by＝"grype only"、sources＝["grype"]、grype_namespaces、grype_matches（比對筆數）；n_findings＝0（不是 DT 的 finding）。
    和現有的列（例如 NVIDIA 公告的列）同一個（編號、元件、版本）的不另加（那一列已經在表上；這一列另外的 CVE 由呼叫端點名，g_norow）。
    版本未知的元件（專案規則 13）不成列、不做弱點比對：sbomgate 排除的比對（version_unknown＝grype_version_unknown：
    VERSION_FROM_RANGE、NO_VERSION…；沒有 sbomgate.json 時是 sbom_version_unknown，鍵 ("*", purl)），以及 artifact 沒有版本的比對
    （NO_VERSION）；呼叫端標 GAP 並點名。
    回傳 (新的列, 不能成列的比對 [{"id", "cves", "package"}]：artifact 沒有 purl 也沒有名稱,
    版本未知的比對 [{"id", "cves", "package", "version", "reason"}])。"""
    synth, info, unlisted, unknown = [], {}, [], []
    unc, _, attach = grype_coverage(grype, dt_rows_of(rows), dpy, binary_exposed(services))
    attach_grype_binaries(attach)
    for m, ids in unc:
        v = m.get("vulnerability") if isinstance(m.get("vulnerability"), dict) else {}
        rel = [x for x in m.get("relatedVulnerabilities") or [] if isinstance(x, dict) and isinstance(x.get("id"), str) and x["id"]]
        vid = v.get("id") if isinstance(v.get("id"), str) and v["id"] else min(ids)
        c = grype_component(m.get("artifact"))
        if c is None:
            unlisted.append({"id": vid, "cves": sorted(cves_of(ids)), "package": "?"})
            continue
        why = (version_unknown or {}).get((vid.upper(), c["purl"] or c["name"])) or (version_unknown or {}).get(("*", c["purl"])) \
            or (None if c["version"] else "NO_VERSION")
        if why:
            unknown.append({"id": vid, "cves": sorted(cves_of(ids)), "package": c["name"] or purl_path(c["purl"]) or "?",
                            "version": c["version"] or None, "reason": why})
            continue
        recs = [v] + rel
        sevs = {}
        for x in recs:
            sv = GRYPE_SEVERITY.get(str(x.get("severity") or "").strip().lower())
            if sv:
                sevs.setdefault(grype_source(x.get("namespace")), []).append(sv)
        cv = {}
        for x in recs:
            for sc, _, _, ver in grype_cvss_entries(x):
                k = {4: "cvssV4Score", 3: "cvssV3BaseScore", 2: "cvssV2BaseScore"}.get(ver[0])
                if k and (cv.get(k) is None or sc > cv[k]):
                    cv[k] = sc
        own = cves_of(ids)
        ep = max(((unit(e.get("epss")), unit(e.get("percentile"))) for e in (v.get("epss") if isinstance(v.get("epss"), list) else [])
                  if isinstance(e, dict) and isinstance(e.get("cve"), str) and cves_of({e["cve"]}) & own and unit(e.get("epss")) is not None),
                 key=lambda e: (e[0], pct_key(e[1])), default=(None, None))
        vuln = {"source": "GRYPE", "vulnId": vid, "aliases": [{"id": x["id"]} for x in rel if x["id"] != vid],
                "severity": most_severe([y for ys in sevs.values() for y in ys]) or "UNASSIGNED", "isKev": False, **cv}
        if ep[0] is not None:
            vuln.update(epssScore=ep[0], epssPercentile=ep[1])
        synth.append({"component": c, "vulnerability": vuln})
        k = (vid, purl_fullname(c["purl"]) or (c["name"] or "?").lower(), c["version"])
        x = info.setdefault(k, {"sev": {}, "ns": set()})
        for src, ys in sevs.items():
            x["sev"].setdefault(src, []).extend(ys)
        x["ns"].update(str(y.get("namespace")) for y in recs if y.get("namespace"))
    if not synth:
        return [], unlisted, unknown
    have = {tuple(r["key"]) for r in rows}
    out = []
    # DT 對同一個 CVE（在別的元件上）的 KEV 與 EPSS（dt_same＝dt_same_cve(findings)）：和 DT 的列一樣算「same CVE」——KEV 進 P1、
    # 批次規則不套用；EPSS 只並列顯示（epss_other，不拿來分級）。EUVD 與人工證據由 apply_exploitation 對所有的列一起加
    dkev, depss = dt_same or (set(), {})
    km = {c: set(x) for c, x in (kev_more or {}).items()}
    for c in dkev:
        km.setdefault(c, set()).add("same CVE")
    for r in build_rows(synth, pol, gidx, have_grype, srcmap, kmap, None, km, sev, epss_more):
        if tuple(r["key"]) in have:
            continue
        if "same CVE" in r["kev_sources"]:
            r["kev_sources"] = ["same CVE"] + [x for x in r["kev_sources"] if x != "same CVE"]      # 和 DT 的列同一個順序
            r["kev_by_cve"] = True
        same = [dict(depss[c], source="same CVE", cve=c) for c in r["cves"] if c in depss
                and (depss[c]["probability"], depss[c]["percentile"]) != (r["epss"], r["epss_pct"])]
        if same:
            best = max(same, key=lambda e: (e["probability"], pct_key(e["percentile"])))
            r["epss_other"] = [{k: best[k] for k in ("source", "cve", "probability", "percentile", "date")}] + \
                [x for x in r.get("epss_other") or [] if x["source"] != "same CVE"]
        sb, ns = {}, set()
        for a in r["analysis"]:
            x = info.get((a["vuln_id"], r["key"][1], r["key"][2])) or {"sev": {}, "ns": set()}
            for src, ys in x["sev"].items():
                sb.setdefault(src, []).extend(ys)
            ns |= x["ns"]
        r["sev_by_source"] = {src: most_severe(ys) for src, ys in sorted(sb.items())} or {"GRYPE": "UNASSIGNED"}
        r["severity"], r["severity_source"], r["severity_detail"] = pick_severity(r, pol.get("severity_sources", SEVERITY_SOURCES), **(sev or {}))
        r["tier"] = tier_of(r, pol)
        r.update(found_by=GRYPE_ONLY, sources=["grype"], grype_namespaces=sorted(ns), grype_matches=r["n_findings"], n_findings=0)
        out.append(r)
    return out, unlisted, unknown


KERNEL_CNA = "kernel cna"
KERNEL_CNA_SCHEMA = "sca-center-kernel-cna-version/1"


def kernel_cna_rows(cl, kcfg, rows, kinfo, pol, gidx, have_grype, srcmap, kmap, sev, kev_more=None):
    """廠商核心（不是套件安裝的核心，例如 SoC 廠商的 BSP 核心）的列。Grype、DT 都沒有核心的列、可是 sca-scan 有依產品核心版本從 Linux 核心 CNA
    產生 CVE 清單（scan/kernel-cve-list.json，kernel_cna_version.py）並且 kernel-config.json 用了那份清單（inputs.cves_origin）時，
    清單裡每個 K1 判定過的 CVE 成為一列（元件＝產品核心 pkg:generic/linux-kernel、CPE linux_kernel，版本取自 kernel-config.json 的 component），
    交給 build_rows 另外建列（同 grype_only_rows：之後的 EUVD／KEV 分級、VEX（K1 的判定與證據）、批次規則和其他列相同）。
    標記 found_by "kernel cna"、sources ["kernel-cna-version"]、row["kernel_cna"]＝{version_verdict: affected|unknown|explicit, reason, note}（explicit＝KERNEL_CVES 明確給的清單，沒有版本比對；origin 是 KERNEL_CVES… 時不需要 kernel-cve-list.json，以 kernel-config.json 的 results 為準）：
    版本比對判不了（unknown）的列照實標「版本判斷不了」，不寫成受影響，也不當成沒問題。
    不符合條件（沒有清單、清單不是這次用的、已經有核心的列）→ 回傳 ([], None)；回傳 (新的列, 摘要)。"""
    if not (isinstance(kcfg, dict) and kcfg.get("schema") == "sca-center-kernel-config/1"):
        return [], None
    origin = (kcfg.get("inputs") or {}).get("cves_origin")
    comp = kcfg.get("component") if isinstance(kcfg.get("component"), dict) else {}
    explicit = isinstance(origin, str) and origin.startswith("KERNEL_CVES")        # 明確給的清單：沒有版本比對
    cna = isinstance(origin, str) and origin.startswith("kernel-cna-version")
    if not ((cna and isinstance(cl, dict) and cl.get("schema") == KERNEL_CNA_SCHEMA and isinstance(cl.get("cves"), list)) or explicit):
        return [], None
    if not (comp.get("purl") and comp.get("version")):
        return [], None
    if any(is_kernel_row(r, kinfo) for r in rows):
        return [], None                       # Grype／DT 已經有核心的列：走原本的路
    ver = ({c.get("cve"): c for c in cl["cves"] if isinstance(c, dict) and isinstance(c.get("cve"), str)} if cna else {})
    synth, seen = [], set()
    for r in kcfg.get("results") or []:
        cve = r.get("cve") if isinstance(r, dict) else None
        if not isinstance(cve, str) or cve in seen or (cna and cve not in ver):
            continue
        seen.add(cve)
        synth.append({"component": {"name": comp.get("name") or "linux-kernel", "version": comp["version"], "purl": comp["purl"],
                                    "cpe": comp.get("cpe") or ""},
                      "vulnerability": {"source": "KERNEL-CNA", "vulnId": cve, "aliases": [], "severity": "UNASSIGNED", "isKev": False}})
    out = []
    for row in build_rows(synth, pol, gidx, have_grype, srcmap, kmap, None, kev_more, sev, None):
        v = ver.get(row["id"]) or ({"verdict": "explicit", "reason": "explicit CVE list (KERNEL_CVES): no version comparison"} if explicit else {})
        row["kernel_cna"] = {"version_verdict": v.get("verdict"), "reason": v.get("reason"), "note": v.get("note")}
        row.update(found_by=KERNEL_CNA, sources=["kernel-cna-version"], n_findings=0)
        out.append(row)
    n_unk = sum(1 for r in out if r["kernel_cna"]["version_verdict"] not in ("affected", "explicit"))
    return out, {"rows": len(out), "version_affected": len(out) - n_unk, "version_unknown": n_unk, "origin": origin,
                 "cna_commit": ((cl.get("mirror") or {}).get("commit") if isinstance(cl.get("mirror"), dict) else None) if cna else None}


def fix_lookup(ids, lnames, ver, gidx):
    """Grype 對這一列的 fix 狀態集合與修補版本集合（以 ID 或 CVE、套件名稱、版本查）。"""
    st, vers = set(), set()
    for i in ids:
        for lname in lnames:
            s, v = gidx.get((i, lname, ver), ((), ()))
            st.update(s)
            vers.update(v)
    return st, vers


def fix_text(st, vers, have_grype):
    if not have_grype:
        return "unknown (no Grype data)"
    if vers:
        return "fixed in " + ", ".join(sorted(vers))
    return "/".join(sorted(st)) if st else "unknown (not matched by Grype)"


def next_fix(r):
    """VEX 批次規則範本的 {fix_version}：deb 取比安裝版本新的最低修補版本（與 kernel_fix_all 相同的規則）；其他類型不比較版本，
    Grype 列的全部寫出（以「, 」分隔）；沒有可用的版本 → None（用到 {fix_version} 的規則不套用在這一列）。"""
    vers = r["fix_versions"]
    if r["fix_state"] != "fixed" or not vers:
        return None
    if r["ptype"] == "deb":
        newer = [v for v in vers if not r["version"] or deb_vercmp(v, r["version"]) > 0]
        return min(newer, key=deb_key) if newer else None
    return ", ".join(vers)


# 核心段落的修補狀態分類（Grype 的 fix.state；沒有 Grype 結果或 Grype 沒有比對到這一列 → no Grype data）。
# 核心以外的 Ubuntu 列沒有 Grype 的修補狀態時，可能改用 Ubuntu CVE Tracker 推出的（apply_ubuntu_tracker；fix_state_source）
FIX_STATES = ("fixed", "not-fixed", "wont-fix", "unknown", "no Grype data")


def fix_state(st, vers, have_grype):
    """一列一個狀態：有修補版本或 Grype 寫 fixed → fixed；否則 not-fixed 優先於 wont-fix（之後還可能修）；
    其他 Grype 狀態 → unknown；沒有 Grype 資料或沒有比對到 → no Grype data。"""
    if not have_grype or not (st or vers):
        return "no Grype data"
    if vers or "fixed" in st:
        return "fixed"
    for s in ("not-fixed", "wont-fix"):
        if s in st:
            return s
    return "unknown"


# ---------- Debian 版本比較（dpkg 的規則；deb-version(7)） ----------

def _deb_order(c):
    """dpkg 的字元順序：~ 比結尾小，結尾（''）與數字是 0，字母依 ASCII，其他符號排在所有字母之後。"""
    if c == "~":
        return -1
    if c == "" or (c.isascii() and c.isdigit()):
        return 0
    if c.isascii() and c.isalpha():
        return ord(c)
    return ord(c) + 256


def _verrevcmp(a, b):
    """dpkg 的 verrevcmp：非數字段逐字元以 _deb_order 比，數字段以數值比（前導 0 不算）。"""
    i = j = 0
    ch = lambda s, k: s[k] if k < len(s) else ""            # noqa: E731
    dig = lambda s, k: k < len(s) and s[k].isascii() and s[k].isdigit()   # noqa: E731
    while i < len(a) or j < len(b):
        while (i < len(a) and not dig(a, i)) or (j < len(b) and not dig(b, j)):
            ac, bc = _deb_order(ch(a, i)), _deb_order(ch(b, j))
            if ac != bc:
                return -1 if ac < bc else 1
            i, j = i + 1, j + 1
        while ch(a, i) == "0":
            i += 1
        while ch(b, j) == "0":
            j += 1
        first = 0
        while dig(a, i) and dig(b, j):
            if not first and a[i] != b[j]:
                first = -1 if a[i] < b[j] else 1
            i, j = i + 1, j + 1
        if dig(a, i):
            return 1
        if dig(b, j):
            return -1
        if first:
            return first
    return 0


def _deb_split(v):
    """[epoch:]upstream[-revision]：epoch 是第一個冒號前的數字（沒有時 0），revision 是最後一個 - 之後（沒有時空字串）。"""
    v = str(v).strip()
    epoch, _, rest = v.partition(":") if ":" in v and v.split(":", 1)[0].isdigit() else ("0", "", v)
    up, _, rev = rest.rpartition("-") if "-" in rest else (rest, "", "")
    return int(epoch), up, rev


def deb_vercmp(a, b):
    """比較兩個 Debian 版本：a < b → -1，相等 → 0，a > b → 1（依序比 epoch、upstream、revision）。"""
    ea, ua, ra = _deb_split(a)
    eb, ub, rb = _deb_split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _verrevcmp(ua, ub) or _verrevcmp(ra, rb)


deb_key = functools.cmp_to_key(deb_vercmp)


# ---------- 沒有 Grype 修補狀態的 Ubuntu 列：依 Ubuntu CVE Tracker（scan/ubuntu-status.json）推出修補狀態 ----------

# Tracker 的狀態 → 修補狀態。not-affected 不在這裡（證據規則 U1 有自己的版本規則）；needs-triage、DNE、沒有、conflict、認得以外的 → 不推。
# deferred 和 Grype 一樣當 not-fixed（Ubuntu CVE Tracker 的 deferred 是「暫緩處理」，之後還可能修；公開依據：Ubuntu CVE Tracker 對狀態的定義）：
# 同一個 Tracker 狀態在 Grype 的列與這裡推出的列套同一條規則
TRACKER_FIX = {"released": "fixed", "needed": "not-fixed", "pending": "not-fixed", "in-progress": "not-fixed",
               "deferred": "not-fixed", "ignored": "wont-fix"}
KERNEL_SRC = re.compile(r"^linux($|-)")


def tracker_fix(row, us):
    """一列（Ubuntu 的 deb 列，或有唯一擁有者的 Ubuntu 打包 Python 模組列：看擁有它的 deb 套件）的每個 CVE，在它的原始碼套件、這個發行版的
    Tracker 狀態 → {state, versions, fix_next, status, note, source_package, source_version, release, purl}；推不出來 → None。
    每個 CVE 都要有狀態、沒有 conflict、對應到同一個修補狀態；released 的註記要是 Debian 版本（安裝的原始碼版本 ≥ 註記 → 已修好，
    fix_next 是 None）。核心的列與核心的原始碼套件不推。"""
    if row.get("kernel") or not us or not row.get("cves"):
        return None
    o = (row.get("deb_python") or {}).get("owner")
    if row.get("ptype") != "deb" and not o:
        return None
    purl = (o or {}).get("purl") or row.get("purl") or ""
    if not purl.startswith("pkg:deb/ubuntu/"):
        return None
    comp = (us.get("components") or {}).get(purl)
    if not isinstance(comp, dict) or not all(isinstance(comp.get(k), str) and comp[k] for k in ("source", "source_version", "release")):
        return None
    src, sver, rel = comp["source"], comp["source_version"], comp["release"]
    if KERNEL_SRC.match(src):
        return None
    per = []
    for c in row["cves"]:
        e = (((us.get("entries") or {}).get(c.upper()) or {}).get(src) or {}).get(rel)
        if not isinstance(e, dict) or "conflict" in e:
            return None
        st, note = str(e.get("status") or ""), str(e.get("note") or "").strip()
        if st not in TRACKER_FIX or (st == "released" and vexmod().deb_version_parts(note) is None):
            return None
        per.append((c.upper(), st, note))
    states = {TRACKER_FIX[st] for _, st, _ in per}
    if len(states) != 1:
        return None
    state = states.pop()
    vers = sorted({n for _, st, n in per if st == "released"}, key=deb_key)
    return {"state": state, "versions": vers, "status": "/".join(sorted({st for _, st, _ in per})),
            "note": "; ".join(sorted({n for _, _, n in per if n})),
            "per_cve": [{"cve": c, "status": st, "note": n} for c, st, n in per],
            "fix_next": next_fix({"fix_state": state, "fix_versions": vers, "ptype": "deb", "version": sver}),
            "source_package": src, "source_version": sver, "release": rel, "purl": purl}


def tracker_status_text(status, note):
    """released 10.2.0-1ubuntu1.3；其他狀態的註記放括號：deferred (2026-10-22)、ignored (only affects Windows)。"""
    return f"{status} {note}" if status == "released" and note else f"{status} ({note})" if note else status


def tracker_text(t, mirror):
    """「fix state from Ubuntu CVE Tracker (commit X, YYYY-MM-DD): released 10.2.0-1ubuntu1.3」：VEX 陳述與修補欄用。日期是鏡像下載的日期。"""
    m = mirror or {}
    what = "; ".join(f"{x['cve']} " + tracker_status_text(x["status"], x["note"]) for x in t["per_cve"]) if len(t["per_cve"]) > 1 \
        else tracker_status_text(t["status"], t["note"])
    return (f"fix state from Ubuntu CVE Tracker (commit {str(m.get('commit') or '?')[:12]}, {str(m.get('fetched_utc') or '?')[:10]}): "
            f"{what} for source package {t['source_package']} in {t['release']}, installed source version {t['source_version']}")


def apply_ubuntu_tracker(rows, us_doc):
    """Grype 沒有修補狀態（fix_state「no Grype data」）的 Ubuntu 列（tracker_fix）依 Tracker 推出修補狀態：released → fixed（修補版本＝註記；
    安裝的原始碼版本比較新或一樣 → 已修好，沒有 {fix_version}）；needed／pending／in-progress／deferred → not-fixed；ignored → wont-fix
    （註記照寫進理由）。列記下 fix_state_source「ubuntu-tracker」、ubuntu_tracker（狀態、註記、commit、下載時間）與 fix_state_detail
    （VEX 規則的陳述附上）。Grype 有修補狀態的列照用 Grype 的；和 Tracker 推出的不同時列在回傳的 disagreements（交叉核對並列，不覆蓋）。
    scan/ubuntu-status.json 沒有、status 不是 OK（沒有鏡像、過期）或格式不對 → 什麼都不改。回傳 summary 用的統計。"""
    us, problem = vexmod().ubuntu_status_of(us_doc)
    info = {"status": "OK" if us else "not_available", "detail": problem, "derived": 0, "by_state": {}, "already_fixed": 0,
            "disagreements": []}
    if us is None:
        return info
    m = us.get("mirror") or {}
    prov = {"commit": m.get("commit"), "commit_date": m.get("commit_date"), "fetched_utc": m.get("fetched_utc")}
    by = Counter()
    for r in rows:
        if r.get("fix_state") not in ("no Grype data", "fixed", "not-fixed", "wont-fix") or r.get("fix_state_source"):
            continue
        t = tracker_fix(r, us)
        if t is None:
            continue
        txt = tracker_text(t, m)
        if r["fix_state"] != "no Grype data":
            # Grype 的修補狀態優先；Tracker 推出的狀態或修補版本不同 → 並列（不改這一列）
            gv = list(r["fix_versions"])
            if t["state"] != r["fix_state"] or (t["state"] == "fixed" and set(gv) != set(t["versions"])):
                info["disagreements"].append({"id": r["id"], "component": r["component"], "version": r["version"],
                                              "grype": {"fix_state": r["fix_state"], "fix_versions": gv},
                                              "tracker": {"fix_state": t["state"], "status": t["status"], "note": t["note"],
                                                          "source_package": t["source_package"], "release": t["release"]}})
            continue
        r["fix_state"], r["fix_versions"], r["fix_next"] = t["state"], t["versions"], t["fix_next"]
        r["fix_state_source"] = "ubuntu-tracker"
        r["ubuntu_tracker"] = {k: t[k] for k in ("status", "note", "per_cve", "source_package", "source_version", "release")} | prov
        r["fix_state_detail"] = txt
        if t["state"] == "fixed":
            ufix = (f"fixed in {', '.join(t['versions'])}" if t["fix_next"] else
                    f"already fixed in the installed source version (fixed in {', '.join(t['versions'])})")
        else:
            ufix = {"not-fixed": "not fixed yet", "wont-fix": "won't fix"}[t["state"]]
        o = (r.get("deb_python") or {}).get("owner")
        if o:
            r["fix"] = (f"update the Ubuntu package {o['name']} (installed {o['version']}), not pip; Ubuntu fix state: {ufix} ({txt})"
                        + (f"; the PyPI fix {', '.join(r['deb_python']['pypi_fix'])} does not apply to the distribution package"
                           if r["deb_python"].get("pypi_fix") else ""))
        else:
            r["fix"] = f"{ufix} ({txt})"
        info["derived"] += 1
        by[t["state"]] += 1
        info["already_fixed"] += t["state"] == "fixed" and not t["fix_next"]
    info["by_state"] = dict(sorted(by.items()))
    info["disagreements"].sort(key=lambda x: (x["id"], str(x["component"]), str(x["version"])))
    # 擁有者不明、但候選都來自同一個原始碼套件的 Python 模組（deb_python.source_owner）：Tracker 推出的修補狀態只記在
    # deb_python.source_owner_fix（批次規則用），這一列自己的修補欄照舊
    for r in rows:
        dp = r.get("deb_python") or {}
        sf = dp.get("source_owner_fix")
        if not sf or sf.get("fix_state") != "no Grype data":
            continue
        t = tracker_fix(dict(r, deb_python={"owner": dp["source_owner"]}), us)
        if t is None:
            continue
        sf.update(fix_state=t["state"], fix_versions=t["versions"], fix_next=t["fix_next"], fix_state_source="ubuntu-tracker",
                  fix_state_detail=tracker_text(t, m))
        info["derived_source_owner"] = info.get("derived_source_owner", 0) + 1
    return info


# ---------- 自成一列的 USN（沒有 CVE）：USN 是 Ubuntu 發布修補版本的公告 → 修補狀態取自它的修補版本 ----------

def usn_fixed_map(doc):
    """scan/usn-cves.json 的 fixed（tools/pilot/lib/usn_cves.py）→ {USN: {(ecosystem, 原始碼套件): [修補版本]}}；status 不是 OK、
    沒有 fixed（舊的掃描）、格式不對 → None。只收 USN-數字-數字 的鍵（鏡像資料不可信，只解析）。"""
    if not isinstance(doc, dict) or doc.get("status") != "OK" or not isinstance(doc.get("fixed"), dict):
        return None
    out = {}
    for k, xs in doc["fixed"].items():
        if not isinstance(k, str) or not USN_RE.match(k.upper()) or not isinstance(xs, list):
            continue
        for x in xs:
            if isinstance(x, dict) and isinstance(x.get("ecosystem"), str) and isinstance(x.get("package"), str) \
                    and isinstance(x.get("fixed"), list) and all(isinstance(v, str) for v in x["fixed"]) and x["fixed"]:
                out.setdefault(k.upper(), {})[(x["ecosystem"], x["package"].lower())] = list(x["fixed"])
    return out


def deb_purl_parts(purl):
    """pkg:deb/ubuntu/<名稱>@<版本>?… → (名稱, 版本, qualifiers)；不是 Ubuntu 的 deb purl → None。"""
    if not str(purl or "").startswith("pkg:deb/ubuntu/"):
        return None
    base, _, qs = str(purl).split("#", 1)[0].partition("?")
    name, _, ver = purl_path(base).rpartition("/")[2].partition("@")
    q = {k.lower(): urllib.parse.unquote(v[0]) for k, v in urllib.parse.parse_qs(qs).items() if v}
    return urllib.parse.unquote(name).lower(), urllib.parse.unquote(ver) or urllib.parse.unquote(base.rpartition("@")[2]), q


def apply_usn_fix(rows, usn_doc, comps=(), us_doc=None):
    """自成一列、沒有 CVE、Grype 沒有修補狀態的 USN 列（Ubuntu 的 deb 列，核心以外）：USN 的 OSV 紀錄（scan/usn-cves.json 的 fixed）裡
    這個原始碼套件在映像的 Ubuntu 版本（purl 的 distro：ubuntu-24.04 → Ubuntu:24.04:LTS 或 Ubuntu:24.04）的修補版本 V →
    fixed；安裝的原始碼版本比 V 舊 → {fix_version} 是 V（R3）；一樣或比較新 → 已修好（沒有 {fix_version}）。
    原始碼套件：purl 是 arch=source → 它自己；purl 的 upstream；SBOM 的 syft:metadata:source／sourceVersion；scan/ubuntu-status.json 的
    components；都沒有時，二進位名稱剛好是這個 USN 在這個 Ubuntu 版本列的套件才用它。不知道、紀錄沒有這個套件或版本、多個修補版本不同 → 不推。
    列記下 fix_state_source「usn」、usn（編號、套件、Ubuntu 版本、修補版本、紀錄的 modified、鏡像下載時間）與 fix_state_detail。回傳統計。"""
    fx = usn_fixed_map(usn_doc)
    info = {"status": "OK" if fx is not None else "not_available", "derived": 0, "already_fixed": 0, "not_derived": {}}
    if fx is None:
        return info
    fetched = str(((usn_doc.get("mirror") or {}) if isinstance(usn_doc.get("mirror"), dict) else {}).get("fetched_utc") or "?")[:10]
    usns = usn_doc.get("usns") if isinstance(usn_doc.get("usns"), dict) else {}
    srcs = {}
    for c in comps or ():
        if isinstance(c, dict) and isinstance(c.get("purl"), str) and c["purl"].startswith("pkg:deb/"):
            prop = {x.get("name"): x.get("value") for x in c.get("properties") or [] if isinstance(x, dict)}
            if isinstance(prop.get("syft:metadata:source"), str) and prop["syft:metadata:source"]:
                srcs[c["purl"]] = (prop["syft:metadata:source"].lower(), prop.get("syft:metadata:sourceVersion") or c.get("version"))
    ucomps = (us_doc.get("components") or {}) if isinstance(us_doc, dict) and us_doc.get("status") == "OK" else {}
    why = Counter()
    for r in rows:
        uid = str(r.get("id") or "").upper()
        if r.get("cves") or not USN_RE.match(uid) or r.get("fix_state") != "no Grype data" or r.get("kernel") or r.get("fix_state_source"):
            continue
        p = deb_purl_parts(r.get("purl"))
        if p is None:
            continue
        name, ver, q = p
        m = re.fullmatch(r"(?:ubuntu-)?(\d+\.\d+)", str(q.get("distro") or "").lower())
        recs = fx.get(uid) or {}
        if not m:
            why["release_unknown"] += 1
            continue
        if not recs:
            why["no_fixed_version_in_record"] += 1
            continue
        if q.get("arch") == "source":
            src, sver = name, ver
        elif q.get("upstream"):
            up, _, uv = q["upstream"].partition("@")
            src, sver = up.strip().lower() or name, uv.strip() or ver
        elif r.get("purl") in srcs:
            src, sver = srcs[r["purl"]]
        elif isinstance(ucomps.get(r.get("purl")), dict) and ucomps[r["purl"]].get("source"):
            src, sver = str(ucomps[r["purl"]]["source"]).lower(), ucomps[r["purl"]].get("source_version") or ver
        else:
            src, sver = name, ver      # 只有在這個 USN 列了這個名稱時才用（下面）
        if KERNEL_SRC.match(src):
            continue
        rel = m.group(1)
        hits = [(e, v) for (e, pkg), v in recs.items() if pkg == src and e in (f"Ubuntu:{rel}:LTS", f"Ubuntu:{rel}")]
        vers = sorted({x for _, v in hits for x in v}, key=deb_key)
        if not vers:
            why["package_not_in_record"] += 1
            continue
        if len(vers) > 1 or not sver:
            why["ambiguous"] += 1
            continue
        v, eco = vers[0], hits[0][0]
        nxt = next_fix({"fix_state": "fixed", "fix_versions": [v], "ptype": "deb", "version": sver})
        mod = str((usns.get(uid) or {}).get("modified") or "")[:10] if isinstance(usns.get(uid), dict) else ""
        r["fix_state"], r["fix_versions"], r["fix_next"], r["fix_state_source"] = "fixed", [v], nxt, "usn"
        r["usn"] = {"id": uid, "package": src, "ecosystem": eco, "fixed": v, "source_version": sver, "modified": mod or None,
                    "fetched_utc": (usn_doc.get("mirror") or {}).get("fetched_utc") if isinstance(usn_doc.get("mirror"), dict) else None}
        r["fix_state_detail"] = (f"fix state from Ubuntu security notice {uid} (OSV record" + (f" modified {mod}" if mod else "")
                                 + f", mirror fetched {fetched}): fixed in {v} for source package {src} in {eco}, installed source version {sver}")
        r["fix"] = (f"fixed in {v}" if nxt else f"already fixed in the installed source version (fixed in {v})") + f" ({r['fix_state_detail']})"
        info["derived"] += 1
        info["already_fixed"] += not nxt
    info["not_derived"] = dict(sorted(why.items()))
    return info


def tier_of(row, pol):
    """exploitation：P1＝已被利用（row["kev"]＝KEV 任一來源，或 row["exploited_sources"]＝EUVD、人工證據；apply_exploitation 加上）。
    被利用的列在這裡一律是 P1；要不要離開 P1 在 VEX 判定之後由 generate 決定（每個合併的 CVE 都要有人的判定，dt_complete、vex_ok），
    因為要看這一列與併進來的其他 CVE（vex_extra）各自的 VEX 陳述。P2＝DT 分析 EXPLOITABLE（任一筆 finding，**suppress 也一樣**：
    人判斷過可被利用，不能因為 suppress 變成 accepted；具名的 VEX exploitable 在 VEX 判定後由 generate 升到 P2），其他 P3。
    沒有被利用的列的 accepted 和 current 相同。"""
    acc = pol["accepted"]
    if scheme_of(pol) == "exploitation":
        if row["kev"] or row.get("exploited_sources"):
            return "p1"
        if any(a["state"] == "EXPLOITABLE" for a in row["analysis"]):
            return "p2"
    if scheme_of(pol) != "exploitation" and euvd_hit(row):
        # current：EUVD 標示已遭利用的列不因 DT 的 suppress 或沒有理由的判定變成 accepted（和 exploitation 相同；離開 P1 在 VEX 判定之後，
        # 只採用人的判定：DT 分析要每一筆 finding 都有理由，或具名的 vex-annotations.json）。KEV 的列在 current 照舊（原本帳號的決定）
        for t in ("p1", "p2"):
            if pol["tiers"][t].get("kev"):
                return t
        # 政策的 p1、p2 都沒有 kev 條件：不跳過其他條件，但也不進 accepted（下面的條件分到開放的層級，都不符合就是 P3）
    elif all((a["suppressed"] and acc.get("include_suppressed", True)) or a["state"] in acc.get("states", []) for a in row["analysis"]):
        return "accepted"
    if scheme_of(pol) == "exploitation":
        return "p2" if any(a["state"] == "EXPLOITABLE" for a in row["analysis"]) else "p3"
    for t in ("p1", "p2"):
        r = pol["tiers"][t]
        # EUVD 的被利用標記（exploited_sources；current 只有 EUVD）和 KEV 一樣符合 kev 條件：EUVD 的標記就是 CISA KEV ∪ ENISA EU KEV
        if (r.get("kev") and (row["kev"] or row.get("exploited_sources"))) \
                or (r.get("epss_percentile_min") is not None and row["epss_pct"] is not None and row["epss_pct"] >= r["epss_percentile_min"]) \
                or (r.get("epss_probability_min") is not None and row["epss"] is not None and row["epss"] >= r["epss_probability_min"]) \
                or row["severity"] in (r.get("severities") or []) \
                or (r.get("cvss_min") is not None and row["cvss_score"] is not None and row["cvss_score"] >= r["cvss_min"]
                    and row.get("severity_source", "nvd-cvss") in ("nvd-cvss", "other")):
            return t
    return "p3"


def rule_text(t, pol, euvd=False):
    """euvd：掃描輸出有 scan/euvd.json（current 的 kev 條件也收 EUVD 的被利用標記；沒有檔案時文字和以前一樣）。"""
    if t == "accepted":
        a = pol["accepted"]
        parts = [f"analysis state in {{{', '.join(a.get('states') or [])}}}"] + (["suppressed in Dependency-Track"] if a.get("include_suppressed", True) else [])
        vs = sorted({x.lower() for x in a.get("states") or []} & {"not_affected", "false_positive"})
        return ("every Dependency-Track finding merged into the row is " + " or ".join(parts)
                + (f"; or the VEX status of every vulnerability merged into the row is {' or '.join(vs)} (a decision in "
                   "vex-annotations.json or the kernel configuration check; for rows in a KEV catalogue only a decision by a named person "
                   "counts)" if vs else ""))
    if scheme_of(pol) == "exploitation":
        return {"p1": "exploited: listed in a Known Exploited Vulnerabilities catalogue (CISA/ENISA KEV, any source), marked exploited "
                      "by EUVD (`scan/euvd.json`), or manual exploitation evidence (`CRA/Config/exploitation-evidence.json`); and not "
                      "assessed as not affected by a person: an exploited row is accepted only when every CVE merged into the row "
                      "has a person's not_affected, false_positive or resolved decision – a named decision in vex-annotations.json, or "
                      "Dependency-Track analyses on every finding of the row (NOT_AFFECTED with a justification or details, "
                      "FALSE_POSITIVE with a justification, RESOLVED with details); a row where only some findings have a "
                      "Dependency-Track decision, suppression alone, or a decision without justification or details stays P1)",
                "p2": "no exploitation evidence, but assessed exploitable by a person: Dependency-Track analysis state EXPLOITABLE "
                      "(also when suppressed), or "
                      "a named exploitable decision in vex-annotations.json (an exploitable statement from a bulk VEX rule leaves the "
                      "row in P3; the rule is shown in the VEX status column)",
                "p3": "all other open findings (not assessed, in triage, exploitable only by a bulk rule, or assessed without an "
                      "exploitable decision)"}[t]
    if t == "p3":
        return "all other open findings (including severity UNASSIGNED)"
    r, parts = pol["tiers"][t], []
    if r.get("kev"):
        parts.append("listed in a Known Exploited Vulnerabilities catalogue (CISA/ENISA KEV)"
                     + (" or marked exploited by EUVD (`scan/euvd.json`: CISA KEV or ENISA EU KEV)" if euvd else ""))
    if r.get("epss_percentile_min") is not None:
        parts.append(f"EPSS percentile ≥ {r['epss_percentile_min']}")
    if r.get("epss_probability_min") is not None:
        parts.append(f"EPSS probability ≥ {r['epss_probability_min']}")
    if r.get("severities"):
        parts.append(f"severity in {{{', '.join(r['severities'])}}}")
    if r.get("cvss_min") is not None:
        parts.append(f"CVSS base score ≥ {r['cvss_min']}")
    return " OR ".join(parts) or "(no criteria: never matches)"


def kev_text(r):
    """KEV 欄：只有這一列自己的 DT finding 是 KEV → YES；其他來源寫在括號（same CVE＝DT 在同一個 CVE 的別筆紀錄；Grype＝Grype 的 knownExploited）。"""
    # 分級方式 exploitation：KEV 以外的被利用證據（EUVD、人工證據）並列在後面（current 沒有 exploited_sources，欄位和以前一樣）
    more = f"; exploited: {'; '.join(r['exploited_sources'])}" if r.get("exploited_sources") else ""
    if not r["kev"]:
        return "no" + more
    src = r.get("kev_sources") or (["same CVE"] if r.get("kev_by_cve") else ["DT"])
    return ("YES" if src == ["DT"] else f"YES ({'; '.join(src)})") + more


def epss_text(r):
    """EPSS 欄：這一列自己的 DT 值「機率 (p百分位)」；同一個 CVE 的其他來源不同時並列（來源、CVE、日期），註明不拿來分級。"""
    def one(p, pct):
        return (f"{p:.4f}" if p is not None else "—") + (f" (p{pct:.3f})" if pct is not None else "")
    own = one(r["epss"], r["epss_pct"]) if r["epss"] is not None or r["epss_pct"] is not None else None
    oth = r.get("epss_other") or []
    if not oth:
        return own
    many = len(r.get("cves") or []) > 1
    parts = [f"{x['source']} {one(x['probability'], x['percentile'])}"
             + "".join(f" {y}" for y in ((f"for {x['cve']}" if many else ""), (f"[{x['date']}]" if x.get("date") else "")) if y) for x in oth]
    return "; ".join(([own] if own else []) + parts) + " (other sources: not used for tiers)"


def epss_note(rows, pol, have_grype=True):
    """8.3 節 EPSS 的說明與 summary.json 的 counts.epss。"""
    n_dt = sum(1 for r in rows if (r["epss"] is not None or r["epss_pct"] is not None) and not r.get("found_by"))
    # 只有 Grype 的列：這一列自己的值就是 Grype 的 EPSS（沒有 DT finding）；有這種列時才多一個計數與一句
    n_go = sum(1 for r in rows if (r["epss"] is not None or r["epss_pct"] is not None) and r.get("found_by") == GRYPE_ONLY)
    oth = [r for r in rows if r.get("epss_other")]
    only = [r for r in oth if r["epss"] is None and r["epss_pct"] is None]
    by = Counter(x["source"] for r in oth for x in r["epss_other"])
    dates = sorted({x["date"] for r in oth for x in r["epss_other"] if x.get("date")})
    # 分級方式 exploitation 不用 EPSS（tiers 的條件都不用）
    rules = {t: {k: (pol["tiers"][t].get(k) if scheme_of(pol) == "current" else None) for k in ("epss_probability_min", "epss_percentile_min")}
             for t in ("p1", "p2")}
    used = [f"{t.upper()} " + " or ".join(f"{'probability' if k == 'epss_probability_min' else 'percentile'} ≥ {v}"
                                          for k, v in rules[t].items() if v is not None)
            for t in ("p1", "p2") if any(v is not None for v in rules[t].values())]
    counts = {"dt": n_dt, "other_sources_shown": len(oth), "only_other_sources": len(only), "by_source": dict(sorted(by.items())),
              "grype_score_dates": dates if have_grype else None, "rules": rules}
    if any(r.get("found_by") == GRYPE_ONLY for r in rows):
        counts["grype_only_rows"] = n_go
    if not rows:
        return "", counts
    text = ("EPSS (FIRST's Exploit Prediction Scoring System) is shown as the probability of exploitation activity in the next "
            "30 days, with its percentile in brackets. The percentile ranks the CVE against all scored CVEs on the score date and "
            "moves when other CVEs are scored, so the same percentile does not mean the same probability over time. "
            + (f"EPSS rules in the tiers: {'; '.join(used)}, evaluated on the EPSS of the row's own Dependency-Track findings "
               f"({plural(n_dt, 'row')} {verb(n_dt, 'has', 'have')} one)." if used else
               f"No tier uses EPSS ({plural(n_dt, 'row')} {verb(n_dt, 'has', 'have')} an EPSS value from Dependency-Track).")
            + (f" For {plural(len(oth), 'row')} another source has a different EPSS for the same CVE ("
               + ", ".join(f"{k} {by[k]}" for k in sorted(by)) + (f"; Grype score date {', '.join(dates)}" if dates else "")
               + (f"; {len(only)} of these rows {verb(len(only), 'has', 'have')} no EPSS of {verb(len(only), 'its', 'their')} own" if only else "")
               + "): it is shown next to the row's value and is not used for the tiers." if oth else "")
            + (f" Rows found only by Grype have no Dependency-Track finding: their own EPSS is Grype's ({plural(n_go, 'row')} "
               f"{verb(n_go, 'has', 'have')} one)." if n_go else ""))
    return text, counts


# ---------- 分級方式 exploitation（vulnerability_policy.scheme，選用；使用者決定 2026-11-05，主管核定前預設不用） ----------

EVIDENCE_REL = Path("CRA") / "Config" / "exploitation-evidence.json"      # 人工的被利用證據（客戶回報、供應商公告…）
EVIDENCE_SCHEMA = "sca-center-exploitation-evidence/1"
EVIDENCE_KEYS = {"cve", "source", "date", "owner", "note"}
SERVICES_REL = Path("CRA") / "Config" / "exposed-services.json"          # 對外服務清單（板子上 ss -lntup＋dpkg -S；board_import 匯入）
SERVICES_SCHEMA = "sca-center-exposed-services/1"
SERVICE_KEYS = {"program", "package", "purl", "protocol", "port", "address", "note"}
CRA_APPLY_DATE = "2027-12-11"      # CRA 主要義務開始適用（Art. 71(2)）；出貨關卡從這天起多擋 P2 與「必須判斷範圍」內沒判斷的列
DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
CVE_ONLY_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
# 負責人欄的佔位字（vex_export.author_missing 之外再加；比對前去掉空白、轉小寫）；只有標點符號的也算
OWNER_PLACEHOLDERS = {"tbd", "tba", "todo", "n/a", "na", "none", "null", "unknown", "owner", "xxx", "待定", "未定", "待補", "不明", "無"}
# 必須判斷範圍的對外元件條件（使用者決定 f347d53「範圍更新」，取代供應商評級 HIGH／CRITICAL）：CVSS 基本分數（各來源取最高）≥ 7 而且
# AV:N 或 AV:A（向量不明 → 偏保守納入）；完全沒有 CVSS 時 Ubuntu priority high／critical。
CVSS_SCOPE_MIN = 7.0
AV_RE = re.compile(r"(?:^|[/(])AV:([NALP])(?:[/)]|$)")      # CVSS v2「(AV:N/…)」、v3／v4「CVSS:3.1/AV:N/…」
AV_NAME = {"N": "network", "A": "adjacent", "L": "local", "P": "physical"}
NO_DATA_REASON = "no CVSS and no Ubuntu priority on an exposed component (GAP)"


def _date_ok(v):
    try:
        return isinstance(v, str) and bool(DATE_RE.match(v)) and bool(datetime.date.fromisoformat(v))
    except ValueError:
        return False


def _text_ok(v):
    return isinstance(v, str) and bool(v.strip())


def owner_missing(v):
    """負責人沒寫：空白、vex_export 的佔位字（專案負責人、(your name)…）、OWNER_PLACEHOLDERS，或只有標點符號（-、?、—）。"""
    if vexmod().author_missing(v):
        return True
    s = v.strip().casefold()
    return s in OWNER_PLACEHOLDERS or not any(ch.isalnum() for ch in s)


def _read_config_json(project, rel, schema, list_key, what):
    """CRA/Config 下的 JSON 檔：不存在 → (None, None)；不是 JSON、schema 不對 → Fail。回傳 (doc, 原始 bytes)。"""
    p = Path(project) / rel
    if not p.is_file():
        return None, None
    raw = p.read_bytes()
    try:
        doc = json.loads(raw.decode("utf-8-sig"))      # 接受 UTF-8 BOM（Windows 編輯器存的檔）
    except (UnicodeDecodeError, ValueError) as e:
        raise Fail(f"{what}（{rel}）不是 JSON：{e}")
    if not isinstance(doc, dict) or doc.get("schema") != schema or not isinstance(doc.get(list_key), list):
        raise Fail(f"{what}（{rel}）要是 {{\"schema\": \"{schema}\", \"{list_key}\": [...]}}")
    return doc, raw


def load_exploitation_evidence(project, today):
    """CRA/Config/exploitation-evidence.json → (證據清單（cve 轉大寫）, {file, sha256, count} 或 None)。
    每筆：cve（CVE-…，只收 ASCII 數字）、source（例如 customer report、vendor advisory）、date（YYYY-MM-DD，最多晚於 today＝報告日 UTC 一天）、
    owner（負責人或職務，不可是佔位字）、note（理由：證據寫了什麼、在哪裡；專案規則「人工判斷要記理由」）都必填。
    不認得的鍵、同一個 CVE、同一個來源、同一天兩筆 → Fail（和其他設定錯誤一樣，不產生文件）。"""
    doc, raw = _read_config_json(project, EVIDENCE_REL, EVIDENCE_SCHEMA, "evidence", "被利用證據檔")
    if doc is None:
        return [], None
    errs = [f"不認得的鍵 {', '.join(sorted(set(doc) - {'schema', 'evidence', '$comment'}))}"] if set(doc) - {"schema", "evidence", "$comment"} else []
    seen = {}
    for i, e in enumerate(doc["evidence"]):
        w = f"evidence[{i}]"
        if not isinstance(e, dict):
            errs.append(f"{w}：要是物件")
            continue
        errs += [f"{w}.{k}：不認得的鍵" for k in sorted(set(e) - EVIDENCE_KEYS)]
        errs += [f"{w}.{k}：必填（文字）" for k in ("cve", "source", "date", "owner", "note") if not _text_ok(e.get(k))]
        if _text_ok(e.get("cve")) and not CVE_ONLY_RE.match(e["cve"].strip().upper()):
            errs.append(f"{w}.cve：要是 CVE 編號（例如 CVE-2024-3094）")
        if _text_ok(e.get("date")):
            if not _date_ok(e["date"].strip()):
                errs.append(f"{w}.date：要是 YYYY-MM-DD")
            elif e["date"].strip() > (datetime.date.fromisoformat(today) + datetime.timedelta(days=1)).isoformat():
                # 報告日是 UTC；台灣 00:00–08:00 寫的「今天」在 UTC 是明天，所以容許一天
                errs.append(f"{w}.date：{e['date'].strip()} 晚於報告日 {today}（UTC）超過一天")
        if _text_ok(e.get("owner")) and owner_missing(e["owner"]):
            errs.append(f"{w}.owner：要寫負責人或職務（不能是佔位字 {e['owner'].strip()}）")
        if all(_text_ok(e.get(k)) for k in ("cve", "source", "date")):
            k = (e["cve"].strip().upper(), e["source"].strip().casefold(), e["date"].strip())
            if k in seen:
                errs.append(f"{w}：和 evidence[{seen[k]}] 是同一個 CVE、同一個來源、同一天（{k[0]}、{e['source'].strip()}、{k[2]}）")
            seen.setdefault(k, i)
    if errs:
        raise Fail(f"被利用證據檔（{EVIDENCE_REL}）不符合格式：" + "；".join(errs))
    ev = [dict({k: v.strip() for k, v in e.items() if isinstance(v, str)}, cve=e["cve"].strip().upper()) for e in doc["evidence"]]
    return ev, {"file": str(EVIDENCE_REL), "sha256": hashlib.sha256(raw).hexdigest(), "count": len(ev)}


def service_packages(v):
    """package 欄 → Debian 套件名稱清單：可以是文字或文字清單；dpkg -S 一個檔案屬於多個套件時是「a, b」，逗號或空白分開；
    「名稱:架構」的架構去掉，轉小寫。"""
    vals = [v] if isinstance(v, str) else list(v)
    return sorted({p.split(":", 1)[0].lower() for x in vals for p in re.split(r"[,\s]+", x.strip()) if p.split(":", 1)[0]})


def load_exposed_services(project, today=None):
    """CRA/Config/exposed-services.json → (服務清單, {file, sha256, collected, source, count} 或 None＝沒有清單)。
    格式：{"schema", "collected"（YYYY-MM-DD，必填）, "source"（選填：哪一塊板子、哪個映像、怎麼收集）, "services": [...]}；
    每個服務：program（監聽的程式）、protocol（tcp／udp）、port（1–65535）必填，package（dpkg -S 的 Debian 套件名稱：文字或清單，
    「a, b」會分開，「名稱:架構」的架構會去掉）或 purl（不是 deb 的元件）至少一個，address、note 選填。
    空清單＝確認沒有對外服務。格式錯 → Fail。每個服務加上 packages（service_packages）。"""
    doc, raw = _read_config_json(project, SERVICES_REL, SERVICES_SCHEMA, "services", "對外服務清單")
    if doc is None:
        return [], None
    top = {"schema", "collected", "source", "services", "kernel_network", "$comment"}
    errs = [f"不認得的鍵 {', '.join(sorted(set(doc) - top))}"] if set(doc) - top else []
    if not _date_ok(doc.get("collected")):
        errs.append("collected：必填（收集日期 YYYY-MM-DD）")
    elif today and doc["collected"] > (datetime.date.fromisoformat(today) + datetime.timedelta(days=1)).isoformat():
        errs.append(f"collected：{doc['collected']} 晚於報告日 {today}（UTC）超過一天")
    kn = doc.get("kernel_network")
    if kn is not None:
        if not isinstance(kn, dict) or set(kn) - {"interfaces", "note"} or not isinstance(kn.get("interfaces"), list) \
                or not kn["interfaces"] or not all(_text_ok(x) for x in kn["interfaces"]) or ("note" in kn and not _text_ok(kn["note"])):
            errs.append("kernel_network：要是 {\"interfaces\": [\"eth0\", …], \"note\": \"…\"}（使用中的網路介面，至少一個；note 選填）")
    if "source" in doc and not _text_ok(doc["source"]):
        errs.append("source：要是文字")
    for i, x in enumerate(doc["services"]):
        w = f"services[{i}]"
        if not isinstance(x, dict):
            errs.append(f"{w}：要是物件")
            continue
        errs += [f"{w}.{k}：不認得的鍵" for k in sorted(set(x) - SERVICE_KEYS)]
        if not _text_ok(x.get("program")):
            errs.append(f"{w}.program：必填（監聽的程式，例如 /usr/sbin/sshd）")
        if x.get("protocol") not in ("tcp", "udp"):
            errs.append(f"{w}.protocol：只能是 tcp、udp")
        if not (isinstance(x.get("port"), int) and not isinstance(x.get("port"), bool) and 1 <= x["port"] <= 65535):
            errs.append(f"{w}.port：要是 1–65535 的整數")
        pk = x.get("package")
        pk_ok = _text_ok(pk) or (isinstance(pk, list) and bool(pk) and all(_text_ok(y) for y in pk))
        if "package" in x and not pk_ok:
            errs.append(f"{w}.package：要是文字或文字清單")
        elif pk_ok and any("/" in t or t.endswith(":") for x in ([pk] if isinstance(pk, str) else pk) for t in re.split(r"[,\s]+", x.strip())):
            errs.append(f"{w}.package：看起來是貼上的 dpkg -S 輸出（{pk if isinstance(pk, str) else ', '.join(pk)}）；只寫套件名稱，"
                        "例如 \"openssh-server\" 或 \"openssh-server:arm64\"，多個套件用逗號分開或寫成清單；程式路徑寫在 program")
        elif pk_ok and not service_packages(pk):
            errs.append(f"{w}.package：沒有套件名稱")
        if not pk_ok and not _text_ok(x.get("purl")):
            errs.append(f"{w}：package（dpkg -S 的套件名稱）或 purl 至少要有一個；不是套件裝的程式請人工對應到 SBOM 元件的 purl")
        for k in ("address", "note"):
            if k in x and not _text_ok(x[k]):
                errs.append(f"{w}.{k}：要是文字")
        if "purl" in x and (not _text_ok(x["purl"]) or vexmod().purl_split(x["purl"])[0] is None):
            errs.append(f"{w}.purl：不是 purl（pkg:類型/名稱）")
    if errs:
        raise Fail(f"對外服務清單（{SERVICES_REL}）不符合格式：" + "；".join(errs))
    svcs = [dict(x, packages=service_packages(x["package"]) if x.get("package") else []) for x in doc["services"]]
    return svcs, {"file": str(SERVICES_REL), "sha256": hashlib.sha256(raw).hexdigest(), "collected": doc["collected"],
                  "source": doc.get("source"), "count": len(svcs),
                  "kernel_network": {"interfaces": [x.strip() for x in kn["interfaces"]], **({"note": kn["note"]} if kn.get("note") else {})}
                  if kn else None}


def euvd_exploited(doc, loose=False):
    """scan/euvd.json 標示已遭利用（exploited == "yes"）的 CVE；檔案沒有或格式不對 → None（和 vex_export 的規則用同一個讀法）。
    loose：分級方式 exploitation 用，yes 不分大小寫、CVE 轉大寫（current 的批次規則照舊只認 "yes"，輸出不變）。"""
    if isinstance(doc, dict) and isinstance(doc.get("cves"), dict):
        if loose:
            return sorted({str(c).upper() for c, x in doc["cves"].items() if isinstance(x, dict) and str(x.get("exploited")).strip().lower() == "yes"})
        return sorted(c for c, x in doc["cves"].items() if isinstance(x, dict) and x.get("exploited") == "yes")
    return None


# EUVD 的 kev_sources（kev/dump 的 sources）→ KEV 欄與 summary 的名稱：EUVD 的已遭利用標記就是這兩份清單的聯集（tools/pilot/lib/euvd.md）
EUVD_CATALOGUES = {"cisa_kev": "CISA KEV", "eukev_kev": "ENISA EU KEV"}
EUVD_OPEN_LABEL = "Open rows marked exploited by EUVD (CISA KEV / ENISA EU KEV via `scan/euvd.json`)"


def euvd_catalogues(doc):
    """scan/euvd.json 標示已遭利用的 CVE → EUVD 寫的 KEV 清單（kev_sources，排序、去重；沒寫＝[]）。yes 不分大小寫、CVE 轉大寫
    （同 euvd_exploited 的 loose）。檔案沒有或格式不對 → None。status 由呼叫端判斷（不是 OK → 當作沒有資料）。"""
    if not (isinstance(doc, dict) and isinstance(doc.get("cves"), dict)):
        return None
    out = {}
    for c, x in doc["cves"].items():
        if isinstance(x, dict) and str(x.get("exploited")).strip().lower() == "yes":
            ks = x.get("kev_sources") if isinstance(x.get("kev_sources"), list) else []
            out.setdefault(str(c).upper(), set()).update(str(k) for k in ks if isinstance(k, str) and k.strip())
    return {c: sorted(v) for c, v in sorted(out.items())}


def euvd_label(sources):
    """KEV 欄的 EUVD 來源：EUVD (CISA KEV)、EUVD (ENISA EU KEV)、EUVD (CISA KEV, ENISA EU KEV)；沒寫清單時只寫 EUVD。"""
    names = [EUVD_CATALOGUES.get(k, k) for k in sources or ()]
    return "EUVD" + (f" ({', '.join(names)})" if names else "")


def row_order(r, euvd=False):
    """風險表的排序：KEV 在前（euvd：EUVD 的列和 KEV 同一級），再依 EPSS 百分位、嚴重度、編號、元件、版本。"""
    return (not (r["kev"] or (euvd and euvd_hit(r))), -(r["epss_pct"] or 0), SEV_RANK.get(r["severity"], 9), r["id"],
            r["component"].lower(), r["version"])


def euvd_hit(r):
    """這一列有 EUVD 的被利用標記（exploited_sources 裡 EUVD 開頭的）。EUVD 不設 row["kev"]（另一種被利用證據，使用者決定）。"""
    return any(str(x).startswith("EUVD") for x in r.get("exploited_sources") or [])


def euvd_unavailable_reason(status, path, stage=None):
    """EUVD 不能用時，風險評估文件 GAP 的理由（只在這裡產生；exploitation 由 exploitation_section、current 由 generate 加進文件狀態，
    兩者不會同時出現）。status：檔案的 status（不是 OK 的）；path：檔案；stage：沒有檔案時 status.tsv 的 C-euvd 狀態（None＝沒有這一行）。"""
    return ("EUVD exploited list not available (" + ("status " + status if status else "unreadable" if path
                                                       else f"C-euvd {stage}, no scan/euvd.json" if stage else "no scan/euvd.json")
            + "): EU-KEV entries added after 2026-08 may be missing")


def apply_exploitation(rows, pol, euvd_cves, evidence):
    """KEV 以外的被利用證據記在 row["exploited_sources"]（EUVD (清單)、manual: 來源, 日期；CVE 是併進這一列的別名、不是這一列的編號時
    加「for CVE-…」），層級重算。euvd_cves：{CVE: EUVD 的 kev_sources}（euvd_catalogues；CVE 清單也可以；None／空＝沒有 EUVD 資料）。
    兩種分級方式都用（current 只傳 EUVD，人工證據只在 exploitation 用）。
    回傳 {CVE: 對到的列數}（人工證據；一個 CVE 有幾筆證據都只算一次；0＝沒有對到）。"""
    eu = ({str(c).upper(): v for c, v in euvd_cves.items()} if isinstance(euvd_cves, dict)
          else {str(c).upper(): [] for c in euvd_cves or ()})       # CVE 清單（沒有 KEV 清單的資料）也收
    used = Counter({e["cve"]: 0 for e in evidence})
    for r in rows:
        cs = {c.upper() for c in r["cves"]}
        rid = str(r["id"]).upper()
        src = [f"{euvd_label(eu[c])}{'' if c == rid else ' for ' + c}" for c in sorted(cs & set(eu))]
        hits = sorted((e for e in evidence if e["cve"] in cs), key=lambda e: (e["cve"], e["source"].casefold(), e["date"]))
        src += [f"manual: {e['source']}, {e['date']}{'' if e['cve'] == rid else ' for ' + e['cve']}" for e in hits]
        used.update({e["cve"] for e in hits})
        if src:
            r["exploited_sources"] = src
            r["exploited_evidence"] = [{k: e.get(k) for k in ("cve", "source", "date", "owner", "note") if e.get(k)} for e in hits]
            r["tier"] = tier_of(r, pol)
    return dict(sorted(used.items()))


def exploited(r):
    return bool(r.get("kev") or r.get("exploited_sources"))


def nvidia_exploited_findings(nvb, have, euvd_doc, evidence, use_evidence):
    """NVIDIA 公告的 CVE（presumed_included、needs_vendor_confirmation，沒有 DT／NVIDIA finding）中已遭利用的（EUVD 的 KEV 標記，
    或人工證據〔分級方式 exploitation〕）→ 合成 finding（元件＝Jetson Linux 的錨點套件），讓它和其他列一樣成為真正的列：
    進 P1 的計數、8.4 節、出貨關卡、必須判斷的計數與風險表（exploited_sources 由 apply_exploitation 填入真正的來源，不設 kev）。
    have：已有的 finding（DT＋NVIDIA 已審核的）；同一個 CVE 在 nvidia-l4t 元件上已有 finding 就不再加。
    EUVD 檔案的 status 不是 OK 時不用（同 apply_exploitation 的輸入）。"""
    if not isinstance(nvb, dict) or not isinstance(nvb.get("jetson_linux"), dict):
        return []
    anchor = nvb["jetson_linux"].get("anchor") or {}
    if not anchor.get("name"):
        return []
    hot = set()
    if isinstance(euvd_doc, dict) and euvd_doc.get("status") == "OK":
        hot |= set(euvd_catalogues(euvd_doc) or {})
    if use_evidence:
        hot |= {str(e["cve"]).upper() for e in evidence}
    if not hot:
        return []
    on_l4t = set()
    for f in have:
        c = (f.get("component") or {}) if isinstance(f, dict) else {}
        if str(c.get("name") or "").startswith("nvidia-l4t"):
            on_l4t |= {x.upper() for x in cves_of(ids_of(f.get("vulnerability") or {}))}
    out, seen = [], set()
    for k in ("presumed_included", "needs_vendor_confirmation"):
        for x in nvb.get(k) or []:
            cve = str(x.get("cve") or "").upper() if isinstance(x, dict) else ""
            if not cve or cve in seen or cve not in hot or cve in on_l4t:
                continue
            seen.add(cve)
            out.append({"component": {"name": anchor["name"], "version": anchor.get("version") or "", "purl": anchor.get("purl") or ""},
                        "vulnerability": {"vulnId": cve, "source": "NVIDIA", "aliases": [{"cveId": cve}], "severity": "UNASSIGNED",
                                          "description": "NVIDIA security bulletin CVE (presumed included or needs confirmation); "
                                                         "added as a row because it is marked as exploited"}})
    return out


def dt_usable_decision(a, acc):
    """一筆 DT 分析是不是「人判斷過不受影響或已修補」：NOT_AFFECTED 有 justification（CycloneDX 的值）或 details、FALSE_POSITIVE 有
    justification（兩者也要在政策的 accepted.states 裡；和 vex_export.from_dt 能當陳述的規則一致）、RESOLVED 有 details（使用者決定 B）。"""
    vx = vexmod()
    st = a.get("state")
    just = str(a.get("justification") or "").lower() in vx.CDX_JUST
    det = bool(str(a.get("details") or "").strip())
    if st == "NOT_AFFECTED":
        return (just or det) and st in acc.get("states", [])
    if st == "FALSE_POSITIVE":
        return just and st in acc.get("states", [])
    return st == "RESOLVED" and det


def dt_complete(row, acc):
    """被利用的列（分級方式 exploitation）採用 DT 判定的條件（使用者決定 A）：這一列**每一筆** finding 都有人判斷過不受影響或已修補
    （dt_usable_decision）；只有部分 finding 有判定、只有 suppress、沒有理由 → 不離開 P1（和 current 一樣嚴格，可能和 VEX 不同，範圍表標出）。"""
    an = row.get("analysis") or []
    return bool(an) and all(dt_usable_decision(a, acc) for a in an)


def link_inherited_owners(rows):
    """分級方式 exploitation：沿用 DT 判定的列（vex_export.inherit_deb_python，Ubuntu 打包的 Python 模組）記下擁有它的 deb 列
    （row["dt_inherited_owners"]，以 vex["inherited_from"] 的編號、元件、版本對），供 inherited_dt_usable 檢查擁有者的 DT 判定。"""
    idx, allr = {}, [x for r in rows for x in [r] + (r.get("vex_extra") or [])]     # inherit_deb_python 也看拆出來的 CVE（vex_extra）
    for d in allr:
        if d.get("ptype") == "deb":
            idx.setdefault((str(d.get("id")), d.get("component"), d.get("version")), []).append(d)
    for r in allr:
        v = r.get("vex") or {}
        f = v.get("inherited_from")
        if v.get("source") == "dt" and f:
            r["dt_inherited_owners"] = [d for d in idx.get((str(f.get("id")), f.get("component"), f.get("version")), []) if d is not r]


def inherited_dt_usable(row, acc):
    """沿用來的 DT 判定在被利用的列上算不算人的判定（審查）：擁有它的 deb 列每一筆 finding 都要判過（dt_complete；RESOLVED 要有
    details，使用者決定 B）——和 deb 列自己離開 P1 的條件相同。對不到擁有者 → 不算（偏保守）。"""
    owners = row.get("dt_inherited_owners") or []
    return bool(owners) and all(dt_complete(o, acc) for o in owners)


def dt_decided_counts(row, acc):
    """這一列 DT finding 的判定情形（範圍表的「partially assessed: N of M findings (…)」）：decided＝能用的不受影響／已修補判定
    （dt_usable_decision）、without_reason＝NOT_AFFECTED／FALSE_POSITIVE／RESOLVED 但沒有 justification 或 details（或不在 accepted.states）、
    other_state＝EXPLOITABLE、IN_TRIAGE 等其他狀態、not_analysed＝沒有 DT 狀態（沒分析或只有 suppress）、total。"""
    an = row.get("analysis") or []
    c = Counter()
    for a in an:
        st = a.get("state")
        c["decided" if dt_usable_decision(a, acc) else "without_reason" if st in ("NOT_AFFECTED", "FALSE_POSITIVE", "RESOLVED")
          else "other_state" if st else "not_analysed"] += 1
    return {"decided": c["decided"], "total": len(an), "without_reason": c["without_reason"], "other_state": c["other_state"],
            "not_analysed": c["not_analysed"]}


def partial_text(d):
    """「partially assessed: 1 of 2 findings (1 without justification or details)」。"""
    more = [f"{d['without_reason']} without justification or details" if d["without_reason"] else "",
            f"{d['not_analysed']} not analysed" if d["not_analysed"] else "",
            f"{d['other_state']} with another analysis state" if d["other_state"] else ""]
    return f"partially assessed: {d['decided']} of {d['total']} findings" + (f" ({', '.join(x for x in more if x)})" if any(more) else "")


RESOLVED_NO_DETAILS = "RESOLVED without details (does not count for an exploited row)"


def resolved_without_details(row, acc):
    """這一列 DT 分析中 RESOLVED 但沒有 details 的筆數（使用者決定 B：被利用的列不算判定；VEX 照樣寫 resolved (DT)）。"""
    return sum(1 for a in row.get("analysis") or [] if a.get("state") == "RESOLVED" and not dt_usable_decision(a, acc))


def unassessed_note(r, acc):
    """被利用、範圍內、沒有算判斷過、也不是「部分 finding 有判定」（partial_text）的列，VEX 卻看起來有結論時的原因（範圍表的 Assessed 欄、
    關卡理由；審查的低）：(a) DT 的判定只有 RESOLVED 沒有 details（VEX resolved (DT)）；沿用來的 DT 判定在擁有它的 deb 列上是這樣；
    (b) 這一列有陳述，但併進來的其他 CVE（vex_extra）沒有陳述。回傳文字或 None。"""
    out = []
    n, tot = resolved_without_details(r, acc), len(r.get("analysis") or [])
    if n and not dt_decided_counts(r, acc)["decided"]:
        out.append(RESOLVED_NO_DETAILS + (f" on {n} of {tot} findings" if n < tot else ""))
    v = r.get("vex") or {}
    f = v.get("inherited_from")
    if v.get("source") == "dt" and f and not inherited_dt_usable(r, acc):
        on = [o for o in r.get("dt_inherited_owners") or [] if not dt_complete(o, acc)]
        why = ([RESOLVED_NO_DETAILS] if any(resolved_without_details(o, acc) for o in on) else []) \
            or [partial_text(dt_decided_counts(o, acc)) for o in on[:1]] or ["owning row not found"]
        out.append(f"decision inherited from {f.get('component')} {f.get('version')}: {why[0]}")
    missing = [str(x.get("id")) for x in r.get("vex_extra") or [] if not x.get("vex")]
    if missing and v.get("state") and v["state"] != "in_triage":
        out.append("no statement for merged " + ", ".join(missing))
    return "; ".join(out) or None


def human_vex(v):
    """人做的 VEX 判定：DT 的分析，或 vex-annotations.json 裡具名的判定（批次規則、自動來源不算）。"""
    return bool(v) and (v["source"] == "dt" or (v["source"] == "annotation" and not vexmod().author_missing(v.get("author"))))


def exposed_hits(r, services):
    """這一列的元件在對外服務清單上：purl 比 base（類型＋namespace＋名稱）；package 比 Debian 套件名稱（這一列的名稱、DT 以原始碼
    套件比對時從它安裝的二進位套件、Ubuntu 打包的 Python 模組的擁有者；grype_binaries 不算：對外的那些已經自成一列）。
    只比監聽程式所屬的套件，不含它載入的函式庫。回傳對到的服務。"""
    vx = vexmod()
    rbase, _ = vx.purl_split(r.get("purl"))
    deb = bool(rbase and rbase.startswith("pkg:deb/"))
    names = ({str(r.get("name") or "").lower(), rbase.rsplit("/", 1)[1]} | {b.lower() for b in r.get("installed_as") or []}) if deb else set()
    owner = ((r.get("deb_python") or {}).get("owner") or {}).get("name")
    if owner:
        names.add(owner.lower())
    ns = rbase.rsplit("/", 1)[0] if deb else None
    hits = []
    for s in services:
        ok = bool(set(s.get("packages") or ()) & names)
        if not ok and s.get("purl"):
            sb = vx.purl_split(s["purl"])[0]
            ok = sb == rbase or (ns is not None and sb in {f"{ns}/{n}" for n in names})
        if ok:
            hits.append(s)
    return hits


def service_text(s):
    return f"{s['program']} ({s['protocol']}/{s['port']}" + (f" on {s['address']}" if s.get("address") else "") + ")"


def assessed(r, acc=None):
    """「必須判斷範圍」的列算判斷過：這一列與併進來的其他 CVE（vex_extra）都有結論（不是 untriaged、in_triage，也不是批次規則
    設的：規則沒有人逐列看過）。被利用的列（KEV、EUVD、人工證據）只算人的判定（human_vex），而且這一列自己的 DT 判定只在每一筆
    finding 都判過時算（dt_complete，使用者決定 A）；沒有被利用的對外列，核心設定、發行版紀錄、NVIDIA 推定以外的 in_triage 等自動來源也算。
    證據規則（K1／K2／U1，v["evidence"]）例外：結論是逐列由產物算出的，和核心設定、發行版覆核等自動來源一樣算（K1 取代的就是核心設定來源）；
    被利用的列本來就不套用規則，照樣只算人的判定。"""
    def ok(v):
        if not v or v["state"] == "in_triage" or (v["source"] == "rule" and not v.get("evidence")):
            return False
        if not exploited(r):
            return True
        if v["source"] == "dt" and not v.get("inherited_from") and acc is not None and not dt_complete(r, acc):
            return False
        if v["source"] == "dt" and v.get("inherited_from") and acc is not None and not inherited_dt_usable(r, acc):
            # 沿用的 DT 判定：擁有它的 deb 列的判定也要每一筆都能用（例如 RESOLVED 沒有 details 不算）
            return False
        return human_vex(v)
    return ok(r.get("vex")) and all(ok(x.get("vex")) for x in r.get("vex_extra") or [])


def cvss_index(findings, grype):
    """CVSS 基本分數與向量的來源（必須判斷範圍用；不改 build_rows）：
      - DT 與 NVIDIA 公告的 finding（cvssV4Score／cvssV4BaseScore＋cvssV4Vector、cvssV3BaseScore＋cvssV3Vector、cvssV2BaseScore＋
        cvssV2Vector；NVIDIA 公告的 finding 由 nvidia_bulletins.py 填 cvssV3*），以「來源:編號」為鍵（＝row["source_ids"]）；
      - Grype（matches[].vulnerability.cvss 與 relatedVulnerabilities[].cvss：NVD 與 CNA 等各來源的 vector、metrics.baseScore），以編號為鍵。
    回傳 (dt, grype)：{鍵: {(分數, 向量或 None, 來源標籤)}}。
    每個來源（DT 的一筆紀錄；Grype 的一筆紀錄 × cvss 的 source）只用最新版的 CVSS（v4 ＞ v3.x ＞ v2，使用者決定 D）：同一個來源的 v2 與 v3
    不算兩個來源。"""
    dt, gr = {}, {}
    for f in findings or []:
        v = (f.get("vulnerability") or {}) if isinstance(f, dict) else {}
        if not isinstance(v, dict):
            continue
        src = str(v.get("source") or "?")
        lab = "NVIDIA bulletin" if src.upper() == "NVIDIA" else f"DT {src}"
        for sk, vk, tag in (("cvssV4Score", "cvssV4Vector", "v4"), ("cvssV4BaseScore", "cvssV4Vector", "v4"),
                            ("cvssV3BaseScore", "cvssV3Vector", "v3"), ("cvssV2BaseScore", "cvssV2Vector", "v2")):
            sc = num(v.get(sk))
            if sc is not None:
                vec = v.get(vk) if isinstance(v.get(vk), str) and v.get(vk).strip() else None
                dt.setdefault(f"{v.get('source') or '?'}:{v.get('vulnId') or '?'}", set()).add((sc, vec, f"{lab} {tag}"))
                break                       # 這一筆紀錄最新版的那個（順序 v4、v3、v2）
    for m in (grype or {}).get("matches") or [] if isinstance(grype, dict) else []:
        if not isinstance(m, dict):
            continue
        for x in [m.get("vulnerability") or {}] + list(m.get("relatedVulnerabilities") or []):
            if not isinstance(x, dict) or not isinstance(x.get("id"), str):
                continue
            for sc, vec, lab, _ in grype_cvss_entries(x):
                gr.setdefault(x["id"].upper(), set()).add((sc, vec, lab))
    return dt, gr


def grype_cvss_entries(x):
    """Grype 的一筆紀錄（vulnerability 或 relatedVulnerabilities 的一項）的 CVSS：[(分數, 向量或 None, 來源標籤, 版本 tuple)]。
    每個 cvss 的 source 只用最新的主版本（v4 ＞ v3.x ＞ v2，使用者決定 D；cvss_index 與只有 Grype 的列共用）。"""
    per = {}                        # cvss 的 source → [(版本, 分數, 向量)]
    for c in x.get("cvss") or [] if isinstance(x.get("cvss"), list) else []:
        sc = num((c.get("metrics") or {}).get("baseScore")) if isinstance(c, dict) else None
        if sc is None:
            continue
        vec = c.get("vector") if isinstance(c.get("vector"), str) and c["vector"].strip() else None
        per.setdefault(str(c.get("source") or x.get("namespace") or "?"), []).append((cvss_version(c.get("version"), vec), sc, vec))
    out = []
    for src, es in per.items():
        top = max(e[0][0] for e in es)       # 主版本：v4 ＞ v3（3.0、3.1 同一級）＞ v2
        out += [(sc, vec, f"Grype {src} v{fmt_version(ver)}", ver) for ver, sc, vec in es if ver[0] == top]
    return out


def cvss_version(v, vec=None):
    """CVSS 版本 → 可比較的 tuple（4.0 ＞ 3.1 ＞ 3.0 ＞ 2.0）；沒寫時看向量的前綴（CVSS:3.1/…；沒有前綴的是 v2）。"""
    m = re.match(r"^\s*([0-9]+)(?:\.([0-9]+))?", str(v or ""))
    if not m:
        m = re.match(r"^CVSS:([0-9]+)\.([0-9]+)/", str(vec or ""))
    return (int(m.group(1)), int(m.group(2) or 0)) if m else ((2, 0) if vec else (0, 0))


def fmt_version(t):
    return f"{t[0]}.{t[1]}" if t != (0, 0) else "?"


def cvss_of(r, idx):
    """這一列所有來源的 (分數, 向量, 來源)，分數高的在前。"""
    dt, gr = idx
    es = set()
    for k in r.get("source_ids") or []:
        es |= dt.get(k, set())
    for i in {str(x).upper() for x in (r.get("all_ids") or [])} | {str(x).upper() for x in r.get("cves") or []}:
        es |= gr.get(i, set())
    return sorted(es, key=lambda e: (-e[0], e[2], e[1] or ""))


def av_of(vec):
    m = AV_RE.search(vec or "")
    return m.group(1) if m else None


def ubuntu_priority_of(r, upri, gpri, nvdebs):
    """這一列的 Ubuntu priority（只有 Ubuntu 打包的元件；各 CVE 取最嚴重的，鏡像優先、沒有再用 Grype 的 Ubuntu 比對）；沒有 → None。"""
    if not ubuntu_packaged(r, nvdebs):
        return None
    ps = [(upri or {}).get(c) or (gpri or {}).get(c) for c in r.get("cves") or []]
    ps = [p for p in ps if p in UBUNTU_SEVERITY]
    return min(ps, key=lambda p: SEV_RANK.get(UBUNTU_SEVERITY[p], 9)) if ps else None


# drivers/staging/ 底下的網路驅動程式（Wi-Fi 與其他網路裝置）：Linux 6.8 的 drivers/staging 子目錄中，Kconfig 依賴 WLAN、CFG80211、
# MAC80211、WIRELESS_EXT、NET 或 NETDEVICES 的（以 Ubuntu linux-hwe-6.8-headers-6.8.0-138 的 drivers/staging/*/Kconfig 核對，2026-11-05）。
# Wi-Fi：ks7010、rtl8192e、rtl8712、rtl8723bs、vt6655、vt6656、wlan-ng；其他網路裝置：gdm724x（LTE）、octeon（乙太網路）、most/net。
# r8188eu 在 6.8 已經不在 staging（沒有列）。其他核心版本的 staging 驅動程式不同，換核心時要重新核對
KERNEL_NET_STAGING = ("ks7010", "rtl8192e", "rtl8712", "rtl8723bs", "vt6655", "vt6656", "wlan-ng", "gdm724x", "octeon", "most/net")
KERNEL_NET_PREFIXES = ("net/", "drivers/net/", "drivers/usb/", "drivers/bluetooth/", "net/bluetooth/", "drivers/net/can/",
                       "net/wireless/", "net/mac80211/", "include/net/", "fs/smb/server/", "fs/nfsd/", "drivers/nfc/",
                       "drivers/infiniband/") + tuple(f"drivers/staging/{d}/" for d in KERNEL_NET_STAGING)


def kernel_fix_files(kcfg):
    """scan/kernel-config.json（schema 對、有 results）→ {CVE: [修補的檔案路徑]}；results 的 files 是 {"path": …} 或文字。沒有 → {}。"""
    if not isinstance(kcfg, dict) or kcfg.get("schema") != "sca-center-kernel-config/1":
        return {}
    out = {}
    for x in kcfg.get("results") or []:
        if isinstance(x, dict) and isinstance(x.get("cve"), str):
            out[x["cve"].upper()] = [f["path"] if isinstance(f, dict) else f for f in x.get("files") or []
                                     if isinstance(f, str) or (isinstance(f, dict) and isinstance(f.get("path"), str))]
    return out


def kernel_network_where(r, knet, kfiles, kmatch):
    """核心的列算對外（使用者決定 C）：對外服務清單有 kernel_network（使用中的網路介面）時，修補的檔案在 KERNEL_NET_PREFIXES 下；
    對不到修補檔案（scan/kernel-config.json 沒有這個核心、沒有這個 CVE、或沒有 files）→ 也算對外並寫明。回傳理由文字或 None。"""
    if not knet or not r.get("kernel"):
        return None
    ifs = ", ".join(knet["interfaces"])
    files = sorted({f for c in r.get("cves") or [] for f in (kfiles.get(c.upper()) or [])}) if kmatch(r) else []
    if not files:
        return f"kernel network (interfaces {ifs}; no fix files mapped in scan/kernel-config.json, treated as exposed)"
    net = [f for f in files if f.lstrip("./").startswith(KERNEL_NET_PREFIXES)]
    if not net:
        return None
    return f"kernel network (interfaces {ifs}; fix files {', '.join(net[:3])}{', …' if len(net) > 3 else ''})"


def exposed_reason(r, where, cv, upri):
    """對外元件的列是否在必須判斷範圍（f347d53）：(b) CVSS（各來源最高）≥ 7 而且 AV:N／AV:A；分數 ≥ 7 的來源都沒有向量 → 納入，
    理由寫 attack vector unknown；(c) 完全沒有 CVSS、Ubuntu priority high／critical。where：對外的位置（服務或核心網路）。回傳理由文字或 None。"""
    hi = [e for e in cv if e[0] >= CVSS_SCOPE_MIN]
    net = [e for e in hi if av_of(e[1]) in ("N", "A")]
    if net:
        return f"exposed, CVSS {net[0][0]:.1f} ({net[0][2]}) AV:{av_of(net[0][1])}: {where}"
    unk = [e for e in hi if av_of(e[1]) is None]
    if unk:
        return f"exposed, CVSS {unk[0][0]:.1f} ({unk[0][2]}), attack vector unknown: {where}"
    if not cv and upri in ("high", "critical"):
        return f"exposed, no CVSS, Ubuntu priority {upri}: {where}"
    return None


def exploitation_section(num, rows, by, pol, have_findings, data_status, services, svc_info, ev, ev_info, ev_used,
                         euvd_cves, euvd_p, ref_date, ref_src, table, comps=(), vex_verdict=None, cvss_idx=({}, {}), upri_of=None,
                         euvd_status=None, kernel_net=None, collected_note=None, euvd_stage=None):
    """風險評估「To be assessed before release」小節（前面帶空行）、summary.json 的 exploitation、文件狀態與理由。
    必須判斷的範圍（使用者決定 f347d53）：被利用的列（KEV、EUVD、人工證據），加上對外服務清單上元件的列中 CVSS（各來源最高）≥ 7 而且
    AV:N／AV:A（向量不明 → 納入）、或完全沒有 CVSS 而 Ubuntu priority high／critical 的（exposed_reason）。cvss_idx：cvss_index 的結果；
    upri_of：列 → Ubuntu priority。沒有清單時範圍只有被利用的列，這一部分是 GAP。出貨關卡依日期（ref_date 對 CRA_APPLY_DATE）：
    之前擋 P1；之後擋 P1、P2，以及範圍內還沒判斷的列。這個關卡只在這裡計算與報告；vex_export 的發行閘門不變。
    euvd_p：scan/euvd.json 的路徑（None＝沒有檔案）；有檔案但 euvd_cves 是 None ＝ 讀不到或格式不對。comps：SBOM 的套件元件（找沒對到的服務）。"""
    vx = vexmod()
    scope, raw, no_data = [], {}, []
    for r in rows:
        why = []
        if r.get("kev"):
            why.append("KEV (" + "; ".join(r.get("kev_sources") or ["DT"]) + ")")
        why += r.get("exploited_sources") or []
        hits = exposed_hits(r, services) if svc_info else []
        where = ", ".join(service_text(s) for s in hits) or (kernel_net(r) if svc_info and kernel_net else None)
        cv = cvss_of(r, cvss_idx)
        up = upri_of(r) if upri_of else None
        raw[id(r)] = (cv, up)
        if where:
            x = exposed_reason(r, where, cv, up)
            if x:
                why.append(x)
            elif not cv and not up:
                # 對外元件上沒有任何 CVSS、也沒有 Ubuntu priority：資料不足，不能當成不在範圍 → 算在範圍內、標 GAP（使用者決定）
                why.append(f"{NO_DATA_REASON}: {where}")
                no_data.append(r)
        if why:
            scope.append((r, why, assessed(r, pol["accepted"])))
    scope.sort(key=lambda x: ({"p1": 0, "p2": 1, "p3": 2}.get(x[0]["tier"], 3), x[2], not exploited(x[0]), SEV_RANK.get(x[0]["severity"], 9),
                              x[0]["id"], x[0]["component"].lower(), x[0]["version"]))
    na = [x for x in scope if not x[2]]
    scope_st = "OK" if svc_info else "GAP"
    # 資料不足（沒有 CVSS、也沒有 Ubuntu priority）而且沒有人判斷過的對外列：範圍這一部分 GAP；2027-12-11 前不擋，之後和其他沒判斷的列一樣擋
    gap_na = [r for r in no_data if not assessed(r, pol["accepted"])]
    # 被利用、只有部分 finding 有 DT 判定的列（使用者決定 A：不離開 P1；VEX 可能已寫 not_affected，表上標出）
    dcount = {id(r): dt_decided_counts(r, pol["accepted"]) for r, _, _ in scope}
    partial = {k: d for k, d in dcount.items() if 0 < d["decided"] < d["total"]
               and any(exploited(r) for r, _, _ in scope if id(r) == k)}
    # 被利用、沒有算判斷過、VEX 卻有結論的其他原因（RESOLVED 沒有 details、沿用的判定、併進來的 CVE 沒有陳述；unassessed_note）
    unote = {id(r): t for r, _, a in scope if not a and exploited(r) and id(r) not in partial
             for t in [unassessed_note(r, pol["accepted"])] if t}
    after = ref_date >= CRA_APPLY_DATE
    blocking = {id(r): r for r in by["p1"] + ((by["p2"] + [x[0] for x in na]) if after else [])}
    reasons = []
    if not have_findings:
        verdict = "NOT_ASSESSED"
        reasons.append("no Dependency-Track findings: nothing could be assessed")
    else:
        if by["p1"]:
            reasons.append(f"{plural(len(by['p1']), 'open row')} in P1 (exploited and not assessed as not affected by a person)")
        if after and by["p2"]:
            reasons.append(f"{plural(len(by['p2']), 'open row')} in P2 (assessed exploitable by a person)")
        if partial:
            pr = [r for r, _, _ in scope if id(r) in partial]
            reasons.append(f"{plural(len(partial), 'exploited row')} {verb(len(partial), 'is', 'are')} only partially assessed in "
                           "Dependency-Track and stay in P1, even where the VEX statement already says not_affected or resolved: "
                           + "; ".join(f"{r['id']} on {r['component']} {r['version']} ({partial_text(partial[id(r)])})" for r in pr[:10])
                           + ("; …" if len(pr) > 10 else ""))
        if unote:
            ur = [r for r, _, _ in scope if id(r) in unote]
            reasons.append(f"{plural(len(ur), 'exploited row')} {verb(len(ur), 'is', 'are')} not assessed by a decision that counts and "
                           f"{verb(len(ur), 'stays', 'stay')} in P1, even where the VEX status is not untriaged: "
                           + "; ".join(f"{r['id']} on {r['component']} {r['version']} ({unote[id(r)]})" for r in ur[:10])
                           + ("; …" if len(ur) > 10 else ""))
        if after and na:
            reasons.append(f"{plural(len(na), 'row')} in the must-assess scope not assessed"
                           + (f" ({len(gap_na)} of them with no CVSS and no Ubuntu priority, GAP)" if gap_na else ""))
        verdict = "BLOCKED" if blocking else "OK"
        if verdict == "OK" and data_status in ("GAP", "NOT_ASSESSED"):
            verdict = data_status
            reasons.append(f"vulnerability data status is {data_status}: the list of candidate vulnerabilities is incomplete")
        if verdict == "OK" and after and scope_st == "GAP":
            verdict = "GAP"
            reasons.append("no exposed services list: rows on externally exposed components could not be determined")
        if not after and gap_na:
            # 2027-12-11 前不擋，但只看關卡的人也要看到
            reasons.append(f"{plural(len(gap_na), 'row')} in the must-assess scope {verb(len(gap_na), 'is', 'are')} GAP (no CVSS and no "
                           f"Ubuntu priority) and not assessed; {verb(len(gap_na), 'it does', 'they do')} not block before "
                           f"{CRA_APPLY_DATE} and will block from {CRA_APPLY_DATE}")
    n_exp = sum(1 for r, _, _ in scope if exploited(r))
    n_pub = sum(1 for _, w, _ in scope if any(x.startswith(("exposed, ", NO_DATA_REASON)) for x in w))
    rule_exp = Counter((r.get("vex") or {}).get("rule") or "?" for r in by["p3"] if (r.get("vex") or {}).get("state") == "exploitable"
                       and (r.get("vex") or {}).get("source") == "rule")
    scope_txt = ("whose CVSS base score (the highest of all sources: Dependency-Track/NVD, CNA records via Grype, NVIDIA bulletins) is "
                 "at least 7.0 with attack vector network (AV:N) or adjacent (AV:A) – included as well when no source with a score of "
                 "7.0 or more has a vector (attack vector unknown) – or that have no CVSS at all and Ubuntu priority high or critical. "
                 "The Ubuntu priority is not used otherwise (it is not a CVSS score); the vendor-first severity of section 8.3 is "
                 "not used for the scope")
    parts = [("Tier scheme **exploitation** (`vulnerability_policy.scheme`; " + pol["status"] + "): P1 = exploited (KEV from any source, "
              "EUVD marks it exploited, or manual exploitation evidence) and not assessed as not affected by a person; P2 = no "
              "exploitation evidence but assessed exploitable by a person (Dependency-Track EXPLOITABLE or a named `exploitable` "
              "decision in `vex-annotations.json`); P3 = all other open rows. The conditions in `vulnerability_policy.tiers` (KEV flag, "
              "EPSS, severities, CVSS) are not used in this scheme; EPSS and severity are shown only (the scope below uses CVSS). "
              "Bulk VEX rules never apply to exploited rows (they are the P1 rows of this scheme), and an `exploitable` statement "
              "set by a bulk rule does not make a row P2.")]
    if rule_exp:
        parts.append(f"{plural(sum(rule_exp.values()), 'P3 row')} {verb(sum(rule_exp.values()), 'has', 'have')} VEX status `exploitable` "
                     "from a bulk rule (" + ", ".join(f"{k} {n}" for k, n in sorted(rule_exp.items())) + "): they stay in P3 and are shown "
                     "with the rule in the VEX status column; a person's decision is needed to make them P2.")
    euvd_n = len(euvd_cves or [])
    # DT 5.2 的 ENISA KEV 來源（enisaeu/CNW 的 eukev.json）自 2026-08-13 起沒有更新；EUVD 的已遭利用清單（API kev/dump）涵蓋它之後的
    # EU-KEV（2026-11-05 評估：EUVD 是 DT 的 CISA ∪ eukev.json 的嚴格超集）。沒有 EUVD 時要說可能漏掉
    stale = ("Dependency-Track's ENISA KEV source (`eukev.json`) has not been updated since 2026-08-13, so EU-KEV entries added after "
             "2026-08 may be missing from the KEV column and from P1")
    if euvd_cves is not None:
        eutxt = (f"EUVD (`scan/euvd.json`, SHA-256 {sha256(euvd_p)[:12]}) marks {plural(euvd_n, 'CVE')} as exploited; EUVD is the source "
                 "for EU-KEV entries added after 2026-08 (Dependency-Track's ENISA KEV file `eukev.json` has not been updated since "
                 "2026-08-13)")
    elif euvd_status is not None:
        eutxt = f"EUVD: **not available** (`scan/euvd.json` has status {euvd_status}; not used): " + stale
    elif euvd_p:
        eutxt = "EUVD: **unreadable** (`scan/euvd.json` exists but is not readable JSON with a `cves` object; not used): " + stale
    elif euvd_stage:
        eutxt = f"EUVD: **not available** (no `scan/euvd.json` in the scan output; sca-scan's C-euvd stage is {euvd_stage}): " + stale
    else:
        eutxt = "EUVD: **not available** (no `scan/euvd.json` in the scan output): " + stale
    parts.append("Exploitation evidence besides KEV: " + eutxt + "; "
                 + (f"manual evidence `{ev_info['file']}` (SHA-256 {ev_info['sha256'][:12]}): {plural(len(ev), 'entry', 'entries')}"
                    if ev_info else f"no manual evidence file (`{EVIDENCE_REL}`)") + ".")
    if ev:
        parts.append(table(["CVE", "Source", "Date", "Owner", "Note", "Rows (for this CVE)"],
                           [[e["cve"], e["source"], e["date"], e["owner"], e.get("note"), ev_used.get(e["cve"], 0)] for e in ev]))
        unused = sorted({e["cve"] for e in ev if not ev_used.get(e["cve"])})
        if unused:
            parts.append(f"{plural(len(unused), 'CVE')} with manual evidence {verb(len(unused), 'matches', 'match')} no row "
                         f"(not reported for this product, or a typo): {', '.join(unused)}.")
    svc_unmatched = []
    if svc_info:
        nmatch = len({id(s) for r in rows for s in exposed_hits(r, services)})
        # 對到任何一列（含 DT 以原始碼套件比對、Ubuntu 打包的 Python 模組的擁有者）或 SBOM 的任何元件就算對到；沒有 SBOM 時只看列
        cpseudo = [{"name": c.get("name") or "", "purl": c.get("purl") or "", "installed_as": []} for c in comps]
        svc_unmatched = [s for s in services if not any(exposed_hits(c, [s]) for c in list(rows) + cpseudo)]
        svc = (f"Exposed services list `{svc_info['file']}` (collected {svc_info['collected']}"
               + (f", {svc_info['source']}" if svc_info.get("source") else "") + f", SHA-256 {svc_info['sha256'][:12]}): "
               f"{plural(len(services), 'listening service')}, {nmatch} of them on a component with vulnerability rows."
               + (f" {collected_note}" if collected_note else "")
               + (f" Kernel network in use (interfaces {', '.join(svc_info['kernel_network']['interfaces'])}): operating system kernel "
                  "rows whose fix files are under " + ", ".join(f"`{x}`" for x in KERNEL_NET_PREFIXES) + " count as exposed (files from "
                  "`scan/kernel-config.json`; rows with no mapped files count as exposed too)." if svc_info.get("kernel_network") else
                  " No kernel network entry (`kernel_network`): kernel rows are not treated as exposed.")
               + (f" {plural(len(svc_unmatched), 'service')} {verb(len(svc_unmatched), 'matches', 'match')} no component in the SBOM "
                  "and no vulnerability row (wrong package name or purl, or the program is not from a package in the SBOM; check "
                  "the mapping): " + "; ".join(service_text(s) + " → " + (", ".join(s.get("packages") or []) or s.get("purl") or "?")
                                         for s in svc_unmatched) + "." if svc_unmatched else ""))
    else:
        svc = (f"**GAP: no exposed services list** (`{SERVICES_REL}`, from `ss -lntup` and `dpkg -S` on the board). The scope "
               "below covers only exploited rows; rows on externally exposed components were **not determined**.")
    parts.append("Must be assessed before release: rows listed in a KEV catalogue or with other exploitation evidence, and rows on "
                 "externally exposed components (listening services) " + scope_txt + ". Only the package that owns the "
                 "listening program counts as exposed, not the libraries it loads. Assessed means a VEX decision other than "
                 "`in_triage` that was not set by a bulk rule; for exploited rows only a decision by a person counts "
                 "(Dependency-Track analysis or a named decision in `vex-annotations.json`). " + svc)
    parts.append(f"Rows in scope: {len(scope)} ({n_exp} exploited, {n_pub} on exposed components); assessed {len(scope) - len(na)}, "
                 f"**not assessed {len(na)}**."
                 + (f" **GAP:** {plural(len(no_data), 'row')} on exposed components {verb(len(no_data), 'has', 'have')} neither a CVSS "
                    f"score nor an Ubuntu priority, so whether {verb(len(no_data), 'it needs', 'they need')} an assessment cannot be "
                    f"decided from the data: {verb(len(no_data), 'it is', 'they are')} counted in the scope ({len(gap_na)} not assessed by "
                    f"a person). Before {CRA_APPLY_DATE} {verb(len(no_data), 'it does', 'they do')} not block the gate; from "
                    f"{CRA_APPLY_DATE} {verb(len(no_data), 'it blocks', 'they block')} like any other row in the scope that is not "
                    "assessed: " + ", ".join(f"{r['id']} on {r['component']} {r['version']}" for r in no_data[:10])
                    + (", …" if len(no_data) > 10 else "") + "." if no_data else ""))

    def cv_cells(r):
        cv, up = raw[id(r)]
        return ([f"{cv[0][0]:.1f} ({cv[0][2]})", cv[0][1] or "AV unknown"] if cv else ["none", "—"]) + [up or "—"]
    parts.append(table(["#", "ID", "Component", "Version", "Tier", "Max CVSS (source)", "Vector", "Ubuntu priority", "Why in scope",
                        "Assessed", "VEX status"],
                       [[i, r["id"], component_text(r), version_text(r), str(r["tier"]).upper(), *cv_cells(r), "; ".join(w),
                         ("yes" if a else "**no**") + (f" ({partial_text(partial[id(r)])})" if id(r) in partial else
                                                       f" ({unote[id(r)]})" if id(r) in unote else ""),
                         vx.label(r)] for i, (r, w, a) in enumerate(scope, 1)]))
    parts.append(f"Release gate by date (this scheme): reference date {ref_date} ({ref_src}). Before {CRA_APPLY_DATE} the gate blocks "
                 f"P1; from {CRA_APPLY_DATE} it blocks P1, P2 and rows in the scope above that are not assessed. "
                 f"**{verdict}**" + (": " + "; ".join(reasons) if reasons else "") + ". "
                 + (f"VEX release gate (previous subsection, unchanged): **{vex_verdict}**. " if vex_verdict else "")
                 + "Both are reported; OK does not mean the product has no vulnerabilities.")
    doc_st, doc_reasons = "OK", []
    if have_findings and scope_st == "GAP":
        doc_st = "GAP"
        doc_reasons.append("must-assess scope: no exposed services list (only exploited rows are in scope)")
    if have_findings and euvd_cves is None:
        # 使用者決定（EUVD ②）：DT 的 ENISA KEV 停在 2026-08-13，EUVD 不存在或過期 → 風險評估 GAP
        doc_st = "GAP" if doc_st == "OK" else doc_st
        doc_reasons.append(euvd_unavailable_reason(euvd_status, euvd_p, euvd_stage))
    if gap_na:
        doc_st = "GAP" if doc_st == "OK" else doc_st
        doc_reasons.append(f"must-assess scope: {plural(len(gap_na), 'row')} on exposed components with no CVSS and no Ubuntu priority "
                           "not assessed (GAP)")
    if verdict == "BLOCKED":
        doc_st = worst([doc_st, "ATTENTION"])
        doc_reasons.append(f"release gate by date (exploitation scheme) BLOCKED: {len(blocking)} rows")
    summ = {"scheme": "exploitation", "section": num,
            "tiers": {t: len(by[t]) for t in TIERS},
            "p1_by_evidence": {"kev": sum(1 for r in by["p1"] if r.get("kev")),
                               "euvd": sum(1 for r in by["p1"] if any(x.startswith("EUVD") for x in r.get("exploited_sources") or [])),
                               "manual": sum(1 for r in by["p1"] if any(x.startswith("manual: ") for x in r.get("exploited_sources") or []))},
            "p2_by": {"dt_exploitable": sum(1 for r in by["p2"] if not r.get("p2_by_vex")), "vex_exploitable": sum(1 for r in by["p2"] if r.get("p2_by_vex"))},
            "p3_rule_exploitable": dict(sorted(rule_exp.items())),
            "evidence": dict(ev_info, used=ev_used) if ev_info else None,
            "euvd": {"available": euvd_cves is not None, "file_present": bool(euvd_p), "file_status": euvd_status,
                     "exploited_cves": euvd_n if euvd_cves is not None else None},
            "exposed_services": dict(svc_info, unmatched=[{"program": s["program"], "protocol": s["protocol"], "port": s["port"],
                                                          "packages": s.get("packages") or [], "purl": s.get("purl")} for s in svc_unmatched])
            if svc_info else None,
            "must_assess": {"status": "GAP" if scope_st == "GAP" or gap_na else "OK",
                            "partially_assessed_exploited": len(partial),
                            "status_reasons": (["no exposed services list"] if scope_st == "GAP" else [])
                            + ([f"{len(gap_na)} exposed rows with no CVSS and no Ubuntu priority not assessed"] if gap_na else []),
                            "rule": "exploited, or exposed with CVSS >= 7 and AV:N/AV:A (AV unknown included), or "
                                    "exposed without CVSS and Ubuntu priority high/critical, or exposed with neither CVSS nor "
                                    "Ubuntu priority (GAP)",
                            "rows": len(scope), "exploited": n_exp, "exposed": n_pub, "assessed": len(scope) - len(na),
                            "not_assessed": len(na), "exposed_without_cvss_or_priority": len(no_data),
                            # gap：沒有 CVSS、也沒有 Ubuntu priority 的對外列（在範圍內）；gap_not_assessed：其中沒有人判斷過的（文件 GAP）
                            "gap": {"rows": len(no_data), "not_assessed": len(gap_na), "reason": NO_DATA_REASON if no_data else None},
                            "list": [{"id": r["id"], "component": r["component"], "version": r["version"], "tier": r["tier"],
                                      "severity": r["severity"],
                                      "cvss_max": raw[id(r)][0][0][0] if raw[id(r)][0] else None,
                                      "cvss_source": raw[id(r)][0][0][2] if raw[id(r)][0] else None,
                                      "cvss_vector": raw[id(r)][0][0][1] if raw[id(r)][0] else None,
                                      "attack_vector": av_of(raw[id(r)][0][0][1]) if raw[id(r)][0] else None,
                                      "ubuntu_priority": raw[id(r)][1], "why": w, "assessed": a,
                                      # 只有 Grype 的列沒有 DT finding（found_by 標出；DT 的列沒有這個鍵）
                                      "dt_findings": dict.fromkeys(dcount[id(r)], 0) if r.get("found_by") else dcount[id(r)],
                                      "not_assessed_note": unote.get(id(r)),
                                      "vex": (r.get("vex") or {}).get("state") or "untriaged",
                                      **({"found_by": r["found_by"]} if r.get("found_by") else {}),
                                      # Grype 在同一個原始碼套件的其他二進位套件上也有（DT 列；沒有時沒有這個鍵）
                                      **({"grype_binaries": [b["name"] for b in r["grype_binaries"]]} if r.get("grype_binaries") else {})}
                                     for r, w, a in scope]},
            "gate": {"verdict": verdict, "reasons": reasons, "reference_date": ref_date, "date_source": ref_src, "cutoff": CRA_APPLY_DATE,
                     "after_cutoff": after, "blocks": ["p1", "p2", "must_assess_not_assessed"] if after else ["p1"],
                     "blocking_rows": len(blocking), "p1": len(by["p1"]), "p2": len(by["p2"]), "not_assessed": len(na),
                     "gap_not_assessed": len(gap_na)}}
    head = f"\n\n### {num} To be assessed before release ({len(scope)})\n\n"
    return head + "\n\n".join(parts), summ, doc_st, doc_reasons


ROWS_FILE = "vulnerability-rows.json"
ROWS_SCHEMA = "sca-center-vulnerability-rows/1"


def vulnerability_rows(vrows, cidx, upri_of, services, svc_info, kernel_net, gsets, have_grype, extra=None):
    """機器可讀的逐列資料（vulnerability-rows.json，內部用，不給客戶）：每一列（CVE × 元件，含 NVIDIA 公告列）一筆，鍵穩定。
    只整理 generate() 已經算好的值，不改任何判定；report_package.py 用它產生給人看的清單。"""
    g_all = set().union(*gsets) if gsets else set()
    out = []
    for r in vrows:
        v = r.get("vex") or None
        cv = cvss_of(r, cidx)
        top = cv[0] if cv else None
        where = None
        if svc_info:
            hits = exposed_hits(r, services)
            where = ", ".join(service_text(s) for s in hits) or (kernel_net(r) if kernel_net else None) or None
        ev = (["KEV (" + ", ".join(r.get("kev_sources") or ["DT"]) + ")"] if r.get("kev") else []) + list(r.get("exploited_sources") or [])
        key = "|".join(str(x) for x in (r["id"], r.get("purl") or r.get("component"), r.get("version")))
        out.append({
            "id": r["id"],
            "aliases": sorted(set(r.get("all_ids") or []) - {r["id"]}),
            "component": r.get("component"), "version": r.get("version"), "purl": r.get("purl") or None,
            "is_kernel": bool(r.get("kernel")),
            **({"layer": r["layer"], "layer_todo": r.get("layer_todo", True), "layer_basis": r.get("layer_basis")} if r.get("layer") else {}),
            **({"uefi_build_check": r["uefi_build_check"]} if r.get("uefi_build_check") else {}),
            **({"uefi_image_check": r["uefi_image_check"]} if r.get("uefi_image_check") else {}),
            **({"suggestion": r["suggestion"]} if r.get("suggestion") else {}),
            **({"tee_note": r["tee_note"]} if r.get("tee_note") else {}),
            "tier": r["tier"],
            # NVIDIA 公告的 CVE 其實是發行版套件的（nvidia_distro.py）：分析結果（含 ambiguous 的原因）與建議（給 RD 確認，不改判定；
            # suggestion＝{rule, state, justification, basis, detail, needs}）；沒有 → 不加鍵
            **({"nvidia_distro": r["nvidia_distro"]} if r.get("nvidia_distro") else {}),
            **({"suggestion_more": r["suggestion_more"]} if r.get("suggestion_more") else {}),
            "vex": ({"state": v.get("state"), "source": v.get("source"), "rule": v.get("rule"), "justification": v.get("justification"),
                     "detail": v.get("detail"), "author": v.get("author") or v.get("rule_author"), "date": v.get("date") or v.get("rule_date"),
                     "markers": [x.get("code") for x in r.get("vex_markers") or []]} if v else None),
            "fix_state": r.get("fix_state"), "fix_versions": list(r.get("fix_versions") or []), "fix_next": r.get("fix_next"),
            # Ubuntu 打包的 Python 模組（apply_deb_python）：擁有的 deb 套件（不明時 None）、候選套件名、PyPI 的修補版本（不適用於發行版套件）
            "deb_python": ({"owner": ({"name": (r["deb_python"].get("owner") or {}).get("name"),
                                       "version": (r["deb_python"].get("owner") or {}).get("version")}
                                      if r["deb_python"].get("owner") else None),
                            "candidates": [str(c).split(" ", 1)[0] for c in r["deb_python"].get("candidates") or []],
                            "pypi_fix": [str(y) for y in r["deb_python"].get("pypi_fix") or []],
                            **({"version_resolution": {k: r["deb_python"]["version_resolution"].get(k) for k in
                                                       ("state", "version", "original_version", "dpkg", "init_version", "reason")}}
                               if r["deb_python"].get("version_resolution") else {})}
                           if isinstance(r.get("deb_python"), dict) else None),
            "cvss": ({"score": top[0], "vector": top[1], "source": top[2]} if top else None),
            "ubuntu_priority": upri_of(r) if upri_of else None,
            "severity": r.get("severity"),
            "exploited": bool(ev), "exploitation_evidence": ev,
            # None＝沒有對外服務清單，不知道；True／False 是依清單的結果
            "exposed": (bool(where) if svc_info else None), "exposed_where": where,
            "found_by": {"dt_sources": sorted({x.split(":", 1)[0] for x in r.get("source_ids") or []} - {"GRYPE"}),
                         "grype": (bool({str(x).upper() for x in r.get("all_ids") or []} & g_all) if have_grype else None),
                         "grype_only": r.get("found_by") == GRYPE_ONLY},
            "vex_statement_ref": f"vex-{r['id']}-{hashlib.sha256(key.encode()).hexdigest()[:12]}" if v else None,
            # 附加證據（runtime_evidence.py）：只加欄位，不影響 tier、VEX 狀態。沒有 extra → 照舊不加
            **(extra(r, cv) if extra else {}),
        })
    return out


def reference_date(market, today):
    """出貨關卡的參考日：首次上市日與報告日（UTC）較晚的那個。上市（placing on the market）是每一台各自算，首次上市日在過去時，
    之後出貨的每一台都以出貨當天為準，所以不能停在首次上市日（否則 2027-12-11 以後仍只擋 P1）。回傳 (日期, 說明)。"""
    if market and market > today:
        return market, "first placing on the market (planned), `product.first_placing_on_market`; later than the report date"
    if market and market == today:
        return market, "first placing on the market, `product.first_placing_on_market`; the same day as the report date (UTC)"
    if market:
        return today, (f"report date (UTC); `product.first_placing_on_market` {market} is earlier, and placing on the market applies to "
                       "each unit, so the later date is used")
    return today, "report date (UTC); `product.first_placing_on_market` is not set"


def vuln_table(rows, kernel=False):
    """主清單的欄位；kernel=True（核心的清單，各層級混在一起）另加層級、Grype 的修補狀態與 DT 的分析狀態。"""
    head = ["#", "ID", "CVE", "Source IDs", "Component", "Version", "Type", "Severity", "Severity source", "CVSS", "EPSS probability (percentile)", "KEV",
            "Fix (Grype)"]
    if kernel:
        head = head[:1] + ["Tier"] + head[1:-1] + ["Fix state (Grype)", "Fix (Grype)", "Analysis state"]
    layered = bool(rows) and all("layer" in r for r in rows)       # 分層（SBOM 有 dumpling:layer）時多一欄 Layer，放在 Type 後面
    if layered:
        head.insert(head.index("Type") + 1, "Layer")
    head = head + ["VEX status"]
    out = []
    for i, r in enumerate(rows, 1):
        x = [i, r["id"], cve_text(r), ", ".join(r["source_ids"]), component_text(r), version_text(r), type_text(r),
             r["severity"], severity_text(r), r["cvss"], epss_text(r), kev_text(r), r["fix"]]
        if kernel:
            x = x[:1] + [r["tier"].upper()] + x[1:-1] + [r["fix_state"], r["fix"],
                                                       ", ".join(sorted({a["state"] or "NOT_SET" for a in r["analysis"]}))
                                                       + (" (suppressed)" if all(a["suppressed"] for a in r["analysis"]) else "")]
        if layered:
            x.insert(head.index("Layer"), LAYER_ZH.get(r["layer"], r["layer"]))
        out.append(x + [vexmod().label(r)])
    return table(head, out)


def cve_text(r):
    if r["cves"]:
        return ", ".join(r["cves"])
    u = r.get("usn_listed")   # USN 自成一列：清單上的 CVE 不是每一個在同一個元件版本上都有列
    return (f"no CVE alias (the notice lists {', '.join(u[:5])}{', …' if len(u) > 5 else ''}; not merged: not every listed CVE "
            "has a row on this component)" if u else "no CVE alias")


def version_text(r):
    """Debian 打包的 Python 模組的 egg-info 常寫 0.0.0（或沒有版本）：顯示擁有它的 deb 套件的版本，註明原本的值。"""
    vr = (r.get("deb_python") or {}).get("version_resolution")
    if vr and vr.get("state") == "RESOLVED" and vr.get("version"):
        return (f"{vr['version']} (from dpkg {vr['dpkg']['name']} {vr['dpkg']['version']}; Python metadata said "
                f"{vr.get('original_version') or 'none'}"
                + ("" if vr.get("init_version") else "; presumed to be the module version, no __version__ to cross-check") + ")")
    if vr and vr.get("state") in ("DISAGREE", "UNSURE", "NOT_OWNED", "NO_OWNER_DATA"):
        return f"unknown (Python metadata said {vr.get('original_version') or 'none'}; {vr['reason']})"
    o = (r.get("deb_python") or {}).get("owner")
    if o and r["version"] in ("", "0.0.0"):
        return f"{o['version']} (deb {o['name']}; Python metadata {r['version'] or 'none'})"
    return r["version"]


def type_text(r):
    return f"{r['ptype']} (deb-packaged)" if r.get("deb_python") else r["ptype"]


def component_text(r):
    if r.get("found_by") == KERNEL_CNA:      # 廠商核心：CVE 清單是 Linux 核心 CNA 的版本比對（不是 Grype／DT）
        kc = r.get("kernel_cna") or {}
        if kc.get("version_verdict") == "explicit":
            return component_text(dict(r, found_by=None)) + " (vendor kernel; CVE from an explicit list (KERNEL_CVES), kernel version not compared)"
        return (component_text(dict(r, found_by=None)) + " (vendor kernel; CVE from Linux kernel CNA version match: "
                + ("version affected" if kc.get("version_verdict") == "affected" else "version could not be determined (unknown), not shown as affected")
                + ")")
    if r.get("found_by") == GRYPE_ONLY:      # 只有 Grype 的列：元件欄標出來（DT 的列不變）
        return component_text(dict(r, found_by=None)) + " (found only by Grype)"
    if r.get("grype_binaries"):             # 同一個原始碼套件的其他（不對外的）二進位套件上 Grype 也有（grype_coverage）；只是文字
        gb = r["grype_binaries"]
        return (component_text(dict(r, grype_binaries=None)) + " (also found by Grype on "
                + ", ".join(b["name"] for b in gb[:4]) + (f" and {len(gb) - 4} more" if len(gb) > 4 else "") + ")")
    dp = r.get("deb_python")
    if dp:
        where = dp["path"].rsplit("/dist-packages/", 1)[0] + "/dist-packages"
        o = dp["owner"]
        return (f"{r['component']} (Ubuntu package {o['name']} {o['version']} installs it in {where}; not managed by pip)" if o else
                f"{r['component']} (installed by the distribution in {where}; owning deb package "
                + (f"ambiguous: {', '.join(dp['candidates'])})" if dp["candidates"] else "not found in the SBOM)"))
    if r.get("mapped_from"):     # 只供比對的合成元件（C-kernel-l4t-map）：產品裡安裝的是 NVIDIA 的核心套件
        return f"{r['component']} (Canonical kernel source used for matching; mapped from {r['mapped_from']})"
    b = r.get("installed_as") or []
    if not b:
        return r["component"]
    return f"{r['component']} (source package; installed as {', '.join(b[:4])}{f' and {len(b) - 4} more' if len(b) > 4 else ''})"


def annex_i_table(cfg, risk_st, gate_st=None, sec_evidence=None):
    """Annex I Part I (2) 的適用性表與缺少的欄位。(a) 指向第 8 節；(b)–(m) 讀 risk_assessment.annex_i_applicability.<字母>。
    sec_evidence：{字母: 安全測試的一句證據}，接在人寫的內容後面（不取代；沒有人寫的內容時照樣 TO BE COMPLETED）。"""
    sec_evidence = sec_evidence or {}
    app = ((cfg.get("risk_assessment") or {}).get("annex_i_applicability") or {})
    rows, missing = [], []
    for x, title in ANNEX_I:
        path = f"risk_assessment.annex_i_applicability.{x}"
        if x == "a":
            rows.append([f"({x})", title, "Applies", f"Section 8 (generated from the scan; vulnerability data status {risk_st}"
                         + (f"; release gate {gate_st}, see the subsection on vulnerability status (VEX)" if gate_st else "") + ")"])
            continue
        e = app.get(x) or {}
        applies, meas, just = e.get("applies"), e.get("measures"), e.get("justification")
        meas = "; ".join(meas) if isinstance(meas, list) else meas
        ev = f" {sec_evidence[x]}" if x in sec_evidence else ""
        if applies is True and meas:
            rows.append([f"({x})", title, "Applies", f"{meas}{ev}"])
        elif applies is False and just:
            rows.append([f"({x})", title, "Does not apply", f"{just}{ev}"])
        else:
            missing.append(path)
            need = "measures" if applies is True else "justification" if applies is False else "applies + measures or justification"
            rows.append([f"({x})", title, TBC, f"`{path}` ({need}){ev}"])
    return table(["Point", "Requirement (summary)", "Applicability", "Implementation or justification"], rows), missing


# sca-scan 掃描時的暫存路徑（runner 上的 .sca-scan-work.XXXX/cdxgen-src/ 等）：產品 SBOM 會交給客戶，只留專案內的相對路徑
# 每段路徑都不能跨過空白、換行、逗號、反斜線（cdxgen 的 cdx:bom:componentSrcFiles 用 \n 串接多個路徑）；根目錄本身換成 .
WORK_PATH = re.compile(r'(?:file://)?(?:/[^/\s,\\]+)*/\.sca-scan-work\.[A-Za-z0-9]+(?:/(?:cdxgen-src|src)(?=/|$|[\s,\\]))?(/)?')


def strip_work_paths(obj):
    """走訪解析後的 SBOM，逐個字串去掉暫存路徑前綴（不在序列化後的 JSON 文字上做，免得跨過跳脫字元）。"""
    if isinstance(obj, dict):
        return {k: strip_work_paths(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [strip_work_paths(v) for v in obj]
    if isinstance(obj, str) and ".sca-scan-work." in obj:
        return WORK_PATH.sub(lambda m: "" if m.group(1) else ".", obj)
    return obj


def product_bom(bom, cfg, artifact, now, source_sha, extra=None):
    """產品 SBOM：掃描得到的 SBOM 加上產品與製造商資料（BSI TR-03183-2 與 NTIA 最低要素的 SBOM 作者、主元件）。
    主元件沿用原本的 bom-ref（依賴關係圖的根不變），名稱與版本換成 config 的產品；原本掃描對象的名稱、序號、時間記在屬性。
    序號換新（內容已變）。CycloneDX 1.6 起用 metadata.manufacturer 與 component.manufacturer，更早的版本用 metadata.manufacture。
    extra：(元件, 依賴, 頂層 ref)，刷機包的韌體（firmware_bom.build），加在頂層 components，根元件的 dependsOn 加上頂層 ref。"""
    b = json.loads(json.dumps(bom))
    m, prod, mf = b.setdefault("metadata", {}), cfg["product"], cfg["manufacturer"]
    org = {"name": mf["name"]}
    if mf.get("website"):
        org["url"] = [mf["website"]]
    if mf.get("email") and "@" in mf["email"]:
        org["contact"] = [{"name": mf["name"], "email": mf["email"]}]
    orig = m.get("component") if isinstance(m.get("component"), dict) else {}
    props = [{"name": "sca-center:scanned-artifact", "value": str(artifact.get("name") or orig.get("name") or NR)},
             {"name": "sca-center:scanned-artifact-version", "value": str(artifact.get("version") or orig.get("version") or NR)},
             # 原主元件（名稱只留檔名：掃描時的暫存路徑不寫進要交給客戶的 SBOM）
             {"name": "sca-center:source-main-component", "value": json.dumps(
                 {k: (str(orig[k]).rstrip("/").rsplit("/", 1)[-1] if k == "name" else orig[k]) for k in ("type", "name", "version", "purl", "hashes")
                  if k in orig}, ensure_ascii=False) if orig else NR},
             {"name": "sca-center:source-sbom-serial", "value": str(b.get("serialNumber") or NR)},
             {"name": "sca-center:source-sbom-timestamp", "value": str(m.get("timestamp") or NR)},
             {"name": "sca-center:source-sbom-sha256", "value": source_sha}]
    refs = {c.get("bom-ref") for c in flatten(b.get("components"))}
    # 沒有原主元件的 bom-ref 時用 product、product-2…（不用隨機值，輸出才穩定）
    ref = orig.get("bom-ref") or next(r for r in ("product", *(f"product-{i}" for i in range(2, len(refs) + 3))) if r not in refs)
    ctype = (cfg.get("sbom") or {}).get("component_type") or ("firmware" if artifact.get("mode") == "image" else "application")
    comp = {"type": ctype, "bom-ref": ref, "name": prod["name"], "supplier": org, "properties": props}
    if prod.get("version"):        # 沒有產品版本時不填（不拿掃描對象的 ID 冒充產品版本；文件裡是 TO BE COMPLETED）
        comp["version"] = prod["version"]
    if orig.get("components"):     # 原主元件底下的子元件保留（依賴關係可能指向它們）
        comp["components"] = orig["components"]
    try:
        new_spec = tuple(int(x) for x in str(b.get("specVersion") or "0").split(".")[:2]) >= (1, 6)
    except ValueError:
        new_spec = False
    if new_spec:
        comp["manufacturer"] = m["manufacturer"] = org
    else:
        m["manufacture"] = org
    m["supplier"] = org
    m["authors"] = [{"name": mf["name"], **({"email": mf["email"]} if mf.get("email") and "@" in mf["email"] else {})}]
    m["component"] = comp
    m["timestamp"] = now
    if extra and extra[0]:
        try:
            fwmod().merge(b, ref, *extra)
        except ValueError as e:
            raise Fail(f"刷機包韌體無法併進 SBOM：{e}")
    tool = {"name": "cra_report.py", "vendor": "sca-center"}
    t = m.get("tools")
    if isinstance(t, dict):
        t.setdefault("components", []).append({"type": "application", "name": "cra_report.py", "group": "sca-center"})
    elif isinstance(t, list):
        t.append(tool)
    # 序號由內容決定（不含時間）：同樣的輸入產生同樣的序號，VEX 以 BOM-Link（序號／版本＃bom-ref）指向這份 SBOM，
    # 兩個發行版本的 VEX 才能直接比較差異；內容不同序號就不同
    b["serialNumber"], b["version"] = None, 1
    body = json.dumps(strip_work_paths({k: v for k, v in b.items() if k != "metadata"}), sort_keys=True, ensure_ascii=False) + json.dumps(
        strip_work_paths({k: v for k, v in m.items() if k != "timestamp"}), sort_keys=True, ensure_ascii=False)
    b["serialNumber"] = f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, 'sca-center-product-sbom|' + hashlib.sha256(body.encode()).hexdigest())}"
    return b


def accepted_table(rows):
    """DT 分析判定的列照舊列分析狀態與理由；VEX 判定的列（accepted_by_vex）列 VEX 的狀態、來源、負責人與說明。"""
    def cells(r):
        if r.get("accepted_by_vex"):
            v, vx = r["vex"], vexmod()
            who = f", {v['author'] if not vx.author_missing(v.get('author')) else 'author: TO BE COMPLETED'}" if v["source"] == "annotation" else ""
            return [f"VEX {v['state']} ({vx.SRC_LABEL.get(v['source'], v['source'])}{who})", "—", v.get("justification") or "not recorded",
                    v.get("detail") or "not recorded"]
        return [", ".join(sorted({a["state"] or "NOT_SET" for a in r["analysis"]})),
                "yes" if all(a["suppressed"] for a in r["analysis"]) else "partly" if any(a["suppressed"] for a in r["analysis"]) else "no",
                "; ".join(sorted({a["justification"] for a in r["analysis"] if a["justification"]})) or "not recorded",
                "; ".join(sorted({a["details"] for a in r["analysis"] if a["details"]})) or "not recorded"]
    return table(["#", "ID", "Component", "Version", "Severity", "KEV", "Analysis state", "Suppressed", "Justification", "Details"],
                 [[i, r["id"], component_text(r), version_text(r), r["severity"], kev_text(r), *cells(r)] for i, r in enumerate(rows, 1)])


def flatten(comps):
    for c in comps or []:
        if isinstance(c, dict):
            yield c
            yield from flatten(c.get("components"))


# ---------- 作業系統核心（風險評估 8.7 節、kernel-vulnerabilities.md） ----------

TIERS = ("p1", "p2", "p3", "accepted")


def tally(rs):
    """一組列的數量：列數、原始 finding 數、各層級、未處理的 KEV、未處理的各嚴重度。"""
    return {"rows": len(rs), "findings": sum(r["n_findings"] for r in rs), **{t: sum(1 for r in rs if r["tier"] == t) for t in TIERS},
            "kev_open": sum(1 for r in rs if r["kev"] and r["tier"] in OPEN_TIERS),
            "sev": Counter(r["severity"] for r in rs if r["tier"] in OPEN_TIERS),
            "distro_fixed": sum(1 for r in rs if r["tier"] == "distro_fixed"),
            "distro_fixed_kev": sum(1 for r in rs if r["tier"] == "distro_fixed" and r["kev"]),
            # cves：DT 的唯一 CVE（summary 的 dt_unique_cves）；只有 Grype 的列另外計數
            "cves": len(set().union(*(set(r["cves"]) for r in rs if not r.get("found_by")))) if rs else 0,
            "grype_only": sum(1 for r in rs if r.get("found_by") == GRYPE_ONLY)}


def kernel_fix_all(krows):
    """修補狀態 fixed 的核心列，依元件分組。每一列先去掉不比安裝版本新的修補版本，再取最低的（有多個時，最早修好的那個就夠）；
    全部修好所需的最低版本＝這些版本裡最高的一個。版本順序只對 deb 實作（deb_vercmp）：rpm、apk 等不比較，fix_all_version 留空
    （comparable False，文件不寫「最低版本」那一句）。fixed 但沒有可用版本（沒有版本或都不比安裝版本新）的列記在 without_version。"""
    groups = {}
    for r in krows:
        if r["fix_state"] != "fixed":
            continue
        g = groups.setdefault(r["component"], {"component": r["component"], "mapped_from": r["mapped_from"], "rows": 0,
                                               "without_version": 0, "fix_all_version": None, "comparable": True})
        g["rows"] += 1
        if r["ptype"] != "deb":
            g["comparable"] = False
            continue
        vers = [v for v in r["fix_versions"] if not r["version"] or deb_vercmp(v, r["version"]) > 0]
        if not vers:
            g["without_version"] += 1
            continue
        v = min(vers, key=deb_key)
        if g["fix_all_version"] is None or deb_vercmp(v, g["fix_all_version"]) > 0:
            g["fix_all_version"] = v
    for g in groups.values():
        if not g["comparable"]:
            g["fix_all_version"] = None
    return sorted(groups.values(), key=lambda g: (g["mapped_from"] is None, g["component"]))


def kernel_stage_text(status):
    st = [f"`{k}` {status[k][0]}" for k in ("C-kernel-l4t-map", "C-kernel-coverage") if status and k in status]
    return ("sca-scan kernel stages: " + ", ".join(st) + ". OK only means that the kernel was matched against vulnerability data; "
            "it does not prove that the list is complete.") if st else ""


NOT_ASSESSED_TAIL = ("Kernel vulnerabilities were NOT assessed: the absence of kernel rows does not mean that the kernel has "
                     "no known vulnerabilities.")


def kernel_absent_text(status, mode, have_findings):
    """沒有核心的列時，8.7 節的一段說明與狀態代號。核心在 SBOM 裡卻沒有比對（GAP 等）一律寫 NOT assessed，不寫「沒有弱點」。
    C-kernel-l4t-map 是 FAIL 時只說對應的步驟失敗（不斷定 SBOM 有 L4T 核心）。"""
    if not have_findings:
        return "not_assessed", "Not produced: no Dependency-Track findings (see the data status at the top of this document)."
    if status is None:
        return "unknown", ("Not determined: `status.tsv` is missing, so it is unknown whether the SBOM contains an operating system kernel "
                           "and whether it was matched. Kernel vulnerabilities are NOT assessed.")
    m = status.get("C-kernel-l4t-map")
    if m and m[0] == "FAIL":
        return "not_assessed", (f"**Kernel not assessed.** The Jetson Linux (L4T) kernel mapping step failed (`C-kernel-l4t-map` FAIL: "
                                f"{en(m[1])}), so the kernel was matched without the Canonical kernel mapping. " + NOT_ASSESSED_TAIL)
    for k, what in (("C-kernel-l4t-map", "a Jetson Linux (L4T) kernel, but no Canonical kernel mapping was applied"),
                    ("C-kernel-coverage", "an operating system kernel, but the kernel was not matched against vulnerability data")):
        if k in status and status[k][0] != "OK":
            return "not_assessed", (f"**Kernel not assessed.** The SBOM contains {what} (`{k}` {status[k][0]}: {en(status[k][1])}). "
                                    + NOT_ASSESSED_TAIL)
    if any(k in status for k in ("C-kernel-l4t-map", "C-kernel-coverage")):
        return "no_findings", ("The operating system kernel was matched, but Dependency-Track reported no findings for it. "
                               "Compare with the Grype cross-check in section 8.1; this does not prove that the kernel has no known "
                               "vulnerabilities. " + kernel_stage_text(status))
    if mode in ("image", "sbom"):
        return "no_kernel", "No operating system kernel in the SBOM (sca-scan found no kernel component, Linux kernel CPE or kernel package)."
    return "not_checked", (f"Not checked: sca-scan only checks the operating system kernel for image and SBOM scans (scan mode {mode}); "
                           "an operating system the product runs on is not covered by this scan.")


def kernel_section(krows, kinfo, status, pol, mode, have_findings, have_grype, euvd=None):
    """euvd：None＝沒有 EUVD（沒有檔案、也沒有 C-euvd 這一行）；True＝EUVD 能用；字串＝不能用的原因（EUVD 的行寫 not available，不寫 0）。"""
    """回傳 (8.7 節的內容（Markdown）, 狀態代號, summary.json 用的數量, kernel-vulnerabilities.md 的摘要段)。"""
    if not krows:
        state, text = kernel_absent_text(status, mode, have_findings)
        return text, state, None, None
    t = tally(krows)
    fs = Counter(r["fix_state"] for r in krows)
    fix_all = kernel_fix_all(krows)
    parts = []
    if kinfo and any(r["mapped_from"] for r in krows):
        parts.append(f"**What was matched.** The Jetson Linux (L4T {kinfo['release']}) kernel package `{kinfo['l4t']}` is NVIDIA's "
                     "package and has no records in the Ubuntu vulnerability data. sca-scan (`C-kernel-l4t-map`) therefore added the Canonical kernel source package "
                     f"**{kinfo['name']} {kinfo['version']}**, from which this L4T kernel is built, as a matching-only component: it is "
                     "not installed in the product and is not in `sbom.cdx.json`. Grype and Dependency-Track apply Canonical's "
                     "vulnerability and fix data for that version. **Not covered:** NVIDIA's out-of-tree kernel modules (nvgpu, "
                     "nvethernetrm, linux-nv-oot) and the NVIDIA SAUCE patches; their vulnerabilities are NOT assessed. If the L4T "
                     "kernel lacks a fix that Canonical shipped in this version, the kernel is affected although this list does not show it.")
    other = Counter((r["component"], r["version"]) for r in krows if not r["mapped_from"])
    if other:
        parts.append("Kernel components matched directly: " + "; ".join(
            f"{c} {v} ({plural(n, 'row')})" for (c, v), n in sorted(other.items())) + ".")
    if t["grype_only"]:
        parts.append(f"{plural(t['grype_only'], 'kernel row')} {verb(t['grype_only'], 'was', 'were')} found only by Grype (no Dependency-Track "
                     "finding for any of its IDs; Source IDs `GRYPE:…`). They are counted, tiered and assessed (kernel configuration, "
                     "bulk and evidence rules) like the other kernel rows.")
    stages = kernel_stage_text(status)
    if stages:
        parts.append(stages)
    metrics = [["Kernel vulnerability rows (vulnerability × component version)", t["rows"]]]
    metrics += [[f"Grype fix state: {s}", fs[s]] for s in FIX_STATES if s != "unknown" or fs[s]]
    metrics += [[f"{x.upper()} – {pol['tiers'][x]['label']}", t[x]] for x in ("p1", "p2", "p3")]
    metrics += [[pol["accepted"]["label"], t["accepted"]], ["Open rows listed in a KEV catalogue", t["kev_open"]]]
    if euvd is not None:
        metrics.append([EUVD_OPEN_LABEL, sum(1 for r in krows if euvd_hit(r) and r["tier"] in OPEN_TIERS) if euvd is True
                        else f"not available: {euvd}"])
    parts.append(table(["Metric", "Rows"], metrics))
    if not have_grype:
        parts.append("Fix states are unknown: there is no Grype result (`scan/grype.json`) for this scan.")
    for g in fix_all:
        mapped = bool(g["mapped_from"])
        if g["fix_all_version"]:
            s = (f"**Fixed in later versions:** {plural(g['rows'], 'row')} {verb(g['rows'], 'is', 'are')} fixed in later {'Canonical kernel' if mapped else g['component']} "
                 f"versions (Grype fix state `fixed`). The lowest version that fixes all of them is **{g['component']} {g['fix_all_version']}** "
                 "(the highest fix version among them). ")
            s += (f"Recommended action: move to a Jetson Linux (L4T) release whose kernel is based on {g['component']} {g['fix_all_version']} "
                  "or later, then scan again; NVIDIA's own changes are not covered by this statement." if mapped else
                  f"Recommended action: update the kernel to {g['component']} {g['fix_all_version']} or later, then scan again.")
            if g["without_version"]:
                s += (f" {g['without_version']} of these rows {verb(g['without_version'], 'has', 'have')} no fix version above the installed version in Grype and are not "
                      "taken into account for this version.")
        elif not g["comparable"]:
            s = (f"**Fixed in later versions:** {plural(g['rows'], 'row')} for {g['component']} {verb(g['rows'], 'is', 'are')} fixed according to Grype (see the fix "
                 "versions in the full list). A single version that fixes all of them is not computed: version ordering is only "
                 "implemented for Debian packages.")
        else:
            s = (f"**Fixed in later versions:** {plural(g['rows'], 'row')} for {g['component']} {verb(g['rows'], 'is', 'are')} fixed according to Grype, but Grype gives no "
                 "fix version above the installed version.")
        parts.append(s)
    if fs["not-fixed"] or fs["wont-fix"]:
        parts.append(f"**Not fixed:** {plural(fs['not-fixed'], 'row')} {verb(fs['not-fixed'], 'has', 'have')} no fix from the kernel supplier yet (`not-fixed`; this includes "
                     f"vulnerabilities still under triage or deferred) and {fs['wont-fix']} will not be fixed (`wont-fix`). Updating within "
                     "this kernel version line does not remove them yet; assess them in the risk register "
                     "(`risk-assessment.md`, section 5) and track them.")
    if fs["no Grype data"] and have_grype:
        parts.append(f"{plural(fs['no Grype data'], 'row')} {verb(fs['no Grype data'], 'was', 'were')} not matched by Grype: "
                     f"{verb(fs['no Grype data'], 'its', 'their')} fix state is unknown.")
    common, acc = "\n\n".join(parts), kernel_accepted_text(krows, full=False)
    parts = [f"{plural(t['rows'], 'vulnerability row')} {verb(t['rows'], 'is', 'are')} for the operating system kernel. {verb(t['rows'], 'It is', 'They are')} counted in the tiers and in the "
             f"data status of this document (section 8.2), but {verb(t['rows'], 'is', 'are')} not listed in sections 8.4–8.6 or Appendix A.", common]
    p1 = [r for r in krows if r["tier"] == "p1"]
    parts.append(f"#### Kernel rows in P1 ({len(p1)})\n\nRegardless of fix state. P1: {rule_text('p1', pol, euvd is True)}.\n\n"
                 + vuln_table(p1, kernel=True))
    parts.append(acc)
    rest = t["p2"] + t["p3"]
    full = (f"**Full list:** `{KERNEL_DOC[1]}` ({plural(t['rows'], 'row')}; same columns as sections 8.4–8.6 plus tier, Grype fix state and "
            "analysis state).")
    if rest == 0:
        parts.append(f"All kernel rows are in P1 or accepted and are listed above or counted by VEX source. {full}")
    elif not (p1 or t["accepted"]):
        parts.append(f"No kernel row is in P1 or accepted; {'the' if rest == 1 else 'all'} {plural(rest, 'kernel row')} (P2 {t['p2']}, P3 {t['p3']}) "
                     f"{verb(rest, 'is', 'are')} only counted here. {full}")
    else:
        parts.append(f"The remaining {plural(rest, 'kernel row')} (P2 {t['p2']}, P3 {t['p3']}) {verb(rest, 'is', 'are')} only counted here. {full}")
    counts = {"rows": t["rows"], "findings_raw": t["findings"], **{x: t[x] for x in TIERS}, "kev_open": t["kev_open"],
              "dt_unique_cves": t["cves"], "grype_only_rows": t["grype_only"], "fix_states": {s: fs[s] for s in FIX_STATES}, "fix_all": fix_all}
    return "\n\n".join(parts), "listed", counts, common + "\n\n" + kernel_accepted_text(krows)


def ann_label(a):
    return a["cve"] + "".join(f" ({x})" for x in (a.get("purl"), a.get("version") and f"version {a['version']}") if x)


def kernel_accepted_text(krows, full=True):
    """accepted 的核心列：和附錄 A 一樣列出分析狀態、suppress、理由與說明（不只在完整清單裡寫狀態）。
    full=False（風險評估）：VEX 判定的列（核心設定檢查可能有上千列）只寫來源與數量，逐列在 kernel-vulnerabilities.md。"""
    acc, vx = [r for r in krows if r["tier"] == "accepted"], vexmod()
    shown = acc if full else [r for r in acc if not r.get("accepted_by_vex")]
    byv = Counter(vx.SRC_LABEL.get(r["vex"]["source"], r["vex"]["source"]) for r in acc if r.get("accepted_by_vex"))
    note = "" if full or not byv else (f"\n\nAnother {plural(sum(byv.values()), 'row')} {verb(sum(byv.values()), 'is', 'are')} accepted because "
                                       f"{verb(sum(byv.values()), 'its', 'their')} VEX status is not affected ("
                                       + ", ".join(f"{n} by {k}" for k, n in sorted(byv.items())) + f"); listed in `{KERNEL_DOC[1]}`.")
    return (f"#### Accepted kernel rows ({len(acc)})\n\nRegardless of fix state. The decision recorded for each row (justification, owner "
            f"and date must be on record):\n\n{accepted_table(shown)}{note}")


def kernel_document(krows, ctx, risk_st, summary, split=True):
    """kernel-vulnerabilities.md：核心的完整清單（依層級，同層級照主清單的順序）。"""
    rows = sorted(krows, key=lambda r: TIERS.index(r["tier"]))
    where = "sections 8.3 and 8.7" if split else "section 8, where the kernel rows are also listed"
    return (f"# Operating System Kernel Vulnerabilities – {ctx['product.name']} {ctx['product.version']}\n\n"
            f"> DRAFT generated by {ctx['report.tool']} on {ctx['report.generated']} from the scan of `{ctx['artifact.name']}` "
            f"({ctx['artifact.version']}). Full list of the vulnerability rows for the operating system kernel. The summary, the fix "
            f"advice and the handling rules are in `risk-assessment.md` ({where}). Review before use.\n\n"
            f"**Vulnerability data status: {risk_st}** (same as `risk-assessment.md`, section 8)\n\n"
            f"## Summary\n\n{summary}\n\n## Full list ({len(rows)})\n\n{vuln_table(rows, kernel=True)}\n")


# ---------- NVIDIA 安全公告（Jetson Linux；風險評估 8.8 節） ----------

NV_STAGE = "C-nvidia-bulletins"
NV_HEAD = "\n\n### 8.8 NVIDIA security bulletins (Jetson Linux)\n\n"


def nv_where(w):
    return {"flash": "flash (not visible in the SBOM)", "unknown": "not stated"}.get(w, f"`{w}` (root file system)")


def nv_reason_text(nvb):
    """C-nvidia-bulletins 不是 OK 的原因（英文；status.tsv 的說明是中文，en() 讀不出來，所以從 nvidia-bulletins.json 重組）。"""
    why, m, jl = [], nvb.get("mirror"), nvb.get("jetson_linux") or {}
    t = nvb.get("table")
    if t is None:
        why.append("there is no bulletin table, so the bulletins were not compared")
    if t is not None and m is None:
        why.append("no NVIDIA bulletin mirror was configured (sca-scan reads its path from the PILOT_ENV key "
                   "`NVIDIA_BULLETINS_MIRROR`), so it is unknown whether the table covers the latest bulletins")
    elif m and not m.get("ok"):
        if m.get("fetched_utc"):
            why.append(f"the bulletin mirror is out of date (downloaded {m['fetched_utc']}, {m.get('age_days')} days ago; limit "
                       f"{m.get('max_age_days')} days), so it is unknown whether the table covers the latest bulletins")
        else:
            why.append(f"the bulletin mirror `{m.get('path')}` is missing or unreadable, so it is unknown whether the table covers "
                       "the latest bulletins")
    stale = [p for p in nvb.get("pending_bulletins") or [] if {"not_in_table", "revised"} & set(p.get("reasons") or [])]
    if stale:
        why.append(f"the mirror has {plural(len(stale), 'bulletin')} that {verb(len(stale), 'is', 'are')} not in the table or "
                   f"{verb(len(stale), 'was', 'were')} revised by NVIDIA ({', '.join(p['id'] for p in stale[:10])})")
    if t and t.get("same_line_unreviewed_rows"):
        why.append(f"{plural(t['same_line_unreviewed_rows'], 'table row')} for Jetson Linux {jl.get('line')} "
                   f"{verb(t['same_line_unreviewed_rows'], 'is', 'are')} not reviewed yet (unreviewed rows never produce findings)")
    if nvb.get("needs_vendor_confirmation"):
        why.append(f"{plural(len(nvb['needs_vendor_confirmation']), 'CVE')} need{'s' if len(nvb['needs_vendor_confirmation']) == 1 else ''} "
                   "confirmation from NVIDIA")
    if jl.get("other_versions"):
        why.append(f"the SBOM also contains Jetson Linux {', '.join(jl['other_versions'])}")
    return why


def nvidia_section(nvb, status):
    """回傳 (8.8 節的 Markdown（前面帶空行；不是 Jetson Linux 時是空字串，非 Jetson 的文件不變）, 狀態代號, summary.json 用的數量)。"""
    st = (status or {}).get(NV_STAGE)
    if not isinstance(nvb, dict) or not nvb.get("jetson_linux"):
        if st:   # 有這一列卻沒有結果檔（例如 nvidia_bulletins.py 失敗）
            return (NV_HEAD + f"**Not assessed.** `{NV_STAGE}` is {st[0]} and there is no result file (`scan/nvidia-bulletins.json`): "
                    "NVIDIA's Jetson Linux security bulletins were NOT compared with this release. The absence of NVIDIA findings "
                    "does not mean that the release is not affected."), "not_assessed", None
        return "", "not_applicable", None
    jl, t, m = nvb["jetson_linux"], nvb.get("table") or {}, nvb.get("mirror")
    line, stname = jl.get("line"), (st[0] if st else nvb.get("status") or NR)
    anc = jl.get("anchor") or {}
    parts = [f"The SBOM contains NVIDIA Jetson Linux **{jl.get('version')}** (from `{anc.get('name')}` {anc.get('version')}; release build "
             f"date {jl.get('build_date') or 'unknown'}). NVIDIA publishes Jetson Linux vulnerabilities as security bulletins with "
             "free-text version ranges that Grype and Dependency-Track cannot match. sca-scan (`C-nvidia-bulletins`) compares the "
             "release with a manually curated table of these bulletins (`tools/pilot/lib/nvidia-bulletins.json`). Only table rows "
             "that a person has reviewed produce findings; they appear with source `NVIDIA` in the vulnerability lists above."]
    why = nv_reason_text(nvb)
    parts.append(f"`{NV_STAGE}` is **{stname}**" + (": " + "; ".join(why) + "." if why else "."))
    nur = nvb.get("lines_from_unreviewed_rows") or 0
    if nur:
        parts.append(f"**Not reviewed by a person:** the release lines each advisory names are taken from table rows that have not been "
                     f"reviewed by a person (reviewed_until: {t.get('reviewed_until') or 'not set'}). This applies to {nur} of the "
                     f"{plural(len(nvb.get('presumed_included') or []) + len(nvb.get('needs_vendor_confirmation') or []), 'entry', 'entries')} "
                     "in the two tables below, so their classification is not confirmed even where the stage is OK.")
    mtxt = ("not configured" if m is None else
            f"commit {str(m.get('commit') or '?')[:12]}, downloaded {m.get('fetched_utc') or 'unknown'}"
            + (f" ({m.get('age_days')} days old)" if m.get("age_days") is not None else "") + ("" if m.get("ok") else " – NOT usable"))
    nf, pi, nc = nvb.get("findings") or [], nvb.get("presumed_included") or [], nvb.get("needs_vendor_confirmation") or []
    parts.append(table(["Item", "Value"], [
        ["Jetson Linux release", f"{jl.get('version')} (line {line}; build date {jl.get('build_date') or 'unknown'})"],
        [f"Table rows for Jetson Linux {line}", f"{t.get('same_line_rows', 0)} ({t.get('same_line_unreviewed_rows', 0)} not reviewed)"],
        ["Table rows in total", f"{t.get('rows', 0)} ({t.get('reviewed_rows', 0)} reviewed)"] if t else ["Bulletin table", "missing"],
        ["Table reviewed until", t.get("reviewed_until") or "not set (no bulletin has been reviewed yet)"],
        ["Bulletin mirror", mtxt],
        ["Findings (reviewed rows)", len(nf)],
        [f"Presumed included (bulletin × CVE; the bulletin does not name line {line})", len(pi)],
        ["Needs confirmation from NVIDIA (bulletin × CVE)", len(nc)]]))
    if nf:
        parts.append(f"#### NVIDIA findings ({len(nf)})\n\n" + table(
            ["#", "CVE", "Bulletin", "Component", "Where it lives", "Affected (bulletin text)", "Fixed in (bulletin text)"],
            [[i, f["vulnerability"]["vulnId"], f["evidence"]["bulletin"], f["evidence"].get("component") or "not stated",
              nv_where(f["evidence"].get("where_it_lives")), f["evidence"].get("affected_text"), f["evidence"].get("fixed_text")]
             for i, f in enumerate(nf, 1)]))
    always = (nvb.get("policy") or {}).get("unnamed_line") == "always_needs_confirmation"
    parts.append(f"**Bulletins that do not name Jetson Linux {line}.** "
                 + ("Rule: every such CVE needs confirmation from NVIDIA." if always else
                    "Rule (decided 2026-11-02): when this release was built after the bulletin date (the later of first publication "
                    "and last revision), the fix is "
                    "presumed to be included in the release; NVIDIA has not confirmed this. When the release was built on or before "
                    "the bulletin date, or a date is unknown, the CVE needs confirmation from NVIDIA.")
                 + " Neither case means that the release is not affected.")
    cols = ["#", "CVE", "Bulletin", "Bulletin date", "Lines named", "Where it lives"]
    reasons_en = {"range_gap": "version between the affected range and the fix",
                  "line_not_named": f"line {line} not named, release not built after the bulletin"}
    def nrows(xs, reason=False):
        return [[i, x["cve"], x["bulletin"], x.get("bulletin_date") or "unknown", ", ".join(x.get("lines_named") or []) or "–",
                 ", ".join(nv_where(w) for w in (x.get("where_it_lives") if isinstance(x.get("where_it_lives"), list)
                                                 else [x.get("where_it_lives") or "unknown"]))]
                + ([("no Jetson Linux line named (IGX OS only)" if x.get("reason") == "line_not_named"
                     and not any(str(l).isdigit() for l in x.get("lines_named") or []) else reasons_en.get(x.get("reason"), x.get("reason")))]
                   if reason else [])
                for i, x in enumerate(xs, 1)]
    parts.append(f"#### Presumed included – not confirmed by NVIDIA ({len(pi)})\n\n" + table(cols, nrows(pi)))
    parts.append(f"#### Needs confirmation from NVIDIA ({len(nc)})\n\n" + table(cols + ["Reason"], nrows(nc, True)))
    def flash(x):
        w = x.get("where_it_lives")
        return "flash" in (w if isinstance(w, list) else [w])
    fl = sorted({x["cve"] for x in pi + nc if flash(x)} | {f["vulnerability"]["vulnId"] for f in nf if f["evidence"].get("where_it_lives") == "flash"})
    if fl:
        parts.append(f"**Not visible in the SBOM:** {plural(len(fl), 'CVE')} ({', '.join(fl[:12])}{', …' if len(fl) > 12 else ''}) "
                     f"{verb(len(fl), 'is', 'are')} in firmware stored in the device's flash memory (for example UEFI, the bootloader or "
                     "OP-TEE). Flash contents are not part of the root file system SBOM: their status is inferred from the Jetson Linux "
                     "release of the root file system, and the firmware flashed on a device may differ.")
    uw = nvb.get("unreviewed_would_match") or []
    if uw:
        parts.append(f"Not counted as findings: {plural(len(uw), 'unreviewed table row')} would match this release "
                     f"({', '.join(sorted({x['cve'] for x in uw}))}); a person must review {verb(len(uw), 'it', 'them')} first.")
    parts.append("Not covered: customer-modified BSP components (a self-built kernel, initrd or UEFI keeps NVIDIA's version number), "
                 "and IGX OS.")
    counts = {"status": stname, "release": jl.get("version"), "build_date": jl.get("build_date"), "findings": len(nf),
              "presumed_included": len(pi), "needs_vendor_confirmation": len(nc),
              "same_line_unreviewed_rows": t.get("same_line_unreviewed_rows", 0), "flash_cves": len(fl),
              "mirror_commit": (m or {}).get("commit"), "reviewed_until": t.get("reviewed_until")}
    return NV_HEAD + "\n\n".join(parts), "listed", counts


# ---------- 發行版已修補（風險評估 8.8／8.9 節；tools/pilot/lib/distro_recheck.py） ----------

DISTRO_TITLE = "Reported only via NVD but fixed by the distribution (backported)"


def distro_index(drc):
    """scan/distro-recheck.json → {(ID, 名稱, 版本): 那一列}：只收 distro_fixed，而且檔案的 status 是 OK（GAP 時沒有判定，一列都不移）。"""
    if not isinstance(drc, dict) or drc.get("status") != "OK":
        return {}
    return {tuple(str(k) for k in x["key"]): x for x in drc.get("rows") or []
            if isinstance(x, dict) and x.get("decision") == "distro_fixed" and isinstance(x.get("key"), list) and len(x["key"]) == 3}


class DistroKept(Counter):
    """apply_distro 沒有移的列數 {原因: 數量}；exploited_rows：已遭利用、發行版紀錄說已修補但沒有移的列（給工程師看的資訊）。"""
    def __init__(self):
        super().__init__()
        self.exploited_rows = []


def apply_distro(rows, drc):
    """distro_fixed 的列改成 tier distro_fixed（只移 P1–P3、不移核心；列裡每一筆 finding 都要在 distro_recheck 看過的 source_ids 內，
    例如多了 NVIDIA 公告的 finding 就不移）。已遭利用的列（KEV、EUVD、人工證據）不自動移：被利用的列只能由具名的工程師離開 P1，
    發行版紀錄當資訊列在區段裡（kept["exploited"]）。回傳 (移出的列, 判定 distro_fixed 但沒有移的列數 {原因: 數量})。"""
    idx, moved, kept = distro_index(drc), [], DistroKept()
    for r in rows:
        x = idx.get(tuple(r["key"]))
        if x is None:
            continue
        if r["kernel"]:
            kept["kernel"] += 1
        elif r["tier"] not in OPEN_TIERS:
            kept[r["tier"]] += 1
        elif exploited(r):
            kept["exploited"] += 1
            r["distro_info"] = x
            kept.exploited_rows.append(r)
        elif not set(r["source_ids"]) <= set(x.get("source_ids") or []):
            kept["other_findings"] += 1
        else:
            r["tier_before"], r["tier"], r["distro"] = r["tier"], "distro_fixed", x
            moved.append(r)
    return moved, kept


def distro_reason_text(drc):
    """D-distro-recheck 不是 OK 的原因（英文；distro_recheck.py 的說明是中文）。"""
    m = drc.get("mirror") or {}
    if not m.get("path"):
        return "no distribution OSV mirror was configured (sca-scan reads its path from the PILOT_ENV key `OSV_DISTRO_MIRROR`)"
    if m.get("age_days") is not None and m.get("max_age_days") is not None and m["age_days"] > m["max_age_days"]:
        return (f"the distribution OSV mirror is out of date (downloaded {m.get('fetched_utc')}, {m['age_days']} days ago; limit "
                f"{m['max_age_days']} days)")
    return f"the distribution OSV mirror `{m.get('path')}` is missing, incomplete or unreadable"


def distro_section(drc, moved, kept, num, status):
    """回傳 (小節的 Markdown（前面帶空行；沒有 scan/distro-recheck.json 也沒有這個階段時是空字串）, 狀態代號)。"""
    st = (status or {}).get(DISTRO_STAGE)
    head = f"\n\n### {num} {DISTRO_TITLE}\n\n"
    if not isinstance(drc, dict):
        if st:
            return (head + f"**Not rechecked.** `{DISTRO_STAGE}` is {st[0]} and there is no result file (`scan/distro-recheck.json`): no row "
                    "was moved. Rows reported only via NVD/GitHub on Debian/Ubuntu packages stay in P1–P3, even where the distribution "
                    "has already fixed them."), "not_assessed"
        return "", "not_applicable"
    intro = ("Dependency-Track also matches Debian/Ubuntu packages against NVD (CPE) and other data that is not from the distribution "
             "(GitHub advisories, OSV records of other ecosystems). These sources only know the upstream version (for example OpenSSL "
             "3.0.13); they do not know that the distribution backported a fix into its own package revision (for example "
             "3.0.13-0ubuntu3.11). sca-scan (`D-distro-recheck`) rechecks every row on a Debian/Ubuntu package whose findings all come "
             "from such sources and that Grype (which uses the distribution data) did not match. It reads the distribution's own OSV "
             "per-CVE records (UBUNTU-CVE-…, DEBIAN-CVE-…) for the same release and source package and compares versions with "
             "the Debian version ordering; a row is only moved when the per-CVE record says the installed version is fixed (an "
             "advisory such as a USN, DSA or DLA alone never moves a row). Operating system kernel rows are not rechecked (section 8.7). The raw Dependency-Track "
             "findings are not changed (`scan/distro-recheck.json` holds the evidence).")
    if drc.get("status") != "OK":
        return (head + intro + f"\n\n**Not applied.** `{DISTRO_STAGE}` is {drc.get('status') or '?'}: {distro_reason_text(drc)}. No row "
                "was moved: rows reported only via NVD/GitHub on Debian/Ubuntu packages stay in P1–P3, even where the distribution has "
                "already fixed them."), "not_applied"
    c = drc.get("counts") or {}
    nfix = c.get("distro_fixed", 0)
    parts = [intro, table(["Recheck result (rows)", "Rows", "Effect"], [
        ["Fixed by the distribution (installed version ≥ distribution fix version)", nfix,
         f"{len(moved)} moved here from P1–P3" + (f"; {sum(kept.values())} not moved (accepted, kernel, exploited or other findings in the row)"
                                                  if kept else "")],
        ["Affected according to the distribution", c.get("distro_affected", 0), "kept in P1–P3"],
        ["Distribution record exists but does not list this release or package", c.get("distro_not_listed", 0), "kept in P1–P3 (unknown)"],
        ["Fixed according to a distribution advisory only (USN/DSA/DLA; no per-CVE record)", c.get("distro_fixed_advisory_only", 0),
         "kept in P1–P3 (an advisory's CVE list covers the whole advisory, not each release and package)"],
        ["No distribution record for the CVE", c.get("no_distro_record", 0), "kept in P1–P3"],
        ["Not rechecked: Grype matched the same vulnerability on the package", c.get("skipped_grype_matched", 0), "kept (Grype decides)"],
        ["Not rechecked: the row also has a distribution finding", c.get("skipped_distro_source", 0), "kept"],
        ["Not rechecked: operating system kernel", c.get("skipped_kernel", 0), "kept (section 8.7)"],
        ["Not rechecked: distribution release unknown", c.get("skipped_release_unknown", 0), "kept"]])]
    u2n = sum(1 for r in moved if r["distro"].get("via") == "U2")
    if u2n:
        parts.append(f"{u2n} of the moved rows are Python modules installed by an Ubuntu package. They are moved by the evidence rule U2, not by "
                     "the recheck above: the Ubuntu CVE Tracker marks the owning source package as released in this Ubuntu release and the "
                     "installed source version is not older than the release that fixes it (the PyPI fix version does not apply). Their "
                     "\"distribution record\" column names the Tracker, not an OSV record.")
    held = getattr(kept, "exploited_rows", [])
    if held:
        parts.append(f"**Exploited rows with a distribution record that states a fix – not moved ({len(held)}):** " + "; ".join(
            f"{', '.join(r['cves']) or r['id']} on {r['component']} {r['version']} (distribution record "
            f"{', '.join(sorted({e.get('record') or '?' for e in r['distro_info'].get('evidence') or []}))}, fix version "
            f"{', '.join(sorted({e.get('fixed_version') or '?' for e in r['distro_info'].get('evidence') or []}, key=deb_key))})"
            for r in held)
            + ". These vulnerabilities are known to be exploited (KEV, EUVD or manual evidence), so the recheck never moves them: "
              "they stay in P1 and leave it only by a decision of a named engineer. The distribution record is shown here as information "
              "(confirm it, for example in the package changelog, and record the decision in Dependency-Track).")
    kev = [r for r in moved if r["kev"] or euvd_hit(r)]     # EUVD 的被利用標記也是 KEV 清單（不設 kev）
    if kev:
        parts.append(f"**Listed in a KEV catalogue ({len(kev)}):** " + "; ".join(
            f"{', '.join(r['cves']) or r['id']} on {r['component']} {r['version']} (distribution record "
            f"{', '.join(sorted({e.get('record') or '?' for e in r['distro'].get('evidence') or []}))})" for r in kev)
            + ". These vulnerabilities are known to be exploited. They are moved here only because the distribution's record states "
              "that the installed package contains the fix. Confirm this (for example in the package changelog) and record the "
              "decision in Dependency-Track before relying on it.")
    else:
        parts.append("None of the moved rows is listed in a KEV catalogue.")
    parts.append(f"#### Moved rows ({len(moved)})\n\nTier before: the tier the row would have without this recheck.\n\n" + table(
        ["#", "CVE", "Component", "Installed version", "Source package", "Distribution fix version", "Distribution record",
         "Record modified", "Release", "Tier before", "KEV", "Source IDs"],
        [[i, ", ".join(r["cves"]) or r["id"], component_text(r), r["version"]
          + (f" (source {r['distro'].get('source_version')})" if r["distro"].get("source_version") not in (None, r["version"]) else ""),
          r["distro"].get("source_package"),
          ", ".join(sorted({e.get("fixed_version") or "?" for e in r["distro"].get("evidence") or []}, key=deb_key)),
          ", ".join(sorted({e.get("record") or "?" for e in r["distro"].get("evidence") or []})),
          max((str(e.get("modified") or "")[:10] for e in r["distro"].get("evidence") or []), default="") or None,
          (lambda rel: f"{rel.get('distro')} {rel.get('version')} ({rel.get('codename')})" if rel else None)(r["distro"].get("release")),
          r["tier_before"].upper(), kev_text(r), ", ".join(r["source_ids"])] for i, r in enumerate(moved, 1)]))
    return head + "\n\n".join(parts), "listed"


# ---------- 產生 ----------

def scan_command(project, out, cfg):
    """--run-scan 的 sca-scan 指令（清單，不經 shell）。"""
    s = cfg.get("scan") or {}
    mode, target = s.get("mode"), s.get("target")
    if mode not in ("image", "dir", "sbom") or (mode in ("image", "sbom") and not target):
        raise Fail("config.json 的 scan.mode 要是 image／dir／sbom，image 與 sbom 要有 scan.target")
    if mode != "image":
        target = str((project / (target or ".")).resolve())
    return [str(ROOT / "tools" / "pilot" / "sca-scan"), f"--{mode}", target, "--out", str(out),
            "--name", s.get("name") or cfg["product"]["name"]] + list(s.get("options") or [])


# ---------- 分層（bsp／os／host-tool／unknown；規則見 docs/LAYERS.md） ----------
# SBOM 的元件由 pipeline/sbom-layers.py（pipeline/lib/layers.py）標 property；沒有任何元件帶 dumpling:layer 時
# 這一節的程式全部不動作（layers_on 為 False），輸出和沒有分層功能時一樣。property 名稱要和 pipeline/lib/layers.py 一致（測試核對）。
LAYER_PROP, LAYER_BASIS_PROP, LAYER_RESP_PROP = "dumpling:layer", "dumpling:layer-basis", "dumpling:os-responsibility"
LAYER_VALUES = ("bsp", "os", "host-tool", "unknown")
LAYER_PRECEDENCE = ("bsp", "unknown", "os", "host-tool")      # 同一列對到多個層時：最保守的優先（在產品上、我們負責的優先）
LAYER_RANK = {"bsp": 0, "unknown": 1, "os": 2, "host-tool": 3}
OS_RESPONSIBILITIES = ("ours", "customer", "upstream-vendor")
LAYER_ZH = {"bsp": "BSP", "os": "OS", "unknown": "unknown", "host-tool": "host tools"}
DISTRO_PURL_TYPES = ("deb", "rpm", "apk", "alpm")


def _purl_key(purl):
    return purl.split("#", 1)[0].split("?", 1)[0] if isinstance(purl, str) else ""


def _purl_type_name(purl):
    body = _purl_key(purl)
    if not body.startswith("pkg:"):
        return None, None
    typ, _, rest = body[4:].partition("/")
    name = urllib.parse.unquote(rest.rsplit("/", 1)[-1].split("@", 1)[0]) if rest else None
    return (typ.lower() or None), (name or None)


def build_layer_index(bom):
    """SBOM（scan 的 sbom/sbom.cdx.json）→ 分層索引；沒有任何元件帶 dumpling:layer → None（不分層）。
    索引：purl（不含 qualifiers）、(名稱, 版本)、發行版套件名稱 → 該處出現過的層（集合）；host-tool 元件清單；各層元件數；
    SBOM metadata 的 dumpling:os-responsibility。沒標層或值不認得的元件算 unknown（不丟）。"""
    if not isinstance(bom, dict):
        return None
    comps = list(flatten(bom.get("components")))
    props = [{p["name"]: p["value"] for p in c.get("properties") or []
              if isinstance(p, dict) and isinstance(p.get("name"), str) and isinstance(p.get("value"), str)} for c in comps]
    if not any(LAYER_PROP in p for p in props):
        return None
    idx = {"purl": {}, "nv": {}, "deb": {}, "counts": dict.fromkeys(LAYER_VALUES, 0), "host": [], "basis": Counter(), "unknown_types": Counter()}
    for c, p in zip(comps, props):
        layer = p.get(LAYER_PROP) if p.get(LAYER_PROP) in LAYER_VALUES else "unknown"
        idx["counts"][layer] += 1
        idx["basis"][p.get(LAYER_BASIS_PROP) or "(none)"] += 1
        pk = _purl_key(c.get("purl"))
        if pk:
            idx["purl"].setdefault(pk, set()).add(layer)
        if c.get("name"):
            idx["nv"].setdefault((c["name"], str(c.get("version") or "")), set()).add(layer)
        t, n = _purl_type_name(c.get("purl"))
        if t in DISTRO_PURL_TYPES and n:
            idx["deb"].setdefault(n, set()).add(layer)
        if layer == "host-tool":
            idx["host"].append({"name": c.get("name") or "?", "version": c.get("version") or "", "purl": c.get("purl") or ""})
        if layer == "unknown":
            idx["unknown_types"][t or ("(no purl)" if not c.get("purl") else "(other)")] += 1
    mp = {q["name"]: q["value"] for q in (bom.get("metadata") or {}).get("properties") or []
          if isinstance(q, dict) and isinstance(q.get("name"), str) and isinstance(q.get("value"), str)}
    idx["resp"] = mp.get(LAYER_RESP_PROP) if mp.get(LAYER_RESP_PROP) in OS_RESPONSIBILITIES else None
    return idx


def _pick_layer(layers):
    return next((l for l in LAYER_PRECEDENCE if l in layers), "unknown")


def host_only(purl, name, version, idx):
    """這個元件在 SBOM 裡只出現在 host-tool 層（同一個 purl 或名稱＋版本在別的層也有 → 不算，保守地留在產品清單）。"""
    ls = idx["purl"].get(_purl_key(purl))
    if ls is None:
        ls = idx["nv"].get((name, str(version or "")))
    return ls == {"host-tool"}


def drop_host_tool(findings, grype, idx):
    """host-tool 層元件上的 DT findings 與 Grype 比對移出產品的比對結果（不進產品漏洞清單，也不進交叉核對）。
    回傳 (findings, grype, 記錄)；記錄：移出的 finding／比對筆數與 CVE 編號（summary.json 與報告的 host tools 一節用，漏洞不是消失，只是不在產品清單）。"""
    info = {"findings": 0, "matches": 0, "ids": set()}
    if isinstance(findings, list):
        keep = []
        for f in findings:
            c = (f.get("component") if isinstance(f, dict) else None) or {}
            if isinstance(f, dict) and host_only(c.get("purl"), c.get("name"), c.get("version"), idx):
                info["findings"] += 1
                info["ids"].add(str((f.get("vulnerability") or {}).get("vulnId") or "?"))
            else:
                keep.append(f)
        findings = keep
    if isinstance(grype, dict) and isinstance(grype.get("matches"), list):
        keep = []
        for m in grype["matches"]:
            a = (m.get("artifact") if isinstance(m, dict) else None) or {}
            if isinstance(m, dict) and host_only(a.get("purl"), a.get("name"), a.get("version"), idx):
                info["matches"] += 1
                info["ids"].add(str((m.get("vulnerability") or {}).get("id") or "?"))
            else:
                keep.append(m)
        grype = dict(grype, matches=keep)
    return findings, grype, info


def layer_of_row(r, idx):
    """漏洞列 → (層, 依據)。順序：cra_report 自己用 BSP 專屬輸入產生的列（UEFI／OP-TEE 內建函式庫、NVIDIA 公告、廠商核心 CVE 清單）→ bsp；
    purl → 名稱＋版本 → 對應來源（mapped_from、l4t 核心對應）→ 安裝的二進位套件（DT 以原始碼套件比對時）→ 擁有它的 deb（Ubuntu 打包的 Python）。
    都對不到 → unknown（不猜）。同一列對到多個層時 bsp > unknown > os（保守）。host-tool 不會到這裡（已在比對結果階段移出）。"""
    if r.get("found_by") == KERNEL_CNA:
        return "bsp", "synthetic:kernel-cna"
    if r.get("bundled_in"):
        return "bsp", "synthetic:bundled-library"
    if r.get("source_ids") and all(str(x).startswith("NVIDIA:") for x in r["source_ids"]):
        return "bsp", "synthetic:nvidia-bulletin"
    pk = _purl_key(r.get("purl"))
    if pk in idx["purl"]:
        return _pick_layer(idx["purl"][pk]), "purl"
    if (r.get("name"), r.get("version")) in idx["nv"]:
        return _pick_layer(idx["nv"][(r["name"], r["version"])]), "name-version"
    names = [n for n in [r.get("mapped_from")] + list(r.get("installed_as") or [])
             + [((r.get("deb_python") or {}).get("owner") or {}).get("name")] if n]
    found = set().union(*(idx["deb"].get(n, set()) for n in names)) if names else set()
    if found:
        return _pick_layer(found), "owner-package"
    return "unknown", "unmatched"


def layer_todo(layer, resp):
    """這一層的列算不算我們的待辦：bsp、unknown 一定算；os 只有 os_responsibility 是 ours 或沒給（保守）時算。"""
    return layer != "os" or resp in (None, "ours")


def notify_rows(rows, resp):
    """要通知客戶的列：OS 層、不是我們的待辦（customer／upstream-vendor）、而且已被利用（KEV、EUVD、人工證據）、還沒被判定為不受影響。"""
    return [r for r in rows if r.get("layer") == "os" and not r.get("layer_todo", True) and exploited(r)
            and r["tier"] in ("p1", "p2", "p3", "distro_fixed")]


RESP_TEXT = {
    "ours": "The OS layer is part of the product we ship and maintain: its open rows are our to-do, like the BSP layer.",
    "customer": "The OS layer (the example root file system) is the customer's responsibility. It is scanned and listed separately for the "
                "customer's reference; its open rows are not our to-do and do not by themselves make the status ATTENTION. Exploited rows "
                "(KEV, EUVD, manual evidence) in the OS layer are listed under customer notification.",
    "upstream-vendor": "The OS is the responsibility of the upstream OS vendor. It is scanned and listed separately; its open rows are not "
                       "our to-do and do not by themselves make the status ATTENTION, but we notify the customer: exploited rows (KEV, EUVD, "
                       "manual evidence) in the OS layer are listed under customer notification.",
    None: "GAP: os_responsibility was not given (`--os-responsibility` or the SBOM property `dumpling:os-responsibility`). It is not defaulted: "
          "all layers are treated as our to-do (the most conservative way) until it is set.",
}


def layers_summary(rows, vrows, idx, resp, host_info, notify):
    """summary.json 的 layers 與 vulnerability-rows.json 的 layers 共用的內容。"""
    by = {l: [r for r in rows if r.get("layer") == l] for l in ("bsp", "os", "unknown")}
    return {
        "active": True, "os_responsibility": resp, "os_responsibility_gap": resp is None,
        "components": dict(idx["counts"]), "basis": dict(sorted(idx["basis"].items())),
        "rows": {l: len(v) for l, v in by.items()},
        "open_rows": {l: sum(1 for r in v if r["tier"] in OPEN_TIERS) for l, v in by.items()},
        "p1_rows": {l: sum(1 for r in v if r["tier"] == "p1") for l, v in by.items()},
        "todo_rows": sum(1 for r in rows if r.get("layer_todo", True)),
        "unknown": {"components": idx["counts"]["unknown"], "by_purl_type": dict(sorted(idx["unknown_types"].items())),
                    "rows": len(by["unknown"]), "handling": "treated as our to-do (not defaulted to OS)"},
        "notify_customer": [{"id": r["id"], "component": r["component"], "version": r["version"], "tier": r["tier"],
                             "evidence": (["KEV (" + ", ".join(r.get("kev_sources") or ["DT"]) + ")"] if r.get("kev") else [])
                             + list(r.get("exploited_sources") or [])} for r in notify],
        "host_tool": {"components": sorted(idx["host"], key=lambda x: (x["name"], x["version"])), "count": len(idx["host"]),
                      "findings_not_listed": host_info["findings"], "grype_matches_not_listed": host_info["matches"],
                      "ids": sorted(host_info["ids"])},
    }


def layer_section(num, summ, rows, notify, table):
    """風險評估的分層一節（前面帶空行）。summ 是 layers_summary 的結果。"""
    resp = summ["os_responsibility"]
    n = summ["components"]
    head = ["Layer", "Components", "Rows", "P1", "Open rows (P1–P3)", "In our to-do"]
    body = []
    for l in ("bsp", "os", "unknown"):
        vs = [r for r in rows if r.get("layer") == l]
        body.append([LAYER_ZH[l], n.get(l, 0), len(vs), summ["p1_rows"][l], summ["open_rows"][l],
                     sum(1 for r in vs if r.get("layer_todo", True) and r["tier"] in OPEN_TIERS)])
    txt = [f"\n### {num} Layers (BSP / OS / host tools)\n",
           "Every component of the SBOM carries a layer (SBOM property `dumpling:layer`, set by `pipeline/sbom-layers.py`): `bsp` (BSP: kernel, "
           "out-of-tree modules, boot software, firmware, vendor user-space packages, our own software), `os` (the operating system "
           "packages), `host-tool` (tools that run on the development host, not on the product) or `unknown` (the layer could not be "
           "determined). Rows are assigned to the layer of their component. "
           f"Components: BSP {n.get('bsp', 0)}, OS {n.get('os', 0)}, unknown {n.get('unknown', 0)}, host tools {n.get('host-tool', 0)}.\n",
           RESP_TEXT[resp] + "\n", table(head, body)]
    if summ["unknown"]["components"]:
        bt = ", ".join(f"{k} {v}" for k, v in summ["unknown"]["by_purl_type"].items())
        txt.append(f"\n{plural(summ['unknown']['components'], 'component')} ({bt}) could not be assigned to a layer (no package identity from a "
                   f"distribution and no path); {plural(summ['unknown']['rows'], 'row')} {verb(summ['unknown']['rows'], 'is', 'are')} listed. "
                   "They are not defaulted to OS: they are treated as our to-do.")
    if resp in ("customer", "upstream-vendor"):
        txt.append(f"\n**Customer notification** (exploited rows in the OS layer): {plural(len(notify), 'row')}.\n")
        txt.append(table(["CVE", "Component", "Version", "Tier", "Exploitation evidence"],
                         [[x["id"], x["component"], x["version"], x["tier"].upper(), "; ".join(x["evidence"]) or "—"] for x in summ["notify_customer"]]))
    h = summ["host_tool"]
    txt.append(f"\n**Host tools (not running on the product)**: {plural(h['count'], 'component')}; "
               f"{plural(h['findings_not_listed'], 'Dependency-Track finding')} and {plural(h['grype_matches_not_listed'], 'Grype match', 'Grype matches')} "
               "on them are not in the product vulnerability list. "
               + ("; ".join(f"{x['name']} {x['version']}".strip() for x in h["components"][:20]) + ("; …" if h["count"] > 20 else "") if h["count"] else ""))
    return "\n".join(txt) + "\n"


def generate(project, scan, out, cfg, warnings, company=None, image_check=None, board_test=None, flash_inventory=None, pkgdb=None,
             own_software_file=None, uefi_source=None, tee_source=None, os_responsibility=None):
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    pol = policy_of(cfg)
    paths = {k: find(scan, k) for k in ("dt/findings.json", "sbom/sbom.cdx.json", "scan/grype.json", "meta.json", "status.tsv",
                                        "dt/deb-sources.json", "scan/sbomgate.json", "scan/l4t-kernel-map.json",
                                        "scan/nvidia-bulletins.json", "scan/distro-recheck.json", "scan/kernel-config.json",
                                        "dt/analysis.json", "scan/usn-cves.json", "scan/ubuntu-priority.json",
                                        "scan/ubuntu-status.json", "scan/kernel-module-map.json", "scan/kernel-boot.json")}
    findings, bom, grype, meta = (load_json(paths[k]) for k in ("dt/findings.json", "sbom/sbom.cdx.json", "scan/grype.json", "meta.json"))
    findings = merge_readback(findings, load_json(paths["dt/analysis.json"]))
    # 分層（SBOM 的元件帶 dumpling:layer 時才動作；沒有時 layers_on 是 False，下面所有分層的程式都不改任何輸出）
    lidx = build_layer_index(bom)
    layers_on = lidx is not None
    resp = (os_responsibility or lidx["resp"]) if layers_on else None
    host_info = {"findings": 0, "matches": 0, "ids": set()}
    if layers_on and lidx["host"]:
        findings, grype, host_info = drop_host_tool(findings, grype, lidx)       # host-tool 不進產品漏洞清單
    vx = vexmod()
    try:
        anns, ann_info = vx.load_annotations(project)
    except (vx.VexInputError, OSError) as e:
        raise Fail(f"VEX 人工判定檔有錯：{e}")
    if ann_info and ann_info["warnings"]:
        warnings = list(warnings) + ann_info["warnings"]
    try:
        vrules, rules_info = vx.load_rules(project)
    except (vx.VexInputError, OSError) as e:
        raise Fail(f"VEX 批次規則檔有錯：{e}")
    # 證據規則 K2 的輸入：映像裡的模組與載入限制（人或 board_import 寫的檔案；格式錯 → FAIL，和其他 CRA/Config 的檔案一樣）
    try:
        kmods, kmods_info = vx.load_kernel_modules(project)
    except (vx.VexInputError, OSError) as e:
        raise Fail(f"核心模組清單有錯：{e}")
    if kmods_info and not any(r.get("evidence") == "K2" for r in vrules):
        warnings = list(warnings) + [f"{kmods_info['file']} 只給 vex-rules.json 的證據規則 K2 用（現在沒有 K2 規則，沒有用到）"]
    # 分級方式 exploitation（選用）：人工的被利用證據與對外服務清單。檔案有就驗證（格式錯 → FAIL）；current 時不使用，只記警告
    expl = scheme_of(pol) == "exploitation"
    evidence, ev_info = load_exploitation_evidence(project, now[:10])
    services, svc_info = load_exposed_services(project, now[:10])
    if not expl:
        warnings = list(warnings) + [f"{svc_info['file']} 只在 vulnerability_policy.scheme 是 exploitation 時使用（現在是 current，沒有用到）"] \
            if svc_info else warnings
        if ev_info:
            # 人工的被利用證據在 current 也有一個用處：它的 CVE 不套用批次規則（被利用的列要人判斷；兩種分級方式都一樣）
            warnings = list(warnings) + [f"{ev_info['file']} 只在 vulnerability_policy.scheme 是 exploitation 時使用於分級（現在是 current，"
                                         "分級沒有用到）；它的 CVE 照樣不套用 vex-rules.json 的批次規則"]
    else:
        crit = {"kev", "epss_percentile_min", "epss_probability_min", "severities", "cvss_min"}
        utiers = ((cfg.get("vulnerability_policy") or {}).get("tiers") or {})
        warnings = list(warnings) + [f"vulnerability_policy.tiers.{t} 的條件（{', '.join(sorted(crit & set(utiers[t])))}）在 scheme exploitation "
                                     "不使用（只用 label、action）" for t in ("p1", "p2") if isinstance(utiers.get(t), dict) and crit & set(utiers[t])]
    sm = secmod()
    try:
        sdecs, sdec_info = sm.load_decisions(project)
    except (sm.SecInputError, OSError) as e:
        raise Fail(f"安全測試的人工決定檔有錯：{e}")
    status = read_status(paths["status.tsv"])
    hashes = {k: sha256(p) for k, p in paths.items() if p}
    meta = meta if isinstance(meta, dict) else {}
    ctx = dict(report_fields(cfg))
    ctx.update({"report.generated": now, "report.tool": "sca-center tools/cra/cra_report.py",
                "report.config": "CRA/Config/config.json",
                "report.company": (f"Company-wide settings: `{company['file']}` (SHA-256 {company['sha256'][:12]}), merged into the project "
                                   "configuration; manufacturer, vulnerability contact and vulnerability handling rules come from it."
                                   if company else "No company-wide settings file was used.")})
    for k in ("name", "version", "mode", "source", "started", "finished", "dt_version", "grype_db_built"):
        ctx[f"artifact.{k}"] = meta.get(k) or NR
    ctx["artifact.tools"] = ", ".join(f"{k} {v}" for k, v in sorted((meta.get("tools") or {}).items())) or NR
    role = cfg.get("role") or "manufacturer"
    ctx.update({"role.name": role, "role.company_label": "Supplier" if role == "supplier" else "Manufacturer",
                "role.company_noun": "supplier" if role == "supplier" else "manufacturer"})
    # role supplier 不產生技術文件（SUPPLIER_SKIP）：風險評估裡原本指向技術文件的兩句改指向供應商資料包
    ctx.update({"role.risk_assessment_use": "a summary is given to the manufacturer that integrates the product (`supplier-package/risk-summary.md`), "
                                            "as input to their own risk assessment and technical documentation (Annex VII point 3)"
                if role == "supplier" else "it becomes part of the technical documentation (Annex VII point 3)",
                "role.part_ii_evidence": "The supplier information package (`supplier-package/`) gives the manufacturer the SBOM, the VEX "
                                         "statements and the supplier's security contact (`support-and-notification.md`)."
                if role == "supplier" else "The technical documentation, point 2(b), lists the SBOM, the coordinated vulnerability "
                                           "disclosure policy and\nthe reporting contact."})
    active_docs = {k: v for k, v in DOCS.items() if not (role == "supplier" and k in SUPPLIER_SKIP)}

    # SBOM
    comps = list(flatten(bom.get("components"))) if isinstance(bom, dict) else []
    pkgs = [c for c in comps if c.get("type") != "file"]
    bom_reasons = []
    if not isinstance(bom, dict):
        bom_st = "NOT_ASSESSED"
        bom_reasons.append("no readable SBOM (sbom/sbom.cdx.json) in the scan output")
    elif not pkgs:
        bom_st = "NOT_ASSESSED"
        bom_reasons.append("the SBOM has 0 package components (project rule 12: not shown as 'no vulnerabilities')")
    else:
        bom_st = "OK"
    bom_stages = sorted(k for k in (status or {}) if k.startswith("B-sbom") or k in ("C-sbomgate", "C-upload-sbom", "B-toolchain", "B-npm-no-lockfile"))
    if bom_st == "OK":
        if status is None:
            bom_reasons.append("status.tsv missing: SBOM generation and completeness status unknown")
        elif not any(k.startswith("B-sbom") for k in status) or "C-sbomgate" not in status:
            bom_reasons.append("SBOM generation (B-sbom-*) or completeness check (C-sbomgate) not in status.tsv")
        bom_reasons += [f"{k} is {status[k][0]}" for k in bom_stages if status[k][0] != "OK"]
        bom_st = "GAP" if bom_reasons else "OK"
    b = bom if isinstance(bom, dict) else {}
    tools = (b.get("metadata") or {}).get("tools")
    tools = tools.get("components") if isinstance(tools, dict) else tools
    ptypes = Counter(((c.get("purl") or "").partition(":")[2].partition("/")[0] or "(no purl)") for c in pkgs)
    ctx.update({
        "bom.file": "sbom.cdx.json" if b else NR,
        "bom.sha256": hashes["sbom/sbom.cdx.json"] if b else NR,
        "bom.format": f"{b.get('bomFormat') or '?'} {b.get('specVersion') or '?'}" if b else NR,
        "bom.serial": b.get("serialNumber") or NR,
        "bom.timestamp": (b.get("metadata") or {}).get("timestamp") or NR,
        "bom.generators": ", ".join(f"{t.get('name')} {t.get('version') or ''}".strip() for t in tools or [] if isinstance(t, dict)) or NR,
        "bom.components_total": len(comps), "bom.packages": len(pkgs),
        "bom.no_version": sum(1 for c in pkgs if not c.get("version")), "bom.no_purl": sum(1 for c in pkgs if not c.get("purl")),
        "bom.status": bom_st, "bom.status_detail": bom_reasons or ["no issue recorded by sca-scan (this does not prove the SBOM is complete)"],
        "tables.bom_types": table(["Component type", "Count"], sorted(Counter(c.get("type") or "?" for c in comps).items(), key=lambda x: -x[1])),
        "tables.bom_ecosystems": table(["Package URL type", "Count"], sorted(ptypes.items(), key=lambda x: -x[1])),
        "tables.bom_stages": table(["Stage", "Status", "Detail (as recorded by sca-scan)"],
                                   [[k, status[k][0], en(status[k][1])] for k in bom_stages]) if status else "_status.tsv not available._",
    })

    # pkgdb（pkg_why.py extract 的資料夾）：--pkgdb，或掃描資料夾旁邊的 <scan>/../pkgdb（有 dpkg-status 時）。
    # 待確認事項表與「沒有漏洞資料的套件」都用（讀一次）；載入失敗當作沒有 pkgdb（待確認事項表照舊在自己的 try 裡處理）
    if pkgdb is None and (scan.parent / "pkgdb" / "dpkg-status").is_file():
        pkgdb = scan.parent / "pkgdb"
    try:
        pdb = confmod().load_pkgdb(pkgdb)
    except Exception as e:      # noqa: BLE001 — 和待確認事項表一樣，不能擋住其他文件
        pdb = (None, f"載入失敗（{type(e).__name__}）")

    # 風險評估
    gate_doc = load_json(paths["scan/sbomgate.json"])
    grype, self_dropped = drop_self_matches(grype, gate_doc)
    gidx, gcves = grype_index(grype)
    gkev_map, gepss = grype_kev_map(grype), grype_epss(grype)
    gkev = set(gkev_map)
    gkev_more = {c: {"Grype"} for c in gkev} | {i: {"Grype"} for ids in gkev_map.values() for i in ids}
    have_grype = isinstance(grype, dict)
    gk = [] if have_grype else None     # 只有 Grype 有、在 KEV 目錄、不在風險表的 CVE（交叉核對時算；沒有 Grype 結果 → None，不是「沒有」）
    srcmap = deb_source_map(load_json(paths["dt/deb-sources.json"]))
    kmap_doc = load_json(paths["scan/l4t-kernel-map.json"])
    kmap, kinfo = kernel_map_index(kmap_doc), kernel_map_info(kmap_doc)
    # NVIDIA 安全公告的發現（只有對照表已審核的列；source NVIDIA）和 DT 的發現一起進清單；DT 沒有結果時清單仍是 NOT_ASSESSED
    nvb = load_json(paths["scan/nvidia-bulletins.json"])
    nvf = [f for f in (nvb.get("findings") or []) if isinstance(f, dict)] if isinstance(nvb, dict) else []
    # 公告的 CVE 已遭利用（scan/euvd.json 或人工證據）：成為真正的列（不只是 VEX 另加的列），見 nvidia_exploited_findings
    nvf = nvf + nvidia_exploited_findings(nvb, (findings if isinstance(findings, list) else []) + nvf, load_json(find(scan, "scan/euvd.json")),
                                          evidence, expl)
    # 沒有 CVE 別名的 USN 併進同一個元件版本上它列出的 CVE 的列（scan/usn-cves.json，status OK 時；沒有時照舊各自成列）
    usn_doc = load_json(paths["scan/usn-cves.json"])
    usn = usn_map(usn_doc)
    # 分級的嚴重度依政策的來源順序（NVIDIA 公告 → Ubuntu priority → DT／NVD）：Ubuntu priority 取自 scan/ubuntu-priority.json（status OK 時），
    # 沒有再用 Grype 的 Ubuntu 比對；對照表未審核的 NVIDIA 評級只顯示
    upri_doc = load_json(paths["scan/ubuntu-priority.json"])
    upri, gpri = ubuntu_priority_map(upri_doc), grype_ubuntu_severity(grype)
    # NVIDIA 出的 deb（L4T 的 nvidia-l4t-* 等，purl 也是 pkg:deb/ubuntu/）不用 Ubuntu priority
    sevin = {"upri": upri, "gpri": gpri, "nvun": nvidia_unreviewed(nvb), "nvdebs": nvidia_debs(comps)}
    rows = (build_rows(findings + nvf, pol, gidx, have_grype, srcmap, kmap, usn, gkev_more, sevin, gepss)
            if isinstance(findings, list) else [])
    # Grype 有、DT 沒有的比對（交叉核對的同一個判斷）也成為列，標 found_by "grype only"；之後的處理（Ubuntu 打包的 Python、核心、
    # 發行版覆核、EUVD、對外服務、VEX 與批次規則）和其他列相同。沒有 DT findings 時照舊沒有列（文件是 NOT_ASSESSED）
    # 同一個元件的判斷要知道 Ubuntu 打包的 Python 模組的擁有者（deb_python_index；下面 apply_deb_python 也用同一份）
    pyres = pyver_mod().by_path(pyver_mod().load(Path(pkgdb) / "python-versions.json")) if pkgdb is not None else {}
    dpy, dpy_notes = deb_python_index(pkgs, pyres)
    # 版本未知的元件（sbomgate 排除的比對；專案規則 13）不成列，標 GAP
    gvu = grype_version_unknown(gate_doc)
    if not isinstance(gate_doc, dict) and have_grype and isinstance(findings, list):
        # 沒有（或讀不到）scan/sbomgate.json：直接以 SBOM 分類（同一份規則），鍵是 ("*", purl)：這個元件上的每一筆比對
        gvu = {("*", p): why for p, why in sbom_version_unknown(pkgs).items()}
    g_rows, g_unlisted, g_unknown = (grype_only_rows(grype, rows, pol, gidx, have_grype, srcmap, kmap, gkev_more, sevin, gepss, dpy, gvu,
                                                     services if expl else [], dt_same_cve(findings + nvf))
                                     if have_grype and isinstance(findings, list) else ([], [], []))
    if g_rows:
        rows = sorted(rows + g_rows, key=row_order)
    # 廠商核心：Grype、DT 都沒有核心的列、有 CVE 清單（kernel_cna_version.py）與用了它的 kernel-config.json → 核心的列（kernel_cna_rows）
    kcna_rows, kcna_info = kernel_cna_rows(load_json(find(scan, "scan/kernel-cve-list.json")), load_json(paths["scan/kernel-config.json"]),
                                           rows, kinfo, pol, gidx, have_grype, srcmap, kmap, sevin, gkev_more)
    if kcna_rows:
        rows = sorted(rows + kcna_rows, key=row_order)
    # UEFI 內建函式庫（--uefi-source 或 <scan>/../uefi-source/）：另一份 SBOM（uefi_source.py）、另一次 Grype（離線，uefi_bundled.py grype）。
    # DT 沒有這些元件，所以比對結果只來自 Grype，成為「只有 Grype」的列（元件欄 "OpenSSL 3.4.1 (bundled in UEFI)"，修補建議是重建 UEFI）。
    # 沒有給資料夾（也沒有 <scan>/../uefi-source/）→ uefi_info 是 None，下面全部照舊
    uefi_dir = Path(uefi_source) if uefi_source else (scan.parent / "uefi-source" if (scan.parent / "uefi-source").is_dir() else None)
    uefi_info, uefi_rows = (uefimod().load(uefi_dir) if uefi_dir else None), []
    # 開機韌體涵蓋說明（scan-flash-package.sh 寫的 <rootfs>/bootloader-coverage.json）與 UEFI 映像-原始碼一致性檢查（<結果>/uefi-binary-check.json）；
    # 都沒有（舊的結果、不是 Jetson 刷機包）→ None，下面全部照舊
    boot_cov = load_json(scan.parent / "bootloader-coverage.json")
    boot_cov = boot_cov if isinstance(boot_cov, dict) and boot_cov.get("schema") == bootmod().SCHEMA else None
    boot_chk = load_json(scan.parent.parent / "uefi-binary-check.json")
    if uefi_info is not None and isinstance(boot_chk, dict) and boot_chk.get("schema") == bootmod().CHECK_SCHEMA:
        uefi_info["build_check"] = bootmod().check_line(boot_chk)
        uefimod().image_check(uefi_info, boot_chk)       # 出貨映像解開後的函式庫指紋（沒有 libraries 欄 → 不動）
    if uefi_info and uefi_info["grype"] is not None:
        if isinstance(findings, list):
            ug = uefi_info["grype"]
            uidx = {**gidx, **grype_index(ug)[0]}
            uefi_rows, _, _ = grype_only_rows(ug, rows, pol, uidx, True, srcmap, kmap, {c: {"Grype"} for c in grype_kev_map(ug)}, sevin,
                                              grype_epss(ug), dpy, {}, [], dt_same_cve(findings + nvf))
            rows = sorted(rows + uefimod().relabel_rows(uefi_rows, uefi_info), key=row_order)
        else:
            uefi_info["gaps"].append("no Dependency-Track findings (dt/findings.json): the Grype matches on the UEFI libraries were not listed as rows")
            uefi_info["status"] = "GAP"
    # tos-optee 映像的 OP-TEE、TF-A 與 OP-TEE 內建的 Mbed TLS（--tee-source 或 <scan>/../tee-source/）：做法同上面的 UEFI 內建函式庫（tee_source.py、tee_bundled.py grype）。
    # 沒有給資料夾（也沒有 <scan>/../tee-source/）→ tee_info 是 None，下面全部照舊
    tee_dir = Path(tee_source) if tee_source else (scan.parent / "tee-source" if (scan.parent / "tee-source").is_dir() else None)
    tee_info, tee_rows = (teemod().load(tee_dir) if tee_dir else None), []
    if tee_info is not None:
        tee_info["auto_detected"] = not tee_source      # 沒給 --tee-source、由 <scan>/../tee-source 自動帶入
    if tee_info and tee_info["grype"] is not None:
        if isinstance(findings, list):
            tg = tee_info["grype"]
            tidx = {**gidx, **grype_index(tg)[0]}
            tee_rows, _, _ = grype_only_rows(tg, rows, pol, tidx, True, srcmap, kmap, {c: {"Grype"} for c in grype_kev_map(tg)}, sevin,
                                             grype_epss(tg), dpy, {}, [], dt_same_cve(findings + nvf))
            rows = sorted(rows + teemod().relabel_rows(tee_rows, tee_info), key=row_order)
        else:
            tee_info["gaps"].append("no Dependency-Track findings (dt/findings.json): the Grype matches on the OP-TEE/TF-A/Mbed TLS components were not listed as rows")
            tee_info["status"] = "GAP"
    # Debian／Ubuntu 打包的 Python 模組（/usr/lib/python3/dist-packages）：指向擁有它的 deb 套件，不給 pip 的修補建議
    dprows = apply_deb_python(rows, dpy, gidx, have_grype)
    for r in dprows:
        # Ubuntu 套件裝的 Python 模組：嚴重度和擁有它的 Ubuntu 套件一樣依 Ubuntu priority（同一個 CVE 在 deb 列與 Python 列不會一邊 LOW 一邊 CRITICAL）
        if (r["deb_python"] or {}).get("owner"):
            r["severity"], r["severity_source"], r["severity_detail"] = pick_severity(r, pol["severity_sources"], **sevin)
            r["tier"] = tier_of(r, pol)
    # scan/euvd.json（tools/pilot/lib/euvd.py annotate，C-euvd）：兩種分級方式都讀。EUVD 標示已遭利用的 CVE 是另一種被利用證據
    # （不設 kev；row["exploited_sources"]），兩種分級方式都進 P1；批次規則也不套用。沒有檔案時文件與 summary.json 和以前一樣
    euvd_p = find(scan, "scan/euvd.json")
    euvd_doc = load_json(euvd_p)
    # 批次規則的排除：yes 不分大小寫（兩種分級方式都是；分級用的 EUVD 列一定被排除），status 不是 OK 也照樣排除（偏保守：只影響分級的
    # 證據與文字，不放寬規則）
    euvd_rule_cves = euvd_exploited(euvd_doc, loose=True)
    euvd_map, euvd_status = euvd_catalogues(euvd_doc), None
    if isinstance(euvd_doc, dict) and "status" in euvd_doc and euvd_doc.get("status") != "OK":
        # status 不是 OK（GAP：沒有設定鏡像、索引壞掉或過期；這時 C-euvd 不寫 cves）→ 當作沒有資料（使用者決定 EUVD ②），照實寫出 status
        euvd_map, euvd_status = None, str(euvd_doc.get("status"))
        warnings = list(warnings) + [f"scan/euvd.json 的 status 是 {euvd_status}（不是 OK）：EUVD 的被利用標示沒有用到"]
    elif euvd_map is not None and "status" not in euvd_doc:
        # 沒有 status：新舊不明（新舊由 C-euvd 階段依鏡像的時間寫進 status）→ 當作沒有資料
        euvd_map, euvd_status = None, "missing (freshness unknown)"
        warnings = list(warnings) + [f"scan/euvd.json 的 status 是 {euvd_status}（不是 OK）：EUVD 的被利用標示沒有用到"]
    elif euvd_p and euvd_map is None:
        warnings = list(warnings) + [f"scan/euvd.json 讀不到或格式不對（要有 cves 物件）：EUVD 的被利用標示沒有用到（{euvd_p.name}）"]
    euvd_cves = sorted(euvd_map) if euvd_map is not None else None
    # 沒有檔案、但 status.tsv 有 C-euvd 這一行（FAIL、逾時會刪檔，NOT_RUN 不寫檔）：sca-scan 跑過 EUVD 但沒有可用的結果 → 兩種分級方式都 GAP。
    # 沒有這一行的舊掃描輸出照舊（current 不看 EUVD，輸出不變）
    # 有沒有這一行看 status.tsv 本身（不看值）：狀態欄空的、只有階段名也算跑過，值空的寫成 (no status)，不認得的值照寫，都不是 OK
    euvd_stage = None if euvd_p else stage_line(paths["status.tsv"], "C-euvd")
    euvd_used = bool(euvd_p) or euvd_stage is not None
    euvd_reason = euvd_unavailable_reason(euvd_status, euvd_p, euvd_stage) if euvd_used and euvd_map is None else None
    euvd_na = f"not available: {euvd_reason}" if euvd_reason else None
    # 人工證據只在 exploitation 用（current 照樣驗證格式、記警告）；EUVD 兩種都用
    ev_used = apply_exploitation(rows, pol, euvd_map, evidence if expl else [])
    if any(euvd_hit(r) for r in rows):
        # 風險表的排序：被利用的列（KEV 或 EUVD）同一級（同 vex_export.priority_key）；人工證據不算。沒有 EUVD 的列時不重排（順序不變）
        rows.sort(key=lambda r: row_order(r, euvd=True))
    for r in rows:
        r["kernel"] = is_kernel_row(r, kinfo)
    if layers_on:
        for r in rows:
            r["layer"], r["layer_basis"] = layer_of_row(r, lidx)
            if r["layer"] == "host-tool":      # 不會發生（比對結果階段已移出）；萬一有，不讓它從待辦消失
                r["layer"], r["layer_basis"] = "unknown", "host-tool-not-filtered"
            r["layer_todo"] = layer_todo(r["layer"], resp)
    # Grype 沒有修補狀態的 Ubuntu 列（含 Ubuntu 打包的 Python 模組，看擁有它的 deb）：依 Ubuntu CVE Tracker 推出修補狀態
    # （scan/ubuntu-status.json，status OK 時；apply_ubuntu_tracker）。Grype 有的照用 Grype 的，不同的在交叉核對並列
    ustatus_doc = load_json(paths["scan/ubuntu-status.json"])
    utfix = apply_ubuntu_tracker(rows, ustatus_doc)
    # 自成一列的 USN（沒有 CVE）：修補狀態取自 USN 的修補版本（scan/usn-cves.json 的 fixed；apply_usn_fix）
    usnfix = apply_usn_fix(rows, usn_doc, pkgs, ustatus_doc)
    ra_text = template_text(project, "risk-assessment")[0]
    ra_ph = {m.group(1) for m in PH_RE.finditer(ra_text)}
    # 發行版已修補（scan/distro-recheck.json）：distro_fixed 的列移出 P1–P3（tier distro_fixed，不在 TIERS 裡，所以 by／mby 都不含）。
    # 專案範本沒有 text.distro_section 時不移（列不能從文件消失），並記警告
    drc = load_json(paths["scan/distro-recheck.json"])
    if "text.distro_section" in ra_ph:
        dmoved, dkept = apply_distro(rows, drc)
    else:
        dmoved, dkept = [], Counter()
        if distro_index(drc):
            warnings = list(warnings) + ["專案的風險評估範本（CRA/templates/risk-assessment.md）沒有引用 text.distro_section：發行版已修補"
                                         "（backport）的列照舊留在 P1–P3；要分開列請在 {{ text.nvidia_section }} 後面加上 {{ text.distro_section }}"]
    # VEX：每一列的判定（DT 的人工分析 ＞ vex-annotations.json ＞ 發行版已修補 ＞ 核心設定 ＞ NVIDIA 推定），表格的 VEX status 欄用
    kcfg = load_json(paths["scan/kernel-config.json"])
    # 刷機包有兩顆不同的核心（scan/kernel-boot.json，C-kernel-boot）：資訊性 ATTENTION／GAP 進設定警告（報告包的警告區也會顯示）
    kboot = load_json(paths["scan/kernel-boot.json"])
    if isinstance(kboot, dict) and kboot.get("schema") == "sca-center-kernel-boot/1" and kboot.get("status") in ("ATTENTION", "GAP"):
        warnings = list(warnings) + [f"C-kernel-boot {kboot['status']}：{str(kboot.get('detail'))[:500]}"]
    # 批次規則（CRA/Config/vex-rules.json）最後才套用；範本的 {kernel_fix_all} 是每個核心元件全部修好所需的最低版本（8.7 節同一個值）。
    # scan/euvd.json（有的話）標示已遭利用的 CVE 和 KEV 一樣不套用規則
    rctx = {"kernel_fix_all": {g["component"]: g["fix_all_version"] for g in kernel_fix_all([r for r in rows if r["kernel"]])
                               if g["fix_all_version"]}}
    # 沒有批次規則時也傳：NVIDIA 公告另加的列（vex_export.nvidia_extra）要看 CVE 是否已遭利用，才能進 P1
    if euvd_rule_cves is not None:
        # exploitation：不分大小寫的清單，status 不是 OK 也照樣排除（上面）；current：和以前一樣
        rctx["exploited"] = euvd_rule_cves
    if evidence:
        # 人工證據的 CVE 和 EUVD（euvd_rule_cves）一樣不套用批次規則（被利用的列要人判斷）；current 與 exploitation 兩種分級方式都一樣。
        # 排除只走 rctx["exploited"] 這一條路（證據規則與一般規則共用 vex_export.on_kev）
        rctx["exploited"] = sorted(set(rctx.get("exploited") or ()) | {e["cve"] for e in evidence})
    # 每個已遭利用的 CVE 的真正證據來源（EUVD 的 KEV 清單、人工證據）：vex_export.nvidia_extra 寫進 exploited_sources 用
    rctx["exploited_sources"] = {c: [euvd_label(v)] for c, v in (euvd_map or {}).items()}
    if expl:
        for e in evidence:
            rctx["exploited_sources"].setdefault(e["cve"], []).append(f"manual: {e['source']}, {e['date']}")
    # 證據規則（K1、K2、U1）的輸入：只有產物。映像雜湊取自 meta.json（registry digest、映像 ID、資料夾或 SBOM 的內容雜湊），
    # 生效日和報告日（UTC）比；Debian 版本比較用 deb_vercmp
    rctx.update(image_ids=sorted({x for x in (vx.norm_image(meta.get(k)) for k in ("digest", "image_id", "content_sha256", "version")) if x}),
                today=now[:10], kernel_modules=kmods, kernel_modules_info=kmods_info,
                module_map=load_json(paths["scan/kernel-module-map.json"]), module_map_sha256=hashes.get("scan/kernel-module-map.json"),
                ubuntu_status=ustatus_doc, vercmp=deb_vercmp)
    # NVIDIA 公告的 CVE 其實是發行版套件的（nvidia_distro.py）：依 Grype DB（唯讀）判斷；沒有資料庫 → 不查，維持原狀並記在 summary
    nvd_info = {"checked": False, "reason": "no NVIDIA bulletin", "remapped": {}}
    if isinstance(nvb, dict) and nvb.get("jetson_linux"):
        nvd_cves = sorted({str(x.get("cve")).upper() for k in ("presumed_included", "needs_vendor_confirmation") for x in nvb.get(k) or []
                           if isinstance(x, dict) and x.get("cve")})
        ndm = nvdistro_mod()
        try:
            found = ndm.find_db(NVD_OPTS.get("grype_db"))
        except ndm.DbError as e:
            found, nvd_err = None, str(e.args[0])
        else:
            nvd_err = None
        if not nvd_cves:
            nvd_info = {"checked": False, "reason": "no bulletin-only CVE", "remapped": {}}
        elif nvd_err or found is None:
            nvd_info = {"checked": False, "reason": (nvd_err or "no Grype DB given (--grype-db or GRYPE_DB_CACHE_DIR)")
                        + ": bulletin CVEs were not compared with the distribution data", "remapped": {}}
        else:
            try:
                max_age = float(os.environ.get("GRYPE_DB_MAX_AGE_DAYS") or ndm.DEFAULT_MAX_AGE_DAYS)
            except ValueError:
                max_age = ndm.DEFAULT_MAX_AGE_DAYS
            # 有問題的執行檔在不在：給了 --rootfs-dir 就看那個資料夾；沒有就用 pkgdb（掃描一定會抽出）的完整 rootfs 項目清單（rootfs-files）；
            # 只有 dpkg 檔案擁有者清單時只能當備註（非套件檔案看不到），結果是不明；清單不存在或被截斷 → 不明（不當成不在）
            no_dir = not NVD_OPTS.get("rootfs")
            nvd_files, why_f = ndm.load_rootfs_files(pkgdb) if no_dir else (None, None)
            nvd_owners, why_o = ndm.load_owners(pkgdb) if no_dir else (None, None)
            rm, ri = ndm.remap(nvd_cves, pkgs, found[0], deb_vercmp, now, NVD_OPTS.get("rootfs"), max_age, found[1], nvd_owners, nvd_files)
            ri["file_list"] = ("rootfs-dir" if not no_dir else "rootfs-files" if nvd_files else
                               "dpkg-file-owners (note only; non-package files are not covered)" if nvd_owners else f"unavailable ({why_f})")
            if ri["checked"]:
                rctx["nvidia_distro"] = rm
            nvd_info = {"checked": ri["checked"], "reason": ri["reason"], "db": ri["db"], "cves": len(nvd_cves), "remapped": rm,
                        "file_list": ri["file_list"]}
    vrows, vconf, vinfo = vx.assess(rows, drc, kcfg, nvb, anns, vrules, rctx)
    # 可能誤報（只標記）：發行版紀錄沒有版本範圍、grype.json 裡同一個 CVE 的上游 CPE 範圍不含安裝的上游版本
    vinfo["upstream_excludes"] = vx.upstream_exclusion_flags(vrows, grype if have_grype else None, vx.ubuntu_status_of(ustatus_doc)[0])
    # 可能誤報的標記是 assess 之後才加的：標記的計數重算（含 NVIDIA 另加的列與拆出來的 CVE）
    vinfo["markers"] = vx.marker_counts(vrows + [x for r in vrows for x in r.get("vex_extra") or []])
    if expl:
        link_inherited_owners(rows)
        # P2＝人判斷為可被利用：VEX exploitable（這一列或併進來的其他 CVE），只算人的判定（DT 分析、具名的 vex-annotations.json）；
        # 批次規則的 exploitable 留在 P3（例如「有修補版本 → update」的規則；2027-12-11 起會擋住每一個可修補的列），VEX 欄寫出規則
        for r in rows:
            if r["tier"] == "p3" and any((v or {}).get("state") == "exploitable" and human_vex(v)
                                         for v in [r.get("vex")] + [x.get("vex") for x in r.get("vex_extra") or []]):
                r["tier"], r["p2_by_vex"] = "p2", True
    # VEX 判定為不受影響的列（人工判定、核心設定、NVIDIA 推定）也移到 accepted：風險評估的層級要和 VEX 一致，
    # 不能 VEX 寫 not_affected、風險評估卻寫「下一版修」。KEV 的列只採用人的判定（DT 分析、vex-annotations.json）
    # 只收 not_affected／false_positive（政策的 accepted.states 可以多寫 IN_TRIAGE 等，但那些不是「不受影響」）；DT 的分析已由 tier_of 依
    # 「每一筆 finding」判斷，這裡不再用（部分 finding 有分析的列不移）；一列併了多個 CVE 時，每個 CVE 的判定都要符合；
    # KEV 的列要有具名負責人的人工判定（代稱不算）
    acc_states = {str(x).lower() for x in pol["accepted"].get("states") or []} & {"not_affected", "false_positive"}
    vex_acc = Counter()

    def vex_ok(v, kev, inherited_ok=False, dt_ok=False, more_states=()):
        # 沿用來的 DT 判定（vex_export.inherit_deb_python）例外：這一列沒有自己的 DT finding 分析，tier_of 不會處理它
        if not v or (v["state"] not in acc_states and v["state"] not in more_states):
            return False
        if v["source"] == "dt" and not v.get("inherited_from"):
            # dt_ok（分級方式 exploitation 的被利用列）：這一列自己的 DT 判定，只在每一筆 finding 都判過時採用（dt_complete）；
            # current 與其他列由 tier_of 處理
            return dt_ok
        # inherited_ok（分級方式 exploitation，EUVD／人工證據、不是 KEV 的列）：沿用擁有它的 deb 列的 DT 人工判定也算人的判定
        # （同一份安裝的程式；vex_export 對這種列照樣發布沿用的陳述，只有 KEV 的列不沿用），但擁有者的判定也要每一筆都能用
        # （inherited_dt_usable：RESOLVED 沒有 details 不算，和 deb 列自己一樣留在 P1；呼叫端算好傳進來）
        return not kev or (v["source"] in vx.HUMAN and not vx.author_missing(v.get("author"))) \
            or (inherited_ok and v["source"] == "dt" and bool(v.get("inherited_from")))
    # 分級方式 exploitation：EUVD、人工證據的被利用列和 KEV 一樣，只採用具名的人工判定（沿用的 DT 判定例外，見上）。被利用的列離開 P1
    # 要**每一個**合併的 CVE（這一列＋vex_extra）都有人的 not_affected／false_positive（或 resolved，使用者決定 B）判定，DT 的判定要
    # 這一列每一筆 finding 都判過（使用者決定 A）
    kev_of = exploited      # current：exploited_sources 只有 EUVD（和 KEV 一樣只採用人的判定）；沒有 EUVD 時就是 r["kev"]
    for r in rows:
        xp = exploited(r) if expl else euvd_hit(r)     # current：EUVD 的列和 exploitation 的被利用列同一套規則（KEV 的列照舊）
        dok, more = (dt_complete(r, pol["accepted"]), ("resolved",)) if xp else (False, ())
        def iok(y):
            return xp and not (r["kev"] or y.get("kev")) and inherited_dt_usable(y, pol["accepted"])
        if r["tier"] in OPEN_TIERS and vex_ok(r.get("vex"), kev_of(r), iok(r), dok, more) \
                and all(vex_ok(x.get("vex"), kev_of(r) or x.get("kev"), iok(x), dok, more)
                        for x in r.get("vex_extra") or []):
            r["tier_before"], r["tier"], r["accepted_by_vex"] = r["tier"], "accepted", True
            vex_acc[r["vex"]["source"]] += 1
    # 證據規則 U2（Ubuntu 打包的 Python 模組，Ubuntu 已在安裝的版本修好，VEX resolved）和 distro_fixed 的列一樣處理（同規則 5c：backport）：
    # 移出 P1–P3，列在「發行版已修補」小節（r["distro"]["via"] == "U2"），算進 counts.distro_fixed。條件：沒有 U2 規則的專案不受影響；
    # 風險評估範本要有 text.distro_section、scan/distro-recheck.json 要是 OK（小節才寫得出來，列不能從文件消失）；KEV／被利用的列、核心的列
    # 不移（U2 本來就不套用）。vex-annotations.json／DT 的 resolved 照舊不移（只有 U2 與 distro 來源）
    if "text.distro_section" in ra_ph and isinstance(drc, dict) and drc.get("status") == "OK":
        u2_moved = {}
        for r in rows:
            v = r.get("vex")
            if r["tier"] in OPEN_TIERS and not r["kernel"] and not exploited(r) and v and v["source"] == "rule" and v.get("evidence") == "U2" \
                    and v["state"] == "resolved" and isinstance(v.get("rule_evidence"), dict) \
                    and all((x.get("vex") or {}).get("state") == "resolved" for x in r.get("vex_extra") or []):
                ev = v["rule_evidence"]
                r["tier_before"], r["tier"] = r["tier"], "distro_fixed"
                r["distro"] = {"via": "U2", "source_package": ev["source_package"], "source_version": ev["source_version"],
                               "release": None, "evidence": [{"fixed_version": c["ubuntu_note"], "record": f"{c['cve']} (Ubuntu CVE Tracker, evidence rule {v['rule']})",
                                                             "modified": (ev.get("tracker") or {}).get("commit_date")} for c in ev["cves"]]}
                dmoved.append(r)
                u2_moved[(r["id"], r.get("component"), r.get("version"))] = r
        for e in vinfo.get("u2_resolved") or []:
            if (e["id"], e["component"], e["version"]) in u2_moved:
                e["tier_before"], e["tier"] = u2_moved[(e["id"], e["component"], e["version"])]["tier_before"], "distro_fixed"
    # 層級與整體狀態用全部的列（by）；主清單（8.4–8.6、附錄 A）只列核心以外的（mby），核心的列在 8.7 節與 kernel-vulnerabilities.md
    krows, mrows = [r for r in rows if r["kernel"]], [r for r in rows if not r["kernel"]]
    by = {t: [r for r in rows if r["tier"] == t] for t in TIERS}
    # 我們的待辦（分層：OS 層在 customer／upstream-vendor 時不算）：依日期的出貨關卡（exploitation）用這一組；沒分層時就是 rows、by 本身
    rows_t = [r for r in rows if r.get("layer_todo", True)] if layers_on else rows
    by_t = {t: [r for r in v if r.get("layer_todo", True)] for t, v in by.items()} if layers_on else by
    # 專案自己的風險評估範本沒有引用 text.kernel_section：核心的列留在主清單（不讓它們從文件消失），並記警告
    split = not krows or "text.kernel_section" in ra_ph
    mby = {t: [r for r in (mrows if split else rows) if r["tier"] == t] for t in TIERS}
    if not split:
        warnings = list(warnings) + [f"專案的風險評估範本（CRA/templates/risk-assessment.md）沒有引用 text.kernel_section：作業系統核心的 "
                                     f"{len(krows)} 列照舊列在主清單（另有 {KERNEL_DOC[1]}）；要分開列請在範本加上 {{{{ text.kernel_section }}}}"]
    reasons, risk_st = [], "OK"
    if not isinstance(findings, list):
        risk_st = "NOT_ASSESSED"
        reasons.append("no readable Dependency-Track findings (dt/findings.json): the vulnerability list could not be produced")
    if bom_st == "NOT_ASSESSED":
        risk_st = "NOT_ASSESSED"
        reasons.append("SBOM missing or empty: nothing was analysed")
    if status is None:
        risk_st = worst([risk_st, "GAP"])
        reasons.append("status.tsv missing: data-source freshness and completeness unknown")
    else:
        for k in RISK_STAGES:
            st = status.get(k, ("NOT_RUN", ""))[0]
            if st != "OK":
                risk_st = worst([risk_st, "GAP"])
                reasons.append(f"{k} is {st}" + ("" if k in status else " (not in status.tsv)"))
        for k in COND_STAGES:
            if k in status and status[k][0] != "OK":
                # ATTENTION（例如 B-npm-no-lockfile 在連網解析時）只提醒；其他非 OK 表示資料不完整
                risk_st = worst([risk_st, "ATTENTION" if status[k][0] == "ATTENTION" else "GAP"])
                reasons.append(f"{k} is {status[k][0]}")
        for k in FRESH_STAGES:
            lv = fresh_stage_level(k, status[k][0], status[k][1]) if k in status else None
            if lv:
                risk_st = worst([risk_st, lv])
                reasons.append(f"{k} is {status[k][0]}: vulnerability data may be out of date")
        if status.get("C-grype", ("NOT_RUN",))[0] != "OK":
            risk_st = worst([risk_st, "ATTENTION"])
            reasons.append(f"C-grype is {status.get('C-grype', ('NOT_RUN',))[0]}: no second matcher for the cross-check, fix versions unknown")
        elif not have_grype:
            risk_st = worst([risk_st, "ATTENTION"])
            reasons.append("no scan/grype.json in the scan output: no second matcher for the cross-check, fix versions unknown")
    if not meta:
        risk_st = worst([risk_st, "GAP"])
        reasons.append("meta.json missing: scanned artifact version unknown")
    if uefi_info and uefi_info["status"] != "OK":
        risk_st = worst([risk_st, uefi_info["status"]])
        reasons += [f"UEFI bundled libraries: {g}" for g in (uefi_info["gaps"] + uefi_info["attention"])[:10]]
    if tee_info and tee_info["status"] != "OK":
        risk_st = worst([risk_st, tee_info["status"]])
        reasons += [f"OP-TEE/TF-A/Mbed TLS (tos-optee): {g}" for g in (tee_info["gaps"] + tee_info["attention"])[:10]]
    # 交叉核對只比 DT 的列（只有 NVIDIA 公告的列 Grype 本來就沒有，不算「只有 DT」；只有 Grype 的列也不算）
    dtr = dt_rows_of(rows)
    dt_cves = set().union(*(set(r["cves"]) for r in dtr)) if dtr else set()
    # 交叉核對用所有編號（CVE、GHSA、OSV…）：Grype 對 composer 等生態系常只給 GHSA，只比 CVE 會把兩邊都有的算成「只有 DT」。
    # 每個元件分開比（grype_coverage，和只有 Grype 的列同一個判斷）：同一個 CVE 在別的元件上不算對上
    gsets = grype_idsets(grype) if have_grype else []
    g_cov, dt_only_rows, _ = grype_coverage(grype, dtr, dpy, binary_exposed(services if expl else [])) if have_grype else ([], [], [])
    g_only_adv = {min(ids) for _, ids in g_cov}
    g_only = gcves - dt_cves
    all_row_cves = set().union(*(set(r["cves"]) for r in rows)) if rows else set()
    gu_text = [f"{d['id']}" + (f" ({'/'.join(d['cves'])})" if d["cves"] and d["cves"] != [d["id"]] else "") for d in g_unlisted]
    gvu_text = [f"{d['id']}" + (f" ({'/'.join(d['cves'])})" if d["cves"] and d["cves"] != [d["id"]] else "")
                + f" on {d['package']}{' ' + d['version'] if d['version'] else ''} ({d['reason']})" for d in g_unknown]
    if have_grype:
        cross = (f"Cross-check: Grype reports {plural(len({min(gs) for gs in gsets}), 'advisory', 'advisories')} "
                 f"({plural(len(gcves), 'unique CVE')}), "
                 f"Dependency-Track {plural(len(dtr), 'vulnerability row')} ({plural(len(dt_cves), 'unique CVE')}). Compared by all advisory IDs "
                 f"(CVE, GHSA, OSV and others) on the same component: {plural(len(g_only_adv), 'Grype advisory', 'Grype advisories')} "
                 f"{verb(len(g_only_adv), 'has', 'have')} no counterpart in Dependency-Track"
                 + (f" ({', '.join(sorted(g_only_adv)[:10])}{', …' if len(g_only_adv) > 10 else ''})" if g_only_adv else "")
                 + f", {plural(len(dt_only_rows), 'Dependency-Track row')} {verb(len(dt_only_rows), 'has', 'have')} no counterpart in Grype"
                 + (f"; {plural(len(g_only), 'CVE')} listed by Grype {verb(len(g_only), 'is', 'are')} not in the Dependency-Track list ({', '.join(sorted(g_only)[:10])}"
                    f"{', …' if len(g_only) > 10 else ''})" if g_only else "") + ". "
                 "Differences need review (matching rules and data sources differ; for Debian/Ubuntu, Dependency-Track matches "
                 "source packages added by sca-scan, Grype matches the installed binary packages).")
        if g_rows:
            cross += (f" The Grype matches without a counterpart in Dependency-Track are not dropped: they are listed as "
                      f"{plural(len(g_rows), 'row')} found only by Grype (Source IDs `GRYPE:…`; severity, CVSS, EPSS, KEV and fix state "
                      "from Grype) and are tiered, assessed and given VEX statements like every other row.")
        if g_unknown:
            cross += (f" {plural(len(g_unknown), 'Grype match', 'Grype matches')} without a counterpart {verb(len(g_unknown), 'is', 'are')} on "
                      "components whose version is unknown (sbomgate: version from a range or no version; project rule 13): not "
                      "matched as vulnerabilities and not listed as rows (GAP): " + "; ".join(gvu_text[:10]) + ("; …" if len(gvu_text) > 10 else "") + ".")
        if g_unlisted:
            cross += (f" {plural(len(g_unlisted), 'Grype match', 'Grype matches')} without a counterpart could not be listed as "
                      f"{verb(len(g_unlisted), 'a row', 'rows')} because Grype gives no package name or purl: "
                      + ", ".join(gu_text[:10]) + (", …" if len(gu_text) > 10 else "") + ". They are NOT assessed.")
        nfx = sum(1 for r in dt_only_rows if r["tier"] == "distro_fixed")
        if nfx:
            cross += (f" {nfx} of the Dependency-Track rows without a counterpart in Grype {verb(nfx, 'is', 'are')} fixed by the distribution "
                      "according to its own records (see the section on rows reported only via NVD).")
        if self_dropped:
            ids = ", ".join(sorted({f"{d['id']}" + (f" ({'/'.join(d['cves'])})" if d['cves'] else "") + f" on {d['package']}" for d in self_dropped}))
            cross += (f" {plural(len(self_dropped), 'Grype advisory', 'Grype advisories')} {verb(len(self_dropped), 'matches', 'match')} the product "
                      f"itself without a version and {verb(len(self_dropped), 'is', 'are')} not counted above: "
                      f"{ids}. Whether the product version is affected was NOT assessed; check it manually.")
            risk_st = worst([risk_st, "ATTENTION"])
            reasons.append(f"{plural(len(self_dropped), 'advisory', 'advisories')} {verb(len(self_dropped), 'matches', 'match')} the product itself "
                           "without a version (not assessed)")
        if (g_only_adv or g_only) and isinstance(findings, list):
            risk_st = worst([risk_st, "ATTENTION"])
            # 只有 Grype 的列已經在表上（照樣 ATTENTION：兩個比對工具的結果不同，要人看）；沒有列的 CVE 另外點名
            g_norow = sorted(g_only - all_row_cves)
            reasons.append(f"Grype reports {plural(len(g_only_adv), 'advisory', 'advisories')} and {plural(len(g_only), 'CVE')} "
                           "not in the Dependency-Track list"
                           + (f"; {plural(len(g_rows), 'row')} found only by Grype {verb(len(g_rows), 'is', 'are')} included in the "
                              "risk tables and marked (Source IDs GRYPE:…)" if g_rows else "")
                           + (f"; {plural(len(g_norow), 'CVE')} of them {verb(len(g_norow), 'is', 'are')} in no row: "
                              f"{', '.join(g_norow[:10])}{', …' if len(g_norow) > 10 else ''}" if g_norow else ""))
            if g_unknown:
                # 專案規則 13：版本未知 → 不做弱點比對，列為 GAP（不可顯示為沒有弱點）
                risk_st = worst([risk_st, "GAP"])
                reasons.append(f"{plural(len(g_unknown), 'Grype match', 'Grype matches')} on components with an unknown version (version from a "
                               f"range or no version; project rule 13) {verb(len(g_unknown), 'was', 'were')} not matched as vulnerabilities "
                               f"(GAP): {'; '.join(gvu_text[:10])}{'; …' if len(gvu_text) > 10 else ''}")
            if g_unlisted:
                reasons.append(f"{plural(len(g_unlisted), 'Grype match', 'Grype matches')} without a counterpart in Dependency-Track "
                               f"could not be listed as {verb(len(g_unlisted), 'a row', 'rows')} (no package name or purl) and "
                               f"{verb(len(g_unlisted), 'is', 'are')} not assessed: {', '.join(gu_text[:10])}{', …' if len(gu_text) > 10 else ''}")
            # 以 GHSA 等編號對到某一列的（那一列已經標 KEV）不算「不在風險表」
            # 只有「那個 GHSA 所在的列沒有 CVE 別名」時，以 GHSA 對到的列才算已在風險表（和 build_rows 的對應一致）。
            # 只有 Grype 的列也是風險表的列：那些 CVE 已經在表上（KEV 欄 YES (Grype)），不再點名
            nocve = {i.upper() for r in dtr if not r["cves"] for i in r["all_ids"]}
            gk = sorted(c for c in g_only & gkev if c not in all_row_cves and not gkev_map[c] & nocve)
            if gk:      # 只有 Grype 有、而且在 KEV 目錄：不在風險表裡，要點名
                reasons.append(f"{plural(len(gk), 'CVE')} reported only by Grype {verb(len(gk), 'is', 'are')} listed in a KEV catalogue "
                               f"and {verb(len(gk), 'is', 'are')} not in the risk table: {', '.join(gk[:10])}{', …' if len(gk) > 10 else ''}")
    else:
        cross = "Cross-check: not possible (no scan/grype.json); Dependency-Track counts could not be compared with a second matcher."
    # EUVD 標示已遭利用、但不在風險表的 CVE（scan/euvd.json 的輸入是 DT findings 與 Grype，所以多半是只有 Grype 報的）：沒有列可以放進 P1，
    # 和只有 Grype 有的 KEV 一樣逐一點名（ATTENTION）
    row_cves = set().union(*(set(r["cves"]) for r in rows)) if rows else set()
    euvd_missing = sorted(set(euvd_map or ()) - row_cves - set(gk or ())) if isinstance(findings, list) else []
    if euvd_missing:
        risk_st = worst([risk_st, "ATTENTION"])
        reasons.append(f"{plural(len(euvd_missing), 'CVE')} marked exploited by EUVD {verb(len(euvd_missing), 'is', 'are')} not in the risk "
                       f"table (reported by another matcher only, or not matched to a component): {', '.join(euvd_missing[:10])}"
                       f"{', …' if len(euvd_missing) > 10 else ''}")
    if usnfix["derived"]:
        cross += (f" Fix state for {plural(usnfix['derived'], 'Ubuntu security notice row')} without a CVE is taken from the fixed version "
                  "in the notice (scan/usn-cves.json).")
    if utfix["derived"] or utfix["disagreements"]:
        # 修補狀態取自 Ubuntu CVE Tracker 的列（Grype 沒有）；Grype 和 Tracker 不同的列並列（照用 Grype 的，不覆蓋）
        ud = utfix["disagreements"]
        cross += (f" Fix state for {plural(utfix['derived'], 'Ubuntu row')} without a Grype fix state is taken from the Ubuntu CVE Tracker "
                  "(scan/ubuntu-status.json; " + ", ".join(f"{k} {n}" for k, n in utfix["by_state"].items()) + ")."
                  if utfix["derived"] else "")
        if ud:
            cross += (f" {plural(len(ud), 'row')}: Grype's fix state differs from the Ubuntu CVE Tracker; Grype's is used, both are shown: "
                      + "; ".join(f"{x['id']} on {x['component']} {x['version']}: Grype {x['grype']['fix_state']}"
                                  + (f" {', '.join(x['grype']['fix_versions'])}" if x["grype"]["fix_versions"] else "")
                                  + f", Tracker {tracker_status_text(x['tracker']['status'], x['tracker']['note'])}"
                                  for x in ud[:10]) + ("; …" if len(ud) > 10 else "") + " (summary.json ubuntu_tracker_fix lists all).")
    # 分層：整體狀態（ATTENTION）只看我們的待辦（bsp、unknown、os 在 ours 或沒給 os_responsibility 時）；OS 層在 customer／
    # upstream-vendor 時不算，但列照樣在表上與「通知客戶」裡（沒有列消失）。沒分層時 p1_todo 就是 by["p1"]，文字不變
    p1_todo = [r for r in by["p1"] if r.get("layer_todo", True)]
    p1_other = len(by["p1"]) - len(p1_todo)
    if p1_todo:
        risk_st = worst([risk_st, "ATTENTION"])
        nk = sum(1 for r in p1_todo if r["kernel"])
        reasons.append(f"{plural(len(p1_todo), 'open finding')} in tier P1 ({pol['tiers']['p1']['label']})"
                       + (f"; {nk} of them for the operating system kernel ({'section 8.7' if split else '`' + KERNEL_DOC[1] + '`'})" if nk else "")
                       + (f"; {plural(p1_other, 'more P1 row')} in the OS layer {verb(p1_other, 'is', 'are')} not counted here "
                          f"(os_responsibility {resp}: for the customer, see the layers section)" if p1_other else ""))
    # 移出 P1–P3 的 KEV 列：已知被利用，只靠發行版紀錄移出，要人工確認，所以整體至少 ATTENTION（不會因為移出而變成 OK）
    dkev = [r for r in dmoved if r["kev"] or euvd_hit(r)]     # EUVD 的被利用標記也算（不設 kev）
    if any(r.get("layer_todo", True) for r in dkev):       # 分層：OS 層不是我們的待辦時不讓整體變 ATTENTION（列在通知客戶）；沒分層時就是 if dkev
        risk_st = worst([risk_st, "ATTENTION"])
        reasons.append(f"{plural(len(dkev), 'row')} listed in a KEV catalogue {verb(len(dkev), 'was', 'were')} moved out of P1–P3 because the "
                       f"distribution's records state the installed package is fixed ({', '.join(sorted(c for r in dkev for c in (r['cves'] or [r['id']])))}); "
                       "this needs manual confirmation")
    incomplete = risk_st in ("NOT_ASSESSED", "GAP")
    completeness = (("**The vulnerability list below is INCOMPLETE or could not be produced.** " if incomplete else
                     "All recorded data-source checks are OK. ")
                    + "A vulnerability that is not listed is not proven absent: the list only contains what the data sources "
                    "and matchers found for the components in the SBOM at the time of the scan.")
    # 8.2 的數量：有核心的列時多兩欄（核心、其他元件），沒有時和以前一樣只有一欄
    ta, tk, tm = tally(rows), tally(krows), tally(mrows)
    if euvd_used:
        # EUVD 的列另一行（不設 kev，KEV 的計數不變；沒有 EUVD 時 8.2 不變）。EUVD 不能用時寫 not available 與原因，不寫 0
        # （專案規則：缺資料不可寫成沒有）；原因只由 euvd_unavailable_reason 產生
        for x, rs in ((ta, rows), (tk, krows), (tm, mrows)):
            x["euvd_open"] = sum(1 for r in rs if euvd_hit(r) and r["tier"] in OPEN_TIERS) if euvd_map is not None else euvd_na
            x["distro_fixed_euvd"] = sum(1 for r in rs if euvd_hit(r) and r["tier"] == "distro_fixed") if euvd_map is not None else euvd_na
    raw = len(findings) if isinstance(findings, list) else NR
    sev_keys = sorted(ta["sev"], key=lambda s: SEV_RANK.get(s, 9))
    metrics = [("Dependency-Track findings (raw)", lambda x: x["findings"]),
               ("Rows after de-duplication (vulnerability × component version)", lambda x: x["rows"]),
               *[(f"{t.upper()} – {pol['tiers'][t]['label']}", lambda x, t=t: x[t]) for t in ("p1", "p2", "p3")],
               (pol["accepted"]["label"], lambda x: x["accepted"]),
               ("Open rows listed in a KEV catalogue", lambda x: x["kev_open"]),
               *([(EUVD_OPEN_LABEL, lambda x: x["euvd_open"])] if euvd_used else []),
               *[(f"Open rows with severity {s}", lambda x, s=s: x["sev"][s]) for s in sev_keys]]
    nsection, nstate, ncounts = nvidia_section(nvb, status)
    dnum = "8.9" if nsection else "8.8"
    if isinstance(drc, dict):     # 只有在有 scan/distro-recheck.json 時才多這兩列（沒有時 8.2 不變）
        metrics[7:7] = [(f"Fixed by the distribution, reported only via NVD/GitHub (section {dnum}; not in P1–P3)", lambda x: x["distro_fixed"]),
                        (f"– of them listed in a KEV catalogue (named in section {dnum})", lambda x: x["distro_fixed_kev"])] \
            + ([(f"– of them marked exploited by EUVD (named in section {dnum})", lambda x: x["distro_fixed_euvd"])] if euvd_used else [])
    if g_rows:     # 只有 Grype 的列（沒有時 8.2 不變）
        metrics[2:2] = [("– of them found only by Grype (no Dependency-Track finding; Source IDs GRYPE:…)", lambda x: x["grype_only"])]
    counts = [[m, raw if i == 0 else f(ta)] + ([f(tk), f(tm)] if krows else []) for i, (m, f) in enumerate(metrics)]
    ksection, kstate, kcounts, ksummary = kernel_section(krows, kinfo, status, pol, meta.get("mode") or NR,
                                                         isinstance(findings, list), have_grype,
                                                         None if not euvd_used else True if euvd_map is not None else euvd_reason)
    # 版面的說明不是狀態的理由：寫在資料狀態說明的後面並標明 Note，不放進 reasons（summary.json 的 detail 也不放）
    notes = []
    if not split:
        notes.append(f"Note (layout, does not affect the status): the project's risk-assessment template has no kernel section, so the "
                     f"{plural(len(krows), 'operating system kernel row')} {verb(len(krows), 'is', 'are')} listed in the main tables "
                     f"(also in `{KERNEL_DOC[1]}`)")
    if nsection and "text.nvidia_section" not in ra_ph:
        warnings = list(warnings) + ["專案的風險評估範本（CRA/templates/risk-assessment.md）沒有引用 text.nvidia_section：NVIDIA 安全公告"
                                     "（Jetson Linux）的比對結果不會出現在文件裡；請在 {{ text.kernel_section }} 後面加上 {{ text.nvidia_section }}"]
        notes.append("Note (layout, does not affect the status): the project's risk-assessment template has no NVIDIA bulletin section "
                     f"(`text.nvidia_section`); `{NV_STAGE}` is {ncounts['status'] if ncounts else (status or {}).get(NV_STAGE, ('?',))[0]} "
                     "and its details are in `scan-status.tsv`")
    kmoved = (f"Rows for the operating system kernel ({tk['rows']}: P1 {tk['p1']}, P2 {tk['p2']}, P3 {tk['p3']}, accepted "
              f"{tk['accepted']}) are not listed in sections 8.4–8.6 or Appendix A; they are summarised in section 8.7 and listed in "
              f"full in `{KERNEL_DOC[1]}`. The counts in section 8.2 and the data status include them." if krows and split else "")
    dsection, dstate = distro_section(drc, dmoved, dkept, dnum, status)
    if status and DISTRO_STAGE in status and status[DISTRO_STAGE][0] != "OK":
        notes.append(f"Note (does not affect the status): `{DISTRO_STAGE}` is {status[DISTRO_STAGE][0]}, so rows reported only via NVD/GitHub "
                     "on Debian/Ubuntu packages were not rechecked against the distribution data; P1–P3 may contain rows that the "
                     f"distribution has already fixed (section {dnum})")
    dmf = Counter(r["tier_before"] for r in dmoved)
    dtext = (("\n\n" if kmoved else "") + f"{plural(len(dmoved), 'row')} on Debian/Ubuntu packages that {verb(len(dmoved), 'was', 'were')} reported only via NVD/GitHub "
             f"{verb(len(dmoved), 'is', 'are')} fixed by the distribution (backported) according to its own records ({', '.join(f'{t.upper()} {dmf[t]}' for t in OPEN_TIERS)}"
             + (f"; {len(dkev)} listed in a KEV catalogue" if dkev else "") + f"). {verb(len(dmoved), 'It is', 'They are')} listed in section {dnum} "
             "instead of sections 8.4–8.6 and are not counted in P1–P3 (this changes the tier counts by design); the total number of rows "
             "in section 8.2 still includes them." if dmoved else "")
    usn_ids = usn_without_cve(findings)
    # 依（USN、元件版本）計數：同一個 USN 可能在一個元件上併進 CVE 的列、在另一個元件上自成一列
    usn_merged = sorted(f"{u} on {r['component']} {r['version']}" for r in rows for u in r.get("usn_merged") or {})
    usn_own = sorted(f"{r['id']} on {r['component']} {r['version']}" for r in rows if r["id"] in usn_ids)
    if usn is not None and usn_ids:
        mir = (usn_doc.get("mirror") or {}) if isinstance(usn_doc, dict) else {}
        utext = (f"{plural(len(usn_merged), 'Ubuntu security notice finding')} (USN) without a CVE alias {verb(len(usn_merged), 'was', 'were')} merged "
                 "into the row of a CVE that the notice lists on the same component version, because every CVE of the notice has a row "
                 "on that component version (CVE list from the Ubuntu OSV mirror, "
                 f"`scan/usn-cves.json`, mirror fetched {mir.get('fetched_utc') or NR}); the notice IDs stay in the Source IDs column."
                 + (f" {plural(len(usn_own), 'notice finding')} {verb(len(usn_own), 'stays', 'stay')} a row of {verb(len(usn_own), 'its', 'their')} own "
                    "(not every listed CVE has a row on that component version, or the notice is not in the mirror)." if usn_own else ""))
    elif usn_ids:
        why = ("no `scan/usn-cves.json` in the scan output" if not paths["scan/usn-cves.json"] else
               f"`scan/usn-cves.json` has status {usn_doc.get('status') if isinstance(usn_doc, dict) else 'unreadable'}")
        utext = (f"The mapping of Ubuntu security notices (USN) to CVEs was not available ({why}): {plural(len(usn_ids), 'notice')} "
                 "without a CVE alias " + verb(len(usn_ids), "is", "are") + " listed as rows of their own and may duplicate a CVE row "
                 "on the same component.")
    else:
        utext = ""
    nown = sum(1 for r in dprows if r["deb_python"]["owner"])
    ptext = (f"{plural(len(dprows), 'row')} {verb(len(dprows), 'is', 'are')} for Python modules installed by Ubuntu packages "
             "(`/usr/lib/python3/dist-packages`), not by pip: the Component column names the owning deb package and its version, the fix "
             "column refers to updating that Ubuntu package (a PyPI fix version does not apply), and bulk VEX rules are not applied to them"
             + (f"; for {len(dprows) - nown} of them the owning package was not identified in the SBOM (their PyPI fix data is kept "
                "with a note to check which package installed them)" if nown < len(dprows) else "")
             + "." if dprows else "")
    # 分級用的嚴重度從哪裡來（政策的來源順序；Ubuntu priority 能不能用）
    sev_n = Counter(r.get("severity_source") or "nvd-cvss" for r in rows)
    order_txt = {"vendor": "the NVIDIA security bulletin (reviewed table rows only)",
                 "distro": "the Ubuntu priority (Ubuntu packages and the Canonical kernel)", "nvd": "the Dependency-Track value (NVD CVSS or other source)"}
    seq = [order_txt[k] for k in pol["severity_sources"]] + ([order_txt["nvd"]] if "nvd" not in pol["severity_sources"] else [])
    ubu_rows = sum(1 for r in rows if (r.get("purl") or "").lower().startswith("pkg:deb/ubuntu/"))
    if upri is not None:
        uwhy = f"from the Ubuntu OSV mirror (`scan/ubuntu-priority.json`, mirror fetched {((upri_doc or {}).get('mirror') or {}).get('fetched_utc') or NR})"
    else:
        gwhy = ("Grype's Ubuntu matches were used instead" if gpri else
                "Grype has no Ubuntu matches either" if have_grype else "there is no Grype result either (`scan/grype.json`)")
        uwhy = ("NOT available from the Ubuntu OSV mirror (" + ("no `scan/ubuntu-priority.json` in the scan output" if not paths["scan/ubuntu-priority.json"]
                else f"`scan/ubuntu-priority.json` has status {upri_doc.get('status') if isinstance(upri_doc, dict) else 'unreadable'}")
                + f"); {gwhy}")
    cfg_txt = ("" if pol["severity_sources_configured"] else
               " The configuration does not set `vulnerability_policy.severity_sources`, so the default order (vendor rating first) is used.")
    if "vendor" in pol["severity_sources"] or "distro" in pol["severity_sources"]:
        stext = ("Severity used for the tiers: the first of " + ", then ".join(seq) + " that has a value; the Severity source column names it, "
                 "and the Dependency-Track value is shown when it differs. The Ubuntu priority is used alone only when every CVE of the row "
                 "has one; otherwise the more severe of it and the next source is used. CVSS thresholds apply only when the Dependency-Track "
                 "value is used. NVIDIA ratings from table rows that are not reviewed are shown but not used. NVIDIA's own Debian packages "
                 "(for example `nvidia-l4t-*`) are not Ubuntu packages and do not use the Ubuntu priority. Rows by severity source: "
                 + ", ".join(f"{SEV_SOURCE_TEXT.get(k, k)} {sev_n[k]}" for k in sorted(sev_n)) + "." + cfg_txt
                 + (f" Ubuntu priority {uwhy}." if ubu_rows and "distro" in pol["severity_sources"] else ""))
    else:
        stext = ("Severity used for the tiers: the most severe value of the findings merged into the row (Dependency-Track and, for "
                 "NVIDIA bulletin findings, the bulletin rating), as before the vendor-first order; the policy sets "
                 "`severity_sources` to [\"nvd\"], so the Ubuntu priority is not used. Rows by severity source: "
                 + ", ".join(f"{SEV_SOURCE_TEXT.get(k, k)} {sev_n[k]}" for k in sorted(sev_n)) + ".")
    if expl:
        stext = stext.replace("Severity used for the tiers:", "Severity shown in the tables (the exploitation scheme uses it neither for "
                              "the tiers nor for the must-assess scope, which uses the CVSS score and attack vector):", 1)
    etext, ecounts = epss_note(rows, pol, have_grype)
    ecounts["dt_invalid"] = dt_epss_invalid(findings)
    if ecounts["dt_invalid"] and etext:
        etext += (f" {plural(ecounts['dt_invalid'], 'EPSS value')} from Dependency-Track {verb(ecounts['dt_invalid'], 'was', 'were')} not used "
                  "(outside 0–1, NaN, infinite or not a number); the row is treated as having no EPSS from that finding.")
    dtext = "\n\n".join(x for x in (dtext, utext, ptext, stext, etext) if x)
    if dtext and kmoved and not dmoved:
        dtext = "\n\n" + dtext
    # 可能沒有漏洞資料的 deb 套件（no_vuln_data.py）：只增加可見度，不改層級、排除與資料狀態（附註寫在資料狀態說明後面，標明不影響狀態）
    try:
        nvd = nvdmod().classify(pkgs, rows, grype if have_grype else None, pdb[0], sevin["nvdebs"],
                                (status or {}).get(NV_STAGE, ("NOT_RUN",))[0] == "OK", isinstance(findings, list) or have_grype,
                                nvdmod().config_domains(cfg))
    except Exception as e:      # noqa: BLE001 — 輸入格式錯不能擋住其他文件：這一項是 GAP（小節與 summary 寫出原因）
        nvd = nvdmod().failed(f"{type(e).__name__}: {e}")
        notes.append("Note (does not affect the status): the check for packages without vulnerability data could not be completed "
                     f"({type(e).__name__}): GAP, such packages are not identified (section 8.1)")
    if nvd["count"]:
        notes.append(f"Note (does not affect the status): {plural(nvd['count'], 'Debian/Ubuntu package')} probably "
                     f"{verb(nvd['count'], 'has', 'have')} no vulnerability data and {verb(nvd['count'], 'is', 'are')} NOT ASSESSED "
                     "(section 8.1, “Packages without vulnerability data”): no rows does not mean no vulnerabilities")
        if "text.no_vuln_data_section" not in ra_ph:
            warnings = list(warnings) + ["專案的風險評估範本（CRA/templates/risk-assessment.md）沒有引用 text.no_vuln_data_section：沒有漏洞資料的套件"
                                         "（未評估）的清單不會出現在文件裡（資料狀態的附註、summary.json 與待確認事項表照樣有）；"
                                         "請在 {{ text.cross_check }} 後面加上 {{ text.no_vuln_data_section }}"]
    vscan = ("Vulnerability rows (vulnerability × component version): not produced (no Dependency-Track findings)."
             if not isinstance(findings, list) else
             f"Vulnerability rows (vulnerability × component version): {ta['rows']} in total; {tk['rows']} for the operating system "
             f"kernel{f' (`{KERNEL_DOC[1]}`)' if krows else ''}, {tm['rows']} for other components.")
    ctx.update({
        "risk.data_status": risk_st, "risk.data_status_detail": (reasons or ["no issue recorded"]) + notes,
        "text.completeness": completeness, "text.cross_check": cross, "text.no_vuln_data_section": nvdmod().section(nvd, table),
        "tables.data_sources": table(["Stage", "Status", "Detail (as recorded by sca-scan)"],
                                     [[k, (status.get(k) or ("NOT_RUN",))[0], en((status.get(k) or ("", "not in status.tsv"))[1])] for k in RISK_STAGES + INFO_STAGES]
                                     + [[k, status[k][0], en(status[k][1])] for k in [x for x in FRESH_STAGES if x != "C-grype-db"] + COND_STAGES + NOTE_STAGES if k in status])
        if status is not None else "_status.tsv not available: data-source status is UNKNOWN._",
        "tables.counts": table(["Metric", "Total", "OS kernel (section 8.7)" if split else f"OS kernel (`{KERNEL_DOC[1]}`)",
                                "Other components"] if krows else ["Metric", "Value"], counts),
        "text.kernel_moved": kmoved, "text.kernel_section": ksection, "text.nvidia_section": nsection,
        # 8.3 節：只有 Grype 跑了而且有只有 Grype 的列時才寫這一段（沒有時文件和以前一樣）
        "text.grype_only_rows": ("\nRows found only by Grype (no Dependency-Track finding with any of their IDs on the same component) are "
                                 "included and marked:\ntheir Source IDs start with `GRYPE:` and the component is marked `(found only by "
                                 "Grype)`; their severity, CVSS, EPSS,\nKEV and fix state come from Grype. They are tiered, assessed and "
                                 "given VEX statements like every other row." if g_rows else ""),
        "text.distro_section": dsection, "text.distro_moved": dtext, "counts.distro_fixed": len(dmoved), "counts.kernel": len(krows), "text.vuln_scan": vscan,
        "tables.policy": table(["Order", "Tier", "Label", "Rule", "Action"],
                               [[1, "ACCEPTED", pol["accepted"]["label"], rule_text("accepted", pol), pol["accepted"].get("action")]]
                               + [[i, t.upper(), pol["tiers"][t]["label"], rule_text(t, pol, euvd_map is not None), pol["tiers"][t].get("action")]
                                  for i, t in enumerate(("p1", "p2", "p3"), 2)]),
        "policy.status": pol["status"], "policy.accepted.label": pol["accepted"]["label"],
        "tables.accepted": accepted_table(mby["accepted"]), "counts.accepted": len(mby["accepted"]),
    })
    # 發行閘門（風險評估的 VEX 小節、技術文件第 6 項、summary.json 的 vex）
    grype_checked = have_grype and (status or {}).get("C-grype", ("NOT_RUN",))[0] == "OK"
    # 讓 risk_st 變 ATTENTION 的理由，逐項決定要不要擋閘門（閘門只看「每個候選弱點有沒有評估」，不看優先順序）：
    #   - COND_STAGES 是 ATTENTION（例如 B-npm-no-lockfile 在連網解析）：清單照樣完整，只是提醒 → 不擋
    #     （其他非 OK 是 GAP，閘門已經因 data_status 擋）
    #   - C-grype 不是 OK／沒有 grype.json：交叉核對沒做 → 擋（grype_checked）
    #   - sbomgate 的 SELF_NO_VERSION：比對到產品本身、沒有版本，沒有評估、不在任何一列 → 擋（not_assessed）
    #   - Grype 有、DT 沒有的公告：成為只有 Grype 的列（grype_only_rows），和其他列一樣要判定；不能成列的比對（沒有套件名稱與 purl）
    #     沒有 VEX 狀態 → 擋（grype_only，逐一點名）
    #   - P1 有未處理的列：優先順序；那些列沒有判定時本來就是 untriaged → 閘門自己會擋，不另外傳
    #   - KEV 列只靠發行版紀錄移出 P1–P3：要人確認 → 擋（gate() 看 KEV 列的判定是不是只有自動來源）
    unassessed = [f"{d['id']}" + (f" ({'/'.join(d['cves'])})" if d.get("cves") else "") + f" on {d['package']} (product itself, no version)"
                  for d in sorted(self_dropped or [], key=lambda d: (d["id"], d["package"]))] if have_grype else []
    # 版本未知的元件上的 Grype 比對（專案規則 13）：沒有比對、沒有列，也沒有評估
    unassessed += [f"{t} – version unknown, project rule 13" for t in gvu_text]
    vgate = vx.gate(vrows, vconf, risk_st, gu_text if have_grype and isinstance(findings, list) else 0, isinstance(findings, list),
                    grype_checked=grype_checked, not_assessed=unassessed,
                    rules_without_author=(rules_info or {}).get("without_author") or (),
                    annotations_without_author=sorted({ann_label(a) for a in anns if vx.author_missing(a.get("author"))}),
                    # 沒有 DT findings 時每一筆都「沒對到」，不另外點名（閘門本來就是 NOT_ASSESSED）
                    annotations_unused=[ann_label(anns[i]) for i in vinfo["annotations_unused"]] if isinstance(findings, list) else [])
    # 安全測試（風險評估第 9 節、技術文件第 6 項、security-findings.md）：掃描資料夾旁邊的 image-check／board-test，或 --image-check／--board-test
    img_p = Path(image_check) if image_check else (scan.parent / "image-check" / "image-check.json")
    brd_p = Path(board_test) if board_test else (scan.parent / "board-test" / "board-test.json")
    img_p = img_p if (image_check or img_p.is_file()) else None
    brd_p = brd_p if (board_test or brd_p.is_file()) else None
    rbase = scan.parent.parent

    def srel(p):
        """文件裡的路徑：相對於結果資料夾（<rootfs>/image-check/…）；不在結果資料夾裡的只寫檔名（不寫本機的絕對路徑）。"""
        try:
            return str(Path(p).resolve().relative_to(rbase.resolve()))
        except ValueError:
            return Path(p).name
    sec = sm.evaluate(img_p, brd_p, sdecs, sdec_info, srel)
    sec_st = sec["status"]
    sec_reasons = [f"security testing: {r}" for r in sec["reasons"]]
    if "text.security_testing" not in ra_ph:
        warnings = list(warnings) + ["專案的風險評估範本（CRA/templates/risk-assessment.md）沒有引用 text.security_testing：安全測試的結果"
                                     "不會出現在文件裡（security-findings.md 照樣產生）；請在第 8 節後面加上 {{ text.security_testing }}"]
    if role == "supplier" and not {"role.risk_assessment_use", "role.part_ii_evidence"} <= ra_ph:
        warnings = list(warnings) + ["role supplier：專案的風險評估範本（CRA/templates/risk-assessment.md）沒有引用 role.risk_assessment_use"
                                     "、role.part_ii_evidence：範本自己寫的「技術文件」說明會原樣留著，但 supplier 不產生技術文件；"
                                     "請改用內建範本的這兩個 placeholder"]
    ctx["tables.annex_i"], annex_missing = annex_i_table(cfg, risk_st, vgate["verdict"], sm.annex_evidence(sec))
    fw_text = ""      # 板子韌體版本 vs 刷機包（runtime_evidence.py；只比版本字串，附加在安全測試小節後面）
    try:
        _rtm = rtmod()
        _bd0 = load_json(brd_p) if brd_p else None
        if _rtm is not None and isinstance(_bd0, dict):
            _l4t = ((pdb[0].pkgs.get("nvidia-l4t-core") or {}).get("Version") if pdb[0] is not None else None)
            fw_text = _rtm.firmware_text(_rtm.firmware_rows(_bd0, boot_chk, _l4t), table)
    except Exception as e:      # noqa: BLE001 — 附加內容，不能擋住其他文件
        warnings = list(warnings) + [f"firmware comparison not added ({type(e).__name__})"]
    ctx.update({"text.security_testing": sm.section(sec, table, role) + ("\n\n" + fw_text if fw_text else ""), "security.status": sec_st,
                "text.security_techdoc": sm.techdoc_text(sec)})
    fwc, fwd, fwt, fw_info = (flash_firmware(scan, cfg, b.get("specVersion"), flash_inventory) if b else
                              (None, None, None, {"absent": "No product SBOM (no scanner SBOM): flash firmware was not added."}))
    # 產品自有軟體（設定 sbom.own_software；own_software.py）：沒有設定時 own_info 是 None，下面全部照舊
    owc, owt, own_info, fwc = own_software(scan, cfg, b.get("specVersion"), fwc, fw_info, own_software_file) if b else (None, None, None, fwc)
    if own_info is None and ownmod().configured(cfg):
        own_info = ownmod().build(None, cfg, None)[2]       # 沒有掃描的 SBOM：自有軟體也沒有加進去
        own_info["gaps"] = ["no product SBOM (no scanner SBOM): the manufacturer's own software was not added"]
    if owc:
        fwc, fwd, fwt = (fwc or []) + owc, dict(fwd or {}, **{r: [] for r in owt}), (fwt or []) + owt
    if own_info is not None and own_info["status"] != "OK":
        bom_reasons = bom_reasons + [f"own software (sbom.own_software): {g}" for g in own_info["gaps"][:20]]
        bom_st = worst([bom_st, "GAP"])
        ctx.update({"bom.status": bom_st, "bom.status_detail": bom_reasons})
    if uefi_info is not None:
        if uefi_info["comps"] and b:
            fwc, fwd, fwt = (fwc or []) + uefi_info["comps"], dict(fwd or {}, **uefi_info["deps"]), (fwt or []) + uefi_info["top"]
        if uefi_info["status"] != "OK":
            bom_reasons = bom_reasons + [f"UEFI bundled libraries: {g}" for g in uefi_info["gaps"][:20]]
            if uefi_info["gaps"]:
                bom_st = worst([bom_st, "GAP"])
                ctx.update({"bom.status": bom_st, "bom.status_detail": bom_reasons})
    if tee_info is not None:
        if tee_info["comps"] and b:
            fwc, fwd, fwt = (fwc or []) + tee_info["comps"], dict(fwd or {}, **tee_info["deps"]), (fwt or []) + tee_info["top"]
        if tee_info["status"] != "OK":
            bom_reasons = bom_reasons + [f"OP-TEE/TF-A/Mbed TLS (tos-optee): {g}" for g in tee_info["gaps"][:20]]
            if tee_info["gaps"]:
                bom_st = worst([bom_st, "GAP"])
                ctx.update({"bom.status": bom_st, "bom.status_detail": bom_reasons})
    if layers_on:
        # 產品 SBOM 裡 cra_report 自己加的元件（刷機包韌體、自有軟體、UEFI／OP-TEE 內建函式庫）都是 BSP 的東西；掃描 SBOM 的元件已帶層
        for c in flatten(fwc or []):
            if not any(isinstance(q, dict) and q.get("name") == LAYER_PROP for q in c.get("properties") or []):
                c.setdefault("properties", []).extend([{"name": LAYER_PROP, "value": "bsp"}, {"name": LAYER_BASIS_PROP, "value": "synthetic"}])
    pbom = product_bom(b, cfg, meta, now, hashes["sbom/sbom.cdx.json"], (fwc, fwd, fwt)) if b else None
    pbom = strip_work_paths(pbom) if pbom else None
    # 支援期檢查（support_check.py；技術文件第 4 節）：產品 SBOM（含刷機包韌體）元件的維護期 vs 產品的 support.end_date；只回報，不改文件狀態
    sup = supmod().run(pbom, cfg, datetime.date.fromisoformat(now[:10]))
    ctx.update({"text.support_check": supmod().section(sup, table), "support_check.status": sup["status"]})
    # role supplier 沒有技術文件：結果只在 summary.json，不提醒範本
    if "technical-documentation" in active_docs and \
            "text.support_check" not in {m.group(1) for m in PH_RE.finditer(template_text(project, "technical-documentation")[0])}:
        warnings = list(warnings) + ["專案的技術文件範本（CRA/templates/technical-documentation.md）沒有引用 text.support_check：支援期檢查"
                                     "不會出現在文件裡（summary.json 照樣有）；請在第 4 節加上 {{ text.support_check }}"]
    tr = fwmod().tr03183(pbom)
    sb_ph = {m.group(1) for m in PH_RE.finditer(template_text(project, "sbom")[0])}
    for k, sec_name in (("text.sbom_firmware", "flash firmware"), ("text.sbom_tr03183", "BSI TR-03183-2 coverage")):
        if k not in sb_ph:
            warnings = list(warnings) + [f"專案的 SBOM 範本（CRA/templates/sbom.md）沒有引用 {k}：{sec_name} 不會出現在 sbom.md"
                                         f"（產品 SBOM 照樣產生）；請參考內建範本加上 {{{{ {k} }}}}"]
    # 範圍說明（建置工具、刷機工具不在產品 SBOM）：sbom.tools_scope_note 沒寫時，刷機包掃描預設寫，其他不寫
    scope_note = bool(fw_info.get("flash_package")) if (cfg.get("sbom") or {}).get("tools_scope_note") is None \
        else bool(cfg["sbom"]["tools_scope_note"])
    scope_txt = spmod().TOOLS_SCOPE_NOTE if scope_note else ""
    ctx.update({"text.sbom_scope": ("\n\n" + scope_txt) if scope_txt else ""})
    ctx.update({"text.sbom_firmware": fwmod().firmware_text(fw_info, table) + ("\n\n### Scope of the SBOM\n\n" + scope_txt if scope_txt else "") + ("\n\n" + ownmod().text(own_info, table) if own_info else "")
                                                                                + ("\n\n" + uefimod().text(uefi_info, table) if uefi_info else "")
                                                                                + ("\n\n" + teemod().text(tee_info, table) if tee_info else "")
                                                                                + ("\n\n### Boot firmware coverage\n\n" + bootmod().customer_text(boot_cov) if boot_cov else ""),
                "text.sbom_tr03183": fwmod().tr_text(tr, table),
                "bom.firmware_status": fw_info.get("status") or "not applicable", "bom.tr03183_status": tr["status"]})
    pbom_text = json.dumps(pbom, ensure_ascii=False, separators=(",", ":")) + "\n" if pbom else None
    # 板子執行中使用的證據（runtime_evidence.py）：只加欄位與 VEX 說明的一句話，不改 tier、不改 VEX 狀態。
    # 沒有板子資料、沒有檔案擁有者清單 → 欄位寫 not measured（不猜）
    rt_extra, rt_ev = None, None
    rtm = rtmod()
    if rtm is not None:
        try:
            _bd = load_json(brd_p) if brd_p else None
            _own, _prob = rtm.load_owners(pkgdb)
            _il = (((pdb[0].pkgs.get("nvidia-l4t-core") or {}).get("Version") or "") if pdb[0] is not None else "")
            _m = re.match(r"^(\d{2,3})\.(\d{1,3}(?:\.\d{1,3})?)", _il)
            rt_ev = rtm.Evidence(rtm.pick_runtime(_bd) if isinstance(_bd, dict) else None, _own, _prob, pdb[0], kcfg,
                                 f"R{_m.group(1)}.{_m.group(2)}" if _m else None)

            def rt_extra(r, cv):
                return rt_ev.fields(r, cv)
            for _r in vrows:
                for _x in [_r] + list(_r.get("vex_extra") or []):
                    if (_x.get("vex") or {}).get("state") in ("exploitable", "in_triage"):
                        _x["runtime_note"] = rt_ev.vex_note(rt_ev.fields(_x))
        except Exception as e:      # noqa: BLE001 — 附加證據，不能擋住其他文件
            warnings = list(warnings) + [f"runtime evidence not added ({type(e).__name__})"]
            rt_extra, rt_ev = None, None
    # VEX 檔案：要有產品 SBOM（affects 指向它的元件）與 DT findings；否則不寫（並刪掉上一次的）
    vex_texts, vex_files, vex_stats = {}, [], None
    pname = f"{cfg['product']['name']} {cfg['product'].get('version') or '(no product version)'}"
    if pbom and (isinstance(findings, list) or kcna_rows):      # 廠商核心的列（kernel_cna_rows）自己也是 VEX 的材料
        try:
            vcdx, vex_stats = vx.cdx_vex(vrows, pbom, meta, cfg["product"], vgate["verdict"])
        except vx.VexInputError as e:
            raise Fail(f"VEX 匯出失敗：{e}")
        vex_texts["vex.cdx.json"] = vx.dumps(vcdx)
        vov = vx.openvex(vcdx, cfg["manufacturer"]["name"], vx.purl_by_bomlink(pbom))
        if vov:
            vex_texts["vex.openvex.json"] = vx.dumps(vov)
    why_not = ("no product SBOM" if not pbom else "no Dependency-Track findings") if not vex_texts else "no statement (OpenVEX needs at least one)"
    vex_out = {}
    for n in ("vex.cdx.json", "vex.openvex.json"):
        t = vex_texts.get(n)
        vex_out[n] = {"file": n, "sha256": hashlib.sha256(t.encode("utf-8")).hexdigest(),
                      "statements": len(json.loads(t).get("vulnerabilities" if n == "vex.cdx.json" else "statements"))} if t else None
        vex_files.append((n, vex_out[n], why_not))
    vnum = f"8.{8 + bool(nsection) + bool(dsection)}"
    vsection = vx.section(vnum, vgate, vinfo, vconf, vex_files, f"{pname}, SBOM serial {pbom['serialNumber']}" if pbom else pname,
                          table, ann_info, rules_info)
    if "text.vex_section" not in ra_ph:
        warnings = list(warnings) + ["專案的風險評估範本（CRA/templates/risk-assessment.md）沒有引用 text.vex_section：VEX 狀態與發行閘門"
                                     "不會出現在文件裡（VEX 檔案照樣產生）；請在 {{ text.distro_section }} 後面加上 {{ text.vex_section }}"]
    # 分級方式 exploitation：「To be assessed before release」小節（接在 VEX 小節後面）與依日期的出貨關卡；current 時是空字串
    esection, esumm, est, ereasons = "", None, "OK", []
    if not expl and euvd_used and euvd_map is None and isinstance(findings, list):
        # current：scan/euvd.json 有檔案但不能用（status 不是 OK、讀不到）→ 風險評估文件 GAP（和 exploitation 一樣只在文件，漏洞資料狀態
        # 與發行閘門不變）；沒有檔案的 current 和以前一樣不看 EUVD。exploitation 的同一個理由由 exploitation_section 加（兩者不會同時出現）
        est, ereasons = "GAP", [euvd_unavailable_reason(euvd_status, euvd_p, euvd_stage)]
    if expl:
        ref = reference_date((cfg.get("product") or {}).get("first_placing_on_market"), now[:10])
        # 對外服務清單比這次掃描舊：可能是舊映像的清單（警告，不改狀態）
        scan_day = str(meta.get("started") or meta.get("finished") or "")[:10]
        cnote = None
        if svc_info and _date_ok(scan_day) and svc_info["collected"] < scan_day:
            cnote = (f"The list was collected on {svc_info['collected']}, before this scan ({scan_day}): it may describe an older image; "
                     "collect it again on the scanned image.")
            warnings = list(warnings) + [f"{SERVICES_REL} 的 collected {svc_info['collected']} 早於這次掃描 {scan_day}：可能是舊映像的清單"]
        kfiles = kernel_fix_files(kcfg)
        knet = (svc_info or {}).get("kernel_network")
        esection, esumm, est, ereasons = exploitation_section(
            f"8.{9 + bool(nsection) + bool(dsection)}", rows_t, by_t, pol, isinstance(findings, list), risk_st, services, svc_info,
            evidence, ev_info, ev_used, euvd_cves, euvd_p, ref[0], ref[1], table, pkgs, vgate["verdict"],
            cvss_index(findings + nvf if isinstance(findings, list) else nvf, grype),
            lambda r: ubuntu_priority_of(r, upri, gpri, sevin["nvdebs"]), euvd_status,
            (lambda r: kernel_network_where(r, knet, kfiles, lambda x: vx.kconfig_component_matches(x, kcfg or {}))) if knet else None,
            cnote, euvd_stage)
        if "text.exploitation_section" not in ra_ph:
            warnings = list(warnings) + ["專案的風險評估範本（CRA/templates/risk-assessment.md）沒有引用 text.exploitation_section：「出貨前要判斷的」"
                                         "清單與依日期的出貨關卡不會出現在文件裡（summary.json 的 exploitation 照樣有）；請在 {{ text.vex_section }} "
                                         "後面加上 {{ text.exploitation_section }}"]
    ctx["text.exploitation_section"] = esection
    # 分層一節（8.x）、通知客戶、host tools；沒有 os_responsibility → 文件 GAP（不預設，全部列入待辦）
    lsumm, lsection = None, ""
    if layers_on:
        for r in vrows:        # vex_export 另加的列（NVIDIA 公告推定）沒經過上面的標層
            if "layer" not in r:
                r["layer"], r["layer_basis"] = layer_of_row(r, lidx)
                r["layer_todo"] = layer_todo(r["layer"], resp)
        notify = notify_rows(rows, resp)
        lsumm = layers_summary(rows, vrows, lidx, resp, host_info, notify)
        lsection = layer_section(f"8.{9 + bool(nsection) + bool(dsection) + bool(expl)}", lsumm, rows, notify, table)
        if "text.layer_section" not in ra_ph:
            warnings = list(warnings) + ["專案的風險評估範本（CRA/templates/risk-assessment.md）沒有引用 text.layer_section：分層（BSP／OS／host tools）、"
                                         "通知客戶的列不會出現在文件裡（summary.json 的 layers 與 vulnerability-rows.json 照樣有）；請在 "
                                         "{{ text.exploitation_section }} 後面加上 {{ text.layer_section }}"]
        if resp is None:
            est = worst([est, "GAP"])
            ereasons = ereasons + ["layers: os_responsibility was not given (GAP); not defaulted, all layers are treated as our to-do"]
    ctx["text.layer_section"] = lsection
    # 逐列的機器可讀資料（內部用）：和上面的分級用同一批列與同一組 CVSS／Ubuntu priority／對外服務判斷
    _kn = (svc_info or {}).get("kernel_network")
    _kf = kernel_fix_files(kcfg) if _kn else {}
    rows_json = json.dumps({
        "schema": ROWS_SCHEMA, "generated": now, "internal": True, "have_findings": isinstance(findings, list),
        "vulnerability_data_status": risk_st, "exposed_services_list": bool(svc_info), "row_count": len(vrows),
        **({"layers": lsumm} if lsumm else {}),
        "rows": vulnerability_rows(vrows, cvss_index(findings + nvf if isinstance(findings, list) else nvf, grype),
                                   lambda r: ubuntu_priority_of(r, upri, gpri, sevin["nvdebs"]), services, svc_info,
                                   (lambda r: kernel_network_where(r, _kn, _kf, lambda x: vx.kconfig_component_matches(x, kcfg or {}))) if _kn else None,
                                   gsets, have_grype, extra=rt_extra)}, ensure_ascii=False, separators=(",", ":")) + "\n"
    vc = vgate["counts"]["total"]
    ctx.update({"text.vex_section": vsection, "vex.gate": vgate["verdict"],
                "text.vex_techdoc": (f"Vulnerability status (VEX) and release gate: `risk-assessment.md`, section {vnum}; release gate "
                                     f"**{vgate['verdict']}** (resolved {vc['resolved']}, not_affected {vc['not_affected']}, exploitable "
                                     f"{vc['exploitable']}, in_triage {vc['in_triage']}, untriaged {vc['untriaged']}). VEX files: "
                                     + ", ".join(f"`{n}` (SHA-256 `{x['sha256']}`)" for n, x, _ in vex_files if x)
                                     + "." if vex_texts else
                                     f"Vulnerability status (VEX) and release gate: release gate **{vgate['verdict']}**; no VEX file was "
                                     f"written ({why_not}).")})
    ctx.update({"bom.product_sha256": hashlib.sha256(pbom_text.encode("utf-8")).hexdigest() if pbom else NR,
                "bom.product_component": f"{pbom['metadata']['component']['name']} {pbom['metadata']['component'].get('version', '(no product version)')}" if pbom else NR,
                "bom.product_serial": pbom["serialNumber"] if pbom else NR})
    # sbom.md 第 3 節的「沒有版本」：數產品 SBOM（含核心模組），版本空白或 UNKNOWN 都算沒有版本；沒有產品 SBOM 時沿用掃描器 SBOM 的數字
    ppk = [c for c in flatten(pbom.get("components")) if c.get("type") != "file"] if pbom else pkgs
    ctx.update({"bom.no_version": sum(1 for c in ppk if fwmod().version_missing(c)), "bom.no_purl": sum(1 for c in ppk if not c.get("purl")),
                "bom.product_packages": len(ppk),
                "bom.product_components": len(list(flatten(pbom.get("components")))) if pbom else len(comps)})
    for t in ("p1", "p2", "p3"):
        ctx.update({f"policy.{t}.label": pol["tiers"][t]["label"], f"policy.{t}.action": pol["tiers"][t].get("action") or "",
                    f"tables.{t}": vuln_table(mby[t]), f"counts.{t}": len(mby[t])})

    # 套範本（全部成功才寫檔）
    docs, rendered = {}, {}
    # 風險評估的文件狀態＝漏洞資料狀態（第 8 節）與安全測試狀態（第 9 節）較差的那個；risk.data_status 仍只講第 8 節
    # 分級方式 exploitation：沒有對外服務清單（必須判斷的範圍不完整）→ GAP，依日期的出貨關卡擋住 → ATTENTION（current 時 est 是 OK）
    data_st = {"risk-assessment": (worst([risk_st, sec_st, est]), reasons + sec_reasons + ereasons), "sbom": (bom_st, bom_reasons),
               "user-information": ("OK", [])}
    # 缺的欄位不只看實際用的範本：內建範本引用的欄位（專案範本少引用時也算缺）、Annex I 的逐項表、技術文件檢查清單的 config 欄位
    extra_missing = {"risk-assessment": set(annex_missing),
                     "technical-documentation": {src for _, _, src in TECHDOC_ITEMS if not src.startswith("doc:") and isinstance(ctx.get(src), Missing)}}
    # security-findings.md 沒有範本；先放進 docs，技術文件的檢查清單（第 6 項）要用它的狀態
    docs[SEC_DOC[0]] = {"file": SEC_DOC[1], "status": sec_st, "detail": sec["reasons"], "template": "none (generated)", "missing_fields": []}
    for name, fn in active_docs.items():
        text, src, tpath = template_text(project, name)
        if src == "project":
            builtin = (HERE / "templates" / fn).read_text(encoding="utf-8")
            extra_missing.setdefault(name, set()).update(m.group(1) for m in PH_RE.finditer(builtin)
                                                         if isinstance(ctx.get(m.group(1)), Missing))
        if name == "technical-documentation":
            for k, d in docs.items():
                ctx[f"docs.{k.replace('-', '_')}.status"] = d["status"]
            ctx["techdoc.status"] = ctx["tables.techdoc_checklist"] = ""
            _, miss0 = render(text, ctx, tpath)
            ctx["tables.techdoc_checklist"] = techdoc_checklist(ctx, docs)
            data_st[name] = (worst([d["status"] for d in docs.values()]), [f"{k} is {d['status']}" for k, d in docs.items() if d["status"] != "OK"])
            ctx["techdoc.status"] = worst([data_st[name][0]] + (["GAP"] if set(miss0) | extra_missing[name] else []))
        rendered[name], miss = render(text, ctx, tpath)
        miss = sorted(set(miss) | extra_missing.get(name, set()))
        st, why = data_st[name]
        if miss:
            st, why = worst([st, "GAP"]), why + [f"{len(miss)} config fields TO BE COMPLETED"]
        docs[name] = {"file": fn, "status": st, "detail": why, "template": src, "missing_fields": miss}
    out.mkdir(parents=True, exist_ok=True)
    for name, fn in DOCS.items():
        if name in active_docs:
            (out / fn).write_text(rendered[name], encoding="utf-8")
        else:
            (out / fn).unlink(missing_ok=True)     # role supplier：不留上一次製造商角色的文件
    if krows:
        (out / KERNEL_DOC[1]).write_text(kernel_document(krows, ctx, risk_st, ksummary, split), encoding="utf-8")
        docs[KERNEL_DOC[0]] = {"file": KERNEL_DOC[1], "status": risk_st, "detail": reasons, "template": "none (generated)",
                               "missing_fields": [], "counts": {k: v for k, v in kcounts.items() if k != "fix_all"}}
    else:
        (out / KERNEL_DOC[1]).unlink(missing_ok=True)      # 不留上一次的清單冒充這次的結果
    (out / SEC_DOC[1]).write_text(sm.document(sec, f"{cfg['product']['name']} {cfg['product'].get('version') or ''}".strip(), now, table),
                                  encoding="utf-8")
    docs[SEC_DOC[0]] = docs.pop(SEC_DOC[0])          # summary.json 裡排在其他文件後面
    (out / ROWS_FILE).write_text(rows_json, encoding="utf-8")
    docs["vulnerability-rows"] = {"file": ROWS_FILE, "status": "OK", "detail": [], "template": "none (generated; internal, machine-readable)",
                                  "missing_fields": []}
    if pbom_text is None:
        (out / "sbom.cdx.json").unlink(missing_ok=True)   # 不留舊的複本冒充這次的結果
    else:
        (out / "sbom.cdx.json").write_text(pbom_text, encoding="utf-8")
    for n in ("vex.cdx.json", "vex.openvex.json"):
        if n in vex_texts:
            (out / n).write_text(vex_texts[n], encoding="utf-8")
        else:
            (out / n).unlink(missing_ok=True)
    if paths["status.tsv"] is None:
        (out / "scan-status.tsv").unlink(missing_ok=True)
    else:
        with open_bin(paths["status.tsv"]) as fi, open(out / "scan-status.tsv", "wb") as fo:
            shutil.copyfileobj(fi, fo)
    ub_info = copy_upstream_baseline(scan, out)
    summary = {
        "tool": "cra_report", "generated": now, "status": worst(d["status"] for d in docs.values()), "scan_dir": str(scan),
        "documents": docs, "missing_fields": sorted({m for d in docs.values() for m in d["missing_fields"]}),
        "config_warnings": warnings, "company_config": company, "policy": pol,
        **({"layers": lsumm} if lsumm else {}),
        "counts": {"findings_raw": len(findings) if isinstance(findings, list) else None, "rows": len(rows),
                   **{t: len(v) for t, v in by.items()}, "kev_open": sum(1 for r in rows if r["kev"] and r["tier"] in OPEN_TIERS),
                   # EUVD 的列（不設 kev，所以不在 kev_open；有 scan/euvd.json 或 C-euvd 這一行時才有這個鍵）
                   **({"euvd_open": ta["euvd_open"] if euvd_map is not None else None} if euvd_used else {}),
                   # 只有 Grype 有、在 KEV 目錄、不在風險表的 CVE（儀表板與監控讀得到；原因文字也點名）
                   "kev_grype_only_not_in_table": gk,
                   "accepted_by_vex": dict(sorted(vex_acc.items())),
                   "dt_unique_cves": len(dt_cves), "grype_unique_cves": len(gcves) if have_grype else None,
                   "grype_only_cves": len(g_only) if have_grype else None,
                   "grype_advisories": len({min(gs) for gs in gsets}) if have_grype else None,
                   # 只有 Grype 的列數（Grype 有、DT 沒有的比對加成的列）；grype_advisories_without_dt＝交叉核對的「DT 沒有」的公告數；
                   # grype_only_unlisted＝不能成列的比對（沒有套件名稱與 purl，沒有評估）
                   "grype_only_advisories": len(g_rows) if have_grype else None,
                   "grype_advisories_without_dt": len(g_only_adv) if have_grype else None,
                   "grype_only_unlisted": len(g_unlisted) if have_grype else None,
                   # 版本未知的元件上的 Grype 比對（sbomgate 的 VERSION_FROM_RANGE、NO_VERSION…，或 artifact 沒有版本；規則 13，GAP）
                   "grype_version_unknown": len(g_unknown) if have_grype else None,
                   "dt_only_rows": len(dt_only_rows) if have_grype else None,
                   "sbom_components": len(comps), "sbom_packages": len(pkgs),
                   # 廠商核心（Grype、DT 都沒有核心的列）：CVE 清單來自 Linux 核心 CNA 的版本比對（kernel_cna_rows）；沒有時不出現這一欄
                   **({"kernel_cna": kcna_info} if kcna_info else {}),
                   # 核心與其他元件分開的數量（上面的鍵是全部的列，不變）；kernel.section：8.7 節的狀態代號
                   "kernel": dict(kcounts or {"rows": 0, "findings_raw": 0, **dict.fromkeys(TIERS, 0), "kev_open": 0, "dt_unique_cves": 0, "grype_only_rows": 0,
                                              "fix_states": dict.fromkeys(FIX_STATES, 0), "fix_all": []}, section=kstate,
                                  # separate：風險評估 8.7 節；main_tables：專案範本沒有 8.7 節，核心的列留在主清單
                                  risk_assessment_layout="separate" if split else "main_tables"),
                   # NVIDIA 安全公告（Jetson Linux；風險評估 8.8 節）；section：not_applicable／not_assessed／listed
                   "nvidia_bulletins": dict(ncounts or {}, section=nstate),
                   # 發行版已修補（scan/distro-recheck.json）：distro_fixed＝移出 P1–P3 的列數（沒有檔案時 None）；不含在 p1／p2／p3、kev_open 裡
                   "distro_fixed": len(dmoved) if isinstance(drc, dict) else None,
                   # 沒有 CVE 的 USN（scan/usn-cves.json）：mapping＝OK／not_available；without_cve＝這種 USN 的個數；
                   # merged＝併進 CVE 列的、own_row＝仍自成一列的（都是「USN on 元件 版本」，一個 USN 在不同元件上各算一次）
                   # 分級用的嚴重度：policy＝來源順序；by_source＝各來源的列數；ubuntu_priority＝OK／not_available（scan/ubuntu-priority.json）
                   # EPSS：dt＝這一列自己的 DT finding 有 EPSS 的列數（分級用）；other_sources_shown＝並列顯示其他來源的列數；
                   # only_other_sources＝自己沒有、只有其他來源有的列數；by_source；grype_score_dates＝Grype 的分數日期（沒有 Grype 結果 → None）；
                   # rules＝各層的 EPSS 條件（None＝沒用）；dt_invalid＝DT finding 裡不收的 EPSS 值（超出 0–1、NaN、不是數字）的個數
                   "epss": ecounts,
                   "severity_sources": {"policy": pol["severity_sources"], "configured": pol["severity_sources_configured"], "by_source": dict(sorted(sev_n.items())),
                                        "ubuntu_priority": "OK" if upri is not None else "not_available",
                                        "ubuntu_priority_file_status": upri_doc.get("status") if isinstance(upri_doc, dict) else None},
                   "usn_cves": {"mapping": "OK" if usn is not None else "not_available",
                                "file_status": usn_doc.get("status") if isinstance(usn_doc, dict) else None,
                                "without_cve": len(usn_ids), "merged": usn_merged, "own_row": usn_own},
                   # Debian／Ubuntu 打包的 Python 模組的列（不是 pip 管理；批次規則不套用）；mixed_purls：同一個 purl 也有 pip 裝的；
                   # version_mismatch_purls：在 dist-packages、名稱對到 deb 但版本不同（當 pip 套件）
                   "deb_python": {"rows": len(dprows), "with_owner": nown, "without_owner": len(dprows) - nown,
                                  "sbom_components": len(dpy), "mixed_purls": len(dpy_notes["mixed"]),
                                  "version_mismatch_purls": len(dpy_notes["version_mismatch"]),
                                  # 版本是佔位值（0.0.0…）的 Python 模組（py_dpkg_version.py）：各判定的數量；沒有 python-versions.json 時不加
                                  **({"placeholder_versions": {k: sum(1 for c in pyres.values() if c.get("state") == k)
                                                               for k in ("RESOLVED", "DISAGREE", "UNSURE", "NOT_OWNED", "NO_OWNER_DATA")}} if pyres else {})},
                   **({"distro_recheck": {"section": dstate, "status": drc.get("status") if isinstance(drc, dict) else None,
                                      "moved_from": {t: dmf[t] for t in OPEN_TIERS}, "kev": sorted(c for r in dkev for c in (r["cves"] or [r["id"]])),
                                      "not_moved": dict(dkept), "recheck_counts": drc.get("counts")}} if isinstance(drc, dict) else {}),
                   "non_kernel": {"rows": tm["rows"], "findings_raw": tm["findings"], **{t: tm[t] for t in TIERS},
                                  "kev_open": tm["kev_open"], "dt_unique_cves": tm["cves"], "grype_only_rows": tm["grype_only"]}},
        "product_sbom": {"file": "sbom.cdx.json", "sha256": ctx["bom.product_sha256"], "serial": ctx["bom.product_serial"],
                         # 刷機包的韌體（firmware_bom.build 的 info）與 BSI TR-03183-2 覆蓋率（只回報，ATTENTION 不影響文件狀態與發行閘門）
                         "flash_firmware": fw_info, "tr03183": tr, **({"own_software": own_info} if own_info else {}),
                         **({"uefi_source": {k: uefi_info[k] for k in ("status", "dir", "source_status", "gaps", "attention", "libs", "matches", "grype_run")}
                             | ({"image_libs": uefi_info["image_libs"]} if uefi_info.get("image_libs") else {})
                             | {"rows": len(uefi_rows)}} if uefi_info else {}),
                         **({"tee_source": {k: tee_info[k] for k in ("status", "dir", "source_status", "gaps", "attention", "libs", "matches", "grype_run",
                                                                       "image_check", "build_config", "auto_detected")} | {"rows": len(tee_rows)}} if tee_info else {})} if pbom else None,
        # 支援期檢查：status（OK／ATTENTION／NOT_ASSESSED／FAIL）、reasons、entries（元件、維護到何時、結果、來源與查核日期）
        "support_check": sup,
        # VEX 與發行閘門：gate.counts 是每一列（含 NVIDIA 公告另加的列）的 VEX 狀態；files 的 sha256 是寫出的檔案內容
        "vex": {"gate": vgate, "files": vex_out, "not_written_reason": None if vex_out["vex.openvex.json"] else why_not,
                "sources": vinfo["sources"], "conflicts": vconf, "annotations": dict({k: v for k, v in ann_info.items() if k != "warnings"}, used=vinfo["annotations_used"],
                                                                                         unused_indexes=vinfo["annotations_unused"]) if ann_info else None,
                "rules": dict(rules_info, rules=vinfo["rules"]) if rules_info else None,
                "kernel_config": vinfo["kernel_config"], "nvidia_extra_rows": vinfo["nvidia_extra_rows"],
                "suppressed_without_state": vinfo.get("suppressed_without_state", 0), "dt_partial": vinfo.get("dt_partial", 0),
                "deb_python_inherited": vinfo.get("deb_python_inherited", 0),
                "deb_python_inherit_conflict": vinfo.get("deb_python_inherit_conflict", 0),
                "deb_python_kev_not_inherited": vinfo.get("deb_python_kev_not_inherited", 0),
                # 證據規則與標記：markers（K3、K4、U1-not-applied、U1-older-revision、distro_no_range_upstream_excludes 的列數）、evidence_inputs（輸入的狀態與版本）、
                # kernel_modules（CRA/Config/kernel-modules.json）、upstream_excludes（可能誤報的列與證據）、rule_shadowed_rows
                "markers": vinfo.get("markers", {}), "evidence_inputs": vinfo.get("evidence_inputs"),
                "kernel_config_via_rule": vinfo.get("kernel_config_via_rule", False), "rule_shadowed_rows": vinfo.get("rule_shadowed_rows", 0),
                "kernel_modules": kmods_info, "upstream_excludes": vinfo["upstream_excludes"],
                # 被證據規則 U1 設成 not_affected 的每一列與理由、證據（vex_export.u1_exclusions；報告的「被排除清單」用）
                "u1_excluded": vinfo.get("u1_excluded", []),
                # NVIDIA 公告列的 CVE 其實是發行版套件的（nvidia_distro.py）：checked＝有沒有查（沒給 Grype DB 就沒查）、remapped＝每個 CVE 的結果
                "nvidia_distro": nvd_info,
                # 被證據規則 U2 設成 resolved 的每一列（只有設定了 U2 時才有這個鍵；tier 是最後的層級，distro_fixed＝已移到發行版已修補小節）
                **({"u2_resolved": vinfo["u2_resolved"]} if "u2_resolved" in vinfo else {}),
                "section": vnum, **(vex_stats or {})},
        "inputs": {k: {"file": str(p.relative_to(scan)), "sha256": hashes[k]} if p else None for k, p in paths.items()},
        # 安全測試：status、reasons、ran（image／board／network）、inputs、counts（各嚴重度的 total／open／fixed／accepted／false_positive）、
        # open、decisions（used／unused）、findings（id、severity、source、annex、status）、files（技術文件第 6 項的報告檔）
        "security_testing": sm.summary(sec),
    }
    summary["role"] = role
    # 可能沒有漏洞資料的 deb 套件（no_vuln_data.py）：status（NOT_ASSESSED／OK／GAP／NOT_RUN）、count、likely、possible、held、examples、
    # signals（used、not_used）、groups、excluded、maintainer_source、hold_known、deb_packages、detail。不算進 counts 與層級
    summary["packages_without_vuln_data"] = nvdmod().summary(nvd)
    # 依 Ubuntu CVE Tracker 推出修補狀態的列（apply_ubuntu_tracker）：status（OK／not_available）、derived、by_state、already_fixed、
    # disagreements（Grype 與 Tracker 不同的列，照用 Grype 的）。沒有 scan/ubuntu-status.json 時沒有這個鍵（summary 和以前一樣）
    if ustatus_doc is not None:
        summary["ubuntu_tracker_fix"] = utfix
    # Ubuntu 打包的 Python 模組的批次規則（vex_export.deb_python_rules）：沿用 deb 列的規則判定、以擁有者套用、不沿用的原因
    if vrules:
        summary["vex"].update({k: vinfo.get(k, 0) for k in ("deb_python_rule_inherited", "deb_python_rule_direct", "deb_python_rule_inherit_conflict",
                                                           "deb_python_rule_kev_not_inherited", "deb_python_rule_p1_not_inherited",
                                                           "deb_python_rule_evidence_conflict", "deb_python_rule_criteria_not_met")})
    # 修補狀態取自 USN 的列（apply_usn_fix）：scan/usn-cves.json 有 fixed（status OK）時才有這個鍵
    if usnfix["status"] == "OK":
        summary["usn_fix"] = usnfix
    if euvd_used:
        # scan/euvd.json 有檔案、或 status.tsv 有 C-euvd 這一行時（兩種分級方式）：EUVD 的被利用標記用在哪些列、各 KEV 清單的列數（KEV 欄的來源分得出 DT／Grype 與
        # EUVD 的 CISA KEV、ENISA EU KEV）。沒有檔案時沒有這個鍵（summary.json 和以前一樣）
        erows = [r for r in rows if euvd_hit(r)]
        summary["euvd"] = {
            "available": euvd_map is not None, "file": str(euvd_p.relative_to(scan)) if euvd_p else None, "file_status": euvd_status,
            "stage_status": euvd_stage,
            "exploited_cves": len(euvd_map) if euvd_map is not None else None,
            "rows": len(erows), "rows_not_kev": sum(1 for r in erows if not r["kev"]),
            "by_tier": dict(sorted(Counter(r["tier"] for r in erows).items())),
            "by_catalogue": dict(sorted(Counter(EUVD_CATALOGUES.get(k, k) for r in erows
                                                for k in {k for c in r["cves"] for k in (euvd_map or {}).get(c.upper(), ())}).items())),
            "kev_sources_on_euvd_rows": dict(sorted(Counter(x for r in erows for x in r.get("kev_sources") or []).items())),
            "not_in_table": euvd_missing,
            "list": [{"id": r["id"], "component": r["component"], "version": r["version"], "tier": r["tier"], "kev": r["kev"],
                      "kev_sources": r.get("kev_sources") or [], "euvd": [x for x in r["exploited_sources"] if str(x).startswith("EUVD")]}
                     for r in erows]}
    if ub_info:
        summary["upstream_baseline"] = ub_info      # 與 NVIDIA 原版的比對（選用輸入；檔案在輸出資料夾，會進內部存檔）
    if esumm:
        # 分級方式 exploitation：tiers、p1_by_evidence、p2_by、evidence、euvd、exposed_services、must_assess（status、數量、list）、
        # gate（verdict BLOCKED／OK／GAP／NOT_ASSESSED、reference_date、date_source、cutoff、blocks、數量）。current 時沒有這個鍵
        summary["exploitation"] = esumm
    if role == "supplier":
        # 供應商資料包（supplier_package.py）：用上面寫好的 SBOM、VEX 與這次的評估結果
        try:
            spk = spmod().write(out, cfg, summary, sec, vrows, dict({k: meta.get(k) for k in ("finished", "dt_version", "grype_db_built")},
                                                                     data_status=risk_st,
                                                                     **({"boot_firmware_text": bootmod().customer_text(boot_cov)} if boot_cov else {}),
                                                                     **({"tools_scope_note": True} if scope_txt else {})),
                                now, ctx["report.tool"], table, {n: why_not for n in ("vex.cdx.json", "vex.openvex.json") if n not in vex_texts}
                                | ({} if pbom else {"sbom.cdx.json": "no scanner SBOM"}))
        except (OSError, ValueError, TypeError, OverflowError) as e:
            raise Fail(f"供應商資料包寫不出來：{type(e).__name__}: {e}")
        summary["supplier_package"] = spk
        docs["supplier-package"] = {"file": spk["folder"] + "/", "status": {"INCOMPLETE": "GAP"}.get(spk["status"], spk["status"]),
                                    "detail": [f"{len(spk['missing_fields'])} supplier fields TO BE COMPLETED"] if spk["missing_fields"] else [],
                                    "template": "none (generated)", "missing_fields": spk["missing_fields"]}
        summary["status"] = worst(x["status"] for x in docs.values())
        summary["missing_fields"] = sorted({m for x in docs.values() for m in x["missing_fields"]})
    elif any(out.glob("supplier-package")) or any(out.glob(".supplier-package.*")):
        spmod().remove(out)       # 上一次是 supplier：刪掉舊的資料包（沒有時不載入模組）
    # 待確認事項表（confirm_items.py）：工具判斷不了、直接問產品工程師、經專案負責人（PM）問法務／主管的事，從這次已有的資料列出
    # （缺的輸入也列一筆）。pkgdb 在風險評估之前已經讀好（pdb，和「沒有漏洞資料的套件」共用）
    try:
        cm = confmod()
        citems = cm.build(rows=vrows, sec=sec, pkgs=pkgs, krows=krows, kstate=kstate, kcfg=kcfg, kboot=kboot, status=status, expl=expl, svc_info=svc_info,
                          missing_fields=summary["missing_fields"], cfg=cfg, role=role, have_findings=isinstance(findings, list),
                          risk_st=risk_st, risk_reasons=reasons, bom_st=bom_st, bom_reasons=bom_reasons, human=vx.HUMAN,
                          author_missing=vx.author_missing, schema=SCHEMA, db=pdb, no_vuln=nvd)
        summary["confirmation_items"] = dict(status="OK", **cm.write(
            out, citems, f"{cfg['product']['name']} {cfg['product'].get('version') or ''}".strip(),
            f"{meta.get('name') or NR} {meta.get('version') or ''}".strip() + (f"（掃描完成 {meta['finished']}）" if meta.get("finished") else ""),
            role), pkgdb="used" if pdb[0] is not None else "not_available")
    except Exception as e:      # noqa: BLE001 — 待確認事項表不是 CRA 文件：任何錯誤都不能擋住其他文件與 summary.json
        # 不留上一次的表冒充這次的結果；刪不掉時記下原因（summary.json 照樣重寫，不會留著上一次的 status OK）
        rm_err = None
        for n in ("confirmation-items.csv", "confirmation-items.md"):
            try:
                (out / n).unlink(missing_ok=True)
            except OSError as e2:
                rm_err = f"{n} 刪不掉（{type(e2).__name__}: {e2}）"
        summary["confirmation_items"] = {"status": "FAIL", "error": f"{type(e).__name__}: {e}", "total": None,
                                         **({"remove_error": rm_err} if rm_err else {})}
        summary["config_warnings"] = list(summary["config_warnings"]) + [f"待確認事項表寫不出來（{type(e).__name__}: {e}）"
                                                                       + (f"；{rm_err}" if rm_err else "")]
    # 沒有漏洞資料的套件的完整清單（no_vuln_data.write_list；文件與待確認事項表只寫前幾個名稱）
    try:
        summary["packages_without_vuln_data"]["file"] = nvdmod().write_list(out, nvd)
    except Exception as e:      # noqa: BLE001 — 清單寫不出來不能擋住其他文件；不留上一次的檔案
        try:
            (out / nvdmod().LIST_NAME).unlink(missing_ok=True)
        except OSError:
            pass
        summary["packages_without_vuln_data"]["file"] = None
        summary["config_warnings"] = list(summary["config_warnings"]) + [f"沒有漏洞資料的套件清單寫不出來（{type(e).__name__}: {e}）"]
    (out / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return summary


# Annex VII 檢查清單：(項目, 內容, 來源)；來源是 config 的點路徑（缺少就是 TO BE COMPLETED）或產生的文件
TECHDOC_ITEMS = [
    ("1(a)", "Intended purpose", "intended_use.purpose"),
    ("1(b)", "Software versions affecting compliance", "technical_documentation.software_versions"),
    ("1(c)", "Hardware photographs or illustrations", "technical_documentation.hardware_illustrations"),
    ("1(d)", "User information and instructions (Annex II)", "doc:user-information"),
    ("2(a)", "Design, development and system architecture", "technical_documentation.architecture"),
    ("2(b)", "SBOM", "doc:sbom"),
    ("2(b)", "Coordinated vulnerability disclosure policy", "vulnerability_contact.cvd_policy_url"),
    ("2(b)", "Contact address for reporting vulnerabilities", "vulnerability_contact.contact"),
    ("2(b)", "Secure distribution of updates", "technical_documentation.secure_update_distribution"),
    ("2(c)", "Production and monitoring processes and their validation", "technical_documentation.production_monitoring"),
    ("3", "Cybersecurity risk assessment", "doc:risk-assessment"),
    ("4", "Support period: end date", "support.end_date"),
    ("4", "Support period: information taken into account", "technical_documentation.support_period_rationale"),
    ("5", "Standards, common specifications or certification schemes applied", "technical_documentation.standards"),
    ("6", "Test reports: vulnerability scan", "doc:risk-assessment"),
    ("6", "Test reports: security testing (image, board, network)", "doc:security-findings"),
    ("6", "Test reports: other tests", "technical_documentation.test_reports"),
    ("7", "EU declaration of conformity (copy)", "technical_documentation.eu_declaration_of_conformity_copy"),
    ("8", "SBOM for market surveillance authorities", "doc:sbom"),
]


def techdoc_checklist(ctx, docs):
    rows = []
    for item, what, src in TECHDOC_ITEMS:
        if src.startswith("doc:"):
            d = docs[src[4:]]
            rows.append([item, what, f"Generated: `{d['file']}`", d["status"]])
        else:
            rows.append([item, what, f"`{src}`", TBC if isinstance(ctx.get(src), Missing) else "Provided"])
    return table(["Annex VII", "Content", "Source", "Status"], rows)


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        print(f"參數錯誤：{message}", file=sys.stderr)
        sys.exit(64)


def main(argv=None):
    ap = Parser(description="CRA 文件草稿產生器（risk-assessment、SBOM、user information、technical documentation）")
    ap.add_argument("--project", help="產品專案根目錄（含 CRA/Config/config.json）")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--scan", help="sca-scan 的輸出資料夾")
    g.add_argument("--run-scan", metavar="OUT", help="依 config.json 的 scan 段執行 sca-scan，輸出到 OUT")
    g.add_argument("--check-company", metavar="FILE", help="只檢查公司共用設定，不產生文件")
    c = ap.add_mutually_exclusive_group()
    c.add_argument("--company", help="公司共用設定（預設 CRA_COMPANY_CONFIG 或 /etc/sca-gitlab/company.json）")
    c.add_argument("--no-company", action="store_true", help="不用公司共用設定")
    ap.add_argument("--out", help="輸出資料夾（預設 <project>/CRA/Reports）")
    ap.add_argument("--image-check", help="映像靜態檢查的 image-check.json（預設 <scan>/../image-check/image-check.json，存在時）")
    ap.add_argument("--board-test", help="板子檢查的 board-test.json（預設 <scan>/../board-test/board-test.json，存在時）")
    ap.add_argument("--flash-inventory", help="刷機包的 flash-inventory.json（旁邊要有 list.json；預設 <scan>/../../flash-inventory.json，"
                                              "<scan>/../../list.json 存在時）")
    ap.add_argument("--grype-db", help="（選用）Grype DB 的 vulnerability.db 或資料夾（預設環境變數 GRYPE_DB_CACHE_DIR），唯讀：NVIDIA 公告的 CVE "
                    "若其實是發行版套件的，依它判斷；沒有就不查")
    ap.add_argument("--rootfs-dir", help="（選用）解開的 rootfs 資料夾，只用來補充證據（有問題的執行檔在不在）；不讀內容")
    ap.add_argument("--own-software", help="own_software.py 的 own-software.json（設定有 sbom.own_software 時才用；"
                                           "預設 <scan>/../own-software/own-software.json）")
    ap.add_argument("--uefi-source", help="uefi_source.py 的輸出資料夾（uefi-source.cdx.json；旁邊有 uefi_bundled.py grype 的 grype.json、grype-run.json）："
                                          "UEFI 內建的函式庫併進產品 SBOM、Grype 的比對成列（預設 <scan>/../uefi-source，資料夾存在時）")
    ap.add_argument("--tee-source", help="tee_source.py 的輸出資料夾（tee-source.cdx.json；旁邊有 tee_bundled.py grype 的 grype.json、grype-run.json）："
                                         "tos-optee 的 OP-TEE、TF-A 與內建 Mbed TLS 併進產品 SBOM、Grype 的比對成列（預設 <scan>/../tee-source，資料夾存在時）")
    ap.add_argument("--pkgdb", help="pkg_why.py extract 的資料夾（待確認事項表用來找出沒有修補的套件是誰帶進來的；預設 <scan>/../pkgdb，"
                                    "有 dpkg-status 時）")
    ap.add_argument("--os-responsibility", choices=OS_RESPONSIBILITIES,
                    help="（選用）OS 層歸誰：ours（OS 也是我們的待辦）｜customer（客戶負責：OS 層分開列、被利用的列通知客戶，不算我們的待辦）｜"
                         "upstream-vendor（上游 OS 廠商負責，我們只通知客戶）。只在 SBOM 的元件帶 dumpling:layer 時才有作用"
                         "（pipeline/sbom-layers.py 標；SBOM 的 metadata 也記 dumpling:os-responsibility，這個參數優先）。"
                         "分層但沒有給 → 文件 GAP，全部列入待辦（不預設）")
    a = ap.parse_args(argv)
    if a.check_company is not None:
        if not a.check_company or a.project or a.company or a.no_company or a.out or a.image_check or a.board_test or a.flash_inventory \
                or a.pkgdb or a.own_software or a.uefi_source or a.tee_source or a.os_responsibility:
            ap.error("--check-company <檔案> 要單獨使用")
        try:
            comp, w = load_company(a.check_company)
        except Fail as e:
            print(f"FAIL\t{e}")
            return 1
        filled = sum(1 for v in report_fields(comp).values() if not isinstance(v, Missing))
        print(f"OK\t公司共用設定格式正確；填了 {filled} 個報告欄位" + (f"；警告 {len(w)}：" + "；".join(w) if w else ""))
        return 0
    if not a.project:
        ap.error("需要 --project")
    project = Path(a.project).resolve()
    if not project.is_dir():
        ap.error(f"不是資料夾：{project}")
    if a.scan and not Path(a.scan).is_dir():
        ap.error(f"不是資料夾：{a.scan}")
    for opt, v in (("--image-check", a.image_check), ("--board-test", a.board_test), ("--flash-inventory", a.flash_inventory),
                   ("--own-software", a.own_software)):
        if v is not None and (a.run_scan or not Path(v).is_file()):
            ap.error(f"{opt} 要給存在的檔案（只配 --scan）：{v}")
    if a.uefi_source is not None and (a.run_scan or not Path(a.uefi_source).is_dir()):
        ap.error(f"--uefi-source 要給存在的資料夾（只配 --scan）：{a.uefi_source}")
    if a.tee_source is not None and (a.run_scan or not Path(a.tee_source).is_dir()):
        ap.error(f"--tee-source 要給存在的資料夾（只配 --scan）：{a.tee_source}")
    if a.pkgdb is not None and (a.run_scan or not (Path(a.pkgdb) / "dpkg-status").is_file()):
        ap.error(f"--pkgdb 要給有 dpkg-status 的資料夾（只配 --scan）：{a.pkgdb}")
    out = Path(a.out).resolve() if a.out else project / "CRA" / "Reports"
    NVD_OPTS.update(grype_db=a.grype_db, rootfs=a.rootfs_dir)
    if a.grype_db:      # 明確給的資料庫要能用（不退回環境變數）；找不到或不是 Grype v6 → 錯誤
        try:
            nvdistro_mod().find_db(a.grype_db)
        except nvdistro_mod().DbError as e:
            ap.error(str(e.args[0]))
    try:
        cfg, warnings, company = load_config(project, company_file(a.company, a.no_company))
        if a.run_scan:
            cmd = scan_command(project, Path(a.run_scan).resolve(), cfg)
            print("執行 sca-scan " + " ".join(cmd[1:]), file=sys.stderr)
            return subprocess.run(cmd).returncode
        s = generate(project, Path(a.scan).resolve(), out, cfg, warnings, company,
                     Path(a.image_check).resolve() if a.image_check else None, Path(a.board_test).resolve() if a.board_test else None,
                     Path(a.flash_inventory).resolve() if a.flash_inventory else None, Path(a.pkgdb).resolve() if a.pkgdb else None,
                     Path(a.own_software).resolve() if a.own_software else None,
                     Path(a.uefi_source).resolve() if a.uefi_source else None,
                     Path(a.tee_source).resolve() if a.tee_source else None, a.os_responsibility)
    except Fail as e:
        if not a.run_scan:
            try:
                out.mkdir(parents=True, exist_ok=True)
                for fn in [*DOCS.values(), KERNEL_DOC[1], SEC_DOC[1], "sbom.cdx.json", "scan-status.tsv", "vex.cdx.json", "vex.openvex.json",
                           "confirmation-items.csv", "confirmation-items.md", "packages-without-vuln-data.csv", ROWS_FILE,
                           *(f"{st}.{e}" for st in UPSTREAM_BASELINE_STEMS for e in ("json", "md"))]:   # 不留上一次的文件冒充這次的結果
                    try:
                        (out / fn).unlink(missing_ok=True)
                    except OSError:
                        pass        # 例如同名的資料夾：照樣往下刪其他的、寫 FAIL 的 summary.json
                shutil.rmtree(out / "supplier-package", ignore_errors=True)
                for x in out.glob(".supplier-package.*"):
                    shutil.rmtree(x, ignore_errors=True)
                (out / "summary.json").write_text(json.dumps({"tool": "cra_report", "status": "FAIL", "error": str(e),
                                                              "note": "沒有產生文件（上一次的文件已刪除）"}, ensure_ascii=False, indent=1) + "\n",
                                                  encoding="utf-8")
            except OSError:
                pass
        print(f"FAIL\t{e}")
        return 1
    d, c = s["documents"], s["counts"]
    print(f"{s['status']}\trisk-assessment {d['risk-assessment']['status']}（P1 {c['p1']}、P2 {c['p2']}、P3 {c['p3']}、accepted {c['accepted']}"
          + (f"，其中核心 {c['kernel']['rows']} 列（{KERNEL_DOC[1]}）" if c["kernel"]["rows"] else "")
          + (f"；發行版已修補（backport，移出 P1–P3）{c['distro_fixed']} 列" if c.get("distro_fixed") else "") + "；"
          f"DT CVE {c['dt_unique_cves']}、Grype CVE {c['grype_unique_cves'] if c['grype_unique_cves'] is not None else '無資料'}）；"
          f"發行閘門 {s['vex']['gate']['verdict']}（未評估 {s['vex']['gate']['assessment']['untriaged_for_gate']}、"
          f"exploitable {s['vex']['gate']['open_affected']['rows']}"
          + (f"；判定沒有對到任何列 {len(s['vex']['gate']['annotations_unused'])} 筆" if s['vex']['gate'].get('annotations_unused') else "")
          + (f"；判定沒有負責人 {len(s['vex']['gate']['annotations_without_author'])} 筆" if s['vex']['gate'].get('annotations_without_author') else "")
          + "）；"
          + (f"依日期的出貨關卡（exploitation）{s['exploitation']['gate']['verdict']}（參考日 {s['exploitation']['gate']['reference_date']}；"
             f"P1 {s['exploitation']['gate']['p1']}、P2 {s['exploitation']['gate']['p2']}、必須判斷但未判斷 {s['exploitation']['gate']['not_assessed']}）；"
             if s.get("exploitation") else "") +
          f"安全測試 {s['security_testing']['status']}（open high {s['security_testing']['open']['high']}、medium {s['security_testing']['open']['medium']}；"
          f"{'、'.join(k for k, v in s['security_testing']['ran'].items() if v) or '沒有結果'}）；"
          + (f"待確認事項 {s['confirmation_items']['total']} 項（confirmation-items.csv）；" if s["confirmation_items"]["status"] == "OK"
             else "待確認事項表 FAIL（見 summary.json）；") +
          f"sbom {d['sbom']['status']}；支援期檢查 {s['support_check']['status']}；"
          + "".join(f"{k} {d[k]['status']}（缺 {len(d[k]['missing_fields'])} 個欄位）；" for k in (*SUPPLIER_SKIP, "supplier-package") if k in d)
          + (f"config 警告 {len(s['config_warnings'])}（見 summary.json）；" if s["config_warnings"] else "") + (f"公司共用設定 {company['path']}；" if company else "") + f"輸出 {out}")
    for w in s["config_warnings"]:
        print(f"config 警告：{w}", file=sys.stderr)
    return {"FAIL": 1, "OK": 0}.get(s["status"], 2)


if __name__ == "__main__":
    sys.exit(main())
