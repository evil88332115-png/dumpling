#!/usr/bin/env python3
"""vex_export.py：每個發行版本的 VEX（CycloneDX 1.6 VEX、OpenVEX 0.2.0）與發行閘門（release gate）。

為什麼：CRA Annex I Part I (2)(a) 要求產品上市時沒有「已知可被利用的弱點」。交給品牌客戶的每個發行版本除了 SBOM，還要有一份 VEX：
每個 CVE 對這個產品是否受影響、為什麼。cra_report.py 的 P1／P2／P3 只是依 KEV／EPSS／嚴重度排的優先順序，本身不記錄判定；
這支程式把已有的判定整理成每一列（CVE × 元件版本）的 VEX 狀態，寫成兩種格式，並算出發行閘門。

用法：
  文件產生時由 cra_report.py 呼叫（同一份列，與風險評估第 8 節一致），輸出 <Reports>/vex.cdx.json、vex.openvex.json。
  python3 -I vex_export.py annotate --project <專案> --cve CVE-… --state not_affected --justification code_not_reachable \
      --detail "…" --author "姓名" [--purl pkg:deb/ubuntu/openssl[@版本]] [--version 版本] [--response update …] [--date YYYY-MM-DD] [--replace] \
      [--evidence build-record|source|on-device|design-doc|vendor-statement --evidence-location 位置 […] | --evidence-basis '[{"type":…,"location":…,"kernel":…}]']
      在 <專案>/CRA/Config/vex-annotations.json 加一筆人工判定（先驗證整份檔案，寫到暫存檔再換上，不會留下寫一半的檔案）。
      resolved、not_affected、false_positive 這類排除要寫依據（見下面「排除的依據」）；沒有寫的排除算沒有類型，擋發行閘門。
  python3 -I vex_export.py check --project <專案>：只檢查 vex-annotations.json 的格式。
  python3 -I vex_export.py rules check --project <專案> [--scan <掃描輸出>]：檢查 CRA/Config/vex-rules.json；有 --scan 時乾跑
      （用 cra_report 產生到暫存資料夾），印出每條規則套用的列數、例子、因 KEV／P1／已有判定／範本缺值而不套用的列與閘門。
  python3 -I vex_export.py rules add --project <專案> --id R1 --description "…" [--author "…"] --reason "…" --scope kernel \
      --fix-state fixed --state exploitable --response update --detail-template "Fixed in {fix_version}; …" [--replace]
      在規則檔最後加一條規則（驗證、鎖、原子寫入、保留權限，同 annotate）。
  退出碼：0 成功；1 檔案格式錯、同一範圍已有判定（沒加 --replace），或 check 發現不會採用的判定（not_affected／false_positive／
  resolved 沒有 purl，印 WARN）；64 參數錯誤。

判定來源（每一列取第一個有判定的來源；後面的來源判定不同時記為衝突，不覆蓋）：
  (a) dt：Dependency-Track 裡人設的 analysis state（NOT_AFFECTED、FALSE_POSITIVE、RESOLVED、EXPLOITABLE、IN_TRIAGE），
      justification、response、details 原文照抄（DT 的 findings API 多半只有 state；有 dt/analysis.json〔dtread.py readback〕時用完整的分析；
      待辦：sca-scan 還不會寫這個檔案，等核心設定檢查的 PR 合併後再接上）。
      只有 suppress、沒有 state 的列不算判定（suppress 不是 VEX 狀態）。
  (a') annotation：專案的 CRA/Config/vex-annotations.json（人寫的判定，每個 CVE，可限定 purl 與版本），每次產生文件都套用，
      所以會自動帶到之後的發行版本。限定越精確的優先（purl＋版本 ＞ purl ＞ 只有 CVE）。not_affected／false_positive／resolved
      至少要限定 purl（annotate 拒絕；檔案裡已有的不採用並警告）；只有 CVE 的範圍只允許 in_triage、exploitable。
  (b) distro：scan/distro-recheck.json（status OK）的 distro_fixed → resolved（OpenVEX fixed），附發行版、修補版本、紀錄編號、安裝版本。
      規則與 cra_report 移列相同：不含核心，列裡每一筆 finding 都要在 distro_recheck 看過的 source_ids 內。
  (c) kconfig：scan/kernel-config.json（核心設定檢查，status OK）的 not_affected → not_affected＋code_not_present，只套用在核心的列。
  (d) nvidia：scan/nvidia-bulletins.json 的 presumed_included（推定已含修正，NVIDIA 未確認）→ in_triage，永遠不是 fixed／not_affected。
      公告的 CVE 在 DT 沒有對應的列時，另加一列（元件是 Jetson Linux 的 nvidia-l4t-core）；needs_vendor_confirmation 也加列，但沒有判定。
  (e) rule：專案的 CRA/Config/vex-rules.json（批次規則，人寫、有責任人與理由），只用在 (a)–(d) 都沒有判定的列，依檔案順序取第一條
      條件全部成立的規則。只能設 exploitable（response 可省略）或 in_triage；not_affected／resolved／false_positive 要逐列的證據，
      規則檔裡有就整份拒絕。在 KEV 目錄（DT 的 isKev；有 scan/euvd.json 時加上它標示已遭利用的）的列永遠不套用；P1 的列只在規則寫
      allow_p1 時套用。detail 由範本產生，用到的值（例如 {fix_version}）這一列沒有時這條規則不套用（記 template_missing）。
      陳述的 detail 結尾是「(bulk rule <id>: <description>)」，CycloneDX 另有屬性 sca-center:vex-rule，看得出不是逐列的評估。
      已有判定的列不套用，記在那條規則的 shadowed（依來源計數），所以規則不會和其他來源衝突。
      證據規則（寫 "evidence": K1／K2／U1 的規則，沒有 match／set）例外地可以設 not_affected，因為輸入只能是產物（核心 .config、
      scan/kernel-module-map.json 的模組對應與 CRA/Config/kernel-modules.json 的映像模組與載入限制、scan/ubuntu-status.json 的 Ubuntu 狀態、
      映像雜湊），嚴重度與 EPSS 進不去（evidence_view）。證據規則在 match 規則之前；要有 images（適用映像）、生效日已到、具名的責任人；
      KEV 與被利用的列不套用（不看 P1：P1 可能只是 EPSS 高）；被人或其他來源蓋過時記 shadowed 與這一列的 rule_shadowed，
      結論不同時列為衝突。K2 沒套用的核心列加標記 K3（模組可以載入）、K4（對不到模組，GAP）。有生效的 K1 規則時 (c) 改由規則套用（沒生效時照舊）。
      另有標記 distro_no_range_upstream_excludes（upstream_exclusion_flags，只標記「可能誤報，請人確認」，不改狀態）。
  (f) 其他：沒有判定（untriaged）。assess 的結果不變（r["vex"] 是空的，閘門照舊算 untriaged）；只在輸出階段（cdx_vex）寫成
      in_triage 加屬性 dumpling:assessment＝NOT_ASSESSED（OpenVEX：under_investigation、status_notes「dumpling: not assessed」），
      意思是「沒有評估」，不是有人在調查（M7c-1，A4／D-057；客戶版也輸出，句子是中性英文）。dt_writeback 不寫回這些陳述。
  人的判定（dt、annotation）彼此不同時：dt 優先，並記為「人工判定衝突」（閘門 ATTENTION）。

排除的依據（M7c-2，D-035／D-057）：每一筆排除（BUCKET 是 resolved 或 not_affected 的陳述，含 false_positive、resolved_with_pedigree）記依據的
  類型（build-record、source、on-device、design-doc、vendor-statement）與位置，放在陳述的 evidence_basis（[{"type", "location", "kernel"（選填）}]）。
  規則的 evidence 欄位（K1、K2、U1、U2，也就是規則種類）不動。各來源：
    kconfig、證據規則 K1 → build-record，位置 scan/kernel-config.json 加核心版本與 config 的 SHA-256；
    證據規則 K2 → build-record，位置 scan/kernel-module-map.json 與 CRA/Config/kernel-modules.json（各附 SHA-256；有核心設定檢查時再加 scan/kernel-config.json）；
    證據規則 U1、U2、發行版修補紀錄（distro_fixed）→ vendor-statement（發行版是 OS 的供應者，不新增第六種類型），位置是 Ubuntu CVE Tracker 的
      檔案加 commit 與 ubuntu.com 的頁面（U1、U2，每個 CVE 一筆），或紀錄編號（DSA、DLA、USN、UBUNTU-CVE-…，每個編號一筆）；
    annotation → 人寫在判定裡：evidence＋evidence_location（位置可以是清單＝多筆依據），或 evidence_basis（每筆自己的類型，可帶 kernel）；
    dt（人在 Dependency-Track 的判定）→ 沒有放類型的欄位，一律沒有類型（請改用 annotation 補依據）。
  on-device 的位置必須是專案資料夾內實際存在的檔案（相對路徑、不能有「..」、不能經符號連結指到外面）；只檢查檔案存在，沒有驗證內容。
  design-doc 的位置只要是合格的文字，不檢查文件。位置的共同限制見 vexconv.location_problem：不能空、不超過 512 字、不能有「;」、換行與控制字元
  （拒收「;」而不是編碼：OpenVEX 的依據行用「;」分隔欄位，不需要跳脫規則；輸入端與 vexconv 用同一個檢查）。
  沒有類型的排除：算進 assessment.untriaged_for_gate 與 exclusions_without_evidence、assessment.complete 變 false、reasons 加一條
  "N exclusions without evidence type"（和批次規則設的 in_triage 一樣）；其他數字（counts、untriaged、verdict 的算法）不變。
  輸出：內部 CycloneDX 的屬性 dumpling:evidence／dumpling:evidence-location／dumpling:evidence-kernel（沒有類型：dumpling:evidence＝none）；
  內部 OpenVEX 的 status_notes 一筆一行；客戶版只帶類型（supplier_package）。

發行閘門：每一列的 VEX 狀態分成 resolved、not_affected（含 false_positive）、exploitable、in_triage、untriaged，核心與其他元件分開。
  分開報告兩件事：(1) 評估是否完整（untriaged；規則判定的列算已評估）；(2) 仍受影響（exploitable，含規則判定的，依 response 分）。
  批次規則設的 in_triage 算沒有評估（擋閘門，另列一行）；NVIDIA 推定的 in_triage 照舊不擋。
  CRA Annex I Part I (2)(a) 要求上市時沒有已知可被利用的弱點，仍受影響的列要有人做出貨決定，所以有 exploitable 時閘門不會是 OK
  （沒有 untriaged 時理由寫 "assessment complete; N affected rows need a release decision"）。
  OK 只在：沒有 untriaged、沒有 exploitable、併進別列的其他 CVE（GHSA 的別名同時是 CVE-A、CVE-B，列在 CVE-A；CVE-B 自己沒有一列時）都有自己的判定、
  沒有缺 response 的 exploitable、沒有人工判定衝突（兩個人的結論相反，交給客戶的 VEX 只能有一個，要先有人裁決）、
  沒有缺理由而不採用的 DT 分析、Grype 有跑（有 grype.json 而且 C-grype 是 OK）而且沒有 DT 清單以外的弱點
  （那些弱點不在任何一列，VEX 也沒有它們的狀態），而且弱點清單完整
  （風險評估的資料狀態不是 GAP／NOT_ASSESSED）；否則 ATTENTION（清單不完整時是 GAP 或 NOT_ASSESSED），列出數量與優先順序最高的
  untriaged。in_triage 不擋閘門（照使用者的規則；文件與 summary.json 照樣列出數量）。OK 也不代表產品安全。

不寫回 DT：DT 匯入 CycloneDX VEX 會直接覆寫既有的分析（integration/reachmap/README.md 的教訓），可能蓋掉人的判定，
  所以這支程式不提供 push 到 DT 的功能；要在 DT 記判定請在 DT 介面操作，或寫進 vex-annotations.json。
只用標準函式庫。OpenVEX 的狀態與理由對映沿用 tools/vexconv/vexconv.py（依路徑載入）。
"""
import argparse
import copy
import datetime
import fnmatch
import hashlib
import importlib.util
import json
import os
import re
import stat
import string
import sys
import tempfile
import unicodedata
import urllib.parse
import uuid
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import nvidia_distro  # noqa: E402
ROOT = HERE.parents[1]
ANN_REL = Path("CRA") / "Config" / "vex-annotations.json"
ANN_SCHEMA = "sca-center-vex-annotations/1"
KCFG_SCHEMA = "sca-center-kernel-config/1"
# CycloneDX 1.6 的 impactAnalysisState／justification／response
CDX_STATES = ("resolved", "resolved_with_pedigree", "exploitable", "in_triage", "false_positive", "not_affected")
CDX_JUST = ("code_not_present", "code_not_reachable", "requires_configuration", "requires_dependency", "requires_environment",
            "protected_by_compiler", "protected_at_runtime", "protected_at_perimeter", "protected_by_mitigating_control")
CDX_RESP = ("can_not_fix", "will_not_fix", "update", "rollback", "workaround_available")
DT_STATE = {"NOT_AFFECTED": "not_affected", "FALSE_POSITIVE": "false_positive", "RESOLVED": "resolved",
            "EXPLOITABLE": "exploitable", "IN_TRIAGE": "in_triage"}
# 閘門的分類
BUCKETS = ("resolved", "not_affected", "exploitable", "in_triage", "untriaged")
BUCKET = {"resolved": "resolved", "resolved_with_pedigree": "resolved", "not_affected": "not_affected",
          "false_positive": "not_affected", "exploitable": "exploitable", "in_triage": "in_triage"}
# 同一個來源有多個不同判定時取最保守的（數字小的）
RANK = {"exploitable": 0, "in_triage": 1, "resolved": 2, "resolved_with_pedigree": 2, "not_affected": 3, "false_positive": 3}
# 候選判定衝突時的保守程度（小的優先）：resolved 與 not_affected 同級（都是「關閉」），不互相排序
CONSERVATIVE = {"exploitable": 0, "in_triage": 1, "resolved": 2, "not_affected": 2}
SOURCES = ("dt", "annotation", "distro", "kconfig", "nvidia", "rule")
HUMAN = ("dt", "annotation")
SRC_LABEL = {"dt": "DT", "annotation": "annotation", "distro": "distro", "kconfig": "kconfig", "nvidia": "NVIDIA", "rule": "rule",
             "dt_suppressed": "DT suppressed"}
# 規則的 shadowed 計數多一種：DT 裡 suppress、沒有 state 的列（人看過、壓掉了，規則不寫相反的陳述；這一列仍是 untriaged）
SHADOW_KEYS = SOURCES + ("dt_suppressed",)
TIER_ORDER = {"p1": 0, "p2": 1, "p3": 2}
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
# 說「沒有影響／已修好」的判定至少要限定到套件（purl，名稱層級）：只寫 CVE 的範圍會套到任何元件與之後的任何版本，
# 對 not_affected 這種結論太廣（使用者 2026-11-02 決定）。只有 CVE 的範圍只允許 in_triage、exploitable（保守的方向）
PURL_REQUIRED = ("not_affected", "false_positive", "resolved", "resolved_with_pedigree")
CVE_ID = re.compile(r"^(?:[A-Z]+-)?(CVE-\d{4}-\d{4,})$")    # CVE-…、UBUNTU-CVE-…（與 cra_report 的 CVE_RE 相同）
ANN_KEYS = {"cve", "purl", "version", "state", "justification", "response", "detail", "action_statement", "author", "date",
            "evidence", "evidence_location", "evidence_basis"}
# 排除的依據（M7c-2，D-035／D-057）。類型與 tools/vexconv/vexconv.py 的 EVIDENCE_TYPES 同值（測試核對）
EVIDENCE_TYPES = ("build-record", "source", "on-device", "design-doc", "vendor-statement")
EVIDENCE_BUCKETS = ("resolved", "not_affected")          # 要有依據的分類（BUCKET 的值）
EVIDENCE_BASIS_MAX = 64                                   # 一筆判定最多幾筆依據
EVIDENCE_TABLE_MAX = 100                                  # 風險評估列出的 on-device／design-doc 排除筆數上限（summary.json 是全部）
# 沒有類型的排除的原因代號 → 閘門與報告的說明（英文）
EVIDENCE_MISSING = {
    "dt": "Dependency-Track decision (no field for an evidence type)",
    "annotation_no_evidence": "annotation without evidence",
    "annotation_evidence_invalid": "annotation with invalid evidence",
    "on_device_missing": "on-device file missing",
    "on_device_unsafe_path": "on-device path not allowed",
    "on_device_no_project": "on-device file not checked (no project folder)",
    "distro_no_record": "distribution record without an ID",
    "no_basis": "no evidence recorded by the tool",
}
# 批次規則（CRA/Config/vex-rules.json）：只能設 exploitable（response 可省略）或 in_triage。說「沒有影響／已修好」要逐列的證據
# （發行版覆核、核心設定檢查，或判定檔裡限定 purl 的逐個 CVE 判定），規則不能設
RULES_REL = Path("CRA") / "Config" / "vex-rules.json"
RULES_SCHEMA = "sca-center-vex-rules/1"
RULE_STATES = ("exploitable", "in_triage")
RULE_KEYS = {"id", "description", "author", "date", "reason", "match", "set", "$comment"}
MATCH_KEYS = {"scope", "purl_prefix", "purl_type", "fix_state", "kernel_config", "tier", "severity", "epss_percentile_max",
              "include_no_epss", "kev", "allow_p1"}
SET_KEYS = {"state", "response", "detail_template", "recommendation"}
SCOPES = ("kernel", "non_kernel", "all")
FIX_STATES = ("fixed", "not-fixed", "wont-fix", "unknown", "no Grype data")     # 與 cra_report 的 FIX_STATES 相同
KCFG_MATCH = ("affected", "unknown")           # not_affected 的列已經有 kconfig 的陳述，規則用不到
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNASSIGNED")
TEMPLATE_FIELDS = ("fix_version", "installed_version", "component", "kernel_fix_all", "cve")
RULE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
# 證據規則（rules[] 裡寫 "evidence" 的規則；README「證據規則」）：結果固定是 not_affected，輸入由種類固定，只能是產物
# （核心 .config／Kbuild 判定、映像內模組清單、modprobe 設定／modules_disabled、套件清單、Ubuntu 的狀態、映像雜湊）。
# 沒有 match／set：嚴重度、EPSS、層級、CVSS 不能當輸入（evidence_view 只把產物欄位交給判定函式；測試鎖住）。
#   K1：核心設定檢查（scan/kernel-config.json）判定修補的程式沒編進核心 → not_affected／code_not_present。
#       有「生效的」K1 規則時，原本自動套用的來源 (c) kconfig 改由規則套用（同樣的證據，多了責任人、生效日、適用映像，KEV 的列不套用）；
#       K1 沒有生效（責任人是佔位字、映像不符、還沒到生效日）時照舊是來源 (c)，輸出和沒有 K1 一樣。
#   K2：修補動到的程式只在核心模組裡，而模組已從映像移除（code_not_present）或被禁止載入（code_not_reachable）→ not_affected。
#       沒套用的核心列加標記（不改狀態）：K3＝模組可以載入（仍受影響）；K4＝對不到模組（當作編進核心、受影響；這一列 GAP）。
#   U1：Ubuntu CVE Tracker 對這個原始碼套件、這個發行版是 not-affected，而且安裝的版本符合它的版本註記 → not_affected／code_not_present。
#   U2：Ubuntu 打包的 Python 模組（deb_python 的擁有者）的每個 CVE，Tracker 對擁有者的原始碼套件、這個發行版是 released，而且安裝的原始碼版本
#       不比註記舊（Ubuntu 已在安裝的版本修好）→ resolved（唯一結果是 resolved 的證據規則；沒有設定 U2 時輸出和以前逐位元相同）。
EVIDENCE_KINDS = ("K1", "K2", "U1", "U2")
EVIDENCE_RULE_KEYS = {"id", "description", "author", "date", "reason", "evidence", "images", "$comment"}
IMAGE_RE = re.compile(r"^(?:sha256:)?([0-9a-f]{64})$")
# 範例規則檔的適用映像佔位字：責任人還是佔位字時規則本來就不套用；填了責任人卻沒換掉 → 格式錯（check_rules）
IMAGE_PLACEHOLDER = "sha256:<image digest>"
# 判定函式看得到的欄位（只有產物的身分與這一列的 CVE）。不含 severity、epss、epss_pct、cvss、tier、kev 等：它們只能用來「排除」
# （KEV／被利用的列不套用），不能讓一列變成 not_affected
EVIDENCE_VIEW_KEYS = ("id", "cves", "key", "component", "name", "version", "purl", "kernel", "installed_as", "deb_python")
# deb_python 只交出擁有者的身分（U2 用）；Ubuntu 的修補狀態、PyPI 的修補版本等推出來的欄位不交
DEB_PYTHON_VIEW_KEYS = ("owner", "source_owner", "candidates")
KMOD_REL = Path("CRA") / "Config" / "kernel-modules.json"
KMOD_SCHEMA = "sca-center-kernel-modules/1"
KMOD_KEYS = {"schema", "image_sha256", "kernel_version", "captured", "owner", "source", "modules_in_image", "modules_outside_dirs",
             "modules_builtin", "modprobe_d", "modules_softdep", "modules_disabled", "loaded", "$comment"}
MODMAP_SCHEMA = "sca-center-kernel-module-map/1"
USTATUS_SCHEMA = "sca-center-ubuntu-status/1"
U1_TABLE_MAX = 200     # 風險評估裡 U1 排除清單最多列幾筆（完整清單在 summary.json 的 vex.u1_excluded）
# modprobe.d 的 install 指令：只有這幾個「什麼都不做就結束」的指令算禁止載入（CIS 的寫法）；其他指令（含 || 等組合）不算
SOFTDEP_HEADER = "# Soft dependencies extracted from modules themselves."   # depmod 寫在 modules.softdep 的第一行
BLOCK_CMDS = ("/bin/false", "/bin/true", "/usr/bin/false", "/usr/bin/true", "false", "true")
DEB_VERSION_RE = re.compile(r"^(?:\d+:)?[0-9][A-Za-z0-9.+~-]*$")      # 粗略的形狀（可能誤報標記用）；U1 用 deb_version_parts


def deb_version_parts(v):
    """Debian 版本（dpkg／Debian Policy 5.6.12）→ (epoch, 上游版本, revision)；不合規則 → None。
    epoch 是數字；有 - 時最後一個 - 之後是 revision（不能是空的，只有 A-Za-z0-9.+~），之前是上游版本（數字開頭，A-Za-z0-9.+~-）；
    沒有 - 時是原生套件（上游版本不能有 -）。上游版本裡的冒號（dpkg 在有 epoch 時允許）不收：比不出來就不排除。"""
    m = re.fullmatch(r"(?:(\d+):)?([0-9][A-Za-z0-9.+~-]*?)(?:-([A-Za-z0-9.+~]+))?", str(v or ""))
    if not m or (m.group(3) is None and "-" in m.group(2)) or int(m.group(1) or 0) > 2 ** 31 - 1:
        return None
    return int(m.group(1) or 0), m.group(2), m.group(3) or ""
MARKER_TEXT = {"K3": "K3: module loadable", "K4": "K4 GAP: no module mapping", "U1-not-applied": "U1 not applied",
               "U1-older-revision": "U1 not applied: older revision",
               "distro_no_range_upstream_excludes": "possible false positive",
               "kernel_scope": "K1/K2 not adopted: another shipped kernel was not judged"}
# 規則檔最上層的 author 是所有規則的預設責任人（專案負責人填一次）；規則自己的 author 優先。空的或還是範例的佔位字時規則照樣套用，
# 但文件寫 TO BE COMPLETED、閘門 ATTENTION（不替人編名字，VEX 照原樣寫）
# 責任人欄的佔位字（author_missing：比對前去掉前後空白、不分大小寫）。TBD、TODO、N/A、NA、unknown、none、-、? 是原本帳號 2026-11-07 加的：
# 這些署名的判定不算「具名的人工判定」（cra_report 不採用、exploited_watch 不算已評估）
AUTHOR_PLACEHOLDERS = ("專案負責人", "(your name)", "to be completed", "tbd", "todo", "n/a", "na", "unknown", "none", "-", "?")


class VexInputError(ValueError):
    pass


_VEXCONV = []


def _vexconv():
    """tools/vexconv/vexconv.py（依路徑載入，只載入一次）。"""
    if not _VEXCONV:
        p = ROOT / "tools" / "vexconv" / "vexconv.py"
        spec = importlib.util.spec_from_file_location("sca_center_vexconv", p)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        _VEXCONV.append(m)
    return _VEXCONV[0]


# ---------- 人工判定檔（CRA/Config/vex-annotations.json） ----------

def purl_split(purl):
    """purl → (不含版本、qualifiers、subpath 的小寫 base, 版本或 None)。不是 purl → (None, None)。"""
    if not isinstance(purl, str) or not purl.startswith("pkg:") or "/" not in purl:
        return None, None
    body = purl.split("#", 1)[0].split("?", 1)[0]
    typ, _, rest = body[4:].partition("/")
    at = rest.rfind("@")
    name, ver = (rest[:at], rest[at + 1:]) if at > 0 else (rest, None)
    return f"pkg:{typ.lower()}/{urllib.parse.unquote(name).lower()}", urllib.parse.unquote(ver) if ver else None


def purl_quals(purl):
    """purl 的 qualifiers → {小寫鍵: 值}（沒有時空 dict）。"""
    if not isinstance(purl, str):
        return {}
    q = purl.split("#", 1)[0].partition("?")[2]
    return {k.lower(): v for k, v in urllib.parse.parse_qsl(q, keep_blank_values=True)}


def validate_annotation(a, where):
    errs = []
    if not isinstance(a, dict):
        return [f"{where}：要是物件"]
    errs += [f"{where}.{k}：不認得的鍵" for k in sorted(set(a) - ANN_KEYS)]
    for k in ("cve", "state", "detail", "author", "date"):
        if not isinstance(a.get(k), str) or not a[k].strip():
            errs.append(f"{where}.{k}：必填（文字）")
    if isinstance(a.get("cve"), str) and not re.match(r"^[A-Za-z][A-Za-z0-9]*-[A-Za-z0-9.:_-]+$", a["cve"]):
        errs.append(f"{where}.cve：不像弱點編號（例如 CVE-2024-6119、GHSA-…）")
    if a.get("state") is not None and a.get("state") not in CDX_STATES:
        errs.append(f"{where}.state：只能是 {', '.join(CDX_STATES)}")
    if a.get("justification") is not None and a.get("justification") not in CDX_JUST:
        errs.append(f"{where}.justification：只能是 {', '.join(CDX_JUST)}")
    if a.get("state") in ("not_affected", "false_positive") and not a.get("justification"):
        errs.append(f"{where}.justification：{a.get('state')} 一定要寫理由")
    if a.get("justification") and a.get("state") not in ("not_affected", "false_positive"):
        errs.append(f"{where}.justification：只用在 not_affected")
    resp = a.get("response", [])
    if not isinstance(resp, list) or any(x not in CDX_RESP for x in resp) or len(set(resp)) != len(resp):
        errs.append(f"{where}.response：要是不重複的清單，值只能是 {', '.join(CDX_RESP)}")
    elif a.get("state") == "exploitable" and not resp:
        errs.append(f"{where}.response：exploitable 一定要寫處理方式（例如 update、workaround_available）")
    if isinstance(a.get("date"), str) and a["date"].strip():
        try:
            if not DATE_RE.match(a["date"]):
                raise ValueError
            datetime.date.fromisoformat(a["date"])
        except ValueError:
            errs.append(f"{where}.date：要是 YYYY-MM-DD")
    if a.get("purl") is not None and purl_split(a["purl"])[0] is None:
        errs.append(f"{where}.purl：不是 purl（pkg:類型/名稱[@版本]）")
    if a.get("version") is not None and (not isinstance(a["version"], str) or not a["version"].strip()):
        errs.append(f"{where}.version：要是文字")
    if a.get("version") and a.get("purl") and purl_split(a["purl"])[1] not in (None, a["version"]):
        errs.append(f"{where}：purl 的版本和 version 不同")
    if a.get("action_statement") is not None and (not isinstance(a["action_statement"], str) or not a["action_statement"].strip()):
        errs.append(f"{where}.action_statement：要是文字")
    errs += annotation_evidence_errors(a, where)
    return errs


def _basis_entry_errors(e, where):
    """一筆依據 {type, location, kernel?} 的格式問題（不看檔案；on-device 的檔案另在 on_device_problem 檢查）。"""
    vc = _vexconv()
    if not isinstance(e, dict):
        return [f"{where}：要是物件 {{type, location, kernel（選填）}}"]
    errs = [f"{where}.{k}：不認得的鍵" for k in sorted(set(e) - {"type", "location", "kernel"})]
    if e.get("type") not in EVIDENCE_TYPES:
        errs.append(f"{where}.type：只能是 {', '.join(EVIDENCE_TYPES)}")
    p = vc.location_problem(e.get("location"))
    if p:
        errs.append(f"{where}.location：{p}")
    if e.get("kernel") is not None and vc.kernel_problem(e["kernel"]):
        errs.append(f"{where}.kernel：{vc.kernel_problem(e['kernel'])}")
    return errs


def annotation_evidence_errors(a, where):
    """判定的依據欄位（選填，只對 resolved、not_affected 等排除有作用）的格式：
      evidence：五種類型之一（EVIDENCE_TYPES）；evidence_location：位置（文字），或文字清單（清單＝同一個類型的多筆依據）。
        兩個要一起寫。
      evidence_basis：{type, location, kernel（選填，這一筆是哪一顆核心的）} 的清單，每一筆依據自己一個類型；映像有多顆核心時
        每顆各一筆。不能和 evidence／evidence_location 一起用。
    位置的限制（vexconv.location_problem）：不能空、前後沒有空白、不超過 512 字、不能有「;」、換行與控制字元。"""
    errs = []
    has = [k for k in ("evidence", "evidence_location", "evidence_basis") if k in a]
    if not has:
        return errs
    if "evidence_basis" in a and ("evidence" in a or "evidence_location" in a):
        return [f"{where}.evidence_basis：不能和 evidence、evidence_location 一起用"]
    if "evidence_basis" in a:
        b = a["evidence_basis"]
        if not isinstance(b, list) or not b or len(b) > EVIDENCE_BASIS_MAX:
            return [f"{where}.evidence_basis：要是 1–{EVIDENCE_BASIS_MAX} 筆依據的清單"]
        for i, e in enumerate(b):
            errs += _basis_entry_errors(e, f"{where}.evidence_basis[{i}]")
        return errs
    if "evidence" not in a or "evidence_location" not in a:
        return [f"{where}：evidence 與 evidence_location 要一起寫（類型加位置）"]
    if a["evidence"] not in EVIDENCE_TYPES:
        errs.append(f"{where}.evidence：只能是 {', '.join(EVIDENCE_TYPES)}")
    loc = a["evidence_location"]
    locs = loc if isinstance(loc, list) else [loc]
    if not locs or len(locs) > EVIDENCE_BASIS_MAX:
        return errs + [f"{where}.evidence_location：清單要有 1–{EVIDENCE_BASIS_MAX} 筆"]
    for i, x in enumerate(locs):
        p = _vexconv().location_problem(x)
        if p:
            errs.append(f"{where}.evidence_location{f'[{i}]' if isinstance(loc, list) else ''}：{p}")
    return errs


def annotation_basis(a):
    """（已驗證的）判定 → 依據清單 [{type, location, kernel?}]（去掉重複、保留順序）；沒有依據欄位 → []。"""
    if isinstance(a.get("evidence_basis"), list):
        raw = [dict(e) for e in a["evidence_basis"]]
    elif "evidence" in a:
        loc = a.get("evidence_location")
        raw = [{"type": a["evidence"], "location": x} for x in (loc if isinstance(loc, list) else [loc])]
    else:
        return []
    out = []
    for e in raw:
        e = {k: e[k] for k in ("type", "location", "kernel") if e.get(k) is not None}
        if e not in out:
            out.append(e)
    return out


def on_device_problem(loc, project):
    """on-device 依據的位置檢查 → None（通過）或原因代號。只檢查「專案資料夾內有這個檔案」，沒有驗證檔案的內容。
    位置只收相對路徑，不能是絕對路徑（含磁碟機代號、~）、不能有「\\」、任何一段都不能是「..」→ on_device_unsafe_path；
    resolve（跟著符號連結）之後必須是專案資料夾內的一般檔案：不存在、是資料夾、經符號連結指到專案資料夾外 → on_device_missing；
    沒有專案資料夾可以檢查 → on_device_no_project。"""
    if not isinstance(loc, str) or not loc or "\\" in loc or loc.startswith(("/", "~")) or re.match(r"^[A-Za-z]:", loc) \
            or any(seg == ".." for seg in loc.split("/")):
        return "on_device_unsafe_path"
    if project is None:
        return "on_device_no_project"
    try:
        root = Path(project).resolve()
        real = (root / loc).resolve(strict=True)
        ok = real.is_file() and root in real.parents
    except (OSError, RuntimeError, ValueError):
        return "on_device_missing"
    return None if ok else "on_device_missing"


def annotation_evidence(a, project):
    """判定的依據 → (依據清單, None)；沒有可用的依據 → ([], 原因代號)。沒有寫依據 → annotation_no_evidence；格式不合（呼叫端沒經過
    check_annotations 時）→ annotation_evidence_invalid；on-device 的檔案不合格 → on_device_*。有任何一筆不合格，整筆都算沒有類型
    （不留一半：說有上機核對、檔案卻不存在的排除，不能靠另一筆依據過關）。"""
    basis = annotation_basis(a)
    if not basis:
        return [], "annotation_no_evidence"
    if annotation_evidence_errors(a, "x"):
        return [], "annotation_evidence_invalid"
    for e in basis:
        if e["type"] == "on-device":
            why = on_device_problem(e["location"], project)
            if why:
                return [], why
    return basis, None


def safe_location(text):
    """工具自己組的依據位置 → 通過 vexconv.location_problem 的文字（「;」換成「,」、換行與控制字元換成空白、去掉前後空白、截到 512 字）。"""
    vc = _vexconv()
    t = "".join(" " if unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp") else "," if c == ";" else c for c in str(text))
    return re.sub(r" {2,}", " ", t).strip()[:vc.LOCATION_MAX].strip()


def basis_entry(typ, location, kernel=None):
    """一筆依據 {type, location, kernel?}。核心版本不是核心版本的寫法時不放 kernel（位置照樣寫）。"""
    e = {"type": typ, "location": safe_location(location)}
    if kernel and not _vexconv().kernel_problem(str(kernel)):
        e["kernel"] = str(kernel)
    return e


def sha_part(path, sha, label="SHA-256"):
    return f"{path} ({label} {sha})" if sha else path


def kcfg_basis(kcfg):
    """核心設定檢查（scan/kernel-config.json）的依據：build-record，位置寫檔案、核心版本與 config 的 SHA-256。"""
    k = (kcfg or {}).get("kernel") or {}
    ver, sha = k.get("version"), k.get("config_sha256")
    inner = ", ".join(x for x in (f"kernel {ver}" if ver else "", f"config SHA-256 {sha}" if sha else "") if x)
    return basis_entry("build-record", "scan/kernel-config.json" + (f" ({inner})" if inner else ""), ver)


def k2_basis(mm, ec, km):
    """K2 的依據：build-record，位置寫核心設定檢查（有 config 的 SHA-256 時）、模組對應與映像模組清單（各附 SHA-256）。"""
    parts = []
    if ec.get("kcfg_sha"):
        parts.append(sha_part("scan/kernel-config.json", ec["kcfg_sha"], "config SHA-256"))
    parts += [sha_part("scan/kernel-module-map.json", ec.get("mm_sha")), sha_part(KMOD_REL.as_posix(), km.get("sha256"))]
    return basis_entry("build-record", ", ".join(parts), ((mm or {}).get("kernel") or {}).get("version"))


def ubuntu_basis(ev, cve_info=None):
    """U1、U2 的依據（rule_evidence）：vendor-statement，每個 CVE 一筆，位置寫 tracker 的檔案（active/<CVE> 或 retired/<CVE>；
    cve_info 或這個 CVE 的紀錄沒有時寫 CVE 編號）與 commit，加 ubuntu.com 的頁面。"""
    commit = (ev.get("tracker") or {}).get("commit")
    return [basis_entry("vendor-statement", f"Ubuntu CVE Tracker {c.get('tracker_file') or ((cve_info or {}).get(c['cve']) or {}).get('tracker_file') or c['cve']}"
                        + (f"@{commit}" if commit else " (commit not recorded)") + f", {c['url']}") for c in ev.get("cves") or []]


def distro_basis(x):
    """發行版修補紀錄（distro_fixed）的依據：vendor-statement，每個紀錄編號（DSA、DLA、USN、UBUNTU-CVE-…）一筆。"""
    recs = sorted({str(e["record"]) for e in x.get("evidence") or [] if isinstance(e, dict) and e.get("record") not in (None, "", "?")})
    out = [basis_entry("vendor-statement", r) for r in recs]
    return [e for e in out if not _vexconv().location_problem(e["location"])]


def scope_of(a):
    """判定的適用範圍（重複判斷用）與精確度：只有 CVE 1，purl 或版本各加 1，purl 帶 qualifiers（例如 ?arch=arm64）再加 1。"""
    base, pver = purl_split(a.get("purl")) if a.get("purl") else (None, None)
    ver = a.get("version") or pver
    quals = "&".join(f"{k}={v}" for k, v in sorted(purl_quals(a.get("purl")).items())) or None
    return (a["cve"].upper(), base, ver, quals), 1 + bool(base) + bool(ver) + bool(quals)


def unscoped(a):
    """not_affected／false_positive／resolved 卻沒有 purl 的判定（只寫 CVE，或只寫版本）。"""
    return a.get("state") in PURL_REQUIRED and not a.get("purl")


def check_annotations(doc, path="vex-annotations.json"):
    if not isinstance(doc, dict) or doc.get("schema") != ANN_SCHEMA or not isinstance(doc.get("annotations"), list):
        raise VexInputError(f"{path}：要是 {{\"schema\": \"{ANN_SCHEMA}\", \"annotations\": [...]}}")
    extra = set(doc) - {"schema", "annotations", "$comment"}
    errs = [f"{path}：不認得的鍵 {', '.join(sorted(extra))}"] if extra else []
    seen = {}
    for i, a in enumerate(doc["annotations"]):
        e = validate_annotation(a, f"annotations[{i}]")
        errs += e
        if not e:
            sc = scope_of(a)[0]
            if sc in seen:
                errs.append(f"annotations[{i}]：和 annotations[{seen[sc]}] 的範圍相同（{sc[0]}、{sc[1] or '任何元件'}、{sc[2] or '任何版本'}"
                            f"{'、' + sc[3] if sc[3] else ''}）")
            seen.setdefault(sc, i)
    if errs:
        raise VexInputError(f"{path} 不符合格式：" + "；".join(errs))
    return doc["annotations"]


def load_annotations(project):
    """回傳 (判定清單, {file, sha256, count, ignored, warnings} 或 None)。檔案不存在 → ([], None)；格式錯 → VexInputError。
    not_affected／false_positive／resolved 卻沒有 purl 的判定（unscoped）不用，記在 ignored 與 warnings（不讓整份文件 FAIL：
    舊檔案裡可能已有這種判定，其他判定照常套用）。"""
    p = Path(project) / ANN_REL
    if not p.is_file():
        return [], None
    raw = p.read_bytes()
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        raise VexInputError(f"{ANN_REL} 不是 JSON：{e}")
    allanns = check_annotations(doc, str(ANN_REL))
    anns = [a for a in allanns if not unscoped(a)]
    ign = [f"{a['cve']} {a['state']}" + (f" (version {a['version']})" if a.get("version") else "") for a in allanns if unscoped(a)]
    warn = [f"{ANN_REL}：{x} 沒有限定套件（purl），不採用；not_affected／false_positive／resolved 至少要寫 purl（套件名稱層級）"
            for x in ign]
    return anns, {"file": str(ANN_REL), "sha256": hashlib.sha256(raw).hexdigest(), "count": len(anns), "ignored": ign, "warnings": warn}


def annotation_matches(a, row):
    """這筆判定是否適用於這一列。VEX 的陳述寫在這一列的編號（row["id"]）下，所以：
      - 判定的編號要就是這一列的編號；別名（例如 GHSA-…）只在判定寫的不是 CVE、而且這一列最多只有一個 CVE 時才算
        （同一列可能併了別名不同的 CVE：GHSA 同時是 CVE-A 與 CVE-B 時列在 CVE-A，CVE-B 的判定不能變成 CVE-A 的陳述）；
      - purl 比 base（類型＋namespace＋名稱；DT 的原始碼套件也比安裝的二進位套件）；purl 有 qualifiers 時要直接對上，
        而且每個 qualifier 都要和這一列的 purl 相同；有版本時版本要完全相同。"""
    vid, rid = a["cve"].upper(), str(row.get("id") or "").upper()
    if vid != rid:
        ids = {x.upper() for x in row.get("all_ids") or []}
        if CVE_ID.match(vid) or len(row.get("cves") or []) > 1 or vid not in ids:
            return False
        # 併進這一列的 USN（cra_report 的 usn_merged）：只在 USN 只列這一列的 CVE 時才算（和 DT 對 USN 的分析相同）；
        # 列多個 CVE 的 USN 的判定不能變成其中一個 CVE 的陳述
        merged = {k.upper(): {c.upper() for c in v} for k, v in (row.get("usn_merged") or {}).items()}
        if vid in merged and merged[vid] != {rid}:
            return False
    (_, base, ver, quals), _ = scope_of(a)
    if ver is not None and ver != row.get("version"):
        return False
    if base is None:
        return True
    rbase, _ = purl_split(row.get("purl"))
    if quals:
        rq = purl_quals(row.get("purl"))
        return base == rbase and all(rq.get(k) == v for k, v in purl_quals(a.get("purl")).items())
    if base == rbase:
        return True
    if rbase and rbase.startswith("pkg:deb/"):
        ns = rbase.rsplit("/", 1)[0]
        return any(base == f"{ns}/{b.lower()}" for b in row.get("installed_as") or [])
    return False


# ---------- 批次規則（CRA/Config/vex-rules.json） ----------

def template_errors(t, where):
    """範本只能用 TEMPLATE_FIELDS 的欄位名稱（不能有格式、轉換、屬性或索引：{component.__class__} 之類一律拒絕）。"""
    if not isinstance(t, str) or not t.strip():
        return [f"{where}：必填（文字）"]
    try:
        parts = list(string.Formatter().parse(t))
    except ValueError as e:
        return [f"{where}：範本格式錯（{e}；要寫大括號本身請用 {{{{ 與 }}}}）"]
    errs = []
    for _, field, spec, conv in parts:
        if field is None:
            continue
        if field not in TEMPLATE_FIELDS or spec or conv:
            errs.append(f"{where}：不認得的欄位 {{{field}{'!' + conv if conv else ''}{':' + spec if spec else ''}}}，"
                        f"只能用 {', '.join('{' + x + '}' for x in TEMPLATE_FIELDS)}")
    return errs


def _str_list(v, allowed, where, upper=False):
    if not isinstance(v, list) or not v or any(not isinstance(x, str) for x in v) or len(set(v)) != len(v):
        return [f"{where}：要是不重複、不是空的文字清單"]
    bad = [x for x in v if (x.upper() if upper else x) not in allowed]
    return [f"{where}：{', '.join(bad)} 不是可用的值（{', '.join(allowed)}）"] if bad else []


def validate_evidence_rule(r, where):
    """證據規則：id、description、date（生效日）、reason、evidence（K1／K2／U1）、images（適用映像）必填；不能有 match／set。"""
    errs = []
    if "match" in r or "set" in r:
        errs.append(f"{where}：證據規則（evidence）不能有 match／set：輸入由種類固定、只能是產物（嚴重度、EPSS、層級不能當 not_affected 的輸入），"
                    "結果固定是 not_affected")
    errs += [f"{where}.{k}：不認得的鍵" for k in sorted(set(r) - EVIDENCE_RULE_KEYS - {"match", "set"})]
    if r.get("evidence") not in EVIDENCE_KINDS:
        errs.append(f"{where}.evidence：只能是 {', '.join(EVIDENCE_KINDS)}")
    im = r.get("images")
    if not isinstance(im, list) or not im or any(not isinstance(x, str) for x in im) or len(set(im)) != len(im):
        errs.append(f"{where}.images：必填，要是不重複的清單：映像的 sha256（sha256:<64 個十六進位字元>），或只寫 [\"*\"]（這個專案的所有映像）")
    elif im != ["*"] and any(x == "*" or (x != IMAGE_PLACEHOLDER and not IMAGE_RE.match(x.lower())) for x in im):
        errs.append(f"{where}.images：每一項要是 sha256:<64 個十六進位字元>；\"*\" 只能單獨寫")
    return errs


def validate_rule(r, where):
    errs = []
    if not isinstance(r, dict):
        return [f"{where}：要是物件"]
    if "evidence" in r:
        errs += validate_evidence_rule(r, where)
    else:
        errs += [f"{where}.{k}：不認得的鍵" for k in sorted(set(r) - RULE_KEYS)]
    for k in ("id", "description", "date", "reason"):
        if not isinstance(r.get(k), str) or not r[k].strip():
            errs.append(f"{where}.{k}：必填（文字）")
    if "author" in r and not isinstance(r["author"], str):
        errs.append(f"{where}.author：要是文字")
    if isinstance(r.get("id"), str) and r["id"].strip() and not RULE_ID.match(r["id"]):
        errs.append(f"{where}.id：只能用英文字母、數字、. _ -（最多 64 字，例如 R1、kernel-fixed）")
    if isinstance(r.get("date"), str) and r["date"].strip():
        try:
            if not DATE_RE.match(r["date"]):
                raise ValueError
            datetime.date.fromisoformat(r["date"])
        except ValueError:
            errs.append(f"{where}.date：要是 YYYY-MM-DD")
    if "evidence" in r:
        return errs
    m, s = r.get("match"), r.get("set")
    if not isinstance(m, dict):
        errs.append(f"{where}.match：必填（物件）")
        m = {}
    if not isinstance(s, dict):
        errs.append(f"{where}.set：必填（物件）")
        s = {}
    errs += [f"{where}.match.{k}：不認得的鍵" for k in sorted(set(m) - MATCH_KEYS)]
    errs += [f"{where}.set.{k}：不認得的鍵" for k in sorted(set(s) - SET_KEYS)]
    w = f"{where}.match"
    if m.get("scope") not in SCOPES:
        errs.append(f"{w}.scope：必填，只能是 {', '.join(SCOPES)}")
    if "purl_prefix" in m:
        pp = m["purl_prefix"]
        if not isinstance(pp, list) or not pp or any(not isinstance(x, str) or not x.lower().startswith("pkg:") or "/" not in x
                                                      or any(c in x for c in "@?#") for x in pp):
            errs.append(f"{w}.purl_prefix：要是 purl 開頭的清單（例如 [\"pkg:deb/ubuntu/\"]；不含 @版本、?qualifiers）")
    if "purl_type" in m:
        pt = m["purl_type"]
        if not isinstance(pt, list) or not pt or any(not isinstance(x, str) or not re.match(r"^[a-z0-9.+-]+$", x) for x in pt):
            errs.append(f"{w}.purl_type：要是 purl 類型的清單（小寫，例如 [\"deb\"]、[\"pypi\"]）")
    for k, allowed, up in (("fix_state", FIX_STATES, False), ("kernel_config", KCFG_MATCH, False), ("tier", tuple(TIER_ORDER), False),
                           ("severity", SEVERITIES, True)):
        if k in m:
            errs += _str_list(m[k], allowed, f"{w}.{k}", up)
    if "kernel_config" in m and m.get("scope") != "kernel":
        errs.append(f"{w}.kernel_config：只用在 scope kernel（核心設定檢查只有核心的列有結果）")
    if "epss_percentile_max" in m and (isinstance(m["epss_percentile_max"], bool) or not isinstance(m["epss_percentile_max"], (int, float))
                                       or not 0 <= m["epss_percentile_max"] <= 1):
        errs.append(f"{w}.epss_percentile_max：要是 0 到 1 的數字")
    if "include_no_epss" in m and (not isinstance(m["include_no_epss"], bool) or "epss_percentile_max" not in m):
        errs.append(f"{w}.include_no_epss：要是 true／false，而且只配 epss_percentile_max")
    if "kev" in m and m["kev"] is not False:
        errs.append(f"{w}.kev：只能是 false——在 KEV 目錄（CISA、ENISA／EUVD 已遭利用）的列一律不套用規則，要逐列判定")
    if "allow_p1" in m and not isinstance(m["allow_p1"], bool):
        errs.append(f"{w}.allow_p1：要是 true／false")
    w = f"{where}.set"
    st = s.get("state")
    if st in PURL_REQUIRED:
        errs.append(f"{w}.state：規則不能設 {st}。not_affected／false_positive／resolved 要有逐列的證據：發行版覆核（distro-recheck）、"
                    "核心設定檢查（kernel-config），或在 vex-annotations.json 逐個 CVE 加 purl 的判定（vex_export.py annotate）")
    elif st not in RULE_STATES:
        errs.append(f"{w}.state：必填，只能是 {', '.join(RULE_STATES)}")
    resp = s.get("response", [])
    if not isinstance(resp, list) or any(x not in CDX_RESP for x in resp) or len(set(resp)) != len(resp):
        errs.append(f"{w}.response：要是不重複的清單，值只能是 {', '.join(CDX_RESP)}")
    # 規則的 exploitable 可以不寫 response：no fix yet／發行版 won't fix／資料不足這幾類不是「供應商能不能修」，
    # can_not_fix／will_not_fix 會讓客戶誤讀（舊設定檔仍可寫，照常通過）。處理說明改由 detail_template／recommendation 表達
    errs += template_errors(s.get("detail_template"), f"{w}.detail_template")
    if "recommendation" in s:
        if st != "exploitable":
            errs.append(f"{w}.recommendation：只用在 exploitable（OpenVEX 的 action_statement）")
        else:
            errs += template_errors(s["recommendation"], f"{w}.recommendation")
    return errs


def check_rules(doc, path="vex-rules.json"):
    if not isinstance(doc, dict) or doc.get("schema") != RULES_SCHEMA or not isinstance(doc.get("rules"), list):
        raise VexInputError(f"{path}：要是 {{\"schema\": \"{RULES_SCHEMA}\", \"rules\": [...]}}")
    extra = set(doc) - {"schema", "rules", "author", "$comment", "confirmed_by", "confirmed_date"}
    errs = [f"{path}：不認得的鍵 {', '.join(sorted(extra))}"] if extra else []
    if "author" in doc and not isinstance(doc["author"], str):
        errs.append(f"{path}.author：要是文字（所有規則的預設責任人）")
    # 選用：規則整份經誰、哪一天確認（report_package.py 的「判定者／判定日期」用；不影響判定）
    for k in ("confirmed_by", "confirmed_date"):
        if k in doc and (not isinstance(doc[k], str) or not doc[k].strip()):
            errs.append(f"{path}.{k}：要是文字")
    if isinstance(doc.get("confirmed_date"), str) and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", doc["confirmed_date"]):
        errs.append(f"{path}.confirmed_date：要是 YYYY-MM-DD")
    seen = {}
    for i, r in enumerate(doc["rules"]):
        errs += validate_rule(r, f"rules[{i}]")
        if isinstance(r, dict) and "author" not in r and "author" not in doc:
            errs.append(f"rules[{i}].author：沒有責任人；在規則寫 author，或在檔案最上層寫 \"author\"（所有規則的預設）")
        if isinstance(r, dict) and r.get("evidence") and isinstance(r.get("images"), list) and IMAGE_PLACEHOLDER in r["images"]:
            a = r["author"] if isinstance(r.get("author"), str) and r["author"].strip() else doc.get("author", r.get("author"))
            if not author_missing(a):
                # 責任人已填（規則要生效了），適用映像卻還是範例的佔位字
                errs.append(f"rules[{i}].images：還是範例的佔位字 {IMAGE_PLACEHOLDER}；請換成這條規則審過的映像 sha256，"
                            "或刻意寫 [\"*\"]（這個專案的所有映像）")
        rid = r.get("id") if isinstance(r, dict) else None
        if isinstance(rid, str) and rid in seen:
            errs.append(f"rules[{i}].id：和 rules[{seen[rid]}] 相同（{rid}）")
        if isinstance(rid, str):
            seen.setdefault(rid, i)
    if errs:
        raise VexInputError(f"{path} 不符合格式：" + "；".join(errs))
    return doc["rules"]


def author_missing(a):
    return not isinstance(a, str) or not a.strip() or a.strip().casefold() in AUTHOR_PLACEHOLDERS


def effective_rules(doc):
    """每條規則換上實際的責任人（規則的 author ＞ 檔案的 author）；author_missing 記是不是空的或佔位字。不改原本的 doc。"""
    out = []
    for r in doc["rules"]:
        a = r["author"] if isinstance(r.get("author"), str) and r["author"].strip() else doc.get("author", r.get("author"))
        out.append(dict(r, author=(a or "").strip(), author_missing=author_missing(a)))
    return out


def load_rules(project):
    """回傳 (規則清單（effective_rules）, {file, sha256, count, author, without_author} 或 None)。檔案不存在 → ([], None)；
    格式錯（含禁止的狀態、沒有任何責任人）→ VexInputError。"""
    p = Path(project) / RULES_REL
    if not p.is_file():
        return [], None
    raw = p.read_bytes()
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        raise VexInputError(f"{RULES_REL} 不是 JSON：{e}")
    check_rules(doc, str(RULES_REL))
    rules = effective_rules(doc)
    return rules, {"file": str(RULES_REL), "sha256": hashlib.sha256(raw).hexdigest(), "count": len(rules), "author": doc.get("author"),
                   # 證據規則沒有具名責任人時根本不套用（記在證據規則表的 inactive），所以不列在這裡（閘門的 ATTENTION 理由只講「照樣套用了」的規則）
                   "without_author": [r["id"] for r in rules if r["author_missing"] and not r.get("evidence")],
                   "evidence_without_author": [r["id"] for r in rules if r["author_missing"] and r.get("evidence")],
                   "evidence": [r["id"] for r in rules if r.get("evidence")]}


# .config 標頭的 ARCH → 核心的 SRCARCH（同 tools/pilot/lib/kernel_config.py 的 SRCARCH_OF）
KCFG_SRCARCH = {"x86_64": "x86", "i386": "x86", "x86": "x86", "sparc64": "sparc", "sparc32": "sparc", "parisc64": "parisc", "sh64": "sh"}


def kconfig_ikconfig(kcfg):
    """kernel-config.json 是依燒錄核心的內建設定（IKCONFIG）判定的（status ATTENTION，headers .config 和燒錄的核心不同）、
    而且 IKCONFIG 完整 → kernel.config_check；其他 → None。條件全部要成立：config_check.result 是 differs、config_source 是
    "… (IKCONFIG)"、image.ikconfig_complete 是 true、config_sha256 就是 image_config_sha256，而且 config_header（標頭不同時才有）
    的架構相同（產生端在架構不同時記 GAP；這裡再擋一次）。其他原因的 ATTENTION 不採用。"""
    if not isinstance(kcfg, dict) or kcfg.get("schema") != KCFG_SCHEMA or kcfg.get("status") != "ATTENTION":
        return None
    k = kcfg.get("kernel") if isinstance(kcfg.get("kernel"), dict) else {}
    c = k.get("config_check") if isinstance(k.get("config_check"), dict) else {}
    img = c.get("image") if isinstance(c.get("image"), dict) else {}
    sha = k.get("config_sha256")
    hdr = c.get("config_header")
    if hdr is not None:
        h, i = (hdr.get("headers"), hdr.get("image")) if isinstance(hdr, dict) else (None, None)
        if not (isinstance(h, list) and isinstance(i, list) and h and i and h[0] and KCFG_SRCARCH.get(h[0], h[0]) == KCFG_SRCARCH.get(i[0], i[0])):
            return None
    if (c.get("result") == "differs" and str(k.get("config_source") or "").endswith(" (IKCONFIG)") and img.get("ikconfig_complete") is True
            and isinstance(sha, str) and sha and sha == c.get("image_config_sha256")):
        return c
    return None


def kconfig_toolchain_only(kcfg):
    """status OK、config_check.result 是 same_except_toolchain（headers .config 和燒錄核心的 IKCONFIG 只差工具鏈衍生的設定，
    kernel_config.py 已改用 IKCONFIG 判定）→ config_check；其他 → None。只用來寫說明（status OK 本來就採用）；
    說明要和實際用的設定一致，所以同樣要 config_source 是 "… (IKCONFIG)"、IKCONFIG 完整、config_sha256 就是 image_config_sha256。"""
    if not isinstance(kcfg, dict) or kcfg.get("schema") != KCFG_SCHEMA or kcfg.get("status") != "OK":
        return None
    k = kcfg.get("kernel") if isinstance(kcfg.get("kernel"), dict) else {}
    c = k.get("config_check") if isinstance(k.get("config_check"), dict) else {}
    img = c.get("image") if isinstance(c.get("image"), dict) else {}
    sha = k.get("config_sha256")
    if (c.get("result") == "same_except_toolchain" and str(k.get("config_source") or "").endswith(" (IKCONFIG)")
            and img.get("ikconfig_complete") is True and isinstance(sha, str) and sha and sha == c.get("image_config_sha256")):
        return c
    return None


KVERS_SCHEMAS = ("sca-center-kernel-versions/1", "sca-center-kernel-versions/2")      # /2：shipped 是物件清單；not_judged 兩版相同，舊檔照樣讀


def kernel_scope_of(kvers):
    """scan/kernel-versions.json（sca-scan 的 --kernel-version）→ {"judged": [版本], "not_judged": [版本]}；沒有檔案、格式不對、
    或沒有「出貨但沒判定」的核心 → None（沒有範圍限制，輸出和以前相同）。"""
    if not isinstance(kvers, dict) or kvers.get("schema") not in KVERS_SCHEMAS:
        return None
    nj = [x["version"] for x in kvers.get("not_judged") or []
          if isinstance(x, dict) and isinstance(x.get("version"), str) and x.get("shipped") is not False]
    if not nj:
        return None
    return {"judged": [v for v in kvers.get("judged") or [] if isinstance(v, str)], "not_judged": nj}


def kernel_with_scope(doc, kvers):
    """K1／K2 的輸入（scan/kernel-config.json、scan/kernel-module-map.json）只判定了映像出貨的部分核心時，標上 scope_incomplete 與
    scope（judged、not_judged）：這些檔案的排除（not_affected、resolved）只對判定過的核心成立，讀取端（kconfig_usable、module_map_of、
    runtime_evidence）看到 scope_incomplete 就不採用。這是唯一的入口（cra_report 讀完檔案就呼叫）；沒有範圍限制時原樣回傳。"""
    sc = kernel_scope_of(kvers)
    if sc is None or not isinstance(doc, dict):
        return doc
    return dict(doc, scope_incomplete=True, scope=sc)


def kernel_scope_note(doc):
    """被 scope_incomplete 擋下的排除，寫在受影響的列與 VEX 小節的說明；沒有限制 → ""。"""
    sc = (doc or {}).get("scope") if isinstance(doc, dict) and doc.get("scope_incomplete") else None
    if not isinstance(sc, dict):
        return ""
    j, n = ", ".join(sc.get("judged") or []), ", ".join(sc.get("not_judged") or [])
    return (f"Kernel exclusions (K1/K2) are not adopted: {'only kernel ' + j + ' was judged' if j else 'no kernel was judged'}; {n} shipped but "
            f"{'was' if len(sc.get('not_judged') or []) == 1 else 'were'} not judged, so an exclusion does not apply to the whole product "
            f"({'只判定了核心 ' + j if j else '沒有判定任何核心'}；{n} 已出貨、未判定，排除不適用整個產品)")


def kconfig_usable(kcfg):
    """讀取端採用 kernel-config.json 的結果：status OK，或依完整的 IKCONFIG 判定的 ATTENTION（kconfig_ikconfig）。
    scope_incomplete（映像另有出貨但沒判定的核心，kernel_with_scope）→ 不採用。"""
    return (isinstance(kcfg, dict) and kcfg.get("schema") == KCFG_SCHEMA and not kcfg.get("scope_incomplete")
            and (kcfg.get("status") == "OK" or kconfig_ikconfig(kcfg) is not None))


def kconfig_all(kcfg):
    """kernel-config.json（kconfig_usable）→ {CVE: decision}（affected、unknown、not_affected 全部）。"""
    if not kconfig_usable(kcfg):
        return {}
    return {str(x["cve"]).upper(): x.get("decision") for x in kcfg.get("results") or []
            if isinstance(x, dict) and isinstance(x.get("cve"), str)}


def kconfig_decision(row, kall, kcfg):
    """這一列（核心、而且是 kernel-config.json 檢查的那個核心）的核心設定結果：每個 CVE 都要有結果，有一個 affected 就是 affected，
    否則有 unknown 就是 unknown；其他（不是核心的列、別的核心、有 CVE 沒檢查）→ None（規則的 kernel_config 條件不成立）。"""
    if not row.get("kernel") or not kall or not kconfig_component_matches(row, kcfg or {}):
        return None
    ds = [kall.get(c.upper()) for c in row.get("cves") or []]
    if not ds or None in ds:
        return None
    return "affected" if "affected" in ds else "unknown" if "unknown" in ds else "not_affected"


def on_kev(row, exploited=frozenset()):
    """在 KEV 目錄：DT 的 isKev（CISA、ENISA KEV），或 scan/euvd.json 標示已遭利用（有這個檔案時）。拆出來的 CVE 沿用整列的 KEV（偏保守）。"""
    return bool(row.get("kev")) or any(c.upper() in exploited for c in (row.get("cves") or [row.get("id") or ""]))


def euvd_sources(row):
    """cra_report 標上的 EUVD 被利用標記（row["exploited_sources"] 裡 EUVD 開頭的，例如 EUVD (CISA KEV)；兩種分級方式都有，
    scan/euvd.json 的 status 是 OK 時）。"""
    return [str(x) for x in row.get("exploited_sources") or [] if str(x).startswith("EUVD")]


def on_euvd(row):
    return bool(euvd_sources(row))


def exploited_row(row):
    """已遭利用：KEV（row["kev"]）、EUVD 或人工證據（row["exploited_sources"]，含 "manual: …"）。和 cra_report.exploited 同一個判斷。"""
    return bool(row.get("kev") or row.get("exploited_sources"))


def rule_criteria(rule, row, kdec):
    """match 的條件（全部要成立）。KEV、P1、範本缺值不在這裡（由 apply_rules 計數）。"""
    m = rule["match"]
    if m["scope"] == "kernel" and not row.get("kernel") or m["scope"] == "non_kernel" and row.get("kernel"):
        return False
    if "purl_prefix" in m:
        base = purl_split(row.get("purl"))[0] or ""
        if not any(base.startswith(p.lower()) for p in m["purl_prefix"]):
            return False
    if "purl_type" in m and purl_type(row.get("purl")) not in m["purl_type"]:
        return False
    if "fix_state" in m and row.get("fix_state") not in m["fix_state"]:
        return False
    if "kernel_config" in m and kdec not in m["kernel_config"]:
        return False
    if "tier" in m and row.get("tier") not in m["tier"]:
        return False
    if "severity" in m and str(row.get("severity") or "").upper() not in {s.upper() for s in m["severity"]}:
        return False
    if "epss_percentile_max" in m:
        e = row.get("epss_pct")
        if e is None:
            return bool(m.get("include_no_epss"))
        if e > m["epss_percentile_max"]:
            return False
    return True


def template_values(row, ctx):
    k = (ctx or {}).get("kernel_fix_all") or {}
    return {"fix_version": row.get("fix_next"), "installed_version": row.get("version"), "component": row.get("component"),
            "kernel_fix_all": k.get(row.get("component")) if row.get("kernel") else None, "cve": row.get("id")}


def render_template(t, vals):
    """缺任何一個用到的值 → None（這條規則不套用在這一列）。"""
    need = {f for _, f, _, _ in string.Formatter().parse(t) if f}
    if any(vals.get(f) in (None, "") for f in need):
        return None
    return t.format_map({f: str(vals[f]) for f in need}).strip()


def new_rule_stats(rules):
    return [{"id": r["id"], "applied": 0, "kernel": 0, "non_kernel": 0, "shadowed": Counter(), "excluded_kev": 0, "excluded_p1": 0, "excluded_deb_python": 0,
             "inherited_deb_python": 0,
             "template_missing": 0, "rows": [], "dp_excluded_rows": []} for r in rules]


def apply_rules(row, rules, stats, existing, kdec, ctx, exploited=frozenset()):
    """依檔案順序找第一條條件成立的規則（rule_criteria）。這一列已有判定（人的判定或逐列的證據）→ 記在那條規則的 shadowed，不套用；
    在 KEV 目錄 → excluded_kev，任何規則都不套用；Debian／Ubuntu 打包的 Python 模組（cra_report 的 row["deb_python"]）→ excluded_deb_python，
    這裡不套用（它的 pypi 類型與 PyPI 的修補資料不代表 Ubuntu 套件；之後由 deb_python_rules 沿用擁有它的 deb 列的規則判定或以擁有者套用）；
    P1 而規則沒有 allow_p1 → excluded_p1，換下一條；範本缺值 → template_missing，換下一條。
    NVIDIA 公告另加的列（tier nvidia_bulletin，沒有 Grype、DT 的資料）一律不套用、不計數。回傳規則的判定或 None。"""
    if is_nv_bulletin_row(row):
        return None
    for ru, st in zip(rules, stats):
        if not rule_criteria(ru, row, kdec):
            continue
        if existing:
            st["shadowed"][existing["source"]] += 1
            return None
        if on_kev(row, exploited):
            st["excluded_kev"] += 1
            return None
        if row.get("deb_python"):
            st["excluded_deb_python"] += 1
            st["dp_excluded_rows"].append(row)       # deb_python_rules 之後沿用或以擁有者套用時，這一列就不算排除（每一列只算一次）
            return None
        if (row.get("tier") == "p1" or row.get("tier_before") == "p1") and not ru["match"].get("allow_p1"):
            st["excluded_p1"] += 1
            continue
        vals = template_values(row, ctx)
        s = ru["set"]
        det = render_template(s["detail_template"], vals)
        rec = render_template(s["recommendation"], vals) if s.get("recommendation") else None
        if det is None or (s.get("recommendation") and rec is None):
            st["template_missing"] += 1
            continue
        st["applied"] += 1
        st["kernel" if row.get("kernel") else "non_kernel"] += 1
        st["rows"].append(row)
        tag = f"(bulk rule {ru['id']}: {ru['description'].strip()})"
        # 修補狀態不是 Grype 的（cra_report.apply_ubuntu_tracker：Ubuntu CVE Tracker）而規則看修補狀態 → 陳述寫出處
        fsd = str(row.get("fix_state_detail") or "") if "fix_state" in ru["match"] else ""
        if fsd:
            det = f"{det} {fsd[:1].upper()}{fsd[1:]}."
        return stmt("rule", s["state"], f"{det} {tag}", response=s.get("response") or (), rule=ru["id"], rule_author=ru.get("author"),
                    action_statement=f"{rec} {tag}" if rec else None)
    return None


def rule_summary(rules, stats, samples=5):
    """每條規則的統計（summary.json、文件、rules check）：套用的列數、被其他判定蓋過、因 KEV／P1 排除、範本缺值，與優先順序最高的幾列。"""
    out = []
    for ru, st in zip(rules, stats):
        rows = sorted(st["rows"], key=priority_key)
        out.append({"id": ru["id"], "description": ru["description"], "author": ru.get("author") or "",
                    "author_missing": author_missing(ru.get("author")), "date": ru["date"], "reason": ru["reason"],
                    "state": ru["set"]["state"], "response": list(ru["set"].get("response") or []), "match": ru["match"],
                    "applied": st["applied"], "kernel": st["kernel"], "non_kernel": st["non_kernel"],
                    "shadowed": {k: st["shadowed"][k] for k in SHADOW_KEYS if st["shadowed"][k]}, "excluded_kev": st["excluded_kev"],
                    "excluded_p1": st["excluded_p1"], "excluded_deb_python": st["excluded_deb_python"],
                    "inherited_deb_python": st["inherited_deb_python"], "template_missing": st["template_missing"],
                    "sample": [{"id": r["id"], "component": r.get("component"), "version": r.get("version"), "tier": r.get("tier"),
                                "fix_state": r.get("fix_state"), "severity": r.get("severity"), "epss_percentile": r.get("epss_pct"),
                                "kernel": bool(r.get("kernel")), "detail": r["vex"]["detail"] if r.get("vex") else None}
                               for r in rows[:samples]]})
    return out


# ---------- 證據規則的輸入 ----------

def norm_image(x):
    """映像識別（sha256:<hex>、<hex>）→ 小寫 64 位十六進位；不是 → None。"""
    m = IMAGE_RE.match(str(x or "").strip().lower())
    return m.group(1) if m else None


def norm_module(x):
    """模組名稱 → 比對用的名稱：去掉路徑與 .ko[.xz|.zst|.gz]，- 與 _ 視為相同（modprobe 的規則）。"""
    n = str(x or "").strip().rsplit("/", 1)[-1]
    n = re.sub(r"\.ko(?:\.(?:xz|zst|gz))?$", "", n)
    return n.replace("-", "_")


def _str_items(v, where, allow_empty=True):
    if not isinstance(v, list) or any(not isinstance(x, str) or not x.strip() for x in v) or (not allow_empty and not v):
        return [f"{where}：要是{'不是空的' if not allow_empty else ''}文字清單"]
    return []


def check_kernel_modules(doc, path=str(KMOD_REL)):
    """CRA/Config/kernel-modules.json（K2 的輸入：映像裡的模組與載入限制；README「K2 的輸入」）。格式錯 → VexInputError。"""
    if not isinstance(doc, dict) or doc.get("schema") != KMOD_SCHEMA:
        raise VexInputError(f"{path}：要是 {{\"schema\": \"{KMOD_SCHEMA}\", ...}}")
    errs = [f"{path}.{k}：不認得的鍵" for k in sorted(set(doc) - KMOD_KEYS)]
    if not norm_image(doc.get("image_sha256")):
        errs.append(f"{path}.image_sha256：必填，清單取自的映像（sha256:<64 個十六進位字元>）")
    for k in ("kernel_version", "source"):
        if not isinstance(doc.get(k), str) or not doc[k].strip():
            errs.append(f"{path}.{k}：必填（文字）")
    if author_missing(doc.get("owner")):
        errs.append(f"{path}.owner：必填（負責人的名字，不是佔位字）")
    c = doc.get("captured")
    if not isinstance(c, str) or not DATE_RE.match(c):
        errs.append(f"{path}.captured：必填（YYYY-MM-DD）")
    else:
        try:
            datetime.date.fromisoformat(c)
        except ValueError:
            errs.append(f"{path}.captured：必填（YYYY-MM-DD）")
    # 空的模組清單不收：K2 會把它當成「所有模組都移除了」
    errs += _str_items(doc.get("modules_in_image"), f"{path}.modules_in_image", allow_empty=False)
    # modules_outside_dirs（可以不寫或 null）：模組資料夾以外的 .ko（映像裡的絕對路徑，insmod 可以載入）。K2 不判同名的模組「已移除」；
    # 不參與和對應表 modules_present 的矛盾檢查（對應表只看模組資料夾）
    if doc.get("modules_outside_dirs") is not None:
        e = _str_items(doc["modules_outside_dirs"], f"{path}.modules_outside_dirs")
        errs += e or [f"{path}.modules_outside_dirs：{x[:80]} 要是映像裡的絕對路徑（/ 開頭）"
                      for x in doc["modules_outside_dirs"] if not x.strip().startswith("/")][:3]
    # modules_builtin：null＝沒有收（不知道哪些編進核心，K2 不判「已移除」）；有收就不能是空的（核心一定有 modules.builtin）
    if "modules_builtin" not in doc:
        errs.append(f"{path}.modules_builtin：必填（modules.builtin 的清單；沒有收就寫 null）")
    elif doc["modules_builtin"] is not None:
        errs += _str_items(doc["modules_builtin"], f"{path}.modules_builtin", allow_empty=False)
    errs += _str_items(doc.get("modprobe_d"), f"{path}.modprobe_d")
    # modules_softdep：depmod 的 modules.softdep 的行，第一行一定是 depmod 寫的標頭（貼錯檔、空的清單 → 格式錯，不會被當成「沒有 softdep」）；
    # 沒有收寫 null 或不寫（K2 就不認 install 的「被擋」）
    if doc.get("modules_softdep") is not None:
        e = _str_items(doc["modules_softdep"], f"{path}.modules_softdep", allow_empty=False)
        errs += e or ([] if str(doc["modules_softdep"][0]).strip() == SOFTDEP_HEADER else
                      [f"{path}.modules_softdep：第一行要是 depmod 的標頭「{SOFTDEP_HEADER}」（modules.softdep 的原始行）"])
    # true／false／null 要是真的布林（JSON 的 1、0、1.0 不算）
    if doc.get("modules_disabled") is not None and not isinstance(doc["modules_disabled"], bool):
        errs.append(f"{path}.modules_disabled：要是 true、false 或 null（不知道）")
    if doc.get("loaded") is not None:
        # 空的載入清單不收：不知道就寫 null（[] 會被當成「什麼都沒載入」）
        e = _str_items(doc["loaded"], f"{path}.loaded", allow_empty=False)
        errs += e
        if not e and not _str_items(doc.get("modules_in_image"), "x", allow_empty=False):
            # 有載入、卻不在映像的模組清單裡：清單互相矛盾（多半是取自不同的映像或核心）
            present = {norm_module(m) for m in doc["modules_in_image"]}
            if isinstance(doc.get("modules_outside_dirs"), list):
                present |= {norm_module(m) for m in doc["modules_outside_dirs"] if isinstance(m, str)}
            bad = sorted({norm_module(m) for m in doc["loaded"]} - present)
            if bad:
                errs.append(f"{path}.loaded：{', '.join(bad[:5])}{' …' if len(bad) > 5 else ''} 有載入，卻不在 modules_in_image"
                            "（或 modules_outside_dirs）（兩份清單互相矛盾）")
    if errs:
        raise VexInputError(f"{path} 不符合格式：" + "；".join(errs))
    return doc


def load_kernel_modules(project):
    """回傳 (文件, {file, sha256, image, kernel_version}) 或 (None, None)。格式錯 → VexInputError。"""
    p = Path(project) / KMOD_REL
    if not p.is_file():
        return None, None
    raw = p.read_bytes()
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        raise VexInputError(f"{KMOD_REL} 不是 JSON：{e}")
    check_kernel_modules(doc)
    return doc, {"file": str(KMOD_REL), "sha256": hashlib.sha256(raw).hexdigest(), "image": norm_image(doc["image_sha256"]),
                 "kernel_version": doc["kernel_version"], "captured": doc["captured"], "owner": doc["owner"]}


def kmod_pattern(p):
    """install／softdep 行的模組名稱 → kmod 比對用的樣式，或 None（不確定）。
    kmod 的 underscores() 把 - 換成 _；比對用 libc 的 fnmatch(…, 0)。有中括號時 Python 的 fnmatchcase 和 libc 不一致
    （[^…] 否定、POSIX 類別 [[:lower:]]、[[=s=]]、[[.s.]]、反向或以 - 結尾的範圍、[]_[=] 等，以真實的 modprobe 對照過），
    kmod 也會整行拒收不成對的中括號 → 樣式裡只要有 [ 或 ]，一律當作不確定（install 與 softdep 都不算被擋）。
    沒有中括號的樣式（*、?、一般字元）和 libc 一致（反斜線另外在 modprobe_lines 處理）。"""
    p = str(p)
    if "[" in p or "]" in p or "\\" in p:
        return None
    return p.replace("-", "_")


def modprobe_lines(lines):
    """modprobe.d 的原始行 → (欄位清單的清單, 有沒有反斜線)。欄位只用空白與 tab 分開（kmod 的 strtok_r；NBSP 等其他空白不是分隔），
    # 開頭的是註解。kmod 讀檔時處理反斜線（行尾的續行、其他位置的 \\X → X），而且續行不跨檔、遇空行結束——這份清單表達不出檔案與空行的
    界線，所以**只要有任何反斜線**，呼叫端就不認 install 的「被擋」（不模擬 kmod 的反斜線規則，偏保守）。"""
    out, bs = [], False
    for ln in lines or ():
        t = str(ln)
        if t.endswith("\r\n"):
            t = t[:-2]
        elif t.endswith(("\r", "\n")):
            t = t[:-1]
        if "\\" in t or "\n" in t or "\r" in t:
            # 反斜線，或一個元素裡夾了換行或 CR（kmod 讀檔時是兩行，或 CR 是名稱的一部分）：不認 install 的「被擋」
            bs = True
            continue
        f = [x for x in t.replace("\t", " ").split(" ") if x]
        if f and not f[0].startswith("#"):
            out.append(f)
    return out, bs


def modprobe_state(lines):
    """modprobe.d 的行 → ({黑名單的模組}, [(樣式或 None, 指令, 原文), …] 依生效順序, [softdep 的樣式或 None, …])。
    kmod 的規則：install 的模組名稱是 fnmatch 樣式（例如 `install usb* …`），**第一條**符合的 install 生效。所以 install_block 只看第一條
    符合的那一行：它是 /bin/false 之類什麼都不做的指令才算被擋；前面一條 `install foo* <真的指令>` 會讓後面的 `install foo /bin/true` 失效。
    blacklist 是完全相同的名稱（只擋 alias 自動載入，K2 不當作被擋）。softdep 另外收（install_block 用）。原文寫進 K2 的 rule_inputs 與說明。
    同名檔的覆蓋與檔案順序不在這裡處理：清單的順序就是生效順序（README）。"""
    bl, inst, soft = set(), [], []
    fields, bs = modprobe_lines(lines)
    if bs:
        # 有反斜線：kmod 看到的行可能不同（關鍵字、樣式、續行），install 一律不算被擋
        soft.append(None)
    for f in fields:
        if f[0] == "blacklist" and len(f) >= 2:
            bl.add(norm_module(f[1]))
        elif f[0] == "install" and len(f) >= 3:
            inst.append((kmod_pattern(f[1]), " ".join(f[2:]), " ".join(f)))
        elif f[0] == "softdep" and len(f) >= 2:
            soft.append(kmod_pattern(f[1]))
    return bl, inst, soft


def install_block(m, installs, softdeps=None):
    """模組 m（正規化後的名稱）→ 擋住它的那一行原文，或 None。
    - 第一條 fnmatch 符合的 install 是什麼都不做的指令才算；前面有不確定的樣式（kmod 可能比對成別的結果）→ 不算。
    - kmod v34 以前（所有已發布版本到 2026-11）：模組只要有 softdep（modprobe.d 的 softdep 行或 depmod 的 modules.softdep），
      install 指令就被略過、直接 insmod（kmod commit 7e46311 才修）。所以 softdeps 是 None（沒有收 modules.softdep）、
      或這個模組有 softdep（樣式不確定也算有）→ 不算被擋。"""
    if softdeps is None or any(p is None or fnmatch.fnmatchcase(m, p) for p in softdeps):
        return None
    for pat, cmd, line in installs or ():
        if pat is None:
            return None
        if fnmatch.fnmatchcase(m, pat):
            return line if cmd in BLOCK_CMDS else None
    return None


def module_map_of(doc):
    """scan/kernel-module-map.json（K2–K4 的輸入：每個核心 CVE 修補動到的程式在哪些模組；README「K2 的輸入」）→ (文件, 問題)。
    這是掃描產生的檔案：格式不對時不 FAIL，當作沒有（K4），問題寫進報告。格式不對的單筆 CVE 當作對不到。"""
    if doc is None:
        return None, "no scan/kernel-module-map.json (the CVE-to-module mapping, line B: Kbuild module mapping)"
    if not isinstance(doc, dict) or doc.get("schema") != MODMAP_SCHEMA or not isinstance(doc.get("cves"), dict):
        return None, f"scan/kernel-module-map.json is not {MODMAP_SCHEMA}"
    if doc.get("status") != "OK":
        return None, f"scan/kernel-module-map.json has status {doc.get('status')!r}"
    if doc.get("scope_incomplete"):
        return None, "scan/kernel-module-map.json covers only part of the kernels shipped in the image (" + kernel_scope_note(doc) + ")"
    if not isinstance((doc.get("kernel") or {}).get("version"), str) or not isinstance(doc.get("component"), dict):
        return None, "scan/kernel-module-map.json has no kernel.version or component"
    return doc, None


def module_names(v):
    """對應表最上層的 modules_order／modules_builtin（正規化後的名稱清單）→ 名稱集合；不是文字清單（含 null、沒有這個鍵）→ None。"""
    if not isinstance(v, list) or any(not isinstance(m, str) or not m.strip() for m in v):
        return None
    return {norm_module(m) for m in v}


def module_entry(mm, cve):
    """一個 CVE 的對應：{"modules": [...], "builtin": bool}；沒有、格式不對、builtin 不是 true／false、或沒編進核心也沒有模組 → None（對不到）。"""
    e = (mm.get("cves") or {}).get(cve)
    if not isinstance(e, dict) or not isinstance(e.get("builtin"), bool):        # JSON 的 0／1 不算布林
        return None
    mods = e.get("modules")
    if not isinstance(mods, list) or any(not isinstance(m, str) or not m.strip() for m in mods):
        return None
    if e["builtin"] is False and not mods:
        return None
    # 逐檔的證據（B 線③ 的 files：[{path, build: builtin|module|not_built|unknown, …}]）只用來在說明裡多寫一句「另有 N 個檔沒編」；
    # 沒有或格式不對 → None（不寫那一句，判定不受影響）
    fl = e.get("files")
    nb = None
    if isinstance(fl, list) and fl and all(isinstance(f, dict) and isinstance(f.get("path"), str) and f["path"].strip()
                                           and isinstance(f.get("build"), str) for f in fl):
        if e["builtin"] is False and any(f["build"] not in ("module", "not_built") for f in fl):
            # 同一筆裡的逐檔證據說有檔案編進核心、不知道，或 build 是約定以外的值（拼錯也算），卻寫 builtin: false：
            # 對應表自相矛盾，當作對不到（K4，偏保守），說明寫出是矛盾、不是沒有對應
            return {"inconsistent": sorted({f["build"][:40] for f in fl if f["build"] not in ("module", "not_built")})}
        nb = sorted({f["path"] for f in fl if f["build"] == "not_built"})
    return {"modules": sorted({norm_module(m) for m in mods}), "builtin": e["builtin"], "not_built": nb}


def ubuntu_status_of(doc):
    """scan/ubuntu-status.json（sca-scan 的 D-ubuntu-status，tools/pilot/lib/ubuntu_status.py）→ (文件, 問題)；status 不是 OK → (None, 原因)。"""
    if doc is None:
        return None, "no scan/ubuntu-status.json (D-ubuntu-status did not run: no Ubuntu CVE Tracker mirror, or no Ubuntu packages)"
    if not isinstance(doc, dict) or doc.get("schema") != USTATUS_SCHEMA or not isinstance(doc.get("entries"), dict) \
            or not isinstance(doc.get("components"), dict):
        return None, f"scan/ubuntu-status.json is not {USTATUS_SCHEMA}"
    if doc.get("status") != "OK":
        return None, f"scan/ubuntu-status.json has status {doc.get('status')!r}: {doc.get('detail') or ''}".strip()
    def entry(e):
        return isinstance(e, dict) and isinstance(e.get("status"), str) and isinstance(e.get("note", ""), str)
    if not all(isinstance(c, dict) and all(isinstance(c.get(k), str) or c.get(k) is None for k in ("source", "source_version", "release"))
               for c in doc["components"].values()) \
            or not all(isinstance(p, dict) and all(isinstance(r, dict) and all(entry(e) for e in r.values()) for r in p.values())
                       for p in doc["entries"].values()) \
            or not isinstance(doc.get("mirror") or {}, dict) or not isinstance(doc.get("cve_info") or {}, dict) \
            or not all(isinstance(x, dict) for x in (doc.get("cve_info") or {}).values()) \
            or not isinstance(doc.get("other_releases") or {}, dict) \
            or not all(isinstance(p, dict) and all(isinstance(r, dict) and all(entry(e) for e in r.values()) for r in p.values())
                       for p in (doc.get("other_releases") or {}).values()):
        return None, f"scan/ubuntu-status.json is malformed (components, entries or cve_info are not in the {USTATUS_SCHEMA} shape)"
    return doc, None


def evidence_view(row):
    """判定函式只看得到產物的欄位（EVIDENCE_VIEW_KEYS）：嚴重度、EPSS、CVSS、層級、KEV 在結構上就進不去。"""
    out = {k: copy.deepcopy(row.get(k)) for k in EVIDENCE_VIEW_KEYS if k != "deb_python"}
    dp = row.get("deb_python")
    out["deb_python"] = {k: copy.deepcopy(dp.get(k)) for k in DEB_PYTHON_VIEW_KEYS} if isinstance(dp, dict) else None
    return out


def evidence_context(kcfg, ctx):
    """assess 一次準備好的證據輸入（每次產生文件都重新讀、重新判定：輸入改變，結果跟著變，沒有快取）。"""
    ctx = ctx or {}
    mm, mm_problem = module_map_of(ctx.get("module_map"))
    us, us_problem = ubuntu_status_of(ctx.get("ubuntu_status"))
    km, kmi = ctx.get("kernel_modules"), ctx.get("kernel_modules_info") or {}
    images = {norm_image(x) for x in ctx.get("image_ids") or ()} - {None}
    km_problem = None
    if km is None:
        km_problem = f"no {KMOD_REL} (modules in the image and load restrictions)"
    elif kmi.get("image") not in images:
        # 清單取自別的映像（或掃描沒有映像雜湊）：過期的輸入，不用
        km_problem = f"{KMOD_REL} was taken from image sha256:{str(kmi.get('image'))[:12]}…, not from the scanned image"
    elif mm is not None and km.get("kernel_version") != mm["kernel"]["version"]:
        km_problem = f"{KMOD_REL} is for kernel {km.get('kernel_version')}, the module map for {mm['kernel']['version']}"
    if km_problem is None:
        bl, blocked, soft = modprobe_state(km.get("modprobe_d"))
        # 模組的 softdep：modprobe.d 的 softdep 行，加上 depmod 的 modules.softdep（`softdep <模組> pre: …`）。
        # modules.softdep 沒有收 → None（install 的「被擋」不認）
        msd = km.get("modules_softdep")
        if msd is None or not msd or str(msd[0]).strip() != SOFTDEP_HEADER:
            # 沒有收，或不是 modules.softdep（直接給 rule_ctx 的呼叫端也一樣；正式流程由 check_kernel_modules 擋）
            soft = None
        else:
            mf, mbs = modprobe_lines(msd)
            soft = soft + [kmod_pattern(f[1]) for f in mf if f[0] == "softdep" and len(f) >= 2] + ([None] if mbs else [])
        # present：模組資料夾（與 initramfs）的模組，和對應表的 modules_present 比；outside：模組資料夾以外的 .ko（名稱 → 路徑），只用來不判「已移除」
        outside = {}
        for x in km.get("modules_outside_dirs") or []:
            outside.setdefault(norm_module(x), x)
        kms = {"present": {norm_module(m) for m in km["modules_in_image"]}, "outside": outside, "builtin": None if km.get("modules_builtin") is None else {norm_module(m) for m in km["modules_builtin"]},
               "blacklist": bl, "installs": blocked, "softdeps": soft, "modules_disabled": km.get("modules_disabled") is True,
               # 空的載入清單當作不知道（驗證本來就不收 []；這裡防直接給 rule_ctx 的呼叫端）
               "loaded": {norm_module(m) for m in km["loaded"]} if km.get("loaded") else None, "sha256": kmi.get("sha256")}
    else:
        kms = None
    k = (kcfg or {}).get("kernel") or {} if isinstance(kcfg, dict) else {}
    srcs = (mm or {}).get("sources") if isinstance((mm or {}).get("sources"), dict) else {}
    return {"kidx": kconfig_index(kcfg), "kcfg": kcfg if isinstance(kcfg, dict) else {}, "kcfg_sha": k.get("config_sha256"),
            "mm": mm, "mm_problem": mm_problem, "km": kms, "km_problem": km_problem,
            # 這個核心建置的 modules.order／modules.builtin（對應表最上層，B 線③）：已移除的模組必須是這個建置真的有的模組
            "mm_order": module_names((mm or {}).get("modules_order")), "mm_builtin": module_names((mm or {}).get("modules_builtin")),
            # 整個 /usr/lib/modules/<版本>/ 底下（含 updates/、extra/）所有 .ko 的名稱（B 線③；沒有時 null）：「已移除」的第二道檢查
            "mm_present": module_names((mm or {}).get("modules_present")),
            # modules_present 不是清單（null：模組資料夾不完整或讀不到）、或 modules_present_gaps 不是空的 → 第二道檢查做不了，不判「已移除」
            "mm_present_problem": present_problem(mm),
            "mm_order_sha": srcs.get("modules_order_sha256") if isinstance(srcs.get("modules_order_sha256"), str) else None,
            "mm_sha": ctx.get("module_map_sha256"),
            "us": us, "us_problem": us_problem,
            "images": images, "today": ctx.get("today"), "vercmp": ctx.get("vercmp")}


# ---------- 證據規則的判定（只看 evidence_view 與產物） ----------

def ev_k1(v, ec):
    """K1：kernel-config.json（status OK、同一個核心）每個 CVE 都是 not_affected。"""
    if not v["kernel"]:
        return None
    s = from_kconfig(v, ec["kidx"], ec["kcfg"])
    if not s:
        return None
    return {"decision": "not_affected", "justification": "code_not_present", "detail": s["detail"],
            "inputs": f"kernel {'IKCONFIG' if kconfig_ikconfig(ec['kcfg']) or kconfig_toolchain_only(ec['kcfg']) else '.config'} SHA-256 {str(ec['kcfg_sha'] or '?')[:12]}",
            "basis": [kcfg_basis(ec["kcfg"])]}


def present_problem(mm):
    """對應表的 modules_present 能不能當「已移除」的第二道檢查 → 問題（文字）或 None。
    要是名稱清單，而且 modules_present_gaps 沒有或是空的清單；null、沒有這個鍵、格式不對、有 gaps → 不能（不知道）。"""
    if mm is None:
        return None
    if module_names(mm.get("modules_present")) is None:
        return "modules_present is missing or null (the module tree could not be read completely)"
    g = mm.get("modules_present_gaps")
    if g is not None and (not isinstance(g, list) or g):
        return "modules_present_gaps: " + (", ".join(str(x) for x in g[:3]) if isinstance(g, list) else "not a list")[:200]
    return None


def kconfig_only_these_modules(res, mods):
    """kernel-config.json 的一筆 affected 結果，有編的檔案是不是**全部** built_as == "module" 而且 module 在 mods 裡（正規化後比）。
    沒有 files、沒有任何有編的檔、有一個是 builtin／null（不知道）、module 是 null 或不在 mods → False（照樣列衝突）。"""
    fl = res.get("files")
    if not isinstance(fl, list) or any(not isinstance(f, dict) or not any(f.get("built") is x for x in (True, False, None)) for f in fl):
        # 格式不對（不是 dict、built 不是 true／false／null）：不能確定，照樣列衝突
        return False
    built = [f for f in fl if f.get("built") is True]
    return bool(built) and all(f.get("built_as") == "module" and isinstance(f.get("module"), str) and f["module"].strip()
                               and norm_module(f["module"]) in mods for f in built)


def ev_k2(v, ec):
    """K2：修補動到的程式只在模組裡（對應表 builtin false），每個模組都已移除或被禁止載入。沒套用時回傳 K3／K4 標記。"""
    if not v["kernel"]:
        return None
    mm = ec["mm"]
    if mm is None:
        return {"marker": "K4", "detail": f"not mapped to a kernel module: {ec['mm_problem']}; treated as built into the kernel (affected)"}
    if not kconfig_component_matches(v, mm):
        return {"marker": "K4", "detail": "the module map is for another kernel component; treated as built into the kernel (affected)"}
    ents = {c: module_entry(mm, c.upper()) for c in v["cves"] or []}
    if not ents:
        # 沒有 CVE 編號的核心列（例如只有 GHSA、OSV 的編號）：對應表以 CVE 為鍵，對不到
        return {"marker": "K4", "detail": "the row has no CVE ID, so it cannot be mapped to a kernel module; treated as built into the kernel (affected)"}
    miss = sorted(c for c, e in ents.items() if e is None)
    if miss:
        return {"marker": "K4", "detail": f"no module mapping for {', '.join(miss)}; treated as built into the kernel (affected)"}
    bad = sorted(c for c, e in ents.items() if "inconsistent" in e)
    if bad:
        return {"marker": "K4", "detail": f"the module map contradicts itself for {', '.join(bad)} (builtin false, but per-file build "
                                          f"{', '.join(sorted({b for c in bad for b in ents[c]['inconsistent']}))}); treated as built into the kernel (affected)"}
    if any(e["builtin"] for e in ents.values()):
        return {"not_applied": "built_in", "detail": "the fix changes code built into the kernel"}
    mods = sorted({m for e in ents.values() for m in e["modules"]})
    # 建置的 modules.builtin 有它：編進核心（受影響，不是 GAP）；再來名稱必須在建置的 modules.order 裡（打錯字、別的核心的名稱 → K4）
    inb = [m for m in mods if ec["mm_builtin"] and m in ec["mm_builtin"]]
    if inb:
        return {"not_applied": "built_in", "detail": f"{', '.join(inb)} is listed in modules.builtin of the kernel build (built into the kernel)"}
    if ec["mm_order"] is None:
        return {"marker": "K4", "detail": "the module map has no modules.order of this kernel build (modules_order), so the module names "
                                          "cannot be confirmed; treated as built into the kernel (affected)"}
    unknown = [m for m in mods if m not in ec["mm_order"]]
    if unknown:
        return {"marker": "K4", "detail": f"{', '.join(unknown[:5])}{', …' if len(unknown) > 5 else ''} not in modules.order of this kernel "
                                          "build, so not confirmed as a module; treated as built into the kernel (affected)"}
    km = ec["km"]
    if km is None:
        return {"marker": "K3", "detail": f"built as module {', '.join(mods[:5])}; module state unknown ({ec['km_problem']}): counted as loadable"}
    removed, blocked, loadable, block_lines = [], [], [], []
    for m in mods:
        if km["builtin"] is not None and m in km["builtin"]:
            return {"not_applied": "built_in", "detail": f"{m} is listed in modules.builtin of the image (built into the kernel)"}
        ib = install_block(m, km["installs"], km.get("softdeps"))
        loaded = km["loaded"] is not None and m in km["loaded"]
        not_loaded = km["loaded"] is not None and m not in km["loaded"]
        if loaded:
            # 有載入：一定受影響，不看其他清單（檢查順序在「已移除」之前）
            loadable.append(f"{m} (loaded)")
        elif m not in km["present"] and m in (km.get("outside") or {}):
            # 模組資料夾以外有同名的 .ko（例如 /opt/vendor/x.ko）：insmod 可以載入，不判「已移除」
            loadable.append(f"{m} (not in the module directory, but a .ko with this name exists outside the modules directory: "
                            f"{str(km['outside'][m])[:120]}; counted as present)")
        elif m not in km["present"] and km["builtin"] is not None and ec["mm_present"] is not None and m in ec["mm_present"]:
            # 映像清單沒有、對應表的 modules_present 卻有同名的 .ko（例如 NVIDIA 放在 updates/ 的模組）：兩份清單矛盾，當作還在
            loadable.append(f"{m} (not in {KMOD_REL.name}, but the module map's modules_present has a .ko with this name, e.g. under "
                            "updates/ or extra/: counted as present)")
        elif m not in km["present"] and km["builtin"] is not None and (ec["mm_present_problem"] or (ec["mm_present"] is not None and km["present"] - ec["mm_present"])):
            # 第二道檢查（對應表的 modules_present）做不了：不知道映像裡別處（updates/、extra/、資料夾連結）有沒有同名的 .ko
            # 或兩份清單矛盾：kernel-modules.json 有、modules_present 卻沒有的名稱（modules_present 漏列，可能也漏了 m）
            why = ec["mm_present_problem"] or ("modules_present lacks " + ", ".join(sorted(km["present"] - ec["mm_present"])[:3])
                                               + f" listed in {KMOD_REL.name}")
            loadable.append(f"{m} (not in {KMOD_REL.name}, but the module map cannot confirm it is absent: {why})")
        elif m not in km["present"] and km["builtin"] is not None:
            # 「已移除」要正面的證據：對應表說它是模組（builtin false）、modules.builtin 有收而且沒有它、模組清單裡也沒有它
            # （比的是正規化後的名稱，不是路徑：updates/、extra/ 底下同名的 .ko 也算還在）
            removed.append(m)
        elif m not in km["present"]:
            loadable.append(f"{m} (not in the image's module list, but modules.builtin was not captured: it may be built in)")
        elif ib and not_loaded:
            blocked.append(f"{m} (modprobe.d: {ib[:200]}; not loaded)")
            block_lines.append(ib)
        elif km["modules_disabled"] is True and not_loaded:
            blocked.append(f"{m} (kernel.modules_disabled=1; not loaded)")
        else:
            why = "not loaded" if km["loaded"] is not None else "load state unknown"
            if m in km["blacklist"]:
                why += "; blacklisted only (blacklist stops automatic loading by alias, not modprobe by name or as a dependency)"
            elif ib or km["modules_disabled"] is True:
                why += "; loading restricted, but without a list of loaded modules it is not shown that it never runs"
            loadable.append(f"{m} ({why})")
    if loadable:
        return {"marker": "K3", "detail": "loadable module: " + "; ".join(loadable[:5]) + ("; …" if len(loadable) > 5 else "")
                + " – still affected"}
    parts = ([f"removed from the image: {', '.join(removed)}"] if removed else []) + ([f"blocked from loading: {'; '.join(blocked)}"] if blocked else [])
    # kernel-config.json 對同一個 CVE 說 affected（例如 CONFIG_X=m）：結論不同，照樣列為衝突（並列，不互相覆蓋）
    kc = ec["kcfg"]
    # 只因 =m 而 affected、而且就是 K2 判的模組（kernel-config 的 files[] 每個有編的檔都是 built_as module、module 在 K2 的模組裡）：
    # 兩個結論其實一致（核心設定只說「編成模組」，K2 另看映像裡有沒有那個模組），不列衝突
    kaff = [] if not (kconfig_usable(kc) and kconfig_component_matches(v, kc)) else [
        {"cve": str(x["cve"]).upper(), "detail": str(x.get("detail") or "")[:300]} for x in kc.get("results") or []
        if isinstance(x, dict) and str(x.get("cve") or "").upper() == str(v["id"] or "").upper() and x.get("decision") == "affected"
        and not kconfig_only_these_modules(x, set((ents.get(v["id"]) or ents.get(str(v["id"] or "").upper()) or {}).get("modules") or ()))]
    nbs = [e["not_built"] for e in ents.values()]
    nb = len(set().union(*nbs)) if nbs and all(x is not None for x in nbs) else 0
    return {"decision": "not_affected", "justification": "code_not_reachable" if blocked else "code_not_present",
            "detail": f"The fix only changes code in kernel module(s) {', '.join(mods)} ({'; '.join(parts)}); kernel "
                      f"{mm['kernel']['version']}, module map {mm.get('method') or 'scan/kernel-module-map.json'}."
                      + (f" {nb} more file(s) changed by the fix are not built into this kernel (kernel-config)." if nb else ""),
            "inputs": f"{KMOD_REL.name} SHA-256 {str(km['sha256'] or '?')[:12]}; module map SHA-256 {str(ec['mm_sha'] or '?')[:12]}; "
                      f"modules.order SHA-256 {str(ec['mm_order_sha'] or '?')[:12]}"
                      + (f"; blocking line(s): {' | '.join(sorted(set(block_lines)))[:300]}" if block_lines else ""),
            "kcfg_affected": kaff, "basis": [k2_basis(mm, ec, km)]}


def ev_u1(v, ec):
    """U1：Ubuntu 套件（不是核心）的每個 CVE，這個原始碼套件在這個發行版的狀態都是 not-affected、沒有 conflict、有版本註記，而且
    安裝的原始碼版本和註記的 epoch＋上游版本相同（只差 Debian revision），而且不比註記舊（舊的 revision 標 U1-older-revision）。tracker 的 not-affected (版本) 是「這個版本
    不受影響」，不是下限：上游版本不同就可能是不同的程式碼（例如 CVE-2024-3094 的 xz-utils 5.6.1-1 比註記 5.4.5-0.3 新，卻有後門）。
    沒有版本註記的 not-affected 也不套用（不知道 Ubuntu 看的是哪個版本）。沒套用時回傳原因（not_applied）。"""
    base = purl_split(v["purl"])[0] or ""
    if v["kernel"] or not base.startswith("pkg:deb/ubuntu/"):
        return None
    us = ec["us"]
    if us is None:
        return {"not_applied": "no_data", "detail": ec["us_problem"]}
    if not v["cves"]:
        return {"not_applied": "no_cve", "detail": "the row has no CVE ID (the tracker is keyed by CVE)"}
    comp = us["components"].get(v["purl"])
    if not isinstance(comp, dict) or not comp.get("source") or not comp.get("release") or not comp.get("source_version"):
        return {"not_applied": "source_unknown", "detail": "source package, its version or the Ubuntu release of this component is not known"}
    src, rel, sver = comp["source"], comp["release"], comp["source_version"]
    iv = deb_version_parts(sver)
    if iv is None:
        # 比不出來就不排除（例如 "unknown"、"${source:Version}"）
        return {"not_applied": "source_version_not_version", "marker": True,
                "detail": f"U1 not applied: the installed source version of {src} is not a Debian version ({str(sver)[:80]}); decide by hand"}
    notes, per_cve = [], []
    for c in v["cves"]:
        e = (((us["entries"].get(c.upper()) or {}).get(src) or {}).get(rel))
        if not isinstance(e, dict):
            return {"not_applied": "no_entry", "detail": f"the tracker has no status for {c} on {src} in {rel} (Ubuntu has no opinion)"}
        st, note = str(e.get("status") or ""), str(e.get("note") or "").strip()
        if "conflict" in e:
            # 同一個發行版與套件有不同的行（ubuntu-cve-status.sh：第一行是 status／note，後面不同的行在 conflict：[{status, note}, …]）
            later = "; ".join((f"{x.get('status')} ({x.get('note')})" if x.get("note") else str(x.get("status")))
                              if isinstance(x, dict) else str(x) for x in (e["conflict"] if isinstance(e["conflict"], list) else [e["conflict"]]))
            return {"not_applied": "conflict", "marker": True,
                    "detail": f"{c} on {src} in {rel}: U1 not applied (conflicting tracker lines: {st}{' (' + note + ')' if note else ''} "
                              f"and {later[:200]}); decide by hand"}
        if st != "not-affected":
            return {"not_applied": "other_status", "detail": f"{c} on {src} in {rel}: {st or 'no status'}"}
        if not note:
            return {"not_applied": "no_version_note", "marker": True,
                    "detail": f"{c} on {src} in {rel}: U1 not applied: not-affected without a version note (the version Ubuntu checked is "
                              "not known); decide by hand"}
        nv = deb_version_parts(note)
        if nv is None:
            return {"not_applied": "note_not_version", "marker": True,
                    "detail": f"{c} on {src} in {rel}: not-affected with a note that is not a version ({note[:120]}); decide by hand"}
        if iv[:2] != nv[:2]:
            return {"not_applied": "upstream_differs", "marker": True,
                    "detail": f"{c} on {src} in {rel}: U1 not applied: installed upstream version differs from the tracker note "
                              f"(tracker: not-affected ({note}); installed source version {sver}); decide by hand"}
        if ec["vercmp"] is None:
            return {"not_applied": "no_version_compare", "detail": "no Debian version comparison available"}
        if ec["vercmp"](sver, note) < 0:
            # 舊的 revision：tracker 看的是 note 那個 revision；修補可能是 Debian／Ubuntu 在之後的 revision 才打的，鏡像裡沒有能證明
            # 「修補不是 revision 層級」的資料（upstream_<套件>、Patches_<套件> 沒有收）→ 不套用，獨立的標記方便之後整批人工判斷
            return {"not_applied": "older_revision", "marker": "U1-older-revision",
                    "detail": f"{c} on {src} in {rel}: U1 not applied: older revision than the tracker note (evaluated at {note}, "
                              f"installed {sver}); decide by hand"}
        notes.append(f"{c}: not-affected ({note}), installed {sver}")
        cmp_ = (f"installed source version {sver} has the same epoch and upstream version as the tracker note {note} "
                "(only the Debian revision may differ) and is not older")
        ci = (us.get("cve_info") or {}).get(c.upper()) or {}
        # Priority：套件專屬的 Priority_<套件>[_<發行版>]（鏡像寫在這一筆的 priority）優先，沒有才用 CVE 層級的
        prio, psrc = (e["priority"], "package") if isinstance(e.get("priority"), str) else (ci.get("priority"), "cve")
        per_cve.append({"cve": c.upper(), "ubuntu_status": st, "ubuntu_note": note, "version_check": cmp_,
                        "ubuntu_priority": prio, "ubuntu_priority_from": psrc if prio is not None else None,
                        "tracker_file": ci.get("tracker_file"), "url": f"https://ubuntu.com/security/{c.upper()}"})
    m = us.get("mirror") or {}
    # 排除清單（evidence_exclusions）的一筆：Ubuntu 的狀態、版本比較、出處（tracker 倉庫、commit、檔案）
    ev = {"source_package": src, "source_version": sver, "release": rel, "purl": v["purl"], "cves": per_cve,
          "tracker": {"source": m.get("source"), "commit": m.get("commit"), "commit_date": m.get("commit_date"),
                      "fetched_utc": m.get("fetched_utc")}}
    return {"decision": "not_affected", "justification": "code_not_present", "evidence": ev, "basis": ubuntu_basis(ev),
            "detail": f"Ubuntu CVE Tracker (commit {str(m.get('commit') or '?')[:12]}, {str(m.get('commit_date') or '?')[:10]}) for source package "
                      f"{src} in {rel}: " + "; ".join(notes) + ". The installed source version has the same upstream version as the "
                      "version Ubuntu marks not-affected; the justification is inferred from Ubuntu's status.",
            "inputs": f"Ubuntu CVE Tracker commit {str(m.get('commit') or '?')[:12]}"}


def real_deb_version(v):
    """U2 用：Debian 版本，而且是真的版本——epoch 之後要有 "." 或 "-"（"1"、"0"、"1234" 這種只有數字的註記不算；
    deb_version_parts 把它們當原生套件的版本）。"""
    p = deb_version_parts(v)
    return p is not None and bool(re.search(r"[.\-]", re.sub(r"^\d+:", "", str(v))))


def ev_u2(v, ec):
    """U2：Ubuntu 打包的 Python 模組的列（擁有者 owner，或候選都來自同一個原始碼套件的 source_owner）。每個 CVE，Tracker 對擁有者的
    原始碼套件、這個發行版都是 released、沒有 conflict、註記是 Debian 版本，而且安裝的原始碼版本不比註記舊 → Ubuntu 已在安裝的版本修好
    → resolved。其他狀態（needed、ignored…）、安裝的版本比較舊、沒有資料都不套用（那些列由 R6、R7、R8 這類批次規則或人處理）。
    PyPI 的修補版本不適用 Ubuntu 打包的模組，這裡完全不看。沒套用時回傳原因（not_applied）。"""
    dp = v.get("deb_python") or {}
    o = dp.get("owner") or dp.get("source_owner")
    if v["kernel"] or not isinstance(o, dict):
        return None
    us = ec["us"]
    if us is None:
        return {"not_applied": "no_data", "detail": ec["us_problem"]}
    if not v["cves"]:
        return {"not_applied": "no_cve", "detail": "the row has no CVE ID (the tracker is keyed by CVE)"}
    comp = us["components"].get(o.get("purl"))
    if not isinstance(comp, dict) or not comp.get("source") or not comp.get("release") or not comp.get("source_version"):
        return {"not_applied": "source_unknown", "detail": "source package, its version or the Ubuntu release of the owning package is not known"}
    src, rel, sver = comp["source"], comp["release"], comp["source_version"]
    if not real_deb_version(sver):
        return {"not_applied": "source_version_not_version", "detail": f"the installed source version of {src} is not a Debian version ({str(sver)[:80]})"}
    if ec["vercmp"] is None:
        return {"not_applied": "no_version_compare", "detail": "no Debian version comparison available"}
    notes, per_cve = [], []
    for c in v["cves"]:
        e = (((us["entries"].get(c.upper()) or {}).get(src) or {}).get(rel))
        if not isinstance(e, dict):
            return {"not_applied": "no_entry", "detail": f"the tracker has no status for {c} on {src} in {rel} (Ubuntu has no opinion)"}
        st, note = str(e.get("status") or ""), str(e.get("note") or "").strip()
        if "conflict" in e:
            return {"not_applied": "conflict", "detail": f"{c} on {src} in {rel}: conflicting tracker lines"}
        if st != "released":
            return {"not_applied": "other_status", "detail": f"{c} on {src} in {rel}: {st or 'no status'}"}
        if not real_deb_version(note):
            return {"not_applied": "note_not_version", "detail": f"{c} on {src} in {rel}: released with a note that is not a version ({note[:120]})"}
        if ec["vercmp"](sver, note) < 0:
            return {"not_applied": "installed_older", "detail": f"{c} on {src} in {rel}: released in {note}, installed source version {sver} is older"}
        notes.append(f"{c}: released {note}")
        per_cve.append({"cve": c.upper(), "ubuntu_status": st, "ubuntu_note": note, "url": f"https://ubuntu.com/security/{c.upper()}"})
    m = us.get("mirror") or {}
    ev = {"source_package": src, "source_version": sver, "release": rel, "purl": o.get("purl"), "cves": per_cve,
          "tracker": {"source": m.get("source"), "commit": m.get("commit"), "commit_date": m.get("commit_date"), "fetched_utc": m.get("fetched_utc")}}
    return {"decision": "resolved", "justification": None, "evidence": ev, "basis": ubuntu_basis(ev, us.get("cve_info")),
            "detail": f"Ubuntu CVE Tracker (commit {str(m.get('commit') or '?')[:12]}, {str(m.get('commit_date') or '?')[:10]}) for source package "
                      f"{src} in {rel}: " + "; ".join(notes) + f". The installed source version {sver} of the Ubuntu package {o.get('name')}, which "
                      "installed this Python module, is not older than the release that fixes it; the PyPI fix versions do not apply to it.",
            "inputs": f"Ubuntu CVE Tracker commit {str(m.get('commit') or '?')[:12]}"}


EVIDENCE_FUNCS = {"K1": ev_k1, "K2": ev_k2, "U1": ev_u1, "U2": ev_u2}


def rule_inactive(ru, ec):
    """這次產生文件時規則不生效的原因（清單）：映像不在 images、還沒到生效日、沒有具名的責任人。"""
    why = []
    im = ru.get("images") or []
    if IMAGE_PLACEHOLDER in im:
        why.append(f"images is still the placeholder {IMAGE_PLACEHOLDER}")
    elif not ec["images"]:
        # "*" 也一樣：掃描沒有映像雜湊時不知道評估的是哪一個映像
        why.append("the scan has no image hash (meta.json)")
    elif im != ["*"] and not ({norm_image(x) for x in im} & ec["images"]):
        why.append("the scanned image is not in the rule's images")
    if not ec["today"]:
        why.append("no report date: the effective date cannot be checked")
    elif ru["date"] > ec["today"]:
        why.append(f"effective from {ru['date']}")
    if ru.get("author_missing"):
        why.append("no named author")
    return why


def new_evidence_stats(rules, ec):
    return [{"id": r["id"], "evidence": r["evidence"], "inactive": rule_inactive(r, ec), "applied": 0, "kernel": 0, "non_kernel": 0,
             "shadowed": Counter(), "shadowed_rows": [], "excluded_kev": 0, "inactive_rows": 0, "not_applied": Counter(),
             "marker_rows": [], "justification": Counter(), "rows": [], "not_applied_rows": [], "excluded_kev_rows": []} for r in rules]


def apply_evidence(row, rules, stats, existing, ec, exploited=frozenset()):
    """證據規則（依檔案順序，在 match 規則之前）。回傳 (陳述或 None, 被蓋過的陳述或 None)。
    已有判定（人的、逐列證據的）→ shadowed（依來源計數，並記在這一列的 rule_shadowed）；KEV、被利用的列 → excluded_kev，不套用；
    規則不生效（映像、生效日、責任人）→ inactive_rows。沒套用的原因與 K3／K4 標記只記在沒有其他判定的列（不改狀態）。"""
    if is_nv_bulletin_row(row):
        return None, None
    v = evidence_view(row)
    for ru, st in zip(rules, stats):
        res = EVIDENCE_FUNCS[ru["evidence"]](v, ec)
        if res is None:
            continue
        if "decision" not in res:
            if not st["inactive"] and not existing:
                if res.get("marker"):
                    code = res["marker"] if isinstance(res["marker"], str) else "U1-not-applied"
                    ms = row.setdefault("vex_markers", [])
                    # 同一列同一種標記只記一次（兩條同種類的規則不重複）
                    if not any(m["code"] == code for m in ms):
                        ms.append({"code": code, "rule": ru["id"], "detail": res["detail"], "gap": code == "K4"})
                        st["marker_rows"].append(row)
                if res.get("not_applied"):
                    st["not_applied"][res["not_applied"]] += 1
                    st["not_applied_rows"].append((res["not_applied"], row, res["detail"]))
            continue
        if st["inactive"]:
            st["inactive_rows"] += 1
            continue
        tag = f"(bulk rule {ru['id']} [{ru['evidence']}]: {ru['description'].strip()})"
        s = stmt("rule", res["decision"], f"{res['detail']} {tag}", res["justification"], rule=ru["id"], rule_author=ru.get("author"),
                 evidence=ru["evidence"], rule_inputs=res.get("inputs"), rule_evidence=res.get("evidence"),
                 evidence_basis=res.get("basis"))
        if existing:
            st["shadowed"][existing["source"]] += 1
            st["shadowed_rows"].append((row, existing))
            row.setdefault("rule_shadowed", []).append({"rule": ru["id"], "evidence": ru["evidence"], "would_set": res["decision"],
                                                        "decided_by": existing["source"], "state": existing.get("state")})
            return None, (s if existing.get("state") else None)
        if on_kev(row, exploited) or row.get("exploited_sources"):
            st["excluded_kev"] += 1
            # 被利用的列要人判斷，但判斷的人需要看到規則的證據（例如 CONFIG_X is not set）：寫在這一列的說明，不改狀態
            row["rule_excluded_kev"] = {"rule": ru["id"], "evidence": ru["evidence"], "detail": res["detail"]}
            if res["decision"] != "not_affected":
                row["rule_excluded_kev"]["would_set"] = res["decision"]
            st["excluded_kev_rows"].append(row)
            return None, None
        if res.get("kcfg_affected"):
            row["rule_conflicts"] = [{"rule": ru["id"], "cve": k["cve"], "other": "kernel_config:affected", "detail": k["detail"]}
                                     for k in res["kcfg_affected"]]
        st["applied"] += 1
        st["kernel" if row.get("kernel") else "non_kernel"] += 1
        st["justification"][res["justification"] or "none"] += 1
        st["rows"].append(row)
        return s, None
    return None, None


def evidence_summary(rules, stats, samples=5):
    """證據規則的統計（和 rule_summary 同一個清單；match 規則專用的欄位補 0）。"""
    out = []
    for ru, st in zip(rules, stats):
        rows = sorted(st["rows"], key=priority_key)
        out.append({"id": ru["id"], "description": ru["description"], "author": ru.get("author") or "",
                    "author_missing": author_missing(ru.get("author")), "date": ru["date"], "reason": ru["reason"],
                    "evidence": ru["evidence"], "images": list(ru["images"]), "inactive": st["inactive"],
                    "state": "resolved" if ru["evidence"] == "U2" else "not_affected", "response": [], "match": None, "justification": dict(sorted(st["justification"].items())),
                    "applied": st["applied"], "kernel": st["kernel"], "non_kernel": st["non_kernel"],
                    **({"owner_decided": st.get("owner_decided", 0)} if ru["evidence"] == "U2" else {}),
                    "shadowed": {k: st["shadowed"][k] for k in SHADOW_KEYS if st["shadowed"][k]},
                    "shadowed_sample": [{"id": r["id"], "component": r.get("component"), "version": r.get("version"), "decided_by": e["source"],
                                         "state": e.get("state")} for r, e in st["shadowed_rows"][:samples]],
                    "excluded_kev": st["excluded_kev"],
                    "excluded_kev_sample": [{"id": r["id"], "component": r.get("component"), "version": r.get("version"),
                                             "detail": r["rule_excluded_kev"]["detail"]} for r in st["excluded_kev_rows"][:samples]],
                    # 全部（風險評估的 VEX 小節列出：判斷 P1 列的人要看到規則的證據）
                    "excluded_kev_rows": [{"id": r["id"], "component": r.get("component"), "version": r.get("version"),
                                           "detail": r["rule_excluded_kev"]["detail"]} for r in st["excluded_kev_rows"]],
                    "excluded_p1": 0, "excluded_deb_python": 0, "template_missing": 0,
                    "inactive_rows": st["inactive_rows"], "not_applied": dict(sorted(st["not_applied"].items())),
                    "not_applied_sample": [{"reason": why, "id": r["id"], "component": r.get("component"), "version": r.get("version"),
                                            "detail": d} for why, r, d in st["not_applied_rows"][:samples * 4]],
                    # 標記的列數：只算最後還留著這條規則標記的列（之後被別的規則或來源判定的列，標記已拿掉）
                    "markers": dict(sorted(Counter(m["code"] for r in st["marker_rows"] for m in r.get("vex_markers") or []
                                                   if m.get("rule") == ru["id"]).items())),
                    "sample": [{"id": r["id"], "component": r.get("component"), "version": r.get("version"), "tier": r.get("tier"),
                                "kernel": bool(r.get("kernel")), "detail": r["vex"]["detail"] if r.get("vex") else None} for r in rows[:samples]]})
    return out


def snapshot_age_days(fetched, today):
    """tracker 快照（鏡像的 fetched_utc）到報告日（UTC 日期）的天數；不知道 → None。新舊只在掃描時檢查，這裡只寫進說明。"""
    try:
        f = datetime.date.fromisoformat(str(fetched)[:10])
        t = datetime.date.fromisoformat(str(today)[:10])
    except ValueError:
        return None
    return (t - f).days


def marker_counts(rows):
    """每種標記的列數（一列同一種只算一次）。"""
    return dict(sorted(Counter(c for x in rows for c in {m["code"] for m in x.get("vex_markers") or []}).items()))


def u1_exclusions(rows, erules):
    """被證據規則 U1 設成 not_affected 的每一列（看最後的判定：被人或其他來源蓋過、KEV／被利用而沒套用的不在裡面）→ 排除清單。
    每一筆：列（編號、元件、版本、層級）、判定與理由、規則（編號、責任人、生效日、規則的理由）、證據（ev_u1 的 evidence：原始碼套件、
    原始碼版本、發行版、purl、每個 CVE 的 Ubuntu 狀態與註記、版本比較、CVE 的 Priority、tracker 裡的檔案、ubuntu.com 的頁面；
    tracker 倉庫、commit、commit_date、fetched_utc）。報告的「被排除清單」直接用這份。"""
    by_id = {r["id"]: r for r in erules if r["evidence"] == "U1"}
    out = []
    for x in rows:
        s = x.get("vex")
        if not s or s["source"] != "rule" or s.get("evidence") != "U1" or not isinstance(s.get("rule_evidence"), dict):
            continue
        ru, ev = by_id.get(s.get("rule")) or {}, s["rule_evidence"]
        why = (f"Ubuntu CVE Tracker marks source package {ev['source_package']} not-affected in {ev['release']} for "
               + "; ".join(f"{c['cve']} ({c['version_check']})" for c in ev["cves"]))
        out.append({"id": x["id"], "component": x.get("component"), "version": x.get("version"), "tier": x.get("tier"),
                    "state": s["state"], "justification": s.get("justification"), "reason": why,
                    "rule": s.get("rule"), "rule_author": s.get("rule_author"), "rule_date": ru.get("date"), "rule_reason": ru.get("reason"),
                    **copy.deepcopy(ev)})
    out.sort(key=lambda e: (e["id"], str(e["component"]), str(e["version"])))
    return out


def u2_defer_to_owner(rows, erules, estats, conflicts):
    """U2 在 judge 時還看不到擁有者 deb 列的判定（deb 列可能排在後面）。這裡在沿用（inherit_deb_python）之前補檢查：擁有它的 deb 列有人的判定
    （INHERITABLE：DT 人工分析、vex-annotations.json）→ 拿掉 U2 的陳述，讓人的判定照 inherit_deb_python 沿用；記在這一列的 rule_shadowed、
    vex_note、規則統計（shadowed、owner_decided），分類不同時也記衝突。和 deb_python_rules 一樣：擁有者有人的判定就不由規則決定。"""
    by_id = {}
    for d in rows:
        if d.get("ptype") == "deb" and d.get("vex") and d["vex"]["source"] in INHERITABLE \
                and not (d["vex"]["source"] == "dt" and d.get("dt_partial")):
            by_id.setdefault(str(d.get("id") or "").upper(), []).append(d)
    stats = {r["id"]: st for r, st in zip(erules, estats) if r["evidence"] == "U2"}
    for x in rows:
        s = x.get("vex")
        if not s or s["source"] != "rule" or s.get("evidence") != "U2" or s.get("rule") not in stats:
            continue
        dp = x.get("deb_python") or {}
        so = dp.get("source_owner") or {}
        owners = [dp["owner"]] if dp.get("owner") else \
            ([so] + [dict(so, name=str(c).rsplit(" ", 1)[0], version=str(c).rsplit(" ", 1)[-1]) for c in dp.get("candidates") or []] if so else [])
        hits = [d for o in owners for d in owning_deb_rows(x, by_id, o)]
        if not hits:
            continue
        h = hits[0]
        st = stats[s["rule"]]
        st["applied"] -= 1
        st["kernel" if x.get("kernel") else "non_kernel"] -= 1
        st["justification"][s.get("justification") or "none"] -= 1
        if st["justification"][s.get("justification") or "none"] <= 0:
            del st["justification"][s.get("justification") or "none"]
        st["rows"] = [r for r in st["rows"] if r is not x]
        st["owner_decided"] = st.get("owner_decided", 0) + 1
        st["shadowed"][h["vex"]["source"]] += 1
        st["shadowed_rows"].append((x, h["vex"]))
        x.setdefault("rule_shadowed", []).append({"rule": s["rule"], "evidence": "U2", "would_set": "resolved", "decided_by": h["vex"]["source"],
                                                   "state": h["vex"].get("state"), "owner": h.get("component")})
        x["vex"] = None
        x["vex_note"] = (f"evidence rule {s['rule']} [U2] would set resolved, but the Ubuntu package row {h.get('component')} {h.get('version')} "
                         f"has a decision by a person ({h['vex']['source']}: {h['vex'].get('state')}): U2 not applied, that decision is used for this row")
        if BUCKET["resolved"] != BUCKET[h["vex"]["state"]]:
            conflicts.append({"id": x["id"], "component": x.get("component"), "version": x.get("version"),
                              "used": f"{h['vex']['source']}:{h['vex']['state']}", "other": f"rule:resolved ({s['rule']})", "human": False})


def u2_resolved(rows, erules):
    """被證據規則 U2 設成 resolved 的每一列（看最後的判定）→ 清單（summary.json 的 vex.u2_resolved；和 u1_exclusions 同樣的欄位）。"""
    by_id = {r["id"]: r for r in erules if r["evidence"] == "U2"}
    out = []
    for x in rows:
        s = x.get("vex")
        if not s or s["source"] != "rule" or s.get("evidence") != "U2" or not isinstance(s.get("rule_evidence"), dict):
            continue
        ru, ev = by_id.get(s.get("rule")) or {}, s["rule_evidence"]
        out.append({"id": x["id"], "component": x.get("component"), "version": x.get("version"), "tier": x.get("tier"),
                    "state": s["state"], "reason": "Ubuntu CVE Tracker: released for source package " + f"{ev['source_package']} in {ev['release']} for "
                    + "; ".join(f"{c['cve']} ({c['ubuntu_note']})" for c in ev["cves"]) + f", installed source version {ev['source_version']}",
                    "rule": s.get("rule"), "rule_author": s.get("rule_author"), "rule_date": ru.get("date"), "rule_reason": ru.get("reason"),
                    **copy.deepcopy(ev)})
    out.sort(key=lambda e: (e["id"], str(e["component"]), str(e["version"])))
    return out


# ---------- 可能誤報：發行版紀錄沒有版本範圍，上游範圍不含安裝的版本（distro_no_range_upstream_excludes） ----------

def upstream_numeric(v):
    """deb 版本的上游部分 → 數字 tuple（3.16-1build2 → (3, 16)）。去掉 epoch、revision 與 + 之後（+dfsg 等重新打包）；
    有 ~（預發行，比較順序不同）或不是純數字點分 → None（比不出來就不標）。"""
    v = str(v or "").strip()
    if re.match(r"^\d+:", v):
        v = v.split(":", 1)[1]
    if "-" in v:
        v = v.rpartition("-")[0]
    if "~" in v:
        return None
    v = v.split("+", 1)[0]
    return tuple(int(x) for x in v.split(".")) if re.fullmatch(r"\d+(?:\.\d+)*", v) else None


def _vt_cmp(a, b):
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def constraint_contains(con, ver):
    """Grype 的 versionConstraint（例如 "< 3.14 (unknown)"、">= 2.0, < 2.4.1 || >= 3.0, < 3.1 (unknown)"）是否包含 ver（數字 tuple）。
    True／False；沒有範圍（none）、格式看不懂、版本不是純數字 → None。"""
    body = re.sub(r"\s*\([^()]*\)\s*$", "", str(con or "")).strip()
    if body.lower() in ("", "none", "unknown"):
        return None
    ops = {"<": lambda c: c < 0, "<=": lambda c: c <= 0, ">": lambda c: c > 0, ">=": lambda c: c >= 0,
           "=": lambda c: c == 0, "==": lambda c: c == 0, "!=": lambda c: c != 0}
    hit = False
    for g in body.split("||"):
        ok = True
        for t in g.split(","):
            m = re.fullmatch(r"\s*(<=|>=|==|!=|<|>|=)?\s*([0-9]+(?:\.[0-9]+)*)\s*", t)
            if not m:
                return None
            if not ops[m.group(1) or "="](_vt_cmp(ver, tuple(int(x) for x in m.group(2).split(".")))):
                ok = False
        hit = hit or ok
    return hit


def _cpe_product(cpe):
    p = str(cpe or "").split(":")
    return p[4].lower().replace("-", "_") if len(p) > 4 and p[0] == "cpe" and p[1] == "2.3" else None


def _no_constraint(md):
    con = str(((md.get("found") or {}) if isinstance(md, dict) else {}).get("versionConstraint") or "")
    return re.sub(r"\s*\([^()]*\)\s*$", "", con).strip().lower() in ("", "none", "unknown")


def upstream_exclusion_flags(rows, grype, ustatus=None):
    """標記 distro_no_range_upstream_excludes（只標記、不改 VEX 狀態）：Grype 由發行版資料（namespace 含 ":distro:"）比對到、
    versionConstraint 是 none／unknown，而 grype.json 裡同一個 CVE 的 CPE 比對紀錄（matchDetails type cpe-match，NVD 或其他 CPE 資料源）
    對同一個產品（CPE 的 product＝套件或原始碼套件名稱）的範圍**全部**不含安裝版本的上游部分。
    離線可用的範圍資料只有這些（Grype 的 relatedVulnerabilities、DT 的 findings 都沒有 CPE 範圍）；沒有範圍、比不出來、
    DT 對這一列另有 NVD 的 finding（DT 以 CPE 比對認為在範圍內）、已有人的判定 → 不標，原因計數。回傳摘要。"""
    out = {"basis": "scan/grype.json: distro matches without a version constraint, and cpe-match records for the same CVE and product",
           "candidates": 0, "flagged": 0, "not_flagged": Counter(), "rows": []}
    if not isinstance(grype, dict):
        out["basis"] = None
        out["not_flagged"] = {}
        return out
    ranges = {}
    for m in grype.get("matches") or []:
        if not isinstance(m, dict):
            continue
        for md in m.get("matchDetails") or []:
            if not isinstance(md, dict) or md.get("type") != "cpe-match":
                continue
            f = md.get("found") or {}
            mc = CVE_ID.match(str(f.get("vulnerabilityID") or (m.get("vulnerability") or {}).get("id") or "").upper())
            if not mc or _no_constraint(md):
                continue
            for cpe in f.get("cpes") or []:
                pr = _cpe_product(cpe)
                if pr:
                    ranges.setdefault(mc.group(1), []).append({"product": pr, "constraint": str(f["versionConstraint"]), "cpe": cpe,
                                                               "namespace": (md.get("searchedBy") or {}).get("namespace")
                                                               or (m.get("vulnerability") or {}).get("namespace")})
    by_row = {}
    for r in rows:
        for c in r.get("cves") or []:
            for n in {str(r.get("name") or "").lower(), *(str(b).lower() for b in r.get("installed_as") or [])} - {""}:
                by_row.setdefault((c.upper(), n, str(r.get("version") or "")), []).append(r)
    seen = set()
    for m in grype.get("matches") or []:
        if not isinstance(m, dict):
            continue
        v, a = m.get("vulnerability") or {}, m.get("artifact") or {}
        mc = CVE_ID.match(str(v.get("id") or "").upper())
        mds = [x for x in m.get("matchDetails") or [] if isinstance(x, dict)]
        if not mc or ":distro:" not in str(v.get("namespace") or "") or not mds or not all(_no_constraint(x) for x in mds):
            continue
        cve, name, ver = mc.group(1), str(a.get("name") or ""), str(a.get("version") or "")
        if (cve, name, ver) in seen:
            continue
        seen.add((cve, name, ver))
        out["candidates"] += 1
        products = {name.lower().replace("-", "_")} | {str(u.get("name") or "").lower().replace("-", "_")
                                                       for u in a.get("upstreams") or [] if isinstance(u, dict)} - {""}
        rs = [x for x in ranges.get(cve, []) if x["product"] in products]
        up = upstream_numeric(ver)
        targets = by_row.get((cve, name.lower(), ver), [])
        if not rs:
            why = "no_range_data"
        elif up is None:
            why = "version_not_comparable"
        else:
            res = [constraint_contains(x["constraint"], up) for x in rs]
            why = "range_not_comparable" if None in res else "range_includes_version" if any(res) else None
        if why is None and not targets:
            why = "not_in_table"
        if why:
            out["not_flagged"][why] += 1
            continue
        for r in targets:
            if any(str(s).upper().startswith("NVD:") for s in r.get("source_ids") or []):
                out["not_flagged"]["dt_nvd_match"] += 1
                continue
            if r.get("vex") and r["vex"]["source"] in HUMAN:
                out["not_flagged"]["decided_by_person"] += 1
                continue
            src = ((ustatus or {}).get("components") or {}).get(r.get("purl")) or {}
            e = ((((ustatus or {}).get("entries") or {}).get(cve) or {}).get(src.get("source") or "") or {}).get(src.get("release") or "")
            ub = (f"{e.get('status')}{' (' + str(e.get('note')) + ')' if e.get('note') else ''} in {src.get('release')} (Ubuntu CVE Tracker mirror)"
                  if isinstance(e, dict) and e.get("status") else "not available offline: check https://ubuntu.com/security/" + cve)
            ev = {"id": r["id"], "cve": cve, "component": r.get("component"), "version": r.get("version"), "upstream_version": ".".join(map(str, up)),
                  "distro_match": {"namespace": v.get("namespace"), "fix_state": (v.get("fix") or {}).get("state"),
                                   "constraint": ", ".join(sorted({str((x.get("found") or {}).get("versionConstraint") or "") for x in mds}))},
                  "upstream_ranges": [{"cpe": x["cpe"], "constraint": x["constraint"], "namespace": x["namespace"]} for x in rs],
                  "ubuntu_status": ub,
                  "ubuntu_changelog": f"not checked: look for {cve} in /usr/share/doc/{src.get('source') or r.get('name')}/changelog.Debian.gz of the image"}
            r.setdefault("vex_markers", []).append({"code": "distro_no_range_upstream_excludes", "rule": None, "gap": False,
                                                    "detail": f"possible false positive, confirm: the distribution record has no version range, the "
                                                              f"upstream range ({'; '.join(x['constraint'] for x in rs)}) excludes upstream version "
                                                              f"{ev['upstream_version']}", "evidence": ev})
            out["rows"].append(ev)
    out["flagged"] = len(out["rows"])
    out["not_flagged"] = dict(sorted(out["not_flagged"].items()))
    out["rows"].sort(key=lambda x: (x["cve"], str(x["component"]), str(x["version"])))
    return out


# ---------- 各來源的判定 ----------

def stmt(source, state, detail, justification=None, response=(), **extra):
    s = {"source": source, "state": state, "detail": detail}
    if justification:
        s["justification"] = justification
    if response:
        s["response"] = sorted(set(response))
    s.update({k: v for k, v in extra.items() if v})
    return s


def dt_attributable(a, row):
    """這筆 finding 的分析能不能當成這一列（row["id"]）的判定：finding 的弱點編號就是這一列的編號（UBUNTU-CVE-X 算 CVE-X），
    或 finding 是 GHSA 等非 CVE 編號、而它的別名只有這一個 CVE。沒有記 finding 編號（舊的呼叫端）時當作可以。"""
    if "vuln_id" not in a:
        return True
    vid, rid = str(a.get("vuln_id") or "").upper(), str(row.get("id") or "").upper()
    m = CVE_ID.match(vid)
    if m:
        return m.group(1) == rid
    if CVE_ID.match(rid):
        return {c.upper() for c in a.get("cves") or []} == {rid}
    return vid == rid


def dt_decided(row):
    """DT 裡有沒有任何一筆人設的分析（有 DT state）提到這一列的編號：finding 的編號就是它（UBUNTU-CVE-X 算 CVE-X），
    或 finding 的 CVE 別名含它。只給規則判斷「人已經看過」用，不是 VEX 陳述（陳述仍只採用 dt_attributable 的）。"""
    rid = str(row.get("id") or "").upper()
    for a in row.get("analysis") or []:
        if not DT_STATE.get(str(a.get("state") or "").upper()):
            continue
        m = CVE_ID.match(str(a.get("vuln_id") or "").upper())
        if (m and m.group(1) == rid) or rid in {str(c).upper() for c in a.get("cves") or []}:
            return True
    return False


def from_dt(row):
    """人在 DT 設的分析（每一筆 finding 一個）。回傳 (判定或 None, 這一列裡彼此不同的判定（衝突）, 只有部分 finding 有判定,
    不能用的分析 {原因: [DT 狀態]})。
    不能用：NOT_AFFECTED 沒有 justification 也沒有 details、FALSE_POSITIVE 沒有 justification（不替人編理由）、
    分析的 finding 不是這一列的 CVE（dt_attributable）。"""
    got, bad = [], {}
    for a in row.get("analysis") or []:
        st = DT_STATE.get(str(a.get("state") or "").upper())
        if not st:
            continue
        if not dt_attributable(a, row):
            bad.setdefault("other_vulnerability", []).append(str(a.get("state")).upper())
            continue
        j = str(a.get("justification") or "").lower()
        j = j if j in CDX_JUST else None
        r = str(a.get("response") or "").lower()
        det = str(a.get("details") or "").strip()
        if (st == "not_affected" and not (j or det)) or (st == "false_positive" and not j):
            bad.setdefault("no_justification", []).append(str(a.get("state")).upper())
            continue
        got.append(stmt("dt", st, det or f"Assessed as {a.get('state')} ({j or 'no justification'}) in Dependency-Track; no details "
                                         "were included in the Dependency-Track findings export.",
                        j, [r] if r in CDX_RESP else ()))
    if not got:
        return None, [], False, bad
    distinct = {json.dumps(g, sort_keys=True): g for g in got}
    best = min(distinct.values(), key=lambda g: (RANK[g["state"]], json.dumps(g, sort_keys=True)))
    return best, (sorted(distinct.values(), key=lambda g: json.dumps(g, sort_keys=True)) if len(distinct) > 1 else []), \
        len(got) < len(row.get("analysis") or []), bad


def from_annotations(row, anns, used, project=None):
    hits = [(scope_of(a)[1], i, a) for i, a in enumerate(anns) if annotation_matches(a, row)]
    if not hits:
        return None, []
    top = max(h[0] for h in hits)
    best = [h for h in hits if h[0] == top]
    for _, i, _ in hits:
        used.add(i)
    ss = []
    for _, _, a in best:
        # 排除（resolved、not_affected）才看依據；on-device 的檔案在這裡檢查（需要專案資料夾）
        basis, why = annotation_evidence(a, project) if BUCKET[a["state"]] in EVIDENCE_BUCKETS else ([], None)
        ss.append(stmt("annotation", a["state"], a["detail"].strip(), a.get("justification"), a.get("response") or (),
                       author=a["author"], date=a["date"], action_statement=a.get("action_statement"),
                       scope=" ".join(x for x in (a["cve"], a.get("purl"), a.get("version")) if x),
                       evidence_basis=basis,
                       # annotation_no_evidence 是預設原因（exclusion_basis），只有其他原因才記在陳述上
                       evidence_missing=why if why not in (None, "annotation_no_evidence") else None))
    ss.sort(key=lambda g: (RANK[g["state"]], json.dumps(g, sort_keys=True)))
    others = ss[1:] if len({(g["state"], g.get("justification")) for g in ss}) > 1 else []
    return ss[0], others


def distro_rows(drc):
    if not isinstance(drc, dict) or drc.get("status") != "OK":
        return {}
    return {tuple(str(k) for k in x["key"]): x for x in drc.get("rows") or []
            if isinstance(x, dict) and x.get("decision") == "distro_fixed" and isinstance(x.get("key"), list) and len(x["key"]) == 3}


def from_distro(row, idx):
    x = idx.get(tuple(row.get("key") or ()))
    if x is None or row.get("kernel") or not set(row.get("source_ids") or []) <= set(x.get("source_ids") or []):
        return None
    rel = x.get("release") or {}
    dname = " ".join(str(v) for v in (rel.get("distro"), rel.get("version")) if v) + (f" ({rel['codename']})" if rel.get("codename") else "")
    ev = [e for e in x.get("evidence") or [] if isinstance(e, dict)]
    fixes = "; ".join(sorted({f"{e.get('fixed_version') or '?'} ({e.get('record') or '?'})" for e in ev})) or "? (?)"
    inst = row.get("version") or x.get("version") or "?"
    src, sver = x.get("source_package"), x.get("source_version")
    srcnote = f" (source package {src} {sver})" if src and sver and (src, sver) != (row.get("name"), inst) else ""
    return stmt("distro", "resolved", f"fixed by {dname or 'the distribution'} in {fixes}; installed {inst}{srcnote}. "
                                      "Reported only via NVD/GitHub data, which does not know the distribution's backported fix.",
                evidence_basis=distro_basis(x), evidence_missing=None if distro_basis(x) else "distro_no_record")


def kconfig_index(kcfg):
    """scan/kernel-config.json（kconfig-vex-interface.md）→ {CVE: 那一筆}：只收 kconfig_usable（status OK，或依完整的 IKCONFIG
    判定的 ATTENTION）的 not_affected。"""
    if not kconfig_usable(kcfg):
        return {}
    return {str(x["cve"]).upper(): x for x in kcfg.get("results") or []
            if isinstance(x, dict) and isinstance(x.get("cve"), str) and x.get("decision") == "not_affected"}


def kconfig_component_matches(row, kcfg):
    """kernel-config.json 只對它檢查的那個核心有效（kconfig-vex-interface.md 的 component 與 kernel.version）：
    這一列的 purl（base＋版本）或名稱＋版本要和 component 相同，或是名稱以 -<kernel.version> 結尾的核心套件
    （linux-image-6.8.12-1021-tegra 之類）。沒有 component 時一律不套用。"""
    comp, k = kcfg.get("component") or {}, kcfg.get("kernel") or {}
    rb, rv = purl_split(row.get("purl"))
    cb, cv = purl_split(comp.get("purl"))
    if cb and rb == cb and (rv or row.get("version")) == (cv or comp.get("version")):
        return True
    if comp.get("name") and (row.get("name"), row.get("version")) == (comp.get("name"), comp.get("version")):
        return True
    kv = str(k.get("version") or "")
    return bool(kv) and bool(comp) and str(row.get("name") or "").endswith("-" + kv)


def kconfig_source_note(kcfg):
    """依 IKCONFIG 判定時放在說明前面的一句（VEX 與風險評估）；其他 → ""。"""
    # differences_total 是正規化後的數（沒有的設定與 is not set 都算 n）
    c = kconfig_ikconfig(kcfg)
    if c is not None:
        n = c.get("differences_total")
        return (f"based on the flashed kernel's built-in configuration (IKCONFIG sha {str(c.get('image_config_sha256'))[:12]}); "
                f"the headers .config differs from it in {n if isinstance(n, int) else '?'} option(s); ")
    c = kconfig_toolchain_only(kcfg)
    if c is not None:
        n = c.get("toolchain_differences_total")
        return (f"based on the flashed kernel's built-in configuration (IKCONFIG sha {str(c.get('image_config_sha256'))[:12]}; "
                f"only toolchain options differ from the headers .config: {n if isinstance(n, int) else '?'}); ")
    return ""


def from_kconfig(row, kidx, kcfg):
    if not row.get("kernel") or not kidx or not kconfig_component_matches(row, kcfg):
        return None
    hits = [kidx[c.upper()] for c in row.get("cves") or [] if c.upper() in kidx]
    # 一列有多個 CVE 時每個都要是 not_affected
    if not hits or len(hits) != len(row.get("cves") or []):
        return None
    k = kcfg.get("kernel") or {}
    where = ", ".join(x for x in (f"kernel {k['version']}" if k.get("version") else "",
                                  f"configuration {k['config_source']}" if k.get("config_source") else "",
                                  f"SHA-256 {str(k['config_sha256'])[:12]}" if k.get("config_sha256") else "") if x)
    det = " / ".join(str(h.get("detail") or "all files of the fix are only built with kernel options that are not set") for h in hits)
    det = kconfig_source_note(kcfg) + det
    return stmt("kconfig", "not_affected", f"Kernel configuration check ({where or 'see scan/kernel-config.json'}): {det}",
                "code_not_present", evidence_basis=[kcfg_basis(kcfg)])


UB_ABSENT, UB_PRESENT = "UB1", "UB2"       # 建議的代號（不是會套用的規則）


def uefi_image_detail(c):
    """row["uefi_image_check"]（uefi_bundled.relabel_rows 標上的）→ 英文證據（含檢查範圍與 DSC 佐證）。"""
    ev = c.get("evidence") or {}
    lib = c.get("label") or c.get("library") or "the library"
    scope = ev.get("scope") or "the UEFI images uefi_*.bin listed in the flash package; capsules were not examined"
    if c.get("result") == "absent":
        co = ev.get("corroboration") or {}
        cos = ""
        if co.get("ok"):
            cos = (f" Corroboration from the platform DSC ({', '.join(co.get('dsc') or [])}): " + "; ".join(co.get("evidence") or []) + ".")
            if co.get("defines_files"):
                cos += f" Kconfig defines read from: {', '.join(co['defines_files'])}."
            if co.get("missing_inf_count"):
                cos += (f" Caveat: {co['missing_inf_count']} INF file(s) named by the platform DSC were not found in the source tree and could not be "
                        f"checked (first: {'; '.join(co.get('missing_inf_first') or [])}).")
        return (f"{lib} is in the UEFI source tree, but the shipped UEFI image(s) contain no code or strings of it: "
                f"the image(s) were fully decoded ({ev.get('images', '?')} image(s), {ev.get('ffs_files', '?')} firmware files, "
                f"{ev.get('decompressed_total', '?')} bytes decompressed) and no {lib} pattern matched.{cos} "
                f"Scope: absent from {scope}.")
    return (f"{lib} is built into the shipped UEFI image: {ev.get('distinct_strings', '?')} distinct library strings and "
            f"{ev.get('distinct_paths', '?')} build paths were found in the decoded image(s); the vulnerability match by version stands.")


UB_RULES = ("UB1", "UB2")
N_RULES = ("N1", "N2")


def all_suggestions(row):
    """一列的所有建議：row["suggestion"]（主要的一筆）＋ row["suggestion_more"]（同一列另有別的來源的建議時，通常沒有）。"""
    out = [row["suggestion"]] if isinstance(row.get("suggestion"), dict) else []
    return out + [x for x in row.get("suggestion_more") or [] if isinstance(x, dict)]


def set_suggestion(row, sg, owned):
    """換掉這個來源（owned＝它的規則代號）的建議為 sg（None＝移除），別的來源的建議保留。第一筆放 row["suggestion"]，其餘放 row["suggestion_more"]。
    建議不改判定、不進 VEX 檔。"""
    new = [x for x in all_suggestions(row) if x.get("rule") not in owned] + ([sg] if sg else [])
    row.pop("suggestion", None)
    row.pop("suggestion_more", None)
    if new:
        row["suggestion"] = new[0]
    if len(new) > 1:
        row["suggestion_more"] = new[1:]


def uefi_image_suggestion(row, winner):
    """UEFI 映像檢查（uefi_image.py）對這一列的**建議**（row["suggestion"]）。不改判定：這一列的 VEX 狀態、理由、層級、規則都照原本，
    也不會進 VEX 檔與客戶資料包；RD 確認後由人工判定（vex-annotations.json 或 Dependency-Track 分析）改判定，這裡沒有自動套用的開關。
    UB1：函式庫不在所有出貨映像（完整解開，弱標記要 DSC 佐證）→ 建議 not_affected／code_not_present；這一列已經是關閉的判定就不建議。
    UB2：函式庫確實編進映像 → 只在目前的判定是「是否編進韌體、工具確認不了」這一類 in_triage（例如批次規則 R9m）時建議 exploitable。
    其他情形（沒有映像檢查結果、not_assessed）→ 不建議（並移除舊的）。"""
    c = row.get("uefi_image_check")
    sg = None
    cur = (winner or {}).get("state")
    if isinstance(c, dict):
        if c.get("result") == "absent" and cur not in ("not_affected", "false_positive", "resolved"):
            sg = {"rule": UB_ABSENT, "state": "not_affected", "justification": "code_not_present",
                  "detail": uefi_image_detail(c), "needs": "RD confirmation"}
        elif c.get("result") == "present" and winner and winner.get("source") == "rule" and cur == "in_triage" and not winner.get("evidence") \
                and re.search(r"built[- ]?in[^.]*not confirmed|not confirmed[^.]*built[- ]?in", str(winner.get("detail") or ""), re.I):
            sg = {"rule": UB_PRESENT, "state": "exploitable", "justification": None,
                  "detail": uefi_image_detail(c), "needs": "RD confirmation"}
    set_suggestion(row, sg, UB_RULES)


def is_nv_bulletin_row(row):
    """NVIDIA 公告另加的列（nvidia_extra）。tier 可能已升為 p1（已遭利用），所以另看 row["nvidia_bulletin"]。"""
    return row.get("tier") == "nvidia_bulletin" or bool(row.get("nvidia_bulletin"))


def nvidia_distro_suggest(row, ndistro):
    """NVIDIA 公告的列（nvidia-l4t 元件，只有一個 CVE）的 CVE 其實是發行版套件的 CVE（ndistro＝nvidia_distro.remap 的結果）：
    只記錄**建議**，不改判定、不產生 VEX 陳述（客戶看到的 VEX 與以前完全一樣）。row["nvidia_distro"]＝分析結果（一律記下，含 ambiguous 的原因）；
    row["suggestion"]＝{rule, state, justification, basis, detail, needs}（不是 ambiguous 時）：N1＝建議不受影響／已修補、N2＝建議受影響
    （指向發行版套件的列）。要採用必須由 RD 走人的判定路徑（vex-annotations.json 或 Dependency-Track 的分析）。"""
    if not ndistro or not (is_nv_bulletin_row(row) or str(row.get("name") or "").startswith("nvidia-l4t")):
        return
    cves = [str(c).upper() for c in row.get("cves") or []]
    res = ndistro.get(str(row.get("id") or "").upper())
    if len(cves) != 1 or not res or cves[0] != str(row.get("id") or "").upper():
        return
    set_suggestion(row, None, N_RULES)
    row["nvidia_distro"] = {k: res.get(k) for k in ("state", "package", "binaries", "version", "basis", "detail", "binary_note", "db", "fixed")}
    if res["state"] == "ambiguous":
        return
    text = nvidia_distro.statement_text(res, cves[0])
    closed = res["state"] in ("not_affected", "resolved")
    if not closed:
        text += f" The distribution data says it is affected: see the row of {res['package']} (the Ubuntu/Debian package rows of this CVE)."
    set_suggestion(row, {"rule": "N1" if closed else "N2", "state": res["state"], "justification": res.get("justification") if closed else None,
                         "basis": res.get("basis"), "detail": text, "needs": "RD confirmation"}, N_RULES)


def nvidia_extra(nvb, rows, exploited=frozenset(), sources=None):
    """NVIDIA 公告裡沒有 DT／NVIDIA finding 的 CVE（presumed_included、needs_vendor_confirmation）：
    回傳 ({CVE: 推定已含修正的判定}, 另加的列)。已有 nvidia-l4t 元件上同一個 CVE 的列時套用到那一列，不另加。
    exploited：已遭利用的 CVE 集合（scan/euvd.json 標示 exploited，含人工證據；大寫）。公告列的 CVE 在裡面時，這一列和其他列一樣
    是被利用的列：tier p1、exploited_sources 記真正的來源（sources＝{CVE: [標籤]}，例如 EUVD (CISA KEV)、manual: …）。
    不設 kev（那是 DT／Grype 的 KEV 標記；只有 EUVD 或人工證據時不寫成 KEV）。cra_report 通常已先把這種 CVE 做成真正的列，這裡是備援。"""
    if not isinstance(nvb, dict) or not nvb.get("jetson_linux"):
        return {}, []
    jl = nvb["jetson_linux"]
    anchor = jl.get("anchor") or {}
    line = jl.get("line")
    presumed, extra = {}, {}
    by_cve = {}
    for x in nvb.get("presumed_included") or []:
        if isinstance(x, dict) and x.get("cve"):
            by_cve.setdefault(x["cve"], {"presumed": [], "confirm": []})["presumed"].append(x)
    for x in nvb.get("needs_vendor_confirmation") or []:
        if isinstance(x, dict) and x.get("cve"):
            by_cve.setdefault(x["cve"], {"presumed": [], "confirm": []})["confirm"].append(x)
    for cve, g in sorted(by_cve.items()):
        if g["presumed"] and not g["confirm"]:       # 同一個 CVE 另有公告要原廠確認時，不推定
            bl = sorted({f"{x.get('bulletin')} ({str(x.get('bulletin_date') or 'date unknown')[:10]})" for x in g["presumed"]})
            presumed[cve] = stmt("nvidia", "in_triage",
                                 f"NVIDIA security bulletin {', '.join(bl)} does not name Jetson Linux line {line}. This release "
                                 f"(Jetson Linux {jl.get('version')}, built {jl.get('build_date') or 'date unknown'}) was built after the "
                                 "bulletin, so the fix is presumed to be included. NVIDIA has not confirmed this; this is not a statement "
                                 "that the release is not affected.")
        on_l4t = [r for r in rows if cve in (r.get("cves") or []) and str(r.get("name") or "").startswith("nvidia-l4t")]
        if not on_l4t and anchor.get("name"):
            extra[cve] = {"id": cve, "cves": [cve], "all_ids": [cve], "key": [cve, str(anchor.get("name")).lower(), anchor.get("version") or ""],
                          "component": anchor.get("name"), "name": anchor.get("name"), "version": anchor.get("version") or "",
                          "purl": anchor.get("purl") or "", "ptype": "deb", "severity": "UNASSIGNED", "kev": False, "epss_pct": None,
                          "tier": "nvidia_bulletin", "kernel": False, "analysis": [], "installed_as": [], "mapped_from": None,
                          "source_ids": sorted({f"NVIDIA:{x.get('bulletin')}" for x in g["presumed"] + g["confirm"]}),
                          "nvidia_bulletin": "presumed_included" if cve in presumed else "needs_vendor_confirmation"}
            if cve.upper() in exploited:
                extra[cve].update(tier="p1", exploited_sources=list((sources or {}).get(cve.upper()) or ["exploited (source not recorded)"]))
    return presumed, [extra[c] for c in sorted(extra)]


INHERITABLE = ("dt", "annotation")


def is_source_row(d):
    return "arch=source" in str(d.get("purl") or "")


def inherit_deb_python(rows):
    """Debian／Ubuntu 打包的 Python 模組的列（cra_report.apply_deb_python 的 row["deb_python"]，有唯一的擁有者）自己沒有判定時，
    沿用同一個編號、在擁有它的 deb 套件那一列的人工判定：裝在系統上的是同一份程式，修補也是靠更新那個 deb 套件。
    對到的 deb 列（版本＝擁有者安裝的版本）：擁有者的二進位套件本身；或原始碼套件的列（purl 是 arch=source、名稱＝擁有者的原始碼套件）；
    或 installed_as 含擁有者的列。只是名稱和原始碼套件相同的「二進位」套件不算（例如 brotli 指令工具不是裝 python3-brotli 的套件）。
    只沿用人逐筆的判定（INHERITABLE：DT 人工分析、vex-annotations.json）：
      - 批次規則不沿用（這些列本來就不套規則）；
      - 發行版已修補（distro）不沿用：它的證據（Ubuntu 紀錄涵蓋這一列的來源編號）是對 deb 列檢查的，這一列的 GHSA 等來源沒有檢查，
        而且 deb 列移到 distro_fixed、這一列沒有，風險評估會不一致。
    不沿用的情況：deb 列的 DT 判定只涵蓋部分 finding（dt_partial）；這一列是 KEV（要人對這一列自己判定）、在 DT 裡已有人設的分析（缺理由或沒採用）或 suppress（人已經看過這一列）；
    對到的 deb 列判定分類不同 → 記在 vex_note，留給人判定。回傳統計（Counter 的鍵）。"""
    by_id = {}
    for d in rows:
        # DT 的判定只涵蓋這一列部分的 finding（dt_partial）：deb 列本身由 tier_of 留在 P1–P3，沿用的列不能因此被關掉
        if d.get("ptype") == "deb" and d.get("vex") and d["vex"]["source"] in INHERITABLE \
                and not (d["vex"]["source"] == "dt" and d.get("dt_partial")):
            by_id.setdefault(str(d.get("id") or "").upper(), []).append(d)
    st = Counter()
    for x in rows:
        o = (x.get("deb_python") or {}).get("owner")
        if not o or x.get("vex") or dt_decided(x) or any(a.get("suppressed") for a in x.get("analysis") or []):
            continue
        oname, osrc, over = (str(o.get(k) or "").lower() for k in ("name", "source", "version"))

        def owns(d):
            n = str(d.get("name") or "").lower()
            return (n == oname and not is_source_row(d)) or (n == osrc and is_source_row(d)) \
                or oname in [str(b).lower() for b in d.get("installed_as") or []]
        hit = sorted((d for d in by_id.get(str(x.get("id") or "").upper(), [])
                      if str(d.get("version") or "").lower() == over and owns(d)),
                     key=lambda d: (is_source_row(d), d["vex"]["source"] != "annotation", str(d.get("component"))))
        if not hit:
            continue
        if x.get("kev"):
            x["vex_note"] = (f"KEV: the Ubuntu package row {hit[0]['component']} {hit[0]['version']} has a decision "
                             f"({hit[0]['vex']['state']}), not inherited; decide this row by hand")
            st["deb_python_kev_not_inherited"] += 1
            continue
        if len({BUCKET[d["vex"]["state"]] for d in hit}) > 1:
            x["vex_note"] = ("the deb package rows for this Python module disagree ("
                             + ", ".join(f"{d['component']} {d['vex']['state']}" for d in hit) + "): not inherited, decide by hand")
            st["deb_python_inherit_conflict"] += 1
            continue
        d = hit[0]
        how = (f"the Ubuntu source package {d['component']} {d['version']}, from which {o.get('name')} (which installed this module) is built"
               if is_source_row(d) else f"the Ubuntu package {d['component']} {d['version']}, which installed this module")
        x["vex"] = dict(d["vex"], detail=f"inherited from the decision on {how}: " + str(d["vex"].get("detail") or ""),
                        inherited_from={"id": d["id"], "component": d.get("component"), "version": d.get("version")})
        st["deb_python_inherited"] += 1
    return st


def owning_deb_rows(x, rows_by_id, o=None):
    """Ubuntu 打包的 Python 模組的列 x → 同一個編號、在擁有它的 deb 套件 o（預設 deb_python 的 owner）上的列（同 inherit_deb_python
    的對法：擁有者的二進位套件、擁有者的原始碼套件的 arch=source 列，或 installed_as 含擁有者；版本＝擁有者安裝的版本）。"""
    o = o or (x.get("deb_python") or {}).get("owner") or {}
    oname, osrc, over = (str(o.get(k) or "").lower() for k in ("name", "source", "version"))

    def owns(d):
        n = str(d.get("name") or "").lower()
        return (n == oname and not is_source_row(d)) or (n == osrc and is_source_row(d)) \
            or oname in [str(b).lower() for b in d.get("installed_as") or []]
    return sorted((d for d in rows_by_id.get(str(x.get("id") or "").upper(), [])
                   if str(d.get("version") or "").lower() == over and owns(d)),
                  key=lambda d: (is_source_row(d), str(d.get("component"))))


def deb_python_rules(rows, rules, stats, ctx, exploited=frozenset()):
    """Ubuntu 打包的 Python 模組的列（有唯一的擁有者，自己沒有判定，批次規則在 apply_rules 被 excluded_deb_python 擋下）：裝在系統上的
    是擁有它的 deb 套件的同一份程式，所以
      - 擁有它的 deb 套件有這個編號的列、那一列的判定是一般批次規則（不是證據規則）→ 沿用那條規則的陳述（規則編號、狀態、response、
        detail、修補版本），detail 寫「inherited from <deb> <版本>」；那幾列的規則判定分類不同 → vex_note，留給人；
        那一列沒有判定或是別的來源（人的判定由 inherit_deb_python 處理；發行版已修補不沿用）→ 不動；
      - 擁有它的 deb 套件沒有這個編號的列 → 以擁有者的 purl（purl_type deb）、名稱與版本把批次規則直接套在這一列（修補狀態已是
        Ubuntu 的：cra_report.apply_deb_python 或 apply_ubuntu_tracker）。
    KEV／被利用的列一律不沿用、不套用；P1 只在規則有 allow_p1 時。DT 裡人設過分析或 suppress 的列不動。
    擁有者不明、但候選都來自同一個原始碼套件、同一個版本（deb_python 的 source_owner）的列也照這樣做，擁有者用 source_owner、
    修補狀態用 deb_python 的 source_owner_fix（這一列自己的修補欄、嚴重度、層級與人工判定的沿用都照擁有者不明時）。回傳統計（Counter 的鍵）。"""
    by_id = {}
    for d in rows:
        if d.get("ptype") == "deb" and not d.get("deb_python"):
            by_id.setdefault(str(d.get("id") or "").upper(), []).append(d)
    rid = {ru["id"]: (ru, st) for ru, st in zip(rules, stats)}
    st = Counter()

    def resolved(x):
        # 這一列在 apply_rules 記成 excluded_deb_python 的那條規則：拿掉（最後是沿用或以擁有者套用，每一列只算一次）
        for s in stats:
            for i, r in enumerate(s["dp_excluded_rows"]):
                if r is x:
                    s["excluded_deb_python"] -= 1
                    del s["dp_excluded_rows"][i]
                    return
    for x in rows:
        dp = x.get("deb_python") or {}
        o = dp.get("owner") or dp.get("source_owner")
        if not o or x.get("vex") or dt_decided(x) or any(a.get("suppressed") for a in x.get("analysis") or []):
            continue
        # Ubuntu 的修補狀態：有擁有者時就是這一列的（cra_report.apply_deb_python 改過），source_owner 時記在 source_owner_fix
        fx = {k: x.get(k) for k in ("fix_state", "fix_versions", "fix_next", "fix_state_detail")} if dp.get("owner") \
            else {k: (dp.get("source_owner_fix") or {}).get(k) for k in ("fix_state", "fix_versions", "fix_next", "fix_state_detail")}
        # source_owner（擁有者不明、候選都來自同一個原始碼套件）：陳述與處理說明列出全部候選套件，不說是哪一個裝的
        cands = [str(c).rsplit(" ", 1)[0] for c in dp.get("candidates") or []] if not dp.get("owner") else []
        pkgs = " ".join(cands) if cands else o.get("name")
        who = (f"the Ubuntu packages built from source package {o.get('source')} ({', '.join(cands)} {o.get('version')}), one of which "
               "installed this module") if cands else None
        hits = owning_deb_rows(x, by_id, o)
        if hits:
            if any(d.get("vex") and d["vex"]["source"] != "rule" for d in hits):
                continue
            rh = [d for d in hits if d.get("vex") and not d["vex"].get("evidence")]
            if not rh:
                continue
            if on_kev(x, exploited):
                st["deb_python_rule_kev_not_inherited"] += 1
                continue
            ev = [d for d in hits if d.get("vex") and d["vex"].get("evidence")]
            if ev:
                # 擁有者的列一邊是證據規則（U1／K1／K2 的 not_affected）、一邊是批次規則：結論來源不同，不沿用，留給人
                x["vex_note"] = ("the deb package rows for this Python module have an evidence-rule decision and a bulk-rule decision ("
                                 + ", ".join(f"{d['component']} {d['vex'].get('rule')} {d['vex']['state']}" for d in ev + rh)
                                 + "): not inherited, decide by hand")
                st["deb_python_rule_evidence_conflict"] += 1
                continue
            if len({BUCKET[d["vex"]["state"]] for d in rh}) > 1 or len({d["vex"].get("rule") for d in rh}) > 1:
                x["vex_note"] = ("the deb package rows for this Python module have different bulk-rule decisions ("
                                 + ", ".join(f"{d['component']} {d['vex'].get('rule')} {d['vex']['state']}" for d in rh) + "): not inherited, decide by hand")
                st["deb_python_rule_inherit_conflict"] += 1
                continue
            d = rh[0]
            ru, rs = rid.get(d["vex"].get("rule"), (None, None))
            if ru is None:
                continue
            if (x.get("tier") == "p1" or x.get("tier_before") == "p1") and not ru["match"].get("allow_p1"):
                st["deb_python_rule_p1_not_inherited"] += 1
                continue
            # 規則自己的條件（層級、嚴重度、EPSS…）要對這一列也成立：purl 類型與修補狀態看擁有者（Ubuntu 的），其他用這一列自己的值
            cview = dict(x, purl=o.get("purl") or "", ptype="deb", deb_python=None, kernel=False, **fx)
            if not rule_criteria(ru, cview, None):
                st["deb_python_rule_criteria_not_met"] += 1
                continue
            how = (who if who else f"the Ubuntu source package of {o.get('name')}, which installed this module" if is_source_row(d)
                   else "the Ubuntu package that installed this module")
            x["vex"] = dict(d["vex"], detail=f"inherited from {d['component']} {d['version']} ({how}): " + str(d["vex"].get("detail") or ""),
                            inherited_from={"id": d["id"], "component": d.get("component"), "version": d.get("version")},
                            **({"fix_version": d["fix_next"]} if d.get("fix_next") else {}))
            if cands and ru["set"].get("recommendation") and x["vex"].get("action_statement"):
                # 處理說明改列全部候選套件（{component}＝它們，{fix_version}＝deb 列的）；範本缺值時照用 deb 列的
                rec = render_template(ru["set"]["recommendation"], dict(template_values(d, ctx), component=pkgs, installed_version=o.get("version")))
                if rec:
                    x["vex"]["action_statement"] = f"{rec} (bulk rule {ru['id']}: {ru['description'].strip()})"
            rs["inherited_deb_python"] += 1
            st["deb_python_rule_inherited"] += 1
            resolved(x)
            continue
        # 擁有它的 deb 套件沒有這個編號的列：以擁有者套用。統計用另一份（apply_rules 已經以 pypi 算過這一列一次：KEV、排除等不重算），
        # 套用了才把那條規則的 applied 加上、拿掉原本的 excluded_deb_python
        if on_kev(x, exploited):
            continue
        view = dict(x, purl=o.get("purl") or "", ptype="deb", component=pkgs, version=o.get("version"), deb_python=None, kernel=False,
                    **fx)
        tmp = new_rule_stats(rules)
        res = apply_rules(view, rules, tmp, None, None, ctx, exploited)
        if res:
            for s, t in zip(stats, tmp):
                if t["applied"]:
                    s["applied"] += 1
                    s["non_kernel"] += 1
                    s["rows"].append(view)
            resolved(x)
            res["detail"] = ((f"applied to {who} " if who else f"applied to the Ubuntu package {o.get('name')} {o.get('version')}, which installed this module ")
                             + f"({x.get('component')} {x.get('version')}): " + res["detail"])
            res["applied_via_owner"] = {"purl": o.get("purl"), "name": o.get("name"), "version": o.get("version")}
            if fx.get("fix_next"):
                res["fix_version"] = fx["fix_next"]
            x["vex"] = view["vex"] = res
            st["deb_python_rule_direct"] += 1
    return st


def assess(rows, drc=None, kcfg=None, nvb=None, annotations=(), rules=(), rule_ctx=None, project=None):
    """每一列加上 row["vex"]（判定或 None）與 row["vex_note"]。回傳 (全部的列（含 NVIDIA 另加的列）, 衝突清單, 摘要)。
    rules：vex-rules.json 的規則，只用在其他來源都沒有判定的列（apply_rules）。rule_ctx：{"kernel_fix_all": {核心元件: 版本},
    "exploited": CVE 集合（scan/euvd.json 標示已遭利用）}。
    project：專案資料夾（cra_report 的 --project）。annotation 的 on-device 依據要檢查檔案是否在專案資料夾內（on_device_problem）；
    沒給時 on-device 依據不通過（原因 on_device_no_project）。"""
    didx, kidx = distro_rows(drc), kconfig_index(kcfg)
    kall = kconfig_all(kcfg) if rules else {}
    # 證據規則（evidence）在 match 規則之前、依檔案順序；有生效的 K1 時，核心設定檢查的 not_affected 改由規則 K1 套用（不再是自動的來源 (c)）
    erules = [r for r in rules if r.get("evidence")]
    rules = [r for r in rules if not r.get("evidence")]
    ec = evidence_context(kcfg, rule_ctx) if erules else None
    estats = new_evidence_stats(erules, ec) if erules else []
    # 只有「生效」的 K1（具名的責任人、映像符合、生效日已到）才把核心設定的結果改由規則套用；沒有生效的 K1（例如照抄範例、
    # 責任人還是佔位字）照舊：核心設定檢查仍是自動的來源 (c)（KEV 的列也和以前一樣）
    kidx_src = {} if any(r["evidence"] == "K1" and not st["inactive"] for r, st in zip(erules, estats)) else kidx
    rstats = new_rule_stats(rules)
    exploited = frozenset(str(c).upper() for c in (rule_ctx or {}).get("exploited") or ())
    presumed, extra = nvidia_extra(nvb, rows, exploited, (rule_ctx or {}).get("exploited_sources"))
    ndistro = (rule_ctx or {}).get("nvidia_distro") or {}
    used, conflicts = set(), []
    allrows = list(rows) + extra
    notes = Counter()
    # 映像另有出貨但沒判定的核心（kernel-versions.json，kernel_with_scope）：K1／K2 的排除不採用（kconfig_usable、module_map_of），
    # 但說明哪些核心列「本來會被排除」，寫在那一列的 vex_note 與摘要，留給人判定
    mm_doc = (rule_ctx or {}).get("module_map")
    scope_txt = kernel_scope_note(kcfg) or kernel_scope_note(mm_doc)
    kfull = kconfig_index({k: v for k, v in kcfg.items() if k != "scope_incomplete"}) if scope_txt and isinstance(kcfg, dict) else {}
    mm_cves = {str(c).upper() for c in (mm_doc.get("cves") or {})} if scope_txt and isinstance(mm_doc, dict) and isinstance(mm_doc.get("cves"), dict) else set()

    def scope_withheld(r):
        if not scope_txt or not r.get("kernel"):
            return False
        cves = [str(c).upper() for c in r.get("cves") or []]
        k1 = bool(cves) and all(c in kfull for c in cves) and kconfig_component_matches(r, kcfg)
        return k1 or any(c in mm_cves for c in cves)

    def judge(r, extra_cve=False):
        cands = []
        d, dconf, partial, dbad = from_dt(r)
        if d:
            cands.append(d)
        a, aconf = from_annotations(r, list(annotations), used, project)
        if a:
            cands.append(a)
        for s in (from_distro(r, didx), from_kconfig(r, kidx_src, kcfg or {})):
            if s:
                cands.append(s)
        # NVIDIA 公告的 CVE 其實是發行版套件的（nvidia_distro.remap）：只記建議（row["suggestion"]），不改判定
        nvidia_distro_suggest(r, ndistro)
        # 推定只用在這一列的編號本身（陳述寫在 row["id"] 下），而且這一列的每個 CVE 都是推定已含修正
        if r["id"] in presumed and all(c in presumed for c in r.get("cves") or []) \
                and (is_nv_bulletin_row(r) or str(r.get("name") or "").startswith("nvidia-l4t")):
            cands.append(presumed[r["id"]])
        if rules or erules:
            # 規則最後：只在沒有任何其他判定時套用，不會覆蓋；被蓋過的記在統計（證據規則另記在這一列的 rule_shadowed，
            # 結論不同時照樣列為衝突，和原本的核心設定來源一樣）。
            # DT 有人設的分析、只是沒有採用時也不套用（缺理由，或分析在別名含這一列 CVE 的 finding 上，例如 GHSA 的別名是
            # CVE-A、CVE-B）：人已經下了結論，不能讓規則寫一個可能相反的陳述。DT 裡 suppress 的列同樣不套用
            existing = cands[0] if cands else ({"source": "dt"} if dbad.get("no_justification") or dt_decided(r) else
                                               {"source": "dt_suppressed"} if any(x.get("suppressed") for x in r.get("analysis") or [])
                                               else None)
            es, shadow = apply_evidence(r, erules, estats, existing, ec, exploited) if erules else (None, None)
            if shadow:
                cands.append(shadow)
            if es:
                cands.append(es)
            rs = apply_rules(r, rules, rstats, existing or es, kconfig_decision(r, kall, kcfg), rule_ctx, exploited) if rules else None
            if rs:
                cands.append(rs)
        # 候選的判定衝突時取最保守的（exploitable < in_triage < 已關閉〔resolved、not_affected〕），同樣保守時維持原本的來源順序
        # （dt > annotation > distro > kconfig > 規則）。不是「第一個」：舊的 DT not_affected 不能蓋過較新、具名的 exploitable／in_triage 註記，
        # 自動來源排在人的判定後面（被利用的列也一樣）。被蓋過的在下面列為衝突。
        # 只有人的來源（dt、annotation）之間比保守程度；自動來源（nvidia 推定、distro、kconfig、規則）維持原本的位置，
        # 不會因為「比較保守」（例如 NVIDIA 推定的 in_triage）而蓋過人的關閉結論
        if len(cands) > 1:
            hum = sorted((c for c in cands if c["source"] in HUMAN), key=lambda g: CONSERVATIVE[BUCKET[g["state"]]])   # sort 穩定
            cands[:] = hum + [c for c in cands if c["source"] not in HUMAN]
        r["vex"] = cands[0] if cands else None
        uefi_image_suggestion(r, r["vex"])      # 只加建議（row["suggestion"]），不改判定
        if r["vex"] and r.get("vex_markers"):
            # 證據規則的標記（K3、K4…）只說明「這條規則為什麼沒套用」：這一列之後被別的規則或來源判定了，就拿掉
            r["vex_markers"] = [m for m in r["vex_markers"] if not m.get("rule")]
        r["vex_note"] = ""
        r["dt_unusable"] = dbad if not d else {}
        if extra_cve:
            # 另一個 CVE 的 finding（例如別名是 CVE-A、CVE-B 的 GHSA）對這個 CVE 本來就是 other_vulnerability，不算註記
            r["dt_unusable"] = {k: v for k, v in r["dt_unusable"].items() if k != "other_vulnerability"}
        r["dt_partial"] = bool(partial and d)
        if partial and d:
            r["vex_note"] = "only some of the Dependency-Track findings merged into this row have a usable analysis"
            notes["dt_partial"] += 1
        if r["dt_unusable"].get("no_justification"):
            r["vex_note"] = (f"Dependency-Track analysis {', '.join(sorted(set(dbad['no_justification'])))} without justification "
                             "(not used as a VEX statement)")
            notes["dt_without_justification"] += 1
        if r["dt_unusable"].get("other_vulnerability"):
            notes["dt_other_vulnerability"] += 1
        if not cands and r.get("analysis") and all(x.get("suppressed") for x in r["analysis"]):
            r["vex_note"] = "suppressed in Dependency-Track without an analysis state (suppression is not a VEX status)"
            notes["suppressed_without_state"] += 1
        if r.get("rule_excluded_kev"):
            x = r["rule_excluded_kev"]
            r["vex_note"] = ((r["vex_note"] + "; ") if r["vex_note"] else "") + (
                f"evidence rule {x['rule']} [{x['evidence']}] would set {x.get('would_set', 'not_affected')}: {x['detail']} – not applied because the row is "
                "exploited (KEV, EUVD or manual evidence); decide by hand")
        if not r["vex"] and scope_withheld(r):
            r["vex_note"] = ((r["vex_note"] + "; ") if r["vex_note"] else "") + scope_txt
            r.setdefault("vex_markers", []).append({"code": "kernel_scope", "rule": None, "gap": False, "detail": scope_txt})
            notes["kernel_scope_withheld"] += 1
        return cands, d, dconf, aconf

    # 已經有自己一列的（CVE, 元件, 版本）：由那一列判定，不再從別列拆出來（否則同一個 CVE 在同一個元件上會有兩條陳述、各自判定、互相看不到）
    owned = {(str(r.get("id") or "").upper(), *(str(k) for k in (r.get("key") or ["", "", ""])[1:3])) for r in allrows}
    split = {}   # 拆出來的 (CVE, 元件, 版本) → 那一份（extra_of 記所有來源列，以「, 」分隔）
    for r in allrows:
        # 一列可能併了好幾個 CVE（例如 GHSA 的別名同時是 CVE-A 與 CVE-B，列在 CVE-A）。這一列的判定只寫在 row["id"] 下，
        # 其他 CVE 各自另外判定（每個 CVE 一個 vex_extra 項目；判定檔要寫那個 CVE 加 purl），沒有判定的由閘門點名。
        # all_ids 只留這個 CVE：GHSA 的判定在原本那一列不採用（別名不只一個 CVE），在這裡也不採用。
        r["vex_extra"] = []
        rid = str(r.get("id") or "").upper()
        rkey = [str(k) for k in (r.get("key") or ["", "", ""])[1:3]]
        for c in sorted({str(x).upper() for x in r.get("cves") or []} - {rid}):
            if (c, *rkey) in owned:
                # 已有自己一列，或已經從別列拆出來（兩列的別名都含這個 CVE）：只記下多一個來源列，不再拆第二份
                prev = split.get((c, *rkey))
                if prev is not None and r["id"] not in prev["extra_of"].split(", "):
                    prev["extra_of"] += ", " + r["id"]
                    prev["source_ids"] = sorted(set(prev["source_ids"]) | {x for x in r.get("source_ids") or []
                                                                         if c in str(x).upper() or not CVE_ID.search(str(x).split(":", 1)[-1])})
                continue
            owned.add((c, *rkey))
            rc = {k: v for k, v in r.items() if k != "vex_extra"}
            # source_ids 只留提到這個 CVE 的來源與非 CVE 的公告（GHSA 等，別名含這個 CVE 才會併進這一列）：
            # 這一列自己的 NVD:CVE-A 不是 CVE-B 的來源。KEV、EPSS、tier、嚴重度沒有逐個 CVE 的資料，沿用這一列的（只影響排序，偏保守）
            sids = [x for x in r.get("source_ids") or [] if c in str(x).upper() or not CVE_ID.search(str(x).split(":", 1)[-1])]
            rc.update(id=c, cves=[c], all_ids=[c], extra_of=r["id"], source_ids=sids)
            split[(c, *rkey)] = rc
            r["vex_extra"].append(rc)
        for x in [r] + r["vex_extra"]:
            cands, d, dconf, aconf = judge(x, x is not r)
            win = x["vex"]
            if not win:
                continue
            # 衝突＝分類不同（例如 resolved 與 exploitable）；同一分類只是理由不同不算。同一來源內的不同判定（DT 的多筆 finding、
            # 同樣精確的多筆 annotation）也列出
            for o in cands[1:] + [y for y in dconf if y is not d] + aconf:
                if BUCKET[o["state"]] == BUCKET[win["state"]]:
                    continue
                conflicts.append({"id": x["id"], "component": x.get("component"), "version": x.get("version"),
                                  "used": f"{win['source']}:{win['state']}", "other": f"{o['source']}:{o['state']}",
                                  "human": o["source"] in HUMAN and win["source"] in HUMAN})
            if win["source"] == "rule" and x.get("rule_conflicts"):
                # K2 判已移除、kernel-config 說 affected：兩個結論並列（核心設定只看 .config，K2 另看映像的模組清單）
                for c in x["rule_conflicts"]:
                    conflicts.append({"id": x["id"], "component": x.get("component"), "version": x.get("version"),
                                      "used": f"rule:{win['state']} ({c['rule']})",
                                      "other": f"{c['other']} ({c['cve']}: {c['detail'] or 'no detail'})", "human": False})
    ext = [x for r in allrows for x in r["vex_extra"]]
    if any(r["evidence"] == "U2" for r in erules):
        u2_defer_to_owner(allrows + ext, erules, estats, conflicts)
    notes.update(inherit_deb_python(allrows + ext))
    if rules:
        # 批次規則被 excluded_deb_python 擋下的 Ubuntu 打包 Python 模組：沿用擁有它的 deb 列的規則判定，或以擁有者套用（deb_python_rules）
        notes.update(deb_python_rules(allrows + ext, rules, rstats, rule_ctx, exploited))
    conflicts.sort(key=lambda c: (not c["human"], c["id"], str(c["component"]), str(c["version"]), c["other"]))
    info = {"sources": {s: sum(1 for r in allrows + ext if r["vex"] and r["vex"]["source"] == s) for s in SOURCES},
            "extra_cves": {"total": len(ext), "with_statement": sum(1 for x in ext if x["vex"])},
            "nvidia_extra_rows": len(extra), "nvidia_presumed": len(presumed),
            "annotations_used": len(used), "annotations_unused": sorted(i for i in range(len(annotations)) if i not in used),
            "kernel_config": None if not isinstance(kcfg, dict) else {"status": kcfg.get("status"), "not_affected": len(kidx),
                                                                       "used": kidx != {} and kcfg.get("schema") == KCFG_SCHEMA,
                                                                       **({"scope_incomplete": True, "scope": kcfg.get("scope"), "rows_withheld": notes["kernel_scope_withheld"]}
                                                                          if kcfg.get("scope_incomplete") else {})},
            "distro_fixed_available": len(didx), "rules": evidence_summary(erules, estats) + rule_summary(rules, rstats),
            "kernel_config_via_rule": kidx_src is not kidx,
            "u1_excluded": u1_exclusions(allrows + ext, erules),
            **({"u2_resolved": u2_resolved(allrows + ext, erules)} if any(r["evidence"] == "U2" for r in erules) else {}),
            "markers": marker_counts(allrows + ext),
            "rule_shadowed_rows": sum(1 for x in allrows + ext if x.get("rule_shadowed")),
            "evidence": exclusion_evidence(allrows + ext),
            "evidence_inputs": None if ec is None else {
                "kernel_config_sha256": ec["kcfg_sha"], "module_map": ec["mm_problem"] or "OK", "kernel_modules": ec["km_problem"] or "OK",
                "kernel_modules_sha256": (ec["km"] or {}).get("sha256"), "ubuntu_status": ec["us_problem"] or "OK",
                "ubuntu_tracker_commit": ((ec["us"] or {}).get("mirror") or {}).get("commit"),
                "ubuntu_tracker_fetched": ((ec["us"] or {}).get("mirror") or {}).get("fetched_utc"),
                "ubuntu_tracker_age_days": snapshot_age_days(((ec["us"] or {}).get("mirror") or {}).get("fetched_utc"), ec["today"]),
                "ubuntu_mirror_counts": (ec["us"] or {}).get("mirror_counts"), "images": sorted(ec["images"])}, **notes}
    return allrows, conflicts, info


# ---------- 排除的依據（M7c-2，D-035／D-057） ----------

def is_exclusion(s):
    """排除＝BUCKET 是 resolved 或 not_affected 的陳述（含 false_positive、resolved_with_pedigree）。"""
    return bool(s) and BUCKET[s["state"]] in EVIDENCE_BUCKETS


def exclusion_basis(s):
    """一筆排除的陳述 → (依據清單, None)；沒有類型 → ([], 原因代號)。
    有類型＝陳述帶 evidence_basis（工具來源在建立陳述時算好；annotation 在 annotation_evidence，on-device 通過檔案檢查才有）。
    dt（人在 Dependency-Track 的判定）沒有放依據的欄位，一律沒有類型。"""
    if s.get("evidence_basis"):
        return s["evidence_basis"], None
    return [], s.get("evidence_missing") or {"dt": "dt", "annotation": "annotation_no_evidence"}.get(s.get("source"), "no_basis")


def exclusions_without_type(rows):
    """沒有依據類型的排除 → [(列, 原因代號)]，依優先順序排序（rows＝所有列加上 vex_extra 的別名列）。"""
    out = [(x, exclusion_basis(x["vex"])[1]) for x in rows if is_exclusion(x.get("vex")) and not exclusion_basis(x["vex"])[0]]
    return sorted(out, key=lambda t: priority_key(t[0]))


def exclusion_evidence(rows):
    """排除的依據統計（summary.json 的 vex.evidence、風險評估的 VEX 小節）。
    exclusions：排除的陳述數；by_type：五種類型各有幾筆排除（一筆排除有多種類型時每種各算一次，同一種類型的多筆依據只算一次）；
    with_type：至少有一種類型的排除；without_type：沒有類型的排除（total、by_reason、sample 前 10 筆）；
    on_device、design_doc：依據是 on-device／design-doc 的每一筆（id、component、version、source、location、kernel），全部列出
    （D-035：靠上機核對或設計文件的排除要單獨看）。on-device 只檢查專案資料夾內有這個檔案，沒有驗證內容。"""
    ex = sorted((x for x in rows if is_exclusion(x.get("vex"))), key=lambda x: (x["id"], str(x.get("component")), str(x.get("version"))))
    by_type, untyped, on_dev, design = Counter(), Counter(), [], []
    wt = []
    for x in ex:
        basis, why = exclusion_basis(x["vex"])
        if not basis:
            untyped[why] += 1
            wt.append((x, why))
            continue
        by_type.update({e["type"] for e in basis})
        for e in basis:
            if e["type"] in ("on-device", "design-doc"):
                (on_dev if e["type"] == "on-device" else design).append(
                    {"id": x["id"], "component": x.get("component"), "version": x.get("version"), "source": x["vex"]["source"],
                     "location": e["location"], **({"kernel": e["kernel"]} if e.get("kernel") else {})})
    return {"exclusions": len(ex), "by_type": {t: by_type[t] for t in EVIDENCE_TYPES}, "with_type": len(ex) - len(wt),
            "without_type": {"total": len(wt), "by_reason": dict(sorted(untyped.items())),
                             "sample": [{"id": x["id"], "component": x.get("component"), "version": x.get("version"),
                                         "source": x["vex"]["source"], "reason": why} for x, why in
                                        sorted(wt, key=lambda t: priority_key(t[0]))[:10]]},
            "on_device": on_dev, "design_doc": design}


# ---------- 發行閘門 ----------

def bucket_of(r):
    return BUCKET[r["vex"]["state"]] if r.get("vex") else "untriaged"


def priority_key(r):
    # 被利用的列（KEV 或 EUVD；EUVD 不設 kev）同一級。人工證據不在這裡（沒有 scan/euvd.json 時排序不變）
    return (TIER_ORDER.get(r.get("tier"), 3), not (r.get("kev") or on_euvd(r)), -(r.get("epss_pct") or 0),
            {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(r.get("severity"), 4), r["id"], str(r.get("component")), str(r.get("version")))


def untriaged_breakdown(untri, top=15):
    """沒有判定的列分組（給 rules check 找還能加哪些規則）：核心／套件類型 × 修補狀態，各組的 P1–P3；再列數量最多的套件。"""
    def tiers(rs):
        c = Counter(r.get("tier") if r.get("tier") in TIER_ORDER else "other" for r in rs)
        return {t: c[t] for t in ("p1", "p2", "p3", "other") if c[t]}
    groups, comps = {}, {}
    for r in untri:
        pt = row_type(r)
        groups.setdefault((pt, r.get("fix_state") or "none"), []).append(r)
        comps.setdefault((str(r.get("component")), pt), []).append(r)
    return {"groups": [{"type": t, "fix_state": f, "rows": len(rs), "tiers": tiers(rs)}
                       for (t, f), rs in sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0]))],
            "components": [{"component": c, "type": t, "rows": len(rs),
                            "fix_states": dict(Counter(r.get("fix_state") or "none" for r in rs).most_common()), "tiers": tiers(rs)}
                           for (c, t), rs in sorted(comps.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:top]],
            "components_total": len(comps)}


def row_type(r):
    """分組用的類型：kernel、pypi-deb（Debian／Ubuntu 打包的 Python 模組，不是 pip 管理的）、purl 類型，或 none。"""
    if r.get("kernel"):
        return "kernel"
    pt = purl_type(r.get("purl")) or "none"
    return "pypi-deb" if pt == "pypi" and r.get("deb_python") else pt


def open_components(allrows):
    """還沒處理完的列（untriaged、exploitable、in_triage）依元件彙總，列數多的在前（給 pkg_why.py 找「為什麼這個套件在映像裡」）。
    installed_as：DT 以 Debian／Ubuntu 原始碼套件比對時，從它安裝的二進位套件（cra_report 的 dt/deb-sources.json）。"""
    comps = {}
    for r in allrows:
        b = bucket_of(r)
        if b not in ("untriaged", "exploitable", "in_triage"):
            continue
        k = (str(r.get("component")), str(r.get("version") or ""), str(r.get("purl") or ""))
        c = comps.setdefault(k, {"component": k[0], "version": k[1], "purl": k[2],
                                 "type": row_type(r),
                                 "installed_as": sorted(set(r.get("installed_as") or [])), "rows": 0,
                                 "states": Counter(), "tiers": Counter()})
        c["rows"] += 1
        c["states"][b] += 1
        c["tiers"][r.get("tier") if r.get("tier") in TIER_ORDER else "other"] += 1
    out = sorted(comps.values(), key=lambda c: (-c["rows"], c["component"], c["version"]))
    for c in out:
        c["states"], c["tiers"] = dict(sorted(c["states"].items())), {t: c["tiers"][t] for t in ("p1", "p2", "p3", "other") if c["tiers"][t]}
    return out


def gate(allrows, conflicts, data_status="OK", grype_only=0, have_findings=True, top=10, grype_checked=False, not_assessed=None,
         rules_without_author=(), annotations_without_author=(), annotations_unused=()):
    """有 exploitable 的列（含批次規則判定的）→ 不能是 OK：評估完整也要有人做出貨決定（assessment、open_affected 分開回報）。
    grype_checked=False：沒有 Grype 結果或 C-grype 不是 OK，「Grype 有、DT 沒有」的比對沒做 → 不能是 OK。
    grype_only：Grype 有、DT 沒有、又不能成列的公告（數量或說明清單；cra_report 把其他的做成只有 Grype 的列）→ 不能是 OK。
    not_assessed：不在任何一列、也沒有 VEX 狀態的「沒有評估」項目（說明字串的清單，例如 sbomgate 的 SELF_NO_VERSION：Grype 比對到產品本身、
    沒有版本）。None＝呼叫端沒說 → 當作不知道，不能是 OK；空清單＝確認沒有。
    在 KEV 目錄裡、只靠發行版紀錄判 resolved（沒有人的判定）的列也擋：已知被利用，要人確認（cra_report 的資料狀態同樣是 ATTENTION）。
    一列併了多個 CVE 時，row["vex_extra"] 是其他 CVE 各自的判定：沒有判定的另外點名（不能因為 row["id"] 有判定就算整列已評估）。
    沒有依據類型的排除（M7c-2，D-035／D-057；exclusions_without_type：dt 的判定、沒寫依據的 annotation、on-device 的檔案不合格…）和規則設的
    in_triage 一樣算「沒有處理完」：算進 assessment.untriaged_for_gate 與 exclusions_without_evidence、complete 變 false、reasons 加一條
    「N exclusions without evidence type …」（原因分項與前 10 筆）；counts、untriaged、untriaged_by_tier 等其他數字不變。"""
    def cnt(rs):
        c = Counter(bucket_of(r) for r in rs)
        return {"rows": len(rs), **{b: c[b] for b in BUCKETS}}
    k = [r for r in allrows if r.get("kernel")]
    nk = [r for r in allrows if not r.get("kernel")]
    ext = [x for r in allrows for x in r.get("vex_extra") or []]
    untri = sorted((r for r in allrows if not r.get("vex")), key=priority_key)
    ext_un = sorted((x for x in ext if not x.get("vex")), key=priority_key)
    # 批次規則設的 in_triage：沒有人逐列看過，算「沒有評估」（擋評估完整）。NVIDIA 推定的 in_triage 有公告日期當證據，照舊不擋
    rule_tri = [r for r in allrows + ext if r.get("vex") and r["vex"]["source"] == "rule" and r["vex"]["state"] == "in_triage"]
    # 沒有依據類型的排除（D-035／D-057）：和 rule_tri 一樣算「沒有處理完」（擋評估完整），原因與前 10 筆寫在 reasons
    exc = exclusions_without_type(allrows + ext)
    # 批次規則的 exploitable 可以沒有 response（處理說明在 detail／action_statement）；人工判定仍要寫處理方式
    exp_nr = [r for r in allrows + ext if r.get("vex") and r["vex"]["state"] == "exploitable" and not r["vex"].get("response")
              and r["vex"]["source"] != "rule"]
    # 仍受影響（exploitable，含規則判定的）：評估完成不等於可以出貨。CRA Annex I Part I (2)(a)：上市時不能有已知可被利用的弱點，
    # 每一列都要有人做出貨決定（出貨前修好，或寫下以風險為基礎的理由），所以有這種列時閘門不會是 OK
    aff = [r for r in allrows + ext if r.get("vex") and r["vex"]["state"] == "exploitable"]
    aff_resp = Counter("+".join(r["vex"].get("response") or ["none"]) for r in aff)
    aff_rule = sum(1 for r in aff if r["vex"]["source"] == "rule")
    hc = [c for c in conflicts if c["human"]]
    nj = sorted((r for r in allrows + ext if (r.get("dt_unusable") or {}).get("no_justification")), key=priority_key)
    ut = Counter(r.get("tier") if r.get("tier") in TIER_ORDER else "other" for r in untri)
    # EUVD 標示已遭利用的列（cra_report 的 exploited_sources 以 EUVD 開頭；EUVD 不設 kev）也一樣：EUVD 的標記就是 CISA KEV ∪ ENISA EU KEV
    kev_auto = sorted((r for r in allrows + ext if exploited_row(r) and r.get("vex") and r["vex"]["source"] not in HUMAN
                       and BUCKET[r["vex"]["state"]] in ("resolved", "not_affected")), key=priority_key)
    na = None if not_assessed is None else [str(x) for x in not_assessed]
    # 證據規則 K2 的標記：K4＝對不到模組（當作編進核心、受影響；這一列 GAP），K3＝模組可以載入（仍受影響）。不改狀態，只列出
    mk = Counter(c for x in allrows + ext if not x.get("vex") for c in {m["code"] for m in x.get("vex_markers") or []})
    # grype_only：數量，或不能成列的 Grype 公告的說明清單（cra_report；逐一點名）
    go_list = [str(x) for x in grype_only] if isinstance(grype_only, (list, tuple)) else []
    go_n = len(go_list) if isinstance(grype_only, (list, tuple)) else (grype_only or 0)
    reasons = []
    if not have_findings:
        verdict = "NOT_ASSESSED"
        reasons.append("no Dependency-Track findings: the vulnerability status could not be assessed")
    else:
        if untri:
            reasons.append(f"{len(untri)} untriaged (P1 {ut['p1']}, P2 {ut['p2']}, P3 {ut['p3']}, other {ut['other']})")
        if ext_un:
            reasons.append(f"{len(ext_un)} further CVEs merged into a row of another CVE (aliases of the same advisory) have no VEX "
                           "statement of their own: " + ", ".join(f"{x['id']} (row {x['extra_of']}) on {x.get('component')} {x.get('version')}"
                                                                  for x in ext_un[:10]) + (", …" if len(ext_un) > 10 else ""))
        if rule_tri:
            reasons.append(f"set to in_triage by bulk rule, not individually assessed: {len(rule_tri)}")
        if exc:
            by = Counter(why for _, why in exc)
            reasons.append(f"{len(exc)} exclusions without evidence type ("
                           + ", ".join(f"{EVIDENCE_MISSING.get(k, k)} {n}" for k, n in sorted(by.items(), key=lambda kv: (-kv[1], kv[0])))
                           + "): " + ", ".join(f"{x['id']} on {x.get('component')} {x.get('version')} ({x['vex']['source']})" for x, _ in exc[:10])
                           + (", …" if len(exc) > 10 else "")
                           + "; every resolved or not_affected statement needs an evidence type")
        if mk["K4"]:
            reasons.append(f"{mk['K4']} untriaged kernel rows cannot be mapped to a kernel module (K4: treated as built into the kernel "
                           "and affected; GAP for these rows)")
        if rules_without_author:
            reasons.append(f"bulk rules without a named author: {', '.join(rules_without_author)}")
        if annotations_without_author:
            reasons.append(f"{len(annotations_without_author)} decisions in vex-annotations.json without a named author (empty or a "
                           "placeholder such as 專案負責人): " + ", ".join(list(annotations_without_author)[:10])
                           + (", …" if len(annotations_without_author) > 10 else ""))
        if annotations_unused:
            reasons.append(f"{len(annotations_unused)} decisions in vex-annotations.json match no row (wrong CVE, purl or version, or "
                           "no longer reported; remove a decision that no longer applies): " + ", ".join(list(annotations_unused)[:10]) + (", …" if len(annotations_unused) > 10 else ""))
        if exp_nr:
            reasons.append(f"{len(exp_nr)} exploitable without a response")
        if aff:
            reasons.append(("assessment complete; " if not untri and not ext_un and not rule_tri and not exc else "")
                           + f"{len(aff)} affected rows (exploitable; {aff_rule} by bulk rules) need a release decision by a person "
                             "(fixed before placing on the market, or a documented risk-based justification): by response "
                           + ", ".join(f"{k} {n}" for k, n in sorted(aff_resp.items())))
        if hc:
            reasons.append(f"{len(hc)} conflicting human decisions (Dependency-Track vs. annotations)")
        if nj:
            reasons.append(f"{len(nj)} Dependency-Track analyses without justification (NOT_AFFECTED without justification or details, "
                           f"FALSE_POSITIVE without justification; not used): "
                           + ", ".join(f"{r['id']} on {r.get('component')} {r.get('version')}" for r in nj[:10]) + (", …" if len(nj) > 10 else ""))
        if go_n:
            # cra_report 把 Grype 有、DT 沒有的比對做成列（只有 Grype 的列，和其他列一樣判定）；這裡只剩不能成列的（沒有套件名稱與 purl）
            reasons.append(f"{go_n} Grype advisories are not in the Dependency-Track list, could not be listed as rows (no package "
                           "name or purl) and have no VEX status" + (": " + ", ".join(go_list[:10]) + (", …" if len(go_list) > 10 else "")
                                                                     if go_list else ""))
        if not grype_checked:
            reasons.append("Grype cross-check not run (no Grype result or C-grype is not OK): advisories that only Grype reports "
                           "could not be checked")
        if na is None:
            reasons.append("unknown whether some matches were left unassessed (the caller did not report them)")
        elif na:
            reasons.append(f"{len(na)} matches are not assessed and have no VEX status: " + "; ".join(na[:10]) + ("; …" if len(na) > 10 else ""))
        if kev_auto:
            reasons.append(f"{len(kev_auto)} rows in a KEV catalogue are resolved or not affected only by automated checks (no human decision): "
                           + ", ".join(f"{r['id']} on {r.get('component')} {r.get('version')} ({r['vex']['source']})" for r in kev_auto[:10])
                           + (", …" if len(kev_auto) > 10 else ""))
        verdict = "ATTENTION" if reasons else "OK"
        if data_status in ("GAP", "NOT_ASSESSED", "FAIL"):
            verdict = data_status
            reasons.insert(0, f"vulnerability data status is {data_status}: the list of candidate vulnerabilities is incomplete")
    return {"verdict": verdict, "reasons": reasons,
            # (a) 評估是否完整（規則判定的列算已評估）；(b) 仍受影響、要有人做出貨決定的列。兩者分開報告
            "assessment": {"complete": not untri and not ext_un and not rule_tri and not exc, "untriaged": len(untri), "extra_cves_untriaged": len(ext_un),
                           "untriaged_for_gate": len(untri) + len(ext_un) + len(rule_tri) + len(exc),
                           "exclusions_without_evidence": len(exc),
                           "by_rule": sum(1 for r in allrows + ext if r.get("vex") and r["vex"]["source"] == "rule"),
                           "in_triage_by_rule": sum(1 for r in allrows + ext if r.get("vex") and r["vex"]["source"] == "rule"
                                                    and r["vex"]["state"] == "in_triage")},
            "open_affected": {"rows": len(aff), "by_response": dict(sorted(aff_resp.items())), "by_rule": aff_rule,
                              "individual": len(aff) - aff_rule},
            "counts": {"total": cnt(allrows), "kernel": cnt(k), "non_kernel": cnt(nk)},
            "untriaged_by_tier": {t: ut[t] for t in ("p1", "p2", "p3", "other")},
            "untriaged_high": ut["p1"] + ut["p2"], "untriaged_breakdown": untriaged_breakdown(untri),
            "open_components": open_components(allrows),
            "exploitable_without_response": len(exp_nr),
            "in_triage": sum(1 for r in allrows if bucket_of(r) == "in_triage"),
            "human_conflicts": len(hc), "conflicts": len(conflicts), "grype_only_advisories": go_n,
            "rules_without_author": list(rules_without_author),
            "annotations_without_author": list(annotations_without_author), "annotations_unused": list(annotations_unused),
            "not_assessed": na, "kev_without_human_decision": len(kev_auto),
            "untriaged_markers": dict(sorted(mk.items())),
            "grype_cross_check": bool(grype_checked),
            "extra_cves": len(ext), "extra_cves_untriaged": len(ext_un),
            "extra_cves_untriaged_list": [{"id": x["id"], "row": x["extra_of"], "component": x.get("component"),
                                           "version": x.get("version")} for x in ext_un],
            "dt_without_justification": [{"id": r["id"], "component": r.get("component"), "version": r.get("version"),
                                          "states": sorted(set(r["dt_unusable"]["no_justification"]))} for r in nj],
            "top_untriaged": [{"id": r["id"], "cves": r.get("cves") or [], "component": r.get("component"), "version": r.get("version"),
                               "tier": r.get("tier"), "kev": bool(r.get("kev")), "kev_by_cve": bool(r.get("kev_by_cve")), "epss_percentile": r.get("epss_pct"),
                               "severity": r.get("severity"), "kernel": bool(r.get("kernel")),
                               # EUVD 的列（不設 kev）：和風險表的 KEV 欄一致；沒有 EUVD 的列沒有這個鍵（summary.json 不變）
                               **({"exploited_sources": euvd_sources(r)} if on_euvd(r) else {})} for r in untri[:top]]}


def label(r):
    """表格的 VEX status 欄（精簡）：狀態（來源）。"""
    def one(v):
        return f"{v['state']} ({SRC_LABEL[v['source']]}{' ' + v['rule'] if v.get('rule') else ''})" if v else "untriaged"
    def marks(x):
        ms = sorted({MARKER_TEXT.get(m["code"], m["code"]) for m in x.get("vex_markers") or []})
        return f" [{'; '.join(ms)}]" if ms else ""
    s = one(r.get("vex")) + marks(r)
    for x in r.get("vex_extra") or []:
        s += f"; {x['id']}: " + one(x.get("vex")) + marks(x)
    return s


# ---------- 文件 ----------

def bomlink(serial, version, ref):
    return f"urn:cdx:{serial[len('urn:uuid:'):]}/{version}#{urllib.parse.quote(ref, safe=chr(47) + '?:@!$&()*+,;=-._~')}"


def _flatten(comps):
    for c in comps or []:
        if isinstance(c, dict):
            yield c
            yield from _flatten(c.get("components"))


def ref_index(pbom):
    """產品 SBOM 的 bom-ref 索引：purl（完整）、purl base＋版本、名稱＋版本。"""
    full, base, nv = {}, {}, {}
    for c in _flatten(pbom.get("components")):
        ref = c.get("bom-ref")
        if not ref:
            continue
        if c.get("purl"):
            full.setdefault(c["purl"], ref)
            b, v = purl_split(c["purl"])
            base.setdefault((b, v or c.get("version") or ""), set()).add(ref)
        if c.get("name"):
            nv.setdefault((str(c["name"]), str(c.get("version") or "")), set()).add((ref, purl_type(c.get("purl"))))
    return full, base, nv


def purl_type(purl):
    """pkg:npm/foo@1 → "npm"；沒有 purl → None。"""
    m = re.match(r"^pkg:([A-Za-z0-9.+-]+)/", str(purl or ""))
    return m.group(1).lower() if m else None


def _same_ecosystem(refs, ptype):
    """名稱＋版本對元件時，兩邊都有 purl 就要同一種類型（npm 的 foo 1.0 不是 pypi 的 foo 1.0）。"""
    return sorted(ref for ref, t in refs if ptype is None or t is None or t == ptype)


def refs_for(r, idx):
    """一列對應的產品 SBOM 元件 bom-ref（可能多個）。依序：完整 purl → purl base＋版本 → DT 原始碼套件安裝的二進位套件 →
    核心對應的 nvidia-l4t-kernel → 名稱＋版本。都沒有 → 空清單（呼叫端改指向產品主元件並記下）。"""
    full, base, nv = idx
    b, v = purl_split(r.get("purl"))
    # DT 的原始碼套件元件（sca-scan 的 D-dt-deb-sources 加的，arch=source）不在 SBOM：先對到從它安裝的二進位套件
    # （原始碼套件 openssl 也有同名的二進位套件 openssl，只對名稱會漏掉 libssl3t64 等）
    src = "arch=source" in str(r.get("purl") or "").partition("?")[2].split("&")
    if not (src and r.get("installed_as")):
        if r.get("purl") in full:
            return [full[r["purl"]]]
        if b and (b, v or r.get("version") or "") in base:
            return sorted(base[(b, v or r.get("version") or "")])
    if r.get("installed_as") and b and b.startswith("pkg:deb/"):
        ns = b.rsplit("/", 1)[0]
        names = {f"{ns}/{n.lower()}" for n in r["installed_as"]}
        same = {ref for (bb, vv), refs in base.items() if bb in names and vv == (v or r.get("version")) for ref in refs}
        got = same or {ref for (bb, _), refs in base.items() if bb in names for ref in refs}   # 二進位套件版本可能和原始碼不同
        if got:
            return sorted(got)
    pt = purl_type(r.get("purl"))
    if r.get("mapped_from"):
        name, _, ver = str(r["mapped_from"]).partition(" ")
        got = _same_ecosystem(nv.get((name, ver), ()), pt)
        if got:
            return got
    return _same_ecosystem(nv.get((str(r.get("name") or ""), str(r.get("version") or "")), ()), pt)


def doc_timestamp(meta, pbom):
    """VEX 的時間：掃描結束（meta.json 的 finished）→ 開始 → 原始 SBOM 的時間；都沒有才用現在（輸出就不穩定，summary.json 記來源）。"""
    props = {x.get("name"): x.get("value") for x in ((pbom.get("metadata") or {}).get("component") or {}).get("properties") or []
             if isinstance(x, dict)}
    for t, src in ((meta.get("finished"), "meta.finished"), (meta.get("started"), "meta.started"),
                   (props.get("sca-center:source-sbom-timestamp"), "source SBOM timestamp")):
        if isinstance(t, str) and re.match(r"^\d{4}-\d{2}-\d{2}T", t):
            return t, src
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "generated (no scan or SBOM time)"


def cdx_vex(allrows, pbom, meta, product, gate_verdict):
    """CycloneDX 1.6 VEX：每一列有判定的一個 vulnerability，affects 以 BOM-Link 指向產品 SBOM 的元件。回傳 (文件, 統計)。
    沒有判定的列（含 vex_extra 裡沒有判定的別名）也各輸出一條（M7c-1，A4／D-057）：analysis.state＝in_triage，加屬性
    dumpling:assessment＝NOT_ASSESSED，detail 寫明是沒有評估、不是有人在調查。只在這裡輸出，不改列、不改 assess 的結果，閘門的分類不受影響
    （r["vex"] 仍是空的）。同一個 (編號, 元件, 版本) 已經有判定的陳述時，沒判定的重複列不再輸出（以判定為準）。"""
    serial, bver = pbom["serialNumber"], pbom.get("version") or 1
    main = (pbom.get("metadata") or {}).get("component") or {}
    idx = ref_index(pbom)
    vulns, added, bomrefs = [], {}, set()
    vc = _vexconv()
    everyone = [x for r in allrows for x in [r] + (r.get("vex_extra") or [])]
    stated = [x for x in everyone if x.get("vex")]
    # 同一個編號在同一個元件版本上只能有一條陳述（兩條會互相矛盾，bom-ref 也會重複，文件無效）：不靜靜挑一條，直接失敗
    seen = Counter((x["id"], x.get("purl") or x.get("component"), x.get("version")) for x in stated)
    dup = sorted(k for k, n in seen.items() if n > 1)
    if dup:
        raise VexInputError("同一個弱點在同一個元件版本上有多條 VEX 陳述（程式錯誤，沒有產生 VEX）："
                            + "；".join(" ".join(str(v) for v in k) for k in dup[:5]))
    # 沒有判定的列：同一個 (編號, 元件, 版本) 只留一條，而且已經有判定的陳述優先（bom-ref 由這三個值決定，重複會讓文件無效）
    pending, seen_na, na_dup = [], set(seen), 0
    for x in sorted((y for y in everyone if not y.get("vex")), key=lambda y: (y["id"], str(y.get("component")), str(y.get("version")), str(y.get("purl")))):
        k = (x["id"], x.get("purl") or x.get("component"), x.get("version"))
        if k in seen_na:
            na_dup += 1
            continue
        seen_na.add(k)
        pending.append(x)
    for r in sorted(stated + pending, key=lambda x: (x["id"], str(x.get("component")), str(x.get("version")), str(x.get("purl")))):
        s = r.get("vex")
        refs = refs_for(r, idx)
        props = [{"name": "sca-center:vex-source", "value": s["source"]}] if s else []
        props.append({"name": "sca-center:component", "value": f"{r.get('component')} {r.get('version')}".strip()})
        if r.get("purl"):
            props.append({"name": "sca-center:component-purl", "value": r["purl"]})
        if r.get("source_ids"):
            props.append({"name": "sca-center:source-ids", "value": ", ".join(r["source_ids"])})
        if not s:
            props.append({"name": vc.PROP_ASSESSMENT, "value": vc.NOT_ASSESSED})
        links = [bomlink(serial, bver, x) for x in refs if x]
        if not links:
            # 元件不在產品 SBOM（例如只供比對的原始碼套件）：不把範圍擴大成整個產品，改把這個元件列在這份 VEX 自己的 components，
            # affects 指向它（同一份文件內的 bom-ref）
            ck = "|".join(str(x) for x in (r.get("purl") or "", r.get("name") or r.get("component"), r.get("version")))
            cref = f"vex-component-{hashlib.sha256(ck.encode()).hexdigest()[:16]}"
            c = {"type": "library", "bom-ref": cref, "name": str(r.get("name") or r.get("component") or "?")}
            if r.get("version"):
                c["version"] = str(r["version"])
            if r.get("purl"):
                c["purl"] = r["purl"]
            c["properties"] = [{"name": "sca-center:note", "value": "not in the product SBOM (for example a source package used only "
                                                                     "for matching); listed here so that the statement is scoped to it"}]
            added[cref] = c
            links = [cref]
        for k in ("author", "date", "scope"):
            if s and s.get(k):
                props.append({"name": f"sca-center:annotation-{k}", "value": s[k]})
        if s and s.get("inherited_from"):
            # Ubuntu 打包的 Python 模組沿用擁有它的 deb 套件那一列的判定（inherit_deb_python）
            f = s["inherited_from"]
            props.append({"name": "sca-center:vex-inherited-from", "value": f"{f['id']} on {f.get('component')} {f.get('version')}"})
        if s and s.get("rule"):
            # 批次規則的判定：讓客戶與稽核看得出這不是逐列的評估（規則全文在風險評估的 VEX 小節）
            props.append({"name": "sca-center:vex-rule", "value": s["rule"]})
            if s.get("rule_author"):
                props.append({"name": "sca-center:vex-rule-author", "value": s["rule_author"]})
            if s.get("evidence"):
                # 證據規則：種類（K1／K2／U1）與這次用到的輸入版本（.config、模組清單的 SHA-256、Ubuntu tracker 的 commit）
                props.append({"name": "sca-center:vex-rule-evidence", "value": s["evidence"]})
                if s.get("rule_inputs"):
                    props.append({"name": "sca-center:vex-rule-inputs", "value": s["rule_inputs"]})
        if is_exclusion(s):
            # 排除的依據（M7c-2，D-035／D-057）：每一筆依據依序一組屬性（類型、位置、選填的核心）；沒有類型的排除只有 dumpling:evidence＝none
            # （明寫「沒有」，下游分得出「沒記」和「這個版本的工具不寫依據」）。vexconv 轉成 OpenVEX 時變成 status_notes 的依據行
            basis, _why = exclusion_basis(s)
            if not basis:
                props.append({"name": vc.PROP_EVIDENCE, "value": vc.EVIDENCE_NONE})
            for e in basis:
                props.append({"name": vc.PROP_EVIDENCE, "value": e["type"]})
                props.append({"name": vc.PROP_EVIDENCE_LOCATION, "value": e["location"]})
                if e.get("kernel"):
                    props.append({"name": vc.PROP_EVIDENCE_KERNEL, "value": e["kernel"]})
        if s and s["state"] == "exploitable":
            # 沒有 response 時（批次規則：no fix yet、發行版 won't fix、資料不足）以 detail 當處理說明，OpenVEX 的 affected 一定要有
            # 舊設定檔的 can_not_fix／will_not_fix 不放進說明（客戶會讀成供應商不能修／不修），說明只用 detail
            real = [x for x in s.get("response") or [] if x not in ("can_not_fix", "will_not_fix")]
            act = s.get("action_statement") or (f"Planned response: {', '.join(real)}. {s['detail']}" if real else s["detail"])
            if r.get("fix_state"):
                props.append({"name": "sca-center:fix-state", "value": str(r["fix_state"])})
            if act:
                props.append({"name": "openvex:action_statement", "value": act})
        if not s:
            analysis = {"state": "in_triage", "detail": vc.DETAIL_NOT_ASSESSED}
        else:
            analysis = {"state": s["state"]}
            if s.get("justification"):
                analysis["justification"] = s["justification"]
            if s.get("response"):
                analysis["response"] = s["response"]
            analysis["detail"] = s["detail"]
            if r.get("runtime_note") and s["state"] in ("exploitable", "in_triage"):
                # 板子上量到的執行中證據（runtime_evidence.py）：只附一句話，不改狀態；沒有量測時沒有這個欄位
                analysis["detail"] = f"{s['detail']} {r['runtime_note']}".strip()
        key = "|".join(str(x) for x in (r["id"], r.get("purl") or r.get("component"), r.get("version")))
        v = {"bom-ref": f"vex-{r['id']}-{hashlib.sha256(key.encode()).hexdigest()[:12]}", "id": r["id"]}
        if v["bom-ref"] in bomrefs:          # set：沒有判定的列也輸出後，Jetson 約一萬條，逐條比對會太慢
            raise VexInputError(f"VEX 的 bom-ref 重複：{v['bom-ref']}（程式錯誤，沒有產生 VEX）")
        bomrefs.add(v["bom-ref"])
        if r["id"].startswith("CVE-"):
            v["source"] = {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{r['id']}"}
        v.update({"analysis": analysis, "affects": [{"ref": x} for x in links], "properties": props})
        vulns.append(v)
    comp = {k: main[k] for k in ("type", "bom-ref", "name", "version", "purl") if main.get(k)}
    comp.setdefault("name", product.get("name") or "?")
    ts, tsrc = doc_timestamp(meta, pbom)
    comps = [added[k] for k in sorted(added)]
    body = json.dumps([comps, vulns], sort_keys=True, ensure_ascii=False)
    vserial = "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, f"sca-center-vex|{serial}|{hashlib.sha256(body.encode()).hexdigest()}"))
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": vserial, "version": 1,
           "metadata": {"timestamp": ts, "component": comp,
                        "tools": {"components": [{"type": "application", "group": "sca-center", "name": "vex_export.py"}]},
                        "properties": [{"name": "sca-center:product-sbom-serial", "value": serial},
                                       {"name": "sca-center:product-sbom-version", "value": str(bver)},
                                       {"name": "sca-center:scanned-artifact", "value": f"{meta.get('name') or '?'} {meta.get('version') or ''}".strip()},
                                       {"name": "sca-center:release-gate", "value": gate_verdict},
                                       {"name": "sca-center:timestamp-source", "value": tsrc}]},
           **({"components": comps} if comps else {}),
           "vulnerabilities": vulns}
    # statements＝檔案裡的陳述總數（含沒有評估的）；statements_assessed＝有判定的；statements_not_assessed＝標了 NOT_ASSESSED 的（M7c-1）
    return doc, {"statements": len(vulns), "statements_assessed": len(stated), "statements_not_assessed": len(pending),
                 **({"not_assessed_duplicates_skipped": na_dup} if na_dup else {}),
                 "components_not_in_sbom": len(comps), "timestamp_source": tsrc}


def openvex(cdx, author, purl_of):
    """CycloneDX VEX → OpenVEX 0.2.0（vexconv.to_openvex 的狀態與理由對映）；products 換成元件的 purl，@id 由內容決定。
    沒有任何陳述時回傳 None（OpenVEX 至少要一條陳述）。"""
    if not cdx["vulnerabilities"]:
        return None
    vc = _vexconv()
    purl_of = dict(purl_of, **{c["bom-ref"]: c["purl"] for c in cdx.get("components") or [] if c.get("purl")})
    ov = vc.to_openvex(cdx, author=author, lenient=True)
    for st, v in zip(ov["statements"], cdx["vulnerabilities"]):
        purl = next((p["value"] for p in v.get("properties", []) if p["name"] == "sca-center:component-purl"), None)
        prods = []
        for p in st["products"]:
            pu = purl_of.get(p["@id"]) or purl
            prods.append({"@id": pu, "identifiers": {"purl": pu}} if pu else p)
        st["products"] = [json.loads(x) for x in sorted({json.dumps(p, sort_keys=True) for p in prods})]
    body = json.dumps(ov["statements"], sort_keys=True, ensure_ascii=False)
    ov["@id"] = "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, f"sca-center-openvex|{cdx['serialNumber']}|{hashlib.sha256(body.encode()).hexdigest()}"))
    return ov


def not_assessed_count(doc, name):
    """寫出的 VEX 檔案裡「沒有評估」的陳述數（summary.json 的 vex.files 用）：CycloneDX 看 dumpling:assessment＝NOT_ASSESSED，
    OpenVEX 看 under_investigation 加固定的 status_notes。"""
    vc = _vexconv()
    if name == "vex.cdx.json":
        return sum(1 for v in doc.get("vulnerabilities") or []
                   if any(p.get("name") == vc.PROP_ASSESSMENT and p.get("value") == vc.NOT_ASSESSED for p in v.get("properties") or []))
    return sum(1 for st in doc.get("statements") or [] if st.get("status") == "under_investigation" and st.get("status_notes") in vc.NOT_ASSESSED_NOTES)


def purl_by_bomlink(pbom):
    serial, bver = pbom["serialNumber"], pbom.get("version") or 1
    return {bomlink(serial, bver, c["bom-ref"]): c["purl"] for c in _flatten(pbom.get("components")) if c.get("bom-ref") and c.get("purl")}


def dumps(doc):
    return json.dumps(doc, ensure_ascii=False, indent=1, sort_keys=False) + "\n"


# ---------- 風險評估的小節（英文） ----------

def md_code(text):
    """Markdown 的行內程式碼（code span）：位置是人寫的文字，不能被當成 Markdown 或 HTML 解讀（連結、強調、標籤、表格分隔）。
    反引號框的長度比文字裡最長的連續反引號多一個；開頭或結尾是反引號時兩側補空白。表格儲存格的「|」由 cra_report.cell 跳脫。"""
    t = str(text)
    n = max((len(m) for m in re.findall(r"`+", t)), default=0)
    pad = " " if t.startswith("`") or t.endswith("`") else ""
    return "`" * (n + 1) + pad + t + pad + "`" * (n + 1)


EVIDENCE_TYPE_TEXT = {"build-record": "build-record (kernel configuration, module map, build output)", "source": "source (source code or backported fix commit)",
                      "on-device": "on-device (checked on the device)", "design-doc": "design-doc (product design document)",
                      "vendor-statement": "vendor-statement (vendor or distribution advisory)"}


def evidence_paragraphs(ev, table):
    """風險評估 VEX 小節的「排除的依據」：各類型筆數、沒有類型的排除（擋閘門）、靠 on-device 或 design-doc 的排除（D-035，單獨列出）。"""
    out = []
    if not ev["exclusions"]:
        return ["Evidence for exclusions (D-035): there is no `resolved` or `not_affected` statement, so no evidence is recorded."]
    wt = ev["without_type"]
    out.append(f"Evidence for exclusions (D-035): {ev['exclusions']} statements are `resolved` or `not_affected` (including `false_positive`); each needs "
               "an evidence type and a location. By evidence type (a statement with several types counts once per type): "
               + ", ".join(f"{t} {ev['by_type'][t]}" for t in EVIDENCE_TYPES) + ". "
               f"Build-record evidence is the kernel configuration check, the kernel module map and the image's module list; vendor-statement "
               "evidence is a distribution or vendor record (Ubuntu CVE Tracker, DSA, DLA, USN); on-device and design-doc evidence is written by a "
               "person in `vex-annotations.json` (`evidence`, `evidence_location`, or `evidence_basis` per kernel). "
               f"A decision made in Dependency-Track always has no evidence type (there is no field for it): record it as an annotation with evidence.")
    if wt["total"]:
        out.append(f"**{wt['total']} exclusions have no evidence type** ("
                   + ", ".join(f"{EVIDENCE_MISSING.get(k, k)} {n}" for k, n in sorted(wt["by_reason"].items(), key=lambda kv: (-kv[1], kv[0])))
                   + "). They are treated as not assessed: they count in the release gate's untriaged-for-gate number, the gate cannot be OK, and this "
                     "document's status is at least ATTENTION. In the files for customers they carry `Evidence: not recorded`. First "
                     f"{len(wt['sample'])}: "
                   + ", ".join(f"{x['id']} on {x['component']} {x['version']} ({x['source']})" for x in wt["sample"]) + ".")
    for key, title, note in (
            ("on_device", "Exclusions based on an on-device check",
             "The location must be a file inside the project folder (relative path, no `..`, not through a symbolic link to outside the "
             "project). The tool only checks that the file exists; it does not verify the file's content. A person must review the file "
             "(for example, output of read-only commands run on the device) before the release."),
            ("design_doc", "Exclusions based on a design document",
             "The location is free text written by a person (document name, version, section); the tool does not check that the document "
             "exists or what it says. A person must review these exclusions before the release.")):
        rows = ev[key]
        if not rows:
            continue
        shown = rows[:EVIDENCE_TABLE_MAX]
        out.append(f"#### {title} ({len(rows)})\n\n{note}"
                   + (f" The first {EVIDENCE_TABLE_MAX} are shown; the full list is `vex.evidence.{key}` in summary.json." if len(rows) > len(shown) else "")
                   + "\n\n" + table(["#", "ID", "Component", "Version", "Kernel", "Location", "Decided by"],
                                    [[i, x["id"], x["component"], x["version"], x.get("kernel"), md_code(x["location"]), SRC_LABEL.get(x["source"], x["source"])]
                                     for i, x in enumerate(shown, 1)]))
    return out


def section(num, g, info, conflicts, files, product, table, annotations_info, rules_info=None):
    """風險評估「Vulnerability status (VEX) and release gate」小節的 Markdown（前面帶空行）。"""
    c = g["counts"]
    parts = [("Each row of section 8 is a candidate vulnerability found by automated matching of the SBOM components against "
              "vulnerability data, not by itself a known exploitable vulnerability. A VEX (Vulnerability Exploitability eXchange) statement records, per row, whether the product is "
              "affected and why. Statements come from, in this order: (1) decisions recorded by people – the analysis in "
              "Dependency-Track and the project's annotation file `CRA/Config/vex-annotations.json` (carried to later releases "
              "automatically); (2) the distribution's own records for rows reported only via NVD/GitHub (`resolved`: the installed "
              "package contains the backported fix); (3) the kernel configuration check (`not_affected`, `code_not_present`: the "
              "vulnerable code is not built); (4) NVIDIA bulletins that do not name this release line but predate it (`in_triage` – "
              "presumed, never `not_affected`); (5) the project's bulk rules `CRA/Config/vex-rules.json` (evidence rules, which set "
              "`not_affected` only from the product's artifacts – kernel configuration, kernel modules, Ubuntu CVE Tracker status – "
              "and triage rules, which set only `exploitable` (a response is optional), or `in_triage`; only for rows without a decision from "
              "(1)–(4); never for rows in a KEV catalogue; each such statement names its rule). The first source with a decision is used; a different decision from a later source "
              "is listed as a conflict and does not override it. Rows without any decision are `untriaged`. "
              "They are written to the VEX files as well, as `in_triage` in CycloneDX (`under_investigation` in OpenVEX) with the property "
              "`dumpling:assessment` = `NOT_ASSESSED` (OpenVEX: status notes \"dumpling: not assessed\"). Such a statement means that the row "
              "has not been assessed; it does not mean that anyone is investigating it. The release gate counts these rows as `untriaged`, "
              "not as `in_triage`, and they are not written back to Dependency-Track. Every `resolved` or `not_affected` statement "
              "(an exclusion) also records the type and location of its evidence (D-035): in CycloneDX the properties `dumpling:evidence`, "
              "`dumpling:evidence-location` and, for a specific kernel, `dumpling:evidence-kernel`; in OpenVEX one line "
              "`dumpling: evidence=<type>; location=<location>` per piece of evidence in the status notes. The files for customers "
              "carry the type only, as a fixed sentence (`Evidence: …`), never the location."),
             (f"Files for customers, with the SBOM `sbom.cdx.json` (product {product}): "
              + "; ".join(f"`{n}` ({x['statements']} statements{', ' + str(x['not_assessed']) + ' of them not assessed' if x.get('not_assessed') else ''}, SHA-256 {x['sha256'][:12]})" if x else f"`{n}` not written ({why})"
                          for n, x, why in files)
              + ". The statements refer to the components of the product SBOM. They are not imported into Dependency-Track: "
                "importing a CycloneDX VEX overwrites existing analyses there.")]
    rows = [[lbl, c["total"][b], c["kernel"][b], c["non_kernel"][b]] for b, lbl in (
        ("resolved", "resolved (fixed)"), ("not_affected", "not_affected (including false_positive)"),
        ("exploitable", "exploitable"), ("in_triage", "in_triage (under investigation)"), ("untriaged", "untriaged (no assessment)"))]
    rows.append(["Total rows", c["total"]["rows"], c["kernel"]["rows"], c["non_kernel"]["rows"]])
    parts.append(table(["VEX status", "Total", "OS kernel", "Other components"], rows))
    src = info["sources"]
    parts.append("Statements by source: " + ", ".join(f"{SRC_LABEL[s]} {src[s]}" for s in SOURCES) + "."
                 + (f" {info['nvidia_extra_rows']} rows are NVIDIA bulletin entries without a Dependency-Track finding "
                    "(presumed included or needing confirmation from NVIDIA)." if info["nvidia_extra_rows"] else "")
                 + (f" {info['suppressed_without_state']} rows are suppressed in Dependency-Track without an analysis state; they "
                    "count as untriaged." if info.get("suppressed_without_state") else "")
                 + (f" {info['dt_without_justification']} rows have a Dependency-Track analysis without justification (NOT_AFFECTED "
                    "without justification or details, or FALSE_POSITIVE without justification); it is not used as a VEX statement – "
                    "record the justification in Dependency-Track." if info.get("dt_without_justification") else "")
                 + (f" In {info['dt_partial']} rows only some of the merged Dependency-Track findings have a usable analysis; the "
                    "analysed finding decides the row – check that the decision covers the others." if info.get("dt_partial") else "")
                 + (f" {info['dt_other_vulnerability']} rows have a Dependency-Track analysis on a finding for a different CVE than "
                    "the row's ID; it is not used." if info.get("dt_other_vulnerability") else "")
                 + (f" {info['extra_cves']['total']} further CVEs are merged into a row of another CVE (aliases of the same advisory); "
                    f"each needs its own decision (an annotation with that CVE and a purl, or an analysis in Dependency-Track on a finding "
                    f"for that CVE): {info['extra_cves']['with_statement']} have one." if (info.get("extra_cves") or {}).get("total") else ""))
    kc = info.get("kernel_config")
    if kc is None:
        parts.append("Kernel configuration check: no result (`scan/kernel-config.json`); no kernel row was marked `not_affected` by it.")
    elif kc.get("scope_incomplete"):
        sc = kc.get("scope") or {}
        parts.append(f"Kernel configuration check and module map (K1/K2) are not adopted: the image ships kernels that were not judged "
                     f"({', '.join(sc.get('not_judged') or [])}; judged: {', '.join(sc.get('judged') or []) or 'none'}), so no kernel row was marked "
                     f"`not_affected` or `resolved` by them. {info.get('kernel_scope_withheld', 0)} kernel rows would have been excluded; they keep the "
                     "status they have without K1/K2 (see each row's note). 只判定了部分核心，其餘已出貨的核心未判定，排除不適用整個產品。")
    elif not kc["used"]:
        parts.append(f"Kernel configuration check: status {kc['status'] or '?'}; its results are only used when the status is OK, so "
                     "no kernel row was marked `not_affected` by it.")
    ann = annotations_info
    if ann:
        parts.append(f"Annotations: `{ann['file']}` (SHA-256 {ann['sha256'][:12]}), {ann['count']} decisions, {info['annotations_used']} "
                     f"applied to this release" + (f", {len(info['annotations_unused'])} not matching any row" if info["annotations_unused"] else "")
                     + (f"; {len(ann['ignored'])} ignored because a `not_affected`, `false_positive` or `resolved` decision must name a "
                        f"package (purl): {', '.join(ann['ignored'][:10])}" if ann.get("ignored") else "") + ".")
    else:
        parts.append("Annotations: no `CRA/Config/vex-annotations.json` in the project.")
    ev = info.get("evidence")
    if ev:
        parts += evidence_paragraphs(ev, table)
    rs_all = info.get("rules") or []
    ers, rs = [x for x in rs_all if x.get("evidence")], [x for x in rs_all if not x.get("evidence")]
    rules_block = None
    if rules_info:
        parts.append(f"Bulk triage rules: `{rules_info['file']}`, {rules_info['count']} rules, {sum(x['applied'] for x in rs_all)} rows decided "
                     "by them (the rules and their counts follow the release gate).")
        rules_block = ""
        if ers:
            ei = info.get("evidence_inputs") or {}
            rules_block += (
                "#### Evidence rules (not_affected from product artifacts)\n\n"
                # 檔案裡只有證據規則時，規則檔的 SHA-256 寫在這裡（否則寫在下面的 Bulk triage rules）
                + (f"`{rules_info['file']}` (SHA-256 {rules_info['sha256'][:12]}), {rules_info['count']} rules. " if not rs else "")
                + "An evidence rule sets `not_affected` only from the product's own artifacts, re-evaluated every time the documents are "
                "generated (a changed input changes the result): K1 – the kernel configuration check found that the fix's code is not "
                "built (`code_not_present`); K2 – the fix only changes kernel modules that are removed from the image (`code_not_present`) "
                "or blocked from loading and not loaded (`code_not_reachable`); U1 – the Ubuntu CVE Tracker marks the source package as "
                "`not-affected` in this Ubuntu release with a version note, and the installed source version has the same epoch and upstream "
                "version as that note (only the Debian revision may differ, and not older) – the note means \"this version is not affected\", "
                "not \"this version and later\" (`code_not_present`, inferred from Ubuntu's status)"
                + ("; U2 – for a Python module installed by an Ubuntu package, the Ubuntu CVE Tracker has `released` for the owning source "
                   "package in this Ubuntu release and the installed source version is not older than the release that fixes it, so Ubuntu "
                   "has fixed it in the installed version (`resolved`; the PyPI fix version does not apply)" if any(x["evidence"] == "U2" for x in ers) else "")
                + ". Severity, EPSS and the tier are never inputs. Evidence rules apply "
                "before the other rules, never to rows in a KEV catalogue or marked exploited, never over a decision by a person or another "
                "source (such rows are counted as already decided, and listed as a conflict when the decision differs), and only when the "
                "scanned image is in the rule's images, the effective date is reached and the author is named. "
                + ("With an active K1 rule the kernel configuration check is applied through the rule (not as source (3) above). "
                   if info.get("kernel_config_via_rule") else
                   "No K1 rule is active, so the kernel configuration check is applied as source (3) above, as before. "
                   if any(x["evidence"] == "K1" for x in ers) else "")
                + f"Inputs: module map {ei.get('module_map')}; kernel modules {ei.get('kernel_modules')}; Ubuntu status "
                  f"{ei.get('ubuntu_status')}"
                + (f" (tracker commit {str(ei['ubuntu_tracker_commit'])[:12]}"
                   + (f", snapshot fetched {str(ei.get('ubuntu_tracker_fetched'))[:10]}, {ei['ubuntu_tracker_age_days']} day(s) before the report date; "
                      "its age is checked only when the scan runs" if ei.get("ubuntu_tracker_age_days") is not None else "") + ")"
                   if ei.get("ubuntu_tracker_commit") else "")
                + (". Mirror counts that need a person: " + ", ".join(f"{k} {n}" for k, n in sorted((ei.get("ubuntu_mirror_counts") or {}).items()) if n)
                   if any((ei.get("ubuntu_mirror_counts") or {}).values()) else "") + ".\n\n"
                + table(["ID", "Evidence", "Description", "Author", "Effective from", "Images", "Reason", "Rows (kernel / other)",
                         "Already decided by another source", "Not applied: KEV / rule not active", "Not applied (reason: rows)", "Markers"],
                        [[x["id"], x["evidence"], x["description"], "author: TO BE COMPLETED" if x["author_missing"] else x["author"], x["date"],
                          "all images of the project" if x["images"] == ["*"] else ", ".join(i[:19] + "…" for i in x["images"]),
                          x["reason"], f"{x['applied']} ({x['kernel']} / {x['non_kernel']})",
                          ", ".join(f"{SRC_LABEL[k]} {n}" for k, n in x["shadowed"].items()) or "0",
                          f"{x['excluded_kev']} / {x['inactive_rows']}" + (f" ({'; '.join(x['inactive'])})" if x["inactive"] else ""),
                          ", ".join(f"{k}: {n}" for k, n in x["not_applied"].items()) or "0",
                          ", ".join(f"{k}: {n}" for k, n in x["markers"].items()) or "0"] for x in ers]))
            kx = [(x, e) for x in ers for e in x.get("excluded_kev_rows") or []]
            if kx:
                rules_block += ("\n\nExploited rows (KEV, EUVD or manual evidence) that an evidence rule would set to `not_affected`: the rule "
                                "is not applied – a person decides these rows – but its evidence is listed for that decision.\n\n"
                                + table(["#", "ID", "Component", "Version", "Rule", "What the rule found"],
                                        [[i, e["id"], e["component"], e["version"], f"{x['id']} [{x['evidence']}]", e["detail"]]
                                         for i, (x, e) in enumerate(kx, 1)]))
        if rs or not ers:
            # 沒有任何規則（{"rules": []}）時照舊寫這一段（表是 _None._）
            rules_block += ("\n\n" if rules_block else "") + (
                f"#### Bulk triage rules\n\n`{rules_info['file']}` (SHA-256 {rules_info['sha256'][:12]}), {rules_info['count']} rules. "
                       "A rule sets the same statement for every row that meets all of its conditions; it is a decision by the named author "
                       "for a group of rows, not an individual assessment of each row (the statements carry the rule ID in "
                       "`sca-center:vex-rule` and in the detail). Rules can only set `exploitable` (a response is optional) or `in_triage`, apply only "
                       "to rows without another decision, never to rows in a KEV catalogue or to Python modules installed by Ubuntu packages "
                       "(their PyPI type and fix data do not describe the Ubuntu package), and to P1 rows only when the rule says so. "
                       "The first matching rule in file order is used.\n\n"
                       + table(["ID", "Description", "Author", "Date", "Reason", "Sets", "Rows (kernel / other)",
                                "Already decided by another source", "Not applied: KEV / P1 / value missing / deb-packaged Python"],
                               [[x["id"], x["description"], "author: TO BE COMPLETED" if x["author_missing"] else x["author"],
                                 x["date"], x["reason"],
                                 x["state"] + (f" ({', '.join(x['response'])})" if x["response"] else ""),
                                 f"{x['applied']} ({x['kernel']} / {x['non_kernel']})",
                                 ", ".join(f"{SRC_LABEL[k]} {n}" for k, n in x["shadowed"].items()) or "0",
                                 f"{x['excluded_kev']} / {x['excluded_p1']} / {x['template_missing']} / {x['excluded_deb_python']}"] for x in rs]))
    else:
        parts.append("Bulk triage rules: no `CRA/Config/vex-rules.json` in the project.")
    mk = info.get("markers") or {}
    if mk.get("K3") or mk.get("K4") or mk.get("U1-not-applied") or mk.get("U1-older-revision"):
        parts.append("Row markers (no change of the VEX status; shown in brackets in the VEX status column): "
                     + "; ".join(t for t in (
                         f"K3 {mk['K3']} – the fix is in a kernel module that can be loaded, so the row stays affected" if mk.get("K3") else "",
                         f"K4 {mk['K4']} – the CVE cannot be mapped to a kernel module, so it is treated as built into the kernel "
                         "(affected) and the row is a GAP" if mk.get("K4") else "",
                         f"U1 not applied {mk['U1-not-applied']} – Ubuntu marks it not-affected, but the entry is conflicting, has no "
                         "version note or a note that is not a version, or the installed upstream version differs from the note; decide by hand" if mk.get("U1-not-applied") else "",
                         f"U1 older revision {mk['U1-older-revision']} – Ubuntu marks the same upstream version not-affected, but the installed "
                         "Debian revision is older than the one the tracker evaluated (the fix may be revision-level); decide these rows by hand, "
                         "together" if mk.get("U1-older-revision") else "")
                         if t) + ".")
    ux = info.get("u1_excluded") or []
    if ux:
        # 被 U1 排除的每一列：理由與證據（Ubuntu 的狀態與註記、版本比較、出處）。完整清單在 summary.json 的 vex.u1_excluded
        parts.append(f"Rows set to `not_affected` by evidence rule U1: {len(ux)}. Each row's reason is the Ubuntu CVE Tracker status for the "
                     "source package in this Ubuntu release, compared with the installed source version; the source is the tracker file "
                     "at the mirrored commit (the page on ubuntu.com shows the current status, which can be newer). "
                     + (f"The first {U1_TABLE_MAX} are shown; " if len(ux) > U1_TABLE_MAX else "")
                     + "the full list with the same fields is `vex.u1_excluded` in summary.json.")
        parts.append(table(["#", "ID", "Component", "Version", "Source package (release)", "Ubuntu status", "Version check", "Source"],
                           [[i, x["id"], x["component"], x["version"], f"{x['source_package']} {x['source_version']} ({x['release']})",
                             "; ".join(f"{c['cve']}: {c['ubuntu_status']}" + (f" ({c['ubuntu_note']})" if c["ubuntu_note"] else "")
                                       for c in x["cves"]),
                             "; ".join(c["version_check"] for c in x["cves"]),
                             f"{', '.join(c['tracker_file'] or c['cve'] for c in x['cves'])} @ {str(x['tracker']['commit'] or '?')[:12]} "
                             f"({str(x['tracker']['commit_date'] or '?')[:10]}), rule {x['rule']}"]
                            for i, x in enumerate(ux[:U1_TABLE_MAX], 1)]))
    fl = info.get("upstream_excludes") or {}
    if fl.get("candidates"):
        nf = fl.get("not_flagged") or {}
        parts.append(f"Possible false positives (`distro_no_range_upstream_excludes`): {fl['flagged']} rows. Grype matched "
                     f"{fl['candidates']} vulnerabilities from distribution data without a version range (the record has only a status, "
                     "so every version counts as affected); a row is marked when every CPE range for the same CVE and package found in "
                     "the Grype result (cpe-match records, for example from NVD) excludes the upstream part of the installed version. "
                     "It is only a marker: version comparison and backports can be wrong, so nothing is set to `not_affected` or "
                     "`false_positive` – a person confirms with the evidence below. The opposite case (the distribution says fixed, but "
                     "the fix is not in our build) cannot be detected automatically. "
                     + ("Not marked: " + ", ".join(f"{k} {n}" for k, n in nf.items()) + "." if nf else ""))
        if fl.get("rows"):
            parts.append(table(["#", "ID", "Component", "Installed (upstream)", "Upstream range (source)", "Distribution match",
                                "Ubuntu status", "Ubuntu changelog"],
                               [[i, x["id"], x["component"], f"{x['version']} ({x['upstream_version']})",
                                 "; ".join(f"{u['constraint']} for {u['cpe']} ({u['namespace'] or '?'})" for u in x["upstream_ranges"]),
                                 f"{x['distro_match']['namespace']}, {x['distro_match']['constraint']}, fix state {x['distro_match']['fix_state']}",
                                 x["ubuntu_status"], x["ubuntu_changelog"]] for i, x in enumerate(fl["rows"][:50], 1)]))
    parts.append(f"**Release gate: {g['verdict']}**" + (" – " + "; ".join(g["reasons"]) + "." if g["reasons"] else
                 " – every row has a VEX status and no row is affected.")
                 + " Rule: OK only when no row is untriaged, every `resolved` or `not_affected` row has an evidence type, every further CVE merged into a row has its own VEX status, no row is "
                   "`exploitable` (affected), people's decisions do not conflict, Grype was run and has no vulnerability "
                   "outside this list, and the list is complete (data status not GAP or NOT_ASSESSED). `in_triage` rows do not block the gate but must be followed up. OK does not mean the product is secure.")
    a, o = g["assessment"], g["open_affected"]
    parts.append(f"(a) Assessment completeness: {a['untriaged']} untriaged rows ({g['untriaged_high']} in P1 or P2)"
                 + (f" and {a['extra_cves_untriaged']} further merged CVEs without a statement" if a["extra_cves_untriaged"] else "")
                 + f"; set to in_triage by bulk rule, not individually assessed: {a['in_triage_by_rule']} (counted as not assessed); "
                 + (f"{a['exclusions_without_evidence']} exclusions (`resolved` or `not_affected`) without an evidence type, counted as not assessed; "
                    if a.get("exclusions_without_evidence") else "")
                 + f"{a['untriaged_for_gate']} not assessed in total. Rows set by a bulk rule to `exploitable`, or to `not_affected` by an evidence rule, count as assessed "
                 f"({a['by_rule'] - a['in_triage_by_rule']}). "
                 f"(b) Open affected: {o['rows']} rows are `exploitable` ({o['individual']} decided individually, {o['by_rule']} by bulk rules)"
                 + (": by response " + ", ".join(f"{k} {n}" for k, n in o["by_response"].items()) if o["rows"] else "")
                 + ". CRA Annex I Part I point (2)(a) requires that a product is placed on the market without known exploitable "
                   "vulnerabilities, so every open affected row needs a release decision by a person: fixed before shipping, or a "
                   "documented risk-based justification. The gate is never OK while such rows exist.")
    if rules_block:
        parts.append(rules_block)
    if g["top_untriaged"]:
        parts.append(f"#### Highest-priority untriaged rows ({len(g['top_untriaged'])} of {c['total']['untriaged']})\n\n" + table(
            ["#", "ID", "Component", "Version", "Tier", "KEV", "EPSS percentile", "Severity", "Kernel"],
            [[i, x["id"], x["component"], x["version"], str(x["tier"]).upper(), (("YES (same CVE)" if x.get("kev_by_cve") else "YES") if x["kev"] else "no")
             + ("; exploited: " + "; ".join(x["exploited_sources"]) if x.get("exploited_sources") else ""),
              f"{x['epss_percentile']:.3f}" if isinstance(x["epss_percentile"], (int, float)) else None, x["severity"],
              "yes" if x["kernel"] else "no"] for i, x in enumerate(g["top_untriaged"], 1)]))
    if conflicts:
        parts.append(f"#### Conflicting decisions ({len(conflicts)}{', first 20' if len(conflicts) > 20 else ''})\n\n"
                     "Used: the decision in the VEX. Other: a later source with a different decision (not applied).\n\n" + table(
                         ["#", "ID", "Component", "Version", "Used", "Other", "Both by people"],
                         [[i, x["id"], x["component"], x["version"], x["used"], x["other"], "YES" if x["human"] else "no"]
                          for i, x in enumerate(conflicts[:20], 1)]))
    return f"\n\n### {num} Vulnerability status (VEX) and release gate\n\n" + "\n\n".join(parts)


# ---------- CLI ----------

class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        print(f"參數錯誤：{message}", file=sys.stderr)
        sys.exit(64)


def write_atomic(p, text):
    """寫到同資料夾的暫存檔再換上。權限沿用原檔（mkstemp 是 0600）；新檔依 umask（一般是 0644）。"""
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.exists():
        mode = stat.S_IMODE(p.stat().st_mode)
    else:
        um = os.umask(0)
        os.umask(um)
        mode = 0o666 & ~um
    fd, tmp = tempfile.mkstemp(prefix=f".{p.stem}.", dir=p.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, p)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def on_device_warnings(a, project):
    """判定裡 on-device 依據的檔案目前不合格的說明（文字清單）：annotate、check 提醒用；這筆排除在檔案補上之前算沒有類型（閘門會擋）。"""
    return [f"on-device 依據 {e['location']!r} 不合格（{why}）：檔案要放在專案資料夾內（相對路徑、沒有 ..、不經符號連結到外面），"
            f"補上之前這筆排除算沒有依據類型"
            for e in annotation_basis(a) if e["type"] == "on-device" and (why := on_device_problem(e["location"], project))]


def annotate(a):
    """讀、改、寫期間持有同資料夾 .vex-annotations.json.lock 的排他鎖（fcntl.flock，建議性），兩個人同時加判定不會互相蓋掉。"""
    import fcntl
    p = Path(a.project) / ANN_REL
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p.parent / f".{p.name}.lock", "a") as lk:
        fcntl.flock(lk, fcntl.LOCK_EX)
        return _annotate(a, p)


def _annotate(a, p):
    if p.is_file():
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, ValueError) as e:
            raise VexInputError(f"{p} 不是 JSON：{e}（沒有修改）")
        check_annotations(doc, str(p))
    else:
        doc = {"schema": ANN_SCHEMA, "annotations": []}
    new = {"cve": a.cve.strip(), "state": a.state, "detail": a.detail.strip(), "author": a.author.strip(),
           "date": a.date or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")}
    for k in ("purl", "version", "justification", "action_statement"):
        if getattr(a, k):
            new[k] = getattr(a, k).strip()
    if a.response:
        new["response"] = list(dict.fromkeys(a.response))
    if a.evidence:
        new["evidence"] = a.evidence
    if a.evidence_location:
        new["evidence_location"] = a.evidence_location[0] if len(a.evidence_location) == 1 else list(a.evidence_location)
    if a.evidence_basis:
        try:
            new["evidence_basis"] = json.loads(a.evidence_basis)
        except ValueError as e:
            raise VexInputError(f"--evidence-basis 不是 JSON：{e}（沒有修改）")
    errs = validate_annotation(new, "新的判定")
    if not errs and unscoped(new):
        errs.append(f"{new['state']} 至少要用 --purl 限定套件（例如 pkg:deb/ubuntu/openssl）；只寫 CVE 的範圍只允許 in_triage、exploitable")
    if errs:
        raise VexInputError("；".join(errs) + "（沒有修改）")
    sc = scope_of(new)[0]
    same = [i for i, x in enumerate(doc["annotations"]) if scope_of(x)[0] == sc]
    if same and not a.replace:
        raise VexInputError(f"同一範圍已有判定（annotations[{same[0]}]：{doc['annotations'][same[0]]['state']}，"
                            f"{doc['annotations'][same[0]]['author']} {doc['annotations'][same[0]]['date']}）；要取代請加 --replace（沒有修改）")
    doc["annotations"] = [x for i, x in enumerate(doc["annotations"]) if i not in same] + [new]
    doc["annotations"].sort(key=lambda x: (scope_of(x)[0][0], scope_of(x)[0][1] or "", scope_of(x)[0][2] or ""))
    check_annotations(doc, str(p))
    write_atomic(p, json.dumps(doc, ensure_ascii=False, indent=1) + "\n")
    warn = "".join(f"；注意：{x}" for x in on_device_warnings(new, a.project))
    return f"{'取代' if same else '新增'} {new['cve']}（{new['state']}）；{p} 共 {len(doc['annotations'])} 筆{warn}"


def rules_add(a):
    """和 annotate 一樣：讀、改、寫期間持有同資料夾 .vex-rules.json.lock 的排他鎖；先驗證整份檔案，寫到暫存檔再換上，保留原檔權限。
    新規則加在最後（檔案順序就是優先順序）；同一個 id 已有時拒絕，--replace 時在原位置取代。"""
    import fcntl
    p = Path(a.project) / RULES_REL
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p.parent / f".{p.name}.lock", "a") as lk:
        fcntl.flock(lk, fcntl.LOCK_EX)
        if p.is_file():
            try:
                doc = json.loads(p.read_text(encoding="utf-8"))
            except (UnicodeDecodeError, ValueError) as e:
                raise VexInputError(f"{p} 不是 JSON：{e}（沒有修改）")
            check_rules(doc, str(p))
        else:
            doc = {"schema": RULES_SCHEMA, "rules": []}
        m = {"scope": a.scope}
        for k, v in (("purl_prefix", a.purl_prefix), ("purl_type", a.purl_type), ("fix_state", a.fix_state),
                     ("kernel_config", a.kernel_config), ("tier", a.tier), ("severity", a.severity)):
            if v:
                m[k] = list(dict.fromkeys(v))
        if a.epss_max is not None:
            m["epss_percentile_max"] = a.epss_max
        if a.include_no_epss:
            m["include_no_epss"] = True
        if a.allow_p1:
            m["allow_p1"] = True
        st = {"state": a.state, "detail_template": a.detail_template.strip()}
        if a.response:
            st["response"] = list(dict.fromkeys(a.response))
        if a.recommendation:
            st["recommendation"] = a.recommendation.strip()
        new = {"id": a.id.strip(), "description": a.description.strip(),
               "date": a.date or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d"), "reason": a.reason.strip(),
               "match": m, "set": st}
        if a.author is not None:
            new["author"] = a.author.strip()
        elif "author" not in doc:
            raise VexInputError(f"{p} 最上層沒有 author（所有規則的預設責任人），新的規則要加 --author（沒有修改）")
        errs = validate_rule(new, "新的規則")
        if errs:
            raise VexInputError("；".join(errs) + "（沒有修改）")
        same = [i for i, x in enumerate(doc["rules"]) if x["id"] == new["id"]]
        if same and not a.replace:
            x = doc["rules"][same[0]]
            raise VexInputError(f"已有 id {new['id']} 的規則（rules[{same[0]}]，{x.get('author') or doc.get('author')} {x['date']}）；"
                                "要取代請加 --replace（沒有修改）")
        if same:
            doc["rules"][same[0]] = new
        else:
            doc["rules"].append(new)
        check_rules(doc, str(p))
        write_atomic(p, json.dumps(doc, ensure_ascii=False, indent=1) + "\n")
        return f"{'取代' if same else '新增'}規則 {new['id']}（{st['state']}）；{p} 共 {len(doc['rules'])} 條"


def rules_check(a):
    """只檢查格式；有 --scan 時另做一次「乾跑」：用 cra_report 產生文件到暫存資料夾（同樣的列、同樣的判定順序），印出每條規則的結果。
    回傳 (退出碼, 輸出的行)。"""
    rules, info = load_rules(a.project)
    if not info:
        return 0, [f"OK\t沒有 {RULES_REL}（不需要）"]
    lines = [f"OK\t{info['file']} 格式正確，{info['count']} 條規則"]
    if info["without_author"]:
        lines.append(f"WARN\t沒有責任人（空的或佔位字）：{', '.join(info['without_author'])}；規則照樣套用，但文件寫 TO BE COMPLETED、閘門 ATTENTION")
    if info.get("evidence_without_author"):
        lines.append(f"WARN\t證據規則沒有責任人（空的或佔位字）：{', '.join(info['evidence_without_author'])}；不套用（核心設定檢查照舊自動套用），"
                     "填上名字才生效")
    if not a.scan:
        return 0, lines
    spec = importlib.util.spec_from_file_location("sca_center_cra_report", HERE / "cra_report.py")
    cra = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cra)
    project, scan = Path(a.project).resolve(), Path(a.scan).resolve()
    try:
        cfg, warnings, company = cra.load_config(project, cra.company_file(a.company, a.no_company))
        with tempfile.TemporaryDirectory(prefix="vex-rules-check.") as out:
            s = cra.generate(project, scan, Path(out), cfg, warnings, company)
    except cra.Fail as e:
        raise VexInputError(f"cra_report 無法產生（乾跑沒有結果）：{e}")
    v = s["vex"]
    g = v["gate"]
    for x in v["rules"]["rules"]:
        if x.get("evidence"):
            lines.append(f"RULE\t{x['id']}\t{x['evidence']}\t{x['state']}\t套用 {x['applied']} 列（核心 {x['kernel']}、其他 {x['non_kernel']}；"
                         + ("、".join(f"{k} {n}" for k, n in x["justification"].items()) or "—") + "）；已有其他判定 "
                         + ("、".join(f"{SRC_LABEL[k]} {n}" for k, n in x["shadowed"].items()) or "0")
                         + f"；排除：KEV／被利用 {x['excluded_kev']}、規則不生效 {x['inactive_rows']}"
                         + (f"（{'；'.join(x['inactive'])}）" if x["inactive"] else "")
                         + "；沒套用：" + ("、".join(f"{k} {n}" for k, n in x["not_applied"].items()) or "0")
                         + "；標記：" + ("、".join(f"{k} {n}" for k, n in x["markers"].items()) or "0"))
            for r in x["sample"]:
                lines.append(f"  例\t{r['id']}\t{r['component']} {r['version']}\t{r['detail']}")
            for r in x["not_applied_sample"][:10]:
                lines.append(f"  沒套用\t{r['reason']}\t{r['id']}\t{r['component']} {r['version']}\t{r['detail']}")
            continue
        lines.append(f"RULE\t{x['id']}\t{x['state']}{'（' + ', '.join(x['response']) + '）' if x['response'] else ''}\t"
                     f"套用 {x['applied']} 列（核心 {x['kernel']}、其他 {x['non_kernel']}）；已有其他判定 "
                     + ("、".join(f"{SRC_LABEL[k]} {n}" for k, n in x["shadowed"].items()) or "0")
                     + f"；排除：KEV {x['excluded_kev']}、P1 {x['excluded_p1']}、範本缺值 {x['template_missing']}、"
                       f"Ubuntu 打包的 Python {x['excluded_deb_python']}")
        for r in x["sample"]:
            lines.append(f"  例\t{r['id']}\t{r['component']} {r['version']}\t{str(r['tier']).upper()}\t{r['fix_state']}\t{r['detail']}")
    a_, o = g["assessment"], g["open_affected"]
    lines.append(f"GATE\t{g['verdict']}\tuntriaged {a_['untriaged']}（核心 {g['counts']['kernel']['untriaged']}、其他 "
                 f"{g['counts']['non_kernel']['untriaged']}）＋規則設 in_triage {a_['in_triage_by_rule']}（未評估）＝{a_['untriaged_for_gate']}；"
                 f"規則判定 {a_['by_rule']}；"
                 f"exploitable {o['rows']}（規則 {o['by_rule']}；" + "、".join(f"{k} {n}" for k, n in o["by_response"].items()) + "）")
    fl = v.get("upstream_excludes") or {}
    if fl.get("basis"):
        lines.append(f"FLAG\tdistro_no_range_upstream_excludes\t可能誤報 {fl['flagged']} 列（只標記，請人確認；Grype 發行版比對沒有版本範圍的 "
                     f"{fl['candidates']} 筆）；沒標：" + ("、".join(f"{k} {n}" for k, n in fl["not_flagged"].items()) or "0"))
        for x in fl["rows"][:20]:
            lines.append(f"  例\t{x['id']}\t{x['component']} {x['version']}\t上游 {x['upstream_version']}\t"
                         + "; ".join(u["constraint"] for u in x["upstream_ranges"]) + f"\tUbuntu：{x['ubuntu_status']}")
    # 沒有規則套到、也沒有其他判定的列：分組，看還能加哪些規則（剩下的才要逐列看）
    b, ut = g["untriaged_breakdown"], g["untriaged_by_tier"]
    tl = lambda d: "、".join(f"{k.upper() if k != 'other' else '其他'} {n}" for k, n in d.items())
    if a_["untriaged"]:
        lines.append(f"REST\t沒有判定的 {a_['untriaged']} 列（{tl({k: n for k, n in ut.items() if n})}），依類型 × 修補狀態：")
        for x in b["groups"]:
            lines.append(f"  組\t{x['type']}\t{x['fix_state']}\t{x['rows']} 列（{tl(x['tiers'])}）")
        lines.append(f"REST\t列數最多的套件（前 {len(b['components'])} 個，共 {b['components_total']} 個）：")
        for x in b["components"]:
            lines.append(f"  套件\t{x['component']}\t{x['type']}\t{x['rows']} 列（"
                         + "、".join(f"{k} {n}" for k, n in x["fix_states"].items()) + f"；{tl(x['tiers'])}）")
    return 0, lines


def main(argv=None):
    ap = Parser(description="VEX 的人工判定檔（CRA/Config/vex-annotations.json）；VEX 檔案本身由 cra_report.py 產生")
    sub = ap.add_subparsers(dest="cmd", required=True, parser_class=Parser)
    an = sub.add_parser("annotate", help="新增（或用 --replace 取代）一筆人工判定")
    an.add_argument("--project", required=True)
    an.add_argument("--cve", required=True, help="弱點編號（CVE-…；沒有 CVE 時用原始編號，例如 GHSA-…）")
    an.add_argument("--state", required=True, choices=CDX_STATES)
    an.add_argument("--justification", choices=CDX_JUST, help="not_affected 必填")
    an.add_argument("--response", nargs="+", choices=CDX_RESP, help="exploitable 必填")
    an.add_argument("--detail", required=True, help="理由（英文；會寫進交給客戶的 VEX）")
    an.add_argument("--action-statement", help="exploitable 時給客戶的處理說明（OpenVEX action_statement；沒給時由 response 與 detail 組成）")
    an.add_argument("--author", required=True, help="責任人")
    an.add_argument("--date", help="YYYY-MM-DD（預設今天，UTC）")
    an.add_argument("--purl", help="只用在這個套件（pkg:類型/名稱，可加 @版本）")
    an.add_argument("--version", help="只用在這個版本")
    an.add_argument("--replace", action="store_true", help="取代同一範圍已有的判定")
    an.add_argument("--evidence", choices=EVIDENCE_TYPES, help="排除（not_affected、resolved…）的依據類型；要和 --evidence-location 一起寫")
    an.add_argument("--evidence-location", nargs="+", metavar="LOCATION",
                    help="依據的位置（不能空、不超過 512 字、不能有 ; 與換行）；給多個＝同一類型的多筆依據。on-device：專案資料夾內的相對路徑，檔案要存在；"
                         "design-doc：文件名稱、版本、章節")
    an.add_argument("--evidence-basis", metavar="JSON",
                    help="每一筆依據自己的類型（映像有多顆核心時每顆各一筆）：'[{\"type\": \"build-record\", \"location\": \"…\", \"kernel\": \"5.15.136\"}]'；"
                         "不能和 --evidence 一起用")
    ck = sub.add_parser("check", help="只檢查 vex-annotations.json")
    ck.add_argument("--project", required=True)
    ru = sub.add_parser("rules", help="批次規則（CRA/Config/vex-rules.json）")
    rsub = ru.add_subparsers(dest="rcmd", required=True, parser_class=Parser)
    rc = rsub.add_parser("check", help="檢查格式；加 --scan 時乾跑：每條規則會套用幾列、例子、因 KEV／P1／已有判定而不套用的列")
    rc.add_argument("--project", required=True)
    rc.add_argument("--scan", help="sca-scan 的輸出資料夾（乾跑用）")
    c = rc.add_mutually_exclusive_group()
    c.add_argument("--company", help="公司共用設定（同 cra_report.py）")
    c.add_argument("--no-company", action="store_true")
    ra = rsub.add_parser("add", help="在最後加一條規則（或用 --replace 取代同 id 的規則）")
    ra.add_argument("--project", required=True)
    ra.add_argument("--id", required=True)
    ra.add_argument("--description", required=True, help="一句話說明（英文；會寫進交給客戶的 VEX）")
    ra.add_argument("--author", help="責任人（檔案最上層有 author 時可省略，用那個預設）")
    ra.add_argument("--reason", required=True, help="為什麼可以批次判定（英文；寫進風險評估）")
    ra.add_argument("--date", help="YYYY-MM-DD（預設今天，UTC）")
    ra.add_argument("--scope", required=True, choices=SCOPES)
    ra.add_argument("--purl-prefix", nargs="+")
    ra.add_argument("--purl-type", nargs="+")
    ra.add_argument("--fix-state", nargs="+", choices=FIX_STATES)
    ra.add_argument("--kernel-config", nargs="+", choices=KCFG_MATCH)
    ra.add_argument("--tier", nargs="+", choices=tuple(TIER_ORDER))
    ra.add_argument("--severity", nargs="+", type=str.upper, choices=SEVERITIES)
    ra.add_argument("--epss-max", type=float, help="EPSS 百分位上限（0–1）")
    ra.add_argument("--include-no-epss", action="store_true", help="沒有 EPSS 的列也算（只配 --epss-max）")
    ra.add_argument("--allow-p1", action="store_true", help="也套用在 P1 的列（KEV 的列仍然不套用）")
    ra.add_argument("--state", required=True, choices=CDX_STATES, help="只允許 exploitable、in_triage")
    ra.add_argument("--response", nargs="+", choices=CDX_RESP, help="可省略（上游還沒有修補、發行版 won't fix、資料不足不要寫 can_not_fix/will_not_fix，改用 --detail-template 說明）")
    ra.add_argument("--detail-template", required=True, help="英文；可用 " + "、".join("{" + x + "}" for x in TEMPLATE_FIELDS))
    ra.add_argument("--recommendation", help="exploitable 時給客戶的處理說明（OpenVEX action_statement；同樣可用範本欄位）")
    ra.add_argument("--replace", action="store_true", help="取代同 id 的規則（位置不變）")
    a = ap.parse_args(argv)
    if not Path(a.project).is_dir():
        ap.error(f"不是資料夾：{a.project}")
    if a.cmd == "rules" and a.rcmd == "check" and a.scan and not Path(a.scan).is_dir():
        ap.error(f"不是資料夾：{a.scan}")
    try:
        if a.cmd == "annotate":
            print(f"OK\t{annotate(a)}")
        elif a.cmd == "rules" and a.rcmd == "add":
            print(f"OK\t{rules_add(a)}")
        elif a.cmd == "rules":
            rc, lines = rules_check(a)
            print("\n".join(lines))
            return rc
        else:
            anns, info = load_annotations(a.project)
            for x in anns:
                for w in on_device_warnings(x, a.project):
                    print(f"WARN\t{x['cve']}：{w}")
            if info and info["warnings"]:
                for w in info["warnings"]:
                    print(f"WARN\t{w}")
                print(f"FAIL\t{info['file']} 有 {len(info['ignored'])} 筆判定不會採用（見上方 WARN），其他 {len(anns)} 筆可用")
                return 1
            print(f"OK\t{info['file']} 格式正確，{len(anns)} 筆" if info else f"OK\t沒有 {ANN_REL}（不需要）")
    except (VexInputError, OSError) as e:
        print(f"FAIL\t{e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
