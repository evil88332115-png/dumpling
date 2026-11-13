#!/usr/bin/env python3
"""confirm_items.py：掃描後「要請別人確認的事」的表（待確認事項表），cra_report.py 每次產生文件時一起寫。

軟體部門的 CRA 負責人只做掃描；這張表是出貨前（新版本）用的：掃描負責人和產品工程師直接一起處理，工程師回覆、具名判斷、修好後
掃描負責人記錄並重掃，完成後把六樣交付交給專案負責人（PM）；只有需要別人（專案負責人／法務／核准人）的問題才經過專案負責人。
（出貨後，每日監控發現已出貨產品有新的已被積極利用漏洞時不用這張表：掃描負責人 → 專案負責人 → 通知產品工程師修補，並轉給公司指定的人＋法務。）
這份表把要問的事從這次已有的資料列出來
（不是新的判斷，也不猜事實）；輸入缺少時列一筆「缺少輸入」，不留空白。

cra_report.py 以檔案路徑載入這個模組（build、write、remove），輸出到 CRA/Reports/：
  confirmation-items.csv（UTF-8 加 BOM，Excel 直接開中文不會亂碼；一列一個事項）、
  confirmation-items.md（同樣的內容，給閱讀、列印），summary.json 的 confirmation_items（total、by_ask、by_category）。
欄位：編號、類別、掃描發現（為什麼要問）、影響、要問誰（建議）、要確認的問題、建議做法、回答、決定、填寫人、日期、軟體部門後續。
  回答、決定、填寫人、日期留空給人填；決定是「照建議做／不同意（理由寫在回答）／需要再討論」之一。
規則（依序；每條只用已有的資料）：
  0 缺少輸入：漏洞資料讀不到或不完整、SBOM 沒有、安全測試沒有做、需要套件依賴資料卻沒有 pkgdb。
  1 被利用或 P1 的漏洞：每個（漏洞編號＋元件）一筆；只有具名的「受影響＋處理方式」判定不列（列還在 P1–P3
    就表示 cra_report 沒有採用不受影響／已修補的判定，照樣列出並寫原因）。
    有修補版本 → 建議升級；沒有修補（not-fixed／wont-fix）的 deb 套件 → 用 pkg_why.py 的依賴資料找出是哪個頂層套件帶進來的，
    頂層套件不多（FEW_ROOTS 個以內）時問專案負責人產品需不需要那個功能。
  1b 沒有漏洞資料的套件：no_vuln_data.py 列出的 deb 套件（可能沒有漏洞資料，未評估），每組一筆（很可能的依維護者網域分組，
    可能的合成一組）；問產品工程師版本與上游安全公告。
  2 安全測試：還沒有決定（open）的項目依種類各一筆（預設密碼、映像裡的 SSH 主機金鑰、開機啟動的網路服務、所有人可寫的檔案、
    映像裡的私鑰與帳密）；其他 open 的 high／medium 合成一筆。
  3 開發工具：SBOM 的 deb 套件有編譯器、除錯器等開發工具（DEV_TOOLS），或除錯符號套件，或 -dev 套件 DEV_MIN 個以上 → 問專案負責人客戶要不要在板子上開發；
    影響是只屬於這些套件的未處理漏洞列數。
  4 作業系統核心：核心沒有評估（8.7 節 not_assessed）；核心有漏洞列而核心設定比對（scan/kernel-config.json）沒有可用的結果；
    沒有用到核心的建置紀錄（kernel-config.json 的 kernel.build_record.status 不是 OK；舊版沒有這個欄位時也算沒有）。
  5 對外服務清單：分級方式 exploitation 卻沒有 CRA/Config/exposed-services.json。
  6 公司與產品資料：summary.json 的 missing_fields（TO BE COMPLETED）依負責人分組，每組一筆（OWNER_RULES）。
  7 出貨紀錄：報告只讀得到 product.first_placing_on_market；沒有填 → 問專案負責人出貨紀錄。
排序與編號固定（類別順序、類別內依穩定的鍵排序；Q1、Q2…），同樣的輸入重跑結果相同（不寫產生時間）。
只用標準函式庫。
"""
import csv
import importlib.util
import io
import re
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
CSV_NAME, MD_NAME = "confirmation-items.csv", "confirmation-items.md"
COLUMNS = ("編號", "類別", "掃描發現（為什麼要問）", "影響", "要問誰（建議）", "要確認的問題", "建議做法",
           "回答", "決定", "填寫人", "日期", "軟體部門後續")
DECISIONS = "照建議做／不同意（理由寫在回答）／需要再討論"
CATEGORIES = ("缺少輸入", "被利用或優先處理的漏洞", "沒有漏洞資料的套件", "安全測試", "開發工具", "作業系統核心", "對外服務清單", "公司與產品資料", "出貨紀錄")
ENG, PM, LEGAL, BOSS, QA, SW = "產品工程師", "專案負責人（PM）", "法務", "核准人／產品主管", "QA／認證", "軟體部門（掃描負責人）"
HUMAN_DEFAULT = ("dt", "annotation")         # vex_export.HUMAN（cra_report 傳進來；單獨測試時用這個）
FEW_ROOTS = 3                                # 帶進來的頂層套件在這個數量以內 → 問專案負責人要不要那個功能
LIST_MAX = 8                                 # 一格裡最多列幾個名稱
DEV_MIN = 10                                 # -dev 套件達到這個數量才算「很多」（只有幾個 -dev 常是執行期套件連帶裝的）
DEV_TOOLS = re.compile(r"^(build-essential|gcc(-\d+)?|g\+\+(-\d+)?|clang(-\d+)?|gdb|gdbserver|git|cmake|make|strace|ltrace|valgrind"
                       r"|autoconf|automake|libtool|dpkg-dev)$")
DEV_PKG = re.compile(r"-dev$")
DBG_PKG = re.compile(r"-(dbg|dbgsym)$")
OPEN_TIERS = ("p1", "p2", "p3")
NOT_P1 = "（非 P1：2027-12-11 前處理）"      # 已知、不急的事項（部門決定）：照樣列出，但不寫成現在就要做的事
# 風險評估資料狀態的理由裡，讓清單不完整的（GAP／NOT_ASSESSED）；其他（ATTENTION：有 P1、交叉核對的差異）不是缺少輸入
GAP_REASON = re.compile(r"\b(GAP|NOT_RUN|NOT_ASSESSED|FAIL|TIMEOUT)\b|missing|not in status\.tsv|no readable|nothing was analysed|not available")
STATE_TEXT = {"in_triage": "調查中", "exploitable": "受影響（還沒有處理方式）", "not_affected": "不受影響", "resolved": "已修補",
              "false_positive": "誤報"}          # exploitable 有 response 時改寫「受影響（已有處理方式：…）」，見 state_text
SOURCE_TEXT = {"dt": "DT 的人工分析", "annotation": "人工判定檔", "rule": "批次規則", "distro": "發行版紀錄", "kconfig": "核心設定",
               "nvidia": "NVIDIA 公告推定"}

# 缺的欄位 → 負責人（第一個符合的前綴）。要問誰是建議；欄位說明取自 config.schema.json 的 description。
# 負責人的代號（"PM"、"PM＋法務"…）也是穩定鍵 fields:<代號> 的一部分，不跟著稱呼改；格子裡的文字見 ASK_OF_OWNER
OWNER_RULES = (
    ("vulnerability_contact.", "PM＋法務", "弱點通報窗口與 CVD 政策"),
    ("supplier.notification.", "PM＋法務", "給客戶的通知承諾（時數、管道）"),
    ("supplier.contract_reference", "PM＋法務", "合約編號"),
    ("support.", "核准人／產品主管", "支援期"),
    ("technical_documentation.support_period_rationale", "核准人／產品主管", "支援期"),
    ("risk_assessment.expected_use_period", "核准人／產品主管", "支援期"),
    ("risk_assessment.approval.", "核准人／產品主管", "風險評估的核准與剩餘風險"),
    ("risk_assessment.residual_risk", "核准人／產品主管", "風險評估的核准與剩餘風險"),
    ("risk_assessment.method", "核准人／產品主管", "公司的風險評估方法與流程"),
    ("risk_assessment.part_i_1_and_part_ii", "核准人／產品主管", "公司的風險評估方法與流程"),
    ("technical_documentation.standards", "QA／認證", "標準、測試報告與符合性聲明"),
    ("technical_documentation.test_reports", "QA／認證", "標準、測試報告與符合性聲明"),
    ("technical_documentation.eu_declaration_of_conformity_copy", "QA／認證", "標準、測試報告與符合性聲明"),
    ("eu_declaration_of_conformity_url", "QA／認證", "標準、測試報告與符合性聲明"),
    ("technical_documentation.production_monitoring", "QA／認證", "標準、測試報告與符合性聲明"),
    ("manufacturer.", "PM", "製造商名稱與聯絡方式"),
    ("supplier.customer", "PM", "客戶與更新方式"),
    ("supplier.security_update_delivery", "PM", "客戶與更新方式"),
    ("instructions.security_updates", "PM", "更新怎麼交給客戶"),
    ("instructions.disable_automatic_updates", "PM", "更新怎麼交給客戶"),
    ("technical_documentation.secure_update_distribution", "PM", "更新怎麼交給客戶"),
    ("sbom.", "PM", "更新怎麼交給客戶"),
    ("product.", "PM", "產品資料、用途與使用說明"),
    ("intended_use.", "PM", "產品資料、用途與使用說明"),
    ("foreseeable_risks", "PM", "產品資料、用途與使用說明"),
    ("instructions.", "PM", "產品資料、用途與使用說明"),
    ("", "產品工程師", "產品的技術資料與風險評估內容"),
)
OWNER_ORDER = ("PM", "PM＋法務", "核准人／產品主管", "QA／認證", "產品工程師")
ASK_OF_OWNER = {"PM": PM, "PM＋法務": f"{PM}＋{LEGAL}", "核准人／產品主管": BOSS, "QA／認證": QA, "產品工程師": ENG}
# 公司共用設定可以放的欄位（cra_report.COMPANY_SECTIONS 的報告欄位）：填一次，全部產品共用
COMPANY_PREFIXES = ("manufacturer.", "vulnerability_contact.", "sbom.availability", "technical_documentation.production_monitoring",
                    "technical_documentation.standards", "technical_documentation.secure_update_distribution", "risk_assessment.method",
                    "risk_assessment.part_i_1_and_part_ii")
ANNEX_I_TEXT = {"b": "安全的預設設定", "c": "安全更新", "d": "存取控制", "e": "資料機密性", "f": "資料完整性", "g": "資料最小化",
                "h": "可用性", "i": "不影響其他裝置", "j": "攻擊面最小化", "k": "降低事件影響", "l": "記錄與監控", "m": "資料刪除與移轉"}

# 安全測試的種類：(鍵, 標題, 比對 ID 的樣式, 要問誰, 要確認的問題, 建議做法)
SEC_KINDS = (
    ("passwords", "映像裡設好的密碼（每台相同的預設密碼）",
     re.compile(r"^(img:accounts:(password-in-image|empty-password|hash-in-passwd|weak-hash)|board:account-(empty-)?password:.*"
                r"|img:ssh:(password-auth|permit-empty-passwords|permit-root-login|kbd-interactive-pam)"
                r"|board:ssh-(password-auth|permit-empty-passwords|permit-root-login|kbd-interactive-pam))$"),
     (PM, ENG), "出貨時每台板子是不是同一組帳號密碼？客戶第一次要怎麼登入？需要用密碼從 SSH 登入嗎？",
     "每台不同的密碼（生產時設定）或第一次登入強制改密碼；不需要時關掉 SSH 的密碼登入、改用金鑰"),
    ("host-keys", "映像裡的 SSH 主機金鑰（每台相同）",
     re.compile(r"^img:ssh:baked-host-keys$"),
     (ENG,), "主機金鑰是不是每台板子相同（燒錄時一起複製）？第一次開機會不會重新產生？",
     "出貨映像拿掉 /etc/ssh/ssh_host_*_key，第一次開機時產生（例如 ssh-keygen -A 或 openssh 的首次開機服務）"),
    ("services", "開機就啟動的網路服務",
     re.compile(r"^(img:service:.*|board:service-enabled:.*|board:listen-.*|net:open-.*)$"),
     (PM, ENG), "這些服務是產品功能需要的嗎？客戶會用到哪些？",
     "不需要的服務在出貨映像關掉或拿掉；需要的寫進對外服務清單（CRA/Config/exposed-services.json）並確認預設設定安全"),
    ("world-writable", "所有人都可以寫的檔案或資料夾",
     re.compile(r"^(img:perm:world-writable|board:world-writable-dirs)$"),
     (ENG,), "這些檔案或資料夾為什麼要讓所有帳號都能寫？",
     "改成只有需要的帳號能寫（chmod o-w，資料夾加 sticky bit）"),
    ("secrets", "映像裡的私鑰或帳密",
     re.compile(r"^img:secrets:(private-keys|credentials)$"),
     (ENG, PM), "這些私鑰或帳密是做什麼用的？每台相同嗎？客戶拿到映像就能取出嗎？",
     "從出貨映像拿掉；需要的金鑰在生產或第一次開機時每台各自產生或注入"),
)


_PW = None


def pkgwhy():
    """tools/cra/pkg_why.py（套件依賴；同 cra_report 的其他模組依路徑載入）。載入失敗回傳 None（依賴的說明改寫「看不出來」）。"""
    global _PW
    if _PW is None:
        p = HERE / "pkg_why.py"
        try:
            spec = importlib.util.spec_from_file_location("sca_center_pkg_why", p)
            m = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(m)
        except Exception:
            return None
        _PW = m
    return _PW


def load_pkgdb(path):
    """pkg_why.py extract 的資料夾 → PkgDB；沒有或讀不到 → (None, 原因)。"""
    if path is None:
        return None, "沒有提供"
    pw = pkgwhy()
    if pw is None:
        return None, "pkg_why.py 載入失敗"
    try:
        db = pw.load_db(path)
    except pw.Fail as e:
        return None, f"不能用（{e}）"
    except (OSError, ValueError, KeyError) as e:
        return None, f"讀不到（{type(e).__name__}）"
    return (db, None) if db is not None else (None, "沒有 dpkg-status")


def names(xs, n=LIST_MAX):
    xs = list(xs)
    return "、".join(str(x) for x in xs[:n]) + (f" 等 {len(xs)} 個" if len(xs) > n else "")


def state_text(v):
    """判定 → 給人看的狀態。exploitable 有 response 時寫出處理方式（response 是清單；舊資料可能是字串）。"""
    st = v.get("state")
    if st == "exploitable":
        resp = v.get("response")
        resp = [resp] if isinstance(resp, str) else [str(x) for x in resp] if isinstance(resp, (list, tuple)) else []
        resp = sorted({x.strip() for x in resp if x.strip()})
        if resp:
            return f"受影響（已有處理方式：{'、'.join(resp)}）"
    return STATE_TEXT.get(st, st)


def item(cat, key, finding, impact, ask, question, suggestion, followup):
    return {"category": cat, "key": key, "finding": finding, "impact": impact,
            "ask": "、".join(ask) if isinstance(ask, (list, tuple)) else ask, "question": question, "suggestion": suggestion,
            "followup": followup}


# ---------- 規則 1：被利用或 P1 的漏洞 ----------

def author_missing_default(a):
    return not isinstance(a, str) or not a.strip() or a.strip().casefold() in ("tbd", "todo", "n/a", "unknown", "none", "-", "?", "專案負責人")


def decided(v, human, author_missing=author_missing_default):
    """這一列不用再問：人判定受影響而且寫了處理方式（exploitable＋response），有具名負責人。
    不受影響、誤報、已修補的判定不在這裡算：列還在 P1–P3 就表示 cra_report 沒有採用它（vex_ok、dt_complete 等更嚴格），要留在表裡。"""
    return bool(v) and v.get("source") in human and v.get("state") == "exploitable" and bool(v.get("response")) \
        and not author_missing(v.get("author"))


def row_decided(r, human, author_missing=author_missing_default):
    return decided(r.get("vex"), human, author_missing) and all(decided(x.get("vex"), human, author_missing)
                                                                for x in r.get("vex_extra") or [])


def rejected_why(r, human, author_missing, expl):
    """這一列有人的判定、列卻還在 P1–P3（cra_report 沒有採用）時的原因（盡量說得出來；說不出來時寫一般的說法）。沒有人的判定 → None。"""
    v = r.get("vex") or {}
    if v.get("source") not in human:
        return None
    st = v.get("state")
    if st == "exploitable" and v.get("response"):
        if not author_missing(v.get("author")):
            return None
        return "沒有具名負責人" + ("（DT 的分析不帶負責人，要用 vex_export.py annotate 記具名的決定）" if v.get("source") == "dt" else "")
    if st not in ("not_affected", "false_positive", "resolved", "resolved_with_pedigree"):
        return None
    out = []
    if v.get("source") == "annotation" and author_missing(v.get("author")):
        out.append("沒有具名負責人")
    if v.get("source") == "dt" and r.get("dt_partial"):
        out.append("DT 有部分 finding 沒判")
    if v.get("source") == "dt" and not r.get("dt_partial"):
        out.append("DT 的分析沒有涵蓋每一筆 finding 或沒有理由")
    if st.startswith("resolved") and not expl:
        out.append("已修補（resolved）在現行分級不會讓列離開優先處理")
    if any(not (x.get("vex") or {}).get("state") for x in r.get("vex_extra") or []):
        out.append("併進來的其他 CVE 沒有判定")
    return "、".join(out) or "不符合採用條件，見風險評估的說明"


def why_p1(rs):
    kev = sorted({s for r in rs for s in r.get("kev_sources") or []})
    ex = sorted({s for r in rs for s in r.get("exploited_sources") or []})
    out = []
    if any(r.get("kev") for r in rs):
        out.append("已知被拿來攻擊（KEV" + (f"：{'、'.join(kev)}" if kev else "") + "）")
    if ex:
        out.append("被利用的證據：" + "；".join(ex[:4]) + (" …" if len(ex) > 4 else ""))
    pct = max((r["epss_pct"] for r in rs if isinstance(r.get("epss_pct"), (int, float))), default=None)
    if not out and pct is not None:
        out.append(f"EPSS 百分位 {pct:.3f}（未來 30 天被利用的可能性排在前段）")
    return "；".join(out) or "依弱點處理規則是 P1（優先處理）"


def fix_versions_text(rs):
    vs = sorted({r["fix_next"] for r in rs if r.get("fix_next")}) or sorted({v for r in rs for v in r.get("fix_versions") or []})
    return "、".join(vs)


def deb_roots(db, rs):
    """這個元件在映像裡的二進位套件，與帶進來的頂層（手動安裝）套件。回傳 (bins, roots, base)；看不出來時 bins 是 []。"""
    pw = pkgwhy()
    c = {"purl": rs[0].get("purl"), "component": rs[0].get("name") or rs[0].get("component"),
         "installed_as": sorted({b for r in rs for b in r.get("installed_as") or []})}
    bins = pw.component_bins(db, c)
    if not bins:
        return [], [], False
    roots = sorted({x for b in bins for x in db.why(b)[0]}, key=lambda x: (pw.is_dev(x), x))
    return bins, roots, any(db.base(b) for b in bins)


def vuln_items(rows, human, db, db_why, author_missing=author_missing_default, expl=False):
    groups = {}
    for r in rows:
        if r.get("tier") not in OPEN_TIERS or not (r.get("tier") == "p1" or r.get("kev") or r.get("exploited_sources")):
            continue
        if row_decided(r, human, author_missing):
            continue
        groups.setdefault((str(r.get("id")), str(r.get("component"))), []).append(r)
    items, need_db = [], []
    for (rid, comp), rs in sorted(groups.items(), key=lambda kv: (not any(r.get("kev") or r.get("exploited_sources") for r in kv[1]),
                                                                   kv[0][0], kv[0][1])):
        rs = sorted(rs, key=lambda r: str(r.get("version") or ""))
        vers = sorted({str(r.get("version") or "") for r in rs if r.get("version")})
        other = sorted({c for r in rs for c in r.get("cves") or [] if c != rid})
        kernel = any(r.get("kernel") for r in rs)
        fstates = sorted({r.get("fix_state") or "no Grype data" for r in rs})
        fixv = fix_versions_text(rs)
        cur = [r.get("vex") for r in rs if r.get("vex")]
        cur_txt = "；目前的判定：" + "、".join(sorted({f"{state_text(v)}（{SOURCE_TEXT.get(v['source'], v['source'])}）"
                                                     for v in cur})) if cur else "；還沒有任何判定"
        rej = sorted({w for w in (rejected_why(r, human, author_missing, expl) for r in rs) if w})
        if rej:
            cur_txt += "；判定沒有被採用（" + "；".join(rej) + "）"
        finding = (f"{rid}" + (f"（也是 {names(other, 4)}）" if other else "") + f" 在 {comp} {names(vers, 4) or '（版本不明）'}："
                   + why_p1(rs) + cur_txt)
        sev = sorted({str(r.get("severity") or "UNASSIGNED") for r in rs})
        impact = ("優先處理（P1）" if any(r.get("tier") == "p1" for r in rs) else "已被利用（層級 " + "、".join(sorted({r['tier'].upper() for r in rs})) + "）") \
            + f"；嚴重度 {'、'.join(sev)}" + ("；作業系統核心" if kernel else "")
        ask, extra_q = [ENG], ""
        if kernel:
            sug = ("核心的漏洞：換到包含修補的核心或 L4T 版本" + (f"（Canonical 核心 {fixv} 已修補）" if fixv else "（修補狀態："
                                                                           + "、".join(fstates) + "）")
                   + "；或用核心設定證明有問題的程式沒有編進產品核心")
        elif "fixed" in fstates and fixv:
            sug = f"升級到 {fixv}（或更新的版本），重新掃描確認"
        elif set(fstates) & {"not-fixed", "wont-fix"}:
            sug = f"目前沒有修補版本（{'、'.join(f for f in fstates if f in ('not-fixed', 'wont-fix'))}）。"
            if rs[0].get("ptype") == "deb" or str(rs[0].get("purl") or "").startswith("pkg:deb/"):
                if db is None:
                    need_db.append(f"{rid} {comp}")
                    sug += f"套件依賴資料（pkgdb）{db_why}，看不出是哪個套件把它帶進映像；由產品工程師確認能不能拿掉或關掉相關功能"
                else:
                    bins, roots, base = deb_roots(db, rs)
                    if not bins:
                        sug += "映像的 dpkg 資料裡找不到這個套件（可能不是用 apt 裝的）：由產品工程師確認它從哪裡來、能不能拿掉"
                    elif base:
                        sug += f"{names(bins, 4)} 是系統基本套件，通常不能拿掉：由產品工程師評估緩解方式（關掉相關功能、限制存取）"
                    elif all(db.manual(b) for b in bins) and not any(db.rdeps.get(b) for b in bins):
                        sug += f"{names(bins, 4)} 是直接指定安裝的，沒有別的套件需要它：產品不用的話從映像拿掉，這個漏洞就不在產品裡"
                        ask.append(PM)
                        extra_q = f"專案負責人：產品需要 {names(bins, 4)} 嗎？"
                    elif all(db.manual(b) for b in bins):
                        ups = sorted({u for b in bins for u in db.rdeps.get(b, {})})
                        sug += (f"{names(bins, 4)} 是直接指定安裝的，另外 {names(ups, 4)} 也需要它：要拿掉得先確認這些套件用不用；"
                                "否則由產品工程師評估緩解方式（關掉相關功能、限制存取）")
                    elif not roots:
                        sug += f"找不到把 {names(bins, 4)} 帶進來的頂層套件（依賴關係有循環或太深）：由產品工程師人工確認能不能拿掉"
                    elif len(roots) <= FEW_ROOTS:
                        sug += (f"{names(bins, 4)} 是被 {names(roots)} 帶進來的：產品不需要 {names(roots)} 的功能的話，"
                                "可以一起從映像拿掉，這個漏洞就不在產品裡（拿掉前在板子上確認功能）")
                        ask.append(PM)
                        extra_q = f"專案負責人：產品需要 {names(roots)} 的功能嗎？"
                    else:
                        sug += (f"{names(bins, 4)} 被 {len(roots)} 個頂層套件需要（{names(roots, 4)}），不容易拿掉："
                                "由產品工程師評估緩解方式（關掉相關功能、限制存取）")
            else:
                sug += "由產品工程師確認是哪個應用把它帶進來的、能不能換掉或關掉相關功能"
        else:
            sug = f"修補狀態不明（{'、'.join(fstates)}）：由產品工程師查上游或供應商有沒有修補版本"
        q = ("產品核心有沒有編進或載入有問題的部分（會不會被攻擊到）？要換到哪一版核心或 L4T、什麼時候？" if kernel else
             "產品有用到這個元件有問題的功能嗎（會不會被攻擊到）？要怎麼處理、哪個版本修好？") + (f" {extra_q}" if extra_q else "")
        follow = ("記下判定（vex_export.py annotate，寫負責人與日期）：不受影響寫 not_affected 與理由；受影響寫 exploitable 與處理方式"
                  "（update、workaround_available…）；修好或拿掉後重新掃描")
        items.append(item("被利用或優先處理的漏洞", f"vuln:{rid}:{comp}", finding, impact, ask, q, sug, follow))
    return items, need_db


# ---------- 規則 1b：沒有漏洞資料的套件 ----------

NOVULN_SIGNAL_TEXT = {"vendor_maintainer": "維護者不是發行版", "no_maintainer": "沒有維護者", "no_distro_revision": "版本沒有發行版的修訂號",
                      "same_vendor_domain": "維護者是廠商網域", "origin": "dpkg Origin 不是 Debian／Ubuntu",
                      "nvidia_bulletins_not_ok": "Jetson Linux 套件、NVIDIA 公告的檢查不是 OK",
                      "nvidia_not_jetson_linux": "NVIDIA 套件但不是 Jetson Linux（NVIDIA 公告的檢查沒有評估）",
                      "distro_name_other_domain": "維護者名稱是 Debian／Ubuntu、但沒有發行版的信箱網域",
                      "distro_maintainer_no_revision": "維護者是發行版、版本卻沒有修訂號", "held": "dpkg hold",
                      "vendor_revision_suffix": "修訂號有廠商字尾", "vendor_version_tag": "上游版本有廠商標記",
                      "not_fully_installed": "dpkg 狀態不是 installed"}
NOVULN_LIST = "packages-without-vuln-data.csv"      # no_vuln_data.LIST_NAME：完整清單


def novuln_items(res):
    """no_vuln_data.classify 的結果 → 每組一筆（組的順序沿用結果：很可能的先、套件多的先、鍵）。沒有結果或沒有列出的套件 → []。"""
    if not isinstance(res, dict):
        return []
    items = []
    for g in res.get("groups") or []:
        ps = [p for p in res.get("packages") or [] if p.get("group") == g["key"]]
        if not ps:
            continue
        dom = g["key"].split(":", 1)[1] if ":" in g["key"] else None
        # 組的鍵只有可以印出的網域（no_vuln_data 的隱私規則）；vendor-<雜湊> 是不印出的廠商網域；其他是固定的代號
        who = {"no-maintainer": "沒有維護者", "nvidia": "NVIDIA 套件", "origin": "dpkg Origin 不是 Debian／Ubuntu",
               "held-distro-maintainer": "維護者是發行版、但 dpkg hold 而且版本沒有修訂號（可能是廠商重編的）",
               "held-vendor-revision": "dpkg hold 而且版本有廠商的字尾或標記（可能是廠商重編的）",
               None: "維護者不是發行版或看不出來"}.get(dom) or ("同一個廠商網域（不寫出）" if dom.startswith("vendor-") and "." not in dom
                                                         else f"維護者 @{dom}")
        sig = Counter(s for p in ps for s in p["signals"])
        held = sum(1 for p in ps if p.get("held"))
        lvl = "很可能沒有" if g["level"] == "likely" else "可能沒有"
        labels = [(p["name"] + " " + (p.get("version") or "")).strip() for p in ps]
        finding = (f"這些套件沒有漏洞資料，要人工確認版本與上游安全公告：{names(labels)}（完整清單：{NOVULN_LIST}）"
                   f"（{len(ps)} 個，{who}；{lvl}發行版的漏洞資料；訊號："
                   + "、".join(f"{NOVULN_SIGNAL_TEXT.get(k, k)} {n}" for k, n in sorted(sig.items()))
                   + (f"；dpkg hold {held} 個（apt 不會更新）" if held else "") + "）")
        items.append(item("沒有漏洞資料的套件", f"novuln:{g['key']}", finding,
                          "未評估（NOT_ASSESSED）：沒有任何比對工具報出它們的漏洞列，不代表沒有漏洞（發行版的資料可能不認得這些名稱，"
                          "或不適用廠商自己建置的版本）；詳見風險評估 8.1 節「Packages without vulnerability data」", (ENG,),
                          "這些套件是誰建置的（晶片廠的 BSP、供應商、自己編的）？對應哪個上游專案與版本？上游或供應商有沒有安全公告？",
                          "向供應商要這些套件的上游版本與安全公告（或它們的 SBOM／VEX）；對得到上游元件時，把上游元件與版本告訴掃描負責人，"
                          "加進 SBOM 讓漏洞比對涵蓋；產品不需要的套件從出貨映像拿掉",
                          "記下確認的結果（上游版本、看過的公告、負責人與日期）；SBOM 補上上游元件或拿掉套件後重新掃描"))
    vw = res.get("vendor_with_data") if isinstance(res.get("vendor_with_data"), dict) else {}
    if vw.get("count"):
        ex = [str(x) for x in vw.get("examples") or []]
        br = vw.get("by_reason") if isinstance(vw.get("by_reason"), dict) else {}
        why = "、".join(f"{NOVULN_SIGNAL_TEXT.get(k, k)} {n}" for k, n in sorted(br.items()))
        items.append(item("沒有漏洞資料的套件", "novuln:vendor-with-data",
                          f"只靠名稱（或原始碼套件名稱）對到發行版漏洞資料、但可能不是發行版原版的套件（維護者不是發行版、dpkg hold、"
                          f"或修訂號有廠商字尾）：{names(ex)}"
                          + (f" 等 {vw['count']} 個" if vw["count"] > len(ex) else f"（{vw['count']} 個）") + (f"；{why}" if why else "")
                          + f"（完整清單：{NOVULN_LIST} 的 name_only_data）",
                          "有漏洞列，但那是發行版同名套件的資料：廠商自己建置的版本可能不同（修補可能沒有帶進來，或公告不適用；"
                          "用發行版的修補版本比較，可能把沒修好的判成已修補）",
                          (ENG,), "這些套件是發行版的原版，還是廠商改過、重編的？hold 的版本是不是發行版的建置？發行版的安全公告適用嗎？",
                          "對照供應商的套件來源與版本；是廠商改過的就向供應商要它的安全公告，必要時在 SBOM 標出上游元件",
                          "記下確認的結果（負責人與日期）；不適用的漏洞列用 vex_export.py annotate 記具名的判定"))
    return items


# ---------- 規則 2：安全測試 ----------

def security_items(sec):
    if not sec:
        return []
    opened = sorted((f for f in sec.get("findings") or [] if f.get("state") == "open"), key=lambda f: f["id"])
    items, used = [], set()
    for key, title, rx, ask, q, sug in SEC_KINDS:
        hit = [f for f in opened if rx.match(f["id"]) and f.get("severity") != "info"]
        if not hit:
            continue
        used |= {f["id"] for f in hit}
        sev = Counter(f["severity"] for f in hit)
        finding = f"{title}：" + "；".join(f"{f['id']}（{f['severity']}）{f.get('title') or ''}".strip() for f in hit[:LIST_MAX]) \
            + (f" 等 {len(hit)} 項" if len(hit) > LIST_MAX else "")
        impact = f"{len(hit)} 項沒有決定（" + "、".join(f"{s} {sev[s]}" for s in ("high", "medium", "low") if sev[s]) + "）；詳見 security-findings.md"
        items.append(item("安全測試", f"sec:{key}", finding, impact, ask, q, sug + NOT_P1,
                          "記下決定（security_findings.py decide，寫理由、負責人與日期）；改好後重新做映像檢查或板子檢查"))
    rest = [f for f in opened if f["id"] not in used and f.get("severity") in ("high", "medium")]
    if rest:
        items.append(item("安全測試", "sec:other",
                          "其他沒有決定的 high／medium 安全測試項目：" + "；".join(f"{f['id']}（{f['severity']}）" for f in rest[:LIST_MAX])
                          + (f" 等 {len(rest)} 項" if len(rest) > LIST_MAX else ""),
                          f"{len(rest)} 項；詳見 security-findings.md 的說明與建議處理", (ENG,),
                          "這些項目要改、可以接受，還是誤報？", "依 security-findings.md 每一項的建議處理" + NOT_P1,
                          "記下決定（security_findings.py decide）；改好後重新檢查"))
    return items


# ---------- 規則 3：開發工具 ----------

def dev_items(pkgs, rows):
    debs = sorted({str(c.get("name")) for c in pkgs if str(c.get("purl") or "").startswith("pkg:deb/") and c.get("name")})
    tools = [n for n in debs if DEV_TOOLS.match(n)]
    dbg = [n for n in debs if DBG_PKG.search(n)]
    dev = [n for n in debs if DEV_PKG.search(n)]
    if not tools and not dbg and len(dev) < DEV_MIN:
        return []
    devset = set(tools) | set(dbg) | set(dev)
    hit = [r for r in rows if r.get("tier") in OPEN_TIERS and not r.get("kernel")
           and (set(r.get("installed_as") or []) or {r.get("name")}) <= devset]
    tiers = Counter(r["tier"] for r in hit)
    parts = []
    if tools:
        parts.append(f"開發工具 {names(tools)}")
    if dev:
        parts.append(f"-dev 套件 {len(dev)} 個")
    if dbg:
        parts.append(f"除錯符號套件 {len(dbg)} 個（{names(dbg, 4)}）")
    impact = (f"只屬於這些套件的未處理漏洞列 {len(hit)} 列（P1 {tiers['p1']}、P2 {tiers['p2']}、P3 {tiers['p3']}）；"
              "開發工具也讓拿到板子的人更容易改裝產品")
    return [item("開發工具", "dev:tools", "出貨映像裡有開發或除錯用的套件：" + "；".join(parts), impact, (PM,),
                 "客戶需要在板子上開發（編譯程式、除錯）嗎？",
                 "不需要的話，出貨映像不裝開發套件（pkg_why.py rank 有「不裝開發套件」可以少掉多少列的估計）；需要的話另外做開發版映像" + NOT_P1,
                 "專案負責人決定後回覆掃描負責人；要改映像時掃描負責人和產品工程師一起改，改好後重新掃描")]


# ---------- 規則 4：作業系統核心 ----------

def build_record_used(kcfg):
    """kernel-config.json 的 kernel.build_record（另一個 PR 加的欄位；沒有這個欄位＝沒有用到建置紀錄）。
    格式（kernel_config 的草案）：{"status": "OK"|"GAP", "reason": …}。只有 status 是 OK 才算有用到；其他（沒有欄位、不是物件、GAP）都算沒有。
    回傳 (有沒有用到, 說明)。"""
    k = (kcfg or {}).get("kernel") if isinstance(kcfg, dict) else None
    br = k.get("build_record") if isinstance(k, dict) else None
    if br is None:
        return False, "kernel-config.json 沒有記錄建置紀錄（kernel.build_record）"
    if isinstance(br, dict) and br.get("status") == "OK":
        return True, ""
    why = (br.get("reason") or br.get("detail") or br.get("status")) if isinstance(br, dict) else None
    return False, "沒有用到核心的建置紀錄" + (f"（{why}）" if isinstance(why, str) and why else "")


def boot_items(kboot):
    """scan/kernel-boot.json（C-kernel-boot）：文字依 status 與實際欄位（sha、extlinux、建置紀錄、板子）寫，不假設「兩顆不同、extlinux 指向 rootfs」。
    ATTENTION／GAP 才問；OK 不問。問的人是 RD。"""
    if not isinstance(kboot, dict) or kboot.get("schema") != "sca-center-kernel-boot/1" or kboot.get("status") not in ("ATTENTION", "GAP"):
        return []
    RD = "RD"
    b = kboot.get("board") if isinstance(kboot.get("board"), dict) else {}
    br = kboot.get("build_record") if isinstance(kboot.get("build_record"), dict) else {}
    pi, ri = kboot.get("partition_image") or {}, kboot.get("rootfs_image") or {}
    ext = kboot.get("extlinux") if isinstance(kboot.get("extlinux"), dict) else {}
    cd = kboot.get("config_diff") if isinstance(kboot.get("config_diff"), dict) else {}

    def img(name, d):
        sha = d.get("sha256")
        return f"{name} {str(sha)[:12]}（{d.get('uts') or '沒有版本字串'}）" if sha else f"{name}（讀不到）"
    detail = str(kboot.get("detail") or "")[:300]
    if kboot["status"] == "GAP":
        return [item("作業系統核心", "kernel:two-kernels", f"刷機包的兩顆核心無法比較：{detail}",
                     "不知道 kernel/Image 與 rootfs/boot/Image 是不是同一顆，核心的判定仍以 kernel/Image 為準但沒有核對", (RD,),
                     "kernel/Image 和 rootfs/boot/Image 為什麼讀不到（連結、特殊檔案）？實際開機的是哪一顆核心？",
                     "確認刷機包的兩個檔案都是一般檔案；在板子上跑 uname -v 或 cat /proc/version 放進 board-test 的 os.txt", "修好後重新掃描")]
    same = bool(pi.get("sha256")) and pi.get("sha256") == ri.get("sha256")
    run_rootfs = kboot.get("k1_kernel") == "rootfs"
    parts = ["兩顆核心位元組相同：" + img("kernel/Image", pi)] if same else \
        ["刷機包有兩顆不同的核心：" + img("kernel/Image", pi) + "、" + img("rootfs/boot/Image", ri)
         + (f"；設定差 {cd['differences_total']} 項" if cd.get("differences_total") is not None else "")]
    if ext.get("points_at") == "rootfs/boot/Image":
        parts.append("extlinux.conf 指向 /boot/Image")
    elif ext.get("present") and ext.get("resolved"):
        parts.append(f"extlinux.conf 指向 {ext['resolved']}（不是 /boot/Image）")
    elif not same:
        parts.append("沒有 extlinux.conf")
    qs = []
    if b.get("parsed"):
        if run_rootfs:
            parts.append(f"板子的 uname -v（{b.get('uname_v')}）對上 rootfs/boot/Image，不是 kernel/Image")
        elif b.get("matches_partition_image") and b.get("matches_rootfs_image"):
            parts.append(f"板子的 uname -v（{b.get('uname_v')}）對上兩顆（版本字串相同），分不出來")
        elif not (b.get("matches_partition_image") or b.get("matches_rootfs_image")):
            parts.append(f"板子的 uname -v（{b.get('uname_v')}）和兩顆核心都對不上")
    elif b.get("given"):
        parts.append("給了板子檔但沒有 uname 那一行")
    if br and br.get("matches_partition_image") is False:
        parts.append("建置紀錄 BUILD-INFO 的 image sha256 不是 kernel/Image" + ("（對上 rootfs/boot/Image）" if br.get("matches_rootfs_image") else ""))
        qs.append("建置紀錄是不是這版出貨的核心的？")
    if b.get("parsed") and not run_rootfs and not (b.get("matches_partition_image") and not b.get("matches_rootfs_image")):
        qs.append("板子實際跑的核心和刷機包的核心對不上：板子燒的是哪一版？")
    if not b.get("parsed") and not same:
        qs.append("刷機包有兩顆核心，建置紀錄對應 kernel/Image；請 RD 確認實際開機的核心")
    if not qs:
        qs.append("請 RD 確認實際開機的核心")
    impact = ("板子實際跑 rootfs/boot/Image：核心建置紀錄的排除不適用，核心的漏洞列改用該核心的設定、逐列處理" if run_rootfs else
              "預設仍用 kernel/Image 與建置紀錄判定；若實際開機的是另一顆，核心的判定要重做")
    return [item("作業系統核心", "kernel:two-kernels", "；".join(parts), impact, (RD,), "；".join(qs),
                 "在剛刷好的板子上跑 uname -v 或 cat /proc/version，把輸出放進 board-test 的 os.txt（board-import.sh 匯入）；檔案無法證明實際開機的核心"
                 "（UEFI 開機模式可能改變）", "板子結果匯入後重新掃描（KERNEL_BOARD_OS_TXT）")]


def kernel_versions_items(kvers):
    """scan/kernel-versions.json（sca-scan 的 --kernel-version）：映像出貨（或被指定）但沒有判定的核心。有 not_judged 才問；問的人是 RD。
    C-kernel-config／C-kernel-module-map 的結論只對 judged 的核心成立，沒判定的核心不可以當作不受影響。"""
    if not isinstance(kvers, dict) or kvers.get("schema") not in ("sca-center-kernel-versions/1", "sca-center-kernel-versions/2"):
        return []
    nj = [x for x in kvers.get("not_judged") or [] if isinstance(x, dict) and isinstance(x.get("version"), str)]
    if not nj:
        return []
    RD = "RD"
    judged = [v for v in kvers.get("judged") or [] if isinstance(v, str)]
    reasons = sorted({str(x.get("reason") or "") for x in nj} - {""})
    return [item("作業系統核心", "kernel:not-judged",
                 f"映像出貨的核心有 {len(kvers.get('shipped') or [])} 顆，{len(nj)} 顆沒有判定：{names(x['version'] for x in nj)}"
                 + (f"（{'；'.join(reasons)}）" if reasons else ""),
                 "核心設定比對（C-kernel-config）與模組對應（C-kernel-module-map）至少是 GAP；結論只對判定過的核心（"
                 + (names(judged) if judged else "沒有") + "）成立，沒判定的核心上的漏洞不能用「程式沒有編進核心」排除", (RD,),
                 "沒判定的核心是不是出貨給使用者、板子會不會載入它？要排除它的證據在哪裡？",
                 "要排除某顆核心必須記錄證據（例如設計文件寫明「這個板子不載入它」）；或用 --kernel-version 指定要判定的核心（一次指定一顆；多顆逐一判定還沒實作）",
                 "記錄證據或指定核心後重新掃描")]


def kernel_items(krows, kstate, kcfg, status, kboot=None, kvers=None):
    items = boot_items(kboot) + kernel_versions_items(kvers)
    st = status or {}
    if kstate == "not_assessed":
        why = "；".join(f"{k} {st[k][0]}" for k in ("C-kernel-l4t-map", "C-kernel-coverage") if k in st and st[k][0] != "OK")
        items.append(item("作業系統核心", "kernel:not-assessed", "核心的漏洞沒有評估" + (f"（{why}）" if why else "")
                          + "：沒有核心的漏洞列不代表核心沒有漏洞", "核心的漏洞完全沒有列在報告裡（不是 0 個）", (ENG,),
                          "產品用的是哪一版核心（L4T 版本、核心版本）？SBOM 裡有沒有核心套件？",
                          "提供核心的版本資料，讓掃描能對應到 Canonical 核心（tools/pilot/lib/l4t-kernel-map.json）",
                          "補上對應後重新掃描"))
    ex = ((kcfg or {}).get("kernel") or {}).get("build_record") if isinstance(kcfg, dict) and isinstance((kcfg or {}).get("kernel"), dict) else None
    ex = ex.get("image_modules_not_in_record") if build_record_used(kcfg)[0] and isinstance(ex, dict) else None
    if isinstance(ex, dict) and ex.get("count"):
        mods = [m for m in ex.get("modules") or [] if isinstance(m, dict) and isinstance(m.get("module"), str)]
        def label(m):
            n = m["module"].rsplit("/", 1)[-1]
            mi = m.get("modinfo") if isinstance(m.get("modinfo"), dict) else {}
            det = "；".join(f"{k} {mi[k]}" for k in ("author", "description", "vermagic", "srcversion") if mi.get(k))
            if m.get("class") == 5:
                return f"{n}（樹外廠商模組，未評估{('；' + det) if det else ''}）"
            if m.get("class") == 4:
                return f"{n}（樹外，名稱與樹內模組相同{('；' + det) if det else ''}）"
            if m.get("class") == 2:
                return f"{n}（標示樹內但找不到來源{('；' + det) if det else ''}）"
            return n
        nm = [label(m) for m in mods if m.get("source") == "not_found"]
        im = [label(m) for m in mods if m.get("source") != "not_found"]
        items.append(item("作業系統核心", "kernel:extra-modules",
                          f"出貨映像有 {ex['count']} 個核心模組不在核心建置紀錄的 modules.order"
                          f"（有原始碼的 {ex.get('in_tree', len(im))} 個：{names(im) or '無'}；找不到原始碼的 {ex.get('not_found', len(nm))} 個：{names(nm) or '無'}）",
                          "這些模組的檔案不判「沒編進核心」（判不出來），涉及它們的核心漏洞列要逐列處理；找不到原始碼的模組是 GAP",
                          (ENG,),
                          "這些模組的來源是什麼？是核心原始碼樹的一部分（為什麼建置紀錄沒有）、另外編的樹外模組，還是別的版本留下的？原始碼在哪裡？",
                          "確認來源後，樹外模組補原始碼與建置方式；樹內的補進建置紀錄（用出貨的設定重編）",
                          "拿到來源後重新掃描"))
    if not krows:
        return items
    kst = kcfg.get("status") if isinstance(kcfg, dict) else None
    cst = st.get("C-kernel-config", (None,))[0]
    if kst not in ("OK", "ATTENTION"):
        why = (f"核心設定比對（C-kernel-config）是 {cst or kst or 'NOT_RUN'}" if (cst or kst) else "沒有核心設定比對的結果（scan/kernel-config.json）")
        detail = kcfg.get("detail") if isinstance(kcfg, dict) and isinstance(kcfg.get("detail"), str) else ""
        items.append(item("作業系統核心", "kernel:config", f"{why}" + (f"：{detail[:200]}" if detail else ""),
                          f"核心的 {len(krows)} 列漏洞都不能用「程式沒有編進核心」排除，全部要逐列處理", (ENG,),
                          "能提供產品核心的建置設定嗎（.config 與核心原始碼樹，或映像裡的 linux-headers）？",
                          "提供後用 sca-scan 的 --kernel-build 重新掃描", "拿到後重新掃描"))
    used, why = build_record_used(kcfg)
    if not used:
        items.append(item("作業系統核心", "kernel:build-record", why + "：只能用 headers 的 .config 或 Image 內建的設定推定哪些程式編進核心",
                          f"核心的 {len(krows)} 列漏洞；建置紀錄能證明哪些檔案真的編進核心，排除得更多也更可靠", (ENG,),
                          "這一版出貨的核心，建置時的檔案還在嗎？",
                          "每一版出貨都保留核心建置紀錄：.config、全部的 .*.cmd、modules.order、modules.builtin、System.map（和刷進去的 Image 同一次建置）",
                          "拿到建置紀錄後交給掃描重新判定；之後每版出貨都收"))
    return items


# ---------- 規則 5–7 ----------

def services_items(expl, svc_info):
    if not expl or svc_info is not None:
        return []
    return [item("對外服務清單", "services:list", "分級方式 exploitation 要判斷「對外服務上的漏洞」，但沒有對外服務清單（CRA/Config/exposed-services.json）",
                 "必須判斷的範圍不完整（GAP）；出貨關卡不能判定", (ENG,),
                 "板子開機後有哪些程式在聽網路（哪個埠、哪個套件）？",
                 "在剛刷好的板子上跑 tools/demo/board-on-device.sh（或 ss -lntup 加 dpkg -S），用 board-import.sh 匯入；或手寫 exposed-services.json",
                 "匯入清單後重新產生文件")]


def field_label(path, schema):
    m = re.match(r"^risk_assessment\.annex_i_applicability\.([a-m])$", path)
    if m:
        return f"Annex I ({m.group(1)}) {ANNEX_I_TEXT.get(m.group(1), '')}是否適用與做法"
    node = schema
    for part in re.sub(r"\[\d+\]$", "", path).split("."):
        node = (node.get("properties") or {}).get(part) if isinstance(node, dict) else None
        if node is None:
            break
    d = (node or {}).get("description") if isinstance(node, dict) else None
    if isinstance(d, str) and "：" in d and len(d.split("：", 1)[0]) <= 16:
        d = d.split("：", 1)[1]          # 「VII 1(b)：…」「Annex II 第 5 項：…」的條文編號不要
    return (d.split("；")[0].split("（")[0].strip() if isinstance(d, str) and d.strip() else "") or path


def owner_of(path):
    for pre, owner, topic in OWNER_RULES:
        if path.startswith(pre):
            return owner, topic
    return "產品工程師", "產品的技術資料與風險評估內容"


def company_items(missing, schema, role):
    groups = {}
    for p in sorted(set(missing or [])):
        owner, topic = owner_of(p)
        groups.setdefault(owner, {}).setdefault(topic, []).append(p)
    items = []
    for owner in OWNER_ORDER:
        if owner not in groups:
            continue
        topics = groups[owner]
        paths = [p for t in sorted(topics) for p in topics[t]]
        comp = [p for p in paths if p.startswith(COMPANY_PREFIXES)]
        finding = f"文件裡還是 TO BE COMPLETED 的欄位（{len(paths)} 個）：" + "；".join(
            f"{t}：" + "、".join(f"{field_label(p, schema)}（{p}）" for p in topics[t]) for t in sorted(topics))
        impact = "文件是 GAP，不能交給客戶或主管機關" + ("（供應商資料包也是）" if role == "supplier" else "")
        # 出貨前：產品工程師的欄位直接問；其他人（專案負責人、法務、核准人、QA）的經專案負責人
        sug = (("產品工程師直接回覆掃描負責人，" if owner == "產品工程師" else "經專案負責人找人回答、交回掃描負責人，")
               + "掃描負責人寫進 CRA/Config/config.json"
               + ("；其中公司層級的欄位（" + names(comp, 4) + "）寫進公司共用設定，填一次全部產品共用" if comp else ""))
        q = "請提供這些欄位的內容（不適用的寫 Not applicable 與理由，不要留空）"
        items.append(item("公司與產品資料", f"fields:{owner}", finding, impact, ASK_OF_OWNER[owner], q, sug,
                          "寫進設定檔後重新產生文件，確認 missing_fields 不再列出"))
    return items


def shipping_items(cfg, role):
    prod = (cfg or {}).get("product") or {}
    if prod.get("first_placing_on_market"):
        return []
    who = "客戶（製造商）" if role == "supplier" else "客戶"
    return [item("出貨紀錄", "shipping:record",
                 "報告沒有出貨資料（product.first_placing_on_market 沒填，報告也沒有其他出貨紀錄）",
                 "看不出這一版有沒有出貨、出到哪裡；已出貨版本的被利用漏洞監控（exploited_watch.py）要知道哪些版本出貨了", (PM,),
                 f"這一版要不要出貨？哪個產品、哪個版本、出貨日期、{who}、是不是賣到歐盟？",
                 "專案負責人提供出貨紀錄；首次上市日寫進 product.first_placing_on_market，已出貨的版本在 DT 加 sca-shipped 標籤",
                 "寫進設定與 DT 標籤後重新產生文件")]


def missing_items(have_findings, risk_st, risk_reasons, bom_st, sec, need_db, db_why, bom_reasons=()):
    items = []
    if not have_findings:
        items.append(item("缺少輸入", "input:findings", "漏洞資料（dt/findings.json）沒有讀到", "漏洞相關的事項都沒有列出（不是沒有漏洞）",
                          (SW,), "掃描有沒有跑完、Dependency-Track 有沒有回傳結果？", "查 status.tsv 的 D-dt-* 階段，修好後重新掃描",
                          "重新掃描後再產生這張表"))
    elif risk_st in ("GAP", "NOT_ASSESSED"):
        gap = [str(x) for x in risk_reasons or () if GAP_REASON.search(str(x))]
        items.append(item("缺少輸入", "input:vuln-data", f"漏洞資料不完整（{risk_st}）" + ("：" + "；".join(gap[:4]) + (" …" if len(gap) > 4 else "")
                                                                                         if gap else ""),
                          "下面的漏洞事項可能不完整，沒有列出的不代表沒有問題", (SW,), "哪個掃描階段沒有完成？",
                          "依風險評估開頭的資料狀態說明補齊後重新掃描", "重新掃描後再產生這張表"))
    if bom_st == "NOT_ASSESSED":
        items.append(item("缺少輸入", "input:sbom", "沒有可用的 SBOM（或 0 個元件）", "開發工具與套件的事項都沒有檢查", (SW,),
                          "SBOM 為什麼是空的？", "查 B-sbom-* 與 C-sbomgate，修好後重新掃描", "重新掃描後再產生這張表"))
    elif bom_st == "GAP":
        br = [str(x) for x in bom_reasons or ()]
        items.append(item("缺少輸入", "input:sbom-gap", "SBOM 不完整" + ("：" + "；".join(br[:4]) + (" …" if len(br) > 4 else "") if br else ""),
                          "SBOM 可能少了元件，少掉的元件上的漏洞與開發工具都看不到（不是沒有）", (SW,),
                          "哪個 SBOM 階段沒有完成（B-sbom-*、B-toolchain、B-npm-no-lockfile、C-sbomgate）？",
                          "查 status.tsv 的這些階段；缺鎖定檔或工具鏈的補齊後重新掃描", "重新掃描後再產生這張表"))
    ran = (sec or {}).get("ran") or {}
    notrun = [label for k, label in (("image", "映像靜態檢查（image_check.py）"), ("board", "板子上的檢查"), ("network", "網路掃描")) if not ran.get(k)]
    if notrun:
        items.append(item("缺少輸入", "input:security-tests", "沒有做的安全測試：" + "、".join(notrun),
                          "這些測試的問題（預設密碼、開著的服務等）都沒有列出（不是沒有問題）", (ENG,),
                          "能提供出貨映像或一塊剛刷好的板子做測試嗎？",
                          "映像：scan-flash-package.sh 會自動做映像檢查；板子：tools/demo/board-test.md 的步驟",
                          "匯入結果後重新產生文件"))
    if need_db:
        items.append(item("缺少輸入", "input:pkgdb", f"套件依賴資料（pkgdb）{db_why}：沒有修補的 {len(need_db)} 個漏洞看不出是哪個套件帶進來的"
                          f"（{names(need_db, 4)}）", "不能建議拿掉哪個功能", (SW,), "掃描時有沒有給映像（--archive／--dir）？",
                          "用 pkg_why.py extract 從映像取出 pkgdb（<結果>/<rootfs>/pkgdb），再重新產生文件", "重新產生這張表"))
    return items


# ---------- 組合與輸出 ----------

def build(rows=(), sec=None, pkgs=(), krows=(), kstate=None, kcfg=None, kboot=None, status=None, expl=False, svc_info=None, missing_fields=(),
          cfg=None, role="manufacturer", have_findings=True, risk_st="OK", risk_reasons=(), bom_st="OK", pkgdb=None, human=HUMAN_DEFAULT,
          schema=None, db=None, bom_reasons=(), author_missing=author_missing_default, no_vuln=None, kvers=None):
    """已有的資料 → 事項清單（排好序、編好號）。pkgdb：pkg_why.py extract 的資料夾（或 None）；db：已經讀好的 load_pkgdb(pkgdb) 結果
    （(PkgDB 或 None, 原因)；給了就不再讀 pkgdb）。no_vuln：no_vuln_data.classify 的結果（或 None：不列這一類）。"""
    db, db_why = db if db is not None else load_pkgdb(pkgdb)
    vitems, need_db = vuln_items(list(rows), tuple(human), db, db_why, author_missing, expl) if have_findings else ([], [])
    groups = {
        "缺少輸入": missing_items(have_findings, risk_st, risk_reasons, bom_st, sec, need_db, db_why, bom_reasons),
        "被利用或優先處理的漏洞": vitems,
        "沒有漏洞資料的套件": novuln_items(no_vuln) if bom_st != "NOT_ASSESSED" else [],
        "安全測試": security_items(sec),
        "開發工具": dev_items(list(pkgs), list(rows)) if bom_st != "NOT_ASSESSED" else [],
        "作業系統核心": kernel_items(list(krows), kstate, kcfg, status, kboot, kvers),
        "對外服務清單": services_items(expl, svc_info),
        "公司與產品資料": company_items(missing_fields, schema or {}, role),
        "出貨紀錄": shipping_items(cfg, role),
    }
    out = []
    for c in CATEGORIES:
        out += groups[c]
    for i, x in enumerate(out, 1):
        x["id"] = f"Q{i}"
    return out


def cells(x):
    # 掃描發現前面放穩定的鍵：編號重排後，填好的回答還對得上
    return [x["id"], x["category"], f"[{x['key']}] {x['finding']}", x["impact"], x["ask"], x["question"], x["suggestion"], "", "", "", "", x["followup"]]


def csv_safe(c):
    """試算表會把 = + - @ 開頭的格子當公式（tab、\\r 開頭也會被某些程式略過再當公式）：前面加 '（內容來自掃描資料，不可信）。"""
    c = str(c)
    return "'" + c if c[:1] in ("=", "+", "-", "@", "\t", "\r", "＝", "＋", "－", "＠") else c


def csv_text(items):
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow(COLUMNS)
    for x in items:
        w.writerow([csv_safe(c) for c in cells(x)])
    return "\ufeff" + buf.getvalue()


def md_cell(s):
    return str(s).replace("|", "\\|").replace("\r", " ").replace("\n", " ").strip()


def md_text(items, product, artifact, role):
    who = "客戶（製造商）" if role == "supplier" else "客戶"
    lines = [f"# 待確認事項表：{product}", "",
             f"掃描對象：{artifact}。這張表由 `cra_report.py` 從這次的掃描與設定產生（`{CSV_NAME}` 是同樣內容，用 Excel 填寫）。", "",
             "## 怎麼用", "",
             "這張表是出貨前（新版本）用的。流程：掃描負責人和產品工程師直接一起處理這張表 → 工程師回覆、具名判斷、修好後 → "
             "掃描負責人記錄並重掃 → 完成後把六樣交付交給專案負責人（PM）。只有需要別人（專案負責人／法務／核准人）的問題才經過專案負責人。",
             "六樣交付：SBOM、漏洞清單、VEX、安全檢查結果、待確認事項表、客戶資料包（ODM 案）。", "",
             "1. 軟體部門的掃描負責人列出事項（這張表），和產品工程師一起逐項處理。「要問誰」是產品工程師的，工程師直接回答；"
             "寫專案負責人（PM）（例如「專案負責人（PM）＋法務」）、核准人／產品主管或 QA／認證的，由掃描負責人交給專案負責人，專案負責人找人回答後交回。",
             "2. 「要問誰」只是建議，可以換人。回答的人把答案填在「回答」，並填「決定」、「填寫人」、「日期」。",
             f"   「決定」填其中一個：{DECISIONS}。",
             "3. 掃描負責人記下每個決定（具名、日期）：漏洞的判定用 `vex_export.py annotate`，"
             "安全測試用 `security_findings.py decide`，設定欄位寫進 `CRA/Config/config.json` 或公司共用設定，然後重新掃描。",
             "4. 重新掃描後這張表會重新產生：處理好的事項會消失，沒處理的會留著。編號照順序重排，對照時看「掃描發現」開頭方括號裡的鍵"
             "（例如 `[vuln:CVE-…:元件]`），鍵不會變。",
             f"5. 建議做法寫「{NOT_P1}」的是已知、不急的事：照樣要有決定，但排在 2027-12-11（CRA 主要義務開始適用）之前處理，不是現在就要做。", "",
             "出貨後（已出貨的產品）不用這張表：每日監控發現新的已被積極利用漏洞時，掃描負責人 → 專案負責人（PM）→ "
             "專案負責人通知產品工程師（修補），並轉給公司指定的人＋法務（要不要通報）。", "",
             "注意：表裡只有工具從已有資料看得出來、需要人決定的事；沒有列出的不代表沒有問題。"
             f"要不要通報主管機關或通知{who}，不是這張表要決定的事。", ""]
    by = Counter(x["category"] for x in items)
    lines += [f"共 {len(items)} 項：" + ("、".join(f"{c} {by[c]}" for c in CATEGORIES if by[c]) or "沒有") + "。", ""]
    if items:
        lines += ["| " + " | ".join(COLUMNS) + " |", "|" + "---|" * len(COLUMNS)]
        lines += ["| " + " | ".join(md_cell(c) for c in cells(x)) + " |" for x in items]
        lines.append("")
    return "\n".join(lines) + "\n"


def summary_of(items):
    return {"files": [CSV_NAME, MD_NAME], "total": len(items),
            "by_ask": dict(sorted(Counter(x["ask"] for x in items).items())),
            "by_category": {c: n for c, n in ((c, sum(1 for x in items if x["category"] == c)) for c in CATEGORIES) if n},
            "items": [{"id": x["id"], "key": x["key"], "category": x["category"], "ask": x["ask"]} for x in items]}


def write(out, items, product, artifact, role="manufacturer"):
    out = Path(out)
    (out / CSV_NAME).write_text(csv_text(items), encoding="utf-8", newline="")
    (out / MD_NAME).write_text(md_text(items, product, artifact, role), encoding="utf-8")
    return summary_of(items)


def remove(out):
    for n in (CSV_NAME, MD_NAME):
        (Path(out) / n).unlink(missing_ok=True)


if __name__ == "__main__":
    print("confirm_items.py 由 cra_report.py 載入使用（沒有獨立的指令）")
