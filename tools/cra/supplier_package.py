#!/usr/bin/env python3
"""供應商資料包（計畫總表 #9，對應 S-1、M-6）：config 的 role 是 supplier 時，cra_report.py 呼叫 write() 產生
CRA/Reports/supplier-package/，給把我們的板子與系統映像整合進自己產品的製造商（客戶）。規格：專案文件「供應商資料包規格」。

規則：
- 正文英文。缺的資料寫 TO BE COMPLETED，不填假值；通知時數、天數也一樣（部門規則：不是法定期限就不訂數字；沒填就不寫建議值）。
  supplier.notification.exploited_hours／other_days 可以是數字（寫成 N hours／N days），或一段文字（例如「as agreed in the contract」，原文照寫）。
- 完整風險評估不放進資料包，只放摘要版 risk-summary.md（完整版簽保密協議後另外給，工具不處理）。
- 客戶名稱只來自產品的設定檔（supplier.customer.name），只出現在產出的資料包。
- 沒有掃描或測試結果的部分寫 not assessed，不寫成沒有問題。
- 先寫到暫存資料夾，全部成功才換上（不留半套的資料包）。
"""
import hashlib
import json
import math
import os
import re
import shutil
import tempfile
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))      # cra_report 用 -I 執行，不會自動帶腳本資料夾
from xlsx_min import Sheet, read_xlsx, write_xlsx  # noqa: E402

PKG = "supplier-package"
TBC = "TO BE COMPLETED"
TOOLS_SCOPE_NOTE = ("Scope: build tools delivered with the source code (the build environment container image and the cross toolchain) and "
                    "host-side flashing tools run on the build or flashing machine and are not installed on the product. They are therefore "
                    "not part of the product SBOM and are not scanned.")
COPIED = ("sbom.cdx.json", "vex.cdx.json", "vex.openvex.json")       # 從 CRA/Reports 複製（VEX 改成客戶版白名單輸出）
# 公司欄位還沒填完（文件裡還有 TO BE COMPLETED）的文件不放進資料包，README 與 summary.json 列為「未提供」；不交只有佔位字的文件
OMITTABLE = ("risk-summary.md", "integration-and-configuration.md", "support-and-notification.md")
NOT_PROVIDED = "not provided yet: the supplier information for this document is not complete"
FILES = ("README.md", "sbom.cdx.json", "sbom.md", "vex.cdx.json", "vex.openvex.json", "vulnerability-status.md", "vulnerabilities.xlsx",
         "risk-summary.md", "security-testing-summary.md", "integration-and-configuration.md", "support-and-notification.md", "manufacturer-checklist.md",
         "summary.json", "SHA256SUMS")
PURPOSE = {
    "README.md": "This overview: product identification, supplier contact and the list of files",
    "sbom.cdx.json": "Software bill of materials (CycloneDX JSON) of the supplied software image",
    "sbom.md": "Summary of the SBOM (serial number and component counts)",
    "vex.cdx.json": "Vulnerability status of each candidate vulnerability (CycloneDX VEX)",
    "vex.openvex.json": "The same vulnerability statements in OpenVEX format",
    "vulnerability-status.md": "Summary of known vulnerabilities, their status and what was not assessed",
    "vulnerabilities.xlsx": "Filterable list of all vulnerabilities and their status, one row per vulnerability and component (Excel)",
    "risk-summary.md": "Summary of the supplier's risk assessment for the supplied part (residual risks, mitigations, security testing)",
    "security-testing-summary.md": "Security tests performed on the supplied image and board, and their results",
    "integration-and-configuration.md": "Information for the integrator: known risks, recommended configuration, responsibilities",
    "support-and-notification.md": "Support period, security updates and vulnerability notification commitments",
    "manufacturer-checklist.md": "Obligations of the manufacturer (the integrator) that the supplier cannot fulfil, and what this package provides for each",
    "summary.json": "Machine-readable list of files, hashes and fields still to be completed",
    "SHA256SUMS": "SHA-256 of every file in this package",
}
ANNEX_I = {"b": "Secure by default configuration", "c": "Security updates", "d": "Protection from unauthorised access",
           "e": "Confidentiality of data", "f": "Integrity of data, programs and configuration", "g": "Data minimisation",
           "h": "Availability of essential functions", "i": "Minimise negative impact on other devices or networks",
           "j": "Limit attack surfaces", "k": "Reduce the impact of incidents", "l": "Recording and monitoring of internal activity",
           "m": "Secure removal of data and settings"}
CHECKLIST = [
    ("Determine the product category (default, important class I/II or critical; Annex III and IV)", "Article 7, 8",
     "Product identification and intended use of the supplied part (README.md)"),
    ("Cybersecurity risk assessment of the whole product", "Article 13(2)-(4)", "risk-summary.md; the full supplier assessment on request under NDA"),
    ("Due diligence on integrated components", "Article 13(5); recital 34",
     "sbom.cdx.json, vex.cdx.json, vulnerability-status.md, security-testing-summary.md, support-and-notification.md"),
    ("Vulnerability handling for the whole product during the support period", "Article 13(8); Annex I Part II",
     "support-and-notification.md (security updates and notifications from the supplier)"),
    ("Report vulnerabilities found in the supplied part to the supplier", "Article 13(6)", "support-and-notification.md (security contact)"),
    ("Notify actively exploited vulnerabilities and severe incidents (24 h early warning, 72 h notification, final report)", "Article 14",
     "support-and-notification.md (supplier notification commitments)"),
    ("Coordinated vulnerability disclosure policy and single point of contact", "Article 13(17); Annex I Part II (5), (6)", "—"),
    ("Information and instructions to the user", "Annex II", "integration-and-configuration.md (input for Annex II points 5 and 8)"),
    ("Technical documentation", "Article 31; Annex VII", "sbom.cdx.json (Annex VII point 8), security-testing-summary.md (point 6)"),
    ("Conformity assessment", "Article 32", "—"),
    ("EU declaration of conformity", "Article 28; Annex V", "—"),
    ("CE marking", "Articles 29, 30", "—"),
    ("Indicate the end date of the support period at the time of purchase", "Article 13(19)", "support-and-notification.md (supplier support period)"),
]


def s(v):
    """設定的值 → 字串；空的 → None。"""
    if isinstance(v, str):
        return v.strip() or None
    return None


def strs(v):
    return [x.strip() for x in v if isinstance(x, str) and x.strip()] if isinstance(v, list) else []


def d(v):
    return v if isinstance(v, dict) else {}


class Fields:
    """記錄用到的公司欄位：有值 → 值；沒有 → TO BE COMPLETED 並記進 missing。"""

    def __init__(self):
        self.missing = []

    def get(self, path, value, fallback=TBC):
        if value in (None, "", []):
            if path not in self.missing:
                self.missing.append(path)
            return fallback
        return value

    def listed(self, path, items):
        """清單欄位 → Markdown 清單；空的 → TO BE COMPLETED（記進 missing）。"""
        return bullets(items, "") if items else f"- {self.get(path, None)}"


def header(title, ctx):
    return [f"# {title}", "", f"Product: **{ctx['product']}** · Supplier: **{ctx['supplier']}** · Generated: {ctx['now']}", ""]


def one(x):
    """清單項目：換行改成空白（不讓自由文字拆開 Markdown 清單）。"""
    return " ".join(str(x).split())


def bullets(items, empty):
    return "\n".join(f"- {one(x)}" for x in items) if items else f"- {empty}"


def readme(cfg, f, ctx, table, present, hashes):
    m, p, sp = d(cfg.get("manufacturer")), d(cfg.get("product")), d(cfg.get("supplier"))
    rows = [["Product name", s(p.get("name")) or TBC], ["Model", f.get("product.model", s(p.get("model")))],
            ["Software version", f.get("product.version", s(p.get("version")))],
            ["Identification", f.get("product.identification", s(p.get("identification")))],
            ["Supplier", s(m.get("name")) or TBC], ["Supplier address", f.get("manufacturer.address", s(m.get("address")))],
            ["Supplier website", f.get("manufacturer.website", s(m.get("website")))],
            ["Supplier security contact", f.get("vulnerability_contact.contact", s(d(cfg.get("vulnerability_contact")).get("contact")))],
            ["Customer (manufacturer of the end product)", ctx["customer"]],
            ["Contract reference", f.get("supplier.contract_reference", s(sp.get("contract_reference")))]]
    out = header("Supplier Information Package", ctx) + [
        "This package is provided by the supplier of a component (hardware board and software image) to the manufacturer that integrates "
        "it into its own product with digital elements under Regulation (EU) 2024/2847 (Cyber Resilience Act). It supports the "
        "manufacturer's due diligence on integrated components (Article 13(5)) and the information for integrators (Annex II point 8(f)).", "",
        "**Roles:** supplier of the component: the company named above; manufacturer of the end product: the customer.", "",
        "## Identification", "", table(["Item", "Value"], rows), "",
        "## Files", "",
        table(["File", "Purpose", "SHA-256"],
              [[f"`{n}`", PURPOSE[n] + ("" if n in present else " — **not included in this package** (see below)"),
                f"`{hashes[n]}`" if n in hashes else ("see `SHA256SUMS`" if n in ("summary.json",) else "—")]
               for n in FILES if n not in ("README.md",)]), ""]
    absent = [n for n in COPIED + OMITTABLE if n not in present]
    if absent:
        out += ["Not included: " + "; ".join(f"`{n}` ({present_reason(n, ctx)})" for n in absent) + ".", ""]
    out += ["`manufacturer-checklist.md` is a checklist template for the manufacturer to fill in; it contains no supplier statements.", "",
            "Verify all files with `sha256sum -c SHA256SUMS`.", ""]
    return "\n".join(out)


def present_reason(n, ctx):
    return ctx["absent_reason"].get(n, "not produced by this scan")


TEST_LABELS = {"image": "Static check of the software image (services, SSH, accounts, permissions, keys, binary hardening)",
               "board": "Check on a flashed board (listening ports, SSH, accounts, kernel settings, firewall, updates)",
               "network": "Network scan of a flashed board from another host (open ports, SSH and TLS configuration)"}
COMPLETENESS = {"OK": "complete", "ATTENTION": "complete", "GAP": "incomplete", "NOT_ASSESSED": "not assessed", "FAIL": "failed"}
ORDER = {"OK": 0, "ATTENTION": 1, "INCOMPLETE": 2, "GAP": 3, "NOT_ASSESSED": 4, "FAIL": 5}
NOT_ASSESSED = ("**Not assessed:** no vulnerability findings were available for this scan, so the vulnerability status of the software is "
                "unknown. This does not mean that there are no vulnerabilities.")


BUCKET = {"resolved": "resolved", "resolved_with_pedigree": "resolved", "not_affected": "not_affected", "false_positive": "not_affected",
          "exploitable": "exploitable", "in_triage": "in_triage"}


def statements(vrows):
    """每一列與它併進來的其他 CVE（vex_extra：一列有多個 CVE 別名時，其他 CVE 各自的判定）。"""
    return [x for r in vrows if isinstance(r, dict) for x in [r] + [y for y in r.get("vex_extra") or [] if isinstance(y, dict)]]


def bucket_counts(vrows):
    c = {k: 0 for k in ("exploitable", "in_triage", "untriaged", "resolved", "not_affected")}
    for x in statements(vrows):
        c[BUCKET.get((x.get("vex") or {}).get("state"), "untriaged")] += 1
    return c


# 客戶表格的「Response」「Fix」欄：不放工具名稱與內部欄位文字，也不把「上游還沒有修補」寫成「供應商不能修」。
# 內部報告與 CSV 的原始證據（r["fix"]、修補狀態）不動，這裡只換面向客戶的說法。措辭與 vex-rules.example.json 的 detail_template 一致
MAY_FIX = "A fix may be included in a future release, depending on availability from the distribution or upstream project"
OUTLOOK = {"not-fixed": "No fix available yet; " + MAY_FIX[0].lower() + MAY_FIX[1:],
           "wont-fix": "The distribution has marked this as will not fix; under review",
           "unknown": "Insufficient data (version unknown or no fix information); treated as affected",
           "no Grype data": "Insufficient data (version unknown or no fix information); treated as affected"}
FIXED_OUTLOOK = "A fix is available from the distribution or upstream project and is not yet included in this release"
AMBIGUOUS_OWNER = "Under review: depends on which distribution package installed it"
CUSTOMER_STATUS = {"exploitable": "Affected", "in_triage": "Under assessment", "untriaged": "Under assessment", "resolved": "Fixed",
                   "not_affected": "Not affected"}
LEGACY_RESPONSE = {"can_not_fix": OUTLOOK["not-fixed"], "will_not_fix": "Under review"}
RESPONSE_WORDS = {"update": FIXED_OUTLOOK, "rollback": "Rolling back to an earlier version is an option", "workaround_available": "Workaround available"}


def ambiguous_owner(x):
    """Ubuntu 打包的 Python 模組，但擁有的套件不明或不只一個：修補要看是哪個套件裝的。"""
    dp = x.get("deb_python")
    return isinstance(dp, dict) and not (isinstance(dp.get("owner"), dict) and dp["owner"].get("name"))


def has_fix(x):
    """「A fix is available」只在修補狀態是 fixed 而且有修補版本時才寫。"""
    return x.get("fix_state") == "fixed" and bool(x.get("fix_versions"))


def no_fix_outlook(fs):
    """沒有（確定的）修補時依修補狀態說；fixed 但沒有版本資料＝資料不足。"""
    if fs == "fixed":
        return OUTLOOK["unknown"]
    return OUTLOOK.get(fs, OUTLOOK["unknown"] if fs else "Under review; treated as affected")


def customer_response(x):
    """Response 欄。有 response 的（update 等）照意思說；舊設定檔的 can_not_fix／will_not_fix 不照字面（客戶會讀成供應商不能修／不修），
    改依修補狀態說；沒有 response 的 exploitable 依修補狀態說。"""
    v = x.get("vex") or {}
    resp = [str(y) for y in v.get("response") or []]
    fs = x.get("fix_state")
    if v.get("state") == "exploitable" and ambiguous_owner(x):
        return AMBIGUOUS_OWNER             # 同一種情況不因 response 有沒有寫而說法不同
    out = []
    for y in resp:
        if y in LEGACY_RESPONSE:
            out.append(FIXED_OUTLOOK if has_fix(x) else OUTLOOK.get(fs) or LEGACY_RESPONSE[y])
        elif y in ("update", "rollback"):
            out.append(RESPONSE_WORDS[y] if has_fix(x) else no_fix_outlook(fs))      # 沒有修補版本就不說有修補
        else:
            out.append(RESPONSE_WORDS.get(y, y))
    if out:
        return "; ".join(dict.fromkeys(out))
    if v.get("state") == "exploitable":
        return FIXED_OUTLOOK if has_fix(x) else no_fix_outlook(fs)
    return "—"


def bundled_fix(x, fs, vers):
    """韌體（UEFI）內建的函式庫：apt 升級不適用，要用修補後的函式庫重建韌體。（#188 改 Fix 欄時漏掉，這裡補回，不含工具名稱。）
    修補版本只取與安裝版本同一條發行線的（3.4.1 → 3.4.x）；沒有同線的就全部。"""
    m = re.match(r"(.*?)\s+(\d[^\s]*)\s*\(", str(x.get("component") or ""))
    name, ver = (m.group(1), m.group(2)) if m else (str(x.get("component") or "the library").split(" (")[0], "")
    line = re.match(r"(\d+)\.(\d+)", ver)
    own = [v for v in vers if line and v.startswith(f"{line.group(1)}.{line.group(2)}.")]
    vers = own or vers
    copy = "copy" in str(x.get("bundled_in"))
    where = ("Found in the UEFI source tree, not confirmed to be built into the firmware; if it is, rebuild the UEFI with"
             if copy else "Rebuild the UEFI with")
    if fs == "fixed" and vers:
        return f"{where} {name} {', '.join(vers)} or later (an apt upgrade does not apply)."
    return (f"No fixed {name} version is known yet (an apt upgrade does not apply; the UEFI has to be rebuilt with a fixed {name} once one "
            "exists)" + (", if the library is built into the firmware." if copy else "."))


def affected_fix(fix):
    """狀態是 Affected 的列：Fix 欄的「Fixed in …」是「有修補版本，但不在這個版本裡」，所以寫 Fix available in …，不寫 Fixed。"""
    if isinstance(fix, str) and fix.startswith("Fixed in "):
        return "Fix available in " + fix[len("Fixed in "):]
    return fix


def customer_fix(x):
    """Fix 欄。發行版安裝的套件（含 Ubuntu 打包的 Python 模組）以發行版的修補狀態為準，PyPI 的修補版本不適用、只註明。"""
    fs = x.get("fix_state")
    vers = [str(y) for y in x.get("fix_versions") or []]
    if x.get("bundled_in"):
        return bundled_fix(x, fs, vers)
    o = (x.get("deb_python") or {}).get("owner")
    if isinstance(o, dict) and o.get("name"):
        who = f"{o['name']} (installed {o['version']})" if o.get("version") else str(o["name"])
        pypi = (x.get("deb_python") or {}).get("pypi_fix") or []
        note = (f"; the upstream PyPI fix {', '.join(map(str, pypi))} does not apply to the distribution package" if pypi else "")
        if fs == "fixed" and vers:
            return f"Fixed in the Ubuntu package {o['name']} {', '.join(vers)} (installed {o.get('version') or 'unknown'}){note}."
        if fs == "not-fixed":
            return f"No fix from Ubuntu yet for {who}{note}."
        if fs == "wont-fix":
            return f"Ubuntu has marked this as will not fix for {who}{note}."
        return f"Fix information for the Ubuntu package {who} is not available{note}."
    dp = x.get("deb_python")
    if isinstance(dp, dict):
        # 在發行版的 Python 目錄裡，但擁有的套件不明或不只一個：PyPI 的修補版本不一定適用，要先確認是哪個套件裝的
        cands = [str(c).split(" ", 1)[0] for c in dp.get("candidates") or []]
        pypi = [str(y) for y in dp.get("pypi_fix") or []] or (vers if fs == "fixed" else [])
        who = f"a distribution package ({' or '.join(cands)})" if cands else "a distribution package"
        fixtxt = f"the upstream PyPI fix {', '.join(pypi)} may not apply" if pypi else "no fix information is available"
        return f"Installed by {who}; {fixtxt} — check which package installed it."
    if fs == "fixed" and vers:
        return "Fixed in " + ", ".join(vers) + "."
    if fs == "not-fixed":
        return "No fix available yet."
    if fs == "wont-fix":
        return "Marked as will not fix by the distribution."
    if fs in ("unknown", "no Grype data"):
        return "Fix information not available."
    raw = str(x.get("fix") or "").strip()
    if not raw or raw.lower().startswith("unknown ("):
        return "Fix information not available." if raw else "—"
    return raw


def vulnerability_status(summary, vrows, ctx, table):
    g = d(d(summary.get("vex")).get("gate"))
    a = ctx["artifact"]
    out = header("Vulnerability Status", ctx)
    out += ["## Data used", "",
            table(["Item", "Value"], [["Scan finished", a.get("finished") or "not recorded"],
                                      ["Vulnerability analysis platform version", a.get("dt_version") or "not recorded"],
                                      ["Vulnerability database built", a.get("grype_db_built") or "not recorded"],
                                      ["Completeness of the vulnerability data", COMPLETENESS.get(a.get("data_status"), "not recorded")]]), ""]
    verdict = g.get("verdict")
    if not g or verdict == "NOT_ASSESSED":
        return "\n".join(out + [NOT_ASSESSED, ""])
    if verdict in ("GAP", "FAIL"):
        out += ["**Incomplete:** the vulnerability data for this scan is incomplete. The figures below cover only what was "
                "assessed; missing results do not mean that there are no vulnerabilities.", ""]
    c = bucket_counts(vrows)        # 含別名 CVE 各自的判定（gate 的 counts 只算列本身）
    asm = d(g.get("assessment"))
    under = c.get("in_triage", 0) + c.get("untriaged", 0)
    out += ["## Summary", "",
            table(["Status", "Rows"], [["Affected", c.get("exploitable", 0)], ["Under assessment", under], ["Fixed", c.get("resolved", 0)],
                                       ["Not affected", c.get("not_affected", 0)]]),
            "", "A row is one vulnerability on one component version. Rows under assessment have not been assessed yet; "
                "they are candidates from automated matching, not confirmed vulnerabilities.", "",
            "Rows are counted per vulnerability identifier, including aliases of the same vulnerability, so the totals can differ "
            "slightly from the number of statements in the VEX files.", "",
            f"Assessment complete: **{'yes' if asm.get('complete') else 'no'}**"
            + (f" ({under} rows still under assessment)." if not asm.get("complete") else "."), ""]
    allx = statements(vrows)
    aff = [r for r in allx if (r.get("vex") or {}).get("state") == "exploitable"]
    # 已被利用且還沒解決：KEV、EUVD 與人工證據（exploited_sources）都算；NVIDIA 公告另加的列也在 vrows 裡，不排除。表與上面的句子用同一份清單
    kev = [r for r in allx if (r.get("kev") or r.get("exploited_sources")) and (r.get("vex") or {}).get("state") not in
           ("resolved", "resolved_with_pedigree", "not_affected", "false_positive")]
    kev = sorted(kev, key=lambda r: (r["id"], str(r.get("component")), str(r.get("version"))))
    kev_line = (f"{len(kev)} rows ({len({r['id'] for r in kev})} vulnerabilities) are reported as actively exploited and are not resolved."
                if kev else "")
    out += ["## Affected vulnerabilities", "",
            table(["Vulnerability", "Component", "Version", "Response", "Fix"],
                  [[r["id"], r.get("component"), r.get("version") or "unknown", customer_response(r), affected_fix(customer_fix(r))] for r in sorted(aff, key=lambda r: (r["id"], str(r.get("component"))))])
            if aff else "None recorded as affected.", "",
            "## Reported as actively exploited and not resolved", "",
            *([kev_line, ""] if kev else []),
            table(["Vulnerability", "Component", "Version", "Status"],
                  [[r["id"], r.get("component"), r.get("version") or "unknown", CUSTOMER_STATUS.get((r.get("vex") or {}).get("state"), "Under assessment")]
                   for r in kev]) if kev else "None.", "",
            "## Not assessed", "",
            "Only the components listed in the SBOM were matched against vulnerability databases. Parts that are not software packages in the "
            "root file system (for example boot firmware, device trees and microcontroller firmware) are listed in the SBOM where available "
            "but were not matched against vulnerability databases.", ""]
    return "\n".join(out)


XLSX = "vulnerabilities.xlsx"
XLSX_HEADER = ["Vulnerability", "Component", "Version", "Status", "Known exploited", "Severity", "Severity note", "Response", "Fix",
               "Justification"]
XLSX_WIDTHS = [20, 28, 14, 18, 12, 10, 16, 48, 48, 60]
STATUS_RANK = {"Affected": 0, "Under assessment": 1, "Fixed": 2, "Not affected": 3}
XLSX_NOTES = [
    "Status: Affected means the vulnerability applies to the component version in this release. Under assessment means the "
    "vulnerability is a candidate from automated matching and has not been assessed yet; it is not a confirmed vulnerability. "
    "Fixed means the installed version already contains the fix. Not affected means the vulnerability does not apply to this release; "
    "the Justification column gives the reason.",
    "Known exploited: Yes means the vulnerability is reported as actively exploited in public sources.",
    "This list reflects automated analysis at the date stated on the Vulnerabilities sheet and is provided as information.",
    "The same statements are available in machine-readable form in vex.cdx.json (CycloneDX) and vex.openvex.json (OpenVEX).",
]


def xlsx_rows(vrows, stats=None):
    """vulnerabilities.xlsx 的資料列：沿用 vulnerability-status.md 與客戶 VEX 的同一批列（含別名 CVE）與同一套客戶用語。"""
    out = []
    for x in statements(vrows):
        v = x.get("vex") or {}
        state = BUCKET.get(v.get("state"), "untriaged")
        status = CUSTOMER_STATUS[state]
        score = x.get("cvss_score")
        score = round(float(score), 1) if isinstance(score, (int, float)) and not isinstance(score, bool) and math.isfinite(score) else None
        exploited = bool(x.get("kev") or x.get("exploited_sources"))
        just = ""
        if state == "not_affected":
            just = customer_text(v.get("detail"), "not_affected", stats=stats) if v.get("detail") else FALLBACK["not_affected"]
        fix = customer_fix(x)
        if status in ("Affected", "Under assessment"):
            fix = affected_fix(fix)         # 有修補版本但不在這個版本：Fix available in …（只有 Fixed 的列寫 Fixed in）
        if state == "not_affected":
            fix = "—"                      # 不受影響：沒有要修的東西，理由在 Justification
        elif state == "resolved" and (not has_fix(x) or ambiguous_owner(x)):
            fix = FALLBACK["fixed"]        # 已修補但沒有修補版本資料：不寫「沒有修補」
        out.append((not exploited, STATUS_RANK[status], str(x.get("id")),
                    [x.get("id"), x.get("component"), x.get("version") or "unknown", status, "Yes" if exploited else "No",
                     score if score is not None else "", "" if score is not None else "No CVSS score", customer_response(x),
                     fix, just]))
    out.sort(key=lambda t: (t[0], t[1], t[2], str(t[3][1]), str(t[3][2])))
    return [t[3] for t in out]


def vulnerabilities_xlsx(path, summary, vrows, ctx):
    """Sheet "Vulnerabilities"（一列一個弱點 × 元件，所有狀態）＋ Sheet "Notes"。沒有評估時用一列說明，不留空白工作表。"""
    g = d(d(summary.get("vex")).get("gate"))
    verdict = g.get("verdict")
    top = [[f"Product: {ctx['product']}"]]
    if not g or verdict == "NOT_ASSESSED":
        rows = [["Not assessed", "", "", "Not assessed", "", "", "", NOT_ASSESSED.replace("**", ""), "", ""]]
    else:
        rows = xlsx_rows(vrows)
        c = bucket_counts(vrows)
        top.append(["Rows per status: " + "; ".join(f"{k}: {n}" for k, n in (
            ("Affected", c.get("exploitable", 0)), ("Under assessment", c.get("in_triage", 0) + c.get("untriaged", 0)),
            ("Fixed", c.get("resolved", 0)), ("Not affected", c.get("not_affected", 0))))])
        top.append(["Rows are counted per vulnerability identifier, including aliases of the same vulnerability."])
        if verdict in ("GAP", "FAIL"):
            top.append(["Incomplete: the vulnerability data for this scan is incomplete; missing results do not mean that there are "
                        "no vulnerabilities."])
        if not rows:
            rows = [["None recorded", "", "", "", "", "", "", "No vulnerability rows were recorded in this assessment.", "", ""]]
    top.append([f"Generated: {ctx['now']}"])
    write_xlsx(path, [Sheet("Vulnerabilities", XLSX_HEADER, rows, widths=XLSX_WIDTHS, top=top),
                      Sheet("Notes", ["Notes"], [[n] for n in XLSX_NOTES], widths=[120])])


def _flat(comps):
    for c in comps or []:
        if isinstance(c, dict):
            yield c
            yield from _flat(c.get("components"))


def sbom_counts(bom):
    """送給客戶的 sbom.cdx.json 自己的數字（每個數字同一個來源）：全部元件、非 file 的套件元件、沒有版本（空白或 UNKNOWN）、沒有 purl。"""
    allc = list(_flat(bom.get("components"))) if isinstance(bom, dict) else []
    pk = [c for c in allc if c.get("type") != "file"]
    nov = [c for c in pk if not str(c.get("version") or "").strip() or str(c.get("version")).strip().upper() == "UNKNOWN"]
    return {"components": len(allc), "packages": len(pk), "no_version": len(nov), "no_purl": sum(1 for c in pk if not c.get("purl"))}


def sbom_summary(summary, ctx, table, present, bom=None):
    ps = d(summary.get("product_sbom"))
    out = header("Software Bill of Materials – Summary", ctx)
    if "sbom.cdx.json" not in present:
        return "\n".join(out + [f"**No SBOM in this package** ({present_reason('sbom.cdx.json', ctx)}).", ""])
    c = sbom_counts(bom) if bom is not None else {}
    nr = "not recorded"
    return "\n".join(out + [
        "`sbom.cdx.json` is the software bill of materials of the supplied software image (CycloneDX JSON). "
        "All numbers below are counted in that file.", "",
        table(["Item", "Value"], [["Serial number", ps.get("serial") or nr],
                                  ["Components (all, including files)", c.get("components", nr)],
                                  ["Package components (not files)", c.get("packages", nr)],
                                  ["Package components without a version (empty or `UNKNOWN`)", c.get("no_version", nr)],
                                  ["Package components without a Package URL", c.get("no_purl", nr)]]), "",
        "A component whose version is `UNKNOWN` has no known version; it is not matched against vulnerability data. "
        "The SBOM lists the components found by automated analysis of the software image; components that the analysis does not "
        "recognise are not listed.", ""]
        + ([TOOLS_SCOPE_NOTE, ""] if ctx["artifact"].get("tools_scope_note") else [])
        + (["## Boot firmware coverage", "", ctx["artifact"]["boot_firmware_text"], ""] if ctx["artifact"].get("boot_firmware_text") else []))


def security_testing(sec, ctx, table):
    out = header("Security Testing Summary", ctx)
    tests = [t for t in sec.get("tests") or [] if isinstance(t, dict)]
    out += ["## Tests", "",
            table(["Test", "Performed", "Date", "Result"],
                  [[TEST_LABELS.get(t.get("key"), str(t.get("key"))), "yes" if t.get("ran") else "**no (not assessed)**", t.get("date") or "—",
                    ("incomplete or failed checks" if (t.get("status") not in (None, "OK") or t.get("checks_not_ok") or t.get("missing"))
                     else "completed") if t.get("ran") else "—"] for t in tests]), ""]
    if not any(t.get("ran") for t in tests):
        return "\n".join(out + ["**No security test results were available.** This does not mean that there are no findings.", ""])
    if sec.get("status") not in ("OK",):
        out += ["Some tests have open findings, incomplete checks or findings still to be decided (details below).", ""]
    cnt = d(sec.get("counts"))
    out += ["## Findings by severity", "",
            table(["Severity", "Total", "Open", "Of the open: marked fixed, not confirmed by re-test", "Accepted risk", "False positive"],
                  [[sv, d(cnt.get(sv)).get("total", 0), d(cnt.get(sv)).get("open", 0), d(cnt.get(sv)).get("fixed", 0),
                    d(cnt.get(sv)).get("accepted", 0), d(cnt.get(sv)).get("false_positive", 0)] for sv in cnt]), ""]
    acc = [x for x in sec.get("findings") or [] if x.get("state") == "accepted"]
    if acc:
        out += ["## Accepted risks", "", table(["Severity", "Finding"], [[x["severity"], one(x.get("title") or x["id"])] for x in acc]), "",
                "The rationale for each accepted risk is recorded in the supplier's risk assessment (available under a non-disclosure "
                "agreement).", ""]
    return "\n".join(out)


def risk_summary(cfg, sec, summary, vrows, f, ctx, table):
    sp = d(cfg.get("supplier"))
    risks = [r for r in (sp.get("risks") if isinstance(sp.get("risks"), list) else []) if isinstance(r, dict)]
    out = header("Risk Assessment Summary (supplied part)", ctx)
    out += ["This is a summary of the supplier's cybersecurity risk assessment of the supplied board and software image. The manufacturer "
            "remains responsible for the risk assessment of its whole product (Article 13(2)).", "",
            "## Risks and mitigations in the supplied part", ""]
    if risks:
        out += [table(["Risk", "Mitigation", "Residual risk"], [[s(r.get("risk")) or TBC, s(r.get("mitigation")) or TBC,
                                                                 s(r.get("residual")) or TBC] for r in risks])]
        f.missing += [f"supplier.risks[{i}]" for i, r in enumerate(risks) if not all(s(r.get(k)) for k in ("risk", "mitigation", "residual"))]
    else:
        out += [f.get("supplier.risks", None)]
    ap = d(d(cfg.get("risk_assessment")).get("annex_i_applicability"))
    rows = []
    for k, name in ANNEX_I.items():
        x = d(ap.get(k))
        if x.get("applies") is True:
            rows.append([f"({k}) {name}", "applies", s(x.get("measures")) or TBC])
        elif x.get("applies") is False:
            rows.append([f"({k}) {name}", "not applicable", s(x.get("justification")) or TBC])
        else:
            rows.append([f"({k}) {name}", TBC, TBC])
            f.get(f"risk_assessment.annex_i_applicability.{k}", None)
    vg = d(d(summary.get("vex")).get("gate"))
    vc = bucket_counts(vrows)
    op = d(sec.get("open"))
    ran = any(t.get("ran") for t in sec.get("tests") or [] if isinstance(t, dict))
    if not vg or vg.get("verdict") == "NOT_ASSESSED":
        vline = "Vulnerabilities: not assessed (no vulnerability findings available); this does not mean that there are none."
    else:
        vline = (f"Vulnerabilities: {vc.get('exploitable', 0)} rows affected, {vc.get('in_triage', 0) + vc.get('untriaged', 0)} under assessment "
                 "(see vulnerability-status.md)" + ("; the vulnerability data is incomplete." if vg.get("verdict") in ("GAP", "FAIL") else "."))
    out += ["", "## Essential cybersecurity requirements (Annex I Part I point (2)): applicability and supplier measures", "",
            "Input for the manufacturer's own assessment; this is not a statement of conformity.", "",
            table(["Requirement", "Status", "Measures or justification"], rows), "",
            "## Residual risks", "",
            bullets([vline,
                     ("Security testing: open findings " + ", ".join(f"{k} {v}" for k, v in op.items()) + " (see security-testing-summary.md)."
                      if ran else "Security testing: not assessed (no test results available)."),
                     *[f"Accepted risk: {x.get('title') or x['id']}" for x in sec.get("findings") or [] if x.get("state") == "accepted"]], ""), "",
            "The full risk assessment of the supplied part is available on request under a non-disclosure agreement.", ""]
    return "\n".join(out)


def integration(cfg, sec, f, ctx):
    it = d(d(cfg.get("supplier")).get("integration"))
    op = [x for x in sec.get("findings") or [] if x.get("state") == "open" and x.get("severity") in ("high", "medium")]
    ran = any(t.get("ran") for t in sec.get("tests") or [] if isinstance(t, dict))
    out = header("Integration and Configuration Information", ctx)
    out += ["Information necessary for the integrator (Annex II point 8(f)); input for the manufacturer's user information (Annex II points 5 "
            "and 8).", "",
            "## Known risks and limitations", "", f.listed("supplier.integration.known_risks", strs(it.get("known_risks"))), "",
            "## Recommended secure configuration", "",
            f.listed("supplier.integration.recommended_configuration", strs(it.get("recommended_configuration"))), "",
            "## Responsibilities of the manufacturer", "",
            f.listed("supplier.integration.manufacturer_responsibilities", strs(it.get("manufacturer_responsibilities"))), "",
            "## Open security test findings (high and medium)", "",
            bullets([f"{x['severity']}: {x.get('title') or x['id']}" for x in op],
                    "None open in the tests performed (see security-testing-summary.md)." if ran else
                    "Not assessed (no security test results)."), ""]
    return "\n".join(out)


def number(v, top):
    """設定的時數／天數：1 到 top 之間的有限數字 → 文字（整數不帶小數）；其他 → None。"""
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    try:
        x = float(v)
    except OverflowError:
        return None
    if not (math.isfinite(x) and 1 <= x <= top):
        return None
    return str(int(x)) if x == int(x) else f"{x:g}"


def notice_time(v, top, unit):
    """通知時限：數字 → 「N hours／days」；非空文字 → 原文；其他 → None（沒填）。"""
    if isinstance(v, str) and v.strip():
        return " ".join(v.split())
    n = number(v, top)
    return f"{n} {unit}" if n else None


def support(cfg, f, ctx, table):
    sp, su, vc = d(cfg.get("supplier")), d(cfg.get("support")), d(cfg.get("vulnerability_contact"))
    n = d(sp.get("notification"))
    h = f.get("supplier.notification.exploited_hours", notice_time(n.get("exploited_hours"), 8760, "hours"))
    dtext = f.get("supplier.notification.other_days", notice_time(n.get("other_days"), 3650, "days"))
    out = header("Support and Notification Commitments", ctx)
    out += ["## Support period", "",
            table(["Item", "Value"], [["End of the supplier's support period (month/year)", f.get("support.end_date", s(su.get("end_date")))],
                                      ["Type of security support", f.get("support.type", s(su.get("type")))],
                                      ["How security updates are provided", f.get("supplier.security_update_delivery",
                                                                                  s(sp.get("security_update_delivery")))]]), "",
            "## Vulnerability notifications from the supplier to the manufacturer", "",
            table(["Item", "Commitment"], [["Actively exploited vulnerability affecting the supplied part: notify within", h],
                                           ["Other vulnerabilities affecting the supplied part: notify within", dtext],
                                           ["Notification channel", f.get("supplier.notification.channel", s(n.get("channel")))]]), "",
            "Times run from when the supplier becomes aware of the vulnerability. They are intended to let the manufacturer meet its own "
            "reporting obligations under Article 14.", "",
            "## Reporting vulnerabilities to the supplier", "",
            f"Report vulnerabilities found in the supplied part (Article 13(6)) to: {f.get('vulnerability_contact.contact', s(vc.get('contact')))}.", ""]
    if s(sp.get("contract_reference")):
        out += [f"The binding terms are those of contract {one(sp['contract_reference'])}.", ""]
    return "\n".join(out)


def checklist(ctx, table, omitted=()):
    out = header("Manufacturer Checklist", ctx)
    out += [f"Manufacturer of the end product: **{ctx['customer']}**.", "",
            "The following obligations of Regulation (EU) 2024/2847 apply to the manufacturer of the end product. The supplier cannot "
            "fulfil them on the manufacturer's behalf; the right-hand column shows what this package provides as input.", "",
            table(["Obligation of the manufacturer", "Reference", "Input from this package"], [list(x) for x in CHECKLIST]), ""]
    text = "\n".join(out)
    for n in omitted:          # 這份資料包沒有提供的文件：不指向不存在的檔案
        text = text.replace(n, f"{n} (not provided in this package)")
    return text


def vuln_status(summary, ctx):
    """漏洞資料：NOT_ASSESSED（沒有 DT 結果）、GAP／FAIL（不完整）、OK。"""
    g = d(d(summary.get("vex")).get("gate"))
    if not g or g.get("verdict") == "NOT_ASSESSED":
        return "NOT_ASSESSED"
    ds = ctx["artifact"].get("data_status")
    return ds if ds in ORDER else ("GAP" if g.get("verdict") in ("GAP", "FAIL") else "OK")


def tests_status(sec):
    """安全測試：NOT_ASSESSED（都沒做）、INCOMPLETE（有沒做的或檢查不完整）、ATTENTION（有未處理的發現）、OK。"""
    tests = [t for t in sec.get("tests") or [] if isinstance(t, dict)]
    if not any(t.get("ran") for t in tests):
        return "NOT_ASSESSED"
    if not all(t.get("ran") for t in tests) or any(t.get("status") not in (None, "OK") or t.get("checks_not_ok") or t.get("missing")
                                                   for t in tests if t.get("ran")):
        return "INCOMPLETE"
    return "ATTENTION" if any(d(sec.get("open")).values()) else "OK"


def sha(data):
    return hashlib.sha256(data).hexdigest()


PERSONAL_PROPS = ("sca-center:annotation-author", "sca-center:vex-rule-author")


def scrub(obj):
    """VEX 的複本拿掉內部人員姓名（人工判定與批次規則的作者）。（舊的黑名單做法；客戶資料包改用下面的白名單 customer_vex，這個留給外部呼叫端）"""
    if isinstance(obj, dict):
        return {k: scrub(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [scrub(x) for x in obj if not (isinstance(x, dict) and x.get("name") in PERSONAL_PROPS)]
    return obj


# ---- 客戶版 VEX：白名單輸出。只留 CycloneDX／OpenVEX 要的欄位與文字；內部屬性（sca-center:*）、規則代號、工具名稱、建置紀錄／IKCONFIG 證據一律不帶。
# 判定（state、justification、response、affects、status）原樣照抄，只有說明文字被換成客戶看得懂的句子。內部版（Reports/vex.cdx.json）不動。
CJK = re.compile(r"[\u2e80-\u9fff\uf900-\ufaff\uff00-\uffef\u3000-\u303f]")
LOCAL_PATH = re.compile(r"(?:^|[\s\"'(=])(?:/media/|/home/|/opt/|/tmp/|/var/|/mnt/|/usr/local/|[A-Za-z]:\\)")
INTERNAL_WORDS = re.compile(r"Grype|Dependency[- ]Track|\bDT\b|sca-center|sca-scan|bulk rule|IKCONFIG|build record|"
                            r"vulnerability-handling rule|\.py\b|\bR\d+[a-z]*\b(?=[:\s)])|CLAUDE\.md|osv-offline|scan/")
# 說明文字（不是整個檔案）另不可有內部狀態代號；in_triage 是 CycloneDX 的狀態值，在檔案裡是合法的
# 發版承諾式用語：客戶可見的檔案不可以出現（對外不訂「之後會修」）
COMMIT_WORDS = re.compile(r"(?i:later release|will be included|re-checked|every release|planned|next image)")
TOOL_WORDS = re.compile(r"Grype|Dependency[- ]Track|sca-center|sca-scan|bulk rule")
TEXT_WORDS = re.compile(INTERNAL_WORDS.pattern + r"|NOT_ASSESSED|in_triage|untriaged|" + COMMIT_WORDS.pattern)
# SBOM 有檔案元件（*.py、scan/ 目錄都合法），所以只查工具名稱
SBOM_WORDS = re.compile(r"Grype|Dependency[- ]Track|sca-center|sca-scan")
BULK_SUFFIX = re.compile(r"\s*\(bulk rule .*\)\s*$", re.S)
KIND = {"exploitable": "affected", "in_triage": "under_investigation", "untriaged": "under_investigation", "resolved": "fixed",
        "resolved_with_pedigree": "fixed", "not_affected": "not_affected", "false_positive": "not_affected",
        "affected": "affected", "under_investigation": "under_investigation", "fixed": "fixed"}
KERNEL_NOT_BUILT = "The affected code is not built into the shipped kernel (kernel build configuration)."
FALLBACK = {"affected": "Treated as affected; no fix is available in this release.", "under_investigation": "Under assessment.",
            "fixed": "Fixed in the installed version.", "not_affected": "Assessed as not affected."}
ACTION_FALLBACK = "Under review; a fix may be included in a future release, depending on availability from the distribution or upstream project."
DISTRO_NOT_AFFECTED = "The distribution's security records state that the installed package version is not affected."
DISTRO_FIXED = "The distribution's security records show that the installed package version already contains the fix."
VERSION_UNKNOWN = ("Under assessment: the component version is not known, so the component is not matched against vulnerability data; "
                   "no version is assumed.")


FIXED_IN = re.compile(r"(?:^|(?<=[.:] ))Fixed in ")
NEXT_IMAGE = re.compile(r"Fixed by updating (\S+) to (\S+) or later in the next image\.?")


def customer_sbom(bom):
    """客戶版 SBOM：拿掉內部屬性（sca-center:*）與產生工具（sca-center 自己的工具項）。元件、版本（含 UNKNOWN）、purl、依賴不動。
    內部版（Reports/sbom.cdx.json）不動。"""
    def walk(o):
        if isinstance(o, dict):
            out = {}
            for k, v in o.items():
                if k == "properties" and isinstance(v, list):
                    v = [x for x in v if not (isinstance(x, dict) and str(x.get("name", "")).startswith("sca-center:"))]
                    if not v:
                        continue
                out[k] = walk(v)
            return out
        if isinstance(o, list):
            return [walk(x) for x in o if not (isinstance(x, dict) and x.get("group") == "sca-center")]
        if isinstance(o, str) and o.startswith("sca-center:"):      # bom-ref／依賴的參照（sca-center:flash:…）：整份一致地改前綴，參照關係不變
            return "ext:" + o[len("sca-center:"):]
        return o
    return walk(bom)


ACTION_REWRITE = ((re.compile(r"^Track\b.*", re.S), ACTION_FALLBACK),
                  (re.compile(r"^The distribution will not fix it;.*", re.S), "The distribution has marked this as will not fix; under review."),
                  (re.compile(r"^Look for fix information .*", re.S), "Insufficient data; treated as affected until fix information is available."),
                  (re.compile(r"^Plan: move to"), "Move to"))


def customer_text(text, kind, action=False, stats=None):
    """VEX 的說明文字 → 客戶版。去掉內部後綴（「(bulk rule R8: …)」）；已知的內部證據文字換成一句白話；
    清完後仍有工具名稱、內部代號、中文、本機路徑的，整段換成依狀態的一般句子。判定本身不經過這裡。"""
    if not isinstance(text, str):
        return text
    t = BULK_SUFFIX.sub("", text).strip()
    if t.startswith("Kernel configuration check ("):
        t = KERNEL_NOT_BUILT
    elif t.startswith("Ubuntu CVE Tracker ("):
        t = DISTRO_FIXED if kind == "fixed" else DISTRO_NOT_AFFECTED
    elif t.startswith("fixed by Ubuntu "):
        t = DISTRO_FIXED
    elif t.startswith("Version unknown:"):
        t = VERSION_UNKNOWN
    if kind in ("affected", "under_investigation"):      # 還沒修好的列：有修補版本但不在這個版本，不寫「Fixed in」
        t = FIXED_IN.sub("Fix available in ", t)
    t = NEXT_IMAGE.sub(lambda m: f"Apply {m.group(1)} {m.group(2)} or later when it is included in a release.", t)
    if action:
        for rx, new in ACTION_REWRITE:
            if rx.search(t):
                t = rx.sub(new, t) if new == "Move to" else new
                break
    elif COMMIT_WORDS.search(t):                  # 說明文字：只拿掉含承諾用語的句子，其餘照留
        t = " ".join(x for x in re.split(r"(?<=\.)\s+", t) if not COMMIT_WORDS.search(x)).strip()
    if not t or CJK.search(t) or LOCAL_PATH.search(t) or TEXT_WORDS.search(t):
        if stats is not None:
            stats["generic"] = stats.get("generic", 0) + 1
        return ACTION_FALLBACK if action else FALLBACK.get(kind, "Under assessment.")
    return t


CDX_VULN_KEYS = ("bom-ref", "id", "source", "references", "ratings", "cwes", "description", "recommendation", "advisories", "created",
                 "published", "updated", "analysis", "affects")
CDX_ANALYSIS_KEYS = ("state", "justification", "response", "detail", "firstIssued", "lastUpdated")
CDX_TOP_KEYS = ("bomFormat", "specVersion", "serialNumber", "version", "metadata", "vulnerabilities")
OPENVEX_TOP_KEYS = ("@context", "@id", "author", "role", "timestamp", "last_updated", "version", "statements")
OPENVEX_STMT_KEYS = ("@id", "vulnerability", "products", "status", "justification", "impact_statement", "status_notes", "action_statement",
                     "timestamp", "last_updated", "supplier")


def customer_cdx(bom, stats=None):
    """CycloneDX VEX → 客戶版（白名單）。metadata 只留時間與產品；屬性只留 openvex:action_statement（OpenVEX 的 action 對照，文字已清）。"""
    out = {k: bom[k] for k in CDX_TOP_KEYS if k in bom and k not in ("metadata", "vulnerabilities")}
    md = bom.get("metadata")
    if isinstance(md, dict):
        out["metadata"] = {k: md[k] for k in ("timestamp", "component") if k in md}
    vulns = []
    for v in bom.get("vulnerabilities") or []:
        if not isinstance(v, dict):
            continue
        kind = KIND.get(str((v.get("analysis") or {}).get("state")), "under_investigation")
        o = {k: v[k] for k in CDX_VULN_KEYS if k in v}
        if isinstance(v.get("analysis"), dict):
            a = {k: v["analysis"][k] for k in CDX_ANALYSIS_KEYS if k in v["analysis"]}
            if "detail" in a:
                a["detail"] = customer_text(a["detail"], kind, stats=stats)
            o["analysis"] = a
        props = []
        for p in v.get("properties") or []:
            if isinstance(p, dict) and p.get("name") == "openvex:action_statement":
                props.append({"name": p["name"], "value": customer_text(p.get("value"), kind, action=True, stats=stats)})
        if props:
            o["properties"] = props
        vulns.append(o)
    out["vulnerabilities"] = vulns
    return out


def customer_openvex(doc, stats=None):
    """OpenVEX → 客戶版（白名單）。affected 的陳述一定要有 action_statement（OpenVEX 要求）。"""
    out = {k: doc[k] for k in OPENVEX_TOP_KEYS if k in doc and k != "statements"}
    stmts = []
    for s_ in doc.get("statements") or []:
        if not isinstance(s_, dict):
            continue
        kind = KIND.get(str(s_.get("status")), "under_investigation")
        o = {k: s_[k] for k in OPENVEX_STMT_KEYS if k in s_}
        for k in ("status_notes", "impact_statement"):
            if k in o:
                o[k] = customer_text(o[k], kind, stats=stats)
        if "action_statement" in o:
            o["action_statement"] = customer_text(o["action_statement"], kind, action=True, stats=stats)
        if s_.get("status") == "affected" and not o.get("action_statement"):
            o["action_statement"] = ACTION_FALLBACK
        stmts.append(o)
    out["statements"] = stmts
    return out


def customer_vex(name, obj, stats=None):
    return customer_cdx(obj, stats) if name == "vex.cdx.json" else customer_openvex(obj, stats)


def check_customer_text(name, text):
    """客戶檔案的語言與內容檢查：不可有中文、本機路徑。VEX 另不可有內部屬性與工具名稱。回傳問題清單（空的＝通過）。"""
    bad = []
    if CJK.search(text):
        bad.append("CJK")
    if name != "sbom.cdx.json" and LOCAL_PATH.search(text):       # SBOM 裡的路徑是映像裡的路徑（/opt/…），不是本機路徑
        bad.append("local path")
    if (name.startswith("vex.") and (INTERNAL_WORDS.search(text) or "sca-center:" in text)) or \
            (name == "sbom.cdx.json" and SBOM_WORDS.search(text)) or (name != "sbom.cdx.json" and TOOL_WORDS.search(text)):
        bad.append("internal term")
    if name != "sbom.cdx.json" and COMMIT_WORDS.search(text):
        bad.append("commitment wording")
    return [f"{name}: {b}" for b in bad]


def write(out, cfg, summary, sec, vrows, artifact, now, tool, table, absent_reason=None):
    """產生 <out>/supplier-package/。回傳 summary.json 用的 dict（status、files、missing_fields）。
    sec：security_findings.evaluate() 的結果；vrows：VEX 判定後的列；artifact：meta.json 的欄位與 data_status（漏洞資料的完整度）。
    先寫到同一層的暫存資料夾，全部成功才換上；舊的資料包先改名放旁邊，換上後才刪。"""
    out = Path(out)
    pdir = out / PKG
    for x in out.glob(f".{PKG}.*"):          # 上一次被中斷留下的暫存資料夾
        shutil.rmtree(x, ignore_errors=True)
    tmp = Path(tempfile.mkdtemp(prefix=f".{PKG}.", dir=out))
    f = Fields()
    m, p, sp = d(cfg.get("manufacturer")), d(cfg.get("product")), d(cfg.get("supplier"))
    ctx = {"product": " ".join(x for x in (s(p.get("name")), s(p.get("version"))) if x) or TBC, "supplier": s(m.get("name")) or TBC,
           "now": now, "artifact": artifact or {}, "absent_reason": absent_reason or {}}
    ctx["customer"] = f.get("supplier.customer.name", s(d(sp.get("customer")).get("name")))
    present = set()
    stats = {}
    try:
        for n in COPIED:
            if not (out / n).is_file():
                continue
            if n == "sbom.cdx.json":
                (tmp / n).write_text(json.dumps(customer_sbom(json.loads((out / n).read_text(encoding="utf-8"))), ensure_ascii=False,
                                                separators=(",", ":")) + "\n", encoding="utf-8")
            elif n.startswith("vex."):
                stats[n] = {}
                (tmp / n).write_text(json.dumps(customer_vex(n, json.loads((out / n).read_text(encoding="utf-8")), stats[n]), ensure_ascii=False,
                                                separators=(",", ":")) + "\n", encoding="utf-8")
            else:
                shutil.copyfile(out / n, tmp / n)
            present.add(n)
        cbom = json.loads((tmp / "sbom.cdx.json").read_text(encoding="utf-8")) if "sbom.cdx.json" in present else None
        texts = {"sbom.md": sbom_summary(summary, ctx, table, present, cbom),
                 "vulnerability-status.md": vulnerability_status(summary, vrows, ctx, table),
                 "risk-summary.md": risk_summary(cfg, sec, summary, vrows, f, ctx, table),
                 "security-testing-summary.md": security_testing(sec, ctx, table),
                 "integration-and-configuration.md": integration(cfg, sec, f, ctx),
                 "support-and-notification.md": support(cfg, f, ctx, table)}
        omitted = [n for n in OMITTABLE if TBC in texts[n]]     # 還有 TO BE COMPLETED 的不交（不讓半成品看起來像完成的文件）
        for n in omitted:
            del texts[n]
            ctx["absent_reason"][n] = NOT_PROVIDED
        texts["manufacturer-checklist.md"] = checklist(ctx, table, omitted)
        for n, t in texts.items():
            (tmp / n).write_text(t, encoding="utf-8")
        vulnerabilities_xlsx(tmp / XLSX, summary, vrows, ctx)
        present.update(texts)
        present.update((XLSX, "summary.json", "SHA256SUMS"))
        hashes = {n: sha((tmp / n).read_bytes()) for n in present if (tmp / n).is_file()}
        (tmp / "README.md").write_text(readme(cfg, f, ctx, table, present, hashes), encoding="utf-8")

        def status_of(n):
            if n.endswith(".md") and TBC in (tmp / n).read_text(encoding="utf-8"):
                return TBC
            return "OK"
        files = [{"file": n, "sha256": sha((tmp / n).read_bytes()), "status": status_of(n)} for n in FILES if (tmp / n).is_file()]
        vuln = vuln_status(summary, ctx)
        tests = tests_status(sec)
        lang = language_check(tmp)
        lang["generic_sentences"] = {n: x.get("generic", 0) for n, x in sorted(stats.items())}     # 換成一般句子的說明文字數（原文不適合給客戶）
        st = max(("GAP" if f.missing else "OK", vuln, tests, lang["status"]), key=lambda x: ORDER.get(x, 5))
        # status：公司欄位、漏洞資料、安全測試三者最差的；分開的鍵讓客戶的工具不會把「沒評估」讀成「沒問題」
        res = {"status": st, "company_fields": "TO BE COMPLETED" if f.missing else "OK", "vulnerability_data": vuln,
               "security_testing": tests, "role": "supplier", "folder": PKG, "files": files,
               "not_included": {n: present_reason(n, ctx) for n in COPIED + OMITTABLE if n not in present},
               "language_check": lang,
               "missing_fields": sorted(set(f.missing)),
               "notification_hours": "configured" if "supplier.notification.exploited_hours" not in f.missing else "not decided"}
        sf = check_customer_text("summary.json", json.dumps({k: v for k, v in res.items() if k != "language_check"}, ensure_ascii=False))
        if sf:                       # summary.json 自己也是客戶檔案，同樣的禁用字檢查
            lang["findings"] += sf
            lang["status"] = "GAP"
            res["status"] = max((res["status"], "GAP"), key=lambda x: ORDER.get(x, 5))
        (tmp / "summary.json").write_text(json.dumps({"generated": now, **res}, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        sums = [(n, sha((tmp / n).read_bytes())) for n in FILES if n != "SHA256SUMS" and (tmp / n).is_file()]
        (tmp / "SHA256SUMS").write_text("".join(f"{h}  {n}\n" for n, h in sums), encoding="utf-8")
        res["files"] = [{"file": n, "sha256": sha((tmp / n).read_bytes()), "status": status_of(n) if n.endswith(".md") else "OK"}
                        for n in FILES if (tmp / n).is_file()]
        old = None
        if pdir.exists():
            old = Path(tempfile.mkdtemp(prefix=f".{PKG}.old.", dir=out))
            os.replace(pdir, old / PKG)
        os.replace(tmp, pdir)
        if old:
            shutil.rmtree(old, ignore_errors=True)
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    return res


def language_check(d_):
    """客戶檔案不可有中文與本機路徑（VEX 另不可有內部屬性與工具名稱）。有的話狀態 GAP 並列出檔案，不默默放行。"""
    found = []
    for p_ in sorted(d_.iterdir()):
        if p_.is_file() and p_.name not in ("summary.json", "SHA256SUMS"):
            if p_.suffix == ".xlsx":          # 二進位檔：讀回每一格的文字再查
                try:
                    text = "\n".join(str(c) for rows in read_xlsx(p_).values() for r in rows for c in r)
                except Exception as e:
                    found.append(f"{p_.name}: unreadable ({type(e).__name__})")
                    continue
                found += check_customer_text(p_.name, text)
                continue
            found += check_customer_text(p_.name, p_.read_text(encoding="utf-8"))
    return {"status": "GAP" if found else "OK", "findings": found}


def remove(out):
    """role 不是 supplier 時刪掉上一次的資料包與留下的暫存資料夾（不留舊的冒充這次的結果）。"""
    out = Path(out)
    shutil.rmtree(out / PKG, ignore_errors=True)
    for x in out.glob(f".{PKG}.*"):
        shutil.rmtree(x, ignore_errors=True)
