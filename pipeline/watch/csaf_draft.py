"""每日監控的 CSAF 使用者通知草稿（CRA 第 14 條第 8 項；docs/CSAF.md 的 B、docs/WATCH.md 第 8 節）。

match.py 在 real 模式、**新的 KEV 命中群組**（第一次開 Issue 的群組，含併進彙總的）時呼叫 Drafts.for_group()：
- 只有 shipped 的正式版（kind release、status shipped）才產生。development 的 dev Release 還沒上市、也沒有報告 zip → NOT_RUN（寫原因）。
- 報告來源：collect.py 從同一個 Release 下載的報告 zip（report_package 的輸出），只讀 collect.REPORT_MEMBERS 列的 4 個固定成員，
  寫成固定檔名的 Reports 資料夾，再交給 tools/cra/csaf_advisory.py 的 exploited_run（草稿，tracking.status 一律 draft）。
- 發布者資料：repo 裡 projects/<專案>/CRA/Config/config.json（公開示範專案的設定；沒填的欄位是 TO BE COMPLETED，不放預設值）。
- 草稿放 <out>/csaf-drafts/NN-<8 碼 hash>/（workflow 以 artifact 上傳）；每份另寫 README.md 說明是草稿、示範專案時寫明不是出貨產品。
- 一次最多 MAX_DRAFTS 份，超過的記 NOT_RUN。任何錯誤只記在這份的狀態（FAIL），不影響監控本身。

報告 zip 是不可信資料：不解壓整包，只依固定成員名稱讀，邊讀邊算大小（超過上限就停），不跟隨連結、不用 zip 裡的路徑寫檔。
"""
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import zipfile
from pathlib import Path

import collect

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
CSAF_TOOL = os.path.join(ROOT, "tools", "cra", "csaf_advisory.py")
DRAFT_DIR = "csaf-drafts"
MAX_DRAFTS = 20
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}\Z")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}\Z")
PROJECT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}\Z")
STATUS_ZH = {"OK": "已產生", "ATTENTION": "已產生（還有要補的欄位）", "GAP": "沒有產生（GAP）", "NOT_RUN": "沒有產生（NOT_RUN）",
             "FAIL": "沒有產生（FAIL）"}


class ZipProblem(Exception):
    pass


def _tool():
    spec = importlib.util.spec_from_file_location("csaf_advisory", CSAF_TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def extract_reports(zpath, dest):
    """報告 zip → dest（Reports 資料夾：vulnerability-rows.json、vex.cdx.json，有的話 sbom.cdx.json、summary.json）。
    只讀固定成員；每個成員邊讀邊算，超過 collect.REPORT_MEMBER_MAX 就 ZipProblem。"""
    os.makedirs(dest)
    try:
        with zipfile.ZipFile(zpath) as z:
            infos = z.infolist()
            if len(infos) > collect.REPORT_MAX_MEMBERS:
                raise ZipProblem(f"報告 zip 的成員超過 {collect.REPORT_MAX_MEMBERS} 個")
            by = {}
            for i in infos:
                by.setdefault(i.filename, []).append(i)
            for out_name, member in collect.REPORT_MEMBERS.items():
                lst = by.get(member) or []
                if not lst:
                    if out_name in collect.REPORT_REQUIRED:
                        raise ZipProblem(f"報告 zip 沒有 {member}")
                    continue
                if len(lst) > 1:
                    raise ZipProblem(f"報告 zip 的 {member} 重複")
                info = lst[0]
                if stat.S_ISLNK(info.external_attr >> 16) or info.is_dir():
                    raise ZipProblem(f"報告 zip 的 {member} 不是一般檔案")
                n = 0
                with z.open(info) as src, open(os.path.join(dest, out_name), "xb") as dst:
                    while True:
                        b = src.read(1 << 20)
                        if not b:
                            break
                        n += len(b)
                        if n > collect.REPORT_MEMBER_MAX:
                            raise ZipProblem(f"報告 zip 的 {member} 解壓後超過大小上限")
                        dst.write(b)
    except (OSError, zipfile.BadZipFile, ValueError, RuntimeError, NotImplementedError, EOFError) as e:
        raise ZipProblem(f"報告 zip 讀不了（{type(e).__name__}）")


def load_config(project):
    """projects/<專案>/CRA/Config/config.json（公開示範專案的設定）；讀不到或格式不對 → {}（發布者欄位全部 TO BE COMPLETED）。"""
    if not (isinstance(project, str) and PROJECT_RE.match(project)):
        return {}
    p = os.path.join(ROOT, "projects", project, "CRA", "Config", "config.json")
    try:
        if os.path.islink(p):
            return {}
        with open(p, encoding="utf-8") as f:
            cfg = json.load(f)
        return cfg if isinstance(cfg, dict) else {}
    except (OSError, ValueError):
        return {}


def readme(rec, demo):
    lines = ["# CSAF 使用者通知草稿（CRA 第 14 條第 8 項）", "",
             "**這是草稿，工具不發布。** `csaf-exploited-draft.json` 的 `tracking.status` 是 `draft`；緩解措施、修補時程、發布者資料等要人補（見 `csaf-exploited-summary.json`）。"
             "要不要通知使用者、怎麼通知由負責人決定；向主管機關的通報是另一件事。", ""]
    if demo:
        lines += ["**示範專案（公開 BSP）**：dumpling 公開 repo 的示範專案，以公開 BSP／公開資料建置；Release 的 shipped 只是示範狀態，**不是真的出貨產品**。", ""]
    lines += [f"- 專案：{rec['project']}；版本：{rec['version']}；層：{rec['layer']}",
              f"- CVE：{', '.join(rec['cves'])}",
              f"- 報告來源：同一個 Release 的附件 {rec['report']}（sha256 {rec['report_sha256']}）",
              f"- 產生狀態：{rec['status']}", ""]
    return "\n".join(lines)


class Drafts:
    """一次執行的草稿產生器。records：每個新的 KEV 群組一筆（產生了或沒產生，都記原因）。"""

    def __init__(self, out_dir, now, demo=False, artifact=None, tool=None, text=None, code=None, cell=None):
        """text／code／cell：match.py 的 md_text／md_code／md_cell（寫進 Issue 與報告的外部字串一律經過它們）。"""
        self.out_dir, self.now, self.demo, self.artifact = out_dir, now, demo, artifact
        self.t = text or (lambda x, n=300: str(x)[:n])
        self.c = code or (lambda x: str(x))
        self.cell = cell or (lambda x: str(x))
        self.root = os.path.join(out_dir, DRAFT_DIR)
        shutil.rmtree(self.root, ignore_errors=True)      # 不留上一次的草稿
        self._tool = tool
        self.records = []
        self.made = 0

    def tool(self):
        if self._tool is None:
            self._tool = _tool()
        return self._tool

    def for_group(self, es, p):
        """es：同一個群組（同一份 SBOM × CVE）的比對；p：那份 SBOM 的 Release 資訊（可能是 None）。→ 這一筆的紀錄。"""
        e0 = es[0]
        cves = sorted({e.get("cve") for e in es if isinstance(e.get("cve"), str) and CVE_RE.match(e["cve"])})
        rec = {"project": str(e0.get("project") or "?"), "version": str(e0.get("version") or "?"), "layer": (p or {}).get("layer") or "?",
               "cves": cves, "status": "NOT_RUN", "detail": "", "dir": None}
        self.records.append(rec)
        try:
            self._make(rec, es, p)
        except Exception as e:      # 草稿是額外的：任何意外都只記在這一筆，不影響監控
            rec.update(status="FAIL", detail=f"內部錯誤（{type(e).__name__}）", dir=None)
        return rec

    def _make(self, rec, es, p):
        if not p:
            rec["detail"] = "找不到這份 SBOM 的 Release 資訊"
            return
        if p.get("kind") != "release" or p.get("status") != "shipped":
            rec["detail"] = ("development 的 dev Release：還沒上市，也沒有報告 zip，不需要第 14 條第 8 項的使用者通知" if p.get("kind") == "dev"
                             else f"這個 Release 的狀態是 {p.get('status')}（只有 shipped 的正式版才產生）")
            return
        if not rec["cves"]:
            rec["detail"] = "這個群組沒有 CVE 編號"
            return
        if not p.get("report_zip") or not os.path.isfile(p["report_zip"]):
            rec["detail"] = "這個 Release 沒有這一層的報告 zip（report-<專案>-<版本>[-<層>].zip），沒有可用的判定資料"
            return
        if self.made >= MAX_DRAFTS:
            rec["detail"] = f"這次已經產生 {MAX_DRAFTS} 份草稿（一次的上限），其餘下一次有新的命中時才會產生"
            return
        self.made += 1
        tag = hashlib.sha256((p["uuid"] + "|" + ",".join(rec["cves"])).encode()).hexdigest()[:8]
        rel = f"{DRAFT_DIR}/{self.made:02d}-{tag}"
        leaf = os.path.join(self.out_dir, rel)
        src = os.path.join(self.out_dir, DRAFT_DIR, f".src-{self.made:02d}-{tag}")
        try:
            try:
                extract_reports(p["report_zip"], src)
            except ZipProblem as e:
                rec.update(status="FAIL", detail=str(e))
                return
            h = hashlib.sha256()
            with open(p["report_zip"], "rb") as f:
                for b in iter(lambda: f.read(1 << 20), b""):
                    h.update(b)
            zsha = h.hexdigest()
            rec["report"], rec["report_sha256"] = os.path.basename(p["report_zip"]), zsha
            detected = {c: min(str(e.get("cve_first_detected") or e.get("first_detected") or "") for e in es if e.get("cve") == c) or None
                        for c in rec["cves"]}
            evidence = {}
            for c in rec["cves"]:
                ces = [e for e in es if e.get("cve") == c]
                srcs = sorted({str(x)[:200] for e in ces for x in (e.get("sources") or []) if isinstance(x, str)})
                dates = sorted(x for x in ((e.get("euvd") or {}).get("date_added") if isinstance(e.get("euvd"), dict) else None for e in ces)
                               if isinstance(x, str) and DATE_RE.match(x))
                evidence[c] = {"sources": srcs or ["dumpling daily monitoring (KEV match)"], "date": dates[0] if dates else None}
            ca = self.tool()
            st, detail, _ = ca.exploited_run(Path(src), rec["cves"], load_config(rec["project"]), Path(leaf), now=self.now,
                                             detected=detected, evidence=evidence)
            rec.update(status=st, detail=str(detail)[:300], dir=rel if st in ("OK", "ATTENTION") else None)
            if rec["dir"]:
                with open(os.path.join(leaf, "README.md"), "w", encoding="utf-8") as f:
                    f.write(readme(rec, self.demo))
            else:
                shutil.rmtree(leaf, ignore_errors=True)
        finally:
            shutil.rmtree(src, ignore_errors=True)

    def issue_line(self, rec):
        """新 Issue 內文的一句（只有 shipped 的正式版才寫；development 只記在報告與 result.json）。"""
        if rec is None or rec["detail"].startswith("development 的 dev Release"):
            return None
        where = f"這次執行的 artifact {self.c(self.artifact)}" if self.artifact else "這次執行的輸出資料夾"
        if rec["dir"]:
            return (f"CRA 第 14 條第 8 項的使用者通知草稿（CSAF，draft，未發布）{STATUS_ZH[rec['status']]}：{where} 的 {self.c(rec['dir'] + '/')}"
                    "（artifact 保留 90 天；草稿只是起點，要不要通知使用者由負責人決定）。")
        return f"CRA 第 14 條第 8 項的使用者通知草稿{STATUS_ZH.get(rec['status'], 'NOT_RUN')}：{self.t(rec['detail'])}。"

    def summary_line(self):
        """彙總 Issue 的一句（有 shipped 的正式版才寫）。"""
        recs = [r for r in self.records if not r["detail"].startswith("development 的 dev Release")]
        if not recs:
            return None
        made = [r for r in recs if r["dir"]]
        where = f"這次執行的 artifact {self.c(self.artifact)}" if self.artifact else "這次執行的輸出資料夾"
        return (f"CRA 第 14 條第 8 項的使用者通知草稿（CSAF，draft，未發布）：已產生 {len(made)} 份（{where}，保留 90 天）、"
                f"沒有產生 {len(recs) - len(made)} 份（原因見執行報告）。")

    def report_lines(self):
        if not self.records:
            return []
        L = ["", "## CSAF 使用者通知草稿（第 14 條第 8 項）", "",
             "新的 KEV 命中群組，每組一筆；只有 shipped 的正式版才產生。草稿的 `tracking.status` 一律是 `draft`，工具不發布。", "",
             "| 專案 | 版本 | 層 | CVE | 狀態 | 草稿 | 說明 |", "|---|---|---|---|---|---|---|"]
        for r in self.records:
            L.append(f"| {self.cell(r['project'])} | {self.cell(r['version'])} | {self.cell(r['layer'])} | {self.cell(', '.join(r['cves']) or '—')} | "
                     f"{r['status']} | {self.c(r['dir']) if r['dir'] else '—'} | {self.cell(r['detail'])} |")
        return L
