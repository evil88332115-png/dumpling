#!/usr/bin/env python3
"""distro_recheck.py：Debian／Ubuntu 套件上「只經 NVD 等非發行版資料比對到」的 DT 發現，用發行版自己的 OSV 紀錄再判一次
（sca-scan 的 D-distro-recheck）。寫 scan/distro-recheck.json，並印一行 status：
  D-distro-recheck<TAB>狀態<TAB>說明

用法：python3 -I distro_recheck.py --findings <dt/findings.json[.xz]> [--grype <scan/grype.json[.xz]>] [--sbom <sbom.cdx.json[.xz]>]
                              [--deb-sources <dt/deb-sources.json>] [--kernel-map <scan/l4t-kernel-map.json>]
                              [--mirror <OSV 發行版鏡像>] [--max-age-days N] --out <scan/distro-recheck.json>
  --mirror：tools/mirror/osv-distro.sh 的輸出（<鏡像>/Ubuntu/all.zip、<鏡像>/Debian/all.zip、SOURCE）；sca-scan 從 PILOT_ENV 的
    OSV_DISTRO_MIRROR 讀。--max-age-days 預設 3（環境變數 OSV_DISTRO_MAX_AGE_DAYS；依 SOURCE 的 fetched_utc，與 osv-distro.sh --check 相同）。
退出碼：0 已判定（OK／GAP／NOT_RUN）；3 輸入錯誤（同時印 FAIL 那一行，不印 traceback）。原始的 findings、Grype、SBOM 檔案一律不改。

為什麼（實例，Jetson R39.2.1 的 Ubuntu 24.04 rootfs）：DT 以 NVD 的 CPE（cpe:2.3:a:openssl:openssl）比對
deb 套件 openssl 3.0.13-0ubuntu3.11，回報 CVE-2024-6119（Ubuntu 在 3.0.13-0ubuntu3.4 修好）與 CVE-2026-45447（3.0.13-0ubuntu3.11 修好）。
NVD 只看上游版本 3.0.13，不知道 Ubuntu 把修補 backport 到 -0ubuntu3.x，所以 CRA 風險評估把它們列成 P1；Grype 用 Ubuntu 的資料比對，
沒有回報（報告寫 "Fix (Grype): unknown (not matched by Grype)"）。發行版套件上只有 NVD（或 GitHub、非發行版的 OSV）的列，是 P1／P2 誤報的主要來源。

判定（每一列＝cra_report.py 的一列：CVE（沒有 CVE 時最小的 ID）＋元件名稱＋版本，分組規則相同，cra_report 才能一對一對回去）：
  候選：元件是 pkg:deb/ubuntu 或 pkg:deb/debian，而且這一列至少有一筆來自非發行版資料的 finding
    （DT 的 source 是 NVD、GITHUB，或 OSV 但編號不是 UBUNTU-／DEBIAN-／USN-／DSA-／DLA-／DTSA-／LSN- 開頭）。
  依序略過（照常留在清單裡，只計數）：
    skipped_distro_source：同一列也有發行版紀錄的 finding（DT 已用發行版資料比對到，這一列本來就是發行版的判斷）；
    skipped_kernel：作業系統核心（C-kernel-l4t-map 加上的 linux-nvidia-tegra 等、kernelcheck.py 的核心套件、原始碼是 linux 或
      linux-*；含 linux-libc-dev）：核心由 Grype 與 8.7 節處理，不在這裡判；
    skipped_grype_matched：Grype 對同一個套件（二進位名稱、原始碼名稱，或從原始碼安裝的二進位套件）比對到同一個 CVE（含
      relatedVulnerabilities 與別名）：Grype 已經用發行版資料判過，照它的結果；
    skipped_release_unknown：purl 沒有 distro qualifier 或認不得（例如 debian-unstable），不知道該看哪個版本的紀錄。
  其他的查鏡像：同一個 CVE 的 UBUNTU-CVE-<CVE>／DEBIAN-CVE-<CVE>（每個 CVE 一筆）；只有在沒有這筆紀錄時才看 upstream 或 aliases
  列出這個 CVE 的 USN／DSA／DLA／DTSA 公告（related 不算：213 個 USN 只在 related 列 CVE，多半是 regression 公告）。
  為什麼公告不能單獨判「已修補」：公告的 CVE 清單涵蓋整份公告，不是每個發行版本、每個套件都修了每個 CVE。實例（2026-11-02 的資料）：
  noble 的 curl 8.5.0-2ubuntu10.15，USN-8820-1 列了 CVE-2026-80229 與 Ubuntu:24.04:LTS 的 curl 修補版本 8.5.0-2ubuntu10.15，
  但 UBUNTU-CVE-2026-80229 只列 26.04 與 26.10。所以有每個 CVE 一筆的紀錄時只看它（公告只記在 advisory_evidence）；
  它沒列這個發行版本的這個套件 → distro_not_listed（例如 CVE-2025-9086：UBUNTU-CVE 只列 25.10，USN-8062-1 有 noble 的修補，
  仍是 distro_not_listed，照常保留）。沒有每個 CVE 一筆的紀錄、只有公告說已修補 → distro_fixed_advisory_only（照常保留，CRA 報告只註記）。
  只看「同一個發行版本」（distro qualifier ubuntu-24.04／noble ↔ 生態系 Ubuntu:24.04:LTS；
  debian-12／bookworm ↔ Debian:12；Ubuntu Pro、FIPS、Realtime 等生態系不算）裡「原始碼套件」名稱相同的 affected 項目。
  原始碼名稱與版本：purl 的 upstream qualifier（Syft 從 dpkg 的 Source 欄位填，<名稱> 或 <名稱>@<版本>）→ SBOM 同一個元件的
  syft:metadata:source → dt/deb-sources.json（arch=source 的原始碼元件本身就是原始碼名稱）→ 二進位名稱本身。版本以 dpkg 規則比較
  （cra_report.py 的 deb_vercmp；例如 3.0.13-0ubuntu3.11 > 3.0.13-0ubuntu3.4）。範圍依 OSV 的 ECOSYSTEM 規則（introduced／fixed／
  last_affected），另外 versions 清單裡有安裝的版本也算受影響。撤回（withdrawn）的紀錄不用。
    distro_fixed：（每個 CVE 一筆的紀錄裡）每一個符合的項目都判定安裝的版本不受影響，而且至少一個項目的修補版本 ≤ 安裝版本（backport 已含修補）；
    distro_affected：任何一個項目判定安裝的版本受影響（比修補版本舊，或沒有修補版本）：真的發現，照常保留並記下證據；
    distro_not_listed：有這個 CVE 的發行版紀錄，但沒有列這個發行版本的這個原始碼套件（或安裝的版本不在任何範圍、也沒有
      不高於它的修補版本）：未知，照常保留；
    no_distro_record：這個發行版沒有這個 CVE 的紀錄（或這一列沒有 CVE 編號）：照常保留。
    distro_fixed_advisory_only：沒有每個 CVE 一筆的紀錄，只有公告說已修補：照常保留。
  一列有多個 CVE 時每個都判，取最保守的（affected > not_listed > advisory_only > no_record > fixed）：全部是 fixed 才算 distro_fixed。
狀態：沒有候選（或只有核心）→ NOT_RUN（sca-scan 不寫這一列）；有要查鏡像的列但沒有鏡像、讀不到、sha256 不符或過期 → GAP
  （沒有判定，所有列照常保留；cra_report 只採用 status OK 的結果）；其他 → OK（只表示判定完成，不代表清單完整）。
"""
import argparse
import datetime
import functools
import hashlib
import importlib.util
import json
import lzma
import os
import re
import stat
import sys
import zipfile
from pathlib import Path

STAGE = "D-distro-recheck"
SCHEMA = "sca-distro-recheck/1"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
DISTRO_PREFIXES = ("UBUNTU-", "DEBIAN-", "USN-", "DSA-", "DLA-", "DTSA-", "LSN-")
# 發行版本 ↔ 代號（OSV 紀錄的 purl distro qualifier 與生態系實測 2026-11-02；舊版只在需要時才會用到）
UBUNTU = {"14.04": "trusty", "16.04": "xenial", "18.04": "bionic", "20.04": "focal", "22.04": "jammy", "23.04": "lunar",
          "23.10": "mantic", "24.04": "noble", "24.10": "oracular", "25.04": "plucky", "25.10": "questing", "26.04": "resolute",
          "26.10": "stonking"}
DEBIAN = {"7": "wheezy", "8": "jessie", "9": "stretch", "10": "buster", "11": "bullseye", "12": "bookworm", "13": "trixie",
          "14": "forky", "15": "duke"}
ZIP_DIR = {"ubuntu": "Ubuntu", "debian": "Debian"}
PER_CVE = {"Ubuntu": "UBUNTU-", "Debian": "DEBIAN-"}
ADVISORY_PREFIXES = {"Ubuntu": ("USN-",), "Debian": ("DSA-", "DLA-", "DTSA-")}   # LSN（核心 livepatch）只有 Pro 生態系，不用
MAX_RECORD = 64 << 20          # 單筆紀錄解壓後的上限（估計：一般最大約數 MB）
CVE_IN = re.compile(r"^(?:UBUNTU-|DEBIAN-)?(CVE-\d{4}-\d{4,})$")
DECISIONS = ("distro_fixed", "distro_affected", "distro_not_listed", "distro_fixed_advisory_only", "no_distro_record")
SKIPS = ("skipped_distro_source", "skipped_kernel", "skipped_grype_matched", "skipped_release_unknown")
CONSERVATIVE = ("distro_affected", "distro_not_listed", "distro_fixed_advisory_only", "no_distro_record", "distro_fixed")   # 多個 CVE 時取最前面的


class InputError(Exception):
    pass


def line(st, detail):
    print(f"{STAGE}\t{st}\t" + re.sub(r"[\t\r\n]+", " ", str(detail))[:900])


def _load(name, path):
    """python3 -I 不把這個資料夾放進 sys.path，所以依路徑載入同一份規則（不複製程式）。"""
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m
    except Exception as e:
        raise InputError(f"無法載入 {path}（{type(e).__name__}）")


@functools.lru_cache(maxsize=None)
def libs():
    """(cra_report：deb_vercmp、ids_of、cves_of、purl_fullname；deb_sources：parse、source_of、is_kernel；kernelcheck：核心套件名稱)。"""
    return (_load("sca_center_cra_report", ROOT / "tools" / "cra" / "cra_report.py"),
            _load("sca_center_deb_sources", HERE / "deb_sources.py"),
            _load("sca_center_kernelcheck", HERE / "kernelcheck.py"))


def vercmp(a, b):
    return libs()[0].deb_vercmp(a, b)


def load(path, label):
    if not path:
        return None
    try:
        with (lzma.open(path, "rt", encoding="utf-8") if str(path).endswith(".xz") else open(path, encoding="utf-8")) as f:
            return json.load(f)
    except (OSError, ValueError, lzma.LZMAError) as e:
        raise InputError(f"{label} 無法讀取（{path}：{type(e).__name__}）")


# ---------- 發行版本 ----------

def release_of(ns, distro):
    """purl 的 namespace（ubuntu／debian）與 distro qualifier → {distro, version, codename, ecosystems}；認不得回 None。
    接受 ubuntu-24.04、ubuntu-noble、noble、24.04；debian-12、debian-12.5、debian-bookworm、bookworm、12。"""
    ns, d = (ns or "").lower(), (distro or "").strip().lower()
    if ns not in ZIP_DIR or not d:
        return None
    table = UBUNTU if ns == "ubuntu" else DEBIAN
    if d.startswith(ns + "-"):
        d = d[len(ns) + 1:]
    by_name = {v: k for k, v in table.items()}
    if d in by_name:
        ver = by_name[d]
    elif ns == "debian" and re.fullmatch(r"\d+(\.\d+)*", d) and d.split(".")[0] in table:
        ver = d.split(".")[0]
    elif d in table:
        ver = d
    else:
        return None
    if ns == "ubuntu":
        ecos = [f"Ubuntu:{ver}:LTS", f"Ubuntu:{ver}"]
    else:
        ecos = [f"Debian:{ver}"]
    return {"distro": ZIP_DIR[ns], "version": ver, "codename": table[ver], "ecosystems": ecos}


# ---------- OSV 範圍 ----------

def _evcmp(a, b):
    """事件排序：introduced "0" 最小，其他依 dpkg 版本順序。"""
    za, zb = a == ("introduced", "0"), b == ("introduced", "0")
    if za or zb:
        return 0 if za and zb else (-1 if za else 1)
    return vercmp(a[1], b[1])


def evaluate(entry, ver):
    """一個 affected 項目對安裝版本 ver 的判定：{affected, fixed（全部修補版本）, fixed_passed（不高於 ver 的最高修補版本）, no_fix, evaluable}。"""
    fixed, passed, affected, evaluable, no_fix = [], None, False, False, False
    for r in entry.get("ranges") or []:
        if not isinstance(r, dict) or r.get("type") != "ECOSYSTEM":
            continue
        evs = [(k, str(v)) for e in r.get("events") or [] if isinstance(e, dict)
               for k, v in e.items() if k in ("introduced", "fixed", "last_affected") and isinstance(v, (str, int))]
        if not evs:
            continue
        evaluable = True
        evs.sort(key=functools.cmp_to_key(_evcmp))
        vul = False
        for k, v in evs:            # OSV 規格的評估方式：依版本排序後逐一套用不高於安裝版本的事件
            if k == "introduced" and (v == "0" or vercmp(ver, v) >= 0):
                vul = True
            elif k == "fixed" and vercmp(ver, v) >= 0:
                vul = False
            elif k == "last_affected" and vercmp(ver, v) > 0:
                vul = False
        fs = [v for k, v in evs if k == "fixed"]
        fixed += fs
        below = [v for v in fs if vercmp(v, ver) <= 0]
        if below:
            best = max(below, key=functools.cmp_to_key(vercmp))
            passed = best if passed is None or vercmp(best, passed) > 0 else passed
        if vul:
            affected = True
            no_fix = no_fix or not any(vercmp(v, ver) > 0 for v in fs)
    vs = [str(v) for v in entry.get("versions") or [] if isinstance(v, (str, int))]
    if vs:
        evaluable = True
        if any(v == ver or vercmp(v, ver) == 0 for v in vs):
            affected = True
    if not evaluable:          # 列了套件卻沒有可判斷的範圍：保守當作受影響
        affected = no_fix = True
    return {"affected": affected, "fixed": sorted(set(fixed), key=functools.cmp_to_key(vercmp)), "fixed_passed": passed,
            "no_fix": affected and no_fix, "evaluable": evaluable}


# 發行版自己的修訂號寫法（deb12u1、bpo12、ubuntu0.24.04.1、build1、esm1、+b1 的 binNMU…）；去掉以後修訂號裡還有字母 → 廠商或第三方重建
# （同 tools/cra/no_vuln_data.py 的 DISTRO_REV_TOKENS）
DISTRO_REV_TOKENS = re.compile(r"deb\d+u\d+|deb\d+|bpo\d+|ubuntu|build|nmu|esm|fips|exp|cross|fakesync|\+b(?=\d)|really|dfsg|ds")
# 不論寫在版本的哪個位置，出現就是廠商／第三方建置的明確標記（Rockchip、NVIDIA L4T／Tegra、PPA）
VENDOR_TOKENS = re.compile(r"(?<![a-z])(rk\d*|rockchip|l4t|tegra|nvidia|ppa\d*)(?![a-z])")


def is_vendor_build(ver):
    """安裝的版本看起來不是發行版建置的（廠商或第三方重建，例如 2.4.114-1+rk1、1.0-1~ppa1、6.1-rockchip）：
    發行版的修補版本（2.4.114-1+deb12u1）比它小，但那個修補不一定在這份重建裡，所以不能只靠版本比較判為已修補。
    啟發式：上游版本只找明確的廠商標記（VENDOR_TOKENS；上游版本的 +gitXXX、+dfsg、~r495 等是正常寫法，不看）；
    Debian 修訂號（最後一個 - 之後）去掉發行版的寫法（DISTRO_REV_TOKENS）以後還有字母 → 重建（例如 1+custom1、1local2）。
    沒有任何標記的第三方重建（例如 +deb12u1.1）偵測不到。"""
    v = str(ver or "").lower()
    if VENDOR_TOKENS.search(v):
        return True
    rest = v.split(":", 1)[1] if re.match(r"^\d+:", v) else v
    if "-" in rest:
        rev = rest.rsplit("-", 1)[1]
        if re.search(r"[a-z]", DISTRO_REV_TOKENS.sub("", rev)):
            return True
    return False


def decide(entries, ver):
    """entries：[(紀錄摘要, affected 項目)]（已篩選到同一發行版本、同一原始碼套件）→ (判定, 證據清單, 說明)。"""
    ev = []
    for rec, a in entries:
        r = evaluate(a, ver)
        ev.append({**rec, "ecosystem": (a.get("package") or {}).get("ecosystem"), "package": (a.get("package") or {}).get("name"),
                   "installed_version": ver, "fixed_versions": r["fixed"], "fixed_version": r["fixed_passed"],
                   "affected": r["affected"], "no_fix": r["no_fix"]})
    if not ev:
        return None, ev, ""
    if any(e["affected"] for e in ev):
        nf = [e for e in ev if e["affected"] and e["no_fix"]]
        return "distro_affected", ev, ("發行版紀錄判定安裝的版本受影響" + ("（沒有修補版本）" if nf else
                                       f"（修補版本 {', '.join(sorted({f for e in ev for f in e['fixed_versions'] if vercmp(f, ver) > 0}))}）"))
    if all(e["fixed_version"] for e in ev):
        if is_vendor_build(ver):
            return "distro_not_listed", ev, (f"安裝的 {ver} 不是發行版建置的（版本有廠商或第三方的後綴），雖然 ≥ 發行版的修補版本 "
                                             f"{', '.join(sorted({e['fixed_version'] for e in ev}))}，不能判為已修補（發行版的修補不一定在這份重建裡）：照常保留")
        return "distro_fixed", ev, f"安裝的 {ver} ≥ 發行版的修補版本 {', '.join(sorted({e['fixed_version'] for e in ev}))}（backport）"
    return "distro_not_listed", ev, "有列這個套件，但安裝的版本不在任何範圍內，也沒有不高於它的修補版本"


# ---------- 鏡像 ----------

def _sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


class Mirror:
    """OSV 發行版鏡像（osv-distro.sh 的輸出）。只讀需要的紀錄；不解壓整個 zip。"""

    def __init__(self, path, needed, max_age):
        self.path, self.zips, self._adv = path, {}, {}
        self.state = {"path": path, "ok": False, "reason": None, "fetched_utc": None, "age_days": None, "max_age_days": max_age,
                      "ecosystems": {}}
        self.state["reason"] = self._open(needed, max_age)
        self.state["ok"] = self.state["reason"] is None

    def _open(self, needed, max_age):
        if not self.path:
            return "沒有設定鏡像（PILOT_ENV 的 OSV_DISTRO_MIRROR）"
        if not os.path.isdir(self.path):
            return f"鏡像資料夾不存在：{self.path}"
        sp = os.path.join(self.path, "SOURCE")
        try:
            if not stat.S_ISREG(os.lstat(sp).st_mode):      # FIFO 會讓讀取卡住、連結可能指到別處
                return "SOURCE 不是一般檔案"
            src = dict(l.split("=", 1) for l in open(sp, encoding="utf-8").read().splitlines() if "=" in l)
        except OSError:
            return "缺少 SOURCE（無法判斷新舊）"
        self.state["fetched_utc"] = src.get("fetched_utc")
        try:
            t = datetime.datetime.fromisoformat(str(src.get("fetched_utc")).replace("Z", "+00:00"))
        except ValueError:
            return "SOURCE 沒有可解析的 fetched_utc"
        age = (datetime.datetime.now(datetime.timezone.utc) - t).total_seconds() / 86400
        self.state["age_days"] = round(age, 1)
        if age > max_age:
            return f"鏡像過期：下載後 {age:.1f} 天 > {max_age:g} 天（fetched_utc={src.get('fetched_utc')}）"
        for e in sorted(needed):
            lc = e.lower()
            if e not in src.get("ecosystems", "").split():
                return f"鏡像沒有 {e}（SOURCE 的 ecosystems={src.get('ecosystems')!r}）"
            zp = os.path.join(self.path, e, "all.zip")
            try:
                if not stat.S_ISREG(os.lstat(zp).st_mode):
                    return f"{e}/all.zip 不是一般檔案"
                if _sha256(zp) != src.get(f"{lc}_sha256"):
                    return f"{e}/all.zip 的 sha256 與 SOURCE 不符（下載不完整或被換掉）"
                self.zips[e] = zipfile.ZipFile(zp)
            except (OSError, zipfile.BadZipFile) as ex:
                return f"{e}/all.zip 無法讀取（{type(ex).__name__}）"
            self.state["ecosystems"][e] = {"sha256": src.get(f"{lc}_sha256"), "bytes": src.get(f"{lc}_bytes"),
                                           "upstream_last_modified": src.get(f"{lc}_last_modified")}
        return None

    def _read(self, eco, name):
        z = self.zips[eco]
        try:
            i = z.getinfo(name)
        except KeyError:
            return None
        if i.file_size > MAX_RECORD:
            return None
        try:
            d = json.loads(z.read(i))
        except (ValueError, zipfile.BadZipFile, OSError):
            return None
        return d if isinstance(d, dict) else None

    def advisories(self, eco):
        """{CVE: [公告檔名]}：upstream、aliases 列出的 CVE（含 UBUNTU-CVE-／DEBIAN-CVE- 形式；related 不算）。第一次用到時建一次。"""
        if eco not in self._adv:
            idx = {}
            for i in self.zips[eco].infolist():
                n = i.filename
                if "/" in n or not n.endswith(".json") or not n.startswith(ADVISORY_PREFIXES[eco]):
                    continue
                d = self._read(eco, n)
                if not d or d.get("withdrawn"):
                    continue
                for x in (d.get("upstream") or []) + (d.get("aliases") or []):
                    m = CVE_IN.match(str(x))
                    if m:
                        idx.setdefault(m.group(1), set()).add(n)
            self._adv[eco] = idx
        return self._adv[eco]

    def records(self, eco, cve):
        """(每個 CVE 一筆的紀錄或 None, [公告])；撤回的不算。"""
        pc = self._read(eco, f"{PER_CVE[eco]}{cve}.json")
        advs = [d for n in sorted(self.advisories(eco).get(cve, ())) for d in [self._read(eco, n)] if d and not d.get("withdrawn")]
        return (pc if pc and not pc.get("withdrawn") else None), advs


# ---------- DT 的列 ----------

def is_distro_finding(v):
    """DT 的 finding 是否來自發行版資料（OSV 的 UBUNTU-／DEBIAN-／USN-／DSA-／DLA-／DTSA-／LSN-）。"""
    return str(v.get("source") or "").upper() == "OSV" and str(v.get("vulnId") or "").upper().startswith(DISTRO_PREFIXES)


def sbom_sources(bom):
    """SBOM 的 deb 元件 → {完整 purl: (原始碼名稱, 原始碼版本)}，也以 (namespace, 名稱, 版本) 建索引。purl 沒有 upstream qualifier 時
    用 Syft 的 syft:metadata:source／syft:metadata:sourceVersion 屬性。"""
    cra, ds, _ = libs()
    out = {}
    for c in ds.components((bom or {}).get("components")):
        p = ds.parse(c.get("purl"))
        if not p:
            continue
        ns, name, ver, q = p
        src, sver = ds.source_of(name, ver, q)
        if not q.get("upstream"):
            prop = {x.get("name"): x.get("value") for x in c.get("properties") or [] if isinstance(x, dict)}
            src = prop.get("syft:metadata:source") or name
            sver = prop.get("syft:metadata:sourceVersion") or ver
        out[c.get("purl")] = out[(ns, name, ver)] = (src, sver)
    return out


def deb_source_bins(dsj):
    """dt/deb-sources.json → {原始碼 purl（不含 qualifiers）: [二進位套件名稱]}（added 與 shared_sources）。"""
    _, ds, _ = libs()
    out = {}
    for x in ((dsj or {}).get("added") or []) + ((dsj or {}).get("shared_sources") or []):
        if not isinstance(x, dict) or not isinstance(x.get("purl"), str):
            continue
        bins = [ds.parse(b)[1] for b in x.get("binary_purls") or [] if ds.parse(b)]
        out.setdefault(x["purl"].split("?", 1)[0], set()).update(bins)
    return out


def grype_index(grype):
    """{(編號, 套件名稱小寫)}：每筆 Grype 比對的主編號、relatedVulnerabilities 與其中的 CVE，配上 artifact 名稱與原始碼名稱
    （artifact.upstreams、purl 的 upstream qualifier）。不看版本：同名套件被 Grype 判過就照 Grype（保守）。"""
    cra, ds, _ = libs()
    idx = set()
    for m in (grype or {}).get("matches") or []:
        if not isinstance(m, dict):
            continue
        v, a = m.get("vulnerability") or {}, m.get("artifact") or {}
        ids = {v.get("id")} | {r.get("id") for r in m.get("relatedVulnerabilities") or [] if isinstance(r, dict)}
        ids = {i for i in ids if isinstance(i, str) and i}
        ids |= cra.cves_of(ids)
        names = {str(a.get("name") or "")} | {str(u.get("name") or "") for u in a.get("upstreams") or [] if isinstance(u, dict)}
        p = ds.parse(a.get("purl"))
        if p:
            names.add(ds.source_of(p[1], p[2], p[3])[0])
        for i in ids:
            for n in names - {""}:
                idx.add((i, n.lower()))
    return idx


def kernel_purls(kmap):
    c = ((kmap or {}).get("map_entry") or {}).get("component") if isinstance(kmap, dict) else None
    return {c["purl"].split("?", 1)[0]} if isinstance(c, dict) and isinstance(c.get("purl"), str) else set()


def groups_of(findings):
    """同 cra_report.build_rows 的分組：(CVE 或最小 ID, purl 的完整名稱或元件名稱小寫, 版本) → [finding]。
    cra_report 另把沒有 CVE 的 USN 併進 CVE 的列（scan/usn-cves.json）：這裡不併，那一列多了這裡沒看過的 finding，cra_report 不會移它。"""
    cra = libs()[0]
    g = {}
    for f in findings:
        if not isinstance(f, dict):
            continue
        c, v = f.get("component") or {}, f.get("vulnerability") or {}
        ids = cra.ids_of(v) or {"?"}
        cves = sorted(cra.cves_of(ids))
        key = (cves[0] if cves else min(ids), cra.purl_fullname(c.get("purl")) or (c.get("name") or "?").lower(), c.get("version") or "")
        g.setdefault(key, []).append(f)
    return g


def recheck(findings, grype, bom, dsj, kmap, mirror_path, max_age):
    """回傳 (狀態, 說明, 輸出 JSON)。"""
    cra, ds, kc = libs()
    if not isinstance(findings, list):
        raise InputError("DT findings 不是清單")
    if grype is not None and not isinstance(grype, dict):
        raise InputError("Grype JSON 不是物件")
    gidx = grype_index(grype) if grype is not None else None
    srcs, bins, kpurls = sbom_sources(bom), deb_source_bins(dsj), kernel_purls(kmap)
    rows, pending = [], []
    for (rid, lname, ver), fs in groups_of(findings).items():
        c = fs[0].get("component") or {}
        purl = c.get("purl") or ""
        p = ds.parse(purl)
        if not p or p[0].lower() not in ZIP_DIR:
            continue
        vs = [f.get("vulnerability") or {} for f in fs]
        if all(is_distro_finding(v) for v in vs):
            continue                                   # 發行版資料比對到的列：不是這裡要處理的
        ns, name, cver, q = p
        ids = set().union(*(cra.ids_of(v) for v in vs))
        cves = sorted(cra.cves_of(ids))
        if q.get("arch") == "source":
            src, sver = name, cver
        elif q.get("upstream"):
            src, sver = ds.source_of(name, cver, q)
        else:
            src, sver = srcs.get(purl) or srcs.get((ns, name, cver)) or (name, cver)
        installed_as = sorted(bins.get(purl.split("?", 1)[0], ()))
        rel = release_of(ns, q.get("distro"))
        row = {"key": [rid, lname, ver], "cves": cves, "ids": sorted(ids),
               "source_ids": sorted({f"{v.get('source') or '?'}:{v.get('vulnId') or '?'}" for v in vs}),
               "component": c.get("name") or name, "version": cver, "purl": purl, "source_package": src, "source_version": sver,
               "installed_as": installed_as, "release": rel and {k: rel[k] for k in ("distro", "version", "codename")},
               "kev": any(v.get("isKev") is True for v in vs), "decision": None, "reason": "", "evidence": []}
        rows.append(row)
        kernel = (purl.split("?", 1)[0] in kpurls or ds.is_kernel(name, src) or src == "linux" or kc.is_kernel_package_name(name)
                  or kc.is_kernel_cpe(c.get("cpe")) or any(kc.is_kernel_package_name(b) for b in installed_as))
        if any(is_distro_finding(v) for v in vs):
            row.update(decision="skipped_distro_source", reason="同一列也有發行版紀錄的 finding（DT 已用發行版資料比對到）")
        elif kernel:
            row.update(decision="skipped_kernel", reason="作業系統核心：由 Grype 與 CRA 風險評估 8.7 節處理")
        elif gidx is not None and any((i, n.lower()) in gidx for i in ids | set(cves) for n in {name, src, *installed_as}):
            row.update(decision="skipped_grype_matched", reason="Grype 對同一個套件比對到同一個弱點（已用發行版資料判過）")
        elif rel is None:
            row.update(decision="skipped_release_unknown", reason=f"認不得發行版本（distro qualifier {q.get('distro')!r}）")
        elif not cves:
            row.update(decision="no_distro_record", reason="這一列沒有 CVE 編號，發行版紀錄以 CVE 為鍵")
        else:
            pending.append((row, rel))
    if not any(r["decision"] != "skipped_kernel" for r in rows):
        nk = len(rows)
        return "NOT_RUN", ("沒有只經 NVD／GitHub 等非發行版資料比對到的 Debian／Ubuntu 發現" + (f"（核心 {nk} 列不在範圍內）" if nk else "")), None
    needed = {rel["distro"] for _, rel in pending}
    mir = Mirror(mirror_path, needed, max_age) if pending else None
    if mir is not None and not mir.state["ok"]:
        for row, _ in pending:
            row.update(decision="not_rechecked", reason=mir.state["reason"])
    else:
        for row, rel in pending:
            per = []
            adv_ev = []
            for cve in row["cves"]:
                pc, advs = mir.records(rel["distro"], cve)

                def match(recs, kind):
                    return [({"record": d.get("id"), "kind": kind, "modified": d.get("modified"), "published": d.get("published"),
                              "upstream": d.get("upstream") or d.get("aliases") or [], "cve": cve}, a)
                            for d in recs for a in d.get("affected") or [] if isinstance(a, dict)
                            and (a.get("package") or {}).get("ecosystem") in rel["ecosystems"]
                            and str((a.get("package") or {}).get("name") or "") == row["source_package"]]
                where = f"{rel['distro']} {rel['version']} 的 {row['source_package']}"
                aids = ", ".join(sorted(str(d.get("id")) for d in advs))
                if pc is not None:            # 每個 CVE 一筆的紀錄說了算；公告只記下來
                    dec, ev, why = decide(match([pc], "per_cve"), row["source_version"])
                    _, aev, _ = decide(match(advs, "advisory"), row["source_version"])
                    adv_ev += aev
                    if dec is None:
                        dec = "distro_not_listed"
                        why = (f"每個 CVE 一筆的紀錄 {pc.get('id')} 沒有列 {where}"
                               + (f"（公告 {', '.join(sorted({e['record'] for e in aev}))} 雖然列了，但公告的 CVE 清單涵蓋整份公告，"
                                  "不代表每個發行版本與套件都修了這個 CVE，不採用）" if aev else ""))
                elif advs:
                    dec, ev, why = decide(match(advs, "advisory"), row["source_version"])
                    if dec is None:
                        dec, why = "no_distro_record", f"沒有每個 CVE 一筆的紀錄；公告（{aids}）沒有列 {where}"
                    elif dec == "distro_fixed":
                        dec, why = "distro_fixed_advisory_only", why + "；只有公告、沒有每個 CVE 一筆的紀錄，照常保留"
                else:
                    dec, ev, why = "no_distro_record", [], f"{rel['distro']} 沒有 {cve} 的紀錄"
                per.append((cve, dec, ev, why))
            row["evidence"] = [e for _, _, ev, _ in per for e in ev]
            row["advisory_evidence"] = adv_ev
            row["per_cve"] = [{"cve": c, "decision": d, "reason": w} for c, d, _, w in per]
            dec = min((d for _, d, _, _ in per), key=CONSERVATIVE.index)
            row.update(decision=dec, reason="；".join(f"{c}：{w}" for c, _, _, w in per))
    counts = {k: sum(1 for r in rows if r["decision"] == k) for k in DECISIONS + SKIPS + ("not_rechecked",)}
    counts["rows"] = len(rows)
    counts["distro_fixed_kev"] = sum(1 for r in rows if r["decision"] == "distro_fixed" and r["kev"])
    ok = mir is None or mir.state["ok"]
    st = "OK" if ok else "GAP"
    nl = len(pending)
    detail = (f"只經非發行版資料（NVD、GitHub…）比對到的 Debian／Ubuntu 發現 {len(rows)} 列："
              + (f"發行版已修補（backport）{counts['distro_fixed']}、仍受影響 {counts['distro_affected']}、"
                 f"紀錄沒列這個版本或套件 {counts['distro_not_listed']}、只有公告說已修補 {counts['distro_fixed_advisory_only']}、"
                 f"沒有發行版紀錄 {counts['no_distro_record']}"
                 if ok else f"{nl} 列沒有再判（{mir.state['reason']}），照常保留在清單裡")
              + f"；略過：Grype 有比對 {counts['skipped_grype_matched']}、核心 {counts['skipped_kernel']}、"
                f"DT 已有發行版紀錄 {counts['skipped_distro_source']}、發行版本不明 {counts['skipped_release_unknown']}"
              + (f"；其中 KEV {counts['distro_fixed_kev']} 列判定已修補" if counts["distro_fixed_kev"] else "")
              + ("；沒有 Grype 結果，不依 Grype 略過" if gidx is None else "")
              + "（scan/distro-recheck.json；原始 findings 不變）")
    out = {"schema": SCHEMA, "stage": STAGE, "status": st, "detail": detail,
           "generated": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "mirror": mir.state if mir is not None else None, "grype": gidx is not None, "counts": counts,
           "rows": sorted(rows, key=lambda r: (DECISIONS + SKIPS + ("not_rechecked",)).index(r["decision"]) if r["decision"] in DECISIONS + SKIPS + ("not_rechecked",) else 99)}
    return st, detail, out


def main(argv=None):
    ap = argparse.ArgumentParser(description="Debian／Ubuntu 套件上只經 NVD 比對到的發現，以發行版的 OSV 紀錄再判（D-distro-recheck）")
    ap.add_argument("--findings", required=True)
    ap.add_argument("--grype")
    ap.add_argument("--sbom")
    ap.add_argument("--deb-sources")
    ap.add_argument("--kernel-map")
    ap.add_argument("--mirror")
    ap.add_argument("--max-age-days", type=float, default=None)
    ap.add_argument("--out", required=True)
    try:
        a = ap.parse_args(argv)
    except SystemExit:
        line("FAIL", "distro_recheck.py 參數錯誤")
        return 3
    try:
        max_age = a.max_age_days if a.max_age_days is not None else float(os.environ.get("OSV_DISTRO_MAX_AGE_DAYS") or 3)
        st, detail, out = recheck(load(a.findings, "DT findings"), load(a.grype, "Grype JSON"), load(a.sbom, "SBOM"),
                                  load(a.deb_sources, "deb-sources 摘要"), load(a.kernel_map, "核心對應摘要"), a.mirror, max_age)
    except InputError as e:
        line("FAIL", f"distro_recheck.py 輸入錯誤：{e}")
        return 3
    except Exception as e:      # 結構意外（例如欄位型別不對）：記 FAIL，不讓掃描中斷、不印 traceback
        line("FAIL", f"distro_recheck.py 無法判定（{type(e).__name__}）")
        return 3
    if out is not None:
        try:
            with open(a.out, "w", encoding="utf-8") as f:
                json.dump(out, f, ensure_ascii=False, indent=1)
        except OSError as e:
            line("FAIL", f"無法寫入 {a.out}（{type(e).__name__}）")
            return 3
    line(st, detail)
    return 0


if __name__ == "__main__":
    sys.exit(main())
