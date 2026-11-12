#!/usr/bin/env python3
"""runtime_evidence.py：板子上量到的「執行中有被使用」證據 → 弱點列的附加欄位（cra_report.py 用；只加欄位，不改分級也不改 VEX 狀態）。

輸入（都是 cra_report.generate() 已經讀好的東西）：
  - board-test.json 裡板子結果的 runs[].info.runtime（board_import.py 解析 board-on-device.sh 的 runtime-files.txt／runtime-modules.txt）；
  - pkgdb/dpkg-file-owners（pkg_why.py extract 從映像的 var/lib/dpkg/info/*.list 取出；每行「套件<TAB>路徑」）；
  - scan/kernel-config.json 的 results（每個 CVE 的修補檔案：built_as builtin／module、module 名稱）。

欄位（vulnerability-rows.json 的每一列）：
  attack_vector      N｜A｜L｜P｜unknown（最高分、有向量的 CVSS 來源的 AV；沒有向量 → unknown）
  runtime_observed   使用者空間的列：in use on the tested board｜not observed on the tested board｜not measured；核心的列 None
  runtime_evidence   一句證據（套件與路徑）或 not measured 的原因
  module_state       核心的列：built-in｜module, loaded on the tested board｜module, not loaded on the tested board｜
                     module, load state not measured｜unknown；使用者空間的列 None；kernel-config 判定不受影響的列 None

這是「這一塊板子、這一次量測時」的觀察：沒有出現不等於沒用到（沒量到的功能、閒置的服務、之後才載入的模組），不能用來降級或當作不受影響的理由。
沒有板子資料、沒有檔案擁有者清單、元件對不到套件 → not measured，不猜。
"""
import os
import re
import stat

CODE_RE = re.compile(r"^/usr/(?:s?bin|libexec)/|\.so(?:\.|$)")
NOT_CODE_RE = re.compile(r"-(?:dev|doc|common|data|dbg|dbgsym|locales|l10n)$")
AV_RE = re.compile(r"(?:^|[/(])AV:([NALP])(?:[/)]|$)")
OWNERS_NAME = "dpkg-file-owners"
MAX_OWNERS = 128 << 20
IN_USE = "in use on the tested board"
NOT_SEEN = "not observed on the tested board"
NOT_MEASURED = "not measured"
BUILT_IN = "built-in"
MOD_LOADED = "module, loaded on the tested board"
MOD_NOT_LOADED = "module, not loaded on the tested board"
MOD_UNMEASURED = "module, load state not measured"
UNKNOWN = "unknown"
DEB_RE = re.compile(r"^pkg:deb/[^/]+/([^@?#]+)")


def attack_vector(cvss_entries):
    """[(分數, 向量, 來源)]（分數高的在前）→ N｜A｜L｜P｜unknown。取最高分且有向量的那一個來源。"""
    for e in cvss_entries or []:
        m = AV_RE.search(e[1] or "")
        if m:
            return m.group(1)
    return UNKNOWN


def canon(path):
    """合併 /usr 之後路徑一樣的寫法：/bin、/sbin、/lib、/lib64 → /usr/…（dpkg 清單與 /proc 的寫法會不同）；去掉 ' (deleted)'。"""
    p = str(path).replace(" (deleted)", "")
    for d in ("/bin/", "/sbin/", "/lib/", "/lib64/"):
        if p.startswith(d):
            return "/usr" + p
    return p


def load_owners(pkgdb):
    """pkgdb 資料夾的 dpkg-file-owners → ({canon 路徑: {套件}}, None)；沒有或不能用 → (None, 原因)。不跟隨符號連結。"""
    if pkgdb is None:
        return None, "no pkgdb"
    p = os.path.join(str(pkgdb), OWNERS_NAME)
    try:
        st = os.lstat(p)
    except FileNotFoundError:
        return None, "the scanned image has no dpkg file lists (re-run the scan to extract them)"
    except OSError as e:
        return None, f"{OWNERS_NAME} unreadable ({type(e).__name__})"
    if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_OWNERS:
        return None, f"{OWNERS_NAME} is not a regular file or too large"
    try:
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as f:
            text = f.read(MAX_OWNERS + 1).decode("utf-8", "replace")
    except OSError as e:
        return None, f"{OWNERS_NAME} unreadable ({type(e).__name__})"
    if text.startswith("#partial"):
        return None, "the dpkg file lists were cut off at the size limit (partial), so files cannot be mapped reliably"
    owners = {}
    for line in text.splitlines():
        pkg, _, path = line.partition("\t")
        if pkg and path.startswith("/"):
            owners.setdefault(canon(path), set()).add(pkg)
    return (owners, None) if owners else (None, f"{OWNERS_NAME} is empty")


def pick_runtime(board_doc):
    """board-test.json → 最新一次、有 runtime 資料的板子結果 {files, modules, uptime, processes, captured, target, stem}；沒有 → None。"""
    best = None
    runs = board_doc.get("runs") if isinstance(board_doc, dict) else None
    for r in runs if isinstance(runs, list) else []:
        info = r.get("info") if isinstance(r, dict) else None
        rt = info.get("runtime") if isinstance(info, dict) else None
        if r.get("kind") != "board" or not r.get("current") or not isinstance(rt, dict):
            continue
        if not isinstance(rt.get("files"), list) and not isinstance(rt.get("modules"), list):
            continue
        key = str(r.get("time") or "")
        if best is None or key > best[0]:
            best = (key, dict(rt, target=r.get("target"), stem=r.get("stem"), when=r.get("time"),
                              l4t=(info.get("firmware") or {}).get("l4t") if isinstance(info.get("firmware"), dict) else None))
    return best[1] if best else None


class Evidence:
    """一次量測 + 檔案擁有者 + kernel-config → 每一列的欄位。"""

    def __init__(self, runtime, owners, owners_problem, pkgdb, kcfg, image_l4t=None):
        self.rt = runtime
        # 板子的 L4T 版本和被掃描的映像不同：板子上量到的東西不代表這個映像（任一邊不知道時不擋）
        bl = (runtime or {}).get("l4t")
        self.mismatch = (f"the tested board runs L4T {bl} but the scanned image has {image_l4t}" if bl and image_l4t and bl != image_l4t else None)
        self.owners, self.owners_problem = owners, owners_problem
        self.db = pkgdb
        self.files = {canon(p) for p in (runtime or {}).get("files") or []} if runtime and isinstance(runtime.get("files"), list) else None
        mods = (runtime or {}).get("modules")
        self.modules = {str(m).replace("-", "_") for m in mods} if isinstance(mods, list) else None
        self.files_problem = (runtime or {}).get("files_problem")
        self.used = {}                      # 套件 → [有被使用的路徑]
        self.ships_code = {}                # 套件 → 有執行檔或 .so（-dev、-doc 之類只有標頭、文件的不算）
        for path, pkgs in (owners or {}).items():
            if CODE_RE.search(path):
                for pkg in pkgs:
                    self.ships_code[pkg] = True
        if self.files is not None and owners:
            for p in sorted(self.files):
                for pkg in owners.get(p, ()):
                    self.used.setdefault(pkg, []).append(p)
        self.kres = {}
        if isinstance(kcfg, dict) and kcfg.get("schema") == "sca-center-kernel-config/1":
            for x in kcfg.get("results") or []:
                if isinstance(x, dict) and isinstance(x.get("cve"), str):
                    self.kres[x["cve"].upper()] = x

    def when(self):
        rt = self.rt or {}
        return str(rt.get("when") or rt.get("captured") or "")[:10] or "date not recorded"

    def scope(self):
        rt = self.rt or {}
        n = rt.get("processes")
        return f"one board, measured {self.when()}" + (f", {n} processes" if isinstance(n, int) else "")

    def bins(self, r):
        """列的元件 → (名稱相同的二進位套件, 同一個來源套件的其他二進位套件)。元件名稱同時是二進位與來源套件的名稱
        （例如 openssl）時，兩邊都看：只看命令列工具會漏掉 libssl 之類的函式庫。對不到 → ([], [])。"""
        names = []
        m = DEB_RE.match(str(r.get("purl") or ""))
        if m:
            names.append(m.group(1).lower())
        if r.get("component"):
            names.append(str(r["component"]).lower())
        exact = [n for n in dict.fromkeys(names) if n in self.db.pkgs]
        sib = set()
        for n in names:
            sib |= set(self.db.by_source.get(n) or ())
        sib -= set(exact)
        return exact, sorted(sib)

    def code_bins(self, pkgs):
        """只留有執行檔或 .so 的二進位套件（名稱是 -dev、-doc、-common、-data 等的不算；再看檔案清單裡實際有沒有執行檔或 .so）。"""
        return [p for p in pkgs if not NOT_CODE_RE.search(p) and self.ships_code.get(p)]

    def userland(self, r):
        """回傳 (狀態, 證據, 附加資訊 {via_source, binaries})。"""
        meta = {"via_source": None, "binaries": None}
        if self.rt is None or (self.files is None and not self.files_problem):
            return NOT_MEASURED, "no runtime data from a board (board-on-device.sh runtime-files.txt)", meta
        if self.files is None:
            return NOT_MEASURED, f"the board's file list cannot be used: {self.files_problem}", meta
        if self.mismatch:
            return NOT_MEASURED, self.mismatch, meta
        if self.owners is None:
            return NOT_MEASURED, self.owners_problem or "no dpkg file lists", meta
        if self.db is None:
            return NOT_MEASURED, "the scanned image has no dpkg-status, so the component cannot be mapped to a package", meta
        if not DEB_RE.match(str(r.get("purl") or "")):
            return NOT_MEASURED, "the component is not a dpkg package, so its files cannot be mapped", meta
        exact, sib = self.bins(r)
        if not exact and not sib:
            return NOT_MEASURED, "the component is not an installed dpkg package of the scanned image", meta
        # 同一個來源套件的二進位套件：只算有程式碼的；名稱相同的二進位套件自己一定算
        cand = list(dict.fromkeys(exact + self.code_bins(sib)))
        used = [p for p in cand if p in self.used]
        meta["binaries"] = f"{len(used)} of {len(cand)} binaries in use"
        if used:
            via = not any(p in exact for p in used)
            meta["via_source"] = via
            b = max(used, key=lambda p: (len(self.used[p]), p))
            paths = self.used[b]
            return IN_USE, (f"built from the same source package ({meta['binaries']}): " if via else "") + \
                f"{b}: {', '.join(paths[:2])}{', …' if len(paths) > 2 else ''}", meta
        meta["via_source"] = bool(len(cand) > 1 or (sib and not exact))
        return NOT_SEEN, f"no file of {', '.join(cand[:3])}{', …' if len(cand) > 3 else ''} was mapped or executing ({meta['binaries']})", meta

    def kernel(self, r):
        ids = [str(r.get("id") or "").upper()] + [str(c).upper() for c in r.get("cves") or []]
        res = next((self.kres[i] for i in ids if i in self.kres), None)
        if res is None:
            return UNKNOWN, "no kernel-config result for this CVE"
        if res.get("decision") == "not_affected":
            return None, "kernel-config: the fixed code is not built"
        if res.get("decision") != "affected":
            return UNKNOWN, "kernel-config could not decide whether the fixed code is built"
        code = [f for f in res.get("files") or [] if isinstance(f, dict) and f.get("built") is not False
                and f.get("built_as") in ("builtin", "module")]
        if any(f["built_as"] == "builtin" for f in code):
            return BUILT_IN, next(f["path"] for f in code if f["built_as"] == "builtin")
        if not code:
            return UNKNOWN, "no source file of the fix is mapped to the kernel image or a module (headers only or unmapped)"
        names = {str(f.get("module") or "").replace("-", "_") for f in code}
        if "" in names:
            return UNKNOWN, "a module file has no module name"
        if self.modules is None or self.mismatch:
            return MOD_UNMEASURED, ", ".join(sorted(names)[:3])
        loaded = sorted(names & self.modules)
        if loaded:
            return MOD_LOADED, ", ".join(loaded[:3])
        return MOD_NOT_LOADED, ", ".join(sorted(names)[:3]) + " (can be loaded on demand)"

    def fields(self, r, cvss_entries=None):
        """一列 → 要加的欄位。"""
        out = {"attack_vector": attack_vector(cvss_entries), "runtime_observed": None, "runtime_evidence": None, "module_state": None,
               "runtime_via_source": None, "runtime_binaries": None}
        if r.get("kernel") or r.get("is_kernel"):
            out["module_state"], out["runtime_evidence"] = self.kernel(r)
        else:
            out["runtime_observed"], out["runtime_evidence"], meta = self.userland(r)
            out["runtime_via_source"], out["runtime_binaries"] = meta["via_source"], meta["binaries"]
        return out

    def vex_note(self, f):
        """VEX 的 analysis.detail 後面接的短句；沒有量測 → ''（不寫「沒量到」）。來源套件的其他二進位套件被用到時要明說。"""
        ro, ms = f.get("runtime_observed"), f.get("module_state")
        via, k = f.get("runtime_via_source"), f.get("runtime_binaries")
        kk = f" ({k})" if k else ""
        if ro == IN_USE:
            if via:
                return (f"Runtime observation ({self.scope()}): a binary package built from the same source package was in use "
                        f"on the tested board{kk}; the affected code is not necessarily the part that was used.")
            return f"Runtime observation ({self.scope()}): component {IN_USE}."
        if ro == NOT_SEEN:
            return (f"Runtime observation ({self.scope()}): not observed in use on the tested board{kk}; "
                    f"this is not evidence that {'the binary packages built from this source package are' if via else 'the component is'} unused.")
        if ms == BUILT_IN:
            return "Kernel build: the affected code is built into the kernel image."
        if ms == MOD_LOADED:
            return f"Runtime observation ({self.scope()}): the kernel module is loaded."
        if ms == MOD_NOT_LOADED:
            return (f"Runtime observation ({self.scope()}): the kernel module is not loaded; it can be loaded on demand, "
                    "so this is not evidence that it is unused.")
        return ""


# ---------- 韌體版本比對（板子 vs 刷機包） ----------

def firmware_rows(board_doc, uefi_chk, l4t_pkg_version):
    """[(項目, 板子, 刷機包, 結果)]；沒有板子的韌體資料 → None。結果：same｜different｜not comparable。只比版本字串，不比映像內容。"""
    fw = None
    runs = board_doc.get("runs") if isinstance(board_doc, dict) else None
    best = ""
    for r in runs if isinstance(runs, list) else []:
        info = r.get("info") if isinstance(r, dict) else None
        if r.get("kind") == "board" and r.get("current") and isinstance(info, dict) and isinstance(info.get("firmware"), dict) \
                and str(r.get("time") or "") >= best:
            fw, best = info["firmware"], str(r.get("time") or "")
    if fw is None:
        return None
    rows = []
    bv = fw.get("bios_version")
    found, n_img, n_hit = set(), 0, 0
    for im in (uefi_chk or {}).get("images") or [] if isinstance(uefi_chk, dict) else []:
        n_img += 1
        vs = {v.get("found") for v in im.get("version_found") or [] if isinstance(v, dict) and v.get("found")}
        if vs:
            n_hit += 1
        found |= vs
    if bv is None:
        rows.append(("UEFI version (DMI bios_version)", "NOT_RUN", ", ".join(sorted(found)) or "not available", "not comparable"))
    elif not found:
        rows.append(("UEFI version (DMI bios_version)", bv, "no version string found in the flash package UEFI images", "not comparable"))
    else:
        rows.append(("UEFI version (DMI bios_version)", bv, f"{', '.join(sorted(found))} (in {n_hit} of {n_img} UEFI images)",
                     "same" if bv in found else "different"))
    l4t = fw.get("l4t")
    pk = re.match(r"^(\d{2,3})\.(\d{1,3}(?:\.\d{1,3})?)", str(l4t_pkg_version or ""))
    flash_l4t = f"R{pk.group(1)}.{pk.group(2)}" if pk else None
    if l4t is None:
        rows.append(("L4T release (/etc/nv_tegra_release)", "NOT_RUN", flash_l4t or "not available", "not comparable"))
    elif flash_l4t is None:
        rows.append(("L4T release (/etc/nv_tegra_release)", l4t, "no nvidia-l4t-core package in the scanned image", "not comparable"))
    else:
        rows.append(("L4T release (/etc/nv_tegra_release)", l4t, f"{flash_l4t} (nvidia-l4t-core {l4t_pkg_version})",
                     "same" if l4t == flash_l4t else "different"))
    for label, key in (("OP-TEE", "optee"), ("BPMP firmware", "bpmp")):
        rows.append((label + " (dmesg)", fw.get(key) or "NOT_RUN", "not compared (no version string of this component in the flash package inventory)", "not comparable"))
    for label, key in (("Secure Boot (efivars)", "secure_boot"), ("Setup Mode (efivars)", "setup_mode")):
        v = fw.get(key)
        rows.append((label, "NOT_RUN" if v is None else str(v), "not applicable", "reported"))
    if fw.get("nvbootctrl_slots"):
        rows.append(("Boot slots (nvbootctrl)", "; ".join(fw["nvbootctrl_slots"][:6]), "not applicable", "reported"))
    return rows


def firmware_text(rows, table):
    if rows is None:
        return ""
    head = ("#### Firmware versions: tested board vs flash package\n\nVersion strings reported by one tested board compared with the "
            "version strings found in the flash package. A matching string means the labels agree; it is not a comparison of the images, "
            "and a different or missing string is not by itself a vulnerability.")
    return head + "\n\n" + table(["Item", "Tested board", "Flash package", "Result"], [list(r) for r in rows])
