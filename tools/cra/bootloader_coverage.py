#!/usr/bin/env python3
"""刷機包的開機韌體涵蓋說明、UEFI 映像與原始碼的對照檢查、另外交付的韌體紀錄。三個子指令，都只讀、不執行任何東西。

用法（python3 -I）：
  uefi-check  --inventory <flash-inventory.json> (--archive <tbz2> | --dir <資料夾>) --tree <UEFI 原始碼樹>
              [--uefi-json <uefi-source.json>] [--platform-dsc <樹內的平台 DSC>]（可重複）[--platform-defines <Kconfig 的 config.dsc.inc／.config>]（可重複）--out <uefi-binary-check.json>
      刷機包 bootloader 清點裡的每個 uefi_*.bin：讀映像內容（串流，不解開到磁碟，單檔最多讀 MAX_BIN），
      (a) 在映像裡找原始碼樹的版本字串（UTF-16LE 與 ASCII）：廠商版本檔（檔名含 VERSION_INFO，兩行時接成「第一行-第二行」，
          第一行另列為基底）、images/buildid_*.txt、uefi-source.json 的字面版本字串（--uefi-json）；逐字記下在映像裡找到的內容；
      (b) 映像內嵌的除錯來源路徑（ASCII）：去掉到 edk2／edk2-nvidia／edk2-platforms…元件資料夾為止的前綴，看相對路徑在樹裡存不存在。
      每個映像一個結果：
        MATCH        版本字串完整相符（整個詞相同），而且路徑相符比例 >= PATH_RATIO（0.90）；映像裡沒有任何屬於元件資料夾的路徑時
                     只憑版本字串（path_evidence = none，詳見 detail）；
        MISMATCH     映像裡有同一個前綴但不同的版本字串而沒有任何候選相符，或版本相符但路徑相符比例 < PATH_RATIO，
                     或沒有版本字串但路徑 >= MIN_PATHS_MISMATCH 個而相符比例 < MISMATCH_RATIO（0.50）；
        NOT_ASSESSED 讀不到（不是一般檔案、不在刷機包裡、讀取失敗）、原始碼樹沒有版本字串、或證據不足以判斷。
      用語永遠是「與用這份原始碼建置一致（consistent with being built from this source version）」，不是逐位元相同的比對。
      另外每個映像用 uefi_image.py 解開（FV／FFS／GUID-defined LZMA…，有解壓縮大小與深度限制）並找內建函式庫（OpenSSL、Mbed TLS）的字串與建置路徑，
      每個映像記在 images[].bundled_libs，全部映像合併的 present／absent／not_assessed 記在 libraries（cra_report 據此判 UB1／UB2；absent 要求映像完整解開）。
      stdout 一行 `X-uefi-binary<TAB>OK|ATTENTION|GAP|FAIL<TAB>說明`（全部 MATCH → OK；有 MISMATCH → ATTENTION；
      有 NOT_ASSESSED 或沒有 UEFI 映像 → GAP）。退出碼：OK 0；ATTENTION／GAP 2；FAIL 1；參數錯誤 64。
  extra       --inventory <flash-inventory.json> --deliverable <檔案>（可重複） --name <產品名稱> --version <產品版本>
              [--l4t <Jetson Linux 版本>] [--tree <UEFI 原始碼樹>] [--uefi-json <uefi-source.json>] --out <extra-deliverables.json>
      另外交付的韌體（例如 RD 自己建的 bootloader capsule、回退用的舊版）：名稱、大小、sha256、sha512、可讀的版本字串
      （原始碼樹的候選字串，加上通用的 `<名稱>_R<版本>` 樣式），「配對」的刷機包名稱／版本。只收一般檔案（符號連結、資料夾、
      裝置檔都拒絕），只讀給的檔案。版本字串與刷機包的 L4T／產品版本不同 → ATTENTION；找不到版本字串 → NOT_ASSESSED，不猜。
      結果寫進 --out 與 --inventory 的 extra_deliverables（firmware_bom.py 讀它併進產品 SBOM）；沒有這個子指令時清點檔不變。
      stdout 一行 `X-extra-deliverable<TAB>...`。
  coverage    --result <scan-flash-package.sh 的結果資料夾> --variant <rootfs 名稱> [--check <uefi-binary-check.json>]
      每個 bootloader 清點項目的涵蓋說明（bootloader-coverage.json、bootloader-coverage.md 寫在 <結果>/<variant>/）：
      UEFI 映像、廠商閉源韌體、資料檔、未分類、非韌體（腳本、設定、文字、套件）、非一般檔案；各類數量加起來等於清點總數。
      rootfs 的 opt/ota_package/<soc>/TEGRA_BL_*.Cap（從 rootfs 的 SBOM 找）另列。
      stdout 一行 `X-bootloader-coverage<TAB>...`（有閉源韌體或未分類的項目就是 GAP，退出碼 2）。
      --platform raspberrypi：原始磁碟映像（Raspberry Pi OS）。boot 分割區的檔案與 kernel/ 分類：閉源 GPU 韌體（start*.elf、fixup*.dat、
      bootcode.bin）GAP（只有廠商發行說明、沒有安全公告可比對）、kernel／initramfs NOT_ASSESSED、.dtb／.dtbo 資料檔；Pi 4／5 的 EEPROM
      開機程式不在映像裡 → not_in_image 明列沒有涵蓋。
      --not-assessed <平台>（例如 rockchip；不需要 flash-inventory.json）：這個平台沒有定義開機鏈的分類 → 狀態 NOT_ASSESSED、
      說明 "boot chain not defined for this platform"，沒有任何分類與數量；報告因此不會看起來像「沒有開機韌體的問題」。退出碼 2。

規則：不寫「沒用」「可移除」；沒有成分層級掃描的項目一律明說 GAP，不顯示安全。建置機器的路徑與使用者名稱只寫在內部的 JSON，
客戶版文字（customer_text）不含。
"""
import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
FP_PATH = HERE.parent / "demo" / "flash_package.py"

SCHEMA = "sca-center-bootloader-coverage/1"
CHECK_SCHEMA = "sca-center-uefi-binary-check/1"
MAX_BIN = 64 << 20            # 單一映像最多讀進記憶體的位元組數（超過：只搜前面這一段並註明）
MAX_STR = 2000                # 單一字串最多保留幾個字元
MIN_STR = 4                   # 可印字元連續幾個以上才算字串
MIN_CAND = 6                  # 版本字串候選最少幾個字元
MAX_TREE_ENTRIES = 400000     # 走原始碼樹找版本檔的項目數上限
MAX_TREE_DEPTH = 12
MAX_PATHS = 5000              # 單一映像最多比對幾個內嵌路徑
PATH_RATIO = 0.90             # MATCH：內嵌路徑在樹裡存在的比例下限
MISMATCH_RATIO = 0.50         # 沒有版本字串時，比例低於這個而且路徑夠多才判 MISMATCH
MIN_PATHS_MISMATCH = 5
VINFO_MAX = 4096
TOK = "A-Za-z0-9_.+-"        # 版本詞的字元
SRC_EXT = r"(?:c|h|S|s|asm|nasm|cpp|cc|inf|uni|vfr|asl|iasl)"
PATH_RE = re.compile(r"/[A-Za-z0-9_.+@~-]+(?:/[A-Za-z0-9_.+@~-]+){2,}\." + SRC_EXT + r"(?![A-Za-z0-9_])")
GENERIC_VER = re.compile(r"(?<![A-Za-z0-9])(?:[A-Za-z][A-Za-z0-9]*(?:[_-][A-Za-z0-9]+)*_)?[rR]\d{2,3}\.\d+(?:\.\d+)*(?:-\d+)?(?![A-Za-z0-9.])")
EXTRA_MAX = 20                # 每個另外交付的檔案最多記幾個通用版本字串

# ---- bootloader 清點項目的分類（檔名樣式；不認得的韌體副檔名 → unclassified，不猜） ----
FW_EXT = (".bin", ".efi", ".elf", ".img", ".fw", ".rom", ".fip")
DATA_EXT = (".bct", ".dtb", ".dtbo")
TEE_IMG_RE = re.compile(r"^tos-optee_[a-z0-9]+\.img$")
UEFI_RE = re.compile(r"^uefi_[a-z0-9_]+\.bin$")
NOT_FW_PREFIX = ("license", "notice", "readme", "copying")
# (檔名開頭的樣式, 標籤)：NVIDIA 閉源韌體。樣式取自 Jetson 刷機包的 bootloader 資料夾檔名；沒有列到的 → unclassified
VENDOR_PATTERNS = [
    (r"^mb1[_.-]", "MB1 (first-stage bootloader)"), (r"^mb2rf[_.-]", "MB2 RF"), (r"^mb2[_.-]", "MB2 (second-stage bootloader)"),
    (r"^bpmp[_.-]", "BPMP firmware"), (r"^(tos|standalonemm_optee)[_.-]", "TOS / OP-TEE"), (r"^bl31[_.-]", "Arm Trusted Firmware BL31"),
    (r"^hafnium[_.-]", "Hafnium (secure partition manager)"), (r"^psc[a-z_]*[_.-]", "PSC firmware"), (r"^spe[_.-]", "SPE firmware"),
    (r"^(sc7|warmboot)[a-z0-9_]*[_.-]", "SC7 (low-power state) firmware"), (r"^applet[_.-]", "Applet firmware"),
    (r"^aon[_.-]", "AON firmware"), (r"^adsp[a-z0-9]*[_.-]", "ADSP firmware"), (r"^camera-rtcpu[_.-]", "Camera RTCPU firmware"),
    (r"^display[_.-]", "Display firmware"), (r"^fsi[_.-]", "FSI firmware"), (r"^fskp[_.-]", "FSKP"), (r"^xusb[_.-]", "XUSB firmware"),
    (r"^hpse", "HPSE firmware"), (r"^nvdec[_.-]", "NVDEC firmware"), (r"^nvpva[_.-]", "PVA firmware"), (r"^mce[_.-]", "MCE firmware"),
    (r"^eks[_.-]", "EKS"), (r"^(sb_bl1|sbfw|sbraw)[a-z0-9_]*_prod\.", "Secure boot firmware"), (r"^tsec[_.-]", "TSEC firmware"), (r"^nv-rce\d", "Camera RCE firmware"), (r"^igbfw[_.-]", "GPU system processor package"), (r"^rtl\d+", "Network adapter firmware"),
]
VENDOR_RE = [(re.compile(p), lab) for p, lab in VENDOR_PATTERNS]
CLASS_ORDER = ("uefi", "vendor_firmware", "data", "unclassified", "packaged_firmware", "not_firmware", "not_file")
CLASS_TEXT = {
    "uefi": "UEFI images", "vendor_firmware": "Vendor closed-source firmware", "data": "Data files (.bct, .dtb, .dtbo)",
    "unclassified": "Unclassified firmware-type files", "packaged_firmware": "Packaged firmware (.deb, .pkg), content not scanned",
    "not_firmware": "Other files (scripts, configuration, text, tools)",
    "not_file": "Entries that are not regular files (links)"}
# 沒有成分層級掃描的類別的說明（客戶版與內部共用，英文）
COVER_VENDOR = ("closed-source vendor firmware, no component-level scan; covered only by NVIDIA security bulletins matched on the "
                "Jetson Linux version")
COVER_UNCL = "file name pattern not recognised; no component-level scan"
COVER_DATA = "data file; not vulnerability-scanned"
COVER_NOTFW = "not firmware (script, configuration, text or tool); not part of this coverage list"
COVER_PKG = "packaged firmware (.deb or .pkg): the package content is not unpacked or scanned (gap)"
COVER_NOTFILE = "not a regular file (link); target not followed"
# module id（TEGRA_BL_<id>…Cap 的數字）→ 名稱：只放確定的；其他原樣印出，不猜
MODULE_IDS = {"3767": "Jetson Orin NX/Nano module", "3701": "Jetson AGX Orin module"}
CAP_RE = re.compile(r"(?:^|/)opt/ota_package/([A-Za-z0-9_.-]+)/(TEGRA_BL_([0-9]{4})([A-Za-z0-9_.-]*)\.[Cc]ap)$")


class Fail(Exception):
    pass


_FP = None


_UIMG = None


def uimgmod():
    """tools/cra/uefi_image.py（映像解開後的函式庫指紋；依路徑載入）。載入失敗 → None（該映像的函式庫檢查標 NOT_ASSESSED）。"""
    global _UIMG
    if _UIMG is None:
        try:
            spec = importlib.util.spec_from_file_location("sca_center_uefi_image", HERE / "uefi_image.py")
            m = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(m)
            _UIMG = m
        except Exception:      # noqa: BLE001
            _UIMG = False
    return _UIMG or None


def fpmod():
    """tools/demo/flash_package.py（串流讀取、open_nofollow；依路徑載入，同 cra_report.py 的做法）。"""
    global _FP
    if _FP is None:
        try:
            spec = importlib.util.spec_from_file_location("sca_center_flash_package", FP_PATH)
            m = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(m)
        except Exception as e:      # noqa: BLE001
            raise Fail(f"無法載入 {FP_PATH.name}（{type(e).__name__}）")
        _FP = m
    return _FP


def load_json(p):
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def write_json_atomic(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name("." + path.name + ".tmp")
    tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    os.replace(tmp, path)


# ---------------------------------------------------------------- 分類（項目 1）

def classify(item):
    """bootloader 清點的一筆 → (類別, 標籤)。標籤只在 vendor_firmware 有值。"""
    if not isinstance(item, dict) or item.get("type") != "file":
        return "not_file", None
    name = str(item.get("path", "")).rsplit("/", 1)[-1].lower()
    if name.startswith(NOT_FW_PREFIX):
        return "not_firmware", None
    if UEFI_RE.match(name):
        return "uefi", None
    if name.endswith(DATA_EXT) or re.match(r"^spvault-.*conf\.bin$", name):
        return "data", None
    if name.startswith("source."):
        return "not_firmware", None
    if name.endswith((".deb", ".pkg")):
        return "packaged_firmware", None
    if name.endswith(FW_EXT):
        for rx, lab in VENDOR_RE:
            if rx.match(name):
                return "vendor_firmware", lab
        return "unclassified", None
    return "not_firmware", None


def cap_info(path):
    """rootfs 裡的路徑 → (soc 資料夾, 檔名, module id, 後綴) 或 None（不是 opt/ota_package/<soc>/TEGRA_BL_*.Cap）。"""
    m = CAP_RE.search(path.lstrip("/"))
    if not m:
        return None
    return m.group(1), m.group(2), m.group(3), m.group(4).lstrip("_")


def rootfs_capsules(sbom, owners=None):
    """rootfs SBOM（CycloneDX）的檔案元件 → opt/ota_package/<soc>/TEGRA_BL_*.Cap 的清單。
    owners：選用，{套件名稱: [檔案路徑]}（dpkg 的 .list）；沒有或找不到 → "unknown"，不猜。"""
    out = []
    owner_of = {}
    for pkg, paths in (owners or {}).items():
        if isinstance(paths, list):
            for p in paths:
                if isinstance(p, str):
                    owner_of.setdefault("/" + p.lstrip("/"), pkg)
    comps = sbom.get("components") if isinstance(sbom, dict) else None
    for c in comps if isinstance(comps, list) else []:
        if not isinstance(c, dict) or c.get("type") != "file" or not isinstance(c.get("name"), str):
            continue
        ci = cap_info(c["name"])
        if not ci:
            continue
        soc, fname, mid, suffix = ci
        hs = {h.get("alg"): h.get("content") for h in c.get("hashes") or [] if isinstance(h, dict)}
        p = "/" + c["name"].lstrip("/")
        out.append({"path": p, "soc_folder": soc, "file": fname, "module_id": mid,
                    "module": MODULE_IDS.get(mid) or "not mapped", "variant_suffix": suffix or None,
                    "sha256": hs.get("SHA-256"), "dpkg_package": owner_of.get(p) or "unknown",
                    "dpkg_package_note": None if p in owner_of else "dpkg file lists were not recorded or do not list this file",
                    "coverage": "vendor generic bootloader capsule shipped in the rootfs; content not scanned",
                    "board_match": "NOT_ASSESSED"})
    out.sort(key=lambda x: x["path"])
    return out


# ---------------------------------------------------------------- 字串與版本候選（項目 2、3）

def extract_strings(data):
    """位元組 → (ASCII 字串清單, UTF-16LE 字串清單)；連續可印字元 >= MIN_STR。"""
    a = [m.group().decode("ascii")[:MAX_STR] for m in re.finditer(rb"[\x20-\x7e]{%d,}" % MIN_STR, data)]
    u = [m.group().decode("utf-16-le", "replace")[:MAX_STR] for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % MIN_STR, data)]
    return a, u


def tree_candidates(tree, uefi_json=None):
    """UEFI 原始碼樹 → 版本字串候選 [{"value", "kind", "source"}]。
    - 檔名含 VERSION_INFO 的小檔（<= VINFO_MAX）：非空行；兩行 → 「第一行-第二行」（kind joined）與第一行（kind base）；一行 → 該行；
    - images/buildid_*.txt 的第一行（kind build-id）；
    - uefi-source.json 的 source_strings 字面值（kind literal）。
    走訪不跟隨符號連結、不進 .git，項目數與深度有上限。回傳 (候選清單, 備註清單)。"""
    cands, notes, seen = [], [], set()

    def add(value, kind, source):
        value = (value or "").strip()
        # 太短或沒有字母的字串（例如 DSC 裡別的平台的 "2.7"）在映像裡太容易巧合，不當候選
        if re.fullmatch(r"[\x20-\x7e]{%d,200}" % MIN_CAND, value) and re.search(r"[A-Za-z]", value) and (value, kind) not in seen:
            seen.add((value, kind))
            cands.append({"value": value, "kind": kind, "source": source})

    n, stack, hit_limit = 0, [("", 0)], False
    while stack:
        rel, depth = stack.pop()
        try:
            with os.scandir(os.path.join(tree, rel) if rel else tree) as it:
                ents = sorted(it, key=lambda e: e.name)
        except OSError:
            notes.append(f"cannot read a folder of the source tree ({rel or '.'})")
            continue
        for e in ents:
            n += 1
            if n > MAX_TREE_ENTRIES:
                hit_limit = True
                break
            r = f"{rel}/{e.name}" if rel else e.name
            try:
                if e.is_symlink():
                    continue
                if e.is_dir(follow_symlinks=False):
                    if e.name != ".git" and depth < MAX_TREE_DEPTH:
                        stack.append((r, depth + 1))
                    continue
                if not e.is_file(follow_symlinks=False):
                    continue
                st = e.stat(follow_symlinks=False)
            except OSError:
                continue
            is_vi = "VERSION_INFO" in e.name.upper() and st.st_size <= VINFO_MAX
            is_bid = re.fullmatch(r"buildid_[A-Za-z0-9_.-]{1,100}\.txt", e.name) and rel.split("/")[-1] == "images" and st.st_size <= VINFO_MAX
            if not (is_vi or is_bid):
                continue
            try:
                with fpmod().open_nofollow(os.path.join(tree, r)) as f:
                    lines = [x.strip() for x in f.read(VINFO_MAX).decode("utf-8", "replace").splitlines() if x.strip()]
            except OSError:
                continue
            if not lines:
                continue
            if is_bid:
                add(lines[0], "build-id", r)
            elif len(lines) == 1:
                add(lines[0], "version-info", r)
            else:
                add(f"{lines[0]}-{lines[1]}", "joined", r)
                add(lines[0], "base", r)
                if len(lines) > 2:
                    notes.append(f"{r}: more than two lines; only the first two were used")
        if hit_limit:
            notes.append(f"source tree walk stopped after {MAX_TREE_ENTRIES} entries: version files may be missing")
            break
    if isinstance(uefi_json, dict):
        for s in uefi_json.get("source_strings") or []:
            if isinstance(s, dict) and s.get("kind") == "literal" and isinstance(s.get("value"), str):
                add(s["value"], "literal", str(s.get("file") or "uefi-source.json"))
        for b in uefi_json.get("build_ids") or []:
            if isinstance(b, dict) and isinstance(b.get("value"), str):
                add(b["value"], "build-id", str(b.get("file") or "uefi-source.json"))
    return cands, notes


def find_candidates(cands, strings):
    """候選 → 在字串裡找到的紀錄。exact：前後都不是版本詞的字元（整個詞相同）；否則 embedded（記較長的詞）。"""
    finds = []
    ascii_s, utf_s = strings
    for c in cands:
        v = c["value"]
        tokenlike = re.fullmatch(f"[{TOK}]+", v) is not None
        rx = re.compile(r"(?<![%s])%s(?![%s])" % (TOK, re.escape(v), TOK)) if tokenlike else None
        for enc, lst in (("UTF-16LE", utf_s), ("ASCII", ascii_s)):
            got, longer = 0, None
            for s in lst:
                if v not in s:
                    continue
                if rx is None or rx.search(s):
                    finds.append({"candidate": v, "kind": c["kind"], "source": c["source"], "encoding": enc, "exact": True, "found": v})
                    got += 1
                else:
                    m = re.search(r"[%s]*%s[%s]*" % (TOK, re.escape(v), TOK), s)
                    longer = longer or (m.group() if m else s[:100])
                if got >= 3:
                    break
            if not got and longer:
                finds.append({"candidate": v, "kind": c["kind"], "source": c["source"], "encoding": enc, "exact": False, "found": longer[:200]})
    return finds


def stem_of(value):
    """版本字串的前綴（第一個「_R<數字>」或「-R<數字>」之前，含分隔符號）；沒有 → None。"""
    m = re.search(r"[_-]R?\d", value)
    return value[:m.start() + 1] if m and m.start() >= 2 else None


def other_versions(cands, strings, exact_values):
    """映像裡和候選同前綴、但不是任何候選的版本詞（不同版本的證據）。"""
    out = []
    stems = sorted({stem_of(c["value"]) for c in cands if stem_of(c["value"])})
    for stem in stems:
        rx = re.compile(re.escape(stem) + r"R?\d[%s]*" % TOK)
        for lst in strings:
            for s in lst:
                if stem not in s:
                    continue
                for m in rx.finditer(s):
                    t = m.group().rstrip(".-")
                    if t not in exact_values and t not in {c["value"] for c in cands} and t not in out:
                        out.append(t)
                if len(out) >= 10:
                    return out
    return out


def embedded_paths(strings_ascii, tree):
    """ASCII 字串裡的原始碼路徑 → (相對路徑 matched/missing 清單, 元件外路徑數, 建置前綴範例)。
    路徑以 /<元件>/ 切開（元件＝樹最上層名稱以 edk2 開頭的資料夾）；相對路徑在樹裡以 lexists 檢查（不讀內容）。"""
    comps = set()
    try:
        comps = {e.name for e in os.scandir(tree) if e.name.startswith("edk2") and e.is_dir(follow_symlinks=False)}
    except OSError:
        pass
    root_edk2 = os.path.isdir(os.path.join(tree, "MdePkg"))
    if root_edk2:
        comps.add("edk2")
    seen, matched, missing, other, prefixes = set(), [], [], 0, []
    for s in strings_ascii:
        for m in PATH_RE.finditer(s):
            p = m.group()
            if p in seen:
                continue
            seen.add(p)
            if len(seen) > MAX_PATHS:
                break
            segs = p.split("/")[1:]
            options = [(segs[i], "/".join(segs[i + 1:])) for i in range(len(segs) - 1) if segs[i] in comps]
            options = [(c, r) for c, r in options if r and ".." not in r.split("/") and "." not in r.split("/")]
            if not options:
                other += 1
                continue
            hit = None
            for comp, rel in options:
                base = tree if (root_edk2 and comp == "edk2" and not os.path.lexists(os.path.join(tree, comp))) else os.path.join(tree, comp)
                if os.path.lexists(os.path.join(base, rel)):
                    hit = (comp, rel)
                    break
            if hit:
                matched.append(f"{hit[0]}/{hit[1]}")
            else:
                missing.append(f"{options[0][0]}/{options[0][1]}")
            pre = p[:p.index("/" + options[0][0] + "/")]
            if pre and pre not in prefixes and len(prefixes) < 3:
                prefixes.append(pre)
    return sorted(matched), sorted(missing), other, prefixes


def decide(finds, others, matched, missing, have_cands):
    """版本與路徑的證據 → (結果, 說明)。門檻見模組開頭的說明。"""
    total = len(matched) + len(missing)
    ratio = len(matched) / total if total else None
    exact = [f for f in finds if f["exact"]]
    if exact:
        if total == 0:
            return "MATCH", "version string found in the image; no source paths under an edk2 component folder were embedded (path evidence: none)"
        if ratio >= PATH_RATIO:
            return "MATCH", f"version string found in the image; {len(matched)} of {total} embedded source paths exist in the source tree"
        return "MISMATCH", (f"version string found in the image, but only {len(matched)} of {total} embedded source paths exist in the "
                            f"source tree (threshold {int(PATH_RATIO * 100)}%)")
    if others:
        return "MISMATCH", "the image contains a different version string with the same prefix than the source tree: " + ", ".join(others[:3])
    if total >= MIN_PATHS_MISMATCH and ratio < MISMATCH_RATIO:
        return "MISMATCH", (f"no version string from the source tree found in the image, and only {len(matched)} of {total} embedded "
                            "source paths exist in the source tree")
    if not have_cands:
        return "NOT_ASSESSED", "the source tree has no version string to search for" + (f"; {len(matched)} of {total} embedded paths exist" if total else "")
    if finds:
        return "NOT_ASSESSED", "a candidate version string appears only inside a longer string: not an exact match"
    return "NOT_ASSESSED", "no version string from the source tree was found in the image" + (
        f"; {len(matched)} of {total} embedded source paths exist in the source tree" if total else "; no embedded source paths")


def check_image(data, tree, cands, truncated=False):
    """一個 UEFI 映像的內容 → 結果 dict（result、detail、version_found、path 統計）。"""
    strings = extract_strings(data)
    finds = find_candidates(cands, strings)
    exact_vals = {f["candidate"] for f in finds if f["exact"]}
    others = other_versions(cands, strings, exact_vals) if not exact_vals else []
    matched, missing, other, prefixes = embedded_paths(strings[0], tree)
    result, detail = decide(finds, others, matched, missing, bool(cands))
    return {"result": result, "detail": detail + ("; only the first %d MiB of the image were searched" % (MAX_BIN >> 20) if truncated else ""),
            "version_found": [{k: f[k] for k in ("candidate", "kind", "encoding", "exact", "found")} for f in finds][:10],
            "other_versions_seen": others,
            "paths": {"total": len(matched) + len(missing), "matched": len(matched), "missing": len(missing),
                      "missing_examples": missing[:10], "outside_components": other},
            "build_prefix_examples": prefixes,
            "wording": "consistent with being built from this source version (not a bit-for-bit comparison)"}


def read_images(inventory_items, archive=None, directory=None):
    """清點項目（路徑 → 內容）：用 flash_package 的串流讀取器讀符合的成員（只讀、不解開到磁碟）。
    回傳 {路徑: (位元組 或 None, 截斷, 原因)}。"""
    fp = fpmod()
    want = {x["path"] for x in inventory_items}
    got = {}
    with fp.open_source(archive, directory) as (entries, _src):
        for e in entries:
            if e.parts is None:
                continue
            if e.kind == "dir" and directory and e.parts[-1] in fp.VARIANTS:
                e.descend = False          # 資料夾來源：rootfs 很大，不走進去
                continue
            n = e.name
            if n not in want or n in got:
                continue
            if e.kind != "file":
                got[n] = (None, False, f"not a regular file in the flash package ({e.kind})")
            else:
                try:
                    with contextlib.closing(e.open()) as f:
                        data = f.read(MAX_BIN + 1)
                    got[n] = (data[:MAX_BIN], len(data) > MAX_BIN, None)
                except OSError as err:
                    got[n] = (None, False, f"cannot be read ({err.strerror or type(err).__name__})")
            if len(got) == len(want):
                break
    for p in want - set(got):
        got[p] = (None, False, "not found in the given flash package")
    if want and all(v[2] == "not found in the given flash package" for v in got.values()):
        hint = " (none of the inventory paths exist here: the --dir/--archive folder level may differ from the one used for the inventory)"
        got = {k: (v[0], v[1], v[2] + hint) for k, v in got.items()}
    return got


SCOPE_TEXT = "the UEFI images uefi_*.bin listed in the flash package; UEFI payloads inside capsules (e.g. TEGRA_BL_*.Cap) were not examined"


def image_libs(data, truncated, corroboration=None):
    """映像解開後的函式庫指紋（uefi_image.analyze）。讀取被截斷（超過 MAX_BIN）→ 不完整，不給 absent。永遠回傳 dict。"""
    um = uimgmod()
    if um is None:
        return {"method": None, "complete": False, "libraries": {}, "undecoded": [{"where": "image", "reason": "uefi_image.py could not be loaded"}]}
    r = um.analyze(data, corroboration)
    if truncated:
        r["complete"] = False
        r["undecoded"] = [{"where": "image", "reason": f"only the first {MAX_BIN >> 20} MiB of the image were read"}] + r["undecoded"]
        for v in r["libraries"].values():
            if v["result"] == "absent":
                v["result"], v["reason"] = "not_assessed", "the image was larger than the read limit and was not fully decoded"
    return r


def uefi_items(inv):
    return [x for x in (inv.get("bootloader") or []) if isinstance(x, dict) and classify(x)[0] == "uefi"]


def run_uefi_check(inv, tree, archive=None, directory=None, uefi_json=None, platform_dsc=(), platform_defines=()):
    """→ 結果 dict（寫成 uefi-binary-check.json）。"""
    cands, notes = tree_candidates(tree, uefi_json)
    items = uefi_items(inv)
    res = {"schema": CHECK_SCHEMA, "wording": "consistent with being built from this source version (not a bit-for-bit comparison)",
           "thresholds": {"path_ratio_match": PATH_RATIO, "path_ratio_mismatch": MISMATCH_RATIO, "min_paths_for_path_mismatch": MIN_PATHS_MISMATCH,
                          "max_read_bytes": MAX_BIN},
           "candidates": cands, "notes": notes, "images": []}
    if not items:
        res["status"], res["detail"] = "GAP", "the flash package inventory lists no UEFI image (uefi_*.bin)"
        return res
    imgs = read_images(items, archive, directory)
    um = uimgmod()
    dsc_list = [str(x) for x in platform_dsc] or [str(r.get("dsc")) for r in ((uefi_json or {}).get("build_analysis") or {}).get("runs") or [] if r.get("dsc")]
    corr = um.corroborate(tree, dsc_list, [str(x) for x in platform_defines]) if um else {}
    res["platform_dsc"], res["corroboration"] = dsc_list, corr
    res["scope"] = SCOPE_TEXT
    cache = {}
    for x in items:
        data, trunc, why = imgs[x["path"]]
        r = {"path": x["path"], "sha256": x.get("sha256")}
        if data is None:
            r.update({"result": "NOT_ASSESSED", "detail": why})
        else:
            key = hashlib.sha256(data).hexdigest()
            if key not in cache:
                cache[key] = check_image(data, tree, cands, trunc)
                cache[key]["bundled_libs"] = image_libs(data, trunc, corr)
            r.update(cache[key])
        res["images"].append(r)
    cnt = {k: sum(1 for i in res["images"] if i["result"] == k) for k in ("MATCH", "MISMATCH", "NOT_ASSESSED")}
    res["counts"] = cnt
    um = uimgmod()
    res["libraries"] = um.combine([{"path": i["path"], "libraries": (i.get("bundled_libs") or {}).get("libraries")} for i in res["images"]]) if um else {}
    res["status"] = "ATTENTION" if cnt["MISMATCH"] else "GAP" if cnt["NOT_ASSESSED"] else "OK"
    if not cands:
        res["status"] = "GAP" if res["status"] == "OK" else res["status"]
    res["detail"] = (f"{len(items)} UEFI image(s): consistent with the source version {cnt['MATCH']}, different {cnt['MISMATCH']}, "
                     f"not assessed {cnt['NOT_ASSESSED']} (consistency, not a bit-for-bit comparison)")
    return res


# ---------------------------------------------------------------- 另外交付的韌體（項目 3）

def norm_version(text):
    """版本字串 → (基底, 完整)：「R39.2.0-2」→ ("39.2.0", "39.2.0.2")；沒有後綴時完整＝基底；認不出 → None。"""
    m = re.search(r"[rR]?(\d+(?:\.\d+)+)(?:-(\d+))?", text or "")
    if not m:
        return None
    return m.group(1), m.group(1) + ("." + m.group(2) if m.group(2) else "")


def compare_version(found, product_version, l4t):
    """找到的版本字串 vs 刷機包（產品版本與 L4T 版本兩種都比）→ consistent／different／unknown（對不出來）。"""
    nf = norm_version(found)
    if not nf:
        return "unknown"
    pv = norm_version(product_version)
    flash = set(pv or ()) | ({str(l4t)} if l4t else set())
    if not flash:
        return "unknown"
    base, full = nf
    if full in flash or (base == full and base in flash):
        return "consistent"
    if base in flash:
        # 基底相同、修訂不同：產品版本帶有同基底的修訂（例如 40.1.0.3 對 -4）才是不同；否則比不出來
        if pv and pv[1].startswith(base + ".") and pv[1] != full:
            return "different"
        return "unknown"
    return "different"


def extra_record(path, cands, product, version, l4t):
    """另外交付的一個檔案 → 紀錄。只收一般檔案（lstat 與 O_NOFOLLOW 雙重確認）。"""
    p = os.path.abspath(path)
    try:
        st = os.lstat(p)
    except OSError as e:
        raise Fail(f"cannot read the extra deliverable ({e.strerror})")
    if not stat.S_ISREG(st.st_mode):
        raise Fail("an extra deliverable must be a regular file (symbolic links, folders and special files are rejected): "
                   + os.path.basename(p))
    h2, h5, n, keep = hashlib.sha256(), hashlib.sha512(), 0, []
    try:
        with fpmod().open_nofollow(p) as f:
            for b in iter(lambda: f.read(1 << 20), b""):
                h2.update(b)
                h5.update(b)
                n += len(b)
                if sum(map(len, keep)) < MAX_BIN:
                    keep.append(b)
    except OSError as e:
        raise Fail(f"cannot read the extra deliverable {os.path.basename(p)} ({e.strerror or type(e).__name__})")
    data = b"".join(keep)[:MAX_BIN]
    strings = extract_strings(data)
    finds = [f for f in find_candidates(cands, strings) if f["exact"]]
    found = [{"value": f["candidate"], "encoding": f["encoding"], "basis": f"source tree candidate ({f['kind']})"} for f in finds]
    seen = {x["value"] for x in found}
    for enc, lst in (("UTF-16LE", strings[1]), ("ASCII", strings[0])):
        for s in lst:
            for m in GENERIC_VER.finditer(s):
                if m.group() not in seen and len(found) < EXTRA_MAX:
                    seen.add(m.group())
                    found.append({"value": m.group(), "encoding": enc, "basis": "generic version-like string"})
    version_found = found[0]["value"] if found else None
    per = [compare_version(x["value"], version, l4t) for x in found]
    for x, r in zip(found, per):
        x["vs_flash_package"] = r
    known = {r for r in per if r != "unknown"}
    vs = "unknown" if not known else (known.pop() if len(known) == 1 else "conflict")
    if vs != "unknown" and per and per[0] == "unknown":
        version_found = next(x["value"] for x, r in zip(found, per) if r != "unknown")
    rec = {"name": os.path.basename(p), "type": "file", "size": n, "mtime": int(st.st_mtime), "sha256": h2.hexdigest(), "sha512": h5.hexdigest(),
           "version_strings": found, "version": version_found, "version_vs_flash_package": vs,
           "paired_with": {"name": product, "version": version, "jetson_linux": l4t or None},
           "scanned": False, "scan_note": "recorded only; no component-level or vulnerability scan"}
    if n > MAX_BIN:
        rec["read_note"] = f"hashes cover the whole file; version strings were searched in the first {MAX_BIN >> 20} MiB only"
    if vs == "conflict":
        rec["status"], rec["note"] = "ATTENTION", ("version strings in the file disagree with each other about this flash package ("
                                                   + "; ".join(f"{x['value']}: {x['vs_flash_package']}" for x in found[:6]) + "); not scanned")
    elif vs == "different":
        rec["status"], rec["note"] = "ATTENTION", f"different version from this flash package ({version_found}); not scanned"
    elif vs == "consistent":
        rec["status"], rec["note"] = "OK", f"version string {version_found} is consistent with this flash package; recorded only, not scanned"
    elif version_found:
        rec["status"], rec["note"] = "NOT_ASSESSED", f"version string {version_found} found but cannot be compared with this flash package; not scanned"
    else:
        rec["status"], rec["note"] = "NOT_ASSESSED", "no readable version string: version unknown; not scanned"
    return rec


def run_extra(inv_path, files, product, version, l4t, tree=None, uefi_json=None):
    names = [os.path.basename(f) for f in files]
    if len(set(names)) != len(names):
        raise Fail("two extra deliverables have the same file name")
    cands, notes = tree_candidates(tree, uefi_json) if tree else ([], [])
    recs = [extra_record(f, cands, product, version, l4t) for f in files]
    return recs, notes


# ---------------------------------------------------------------- 涵蓋說明（項目 1）

def build_coverage(inv, caps, uefi_src, check, variant, tee_src=None):
    """inv：flash-inventory.json；caps：rootfs_capsules()；uefi_src：uefi-source.json 或 None；check：uefi-binary-check.json 或 None。"""
    boot = [x for x in (inv.get("bootloader") or []) if isinstance(x, dict)]
    by = {}
    for x in (check or {}).get("images") or []:
        if isinstance(x, dict):
            by[x.get("path")] = x
    tee_by = {}
    for x in ((tee_src or {}).get("image_check") or {}).get("images") or []:
        if isinstance(x, dict):
            tee_by[x.get("path")] = x
    items, counts = [], dict.fromkeys(CLASS_ORDER, 0)
    for x in boot:
        cls, lab = classify(x)
        counts[cls] += 1
        it = {"path": x.get("path"), "class": cls, "sha256": x.get("sha256")}
        if cls == "uefi":
            if uefi_src is None:
                it.update(status="GAP", coverage="UEFI image; no UEFI source tree was given, so its bundled libraries are not scanned")
            else:
                c = by.get(x.get("path"))
                it["uefi_source_status"] = uefi_src.get("status")
                if c is None:
                    it.update(status="GAP", build_check="NOT_RUN",
                              coverage="scanned from UEFI source; the check that this image was built from that source was not run")
                else:
                    r = c.get("result")
                    it.update(status={"MATCH": "OK", "MISMATCH": "ATTENTION"}.get(r, "GAP"), build_check=r, build_check_detail=c.get("detail"),
                              coverage="scanned from UEFI source; build check: " + {"MATCH": "consistent with being built from this source version",
                                                                                  "MISMATCH": "NOT consistent with this source version (the source scan may not describe this image)"
                                                                                  }.get(r, "not assessed"))
        elif cls == "vendor_firmware" and tee_src is not None and TEE_IMG_RE.match(str(x.get("path", "")).rsplit("/", 1)[-1].lower()):
            c = tee_by.get(x.get("path"))
            r = (c or {}).get("result")
            it.update(label=lab, tee_source_status=tee_src.get("status"), build_check=r or "NOT_RUN",
                      status={"MATCH": "OK", "MISMATCH": "ATTENTION"}.get(r, "GAP"),
                      coverage="scanned from vendor public source (OP-TEE, TF-A and the Mbed TLS bundled in OP-TEE); build check: " + {
                          "MATCH": "consistent with being built from this source version",
                          "MISMATCH": "NOT consistent with this source version (the source scan may not describe this image)"}.get(r, "not assessed"))
        elif cls == "vendor_firmware":
            it.update(label=lab, status="GAP", coverage=COVER_VENDOR)
        elif cls == "unclassified":
            it.update(status="GAP", coverage=COVER_UNCL)
        elif cls == "data":
            it.update(status="NOT_ASSESSED", coverage=COVER_DATA)
        elif cls == "packaged_firmware":
            it.update(status="GAP", coverage=COVER_PKG)
        elif cls == "not_firmware":
            it.update(status="INFO", coverage=COVER_NOTFW)
        else:
            it.update(status="INFO", coverage=COVER_NOTFILE)
        items.append(it)
    st = {k: sorted({i["status"] for i in items if i["class"] == k}) for k in CLASS_ORDER}
    total = len(boot)
    cov = {"schema": SCHEMA, "variant": variant, "total": total, "counts": counts, "counts_add_up": sum(counts.values()) == total,
           "class_text": CLASS_TEXT, "class_status": st,
           "uefi_source": {"present": uefi_src is not None, "status": (uefi_src or {}).get("status"),
                           "build_check": {"present": check is not None, "status": (check or {}).get("status"),
                                           "counts": (check or {}).get("counts"), "detail": (check or {}).get("detail"),
                                           "wording": "consistent with being built from this source version (not a bit-for-bit comparison)"}},
           "vendor_firmware_labels": sorted({i["label"] for i in items if i["class"] == "vendor_firmware"}),
           "rootfs_capsules": caps, "rootfs_capsules_board_match": "NOT_ASSESSED",
           "extra_deliverables": [{k: x.get(k) for k in ("name", "size", "sha256", "version", "version_vs_flash_package", "status", "note")}
                                  for x in inv.get("extra_deliverables") or [] if isinstance(x, dict)],
           "items": items}
    gaps = [k for k in ("uefi", "vendor_firmware", "unclassified", "packaged_firmware") if "GAP" in st[k] or "ATTENTION" in st[k]]
    cov["status"] = "GAP" if gaps else "OK"
    if "ATTENTION" in st["uefi"]:
        cov["status"] = "ATTENTION"      # 有 UEFI 映像與原始碼不一致：不折進 GAP
    if total == 0:
        cov["status"] = "GAP"
    if tee_src is not None:
        cov["tee_source"] = {"present": True, "status": tee_src.get("status"), "versions": tee_src.get("versions"),
                             "image_check": {k: (tee_src.get("image_check") or {}).get(k) for k in ("status", "counts", "detail")}}
    cov["gap_classes"] = gaps
    cov["detail"] = (f"{total} bootloader inventory entries: " + ", ".join(f"{k} {counts[k]}" for k in CLASS_ORDER if counts[k])
                     + f"; rootfs bootloader capsules {len(caps)}; no component-level scan for vendor firmware ({counts['vendor_firmware']}) "
                       f"and unclassified files ({counts['unclassified']}); packaged firmware not unpacked ({counts['packaged_firmware']})")
    if total == 0:
        cov["detail"] = "no bootloader entries in the inventory: nothing was assessed"
    return cov


def build_not_assessed(variant, platform):
    """沒有定義開機鏈的平台（例如 Rockchip）：不分類，明講 NOT_ASSESSED。"""
    return {"schema": SCHEMA, "variant": variant, "status": "NOT_ASSESSED", "platform": platform, "platform_not_defined": True,
            "detail": "boot chain not defined for this platform: boot firmware coverage was not assessed (no classification)",
            "total": 0, "counts": dict.fromkeys(CLASS_ORDER, 0), "counts_add_up": True, "items": [], "rootfs_capsules": [],
            "extra_deliverables": []}


# ---------------------------------------------------------------- Raspberry Pi（原始磁碟映像）

RPI_PLATFORM = "raspberrypi"
RPI_ORDER = ("vendor_firmware", "kernel", "data", "unclassified", "not_firmware", "not_file")
RPI_CLASS_TEXT = {
    "vendor_firmware": "Raspberry Pi GPU firmware (closed source: start*.elf, fixup*.dat, bootcode.bin)",
    "kernel": "Linux kernel images and initramfs", "data": "Device tree files (.dtb, .dtbo)",
    "unclassified": "Unclassified firmware-type files",
    "not_firmware": "Other files (configuration, text, licences)", "not_file": "Entries that are not regular files (links)"}
RPI_VENDOR = re.compile(r"^(start[a-z0-9_]*\.elf|fixup[a-z0-9_]*\.dat|bootcode\.bin)$")
COVER_RPI_VENDOR = ("closed-source Raspberry Pi VideoCore GPU firmware, no component-level scan; covered only by the vendor's release "
                    "notes, no security bulletins are matched (gap)")
COVER_RPI_KERNEL = ("kernel image or initramfs; not scanned by this firmware list; kernel vulnerabilities are assessed by the kernel "
                    "steps only where a kernel version and configuration are available (not assessed here)")
RPI_NOT_IN_IMAGE = [{"name": "Raspberry Pi 4 / 5 EEPROM bootloader (pieeprom, recovery.bin)", "status": "NOT_ASSESSED",
                     "note": "Lives in the board's EEPROM, not in the image: not inventoried, not scanned, not covered."}]


def classify_rpi(item):
    if not isinstance(item, dict) or item.get("type") != "file":
        return "not_file", None
    path = str(item.get("path", ""))
    name = path.rsplit("/", 1)[-1].lower()
    if name.startswith(NOT_FW_PREFIX):
        return "not_firmware", None
    if RPI_VENDOR.match(name):
        return "vendor_firmware", "Raspberry Pi VideoCore GPU firmware"
    if path.startswith("kernel/") or re.match(r"^(kernel[a-z0-9_.+-]*\.img|initramfs[a-z0-9_.+-]*)$", name):
        return "kernel", None
    if name.endswith((".dtb", ".dtbo")):
        return "data", None
    if name.endswith(FW_EXT):
        return "unclassified", None
    return "not_firmware", None


def build_coverage_rpi(inv, variant):
    """Raspberry Pi 的原始磁碟映像：boot 分割區的檔案（bootloader/）加 kernel/ 的檔案；EEPROM 開機程式不在映像裡，列為沒有涵蓋。"""
    boot = [x for x in (inv.get("bootloader") or []) if isinstance(x, dict)]
    boot += [x for x in (inv.get("outside_rootfs") or []) if isinstance(x, dict) and str(x.get("path", "")).startswith("kernel/")]
    counts, items = dict.fromkeys(RPI_ORDER, 0), []
    cover = {"vendor_firmware": ("GAP", COVER_RPI_VENDOR), "kernel": ("NOT_ASSESSED", COVER_RPI_KERNEL),
             "data": ("NOT_ASSESSED", COVER_DATA), "unclassified": ("GAP", COVER_UNCL), "not_firmware": ("INFO", COVER_NOTFW),
             "not_file": ("INFO", COVER_NOTFILE)}
    for x in boot:
        cls, lab = classify_rpi(x)
        counts[cls] += 1
        st, text = cover[cls]
        it = {"path": x.get("path"), "class": cls, "sha256": x.get("sha256"), "status": st, "coverage": text}
        if lab:
            it["label"] = lab
        items.append(it)
    total = len(boot)
    gaps = [k for k in ("vendor_firmware", "unclassified") if counts[k]]
    cov = {"schema": SCHEMA, "variant": variant, "platform": RPI_PLATFORM, "total": total, "counts": counts,
           "counts_add_up": sum(counts.values()) == total, "class_text": RPI_CLASS_TEXT,
           "class_status": {k: sorted({i["status"] for i in items if i["class"] == k}) for k in RPI_ORDER},
           "not_in_image": RPI_NOT_IN_IMAGE, "gap_classes": gaps, "rootfs_capsules": [], "extra_deliverables": [], "items": items,
           "status": "GAP" if gaps or total == 0 else "OK"}
    cov["detail"] = (f"{total} boot partition and kernel entries: " + ", ".join(f"{k} {counts[k]}" for k in RPI_ORDER if counts[k])
                     + "; closed-source GPU firmware has no component-level scan (gap); the Raspberry Pi 4/5 EEPROM bootloader is not in the "
                       "image and is not covered")
    if total == 0:
        cov["detail"] = "no boot partition entries in the inventory: nothing was assessed"
    return cov


def markdown_rpi(cov):
    c = cov["counts"]
    L = [f"## Bootloader 與韌體涵蓋（{cov.get('variant') or ''}，Raspberry Pi 磁碟映像）", "",
         f"- 狀態：{cov['status']}。boot 分割區與 kernel 共 {cov['total']} 筆；各類相加 {'= 總數' if cov['counts_add_up'] else '≠ 總數（要查）'}。", "",
         "| 類別 | 數量 | 涵蓋 |", "|---|---|---|",
         f"| 閉源 GPU 韌體（start*.elf、fixup*.dat、bootcode.bin） | {c['vendor_firmware']} | 沒有成分層級掃描，只能對照廠商發行說明，沒有安全公告可比對 → GAP |",
         f"| kernel 與 initramfs | {c['kernel']} | 這份清單不掃；核心弱點在核心的步驟處理 → NOT_ASSESSED |",
         f"| 裝置樹（.dtb、.dtbo） | {c['data']} | 不做弱點掃描 |",
         f"| 未分類 | {c['unclassified']} | 沒有掃描 → GAP |",
         f"| 其他（設定、文字、授權） | {c['not_firmware']} | 不在涵蓋範圍 |",
         f"| 非一般檔案 | {c['not_file']} | 不跟隨 |", "",
         "- Raspberry Pi 4／5 的 EEPROM 開機程式不在映像裡（在板子上）：沒有清點、沒有掃描、沒有涵蓋（NOT_ASSESSED）。"]
    return "\n".join(L) + "\n"


def check_line(check):
    """uefi-binary-check.json → 一行英文（UEFI 列的證據、sbom.md）；沒有路徑與使用者名稱。"""
    cnt = check.get("counts") or {}
    return ("Flashed UEFI images compared with the scanned UEFI source: "
            f"consistent with being built from this source version {cnt.get('MATCH', 0)}, different {cnt.get('MISMATCH', 0)}, "
            f"not assessed {cnt.get('NOT_ASSESSED', 0)} (version string and embedded source paths; not a bit-for-bit comparison).")


def customer_text(cov):
    """客戶版文字（英文、中性）：沒有路徑、使用者名稱、建置機器資訊。"""
    if cov.get("platform") == RPI_PLATFORM:
        c, n = cov["counts"], cov["total"]
        rows = [["Raspberry Pi GPU firmware (closed source)", c["vendor_firmware"], "No component-level scan. Covered only by the vendor's release notes; no security bulletins are matched (gap)."],
                ["Kernel images and initramfs", c["kernel"], "Not scanned by this list (not assessed here)."],
                ["Device tree files", c["data"], "Not vulnerability-scanned."],
                ["Unclassified firmware-type files", c["unclassified"], "File name pattern not recognised; no component-level scan (gap)."],
                ["Other files (configuration, text, licences)", c["not_firmware"] + c["not_file"], "Not firmware; not part of this list."]]
        out = [f"The disk image's boot partition and kernel folder list {n} entries. Coverage by class (the counts add up to {n}):", "",
               "| Class | Files | Coverage |", "|---|---|---|"] + [f"| {a} | {b} | {t} |" for a, b, t in rows]
        out += ["", "The Raspberry Pi 4 and 5 boot from an EEPROM on the board. It is not part of the image, so it was not inventoried "
                    "or scanned and is not covered by this assessment."]
        return "\n".join(out)
    if cov.get("platform_not_defined"):
        return ("Boot firmware coverage: NOT_ASSESSED. The boot chain is not defined for this platform, so the boot firmware "
                "(bootloader and early boot stages) was not classified or scanned. This is not a statement that it has no vulnerabilities.")
    c, n = cov["counts"], cov["total"]
    u = cov["uefi_source"]
    bc = u["build_check"]
    if not u["present"]:
        uefi = "UEFI source was not provided: the bundled libraries of the UEFI images are not scanned (gap)."
    elif bc["present"] and bc.get("counts"):
        k = bc["counts"]
        uefi = ("Scanned from the UEFI source tree supplied for this build. Images consistent with being built from that source "
                f"version (version string and embedded source paths; not a bit-for-bit comparison): consistent {k.get('MATCH', 0)}, "
                f"different {k.get('MISMATCH', 0)}, not assessed {k.get('NOT_ASSESSED', 0)}.")
    else:
        uefi = "Scanned from the UEFI source tree supplied for this build. The check that the images were built from that source was not run."
    rows = [["UEFI images", c["uefi"], uefi],
            ["Vendor closed-source firmware", c["vendor_firmware"],
             "No component-level scan (closed source). Covered only by the vendor's security bulletins, matched on the Jetson Linux version (gap)."],
            ["Data files (.bct, .dtb, .dtbo)", c["data"], "Not vulnerability-scanned."],
            ["Unclassified firmware-type files", c["unclassified"], "File name pattern not recognised; no component-level scan (gap)."],
            ["Packaged firmware (.deb, .pkg)", c["packaged_firmware"], "Package content is not unpacked or scanned (gap)."],
            ["Other files (scripts, configuration, text, tools)", c["not_firmware"] + c["not_file"],
             "Not firmware; not part of this list."]]
    out = [f"The flash package inventory lists {n} entries in its bootloader folder. Coverage by class (the counts add up to {n}):", "",
           "| Class | Files | Coverage |", "|---|---|---|"]
    out += [f"| {a} | {b} | {t} |" for a, b, t in rows]
    if cov.get("tee_source"):
        t = cov["tee_source"]
        v = t.get("versions") or {}
        out += ["", "The OP-TEE and TF-A in the tos-optee images are scanned from the vendor public source supplied for this build "
                    f"(TF-A {v.get('tfa') or 'unknown'}, OP-TEE {v.get('optee') or 'unknown'}, Mbed TLS {v.get('mbedtls') or 'unknown'}); "
                    f"image comparison (consistency, not a bit-for-bit comparison): {(t.get('image_check') or {}).get('detail') or 'not run'}."]
    caps = cov["rootfs_capsules"]
    if caps:
        out += ["", f"The root file system also contains {len(caps)} vendor generic bootloader capsule(s) "
                    "(OTA package folder, files named TEGRA_BL_*.Cap), listed here as shipped: "
                + ", ".join(f"{x['soc_folder']}/{x['file']}" for x in caps)
                + ". Their content is not scanned. Whether each one matches this product's board configuration is not assessed."]
    ex = cov.get("extra_deliverables") or []
    if ex:
        out += ["", f"Firmware delivered separately from the flash package ({len(ex)}): " + "; ".join(
            f"{x['name']} (sha256 {str(x['sha256'])[:16]}…, version {x['version'] or 'unknown'}, not scanned)" for x in ex) + "."]
    return "\n".join(out)


def markdown_zh(cov):
    """內部報告用的簡短段落（中文）。"""
    if cov.get("platform") == RPI_PLATFORM:
        return markdown_rpi(cov)
    if cov.get("platform_not_defined"):
        return (f"## Bootloader 與韌體涵蓋（{cov.get('variant') or ''}）\n\n"
                "- 狀態：NOT_ASSESSED。這個平台沒有定義開機鏈（boot chain not defined for this platform），沒有做任何分類，也沒有掃描開機韌體。\n"
                "- 這不是「沒有開機韌體的問題」：只是沒有評估。\n")
    c = cov["counts"]
    L = [f"## Bootloader 與韌體涵蓋（{cov.get('variant') or ''}）", "",
         f"- 狀態：{cov['status']}。bootloader 清點共 {cov['total']} 筆；各類相加 {'= 總數' if cov['counts_add_up'] else '≠ 總數（要查）'}。",
         "- 涵蓋說明（每一筆見 bootloader-coverage.json）：", "",
         "| 類別 | 數量 | 涵蓋 |", "|---|---|---|",
         f"| UEFI 映像 | {c['uefi']} | 有 UEFI 原始碼結果時「從 UEFI 原始碼掃描」，並附映像與原始碼的一致性檢查；沒有原始碼 → GAP |",
         f"| NVIDIA 閉源韌體（MB1、MB2、BPMP、TOS/OP-TEE/ATF、SPE、PSC、SC7 等） | {c['vendor_firmware']} | "
         "沒有成分層級掃描，只靠 NVIDIA 安全公告依 L4T 版本對照 → GAP |",
         f"| 資料檔（.bct、.dtb、.dtbo） | {c['data']} | 不做弱點掃描 |",
         f"| 未分類（韌體副檔名但檔名樣式不認得） | {c['unclassified']} | 沒有掃描 → GAP |",
         f"| 打包的韌體（.deb、.pkg） | {c['packaged_firmware']} | 套件內容沒有解開、沒有掃描 → GAP |",
         f"| 非韌體（腳本、設定、文字、工具） | {c['not_firmware']} | 不在涵蓋範圍 |",
         f"| 非一般檔案（連結） | {c['not_file']} | 不跟隨 |", ""]
    u = cov["uefi_source"]
    bc = u["build_check"]
    if not u["present"]:
        L.append("- UEFI：這次沒有 UEFI 原始碼結果，UEFI 映像標 GAP。")
    elif bc["present"]:
        L.append(f"- UEFI 映像與原始碼的一致性（用語：與用這份原始碼建置一致，不是逐位元相同）：{bc.get('detail')}（狀態 {bc.get('status')}）。")
        bad = [i for i in cov["items"] if i["class"] == "uefi" and i.get("build_check") not in ("MATCH",)]
        for i in bad[:10]:
            L.append(f"  - {i['path']}：{i.get('build_check')}；{i.get('build_check_detail') or ''}")
    else:
        L.append("- UEFI：有原始碼結果，但沒有做映像與原始碼的一致性檢查（NOT_RUN）。")
    if cov.get("tee_source"):
        t = cov["tee_source"]
        L.append(f"- tos-optee 映像：從廠商公開原始碼掃描（TF-A {(t.get('versions') or {}).get('tfa') or '未知'}、OP-TEE {(t.get('versions') or {}).get('optee') or '未知'}、"
                 f"Mbed TLS {(t.get('versions') or {}).get('mbedtls') or '未知'}）；映像與原始碼的一致性（不是逐位元相同）：{(t.get('image_check') or {}).get('detail')}（狀態 {t.get('status')}）。")
    caps = cov["rootfs_capsules"]
    if caps:
        L += ["", f"### rootfs 裡的廠商通用 bootloader capsule（{len(caps)} 個；照實列出）", "",
              "| 路徑 | module id | 所屬 dpkg 套件 | sha256 | 與本產品板子設定是否相符 |", "|---|---|---|---|---|"]
        for x in caps:
            L.append(f"| {x['path']} | {x['module_id']}（{x['module']}） | {x['dpkg_package']} | {(x['sha256'] or '—')[:16]}… | NOT_ASSESSED |")
        L.append("")
        L.append("- 這些檔案是 rootfs 內容的一部分，內容沒有掃描；dpkg 檔案清單沒有記錄時所屬套件寫 unknown，不猜。")
    ex = cov.get("extra_deliverables") or []
    if ex:
        L += ["", f"### 另外交付的韌體（{len(ex)} 個）", ""]
        for x in ex:
            L.append(f"- {x['name']}：{x['status']}；{x['note']}")
    return "\n".join(L) + "\n"


def run_coverage(result, variant, check_path=None, tee_path=None, platform=None):
    result = Path(result)
    inv = load_json(result / "flash-inventory.json")
    if not isinstance(inv, dict):
        raise Fail("flash-inventory.json is missing or unreadable")
    vd = result / variant
    if platform == RPI_PLATFORM:
        cov = build_coverage_rpi(inv, variant)
        write_json_atomic(vd / "bootloader-coverage.json", cov)
        (vd / "bootloader-coverage.md").write_text(markdown_zh(cov), encoding="utf-8")
        return cov
    sbom = load_json(vd / "scan" / "sbom" / "sbom.cdx.json")
    owners = load_json(vd / "pkgdb" / "dpkg-file-lists.json")
    caps = rootfs_capsules(sbom, owners if isinstance(owners, dict) else None)
    us = load_json(vd / "uefi-source" / "uefi-source.json")
    check = load_json(check_path or result / "uefi-binary-check.json")
    tee = load_json(tee_path or vd / "tee-source" / "tee-source.json")
    cov = build_coverage(inv, caps, us if isinstance(us, dict) else None, check if isinstance(check, dict) else None, variant,
                         tee if isinstance(tee, dict) and tee.get("schema") == "sca-center-tee-source/1" else None)
    cov["rootfs_sbom_present"] = isinstance(sbom, dict)
    if not isinstance(sbom, dict):
        cov["status"] = "GAP"
        cov["detail"] += "; the rootfs SBOM was not available, so rootfs bootloader capsules were not looked for"
    write_json_atomic(vd / "bootloader-coverage.json", cov)
    (vd / "bootloader-coverage.md").write_text(markdown_zh(cov), encoding="utf-8")
    return cov


def run_not_assessed(result, variant, platform):
    cov = build_not_assessed(variant, platform)
    vd = Path(result) / variant
    vd.mkdir(parents=True, exist_ok=True)
    write_json_atomic(vd / "bootloader-coverage.json", cov)
    (vd / "bootloader-coverage.md").write_text(markdown_zh(cov), encoding="utf-8")
    return cov


# ---------------------------------------------------------------- 指令列

def line(stage, st, detail):
    d = detail.replace("\t", " ").replace("\n", " ")
    print(f"{stage}\t{st}\t{d[:470]}")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0], allow_abbrev=False)
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("uefi-check")
    a.add_argument("--inventory", required=True)
    g = a.add_mutually_exclusive_group(required=True)
    g.add_argument("--archive")
    g.add_argument("--dir")
    a.add_argument("--tree", required=True)
    a.add_argument("--uefi-json")
    a.add_argument("--platform-dsc", action="append", default=[])
    a.add_argument("--platform-defines", action="append", default=[])
    a.add_argument("--out", required=True)
    a = sub.add_parser("extra")
    a.add_argument("--inventory", required=True)
    a.add_argument("--deliverable", action="append", required=True)
    a.add_argument("--name", required=True)
    a.add_argument("--version", required=True)
    a.add_argument("--l4t")
    a.add_argument("--tree")
    a.add_argument("--uefi-json")
    a.add_argument("--out", required=True)
    a = sub.add_parser("coverage")
    a.add_argument("--result", required=True)
    a.add_argument("--variant", required=True)
    a.add_argument("--check")
    a.add_argument("--tee", help="tee-source.json to use (default <result>/<variant>/tee-source/tee-source.json); pass the one cra_report.py uses")
    a.add_argument("--not-assessed", metavar="PLATFORM")
    a.add_argument("--platform", choices=[RPI_PLATFORM])
    try:
        args = ap.parse_args(argv)
    except SystemExit as e:
        return 64 if e.code else 0
    stage = {"uefi-check": "X-uefi-binary", "extra": "X-extra-deliverable", "coverage": "X-bootloader-coverage"}[args.cmd]
    try:
        if args.cmd == "uefi-check":
            inv = load_json(args.inventory)
            if not isinstance(inv, dict):
                raise Fail("flash-inventory.json is missing or unreadable")
            if not os.path.isdir(args.tree):
                raise Fail("--tree is not a folder")
            res = run_uefi_check(inv, args.tree, args.archive, args.dir, load_json(args.uefi_json) if args.uefi_json else None, args.platform_dsc, args.platform_defines)
            write_json_atomic(args.out, res)
            line(stage, res["status"], res["detail"])
            return {"OK": 0, "ATTENTION": 2, "GAP": 2}.get(res["status"], 1)
        if args.cmd == "extra":
            inv = load_json(args.inventory)
            if not isinstance(inv, dict):
                raise Fail("flash-inventory.json is missing or unreadable")
            if args.tree and not os.path.isdir(args.tree):
                raise Fail("--tree is not a folder")
            recs, notes = run_extra(args.inventory, args.deliverable, args.name, args.version, args.l4t, args.tree,
                                    load_json(args.uefi_json) if args.uefi_json else None)
            inv["extra_deliverables"] = recs
            inv["extra_deliverables_note"] = ("Firmware delivered separately from the flash package (option --extra-deliverable): name, size, hashes, "
                                              "readable version string, paired flash package. Recorded only; not scanned.")
            write_json_atomic(args.inventory, inv)
            write_json_atomic(args.out, {"schema": "sca-center-extra-deliverables/1", "notes": notes, "extra_deliverables": recs})
            st = "ATTENTION" if any(r["status"] == "ATTENTION" for r in recs) else "GAP" if any(r["status"] == "NOT_ASSESSED" for r in recs) else "OK"
            line(stage, st, f"{len(recs)} extra deliverable(s): " + "; ".join(f"{r['name']}: {r['note']}" for r in recs))
            return 0 if st == "OK" else 2
        if args.not_assessed:
            cov = run_not_assessed(args.result, args.variant, args.not_assessed)
            line(stage, cov["status"], cov["detail"])
            return 2
        cov = run_coverage(args.result, args.variant, args.check, args.tee, args.platform)
        line(stage, cov["status"], cov["detail"])
        return 0 if cov["status"] == "OK" else 2
    except Fail as e:
        line(stage, "FAIL", str(e))
        return 1
    except Exception as e:      # noqa: BLE001  結構意外：記 FAIL，不印 traceback
        line(stage, "FAIL", f"bootloader_coverage.py could not complete ({type(e).__name__}: {str(e)[:100]})")
        return 1


if __name__ == "__main__":
    sys.exit(main())
