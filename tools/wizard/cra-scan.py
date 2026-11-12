#!/usr/bin/env python3
"""CRA 掃描精靈：依序輸入「刷機包」和「SourceCode 資料夾」，自動完成整個流程。

用法（用自己的帳號，不要 sudo）：
  python3 -I tools/wizard/cra-scan.py [--site-config 本機設定檔.json]
  （站台設定：路徑、工具位置等見 tools/wizard/README.md 與 wizard.example.json）
  （非互動、測試用：--archive A [--source S（不給＝沒有原始碼，核心原始碼判斷標 GAP；不去目前資料夾找）] [--name N --version V --config C --role both|manufacturer|supplier --yes --plan-only]）

流程：核對 MD5 → 安全解開原始碼（不執行裡面任何東西）→ 自動找核心原始碼、UEFI、NVIDIA 樹外模組、核心建置紀錄
     → 列出計畫請你確認 → 取工具（預設目前 checkout 的 HEAD，用 git archive 取乾淨副本；--tools-rev 或 DUMPLING_TOOLS_REV 可指定其他版本）→ 掃描 → 套用規則產生 CRA 文件（製造商／供應商）→ 整理成報告（工具有 report_package.py 時）
輸出：<站台設定的 outroot>/<產品>-<版本>-<日期時間>/（每次新資料夾，舊的不動）
"""
import argparse, hashlib, json, os, re, shutil, subprocess, sys, tarfile, zipfile, zlib, datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_SITE_CONFIG = Path("~/.config/sca-center/wizard.json")
# 站台設定檔（JSON）的鍵；每一項都有預設值，路徑類可以用 ~。說明見 tools/wizard/README.md
SITE_KEYS = {"repo", "root", "outroot", "python", "tools_bin", "pilot_env", "grype_seed", "grype_cache", "stable_git", "rules_template", "upstream"}
# 沒有產品設定包時可套用的通用處理規則：rules_template 指向一份 vex-rules.json（通用規則，不含人工判定、不含產品專屬規則）
PRODUCT_SPECIFIC_RULES = {"R9m"}
REPO = ROOT = OUTROOT = GRYPE_CACHE = None
PY = TOOLS_BIN = None
PILOT_ENV = GRYPE_SEED = RULES_TEMPLATE = None
STABLE_GIT = {}
UPSTREAM = {}      # 上游基準：{組名: {"public_sources": 路徑, "bsp": 路徑, ...}}，輸入清單用組名＋鍵引用
INPUT_KINDS = {"flash_package", "source_archive", "build_record", "extra_deliverable", "upstream_source", "upstream_bsp",
               "upstream_uefi", "vendor_bulletin", "board_test", "product_config", "other"}
PLATFORMS_DIR = HERE / "platforms"


def _p(v):
    return Path(str(v)).expanduser()


def load_site_config(path=None):
    """讀站台設定。順序：--site-config → 環境變數 SCA_WIZARD_CONFIG → ~/.config/sca-center/wizard.json（可以不存在，全用預設值）。"""
    global REPO, ROOT, OUTROOT, PY, TOOLS_BIN, PILOT_ENV, GRYPE_SEED, GRYPE_CACHE, STABLE_GIT, RULES_TEMPLATE, UPSTREAM
    explicit = path or os.environ.get("SCA_WIZARD_CONFIG")
    cf = _p(explicit) if explicit else DEFAULT_SITE_CONFIG.expanduser()
    c = {}
    if cf.exists():
        try:
            c = json.loads(cf.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            sys.exit(f"錯誤：站台設定檔 {cf} 讀不了或不是 JSON（{e}）")
        if not isinstance(c, dict):
            sys.exit(f"錯誤：站台設定檔 {cf} 最外層必須是物件")
        bad = sorted(k for k in c if k not in SITE_KEYS and not k.startswith("_"))
        if bad:
            sys.exit(f"錯誤：站台設定檔 {cf} 有不認得的鍵：{', '.join(bad)}（可用：{', '.join(sorted(SITE_KEYS))}）")
    elif explicit:
        sys.exit(f"錯誤：找不到站台設定檔 {cf}")
    REPO = _p(c["repo"]) if c.get("repo") else HERE.parent.parent
    ROOT = _p(c["root"]) if c.get("root") else Path("~/cra-scan").expanduser()
    OUTROOT = _p(c["outroot"]) if c.get("outroot") else ROOT / "輸出"
    PY = str(c["python"]) if c.get("python") else sys.executable
    TOOLS_BIN = str(_p(c["tools_bin"])) if c.get("tools_bin") else None
    PILOT_ENV = _p(c["pilot_env"]) if c.get("pilot_env") else None
    GRYPE_SEED = _p(c["grype_seed"]) if c.get("grype_seed") else None
    GRYPE_CACHE = _p(c["grype_cache"]) if c.get("grype_cache") else ROOT / "grype-db"
    STABLE_GIT = {str(k): _p(v) for k, v in (c.get("stable_git") or {}).items()}
    RULES_TEMPLATE = _p(c["rules_template"]) if c.get("rules_template") else None
    up = c.get("upstream") or {}
    if not isinstance(up, dict) or any(not isinstance(v, dict) for k, v in up.items() if not str(k).startswith("_")):
        sys.exit(f"錯誤：站台設定檔 {cf} 的 upstream 必須是 {{組名: {{鍵: 路徑}}}}")
    UPSTREAM = {str(k): {str(kk): _p(vv) for kk, vv in v.items() if not str(kk).startswith("_")}
                for k, v in up.items() if not str(k).startswith("_")}
    return cf


def load_inputs_manifest(path):
    """讀輸入清單（見 README「輸入清單」）。格式錯誤直接停止並說明哪一項。"""
    try:
        d = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        sys.exit(f"錯誤：輸入清單 {path} 讀不了或不是 JSON（{e}）")
    if not isinstance(d, dict) or not isinstance(d.get("inputs"), list):
        sys.exit(f"錯誤：輸入清單 {path} 最外層要是物件且有 inputs 清單")
    seen = set()
    for i, it in enumerate(d["inputs"], 1):
        if not isinstance(it, dict) or not it.get("id") or not it.get("label"):
            sys.exit(f"錯誤：輸入清單 {path} 第 {i} 項缺 id 或 label")
        if it["id"] in seen:
            sys.exit(f"錯誤：輸入清單 {path} 的 id 重複：{it['id']}")
        seen.add(it["id"])
        if it.get("kind", "other") not in INPUT_KINDS:
            sys.exit(f"錯誤：輸入清單 {path} 的 {it['id']} kind 不認得：{it.get('kind')}（可用：{', '.join(sorted(INPUT_KINDS))}）")
        loc = it.get("locate")
        if not isinstance(loc, dict) or len({"plan", "glob", "upstream", "config_file", "manual"} & set(loc)) != 1:
            sys.exit(f"錯誤：輸入清單 {path} 的 {it['id']} locate 要剛好有 plan／glob／upstream／config_file／manual 其中一個")
        if "required" in it and not isinstance(it["required"], bool):
            sys.exit(f"錯誤：輸入清單 {path} 的 {it['id']} required 必須是 true 或 false（不是字串）")
        for k in ("plan", "glob", "upstream", "config_file", "companion"):
            if k in loc and (not isinstance(loc[k], str) or not loc[k].strip()):
                sys.exit(f"錯誤：輸入清單 {path} 的 {it['id']} locate.{k} 必須是非空字串")
        for k in ("glob", "config_file"):
            if k in loc and (Path(loc[k]).is_absolute() or ".." in Path(loc[k]).parts or loc[k].startswith(("/", "~"))):
                sys.exit(f"錯誤：輸入清單 {path} 的 {it['id']} locate.{k} 不可是絕對路徑、不可含 ..（只能找來源資料夾／設定包裡面）")
        if "base" in loc and loc["base"] not in ("source", "flash"):
            sys.exit(f"錯誤：輸入清單 {path} 的 {it['id']} locate.base 只能是 source 或 flash")
        if "manual" in loc and loc["manual"] is not True:
            sys.exit(f"錯誤：輸入清單 {path} 的 {it['id']} locate.manual 必須是 true")
        for k in ("note", "affects", "provider"):
            if k in it and not isinstance(it[k], str):
                sys.exit(f"錯誤：輸入清單 {path} 的 {it['id']} {k} 必須是字串")
    return d


def resolve_upstream(manifest):
    """→ (組名, {鍵: Path})；清單沒有 upstream_set 或站台設定沒有這一組時，字典是空的。"""
    name = (manifest or {}).get("upstream_set")
    up = dict(UPSTREAM.get(name) or {}) if name else {}
    if name and "public_sources_dir" not in up and up.get("public_sources"):
        guess = up["public_sources"].parent / "extract"      # 沒設定時：public_sources 旁邊的 extract/（解開過的樹）；不存在就不填
        if guess.is_dir() and not guess.is_symlink():
            up["public_sources_dir"] = guess
    return name, up


def find_tee_tree(d, maxdepth=5, limit=200000):
    """--tee-source 要的資料夾裡要有 TF-A（arm-trusted-firmware*）與 OP-TEE（optee_os）的原始碼樹。只走資料夾，不跟隨符號連結。
    → (找到, 缺的說明)；巢狀 tarball 不會自動解開（要先解開）。"""
    d = Path(d)
    if not d.is_dir() or d.is_symlink():
        return False, f"{d} 不是資料夾"
    tfa = optee = False
    n = 0
    for root, dirs, files in os.walk(d):
        n += len(dirs) + len(files)
        if n > limit or len(Path(root).relative_to(d).parts) >= maxdepth:
            dirs[:] = []
        for x in dirs:
            if x == "optee_os" and (Path(root) / x / "mk" / "config.mk").is_file():
                optee = True
            if x.startswith("arm-trusted-firmware") and (Path(root) / x / "Makefile").is_file():
                tfa = True
        if tfa and optee:
            return True, ""
    miss = [m for m, ok in (("TF-A（arm-trusted-firmware*/Makefile）", tfa), ("OP-TEE（optee_os/mk/config.mk）", optee)) if not ok]
    return False, f"{d} 裡找不到 " + "、".join(miss) + "（公開原始碼的 tarball 要先解開）"


UEFI_DEFINES_RE = re.compile(r"^(?:\./)?uefi/nvidia-config/([A-Za-z0-9][A-Za-z0-9._+-]*)/config\.dsc\.inc$")
UEFI_DEFINES_MAX = 4 << 20     # 單檔上限（Kconfig 產生的 .inc 只有幾 KB）
UEFI_DEFINES_MAX_FILES = 8
BUILD_RECORD_FLOOR = 256 << 20     # 建置紀錄解壓後總量上限 = max(下限, 壓縮檔大小 × 倍數)；超過就停（壓縮炸彈），UEFI 平台設定記 GAP
BUILD_RECORD_RATIO = 20


class _CapReader:
    """包住解壓後的串流，累計讀出的位元組，超過上限丟 OSError。"""

    def __init__(self, f, cap):
        self.f, self.cap, self.n = f, cap, 0

    def read(self, k=-1):
        k = 1 << 20 if k is None or k < 0 else min(k, 1 << 20)
        b = self.f.read(k)
        self.n += len(b)
        if self.n > self.cap:
            raise OSError(f"解壓後超過 {self.cap >> 20} MB 上限")
        return b


def extract_uefi_defines(br, dest, max_total=None):
    """從核心建置紀錄（pack-build-record.sh --uefi= 的 .tar.gz／.tgz／.tar，或解開的資料夾）取出 uefi/nvidia-config/*/config.dsc.inc。
    只讀一般檔案：連結（符號、硬）、裝置檔、超過單檔上限的檔案一律不收，各記一行原因；同一平台出現多次只採用最後一份（記錄）；
    整個壓縮檔解壓後的總量有上限（max_total，預設 max(256 MB, 壓縮檔 × 20)），超過 → 不採用任何一份（GAP）。
    → ([檔案路徑], [說明…])；沒有就是 ([], [原因])。"""
    br, notes, got = Path(br), [], {}
    if br.is_dir() and not br.is_symlink():
        root = br.resolve()
        base = br / "uefi" / "nvidia-config"
        if not base.is_dir() or base.is_symlink() or not base.resolve().is_relative_to(root):
            return [], ["建置紀錄資料夾裡沒有 uefi/nvidia-config/（或它是指到資料夾外面的連結）"]
        for d in sorted(base.iterdir())[:UEFI_DEFINES_MAX_FILES * 4]:
            f = d / "config.dsc.inc"
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", d.name) or d.is_symlink() or not d.is_dir():
                continue
            if f.is_symlink() or not f.is_file() or not f.resolve().is_relative_to(root):
                if f.exists() or f.is_symlink():
                    notes.append(f"{f.relative_to(br)} 不是一般檔案（或連結指到資料夾外面），不收")
            elif f.stat().st_size > UEFI_DEFINES_MAX:
                notes.append(f"{f.relative_to(br)} 超過 {UEFI_DEFINES_MAX >> 20} MB，不收")
            elif len(got) >= UEFI_DEFINES_MAX_FILES:
                notes.append(f"超過 {UEFI_DEFINES_MAX_FILES} 份，其餘不收")
                break
            else:
                got[d.name] = f
        return list(got.values()), notes or ([] if got else ["建置紀錄資料夾沒有 uefi/nvidia-config/*/config.dsc.inc"])
    if not br.is_file() or br.is_symlink() or not re.search(r"\.(tar\.gz|tgz|tar)$", br.name):
        return [], ["建置紀錄不是 .tar.gz／.tgz／.tar 檔或資料夾，沒有讀 UEFI 平台設定"]
    cap = max_total if max_total is not None else max(BUILD_RECORD_FLOOR, BUILD_RECORD_RATIO * br.stat().st_size)
    try:
        import gzip
        raw = open(br, "rb")
        try:
            src = gzip.GzipFile(fileobj=raw) if re.search(r"\.(tar\.gz|tgz)$", br.name) else raw
            with tarfile.open(fileobj=_CapReader(src, cap), mode="r|") as t:
                for m in t:
                    mm = UEFI_DEFINES_RE.match(m.name)
                    if not mm or ".." in Path(m.name).parts:
                        continue
                    if not m.isreg():
                        notes.append(f"{m.name} 不是一般檔案（連結或裝置檔），不收")
                        continue
                    if m.size > UEFI_DEFINES_MAX:
                        notes.append(f"{m.name} 超過 {UEFI_DEFINES_MAX >> 20} MB，不收")
                        continue
                    plat = mm.group(1)
                    if plat in got:
                        notes.append(f"{plat}/config.dsc.inc 在建置紀錄裡出現多次（重複成員），採用最後一份")
                    elif len(got) >= UEFI_DEFINES_MAX_FILES:
                        notes.append(f"超過 {UEFI_DEFINES_MAX_FILES} 份，其餘不收")
                        continue
                    out = Path(dest) / plat / "config.dsc.inc"
                    out.parent.mkdir(parents=True, exist_ok=True)
                    out.write_bytes(t.extractfile(m).read(UEFI_DEFINES_MAX + 1)[:UEFI_DEFINES_MAX])
                    got[plat] = out
        finally:
            raw.close()
    except OSError as e:
        return [], [f"建置紀錄讀取中止（{e}）：UEFI 平台設定記 GAP，不採用任何一份"]
    except (tarfile.TarError, EOFError, zlib.error) as e:
        return [], [f"建置紀錄讀不了（{type(e).__name__}）：沒有讀 UEFI 平台設定"]
    if not got and not notes:
        notes.append("建置紀錄裡沒有 uefi/nvidia-config/*/config.dsc.inc（打包時沒給 --uefi=）；UEFI 映像檢查的列維持 not_assessed")
    return list(got.values()), notes


def check_board_test_file(v):
    """板子結果檔（board-test-*.tar.gz、board-net-*.tar.gz）：要是一般檔案、不是連結。內容由 board_import.py 逐項驗證。"""
    p = Path(v)
    if p.is_symlink() or not p.is_file():
        return f"找不到這個檔案（或不是一般檔案）：{v}"
    if not re.match(r"board-(test|net)-.+\.tar\.gz$", p.name):
        return f"檔名不是 board-test-*.tar.gz 或 board-net-*.tar.gz：{p.name}"
    return None


def board_import_status(rc, log):
    """board-import.sh 的結果 → (狀態, 說明)。board_import.py 的退出碼：0＝OK、2＝匯入成功但有 ATTENTION／GAP（有發現事項）、1＝FAIL；
    狀態以它印的 `D-board-test<TAB>狀態<TAB>說明`（有 --kernel-modules-from 時還有 D-kernel-modules）為準，沒有狀態行才當 FAIL。"""
    parts, worst = [], None
    order = ["OK", "ATTENTION", "GAP", "FAIL"]
    for tag in ("D-board-test", "D-kernel-modules"):
        st, dt = step_line(log, tag)
        if st:
            parts.append(f"{tag} {st}" + (f"：{dt[:200]}" if dt and st != "OK" else ""))
            if st not in order:
                st = "FAIL"
            worst = st if worst is None or order.index(st) > order.index(worst) else worst
    if worst is None:
        return "FAIL", f"exit {rc}，沒有結果行（D-board-test），看 board-import.log"
    if rc == 1 and worst != "FAIL":
        worst = "FAIL"
    return worst, f"exit {rc}；" + "；".join(parts)


def merge_step_status(out, steps, inputs_check_name="inputs-check.json"):
    """把掃描前後各附加步驟的狀態併進 inputs-check.json 的 inputs（kind＝step），報告（report_package.py --inputs-check）才讀得到。
    steps：[{id, label, status(OK／ATTENTION／GAP／FAIL／NOT_RUN／found), note, affects}]。OK／ATTENTION 記 found（ATTENTION 把說明放 note）；
    GAP→gap、FAIL→fail、NOT_RUN→not_run。重複呼叫會先清掉舊的 step 項。檔案不存在時建一個只有 step 的。"""
    f = Path(out) / inputs_check_name
    try:
        d = json.loads(f.read_text(encoding="utf-8")) if f.exists() else {}
    except (OSError, ValueError):
        d = {}
    if not isinstance(d, dict) or not isinstance(d.get("inputs"), list):
        d = {"manifest": None, "inputs": [], "missing_required": [], "missing_optional": [], "unconfirmed_required": []}
    d["inputs"] = [r for r in d["inputs"] if not (isinstance(r, dict) and r.get("kind") == "step")]
    for st in steps:
        s0 = str(st["status"]).upper()
        status = {"OK": "found", "ATTENTION": "found", "FOUND": "found", "GAP": "gap", "FAIL": "fail", "NOT_RUN": "not_run"}.get(s0, "gap")
        d["inputs"].append({"id": "step:" + st["id"], "label": st["label"], "provider": "", "required": False, "kind": "step", "status": status,
                            "path": None, "affects": st.get("affects", ""), "note": st.get("note", ""), "step_status": s0})
    f.write_text(json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")


def step_line(log, prefix):
    """工具 stdout 裡 `A0-xxx<TAB>狀態<TAB>說明` 那一行 → (狀態, 說明)；沒有 → (None, None)。"""
    try:
        for ln in Path(log).read_text(encoding="utf-8", errors="replace").splitlines():
            if ln.startswith(prefix + "\t"):
                parts = ln.split("\t", 2)
                return parts[1], (parts[2] if len(parts) > 2 else "")
    except OSError:
        pass
    return None, None


def check_inputs(manifest, plan, source_dir, cfg_dir, up_name, up):
    """逐項檢查輸入清單 → 結果列表。status：found／missing／unchecked（需要人確認，不自動判斷）。"""
    res = []
    for it in manifest["inputs"]:
        loc, found, note = it["locate"], None, ""
        if it.get("kind") == "board_test" and "manual" in loc:
            loc = {"plan": "board_test"}       # 舊清單把實機測試標成 manual：現在精靈有 --board-test，直接依 plan 判斷 found／missing
        if "plan" in loc:
            v = plan.get(loc["plan"])
            found = (", ".join(v) if isinstance(v, list) else v) or None
            if found and loc.get("companion"):
                first = (v[0] if isinstance(v, list) else v)
                if not Path(str(first) + loc["companion"]).exists():
                    note = f"沒有 {loc['companion']} 檔，無法核對"
        elif "glob" in loc:
            base = source_dir if loc.get("base", "source") == "source" else Path(plan["archive"]).parent
            hits = []
            if base and base.is_dir():
                root = base.resolve()
                for h in sorted(base.glob(loc["glob"])):    # 只認來源資料夾裡面的一般檔案／資料夾：跳過符號連結與解析後跑到外面的
                    if not h.is_symlink() and h.resolve().is_relative_to(root):
                        hits.append(h)
            found = str(hits[0]) if hits else None
        elif "upstream" in loc:
            pth = up.get(loc["upstream"])
            if not up_name:
                note = "清單沒有 upstream_set"
            elif pth is None:
                note = f"站台設定 upstream.{up_name}.{loc['upstream']} 沒設定"
            elif not pth.exists():
                note = f"站台設定指到 {pth}，但檔案不存在"
            else:
                found = str(pth)
        elif "config_file" in loc:
            f = cfg_dir / loc["config_file"] if cfg_dir else None
            found = str(f) if f and f.exists() and not f.is_symlink() and f.resolve().is_relative_to(cfg_dir.resolve()) else None
            if not cfg_dir:
                note = "沒有給產品設定包"
        else:
            note = str(loc.get("note") or "")
        status = "unchecked" if "manual" in loc else ("found" if found else "missing")
        extra = it.get("note", "") if status != "found" else ""
        res.append({"id": it["id"], "label": it["label"], "provider": it.get("provider", ""), "required": bool(it.get("required")),
                    "kind": it.get("kind", "other"), "status": status, "path": found, "affects": it.get("affects", ""),
                    "note": " ".join(x for x in (note, extra) if x)})
    return res


def print_checklist(manifest, res):
    say(f"\n== 這個產品的輸入清單（{manifest.get('platform', '?')}" + ("，草稿" if manifest.get("draft") else "") + "）==")
    for r in res:
        tag = "必要" if r["required"] else "選用"
        who = f"，由 {r['provider']} 提供" if r["provider"] else ""
        if r["status"] == "found":
            say(f"  ✓ {r['label']}（{tag}）：{r['path']}" + (f"　※{r['note']}" if r["note"] else ""))
        elif r["status"] == "unchecked":
            say(f"  － {r['label']}（{tag}{who}）：無法自動檢查" + ("，【未確認】請人工確認" if r["required"] else "") + (f"　{r['note']}" if r["note"] else ""))
        else:
            say(f"  ✗ {r['label']}（{tag}{who}）：缺少" + (f"（{r['note']}）" if r["note"] else "")
                + (f"\n      影響：{r['affects']}" if r["affects"] else ""))


JETSON_OOT = ["nvidia-oot", "nvgpu", "nvdisplay", "hwpm", "nvethernetrm", "unifiedgpudisp/kernel-open"]
ARCHIVE_EXT = (".tbz2", ".tar.bz2", ".tar.gz", ".tgz", ".tar.xz", ".txz", ".zip", ".tar")


def say(s=""):
    print(s, flush=True)


def ask(prompt, default=None, check=None, args_value=None, noninteractive=False):
    if args_value is not None:
        v = args_value
    elif noninteractive:
        v = default or ""
    else:
        d = f"［預設：{default}］" if default else ""
        v = input(f"{prompt}{d}：").strip() or (default or "")
    v = v.strip().strip("'\"")
    if check:
        err = check(v)
        if err:
            if args_value is not None or noninteractive:
                sys.exit(f"錯誤：{err}")
            say(f"  → {err}")
            return ask(prompt, default, check)
    return v


def md5_check(path):
    m = Path(str(path) + ".md5")
    if not m.exists():
        return "沒有 .md5 檔，無法核對（報告會記 NOT_RUN）"
    want = m.read_text(errors="replace").split()[0].lower() if m.read_text(errors="replace").split() else ""
    h = hashlib.md5()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 22), b""):
            h.update(b)
    if h.hexdigest() != want:
        sys.exit(f"錯誤：{path.name} 的 MD5 和 .md5 檔不同（{h.hexdigest()} ≠ {want}），檔案可能不完整，停止。")
    return f"MD5 相符（{want}）"


def pick_source_archive(src):
    """src 可以是原始碼壓縮檔本身，或放著它的 SourceCode 資料夾。"""
    if src.is_file():
        return src
    cands = [p for p in sorted(src.iterdir()) if p.is_file() and p.name.lower().endswith(ARCHIVE_EXT)
             and "toolchain" not in p.name.lower()]
    # 排除 docker 映像（大型純 tar，名稱沒有 source）
    cands = [p for p in cands if not (p.suffix == ".tar" and "source" not in p.name.lower() and p.stat().st_size > (1 << 30))]
    src_named = [p for p in cands if "source" in p.name.lower()]
    if len(src_named) == 1:
        return src_named[0]
    if not cands:
        sys.exit(f"錯誤：{src} 裡找不到原始碼壓縮檔（{', '.join(ARCHIVE_EXT)}）")
    say("找到多個壓縮檔，請選原始碼那一個：")
    for i, p in enumerate(cands, 1):
        say(f"  {i}. {p.name}（{p.stat().st_size / 1e6:,.0f} MB）")
    n = ask("輸入編號", "1", lambda v: None if v.isdigit() and 1 <= int(v) <= len(cands) else "請輸入列出的編號")
    return cands[int(n) - 1]


def safe_extract(archive, dest):
    """原始碼是不可信資料：只解開一般檔案與資料夾，擋絕對路徑、..、裝置檔、setuid；不執行任何東西。"""
    dest.mkdir(parents=True)
    name = archive.name.lower()
    if name.endswith(".zip"):
        with zipfile.ZipFile(archive) as z:
            for m in z.infolist():
                p = Path(m.filename)
                if p.is_absolute() or ".." in p.parts:
                    sys.exit(f"錯誤：壓縮檔內有不安全的路徑 {m.filename}，停止。")
            z.extractall(dest)
        return
    skipped = []

    def filt(member, path):
        try:
            return tarfile.data_filter(member, path)
        except tarfile.FilterError as e:          # 絕對路徑的連結、指到外面的連結、裝置檔等：跳過並記錄
            skipped.append(f"{member.name}（{type(e).__name__}）")
            return None
    with tarfile.open(archive, "r:*") as t:
        t.extractall(dest, filter=filt)
    if skipped:
        (dest.parent / "解開時跳過的項目.txt").write_text("\n".join(skipped) + "\n", encoding="utf-8")
        say(f"  跳過 {len(skipped)} 個不安全的項目（例如指向系統路徑的連結），清單：{dest.parent / '解開時跳過的項目.txt'}")


def find_kernel_tree(base):
    best = None
    for d, dirs, files in os.walk(base):
        depth = len(Path(d).relative_to(base).parts)
        if depth > 6:
            dirs[:] = []
            continue
        dirs[:] = [x for x in dirs if not x.startswith(".")]
        if "Makefile" in files and "Kconfig" in files and "arch" in dirs:
            try:
                head = Path(d, "Makefile").read_text(errors="replace")[:600]
            except OSError:
                continue
            m1, m2 = re.search(r"^VERSION\s*=\s*(\d+)", head, re.M), re.search(r"^PATCHLEVEL\s*=\s*(\d+)", head, re.M)
            if m1 and m2:
                cand = (Path(d), f"{m1.group(1)}.{m2.group(1)}")
                if best is None or len(cand[0].parts) < len(best[0].parts):
                    best = cand
                dirs[:] = []
    return best


def find_dir_named(base, names, maxdepth=4):
    for d, dirs, files in os.walk(base):
        if len(Path(d).relative_to(base).parts) >= maxdepth:
            dirs[:] = []
        for x in dirs:
            if x in names:
                return Path(d, x)
    return None


def find_build_record(*bases):
    for base in bases:
        if not base or not base.exists():
            continue
        for d, dirs, files in os.walk(base):
            if len(Path(d).relative_to(base).parts) > 5:
                dirs[:] = []
                continue
            for f in sorted(files):
                if re.match(r"(?i)buildrecord.*\.(tar\.gz|tgz|tar|tar\.zst)$", f):
                    return Path(d, f)
            if "BUILD-INFO.txt" in files and Path(d).name.lower().startswith("buildrecord"):
                return Path(d)
    return None


def has_cmd(d, limit=20000):
    """資料夾裡有沒有編譯紀錄（.*.o.cmd 等 .cmd 檔）；不跟隨符號連結，最多看 limit 個項目。"""
    n = 0
    for root, dirs, files in os.walk(d):
        n += len(files) + len(dirs)
        if any(f.endswith(".cmd") for f in files):
            return True
        if n > limit:
            return False
    return False


def find_built_oot(base, maxdepth=4):
    """在 SourceCode 資料夾裡找「已經編譯過」的原始碼樹（sources/ 底下的 NVIDIA 樹外模組資料夾有 .cmd）。
    回傳有 .cmd 的樹外模組資料夾清單；找不到回傳 []。"""
    if not base or not base.is_dir():
        return []
    for root, dirs, files in os.walk(base):
        depth = len(Path(root).relative_to(base).parts)
        if depth >= maxdepth:
            dirs[:] = []
        if Path(root).name == "sources" and (Path(root) / "nvidia-oot").is_dir():
            found = [Path(root) / x for x in JETSON_OOT if (Path(root) / x).is_dir() and has_cmd(Path(root) / x)]
            if found:
                return found
    return []


def split_pack_record(br, dest):
    """pack-build-record.sh 的壓縮檔裡有 kernel/ 與 oot<N>-<名稱>/：掃描工具要分開給（核心一份、樹外模組各一個資料夾），
    混在一起會被判成格式不對（GAP）。安全解開後回傳 (核心資料夾, [樹外模組資料夾…])；不是這種格式就原樣回傳 (br, [])。"""
    br = Path(br)
    if not br.is_file() or not re.search(r"\.(tar\.gz|tgz|tar)$", br.name):
        return br, []
    with tarfile.open(br, "r:*") as t:
        tops = {Path(m.name).parts[0] for m in t.getmembers() if m.name not in (".", "./") and Path(m.name).parts}
    if "kernel" not in tops or not any(re.match(r"oot\d+-", x) for x in tops):
        return br, []
    dest.mkdir(parents=True)
    with tarfile.open(br, "r:*") as t:
        t.extractall(dest, filter="data")
    oot = sorted((dest / x for x in tops if re.match(r"oot\d+-", x)), key=lambda p: int(re.match(r"oot(\d+)-", p.name).group(1)))
    return dest / "kernel", [p for p in oot if p.is_dir()]


def extract_board_os_txt(tars, dest):
    """板子結果檔（board-test-*.tar.gz）裡的 os.txt（board-on-device.sh 寫的，含 uname -a）→ 安全地只取這一個一般檔案寫到 dest，回傳路徑或 None。
    壓縮檔是不可信資料：不收連結、絕對路徑、含 .. 的成員，大小上限 1 MB，只讀不執行；其他成員一律不解開（board-import 之後照常匯入）。"""
    for tp in tars:
        try:
            with tarfile.open(tp, "r:*") as t:
                for m in t:
                    parts = Path(m.name).parts
                    if (m.isreg() and parts and parts[-1] == "os.txt" and len(parts) <= 3 and not Path(m.name).is_absolute()
                            and ".." not in parts and m.size <= (1 << 20)):
                        f = t.extractfile(m)
                        data = f.read(1 << 20) if f else b""
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        dest.write_bytes(data)
                        return dest
        except (OSError, tarfile.TarError, EOFError):
            continue
    return None


def run(cmd, log, env=None, cwd=None):
    say(f"  執行中… 紀錄：{log}")
    with open(log, "w") as f:
        r = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, env=env, cwd=cwd)
    return r.returncode


class ToolsRevError(Exception):
    pass


def resolve_tools_rev(repo, rev):
    """工具版本：預設是 repo 目前 checkout 的 HEAD（CI 上就是正在測的那個 commit），可用 --tools-rev 或 DUMPLING_TOOLS_REV 指定其他版本
    （例如 origin/main：這種遠端分支會先 fetch）。回傳 (完整 commit hash, 寫進輸出的說明 dict)。
    說明 dict 會存成 <輸出>/tools-version.json：實際用的 commit、要求的版本、工作目錄有沒有沒 commit 的修改（有也不會帶進去）。"""
    rev = (rev or "HEAD").strip()
    if not rev or rev.startswith("-") or not re.fullmatch(r"[A-Za-z0-9._/~^@{}+-]+", rev):
        raise ToolsRevError(f"工具版本的寫法不對：{rev!r}（接受 commit、分支、tag 或 HEAD）")
    git = ["git", "-C", str(repo)]
    if rev.startswith("origin/"):
        subprocess.run(git + ["fetch", "-q", "origin"], check=False)
    r = subprocess.run(git + ["rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}"], capture_output=True, text=True)
    commit = r.stdout.strip()
    if r.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit):
        raise ToolsRevError(f"在 {repo} 找不到工具版本 {rev}（不是 git checkout，或沒有這個 commit）")
    st = subprocess.run(git + ["status", "--porcelain", "--untracked-files=no"], capture_output=True, text=True)
    return commit, {"requested": rev, "commit": commit, "source": "git archive", "repo_checkout": str(repo),
                    "worktree_dirty": bool(st.stdout.strip()),
                    "note": "工具是 git archive <commit> 取出的乾淨副本，工作目錄裡沒 commit 的修改不會混進去"}


def extract_tools(repo, commit, dest):
    """git archive <commit> 解開到 dest（乾淨副本，不含 .git 與沒 commit 的修改）。"""
    dest = Path(dest)
    dest.mkdir()
    p1 = subprocess.Popen(["git", "-C", str(repo), "archive", commit], stdout=subprocess.PIPE)
    t = subprocess.run(["tar", "-x", "-C", str(dest)], stdin=p1.stdout)
    p1.stdout.close()
    if p1.wait() != 0 or t.returncode != 0:
        raise ToolsRevError(f"git archive {commit} 或解開失敗")


def main():
    ap = argparse.ArgumentParser(description="CRA 掃描精靈")
    ap.add_argument("--tools-rev", help="掃描用的工具版本（commit、分支或 tag）；不給時用環境變數 DUMPLING_TOOLS_REV，再不然目前 checkout 的 HEAD。"
                                        "實際用的 commit 寫進 <輸出>/tools-version.json 與報告的 provenance")
    ap.add_argument("--archive"); ap.add_argument("--source"); ap.add_argument("--name"); ap.add_argument("--version")
    ap.add_argument("--rootfs"); ap.add_argument("--config"); ap.add_argument("--role", choices=["both", "manufacturer", "supplier"])
    ap.add_argument("--generic-rules", choices=["yes", "no"]); ap.add_argument("--build-record")
    ap.add_argument("--oot-build-dir", help="已編譯過的 sources 資料夾（NVIDIA 樹外模組有 .cmd 編譯紀錄）；不給時在 SourceCode 資料夾裡自動找")
    ap.add_argument("--extra-deliverable", action="append", help="另外交給客戶的韌體檔（例如 capsule .Cap），可重複；不給時互動模式會問")
    ap.add_argument("--board-test", action="append", help="板子檢查結果檔（board-test-*.tar.gz、board-net-*.tar.gz；board-on-device.sh／board-from-network.sh 的產出），可重複；掃描後匯入，不給時互動模式會問")
    ap.add_argument("--tee-source", help="廠商公開原始碼資料夾（OP-TEE／TF-A）；不給時用站台設定 upstream.<組>.public_sources_dir，再不然 public_sources 旁邊的 extract/")
    ap.add_argument("--inputs", help="輸入清單檔（JSON）；不給時用產品設定包裡的 inputs.json")
    ap.add_argument("--platform", help="沒有清單檔時改用平台範本（tools/wizard/platforms/<名稱>.json：jetson、rockchip、raspberrypi；草稿）")
    ap.add_argument("--site-config", help="站台設定檔（JSON）；不給時用環境變數 SCA_WIZARD_CONFIG，再不然 ~/.config/sca-center/wizard.json")
    ap.add_argument("--rescan-from", help="上一次完整掃描的 scan 資料夾（scan-flash-package.sh 的結果，要有 list.json）：只重跑比對，沿用它的 SBOM（可以事先換成某一層的 SBOM，"
                                          "分層用）與 A0 上游比對結果；不再做 A0。見 docs/LAYERS.md、docs/JETSON.md")
    ap.add_argument("--yes", action="store_true"); ap.add_argument("--plan-only", action="store_true")
    a = ap.parse_args()
    ni = a.yes
    load_site_config(a.site_config)

    say("== CRA 掃描精靈 ==（Ctrl+C 可隨時中止；舊的結果不會被動到）\n")
    fp = Path(ask("1. 刷機包的路徑（.tbz2、update.img 或 zip）", check=lambda v: None if Path(v).is_file() else "找不到這個檔案",
                  args_value=a.archive, noninteractive=ni)).resolve()
    # 沒給（--yes 沒有 --source，或互動時直接按 Enter）＝沒有原始碼：核心原始碼判斷標 GAP，其他步驟照跑。
    # 不去目前資料夾找：結果不能取決於執行時剛好放了什麼檔（可能拿錯版本或不可信的檔，也無法重現）。
    sv = ask("2. SourceCode 資料夾的路徑（裡面放著還沒解開的原始碼壓縮檔；也可以直接給壓縮檔；沒有就直接按 Enter → 核心原始碼判斷標 GAP）", "",
             check=lambda v: None if not v or Path(v).exists() else "找不到這個路徑", args_value=a.source, noninteractive=ni)
    sp = Path(sv).resolve() if sv else None
    sp_dir = (sp if sp.is_dir() else sp.parent) if sp else None
    m = re.match(r"(.+?)[_-]V?(\d[\w.\-]*?)(\.tbz2|\.tar\.\w+|\.img|\.zip)$", fp.name)
    name = ask("3. 產品名稱", m.group(1) if m else fp.stem, args_value=a.name, noninteractive=ni)
    version = ask("4. 版本", ("V" + m.group(2)) if m else "", args_value=a.version, noninteractive=ni)
    rootfs = ask("5. 要掃的 rootfs（rootfs、rootfs_no_gui、rootfs_gui、all）", "rootfs", args_value=a.rootfs, noninteractive=ni)
    cfg_in = ask("6. 產品設定包（CRA/Config 資料夾或 config.json；沒有就直接按 Enter）", "",
                 check=lambda v: None if not v or Path(v).exists() else "找不到這個路徑", args_value=a.config, noninteractive=ni)
    cfg_dir = None
    if cfg_in:
        cfg_dir = Path(cfg_in).resolve()
        cfg_dir = cfg_dir.parent if cfg_dir.is_file() else cfg_dir
        if not (cfg_dir / "config.json").exists():
            sys.exit(f"錯誤：{cfg_dir} 裡沒有 config.json")
    generic = "no"
    if not cfg_dir:
        generic = ask("   沒有設定包：要套用通用處理規則嗎（核心沒編進、發行版已修…；不含人工判定）？yes/no", "yes",
                      check=lambda v: None if v in ("yes", "no") else "請輸入 yes 或 no", args_value=a.generic_rules, noninteractive=ni)
    generic_requested = generic
    if generic == "yes" and not (RULES_TEMPLATE and RULES_TEMPLATE.exists()):
        say("  注意：未設定 rules_template（或檔案不存在），沒有套用通用規則；全部列會是未評估。")
        generic = "no"
    role = ask("7. 角色：both（製造商＋客戶資料包）／manufacturer／supplier", "both",
               check=lambda v: None if v in ("both", "manufacturer", "supplier") else "請輸入 both、manufacturer 或 supplier",
               args_value=a.role, noninteractive=ni)
    def _extra_check(v):
        for x in [s.strip() for s in v.split(",") if s.strip()]:
            p = Path(x)
            if p.is_symlink() or not p.is_file():
                return f"找不到這個檔案（或不是一般檔案）：{x}"
        return None
    ex_in = ask("8. 另外交給客戶的韌體檔（例如開機程式 capsule .Cap；多個用逗號分隔；沒有就直接按 Enter）", "", check=_extra_check,
                args_value=",".join(a.extra_deliverable) if a.extra_deliverable else None, noninteractive=ni)
    if _extra_check(ex_in or ""):
        sys.exit(f"錯誤：{_extra_check(ex_in)}")
    extras = [Path(s.strip()).absolute() for s in (ex_in or "").split(",") if s.strip()]

    def _board_check(v):
        for x in [s.strip() for s in v.split(",") if s.strip()]:
            e = check_board_test_file(x)
            if e:
                return e
        return None
    bt_in = ask("9. 有板子檢查結果檔嗎？（board-test-*.tar.gz、board-net-*.tar.gz；多個用逗號分隔；沒有就直接按 Enter）", "", check=_board_check,
                args_value=",".join(a.board_test) if a.board_test else None, noninteractive=ni)
    if _board_check(bt_in or ""):
        sys.exit(f"錯誤：{_board_check(bt_in)}")
    board_tests = [Path(s.strip()).absolute() for s in (bt_in or "").split(",") if s.strip()]

    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M")
    OUT = OUTROOT / f"{re.sub(r'[^A-Za-z0-9._-]', '_', name)}-{re.sub(r'[^A-Za-z0-9._-]', '_', version)}-{stamp}"
    if OUT.exists():
        sys.exit(f"錯誤：{OUT} 已存在，請一分鐘後再跑")
    OUT.mkdir(parents=True, mode=0o700)
    say(f"\n輸出資料夾：{OUT}\n")

    say("== 核對與解開原始碼 ==")
    say(f"  刷機包：{md5_check(fp)}")
    no_source = "沒有指定原始碼（--source）：核心原始碼判斷標 GAP；不去目前資料夾找" if sp is None else None
    if sp is None:
        sa = None
        say(f"  原始碼：{no_source}")
        (OUT / "src").mkdir()
    else:
        sa = pick_source_archive(sp)
        say(f"  原始碼壓縮檔：{sa.name}；{md5_check(sa)}")
        say("  解開中（只解開一般檔案，不執行任何內容；大檔要幾分鐘）…")
        safe_extract(sa, OUT / "src")
    kt = find_kernel_tree(OUT / "src")
    uefi = find_dir_named(OUT / "src", {"uefi"})
    sources_root = kt[0].parent.parent if kt else None
    oot = [sources_root / x for x in JETSON_OOT if sources_root and (sources_root / x).is_dir()]
    # --build-record 有給就用它（優先於自動找到的）；沒給才在原始碼與 SourceCode 資料夾裡找
    br = Path(a.build_record).resolve() if a.build_record else find_build_record(OUT / "src", sp_dir)
    if br and not br.exists():
        sys.exit(f"錯誤：找不到建置紀錄 {br}")
    if not br:
        say("  原始碼裡沒有找到核心建置紀錄（BuildRecord*.tar.gz 或 BuildRecord/ 資料夾）。")
        b = ask("   另外有建置紀錄檔嗎？（路徑；沒有就按 Enter）", "", check=lambda v: None if not v or Path(v).exists() else "找不到這個路徑",
                args_value=a.build_record, noninteractive=ni)
        br = Path(b).resolve() if b else None
    # 樹外模組的編譯紀錄：--oot-build-dir 指定的 sources 資料夾 → SourceCode 裡已編譯過的原始碼樹 → （沒有就用解開的原始碼，沒有 .cmd）
    if a.oot_build_dir:
        built_oot = [Path(a.oot_build_dir).resolve() / x for x in JETSON_OOT
                     if (Path(a.oot_build_dir) / x).is_dir() and has_cmd(Path(a.oot_build_dir) / x)]
        if not built_oot:
            sys.exit(f"錯誤：{a.oot_build_dir} 底下的樹外模組資料夾都沒有編譯紀錄（.cmd）")
    else:
        built_oot = find_built_oot(sp if sp and sp.is_dir() else None)
    stable = STABLE_GIT.get(kt[1]) if kt else None
    stable = stable if stable and stable.exists() else None

    say("\n== 找到的輸入（請確認）==")
    say(f"  刷機包：{fp}")
    say(f"  核心原始碼：{kt[0] if kt else (no_source or '找不到 → 核心判斷會標 GAP')}" + (f"（Linux {kt[1]}）" if kt else ""))
    say(f"  UEFI 原始碼：{uefi or '找不到 → 不比對 UEFI 內建函式庫'}")
    say(f"  核心建置紀錄：{br or '找不到 → 核心判斷不了的一律當成受影響（路線 B）'}")
    say(f"  樹外模組編譯紀錄：{(str(built_oot[0].parent) + f'（{len(built_oot)} 個資料夾有 .cmd）') if built_oot else '沒有已編譯的原始碼樹 → 標頭檔類的核心漏洞較多判斷不了'}")
    say(f"  NVIDIA 樹外模組（{len(oot)} 個）：{', '.join(p.name if p.name != 'kernel-open' else 'unifiedgpudisp/kernel-open' for p in oot) or '無'}")
    say(f"  Linux 穩定版對照：{stable or '無（只影響少數核心列）'}")
    say(f"  產品設定包：{cfg_dir or ('無；套用通用規則' if generic == 'yes' else '無；不套規則（全部列會是未評估）')}")
    say(f"  名稱／版本／rootfs／角色：{name}／{version}／{rootfs}／{role}")
    say(f"  另外交付的韌體（{len(extras)} 個）：{', '.join(p.name for p in extras) or '無'}")
    say(f"  板子檢查結果檔（{len(board_tests)} 個）：{', '.join(p.name for p in board_tests) or '無 → 對外服務欄顯示「不明」'}")
    plan = {"archive": str(fp), "source_archive": str(sa) if sa else None, "source_note": no_source, "kernel_source": str(kt[0]) if kt else None, "kernel_version": kt[1] if kt else None,
            "uefi_source": str(uefi) if uefi else None, "build_record": str(br) if br else None, "oot": [str(p) for p in oot], "oot_build_records": [str(p) for p in built_oot],
            "stable_git": str(stable) if stable else None, "config": str(cfg_dir) if cfg_dir else None, "generic_rules": generic, "generic_rules_requested": generic_requested,
            "name": name, "version": version, "rootfs": rootfs, "role": role, "extra_deliverables": [str(p) for p in extras],
            "platform": a.platform or None}      # 由呼叫端（project.yml）明確給定；沒給就是 None，不從映像格式推測
    # 輸入清單：--inputs → 設定包裡的 inputs.json → --platform 範本
    mpath = Path(a.inputs).resolve() if a.inputs else (cfg_dir / "inputs.json" if cfg_dir and (cfg_dir / "inputs.json").is_file() else None)
    if not mpath and a.platform:
        mpath = PLATFORMS_DIR / f"{a.platform}.json"
        if not mpath.is_file():
            sys.exit(f"錯誤：沒有平台範本 {mpath}")
    manifest = load_inputs_manifest(mpath) if mpath else None
    up_name, up = resolve_upstream(manifest)
    plan["upstream_set"] = up_name
    plan["upstream_bsp"] = str(up["bsp"]) if up.get("bsp") and up["bsp"].exists() else None
    plan["upstream_source"] = str(up["public_sources"]) if up.get("public_sources") and up["public_sources"].exists() else None
    plan["inputs_manifest"] = str(mpath) if mpath else None
    # 1. OP-TEE／TF-A：--tee-source > 站台設定 public_sources_dir（或旁邊的 extract/）；找不到只記 GAP，不中止
    tee_dir, tee_note = None, None
    cand = Path(a.tee_source).absolute() if a.tee_source else up.get("public_sources_dir")
    if cand:
        ok, why = find_tee_tree(cand)
        if ok:
            tee_dir = Path(cand)
        else:
            tee_note = why
    else:
        tee_note = "沒有廠商公開原始碼資料夾（站台設定 upstream.<組>.public_sources_dir 沒設定，旁邊也沒有 extract/，也沒給 --tee-source）"
    plan["tee_source"] = str(tee_dir) if tee_dir else None
    plan["tee_source_gap"] = tee_note
    # 2. UEFI 平台設定（G1）：建置紀錄裡的 uefi/nvidia-config/*/config.dsc.inc（只讀一般檔案、有大小上限）；沒有 → 維持 not_assessed
    uefi_defs, uefi_notes = ([], ["沒有核心建置紀錄"])
    if br:
        uefi_defs, uefi_notes = extract_uefi_defines(br, OUT / "uefi-platform-defines")
    plan["uefi_platform_defines"] = [str(p) for p in uefi_defs]
    plan["uefi_platform_defines_notes"] = uefi_notes
    # 3. A0 上游基準（掃描後執行）；4. 板子結果（掃描後匯入）
    plan["a0_artifacts"] = bool(plan["upstream_bsp"])
    plan["a0_source"] = bool(plan["upstream_source"]) and bool(oot or built_oot or kt)
    plan["board_test"] = [str(p) for p in board_tests]
    say(f"  OP-TEE／TF-A 公開原始碼（--tee-source）：{tee_dir or ('GAP：' + tee_note)}")
    say("  UEFI 平台設定（config.dsc.inc）：" + (f"建置紀錄裡有 {len(uefi_defs)} 份" if uefi_defs else "建置紀錄裡沒有 → UEFI 映像檢查維持 not_assessed（" + "；".join(uefi_notes) + "）")
        + ("　※" + "；".join(uefi_notes) if uefi_defs and uefi_notes else ""))
    say(f"  A0 上游基準：成品比對 {'會做（' + plan['upstream_bsp'] + '）' if plan['a0_artifacts'] else 'GAP：沒有上游 BSP'}；"
        f"原始碼比對 {'會做（' + plan['upstream_source'] + '）' if plan['a0_source'] else 'GAP：沒有上游 public_sources 或沒有我們的 sources'}")
    if manifest:
        res = check_inputs(manifest, plan, sp_dir, cfg_dir, up_name, up)
        print_checklist(manifest, res)
        miss_req = [r for r in res if r["status"] == "missing" and r["required"]]
        miss_opt = [r for r in res if r["status"] == "missing" and not r["required"]]
        unconf = [r for r in res if r["status"] == "unchecked" and r["required"]]
        if unconf:
            say(f"\n  必要但無法自動檢查的輸入 {len(unconf)} 項（未確認）：報告會列為警告，請人工確認後再信任結果。")
        cont = True
        if miss_req:
            say(f"\n  必要的輸入缺 {len(miss_req)} 項：報告會把它們標 GAP，缺的部分不會被當成沒有問題。")
            cont = True if ni else ask("  仍要繼續嗎？yes/no", "no") == "yes"
        chk = {"manifest": str(mpath), "platform": manifest.get("platform"), "draft": bool(manifest.get("draft")), "upstream_set": up_name,
               "missing_required": [r["id"] for r in miss_req], "missing_optional": [r["id"] for r in miss_opt],
               "unconfirmed_required": [r["id"] for r in unconf], "continued_with_missing_required": bool(miss_req) and cont, "inputs": res}
        (OUT / "inputs-check.json").write_text(json.dumps(chk, ensure_ascii=False, indent=1), encoding="utf-8")
        plan["inputs_check"] = {"file": "inputs-check.json", "missing_required": chk["missing_required"],
                                "missing_optional": chk["missing_optional"], "unconfirmed_required": chk["unconfirmed_required"],
                                "continued_with_missing_required": chk["continued_with_missing_required"]}
        if not cont:
            (OUT / "plan.json").write_text(json.dumps(plan, ensure_ascii=False, indent=1), encoding="utf-8")
            say("已取消（必要的輸入不齊）。檢查結果存在 " + str(OUT / "inputs-check.json"))
            return 0
    else:
        say("\n  這個產品沒有輸入清單（設定包裡沒有 inputs.json，也沒有 --inputs／--platform）；不檢查必要輸入，照原本流程繼續。")
        plan["inputs_check"] = None
    plan_steps = []
    if up_name or a.tee_source:
        plan_steps.append({"id": "tee-source", "label": "OP-TEE／TF-A／Mbed TLS 公開原始碼（B-tee-source）", "status": "OK" if tee_dir else "GAP",
                           "note": str(tee_dir) if tee_dir else tee_note, "affects": "tos-optee 映像的 OP-TEE、TF-A、Mbed TLS 不在 SBOM，也沒有弱點比對"})
    if uefi:
        plan_steps.append({"id": "uefi-platform-defines", "label": "UEFI 平台設定（建置紀錄的 config.dsc.inc）", "status": "OK" if uefi_defs else "GAP",
                           "note": f"{len(uefi_defs)} 份" if uefi_defs else "；".join(uefi_notes), "affects": "UEFI 映像檢查的 DSC 佐證做不了，該列維持 not_assessed"})
    if manifest:          # 沒有輸入清單時，步驟狀態等掃描後才寫（plan-only 不產生 inputs-check.json）
        merge_step_status(OUT, plan_steps)
    (OUT / "plan.json").write_text(json.dumps(plan, ensure_ascii=False, indent=1), encoding="utf-8")
    if a.plan_only:
        say(f"\n（--plan-only：只列計畫，不掃描。計畫存在 {OUT / 'plan.json'}）")
        return 0
    if not ni and ask("\n開始掃描？yes/no", "yes") != "yes":
        say("已取消。")
        return 0

    pe = PILOT_ENV or (Path(os.environ["PILOT_ENV"]).expanduser() if os.environ.get("PILOT_ENV") else None)
    if not pe or not pe.is_file():
        sys.exit("錯誤：沒有掃描設定檔（PILOT_ENV）。請在站台設定檔設定 pilot_env（指向存在的 pilot.env），或先設定環境變數 PILOT_ENV；"
                 + (f"目前指向 {pe}，但檔案不存在。" if pe else "目前兩者都沒有設定。"))
    say("\n== 1. 取工具 ==")
    try:
        commit, tools_info = resolve_tools_rev(REPO, a.tools_rev or os.environ.get("DUMPLING_TOOLS_REV") or "HEAD")
        extract_tools(REPO, commit, OUT / "wt")
    except ToolsRevError as e:
        sys.exit(f"錯誤：{e}")
    (OUT / "tools-version.json").write_text(json.dumps(tools_info, ensure_ascii=False, indent=1), encoding="utf-8")
    say(f"  工具版本 {commit[:12]}（要求的版本：{tools_info['requested']}）"
        + ("；注意：工作目錄有沒 commit 的修改，沒有帶進來（只用 commit 裡的內容）" if tools_info["worktree_dirty"] else ""))

    say("\n== 2. 產品設定 ==")
    mcfg = OUT / "cra-project/CRA/Config"
    if cfg_dir:
        shutil.copytree(cfg_dir, mcfg)
        say(f"  複製設定包：{cfg_dir}")

    say("\n== 3、4. 掃描（約 10–15 分鐘）==")
    env = dict(os.environ)
    env.update(GRYPE_DB_CACHE_DIR=str(GRYPE_CACHE), GRYPE_DB_UPDATE="online", TMPDIR=str(OUT / "tmp"))
    if TOOLS_BIN:
        env["PATH"] = f"{TOOLS_BIN}:{env.get('PATH', '')}"
    env["PILOT_ENV"] = str(pe)
    if re.fullmatch(r"[0-9a-f]{40}", commit):
        env["SCA_CENTER_COMMIT"] = commit      # 跑的是 git archive（沒有 .git）：把取到的 commit 告知 A-provenance
    (OUT / "tmp").mkdir()
    if not GRYPE_CACHE.exists() and GRYPE_SEED and GRYPE_SEED.exists():
        shutil.copytree(GRYPE_SEED, GRYPE_CACHE, symlinks=True)
    bos = extract_board_os_txt(board_tests, OUT / "board-os" / "os.txt") if board_tests else None
    if bos:
        env["KERNEL_BOARD_OS_TXT"] = str(bos)      # C-kernel-boot 用板子的 uname -v 確認實際跑的核心（board-import 之後照常匯入整個檔案）
        say(f"  板子 os.txt：{bos}（給 C-kernel-boot 比對）")
    if br:
        kbr, ooot = split_pack_record(br, OUT / "buildrecord")
        env["KERNEL_BUILD_RECORD"] = str(kbr)
        use_oot = ooot or built_oot or oot
        if use_oot:
            env["KERNEL_OOT_BUILD_RECORDS"] = ":".join(str(p) for p in use_oot)
        say(f"  核心建置紀錄：{kbr}" + (f"；樹外模組紀錄取自建置紀錄（{len(ooot)} 個）" if ooot else
                                       (f"；樹外模組紀錄取自已編譯的原始碼樹（{len(built_oot)} 個）" if built_oot else "")))
        if stable:
            env["KERNEL_STABLE_GIT"] = str(stable)
    cmd = ["tools/demo/scan-flash-package.sh", "--archive", str(fp), "--rootfs", rootfs, "--name", name, "--version", version,
           "--no-company", "--out", str(OUT / "scan")]
    if a.platform:      # 平台由呼叫端（project.yml）明確給，原樣傳下去；沒給時 scan-flash-package.sh 對原始磁碟映像標 GAP，不推測
        cmd += ["--platform", a.platform]
    if a.rescan_from:   # 分層：沿用上一次完整掃描的資料夾（SBOM 已換成這一層的），只重跑比對
        cmd += ["--rescan-from", str(Path(a.rescan_from).resolve())]
    if cfg_dir:
        cmd += ["--product-config", str(mcfg / "config.json")]
    if kt:
        cmd += ["--kernel-source", str(kt[0])]
    if uefi:
        cmd += ["--uefi-source", str(uefi)]
        for d in ("edk2-nvidia/Platform/NVIDIA/NVIDIA.common.dsc",):      # NVIDIA Jetson 的平台 DSC（有的話才給；UEFI 映像檢查的 DSC 佐證）
            if (Path(uefi) / d).is_file():
                cmd += ["--uefi-platform-dsc", d]
                cfgs = sorted((Path(uefi) / "nvidia-config").glob("*/config.dsc.inc")) if (Path(uefi) / "nvidia-config").is_dir() else []
                if uefi_defs:      # 建置紀錄裡的（pack-build-record.sh --uefi=）：RD 實際建置時產生的，優先
                    for f in uefi_defs:
                        cmd += ["--uefi-platform-defines", str(f)]
                elif len(cfgs) == 1 and cfgs[0].is_file() and not cfgs[0].is_symlink():      # 建置時產生的 Kconfig 設定（原始碼包裡通常沒有；有且只有一份才用）
                    cmd += ["--uefi-platform-defines", str(cfgs[0])]
    if tee_dir:
        cmd += ["--tee-source", str(tee_dir)]
    for p in extras:
        cmd += ["--extra-deliverable", str(p)]
    rc = run(cmd, OUT / "scan.log", env=env, cwd=OUT / "wt")
    say(f"  掃描結束 exit={rc}（2＝有 GAP，屬預期；1＝失敗，看 scan.log 與 scan/summary.md）")
    rd = OUT / "scan" / ("rootfs" if rootfs != "all" else "rootfs")
    scan_dir = rd / "scan"
    if not scan_dir.exists():
        sys.exit(f"錯誤：沒有掃描結果（{scan_dir}），請看 {OUT / 'scan.log'}")

    steps = {}     # 掃描後的附加步驟：每一步分開記（OK／GAP／FAIL…），失敗只記錄、不中止
    py_wt = OUT / "wt/tools/cra/upstream_baseline.py"
    a0 = [("artifacts", "A0-artifacts", fp, plan["upstream_bsp"], "成品（刷機包）對 NVIDIA BSP", 3600),
          ("source", "A0-source", sources_root, plan["upstream_source"], "原始碼對 NVIDIA public_sources", 3600)]
    say("\n== 3b. A0 與 NVIDIA 原版的逐檔比對 ==")
    for mode, tag, ours, up_path, label, lim in a0:
        t0 = datetime.datetime.now()
        prev_a0 = Path(a.rescan_from) / "rootfs" / f"upstream-baseline-{mode}.json" if a.rescan_from else None
        if prev_a0 and prev_a0.is_file():      # 分層重跑：A0 與 SBOM 無關，沿用完整掃描的結果，不重算
            for ext in ("json", "md"):
                if (prev_a0.parent / f"upstream-baseline-{mode}.{ext}").is_file():
                    shutil.copy2(prev_a0.parent / f"upstream-baseline-{mode}.{ext}", rd)
            steps[tag] = {"status": "GAP", "detail": "完整掃描沒有留下這一步的狀態紀錄（wizard-steps.json），不推測", "reused": True}
            try:
                prev_steps = json.loads((Path(a.rescan_from).parent / "wizard-steps.json").read_text(encoding="utf-8"))
                if tag in prev_steps:
                    steps[tag] = dict(prev_steps[tag], reused=True, detail="沿用完整掃描的結果：" + str(prev_steps[tag].get("detail", "")))
            except (OSError, ValueError):
                pass
        elif not up_path:
            steps[tag] = {"status": "GAP", "detail": "沒有上游基準檔（站台設定 upstream 沒有或檔案不存在）"}
        elif not ours or not Path(ours).exists():
            steps[tag] = {"status": "GAP", "detail": "找不到我們的 " + ("刷機包" if mode == "artifacts" else "sources 資料夾")}
        elif not py_wt.is_file():
            steps[tag] = {"status": "GAP", "detail": "這版工具沒有 upstream_baseline.py"}
        else:
            lg = OUT / f"upstream-baseline-{mode}.log"
            try:
                with open(lg, "w") as f:
                    r = subprocess.run([PY, "-I", str(py_wt), mode, "--ours", str(ours), "--upstream", str(up_path), "--out", str(rd)],
                                       stdout=f, stderr=subprocess.STDOUT, env=env, timeout=lim)
                st, dt = step_line(lg, tag)
                steps[tag] = {"status": st or "FAIL", "detail": dt or f"upstream_baseline.py exit {r.returncode}，沒有結果行，看 {lg.name}"}
            except subprocess.TimeoutExpired:
                steps[tag] = {"status": "FAIL", "detail": f"逾時（{lim} 秒）"}
            except OSError as e:
                steps[tag] = {"status": "FAIL", "detail": f"無法執行（{type(e).__name__}）"}
        steps[tag]["seconds"] = round((datetime.datetime.now() - t0).total_seconds())
        say(f"  {label}：{steps[tag]['status']}（{steps[tag]['seconds']} 秒）{steps[tag]['detail']}" + ("　→ GAP，不是通過" if steps[tag]["status"] in ("GAP", "FAIL") else ""))

    say("\n== 3c. 板子檢查結果匯入 ==")
    if not board_tests:
        steps["board-import"] = {"status": "NOT_RUN", "detail": "沒有給板子檢查結果檔（--board-test）→ 對外服務欄顯示「不明」"}
    else:
        bi = OUT / "wt/tools/demo/board-import.sh"
        benv = dict(env, SCA_PYTHON=PY)
        if not bi.is_file():
            steps["board-import"] = {"status": "GAP", "detail": "這版工具沒有 board-import.sh"}
        else:
            t0 = datetime.datetime.now()
            rc = run(["bash", str(bi), "--result", str(rd), "--no-cra", *[str(p) for p in board_tests]], OUT / "board-import.log", env=benv)
            bst, bdt = board_import_status(rc, OUT / "board-import.log")      # exit 2 是「匯入成功但有 ATTENTION／GAP」，不是失敗
            steps["board-import"] = {"status": bst, "detail": f"{bdt}；{len(board_tests)} 個檔案；看 board-import.log",
                                     "seconds": round((datetime.datetime.now() - t0).total_seconds())}
    for k in ("board-import",):
        say(f"  {k}：{steps[k]['status']}　{steps[k]['detail']}")
    (OUT / "wizard-steps.json").write_text(json.dumps(steps, ensure_ascii=False, indent=1), encoding="utf-8")
    # C-kernel-boot（兩顆核心）是掃描裡的一個階段（scan/status.tsv）：精靈把它的狀態一併顯示並記進輸入清單的步驟，不另外執行
    kb_st, kb_dt = step_line(scan_dir / "status.tsv", "C-kernel-boot")
    if kb_st:
        steps["kernel-boot"] = {"status": kb_st, "detail": kb_dt}
        say(f"  C-kernel-boot（刷機包有兩顆核心？）：{kb_st}　{kb_dt[:300]}" + ("　→ 資訊性，需要在板子上確認實際開機的核心" if kb_st == "ATTENTION" else ""))
    labels = {"kernel-boot": ("C-kernel-boot 刷機包兩顆核心的比對", "實際開機的核心要在板子上確認（uname -v）"),
              "A0-artifacts": ("A0 成品（刷機包）對 NVIDIA BSP 的逐檔比對", "不知道哪些檔案和 NVIDIA 原版相同"),
              "A0-source": ("A0 原始碼對 NVIDIA public_sources 的逐檔比對", "不知道哪些原始碼是 RD 改過的"),
              "board-import": ("板子檢查結果匯入", "對外服務欄維持「不明」")}
    merge_step_status(OUT, plan_steps + [{"id": k, "label": labels[k][0], "status": v["status"], "note": v["detail"], "affects": labels[k][1]}
                                         for k, v in steps.items() if k in labels])

    if not cfg_dir:   # 用掃描產生的最小設定；需要時加通用規則
        shutil.copytree(rd / "cra-project/CRA/Config", mcfg)
        if generic_requested == "yes" and generic == "no":
            say("  未設定 rules_template，沒有套用通用規則")
        if generic == "yes" and RULES_TEMPLATE and RULES_TEMPLATE.exists():
            d = json.loads(RULES_TEMPLATE.read_text(encoding="utf-8"))
            rules = d["rules"] if isinstance(d, dict) else d
            keep = [r for r in rules if r.get("id") not in PRODUCT_SPECIFIC_RULES]
            if isinstance(d, dict):
                d["rules"] = keep
            else:
                d = keep
            (mcfg / "vex-rules.json").write_text(json.dumps(d, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
            say(f"  套用通用處理規則 {len(keep)} 條（來源 {RULES_TEMPLATE}）")
    projects = []
    if role in ("both", "manufacturer"):
        projects.append(("製造商", OUT / "cra-project"))
    if role in ("both", "supplier"):
        scfg = OUT / "supplier/cra-project/CRA/Config"
        shutil.copytree(mcfg, scfg)
        c = json.loads((scfg / "config.json").read_text(encoding="utf-8"))
        c["role"] = "supplier"
        (scfg / "config.json").write_text(json.dumps(c, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        projects.append(("供應商（客戶資料包）", OUT / "supplier/cra-project"))

    say("\n== 5. 套用規則，產生 CRA 文件 ==")
    for label, proj in projects:
        args = [PY, "-I", str(OUT / "wt/tools/cra/cra_report.py"), "--project", str(proj), "--scan", str(scan_dir), "--no-company"]
        if (rd / "own-software/own-software.json").exists():
            args += ["--own-software", str(rd / "own-software/own-software.json")]
        if (rd / "uefi-source").exists():
            args += ["--uefi-source", str(rd / "uefi-source")]
        if GRYPE_CACHE.exists() and "--grype-db" in (OUT / "wt/tools/cra/cra_report.py").read_text(encoding="utf-8"):
            # NVIDIA 公告的 CVE 其實是發行版套件的：依掃描用的 Grype DB（site config grype_cache）判斷；有問題的執行檔在不在，
            # 用掃描抽出的 pkgdb 的完整 rootfs 項目清單（rootfs-files；只有 dpkg 檔案擁有者清單時不能證明檔案不存在）
            args += ["--grype-db", str(GRYPE_CACHE)]
            if (rd / "pkgdb" / "dpkg-status").is_file():
                args += ["--pkgdb", str(rd / "pkgdb")]
        rc = run(args, OUT / f"cra-{proj.parent.name if proj.parent != OUT else 'manufacturer'}.log", env=env)
        say(f"  {label}：exit={rc}（2＝有 GAP，屬預期）")

    say("\n== 6. 整理成報告 ==")
    pkg = OUT / "wt/tools/cra/report_package.py"
    if pkg.exists():
        args = [PY, "-I", str(pkg), "--out", str(OUT / "報告"), "--name", name, "--version", version]
        if role in ("both", "manufacturer"):
            args += ["--project", str(OUT / "cra-project")]
        if role in ("both", "supplier"):
            args += ["--supplier-project", str(OUT / "supplier/cra-project")]
        if (OUT / "inputs-check.json").exists() and "--inputs-check" in pkg.read_text(encoding="utf-8"):
            args += ["--inputs-check", str(OUT / "inputs-check.json")]
        rc = run(args, OUT / "report_package.log", env=env)
        say(f"  整理 exit={rc}")
    else:
        say("  這版工具還沒有整理程式（report_package.py），先跳過；原始產出在下面")

    say("\n== 看結果 ==")
    say(f"  掃描狀態（每一步分開）：{OUT / 'scan/summary.md'}")
    if (OUT / "報告").exists():
        say(f"  整理好的報告：        {OUT / '報告'}")
    say(f"  CRA 文件（製造商）：  {OUT / 'cra-project/CRA/Reports'}")
    if role in ("both", "supplier"):
        say(f"  客戶資料包：          {OUT / 'supplier/cra-project/CRA/Reports/supplier-package'}")
    say(f"  （{rd / 'cra-project'} 是掃描內建的草稿，沒有套規則，不要用）")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit("\n已中止。")
