"""專案與平台設定的讀取與驗證（契約見 docs/PLATFORM-INTERFACE.md）。

- parse_tag("<專案>/<版本>")                      → (專案, 版本)，格式錯就 ConfigError
- load_project(專案資料夾) / validate_project(doc)   → project.yml
- load_sources(sources.yml) / validate_sources(doc)  → sources.yml
- load_platform_config(平台名或 platform.yml 路徑)   → 驗證過的平台設定（分層規則給 L 軌用）
- classify_package(名稱, 設定) / classify_path(路徑, 設定) → "bsp"／"host-tool"／"os"

所有讀檔都用 yaml.safe_load；錯誤訊息只含欄位名稱，不回顯檔案內容的值（可能不可信）。
用法（指令列）：python3 -I project_config.py validate <專案資料夾> [--platforms-dir <資料夾>]
                python3 -I project_config.py platform <平台名或 platform.yml> [--platforms-dir <資料夾>]
"""
import datetime
import fnmatch
import os
import re
import sys

try:
    import yaml
except ImportError:  # 由呼叫端回報
    yaml = None

HERE = os.path.dirname(os.path.abspath(__file__))
PLATFORMS_DIR = os.environ.get("DUMPLING_PLATFORMS_DIR") or os.path.normpath(os.path.join(HERE, "..", "platforms"))

PROJECT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
VERSION_RE = re.compile(r"^v[0-9][A-Za-z0-9._+-]{0,62}$")
PLATFORM_RE = PROJECT_RE
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
FILE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
PKG_PATTERN_RE = re.compile(r"^[a-z0-9*?\[\]][a-z0-9+.*?\[\]_-]*$")
PLACEHOLDER = "TO BE COMPLETED"

STATUSES = ("development", "shipped")
COMPANY_ROLES = ("manufacturer", "supplier", "both")
OS_RESPONSIBILITIES = ("ours", "customer", "upstream-vendor")
# metadata＝廠商附的清單或說明檔（官方 SBOM、.info、.manifest、.json）：唯讀、不掃描。fetch 照樣下載並核對 sha256；
# assemble／scan 只依 role 明確挑 bsp、rootfs 等，不會把 metadata 當掃描輸入。
FILE_ROLES = ("bsp", "rootfs", "source", "image", "package", "tool", "metadata")
LAYERS = ("bsp", "host-tool", "os")
BUILD_MODES = ("compile", "none")
ARCHES = ("arm64", "amd64")                                  # 目標映像的架構（platform.yml 的 arch）與 runner 架構（build.runner、scan.runner）
RUNNER_LABELS = {"arm64": "ubuntu-24.04-arm", "amd64": "ubuntu-24.04"}
SCAN_PLATFORM_ARGS = ("jetson", "raspberrypi", "rockchip", "generic")   # scan-flash-package.sh／cra-scan.py 的 --platform 認得的值
SCAN_ROOTFS = "rootfs"                                       # scan.rootfs：scan.sh 與 platform_scan 目前固定用這個名稱（結果在 scan/rootfs/）
SCAN_TOOLS = ("sbom-only", "full")                            # scan.tools：sbom-only＝Syft、Grype、bwrap；full＝install-tools.sh 不帶旗標（再加 cdxgen、govulncheck、guarddog）
APT_RE = re.compile(r"^[a-z0-9][a-z0-9+.-]{0,80}$")          # apt 套件名稱（Debian Policy 5.6.1）；進 workflow 的指令列，所以限制字元

PROJECT_STRING_FIELDS = ("product_name", "brand", "platform_version", "bsp_os_source", "kernel_source", "bootloader")
PROJECT_LIST_FIELDS = ("markets", "interfaces", "own_software")  # own_software 可以是空清單
PROJECT_REQUIRED = ("schema", "platform", "company_role", "status", "os_responsibility", "support_until") \
    + PROJECT_STRING_FIELDS + PROJECT_LIST_FIELDS


class ConfigError(Exception):
    """設定錯誤；str(e) 是給人看的訊息。"""


def _require_yaml():
    if yaml is None:
        raise ConfigError("缺少 PyYAML（Ubuntu：apt install python3-yaml）")


def _load_yaml(path):
    _require_yaml()
    try:
        with open(path, encoding="utf-8") as fh:
            return yaml.safe_load(fh)
    except FileNotFoundError:
        raise ConfigError("找不到 %s" % os.path.basename(path))
    except (OSError, yaml.YAMLError, UnicodeDecodeError) as e:
        raise ConfigError("讀不到 %s（%s）" % (os.path.basename(path), type(e).__name__))


def parse_tag(tag):
    """'<專案>/<版本>' → (專案, 版本)。"""
    if not isinstance(tag, str) or tag.count("/") != 1:
        raise ConfigError("tag 格式必須是 <專案>/<版本>")
    project, version = tag.split("/")
    if not PROJECT_RE.match(project):
        raise ConfigError("tag 的專案名只能用小寫英數與連字號（最長 63 字元）")
    if not VERSION_RE.match(version):
        raise ConfigError("tag 的版本必須以 v 加數字開頭，只能用英數與 . _ + -")
    return project, version


# ---------------------------------------------------------------- project.yml

def _nonempty_str(v):
    return isinstance(v, str) and v.strip() != ""


def validate_project(doc, platforms_dir=PLATFORMS_DIR):
    """回傳 (錯誤清單, 待填欄位清單)。待填＝值是 'TO BE COMPLETED'；status 是 shipped 時待填算錯誤。"""
    if not isinstance(doc, dict):
        return ["project.yml 不是 mapping"], []
    errs, todo = [], []
    for k in PROJECT_REQUIRED:
        if k not in doc or doc[k] is None:
            errs.append("缺欄位 " + k)
    if doc.get("schema") != 1 and "schema" in doc:
        errs.append("schema 必須是 1")
    for k in PROJECT_STRING_FIELDS:
        v = doc.get(k)
        if k in doc and v is not None and not _nonempty_str(v):
            errs.append("%s 必須是非空字串" % k)
        elif v == PLACEHOLDER:
            todo.append(k)
    for k in PROJECT_LIST_FIELDS:
        v = doc.get(k)
        if v is None:
            continue
        if not isinstance(v, list) or not all(_nonempty_str(x) for x in v):
            errs.append("%s 必須是字串清單" % k)
        elif k != "own_software" and not v:
            errs.append("%s 不可為空清單" % k)
        elif PLACEHOLDER in v:
            todo.append(k)
    plat = doc.get("platform")
    if plat is not None:
        if not (isinstance(plat, str) and PLATFORM_RE.match(plat)):
            errs.append("platform 格式不合法")
        elif not os.path.isfile(os.path.join(platforms_dir, plat, "platform.yml")):
            errs.append("未知平台（沒有 pipeline/platforms/<platform>/platform.yml）")
    for key, allowed in (("company_role", COMPANY_ROLES), ("status", STATUSES), ("os_responsibility", OS_RESPONSIBILITIES)):
        v = doc.get(key)
        if v is not None and v not in allowed:
            errs.append("%s 必須是 %s" % (key, "／".join(allowed)))
    su = doc.get("support_until")
    if su is not None:
        s = su.isoformat() if isinstance(su, datetime.date) else su
        if s == PLACEHOLDER:
            todo.append("support_until")
        elif not (isinstance(s, str) and re.match(r"^\d{4}-\d{2}-\d{2}$", s)):
            errs.append("support_until 必須是 YYYY-MM-DD")
        else:
            try:
                datetime.date.fromisoformat(s)
            except ValueError:
                errs.append("support_until 不是有效日期")
    if doc.get("status") == "shipped" and todo:
        errs.append("status 是 shipped 時不可有待填欄位（%s）" % "、".join(sorted(set(todo))))
    return errs, sorted(set(todo))


def load_project(project_dir, platforms_dir=PLATFORMS_DIR):
    """讀並驗證 project.yml；回傳 dict（加上 '_todo' 待填欄位清單）。"""
    doc = _load_yaml(os.path.join(project_dir, "project.yml"))
    errs, todo = validate_project(doc, platforms_dir)
    if errs:
        raise ConfigError("project.yml 欄位錯誤：" + "；".join(errs))
    doc = dict(doc)
    doc["_todo"] = todo
    return doc


# ---------------------------------------------------------------- sources.yml

def validate_file_entry(f, prefix):
    errs = []
    if not isinstance(f, dict):
        return ["%s 不是 mapping" % prefix]
    for k in ("name", "url", "role"):
        if f.get(k) in (None, ""):
            errs.append("%s 缺 %s" % (prefix, k))
    name = f.get("name")
    if name and not (isinstance(name, str) and FILE_NAME_RE.match(name)):
        errs.append("%s name 不合法" % prefix)
    url = f.get("url")
    if url and not (isinstance(url, str) and url.startswith("https://")):
        errs.append("%s url 必須是 https" % prefix)
    if f.get("role") and f["role"] not in FILE_ROLES:
        errs.append("%s role 必須是 %s" % (prefix, "／".join(FILE_ROLES)))
    gap = f.get("gap")
    sha = f.get("sha256")
    if gap is not None:
        # 還沒有可核對的雜湊：寫明原因，fetch 不下載、不接受任何雜湊，回報 GAP
        if not _nonempty_str(gap):
            errs.append("%s gap 必須是說明文字" % prefix)
        if sha not in (None, ""):
            errs.append("%s 有 gap 就不可同時有 sha256" % prefix)
    else:
        if sha in (None, ""):
            errs.append("%s 缺 sha256（尚未記錄雜湊的請改用 gap: <原因>）" % prefix)
        elif not (isinstance(sha, str) and SHA256_RE.match(sha)):
            errs.append("%s sha256 必須是 64 位小寫十六進位" % prefix)
    sha1 = f.get("sha1")
    if sha1 not in (None, "") and not (isinstance(sha1, str) and SHA1_RE.match(sha1)):
        errs.append("%s sha1 必須是 40 位小寫十六進位" % prefix)
    size = f.get("size")
    if size is not None and (not isinstance(size, int) or isinstance(size, bool) or size <= 0):
        errs.append("%s size 必須是正整數（不知道就省略）" % prefix)
    commit, repo = f.get("commit"), f.get("repo")
    if commit is not None or repo is not None:
        # GitHub 動態封存檔：以 commit SHA 為準（D-025、D-027）
        if not (isinstance(commit, str) and SHA1_RE.match(commit)):
            errs.append("%s commit 必須是 40 位小寫十六進位 commit SHA" % prefix)
        if not (isinstance(repo, str) and repo.startswith("https://")):
            errs.append("%s 有 commit 時 repo 必須是 https 的 clone 網址" % prefix)
    return errs


KERNEL_RELEASE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+~-]{0,99}$")   # 同 tools/wizard/cra-scan.py 的 --kernel-version
KERNEL_UPSTREAM_RE = re.compile(r"^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,6}$")    # 同 tools/pilot/lib/kernel_versions.py 的 UP_RE（X.Y.Z）


NOT_DISTRO_MAX_BYTES = 300     # 同 tools/wizard/cra-scan.py 的 --kernel-not-distro


def check_not_distro(v, label):
    """kernel_not_distro 的理由：非空字串、沒有控制字元（換行、tab）、最多 300 位元組。不合法 → ConfigError。"""
    if not (isinstance(v, str) and v.strip() and v.isprintable() and len(v.encode("utf-8")) <= NOT_DISTRO_MAX_BYTES):
        raise ConfigError("%s 必須是理由字串（非空、沒有換行或控制字元、最多 %d 位元組）" % (label, NOT_DISTRO_MAX_BYTES))
    return v


def kernel_wizard_args(params, platform_not_distro=None):
    """版本的 platform_params → 精靈（tools/wizard/cra-scan.py）的核心參數清單。
    - kernel_release：字串或字串清單 → 每個一個 `--kernel-version`。
    - kernel_upstream_version：上游版本 X.Y.Z。字串＝只有一顆 kernel_release 時那一顆的；mapping＝{kernel_release: X.Y.Z}（鍵要在 kernel_release 裡）
      → 每個一個 `--kernel-upstream-version <kernel_release>=<X.Y.Z>`（kernel_versions.py 和原始碼 Makefile 核對，不一致不採用）。
    - kernel_not_distro：理由字串 → `--kernel-not-distro <理由>`：宣告這個產品的核心不是發行版（Debian／Ubuntu）的核心，SBOM 有核心時 C-kernel-coverage 是 GAP
      （發行版資料的比對不可靠）。給版本字串看不出來的平台（例如部分 Radxa 核心）。platform_not_distro 是 platform.yml（scan.kernel_not_distro）的預設，
      適用該平台所有專案的所有版本；版本的 platform_params.kernel_not_distro 優先（取代它）。兩邊都沒有就不印。
    都沒有 → []。格式不對 → ConfigError。"""
    params = params or {}
    if not isinstance(params, dict):
        raise ConfigError("platform_params 必須是 mapping")
    kr = params.get("kernel_release")
    rels = [] if kr is None else [kr] if isinstance(kr, str) else kr
    if not isinstance(rels, list) or not all(isinstance(r, str) and KERNEL_RELEASE_RE.match(r) for r in rels) or len(set(rels)) != len(rels):
        raise ConfigError("platform_params.kernel_release 必須是核心版本字串或不重複的清單（英數字開頭、英數字與「. _ + ~ -」）")
    up = params.get("kernel_upstream_version")
    if up is None:
        ups = {}
    elif isinstance(up, str):
        if len(rels) != 1:
            raise ConfigError("platform_params.kernel_upstream_version 是字串時 kernel_release 要剛好一顆；多顆請寫成 {kernel_release: X.Y.Z}")
        ups = {rels[0]: up}
    elif isinstance(up, dict):
        ups = up
    else:
        raise ConfigError("platform_params.kernel_upstream_version 必須是 X.Y.Z 或 {kernel_release: X.Y.Z}")
    for k, v in ups.items():
        if k not in rels or not isinstance(v, str) or not KERNEL_UPSTREAM_RE.match(v):
            raise ConfigError("platform_params.kernel_upstream_version 的鍵要是 kernel_release 裡的核心、值要是 X.Y.Z")
    nd = params.get("kernel_not_distro")
    if nd is not None:
        check_not_distro(nd, "platform_params.kernel_not_distro")
    elif platform_not_distro is not None:
        nd = check_not_distro(platform_not_distro, "platform.yml 的 scan.kernel_not_distro")
    out = []
    for r in rels:
        out += ["--kernel-version", r]
    for r in rels:
        if r in ups:
            out += ["--kernel-upstream-version", "%s=%s" % (r, ups[r])]
    if nd is not None:
        out += ["--kernel-not-distro", nd]
    return out


def validate_sources(doc):
    """回傳錯誤清單。releases 是 {版本: {platform_params?, files: [...]}}。"""
    if not isinstance(doc, dict):
        return ["sources.yml 不是 mapping"]
    errs = []
    if doc.get("schema") != 1:
        errs.append("schema 必須是 1")
    rel = doc.get("releases")
    if not isinstance(rel, dict) or not rel:
        return errs + ["releases 必須是非空 mapping（版本 → 內容）"]
    for ver, body in rel.items():
        if not (isinstance(ver, str) and VERSION_RE.match(ver)):
            errs.append("版本名稱不合法")
            continue
        p = "releases.%s" % ver
        if not isinstance(body, dict):
            errs.append("%s 不是 mapping" % p)
            continue
        params = body.get("platform_params")
        if params is not None and not isinstance(params, dict):
            errs.append("%s.platform_params 必須是 mapping" % p)
        elif params:
            try:
                kernel_wizard_args(params)
            except ConfigError as e:
                errs.append("%s：%s" % (p, e))
        files = body.get("files")
        if not isinstance(files, list) or not files:
            errs.append("%s.files 必須是非空清單" % p)
            continue
        names = set()
        for i, f in enumerate(files):
            errs += validate_file_entry(f, "%s.files[%d]" % (p, i))
            n = f.get("name") if isinstance(f, dict) else None
            if n in names:
                errs.append("%s.files[%d] name 重複" % (p, i))
            names.add(n)
    return errs


def load_sources(path):
    doc = _load_yaml(path)
    errs = validate_sources(doc)
    if errs:
        raise ConfigError("sources.yml 欄位錯誤：" + "；".join(errs))
    return doc


def load_project_all(project_dir, platforms_dir=PLATFORMS_DIR):
    """project.yml＋sources.yml 一起驗證；回傳 (project, sources)。"""
    return load_project(project_dir, platforms_dir), load_sources(os.path.join(project_dir, "sources.yml"))


# ---------------------------------------------------------------- platform.yml

def _validate_patterns(v, label, kind, errs):
    if v is None:
        return []
    if not isinstance(v, list) or not all(isinstance(x, str) and x for x in v):
        errs.append("%s 必須是字串清單" % label)
        return []
    for x in v:
        if kind == "package":
            if not PKG_PATTERN_RE.match(x) or "/" in x:
                errs.append("%s 的套件名稱樣式不合法（只能小寫英數與 + . - _ 和 * ? []，不含 /、不含版本）" % label)
        else:
            if x.startswith("/") or ".." in x.split("/") or "\\" in x or "\x00" in x:
                errs.append("%s 的路徑樣式必須是相對路徑，不可含 .." % label)
    return list(v)


def _validate_apt(v, label, errs):
    if v is None:
        return
    if not isinstance(v, list) or not all(isinstance(x, str) and APT_RE.match(x) for x in v):
        errs.append("%s 必須是 apt 套件名稱清單（小寫英數與 + . -）" % label)


def platform_plan(config):
    """platform.yml（驗證過的 dict）→ workflow 需要的規劃值：build_mode、build_runner（runner 標籤）、build_apt、scan_runner、scan_apt、arch。
    預設：arch＝arm64；build.runner＝arm64；scan.tools＝sbom-only；scan.runner＝amd64（scan 只匯入與讀映像、不執行目標平台的程式，所以不跟著 arch）。"""
    b, sc = config.get("build") or {}, config.get("scan") or {}
    return {"build_mode": b["mode"], "build_runner": RUNNER_LABELS[b.get("runner", "arm64")], "build_apt": list(b.get("apt") or []),
            "scan_runner": RUNNER_LABELS[sc.get("runner", "amd64")], "scan_apt": list(sc.get("apt") or []), "scan_tools": sc.get("tools", "sbom-only"),
            "arch": config.get("arch", "arm64"),
            # 傳給 scan-flash-package.sh／cra-scan.py 的 --platform：scan.platform_arg，沒寫就是平台名稱（驗證時已確認是工具認得的值）
            "scan_platform_arg": sc.get("platform_arg") or config.get("platform")}


def validate_platform_config(doc, name=None):
    """回傳錯誤清單。"""
    if not isinstance(doc, dict):
        return ["platform.yml 不是 mapping"]
    errs = []
    if doc.get("schema") != 1:
        errs.append("schema 必須是 1")
    plat = doc.get("platform")
    if not (isinstance(plat, str) and PLATFORM_RE.match(plat)):
        errs.append("platform 格式不合法")
    elif name is not None and plat != name:
        errs.append("platform 必須和資料夾名稱相同")
    if not _nonempty_str(doc.get("description")):
        errs.append("缺 description")
    build = doc.get("build")
    if not isinstance(build, dict) or build.get("mode") not in BUILD_MODES:
        errs.append("build.mode 必須是 %s" % "／".join(BUILD_MODES))
    else:
        for k in build:
            if k not in ("mode", "apt", "runner"):
                errs.append("build 不認得的鍵 %s" % k)
        _validate_apt(build.get("apt"), "build.apt", errs)
        if "runner" in build and build["runner"] not in ARCHES:
            errs.append("build.runner 必須是 %s" % "／".join(ARCHES))
    if "arch" in doc and doc["arch"] not in ARCHES:
        errs.append("arch 必須是 %s" % "／".join(ARCHES))
    rs = doc.get("raw_sectors", {"enabled": False})
    if not isinstance(rs, dict) or not isinstance(rs.get("enabled"), bool):
        errs.append("raw_sectors.enabled 必須是 true／false")
    layers = doc.get("layers")
    if not isinstance(layers, dict):
        errs.append("缺 layers")
    else:
        for k in layers:
            if k not in ("bsp", "os", "host-tool", "default"):
                errs.append("layers 不認得的鍵 " + str(k))
        if layers.get("default", "os") != "os":
            errs.append("layers.default 目前只能是 os")
        # os 的規則是選用：分層模組（layers.py）用它明確宣告「這些路徑／套件是 OS」；沒列的非套件元件標 unknown，不默默歸成 os
        for layer in ("bsp", "os", "host-tool"):
            body = layers.get(layer)
            if body is None:
                continue
            if not isinstance(body, dict):
                errs.append("layers.%s 必須是 mapping" % layer)
                continue
            for k in body:
                # os 只有 paths：套件沒列在 bsp／host-tool 的本來就是 os（D-027）
                if k not in (("paths",) if layer == "os" else ("packages", "paths")):
                    errs.append("layers.%s 不認得的鍵 %s" % (layer, k))
            _validate_patterns(body.get("packages") if layer != "os" else None, "layers.%s.packages" % layer, "package", errs)
            _validate_patterns(body.get("paths"), "layers.%s.paths" % layer, "path", errs)
    pd = doc.get("project_defaults")
    if pd is not None:
        allowed = ("platform_version", "bsp_os_source", "kernel_source", "bootloader", "interfaces", "own_software", "platform_params")
        if not isinstance(pd, dict):
            errs.append("project_defaults 必須是 mapping")
        else:
            for k, v in pd.items():
                if k not in allowed:
                    errs.append("project_defaults 不認得的鍵 " + str(k))
                elif k in ("interfaces", "own_software"):
                    if not isinstance(v, list) or not all(_nonempty_str(x) for x in v):
                        errs.append("project_defaults.%s 必須是字串清單" % k)
                elif k == "platform_params":
                    if not isinstance(v, dict):
                        errs.append("project_defaults.platform_params 必須是 mapping")
                elif not _nonempty_str(v):
                    errs.append("project_defaults.%s 必須是非空字串" % k)
    scan = doc.get("scan")
    if scan is not None:
        if not isinstance(scan, dict):
            errs.append("scan 必須是 mapping")
        else:
            for k in scan:
                if k not in ("inputs_template", "platform_arg", "rootfs", "apt", "runner", "tools", "kernel_not_distro"):
                    errs.append("scan 不認得的鍵 %s" % k)
            _validate_apt(scan.get("apt"), "scan.apt", errs)
            if "tools" in scan and scan["tools"] not in SCAN_TOOLS:
                errs.append("scan.tools 必須是 %s" % "／".join(SCAN_TOOLS))
            if "runner" in scan and scan["runner"] not in ARCHES:
                errs.append("scan.runner 必須是 %s" % "／".join(ARCHES))
            if "kernel_not_distro" in scan:
                try:
                    check_not_distro(scan["kernel_not_distro"], "scan.kernel_not_distro")
                except ConfigError as e:
                    errs.append(str(e))
            for k in ("inputs_template", "platform_arg", "rootfs"):
                if k in scan and not (isinstance(scan[k], str) and re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*$", scan[k])):
                    errs.append("scan.%s 不合法" % k)
            parg = scan.get("platform_arg") or doc.get("platform")
            if isinstance(parg, str) and parg not in SCAN_PLATFORM_ARGS:
                errs.append("scan.platform_arg（沒寫時是平台名稱 %s）必須是掃描工具認得的 %s" % (parg, "／".join(SCAN_PLATFORM_ARGS)))
            if "rootfs" in scan and scan["rootfs"] != SCAN_ROOTFS:
                errs.append("scan.rootfs 目前只能是 %s（scan.sh 與 platform_scan 固定用這個名稱）" % SCAN_ROOTFS)
    return errs


def load_platform_config(platform, platforms_dir=PLATFORMS_DIR):
    """platform 是平台名稱（pipeline/platforms/<名稱>/platform.yml）或 platform.yml 的路徑。回傳驗證過的 dict。"""
    if os.sep in platform or platform.endswith(".yml"):
        path, name = platform, None
    else:
        if not PLATFORM_RE.match(platform):
            raise ConfigError("平台名稱格式不合法")
        path, name = os.path.join(platforms_dir, platform, "platform.yml"), platform
    doc = _load_yaml(path)
    errs = validate_platform_config(doc, name)
    if errs:
        raise ConfigError("platform.yml 欄位錯誤：" + "；".join(errs))
    return doc


def _match_any(value, patterns):
    return any(fnmatch.fnmatchcase(value, p) for p in patterns or [])


def classify_package(name, config):
    """套件名稱（不含版本）→ 層。bsp 優先於 host-tool；都不符合是 os。"""
    layers = config.get("layers", {})
    for layer in ("bsp", "host-tool"):
        if _match_any(name, (layers.get(layer) or {}).get("packages")):
            return layer
    return "os"


def classify_path(path, config):
    """檔案路徑（相對於 BSP 根目錄）→ 層。fnmatch 的 * 也會比對 /。"""
    layers = config.get("layers", {})
    for layer in ("bsp", "host-tool"):
        if _match_any(path, (layers.get(layer) or {}).get("paths")):
            return layer
    return "os"


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    pdir = PLATFORMS_DIR
    if "--platforms-dir" in argv:
        i = argv.index("--platforms-dir")
        pdir = argv[i + 1] if i + 1 < len(argv) else ""
        del argv[i:i + 2]
    try:
        if len(argv) == 2 and argv[0] == "validate":
            p, s = load_project_all(argv[1], pdir)
            todo = p["_todo"]
            print("validate: OK（%d 個版本%s）" % (len(s["releases"]), "；待填欄位：" + "、".join(todo) if todo else ""))
            return 0
        if len(argv) == 2 and argv[0] == "platform":
            c = load_platform_config(argv[1], pdir)
            print("platform: OK（%s）" % c["platform"])
            return 0
    except ConfigError as e:
        print("validate: FAIL（%s）" % e)
        return 1
    print("用法：project_config.py validate <專案資料夾> | platform <平台>", file=sys.stderr)
    return 64


if __name__ == "__main__":
    sys.exit(main())
