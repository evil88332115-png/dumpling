#!/usr/bin/env python3
"""no_vuln_data.py：SBOM 裡「可能沒有漏洞資料」的 deb 套件（未評估，NOT_ASSESSED），cra_report.py 每次產生文件時呼叫。

為什麼：晶片廠的映像會裝廠商自己建置的 deb（例如 Rockchip 的 chromium-x11 132.0.6834.83，Maintainer @rock-chips.com，
dpkg 標記 hold）。發行版（Debian／Ubuntu）的漏洞資料不認得這個名稱，Grype 與 Dependency-Track 都比對不到任何東西，套件就是 0 列。
0 列不代表沒有漏洞（CLAUDE.md：「未收錄」不等於「沒有問題」），所以這裡把它們列出來，標未評估，並在待確認事項表問產品工程師。
只增加可見度：不改 P1／P2／P3、不改任何排除規則、不改漏洞資料狀態與發行閘門。

輸入（都是 cra_report 已有的資料；不連網、不下載）：
  SBOM 的 deb 元件（Syft 的 publisher＝dpkg 的 Maintainer；沒有時用 author、supplier.name）；
  pkgdb（pkg_why.py extract 的 dpkg-status；每一個段落的 Maintainer 和 SBOM 的 publisher 合起來用，另讀 Origin 與 Status 的 hold）；
  有沒有漏洞資料：這次報告的漏洞列（DT findings、只有 Grype 的列；含已接受、發行版已修補的列）的元件名稱與安裝的二進位套件，
  以及 scan/grype.json 裡 deb 比對的套件名稱與原始碼套件（upstreams）。任何一個比對到這個套件（或它的原始碼套件）就算有資料，不列。
訊號（只用這些；每個列出的套件寫出用到的訊號）：
  vendor_maintainer：Maintainer（或 Origin）不是發行版的。發行版＝信箱網域是 debian.org、debian.net、ubuntu.com、canonical.com、
    launchpad.net（含子網域，例如 lists.debian.org、lists.ubuntu.com），或 Origin 是 Debian／Ubuntu。只有真的發行版信箱網域才算：
    名稱是 Debian／Ubuntu 但沒有網域或網域不是發行版的（例如 dh_make 預設的 ubuntu@<本機網域>、debian@localhost）不算。
    注意：Debian 的個人維護者也常用個人信箱（gmail.com 等），所以只有這個訊號時只算「可能」。
  distro_name_other_domain：名稱以 Debian／Ubuntu 開頭、信箱網域卻不是發行版的（或沒有網域）→ 列為「可能」（不管版本有沒有修訂號）。
  distro_maintainer_no_revision：Maintainer 是發行版的，但沒有任何漏洞資料而且版本沒有修訂號（no_distro_revision 的同一個條件）→「可能」
    （保留 Debian 維護者欄位的廠商分支，例如自己重編的 chromium）；再加上 dpkg hold（held）→「很可能」。
    Maintainer 是發行版的、版本有發行版的修訂號、沒有 hold、沒有漏洞資料的套件不列：只因為維護者假設發行版的資料涵蓋它，
    **沒有用名稱確認**（文件照實寫）。同一個發行版的套件太少或修訂號比例不夠，沒辦法判斷 no_distro_revision 時，發行版維護、沒有
    修訂號的套件另計（distro_no_revision_unchecked），文件寫出跳過的原因。
  發行版的＝Maintainer 的每一個信箱網域都是發行版的（Maintainer 可以有多個地址，只要一個不是就不算），而且 Origin 不是別的廠商。
    Origin 只能讓套件「不是發行版的」（origin 訊號），不能讓套件變成發行版的：Origin 寫 Debian、Maintainer 是廠商的，照樣列出。
  no_maintainer：這個映像其他套件都有 Maintainer，這個沒有（Debian／Ubuntu 的套件一定有 Maintainer）。
  no_distro_revision：版本沒有發行版的修訂號（epoch 後面沒有 -revision，也沒有 +debNuM、~debN、ubuntu、bpo、build 等標記），
    而同一個發行版（purl 的 distro）的其他 deb 套件至少 REV_SHARE 有（而且至少 REV_MIN 個）。
  same_vendor_domain：維護者網域是「廠商網域」（見下）的套件。
  廠商網域：不是免費信箱（FREEMAIL），而且至少 SEED_MIN 個 vendor_maintainer＋no_distro_revision 的套件（種子）用它，或其中一個種子是
    dpkg hold，或有 origin 或 NVIDIA 訊號的套件用它（這兩種一個就夠）。只有一個、沒有 hold 的種子不算（Debian 個人維護者的原生套件）。
  held：dpkg 的 Status 是 hold（apt 不會更新）。沒有漏洞資料的 hold 套件不管維護者與修訂號，至少列為「可能」（廠商常 hold 自己
    重編的套件，版本可能和發行版不同）；held＋distro_maintainer_no_revision 或 held＋vendor_revision_suffix → 很可能；也是廠商網域的種子
    （一個 hold 的種子就夠）。
  有漏洞資料、但「沒有資料時會列出」的套件（任何上面的訊號：hold、沒有裝完、沒有修訂號、廠商字尾或標記、維護者不是發行版…）不列，
    改記在 vendor_with_data（只靠名稱對到發行版的資料，要確認那是不是發行版的建置）。
  完整清單：write_list 把列出的套件與 vendor_with_data 全部寫到 Reports 的 packages-without-vuln-data.csv（文件、summary 與待確認事項表
    只寫前幾個名稱，指向這個檔案）。
  vendor_revision_suffix：Debian 修訂號（最後一個 - 後面）有發行版以外的字母字尾（例如 1rockchip1、1+rk1）。發行版的寫法不算：
    debNuM、debN、bpoN、ubuntu、build、nmu、esm、fips、exp、cross、fakesync、+bN（binNMU）、really、dfsg、ds。至少「可能」。
    已知的漏洞：這些字被當作整串移除，所以 1ds1、1+exp1、1build1、1esm 這類寫法也不算廠商字尾（可以接受）。
  vendor_version_tag：上游版本（最後一個 - 前面）裡 + 或 ~ 後面的字母標記不是常見的發行版或上游寫法（UPSTREAM_OK：dfsg、ds、really、
    repack、git、svn、snapshot、rc、beta…）→ 至少「可能」（例如 1.0+rk1-1）。
  not_fully_installed：dpkg 的狀態不是 installed（unpacked、half-configured、half-installed、triggers-*、config-files）→ 至少「可能」。
    hold 與 Maintainer、Origin 從 pkgdb 的**每一個**段落讀（pkg_why.PkgDB.all_paras，含沒有裝完的、同名多架構的）。
沒有用的訊號：發行版漏洞資料的套件名稱索引（Grype DB 的套件名稱、OSV 發行版鏡像、Ubuntu CVE Tracker）。sca-scan 的輸出裡沒有這種
  索引（scan/ubuntu-status.json、scan/distro-recheck.json、scan/usn-cves.json 只收這次 DT findings 裡的 CVE），所以「名稱不在發行版資料裡」
  沒有辦法離線確認；要的話 sca-scan 要另外輸出索引（之後的變更）。
分級：很可能（likely）＝no_maintainer、origin、NVIDIA 的兩個訊號、維護者網域是廠商網域；可能（possible）＝其他列出的
  （只有 vendor_maintainer、只有一個種子的 vendor_maintainer＋no_distro_revision、distro_name_other_domain；沒有任何 Maintainer 資料時
  只有 no_distro_revision）。不確定時列出、寫原因，不藏起來。
NVIDIA：C-nvidia-bulletins（tools/pilot/lib/nvidia_bulletins.py match）只評估 Jetson Linux，也就是 nvidia-l4t-* 套件的版本。
  nvidia-l4t-* 在該階段 OK 時不列（另計數），不是 OK 時列出（nvidia_bulletins_not_ok）。其他 NVIDIA 的 deb（publisher 含 NVIDIA，
  或 cra_report.nvidia_debs；例如 CUDA、cuDNN、TensorRT）公告比對沒有評估，一律列出（nvidia_not_jetson_linux）。
隱私：只寫「已知的廠商網域」：設定檔的 sbom.vendor_domains、sbom.flash_package_supplier 的 email／url、manufacturer.email 的網域
  （config_domains），以及 nvidia.com；發行版的網域（debian.org 等，是組織不是個人）也照寫。其他一律「(not shown)」（免費信箱或只有
  一個套件的寫「(personal)」），組的鍵也不寫：用網域的 sha256 前 8 碼（likely:vendor-xxxxxxxx），分組照樣用網域。不寫姓名與信箱。
不可信的輸入：Maintainer 是 pkgdb 每一個段落的 Maintainer 加上 SBOM 的 publisher 合起來（任何一個地址不是發行版的就不算發行版的）；
  解析最多 MAINT_SCAN 個字、最多 MAINT_ADDRS 個地址（線性時間，不回溯）；超過的當作「不只是發行版的」（maintainer_too_long，至少可能）。
已知的限制（啟發式，只用兩個廠商映像調整過）：
  - HEX_HASH 與 UPSTREAM_OK 會放過看起來像雜湊或上游字的廠商標記（例如 1.0+abc1234-1、+test.rockchip）；
  - 每個 + 或 ~ 標記只看第一段字母（例如 1.0+dfsg1rk1-1 只看 dfsg）；
  - 修訂號與上游標記的允許清單是啟發式，換別的發行版或廠商時要再對一次。
狀態：GAP（沒有任何 Maintainer 資料：廠商套件分辨不出來，有列出的也一樣；或沒有任何比對結果；或輸入格式錯、分類失敗：failed()）；
  NOT_ASSESSED（有列出的套件）；OK（沒有列出，Maintainer 資料可用）；NOT_RUN（SBOM 沒有 deb 套件或沒有 SBOM）。輸出排序固定（同樣的輸入結果相同）。只用標準函式庫。
"""
import hashlib
import re
from collections import Counter

DISTRO_DOMAINS = ("debian.org", "debian.net", "ubuntu.com", "canonical.com", "launchpad.net")
DISTRO_NAME = re.compile(r"^\s*(debian|ubuntu)\b", re.I)
DISTRO_ORIGINS = ("debian", "ubuntu")
FREEMAIL = ("gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com", "gmx.de", "gmx.net", "web.de",
            "mail.ru", "posteo.net", "posteo.de", "protonmail.com", "proton.me", "icloud.com", "disroot.org", "riseup.net", "qq.com",
            "163.com", "126.com", "yandex.ru", "aol.com")
REV_MARK = re.compile(r"[+~.](deb\d|bpo\d)|(?<=\d)build\d+$|ubuntu\d", re.I)   # 數字後面、結尾的 buildN：Ubuntu 的 rebuild（3.6.3build1、7.7+11build3）
DISTRO_REV_TOKENS = re.compile(r"deb\d+u\d+|deb\d+|bpo\d+|ubuntu|build|nmu|esm|fips|exp|cross|fakesync|\+b(?=\d)|really|dfsg|ds")
# 上游版本（最後一個 - 前面）裡 + 或 ~ 後面的字母標記，發行版與上游常用、不算廠商標記的
UPSTREAM_OK = frozenset(("dfsg", "ds", "really", "repack", "git", "svn", "bzr", "hg", "cvs", "snapshot", "snap", "rc", "beta", "alpha",
                         "pre", "dev", "post", "final", "b", "deb", "bpo", "ubuntu", "build", "nmu", "esm", "fips", "exp", "cross",
                         "fakesync", "debian", "is", "r", "p", "a", "gh", "orig", "nightly", "trunk", "next", "lts", "ga", "u", "g",
                         "real", "samba", "tests", "test", "prealpha", "prebeta"))
LIST_NAME = "packages-without-vuln-data.csv"
LIST_COLUMNS = ("分類", "套件", "版本", "分級", "訊號", "dpkg hold", "dpkg 狀態", "維護者", "組")
REV_SHARE, REV_MIN = 0.8, 10
DOMAIN_HEAD = re.compile(r"[A-Za-z0-9.-]{1,253}")
FIELD_MAX, MAINT_MAX = 200, 512
MAINT_SCAN, MAINT_ADDRS = 65536, 256     # Maintainer 最多解析這麼多個字、這麼多個地址；超過 → maintainer_too_long
HEX_HASH = re.compile(r"[0-9a-f]{7,}")
SEED_MIN = 2                 # 廠商網域：至少這麼多個 vendor_maintainer＋no_distro_revision 的套件（或一個 hold 的）
EXAMPLES_MAX = 20
BUILTIN_VENDOR_DOMAINS = ("nvidia.com",)
SIGNAL_TEXT = {
    "vendor_maintainer": "Maintainer/Origin is not the distribution's",
    "no_maintainer": "no Maintainer (every other package has one; Debian/Ubuntu packages always do)",
    "no_distro_revision": "version has no distribution revision (most other packages of this distribution have one)",
    "same_vendor_domain": "same maintainer domain as a package that is likely without data",
    "origin": "dpkg Origin is not Debian/Ubuntu",
    "nvidia_bulletins_not_ok": "Jetson Linux package (nvidia-l4t-*): the NVIDIA bulletin check is not OK",
    "nvidia_not_jetson_linux": "NVIDIA package outside Jetson Linux (for example CUDA, cuDNN, TensorRT): the NVIDIA bulletin check "
                               "only evaluates nvidia-l4t-*",
    "distro_name_other_domain": "maintainer name starts with Debian/Ubuntu but there is no distribution mail domain (for example a "
                                "dh_make default such as ubuntu@<本機網域>)",
    "distro_maintainer_no_revision": "Maintainer is the distribution's, but the version has no distribution revision and no matcher "
                                     "reported anything (possibly a vendor build that kept the distribution's Maintainer)",
    "held": "dpkg hold (apt does not upgrade it; vendors often hold their own rebuilds)",
    "maintainer_too_long": "the Maintainer field is too long to parse completely (more than 65536 characters or 256 addresses)",
    "vendor_revision_suffix": "the Debian revision has a suffix that is not a distribution pattern (for example 1rockchip1, 1+rk1)",
    "vendor_version_tag": "the upstream part of the version has a tag that is not a distribution or upstream pattern (for example "
                          "1.0+rk1-1)",
    "not_fully_installed": "dpkg status is not fully installed (unpacked, half-configured, half-installed, triggers-*, config-files)",
}
EXCLUDED_TEXT = {
    "distro_maintained": "maintained by the distribution and with a distribution revision (assumed to be covered by the "
                         "distribution's advisory data because of the Maintainer; NOT checked by package name, see `distro_name_index`)",
    "has_vulnerability_data": "with vulnerability data (a row or a Grype match)",
    "has_vulnerability_data_vendor_maintainer": "not maintained by the distribution but with vulnerability data (matched by name; "
                                                "check that the distribution's advisories apply to that build)",
    "has_vulnerability_data_held_or_vendor_revision": "maintained by the distribution, with vulnerability data, but dpkg-held, not "
                                                      "fully installed, without a distribution revision or with a vendor version tag "
                                                      "(matched by name; check that it is the distribution's build)",
    "distro_no_revision_unchecked": "maintained by the distribution, version without a distribution revision, but the revision check "
                                    "was skipped because this distribution has fewer than 10 other packages in the SBOM or fewer than "
                                    "80% of them have a revision (NOT listed and NOT checked)",
    "nvidia_bulletins": "Jetson Linux packages (nvidia-l4t-*) covered by the NVIDIA bulletin check (OK)",
    "no_signal": "without any signal",
}
SIGNALS_USED = ("vendor_maintainer", "distro_name_other_domain", "distro_maintainer_no_revision", "no_maintainer", "no_distro_revision",
                "vendor_revision_suffix", "vendor_version_tag", "not_fully_installed", "maintainer_too_long", "same_vendor_domain",
                "origin", "held",
                "nvidia_bulletins_not_ok", "nvidia_not_jetson_linux")
VENDOR_BUILD = ("distro_maintainer_no_revision", "vendor_revision_suffix", "vendor_version_tag")      # held＋這些 → 很可能
STRONG = ("no_maintainer", "origin", "nvidia_bulletins_not_ok", "nvidia_not_jetson_linux")
NOT_USED = {"distro_name_index": "no package-name index of the distribution's advisory data (Grype DB package names, OSV distribution "
                                 "mirror, Ubuntu CVE Tracker) in the scan output: scan/ubuntu-status.json, scan/distro-recheck.json and "
                                 "scan/usn-cves.json only cover the CVEs of this scan's findings"}


def clip(s):
    s = re.sub(r"[\x00-\x1f\x7f]", " ", str(s or "")).strip()
    return s[:FIELD_MAX]


def domains_of(maint):
    """Maintainer → 每一個信箱網域（小寫、去掉結尾的點、不重複、照出現順序）。最多解析 MAINT_SCAN 個字、MAINT_ADDRS 個地址；每個 @ 後面只看網域字元
    （每個最多 253 個字，不回溯）。"""
    s = str(maint or "")[:MAINT_SCAN]
    out = []
    i = s.find("@")
    while i >= 0 and len(out) < MAINT_ADDRS:
        m = DOMAIN_HEAD.match(s, i + 1)
        d = m.group(0).strip(".").lower() if m else ""
        if "." in d and ".." not in d and d not in out:
            out.append(d)
        i = s.find("@", i + 1)
    return out


def domain_of(maint):
    """Maintainer → 代表的網域：第一個不是發行版的網域；都是發行版的時候第一個；沒有 → None。"""
    ds = domains_of(maint)
    return next((d for d in ds if not is_distro_domain(d)), ds[0] if ds else None)


def domain_matches(d, known):
    return bool(d) and any(d == k or d.endswith("." + k) for k in known)


def config_domains(cfg):
    """設定檔裡已知的廠商網域（小寫、排序）：sbom.vendor_domains、sbom.flash_package_supplier 的 email／url、manufacturer.email。"""
    out = set()
    c = cfg if isinstance(cfg, dict) else {}
    sb = c.get("sbom") if isinstance(c.get("sbom"), dict) else {}
    vals = list(sb.get("vendor_domains") or []) if isinstance(sb.get("vendor_domains"), list) else []
    fps = sb.get("flash_package_supplier") if isinstance(sb.get("flash_package_supplier"), dict) else {}
    man = c.get("manufacturer") if isinstance(c.get("manufacturer"), dict) else {}
    for v in vals + [fps.get("email"), fps.get("url"), man.get("email")]:
        if not isinstance(v, str) or not v.strip():
            continue
        v = v.strip()[:MAINT_MAX]
        d = domain_of(v) if "@" in v else None
        if d is None:
            host = re.sub(r"^[a-z][a-z0-9+.-]*://", "", v.lower()).split("/", 1)[0].split(":", 1)[0]
            m = DOMAIN_HEAD.fullmatch(host)
            d = host.strip(".") if m and "." in host and ".." not in host else None
        if d:
            out.add(d[4:] if d.startswith("www.") else d)
    return sorted(out)


def is_distro_domain(d):
    return bool(d) and any(d == x or d.endswith("." + x) for x in DISTRO_DOMAINS)


def vendor_revision_suffix(v):
    """Debian 修訂號（epoch 之後、最後一個 - 後面）去掉發行版的寫法（DISTRO_REV_TOKENS）以後還有字母 → True。沒有修訂號 → False。"""
    v = str(v or "")[:FIELD_MAX]
    rest = v.split(":", 1)[1] if re.match(r"^\d+:", v) else v
    if "-" not in rest:
        return False
    rev = rest.rsplit("-", 1)[1].lower()
    return bool(re.search(r"[a-z]", DISTRO_REV_TOKENS.sub("", rev)))


def vendor_version_tag(v):
    """上游版本（epoch 之後、最後一個 - 前面；沒有 - 時是整個版本）裡 + 或 ~ 後面的字母標記不在 UPSTREAM_OK → True（例如 1.0+rk1-1）。"""
    v = str(v or "")[:FIELD_MAX].lower()
    rest = v.split(":", 1)[1] if re.match(r"^\d+:", v) else v
    up = rest.rsplit("-", 1)[0] if "-" in rest else rest
    for t in re.findall(r"[+~]([0-9a-z]+)", up):
        if t.isdigit() or HEX_HASH.fullmatch(t):          # 數字、git 的雜湊（7 個字以上的十六進位，例如 +ed310a0）
            continue
        word = re.search(r"[a-z]+", t).group(0)
        if word not in UPSTREAM_OK:
            return True
    return False


def csv_safe(c):
    """試算表會把 = + - @ tab \\r 開頭的格子當公式：前面加 '（內容來自掃描資料，不可信）。"""
    c = str(c)
    return "'" + c if c[:1] in ("=", "+", "-", "@", "\t", "\r", "＝", "＋", "－", "＠") else c


def has_revision(v):
    v = str(v or "")
    rest = v.split(":", 1)[1] if re.match(r"^\d+:", v) else v
    return "-" in rest or bool(REV_MARK.search(rest))


def purl_qualifier(purl, key):
    q = str(purl or "").split("#", 1)[0].partition("?")[2]
    for kv in q.split("&"):
        k, _, val = kv.partition("=")
        if k == key:
            return val
    return None


def purl_namespace(purl):
    m = re.match(r"^pkg:deb/([^/]+)/", str(purl or ""))
    return m.group(1).lower() if m else "?"


def source_of(c):
    props = c.get("properties")
    for p in props if isinstance(props, list) else []:
        if isinstance(p, dict) and p.get("name") == "syft:metadata:source" and isinstance(p.get("value"), str):
            return p["value"].split(" ", 1)[0].strip() or None
    up = purl_qualifier(c.get("purl"), "upstream")
    return up.split("%40", 1)[0].split("@", 1)[0] if up else None


def sbom_maintainer(c):
    for k in ("publisher", "author"):
        if isinstance(c.get(k), str) and c[k].strip():
            return c[k]
    s = c.get("supplier")
    if isinstance(s, dict) and isinstance(s.get("name"), str) and s["name"].strip():
        return s["name"]
    return None


def known_names(rows, grype):
    """有漏洞資料的套件名稱（小寫）：deb 漏洞列（purl 是 pkg:deb/ 或 ptype deb）的元件、安裝的二進位套件；grype.json 的 deb 比對的套件
    與原始碼套件。其他生態系的列（例如 dist-packages 的 Python 模組）不算：名稱相同不代表是同一個 deb。"""
    out = set()
    for r in rows or []:
        if not isinstance(r, dict) or not (str(r.get("purl") or "").startswith("pkg:deb/") or r.get("ptype") == "deb"):
            continue
        ia = r.get("installed_as")
        for n in [r.get("name"), r.get("component")] + (list(ia) if isinstance(ia, (list, tuple)) else []):
            if isinstance(n, str) and n:
                out.add(n.lower())
        p = r.get("purl")
        if isinstance(p, str) and p.startswith("pkg:deb/"):
            m = re.match(r"^pkg:deb/[^/]+/([^@?#]+)", p)
            if m:
                out.add(m.group(1).lower())
    ms = grype.get("matches") if isinstance(grype, dict) else None
    for m in ms if isinstance(ms, list) else []:
        a = m.get("artifact") if isinstance(m, dict) else None
        if not isinstance(a, dict) or a.get("type") != "deb":
            continue
        if isinstance(a.get("name"), str):
            out.add(a["name"].lower())
        ups = a.get("upstreams")
        for u in ups if isinstance(ups, list) else []:
            if isinstance(u, dict) and isinstance(u.get("name"), str):
                out.add(u["name"].lower())
    return out


def failed(reason):
    """分類失敗（輸入格式錯等）時的結果：GAP，不列套件（cra_report 照樣寫小節與 summary）。"""
    return {"status": "GAP", "count": 0, "likely": 0, "possible": 0, "held": 0, "examples": [], "packages": [], "groups": [],
            "signals": {"used": list(SIGNALS_USED), "not_used": dict(NOT_USED)}, "deb_packages": None, "maintainer_source": None,
            "hold_known": None, "excluded": {}, "vendor_with_data": {"count": 0, "examples": [], "by_reason": {}}, "name_only": [],
            "detail": [f"the check could not be completed ({clip(reason)}): packages without vulnerability data are NOT identified"]}


def classify(pkgs, rows=(), grype=None, db=None, nvdebs=(), nvidia_ok=False, have_matcher=True, vendor_domains=()):
    """SBOM 的套件元件 → 結果（dict；見模組說明）。db：pkg_why.PkgDB 或 None。vendor_domains：config_domains(cfg)（可以印出的網域）。"""
    debs = {}
    for c in pkgs or []:
        if not isinstance(c, dict) or not str(c.get("purl") or "").startswith("pkg:deb/") or not isinstance(c.get("name"), str):
            continue
        debs.setdefault((c["name"], str(c.get("version") or "")), c)
    res = {"status": "NOT_RUN", "count": 0, "likely": 0, "possible": 0, "examples": [], "packages": [], "groups": [],
           "signals": {"used": list(SIGNALS_USED), "not_used": dict(NOT_USED)}, "deb_packages": len(debs),
           "maintainer_source": None, "hold_known": db is not None, "excluded": {}, "detail": []}
    if not debs:
        res["detail"].append("no Debian/Ubuntu (pkg:deb) package in the SBOM")
        return res
    known = known_names(rows, grype)
    nvset = set(nvdebs or ())
    allp = getattr(db, "all_paras", None) if db is not None else None
    pk = getattr(db, "pkgs", None) if db is not None else None
    info = []
    src_used = Counter()
    for (name, ver), c in sorted(debs.items()):
        # pkgdb 的每一個段落（含沒有裝完的、同名多架構的）；舊的 PkgDB 沒有 all_paras 時用 pkgs（只有裝好的）
        paras = [p for p in ((allp.get(name) if isinstance(allp, dict) else None) or []) if isinstance(p, dict)]
        if not paras and isinstance(pk, dict) and isinstance(pk.get(name), dict):
            paras = [pk[name]]
        # 每一個段落的 Maintainer 加上 SBOM 的 publisher 合起來（同名多架構可能不同；任何一個不是發行版的就不算發行版的）
        pm = [p["Maintainer"] for p in paras if isinstance(p.get("Maintainer"), str) and p["Maintainer"].strip()]
        sm = sbom_maintainer(c)
        parts = sorted({str(x) for x in pm + ([sm] if sm else [])})      # 排序：段落順序不影響結果
        if pm:
            src_used["pkgdb"] += 1
        elif parts:
            src_used["sbom"] += 1
        raw = ", ".join(str(x) for x in parts)
        too_long = len(raw) > MAINT_SCAN or raw.count("@") > MAINT_ADDRS
        maint = raw[:MAINT_SCAN] if raw else None        # 不可信：解析有上限
        origins = [str(p["Origin"])[:MAINT_MAX] for p in paras if isinstance(p.get("Origin"), str) and p["Origin"].strip()]
        origin = next((o for o in origins if o.strip().lower() not in DISTRO_ORIGINS), origins[0] if origins else None)
        sts = [str(p.get("Status") or "").split() for p in paras]
        states = sorted({(st[2] if len(st) == 3 else "unknown") for st in sts if not (len(st) == 3 and st[2] == "installed")})
        info.append({"name": name, "version": ver, "purl": c.get("purl"), "maint": maint, "domain": domain_of(maint), "too_long": too_long,
                     "name_distro": bool(parts) and all(DISTRO_NAME.match(x) for x in parts),
                     # 每一個 Maintainer（段落、SBOM）都至少有一個網域、而且全部是發行版的：沒有可用網域的（build@localhost、只有名字）不算
                     "parts_distro": bool(parts) and all(ds and all(is_distro_domain(d) for d in ds) for ds in map(domains_of, parts)),
                     "domains": domains_of(maint), "origin": origin,
                     "held": any(st[:1] == ["hold"] for st in sts) if paras else None, "states": [clip(x) for x in states],
                     "source": source_of(c), "ns": purl_qualifier(c.get("purl"), "distro") or purl_namespace(c.get("purl"))})
    have_maint = any(x["maint"] for x in info)
    res["maintainer_source"] = "+".join(k for k in ("pkgdb", "sbom") if src_used[k]) or None
    # 同一個發行版的修訂號比例（不含自己）
    by_ns = Counter(x["ns"] for x in info)
    rev_ns = Counter(x["ns"] for x in info if has_revision(x["version"]))
    dom_count = Counter(x["domain"] for x in info if x["domain"])
    excl, vendor_with_data = Counter(), []
    cand = []
    for x in info:
        ori = (x["origin"] or "").strip().lower()
        dom_distro = x["parts_distro"]
        name_distro = x["name_distro"]          # 每一個 Maintainer（段落、SBOM）的名稱都是 Debian／Ubuntu
        origin_vendor = bool(ori) and ori not in DISTRO_ORIGINS
        # 任何一個地址不是發行版的、沒有發行版網域，或 Maintainer 長到不能完整解析
        maint_vendor = bool(x["maint"]) and (not dom_distro or x["too_long"])
        dom_distro = dom_distro and not x["too_long"]
        # 發行版的：Maintainer 的每一個網域都是發行版的，而且 Origin 不是別的廠商（Origin 寫 Debian 不能讓廠商的 Maintainer 變成發行版的）
        distro = bool(x["maint"]) and dom_distro and not origin_vendor
        held = x["held"] is True
        has_data = x["name"].lower() in known or bool(x["source"] and x["source"].lower() in known)
        jl = x["name"].lower().startswith("nvidia-l4t-")      # nvidia_bulletins.py match 只評估這些
        # 其他 NVIDIA 的 deb：發行版維護的不算（例如 Debian 的 pkg-nvidia 團隊打包的套件，維護者字串也有 nvidia）
        nv_other = not jl and not distro and ((x["purl"] or "").split("#", 1)[0].split("?", 1)[0] in nvset
                                              or "nvidia" in (x["maint"] or "").lower())
        if jl and nvidia_ok and not has_data:
            excl["nvidia_bulletins"] += 1
            continue
        norev = not has_revision(x["version"])
        n_other = by_ns[x["ns"]] - 1
        r_other = rev_ns[x["ns"]] - (0 if norev else 1)
        rev_ok = n_other >= REV_MIN and r_other >= REV_SHARE * n_other      # 這個發行版能不能用「有沒有修訂號」判斷
        rev_signal = norev and rev_ok
        sig = []
        if jl and not nvidia_ok:
            sig.append("nvidia_bulletins_not_ok")
        if nv_other:
            sig.append("nvidia_not_jetson_linux")
        if origin_vendor:
            sig.append("origin")
        if maint_vendor:
            sig.append("distro_name_other_domain" if name_distro else "vendor_maintainer")
        if have_maint and not x["maint"]:
            sig.append("no_maintainer")
        if x["too_long"]:
            sig.append("maintainer_too_long")
        if rev_signal and not distro:
            sig.append("no_distro_revision")
        if distro and rev_signal:
            sig.append("distro_maintainer_no_revision")
        if vendor_revision_suffix(x["version"]):
            sig.append("vendor_revision_suffix")
        if vendor_version_tag(x["version"]):
            sig.append("vendor_version_tag")
        if x["states"]:
            sig.append("not_fully_installed")
        if held:
            sig.append("held")
        if has_data:
            # 只靠名稱對到發行版的資料：沒有資料時會列出的（有任何訊號）記在 vendor_with_data，要確認那是不是發行版的建置
            if maint_vendor or origin_vendor:
                excl["has_vulnerability_data_vendor_maintainer"] += 1
            elif sig:
                excl["has_vulnerability_data_held_or_vendor_revision"] += 1
            else:
                excl["has_vulnerability_data"] += 1
            if sig:
                vendor_with_data.append((x, sig))
            continue
        if distro and not (jl or nv_other) and not sig:
            excl["distro_no_revision_unchecked" if norev and not rev_ok else "distro_maintained"] += 1
            continue
        if not sig:
            excl["no_signal"] += 1
            continue
        cand.append((x, sig))
    # 廠商網域：至少 SEED_MIN 個種子（vendor_maintainer＋no_distro_revision），或一個 hold 的種子，或一個 origin／NVIDIA 的套件
    seeds, strong_dom = Counter(), set()
    for x, sig in cand:
        d = x["domain"]
        if not d or d in FREEMAIL:
            continue
        if {"vendor_maintainer", "no_distro_revision"} <= set(sig):
            seeds[d] += SEED_MIN if x["held"] else 1
        if set(sig) & {"origin", "nvidia_bulletins_not_ok", "nvidia_not_jetson_linux"}:
            strong_dom.add(d)
    group_domains = {d for d, n in seeds.items() if n >= SEED_MIN} | strong_dom      # 分組用（不一定印出）
    vds = vendor_domains if isinstance(vendor_domains, (list, tuple, set)) else ()
    printable = set(BUILTIN_VENDOR_DOMAINS) | {d.strip().lower() for d in vds if isinstance(d, str) and d.strip()}

    def label_of(d):
        """隱私規則：可以印出的網域（設定檔、nvidia.com、發行版的）才寫；其他 (personal)／(not shown)。"""
        if d and (domain_matches(d, printable) or is_distro_domain(d)):
            return "@" + d
        return "(personal)" if d and (d in FREEMAIL or dom_count[d] <= 1) else "(not shown)" if d else "(none)"
    out = []
    for x, sig in cand:
        if "vendor_maintainer" in sig and x["domain"] in group_domains:
            sig.append("same_vendor_domain")
        s_ = set(sig)
        level = "likely" if (s_ & set(STRONG) or "same_vendor_domain" in s_ or ("held" in s_ and s_ & set(VENDOR_BUILD))) else "possible"
        d = x["domain"]
        show = bool(d) and (domain_matches(d, printable) or is_distro_domain(d))
        label = label_of(d)
        if level != "likely":
            why = None
        elif d in group_domains:
            why = d if show else "vendor-" + hashlib.sha256(d.encode("utf-8")).hexdigest()[:8]
        else:
            why = ("no-maintainer" if "no_maintainer" in s_ else "origin" if "origin" in s_ else "held-distro-maintainer"
                   if "distro_maintainer_no_revision" in s_ else "held-vendor-revision" if s_ & set(VENDOR_BUILD) else "nvidia")
        out.append({"name": x["name"], "version": x["version"], "purl": clip(x["purl"]), "maintainer": label,
                    "origin": clip(x["origin"]) or None, "held": x["held"], "states": x["states"], "level": level,
                    "signals": [k for k in SIGNALS_USED if k in s_], "group": f"likely:{why}" if why else "possible"})
    out.sort(key=lambda p: (p["level"] != "likely", p["name"], p["version"]))
    groups = {}
    for p in out:
        groups.setdefault(p["group"], []).append(p)
    name_only = sorted(({"name": x["name"], "version": x["version"], "signals": [k for k in SIGNALS_USED if k in set(sig)],
                         "held": x["held"], "states": x["states"], "maintainer": label_of(x["domain"])} for x, sig in vendor_with_data),
                       key=lambda p: (p["name"], p["version"]))
    vw_reasons = Counter(r for p in name_only for r in p["signals"])
    res.update(count=len(out), likely=sum(1 for p in out if p["level"] == "likely"),
               possible=sum(1 for p in out if p["level"] == "possible"), packages=out,
               examples=[f"{p['name']} {p['version']}".strip() for p in out[:10]],
               held=sum(1 for p in out if p["held"]), excluded=dict(sorted(excl.items())),
               vendor_with_data={"count": len(name_only), "examples": [f"{p['name']} {p['version']}".strip() for p in name_only[:EXAMPLES_MAX]],
                                 "by_reason": dict(sorted(vw_reasons.items()))}, name_only=name_only,
               groups=[{"key": k, "level": k.split(":", 1)[0], "count": len(v),
                        "packages": [f"{p['name']} {p['version']}".strip() for p in v]}
                       for k, v in sorted(groups.items(), key=lambda kv: (kv[0] == "possible", -len(kv[1]), kv[0]))])
    if not have_maint:
        res["detail"].append("no maintainer data (no SBOM publisher/author/supplier and no pkgdb Maintainer): vendor packages cannot be "
                             "identified; only the version signal was used")
    if db is None:
        res["detail"].append("no pkgdb (dpkg-status): dpkg hold and Origin unknown")
    if not have_matcher:
        res["detail"].append("no vulnerability matcher result (no Dependency-Track findings and no Grype result): every package has 0 rows")
    # 沒有任何 Maintainer 資料或沒有比對結果：整體是 GAP（有列出的也是：廠商套件分辨不出來，清單不完整）
    res["status"] = "GAP" if not have_maint or not have_matcher else "NOT_ASSESSED" if out else "OK"
    return res


def section(res, table):
    """風險評估 8.1 的小節（英文，和文件其他部分一樣；標題附中文）。"""
    head = "#### Packages without vulnerability data – not assessed（沒有漏洞資料的套件（未評估））\n\n"
    st = res["status"]
    if st == "NOT_RUN":
        return head + "Not run: " + "; ".join(res["detail"] or ["no Debian/Ubuntu package in the SBOM"]) + ".\n"
    used = ", ".join(f"`{k}`" for k in res["signals"]["used"])
    sig = (f"Signals used: {used} (the Maintainer comes from {res['maintainer_source'] or 'nowhere: not available'}). Not used: "
           + "; ".join(f"`{k}` – {v}" for k, v in res["signals"]["not_used"].items()) + ".")
    ex = res.get("excluded") or {}
    exc = ("Not listed: " + ", ".join(f"{n} {EXCLUDED_TEXT.get(k, k)}" for k, n in ex.items()) + "." if ex else "")
    vw = res.get("vendor_with_data") or {}
    if vw.get("count"):
        exc += (" Matched only by name and possibly not the distribution's build (any of the signals above, for example not "
                "maintained by the distribution, dpkg-held, not fully installed, no distribution revision, or a vendor revision suffix "
                f"or version tag; the reasons per package are in `{LIST_NAME}`; confirm that the distribution's advisories apply): "
                + ", ".join(clip(x) for x in vw["examples"])
                + (f" and {vw['count'] - len(vw['examples'])} more" if vw["count"] > len(vw["examples"]) else "")
                + f" (all of them in `{LIST_NAME}`).")
    notes = " ".join(f"Note: {d}." for d in res["detail"])
    if not res["count"]:
        return head + (f"Status **{st}**: no Debian/Ubuntu package was identified as probably lacking vulnerability data. This does not "
                       "prove that every package is covered. " + sig + (" " + exc if exc else "") + (" " + notes if notes else "")) + "\n"
    rows = [[clip(p["name"]), clip(p["version"]) or "—", p["maintainer"],
             "hold" if p["held"] else ("unknown" if p["held"] is None else "install"), p["level"],
             "; ".join(SIGNAL_TEXT[s] for s in p["signals"])] for p in res["packages"]]
    return (head + f"Status **{st}**: {res['count']} Debian/Ubuntu "
            + ("package" if res["count"] == 1 else "packages") + f" ({res['likely']} likely, {res['possible']} possible) probably "
            "have no vulnerability data: no matcher reported anything for them, and the signals below suggest they were not built by "
            "the distribution, so the distribution's advisory data may not know them. They are NOT ASSESSED: having no rows in this "
            "report does not mean they have no known vulnerabilities. Their versions have to be checked by hand against the upstream "
            "or vendor security advisories (confirmation items `novuln:…` in `confirmation-items.md`; the same list with the packages "
            f"matched only by name is in `{LIST_NAME}`). " + sig
            + (" " + exc if exc else "") + (" " + notes if notes else "") + "\n\n"
            + table(["Package", "Version", "Maintainer domain", "dpkg status", "Level", "Why it is listed"], rows) + "\n")


def list_text(res):
    """完整清單（UTF-8 加 BOM 的 CSV；一列一個套件）：列出的套件（listed）與只靠名稱對到資料的（name_only_data）。排序固定。"""
    import csv
    import io
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow(LIST_COLUMNS)
    for kind, ps in (("listed", res.get("packages") or []), ("name_only_data", res.get("name_only") or [])):
        for p in ps:
            w.writerow([csv_safe(clip(c)) for c in (kind, p.get("name"), p.get("version"), p.get("level") or "", " ".join(p.get("signals") or []),
                                                    {True: "hold", False: "no", None: "unknown"}.get(p.get("held"), "unknown"),
                                                    " ".join(p.get("states") or []) or "installed",
                                                    str(p.get("maintainer") or "").lstrip("@"),       # 網域不加 @（不用跳脫）
                                                    p.get("group") or "")])
    return "\ufeff" + buf.getvalue()


def write_list(out, res):
    """Reports/packages-without-vuln-data.csv（每次都寫，沒有套件時只有標題列）。回傳檔名。"""
    from pathlib import Path
    (Path(out) / LIST_NAME).write_text(list_text(res), encoding="utf-8", newline="")
    return LIST_NAME


def summary(res):
    keys = ("status", "count", "likely", "possible", "held", "examples", "signals", "groups", "excluded", "vendor_with_data",
            "maintainer_source", "hold_known", "deb_packages", "detail", "file")
    return {k: res[k] for k in keys if k in res}
