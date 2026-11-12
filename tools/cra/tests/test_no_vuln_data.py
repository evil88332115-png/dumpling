"""沒有漏洞資料的套件（no_vuln_data.py；風險評估 8.1 節、summary.json 的 packages_without_vuln_data、待確認事項表）。合成的輸入，不含產品資料。"""
import csv
import io
import json
import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import no_vuln_data as nvd  # noqa: E402
from test_cra_report import EXAMPLE, finding, make_project, make_scan, run  # noqa: E402

DEBIAN = "pkg:deb/debian/{}@{}?arch=arm64&distro=debian-12"
DISTRO_MAINT = "Debian Foo Maintainers <pkg-foo@" "lists.debian.org>"


def comp(name, version, publisher=None, purl=None):
    c = {"type": "library", "name": name, "version": version, "purl": purl or DEBIAN.format(name, version)}
    if publisher:
        c["publisher"] = publisher
    return c


# 發行版的套件（有修訂號、Debian 的維護者）：讓「同一個發行版的其他套件大多有修訂號」成立
DISTRO = [comp(f"libdistro{i}", f"1.{i}-{i + 1}", DISTRO_MAINT) for i in range(12)]
VENDOR = [
    comp("chromium-x11", "132.0.6834.83", "Vendor Dev <dev@" "vendor.example>"),        # 廠商、沒有修訂號、dpkg hold → 很可能
    comp("libvendor-mpp1", "1.5.0-1", "Other Dev <other@" "vendor.example>"),           # 同一個廠商網域 → 很可能
    comp("libpersonal1", "1.2-3", "Joe Packager <joe@" "gmail.com>"),                   # 只有維護者不是發行版 → 可能
    comp("libheld1", "2.0-1", DISTRO_MAINT),                                         # 發行版的、有修訂號、但 hold → 可能
    comp("libmatched1", "0.9", "Vendor Dev <dev@" "vendor.example>"),                   # 廠商的但 Grype 有比對 → 不列
]
OPENSSL = comp("openssl", "3.0.15-1~deb12u1", "Debian OpenSSL Team <pkg-openssl-devel@" "alioth-lists.debian.net>")
FINDINGS = [finding("openssl", "3.0.15-1~deb12u1", "CVE-2025-0003", "NVD", "LOW", purl=DEBIAN.format("openssl", "3.0.15-1~deb12u1"))]
GRYPE = {"matches": [
    {"vulnerability": {"id": "CVE-2025-0003", "fix": {"state": "fixed", "versions": ["3.0.15-1~deb12u2"]}},
     "artifact": {"name": "openssl", "version": "3.0.15-1~deb12u1", "type": "deb"}},
    {"vulnerability": {"id": "CVE-2025-0007", "fix": {"state": "not-fixed", "versions": []}},
     "artifact": {"name": "libmatched1", "version": "0.9", "type": "deb", "upstreams": [{"name": "matched"}]}}]}


# 設定檔列出的廠商網域：只有這些（和 nvidia.com、發行版的網域）會印出
VCFG = json.loads(json.dumps(EXAMPLE))
VCFG["sbom"]["vendor_domains"] = ["vendor.example"]


def sbom(components):
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": "urn:uuid:1",
            "metadata": {"tools": {"components": [{"name": "syft", "version": "1.55.0"}]}}, "components": components}


def dpkg_status(d, held=("chromium-x11", "libheld1")):
    paras = []
    for c in DISTRO + VENDOR + [OPENSSL]:
        st = "hold ok installed" if c["name"] in held else "install ok installed"
        paras.append(f"Package: {c['name']}\nStatus: {st}\nArchitecture: arm64\nVersion: {c['version']}\n"
                     f"Maintainer: {c.get('publisher') or 'x'}")
    (d / "pkgdb").mkdir(parents=True, exist_ok=True)
    (d / "pkgdb" / "dpkg-status").write_text("\n\n".join(paras) + "\n", encoding="utf-8")


def scan_with(tmp, name, components, pkgdb=True, findings=FINDINGS, grype=GRYPE):
    base = tmp / name
    s = make_scan(base / "scan", findings=findings, grype=grype, sbom=sbom(components))
    if pkgdb:
        dpkg_status(base)
    return s


def section_of(md):
    h = "#### Packages without vulnerability data"
    assert h in md
    return md.split(h, 1)[1].split("\n### ", 1)[0]


def citems(reports):
    raw = (reports / "confirmation-items.csv").read_bytes().decode("utf-8-sig")
    rows = list(csv.reader(io.StringIO(raw)))
    return [dict(zip(rows[0], r)) for r in rows[1:]]


def test_vendor_package_listed_not_assessed(tmp_path):
    proj = make_project(tmp_path / "p", VCFG)
    r, s, reports = run(proj, scan_with(tmp_path, "r", DISTRO + VENDOR + [OPENSSL]))
    assert r.returncode in (0, 2), r.stderr
    x = s["packages_without_vuln_data"]
    assert x["status"] == "NOT_ASSESSED" and x["count"] == 4 and x["likely"] == 2 and x["possible"] == 2 and x["held"] == 2
    assert x["examples"] == ["chromium-x11 132.0.6834.83", "libvendor-mpp1 1.5.0-1", "libheld1 2.0-1", "libpersonal1 1.2-3"]
    assert [(g["key"], g["count"]) for g in x["groups"]] == [("likely:vendor.example", 2), ("possible", 2)]
    assert "distro_name_index" in x["signals"]["not_used"] and "vendor_maintainer" in x["signals"]["used"]
    assert x["excluded"] == {"distro_maintained": 12, "has_vulnerability_data": 1, "has_vulnerability_data_vendor_maintainer": 1}
    assert x["maintainer_source"] == "pkgdb" and x["hold_known"] is True and x["deb_packages"] == 18
    assert x["vendor_with_data"] == {"count": 1, "examples": ["libmatched1 0.9"],
                                     "by_reason": {"no_distro_revision": 1, "vendor_maintainer": 1}}
    # 完整清單：列出的與只靠名稱對到資料的都在 packages-without-vuln-data.csv
    assert x["file"] == "packages-without-vuln-data.csv"
    lst = list(csv.reader(io.StringIO((reports / x["file"]).read_bytes().decode("utf-8-sig"))))
    assert lst[0] == list(nvd.LIST_COLUMNS) and len(lst) == 1 + 4 + 1
    assert [r[0] for r in lst[1:]] == ["listed"] * 4 + ["name_only_data"] and lst[-1][1:3] == ["libmatched1", "0.9"]
    assert "vendor.example" in (reports / x["file"]).read_text(encoding="utf-8-sig") and "dev@" "vendor.example" not in lst[-1]
    md = (reports / "risk-assessment.md").read_text(encoding="utf-8")
    sec = section_of(md)
    assert "（沒有漏洞資料的套件（未評估））" in md and "Status **NOT_ASSESSED**: 4 Debian/Ubuntu packages (2 likely, 2 possible)" in sec
    line = next(ln for ln in sec.splitlines() if ln.startswith("| chromium-x11 "))
    assert "| 132.0.6834.83 | @vendor.example | hold | likely |" in line and "version has no distribution revision" in line
    # 發行版維護、有修訂號的 hold 套件：至少「可能」
    assert "| libheld1 | 2.0-1 | @lists.debian.org | hold | possible | dpkg hold" in sec
    assert "| libmatched1 " not in sec and "| openssl " not in sec
    assert "| libpersonal1 | 1.2-3 | (personal) | install | possible |" in sec and "gmail.com" not in sec    # 個人網域不寫
    assert "confirm that the distribution's advisories apply): libmatched1 0.9 (all of them in `packages-without-vuln-data.csv`)." in sec
    assert "Vendor Dev" not in sec and "dev@" "vendor.example" not in sec          # 只寫網域，不寫姓名與信箱
    assert "probably have no vulnerability data and are NOT ASSESSED" in md.split("## 1.", 1)[0]   # 資料狀態的附註
    # 待確認事項表：每組一筆，問產品工程師
    nv = [i for i in citems(reports) if i["類別"] == "沒有漏洞資料的套件"]
    assert [i["掃描發現（為什麼要問）"].split("]", 1)[0] for i in nv[:2]] == ["[novuln:likely:vendor.example", "[novuln:possible"]
    assert [i["掃描發現（為什麼要問）"].split("]", 1)[0] for i in nv][2:] == ["[novuln:vendor-with-data"]
    for i in nv[:2]:
        assert i["掃描發現（為什麼要問）"].split("] ", 1)[1].startswith("這些套件沒有漏洞資料，要人工確認版本與上游安全公告：")
        assert i["要問誰（建議）"] == "產品工程師" and "NOT_ASSESSED" in i["影響"]
    assert "chromium-x11 132.0.6834.83" in nv[0]["掃描發現（為什麼要問）"] and "dpkg hold 1 個" in nv[0]["掃描發現（為什麼要問）"]
    # 維護者不是發行版、只靠名稱對到資料的套件：也問產品工程師
    assert "libmatched1 0.9" in nv[2]["掃描發現（為什麼要問）"] and nv[2]["要問誰（建議）"] == "產品工程師"
    assert s["confirmation_items"]["by_category"]["沒有漏洞資料的套件"] == 3
    # 設定檔沒有列廠商網域：網域不印出，組的鍵用雜湊
    _, s2, rep2 = run(make_project(tmp_path / "p2"), scan_with(tmp_path, "r2", DISTRO + VENDOR + [OPENSSL]))
    keys2 = [g["key"] for g in s2["packages_without_vuln_data"]["groups"]]
    assert keys2[0].startswith("likely:vendor-") and "vendor.example" not in json.dumps(s2["packages_without_vuln_data"])
    sec2 = section_of((rep2 / "risk-assessment.md").read_text(encoding="utf-8"))
    assert "vendor.example" not in sec2 and "| 132.0.6834.83 | (not shown) | hold | likely |" in sec2
    assert "vendor.example" not in (rep2 / "confirmation-items.csv").read_text(encoding="utf-8-sig")


def test_does_not_change_tiers_status_or_gate(tmp_path):
    proj = make_project(tmp_path / "p")
    _, base, _ = run(proj, scan_with(tmp_path, "a", DISTRO + [OPENSSL]))
    _, s, _ = run(proj, scan_with(tmp_path, "b", DISTRO + VENDOR + [OPENSSL]))
    assert base["packages_without_vuln_data"]["status"] == "OK" and base["packages_without_vuln_data"]["count"] == 0
    for k in ("rows", "p1", "p2", "p3", "accepted", "kev_open"):
        assert s["counts"][k] == base["counts"][k], k
    assert s["documents"]["risk-assessment"]["status"] == base["documents"]["risk-assessment"]["status"]
    assert s["vex"]["gate"]["verdict"] == base["vex"]["gate"]["verdict"]
    assert s["documents"]["risk-assessment"]["detail"] == base["documents"]["risk-assessment"]["detail"]


def test_deterministic(tmp_path):
    proj = make_project(tmp_path / "p")
    comps = DISTRO + VENDOR + [OPENSSL]
    _, s1, rep = run(proj, scan_with(tmp_path, "a", comps))
    csv1, sec1 = (rep / "confirmation-items.csv").read_bytes(), section_of((rep / "risk-assessment.md").read_text(encoding="utf-8"))
    shuffled = list(comps)
    random.Random(7).shuffle(shuffled)
    _, s2, rep = run(proj, scan_with(tmp_path, "b", shuffled))
    assert s1["packages_without_vuln_data"] == s2["packages_without_vuln_data"]
    assert (rep / "confirmation-items.csv").read_bytes() == csv1
    assert section_of((rep / "risk-assessment.md").read_text(encoding="utf-8")) == sec1


def test_without_pkgdb_uses_sbom_publisher(tmp_path):
    _, s, reports = run(make_project(tmp_path / "p"), scan_with(tmp_path, "r", DISTRO + VENDOR + [OPENSSL], pkgdb=False))
    x = s["packages_without_vuln_data"]
    assert x["status"] == "NOT_ASSESSED" and x["count"] == 3 and x["maintainer_source"] == "sbom" and x["hold_known"] is False
    # 沒有 pkgdb：hold 不明，libheld1 是發行版維護、有修訂號 → 不列
    assert x["held"] == 0 and any("no pkgdb" in d for d in x["detail"])
    # 沒有 pkgdb：hold 不明，只有一個種子 → 不算廠商網域，全部是「可能」，網域不寫
    assert x["likely"] == 0 and x["possible"] == 3 and [g["key"] for g in x["groups"]] == ["possible"]
    sec = section_of((reports / "risk-assessment.md").read_text(encoding="utf-8"))
    assert "| 132.0.6834.83 | (not shown) | unknown | possible |" in sec and "vendor.example" not in sec


def test_no_maintainer_data_is_gap_and_no_debs_not_run(tmp_path):
    bare = [{k: v for k, v in c.items() if k != "publisher"} for c in DISTRO + VENDOR + [OPENSSL]]
    _, s, reports = run(make_project(tmp_path / "p"), scan_with(tmp_path, "r", bare, pkgdb=False))
    x = s["packages_without_vuln_data"]
    # 沒有任何維護者資料：只剩版本的訊號（chromium-x11 沒有修訂號 → 可能），整體看不出廠商套件 → 整體是 GAP（不是 NOT_ASSESSED）
    assert x["status"] == "GAP" and x["count"] == 1 and x["possible"] == 1 and x["maintainer_source"] is None
    assert "Status **GAP**: 1 Debian/Ubuntu package" in section_of((reports / "risk-assessment.md").read_text(encoding="utf-8"))
    assert any("no maintainer data" in d for d in x["detail"])
    only_rev = [c for c in bare if c["name"] != "chromium-x11"]
    _, s, _ = run(make_project(tmp_path / "p2"), scan_with(tmp_path, "r2", only_rev, pkgdb=False))
    assert s["packages_without_vuln_data"]["status"] == "GAP" and s["packages_without_vuln_data"]["count"] == 0
    _, s, reports = run(make_project(tmp_path / "p3"), make_scan(tmp_path / "r3" / "scan"))     # 只有 Ubuntu 的 openssl（有列）
    assert s["packages_without_vuln_data"]["count"] == 0
    _, s, reports = run(make_project(tmp_path / "p4"), scan_with(tmp_path, "r4", [{"type": "library", "name": "brotli", "version": "1.1.0",
                                                                                  "purl": "pkg:pypi/brotli@1.1.0"}], pkgdb=False))
    assert s["packages_without_vuln_data"]["status"] == "NOT_RUN"
    assert "Not run: no Debian/Ubuntu (pkg:deb) package in the SBOM" in (reports / "risk-assessment.md").read_text(encoding="utf-8")


def test_project_template_without_placeholder_warns(tmp_path):
    tpl = (HERE.parent / "templates" / "risk-assessment.md").read_text(encoding="utf-8").replace("{{ text.no_vuln_data_section }}", "")
    proj = make_project(tmp_path / "p", templates={"risk-assessment": tpl})
    _, s, _ = run(proj, scan_with(tmp_path, "r", DISTRO + VENDOR + [OPENSSL]))
    assert any("text.no_vuln_data_section" in w for w in s["config_warnings"])
    assert s["packages_without_vuln_data"]["count"] == 4


# ---------- 單元 ----------

def test_unit_signals():
    assert nvd.has_revision("2.36-9+deb12u14") and nvd.has_revision("1:1.2-3") and nvd.has_revision("12.4+deb12u5")
    assert nvd.has_revision("1.0ubuntu2") and not nvd.has_revision("132.0.6834.83") and not nvd.has_revision("1:2.0")
    assert nvd.domain_of("Jeffy <j@" "Rock-Chips.COM>") == "rock-chips.com" and nvd.domain_of("no mail") is None
    assert nvd.is_distro_domain("lists.debian.org") and nvd.is_distro_domain("ubuntu.com") and not nvd.is_distro_domain("notdebian.org")
    assert not nvd.is_distro_domain("debian.org.evil.example")


NV = "NVIDIA Corporation <cudatools@" "nvidia.com>"


def test_nvidia_only_jetson_linux_is_covered_by_bulletins(tmp_path):
    pk = DISTRO + [comp("nvidia-l4t-core", "39.2.1-20251201", "NVIDIA Corporation <linux-tegra-bugs@" "nvidia.com>"),
                   comp("cuda-cudart-12-6", "12.6.68-1", NV), comp("libnvinfer10", "11.3.0.30-1+cuda12.5", NV)]
    r = nvd.classify(pk, nvidia_ok=True, grype={"matches": []})
    # 公告比對只評估 nvidia-l4t-*：CUDA、TensorRT 照樣列出
    assert r["excluded"]["nvidia_bulletins"] == 1 and r["count"] == 2 and r["likely"] == 2
    assert {p["name"]: p["signals"] for p in r["packages"]} == {
        "cuda-cudart-12-6": ["vendor_maintainer", "same_vendor_domain", "nvidia_not_jetson_linux"],
        "libnvinfer10": ["vendor_maintainer", "vendor_revision_suffix", "same_vendor_domain", "nvidia_not_jetson_linux"]}
    assert [(g["key"], g["count"]) for g in r["groups"]] == [("likely:nvidia.com", 2)]
    r = nvd.classify(pk, nvidia_ok=False, grype={"matches": []})
    assert r["count"] == 3 and "nvidia_bulletins_not_ok" in next(p for p in r["packages"] if p["name"] == "nvidia-l4t-core")["signals"]
    # 發行版打包的 NVIDIA 相關套件（Debian 的 pkg-nvidia 團隊）不是廠商套件：不列
    deb_nv = comp("nvidia-kernel-support", "535.183.01-1~deb12u1", "Debian NVIDIA Maintainers <pkg-nvidia-devel@" "lists.alioth.debian.org>")
    r = nvd.classify(DISTRO + [deb_nv], nvdebs={deb_nv["purl"].split("?", 1)[0]}, nvidia_ok=True, grype={"matches": []})
    assert r["count"] == 0 and r["excluded"]["distro_maintained"] == 13
    # cra_report.nvidia_debs 給的 purl（publisher 沒有寫 NVIDIA）也算
    other = comp("libcudnn9", "9.3.0.75-1", "Packager <p@" "vendor.example>")
    r = nvd.classify(DISTRO + [other], nvdebs={other["purl"].split("?", 1)[0]}, nvidia_ok=True, grype={"matches": []})
    assert r["packages"][0]["signals"][-1] == "nvidia_not_jetson_linux" and r["packages"][0]["level"] == "likely"
    # 端到端：C-nvidia-bulletins OK 的掃描
    proj = make_project(tmp_path / "p")
    s_ = make_scan(tmp_path / "r" / "scan", findings=FINDINGS, grype=GRYPE, sbom=sbom(pk + [OPENSSL]), stages={"C-nvidia-bulletins": "OK"})
    _, summ, reports = run(proj, s_)
    x = summ["packages_without_vuln_data"]
    assert x["count"] == 2 and x["excluded"]["nvidia_bulletins"] == 1
    sec = section_of((reports / "risk-assessment.md").read_text(encoding="utf-8"))
    assert "| cuda-cudart-12-6 | 12.6.68-1 | @nvidia.com |" in sec and "| nvidia-l4t-core " not in sec


def test_long_untrusted_maintainer_is_fast():
    import time
    shapes = ["<" + "a" * 1_000_000, "x@" * 500_000, "a" * 1_000_000 + "@b.example", "<a@" + "b" * 1_000_000 + ">",
              "@" + "." * 1_000_000, "a@" + "b." * 500_000 + "c"]
    t0 = time.monotonic()
    for v in shapes:
        nvd.domain_of(v)
        nvd.classify(DISTRO + [comp("liblong1", "1.0", v)], grype={"matches": []})
    assert time.monotonic() - t0 < 5
    assert nvd.domain_of("a" * 70000 + "<x@" "late.example>") is None        # 只解析前 65536 個字
    assert nvd.domain_of("Jeffy <j@" "Rock-Chips.COM>") == "rock-chips.com" and nvd.domain_of("x@localhost") is None


def test_distro_name_with_other_domain():
    # 名稱是 Debian／Ubuntu，但沒有發行版的信箱網域：不管有沒有修訂號都列為「可能」（只有真的發行版網域才算發行版的）
    pk = DISTRO + [comp("libfake1", "2.0", "Debian Foo Team <team@" "notdebian.example>"),
                   comp("libfake2", "2.0-1", "Debian Foo Team <team@" "notdebian.example>"),
                   comp("libteam1", "1.0", "Ubuntu Desktop Team")]
    r = nvd.classify(pk, grype={"matches": []})
    assert [(p["name"], p["level"], p["signals"]) for p in r["packages"]] == [
        ("libfake1", "possible", ["distro_name_other_domain", "no_distro_revision"]),
        ("libfake2", "possible", ["distro_name_other_domain"]),
        ("libteam1", "possible", ["distro_name_other_domain", "no_distro_revision"])]
    assert r["excluded"]["distro_maintained"] == 12
    # dh_make 的預設值等（審查的重現案例）：每一個都列出，不算發行版的
    for maint, ver in (("Ubuntu <ubuntu@ubuntu>", "1.0"), ("Debian <debian@localhost>", "1.0-1"),
                       ("Ubuntu <ubuntu@" "ubuntu.localdomain>", "1.0-1")):
        r = nvd.classify(DISTRO + [comp("myapp", ver, maint)], grype={"matches": []})
        assert r["status"] == "NOT_ASSESSED" and [p["name"] for p in r["packages"]] == ["myapp"], maint
        assert r["packages"][0]["level"] == "possible" and r["excluded"]["distro_maintained"] == 12


def test_vendor_fork_with_distro_maintainer():
    # 保留 Debian Maintainer 的廠商分支：沒有資料、版本沒有修訂號 → 可能；再加上 hold → 很可能
    fork = comp("chromium-x11", "132.0.6834.83", "Debian Chromium Team <chromium@" "packages.debian.org>")
    r = nvd.classify(DISTRO + [fork], grype={"matches": []})
    assert r["status"] == "NOT_ASSESSED" and [(p["level"], p["signals"], p["maintainer"]) for p in r["packages"]] == [
        ("possible", ["distro_maintainer_no_revision"], "@packages.debian.org")]

    class DB:
        pkgs = {"chromium-x11": {"Package": "chromium-x11", "Maintainer": fork["publisher"], "Status": "hold ok installed"}}
    r = nvd.classify(DISTRO + [fork], db=DB(), grype={"matches": []})
    assert [(p["level"], p["signals"]) for p in r["packages"]] == [("likely", ["distro_maintainer_no_revision", "held"])]
    assert [g["key"] for g in r["groups"]] == ["likely:held-distro-maintainer"]
    # 發行版維護、有修訂號、沒有資料的不列，文件照實寫「沒有用名稱確認」
    out = nvd.section(r, lambda h, rows: "")
    assert "12 maintained by the distribution and with a distribution revision" in out and "NOT checked by package name" in out


def test_same_vendor_domain_needs_two_seeds_or_hold():
    one = DISTRO + [comp("native1", "3.4", "Joe <joe@" "person.example>"), comp("other1", "1.0-1", "Joe <joe@" "person.example>")]
    r = nvd.classify(one, grype={"matches": []})
    # 一個沒有 hold 的種子（例如 Debian 個人維護者的原生套件）：不擴散，都只是「可能」，網域不寫
    assert [(p["name"], p["level"], p["maintainer"]) for p in r["packages"]] == [
        ("native1", "possible", "(not shown)"), ("other1", "possible", "(not shown)")]
    two = one + [comp("native2", "5.6", "Ann <ann@" "person.example>")]
    r = nvd.classify(two, grype={"matches": []})
    # 分組用網域，但沒有在設定檔列出的網域不印出（鍵用雜湊）；列在設定檔的才寫網域
    assert r["likely"] == 3 and [g["key"] for g in r["groups"]][0].startswith("likely:vendor-")
    assert {p["maintainer"] for p in r["packages"]} == {"(not shown)"}
    r = nvd.classify(two, grype={"matches": []}, vendor_domains=["person.example"])
    assert [g["key"] for g in r["groups"]] == ["likely:person.example"] and {p["maintainer"] for p in r["packages"]} == {"@person.example"}

    class DB:
        pkgs = {"native1": {"Package": "native1", "Maintainer": "Joe <joe@" "person.example>", "Status": "hold ok installed"}}
    r = nvd.classify(one, db=DB(), grype={"matches": []})
    assert r["likely"] == 2 and all(p["maintainer"] == "(not shown)" for p in r["packages"])
    assert "person.example" not in json.dumps(nvd.summary(r))
    # 免費信箱不會成為廠商網域
    free = DISTRO + [comp(f"g{i}", "1.0", "G <g@" "gmail.com>") for i in range(3)]
    r = nvd.classify(free, grype={"matches": []})
    assert r["likely"] == 0 and {p["maintainer"] for p in r["packages"]} == {"(personal)"}


def test_known_names_only_from_deb_rows():
    pk = DISTRO + [comp("libx1", "1.0", "V <v@" "vendor.example>")]
    r = nvd.classify(pk, rows=[{"name": "libx1", "component": "libx1", "purl": "pkg:pypi/libx1@1.0", "ptype": "pypi"}], grype={"matches": []})
    assert r["count"] == 1
    r = nvd.classify(pk, rows=[{"name": "libx", "component": "libx", "installed_as": ["libx1"], "purl": "pkg:deb/debian/libx@1.0?arch=source"}],
                     grype={"matches": []})
    assert r["count"] == 0 and r["vendor_with_data"]["examples"] == ["libx1 1.0"]


def test_unit_nvidia_and_origin():
    pk = DISTRO + [comp("nvidia-l4t-core", "39.2.1-20251201", "NVIDIA Corporation <linux-tegra-bugs@" "nvidia.com>")]
    r = nvd.classify(pk, nvidia_ok=True, grype={"matches": []})
    assert r["count"] == 0 and r["excluded"]["nvidia_bulletins"] == 1
    r = nvd.classify(pk, nvidia_ok=False, grype={"matches": []})
    assert r["count"] == 1 and r["packages"][0]["signals"] == ["vendor_maintainer", "same_vendor_domain", "nvidia_bulletins_not_ok"]

    class DB:
        pkgs = {"libx": {"Package": "libx", "Maintainer": DISTRO_MAINT, "Origin": "Vendor", "Status": "install ok installed"}}
    r = nvd.classify(DISTRO + [comp("libx", "1.0-1", DISTRO_MAINT)], db=DB(), grype={"matches": []})
    assert r["count"] == 1 and r["packages"][0]["level"] == "likely" and r["packages"][0]["signals"] == ["origin"]
    # 不可信的輸入：控制字元與 | 不會壞掉表格
    r = nvd.classify(DISTRO + [comp("liby", "1.0", "x|y\n<a@" "b.example>")], grype={"matches": []})
    out = nvd.section(r, lambda h, rows: "\n".join("|".join(map(str, x)) for x in rows))
    assert r["packages"][0]["maintainer"] == "(personal)" and "\n<a@" not in out and "b.example" not in out
    assert json.dumps(nvd.summary(r), sort_keys=True) == json.dumps(nvd.summary(nvd.classify(list(reversed(DISTRO)) + [
        comp("liby", "1.0", "x|y\n<a@" "b.example>")], grype={"matches": []})), sort_keys=True)
    assert EXAMPLE      # 範例設定照常載入（make_project 用）


def test_malformed_inputs_do_not_crash(tmp_path, monkeypatch):
    bad = DISTRO + [dict(comp("libbad1", "1.0", "V <v@" "vendor.example>"), properties=5)]
    r = nvd.classify(bad, rows=[{"name": "x", "purl": "pkg:deb/debian/x@1", "installed_as": 5}],
                     grype={"matches": 5}, vendor_domains=5)
    assert r["status"] == "NOT_ASSESSED"
    r = nvd.classify(bad, grype={"matches": [{"artifact": {"type": "deb", "name": "y", "upstreams": 5}}, 5]})
    assert r["count"] == 1
    # classify 失敗時：報告照樣寫，這一項是 GAP
    import cra_report as cr
    proj = make_project(tmp_path / "p")
    scan = scan_with(tmp_path, "r", DISTRO + VENDOR + [OPENSSL])
    m = cr.nvdmod()

    def boom(*a, **k):
        raise TypeError("forced")
    monkeypatch.setattr(m, "classify", boom)
    monkeypatch.setenv("CRA_COMPANY_CONFIG", "none")
    rc = cr.main(["--project", str(proj), "--scan", str(scan)])
    rep_ = proj / "CRA" / "Reports"
    summ = json.loads((rep_ / "summary.json").read_text(encoding="utf-8"))
    x = summ["packages_without_vuln_data"]
    assert rc in (0, 2) and x["status"] == "GAP" and x["count"] == 0 and "TypeError" in x["detail"][0]
    md = (rep_ / "risk-assessment.md").read_text(encoding="utf-8")
    assert "Status **GAP**" in section_of(md) and "could not be completed (TypeError)" in md


def test_config_domains():
    cfg = {"manufacturer": {"email": "Contact <cra@" "Maker.example>"},
           "sbom": {"vendor_domains": ["bsp.example", " ", 5], "flash_package_supplier": {"name": "V", "url": "https://www.vendor.example/x"}}}
    assert nvd.config_domains(cfg) == ["bsp.example", "maker.example", "vendor.example"]
    assert nvd.config_domains(None) == [] and nvd.config_domains({"sbom": 5}) == []


class _DB:
    def __init__(self, paras):
        self.pkgs = {p["Package"]: p for p in paras}


def test_held_distro_package_with_revision_is_listed():
    # 審查的重現：發行版的 Maintainer、-N 修訂號、dpkg hold、沒有資料 → 可能（不再只算進 distro_maintained）
    c = comp("libfoo-held", "1.22.9-1", DISTRO_MAINT)
    db = _DB([{"Package": "libfoo-held", "Maintainer": DISTRO_MAINT, "Status": "hold ok installed"}])
    r = nvd.classify(DISTRO + [c], db=db, grype={"matches": []})
    assert [(p["name"], p["level"], p["signals"]) for p in r["packages"]] == [("libfoo-held", "possible", ["held"])]
    # 有資料的 hold 套件：不列，但記在 vendor_with_data（要確認 hold 的版本是不是發行版的建置），待確認事項表另一筆
    g = {"matches": [{"artifact": {"type": "deb", "name": "libfoo-held"}}]}
    r = nvd.classify(DISTRO + [c], db=db, grype=g)
    assert r["count"] == 0 and r["excluded"]["has_vulnerability_data_held_or_vendor_revision"] == 1
    assert r["vendor_with_data"] == {"count": 1, "examples": ["libfoo-held 1.22.9-1"], "by_reason": {"held": 1}}
    import confirm_items as ci
    it = ci.novuln_items(r)
    assert [x["key"] for x in it] == ["novuln:vendor-with-data"] and "hold" in it[0]["question"] and it[0]["ask"] == "產品工程師"


def test_vendor_revision_suffix():
    assert nvd.vendor_revision_suffix("1.0-1rockchip1") and nvd.vendor_revision_suffix("2.4.114-1+rk1")
    assert nvd.vendor_revision_suffix("1:2.0-3vendor2")
    for v in ("2.36-9+deb12u14", "3.0.15-1~deb12u1", "1.2-3ubuntu0.1+esm1", "1.0-1build2", "1.0-2+b1", "1.0-1~bpo12+1", "1.0-1.1",
              "1.0", "1.0-0ubuntu0.22.04.1", "4.1-1~exp1", "1:1.2+dfsg-3"):
        assert not nvd.vendor_revision_suffix(v), v
    r = nvd.classify(DISTRO + [comp("libfoo1", "1.0-1rockchip1", DISTRO_MAINT)], grype={"matches": []})
    assert [(p["level"], p["signals"]) for p in r["packages"]] == [("possible", ["vendor_revision_suffix"])]
    db = _DB([{"Package": "libfoo1", "Maintainer": DISTRO_MAINT, "Status": "hold ok installed"}])
    r = nvd.classify(DISTRO + [comp("libfoo1", "1.0-1rockchip1", DISTRO_MAINT)], db=db, grype={"matches": []})
    assert [(p["level"], p["signals"]) for p in r["packages"]] == [("likely", ["vendor_revision_suffix", "held"])]
    assert [g["key"] for g in r["groups"]] == ["likely:held-vendor-revision"]


def test_origin_does_not_override_vendor_maintainer():
    for ori in ("Debian", " DEBIAN ", "Ubuntu"):
        db = _DB([{"Package": "libv1", "Maintainer": "V <a@" "vendor.example>", "Origin": ori, "Status": "install ok installed"}])
        r = nvd.classify(DISTRO + [comp("libv1", "1.0-1", "V <a@" "vendor.example>")], db=db, grype={"matches": []})
        assert [(p["name"], p["signals"]) for p in r["packages"]] == [("libv1", ["vendor_maintainer"])], ori
    # Origin 寫 Debian、沒有 Maintainer：Origin 不能讓它變成發行版的
    db = _DB([{"Package": "libv2", "Origin": "Debian", "Status": "install ok installed"}])
    r = nvd.classify(DISTRO + [comp("libv2", "1.0-1")], db=db, grype={"matches": []})
    assert [(p["name"], p["signals"]) for p in r["packages"]] == [("libv2", ["no_maintainer"])]


def test_every_maintainer_address_counts():
    both = "Debian Foo <pkg-foo@" "lists.debian.org>, V <v@" "vendor.example.>"
    assert nvd.domains_of(both) == ["lists.debian.org", "vendor.example"] and nvd.domain_of(both) == "vendor.example"
    r = nvd.classify(DISTRO + [comp("libmix1", "1.0-1", both)], grype={"matches": []})
    assert [(p["name"], p["signals"]) for p in r["packages"]] == [("libmix1", ["distro_name_other_domain"])]
    r = nvd.classify(DISTRO + [comp("libok1", "1.0-1", "A <a@" "debian.org>, B <b@" "lists.debian.org>")], grype={"matches": []})
    assert r["count"] == 0


def test_revision_check_skipped_is_reported():
    few = [comp("libdistro0", "1.0-1", DISTRO_MAINT), comp("dpkg", "1.21.22", DISTRO_MAINT)]
    r = nvd.classify(few, grype={"matches": []})
    assert r["count"] == 0 and r["excluded"] == {"distro_maintained": 1, "distro_no_revision_unchecked": 1}
    out = nvd.section(r, lambda h, rows: "")
    assert "1 maintained by the distribution, version without a distribution revision, but the revision check was skipped" in out


import pkg_why as _pw  # noqa: E402


def _status(*paras):
    return "\n\n".join("\n".join(f"{k}: {v}" for k, v in p.items()) for p in paras) + "\n"


def test_not_fully_installed_and_held_from_every_paragraph():
    # pkg_why.PkgDB.pkgs 只收裝好的；hold 與狀態要從每一個段落讀（含 unpacked、half-configured、同名多架構）
    st = _status({"Package": "libun1", "Status": "hold ok unpacked", "Maintainer": DISTRO_MAINT, "Version": "2.0-1", "Architecture": "arm64"},
                 {"Package": "libhc1", "Status": "install ok half-configured", "Maintainer": DISTRO_MAINT, "Version": "2.0-1",
                  "Architecture": "arm64"},
                 {"Package": "libma1", "Status": "install ok installed", "Maintainer": DISTRO_MAINT, "Version": "2.0-1", "Architecture": "arm64"},
                 {"Package": "libma1", "Status": "hold ok installed", "Maintainer": DISTRO_MAINT, "Version": "2.0-1", "Architecture": "armhf"})
    db = _pw.PkgDB(st)
    assert "libun1" not in db.pkgs and len(db.all_paras["libma1"]) == 2
    pk = DISTRO + [comp("libun1", "2.0-1", DISTRO_MAINT), comp("libhc1", "2.0-1", DISTRO_MAINT), comp("libma1", "2.0-1", DISTRO_MAINT)]
    r = nvd.classify(pk, db=db, grype={"matches": []})
    got = {p["name"]: (p["level"], p["signals"], p["states"]) for p in r["packages"]}
    assert got == {"libun1": ("possible", ["not_fully_installed", "held"], ["unpacked"]),
                   "libhc1": ("possible", ["not_fully_installed"], ["half-configured"]),
                   "libma1": ("possible", ["held"], [])}
    # 有名稱比對時：不列，但在 vendor_with_data（原因寫出來）
    g = {"matches": [{"artifact": {"type": "deb", "name": n}} for n in ("libun1", "libhc1", "libma1")]}
    r = nvd.classify(pk, db=db, grype=g)
    assert r["count"] == 0 and r["vendor_with_data"]["count"] == 3
    assert r["vendor_with_data"]["by_reason"] == {"held": 2, "not_fully_installed": 2}


def test_name_match_with_distro_maintainer_and_no_revision():
    c = comp("nr", "132.0.6834.83", DISTRO_MAINT)
    r = nvd.classify(DISTRO + [c], grype={"matches": [{"artifact": {"type": "deb", "name": "nr"}}]})
    assert r["count"] == 0 and r["vendor_with_data"] == {"count": 1, "examples": ["nr 132.0.6834.83"],
                                                         "by_reason": {"distro_maintainer_no_revision": 1}}
    assert r["excluded"]["has_vulnerability_data_held_or_vendor_revision"] == 1


def test_vendor_version_tag_in_upstream_part():
    assert nvd.vendor_version_tag("1.0+rk1-1") and nvd.vendor_version_tag("2:1.0~rockchip2-3")
    for v in ("1.2+dfsg-1", "1.2+ds1-1", "2.0+really1.9-1", "1.0+git20200101.abc-1", "1.0~rc1-1", "1.0+repack-2", "12.4+deb12u5",
              "1.0+svn123-1", "3.0.15-1~deb12u1", "1.0"):
        assert not nvd.vendor_version_tag(v), v
    r = nvd.classify(DISTRO + [comp("libtag1", "1.0+rk1-1", DISTRO_MAINT)], grype={"matches": []})
    assert [(p["level"], p["signals"]) for p in r["packages"]] == [("possible", ["vendor_version_tag"])]
    # Ubuntu 的 cross、fakesync 是發行版的寫法
    assert not nvd.vendor_revision_suffix("2.38-4ubuntu2cross1") and not nvd.vendor_revision_suffix("1.0-1fakesync1")


def test_list_file_and_held_vendor_revision_label(tmp_path):
    db = _DB([{"Package": "libfoo1", "Maintainer": DISTRO_MAINT, "Status": "hold ok installed"}])
    r = nvd.classify(DISTRO + [comp("libfoo1", "1.0-1rockchip1", DISTRO_MAINT)], db=db, grype={"matches": []})
    import confirm_items as ci
    it = ci.novuln_items(r)
    assert it[0]["key"] == "novuln:likely:held-vendor-revision" and "dpkg hold 而且版本有廠商的字尾或標記" in it[0]["finding"]
    assert "維護者 @held-vendor-revision" not in it[0]["finding"] and "packages-without-vuln-data.csv" in it[0]["finding"]
    assert nvd.write_list(tmp_path, r) == "packages-without-vuln-data.csv"
    t1 = (tmp_path / "packages-without-vuln-data.csv").read_bytes()
    assert t1.startswith(b"\xef\xbb\xbf") and b"libfoo1" in t1
    nvd.write_list(tmp_path, nvd.classify(list(reversed(DISTRO)) + [comp("libfoo1", "1.0-1rockchip1", DISTRO_MAINT)], db=db,
                                          grype={"matches": []}))
    assert (tmp_path / "packages-without-vuln-data.csv").read_bytes() == t1
    # 公式字元開頭的格子前面加 '
    assert nvd.csv_safe("=cmd") == "'=cmd" and nvd.csv_safe("\t1") == "'\t1"


def test_maintainer_from_every_paragraph_and_sbom_publisher():
    # 同名多架構：一個段落是 Debian 的維護者、另一個是廠商的 → 不是發行版的（兩種段落順序結果一樣）
    deb = {"Package": "libfoo", "Status": "install ok installed", "Maintainer": DISTRO_MAINT, "Version": "1.0-1", "Architecture": "arm64"}
    ven = {"Package": "libfoo", "Status": "install ok installed", "Maintainer": "V <v@" "vendor.example>", "Version": "1.0-1",
           "Architecture": "armhf"}
    res = []
    for order in ((deb, ven), (ven, deb)):
        db = _pw.PkgDB(_status(*order))
        r = nvd.classify(DISTRO + [comp("libfoo", "1.0-1", DISTRO_MAINT)], db=db, grype={"matches": []})
        res.append([(p["name"], p["signals"]) for p in r["packages"]])
    assert res[0] == res[1] == [("libfoo", ["vendor_maintainer"])]
    # pkgdb 是 Debian 的、SBOM 的 publisher 是廠商的 → 也算
    db = _pw.PkgDB(_status(deb))
    r = nvd.classify(DISTRO + [comp("libfoo", "1.0-1", "V <v@" "vendor.example>")], db=db, grype={"matches": []})
    assert [p["name"] for p in r["packages"]] == ["libfoo"]


def test_overlong_maintainer_is_not_distro_only():
    import time
    long = DISTRO_MAINT + ", " + "x" * 70000 + " <v@" "vendor.example>"
    t0 = time.monotonic()
    r = nvd.classify(DISTRO + [comp("liblong2", "1.0-1", long)], grype={"matches": []})
    assert time.monotonic() - t0 < 5
    assert [(p["level"], p["signals"]) for p in r["packages"]] == [("possible", ["distro_name_other_domain", "maintainer_too_long"])]
    many = ", ".join(f"D{i} <d{i}@lists.debian.org>" for i in range(300))
    r = nvd.classify(DISTRO + [comp("libmany1", "1.0-1", many)], grype={"matches": []})
    assert "maintainer_too_long" in r["packages"][0]["signals"]


def test_round5_noise_and_csv_cosmetics(tmp_path):
    # Ubuntu 的 rebuild（沒有分隔字元的 buildN）是發行版的修訂號
    assert nvd.has_revision("3.6.3build1") and nvd.has_revision("7.7+11build3")
    r = nvd.classify(DISTRO + [comp("libnative1", "3.6.3build1", DISTRO_MAINT)], grype={"matches": []})
    assert r["count"] == 0
    # git 雜湊與上游常用的字不是廠商標記
    for v in ("1.0+ed310a0-1", "4.17.12+dfsg-0+samba4-1", "0.9.8+real5prealpha-1", "2.0+tests-1", "1.0+20230101-1", "0.8+5prealpha+1-17build2"):
        assert not nvd.vendor_version_tag(v), v
    assert nvd.vendor_version_tag("1.0+rk1-1") and nvd.vendor_version_tag("1.0+abc12-1")
    # CSV：維護者網域不加 @（不用跳脫）；全形 ＝ 也跳脫
    r = nvd.classify(DISTRO + [comp("libheld9", "2.0-1", DISTRO_MAINT)],
                     db=_DB([{"Package": "libheld9", "Maintainer": DISTRO_MAINT, "Status": "hold ok installed"}]), grype={"matches": []})
    t = nvd.list_text(r)
    assert ",lists.debian.org," in t and "'@" not in t
    assert nvd.csv_safe("＝HYPERLINK(1)") == "'＝HYPERLINK(1)"
    import confirm_items as ci
    assert ci.csv_safe("＝1") == "'＝1"
    out = nvd.section(dict(r, vendor_with_data={"count": 1, "examples": ["x 1"], "by_reason": {}}), lambda h, rows: "")
    assert "the reasons per package are in `packages-without-vuln-data.csv`" in out


def test_part_without_usable_domain_is_not_distro():
    # pkgdb 的 Maintainer 沒有可用的網域、SBOM 的 publisher 是 debian.org：不算發行版的
    db = _pw.PkgDB(_status({"Package": "librk1", "Status": "install ok installed", "Maintainer": "RK <build@localhost>",
                            "Version": "1.0-1", "Architecture": "arm64"}))
    r = nvd.classify(DISTRO + [comp("librk1", "1.0-1", "A Developer <a@" "debian.org>")], db=db, grype={"matches": []})
    assert [(p["name"], p["signals"]) for p in r["packages"]] == [("librk1", ["vendor_maintainer"])]
    # 只有名字、非 ASCII 網域的段落也一樣（每一個 Maintainer 都要有可用的發行版網域）
    for bare in ("Just A Name", "X <x@例え.jp>"):
        db = _pw.PkgDB(_status({"Package": "libbare1", "Status": "install ok installed", "Maintainer": bare, "Version": "1.0-1",
                                "Architecture": "arm64"}))
        r = nvd.classify(DISTRO + [comp("libbare1", "1.0-1", "B <b@" "lists.debian.org>")], db=db, grype={"matches": []})
        assert [p["name"] for p in r["packages"]] == ["libbare1"], bare


def test_build_mark_only_at_the_end_after_a_digit():
    for v in ("3.6.3build1", "7.7+11build3", "5.17build1"):
        assert nvd.has_revision(v), v
    for v in ("1.0rkbuild1", "1.0build1rk", "2.1_build5"):
        assert not nvd.has_revision(v), v
