"""WP7：pipeline/platforms/_shared/sbom_augment.py（原始磁區元件、併入原始碼 SBOM）。合成資料、不連網。"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import urllib.parse

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
AUG = os.path.join(ROOT, "pipeline", "platforms", "_shared", "sbom_augment.py")
COMMIT = "9d8530ffa6912ece116bc6c74d0f3d06045b6c26"
REPO = "https://github.com/openmediavault/openmediavault.git"

def rj(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def rb(path):
    with open(path, "rb") as f:
        return f.read()


def wb(path, data):
    with open(path, "wb") as f:
        f.write(data)



def bom(components, deps=(), root="root-1"):
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {"component": {"bom-ref": root, "type": "container", "name": "img"}},
            "components": components, "dependencies": list(deps)}


def props(c):
    return {p["name"]: p["value"] for p in c.get("properties", [])}


class AugmentTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wp7-aug-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def path(self, name, doc=None):
        p = os.path.join(self.tmp, name)
        if doc is not None:
            with open(p, "w", encoding="utf-8") as f:
                json.dump(doc, f)
        return p

    def run_aug(self, *args):
        p = subprocess.run([sys.executable, "-I", AUG, *args], capture_output=True, text=True)
        return p.returncode, (p.stdout.strip().splitlines() or [""])[-1]

    def raw(self, regions):
        return {"schema": 1, "platform": "rockchip", "regions": regions}

    def region(self, slot="idbloader.img", lba=64, versions=None, state="一致"):
        return {"slot": slot, "start_lba": lba, "sectors": 10, "sha256": "ab" * 32,
                "identity": {"kind": "rockchip-idblock", "versions": versions if versions is not None else [
                    {"component": "U-Boot SPL", "version": "rk2410-2017.09-64-39cd993-g58d424f"},
                    {"component": "Rockchip DDR init", "version": "v1.22"}]},
                "corroboration": [{"source": "package", "file": "u.deb", "state": state}]}

    def test_raw_sectors_components(self):
        base = self.path("in.json", bom([{"bom-ref": "a", "type": "library", "name": "a"}]))
        tfa = [{"component": "U-Boot", "version": "rk2410-2017.09-64-39cd993-g58d424f"},
               {"component": "TF-A BL31 (Rockchip rkbin)", "version": "v1.54"},
               {"component": "TF-A git describe", "version": "v2.3-964-g8319968f5"}]
        raw = self.path("raw.json", self.raw([self.region(), self.region("u-boot.itb", 16384, tfa)]))
        out = self.path("out.json")
        rc, line = self.run_aug("raw-sectors", base, raw, out)
        self.assertEqual(rc, 0, line)
        d = rj(out)
        fw = [c for c in d["components"] if c["type"] == "firmware"]
        self.assertEqual(len(fw), 2)
        idb, itb = fw
        self.assertEqual(idb["version"], "rk2410-2017.09-64-39cd993-g58d424f")
        self.assertEqual(idb["hashes"], [{"alg": "SHA-256", "content": "ab" * 32}])
        p = props(idb)
        self.assertEqual((p["dumpling:origin"], p["dumpling:raw-sectors:start_lba"]), ("raw-sectors", "64"))
        ddr = [s for s in idb["components"] if "DDR" in s["name"]][0]
        self.assertEqual((props(ddr)["dumpling:closed-source"], props(ddr)["dumpling:advisory-check"]), ("true", "GAP"))
        bl31 = [s for s in itb["components"] if "BL31" in s["name"]][0]
        self.assertEqual(props(bl31)["dumpling:tf-a-describe"], "v2.3-964-g8319968f5")
        ub = [s for s in itb["components"] if s["name"] == "U-Boot"][0]
        pu = props(ub)
        self.assertEqual(ub["cpe"], "cpe:2.3:a:denx:u-boot:2017.09:*:*:*:*:*:*:*")          # D-034：版本以磁區讀出的為準
        self.assertEqual((pu["dumpling:advisory-check"], pu["dumpling:vendor-branch"], pu["dumpling:vendor-commit"]),
                         ("ATTENTION", "rk2410", "39cd993"))
        self.assertIn("候選", pu["dumpling:advisory-note"])
        self.assertNotIn("purl", ub)
        spl = [s for s in idb["components"] if s["name"] == "U-Boot SPL"][0]
        self.assertEqual(spl["cpe"], "cpe:2.3:a:denx:u-boot:2017.09:*:*:*:*:*:*:*")
        self.assertNotIn("cpe", ddr)
        self.assertNotIn("cpe", idb)                                   # 區段本身不給，避免同一份 U-Boot 比對兩次
        self.assertEqual(len([s for s in itb["components"]]), 2)          # git describe 不是另一個元件
        root = [x for x in d["dependencies"] if x["ref"] == "root-1"][0]
        self.assertEqual(root["dependsOn"], [idb["bom-ref"], itb["bom-ref"]])
        allrefs = {c["bom-ref"] for c in d["components"]} | {s["bom-ref"] for c in fw for s in c.get("components", [])} | {"root-1"}
        for e in d["dependencies"]:
            self.assertIn(e["ref"], allrefs)
            for x in e["dependsOn"]:
                self.assertIn(x, allrefs)

    def test_raw_sectors_no_version_or_no_corroboration_is_gap(self):
        base = self.path("in.json", bom([]))
        raw = self.path("raw.json", self.raw([self.region(versions=[], state="不一致")]))
        out = self.path("out.json")
        rc, line = self.run_aug("raw-sectors", base, raw, out)
        self.assertEqual(rc, 3, line)
        c = rj(out)["components"][0]
        self.assertNotIn("version", c)
        self.assertEqual(props(c)["dumpling:version-status"], "GAP")
        self.assertEqual(props(c)["dumpling:raw-sectors:corroboration-status"], "GAP")

    def test_uboot_version_without_year_month_gets_no_cpe(self):
        base = self.path("in.json", bom([]))
        raw = self.path("raw.json", self.raw([self.region(versions=[{"component": "U-Boot", "version": "vendor-build"}])]))
        out = self.path("out.json")
        rc, line = self.run_aug("raw-sectors", base, raw, out)
        self.assertEqual(rc, 3, line)
        ub = rj(out)["components"][0]["components"][0]
        self.assertNotIn("cpe", ub)
        self.assertEqual(props(ub)["dumpling:advisory-check"], "GAP")

    def test_raw_sectors_twice_fails(self):
        base = self.path("in.json", bom([]))
        raw = self.path("raw.json", self.raw([self.region()]))
        out = self.path("out.json")
        self.assertEqual(self.run_aug("raw-sectors", base, raw, out)[0], 0)
        rc, line = self.run_aug("raw-sectors", out, raw, self.path("out2.json"))
        self.assertEqual(rc, 1)
        self.assertIn("重複執行", line)

    def test_merge_source(self):
        img = bom([{"bom-ref": "pkg:deb/debian/bash@5", "type": "library", "name": "bash",
                    "components": [{"bom-ref": "nested", "type": "file", "name": "x"}]}],
                  [{"ref": "pkg:deb/debian/bash@5", "dependsOn": []}])
        src = {"bomFormat": "CycloneDX", "specVersion": "1.6",
               "metadata": {"component": {"bom-ref": "pkg:generic/openmediavault@8.6.1", "type": "application", "name": "openmediavault", "version": "8.6.1"}},
               "components": [{"bom-ref": "pkg:pypi/requests@2", "type": "library", "name": "requests", "version": "2",
                               "properties": [{"name": "dumpling:origin", "value": "image"}]},
                              {"bom-ref": "pkg:deb/debian/bash@5", "type": "library", "name": "bash"}],
               "dependencies": [{"ref": "pkg:generic/openmediavault@8.6.1", "dependsOn": ["pkg:pypi/requests@2", "missing-ref"]},
                                {"ref": "pkg:pypi/requests@2", "dependsOn": []}]}
        out = self.path("out.json")
        rc, line = self.run_aug("merge-source", self.path("img.json", img), self.path("src.json", src), out,
                                "--label", "openmediavault", "--repo", REPO, "--commit", COMMIT)
        self.assertEqual(rc, 0, line)
        self.assertIn("丟掉 1 條", line)
        d = rj(out)
        by = {c["bom-ref"]: c for c in d["components"]}
        self.assertEqual(props(by["pkg:deb/debian/bash@5"])["dumpling:origin"], "image")
        self.assertEqual(props(by["pkg:deb/debian/bash@5"]["components"][0])["dumpling:origin"], "image")
        app = by["dumpling:src:openmediavault:pkg:generic/openmediavault@8.6.1"]
        pa = props(app)
        self.assertEqual((pa["dumpling:origin"], pa["dumpling:origin-commit"], pa["dumpling:origin-repo"], pa["dumpling:source-vs-package"]),
                         ("source", COMMIT, REPO, "NOT_ASSESSED"))
        req = by["dumpling:src:openmediavault:pkg:pypi/requests@2"]
        self.assertEqual(props(req)["dumpling:origin"], "source")          # 原始碼 SBOM 自己帶的 origin 不採用
        self.assertIn("dumpling:src:openmediavault:pkg:deb/debian/bash@5", by)   # 同名元件不跟映像的合併、不覆蓋
        deps = {e["ref"]: e["dependsOn"] for e in d["dependencies"]}
        self.assertEqual(deps[app["bom-ref"]], ["dumpling:src:openmediavault:pkg:pypi/requests@2"])
        self.assertEqual(deps["root-1"], [app["bom-ref"]])
        self.assertIn("pkg:deb/debian/bash@5", deps)                     # 映像原本的依賴還在

    def test_merge_source_app_name_and_version(self):
        img = self.path("img.json", bom([]))
        src = self.path("src.json", {"bomFormat": "CycloneDX", "metadata": {"component": {"bom-ref": "r", "type": "application", "name": "src", "version": "0",
                                                                                  "purl": "pkg:npm/src@0"}},
                                     "components": []})
        out = self.path("o.json")
        rc, line = self.run_aug("merge-source", img, src, out, "--label", "app-source", "--repo", REPO, "--commit", COMMIT,
                                "--app-name", "openmediavault", "--app-version", "8.6.1-1")
        self.assertEqual(rc, 0, line)
        app = rj(out)["components"][0]
        self.assertEqual((app["name"], app["version"]), ("openmediavault", "8.6.1-1"))
        self.assertEqual((props(app)["dumpling:source-root-name"], props(app)["dumpling:source-root-version"]), ("src", "0"))
        # 名稱與版本改了：purl 跟著改（不能留 cdxgen 的 pkg:npm/src@0），原值留在屬性；vcs_url 指到固定 commit
        self.assertEqual(props(app)["dumpling:source-root-purl"], "pkg:npm/src@0")
        self.assertTrue(app["purl"].startswith("pkg:generic/openmediavault@8.6.1-1?vcs_url=git%2B"), app["purl"])
        self.assertIn(COMMIT, app["purl"])
        rc, _ = self.run_aug("merge-source", img, src, out, "--label", "x", "--repo", REPO, "--commit", COMMIT, "--app-name", "bad name")
        self.assertEqual(rc, 64)

    def test_merge_source_bad_args_and_input(self):
        img = self.path("img.json", bom([]))
        rc, _ = self.run_aug("merge-source", img, img, self.path("o.json"), "--label", "x", "--repo", "http://x", "--commit", COMMIT)
        self.assertEqual(rc, 64)
        rc, _ = self.run_aug("merge-source", img, img, self.path("o.json"), "--label", "x", "--repo", REPO, "--commit", "abc")
        self.assertEqual(rc, 64)
        bad = self.path("bad.json", {"not": "cyclonedx"})
        rc, line = self.run_aug("merge-source", img, bad, self.path("o.json"), "--label", "x", "--repo", REPO, "--commit", COMMIT)
        self.assertEqual(rc, 1)
        self.assertIn("不是 CycloneDX", line)

    def test_merge_source_without_app_is_gap(self):
        img = self.path("img.json", bom([]))
        src = self.path("src.json", {"bomFormat": "CycloneDX", "components": [{"bom-ref": "a", "type": "library", "name": "a"}]})
        rc, line = self.run_aug("merge-source", img, src, self.path("o.json"), "--label", "x", "--repo", REPO, "--commit", COMMIT)
        self.assertEqual(rc, 3, line)

    def test_deterministic(self):
        img = self.path("img.json", bom([{"bom-ref": "a", "type": "library", "name": "a"}]))
        raw = self.path("raw.json", self.raw([self.region()]))
        a, b = self.path("a.json"), self.path("b.json")
        self.run_aug("raw-sectors", img, raw, a)
        self.run_aug("raw-sectors", img, raw, b)
        self.assertEqual(rb(a), rb(b))



class SourcePathsTest(unittest.TestCase):
    """原始碼 SBOM（cdxgen）的絕對路徑：併入後去掉掃描暫存資料夾（<WORK>，原始碼根目錄是 <WORK>/cdxgen-src）的前綴；整個值是絕對路徑時只留檔名；
    自由文字的其他斜線不碰。原始碼元件的 bom-ref、purl 也改，依賴的 ref 用同一份對照表。最後保險：整份 SBOM 還有 WORK 的任何寫法 → FAIL。
    鎖住：完整、bsp、os、產品 SBOM（sbom-layers.py split 的實際輸出）走訪整份 JSON（沒有例外欄位）都沒有暫存路徑。
    映像元件（Syft 記的是裝置上的路徑，例如 /usr/…）不是暫存路徑，原樣保留。"""
    LAYERS = os.path.join(ROOT, "pipeline", "sbom-layers.py")
    SUF = ".sca-scan-work.Ab12Cd"

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wp7-aug-paths-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.parent = os.path.join(self.tmp, "out", "augment")
        os.makedirs(self.parent)
        self.work = os.path.join(self.parent, self.SUF)                 # sca-scan 掃完會刪掉：這裡也不建
        self.root = os.path.join(self.work, "cdxgen-src")

    def w(self, name, doc):
        p = os.path.join(self.tmp, name)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(doc, f)
        return p

    def src(self, root=None):
        root = root or self.root
        work = os.path.dirname(root)
        f = root + "/deb/openmediavault/workbench/package-lock.json"
        def lib(name, extra=None, ref=None):
            purl = "pkg:npm/%s@1" % name
            c = {"bom-ref": ref or purl, "type": "library", "name": name, "version": "1", "purl": purl,
                 "properties": [{"name": "SrcFile", "value": f}, {"name": "ResolvedUrl", "value": "https://registry.npmjs.org/%s/-/%s-1.tgz" % (name, name)}],
                 "evidence": {"identity": [{"field": "purl", "confidence": 1, "concludedValue": f,
                                            "methods": [{"technique": "manifest-analysis", "confidence": 1, "value": f}]}]}}
            c.update(extra or {})
            return c
        withpath_ref = "pkg:npm/withpath@1?file_path=" + urllib.parse.quote(root + "/a.json", safe="")
        return {"bomFormat": "CycloneDX", "specVersion": "1.6",
                "metadata": {"component": {"bom-ref": "pkg:npm/openmediavault-workbench@0.0.0", "type": "application",
                                           "name": "openmediavault-workbench", "version": "0.0.0",
                                           "properties": [{"name": "SrcFile", "value": root}]}},
                "components": [
                    lib("tmp"),
                    lib("core", {"description": "Route requests to /login and /api/v1; limit 10 /s",
                                 "properties": [{"name": "Other", "value": "/opt/build/core.js"},
                                                {"name": "Url", "value": "file://" + root + "/a/b.json"},
                                                {"name": "Work", "value": work + "/o/cdxgen/bom.json"}]}),
                    lib("withpath", {"purl": "pkg:npm/withpath@1?file_path=" + urllib.parse.quote(root + "/a.json", safe="")}, ref=withpath_ref),
                    lib("nested", {"components": [lib("inner")]})],
                "dependencies": [{"ref": "pkg:npm/openmediavault-workbench@0.0.0", "dependsOn": [withpath_ref, "pkg:npm/tmp@1"]},
                                 {"ref": withpath_ref, "dependsOn": ["pkg:npm/core@1"]}]}

    def image(self):
        return bom([{"bom-ref": "pkg:deb/debian/bash@5", "type": "library", "name": "bash", "version": "5", "purl": "pkg:deb/debian/bash@5",
                     "properties": [{"name": "syft:location:0:path", "value": "/usr/share/doc/bash/copyright"}]}])

    def merge(self, *extra, src=None, img=None, home=None):
        out = os.path.join(self.tmp, "merged.json")
        if os.path.exists(out):
            os.remove(out)
        env = dict(os.environ, HOME=home) if home else None
        p = subprocess.run([sys.executable, "-I", AUG, "merge-source", self.w("img.json", img or self.image()), self.w("src.json", src or self.src()), out,
                            "--label", "app-source", "--repo", REPO, "--commit", COMMIT, "--app-name", "openmediavault", "--app-version", "8.6.1-1",
                            *extra], capture_output=True, text=True, env=env)
        return p.returncode, (p.stdout.strip().splitlines() or [""])[-1], out

    def strings(self, o, path=""):
        if isinstance(o, dict):
            for k, v in o.items():
                yield path + ".<key>", k
                yield from self.strings(v, path + "." + k)
        elif isinstance(o, list):
            for i, v in enumerate(o):
                yield from self.strings(v, "%s[%d]" % (path, i))
        elif isinstance(o, str):
            yield path, o

    def assert_clean(self, doc, name):
        """整份 JSON（鍵與值，沒有例外欄位）都沒有暫存路徑；原始碼元件沒有「整個值是絕對路徑」的字串。"""
        text = json.dumps(doc, ensure_ascii=False)
        for b in (self.tmp, self.tmp.replace("/", "\\/"), urllib.parse.quote(self.tmp, safe=""), ".sca-scan-work", "/home/runner"):
            self.assertNotIn(b, text, name)
        for c in doc.get("components") or []:
            if props(c).get("dumpling:origin") != "source":
                continue
            for p, v in self.strings(c):
                self.assertFalse(v.startswith("/") and " " not in v, "%s 原始碼元件有絕對路徑 %s=%s" % (name, p, v))

    def by_name(self, d):
        return {c["name"]: c for c in d["components"] if props(c).get("dumpling:origin") == "source"}

    def test_paths_become_relative_and_all_outputs_are_clean(self):
        rc, line, out = self.merge("--work-parent", self.parent)
        self.assertEqual(rc, 0, line)
        d = rj(out)
        src = self.by_name(d)
        rel = "deb/openmediavault/workbench/package-lock.json"
        self.assertEqual(props(src["tmp"])["SrcFile"], rel)
        ev = src["tmp"]["evidence"]["identity"][0]
        self.assertEqual((ev["concludedValue"], ev["methods"][0]["value"]), (rel, rel))
        self.assertEqual(props(src["tmp"])["ResolvedUrl"], "https://registry.npmjs.org/tmp/-/tmp-1.tgz")            # 網址不動
        core = src["core"]
        self.assertEqual(core["description"], "Route requests to /login and /api/v1; limit 10 /s")                  # 自由文字不碰
        pc = props(core)
        self.assertEqual((pc["Other"], pc["Url"], pc["Work"]), ("core.js", "a/b.json", "o/cdxgen/bom.json"))       # 只留檔名、file:// 拿掉、相對於 WORK
        wp = src["withpath"]
        self.assertEqual(wp["purl"], "pkg:npm/withpath@1?file_path=a.json")                                          # purl 的 qualifier（百分比編碼）
        self.assertEqual(wp["bom-ref"], "dumpling:src:app-source:pkg:npm/withpath@1?file_path=a.json")              # bom-ref 也改
        deps = {e["ref"]: e["dependsOn"] for e in d["dependencies"]}
        self.assertEqual(deps[wp["bom-ref"]], ["dumpling:src:app-source:pkg:npm/core@1"])                           # 依賴的 ref 對得起來
        self.assertIn(wp["bom-ref"], deps[src["openmediavault"]["bom-ref"]])
        allrefs = {c["bom-ref"] for c in d["components"]} | {x["bom-ref"] for c in d["components"] for x in c.get("components", [])}
        for e in d["dependencies"]:
            for r in [e["ref"]] + e["dependsOn"]:
                self.assertIn(r, allrefs | {"root-1"})
        self.assertEqual(props(src["nested"]["components"][0])["SrcFile"], rel)
        self.assertEqual(props(src["openmediavault"])["SrcFile"], ".")                                               # 根目錄本身
        bash = [c for c in d["components"] if c["name"] == "bash"][0]
        self.assertEqual(props(bash)["syft:location:0:path"], "/usr/share/doc/bash/copyright")                      # 映像裡的路徑原樣
        mp = {x["name"]: x["value"] for x in d["metadata"]["properties"]}
        self.assertRegex(mp["dumpling:augment:source:app-source:paths"], r"^改成相對路徑 \d+ 個；不在原始碼根目錄底下的絕對路徑只留檔名 1 個$")
        self.assertIn("只留檔名 1", line)
        self.assert_clean(d, "merged")
        lay = os.path.join(self.tmp, "layers")
        r = subprocess.run([sys.executable, "-I", self.LAYERS, "split", out, "ai-nas", os.path.join(ROOT, "projects", "ai-nas-demo"), lay,
                            "--os-responsibility", "ours"], capture_output=True, text=True)
        self.assertIn(r.returncode, (0, 3), r.stdout + r.stderr)
        made = sorted(f for f in os.listdir(lay) if f.endswith(".cdx.json"))
        self.assertTrue({"sbom.bsp.cdx.json", "sbom.os.cdx.json", "sbom.product.cdx.json"} <= set(made), made)
        for f in made:
            self.assert_clean(rj(os.path.join(lay, f)), f)

    def test_without_work_parent_only_whole_absolute_values_change(self):
        rc, line, out = self.merge()
        self.assertEqual(rc, 0, line)
        src = self.by_name(rj(out))
        self.assertEqual(props(src["tmp"])["SrcFile"], "package-lock.json")
        self.assertEqual(src["core"]["description"], "Route requests to /login and /api/v1; limit 10 /s")

    def test_root_must_be_the_real_parent(self):
        # 同樣長得像 .sca-scan-work.XXXXXX/cdxgen-src，但不在 --work-parent 底下：不當成 WORK（整個值是絕對路徑的只留檔名）
        other = os.path.join(self.tmp, "elsewhere", ".sca-scan-work.Zz99Yy", "cdxgen-src")
        rc, line, out = self.merge("--work-parent", self.parent, src=self.src(other))
        self.assertEqual(rc, 0, line)
        self.assertEqual(props(self.by_name(rj(out))["tmp"])["SrcFile"], "package-lock.json")
        self.assertIn("相對 0、", line)

    def test_two_work_dirs_fail(self):
        s = self.src()
        s["components"][0]["properties"][0]["value"] = os.path.join(self.parent, ".sca-scan-work.Qq11Ww", "cdxgen-src", "a.json")
        rc, line, _ = self.merge("--work-parent", self.parent, src=s)
        self.assertEqual(rc, 1)
        self.assertIn("2 個不同的掃描暫存資料夾", line)

    def test_abspath_and_realpath_of_the_same_work_are_one_root(self):
        real = os.path.join(self.tmp, "real-out")
        os.makedirs(os.path.join(real, "augment"))
        link = os.path.join(self.tmp, "link-out")
        os.symlink(real, link)
        parent = os.path.join(link, "augment")
        s = self.src(os.path.join(parent, self.SUF, "cdxgen-src"))                                  # abspath（經過符號連結）
        s["components"][0]["properties"][0]["value"] = os.path.join(real, "augment", self.SUF, "cdxgen-src", "x.json")   # realpath
        rc, line, out = self.merge("--work-parent", parent, src=s)
        self.assertEqual(rc, 0, line)
        d = rj(out)
        self.assertEqual(props(self.by_name(d)["tmp"])["SrcFile"], "x.json")
        for b in (real, link):
            self.assertNotIn(b, json.dumps(d))

    def test_safety_net_knows_the_other_spelling_of_the_work_dir(self):
        # 原始碼 SBOM 只出現 abspath 的寫法；映像 SBOM 裡出現同一個 WORK 的 realpath 寫法 → 也算 WORK，FAIL、不輸出
        real = os.path.join(self.tmp, "real-out")
        os.makedirs(os.path.join(real, "augment"))
        link = os.path.join(self.tmp, "link-out")
        os.symlink(real, link)
        parent = os.path.join(link, "augment")
        img = self.image()
        img["components"][0]["properties"].append({"name": "y", "value": os.path.join(real, "augment", self.SUF, "o", "log.txt") + " (scan)"})
        rc, line, out = self.merge("--work-parent", parent, src=self.src(os.path.join(parent, self.SUF, "cdxgen-src")), img=img)
        self.assertEqual(rc, 1, line)
        self.assertIn("改寫後 SBOM 仍有掃描暫存資料夾的路徑", line)
        self.assertFalse(os.path.exists(out))

    def test_safety_net_fails_on_unhandled_forms(self):
        # 鍵名裡的路徑（只改值，不改鍵）、映像元件裡的 WORK 路徑：都不該出現，出現就 FAIL、不輸出
        s = self.src()
        s["components"][0]["properties"].append({"name": "x", self.root + "/k": "v"})
        rc, line, out = self.merge("--work-parent", self.parent, src=s)
        self.assertEqual(rc, 1, line)
        self.assertIn("改寫後 SBOM 仍有掃描暫存資料夾的路徑", line)
        self.assertFalse(os.path.exists(out))
        img = self.image()
        img["components"][0]["properties"].append({"name": "y", "value": "see " + self.work.replace("/", "\\/") + "\\/z"})
        rc, line, out = self.merge("--work-parent", self.parent, img=img)
        self.assertEqual(rc, 1, line)
        self.assertFalse(os.path.exists(out))

    def minimal_src(self, comp):
        return {"bomFormat": "CycloneDX", "specVersion": "1.6",
                "metadata": {"component": {"bom-ref": "app", "type": "application", "name": "a", "version": "1"}},
                "components": [comp], "dependencies": []}

    def test_duplicate_bom_ref_after_rewrite_fails(self):
        s = self.src()
        s["components"].append({"bom-ref": "pkg:npm/dup@1?file=" + self.root + "/x.json", "type": "library", "name": "dup1"})
        s["components"].append({"bom-ref": "pkg:npm/dup@1?file=x.json", "type": "library", "name": "dup2"})
        rc, line, out = self.merge("--work-parent", self.parent, src=s)
        self.assertEqual(rc, 1, line)
        self.assertIn("路徑改寫後 bom-ref 重複", line)
        self.assertFalse(os.path.exists(out))

    def test_safety_net_root_only_in_a_key(self):
        # find_work 只看值：根目錄只出現在鍵名時找不到 → 最後保險直接用 --work-parent 的樣式比對，仍然 FAIL（不是結束碼 0）
        comp = {"bom-ref": "pkg:npm/k@1", "type": "library", "name": "k", "properties": [{"name": "x", self.root + "/k.json": "v"}]}
        rc, line, out = self.merge("--work-parent", self.parent, src=self.minimal_src(comp))
        self.assertEqual(rc, 1, line)
        self.assertIn("改寫後 SBOM 仍有掃描暫存資料夾的路徑", line)
        self.assertFalse(os.path.exists(out))

    def test_safety_net_double_percent_encoding(self):
        # 兩層百分比編碼的 purl：find_work 只解一層 → 最後保險反覆解碼，仍然 FAIL
        twice = urllib.parse.quote(urllib.parse.quote(self.root + "/a.json", safe=""), safe="")
        comp = {"bom-ref": "pkg:npm/e@1", "type": "library", "name": "e", "purl": "pkg:npm/e@1?file_path=" + twice}
        rc, line, out = self.merge("--work-parent", self.parent, src=self.minimal_src(comp))
        self.assertEqual(rc, 1, line)
        self.assertIn("改寫後 SBOM 仍有掃描暫存資料夾的路徑", line)
        self.assertFalse(os.path.exists(out))

    def test_image_metadata_component_path_does_not_trip_the_safety_net(self):
        # 精靈那次掃描（映像）的 WORK 寫在 metadata.component.name（之後 sbom-layers.py tag 才換掉）：不在 --work-parent 底下，不擋
        img = self.image()
        img["metadata"]["component"]["name"] = os.path.join(self.tmp, "wizard-out", "x", ".sca-scan-work.Mm55Nn", "image.tar")
        rc, line, _ = self.merge("--work-parent", self.parent, img=img)
        self.assertEqual(rc, 0, line)

    def test_home_cache_work_dir(self):
        # sca-scan 的 WORK 退回 $HOME/.cache/sca-scan/work.XXXXXX 時：映像的 metadata.component.name 有這種路徑不擋（之後才換掉），
        # 其他地方有就 FAIL
        home = os.path.join(self.tmp, "home")
        hw = os.path.join(home, ".cache", "sca-scan", "work.Hh77Jj")
        img = self.image()
        img["metadata"]["component"]["name"] = hw + "/image.tar"
        rc, line, _ = self.merge("--work-parent", self.parent, img=img, home=home)
        self.assertEqual(rc, 0, line)
        img["components"][0]["properties"].append({"name": "z", "value": "see " + hw + "/log (x)"})
        rc, line, out = self.merge("--work-parent", self.parent, img=img, home=home)
        self.assertEqual(rc, 1, line)
        self.assertFalse(os.path.exists(out))

    def test_no_syntax_warning(self):
        r = subprocess.run([sys.executable, "-I", "-W", "error::SyntaxWarning", "-c",
                            "import ast,sys;ast.parse(open(sys.argv[1],encoding='utf-8').read())", AUG], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_scan_disk_passes_work_parent(self):
        with open(os.path.join(ROOT, "pipeline", "platforms", "_shared", "scan-disk.sh"), encoding="utf-8") as f:
            sh = f.read()
        self.assertIn('--out "$out/augment/app-scan"', sh)                       # sca-scan 的 --out 在 $out/augment 底下
        self.assertIn('--work-parent "$out/augment")', sh)                        # → WORK 在 $out/augment/.sca-scan-work.XXXXXX

if __name__ == "__main__":
    unittest.main()
