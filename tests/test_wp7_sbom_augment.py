"""WP7：pipeline/platforms/_shared/sbom_augment.py（原始磁區元件、併入原始碼 SBOM）。合成資料、不連網。"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

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
    """原始碼 SBOM（cdxgen）的絕對路徑：併入後改成相對於原始碼根目錄（<WORK>/cdxgen-src）的路徑；其他絕對路徑只留檔名。
    鎖住：完整、-bsp、-os、產品 SBOM（sbom-layers.py split 的實際輸出）走訪整份 JSON 都沒有暫存路徑；原始碼元件沒有任何絕對路徑。
    映像元件（Syft 記的是裝置上的路徑，例如 /usr/lib/…）不是暫存路徑，原樣保留。"""
    LAYERS = os.path.join(ROOT, "pipeline", "sbom-layers.py")

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wp7-aug-paths-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.parent = os.path.join(self.tmp, "out", "augment")
        os.makedirs(self.parent)
        self.root = os.path.join(self.parent, ".sca-scan-work.Ab12Cd", "cdxgen-src")     # sca-scan 掃完會刪掉：這裡也不建

    def w(self, name, doc):
        p = os.path.join(self.tmp, name)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(doc, f)
        return p

    def lockfile(self, rel):
        return os.path.join(self.root, rel)

    def src(self, root=None):
        root = root or self.root
        f = os.path.join(root, "deb/openmediavault/workbench/package-lock.json")
        def lib(name, extra=None):
            c = {"bom-ref": "pkg:npm/%s@1" % name, "type": "library", "name": name, "version": "1", "purl": "pkg:npm/%s@1" % name,
                 "properties": [{"name": "SrcFile", "value": f}, {"name": "ResolvedUrl", "value": "https://registry.npmjs.org/%s/-/%s-1.tgz" % (name, name)}],
                 "evidence": {"identity": [{"field": "purl", "confidence": 1, "concludedValue": f,
                                            "methods": [{"technique": "manifest-analysis", "confidence": 1, "value": f}]}]}}
            c.update(extra or {})
            return c
        return {"bomFormat": "CycloneDX", "specVersion": "1.6",
                "metadata": {"component": {"bom-ref": "pkg:npm/openmediavault-workbench@0.0.0", "type": "application",
                                           "name": "openmediavault-workbench", "version": "0.0.0",
                                           "properties": [{"name": "SrcFile", "value": root}]}},
                "components": [lib("tmp"), lib("core", {"description": "built from /home/runner/work/_temp/x/core.js"}),
                               lib("nested", {"components": [lib("inner")]})],
                "dependencies": []}

    def image(self):
        return bom([{"bom-ref": "pkg:deb/debian/bash@5", "type": "library", "name": "bash", "version": "5", "purl": "pkg:deb/debian/bash@5",
                     "properties": [{"name": "syft:location:0:path", "value": "/usr/share/doc/bash/copyright"}]}])

    def merge(self, *extra, src=None):
        out = os.path.join(self.tmp, "merged.json")
        p = subprocess.run([sys.executable, "-I", AUG, "merge-source", self.w("img.json", self.image()), self.w("src.json", src or self.src()), out,
                            "--label", "app-source", "--repo", REPO, "--commit", COMMIT, "--app-name", "openmediavault", "--app-version", "8.6.1-1",
                            *extra], capture_output=True, text=True)
        return p.returncode, (p.stdout.strip().splitlines() or [""])[-1], out

    def strings(self, o, path=""):
        if isinstance(o, dict):
            for k, v in o.items():
                yield from self.strings(v, path + "." + k)
        elif isinstance(o, list):
            for i, v in enumerate(o):
                yield from self.strings(v, "%s[%d]" % (path, i))
        elif isinstance(o, str):
            yield path, o

    def assert_clean(self, doc, name):
        bad = ("/home/runner", ".sca-scan-work", self.tmp)
        for p, v in self.strings(doc):
            for b in bad:
                self.assertNotIn(b, v, "%s %s" % (name, p))
        for c in doc.get("components") or []:
            if props(c).get("dumpling:origin") != "source":
                continue
            for p, v in self.strings({k: x for k, x in c.items() if k not in ("bom-ref", "purl")}):
                self.assertNotRegex(v, r"(^|[\s(=])/(?!/)[^\s]*", "%s 原始碼元件有絕對路徑 %s" % (name, p))

    def test_paths_become_relative_and_all_outputs_are_clean(self):
        rc, line, out = self.merge("--work-parent", self.parent)
        self.assertEqual(rc, 0, line)
        self.assertIn("路徑：相對 ", line)
        d = rj(out)
        src = {c["name"]: c for c in d["components"] if props(c).get("dumpling:origin") == "source"}
        self.assertEqual(props(src["tmp"])["SrcFile"], "deb/openmediavault/workbench/package-lock.json")
        ev = src["tmp"]["evidence"]["identity"][0]
        self.assertEqual((ev["concludedValue"], ev["methods"][0]["value"]), ("deb/openmediavault/workbench/package-lock.json",) * 2)
        self.assertEqual(props(src["tmp"])["ResolvedUrl"], "https://registry.npmjs.org/tmp/-/tmp-1.tgz")   # 網址不動
        self.assertEqual(src["core"]["description"], "built from core.js")                                 # 根目錄外的絕對路徑：只留檔名
        self.assertEqual(props(src["nested"]["components"][0])["SrcFile"], "deb/openmediavault/workbench/package-lock.json")
        self.assertEqual(props(src["openmediavault"])["SrcFile"], ".")                                      # 根目錄本身
        bash = [c for c in d["components"] if c["name"] == "bash"][0]
        self.assertEqual(props(bash)["syft:location:0:path"], "/usr/share/doc/bash/copyright")            # 映像裡的路徑原樣
        mp = {x["name"]: x["value"] for x in d["metadata"]["properties"]}
        self.assertEqual(mp["dumpling:augment:source:app-source:paths"], "改成相對路徑 13 個；不在原始碼根目錄底下的絕對路徑只留檔名 1 個")   # 4 個元件 × 3 個欄位＋根目錄本身
        self.assert_clean(d, "merged")
        lay = os.path.join(self.tmp, "layers")
        r = subprocess.run([sys.executable, "-I", self.LAYERS, "split", out, "ai-nas", os.path.join(ROOT, "projects", "ai-nas-demo"), lay,
                            "--os-responsibility", "ours"], capture_output=True, text=True)
        self.assertIn(r.returncode, (0, 3), r.stdout + r.stderr)
        made = sorted(f for f in os.listdir(lay) if f.endswith(".cdx.json"))
        self.assertIn("sbom.product.cdx.json", made)
        self.assertTrue({"sbom.bsp.cdx.json", "sbom.os.cdx.json"} <= set(made), made)
        for f in made:
            self.assert_clean(rj(os.path.join(lay, f)), f)

    def test_without_work_parent_absolute_paths_keep_only_file_name(self):
        rc, line, out = self.merge()
        self.assertEqual(rc, 0, line)
        d = rj(out)
        tmp = [c for c in d["components"] if c["name"] == "tmp"][0]
        self.assertEqual(props(tmp)["SrcFile"], "package-lock.json")
        self.assert_clean(d, "merged")

    def test_root_must_be_the_real_parent(self):
        # 同樣長得像 .sca-scan-work.XXXXXX/cdxgen-src，但不在 --work-parent 底下：不當成根目錄，只留檔名
        other = os.path.join(self.tmp, "elsewhere", ".sca-scan-work.Zz99Yy", "cdxgen-src")
        rc, line, out = self.merge("--work-parent", self.parent, src=self.src(other))
        self.assertEqual(rc, 0, line)
        self.assertEqual(props([c for c in rj(out)["components"] if c["name"] == "tmp"][0])["SrcFile"], "package-lock.json")
        self.assertIn("相對 0、只留檔名", line)

    def test_two_roots_fail(self):
        s = self.src()
        s["components"][0]["properties"][0]["value"] = os.path.join(self.parent, ".sca-scan-work.Qq11Ww", "cdxgen-src", "a.json")
        rc, line, _ = self.merge("--work-parent", self.parent, src=s)
        self.assertEqual(rc, 1)
        self.assertIn("2 個不同的掃描根目錄", line)

    def test_scan_disk_passes_work_parent(self):
        with open(os.path.join(ROOT, "pipeline", "platforms", "_shared", "scan-disk.sh"), encoding="utf-8") as f:
            sh = f.read()
        self.assertIn('--out "$out/augment/app-scan"', sh)                       # sca-scan 的 --out 在 $out/augment 底下
        self.assertIn('--work-parent "$out/augment")', sh)                        # → WORK 在 $out/augment/.sca-scan-work.XXXXXX

if __name__ == "__main__":
    unittest.main()
