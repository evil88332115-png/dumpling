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
        self.assertEqual(props(ub)["dumpling:advisory-check"], "NOT_ASSESSED")
        self.assertNotIn("cpe", ub)
        self.assertNotIn("purl", ub)
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


if __name__ == "__main__":
    unittest.main()
