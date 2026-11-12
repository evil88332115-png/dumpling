"""SBOM 分層（pipeline/lib/layers.py、pipeline/sbom-layers.py）的單元測試。不連網、不下載；Jetson 的標準答案測資是
tests/fixtures/jetson-r39.2.1-base.cdx.json.xz（Syft 1.55.0 對公開 R39.2.1 BSP＋範例 rootfs 的結果，3851 個元件）。"""
import copy
import json
import lzma
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(ROOT, "pipeline", "lib"))
import layers as ly  # noqa: E402
import project_config as pc  # noqa: E402

CLI = os.path.join(ROOT, "pipeline", "sbom-layers.py")
FIXTURE = os.path.join(ROOT, "tests", "fixtures", "jetson-r39.2.1-base.cdx.json.xz")
DEMO = os.path.join(ROOT, "projects", "orin-nano-demo")

# Jetson R39.2.1 base 的標準答案（Syft 1.55.0；固定資料，數字是實際數出來的，不是估計）。
# 改了分層規則或 platform.yml 讓這些數字變動時，要同時確認新的歸屬是對的（docs/LAYERS.md「標準答案」）。
JETSON_EXPECTED = {"total": 3851, "bsp": 1537, "os": 1975, "host-tool": 0, "unknown": 339,
                   "nvidia_l4t_debs": 69, "kernel_modules": 1468, "other_debs": 1974,
                   "unknown_by_purl_type": {"golang": 235, "maven": 3, "pypi": 101}}


def load_fixture():
    with lzma.open(FIXTURE, "rb") as fh:
        return json.loads(fh.read().decode("utf-8"))


def comp(name, version="1.0", purl=None, typ="library", props=None, **kw):
    c = {"type": typ, "name": name, "version": version, "bom-ref": "ref-" + name}
    if purl:
        c["purl"] = purl
    if props:
        c["properties"] = [{"name": k, "value": v} for k, v in props.items()]
    c.update(kw)
    return c


def deb(name, version="1.0"):
    return comp(name, version, "pkg:deb/ubuntu/%s@%s?arch=arm64&distro=ubuntu-24.04" % (name, version))


def sbom(*comps, deps=None):
    d = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "metadata": {"component": {"type": "container", "name": "img", "bom-ref": "root"}},
         "components": list(comps)}
    if deps is not None:
        d["dependencies"] = deps
    return d


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dumpling-layers-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.cfg = pc.load_platform_config("jetson")

    def classify(self, c, own=((), (), 0)):
        return ly.classify_component(c, self.cfg, own)

    def project(self, resp="customer", own=None, platform="jetson"):
        """在暫存資料夾複製示範專案，改 os_responsibility（與 own_software）。"""
        d = os.path.join(self.tmp, "proj-" + resp)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(DEMO, "project.yml"), encoding="utf-8") as fh:
            text = fh.read()
        text = text.replace('os_responsibility: "customer"', 'os_responsibility: "%s"' % resp)
        if own is not None:
            text = text.replace("own_software: []", "own_software: %s" % json.dumps(own))
        with open(os.path.join(d, "project.yml"), "w", encoding="utf-8") as fh:
            fh.write(text)
        return d

    def run_cli(self, *args):
        return subprocess.run([sys.executable, "-I", CLI, *args], capture_output=True, text=True)


class ClassifyRules(Base):
    def test_package_by_name_wildcard_not_version(self):
        for v in ("39.2.1-20260806224157", "1.0+rpt1", "6.8.12-tegra-39.2.1", "1:2.3-0ubuntu1"):
            self.assertEqual(self.classify(deb("nvidia-l4t-core", v)), ("bsp", "package-name"))
        self.assertEqual(self.classify(deb("nvidia-l4t-kernel-oot-modules")), ("bsp", "package-name"))
        # 版本字尾像 BSP 也不算（D-027）：名稱不符 → os
        self.assertEqual(self.classify(deb("openssl", "3.0.13-0ubuntu3.11+nvidia1")), ("os", "package-name"))
        self.assertEqual(self.classify(deb("libc6")), ("os", "package-name"))

    def test_other_distro_purl_types_use_names_too(self):
        rpm = comp("nvidia-l4t-core", purl="pkg:rpm/redhat/nvidia-l4t-core@1.0?arch=aarch64")
        self.assertEqual(self.classify(rpm), ("bsp", "package-name"))
        apk = comp("busybox", purl="pkg:apk/alpine/busybox@1.36")
        self.assertEqual(self.classify(apk), ("os", "package-name"))

    def test_percent_encoded_name_in_purl(self):
        self.assertEqual(ly.purl_type_name("pkg:deb/ubuntu/libstdc%2B%2B6@14?arch=arm64"), ("deb", "libstdc++6"))
        self.assertEqual(ly.purl_type_name("not-a-purl"), (None, None))

    def test_operating_system_and_firmware_types(self):
        self.assertEqual(self.classify(comp("ubuntu", typ="operating-system")), ("os", "component-type"))
        self.assertEqual(self.classify(comp("mb1", typ="firmware")), ("bsp", "component-type"))

    def test_path_rules(self):
        def k(path):
            return comp("m", purl="pkg:generic/m@1", props={"syft:location:0:path": path})
        self.assertEqual(self.classify(k("/usr/lib/modules/6.8.12-1021-tegra/kernel/net/8021q/8021q.ko")), ("bsp", "path"))
        self.assertEqual(self.classify(k("/boot/Image")), ("bsp", "path"))
        self.assertEqual(self.classify(k("Linux_for_Tegra/bootloader/uefi_jetson.bin")), ("bsp", "path"))
        self.assertEqual(self.classify(k("Linux_for_Tegra/flash.sh")), ("host-tool", "path"))
        self.assertEqual(self.classify(k("./Linux_for_Tegra/tools/kernel_flash/x.py")), ("host-tool", "path"))

    def test_path_without_rule_is_unknown_not_os(self):
        c = comp("daemon", purl="pkg:generic/daemon@1", props={"syft:location:0:path": "/usr/local/bin/daemon"})
        self.assertEqual(self.classify(c), ("unknown", "unresolved"))
        # 套件沒有路徑可看、也不是發行版套件 → unknown
        self.assertEqual(self.classify(comp("attrs", purl="pkg:pypi/attrs@1")), ("unknown", "unresolved"))
        self.assertEqual(self.classify(comp("x")), ("unknown", "unresolved"))

    def test_platform_can_declare_os_paths(self):
        cfg = copy.deepcopy(self.cfg)
        cfg["layers"]["os"] = {"paths": ["usr/share/*", "usr/lib/python3/dist-packages/*"]}
        self.assertEqual(pc.validate_platform_config(cfg, "jetson"), [])
        c = comp("py", purl="pkg:pypi/py@1", props={"syft:location:0:path": "/usr/lib/python3/dist-packages/py/METADATA"})
        self.assertEqual(ly.classify_component(c, cfg), ("os", "path"))
        # bsp 規則優先於 os 規則
        c2 = comp("m", purl="pkg:generic/m@1", props={"syft:location:0:path": "/usr/lib/modules/x/y.ko"})
        self.assertEqual(ly.classify_component(c2, cfg), ("bsp", "path"))
        bad = copy.deepcopy(self.cfg)
        bad["layers"]["os"] = {"packages": ["foo"]}      # os 不收套件名稱（本來就是預設）
        self.assertTrue(pc.validate_platform_config(bad, "jetson"))

    def test_multiple_paths_most_conservative_wins(self):
        c = comp("m", purl="pkg:generic/m@1", props={"syft:location:0:path": "/usr/lib/modules/a.ko", "syft:location:1:path": "Linux_for_Tegra/flash.sh"})
        self.assertEqual(self.classify(c)[0], "bsp")        # 在產品上的優先於 host-tool
        c = comp("m", purl="pkg:generic/m@1", props={"syft:location:0:path": "Linux_for_Tegra/flash.sh", "syft:location:1:path": "/opt/x"})
        self.assertEqual(self.classify(c)[0], "unknown")    # 有一個路徑判斷不了 → unknown，不當成 host-tool

    def test_untrusted_paths_are_ignored(self):
        for bad in ("../../usr/lib/modules/x.ko", "a/../usr/lib/modules/x.ko", "usr/lib/modules/\x00x.ko", ""):
            c = comp("m", purl="pkg:generic/m@1", props={"syft:location:0:path": bad})
            self.assertEqual(self.classify(c)[0], "unknown", repr(bad))

    def test_cyclonedx_evidence_occurrences_and_file_type(self):
        c = comp("m", purl="pkg:generic/m@1", evidence={"occurrences": [{"location": "/boot/Image"}]})
        self.assertEqual(self.classify(c), ("bsp", "path"))
        self.assertEqual(self.classify(comp("Linux_for_Tegra/flash.sh", typ="file")), ("host-tool", "path"))

    def test_own_software_by_marker_and_by_project_list(self):
        c = comp("ourd", purl="pkg:generic/ourd@1", **{"bom-ref": "sca-center:own:usr/bin/ourd"})
        self.assertEqual(self.classify(c), ("bsp", "own-software"))
        c = comp("x", purl="pkg:generic/x@1", props={"sca-center:source": "own software (configuration sbom.own_software)"})
        self.assertEqual(self.classify(c), ("bsp", "own-software"))
        own = ly.own_patterns({"own_software": ["ourapp-*", "opt/ours/*", "Free text description", ly.pc.PLACEHOLDER]})
        self.assertEqual(own, (["ourapp-*"], ["opt/ours/*"], 2))
        # 專案清單蓋過套件名稱規則：我們的套件即使是 os 預設也算 bsp
        self.assertEqual(self.classify(deb("ourapp-daemon"), own), ("bsp", "own-software-list"))
        self.assertEqual(self.classify(deb("ourapp-daemon")), ("os", "package-name"))
        c = comp("ours", purl="pkg:generic/ours@1", props={"syft:location:0:path": "/opt/ours/bin/ours"})
        self.assertEqual(self.classify(c, own), ("bsp", "own-software-list"))

    def test_children_inherit_the_parent_layer(self):
        parent = deb("openssl")
        parent["components"] = [deb("nvidia-l4t-core")]
        tagged, summary = ly.tag_sbom(sbom(parent), self.cfg, os_responsibility="customer", platform="jetson")
        kid = tagged["components"][0]["components"][0]
        self.assertEqual(ly.component_layer(kid), "os")
        self.assertEqual(summary["basis"], {"inherited": 1, "package-name": 1})
        self.assertEqual(ly.layer_counts(tagged)["os"], 2)

    def test_tag_records_responsibility_and_platform_and_is_idempotent(self):
        b = sbom(deb("openssl"))
        t1, _ = ly.tag_sbom(b, self.cfg, os_responsibility="ours", platform="jetson")
        t2, _ = ly.tag_sbom(t1, self.cfg, os_responsibility="ours", platform="jetson")
        self.assertEqual(t1, t2)
        self.assertEqual(ly.sbom_os_responsibility(t1), "ours")
        self.assertNotIn(ly.LAYER_PROP, json.dumps(b))      # 不改傳入的 SBOM
        with self.assertRaises(ly.LayerError):
            ly.tag_sbom(b, self.cfg, os_responsibility="nobody")

    def test_untagged_component_counts_as_unknown_never_dropped(self):
        parts, _ = ly.split_sbom(sbom(deb("a"), deb("b")))
        self.assertEqual(list(parts), ["unknown"])
        self.assertEqual(len(parts["unknown"]["components"]), 2)


class Split(Base):
    def test_partition_has_no_loss_and_no_duplicate(self):
        b = sbom(deb("nvidia-l4t-core"), deb("openssl"), comp("attrs", purl="pkg:pypi/attrs@1"),
                 comp("Linux_for_Tegra/flash.sh", typ="file"), comp("ubuntu", typ="operating-system"))
        tagged, _ = ly.tag_sbom(b, self.cfg)
        parts, _ = ly.split_sbom(tagged)
        refs = [c["bom-ref"] for p in parts.values() for c in p["components"]]
        self.assertEqual(sorted(refs), sorted(c["bom-ref"] for c in b["components"]))
        self.assertEqual({k: len(v["components"]) for k, v in parts.items()}, {"bsp": 1, "os": 2, "unknown": 1, "host-tool": 1})
        for k, p in parts.items():      # 每一份都標了自己是哪一層，metadata 的其他內容（主元件）保留
            self.assertEqual([q["value"] for q in p["metadata"]["properties"] if q["name"] == ly.PART_PROP], [k])
            self.assertEqual(p["metadata"]["component"]["name"], "img")

    def test_dependencies_only_inside_a_part_and_edges_are_counted(self):
        a, o = deb("nvidia-l4t-core"), deb("libc6")
        b = sbom(a, o, deps=[{"ref": "root", "dependsOn": ["ref-nvidia-l4t-core", "ref-libc6"]},
                             {"ref": "ref-nvidia-l4t-core", "dependsOn": ["ref-libc6"]}, {"ref": "ref-libc6", "dependsOn": []}])
        tagged, _ = ly.tag_sbom(b, self.cfg)
        parts, dropped = ly.split_sbom(tagged)
        self.assertEqual(dropped, 1)        # 只有 bsp→os 那一條跨層；root 在每一份裡都有，root 的邊各留自己那層的；不留懸空的 ref
        for p in parts.values():
            refs = {c["bom-ref"] for c in p["components"]} | {"root"}
            for d in p["dependencies"]:
                self.assertIn(d["ref"], refs)
                self.assertTrue(set(d.get("dependsOn", [])) <= refs)

    def test_groups_merge_bsp_and_unknown_and_skip_host_tool(self):
        tagged, _ = ly.tag_sbom(sbom(deb("nvidia-l4t-core"), comp("attrs", purl="pkg:pypi/attrs@1"), deb("libc6"),
                                      comp("Linux_for_Tegra/flash.sh", typ="file")), self.cfg)
        g, _ = ly.split_sbom(tagged, {"bsp": "bsp", "unknown": "bsp", "os": "os", "host-tool": None})
        self.assertEqual({k: len(v["components"]) for k, v in g.items()}, {"bsp": 2, "os": 1})


class FixtureJetson(Base):
    """標準答案測試的起點：Jetson R39.2.1 base 的各層數量。"""

    @classmethod
    def setUpClass(cls):
        cls.bom = load_fixture()

    def test_layer_counts_equal_the_expected_numbers(self):
        cfg = pc.load_platform_config("jetson")
        tagged, summary = ly.tag_sbom(self.bom, cfg, os_responsibility="customer", platform="jetson")
        e = JETSON_EXPECTED
        self.assertEqual(summary["total"], e["total"])
        self.assertEqual(summary["layers"], {"bsp": e["bsp"], "os": e["os"], "host-tool": e["host-tool"], "unknown": e["unknown"]})
        self.assertEqual(summary["unknown_by_purl_type"], e["unknown_by_purl_type"])
        self.assertEqual(sum(summary["layers"].values()), len(self.bom["components"]))

    def test_nvidia_l4t_packages_and_kernel_modules_are_bsp_and_ubuntu_is_os(self):
        cfg = pc.load_platform_config("jetson")
        tagged, _ = ly.tag_sbom(self.bom, cfg)
        l4t = [c for c in tagged["components"] if c["name"].startswith("nvidia-l4t-")]
        self.assertEqual(len(l4t), JETSON_EXPECTED["nvidia_l4t_debs"])
        self.assertTrue(all(ly.component_layer(c) == "bsp" for c in l4t))
        mods = [c for c in tagged["components"] if any(p["name"] == "syft:package:type" and p["value"] == "linux-kernel-module"
                                                                for p in c.get("properties", []))]
        self.assertEqual(len(mods), JETSON_EXPECTED["kernel_modules"])
        self.assertTrue(all(ly.component_layer(c) == "bsp" for c in mods))
        debs = [c for c in tagged["components"] if c.get("purl", "").startswith("pkg:deb/") and not c["name"].startswith("nvidia-l4t-")]
        self.assertEqual(len(debs), JETSON_EXPECTED["other_debs"])
        self.assertTrue(all(ly.component_layer(c) == "os" for c in debs))
        osid = [c for c in tagged["components"] if c["type"] == "operating-system"]
        self.assertEqual([ly.component_layer(c) for c in osid], ["os"])

    def test_nothing_is_silently_os(self):
        """歸 os 的只有發行版套件（+OS 本身）：沒有套件身分的元件不會在這裡變成 os。"""
        cfg = pc.load_platform_config("jetson")
        tagged, _ = ly.tag_sbom(self.bom, cfg)
        for c in tagged["components"]:
            if ly.component_layer(c) == "os":
                self.assertTrue(c.get("purl", "").startswith("pkg:deb/") or c["type"] == "operating-system", c["name"])


class Cli(Base):
    def split(self, resp="customer", sbom_doc=None, extra=(), tag=""):
        src = os.path.join(self.tmp, "in.cdx.json")
        with open(src, "w", encoding="utf-8") as fh:
            json.dump(sbom_doc if sbom_doc is not None else load_fixture(), fh)
        out = os.path.join(self.tmp, "out-" + resp + tag)
        r = self.run_cli("split", src, "jetson", self.project(resp), out, *extra)
        return r, out

    def read(self, out, name):
        with open(os.path.join(out, name), encoding="utf-8") as fh:
            return json.load(fh)

    def test_split_fixture_customer(self):
        r, out = self.split("customer")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(r.stdout.strip().startswith("sbom-layers: OK（bsp 1537、os 1975、host-tool 0、unknown 339（共 3851）"), r.stdout)
        self.assertEqual(sorted(os.listdir(out)), ["layers.json", "sbom.bsp.cdx.json", "sbom.os.cdx.json", "sbom.product.cdx.json"])
        doc = self.read(out, "layers.json")
        self.assertEqual(doc["components"], {"bsp": 1537, "os": 1975, "host-tool": 0, "unknown": 339})
        self.assertEqual(doc["files"]["bsp"]["layers"], {"bsp": 1537, "unknown": 339})        # unknown 跟著 bsp（待辦）
        self.assertEqual(doc["files"]["bsp"]["components"] + doc["files"]["os"]["components"], 3851)
        self.assertEqual(doc["files"]["product"]["components"], 3851)
        self.assertEqual(doc["upload_excludes"], ["host-tool"])
        self.assertEqual([(p["name_suffix"], p["sbom"]) for p in doc["scan_plan"]], [("-bsp", "sbom.bsp.cdx.json"), ("-os", "sbom.os.cdx.json")])
        self.assertFalse(doc["os_responsibility_gap"])
        # 元件不重複、不遺失：bsp 檔＋os 檔 的 bom-ref 就是原本的
        orig = [c["bom-ref"] for c in load_fixture()["components"]]
        parts = [c["bom-ref"] for n in ("sbom.bsp.cdx.json", "sbom.os.cdx.json") for c in self.read(out, n)["components"]]
        self.assertEqual(sorted(parts), sorted(orig))
        self.assertEqual(len(set(parts)), len(parts))
        # 產品檔：全部，每個元件都帶層
        prod = self.read(out, "sbom.product.cdx.json")
        self.assertEqual(ly.layer_counts(prod), {"bsp": 1537, "os": 1975, "host-tool": 0, "unknown": 339})
        self.assertEqual(ly.sbom_os_responsibility(prod), "customer")

    def test_scan_plan_per_os_responsibility(self):
        small = sbom(deb("nvidia-l4t-core"), deb("libc6"))
        plans = {}
        for resp in ("ours", "customer", "upstream-vendor"):
            r, out = self.split(resp, small)
            self.assertEqual(r.returncode, 0, r.stdout)
            plans[resp] = [(p["name_suffix"], p["sbom"], p["report_role"]) for p in self.read(out, "layers.json")["scan_plan"]]
        self.assertEqual(plans["ours"], [("", "sbom.product.cdx.json", "product：bsp＋os（OS 也是我們的待辦）")])
        self.assertEqual([x[:2] for x in plans["customer"]], [("-bsp", "sbom.bsp.cdx.json"), ("-os", "sbom.os.cdx.json")])
        self.assertIn("範例 rootfs", plans["customer"][1][2])
        self.assertIn("上游 OS 廠商負責", plans["upstream-vendor"][1][2])

    def test_override_os_responsibility_on_the_command_line(self):
        r, out = self.split("customer", sbom(deb("libc6")), ("--os-responsibility", "ours"), tag="-ours")
        self.assertEqual(self.read(out, "layers.json")["os_responsibility"], "ours")
        r2 = self.run_cli("split", os.path.join(self.tmp, "in.cdx.json"), "jetson", self.project("customer"), os.path.join(self.tmp, "o2"),
                          "--os-responsibility", "nobody")
        self.assertEqual(r2.returncode, 1)
        self.assertIn("FAIL", r2.stdout)

    def test_only_one_side_present_means_one_plan_item(self):
        r, out = self.split("customer", sbom(deb("libc6")))
        self.assertEqual(sorted(os.listdir(out)), ["layers.json", "sbom.os.cdx.json", "sbom.product.cdx.json"])
        self.assertEqual([p["name_suffix"] for p in self.read(out, "layers.json")["scan_plan"]], ["-os"])

    def test_host_tool_is_never_in_upload_files_but_is_kept_as_a_record(self):
        b = sbom(deb("nvidia-l4t-core"), comp("Linux_for_Tegra/flash.sh", typ="file"), comp("Linux_for_Tegra/tools/x.py", typ="file"))
        r, out = self.split("customer", b)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertEqual(sorted(os.listdir(out)), ["layers.json", "sbom.bsp.cdx.json", "sbom.host-tool.cdx.json", "sbom.product.cdx.json"])
        self.assertEqual(len(self.read(out, "sbom.host-tool.cdx.json")["components"]), 2)
        self.assertEqual([c["name"] for c in self.read(out, "sbom.product.cdx.json")["components"]], ["nvidia-l4t-core"])
        self.assertEqual([p["sbom"] for p in self.read(out, "layers.json")["scan_plan"]], ["sbom.bsp.cdx.json"])
        self.assertEqual(self.read(out, "layers.json")["files"]["host-tool"]["components"], 2)

    def test_own_software_from_project_makes_bsp(self):
        src = os.path.join(self.tmp, "in.cdx.json")
        with open(src, "w", encoding="utf-8") as fh:
            json.dump(sbom(deb("ourapp-daemon"), deb("libc6")), fh)
        out = os.path.join(self.tmp, "out-own")
        r = self.run_cli("split", src, "jetson", self.project("customer", own=["ourapp-*"]), out)
        self.assertEqual(r.returncode, 0, r.stdout)
        doc = self.read(out, "layers.json")
        self.assertEqual(doc["components"]["bsp"], 1)
        self.assertEqual(doc["own_software"], {"patterns": 1, "ignored_entries": 0, "matched_components": 1})

    def test_deterministic_output(self):
        r1, o1 = self.split("customer", sbom(deb("nvidia-l4t-core"), deb("libc6")))
        r2, o2 = self.split("customer", sbom(deb("nvidia-l4t-core"), deb("libc6")), ("--platforms-dir", pc.PLATFORMS_DIR), tag="-2")
        self.assertEqual(sorted(os.listdir(o1)), sorted(os.listdir(o2)))
        for n in os.listdir(o1):
            with open(os.path.join(o1, n), "rb") as f1, open(os.path.join(o2, n), "rb") as f2:
                self.assertEqual(f1.read(), f2.read(), n)

    def test_errors_and_exit_codes(self):
        p = self.project("customer")
        self.assertEqual(self.run_cli().returncode, 64)
        self.assertEqual(self.run_cli("split", "a", "jetson", p).returncode, 64)
        self.assertEqual(self.run_cli("split", "a", "jetson", p, "o", "--bogus").returncode, 64)
        bad = os.path.join(self.tmp, "bad.json")
        with open(bad, "w") as fh:
            fh.write("[1, 2]")
        r = self.run_cli("split", bad, "jetson", p, os.path.join(self.tmp, "o"))
        self.assertEqual((r.returncode, r.stdout.startswith("sbom-layers: FAIL")), (1, True), r.stdout)
        r = self.run_cli("split", os.path.join(self.tmp, "missing.json"), "jetson", p, os.path.join(self.tmp, "o"))
        self.assertEqual(r.returncode, 1)
        r = self.run_cli("split", bad, "no-such-platform", p, os.path.join(self.tmp, "o"))
        self.assertEqual(r.returncode, 1)

    def test_tag_and_show(self):
        src = os.path.join(self.tmp, "in.cdx.json")
        with open(src, "w", encoding="utf-8") as fh:
            json.dump(sbom(deb("nvidia-l4t-core"), deb("libc6")), fh)
        out = os.path.join(self.tmp, "tagged.json")
        r = self.run_cli("tag", src, "jetson", self.project("upstream-vendor"), out)
        self.assertEqual(r.returncode, 0, r.stdout)
        r = self.run_cli("show", out)
        self.assertEqual(json.loads(r.stdout), {"layers": {"bsp": 1, "os": 1, "host-tool": 0, "unknown": 0}, "total": 2,
                                                "os_responsibility": "upstream-vendor"})

    def test_xz_input(self):
        r = self.run_cli("tag", FIXTURE, "jetson", self.project("customer"), os.path.join(self.tmp, "t.json"))
        self.assertEqual(r.returncode, 0, r.stdout)


class JetsonPlatformConfig(unittest.TestCase):
    def test_paths_for_rootfs_and_bsp_folder(self):
        cfg = pc.load_platform_config("jetson")
        for p, want in (("usr/lib/modules/6.8.12-1021-tegra/updates/opensrc-disp/nvidia.ko", "bsp"), ("boot/Image", "bsp"),
                        ("Linux_for_Tegra/rootfs/usr/lib/modules/x/y.ko", "bsp"), ("Linux_for_Tegra/kernel/Image", "bsp"),
                        ("Linux_for_Tegra/bootloader/uefi_jetson.bin", "bsp"), ("Linux_for_Tegra/flash.sh", "host-tool"),
                        ("Linux_for_Tegra/tools/kernel_flash/flash_l4t_t234_nvme.xml", "host-tool"), ("etc/passwd", "os")):
            self.assertEqual(pc.classify_path(p, cfg), want, p)

    def test_properties_names_match_the_report_tool(self):
        """tools/cra/cra_report.py 為了不 import pipeline/lib 重複寫了 property 名稱，這裡核對兩邊一致。"""
        import re
        with open(os.path.join(ROOT, "tools", "cra", "cra_report.py"), encoding="utf-8") as fh:
            text = fh.read()
        m = re.search(r'LAYER_PROP, LAYER_BASIS_PROP, LAYER_RESP_PROP = "([^"]+)", "([^"]+)", "([^"]+)"', text)
        self.assertEqual(m.groups(), (ly.LAYER_PROP, ly.BASIS_PROP, ly.RESP_PROP))
        m = re.search(r'LAYER_PRECEDENCE = \(([^)]*)\)', text)
        self.assertEqual(tuple(re.findall(r'"([^"]+)"', m.group(1))), ly.PRECEDENCE)
        m = re.search(r'OS_RESPONSIBILITIES = \(([^)]*)\)', text)
        self.assertEqual(tuple(re.findall(r'"([^"]+)"', m.group(1))), pc.OS_RESPONSIBILITIES)


if __name__ == "__main__":
    unittest.main()
