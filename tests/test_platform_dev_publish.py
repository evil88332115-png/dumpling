"""pipeline/dev-release-publish.sh（dev.yml 的滾動 pre-release）：用假的 gh 測，不連網。

重點：main／dev/** 上同一個 tag 只有功能分支留下的草稿時，要依 id 刪掉草稿、新建公開的 pre-release（不是把草稿改成公開）；
已經公開的 pre-release 照舊改說明、覆蓋附件；刪除只用在同一個 tag 的草稿。
"""
import json
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "pipeline", "dev-release-publish.sh")
DEV_YML = os.path.join(ROOT, ".github", "workflows", "dev.yml")

FAKE_GH = r"""#!/usr/bin/env python3
import json, os, sys
d = os.environ["FAKE_GH_STATE"]
sp = os.path.join(d, "state.json")
st = json.load(open(sp))
a = sys.argv[1:]
st.setdefault("calls", []).append(a)
def save(): json.dump(st, open(sp, "w"))
def fail_once(key):
    n = st.get("fail", {}).get(key, 0)
    if n > 0:
        st["fail"][key] = n - 1; save(); return True
    return False
def opt(name):
    return a[a.index(name) + 1] if name in a else None
def by_tag(tag):
    # gh release view／edit／upload 用 tag 找：只找得到公開的 Release（草稿沒有 git tag）
    r = [x for x in st["releases"] if x["tag_name"] == tag and x["draft"] is False]
    return r[0] if r else None
if a[:1] == ["api"]:
    method, args = "GET", a[1:]
    if args[:1] == ["-X"]:
        method, args = args[1], args[2:]
    parts = args[0].split("/")
    if method == "GET" and parts[-1] == "releases":
        if fail_once("list"):
            save(); sys.stderr.write("HTTP 403\n"); sys.exit(1)
        save(); rels = st["releases"]
        sys.stdout.write(json.dumps(rels[:1]) + "\n" + json.dumps(rels[1:])); sys.exit(0)
    if method == "GET" and parts[-2] == "releases":
        r = [x for x in st["releases"] if str(x["id"]) == parts[-1]]
        save(); print(json.dumps(r[0])); sys.exit(0)
    if method == "DELETE":
        st.setdefault("deleted", []).append(int(parts[-1]))
        st["releases"] = [x for x in st["releases"] if str(x["id"]) != parts[-1]]; save(); sys.exit(0)
if a[:2] == ["release", "create"]:
    tag = a[2]
    if not ("--draft" in a) and by_tag(tag):
        save(); sys.stderr.write("already exists\n"); sys.exit(1)
    files = []
    for x in a[3:]:
        if x.startswith("--"): break
        files.append(os.path.basename(x))
    st["releases"].append({"id": st["next"], "tag_name": tag, "draft": "--draft" in a, "prerelease": "--prerelease" in a,
                           "name": opt("--title"), "body": opt("--notes"), "assets": [{"name": f} for f in files]})
    st["next"] += 1; save(); sys.exit(0)
if a[:2] == ["release", "edit"]:
    r = by_tag(a[2])
    if not r:
        save(); sys.stderr.write("release not found\n"); sys.exit(1)
    r["prerelease"] = "--prerelease" in a or r.get("prerelease"); r["body"] = opt("--notes"); save(); sys.exit(0)
if a[:2] == ["release", "upload"]:
    r = by_tag(a[2])
    if not r or fail_once("upload"):
        save(); sys.stderr.write("upload failed\n"); sys.exit(1)
    for x in a[3:]:
        if x.startswith("--"): break
        n = os.path.basename(x)
        if n not in [y["name"] for y in r["assets"]]:
            r["assets"].append({"name": n})
    save(); sys.exit(0)
if a[:2] == ["release", "delete-asset"]:
    r = by_tag(a[2])
    r["assets"] = [y for y in r["assets"] if y["name"] != a[3]]; save(); sys.exit(0)
save(); sys.stderr.write("fake gh: unsupported " + " ".join(a) + "\n"); sys.exit(9)
"""

TAG = "dev/rpi-lite-demo"
FILES = ("release-meta.json", "sbom-rpi-lite-demo-1.cdx.json", "layers.json")


class DevReleasePublish(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="dumpling-devpub-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.bin = os.path.join(self.dir, "bin")
        os.makedirs(self.bin)
        with open(os.path.join(self.bin, "gh"), "w") as fh:
            fh.write(FAKE_GH)
        os.chmod(os.path.join(self.bin, "gh"), 0o755)
        self.work = os.path.join(self.dir, "result")
        os.makedirs(self.work)
        for n in FILES:
            with open(os.path.join(self.work, n), "w") as fh:
                fh.write("{}")
        self.notes = os.path.join(self.dir, "notes.txt")
        with open(self.notes, "w") as fh:
            fh.write("開發版的最新 SBOM。")
        self.state_dir = os.path.join(self.dir, "state")
        os.makedirs(self.state_dir)

    def state(self, releases=(), **extra):
        with open(os.path.join(self.state_dir, "state.json"), "w") as fh:
            json.dump({"releases": list(releases), "next": 100, **extra}, fh)

    def load(self):
        with open(os.path.join(self.state_dir, "state.json")) as fh:
            return json.load(fh)

    def run_script(self, ref="refs/heads/main", files=FILES, tag=TAG):
        env = {"PATH": self.bin + ":" + os.environ["PATH"], "FAKE_GH_STATE": self.state_dir, "GH_REPO": "o/r",
               "GITHUB_REF": ref, "GITHUB_SHA": "abc123", "GHX_SLEEP": "0", "GHX_TRIES": "3", "TMPDIR": self.dir, "HOME": self.dir}
        return subprocess.run(["bash", SCRIPT, tag, self.notes, *files], capture_output=True, text=True, env=env, cwd=self.work)

    @staticmethod
    def rel(rid, draft, tag=TAG, assets=(), prerelease=True, name=None):
        return {"id": rid, "tag_name": tag, "draft": draft, "prerelease": prerelease, "name": name or tag,
                "assets": [{"name": n} for n in assets]}

    def calls(self, st, *prefix):
        return [c for c in st.get("calls", []) if c[:len(prefix)] == list(prefix)]

    # ---------------------------------------------------------------- main／dev/**：功能分支留下的草稿

    def test_main_with_only_a_feature_branch_draft_deletes_it_and_creates_a_public_prerelease(self):
        draft = self.rel(5, True, assets=("release-meta.json", "old-feature-only.json"), prerelease=False,
                         name=TAG + "（草稿，非 main／dev 分支）")
        self.state([draft])
        r = self.run_script()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        st = self.load()
        self.assertEqual(st["deleted"], [5])
        self.assertEqual(self.calls(st, "release", "edit"), [], "草稿不能直接改成公開")
        self.assertEqual(self.calls(st, "release", "upload"), [])
        [new] = st["releases"]
        self.assertFalse(new["draft"])
        self.assertTrue(new["prerelease"])
        self.assertEqual(new["name"], TAG + "（滾動的開發版）")
        self.assertEqual(sorted(x["name"] for x in new["assets"]), sorted(FILES), "功能分支的舊附件不能留下")
        [create] = self.calls(st, "release", "create")
        self.assertNotIn("--draft", create)
        self.assertEqual(create[create.index("--target") + 1], "abc123")
        self.assertIn("publish: OK（滾動 pre-release", r.stdout)

    def test_dev_branch_behaves_like_main(self):
        self.state([self.rel(5, True, prerelease=False)])
        r = self.run_script(ref="refs/heads/dev/rpi")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        st = self.load()
        self.assertEqual(st["deleted"], [5])
        self.assertEqual([(x["draft"], x["prerelease"]) for x in st["releases"]], [(False, True)])

    def test_only_drafts_of_the_same_tag_are_deleted(self):
        others = [self.rel(7, False, tag="dev/ai-nas-demo"), self.rel(8, True, tag="dev/ai-nas-demo"),
                  self.rel(9, True, tag=TAG + "-2"), self.rel(10, True, tag="v39.2.1")]
        self.state([others[0], self.rel(5, True), others[1], self.rel(6, True), others[2], others[3]])
        r = self.run_script()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        st = self.load()
        self.assertEqual(sorted(st["deleted"]), [5, 6])
        self.assertEqual([x["id"] for x in st["releases"][:4]], [7, 8, 9, 10])

    def test_draft_flag_must_be_exactly_true_to_delete(self):
        odd = self.rel(5, "true")
        odd2 = {k: v for k, v in self.rel(6, True).items() if k != "draft"}
        self.state([odd, odd2])
        r = self.run_script()
        st = self.load()
        self.assertEqual(st.get("deleted", []), [], r.stdout + r.stderr)

    def test_main_with_nothing_creates_a_public_prerelease(self):
        self.state()
        r = self.run_script()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        st = self.load()
        self.assertEqual(st.get("deleted", []), [])
        self.assertEqual([(x["draft"], x["prerelease"]) for x in st["releases"]], [(False, True)])

    # ---------------------------------------------------------------- main：已經公開的 pre-release 照舊改說明、覆蓋附件

    def test_existing_public_prerelease_is_edited_and_stale_assets_removed(self):
        pub = self.rel(3, False, assets=("release-meta.json", "kernel-versions-rpi-lite-demo-0.json"))
        self.state([pub])
        r = self.run_script()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        st = self.load()
        self.assertEqual(st.get("deleted", []), [])
        self.assertEqual(self.calls(st, "release", "create"), [])
        [edit] = self.calls(st, "release", "edit")
        self.assertIn("--prerelease", edit)
        self.assertEqual(edit[edit.index("--notes") + 1], "開發版的最新 SBOM。")
        [upload] = self.calls(st, "release", "upload")
        self.assertIn("--clobber", upload)
        self.assertEqual(sorted(x["name"] for x in st["releases"][0]["assets"]), sorted(FILES))
        self.assertEqual([c[3] for c in self.calls(st, "release", "delete-asset")], ["kernel-versions-rpi-lite-demo-0.json"])

    def test_public_prerelease_and_a_draft_of_the_same_tag_keeps_the_draft_and_edits(self):
        self.state([self.rel(3, False, assets=FILES), self.rel(5, True)])
        r = self.run_script()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        st = self.load()
        self.assertEqual(st.get("deleted", []), [])
        self.assertEqual(len(self.calls(st, "release", "edit")), 1)
        self.assertEqual(self.calls(st, "release", "create"), [])

    def test_upload_failure_keeps_the_old_assets(self):
        self.state([self.rel(3, False, assets=("release-meta.json", "old.json"))], fail={"upload": 5})
        r = self.run_script()
        self.assertNotEqual(r.returncode, 0)
        st = self.load()
        self.assertEqual(self.calls(st, "release", "delete-asset"), [])
        self.assertEqual(sorted(x["name"] for x in st["releases"][0]["assets"]), ["old.json", "release-meta.json"])

    def test_two_public_releases_of_the_same_tag_fail(self):
        self.state([self.rel(3, False), self.rel(4, False)])
        r = self.run_script()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("不只一個公開的 Release", r.stdout)
        st = self.load()
        self.assertEqual(self.calls(st, "release", "edit") + self.calls(st, "release", "create"), [])

    # ---------------------------------------------------------------- 功能分支：只建草稿

    def test_feature_branch_replaces_its_draft_and_never_touches_the_public_one(self):
        self.state([self.rel(3, False, assets=FILES), self.rel(5, True)])
        r = self.run_script(ref="refs/heads/wp1/m7d1")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        st = self.load()
        self.assertEqual(st["deleted"], [5])
        self.assertEqual(self.calls(st, "release", "edit") + self.calls(st, "release", "upload"), [])
        [create] = self.calls(st, "release", "create")
        self.assertIn("--draft", create)
        self.assertEqual(create[create.index("--title") + 1], TAG + "（草稿，非 main／dev 分支）")
        self.assertEqual([(x["id"], x["draft"]) for x in st["releases"]], [(3, False), (100, True)])
        self.assertIn("publish: OK（draft", r.stdout)

    # ---------------------------------------------------------------- 重試、分頁、參數

    def test_listing_is_retried_after_a_403(self):
        self.state([self.rel(5, True)], fail={"list": 2})
        r = self.run_script()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.load()["deleted"], [5])

    def test_listing_failure_stops_before_anything_is_changed(self):
        self.state([self.rel(5, True)], fail={"list": 9})
        r = self.run_script()
        self.assertNotEqual(r.returncode, 0)
        st = self.load()
        self.assertEqual(st.get("deleted", []), [])
        self.assertEqual(self.calls(st, "release", "create"), [])

    def test_usage_errors(self):
        self.state()
        env = {"PATH": self.bin + ":" + os.environ["PATH"], "FAKE_GH_STATE": self.state_dir}
        r = subprocess.run(["bash", SCRIPT, TAG, self.notes], capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 64)
        r = subprocess.run(["bash", SCRIPT, TAG, self.notes, "a.json"], capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 64)
        self.assertIn("缺少 GH_REPO", r.stdout)

    # ---------------------------------------------------------------- dev.yml 用這支腳本

    def test_dev_workflow_publishes_through_the_script(self):
        with open(DEV_YML, encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn('pipeline/dev-release-publish.sh" "$tag"', text)
        self.assertIn('GH_REPO="$GITHUB_REPOSITORY"', text)
        for inline in ("gh release create", "gh release edit", "gh release upload", "releases/$id"):
            self.assertNotIn(inline, text, inline)


if __name__ == "__main__":
    unittest.main()
