"""gitlab/.gitlab-ci.yml 的規則檢查（不連網；標準庫 unittest＋PyYAML）。

官方 JSON schema 的驗證是另一步（validate_schema.py，需要 jsonschema 與已核對 sha256 的 schema 檔），見 tests/run.d/c3-gitlab.sh。
"""
import importlib.util
import json
import re
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import gitlabci  # noqa: E402

TAG_RE_YAML = r"^[a-z0-9][a-z0-9-]*\/[A-Za-z0-9][A-Za-z0-9._+-]*$"
VAR_PREFIXES = ("DUMPLING_", "WATCH_", "INTERNAL_", "PILOT_", "MIRROR_", "DT_")
PREDEFINED_OK = {"GIT_DEPTH", "GIT_STRATEGY", "GIT_SUBMODULE_STRATEGY", "GIT_CLEAN_FLAGS", "FF_USE_FASTZIP"}
# pipeline 腳本既有的環境變數名稱（不是範本自訂的）：pipeline/lib/mirrors.sh 的 KCVE_CACHE_DIR
PIPELINE_ENV_OK = {"KCVE_CACHE_DIR"}
DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")


def _spec(path, name):
    s = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


class CiFile(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = gitlabci.load()
        cls.jobs = gitlabci.jobs(cls.doc)
        cls.text = gitlabci.CI_FILE.read_text(encoding="utf-8")
        cls.vars = cls.doc.get("variables", {})

    def lines_of(self, job):
        """job 展開後的 script 文字（!reference 先展開成其內容）。"""
        out = []
        def flat(items):
            for it in items:
                if isinstance(it, list) and len(it) == 2 and all(isinstance(x, str) for x in it):
                    ref = self.doc[it[0]][it[1]]
                    flat(ref)
                elif isinstance(it, list):
                    flat(it)
                else:
                    out.append(str(it))
        for k in ("before_script", "script", "after_script"):
            flat(self.jobs[job].get(k, []))
        return "\n".join(out)

    def test_parse_and_top_level(self):
        self.assertIsInstance(self.doc, dict)
        self.assertEqual(self.doc["stages"], ["validate", "build", "scan", "release", "watch"])
        self.assertIn("workflow", self.doc)
        self.assertTrue(self.doc["workflow"]["rules"])

    def test_every_job_has_stage_and_script_or_trigger(self):
        for n, j in self.jobs.items():
            with self.subTest(job=n):
                self.assertIn(j.get("stage"), self.doc["stages"], "stage 要在 stages 裡")
                self.assertTrue(j.get("script") or j.get("trigger"), "要有 script 或 trigger")

    def test_script_items_are_strings(self):
        # 項目裡有「: 」的純量會被 YAML 當成 mapping（GitLab 會拒絕）；要用 | 區塊或加引號
        for n, j in self.doc.items():
            if n in gitlabci.RESERVED or not isinstance(j, dict):
                continue
            for k in ("before_script", "script", "after_script"):
                for it in j.get(k) or []:
                    with self.subTest(job=n, key=k):
                        self.assertIsInstance(it, (str, list), "script 項目不是字串：%r" % (it,))

    def test_extends_needs_references_exist(self):
        for n, j in self.doc.items():
            if n in gitlabci.RESERVED or not isinstance(j, dict):
                continue
            ext = j.get("extends") or []
            for e in ([ext] if isinstance(ext, str) else ext):
                self.assertIn(e, self.doc, "%s extends 不存在的 %s" % (n, e))
            for nd in j.get("needs") or []:
                target = nd if isinstance(nd, str) else nd["job"]
                self.assertIn(target, self.jobs, "%s needs 不存在的 job %s" % (n, target))
            for it in j.get("script") or []:
                if isinstance(it, list) and len(it) == 2 and all(isinstance(x, str) for x in it):
                    self.assertIn(it[1], self.doc.get(it[0], {}), "%s 的 !reference %s 不存在" % (n, it))

    def test_no_latest_and_images_pinned(self):
        self.assertNotRegex(self.text, r"(?im)^[^#\n]*:latest\b", "不可使用 :latest")
        imgs = []
        d = self.doc.get("default", {}).get("image")
        if d:
            imgs.append(("default", d))
        for n, j in self.jobs.items():
            if j.get("image"):
                imgs.append((n, j["image"]))
        self.assertTrue(imgs, "至少要有一個 image（default:image）")
        for n, im in imgs:
            name = im["name"] if isinstance(im, dict) else im
            name = gitlabci.expand_vars(name, self.vars)
            with self.subTest(job=n, image=name):
                self.assertNotIn("$", name, "image 變數沒有預設值")
                if DIGEST_RE.search(name):
                    continue
                last = name.rsplit("/", 1)[-1]
                self.assertIn(":", last, "沒有 tag 也沒有 digest")
                tag = last.split(":", 1)[1]
                self.assertNotEqual(tag.lower(), "latest")
                self.assertRegex(tag, r"\d", "tag 要是固定版本（含數字）")

    def test_variable_names(self):
        def check(vs, where):
            for k in vs:
                with self.subTest(where=where, var=k):
                    self.assertRegex(k, r"^[A-Z][A-Z0-9_]*$")
                    self.assertTrue(k.startswith(VAR_PREFIXES) or k in PREDEFINED_OK or k in PIPELINE_ENV_OK, "自訂變數要用 %s 開頭" % "／".join(VAR_PREFIXES))
        check(self.vars, "top")
        for n, j in self.doc.items():
            if n not in gitlabci.RESERVED and isinstance(j, dict) and isinstance(j.get("variables"), dict):
                check(j["variables"], n)

    def test_artifacts_have_expire_in(self):
        for n, j in self.jobs.items():
            a = j.get("artifacts")
            if a:
                with self.subTest(job=n):
                    self.assertIn("expire_in", a, "artifacts 要明確寫 expire_in（預設值取決於 instance 設定）")
                    self.assertNotEqual(str(a["expire_in"]).lower(), "never", "不用 never；長期保存靠 Package Registry 與 Release")

    def test_tag_regex_consistent_and_correct(self):
        found = re.findall(r"\$CI_COMMIT_TAG =~ /(.+?)/'", self.text)
        self.assertGreaterEqual(len(found), 2)
        for f in found:
            self.assertEqual(f, TAG_RE_YAML)
        rx = re.compile(TAG_RE_YAML.replace(r"\/", "/"))
        for ok in ("orin-nano-demo/v39.2.1-demo1", "a/1", "p1/V1.0+build"):
            self.assertTrue(rx.match(ok), ok)
        for bad in ("v1.0", "Orin/v1", "p/", "p/-1", "p/v1/x", "/v1", "p q/v1"):
            self.assertFalse(rx.match(bad), bad)

    def test_release_flow_rules(self):
        for n in ("release:build", "release:scan", "release:publish"):
            r = self.jobs[n]["rules"]
            self.assertTrue(any("CI_COMMIT_TAG" in x.get("if", "") for x in r), n)
        self.assertEqual(self.jobs["release:publish"]["needs"], ["release:scan"])
        # 有 tag 以外的條件才會跑的 job 不可以是 release 階段（避免非 tag 發 Release）
        for n, j in self.jobs.items():
            if "/releases" in self.lines_of(n):      # 呼叫 Releases API 的 job（建 Release）只能在 tag 跑
                self.assertTrue(any("CI_COMMIT_TAG" in x.get("if", "") for x in j["rules"]), n)

    def test_dev_and_firmware_rules(self):
        for n in ("dev:build", "dev:scan"):
            txt = json.dumps(self.jobs[n]["rules"])
            self.assertIn("^dev", txt)
            self.assertIn("DUMPLING_JOB", txt)
        fw = json.dumps(self.jobs["firmware:fetch"]["rules"])
        self.assertIn("changes", fw)
        self.assertIn("firmware/", fw)

    def test_watch_jobs_manual_until_backend_exists_and_confidential(self):
        for n in ("watch:compute", "watch:notify"):
            r = self.jobs[n]["rules"]
            self.assertTrue(all(x.get("when") == "manual" for x in r), n + " 在 GitLab 後端完成前必須 when: manual")
            self.assertIn("DUMPLING_JOB", json.dumps(r))
            self.assertIn("schedule", json.dumps(r))
            self.assertIn("NOT_RUN", self.lines_of(n), "沒有後端時要印 NOT_RUN，不假裝能跑")
        notify = self.lines_of("watch:notify")
        self.assertIn("--confidential", notify)
        self.assertEqual(self.jobs["watch:notify"]["variables"]["DUMPLING_ISSUES_CONFIDENTIAL"], "true")
        self.assertIn("watch:compute", self.jobs["watch:notify"]["needs"])

    def test_issue_creation_is_confidential_and_token_hygiene(self):
        for n in self.jobs:
            body = self.lines_of(n)
            for ln in body.splitlines():
                if re.search(r"/issues\b", ln) and re.search(r"(-X\s*POST|--data|-d\s)", ln):
                    self.assertIn("confidential=true", ln, "直接呼叫 Issues API 建 Issue 必須帶 confidential=true：" + n)
                self.assertNotRegex(ln, r"echo[^\n]*\$\{?(WATCH_GITLAB_TOKEN|CI_JOB_TOKEN)\b", n + " 不可印出 token")
            self.assertNotRegex(body, r"(?m)^\s*set\s+-[a-z]*x", n + " 不可 set -x（會洩漏 token）")
            if "/issues" in body:
                self.assertNotIn("CI_JOB_TOKEN", body, "官方文件沒有列出 job token 可用 Issues API：" + n)
        for n in self.jobs:
            if n != "watch:notify":
                self.assertNotIn("WATCH_GITLAB_TOKEN", self.lines_of(n) + json.dumps(self.jobs[n].get("variables", {})), "只有 watch:notify 用 WATCH_GITLAB_TOKEN：" + n)

    def test_signing_job(self):
        j = self.jobs["release:sign"]
        self.assertEqual(j["id_tokens"]["SIGSTORE_ID_TOKEN"]["aud"], "sigstore")
        self.assertEqual(self.vars["DUMPLING_SIGN_MODE"], "none", "預設不簽章")
        for n, other in self.jobs.items():
            if n != "release:sign":
                self.assertNotIn("id_tokens", other, "id_tokens 只給簽章 job")

    def test_no_internal_or_secret_literals(self):
        for pat in (r"(?i)glpat-[A-Za-z0-9_-]{10,}", r"(?i)password\s*[:=]\s*\S+", r"\b(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d+\.\d+(?:\.\d+)?\b"):
            self.assertNotRegex(self.text, pat)

    def test_script_lines_not_piped_through_tee_for_status(self):
        # tee 會吃掉前一個指令的結束碼（不同 shell 的 pipefail 行為不同）
        self.assertNotRegex(self.text, r"\|\s*tee\b")


    def test_t01_release_meta_same_flags_as_github(self):
        # T-01：release-meta.py 的參數與 .github/workflows/release.yml 相同（少了 --scan-summary，report_status／release_gate 會是 NOT_RUN）
        gh = (HERE.parents[1] / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        mine = self.lines_of("release:publish")
        for flag in ("--project", "--version", "--tag", "--commit", "--run-id", "--steps", "--scan-summary", "--out"):
            self.assertIn(flag, gh, "release.yml 已不用 %s：重新核對 T-01" % flag)
            self.assertIn(flag, mine, "release:publish 的 release-meta.py 少了 %s" % flag)

    def test_t01_kernel_cve_cache(self):
        # 核心 CVE 鏡像的上一份（pipeline/lib/mirrors.sh 的 KCVE_CACHE_DIR）：scan 與 watch:compute 都用，只存新抓的
        kc = self.doc[".kcve-cache"]
        self.assertTrue(kc["variables"]["KCVE_CACHE_DIR"].startswith("$CI_PROJECT_DIR/"), "cache 路徑要在專案資料夾內（官方）")
        self.assertEqual(kc["cache"]["paths"], [".kcve-cache/kcve/"])
        self.assertEqual(kc["cache"].get("when"), "always", "scan 失敗也存（同 pipeline.yml 的 !cancelled()）")
        self.assertIn(".kcve-cache", self.doc[".scan"]["extends"])
        for job in ("release:scan", "dev:scan", "watch:compute"):      # 展開 extends 後：有 cache 與變數（watch:compute 自己的變數也還在）
            self.assertEqual(self.jobs[job]["cache"], kc["cache"], job)
            self.assertEqual(self.jobs[job]["variables"]["KCVE_CACHE_DIR"], kc["variables"]["KCVE_CACHE_DIR"], job)
        self.assertIn("INTERNAL_MIRROR_URL", self.jobs["watch:compute"]["variables"])
        for job, name in (("release:scan", "kcve"), ("watch:compute", "kernel-cve")):
            self.assertIn("mirror_is_fresh %s" % name, self.lines_of(job))


    def test_tag_push_does_not_run_validate_jobs(self):
        # 官方 job_rules：tag 的 push 也是 CI_PIPELINE_SOURCE == "push"；validate 的 job 不能在 tag pipeline 跑（會擋 release）
        for n in ("validate:unit-tests", "firmware:fetch"):
            for r in self.jobs[n]["rules"]:
                cond = r.get("if", "")
                if '"push"' in cond:
                    self.assertIn('($CI_PIPELINE_SOURCE == "push" && $CI_COMMIT_BRANCH)', cond, n)

    def test_scan_matches_current_scan_sh(self):
        # pipeline/platforms/*/scan.sh 目前一定開臨時 DT（docker）並寫入 PILOT_ENV 這個路徑：範本不能要求 File 變數、要檢查 docker
        txt = self.lines_of("release:scan")
        self.assertIn('export PILOT_ENV="$DUMPLING_OUT_BASE/pilot-env/pilot.env"', txt)
        self.assertIn("command -v docker", txt)
        self.assertNotIn("test -n \"${PILOT_ENV:-}\"", txt)
        self.assertIn("bubblewrap python3-yaml $SCAN_APT", txt)
        scan_sh = (HERE.parents[1] / "pipeline" / "platforms" / "jetson" / "scan.sh").read_text(encoding="utf-8")
        self.assertIn("dt-ephemeral.sh", scan_sh, "scan.sh 已不用臨時 DT：重新評估 T-14 與範本的 scan")

    def test_platform_apt_and_sudo(self):
        # platform.yml 的 build.apt／scan.apt 要裝（同 pipeline.yml）；非 root 用 sudo（install-scan-tools.sh 本身用 sudo）
        for n in ("release:build", "dev:build"):
            self.assertIn("$SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends $BUILD_APT", self.lines_of(n))
        for n in ("release:build", "release:scan", "dev:build", "dev:scan"):
            txt = self.lines_of(n)
            self.assertIn("BUILD_APT=$(sed -n 's/^BUILD_APT=//p' info.txt); SCAN_APT=$(sed -n 's/^SCAN_APT=//p' info.txt)", txt)
            self.assertIn('if [ "$(id -u)" = 0 ]; then SUDO=""; else SUDO=sudo; fi', txt)
        self.assertIn("sudo", self.vars["DUMPLING_APT"].split())

    def test_watch_exit_codes_like_watch_round(self):
        c = self.lines_of("watch:compute")
        self.assertIn('[ "$rc" = 0 ] || [ "$rc" = 3 ] || exit "$rc"', c)
        self.assertIn('[ "$rc" = 0 ] || [ "$rc" = 2 ] || [ "$rc" = 3 ] || exit "$rc"', c)
        self.assertIn('install -m 0755 -t /usr/local/bin "$DUMPLING_OUT_BASE/tools/bin/grype"', c)
        self.assertIn("test -f watch-out/plan.json", self.lines_of("watch:notify"))

    def test_firmware_sbom_check_like_github(self):
        txt = self.lines_of("firmware:fetch")
        for x in ("install-tool.sh sbomqs", "check-tool-version.sh sbomqs", "firmware-sbom-check.sh"):
            self.assertIn(x, txt)


class ReleasePayload(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m = _spec(HERE.parent / "release-payload.py", "release_payload")

    def build(self, lines=("sbom-p-v1.cdx.json\tSBOM\n", "release-meta.json\tmeta\n"), **kw):
        a = dict(tag="p/v1", project="p", version="v1", api_url="https://gitlab.example.com/api/v4", project_id="12", notes_text="n")
        a.update(kw)
        return self.m.build(list(lines), **a)

    def test_payload_shape(self):
        p = self.build()
        self.assertEqual(p["tag_name"], "p/v1")
        links = p["assets"]["links"]
        self.assertEqual(links[0]["url"], "https://gitlab.example.com/api/v4/projects/12/packages/generic/p/v1/sbom-p-v1.cdx.json")
        self.assertEqual(links[0]["link_type"], "package")
        self.assertEqual(links[0]["direct_asset_path"], "/sbom-p-v1.cdx.json")

    def test_rejects_bad_input(self):
        for kw in ({"tag": "p/v2"}, {"project": "P"}, {"api_url": "http://gitlab.example.com/api/v4"}, {"project_id": "1;id"}):
            with self.assertRaises(ValueError, msg=str(kw)):
                self.build(**kw)
        for bad in ("../x\tl\n", "a b\tl\n", "-rf\tl\n", "/etc/passwd\tl\n"):
            with self.assertRaises(ValueError, msg=bad):
                self.build(lines=[bad])
        with self.assertRaises(ValueError):
            self.build(lines=[])


class SchemaValidatorScript(unittest.TestCase):
    """validate_schema.py 本身（用很小的假 schema，不需要官方檔案）。系統 python 沒有 jsonschema 就 skip（真正的驗證在 c3-gitlab-schema.sh 的 venv 裡跑）。"""

    def test_detects_violation(self):
        try:
            import jsonschema  # noqa: F401
        except ImportError:
            self.skipTest("沒有 jsonschema")
        import subprocess, tempfile
        with tempfile.TemporaryDirectory() as d:
            sch = Path(d) / "s.json"
            sch.write_text(json.dumps({"$schema": "http://json-schema.org/draft-07/schema#", "type": "object", "required": ["stages"], "properties": {"stages": {"type": "array"}}}))
            good, bad = Path(d) / "g.json", Path(d) / "b.json"
            good.write_text('{"stages": ["a"]}')
            bad.write_text('{"stages": "nope"}')
            script = str(HERE / "validate_schema.py")
            self.assertEqual(subprocess.run([sys.executable, "-I", script, str(sch), str(good)], capture_output=True).returncode, 0)
            self.assertEqual(subprocess.run([sys.executable, "-I", script, str(sch), str(bad)], capture_output=True).returncode, 1)


class SchemaData(unittest.TestCase):
    """repo 裡的 schema 資料夾：檔案齊全、sha256 與 SOURCE.md 一致、授權文件有兩種授權。"""
    D = HERE / "data" / "gitlab-ci-schema"
    SHA = "1c6eeb7d3a34c39996afbfe1ade220480eb05bbeae674e86d3c745dfeeded7fd"
    COMMIT = "28aa2bf90771a11ecc2f86525bc8a70a49c4d810"

    def test_files_and_hash(self):
        import hashlib
        for f in ("ci.json", "NOTICE", "LICENSE.md", "SOURCE.md"):
            self.assertTrue((self.D / f).is_file(), f)
        self.assertEqual(hashlib.sha256((self.D / "ci.json").read_bytes()).hexdigest(), self.SHA)
        src = (self.D / "SOURCE.md").read_text(encoding="utf-8")
        self.assertIn(self.SHA, src)
        self.assertIn(self.COMMIT, src)
        self.assertIn("app/assets/javascripts/editor/schema/ci.json", src)
        for needle in ("MIT Expat", "Apache-2.0", "未證實"):
            self.assertIn(needle, src)

    def test_license_md_has_both(self):
        t = (self.D / "LICENSE.md").read_text(encoding="utf-8")
        for needle in ("Copyright (c) 2011-present GitLab Inc.", "Permission is hereby granted, free of charge",
                       "Mads Kristensen", "https://www.apache.org/licenses/LICENSE-2.0"):
            self.assertIn(needle, t)
        self.assertIn("Mads Kristensen", (self.D / "NOTICE").read_text(encoding="utf-8"))

    def test_pins_agree(self):
        root = HERE.parent.parent
        for f in ("gitlab/fetch-ci-schema.sh", "tests/run.d/c3-gitlab-schema.sh"):
            self.assertIn(self.SHA, (root / f).read_text(encoding="utf-8"), f)


if __name__ == "__main__":
    unittest.main()
