"""gitlab/.gitlab-ci.yml 的規則檢查（不連網；標準庫 unittest＋PyYAML）。

官方 JSON schema 的驗證是另一步（validate_schema.py，需要 jsonschema 與已核對 sha256 的 schema 檔），見 tests/run.d/c3-gitlab.sh。
"""
import importlib.util
import json
import re
import shlex
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import gitlabci  # noqa: E402

# 同 GitHub release.yml 的 */v* 與 pipeline/lib/project_config.py 的 VERSION_RE（v 加數字開頭）
TAG_RE_YAML = r"^[a-z0-9][a-z0-9-]*\/v[0-9][A-Za-z0-9._+-]*$"
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


def command_text(text, script):
    """text 裡以 python3 -I 執行 script 的那一個指令（含 \\ 接續的下一行），只取到指令結尾。只能出現一次（註解裡提到不算）。"""
    starts = [m.start() for m in re.finditer(r"python3\s+-I\s+" + re.escape(script), text)]
    if len(starts) != 1:
        raise AssertionError("%s 應該剛好呼叫一次，找到 %d 次" % (script, len(starts)))
    out = []
    for line in text[starts[0]:].splitlines():
        out.append(line.rstrip())
        if not line.rstrip().endswith("\\"):
            break
    return " ".join(x.rstrip("\\") for x in out)


def command_flags(text, script):
    return re.findall(r"(?<!\S)(--[a-z][a-z0-9-]*)", command_text(text, script))


def command_args(text, script):
    """{參數: 值}。用 shlex 依 shell 規則切字（引號裡有空白的值不會被切開，引號也會去掉）。"""
    toks = shlex.split(command_text(text, script))
    return {t: toks[i + 1] for i, t in enumerate(toks[:-1]) if t.startswith("--")}


class CiFile(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = gitlabci.load()
        cls.jobs = gitlabci.jobs(cls.doc)
        cls.text = gitlabci.CI_FILE.read_text(encoding="utf-8")
        cls.vars = cls.doc.get("variables", {})

    def items_of(self, job):
        """job 展開後的 script 項目清單（每個 - 一項）。"""
        out = []
        def flat(items):
            for it in items:
                if isinstance(it, list) and len(it) == 2 and all(isinstance(x, str) for x in it):
                    flat(self.doc[it[0]][it[1]])
                elif isinstance(it, list):
                    flat(it)
                else:
                    out.append(str(it))
        for k in ("before_script", "script", "after_script"):
            flat(self.jobs[job].get(k, []))
        return out

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
        for ok in ("orin-nano-demo/v39.2.1-demo1", "a/v1", "p1/v1.0+build"):
            self.assertTrue(rx.match(ok), ok)
        # 版本要 v 加數字開頭（同 GitHub 的 */v* 與 project_config.VERSION_RE）：a/1、V1.0 不建 release pipeline
        for bad in ("v1.0", "Orin/v1", "p/", "p/-1", "p/v1/x", "/v1", "p q/v1", "a/1", "p1/V1.0", "p/vx"):
            self.assertFalse(rx.match(bad), bad)

    def test_release_flow_rules(self):
        for n in ("release:build", "release:scan", "release:publish"):
            r = self.jobs[n]["rules"]
            self.assertTrue(any("CI_COMMIT_TAG" in x.get("if", "") for x in r), n)
        self.assertEqual(self.jobs["release:publish"]["needs"], ["release:scan"])
        # 會建 Release 的 job（直接呼叫 Releases API 或 release-publish.sh）：每一條規則都要是 tag，或明確的試跑（DUMPLING_RELEASE_DRY_RUN == "1"）
        for n, j in self.jobs.items():
            t = self.lines_of(n)
            if "/releases" in t or "release-publish.sh" in t:
                for x in j["rules"]:
                    self.assertTrue("CI_COMMIT_TAG" in x.get("if", "") or '$DUMPLING_RELEASE_DRY_RUN == "1"' in x.get("if", ""), (n, x))
        # 簽章（寫進透明紀錄）只在真的 tag push、不是試跑時跑：規則與腳本兩道都要有（#72 驗證）
        sign = self.jobs["release:sign"]
        tag_push = self.ctx(CI_PIPELINE_SOURCE="push", CI_COMMIT_TAG="orin-nano-demo/v39.2.0-demo1")
        self.assertEqual(gitlabci.job_when(sign, tag_push), "on_success")
        self.assertEqual(gitlabci.job_when(sign, dict(tag_push, DUMPLING_RELEASE_DRY_RUN="1")), "never")
        self.assertIn('[ "${DUMPLING_RELEASE_DRY_RUN:-0}" != 1 ] || { echo "sign: NOT_RUN（試跑不簽章', self.lines_of("release:sign"))

    def test_manual_pipeline_on_tag_ref_does_not_release(self):
        # #72 驗證應修 2：在 tag ref 上從網頁／API 手動建 pipeline（CI_COMMIT_TAG 有值）、沒帶 DRY_RUN → release 的 job 一個都不跑
        for src in ("web", "api"):
            ctx = self.ctx(CI_PIPELINE_SOURCE=src, CI_COMMIT_TAG="orin-nano-demo/v39.2.0-demo1")
            for n in ("release:build", "release:scan", "release:publish", "release:sign"):
                self.assertEqual(gitlabci.job_when(self.jobs[n], ctx), "never", (src, n))
            # 帶了 DRY_RUN＋DUMPLING_RELEASE_TAG：只有試跑（不簽）
            dry = dict(ctx, DUMPLING_RELEASE_DRY_RUN="1", DUMPLING_RELEASE_TAG="orin-nano-demo/v39.2.0-demo1")
            for n in ("release:build", "release:scan", "release:publish"):
                self.assertEqual(gitlabci.job_when(self.jobs[n], dry), "on_success", (src, n))
            self.assertEqual(gitlabci.job_when(self.jobs["release:sign"], dry), "never")

    def ctx(self, **kw):
        base = {"CI_DEFAULT_BRANCH": "main", "CI_API_V4_URL": "https://gitlab.example.com/api/v4"}
        base.update(kw)
        return base

    def test_rule_evaluator_basics(self):
        tag = {"CI_COMMIT_TAG": "orin-nano-demo/v39.2.0-demo1", "CI_PIPELINE_SOURCE": "push"}
        self.assertEqual(gitlabci.job_when(self.jobs["release:publish"], self.ctx(**tag)), "on_success")
        self.assertEqual(gitlabci.job_when(self.jobs["release:sign"], self.ctx(**tag)), "on_success")
        self.assertEqual(gitlabci.job_when(self.jobs["validate:unit-tests"], self.ctx(**tag)), "never")    # tag pipeline 不跑
        with self.assertRaises(ValueError):
            gitlabci.rule_matches('$A == "x" || foo()', {})

    def test_t17_dry_run_pipeline_writes_nothing(self):
        # 手動試跑（網頁、DUMPLING_RELEASE_DRY_RUN=1）：自動跑的 job 只有 release-publish.sh 碰得到寫入，而它在試跑時不寫（ReleasePublish 測試）；
        # 簽章、每日監控、dev:publish 都不會自動跑
        ctx = self.ctx(CI_PIPELINE_SOURCE="web", CI_COMMIT_BRANCH="main", DUMPLING_RELEASE_DRY_RUN="1", DUMPLING_RELEASE_TAG="orin-nano-demo/v39.2.0-demo1")
        auto = {n for n, j in self.jobs.items() if gitlabci.job_when(j, ctx) in ("on_success", "always")}
        self.assertTrue({"release:build", "release:scan", "release:publish"} <= auto, auto)
        self.assertNotIn("release:sign", auto)
        writes = ("--upload-file", "/releases", "issues.py apply", "art14.py", "cosign")
        for n in auto - {"release:publish"}:
            t = self.lines_of(n)
            self.assertFalse([w for w in writes if w in t], n)
        pub = self.lines_of("release:publish")
        self.assertFalse([w for w in writes if w in pub], "release:publish 的寫入只能在 release-publish.sh 裡")
        # 沒帶 DUMPLING_RELEASE_DRY_RUN=1 的手動 pipeline：release 的 job 都不跑
        ctx2 = self.ctx(CI_PIPELINE_SOURCE="web", CI_COMMIT_BRANCH="main", DUMPLING_RELEASE_TAG="orin-nano-demo/v39.2.0-demo1")
        for n in ("release:build", "release:scan", "release:publish", "release:sign"):
            self.assertEqual(gitlabci.job_when(self.jobs[n], ctx2), "never", n)
        self.assertIn('[ "${DUMPLING_RELEASE_DRY_RUN:-0}" = 1 ] || {', self.lines_of("release:build"))   # 沒有 tag 又不是試跑：resolve 就 FAIL

    def test_t19_open_mr_dedup(self):
        push = self.ctx(CI_PIPELINE_SOURCE="push", CI_COMMIT_BRANCH="dev/x")
        for n in ("validate:unit-tests", "firmware:fetch"):
            self.assertEqual(gitlabci.job_when(self.jobs[n], dict(push, CI_OPEN_MERGE_REQUESTS="g/p!1")), "never", n)
            self.assertEqual(gitlabci.job_when(self.jobs[n], push), "on_success", n)
            self.assertEqual(gitlabci.job_when(self.jobs[n], self.ctx(CI_PIPELINE_SOURCE="merge_request_event")), "on_success", n)
        # dev 的 build／scan 不受影響（只在 branch pipeline 跑）：整條 branch pipeline 照樣建立（never 不能放在 workflow:rules；#72 驗證）
        mr_open = dict(push, CI_OPEN_MERGE_REQUESTS="g/p!1")
        self.assertNotEqual(gitlabci.pipeline_when(self.doc, mr_open), "never")
        self.assertNotIn("CI_OPEN_MERGE_REQUESTS", json.dumps(self.doc["workflow"]))
        self.assertEqual(gitlabci.job_when(self.jobs["dev:build"], mr_open), "on_success")

    def test_t20_not_run_exit_3(self):
        for n in ("dev:publish", "release:sign"):
            self.assertEqual(self.jobs[n]["allow_failure"], {"exit_codes": [3]}, n)
        # 每一個印 NOT_RUN 的地方，之後的第一個 exit 一定是 3（exit 可能在同一項，也可能在下一項，例如 echo 與 - exit 分開寫；#72 驗證）
        for n in ("dev:publish", "firmware:dt", "watch:compute", "watch:notify", "release:sign"):
            items = self.items_of(n)
            seen = 0
            for k, it in enumerate(items):
                for m in re.finditer("NOT_RUN", it):
                    after = it[m.end():] + "\n" + (items[k + 1] if k + 1 < len(items) else "")
                    e = re.search(r"\bexit\s+(\d+)", after)
                    self.assertIsNotNone(e, (n, it))
                    self.assertEqual(e.group(1), "3", (n, it[:120]))
                    seen += 1
            self.assertGreater(seen, 0, n)

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
                self.assertNotRegex(ln, r"echo[^\n]*\$\{?(WATCH_GITLAB_TOKEN|WATCH_GITLAB_READ_TOKEN|CI_JOB_TOKEN)\b", n + " 不可印出 token")
            self.assertNotRegex(body, r"(?m)^\s*set\s+-[a-z]*x", n + " 不可 set -x（會洩漏 token）")
            if "/issues" in body:
                self.assertNotIn("CI_JOB_TOKEN", body, "官方文件沒有列出 job token 可用 Issues API：" + n)
        for n in self.jobs:
            if n != "watch:notify":
                self.assertNotIn("WATCH_GITLAB_TOKEN", self.lines_of(n) + json.dumps(self.jobs[n].get("variables", {})), "只有 watch:notify 用 WATCH_GITLAB_TOKEN：" + n)
            txt = self.lines_of(n) + json.dumps(self.jobs[n].get("variables", {}))
            if n != "watch:compute":
                self.assertNotIn("WATCH_GITLAB_READ_TOKEN", txt, "只有 watch:compute 用 WATCH_GITLAB_READ_TOKEN：" + n)
        c = self.lines_of("watch:compute")
        self.assertIn('GITLAB_TOKEN="$WATCH_GITLAB_READ_TOKEN" python3 -I pipeline/watch/issues.py read-state', c)
        self.assertIn('GITLAB_TOKEN="$WATCH_GITLAB_READ_TOKEN" python3 -I pipeline/watch/collect.py', c)

    def test_t10_art14_countdown_rules_and_token(self):
        j = self.jobs["art14:countdown"]
        sched = self.ctx(CI_PIPELINE_SOURCE="schedule", DUMPLING_JOB="art14")
        # 排程 DUMPLING_JOB=art14 會建立 pipeline；驗證完成前是 manual＋allow_failure（同 watch:*）
        self.assertNotEqual(gitlabci.pipeline_when(self.doc, sched), "never")
        self.assertEqual(gitlabci.job_when(j, sched), "manual")
        self.assertTrue(all(r.get("when") == "manual" and r.get("allow_failure") is True for r in j["rules"]))
        # 其他排程、其他來源都不跑
        for ctx in (self.ctx(CI_PIPELINE_SOURCE="schedule", DUMPLING_JOB="watch"), self.ctx(CI_PIPELINE_SOURCE="schedule", DUMPLING_JOB="dev"),
                    self.ctx(CI_PIPELINE_SOURCE="schedule"), self.ctx(CI_PIPELINE_SOURCE="web", DUMPLING_JOB="art14"),
                    self.ctx(CI_PIPELINE_SOURCE="push", CI_COMMIT_BRANCH="main"), self.ctx(CI_PIPELINE_SOURCE="merge_request_event")):
            self.assertEqual(gitlabci.job_when(j, ctx), "never", ctx)
        # art14 排程的 pipeline 裡只有 art14:countdown（以及 watch:*／dev 的 job 不會被這個排程帶起來）
        active = {n for n, jj in self.jobs.items() if gitlabci.job_when(jj, sched) != "never"}
        self.assertEqual(active, {"art14:countdown"})
        # 反方向：watch 排程不會跑 art14
        wsched = self.ctx(CI_PIPELINE_SOURCE="schedule", DUMPLING_JOB="watch")
        self.assertNotIn("art14:countdown", {n for n, jj in self.jobs.items() if gitlabci.job_when(jj, wsched) != "never"})
        # 指令與 token：獨立的 ART14_GITLAB_TOKEN（只有這個 job 用）、GITLAB_TOKEN 只在指令前綴、不印 token、GitLab 後端參數齊全
        c = self.lines_of("art14:countdown")
        self.assertIn('GITLAB_TOKEN="$ART14_GITLAB_TOKEN" python3 -I pipeline/watch/art14.py countdown', c)
        a = command_args(c, "pipeline/watch/art14.py")
        self.assertEqual((a["--backend"], a["--gitlab-url"], a["--gitlab-project"]), ("gitlab", "$CI_API_V4_URL", "$CI_PROJECT_ID"))
        self.assertNotRegex(c, r"echo[^\n]*\$\{?ART14_GITLAB_TOKEN")
        self.assertIn("ART14_GITLAB_TOKEN", c)
        self.assertNotIn("exit 3", c.replace("NOT_RUN", ""), "結束碼只有 0（OK）與 1（FAIL）")
        self.assertIn("exit 1", c)
        for n in self.jobs:
            if n != "art14:countdown":
                self.assertNotIn("ART14_GITLAB_TOKEN", self.lines_of(n) + json.dumps(self.jobs[n].get("variables", {})), n)
        for n in ("watch:compute", "watch:notify"):
            self.assertNotIn("art14.py", self.lines_of(n))
        self.assertNotRegex(c, r"(?m)^\s*set\s+-[a-z]*x")
        self.assertNotIn("CI_JOB_TOKEN", c)
        self.assertEqual(j["resource_group"], "art14")
        self.assertIn("art14-out/result.json", j["artifacts"]["paths"])

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
        # T-01：release-meta.py 的參數與 .github/workflows/release.yml 相同。不寫死清單：從兩邊的指令抓出參數名稱比對，
        # release.yml 加了參數（例如 M7a 的 --notes，adapter-gaps #26）而範本沒跟上就失敗。
        gh = (HERE.parents[1] / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        gh_flags = command_flags(gh, "pipeline/release-meta.py")
        mine = command_flags(self.lines_of("release:publish"), "pipeline/release-meta.py")
        self.assertIn("--scan-summary", gh_flags)          # 沒有它 report_status／release_gate 會是 NOT_RUN
        self.assertIn("--notes", gh_flags)
        self.assertEqual(sorted(mine), sorted(gh_flags), "release:publish 的 release-meta.py 參數和 release.yml 不同")

    def test_release_notes_rewritten_then_used(self):
        # release-meta.py --notes 重寫的 notes.md，就是 release-payload.py 拿來當 Release 說明的那一份（notes.md 與 release-meta.json 的 pipeline_result 一致）
        # release:publish 先跑 release-meta.py（重寫 result/notes.md），再跑 release-publish.sh result …（它的 release-payload.py 讀 $res/notes.md）
        text = self.lines_of("release:publish")
        meta = command_args(text, "pipeline/release-meta.py")
        self.assertEqual(meta.get("--notes"), "result/notes.md")
        m = re.search(r"bash gitlab/release-publish\.sh (\S+) ", text)
        self.assertEqual(m.group(1), "result")
        self.assertLess(text.index("pipeline/release-meta.py"), m.start())
        pub = (HERE.parent / "release-publish.sh").read_text(encoding="utf-8")
        self.assertEqual(command_args(pub, "\"$here/release-payload.py\"").get("--notes"), "$res/notes.md")

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
                if '"push"' in cond and r.get("when") != "never":
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


    def test_ephemeral_dt_cleanup_and_isolation(self):
        # 自架 runner：job 被取消或逾時也要收掉臨時 DT；compose 專案名與狀態資料夾每個 job 分開
        for n in ("release:scan", "dev:scan"):
            j = self.jobs[n]
            self.assertIn("bash pipeline/dt-ephemeral.sh down || true", "\n".join(j["after_script"]), n)
            self.assertLess("\n".join(j["after_script"]).index("dt-ephemeral.sh down"), "\n".join(j["after_script"]).index('rm -rf "$DUMPLING_OUT_BASE"'))
            self.assertEqual(j["variables"]["DT_EPH_PROJECT"], "dumpling-dt-$CI_JOB_ID")
            self.assertTrue(j["variables"]["DT_EPH_DIR"].startswith("$DUMPLING_OUT_BASE/"))
            self.assertIn("KCVE_CACHE_DIR", j["variables"])          # 跟 .kcve-cache 的變數合併，不是取代

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


class ReleasePublish(unittest.TestCase):
    """gitlab/release-publish.sh 的行為（T-21 先驗再傳、T-17 試跑不寫）：用假的 curl 記錄每一次呼叫。"""

    def setUp(self):
        import tempfile
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        d = Path(self.td.name)
        self.res, self.bin, self.log = d / "result", d / "bin", d / "curl.log"
        self.res.mkdir()
        self.bin.mkdir()
        # 假 curl：記錄每次呼叫。FAIL_UPLOAD=1 時，上傳回 HTTP 錯誤：有 --fail 才回非 0（同真的 curl：沒有 --fail 時 HTTP 4xx／5xx 也是 0）
        (self.bin / "curl").write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$CURL_LOG"\n'
                                       'case " $* " in *" --upload-file "*) if [ "${FAIL_UPLOAD:-}" = 1 ]; then '
                                       'case " $* " in *" --fail "*) exit 22 ;; esac; fi ;; esac\nexit 0\n')
        (self.bin / "curl").chmod(0o755)
        for f in ("sbom-p-v1.cdx.json", "release-meta.json", "notes.md"):
            (self.res / f).write_text("{}")
        (self.res / "manifest.tsv").write_text("sbom-p-v1.cdx.json\tSBOM\nrelease-meta.json\tmeta\n")

    def run_pub(self, **env):
        import os
        import subprocess
        e = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}", CURL_LOG=str(self.log), CI_API_V4_URL="https://gitlab.example.com/api/v4",
                 CI_PROJECT_ID="12", CI_JOB_TOKEN="tok")
        e.update(env)
        r = subprocess.run(["bash", str(HERE.parent / "release-publish.sh"), str(self.res), "p/v1", "p", "v1"], env=e, cwd=self.td.name,
                           capture_output=True, text=True)
        calls = self.log.read_text().splitlines() if self.log.exists() else []
        return r.returncode, r.stdout + r.stderr, calls

    def test_ok_uploads_then_creates_release(self):
        rc, out, calls = self.run_pub()
        self.assertEqual(rc, 0, out)
        self.assertEqual(len(calls), 3, calls)
        self.assertIn("--upload-file", calls[0])
        self.assertIn("--upload-file", calls[1])
        self.assertTrue(calls[2].endswith("/projects/12/releases"), calls[2])

    def test_any_invalid_attachment_uploads_nothing(self):
        # 第二個檔才有問題：第一個也不能先傳（T-21）
        cases = {"missing": "sbom-p-v1.cdx.json\tSBOM\nnot-there.json\tx\n",
                 "unsafe": "sbom-p-v1.cdx.json\tSBOM\n../etc/passwd\tx\n",
                 "duplicate": "sbom-p-v1.cdx.json\tSBOM\nsbom-p-v1.cdx.json\tSBOM\n",
                 "symlink": "sbom-p-v1.cdx.json\tSBOM\nlink.json\tx\n",
                 "directory": "sbom-p-v1.cdx.json\tSBOM\nsub\tx\n"}
        (self.res / "link.json").symlink_to(self.res / "release-meta.json")
        (self.res / "sub").mkdir()
        for name, manifest in cases.items():
            (self.res / "manifest.tsv").write_text(manifest)
            if self.log.exists():
                self.log.unlink()
            rc, out, calls = self.run_pub()
            self.assertNotEqual(rc, 0, name)
            self.assertEqual(calls, [], name)

    def test_manifest_without_trailing_newline_uploads_everything(self):
        # #72 驗證應修 1：最後一行沒有換行時，以前 bash 的 while read 會漏掉那一行（Release 卻掛著它的連結）
        for manifest, n in (("sbom-p-v1.cdx.json\tSBOM\nrelease-meta.json\tmeta", 2), ("sbom-p-v1.cdx.json\tSBOM", 1)):
            (self.res / "manifest.tsv").write_text(manifest)
            if self.log.exists():
                self.log.unlink()
            rc, out, calls = self.run_pub()
            self.assertEqual(rc, 0, out)
            ups = [c for c in calls if "--upload-file" in c]
            self.assertEqual(len(ups), n, calls)
            self.assertTrue(calls[-1].endswith("/projects/12/releases"))
            rel = json.load(open(Path(self.td.name) / "release.json"))
            self.assertEqual(len(rel["assets"]["links"]), n)

    def test_cr_in_manifest_uploads_nothing(self):
        for manifest in ("sbom-p-v1.cdx.json\tSBOM\rrelease-meta.json\tmeta\n", "sbom-p-v1.cdx.json\tSBOM\r\n"):
            (self.res / "manifest.tsv").write_bytes(manifest.encode())
            if self.log.exists():
                self.log.unlink()
            rc, out, calls = self.run_pub()
            self.assertNotEqual(rc, 0, repr(manifest))
            self.assertEqual(calls, [], repr(manifest))

    def test_upload_http_error_stops_before_release(self):
        # 上傳回 HTTP 錯誤：curl --fail 讓腳本停下，不建 Release（拿掉 --fail 這個測試會失敗）
        rc, out, calls = self.run_pub(FAIL_UPLOAD="1")
        self.assertNotEqual(rc, 0, out)
        self.assertFalse([c for c in calls if c.endswith("/releases")], calls)
        pub = (HERE.parent / "release-publish.sh").read_text(encoding="utf-8")
        for line in pub.splitlines():
            if line.strip().startswith("curl "):
                self.assertIn("--fail", line)

    def test_bad_tag_or_url_uploads_nothing(self):
        for env in ({"CI_API_V4_URL": "http://gitlab.example.com/api/v4"}, {"CI_PROJECT_ID": "1;x"}):
            rc, out, calls = self.run_pub(**env)
            self.assertNotEqual(rc, 0, env)
            self.assertEqual(calls, [], env)

    def test_dry_run_writes_nothing(self):
        rc, out, calls = self.run_pub(DUMPLING_RELEASE_DRY_RUN="1")
        self.assertEqual(rc, 0, out)
        self.assertEqual(calls, [])
        self.assertIn("release: DRY_RUN", out)
        self.assertIn("會上傳：sbom-p-v1.cdx.json", out)
        rc, out, calls = self.run_pub(DUMPLING_RELEASE_DRY_RUN="yes")          # 只認 0／1
        self.assertNotEqual(rc, 0)
        self.assertEqual(calls, [])


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
