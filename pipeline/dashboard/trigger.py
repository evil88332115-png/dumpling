#!/usr/bin/env python3
"""trigger.py：決定 pages.yml 這次要不要更新頁面（docs/DASHBOARD.md 第 5 節）。

用法（CI）：python3 -I pipeline/dashboard/trigger.py
  讀 $GITHUB_EVENT_NAME、$GITHUB_EVENT_PATH、$GITHUB_REPOSITORY、$GITHUB_REF。
  stdout 兩行：go=true|false、reason=<固定說明>（不含事件裡的任何字串，可以直接寫進 $GITHUB_OUTPUT）。

規則：
  - workflow_dispatch：只有 refs/heads/main 才更新。
  - workflow_run：
      * 來源 workflow 的 head_repository.full_name 必須等於本 repo（不能來自 fork）。
      * conclusion 不是 cancelled（failure 照樣更新：頁面要能顯示失敗）。
      * watch、dev：head_branch 必須是 main，event 必須是 schedule／workflow_dispatch／push。
      * release：event 必須是 push，head_branch（tag 名稱）經 collect.classify(tag, False) 判定為 "release"，
        而且版本部分以 v 開頭（release.yml 的觸發條件是 tags: ["*/v*"]）。
  - 其他一律不更新。
觸發只是「該更新了」的訊號：頁面資料之後一律重新從 API 讀，不用事件帶進來的任何欄位產生內容。
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import watchlib  # noqa: E402

MAIN_REF = "refs/heads/main"
EVENTS_MAIN = ("schedule", "workflow_dispatch", "push")
# dev.yml 在 dev/** 分支 push 時也會更新滾動的開發版（C0 決定 2026-11-15 收進來；workflow 定義讀預設分支，fork 碰不到）
DEV_BRANCH_RE = re.compile(r"dev/[A-Za-z0-9._/-]{1,200}")


def _str(x):
    return x if isinstance(x, str) else None


def decide(event_name, event, repository, ref):
    """→ (go: bool, reason: 固定字串)。event 是 GITHUB_EVENT_PATH 的 JSON（不可信，型別都要檢查）。"""
    if event_name == "workflow_dispatch":
        if ref == MAIN_REF:
            return True, "手動觸發，在 main 上"
        return False, "手動觸發不在 main 上，跳過"
    if event_name != "workflow_run":
        return False, "不是 workflow_run 或 workflow_dispatch，跳過"
    wr = event.get("workflow_run") if isinstance(event, dict) else None
    if not isinstance(wr, dict):
        return False, "事件裡沒有 workflow_run，跳過"
    head_repo = wr.get("head_repository")
    full = _str(head_repo.get("full_name")) if isinstance(head_repo, dict) else None
    if not repository or full != repository:
        return False, "來源 run 不是出自本 repo（fork 或缺資料），跳過"
    if wr.get("conclusion") == "cancelled":
        return False, "來源 run 被取消，跳過"
    name = _str(wr.get("name"))
    run_event = _str(wr.get("event"))
    branch = _str(wr.get("head_branch"))
    if name == "dev" and branch is not None and branch != "main":
        if not DEV_BRANCH_RE.fullmatch(branch) or ".." in branch.split("/"):
            return False, "dev 的來源分支不是 main 也不是 dev/**，跳過"
        if run_event != "push":
            return False, "dev/** 分支的 dev run 不是 push 觸發，跳過"
        return True, "dev 在 dev/** 分支 push 完成"
    if name in ("watch", "dev"):
        if branch != "main":
            return False, "watch／dev 的來源分支不是 main，跳過"
        if run_event not in EVENTS_MAIN:
            return False, "watch／dev 的觸發事件不是 schedule／workflow_dispatch／push，跳過"
        return True, "watch／dev 在 main 上完成"
    if name == "release":
        if run_event != "push":
            return False, "release 不是 tag push 觸發（例如手動建的 draft），跳過"
        if branch is None:
            return False, "release 沒有 head_branch，跳過"
        kind = watchlib.load("collect").classify(branch, False)[0]
        # release.yml 的觸發條件是 tags: ["*/v*"]：版本部分一定以 v 開頭（classify 只看 <專案>/<版本> 的字元，feature/x 也會過）
        if kind != "release" or not branch.split("/")[1].startswith("v"):
            return False, "release 的 head_branch 不是 <專案>/<版本> 的 tag 格式，跳過"
        return True, "release 的 tag push 完成"
    return False, "來源 workflow 不是 watch／dev／release，跳過"


def main(env=None):
    env = os.environ if env is None else env
    event_name = env.get("GITHUB_EVENT_NAME", "")
    path = env.get("GITHUB_EVENT_PATH", "")
    event = {}
    if path:
        try:
            with open(path, encoding="utf-8") as f:
                event = json.load(f)
        except (OSError, ValueError, RecursionError):
            sys.stdout.write("go=false\nreason=讀不到事件檔，跳過\n")
            return 0
    go, reason = decide(event_name, event, env.get("GITHUB_REPOSITORY", ""), env.get("GITHUB_REF", ""))
    sys.stdout.write("go=%s\nreason=%s\n" % ("true" if go else "false", reason))
    return 0


if __name__ == "__main__":
    sys.exit(main())
