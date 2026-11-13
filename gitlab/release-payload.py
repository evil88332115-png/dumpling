#!/usr/bin/env python3
"""產生 GitLab Releases API（POST /projects/:id/releases）的 JSON：附件 assets links 指向 Generic Package Registry 的檔案。

用法：python3 -I gitlab/release-payload.py --manifest result/manifest.tsv --tag <專案>/<版本> --project <專案> --version <版本> \
        --api-url "$CI_API_V4_URL" --project-id "$CI_PROJECT_ID" [--notes result/notes.md] [--files-dir result] --out release.json
manifest.tsv 每行「檔名<TAB>標籤」（與 GitHub 版 release.yml 的 manifest 相同）。
欄位名稱依官方 Releases API：tag_name、name、description、assets.links[].name／url／direct_asset_path／link_type。
所有輸入都當不可信資料：檔名只允許安全字元，不含路徑。
--files-dir：每個附件都要是這個資料夾裡的一般檔案（不是連結、不是資料夾），而且不重複。gitlab/release-publish.sh 先用它驗完全部，
驗過才上傳（GITLAB-PORT T-21：驗不過時一個檔都不上傳）。
"""
import argparse
import json
import os
import re
import stat
import sys

SAFE_FILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
SAFE_NAME = re.compile(r"^[a-z0-9][a-z0-9-]*$")
SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")


def build(manifest_lines, tag, project, version, api_url, project_id, notes_text="", files_dir=None):
    if not SAFE_NAME.match(project) or not SAFE_VERSION.match(version):
        raise ValueError("專案或版本含不安全字元")
    if tag != project + "/" + version:
        raise ValueError("tag 必須是 <專案>/<版本>")
    if not re.match(r"^https://[A-Za-z0-9.-]+(:[0-9]+)?(/[A-Za-z0-9._/-]*)?$", api_url):
        raise ValueError("api-url 必須是 https 網址")
    if not re.match(r"^[0-9]+$", str(project_id)):
        raise ValueError("project-id 必須是數字")
    links, seen = [], set()
    for ln in manifest_lines:
        ln = ln.rstrip("\n")
        if not ln:
            continue
        f, _, label = ln.partition("\t")
        if not SAFE_FILE.match(f):
            raise ValueError("附件檔名含不安全字元：" + f)
        if f in seen:
            raise ValueError("附件重複：" + f)
        seen.add(f)
        if files_dir is not None:
            try:
                st = os.lstat(os.path.join(files_dir, f))
            except OSError:
                raise ValueError("manifest 列出的附件不存在：" + f)
            if not stat.S_ISREG(st.st_mode):
                raise ValueError("附件不是一般檔案（連結或資料夾）：" + f)
        links.append({
            "name": label or f,
            "url": "%s/projects/%s/packages/generic/%s/%s/%s" % (api_url.rstrip("/"), project_id, project, version, f),
            "direct_asset_path": "/" + f,
            "link_type": "package",
        })
    if not links:
        raise ValueError("manifest 是空的")
    return {"tag_name": tag, "name": tag, "description": notes_text, "assets": {"links": links}}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--project", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--api-url", required=True)
    ap.add_argument("--project-id", required=True)
    ap.add_argument("--notes")
    ap.add_argument("--files-dir", help="附件所在的資料夾：每個附件都要存在而且是一般檔案")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    try:
        with open(a.manifest, encoding="utf-8") as fh:
            lines = fh.readlines()
        notes = ""
        if a.notes:
            try:
                with open(a.notes, encoding="utf-8") as fh:
                    notes = fh.read()
            except FileNotFoundError:
                notes = ""
        payload = build(lines, a.tag, a.project, a.version, a.api_url, a.project_id, notes, a.files_dir)
    except (ValueError, OSError) as e:
        print("release-payload: FAIL（%s）" % e)
        return 1
    with open(a.out, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    print("release-payload: OK（%d 個附件）" % len(payload["assets"]["links"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
