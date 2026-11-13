#!/usr/bin/env python3
"""用 GitLab 官方 CI JSON schema 驗證 .gitlab-ci.yml。

用法：python3 -I gitlab/tests/validate_schema.py <ci.json> [<.gitlab-ci.yml>]
schema 檔要先由 gitlab/fetch-ci-schema.sh 下載並核對 sha256；這裡不連網。
做法與 tools/cra/tests/cdx_schema.py 相同：jsonschema 的 Draft7Validator（官方 schema 是 draft-07）。
結束碼：0＝通過、1＝不符 schema、2＝用法錯誤或缺 jsonschema／PyYAML。
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))


def main(argv):
    if len(argv) not in (2, 3):
        print("用法：validate_schema.py <ci.json> [<.gitlab-ci.yml>]", file=sys.stderr)
        return 2
    try:
        import jsonschema
        import gitlabci
    except ImportError as e:
        print("validate_schema: 缺少套件（%s）；CI 用 pip install --require-hashes 安裝固定版本" % e, file=sys.stderr)
        return 2
    schema = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    doc = gitlabci.load(argv[2]) if len(argv) == 3 else gitlabci.load()
    v = jsonschema.Draft7Validator(schema)
    errs = sorted(v.iter_errors(doc), key=lambda e: list(map(str, e.absolute_path)))
    for e in errs[:20]:
        print("schema: %s: %s" % ("/".join(map(str, e.absolute_path)) or "(root)", e.message[:300]))
    if errs:
        print("validate_schema: FAIL（%d 個錯誤）" % len(errs))
        return 1
    print("validate_schema: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
