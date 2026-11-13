#!/usr/bin/env python3
"""用 GitLab 官方 CI JSON schema 驗證「已轉成 JSON 的」.gitlab-ci.yml。

用法：python3 -I gitlab/tests/validate_schema.py <ci.json 的 schema> <instance.json>
instance.json 由系統 python 的 PyYAML 轉出（python3 -I gitlab/tests/gitlabci.py tojson <yml> <out.json>）；
這支在 venv 裡跑（只需要 tools/cra/tests/requirements.txt 的 jsonschema，不需要 PyYAML）。不連網。
做法與 tools/cra/tests/cdx_schema.py 相同：jsonschema 的 Draft7Validator（官方 schema 是 draft-07）。
結束碼：0＝通過、1＝不符 schema、2＝用法錯誤或缺 jsonschema。
"""
import json
import sys
from pathlib import Path


def main(argv):
    if len(argv) != 3:
        print("用法：validate_schema.py <schema.json> <instance.json>", file=sys.stderr)
        return 2
    try:
        import jsonschema
        from importlib.metadata import version
    except ImportError as e:
        print("validate_schema: 缺少 jsonschema（%s）" % e, file=sys.stderr)
        return 2
    print("jsonschema %s" % version("jsonschema"))
    schema = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    doc = json.loads(Path(argv[2]).read_text(encoding="utf-8"))
    errs = sorted(jsonschema.Draft7Validator(schema).iter_errors(doc), key=lambda e: list(map(str, e.absolute_path)))
    for e in errs[:20]:
        print("schema: %s: %s" % ("/".join(map(str, e.absolute_path)) or "(root)", e.message[:300]))
    if errs:
        print("validate_schema: FAIL（%d 個錯誤）" % len(errs))
        return 1
    print("validate_schema: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
