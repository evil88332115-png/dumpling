"""CycloneDX 1.6.1 官方 JSON schema 的驗證器（測試共用；C1、C2 的 cra 測試都從這裡 import）。"""
import json
from pathlib import Path

import pytest

SCHEMA_DIR = Path(__file__).resolve().parent / "data" / "cyclonedx-1.6.1"


def cdx_validator():
    """CycloneDX 1.6.1 官方 schema（tools/cra/tests/data/cyclonedx-1.6.1，來源與 SHA-256 見那裡的 README.md）。
    沒裝 jsonschema／referencing 時 skip；DUMPLING_REQUIRE_TEST_DATA=1 時 skip 算失敗（見 conftest.py）。"""
    jsonschema = pytest.importorskip("jsonschema")
    referencing = pytest.importorskip("referencing")
    res = {}
    for n in ("bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json"):
        doc = json.loads((SCHEMA_DIR / n).read_text(encoding="utf-8"))
        res["http://cyclonedx.org/schema/" + n] = referencing.Resource.from_contents(doc, default_specification=referencing.jsonschema.DRAFT7)
    reg = referencing.Registry().with_resources(res.items())
    return jsonschema.Draft7Validator(res["http://cyclonedx.org/schema/bom-1.6.schema.json"].contents, registry=reg)
