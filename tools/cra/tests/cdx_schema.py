"""CycloneDX 官方 JSON schema 的驗證器（測試共用；C1、C2 的 cra 測試都從這裡 import）。
cdx_validator() 是 1.6.1（本專案產生的 SBOM）；cdx_validator_14() 是 1.4（供應商 SBOM 正規化後的驗證，見 firmware_sbom_normalize.py）。"""
import json
from pathlib import Path

import pytest

DATA_DIR = Path(__file__).resolve().parent / "data"
SCHEMA_DIR = DATA_DIR / "cyclonedx-1.6.1"
SCHEMA_DIR_14 = DATA_DIR / "cyclonedx-1.4"


def _validator(schema_dir, bom_name):
    jsonschema = pytest.importorskip("jsonschema")
    referencing = pytest.importorskip("referencing")
    res = {}
    for n in (bom_name, "spdx.schema.json", "jsf-0.82.schema.json"):
        doc = json.loads((schema_dir / n).read_text(encoding="utf-8"))
        res["http://cyclonedx.org/schema/" + n] = referencing.Resource.from_contents(doc, default_specification=referencing.jsonschema.DRAFT7)
    reg = referencing.Registry().with_resources(res.items())
    return jsonschema.Draft7Validator(res["http://cyclonedx.org/schema/" + bom_name].contents, registry=reg)


def cdx_validator():
    """CycloneDX 1.6.1 官方 schema（tools/cra/tests/data/cyclonedx-1.6.1，來源與 SHA-256 見那裡的 README.md）。
    沒裝 jsonschema／referencing 時 skip；DUMPLING_REQUIRE_TEST_DATA=1 時 skip 算失敗（見 conftest.py）。"""
    return _validator(SCHEMA_DIR, "bom-1.6.schema.json")


def cdx_validator_14():
    """CycloneDX 1.4 官方 schema（tools/cra/tests/data/cyclonedx-1.4，來源與 SHA-256 見那裡的 README.md）。skip 規則同上。"""
    return _validator(SCHEMA_DIR_14, "bom-1.4.schema.json")
