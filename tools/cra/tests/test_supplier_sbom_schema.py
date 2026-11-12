"""供應商 SBOM 正規化（pipeline/lib/firmware_sbom_normalize.py）後的副本，用 CycloneDX 官方 schema 驗證。
原檔違規（頂層多出欄位、license 沒有 id 與 name）→ 驗證失敗；正規化後 → 通過；不認得的違規 → 照樣失敗（不能被「修好」）。
測資是自己組的（結構仿 3mdeb Dasharo 供應商 SBOM，但內容是假的；真的供應商 SBOM 不進 repo）。
真的供應商 SBOM 不進 repo，也不在這裡驗證（嚴格模式不允許 skip）；它的驗證見 docs/notes/c2-supplier-sbom.md。"""
import copy
import importlib.util
import json
from pathlib import Path

import pytest

from cdx_schema import cdx_validator, cdx_validator_14

REPO = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("firmware_sbom_normalize", REPO / "pipeline" / "lib" / "firmware_sbom_normalize.py")
fsn = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fsn)

SHA = "0" * 64


def supplier_doc(spec_version="1.4"):
    comp = {"type": "firmware", "bom-ref": "c1", "name": "coreboot", "version": "1.0", "purl": "pkg:generic/example/coreboot@1.0",
            "licenses": [{"license": {"id": "GPL-2.0-only"}}, {"license": {"url": "https://spdx.org/licenses/exceptions.html"}},
                         {"license": {"name": "Acme license"}}],
            "properties": [{"name": "k", "value": "v"}]}
    sub = {"type": "library", "bom-ref": "c2", "name": "sub", "licenses": [{"license": {"url": "https://example.com/l", "text": {"content": "x"}}}]}
    comp["components"] = [sub]
    return {"bomFormat": "CycloneDX", "specVersion": spec_version, "version": 1, "serialNumber": "urn:uuid:6af6c0e6-07e2-5fd1-bd28-05920655b7d3",
            "metadata": {"component": {"type": "firmware", "name": "box", "version": "1"}, "properties": [{"name": "fsp_path", "value": "a/b"}]},
            "components": [comp], "dependencies": [{"ref": "c1", "dependsOn": ["c2"]}],
            "platform": "Notebook X", "firmware_version": "v1.6.0"}


def errors(validator, doc):
    return sorted(e.message[:120] for e in validator.iter_errors(doc))


def test_original_is_invalid_and_normalized_copy_is_valid_14():
    v = cdx_validator_14()
    doc = supplier_doc()
    assert errors(v, doc)                              # 原檔不符 schema（DT 會拒收的原因）
    rec = fsn.normalize(doc, SHA)
    assert rec["applied"] and len(rec["changes"]) == 4 and rec["unnormalized"] == []
    assert errors(v, doc) == []                        # 正規化後通過官方 1.4 schema
    # 不刪資料：被移除的 license 項目與頂層欄位都在 property 裡
    names = [p["name"] for p in doc["metadata"]["properties"]]
    assert "dumpling:supplier-extra:platform" in names and "dumpling:normalized-changes" in names
    comp = doc["components"][0]
    assert [p["value"] for p in comp["properties"] if p["name"] == fsn.PROP_LICENSE_URL] == ["https://spdx.org/licenses/exceptions.html"]
    assert len(comp["licenses"]) == 2
    entry = [p for p in comp["components"][0]["properties"] if p["name"] == fsn.PROP_LICENSE_ENTRY][0]
    assert json.loads(entry["value"]) == {"text": {"content": "x"}, "url": "https://example.com/l"}


@pytest.mark.parametrize("ver", ["1.5", "1.6"])
def test_normalized_copy_is_valid_15_16(ver):
    # repo 只有 1.4 與 1.6.1 的官方 schema：1.5 只核對規則（頂層欄位搬走、license 項目搬走），1.6 另用官方 schema 驗證
    doc = supplier_doc(ver)
    rec = fsn.normalize(doc, SHA)
    assert rec["applied"] and len(rec["changes"]) == 4
    assert "platform" not in doc and "firmware_version" not in doc
    if ver == "1.6":
        v = cdx_validator()
        assert errors(v, doc) == []
        bad = supplier_doc(ver)
        assert errors(v, bad)


def test_unknown_violation_is_not_fixed():
    v = cdx_validator_14()
    doc = supplier_doc()
    doc["components"][0]["type"] = "not-a-type"         # 不認得的違規
    fsn.normalize(doc, SHA)
    errs = errors(v, doc)
    assert errs and any("not-a-type" in e for e in errs)   # 其他違規仍存在，DT 會拒收，報告照實 FAIL
    doc2 = supplier_doc()
    doc2["components"][0]["licenses"].append({"license": {"id": "NOT-AN-SPDX-ID"}})   # id 不合法不是「缺 id 與 name」，不處理
    fsn.normalize(doc2, SHA)
    assert any("NOT-AN-SPDX-ID" in e or "enum" in e for e in errors(v, doc2))


def test_already_valid_document_is_untouched():
    v = cdx_validator_14()
    doc = supplier_doc()
    del doc["platform"], doc["firmware_version"]
    del doc["components"][0]["licenses"][1]
    del doc["components"][0]["components"][0]["licenses"]
    before = copy.deepcopy(doc)
    rec = fsn.normalize(doc, SHA)
    assert doc == before and not rec["applied"] and rec["changes"] == []
    assert errors(v, doc) == []

