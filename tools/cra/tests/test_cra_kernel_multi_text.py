"""cra_report.py：M7d-1（逐顆判定的合併文件）與 M7d-5（核心段落的固定英文句）接在一起時，文字讀每顆核心自己的 kernel-config.json。

合併文件（vex_export.kernel_multi_doc 的 MergedDoc）沒有 kernel.stable_git、inputs.cves_origin：
- K1「kept_not_proven_absent」那一句改讀每顆的文件，每顆一句、前面標 [版本]；
- 「Kernel CVE list」的來源改讀每顆的 inputs.cves_origin，各顆相同就寫一次，不同就逐顆列出。
「這是合併文件」只看型別（MergedDoc），檔案裡寫的欄位不算。只改文字，不改判定。
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import cra_report as cr  # noqa: E402

SCHEMA = "sca-center-kernel-config/1"


def doc(cves, origin=None, kept=None):
    d = {"schema": SCHEMA, "inputs": {"cves_origin": origin} if origin is not None else {},
         "results": [{"cve": c, "decision": "unknown", "files": []} for c in cves], "kernel": {}}
    if kept is not None:
        d["kernel"]["stable_git"] = {"kept_not_proven_absent": kept}
    return d


def merged(docs):
    vx = cr.vexmod()
    cves = sorted({x["cve"] for d in docs.values() if d for x in d["results"]})
    return vx.MergedDoc({"schema": SCHEMA, "status": "OK", "kernel": {"version": ", ".join(docs), "config_source": "merged"},
                         "component": {}, "results": [{"cve": c, "decision": "unknown"} for c in cves],
                         "inputs": {"kernels": list(docs)}, "docs": docs})


def test_kept_sentence_per_kernel_from_the_merged_doc():
    m = merged({"6.12.1-v8": doc(["CVE-2025-0001"], kept={"files": 2, "cves": 1}),
                "6.12.1-2712": doc(["CVE-2025-0002"], kept={"files": 0, "cves": 0}),
                "6.12.1-v7": doc(["CVE-2025-0003"], kept={"files": 5, "cves": 3})})
    t = cr.kernel_kept_text(m)
    assert t == ("[6.12.1-v7] " + cr.KEPT_NOT_PROVEN_ABSENT.format(n=5, m=3) + " [6.12.1-v8] "
                 + cr.KEPT_NOT_PROVEN_ABSENT.format(n=2, m=1))


def test_kept_sentence_empty_when_no_kernel_kept_anything():
    m = merged({"a": doc(["CVE-2025-0001"]), "b": None})
    assert cr.kernel_kept_text(m) == ""


def test_cve_list_source_same_for_all_kernels_is_written_once():
    m = merged({"a": doc(["CVE-2025-0001"], origin="KERNEL_CVES（明確給的清單）"),
                "b": doc(["CVE-2025-0002"], origin="KERNEL_CVES（另一個說明）")})
    cves, src = cr.kernel_cve_list_info(m)
    assert cves == {"CVE-2025-0001", "CVE-2025-0002"}
    assert src == "KERNEL_CVES explicit list, merged with the Grype and Dependency-Track kernel findings; 2 kernels"
    assert "scan/" not in src and "`" not in src          # 交付文件不帶內部檔案路徑


def test_cve_list_source_differs_per_kernel_is_listed_per_kernel():
    m = merged({"b": doc(["CVE-2025-0002"]), "a": doc(["CVE-2025-0001"], origin="kernel-cna-version（…）")})
    _, src = cr.kernel_cve_list_info(m)
    assert src == "per kernel: a: kernel CNA version comparison; b: Grype and Dependency-Track kernel findings; 2 kernels"
    assert "scan/" not in src and "`" not in src


def test_a_plain_dict_that_claims_to_be_merged_is_read_as_a_single_kernel_doc():
    fake = {"schema": SCHEMA, "inputs": {}, "results": [{"cve": "CVE-2025-0001"}], "merged": True,
            "kernel": {"config_source": "merged", "stable_git": {"kept_not_proven_absent": {"files": 1, "cves": 1}}},
            "docs": {"x": doc(["CVE-2025-0009"], origin="kernel-cna-version", kept={"files": 9, "cves": 9})}}
    assert cr.kernel_kept_text(fake) == cr.KEPT_NOT_PROVEN_ABSENT.format(n=1, m=1)
    assert cr.kernel_cve_list_info(fake) == ({"CVE-2025-0001"}, "Grype and Dependency-Track kernel findings; `scan/kernel-config.json`")


def test_single_kernel_doc_text_is_unchanged():
    d = doc(["CVE-2025-0001"], origin="KERNEL_CVES", kept={"files": 3, "cves": 2})
    assert cr.kernel_kept_text(d) == cr.KEPT_NOT_PROVEN_ABSENT.format(n=3, m=2)
    assert cr.kernel_cve_list_info(d)[1] == "KERNEL_CVES explicit list, merged with the Grype and Dependency-Track kernel findings; `scan/kernel-config.json`"
