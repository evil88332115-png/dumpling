"""韌體 Release（firmware-demo/<日期>）的 firmware-meta.json 產生器與檢查（docs/FIRMWARE-WATCH.md §3；說明見 docs/notes/c2-firmware-release.md）。

子命令（都只讀本機檔案、不連網、不執行任何下載檔）：
  check-tag <tag> [--allow-test-tag]
      tag 要 fullmatch firmware-demo/YYYY.MM.DD（同一天第二次起加 .2～.99），日期要是有效日期。
      --allow-test-tag：另外接受測試用的 firmware-demo/0000.00.00（PR 與手動觸發的端到端自我檢查用；真的 tag 不能用）。
  build <firmware.yml>... --ci-out <firmware-ci 的產出資料夾> --supplier-prep <供應商 SBOM 的 prep 資料夾> --out <空資料夾>
        --tag <tag> --commit <40 碼> --built-at <UTC> --workflow-run <網址> [--allow-test-tag] [--ci-summary <firmware-ci 的摘要.md>] [--sbom-check-log <firmware-sbom-check.sh 的 stdout>] --dt-result <success|failure|cancelled|skipped|空>
      產生要上傳的資料夾：fw-<slug>.cdx.json、fw-inventory-<slug>.json、firmware-meta.json（不放任何二進位檔）。
      任何一項不合規就失敗（退出碼 1，原因印在 stderr），不寫半套輸出。
  collect-check --meta <firmware-meta.json> --dir <資料夾> --tag <tag> [--collect <collect.py>]
      用路徑載入 pipeline/watch/collect.py（不改它），對 meta 跑 check_fw_meta 與 _fw_sample_fields，再逐一核對附件的檔名與 sha256。
  rematch-check --meta <firmware-meta.json> --rematch-out <firmware-rematch.sh 的 --out 資料夾>
      每個 bios 樣本的 rematch 結果：changed 是空的、狀態與 meta 一致、表的識別與 meta 一致；沒有多出或缺少的樣本。
  release-notes --meta <firmware-meta.json> --out <檔案>
      Release 說明文字（示範用、只有 JSON、哪些樣本進每日監控）。
"""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)  # Python 3.11 起 -I 含 -P，不會自動把腳本所在目錄放進 sys.path
from firmware_watch import clean_why, parse_watch  # noqa: E402

try:
    import yaml
except ImportError:  # 在 load_manifest 回報
    yaml = None

META_SCHEMA = "dumpling-firmware-meta/1"
INVENTORY_SCHEMA = "sca-center-fw-inventory/1"
META_NAME = "firmware-meta.json"
TAG_RE = re.compile(r"firmware-demo/([0-9]{4})\.([0-9]{2})\.([0-9]{2})(\.[2-9]|\.[1-9][0-9])?")
TEST_TAG = "firmware-demo/0000.00.00"     # 日期不是有效日期，所以真的 tag 一定不會和它相同
SLUG_RE = re.compile(r"[a-z0-9][a-z0-9.-]{0,62}")
RESERVED_SLUGS = frozenset({"summary"})    # firmware-rematch 的 rematch-summary.json 用掉的名字（rematch 會拒收）
SHA256_RE = re.compile(r"[0-9a-f]{64}")
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
BUILT_AT_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
RUN_RE = re.compile(r"https://[!-~]{1,300}")
KINDS = ("bios", "vbios", "sbom")
STATUSES = ("OK", "ATTENTION", "GAP")
DT_RESULTS = ("OK", "FAIL", "NOT_RUN")
DT_REASON = "DT 上傳沒有完成，Release 內容不受影響"       # 固定字串（C3 已確認格式）
MANIFEST_STATUSES = ("ok", "GAP")                       # firmware.yml 的 status：只有 ok 才算監控；GAP 列進 not_watched；其他值一律失敗
EXPECT_VALUES = ("OK", "MISMATCH", "MISSING", "ERROR", "NOT_RUN", "NONE")
EXPECT_ORDER = ("ERROR", "MISMATCH", "MISSING", "NOT_RUN")   # 多項時取最差的；全部 OK 才是 OK
MAX_FILE = 64 * 1024 * 1024
TABLE_FIELDS = {                     # meta 的 tables：表名 → (欄位, inventory 的來源區段, 區段內的路徑)
    "fw_advisory_rules": (("sha256", "rules_advisory", ("table", "sha256")), ("table_updated", "rules_advisory", ("table", "updated"))),
    "intel_microcode": (("source_commit", "advisory", ("source", "commit")), ("source_tag", "advisory", ("source", "tag")),
                        ("table_sha256", "advisory", ("source", "table_sha256"))),
    "nvidia_vbios": (("sha256", "vbios_advisory", ("source", "table_sha256")), ("mirror_commit", "vbios_advisory", ("source", "mirror_commit")),
                     ("reviewed_until", "vbios_advisory", ("source", "reviewed_until"))),
}


class MetaError(Exception):
    pass


# ---------------------------------------------------------------- tag

def check_tag(tag, allow_test=False):
    """tag 合規就回傳；不合丟 MetaError。"""
    if not isinstance(tag, str):
        raise MetaError("tag 不是字串")
    if allow_test and tag == TEST_TAG:
        return tag
    m = TAG_RE.fullmatch(tag)
    if not m:
        raise MetaError("tag 格式不符：要是 firmware-demo/YYYY.MM.DD（同一天第二次起加 .2～.99）")
    try:
        datetime.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except ValueError:
        raise MetaError("tag 的日期不是有效日期")
    return tag


# ---------------------------------------------------------------- 臨時 DT 的結果

def dt_block(job_result):
    """firmware-dt job 的結果（workflow 的 needs.<job>.result：success、failure、cancelled、skipped）→ meta 的 dt 欄位。
    success＝OK；failure、cancelled＝FAIL；skipped 或拿不到結果（空字串、不認得的值）＝NOT_RUN。
    只有兩種組合：OK 時 status OK、reason null；其他 status GAP、reason 固定字串。"""
    r = {"success": "OK", "failure": "FAIL", "cancelled": "FAIL"}.get(job_result if isinstance(job_result, str) else "", "NOT_RUN")
    if r == "OK":
        return {"status": "OK", "result": "OK", "reason": None}
    return {"status": "GAP", "result": r, "reason": DT_REASON}


def dt_problem(dt):
    """meta 的 dt 欄位是否合規 → 問題字串或 None。只接受 dt_block 產生的三種組合，其他一律不合規。"""
    if not isinstance(dt, dict) or set(dt) != {"status", "result", "reason"}:
        return "dt 必須是 {status, result, reason}"
    good = ({"status": "OK", "result": "OK", "reason": None},
            {"status": "GAP", "result": "FAIL", "reason": DT_REASON},
            {"status": "GAP", "result": "NOT_RUN", "reason": DT_REASON})
    return None if dt in good else "dt 的組合不合規（只能是 OK／OK／null，或 GAP＋FAIL／NOT_RUN＋固定的 reason）"


# ---------------------------------------------------------------- 讀檔

def sha256_of(data):
    return hashlib.sha256(data).hexdigest()


def read_regular(path, what):
    """讀一般檔案（不跟隨符號連結）→ bytes。"""
    try:
        st = os.lstat(path)
    except OSError:
        raise MetaError("%s 不存在：%s" % (what, os.path.basename(path)))
    if not stat.S_ISREG(st.st_mode):
        raise MetaError("%s 不是一般檔案：%s" % (what, os.path.basename(path)))
    if st.st_size > MAX_FILE:
        raise MetaError("%s 超過 %d 位元組：%s" % (what, MAX_FILE, os.path.basename(path)))
    with open(path, "rb") as fh:
        return fh.read()


def load_json_bytes(data, what):
    try:
        return json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise MetaError("%s 不是合法 JSON" % what)


def load_manifest(path):
    """firmware.yml → (slug, doc)。slug 是所在資料夾名稱。"""
    if yaml is None:
        raise MetaError("缺少 PyYAML")
    slug = os.path.basename(os.path.dirname(os.path.abspath(path)))
    try:
        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
    except (OSError, yaml.YAMLError, UnicodeDecodeError):
        raise MetaError("%s：firmware.yml 讀不了或不是合法 YAML" % slug)
    if not isinstance(doc, dict):
        raise MetaError("%s：firmware.yml 不是 mapping" % slug)
    if not SLUG_RE.fullmatch(slug) or slug in RESERVED_SLUGS:
        raise MetaError("slug 不合規則（要 fullmatch [a-z0-9][a-z0-9.-]{0,62}，且不能是 summary）：%s" % slug[:80])
    return slug, doc


# ---------------------------------------------------------------- 單一樣本

def table_identity(inv, slug):
    """inventory 的三個比對區段 → meta 的 tables（只讀識別欄位）。區段不是 OK 或欄位缺、型別不對就失敗。"""
    out = {}
    for tname, fields in TABLE_FIELDS.items():
        out[tname] = {}
        for fname, section, path in fields:
            sec = inv.get(section)
            if not isinstance(sec, dict) or sec.get("status") != "OK":
                raise MetaError("%s：inventory 的 %s 不是 OK（表讀不到或比對沒有完成），不能產生 tables" % (slug, section))
            v = sec
            for k in path:
                v = v.get(k) if isinstance(v, dict) else None
            if not isinstance(v, str) or not v.strip():
                raise MetaError("%s：inventory 的 %s.%s 缺少或不是字串" % (slug, section, ".".join(path)))
            out[tname][fname] = v
    return out


def image_sha256_of(inv):
    """inventory 裡只有一個 BIOS 映像時才填它的 sha256，其他情況是 null。"""
    bios = inv.get("bios")
    if isinstance(bios, list) and len(bios) == 1 and isinstance(bios[0], dict):
        s = bios[0].get("sha256")
        if isinstance(s, str) and SHA256_RE.fullmatch(s):
            return s
    return None


def expect_of(doc, log_path):
    """firmware.yml 與 firmware-expect.py 的 expect.log → OK|MISMATCH|MISSING|ERROR|NOT_RUN|NONE。NONE＝firmware.yml 沒寫 expected。"""
    if doc.get("expected") in (None, {}):
        return "NONE"
    try:
        text = read_regular(log_path, "expect.log").decode("utf-8", "replace")
    except MetaError:
        return "NOT_RUN"
    seen = set()
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3 and parts[0] == "FIRMWARE-EXPECT" and parts[1] in ("OK",) + EXPECT_ORDER:
            seen.add(parts[1])
    for v in EXPECT_ORDER:
        if v in seen:
            return v
    return "OK" if "OK" in seen else "NOT_RUN"


def ci_summary_status(summary_text, slug):
    """firmware-ci 的摘要.md 裡這個樣本的狀態（第二欄的第一個詞）；找不到回 None。"""
    for line in summary_text.splitlines():
        m = re.fullmatch(r"\| ([^|]+) \| ([A-Z_]+)\b[^|]*\|.*", line)
        if m and m.group(1).strip() == slug:
            return m.group(2)
    return None


def not_watched_why(slug, doc, mon, why):
    """不監控的原因（為什麼列進 not_watched）。宣告的 why 與 notes 推導出來的原因用同一個檢查（firmware_watch.clean_why）。"""
    status = doc.get("status")
    if mon is False:
        if status != "ok" and not why.startswith(str(status)):
            return clean_why("%s：%s" % (status, why))
        return why
    lines = [x.strip() for x in str(doc.get("notes") or "").splitlines() if x.strip()]
    first = lines[0] if lines else ""
    try:
        clean_why(first)                      # notes 的第一行本身要符合規則（加上「狀態：」前綴之前先檢查，免得前綴蓋掉空的內容）
        return clean_why(first if first.startswith(str(status)) else "%s：%s" % (status, first))
    except ValueError as e:
        raise MetaError("%s：status 是 %s，notes 的第一行不能當原因（%s）" % (slug, status, e))


def build(manifests, ci_out, supplier_prep, out, tag, commit, built_at, workflow_run, allow_test_tag=False, ci_summary=None, sbom_check_log=None, dt_result="", write=True):
    """→ meta（dict）。write=True 時另把附件與 firmware-meta.json 寫進 out（必須不存在或是空資料夾）。"""
    check_tag(tag, allow_test_tag)
    if not (isinstance(commit, str) and COMMIT_RE.fullmatch(commit)):
        raise MetaError("commit 要是 40 位小寫十六進位")
    if not (isinstance(built_at, str) and BUILT_AT_RE.fullmatch(built_at)):
        raise MetaError("built_at 要是 UTC 時間，例如 2026-11-20T03:00:00Z")
    if not (isinstance(workflow_run, str) and RUN_RE.fullmatch(workflow_run)):
        raise MetaError("workflow_run 要是 https 網址（沒有空白與控制字元）")
    if write and os.path.lexists(out) and (os.path.islink(out) or not os.path.isdir(out) or os.listdir(out)):
        raise MetaError("--out 必須不存在或是空資料夾")
    summary_text = None
    if ci_summary is not None:
        summary_text = read_regular(ci_summary, "firmware-ci 摘要").decode("utf-8", "replace")
    sbom_log = read_regular(sbom_check_log, "firmware-sbom-check 的輸出").decode("utf-8", "replace") if sbom_check_log else None
    samples, not_watched, files, seen = [], [], {}, set()
    tables = None
    tables_from = None
    for path in manifests:
        slug, doc = load_manifest(path)
        if slug in seen:
            raise MetaError("slug 重複：%s" % slug)
        seen.add(slug)
        kind, status = doc.get("kind"), doc.get("status")
        if not isinstance(kind, str) or kind not in KINDS:
            raise MetaError("%s：kind 必須是 %s" % (slug, "／".join(KINDS)))
        # 第二道防線（第一道是 firmware_fetch.validate）：status 只有 ok（監控）與 GAP（沒有檔案）兩種；
        # 其他值（大寫的 OK、清單、空值…）一律失敗，不放進 not_watched，免得打錯字的樣本悄悄變成「不監控」。
        if not isinstance(status, str) or status not in MANIFEST_STATUSES:
            raise MetaError("%s：firmware.yml 的 status 必須是 %s（原樣小寫），拿到的值不合規" % (slug, "／".join(MANIFEST_STATUSES)))
        try:
            mon, why = parse_watch(doc)
        except ValueError as e:
            raise MetaError("%s：%s" % (slug, e))
        if mon is True and status != "ok":
            raise MetaError("%s：watch.monitored 是 true，但 status 是 %s（沒有檔案可監控）：矛盾的宣告" % (slug, status))
        # 不監控一律由 firmware.yml 明確宣告（watch.monitored: false）；不從輸出推測。status 不是 ok（沒有檔案）也列進 not_watched。
        if mon is False or status != "ok":
            not_watched.append({"slug": slug, "why": not_watched_why(slug, doc, mon, why)})
            continue
        if kind == "vbios":
            raise MetaError("%s：vbios 樣本沒有每日監控的流程，firmware.yml 必須宣告 watch: {monitored: false, why: …}" % slug)
        fv = doc.get("firmware_version")
        if not isinstance(fv, str) or not fv.strip():
            raise MetaError("%s：firmware.yml 的 firmware_version 必須是非空字串（YAML 數字要加引號）" % slug)
        sbom_name = "fw-%s.cdx.json" % slug
        if kind == "bios":
            d = os.path.join(ci_out, slug)
            sbom_bytes = read_regular(os.path.join(d, "fw.cdx.json"), "%s 的 fw.cdx.json（firmware-ci 的產出）" % slug)
            inv_bytes = read_regular(os.path.join(d, "fw-inventory.json"), "%s 的 fw-inventory.json（firmware-ci 的產出）" % slug)
            inv = load_json_bytes(inv_bytes, "%s 的 fw-inventory.json" % slug)
            if not isinstance(inv, dict) or inv.get("schema") != INVENTORY_SCHEMA:
                raise MetaError("%s：fw-inventory.json 的 schema 不是 %s" % (slug, INVENTORY_SCHEMA))
            st = inv.get("status")
            if st not in STATUSES:
                raise MetaError("%s：inventory 的 status 不是 %s" % (slug, "／".join(STATUSES)))
            if summary_text is not None:
                cs = ci_summary_status(summary_text, slug)
                if cs != st:
                    raise MetaError("%s：firmware-ci 摘要的狀態（%s）與 inventory 的 status（%s）不一致" % (slug, cs, st))
            ident = table_identity(inv, slug)
            if tables is None:
                tables, tables_from = ident, slug
            elif ident != tables:     # 同一次建置用的是同一份表；識別不同＝資料有問題，不挑一份
                raise MetaError("%s：三張表的識別與 %s 不一致（同一次建置的樣本必須用同一份表）" % (slug, tables_from))
            inv_name = "fw-inventory-%s.json" % slug
            files[inv_name] = inv_bytes
            entry = {"slug": slug, "kind": "bios", "firmware_version": fv, "image_sha256": image_sha256_of(inv), "sbom": sbom_name,
                     "sbom_sha256": sha256_of(sbom_bytes), "inventory": inv_name, "inventory_sha256": sha256_of(inv_bytes),
                     "status": st, "expect": expect_of(doc, os.path.join(d, "expect.log"))}
        else:
            sbom_bytes = read_regular(os.path.join(supplier_prep, slug, "sbom.cdx.json"), "%s 的正規化上傳副本（prep 的 sbom.cdx.json）" % slug)
            entry = {"slug": slug, "kind": "sbom", "firmware_version": fv, "image_sha256": None, "sbom": sbom_name,
                     "sbom_sha256": sha256_of(sbom_bytes), "normalized": True, "inventory": None, "inventory_sha256": None,
                     "status": sbom_check_status(sbom_log, doc, slug), "expect": "NONE" if doc.get("expected") in (None, {}) else "NOT_RUN"}
        obj = load_json_bytes(sbom_bytes, "%s 的 SBOM" % slug)
        if not isinstance(obj, dict) or obj.get("bomFormat") != "CycloneDX":
            raise MetaError("%s：SBOM 不是 CycloneDX（bomFormat 不符）" % slug)
        files[sbom_name] = sbom_bytes
        samples.append(entry)
    if tables is None:
        raise MetaError("沒有任何 bios 樣本：沒有表的識別可寫（每日重跑也沒有東西可跑）")
    samples.sort(key=lambda x: x["slug"])
    not_watched.sort(key=lambda x: x["slug"])
    meta = {"schema": META_SCHEMA, "tag": tag, "commit": commit, "built_at": built_at, "workflow_run": workflow_run,
            "samples": samples, "not_watched": not_watched, "tables": tables, "dt": dt_block(dt_result)}
    problems = validate_meta(meta)
    if problems:
        raise MetaError("產生的 meta 自己檢查不過：" + "；".join(problems[:5]))
    if write:
        os.makedirs(out, exist_ok=True)
        try:
            for name, data in sorted(files.items()):
                with open(os.path.join(out, name), "wb") as fh:
                    fh.write(data)
            with open(os.path.join(out, META_NAME), "w", encoding="utf-8") as fh:
                fh.write(dump_meta(meta))
        except BaseException:
            shutil.rmtree(out, ignore_errors=True)
            raise
    return meta


def sbom_check_status(log_text, doc, slug):
    """firmware-sbom-check.sh 的狀態行（FIRMWARE-SBOM<TAB>狀態<TAB>檔名<TAB>說明）裡，這個樣本的 role: sbom 檔案的狀態。
    找不到或是 FAIL 就失敗（FAIL 的供應商 SBOM 不能進 Release）。"""
    names = [f.get("name") for f in (doc.get("files") or []) if isinstance(f, dict) and f.get("role") == "sbom"]
    found = set()
    for line in (log_text or "").splitlines():
        parts = line.split("\t")
        if len(parts) >= 3 and parts[0] == "FIRMWARE-SBOM" and re.sub(r"\\(.)", r"\1", parts[2]) in names:    # 檔名經 md_safe 跳脫（\_）
            found.add(parts[1])
    if not found:
        raise MetaError("%s：firmware-sbom-check 的狀態行裡找不到這個供應商 SBOM（--sbom-check-log）" % slug)
    for v in ("FAIL", "GAP", "ATTENTION", "OK"):      # 多個檔案取最差的
        if v in found:
            if v == "FAIL" or v not in STATUSES:
                raise MetaError("%s：供應商 SBOM 的品質檢查狀態是 %s，不放進 Release" % (slug, v))
            return v
    raise MetaError("%s：firmware-sbom-check 的狀態不認得" % slug)


def dump_meta(meta):
    return json.dumps(meta, ensure_ascii=False, indent=2) + "\n"


# ---------------------------------------------------------------- 自己的結構檢查（collect 的規則另有 collect-check）

def validate_meta(meta):
    """產生器自己的檢查 → 問題清單。"""
    p = []
    if meta.get("schema") != META_SCHEMA:
        p.append("schema")
    for x in meta.get("samples") or []:
        s = x.get("slug")
        if not (isinstance(s, str) and SLUG_RE.fullmatch(s)):
            p.append("slug 不合規則")
            continue
        if x.get("kind") not in ("bios", "sbom"):
            p.append("%s：kind" % s)
        if x.get("status") not in STATUSES:
            p.append("%s：status" % s)
        if x.get("expect") not in EXPECT_VALUES:
            p.append("%s：expect" % s)
        if x.get("kind") == "sbom" and (x.get("inventory") is not None or x.get("image_sha256") is not None or x.get("normalized") is not True):
            p.append("%s：sbom 樣本的欄位" % s)
    for x in meta.get("not_watched") or []:
        s, w = x.get("slug"), x.get("why")
        if not (isinstance(s, str) and SLUG_RE.fullmatch(s)):
            p.append("not_watched 的 slug 不合規則")
        try:
            clean_why(w)
        except ValueError as e:
            p.append("not_watched 的 %s：%s" % (s, e))
    dp = dt_problem(meta.get("dt"))
    if dp:
        p.append(dp)
    return p


# ---------------------------------------------------------------- collect-check

def load_collect(path):
    """用檔案路徑載入 pipeline/watch/collect.py（不改它、不經過 sys.path）。"""
    spec = importlib.util.spec_from_file_location("dumpling_watch_collect", path)
    if spec is None or spec.loader is None:
        raise MetaError("載入不了 collect.py：%s" % os.path.basename(path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["dumpling_watch_collect"] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception as e:
        raise MetaError("載入 collect.py 失敗（%s）" % type(e).__name__)
    for fn in ("check_fw_meta", "_fw_sample_fields", "fw_watch_version", "_sbom_ok", "_json_ok"):
        if not hasattr(mod, fn):
            raise MetaError("collect.py 沒有 %s（介面變了，這個檢查要跟著更新）" % fn)
    return mod


def collect_check(meta_path, directory, tag, collect_path):
    """→ 問題清單（空＝collect 會整份收下）。"""
    col = load_collect(collect_path)
    probs = []
    raw = read_regular(meta_path, META_NAME)
    if len(raw) > col.FW_META_MAX:
        probs.append("%s 超過 collect 的上限 %d 位元組" % (META_NAME, col.FW_META_MAX))
    meta = load_json_bytes(raw, META_NAME)
    err = col.check_fw_meta(meta, tag)
    if err:
        return ["check_fw_meta：%s" % err]
    listed = {}
    keys = set()
    for i, x in enumerate(meta["samples"]):
        err = col._fw_sample_fields(x)
        label = x.get("slug") if isinstance(x, dict) else "#%d" % i
        if err:
            probs.append("%s：_fw_sample_fields：%s" % (label, err))
            continue
        wv, why = col.fw_watch_version(x["slug"], x.get("firmware_version"), x.get("image_sha256"))
        if wv is None or why:
            probs.append("%s：collect 的監控鍵有問題（%s）" % (label, why))
        elif wv in keys:
            probs.append("%s：監控鍵重複（%s）" % (label, wv))
        keys.add(wv)
        for name_key, sha_key, ok in (("sbom", "sbom_sha256", col._sbom_ok), ("inventory", "inventory_sha256", col._json_ok)):
            name = x.get(name_key)
            if name is None:
                continue
            if name in listed:
                probs.append("%s：附件名重複（%s）" % (label, name))
            listed[name] = (x[sha_key], ok)
    # 附件：資料夾裡的檔名與 sha256 要和 meta 完全一致；沒列在 meta 的檔案、meta 列了卻沒有的檔案都算問題
    try:
        present = sorted(os.listdir(directory))
    except OSError:
        return probs + ["附件資料夾讀不了"]
    for name in present:
        if name != META_NAME and name not in listed:
            probs.append("資料夾裡有 meta 沒列的檔案：%s" % name[:80])
    for name, (sha, ok) in sorted(listed.items()):
        p = os.path.join(directory, name)
        try:
            data = read_regular(p, "附件")
        except MetaError as e:
            probs.append("%s：%s" % (name, e))
            continue
        if sha256_of(data) != sha:
            probs.append("%s：sha256 與 meta 不符" % name)
        err = ok(p)
        if err:
            probs.append("%s：collect 的內容檢查：%s" % (name, err))
    return probs


# ---------------------------------------------------------------- rematch-check

def rematch_check(meta_path, rematch_out):
    """每日重跑的自我檢查 → 問題清單（空＝所有 bios 樣本 changed 是空的、狀態一致、表的識別一致）。"""
    probs = []
    meta = load_json_bytes(read_regular(meta_path, META_NAME), META_NAME)
    sp = os.path.join(rematch_out, "rematch-summary.json")
    summary = load_json_bytes(read_regular(sp, "rematch-summary.json"), "rematch-summary.json")
    if summary.get("meta_status") != "OK":
        return ["rematch 不接受 meta：%s" % "；".join(str(r)[:200] for r in (summary.get("reasons") or ["原因不明"]))]
    if summary.get("rejected"):
        probs.append("rematch 丟掉了 meta 的條目：%s" % json.dumps(summary["rejected"], ensure_ascii=False)[:200])
    if summary.get("release_tag") != meta.get("tag"):
        probs.append("rematch 的 release_tag 與 meta 不一致")
    by_slug = {x.get("slug"): x for x in summary.get("samples") or [] if isinstance(x, dict)}
    want = {x["slug"]: x for x in meta["samples"] if x.get("kind") == "bios"}
    for slug in sorted(set(by_slug) - set(want)):
        probs.append("%s：rematch 有輸出，但 meta 沒有這個 bios 樣本" % slug)
    for slug, x in sorted(want.items()):
        got = by_slug.get(slug)
        if got is None:
            probs.append("%s：rematch 沒有這個樣本的輸出（會被當成 NOT_RUN）" % slug)
            continue
        if got.get("status") != x.get("status"):
            probs.append("%s：rematch 的狀態（%s）與 firmware-ci／meta 的狀態（%s）不一致" % (slug, got.get("status"), x.get("status")))
        try:
            doc = load_json_bytes(read_regular(os.path.join(rematch_out, "rematch-%s.json" % slug), "rematch 輸出"), "rematch-%s.json" % slug)
        except MetaError as e:
            probs.append("%s：%s" % (slug, e))
            continue
        if doc.get("changed") != []:
            n = len(doc["changed"]) if isinstance(doc.get("changed"), list) else "?"
            probs.append("%s：changed 不是空的（%s 項；同一份表、同一份 inventory 重跑結果必須相同）" % (slug, n))
        if doc.get("inventory_sha256") != x.get("inventory_sha256"):
            probs.append("%s：rematch 用的 inventory 與 meta 的 inventory_sha256 不一致" % slug)
        for tname, want_t in (meta.get("tables") or {}).items():
            have = (doc.get("tables") or {}).get(tname) or {}
            if have.get("status") != "OK":
                probs.append("%s：表 %s 的狀態是 %s" % (slug, tname, have.get("status")))
            if {k: have.get(k) for k in want_t} != want_t:
                probs.append("%s：表 %s 的識別與 meta 不一致" % (slug, tname))
    return probs


# ---------------------------------------------------------------- Release 說明

def dt_text(dt):
    if not isinstance(dt, dict) or dt_problem(dt):
        return "沒有記錄"
    if dt["result"] == "OK":
        return "OK（上傳與驗證完成）"
    return "GAP（結果 %s，上傳沒有完成；附件由解析與離線公告比對產生，與 DT 的結果無關）" % dt["result"]


def release_notes(meta):
    watched = [x for x in meta["samples"]]
    lines = [
        "# %s" % meta["tag"],
        "",
        "示範用的公開韌體樣本分析結果，不是產品，沒有支援期限。樣本是廠商公開下載的測試資料，映像只在建置時從官方網址下載一次、核對 sha256 後解析。",
        "",
        "- 附件只有 JSON：每個樣本的 CycloneDX SBOM（`fw-<slug>.cdx.json`）、BIOS 樣本的解析結果（`fw-inventory-<slug>.json`）與 `firmware-meta.json`。沒有任何韌體映像或其他二進位檔。",
        "- 狀態是解析結果與離線公告比對的狀態。比對結果是候選或建議，漏洞判定仍是 NOT_ASSESSED；NOT_ASSESSED 是資料庫沒有資料，以廠商公告為準。",
        "- 供應商 SBOM（kind sbom）附的是正規化後的上傳副本（`normalized: true`），沒有 inventory。",
        "- 建置的 commit 與工作流程記錄在 `firmware-meta.json`。",
        "- 臨時 Dependency-Track（DT）上傳：%s。" % dt_text(meta.get("dt")),
        "",
        "## 進每日監控的樣本（%d 份）" % len(watched),
        "",
    ]
    for x in watched:
        lines.append("- `%s`（%s，%s，狀態 %s）" % (x["slug"], x["kind"], x["firmware_version"], x["status"]))
    lines += ["", "## 不進每日監控的樣本（%d 份）" % len(meta["not_watched"]), ""]
    for x in meta["not_watched"]:
        lines.append("- `%s`：%s" % (x["slug"], x["why"]))
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------- CLI

def main(argv=None):
    ap = argparse.ArgumentParser(allow_abbrev=False, description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check-tag", allow_abbrev=False)
    c.add_argument("tag")
    c.add_argument("--allow-test-tag", action="store_true")
    b = sub.add_parser("build", allow_abbrev=False)
    b.add_argument("manifests", nargs="+")
    b.add_argument("--ci-out", required=True)
    b.add_argument("--supplier-prep", required=True)
    b.add_argument("--out", required=True)
    b.add_argument("--tag", required=True)
    b.add_argument("--commit", required=True)
    b.add_argument("--built-at", required=True)
    b.add_argument("--workflow-run", required=True)
    b.add_argument("--allow-test-tag", action="store_true")
    b.add_argument("--ci-summary")
    b.add_argument("--sbom-check-log")
    b.add_argument("--dt-result", required=True, help="firmware-dt job 的 needs 結果：success、failure、cancelled、skipped（空字串＝拿不到結果）")
    k = sub.add_parser("collect-check", allow_abbrev=False)
    k.add_argument("--meta", required=True)
    k.add_argument("--dir", required=True)
    k.add_argument("--tag", required=True)
    k.add_argument("--collect", default=os.path.join(HERE, "..", "watch", "collect.py"))
    r = sub.add_parser("rematch-check", allow_abbrev=False)
    r.add_argument("--meta", required=True)
    r.add_argument("--rematch-out", required=True)
    n = sub.add_parser("release-notes", allow_abbrev=False)
    n.add_argument("--meta", required=True)
    n.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    try:
        if a.cmd == "check-tag":
            check_tag(a.tag, a.allow_test_tag)
            print("FIRMWARE-META\tOK\t-\ttag 合規：%s" % a.tag)
        elif a.cmd == "build":
            meta = build(a.manifests, a.ci_out, a.supplier_prep, a.out, a.tag, a.commit, a.built_at, a.workflow_run,
                         a.allow_test_tag, a.ci_summary, a.sbom_check_log, a.dt_result)
            print("FIRMWARE-META\tOK\t-\t%d 個樣本、%d 個不監控、tag %s" % (len(meta["samples"]), len(meta["not_watched"]), meta["tag"]))
        elif a.cmd in ("collect-check", "rematch-check"):
            if a.cmd == "collect-check":
                probs = collect_check(a.meta, a.dir, a.tag, os.path.abspath(a.collect))
            else:
                probs = rematch_check(a.meta, a.rematch_out)
            label = "FIRMWARE-META-" + a.cmd.split("-")[0].upper()
            for x in probs:
                print("%s\tFAIL\t-\t%s" % (label, x.replace("\n", " ").replace("\t", " ")))
            if probs:
                return 1
            print("%s\tOK\t-\t%s" % (label, "meta 與附件符合 collect 的檢查" if a.cmd == "collect-check"
                                      else "每個 bios 樣本 changed 是空的，狀態與表的識別和 meta 一致"))
        elif a.cmd == "release-notes":
            meta = load_json_bytes(read_regular(a.meta, META_NAME), META_NAME)
            with open(a.out, "w", encoding="utf-8") as fh:
                fh.write(release_notes(meta))
    except MetaError as e:
        print("FIRMWARE-META\tFAIL\t-\t%s" % str(e).replace("\n", " ").replace("\t", " "))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
