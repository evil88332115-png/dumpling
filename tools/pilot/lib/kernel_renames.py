#!/usr/bin/env python3
"""kernel_renames.py：核心檔案改名對照表（tools/mirror/kernel-renames.sh 的輸出）的讀取與查詢（kernel_config.py 的 --rename-map）。

用途：Linux 核心 CNA 紀錄的 programFiles 是「現在主線」的路徑；舊核心的同一個檔案常常是另一個名字（fs/ksmbd/ → fs/smb/server/ …）。
對照表是主線 git 的整個檔案改名（git log -M --diff-filter=R）：{new, old, commit, similarity}，新的在前。
resolve()：從 CVE 列的路徑往回走（最新的改名先、再從舊名往更舊的改名），直到某個路徑存在於這個核心（由呼叫端的 exists 判斷）。
只在「確定」的時候回答：
  - 同一個路徑在同一個時點有多個可能的舊名 → ambiguous（不用）
  - 走不到這個核心有的檔案，或超過 MAX_CHAIN 步 → none（不用）
  - 檔案拆成多個（kernel/futex.c → kernel/futex/*.c 只有其中一個被 git 認成改名）：其他檔案不在表裡 → none
對照表不可用（缺、讀不出、格式不對、過期、不涵蓋這個核心）時 ok 是 False、reason 寫原因；呼叫端必須報 GAP，不可當作「沒有改名」。
不執行任何東西，只讀 JSON。"""
import datetime
import json
import os
import posixpath
import re

MAX_CHAIN = 8                     # 一條改名鏈最多幾步
MAX_BYTES = 200 << 20             # 對照表檔案大小上限
HASH_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


def _norm(p):
    """正規化的樹內相對路徑；不是就 None。"""
    if not isinstance(p, str) or not p or len(p) > 400 or p.startswith("/") or "\0" in p:
        return None
    n = posixpath.normpath(p)
    return None if n.startswith("..") or n != p else n


def base_tuple(v):
    m = re.match(r"^(\d+)\.(\d+)", str(v or ""))
    return (int(m.group(1)), int(m.group(2))) if m else None


class RenameMap:
    def __init__(self, path, max_age, kernel_mm=None, now=None, max_age_error=None):
        """kernel_mm：這個核心的 (主, 次) 或 None（不知道版本時不能確認對照表涵蓋它 → 不可用）。"""
        self.by_new = {}          # 新路徑 → [(順序, old, commit, similarity)]（順序小＝新）
        self.state = {"source": os.path.basename(os.path.normpath(path)) if path else None, "ok": False, "reason": None, "head_commit": None,
                      "head_date": None, "generated_utc": None, "age_days": None, "max_age_days": max_age, "base_version": None, "renames": 0}
        self.state["reason"] = max_age_error or self._open(path, max_age, kernel_mm, now)
        self.state["ok"] = self.state["reason"] is None
        self.stats = {"files_resolved": 0, "ambiguous": 0, "not_resolved": 0}

    def _open(self, path, max_age, kernel_mm, now):
        try:
            if os.path.islink(path) or not os.path.isfile(path):
                return "改名對照表不是一般檔案或不存在"
            if os.path.getsize(path) > MAX_BYTES:
                return "改名對照表太大"
            with open(path, encoding="utf-8") as f:
                d = json.load(f)
        except (OSError, ValueError, RecursionError, UnicodeDecodeError) as e:
            return f"改名對照表無法讀取（{type(e).__name__}）"
        if not isinstance(d, dict) or d.get("schema") != "kernel-renames/1" or not isinstance(d.get("source"), dict) \
                or not isinstance(d.get("renames"), list):
            return "改名對照表格式不對（schema 不是 kernel-renames/1，或沒有 source／renames）"
        s = d["source"]
        st = self.state
        st.update(head_commit=s.get("head_commit"), head_date=s.get("head_date"), generated_utc=s.get("generated_utc"),
                  base_version=s.get("base_version"))
        if not HASH_RE.match(str(s.get("head_commit", ""))):
            return "改名對照表的 source.head_commit 不是 git 的雜湊"
        try:
            gen = datetime.datetime.fromisoformat(str(s["generated_utc"]).replace("Z", "+00:00"))
        except (KeyError, ValueError):
            return "改名對照表沒有可解析的 source.generated_utc（無法判斷新舊）"
        if gen.tzinfo is None:
            return f"改名對照表的 source.generated_utc 沒有時區（{s['generated_utc']}），無法判斷新舊"
        age = ((now or datetime.datetime.now(datetime.timezone.utc)) - gen).total_seconds() / 86400
        st["age_days"] = round(age, 1)
        if age < -1:
            return f"改名對照表的產生時間在未來（{s['generated_utc']}，比現在晚 {-age:.1f} 天），無法判斷新舊"
        if age > max_age:
            return f"改名對照表過期：產生後 {age:.1f} 天 > {max_age:g} 天（generated_utc={s['generated_utc']}）"
        if d.get("count") != len(d["renames"]) or not d["renames"]:
            return "改名對照表的筆數與 count 不符或是空的"
        base = base_tuple(s.get("base_version"))
        if base is None:
            return "改名對照表沒有 source.base_version"
        if kernel_mm is None:
            return "不知道核心的主次版本，無法確認改名對照表涵蓋它"
        if kernel_mm < base:
            return f"核心 {kernel_mm[0]}.{kernel_mm[1]} 比改名對照表的起點 {s['base_version']} 舊，表不涵蓋它的改名"
        n = 0
        for i, e in enumerate(d["renames"]):
            if not isinstance(e, dict):
                return f"改名對照表第 {i} 筆不是物件"
            new, old = _norm(e.get("new")), _norm(e.get("old"))
            c, sim = e.get("commit"), e.get("similarity")
            if new is None or old is None or new == old or not HASH_RE.match(str(c or "")) or not isinstance(sim, int) or isinstance(sim, bool):
                return f"改名對照表第 {i} 筆格式不對"
            self.by_new.setdefault(new, []).append((i, old, c, sim))
            n += 1
        st["renames"] = n
        return None

    def resolve(self, path, exists, quiet=False):
        """→ (結果, chain)。結果："found"（chain 是 [(舊, 新, commit, 相似度)…]，舊的在前，最後一個舊名是這個核心有的檔案）、
        "ambiguous"、"none"。exists(p)：這個核心有這個檔案。"""
        stats = self.stats if not quiet else {"files_resolved": 0, "ambiguous": 0, "not_resolved": 0}
        cur, pos, chain = path, -1, []
        for _ in range(MAX_CHAIN):
            cand = [e for e in self.by_new.get(cur, ()) if e[0] > pos]
            if not cand:
                stats["not_resolved"] += 1
                return "none", []
            if len({e[1] for e in cand}) > 1:          # 不同的舊名才是不確定；同一個舊名（來自不同 commit）視為一致，取最新的那一筆
                stats["ambiguous"] += 1
                return "ambiguous", []
            i, old, commit, sim = min(cand)

            chain.insert(0, (old, cur, commit, sim))
            if exists(old):
                stats["files_resolved"] += 1
                return "found", chain
            cur, pos = old, i
        stats["not_resolved"] += 1
        return "none", []


def chain_text(chain):
    return "; ".join(f"{o} -> {n} (commit {c[:12]}, similarity {s}%)" for o, n, c, s in chain)
