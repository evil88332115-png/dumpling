"""sca-scan --image <本機映像 ID>：不 pull，以映像 ID 當版本（docker import 的映像沒有 registry digest）。docker 用假的。"""
import json
import os
import subprocess

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
IID = "sha256:" + "ab" * 32

FAKE = """#!/bin/sh
echo "$*" >> "$DOCKER_LOG"
case "$1 $2" in
  "image inspect")
    for a in "$@"; do last=$a; done
    [ "$last" = "$KNOWN" ] || exit 1
    case "$*" in *RepoDigests*) ;; *'{{.Id}}'*) echo "$KNOWN";; *Env*) ;; esac; exit 0;;
esac
case "$1" in
  pull) exit 7;;
  save) shift; [ "$1" = -o ] && : > "$2"; exit 0;;
esac
exit 0
"""


def scan(tmp_path, src, known=IID, extra=()):
    fake = tmp_path / "bin"
    fake.mkdir()
    (fake / "docker").write_text(FAKE)
    (fake / "docker").chmod(0o755)
    log = tmp_path / "docker.log"
    env = {**os.environ, "PATH": f"{fake}:{os.environ['PATH']}", "DOCKER_LOG": str(log), "KNOWN": known,
           "PILOT_ENV": str(tmp_path / "none.env"), "HOME": str(tmp_path / "home")}
    out = tmp_path / "out"
    subprocess.run(["bash", os.path.join(ROOT, "tools/pilot/sca-scan"), "--image", src, "--name", "t", "--out", str(out),
                    "--no-upload", *extra], env=env, capture_output=True, timeout=300)
    rows = [l.split("\t") for l in (out / "status.tsv").read_text(encoding="utf-8").splitlines()[1:]]
    meta = json.loads((out / "meta.json").read_text(encoding="utf-8"))
    return {r[0]: (r[1], r[2]) for r in rows}, meta, log.read_text() if log.exists() else ""


def test_local_image_id_no_pull(tmp_path):
    st, meta, log = scan(tmp_path, IID)
    assert st["A-source"][0] == "OK" and "本機映像" in st["A-source"][1]
    assert not any(l.startswith("pull") for l in log.splitlines()) and "save -o" in log
    assert meta["version"] == IID and meta["image_id"] == IID


def test_local_image_missing(tmp_path):
    st, _, log = scan(tmp_path, IID, known="sha256:" + "cd" * 32)
    assert st["A-source"][0] == "FAIL" and "本機沒有映像" in st["A-source"][1]
    assert not any(l.startswith("pull") for l in log.splitlines())


def test_local_image_with_version(tmp_path):
    """--version：DT／meta 的版本用指定的字串，映像 ID 另記 content_version。"""
    st, meta, _ = scan(tmp_path, IID, extra=("--version", "V39.2.0.2_a (rootfs_no_gui)"))
    assert st["A-source"][0] == "OK"
    assert meta["version"] == "V39.2.0.2_a (rootfs_no_gui)" and meta["content_version"] == IID and meta["image_id"] == IID
    assert meta["version_from"] == "--version"
