import gzip
import io
import json
import sys
import tarfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import oscopyright as oc  # noqa: E402


def layer(entries, gz=False):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for name, v in entries:
            ti = tarfile.TarInfo(name)
            if isinstance(v, bytes):
                ti.size = len(v)
                t.addfile(ti, io.BytesIO(v))
            elif v[0] == "dir":
                ti.type = tarfile.DIRTYPE
                t.addfile(ti)
            else:
                ti.type, ti.linkname = tarfile.SYMTYPE, v[1]
                t.addfile(ti)
    data = buf.getvalue()
    return gzip.compress(data) if gz else data


def image(tmp, layers_):
    p = tmp / "img.tar"
    names = [f"blobs/sha256/{i:064d}" for i in range(len(layers_))]
    with tarfile.open(p, "w") as t:
        for n, data in [("manifest.json", json.dumps([{"Layers": names}]).encode())] + list(zip(names, layers_)):
            ti = tarfile.TarInfo(n)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
    return p


DEP5 = b"Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\nFiles: *\nCopyright: 2020 Jane Doe\nLicense: MIT\n"


def test_extract_layers_whiteouts_symlinks(tmp_path):
    l1 = layer([("usr/share/doc/", ("dir",)), ("usr/share/doc/libfoo1/copyright", DEP5), ("usr/share/doc/libfoo-dev", ("sym", "libfoo1")),
                ("usr/share/doc/gone/copyright", b"x"), ("usr/share/doc/abs", ("sym", "/usr/share/doc/libfoo1")),
                ("usr/share/doc/cl/copyright", ("sym", "../../common-licenses/GPL-2")), ("usr/share/doc/old/copyright", b"old"),
                ("usr/share/doc/Bad_Name/copyright", b"x"), ("usr/share/doc/libfoo1/changelog.gz", b"c"),
                ("../../etc/evil/usr/share/doc/x/copyright", b"x")])
    l2 = layer([("usr/share/doc/.wh.gone", b""), ("usr/share/doc/old/copyright", b"new"), ("usr/share/doc/big/copyright", b"y" * (oc.MAX_FILE + 1)),
                ("usr/share/doc/nested/.wh..wh..opq", b"")], gz=True)
    st, d = oc.extract(str(image(tmp_path, [l1, l2])), str(tmp_path / "out.tar"), str(tmp_path / "idx.json"))
    idx = json.loads((tmp_path / "idx.json").read_text())
    assert st == "OK"
    assert sorted(idx["packages"]) == ["abs", "libfoo-dev", "libfoo1", "old"]          # gone 被刪、big 太大、cl 連到外面、Bad_Name 不合法
    assert idx["packages"]["libfoo-dev"]["path"] == "/usr/share/doc/libfoo1/copyright" == idx["packages"]["abs"]["path"]
    assert idx["unresolved_symlinks"] == ["cl"] and idx["bad_names"] == ["Bad_Name"] and idx["too_large"] == ["big"]
    with tarfile.open(tmp_path / "out.tar") as t:
        got = {m.name: t.extractfile(m).read() for m in t.getmembers()}
    assert got["old/debian-copyright.txt"] == b"new" and got["libfoo-dev/debian-copyright.txt"] == DEP5
    assert set(got) == {f"{p}/debian-copyright.txt" for p in idx["packages"]}


def test_extract_not_debian(tmp_path):
    st, _ = oc.extract(str(image(tmp_path, [layer([("etc/os-release", b"ID=alpine\n")])])), str(tmp_path / "o.tar"), str(tmp_path / "i.json"))
    assert st == "NOT_RUN"


def test_extract_bad_image(tmp_path):
    p = tmp_path / "x.tar"
    with tarfile.open(p, "w"):
        pass
    assert oc.main(["extract", str(p), str(tmp_path / "o.tar"), str(tmp_path / "i.json")]) == 1


def test_evidence(tmp_path, capsys):
    (tmp_path / "idx.json").write_text(json.dumps({"packages": {"libfoo1": {"path": "/usr/share/doc/libfoo1/copyright"},
                                                                "libbar": {"path": "/usr/share/doc/libbar/copyright"}}}))
    res = {"files": [{"type": "file", "path": "os-copyright.tar-extract/libfoo1/debian-copyright.txt", "detected_license_expression": "mit",
                      "detected_license_expression_spdx": "MIT", "copyrights": [{"copyright": "Copyright 2020 Jane Doe"}, {"copyright": " "}],
                      "holders": [{"holder": "Jane Doe"}]},
                     {"type": "directory", "path": "os-copyright.tar-extract/libfoo1"}]}
    (tmp_path / "r.json").write_text(json.dumps(res))
    scio = {"packages": [{"type": "deb", "name": "libfoo1", "purl": "pkg:deb/ubuntu/libfoo1@1?arch=arm64"},
                         {"type": "deb", "name": "libfoo1", "purl": "pkg:deb/ubuntu/libfoo1@1?arch=armhf"},
                         {"type": "deb", "name": "libbar", "purl": "pkg:deb/ubuntu/libbar@2"},
                         {"type": "deb", "name": "nodoc", "purl": "pkg:deb/ubuntu/nodoc@3"},
                         {"type": "pypi", "name": "x", "purl": "pkg:pypi/x@1"}]}
    (tmp_path / "s.json").write_text(json.dumps(scio))
    oc.main(["evidence", str(tmp_path / "r.json"), str(tmp_path / "idx.json"), str(tmp_path / "s.json"), str(tmp_path / "e.json")])
    st, d = capsys.readouterr().out.strip().split("\t")
    ev = json.loads((tmp_path / "e.json").read_text())
    assert st == "GAP" and "沒有版權檔 1（nodoc）" in d and "沒有掃描結果 1" in d
    e = ev["packages"]["pkg:deb/ubuntu/libfoo1@1?arch=armhf"]
    assert e == ev["packages"]["pkg:deb/ubuntu/libfoo1@1?arch=arm64"] and e["copyrights"] == ["Copyright 2020 Jane Doe"]
    assert e["declared_license_expression"] == "mit" and e["key_files"][0]["path"] == "/usr/share/doc/libfoo1/copyright"
    assert ev["missing"] == ["nodoc"] and ev["unscanned"] == ["libbar"]
    import pkgscan
    assert pkgscan.copyright_class(e, None, "libfoo1") == "detected"          # notice.py 的分類認得這個格式


def test_evidence_no_debs(tmp_path, capsys):
    for n, d in (("r", {"files": []}), ("i", {"packages": {}}), ("s", {"packages": [{"type": "npm", "name": "a", "purl": "pkg:npm/a@1"}]})):
        (tmp_path / f"{n}.json").write_text(json.dumps(d))
    oc.main(["evidence", *(str(tmp_path / f"{n}.json") for n in "ris"), str(tmp_path / "e.json")])
    assert capsys.readouterr().out.startswith("NOT_RUN")
