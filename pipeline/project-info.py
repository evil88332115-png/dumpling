#!/usr/bin/env python3
"""印出專案資訊給 workflow 用（KEY=VALUE，一行一個，值都是安全字元，可直接 `>> "$GITHUB_OUTPUT"`）。

用法：python3 -I pipeline/project-info.py <專案>/<版本>      （tag 格式）
      python3 -I pipeline/project-info.py --dir <專案資料夾> <版本>
      python3 -I pipeline/project-info.py --kernel-args <專案資料夾> <版本>   （scan.sh 用：精靈的核心參數，一行一個；來自 platform_params 的
                                                   kernel_release、kernel_upstream_version、kernel_not_distro，加上 platform.yml 的 scan.kernel_not_distro 預設，
                                                   見 project_config.kernel_wizard_args；沒有就不印）
      python3 -I pipeline/project-info.py --matrix [<專案名>]    （dev.yml 用：印 JSON 陣列 [{"project","version"}…]；每個專案取 sources.yml 的最後一個版本）
輸出另含 workflow 的規劃值（platform.yml）：BUILD_MODE（compile｜none）、BUILD_RUNNER（runner 標籤）、BUILD_APT、SCAN_RUNNER、SCAN_APT（apt 清單用空白分隔）、SCAN_TOOLS（sbom-only｜full）、ARCH。platform.yml 的 scan.tools 不是這兩個值 → 結束碼 64（用法／設定錯誤）。
tag 格式錯、專案不存在、版本不在 sources.yml、欄位驗證失敗 → 不印 KEY=VALUE，印 "project-info: FAIL（…）" 並以 1 結束。
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "lib"))
import project_config as pc  # noqa: E402


def _rel(path):
    root = os.path.normpath(os.path.join(HERE, ".."))
    ap = os.path.abspath(path)
    return os.path.relpath(ap, root) if ap.startswith(root + os.sep) else path


def info(project_dir, version, platforms_dir=pc.PLATFORMS_DIR):
    project, sources = pc.load_project_all(project_dir, platforms_dir)
    if version not in sources["releases"]:
        raise pc.ConfigError("sources.yml 沒有版本 " + version)
    if not re.match(r"^[A-Za-z0-9_./+-]+$", project_dir):
        raise pc.ConfigError("專案資料夾路徑含不安全字元")
    name = os.path.basename(os.path.normpath(project_dir))
    plan = pc.platform_plan(pc.load_platform_config(project["platform"], platforms_dir))
    return [("PROJECT", name), ("VERSION", version), ("TAG", name + "/" + version),
            ("PLATFORM", project["platform"]), ("STATUS", project["status"]),
            ("OS_RESPONSIBILITY", project["os_responsibility"]), ("COMPANY_ROLE", project["company_role"]),
            ("PROJECT_DIR", _rel(project_dir)),
            ("BUILD_MODE", plan["build_mode"]), ("BUILD_RUNNER", plan["build_runner"]), ("BUILD_APT", " ".join(plan["build_apt"])),
            ("SCAN_RUNNER", plan["scan_runner"]), ("SCAN_APT", " ".join(plan["scan_apt"])), ("SCAN_TOOLS", plan["scan_tools"]), ("ARCH", plan["arch"])]


def matrix(root, only=None):
    """每個專案取 sources.yml 裡最後一個版本（dev.yml 的建置矩陣）。壞掉的專案不略過：丟 ConfigError。"""
    base = os.environ.get("DUMPLING_PROJECTS_DIR", os.path.join(root, "projects"))
    out = []
    for name in sorted(os.listdir(base)):
        pdir = os.path.join(base, name)
        if not os.path.isdir(pdir) or os.path.islink(pdir) or not pc.PROJECT_RE.match(name):
            continue
        if only and name != only:
            continue
        project, sources = pc.load_project_all(pdir)
        out.append({"project": name, "version": list(sources["releases"])[-1]})
    if only and not out:
        raise pc.ConfigError("專案 %s 不存在" % only)
    return out


def main(argv):
    root = os.path.normpath(os.path.join(HERE, ".."))
    try:
        if argv and argv[0] == "--matrix" and len(argv) <= 2:
            import json
            print(json.dumps(matrix(root, argv[1] if len(argv) == 2 else None)))
            return 0
        if len(argv) == 3 and argv[0] == "--kernel-args":
            pdir, version = argv[1], argv[2]
            if not pc.VERSION_RE.match(version):
                raise pc.ConfigError("版本格式不合法")
            project, sources = pc.load_project_all(pdir)
            if version not in sources["releases"]:
                raise pc.ConfigError("sources.yml 沒有版本 " + version)
            plat = pc.load_platform_config(project["platform"]).get("scan") or {}      # 平台預設：scan.kernel_not_distro
            for x in pc.kernel_wizard_args(sources["releases"][version].get("platform_params"), plat.get("kernel_not_distro")):
                print(x)
            return 0
        if len(argv) == 1:
            name, version = pc.parse_tag(argv[0])
            pdir = os.path.join(os.environ.get("DUMPLING_PROJECTS_DIR", os.path.join(root, "projects")), name)
            if not os.path.isdir(pdir) or os.path.islink(pdir):
                raise pc.ConfigError("專案 %s 不存在" % name)
        elif len(argv) == 3 and argv[0] == "--dir":
            pdir, version = argv[1], argv[2]
            if not pc.VERSION_RE.match(version):
                raise pc.ConfigError("版本格式不合法")
            if not pc.PROJECT_RE.match(os.path.basename(os.path.normpath(pdir))):
                raise pc.ConfigError("專案資料夾名稱不合法")
        else:
            print("用法：project-info.py <專案>/<版本> | --dir <專案資料夾> <版本>", file=sys.stderr)
            return 64
        pairs = info(pdir, version)
    except pc.ConfigError as e:
        print("project-info: FAIL（%s）" % e)
        return 64 if "scan.tools" in str(e) else 1
    for k, v in pairs:
        print("%s=%s" % (k, v))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
