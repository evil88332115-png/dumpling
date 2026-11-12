# bwrap 沙箱與沙箱探測（由 real-projects.sh、license.sh、tools/pilot/sca-scan 載入）。
# 呼叫前需要：ROOT、WORK、status()；sandbox_probe <輸出檔> 失敗時記 B-sandbox FAIL 並結束整個腳本（呼叫端可用子 shell 接住）。
# 可選：
#   SBX_TOOL   探測「工具目錄」用的指令名稱（預設 grype）。
#   SBX_RO     （bash 陣列）被遮蔽的範圍內、沙箱需要讀的路徑，唯讀掛回。工具鏈的根目錄（JAVA_HOME、GOROOT、Python 的 base_prefix）
#              不會自動掛回，需要時由呼叫端明確列在這裡。
#   SBX_HIDE   （bash 陣列）一定要遮蔽的路徑（例如存有 API key 的設定檔、秘密清單）；在 SBX_RO 之後套用，所以掛回的資料夾裡的秘密仍被遮住。
#   SBX_TOOLS  要自動掛回的工具指令（預設見 sbx_rebinds）。
#
# 憑證遮蔽（2026-10-23 審查、複審）：根目錄是唯讀可讀的，不遮的話 ~/.ssh、~/.docker/config.json、~/.config/gh、~/.git-credentials、
# ~/.netrc、~/.npmrc、GitHub runner 的 .credentials 都讀得到，連網沙箱就能外送。所以不論是否連網，一律以空的 tmpfs 蓋掉：
#   - 真正的家目錄（getent passwd 的第 6 欄；不信任 $HOME 環境變數，兩者不同時兩個都蓋）
#   - /home/runner/runners 與 $RUNNER_WORKSPACE 的上兩層（runner 程式、註冊憑證、_work、_temp、_tool；存在時）。
#     GitHub runner 沒有提供「runner 根目錄」的變數，實際靠 RUNNER_WORKSPACE（<runner 根目錄>/_work/<repo>）往上兩層推得；
#     RUNNER_ROOT 不是 runner 設定的變數，只作為可選的覆寫（例如自訂的 runner 安裝位置），沒設定時不影響。
# 只唯讀掛回：npm 全域套件的套件根目錄（lib/node_modules/<套件>）、其他工具實際檔案所在的資料夾（dirname(readlink -f)）、
# PATH 上的符號連結本身（以 --symlink 重建，不掛整個資料夾），以及 SBX_RO。
# 一律遮蔽的設定檔（可能含 registry 權杖；不論位置是否在遮蔽範圍內，見 sbx_auto_hide）：npm 全域設定 <prefix>/etc/npmrc、
# Python 的 <base_prefix>/pip.conf、<base_prefix>/etc、<base_prefix>/.condarc（venv 時另含 sys.prefix）、/etc/pip.conf、/etc/xdg/pip、
# /etc/conda，以及每個 SBX_RO 掛回路徑下的 pip.conf、.condarc、.npmrc、npmrc、.netrc、etc（例如掛回的 GOROOT、JAVA_HOME）。

sbx_masks(){  # 印出要以 tmpfs 遮蔽的資料夾（每行一個；已去掉被其他遮蔽涵蓋的子路徑）
  local h d out=() m keep rw
  h=$(getent passwd "$(id -u)" 2>/dev/null | cut -d: -f6)
  rw=; [ -n "${RUNNER_WORKSPACE:-}" ] && rw=$(dirname "$(dirname "$RUNNER_WORKSPACE")")
  for d in "$h" "${HOME:-}" /home/runner/runners "${RUNNER_ROOT:-}" "$rw"; do
    [ -n "$d" ] && [ -d "$d" ] || continue; d=$(readlink -f "$d")
    # 系統層級的資料夾不遮（例如 RUNNER_WORKSPACE 的上兩層算到 /home），避免把整個系統蓋掉
    case $d in /|/home|/usr|/opt|/var|/etc|/tmp|/srv|/mnt|/media) continue;; esac; out+=("$d"); done
  local uniq=(); mapfile -t uniq < <(printf '%s\n' "${out[@]+"${out[@]}"}" | sed '/^$/d' | sort -u)
  for d in "${uniq[@]+"${uniq[@]}"}"; do
    keep=1; for m in "${uniq[@]}"; do [ "$m" != "$d" ] && [[ "$d" == "$m"/* ]] && keep=0; done; [ $keep = 1 ] && echo "$d"; done; }

sbx_unsafe(){  # sbx_unsafe <路徑> <遮蔽...>：掛回這個路徑會重新露出遮蔽內容時成功
  local p=$1 m x; shift
  # runner 的暫存區、runner 目錄本身與它們的上層（_temp 底下有 runner 的檔案命令與暫存的憑證）
  for x in "${RUNNER_TEMP:-}" /home/runner/runners "${RUNNER_ROOT:-}"; do
    [ -n "$x" ] || continue; x=$(readlink -m "$x"); [ "$p" = "$x" ] || [[ "$x" == "$p"/* ]] && return 0; done
  for m; do
    [ "$p" = "$m" ] || [[ "$m" == "$p"/* ]] && return 0      # 遮蔽本身或它的上層
    case $p in
      "$m"/.local|"$m"/.cache|"$m"/.npm|"$m"/.m2|"$m"/.cargo|"$m"/.pyenv|"$m"/.nvm|"$m"/.config|"$m"/.config/*) return 0;;
      "$m"/.ssh|"$m"/.ssh/*|"$m"/.docker|"$m"/.docker/*|"$m"/.gnupg|"$m"/.gnupg/*|"$m"/.aws|"$m"/.aws/*|"$m"/.kube|"$m"/.kube/*) return 0;;
      "$m"/etc|"$m"/etc/*|"$m"/*/etc|"$m"/*/etc/*) return 0;;   # 例如 npm prefix 的 etc/npmrc
    esac; done; return 1; }

sbx_under(){  # sbx_under <路徑> <遮蔽...>：路徑在任一遮蔽之內（含本身）時成功
  local p=$1 m; shift; for m; do [ "$p" = "$m" ] || [[ "$p" == "$m"/* ]] && return 0; done; return 1; }

sbx_rebinds(){  # 印出「ro <路徑>」（唯讀掛回）與「ln <目標> <路徑>」（重建符號連結）
  local masks t p r root d binds=() links=() b skip
  mapfile -t masks < <(sbx_masks)
  [ ${#masks[@]} -gt 0 ] || return 0
  for t in ${SBX_TOOLS:-cdxgen syft grype govulncheck node npm npx go java mvn gradle python3 python pip3 git}; do
    p=$(command -v "$t" 2>/dev/null) || continue; [[ "$p" == /* ]] || continue
    r=$(readlink -f "$p")
    if sbx_under "$r" "${masks[@]}"; then
      if [[ "$r" == */lib/node_modules/* ]]; then   # npm 全域套件：只掛該套件的根目錄（依賴在它自己的 node_modules 內）
        d=${r#*/lib/node_modules/}; root=${r%%/lib/node_modules/*}/lib/node_modules/${d%%/*}
        [[ "${d%%/*}" == @* ]] && { d=${d#*/}; root=$root/${d%%/*}; }
      else root=$(dirname "$r"); fi
      if sbx_unsafe "$root" "${masks[@]}"; then root=$r; sbx_unsafe "$root" "${masks[@]}" && { echo "sandbox.sh：不掛回 $r" >&2; continue; }; fi
      binds+=("$root")
    fi
    # PATH 上的指令是遮蔽範圍內的符號連結：在沙箱內重建同一個連結（指向實際檔案），不掛整個資料夾
    [ -L "$p" ] && sbx_under "$p" "${masks[@]}" && links+=("$r|$p")
  done
  for p in ${SBX_RO[@]+"${SBX_RO[@]}"}; do
    [ -n "$p" ] && [ -e "$p" ] || continue; p=$(readlink -f "$p")
    if sbx_unsafe "$p" "${masks[@]}"; then echo "sandbox.sh：拒絕掛回 $p（會重新露出家目錄、runner 或憑證）" >&2; continue; fi
    sbx_under "$p" "${masks[@]}" /tmp && binds+=("$p"); done
  printf '%s\n' "${binds[@]+"${binds[@]}"}" | awk 'NF && !seen[$0]++ {print "ro " $0}'
  for b in "${links[@]+"${links[@]}"}"; do
    p=${b#*|}; skip=0; for d in "${binds[@]+"${binds[@]}"}"; do [ "$p" = "$d" ] || [[ "$p" == "$d"/* ]] && skip=1; done   # 已在掛回的資料夾內
    [ $skip = 0 ] && echo "ln ${b%%|*} $p"; done | awk '!seen[$0]++'
}

sbx_toolchain_roots(){  # 印出工具鏈的根目錄（每行一個；給呼叫端明確放進 SBX_RO）：只掛 bin 時無法執行的工具
  # JAVA_HOME（沒設時由 java 的實際位置推：<JAVA_HOME>/bin/java）、Maven 安裝目錄（<MAVEN_HOME>/bin/mvn；mvn 需要 boot、lib、conf）、
  # Gradle 安裝目錄、GOROOT、Python 的 base_prefix 與 prefix。只是候選：sbx_rebinds 只掛回在遮蔽範圍內、且不是不安全路徑的。
  # 2026-10-23 實機：自架 runner 沒有 java／mvn 時 cdxgen 退回只讀 pom.xml（petclinic 163 → 19 個元件），這裡無法補上沒有安裝的工具。
  local t r
  if [ -n "${JAVA_HOME:-}" ]; then echo "$JAVA_HOME"
  elif command -v java > /dev/null; then r=$(dirname "$(dirname "$(readlink -f "$(command -v java)")")"); [ "$(basename "$r")" = jre ] && r=$(dirname "$r"); echo "$r"; fi
  for t in mvn gradle; do command -v "$t" > /dev/null && dirname "$(dirname "$(readlink -f "$(command -v "$t")")")"; done
  command -v go > /dev/null && go env GOROOT 2>/dev/null
  command -v python3 > /dev/null && python3 -I -c 'import sys;print(sys.base_prefix);print(sys.prefix)' 2>/dev/null
  return 0; }

sbx_auto_hide(){  # 印出一定遮蔽的設定檔與資料夾（存在的才印；每行一個）。固定部分只算一次，SBX_RO 部分每次重算
  local np pp d
  if [ -z "${SBX_AUTO_HIDE_DONE:-}" ]; then
    np=$(command -v npm > /dev/null && npm prefix -g 2>/dev/null | head -1)
    pp=$(command -v python3 > /dev/null && python3 -I -c 'import sys;print(sys.base_prefix);print(sys.prefix)' 2>/dev/null)
    SBX_AUTO_HIDE_LIST=$( { [ -n "$np" ] && echo "$np/etc/npmrc"
      while IFS= read -r d; do [ -n "$d" ] && [ "$d" != / ] && printf '%s\n' "$d/pip.conf" "$d/etc" "$d/.condarc"; done <<< "$pp"
      printf '%s\n' /etc/pip.conf /etc/xdg/pip /etc/conda; } | awk '!seen[$0]++')
    SBX_AUTO_HIDE_DONE=1; fi
  { printf '%s\n' "${SBX_AUTO_HIDE_LIST:-}"
    # 每個掛回路徑：pip／conda／npm／netrc 設定、etc，以及 Maven 的 conf/settings.xml、conf/settings-security.xml，Gradle 的 init.d、gradle.properties
    # （全域設定可能含 registry 權杖或代理帳密；遮掉後無法經它連內部代理，見 README）
    for d in ${SBX_RO[@]+"${SBX_RO[@]}"}; do [ -n "$d" ] && [ -d "$d" ] && printf '%s\n' "$d/pip.conf" "$d/.condarc" "$d/.npmrc" "$d/npmrc" "$d/.netrc" "$d/etc" \
      "$d/conf/settings.xml" "$d/conf/settings-security.xml" "$d/init.d" "$d/gradle.properties"; done
  } | while IFS= read -r d; do [ -n "$d" ] && [ -e "$d" ] && echo "$d"; done | awk '!seen[$0]++'; return 0; }

sbx_stub(){  # sbx_stub <被遮蔽的檔案>：印出替代用的檔案（主機上的暫存檔）。設定檔不能用 /dev/null（在 nodev 掛載下讀取會失敗，
  # Maven 讀不到全域 settings.xml 會中止），改用內容為空但格式合法的檔案：settings.xml → <settings/>、settings-security.xml →
  # <settingsSecurity/>，其他 → 空檔。
  local d=${SBX_STUB_DIR:-}
  if [ -z "$d" ] || [ ! -d "$d" ]; then d=$(mktemp -d "${TMPDIR:-/tmp}/sbx-stubs.XXXXXX"); SBX_STUB_DIR=$d
    printf '<settings/>\n' > "$d/settings.xml"; printf '<settingsSecurity/>\n' > "$d/settings-security.xml"; : > "$d/empty"; chmod 644 "$d"/*; chmod 755 "$d"; fi
  case $(basename "$1") in settings.xml) echo "$d/settings.xml";; settings-security.xml) echo "$d/settings-security.xml";; *) echo "$d/empty";; esac; }

sbx_stub_sums(){  # 替代檔的 sha256（給探測判斷「讀到的是替代檔」）
  sbx_stub x > /dev/null; sha256sum "$SBX_STUB_DIR"/settings.xml "$SBX_STUB_DIR"/settings-security.xml "$SBX_STUB_DIR"/empty | cut -d' ' -f1; }

sbx(){  # sbx [--net] [--chdir 目錄] [可寫目錄...] -- [VAR=值...] 指令...
  local net=(--unshare-net) cd=() rw=() envs=()
  [ "$1" = --net ] && { net=(); shift; }
  [ "$1" = --chdir ] && { cd=(--chdir "$2"); shift 2; }
  while [ "$1" != -- ]; do rw+=(--bind "$1" "$1"); shift; done; shift
  while [[ "$1" == *=* ]]; do envs+=(--setenv "${1%%=*}" "${1#*=}"); shift; done
  # /run（與 /var/run）蓋成空的 tmpfs：唯讀掛載擋不住對 unix socket 的 connect()，不遮就能操作 /var/run/docker.sock 取得 root。
  # 連網沙箱需要 DNS：Ubuntu 的 /etc/resolv.conf 指向 /run/systemd/resolve，只把那個資料夾唯讀放回。
  local run=(--tmpfs /run); [ -L /var/run ] || run+=(--tmpfs /var/run)
  [ ${#net[@]} -eq 0 ] && [ -d /run/systemd/resolve ] && run+=(--ro-bind /run/systemd/resolve /run/systemd/resolve)
  local mask=() rebind=() hide=() h k a b c
  while IFS= read -r h; do mask+=(--tmpfs "$h"); done < <(sbx_masks)
  while read -r k a b; do case $k in ro) rebind+=(--ro-bind "$a" "$a");; ln) rebind+=(--symlink "$a" "$b");; esac; done < <(sbx_rebinds)
  local auto=(); sbx_auto_hide > /dev/null; mapfile -t auto < <(sbx_auto_hide)   # 第一次呼叫在本 shell 算好固定部分
  sbx_stub x > /dev/null   # 在本 shell 建好替代檔
  # 遮蔽目標一律換成實際路徑（readlink -f）：bwrap 0.9.0 不會跟著目的路徑中間的符號連結建立掛載點，例如 Debian 的 maven 套件
  # /usr/share/maven/conf → /etc/maven，對 /usr/share/maven/conf/settings.xml 掛替代檔會「Can't create file … No such file or directory」，
  # 整個沙箱起不來（2026-10-23 本機重現）。蓋住實際檔案後，經由符號連結看到的也是替代檔。
  for h in ${SBX_HIDE[@]+"${SBX_HIDE[@]}"} ${auto[@]+"${auto[@]}"}; do
    [ -n "$h" ] && [ -e "$h" ] || continue; c=$(readlink -f "$h")
    # 解析後是系統層級資料夾（例如 <prefix>/etc → /etc 的符號連結）時不整個蓋掉（會讓沙箱內的系統壞掉）：記錄後略過，
    # 已知設定檔（/etc/pip.conf 等）在 sbx_auto_hide 另外逐檔遮蔽
    if [ -d "$c" ]; then case $c in /|/etc|/usr|/usr/local|/home|/var|/opt|/bin|/sbin|/lib|/lib64|/usr/lib|/usr/share|/srv|/mnt|/media|/root|/boot|/proc|/sys|/dev|/run|/tmp)
      echo "sandbox.sh：不以 tmpfs 遮蔽系統資料夾 $c（來自 $h），略過" >&2; continue;; esac; fi
    if [ -d "$c" ]; then hide+=(--tmpfs "$c"); else hide+=(--ro-bind "$(sbx_stub "$c")" "$c"); fi; done
  # 順序：根目錄唯讀 → /tmp、/run → 遮蔽家目錄與 runner → 唯讀掛回工具與 SBX_RO → 遮蔽秘密 → 可寫資料夾
  bwrap --unshare-pid --new-session --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp --dir /tmp/home "${run[@]}" "${mask[@]}" "${rebind[@]}" "${hide[@]}" "${rw[@]}" "${net[@]}" "${cd[@]}" --die-with-parent \
    --clearenv --setenv PATH "$PATH" --setenv HOME /tmp/home --setenv LANG C.UTF-8 "${envs[@]}" -- "$@"; }

sandbox_secret_probe(){  # sandbox_secret_probe <輸出檔> [額外要確認讀不到的路徑...]：成功＝全部讀不到
  # 家目錄放一個測試用假檔，加上常見的憑證位置與 runner 的 .credentials；只記「讀得到／讀不到」，不輸出內容
  local h fake= fake2= p paths=() r
  h=$(getent passwd "$(id -u)" 2>/dev/null | cut -d: -f6)
  if [ -n "$h" ] && [ -d "$h" ] && [ -w "$h" ]; then fake=$(mktemp "$h/.sbx-probe-fake-credential.XXXXXX" 2>/dev/null) && echo "fake" > "$fake"; fi
  # runner 的暫存區（$RUNNER_TEMP）也放一個假檔：_temp 底下有 runner 的檔案命令與 setup-* 寫的設定
  if [ -n "${RUNNER_TEMP:-}" ] && [ -d "$RUNNER_TEMP" ] && [ -w "$RUNNER_TEMP" ]; then fake2=$(mktemp "$RUNNER_TEMP/.sbx-probe-fake-credential.XXXXXX" 2>/dev/null) && echo "fake" > "$fake2"; fi
  local auto=(); sbx_auto_hide > /dev/null; mapfile -t auto < <(sbx_auto_hide)
  for p in "$fake" "$fake2" "$h/.ssh" "$h/.docker/config.json" "$h/.config/gh" "$h/.git-credentials" "$h/.netrc" "$h/.npmrc" "$h/.pypirc" \
           "$h/.cargo/credentials.toml" "$h/.cargo/credentials" "${HOME:-}/.ssh" ${auto[@]+"${auto[@]}"} \
           /home/runner/runners/*/.credentials /home/runner/runners/*/.runner \
           ${RUNNER_ROOT:+"$RUNNER_ROOT/.credentials"} ${RUNNER_WORKSPACE:+"$(dirname "$(dirname "$RUNNER_WORKSPACE")")/.credentials"} "${@:2}"; do
    [ -n "$p" ] && [ -e "$p" ] && ! printf '%s\n' "${paths[@]+"${paths[@]}"}" | grep -qxF -- "$p" && paths+=("$p"); done
  {
    [ -n "$fake" ] && echo "測試用假檔：$fake" || echo "家目錄不可寫或不存在，沒有建立測試用假檔"
    [ -n "$fake2" ] && echo "測試用假檔（RUNNER_TEMP）：$fake2"
    if [ ${#paths[@]} -eq 0 ]; then echo "沒有可測的路徑"
    else
      # 讀得到＝資料夾有內容，或檔案非空可讀且內容不是替代檔（替代檔是 <settings/> 之類的空設定）
      r=$(sbx -- bash -c 'for f; do if [ -d "$f" ]; then [ -n "$(ls -A "$f" 2>/dev/null)" ] && printf "%s\tdir\n" "$f"; elif [ -s "$f" ] && head -c1 "$f" >/dev/null 2>&1; then printf "%s\t%s\n" "$f" "$(sha256sum < "$f" | cut -d" " -f1)"; fi; done' _ "${paths[@]}" 2>/dev/null)
      local stubs; stubs=$(sbx_stub_sums)
      r=$(printf '%s\n' "$r" | while IFS=$'\t' read -r f h; do [ -n "$f" ] && ! printf '%s\n' "$stubs" | grep -qxF -- "$h" && echo "$f"; done)
      for p in "${paths[@]}"; do if printf '%s\n' "$r" | grep -qxF -- "$p"; then echo "讀得到（不應該）：$p"; else echo "讀不到（或只讀到空的替代檔）：$p"; fi; done
    fi
  } >> "$1" 2>&1
  [ -n "$fake" ] && rm -f "$fake"; [ -n "$fake2" ] && rm -f "$fake2"
  ! grep -q "讀得到（不應該）" "$1"; }

sandbox_probe(){  # sandbox_probe <輸出檔>
  # 1. 寫入：runner 使用者「本來可寫」的路徑（GITHUB_ENV 檔、工具目錄、checkout、$WORK）。以主機端是否真的出現標記判斷
  #    （家目錄被 tmpfs 遮蔽後，沙箱內寫進 tmpfs 會成功但不會到達主機，那不算可寫）。
  local q mk ok_ctl=0
  probe_paths=("${GITHUB_ENV:-}" "${GITHUB_PATH:-}" "$(dirname "$(command -v "${SBX_TOOL:-grype}")")/sbx-probe" "$ROOT/sbx-probe" "$WORK/sbx-probe")
  : > "$1"
  { for q in "${probe_paths[@]}"; do [ -n "$q" ] || continue
      mk=sbx-probe-$RANDOM$RANDOM
      sbx -- bash -c 'echo "$2" >> "$1"' _ "$q" "$mk" 2>/dev/null
      if grep -qF -- "$mk" "$q" 2>/dev/null; then echo "可寫（不應該）：$q"; else echo "寫不進去（主機上沒有變動）：$q"; fi
      rm -f "$ROOT/sbx-probe" "$WORK/sbx-probe" 2>/dev/null; done
    PROBE='echo "--- 沙箱 ${1:-無網路}"
        curl -sS -m 5 -o /dev/null https://pypi.org 2>/dev/null; echo "對外網路：curl exit=$?（0＝有網路；6/7＝沒有）"
        for s in /var/run/docker.sock /run/docker.sock; do curl -s -m 3 --unix-socket "$s" http://x/version >/dev/null 2>&1 && echo "Docker socket 可連（不應該）：$s" || echo "Docker socket 連不到：$s"; done
        n=$(ls -A /run 2>/dev/null | grep -vx systemd | wc -l); [ "$n" = 0 ] && echo "/run 已遮蔽（沒有其他項目）" || echo "/run 有 $n 個項目（不應該）"
        sudo -n true 2>/dev/null && echo "sudo 可用（不應該）" || echo "sudo 不可用"
        curl -s -m 3 -o /dev/null http://169.254.169.254/ 2>/dev/null && echo "雲端 metadata 169.254.169.254 可連（記錄）" || echo "雲端 metadata 169.254.169.254 連不到"
        # 只記 HTTP 狀態碼，不輸出內容：Azure 的身分端點回 200 代表掛有可取 token 的身分
        echo "雲端身分端點（Azure IMDS identity）HTTP $(curl -s -m 3 -o /dev/null -w "%{http_code}" -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" 2>/dev/null || echo 連不到)"
        echo "看得到的程序數：$(ls -d /proc/[0-9]* | wc -l)"; echo "環境變數：$(env | cut -d= -f1 | sort | tr "\n" " ")"'
    # 2. Docker socket 對照組：沙箱外可連時，沙箱內「連不到」才是遮蔽有效的證據。
    #    沙箱外也連不到（沒有 Docker 或沒有權限）時對照組不可用：這時沙箱內也沒有這條提權路徑（bwrap 不會給更多權限），
    #    改以「沙箱內 /run 是空的」作為遮蔽的證據，不阻止掃描。
    if curl -s -m 3 --unix-socket /var/run/docker.sock http://x/version >/dev/null 2>&1; then echo "對照：沙箱外 Docker socket 可連"
    else echo "對照組不可用：沙箱外也連不到 Docker socket（沒有 Docker 或沒有權限），以 /run 已遮蔽為證據"; fi
    sbx -- bash -c "$PROBE" _ 無網路
    sbx --net -- bash -c "$PROBE" _ 有網路
    echo "--- 憑證遮蔽"
  } >> "$1" 2>&1
  sandbox_secret_probe "$1"
  grep -q "對照：沙箱外 Docker socket 可連" "$1" && ok_ctl=1
  if grep -q "（不應該）" "$1" || grep -q "身分端點.*HTTP 200" "$1" || ! grep -q "/run 已遮蔽" "$1"; then
    status B-sandbox FAIL "沙箱隔離不足（$(basename "$1")）"; echo "沙箱隔離不足，停止：不在這樣的沙箱裡執行不可信程式" >&2; exit 1
  elif [ $ok_ctl = 1 ]; then status B-sandbox OK "主機路徑不可寫、Docker socket 連不到（對照組可連）、無 sudo、家目錄與 runner 憑證讀不到"
  else status B-sandbox OK "主機路徑不可寫、無 sudo、家目錄與 runner 憑證讀不到；Docker 對照組不可用（沙箱外也連不到 Docker socket），以 /run 已遮蔽為證據"; fi
}

# 載入時先建好替代檔（之後在子 shell 內呼叫 sbx 也用同一個資料夾）
sbx_stub x > /dev/null
