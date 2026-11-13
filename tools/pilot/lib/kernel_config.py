#!/usr/bin/env python3
"""kernel_config.py：核心的 CVE 是否「修補的程式根本沒編進產品的核心」（sca-scan 的 C-kernel-config）。
寫 scan/kernel-config.json（格式見 docs 的介面約定：schema sca-center-kernel-config/1），並印一行 status：
  C-kernel-config<TAB>狀態<TAB>說明

用法：python3 -I kernel_config.py [--grype <grype.json[.xz]>] [--findings <dt/findings.json[.xz]>] [--cves <檔案>]
                              [--kernel-map <scan/l4t-kernel-map.json>] [--kernel-version <例如 6.8.12-1021-tegra>]
                              (--from <rootfs tar｜docker save 的 tar｜資料夾｜刷機包 tbz2> [--prefix <rootfs 在刷機包裡的路徑>]
                               | --config <.config> --makefiles-dir <核心原始碼樹>)
                              --mirror <tools/mirror/kernel-cve.sh 的輸出> [--max-age-days N]
                              [--build-record <核心建置紀錄：資料夾｜.tar｜.tar.gz｜.tar.xz>] --out <kernel-config.json>
  --grype／--findings：只取「核心元件」上的 CVE（C-kernel-l4t-map 加上的 Canonical 核心，例如 linux-nvidia-tegra，
    以及 kernelcheck.py 認得的核心套件）；--cves：每行一個 CVE（另外指定時合併）。
  --from：
    rootfs tar（scan-flash-package.sh 的 rootfs tar，可壓縮）、docker save 的 tar（依 manifest.json 的層次序讀，處理 whiteout）、
    rootfs 資料夾、刷機包 tbz2（配 --prefix，例如 Linux_for_Tegra/rootfs_no_gui；沿用 tools/demo/flash_package.py 的串流讀法），
    或一個核心原始碼樹的資料夾（最上層有 .config 與 Makefile）。只讀需要的檔案：
      /usr/src/linux-*/ 底下的 .config、Makefile*、Kbuild*、*.mk 與符號連結（不跟隨到樹外；連結在記憶體裡解析，不碰主機）；
      /usr/lib/modules/<版本>/（或 /lib/modules/）的模組檔名、modules.builtin、modules.order 與 build 連結。
    全部在記憶體裡處理，不解開到磁碟，不執行任何東西。
  燒錄的核心：另外讀 rootfs 的 /boot/Image（或 Image.gz）；有 --prefix（刷機包或解開的 Linux_for_Tegra 資料夾）時再讀
    <prefix 的上一層>/kernel/Image（或 Image.gz；燒錄時蓋掉 rootfs 的 /boot/Image，廠商可能自己重編過）。從 Image 取出內建的設定
    （IKCONFIG：IKCFG_ST＋gzip＋IKCFG_ED，讀法同 Linux 的 scripts/extract-ikconfig；Image 本身是 gzip／xz／bzip2／lzma／zstd 也會先解開），
    和 headers 的 .config 核對（kernel.config_check）。只在記憶體裡做：Image 最多 MAX_IMAGE、解壓後 MAX_IMAGE_UNPACKED、
    config MAX_IKCONFIG；超過只記原因（sha256、md5 照算）。多段 gzip 同 zcat 全部解開；IKCFG_ED 沒有緊接在 gzip 之後 → 不完整
    （image.ikconfig_complete false）。刷機包的 kernel/Image 不跟隨連結；rootfs 的 /boot/Image 是符號連結或硬連結時在映像裡解開
    （目標要是 /boot 底下讀過的 Image* 檔案）。主要的 Image 是刷機包的 kernel/Image，沒有時用 rootfs 的 /boot/Image：
      比較時沒有的設定和 is not set 都算 n。設定相同 → 照舊；只差工具鏈衍生的設定（TOOLCHAIN_OPTION_*）→ same_except_toolchain，OK，
        改用 IKCONFIG 判定；其他不同 → 改用 Image 的設定判定（config_source "kernel/Image (IKCONFIG)"），記兩邊的 sha256（原始位元組）與差異的設定，
        ATTENTION（vex_export 只在 IKCONFIG 完整時採用）；
      讀不到 IKCONFIG：用 rootfs 的 dpkg（var/lib/dpkg/status 與 info/*.md5sums，不可信、只解析、有上限）驗證：擁有 /boot/Image 的套件記的 md5
        和 /boot/Image 相同、刷機包的 kernel/Image 也相同（Image.gz 比解壓後的）、headers .config 的 md5 和擁有它的套件記的相同、
        兩個套件同版本而且名稱成對（<X>／<X>-headers、linux-image-<v>／linux-headers-<v>；Source 相同不算）→ 照舊（dpkg_verified）；
        任何一項不成立 → GAP。IKCONFIG 不完整但設定相同 → 也走 dpkg 驗證；IKCONFIG 標頭的架構和 headers 不同 → GAP。兩個 Image 都沒有 → 照舊（輸出和以前相同，沒有 config_check）。
    C-kernel-module-map（kernel_module_map.py）用同一個判斷（settle_config），兩邊永遠用同一份設定。
  --kernel-version：要看的核心（/usr/lib/modules/<版本>/）；沒給時用 --kernel-map 的 modules_kernel_version；
    都沒有時映像只有一個模組目錄才用它，否則 GAP（不猜）。
  --cves-origin：--cves 的清單從哪裡來（例如 kernel-cna-version：sca-scan 在 Grype／DT 都沒有核心 CVE 時，用 kernel_cna_version.py
    依產品核心版本產生的清單）；只記在輸出的 inputs.cves_origin 與說明，不改判定。沒給時輸出和以前逐位元組相同。
  --source-tree：核心原始碼樹（資料夾，唯讀）當 Makefile／Kbuild 的來源（刷機包／rootfs 的 linux-headers 不完整時）。.config、IKCONFIG
    核對、modules 與 Image 照舊來自 --from；只有 Makefile 類檔案（Makefile*、Kbuild*、*.mk，沿用同樣的讀法與上限）與檔案名稱改讀這棵樹。
    不執行樹裡的任何東西，符號連結不跟隨（不會跟出樹外）。樹裡有 .config 時和判定用的設定核對（kernel.source_tree.config_compare），
    相同或只差工具鏈照舊；不同 → 記出來，狀態 ATTENTION。樹的主.次版本和判定的核心不同 → GAP。輸出的 kernel.source_tree 記 Makefile 的來源。
  --probe-kernel-version：不判定，只從 --from 讀出產品核心版本（/lib/modules/<版本>，沒有時 Image 的版本字串），印一行
    KERNEL-VERSION<TAB>OK|NONE|GAP<TAB>版本或原因（sca-scan 在 Grype／DT 沒有核心 CVE 時用）；不需要 --out。
  --list-kernel-versions：不判定，只列出 --from 的映像出貨的每顆核心（/usr/lib/modules/<版本>/ 有 .ko 或檔案的資料夾，排序、空白分隔），印一行
    KERNEL-VERSIONS<TAB>OK<TAB>版本…（沒有模組資料夾時版本欄是空的）；讀不出來 → KERNEL-VERSIONS<TAB>GAP<TAB>原因。
    sca-scan 用它找出「出貨但沒被判定」的核心（--kernel-version 沒給的那些）；不需要 --out。
  --also-list-kernel-versions：判定（或 --probe-kernel-version）時，讀映像的同一趟順便多印一行 KERNEL-VERSIONS<TAB>OK<TAB>版本…（內容同
    --list-kernel-versions）。sca-scan 用它：刷機包 tbz2 不必為了列出核心再解壓一次。沒給時輸出和以前相同；--from 是核心原始碼樹時不印。
  --oot-build-record：樹外模組（例如 nvidia-oot、nvgpu）的建置資料夾，可重複；需要 --build-record。讀 .*.o.cmd 的 source／deps 與 .*.ko.cmd
    （kernel_oot_record.py）。映像裡每一個樹外 .ko 都有完整的紀錄時，標頭檔看紀錄的 deps（核心與樹外模組都沒列 → 沒編；樹外模組列了 → 有編），
    否則標頭檔照舊因為樹外模組而 unknown（全部或沒有：未驗證的模組可能讀了任何標頭檔，部分採用只能多判 affected，而且要限制在已驗證模組的物件，暫不做）。
    紀錄資料夾裡的 .ko 與映像的 .ko 是同一份建置，依序用：(1) .modinfo srcversion 相同；(2) srcversion 讀不到時比 ELF 區段（SHT_PROGBITS，
    排除 .debug*／.note*／.comment／.BTF*／.gnu_debuglink／.modinfo／__versions／.gnu.linkonce*）完全相同；(3) 只有 .rodata.str* 不同，而且不同的
    字串只差建置日期／時間或原始碼絕對路徑的前綴（遮罩，細節見 kernel_oot_record.py）。結果在 kernel.build_record.out_of_tree_records
    （identity 每種方式的模組數、uncovered_modules 沒驗證的模組）。
  --stable-git：linux-stable 的本機 clone（唯讀、不 fetch、clone 的設定不信任；kernel_git_files.py）。(a) 沒有 CNA 紀錄的 CVE：Grype／DT 的
    references 裡上游核心 commit（每一個都查得到才用）改的程式檔與標頭檔；(b) 有 CNA 紀錄的：紀錄裡修補 commit 在 clone 裡的，實際改的程式檔
    （這個核心有的檔案）和 programFiles 聯集（只會更保守）。找不到 commit 就照舊。結果在 kernel.stable_git。
  --mirror：kernel.org 的 CVE 紀錄（Linux 核心 CNA，vulns.git 的 cve/published/<年>/CVE-….json）；SOURCE 記 commit、
    下載時間與 zip 的 sha256。--max-age-days 預設 7（環境變數 KERNEL_CVE_MAX_AGE_DAYS；同 kernel-cve.sh --check）。
退出碼：0 已判定（OK／ATTENTION／GAP／NOT_ASSESSED／NOT_RUN）；3 輸入錯誤（同時印 FAIL 那一行，不印 traceback）。原始輸入一律不改。

為什麼：Grype／DT 以對應的 Canonical 核心（linux-nvidia-tegra 6.8.0-1021.21）比對 Jetson R39.2.1，核心有約 6,267 個 CVE，
Ubuntu 還沒修的約 3,400 個。很多是產品核心根本沒編進去的驅動（.config 沒開）。Linux 核心 CNA 的紀錄列出修補動到的檔案
（containers.cna.affected[].programFiles），產品映像的 /usr/src/linux-headers-<版本>/ 有建置用的 .config 與全部的 Makefile／Kbuild，
兩者對起來就能證明「修補的程式沒有編進核心」。

判定（只看文字，不執行 make；不確定一律 unknown）：
  每個程式檔（.c／.S／.rs → .o）的「有沒有編」＝它的 Makefile 規則（obj-$(CONFIG_X) += a.o、obj-y、lib-y、a-y／a-objs 的組合物件）
  且它所在資料夾的每一層上層規則（obj-$(CONFIG_X) += dir/、subdir-）。三值：True（一定有編；=m 算有編）／False（一定沒編）／
  None（不知道）。多條規則取 OR，同一條規則的條件取 AND（False 優先於 None）。
  - ifeq／ifdef 等條件區塊裡的規則多一個「不知道」的條件：區塊外的條件已經是 False 時仍是 False，否則最多 None。
  - 只認得 $(CONFIG_X)、$(subst m,y,$(CONFIG_X))、同一個 Makefile 定義的變數、addprefix／addsuffix／filter／patsubst；
    其他無法展開、看起來可能是物件或資料夾的項目，讓那個 Makefile 的「沒編」結論降為 None。無法解析的 include 也一樣。
  - 這個核心的 Makefile 沒有提到的物件（可能被別的 .c #include，或是 6.8 之後才加、搬過家的檔案：programFiles 是修補當時主線的路徑）
    → None，就算上層資料夾沒編也一樣（程式可能在別的位置）。只有 arch/<其他架構>/ 一律 False（根目錄只進 arch/$(SRCARCH)/）；
    arch/<其他架構>/ 底下的 Makefile／Kbuild／Kconfig（含 Makefile.*、Kconfig.*）也是 False（只有建置那個架構時才讀）。
  - 沒有規則進入的資料夾裡的 Makefile（可能只是被別處 include 的片段）不能用來證明「沒編」。
  - 標頭檔（.h）、Kconfig、Makefile、Documentation/、tools/、scripts/、其他非程式檔 → unknown（不用來宣告沒編）。
  每個 CVE：
    not_affected（justification vulnerable_code_not_present）：每一個 programFiles 都是 False（而且至少一個檔案，沒有標頭檔、
      沒有 None）；
    affected：至少一個檔案是 True；
    unknown：其他（沒有 CNA 紀錄、紀錄沒有 programFiles、含標頭檔或非程式檔、有檔案判斷不了）。
  =m（模組）一律算有編：模組可能被載入。映像的 /usr/lib/modules/<版本>/ 有沒有那個 .ko 只記在說明裡，不改判定。
  Kbuild 判沒編、映像的 modules.builtin／modules.order 卻列了那個物件（或也判沒編的組合物件）→ 那個檔案 None（清單沒有擷取到時不核對，
  limitations 註明）。每個檔案另記 built_as（kernel_module_map.py 的對應：builtin／module／null），判定不變。
  被別的檔案 #include 的 .c 依 data/kernel-included-c-<主.次版本>.json（從上游原始碼產生）一律判 unknown；
  核心的主.次版本沒有這份清單時，任何 CVE 都不判 not_affected（降成 unknown，limitations 註明）。
  已知的限制（寫在輸出的 limitations）：清單目前有 6.1 與 6.8（從公開上游 linux-6.1.118 的 git tag、linux-6.8 產生，廠商自己加的 #include 不在內）；
    .S 被另一個 .S include 的情況沒有涵蓋；NVIDIA 的 out-of-tree 模組本身的 CVE 不在範圍內（只看 Canonical／上游核心的 CVE，
    但模組目錄裡同名的 .ko 會讓判定降成 unknown）。
核心建置紀錄（--build-record，選用；sca-scan 的環境變數 KERNEL_BUILD_RECORD）：make 之後的核心建置資料夾（in-tree 或 O= 的輸出
  資料夾），或把它打包的 tar（可在一層資料夾底下，例如 kernel-noble/…；以有 .config 與 kbuild .cmd 的那一層為根）。每個出貨版本要保留：
  .config、每個 .*.cmd、modules.order、modules.builtin、System.map、include/config/kernel.release、include/generated/
  （utsversion.h、compile.h；System.map 這裡不讀，留給人查）。
  每個 .<物件>.cmd 的 source_<物件> 與 deps_<物件> 列出這個物件實際編譯的原始檔與讀到的每個檔案（標頭檔、被 #include 的 .c 都在內），
  所以能直接回答「這個檔案有沒有編進這個核心」，不必從 Makefile 推。
  不可信的資料：tar 串流讀（不解開到磁碟），只讀一般檔案；資料夾不跟隨連結（O_NOFOLLOW）；絕對路徑或含 .. 的成員不收（rejected_members），
  不需要的連結略過（ignored_links），需要的 .cmd 或清單是連結 → GAP；單一檔案 MAX_RECORD_MEMBER、合計 MAX_RECORD_TOTAL、
  tar 成員合計 MAX_RECORD_STREAM、成員數與路徑數各有上限；不合格的項目只留數量與前 MAX_RECORD_EXAMPLES 個例子；
  不執行任何東西，只解析 .cmd 的文字、modules.order／modules.builtin、kernel.release 與 .config。
  .cmd 的位置要和內容的目標一致（<根>/<資料夾>/.<名稱>.cmd 的目標是 <資料夾>/<名稱>，目標可含 .. 但正規化後要在樹內），
  archive 與 .mod 的成員清單要是 kbuild 的格式（cmd_members；成員有一個看不懂就算），而且 .cmd 要完整（cmd_complete：以換行結尾；
  編譯指令有 deps_ 與結尾的 "<目標>: $(deps_<目標>)"、"$(deps_<目標>):" 兩行；其他指令只有 savedcmd_ 一行），否則 GAP：
  被截斷的連結或 ar 指令看得到的成員只是一部分，closure 也只會要求看得到的那些。編譯與否依指令判斷（cmd_kind_ok），不依有沒有
  source_：帶依賴檔旗標、目標是 .o／.s／.lds／.dtb… 的指令卻沒有 source_（編譯的 .cmd 被截在第一行之後），或沒有 source_ 的 .o
  不是 ld／objcopy／strip → GAP。tar 沒有結尾的零區塊（剛好截在成員邊界）→ GAP。
  建置的身分（record_identity）：紀錄的 include/config/kernel.release、include/generated/utsversion.h、compile.h 和燒錄的 Image
  （刷機包的 kernel/Image，沒有時 rootfs 的 /boot/Image）的 linux_banner 逐項核對，對不上 → GAP；沒有識別檔或讀不到 banner →
  identity.result not_tied（照舊採用，limitations 與說明列註明「沒有和映像綁定」）。
  絕對路徑：source_ 推出的原始碼樹前綴（O= 建置；可以有好幾個；只認絕對路徑或只有 ../ 的前綴）去掉後對到樹；其他對不上樹的絕對路徑（in-tree 建置裡
  $(abspath …) 的路徑，例如 arm64 vDSO 的 lib/vdso/gettimeofday.c；O= 的符號連結路徑與實際路徑不同；系統標頭）不丟掉：
  任何一個這種路徑以 /<檔案> 結尾，那個檔案就算有編（只會偏向 affected；unmapped_absolute_paths 記數量，路徑本身不寫出）。
  採用前的驗證（任何一項不成立 → kernel.build_record.status GAP 與 reason，不用這份紀錄，照舊依 Makefile 判定；階段的狀態不變，說明列出原因）：
    - 紀錄的 .config 和 K1 判定用的設定（settle_config 之後：headers 的 .config 或燒錄核心的 IKCONFIG）相同，或只差工具鏈衍生的設定
      （config_diff，和 IKCONFIG 的核對同一個規則；標頭也要相同）；
    - include/config/kernel.release（有的話）等於判定的核心版本（知道版本時）；
    - 完整：有 .config、modules.order（CONFIG_MODULES 開啟時）、最後的連結（.vmlinux.cmd；kbuild 一定寫），而且至少
      MIN_RECORD_OBJECT_CMDS 個物件的 .cmd；
    - 成員都在（membership closure，record_closure）：每個 archive（built-in.a 的 printf、lib.a／vmlinux.a 的 ar）列的成員、
      每個 .mod 列的模組成員、其他沒有 source_ 的指令（連結、objcopy、strip、ld -r、vDSO 的 .so）裡每個樹內的
      *.o／*.a／*.so／*.so.dbg 與 @x.mod、最後的 vmlinux（link-vmlinux.sh：vmlinux.o、vmlinux.a、init/version-timestamp.o、
      CONFIG_MODULES 時 .vmlinux.export.o）、以 .incbin 帶進來的 vDSO（INCBIN_RULES：vdso-wrap.o ← vdso/vdso.so 等）、
      modules.order 每個模組的 .o／.mod／.ko，都要有自己的 .cmd；缺任何一個 → GAP（數量與前幾個例子）。少了某個物件的 .cmd，
      它的原始檔就會被當成「不在紀錄裡」而誤判沒編，所以不能只看數量；
    - 沒有 include/config/kernel.release、但知道核心版本：.config 完全相同（只差工具鏈也不行），而且 modules.order 與 modules.builtin 兩個都和映像的比對過
      才採用（kernel_release_checked false，limitations 註明）；比對不了 → GAP；
    - 紀錄的 modules.order／modules.builtin 和映像的相同（映像有這兩個清單時；比較時去掉 kernel/ 與副檔名）；
      映像模組目錄 kernel/ 底下有 .ko 不在紀錄的 modules.order 時**不拒收**（廠商出貨時可能另外放了模組）：照樣採用紀錄，這些模組
      另外處理（輸出 kernel.build_record.image_modules_not_in_record，每個模組記 intree 與分類）：讀模組自己的 .modinfo（純 Python 讀 ELF 區段表，
      有大小上限，支援 .ko.xz／.gz／.zst；讀不到一律當成 intree，保守）。modpost 對核心樹內編出來的模組加 intree=Y：
        2 intree（或讀不到）、Makefile 對不到：可能由任何樹內檔案編出來 → 所有沒被紀錄證明有編的樹內 .c／.S 一律 unknown（標頭檔本來就 unknown）；
        3 intree（或讀不到）、Makefile 對得到：它的組成物件的檔案 unknown；
        4 樹外（沒有 intree）、名稱對得到樹內模組（例如樹外 fork）：對應的樹內組成物件的檔案 unknown；
        5 樹外、名稱也對不到：樹外廠商模組，未評估（GAP），列出名稱、author、description、vermagic、srcversion；它的程式不是核心樹的檔案
          （CNA programFiles 不涵蓋），不做全面保護。
      intree 標記可被偽造；樹外模組的程式本身沒有漏洞比對。模組名稱進 cra_report 的待確認事項讓工程師問來源；
    - 只有一棵建置樹。
  判斷（RecordJudge；只換「這個檔案有沒有編」的來源，CVE 的規則不變：每個檔案都 False 才 not_affected，任何一個 True 就 affected）：
    - 只看樹內的原始檔（.c／.S／.rs，.lds.S 除外）與標頭檔（.h）；Documentation/、tools/、scripts/、Kconfig、Makefile 等照舊 unknown，
      其他架構的 Makefile／Kconfig 照舊 False。
    - 排除主機程式：目標在 scripts/、tools/、usr/include/（UAPI 標頭的使用者空間編譯測試），或沒有副檔名的主機程式（vmlinux 除外）。
      *.mod.o（modpost 產生、連進 .ko）算核心：它讀的標頭檔編進了出貨的模組。只多算不少算：漏排除的主機程式只會讓結果偏向 affected。
    - 在任何一個物件的 source_ 或 deps_（或對不上樹的絕對路徑以 /<檔案> 結尾）→ True（evidence「build record: compiled as <物件>」
      或「in the deps of <物件>」）；
      built_as 只在 Makefile 的規則也判有編時沿用模組對應，其他 null。
    - 都不在、Makefile 的規則判有編 → None（兩邊矛盾，unknown）。
    - 都不在、檔案在 #include 的 .c 清單（data/kernel-included-c-*.json 與 INCLUDED_C_PREFIXES）→ None：清單照舊是安全網，
      紀錄沒有證明有編就不判沒編（和沒有紀錄時一樣）；核心的主.次版本沒有清單時，有沒有紀錄都不判 not_affected。
    - 都不在、Makefile 的規則也判沒編 → False（映像的模組清單列了它 → None，同 listed_contradiction）。
    - 都不在、Makefile 判斷不了（條件區塊、看不懂的規則、標頭檔）→ 要能證明這個檔案在這個核心裡才 False：
      Makefile 的規則提到它的物件，或映像的核心樹（headers）裡有這個檔案（collect 記下 /usr/src/linux-*/ 底下的檔案名稱，不讀內容）；
      證明不了 → None（programFiles 是修補當時主線的路徑，之後才加或搬過家的程式在這個核心可能在別的位置）。
      標頭檔另外：模組目錄有 out-of-tree 模組（kernel/ 以外、或不在紀錄 modules.order 的 .ko）→ None（它們另外以核心標頭編譯，
      可能 include 這個檔案；紀錄只涵蓋 in-tree 的建置）。
  輸出：kernel.build_record（source 檔名、status、reason、root、config_sha256、config_compare、kernel_release、kernel_release_checked、
  cmd_files、object_cmd_files、host_cmd_files、closure（required、missing）、paths、unmapped_absolute_paths、source_tree_prefixes、
  rejected_members、ignored_links、out_of_tree_modules、limitations；採用時另有
  counts_without_record、decision_changes（只用 Makefile → 有紀錄）、file_judgements）；採用時每個 files[] 多一個 evidence
  （紀錄沒有判斷的檔案是 null）。沒給 --build-record 時輸出和以前逐位元組相同；給了但階段 GAP（沒有判定）→ status NOT_RUN。
狀態：沒有核心的 CVE → NOT_RUN（sca-scan 不寫這一列）；有核心 CVE 但沒有 .config／Makefile、核心版本對不上、CNA 鏡像沒有或過期、
  燒錄的核心讀不到 IKCONFIG 又無法以 dpkg 驗證 → GAP（results 為空，不改變任何發現）；headers 的 .config 和燒錄的核心不同
  （改用 IKCONFIG 判定）→ ATTENTION（讀取端只採用 OK）；其他 → OK（說明列出各判定的數量）。
"""
import argparse
import bz2
import datetime
import functools
import hashlib
import importlib.util
import io
import json
import lzma
import os
import posixpath
import re
import stat
import struct
import sys
import tarfile
import zipfile
import zlib
from pathlib import Path

STAGE = "C-kernel-config"
SCHEMA = "sca-center-kernel-config/1"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
LINUX_CNA_ORG = "f4215fc3-5b6b-47ff-a258-f7189bd81038"     # cveMetadata.assignerOrgId（kernel.org，2024-02 起的 Linux 核心 CNA）
CVE_RE = re.compile(r"CVE-(\d{4})-(\d{4,})")
MAX_FILE = 8 << 20             # 擷取的單一檔案上限（.config 約 300 KB、Makefile 都很小）
MAX_TOTAL = 256 << 20          # 擷取內容合計上限
MAX_ENTRIES = 300_000          # 擷取的檔案與連結數上限（headers 約 1.8 萬個檔案，其中 Makefile／Kbuild 約 3,100 個）
MAX_RECORD = 8 << 20           # 單筆 CNA 紀錄解壓後的上限（估計：一般最大約 1 MB）
MAX_LINK_HOPS = 40
MAX_LINK_NAMES = 10_000        # 經由資料夾連結列出的 .ko 名稱上限
MAX_SEEN = MAX_ENTRIES         # 路徑索引（連結的目標是資料夾、檔案還是不存在）的筆數上限
MAX_SRC_NAMES = 400_000        # /usr/src/linux-*/ 底下一般檔案的名稱（只記路徑，不讀內容；給建置紀錄判斷檔案在不在這個核心）上限
MODULE_EXT = (".ko", ".ko.xz", ".ko.zst", ".ko.gz")
# 燒錄的核心（刷機包的 <Linux_for_Tegra>/kernel/Image 或 rootfs 的 /boot/Image）：只在記憶體裡讀，三個上限
IMAGE_NAMES = ("Image", "Image.gz")      # 同一個資料夾兩個都有時用 Image
MAX_IMAGE = 128 << 20          # Image 檔案本身（壓縮前；arm64 的 Image 約 40–60 MB）。超過：只算 sha256，不讀 IKCONFIG
MAX_IMAGE_UNPACKED = 256 << 20  # Image 是壓縮檔（Image.gz 等）時，解壓後的上限
MAX_IKCONFIG = 8 << 20         # 解出來的 IKCONFIG（.config 約 300 KB；同 MAX_FILE）
MAX_IKCFG_MARKERS = 16         # Image 裡 IKCFG_ST 出現的次數上限（只試前幾個）
MAX_EXTLINUX = 64 << 10        # extlinux.conf 上限（通常不到 1 KB）
MAX_BOOT_PROBES = 16           # /boot 底下讀幾個 Image* 檔案（符號連結、硬連結的目標）
MAX_DPKG_STATUS = 32 << 20     # var/lib/dpkg/status（Ubuntu 約 3 MB）
MAX_DPKG_LINES = 100_000       # md5sums 留下的行數上限（只留 boot/ 與 usr/src/…/.config）
IMAGE_LIMITATIONS = [
    "EFI zboot kernel images (MZ header with 'zimg') are not unpacked: treated as having no IKCONFIG.",
    "Ubuntu's /boot/vmlinuz-* is not read; only /boot/Image (or Image.gz) and the flash package's kernel/Image are.",
    "A /boot/Image link is resolved inside the image; its target is read only if it is a regular Image* file under /boot.",
    "The dpkg check (no IKCONFIG) reads var/lib/dpkg from the same untrusted rootfs as the Image and the headers: it is a "
    "consistency check (stock packages not replaced or edited), not protection against tampering.",
]
# 工具鏈衍生的設定（名稱去掉 CONFIG_ 之後比對）：Kconfig 依編譯器、組譯器、連結器自動算出，不是產品的選擇。
# NVIDIA 的 headers 套件以 Ubuntu 的工具鏈重新產生 .config，所以原廠核心的 IKCONFIG 和 headers 會差這些（R39.2.0 實測：
# AS_VERSION、LD_VERSION、CC_VERSION_TEXT、GCC_PLUGINS）。_VERSION 只認完整的名稱，不用後綴（MODVERSIONS、LOCALVERSION、
# ARCH_*_VERSION 這類是功能性的設定，不算）。GCC_PLUGINS（編譯器支不支援 plugin）算，但 GCC_PLUGIN_*（STACKLEAK、LATENT_ENTROPY、
# RANDSTRUCT 等加固功能，開了會多編物件）不算：只差這些時要讓人看到（ATTENTION），不是 OK。
TOOLCHAIN_OPTION_NAMES = ("GCC_VERSION", "CLANG_VERSION", "AS_VERSION", "LD_VERSION", "LLD_VERSION", "GCC_PLUGINS")
TOOLCHAIN_OPTION_PREFIXES = ("CC_IS_", "CC_HAS_", "CC_CAN_", "CC_NO_", "AS_IS_", "AS_HAS_", "LD_IS_", "LD_HAS_", "TOOLCHAIN_HAS_",
                             "RUSTC_", "PAHOLE_")
TOOLCHAIN_OPTION_SUFFIXES = ("_VERSION_TEXT",)        # CC_VERSION_TEXT、BINDGEN_VERSION_TEXT、RUSTC_VERSION_TEXT
MAX_CONFIG_DIFF = 200          # kernel-config.json 列出的差異設定筆數上限
MAX_DIFF_VALUE = 200           # 每個值的長度上限（字元）
SRCARCH_OF = {"x86_64": "x86", "i386": "x86", "x86": "x86", "sparc64": "sparc", "sparc32": "sparc", "parisc64": "parisc",
              "sh64": "sh", "um": "um"}
DECISIONS = ("not_affected", "affected", "unknown")
NEW_CODE_LIMITATION = (
    "A file that is not in the shipped kernel source tree (--source-tree, complete file names, no link above it) and that no Makefile "
    "rule names is judged not built when the CNA record says the problem was introduced after this kernel's major.minor "
    "(every semver 'affected' version is later, no semver entry says this kernel is affected). Both pieces of evidence are needed; "
    "a vendor backport of the later code would have created the file in the tree.")
STABLE_GIT_LIMITATION = (
    "--stable-git (read-only local linux-stable clone, no fetch): (a) for a CVE without a CNA record, the upstream kernel commits "
    "named in the Grype/DT references are looked up in the clone, and the CVE is judged only if every referenced commit is found; "
    "(b) for a CVE with a CNA record, the files changed by the record's fix commits that the clone has (the product branch's backports) "
    "are added to programFiles (union: a file the mainline fix did not touch can only make the result more conservative). A commit "
    "that the clone does not have, a merge commit or an unusual file name is not used. The file list is that of the commit, which "
    "may not be the complete fix when the fix is split over several commits that the references do not all name.")
LIMITATIONS = [
    "C files #included by other kernel sources are never judged not_affected; the list is generated from upstream sources per "
    "kernel version (data/kernel-included-c-<major.minor>.json; currently 6.1 and 6.8) and does not include vendor-added #include "
    "of .c files. Without a list for the kernel's major.minor version no CVE is judged not_affected.",
    "Assembly files (.S) #included by another .S file are not covered by the list.",
    "Conditional Makefile sections (ifeq/ifdef) are treated as unknown; they can only turn 'affected' into 'unknown', never into 'not_affected'.",
    "=m counts as built (the module may be loaded); module presence in /usr/lib/modules is recorded as evidence only.",
    "Only the Canonical/upstream kernel CVEs on the kernel component are in scope; NVIDIA out-of-tree modules are not.",
    "A member left out of a built composite module by its own config is not built, but the image's module lists name only "
    "the composite: whether that member is really absent from the built module cannot be checked against the lists (only "
    "that the composite itself matches them).",
    "A docker layer whose opaque whiteout for the kernel version directory comes after files at the same level is treated "
    "as deleting the whole version directory, so the stage is GAP (conservative, never a wrong result).",
    "programFiles are taken from the mainline fix. If an older stable branch has the same code in a different file (for example "
    "mainline moved the code to a new file while the fix in the older branch changed the old file), the stable branch's file is "
    "not in programFiles and the CVE can be judged not built when it is. No file comparison with the stable-branch fix (backport) "
    "is done.",
]


class InputError(Exception):
    pass


def line(st, detail):
    print(f"{STAGE}\t{st}\t" + re.sub(r"[\t\r\n]+", " ", str(detail))[:900])


def _load(name, path):
    """python3 -I 不把這個資料夾放進 sys.path，所以依路徑載入同一份程式（不複製）。"""
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m
    except Exception as e:
        raise InputError(f"無法載入 {path}（{type(e).__name__}）")


@functools.lru_cache(maxsize=None)
def kernelcheck():
    return _load("sca_center_kernelcheck", HERE / "kernelcheck.py")


@functools.lru_cache(maxsize=None)
def kernel_git_files():
    return _load("sca_center_kernel_git_files", HERE / "kernel_git_files.py")


@functools.lru_cache(maxsize=None)
def kernel_cna_version():
    return _load("sca_center_kernel_cna_version", HERE / "kernel_cna_version.py")


def kernel_base_tuple(ver):
    """核心版本字串（6.8.12、6.1.118-xxx）→ (主, 次, 修) 或 None。"""
    m = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?", str(ver or ""))
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0), 0) if m else None


@functools.lru_cache(maxsize=None)
def kernel_oot_record():
    return _load("sca_center_kernel_oot_record", HERE / "kernel_oot_record.py")


@functools.lru_cache(maxsize=None)
def flash_package():
    return _load("sca_center_flash_package", ROOT / "tools" / "demo" / "flash_package.py")


def load_json(path, label):
    if not path:
        return None
    try:
        with (lzma.open(path, "rt", encoding="utf-8") if str(path).endswith(".xz") else open(path, encoding="utf-8-sig")) as f:
            return json.load(f)
    except (OSError, ValueError, lzma.LZMAError, RecursionError) as e:
        raise InputError(f"{label} 無法讀取（{path}：{type(e).__name__}）")


# =====================================================================================================
# 1. 從 rootfs／映像／刷機包擷取建置資訊（只在記憶體裡）
# =====================================================================================================

def split_name(name):
    """tar 成員名稱 → 路徑元件；絕對路徑或含 .. → None（同 flash_package.split_name）。"""
    if name.startswith("/"):
        name = name.lstrip("/")         # docker 層的名稱不會是絕對路徑；rootfs tar 有時是。以 rootfs 為根看待
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        return None
    return tuple(parts)


def build_name(n):
    return n in (".config",) or n.startswith(("Makefile", "Kbuild")) or n.endswith(".mk")


class Collected:
    """擷取的內容（rootfs 相對路徑 → 內容或連結目標）。模組目錄：{版本: {"ko": set, "files": {名稱: bytes}, "build": 連結目標}}。"""

    def __init__(self):
        self.files, self.links, self.layer = {}, {}, {}
        self.modules = {}
        self.other_ko = {}             # 模組目錄以外的 .ko（rootfs 相對路徑 → 層）：模組目錄裡的資料夾連結指到外面時用
        # 映像裡看過的路徑（只給模組目錄裡的連結判斷目標是資料夾、檔案、連結還是不存在）：資料夾存字串，檔案與連結只存雜湊
        self.seen_dirs, self.seen_files, self.seen_links = set(), set(), set()
        self.other_links = set()       # 模組目錄以外的符號連結（路徑字串）：資料夾連結的目標底下有連結時記 gap
        self.seen_count, self.seen_overflow = 0, False     # 路徑索引的筆數；超過 MAX_ENTRIES 就停止記，需要索引的判斷一律 gap
        self.bytes = self.entries = self.skipped_large = 0
        self.notes = []
        # /usr/src/linux-*/ 底下的一般檔案名稱（路徑 → 層；不讀內容）：建置紀錄（--build-record）判「沒編」前，確認這個檔案在這個核心裡
        self.src_names, self.src_overflow = {}, False
        # 燒錄的核心（只有 collect(images=True) 時讀；kernel_module_map.py、kernel_modules.py 不讀）
        self.want_images, self.pkg_root = False, None
        self.want_modinfo = False      # 模組的 .modinfo（intree、author…）：建置紀錄比對多出的模組時才讀（--build-record）
        self.boot = {}                 # rootfs 的 /boot 底下：路徑 → (層, "probe"／"symlink"／"hardlink", ImageProbe／連結目標)
        self.dpkg = {}                 # var/lib/dpkg/status 與 info/*.md5sums：路徑 → (層, 內容)（md5sums 只留 boot/ 與 .config 的行）
        self.boot_probes = 0
        self.pkg_images = {}           # 刷機包的 <pkg_root>/kernel/<名稱>：名稱 → ImageProbe
        self.extlinux = None           # rootfs 的 /boot/extlinux/extlinux.conf 原始位元組（最多 MAX_EXTLINUX；C-kernel-boot 用，不影響判定）
        self.extlinux_reason = None    # 有這個路徑但沒讀到（連結、太大）的原因

    # ---- 寫入 ----
    def _room(self, size):
        if self.entries >= MAX_ENTRIES or self.bytes + size > MAX_TOTAL:
            raise InputError(f"擷取的內容超過上限（{MAX_ENTRIES} 個或 {MAX_TOTAL >> 20} MB），不像核心 headers")

    def note(self, parts, kind):
        """記下映像裡有這個路徑（資料夾、檔案或連結；上層資料夾一併算資料夾）。超過 MAX_SEEN（＝MAX_ENTRIES）筆 → seen_overflow。"""
        if self.seen_overflow:
            return
        self.seen_count += 1
        if self.seen_count > MAX_SEEN:
            self.seen_overflow = True
            return
        if kind == "symlink" and not modules_part(parts):
            self.other_links.add("/".join(parts))
        for i in range(1, len(parts)):
            self.seen_dirs.add("/".join(parts[:i]))
        p = "/".join(parts)
        if kind == "dir":
            self.seen_dirs.add(p)
        elif kind == "symlink":
            self.seen_links.add(hash(p))
        else:
            self.seen_files.add(hash(p))

    def src_name(self, parts, layer=0):
        """記下 /usr/src/linux-*/ 底下的一般檔案（只記路徑）。超過 MAX_SRC_NAMES → src_overflow（之後一律當成不知道檔案在不在）。"""
        if self.src_overflow or len(parts) < 4 or parts[:2] != ("usr", "src") or not parts[2].startswith("linux-"):
            return
        if len(self.src_names) >= MAX_SRC_NAMES and parts not in self.src_names:
            self.src_overflow = True
            self.src_names.clear()
            return
        self.src_names[parts] = layer

    def feed(self, parts, kind, link=None, opener=None, size=0, layer=0):
        """一個項目（parts 是 rootfs 相對路徑）。只留需要的。"""
        if not parts:
            return
        self.note(parts, kind)
        if self.want_images and parts == ("boot", "extlinux", "extlinux.conf"):
            if kind == "file" and size <= MAX_EXTLINUX:
                self.extlinux = read_all(opener, size)
            else:
                self.extlinux_reason = f"extlinux.conf is not a regular file under the size limit ({kind}, {size} bytes); not read"
            return
        if self.want_images and len(parts) >= 2 and parts[0] == "boot":
            if kind == "symlink":
                self.boot[parts] = (layer, "symlink", link)      # 只記目標（在映像裡解開，見 boot_image）
                return
            if parts[-1].startswith("Image"):
                if kind == "file" and self.boot_probes >= MAX_BOOT_PROBES:
                    rec = ImageProbe("/" + "/".join(parts), reason=f"more than {MAX_BOOT_PROBES} Image* files under /boot: not read")
                else:
                    self.boot_probes += kind == "file"
                    rec = probe_entry("/" + "/".join(parts), kind, opener, size)
                self.boot[parts] = (layer, "probe", rec)
                return
        if self.want_images and len(parts) >= 4 and parts[:3] == ("var", "lib", "dpkg") and kind == "file":
            if parts[3:] == ("status",):
                self.dpkg[parts] = (layer, read_all(opener, size) if size <= MAX_DPKG_STATUS else None)
                return
            if len(parts) == 5 and parts[3] == "info" and parts[4].endswith(".md5sums"):
                self.dpkg[parts] = (layer, md5sums_lines(read_all(opener, size)) if size <= MAX_FILE else None)
                return
        mod = modules_part(parts)
        if mod:
            ver, rest = mod
            m = self.modules.setdefault(ver, {"ko": set(), "files": {}, "build": None, "layer": layer, "ko_layer": {},
                                              "ko_links": {}, "files_layer": {}, "dir_links": {}, "present_gaps": []})
            r = "/".join(rest)
            if kind == "file" and rest and rest[-1].endswith(MODULE_EXT):
                if self.want_modinfo:
                    m.setdefault("modinfo", {})[r] = read_modinfo(opener, size, rest[-1], sections=module_ko_key(r) is None)
                m["ko"].add(r)
                m["ko_layer"][r] = layer
                m["ko_links"].pop(r, None)
            elif kind == "symlink" and rest and rest[-1].endswith(MODULE_EXT):
                # 連到 .ko 的符號連結：以連結的名稱算（locate 時在映像裡解開，見 resolve_ko_links）
                m["ko_links"][r] = (link, layer, parts)
                m["ko"].discard(r)
            elif kind == "file" and len(rest) == 1 and rest[0] in ("modules.builtin", "modules.order") and size <= MAX_FILE:
                self._room(size)
                m["files"][rest[0]] = read_all(opener, size)
                m["files_layer"][rest[0]] = layer
                self.bytes += size
            elif kind == "symlink" and rest == ("build",):
                m["build"] = link
            elif kind == "symlink" and rest and rest != ("source",) and not rest[-1].startswith("modules."):
                m["dir_links"][r] = (link, layer, parts)      # 可能是資料夾的連結（updates -> /opt/…）：locate 時列出底下的 .ko
            return
        if kind == "file" and parts[-1].endswith(MODULE_EXT):
            self.other_ko[parts] = layer
        if len(parts) >= 3 and parts[0] == "usr" and parts[1] == "src" and parts[2].startswith("linux-"):
            if kind == "file":
                self.src_name(parts, layer)
            else:
                self.src_names.pop(parts, None)
            if kind == "symlink":
                self._room(0)
                self.files.pop(parts, None)
                self.links[parts] = link
                self.layer[parts] = layer
                self.entries += 1
            elif kind == "file" and build_name(parts[-1]):
                if size > MAX_FILE:
                    self.skipped_large += 1
                    return
                self._room(size)
                self.links.pop(parts, None)
                self.files[parts] = read_all(opener, size)
                self.layer[parts] = layer
                self.bytes += size
                self.entries += 1
            elif kind in ("file", "dir"):
                # 上層的檔案或資料夾蓋過下層同名的連結（docker 層）
                if parts in self.links and self.layer.get(parts, -1) < layer:
                    del self.links[parts]
        elif parts == ("lib",) and kind == "symlink":
            self.links[parts] = link      # merged-usr：lib -> usr/lib

    def whiteout(self, parts, layer, opaque=False):
        """docker 層的 whiteout：.wh.<名稱> 刪掉下層的那個路徑（含底下）；.wh..wh..opq 刪掉下層在這個資料夾底下的全部。"""
        n = len(parts)
        for d in (self.boot, self.dpkg):
            for k in [k for k, v in d.items() if k[:n] == parts and (len(k) > n or not opaque) and v[0] < layer]:
                del d[k]
        for k in [k for k, ly in self.other_ko.items() if k[:n] == parts and (len(k) > n or not opaque) and ly < layer]:
            del self.other_ko[k]
        for k in [k for k, ly in self.src_names.items() if k[:n] == parts and (len(k) > n or not opaque) and ly < layer]:
            del self.src_names[k]
        for d in (self.files, self.links):
            for k in [k for k in d if k[:n] == parts and (len(k) > n or not opaque) and self.layer.get(k, 0) < layer]:
                del d[k]
        mp = modules_part(parts)
        if mp and mp[1] and mp[0] in self.modules:
            # 模組目錄裡的單一檔案或資料夾（OCI layer：.wh.<名稱> 刪掉下層的那個路徑與底下；.wh..wh..opq 刪掉下層在這個資料夾底下的全部）
            m, r = self.modules[mp[0]], "/".join(mp[1])
            hit = (lambda k: k.startswith(r + "/")) if opaque else (lambda k: k == r or k.startswith(r + "/"))
            for k in [k for k in m["ko"] if hit(k) and m["ko_layer"].get(k, 0) < layer]:
                m["ko"].discard(k)
                m["ko_layer"].pop(k, None)
            for k in [k for k, v in m["ko_links"].items() if hit(k) and v[1] < layer]:
                del m["ko_links"][k]
            for k in [k for k, v in m["dir_links"].items() if hit(k) and v[1] < layer]:
                del m["dir_links"][k]
            for k in [k for k in m["files"] if hit(k) and m["files_layer"].get(k, 0) < layer]:
                del m["files"][k]
            if not opaque and mp[1] == ("build",):
                m["build"] = None
            return
        if parts in (("lib", "modules"), ("usr", "lib", "modules")):
            for v in [v for v, m in self.modules.items() if m["layer"] < layer]:
                del self.modules[v]
            return
        mod = modules_part(parts + ("x",))
        if mod and mod[1] == ("x",) and self.modules.get(mod[0], {}).get("layer", layer) < layer:
            del self.modules[mod[0]]


class ImageCollected(Collected):
    """collect(images=True) 用：另外收刷機包裡 rootfs 以外的 <pkg_root>/kernel/Image（feed_tar 的 outside 鉤子）。
    基本的 Collected 沒有這個鉤子（kernel_module_map.py、kernel_modules.py 的讀法不變）。"""

    def outside(self, parts, kind, opener, size):
        if (self.want_images and self.pkg_root is not None and len(parts) == len(self.pkg_root) + 2
                and parts[:len(self.pkg_root)] == self.pkg_root and parts[-2] == "kernel" and parts[-1] in IMAGE_NAMES):
            self.pkg_images[parts[-1]] = probe_entry("/".join(parts), kind, opener, size)


MAX_KO_FILE = 256 << 20          # 讀 .modinfo 的 .ko（壓縮檔是壓縮後的大小）上限；超過 → 讀不到（保守）
MAX_KO_UNPACKED = 256 << 20      # .ko.xz／.gz／.zst 解壓後的上限
MAX_MODINFO = 1 << 20            # .modinfo 區段上限
MAX_ELF_SECTIONS = 4096
MODINFO_KEYS = ("intree", "name", "author", "description", "license", "vermagic", "srcversion")
KO_COMPRESSION = ((".ko.xz", "xz"), (".ko.gz", "gzip"), (".ko.zst", "zstd"))


def parse_ko_modinfo(data):
    """.ko（解壓後的 ELF 位元組，不可信）→ {"ok": True, "intree": "Y"|None, 欄位…} 或 {"ok": False, "reason": …}。純 Python 讀 ELF 的區段表，
    找 .modinfo；只讀區段表與那一個區段，全部有邊界檢查。modpost 對核心樹內編出來的模組加 intree=Y（外部編的沒有）。"""
    try:
        if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] not in (1, 2) or data[5] not in (1, 2):
            return {"ok": False, "reason": "not an ELF file"}
        e = "<" if data[5] == 1 else ">"
        if data[4] == 2:
            shoff, shentsize, shnum, shstrndx = struct.unpack_from(e + "Q", data, 0x28)[0], *struct.unpack_from(e + "HHH", data, 0x3A)
            f_off, f_size, f_end = 0x18, 0x20, 0x28
            fmt_off, fmt_size = "Q", "Q"
        else:
            shoff, shentsize, shnum, shstrndx = struct.unpack_from(e + "I", data, 0x20)[0], *struct.unpack_from(e + "HHH", data, 0x2E)
            f_off, f_size, f_end = 0x10, 0x14, 0x18
            fmt_off, fmt_size = "I", "I"
        if not (0 < shnum <= MAX_ELF_SECTIONS and shentsize >= f_end and shstrndx < shnum and shoff + shnum * shentsize <= len(data)):
            return {"ok": False, "reason": "ELF section table is missing or out of range"}

        def sec(i):
            b = shoff + i * shentsize
            return (struct.unpack_from(e + "I", data, b)[0], struct.unpack_from(e + fmt_off, data, b + f_off)[0],
                    struct.unpack_from(e + fmt_size, data, b + f_size)[0])
        _, so, ss = sec(shstrndx)
        if so + ss > len(data) or ss > MAX_MODINFO * 4:
            return {"ok": False, "reason": "ELF section name table is out of range"}
        names = data[so:so + ss]
        for i in range(shnum):
            nm, off, size = sec(i)
            if nm < len(names) and names[nm:names.find(b"\0", nm)] == b".modinfo":
                if size > MAX_MODINFO or off + size > len(data):
                    return {"ok": False, "reason": ".modinfo section is out of range or larger than the limit"}
                got, authors = {"ok": True, "intree": None}, []
                for item in data[off:off + size].split(b"\0"):
                    k, sep, v = item.partition(b"=")
                    k = k.decode("ascii", "replace")
                    if not sep or k not in MODINFO_KEYS:
                        continue
                    v = v.decode("utf-8", "replace")[:200]
                    if k == "author":
                        authors.append(v)
                    elif k == "intree":
                        got["intree"] = "Y" if v == "Y" else got["intree"]
                    else:
                        got.setdefault(k, v)
                if authors:
                    got["author"] = "; ".join(authors[:3])
                return got
        return {"ok": False, "reason": "no .modinfo section"}
    except (struct.error, ValueError, IndexError) as ex:
        return {"ok": False, "reason": f"ELF cannot be parsed ({type(ex).__name__})"}


def read_modinfo(opener, size, name, sections=False):
    """模組檔（.ko、.ko.xz、.ko.gz、.ko.zst）→ parse_ko_modinfo 的結果；太大、壓縮格式不支援、解壓失敗 → {"ok": False, "reason"}（呼叫端保守處理）。"""
    try:
        if size > MAX_KO_FILE:
            return {"ok": False, "reason": f"module file larger than {MAX_KO_FILE >> 20} MB (limit)"}
        data = read_all(opener, size)
        for ext, fmt in KO_COMPRESSION:
            if name.endswith(ext):
                data, why = bounded_unpack(fmt, data, MAX_KO_UNPACKED)
                if data is None:
                    return {"ok": False, "reason": why}
                break
        got = parse_ko_modinfo(data)
        if sections:        # 樹外模組沒有 srcversion 時的 ELF 區段比對（kernel_oot_record.ko_sections）
            got["elf"] = kernel_oot_record().ko_sections(data)
        return got
    except Exception as ex:     # noqa: BLE001 — 不可信輸入：任何失敗都只是「讀不到」
        return {"ok": False, "reason": f"module cannot be read ({type(ex).__name__})"}


def modules_part(parts):
    """(lib|usr/lib)/modules/<版本>/… → (版本, 其餘元件)；不是 → None。"""
    if len(parts) >= 4 and parts[0] == "lib" and parts[1] == "modules":
        return parts[2], parts[3:]
    if len(parts) >= 5 and parts[:3] == ("usr", "lib", "modules"):
        return parts[3], parts[4:]
    return None


def read_all(opener, size):
    if opener is None:
        return b""
    f = opener()
    try:
        data = f.read(size + 1)
    finally:
        try:
            f.close()
        except Exception:
            pass
    if len(data) > size and size >= 0:
        data = data[:size]
    return data


def tar_kind(m):
    return "file" if m.isreg() else "dir" if m.isdir() else "symlink" if m.issym() else "hardlink" if m.islnk() else "other"


def feed_tar(col, t, layer=0, strip=None):
    """tarfile → Collected。strip：只要這個前綴底下的成員（刷機包的 rootfs），去掉前綴。"""
    while True:
        m = t.next()
        if m is None:
            break
        t.members.clear()                 # 記憶體不隨成員數增加（同 flash_package.members）
        parts = split_name(m.name)
        if parts is None:
            continue
        if strip is not None:
            if parts[:len(strip)] != strip:
                if hasattr(col, "outside"):        # 刷機包裡 rootfs 以外的成員（kernel_modules.py 讀 bootloader/l4t_initrd.img）
                    col.outside(parts, tar_kind(m), (lambda m=m: t.extractfile(m)) if m.isreg() else None, m.size if m.isreg() else 0)
                continue
            parts = parts[len(strip):]
        base = parts[-1] if parts else ""
        if layer and base.startswith(".wh."):
            if base == ".wh..wh..opq":
                col.whiteout(parts[:-1], layer, opaque=True)
            else:
                col.whiteout(parts[:-1] + (base[4:],), layer)
            continue
        k = tar_kind(m)
        if k == "hardlink":
            # 硬連結：目標必須是之前出現、也被留下的檔案；需要的檔案不太可能是硬連結，先找已擷取的內容
            tp = split_name(m.linkname)
            if tp is not None and strip is not None:
                tp = tp[len(strip):] if tp[:len(strip)] == strip else None
            if hasattr(col, "hardlink"):           # 呼叫端自己處理（kernel_modules.py：目標沒有收內容的也要記）
                col.hardlink(parts, tp, layer)
                continue
            if getattr(col, "want_images", False) and len(parts) >= 2 and parts[0] == "boot":
                col.note(parts, "file")
                col.boot[parts] = (layer, "hardlink", tp)          # /boot/Image 的硬連結：在映像裡解開（見 boot_image）
                continue
            if parts and parts[-1].endswith(MODULE_EXT):
                col.feed(parts, "file", layer=layer)            # 硬連結的 .ko（模組目錄內外）：以連結的名稱算（只記名稱，不讀內容）
                continue
            col.note(parts, "file")
            if hasattr(col, "src_name"):
                col.src_name(parts, layer)
            data = col.files.get(tp) if tp is not None else None
            tm = modules_part(tp) if tp is not None else None
            if data is None and tm and len(tm[1]) == 1:
                data = col.modules.get(tm[0], {}).get("files", {}).get(tm[1][0])     # modules.order／modules.builtin 的硬連結
            if data is not None:
                col.feed(parts, "file", opener=lambda d=data: io.BytesIO(d), size=len(data), layer=layer)
            continue
        col.feed(parts, k, link=m.linkname if k == "symlink" else None,
                 opener=(lambda m=m: t.extractfile(m)) if k == "file" else None, size=m.size if k == "file" else 0, layer=layer)


def open_layer(outer, name, hops=0):
    """docker save 的層（可能是連結到 blobs/sha256/… 的成員）→ (TarFile, 說明)。未壓縮的層用隨機存取（跳過內容，不讀）。"""
    try:
        m = outer.getmember(name)
    except KeyError:
        raise InputError(f"docker save 的 tar 沒有 manifest 列的層 {name}")
    if m.issym() and hops < 5:
        return open_layer(outer, posixpath.normpath(posixpath.join(posixpath.dirname(name), m.linkname)), hops + 1)
    if not m.isreg():
        raise InputError(f"docker save 的層 {name} 不是一般檔案")
    f = outer.extractfile(m)
    head = f.read(4)
    f.seek(0)
    if head[:2] == b"\x1f\x8b":
        return tarfile.open(fileobj=f, mode="r|gz"), "gzip"
    if head == b"\x28\xb5\x2f\xfd":
        try:
            from compression import zstd        # Python 3.14 起
        except ImportError:
            raise InputError(f"層 {name} 是 zstd 壓縮，這個 Python 沒有 compression.zstd")
        return tarfile.open(fileobj=zstd.ZstdFile(f), mode="r|"), "zstd"
    return tarfile.open(fileobj=f, mode="r:"), "tar"


DOCKER_SAVE_NAME = re.compile(r"^(manifest\.json|index\.json|oci-layout|repositories|[0-9a-f]{64}\.json|[0-9a-f]{64}(/(layer\.tar|json|VERSION))?"
                              r"|blobs(/sha256(/[0-9a-f]{64})?)?)/?$")


def docker_manifest(path):
    """未壓縮的 tar、成員都是 docker save 的名稱（manifest.json、blobs/sha256/…）→ 層的清單（由下而上）；不是 → None。
    看到第一個不是 docker save 的成員就停（rootfs tar 不會讀完整個成員清單）。"""
    try:
        t = tarfile.open(path, mode="r:")
    except (tarfile.TarError, OSError):
        return None
    try:
        m, n = None, 0
        while True:
            x = t.next()
            if x is None:
                break
            n += 1
            name = x.name[2:] if x.name.startswith("./") else x.name
            if not DOCKER_SAVE_NAME.match(name) or n > 10000:
                return None
            if name == "manifest.json":
                m = x
        if m is None or not m.isreg() or m.size > (16 << 20):
            return None
        doc = json.loads(t.extractfile(m).read())
        layers = doc[0].get("Layers") if isinstance(doc, list) and doc and isinstance(doc[0], dict) else None
        return [x for x in layers if isinstance(x, str)] if isinstance(layers, list) and layers else None
    except (ValueError, tarfile.TarError, OSError):
        return None
    finally:
        t.close()


def collect(src, prefix=None, col=None, images=False, modinfo=False):
    """--from → (Collected, 來源說明)。col：呼叫端自己的 Collected 子類別（tools/cra/kernel_modules.py 用同一套讀法、留不同的檔案）。
    images：另外讀燒錄的核心（rootfs 的 /boot/Image；有 --prefix 時再加刷機包的 <prefix 的上一層>/kernel/Image），只給 C-kernel-config。"""
    col = (ImageCollected() if images else Collected()) if col is None else col
    strip = split_name(prefix) if prefix else None
    if prefix and not strip:
        raise InputError(f"--prefix 不合法：{prefix}")
    col.want_images = bool(images)
    col.want_modinfo = bool(modinfo)
    col.pkg_root = tuple(strip[:-1]) if strip else None
    if os.path.isdir(src):
        if strip is None and is_tree(src):
            return None, {"type": "dir", "label": "dir", "path": os.path.abspath(src), "tree": True}
        fp = flash_package()
        base = os.path.join(src, *strip) if strip else src
        if not os.path.isdir(base):
            raise InputError(f"資料夾裡沒有 {prefix}")
        for e in fp.dir_entries(base):
            if e.parts is None or e.kind not in ("file", "dir", "symlink"):
                if hasattr(col, "unreadable"):     # 讀不到的資料夾、檔案、裝置檔等（kernel_modules.py 要知道哪裡沒看到）
                    col.unreadable(e.parts, e.kind, e.raw)
                continue
            col.feed(e.parts, e.kind, link=e.link if e.kind == "symlink" else None, opener=e.open if e.kind == "file" else None,
                     size=e.size)
        if col.want_images and strip:
            for n in IMAGE_NAMES:
                got = probe_dir_file(src, col.pkg_root + ("kernel", n))
                if got is not None:
                    col.pkg_images[n] = got
        return col, {"type": "dir", "label": "dir", "path": os.path.abspath(src) + (f"（{prefix}）" if prefix else "")}
    if not os.path.isfile(src):
        raise InputError(f"--from 不是檔案也不是資料夾：{src}")
    layers = None if strip else docker_manifest(src)
    if layers:
        with tarfile.open(src, mode="r:") as outer:
            kinds = []
            for i, name in enumerate(layers, 1):
                lt, kind = open_layer(outer, name)
                kinds.append(kind)
                with lt:
                    feed_tar(col, lt, layer=i)
        return col, {"type": "docker-save", "label": "docker image", "file": os.path.basename(src), "layers": len(layers)}
    if strip is not None:
        # 刷機包（tbz2）＋前綴：沿用 flash_package.py 的串流讀法（lbzip2／pbzip2 多執行緒解壓，只讀 tar 結構）
        fp = flash_package()
        try:
            with fp.open_stream(src) as t:
                feed_tar(col, t, strip=strip)
        except fp.Fail as e:
            raise InputError(str(e))
        return col, {"type": "archive", "label": "archive", "file": os.path.basename(src), "prefix": "/".join(strip)}
    try:
        with open(src, "rb") as f:
            magic = f.read(262)
    except OSError as e:
        raise InputError(f"讀不到 {src}（{e.strerror}）")
    try:
        if magic[257:262] == b"ustar":
            with tarfile.open(src, mode="r:") as t:            # 未壓縮：隨機存取，跳過內容不讀
                feed_tar(col, t)
        else:
            fp = flash_package()
            with fp.open_stream(src) as t:
                feed_tar(col, t)
    except (tarfile.TarError, EOFError) as e:
        raise InputError(f"{os.path.basename(src)} 不是可讀的 tar（{type(e).__name__}）")
    return col, {"type": "rootfs-tar", "label": "rootfs tar", "file": os.path.basename(src)}


def is_tree(d):
    return all(os.path.isfile(os.path.join(d, n)) for n in (".config", "Makefile")) and os.path.isfile(os.path.join(d, "Kbuild"))


def collect_tree(tree):
    """核心原始碼樹的資料夾（--makefiles-dir，或 --from 指到樹本身）→ Collected，樹放在虛擬路徑 usr/src/linux-tree。不跟隨連結。"""
    col = Collected()
    root = os.path.abspath(tree)
    base = ("usr", "src", "linux-tree")
    for d, dirs, files in os.walk(root, followlinks=False):
        rel = os.path.relpath(d, root)
        rp = () if rel == "." else tuple(rel.split(os.sep))
        for n in dirs + files:
            p = os.path.join(d, n)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            parts = base + rp + (n,)
            if stat.S_ISLNK(st.st_mode):
                col.feed(parts, "symlink", link=os.readlink(p))
            elif stat.S_ISREG(st.st_mode) and build_name(n):
                col.feed(parts, "file", opener=lambda p=p: open(p, "rb"), size=st.st_size)
            elif stat.S_ISREG(st.st_mode):
                col.src_name(parts)              # 只記名稱（建置紀錄判斷檔案在不在這個核心）
        dirs[:] = [x for x in dirs if not os.path.islink(os.path.join(d, x)) and x != ".git"]
    return col, base


# ---------- 燒錄的核心（kernel/Image）的內建設定（IKCONFIG） ----------
# CONFIG_IKCONFIG=y 的核心把建置用的 .config 以 gzip 放在 Image 裡，前後是 "IKCFG_ST" 與 "IKCFG_ED"（kernel/configs.c）；
# 讀法同 Linux 原始碼的 scripts/extract-ikconfig：先在 Image 裡找，找不到時把整個 Image 當成壓縮檔解開再找。
# 不可信的資料：只讀、只在記憶體裡解析，Image、解壓後的 Image、解出來的 config 各有上限；超過或格式不對只記原因，不中斷。

IKCFG_ST, IKCFG_ED = b"IKCFG_ST", b"IKCFG_ED"
GZIP_MAGIC = b"\x1f\x8b\x08"


class ImageProbe:
    """一個 Image 檔案的讀取結果。config：解出來的 IKCONFIG（bytes）或 None（reason 寫原因）；complete：IKCONFIG 是否完整
    （gzip 每一段都解完，而且 IKCFG_ED 緊接在最後一段之後）；link_target：/boot/Image 是連結時，在映像裡解開後的路徑。"""
    __slots__ = ("path", "kind", "size", "sha256", "md5", "format", "config", "complete", "reason", "link_target", "unpacked_md5",
                 "banner")

    def __init__(self, path, kind="file", size=None, sha256=None, fmt=None, config=None, reason=None, md5=None, complete=None):
        self.path, self.kind, self.size, self.sha256, self.md5 = path, kind, size, sha256, md5
        self.format, self.config, self.complete, self.reason, self.link_target = fmt, config, complete, reason, None
        self.unpacked_md5 = None              # Image 本身是壓縮檔（Image.gz 等）時，解壓後的 md5（和 dpkg 記的 /boot/Image 比）
        self.banner = None                    # linux_banner（"Linux version <release> (<by>@<host>) (<compiler>) <version>"；建置紀錄核對用）

    def json(self):
        return {"path": self.path, "link_target": self.link_target, "bytes": self.size, "sha256": self.sha256, "md5": self.md5,
                "unpacked_md5": self.unpacked_md5, "format": self.format, "ikconfig": self.config is not None,
                "ikconfig_complete": bool(self.complete) if self.config is not None else None,
                "ikconfig_sha256": hashlib.sha256(self.config).hexdigest() if self.config is not None else None,
                "reason": self.reason}


def bounded_unpack(fmt, data, cap):
    """壓縮資料 → (bytes, None) 或 (None, 原因)。輸出超過 cap 就停（不會先全部解開）；資料不完整也算失敗。"""
    try:
        if fmt == "gzip":
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        elif fmt in ("xz", "lzma"):
            d = lzma.LZMADecompressor(format=lzma.FORMAT_XZ if fmt == "xz" else lzma.FORMAT_ALONE)
        elif fmt == "bzip2":
            d = bz2.BZ2Decompressor()
        elif fmt == "zstd":
            try:
                from compression import zstd        # Python 3.14 起
            except ImportError:
                return None, "zstd-compressed, and this Python has no compression.zstd"
            d = zstd.ZstdDecompressor()
        else:
            return None, f"unsupported compression {fmt}"
        out = d.decompress(data, cap + 1) if fmt == "gzip" else d.decompress(data, max_length=cap + 1)
    except (zlib.error, lzma.LZMAError, OSError, EOFError, ValueError, MemoryError) as e:
        return None, f"{fmt} data cannot be decompressed ({type(e).__name__})"
    except Exception as e:                  # zstd 的 ZstdError 等
        return None, f"{fmt} data cannot be decompressed ({type(e).__name__})"
    if len(out) > cap:
        return None, f"{fmt} data decompresses to more than {cap >> 20} MB (limit)"
    if not d.eof:
        return None, f"{fmt} data is truncated"
    return out, None


def gunzip_members(mv, cap):
    """IKCFG_ST 之後的資料 → (內容, 完整與否, 原因)。同 zcat：一段 gzip 解完、後面緊接著另一段 gzip 就接著解。
    第一段解不開 → (None, False, 原因)；後面的段解不開或被截斷 → (已解出的部分, False, 原因)。完整：每一段都解完，而且最後一段之後
    沒有剩下的資料（呼叫端只給到 IKCFG_ED 為止）。"""
    out, off, n = bytearray(), 0, 0
    while True:
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            chunk = d.decompress(mv[off:], cap + 1 - len(out))
        except zlib.error as e:
            return (None, False, f"gzip data cannot be decompressed ({type(e).__name__})") if n == 0 else \
                (bytes(out), False, f"gzip member {n + 1} cannot be decompressed")
        out += chunk
        if len(out) > cap:
            return None, False, f"gzip data decompresses to more than {cap >> 20} MB (limit)"
        if not d.eof:
            return (None, False, "gzip data is truncated") if n == 0 else (bytes(out), False, f"gzip member {n + 1} is truncated")
        n += 1
        rest = d.unused_data
        off = len(mv) - len(rest)
        if rest[:2] != b"\x1f\x8b":
            if rest:
                return bytes(out), False, f"{len(rest)} byte(s) after the gzip data are not followed by IKCFG_ED"
            return bytes(out), True, None


def find_ikconfig(data):
    """Image（未壓縮）→ (config bytes, 完整與否, None)；沒有 IKCFG_ST → (None, None, None)；有標記但解不出來 → (None, False, 原因)。
    同 extract-ikconfig：找 IKCFG_ST 後面緊接 gzip 標頭的位置，gzip 解到結尾為止（多段 gzip 同 zcat 全部解開）；IKCFG_ED 緊接在 gzip 之後。"""
    pos, tried, why = 0, 0, None
    while tried < MAX_IKCFG_MARKERS:
        i = data.find(IKCFG_ST, pos)
        if i < 0:
            break
        pos = i + 1
        start = i + len(IKCFG_ST)
        if data[start:start + 3] != GZIP_MAGIC:
            continue
        tried += 1
        end = data.find(IKCFG_ED, start)
        cfg, complete, err = gunzip_members(memoryview(data)[start:end if end > 0 else len(data)], MAX_IKCONFIG)
        if cfg is None:
            why = "IKCONFIG: " + err
            continue
        if not re.search(rb"^(?:CONFIG_[A-Za-z0-9_]+=|# CONFIG_[A-Za-z0-9_]+ is not set)", cfg, re.M):
            why = "IKCONFIG data does not look like a kernel .config"
            continue
        if end <= 0:
            complete, err = False, "no IKCFG_ED after the IKCONFIG data"
        return cfg, complete, (None if complete else "IKCONFIG incomplete: " + err)
    return None, None, why


def image_format(head):
    if head[:3] == GZIP_MAGIC:
        return "gzip"
    if head[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if head[:4] == b"\x28\xb5\x2f\xfd":
        return "zstd"
    if head[:3] == b"BZh":
        return "bzip2"
    if head[:3] == b"\x5d\x00\x00":
        return "lzma"
    return None


BANNER_RE = re.compile(rb"Linux version [^\s\x00]+ \([^\n\x00]{1,900}")


def find_banner(data):
    """Image 的內容 → 第一個 linux_banner（"Linux version <release> (" 開頭、到換行為止）的文字；沒有 → None。"""
    first = None
    for m in BANNER_RE.finditer(data):
        t = m.group(0).decode("utf-8", "replace")
        if re.search(r"\) #\d+\S* ", t):          # 完整的 banner（有 "#<n> SMP … <建置時間>"）；Image 裡另有一份 "# SMP PREEMPT  ()" 的樣板
            return t
        first = first or t
    return first


def extract_ikconfig(data, extra=None):
    """Image 的內容 → (config 或 None, 格式, 原因, 完整與否)。格式：raw（未壓縮）或 Image 本身的壓縮方式（gzip、xz、zstd、bzip2、lzma）。
    EFI zboot（MZ…zimg）不解開（限制）。"""
    if extra is not None:
        extra["banner"] = find_banner(data)
    cfg, complete, why = find_ikconfig(data)
    if cfg is not None or why:
        return cfg, "raw", why, complete
    fmt = image_format(bytes(data[:8]))
    if fmt is None:
        return None, "raw", "no IKCONFIG in the Image (kernel built without CONFIG_IKCONFIG, or an unsupported Image format)", None
    raw, err = bounded_unpack(fmt, data, MAX_IMAGE_UNPACKED)
    if raw is None:
        return None, fmt, f"the Image is {fmt}-compressed: {err}", None
    if extra is not None:
        extra["unpacked_md5"] = hashlib.md5(raw, usedforsecurity=False).hexdigest()
        extra["banner"] = find_banner(raw) or extra.get("banner")
    cfg, complete, why = find_ikconfig(raw)
    if cfg is None:
        return None, fmt, why or "no IKCONFIG in the Image (kernel built without CONFIG_IKCONFIG)", None
    return cfg, fmt, why, complete


def probe_stream(path, f, size):
    """打開的檔案 → ImageProbe。整個檔案都算 sha256 與 md5（串流），只有不超過 MAX_IMAGE 的才留在記憶體裡找 IKCONFIG。"""
    h, h5, n = hashlib.sha256(), hashlib.md5(usedforsecurity=False), 0
    buf = bytearray() if size is None or size <= MAX_IMAGE else None
    while True:
        b = f.read(1 << 20)
        if not b:
            break
        h.update(b)
        h5.update(b)
        n += len(b)
        if buf is not None:
            if len(buf) + len(b) > MAX_IMAGE:
                buf = None
            else:
                buf += b
    rec = ImageProbe(path, size=n, sha256=h.hexdigest(), md5=h5.hexdigest())
    if buf is None:
        rec.reason = f"the Image is larger than {MAX_IMAGE >> 20} MB (limit): IKCONFIG not read (sha256 only)"
        return rec
    extra = {}
    rec.config, rec.format, rec.reason, rec.complete = extract_ikconfig(buf, extra)
    rec.unpacked_md5 = extra.get("unpacked_md5")
    rec.banner = extra.get("banner")
    return rec


def probe_entry(path, kind, opener, size):
    """tar 成員或資料夾項目（collect 的 feed／outside）→ ImageProbe。不是一般檔案（連結、資料夾…）不跟隨，只記原因。"""
    if kind != "file" or opener is None:
        return ImageProbe(path, kind=kind, reason=f"not a regular file ({kind}); not followed")
    f = opener()
    try:
        return probe_stream(path, f, size)
    except OSError as e:
        return ImageProbe(path, reason=f"cannot be read ({e.strerror or type(e).__name__})")
    finally:
        try:
            f.close()
        except Exception:
            pass


def probe_dir_file(src, rel):
    """解開的刷機包資料夾裡的 <rel>（不跟隨連結，中間的資料夾也不能是連結）→ ImageProbe；不存在 → None。"""
    label = "/".join(rel)
    for i in range(1, len(rel)):
        try:
            if not stat.S_ISDIR(os.lstat(os.path.join(src, *rel[:i])).st_mode):
                return ImageProbe(label, kind="other", reason=f"{'/'.join(rel[:i])} is not a directory (maybe a symlink); not followed")
        except FileNotFoundError:
            return None
        except OSError as e:
            return ImageProbe(label, kind="other", reason=f"cannot be read ({e.strerror})")
    p = os.path.join(src, *rel)
    try:
        st = os.lstat(p)
    except FileNotFoundError:
        return None
    except OSError as e:
        return ImageProbe(label, kind="other", reason=f"cannot be read ({e.strerror})")
    if not stat.S_ISREG(st.st_mode):
        return ImageProbe(label, kind="symlink" if stat.S_ISLNK(st.st_mode) else "other",
                          reason="not a regular file (maybe a symlink); not followed")
    try:
        with flash_package().open_nofollow(p) as f:
            return probe_stream(label, f, st.st_size)
    except OSError as e:
        return ImageProbe(label, reason=f"cannot be read ({e.strerror or type(e).__name__})")


def resolve_in(links, parts):
    """路徑元件 → 依 links（映像裡的符號連結：路徑 → 目標文字）解開後的路徑（以映像的根為根，.. 不會超出根，不碰主機）；
    連結太多層 → None。同 VFS.resolve。"""
    out, todo, hops = [], list(parts), 0
    while todo:
        n = todo.pop(0)
        if n in ("", "."):
            continue
        if n == "..":
            if out:
                out.pop()
            continue
        cur = tuple(out) + (n,)
        tgt = links.get(cur)
        if tgt is None:
            out.append(n)
            continue
        hops += 1
        if hops > MAX_LINK_HOPS:
            return None
        if tgt.startswith("/"):
            out = []
        todo = tgt.split("/") + todo
    return tuple(out)


def boot_image(col):
    """rootfs 的 /boot/Image（沒有時 Image.gz）→ ImageProbe 或 None（沒有）。符號連結與硬連結在映像裡解開（/boot 底下的連結，
    以及 Collected 記下的 /usr/src、/lib 的連結）；目標要是 /boot 底下讀過的 Image* 檔案，否則只記原因（不讀其他位置、不跟到映像外）。"""
    start = next((("boot", n) for n in IMAGE_NAMES if ("boot", n) in col.boot), None)
    if start is None:
        return None
    links = dict(col.links)
    links.update({k: v[2] for k, v in col.boot.items() if v[1] == "symlink"})
    label, cur = "/" + "/".join(start), start
    for _ in range(MAX_LINK_HOPS):
        r = resolve_in(links, cur)
        if r is None:
            return ImageProbe(label, kind="symlink", reason="too many link hops")
        e = col.boot.get(r)
        if e is None:
            return ImageProbe(label, kind="symlink", reason=f"the link target /{'/'.join(r)} was not read (only regular Image* files "
                                                            "under /boot are read) or is not in the image")
        if e[1] == "hardlink":
            if e[2] is None:
                return ImageProbe(label, kind="hardlink", reason="hard link to a file outside the rootfs")
            cur = e[2]
            continue
        rec = e[2]
        if r == start:
            return rec
        out = ImageProbe(label, kind=rec.kind, size=rec.size, sha256=rec.sha256, fmt=rec.format, config=rec.config, reason=rec.reason,
                         md5=rec.md5, complete=rec.complete)
        out.link_target, out.unpacked_md5, out.banner = "/" + "/".join(r), rec.unpacked_md5, rec.banner
        return out
    return ImageProbe(label, kind="symlink", reason="too many link hops")


def md5sums_lines(data):
    """dpkg 的 <套件>.md5sums（不可信）→ {正規化的路徑: md5}，只留 boot/ 與 usr/src/…/.config 的行。"""
    out = {}
    for raw in data.decode("utf-8", "replace").splitlines():
        m = re.fullmatch(r"([0-9a-fA-F]{32}) [ *]?(.+)", raw.strip())
        if not m:
            continue
        p = posixpath.normpath(m.group(2).strip().lstrip("/"))
        if p.startswith("./"):
            p = p[2:]
        if p.startswith("..") or not (p.startswith("boot/") or (p.startswith("usr/src/") and p.endswith("/.config"))):
            continue
        out[p] = m.group(1).lower()
        if len(out) >= MAX_DPKG_LINES:
            break
    return out


def dpkg_status_versions(data):
    """var/lib/dpkg/status（不可信）→ {套件名稱: {(架構, 版本, 原始碼套件)}}，只收已安裝的（Status 的第三個字是 installed）。
    原始碼套件：Source 欄位去掉「(版本)」；沒有 Source 時就是套件名稱（同 dpkg）。"""
    out, cur = {}, {}

    def flush():
        st = cur.get("Status", "").split()
        if cur.get("Package") and len(st) == 3 and st[2] == "installed" and cur.get("Version"):
            src = (cur.get("Source") or "").split("(")[0].strip() or cur["Package"]
            out.setdefault(cur["Package"], set()).add((cur.get("Architecture"), cur["Version"], src))

    for raw in data.decode("utf-8", "replace").splitlines():
        if not raw.strip():
            flush()
            cur = {}
            continue
        if raw[:1] in (" ", "\t"):
            continue
        k, sep, v = raw.partition(":")
        if sep and k in ("Package", "Status", "Version", "Architecture", "Source"):
            cur[k] = v.strip()
    flush()
    return out


def primary_image(imgs):
    """K1 判定用的 Image：預設刷機包的 kernel/Image（依據公開 L4T BSP：apply_binaries.sh 呼叫 nv_tools/scripts/nv_apply_kernel_files.sh 把 kernel/Image 裝成 rootfs 的 /boot/Image），沒有時 rootfs 的 /boot/Image。
    prefer_rootfs（C-kernel-boot 依板子的 uname -v 判定板子跑的是 rootfs/boot/Image，--prefer-rootfs-image）→ rootfs 的 /boot/Image。"""
    if not imgs:
        return None
    if imgs.get("prefer_rootfs") and imgs.get("rootfs") is not None:
        return imgs["rootfs"]
    return imgs.get("flashed") or imgs.get("rootfs")


def image_inputs(col):
    """擷取到的燒錄核心 → {"flashed": 刷機包的 kernel/Image 或 None, "rootfs": rootfs 的 /boot/Image 或 None, "dpkg": {...}}；
    兩個 Image 都沒有 → None。"""
    fl = next((col.pkg_images[n] for n in IMAGE_NAMES if n in col.pkg_images), None)
    rf = boot_image(col)
    if fl is None and rf is None:
        return None
    st = col.dpkg.get(("var", "lib", "dpkg", "status"))
    md5 = {k[-1][:-len(".md5sums")]: v[1] for k, v in col.dpkg.items() if k[3:4] == ("info",)}
    return {"flashed": fl, "rootfs": rf, "extlinux": col.extlinux, "extlinux_reason": col.extlinux_reason, "prefer_rootfs": False,
            "dpkg": {"status": st[1] if st else None, "status_reason": None if st is None or st[1] is not None else
                     f"var/lib/dpkg/status is larger than {MAX_DPKG_STATUS >> 20} MB (limit)",
                     "md5sums": {k: v for k, v in md5.items() if v is not None},
                     "md5sums_skipped": sorted(k for k, v in md5.items() if v is None)}}


# ---------- 虛擬檔案系統（擷取的內容＋連結） ----------

class VFS:
    def __init__(self, col):
        self.col = col
        self.children = {}
        for k in list(col.files) + list(col.links):
            for i in range(len(k)):
                self.children.setdefault(k[:i], set()).add(k[i])

    def resolve(self, parts):
        """路徑元件 → 解開連結後的路徑（以 rootfs 為根，.. 不會超出根）；連結太多層 → None。"""
        out, todo, hops = [], list(parts), 0
        while todo:
            n = todo.pop(0)
            if n in ("", "."):
                continue
            if n == "..":
                if out:
                    out.pop()
                continue
            cur = tuple(out) + (n,)
            tgt = self.col.links.get(cur)
            if tgt is None:
                out.append(n)
                continue
            hops += 1
            if hops > MAX_LINK_HOPS:
                return None
            if tgt.startswith("/"):
                out = []
            todo = [x for x in tgt.split("/")] + todo
        return tuple(out)

    def file(self, parts):
        r = self.resolve(parts)
        return None if r is None else self.col.files.get(r)

    def is_dir(self, parts):
        r = self.resolve(parts)
        return r is not None and r in self.children and r not in self.col.files

    def walk(self, top, dirmap=None):
        """樹的根 → [(樹內相對路徑, 內容)]。資料夾連結只在指到樹外時跟隨（Ubuntu 的 headers 分成兩個資料夾）；樹內的會照原路徑走到。
        dirmap：給一個 dict 時另外記下走過的每個資料夾（實際的路徑 → 樹內相對路徑；tree_names 用）。"""
        top_r = self.resolve(top)
        out, seen = [], set()
        if top_r is None:
            return out
        stack = [((), top_r)]
        while stack:
            rel, real = stack.pop()
            if real in seen or len(seen) > MAX_ENTRIES:
                continue
            seen.add(real)
            if dirmap is not None:
                dirmap.setdefault(real, rel)
            for n in sorted(self.children.get(real, ())):
                p = real + (n,)
                if p in self.col.links:
                    r = self.resolve(p)
                    if r is None:
                        continue
                    if r in self.col.files:
                        out.append((rel + (n,), self.col.files[r]))
                    elif r in self.children and r[:len(top_r)] != top_r:
                        stack.append((rel + (n,), r))
                elif p in self.col.files:
                    out.append((rel + (n,), self.col.files[p]))
                elif p in self.children:
                    stack.append((rel + (n,), p))
        return out


# =====================================================================================================
# 2. 找到核心的建置樹與 .config
# =====================================================================================================

def parse_config(text):
    """.config → ({CONFIG_X: 值}, 標頭的 (ARCH, 版本))；# CONFIG_X is not set → "n"。"""
    vals, hdr = {}, (None, None)
    for raw in text.splitlines():
        s = raw.strip()
        m = re.match(r"^#\s*(CONFIG_[A-Za-z0-9_]+) is not set$", s)
        if m:
            vals[m.group(1)] = "n"
            continue
        m = re.match(r"^(CONFIG_[A-Za-z0-9_]+)=(.*)$", s)
        if m:
            v = m.group(2)
            vals[m.group(1)] = v[1:-1] if len(v) >= 2 and v[0] == v[-1] == '"' else v
            continue
        m = re.match(r"^#\s*Linux/(\S+)\s+(\S+)\s+Kernel Configuration", s)
        if m and hdr == (None, None):
            hdr = (m.group(1), m.group(2))
    return vals, hdr


def srcarch(arch, vals):
    if arch:
        return SRCARCH_OF.get(arch, arch)
    for sym, a in (("CONFIG_ARM64", "arm64"), ("CONFIG_X86", "x86"), ("CONFIG_ARM", "arm"), ("CONFIG_RISCV", "riscv"),
                   ("CONFIG_PPC", "powerpc"), ("CONFIG_S390", "s390"), ("CONFIG_LOONGARCH", "loongarch"), ("CONFIG_MIPS", "mips")):
        if vals.get(sym) == "y":
            return a
    return None


class BuildInfo:
    def __init__(self, files, config_text, config_path, kernel_version, source, modules=None):
        self.files = files                        # {樹內相對路徑（tuple）: bytes}，只有 Makefile 類
        self.config_text = config_text
        self.config_path = config_path
        self.kernel_version = kernel_version
        self.source = source
        self.modules = modules or {}              # {"ko": set(相對於模組目錄的路徑), "files": {...}}
        self.images = None                        # image_inputs()：燒錄的核心（只有 build_info(images=True) 時有）
        self.tree_names = None                    # 樹內一般檔案的相對路徑（字串）集合；None：不知道（建置紀錄不用它判「沒編」）
        self.config_raw = None                    # .config 的原始位元組（locate 讀到的；改用 IKCONFIG 時是 IKCONFIG）
        self.source_tree = None                   # apply_source_tree()：Makefile 改讀核心原始碼樹時的紀錄（kernel.source_tree）


def follow_path(col, vfs, parts):
    """rootfs 路徑 → 解開 rootfs 的連結（VFS）與各核心版本模組目錄裡的資料夾連結之後的路徑；解不開（太多層）→ None。"""
    cur = parts
    for _ in range(MAX_LINK_HOPS):
        r = vfs.resolve(cur)
        if r is None:
            return None
        mp = modules_part(r)
        if not mp:
            return r
        v, rest = mp
        dl = (col.modules.get(v) or {}).get("dir_links") or {}
        hit = next((i for i in range(1, len(rest) + 1) if "/".join(rest[:i]) in dl), None)
        if hit is None:
            return r
        tgt = dl["/".join(rest[:hit])][0]
        base = r[: len(r) - len(rest)]
        tp = split_name(tgt) if tgt.startswith("/") else base + rest[:hit - 1] + tuple(tgt.split("/"))
        if tp is None:
            return None
        cur = tp + rest[hit:]
    return None


def resolve_ko_links(col, vfs, ver):
    """模組目錄裡連到 .ko 的符號連結 → 以連結名稱算存在的那些（相對於模組目錄的路徑）。
    目標經過資料夾連結時一併解開（follow_path）。目標在同一個（或另一個）核心版本的模組目錄裡：要解得到存在的 .ko（可以連過幾層）；
    目標是映像裡的一般檔案但名稱不是 .ko（foo.ko -> foo.ko.orig）：modprobe 照樣載入，算存在。目標找不到（懸空、解不開、
    或是無法跟隨的連結）→ 不算存在，另記 gap（清單可能不完整）。目標在模組目錄以外（沒有擷取，無法核對）：算存在
    （寧可多列：K2 依名稱判斷「不在映像裡」，少列會誤判）。回傳 (名稱集合, gaps)。"""
    m = col.modules.get(ver) or {}
    links, out, gaps = m.get("ko_links") or {}, set(), []
    for name, (tgt, _, parts) in links.items():
        t, p, ok = tgt, parts, False
        for _ in range(MAX_LINK_HOPS):
            tp = split_name(t) if t.startswith("/") else p[:-1] + tuple(t.split("/"))
            r = follow_path(col, vfs, tp) if tp is not None else None
            if r is None:
                break
            mp = modules_part(r)
            if not mp or mp[0] not in col.modules:
                ok = True                     # 模組目錄以外：無法核對，算存在
                break
            om, rr = col.modules[mp[0]], "/".join(mp[1])
            if rr in (om.get("ko") or ()):
                ok = True
                break
            if rr not in (om.get("ko_links") or {}):
                # 名稱不是 .ko 的一般檔案（.ko 名稱以模組清單為準：那份清單有處理 docker 的 whiteout，路徑索引沒有）
                ok = not col.seen_overflow and not r[-1].endswith(MODULE_EXT) and hash("/".join(r)) in col.seen_files
                break
            t, _, p = om["ko_links"][rr]
        if ok:
            out.add(name)
        else:
            gaps.append(f"{name} -> {tgt}: the target of the .ko link cannot be found in the image")
    return out, gaps


def resolve_dir_links(col, vfs, ver):
    """模組目錄裡的資料夾連結（updates -> /opt/nv/updates）→ (以連結的路徑列出的 .ko 名稱, gaps)。
    - 目標在同一個模組目錄裡：底下的 .ko 已經以實際的路徑列出（modules_present 只看名稱），不重複展開；目標不存在 → gap。
    - 目標在另一個核心版本的模組目錄裡：列那個版本的 .ko；那裡面又有連結（.ko 連結或資料夾連結）→ gap（不跟隨）。
    - 目標在模組目錄以外：列映像裡那個位置的 .ko（一般檔案與硬連結）；底下有任何符號連結 → gap（不跟隨）。
    - 每個實際的目標資料夾只展開一次；名稱總數超過 MAX_LINK_NAMES → gap。
    - 解不開、目標不存在、目標是無法跟隨的連結 → gap；目標是映像裡的檔案，或是底下沒有 .ko 的資料夾 → 不算。
    映像的路徑索引超過上限（seen_overflow）時，需要用索引判斷的連結一律 gap。"""
    m = col.modules.get(ver) or {}
    out, gaps, expanded = set(), [], set()

    def kind_of(rs):
        if col.seen_overflow:
            return "unknown"
        if rs in col.seen_dirs:
            return "dir"
        if hash(rs) in col.seen_files:
            return "file"
        return "link" if hash(rs) in col.seen_links else "missing"

    for name, (tgt, _, parts) in sorted((m.get("dir_links") or {}).items()):
        tp = split_name(tgt) if tgt.startswith("/") else parts[:-1] + tuple(tgt.split("/"))
        r = follow_path(col, vfs, tp) if tp is not None else None
        if r is None:
            gaps.append(f"{name} -> {tgt}: the link cannot be resolved")
            continue
        rs, mp = "/".join(r), modules_part(r)
        if mp and mp[0] == ver:
            k = kind_of(rs)
            if k in ("missing", "link", "unknown"):
                gaps.append(f"{name} -> {tgt}: the target {'does not exist in the image' if k == 'missing' else 'cannot be checked'}")
            continue
        if r in expanded:
            continue
        expanded.add(r)
        if mp and mp[0] in col.modules:
            om, pre = col.modules[mp[0]], "/".join(mp[1])
            under = (lambda k: True) if not pre else (lambda k: k.startswith(pre + "/"))
            cut = len(pre) + 1 if pre else 0
            got = {name + "/" + k[cut:] for k in om.get("ko") or () if under(k)}
            if any(under(k) for k in list(om.get("ko_links") or {}) + list(om.get("dir_links") or {})):
                gaps.append(f"{name} -> {tgt}: the target is in the module directory of kernel {mp[0]} and contains links "
                            "that are not followed")
        else:
            got = {name + "/" + "/".join(p[len(r):]) for p in col.other_ko if p[:len(r)] == r and len(p) > len(r)}
            if col.seen_overflow or any(l.startswith(rs + "/") for l in col.other_links):
                gaps.append(f"{name} -> {tgt}: the target contains links that are not followed" if not col.seen_overflow else
                            f"{name} -> {tgt}: the image has more entries than the path index holds; the target cannot be checked")
            elif not got:
                k = kind_of(rs)
                if k == "link":
                    gaps.append(f"{name} -> {tgt}: the target is another link that cannot be followed here")
                elif k == "missing" and not (r and r[-1].endswith(MODULE_EXT)):
                    gaps.append(f"{name} -> {tgt}: the target does not exist in the image (dangling link)")
        out |= got
        if len(out) > MAX_LINK_NAMES:
            gaps.append(f"more than {MAX_LINK_NAMES} .ko names reached through directory links: the list is cut off")
            break
    return out, gaps


def locate(col, src, want_ver):
    """Collected → (BuildInfo, None) 或 (None, GAP 的原因)。"""
    vfs = VFS(col)
    vers = sorted(v for v, m in col.modules.items() if m["ko"] or m["files"] or m.get("ko_links"))
    if want_ver:
        if want_ver not in vers:
            return None, (f"映像沒有核心模組目錄 /usr/lib/modules/{want_ver}/（有：{'、'.join(vers) or '沒有'}）："
                          "不知道 .config 是不是執行中的核心的")
        ver = want_ver
    elif len(vers) == 1:
        ver = vers[0]
    elif not vers:
        return None, "映像沒有核心模組目錄（/usr/lib/modules/<版本>/）：不知道執行中的核心是哪一個，不用 .config"
    else:
        return None, f"映像有 {len(vers)} 個核心模組目錄（{'、'.join(vers[:4])}），沒有指定要看哪一個（--kernel-version），不猜"
    mod = col.modules[ver]
    # 資料夾連結各展開一次；.ko 連結經過資料夾連結時由 follow_path 解開（不必先展開）
    names, gaps = resolve_dir_links(col, vfs, ver)
    mod["ko"] |= names
    knames, kgaps = resolve_ko_links(col, vfs, ver)
    mod["ko"] |= knames
    mod["present_gaps"] = gaps + kgaps
    roots = []
    if mod.get("build"):
        b = mod["build"]
        for base in ((),) if b.startswith("/") else (("usr", "lib", "modules", ver), ("lib", "modules", ver)):
            bp = split_name(b) if b.startswith("/") else base + tuple(b.split("/"))
            r = vfs.resolve(bp) if bp is not None else None
            if r is not None and (r + (".config",)) in col.files and r not in roots:
                roots.append(r)
    if not roots:
        cands = sorted({k[:-1] for k in col.files if k[-1] == ".config" and len(k) >= 4 and k[2].startswith(f"linux-headers-{ver}")
                        and vfs.file(k[:-1] + ("Makefile",)) is not None})
        shas = {hashlib.sha256(col.files[c + (".config",)]).hexdigest() for c in cands}
        if len(shas) > 1:
            return None, f"/usr/src/linux-headers-{ver}* 有 {len(cands)} 個內容不同的 .config，不猜是哪一個"
        roots = cands[:1]
    if not roots:
        have = sorted({"/".join(k[:3]) for k in col.files if len(k) > 3})
        return None, (f"映像沒有核心 {ver} 的建置設定（/usr/lib/modules/{ver}/build 或 /usr/src/linux-headers-{ver}*/ 底下的 .config"
                      f" 與 Makefile；/usr/src 有：{'、'.join(have[:3]) or '沒有'}）：要安裝核心 headers 套件"
                      "（Jetson：nvidia-l4t-kernel-headers）")
    root = roots[0]
    dirmap = {}
    files = {rel: data for rel, data in vfs.walk(root, dirmap)}
    cfg = col.files[root + (".config",)]
    info = BuildInfo(files, cfg.decode("utf-8", "replace"), "/" + "/".join(root + (".config",)), ver, src, mod)
    info.config_raw = cfg
    info.tree_names = tree_names(col, dirmap)
    return info, None


def tree_names(col, dirmap):
    """擷取到的 /usr/src/linux-*/ 檔案名稱 → 樹內相對路徑的集合（依 VFS.walk 走過的資料夾對應，含指到樹外的資料夾連結）；
    名稱超過上限 → None（不知道）。只給建置紀錄判斷「這個檔案在這個核心裡」。"""
    if col.src_overflow:
        return None
    out = set()
    for p in col.src_names:
        for i in range(len(p) - 1, 0, -1):
            rel = dirmap.get(p[:i])
            if rel is not None:
                out.add("/".join(rel + p[i:]))
                break
    return out


# =====================================================================================================
# 3. Makefile（Kbuild）的文字解析
# =====================================================================================================

ROOTMARK = "\0ROOT"
LISTS = "\0lists"          # 變數表裡的特別鍵：{base: [(字, [Atom])]}，<base>-<後綴> 的全部指派（給 $(base-y) 展開）
FALSE_BASES = {"n", ""}
LIST_BASES = ("obj", "lib", "subdir")
# define 區塊或沒有指派的行（$(eval …) 等）提到物件清單時，這個 Makefile 算看不懂（opaque）
OBJ_LIST_HINT = re.compile(r"\b(?:obj|lib|subdir)-|[A-Za-z0-9_]-(?:y|m|objs)\b|\.o\b")
# 這些 <名稱>-y 不是物件清單（編譯旗標、主機程式、裝置樹…）：不當成組合物件
NOT_OBJECT_LISTS = {"ccflags", "asflags", "ldflags", "subdir-ccflags", "subdir-asflags", "ccflags-remove", "asflags-remove", "always",
                    "extra", "targets", "hostprogs", "userprogs", "clean-files", "no-clean-files", "header-test", "generic",
                    "mandatory", "generated", "dtb", "dtbo", "core", "drivers", "libs"}


def split_words(s):
    """以空白切開，$( ) 與 ${ } 裡的空白不切。"""
    out, cur, depth, i = [], [], 0, 0
    while i < len(s):
        c = s[i]
        if c == "$" and i + 1 < len(s) and s[i + 1] in "({":
            depth += 1
            cur.append(s[i:i + 2])
            i += 2
            continue
        if c in ")}" and depth:
            depth -= 1
        if c.isspace() and depth == 0:
            if cur:
                out.append("".join(cur))
                cur = []
        else:
            cur.append(c)
        i += 1
    if cur:
        out.append("".join(cur))
    return out


def split_args(s):
    """函式參數（逗號分隔，括號裡的不切）。"""
    out, cur, depth = [], [], 0
    for c in s:
        if c in "({":
            depth += 1
        elif c in ")}":
            depth -= 1
        if c == "," and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(c)
    out.append("".join(cur))
    return out


def find_op(s):
    """第一個不在 $( ) 裡的指派運算子或規則的冒號 → (位置, 運算子)；都沒有 → (-1, None)。"""
    depth, i = 0, 0
    while i < len(s):
        c = s[i]
        if c == "$" and i + 1 < len(s) and s[i + 1] in "({":
            depth += 1
            i += 2
            continue
        if c in ")}" and depth:
            depth -= 1
        elif depth == 0:
            for op in ("::=", ":=", "+=", "?=", "!=", "="):
                if s.startswith(op, i):
                    return i, op
            if c == ":":
                return i, ":"
        i += 1
    return -1, None


def logical_lines(text):
    """接起 \\ 續行；去掉註解（# 之後；跳脫的 \\# 不算）。回傳 (是否以 tab 開頭, 內容)。"""
    out, buf, tab = [], [], None
    for raw in text.splitlines():
        if tab is None:
            tab = raw.startswith("\t")
        if raw.endswith("\\") and not raw.endswith("\\\\"):
            buf.append(raw[:-1])
            continue
        buf.append(raw)
        s = " ".join(buf)
        buf = []
        s = re.sub(r"(?<!\\)#.*$", "", s)
        out.append((tab, s))
        tab = None
    if buf:
        out.append((tab, re.sub(r"(?<!\\)#.*$", "", " ".join(buf))))
    return out


class Atom:
    """一個條件：sym（CONFIG 符號）、unknown（看不懂的條件區塊）或 const。
    my：$(CONFIG_X:m=y) 或 $(subst m,y,$(CONFIG_X))：=m 也當成 y（編進核心）。這裡的判定不受影響（=m 本來就算有編），
    給 kernel_module_map.py 分辨 builtin 與模組。"""
    __slots__ = ("kind", "value", "my")

    def __init__(self, kind, value, my=False):
        self.kind, self.value, self.my = kind, value, my

    def __repr__(self):
        return f"{self.kind}:{self.value}"


SYM_RE = re.compile(r"^\$[({](CONFIG_[A-Za-z0-9_]+)(?::m=y)?[)}]$")
SUBST_RE = re.compile(r"^\$[({]subst\s+m\s*,\s*y\s*,\s*\$[({](CONFIG_[A-Za-z0-9_]+)[)}]\s*[)}]$")


def suffix_atom(sfx):
    """obj-<後綴> 的後綴 → Atom；不認得 → None（整個指派算不明）。
    只有 n 與空字串（obj-、obj-n：CONFIG 沒設時 obj-$(CONFIG_X) 展開的結果）確定不編。其他字面後綴（obj-vdso、hyp-obj-…）
    是 Makefile 自己的變數，可能由別的規則使用（arm64 vdso 以 obj-vdso 列物件，經 incbin 編進核心），一律不明。"""
    if sfx == "m":
        return Atom("const", "m")        # 真值（同 y）；值留 "m" 給 kernel_module_map.py 分辨 obj-m
    if sfx in ("y", "objs"):
        return Atom("const", True)
    if sfx in ("", "n"):
        return Atom("const", False)
    m = SYM_RE.match(sfx)
    if m:
        return Atom("sym", m.group(1), my=":m=y" in sfx)
    m = SUBST_RE.match(sfx)
    if m:
        return Atom("sym", m.group(1), my=True)
    return None


def colon_outside(s):
    """字串在 $( ) 與 ${ } 之外有沒有冒號。"""
    depth, i = 0, 0
    while i < len(s):
        c = s[i]
        if c == "$" and i + 1 < len(s) and s[i + 1] in "({":
            depth += 1
            i += 2
            continue
        if c in ")}" and depth:
            depth -= 1
        elif c == ":" and depth == 0:
            return True
        i += 1
    return False


class Makefile:
    """一個資料夾的 Makefile（或 Kbuild）解析結果。"""

    def __init__(self, d):
        self.dir = d                   # 樹內相對路徑（字串，根是 ""）
        self.refs = []                 # (base, target, [Atom])：base 是 obj／lib／subdir 或組合物件名稱；target 是樹內路徑（資料夾以 / 結尾）
        self.unresolved = []           # ([Atom], 原文)：可能是物件或資料夾、但展不開的項目
        self.opaque = []               # 無法解析的 include 等：這個 Makefile 的內容不完整
        self.compiles = []             # 規則的前提裡的原始檔（樹內路徑，可含 %）：這個 Makefile 自己編譯的檔案，可能在別的資料夾
        self.extras = []               # extra-／always- 列的 .o（樹內路徑）：另外建置的目標，不經 obj- 連結；判定不用，給模組對應排除


class Parser:
    def __init__(self, files, arch):
        self.files, self.arch = files, arch

    def get(self, d):
        """資料夾 → Makefile 內容（Kbuild 優先，同 Kbuild 的規則）；沒有 → None。"""
        for n in ("Kbuild", "Makefile"):
            data = self.files.get(tuple(x for x in d.split("/") if x) + (n,))
            if data is not None:
                return data.decode("utf-8", "replace")
        return None

    def parse(self, d, text, predefined=None, mf=None, depth=0, ignore_if=False, shared=None):
        """shared：include 進來的檔案和外層共用同一個變數表。"""
        mf = mf or Makefile(d)
        vars_ = shared if shared is not None else dict(predefined or {})
        stack, in_rule, in_define = [], False, 0
        for tab, s in logical_lines(text):
            st = s.strip()
            if in_define:
                if OBJ_LIST_HINT.search(st):
                    mf.opaque.append(f"define block ({st[:60]})")
                if re.match(r"^endef\b", st):
                    in_define -= 1
                elif re.match(r"^(?:export\s+|override\s+)?define\b", st):
                    in_define += 1
                continue
            if tab and in_rule:
                continue                     # 規則的指令
            if not st:
                continue
            w = st.split(None, 1)
            kw = w[0]
            if kw in ("ifeq", "ifneq", "ifdef", "ifndef"):
                stack.append(st)
                in_rule = False
                continue
            if kw == "else":
                in_rule = False
                continue
            if kw == "endif":
                if stack:
                    stack.pop()
                in_rule = False
                continue
            if re.match(r"^(?:export\s+|override\s+)?define\b", st):
                in_define = 1
                continue
            if kw in ("include", "-include", "sinclude"):
                self.include(mf, d, w[1] if len(w) > 1 else "", vars_, depth)
                in_rule = False
                continue
            body = re.sub(r"^(?:export|override|unexport)\s+", "", st)
            pos, op = find_op(body)
            if op is None:
                if OBJ_LIST_HINT.search(body):
                    mf.opaque.append(f"line without an assignment ({body[:60]})")   # $(eval …)、$(call …)、$(foreach …)
                in_rule = False
                continue
            if op == ":":
                in_rule = True                   # 規則（或 target-specific 變數）
                self.rule_sources(mf, d, body[pos + 1:].lstrip(":"), vars_)
                continue
            in_rule = False
            lhs, rhs = body[:pos].strip(), body[pos + len(op):].strip()
            if colon_outside(lhs):
                continue
            # $( ) 裡的冒號（obj-$(CONFIG_X:m=y)、stub-$(CONFIG_X:m=y)）照常解析：suffix_atom 認得 :m=y，
            # 不認得的後綴由 assign 記成看不懂（unresolved），不會默默略過
            conds = [] if (ignore_if or not stack) else [Atom("unknown", stack[-1][:80])]
            self.assign(mf, d, lhs, op, rhs, conds, vars_, in_cond=bool(stack))
        return mf

    def rule_sources(self, mf, d, prereq, vars_):
        """規則的前提裡的 .c／.S（例如 xe 的 $(obj)/i915-display/%.o: $(srctree)/drivers/gpu/drm/i915/display/%.c）：
        這些檔案由這個 Makefile 的規則編譯，不一定經過那個資料夾自己的 obj- 清單。記下來，判「沒編」時要排除。
        target-specific 變數（target: VAR := x）不是前提。展不開的前提略過（不知道是哪個檔案）。"""
        if find_op(prereq)[1] not in (None, ":"):
            return
        here = ROOTMARK + ("/" + d if d else "")
        for w in split_words(prereq.split(";", 1)[0]):
            if not re.search(r"\.(?:c|S)$", w):
                continue
            x = w.replace("$(srctree)", ROOTMARK).replace("$(objtree)", ROOTMARK).replace("$(src)", here).replace("$(obj)", here)
            if "$" in x:
                # 變數的值裡也可能有 $(srctree) 等：展開時當成已知的單值變數
                vs = dict(vars_, srctree=[(ROOTMARK, [])], objtree=[(ROOTMARK, [])], src=[(here, [])], obj=[(here, [])])
                x = self.expand_str(x, vs)
                if x is None or "$" in x:
                    continue
            path = x[len(ROOTMARK):].lstrip("/") if x.startswith(ROOTMARK) else x
            path = posixpath.normpath(path)
            if path.startswith("..") or path.startswith("/") or path == ".":
                continue
            mf.compiles.append(path)

    def include(self, mf, d, arg, vars_, depth):
        for w in split_words(arg):
            # make 在樹的根執行（kbuild 以 -f scripts/Makefile.build obj=<資料夾>），相對路徑以根為準；$(src)／$(obj) 是這個資料夾
            here = ROOTMARK + ("/" + d if d else "")
            p = w.replace("$(srctree)", ROOTMARK).replace("$(objtree)", ROOTMARK).replace("$(src)", here).replace("$(obj)", here)
            p = self.expand_str(p, vars_)
            if p is None or "$" in p:
                mf.opaque.append(f"include {w}")
                continue
            path = p[len(ROOTMARK):].lstrip("/") if p.startswith(ROOTMARK) else p
            path = posixpath.normpath(path)
            data = self.files.get(tuple(x for x in path.split("/") if x not in ("", ".")))
            if data is None or depth > 4:
                if posixpath.basename(path) not in ("auto.conf", ".config", "Kbuild.include") and not path.startswith("scripts/"):
                    mf.opaque.append(f"include {w}")
                continue
            if path.startswith("scripts/"):
                continue                         # kbuild 自己的規則檔，不是物件清單
            self.parse(d, data.decode("utf-8", "replace"), mf=mf, depth=depth + 1, shared=vars_)

    # ---- 變數展開 ----
    def expand_str(self, s, vars_):
        """把單值的變數換進字串；有多值或不認得的 → None。"""
        def rep(m):
            v = vars_.get(m.group(1))
            if v is None:
                raise KeyError
            toks = [t for t, c in v]
            if len(toks) != 1 or any(c for t, c in v):
                raise KeyError
            return toks[0]
        try:
            prev = None
            while prev != s:
                prev = s
                s = re.sub(r"\$[({]([A-Za-z0-9_.-]+)[)}]", rep, s)
            return s
        except KeyError:
            return None

    def expand(self, word, vars_, conds, depth=0):
        """一個字 → [(字, [Atom])]；展不開 → [(None, conds)]（原文另記）。"""
        if "$" not in word:
            return [(word, conds)]
        if depth > 8:
            return [(None, conds)]
        m = re.fullmatch(r"\$[({]([A-Za-z0-9_.-]+)[)}]", word)
        if m:
            v = vars_.get(m.group(1))
            lm = re.fullmatch(r"(.+)-[ym]", m.group(1))
            if lm and lm.group(1) in vars_.get(LISTS, {}):
                # $(foo-y)：foo-y、foo-$(CONFIG_X)… 的全部指派，各帶自己的後綴條件（=m 的也算進來：只會讓結果偏向「有編」）
                v = vars_[LISTS][lm.group(1)]
            if v is None:
                return [(None, conds)]
            out = []
            for t, c in v:
                out += self.expand(t, vars_, conds + c, depth + 1) if t is not None else [(None, conds + c)]
            return out
        m = re.fullmatch(r"\$[({](addprefix|addsuffix|filter|filter-out|patsubst)\s+(.*)[)}]", word, re.S)
        if m:
            args = split_args(m.group(2))
            fn = m.group(1)
            if fn in ("addprefix", "addsuffix", "filter", "filter-out") and len(args) == 2 or fn == "patsubst" and len(args) == 3:
                head = [a.strip() for a in args[:-1]]
                head = [self.expand_str(a, vars_) if "$" in a else a for a in head]
                if any(a is None for a in head):
                    return [(None, conds)]
                items = []
                for w in split_words(args[-1]):
                    items += self.expand(w, vars_, conds, depth + 1)
                out = []
                for t, c in items:
                    if t is None:
                        out.append((None, c))
                    elif fn == "addprefix":
                        out.append((head[0] + t, c))
                    elif fn == "addsuffix":
                        out.append((t + head[0], c))
                    elif fn in ("filter", "filter-out"):
                        hit = any(pat_match(p, t) for p in head[0].split())
                        if hit == (fn == "filter"):
                            out.append((t, c))
                    else:
                        r = pat_subst(head[0], head[1], t)
                        out.append((r, c))
                return out
            return [(None, conds)]
        s = self.expand_str(word, vars_)
        return [(s, conds)] if s is not None and "$" not in s else [(None, conds)]

    def assign(self, mf, d, lhs, op, rhs, conds, vars_, in_cond=False):
        # 先記變數（給之後的 $(VAR) 展開用）：值保留條件；:= 與 = 都在使用時才展開（Makefile 很少依賴差別）
        words = split_words(rhs)
        vals = [(w, conds) for w in words]
        key = self.expand_str(lhs, vars_) if "$" in lhs else lhs
        if key is not None and "$" not in key:
            if op in ("+=",):
                vars_[key] = vars_.get(key, []) + vals
            elif op == "?=":
                vars_.setdefault(key, vals)
            elif op != "!=":
                # 條件區塊裡的 = 與 :=：另一個分支的值也可能是實際的值（ifdef … X := a.o else X := endif），合併而不覆蓋
                vars_[key] = vars_.get(key, []) + vals if in_cond else vals
        # 清單：<base>-<後綴>
        m = re.match(r"^(.*?)-((?:\$[({].*[)}])|[A-Za-z0-9_]*)$", lhs, re.S)
        if not m:
            return
        base, sfx = m.group(1), m.group(2)
        if "$" in base:
            base = self.expand_str(base, vars_)
            if base is None or "$" in base:
                if any(could_denote(w) for w in words):
                    mf.unresolved.append((conds, f"{lhs} {op} …"))
                return
        if base == "subdir" and sfx in ("", "n"):
            return                  # subdir-：只給 make clean 用（例如 arm64 的 subdir- += vdso vdso32），不代表「沒編」
        atom = suffix_atom(sfx)
        if atom is None:
            # 不認得的字面後綴（obj-vdso、atomic-checks、clean-files、build-version…）：只有左邊看起來是物件清單時才算看不懂；
            # 其他是一般變數（值已記在 vars_，被 obj-y += $(X) 用到時在那裡展開），忽略。不然根目錄 Kbuild 的
            # atomic-checks += $(addprefix …) 會讓整棵樹都變成不知道
            if re.fullmatch(r"[A-Za-z0-9_]*", sfx) and not object_list_like(base, lhs, words):
                return
            if any(could_denote(w) for w in words):
                mf.unresolved.append((conds + [Atom("unknown", f"{lhs}")], f"{lhs} {op} …"))
            return
        if base in NOT_OBJECT_LISTS:
            if base in ("extra", "always"):
                for w in words:
                    for t, _ in self.expand(w, vars_, conds + [atom]):
                        if t and t.endswith(".o") and not t.startswith(ROOTMARK):
                            mf.extras.append(posixpath.normpath(posixpath.join(d, t)))
            return
        c = conds + [atom]
        for w in words:
            for t, tc in self.expand(w, vars_, c):
                if t is None:
                    if could_denote(w):
                        mf.unresolved.append((tc, w))
                    continue
                self.add_ref(mf, d, base, t, tc)
        if sfx != "objs":           # 展開之後才記（foo-objs := $(foo-y) 不能展開到自己）
            lst = vars_.setdefault(LISTS, {}).setdefault(base, [])
            if op == ":=" and sfx == "y" and not conds:
                lst.clear()
            lst += [(w, c) for w in words]

    def add_ref(self, mf, d, base, tok, conds):
        is_dir = tok.endswith("/")
        if base == "subdir" and not is_dir:
            tok += "/"
            is_dir = True
        if not (tok.endswith(".o") or is_dir):
            return
        if base not in LIST_BASES and is_dir:
            return
        if tok.startswith(ROOTMARK):
            path = tok[len(ROOTMARK) + 1:]
        else:
            path = posixpath.join(d, tok)
        path = posixpath.normpath(path)
        if path.startswith("..") or path.startswith("/"):
            return
        if is_dir:
            path = "" if path == "." else path
        mf.refs.append((base, path + ("/" if is_dir and path else ""), conds))


# 不認得的字面後綴時，這些左邊一定不是物件清單（kbuild 的清理、檢查、產生檔清單與指令變數）
NON_OBJECT_LHS = re.compile(r"^(?:clean-files|clean-dirs|no-clean-files|targets|extra-.*|always-.*|hostprogs.*|userprogs.*|"
                            r".*-checks|build-.*|cmd_.*|quiet_cmd_.*|.*flags.*|.*-files|.*-dirs)$")


def object_list_like(base, lhs, words):
    """<base>-<不認得的字面後綴> 是不是物件清單：base 是 obj／lib／subdir 或以 obj 結尾（obj-vdso、hyp-obj-…），
    或右邊有字面上的 .o 或資料夾（而且左邊不是已知的非物件變數）。"""
    if base in LIST_BASES or base.endswith("obj"):
        return True
    if NON_OBJECT_LHS.match(lhs):
        return False
    return any(w.strip().endswith((".o", "/")) for w in words)


def could_denote(w):
    """展不開的字是否可能是物件或資料夾（以 .o 或 / 結尾，或整個是變數或函式）。"""
    w = w.strip()
    return w.endswith(".o") or w.endswith("/") or w.endswith(")") or w.endswith("}")


def pat_match(p, t):
    if "%" not in p:
        return p == t
    a, b = p.split("%", 1)
    return t.startswith(a) and t.endswith(b) and len(t) >= len(a) + len(b)


def pat_subst(p, r, t):
    if "%" not in p:
        return r if t == p else t
    a, b = p.split("%", 1)
    if t.startswith(a) and t.endswith(b) and len(t) >= len(a) + len(b):
        stem = t[len(a):len(t) - len(b)] if b else t[len(a):]
        return r.replace("%", stem, 1)
    return t


# =====================================================================================================
# 4. 有沒有編（三值）
# =====================================================================================================

class Res:
    """value：True／False／None；syms：決定結果的 CONFIG 符號；why：說明片段；modules：=m 時的模組路徑。"""
    __slots__ = ("value", "syms", "why", "modules")

    def __init__(self, value, syms=(), why=(), modules=()):
        self.value, self.syms, self.why, self.modules = value, set(syms), list(why), set(modules)


def r_and(parts):
    fs = [p for p in parts if p.value is False]
    if fs:
        return Res(False, set().union(*[p.syms for p in fs]), [w for p in fs for w in p.why])
    us = [p for p in parts if p.value is None]
    if us:
        return Res(None, set().union(*[p.syms for p in parts]), [w for p in us for w in p.why])
    return Res(True, set().union(*[p.syms for p in parts]) if parts else set(), [w for p in parts for w in p.why],
               set().union(*[p.modules for p in parts]) if parts else set())


def r_or(parts):
    ts = [p for p in parts if p.value is True]
    if ts:
        return Res(True, set().union(*[p.syms for p in ts]), [w for p in ts for w in p.why][:4], set().union(*[p.modules for p in ts]))
    us = [p for p in parts if p.value is None]
    if us:
        return Res(None, set().union(*[p.syms for p in us]), [w for p in us for w in p.why][:4])
    return Res(False, set().union(*[p.syms for p in parts]) if parts else set(), [w for p in parts for w in p.why][:6])


class Model:
    def __init__(self, info):
        self.info = info
        self.config, (arch, self.kver_hdr) = parse_config(info.config_text)
        self.srcarch = srcarch(arch, self.config)
        if not self.srcarch:
            raise InputError(".config 看不出架構（沒有 Linux/<ARCH> 標頭，也沒有 CONFIG_ARM64／CONFIG_X86 等）")
        # 「arch/<其他架構>/ 沒編」的規則只在架構確定時用：headers 要有 arch/<srcarch>/Makefile（標頭寫 Linux/aarch64 之類不是
        # 核心的 SRCARCH 時不用）；UML（um）會用 arch/x86/ 的 Makefile.um 與 um/ 資料夾，也不用
        self.arch_rule = self.srcarch != "um" and ("arch", self.srcarch, "Makefile") in info.files
        p = Parser(info.files, self.srcarch)
        dirs = sorted({"/".join(k[:-1]) for k in info.files if k and k[-1] in ("Makefile", "Kbuild")})
        self.makefiles = {}
        self.obj_refs, self.dir_refs = {}, {}
        self.compiled_by = {}          # 資料夾 → [(檔名或 % 樣式, 編譯它的 Makefile 所在資料夾)]
        self.extra_objs = set()        # extra-／always- 列的物件（判定不用）
        root_vars = self.root_vars(p)
        for d in dirs:
            text = p.get(d)
            if text is None:
                continue
            pre = dict(root_vars) if d == "" else {"SRCARCH": [(self.srcarch, [])], "ARCH": [(self.srcarch, [])]}
            mf = p.parse(d, text, predefined=pre)
            self.makefiles[d] = mf
            for src in mf.compiles:
                self.compiled_by.setdefault(posixpath.dirname(src), []).append((posixpath.basename(src), d))
            self.extra_objs.update(mf.extras)
            for base, target, conds in mf.refs:
                if target.endswith("/"):
                    self.dir_refs.setdefault(target[:-1], []).append((d, base, conds))
                else:
                    self.obj_refs.setdefault(target, []).append((d, base, conds))
        self.memo = {}

    def root_vars(self, p):
        """根目錄 Kbuild 用到的 ARCH_CORE／ARCH_LIB／ARCH_DRIVERS：來自最上層 Makefile 與 arch/$(SRCARCH)/Makefile 的 core-／libs-／drivers-。
        這兩個檔案的條件區塊多半是編譯器旗標，這裡只取這三種清單（區塊裡的也算，只會讓結果更偏向「有編」，不會變成「沒編」）。"""
        lists = {"core": [], "libs": [], "drivers": []}
        for d in ("", f"arch/{self.srcarch}"):
            data = self.info.files.get(tuple(x for x in d.split("/") if x) + ("Makefile",))
            if data is None:
                continue
            for tab, s in logical_lines(data.decode("utf-8", "replace")):
                m = re.match(r"^\s*(?:export\s+)?(core|libs|drivers)-(\S+)\s*(:=|\+=|=)\s*(.*)$", s)
                if not m or tab:
                    continue
                atom = suffix_atom(m.group(2))
                if atom is None:
                    continue
                words = [w for w in split_words(m.group(4)) if not re.fullmatch(r"\$[({](core|libs|drivers)-[ym][)}]", w)]
                words = [w.replace("$(objtree)/", ROOTMARK + "/").replace("$(srctree)/", ROOTMARK + "/") for w in words]
                words = [ROOTMARK + "/" + w if not w.startswith(ROOTMARK) and "$" not in w else w for w in words]
                if m.group(3) == ":=" and m.group(2) == "y" and not d:
                    lists[m.group(1)] = []
                lists[m.group(1)] += [(w, [atom]) for w in words]
        sa = [(self.srcarch, [])]
        return {"SRCARCH": sa, "ARCH": sa, "ARCH_CORE": lists["core"],
                "ARCH_LIB": [(w, c) for w, c in lists["libs"] if w.endswith("/")],
                "ARCH_DRIVERS": lists["drivers"]}

    # ---- 條件 ----
    def atom(self, a):
        if a.kind == "const":
            return Res(bool(a.value))
        if a.kind == "unknown":
            return Res(None, why=[f"conditional block ({a.value})"])
        v = self.config.get(a.value)
        if v in ("y", "m"):
            return Res(True, {a.value}, modules={"?"} if v == "m" else ())
        return Res(False, {a.value}, [f"{a.value}={'n' if v == 'n' else 'unset' if v is None else v}"])

    def uncertain(self, d):
        """這個資料夾的 Makefile 有看不懂、可能是物件或資料夾的地方 → 說明；沒有，或這個資料夾一定沒編（裡面寫什麼都不會編）→ None。"""
        mf = self.makefiles.get(d)
        if mf is None or (not mf.opaque and not mf.unresolved):
            return None
        if self.dir_built(d).value is False:
            return None
        if mf.opaque:
            return f"{d or '(root)'}/Makefile has an unresolved {mf.opaque[0]}"
        for conds, raw in mf.unresolved:
            if r_and([self.atom(a) for a in conds]).value is not False:
                return f"{d or '(root)'}/Makefile has an unexpandable entry ({raw[:60]})"
        return None

    def ref_gate(self, md):
        """規則所在資料夾的 Makefile 會不會被 kbuild 處理。沒有任何規則進入這個資料夾（上層有編）時，那個 Makefile 可能只是被別的
        Makefile include 的片段（例如 amdkfd/Makefile），它的規則不能用來證明「沒編」：回傳 None。"""
        g = self.dir_built(md)
        if g.value is None and md and md not in self.dir_refs:
            return Res(None, why=[f"{md}/Makefile is in a directory no rule descends into (it may be included elsewhere)"]), True
        return g, False

    def uncertain_chain(self, d, refs):
        """d 與它的每一層上層、以及提到這個項目的 Makefile：任何一個看不懂（而且那個資料夾可能有編）→ 說明。
        看不懂的項目可能以路徑指到底下的物件或資料夾（例如 obj-y += $(X)/），所以「沒編」的結論要整條路徑都看得懂。"""
        seen = set()
        for x in [md for md, _, _ in refs] + [d]:
            while x not in seen:
                seen.add(x)
                why = self.uncertain(x)
                if why:
                    return why
                if x == "":
                    break
                x = posixpath.dirname(x)
        return None

    def dir_built(self, d, depth=0):
        if d == "":
            return Res(True)
        key = ("d", d)
        if key in self.memo:
            return self.memo[key] or Res(None, why=["cycle"])
        self.memo[key] = None
        refs = self.dir_refs.get(d, [])
        parent = posixpath.dirname(d)
        parts = d.split("/")
        if not refs:
            if parts[0] == "arch" and len(parts) >= 2 and parts[1] != self.srcarch and self.arch_rule:
                r = Res(False, why=[f"{d} is for another architecture ({parts[1]}; the kernel is {self.srcarch})"])
            else:
                up = self.dir_built(parent, depth + 1)
                r = Res(False, up.syms, up.why) if up.value is False else Res(None, why=[f"no Makefile rule descends into {d}/"])
        else:
            vals = []
            for md, base, conds in refs:
                g, frag = self.ref_gate(md)
                vals.append(g if frag else r_and([self.atom(a) for a in conds] + [g]))
            r = r_or(vals)
            if r.value is False:
                why = self.uncertain_chain(parent, refs)
                if why:
                    r = Res(None, r.syms, [why])
        self.memo[key] = r
        return r

    def compiled_elsewhere(self, p):
        """這個物件的原始檔（.c／.S）是否被某個規則的前提列為原始檔，而且那個 Makefile 所在的資料夾可能有編 → 那個資料夾。"""
        stem = posixpath.basename(p)[:-2]
        for pat, md in self.compiled_by.get(posixpath.dirname(p), []):
            for ext in (".c", ".S"):
                if pat_match(pat, stem + ext) and self.dir_built(md).value is not False:
                    return md or "(root)"
        return None

    def obj_built(self, p, depth=0):
        key = ("o", p)
        if key in self.memo:
            return self.memo[key] or Res(None, why=["cycle"])
        self.memo[key] = None
        refs = self.obj_refs.get(p, [])
        d = posixpath.dirname(p)
        if not refs:
            # 這個核心的 Makefile 沒有提到這個物件：檔案可能是 6.8 之後才加的或搬過家（programFiles 是修補當時主線的路徑），
            # 程式可能在別的位置。所以就算上層資料夾沒編也不判「沒編」，只有其他架構的 arch/<X>/ 例外。
            parts = p.split("/")
            if parts[0] == "arch" and len(parts) >= 3 and parts[1] != self.srcarch and self.arch_rule:
                r = Res(False, why=[f"arch/{parts[1]}/ is for another architecture (the kernel is {self.srcarch})"])
            else:
                r = Res(None, why=[f"no Makefile rule in this kernel builds {p} (file added or moved after this kernel?)"])
        else:
            vals = []
            for md, base, conds in refs:
                cs = [self.atom(a) for a in conds]
                if base in LIST_BASES:
                    gate, frag = self.ref_gate(md)
                    v = gate if frag else r_and(cs + [gate])
                    if v.value is True and any("?" in c.modules for c in cs):
                        v.modules = {posixpath.join(md, posixpath.basename(p))[:-2] + ".ko"}
                else:
                    xo = posixpath.join(md, base + ".o")
                    frag = self.ref_gate(md)[1]
                    gate = (self.ref_gate(md)[0] if frag else self.obj_built(xo, depth + 1) if xo in self.obj_refs
                            else Res(None, why=[f"{base}-y lists it but no rule in this kernel's Makefiles names {base}.o "
                                                f"(it may be used by another rule, e.g. linked into another object)"]))
                    v = gate if frag else r_and(cs + [gate])
                    v.modules = set(gate.modules) if v.value is True else set()
                vals.append(v)
            r = r_or(vals)
            if r.value is False:
                why = self.uncertain_chain(d, refs)
                if why:
                    r = Res(None, r.syms, [why])
        if r.value is False:
            other = self.compiled_elsewhere(p)
            if other:
                r = Res(None, r.syms, [f"{other}/Makefile has a rule that compiles {p[:-2]}.* (built from that directory, "
                                       "not only through this directory's object lists)"])
        r.modules.discard("?")
        self.memo[key] = r
        return r


NON_KERNEL_TOP = ("Documentation", "tools", "scripts", "LICENSES", "usr")
# 會被別的 .c 以 #include 帶進去的檔案：Makefile 看不到（headers 套件也沒有 .c 可以查），一律不判「沒編」。
# 例：drivers/firmware/efi/libstub/zboot.c（CONFIG_EFI_ZBOOT）include lib/decompress_*.c，再帶進 lib/xz/、lib/lz4/、lib/xxhash.c；
# sound/pci/ens1371.c include "ens1370.c"；fs/compat_binfmt_elf.c include fs/binfmt_elf.c。
# 清單來自上游原始碼（data/kernel-included-c-<版本>.json，kernel_included_c.py 產生）；所有版本的清單合併後套用到任何核心
# （多算只會讓結果偏向 unknown）。下面的前綴另外保留。核心的主.次版本沒有自己的清單時，別的版本的清單不夠
# （那個版本才有的 #include 不在內），judge_cve 一律不給 not_affected（included_c_versions）。
INCLUDED_C_DATA = Path(__file__).resolve().parent / "data"
INCLUDED_C_SCHEMA = "sca-center-kernel-included-c/1"


@functools.lru_cache(maxsize=1)
def included_c():
    """data/kernel-included-c-*.json 合併 → {樹內路徑: [include 它的檔案]}。沒有或格式不對 → InputError（不能少了這份清單就判 not_affected）。"""
    got = {}
    paths = sorted(INCLUDED_C_DATA.glob("kernel-included-c-*.json"))
    if not paths:
        raise InputError(f"沒有 {INCLUDED_C_DATA}/kernel-included-c-*.json（會被 #include 的 .c 清單）")
    for p in paths:
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, ValueError) as e:
            raise InputError(f"{p.name} 讀不了（{type(e).__name__}）")
        fs = doc.get("files") if isinstance(doc, dict) and doc.get("schema") == INCLUDED_C_SCHEMA else None
        if not isinstance(fs, dict) or not fs or not all(isinstance(k, str) and isinstance(v, list) and all(isinstance(x, str) for x in v)
                                                         for k, v in fs.items()):
            raise InputError(f"{p.name} 不是 {INCLUDED_C_SCHEMA}")
        for k, v in fs.items():
            got.setdefault(posixpath.normpath(k), set()).update(v)
    return {k: sorted(v) for k, v in got.items()}


@functools.lru_cache(maxsize=1)
def included_c_versions():
    """有清單的核心主.次版本（data 檔的 kernel 欄位，例如 {"6.8"}）。"""
    out = set()
    for p in sorted(INCLUDED_C_DATA.glob("kernel-included-c-*.json")):
        try:
            v = json.loads(p.read_text(encoding="utf-8")).get("kernel")
        except (OSError, UnicodeDecodeError, ValueError, AttributeError):
            continue
        if isinstance(v, str) and re.fullmatch(r"\d+\.\d+", v):
            out.add(v)
    return out


def major_minor(ver):
    m = re.match(r"^(\d+)\.(\d+)", str(ver or ""))
    return f"{m.group(1)}.{m.group(2)}" if m else None


INCLUDED_C_PREFIXES = ("lib/decompress_", "lib/xz/", "lib/lz4/", "lib/zlib_", "lib/zstd/", "lib/lzo/", "lib/inflate.c",
                       "lib/xxhash.c", "lib/crc32.c", "lib/ctype.c", "lib/string.c", "lib/cmdline.c", "lib/fdt", "fs/binfmt_elf.c")


def classify_file(path):
    """programFiles 的一個路徑 → ('object', 物件路徑) 或 ('unknown', 原因)。"""
    p = posixpath.normpath(path)
    if p.startswith("..") or p.startswith("/") or not p or len(p) > 400:
        return "unknown", "invalid path"
    top = p.split("/", 1)[0]
    if top in NON_KERNEL_TOP:
        return "unknown", f"{top}/ is not judged (conservative)"
    base = posixpath.basename(p)
    if base.endswith(".h"):
        return "unknown", "header file"
    inc = included_c().get(p)
    if inc:
        return "unknown", (f"also compiled by #include from {', '.join(inc[:2])}" + (", …" if len(inc) > 2 else "")
                           + " (not visible in Makefiles)")
    if p.startswith(INCLUDED_C_PREFIXES):
        return "unknown", "also compiled by #include from other source files (not visible in Makefiles)"
    if base in ("Kconfig", "Makefile", "Kbuild") or base.startswith(("Kconfig.", "Makefile.")):
        return "unknown", "build file"
    for ext in (".c", ".S", ".rs"):
        if base.endswith(ext) and not base.endswith(".lds.S"):
            return "object", p[: -len(ext)] + ".o"
    return "unknown", "not a source file"


def other_arch_included_only(model, path):
    """arch/<其他架構>/ 底下被 #include 的 .c（data/kernel-included-c-*.json），而且 #include 它的檔案也都在其他架構的 arch/ 底下：
    根目錄只進 arch/$(SRCARCH)/，整個其他架構都不編，所以不必因為「可能被別的檔案 #include」而 unknown。有任何一個 #include 它的檔案不在其他架構
    （例如 lib/ 或本架構）→ False（照舊 unknown）。"""
    p = posixpath.normpath(path)
    parts = p.split("/")
    srcarch = getattr(model, "srcarch", None)
    if len(parts) < 3 or parts[0] != "arch" or not srcarch or parts[1] == srcarch or not p.endswith((".c", ".S", ".rs")):
        return False
    inc = included_c().get(p)
    return bool(inc) and all(x.startswith("arch/") and len(x.split("/")) > 2 and x.split("/")[1] != srcarch for x in inc)


def module_present(m, mods):
    """樹內的模組路徑（drivers/x/foo.ko）是否在模組目錄的檔案清單裡（kernel/drivers/x/foo.ko[.zst]；模組名稱的 - 與 _ 視為相同）。"""
    want = m.replace("-", "_")
    for k in mods:
        for ext in MODULE_EXT:
            if k.endswith(ext):
                k = k[: -len(ext)] + ".ko"
                break
        k = k.replace("-", "_")
        if k == "kernel/" + want or k.endswith("/" + want):
            return True
    return False


def module_names(model, obj):
    """一個物件可能出現的模組 → {名稱: 樹內組合物件的模組路徑或 None}（名稱是檔名，- 與 _ 視為相同）。
    物件本身的名稱（None：樹內的這個模組已判定沒編，模組目錄裡有就是矛盾），加上把它列為組成的組合物件
    （snd-soc-tegra210-admaif-objs := tegra210_admaif.o → snd_soc_tegra210_admaif；值是 drivers/…/snd-soc-tegra210-admaif，
    模組目錄裡正好是 kernel/<這個路徑>.ko 的是樹內的同一個模組：這個檔案只是依 config 沒放進去，不算）。"""
    names = {posixpath.basename(obj)[:-2].replace("-", "_"): None}
    for md, base, _ in model.obj_refs.get(obj, []):
        if base not in LIST_BASES and base:
            names.setdefault(posixpath.basename(base).replace("-", "_"), posixpath.join(md, base).replace("-", "_"))
    return names


def shipped_modules(mods):
    """模組目錄的 .ko → {檔名: {去掉副檔名的相對路徑}}（- 與 _ 視為相同）。"""
    out = {}
    for k in mods or ():
        for ext in MODULE_EXT:
            if k.endswith(ext):
                stem = k[: -len(ext)].replace("-", "_")
                out.setdefault(posixpath.basename(stem), set()).add(stem)
                break
    return out


def same_name_modules(model, files, mods):
    shipped, dup = shipped_modules(mods), set()
    for f in files:
        kind, obj = classify_file(f)
        if kind != "object":
            continue
        for n, inplace in module_names(model, obj).items():
            for stem in shipped.get(n, ()):
                if inplace is None or stem != "kernel/" + inplace:
                    dup.add(stem)
    return sorted(dup)


def module_list_keys(data):
    """modules.order／modules.builtin 的內容 → {(資料夾, 檔名（- 換成 _）): 原文}（去掉 kernel/ 與副檔名）。"""
    out = {}
    for l in data.decode("utf-8", "replace").splitlines():
        s = l.strip()
        for ext in MODULE_EXT + (".o",):
            if s.endswith(ext):
                s = s[: -len(ext)]
                break
        else:
            continue
        s = s[len("kernel/"):] if s.startswith("kernel/") else s
        out.setdefault((posixpath.dirname(s), posixpath.basename(s).replace("-", "_")), l.strip())
    return out


def image_module_lists(model):
    """映像的 modules.order／modules.builtin（有擷取到的）→ {檔名: module_list_keys}；沒有 → {}。"""
    got = getattr(model, "_module_lists", None)
    if got is None:
        fs = (getattr(model.info, "modules", None) or {}).get("files") or {}
        got = {n: module_list_keys(fs[n]) for n in ("modules.order", "modules.builtin") if n in fs}
        model._module_lists = got
    return got


def image_mapper(model):
    """映像的模組清單建成的 kernel_module_map.Mapper（記在 model 上）。"""
    mp = getattr(model, "_image_mapper", None)
    if mp is None:
        km, mods = module_map(), getattr(model.info, "modules", None) or {}
        fs = mods.get("files") or {}
        mp = km.Mapper(model, mods.get("ko"), km.ModList(fs["modules.order"]) if "modules.order" in fs else None,
                       km.ModList(fs["modules.builtin"]) if "modules.builtin" in fs else None)
        model._image_mapper = mp
    return mp


def listed_contradiction(model, obj, mapper=None):
    """Kbuild 判「沒編」（False）的物件，映像的模組清單卻列了它 → 說明；沒有 → None。
    看物件本身，以及把它列為成員的組合物件（每一層）裡 Kbuild 也判沒編的那些。組合物件有編、只是這個成員依 config 沒放進去時，
    清單列那個組合模組是正常的——但組合物件本身要和清單一致（=m：modules.order 在同一個路徑有、modules.builtin 沒有；
    =y：modules.order 沒有；modules.builtin 只列帶模組資訊的物件，不要求），不一致或核對不了 → 說明。清單沒有擷取到時不核對（limitations 註明）。"""
    lists = image_module_lists(model)
    if not lists:
        return None
    todo, seen = [(obj, 0)], set()
    while todo:
        o, depth = todo.pop()
        if o in seen:
            continue
        seen.add(o)
        stem = o[:-2]
        k = (posixpath.dirname(stem), posixpath.basename(stem).replace("-", "_"))
        ob = None if o == obj else model.obj_built(o).value
        if o == obj or ob is False:
            for n, keys in lists.items():
                if k in keys:
                    return f"{n} lists {keys[k]}"
        elif ob is True:
            why = (mapper or image_mapper(model)).composite_doubt(o)
            if why:
                return f"configured-out member of the composite {o}, which does not match the module lists: {why}"
        if depth < 8:
            todo += [(posixpath.join(md, base + ".o"), depth + 1) for md, base, _ in model.obj_refs.get(o, []) if base not in LIST_BASES]
    return None


@functools.lru_cache(maxsize=None)
def module_map():
    return _load("sca_center_kernel_module_map", HERE / "kernel_module_map.py")


def other_arch_build_file(model, path):
    """arch/<其他架構>/ 底下的 Makefile／Kbuild／Kconfig（含 Makefile.*、Kconfig.*）→ 理由；其他 → None。
    根目錄只讀 arch/$(SRCARCH)/ 的 Makefile 與 Kconfig（同 obj_built 對 arch/<其他>/ 的 .c），所以這些檔案不影響這個核心。"""
    p = posixpath.normpath(path)
    parts = p.split("/")
    if len(parts) < 3 or parts[0] != "arch" or parts[1] in (model.srcarch, "", ".", "..") or ".." in parts \
            or not getattr(model, "arch_rule", False):
        return None
    if classify_file(p) != ("unknown", "build file"):
        return None
    return (f"arch/{parts[1]}/ is for another architecture (the kernel is {model.srcarch}): {parts[-1]} there is only read "
            f"when building for {parts[1]}")


def judge_cve(model, files, mods, mapper=None, brec=None, new_code=None):
    """一個 CVE 的 programFiles → (decision, detail, files[], config_values)。
    not_affected 之前另外核對模組目錄（含 updates/、extra/ 的 out-of-tree 模組）：有同名的 .ko（例如 nvidia-oot 帶的上游程式複本）
    → unknown。沒有模組清單（mods 是 None）時無法核對，也是 unknown。Kbuild 判沒編、映像的 modules.builtin／modules.order 卻列了
    它（listed_contradiction）→ 那個檔案是 None（unknown）。
    每個檔案另記 built_as：有編時依 kernel_module_map.py 的對應是 "builtin" 或 "module"，其他（沒編、不知道、對應不確定）是 null。
    brec：驗證過的建置紀錄（RecordJudge）。有的時候，樹內的原始檔與標頭檔改由紀錄判斷（RecordJudge.judge；每個檔案多一個 evidence），
    其他檔案與 CVE 的規則（含 #include 清單的版本規則）不變。built_as 只在 Makefile 的規則
    也判有編時沿用模組對應，其他是 null。"""
    out, vals, rs = [], {}, []
    ekey = {"evidence": None} if brec is not None else {}
    for f in files:
        kind, x = classify_file(f)
        if kind != "object" and other_arch_included_only(model, f):
            ext = next(e for e in (".c", ".S", ".rs") if f.endswith(e))
            kind, x = "object", posixpath.normpath(f)[:-len(ext)] + ".o"           # 其他架構的 #include 對象：當一般的其他架構檔案（沒編）
        oa = other_arch_build_file(model, f) if kind != "object" else None
        if oa:
            # 只改了其他架構的 Makefile／Kconfig：和其他架構的 .c 一樣算「沒編」（判定的其餘規則不變）
            out.append({"path": f, "configs": [], "built": False, "built_as": None, "module": None, **ekey})
            rs.append((f, Res(False, why=[oa]), "other_arch"))
            continue
        obj = RecordJudge.eligible(f) if brec is not None else None
        if obj is not None:
            r, ev = brec.judge(model, f, obj, new_code)
            syms = sorted(s for s in r.syms if s.startswith("CONFIG_"))
            built_as = module = None
            if r.value is True and mapper is not None and obj and model.obj_built(obj).value is True:
                mr = mapper.map_file(f)
                built_as = mr["build"] if mr["build"] in ("builtin", "module") else None
                module = mr["module"] if built_as == "module" else None
            out.append({"path": f, "configs": syms, "built": r.value, "built_as": built_as, "module": module, "evidence": ev})
            for s in syms:
                v = model.config.get(s)
                vals[s] = v if v is not None else "unset"
            rs.append((f, r, "record"))
            continue
        if kind != "object":
            out.append({"path": f, "configs": [], "built": None, "built_as": None, "module": None, **ekey})
            rs.append((f, Res(None, why=[x]), kind))
            continue
        r = model.obj_built(x)
        if r.value is False:
            hit = listed_contradiction(model, x, mapper)
            if hit:
                r = Res(None, r.syms, [hit if hit.startswith("configured-out member") else
                                       f"Kbuild says not built but modules.builtin/modules.order lists it ({hit})"])
        syms = sorted(s for s in r.syms if s.startswith("CONFIG_"))
        built_as = module = None
        if r.value is True and mapper is not None:
            mr = mapper.map_file(f)
            built_as = mr["build"] if mr["build"] in ("builtin", "module") else None
            module = mr["module"] if built_as == "module" else None
        out.append({"path": f, "configs": syms, "built": r.value, "built_as": built_as, "module": module, **ekey})
        for s in syms:
            v = model.config.get(s)
            vals[s] = v if v is not None else "unset"
        rs.append((f, r, kind))
    if any(r.value is True for _, r, _ in rs):
        on = [(f, r) for f, r, _ in rs if r.value is True]
        msg = "; ".join(f"{f} is built ({r.why[0] if k == 'record' else ' && '.join(sorted(r.syms)) or 'always'})"
                        for f, r, k in [x for x in rs if x[1].value is True][:3])
        modn = sorted({m for _, r in on for m in r.modules})
        if modn:
            pres = [m for m in modn if mods is not None and module_present(m, mods)]
            msg += (f"; built as module {', '.join(modn[:3])}" + (f" (present in /usr/lib/modules: {', '.join(pres[:3])})" if pres else
                                                                  " (no such .ko in /usr/lib/modules; still counted as built)" if mods is not None else ""))
        return "affected", msg, out, vals
    if rs and all(r.value is False for _, r, _ in rs):
        mm = major_minor(getattr(model, "kver_hdr", None))
        if mm not in included_c_versions():
            return ("unknown", f"no list of #included .c files for kernel {mm or 'of unknown version'} "
                    f"(lists exist for {', '.join(sorted(included_c_versions())) or 'none'}): a file that is not built by its own "
                    "Makefile rule may still be compiled through #include", out, vals)
        if mods is None:
            return ("unknown", "the fix's program files are not built in-tree, but there is no module directory to check for "
                    "out-of-tree modules that carry copies of them", out, vals)
        dup = same_name_modules(model, [f for f, _, _ in rs], mods)
        if dup:
            return ("unknown", "the fix's program files are not built in-tree, but the module directory has a module with the same "
                    f"name ({', '.join(dup[:3])}; for example an out-of-tree copy of the upstream code)", out, vals)
        syms = sorted({s for _, r, _ in rs for s in r.syms if s.startswith("CONFIG_")})
        reasons = []
        for f, r, k in rs[:6]:
            ss = sorted(s for s in r.syms if s.startswith("CONFIG_")) if k != "record" else []
            reasons.append(f"{f} ({', '.join(f'{s}={vals.get(s, model.config.get(s) or 'unset')}' for s in ss)})" if ss else
                           f"{f} ({'; '.join(r.why[:1])})")
        lead = (f"all program files of the fix are built only when {' / '.join(syms)} {'is' if len(syms) == 1 else 'are'} enabled; "
                f"{'it is not' if len(syms) == 1 else 'none of them is'} set in the product kernel .config" if syms else
                "none of the program files of the fix is built for this kernel")
        if any(k == "record" for _, _, k in rs):
            lead = ("the kernel build record shows that no compiled kernel object has any program file of the fix in its source or "
                    "deps" + (f" (Makefile rules: built only when {' / '.join(syms)} {'is' if len(syms) == 1 else 'are'} enabled, "
                              "not set)" if syms else ""))
        if any(k == "other_arch" for _, _, k in rs):
            arches = sorted({posixpath.normpath(f).split("/")[1] for f, _, k in rs if k == "other_arch"})
            ob = f"build files (Makefile/Kbuild/Kconfig) of other architectures only ({', '.join(f'arch/{x}/' for x in arches)}; " \
                 f"the kernel is {model.srcarch})"
            lead = (f"the fix changes {ob}" if all(k == "other_arch" for _, _, k in rs) else
                    f"the fix changes {ob} and files that are not built: {lead}")
        return "not_affected", f"{lead}: " + "; ".join(reasons) + ("; …" if len(rs) > 6 else ""), out, vals
    why = []
    for f, r, kind in rs:
        if r.value is None:
            why.append(f"{f}: {r.why[0] if r.why else 'unknown'}")
    return "unknown", "; ".join(why[:4]) + ("; …" if len(why) > 4 else ""), out, vals


# =====================================================================================================
# 4b. 核心建置紀錄（--build-record：make 之後的建置資料夾，只讀 .cmd 的 source_／deps_ 與幾個清單）
# =====================================================================================================
# 每個物件的 .<物件>.cmd（kbuild 由 gcc -MMD 的 .d 檔轉成）列出這個物件實際編譯的原始檔（source_<物件>）與讀到的每個檔案
# （deps_<物件>：標頭檔、被 #include 的 .c 都在內）。產品出貨時保留這份紀錄，就能直接回答「修補的檔案有沒有編進這個核心」。
# 不可信的資料：只讀 tar 的一般檔案（串流，不解開到磁碟）或資料夾裡的一般檔案（不跟隨連結），名稱正規化（絕對路徑、.. → 不收），
# 單一檔案與合計各有上限，不執行任何東西；只解析 .cmd 的文字、modules.order／modules.builtin、include/config/kernel.release 與 .config。
# 「不在紀錄裡」要能當成「沒編」，紀錄必須完整：從最上層的 vmlinux.o 起，每個 archive（built-in.a、lib.a、vmlinux.a）列的成員、
# 每個 .mod 列的模組成員、每個 modules.order 的模組都要有自己的 .cmd（membership closure）；少一個就 GAP。

MAX_RECORD_MEMBER = 16 << 20       # 單一 .cmd／清單／.config（估計：.cmd 一般最大約 1 MB、.config 約數百 KB；System.map 等不讀）
MAX_RECORD_TOTAL = 4 << 30         # 讀進來的內容合計（估計：6.8 arm64 的完整建置紀錄約數百 MB）
MAX_RECORD_STREAM = 64 << 30       # tar 全部成員（含不讀的 .o、vmlinux 等：串流讀仍要解壓過去）的大小合計
MAX_RECORD_MEMBERS = 3_000_000     # tar 成員或資料夾項目數（估計：一般約數萬個以內）
MAX_RECORD_PATHS = 2_000_000       # source_／deps_ 裡不同的路徑數，也是成員關係（archive／.mod 的成員）的筆數上限（估計：一般約數萬個以內）
MAX_RECORD_EXAMPLES = 5            # 不合格的項目（連結、太大、格式不對、缺 .cmd）只留數量與前幾個例子
MIN_RECORD_OBJECT_CMDS = 200       # 至少要有這麼多個 .<物件>.o.cmd 才算完整（估計：完整的 arm64 核心一般上萬個；最小的核心也有數百個）
# kbuild 連結階段的產物：scripts/link-vmlinux.sh／Makefile.vmlinux* 把其他物件彙整起來（或只帶版本／export 資料），依核心版本與建置流程
# 可能沒有 .cmd。它們不對應任何 CVE 相關的原始檔，缺 .cmd 不拒收整份紀錄；只豁免這個明確清單（樹根的路徑），其他物件仍嚴格要求。
# 這些產物沒有 .cmd，所以不會有任何路徑從它們來；豁免只放過完整性檢查，不用來判斷任何原始檔。
LINK_STAGE_NO_CMD = ("vmlinux.o", "vmlinux.a", "init/version-timestamp.o", ".vmlinux.export.o")
RECORD_LINK_CMDS = (".vmlinux.cmd",)     # 最後的連結（scripts/link-vmlinux.sh）：kbuild 一定寫這個檔；有它才算建置完成
RECORD_FILES = {(".config",): ".config", ("modules.order",): "modules.order", ("modules.builtin",): "modules.builtin",
                ("include", "config", "kernel.release"): "kernel.release",
                ("include", "generated", "utsversion.h"): "utsversion.h", ("include", "generated", "compile.h"): "compile.h"}
BUILD_INFO_NAME = "BUILD-INFO.txt"     # pack-build-record.sh 寫的 image=<路徑> sha256=<雜湊>（在紀錄最上層，不在核心樹裡）
RECORD_MAX_ROOT_DEPTH = 1          # 建置資料夾可以在 tar 裡的一層資料夾底下（例如 kernel-noble/…）
RECORD_SOURCE_EXT = (".c", ".S", ".rs")
CMD_TARGET_RE = re.compile(r"^(?:saved)?cmd_(\S+?)\s*:=(.*)$")
CMD_VAR_RE = re.compile(r"^(source|deps)_(\S+?)\s*:=(.*)$")
CMD_WILDCARD_RE = re.compile(r"\$\(wildcard\s[^)]*\)")
# kbuild 的成員清單（6.x）：built-in.a 是 printf "<資料夾>/%s " a.o b.o … | xargs ar …；lib.a、vmlinux.a 是 ar c… <archive> <成員>…；
# <模組>.mod 是 printf '%s\n' a.o b.o | awk '…print("<資料夾>/"$$0)…'；組合的模組物件以 ld -r -o x.o @x.mod 連結
CMD_PRINTF_ARCHIVE_RE = re.compile(r'printf\s+"([^"%]*)%s "\s+(.*?)\s*\|\s*xargs\s')
CMD_PRINTF_MOD_RE = re.compile(r"printf\s+'%s\\n'\s+(.*?)\s*\|\s*\S*awk\s.*?print\(\"([^\"]*)\"\s*\$\$0\)")
CMD_MODFILE_RE = re.compile(r"(?:^|\s)@(\S+\.mod)(?:\s|$)")
OBJ_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.+,/-]+\.(?:o|a)$")
# 沒有 source_ 的指令（連結、objcopy、strip、ld -r、vDSO 的 .so）裡的建置產物：kvm nVHE 的 *.nvhe.o → kvm_nvhe.tmp.o → kvm_nvhe.rel.o
# → kvm_nvhe.o（objcopy）、libstub 的 *.o → *.stub.o（strip）、pi/*.o → *.pi.o（objcopy）、vdso/*.o → vdso.so.dbg → vdso.so
CMD_TOKEN_RE = re.compile(r"[^\s;|&()<>'\"`=]+")
PRODUCT_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.+,/-]*[A-Za-z0-9_+,-][A-Za-z0-9_.+,/-]*\.(?:o|a|so|so\.dbg)$")   # 可以是 .module-common.o
# 以 .incbin 帶進來、kbuild 的 .cmd 看不到的產物（Makefile 的額外前提）：<資料夾>/vdso-wrap.o ← <資料夾>/vdso/vdso.so（arm64）、
# vdso32-wrap.o ← vdso32/vdso.so（arm64 compat）、<…>/vdso/vdso.o ← <…>/vdso/vdso.so（riscv 等）
INCBIN_RULES = ((re.compile(r"^(.*/)?(vdso|vdso32)-wrap\.o$"), r"\1\2/vdso.so"), (re.compile(r"^(.*/)?vdso/vdso\.o$"), r"\1vdso/vdso.so"))
BUILD_RECORD_LIMITATIONS = [
    "The build record covers the in-tree kernel build only; out-of-tree modules (for example nvidia-oot) are built separately and "
    "their sources and the kernel headers they include are not in it. A header file that no in-tree object depends on is therefore "
    "not judged 'not built' while the module directory has out-of-tree modules.",
    "Host and build tools (targets under scripts/, tools/, usr/include/, and host programs without a file extension) are excluded: "
    "they run on the build machine and are not part of the kernel. Generated module objects (*.mod.o) are included: they are "
    "linked into the shipped .ko files.",
    "A file that is not in any compiled object's source or deps is judged not built only if this kernel's files show it exists "
    "(a Makefile rule names its object, or it is in the kernel headers or source tree read from the image): programFiles are "
    "mainline paths at fix time, and code that was added or moved later may be at another path in this kernel.",
    "If the build record and the Makefile rules disagree (record: not compiled, Makefile rules: built), the file is unknown.",
    "Absolute paths in source_/deps_ are mapped to the tree with the source-tree prefixes inferred from source_ lines; any other "
    "absolute path (for example $(abspath …) in an in-tree build, or a symlinked versus real source path) still counts: a file "
    "is built if such a path ends with /<file>.",
    ".c files on the list of files #included by other sources (data/kernel-included-c-*.json) stay a safety net: unless the "
    "record shows them built they are unknown, as without a record; without a list for the kernel's major.minor version no CVE "
    "is judged not_affected, record or not.",
    "The record is used only if its .config matches the configuration K1 judges with (identical, or differing only in "
    "toolchain-derived options), include/config/kernel.release (if present) equals the kernel version, it is complete "
    "(.config, modules.order, the final link command .vmlinux.cmd, no truncated .cmd file, at least "
    + str(MIN_RECORD_OBJECT_CMDS) + " object .cmd files, "
    "and a .cmd for every member of every archive and .mod, every build product named by a link/objcopy/strip command, the "
    "final vmlinux inputs, the .incbin'd vDSO and every module in modules.order), and its "
    "modules.order/modules.builtin match the image's lists (when the image has them). Otherwise it is ignored (GAP).",
    "A kernel/ module of the image that is not in the record's modules.order does not reject the record (the vendor may have added "
    "modules to the image): the objects of such a module that this kernel's Makefiles name are never judged not built (unknown), "
    "modules are classified by their own .modinfo (intree) and the Makefiles (kernel.build_record.image_modules_not_in_record, classes 2-5): an "
    "in-tree-flagged (or unreadable) module that no Makefile rule names makes every in-tree source file that the record does not show built "
    "unknown; an out-of-tree vendor module with no in-tree namesake is listed as GAP (not assessed) and protects nothing.",
]
EXTRA_MODULES_MAX = 200            # image_modules_not_in_record.modules 最多列幾個（總數另計）
EXTRA_OBJECTS_MAX = 50             # 一個模組最多列幾個物件
EXTRA_WHY = "the shipped image has this module, but the build record does not (出貨映像有這個模組，但建置紀錄沒有)"
RECORD_RELEASE_LIMITATION = (
    "The record has no include/config/kernel.release: it was accepted because its .config is identical and its modules.order and "
    "modules.builtin match the judged kernel and the image (kernel_release_checked is false).")
RECORD_NOT_TIED_LIMITATION = (
    "The record is not tied to the shipped kernel Image: it has no build-identity file (include/config/kernel.release, "
    "include/generated/utsversion.h, include/generated/compile.h) to compare with the Image's version banner, or the Image's "
    "banner could not be read; it was accepted because its .config and module lists match. A record of another build of the same "
    "version and configuration (for example with other patches) would also pass: keep include/generated/ and "
    "include/config/kernel.release in the record.")
RECORD_NO_VERSION_LIMITATION = (
    "The kernel version being judged is not known (no module directory or --kernel-version): include/config/kernel.release "
    "was not compared (kernel_release_checked is false).")


class RecordLimit(Exception):
    pass


class Examples:
    """數量＋前 MAX_RECORD_EXAMPLES 個例子（不合格的項目不無限累積）。"""
    __slots__ = ("n", "ex")

    def __init__(self):
        self.n, self.ex = 0, []

    def add(self, x):
        self.n += 1
        if len(self.ex) < MAX_RECORD_EXAMPLES:
            self.ex.append(x)

    def text(self):
        return ", ".join(self.ex) + (", …" if self.n > len(self.ex) else "")


def record_parts(name):
    """建置紀錄的成員名稱 → 路徑元件；絕對路徑、含 ..、空的 → None（不收）。"""
    if name.startswith("/"):
        return None
    parts = tuple(p for p in name.split("/") if p not in ("", "."))
    if not parts or any(p == ".." for p in parts):
        return None
    return parts


def cmd_words(s):
    """deps_／source_ 的一段文字 → 路徑（去掉 $(wildcard …)、續行的 \\、看起來不是路徑的字）。"""
    s = CMD_WILDCARD_RE.sub(" ", s)
    return [w for w in s.split() if w != "\\" and "$" not in w and not w.endswith(":")]


def parse_cmd(text):
    """.cmd 的文字 → (目標, source 路徑, deps 路徑, source_／deps_ 用到的目標名稱, 指令, 有沒有 deps_ 那一行)。只認 kbuild 的格式：
    第一行 savedcmd_<目標> := <指令>（舊版 cmd_<目標> :=），source_<目標> := <檔案>，deps_<目標> := \\ 之後一行一個檔案。"""
    target, saved, src, deps, keys, cur, has_deps = None, "", [], [], set(), None, False
    for raw in text.splitlines():
        if cur is not None:
            s = raw.rstrip()
            cont = s.endswith("\\")
            cur.extend(cmd_words(s[:-1] if cont else s))
            cur = cur if cont else None
            continue
        if target is None:
            m = CMD_TARGET_RE.match(raw)
            if m:
                target, saved = m.group(1), m.group(2).strip()
                continue
        m = CMD_VAR_RE.match(raw)
        if m:
            keys.add(m.group(2))
            has_deps = has_deps or m.group(1) == "deps"
            lst = src if m.group(1) == "source" else deps
            s = m.group(3).rstrip()
            cont = s.endswith("\\")
            lst.extend(cmd_words(s[:-1] if cont else s))
            cur = lst if cont else None
    return target, src, deps, keys, saved, has_deps


def obj_norm(t):
    """成員或目標的路徑 → 正規化的樹內路徑；超出樹或絕對路徑 → None。"""
    if t.startswith("/"):
        return None
    p = posixpath.normpath(t)
    return None if p.startswith("..") or p in (".", "") else p


def cmd_members(target, saved, compile_cmd=False):
    """一個 .cmd 的指令 → 它要求存在的成員（樹內路徑的 list）；看不懂（archive 或 .mod 的成員清單不是 kbuild 的格式）→ None。
    archive（.a）：printf 的 built-in.a，或 ar c… <archive> <成員>…（lib.a、vmlinux.a），成員每一個都要是物件或 archive 的路徑；
    .mod：printf＋awk 的成員；其他沒有 source_ 的指令（連結、objcopy、strip、ld -r、vDSO 的 .so…）：指令裡每個樹內的
    *.o／*.a／*.so／*.so.dbg，以及 @x.mod 的 x.mod。編譯指令（有 source_）→ []（它讀的檔案在 deps_）。"""
    out = []
    if target.endswith(".mod"):
        m = CMD_PRINTF_MOD_RE.search(saved)
        if not m:
            return None
        pre = m.group(2)
        toks = m.group(1).split()
        out = [pre + t for t in toks if OBJ_TOKEN_RE.match(t)]
        if len(out) != len(toks):
            return None
    elif target.endswith(".a"):
        m = CMD_PRINTF_ARCHIVE_RE.search(saved)
        if m:
            toks = m.group(2).split()
            out = [m.group(1) + t for t in toks if OBJ_TOKEN_RE.match(t)]
            if len(out) != len(toks):
                return None
        else:
            found = False
            for part in saved.split(";"):
                w = part.split()
                if len(w) >= 3 and posixpath.basename(w[0]).endswith("ar") and w[1].startswith("c") and \
                        obj_norm(w[2]) == obj_norm(target):
                    if not all(OBJ_TOKEN_RE.match(t) for t in w[3:]):
                        return None
                    out += w[3:]
                    found = True
            if not found:
                return None
    elif not compile_cmd:
        out = [t for t in CMD_TOKEN_RE.findall(saved) if PRODUCT_TOKEN_RE.match(t) and obj_norm(t) is not None]
        out += CMD_MODFILE_RE.findall(saved)
    got = [obj_norm(x) for x in out]
    return None if any(x is None for x in got) else sorted({x for x in got if x != obj_norm(target)})


# 編譯指令的特徵：產生依賴檔的旗標（kbuild 的 if_changed_dep；fixdep 會把它轉成 source_／deps_）。6.8 arm64 上萬個編譯 .cmd
# 除了一個以外都帶 -Wp,-MMD（那一個是 vmlinux 的 link-vmlinux.sh，有 source_）；不帶 source_ 卻有這個旗標的只有 lib/test_fortify/*.log
CMD_DEPFLAG_RE = re.compile(r"(?:^|\s)(?:-Wp,-MMD,|-MMD?(?=\s|$)|-MD(?=\s|$)|--emit=dep-info)")
COMPILE_TARGET_EXT = (".o", ".s", ".i", ".lds", ".dtb", ".dtbo", ".ll", ".rsi")
# 沒有 source_ 的 .o：只能是連結類的指令（ld［-r、@x.mod］、objcopy、strip；前面可以有 rm -f …;）
LINK_TOOL_RE = re.compile(r"(?:^|[/-])(?:ld(?:\.bfd|\.lld|\.gold)?|objcopy|strip)$")


def cmd_first_tool(saved):
    """指令的第一個程式（略過開頭的 rm -f …;）的檔名。"""
    for part in saved.split(";"):
        w = part.split()
        if not w:
            continue
        if w[0] == "rm":
            continue
        return posixpath.basename(w[0])
    return ""


def cmd_kind_ok(target, saved, has_src):
    """依指令（不是依有沒有 source_）判斷：看起來是編譯（帶依賴檔旗標、目標是 .o／.s／.lds／.dtb…）卻沒有 source_ → 被截斷；
    沒有 source_ 的 .o 只能是 ld／objcopy／strip。"""
    if has_src:
        return True
    t = posixpath.normpath(target)
    if t.endswith(COMPILE_TARGET_EXT) and CMD_DEPFLAG_RE.search(saved):
        return False
    if t.endswith(".o") and not LINK_TOOL_RE.search(cmd_first_tool(saved)):
        return False
    return True


def cmd_complete(text, target, compile_cmd, has_deps):
    """kbuild 寫的 .cmd 是完整的：以換行結尾；編譯指令有 deps_ 與結尾的兩行；其他指令只有 savedcmd_ 一行（其餘是空行）。"""
    if not text.endswith("\n"):
        return False
    if not compile_cmd:
        return not any(l.strip() for l in text.split("\n")[1:])
    if not has_deps:
        return False
    lines = {l.rstrip() for l in text.split("\n")}
    return f"{target}: $(deps_{target})" in lines and f"$(deps_{target}):" in lines


def cmd_root(parts, target):
    """.cmd 的位置（成員的路徑元件）＋內容的目標 → 建置樹的根（路徑元件）。kbuild 的規則：<根>/<資料夾>/.<名稱>.cmd 的目標是
    <資料夾>/<名稱>（相對於建置樹的根；目標可以含 ..，例如 arch/arm64/kvm/../../../virt/kvm/x.o，正規化後比對）。
    對不上、正規化後超出樹，或根超過 RECORD_MAX_ROOT_DEPTH 層 → None。"""
    name = parts[-1]
    t = posixpath.normpath(target)
    if target.startswith("/") or t.startswith("..") or t == ".":
        return None
    tp = tuple(x for x in t.split("/") if x not in ("", "."))
    if not tp or ".." in tp or tp[-1] != name[1:-len(".cmd")]:
        return None
    d, td = parts[:-1], tp[:-1]
    if len(td) > len(d) or d[len(d) - len(td):] != td:
        return None
    root = d[:len(d) - len(td)]
    return root if len(root) <= RECORD_MAX_ROOT_DEPTH else None


def host_target(t):
    """建置機器上執行的程式（不是核心的一部分）：scripts/、tools/、usr/include/（UAPI 標頭的使用者空間編譯測試），
    以及沒有副檔名的主機程式（例如 lib/gen_crc32table、usr/gen_init_cpio；vmlinux 除外）。"""
    tp = t.split("/")
    return tp[0] in ("scripts", "tools") or t.startswith("usr/include/") or ("." not in tp[-1] and t != "vmlinux")


def new_root():
    return {"cmds": 0, "obj_cmds": 0, "host": 0, "names": set(), "paths": {}, "prefix": {}, "targets": set(), "reqs": []}


class BuildRecord:
    """讀進來的建置紀錄（還沒驗證）。roots：{根: {"cmds", "obj_cmds", "host", "names", "paths": {原始路徑: (物件, "source"／"deps")},
    "prefix": {原始碼樹前綴: 次數}, "targets": 所有 .cmd 的目標（正規化）, "reqs": [(成員, 列它的目標)]}}；
    files：RECORD_FILES 的候選（成員路徑 → bytes）。"""

    def __init__(self, path):
        self.path = path
        self.label = os.path.basename(os.path.normpath(path)) or path
        self.roots, self.files = {}, {}
        self.read = self.members = self.rejected = self.ignored_links = self.nreqs = 0
        self.needed_links, self.oversize, self.anomalies = Examples(), Examples(), Examples()
        self.error = None

    @staticmethod
    def record_file(parts):
        if len(parts) <= 2 and parts[-1] == BUILD_INFO_NAME:
            return True
        for rel in RECORD_FILES:
            n = len(parts) - len(rel)
            if 0 <= n <= RECORD_MAX_ROOT_DEPTH and parts[n:] == rel:
                return True
        return False

    def feed(self, parts, kind, opener, size):
        self.members += 1
        if self.members > MAX_RECORD_MEMBERS:
            raise RecordLimit(f"more than {MAX_RECORD_MEMBERS} entries")
        if parts is None:
            self.rejected += 1              # 絕對路徑或含 ..：不收
            return
        name = parts[-1]
        is_cmd = name.startswith(".") and name.endswith(".cmd") and len(name) > len("..cmd")
        if not is_cmd and not self.record_file(parts):
            if kind not in ("file", "dir"):
                self.ignored_links += 1
            return
        if kind == "dir":
            return
        if kind != "file":
            self.needed_links.add("/".join(parts))         # 需要的檔案是連結或其他：不跟隨（之後 GAP）
            return
        if size > MAX_RECORD_MEMBER:
            self.oversize.add("/".join(parts))
            return
        if self.read + size > MAX_RECORD_TOTAL:
            raise RecordLimit(f"more than {MAX_RECORD_TOTAL >> 20} MB of .cmd and list files")
        data = read_all(opener, size)
        self.read += len(data)
        if not is_cmd:
            self.files[parts] = data
            return
        self.add_cmd(parts, data.decode("utf-8", "replace"))

    def add_cmd(self, parts, text):
        target, src, deps, keys, saved, has_deps = parse_cmd(text)
        root = cmd_root(parts, target) if target else None
        mem = cmd_members(target, saved, bool(src)) if root is not None else None
        # 被截斷的 .cmd 不能用（看得到的成員或 deps 只是一部分，closure 也只會要求看得到的）：kbuild 寫的 .cmd 一定以換行結尾；
        # 編譯指令（有 source_）有 deps_，而且最後有 "<目標>: $(deps_<目標>)" 與 "$(deps_<目標>):" 兩行（之後可能還有 #SYMVER）；
        # 其他指令（連結、ar、objcopy…）只有 savedcmd_ 那一行
        if (root is None or keys - {target} or mem is None or not cmd_complete(text, target, bool(src), has_deps)
                or not cmd_kind_ok(target, saved, bool(src))):
            self.anomalies.add("/".join(parts))
            return
        r = self.roots.setdefault(root, new_root())
        r["cmds"] += 1
        r["targets"].add(posixpath.normpath(target))
        self.nreqs += len(mem)
        if self.nreqs > MAX_RECORD_PATHS:
            raise RecordLimit(f"more than {MAX_RECORD_PATHS} archive/module members")
        r["reqs"].extend((m, target) for m in mem)
        if len(parts) == len(root) + 1:
            r["names"].add(parts[-1])
        if target.endswith(".o"):
            r["obj_cmds"] += 1
        if host_target(target):
            r["host"] += 1
            return
        paths = r["paths"]
        for how, lst in (("source", src), ("deps", deps)):
            for p in lst:
                cur = paths.get(p)
                if cur is None:
                    if len(paths) >= MAX_RECORD_PATHS:
                        raise RecordLimit(f"more than {MAX_RECORD_PATHS} distinct source/deps paths")
                    paths[p] = (target, how)
                elif how == "source" and cur[1] != "source":
                    paths[p] = (target, how)
        if target.endswith(".o"):
            stem = target[:-2]
            for s in src:
                for ext in RECORD_SOURCE_EXT:
                    if s.endswith(stem + ext):
                        pre = s[:-len(stem + ext)]
                        # 只認原始碼樹的前綴：絕對路徑（O= 建置）或只有 ../ 的相對路徑；其他（例如一個奇怪的 .cmd 讓 "drivers/" 變成前綴）不收
                        if pre and (len(pre) > 1 and pre.startswith("/") and pre.endswith("/") or re.fullmatch(r"(?:\.\./)+", pre)):
                            r["prefix"][pre] = r["prefix"].get(pre, 0) + 1
                        break


def record_entries_dir(top):
    """資料夾 → (路徑元件, 種類, opener, 大小)。不跟隨連結（資料夾連結也不走進去），一般檔案以 O_NOFOLLOW 打開。"""
    fp = flash_package()
    root = os.path.abspath(top)
    for d, dirs, files in os.walk(root, followlinks=False):
        rel = os.path.relpath(d, root)
        rp = () if rel == "." else tuple(rel.split(os.sep))
        keep = []
        for n in sorted(dirs) + sorted(files):
            p = os.path.join(d, n)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            parts = rp + (n,)
            if stat.S_ISDIR(st.st_mode):
                keep.append(n)
                yield parts, "dir", None, 0
            elif stat.S_ISREG(st.st_mode):
                yield parts, "file", (lambda p=p: fp.open_nofollow(p)), st.st_size
            else:
                yield parts, "symlink" if stat.S_ISLNK(st.st_mode) else "other", None, 0
        dirs[:] = [x for x in dirs if x in keep]


def record_entries_tar(t):
    total = 0
    while True:
        m = t.next()
        if m is None:
            break
        t.members.clear()                 # 記憶體不隨成員數增加
        k = tar_kind(m)
        total += m.size if k == "file" else 0
        if total > MAX_RECORD_STREAM:
            raise RecordLimit(f"the tar members add up to more than {MAX_RECORD_STREAM >> 30} GB")
        yield record_parts(m.name), k, ((lambda m=m: t.extractfile(m)) if k == "file" else None), (m.size if k == "file" else 0)


class EofTarInfo(tarfile.TarInfo):
    """記下 tar 是不是以結尾的零區塊結束（串流讀時，剛好截在成員邊界的 tar 會被當成正常結束）。"""

    @classmethod
    def fromtarfile(cls, tarfile_):
        try:
            return super().fromtarfile(tarfile_)
        except tarfile.EOFHeaderError:
            tarfile_.sca_eof = True
            raise


def read_build_record(path):
    """--build-record（資料夾、.tar、.tar.gz、.tar.xz、.tar.bz2）→ BuildRecord（讀不了時 error 記原因，不丟例外）。"""
    rec = BuildRecord(path)
    try:
        if os.path.isdir(path):
            for e in record_entries_dir(path):
                rec.feed(*e)
        elif os.path.isfile(path):
            with open(path, "rb") as f, tarfile.open(fileobj=f, mode="r|*", tarinfo=EofTarInfo) as t:
                t.sca_eof = False
                for e in record_entries_tar(t):
                    rec.feed(*e)
                if not t.sca_eof:
                    rec.error = "the build record tar has no end-of-archive marker (truncated at a member boundary?)"
        else:
            rec.error = "the build record does not exist (not a file or directory)"
    except RecordLimit as e:
        rec.error = f"the build record is larger than the limits ({e})"
    except (tarfile.TarError, OSError, EOFError, zlib.error, lzma.LZMAError, ValueError) as e:
        rec.error = f"the build record cannot be read as a tar archive or directory ({type(e).__name__})"
    return rec


def record_norm(raw, prefixes):
    """source_／deps_ 的路徑 → 樹內相對路徑；對不上樹（其他的絕對路徑、正規化後超出樹）→ None。
    prefixes：source_ 推出的原始碼樹前綴（O= 建置的絕對路徑、或 ../ 之類；長的先比）。"""
    for pre in prefixes:
        if raw.startswith(pre):
            raw = raw[len(pre):]
            break
    else:
        if raw.startswith("/"):
            return None
    p = posixpath.normpath(raw)
    return None if p.startswith("..") or p in (".", "") else p


def module_ko_key(k):
    """模組目錄的 .ko（相對路徑）→ (資料夾, 名稱（- 換成 _）)：kernel/ 底下的去掉 kernel/；其他（updates/、extra/…）→ None。"""
    for ext in MODULE_EXT:
        if k.endswith(ext):
            stem = k[:-len(ext)]
            if not stem.startswith("kernel/"):
                return None
            stem = stem[len("kernel/"):]
            return posixpath.dirname(stem), posixpath.basename(stem).replace("-", "_")
    return None


def record_closure(r, order_data, modules=True):
    """完整性（membership closure）→ (要求的數量, 缺的 Examples)。要有自己的 .cmd 的：每個 .cmd 的 cmd_members（archive 與 .mod 的成員、
    其他連結指令裡的建置產物、@x.mod）；最後的 vmlinux（link-vmlinux.sh：vmlinux.o、vmlinux.a、init/version-timestamp.o，
    CONFIG_MODULES 時 .vmlinux.export.o）；以 .incbin 帶進來的 vDSO（INCBIN_RULES）；modules.order 每個模組的 .o、.mod、.ko。
    任何紀錄裡有的 .cmd 都會提出要求，所以要漏掉一個物件，得連同每一個提到它的連結指令一起拿掉，直到 vmlinux.o。"""
    targets = r["targets"]
    miss, seen, exempt = Examples(), set(), []
    reqs = list(r["reqs"])
    if "vmlinux" in targets:
        reqs += [(x, "vmlinux") for x in ("vmlinux.o", "vmlinux.a", "init/version-timestamp.o")
                 + ((".vmlinux.export.o",) if modules else ())]
    for t in sorted(targets):
        for rx, rp in INCBIN_RULES:
            if rx.match(t):
                reqs.append((rx.sub(rp, t), t + " (.incbin)"))
    for line_ in (order_data or b"").decode("utf-8", "replace").splitlines():
        s = line_.strip()
        if not s:
            continue
        stem = s[len("kernel/"):] if s.startswith("kernel/") else s
        for ext in MODULE_EXT + (".o",):
            if stem.endswith(ext):
                stem = stem[:-len(ext)]
                break
        reqs += [(stem + x, "modules.order") for x in (".o", ".mod", ".ko")]
    for m, by in reqs:
        if m in seen:
            continue
        seen.add(m)
        if m not in targets:
            if m in LINK_STAGE_NO_CMD:
                exempt.append(m)
            else:
                miss.add(f"{m} (listed by {posixpath.normpath(by)})")
    return len(seen), miss, sorted(exempt)


class RecordJudge:
    """驗證過（status OK）的建置紀錄：判斷每個 programFile 有沒有編進核心。"""

    def __init__(self, paths, suffixes, tree_names, oot, extra_objs=None, extra_modules=0, unsourced=0):
        self.unsourced = unsourced          # 映像裡有、紀錄沒有、又找不到來源的模組數：有的話，沒被紀錄證明有編的樹內檔案一律 unknown
        self.extra_objs = extra_objs or {}  # {物件: 映像裡有、紀錄沒有的模組（modules 的路徑）}：這些物件的檔案不判沒編
        self.extra_modules = extra_modules  # 映像裡有、紀錄沒有的模組數（樹內與找不到來源的合計；標頭檔可能被它們 include）
        self.paths = paths                  # {樹內相對路徑: (物件, "source"／"deps")}
        self.suffixes = suffixes            # 對不上樹的絕對路徑（與超出樹的路徑）的每個後綴 → (物件, "source"／"deps")
        self.tree_names = tree_names        # 這個核心的檔案（樹內相對路徑）或 None
        self.oot = oot                      # 模組目錄裡 out-of-tree 模組的數量（不在紀錄的 modules.order 裡的 .ko）
        self.full_tree = False              # 核心原始碼樹（--source-tree）的檔案名稱完整：檔案不在樹裡＝這個核心沒有這個檔案
        self.tree_links = frozenset()       # 樹裡的符號連結（路徑在連結底下的檔案，名稱清單不能證明它不存在）
        self.oot_records = []               # --oot-build-record：樹外模組的建置紀錄（OotRecord）；oot_complete 才用（見 attach_oot_records）
        self.oot_complete = False           # 映像裡每一個樹外 .ko 都有完整的紀錄，標頭檔才可以不因為樹外模組而 unknown
        self.stats = {k: 0 for k in ("built", "built_by_unmapped_absolute_path", "not_built", "conflict_makefile_built",
                                     "built_makefile_not_built", "header_out_of_tree_modules", "not_shown_to_exist",
                                     "listed_in_module_lists", "included_c_list")}
        if self.extra_modules:              # 只有映像有多出的模組時才有這個欄位（其他輸出和以前逐位元組相同）
            self.stats["image_module_not_in_record"] = 0
        if self.unsourced:
            self.stats["image_unsourced_module"] = 0

    @staticmethod
    def eligible(path):
        """建置紀錄能判斷的檔案：樹內的原始檔（.c／.S／.rs，.lds.S 除外）與標頭檔（.h），而且不在 Documentation/、tools/、scripts/ 等
        （classify_file 的 NON_KERNEL_TOP）→ 物件路徑（標頭檔是 ""）；其他 → None（照舊的規則）。"""
        p = posixpath.normpath(path)
        if p.startswith("..") or p.startswith("/") or not p or len(p) > 400 or p.split("/", 1)[0] in NON_KERNEL_TOP:
            return None
        base = posixpath.basename(p)
        if base.endswith(".h"):
            return ""
        for ext in RECORD_SOURCE_EXT:
            if base.endswith(ext) and not base.endswith(".lds.S"):
                return p[:-len(ext)] + ".o"
        return None

    def exists(self, model, p, obj):
        """這個核心有這個檔案：Makefile 的規則提到它的物件，或映像的核心樹（headers）裡有這個檔案。"""
        if obj and obj in model.obj_refs:
            return True
        return self.tree_names is not None and p in self.tree_names

    def judge(self, model, path, obj, new_code=None):
        """→ (Res, 證據的說明)。obj：eligible() 的結果。new_code：CNA 紀錄說這個問題在核心之後的版本才出現（字串，例如 "6.10"）；
        只有核心原始碼樹完整（full_tree）而且檔案不在樹裡時才用（見下面 not self.exists 那一段）。"""
        p = posixpath.normpath(path)
        mr = model.obj_built(obj) if obj else None
        hit = self.paths.get(p)
        absolute = False
        if not hit:
            hit, absolute = self.suffixes.get(p), True
        if hit:
            o, how = hit
            ev = (f"build record: {'compiled as' if how == 'source' else 'in the deps of'} {o}" if not absolute else
                  f"build record: an absolute path in the {'source' if how == 'source' else 'deps'} of {o} ends with /{p} "
                  "(outside the inferred source tree; counted as built)")
            self.stats["built_by_unmapped_absolute_path" if absolute else "built"] += 1
            if mr is not None and mr.value is False:
                self.stats["built_makefile_not_built"] += 1
            on = mr is not None and mr.value is True
            return Res(True, mr.syms if on else (), [ev], mr.modules if on else ()), ev
        if obj and self.unsourced:
            # 映像有來源不明的模組（樹外，或名稱和 Makefile 對不上）：它可能就是這個檔案編出來的（.ko 的名稱不一定等於 Makefile 的物件名稱），
            # 所以「不在紀錄裡」不能當成沒編——沒被紀錄證明有編的樹內原始檔一律 unknown
            self.stats["image_unsourced_module"] += 1
            ev = (f"build record: not in the source or deps of any compiled kernel object, but the shipped image has {self.unsourced} module(s) "
                  "of unknown origin that the record does not list and no Makefile rule names, which may be built from this file "
                  "(出貨映像有來源不明的模組)")
            return Res(None, mr.syms if mr is not None else (), [ev]), ev
        if obj and obj in self.extra_objs:
            # 出貨映像有這個模組、建置紀錄沒有：紀錄看不到它的物件，「不在紀錄裡」不能當成沒編
            self.stats["image_module_not_in_record"] += 1
            ev = f"build record: {EXTRA_WHY}: {self.extra_objs[obj]}"
            return Res(None, mr.syms if mr is not None else (), [ev]), ev
        if mr is not None and mr.value is True:
            self.stats["conflict_makefile_built"] += 1
            ev = ("build record: not in the source or deps of any compiled kernel object, but the Makefile rules say it is built "
                  "(conflict, so unknown)")
            return Res(None, mr.syms, [ev]), ev
        if obj and (included_c().get(p) or p.startswith(INCLUDED_C_PREFIXES)) and not other_arch_included_only(model, p):
            # 額外的安全網：會被別的檔案 #include 的 .c，紀錄沒有證明有編 → 不判沒編（和沒有紀錄時一樣）
            self.stats["included_c_list"] += 1
            ev = ("build record: not in any compiled object's source or deps, but the file is on the list of .c files #included by "
                  "other sources (kept as a safety net, so unknown)")
            return Res(None, why=[ev]), ev
        if mr is not None and mr.value is False:
            # 兩邊都說沒編（Makefile 的結論本身已經處理了「檔案在不在」例如其他架構的 arch/<X>/）：
            # 照 Makefile 那邊的核對（映像的模組清單列了它 → unknown）
            hit = listed_contradiction(model, obj)
            if hit:
                self.stats["listed_in_module_lists"] += 1
                ev = f"build record: not in any compiled object's source or deps, but the image's module lists disagree ({hit})"
                return Res(None, mr.syms, [ev]), ev
            self.stats["not_built"] += 1
            ev = "build record: not in the source or deps of any compiled kernel object"
            return Res(False, mr.syms, [ev]), ev
        oot_checked = False
        if not obj and self.oot:
            if self.oot_complete:
                # 每一個樹外 .ko 都有完整的建置紀錄：標頭檔有沒有被它們讀到，看紀錄的 deps（路徑以 /<標頭檔> 結尾就算；偏向 affected）
                o = oot_header_hit(self.oot_records, p)
                if o:
                    self.stats["header_in_out_of_tree_deps"] += 1
                    ev = (f"out-of-tree build record: in the deps of {o[1]} ({o[0]}; compiled into an out-of-tree module of the image)")
                    return Res(True, why=[ev]), ev
                oot_checked = True
            else:
                self.stats["header_out_of_tree_modules"] += 1
                ev = (f"build record: no in-tree object depends on it, but the module directory has {self.oot} out-of-tree module(s), "
                      "built separately against the kernel headers, that may include it")
                return Res(None, why=[ev]), ev
        if not obj and self.extra_modules:
            self.stats["header_out_of_tree_modules"] += 1
            ev = (f"build record: no object in the record depends on it, but the image has {self.extra_modules} module(s) that the "
                  "record does not list, which may include it (出貨映像有這個模組，但建置紀錄沒有)")
            return Res(None, why=[ev]), ev
        if not self.exists(model, p, obj) and new_code and self.full_tree and not any(
                p == l or p.startswith(l + "/") for l in self.tree_links):
            # 這個檔案不在出貨的核心原始碼樹裡、也沒有 Makefile 的規則提到它，而 CNA 紀錄說這個問題在 new_code 才出現（比這個核心新）：
            # 那一段程式不是這個核心的一部分（沒有搬過家的可能：問題出現之前沒有這段程式，不會有舊路徑）。兩項證據缺一不可。
            self.stats["absent_new_code"] = self.stats.get("absent_new_code", 0) + 1
            ev = (f"build record: not in any compiled object's source or deps; {p} is not in the shipped kernel source tree and no Makefile "
                  f"rule names it, and the CNA record says the problem was introduced in {new_code}, after this kernel: the code is not "
                  "part of this kernel")
            return Res(False, why=[ev]), ev
        if not self.exists(model, p, obj):
            self.stats["not_shown_to_exist"] += 1
            ev = (f"build record: not in any compiled object's source or deps, but this kernel's files do not show that {p} exists "
                  "(added or moved after this kernel?)")
            return Res(None, why=[ev]), ev
        if obj:
            stem = obj[:-2]
            k = (posixpath.dirname(stem), posixpath.basename(stem).replace("-", "_"))
            for n, keys in image_module_lists(model).items():
                if k in keys:
                    self.stats["listed_in_module_lists"] += 1
                    ev = f"build record: not in any compiled object's source or deps, but the image's {n} lists {keys[k]}"
                    return Res(None, why=[ev]), ev
        self.stats["not_built"] += 1
        ev = "build record: not in the source or deps of any compiled kernel object"
        if oot_checked:
            self.stats["header_not_built_oot_checked"] += 1
            ev += (f", nor in the deps of any of the {self.oot} out-of-tree module(s) of the image (every one has an out-of-tree "
                   "build record)")
        return Res(False, why=[ev]), ev


def code_file(path):
    """commit 改的檔案裡，值得併進 programFiles 的：程式檔（.c／.S／.rs，.lds.S 除外）與標頭檔（.h），不在 Documentation/、tools/、scripts/ 底下。"""
    p = posixpath.normpath(path)
    if p.startswith("..") or p.startswith("/") or not p or p.split("/", 1)[0] in NON_KERNEL_TOP:
        return False
    return p.endswith((".h", ".c", ".S", ".rs")) and not p.endswith(".lds.S")


def kernel_has_file(model, info, path):
    """這個核心有這個檔案：Makefile 的規則提到它的物件，或核心樹／headers 的檔案名稱裡有它。檔案名稱不知道（tree_names 是 None）→ True（保守）。"""
    p = posixpath.normpath(path)
    for ext in (".c", ".S", ".rs"):
        if p.endswith(ext) and p[:-len(ext)] + ".o" in model.obj_refs:
            return True
    names = getattr(info, "tree_names", None)
    return True if names is None else p in names


def oot_header_hit(records, path):
    """樹外模組的建置紀錄裡有沒有用到這個核心標頭檔 → (紀錄名稱, 物件名稱) 或 None。"""
    mod = kernel_oot_record()
    for r in records:
        o = mod.header_hit(r, path)
        if o:
            return r.label, o
    return None


def header_defines(data):
    """include/generated/*.h → {名稱: 字串值}（只認 #define NAME "值"）。"""
    out = {}
    for l in (data or b"").decode("utf-8", "replace").splitlines():
        m = re.match(r'^\s*#define\s+(\w+)\s+"(.*)"\s*$', l)
        if m:
            out[m.group(1)] = m.group(2).replace('\\"', '"')
    return out


def record_identity(got, info):
    """紀錄的建置識別檔（kernel.release、utsversion.h、compile.h）和映像的 Image banner（linux_banner：
    "Linux version <release> (<by>@<host>) (<compiler>) <version>"）核對 → (紀錄, GAP 的原因或 None)。
    result：matched（有識別檔、banner 讀得到、每一項都對上）／not_tied（沒有識別檔，或讀不到 banner：照舊採用，limitations 註明）。
    對不上 → GAP（不是出貨的那一次建置）。"""
    imgs = getattr(info, "images", None) or {}
    prim = primary_image(imgs)
    banner = getattr(prim, "banner", None) if prim is not None else None
    if banner:
        banner = re.sub(r"\s*\(\)\s*$", "", banner)        # 真實 banner 結尾有 " ()"（UTS_VERSION 之後）
    want = {}
    if got.get("kernel.release") is not None:
        want["release"] = got["kernel.release"].decode("utf-8", "replace").strip()
    d = {**header_defines(got.get("compile.h")), **header_defines(got.get("utsversion.h"))}
    for k, n in (("version", "UTS_VERSION"), ("by", "LINUX_COMPILE_BY"), ("host", "LINUX_COMPILE_HOST"), ("compiler", "LINUX_COMPILER")):
        if d.get(n):
            want[k] = d[n]
    files = [n for n in ("kernel.release", "utsversion.h", "compile.h") if got.get(n) is not None]
    rec = {"files": files, "image": (prim.path if prim is not None else None), "banner_read": banner is not None,
           "compared": sorted(want) if banner is not None else [], "result": "not_tied"}
    if not want or banner is None:
        return rec, None
    bad = []
    if "release" in want and not banner.startswith(f"Linux version {want['release']} ("):
        bad.append("release")
    if "by" in want and "host" in want and f" ({want['by']}@{want['host']}) (" not in banner:
        bad.append("compile by/host")
    if "compiler" in want and f"({want['compiler']}) " not in banner:
        bad.append("compiler")
    if "version" in want and not banner.rstrip().endswith(" " + want["version"]):
        bad.append("version (UTS_VERSION)")
    if bad:
        rec["result"] = "mismatch"
        return rec, (f"the record's build-identity files do not match the version banner of the image's kernel ({prim.path}): "
                     f"{', '.join(bad)} differ: not the build that was shipped")
    rec["result"] = "matched"
    return rec, None


def extra_module_sources(model):
    """Model → ({(資料夾, 名稱（- 換成 _）): 物件}, {組合物件: {成員物件}})：映像多出的模組要找「它的 Makefile 規則」時用。"""
    by_key, members = {}, {}
    for o, refs in model.obj_refs.items():
        by_key.setdefault((posixpath.dirname(o), posixpath.basename(o)[:-2].replace("-", "_")), o)
        for md, base, _ in refs:
            if base not in LIST_BASES and base:
                members.setdefault(posixpath.join(md, base + ".o"), set()).add(o)
    return by_key, members


EXTRA_CLASS_TEXT = {
    2: "intree=Y (or modinfo unreadable) but no Makefile rule names the module: it may be built from any in-tree file; every in-tree source "
       "file that the record does not show as built is judged unknown",
    3: "built in the kernel tree (intree=Y or modinfo unreadable) and a Makefile rule names it: the files of its objects are judged unknown",
    4: "out-of-tree module (no intree flag) with the same name as an in-tree module: it may contain the same code, so the files of the "
       "in-tree module's objects are judged unknown",
    5: "out-of-tree vendor module (no intree flag), no in-tree module of that name: not assessed (its code is not a kernel-tree file, so the "
       "CNA programFiles do not cover it); it does not protect in-tree files",
}


def classify_extra_modules(model, extra, modinfo=None):
    """映像的 kernel/ 模組裡不在紀錄 modules.order 的（extra：.ko 路徑）→ (摘要 dict, {物件: 模組路徑})。依模組自己的 .modinfo 分類
    （modpost 對核心樹內編出來的模組加 intree=Y；讀不到 modinfo 一律當成樹內，保守）和 Makefile 對得到與否：
      2 樹內（或讀不到）、Makefile 對不到：可能由任何樹內檔案編出來 → 所有沒被紀錄證明有編的樹內檔案 unknown（RecordJudge.unsourced）；
      3 樹內（或讀不到）、Makefile 對得到：它的組成物件的檔案 unknown；
      4 樹外（沒有 intree）、名稱對得到樹內模組：樹外 fork 可能含同一段程式 → 對應的樹內組成物件的檔案 unknown；
      5 樹外、名稱也對不到：樹外廠商模組，未評估（GAP）；它的程式不是核心樹的檔案，不做全面保護。
    摘要 source：in_tree（Makefile 對得到）／not_found；intree：Y／null（沒有標記）／unreadable。"""
    by_key, members = extra_module_sources(model)
    modinfo = modinfo or {}
    objs, listed, counts = {}, [], {2: 0, 3: 0, 4: 0, 5: 0}
    for ko in extra:
        key = module_ko_key(ko)
        top = by_key.get(key)
        if top is None:
            top = next((m for m in sorted(members) if (posixpath.dirname(m), posixpath.basename(m)[:-2].replace("-", "_")) == key), None)
        mi = modinfo.get(ko) or {"ok": False, "reason": "modinfo was not read"}
        readable = bool(mi.get("ok"))
        intree = readable and mi.get("intree") == "Y"
        cls = (3 if (intree or not readable) else 4) if top is not None else (2 if (intree or not readable) else 5)
        counts[cls] += 1
        rec = {"module": ko, "intree": "Y" if intree else None if readable else "unreadable", "class": cls,
               "source": "in_tree" if top is not None else "not_found",
               "status": "GAP" if cls in (2, 5) else "UNKNOWN", "reason": EXTRA_CLASS_TEXT[cls] + ": " + EXTRA_WHY}
        if readable:
            rec["modinfo"] = {k: mi[k] for k in MODINFO_KEYS if mi.get(k) and k != "intree"}
        else:
            rec["modinfo_unreadable"] = mi.get("reason")
        if top is not None:
            seen, todo = {top}, [top]
            while todo and len(seen) < 10000:
                for m in sorted(members.get(todo.pop(), ())):
                    if m not in seen:
                        seen.add(m)
                        todo.append(m)
            for o in seen:
                objs.setdefault(o, ko)
            rec.update(object=top, objects=len(seen), object_list=sorted(seen)[:EXTRA_OBJECTS_MAX])
        listed.append(rec)
    summary = {"count": len(extra), "in_tree": counts[3] + counts[4], "not_found": counts[2] + counts[5], "classes": {str(k): v for k, v in counts.items()},
               "modules": listed[:EXTRA_MODULES_MAX], "truncated": len(listed) > EXTRA_MODULES_MAX,
               "note": "kernel/ modules of the shipped image that are not in the build record's modules.order: the record is used, classified by "
                       "the module's own .modinfo (intree) and the Makefiles: " + " | ".join(f"class {k}: {v}" for k, v in EXTRA_CLASS_TEXT.items())
                       + ". The intree flag can be forged; the code of out-of-tree modules is not matched against vulnerability data."}
    return summary, objs


def build_info_sha256s(rec):
    """BuildRecord 的 BUILD-INFO.txt → image=… sha256=<64 hex> 的雜湊集合（沒有檔案或沒有雜湊 → 空）。
    檔案在紀錄最上層（tar 內，或 pack-build-record.sh 的資料夾）；精靈把壓縮檔解開後把 <解開>/kernel 當紀錄，BUILD-INFO.txt 在上一層，
    所以紀錄是資料夾時也看它自己和上一層的一般檔案（不跟隨連結、有大小上限）。"""
    texts = [v for k, v in rec.files.items() if len(k) <= 2 and k[-1] == BUILD_INFO_NAME]
    path = getattr(rec, "path", None)
    if not texts and path and os.path.isdir(path):
        for d in (path, os.path.dirname(os.path.normpath(path))):
            f = os.path.join(d, BUILD_INFO_NAME)
            try:
                if stat.S_ISREG(os.lstat(f).st_mode) and os.lstat(f).st_size <= (1 << 16):
                    with flash_package().open_nofollow(f) as fh:
                        texts.append(fh.read(1 << 16))
                    break
            except OSError:
                continue
    out = set()
    for v in texts:
        out |= set(re.findall(r"^image=\S+\s+sha256=([0-9a-f]{64})\s*$", v.decode("utf-8", "replace"), re.M))
    return out


def check_build_record(rec, info, model, mods):
    """讀進來的 BuildRecord → (kernel.build_record 的紀錄, RecordJudge 或 None)。任何一項不成立 → status GAP（reason），
    不用這份紀錄（照舊用 Makefile 的判定）。"""
    out = {"source": rec.label, "status": "GAP", "reason": None, "root": None, "config_sha256": None, "config_compare": None,
           "kernel_release": None, "kernel_release_checked": False, "cmd_files": 0, "object_cmd_files": 0, "host_cmd_files": 0,
           "closure": None, "paths": 0, "unmapped_absolute_paths": 0, "source_tree_prefixes": 0,
           "rejected_members": rec.rejected, "ignored_links": rec.ignored_links, "out_of_tree_modules": None,
           "limitations": list(BUILD_RECORD_LIMITATIONS)}

    def gap(why):
        out["reason"] = why
        return out, None

    if rec.error:
        return gap(rec.error)
    imgs = getattr(info, "images", None) or {}
    if imgs.get("prefer_rootfs") and imgs.get("rootfs") is not None:
        # 板子跑的是 rootfs/boot/Image（C-kernel-boot）：紀錄要和它同一次建置才能用；BUILD-INFO.txt 的 sha256 對不上（或沒有）→ 不採用
        shas = build_info_sha256s(rec)
        if imgs["rootfs"].sha256 not in shas:
            return gap("the board runs rootfs/boot/Image (sha256 " + str(imgs["rootfs"].sha256)[:12] + "...), which is not the kernel this build "
                       "record describes (BUILD-INFO.txt image sha256 " + (", ".join(x[:12] + "..." for x in sorted(shas)) or "not found") + "): "
                       "the record's exclusions do not apply to the running kernel")
    if rec.needed_links.n:
        return gap(f"{rec.needed_links.n} .cmd or list file(s) in the record are links or special files (not followed): "
                   + rec.needed_links.text())
    if rec.oversize.n:
        return gap(f"{rec.oversize.n} file(s) in the record are larger than {MAX_RECORD_MEMBER >> 20} MB: " + rec.oversize.text())
    roots = set(rec.roots) | {p[:-1] for p in rec.files if p[-1] == ".config"}
    if len(roots) > 1:
        return gap("the record holds more than one build tree (" + ", ".join(sorted("/".join(r) or "." for r in roots))[:200] + ")")
    if not roots:
        return gap("incomplete build record: no .config and no kbuild .cmd files")
    root = next(iter(roots))
    out["root"] = "/".join(root) or "."
    if rec.anomalies.n:
        return gap(f"{rec.anomalies.n} .cmd file(s) do not match kbuild's format or their location in the tree: " + rec.anomalies.text())
    r = rec.roots.get(root) or new_root()
    out.update(cmd_files=r["cmds"], object_cmd_files=r["obj_cmds"], host_cmd_files=r["host"])
    got = {name: rec.files.get(root + rel) for rel, name in RECORD_FILES.items()}
    cfg = got[".config"]
    if cfg is None:
        return gap("incomplete build record: no .config")
    out["config_sha256"] = hashlib.sha256(cfg).hexdigest()
    ctext = cfg.decode("utf-8", "replace")
    rv = parse_config(ctext)[0]
    miss = []
    if rv.get("CONFIG_MODULES") in ("y", "m") and got["modules.order"] is None:
        miss.append("modules.order")
    if not any(n in r["names"] for n in RECORD_LINK_CMDS):
        miss.append("the final link command (.vmlinux.cmd)")
    if r["obj_cmds"] < MIN_RECORD_OBJECT_CMDS:
        miss.append(f"object .cmd files (only {r['obj_cmds']}, at least {MIN_RECORD_OBJECT_CMDS} expected)")
    if miss:
        return gap("incomplete build record: missing " + "; ".join(miss))
    need, lost, exempt = record_closure(r, got["modules.order"], rv.get("CONFIG_MODULES") in ("y", "m"))
    out["closure"] = {"required": need, "missing": lost.n}
    if exempt:
        out["closure"]["exempted_link_stage_artifacts"] = exempt
        out["closure"]["exempted_note"] = ("kbuild link-stage artifacts with no .cmd file in the record (not required; they map to no source "
                                           "file and are never used to judge any source file): " + ", ".join(exempt))
    if lost.n:
        return gap(f"incomplete build record: {lost.n} of {need} object(s), archive(s) or module file(s) linked into the kernel or a "
                   f"module have no .cmd file, for example {lost.text()}")
    _, hh, _, ih, _, names, tool = config_diff(info.config_text, ctext)
    res = "same" if not names and hh == ih else "same_except_toolchain" if len(tool) == len(names) and hh == ih else "differs"
    out["config_compare"] = {"result": res, "differences_total": len(names), "toolchain_differences_total": len(tool),
                             "examples": sorted(names, key=lambda n: (is_toolchain_option(n), n))[:10],
                             "header": {"judged": list(hh), "record": list(ih)} if hh != ih else None}
    if res == "differs":
        eg = [n for n in names if not is_toolchain_option(n)][:3]
        return gap(f"the record's .config is not the configuration K1 judges with ({info.config_path}): {len(names)} option(s) differ"
                   + (f", for example {', '.join(eg)}" if eg else "") + ("; the .config header differs" if hh != ih else ""))
    if got["kernel.release"] is not None:
        rel = got["kernel.release"].decode("utf-8", "replace").strip()
        out["kernel_release"] = rel[:200]
        if info.kernel_version and rel != info.kernel_version:
            return gap(f"the record's include/config/kernel.release is {rel[:80]!r}, the kernel judged is {info.kernel_version}")
        out["kernel_release_checked"] = bool(info.kernel_version)
    ilists = image_module_lists(model)
    rkeys, compared = {}, []
    for n in ("modules.order", "modules.builtin"):
        if got[n] is None:
            continue
        rkeys[n] = module_list_keys(got[n])
        if n in ilists:
            if set(rkeys[n]) != set(ilists[n]):
                a, b = len(set(rkeys[n]) - set(ilists[n])), len(set(ilists[n]) - set(rkeys[n]))
                return gap(f"the record's {n} differs from the image's ({a} only in the record, {b} only in the image): not the same build")
            compared.append(n)
    if not out["kernel_release_checked"]:
        if info.kernel_version and got["kernel.release"] is None:
            # 沒有 kernel.release：只在 .config 完全相同（不接受只差工具鏈）、兩個模組清單都和映像對得上時才採用（明示沒有核對版本）
            if res != "same":
                return gap("the record has no include/config/kernel.release, and its .config is not identical to the configuration "
                           f"K1 judges with ({res}: {len(names)} option(s) differ): cannot show it is the build of kernel "
                           f"{info.kernel_version}")
            if len(compared) < 2:
                return gap("the record has no include/config/kernel.release, and its modules.order and modules.builtin cannot both be "
                           "compared with the image's (compared: " + (", ".join(compared) or "none") + "): cannot show it is the "
                           f"build of kernel {info.kernel_version}")
            out["limitations"].append(RECORD_RELEASE_LIMITATION)
        elif not info.kernel_version:
            out["limitations"].append(RECORD_NO_VERSION_LIMITATION)
    ident, why = record_identity(got, info)
    out["identity"] = ident
    if why:
        return gap(why)
    if ident["result"] != "matched":
        out["limitations"].append(RECORD_NOT_TIED_LIMITATION)
    prefixes = sorted((p for p in r["prefix"] if p), key=lambda p: (-len(p), p))
    paths, suffixes, unmapped = {}, {}, 0
    for raw, v in r["paths"].items():
        p = record_norm(raw, prefixes)
        if p is None:
            # 對不上樹的路徑（in-tree 建置裡 $(abspath …) 的絕對路徑、符號連結與實際路徑不同的 O= 建置、系統標頭）：每個後綴都記下，
            # judge 時「某個這種路徑以 /<檔案> 結尾」也算有編（只會偏向 affected）
            unmapped += 1
            q = [x for x in posixpath.normpath(raw).split("/") if x not in ("", ".", "..")]
            for i in range(len(q)):
                k = "/".join(q[i:])
                if k not in suffixes or (v[1] == "source" and suffixes[k][1] != "source"):
                    suffixes[k] = v
            if len(suffixes) > 4 * MAX_RECORD_PATHS:
                return gap(f"the record has too many paths outside the source tree (more than {4 * MAX_RECORD_PATHS} suffixes)")
        elif p not in paths or (v[1] == "source" and paths[p][1] != "source"):
            paths[p] = v
    out.update(paths=len(paths), unmapped_absolute_paths=unmapped, source_tree_prefixes=len(prefixes))
    order = set(rkeys.get("modules.order") or ())
    # 映像 kernel/ 底下有 .ko 不在紀錄的 modules.order：不拒收（modules.order／modules.builtin 與映像相同、身分相符時，多出的模組是出貨時
    # 另外放進映像的）。這些模組的檔案不判沒編（RecordJudge.extra_objs），找不到來源的標 GAP，列在 image_modules_not_in_record
    intree = [k for k in (mods or ()) if module_ko_key(k) is not None]
    extra = sorted(k for k in intree if module_ko_key(k) not in order)
    oot = [k for k in (mods or ()) if module_ko_key(k) is None]
    out["out_of_tree_modules"] = len(oot) if mods is not None else None
    extra_objs = {}
    if extra:
        summary, extra_objs = classify_extra_modules(model, extra, (info.modules or {}).get("modinfo"))
        out["image_modules_not_in_record"] = summary
        shown = ", ".join(posixpath.basename(m["module"]) for m in summary["modules"][:10])
        cl = summary["classes"]
        out["limitations"].append(
            f"{len(extra)} kernel/ module(s) of the image are not in the record's modules.order ({shown}{', ...' if len(extra) > 10 else ''}); "
            "classified by each module's .modinfo (intree) and the Makefiles: "
            f"class 2 (in-tree or unreadable, no Makefile rule: every in-tree source file that the record does not show as built is judged unknown) {cl['2']}, "
            f"class 3 (in-tree, Makefile rule: its objects' files judged unknown) {cl['3']}, "
            f"class 4 (out-of-tree, same name as an in-tree module: that module's files judged unknown) {cl['4']}, "
            f"class 5 (out-of-tree vendor module, not assessed, GAP) {cl['5']}. "
            "The intree flag can be forged; the code of out-of-tree modules has no vulnerability matching (CNA programFiles do not cover it).")
    out["status"] = "OK"
    return out, RecordJudge(paths, suffixes, getattr(info, "tree_names", None), len(oot), extra_objs, len(extra), summary['classes']['2'] if extra else 0)


def oot_module_name(k):
    """模組目錄的 .ko（相對路徑）→ 模組名稱（- 換成 _）。"""
    b = posixpath.basename(k)
    for ext in MODULE_EXT:
        if b.endswith(ext):
            return b[:-len(ext)].replace("-", "_")
    return b.replace("-", "_")


def attach_oot_records(brec, brecord, paths, info, mods):
    """--oot-build-record（樹外模組的建置紀錄資料夾，可以給多個）：讀進來、核對，結果記在 kernel.build_record.out_of_tree_records，
    全部通過時 brec.oot_complete 為真（RecordJudge 才用紀錄判斷標頭檔）。
    規則：映像裡每一個樹外 .ko（模組目錄裡 kernel/ 以外的 .ko）都要有完整的紀錄（.<模組>.ko.cmd，連結的每個物件與成員都有完整的 .cmd；
    紀錄資料夾裡有那個 .ko 時，.modinfo 的 srcversion 要和映像的相同）。只要有一個沒有紀錄、一份紀錄讀不了（截斷、太大、連結）、
    或建置紀錄（--build-record）本身不能用 → 不採用，標頭檔照舊因為樹外模組而 unknown。brec 是 None（建置紀錄 GAP）時只記原因。"""
    mod = kernel_oot_record()
    me = sys.modules[__name__]
    sm = {"records": [], "image_modules": None, "covered": 0, "uncovered": 0, "uncovered_examples": [], "identity": {},
          "used": False, "reason": None}
    brecord["out_of_tree_records"] = sm
    recs = []
    for p in paths:
        r = mod.read_oot_record(p, me)
        recs.append(r)
        sm["records"].append({"source": r.label, "status": "GAP" if r.error else "OK", "reason": r.error, "cmd_files": r.ncmds,
                              "object_cmd_files": r.nobj, "modules": sum(len(v) for v in r.kos.values()), "paths": r.npaths,
                              "ignored_links": r.links})
    if brec is None:
        sm["reason"] = "the kernel build record is not used (GAP), so out-of-tree records are not used either"
        return
    bad = [x for x in sm["records"] if x["status"] != "OK"]
    oot = sorted(k for k in (mods or ()) if module_ko_key(k) is None)
    sm["image_modules"] = len(oot) if mods is not None else None
    if mods is None:
        sm["reason"] = "the image has no module directory to compare the out-of-tree modules with"
        return
    if not oot:
        sm["reason"] = "the image has no out-of-tree module"
        return
    if bad:
        sm["reason"] = f"{len(bad)} out-of-tree build record(s) are not usable: " + "; ".join(f"{x['source']}: {x['reason']}" for x in bad)[:300]
        return
    minfo = (info.modules or {}).get("modinfo") or {}
    ident, unc, closure_cache = {"srcversion": 0, "sections": 0, "sections_masked": 0, "name_only": 0}, [], {}
    verified_by = {}
    masked_examples = []
    fp = me.flash_package()
    for k in oot:
        name = oot_module_name(k)
        best, why, mismatch = None, "no .ko.cmd for this module in any record", None
        for r, c in mod.module_candidates(recs, name):
            ck = (c["target"],)
            if ck not in closure_cache:
                closure_cache[ck] = mod.module_closure(recs, me, c["target"])
            ok, w = closure_cache[ck]
            if not ok:
                why = w
                continue
            # 紀錄資料夾裡有同名的 .ko：一定要讀得到 srcversion 而且和映像的相同（讀不到、被截斷、是符號連結、不同 → 整個模組不採用）；
            # 沒有 .ko 可比的候選只靠名稱
            kind, bad = "name_only", None
            try:
                present = os.path.lexists(c["file"])
            except OSError:
                present = True
            if present:
                got = None
                try:
                    s = os.lstat(c["file"])
                    if stat.S_ISREG(s.st_mode) and s.st_size <= mod.MAX_OOT_KO:
                        got = read_modinfo(lambda p=c["file"]: fp.open_nofollow(p), s.st_size, c["file"], sections=True)
                except OSError:
                    got = None
                iv = (minfo.get(k) or {}).get("srcversion") if (minfo.get(k) or {}).get("ok") else None
                rv = got.get("srcversion") if isinstance(got, dict) and got.get("ok") else None
                if rv and iv:
                    if iv != rv:
                        bad = f"srcversion of the record's .ko ({rv}) differs from the image's .ko ({iv}): not the same build"
                    else:
                        kind = "srcversion"
                else:
                    # srcversion 讀不到（NVIDIA 的樹外模組多半沒有）：比 ELF 區段（見 kernel_oot_record.compare_ko_sections）
                    kind, w = mod.compare_ko_sections((minfo.get(k) or {}).get("elf") or {"ok": False, "reason": "the image's sections were not read"},
                                                      (got or {}).get("elf") or {"ok": False, "reason": "the record's .ko cannot be read"})
                    if kind is None:
                        bad = ("the record has a .ko of this name but its srcversion (or the image's) cannot be read, and the ELF section "
                               "comparison does not verify it (" + str(w) + "): not verified")
                    else:
                        verified_by[k] = w
            if bad:
                mismatch = bad
                continue
            if best is None or kind == "srcversion" or (kind == "sections" and best in ("sections_masked", "name_only")):
                best = kind
        # 同名的 .ko 在紀錄裡可以有好幾個（例如兩種建置的 nvidia.ko）：映像的 .ko 只要有一個候選用內容驗證過（srcversion 或 ELF 區段），
        # 就是那一個建置，其他候選不相干；沒有任何內容驗證過的候選，而有候選對不上 → 整個模組不採用。只比名稱的候選不抵銷對不上的候選。
        if mismatch and best not in ("srcversion", "sections", "sections_masked"):
            best, why = None, mismatch
        if best is None:
            unc.append((k, why))
        else:
            ident[best] += 1
            if best == "sections_masked" and len(masked_examples) < 3:
                masked_examples.append(f"{posixpath.basename(k)}: {verified_by.get(k)}")
    sm["covered"], sm["uncovered"], sm["identity"] = len(oot) - len(unc), len(unc), ident
    sm["uncovered_examples"] = [f"{posixpath.basename(k)}: {w}" for k, w in unc[:10]]
    sm["uncovered_modules"] = [posixpath.basename(k) for k, _ in unc[:200]]
    sm["verified_by"] = {"srcversion": ".modinfo srcversion equal", "sections": "code and data ELF sections identical (debug/notes/modinfo ignored)",
                         "sections_masked": "ELF sections identical except .rodata.str* strings that differ only in build date/time or build path (masked)",
                         "name_only": "module name only (the record has no .ko to compare)"}
    sm["masked_examples"] = masked_examples
    if unc:
        sm["reason"] = (f"{len(unc)} of {len(oot)} out-of-tree module(s) of the image have no usable build record, for example "
                        + "; ".join(sm["uncovered_examples"][:3]))
        return
    sm["used"], sm["reason"] = True, None
    brec.oot_records, brec.oot_complete = recs, True
    brec.stats.update(header_in_out_of_tree_deps=0, header_not_built_oot_checked=0)
    brecord["limitations"].append(
        f"Out-of-tree build records ({', '.join(x['source'] for x in sm['records'])}) cover all {len(oot)} out-of-tree module(s) of the image "
        f"({ident['srcversion']} matched by .modinfo srcversion, {ident['sections']} by identical ELF code and data sections, "
        f"{ident['sections_masked']} by identical sections except build date/time or build path strings (masked), {ident['name_only']} by module name only): a kernel header that "
        "no in-tree object and no out-of-tree module lists in its deps is judged not built; one that an out-of-tree module lists is "
        "built (by path suffix, so a same-named header of the module's own also counts). The records are trusted to be the builds of "
        "the image's modules; source files of out-of-tree modules are not judged.")


# =====================================================================================================
# 5. CNA 鏡像
# =====================================================================================================

def _sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


class Mirror:
    """tools/mirror/kernel-cve.sh 的輸出：SOURCE＋kernel-cves.zip（cve/published/<年>/CVE-….json）。只讀需要的紀錄。"""

    def __init__(self, path, max_age):
        self.path, self.zip = path, None
        self.state = {"path": path, "ok": False, "reason": None, "commit": None, "commit_date": None, "fetched_utc": None,
                      "age_days": None, "max_age_days": max_age, "source": None}
        self.state["reason"] = self._open(max_age)
        self.state["ok"] = self.state["reason"] is None

    def _open(self, max_age):
        if not self.path:
            return "沒有設定 CNA 鏡像（PILOT_ENV 的 KERNEL_CVE_MIRROR）"
        if not os.path.isdir(self.path):
            return f"CNA 鏡像資料夾不存在：{self.path}"
        sp = os.path.join(self.path, "SOURCE")
        try:
            if not stat.S_ISREG(os.lstat(sp).st_mode):
                return "SOURCE 不是一般檔案"
            src = dict(l.split("=", 1) for l in open(sp, encoding="utf-8").read().splitlines() if "=" in l)
        except OSError:
            return "缺少 SOURCE（無法判斷新舊）"
        for k in ("commit", "commit_date", "fetched_utc", "source", "zip_sha256"):
            self.state[k] = src.get(k)
        try:
            t = datetime.datetime.fromisoformat(str(src.get("fetched_utc")).replace("Z", "+00:00"))
        except ValueError:
            return "SOURCE 沒有可解析的 fetched_utc"
        age = (datetime.datetime.now(datetime.timezone.utc) - t).total_seconds() / 86400
        self.state["age_days"] = round(age, 1)
        if age > max_age:
            return f"CNA 鏡像過期：下載後 {age:.1f} 天 > {max_age:g} 天（fetched_utc={src.get('fetched_utc')}）"
        zp = os.path.join(self.path, "kernel-cves.zip")
        try:
            if not stat.S_ISREG(os.lstat(zp).st_mode):
                return "kernel-cves.zip 不是一般檔案"
            if _sha256(zp) != src.get("zip_sha256"):
                return "kernel-cves.zip 的 sha256 與 SOURCE 不符（下載不完整或被換掉）"
            self.zip = zipfile.ZipFile(zp)
        except (OSError, zipfile.BadZipFile) as e:
            return f"kernel-cves.zip 無法讀取（{type(e).__name__}）"
        return None

    def _load_record(self, cve):
        m = CVE_RE.fullmatch(cve)
        if not m:
            return None
        try:
            i = self.zip.getinfo(f"cve/published/{m.group(1)}/{cve}.json")
        except KeyError:
            return None
        if i.file_size > MAX_RECORD:
            return None
        try:
            d = json.loads(self.zip.read(i))
        except (ValueError, zipfile.BadZipFile, OSError):
            return None
        meta = d.get("cveMetadata") if isinstance(d, dict) else None
        if not isinstance(meta, dict) or meta.get("cveId") != cve or meta.get("state", "PUBLISHED") != "PUBLISHED" \
                or meta.get("assignerOrgId") != LINUX_CNA_ORG:
            return None
        return d

    @staticmethod
    def _linux_blocks(d):
        aff = ((d.get("containers") or {}).get("cna") or {}).get("affected") or []
        return [a for a in aff if isinstance(a, dict)] if isinstance(aff, list) else []

    def record(self, cve):
        """CVE → programFiles 清單（None：沒有紀錄；[]：紀錄沒有 programFiles）。"""
        d = self._load_record(cve)
        if d is None:
            return None
        files = []
        for a in self._linux_blocks(d):
            for p in (a.get("programFiles") or []) if isinstance(a.get("programFiles") or [], list) else []:
                if isinstance(p, str) and p not in files:
                    files.append(p)
        return files

    def new_code(self, cve, kbase):
        """CNA 紀錄說這個問題在核心之後的版本才出現 → 最早出現的版本字串；其他（含看不懂）→ None。判斷在 kernel_cna_version.introduced_after。"""
        d = self._load_record(cve)
        if d is None or kbase is None:
            return None
        ok, intro = kernel_cna_version().introduced_after(kbase, d)
        return intro if ok else None

    def fix_commits(self, cve):
        """CVE → CNA 紀錄裡的修補 commit（git 範圍的 lessThan，40 位十六進位；依出現順序、去重）。沒有紀錄 → []。"""
        d = self._load_record(cve)
        out = []
        for a in self._linux_blocks(d) if d else []:
            for e in a.get("versions") or [] if isinstance(a.get("versions") or [], list) else []:
                h = e.get("lessThan") if isinstance(e, dict) and e.get("versionType") == "git" else None
                if isinstance(h, str) and kernel_git_files().HASH_RE.fullmatch(h) and h not in out:
                    out.append(h)
        return out[:kernel_git_files().MAX_HASHES_PER_CVE]


# =====================================================================================================
# 6. 輸入：核心元件上的 CVE
# =====================================================================================================

def kernel_component_matcher(kmap):
    kc = kernelcheck()
    mapped = None
    if isinstance(kmap, dict):
        e = kmap.get("map_entry") or {}
        c = (e.get("component") if isinstance(e, dict) else None) or kmap.get("added") or {}
        if isinstance(c, dict) and c.get("name"):
            mapped = {"name": c.get("name"), "version": c.get("version"), "purl": c.get("purl")}

    def is_kernel(name, version, purl, typ=None):
        if mapped and name == mapped["name"] and (version == mapped["version"] or purl == mapped["purl"]):
            return True
        if typ in ("linux-kernel",):
            return True
        t, n = kc.purl_type_name(purl)
        if t is None:
            return False
        return t in kc.PACKAGE_TYPES and kc.is_kernel_package_name(n)
    return is_kernel, mapped


def kernel_cves(grype, findings, cves_file, kmap):
    """→ (CVE 集合（排序）, 元件 {name, version, purl} 或 None, 來源計數)。"""
    is_kernel, mapped = kernel_component_matcher(kmap)
    out, comp, n = set(), mapped, {"grype": 0, "dt": 0, "list": 0}
    if grype is not None:
        ms = grype.get("matches") if isinstance(grype, dict) else None
        if not isinstance(ms, list):
            raise InputError("Grype JSON 沒有 matches 清單")
        for m in ms:
            a = m.get("artifact") or {}
            if not is_kernel(a.get("name"), a.get("version"), a.get("purl"), a.get("type")):
                continue
            ids = [(m.get("vulnerability") or {}).get("id")] + [r.get("id") for r in m.get("relatedVulnerabilities") or [] if isinstance(r, dict)]
            got = {x for x in ids if isinstance(x, str) and CVE_RE.fullmatch(x)}
            if got:
                n["grype"] += 1
                out |= got
                comp = comp or {"name": a.get("name"), "version": a.get("version"), "purl": a.get("purl")}
    if findings is not None:
        if not isinstance(findings, list):
            raise InputError("DT findings 不是清單")
        for f in findings:
            c = f.get("component") or {}
            if not is_kernel(c.get("name"), c.get("version"), c.get("purl")):
                continue
            v = f.get("vulnerability") or {}
            ids = [v.get("vulnId")] + [x for a in v.get("aliases") or [] for x in (a.values() if isinstance(a, dict) else [a])]
            got = {m.group(0) for x in ids if isinstance(x, str) for m in [CVE_RE.search(x)] if m}
            if got:
                n["dt"] += 1
                out |= got
                comp = comp or {"name": c.get("name"), "version": c.get("version"), "purl": c.get("purl")}
    if cves_file:
        try:
            text = open(cves_file, encoding="utf-8").read()
        except OSError as e:
            raise InputError(f"--cves 讀不到（{e.strerror}）")
        got = {m.group(0) for m in CVE_RE.finditer(text)}
        n["list"] = len(got)
        out |= got
    return sorted(out, key=lambda c: (int(CVE_RE.fullmatch(c).group(1)), int(CVE_RE.fullmatch(c).group(2)))), comp, n


def kernel_cve_commits(grype, findings, kmap, cves):
    """Grype 與 DT findings 的核心元件發現 → {CVE: [上游核心 commit 雜湊]}（只認 git.kernel.org／github torvalds 的網址；
    References 的文字是不可信的資料，只用正規表示式取雜湊）。--stable-git 用來查沒有 CNA 紀錄的 CVE。"""
    is_kernel, _ = kernel_component_matcher(kmap)
    gf = kernel_git_files()
    want, out = set(cves), {}

    def add(ids, text):
        hs = gf.commit_hashes_in_text(text)
        for c in ids:
            if c in want and hs:
                cur = out.setdefault(c, [])
                cur += [h for h in hs if h not in cur]
    if isinstance(grype, dict) and isinstance(grype.get("matches"), list):
        for m in grype["matches"]:
            a = m.get("artifact") or {}
            if not is_kernel(a.get("name"), a.get("version"), a.get("purl"), a.get("type")):
                continue
            v = m.get("vulnerability") or {}
            rel = [r for r in m.get("relatedVulnerabilities") or [] if isinstance(r, dict)]
            ids = [x for x in [v.get("id")] + [r.get("id") for r in rel] if isinstance(x, str) and CVE_RE.fullmatch(x)]
            add(ids, "\n".join(u for u in (v.get("urls") or []) + [u for r in rel for u in r.get("urls") or []] if isinstance(u, str)))
    if isinstance(findings, list):
        for f in findings:
            c = f.get("component") or {}
            if not is_kernel(c.get("name"), c.get("version"), c.get("purl")):
                continue
            v = f.get("vulnerability") or {}
            ids = [v.get("vulnId")] + [x for al in v.get("aliases") or [] for x in (al.values() if isinstance(al, dict) else [al])]
            add([m.group(0) for x in ids if isinstance(x, str) for m in [CVE_RE.search(x)] if m], v.get("references"))
    return {c: v[:gf.MAX_HASHES_PER_CVE] for c, v in out.items()}


# =====================================================================================================
# 7. 主流程
# =====================================================================================================

def build_info(a, want, images=False):
    """--config＋--makefiles-dir 或 --from → (BuildInfo 或 None, GAP 的原因或 None, 來源標籤（只在 locate 時）)。
    C-kernel-module-map（kernel_module_map.py）共用。images：另外讀燒錄的核心（info.images；C-kernel-config 用）。"""
    if a.config:
        if getattr(a, "source_tree", None):
            raise InputError("--source-tree 只配 --from（--config 搭配 --makefiles-dir 已經指定 Makefile 的來源）")
        try:
            cfg_text = open(a.config, encoding="utf-8", errors="replace").read()
        except OSError as e:
            raise InputError(f"--config 讀不到（{e.strerror}）")
        col, base = collect_tree(a.makefiles_dir)
        files = {k[len(base):]: v for k, v in col.files.items() if k[:len(base)] == base}
        info = BuildInfo(files, cfg_text, os.path.abspath(a.config), want, {"type": "explicit", "label": "explicit"})
        info.tree_names = tree_names(col, {base: ()})
        return info, None, None
    col, src = collect(a.from_, a.prefix, images=images, modinfo=bool(getattr(a, "build_record", None)))
    emit_kernel_versions(a, col)
    if col is None:                              # --from 指到核心原始碼樹本身
        if getattr(a, "source_tree", None):
            raise InputError("--source-tree 不能配核心原始碼樹本身的 --from（已經是樹）")
        col, base = collect_tree(a.from_)
        files = {k[len(base):]: v for k, v in col.files.items() if k[:len(base)] == base}
        cfg = open(os.path.join(a.from_, ".config"), encoding="utf-8", errors="replace").read()
        info = BuildInfo(files, cfg, os.path.join(os.path.abspath(a.from_), ".config"), want, src)
        info.tree_names = tree_names(col, {base: ()})
        return info, None, None
    info, gap = locate(col, src, want)
    if info is not None and images:
        info.images = image_inputs(col)
        if info.images is not None and getattr(a, "prefer_rootfs_image", False):
            info.images["prefer_rootfs"] = True
    if info is not None and getattr(a, "source_tree", None):
        apply_source_tree(info, a.source_tree)
    return info, gap, src["label"]


TREE_VERSION_RE = re.compile(r"^(VERSION|PATCHLEVEL|SUBLEVEL|EXTRAVERSION)\s*[:?]?=\s*(\S*)\s*$", re.M)


def tree_version(files):
    """核心原始碼樹最上層 Makefile 的 VERSION／PATCHLEVEL／SUBLEVEL → ("6.1.75", "6.1") 或 (None, None)。只讀文字。"""
    mf = files.get(("Makefile",))
    if mf is None:
        return None, None
    got = {m.group(1): m.group(2) for m in TREE_VERSION_RE.finditer(mf[:65536].decode("utf-8", "replace"))}
    if not (got.get("VERSION", "").isdigit() and got.get("PATCHLEVEL", "").isdigit()):
        return None, None
    sub = got.get("SUBLEVEL", "")
    return (f"{got['VERSION']}.{got['PATCHLEVEL']}" + (f".{sub}" if sub.isdigit() else "")), f"{got['VERSION']}.{got['PATCHLEVEL']}"


def apply_source_tree(info, tree):
    """--source-tree：Makefile／Kbuild 與檔案名稱改讀核心原始碼樹（collect_tree：唯讀、不跟隨符號連結、不執行任何東西、
    沿用 MAX_FILE／MAX_TOTAL／MAX_ENTRIES／MAX_SRC_NAMES 的上限）。.config、模組與 Image 照舊來自映像。
    info.files 和 info.tree_names 換成樹的；樹的 .config 的內容留在 info.source_tree["_config"]（settle_config 之後才能核對，
    不寫進輸出）。"""
    root = os.path.abspath(tree)
    if not os.path.isdir(root):
        raise InputError("--source-tree 不是資料夾")
    col, base = collect_tree(root)
    files = {k[len(base):]: v for k, v in col.files.items() if k[:len(base)] == base}
    cfg = files.pop((".config",), None)
    ver, mm = tree_version(files)
    n_mk = sum(1 for k in files if k and k[-1] in ("Makefile", "Kbuild"))
    info.files = files
    info.tree_names = tree_names(col, {base: ()})
    info.tree_links = frozenset("/".join(k[len(base):]) for k in col.links if k[:len(base)] == base)     # 樹裡的符號連結（沒有跟隨）
    info.source_tree = {"type": "source-tree", "path_label": os.path.basename(root.rstrip("/")) or "(root)",
                        "version": ver, "major_minor": mm, "makefiles": n_mk, "links_not_followed": len(col.links),
                        "has_config": cfg is not None, "config_compare": None, "_config": cfg}
    return info.source_tree


def source_tree_check(info):
    """settle_config 之後：樹的 .config 和判定用的設定核對 → 寫進 info.source_tree["config_compare"]（沒有 .config 的樹記 no_config）。
    相同（沒有的設定和 is not set 都算 n）→ same；只差工具鏈 → same_except_toolchain；其他 → differs。"""
    st = info.source_tree
    if not st:
        return None
    cfg = st.pop("_config", None)
    if cfg is None:
        st["config_compare"] = {"result": "no_config"}
        return st
    ctext = cfg.decode("utf-8", "replace")
    _, hh, _, ih, _, names, tool = config_diff(info.config_text, ctext)
    res = "same" if not names and hh == ih else "same_except_toolchain" if len(tool) == len(names) and hh == ih else "differs"
    st["config_compare"] = {"result": res, "tree_config_sha256": hashlib.sha256(cfg).hexdigest(),
                            "judged_config_sha256": hashlib.sha256(info.config_raw if info.config_raw is not None else
                                                                   info.config_text.encode("utf-8", "surrogateescape")).hexdigest(),
                            "differences_total": len(names), "toolchain_differences_total": len(tool),
                            "examples": sorted(names, key=lambda n: (is_toolchain_option(n), n))[:10],
                            "header": {"judged": list(hh), "tree": list(ih)} if hh != ih else None}
    return st


def source_tree_gap(info, model):
    """樹的主.次版本和判定的核心（.config 標頭）不同 → GAP 的原因；沒有或相同 → None。樹的版本不明也 GAP（不猜）。"""
    st = info.source_tree
    if not st:
        return None
    want = major_minor(model.kver_hdr)
    if st["major_minor"] is None:
        return "--source-tree 的最上層 Makefile 讀不出核心版本（VERSION／PATCHLEVEL）：不確定是哪個核心的原始碼"
    if want and st["major_minor"] != want:
        return f"--source-tree 是核心 {st['version']} 的原始碼，判定用的設定是核心 {model.kver_hdr} 的（主.次版本不同）：不是同一個核心"
    return None


def vendor_kernel_component(version):
    """CVE 清單不是來自 Grype／DT 的元件（廠商核心，不是套件）：用核心版本當元件（pkg:generic/linux-kernel、CPE linux_kernel；
    kernelcheck.py 與 cra_report 的 is_kernel_row 認得）。"""
    return {"name": "linux-kernel", "version": version, "purl": f"pkg:generic/linux-kernel@{version}",
            "cpe": f"cpe:2.3:o:linux:linux_kernel:{version}:*:*:*:*:*:*:*"}


def is_toolchain_option(name):
    """CONFIG_ 設定 → 是不是工具鏈衍生的（TOOLCHAIN_OPTION_*）。"""
    n = name[len("CONFIG_"):] if name.startswith("CONFIG_") else name
    return n in TOOLCHAIN_OPTION_NAMES or n.startswith(TOOLCHAIN_OPTION_PREFIXES) or n.endswith(TOOLCHAIN_OPTION_SUFFIXES)


def config_value(vals, name):
    """比較兩份 .config 用的值：沒有這一項和「# CONFIG_X is not set」都是 n（Kconfig 的語意：bool／tristate 缺少就是 n）。"""
    v = vals.get(name)
    return "n" if v is None else v


def config_diff(a_text, b_text):
    """兩份 .config 的比較（config_check 與建置紀錄共用同一個規則）→ (a 的值, a 的標頭, b 的值, b 的標頭, 原始不同的名稱,
    正規化後不同的名稱（排序）, 其中工具鏈衍生的)。「沒有這一項」和「is not set」都算 n 之後才比。"""
    av, ah = parse_config(a_text)
    bv, bh = parse_config(b_text)
    raw_names = [n for n in set(av) | set(bv) if av.get(n) != bv.get(n)]
    names = sorted(n for n in raw_names if config_value(av, n) != config_value(bv, n))
    return av, ah, bv, bh, raw_names, names, [n for n in names if is_toolchain_option(n)]


def _cut(v):
    return v if v is None or len(v) <= MAX_DIFF_VALUE else v[:MAX_DIFF_VALUE] + "…"


def dpkg_owner(md5sums, path):
    """md5sums（{套件檔名: {路徑: md5}}）裡擁有 path 的 → ([(套件, 架構或 None, md5)], 原因或 None)。"""
    got = []
    for f, m in sorted(md5sums.items()):
        if path in m:
            name, _, arch = f.partition(":")
            got.append((name, arch or None, m[path]))
    if not got:
        return [], f"找不到擁有 {path} 的套件（var/lib/dpkg/info/*.md5sums）"
    if len({(n, x) for n, x, _ in got}) > 1:
        return got, f"{path} 有多個套件擁有（{'、'.join(sorted({n for n, _, _ in got}))[:200]}）"
    return got, None


def dpkg_version(versions, name, arch):
    """→ ((版本, 原始碼套件), None) 或 (None, 原因)。"""
    vs = {(v, src) for a, v, src in versions.get(name, ()) if arch is None or a in (arch, None, "all")}
    if not vs:
        return None, f"var/lib/dpkg/status 沒有 {name} 的安裝紀錄"
    if len({v for v, _ in vs}) > 1 or len(vs) > 1:
        return None, f"var/lib/dpkg/status 的 {name} 有多個版本（{'、'.join(sorted(v for v, _ in vs))[:120]}）"
    return next(iter(vs)), None


# 核心套件與 headers 套件是同一組（擁有 /boot/Image 的套件 → 擁有 headers .config 的套件）：
#   Jetson：<X> 與 <X>-headers（nvidia-l4t-kernel／nvidia-l4t-kernel-headers；nvidia-l4t-rt-kernel／nvidia-l4t-rt-kernel-headers）；
#   Ubuntu：linux-image-<版本-flavour>（含 linux-image-unsigned-…）與 linux-headers-<版本-flavour>（.config 在有 flavour 的那一層，
#   例如 linux-headers-6.8.0-45-generic；沒有 flavour 的 linux-headers-6.8.0-45 是共用的那一層，不擁有 .config，不算）。
UBUNTU_IMAGE_PREFIXES = ("linux-image-unsigned-", "linux-image-")


def dpkg_paired(kname, hname):
    """名稱成對 → 規則的說明；不成對 → None。"""
    if hname == kname + "-headers":
        return f"{hname} = {kname}-headers"
    for pre in UBUNTU_IMAGE_PREFIXES:
        if kname.startswith(pre) and len(kname) > len(pre) and hname == "linux-headers-" + kname[len(pre):]:
            return f"{pre}<v> / linux-headers-<v> (<v> = {kname[len(pre):]})"
    return None


def dpkg_verify(info, fl, rf):
    """讀不到 IKCONFIG 時用 dpkg 驗證燒錄的核心就是 headers 那個核心（rootfs 的 var/lib/dpkg；不可信資料，只解析）→ (紀錄, 不成立的原因或 None)。
      1. 擁有 rootfs 的 /boot/Image（連結解開後的檔案）的套件，md5sums 記的 md5 和 /boot/Image 相同；
      2. 刷機包（fl 不是 None）：kernel/Image 的 md5 也相同（燒錄時蓋掉 /boot/Image；Image.gz 等比解壓後的 md5）；
      3. headers 的 .config 的 md5 和擁有它的套件記的相同；兩個套件同版本（dpkg status），而且是同一組（dpkg_paired 的名稱成對，
         Source 相同不算）。
    rootfs 的 dpkg 和 Image、headers 來自同一個不可信的 rootfs：這是一致性檢查，不能防竄改（IMAGE_LIMITATIONS）。"""
    dp = (info.images or {}).get("dpkg") or {}
    rec = {"checks": [], "kernel_package": None, "headers_package": None}
    if rf is None:
        return rec, "rootfs 沒有 /boot/Image（第 1 項無法核對）"
    if not rf.md5:
        return rec, f"rootfs 的 /boot/Image 讀不到（{rf.reason}；第 1 項無法核對）"
    md5s = dp.get("md5sums") or {}
    if not md5s:
        return rec, "讀不到 dpkg 的 md5sums（var/lib/dpkg/info/*.md5sums）" + (
            f"（超過上限而略過：{'、'.join(dp['md5sums_skipped'][:3])}）" if dp.get("md5sums_skipped") else "")
    ipath = (rf.link_target or rf.path).lstrip("/")
    own, why = dpkg_owner(md5s, ipath)
    if why:
        return rec, why
    kname, karch, kmd5 = own[0]
    rec["kernel_package"] = {"name": kname, "arch": karch, "version": None, "path": ipath, "md5": kmd5}
    ok1 = kmd5 == rf.md5
    rec["checks"].append({"check": "rootfs /boot/Image md5 == dpkg md5sums", "ok": ok1, "image_md5": rf.md5})
    if not ok1:
        return rec, f"第 1 項不成立：rootfs 的 /{ipath} md5 {rf.md5} 和套件 {kname} 記的 {kmd5} 不同"
    if fl is not None:
        # kernel/Image.gz（或本身是壓縮檔的 Image）：燒錄時寫成 /boot/Image 的是解壓後的內容，所以解壓後的 md5 或檔案本身的 md5
        # 任一個和套件記的相同就算同一份核心（/boot/Image 本身也是壓縮檔時，兩邊都比檔案本身）
        fmd5 = fl.unpacked_md5 if fl.format not in (None, "raw") else fl.md5
        ok2 = kmd5 in {m for m in (fl.md5, fl.unpacked_md5) if m}
        if ok2 and kmd5 == fl.md5:
            fmd5 = fl.md5
        rec["checks"].append({"check": "kernel/Image md5 == dpkg md5sums" + (" (decompressed)" if fmd5 is fl.unpacked_md5 and fmd5 else ""),
                              "ok": ok2, "image_md5": fmd5})
        if not ok2:
            return rec, (f"第 2 項不成立：{posixpath.basename(fl.path)} 的 md5 "
                         f"{fmd5 or f'讀不到（{fl.reason}）'}{'（解壓後）' if fl.format not in (None, 'raw') else ''} 和套件 {kname} 記的 /{ipath} "
                         f"{kmd5} 不同（刷機包的核心不是 dpkg 記的那一份）")
    hpath = str(info.config_path or "").lstrip("/")
    hown, why = dpkg_owner(md5s, hpath)
    if why:
        return rec, f"第 3 項無法核對：{why}"
    hname, harch, hmd5 = hown[0]
    cmd5 = hashlib.md5(info.config_raw, usedforsecurity=False).hexdigest() if info.config_raw is not None else None
    rec["headers_package"] = {"name": hname, "arch": harch, "version": None, "path": hpath, "md5": hmd5}
    okc = cmd5 is not None and cmd5 == hmd5
    rec["checks"].append({"check": "headers .config md5 == dpkg md5sums", "ok": okc, "config_md5": cmd5})
    if not okc:
        return rec, (f"第 3 項不成立：headers 的 /{hpath} md5 {cmd5 or '讀不到'} 和套件 {hname} 記的 {hmd5} 不同"
                     "（.config 被換過或改過，例如為了編 out-of-tree 模組複製進來的）")
    if dp.get("status") is None:
        return rec, f"讀不到 var/lib/dpkg/status（{dp.get('status_reason') or '沒有這個檔案'}；第 3 項無法核對）"
    vers = dpkg_status_versions(dp["status"])
    kvs, why = dpkg_version(vers, kname, karch)
    if why:
        return rec, f"第 3 項無法核對：{why}"
    hvs, why = dpkg_version(vers, hname, harch)
    if why:
        return rec, f"第 3 項無法核對：{why}"
    (kv, ksrc), (hv, hsrc) = kvs, hvs
    rec["kernel_package"].update(version=kv, source=ksrc)
    rec["headers_package"].update(version=hv, source=hsrc)
    ok3 = kv == hv
    rec["checks"].append({"check": "kernel package version == headers package version", "ok": ok3})
    if not ok3:
        return rec, f"第 3 項不成立：{kname} 是 {kv}，headers 的 {hname} 是 {hv}（版本不同）"
    # 只認名稱成對：Source 相同不算（L4T 的 RT 核心與一般核心可能來自同一個原始碼套件，設定卻不同，例如 PREEMPT_RT）
    pair = dpkg_paired(kname, hname)
    rec["checks"].append({"check": "kernel and headers packages belong together (name pair)", "ok": pair is not None,
                          "rule": pair})
    if pair is None:
        return rec, (f"第 3 項不成立：{kname} 和 headers 的 {hname} 不是同一組（名稱不成對：要 <X>／<X>-headers 或 "
                     f"linux-image-<v>／linux-headers-<v>；Source 相同也不算），版本相同不代表是同一個核心")
    return rec, None


def config_check(info):
    """headers 的 .config 和燒錄的核心（info.images）核對 → None（沒有讀到任何 Image：照舊，輸出和以前相同）或 dict：
      record：寫進 kernel.config_check；use：要改用的 config（bytes，不同時）或 None；label：改用時的 config_source；
      gap：GAP 的原因或 None；note：附在說明後面的一句（或 None）；lead：改用時放在說明前面的一句。
    主要的 Image：刷機包的 kernel/Image（有的話），否則 rootfs 的 /boot/Image（連結在映像裡解開）。
      有 IKCONFIG：設定（CONFIG_ 的值與 Linux/<ARCH> <版本> 標頭）和 headers 相同 → 照舊；不同 → 改用 IKCONFIG（ATTENTION；
        image.ikconfig_complete 記 IKCONFIG 是否完整，讀取端只採用完整的）。
      沒有 IKCONFIG（或讀不到）：dpkg 驗證（dpkg_verify）成立 → 照舊（dpkg_verified）；任何一項不成立 → GAP。判定的規則不變，只換設定的來源。"""
    imgs = getattr(info, "images", None)
    if not imgs:
        return None
    fl, rf = imgs.get("flashed"), imgs.get("rootfs")
    prefer = bool(imgs.get("prefer_rootfs")) and rf is not None      # 板子證明跑的是 rootfs/boot/Image：判定改用它（C-kernel-boot）
    pkg = fl is not None and not prefer
    prim = fl if pkg else rf
    name = ("kernel/" + posixpath.basename(prim.path)) if pkg else prim.path
    raw = info.config_raw if info.config_raw is not None else info.config_text.encode("utf-8", "surrogateescape")
    hsha = hashlib.sha256(raw).hexdigest()
    rec = {"result": None, "image_source": "flash package" if pkg else "rootfs", "image": prim.json()}
    if prefer:
        rec["image_source"] = "rootfs (the board runs rootfs/boot/Image, not kernel/Image)"
        rec["partition_image"] = fl.json() if fl is not None else None
    if pkg:
        rec["rootfs_image"] = rf.json() if rf is not None else None
    rec["headers_config"] = {"path": info.config_path, "sha256": hsha}
    rec["image_config_sha256"] = hashlib.sha256(prim.config).hexdigest() if prim.config is not None else None
    rec["limitations"] = IMAGE_LIMITATIONS
    res = {"record": rec, "use": None, "label": None, "gap": None, "note": None, "lead": None, "attention": False}
    if prim.config is not None:
        text = prim.config.decode("utf-8", "replace")
        # 「沒有這一項」和「is not set」都當成 n 之後才比（原始的差異數另記 raw_differences_total）
        hv, hh, iv, ih, raw_names, names, tool = config_diff(info.config_text, text)
        rec["bytes_identical"] = rec["image_config_sha256"] == hsha
        rec["raw_differences_total"] = len(raw_names)
        if len(tool) == len(names) and hh == ih and not prim.complete:
            # 設定看起來相同（或只差工具鏈）、但 IKCONFIG 不完整：不能確認，改走 dpkg 驗證（下面）
            rec["ikconfig_same_but_incomplete"] = True
        elif not names and hh == ih:
            rec["result"] = "same"
            rec["note"] = (f"the built-in configuration (IKCONFIG) of {name} has the same settings as the headers .config"
                           + ("" if rec["bytes_identical"] else " (compared with a missing option counted as 'is not set')"))
            res["note"] = f"{name} 的內建設定（IKCONFIG）和 headers .config 相同" + ("" if rec["bytes_identical"] else "（沒有的設定算 n）")
            return res
        elif len(tool) == len(names) and hh == ih:
            return ikconfig_differs(rec, res, prim, name, names, hv, iv, hh, ih, toolchain_only=True)
        else:
            return ikconfig_differs(rec, res, prim, name, names, hv, iv, hh, ih)
    why = prim.reason or "no IKCONFIG"
    drec, fail = dpkg_verify(info, None if prefer else fl, rf)      # prefer：板子跑 rootfs 的 Image，kernel/Image 與驗證無關
    rec["dpkg"] = drec
    if fail is None:
        k, h = drec["kernel_package"], drec["headers_package"]
        rec["result"] = "dpkg_verified"
        rec["note"] = (f"{name} has no readable IKCONFIG ({why}); dpkg shows it is the kernel of package {k['name']} {k['version']} "
                       f"(md5 matches) and the headers .config belongs to {h['name']} of the same version (md5 matches): the headers "
                       ".config is used" + ("" if pkg else "; the flashed kernel/Image is not visible (rootfs only)"))
        res["note"] = (f"{name} 讀不到 IKCONFIG（{why}），dpkg 驗證通過（{k['name']} {k['version']} 的 md5 和 "
                       f"{'kernel/Image、' if pkg else ''}/boot/Image 相符，headers 的 {h['name']} 同一組、同版本、.config 的 md5 相符），"
                       "沿用 headers .config" + ("" if pkg else "；只有 rootfs，看不到實際燒錄的 kernel/Image"))
        return res
    rec["result"] = "dpkg_not_verified"
    rec["note"] = f"{name} has no readable IKCONFIG ({why}) and dpkg cannot show it is the kernel the headers belong to"
    rec["dpkg"]["failed"] = fail
    res["gap"] = f"燒錄的核心和 headers 可能不一致，無法確認設定（{name} 讀不到 IKCONFIG：{why}；dpkg 驗證不成立：{fail}）"
    return res


def ikconfig_differs(rec, res, prim, name, names, hv, iv, hh, ih, toolchain_only=False):
    """config_check：IKCONFIG 和 headers 的設定不同（names：正規化後不同的設定）→ 改用 IKCONFIG。
    toolchain_only（只差工具鏈衍生的設定、標頭相同、IKCONFIG 完整）→ same_except_toolchain，status OK；其他 → differs，ATTENTION。
    IKCONFIG 標頭的架構和 headers 不同 → GAP。"""
    tool = [n for n in names if is_toolchain_option(n)]
    if hh != ih:
        rec["config_header"] = {"headers": list(hh), "image": list(ih)}
    rec["differences_total"] = len(names)
    rec["toolchain_differences_total"] = len(tool)
    rec["differences_truncated"] = len(names) > MAX_CONFIG_DIFF
    # 非工具鏈的排在前面（截斷時先留下）
    shown = sorted(names, key=lambda n: (is_toolchain_option(n), n))[:MAX_CONFIG_DIFF]
    rec["differences"] = [{"name": n, "headers": _cut(hv.get(n)), "image": _cut(iv.get(n)), "toolchain": is_toolchain_option(n)}
                          for n in shown]
    res.update(use=prim.config, label=f"{name} (IKCONFIG)")
    if toolchain_only:
        rec["result"] = "same_except_toolchain"
        rec["note"] = (f"the headers .config differs from the built-in configuration (IKCONFIG) of {name} only in toolchain options "
                       f"({len(names)}: {', '.join(names[:6])}{', …' if len(names) > 6 else ''}); the IKCONFIG is used")
        res["note"] = (f"headers .config 和 {name} 的內建設定（IKCONFIG）只差工具鏈的 {len(names)} 項"
                       f"（{'、'.join(names[:4])}{'…' if len(names) > 4 else ''}），改用 IKCONFIG 判定")
        return res
    res["attention"] = True
    rec["result"] = "differs"
    rec["note"] = (f"the headers .config differs from the flashed kernel; the built-in configuration (IKCONFIG) of {name} "
                   "is used instead" + ("" if prim.complete else f" (IKCONFIG incomplete: {prim.reason})"))
    eg = "、".join(shown[:3]) + ("…" if len(names) > 3 else "")
    res["lead"] = (f"headers .config 和燒錄的核心不同，已改用燒錄核心的內建設定（{name} 的 IKCONFIG；差 {len(names)} 個設定"
                   + (f"，例如 {eg}" if names else "") + ("；.config 標頭的架構或版本也不同" if hh != ih else "")
                   + ("" if prim.complete else f"；IKCONFIG 不完整（{prim.reason}），讀取端不採用") + "）")
    ha, ia = SRCARCH_OF.get(hh[0], hh[0]), SRCARCH_OF.get(ih[0], ih[0])
    if ha != ia:
        # 版本不同之後由核心版本的核對記 GAP；架構不同在這裡就 GAP（不能拿另一個架構的設定判定）
        rec["result"] = "differs_arch_mismatch"
        res.update(use=None, label=None, lead=None, attention=False)
        res["gap"] = (f"燒錄的核心和 headers 不是同一個架構，無法確認設定（{name} 的 IKCONFIG 標頭是 Linux/{ih[0] or '?'}，"
                      f"headers 的 .config 是 Linux/{hh[0] or '?'}）")
    return res


def settle_config(info):
    """C-kernel-config 與 C-kernel-module-map 共用：核對燒錄的核心（config_check），不同時把 info 的設定換成 IKCONFIG
    → (config_check 的結果或 None, 設定的 sha256)。sha256：有 config_check 時用原始位元組算（兩個欄位一致）；
    沒有時照以前的算法（輸出和以前逐位元組相同）。"""
    chk = config_check(info)
    if chk and chk["use"] is not None:
        info.config_raw, info.config_path = chk["use"], chk["label"]        # 只換設定的來源，判定的規則不變
        info.config_text = chk["use"].decode("utf-8", "replace")
    source_tree_check(info)                      # --source-tree 的 .config 和判定用的設定核對（沒有 --source-tree 時什麼都不做）
    if chk:
        raw = info.config_raw if info.config_raw is not None else info.config_text.encode("utf-8", "surrogateescape")
        return chk, hashlib.sha256(raw).hexdigest()
    return None, hashlib.sha256(info.config_text.encode("utf-8", "surrogateescape")).hexdigest()


def assess(a, max_age):
    """→ (狀態, 說明, 輸出 dict 或 None)。"""
    kmap = load_json(a.kernel_map, "核心對應摘要")
    cves, comp, srcn = kernel_cves(load_json(a.grype, "Grype JSON"), load_json(a.findings, "DT findings"), a.cves, kmap)
    if not cves:
        return "NOT_RUN", "沒有核心元件上的 CVE（不是含核心的映像，或核心沒有比對）", None
    want = a.kernel_version or ((kmap or {}).get("map_entry") or {}).get("modules_kernel_version") or None
    out = {"schema": SCHEMA, "status": None, "detail": None,
           "kernel": {"version": want, "config_source": None, "config_sha256": None, "makefiles": 0, "source": None},
           "cve_data": {"source": None, "commit_or_date": None},
           "component": comp, "results": [], "counts": {k: 0 for k in DECISIONS},
           "inputs": {"kernel_cves": len(cves), "from_grype_matches": srcn["grype"], "from_dt_findings": srcn["dt"], "from_list": srcn["list"]},
           "limitations": LIMITATIONS}
    if getattr(a, "cves_origin", None):
        out["inputs"]["cves_origin"] = a.cves_origin          # 例如 kernel-cna-version：CVE 清單不是 Grype／DT 的
    info, gap, label = build_info(a, want, images=True)
    if label:
        out["kernel"]["source"] = label
    mir = Mirror(a.mirror, max_age)
    out["cve_data"] = {"source": mir.state.get("source"), "commit_or_date": (f"{mir.state.get('commit')} ({mir.state.get('commit_date')})"
                                                                            if mir.state.get("commit") else mir.state.get("fetched_utc")),
                       "fetched_utc": mir.state.get("fetched_utc"), "zip_sha256": mir.state.get("zip_sha256"),
                       "ok": mir.state["ok"], "reason": mir.state["reason"]}
    if gap:
        return "GAP", f"{len(cves)} 個核心 CVE 沒有依 .config 判定：{gap}", out
    chk, ksha = settle_config(info)
    if getattr(a, "cves_origin", None) and not out["component"] and (info.kernel_version or want):
        out["component"] = vendor_kernel_component(info.kernel_version or want)     # 清單不是 Grype／DT 的：元件由核心版本決定
    out["kernel"].update({"version": info.kernel_version or want, "config_source": info.config_path, "config_sha256": ksha,
                          "makefiles": sum(1 for k in info.files if k and k[-1] in ("Makefile", "Kbuild")),
                          "source": info.source.get("label")})
    if info.source_tree:
        out["kernel"]["makefiles_from"] = "source-tree"
        out["kernel"]["source_tree"] = info.source_tree
    if chk:
        out["kernel"]["config_check"] = chk["record"]
        if chk["gap"]:
            return "GAP", f"{len(cves)} 個核心 CVE 沒有依 .config 判定：{chk['gap']}", out
    if out["kernel"]["makefiles"] < 50:
        if info.source_tree:
            return "GAP", (f"{len(cves)} 個核心 CVE 沒有依 .config 判定：--source-tree 只有 {out['kernel']['makefiles']} 個 Makefile／Kbuild"
                           "（不像核心原始碼樹），無法判斷檔案有沒有編"), out
        return "GAP", (f"{len(cves)} 個核心 CVE 沒有依 .config 判定：{info.config_path} 旁邊只有 {out['kernel']['makefiles']} 個 Makefile／Kbuild"
                       "（headers 不完整），無法判斷檔案有沒有編"), out
    model = Model(info)
    kv = info.kernel_version
    out["kernel"]["config_header"] = {"arch": model.srcarch, "version": model.kver_hdr}
    tgap = source_tree_gap(info, model)
    if tgap:
        return "GAP", f"{len(cves)} 個核心 CVE 沒有依 .config 判定：{tgap}", out
    mm = major_minor(model.kver_hdr)
    out["kernel"]["included_c_list"] = mm if mm in included_c_versions() else None
    if out["kernel"]["included_c_list"] is None:
        out["limitations"] = list(LIMITATIONS) + [
            f"No list of #included .c files for kernel {mm or '(unknown version)'}: no CVE was judged not_affected."]
    if kv and model.kver_hdr and not (kv == model.kver_hdr or kv.startswith(model.kver_hdr + "-") or kv.startswith(model.kver_hdr + "+")):
        return "GAP", (f"{len(cves)} 個核心 CVE 沒有依 .config 判定：.config 是核心 {model.kver_hdr} 的，模組目錄是 {kv}（不是同一個核心）"), out
    if not mir.state["ok"]:
        return "GAP", f"{len(cves)} 個核心 CVE 沒有依 .config 判定：{mir.state['reason']}", out
    mods = info.modules.get("ko") if info.modules else None
    if info.modules:
        out["kernel"]["modules"] = len(mods or ())
        miss = [n for n in ("modules.builtin", "modules.order") if n not in (info.modules.get("files") or {})]
        if miss:
            out["limitations"] = list(out["limitations"]) + [
                f"The image's module directory has no {' / '.join(miss)}: a file judged not built is not cross-checked "
                "against that list (a listed object would otherwise make it unknown)."]
    mfiles = (info.modules or {}).get("files") or {}
    km = module_map()
    mapper = km.Mapper(model, mods, km.ModList(mfiles["modules.order"]) if "modules.order" in mfiles else None,
                       km.ModList(mfiles["modules.builtin"]) if "modules.builtin" in mfiles else None)
    brec = None
    if getattr(a, "build_record", None):
        # 建置紀錄：驗證過才用（check_build_record）；GAP 時照舊只用 Makefile 的判定，kernel.build_record 記原因
        brecord, brec = check_build_record(read_build_record(a.build_record), info, model, mods)
        out["kernel"]["build_record"] = brecord
        if getattr(a, "oot_build_record", None):
            attach_oot_records(brec, brecord, a.oot_build_record, info, mods)
    elif getattr(a, "oot_build_record", None):
        out["kernel"]["build_record"] = {"source": None, "status": "NOT_RUN", "limitations": [],
                                         "out_of_tree_records": {"records": [], "image_modules": None, "covered": 0, "uncovered": 0,
                                                                "uncovered_examples": [], "identity": {}, "used": False,
                                                                "reason": "--oot-build-record needs --build-record"}}
    sg = None
    if getattr(a, "stable_git", None):
        sg = kernel_git_files().StableGit(a.stable_git)
        out["kernel"]["stable_git"] = {"source": sg.label, "ok": sg.ok, "reason": sg.error, "head": sg.head, "refs": sg.branch,
                                       "cves_with_commit_files": 0, "cves_with_added_files": 0, "cves_from_references_only": 0,
                                       "commits_resolved": 0, "decision_changes": {},
                                       "note": "read-only local clone; no fetch. Files are the file names in the history of this clone; "
                                               "a commit that the clone does not have is not used (unknown, as without --stable-git)."}
        out["limitations"] = list(out["limitations"]) + [STABLE_GIT_LIMITATION]
    cve_refs = {}
    if sg is not None and sg.ok:
        cve_refs = kernel_cve_commits(load_json(a.grype, "Grype JSON"), load_json(a.findings, "DT findings"), kmap, cves)
        # 查 clone 的雜湊一次查完（CNA 紀錄的修補 commit、References 的 commit）
        allh = []
        for cve in cves:
            allh += mir.fix_commits(cve) if mir.state["ok"] else []
            allh += cve_refs.get(cve, [])
        sg.files(allh)
    kbase = kernel_base_tuple(model.kver_hdr or info.kernel_version)
    if brec is not None and info.source_tree and getattr(info, "tree_names", None) is not None and kbase:
        brec.full_tree, brec.tree_links = True, getattr(info, "tree_links", frozenset())
        brec.stats["absent_new_code"] = 0
        out["kernel"]["build_record"]["limitations"].append(NEW_CODE_LIMITATION)
    base_counts = {k: 0 for k in DECISIONS}
    changes = {}
    unk = {"no_cna_record": 0, "no_program_files": 0, "header_or_non_source": 0, "undetermined": 0}
    for cve in cves:
        files = mir.record(cve)
        origin, gfiles, commits = "cna", [], []
        if sg is not None and sg.ok:
            if files is not None:
                # (b) CNA 的修補 commit（產品分支的 backport）實際改的檔案，和 programFiles 聯集（只會更保守）
                # 只加「程式檔與標頭檔」，而且這個核心有這個檔案（沒有的檔案本來就不可能編進這個核心，加進去只會多一個
                # 「看不出存在」的 unknown）；CNA 的 programFiles 本來的判定不變，聯集只會更保守
                fc = sg.files(mir.fix_commits(cve))
                commits = [h for h, f in fc.items() if f]
                gfiles = sorted(x for x in {x for h in commits for x in fc[h]} - set(files)
                                if code_file(x) and kernel_has_file(model, info, x))
                if gfiles:
                    origin = "cna+commits" if files else "commits"
            else:
                # (a) 沒有 CNA 紀錄：References 的 commit 都查得到才用（有一個查不到就整個不用）；檔案只取程式檔與標頭檔
                # （MAINTAINERS、Documentation、Kconfig、Makefile 不是有漏洞的程式；CNA 的 programFiles 也不列）
                hs = cve_refs.get(cve) or []
                fc = sg.files(hs)
                if hs and all(fc[h] for h in hs):
                    gf = sorted({x for h in hs for x in fc[h] if code_file(x)})
                    if gf:
                        commits, gfiles, origin = hs, gf, "commits-from-references"
        base_files = files
        if gfiles:
            files = (files or []) + gfiles
        if files is None:
            res = {"cve": cve, "decision": "unknown", "detail": "no Linux kernel CNA record in the mirror", "files": [], "config_values": {}}
            unk["no_cna_record"] += 1
        elif not files:
            res = {"cve": cve, "decision": "unknown", "detail": "the CNA record lists no programFiles", "files": [], "config_values": {}}
            unk["no_program_files"] += 1
        else:
            nc = None
            if brec is not None and brec.full_tree and base_files:
                nc = mir.new_code(cve, kbase)          # CNA 紀錄：這個問題比核心新（只有核心原始碼樹完整時才用）
            dec, detail, fl, vals = judge_cve(model, files, mods, mapper, brec, nc)
            if brec is not None:
                d0 = judge_cve(model, files, mods, mapper)[0]          # 只用 Makefile 的判定（比較用）
                base_counts[d0] += 1
                if d0 != dec:
                    changes[f"{d0}->{dec}"] = changes.get(f"{d0}->{dec}", 0) + 1
            if gfiles:
                sgo = out["kernel"]["stable_git"]
                d1 = (judge_cve(model, base_files, mods, mapper, brec)[0] if base_files else "unknown")
                k = f"{d1}->{dec}"
                sgo["decision_changes"][k] = sgo["decision_changes"].get(k, 0) + 1
                sgo["cves_with_added_files" if base_files is not None else "cves_from_references_only"] += 1
                detail += (f"; files from local linux-stable commit(s) {', '.join(h[:12] for h in commits[:3])}"
                           + (f" (added to programFiles: {', '.join(gfiles[:3])})" if base_files is not None else " (no CNA record; commits from references)"))
            res = {"cve": cve, "decision": dec}
            if dec == "not_affected":
                res["justification"] = "vulnerable_code_not_present"
            res.update({"detail": detail, "files": fl, "config_values": vals})
            if gfiles:
                res["files_origin"] = origin
                res["stable_git_commits"] = [h[:12] for h in commits[:10]]
                res["stable_git_added_files"] = gfiles[:20]
            if dec == "unknown":
                if any(classify_file(f)[0] != "object" for f in files):
                    unk["header_or_non_source"] += 1
                else:
                    unk["undetermined"] += 1
        if brec is not None and not files:
            base_counts["unknown"] += 1
        out["results"].append(res)
        out["counts"][res["decision"]] += 1
    if sg is not None and sg.ok:
        out["kernel"]["stable_git"]["commits_resolved"] = sg.resolved
        out["kernel"]["stable_git"]["cves_with_commit_files"] = sum(1 for r in out["results"] if r.get("files_origin"))
    out["unknown_reasons"] = unk
    rsuffix = ""
    if brec is not None:
        br = out["kernel"]["build_record"]
        br.update(counts_without_record=base_counts, decision_changes=dict(sorted(changes.items())), file_judgements=dict(brec.stats))
        rsuffix = (f"；建置紀錄 {br['source']} 採用（.cmd {br['cmd_files']} 個、物件 {br['object_cmd_files']} 個；和只用 Makefile 相比："
                   + ("、".join(f"{k} {v}" for k, v in sorted(changes.items())) or "判定沒有改變")
                   + (f"；建置紀錄與 Makefile 矛盾的檔案 {brec.stats['conflict_makefile_built']} 個，判 unknown" if brec.stats["conflict_makefile_built"] else "")
                   + "）")
        if (br.get("identity") or {}).get("result") != "matched":
            rsuffix += ("；建置紀錄沒有和映像綁定（.config 與模組清單相符；沒有建置識別檔"
                        + ("" if not (br.get("identity") or {}).get("files") else "或讀不到 Image 的版本字串") + "）")
    elif (out["kernel"].get("build_record") or {}).get("status") == "GAP":
        rsuffix = f"；建置紀錄 {out['kernel']['build_record']['source']} 不採用（GAP：{out['kernel']['build_record']['reason']}），照舊依 Makefile 判定"
    oo = (out["kernel"].get("build_record") or {}).get("out_of_tree_records")
    if oo:
        rsuffix += ("；樹外模組建置紀錄：" + (f"採用（映像的 {oo['image_modules']} 個樹外模組都有紀錄；驗證方式 srcversion {oo['identity'].get('srcversion', 0)}、"
                                          f"ELF 區段相同 {oo['identity'].get('sections', 0)}、ELF 區段相同但建置日期／路徑字串遮罩 {oo['identity'].get('sections_masked', 0)}、"
                                          f"只比名稱 {oo['identity'].get('name_only', 0)}；標頭檔看紀錄的 deps）" if oo.get("used")
                                          else f"不採用（{oo.get('reason')}；已驗證 {oo.get('covered')}／{oo.get('image_modules')}），標頭檔照舊因為樹外模組而 unknown"))
    sgi = out["kernel"].get("stable_git")
    if sgi:
        rsuffix += ("；--stable-git " + (f"{sgi['source']}：查到 commit 檔案的 CVE {sgi['cves_with_commit_files']} 個（補進 programFiles "
                                        f"{sgi['cves_with_added_files']}、只靠 References {sgi['cves_from_references_only']}）；判定變化 "
                                        + ("、".join(f"{k} {v}" for k, v in sorted(sgi['decision_changes'].items())) or "無")
                                        if sgi["ok"] else f"不能用（{sgi['reason']}）"))
    exm = (out["kernel"].get("build_record") or {}).get("image_modules_not_in_record") if brec is not None else None
    if exm:
        rsuffix += (f"；出貨映像有 {exm['count']} 個模組不在建置紀錄的 modules.order（樹內 {exm['in_tree']}、找不到來源 {exm['not_found']}）："
                    "它們的檔案不判沒編（unknown），找不到來源的標 GAP")
        out["limitations"] = list(out["limitations"]) + [out["kernel"]["build_record"]["limitations"][-1]]
    c = out["counts"]
    detail = (f"核心 {info.kernel_version or '?'}（{info.source.get('label')}；.config sha256 {ksha[:12]}…；Makefile／Kbuild {out['kernel']['makefiles']} 個"
              + (f"，來自核心原始碼樹 {info.source_tree['path_label']}" if info.source_tree else "") + "）"
              f"的 {len(cves)} 個 CVE：沒編進核心 {c['not_affected']}、有編 {c['affected']}、無法判斷 {c['unknown']}"
              f"（沒有 CNA 紀錄 {unk['no_cna_record']}、紀錄沒有 programFiles {unk['no_program_files']}、含標頭檔或非程式檔 {unk['header_or_non_source']}、"
              f"規則判斷不了 {unk['undetermined']}）；CNA 資料 {mir.state.get('commit') and mir.state['commit'][:12]}（{mir.state.get('commit_date')}）"
              "；只列出，不改原始的發現" + rsuffix)
    if getattr(a, "cves_origin", None):
        detail = f"CVE 清單來源：{a.cves_origin}（不是 Grype／DT）；{detail}"
    tcmp = (info.source_tree or {}).get("config_compare") or {}
    if info.source_tree:
        detail += (f"；--source-tree 的 .config 核對：{tcmp.get('result')}" + (f"（{tcmp['differences_total']} 項不同，例如 "
                   f"{', '.join(tcmp['examples'][:3])}）" if tcmp.get("result") == "differs" else ""))
    if tcmp.get("result") == "differs":
        lead = f"--source-tree 的 .config 和判定用的設定不同（{tcmp['differences_total']} 項）：Makefile 的來源可能不是出貨的那一版"
        return "ATTENTION", f"{(chk['lead'] + '；') if chk and chk['attention'] else ''}{lead}；{detail}", out
    if chk and chk["attention"]:
        return "ATTENTION", f"{chk['lead']}；{detail}", out
    if chk and chk["note"]:
        detail += f"；{chk['note']}"
    return "OK", detail, out


BANNER_VER_RE = re.compile(r"^Linux version (\S+)")


def probe_kernel_version(a):
    """--probe-kernel-version：--from 的映像 → (狀態, 版本或原因)。OK：版本（/lib/modules/<版本> 的資料夾名稱；沒有模組資料夾時
    Image 的 linux_banner）；NONE：映像裡看不到核心（沒有模組資料夾、沒有 Image）；GAP：看得到核心但版本不能確定（多個模組資料夾、
    Image 讀不到版本字串、兩邊不一致）。不猜。"""
    col, _ = collect(a.from_, a.prefix, images=True)
    if col is None:
        raise InputError("--probe-kernel-version 的 --from 要是映像或刷機包（不是核心原始碼樹）")
    emit_kernel_versions(a, col)
    vers = module_dir_versions(col)
    imgs = image_inputs(col)
    if imgs is not None and getattr(a, "prefer_rootfs_image", False):
        imgs["prefer_rootfs"] = True
    prim = primary_image(imgs)
    bv = None
    if prim is not None and prim.banner:
        m = BANNER_VER_RE.match(prim.banner)
        bv = m.group(1) if m else None
    if a.kernel_version:
        if a.kernel_version not in vers:
            return "GAP", f"指定的核心 {a.kernel_version} 沒有模組資料夾（有：{'、'.join(vers) or '沒有'}）"
        ver = a.kernel_version
    elif len(vers) == 1:
        ver = vers[0]
    elif len(vers) > 1:
        return "GAP", f"映像有 {len(vers)} 個核心模組目錄（{'、'.join(vers[:4])}），不知道是哪一個，不猜"
    elif prim is not None:
        if not bv:
            return "GAP", f"映像有核心 Image（{prim.path}）但讀不到版本字串（linux_banner）：不猜版本"
        return "OK", bv
    else:
        return "NONE", "映像裡看不到核心（沒有 /lib/modules/<版本>/，也沒有 Image）"
    if bv and bv != ver:
        return "GAP", f"模組資料夾的核心版本（{ver}）和 Image 的版本字串（{bv}）不同：不是同一個核心，不猜"
    return "OK", ver


def module_dir_versions(col):
    """Collected → 出貨的核心（模組資料夾的名稱，排序）。locate、probe_kernel_version 與 --list-kernel-versions 用同一個判斷。"""
    return sorted(v for v, m in col.modules.items() if m["ko"] or m["files"] or m.get("ko_links"))


def emit_kernel_versions(a, col):
    """--also-list-kernel-versions：已經讀進來的映像順便印出貨的核心（不再讀一次映像）。"""
    if getattr(a, "also_list_kernel_versions", False) and col is not None:
        print("KERNEL-VERSIONS\tOK\t" + " ".join(re.sub(r"\s+", "_", v) for v in module_dir_versions(col))[:4000], flush=True)


def list_kernel_versions(a):
    """--list-kernel-versions：--from 的映像 → 出貨的核心（模組資料夾的名稱，排序）。判斷方式與 locate／probe_kernel_version 相同。"""
    col, _ = collect(a.from_, a.prefix, images=True)
    if col is None:
        raise InputError("--list-kernel-versions 的 --from 要是映像或刷機包（不是核心原始碼樹）")
    return module_dir_versions(col)


def main(argv=None):
    ap = argparse.ArgumentParser(description="核心 CVE 依產品 .config 判斷修補的程式有沒有編進核心（C-kernel-config）")
    ap.add_argument("--grype")
    ap.add_argument("--findings")
    ap.add_argument("--cves")
    ap.add_argument("--kernel-map")
    ap.add_argument("--kernel-version")
    ap.add_argument("--from", dest="from_")
    ap.add_argument("--prefix")
    ap.add_argument("--config")
    ap.add_argument("--makefiles-dir")
    ap.add_argument("--mirror")
    ap.add_argument("--max-age-days", type=float, default=None)
    ap.add_argument("--build-record")
    ap.add_argument("--oot-build-record", action="append", default=[])
    ap.add_argument("--stable-git")
    ap.add_argument("--cves-origin")
    ap.add_argument("--source-tree")
    ap.add_argument("--probe-kernel-version", action="store_true")
    ap.add_argument("--list-kernel-versions", action="store_true")
    ap.add_argument("--also-list-kernel-versions", action="store_true")
    ap.add_argument("--prefer-rootfs-image", action="store_true")
    ap.add_argument("--out")
    try:
        a = ap.parse_args(argv)
    except SystemExit:
        line("FAIL", "kernel_config.py 參數錯誤")
        return 3
    if a.list_kernel_versions:
        if not a.from_:
            print("KERNEL-VERSIONS\tGAP\t--list-kernel-versions 要 --from")
            return 3
        try:
            vers = list_kernel_versions(a)
        except InputError as e:
            print("KERNEL-VERSIONS\tGAP\t" + re.sub(r"[\t\r\n]+", " ", str(e))[:300])
            return 3
        except Exception as e:
            print(f"KERNEL-VERSIONS\tGAP\t讀不出映像出貨的核心（{type(e).__name__}）")
            return 3
        print("KERNEL-VERSIONS\tOK\t" + " ".join(re.sub(r"\s+", "_", v) for v in vers)[:4000])
        return 0
    if a.probe_kernel_version:
        if not a.from_:
            print("KERNEL-VERSION\tGAP\t--probe-kernel-version 要 --from")
            return 3
        try:
            st, text = probe_kernel_version(a)
        except InputError as e:
            print("KERNEL-VERSION\tGAP\t" + re.sub(r"[\t\r\n]+", " ", str(e))[:300])
            return 3
        except Exception as e:
            print(f"KERNEL-VERSION\tGAP\t讀不出核心版本（{type(e).__name__}）")
            return 3
        print(f"KERNEL-VERSION\t{st}\t" + re.sub(r"[\t\r\n]+", " ", text)[:300])
        return 0
    if not a.out:
        line("FAIL", "kernel_config.py 參數錯誤：要 --out")
        return 3
    if a.source_tree and (a.config or not a.from_):
        line("FAIL", "kernel_config.py 參數錯誤：--source-tree 只配 --from")
        return 3
    if bool(a.config) != bool(a.makefiles_dir) or (a.config and a.from_) or not (a.config or a.from_):
        line("FAIL", "kernel_config.py 參數錯誤：要 --from，或同時給 --config 與 --makefiles-dir")
        return 3
    if a.prefix and not a.from_:
        line("FAIL", "kernel_config.py 參數錯誤：--prefix 只配 --from")
        return 3
    try:
        os.remove(a.out)                 # 不留上一次的結果冒充這次的
    except FileNotFoundError:
        pass
    except OSError as e:
        line("FAIL", f"無法刪除舊的輸出（{type(e).__name__}）")
        return 3
    try:
        max_age = a.max_age_days if a.max_age_days is not None else float(os.environ.get("KERNEL_CVE_MAX_AGE_DAYS") or 7)
        st, detail, out = assess(a, max_age)
    except InputError as e:
        line("FAIL", f"kernel_config.py 輸入錯誤：{e}")
        return 3
    except Exception as e:      # 結構意外：記 FAIL，不讓掃描中斷、不印 traceback
        line("FAIL", f"kernel_config.py 無法判定（{type(e).__name__}）")
        return 3
    if out is not None and a.build_record and "build_record" not in out["kernel"]:
        # 給了建置紀錄、但這個階段沒有判定（GAP）：沒有讀紀錄
        out["kernel"]["build_record"] = {"source": os.path.basename(os.path.normpath(a.build_record)) or a.build_record,
                                         "status": "NOT_RUN", "reason": "no CVE was judged (the stage is GAP), so the record was not read"}
    if out is not None:
        out["status"], out["detail"] = st, detail
        try:
            with open(a.out, "w", encoding="utf-8") as f:
                json.dump(out, f, ensure_ascii=False, indent=1)
        except OSError as e:
            line("FAIL", f"無法寫入 {a.out}（{type(e).__name__}）")
            return 3
    line(st, detail)
    return 0


if __name__ == "__main__":
    sys.exit(main())
