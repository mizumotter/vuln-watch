// Rule-based explanations: CWE dictionary + CVSS vector decoding (ja / en).
// Each CWE entry: [name, attack technique, what the attacker gains].
const CWE = {
  20: {
    ja: ["入力値の検証不備", "形式・長さ・範囲などの確認が足りない入力欄やAPIに、想定外の値（極端に長い文字列、負の数、特殊文字、壊れたファイルなど）を送り込みます。プログラムはそれを正しい値として処理を進めてしまい、後段で誤動作します。", "何が起きるかは誤動作する箇所によって変わります。軽いものではエラーやサービス停止、重いものでは情報漏えいやサーバ上でのコード実行につながります。他の脆弱性の入口になることが多い種類です。"],
    en: ["Improper input validation", "The attacker sends values the program did not expect (very long strings, negative numbers, special characters, malformed files) to a field or API that does not check format, length or range. The program accepts them as valid and misbehaves later on.", "The result depends on where the program misbehaves: from errors and outages up to data disclosure or code execution on the server. This weakness is often the entry point for other attacks."],
  },
  22: {
    ja: ["パストラバーサル", "ファイル名やパスを受け取る機能に、「../」を重ねた文字列や絶対パスを渡します。たとえば「../../etc/passwd」のように指定し、公開用フォルダの外にあるファイルを開かせます。URLエンコードで検査をすり抜ける手口もよく使われます。", "設定ファイル、パスワードやAPIキー、ソースコードなどを読み出されます。書き込みができる機能の場合は、ファイルの上書きや削除、不正なプログラムの設置によってサーバの乗っ取りまで進むことがあります。"],
    en: ["Path traversal", "The attacker passes file names containing repeated '../' sequences or absolute paths, for example '../../etc/passwd', to a feature that opens files. This reaches files outside the intended folder; URL encoding is often used to slip past filters.", "Configuration files, passwords, API keys and source code can be read. If the feature can also write, files may be overwritten or deleted, and planting a malicious program can lead to full takeover of the server."],
  },
  59: {
    ja: ["シンボリックリンクの不適切な追跡", "攻撃者は、プログラムが読み書きする場所（一時フォルダなど）に、別のファイルを指すリンクをあらかじめ置いておきます。高い権限で動くプログラムがそのリンクをたどると、攻撃者が本来触れないファイルを代わりに操作してしまいます。", "システムの重要なファイルを上書き・削除されたり、内容を読み出されたりします。一般ユーザーが管理者（root / SYSTEM）の権限を得る権限昇格に使われることが多い種類です。"],
    en: ["Link following", "The attacker plants a symbolic link in a location the program reads or writes, such as a temporary folder. When a privileged program follows the link, it operates on a file the attacker could not touch directly.", "Important system files can be overwritten, deleted or read. This is commonly used for privilege escalation from a normal user to root or SYSTEM."],
  },
  74: {
    ja: ["インジェクション", "入力された文字列を、コマンド・クエリ・テンプレートなどにそのまま埋め込む処理を狙います。攻撃者は引用符や区切り文字と一緒に命令を入力し、データとして扱われるはずの部分を命令として解釈させます。", "埋め込み先に応じて、不正な命令の実行、データの読み出し・改ざん・削除が起きます。埋め込み先がOSやデータベースの場合は、システム全体の乗っ取りにつながります。"],
    en: ["Injection", "The attacker targets code that inserts input directly into a command, query or template. By including quotes or separators together with instructions, the part that should be data is interpreted as instructions.", "Depending on the target interpreter, unintended commands run and data is read, changed or deleted. When the target is the OS or a database, the whole system can be taken over."],
  },
  77: {
    ja: ["コマンドインジェクション", "入力値を使ってコマンドを組み立てる機能（ファイル変換、疎通確認、バックアップなど）に、区切り文字と別のコマンドを混ぜて送ります。サーバは本来のコマンドに続けて、攻撃者のコマンドも実行します。", "アプリケーションと同じ権限で任意のコマンドを実行されます。ファイルの窃取、バックドアの設置、マルウェアの配置が可能になり、サーバを乗っ取られます。"],
    en: ["Command injection", "The attacker sends separators plus an extra command to a feature that builds a command from input (file conversion, connectivity checks, backups). The server runs the attacker's command after the intended one.", "Arbitrary commands run with the application's privileges. Files can be stolen, backdoors and malware installed, and the server taken over."],
  },
  78: {
    ja: ["OSコマンドインジェクション", "入力値がシェルに渡される箇所に、「;」「|」「&&」「$( )」などの記号とOSコマンドを混ぜて送ります。たとえばホスト名の欄に「example.com; cat /etc/passwd」と入力すると、後半が別のコマンドとして実行されます。", "サーバ上で任意のOSコマンドを実行されます。認証情報の窃取、バックドアやランサムウェアの設置、同じネットワーク内の他のサーバへの侵入の足場として使われます。"],
    en: ["OS command injection", "The attacker adds shell metacharacters such as ';', '|', '&&' or '$( )' and an OS command to input that reaches a shell. Entering 'example.com; cat /etc/passwd' in a host-name field, for instance, runs the second part as a separate command.", "Arbitrary OS commands run on the server. Credentials are stolen, backdoors or ransomware are installed, and the server becomes a foothold into other machines on the network."],
  },
  79: {
    ja: ["クロスサイトスクリプティング (XSS)", "入力内容をそのままページに表示する箇所に、スクリプトを含む文字列を仕込みます。掲示板やプロフィールに保存する方法と、細工したURLを被害者に開かせる方法があります。被害者のブラウザは、それを正規サイトのスクリプトとして実行します。", "被害者のセッション情報を盗まれ、本人になりすまして操作されます。画面を書き換えて偽のログイン画面を出す、入力内容を盗む、管理者が被害に遭えば管理機能を操作される、といった被害につながります。"],
    en: ["Cross-site scripting (XSS)", "The attacker places text containing script where input is shown on a page without escaping, either by storing it (comments, profiles) or by getting the victim to open a crafted URL. The victim's browser runs it as if it were the site's own script.", "Session data is stolen and the attacker acts as the victim. Pages can be rewritten to show a fake login form or capture what the user types, and if an administrator is hit, administrative functions can be driven."],
  },
  89: {
    ja: ["SQLインジェクション", "検索欄やログイン欄など、入力値を使ってSQL文を組み立てる箇所に、引用符とSQLの断片を入力します。たとえば「' OR '1'='1」のような文字列で条件を常に真にしたり、UNION で別のテーブルの内容を結果に混ぜたりします。", "データベース内の個人情報やパスワードを丸ごと読み出されます。データの改ざん・削除、ログインの回避も可能で、データベースの機能によってはサーバ上でのコマンド実行まで進みます。"],
    en: ["SQL injection", "The attacker enters quotes and SQL fragments into fields used to build a query, such as search or login forms. A string like ' OR '1'='1 makes a condition always true, and UNION can pull rows from other tables into the result.", "Personal data and passwords in the database can be dumped. Data can be changed or deleted, logins bypassed, and with some database features the attacker can go on to run commands on the server."],
  },
  94: {
    ja: ["コードインジェクション", "テンプレート、数式、設定値など、入力がプログラムコードとして評価される箇所（eval など）に、攻撃用のコードを送り込みます。アプリケーションはそれを自分のコードの一部として実行します。", "アプリケーションの権限で任意のコードを実行されます。データの窃取や改ざん、バックドアの設置が可能になり、多くの場合サーバの乗っ取りに至ります。"],
    en: ["Code injection", "The attacker sends code to a place where input is evaluated as program code, such as templates, formulas or settings passed to eval. The application executes it as part of its own code.", "Arbitrary code runs with the application's privileges. Data can be stolen or altered and backdoors installed, which usually means the server is taken over."],
  },
  119: {
    ja: ["メモリバッファの境界外操作", "長さや位置の確認が足りない処理に、細工したデータ（壊れた画像、長すぎるパケットなど）を読み込ませます。プログラムは確保した領域の外側を読み書きしてしまいます。C / C++ で書かれたソフトに多い種類です。", "最低でもプログラムが異常終了し、サービスが止まります。領域外を読める場合はメモリ上の秘密情報が漏れ、書ける場合は攻撃者のコードを実行されるおそれがあります。"],
    en: ["Memory buffer bounds error", "Crafted data such as a malformed image or an oversized packet reaches code that does not check lengths or offsets, so the program reads or writes outside the buffer it allocated. This is common in software written in C or C++.", "At minimum the program crashes and the service stops. Reading outside the buffer leaks secrets from memory, and writing outside it can let the attacker run code."],
  },
  120: {
    ja: ["バッファオーバーフロー", "入力の長さを確認せずにコピーする処理に、想定より長いデータを送ります。あふれた分が隣のメモリ領域を上書きし、プログラムの動作に必要な情報が壊れます。", "プログラムが異常終了してサービスが止まります。上書きする内容を調整されると、攻撃者が用意したコードを実行され、サーバを乗っ取られます。"],
    en: ["Buffer overflow", "The attacker sends data longer than expected to code that copies input without checking its length. The excess overwrites neighbouring memory and corrupts data the program depends on.", "The program crashes and the service stops. With carefully chosen data the attacker can run their own code and take over the server."],
  },
  121: {
    ja: ["スタックバッファオーバーフロー", "関数の中に確保された小さな領域に、長いデータを書き込ませます。あふれた分が、関数の戻り先アドレスなどの制御情報を上書きします。関数が終わるときに、攻撃者が指定した場所へ処理が飛びます。", "プログラムが異常終了してサービスが止まります。保護機構を回避されると任意のコードを実行され、そのプログラムの権限でシステムを操作されます。"],
    en: ["Stack-based buffer overflow", "Long data is written into a small buffer inside a function. The overflow overwrites control data such as the function's return address, so execution jumps to a location chosen by the attacker when the function returns.", "The program crashes and the service stops. If the built-in protections are bypassed, arbitrary code runs with the program's privileges."],
  },
  122: {
    ja: ["ヒープバッファオーバーフロー", "動的に確保された領域に、その大きさを超えるデータを書き込ませます。隣にある別のデータやメモリ管理用の情報が上書きされます。攻撃者はメモリの配置を調整し、狙ったデータを書き換えます。", "プログラムが異常終了してサービスが止まります。関数の呼び出し先などを書き換えられると、任意のコードを実行されます。"],
    en: ["Heap-based buffer overflow", "Data larger than a dynamically allocated buffer is written into it, overwriting neighbouring objects or allocator metadata. The attacker shapes the memory layout so that a chosen object is the one overwritten.", "The program crashes and the service stops. If a function pointer or similar value is overwritten, arbitrary code can run."],
  },
  125: {
    ja: ["境界外読み取り", "長さの値などを偽ったデータを送り、バッファの終端を越えてメモリを読み取らせます。読み取られた内容が応答に含まれて返ってくる場合、攻撃者はそれを繰り返して周囲のメモリを少しずつ集めます。", "暗号鍵、パスワード、セッション情報、他の利用者のデータなど、メモリ上にあった情報が漏れます。メモリの配置が分かることで、別の脆弱性を使ったコード実行が成功しやすくなります。異常終了によるサービス停止も起きます。"],
    en: ["Out-of-bounds read", "Data with a falsified length or offset makes the program read past the end of a buffer. When the bytes come back in a response, the attacker repeats the request to collect nearby memory piece by piece.", "Keys, passwords, session data and other users' data that happened to be in memory are disclosed. Learning the memory layout also makes code-execution exploits for other flaws more reliable, and the program may crash."],
  },
  190: {
    ja: ["整数オーバーフロー", "サイズや個数として、極端に大きな数値を与えます。計算結果が扱える上限を超えて小さな値に巻き戻り、プログラムは必要より小さい領域しか確保しません。そこへ本来の量のデータが書き込まれ、領域をあふれます。", "メモリ破壊が起き、プログラムの異常終了や任意のコード実行につながります。金額や数量の計算で起きた場合は、不正な値での処理（残高の不整合など）になります。"],
    en: ["Integer overflow", "The attacker supplies extremely large numbers as sizes or counts. The calculation wraps around to a small value, the program allocates too little memory, and the real amount of data then overflows it.", "Memory is corrupted, leading to crashes or arbitrary code execution. When the arithmetic concerns amounts or quantities, the result is processing with wrong values."],
  },
  200: {
    ja: ["情報漏えい", "詳細すぎるエラーメッセージ、デバッグ用の画面、応答内容や応答時間のわずかな差などを手がかりに、本来見えない情報を集めます。存在するユーザー名の判別や、内部のパス・バージョンの特定がよくある例です。", "内部構成、個人情報、認証情報などが攻撃者に渡ります。それ自体の被害に加えて、次の攻撃（不正ログイン、別の脆弱性の悪用）の準備に使われます。"],
    en: ["Information exposure", "The attacker collects data that should not be visible from overly detailed error messages, debug pages, or small differences in responses and response times. Typical examples are telling valid user names apart and learning internal paths or versions.", "Internal structure, personal data or credentials reach the attacker. Beyond the direct damage, the information is used to prepare the next step, such as account takeover or exploiting another flaw."],
  },
  269: {
    ja: ["権限管理の不備", "権限の付与・変更・引き下げの処理にある抜けを突きます。たとえば、一般ユーザーが自分の役割を書き換えられる、高い権限で始まった処理が権限を下げないまま利用者の指示を実行する、といった状況を利用します。", "一般ユーザーが管理者や root の権限を得ます。その結果、全データの閲覧・改ざん、設定変更、他の利用者のアカウント操作が可能になります。"],
    en: ["Improper privilege management", "The attacker abuses gaps in how privileges are granted, changed or dropped: for example a normal user can edit their own role, or a task that starts with high privileges carries out user-supplied actions without lowering them.", "A normal user gains administrator or root privileges, and with them access to all data, settings and other users' accounts."],
  },
  276: {
    ja: ["不適切な既定パーミッション", "インストール直後のファイルやフォルダが、誰でも読み書きできる設定になっている点を利用します。同じ端末にログインできる別の利用者が、設定ファイルを読んだり、実行ファイルやライブラリを差し替えたりします。", "設定ファイル内のパスワードや鍵が漏れます。管理者権限で動くプログラムを差し替えられると、次に実行されたときに攻撃者のコードが高い権限で動き、権限昇格になります。"],
    en: ["Incorrect default permissions", "Files or folders are world-readable or world-writable right after installation. Another user who can log in to the same machine reads configuration files or replaces executables and libraries.", "Passwords and keys in configuration files are disclosed. If a program that runs with administrator rights is replaced, the attacker's code runs with those rights the next time it starts."],
  },
  284: {
    ja: ["アクセス制御の不備", "画面上では隠されている機能やデータに、URLやAPIを直接指定してアクセスします。制限が画面側にしかない、一部の経路だけ確認が抜けている、といった箇所を探して利用します。", "他の利用者のデータを閲覧・変更されます。管理用の機能に届いた場合は、設定変更やアカウント作成など、システム全体に及ぶ操作をされます。"],
    en: ["Improper access control", "The attacker requests hidden functions or data directly by URL or API. They look for places where the restriction exists only in the user interface or is missing on one of several paths.", "Other users' data can be viewed or changed. If administrative functions are reachable, system-wide actions such as changing settings or creating accounts become possible."],
  },
  287: {
    ja: ["認証の不備", "ログイン処理の欠陥を突き、正しいパスワードなしで認証済みとして扱わせます。確認手順の一部を飛ばせる、特定の値を送ると認証が成功扱いになる、パスワード再設定の本人確認が甘い、といった例があります。", "他の利用者や管理者になりすまして、その人の権限でシステムを操作されます。管理者として入られた場合は、全データと設定を掌握されます。"],
    en: ["Improper authentication", "A flaw in the login process lets the attacker be treated as authenticated without the right password: a step can be skipped, a particular value is accepted as success, or the password-reset check is weak.", "The attacker operates the system as another user or as an administrator. As an administrator they control all data and settings."],
  },
  290: {
    ja: ["なりすましによる認証回避", "送信元IPアドレス、HTTPヘッダ（X-Forwarded-For など）、ホスト名といった、利用者側で偽装できる情報を信用している箇所を狙います。攻撃者は「社内からのアクセス」や「信頼済みサーバ」に見える値を付けてリクエストを送ります。", "正規の利用者やサーバとして扱われ、IP制限や認証を回避されます。内部向けの管理機能に外部から到達されることがあります。"],
    en: ["Authentication bypass by spoofing", "The attacker targets checks that trust values the client can forge, such as the source IP address, HTTP headers like X-Forwarded-For, or host names, and sends requests that look as if they came from the internal network or a trusted server.", "The attacker is treated as a legitimate user or server, bypassing IP restrictions and authentication. Internal administrative functions may become reachable from outside."],
  },
  295: {
    ja: ["証明書検証の不備", "攻撃者は通信経路（公衆Wi-Fi、不正な中継機器など）に割り込み、偽の証明書を提示します。クライアント側が有効期限・発行元・ホスト名の確認を正しく行っていないと、偽のサーバを本物として受け入れます。", "暗号化されているはずの通信を盗聴・改ざんされます（中間者攻撃）。パスワードやトークンの窃取、ダウンロードするファイルやソフトウェア更新のすり替えにつながります。"],
    en: ["Improper certificate validation", "The attacker sits on the network path (public Wi-Fi, a rogue gateway) and presents a forged certificate. If the client does not properly check expiry, issuer and host name, it accepts the fake server as genuine.", "Traffic that should be encrypted can be read and altered (man-in-the-middle). Passwords and tokens are stolen, and downloads or software updates can be replaced."],
  },
  306: {
    ja: ["重要な機能の認証欠如", "ログインしていなくても呼び出せてしまう管理用のAPIや設定画面に、直接リクエストを送ります。攻撃者はURLの推測やスキャンでそうした入口を探します。", "未ログインのまま、設定変更、データの取得、アカウントの作成などを実行されます。機能によってはコマンド実行まで可能で、インターネットに公開されている場合は被害が広がりやすい種類です。"],
    en: ["Missing authentication for critical function", "The attacker sends requests straight to an administrative API or settings page that works without logging in, finding such entry points by guessing URLs or scanning.", "Without any login the attacker can change settings, read data or create accounts, and for some functions run commands. Internet-facing systems with this flaw tend to be attacked widely."],
  },
  327: {
    ja: ["危険な暗号アルゴリズムの使用", "MD5、SHA-1、DES、RC4 など、すでに破られている暗号方式が使われている箇所を狙います。攻撃者は現実的な計算量で、暗号文の解読や、同じハッシュ値になる別のデータの作成を行います。", "通信や保存データを解読されます。ハッシュの衝突を利用して、署名や証明書を偽造されることがあります。パスワードのハッシュが弱い場合は、漏えい後に元のパスワードを割り出されます。"],
    en: ["Broken or risky cryptographic algorithm", "The attacker targets places that still use broken algorithms such as MD5, SHA-1, DES or RC4, and with a practical amount of computation decrypts data or creates different data with the same hash.", "Traffic and stored data can be decrypted, and hash collisions can be used to forge signatures or certificates. Weak password hashes let leaked hashes be turned back into passwords."],
  },
  345: {
    ja: ["データの真正性検証の不備", "更新ファイル、設定、メッセージなどの出所や改ざんの有無を確認していない箇所に、偽造または改ざんしたデータを渡します。通信経路への割り込みや、配布元になりすます方法が使われます。", "偽の更新ファイルやメッセージが、正規のものとして処理されます。不正なプログラムのインストールや、設定の書き換えにつながります。"],
    en: ["Insufficient verification of data authenticity", "The attacker supplies forged or modified data where the origin and integrity of updates, settings or messages are not checked, by intercepting traffic or impersonating the source.", "Fake updates or messages are processed as genuine, which can install malicious software or rewrite configuration."],
  },
  347: {
    ja: ["署名検証の不備", "電子署名の確認が抜けている、または誤っている箇所に、偽造したデータを渡します。JWTの署名方式を「none」に変える、署名されていない部分を差し替える、といった手口があります。", "偽造したトークンで他の利用者や管理者になりすまされます。ソフトウェア更新やパッケージの検証で起きた場合は、改ざんされたコードがインストールされます。"],
    en: ["Improper signature verification", "The attacker passes forged data where digital signatures are not verified, or are verified incorrectly, for example by changing a JWT's algorithm to 'none' or replacing a part that the signature does not cover.", "Forged tokens let the attacker act as another user or an administrator. In update or package verification, tampered code gets installed."],
  },
  352: {
    ja: ["クロスサイトリクエストフォージェリ (CSRF)", "対象サイトにログイン中の被害者に、攻撃者が用意したページやメールのリンクを開かせます。そのページから対象サイトへリクエストが自動送信され、ブラウザが被害者のログイン情報を付けるため、本人の操作として処理されます。", "パスワードやメールアドレスの変更、投稿、購入、設定変更など、被害者が意図しない操作を実行されます。管理者が被害に遭うと、アカウントの追加や設定の書き換えに及びます。"],
    en: ["Cross-site request forgery (CSRF)", "A victim who is logged in to the target site is lured to a page or link prepared by the attacker. That page sends a request to the target site, and because the browser attaches the victim's login, the site treats it as the victim's own action.", "Actions the victim never intended are carried out: changing the password or email address, posting, purchasing, changing settings. If an administrator is the victim, accounts can be added and configuration rewritten."],
  },
  362: {
    ja: ["競合状態", "複数のリクエストや処理をほぼ同時に走らせ、「確認」と「実行」の間の一瞬の隙間を突きます。たとえば残高確認と引き落としの間に別の引き落としを割り込ませる、同じクーポンを同時に何度も使う、といった形です。", "権限や残高の確認をすり抜けられ、二重の処理やデータの不整合が起きます。OSやネイティブコードで起きた場合は、メモリ破壊や権限昇格につながります。"],
    en: ["Race condition", "The attacker runs several requests or operations at almost the same moment to hit the gap between a check and the action that follows, for example slipping a second withdrawal between the balance check and the debit, or redeeming one coupon many times at once.", "Permission or balance checks are bypassed, causing duplicated operations and inconsistent data. In OS-level or native code the result can be memory corruption or privilege escalation."],
  },
  400: {
    ja: ["リソースの枯渇", "大量のリクエスト、巨大なデータ、処理に時間のかかる要求などを送り続け、CPU・メモリ・ディスク・接続数を使い切らせます。少ない通信量で大きな負荷をかけられる処理が狙われます。", "サーバが応答しなくなり、正規の利用者がサービスを使えなくなります（DoS）。同じサーバ上の他のサービスにも影響し、従量課金の環境では費用の増加にもつながります。"],
    en: ["Uncontrolled resource consumption", "The attacker keeps sending many requests, huge payloads or expensive operations until CPU, memory, disk or connections run out. Operations that cause a large load from a small request are the usual target.", "The server stops responding and legitimate users cannot use the service (denial of service). Other services on the same host suffer too, and usage-based billing can rise."],
  },
  401: {
    ja: ["メモリリーク", "使い終わったメモリが解放されない処理を、繰り返し呼び出します。1回あたりの漏れは小さくても、リクエストを重ねることで使用量が増え続けます。", "メモリを使い切ってプログラムが異常終了するか、動作が極端に遅くなり、サービスが止まります（DoS）。"],
    en: ["Memory leak", "The attacker repeatedly triggers an operation that never releases the memory it used. Each leak is small, but memory use keeps growing as requests accumulate.", "Memory runs out and the program crashes or slows to a crawl, stopping the service (denial of service)."],
  },
  415: {
    ja: ["二重解放", "同じメモリ領域が2回解放されるような順序で操作を行います。メモリ管理の内部情報が壊れ、その後の確保で同じ領域が2つの用途に同時に使われる状態になります。", "プログラムが異常終了します。攻撃者が領域の内容を調整できる場合は、任意のコード実行につながります。"],
    en: ["Double free", "The attacker drives the program so that the same memory is freed twice. Allocator state is corrupted, and later allocations hand out the same region for two different purposes.", "The program crashes. If the attacker controls what is placed in that region, arbitrary code execution can follow."],
  },
  416: {
    ja: ["解放済みメモリの使用 (Use After Free)", "あるデータが解放されたあとも、プログラムがそれを参照し続ける状況を作ります。攻撃者は空いた領域に自分のデータを割り当てさせ、プログラムにそれを元のデータとして使わせます。ブラウザやOSで頻繁に見つかる種類です。", "プログラムが異常終了します。関数の呼び出し先などを差し替えられると任意のコードを実行され、OSのカーネルで起きた場合は権限昇格につながります。"],
    en: ["Use after free", "The attacker arranges for the program to keep using an object after it has been freed, gets their own data allocated in the vacated space, and the program then treats it as the original object. This is found frequently in browsers and operating systems.", "The program crashes. If a function pointer is replaced, arbitrary code runs, and in an OS kernel this leads to privilege escalation."],
  },
  427: {
    ja: ["検索パスの制御不備", "プログラムがDLLや実行ファイルを探す場所（カレントフォルダ、書き込み可能なPATH上のフォルダなど）に、同じ名前の偽ファイルを置きます。プログラムは正規のファイルより先にそれを見つけて読み込みます。", "そのプログラムの権限で攻撃者のコードが実行されます。管理者権限で動くプログラムやインストーラが対象の場合は、権限昇格になります。"],
    en: ["Uncontrolled search path element", "The attacker places a fake file with the expected name in a location the program searches for DLLs or executables (the current folder, a writable folder on PATH). The program finds and loads it before the real one.", "The attacker's code runs with that program's privileges. When the program or installer runs as administrator, this is a privilege escalation."],
  },
  434: {
    ja: ["危険なファイルのアップロード", "画像などを想定したアップロード機能に、サーバ上で実行できるファイル（PHP、JSPなどのスクリプト）を送ります。拡張子の偽装や二重拡張子で検査をすり抜け、アップロード先のURLにアクセスして実行させます。", "サーバ上で任意のコマンドを実行できる「Webシェル」を設置され、サーバを乗っ取られます。データの窃取、サイトの改ざん、内部ネットワークへの侵入に使われます。"],
    en: ["Unrestricted file upload", "The attacker uploads a file the server can execute (a PHP or JSP script) through a feature meant for images, disguising the extension to pass checks, then requests its URL to run it.", "A web shell that runs arbitrary commands is installed and the server is taken over. It is then used to steal data, deface the site or move into the internal network."],
  },
  444: {
    ja: ["HTTPリクエストスマグリング", "Content-Length と Transfer-Encoding を矛盾させるなどして、プロキシ（ロードバランサ）と背後のサーバでリクエストの区切りの解釈がずれるようにします。プロキシには1件に見えるリクエストの中に、もう1件のリクエストを隠して送り込みます。", "プロキシ側のアクセス制御をすり抜けて、内部向けの機能に届きます。次に来た他の利用者のリクエストに割り込み、セッション情報の窃取やキャッシュの汚染（偽ページの配信）を行われます。"],
    en: ["HTTP request smuggling", "By sending conflicting Content-Length and Transfer-Encoding headers or similar tricks, the attacker makes the front-end proxy and the back-end server disagree on where a request ends, hiding a second request inside what the proxy sees as one.", "Access controls at the proxy are bypassed and internal functions reached. The smuggled request can attach itself to the next user's request, stealing session data or poisoning caches so that fake pages are served."],
  },
  476: {
    ja: ["NULLポインタ参照", "想定外の入力や欠けたデータを送り、プログラムに「何も指していない」ポインタを使わせます。必須の項目が存在する前提で書かれた処理が狙われます。", "プロセスが異常終了し、サービスが止まります（DoS）。再起動するまで復旧しない場合や、繰り返し落とされる場合があります。"],
    en: ["NULL pointer dereference", "Unexpected input or missing data makes the program use a pointer that points to nothing. Code that assumes a required field is always present is the usual target.", "The process crashes and the service stops (denial of service). It may stay down until restarted, or be crashed again and again."],
  },
  502: {
    ja: ["信頼できないデータのデシリアライズ", "オブジェクトを保存・送信用の形式から復元する処理に、細工したデータを送ります。復元の途中で自動的に呼ばれる処理を、既存のクラスを組み合わせて連鎖させ（ガジェットチェーン）、攻撃者の意図した動作を実行させます。", "サーバ上で任意のコードを実行されます。Java、PHP、Python、.NET などで繰り返し悪用されてきた種類で、認証前に届く箇所にある場合は特に危険です。"],
    en: ["Deserialization of untrusted data", "The attacker sends crafted data to code that restores objects from a serialized form. Methods that run automatically during restoration are chained together from existing classes (a gadget chain) to perform the attacker's actions.", "Arbitrary code runs on the server. This has been exploited repeatedly in Java, PHP, Python and .NET, and is especially dangerous when reachable before authentication."],
  },
  522: {
    ja: ["認証情報の保護不足", "平文や弱い暗号で保存・送信されているパスワードやトークンを取得します。設定ファイル、データベース、バックアップ、暗号化されていない通信が狙われます。", "パスワードやトークンを盗まれ、正規の利用者になりすまされます。同じパスワードを使い回している他のサービスへの不正ログインにも使われます。"],
    en: ["Insufficiently protected credentials", "The attacker obtains passwords or tokens that are stored or sent in plain text or with weak protection, from configuration files, databases, backups or unencrypted traffic.", "Stolen credentials let the attacker impersonate legitimate users, and reused passwords open accounts on other services too."],
  },
  532: {
    ja: ["ログへの機密情報の出力", "ログファイルやログ集約サービスに書き出されたパスワード、トークン、個人情報を読み取ります。ログは本体のデータより閲覧できる人が多く、保存期間も長いため、取得しやすい場所になります。", "認証情報が漏れ、なりすましに使われます。個人情報が含まれている場合は、情報漏えい事故になります。"],
    en: ["Sensitive information in log files", "The attacker reads passwords, tokens or personal data that were written to log files or a log service. Logs are readable by more people and kept longer than the primary data, so they are an easy place to look.", "Leaked credentials are used for impersonation, and personal data in logs constitutes a data breach."],
  },
  601: {
    ja: ["オープンリダイレクト", "転送先をパラメータで指定できる機能を利用し、正規サイトのドメインで始まるURLに攻撃者のサイトを転送先として埋め込みます。被害者は見慣れたドメインを見て安心してリンクを開き、偽サイトへ送られます。", "フィッシングサイトへ誘導され、パスワードやカード情報を入力させられます。OAuth などの認証の流れで起きると、認可コードやトークンを盗まれます。"],
    en: ["Open redirect", "Using a feature that takes the destination from a parameter, the attacker builds a URL that starts with the legitimate domain but forwards to their own site. The victim trusts the familiar domain, clicks, and lands on the fake site.", "Victims are led to phishing pages that collect passwords or card details. In OAuth-style login flows, authorization codes or tokens can be stolen."],
  },
  611: {
    ja: ["XML外部実体参照 (XXE)", "XMLを受け付ける機能に、外部実体（別のファイルやURLを取り込む定義）を含むXMLを送ります。サーバのXMLパーサがそれを展開し、指定されたファイルやURLの内容を読み込みます。", "サーバ上のファイル（設定、認証情報など）を読み出されます。サーバを経由して内部ネットワークへリクエストを送られるほか、実体を何重にも展開させてサービスを止められることもあります。"],
    en: ["XML external entity (XXE)", "The attacker sends XML containing an external entity (a definition that pulls in another file or URL) to a feature that accepts XML. The server's parser expands it and loads the named file or URL.", "Files on the server such as configuration and credentials can be read. The server can be made to send requests into the internal network, and nested entities can be used to exhaust it."],
  },
  617: {
    ja: ["到達可能なアサーション", "開発者が「起きないはず」として置いた確認（assert）が、外部からの入力で成立してしまう箇所を狙います。該当する値を含むデータやパケットを送るだけで発動します。", "プロセスが自ら異常終了し、サービスが止まります（DoS）。DNSサーバなど常時稼働が前提のソフトでは、1つのパケットで停止させられることがあります。"],
    en: ["Reachable assertion", "The attacker targets an assertion that developers assumed could never fail but that outside input can trigger. Sending data or a packet with the right value is enough.", "The process aborts itself and the service stops (denial of service). Always-on software such as DNS servers can sometimes be stopped by a single packet."],
  },
  639: {
    ja: ["ID操作による認可回避 (IDOR)", "URLやリクエスト内のID（注文番号、ユーザーID、ファイル番号など）を、他人のものに書き換えて送ります。サーバが「そのIDは本人のものか」を確認していないと、そのまま応答が返ります。連番のIDは総当たりで収集されます。", "他の利用者の個人情報、注文履歴、ファイルなどを閲覧・変更・削除されます。番号を順に変えるだけで大量のデータを抜き取られることがあります。"],
    en: ["Authorization bypass through user-controlled key (IDOR)", "The attacker changes an ID in the URL or request (order number, user ID, file number) to someone else's. If the server does not check that the ID belongs to the requester, it simply answers; sequential IDs can be walked through one by one.", "Other users' personal data, order history or files can be viewed, changed or deleted, and large amounts of data can be harvested just by incrementing a number."],
  },
  732: {
    ja: ["重要リソースへの不適切な権限設定", "誰でも読み書きできる設定になっている重要なファイル、フォルダ、レジストリ、クラウドストレージなどを操作します。設定ミスや既定値の緩さが原因で起きます。", "鍵やパスワードなどの機密情報を取得されます。設定やスクリプトを書き換えられると、不正な処理の実行や権限昇格につながります。"],
    en: ["Incorrect permission assignment for critical resource", "The attacker reads or modifies important files, folders, registry keys or cloud storage that are accessible to everyone because of a misconfiguration or loose defaults.", "Secrets such as keys and passwords are obtained. Rewriting configuration or scripts leads to unauthorized actions or privilege escalation."],
  },
  770: {
    ja: ["制限のないリソース割り当て", "件数やサイズに上限がない処理に、巨大な値や大量の要素を含むリクエストを送ります。サーバは要求どおりにメモリ、スレッド、ファイルなどを確保しようとします。", "リソースを使い切ってサービスが止まります（DoS）。少数のリクエストで停止させられるため、攻撃のコストが低い種類です。"],
    en: ["Allocation of resources without limits", "The attacker sends requests with huge values or very many elements to code that has no cap on counts or sizes, and the server tries to allocate memory, threads or files accordingly.", "Resources are exhausted and the service stops (denial of service). A handful of requests can be enough, so the attack is cheap."],
  },
  787: {
    ja: ["境界外書き込み", "長さや位置の確認が足りない処理に細工したデータを送り、確保した領域の外側のメモリに書き込ませます。書き込む位置と内容を調整して、プログラムの制御に関わる情報を上書きします。悪用が確認される脆弱性に最も多い種類のひとつです。", "プログラムが異常終了します。制御情報を書き換えられると任意のコードを実行され、サーバや端末を乗っ取られます。"],
    en: ["Out-of-bounds write", "Crafted data reaches code that does not check lengths or offsets, and the program writes outside the memory it allocated. The attacker tunes the position and content to overwrite data that controls execution. This is one of the most common types among exploited vulnerabilities.", "The program crashes. If control data is overwritten, arbitrary code runs and the server or device is taken over."],
  },
  798: {
    ja: ["ハードコードされた認証情報", "製品に埋め込まれた共通のパスワード、APIキー、暗号鍵を使ってログインします。これらはファームウェアやソースコードの解析で見つかり、同じ製品のすべての導入先で使えます。", "管理者として不正にアクセスされます。利用者側でパスワードを変更できない場合が多く、修正版を適用するまで防げません。"],
    en: ["Hard-coded credentials", "The attacker logs in with a password, API key or cryptographic key embedded in the product. These are found by analysing firmware or source code and work on every installation of the product.", "Unauthorized access, often as administrator. Users usually cannot change the embedded value, so only the fixed version stops it."],
  },
  835: {
    ja: ["無限ループ", "終了条件が成立しなくなる値を含む入力を送り、処理を終わらせません。長さ0の要素や自分自身を指す参照など、解析処理の想定外のデータが使われます。", "CPUを使い切り、他のリクエストを処理できなくなってサービスが止まります（DoS）。"],
    en: ["Infinite loop", "Input containing a value that never satisfies the exit condition keeps the program looping. Zero-length elements or self-referencing structures that a parser did not anticipate are typical.", "CPU is exhausted, other requests cannot be served, and the service stops (denial of service)."],
  },
  843: {
    ja: ["型の取り違え (Type Confusion)", "あるオブジェクトを、別の種類のオブジェクトとして扱わせます。メモリ上の数値がアドレスとして解釈されるなど、内容を誤って読み書きさせることができます。ブラウザのJavaScriptエンジンで頻繁に見つかる種類です。", "メモリ破壊が起き、任意のコードを実行されます。細工したWebページを開かせるだけで端末を攻撃する手口に使われます。"],
    en: ["Type confusion", "The program is made to treat an object as a different kind of object, so memory is misinterpreted: a number is read as an address, for example. This is found frequently in browser JavaScript engines.", "Memory is corrupted and arbitrary code runs. It is used in attacks that compromise a device simply by getting the user to open a crafted web page."],
  },
  862: {
    ja: ["認可の欠如", "ログインさえしていれば誰でも呼び出せてしまう機能に、権限のない利用者が直接リクエストを送ります。画面にメニューが出ないだけで、サーバ側では権限を確認していない箇所が狙われます。", "他人のデータの閲覧・変更や、管理者向けの操作（ユーザー管理、設定変更など）を実行されます。"],
    en: ["Missing authorization", "An unprivileged user sends requests directly to a function that anyone logged in can call. The target is code where the menu is merely hidden while the server performs no permission check.", "Other users' data can be viewed or changed and administrative actions such as user management or configuration changes carried out."],
  },
  863: {
    ja: ["認可の誤り", "権限確認は行われているものの、条件に誤りがある箇所を突きます。特定のパラメータの組み合わせ、別の経路、大文字小文字の違いなどで、確認を通過させます。", "許可されていないデータの閲覧・変更や、管理者向けの操作を実行されます。"],
    en: ["Incorrect authorization", "A permission check exists but its logic is wrong. The attacker gets past it with a particular combination of parameters, an alternative path, or differences such as letter case.", "Data the user is not allowed to access is viewed or changed, and administrative actions are carried out."],
  },
  918: {
    ja: ["サーバサイドリクエストフォージェリ (SSRF)", "URLを受け取って取得する機能（画像の取り込み、Webhook、プレビューなど）に、内部向けのアドレスを指定します。サーバ自身がそこへリクエストを送るため、外部からは届かない社内システムやクラウドの管理用アドレス（169.254.169.254 など）にアクセスできます。", "内部のAPIや管理画面の情報を取得されます。クラウド環境では一時的な認証情報を盗まれ、ストレージやデータベースへの不正アクセスに発展します。"],
    en: ["Server-side request forgery (SSRF)", "The attacker gives an internal address to a feature that fetches a URL (image import, webhooks, link previews). Because the server itself makes the request, internal systems and cloud metadata addresses such as 169.254.169.254 become reachable from outside.", "Data from internal APIs and admin pages is obtained. In cloud environments temporary credentials are stolen, leading to unauthorized access to storage and databases."],
  },
  1321: {
    ja: ["プロトタイプ汚染", "JSONの結合やコピーを行う処理に、「__proto__」などの特別なキーを含むデータを送ります。JavaScriptのすべてのオブジェクトが共有する元オブジェクトに値が書き込まれ、アプリケーション全体の挙動が変わります。", "権限判定に使う値を書き換えられて認可を回避されたり、例外を起こしてサービスを止められたりします。他の処理と組み合わさると、サーバ上でのコード実行に至ります。"],
    en: ["Prototype pollution", "The attacker sends data containing special keys such as '__proto__' to code that merges or copies JSON. A value is written to the base object shared by every JavaScript object, changing behaviour across the application.", "Values used in permission checks can be overridden to bypass authorization, or errors triggered to stop the service. Combined with other code paths this can reach code execution on the server."],
  },
  1333: {
    ja: ["非効率な正規表現 (ReDoS)", "入れ子の繰り返しを含む正規表現に対して、照合の試行回数が爆発的に増える文字列を送ります。数十文字程度の入力でも、処理が数秒から数分かかるようになります。", "CPUを使い切り、サービスが応答しなくなります（DoS）。Node.js のように1つのスレッドで処理する環境では、1件のリクエストで全体が止まります。"],
    en: ["Inefficient regular expression (ReDoS)", "The attacker sends a string that makes a regular expression with nested repetition try an explosive number of matches. A few dozen characters can take seconds or minutes to process.", "CPU is exhausted and the service stops responding (denial of service). In single-threaded environments such as Node.js one request can stall everything."],
  },
  88: {
    ja: ["引数インジェクション", "外部コマンドの引数として渡される入力に、「-」で始まるオプション文字列を混ぜます。シェルの記号が無害化されていても、コマンド自体のオプション（出力先の指定、別プログラムの実行など）として解釈されます。", "コマンドの動作を変えられ、意図しないファイルの読み書きが起きます。オプションの種類によっては任意のコマンド実行に至ります。"],
    en: ["Argument injection", "The attacker includes option-like strings beginning with '-' in input that is passed as an argument to an external command. Even when shell metacharacters are neutralised, the command interprets them as its own options, such as an output file or a program to run.", "The command behaves differently and unintended files are read or written. Some options lead to arbitrary command execution."],
  },
  93: {
    ja: ["CRLFインジェクション", "入力に改行コード（CR・LF）を混ぜ、HTTPヘッダやログなど行単位で区切られるデータに、新しい行を追加します。", "HTTPレスポンスに任意のヘッダや本文を追加され、Cookieの設定や偽ページの表示に使われます。ログに偽の記録を書き込まれ、調査を妨げられることもあります。"],
    en: ["CRLF injection", "The attacker inserts line breaks (CR and LF) into input so that extra lines are added to line-based data such as HTTP headers or logs.", "Arbitrary headers or body content are added to HTTP responses, used to set cookies or show fake pages. Forged log entries can also hinder investigations."],
  },
  116: {
    ja: ["出力のエンコード・エスケープ不備", "データを別の処理系（HTML、SQL、シェル、ログなど）に渡すときの特殊文字の無害化が足りない点を突きます。攻撃者は、渡し先で特別な意味を持つ文字を入力に含めます。", "渡し先に応じたインジェクション攻撃が成立します。スクリプトの実行（XSS）、コマンドの実行、データの改ざんなどにつながります。"],
    en: ["Improper encoding or escaping of output", "Special characters are not neutralised when data is handed to another interpreter (HTML, SQL, a shell, logs). The attacker includes characters that have special meaning there.", "The matching injection attack becomes possible: script execution (XSS), command execution, data tampering and so on."],
  },
  126: {
    ja: ["バッファの過剰読み取り", "実際より大きな長さを申告するデータを送り、バッファの終端を越えて読み取らせます。越えた部分の内容が応答として返ってくることがあります（Heartbleed が有名な例です）。", "メモリ上にあった秘密情報（鍵、パスワード、他の利用者のデータ）が漏れます。異常終了によるサービス停止も起きます。"],
    en: ["Buffer over-read", "The attacker sends data that claims to be longer than it is, so the program reads past the end of a buffer and may return the extra bytes in its response (Heartbleed is the well-known example).", "Secrets that were in memory, such as keys, passwords and other users' data, are disclosed. The program may also crash."],
  },
  178: {
    ja: ["大文字・小文字の扱いの不備", "検査では大文字と小文字を区別し、実際の処理では区別しない（またはその逆の）箇所を突きます。「/Admin」や「.PHP」のように表記を変えて、禁止リストをすり抜けます。", "アクセス制限やファイル種別のフィルタを回避されます。管理画面への到達や、禁止されているファイルのアップロードにつながります。"],
    en: ["Improper handling of case sensitivity", "A check is case-sensitive while the real processing is not (or the reverse). The attacker writes '/Admin' or '.PHP' to slip past a block list.", "Access restrictions and file-type filters are bypassed, which can expose admin pages or allow forbidden files to be uploaded."],
  },
  191: {
    ja: ["整数アンダーフロー", "引き算の結果が最小値を下回る値を与えます。結果が巻き戻って巨大な正の数として扱われ、コピーする長さや確保するサイズが誤った値になります。", "メモリ破壊が起き、プログラムの異常終了や任意のコード実行につながります。"],
    en: ["Integer underflow", "The attacker supplies values that make a subtraction go below the minimum. The result wraps around to a huge positive number, so a copy length or allocation size becomes wrong.", "Memory is corrupted, leading to crashes or arbitrary code execution."],
  },
  201: {
    ja: ["送信データへの機密情報の混入", "通常の応答、エラー応答、外部への通知などに、本来含めるべきでない情報が入っている点を利用します。攻撃者は通常どおりリクエストを送るだけで、その情報を受け取れます。", "内部情報、他の利用者のデータ、認証情報などが漏れます。"],
    en: ["Sensitive information in sent data", "Normal responses, error responses or outgoing notifications contain data that should not be there. The attacker only has to make ordinary requests to receive it.", "Internal information, other users' data or credentials are disclosed."],
  },
  248: {
    ja: ["捕捉されない例外", "例外を発生させる入力（壊れた形式、想定外の型など）を送ります。どこにも処理されないまま例外が上位まで伝わり、プロセスが終了します。", "サービスが止まります（DoS）。エラーの詳細が応答に出る場合は、内部情報の漏えいにもなります。"],
    en: ["Uncaught exception", "The attacker sends input that raises an exception (malformed data, unexpected types). Nothing handles it, it propagates to the top, and the process exits.", "The service stops (denial of service). If error details are returned, internal information is disclosed as well."],
  },
  252: {
    ja: ["戻り値の確認漏れ", "処理の失敗を確認せずに先へ進む箇所を狙い、その処理が失敗する状況（メモリ不足、不正な入力など）を作ります。プログラムは失敗した結果を正常な値として使い続けます。", "想定外の状態で処理が続き、異常終了やメモリ破壊が起きます。権限を下げる処理の失敗が見逃されると、高い権限のまま動作し続けます。"],
    en: ["Unchecked return value", "The attacker creates a situation (low memory, invalid input) where an operation fails at a point where the program does not check the result, so it carries on using the failed result as if it were valid.", "The program continues in an unexpected state and crashes or corrupts memory. If a failed attempt to drop privileges goes unnoticed, it keeps running with high privileges."],
  },
  285: {
    ja: ["認可の不備", "権限確認の不足や誤りを突き、自分の役割では許可されていない機能やデータにリクエストを送ります。", "他人のデータの閲覧・変更や、管理者向けの操作を実行されます。"],
    en: ["Improper authorization", "The attacker abuses missing or incorrect permission checks and requests functions or data that their role should not be allowed to use.", "Other users' data can be viewed or changed and administrative actions carried out."],
  },
  319: {
    ja: ["機密情報の平文送信", "暗号化されていない通信（HTTP、古いプロトコルなど）を、通信経路上で傍受します。公衆Wi-Fiや、同じネットワーク内の端末からの盗聴が典型です。", "パスワード、トークン、個人情報を盗まれます。通信内容を書き換えられることもあります。"],
    en: ["Cleartext transmission of sensitive information", "The attacker intercepts unencrypted traffic (HTTP, legacy protocols) on the network path, typically on public Wi-Fi or from another machine on the same network.", "Passwords, tokens and personal data are stolen, and the traffic can also be altered."],
  },
  346: {
    ja: ["オリジン検証の不備", "リクエストやメッセージ（postMessage、WebSocket、CORSなど）の送信元の確認が甘い箇所を狙います。攻撃者は自分のサイトを被害者に開かせ、そこから対象サイトとやり取りします。", "別のサイトから、被害者の権限で操作されたり、データを読み取られたりします。"],
    en: ["Origin validation error", "The source of a request or message (postMessage, WebSocket, CORS) is not verified strictly. The attacker gets the victim to open their site, which then talks to the target site.", "Another site can act with the victim's privileges or read the victim's data."],
  },
  367: {
    ja: ["TOCTOU 競合状態", "プログラムがファイルや状態を「確認」してから「使用」するまでの一瞬に、対象を差し替えます。確認時は無害なファイルを置き、使用の直前に重要なファイルへのリンクに入れ替える、といった方法です。", "権限確認をすり抜け、本来触れないファイルを操作されます。権限昇格に使われることが多い種類です。"],
    en: ["Time-of-check time-of-use race", "The attacker swaps a file or state in the instant between the program checking it and using it: a harmless file is present for the check and is replaced by a link to an important file just before use.", "Permission checks are bypassed and files the attacker should not touch are operated on. This is often used for privilege escalation."],
  },
  407: {
    ja: ["計算量の非効率なアルゴリズム", "処理時間が入力の大きさに対して急激に増えるアルゴリズムに、最悪ケースになる入力を送ります。同じハッシュ値になるキーを大量に送る手口（ハッシュ衝突攻撃）が代表例です。", "CPUを使い切り、サービスが応答しなくなります（DoS）。"],
    en: ["Inefficient algorithmic complexity", "The attacker sends worst-case input to an algorithm whose running time grows steeply with input size. Sending many keys that hash to the same value (a hash-collision attack) is the classic example.", "CPU is exhausted and the service stops responding (denial of service)."],
  },
  436: {
    ja: ["解釈の不一致", "検査を行う部品と実際に処理する部品とで、同じデータの解釈が食い違う点を利用します。検査側には無害に見え、処理側では別の意味になるデータを送ります。", "フィルタ、WAF、アクセス制御を回避されます。その先にある別の脆弱性を突く入口になります。"],
    en: ["Interpretation conflict", "The component that checks data and the component that processes it interpret the same data differently. The attacker sends data that looks harmless to the checker but means something else to the processor.", "Filters, WAFs and access controls are bypassed, opening the way to other flaws behind them."],
  },
  441: {
    ja: ["意図しない中継（Confused Deputy）", "脆弱なサーバに、別の宛先への通信を代行させます。サーバが持つ信頼や到達範囲を借りて、攻撃者自身は届かない相手にリクエストを送ります。", "攻撃の送信元を隠されたり、内部ネットワークに到達されたりします。踏み台にされたサーバの管理者が加害者として扱われるおそれがあります。"],
    en: ["Unintended proxy (confused deputy)", "The attacker makes the vulnerable server relay traffic to another destination, borrowing its trust and reach to contact systems the attacker cannot reach directly.", "The origin of attacks is hidden and the internal network becomes reachable. The operator of the relaying server may be seen as the attacker."],
  },
  524: {
    ja: ["キャッシュへの機密情報の保存", "個人向けの応答が共有キャッシュ（CDN、プロキシなど）に保存されてしまう状況を利用します。攻撃者は同じURLにアクセスし、キャッシュに残った他人向けの応答を受け取ります。", "他の利用者の個人情報やセッション情報が漏れます。"],
    en: ["Sensitive information in cache", "A response meant for one person is stored in a shared cache (CDN, proxy). The attacker requests the same URL and receives the cached response intended for someone else.", "Other users' personal data or session information is disclosed."],
  },
  613: {
    ja: ["セッション期限の不備", "ログアウト後や長時間経過後も、セッションやトークンが有効なままになっている点を利用します。共有端末、漏えいしたログ、盗んだCookieから得たセッションを再利用します。", "盗んだセッションで、本人になりすましてログイン状態を使われ続けます。パスワードを変更しても無効にならない場合があります。"],
    en: ["Insufficient session expiration", "Sessions or tokens stay valid after logout or for too long. The attacker reuses one obtained from a shared computer, leaked logs or a stolen cookie.", "The attacker keeps using the victim's logged-in session, sometimes even after the password is changed."],
  },
  668: {
    ja: ["リソースの誤った領域への公開", "内部向けのファイル、ポート、機能が、想定していない利用者やネットワークから届く状態になっている点を利用します。", "情報漏えいや不正な操作につながります。"],
    en: ["Exposure of resource to wrong sphere", "Internal files, ports or functions are reachable by users or networks that were never meant to have access.", "Information disclosure and unauthorized actions follow."],
  },
  674: {
    ja: ["制御されない再帰", "極端に深い入れ子のデータ（何千段にも入れ子になったJSONやXMLなど）を送ります。再帰的に処理する関数がスタック領域を使い切ります。", "プログラムが異常終了し、サービスが止まります（DoS）。"],
    en: ["Uncontrolled recursion", "The attacker sends extremely deeply nested data (JSON or XML nested thousands of levels). The function that processes it recursively exhausts the stack.", "The program crashes and the service stops (denial of service)."],
  },
  693: {
    ja: ["保護機構の不備", "入力検証、アクセス制限、サンドボックスなどのセキュリティ機能が、特定の条件で働かない点を突きます。", "保護を回避されます。単独での被害は小さくても、他の脆弱性と組み合わせることで被害が大きくなります。"],
    en: ["Protection mechanism failure", "A security control such as input validation, access restriction or a sandbox does not apply under certain conditions, and the attacker creates those conditions.", "The protection is bypassed. The direct damage may be small, but combined with other flaws the impact grows."],
  },
  772: {
    ja: ["リソースの解放漏れ", "ファイル、接続、ロックなどが解放されない処理を、繰り返し呼び出します。", "使えるリソースがなくなり、新しい接続や処理を受け付けられなくなってサービスが止まります（DoS）。"],
    en: ["Missing release of resource", "The attacker repeatedly triggers an operation that never releases files, connections or locks.", "Available resources run out, new connections and work are refused, and the service stops (denial of service)."],
  },
  789: {
    ja: ["過大なメモリ割り当て", "サイズや個数を表す値に巨大な数を入れたデータを送ります。プログラムは値を信用して、一度に大量のメモリを確保しようとします。", "メモリ不足でプログラムが異常終了し、サービスが止まります（DoS）。小さなリクエスト1件で起こせる場合があります。"],
    en: ["Excessive memory allocation", "The attacker sends data with a huge number in a size or count field. The program trusts it and tries to allocate a very large amount of memory at once.", "The program runs out of memory and crashes, stopping the service (denial of service), sometimes from a single small request."],
  },
  822: {
    ja: ["信頼できないポインタの参照", "攻撃者が指定した値を、プログラムにメモリアドレスとしてそのまま使わせます。ドライバやカーネルが、アプリケーションから渡された値を確認せずに使う場合などが該当します。", "任意のメモリを読み書きされ、権限昇格やコード実行につながります。"],
    en: ["Untrusted pointer dereference", "The program uses a value supplied by the attacker directly as a memory address, for example when a driver or kernel uses a value from an application without checking it.", "Arbitrary memory can be read or written, leading to privilege escalation or code execution."],
  },
  908: {
    ja: ["未初期化リソースの使用", "初期化されていないメモリや変数を使わせます。そこには以前の処理で使われたデータが残っており、応答に含まれて返ってきたり、処理の分岐に影響したりします。", "以前の処理に含まれていた機密情報が漏れます。不定な値による異常終了も起きます。"],
    en: ["Use of uninitialized resource", "The program uses memory or variables before initialising them. Leftover data from earlier work is still there and may be returned in a response or influence a decision.", "Sensitive data from earlier operations is disclosed, and unpredictable values can crash the program."],
  },
};

const T = {
  "ja": {
    "AV": {
      "N": "攻撃経路: ネットワーク越しに攻撃できます。インターネットに公開している場合は、世界中のどこからでも狙われます。",
      "A": "攻撃経路: 同じネットワーク（社内LAN、同じWi-Fi、Bluetoothの届く範囲など）にいる相手からの攻撃に限られます。インターネット越しには直接届きません。",
      "L": "攻撃経路: 対象の端末上での操作が必要です。攻撃者がその端末にログインできるか、利用者に細工したファイルを開かせるなどの方法が要ります。",
      "P": "攻撃経路: 機器に物理的に触れる必要があります（USB機器の接続、端末の盗難など）。"
    },
    "PR": {
      "N": "必要な権限: アカウントもログインも不要です。誰でも攻撃を試せます。",
      "L": "必要な権限: 一般ユーザーのアカウントが必要です。誰でも登録できるサービスや、アカウントを盗まれた場合は、この条件は簡単に満たされます。",
      "H": "必要な権限: 管理者権限が必要です。管理者アカウントを先に奪われている場合や、内部の不正が前提になります。"
    },
    "Au": {
      "N": "必要な権限: アカウントもログインも不要です。誰でも攻撃を試せます。",
      "S": "必要な権限: ログインが必要です。アカウントを持っているか、盗んだアカウントを使う必要があります。",
      "M": "必要な権限: 複数回の認証が必要です。攻撃者にとっては手間のかかる条件です。"
    },
    "UI": {
      "N": "利用者の操作: 不要です。被害者が何もしなくても成立します。",
      "R": "利用者の操作: 必要です。リンクを開く、ファイルを開く、ページを表示するなど、被害者側の操作がきっかけになります。フィッシングと組み合わせて使われます。",
      "P": "利用者の操作: ページの閲覧など、通常の利用の範囲の操作がきっかけになります。特別な操作をさせる必要はありません。",
      "A": "利用者の操作: 被害者による積極的な操作（ファイルを取り込む、警告を承認するなど）が必要です。"
    },
    "AC": {
      "L": "攻撃の難しさ: 低い。特別な条件や準備なしに、同じ手順で繰り返し成功します。",
      "H": "攻撃の難しさ: 高い。特定の設定、タイミング、事前の情報収集などが必要で、毎回成功するとは限りません。",
      "M": "攻撃の難しさ: 中程度。ある程度の条件や準備が必要です。"
    },
    "AT": {
      "N": "対象側の前提: 特別な設定や状態は不要です。標準的な構成のままで成立します。",
      "P": "対象側の前提: 対象が特定の設定や状態になっている必要があります（特定の機能が有効、タイミングの競争に勝つ、通信経路に割り込める、など）。"
    },
    "sum": {
      "open": "まとめ: インターネット越しに、ログインも被害者の操作もなしで攻撃できます。最も条件の緩い組み合わせで、自動化された大量攻撃に使われやすく、公開しているサーバは無差別に狙われます。",
      "openHard": "まとめ: インターネット越しに、ログインも被害者の操作もなしで攻撃を試せます。ただし成立には特定の条件やタイミングが必要で、安定して成功させるのは難しい部類です。",
      "lure": "まとめ: 攻撃者側にアカウントは要りませんが、被害者に操作させる必要があります。不審なリンクやファイルを開かないことが、当面の防御になります。",
      "local": "まとめ: 攻撃者が先に端末へ入り込んでいることが前提です。侵入後の権限昇格や、マルウェアの動作に使われます。",
      "admin": "まとめ: 管理者権限が前提のため、単独では悪用されにくい条件です。管理者アカウントの保護が重要になります。"
    },
    "C": "機密性（情報の漏えい）",
    "I": "完全性（データ・設定の改ざん）",
    "A": "可用性（サービス停止）",
    "lvl": {
      "H": "大",
      "L": "小",
      "N": "なし",
      "P": "部分的",
      "C": "全面的"
    },
    "scope": "影響が脆弱な部品の外（他のコンポーネントやホスト）にも及ぶ",
    "noCwe": "種類の分類（CWE）がまだ付与されていません。概要と一次情報を確認してください。"
  },
  "en": {
    "AV": {
      "N": "Attack path: over the network. If the system is exposed to the internet, it can be targeted from anywhere in the world.",
      "A": "Attack path: limited to someone on the same network (office LAN, the same Wi-Fi, within Bluetooth range). It cannot be reached directly over the internet.",
      "L": "Attack path: requires activity on the machine itself. The attacker must be able to log in to it, or get a user to open a crafted file.",
      "P": "Attack path: requires physical access to the device (plugging in a USB device, a stolen laptop)."
    },
    "PR": {
      "N": "Privileges needed: none. No account or login is required, so anyone can try the attack.",
      "L": "Privileges needed: a normal user account. Where anyone can sign up, or an account has been stolen, this is easy to meet.",
      "H": "Privileges needed: administrator. The attacker must already have taken an admin account, or be an insider."
    },
    "Au": {
      "N": "Privileges needed: none. No account or login is required, so anyone can try the attack.",
      "S": "Privileges needed: a login. The attacker needs an account of their own or a stolen one.",
      "M": "Privileges needed: several authentications, which makes the attack laborious."
    },
    "UI": {
      "N": "User interaction: none. The attack works without the victim doing anything.",
      "R": "User interaction: required. The victim must open a link or a file or view a page; this is usually combined with phishing.",
      "P": "User interaction: ordinary activity such as viewing a page is enough to trigger it. No unusual action is needed.",
      "A": "User interaction: the victim must take a deliberate action, such as importing a file or accepting a warning."
    },
    "AC": {
      "L": "Attack complexity: low. It succeeds repeatedly with the same steps and no special preparation.",
      "H": "Attack complexity: high. It needs specific configuration, timing or prior reconnaissance and does not succeed every time.",
      "M": "Attack complexity: medium. Some conditions or preparation are needed."
    },
    "AT": {
      "N": "Target prerequisites: none. A standard configuration is enough.",
      "P": "Target prerequisites: the target must be in a particular configuration or state (a feature enabled, a race won, a position on the network path)."
    },
    "sum": {
      "open": "In short: exploitable over the internet with no login and no action by the victim. This is the loosest combination: it suits automated mass exploitation, and exposed servers are attacked indiscriminately.",
      "openHard": "In short: it can be attempted over the internet with no login and no action by the victim, but it needs specific conditions or timing and is hard to make work reliably.",
      "lure": "In short: the attacker needs no account but must get the victim to act. Not opening suspicious links or files is the interim defence.",
      "local": "In short: the attacker must already be on the machine. This is used for privilege escalation after a break-in, or by malware.",
      "admin": "In short: administrator rights are required, so it is hard to exploit on its own. Protecting admin accounts matters most."
    },
    "C": "Confidentiality (data disclosure)",
    "I": "Integrity (data or settings tampering)",
    "A": "Availability (service outage)",
    "lvl": {
      "H": "high",
      "L": "low",
      "N": "none",
      "P": "partial",
      "C": "complete"
    },
    "scope": "Impact extends beyond the vulnerable component (other components or the host)",
    "noCwe": "No weakness type (CWE) has been assigned yet. Check the summary and the primary sources."
  }
};
const OTHER_CWE = { ja: (id) => `${id}（定義はリンク先）`, en: (id) => `${id} (see the link for its definition)` };

function parseVector(v) {
  const m = {};
  for (const part of String(v || '').split('/')) {
    const [k, val] = part.split(':');
    if (k && val) m[k] = val;
  }
  return m;
}

// Returns { types: [{id, name, how, impact}], conditions: [text], effects: [[label, level, levelCode]], scope }
export function explain(item, lang) {
  const t = T[lang] || T.en;
  const types = (item.cwe || []).filter((id) => !/NVD-CWE/.test(id)).map((id) => {
    const e = CWE[Number(id.replace('CWE-', ''))];
    const d = e && (e[lang] || e.en);
    return d ? { id, name: d[0], how: d[1], impact: d[2] } : { id, name: (OTHER_CWE[lang] || OTHER_CWE.en)(id) };
  });
  types.sort((a, b) => !!b.how - !!a.how);
  const m = parseVector(item.cvss?.v);
  const conditions = [];
  if (m.AV) conditions.push(t.AV[m.AV]);
  if (m.PR) conditions.push(t.PR[m.PR]); else if (m.Au) conditions.push(t.Au[m.Au]);
  if (m.UI) conditions.push(t.UI[m.UI]);
  if (m.AC) conditions.push(t.AC[m.AC]);
  if (m.AT) conditions.push(t.AT[m.AT]);
  // One-line reading of the combination, shown first.
  const noAuth = m.PR ? m.PR === 'N' : m.Au === 'N';
  const noUi = !m.UI || m.UI === 'N';
  const hard = (m.AC && m.AC !== 'L') || m.AT === 'P';
  const sum = m.AV === 'N' && noAuth && noUi && m.UI ? (hard ? 'openHard' : 'open')
    : m.AV === 'N' && noAuth && !noUi ? 'lure'
      : m.AV === 'L' || m.AV === 'P' ? 'local'
        : m.PR === 'H' ? 'admin' : '';
  if (sum) conditions.unshift(t.sum[sum]);
  const effects = [];
  for (const k of ['C', 'I', 'A']) {
    const code = m['V' + k] || m[k];
    if (code) effects.push([t[k], t.lvl[code] || code, code]);
  }
  const scope = m.S === 'C' || ['SC', 'SI', 'SA'].some((k) => m[k] && m[k] !== 'N') ? t.scope : '';
  return { types, conditions: conditions.filter(Boolean), effects, scope, noCwe: t.noCwe };
}
