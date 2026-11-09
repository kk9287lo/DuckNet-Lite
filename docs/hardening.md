# 配備ハードニング — OS 公認の自己防衛(evolution #47–#55 の運用面)

> 先に正直なところを。DuckNet の「終了されにくさ・改竄されにくさ」は、OS が公式に用意する保護機構で実現します。
> プロセスを管理者から隠す、taskkill を妨害する、別名で隠れ起動する——こうした手口は、防御目的であっても
> マルウェア(rootkit/persistence)そのものになり、製品の信頼性を壊すので実装しません。本物の EDR と同じく、保護は
> 透明で(管理者は常に正規の手段で停止・確認できる)、阻むのは攻撃者だけです。本書は、その透明な保護を OS ごとに
> 設定する手順です。

アプリ内蔵の自己防衛(可変状態の HMAC 署名=#52–#54、改竄の可視化=ダッシュボード=#55)に、本書の OS 層
(クラッシュからの自動再起動を含む)を重ねて多層防御にします。

前衛の `--listen 8443` はポート番号に関係なく平文 HTTP で、DuckNet 自身は TLS 終端をしません。
公開 HTTPS には同じホストの TLS 終端プロキシを前段に置き、DuckNet の待受を `127.0.0.1`
または非公開の専用ネットワークへ限定してください。バックエンドも外部から直結できないようにします。

## 検査・保存の境界

- Bearerの区切りは検査とcredential集計で共通に読み、複数credentialを選べる要求は転送前に拒否します。
  単一Bearer値の形式は [RFC 6750 §2.1](https://www.rfc-editor.org/rfc/rfc6750.html#section-2.1) を基準にします。
- GraphQL multipartは、先頭のJSONだけでなく全パートの名前・重複・終端を有界に確認します。
  `operations`を検査範囲の後ろへ置いた要求や、一意に読めない名前は遮断モードで転送しません。
  通常の`operations`に続く大きな添付は従来どおり扱い、監査モードでは拒否予定を記録して元の本文を維持します。
- MIMEファイル名はraw値と受け手が復号する名前の両方で拡張子を検査します。
  [文字コード・継続パラメータ](https://www.rfc-editor.org/rfc/rfc2231.html)を復号するときは、
  既知の文字コードだけを解決し、未知・非text・不完全な表現を「安全」として流しません。
  パラメータの外側コメントで名前が変わる入力も拒否し、引用された通常の括弧は維持します。
  Windowsのstream指定がある名前は、その指定前の基本名も同じ拒否拡張子で検査します。
- 追記ログは通常ファイル・単一リンク・開いたFDと名前の一致を確認し、実ログの容量確認から書込みまで
  同じinodeをロックします。forkする子は親から継承した追記FDを閉じ、親のOSロックを解除しません。
- 応答DLPも引用符を考慮したMIMEパラメータを読みます。未対応のcharset拡張や外側コメントで
  受け手の復号結果が変わる場合、遮断設定では応答headの公開前に拒否し、監査設定では記録します。
- multipart本文を検査するとき、パート内転送符号化は検査と同じidentity表現だけを扱います。フォームはpercent復号後の
  key/valueにも宣言charsetを適用し、要素数・走査表現数・総量の上限超過を検査不能として扱います。
  フォームは1024要素まで、走査表現は元の表現を含む8通り・合計8MiBまでです。
- `origin_header`は128文字以内のASCIIフィールド名に限り、Host・本文長・認証・実IP等の既存の意味を
  上書きする名前は拒否します。`cache_poison_headers`も保護対象の削除を全件検証して拒否します。
  有効な旧保存設定に不適切な変更指定がある場合は、元ファイルを保持して既存の設定不正状態を報告します。
- serving leaseもFDを開いて登録する区間をforkと同期し、子への未登録FDの継承を防ぎます。
  registryの競合待ちは期限内とし、解放待ちの所有者は次のregistry解放時に回収します。

状態ディレクトリを同じUID/rootが任意に書き換えられる場合まで、監査の完全性を保証するものではありません。
稼働中の本体へコード修正を反映するときは、**DuckNetアプリの停止・起動**が必要です。Windows自体の再起動は不要です。

---

## 0. 線引き(何を OS に任せ、何をアプリでやるか)

| 目的 | アプリ内蔵 | OS 公認(本書) |
|---|---|---|
| クラッシュからの再起動 | (なし=OS 層に委任) | systemd `Restart=` / Windows サービス回復 / launchd `KeepAlive` |
| 終了されにくさ | (しない=透明) | サービス ACL・専用ユーザ・権限分離 |
| 本体コードの改竄防止 | (なし=OS 層に委任) | `chattr +i` / 読取専用マウント / ファイル ACL |
| 状態ファイルの改竄耐性 | HMAC 署名(#52–#54)。改竄で設定を読めなければ防御を止めない側へ倒す(1.4) | 外部署名鍵(下記)+ state dir 権限 |
| 改竄の気づき | events+metrics(#55・ダッシュボード) | — |

やらないこと(意図的に): プロセス/ファイルの隠蔽、taskkill/Task Manager からの終了妨害、別名での隠れ起動、
「終了したと見せかけて稼働」。これらは透明な実装が存在せず、rootkit になってしまいます。

---

## 1. 共通(全 OS)

### 1.1 外部署名鍵で HMAC 保護を一段上げる
#52–#54 の状態署名鍵は、既定では state dir に `0600` で生成・保存します。鍵を読み取れない・永続化できないときは起動を拒否し、一時鍵で状態を書きません。ただし鍵が保護対象と同じ書込み可能ディスク
にあると、root を取った攻撃者は鍵も読めて再署名できてしまいます。鍵を state dir の外(環境変数 / シークレット
マネージャ / 別権限のファイル)に置くと、この穴が閉じます。

```bash
# 例: 別管理の鍵をサービスにだけ環境変数で渡す（state dir には書かない）
export DUCKNET_STATE_KEY="$(cat /etc/ducknet/keys/state.key)"     # 状態(#52–#54)
```
外部鍵には暗号学的乱数から作った値を使い、UTF-8 で 32 バイト以上を渡してください（例: `python -c 'import secrets; print(secrets.token_hex(32))'` で生成する64文字）。明示した空値・短い値は起動時に拒否します。短い外部鍵で署名した既存状態がある場合、鍵だけを差し替えて起動すると旧署名を検証できません。本体を停止して所有元と状態を確認し、オフラインで検証・再署名するか、旧状態を保持したまま新しい専用保存先で防御設定を再構築してください。自動で移行・消去しません。
鍵ファイルは `root:ducknet` 所有・`0640`、または Vault/KMS 等から起動時に注入します。
state dir 内の自動生成 `.statekey` は実行ユーザー本人の所有が必要です。root で起動した場合も他ユーザー所有のローカル鍵は採用しません。

DuckNet-Lite の既定保存先は `~/.cache/ducknet-lite` です。旧版の `~/.cache/dataplane` は FalcoNet と共有され得て、`.statekey` と BAN・ACL・設定のファイル名も重なります。旧場所に署名状態や DuckNet の監査記録が残る間は、どちらの製品の状態かを署名だけでは判別できないため、DuckNet は毎回の起動前に停止して `DUCKNET_STATE_DIR` の明示を求めます。旧ファイルを自動で移動・削除せず、両製品に同じ保存先を指定しないでください。移行する場合は両アプリを停止し、所有元と署名鍵・本体・`.hw` の組を確認した状態だけを扱ってください。
本体は状態保存先ごとに `.ducknet-serving.lock` を保持し、同じ保存先を使う2つ目の本体を待受前に拒否します。通常停止では最終BAN・クォータ保存を終えてから解放します。外部の署名付き状態更新は転送前に再検証し、古いクォータ・使用量の保存による新しい署名履歴の上書きを拒否します。別プロセスの独立した同時集計を合算する機能はありません。外部の更新者と共有する運用では、状態の所有者を1つにしてください。

### 1.2 改竄の気づき(#55)
ダッシュボードは `GET /api/shield/tamper` で、状態ファイル改竄(`state_tamper`)/ in-memory cfg 改竄(`memory_tamper`)の
要約と直近イベントを返します(ローカル可視化のみで、外部転送はしません)。

### 1.3 最小権限で動かす
専用の非特権ユーザ(例 `ducknet`)で実行し、書込みは state dir だけに限定します。バインドに特権ポート(<1024)が
要るなら、Linux は `CAP_NET_BIND_SERVICE` だけ付与します(フル root にしない)。

同梱 Compose は UID 10001、読取専用のルート FS、全 capability の除去、`no-new-privileges`、有界の `/tmp` tmpfs を使います。
状態は `/data` の専用 volume に保持し、アプリのコードは root 所有にします。新しい state dir は `0700`、鍵は `0600` です。
Dockerfile は利用可能な OS セキュリティ更新を適用します。再ビルド時は `docker compose build --pull --no-cache` で更新を取り込み、
運用するイメージそのものを検査してください。Compose の `host.docker.internal` は `host-gateway` で Linux Engine にも明示します。
単独の `docker run` で Linux ホストの backend を使う場合も `--add-host host.docker.internal:host-gateway` を指定してください。
POSIX では state dir を実行 UID 所有の保存先に限定します。新規作成時は `0700`、既存の
`0755` は権限を変更せず受け入れます。他ユーザー書込み可能な state dir・祖先、他 UID 所有、最終 symlink は
起動時に拒否します。祖先の root 所有 sticky `/tmp` は許可します。外部署名鍵を使う場合も
この保存先検査を行います。Windows の ACL は `chmod` だけでは検証できないため、
サービスアカウント専用の保存先を OS 側で設定してください。

### 1.4 設定を改竄されたときの動作(fail-closed)
設定(`state.json`)とメモリ上の cfg を同時に書き換えて「WAF を OFF に戻す」攻撃に対し、検証できない設定では
防御を止めない側へ倒します。

- **稼働中**: メモリ上の cfg を MAC で周期照合し、API を通らない書換えを見つけたら署名検証済みの `state.json`
  から復元します。`state.json` も改竄・削除・巻き戻しされていて検証できなければ、最後に MAC が一致した cfg を
  保ち、それも照合できなければ既定値+シールド ON にします。どの場合も `memory_tamper` を記録し、
  `verify_cfg_integrity()` は復元元を `source`(`disk` / `memory` / `defaults`)で返します。
- **起動時**: 初回起動は既定値+シールド ON で始めます。署名履歴がある状態の改竄・巻き戻し・
  欠損では `state_tamper` を記録し、失われた設定・規則・BAN を既定値で置き換えて転送を
  再開しません。enforce では backend へ送らず、署名済み監査設定が読める場合は転送と
  would-block を記録します。正しく署名された明示 OFF は尊重します。
- **状態を自動で洗い替えない**: 署名実績のある `state.json`・`rules.json`・`blocklist.json`・
  有限クォータの `traffic.json` が検証不能なら、空の内容を再署名せず次の起動でも拒否を保ちます。
  破損した `.hw` を古い `.hw.tmp` で代用しません。信頼できる署名済みスナップショットを
  復元し、DuckNet **アプリだけを再起動**して検証してください(BAN は検証済み再読込でも回復)。
- **初回起動**: 状態がまだ無ければ防御 ON・改竄記録なしで始めます。意図して全状態を初期化するときは、
  既定の防御設定が使われるため、個別ルールを設定し直してください。
- **鍵の交換**: 既存の state dir で `DUCKNET_STATE_KEY` を替えると旧署名を検証できず、
  改竄の記録と転送拒否になります。旧鍵と署名済み状態を復元するか、意図した初期化なら
  別の新しい state dir に移してから DuckNet アプリを起動してください。

アプリ層ファイアウォールの `acl.json` も同じ鍵で署名します。初回に限り旧版の無署名 ACL を読み、署名形式へ移行します。状態欠落や検証不能ではファイアウォールを ON にして既定ポリシー（外部 `public` は拒否）で起動します。正しく署名された明示 OFF は尊重します。ACL の新規ルールは IP/CIDR 文字列（64 文字以内）、注記は文字列（256 文字以内）、総数は 4096 件まで受け付けます。型・上限違反や保存失敗では既存ルールを保持し、失敗を返します。保存済みの `enabled` が欠損・型違い、または保存済みルールが不正・上限超過なら、ロード時に全ゾーン拒否で起動し、`/api/state` の `firewall.load_warning` に理由を示します。

保存先の同期が置換前に失敗した場合は旧ファイルを保持します。置換後に失敗した場合は、
公開済みの新値とメモリを一致させたまま `ok:false, applied_in_memory:true, persisted:false,
durable:false` を返します。再起動後の保持は確認できないため、保存先を復旧して再適用してください。
Windows と directory fsync 非対応のファイルシステムでは、ファイル名更新の電源断耐久性は未確認です。

防御設定・署名・ACL・BAN の保存は、読み込んだ内容と現在の署名済み内容を同じ保存ロック内で
照合します。別インスタンスの更新があれば古い全表で上書きせず、競合として失敗を返します。
競合時は最新状態を読み直してから再適用してください。複数ワーカーのメモリ状態を自動で合流する機能ではありません。

正直な限界: 本体と `.hw` の両方を消されても防御は ON ですが、初回起動と区別できず、個別ルールの消失を改竄として記録できません。
両方を整合的に古い正署名版へ巻き戻された場合も同じディレクトリ内の情報だけでは検出できません。完全な巻き戻し防止には外部の単調記録が必要です。state dir への書込みを 1.3/2.3 の権限で絞ってください。
旧版互換のため、署名保存の実績が確認できない初回には無署名の旧状態を移行します。攻撃者が state dir 内の本体・`.hw`・マーカーを一緒に消して無署名状態を置けるなら、旧版移行を装って明示 OFF や個別ルールの変更を読ませ得ます。アプリ内だけでは正規の初回移行と識別できないので、state dir の書込み権限を OS で保護してください。

---

## 2. Linux(systemd)

### 2.1 ハードニング済み unit
`/etc/systemd/system/ducknet.service`:

```ini
[Unit]
Description=DuckNet-Lite
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ducknet
Group=ducknet
# 本体はクラッシュで自動再起動（プロセスレベルの強制再開）
ExecStart=/usr/bin/python3 -m dataplane --backend 127.0.0.1:8080 --listen 8443
Restart=on-failure
RestartSec=2
StartLimitIntervalSec=60
StartLimitBurst=5            # クラッシュループ遮断
# --cluster で起動するなら有効に: SIGTERM を親だけへ送り、親が drain 猶予をワーカーへ渡す（下記の注）
#KillMode=mixed

# --- サンドボックス（攻撃者が本体を触れる面を削る）---
NoNewPrivileges=yes
ProtectSystem=strict         # / を読取専用に
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
CapabilityBoundingSet=CAP_NET_BIND_SERVICE   # 特権ポート bind 時のみ。不要なら空に
AmbientCapabilities=CAP_NET_BIND_SERVICE
# 書込みは state dir だけ許す（コードは読取専用のまま）
ReadWritePaths=/var/lib/ducknet
StateDirectory=ducknet

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now ducknet
sudo systemctl stop ducknet      # 管理者は正規に停止できる（透明）
```

> クラッシュからの自動再起動はアプリ自身では行いません(watchdog や親プロセス監督は持ちません)。systemd 配下では
> `Restart=` が、それ以外の環境ではタスクスケジューラ/nssm/launchd の回復設定(下記 §3・§4)がこの役目を担います。

> `--cluster` が実際に複数の fork ワーカーを起動した場合、systemd では `KillMode=mixed` にしてください。既定の
> `KillMode=control-group` は `systemctl stop` の SIGTERM を親と全ワーカーへ *同時に* 送るため、親が drain 猶予
> (`--drain-grace` / `DUCKNET_DRAIN_GRACE`)をワーカーへ渡す前にワーカーが猶予 0 で止まり、進行中のリクエストが切れます。
> `mixed` なら SIGTERM は親だけに届き、親が猶予を渡してからワーカーへ合図し、猶予を過ぎて残ったものを刈り取ります。
> `TimeoutStopSec`(既定 90 秒)は drain 猶予より数秒以上長くしてください。

### 2.2 本体コードを不変属性に(ファイルすり替え防止の OS 層)
```bash
# 配備後、コードと固定 config を変更不能にする（更新時だけ -i で解除）
sudo chattr +R +i /opt/ducknet/dataplane
sudo chattr +i /etc/ducknet/config.json
# 更新手順: sudo chattr -R -i <path> → 更新 → 再度 +i
```
これで書き換え自体を OS が拒否します。読取専用マウント(`mount -o remount,ro`)でも同等です。

### 2.3 state dir の権限
```bash
sudo install -d -o ducknet -g ducknet -m 0700 /var/lib/ducknet
# 署名鍵を別所有に（攻撃者が ducknet を取っても鍵は読めない構成）
sudo install -D -o root -g ducknet -m 0640 state.key /etc/ducknet/keys/state.key
```

---

## 3. Windows(サービス + ACL)

### 3.1 サービス化(自動回復つき)
```powershell
# Python ランチャをサービスに（nssm 例。sc.exe でも可）
nssm install DuckNet "C:\Python3\python.exe" "-m dataplane --backend 127.0.0.1:8080 --listen 8443"
nssm set DuckNet AppExit Default Restart        # クラッシュで自動再起動
nssm set DuckNet AppThrottle 2000               # 再起動の最小間隔（クラッシュループ抑制）
# 専用の低権限アカウントで実行
nssm set DuckNet ObjectName ".\ducknet_svc" "<password>"
Start-Service DuckNet
```
sc.exe を使うなら回復設定:
```cmd
sc.exe failure DuckNet reset= 60 actions= restart/2000/restart/2000/restart/2000
```

### 3.2 終了を「攻撃者には」させない＝サービス ACL
管理者は止められますが(透明)、一般ユーザ/侵入アカウントには `STOP`/`DELETE` を拒否します。
```cmd
:: 既定 SDDL を取得して、Authenticated Users から Stop 権を外した SDDL を設定する
sc.exe sdshow DuckNet
:: 例: 管理者(BA)・システム(SY)にフル、Interactive(IU)は照会のみ、に絞った D:(...) を設定
sc.exe sdset DuckNet "D:(A;;CCLCSWRPWPDTLOCRRC;;;BA)(A;;CCLCSWLOCRRC;;;SY)(A;;CCLCSWLOCRRC;;;IU)..."
```
> taskkill の妨害ではありません。管理者は常に停止できます。一般権限のプロセス(多くの侵入初期段階)からのサービス停止を
> ACL で拒否する、という OS 公認の最小権限制御です。

### 3.3 本体ファイルを読取専用 ACL に
```cmd
:: ducknet_svc とユーザに読取/実行のみ、書込みは Administrators だけ
icacls "C:\Program Files\DuckNet" /inheritance:r /grant:r "Administrators:(OI)(CI)F" "SYSTEM:(OI)(CI)F" "Users:(OI)(CI)RX"
```

### 3.4 最上位の改竄防止 = PPL/ELAM(正直な範囲)
Windows で本物の「プロセス保護」(他プロセスからのメモリ/ハンドル操作・強制終了の拒否)を得るには、
Protected Process Light(PPL)が要り、それには署名済みアンチマルウェアドライバ + ELAM 登録(Microsoft の審査・証明書)
が必要です。これは userspace ツールの範囲外で、ベンダーのドライバ署名の話になります。本書のサービス ACL + 専用アカウント +
読取専用 ACL が、ドライバ無しで取れる最善です。

---

## 4. macOS(launchd)

`/Library/LaunchDaemons/com.ducknet.guard.plist`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.ducknet.guard</string>
  <key>ProgramArguments</key>
  <array><string>/usr/bin/python3</string><string>-m</string><string>dataplane</string>
         <string>--backend</string><string>127.0.0.1:8080</string>
         <string>--listen</string><string>8443</string></array>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>  <!-- クラッシュで再起動 -->
  <key>UserName</key><string>_ducknet</string>
  <key>ThrottleInterval</key><integer>2</integer>
</dict></plist>
```
```bash
sudo launchctl load -w /Library/LaunchDaemons/com.ducknet.guard.plist
sudo chflags schg /opt/ducknet/dataplane/**/*.py    # システム不変フラグ（chattr +i 相当）
```
> 最上位の改竄防止(Endpoint Security / System Extension)は Apple の entitlement 審査が要り、ベンダー署名の領域です。
> launchd + `schg` + 専用ユーザが、ドライバ無しの最善です。

---

## 5. 効いていることの確認

```bash
# 1) 強制再起動: 子を kill → 自動で復活するか
kill -9 $(pgrep -f 'm dataplane') ; sleep 3 ; systemctl is-active ducknet     # → active

# 2) コード不変: 書き換えが OS に拒否されるか
echo x >> /opt/ducknet/dataplane/engine/lifeform/pipeline.py                  # → Operation not permitted

# 3) 状態改竄検知: blocklist を平文すり替え → 起動で弾かれダッシュボードに出るか
#    （署名運用後は無署名/改竄ファイルは fail-safe で破棄され state_tamper が飛ぶ）
curl -s -H "X-Token: $TOKEN" http://127.0.0.1:8081/api/shield/tamper           # → count>=1, events[]
```

---

## 6. 参照
- アプリ内蔵の自己防衛: 可変状態 HMAC 署名(#52–#54)、改竄可視化(#55・ダッシュボード)。クラッシュからの
  自動再起動はアプリでは行わず、OS 層(本書)に委ねます。
- 関連環境変数: `DUCKNET_STATE_KEY`(外部署名鍵)、`DUCKNET_STATE_DIR`(状態の所在)。

## 7. 前衛の資源・並行処理の境界

接続上限を取得できない場合は、制限なしへ倒さず受付を閉じます。要求本文の読取りと
backendへの書込み待ちは同じ総期限を使い、期限超過・キャンセルで部分要求の接続を中断します。
加工・検査する応答ヘッダーにも総期限があり、中間応答で延長しません。最終ヘッダー後の
正常なSSE本文の無通信には、このヘッダー期限を適用しません。

要求の `Content-Length` は前衛で空白を除いた10進数字19桁以内・`2^63-1` 以下に制限し、
超過値は audit / enforce のどちらでも backend に接続する前に拒否します。これは前衛の
整数変換と backend の本文境界が割れる可能性を減らす上限です。backend がさらに狭い上限を
持つ構成では、backend 側の受入上限も合わせて確認してください。

応答の `Connection` / `Proxy-Connection` がキャッシュ指示、`Vary`、ダウンロード指定、
CSP・Permissions-Policy などのブラウザ保護ヘッダー、または設定で除去・追加するヘッダーを
指名した場合は、利用者へ応答ヘッダーを公開する前に拒否します。次の中継器がそれらを
ホップ単位のヘッダーとして取り除き、前衛の保護を消すことを避けるためです。通常の
`Connection: close` や独立した
カスタム・ホップ指定はこの検査だけでは拒否しません。
chunked 応答の `Vary`・`Content-Disposition` trailer は値の転送前に拒否し、通常の情報用 trailer は転送バイト列を保持します。

ACLと使用量の診断ログは、前衛ではプロセス内の共有workerへ渡します。実行中を含め
合計32件までで、キュー超過・強制停止時の見送りは `acl_log_dropped` / `usage_log_dropped`、
書込み失敗は `acl_log_write_failed` / `usage_log_write_failed` に計上します。判定と使用量カウンターは
ログ待ちより先に確定します。ログは有界なbest effortであり、外部の耐久監査サービスの代わりにはなりません。
ACLを直接呼ぶ場合は結果の `log_written` と `stats.log_write_failed` でも失敗を確認できます。
`stop()` が `stopped:false` を返した場合は、未完了の書込みも所有中です。停止完了前に状態ディレクトリを
削除せず、未完処理を回収してから再起動します。POSIXの子は親の診断キュー・ロック・Futureを引き継ぎません。

署名付きチェックポイントとBANの保存は、整合性を保つため依然として状態ロック内の同期I/Oです。
失敗した通常チェックポイントの再試行は15秒間隔に制限し、明示的なflushは間隔に関係なく再試行します。
これらの保存が大きい場合の待ち時間や、ACL非一致時の全件走査は残ります。CPUの局所測定だけから
リクエスト全体の性能や、分散エッジと同等の処理能力を保証することはできません。

監査観点はCloudflareの公開資料の
[代理処理の設計](https://blog.cloudflare.com/how-we-built-pingora-the-proxy-that-connects-cloudflare-to-the-internet/)、
[カウンターの資源制限](https://blog.cloudflare.com/how-pingora-keeps-count/)、
[測定に基づく最適化](https://blog.cloudflare.com/pingora-saving-compute-1-percent-at-a-time/)を参考にしています。
