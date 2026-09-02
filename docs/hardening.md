# 配備ハードニング — OS 公認の自己防衛(evolution #47–#55 の運用面)

> 先に正直なところを。DuckNet の「終了されにくさ・改竄されにくさ」は、OS が公式に用意する保護機構で実現します。
> プロセスを管理者から隠す、taskkill を妨害する、別名で隠れ起動する——こうした手口は、防御目的であっても
> マルウェア(rootkit/persistence)そのものになり、製品の信頼性を壊すので実装しません。本物の EDR と同じく、保護は
> 透明で(管理者は常に正規の手段で停止・確認できる)、阻むのは攻撃者だけです。本書は、その透明な保護を OS ごとに
> 設定する手順です。

アプリ内蔵の自己防衛(可変状態の HMAC 署名=#52–#54、改竄の可視化=ダッシュボード=#55)に、本書の OS 層
(クラッシュからの自動再起動を含む)を重ねて多層防御にします。

---

## 0. 線引き(何を OS に任せ、何をアプリでやるか)

| 目的 | アプリ内蔵 | OS 公認(本書) |
|---|---|---|
| クラッシュからの再起動 | (なし=OS 層に委任) | systemd `Restart=` / Windows サービス回復 / launchd `KeepAlive` |
| 終了されにくさ | (しない=透明) | サービス ACL・専用ユーザ・権限分離 |
| 本体コードの改竄防止 | (なし=OS 層に委任) | `chattr +i` / 読取専用マウント / ファイル ACL |
| 状態ファイルの改竄耐性 | HMAC 署名(#52–#54) | 外部署名鍵(下記)+ state dir 権限 |
| 改竄の気づき | events+metrics(#55・ダッシュボード) | — |

やらないこと(意図的に): プロセス/ファイルの隠蔽、taskkill/Task Manager からの終了妨害、別名での隠れ起動、
「終了したと見せかけて稼働」。これらは透明な実装が存在せず、rootkit になってしまいます。

---

## 1. 共通(全 OS)

### 1.1 外部署名鍵で HMAC 保護を一段上げる
#52–#54 の状態署名鍵は、既定では state dir に `0600` で生成・保存します。ただし鍵が保護対象と同じ書込み可能ディスク
にあると、root を取った攻撃者は鍵も読めて再署名できてしまいます。鍵を state dir の外(環境変数 / シークレット
マネージャ / 別権限のファイル)に置くと、この穴が閉じます。

```bash
# 例: 別管理の鍵をサービスにだけ環境変数で渡す（state dir には書かない）
export DUCKNET_STATE_KEY="$(cat /etc/ducknet/keys/state.key)"     # 状態(#52–#54)
```
鍵ファイルは `root:ducknet` 所有・`0640`、または Vault/KMS 等から起動時に注入します。

### 1.2 改竄の気づき(#55)
ダッシュボードは `GET /api/shield/tamper` で、状態ファイル改竄(`state_tamper`)/ in-memory cfg 改竄(`memory_tamper`)の
要約と直近イベントを返します(ローカル可視化のみで、外部転送はしません)。

### 1.3 最小権限で動かす
専用の非特権ユーザ(例 `ducknet`)で実行し、書込みは state dir だけに限定します。バインドに特権ポート(<1024)が
要るなら、Linux は `CAP_NET_BIND_SERVICE` だけ付与します(フル root にしない)。

---

## 2. Linux(systemd)

### 2.1 ハードニング済み unit
`/etc/systemd/system/ducknet.service`:

```ini
[Unit]
Description=DuckNet L7 Security
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
