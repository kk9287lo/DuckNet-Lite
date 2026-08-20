# ChickenNet-Lite — 軽量 DDoS / WAF セキュリティゲートウェイ(free / trial 版)

**あなたのWebサーバの手前に置くだけで、L7(アプリ層)の DDoS と侵入(WAF)を防ぎます。**
外部依存ゼロ(Python標準ライブラリのみ)・OS非侵襲・防御専用。
（適用範囲は下記「正直な適用範囲」を必ずご確認ください。L3/L4 は対象外です。）

**ChickenNet-Lite は ChickenNet L7 Security の無償/試用エディションです。** 含まれるのは
コア機能一式 —— スコアリング/BAN/チャレンジ・エンジンを備えたリバースプロキシ型
WAF/DDoS ゲートウェイ、正のセキュリティモデル(allowlist)、GeoIP、Web 管理ダッシュボード、
DNS フィルタ(L7検知)、囮ファイルのダウンロード追跡(ビーコン)、SIEM/Webhook 転送、
自己完全性監視、署名付き状態永続化 —— のみです。上位(商用)エディションにある以下の機能は
**本エディションには含まれません**: カナリアトークン、LDAP/SMB/Kerberos の横展開デコイ、
LDAP 列挙検知プロキシ、脅威インテリジェンス(IoC)照合、MITRE ATT&CK 対応の脅威検知コンテンツ
配備、クラスタ間の分散BAN同期(gossip)、商用ライセンス管理。

## これは何か
[攻撃] → **ChickenNet L7 Security(前衛)** → あなたのWebサーバ(WordPress / API など)

- 前衛で **レート制限・侵入シグネチャ(SQLi/XSS/RCE/traversal/XXE/SSRF/JNDI/scanner 等)・脅威スコア・
  動的PoWチャレンジ・自動BAN・ハニーポット** を適用。
- **双方向に検査**: リクエストの head + **ボディ**(POST/JSON/GraphQL・gzip 解凍含む)+ **アップロード**、
  応答の **DLP・セキュリティヘッダ・Cookie/CORS/リダイレクト無害化**。
- **認証・濫用対策**: JWT 検査(`alg:none`/alg 混同)・クレデンシャル単位レート・正のセキュリティモデル
  (allowlist)・スマグリング/オーバーライド/キャッシュ汚染/Range DoS 対策。
- 不正な接続は **即TCP切断(Fail Fast)**。綺麗な(人間/正規)アクセスだけを通します。
- **自己防衛**: watchdog・強制再起動・ファイルすり替え検知+修復・状態の HMAC 署名(下記「自己防衛」節)。
- **Web管理ダッシュボード** で ON/OFF・攻撃グラフ・BAN管理・設定をクリック操作。

防御の一覧・設定キー・既定値(ON / opt-in)は **[docs/defenses.md](docs/defenses.md)**、
変更履歴は [CHANGELOG.md](CHANGELOG.md)。多くの高度な防御は **opt-in**(既定OFF)で、誤検知を避けつつ
必要な配備でのみ有効化できます。

## クイックスタート
```bash
# そのまま(Python 3.10+。依存インストール不要)
python -m dataplane --backend 127.0.0.1:8080 --listen 8443 --admin 8081
#   → 前衛: 0.0.0.0:8443  管理画面: http://127.0.0.1:8081 (トークンは起動時に表示)

# Docker(軽量イメージ)
docker compose up -d                       # ゲートウェイ(前衛 + 管理画面)
docker compose --profile dns up -d         # + DNS の L7 検知
docker compose --profile all up -d         # 全部
```
（検知系の上流は環境変数で設定: `CHICKENNET_DNS_UPSTREAM`。
単発実行も可: `docker run --rm chickennet-security:1.3.0 dns --help`)

起動ランチャ(任意・企業向け): Python 自動検出(venv 優先)+バージョン確認+UTF-8+
任意の設定ファイル読込を備えたラッパを同梱。引数とサブコマンドはそのまま渡せます。
```bash
./run.sh                         # Linux / macOS
run.bat                          # Windows (cmd) — ダブルクリックでも可
.\run.ps1 dns --upstream 1.1.1.1:53   # Windows (PowerShell) — サブコマンド例
```
設定は `app.env`(`app.env.example` を参照。機密を含みうるため
リポジトリにはコミットしない)。`CHICKENNET_PYTHON` で使う Python を明示できます。

全オプション(環境変数 / 設定キー)は **[docs/options.md](docs/options.md)**。

## おまけ: DNS の L7 検知(任意・別プロセス)
HTTP 前段とは別に、DNS(53番)を **問い合わせの中身と振る舞い** で見て、
トンネリング/C2/内部偵察(AD)の兆候を検知する DNS フィルタも同梱します(OS非侵襲・依存ゼロ)。
既定は「止める前にまず可視化(監査)」。
```bash
python -m dataplane dns --listen 5335 --upstream 1.1.1.1:53   # 監査(可視化)
python -m dataplane dns --enforce                            # 悪性判定を遮断
```
これは **DNS の部分適用**です(AD 全体のマイクロセグメンテーションではありません)。
設計と線引きは [docs/dns.md](docs/dns.md)。

> `dns` が別プロセスで稼働していれば、**管理ダッシュボードの「横展開 / DNS 検知」欄に
> 直近の検知が読み取り専用で集約表示**されます(ON/OFF は各プロセスの管轄で、画面からは
> 操作しません＝正直な可視化のみ)。

## おまけ: ステルス運用(防御を侵入者から低プロファイル化)
侵入後の攻撃者が本機を『防御ツール』と特定して狙って無効化するのを難しくする層。
自プロセス名・コンソール/ウィンドウタイトル・管理画面の表示名・`Server` ヘッダ・WAF 遮断
ページ・状態ファイルの場所を、ありふれた保守ユーティリティ名へ偽装します。
```bash
python -m dataplane --stealth                       # 既定名 "System Health Monitor"
python -m dataplane --stealth "Disk Indexer"        # 任意の偽装名
# 状態ファイルの場所だけ移したい場合(全サブコマンド共通):
CHICKENNET_STATE_DIR=~/.cache/sysidx python -m dataplane dns ...
```
**正直な限界**: これは *blend-in(指紋を薄める)* であって rootkit ではありません。OS の
プロセス列挙をフックして隠したり、他プロセス/カーネルへ干渉することは**一切しません**
(OS非侵襲・self-only)。`ps`/タイトル/`Server`/ファイル名での「ざっと見・自動列挙」は外せますが、
**メモリ解析や厳密なフォレンジックには抗えません**。`一切判らなくなる`とは言いません。

## 自己防衛 / 配備ハードニング(落とされない・改竄されない)
防御エージェントは『落とされたら終わり』。本機は **正当な(透明な)self-protection** を内蔵します:
生存監視 watchdog と強制再起動・一時停止からの安定復帰、本体ファイルすり替えの検知+強制修復、
可変状態(BAN/署名/設定)の **HMAC 署名による改竄耐性**、改竄の SIEM 転送+ダッシュボード可視化、
親プロセス監督(`--supervise`)。
```bash
python -m dataplane --supervise --backend 127.0.0.1:8080   # クラッシュで自動再起動(可視・正規)
export CHICKENNET_STATE_KEY=...   # 外部署名鍵で状態の改竄耐性を一段上げる(推奨)
```
**正直な線引き**: プロセス隠蔽・taskkill 妨害・別名での隠れ起動といった *rootkit 手口は実装しません*
(防御目的でも透明な実装が無く、製品自身が脅威になるため)。最上位の「終了されにくさ」は OS 公認の
保護(Linux systemd ハードニング+`chattr +i`・Windows サービス ACL+PPL/ELAM・macOS System Extension)で
得ます。設定手順は **[docs/hardening.md](docs/hardening.md)**。

**APT(国家支援型など)想定**: 高度な攻撃者は WAF と戦わず *迂回*(再ルーティング/直叩き)や
下層(インフラ/BGP/DNS/ランタイム/OS)を狙います。ChickenNet 側の対抗策(**オリジントークンで
迂回トラフィックを backend が拒否**・**迂回の能動検知**・**グローバル接続上限**・外部鍵)と、
WAF 外で運用者が装備すべき統制(RPKI/DNSSEC/IAM/cgroup 等)を4フェーズに対応づけた配備ガイドが
**[docs/apt-threat-model.md](docs/apt-threat-model.md)**。

## 正直な適用範囲(誇張しません)
- これは **L7(アプリ層)** 防御です。あなたのサーバが受理したHTTP要求を検査して弾きます。
- **回線/OSを飽和させる L3/L4 ボリューメトリック攻撃**(UDP/SYN flood 等)は本製品では
  止められません。それはネットワーク層(Anycast / クラウドのDDoS保護 / ISP)の領域です。
- **反撃はしません(防御専用)。** OS のファイアウォール(WFP/iptables)も触りません(非侵襲)。
- 大規模・全コア活用は Linux で `--cluster`(SO_REUSEPORT)。Windows等は単一プロセスへ降格。

## ライセンス / 調達情報
- ChickenNet-Lite は free / trial エディション(商用ライセンス管理機能自体を含みません)。
  利用条件は [LICENSE.txt](LICENSE.txt) を参照。上位(商用)エディションが必要な場合はベンダーへ
  お問い合わせください。
- 第三者ソフトウェア表示: [THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt)
  （本製品は**同梱する第三者コードなし**＝依存ゼロ）
- 機械可読 SBOM(CycloneDX 1.5): [sbom.cdx.json](sbom.cdx.json)
  （再生成: `python tools/gen_sbom.py`）

## 開発(ベンダー向け)
- テスト(依存ゼロ): `python tests/run_all.py`
- パッケージ: `python -m build`(sdist + wheel)/ 検証 `python -m twine check dist/*`
- CI: `.github/workflows/ci.yml`(Linux 3.10–3.13 + Windows でテスト/ビルド)
