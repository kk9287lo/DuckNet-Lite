# DuckNet-Lite — 軽量 DDoS / WAF セキュリティゲートウェイ(free / trial 版)

**あなたのWebサーバの手前に置くだけで、L7(アプリ層)の DDoS と侵入(WAF)を防ぎます。**
外部依存ゼロ(Python標準ライブラリのみ)・OS非侵襲・防御専用。
（適用範囲は下記「正直な適用範囲」を必ずご確認ください。L3/L4 は対象外です。）

**DuckNet-Lite は DuckNet L7 Security の無償/試用エディションです。** 含まれるのは
**コアの L7 WAF/DDoS リバースプロキシ・エンジンのみ** —— スコアリング/自動BAN・
侵入シグネチャ照合を備えたリバースプロキシ型ゲートウェイと、それを操作するための最小限の
Web 管理ダッシュボード(ON/OFF・指標・BAN管理・基本設定)、署名付き状態永続化です。
Lite はこのコアだけで実運用に耐える防御を提供します。次のような領域は上位(商用)エディション
**DuckNet L7 Security** で加わります。

- **可用性** — ファイルの改竄を自己完全性監視で検知・自動修復し、プロセスが落ちても watchdog が
  自動再起動+親プロセス監督(`--supervise`)で立て直します。無人運用でも稼働を維持できます。
- **ボットとの選別** — 動的 PoW(Proof-of-Work)チャレンジで、正規ユーザーを通しながら自動化された
  攻撃だけを絞り込みます(Lite は deny_score 以上の単発拒否 / block_score 以上の自動BANという
  二値判定のみ)。GeoIP・正のセキュリティモデル(allowlist)・ステルス運用(プロセス名偽装)による
  アクセス制御も加わります。
- **侵入後の検知** — LDAP/SMB/Kerberos の横展開デコイ、囮ファイルのダウンロード追跡(ビーコン)、
  カナリアトークン、ハニーポット(囮URLパス命中の即時BAN)で、境界を突破された後の不審な動きも
  捕捉します。DNS フィルタ(L7検知)は C2通信やトンネリングを見つけます。
- **運用への統合** — 検知結果を SIEM や Slack へリアルタイム転送(Webhook/Syslog)。脅威
  インテリジェンス(IoC)照合と MITRE ATT&CK 対応のルールで、既知の攻撃手口を継続的にカバー
  します。
- **複数拠点・大規模環境** — LDAP 列挙検知プロキシ、ノード間で BAN 情報を同期する分散ゴシップに
  より、組織全体で一貫した防御になります(商用ライセンス管理つき)。

## これは何か
[攻撃] → **DuckNet L7 Security(前衛)** → あなたのWebサーバ(WordPress / API など)

- 前衛で **レート制限・侵入シグネチャ(SQLi/XSS/RCE/traversal/XXE/SSRF/JNDI/scanner 等)・脅威スコア・
  自動BAN** を適用。
- **双方向に検査**: リクエストの head + **ボディ**(POST/JSON/GraphQL・gzip 解凍含む)+ **アップロード**、
  応答の **DLP・セキュリティヘッダ・Cookie/CORS/リダイレクト無害化**。
- **認証・濫用対策**: JWT 検査(`alg:none`/alg 混同)・クレデンシャル単位レート・
  スマグリング/オーバーライド/キャッシュ汚染/Range DoS 対策。
- 不正な接続は **即TCP切断(Fail Fast)**。綺麗な(人間/正規)アクセスだけを通します。
- **状態の整合性**: 可変状態(BAN/署名/設定)の HMAC 署名による改竄耐性(下記「配備ハードニング」節)。
- **Web管理ダッシュボード** で ON/OFF・攻撃グラフ・BAN管理・設定をクリック操作。

防御の一覧・設定キー・既定値(ON / opt-in)は **[docs/defenses.md](docs/defenses.md)**、
変更履歴は [CHANGELOG.md](CHANGELOG.md)。多くの高度な防御は **opt-in**(既定OFF)で、誤検知を避けつつ
必要な配備でのみ有効化できます。管理ダッシュボードの各パネルの使い方は
**[docs/dashboard.md](docs/dashboard.md)**(ダッシュボード右上の ❓ からも同様の早見表とフル版との
機能差分を表示できます)。

## クイックスタート
```bash
# そのまま(Python 3.10+。依存インストール不要)
python -m dataplane --backend 127.0.0.1:8080 --listen 8443 --admin 8081
#   → 前衛: 0.0.0.0:8443  管理画面: http://127.0.0.1:8081 (トークンは起動時に表示)

# Docker(軽量イメージ)
docker compose up -d                       # ゲートウェイ(前衛 + 管理画面)
```

起動ランチャ(任意・企業向け): Python 自動検出(venv 優先)+バージョン確認+UTF-8+
任意の設定ファイル読込を備えたラッパを同梱。引数はそのまま渡せます。
```bash
./run.sh                         # Linux / macOS
run.bat                          # Windows (cmd) — ダブルクリックでも可
.\run.ps1 --admin 8081           # Windows (PowerShell)
```
設定は `app.env`(`app.env.example` を参照。機密を含みうるため
リポジトリにはコミットしない)。`DUCKNET_PYTHON` で使う Python を明示できます。

全オプション(環境変数 / 設定キー)は **[docs/options.md](docs/options.md)**。

## 配備ハードニング(落とされない・改竄されない)
防御エージェントは『落とされたら終わり』。本機は可変状態(BAN/署名/設定)の
**HMAC 署名による改竄耐性**と、改竄のダッシュボード可視化を内蔵します。クラッシュからの
自動再起動は **OS 公認の仕組み**(systemd `Restart=`/Windows サービス回復/launchd `KeepAlive`)に
委ねます(アプリ自身は watchdog/親プロセス監督を持ちません=依存ゼロのままシンプルに)。
```bash
export DUCKNET_STATE_KEY=...   # 外部署名鍵で状態の改竄耐性を一段上げる(推奨)
```
**正直な線引き**: プロセス隠蔽・taskkill 妨害・別名での隠れ起動といった *rootkit 手口は実装しません*
(防御目的でも透明な実装が無く、製品自身が脅威になるため)。「終了されにくさ」も「クラッシュからの
自動復帰」も OS 公認の保護(Linux systemd ハードニング+`chattr +i`・Windows サービス ACL+PPL/ELAM・
macOS System Extension)で得ます。設定手順は **[docs/hardening.md](docs/hardening.md)**。

**APT(国家支援型など)想定**: 高度な攻撃者は WAF と戦わず *迂回*(再ルーティング/直叩き)や
下層(インフラ/BGP/DNS/ランタイム/OS)を狙います。DuckNet 側の対抗策(**オリジントークンで
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
- DuckNet-Lite は **GNU Affero General Public License v3.0 以降(AGPL-3.0-or-later)** の
  フリーソフトウェアです(商用ライセンス管理機能自体を含みません)。全文は
  [LICENSE.txt](LICENSE.txt) を参照。AGPL はネットワーク経由でも本製品(の改変版含む)を
  利用させる場合、利用者に対応するソースコードを提供する義務を伴います(第13条)。
  この義務を負わずに利用したい場合や、上位(商用)エディションが必要な場合はベンダーへ
  お問い合わせください。
- 第三者ソフトウェア表示: [THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt)
  （本製品は**同梱する第三者コードなし**＝依存ゼロ）
- 機械可読 SBOM(CycloneDX 1.5): [sbom.cdx.json](sbom.cdx.json)
  （再生成: `python tools/gen_sbom.py`）

## 開発(ベンダー向け)
- テスト(依存ゼロ): `python tests/run_all.py`
- パッケージ: `python -m build`(sdist + wheel)/ 検証 `python -m twine check dist/*`
- CI: `.github/workflows/ci.yml`(Linux 3.10–3.13 + Windows でテスト/ビルド)
