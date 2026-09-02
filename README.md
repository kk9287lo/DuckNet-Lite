# DuckNet-Lite — 軽量 DDoS / WAF セキュリティゲートウェイ(無償版・AGPL)

Web サーバの手前に置くだけで、L7(アプリ層)の DDoS と侵入(WAF)を止めます。
外部依存ゼロ(Python 標準ライブラリのみ)、OS 非侵襲、防御専用。
対応するのは L7 だけで、L3/L4 は範囲外です。詳しくは末尾の「対応範囲について」を必ず読んでください。

DuckNet-Lite は DuckNet L7 Security の無償エディション(AGPL)です。含まれるのはコアの L7 WAF/DDoS リバースプロキシ・
エンジンだけ——スコアリング/自動 BAN と侵入シグネチャ照合を備えたリバースプロキシ型ゲートウェイ、それを操作する
最小限の Web 管理ダッシュボード(ON/OFF・指標・BAN 管理・基本設定)、署名付きの状態永続化です。Lite はこのコアだけで
実運用に耐える防御になります。次の領域が、上位(商用)エディションの DuckNet L7 Security で加わります。

- 可用性: ファイルの改竄を自己完全性監視で検知・自動修復し、プロセスが落ちても watchdog が自動再起動し、
  親プロセス監督(`--supervise`)で立て直します。無人運用でも稼働を維持できます。
- ボットとの選別: 動的 PoW(Proof-of-Work)チャレンジで、正規ユーザーを通しながら自動化された攻撃だけを絞り込みます
  (Lite は deny_score 以上の単発拒否 / block_score 以上の自動 BAN という二値判定のみ)。GeoIP・正のセキュリティモデル
  (allowlist)・ステルス運用(プロセス名偽装)によるアクセス制御も加わります。
- 侵入後の検知: LDAP/SMB/Kerberos の横展開デコイ、囮ファイルのダウンロード追跡(ビーコン)、カナリアトークン、
  ハニーポット(囮 URL パス命中の即時 BAN)で、境界を突破された後の不審な動きも捉えます。DNS フィルタ(L7 検知)は
  C2 通信やトンネリングを見つけます。
- 運用への統合: 検知結果を SIEM や Slack へリアルタイム転送(Webhook/Syslog)。脅威インテリジェンス(IoC)照合と
  MITRE ATT&CK 対応のルールで、既知の攻撃手口を継続的にカバーします。
- 複数拠点・大規模環境: LDAP 列挙検知プロキシと、ノード間で BAN 情報を同期する分散ゴシップにより、組織全体で一貫した
  防御になります(商用ライセンス管理つき)。

## これは何か
[攻撃] → DuckNet L7 Security(前衛) → あなたの Web サーバ(WordPress / API など)

前衛でやること:

- レート制限、侵入シグネチャ(SQLi/XSS/RCE/traversal/XXE/SSRF/JNDI/scanner など)、脅威スコア、自動 BAN。
- 双方向の検査。リクエストは head に加えてボディ(POST/JSON/GraphQL・gzip 解凍込み)とアップロードまで、
  応答側は DLP・セキュリティヘッダ・Cookie/CORS/リダイレクトの無害化。
- 認証まわりの濫用対策。JWT 検査(`alg:none`/alg 混同)、クレデンシャル単位のレート、スマグリング/オーバーライド/
  キャッシュ汚染/Range DoS への対処。
- 不正な接続はその場で TCP 切断(fail fast)。正規のアクセスだけを後ろへ通します。
- 状態の整合性。可変状態(BAN/署名/設定)の HMAC 署名による改竄耐性(後述の「配備ハードニング」)。
- Web 管理ダッシュボードから ON/OFF・攻撃グラフ・BAN 管理・設定をクリックで操作。

防御の一覧・設定キー・既定値(ON か opt-in か)は [docs/defenses.md](docs/defenses.md)、変更履歴は
[CHANGELOG.md](CHANGELOG.md)。高度な防御の多くは既定 OFF の opt-in で、誤検知を避けつつ必要な配備でだけ
有効にできます。ダッシュボード各パネルの使い方は [docs/dashboard.md](docs/dashboard.md)(画面右上の ❓ からも
同じ早見表とフル版との機能差分を開けます)。

## クイックスタート
```bash
# そのまま(Python 3.10+。依存インストール不要)
python -m dataplane --backend 127.0.0.1:8080 --listen 8443 --admin 8081
#   → 前衛: 0.0.0.0:8443  管理画面: http://127.0.0.1:8081 (トークンは起動時に表示)

# Docker(軽量イメージ)
docker compose up -d                       # ゲートウェイ(前衛 + 管理画面)
```

企業向けに、起動ランチャも同梱しています(任意)。Python の自動検出(venv 優先)、バージョン確認、UTF-8 化、
設定ファイルの読込をまとめたラッパで、引数はそのまま渡せます。
```bash
./run.sh                         # Linux / macOS
run.bat                          # Windows (cmd) — ダブルクリックでも可
.\run.ps1 --admin 8081           # Windows (PowerShell)
```
設定は `app.env`(`app.env.example` を参照。機密を含みうるのでリポジトリにはコミットしない)。使う Python は
`DUCKNET_PYTHON` で明示できます。

全オプション(環境変数 / 設定キー)は [docs/options.md](docs/options.md)。

## 配備ハードニング(落とされない・改竄されない)
防御エージェントは、落とされたら終わりです。本機は可変状態(BAN/署名/設定)の HMAC 署名による改竄耐性と、
改竄のダッシュボード可視化を内蔵します。クラッシュからの自動再起動は OS 公認の仕組み
(systemd `Restart=`/Windows サービス回復/launchd `KeepAlive`)に委ねます(アプリ自身は watchdog や親プロセス監督を
持ちません。依存ゼロのままシンプルに保つためです)。
```bash
export DUCKNET_STATE_KEY=...   # 外部署名鍵で状態の改竄耐性を一段上げる(推奨)
```
線引きも明確にしておきます。プロセス隠蔽・taskkill 妨害・別名での隠れ起動といった rootkit 手口は実装しません
(防御目的でも透明な実装が存在せず、製品自身が脅威になってしまうため)。「終了されにくさ」も「クラッシュからの
自動復帰」も、OS 公認の保護(Linux の systemd ハードニング + `chattr +i`、Windows のサービス ACL + PPL/ELAM、
macOS の System Extension)で得ます。設定手順は [docs/hardening.md](docs/hardening.md)。

APT(国家支援型など)を想定すると、高度な攻撃者は WAF と正面から戦わず、迂回(再ルーティング/直叩き)や
下層(インフラ/BGP/DNS/ランタイム/OS)を狙ってきます。DuckNet 側の対抗策(オリジントークンで迂回トラフィックを
backend に拒否させる、迂回を能動検知する、グローバル接続上限、外部鍵)と、WAF の外で運用者が備えるべき統制
(RPKI/DNSSEC/IAM/cgroup など)を 4 フェーズに対応づけた配備ガイドが [docs/apt-threat-model.md](docs/apt-threat-model.md) です。

## 対応範囲について(誇張はしません)
- これは L7(アプリ層)の防御です。サーバが受理した HTTP 要求を検査して弾きます。
- 回線や OS を飽和させる L3/L4 のボリューメトリック攻撃(UDP/SYN flood など)は本製品では止められません。
  そこはネットワーク層(Anycast / クラウドの DDoS 保護 / ISP)の領域です。
- 反撃はしません(防御専用)。OS のファイアウォール(WFP/iptables)にも触れません(非侵襲)。
- 大規模・全コア活用は Linux で `--cluster`(SO_REUSEPORT)。Windows などは単一プロセスに降格します。

## ライセンス / 調達情報
- DuckNet-Lite は GNU Affero General Public License v3.0 以降(AGPL-3.0-or-later)のフリーソフトウェアです
  (商用ライセンス管理機能自体は含みません)。全文は [LICENSE.txt](LICENSE.txt) を参照してください。AGPL は、
  ネットワーク経由でも本製品(の改変版を含む)を利用させる場合、利用者に対応するソースコードを提供する義務を伴います
  (第 13 条)。この義務を負わずに利用したい場合や、上位(商用)エディションが必要な場合はベンダーへお問い合わせください。
- 「無償」には別の入口もあります。フル版(DuckNet)には非商用・無償の Community 枠(全機能・キー不要)がありますが、
  そちらは商用(独占)ライセンスのため商用利用はできません。Lite は機能限定の代わりに AGPL なので、コピーレフト義務を
  受け入れれば商用でも無償で使えます。全機能を非商用で試すなら Community、商用でも無償で使うなら Lite が目安です。
- 第三者ソフトウェア表示: [THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt)
  (本製品は同梱する第三者コードなし＝依存ゼロ)
- 機械可読 SBOM(CycloneDX 1.5): [sbom.cdx.json](sbom.cdx.json)
  (再生成: `python tools/gen_sbom.py`)

## 開発(ベンダー向け)
- テスト(依存ゼロ): `python tests/run_all.py`
- パッケージ: `python -m build`(sdist + wheel)/ 検証 `python -m twine check dist/*`
- CI: `.github/workflows/ci.yml`(Linux 3.10–3.13 + Windows でテスト/ビルド)
