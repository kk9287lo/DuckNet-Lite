# DuckNet-Lite — 次にやること(引き継ぎメモ)

このリポジトリ(`D:\DuckNet-Lite`)は **DuckNet L7 Security の free / trial エディション**の
独立フォークです(防御エンジンは `dataplane/engine/` 配下に同梱、外部依存ゼロ)。上位(商用)
エディションから5回の縮小パスを経て、コアの L7 WAF/DDoS リバースプロキシ・エンジン + 最小限の
Web 管理ダッシュボードだけを残した構成になっています。詳細な削除履歴は
**[CHANGELOG.md](CHANGELOG.md)** の `[Lite]`/`[Lite-2]`/`[Lite-3]`/`[Lite-4]`/`[Lite-5]` を参照。
このメモは次セッション(あなた=Claude / 開発者)が最初に読む引き継ぎです。

## いまの状態(検証済み)

- 外部依存ゼロ(stdlib のみ、`pyproject.toml` の `dependencies = []`)。
- テスト **344/344 緑**(Lite-5 でハニーポット関連テストを3本削除・347→344。うち複数の
  無関係テスト(BANエスカレーション/サブネット集約/appeals/シャットダウン永続化)は、旧来
  ハニーポット命中を「決定論的に一発BANを誘発する」ための手段として流用していたため、
  `penalize(weight=block_score)` 直呼びへ置き換えて意図を維持):
  `python tests/run_all.py` または `pytest tests/`
  (`DUCKNET_OFFLINE=1` / `DUCKNET_STATE_DIR` に一時ディレクトリを指定して実行)。
- CLI: `python -m dataplane --backend HOST:PORT --listen 8443 --admin 8081` で起動。
  `--cluster`(全コア待受)・`--install-autostart`/`--uninstall-autostart`(OS 公認の場所への
  自動起動登録)は健在。**`--supervise`(親プロセス監督)は Lite-3 で削除済み** — クラッシュからの
  自動再起動は OS 側(systemd `Restart=`/Windows サービス回復/launchd `KeepAlive`)に委ねる方針
  (手順は [docs/hardening.md](docs/hardening.md))。
- CI: `.github/workflows/ci.yml`(存在するが、この作業ツリーはまだ最初の `init` コミットのみ=
  3回分の縮小差分は**未コミット**。ユーザーがレビューの上コミットする予定)。
- Docker: `Dockerfile`/`docker-compose.yml` は同梱済みだが、この環境での実ビルド確認は未実施。

## 含まれる機能(現状のスコープ)

- L7 リバースプロキシ・ゲートウェイ: スコアリング/自動BAN/侵入シグネチャ照合
  (SQLi/XSS/RCE/traversal/XXE/SSRF/JNDI 等)、要求ボディ/アップロード検査、応答側の
  Cookie/CORS/DLP/オープンリダイレクト無害化、JWT・クレデンシャルレート・スマグリング対策等。
  スコア閾値は2段階(`deny_score`=単発拒否・BANなし / `block_score`=自動BAN)のみ。
- Web 管理ダッシュボード: ON/OFF・指標・BAN管理・基本設定(トークン認証)。
- 状態永続化: BAN/設定の HMAC 署名(改竄耐性)、宣言的設定ブートストラップ(JSON/ConfigMap)。
- 自動起動登録(`--install-autostart`): Windows タスクスケジューラ/Run キー、systemd、launchd
  ——いずれも透明・公認の場所のみ(隠し永続化はしない)。
- CIDR ベースの `geo_mode=allow/block`、迂回検知(#78)、オリジントークンによる
  バックエンド・バイパス防止(#77)。

網羅的な一覧・設定キー・既定値は **[docs/defenses.md](docs/defenses.md)** と
**[docs/options.md](docs/options.md)** を参照(README の記述と唯一の真実=
`NetShield._DEFAULTS` が食い違ったらコードを正とする)。

## 含まれない機能(上位/商用エディションのみ・意図的に除外)

4回の縮小パスで以下を削除済み(詳細は CHANGELOG の該当エントリ):
- デスクトップ GUI、カナリアトークン、LDAP/SMB/Kerberos デコイ、LDAP 列挙検知プロキシ、
  脅威インテリジェンス(IoC)照合、MITRE ATT&CK 検知コンテンツ配備、クラスタ間分散BAN同期
  (gossip)、商用ライセンス管理 — `[Lite]`。
- DNS フィルタ(L7検知)、囮ファイル・ビーコン追跡、SIEM/Webhook 転送、構造化トランザクション
  ログ、自己完全性監視(ファイルすり替え検知+自動修復)、GeoIP 国別判定、正のセキュリティモデル
  (allowlist)、ステルス運用(プロセス名偽装) — `[Lite-2]`。
- 常駐内 watchdog による自動再起動・親プロセス監督(`--supervise`) — `[Lite-3]`。
  in-memory cfg 改竄検知(#85)・迂回検知(#78)・状態の HMAC 署名は無関係な別機構のため維持。
- PoW(Proof-of-Work)チャレンジ段・Under Attack モード(手動/自動)— `[Lite-4]`。
  スコアが `challenge_score` 以上の帯は `block`(単発拒否・BANなし・新設 `deny_score`)へ統合し、
  中間の『チャレンジで通す』余地は無くした(=フェイルセーフ側に倒す。詳細は CHANGELOG)。
  `under_attack`/`auto_under_attack` はこの PoW ゲートを開閉するためだけの仕組みだったため、
  ゲートごと削除(既定ONの `auto_under_attack` を「block」側へ丸ごと倒すと、通常のトラフィック
  急増だけで全公開トラフィックを自動BANしてしまう=フリー/トライアル層の自爆リスクの方が大きいと
  判断し、こちらは単純撤去を選んだ)。
- ハニーポット(囮URLパス。`add_honeypot`/`remove_honeypot`/`honeypots` cfg キー・命中即時BAN)
  — `[Lite-5]`(今回)。管理API `/api/shield/honeypot` とダッシュボードの追加フォームも削除
  (該当パスへの POST は他の未定義ルートと同様 404)。侵入シグネチャ/レート制限/脅威スコア等
  他の検知系はすべて無関係な別機構のため一切変更なし。

## 未検証 / 次にやること(正直な但し書き)

- **実際の PyPI / Docker Hub 公開は未実施**(このフォーク向けの公開パイプラインが要るかどうかも
  未決定=上位エディションと別ブランドで出すのか、free/trial 明記のまま同名で出すのか要判断)。
- **この作業ツリーの git コミット**: 3回分の縮小差分が未コミット(ユーザーがレビュー後に自分で
  コミットする方針。エージェントは実行しない)。
- **Docker の実ビルド確認は未実施**(この環境に docker 無し)。`docker build .` での動作確認と、
  `--supervise` 依存が無いこと(entrypoint/CMD に古いフラグが残っていないか)の再確認を推奨。
- ~~LICENSE.txt はテンプレート文言のまま~~ → 解消済み: LICENSE.txt を GNU AGPL-3.0-or-later
  の正式全文に差し替え、pyproject.toml のライセンス分類子・THIRD_PARTY_NOTICES.txt・
  sbom.cdx.json(`tools/gen_sbom.py` 側も)・README.md のライセンス節を整合させた。

## 設計の鉄則(踏襲)

- **外部依存ゼロ**を死守(`pyproject.toml` の `dependencies = []` を崩さない)。
- 誇張語を使わない。適用範囲(L7 のみ・L3/L4 ボリューメトリック攻撃は対象外)を常に明示。
- 防御専用(反撃しない・OS 非侵襲)。プロセス隠蔽・taskkill 妨害等の rootkit 手口は実装しない。
- クラッシュからの自動再起動は OS 公認の仕組みに委ねる(アプリ自身に watchdog/親監督を持たない)。
