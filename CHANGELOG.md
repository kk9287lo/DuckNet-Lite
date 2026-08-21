# Changelog

本プロジェクトの主要な変更点。日付は概ねの目安。詳細は各コミット(`evolution #N`)を参照。

## [Lite-3] — 第3次縮小: 自己防衛の watchdog/親プロセス監督を削除

free / trial ティアから、常駐サービス層の *自動復旧*(auto-recovery/self-healing)機構を削除。
状態ファイルの HMAC 署名(#52–#54)・in-memory cfg 改竄検知(#85)・迂回検知(#78)は**無関係な
別機構のため維持**——落ちた/ハングした前衛スレッドを自前で検知・強制再起動する層だけを外す。

- **削除**:
  - **常駐内 Watchdog** — `AsyncEdgeGuard.serve_forever()`(`engine/services/proxy.py`)から
    Watchdog(生存監視・ハング検出・強制再起動・OSスリープ吸収)の配線を除去。`serve_forever()`
    は「起動して `is_alive()` を見張り、スレッドが死んだらプロセスごと終了する」だけの元の
    素朴な形に戻した。ハートビート専用の周期タスク(`_heartbeat_loop`/`heartbeat()`)、
    suspend 通知(`_absorb_suspend`)、watchdog 周期タスク閉包(`_make_period_tick`)を削除。
    `is_alive()`/`restart()` は基本のスレッド状態操作として維持(手動/テストから直接使用可)。
  - **`engine/core/resilience.py` を削除** — `Watchdog`/`Supervisor`/`measure_skew`/`assess`/
    `backoff_delay`/`restart_decision` 一式。他モジュールからの参照なし(watchdog/supervisor
    以外の用途では未使用だったため丸ごと削除可能と確認)。
  - **親プロセス監督 `--supervise`** — `dataplane/service.py` の CLI フラグと、`Supervisor` を
    起動するディスパッチ分岐を削除。クラッシュからの自動再起動は OS 層(systemd `Restart=`/
    Windows サービス回復/launchd `KeepAlive`)にのみ委ねる。
  - `engine/core/autostart.py` の `build_command()`/`install()` から `supervise` 引数を削除
    (自動起動登録コマンドに `--supervise` を付与しなくなった)。OS レベルの自動起動登録
    (ログオン/ブート時の再起動)自体は変更なし。
  - **迂回検知(#78)/cfg 改竄検知(#85)の呼び出し口を独立**: 従来 watchdog の周期タスクに
    便乗していた `traffic_stall_check()`/`verify_cfg_integrity()` の定期実行を、watchdog とは
    無関係な独立の軽量ループ(`AsyncEdgeGuard._periodic_checks_loop`)へ切り離した。どちらも
    自動復旧とは別物のセキュリティ機能のため、機能自体は維持。
- **削除(テスト)**: `tests/test_resilience.py` を削除(Watchdog/Supervisor/skew/heartbeat/
  restart_decision 等、resilience.py 一式のテスト)。`tests/test_autostart.py` の
  `test_build_command_adds_supervise` を `--supervise` を付与しないことを確認するテストへ
  差し替え。`tests/run_all.py` の MODULES から `test_resilience` を除去。`test_stall.py`/
  `test_memtamper.py`(迂回検知/cfg改竄検知の直接テスト)は無関係な独立機能のため変更なし。
- ドキュメント: README/CHANGELOG/docs/hardening.md/docs/options.md/docs/defenses.md/
  docs/apt-threat-model.md から `--supervise`/watchdog の記述を除去し、クラッシュ復旧は
  OS 層の責務であることを明記。`NEXT_STEPS.md` を ChickenNet-Lite の現状に合わせて全面刷新
  (商用版前提の古い引き継ぎメモを置き換え)。
- コード品質: `engine/lifeform/pipeline.py` の `inspect()` に残っていたカナリアトークン
  照合の死コード(`canary.py` は第1次縮小で既に削除済み・常に except 分岐に落ちるだけの無害な
  残骸)を除去。シグネチャ走査(`sig_hit`)ロジックは変更なし。
- テスト: **348/348 件緑**(372 件から Watchdog/Supervisor 関連 24 件を削除)。

## [Lite-2] — 第2次縮小: コアの L7 WAF/DDoS + 最小限の可視化のみへ

free / trial ティアを **さらに** 絞り込み、コアの L7 WAF/DDoS リバースプロキシ・エンジン
(スコアリング/自動BAN/PoWチャレンジ/シグネチャ照合)+ それを操作する最小限の Web 管理
ダッシュボード(ON/OFF・基本指標・BAN管理)だけを残した。**依存ゼロ**は維持。

- **削除(価値付加機能・上位エディションのみ)**:
  - **DNS フィルタ(L7検知)** — `engine/lifeform/dns.py`。`dns` サブコマンド・
    `chickennet-dns` Docker サービス・`docs/dns.md` を削除。
  - **囮ファイルのダウンロード追跡(ビーコン)** — `engine/lifeform/datasets.py`
    (参照トークン台帳)。`/c/<token>.png` ビーコン経路・`/api/ledger` を削除。
  - **SIEM/Webhook 転送** — `engine/lifeform/forwarders.py`(Syslog/Webhook Fanout)・
    `engine/lifeform/alerts.py`(AlertSink。datasets.py 以外に利用者がいないため同時削除)。
    `pipeline.py`/`proxy.py`/`service.py` の転送配線(`_forward`/`_txn` の SIEM 経路)を除去。
    ローカルの改竄可視化(`/api/shield/tamper`)自体は維持。
  - **構造化トランザクションログ** — `engine/services/txnlog.py`。`txnlog_enabled`/
    `txnlog_forward` cfg・`proxy.py` の `_txn()` 記録経路・ダッシュボードのトグルを削除。
  - **自己完全性監視 + 自動修復** — `engine/core/integrity.py`(`SelfIntegrity`)。
    `--integrity-baseline`/`--integrity-check` CLI フラグと watchdog 周期タイマーへの
    配線を削除。in-memory cfg 改竄検知(`verify_cfg_integrity`・#85)と状態ファイルの
    HMAC 署名(#52–#54)は **無関係な別機構のため維持**。
  - **GeoIP 国別判定** — `engine/lifeform/geoip.py`。`geo_mode=country_allow/country_block`・
    `geo_countries` cfg・国別テレメトリ(`country_hits`)を削除。CIDR ベースの `geo_mode=allow/block`
    は維持。
  - **正のセキュリティモデル(allowlist)** — `engine/lifeform/posmodel.py`。`NetShield.__init__`
    で無条件生成されていたハード依存(`self._posmodel`)・`inspect()` ホットパスの照合・
    `reload_posmodel`/`set_posmodel`/`posmodel_status`・`/api/shield/posmodel` を除去。
  - **ステルス運用(プロセス名偽装)** — `dataplane/profile.py` を削除。`--stealth` CLI フラグと
    `service.py`(`run()`)の cover 変数配線を除去。`proxy.py`/`edge_config.py` の
    `profile.cover_thread_name`/`cover_brand` 呼び出しは固定文字列に置換(機能自体は
    `CHICKENNET_COVER` 環境変数を直接参照するブランド表示のみ残置=後方互換)。
- **維持(意図的)**: `--supervise`(Watchdog/Supervisor)、`--install-autostart`/
  `--uninstall-autostart`、`--cluster`(マルチコア待受)、`atomic_io`/`signed_state`
  (状態永続化の署名整合性)、`origin.py`(バックエンド・バイパス防止)、`accel.py`、`i18n.py`。
  これらは基本的な信頼性/正当性であり、削ぎ落とす「付加価値機能」ではないと判断。
- 管理ダッシュボードから該当パネル/API(DNS検知欄・参照トークン台帳欄・国別内訳・
  トランザクションログ トグル・`/api/detections`・`/api/ledger`・`/api/shield/posmodel`)を除去。
  ON/OFF・基本 BAN 管理・基本指標は維持(完全な blackbox 化はしない)。
- ドキュメント: `docs/dns.md` を削除。README/options.md/defenses.md/hardening.md/
  apt-threat-model.md から該当節を整理。`pyproject.toml` の `geoip` optional-dependency
  (未使用の `maxminddb` extra)と SBOM/第三者表示を同期。
- テスト: `test_dns.py`/`test_ops.py`/`test_alertflood.py`/`test_datasets.py`/
  `test_txnlog.py`/`test_integrity.py`/`test_posmodel.py`/`test_profile.py` を削除、
  `test_core.py`/`test_hardening.py`/`test_saferegex.py`/`test_memtamper.py`/
  `test_signed_state.py` から該当ケースを整理。**372/372 件緑**。

## [Lite] — ChickenNet-Lite(free / trial エディション)分岐

上位(商用)エディションから、コアの L7 WAF/DDoS リバースプロキシ・ゲートウェイ + 最小限の
管理ダッシュボード + DNS フィルタだけを残した無償/試用ティアを切り出し。**依存ゼロ**は維持。

- **含まれる**: スコアリング/BAN/チャレンジ・エンジン、正のセキュリティモデル(allowlist)、
  GeoIP、Web 管理ダッシュボード、DNS フィルタ(L7検知)、囮ファイルのダウンロード追跡
  (ビーコン・`/api/ledger`)、SIEM/Webhook 転送、自己完全性監視、署名付き状態永続化。
- **削除(上位エディションのみ)**: デスクトップ GUI(`dataplane/gui`)、カナリアトークン
  (`engine/lifeform/canary.py`)、LDAP/SMB/Kerberos の横展開デコイ(`engine/lifeform/listeners.py`)、
  LDAP 列挙検知プロキシ(`engine/lifeform/ldap_proxy.py`、自作 BER パーサ `ber.py` を含む)、
  脅威インテリジェンス(IoC)照合(`engine/lifeform/intel.py`)、MITRE ATT&CK 対応の脅威検知
  コンテンツ配備(`engine/lifeform/content.py`)、クラスタ間の分散BAN同期(gossip・
  `engine/services/gossip.py`)、商用ライセンス管理(`dataplane/enterprise`)。
- 対応する CLI サブコマンド(`gui` / `canary` / `decoy` / `ldap-proxy` / `content`)と
  ライセンス関連の起動フラグ・env は同時に削除。`dns` サブコマンドと本体ゲートウェイは変更なし。
- 管理ダッシュボードから該当機能の UI/API(`/api/gossip`、`/api/shield/intel_reload` 等)を除去。
- ドキュメント: `docs/listeners.md` / `docs/ldap-proxy.md` / `docs/content.md` /
  `LICENSING.md` / `RELEASING.md` を削除し、README/options.md/defenses.md から該当節を整理。

## [1.3.0] — 脅威検知コンテンツ(ATT&CK / Detection-as-Code)+ SOC テーマ

検知を「コンテンツ」として管理・配備する層と、SOC 風の UI テーマを追加。すべて **依存ゼロ**・
後方互換・テスト付き(**579 件緑**)。

- **脅威検知コンテンツ `engine/lifeform/content.py`**: 組込検知を MITRE ATT&CK 技術 / 深刻度 /
  分類 / 参照つきの可搬ルールとして列挙(`catalog`)。`attack_coverage` / `search` / `stats`。
- **可搬変換(Uncoder 相当・自前実装)**: 1ルールを **Sigma / ModSecurity / Suricata / nginx / JSON**
  へ翻訳して他 SIEM/WAF/IDS へ配備可能(`export`)。可搬 JSON の取り込み(`import_rules`)。
  出力する正規表現も ReDoS lint を通る(配備先の自己 DoS を防ぐ)。
- **CLI `python -m dataplane content`**: `list` / `stats` / `coverage` / `export -f <fmt>`。
- **GUI「脅威コンテンツ」タブ**: ATT&CK 対応カタログの閲覧・検索と、形式選択での配備出力。
- **サイバーテーマ(SOC 風)**: 深紺 + ネオンのシアン/バイオレット。ヘッダにグラデーション帯。
  テーマは 自動 / ダーク / ライト / **サイバー** から選択可。
- 詳細は [docs/content.md](../docs/content.md)。

### 監査強化(極限レビューへの追加対応)
- **接続レート上限 `conn_rate_per_ip`**(既定 0=無効・ロックダウンで自動 50/s): 接続→即RST を
  高速反復する churn フラッドを head 解析や backend 接続より手前で安価に shed(CPython/asyncio の
  接続生成コストへの頭打ち)。
- **セキュリティ比較の bytes 化**: 管理 API トークン・GUI ロック・cfg-MAC の照合を `bytes` での
  `hmac.compare_digest` に統一(非ASCII入力での TypeError と長さ依存タイミングの懸念を排除)。
- **奇形入力の堅牢性をテストで担保**: 乱バイト/未エンコ多byte URI/巨大ヘッダ/0x プレフィクス
  chunk への framing 判定が例外を出さないこと、SMB/LDAP の 0xFFFFFFFF 長フィールドでも分類器が
  クラッシュ/情報漏洩しないこと(Python のスライス安全性)を回帰テスト化。バイト透過 +
  `force_conn_close` によりチャンク・トレーラ経由のデシンクは構造的に不成立。

## [1.2.0] — 耐 APT 監査強化 + デスクトップ GUI(完成版)

1.1.0 を土台に、国家背景クラスの監査(レッドチーム視点)で洗い出した構造的弱点を塞ぎ、
プロ仕様のデスクトップ・コントロールパネルを追加。すべて **依存ゼロ(標準ライブラリのみ)**・
後方互換・テスト付き(**570 件緑**)。

### 耐性強化(極限監査への対応)
- **ReDoS 耐性ライブラリ `engine/core/saferegex.py`**: 危険パターン(ネスト量化子)を *載せる前に*
  lint で拒否、走査前に入力長を上限化、線形時間の Aho-Corasick リテラル照合。`validate_pattern`/
  DNS 規則/シグネチャ照合に差し込み。組込シグネチャ全てが lint を通過(WAF の自己 DoS を防ぐ)。
- **JSON 再帰爆弾**対策: `safe_json_loads`(深さ・サイズで事前足切り)を GraphQL 本文・管理 API へ。
- **状態ファイルのロールバック耐性**: 署名エンベロープに単調バージョン `_ver`(署名対象)+ 高水位
  サイドカー `.hw` を追加。古い正署名ファイルへの巻き戻しを `rolled_back` として拒否。
- **slow-read / TCP zero-window 兵糧攻め**対策: 応答転送の `drain` を全て期限付きにし、滞留時は
  両端(クライアント/バックエンド)を強制解放(バックエンド道連れの阻止)。
- **SIEM アラート洪水 / 盲目化**対策: 転送を容量固定 drop-oldest キュー + レート配分 + 失敗バックオフ化。
  取りこぼし時は「N 件抑制」のメタアラートを必ず送り、*静かな盲目化* を防ぐ。
- **HTTP リクエストスマグリング**の回帰テスト整備(CL.TE/TE.TE/裸LF/obs-fold/非 origin 等の拒否)。
- **IPv4-mapped IPv6 正規化**(`::ffff:` を純 IPv4 化)= dual-stack 束縛時の BAN すり抜けを阻止。
- **DNS UDP 応答レート制限(RRL)** = 送信元詐称による反射増幅の踏み台化を防止。
- **誤検知(誤 BAN)低減**: 要求ボディ由来シグネチャのスコア係数 `body_sig_weight_factor`(既定 0.7)。
- 定数時間比較・例外フレーム非保持・解凍出力上限・gossip のタイムスタンプ署名+鮮度窓+リプレイ
  キャッシュ等を監査で確認。

### デスクトップ GUI(コントロールパネル)
- **角丸カード/ボタンのプロ向け UI**(Canvas 自作・依存ゼロ)。ダッシュボード(KPI・トラフィック
  構成バー・スループット折れ線・稼働時間)、簡易/詳細設定、クレジット、スプラッシュ。
- **ライト/ダーク 2 テーマ**(`auto`=Windows 追随 / 手動)+ **日本語/英語の即時切替**(設定は保存)。
- **おすすめプリセット 10 種**(監視のみ〜ロックダウン、レベル順・誤 BAN 安全側)。
- **各設定項目のホバー説明(ツールチップ)**・設定の **検索/フィルタ**・マウスホイールスクロール。
- **システムトレイ常駐・グローバルホットキー召喚**(ステルス/通常で個別 ON/OFF)・**設定変更パスワード
  ロック(pbkdf2)**・**単一インスタンスガード**(二重起動は既存窓を前面化)。
- **ダブルクリック起動ランチャ**: `ChickenNet.bat` / `ChickenNet.ps1`(Windows・pythonw)/
  `ChickenNet.command`(macOS)/ `ChickenNet.sh`(Linux)。アイコンは差し替え可能な `ico/` フォルダから。

### 運用 / その他
- **ステルス強化**: GUI タイトル/ヘッダ/スプラッシュ/生成設定コメントも `CHICKENNET_COVER` に追従。
- **ビルド後の自動クリーンアップ**(`tools/clean.py`・テスト実行で自動)。
- 環境変数 / 設定キーの一覧は **[docs/options.md](docs/options.md)**。

## [1.1.0] — 防御カバレッジ拡張 + 自己防衛

1.0.0 を土台に、双方向(リクエスト/レスポンス)の検査・認証層・DoS 耐性・自己防衛を大幅に拡張。
すべて **依存ゼロ(標準ライブラリのみ)**・後方互換・テスト付き(491 件緑)。

### 新しい防御(リクエスト側)
- **要求ボディ検査**: POST/JSON/GraphQL 本文を有界・重複ウィンドウで署名走査(head-only の死角)。
  `Content-Encoding: gzip/deflate` は有界解凍してから走査(圧縮による回避封じ)。
- **ファイルアップロード検査**: multipart の危険拡張子(php/jsp/exe/sh 等)を拒否。二重拡張子・NUL 切りも捕捉。
- **正のセキュリティモデル**: 許可した (パス, メソッド) だけ通す allowlist(opt-in)。
- **GraphQL 防御**: 深さ/複雑度/イントロスペクション/バッチの上限(opt-in)。
- **JWT 検査**: `alg:none`(認証バイパス)/ 許可外 alg(alg 混同)を鍵無しで遮断。
- **メソッド/パスオーバーライド対策**: `X-HTTP-Method-Override`・`X-Original-URL` 等での ACL 回避を遮断。
- **クレデンシャル単位レート制限**: トークン/API キー識別子単位(IP ローテーション濫用対策・opt-in)。
- **ヘッダ整合性ボット検知**: ブラウザ UA を名乗るのにブラウザ標準ヘッダを欠くツールを低FP加点。
- **Range DoS(Apache Killer)対策**・**スロー POST(R-U-Dead-Yet)対策**。
- **HTTP リクエストスマグリング**強化(パイプライン第2要求の遮断)。

### 新しい防御(レスポンス側)
- **Set-Cookie ハードニング**(SameSite/Secure[TLS時]/HttpOnly)。
- **CORS 誤設定の無害化**(`ACAO:*`/`null` + 資格情報)。
- **オープンリダイレクト無害化**(外部許可外への 3xx を安全パスへ書換・opt-in)。
- **キャッシュ汚染ヘッダ除去**(非信頼クライアントの `X-Forwarded-Host` 等)。

### 応答アウェア / 可視化
- **応答エラーレート検知**: 4xx 連射(列挙/ブルートフォース)を脅威スコアへ還元。
- **改竄イベントの SIEM 転送 + ダッシュボード**(`/api/shield/tamper`)。

### 対 APT(迂回・下層攻撃への射程内対抗策)
- **バックエンド・バイパス防止**(オリジントークン): エッジ経由を証明する時間有界 HMAC を付与し、
  backend が無トークン(=迂回直叩き/再ルーティング)を拒否。
- **迂回の能動検知**(dead-man's switch): トラフィックが busy→突然ゼロ になったら警報。
- **グローバル同時接続上限** + FD ソフト上限引き上げ(資源枯渇のロードシェッド)。
- 配備ガイド [docs/apt-threat-model.md](docs/apt-threat-model.md)(WAF 外の層=RPKI/DNSSEC/IAM/cgroup の
  責任分担 + 外部鍵運用を4フェーズに対応づけ)。**線引き**: ハイパーバイザ全権・BGP/DNS・CPython
  ゼロデイは WAF では原理的に防げない=多層防御で正しい層に装備する、と明記。

### 自己防衛 / レジリエンス(正当・透明な範囲のみ)
- **watchdog**: 生存監視・ハング/死亡時の強制再起動・**一時停止(OSスリープ等)からの安定復帰**。
- **親プロセス監督**(`--supervise`)・**起動時自動起動の登録**(`--install-autostart`、公認の場所のみ)。
- **ファイルすり替え検知 + 強制修復**(署名付きマニフェスト・バックアップ多重化・`--integrity-baseline`)。
- **可変状態の HMAC 署名**(BAN/署名/設定/テレメトリ/IoC の改竄耐性・移行マーカー)。
- watchdog の周期ランダム化。配備ハードニング手順 [docs/hardening.md](docs/hardening.md)。
- **線引き**: プロセス隠蔽・終了妨害・隠れ起動等の rootkit 手法は実装しない(透明な OS 公認保護のみ)。

### 修正・堅牢化
- 時刻巻き戻し(NTP補正)でのスコア膨張防止・eviction による BAN 回避の阻止・各種メモリ上限化・
  DLP 境界跨ぎ秘密の保留・スキャン面パディング回避の封じ込め 等(`evolution #36`〜)。

### 命名
- ファイル名は低プロファイル(保護露見名を避ける)。`graphql_guard.py` → `graphql.py`。

## [1.0.0] — 初版
L7 レート制限・侵入シグネチャ(SQLi/XSS/traversal/scanner 等)・脅威スコア・動的 PoW チャレンジ・
自動BAN/累犯エスカレーション・ハニーポット・カナリア・出口 DLP・脅威インテリジェンス(IoC)・
応答セキュリティヘッダ注入・サブネット集約防御・Web 管理ダッシュボード・SIEM 転送・
DNS/LDAP/デコイの補助検知・宣言的設定・graceful shutdown・クラスタ待受。依存ゼロ。
