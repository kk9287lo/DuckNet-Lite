"""tests/run_all.py — DuckNet-Lite 全テスト(依存ゼロ・pytest不要)。

実行:
    python tests/run_all.py        # リポジトリ直下から
外部リポジトリには依存しない(バンドル内の vendored サブセットのみを使う)。
"""
from __future__ import annotations

import importlib
import os
import sys
import traceback
from unittest import SkipTest     # 環境依存テストの明示スキップ(標準ライブラリのみ)


def _force_utf8_stdio() -> None:
    """ランナー自身の出力を UTF-8 かつ行バッファへ(失敗しても無害に継続)。

    SKIP/FAIL の説明文は日本語なので、非 UTF-8 コンソール(英語版 Windows の cp1252
    や ASCII ロケール)では print した瞬間に UnicodeEncodeError で落ちる。しかも
    落ちる場所が結果表示なので、**要約行すら出ないまま exit 1** になり、
    「何が失敗したのか分からない」という最悪の壊れ方をする(実際 CI の
    windows-latest がこれで落ちていた)。
    製品側(dataplane.service)にも同じ処理があるが、ランナーは製品が壊れていても
    動けるべきなので import せずここで完結させる。"""
    for stream in (sys.stdout, sys.stderr):
        reconfig = getattr(stream, "reconfigure", None)
        if reconfig is None:
            continue
        try:
            reconfig(encoding="utf-8", errors="backslashreplace", line_buffering=True)
        except Exception:
            try:
                reconfig(encoding="utf-8", errors="backslashreplace")
            except Exception:
                pass


_force_utf8_stdio()

def _isolate_state_dir() -> str:
    """テストが **利用者の本物の状態ディレクトリ**(旧共用 ~/.cache/dataplane、
    現専用 ~/.cache/ducknet-lite の双方)に一切触れないよう、
    使い捨ての一時ディレクトリへ向ける。製品コードを import する *前* に行うこと。

    以前はこれが無く、テストを回すたびに実際の DuckNet の BAN リスト・管理監査ログ・
    使用量・ACL へ書き込んでいた(実測: 127.0.0.1 の BAN が実 blocklist.json へ入り、
    実 admin_audit.jsonl にはテストの操作が 1449 行溜まっていた)。さらに、そこに残った
    状態(acl.json の有効化)を次の実行が読み込み、テスト 3 件が決定的に落ちる、という
    *自己汚染* にもなっていた。この機で製品を実際に使っている利用者ほど壊れる。
    DUCKNET_KEEP_TEST_STATE=1 なら終了後も消さずに場所を表示する(調査用)。"""
    import atexit
    import shutil
    import tempfile
    d = tempfile.mkdtemp(prefix="ducknet-test-state-")
    os.environ["DUCKNET_STATE_DIR"] = d
    if os.environ.get("DUCKNET_KEEP_TEST_STATE") == "1":
        atexit.register(lambda: print("test state kept at: " + d))
    else:
        atexit.register(shutil.rmtree, d, True)
    return d


_TEST_STATE_DIR = _isolate_state_dir()

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _ROOT)   # dataplane / dataplane.engine を import 可能に
sys.path.insert(0, _HERE)   # test_*.py を import 可能に
os.environ["DUCKNET_OFFLINE"] = "1"

MODULES = [
    "test_gui_auth_modal", # masked unlock, retry and instance-bound signed HTTP
    "test_gui_auth_transport", # bounded responses, cancellation and session ownership
    "test_gui_operations", # ACL/policy/events and cluster-aware mutations
    "test_gui_editor_visualization", # structured drafts, safe tables and chart windows
    "test_gui_tray_workflow", # verified gateway, consented clipboard and status menu
    "test_gui_settings_schema", # every supported setting has typed bilingual dashboard metadata
    "test_gui_settings_editor", # advanced settings preserve drafts and commit atomically
    "test_security_admin_quiesce_preflight_round25", # invalid admin payload cannot stop healthy fork workers
    "test_security_explicit_env_file_round25", # explicit missing env file must not select default state
    "test_security_present_corrupt_tmp_round25", # corrupt main cannot recover stale signed tmp
    "test_security_response_status_commit_round25", # invalid backend head cannot score client
    "test_security_monitor_redact_round25", # log-safe URL must not echo nested or malformed secrets
    "test_security_posix_eacces_round24", # unreadable legacy state and BANs cannot look pristine
    "test_security_env_read_round24", # unreadable or oversized app.env must not select fallback state
    "test_security_early_backend_reject_round24", # early origin 413 must not be hidden by body replay
    "test_security_env_utf8_round24", # malformed app.env cannot redirect signed state home
    "test_security_body_probe_capacity_round24", # quota pressure scan is bounded across fork workers
    "test_security_admin_post_status_round24", # failed admin POST must not claim HTTP success
    "test_security_body_reclaim_round23", # killed fork worker cannot strand the live body budget
    "test_security_backend_halfclose_round23", # complete HTTP request must not look aborted to buffering backends
    "test_security_admin_nonce_round22", # full nonce cache cannot amplify each valid rejected MAC
    "test_security_body_atomic_round22", # malformed late request body cannot reach backend
    "test_security_admin_fragment_round21", # direct dashboard bootstrap drops legacy fragment token
    "test_security_state_lifecycle_round21", # explicit empty external state key cannot silently fall back
    "test_security_egress_dlp_round21", # high-confidence secret cannot hide inside an alnum wrapper
    "test_security_ingress_stream_round21", # failed header inspection cannot become a clean view
    "test_security_gui_url_fragment_round21", # tray browser drops legacy fragment credentials
    "test_security_state_namespace_round20", # ambiguous FalcoNet legacy state requires an explicit DuckNet home
    "test_security_windows_commit_lock_round20", # external signed commits cannot race a Windows backend write
    "test_security_ban_commit_barrier_round20", # BAN publication must obey the backend write barrier
    "test_security_traffic_commit_round20", # stale quota accounting cannot overwrite a newer signed window
    "test_security_usage_commit_round20", # stale telemetry cannot overwrite a newer signed usage snapshot
    "test_security_serving_lease_round20", # two servers cannot own one quota state at once
    "test_security_single_owner_round20", # a second listener must not share finite quota state
    "test_security_response_commit_round20", # signed policy ack cannot overtake client response bytes
    "test_security_noop_cluster_round20", # same-value admin requests must not needlessly stop fork workers
    "test_security_external_single_round20", # cluster-origin single owner observes external signed policy
    "test_security_body_response_barrier_round19", # incomplete uploads cannot release early backend responses
    "test_security_config_preflight_round19", # invalid cross-field config cannot quiesce workers
    "test_security_docker_context_round18", # no unrelated local backups reach build context or image
    "test_security_admin_rule_schema_round18", # typos cannot silently replace a live ACL rule
    "test_security_legacy_purpose_round18", # legacy signatures cannot be transplanted across state purposes
    "test_security_proxied_metric_round18", # backend write, not TCP connect, confirms proxied status
    "test_security_path_bucket_budget_round16", # aggregate path buckets cannot grow without limit
    "test_security_numeric_config_round16", # malformed numeric settings cannot poison scoring or deadlines
    "test_security_numeric_bounds_round16", # extreme Range/body settings cannot disable guards
    "test_security_cadence_config_round16", # invalid timing cannot disable cadence detection
    "test_security_cluster_telemetry_round16", # dashboard marks fork-local counters as parent-only
    "test_security_cluster_state_fallback_round16", # unshared worker state cannot claim global enforcement
    "test_security_subnet_capacity_round16", # hot subnet history survives table and per-subnet churn
    "test_security_cluster_parent_death_round16", # orphan fork workers stop before admitting or forwarding
    "test_security_edge_lua_lock_round16", # expired worker lock cannot strand or corrupt Lua ban generations
    "test_security_window_budget_round16", # aggregate timestamp windows fail closed at capacity
    "test_security_active_ip_eviction_round16", # active rate/score history survives IP churn
    "test_security_ip_state_capacity_round16", # full IP table preserves every live BAN and fails new admissions safely
    "test_security_credential_capacity_round16", # active credential window survives key churn
    "test_security_conn_rate_capacity_round16", # active connection-rate window survives IP churn
    "test_security_dlp_early_timeout_round16", # early wakeup cannot hide HTML DLP timeout audit
    "test_security_sec_headers_bool_round16", # direct header toggle rejects non-booleans before client wire changes
    "test_security_penalize_weight_round16", # invalid direct penalty cannot poison score comparisons
    "test_security_score_config_round16", # negative signed scoring cannot cancel threat signals
    "test_security_score_halflife_round16", # invalid decay cannot erase repeated attack scores
    "test_security_ban_args_round16", # direct BAN API rejects coercions before durable mutation
    "test_security_shared_cluster_round16", # worker rate and BAN decisions must share one enforcement state
    "test_security_suspend_gap_round16", # nonfinite sleep gap must not make a finite BAN permanent
    "test_security_gui_stale_round16", # failed refresh makes stale controls inert until verified recovery
    "test_security_admin_disabled_integrity_round16", # disabled Shield still reports signed corruption
    "test_security_cluster_forward_barrier_round16", # signed policy commits cannot overtake backend request writes
    "test_security_edge_export_cluster_round16", # cluster export refuses incomplete parent-only BAN snapshot
    "test_security_unban_atomic_round16", # failed durable unban cannot release live BAN
    "test_security_cluster_direct_setter_round15", # fork workers must see direct parent policy updates
    "test_security_acl_first_save_round15", # marker-only first save must not strand fork workers
    "test_security_cluster_reload_round15", # verified reload preserves ACL work and catches signed tamper
    "test_security_cfg_recovery_round15", # partial signed config cannot restore shield OFF after memory tamper
    "test_security_admin_integrity_status_round15", # signed defense failure cannot paint a healthy dashboard
    "test_security_health_signed_state_round14", # signed-state fail-closed cannot advertise healthy
    "test_security_compose_plaintext_round14", # bundled plain-HTTP edge binds host loopback
    "test_security_cluster_round14", # cluster quota and admin changes cannot bypass forked workers
    "test_security_quota_config_round14", # invalid quota caps cannot silently disable enforcement
    "test_security_redirect_failclosed_round14", # redirect policy errors cannot release unsafe head
    "test_security_forwarding_failclosed_round14", # configured request defenses fail closed before backend
    "test_security_drain_grace_round14", # invalid grace cannot turn shutdown into an unbounded wait
    "test_security_admin_audit_unavailable_round14", # audit read/corrupt tail cannot paint healthy empty history
    "test_security_health_readiness_round14", # unavailable mandatory defense cannot advertise healthy
    "test_security_health_framing_round14", # health 200 follows strict HTTP syntax rejection
    "test_security_admin_list_outage_round13", # failed list sources must not display empty healthy panels
    "test_security_response_quota_round13", # in-flight byte/time quotas bound real response wires
    "test_security_override_cgi_round13", # CGI aliases of method/path overrides cannot skip edge policy
    "test_security_audit_torn_tail_round13", # failed JSONL rollback cannot make a later append look successful
    "test_security_edge_export_tamper_round13", # untrusted signed sources cannot erase edge bans
    "test_security_admin_gui_status_round13", # partial status failure never paints healthy/off GUI
    "test_security_untrusted_ban_result_round12", # failed BAN save cannot report success
    "test_security_custom_state_tamper_round12", # signed config/rules loss cannot reopen backend
    "test_security_header_underscore_round12", # CGI/WSGI aliases cannot revive protected request fields
    "test_security_edit_list_input_round12", # direct list edits validate one item and persist atomically
    "test_security_unknown_config_round12", # unknown keys reject the whole config patch
    "test_security_unmarked_wide_dlp_round12", # detect wide credentials throughout the response stream
    "test_security_response_obs_value_round12", # reject downstream header whitespace ambiguity
    "test_security_corrupt_highwater_round12", # invalid signed history cannot downgrade saved state
    "test_security_ban_tamper_failclosed_round12", # untrusted signed BAN state denies backend admission
    "test_security_quota_tamper_failclosed_round12", # untrusted quota history cannot reset limits
    "test_security_windows_extension_alias_round11", # Win32 file aliases in all path policies
    "test_security_multidecode_path_round11", # protect each 0..5 decode stage and delimiter view
    "test_security_scan_cpu_round11", # preserve signatures/Unicode while bounding scan CPU
    "test_security_encoded_delimiter_path_round11", # decode-first query/fragment route views
    "test_security_state_lock_deadline_round11", # bound signed-state lock acquisition
    "test_security_partial_response_dlp_round11", # reject unscannable partial egress representations
    "test_security_ipv6_site_policy_round10", # site policy checks bracketed IPv6 Host
    "test_security_response_filename_dlp_round10", # DLP scans decoded response filenames
    "test_security_log_rotation_cap_round10", # blocked rotation cannot exceed audit log cap
    "test_security_service_start_cleanup_round9", # admin startup failure reaps the edge listener
    "test_security_response_head_percent_dlp_round9", # inspect percent-decoded URL response metadata
    "test_admin_readiness_slot_round8", # wait until startup probe releases its handler slot
    "test_security_script_style_dlp_round8", # fail closed on executable JS/CSS DLP media
    "test_security_admin_stop_audit_wait_round8", # bound stop while audit append is stalled
    "test_security_html_entity_dlp_round8", # inspect browser-decoded HTML entities before response release
    "test_security_admin_audit_failure_round8", # expose audit-write failure after applied admin changes
    "test_security_windows_path_alias_round8", # include Win32 trailing-dot/space/ADS private-path readings
    "test_security_credential_obs_space_round7", # count backend-equivalent API keys identically
    "test_security_route_override_obs_round7", # reject route-override obs-text whitespace ambiguity
    "test_security_quota_capacity_round7", # retain active quota and block before the next backend response
    "test_security_egress_sfx_zip_round7", # block SFX and disguised archive responses before client bytes
    "test_security_admin_reject_drain_round7", # bound unauthenticated reject body waits
    "test_security_request_target_ctl_round7", # reject request-line CTL before backend interpretation
    "test_security_usage_eviction_round7", # preserve tracked usage history at capacity
    "test_security_append_lock_cache_round4", # reclaim per-path append locks after writes
    "test_security_path_lock_cache_round4", # reclaim per-path state locks after operations
    "test_admin_generation_head_round5", # bound admin heads and reject stale handlers after stop
    "test_admin_pending_heads_round4", # reserve admin handler capacity from slow unauthenticated headers
    "test_security_audit_compressed_eof_round4", # report malformed complete coding in audit mode
    "test_security_deflate_graphql_round4", # complete compressed GraphQL representation
    "test_security_deflate_dual_view_round4", # reject divergent zlib/raw deflate interpretations
    "test_security_gzip_members_round4", # bound empty gzip member CPU work in all decode paths
    "test_admin_readiness_delay_round3", # delayed live admin HTTP readiness
    "test_security_response_trailer_round3", # response-control fields stay out of trailers
    "test_acl_signed_history_round3",    # ACL unsigned replacement after signed history
    "test_security_response_connection_round3", # protected response fields survive downstream hops
    "test_security_declarative_file_round3", # strict all-or-nothing config file authority
    "test_gui_url_scrub_round3",            # legacy token aliases leave browser history
    "test_security_request_length_round3", # bounded request Content-Length before backend
    "test_security_xff_hops_round2",       # trusted-proxy rightmost identity and wire BAN
    "test_security_encoded_upload_round2", # encoded upload completeness in enforce/audit
    "test_security_response_interim_round2", # bounded 1xx chain and exact response bytes
    "test_security_admin_state_round", # strict management request framing
    "test_security_ingress_round",     # protected Connection option semantics
    "test_security_egress_round",      # cache and redirect response boundaries
    "test_security_launcher_round",    # startup address and browser target validation
    "test_falco_admin_boundaries",   # unique credentials, origins and total body deadline
    "test_falco_protocol_alignment", # singleton request fields and origin response boundaries
    "test_falco_graphql_views",      # query aliases and envelope-owned batch accounting
    "test_graphql_persisted_query",  # uninspectable cached operations and wire behavior
    "test_seams_admin",            # absent versus explicit-null management fields
    "test_seams_service",          # startup address syntax cannot discard suffixes
    "test_seams_state",            # persisted inner schemas and strict normalization
    "test_seams_storage",          # log generation preservation on rename failures
    "test_seams_transport",        # finite responses complete at their HTTP boundary
    "test_boundary_corpus_protocol", # bounded grammar mutations and exact wire controls
    "test_boundary_corpus_state",    # atomic configuration and legacy state boundaries
    "test_boundary_corpus_admin",    # strict JSON and all-or-nothing management inputs
    "test_egress_privacy_transport", # decoded/raw response equivalence and opaque formats
    "test_egress_privacy_core",      # current secret formats and atomic accounting bounds
    "test_egress_privacy_admin",     # error, audit and diagnostic data minimization
    "test_egress_privacy_service",   # credential output ownership at startup
    "test_gui_dashboard_edges", # bulk targets, input controls and asynchronous UI results
    "test_gui_native_edges",    # native failure recovery, message and child ownership
    "test_gui_tray",           # Win32 readiness, stop ownership and resource cleanup
    "test_gui_launcher",       # URL, child, status and callback lifecycle
    "test_gui_dashboard",      # modal, async render and operation result boundaries
    "test_edge_proxy",         # deadlines, admission and bounded logging ownership
    "test_edge_proxy_worker_phase", # separate child startup and worker failure deadlines
    "test_edge_pipeline",      # configuration budgets and concurrent accounting
    "test_edge_policy",        # coherent export and ACL hot path
    "test_edge_storage",       # nonwaiting diagnostics and serialized audit writes
    "test_privacy_ingress",     # 非公開経路/機密artifact/uploadと記録用URL
    "test_privacy_response",    # DLP応答境界と私有応答のキャッシュ禁止
    "test_privacy_admin",       # 管理情報をキャッシュへ残さない
    "test_privacy_deployment",  # 適用例・実通信・信頼proxy境界の接続確認
    "test_atomic_storage",      # 鍵・署名状態・失敗時の公開/耐久性
    "test_atomic_pipeline",     # 設定・BAN・解除の一括commitと結果
    "test_atomic_admin",        # 管理API/ACLのロック・成功応答
    "test_atomic_runtime",      # 待受/子プロセスの所有・失敗時回収
    "test_atomic_edge",         # 前衛生成物の準備・復元と部分失敗
    "test_core",                # 管理ダッシュボード制御API
    "test_logio",               # 追記ログのローテーション(肥大防止)
    "test_banner",              # 動的デセプション(偽Serverバナーで指紋攪乱)
    "test_hardening",           # ReDoS/脆弱性・未知攻撃ファズ・資源境界・ホットパス健全性
    "test_secheaders",          # 応答セキュリティヘッダ注入
    "test_paranoia",            # 検知の段階的厳格度(paranoia レベル)
    "test_health",              # データプレーンのヘルスチェック(LB/オーケストレータ用)
    "test_bans",                # 累犯BANエスカレーション(常習攻撃者を重く罰する)
    "test_shutdown",            # SIGTERM graceful shutdown(コンテナ/k8s の停止に応答)
    "test_pathrate",            # パス別レート制限(認証/高コスト経路を構造的に厳格化)
    "test_throttle",            # レート超過応答(HTTP 429 + Retry-After)
    "test_subnet",              # サブネット集約防御(分散攻撃を /24・/64 で束ねて捉える)
    "test_method",              # HTTPメソッドポリシー(XST/プロキシ濫用メソッドを遮断)
    "test_config_bootstrap",    # 宣言的設定ブートストラップ(JSON/ConfigMap を起動時適用)
    "test_connlimit",           # per-IP 同時接続上限(接続枯渇/slowloris 増幅対策)
    "test_keepalive",           # keep-alive 越しの検査回避を封じる(Connection: close 強制)
    "test_realip",              # 信頼proxy背後の実クライアントIP解決(XFF・既定は信頼しない)
    "test_signed_state",        # 自己防衛: 可変状態ファイルの HMAC 署名による改竄耐性
    "test_posix_runtime",       # Linux: 実SIGTERMのflush/子回収と別UID出力権限
    "test_autostart",           # 自己防衛: 起動時自動起動の登録(透明・公認の場所のみ)
    "test_respscore",           # 応答アウェア脅威スコア(4xx連射=列挙/ブルートフォース検知)
    "test_bodyscan",            # 要求ボディ検査(POST/JSON 本文の SQLi/XSS/RCE/SSTI=head死角)
    "test_botconsistency",      # ヘッダ整合性ボット検知(UA偽装ツールを低FP加点)
    "test_slowbody",            # スロー POST(R-U-Dead-Yet)対策(ボディ総受信時間に上限)
    "test_cookieharden",        # Set-Cookie ハードニング(SameSite/Secure/HttpOnly 補完)
    "test_upload",              # ファイルアップロード検査(危険拡張子=webshell 投入対策)
    "test_graphql",             # GraphQL クエリ防御(深さ/複雑度/イントロスペクション/バッチ)
    "test_jwt",                 # JWT 検査(alg:none/許可外alg=認証バイパス・alg混同を遮断)
    "test_cors",                # CORS 誤設定の無害化(ACAO:*/null + 資格情報の危険併存)
    "test_credrate",            # クレデンシャル単位レート制限(IP横断の盗用キー濫用を絞る)
    "test_openredirect",        # オープンリダイレクト無害化(外部許可外への3xxを書換/記録)
    "test_methodoverride",      # メソッドオーバーライド悪用対策(override先にもmethodポリシー適用)
    "test_pathoverride",        # パスオーバーライド ACL バイパス対策(X-Original-URL 等を遮断)
    "test_bodydecode",          # 圧縮ボディの解凍走査(gzip/deflate での署名回避を封じる)
    "test_cachepoison",         # キャッシュ汚染ヘッダ除去(非信頼の X-Forwarded-Host 等を落とす)
    "test_rangedos",            # Range ヘッダ DoS 対策(多数レンジ=Apache Killer を遮断)
    "test_origin",              # バックエンド・バイパス防止(エッジ経由を証明する時間有界トークン)
    "test_buttonmash",          # ボタン連打(並行/二重送信)スキャン: スレッド安全・更新取りこぼし無し
    "test_memtamper",           # in-memory cfg すり替え検知+署名ディスクからの復元
    "test_stall",               # 迂回検知(busy→突然ゼロ=バイパスの疑いを警報)
    "test_connlimit_global",    # グローバル同時接続上限(FD/ソケット枯渇のロードシェッド)
    "test_saferegex",           # ReDoS 耐性(lint/入力上限/線形リテラル照合)・組込sig安全性
    "test_smuggling",           # HTTP リクエストスマグリング/デシンク拒否(CL.TE/裸LF/obs-fold等)
    "test_framing_boundaries",   # TE/ヘッダ構文/chunk 拡張と trailer の前衛・上流境界
    "test_request_body_scan_budget",  # 復号後の走査上限・multipart境界・binary宣言の検査回避
    "test_proxy_boundaries_batch",     # 本文前の backend 接続・Host・DLP chunk 枠の境界
    "test_admin_bootstrap",      # Cookie漏えい防止・管理ヘッダ認証・同一応答のトレイ状態証明
    "test_admin_browser_mac",    # browser要求/応答MAC、再送・再起動・時刻ずれ・Windows bind排他
    "test_scanwindow",          # 走査面のバイパス封じ(パディング/NFKC展開/窓予算)と資源境界
    "test_vulnfix",             # 脆弱性修正の回帰(CSRF/トークン配布/署名束縛)
    "test_complexity",          # 二次コスト(O(N^2))の再発防止(間引きの低水位・走査量削減の非回帰)
    "test_startup_seams",       # 起動部と繋ぎ目の潜在バグ(設定ミス耐性/起動診断/停止経路/fail-closed)
    # 2026-10 細心のバグ総点検(95 候補)の回帰テスト。どれも修正を外すと落ちることを確認済み。
    "test_sweep_admin_ui",      # 管理画面: inline JS へのデータ埋込/不正本文/CSRF のポート
    "test_sweep_config",        # 設定検証: 構造キー・非有限値・設定変更とロック
    "test_sweep_bans",          # BAN: 恒久BANの短縮/追い出し/IP 正規化/永続化の取りこぼし
    "test_sweep_proxy_request", # 要求/応答: 重複ヘッダ/パイプライン/多重 gzip/1xx/DLP/リダイレクト
    "test_sweep_proxy_lifecycle",  # 停止/ドレイン
    "test_sweep_core",          # 自己防衛の基盤: 署名状態/原子的書込/ReDoS lint/ロケール
    "test_sweep_ldap_edge",     # エッジ設定出力
    "test_sweep_enterprise",    # 監視 URL の秘匿
    "test_sweep_service_gui",   # サービス/トレイ/自動起動/起動スクリプト
    "test_sweep_r2_ipsource",   # 取込時点の IP 正規化(XFF/接続元)・複数クレデンシャルのレート
    "test_sweep_r2_misc",       # 非 ASCII トークン比較/使用量ログ/応答 JSON の非有限値/一時承認の既定
    "test_sweep_r3_proxy",      # 使用量の宛先記録
    "test_sweep_r3_net",        # IPv4-mapped の CIDR 照合
    "test_sweep_followups",     # XFF のゾーンID/使用量の IPv6 Host/FW の IPv4-mapped
    "test_sweep_r4_site_whitelist",  # 空の site_whitelist を whitelist モードにする設定を拒否
    # 2026-10 検知エンジン本体の点検の回帰テスト
    "test_sweep_det_normalize",       # 正規化/走査窓/本文専用の正規化(multipart の誤検知)
    "test_sweep_det_signatures",      # シグネチャ: 重み 0/独自規則の照合面/組込との優先/読込の堅牢性
    "test_sweep_det_inspect_state",   # 状態と採点: 追い出し/早期拒否の計上/減衰/各種設定の境界
    "test_sweep_det_inspect_checks",  # 個別検査: JWT/周期判定
    "test_sweep_det_body",            # GraphQL/アップロード/本文検査の配線
    "test_sweep_det_response",        # 出口 DLP/応答採点
    "test_sweep_det_periphery",       # ブルームフィルタ
    "test_sweep_det2_signatures",     # 本文の ';' は文脈必須/管理 API の入力検証/シグネチャ画面
    "test_sweep_det2_body",           # バイナリ本文/要求ヘッダのファイル名
    "test_sweep_det2_config",         # 設定改ざん時も保護を止めない/列挙値と係数の検証
    "test_sweep_det2_path",           # 照合用パスのドットセグメント/'//'/';' の解決
    "test_sweep_det3_crlf",           # 本文の値に符号化された改行+応答ヘッダの検知(誤検知は戻さない)
    "test_sweep_det3_docs",           # カスタム規則の注意文言と文書の整合
    "test_sweep_det3_misc",           # ヘッダに書く設定値の検証
    # 2026-10 人に向けた表示: JSON の垂れ流しをやめ『何が起きたか+次にすること』を出す
    "test_sweep_ux_proxy_pages",      # 訪問者向けの拒否ページ(API には従来の JSON)
    "test_sweep_ux_dashboard_gui",    # ダッシュボードの詳細分析/エラー表示
    "test_sweep_ux_cli",              # CLI の要約表示と --json
    "test_sweep_lite_tray_status",    # トレイのアイコン/ツールチップで防御 ON/OFF を表示
    # 2026-10 全差分の独立レビューで見つかった回帰の修正
    "test_sweep_rv_autostart",        # 自動起動: XML 登録で /TR 261 文字制限を回避
    "test_sweep_rv_bodynorm",         # 本文: 全角記号を記号へ畳まない/符号化改行の文区切り
    "test_sweep_rv_multipart",        # multipart: 部ヘッダ走査を線形に/行数上限/カード IIN
    "test_sweep_rv_config",           # 旧版の設定・状態を更新後も同じ意味で読む
    "test_sweep_rv_proxy",            # 100-continue/IPv6 リダイレクト/API 判定/監査
    "test_sweep_rv_runtime",          # ログ回転で待たない
    "test_sweep_rv_operator",         # run.bat の py -3/表示の言語
    "test_sweep_rv_lite_tray",        # トレイ: 他プロセスへトークンを送らない/監査モード表示
    "test_sweep_dec_headfold",        # URL/ヘッダでも全角の ｜＄（）；｀ をメタ文字にしない
    "test_sweep_dec_runbat",          # run.bat の注釈を ASCII に(日本語版 Windows の誤ったエラー行)
    "test_sweep_rem_jsonesc",         # JSON 本文の \r\n エスケープ後のヘッダ注入/文区切り
    "test_sweep_rem_tray",            # Explorer 再起動(TaskbarCreated)でトレイのアイコンを付け直す
    "test_sweep_rem_fwfold",          # fold_fullwidth_punct(既定 OFF)で全角記号も畳む運用
    "test_sweep_upd_integrity",       # 同じ場所で更新したとき完全性監視が中核を旧版へ戻さない
    "test_sweep_rem_charset",         # 本文を宣言された charset でも読む・GraphQL のフラグメントを展開して数える
    "test_sweep_rem_geoip",           # GeoIP: 入れ子の CIDR・IPv6 の行・IPv4-mapped で国判定が外れない
    "test_sweep_rem_cover",           # 表示名の制御文字・空の DUCKNET_COVER・Tomcat の偽バナーに PHP を付けない
]


_NATIVE_SECRET_VIOLATIONS = []


def _isolate_native_secrets() -> None:
    """Automated tests must explicitly supply fake consent/clipboard APIs."""
    from dataplane.gui import __main__ as gui

    _NATIVE_SECRET_VIOLATIONS.clear()

    def blocked(boundary):
        def refuse(*_args, **_kwargs):
            _NATIVE_SECRET_VIOLATIONS.append(boundary)
            raise AssertionError("real " + boundary + " is forbidden in automated tests")
        return refuse

    gui._confirm_token_copy = blocked("token-copy consent")
    gui._clipboard_api = blocked("clipboard access")


def _assert_native_secrets_untouched(before: int) -> None:
    if len(_NATIVE_SECRET_VIOLATIONS) != before:
        raise AssertionError("test attempted native secret UI: " + repr(_NATIVE_SECRET_VIOLATIONS[before:]))


def main() -> int:
    # 明示順序を保ちつつ、新設した試験を登録せず「全試験成功」と表示する漏れを防ぐ。
    discovered = {p[:-3] for p in os.listdir(os.path.dirname(__file__))
                  if p.startswith("test_") and p.endswith(".py")}
    if discovered != set(MODULES):
        print("FAIL test manifest mismatch: unregistered=" + repr(sorted(discovered - set(MODULES)))
              + " missing=" + repr(sorted(set(MODULES) - discovered)))
        return 1
    _isolate_native_secrets()
    total = passed = 0
    skipped = []
    for name in MODULES:
        mod = importlib.import_module(name)
        fns = [v for k, v in sorted(vars(mod).items())
               if k.startswith("test_") and callable(v)]
        for fn in fns:
            total += 1
            native_before = len(_NATIVE_SECRET_VIOLATIONS)
            try:
                fn()
                _assert_native_secrets_untouched(native_before)
                passed += 1
                print(f"PASS {name}.{fn.__name__}")
            except SkipTest as e:   # 環境を満たせないテスト(Tk 無しのサーバ等)
                if len(_NATIVE_SECRET_VIOLATIONS) != native_before:
                    print(f"FAIL {name}.{fn.__name__} -> attempted native secret UI before skipping")
                else:
                    skipped.append(f"{name}.{fn.__name__}")
                    print(f"SKIP {name}.{fn.__name__} -> {e}")
            except Exception as e:  # noqa: BLE001 (テストランナー)
                print(f"FAIL {name}.{fn.__name__} -> {e!r}")
                traceback.print_exc()
                if os.environ.get("GITHUB_ACTIONS") == "true":
                    # CI では失敗を注釈として出す。ログを開かなくても、どのテストが
                    # どう落ちたかが run の一覧から分かる(ログは権限が要る)。
                    _d = " ".join(repr(e).split())[:400]   # 注釈は 1 行に畳む
                    print(f"::error title={name}.{fn.__name__}::{_d}", flush=True)
    failed = total - passed - len(skipped)
    tail = f" ({len(skipped)} skipped)" if skipped else ""
    print(f"\n=== {passed}/{total} passed{tail} ===")
    if skipped:
        # 飛ばしたテストは *必ず* 名前を出す。黙って素通りさせると「全部緑」に見えて
        # 実際には走っていない、という最悪の読み違いが起きる(以前はそうなっていた)。
        print("skipped: " + ", ".join(skipped))
    _cleanup()
    return 0 if failed == 0 else 1


def _cleanup():
    """ビルド/テスト後に余計なデータ(__pycache__ 等)を毎回掃除する。"""
    try:
        sys.path.insert(0, os.path.join(_ROOT, "tools"))
        import clean
        n = clean.clean(_ROOT)
        print(f"cleanup: removed {n} build artifact(s)")
    except Exception as e:        # 掃除失敗はテスト結果に影響させない
        print(f"cleanup: skipped ({e!r})")


if __name__ == "__main__":
    sys.exit(main())
