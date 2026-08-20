# ChickenNet L7 Security — 次にやること(引き継ぎメモ)

このリポジトリ(`D:\ChickenNet`)は独立したスタンドアロン製品です(防御エンジンは
`dataplane/engine/` 配下に同梱、外部リポジトリ依存なし)。
このメモは次セッション(あなた=Claude / 開発者)が最初に読む引き継ぎです。

## いまの状態(検証済み)
- 外部依存ゼロ(stdlib のみ)。
- テスト **76/76**: `python tests/run_all.py`(CHICKENNET_OFFLINE=1)。socket 絡みの並行/中継
  テストも複数回グリーンで非フレーク確認済み。
- パッケージ: `python -m build` → sdist+wheel、`twine check` PASSED、
  クリーン venv に wheel 導入 → 全 CLI サブコマンド(`--help`)動作・第三者依存ゼロまで確認済み。
- CI: `.github/workflows/ci.yml`(Linux 3.10–3.13 + Windows 3.12)。
- 公開: `.github/workflows/release.yml`(タグ `vX.Y.Z` で GitHub Release + PyPI + Docker Hub)。
  公開は repo 変数 `ENABLE_PYPI` / `ENABLE_DOCKER` で**ゲート(既定オフ)**。
- ライセンス: 検証(製品側)+発行CLI(ベンダー側 `python -m dataplane.enterprise.issue`)+
  失効(jti)+SKU/価格(`tiers.py`、価格はプレースホルダ)。手順は `LICENSING.md`。

## 侵入後対策の add-on(別プロセス・可視化が主・制御は補助)
本体(HTTP前段ゲートウェイ)とは別に、横展開/内部偵察を *可視化* する検知群を追加済み。
いずれも依存ゼロ・OS非侵襲・防御専用。設計と正直な線引きは各 `docs/` を参照。
- `chickennet-security dns` … DNS の L7 振る舞い検知(トンネリング/C2/AD偵察)。
  既定は監査。`docs/dns.md`。
- `chickennet-security decoy` … LDAP/SMB/Kerberos のデコイ(接触=クロ)。
  `docs/listeners.md`。
- `chickennet-security ldap-proxy` … LDAP を透過中継しつつ列挙検知(監査既定/enforce は切断)。
  `docs/ldap-proxy.md`。
- 共有基盤: `ber.py`(BER/LDAP 解析)・`alerts.py`(AlertSink: 除外/集約/メトリクス/ローテログ)・
  `netutil.py`(CIDR)・`atomic_io`(原子書込/ローテ追記/末尾読取)。
- 管理ダッシュボードに「横展開 / DNS 検知」欄(別プロセスのログを**読み取り専用**で集約)。

## 未検証(正直な但し書き)
- **実公開(PyPI / Docker Hub への push)は未実施**(意図的)。要: 資格情報 + タグ。公開は不可逆=
  人間の最終判断で行う。リリース成果物(wheel/sdist)は build + `twine check` PASSED まで検証済み。
- **Docker の実ビルドは未実施**(この環境に docker 無し)。ただし静的検証は実施済み:
  Dockerfile/compose の整合(entrypoint+CMD・healthcheck・非root・HOME=/data)を確認し、
  `.dockerignore` 適用後のビルドコンテキストを再現して `python -m dataplane` 全
  サブコマンド(`--help`)が動くことを確認。**初回の実ビルドのみ** CI(`ENABLE_DOCKER=true`)か
  手元 `docker build .` で要確認。
- **PyPI 名 `chickennet-security` は空き確認済み(2026-06 時点で 404 = 取得可能)**。
  もし取得までに埋まったら `pyproject.toml` の `name` と `DOCKER_IMAGE`/タグを変更する。

## 次にやること(順番)
1. ~~**PyPI 名の空き確認**~~: 済(2026-06 時点で 404=取得可能)。取得が遅れる場合のみ再確認。
2. **GitHub リポ作成して push**:
   `git remote add origin https://github.com/<you>/chickennet-security.git && git push -u origin master`
   → CI が自動で回る(緑を確認)。
3. **価格/プランの確定**: `dataplane/enterprise/tiers.py` の `price_jpy_year` 等を実値へ。
4. **PyPI 公開設定**(`RELEASING.md` §1): Trusted Publisher 登録 + repo 変数 `ENABLE_PYPI=true`。
5. **Docker Hub 公開設定**(`RELEASING.md` §2): secrets `DOCKERHUB_USERNAME`/`DOCKERHUB_TOKEN`、
   変数 `DOCKER_IMAGE=<you>/chickennet-security`、`ENABLE_DOCKER=true`。
6. **Docker をローカルで一度ビルド確認**: `docker build -t chickennet-security:test .` →
   `docker run -p 8443:8443 -p 8081:8081 chickennet-security:test`(管理画面が出るか)。
7. **初回リリース**: `pyproject.toml` と `Dockerfile` の version を合わせ、`python tools/gen_sbom.py` を
   再生成・コミット → `git tag v1.0.0 && git push origin v1.0.0`(これで公開が走る)。

## 中期の候補(任意)
- 適用範囲(L7 のみ・L3/L4 非対象)の図解を README に。
- 管理ダッシュボードの操作デモ(GIF / スクショ)。
- ベンチ(同時接続・スループット)を正直な数値で。誇張語は使わない。
- `cluster_balancer`(`enterprise/__init__.py` に「未実装」と記載)の実装可否を判断。

## 設計の鉄則(踏襲)
- **外部依存ゼロ**を死守(任意機能のみ extra)。`pyproject` の `dependencies = []` を崩さない。
- 誇張語を使わない。適用範囲(L7 のみ)を常に明示(過大広告を避ける)。
- ライセンス秘密鍵(seed)は絶対にコミット/配布しない。
- 防御専用(反撃しない・OS 非侵襲)。
