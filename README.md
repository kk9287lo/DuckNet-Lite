# DuckNet-Lite

Web サーバの前に置く L7 の WAF / DDoS ゲートウェイです。外部依存なしにPython の標準ライブラリだけで動き、OSを汚さずに導入可能です。

上位版 DuckNet L7 Security の無償エディションで、ライセンスは AGPL-3.0-or-later。中身はコアの WAF/DDoS リバースプロキシと、最小限の Web 管理画面。これだけでも実運用に使えます。

守れるのは HTTP(L7)まで。回線や OS を飽和させる L3/L4 の物量攻撃は範囲外です(詳しくは下の「守れる範囲」)。

## まず動かす

```bash
python -m dataplane --backend 127.0.0.1:8080 --listen 8443 --admin 8081
#   前衛 0.0.0.0:8443 → バックエンドへ転送。管理画面 http://127.0.0.1:8081(トークンは起動時に表示)

docker compose up -d      # Docker で動かすなら
```

Python 3.10 以上なら `pip install` は要りません。起動ラッパ(`run.sh` / `run.bat` / `run.ps1`)も同梱していて、Python の自動検出や `app.env` の読み込みをやってくれます。

## 何をするか

```
[攻撃] → DuckNet(前衛) → あなたの Web サーバ
```

- レート制限・脅威スコア・自動 BAN。SQLi/XSS/RCE/traversal/XXE/SSRF/JNDI などのシグネチャ照合。
- head だけでなくボディ(JSON/GraphQL、gzip 解凍込み)とアップロードまで検査。応答側は DLP と Cookie/CORS/リダイレクトの無害化。
- JWT 検査、クレデンシャル単位のレート、リクエストスマグリングや Range DoS への対処。
- 不正な接続はその場で切り、通すのは正規のアクセスだけ。
- BAN や設定は HMAC 署名で保存するので、状態ファイルを書き換えられても弾けます。
- 管理画面で ON/OFF・グラフ・BAN・設定をクリック操作。

防御と設定キーの一覧は [docs/defenses.md](docs/defenses.md)、画面の使い方は [docs/dashboard.md](docs/dashboard.md)、全オプションは [docs/options.md](docs/options.md)。変更履歴は [CHANGELOG.md](CHANGELOG.md)。高度な防御はたいてい既定 OFF で、必要なときだけ点けます。

## フル版との違い

Lite版は最小限の機能に絞っています。下記の機能は上位の DuckNet L7 Security にのみ搭載しています。

- 可用性: 自己完全性チェックとファイル修復、watchdog による自動再起動、`--supervise`。
- ボット選別システム: 動的 PoW チャレンジで人を通しつつボットを弾く(Lite は拒否/BAN の二値のみ)。GeoIP・allowlist・ステルス運用も加わります。
- 侵入後検知: LDAP/SMB/Kerberos デコイ、カナリアトークン、ハニーポット、DNS フィルタ。
- SOC連携: SIEM/Slack 転送、脅威インテリジェンス(IoC)、MITRE ATT&CK ルール。
- 大規模配備: LDAP 列挙検知プロキシ、ノード間の BAN 同期、商用ライセンス管理。

## 落とされない・改竄されない

防御ツールは落とされたら終わりです。Lite は BAN/設定を HMAC 署名で守り、改竄があれば管理画面に出します。クラッシュからの再起動は OS 側(systemd の `Restart=`、Windows のサービス回復、launchd の `KeepAlive`)に任せます。アプリに watchdog を抱えない分、依存ゼロのまま単純に保てます。

```bash
export DUCKNET_STATE_KEY=...   # 署名鍵を外に置くと改竄耐性が一段上がる(推奨)
```

プロセス隠蔽や taskkill 妨害のような rootkit じみたことはしません。設定手順は [docs/hardening.md](docs/hardening.md)、APT を想定した配備は [docs/apt-threat-model.md](docs/apt-threat-model.md) にまとめてあります。

## 守れる範囲

- 守るのは L7。サーバが受け取った HTTP 要求を検査して弾きます。
- L3/L4 の物量攻撃(UDP/SYN flood など)は守れません。そこは Anycast やクラウドの DDoS 保護、ISP の領分です。
- 反撃はしません。OS のファイアウォールにも触れません。
- 全コアを使うなら Linux で `--cluster`(SO_REUSEPORT)。Windows などは単一プロセスになります。

## ライセンス

AGPL-3.0-or-later です([LICENSE.txt](LICENSE.txt))。ネットワーク越しに使わせる場合もソース開示の義務が付きます(第 13 条)。その義務を負いたくない、あるいは全機能が要るならフル版(商用)へ。

同梱する第三者コードはありません(依存ゼロ)。表示は [THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt)、SBOM は [sbom.cdx.json](sbom.cdx.json)。

## 開発

```bash
python tests/run_all.py     # テスト(依存ゼロ)
python -m build             # sdist + wheel
```

CI は Linux(3.10–3.13)と Windows で回しています(`.github/workflows/ci.yml`)。
