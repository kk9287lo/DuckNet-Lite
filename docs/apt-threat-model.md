# APT 想定の配備ハードニング — 「門と戦わず地面を変える」攻撃への対処

> 正直に先に。**ユーザーランドの L7 防御は「1つの層」に過ぎません。** 国家支援型の高度な攻撃グループ
> (APT)は、正面突破が困難なら *その層を迂回し、下の層(インフラ/ネットワーク/ランタイム/OS)を
> 攻める* ことに切り替えます。本書は「DuckNet を万能にする」ためのものではなく、**各層を正しい統制で
> 装備し、DuckNet は改竄・迂回を *検知* する**——という多層防御の現実的な配置を示します。

## 攻撃フェーズ → 統制の所在

| 攻撃(APT の手口) | 正しい防御層(WAF 外) | DuckNet の寄与 | 原理的限界 |
|---|---|---|---|
| クラウド/vCenter 制圧・**VM スナップショット窃取** | IAM 最小権限・MFA・管理面の分離・KMS | 改竄検知(HMAC 状態署名)。**外部鍵**で窃取しても再署名不能 | ハイパーバイザ全権を握られたらメモリ上の鍵も読める |
| **vNIC 再ルーティングで DuckNet を迂回** / backend 直叩き | ネットワーク分離・SG/NACL・backend を WAF 経由のみ到達可能に | **オリジントークン(#77)**=迂回トラフィックを backend が拒否。**迂回検知(#78)**=トラフィック急停止を警報 | 経路を完全制御されたら最終的には通る |
| BGP ハイジャック / DNS ポイズニング | **RPKI(ROA)**・**DNSSEC**・証明書透明性監視・HSTS preload | (範囲外) | 経路/名前解決は WAF の外 |
| CPython コアのゼロデイ(C 層) | OS サンドボックス(seccomp/AppArmor)・最新化 | プロセス分離・最小権限で爆発半径を縮小 | 未知の言語ランタイム脆弱性は事前に防げない |
| **FD/ソケット枯渇 + 再起動ループ悪用**で OS パニック | OS の `ulimit`/cgroup・systemd `LimitNOFILE`/sysctl・`StartLimitBurst`(クラッシュループ遮断) | **グローバル接続上限(#79)**・per-IP 上限(#30)・slow-body/header タイムアウト | カーネルメモリ枯渇は OS の領分 |

---

## 1. バックエンド・バイパス防止(オリジン・クローキング・#77)

迂回トラフィック(再ルーティング/直叩き)を **backend 側で弾く**。エッジと backend で **同一鍵**を共有。

```bash
# エッジ(DuckNet)・backend の両方で同じ鍵を環境変数に(VM 外/シークレット管理から注入)
export DUCKNET_ORIGIN_KEY="$(vault read -field=key secret/ducknet/origin)"
```
エッジ設定:
```json
{ "origin_cloaking_enabled": true, "origin_header": "X-Edge-Token", "origin_window_sec": 30 }
```
backend の検証(Python 参照実装。任意の言語で同等に再現可):
```python
from dataplane.engine.core.origin import verify_origin_token
import os

KEY = os.environ["DUCKNET_ORIGIN_KEY"]

def is_from_edge(request) -> bool:
    return verify_origin_token(request.headers.get("X-Edge-Token", ""), KEY, window=30.0)

# is_from_edge() が False のリクエストは 403 で拒否する(=DuckNet を迂回した直叩き)
```
> 正直な範囲: 時間バケット方式ゆえリプレイは窓(既定30秒)内に限り可能。完全防止には内部
> エッジ→backend 経路の MITM が前提で、そこまで握られていれば別問題。鍵を VM 外に置くのが要。

## 2. 迂回の能動検知(dead-man's switch・#78)

DuckNet 経由のトラフィックが *直近 busy だったのに突然ゼロ* になったら、再ルーティングの疑い。
`stall_detect_enabled`(既定 ON)で `traffic_stall` イベントを記録する。ダッシュボード
(`GET /api/shield/events` / `/api/shield/tamper`)で定期的に監視すること。

## 3. 資源枯渇ハードニング(#79 + OS 層)

アプリ内蔵(既定有効): グローバル接続上限 `max_total_conn`(既定 20000)、per-IP 上限 `max_conn_per_ip`、
クラッシュループ遮断、slow-body/header タイムアウト。**OS 層で必ず併用**:
```ini
# systemd unit(抜粋)。詳細は docs/hardening.md
[Service]
LimitNOFILE=65536
TasksMax=4096
MemoryMax=2G            # cgroup でメモリを頭打ち(OS 巻き込みを防ぐ)
Restart=on-failure
StartLimitIntervalSec=60
StartLimitBurst=5       # クラッシュループ遮断(OS 層。アプリは自動再起動ロジックを持たない)
```

## 4. 外部鍵(スナップショット窃取への耐性)

状態署名(#52/#54)・オリジントークン(#77)の鍵は **VM の外**(KMS/Vault/env 注入)に置く。
VM やディスクのスナップショットを抜かれても、鍵が無ければ **状態の偽造もトークンの偽造もできない**。
```bash
export DUCKNET_STATE_KEY="$(vault read -field=k secret/ducknet/state)"
export DUCKNET_ORIGIN_KEY="$(vault read -field=k secret/ducknet/origin)"
```

## 5. 状態改竄検知(#52–#55)

状態ファイル(BAN/設定)は HMAC 署名され、無署名/改竄されたものは fail-safe で破棄される
(`state_tamper` イベント)。in-memory の cfg すり替えも MAC で検知し、ディスクの署名済み状態から
自動復元する(`memory_tamper`)。ダッシュボード `GET /api/shield/tamper` で要約+直近イベントを確認する。

## 6. ホスト侵害後の横展開抑止(DuckNet を中継地点/C2 として使わせない)

前提の踏み直し: 1〜5節はすべて「DuckNet を迂回される」防御。ここでは逆の想定——**DuckNet 自身が
動くホストが乗っ取られた場合**、そのホストが内部ネットワークへの横展開の中継基地として悪用される
のを防ぐ。DuckNet は通信を検査・復号する特権的な位置(TLS 終端・backend への信頼された経路)に
あり、周囲のファイアウォール/セキュリティグループは *この用途のために* 穴を開けている。ホストを
握った攻撃者にとって、その「既に開いている穴」を通って外へ出る方が、自前の通信経路を新設するより
検知されにくい。

- **エッジ・アウトバウンドの許可リスト化(最重要)**: DuckNet ホストの outbound を、実際に必要な
  宛先だけに **ファイアウォール/SG レベルで** 限定する。監査済みの事実として、DuckNet 自身の
  コードは backend アドレスを起動時の `--backend` 固定値としてのみ保持し、管理API経由でも宣言的
  設定ファイル(`apply_config`/`--config`)経由でも **実行時に変更する経路は存在しない**
  (`NetShield.apply_config` が触るのは検知設定 `self.cfg` のみで、`AsyncEdgeGuard` の
  backend アドレスとは無関係)。つまり *正規の動作として* DuckNet が到達する必要があるのは
  backend の1箇所だけであり(このLiteエディションには SIEM/Webhook 転送は含まれない)、この
  事実を使ってホストの outbound をそれ以外は default-deny にできる:
```
# 例: iptables(概念)。backend 以外への新規 outbound を拒否
iptables -A OUTPUT -d <backend_ip> -p tcp --dport <backend_port> -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -j DROP
```
  クラウドなら SG/NSG の Egress ルールで同じことを実現するほうが、ホスト内改竄に対して堅牢
  (iptables ルール自体もホスト侵害で書き換えられ得るため)。
- **ホストの最小権限**: 専用の非特権サービスアカウントで起動する。ベアメタル/VM 配備では、
  DuckNet 専用の低権限ユーザーで動かし、sudo/管理者権限を持たせない。
- **他システムの認証情報をこのホストに置かない**: DuckNet は防御専用であり、他の内部システムへの
  SSH鍵・クラウド IAM 認証情報・別サービスの API キー等を **このホストにキャッシュ/保管する理由が
  そもそも無い**。監視エージェント等の他ツールを同居させているなら、それらが実際の横展開の踏み台
  になり得ないか個別に精査すること(DuckNet 自体はこの種の認証情報を一切扱わない)。
- **鍵の即時ローテーション**: ホスト侵害が疑われたら、`DUCKNET_ORIGIN_KEY`/`DUCKNET_STATE_KEY`
  (4節)を **直ちにローテーション**する。これらはホスト侵害後も持ち出されて悪用され得る
  「唯一の持続的資産」であり、プロセスの再起動・再デプロイだけでは無効化されない。
- **ネットワークセグメンテーション**: DuckNet ホストは、他の内部ホストへ到達できる必要が基本的に
  無い。専用のセグメント/VLAN に置き、たとえ乗っ取られても隣接ホストへ直接到達できないよう構成
  する(踏み台としての価値そのものを構造的に下げる)。

> 正直な範囲: これらはすべて **ホスト/ネットワーク層の統制**であり、DuckNet 自身のコードで
> 強制することはできない(OS のファイアウォール設定を書き換えるのは「OS 非侵襲」という設計方針
> そのものに反する)。DuckNet 側で監査済みの事実(backend が実行時に変更不能)を踏まえ、
> その事実に対応するネットワーク許可リストを外側で組むのが、この節の唯一の実効策である。

---

## 配備チェックリスト(APT 想定)

- [ ] **ネットワーク**: backend は DuckNet 経由のみ到達可(SG/NACL)。`origin_cloaking_enabled` + backend 検証。
- [ ] **経路/名前**: RPKI(ROA)発行・DNSSEC 有効・証明書透明性監視・HSTS preload。
- [ ] **インフラ IAM**: 管理コンソール MFA・最小権限・管理面の分離・監査ログ。
- [ ] **鍵**: `DUCKNET_*_KEY` を VM 外(KMS/Vault)に。ディスクに置かない。
- [ ] **OS**: systemd ハードニング + `LimitNOFILE`/`MemoryMax`/`TasksMax`、`chattr +i`/読取専用マウント(docs/hardening.md)。
- [ ] **検知**: ダッシュボード(`/api/shield/events` / `/api/shield/tamper`)を定期監視。`stall_detect_enabled`・改竄イベントを確認。
- [ ] **横展開抑止**: DuckNet ホストの outbound を backend のみにファイアウォール/SG で制限。
  専用低権限アカウントで起動、他システムの認証情報を同居させない。侵害疑い時は
  `DUCKNET_*_KEY` を即座にローテーション。
- [ ] **最新化**: CPython・OS を最新に。seccomp/AppArmor で syscall を絞る。

## 関連
- 配備ハードニング全般: [docs/hardening.md](hardening.md)
- 防御×設定キー一覧: [docs/defenses.md](defenses.md)
- 関連 evolution: 自己防衛 #47–#59、オリジントークン #77、迂回検知 #78、資源上限 #79。
