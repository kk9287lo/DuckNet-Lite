# ネイティブ高速化の継ぎ目(evolution #1 — ハイブリッド・データプレーン)

> 先に正直なところを。本リポジトリは純 Python(stdlib のみ)で完結し、ネイティブバイナリは同梱せず、
> Rust/eBPF の速度をこの環境で実測してもいません。ここに書くのは、重い計算ループだけを後からネイティブへ
> 差し替えられる継ぎ目(seam)の設計と、その差し込み手順です。継ぎ目が実際に end-to-end で動くことは
> `tests/test_logio.py` で検証済み(install→使用→例外 fallback→clear→revert)。Rust 本体のビルド・等価検証・
> 実測は、rustc のある環境で行ってください。

## 思想: コントロールプレーン(Python) / データプレーン(native)

- Python はコントロールプレーン。管理ダッシュボード・設定・シグネチャの管理・AST 検証・運用を担います。
- native はデータプレーン。一番重いホットループ(`shannon_entropy` / `prescan_suspicious`)だけを
  Rust(PyO3/cdylib)や Cython に切り出して差し替えます。
- 純 Python が常に動く。native が無くても壊れても、`accel` は純 Python 実装へ自動でフォールバックします
  (`tests` で実証)。防御性能を一切落とさずに「あれば速い」を実現します。

## 継ぎ目の API(`dataplane/engine/core/accel.py`)

```python
from dataplane.engine.core import accel

accel.set_native_override("shannon_entropy", fast_fn)   # 検証済みネイティブを差し込む
accel.native_override_active("shannon_entropy")          # → True
accel.shannon_entropy(data)                              # 以後 fast_fn が使われる
accel.clear_native_override("shannon_entropy")           # 即 revert（純Pythonへ）
```

- `set_native_override(name, fn)` は実行時に差し替え、`clear_native_override` で即座に戻せます。
- `shannon_entropy` / `prescan_suspicious` は override を `try/except` で呼び、例外時は純 Python へフォールバックします
  (native がクラッシュしても防御は止まりません)。
- パッケージ済みバイナリ(`ducknet_accel.*.pyd/.so`)が `import` できる場合は自動採用します。これはインストール先
  (コード本体と同一の信頼境界)にのみ置いてください(任意ビルド、同梱しません)。

## Rust(cdylib)を差し込むレシピ(rustc のある環境で)

1. 等価な Rust 実装を書く。例(シャノンエントロピー。概念雛形なのでビルド検証は必須):

   ```rust
   // prescan.rs — cdylib。純Python と *同一の数式* を実装すること。
   #[no_mangle]
   pub extern "C" fn shannon_entropy(ptr: *const u8, len: usize) -> f64 {
       let data = unsafe { std::slice::from_raw_parts(ptr, len) };
       if data.is_empty() { return 0.0; }
       let mut freq = [0u32; 256];
       for &b in data { freq[b as usize] += 1; }
       let n = data.len() as f64;
       // H = log2(n) - (1/n) Σ c·log2(c)
       let s: f64 = freq.iter().filter(|&&c| c > 0)
           .map(|&c| (c as f64) * (c as f64).log2()).sum();
       n.log2() - s / n
   }
   ```
   ```bash
   rustc -O --crate-type cdylib prescan.rs -o ducknet_accel.so   # 要 rustc
   ```

2. ctypes でロードし、純 Python と等価か検証してから差し込む(不一致なら採用しない):

   ```python
   import ctypes
   from dataplane.engine.core import accel
   lib = ctypes.CDLL("./ducknet_accel.so")
   lib.shannon_entropy.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
   lib.shannon_entropy.restype = ctypes.c_double

   def native(data):
       b = data if isinstance(data, (bytes, bytearray)) else str(data).encode()
       return lib.shannon_entropy(b, len(b))

   # ★等価検証(実コーパスで純Pythonと一致するもののみ採用)
   import os
   ok = all(abs(native(s) - accel._py_shannon_entropy(s)) < 1e-9
            for s in (b"", b"a", os.urandom(64), b"aaaa", b"hello world"))
   if ok:
       accel.set_native_override("shannon_entropy", native)   # ctypes 呼出し中は GIL 解放
   ```

   - 検証が先、が鉄則です。純 Python と値が一致しないネイティブは採用しません(壊れた高速化は遅さより危険)。
     一致したものだけ `set_native_override` し、問題が出たら `clear` で即戻します。

## eBPF/XDP について(線引き)

「悪性パケットを NIC ドライバ層で 444 Drop」は魅力的ですが、本プロジェクトの鉄則と衝突します。

- カーネルへバイトコードを注入する時点で「OS 非侵襲」の真逆になります。要 root・Linux 限定・stdlib 外です。
- これは DuckNet(依存ゼロ・OS 非侵襲の L7 前衛)ではなく、別レイヤ/別コンポーネントとして分離すべきものです。
  「Python のガワのまま Cloudflare 速度」は誇張であり、本書では約束しません。
- L3/L4 ボリューメトリックはもともとネットワーク層(Anycast/ISP/クラウド DDoS)の領域という、README の対応範囲に従います。
  eBPF はその「別レイヤ」の任意拡張として扱ってください。

## まとめ

- 継ぎ目は実在して動きます(テストで実証)。Rust/Cython は任意・可逆・検証付きで差し込めます。
- 本リポジトリは純 Python で完結し、ネイティブは同梱しません。速度は実測してから語ります。
- eBPF は鉄則(OS 非侵襲)の外にあり、別コンポーネントです。誇張せず、線を引いて拡張します。
