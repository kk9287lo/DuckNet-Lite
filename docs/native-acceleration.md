# ネイティブ高速化の継ぎ目（evolution #1 — ハイブリッド・データプレーン）

> 正直に先に。**本リポジトリは純Python(stdlibのみ)で完結し、ネイティブバイナリは同梱せず、
> Rust/eBPF の速度をこの環境で実測してもいません。** ここに書くのは「重い計算ループだけを
> 後からネイティブへ差し替えられる継ぎ目（seam）」の設計と、その差し込み手順です。
> 継ぎ目が *実際に end-to-end で動く* ことは `tests/test_logio.py` で検証済み（install→使用→
> 例外fallback→clear→revert）。Rust 本体のビルド・等価検証・実測は、rustc のある環境で行うこと。

## 思想：コントロールプレーン(Python) / データプレーン(native)

- **Python＝コントロールプレーン**：管理ダッシュボード・設定・シグネチャの管理・AST検証・運用。
- **native＝データプレーン**：一番重いホットループ（`shannon_entropy` / `prescan_suspicious`）
  だけを Rust(PyO3/cdylib) や Cython に切り出して差し替える。
- **純Pythonが常に動く**：native が無くても・壊れても、`accel` は純Python実装へ自動フォールバック
  （`tests` で実証）。防御性能を1ミリも落とさずに「あれば速い」を実現する。

## 継ぎ目の API（`dataplane/engine/core/accel.py`）

```python
from dataplane.engine.core import accel

accel.set_native_override("shannon_entropy", fast_fn)   # 検証済みネイティブを差し込む
accel.native_override_active("shannon_entropy")          # → True
accel.shannon_entropy(data)                              # 以後 fast_fn が使われる
accel.clear_native_override("shannon_entropy")           # 即 revert（純Pythonへ）
```

- `set_native_override(name, fn)` は実行時に差し替え、`clear_native_override` で**即可逆**。
- `shannon_entropy` / `prescan_suspicious` は override を `try/except` で呼び、**例外時は純Python**へ
  フォールバック（native のクラッシュで防御が止まらない）。
- パッケージ済みバイナリ（`chickennet_accel.*.pyd/.so`）が `import` できる場合は自動採用。
  これは**インストール先＝コード本体と同一信頼境界**にのみ置く（任意ビルド、同梱しない）。

## Rust(cdylib)を差し込むレシピ（rustc のある環境で）

1. **等価な Rust 実装を書く**。例（シャノンエントロピー、概念雛形・要ビルド検証）:

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
   rustc -O --crate-type cdylib prescan.rs -o chickennet_accel.so   # 要 rustc
   ```

2. **ctypes でロードし、純Python と等価か検証してから差し込む**（不一致なら採用しない）:

   ```python
   import ctypes
   from dataplane.engine.core import accel
   lib = ctypes.CDLL("./chickennet_accel.so")
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

   - **検証ファースト**が鉄則。純Pythonと値が一致しないネイティブは採用しない（壊れた高速化は
     遅さより危険）。一致したものだけ `set_native_override`、問題が出たら `clear` で即戻す。

## eBPF/XDP について（正直な線引き）

「悪性パケットを NIC ドライバ層で 444 Drop」は魅力的だが、**本プロジェクトの鉄則と衝突する**：

- カーネルへバイトコードを注入する＝**「OS非侵襲」の真逆**。要 root・Linux 限定・stdlib 外。
- これは "ChickenNet(依存ゼロ・OS非侵襲の L7 前衛)" ではなく、**別レイヤ/別コンポーネント**として
  分離すべきもの。"Python のガワのまま Cloudflare 速度" は誇張であり、本書では約束しない。
- L3/L4 ボリューメトリックは元来ネットワーク層(Anycast/ISP/クラウドDDoS)の領域、という
  README の正直な適用範囲に従う。eBPF はその「別レイヤ」の任意拡張として扱うこと。

## まとめ

- 継ぎ目は**実在し、動く**（テストで実証）。Rust/Cython は **任意・可逆・検証付き**で差し込める。
- 本リポジトリは**純Pythonで完結**し、ネイティブは同梱しない。速度は実測してから語る。
- eBPF は鉄則(OS非侵襲)外＝別コンポーネント。誇張せず、線を引いて拡張する。
