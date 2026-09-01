"""
i18n.py — サーバ側の最小多言語(日本語/英語)。依存ゼロ。
====================================================================================
ダッシュボードはクライアント JS で日英を切替えるが、サーバが生成する文言(遮断ページ・CLI
出力等)は env `DUCKNET_LANG`(ja|en、既定 ja)で言語を選ぶ。文言は key→{ja,en} のカタログ。
正直: 翻訳は主要文言のみ。未登録 key は ja(無ければ key 自身)へフォールバック。
"""
from __future__ import annotations

import os


def _locale_lang() -> str:
    """OS ロケール/環境から推定した言語(evolution #84)。英語ロケールなら 'en'、それ以外/不明は ''。
    日本語環境を主としつつ、英語環境では env 設定なしでも自動で英語にするための判定。"""
    try:
        import locale
        srcs = [os.environ.get("LC_ALL"), os.environ.get("LANG"), os.environ.get("LANGUAGE")]
        try:
            srcs.append(locale.getlocale()[0] or "")   # Windows/mac の OS ロケールも見る
        except Exception:
            pass
        for s in srcs:
            s = (s or "").lower()
            if s.startswith("en") or "english" in s or "_us" in s or "_gb" in s:
                return "en"
    except Exception:
        pass
    return ""


def lang() -> str:
    """現在のサーバ言語。優先順: ① env DUCKNET_LANG(明示・en* で英語)② OS ロケール(英語なら en)
    ③ 既定 ja(製品の主言語=日本語環境に最適化、不明時も ja)。英語環境は env 無しでも自動で en。"""
    v = os.environ.get("DUCKNET_LANG", "").strip().lower()
    if v:
        return "en" if v.startswith("en") else "ja"
    return _locale_lang() or "ja"


# key -> {ja, en}。{...} を含む文言は t(..., **fmt) で format する。
_M = {
    # 遮断ページ(end-user 向け)
    "block.title": {"ja": "アクセス遮断", "en": "Access blocked"},
    "block.received.h": {"ja": "解除リクエストを受け付けました",
                         "en": "Your unblock request was received"},
    "block.received.p": {"ja": "管理者の審査後に解除される場合があります。",
                         "en": "It may be lifted after administrator review."},
    "block.pending.h": {"ja": "解除リクエスト 審査中", "en": "Unblock request — under review"},
    "block.pending.p": {"ja": "申立は受理済みです。審査をお待ちください。",
                        "en": "Your request was accepted. Please wait for review."},
    "block.appeal.h": {"ja": "解除をリクエストしますか?", "en": "Request an unblock?"},
    "block.appeal.p": {"ja": "自動防御により遮断されています。誤遮断と思われる場合は理由を添えて"
                             "解除を申請できます。",
                       "en": "You are blocked by automated defense. If this is a false positive, "
                             "you may request an unblock with a reason."},
    "block.appeal.reason": {"ja": "理由(任意)", "en": "Reason (optional)"},
    "block.appeal.submit": {"ja": "解除をリクエスト", "en": "Request unblock"},
    "block.blocked.h": {"ja": "アクセスが一時的に遮断されています",
                        "en": "Access temporarily blocked"},
    "block.blocked.p": {"ja": "自動防御により、あなたの接続元は一時的にブロックされています。",
                        "en": "Your connection has been temporarily blocked by automated defense."},
    "block.blocked.when": {"ja": "解除リクエストは約 {after} 秒後に可能になります"
                                 "(残りBAN時間: 約 {remain} 秒)。",
                           "en": "An unblock request will be available in about {after}s "
                                 "(ban remaining: about {remain}s)."},
    # エンジン status() の note(API/可視化で出る要約。個別判定 reason は内部診断ゆえ対象外)
    "status.note": {"ja": "L7アプリ層防御(OS非侵襲)。L3/L4ボリューメトリックは対象外。防御専用。",
                    "en": "L7 application-layer defense (OS-non-invasive). L3/L4 volumetric is out of "
                          "scope. Defensive only."},
}


def t(key: str, lang_: str = "", **fmt) -> str:
    """key の文言を現在(または指定)言語で返す。未登録は ja→key へフォールバック。fmt で format。"""
    lg = lang_ or lang()
    m = _M.get(key, {})
    s = m.get(lg) or m.get("ja") or key
    return s.format(**fmt) if fmt else s
