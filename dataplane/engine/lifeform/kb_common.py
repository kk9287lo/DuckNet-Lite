"""kb_common.py — トラブル/知識KB群の共通スコアリング・ユーティリティ
=================================================================================
各KB(pc/network/macos/linux/...)に散っていた検索スコアリングを1箇所へ集約し、
ライバルレビュー(G)の指摘を取り込んで精度を上げる:
  · 症状の **完全一致** に大加点(例: 「dns」とだけ打てば dns-failure が確実に1位)。
  · title へのマッチを重く(情報の核は title)。
  · **クエリ被覆率(query coverage)** で長さバイアスを是正。
    ※ レビューは Jaccard(hay長で正規化)を提案だが、それだと『症状が豊富な“正しい”
      プレイブック』を不当に下げうる。そこで hay 長でなく **クエリ長で正規化**し、
      『どれだけクエリを説明できたか』を測る(長さ中立で、網羅的な正答を罰しない)。
  · ASCII語(英語/コード)を日本語2-gramより重く(短い汎用grams のノイズ抑制)。

加えて fixes をステップ配列へ構造化する to_steps() を提供(指摘②)。
"""
from __future__ import annotations
import re

_REBOOT_HINT = ("再起動", "リブート", "reboot", "restart", "再投入", "電源を入れ直", "再起動で")
_CMD_RE = re.compile(r"`([^`]+)`")


def tokens(s: str) -> set:
    """日英混在を語に分解(英数字_ + 日本語2-3gram)。len>=2 のみ。"""
    s = (s or "").lower()
    toks = set(re.findall(r"[a-z0-9_]+", s))
    for run in re.findall(r"[぀-ヿ㐀-鿿ァ-ヿ]+", s):
        toks.add(run)
        for n in (2, 3):
            for i in range(len(run) - n + 1):
                toks.add(run[i:i + n])
    return {t for t in toks if len(t) >= 2}


def rank(query: str, playbooks: list, *, filt=None) -> list:
    """[(score, playbook)] を高い順で返す(全KB共通)。

    filt(p)->bool を渡すと platform/scope 等で事前フィルタできる。
    スコア(純加点・実績式を土台に G指摘①の精度改善を上乗せ):
      症状部分一致*3 + 症状**完全一致*10**(『dns』だけで dns-failure を1位に)
      + ascii一致*2 + jp一致*1 + **ascii題名一致*2**(英語/コードの題名マッチを重く)。
    ※ レビューは hay長正規化(Jaccard)を提案したが、JP 2-gram(「が失敗する」等)が
      長文題名に偶然多く含まれ“正しい短い答え”を下げる副作用が出たため、被覆率正規化と
      JP題名加点は採用せず、ASCIIを核に据える純加点に留める(回帰0で精度向上を確認)。
    """
    ql = (query or "").strip().lower()
    qt = tokens(query)
    if not qt:
        return []
    ascii_q = {t for t in qt if t.isascii()}
    jp_q = qt - ascii_q
    out = []
    for p in playbooks:
        if filt and not filt(p):
            continue
        syms = [str(s).lower() for s in p.get("symptoms", [])]
        exact = 10 if any(s and ql == s for s in syms) else 0
        substr = sum(3 for s in syms if s and s in ql)
        title_t = tokens(p.get("title", ""))
        hay_t = (title_t | tokens(" ".join(str(s) for s in p.get("symptoms", [])))
                 | tokens(p.get("category", "")) | tokens(p.get("kind", ""))
                 | tokens(" ".join(p.get("tags", [])))
                 | tokens(" ".join(str(c) for c in p.get("causes", []))))
        ascii_i = len(ascii_q & hay_t)
        jp_i = len(jp_q & hay_t)
        ascii_title = len(ascii_q & title_t)   # 英語/コードの題名一致は強い信号
        score = exact + substr + ascii_i * 2 + jp_i * 1 + ascii_title * 2
        if score > 0:
            out.append((score, p))
    out.sort(key=lambda t: (-t[0], t[1].get("id", "")))
    return out


def to_steps(fixes: list) -> list:
    """fixes(文字列リスト)を実行/表示しやすいステップ配列へ構造化する(指摘②)。
    各要素: {step, desc, command(あれば`...`内), reboot_required}。元データは非破壊。"""
    steps = []
    for i, f in enumerate(fixes or [], 1):
        text = str(f)
        cmds = _CMD_RE.findall(text)
        steps.append({
            "step": i,
            "desc": text,
            "command": cmds[0] if cmds else None,
            "commands": cmds,
            "reboot_required": any(h in text for h in _REBOOT_HINT),
        })
    return steps
