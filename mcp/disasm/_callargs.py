# -*- coding: utf-8 -*-
"""呼び出し直前の引数レジスタを復元する共通ロジック (Python 3.13 前提)。

`list_call_sites` の骨格をアーキ間で共有します。`_prologue.py` と同じ考え方で、
アーキ側は「この命令はどのレジスタに何を入れるか」という**判定だけ**を渡します。

何を解く道具か:

    疑似 C が `FUN_801a1a0c(param_1,3)` のように引数を落とすと、3 番目の引数が
    何かは逆アセンブルで呼び出し直前の `addiu $a2, $zero, 1` を見るまで分かり
    ません。初期化処理やテーブル駆動のコードでは、この**呼び出し時の定数**が
    解析の要になります。そこを毎回手読みしないための道具です。

判定の考え方 (MIPS 実装で確立したもの):

1. 呼び出し命令から**後ろ向き**に max_back 命令まで見る。ただし
   **直前の呼び出しより先には行かない** (引数レジスタは呼び出しで壊れるため)
2. 集めた命令を**実行順**に並べ、最後に**遅延スロット**を足す
   (`jal` の次の 1 命令は呼び出しより先に実行される = 引数設定の定位置)
3. 各レジスタの状態を前向きに畳み込み、`imm` / `address` / `runtime` /
   `inherited` の別を付ける

★**「不明」を「0」と言わないこと**がこの道具の肝です。追えなかったものは
  必ず kind="runtime" / "inherited" として理由付きで返し、値を捏造しません。
"""


def _hex(value):
    """32bit 値を '0x........' 表記にします。"""
    return "0x{0:08x}".format(value & 0xFFFFFFFF)


class CallArgsSpec(object):
    """アーキ固有の判定をまとめたものです。"""

    def __init__(self, size, arg_regs, reg_name, effect, is_call, text,
                 delay_slots=0, is_branch=None, zero_reg=None):
        """各判定を受け取ります。

        size          : 命令長 (バイト)
        arg_regs      : 引数レジスタ番号のタプル (MIPS なら $a0..$a3 = 4,5,6,7)
        reg_name(n)   : レジスタ番号 -> 表示名 ("$a0")
        effect(w)     : 命令 1 語の効果 (下の「効果の形」を参照)
        is_call(w)    : 呼び出し命令か (引数レジスタを壊す命令か)
        text(w, addr) : 逆アセンブル文字列
        delay_slots   : 制御移行命令の後ろにある遅延スロット命令数 (MIPS は 1)
        is_branch(w)  : 条件分岐か (窓の中にあると実行されない命令が混じる)
        zero_reg      : 常に 0 のレジスタ番号 (MIPS の $zero = 0)。無ければ None

        効果の形 (effect が返すタプル。触らない命令は None):

            ("imm",     dest, value)            即値をそのまま入れる
            ("hi",      dest, value)            上位 16bit だけ入れる (lui)
            ("combine", dest, src, delta, form) src の値に delta を足す
            ("copy",    dest, src)              src をそのまま写す
            ("load",    dest, base, offset, width) メモリから読む (実行時)
            ("clobber", dest, why)              追えない形で書き換える
        """
        self.size = size
        self.arg_regs = tuple(arg_regs)
        self.reg_name = reg_name
        self.effect = effect
        self.is_call = is_call
        self.text = text
        self.delay_slots = int(delay_slots or 0)
        self.is_branch = is_branch or (lambda w: False)
        self.zero_reg = zero_reg


def window_start(spec, words, index, max_back):
    """引数を追ってよい範囲の先頭 index を返します。

    **直前の呼び出しより先は見ません。** 呼び出しを跨ぐと引数レジスタは
    壊れているので、そこで拾った値は嘘になります。戻り値は
    (先頭 index, 打ち切った理由, 直前の呼び出し index or None)。
    """
    lowest = max(0, index - int(max_back))
    j = index - 1
    while j >= lowest:
        if spec.is_call(words[j]):
            # 呼び出しの遅延スロットは**その呼び出しの**引数設定なので含めない。
            return (min(index, j + 1 + spec.delay_slots),
                    "previous_call", j)
        j -= 1
    return (lowest, "max_back", None)


def _state_imm(value, addr, text, kind="imm"):
    """定数が確定した状態を作ります。"""
    return {"kind": kind, "value": value & 0xFFFFFFFF, "set_at": _hex(addr),
            "text": text}


def resolve_at(spec, words, base_addr, index, max_back=24):
    """呼び出し命令 (index) の時点での引数レジスタの状態を返します。

    返り値: {"args": [{...}, ...], "window_start": "0x...",
             "window_reason": ..., "notes": [...]}

    args はレジスタ 1 本につき 1 件で、kind は次のいずれかです:

      imm       … 即値 (定数)。value に整数が入る
      address   … lui + 下位 16bit で組み立てた**アドレス定数**
      runtime   … 実行時に決まる (メモリから読む / 追えない演算)
      inherited … 窓の中で 1 度も書かれていない (呼び出し前から持ち回り)
    """
    start, reason, prev_call = window_start(spec, words, index, max_back)
    order = list(range(start, index))
    # ★遅延スロットは呼び出しより**先に**実行される。ここを飛ばすと
    #   `jal` の直後に置かれた引数設定 (gcc の定型) を丸ごと落とす。
    for k in range(1, spec.delay_slots + 1):
        if index + k < len(words):
            order.append(index + k)

    regs = {}
    branches = []
    if spec.zero_reg is not None:
        regs[spec.zero_reg] = {"kind": "imm", "value": 0, "set_at": None,
                               "text": "$zero は常に 0"}

    for j in order:
        word = words[j]
        addr = base_addr + j * spec.size
        if spec.is_branch(word):
            branches.append(_hex(addr))
        eff = spec.effect(word)
        if not eff:
            continue
        kind = eff[0]
        text = spec.text(word, addr)

        if kind == "imm":
            regs[eff[1]] = _state_imm(eff[2], addr, text)
        elif kind == "hi":
            regs[eff[1]] = {"kind": "hi", "value": eff[2] & 0xFFFFFFFF,
                            "set_at": _hex(addr), "text": text}
        elif kind == "combine":
            _dest, src, delta, form = eff[1], eff[2], eff[3], eff[4]
            base = regs.get(src)
            if base is None:
                regs[_dest] = {"kind": "runtime", "value": None,
                               "set_at": _hex(addr), "text": text,
                               "why": "{0} の値が窓の外で決まっています。".format(
                                   spec.reg_name(src))}
            elif base["kind"] == "hi":
                regs[_dest] = {"kind": "address",
                               "value": (base["value"] + delta) & 0xFFFFFFFF,
                               "set_at": _hex(addr), "text": text,
                               "form": form, "hi_at": base["set_at"]}
            elif base["kind"] in ("imm", "address"):
                regs[_dest] = {"kind": base["kind"],
                               "value": (base["value"] + delta) & 0xFFFFFFFF,
                               "set_at": _hex(addr), "text": text}
            else:
                regs[_dest] = {"kind": "runtime", "value": None,
                               "set_at": _hex(addr), "text": text,
                               "why": "元になる {0} が実行時の値です。".format(
                                   spec.reg_name(src))}
        elif kind == "copy":
            base = regs.get(eff[2])
            if base is None:
                regs[eff[1]] = {"kind": "runtime", "value": None,
                                "set_at": _hex(addr), "text": text,
                                "why": "{0} の値が窓の外で決まっています。".format(
                                    spec.reg_name(eff[2]))}
            else:
                copied = dict(base)
                copied["set_at"] = _hex(addr)
                copied["text"] = text
                regs[eff[1]] = copied
        elif kind == "load":
            _dest, base_reg, offset, width = eff[1], eff[2], eff[3], eff[4]
            src = regs.get(base_reg)
            state = {"kind": "runtime", "value": None, "set_at": _hex(addr),
                     "text": text, "width": width,
                     "why": "メモリから読んだ値です (実行時に決まります)。"}
            # ★"hi" (lui だけ済んだ状態) も解く。`lui $t0,0x8002` +
            #   `lw $a0,0x10($t0)` は最頻出の形で、ここを落とすと
            #   「どこから読んだか」が毎回 $t0+0x10 になって役に立たない。
            if src is not None and src["kind"] in ("address", "imm", "hi"):
                state["load_from"] = _hex(src["value"] + offset)
            else:
                state["load_from"] = "{0}{1:+#x}".format(
                    spec.reg_name(base_reg), offset)
            regs[_dest] = state
        elif kind == "clobber":
            regs[eff[1]] = {"kind": "runtime", "value": None,
                            "set_at": _hex(addr), "text": text,
                            "why": eff[2] if len(eff) > 2 else
                                   "追えない形で書き換えています。"}

    args = []
    for reg in spec.arg_regs:
        state = regs.get(reg)
        if state is None or state["kind"] == "hi":
            args.append({
                "reg": spec.reg_name(reg),
                "kind": "inherited",
                "value": None,
                "set_at": None,
                "text": None,
                "why": ("この窓では 1 度も書かれていません。"
                        "呼び出し元から持ち回っている値 (疑似 C の param_N) か、"
                        "窓の外で決まっています。"
                        if state is None else
                        "上位 16bit だけが入った途中状態です "
                        "(下位を足す命令が窓の外にあります)。"),
            })
            continue
        item = {"reg": spec.reg_name(reg), "kind": state["kind"],
                "value": None, "set_at": state.get("set_at"),
                "text": state.get("text")}
        if state["kind"] in ("imm", "address"):
            value = state["value"]
            item["value"] = value
            item["hex"] = _hex(value)
            if state["kind"] == "imm":
                # 即値は符号つきでも読めるようにしておく (負の定数が実在する)。
                item["signed"] = value - 0x100000000 if value & 0x80000000 else value
            if state.get("form"):
                item["form"] = state["form"]
            if state.get("hi_at"):
                item["hi_at"] = state["hi_at"]
        else:
            item["why"] = state.get("why")
            if state.get("load_from"):
                item["load_from"] = state["load_from"]
            if state.get("width"):
                item["width"] = state["width"]
        args.append(item)

    notes = []
    if reason == "previous_call" and prev_call is not None:
        notes.append(
            "直前の呼び出し {0} より後ろだけを見ています "
            "(引数レジスタは呼び出しで壊れるため)。".format(
                _hex(base_addr + prev_call * spec.size)))
    if reason == "max_back":
        notes.append(
            "最大 {0} 命令ぶん遡りました。inherited が多いときは "
            "max_back を増やしてください。".format(max_back))
    if branches:
        notes.append(
            "窓の中に分岐があります ({0})。分岐の結果によっては"
            "ここで拾った代入が実行されないことがあります。".format(
                ", ".join(branches[:4])))
    return {"args": args, "window_start": _hex(base_addr + start * spec.size),
            "window_reason": reason, "notes": notes}
