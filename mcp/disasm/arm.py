# -*- coding: utf-8 -*-
"""ARMv4T ARM モード (32bit 固定長) の逆アセンブラと参照走査 (Python 3.13 前提)。

読み取り専用 MCP (`ghidra_readonly_mcp.py`) から呼ばれ、
`ghidra_exports/memory/*.bin` の生バイト列をデコードします。
Ghidra にも Ghidra プロジェクトにも触れません (バイト列を受け取るだけ)。

対応範囲:
  - ARMv4T の ARM 命令一式 (データ処理 / ロードストア / ブロック転送 /
    分岐 / 乗算 / ハーフワード転送 / SWP / MRS・MSR / BX / SWI)
  - コプロセッサ命令は形だけ返します (GBA には FPU が無いので実用上不要)。

Thumb モード (16bit 命令) は姉妹モジュール `thumb.py` です。**同じ Program の中で
両モードが混在する**ので、どちらで読むかは呼び出し側が `arch` で指定します。

表記は ARM UAL 準拠。capstone の ARM 表記と揃えてあります
(capstone との突き合わせで検証済み)。
"""

from . import _prologue



# --- モジュール識別 (disasm/__init__.py の登録所が読む) -------------------
NAME = "arm"
DISPLAY = "ARMv4T ARM モード (32bit 固定長)"
INSTRUCTION_SIZE = 4
# ARM/Thumb に遅延スロットは無い。
HAS_DELAY_SLOTS = False

M32 = 0xFFFFFFFF

REFS_NOTE = ("PC 相対の定数プール (ldr Rd,[pc,#imm]) を辿ります。"
             "ARM は 32bit 命令ですが即値は 8bit ローテートしか持てないため、"
             "任意の 32bit アドレスは定数プールから読みます。"
             "そのプールの中身を参照先として索引しています。"
             "add Rd,pc,#imm と b / bl の飛び先も登録します。")

REFS_BLIND_SPOTS = (
    "プールから読んだ基底アドレスに後から加算する形は、"
    "「基底アドレスへの参照」としてしか出ません。",
    "mov/orr の即値を数回に分けて 32bit を組み立てる形 "
    "(mov r0,#0x08000000 / orr r0,#0x1234) は追えません。",
    "Thumb モードのコードは拾えません。arch=\"thumb\" で読み直してください。",
    "sp/fp 相対アクセスはローカル変数なので索引しません。",
)


# --- レジスタ名 / 条件コード ----------------------------------------------
_REG = ("r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
        "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc")

# 0xE (al) は表記を省略、0xF は ARMv4T では未定義。
# cs/cc は UAL では hs/lo が優先名 (hs = unsigned higher or same = carry set)。
# capstone も hs/lo で出すので、表記を揃えてある。
_COND = ("eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc",
         "hi", "ls", "ge", "lt", "gt", "le", "", "nv")

# ★条件サフィックスは常に**最後**に付く (UAL)。
#   例: stmdaeq (stm + da + eq)、andseq (and + s + eq)、strbmi (str + b + mi)。
#   「stmeqda」「andeqs」のように途中へ入れるのは誤り。

# データ処理命令 (bit 24-21)。
_DP = ("and", "eor", "sub", "rsb", "add", "adc", "sbc", "rsc",
       "tst", "teq", "cmp", "cmn", "orr", "mov", "bic", "mvn")

# 比較専用 (結果を書かない = Rd を持たない) 命令。
_DP_NO_RD = frozenset(("tst", "teq", "cmp", "cmn"))
# 第 1 オペランド (Rn) を取らない命令。
_DP_NO_RN = frozenset(("mov", "mvn"))

_SHIFT = ("lsl", "lsr", "asr", "ror")


def _r(index):
    """レジスタ番号を名前にします。"""
    return _REG[index & 0xF]


def _imm(value):
    """即値を `#0x..` 表記にします (10 未満は 10 進のまま読みやすく)。"""
    if value < 10:
        return "#{0}".format(value)
    return "#0x{0:x}".format(value)


def _hex(value):
    """32bit アドレスを '0x........' 表記にします。"""
    return "0x{0:08x}".format(value & M32)


def _sign(value, bits):
    """bits ビットの値を符号付きに広げます。"""
    sign_bit = 1 << (bits - 1)
    return (value ^ sign_bit) - sign_bit


def _cond(word):
    """条件フィールドをニーモニックの接尾辞にします。"""
    return _COND[(word >> 28) & 0xF]


def _out(mnemonic, operands="", target=None, flow=None):
    """デコード結果の共通 dict を作ります。"""
    text = mnemonic if not operands else "{0} {1}".format(mnemonic, operands)
    return {
        "mnemonic": mnemonic,
        "operands": operands,
        "text": text,
        "target": _hex(target) if target is not None else None,
        "flow": flow,
        "size": 4,
        "word": None,
    }


def _word_out(value):
    """未知語を `.word 0x........` として返します (例外は投げない)。"""
    return _out(".word", "0x{0:08x}".format(value & M32))


def _rotated_imm(word):
    """データ処理命令の 8bit ローテート即値を展開します。"""
    imm8 = word & 0xFF
    rotate = ((word >> 8) & 0xF) * 2
    if rotate == 0:
        return imm8
    return ((imm8 >> rotate) | (imm8 << (32 - rotate))) & M32


def _shifter_operand(word):
    """データ処理命令の第 2 オペランドを文字列にします。"""
    if (word >> 25) & 1:
        return _imm(_rotated_imm(word))
    rm = _r(word & 0xF)
    shift_type = (word >> 5) & 3
    if (word >> 4) & 1:
        # レジスタによるシフト量
        return "{0}, {1} {2}".format(rm, _SHIFT[shift_type], _r((word >> 8) & 0xF))
    amount = (word >> 7) & 0x1F
    if amount == 0:
        if shift_type == 0:
            return rm                       # lsl #0 = シフト無し
        if shift_type == 3:
            return "{0}, rrx".format(rm)    # ror #0 = rrx
        amount = 32                         # lsr #0 / asr #0 は 32 の意味
    return "{0}, {1} #{2}".format(rm, _SHIFT[shift_type], amount)


def _decode_dp(word, addr):
    """データ処理命令 (and/add/mov/cmp ...) をデコードします。"""
    opcode = (word >> 21) & 0xF
    set_flags = (word >> 20) & 1
    rn, rd = (word >> 16) & 0xF, (word >> 12) & 0xF
    name = _DP[opcode]
    suffix = ("s" if set_flags and name not in _DP_NO_RD else "") + _cond(word)
    operand2 = _shifter_operand(word)

    if name in _DP_NO_RD:
        return _out(name + _cond(word), "{0}, {1}".format(_r(rn), operand2))

    # add Rd,pc,#imm は「アドレスを作る」形なので実効アドレスを添える。
    if rn == 15 and not ((word >> 4) & 1) and (word >> 25) & 1 and name in ("add", "sub"):
        base = (addr + 8) & M32
        value = _rotated_imm(word)
        resolved = (base + value) & M32 if name == "add" else (base - value) & M32
        return _out(name + suffix, "{0}, pc, {1}  ; ={2}".format(
            _r(rd), _imm(value), _hex(resolved)))

    # pc を書き換える形は分岐になる。mov pc,lr は関数からの復帰。
    flow = None
    if rd == 15:
        flow = "return" if (name == "mov" and (word & 0xFFF) == 14) else "jump"

    if name in _DP_NO_RN:
        return _out(name + suffix, "{0}, {1}".format(_r(rd), operand2), flow=flow)
    return _out(name + suffix, "{0}, {1}, {2}".format(_r(rd), _r(rn), operand2),
                flow=flow)


def _decode_branch(word, addr):
    """b / bl をデコードします。飛び先は PC+8 起点。"""
    link = (word >> 24) & 1
    target = (addr + 8 + _sign(word & 0xFFFFFF, 24) * 4) & M32
    name = ("b" if not link else "bl") + _cond(word)
    return _out(name, _hex(target), target=target,
                flow="call" if link else "jump")


def _decode_bx(word):
    """bx Rn をデコードします。

    thumb.py と同じ理由で **すべて return 扱い**にします (ARMv4T の相互動作対応
    コードは `ldr rN,[pc,..]` / `bx rN` や `pop {rN}` / `bx rN` で復帰するため、
    bx lr だけを return にすると stop_at_return が効かない)。
    テールコールだった場合も、そこで直線的な流れが終わる点は同じです。
    """
    return _out("bx" + _cond(word), _r(word & 0xF), flow="return")


def _decode_mul(word):
    """乗算 (mul / mla / umull / smull ...) をデコードします。"""
    suffix = ("s" if (word >> 20) & 1 else "") + _cond(word)
    rd, rn = (word >> 16) & 0xF, (word >> 12) & 0xF
    rs, rm = (word >> 8) & 0xF, word & 0xF
    if (word >> 23) & 1:
        # 64bit 乗算: RdHi=rd, RdLo=rn
        name = ("umull", "umlal", "smull", "smlal")[(word >> 21) & 3]
        return _out(name + suffix, "{0}, {1}, {2}, {3}".format(
            _r(rn), _r(rd), _r(rm), _r(rs)))
    if (word >> 21) & 1:
        return _out("mla" + suffix, "{0}, {1}, {2}, {3}".format(
            _r(rd), _r(rm), _r(rs), _r(rn)))
    return _out("mul" + suffix, "{0}, {1}, {2}".format(_r(rd), _r(rm), _r(rs)))


def _decode_swp(word):
    """swp / swpb (アトミック交換) をデコードします。"""
    name = ("swpb" if (word >> 22) & 1 else "swp") + _cond(word)
    return _out(name, "{0}, {1}, [{2}]".format(
        _r((word >> 12) & 0xF), _r(word & 0xF), _r((word >> 16) & 0xF)))


def _decode_psr(word):
    """mrs / msr (プログラムステータスレジスタ) をデコードします。"""
    psr = "spsr" if (word >> 22) & 1 else "cpsr"
    if (word >> 21) & 1:
        # msr。即値形とレジスタ形がある。
        if (word >> 25) & 1:
            source = _imm(_rotated_imm(word))
        else:
            source = _r(word & 0xF)
        fields = ""
        for bit, ch in ((19, "f"), (18, "s"), (17, "x"), (16, "c")):
            if (word >> bit) & 1:
                fields += ch
        return _out("msr" + _cond(word), "{0}_{1}, {2}".format(psr, fields or "c", source))
    return _out("mrs" + _cond(word), "{0}, {1}".format(_r((word >> 12) & 0xF), psr))


def _decode_halfword(word, addr):
    """ハーフワード / 符号付きバイト転送 (ldrh / strh / ldrsb / ldrsh)。"""
    load = (word >> 20) & 1
    pre = (word >> 24) & 1
    up = (word >> 23) & 1
    immediate = (word >> 22) & 1
    writeback = (word >> 21) & 1
    rn, rd = (word >> 16) & 0xF, (word >> 12) & 0xF
    kind = (word >> 5) & 3
    if kind == 0:
        return _word_out(word)              # SWP 側で処理済みのはず
    # ARMv4T でストアできるのはハーフワードだけ。L=0 で sb/sh の枠は
    # ARMv5TE の ldrd/strd で、v4T には存在しない (未定義)。
    if not load and kind != 1:
        return _word_out(word)
    name = ("", "h", "sb", "sh")[kind]
    mnemonic = ("ldr" if load else "str") + name
    if not pre and writeback:
        mnemonic += "t"                     # 後置 + W=1 はユーザーモードアクセス
    mnemonic += _cond(word)

    if immediate:
        offset = ((word >> 4) & 0xF0) | (word & 0xF)
        operand = _imm(offset) if offset else None
    else:
        operand = _r(word & 0xF)

    sign = "" if up else "-"
    if pre:
        if operand is None:
            body = "[{0}]".format(_r(rn))
        else:
            body = "[{0}, {1}{2}]{3}".format(_r(rn), sign, operand,
                                             "!" if writeback else "")
    else:
        body = "[{0}], {1}{2}".format(_r(rn), sign, operand or "#0")
    return _out(mnemonic, "{0}, {1}".format(_r(rd), body))


def _decode_single_transfer(word, addr):
    """ldr / str (ワード / バイト) をデコードします。"""
    load = (word >> 20) & 1
    writeback = (word >> 21) & 1
    byte = (word >> 22) & 1
    up = (word >> 23) & 1
    pre = (word >> 24) & 1
    register_offset = (word >> 25) & 1
    rn, rd = (word >> 16) & 0xF, (word >> 12) & 0xF

    mnemonic = ("ldr" if load else "str") + ("b" if byte else "")
    # 後置インデクスで W=1 は「ユーザーモードアクセス」(ldrt/strt)。
    if not pre and writeback:
        mnemonic += "t"
    mnemonic += _cond(word)                 # 条件サフィックスは最後

    # pc 相対 = 定数プールからの読み出し。実効アドレスを添える。
    if rn == 15 and pre and not register_offset:
        offset = word & 0xFFF
        pool = ((addr + 8) + (offset if up else -offset)) & M32
        return _out(mnemonic, "{0}, [pc, {1}{2}]  ; ={3}".format(
            _r(rd), "" if up else "-", _imm(offset), _hex(pool)))

    if register_offset:
        operand = _shifter_operand(word & ~(1 << 25))
    else:
        offset = word & 0xFFF
        operand = _imm(offset) if offset else None

    sign = "" if up else "-"
    if pre:
        if operand is None:
            body = "[{0}]".format(_r(rn))
        else:
            body = "[{0}, {1}{2}]{3}".format(_r(rn), sign, operand,
                                             "!" if writeback else "")
    else:
        body = "[{0}], {1}{2}".format(_r(rn), sign, operand or "#0")

    flow = "jump" if load and rd == 15 else None
    return _out(mnemonic, "{0}, {1}".format(_r(rd), body), flow=flow)


def _block_reglist(mask):
    """ブロック転送のレジスタリストを `{r4-r6, lr}` 表記にします。"""
    parts = []
    i = 0
    while i < 16:
        if not (mask & (1 << i)):
            i += 1
            continue
        j = i
        while j + 1 < 16 and (mask & (1 << (j + 1))):
            j += 1
        if j - i >= 2:
            parts.append("{0}-{1}".format(_REG[i], _REG[j]))
        else:
            parts.extend(_REG[k] for k in range(i, j + 1))
        i = j + 1
    return "{{{0}}}".format(", ".join(parts))


def _decode_block_transfer(word):
    """ldm / stm をデコードします。push / pop の慣用形はそちらで表記します。"""
    load = (word >> 20) & 1
    writeback = (word >> 21) & 1
    psr = (word >> 22) & 1
    up = (word >> 23) & 1
    pre = (word >> 24) & 1
    rn = (word >> 16) & 0xF
    mask = word & 0xFFFF
    suffix = _cond(word)
    reglist = _block_reglist(mask)

    # sp を使う定番形は push / pop と書く (capstone もそう出す)。
    if rn == 13 and writeback and not psr:
        if load and not pre and up:
            flow = "return" if mask & (1 << 15) else None
            return _out("pop" + suffix, reglist, flow=flow)
        if not load and pre and not up:
            return _out("push" + suffix, reglist)

    # ia は既定なので表記しない (UAL / capstone と同じ)。
    mode = ("da", "", "db", "ib")[(pre << 1) | up]
    mnemonic = ("ldm" if load else "stm") + mode + suffix
    flow = "return" if load and (mask & (1 << 15)) else None
    return _out(mnemonic, "{0}{1}, {2}{3}".format(
        _r(rn), "!" if writeback else "", reglist, "^" if psr else ""), flow=flow)


def decode(word, addr):
    """ARM 命令を 1 つデコードします。"""
    cond = (word >> 28) & 0xF
    if cond == 0xF:
        # ARMv4T では未定義 (v5 以降の BLX などが入る領域)。
        return _word_out(word)

    kind = (word >> 25) & 7

    if kind in (0b000, 0b001):
        # bx は特徴的なビットパターンで先に判定する。
        if (word & 0x0FFFFFF0) == 0x012FFF10:
            return _decode_bx(word)
        if kind == 0b000 and ((word >> 4) & 0xF) == 0b1001:
            if ((word >> 23) & 0x1F) == 0b00010:
                return _decode_swp(word)
            if ((word >> 24) & 0xF) == 0b0000:
                return _decode_mul(word)
        if kind == 0b000 and (word >> 4) & 1 and (word >> 7) & 1:
            return _decode_halfword(word, addr)
        # mrs / msr は「S=0 の比較命令 (tst/teq/cmp/cmn)」の枠に同居している。
        # ARMv4T ではこの枠で有効なのは mrs / msr だけで、それ以外は未定義
        # (v6T2 以降の movw/movt がここに入るが、v4T には無いので .word にする)。
        if ((word >> 23) & 3) == 0b10 and not ((word >> 20) & 1):
            if kind == 0b000 and (word & 0x0FBF0FFF) == 0x010F0000:
                return _decode_psr(word)            # mrs Rd,cpsr/spsr
            if (word >> 21) & 1:
                return _decode_psr(word)            # msr (レジスタ形 / 即値形)
            return _word_out(word)
        return _decode_dp(word, addr)

    if kind in (0b010, 0b011):
        if kind == 0b011 and (word >> 4) & 1:
            return _word_out(word)          # 未定義命令
        return _decode_single_transfer(word, addr)

    if kind == 0b100:
        return _decode_block_transfer(word)

    if kind == 0b101:
        return _decode_branch(word, addr)

    if kind == 0b110:
        # bit22 = N (long transfer)。capstone と同じく "l" を付ける。
        name = ("ldc" if (word >> 20) & 1 else "stc")
        if (word >> 22) & 1:
            name += "l"
        return _out(name + _cond(word),
                    "p{0}, c{1}, [{2}]".format((word >> 8) & 0xF,
                                               (word >> 12) & 0xF,
                                               _r((word >> 16) & 0xF)))

    # kind == 0b111
    if (word >> 24) & 1:
        return _out("svc" + _cond(word), "#0x{0:x}".format(word & 0xFFFFFF),
                    flow="call")
    if (word >> 4) & 1:
        return _out(("mrc" if (word >> 20) & 1 else "mcr") + _cond(word),
                    "p{0}, {1}, {2}, c{3}, c{4}".format(
                        (word >> 8) & 0xF, (word >> 21) & 7,
                        _r((word >> 12) & 0xF), (word >> 16) & 0xF, word & 0xF))
    return _out("cdp" + _cond(word), "p{0}".format((word >> 8) & 0xF))


def word_at(data, offset, big_endian):
    """バイト列から 32bit 命令語を 1 つ取り出します。範囲外なら None。"""
    if offset < 0 or offset + 4 > len(data):
        return None
    return int.from_bytes(data[offset:offset + 4], "big" if big_endian else "little")


def to_words(data, big_endian):
    """バイト列を 32bit 語の array に変換します (4 バイト境界で切り捨て)。"""
    import array
    import sys

    words = array.array("I")
    limit = len(data) - (len(data) % 4)
    words.frombytes(bytes(data[:limit]))
    if big_endian != (sys.byteorder == "big"):
        words.byteswap()
    return words


def build_ref_index(data, base_addr, big_endian, window=None):
    """メモリイメージを走査し、コードが参照しているアドレスの索引を作ります。

    返り値: {参照先アドレス(int): [(参照命令アドレス, form, プール/命令アドレス), ...]}

        ldr Rd,[pc,#imm]  → pool = PC+8±imm、その 32bit 値が参照先
        add Rd,pc,#imm    → 計算されたアドレスそのものが参照先
        b / bl            → 飛び先を参照先として登録

    ★既知の盲点は REFS_BLIND_SPOTS を参照。
    """
    index = {}
    words = to_words(data, big_endian)
    count = len(words)
    size = len(data)
    order = "big" if big_endian else "little"

    for i in range(count):
        w = words[i]
        if (w >> 28) & 0xF == 0xF:
            continue                        # ARMv4T では未定義
        addr = base_addr + i * 4
        kind = (w >> 25) & 7

        if kind == 0b010 and ((w >> 16) & 0xF) == 15 and (w >> 24) & 1 and (w >> 20) & 1:
            # ldr Rd,[pc,#imm] — プールの中身が参照先
            offset = w & 0xFFF
            pool = (addr + 8 + (offset if (w >> 23) & 1 else -offset)) & M32
            off = pool - base_addr
            if 0 <= off and off + 4 <= size:
                value = int.from_bytes(data[off:off + 4], order)
                index.setdefault(value, []).append((addr, "ldr@pc", pool))
        elif kind == 0b001 and ((w >> 16) & 0xF) == 15:
            # add/sub Rd,pc,#imm — 計算結果そのものがアドレス
            opcode = (w >> 21) & 0xF
            if opcode in (2, 4):            # sub, add
                imm8 = w & 0xFF
                rotate = ((w >> 8) & 0xF) * 2
                value = imm8 if rotate == 0 else (
                    ((imm8 >> rotate) | (imm8 << (32 - rotate))) & M32)
                resolved = ((addr + 8 + value) if opcode == 4
                            else (addr + 8 - value)) & M32
                index.setdefault(resolved, []).append((addr, "add@pc", resolved))
        elif kind == 0b101:
            tgt = (addr + 8 + _sign(w & 0xFFFFFF, 24) * 4) & M32
            index.setdefault(tgt, []).append(
                (addr, "bl" if (w >> 24) & 1 else "b", addr))

    return index


def pc_relative_targets(data, base_addr, big_endian, lo_addr, hi_addr):
    """[lo_addr, hi_addr] の命令が読む PC 相対プールの番地を {番地: 幅} で返します。

    「その番地はコードではなくデータである」と判定するための材料です。
    ARM の PC 相対ロードは 32bit 幅なので、幅は 4 固定になります。
    """
    out = {}
    lo_off = max(0, lo_addr - base_addr)
    hi_off = min(len(data) - 4, hi_addr - base_addr)
    if hi_off < lo_off:
        return out
    lo_off -= lo_off % 4
    order = "big" if big_endian else "little"
    for off in range(lo_off, hi_off + 1, 4):
        w = int.from_bytes(data[off:off + 4], order)
        if (w >> 28) & 0xF == 0xF:
            continue
        addr = base_addr + off
        if ((w >> 25) & 7) == 0b010 and ((w >> 16) & 0xF) == 15 \
                and (w >> 24) & 1 and (w >> 20) & 1:
            offset = w & 0xFFF
            out[(addr + 8 + (offset if (w >> 23) & 1 else -offset)) & M32] = 4
    return out


def is_unconditional_flow_end(word):
    """その命令の後ろが到達不能になるかを返します。

    無条件の b / bx / mov pc,lr / pop {..,pc} は無条件に飛ぶので、直後が
    分岐先になっていなければ到達不能 = データ (定数プール) の可能性があります。
    """
    if (word >> 28) & 0xF != 0xE:
        return False                        # 条件付きなら落ちてくる可能性がある
    if ((word >> 25) & 7) == 0b101 and not ((word >> 24) & 1):
        return True                         # b (bl は戻ってくる)
    if (word & 0x0FFFFFF0) == 0x012FFF10:
        return True                         # bx
    if ((word >> 25) & 7) == 0b100 and (word >> 20) & 1 and (word & (1 << 15)):
        return True                         # ldm ..,{..,pc}
    if ((word >> 21) & 0xF) == 13 and ((word >> 12) & 0xF) == 15 \
            and ((word >> 25) & 7) in (0b000, 0b001):
        return True                         # mov pc,..
    return False


# ---------------------------------------------------------------------------
# 関数入口の推定 (find_function_entry のアーキ側フック)
# ---------------------------------------------------------------------------

def _popcount(value):
    """立っているビットの本数を返します。"""
    return bin(value & 0xFFFF).count("1")


def _is_push(word):
    """stmfd sp!,{..} = stmdb sp!,{..} かどうか (0xE92D....)。"""
    return (word & 0x0FFF0000) == 0x092D0000


def _is_entry_push(word):
    """**関数入口らしい** push か = lr も積む stmfd sp!,{..,lr}。"""
    return _is_push(word) and (word & 0x4000)


def _is_pop(word):
    """ldmfd sp!,{..} = ldmia sp!,{..} かどうか (0xE8BD....)。"""
    return (word & 0x0FFF0000) == 0x08BD0000


def _is_func_end(word):
    """関数の終わりになりうるか。

    ARM では `ldmfd sp!,{..,pc}` (pc を戻す) と `bx lr` (0xE12FFF1E) 、
    `mov pc,lr` (0xE1A0F00E) が復帰です。
    """
    if _is_pop(word) and (word & 0x8000):
        return True
    # ★`bx lr` だけを復帰とみなす (`bx Rm` は間接呼び出しにも使われるため)。
    if (word & 0x0FFFFFFF) == 0x012FFF1E:            # bx lr
        return True
    if (word & 0x0FFFFFFF) == 0x01A0F00E:            # mov pc,lr
        return True
    return False


def _stack_regs(word):
    """stm / ldm が触るレジスタ本数。"""
    return _popcount(word & 0xFFFF)


def find_function_entry(data, base_addr, big_endian, address,
                        max_back=4096, max_forward=8192):
    """指定アドレスを含む ARM 関数の入口を命令列から判定します。

    `stmfd sp!,{..,lr}` (0xE92D....) を入口の目印にし、`ldmfd sp!,{..,pc}` /
    `bx lr` までを 1 関数とみなします。**積んだ本数と戻した本数が一致するか**で
    誤りを弾きます。その入口を指す `bl` / 関数ポインタも数えて返します。
    """
    words = to_words(data, big_endian)
    count = len(words)

    def refs(entry):
        return _find_callers(data, words, base_addr, entry, big_endian)

    spec = _prologue.PrologueSpec(
        size=4,
        read=lambda i: words[i],
        is_push=_is_push,
        is_pop=_is_pop,
        is_end=_is_func_end,
        count_regs=_stack_regs,
        text=lambda w, a: decode(w, a)["text"],
        is_entry_push=_is_entry_push,
        find_refs=refs,
    )
    return _prologue.find_entry(spec, count, base_addr, address,
                                max_back=max_back, max_forward=max_forward)


def _find_callers(data, words, base_addr, entry, big_endian):
    """その入口を指す bl / b と関数ポインタを数えます。"""
    calls = []
    pointers = []
    for i, word in enumerate(words):
        if (word & 0x0E000000) != 0x0A000000:        # b / bl
            continue
        addr = base_addr + i * 4
        offset = word & 0xFFFFFF
        if offset & 0x800000:
            offset -= 0x1000000
        if ((addr + 8 + offset * 4) & M32) == entry:
            calls.append(_hex(addr))
            if len(calls) >= 32:
                break

    order = "big" if big_endian else "little"
    start = (-base_addr) % 4
    for off in range(start, len(data) - 3, 4):
        if int.from_bytes(data[off:off + 4], order) == (entry & M32):
            pointers.append(_hex(base_addr + off))
            if len(pointers) >= 32:
                break
    return {"total": len(calls) + len(pointers), "bl": calls,
            "pointers": pointers}
