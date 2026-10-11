# -*- coding: utf-8 -*-
"""ARMv4T Thumb (16bit 固定長) の逆アセンブラと参照走査 (Python 3.13 前提)。

読み取り専用 MCP (`ghidra_readonly_mcp.py`) から呼ばれ、
`ghidra_exports/memory/*.bin` の生バイト列をデコードします。
Ghidra にも Ghidra プロジェクトにも触れません (バイト列を受け取るだけ)。

対応範囲:
  - ARMv4T の Thumb 命令 19 フォーマットすべて (GBA / DS / 初期 ARM 機の主役)
  - BL だけは 2 つの 16bit 命令で 1 命令 (32bit) を成すため、
    `decode()` が `size: 4` を返します (共通層がその分読み飛ばします)。

ARM モード (32bit 命令) は姉妹モジュール `arm.py` です。**同じ Program の中で
両モードが混在する**ので、どちらで読むかは呼び出し側が `arch` で指定します
(GBA では実コードのほぼ全てが Thumb。ARM はエントリスタブと IRQ ハンドラ程度)。

表記は ARM UAL 準拠 (フラグを更新する形は `adds` / `movs` のように `s` を付ける)。
capstone の Thumb 表記と揃えてあります (capstone との突き合わせで検証済み)。
"""

from . import _prologue



# --- モジュール識別 (disasm/__init__.py の登録所が読む) -------------------
NAME = "thumb"
DISPLAY = "ARMv4T Thumb (16bit 固定長, BL のみ 32bit)"
INSTRUCTION_SIZE = 2
# ARM/Thumb に遅延スロットは無い。
HAS_DELAY_SLOTS = False

M32 = 0xFFFFFFFF

REFS_NOTE = ("PC 相対の定数プール (ldr Rd,[pc,#imm]) を辿ります。"
             "Thumb は 16bit 命令なので 32bit アドレスを即値に持てず、"
             "関数末尾などに置かれた定数プールから読みます。"
             "そのプールの中身を参照先として索引しています。"
             "add Rd,pc,#imm (プールのアドレス自体を作る形) と "
             "b / bl の飛び先も登録します。")

REFS_BLIND_SPOTS = (
    "プールから読んだ基底アドレスに後から加算する形 "
    "(ldr r0,[pc,#N] / add r0,r1 → 実効アドレス) は、"
    "「基底アドレスへの参照」としてしか出ません。",
    "sp 相対アクセス (ldr Rd,[sp,#imm]) はローカル変数なので索引しません。",
    "ARM モードのコードは拾えません。arch=\"arm\" で読み直してください。",
    "ldrh/ldrb で 32bit アドレスの一部だけを組み立てる形は追えません。",
)


# --- レジスタ名 ------------------------------------------------------------
# r0-r7 が Thumb の「低レジスタ」。r13/r14/r15 は慣用名で出す。
_REG = ("r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
        "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc")

# 条件分岐のサフィックス。0xE (al) と 0xF (SWI) はフォーマット 16 では別扱い。
# cs/cc は UAL では hs/lo が優先名 (hs = unsigned higher or same = carry set)。
# capstone も hs/lo で出すので、arm.py と揃えてある。
_COND = ("eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc",
         "hi", "ls", "ge", "lt", "gt", "le", "al", "nv")

# フォーマット 4 (ALU 演算) のオペコード。すべてフラグを更新する。
_ALU = ("ands", "eors", "lsls", "lsrs", "asrs", "adcs", "sbcs", "rors",
        "tst", "rsbs", "cmp", "cmn", "orrs", "muls", "bics", "mvns")


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


def pc_pool_addr(addr, imm8):
    """PC 相対ロード / add Rd,pc が指す番地を求めます。

    Thumb の PC は「その命令のアドレス + 4」。さらに **4 バイト境界へ切り下げて**
    から imm8*4 を足します。この切り下げを忘れるのが定番の間違いです
    (奇数ワード位置にある命令で 2 バイトずれる)。
    """
    return (((addr + 4) & ~3) + imm8 * 4) & M32


def _reglist(mask, extra=None):
    """レジスタリストを `{r4, r5, lr}` 表記にします。extra は lr / pc の追加。"""
    names = [_REG[i] for i in range(8) if mask & (1 << i)]
    if extra is not None:
        names.append(extra)
    return "{{{0}}}".format(", ".join(names))


def _out(mnemonic, operands="", target=None, flow=None, size=2, word=None):
    """デコード結果の共通 dict を作ります。

    size は命令長 (BL のみ 4)。word は共通層が表示する語 (既定は 16bit 表記)。
    """
    text = mnemonic if not operands else "{0} {1}".format(mnemonic, operands)
    return {
        "mnemonic": mnemonic,
        "operands": operands,
        "text": text,
        "target": _hex(target) if target is not None else None,
        "flow": flow,
        "size": size,
        "word": word,
    }


def _hword(value):
    """未知語を `.hword 0x....` として返します (例外は投げない)。"""
    return _out(".hword", "0x{0:04x}".format(value & 0xFFFF),
                word="0x{0:04x}".format(value & 0xFFFF))


# ---------------------------------------------------------------------------
# フォーマット別デコード
# ---------------------------------------------------------------------------

def _fmt1_shift(hw):
    """フォーマット 1: lsls/lsrs/asrs Rd,Rs,#imm5。"""
    op = (hw >> 11) & 3
    offset5 = (hw >> 6) & 0x1F
    rs, rd = (hw >> 3) & 7, hw & 7
    mnemonic = ("lsls", "lsrs", "asrs")[op]
    if op == 0 and offset5 == 0:
        # lsl #0 はシフトしないので UAL では movs Rd,Rs と書く (capstone も movs)。
        return _out("movs", "{0}, {1}".format(_r(rd), _r(rs)))
    if op != 0 and offset5 == 0:
        offset5 = 32                    # lsr/asr の #0 は「32 シフト」の意味
    return _out(mnemonic, "{0}, {1}, #{2}".format(_r(rd), _r(rs), offset5))


def _fmt2_addsub(hw):
    """フォーマット 2: adds/subs Rd,Rs,Rn または #imm3。"""
    immediate = (hw >> 10) & 1
    op = (hw >> 9) & 1
    operand = (hw >> 6) & 7
    rs, rd = (hw >> 3) & 7, hw & 7
    mnemonic = "subs" if op else "adds"
    third = _imm(operand) if immediate else _r(operand)
    return _out(mnemonic, "{0}, {1}, {2}".format(_r(rd), _r(rs), third))


def _fmt3_imm8(hw):
    """フォーマット 3: movs/cmp/adds/subs Rd,#imm8。"""
    op = (hw >> 11) & 3
    rd = (hw >> 8) & 7
    imm8 = hw & 0xFF
    mnemonic = ("movs", "cmp", "adds", "subs")[op]
    return _out(mnemonic, "{0}, {1}".format(_r(rd), _imm(imm8)))


def _fmt4_alu(hw):
    """フォーマット 4: レジスタ同士の ALU 演算 16 種。"""
    op = (hw >> 6) & 0xF
    rs, rd = (hw >> 3) & 7, hw & 7
    mnemonic = _ALU[op]
    if mnemonic == "rsbs":
        # ARMv4T の neg Rd,Rs は UAL では rsbs Rd,Rs,#0。
        return _out("rsbs", "{0}, {1}, #0".format(_r(rd), _r(rs)))
    return _out(mnemonic, "{0}, {1}".format(_r(rd), _r(rs)))


def _fmt5_hireg(hw, addr):
    """フォーマット 5: 上位レジスタ演算と bx。"""
    op = (hw >> 8) & 3
    h1 = (hw >> 7) & 1
    h2 = (hw >> 6) & 1
    rs = ((hw >> 3) & 7) | (h2 << 3)
    rd = (hw & 7) | (h1 << 3)
    if op == 3:
        # bx Rs は **すべて return 扱い**にする。
        # ARMv4T の Thumb では pop {pc} がモード切り替えを伴わないため、
        # 相互動作(interworking)対応のコンパイラは
        #     pop {r4} / pop {r0} / bx r0
        # を標準的な復帰列として出す。bx lr だけを
        # return にすると stop_at_return がまったく効かない。
        # bx がテールコールだった場合も、そこで直線的な流れが終わる点は同じ。
        return _out("bx", _r(rs), flow="return")
    mnemonic = ("add", "cmp", "mov")[op]
    # mov pc,Rs / add pc,Rs は分岐になる。
    flow = "jump" if rd == 15 and op != 1 else None
    return _out(mnemonic, "{0}, {1}".format(_r(rd), _r(rs)), flow=flow)


def _fmt6_pcload(hw, addr):
    """フォーマット 6: ldr Rd,[pc,#imm] — Thumb がアドレスを持ってくる主役。"""
    rd = (hw >> 8) & 7
    pool = pc_pool_addr(addr, hw & 0xFF)
    # 実効アドレスをコメントとして見せる (プールの位置がすぐ分かるように)。
    return _out("ldr", "{0}, [pc, #0x{1:x}]  ; ={2}".format(
        _r(rd), (hw & 0xFF) * 4, _hex(pool)))


def _fmt7_8_regoffset(hw):
    """フォーマット 7/8: レジスタオフセットのロード/ストア。"""
    ro, rb, rd = (hw >> 6) & 7, (hw >> 3) & 7, hw & 7
    if (hw >> 9) & 1:
        # フォーマット 8: 符号拡張つき / ハーフワード
        # ARM7TDMI データシートの ldsb/ldsh は UAL では ldrsb/ldrsh。
        mnemonic = ("strh", "ldrsb", "ldrh", "ldrsh")[(hw >> 10) & 3]
    else:
        # フォーマット 7: ワード / バイト
        mnemonic = ("str", "strb", "ldr", "ldrb")[(hw >> 10) & 3]
    return _out(mnemonic, "{0}, [{1}, {2}]".format(_r(rd), _r(rb), _r(ro)))


def _fmt9_immoffset(hw):
    """フォーマット 9: 即値オフセットの ldr/str (ワード / バイト)。"""
    byte = (hw >> 12) & 1
    load = (hw >> 11) & 1
    offset5 = (hw >> 6) & 0x1F
    rb, rd = (hw >> 3) & 7, hw & 7
    mnemonic = ("str", "ldr")[load] + ("b" if byte else "")
    # ワードアクセスはオフセットが 4 倍、バイトは等倍。
    offset = offset5 if byte else offset5 * 4
    if offset:
        return _out(mnemonic, "{0}, [{1}, {2}]".format(_r(rd), _r(rb), _imm(offset)))
    return _out(mnemonic, "{0}, [{1}]".format(_r(rd), _r(rb)))


def _fmt10_halfword(hw):
    """フォーマット 10: strh/ldrh Rd,[Rb,#imm]。オフセットは 2 倍。"""
    load = (hw >> 11) & 1
    offset = ((hw >> 6) & 0x1F) * 2
    rb, rd = (hw >> 3) & 7, hw & 7
    mnemonic = "ldrh" if load else "strh"
    if offset:
        return _out(mnemonic, "{0}, [{1}, {2}]".format(_r(rd), _r(rb), _imm(offset)))
    return _out(mnemonic, "{0}, [{1}]".format(_r(rd), _r(rb)))


def _fmt11_sprel(hw):
    """フォーマット 11: sp 相対のロード/ストア (ローカル変数)。"""
    load = (hw >> 11) & 1
    rd = (hw >> 8) & 7
    offset = (hw & 0xFF) * 4
    mnemonic = "ldr" if load else "str"
    return _out(mnemonic, "{0}, [sp, {1}]".format(_r(rd), _imm(offset)))


def _fmt12_loadaddr(hw, addr):
    """フォーマット 12: add Rd,pc,#imm / add Rd,sp,#imm。"""
    use_sp = (hw >> 11) & 1
    rd = (hw >> 8) & 7
    offset = (hw & 0xFF) * 4
    if use_sp:
        return _out("add", "{0}, sp, {1}".format(_r(rd), _imm(offset)))
    # add Rd,pc,#imm は UAL では adr Rd,<label> (capstone も adr)。
    resolved = pc_pool_addr(addr, hw & 0xFF)
    return _out("adr", "{0}, {1}".format(_r(rd), _hex(resolved)))


def _fmt13_addsp(hw):
    """フォーマット 13: add sp,#imm / sub sp,#imm (スタックフレーム)。"""
    offset = (hw & 0x7F) * 4
    if (hw >> 7) & 1:
        return _out("sub", "sp, {0}".format(_imm(offset)))
    return _out("add", "sp, {0}".format(_imm(offset)))


def _fmt14_pushpop(hw):
    """フォーマット 14: push / pop。pop {..,pc} は関数からの復帰。"""
    load = (hw >> 11) & 1
    store_lr = (hw >> 8) & 1
    mask = hw & 0xFF
    if load:
        extra = "pc" if store_lr else None
        flow = "return" if store_lr else None
        return _out("pop", _reglist(mask, extra), flow=flow)
    return _out("push", _reglist(mask, "lr" if store_lr else None))


def _fmt15_multi(hw):
    """フォーマット 15: stmia / ldmia Rb!,{...}。"""
    load = (hw >> 11) & 1
    rb = (hw >> 8) & 7
    mnemonic = "ldmia" if load else "stmia"
    return _out(mnemonic, "{0}!, {1}".format(_r(rb), _reglist(hw & 0xFF)))


def _fmt16_bcond(hw, addr):
    """フォーマット 16: 条件分岐 b<cond>。飛び先は PC+4 起点。"""
    cond = (hw >> 8) & 0xF
    target = (addr + 4 + _sign(hw & 0xFF, 8) * 2) & M32
    return _out("b" + _COND[cond], _hex(target), target=target, flow="branch")


def _fmt18_branch(hw, addr):
    """フォーマット 18: 無条件分岐 b。"""
    target = (addr + 4 + _sign(hw & 0x7FF, 11) * 2) & M32
    return _out("b", _hex(target), target=target, flow="jump")


def _fmt19_bl(hw, nxt, addr):
    """フォーマット 19: bl (16bit 命令 2 つで 1 命令)。

    前半 (0xF000-0xF7FF) がオフセット上位 11bit、後半 (0xF800-0xFFFF) が下位 11bit。
    後半が来ていなければ命令として成立しないので `.hword` を返します
    (バッファ末尾や、データを Thumb として読んでいる場合に起きる)。
    """
    if (nxt >> 11) != 0b11111:
        return _hword(hw)
    offset = (_sign(hw & 0x7FF, 11) << 12) | ((nxt & 0x7FF) << 1)
    target = (addr + 4 + offset) & M32
    word = "0x{0:04x}{1:04x}".format(nxt, hw)
    return _out("bl", _hex(target), target=target, flow="call", size=4, word=word)


def decode(word, addr):
    """Thumb 命令を 1 つデコードします。

    word は `word_at()` が返す値で、下位 16bit が対象命令、上位 16bit が
    **次の 16bit** (bl の後半を読むためだけに使う)。範囲外なら上位は 0。

    共通層が表示する `word` は 16bit 表記に揃えます (先読みぶんを見せない)。
    bl だけは 32bit 命令なので `_fmt19_bl()` が 8 桁の表記を入れます。
    """
    info = _dispatch(word & 0xFFFF, (word >> 16) & 0xFFFF, addr)
    if info.get("word") is None:
        info["word"] = "0x{0:04x}".format(word & 0xFFFF)
    return info


def _dispatch(hw, nxt, addr):
    """16bit 命令語をフォーマット別のデコーダへ振り分けます。"""
    if hw >> 11 == 0b00011:
        return _fmt2_addsub(hw)
    if hw >> 13 == 0b000:
        return _fmt1_shift(hw)
    if hw >> 13 == 0b001:
        return _fmt3_imm8(hw)
    if hw >> 10 == 0b010000:
        return _fmt4_alu(hw)
    if hw >> 10 == 0b010001:
        return _fmt5_hireg(hw, addr)
    if hw >> 11 == 0b01001:
        return _fmt6_pcload(hw, addr)
    if hw >> 12 == 0b0101:
        return _fmt7_8_regoffset(hw)
    if hw >> 13 == 0b011:
        return _fmt9_immoffset(hw)
    if hw >> 12 == 0b1000:
        return _fmt10_halfword(hw)
    if hw >> 12 == 0b1001:
        return _fmt11_sprel(hw)
    if hw >> 12 == 0b1010:
        return _fmt12_loadaddr(hw, addr)
    if hw >> 12 == 0b1011:
        # 0xB000 台は add sp / push / pop が同居する。
        if (hw >> 8) == 0xB0:
            return _fmt13_addsp(hw)
        if ((hw >> 9) & 0b11) == 0b10:
            return _fmt14_pushpop(hw)
        return _hword(hw)
    if hw >> 12 == 0b1100:
        return _fmt15_multi(hw)
    if hw >> 12 == 0b1101:
        cond = (hw >> 8) & 0xF
        if cond == 0xF:
            # 旧称 swi。UAL では svc (capstone も svc)。
            return _out("svc", _imm(hw & 0xFF), flow="call")
        if cond == 0xE:
            return _hword(hw)               # 未定義命令
        return _fmt16_bcond(hw, addr)
    if hw >> 11 == 0b11100:
        return _fmt18_branch(hw, addr)
    if hw >> 11 == 0b11110:
        return _fmt19_bl(hw, nxt, addr)
    # 0b11111 単独 = bl の後半だけ。前半が別に出ているので命令にはならない。
    return _hword(hw)


def word_at(data, offset, big_endian):
    """バイト列から命令語を取り出します。範囲外なら None。

    **下位 16bit が対象命令、上位 16bit が次の 16bit** という形で返します。
    bl (32bit) を 1 命令として組み立てるために先読みが要るためです。
    4 バイト取れないときは上位を 0 にします (bl の後半としては不正なので、
    `decode()` 側で `.hword` に落ちます)。
    """
    if offset < 0 or offset + 2 > len(data):
        return None
    order = "big" if big_endian else "little"
    low = int.from_bytes(data[offset:offset + 2], order)
    if offset + 4 <= len(data):
        high = int.from_bytes(data[offset + 2:offset + 4], order)
    else:
        high = 0
    return low | (high << 16)


def to_words(data, big_endian):
    """バイト列を 16bit 語の array に変換します (2 バイト境界で切り捨て)。

    走査対象は 4MB 級 (= 200 万命令) になるため、int のリストではなく array を使います。
    """
    import array
    import sys

    words = array.array("H")
    limit = len(data) - (len(data) % 2)
    words.frombytes(bytes(data[:limit]))
    if big_endian != (sys.byteorder == "big"):
        words.byteswap()
    return words


def build_ref_index(data, base_addr, big_endian, window=None):
    """メモリイメージを走査し、コードが参照しているアドレスの索引を作ります。

    返り値: {参照先アドレス(int): [(参照命令アドレス, form, プール/命令アドレス), ...]}

    Thumb は 16bit 命令なので 32bit 定数を即値に持てず、**PC 相対の定数プール**から
    読みます (SH-4 と同じ考え方)。そこで「プールの中身 = 参照先アドレス」として
    索引します。

        ldr Rd,[pc,#imm]  → pool = ((PC+4) & ~3) + imm8*4、その 32bit 値が参照先
        add Rd,pc,#imm    → 計算されたアドレスそのものが参照先
        b / bl            → 飛び先を参照先として登録

    3 つ目の要素には**プールのアドレス**を入れます
    (MIPS 版の「lui のアドレス」に対応する「定数がどこにあるか」の情報)。

    ★既知の盲点は REFS_BLIND_SPOTS を参照。特に「プールから読んだ基底に後から
    加算する形」は基底への参照としてしか出ません。0 件だったときは
    「参照が無い」ではなく「基底+オフセットかもしれない」を疑ってください。
    """
    index = {}
    words = to_words(data, big_endian)
    count = len(words)
    size = len(data)
    order = "big" if big_endian else "little"

    for i in range(count):
        w = words[i]
        top5 = w >> 11
        addr = base_addr + i * 2

        if top5 == 0b01001:
            # ldr Rd,[pc,#imm] — プールの中身が参照先
            pool = (((addr + 4) & ~3) + (w & 0xFF) * 4) & M32
            off = pool - base_addr
            if 0 <= off and off + 4 <= size:
                value = int.from_bytes(data[off:off + 4], order)
                index.setdefault(value, []).append((addr, "ldr@pc", pool))
        elif top5 == 0b10100:
            # add Rd,pc,#imm — 計算結果そのものがアドレス
            resolved = (((addr + 4) & ~3) + (w & 0xFF) * 4) & M32
            index.setdefault(resolved, []).append((addr, "add@pc", resolved))
        elif top5 == 0b11100:
            tgt = (addr + 4 + _sign(w & 0x7FF, 11) * 2) & M32
            index.setdefault(tgt, []).append((addr, "b", addr))
        elif top5 == 0b11110:
            # bl は次の語とペア。後半が無ければ命令ではない。
            if i + 1 < count and (words[i + 1] >> 11) == 0b11111:
                offset = (_sign(w & 0x7FF, 11) << 12) | ((words[i + 1] & 0x7FF) << 1)
                tgt = (addr + 4 + offset) & M32
                index.setdefault(tgt, []).append((addr, "bl", addr))

    return index


def pc_relative_targets(data, base_addr, big_endian, lo_addr, hi_addr):
    """[lo_addr, hi_addr] の命令が読む PC 相対プールの番地を {番地: 幅} で返します。

    「その番地はコードではなくデータである」と判定するための材料です。
    Thumb の PC 相対ロードは常に 32bit 幅なので、幅は 4 固定になります。
    """
    out = {}
    lo_off = max(0, lo_addr - base_addr)
    hi_off = min(len(data) - 2, hi_addr - base_addr)
    if hi_off < lo_off:
        return out
    lo_off -= lo_off % 2
    order = "big" if big_endian else "little"
    for off in range(lo_off, hi_off + 1, 2):
        w = int.from_bytes(data[off:off + 2], order)
        addr = base_addr + off
        top5 = w >> 11
        if top5 == 0b01001 or top5 == 0b10100:
            out[(((addr + 4) & ~3) + (w & 0xFF) * 4) & M32] = 4
    return out


def is_unconditional_flow_end(word):
    """その命令の後ろが到達不能になるかを返します。

    b (無条件) / bx / pop {..,pc} / mov pc,Rs は無条件に飛ぶので、直後が
    分岐先になっていなければ到達不能 = データ (定数プール) の可能性があります。
    """
    hw = word & 0xFFFF
    if hw >> 11 == 0b11100:
        return True                                   # b
    if hw >> 8 == 0b01000111:
        return True                                   # bx Rs
    if (hw >> 8) == 0xBD:
        return True                                   # pop {..,pc}
    if hw >> 10 == 0b010001 and ((hw >> 8) & 3) == 2 and (hw & 7) | (((hw >> 7) & 1) << 3) == 15:
        return True                                   # mov pc,Rs
    return False


# ---------------------------------------------------------------------------
# 関数入口の推定 (find_function_entry のアーキ側フック)
# ---------------------------------------------------------------------------

def _popcount(value):
    """立っているビットの本数を返します (push/pop のレジスタ本数)。"""
    return bin(value & 0xFFFF).count("1")


def _is_push(hw):
    """push {..} かどうか (0xB4xx / 0xB5xx)。"""
    return (hw & 0xFE00) == 0xB400


def _is_entry_push(hw):
    """**関数入口らしい** push か = lr も積む push {..,lr} (0xB5xx)。"""
    return (hw & 0xFF00) == 0xB500


def _is_pop(hw):
    """pop {..} かどうか (0xBCxx / 0xBDxx)。"""
    return (hw & 0xFE00) == 0xBC00


def _is_func_end(hw):
    """関数の終わりになりうるか。

    Thumb では `pop {..,pc}` (0xBDxx) と `bx Rm` (0x4700 系) が復帰です。
    `bx lr` = 0x4770 が典型ですが、テールコールの `bx Rm` も終わりとみなします。
    """
    if (hw & 0xFF00) == 0xBD00:
        return True
    # ★`bx lr` (0x4770) だけを復帰とみなす。`bx Rm` を一律に終わり扱いすると、
    #   ARMv4T の**間接呼び出しの定型** `mov lr,pc` / `bx r3` を関数の終わりと
    #   誤読し、関数が途中で切れて push/pop の収支が合わなくなる。
    if hw == 0x4770:
        return True
    return False


def _stack_regs(hw):
    """push / pop が触るレジスタ本数 (lr / pc を含む)。"""
    return _popcount(hw & 0xFF) + (1 if (hw & 0x0100) else 0)


def find_function_entry(data, base_addr, big_endian, address,
                        max_back=4096, max_forward=8192):
    """指定アドレスを含む Thumb 関数の入口を命令列から判定します。

    Raw Binary の Thumb コードは Ghidra の自動解析がほとんど効かないため、
    命令列から直接判定します。

    `push {..,lr}` (0xB5xx) を入口の目印にし、`pop {..,pc}` / `bx` までを
    1 関数とみなします。**積んだ本数と戻した本数が一致するか**で誤りを弾きます。
    誤検出を減らすため、その入口を指す `bl` / 関数ポインタも数えて返します
    (`referenced_by`)。
    """
    words = to_words(data, big_endian)
    count = len(words)

    def refs(entry):
        return _find_callers(data, words, base_addr, entry, big_endian)

    spec = _prologue.PrologueSpec(
        size=2,
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
    """その入口を指す bl と関数ポインタを数えます。

    Thumb の関数ポインタは**下位ビットが 1** (entry|1) で格納されます。
    ここを見落とすと「誰も呼んでいない」と誤読します。
    """
    calls = []
    pointers = []
    count = len(words)
    for i in range(count - 1):
        hw = words[i]
        if (hw & 0xF800) != 0xF000:
            continue
        nxt = words[i + 1]
        if (nxt & 0xF800) != 0xF800:
            continue
        addr = base_addr + i * 2
        offset = ((hw & 0x7FF) << 12) | ((nxt & 0x7FF) << 1)
        if offset & 0x400000:
            offset -= 0x800000
        if ((addr + 4 + offset) & M32) == entry:
            calls.append(_hex(addr))
            if len(calls) >= 32:
                break

    order = "big" if big_endian else "little"
    wanted = {entry & M32, (entry | 1) & M32}
    start = (-base_addr) % 4
    for off in range(start, len(data) - 3, 4):
        if int.from_bytes(data[off:off + 4], order) in wanted:
            pointers.append(_hex(base_addr + off))
            if len(pointers) >= 32:
                break
    return {
        "total": len(calls) + len(pointers),
        "bl": calls,
        "pointers": pointers,
        "note": "Thumb の関数ポインタは entry|1 で格納されるので、両方を探しています。",
    }
