# -*- coding: utf-8 -*-
"""MIPS (R3000 / R5900 系, 32bit) の逆アセンブラと即値ペア走査 (Python 3.13 前提)。

読み取り専用 MCP (`ghidra_readonly_mcp.py`) から呼ばれ、
`ghidra_exports/memory/*.bin` の生バイト列をデコードします。
Ghidra にも Ghidra プロジェクトにも触れません (バイト列を受け取るだけ)。

対応範囲:
  - MIPS I〜III の基本命令 (R3000 / R5900 の共通部分)
  - COP0 / COP1(FPU の主要命令) / COP2 (PS1 GTE コマンド名を含む)
  - R5900 の lq/sq/ld/sd 等。MMI (op=0x1c) は展開せず `mmi` として返す。

命令表は MIPS と PS1 GTE の公開仕様に基づく。
分岐先の算出・遅延スロット・即値ペア走査を含みます。
"""


# --- モジュール識別 (disasm/__init__.py の登録所が読む) -------------------
NAME = "mips"
DISPLAY = "MIPS R3000 / R5900 (32bit)"
INSTRUCTION_SIZE = 4
# 分岐・ジャンプの直後 1 命令が必ず実行される (遅延スロット)。
HAS_DELAY_SLOTS = True

# 汎用レジスタの o32 慣用名。
REG = (
    "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3",
    "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
    "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
    "t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra",
)

# SPECIAL (op=0x00) の funct → ニーモニック。rd, rs, rt 形式のもの。
_SPECIAL_RD_RS_RT = {
    0x20: "add", 0x21: "addu", 0x22: "sub", 0x23: "subu",
    0x24: "and", 0x25: "or", 0x26: "xor", 0x27: "nor",
    0x2A: "slt", 0x2B: "sltu",
    0x2C: "dadd", 0x2D: "daddu", 0x2E: "dsub", 0x2F: "dsubu",
    0x0A: "movz", 0x0B: "movn",
}
# rd, rt, rs 形式 (可変シフト)。
_SPECIAL_SHIFT_VAR = {0x04: "sllv", 0x06: "srlv", 0x07: "srav",
                      0x14: "dsllv", 0x16: "dsrlv", 0x17: "dsrav"}
# rd, rt, sa 形式 (即値シフト)。
_SPECIAL_SHIFT_IMM = {0x00: "sll", 0x02: "srl", 0x03: "sra",
                      0x38: "dsll", 0x3A: "dsrl", 0x3B: "dsra",
                      0x3C: "dsll32", 0x3E: "dsrl32", 0x3F: "dsra32"}
# rs, rt 形式 (乗除算・トラップ)。
_SPECIAL_RS_RT = {
    0x18: "mult", 0x19: "multu", 0x1A: "div", 0x1B: "divu",
    0x1C: "dmult", 0x1D: "dmultu", 0x1E: "ddiv", 0x1F: "ddivu",
    0x30: "tge", 0x31: "tgeu", 0x32: "tlt", 0x33: "tltu",
    0x34: "teq", 0x36: "tne",
}

# REGIMM (op=0x01) の rt → ニーモニック。
_REGIMM = {
    0x00: "bltz", 0x01: "bgez", 0x02: "bltzl", 0x03: "bgezl",
    0x08: "tgei", 0x09: "tgeiu", 0x0A: "tlti", 0x0B: "tltiu",
    0x0C: "teqi", 0x0E: "tnei",
    0x10: "bltzal", 0x11: "bgezal", 0x12: "bltzall", 0x13: "bgezall",
}

# 符号付き即値の I 形式 (rt, rs, simm)。
_IMM_SIGNED = {0x08: "addi", 0x09: "addiu", 0x0A: "slti", 0x0B: "sltiu",
               0x18: "daddi", 0x19: "daddiu"}
# 論理即値の I 形式 (rt, rs, 0xIMM)。
_IMM_LOGICAL = {0x0C: "andi", 0x0D: "ori", 0x0E: "xori"}

# ロード/ストア形式 (rt, simm(rs))。op → ニーモニック。
_MEM_OPS = {
    0x1A: "ldl", 0x1B: "ldr",
    0x1E: "lq", 0x1F: "sq",
    0x20: "lb", 0x21: "lh", 0x22: "lwl", 0x23: "lw",
    0x24: "lbu", 0x25: "lhu", 0x26: "lwr", 0x27: "lwu",
    0x28: "sb", 0x29: "sh", 0x2A: "swl", 0x2B: "sw",
    0x2C: "sdl", 0x2D: "sdr", 0x2E: "swr",
    0x30: "ll", 0x37: "ld", 0x38: "sc", 0x3F: "sd",
}
# コプロセッサのロード/ストア (レジスタ表記が $fN / $cN になるもの)。
_COP_MEM_OPS = {0x31: "lwc1", 0x32: "lwc2", 0x35: "ldc1", 0x36: "ldc2",
                0x39: "swc1", 0x3A: "swc2", 0x3D: "sdc1", 0x3E: "sdc2"}

# 条件分岐 (rs, rt, target)。
_BRANCH_RS_RT = {0x04: "beq", 0x05: "bne", 0x14: "beql", 0x15: "bnel"}
# 条件分岐 (rs, target)。
_BRANCH_RS = {0x06: "blez", 0x07: "bgtz", 0x16: "blezl", 0x17: "bgtzl"}

# PS1 GTE (COP2) コマンドの下位 6bit → 名前。PS1 の 3D 変換ルーチン判別に効く。
_GTE_FUNCS = {
    0x01: "RTPS", 0x06: "NCLIP", 0x0C: "OP", 0x10: "DPCS", 0x11: "INTPL",
    0x12: "MVMVA", 0x13: "NCDS", 0x14: "CDP", 0x16: "NCDT", 0x1B: "NCCS",
    0x1C: "CC", 0x1E: "NCS", 0x20: "NCT", 0x28: "SQR", 0x29: "DCPL",
    0x2A: "DPCT", 0x2D: "AVSZ3", 0x2E: "AVSZ4", 0x30: "RTPT",
    0x3D: "GPF", 0x3E: "GPL", 0x3F: "NCCT",
}

# COP1 (FPU) の代表的な演算。fmt=16(単精度) / 17(倍精度) / 20(word)。
_FPU_FMT = {16: "s", 17: "d", 20: "w", 21: "l"}
_FPU_FUNCS = {
    0x00: "add", 0x01: "sub", 0x02: "mul", 0x03: "div", 0x04: "sqrt",
    0x05: "abs", 0x06: "mov", 0x07: "neg", 0x0D: "trunc.w", 0x20: "cvt.s",
    0x21: "cvt.d", 0x24: "cvt.w",
    0x32: "c.eq", 0x3C: "c.lt", 0x3E: "c.le",
}

# 即値ペアで下位 16bit を合成しうる命令 (op → ニーモニック)。
# lui $rX, hi の直後にこれらが $rX を base/rs として使うと 32bit アドレスになる。
_PAIR_OPS = dict(_MEM_OPS)
_PAIR_OPS.update(_COP_MEM_OPS)
_PAIR_OPS.update({0x08: "addi", 0x09: "addiu", 0x0D: "ori"})

# ori だけは即値がゼロ拡張 (定数合成)。他は符号拡張。
_PAIR_ZERO_EXT = frozenset((0x0D,))

# lui の直後に何命令ぶんまでペアを探すか。ペアはふつう数命令以内に現れる。
PAIR_WINDOW = 8

# find_address_refs の応答に添える、このアーキ固有の取りこぼし注意。
REFS_NOTE = ("lui の結果を別レジスタへ写してから使う形と、"
             "lui から {0} 命令以上離れた使用は拾えません。".format(PAIR_WINDOW))

# 0 件だったときに「参照が無い」と結論させないための、具体的な疑い先。
# find_address_refs が total=0 のときだけ応答に入れる。
REFS_BLIND_SPOTS = (
    "lui の結果を addu/move 等で別レジスタへ写してから使っている "
    "(lui $v0,hi / addu $a0,$v0,$zero / lw $t0,lo($a0) の形)。",
    "lui から {0} 命令以上離れた位置で下位 16bit を足している。".format(PAIR_WINDOW),
    "$gp 相対アクセス (lw $v0,off($gp)) — 参照先が命令に現れない。"
    "$gp の値を突き止めてから off を足す必要がある。",
    "ポインタテーブル経由で参照されている "
    "(コードには表の先頭しか現れない)。",
    "そのアドレスが実行時に計算されている (ベース + index*size)。",
)


def _r(index):
    """汎用レジスタ番号を '$name' 表記にします。"""
    return "$" + REG[index & 0x1F]


def _s16(value):
    """16bit 即値を符号付きに拡張します。"""
    return value - 0x10000 if value & 0x8000 else value


def _hex(value):
    """32bit アドレスを '0x........' 表記にします。"""
    return "0x{0:08x}".format(value & 0xFFFFFFFF)


def _imm(value):
    """符号付き即値を 10 進 (負なら -N) で表記します。"""
    return str(value)


def _branch_target(addr, simm):
    """分岐命令の飛び先アドレスを求めます (遅延スロットぶん +4 してから加算)。"""
    return (addr + 4 + simm * 4) & 0xFFFFFFFF


def _jump_target(addr, target26):
    """j / jal の飛び先アドレスを求めます (上位 4bit は遅延スロットの PC 由来)。"""
    return (((addr + 4) & 0xF0000000) | (target26 << 2)) & 0xFFFFFFFF


def _out(mnemonic, operands="", target=None, flow=None):
    """デコード結果の共通 dict を作ります。"""
    text = mnemonic if not operands else "{0} {1}".format(mnemonic, operands)
    return {
        "mnemonic": mnemonic,
        "operands": operands,
        "text": text,
        "target": _hex(target) if target is not None else None,
        "flow": flow,
    }


def _decode_special(word, addr):
    """SPECIAL (op=0x00) をデコードします。"""
    rs = (word >> 21) & 0x1F
    rt = (word >> 16) & 0x1F
    rd = (word >> 11) & 0x1F
    sa = (word >> 6) & 0x1F
    funct = word & 0x3F

    if funct in _SPECIAL_SHIFT_IMM:
        if word == 0:
            return _out("nop")
        return _out(_SPECIAL_SHIFT_IMM[funct],
                    "{0}, {1}, {2}".format(_r(rd), _r(rt), sa))
    if funct in _SPECIAL_SHIFT_VAR:
        return _out(_SPECIAL_SHIFT_VAR[funct],
                    "{0}, {1}, {2}".format(_r(rd), _r(rt), _r(rs)))
    if funct in _SPECIAL_RD_RS_RT:
        return _out(_SPECIAL_RD_RS_RT[funct],
                    "{0}, {1}, {2}".format(_r(rd), _r(rs), _r(rt)))
    if funct in _SPECIAL_RS_RT:
        return _out(_SPECIAL_RS_RT[funct], "{0}, {1}".format(_r(rs), _r(rt)))
    if funct == 0x08:
        # jr $ra は関数からの復帰。未関数化コードの「関数の終わり」判定に使う。
        flow = "return" if rs == 31 else "jump_reg"
        return _out("jr", _r(rs), flow=flow)
    if funct == 0x09:
        if rd == 31:
            return _out("jalr", _r(rs), flow="call_reg")
        return _out("jalr", "{0}, {1}".format(_r(rd), _r(rs)), flow="call_reg")
    if funct == 0x0C:
        return _out("syscall", "0x{0:x}".format((word >> 6) & 0xFFFFF))
    if funct == 0x0D:
        return _out("break", "0x{0:x}".format((word >> 6) & 0xFFFFF))
    if funct == 0x0F:
        return _out("sync")
    if funct == 0x10:
        return _out("mfhi", _r(rd))
    if funct == 0x11:
        return _out("mthi", _r(rs))
    if funct == 0x12:
        return _out("mflo", _r(rd))
    if funct == 0x13:
        return _out("mtlo", _r(rs))
    return _out(".word", "0x{0:08x}".format(word) + " ; special funct=0x{0:02x}".format(funct))


def _decode_cop0(word):
    """COP0 (op=0x10) の代表的な命令をデコードします。"""
    rs = (word >> 21) & 0x1F
    rt = (word >> 16) & 0x1F
    rd = (word >> 11) & 0x1F
    if rs == 0x00:
        return _out("mfc0", "{0}, $c0_{1}".format(_r(rt), rd))
    if rs == 0x04:
        return _out("mtc0", "{0}, $c0_{1}".format(_r(rt), rd))
    if rs >= 0x10:
        funct = word & 0x3F
        if funct == 0x10:
            return _out("rfe")
        if funct == 0x18:
            return _out("eret")
    return _out("cop0", "0x{0:07x}".format(word & 0x1FFFFFF))


def _decode_cop1(word, addr):
    """COP1 (FPU, op=0x11) の主要命令をデコードします。"""
    rs = (word >> 21) & 0x1F
    rt = (word >> 16) & 0x1F
    fs = (word >> 11) & 0x1F
    fd = (word >> 6) & 0x1F
    ft = rt
    if rs == 0x00:
        return _out("mfc1", "{0}, $f{1}".format(_r(rt), fs))
    if rs == 0x02:
        return _out("cfc1", "{0}, $fcr{1}".format(_r(rt), fs))
    if rs == 0x04:
        return _out("mtc1", "{0}, $f{1}".format(_r(rt), fs))
    if rs == 0x06:
        return _out("ctc1", "{0}, $fcr{1}".format(_r(rt), fs))
    if rs == 0x08:
        name = "bc1t" if (rt & 1) else "bc1f"
        tgt = _branch_target(addr, _s16(word & 0xFFFF))
        return _out(name, _hex(tgt), target=tgt, flow="branch")
    fmt = _FPU_FMT.get(rs)
    funct = word & 0x3F
    if fmt and funct in _FPU_FUNCS:
        base = _FPU_FUNCS[funct]
        name = "{0}.{1}".format(base, fmt)
        if base.startswith("c."):
            return _out(name, "$f{0}, $f{1}".format(fs, ft))
        if base in ("mov", "abs", "neg", "sqrt") or base.startswith("cvt") or base.startswith("trunc"):
            return _out(name, "$f{0}, $f{1}".format(fd, fs))
        return _out(name, "$f{0}, $f{1}, $f{2}".format(fd, fs, ft))
    return _out("cop1", "0x{0:07x}".format(word & 0x1FFFFFF))


def _decode_cop2(word):
    """COP2 (op=0x12) をデコードします。PS1 では GTE コマンドになります。"""
    rs = (word >> 21) & 0x1F
    rt = (word >> 16) & 0x1F
    rd = (word >> 11) & 0x1F
    if word & 0x2000000:
        # bit25 が立っていれば GTE コマンド。既知のものは名前を添える。
        func = word & 0x3F
        name = _GTE_FUNCS.get(func)
        cmd = "0x{0:07x}".format(word & 0x1FFFFFF)
        if name:
            return _out("cop2", "{0} ; {1}".format(cmd, name))
        return _out("cop2", cmd)
    if rs == 0x00:
        return _out("mfc2", "{0}, $vd{1}".format(_r(rt), rd))
    if rs == 0x02:
        return _out("cfc2", "{0}, $vc{1}".format(_r(rt), rd))
    if rs == 0x04:
        return _out("mtc2", "{0}, $vd{1}".format(_r(rt), rd))
    if rs == 0x06:
        return _out("ctc2", "{0}, $vc{1}".format(_r(rt), rd))
    return _out("cop2", "0x{0:07x}".format(word & 0x1FFFFFF))


def decode(word, addr):
    """1 命令語 (32bit int) をデコードし、dict で返します。

    返す dict: mnemonic / operands / text / target / flow。
    target は分岐・ジャンプ先アドレス文字列 (無ければ None)。
    flow は "branch" / "jump" / "call" / "call_reg" / "jump_reg" / "return" / None。
    未知の語は `.word 0x........` として返し、例外は投げません
    (未関数化領域にはデータが混ざるため、落ちずに読めることを優先)。
    """
    word &= 0xFFFFFFFF
    op = (word >> 26) & 0x3F
    rs = (word >> 21) & 0x1F
    rt = (word >> 16) & 0x1F
    imm = word & 0xFFFF
    simm = _s16(imm)

    if op == 0x00:
        return _decode_special(word, addr)

    if op == 0x01:
        name = _REGIMM.get(rt)
        if name is None:
            return _out(".word", "0x{0:08x} ; regimm rt=0x{1:02x}".format(word, rt))
        if name.startswith("b"):
            tgt = _branch_target(addr, simm)
            flow = "call" if "al" in name[-3:] else "branch"
            return _out(name, "{0}, {1}".format(_r(rs), _hex(tgt)), target=tgt, flow=flow)
        return _out(name, "{0}, {1}".format(_r(rs), _imm(simm)))

    if op == 0x02:
        tgt = _jump_target(addr, word & 0x3FFFFFF)
        return _out("j", _hex(tgt), target=tgt, flow="jump")
    if op == 0x03:
        tgt = _jump_target(addr, word & 0x3FFFFFF)
        return _out("jal", _hex(tgt), target=tgt, flow="call")

    if op in _BRANCH_RS_RT:
        tgt = _branch_target(addr, simm)
        return _out(_BRANCH_RS_RT[op],
                    "{0}, {1}, {2}".format(_r(rs), _r(rt), _hex(tgt)),
                    target=tgt, flow="branch")
    if op in _BRANCH_RS:
        tgt = _branch_target(addr, simm)
        return _out(_BRANCH_RS[op], "{0}, {1}".format(_r(rs), _hex(tgt)),
                    target=tgt, flow="branch")

    if op in _IMM_SIGNED:
        return _out(_IMM_SIGNED[op],
                    "{0}, {1}, {2}".format(_r(rt), _r(rs), _imm(simm)))
    if op in _IMM_LOGICAL:
        return _out(_IMM_LOGICAL[op],
                    "{0}, {1}, 0x{2:x}".format(_r(rt), _r(rs), imm))
    if op == 0x0F:
        return _out("lui", "{0}, 0x{1:x}".format(_r(rt), imm))

    if op == 0x10:
        return _decode_cop0(word)
    if op == 0x11:
        return _decode_cop1(word, addr)
    if op == 0x12:
        return _decode_cop2(word)

    if op in _MEM_OPS:
        return _out(_MEM_OPS[op],
                    "{0}, {1}({2})".format(_r(rt), _imm(simm), _r(rs)))
    if op in _COP_MEM_OPS:
        name = _COP_MEM_OPS[op]
        creg = "$f{0}".format(rt) if name.endswith("c1") else "$vd{0}".format(rt)
        return _out(name, "{0}, {1}({2})".format(creg, _imm(simm), _r(rs)))

    if op == 0x1C:
        # R5900 MMI。展開していない (道具箱では未対応と明示する)。
        return _out("mmi", "0x{0:07x} ; R5900 MMI (未展開) funct=0x{1:02x}".format(
            word & 0x1FFFFFF, word & 0x3F))
    if op == 0x2F:
        return _out("cache", "0x{0:x}, {1}({2})".format(rt, _imm(simm), _r(rs)))
    if op == 0x33:
        return _out("pref", "0x{0:x}, {1}({2})".format(rt, _imm(simm), _r(rs)))

    return _out(".word", "0x{0:08x} ; op=0x{1:02x}".format(word, op))


def word_at(data, offset, big_endian):
    """バイト列から 32bit 命令語を 1 つ取り出します。範囲外なら None。"""
    if offset < 0 or offset + 4 > len(data):
        return None
    chunk = data[offset:offset + 4]
    return int.from_bytes(chunk, "big" if big_endian else "little")


def _dest_gpr(word):
    """その命令が書き換える汎用レジスタ番号を返します (無ければ None)。

    即値ペア走査で「lui の結果レジスタが潰されたか」を判定するために使います。
    厳密な完全表ではなく、実際に潰す代表的な形だけを見ます (安全側=見逃しより
    早めに打ち切る方向)。
    """
    op = (word >> 26) & 0x3F
    if op == 0x00:
        funct = word & 0x3F
        if funct in _SPECIAL_RD_RS_RT or funct in _SPECIAL_SHIFT_VAR \
                or funct in _SPECIAL_SHIFT_IMM:
            return (word >> 11) & 0x1F
        if funct in (0x10, 0x12):          # mfhi / mflo
            return (word >> 11) & 0x1F
        if funct == 0x09:                  # jalr rd
            return (word >> 11) & 0x1F
        return None
    if op == 0x03:                          # jal は $ra を潰す
        return 31
    if op in _IMM_SIGNED or op in _IMM_LOGICAL or op == 0x0F:
        return (word >> 16) & 0x1F
    if op in _MEM_OPS and not _MEM_OPS[op].startswith("s"):
        return (word >> 16) & 0x1F
    return None


def to_words(data, big_endian):
    """バイト列を 32bit 命令語の array に変換します (4 バイト境界で切り捨て)。

    走査対象は 16MB 級になるため、Python の int リストではなく array を使います
    (int リストだと 16MB のイメージで 100MB 超のメモリを食う)。
    """
    import array
    import sys

    code = "I" if array.array("I").itemsize == 4 else "L"
    words = array.array(code)
    limit = len(data) - (len(data) % 4)
    words.frombytes(bytes(data[:limit]))
    if big_endian != (sys.byteorder == "big"):
        words.byteswap()
    return words


def build_ref_index(data, base_addr, big_endian, window=PAIR_WINDOW):
    """メモリイメージを走査し、`lui + 下位16bit` で合成されるアドレスの索引を作ります。

    返り値: {合成アドレス(int): [(参照命令アドレス, form, lui のアドレス), ...]}

    MIPS では 32bit 定数を `lui $rX, hi` と後続命令の下位 16bit で組み立てます。
    Ghidra がデータ参照として認識していない (未定義領域に置かれた) テーブルでも、
    この形を再構成すれば参照元を見つけられます。lo が負なら hi 側が実質 -0x10000
    されるので、必ず `(hi << 16) + sext16(lo)` で合成します。
    j / jal の飛び先も同じ索引に入れます (form="j"/"jal")。

    既知の取りこぼし: lui の結果を `addu` 等で別レジスタへ写してから使う形、
    window (既定 8 命令) を越えて離れた位置で使う形は拾えません
    (実用上はこれで足りました)。
    """
    index = {}
    words = to_words(data, big_endian)
    count = len(words)

    for i in range(count):
        w = words[i]
        op = (w >> 26) & 0x3F

        if op == 0x02 or op == 0x03:
            # j / jal の飛び先も「そのアドレスを参照するコード」として索引に入れる。
            addr = base_addr + i * 4
            tgt = _jump_target(addr, w & 0x3FFFFFF)
            index.setdefault(tgt, []).append((addr, "j" if op == 0x02 else "jal", addr))
            continue

        if (w & 0xFC000000) != 0x3C000000:   # lui (op=0x0f, rs=0) 以外は飛ばす
            continue
        reg = (w >> 16) & 0x1F
        if reg == 0:
            continue
        hi_addr = base_addr + i * 4
        base_value = (w & 0xFFFF) << 16
        matched_lo = False

        stop = min(i + 1 + window, count)
        for j in range(i + 1, stop):
            wj = words[j]
            opj = (wj >> 26) & 0x3F
            if opj in _PAIR_OPS and ((wj >> 21) & 0x1F) == reg:
                lo = wj & 0xFFFF
                if opj in _PAIR_ZERO_EXT:
                    resolved = (base_value | lo) & 0xFFFFFFFF
                else:
                    resolved = (base_value + _s16(lo)) & 0xFFFFFFFF
                index.setdefault(resolved, []).append(
                    (base_addr + j * 4, "lui+" + _PAIR_OPS[opj], hi_addr))
                matched_lo = True
            # lui の結果レジスタが書き換わったら、そこで打ち切る。
            # addiu $a0,$a0,lo のような「ペアかつ上書き」も同じ扱い
            # (以降 $a0 は hi<<16 ではなく完成したアドレスを保持するため)。
            if _dest_gpr(wj) == reg:
                break

        if not matched_lo:
            # ペアが無い lui は、それ単独で `hi << 16` を参照しているとみなす。
            index.setdefault(base_value, []).append((hi_addr, "lui", hi_addr))

    return index


# ---------------------------------------------------------------------------
# 解析フック (find_writers / expand_switch / find_function_entry)
#
# 骨格は共通層に置き、ここには「MIPS ではどれが書き込みか」「どれが関数の
# 終わりか」という**判定だけ**を書く。MCP 本体には分岐を増やさない。
# ---------------------------------------------------------------------------

from . import _prologue  # noqa: E402

# build_ref_index が付ける form ("lui+sw" など) の後半で判定する。
_STORE_NAMES = frozenset((
    "sb", "sh", "sw", "sd", "sq", "swl", "swr", "sdl", "sdr", "sc",
    "swc1", "swc2", "sdc1", "sdc2"))
_LOAD_NAMES = frozenset((
    "lb", "lh", "lw", "ld", "lq", "lbu", "lhu", "lwu", "lwl", "lwr",
    "ldl", "ldr", "ll", "lwc1", "lwc2", "ldc1", "ldc2"))

# 「近傍への書き込み」とみなす窓。同じ構造体の別フィールドを拾うため。
NEAR_WINDOW = 0x40

WRITERS_NOTE = (
    "lui + store の組で実効アドレスを再構成しています。MIPS は "
    "`lui $a0,hi` / `sw $v0,lo($a0)` で番地が命令 2 つに割れるので、"
    "この復元をしないと書き込み元が見つかりません。"
    "書く値は `sw $zero` なら 0 で確定、それ以外は直前 trace_imm 命令ぶん"
    "遡って即値を探します (見つからなければ value=null)。")

WRITERS_BLIND_SPOTS = (
    "$gp 相対の書き込み (sw $v0,off($gp)) — 番地が命令に現れないので拾えません。"
    "PS2 (r5900) の小さいグローバルはほぼこの形です。",
    "lui の結果を addu/move 等で別レジスタへ写してから書く形。",
    "lui から max_scan 命令以上離れた位置の store。",
    "ポインタ経由の書き込み (構造体の先頭だけを lui で作り、"
    "実際の番地は実行時に決まる形)。",
    "DMA / メモリカード / 別 Program による書き込み (そもそも命令ではない)。",
)

SWITCH_NOTE = (
    "MIPS のスイッチは `sltiu` で範囲を見てから `lw` で飛び先表を引き、"
    "`jr $rX` で飛びます。飛び先は 32bit アドレスとして表に**だけ**あるので、"
    "jr の命令からは辿れません。エントリ数は sltiu の即値から取れなければ"
    "推定です (count_is_estimated を確認してください)。")


def _form_op(form):
    """build_ref_index の form ('lui+sw') から命令名だけ取り出します。"""
    return form.split("+", 1)[1] if "+" in form else form


def _trace_gpr_immediate(words, index, reg, limit):
    """store のソースレジスタに入っている即値を後ろ向きに探します。

    `$zero` は常に 0 なので即断します。**`sw $zero,...` はフラグを 0 に戻す
    定型**で、find_writers がいちばん答えたい形です。
    """
    if reg == 0:
        return 0
    for k in range(index - 1, max(-1, index - limit - 1), -1):
        w = words[k]
        op = (w >> 26) & 0x3F
        rt = (w >> 16) & 0x1F
        rs = (w >> 21) & 0x1F
        if op in (0x08, 0x09) and rt == reg and rs == 0:      # addi/addiu $rt,$zero,imm
            return _s16(w & 0xFFFF)
        if op == 0x0D and rt == reg and rs == 0:              # ori $rt,$zero,imm
            return w & 0xFFFF
        if op == 0x0F and rt == reg:                          # lui $rt,imm (上位だけ)
            return (w & 0xFFFF) << 16
        if op == 0x00 and (w & 0x3F) in (0x20, 0x21):         # add / addu
            if ((w >> 11) & 0x1F) == reg:
                if rs == 0 and rt == 0:
                    return 0                                   # move $rd,$zero
                return None
        if _dest_gpr(w) == reg:
            return None                                        # 別の値で潰された
    return None


def find_writers(data, base_addr, big_endian, target, mask=0xFFFFFFFF,
                 max_scan=12, trace_imm=16):
    """その番地に **書き込んでいる命令** を、書く値まで添えて列挙します。

    MIPS の手順 (SH-4 の定数プール走査とは別物):

      1. `build_ref_index` で `lui + 下位16bit` の実効アドレスを全部復元する
      2. target と一致するものを store / load に分ける
      3. store ならソースレジスタの即値を直前 trace_imm 命令ぶん遡って探す

    `pools` には**そのアドレスを組み立てている `lui` の位置**を入れます
    (SH-4 の定数プールに相当する「番地の出どころ」)。
    """
    words = to_words(data, big_endian)
    index = build_ref_index(data, base_addr, big_endian,
                            window=max(1, int(max_scan)))
    masked = target & mask
    exact_only = (mask == 0xFFFFFFFF)

    writers, offset_writers, readers, unresolved = [], [], [], []
    luis = set()

    for resolved, refs in index.items():
        exact = (resolved & mask) == masked
        near = (exact_only and not exact
                and abs(resolved - target) <= NEAR_WINDOW)
        if not (exact or near):
            continue
        for at, form, lui_addr in refs:
            name = _form_op(form)
            i = (at - base_addr) // 4
            if i < 0 or i >= len(words):
                continue
            luis.add(lui_addr)
            text = decode(words[i], at)["text"]
            if name in _STORE_NAMES:
                src = (words[i] >> 16) & 0x1F
                value = _trace_gpr_immediate(words, i, src, int(trace_imm))
                (writers if exact else offset_writers).append({
                    "store_addr": _hex(at),
                    "lui_addr": _hex(lui_addr),
                    "target": _hex(resolved),
                    "opcode": "0x{0:08x}".format(words[i]),
                    "width": name,
                    "src_reg": _r(src),
                    "value": value,
                    "writes_zero": (value == 0),
                    "text": text,
                })
            elif name in _LOAD_NAMES:
                if exact:
                    readers.append({
                        "read_addr": _hex(at),
                        "lui_addr": _hex(lui_addr),
                        "width": name,
                        "text": text,
                    })
            elif exact:
                # addiu / ori / lui 単独 = 「番地を作っただけ」。実際の読み書きは
                # そのレジスタ経由で後から起きるので、**書き込みの見落とし候補**。
                unresolved.append({
                    "addr": _hex(at),
                    "form": form,
                    "text": text,
                    "why": "アドレスを組み立てているだけで、読み書きは"
                           "このレジスタ経由で後から起きます。",
                })

    writers.sort(key=lambda x: x["store_addr"])
    offset_writers.sort(key=lambda x: x["store_addr"])
    readers.sort(key=lambda x: x["read_addr"])
    return {
        "pools": sorted(_hex(a) for a in luis),
        "pool_count": len(luis),
        "load_count": (len(writers) + len(offset_writers)
                       + len(readers) + len(unresolved)),
        "writers": writers,
        "offset_writers": offset_writers,
        "readers": readers,
        "unresolved": unresolved,
        "max_scan_reached": 0,
        "near_window": "0x{0:x}".format(NEAR_WINDOW),
    }



def _explain_not_a_table(words, base_addr, size, jr_addr, jr_reg, filler,
                         max_back):
    """表引きでなかったときに、**何なのか**を言い切るための説明文を作ります。

    「lw が見つかりません」だけだと、呼んだ側は次に何をすればいいか分かりません。
    失敗の多くは**関数末尾より後ろのデータを命令として読んでいる**ものです。
    """
    where = "{0} の $rX ({1}) は ".format(_hex(jr_addr), _r(jr_reg))
    if filler is None:
        return (where + "前 {0} 命令のどこでも設定されていません。"
                "関数の引数として渡された関数ポインタか、"
                "**ここがコードではない**可能性があります。".format(max_back))

    w = words[filler]
    at = base_addr + filler * 4
    op = (w >> 26) & 0x3F
    rs = (w >> 21) & 0x1F
    value = None
    if op in (0x08, 0x09) and rs == 0:                 # addiu $rX,$zero,imm
        value = _s16(w & 0xFFFF) & 0xFFFFFFFF
    elif op == 0x0D and rs == 0:                       # ori $rX,$zero,imm
        value = w & 0xFFFF
    elif op == 0x0F:                                   # lui $rX,hi
        value = (w & 0xFFFF) << 16
    elif op in (0x08, 0x09, 0x0D):
        # lui + addiu の対 = 直接ジャンプ (末尾呼び出し)。上位を探しに行く。
        lo = (w & 0xFFFF) if op == 0x0D else _s16(w & 0xFFFF)
        for k in range(filler - 1, max(-1, filler - max_back - 1), -1):
            wk = words[k]
            if ((wk >> 26) & 0x3F) == 0x0F and ((wk >> 16) & 0x1F) == rs:
                value = (((wk & 0xFFFF) << 16) + lo) & 0xFFFFFFFF
                break
            if _dest_gpr(wk) == rs:
                break

    text = decode(w, at)["text"]
    if value is None:
        return (where + "{0} ({1}) で設定されていて、表引き (`lw`) では"
                "ありません。別レジスタからの写しか、実行時に決まる"
                "関数ポインタです。".format(_hex(at), text))

    inside = base_addr <= value < base_addr + size
    if inside:
        return (where + "{0} ({1}) で **{2} という即値**に設定されています。"
                "これは表引きではなく、その番地への直接ジャンプ "
                "(末尾呼び出し) です。get_disassembly で {2} を読んでください。".format(
                    _hex(at), text, _hex(value)))
    return (where + "{0} ({1}) で **{2}** に設定されていますが、"
            "この番地は memory イメージの外です。飛び先として成立しないので、"
            "**ここはコードではなくデータ**の可能性が高いです "
            "(関数の末尾より後ろのデータを命令として読むとこの形になります)。"
            "read_data で中身を確認してください。".format(
                _hex(at), text, _hex(value)))


def expand_switch(data, base_addr, big_endian, jr_addr, max_back=32,
                  max_entries=256, read_word=None):
    """`jr $rX` によるスイッチ表を展開します (参照検索の盲点を塞ぐ)。

    MIPS の定型は 2 通りあり、どちらも飛び先が**表の中にしか無い**ので
    `find_address_refs` では見つかりません:

        (A) lui $t1,hi / addiu $t1,$t1,lo / addu $t1,$t1,$idx4 / lw $t1,0($t1) / jr $t1
        (B) sll $t0,$idx,2 / lui $t1,hi / addu $t1,$t1,$t0 / lw $t1,lo($t1) / jr $t1

    件数は直前の `sltiu $t,$idx,N` から取ります。無ければ「表の外を指すまで」
    読んで推定します (count_is_estimated=true)。

    ★`read_word(addr)` を渡すと、**表を別のブロックから読めます**。
      飛び先表は `.rodata` に置かれるのが普通で、`jr` のある `.text` とは
      別ブロックです。渡さないと「表は求まったのにエントリが 0 件」になります。
    """
    words = to_words(data, big_endian)
    order = "big" if big_endian else "little"
    count = len(words)
    size = len(data)
    i = (jr_addr - base_addr) // 4
    if (jr_addr - base_addr) % 4 or i < 0 or i >= count:
        raise ValueError(
            "アドレス {0} が memory イメージの範囲外か、4 バイト境界に"
            "揃っていません。".format(_hex(jr_addr)))

    w = words[i]
    if (w >> 26) & 0x3F or (w & 0x3F) != 0x08:
        raise ValueError(
            "{0} は jr ではありません (opcode 0x{1:08x})。"
            "スイッチ表の展開は `jr $rX` の番地に対して行ってください。".format(
                _hex(jr_addr), w))
    jr_reg = (w >> 21) & 0x1F
    if jr_reg == 31:
        raise ValueError(
            "{0} は `jr $ra` (関数からの復帰) でスイッチではありません。".format(
                _hex(jr_addr)))
    if jr_reg == 0:
        # ★`jr $zero` は「常に 0 番地へ飛ぶ」= 意味のあるコードではない。
        #   ASCII データを命令として読むとこの形になりやすい。
        #   表引きが見つからない理由をここで言い切る。
        raise ValueError(
            "{0} は `jr $zero` です。常に 0 番地へ飛ぶ意味のないコードなので、"
            "**ここはコードではなくデータ**の可能性が高いです "
            "(ASCII 文字列を命令として読むとこの形になります)。"
            "read_data で中身を確認してください。".format(_hex(jr_addr)))

    # --- 1) jr のレジスタを埋める命令を後方に探す ---
    #   lw なら表引き。即値なら直接ジャンプ (か、データの誤読)。
    lw_i = None
    filler = None
    for k in range(i - 1, max(-1, i - max_back - 1), -1):
        wk = words[k]
        if ((wk >> 26) & 0x3F) == 0x23 and ((wk >> 16) & 0x1F) == jr_reg:
            lw_i = k
            break
        if _dest_gpr(wk) == jr_reg:
            filler = k                 # lw 以外で埋められた = 表引きではない
            break
    if lw_i is None:
        raise ValueError(_explain_not_a_table(
            words, base_addr, size, jr_addr, jr_reg, filler, max_back))

    lw = words[lw_i]
    lw_base = (lw >> 21) & 0x1F
    lw_disp = _s16(lw & 0xFFFF)

    # --- 2) 表の先頭アドレスを求める ---
    #   (B) lw の base が lui 由来 → 表 = (hi<<16) + lw_disp
    #   (A) lw の base が addu 由来 → その相手の lui/addiu ペアが表
    table = None
    how = None
    reg = lw_base
    disp = lw_disp
    for k in range(lw_i - 1, max(-1, lw_i - max_back - 1), -1):
        wk = words[k]
        op = (wk >> 26) & 0x3F
        if op == 0x0F and ((wk >> 16) & 0x1F) == reg:          # lui $reg,hi
            table = (((wk & 0xFFFF) << 16) + disp) & 0xFFFFFFFF
            how = "lui(0x{0:x}) + disp(0x{1:x})".format(wk & 0xFFFF, disp & 0xFFFF)
            break
        if op in (0x08, 0x09, 0x0D) and ((wk >> 16) & 0x1F) == reg:
            # addiu/ori $reg,$rs,lo → 下位を足して、上位は $rs の lui を探し直す
            disp = (disp + (wk & 0xFFFF if op == 0x0D else _s16(wk & 0xFFFF)))
            reg = (wk >> 21) & 0x1F
            continue
        if op == 0x00 and (wk & 0x3F) in (0x20, 0x21) \
                and ((wk >> 11) & 0x1F) == reg:                # addu $reg,$rs,$rt
            # index を足している側は分からないので、両方を候補にして先に
            # 解決できた方を採る (片方は sll した index なので lui を持たない)。
            reg = (wk >> 21) & 0x1F
            alt = (wk >> 16) & 0x1F
            for k2 in range(k - 1, max(-1, k - max_back - 1), -1):
                w2 = words[k2]
                if ((w2 >> 26) & 0x3F) == 0x0F and ((w2 >> 16) & 0x1F) in (reg, alt):
                    table = (((w2 & 0xFFFF) << 16) + disp) & 0xFFFFFFFF
                    how = "addu 経由 lui(0x{0:x}) + disp(0x{1:x})".format(
                        w2 & 0xFFFF, disp & 0xFFFF)
                    break
                if ((w2 >> 26) & 0x3F) in (0x08, 0x09, 0x0D) \
                        and ((w2 >> 16) & 0x1F) in (reg, alt):
                    op2 = (w2 >> 26) & 0x3F
                    disp += (w2 & 0xFFFF) if op2 == 0x0D else _s16(w2 & 0xFFFF)
                    reg = alt = (w2 >> 21) & 0x1F
            break
    if table is None:
        raise ValueError(
            "表の先頭アドレスを復元できませんでした ({0} の lw から遡って "
            "lui が見つかりません)。$gp 相対の表かもしれません。".format(_hex(jr_addr)))

    # --- 3) 件数を sltiu から取る ---
    entries_declared = None
    for k in range(i - 1, max(-1, i - max_back - 1), -1):
        wk = words[k]
        if ((wk >> 26) & 0x3F) == 0x0B:            # sltiu $rt,$rs,imm
            entries_declared = wk & 0xFFFF
            break

    # --- 4) 表を読む ---
    limit = entries_declared if entries_declared else max_entries
    limit = min(int(limit), max_entries)
    entries = []
    estimated = entries_declared is None
    out_of_block = False
    for n in range(limit):
        at = table + n * 4
        off = (table - base_addr) + n * 4
        if 0 <= off and off + 4 <= size:
            value = int.from_bytes(bytes(data[off:off + 4]), order)
        elif read_word is not None:
            # 表が別ブロック (.rodata 等) にある場合。
            value = read_word(at)
            if value is None:
                break
        else:
            out_of_block = True
            break
        inside = (base_addr <= value < base_addr + size) or (
            read_word is not None and read_word(value) is not None)
        if estimated and (not inside or value % 4):
            break                                   # 表の外に出た = ここまで
        entries.append({
            "index": n,
            "slot": _hex(table + n * 4),
            "target": _hex(value),
            "in_image": inside,
        })

    return {
        "address": _hex(jr_addr),
        "register": _r(jr_reg),
        "table": _hex(table),
        "table_out_of_block": out_of_block,
        "table_how": how,
        "lw_addr": _hex(base_addr + lw_i * 4),
        "entries_declared": entries_declared,
        "count": len(entries),
        "count_is_estimated": estimated,
        "entries": entries,
    }


# --- find_function_entry の判定 (骨格は _prologue.py) --------------------
_SP = 29
_RA = 31
# $sp 相対の保存 / 復帰。プロローグとエピローグの収支を数えるのに使う。
_SP_STORE = frozenset((0x2B, 0x3F, 0x39, 0x3D))     # sw / sd / swc1 / sdc1
_SP_LOAD = frozenset((0x23, 0x37, 0x31, 0x35))      # lw / ld / lwc1 / ldc1


def _is_sp_adjust(word):
    """`addiu $sp,$sp,imm` か。imm<0 ならフレーム確保 = 関数の入口。"""
    return (((word >> 26) & 0x3F) in (0x08, 0x09)
            and ((word >> 21) & 0x1F) == _SP
            and ((word >> 16) & 0x1F) == _SP)


def _is_frame_alloc(word):
    return _is_sp_adjust(word) and _s16(word & 0xFFFF) < 0


def _mips_is_push(word):
    """フレーム確保、または $sp 相対の保存。"""
    op = (word >> 26) & 0x3F
    if _is_frame_alloc(word):
        return True
    return op in _SP_STORE and ((word >> 21) & 0x1F) == _SP


def _mips_is_pop(word):
    """$sp 相対の復帰。"""
    return (((word >> 26) & 0x3F) in _SP_LOAD
            and ((word >> 21) & 0x1F) == _SP)


def _mips_is_end(word):
    """関数の終わり = `jr $ra`。

    ★`jr $rX` (X != $ra) はスイッチの表引きなので**終わりではありません**。
      ここを一律に終わり扱いすると関数が途中で切れ、収支が合わなくなります
      (Thumb の `bx Rm` と同じ形)。
    """
    return (((word >> 26) & 0x3F) == 0x00 and (word & 0x3F) == 0x08
            and ((word >> 21) & 0x1F) == _RA)


def _mips_count_regs(word):
    """収支に数えるレジスタ本数。フレーム確保そのものは 0 本。"""
    return 0 if _is_sp_adjust(word) else 1


def _find_callers(data, base_addr, big_endian, entry):
    """その入口を呼ぶ `jal` と、値として持つ関数ポインタを探します。"""
    index = build_ref_index(data, base_addr, big_endian)
    calls, pointers = [], []
    for at, form, _lui in index.get(entry, []):
        if form == "jal":
            calls.append(_hex(at))
        elif form not in ("j",):
            pointers.append({"addr": _hex(at), "form": form})
    # 関数ポインタ表 (データとして 32bit で置かれている形) も拾う。
    order = "big" if big_endian else "little"
    needle = entry.to_bytes(4, order)
    start = 0
    while len(pointers) < 32:
        hit = bytes(data).find(needle, start)
        if hit < 0 or hit % 4:
            if hit < 0:
                break
            start = hit + 1
            continue
        pointers.append({"addr": _hex(base_addr + hit), "form": "data"})
        start = hit + 4
    return {"calls": sorted(set(calls)), "pointers": pointers,
            "total": len(set(calls)) + len(pointers)}


def find_function_entry(data, base_addr, big_endian, address,
                        max_back=4096, max_forward=8192):
    """指定アドレスを含む関数の入口を命令列から判定します。

    MIPS には push/pop 命令が無いので、**フレーム確保 (`addiu $sp,$sp,-N`) を
    入口の印**、`$sp` 相対の `sw` / `lw` の本数を収支として使います。
    `jr $ra` の**遅延スロットも数えます** (必ず実行されるため)。
    """
    words = to_words(data, big_endian)
    spec = _prologue.PrologueSpec(
        size=4,
        read=lambda i: words[i],
        is_push=_mips_is_push,
        is_pop=_mips_is_pop,
        is_end=_mips_is_end,
        count_regs=_mips_count_regs,
        text=lambda w, a: decode(w, a)["text"],
        is_entry_push=_is_frame_alloc,
        find_refs=lambda e: _find_callers(data, base_addr, big_endian, e),
        delay_slots=1,
    )
    return _prologue.find_entry(spec, len(words), base_addr, address,
                                max_back=max_back, max_forward=max_forward)


# --- list_call_sites の判定 (骨格は _callargs.py) ------------------------
#
# 呼び出し直前に $a0〜$a3 へ積まれた値を復元する。疑似 C が
# `FUN_801a1a0c(param_1,3)` のように引数を落としたとき、3 番目が何かを
# 逆アセンブルの手読みなしで一覧するためのもの。

from . import _callargs  # noqa: E402

# o32 の引数レジスタ。$a0=4 .. $a3=7。
ARG_REGS = (4, 5, 6, 7)
ARG_REG_NAMES = tuple(_r(n) for n in ARG_REGS)

CALL_SITES_NOTE = (
    "$a0〜$a3 は o32 の引数レジスタです。kind=imm は即値、address は "
    "lui + 下位16bit で組み立てたアドレス定数、runtime は実行時に決まる値、"
    "inherited は窓の中で 1 度も書かれていない値 (疑似 C の param_N や、"
    "max_back の外で決まった値) です。**遅延スロット (jal の次の 1 命令) は"
    "呼び出しより先に実行されるので、引数設定として数えています。**"
    "float 引数 ($f12/$f14) と 5 個目以降のスタック渡し引数は見ていません。")

CALL_SITES_BLIND_SPOTS = (
    "$f12 / $f14 経由の float 引数は見ていません (o32 の浮動小数点引数)。",
    "5 個目以降の引数は $sp 相対のスタック渡しになるので見ていません。",
    "呼び出しの直前が分岐の合流点だと、窓の中の代入が実行されるとは限りません "
    "(notes に分岐があれば警告します)。",
    "構造体を値渡しする形 ($a1〜$a3 に詰めて渡す) は「定数」には見えません。",
    "jalr による間接呼び出しは、飛び先を lui+addiu で組み立てている場合しか"
    "結び付けられません (関数ポインタ表から引いて呼ぶ形は拾えません)。",
)

# jalr の funct。
_JALR_FUNCT = 0x09


def _is_call_word(word):
    """呼び出し命令か (引数レジスタが壊れる命令か)。"""
    op = (word >> 26) & 0x3F
    if op == 0x03:                                   # jal
        return True
    if op == 0x00 and (word & 0x3F) == _JALR_FUNCT:  # jalr
        return True
    if op == 0x01 and ((word >> 16) & 0x1F) in (0x10, 0x11):  # bltzal / bgezal
        return True
    return False


def _is_branch_word(word):
    """条件分岐か (窓の中にあると実行されない命令が混じる)。"""
    op = (word >> 26) & 0x3F
    if op in _BRANCH_RS_RT or op in _BRANCH_RS:
        return True
    return op == 0x01 and ((word >> 16) & 0x1F) not in (0x10, 0x11)


def _call_arg_effect(word):
    """1 命令が「どのレジスタに何を入れるか」を返します (_callargs.py の形)。

    完全な命令表ではなく、**引数設定に実際に出てくる形だけ**を解きます。
    解けない書き換えは必ず ("clobber", ...) にして、値を捏造しません。
    """
    op = (word >> 26) & 0x3F
    rs = (word >> 21) & 0x1F
    rt = (word >> 16) & 0x1F
    rd = (word >> 11) & 0x1F
    imm = word & 0xFFFF

    if op == 0x0F:                                   # lui rt, imm
        return ("hi", rt, (imm << 16) & 0xFFFFFFFF)
    if op in (0x08, 0x09):                           # addi / addiu rt, rs, imm
        if rs == 0:
            return ("imm", rt, _s16(imm) & 0xFFFFFFFF)
        return ("combine", rt, rs, _s16(imm), "lui+" + _IMM_SIGNED[op])
    if op == 0x0D:                                   # ori rt, rs, imm
        if rs == 0:
            return ("imm", rt, imm)
        return ("combine", rt, rs, imm, "lui+ori")
    if op in (0x0C, 0x0E):                           # andi / xori
        return ("clobber", rt, "{0} は追っていません。".format(_IMM_LOGICAL[op]))
    if op in (0x0A, 0x0B):                           # slti / sltiu
        return ("clobber", rt, "比較結果です (0 か 1)。")
    if op in _MEM_OPS:
        name = _MEM_OPS[op]
        if name.startswith("s"):
            return None                              # store はレジスタを書かない
        return ("load", rt, rs, _s16(imm), name)
    if op == 0x03:                                   # jal は $ra を潰す
        return ("clobber", 31, "jal が戻り番地を入れます。")
    if op == 0x00:
        funct = word & 0x3F
        if funct in (0x20, 0x21):                    # add / addu rd, rs, rt
            if rt == 0:
                return ("copy", rd, rs)              # move rd, rs
            if rs == 0:
                return ("copy", rd, rt)
            return ("clobber", rd, "2 つのレジスタの和です。")
        if funct in (0x24, 0x25):                    # and / or
            if funct == 0x25 and rt == 0:
                return ("copy", rd, rs)              # or rd, rs, $zero = move
            if funct == 0x25 and rs == 0:
                return ("copy", rd, rt)
            return ("clobber", rd, "レジスタ同士の論理演算です。")
        if funct == _JALR_FUNCT:
            return ("clobber", rd or 31, "jalr が戻り番地を入れます。")
        if funct == 0x08:                            # jr はレジスタを書かない
            return None
        target = _dest_gpr(word)
        if target is None:
            return None
        return ("clobber", target,
                "special funct=0x{0:02x} は追っていません。".format(funct))

    target = _dest_gpr(word)
    if target is None:
        return None
    return ("clobber", target, "op=0x{0:02x} は追っていません。".format(op))


def _call_args_spec():
    """MIPS 用の CallArgsSpec を作ります。"""
    return _callargs.CallArgsSpec(
        size=4,
        arg_regs=ARG_REGS,
        reg_name=_r,
        effect=_call_arg_effect,
        is_call=_is_call_word,
        text=lambda w, a: decode(w, a)["text"],
        delay_slots=1,
        is_branch=_is_branch_word,
        zero_reg=0,
    )


def _jalr_after(words, index, reg, window):
    """index の直後 window 命令以内で `jalr reg` していれば その index を返します。"""
    stop = min(index + 1 + int(window), len(words))
    for j in range(index + 1, stop):
        w = words[j]
        if ((w >> 26) & 0x3F) == 0x00 and (w & 0x3F) == _JALR_FUNCT \
                and ((w >> 21) & 0x1F) == reg:
            return j
        if _dest_gpr(w) == reg:
            return None                      # 別の値で潰された
    return None


def list_call_sites(data, base_addr, big_endian, target, max_back=24,
                    indirect_window=8):
    """target を呼んでいる箇所を、呼び出し時の $a0〜$a3 つきで列挙します。

    直接呼び出し (`jal` / `bal` 系) と**末尾ジャンプ** (`j`) を sites に入れます。
    `lui + addiu` で target のアドレスを組み立てている箇所は、直後に
    `jalr` があれば間接呼び出しとして sites に、無ければ
    **関数ポインタとして値だけ取っている箇所**として address_taken に入れます。
    """
    words = to_words(data, big_endian)
    spec = _call_args_spec()
    sites = []
    address_taken = []

    for i in range(len(words)):
        w = words[i]
        op = (w >> 26) & 0x3F
        addr = base_addr + i * 4
        form = None
        if op in (0x02, 0x03):
            if _jump_target(addr, w & 0x3FFFFFF) != target:
                continue
            form = "jal" if op == 0x03 else "j"
        elif op == 0x01 and ((w >> 16) & 0x1F) in (0x10, 0x11):
            if _branch_target(addr, _s16(w & 0xFFFF)) != target:
                continue
            form = _REGIMM[(w >> 16) & 0x1F]
        if form is None:
            continue
        site = _callargs.resolve_at(spec, words, base_addr, i, max_back)
        site["call_addr"] = _hex(addr)
        site["form"] = form
        site["opcode"] = "0x{0:08x}".format(w)
        site["text"] = decode(w, addr)["text"]
        if form == "j":
            site["notes"] = list(site.get("notes") or []) + [
                "`j` による**末尾ジャンプ**です。引数は呼び出し元から"
                "そのまま引き継がれている可能性が高いので inherited が増えます。"]
        sites.append(site)

    # 間接呼び出し / 関数ポインタ: lui + addiu で target を組み立てている箇所。
    index = build_ref_index(data, base_addr, big_endian)
    for at, form, hi_addr in index.get(target, []):
        if form in ("j", "jal"):
            continue                              # 直接呼び出しは上で拾い済み
        i = (at - base_addr) // 4
        if i < 0 or i >= len(words):
            continue
        reg = _dest_gpr(words[i])
        jalr_i = _jalr_after(words, i, reg, indirect_window) if reg else None
        if jalr_i is not None:
            site = _callargs.resolve_at(spec, words, base_addr, jalr_i, max_back)
            site["call_addr"] = _hex(base_addr + jalr_i * 4)
            site["form"] = "jalr"
            site["opcode"] = "0x{0:08x}".format(words[jalr_i])
            site["text"] = decode(words[jalr_i], base_addr + jalr_i * 4)["text"]
            site["address_built_at"] = _hex(at)
            site["notes"] = list(site.get("notes") or []) + [
                "`jalr` による間接呼び出しです ({0} で飛び先を組み立てています)。".format(
                    _hex(at))]
            sites.append(site)
            continue
        address_taken.append({
            "addr": _hex(at),
            "form": form,
            "hi_addr": _hex(hi_addr),
            "text": decode(words[i], at)["text"],
            "why": "アドレスを値として取っているだけで、ここでは呼んでいません "
                   "(関数ポインタ表に入れる / 別のレジスタ経由で呼ぶ形)。",
        })

    sites.sort(key=lambda s: s["call_addr"])
    return {"sites": sites, "address_taken": address_taken,
            "scanned_instructions": len(words)}


# --- find_immediate の判定 ---------------------------------------------
#
# 「この数値 100 はどこで設定されているか」に答える。find_address_refs は
# **アドレス**、find_bytes は**バイト列**なので、`addiu $a0,$zero,100` のような
# **即値**はどちらでも引けなかった。閾値・ID・フラグ値の出どころ探しに使う。

IMMEDIATE_NOTE = (
    "MIPS の 16bit 即値命令と、`lui` + 下位16bit の合成を見ています。kind は "
    "const (定数をレジスタに作っている。**本命**) / compare (その値と比べている) / "
    "add (何かに足し引きしている) / logic (論理演算) / upper (上位 16bit だけ) / "
    "pair (lui と組にして 32bit を作っている) / offset (ロードストアの変位。"
    "既定では出しません) です。"
    "**値をレジスタ同士の演算で作る形や、データとして表に置いてある形は"
    "拾えません** (後者は find_bytes を使ってください)。")

IMMEDIATE_BLIND_SPOTS = (
    "レジスタ同士の演算で作る値 (例: 10 を足して 100 にする) は拾えません。",
    "データとして表に置いてある値は命令ではないので拾えません "
    "(find_bytes / read_data を使ってください)。",
    "分岐命令の飛び先オフセットは即値として数えていません (意味が違うため)。",
    "ロードストアの変位 (構造体のオフセット) は既定で除いています "
    "(include_offsets=true で出せますが、小さい値では大量に出ます)。",
    "16bit に収まらない値を lui + 下位16bit 以外の方法で作る形は拾えません。",
)

# 即値を持つ命令の分類。op -> (kind, 符号つきか)
_IMM_KIND = {}
for _op in (0x08, 0x09):                      # addi / addiu
    _IMM_KIND[_op] = ("add", True)
for _op in (0x0A, 0x0B):                      # slti / sltiu
    _IMM_KIND[_op] = ("compare", _op == 0x0A)
for _op in (0x0C, 0x0D, 0x0E):                # andi / ori / xori
    _IMM_KIND[_op] = ("logic", False)


def _imm_matches(word, value32):
    """その命令の即値が value32 と一致するかを (kind, 表示値) で返します。

    一致しなければ None。`$zero` を基にしている形は「定数を作っている」と
    して kind="const" に格上げします (これが探しているものの本命)。
    """
    op = (word >> 26) & 0x3F
    rs = (word >> 21) & 0x1F
    imm = word & 0xFFFF

    if op == 0x0F:                                    # lui
        if ((imm << 16) & 0xFFFFFFFF) == value32:
            return ("upper", (imm << 16) & 0xFFFFFFFF)
        return None
    entry = _IMM_KIND.get(op)
    if entry is None:
        return None
    kind, signed = entry
    got = (_s16(imm) & 0xFFFFFFFF) if signed else imm
    if got != value32:
        return None
    if rs == 0 and kind in ("add", "logic"):
        kind = "const"                                # li 相当 (定数を作っている)
    return (kind, got)


def find_immediate(data, base_addr, big_endian, value, include_offsets=False,
                   include_pairs=True, pair_index=None, lo_addr=None,
                   hi_addr=None):
    """その定数を即値として使っている命令を列挙します。

    pair_index に build_ref_index の結果を渡すと、`lui` + 下位16bit で
    組み立てた 32bit 値もまとめて拾います (MCP 側の索引キャッシュを使うため、
    ここでは作り直しません)。
    """
    words = to_words(data, big_endian)
    value32 = value & 0xFFFFFFFF
    first = 0 if lo_addr is None else max(0, (lo_addr - base_addr) // 4)
    last = len(words) if hi_addr is None else min(
        len(words), (hi_addr - base_addr) // 4 + 1)

    hits = []
    for i in range(first, last):
        word = words[i]
        addr = base_addr + i * 4
        got = _imm_matches(word, value32)
        if got is not None:
            kind, shown = got
            hits.append({
                "addr": _hex(addr),
                "kind": kind,
                "form": decode(word, addr)["mnemonic"],
                "value": shown,
                "text": decode(word, addr)["text"],
            })
            continue
        if not include_offsets:
            continue
        op = (word >> 26) & 0x3F
        if op in _MEM_OPS or op in _COP_MEM_OPS:
            if (_s16(word & 0xFFFF) & 0xFFFFFFFF) == value32:
                hits.append({
                    "addr": _hex(addr),
                    "kind": "offset",
                    "form": _MEM_OPS.get(op) or _COP_MEM_OPS.get(op),
                    "value": value32,
                    "text": decode(word, addr)["text"],
                })

    if include_pairs and pair_index:
        for at, form, hi in pair_index.get(value32, []):
            if form in ("j", "jal"):
                continue                     # 飛び先であって定数ではない
            if lo_addr is not None and at < lo_addr:
                continue
            if hi_addr is not None and at > hi_addr:
                continue
            i = (at - base_addr) // 4
            if i < 0 or i >= len(words):
                continue
            hits.append({
                "addr": _hex(at),
                "kind": "pair",
                "form": form,
                "value": value32,
                "hi_addr": _hex(hi),
                "text": decode(words[i], at)["text"],
            })

    hits.sort(key=lambda h: h["addr"])
    return {"hits": hits, "scanned_instructions": max(0, last - first)}


# --- infer_signature の判定 --------------------------------------------
#
# 「この関数は実際に何個引数を取るのか」を、**呼ばれる側**から見るための判定。
# 呼び出し側 (list_call_sites) だけだと、引数を使っているのに全部の呼び出し元が
# 持ち回りで渡している場合に「使っていない」と誤判定する。

ARG_USE_NOTE = (
    "関数の本体を**先頭から順に**走査し、引数レジスタごとに「最初に現れるのが"
    "読み出しか書き込みか」を見ています。読み出しが先なら引数として使われて"
    "いる、書き込みが先ならただの作業用レジスタです。"
    "**分岐は追っていません** (経路によっては順序が変わります)。"
    "$f12 / $f14 経由の float 引数と、スタック渡しの 5 個目以降は見ていません。")


def _src_gprs(word):
    """その命令が**読む**汎用レジスタ番号の集合を返します。

    完全な表ではなく、引数レジスタの用途を見分けるのに要る形だけを見ます。
    迷ったら「読む」側に倒します (読みを見落とすと「使っていない」と
    誤って断定してしまうため。安全側は**使っている**と言う方)。
    """
    op = (word >> 26) & 0x3F
    rs = (word >> 21) & 0x1F
    rt = (word >> 16) & 0x1F

    if op == 0x00:
        funct = word & 0x3F
        if funct in _SPECIAL_SHIFT_IMM:            # sll/srl/sra は rt だけ読む
            return {rt}
        if funct in (0x08, 0x09):                  # jr / jalr
            return {rs}
        if funct in (0x10, 0x12):                  # mfhi / mflo
            return set()
        return {rs, rt}
    if op == 0x01:                                 # regimm (bltz 等)
        return {rs}
    if op in (0x02, 0x03):                         # j / jal
        return set()
    if op in _BRANCH_RS_RT:
        return {rs, rt}
    if op in _BRANCH_RS:
        return {rs}
    if op == 0x0F:                                 # lui は何も読まない
        return set()
    if op in _IMM_SIGNED or op in _IMM_LOGICAL:
        return {rs}
    if op in _MEM_OPS:
        name = _MEM_OPS[op]
        return {rs, rt} if name.startswith("s") else {rs}
    if op in _COP_MEM_OPS:
        return {rs}
    if op in (0x10, 0x11, 0x12):                   # cop0/1/2 (mtc 系は rt を読む)
        return {rt} if ((word >> 21) & 0x1F) in (0x04, 0x06) else set()
    return {rs, rt}


def arg_register_use(data, base_addr, big_endian, entry, end_addr,
                     arg_regs=ARG_REGS, max_scan=2048):
    """引数レジスタが「読まれるのが先か、書かれるのが先か」を返します。

    返り値: {レジスタ番号: {"first": "read"/"write", "at": "0x...",
                           "text": "..."}}。触っていないレジスタは入りません。
    """
    words = to_words(data, big_endian)
    first = (entry - base_addr) // 4
    last = min(len(words), (end_addr - base_addr) // 4 + 1, first + int(max_scan))
    out = {}
    wanted = set(arg_regs)
    for i in range(max(0, first), last):
        if not wanted:
            break
        word = words[i]
        addr = base_addr + i * 4
        reads = _src_gprs(word) & wanted
        for reg in sorted(reads):
            out[reg] = {"first": "read", "at": _hex(addr),
                        "text": decode(word, addr)["text"]}
            wanted.discard(reg)
        dest = _dest_gpr(word)
        if dest in wanted:
            out[dest] = {"first": "write", "at": _hex(addr),
                         "text": decode(word, addr)["text"]}
            wanted.discard(dest)
        if _is_call_word(word):
            # ★呼び出しを跨ぐと引数レジスタは壊れる。ここから先で読まれても
            #   「この関数の引数として使った」ことにはならない。
            break
    return out


# ---------------------------------------------------------------------------
# gp 相対 (get_program_info の gp / get_disassembly の resolve_gp /
#          resolve_gp_offset)
#
# PS2 (r5900) の小さいグローバルは `lw $v0,-29048($gp)` の形で読まれ、
# **参照先の番地が命令に現れない**。gp の値が分かれば `gp + off` で決まる。
# ここには「どの命令が gp 相対か」「どこで gp を作っているか」の**判定だけ**を置く
# (gp の値をどの根拠から採るかは MCP 本体の共通層が決める)。
# ---------------------------------------------------------------------------

_GP = 28
_V1 = 3
_A0 = 4
# PS2 の SetupThread システムコール番号。crt0 は `lui $gp` をせず、
# gp の値を $a0 に入れて SetupThread に渡す (カーネルがスレッドの gp に入れる)。
_PS2_SETUP_THREAD = 0x3C
# gp を組み立てる命令列を探す窓 (命令数)。crt0 の lui と addiu は離れていることがある。
GP_SETUP_WINDOW = 32
# gp 相対になりうる即値命令 (addi / addiu / daddi / daddiu)。アドレス計算に使う。
_GP_ADD_OPS = frozenset((0x08, 0x09, 0x18, 0x19))

GP_NOTE = (
    "gp 相対 (off($gp)) の実効番地は gp + 符号付き 16bit です。"
    "gp の値は Program 全体で 1 つとは限りません (別モジュール / IRX は別の gp を"
    "持ちます)。Ghidra のコンテキスト値が範囲ごとにあるときは、命令の番地で引きます。")


def gp_relative(word):
    """その命令が gp 相対 (`lw rt,off($gp)` / `addiu rt,$gp,off`) なら off を返します。

    返り値は符号付き 16bit (int)。gp 相対でなければ None。
    `addiu $gp,$gp,lo` (gp 自身を作る命令) は参照ではないので None です。
    """
    word &= 0xFFFFFFFF
    op = (word >> 26) & 0x3F
    if ((word >> 21) & 0x1F) != _GP:
        return None
    if op in _MEM_OPS or op in _COP_MEM_OPS:
        return _s16(word & 0xFFFF)
    if op in _GP_ADD_OPS and ((word >> 16) & 0x1F) != _GP:
        return _s16(word & 0xFFFF)
    return None


def _track_constants(words, lo, hi):
    """words[lo:hi] を前向きになぞり、即値だけで決まるレジスタ値を返します。

    lui / addiu / ori / addu・or・daddu (両方既知) / move だけを追います。
    それ以外でレジスタが書かれたら「分からない」として忘れます (推測しない)。
    返り値: {レジスタ番号: 32bit 値}
    """
    regs = {0: 0}
    for k in range(max(0, lo), hi):
        w = words[k]
        op = (w >> 26) & 0x3F
        rs = (w >> 21) & 0x1F
        rt = (w >> 16) & 0x1F
        imm = w & 0xFFFF
        dest = _dest_gpr(w)
        value = None
        if op == 0x0F:
            value = imm << 16
        elif op in _GP_ADD_OPS and rs in regs:
            value = regs[rs] + _s16(imm)
        elif op == 0x0D and rs in regs:
            value = regs[rs] | imm
        elif op == 0x00 and (w & 0x3F) in (0x20, 0x21, 0x2C, 0x2D, 0x25) \
                and rs in regs and rt in regs:
            value = (regs[rs] | regs[rt]) if (w & 0x3F) == 0x25 else regs[rs] + regs[rt]
        if dest is None or dest == 0:
            continue
        if value is None:
            regs.pop(dest, None)
        else:
            regs[dest] = value & 0xFFFFFFFF
    return regs


def find_gp_setup(data, base_addr, big_endian, start=None, count=None,
                  window=GP_SETUP_WINDOW):
    """gp を組み立てている命令列を探し、[{value, at, form, text}] で返します。

    見る形は 2 つです:
      - `lui $gp,HI` → `addiu/ori $gp,$gp,LO` (form="lui+addiu gp" 等)
      - PS2 crt0 の `SetupThread` 呼び出し: `$v1=0x3c` で `syscall` するときの
        `$a0` (form="ps2 SetupThread a0")。Sony の crt0 は gp を直接組まず、
        この引数でカーネルに渡す。
    start / count を省くとデータ全体を走査します (code_scan 用)。
    """
    words = to_words(data, big_endian)
    total = len(words)
    first = 0 if start is None else max(0, (int(start) - base_addr) // 4)
    last = total if count is None else min(total, first + int(count))
    found = []
    for i in range(first, last):
        w = words[i]
        if (w & 0xFFFF0000) == 0x3C1C0000:                 # lui $gp,HI
            hi = (w & 0xFFFF) << 16
            for j in range(i + 1, min(total, i + 1 + window)):
                wj = words[j]
                opj = (wj >> 26) & 0x3F
                if ((wj >> 21) & 0x1F) == _GP and ((wj >> 16) & 0x1F) == _GP \
                        and opj in (0x09, 0x19, 0x08, 0x0D):
                    lo = wj & 0xFFFF
                    value = (hi | lo) if opj == 0x0D else hi + _s16(lo)
                    addr = base_addr + j * 4
                    found.append({"value": value & 0xFFFFFFFF, "at": _hex(addr),
                                  "lui_at": _hex(base_addr + i * 4),
                                  "form": "lui+{0} gp".format(
                                      "ori" if opj == 0x0D else "addiu"),
                                  "text": decode(wj, addr)["text"]})
                    break
                if _dest_gpr(wj) == _GP:
                    break
        elif w == 0x0000000C:                             # syscall
            regs = _track_constants(words, i - window, i)
            if regs.get(_V1) == _PS2_SETUP_THREAD and _A0 in regs:
                addr = base_addr + i * 4
                found.append({"value": regs[_A0], "at": _hex(addr),
                              "form": "ps2 SetupThread a0",
                              "text": "syscall ; SetupThread(gp=$a0)"})
    return found
