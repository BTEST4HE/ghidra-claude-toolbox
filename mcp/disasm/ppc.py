# -*- coding: utf-8 -*-
"""PowerPC (Gekko / Broadway = PowerPC 750CL) の逆アセンブラ (Python 3.13 前提)。

GameCube / Wii の main.dol / .rel を読むためのものです。MIPS / SH-4 と同じ
インターフェース (NAME / DISPLAY / INSTRUCTION_SIZE / decode / word_at /
build_ref_index) を実装しているので、MCP 本体には分岐を増やしません。

★**ビッグエンディアン**です。GameCube / Wii の実行ファイルは常に BE なので、
  `big_endian=False` で呼ぶと全命令がゴミになります。

★**遅延スロットはありません** (MIPS の感覚で書かないこと)。分岐の次の命令は
  実行されません。`HAS_DELAY_SLOTS = False`。

アドレスの組み立ては `lis rX, HI` + `addi/ori/lwz/stw ... (rX)` で、
MIPS の `lui` + `addiu` と**同じ形**です。そのため `build_ref_index` は
MIPS 版とほぼ同じ考え方で書けています。

未知の語は `.long 0x........` として返し、例外は投げません
(未関数化領域にはデータが混ざるため、落ちずに読めることを優先)。
"""

NAME = "ppc"
DISPLAY = "PowerPC 32bit (Gekko / Broadway)"
INSTRUCTION_SIZE = 4

# ★PowerPC に遅延スロットは無い。
HAS_DELAY_SLOTS = False

REFS_NOTE = (
    "`lis rX, HI` と、その後の `addi / ori / lwz / stw ...` の下位 16bit を"
    "合成して照合します (MIPS の lui + addiu と同じ形)。"
    "`b` / `bl` の飛び先も同じ索引に入れています。"
    "**r2 / r13 相対 (SDA / small data area) の参照は拾えません** — "
    "GameCube のコンパイラは静的データをここ経由で読むことが多いので、"
    "0 件でも「参照が無い」とは限りません。")

REFS_BLIND_SPOTS = (
    "r2 / r13 相対 (SDA) の参照は拾えません。GameCube では静的データの"
    "読み書きがこの形になっていることが多いです。",
    "`lis` の結果を `mr` で別レジスタへ写してから使う形は拾えません。",
    "window (既定 8 命令) を越えて離れた位置で下位 16bit を足す形は拾えません。",
    "テーブルから読んだアドレスへ `bctr` で飛ぶ形は、命令にアドレスが"
    "現れないので拾えません。",
)

# 汎用レジスタ名。
REG = tuple("r{0}".format(i) for i in range(32))
FREG = tuple("f{0}".format(i) for i in range(32))

# 条件レジスタのビット名 (BI の下位 2bit)。
_CRBIT = ("lt", "gt", "eq", "so")
# BO=12 (条件が真なら分岐) / BO=4 (偽なら分岐) の簡略ニーモニック。
_BC_TRUE = {0: "blt", 1: "bgt", 2: "beq", 3: "bso"}
_BC_FALSE = {0: "bge", 1: "ble", 2: "bne", 3: "bns"}

# D 形式 (opcd, ニーモニック, 種別)。種別: "gpr" / "fpr" / "store" / "load"
_D_FORM = {
    7:  ("mulli", "arith"),
    8:  ("subfic", "arith"),
    12: ("addic", "arith"),
    13: ("addic.", "arith"),
    14: ("addi", "arith"),
    15: ("addis", "arith"),
    24: ("ori", "logic"),
    25: ("oris", "logic"),
    26: ("xori", "logic"),
    27: ("xoris", "logic"),
    28: ("andi.", "logic"),
    29: ("andis.", "logic"),
}

# D 形式のロード / ストア (opcd -> (ニーモニック, 浮動小数か, ストアか))。
_D_MEM = {
    32: ("lwz", False, False), 33: ("lwzu", False, False),
    34: ("lbz", False, False), 35: ("lbzu", False, False),
    36: ("stw", False, True),  37: ("stwu", False, True),
    38: ("stb", False, True),  39: ("stbu", False, True),
    40: ("lhz", False, False), 41: ("lhzu", False, False),
    42: ("lha", False, False), 43: ("lhau", False, False),
    44: ("sth", False, True),  45: ("sthu", False, True),
    46: ("lmw", False, False), 47: ("stmw", False, True),
    48: ("lfs", True, False),  49: ("lfsu", True, False),
    50: ("lfd", True, False),  51: ("lfdu", True, False),
    52: ("stfs", True, True),  53: ("stfsu", True, True),
    54: ("stfd", True, True),  55: ("stfdu", True, True),
}

# opcd=31 の拡張命令 (XO = bit21-30)。OE を持たないもの。
_X31 = {
    0: "cmp", 4: "tw", 11: "mulhwu", 19: "mfcr", 20: "lwarx", 23: "lwzx",
    24: "slw", 26: "cntlzw", 28: "and", 32: "cmpl", 54: "dcbst", 55: "lwzux",
    60: "andc", 75: "mulhw", 83: "mfmsr", 86: "dcbf", 87: "lbzx",
    119: "lbzux", 124: "nor", 144: "mtcrf", 146: "mtmsr", 150: "stwcx.",
    151: "stwx", 183: "stwux", 210: "mtsr", 215: "stbx", 242: "mtsrin",
    246: "dcbtst", 247: "stbux", 278: "dcbt", 279: "lhzx", 284: "eqv",
    306: "tlbie", 310: "eciwx", 311: "lhzux", 316: "xor", 339: "mfspr",
    343: "lhax", 371: "mftb", 375: "lhaux", 407: "sthx", 412: "orc",
    438: "ecowx", 439: "sthux", 444: "or", 467: "mtspr", 470: "dcbi",
    476: "nand", 512: "mcrxr", 533: "lswx", 534: "lwbrx", 535: "lfsx",
    536: "srw", 567: "lfsux", 595: "mfsr", 597: "lswi", 598: "sync",
    599: "lfdx", 631: "lfdux", 659: "mfsrin", 661: "stswx", 662: "stwbrx",
    663: "stfsx", 695: "stfsux", 725: "stswi", 727: "stfdx", 759: "stfdux",
    566: "tlbsync",
    790: "lhbrx", 792: "sraw", 824: "srawi", 854: "eieio", 918: "sthbrx",
    922: "extsh", 954: "extsb", 982: "icbi", 983: "stfiwx", 1014: "dcbz",
}

# opcd=31 で OE を持つ算術命令 (XO = bit22-30)。OE=1 なら末尾に "o" が付く。
_XO31 = {
    8: "subfc", 10: "addc", 40: "subf", 104: "neg", 136: "subfe",
    138: "adde", 200: "subfze", 202: "addze", 232: "subfme", 234: "addme",
    235: "mullw", 266: "add", 459: "divwu", 491: "divw",
}

# opcd=31 のうち、書き込み先が rA になるもの (通常は rD/rS)。
_X31_DEST_RA = frozenset((
    "slw", "srw", "sraw", "srawi", "cntlzw", "and", "andc", "or", "orc",
    "nor", "nand", "xor", "eqv", "extsb", "extsh"))

# opcd=31 のロード / ストア。
_X31_STORE = frozenset((
    "stwx", "stwux", "stbx", "stbux", "sthx", "sthux", "stswx", "stswi",
    "stwbrx", "sthbrx", "stfsx", "stfsux", "stfdx", "stfdux", "stfiwx",
    "stwcx."))
_X31_LOAD = frozenset((
    "lwzx", "lwzux", "lbzx", "lbzux", "lhzx", "lhzux", "lhax", "lhaux",
    "lswx", "lswi", "lwbrx", "lhbrx", "lfsx", "lfsux", "lfdx", "lfdux",
    "lwarx"))

# opcd=19 (XL 形式)。
_XL19 = {
    0: "mcrf", 16: "bclr", 33: "crnor", 50: "rfi", 129: "crandc",
    150: "isync", 193: "crxor", 225: "crnand", 257: "crand", 289: "creqv",
    417: "crorc", 449: "cror", 528: "bcctr",
}

# opcd=59 / 63 (A 形式の浮動小数)。XO は bit26-30 (5bit)。
_A59 = {18: "fdivs", 20: "fsubs", 21: "fadds", 22: "fsqrts", 24: "fres",
        25: "fmuls", 28: "fmsubs", 29: "fmadds", 30: "fnmsubs", 31: "fnmadds"}
_A63 = {18: "fdiv", 20: "fsub", 21: "fadd", 22: "fsqrt", 23: "fsel",
        25: "fmul", 26: "frsqrte", 28: "fmsub", 29: "fmadd", 30: "fnmsub",
        31: "fnmadd"}
# opcd=63 の X 形式 (XO は bit21-30)。
_X63 = {0: "fcmpu", 12: "frsp", 14: "fctiw", 15: "fctiwz", 32: "fcmpo",
        38: "mtfsb1", 40: "fneg", 64: "mcrfs", 70: "mtfsb0", 72: "fmr",
        134: "mtfsfi", 136: "fnabs", 264: "fabs", 583: "mffs", 711: "mtfsf"}

# Gekko の paired-single ロード / ストア (opcd 56/57/60/61)。
_PSQ = {56: "psq_l", 57: "psq_lu", 60: "psq_st", 61: "psq_stu"}

# 特殊レジスタ (mfspr / mtspr でよく出るもの)。
_SPR = {1: "xer", 8: "lr", 9: "ctr", 18: "dsisr", 19: "dar", 22: "dec",
        25: "sdr1", 26: "srr0", 27: "srr1", 272: "sprg0", 273: "sprg1",
        274: "sprg2", 275: "sprg3", 282: "ear", 287: "pvr",
        936: "ummcr0", 952: "mmcr0",
        1008: "hid0", 1009: "hid1", 1017: "l2cr"}
# ★IBAT / DBAT (528〜543) は「番号つきの組」なので名前を作らない。
#   mfibat0u のような名前を勝手に付けると、530 / 532 … を取り違える。
#   素の `mfspr rD, 528` で出す (曖昧さが無い)。

# 即値ペアを探す窓 (命令数)。
PAIR_WINDOW = 8


def _r(index):
    """汎用レジスタ名を返します。"""
    return REG[index & 0x1F]


def _f(index):
    """浮動小数レジスタ名を返します。"""
    return FREG[index & 0x1F]


def _s16(value):
    """16bit を符号つきにします。"""
    value &= 0xFFFF
    return value - 0x10000 if value & 0x8000 else value


def _hex(value):
    """32bit アドレスを '0x........' 表記にします。"""
    return "0x{0:08x}".format(value & 0xFFFFFFFF)


def _imm(value):
    """即値を読みやすい 10 進 / 16 進にします。"""
    if -9 <= value <= 9:
        return str(value)
    return "-0x{0:x}".format(-value) if value < 0 else "0x{0:x}".format(value)


def _out(mnemonic, operands="", target=None, flow=None):
    """decode の戻り値を組み立てます。"""
    text = "{0} {1}".format(mnemonic, operands).strip() if operands else mnemonic
    return {"mnemonic": mnemonic, "operands": operands, "text": text,
            "target": _hex(target) if target is not None else None,
            "flow": flow}


def _rc(mnemonic, word):
    """Rc ビット (bit0) が立っていれば末尾に '.' を付けます。"""
    return mnemonic + "." if (word & 1) else mnemonic


def _crbit(index):
    """条件レジスタのビット名を返します (例: 6 -> "cr1eq")。"""
    return "cr{0}{1}".format(index >> 2, _CRBIT[index & 3])


def _crf(field):
    """条件レジスタ番号を表示用にします (cr0 は省略)。"""
    return "" if field == 0 else "cr{0}, ".format(field)


def _decode_branch(word, addr):
    """opcd=18 (b / ba / bl / bla)。"""
    li = word & 0x03FFFFFC
    if li & 0x02000000:
        li -= 0x04000000
    aa = (word >> 1) & 1
    lk = word & 1
    target = (li if aa else addr + li) & 0xFFFFFFFF
    name = "b" + ("l" if lk else "") + ("a" if aa else "")
    return _out(name, _hex(target), target=target,
                flow="call" if lk else "jump")


def _decode_bc(word, addr):
    """opcd=16 (bc)。よく出る簡略ニーモニックは展開します。"""
    bo = (word >> 21) & 0x1F
    bi = (word >> 16) & 0x1F
    bd = word & 0xFFFC
    if bd & 0x8000:
        bd -= 0x10000
    aa = (word >> 1) & 1
    lk = word & 1
    target = (bd if aa else addr + bd) & 0xFFFFFFFF
    flow = "call" if lk else "branch"
    suffix = ("l" if lk else "") + ("a" if aa else "")

    # ★BO の最下位ビットは**分岐予測ヒント** (y) なので、簡略形の判定では
    #   無視する。ここを見ていないと beq が bc のまま出る。
    if bo in (12, 13):
        name = _BC_TRUE.get(bi & 3)
        if name:
            return _out(name + suffix,
                        "{0}{1}".format(_crf(bi >> 2), _hex(target)),
                        target=target, flow=flow)
    if bo in (4, 5):
        name = _BC_FALSE.get(bi & 3)
        if name:
            return _out(name + suffix,
                        "{0}{1}".format(_crf(bi >> 2), _hex(target)),
                        target=target, flow=flow)
    if bo in (16, 18):
        name = ("bdnz" if bo == 16 else "bdz") + suffix
        return _out(name, _hex(target), target=target, flow=flow)
    return _out("bc" + suffix, "{0}, {1}, {2}".format(bo, bi, _hex(target)),
                target=target, flow=flow)


def _decode_xl(word):
    """opcd=19 (bclr / bcctr / cr 論理演算 / rfi / isync)。"""
    xo = (word >> 1) & 0x3FF
    name = _XL19.get(xo)
    bo = (word >> 21) & 0x1F
    bi = (word >> 16) & 0x1F
    lk = word & 1
    if name == "bclr":
        if bo in (20, 21):
            return _out("blrl" if lk else "blr", flow="return")
        cond = _BC_TRUE.get(bi & 3) if bo in (12, 13) else (
            _BC_FALSE.get(bi & 3) if bo in (4, 5) else None)
        if cond:
            return _out(cond + "lr" + ("l" if lk else ""),
                        _crf(bi >> 2).rstrip(", "), flow="return")
        return _out("bclrl" if lk else "bclr", "{0}, {1}".format(bo, bi),
                    flow="return")
    if name == "bcctr":
        flow = "call_reg" if lk else "jump_reg"
        if bo in (20, 21):
            return _out("bctrl" if lk else "bctr", flow=flow)
        cond = _BC_TRUE.get(bi & 3) if bo in (12, 13) else (
            _BC_FALSE.get(bi & 3) if bo in (4, 5) else None)
        if cond:
            return _out(cond + "ctr" + ("l" if lk else ""),
                        _crf(bi >> 2).rstrip(", "), flow=flow)
        return _out("bcctrl" if lk else "bcctr", "{0}, {1}".format(bo, bi),
                    flow=flow)
    if name in ("rfi", "isync"):
        return _out(name, flow="return" if name == "rfi" else None)
    if name == "mcrf":
        return _out("mcrf", "cr{0}, cr{1}".format((word >> 23) & 7,
                                                  (word >> 18) & 7))
    if name and name.startswith("cr"):
        d = (word >> 21) & 0x1F
        a = (word >> 16) & 0x1F
        b = (word >> 11) & 0x1F
        # よく出る簡略形 (コンパイラが条件フラグを作るのに使う定型)。
        if name == "crxor" and d == a == b:
            return _out("crclr", _crbit(d))
        if name == "creqv" and d == a == b:
            return _out("crset", _crbit(d))
        if name == "cror" and a == b:
            return _out("crmove", "{0}, {1}".format(_crbit(d), _crbit(a)))
        if name == "crnor" and a == b:
            return _out("crnot", "{0}, {1}".format(_crbit(d), _crbit(a)))
        return _out(name, "{0}, {1}, {2}".format(
            _crbit(d), _crbit(a), _crbit(b)))
    if name:
        return _out(name, "{0}, {1}, {2}".format(
            (word >> 21) & 0x1F, (word >> 16) & 0x1F, (word >> 11) & 0x1F))
    return _out(".long", "0x{0:08x} ; opcd=19 xo={1}".format(word, xo))


def _decode_x31(word, addr):
    """opcd=31 (X / XO 形式)。"""
    d = (word >> 21) & 0x1F
    a = (word >> 16) & 0x1F
    b = (word >> 11) & 0x1F
    xo10 = (word >> 1) & 0x3FF

    name = _X31.get(xo10)
    if name is not None:
        if name in ("cmp", "cmpl"):
            wide = (word >> 21) & 1
            pretty = ({"cmp": "cmpd", "cmpl": "cmpld"} if wide
                      else {"cmp": "cmpw", "cmpl": "cmplw"})[name]
            return _out(pretty, "{0}{1}, {2}".format(
                _crf(d >> 2), _r(a), _r(b)))
        if name in ("mfspr", "mtspr"):
            spr = ((word >> 16) & 0x1F) | (((word >> 11) & 0x1F) << 5)
            pretty = _SPR.get(spr)
            if pretty and name == "mfspr":
                return _out("mf" + pretty, _r(d))
            if pretty and name == "mtspr":
                return _out("mt" + pretty, _r(d))
            return _out(name, "{0}, {1}".format(d, _r(d)) if False else
                        ("{0}, {1}".format(spr, _r(d)) if name == "mtspr"
                         else "{0}, {1}".format(_r(d), spr)))
        if name == "mftb":
            spr = ((word >> 16) & 0x1F) | (((word >> 11) & 0x1F) << 5)
            return _out("mftbu" if spr == 269 else "mftb", _r(d))
        if name == "mfcr":
            return _out("mfcr", _r(d))
        if name == "mtcrf":
            return _out("mtcrf", "0x{0:x}, {1}".format((word >> 12) & 0xFF, _r(d)))
        if name == "srawi":
            return _out(_rc("srawi", word), "{0}, {1}, {2}".format(
                _r(a), _r(d), b))
        if name == "or" and d == b:
            return _out(_rc("mr", word), "{0}, {1}".format(_r(a), _r(d)))
        if name in ("cntlzw", "extsb", "extsh"):
            return _out(_rc(name, word), "{0}, {1}".format(_r(a), _r(d)))
        if name in _X31_DEST_RA:
            return _out(_rc(name, word), "{0}, {1}, {2}".format(
                _r(a), _r(d), _r(b)))
        if name in _X31_STORE or name in _X31_LOAD:
            reg = _f(d) if name.startswith("lf") or name.startswith("stf") \
                else _r(d)
            return _out(name, "{0}, {1}, {2}".format(reg, _r(a), _r(b)))
        if name in ("sync", "eieio", "isync", "tlbsync"):
            return _out(name)
        if name in ("dcbst", "dcbf", "dcbt", "dcbtst", "dcbi", "dcbz", "icbi"):
            return _out(name, "{0}, {1}".format(_r(a), _r(b)))
        return _out(_rc(name, word), "{0}, {1}, {2}".format(
            _r(d), _r(a), _r(b)))

    xo9 = (word >> 1) & 0x1FF
    name = _XO31.get(xo9)
    if name is not None:
        if (word >> 10) & 1:
            name += "o"
        if name.startswith("neg") or name.startswith("subfze") \
                or name.startswith("addze") or name.startswith("subfme") \
                or name.startswith("addme"):
            return _out(_rc(name, word), "{0}, {1}".format(_r(d), _r(a)))
        return _out(_rc(name, word), "{0}, {1}, {2}".format(
            _r(d), _r(a), _r(b)))
    return _out(".long", "0x{0:08x} ; opcd=31 xo={1}".format(word, xo10))


def _decode_fp(word, opcd):
    """opcd=59 / 63 (浮動小数)。"""
    d = (word >> 21) & 0x1F
    a = (word >> 16) & 0x1F
    b = (word >> 11) & 0x1F
    c = (word >> 6) & 0x1F
    xo5 = (word >> 1) & 0x1F
    table = _A59 if opcd == 59 else _A63
    name = table.get(xo5)
    if name is not None:
        if name in ("fmadd", "fmsub", "fnmadd", "fnmsub", "fmadds", "fmsubs",
                    "fnmadds", "fnmsubs", "fsel"):
            return _out(_rc(name, word), "{0}, {1}, {2}, {3}".format(
                _f(d), _f(a), _f(c), _f(b)))
        if name in ("fmul", "fmuls"):
            return _out(_rc(name, word), "{0}, {1}, {2}".format(
                _f(d), _f(a), _f(c)))
        if name in ("fsqrt", "fsqrts", "fres", "frsqrte"):
            return _out(_rc(name, word), "{0}, {1}".format(_f(d), _f(b)))
        return _out(_rc(name, word), "{0}, {1}, {2}".format(
            _f(d), _f(a), _f(b)))
    if opcd == 63:
        name = _X63.get((word >> 1) & 0x3FF)
        if name is not None:
            if name in ("fcmpu", "fcmpo"):
                return _out(name, "{0}{1}, {2}".format(
                    _crf(d >> 2), _f(a), _f(b)))
            if name in ("mffs",):
                return _out(_rc(name, word), _f(d))
            if name in ("mtfsb0", "mtfsb1"):
                return _out(_rc(name, word), str(d))
            if name == "mcrfs":
                return _out(name, "cr{0}, cr{1}".format(d >> 2, a >> 2))
            if name == "mtfsf":
                return _out(_rc(name, word), "0x{0:x}, {1}".format(
                    (word >> 17) & 0xFF, _f(b)))
            if name == "mtfsfi":
                return _out(_rc(name, word), "cr{0}, {1}".format(
                    d >> 2, (word >> 12) & 0xF))
            return _out(_rc(name, word), "{0}, {1}".format(_f(d), _f(b)))
    return _out(".long", "0x{0:08x} ; opcd={1}".format(word, opcd))


def decode(word, addr):
    """1 命令語 (32bit int) をデコードし、dict で返します。

    返す dict: mnemonic / operands / text / target / flow。
    flow は "branch" / "jump" / "call" / "call_reg" / "jump_reg" / "return" / None。
    """
    word &= 0xFFFFFFFF
    opcd = (word >> 26) & 0x3F
    d = (word >> 21) & 0x1F
    a = (word >> 16) & 0x1F
    simm = _s16(word & 0xFFFF)
    uimm = word & 0xFFFF

    if opcd == 16:
        return _decode_bc(word, addr)
    if opcd == 17:
        return _out("sc", flow=None)
    if opcd == 18:
        return _decode_branch(word, addr)
    if opcd == 19:
        return _decode_xl(word)
    if opcd == 31:
        return _decode_x31(word, addr)

    if opcd in (20, 21, 23):
        sh = (word >> 11) & 0x1F
        mb = (word >> 6) & 0x1F
        me = (word >> 1) & 0x1F
        name = {20: "rlwimi", 21: "rlwinm", 23: "rlwnm"}[opcd]
        third = _r((word >> 11) & 0x1F) if opcd == 23 else str(sh)
        if opcd == 21:
            if mb == 0 and me == 31 - sh and sh:
                return _out(_rc("slwi", word), "{0}, {1}, {2}".format(
                    _r(a), _r(d), sh))
            if me == 31 and mb == 32 - sh and sh:
                return _out(_rc("srwi", word), "{0}, {1}, {2}".format(
                    _r(a), _r(d), 32 - sh))
            if sh == 0 and me == 31 and mb:
                return _out(_rc("clrlwi", word), "{0}, {1}, {2}".format(
                    _r(a), _r(d), mb))
            if sh == 0 and mb == 0 and me != 31:
                return _out(_rc("clrrwi", word), "{0}, {1}, {2}".format(
                    _r(a), _r(d), 31 - me))
            if mb == 0 and me == 31:
                return _out(_rc("rotlwi", word), "{0}, {1}, {2}".format(
                    _r(a), _r(d), sh))
        return _out(_rc(name, word), "{0}, {1}, {2}, {3}, {4}".format(
            _r(a), _r(d), third, mb, me))

    if opcd in (10, 11):
        # L=0 なら 32bit 比較。PowerPC32 では cmpwi / cmplwi と書くのが普通で、
        # Ghidra も capstone もその形で出す。
        wide = (word >> 21) & 1
        if opcd == 10:
            name = "cmpldi" if wide else "cmplwi"
        else:
            name = "cmpdi" if wide else "cmpwi"
        value = "0x{0:x}".format(uimm) if opcd == 10 else _imm(simm)
        return _out(name, "{0}{1}, {2}".format(_crf(d >> 2), _r(a), value))

    if opcd in _D_FORM:
        name, kind = _D_FORM[opcd]
        if opcd == 14 and a == 0:
            return _out("li", "{0}, {1}".format(_r(d), _imm(simm)))
        if opcd == 15 and a == 0:
            return _out("lis", "{0}, 0x{1:x}".format(_r(d), uimm))
        if kind == "logic":
            if opcd == 24 and d == 0 and a == 0 and uimm == 0:
                return _out("nop")
            return _out(name, "{0}, {1}, 0x{2:x}".format(_r(a), _r(d), uimm))
        return _out(name, "{0}, {1}, {2}".format(_r(d), _r(a), _imm(simm)))

    if opcd in _D_MEM:
        name, is_fp, _store = _D_MEM[opcd]
        reg = _f(d) if is_fp else _r(d)
        return _out(name, "{0}, {1}({2})".format(reg, _imm(simm), _r(a)))

    if opcd in _PSQ:
        name = _PSQ[opcd]
        disp = word & 0xFFF
        if disp & 0x800:
            disp -= 0x1000
        return _out(name, "{0}, {1}({2}), {3}, {4}".format(
            _f(d), _imm(disp), _r(a), (word >> 15) & 1, (word >> 12) & 7))

    if opcd == 4:
        # Gekko の paired-single 演算。展開していない (未対応と明示する)。
        return _out("ps_op", "0x{0:07x} ; Gekko paired-single (未展開)".format(
            word & 0x3FFFFFF))
    if opcd in (59, 63):
        return _decode_fp(word, opcd)
    if opcd == 3:
        return _out("twi", "{0}, {1}, {2}".format(d, _r(a), _imm(simm)))

    return _out(".long", "0x{0:08x} ; opcd=0x{1:02x}".format(word, opcd))


def word_at(data, offset, big_endian):
    """バイト列から 32bit 命令語を 1 つ取り出します。範囲外なら None。"""
    if offset < 0 or offset + 4 > len(data):
        return None
    return int.from_bytes(data[offset:offset + 4], "big" if big_endian else "little")


def to_words(data, big_endian):
    """バイト列を 32bit 命令語の array に変換します (4 バイト境界で切り捨て)。"""
    import array
    import sys

    code = "I" if array.array("I").itemsize == 4 else "L"
    words = array.array(code)
    limit = len(data) - (len(data) % 4)
    words.frombytes(bytes(data[:limit]))
    if big_endian != (sys.byteorder == "big"):
        words.byteswap()
    return words


def _dest_gpr(word):
    """その命令が書き換える汎用レジスタ番号を返します (無ければ None)。

    即値ペア走査で「lis の結果レジスタが潰されたか」を見るために使います。
    完全な表ではなく、実際に潰す代表的な形だけを見ます。
    """
    opcd = (word >> 26) & 0x3F
    d = (word >> 21) & 0x1F
    a = (word >> 16) & 0x1F

    if opcd in (7, 8, 12, 13, 14, 15):        # mulli/subfic/addic/addi/addis
        return d
    if opcd in (24, 25, 26, 27, 28, 29):      # ori/oris/xori/xoris/andi./andis.
        return a
    if opcd in (20, 21, 23):                  # rlwimi / rlwinm / rlwnm
        return a
    if opcd in _D_MEM:
        name, is_fp, store = _D_MEM[opcd]
        if is_fp:
            return a if name.endswith("u") else None   # 更新形は rA を書く
        if store:
            return a if name.endswith("u") else None
        return d
    if opcd == 31:
        xo10 = (word >> 1) & 0x3FF
        name = _X31.get(xo10)
        if name is not None:
            if name in _X31_DEST_RA:
                return a
            if name in _X31_LOAD:
                return d
            if name in _X31_STORE:
                return None
            if name in ("mfcr", "mfspr", "mftb", "mfmsr", "mfsr", "mfsrin"):
                return d
            if name in ("cmp", "cmpl", "mtspr", "mtcrf", "mtmsr", "mtsr",
                        "sync", "eieio", "tlbie", "dcbst", "dcbf", "dcbt",
                        "dcbtst", "dcbi", "dcbz", "icbi", "tw"):
                return None
            return d
        if ((word >> 1) & 0x1FF) in _XO31:
            return d
        return None
    return None


def build_ref_index(data, base_addr, big_endian, window=PAIR_WINDOW):
    """`lis + 下位16bit` で合成されるアドレスの索引を作ります。

    返り値: {合成アドレス(int): [(参照命令アドレス, form, lis のアドレス), ...]}

    PowerPC は 32bit 定数を `lis rX, hi` と後続命令の下位 16bit で組み立てます
    (MIPS の lui + addiu と同じ形)。`addi` / ロードストアの変位は**符号つき**、
    `ori` は**ゼロ拡張**なので、合成の仕方を分けています。
    `b` / `bl` の飛び先も同じ索引に入れます (form="b"/"bl")。
    """
    index = {}
    words = to_words(data, big_endian)
    count = len(words)

    for i in range(count):
        w = words[i]
        opcd = (w >> 26) & 0x3F
        addr = base_addr + i * 4

        if opcd == 18:
            got = _decode_branch(w, addr)
            tgt = int(got["target"], 16)
            index.setdefault(tgt, []).append(
                (addr, "bl" if (w & 1) else "b", addr))
            continue

        # lis rD, imm = addis rD, 0, imm
        if opcd != 15 or ((w >> 16) & 0x1F) != 0:
            continue
        reg = (w >> 21) & 0x1F
        hi_addr = addr
        base_value = (w & 0xFFFF) << 16
        matched = False

        stop = min(i + 1 + window, count)
        for j in range(i + 1, stop):
            wj = words[j]
            oj = (wj >> 26) & 0x3F
            # addi rD, rA, simm / ロードストア d(rA) は rA が lis のレジスタ
            if oj == 14 and ((wj >> 16) & 0x1F) == reg:
                resolved = (base_value + _s16(wj & 0xFFFF)) & 0xFFFFFFFF
                index.setdefault(resolved, []).append(
                    (base_addr + j * 4, "lis+addi", hi_addr))
                matched = True
            elif oj == 24 and ((wj >> 21) & 0x1F) == reg:
                # ori rA, rS, uimm (rS が lis のレジスタ)
                resolved = (base_value | (wj & 0xFFFF)) & 0xFFFFFFFF
                index.setdefault(resolved, []).append(
                    (base_addr + j * 4, "lis+ori", hi_addr))
                matched = True
            elif oj in _D_MEM and ((wj >> 16) & 0x1F) == reg:
                resolved = (base_value + _s16(wj & 0xFFFF)) & 0xFFFFFFFF
                index.setdefault(resolved, []).append(
                    (base_addr + j * 4, "lis+" + _D_MEM[oj][0], hi_addr))
                matched = True
            if _dest_gpr(wj) == reg:
                break

        if not matched:
            index.setdefault(base_value, []).append((hi_addr, "lis", hi_addr))

    return index


# ---------------------------------------------------------------------------
# 解析フック (list_call_sites / find_immediate / infer_signature)
#
# 骨格は共通層に置き、ここには「PowerPC ではどの命令が何をするか」という
# 判定だけを書く。MCP 本体には分岐を増やさない。
# ---------------------------------------------------------------------------

from . import _callargs  # noqa: E402

# PowerPC EABI の引数レジスタ (整数)。r3〜r10 の 8 本。
ARG_REGS = (3, 4, 5, 6, 7, 8, 9, 10)
ARG_REG_NAMES = tuple(_r(n) for n in ARG_REGS)

CALL_SITES_NOTE = (
    "r3〜r10 は PowerPC EABI の整数引数レジスタです。kind=imm は即値、"
    "address は lis + 下位16bit で組み立てたアドレス定数、runtime は実行時に"
    "決まる値、inherited は窓の中で 1 度も書かれていない値です。"
    "**PowerPC に遅延スロットはありません** (分岐の次の命令は実行されません)。"
    "f1〜f8 の float 引数と、9 個目以降のスタック渡しは見ていません。")

CALL_SITES_BLIND_SPOTS = (
    "f1〜f8 経由の float 引数は見ていません。",
    "9 個目以降の引数は r1 相対のスタック渡しなので見ていません。",
    "`bctrl` による間接呼び出しは、飛び先が ctr 経由なので結び付けられません "
    "(仮想関数呼び出しはほぼこの形です)。",
    "呼び出しの直前が分岐の合流点だと、窓の中の代入が実行されるとは限りません。",
    "r2 / r13 相対 (SDA) で値を読んでいる形は、アドレスを復元できません。",
)

IMMEDIATE_NOTE = (
    "PowerPC の 16bit 即値命令と、`lis` + 下位16bit の合成を見ています。"
    "kind は const (定数をレジスタに作っている。**本命**) / "
    "compare (その値と比べている) / add (足し引き) / logic (論理演算) / "
    "upper (上位 16bit だけ) / pair (lis と組にして 32bit を作っている) / "
    "offset (ロードストアの変位。既定では出しません) です。"
    "**r2 / r13 相対で読んだ値や、レジスタ同士の演算で作る値は拾えません。**")

IMMEDIATE_BLIND_SPOTS = (
    "レジスタ同士の演算で作る値は拾えません。",
    "データとして表に置いてある値は命令ではないので拾えません "
    "(find_bytes / read_data を使ってください)。",
    "r2 / r13 相対 (SDA) で読んだ定数は拾えません。",
    "ロードストアの変位は既定で除いています "
    "(include_offsets=true で出せますが、小さい値では大量に出ます)。",
)

ARG_USE_NOTE = (
    "関数の本体を先頭から順に走査し、引数レジスタごとに「最初に現れるのが"
    "読み出しか書き込みか」を見ています。**分岐は追っていません。**"
    "f1〜f8 の float 引数とスタック渡しは見ていません。")


def _is_call_word(word):
    """呼び出し命令か (引数レジスタが壊れる命令か)。"""
    opcd = (word >> 26) & 0x3F
    if opcd == 18 and (word & 1):                    # bl / bla
        return True
    if opcd == 16 and (word & 1):                    # bcl
        return True
    if opcd == 19 and (word & 1):                    # bclrl / bcctrl
        return ((word >> 1) & 0x3FF) in (16, 528)
    return False


def _is_branch_word(word):
    """条件分岐か (窓の中にあると実行されない命令が混じる)。"""
    return ((word >> 26) & 0x3F) == 16 and not (word & 1)


def _call_arg_effect(word):
    """1 命令が「どのレジスタに何を入れるか」を返します (_callargs.py の形)。"""
    opcd = (word >> 26) & 0x3F
    d = (word >> 21) & 0x1F
    a = (word >> 16) & 0x1F
    simm = _s16(word & 0xFFFF)
    uimm = word & 0xFFFF

    if opcd == 15:                                   # addis / lis
        if a == 0:
            return ("hi", d, (uimm << 16) & 0xFFFFFFFF)
        return ("combine", d, a, (uimm << 16), "lis+addis")
    if opcd == 14:                                   # addi / li
        if a == 0:
            return ("imm", d, simm & 0xFFFFFFFF)
        return ("combine", d, a, simm, "lis+addi")
    if opcd == 24:                                   # ori
        if d == a and uimm == 0:
            return None                              # nop / mr 相当
        return ("combine", a, d, uimm, "lis+ori")
    if opcd in (25, 26, 27, 28, 29):
        return ("clobber", a, "opcd={0} は追っていません。".format(opcd))
    if opcd in (7, 8, 12, 13):
        return ("clobber", d, "算術即値です。")
    if opcd in (20, 21, 23):
        return ("clobber", a, "回転 / マスクです。")
    if opcd in _D_MEM:
        name, is_fp, store = _D_MEM[opcd]
        if is_fp or store:
            return None
        return ("load", d, a, _s16(word & 0xFFFF), name)
    if opcd == 18 and (word & 1):
        return ("clobber", 0, "bl が戻り番地を lr に入れます。")
    if opcd == 31:
        xo10 = (word >> 1) & 0x3FF
        name = _X31.get(xo10)
        if name == "or" and d == ((word >> 11) & 0x1F):
            return ("copy", a, d)                    # mr rA, rD
        dest = _dest_gpr(word)
        if dest is None:
            return None
        return ("clobber", dest,
                "opcd=31 xo={0} は追っていません。".format(xo10))
    dest = _dest_gpr(word)
    if dest is None:
        return None
    return ("clobber", dest, "opcd={0} は追っていません。".format(opcd))


def _call_args_spec():
    """PowerPC 用の CallArgsSpec を作ります。"""
    return _callargs.CallArgsSpec(
        size=4,
        arg_regs=ARG_REGS,
        reg_name=_r,
        effect=_call_arg_effect,
        is_call=_is_call_word,
        text=lambda w, a: decode(w, a)["text"],
        delay_slots=0,                  # ★PowerPC に遅延スロットは無い
        is_branch=_is_branch_word,
        zero_reg=None,                  # r0 は「0 として読む」文脈限定なので使わない
    )


def list_call_sites(data, base_addr, big_endian, target, max_back=24,
                    indirect_window=8):
    """target を呼んでいる箇所を、呼び出し時の r3〜r10 つきで列挙します。"""
    words = to_words(data, big_endian)
    spec = _call_args_spec()
    sites = []
    address_taken = []

    for i in range(len(words)):
        w = words[i]
        if ((w >> 26) & 0x3F) != 18:
            continue
        addr = base_addr + i * 4
        got = _decode_branch(w, addr)
        if int(got["target"], 16) != target:
            continue
        site = _callargs.resolve_at(spec, words, base_addr, i, max_back)
        site["call_addr"] = _hex(addr)
        site["form"] = got["mnemonic"]
        site["opcode"] = "0x{0:08x}".format(w)
        site["text"] = got["text"]
        if not (w & 1):
            site["notes"] = list(site.get("notes") or []) + [
                "`b` による**末尾ジャンプ**です。引数は呼び出し元から"
                "そのまま引き継がれている可能性が高いので inherited が増えます。"]
        sites.append(site)

    # lis + addi で target のアドレスを組み立てている箇所 (関数ポインタ)。
    index = build_ref_index(data, base_addr, big_endian)
    for at, form, hi_addr in index.get(target, []):
        if form in ("b", "bl"):
            continue
        i = (at - base_addr) // 4
        if i < 0 or i >= len(words):
            continue
        address_taken.append({
            "addr": _hex(at),
            "form": form,
            "hi_addr": _hex(hi_addr),
            "text": decode(words[i], at)["text"],
            "why": "アドレスを値として取っているだけで、ここでは呼んでいません "
                   "(関数ポインタ表に入れる / ctr 経由で呼ぶ形)。",
        })

    sites.sort(key=lambda s: s["call_addr"])
    return {"sites": sites, "address_taken": address_taken,
            "scanned_instructions": len(words)}


# find_immediate の分類。opcd -> (kind, 符号つきか)
_IMM_KIND = {
    7: ("arith", True), 8: ("arith", True), 12: ("arith", True),
    13: ("arith", True), 14: ("add", True),
    10: ("compare", False), 11: ("compare", True),
    24: ("logic", False), 25: ("logic", False), 26: ("logic", False),
    27: ("logic", False), 28: ("logic", False), 29: ("logic", False),
}


def _imm_matches(word, value32):
    """その命令の即値が value32 と一致するかを (kind, 表示値) で返します。"""
    opcd = (word >> 26) & 0x3F
    a = (word >> 16) & 0x1F
    imm = word & 0xFFFF

    if opcd == 15:                                   # addis / lis
        if ((imm << 16) & 0xFFFFFFFF) == value32:
            return ("upper", (imm << 16) & 0xFFFFFFFF)
        return None
    entry = _IMM_KIND.get(opcd)
    if entry is None:
        return None
    kind, signed = entry
    got = (_s16(imm) & 0xFFFFFFFF) if signed else imm
    if got != value32:
        return None
    if opcd == 14 and a == 0:
        kind = "const"                               # li rD, imm
    elif opcd == 24 and ((word >> 21) & 0x1F) == 0:
        kind = "const"                               # ori rA, r0, imm
    return (kind, got)


def find_immediate(data, base_addr, big_endian, value, include_offsets=False,
                   include_pairs=True, pair_index=None, lo_addr=None,
                   hi_addr=None):
    """その定数を即値として使っている命令を列挙します。"""
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
                "addr": _hex(addr), "kind": kind,
                "form": decode(word, addr)["mnemonic"],
                "value": shown, "text": decode(word, addr)["text"],
            })
            continue
        if not include_offsets:
            continue
        opcd = (word >> 26) & 0x3F
        if opcd in _D_MEM and (_s16(word & 0xFFFF) & 0xFFFFFFFF) == value32:
            hits.append({
                "addr": _hex(addr), "kind": "offset",
                "form": _D_MEM[opcd][0], "value": value32,
                "text": decode(word, addr)["text"],
            })

    if include_pairs and pair_index:
        for at, form, hi in pair_index.get(value32, []):
            if form in ("b", "bl"):
                continue
            i = (at - base_addr) // 4
            if i < 0 or i >= len(words):
                continue
            if lo_addr is not None and at < lo_addr:
                continue
            if hi_addr is not None and at > hi_addr:
                continue
            hits.append({
                "addr": _hex(at), "kind": "pair", "form": form,
                "value": value32, "hi_addr": _hex(hi),
                "text": decode(words[i], at)["text"],
            })

    hits.sort(key=lambda h: h["addr"])
    return {"hits": hits, "scanned_instructions": max(0, last - first)}


def _src_gprs(word):
    """その命令が**読む**汎用レジスタ番号の集合を返します。

    迷ったら「読む」側に倒します (読みを見落とすと「引数を使っていない」と
    誤って断定してしまうため)。
    """
    opcd = (word >> 26) & 0x3F
    d = (word >> 21) & 0x1F
    a = (word >> 16) & 0x1F
    b = (word >> 11) & 0x1F

    if opcd == 15 and a == 0:                        # lis は何も読まない
        return set()
    if opcd == 14 and a == 0:                        # li も同じ
        return set()
    if opcd in (7, 8, 12, 13, 14, 15, 10, 11):       # D 形式の算術 / 比較
        return {a}
    if opcd in (24, 25, 26, 27, 28, 29):             # 論理即値は rS を読む
        return {d}
    if opcd in (20, 21):                             # rlwimi / rlwinm
        return {d, a} if opcd == 20 else {d}
    if opcd == 23:
        return {d, b}
    if opcd in _D_MEM:
        name, is_fp, store = _D_MEM[opcd]
        if is_fp:
            return {a}
        return {a, d} if store else {a}
    if opcd in _PSQ:
        return {a}
    if opcd == 31:
        xo10 = (word >> 1) & 0x3FF
        name = _X31.get(xo10)
        if name in ("mfcr", "mfspr", "mftb", "mfmsr"):
            return set()
        if name in _X31_STORE:
            return {a, b, d}
        if name in _X31_LOAD:
            return {a, b}
        if name in ("cntlzw", "extsb", "extsh"):
            return {d}
        if name in _X31_DEST_RA:
            return {d, b}
        if name in ("mtspr", "mtcrf", "mtmsr"):
            return {d}
        return {a, b}
    if opcd in (16, 18, 19, 17):
        return set()
    return {a, b, d}


def arg_register_use(data, base_addr, big_endian, entry, end_addr,
                     arg_regs=ARG_REGS, max_scan=2048):
    """引数レジスタが「読まれるのが先か、書かれるのが先か」を返します。"""
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
        for reg in sorted(_src_gprs(word) & wanted):
            out[reg] = {"first": "read", "at": _hex(addr),
                        "text": decode(word, addr)["text"]}
            wanted.discard(reg)
        dest = _dest_gpr(word)
        if dest in wanted:
            out[dest] = {"first": "write", "at": _hex(addr),
                         "text": decode(word, addr)["text"]}
            wanted.discard(dest)
        if _is_call_word(word):
            # 呼び出しを跨ぐと引数レジスタは壊れる。
            break
    return out
