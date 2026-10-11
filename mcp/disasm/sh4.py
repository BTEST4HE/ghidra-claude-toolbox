# -*- coding: utf-8 -*-
"""SH-4 / SH-2 (SuperH, 16bit 固定長命令) の逆アセンブラと定数プール走査。

読み取り専用 MCP (`ghidra_readonly_mcp.py`) から呼ばれ、
`ghidra_exports/memory/*.bin` の生バイト列をデコードします。
Ghidra にも Ghidra プロジェクトにも触れません (バイト列を受け取るだけ)。

対応範囲:
  - SH-4 のユーザーモード命令ほぼ全部 (SH-2 は部分集合なのでそのまま読めます)
  - 特権命令 (LDC/STC SR,SSR,SPC,Rn_BANK, RTE, SLEEP, LDTLB)
  - FPU (FADD/FMUL/FTRC/FLOAT/FMOV/FIPR/FTRV/FSCHG …)

★MIPS との決定的な違い — 定数の作り方
  MIPS は `lui + addiu` の**即値ペア**で 32bit を組み立てますが、
  SH-4 は 16bit 命令なので即値が入りきらず、**PC 相対の定数プール**を使います。

      mov.l @(disp,PC),Rn     ; Rn = *( (PC & ~3) + 4 + disp*4 )

  つまり「このアドレスを参照しているコード」を探すには、
  **プールに置かれた 32bit 値**を見て、それを読む命令を逆引きします
  (build_ref_index はこれをやります)。lui ペア走査のような
  「レジスタが潰されたら打ち切り」の取りこぼしは原理的に発生しません。

対象: SH-4 (Dreamcast 等) / SH-2 (Saturn)。
platform_profiles/sh4.json を参照。
"""


# --- モジュール識別 (disasm/__init__.py の登録所が読む) -------------------
NAME = "sh4"
DISPLAY = "SuperH SH-4 / SH-2 (16bit 固定長)"
INSTRUCTION_SIZE = 2
# bra/bsr/jmp/jsr/rts/bt-s/bf-s の直後 1 命令が必ず実行される (遅延スロット)。
HAS_DELAY_SLOTS = True

# find_address_refs の note 用。SH-4 はプール直読みなので「窓」の概念は無い。
PAIR_WINDOW = 0

# find_address_refs の応答に添える、このアーキ固有の取りこぼし注意。
REFS_NOTE = ("PC 相対の定数プール (mov.l @(disp,pc),Rn) を辿ります。"
             "MIPS のような窓・レジスタ上書きによる取りこぼしはありません。"
             "★ただし GBR 相対アクセス (mov.l R0,@(disp,gbr)) は拾えません — "
             "参照先が命令にもプールにも現れないためです。"
             "0 件のときは「参照が無い」ではなく「GBR 相対かも」を疑ってください。")

# 0 件だったときに「参照が無い」と結論させないための、具体的な疑い先。
# find_address_refs が total=0 のときだけ応答に入れる。
REFS_BLIND_SPOTS = (
    "★GBR 相対アクセス (mov.l R0,@(disp,gbr) / mov.b @(disp,gbr),R0)。"
    "参照先が命令にもプールにも現れないので原理的に拾えない。"
    "GBR の値を突き止めて disp を足すこと。",
    "プールから読んだ値に後からオフセットを加算して使っている "
    "(表の先頭への参照としては出るので、表の先頭を探す)。",
    "R0 相対インデックス (mov.l @(R0,Rm),Rn) で実行時に計算されている。",
)

M32 = 0xFFFFFFFF

# find_writers の応答に添える、このアーキ固有の取りこぼし注意。
WRITERS_NOTE = (
    "定数プールを読む mov.l @(disp,pc),Rn を起点に、そのレジスタをベースにした "
    "store を前方 max_scan 命令だけ追います。"
    "★GBR 相対の書き込み (mov.l R0,@(disp,gbr)) はプールに現れないので拾えません。"
    "書き込み 0 件を「誰も書いていない」と読まないでください。")

WRITERS_BLIND_SPOTS = (
    "★GBR 相対の書き込み (mov.l R0,@(disp,gbr))。参照先が命令にもプールにも "
    "現れないので原理的に拾えない。GBR の値を突き止めて disp を足すこと。",
    "プールから読んだアドレスを別レジスタへ写してから書いている形。",
    "max_scan (既定 12 命令) を越えた位置での store。増やして再試行する。",
    "ベースアドレス + 実行時オフセット (mov.l Rm,@(R0,Rn)) で書いている形。"
    "この場合 offset_writers 側に出ることがある。",
    "jsr/bsr の先で書いている (呼び出し先まで追わない)。",
    "DMA や別 Program (オーバーレイ) からの書き込み。",
)



# ---------------------------------------------------------------------------
# 小道具
# ---------------------------------------------------------------------------

def _r(index):
    """汎用レジスタ番号を 'rN' 表記にします。"""
    return "r{0}".format(index & 0xF)


def _fr(index):
    """浮動小数レジスタ番号を 'frN' 表記にします。"""
    return "fr{0}".format(index & 0xF)


def _dr(index):
    """倍精度レジスタ (偶数番) を 'drN' 表記にします。"""
    return "dr{0}".format(index & 0xE)


def _s8(value):
    """8bit 即値を符号付きに拡張します。"""
    return value - 0x100 if value & 0x80 else value


def _s12(value):
    """12bit 即値を符号付きに拡張します。"""
    return value - 0x1000 if value & 0x800 else value


def _hex(value):
    """32bit アドレスを '0x........' 表記にします。"""
    return "0x{0:08x}".format(value & M32)


def _disp_branch(addr, disp, bits):
    """条件分岐 / bra / bsr の飛び先を求めます (PC+4 起点、disp は語数)。"""
    simm = _s8(disp) if bits == 8 else _s12(disp)
    return (addr + 4 + simm * 2) & M32


def pc_pool_addr(addr, disp, size):
    """PC 相対ロードが読むプールのアドレスを求めます。

    mov.l は「PC を 4 バイト境界に切り下げてから」+4+disp*4。
    mov.w は切り下げ無しで +4+disp*2。この差は SH-4 で間違えやすい点です。
    """
    if size == 4:
        return ((addr & ~3) + 4 + disp * 4) & M32
    return (addr + 4 + disp * 2) & M32


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


def _word(value):
    """未知語を `.word 0x....` として返します (例外は投げない)。"""
    return _out(".word", "0x{0:04x}".format(value & 0xFFFF))


# ---------------------------------------------------------------------------
# 表 (下位ニブル / 下位バイトで引くもの)
# ---------------------------------------------------------------------------

# 0x2nnn: 0010nnnnmmmmXXXX
_OP2 = {
    0x0: ("mov.b", "{m},@{n}"), 0x1: ("mov.w", "{m},@{n}"), 0x2: ("mov.l", "{m},@{n}"),
    0x4: ("mov.b", "{m},@-{n}"), 0x5: ("mov.w", "{m},@-{n}"), 0x6: ("mov.l", "{m},@-{n}"),
    0x7: ("div0s", "{m},{n}"), 0x8: ("tst", "{m},{n}"), 0x9: ("and", "{m},{n}"),
    0xA: ("xor", "{m},{n}"), 0xB: ("or", "{m},{n}"), 0xC: ("cmp/str", "{m},{n}"),
    0xD: ("xtrct", "{m},{n}"), 0xE: ("mulu.w", "{m},{n}"), 0xF: ("muls.w", "{m},{n}"),
}

# 0x3nnn: 0011nnnnmmmmXXXX (すべて Rm,Rn 形式)
_OP3 = {
    0x0: "cmp/eq", 0x2: "cmp/hs", 0x3: "cmp/ge", 0x4: "div1", 0x5: "dmulu.l",
    0x6: "cmp/hi", 0x7: "cmp/gt", 0x8: "sub", 0xA: "subc", 0xB: "subv",
    0xC: "add", 0xD: "dmuls.l", 0xE: "addc", 0xF: "addv",
}

# 0x6nnn: 0110nnnnmmmmXXXX
_OP6 = {
    0x0: ("mov.b", "@{m},{n}"), 0x1: ("mov.w", "@{m},{n}"), 0x2: ("mov.l", "@{m},{n}"),
    0x3: ("mov", "{m},{n}"),
    0x4: ("mov.b", "@{m}+,{n}"), 0x5: ("mov.w", "@{m}+,{n}"), 0x6: ("mov.l", "@{m}+,{n}"),
    0x7: ("not", "{m},{n}"), 0x8: ("swap.b", "{m},{n}"), 0x9: ("swap.w", "{m},{n}"),
    0xA: ("negc", "{m},{n}"), 0xB: ("neg", "{m},{n}"),
    0xC: ("extu.b", "{m},{n}"), 0xD: ("extu.w", "{m},{n}"),
    0xE: ("exts.b", "{m},{n}"), 0xF: ("exts.w", "{m},{n}"),
}

# 0x4nnn の下位バイトで一意に決まるもの (Rn 1 個を取る)。
_OP4_RN = {
    0x00: "shll", 0x01: "shlr", 0x04: "rotl", 0x05: "rotr",
    0x08: "shll2", 0x09: "shlr2", 0x10: "dt", 0x11: "cmp/pz",
    0x15: "cmp/pl", 0x18: "shll8", 0x19: "shlr8",
    0x20: "shal", 0x21: "shar", 0x24: "rotcl", 0x25: "rotcr",
    0x28: "shll16", 0x29: "shlr16",
}
# 0x4nnn: LDS 系 (Rm → システムレジスタ)。
#   ★注意: 逆向きの STS/STC (システムレジスタ → Rn) は 0x4 ではなく **0x0 系**にある
#   (STS PR,Rn = 0000nnnn00101010 / LDS Rm,PR = 0100mmmm00101010)。
#   ここに STS/STC を置くと LDS Rm,PR を取り違える。
_OP4_LDS = {0x0A: "mach", 0x1A: "macl", 0x2A: "pr", 0x5A: "fpul", 0x6A: "fpscr"}
# 0x4nnn: STS.L/LDS.L 系 (プッシュ/ポップ)。
_OP4_STSL = {0x02: "mach", 0x12: "macl", 0x22: "pr", 0x52: "fpul", 0x62: "fpscr"}
_OP4_LDSL = {0x06: "mach", 0x16: "macl", 0x26: "pr", 0x56: "fpul", 0x66: "fpscr"}
# 0x4nnn: 制御レジスタ (LDC / LDC.L / STC.L のみ。STC は 0x0 系)。
_OP4_LDC = {0x0E: "sr", 0x1E: "gbr", 0x2E: "vbr", 0x3A: "sgr", 0x3E: "ssr",
            0x4E: "spc", 0xFA: "dbr"}
_OP4_LDCL = {0x07: "sr", 0x17: "gbr", 0x27: "vbr", 0x37: "ssr", 0x47: "spc",
             0xF6: "dbr"}
_OP4_STCL = {0x03: "sr", 0x13: "gbr", 0x23: "vbr", 0x32: "sgr", 0x33: "ssr",
             0x43: "spc", 0xF2: "dbr"}

# 0x0nnn: 下位バイトで決まる 0 オペランド命令。
_OP0_NONE = {
    0x08: "clrt", 0x18: "sett", 0x28: "clrmac", 0x38: "ldtlb",
    0x48: "clrs", 0x58: "sets",
    0x09: "nop", 0x19: "div0u", 0x0B: "rts", 0x1B: "sleep", 0x2B: "rte",
}
# 0x0nnn: STC (制御レジスタ → Rn)。
_OP0_STC = {0x02: "sr", 0x12: "gbr", 0x22: "vbr", 0x32: "ssr", 0x42: "spc",
            0x3A: "sgr", 0xFA: "dbr"}
# 0x0nnn: STS (システムレジスタ → Rn)。
_OP0_STS = {0x0A: "mach", 0x1A: "macl", 0x2A: "pr", 0x5A: "fpul", 0x6A: "fpscr"}
# 0x0nnn: キャッシュ操作 (@Rn)。
_OP0_CACHE = {0x83: "pref", 0x93: "ocbi", 0xA3: "ocbp", 0xB3: "ocbwb", 0xC3: "movca.l"}

# 0xFnnn: 1111nnnnmmmmXXXX (FPU 2 オペランド)。
_OPF = {
    0x0: "fadd", 0x1: "fsub", 0x2: "fmul", 0x3: "fdiv",
    0x4: "fcmp/eq", 0x5: "fcmp/gt",
}
# 0xFnnn: 1111nnnnXXXX1101 (FPU 1 オペランド)。
_OPF_1D = {
    0x0: "fsts", 0x1: "flds", 0x2: "float", 0x3: "ftrc", 0x4: "fneg",
    0x5: "fabs", 0x6: "fsqrt", 0x7: "fsrra", 0x8: "fldi0", 0x9: "fldi1",
    0xA: "fcnvsd", 0xB: "fcnvds",
}


# ---------------------------------------------------------------------------
# ニブル別デコーダ
# ---------------------------------------------------------------------------

def _decode_0(word, n, m, addr):
    """0x0nnn 系 (システム・インデックス付き転送) をデコードします。"""
    low = word & 0xFF
    lo4 = word & 0xF

    if low in _OP0_NONE:
        name = _OP0_NONE[low]
        if name == "rts":
            return _out("rts", flow="return")
        if name == "rte":
            return _out("rte", flow="return")
        return _out(name)
    if low == 0x03:
        return _out("bsrf", _r(n), flow="call_reg")
    if low == 0x23:
        return _out("braf", _r(n), flow="jump_reg")
    if low == 0x29:
        return _out("movt", _r(n))
    if low in _OP0_CACHE:
        return _out(_OP0_CACHE[low],
                    "r0,@{0}".format(_r(n)) if low == 0xC3 else "@{0}".format(_r(n)))
    if low in _OP0_STC:
        return _out("stc", "{0},{1}".format(_OP0_STC[low], _r(n)))
    if low in _OP0_STS:
        return _out("sts", "{0},{1}".format(_OP0_STS[low], _r(n)))
    if (word & 0x8F) == 0x82:
        # 0000nnnn1mmm0010 = stc Rm_BANK,Rn
        return _out("stc", "r{0}_bank,{1}".format((word >> 4) & 0x7, _r(n)))

    if lo4 == 0x4:
        return _out("mov.b", "{0},@(r0,{1})".format(_r(m), _r(n)))
    if lo4 == 0x5:
        return _out("mov.w", "{0},@(r0,{1})".format(_r(m), _r(n)))
    if lo4 == 0x6:
        return _out("mov.l", "{0},@(r0,{1})".format(_r(m), _r(n)))
    if lo4 == 0x7:
        return _out("mul.l", "{0},{1}".format(_r(m), _r(n)))
    if lo4 == 0xC:
        return _out("mov.b", "@(r0,{0}),{1}".format(_r(m), _r(n)))
    if lo4 == 0xD:
        return _out("mov.w", "@(r0,{0}),{1}".format(_r(m), _r(n)))
    if lo4 == 0xE:
        return _out("mov.l", "@(r0,{0}),{1}".format(_r(m), _r(n)))
    if lo4 == 0xF:
        return _out("mac.l", "@{0}+,@{1}+".format(_r(m), _r(n)))
    return _word(word)


def _decode_4(word, n, m, addr):
    """0x4nnn 系 (シフト・システムレジスタ・jmp/jsr) をデコードします。"""
    low = word & 0xFF
    lo4 = word & 0xF

    if low in _OP4_RN:
        return _out(_OP4_RN[low], _r(n))
    if low == 0x0B:
        return _out("jsr", "@{0}".format(_r(n)), flow="call_reg")
    if low == 0x2B:
        return _out("jmp", "@{0}".format(_r(n)), flow="jump_reg")
    if low == 0x1B:
        return _out("tas.b", "@{0}".format(_r(n)))
    if low in _OP4_STSL:
        return _out("sts.l", "{0},@-{1}".format(_OP4_STSL[low], _r(n)))
    if low in _OP4_LDSL:
        return _out("lds.l", "@{0}+,{1}".format(_r(n), _OP4_LDSL[low]))
    if low in _OP4_LDS:
        return _out("lds", "{0},{1}".format(_r(n), _OP4_LDS[low]))
    if low in _OP4_STCL:
        return _out("stc.l", "{0},@-{1}".format(_OP4_STCL[low], _r(n)))
    if low in _OP4_LDCL:
        return _out("ldc.l", "@{0}+,{1}".format(_r(n), _OP4_LDCL[low]))
    if low in _OP4_LDC:
        return _out("ldc", "{0},{1}".format(_r(n), _OP4_LDC[low]))
    if (word & 0x8F) == 0x83:
        return _out("stc.l", "r{0}_bank,@-{1}".format((word >> 4) & 0x7, _r(n)))
    if (word & 0x8F) == 0x87:
        return _out("ldc.l", "@{0}+,r{1}_bank".format(_r(n), (word >> 4) & 0x7))
    if (word & 0x8F) == 0x8E:
        return _out("ldc", "{0},r{1}_bank".format(_r(n), (word >> 4) & 0x7))

    if lo4 == 0xC:
        return _out("shad", "{0},{1}".format(_r(m), _r(n)))
    if lo4 == 0xD:
        return _out("shld", "{0},{1}".format(_r(m), _r(n)))
    if lo4 == 0xF:
        return _out("mac.w", "@{0}+,@{1}+".format(_r(m), _r(n)))
    return _word(word)


def _decode_8(word, addr):
    """0x8nnn 系 (R0 の disp 付き転送・条件分岐) をデコードします。"""
    sub = (word >> 8) & 0xF
    disp = word & 0xFF
    rm = (word >> 4) & 0xF
    d4 = word & 0xF

    if sub == 0x0:
        return _out("mov.b", "r0,@({0},{1})".format(d4, _r(rm)))
    if sub == 0x1:
        return _out("mov.w", "r0,@({0},{1})".format(d4 * 2, _r(rm)))
    if sub == 0x4:
        return _out("mov.b", "@({0},{1}),r0".format(d4, _r(rm)))
    if sub == 0x5:
        return _out("mov.w", "@({0},{1}),r0".format(d4 * 2, _r(rm)))
    if sub == 0x8:
        return _out("cmp/eq", "#{0},r0".format(_s8(disp)))
    if sub in (0x9, 0xB, 0xD, 0xF):
        name = {0x9: "bt", 0xB: "bf", 0xD: "bt/s", 0xF: "bf/s"}[sub]
        tgt = _disp_branch(addr, disp, 8)
        return _out(name, _hex(tgt), target=tgt, flow="branch")
    return _word(word)


def _decode_c(word, addr):
    """0xCnnn 系 (GBR 相対・即値論理演算・mova) をデコードします。"""
    sub = (word >> 8) & 0xF
    disp = word & 0xFF

    if sub == 0x0:
        return _out("mov.b", "r0,@({0},gbr)".format(disp))
    if sub == 0x1:
        return _out("mov.w", "r0,@({0},gbr)".format(disp * 2))
    if sub == 0x2:
        return _out("mov.l", "r0,@({0},gbr)".format(disp * 4))
    if sub == 0x3:
        return _out("trapa", "#{0}".format(disp))
    if sub == 0x4:
        return _out("mov.b", "@({0},gbr),r0".format(disp))
    if sub == 0x5:
        return _out("mov.w", "@({0},gbr),r0".format(disp * 2))
    if sub == 0x6:
        return _out("mov.l", "@({0},gbr),r0".format(disp * 4))
    if sub == 0x7:
        pool = pc_pool_addr(addr, disp, 4)
        return _out("mova", "@({0},pc),r0  ; {1}".format(disp * 4, _hex(pool)))
    if sub == 0x8:
        return _out("tst", "#{0},r0".format(disp))
    if sub == 0x9:
        return _out("and", "#{0},r0".format(disp))
    if sub == 0xA:
        return _out("xor", "#{0},r0".format(disp))
    if sub == 0xB:
        return _out("or", "#{0},r0".format(disp))
    if sub == 0xC:
        return _out("tst.b", "#{0},@(r0,gbr)".format(disp))
    if sub == 0xD:
        return _out("and.b", "#{0},@(r0,gbr)".format(disp))
    if sub == 0xE:
        return _out("xor.b", "#{0},@(r0,gbr)".format(disp))
    return _out("or.b", "#{0},@(r0,gbr)".format(disp))


def _decode_f(word, n, m, addr):
    """0xFnnn 系 (FPU) をデコードします。"""
    lo4 = word & 0xF

    if lo4 in _OPF:
        return _out(_OPF[lo4], "{0},{1}".format(_fr(m), _fr(n)))
    if lo4 == 0x6:
        return _out("fmov.s", "@(r0,{0}),{1}".format(_r(m), _fr(n)))
    if lo4 == 0x7:
        return _out("fmov.s", "{0},@(r0,{1})".format(_fr(m), _r(n)))
    if lo4 == 0x8:
        return _out("fmov.s", "@{0},{1}".format(_r(m), _fr(n)))
    if lo4 == 0x9:
        return _out("fmov.s", "@{0}+,{1}".format(_r(m), _fr(n)))
    if lo4 == 0xA:
        return _out("fmov.s", "{0},@{1}".format(_fr(m), _r(n)))
    if lo4 == 0xB:
        return _out("fmov.s", "{0},@-{1}".format(_fr(m), _r(n)))
    if lo4 == 0xC:
        return _out("fmov", "{0},{1}".format(_fr(m), _fr(n)))
    if lo4 == 0xE:
        return _out("fmac", "fr0,{0},{1}".format(_fr(m), _fr(n)))
    if lo4 == 0xD:
        sub = (word >> 4) & 0xF
        if word == 0xFBFD:
            return _out("frchg")
        if word == 0xF3FD:
            return _out("fschg")
        if (word & 0x03FF) == 0x01FD:
            # FTRV (1111nn0111111101)。**bit9=0 を見ないと FPCHG (0xF7FD) を
            # ftrv と誤識する** (0x01FF マスクだと bit9 を見落とす)。
            return _out("ftrv", "xmtrx,fv{0}".format(n & 0xC))
        if word == 0xF7FD:
            return _out("fpchg")
        if (word & 0x01FF) == 0x00FD:
            # FSCA (1111nnn011111101): fpul の角度から sin/cos を同時に求める。
            # 3D ゲームの行列計算で普通に出るので拾うこと。
            # ※ ftrv (0x01FD) とは bit8 で区別するので、必ず ftrv の後で判定する。
            return _out("fsca", "fpul,{0}".format(_dr(n)))
        if sub == 0xE:
            return _out("fipr", "fv{0},fv{1}".format((n & 0x3) * 4, n & 0xC))
        name = _OPF_1D.get(sub)
        if name is None:
            return _word(word)
        if name == "fsts":
            return _out(name, "fpul,{0}".format(_fr(n)))
        if name == "flds":
            return _out(name, "{0},fpul".format(_fr(n)))
        if name == "float":
            return _out(name, "fpul,{0}".format(_fr(n)))
        if name == "ftrc":
            return _out(name, "{0},fpul".format(_fr(n)))
        if name in ("fcnvsd", "fcnvds"):
            return _out(name, "fpul,{0}".format(_dr(n)) if name == "fcnvsd"
                        else "{0},fpul".format(_dr(n)))
        return _out(name, _fr(n))
    return _word(word)


def decode(word, addr):
    """1 命令語 (16bit int) をデコードし、dict で返します。

    返す dict: mnemonic / operands / text / target / flow。
    target は分岐・ジャンプ先アドレス文字列 (無ければ None)。
    flow は "branch" / "jump" / "call" / "call_reg" / "jump_reg" / "return" / None。
    未知の語は `.word 0x....` として返し、例外は投げません
    (未関数化領域にはデータ・定数プールが混ざるため、落ちずに読めることを優先)。

    ★PC 相対ロードは operands に読み先プールのアドレスを ' ; 0x........' で添えます。
      SH-4 のコードはこれが読めないと何も分からないためです
      (プールの中身までは decode では読みません。バイト列を持っていないため)。
    """
    word &= 0xFFFF
    top = (word >> 12) & 0xF
    n = (word >> 8) & 0xF
    m = (word >> 4) & 0xF
    disp8 = word & 0xFF

    if top == 0x0:
        return _decode_0(word, n, m, addr)
    if top == 0x1:
        return _out("mov.l", "{0},@({1},{2})".format(_r(m), (word & 0xF) * 4, _r(n)))
    if top == 0x2:
        name, form = _OP2[word & 0xF]
        return _out(name, form.format(m=_r(m), n=_r(n)))
    if top == 0x3:
        name = _OP3.get(word & 0xF)
        if name is None:
            return _word(word)
        return _out(name, "{0},{1}".format(_r(m), _r(n)))
    if top == 0x4:
        return _decode_4(word, n, m, addr)
    if top == 0x5:
        return _out("mov.l", "@({0},{1}),{2}".format((word & 0xF) * 4, _r(m), _r(n)))
    if top == 0x6:
        name, form = _OP6[word & 0xF]
        return _out(name, form.format(m=_r(m), n=_r(n)))
    if top == 0x7:
        return _out("add", "#{0},{1}".format(_s8(disp8), _r(n)))
    if top == 0x8:
        return _decode_8(word, addr)
    if top == 0x9:
        pool = pc_pool_addr(addr, disp8, 2)
        return _out("mov.w", "@({0},pc),{1}  ; {2}".format(disp8 * 2, _r(n), _hex(pool)))
    if top == 0xA:
        tgt = _disp_branch(addr, word & 0xFFF, 12)
        return _out("bra", _hex(tgt), target=tgt, flow="jump")
    if top == 0xB:
        tgt = _disp_branch(addr, word & 0xFFF, 12)
        return _out("bsr", _hex(tgt), target=tgt, flow="call")
    if top == 0xC:
        return _decode_c(word, addr)
    if top == 0xD:
        pool = pc_pool_addr(addr, disp8, 4)
        return _out("mov.l", "@({0},pc),{1}  ; {2}".format(disp8 * 4, _r(n), _hex(pool)))
    if top == 0xE:
        return _out("mov", "#{0},{1}".format(_s8(disp8), _r(n)))
    return _decode_f(word, n, m, addr)


def word_at(data, offset, big_endian):
    """バイト列から 16bit 命令語を 1 つ取り出します。範囲外なら None。"""
    if offset < 0 or offset + 2 > len(data):
        return None
    chunk = data[offset:offset + 2]
    return int.from_bytes(chunk, "big" if big_endian else "little")


def to_words(data, big_endian):
    """バイト列を 16bit 命令語の array に変換します (2 バイト境界で切り捨て)。

    走査対象は 16MB 級 (= 800 万命令) になるため、int のリストではなく array を使います。
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

    SH-4 は 16bit 命令なので 32bit 定数を即値に持てず、**PC 相対の定数プール**から
    読みます。そこで「プールの中身 = 参照先アドレス」として索引します。

        mov.l @(disp,pc),Rn   → pool = (PC & ~3) + 4 + disp*4、その 32bit 値が参照先
        mova  @(disp,pc),r0   → 計算されたアドレスそのものが参照先
        bra / bsr             → 飛び先を参照先として登録

    hi_addr 相当の 3 つ目の要素には**プールのアドレス**を入れます
    (MIPS 版の「lui のアドレス」に対応する「定数がどこにあるか」の情報)。

    MIPS の lui ペア走査と違い、レジスタの上書きで取りこぼすことはありません。
    一方で、プールから読んだ値を後で加算して使う形 (テーブル先頭 + オフセット) は
    「テーブル先頭への参照」として出ます。

    ★既知の盲点: **GBR 相対アクセスは拾えません**。

        stc gbr,r1 / add #93,r1 / add #127,r1   ; r1 = GBR + 0xDC
        mov.l r0,@(220,gbr)                     ; [GBR+0xDC] へ書き込み

    この形では参照先アドレスが命令にもプールにも現れないため、索引に載りません。
    0 件だったときは
    「参照が無い」ではなく「GBR 相対かもしれない」を疑ってください。
    """
    index = {}
    words = to_words(data, big_endian)
    count = len(words)
    size = len(data)

    for i in range(count):
        w = words[i]
        top = w >> 12
        if top < 0xA:
            continue                      # 0x0-0x9 に参照元となる形は無い
        addr = base_addr + i * 2

        if top == 0xD:
            # mov.l @(disp,pc),Rn — SH-4 でアドレスを持ってくる主役
            pool = ((addr & ~3) + 4 + (w & 0xFF) * 4) & M32
            off = pool - base_addr
            if 0 <= off and off + 4 <= size:
                value = int.from_bytes(data[off:off + 4],
                                       "big" if big_endian else "little")
                index.setdefault(value, []).append((addr, "mov.l@pc", pool))
        elif top == 0xA or top == 0xB:
            tgt = (addr + 4 + _s12(w & 0xFFF) * 2) & M32
            index.setdefault(tgt, []).append(
                (addr, "bra" if top == 0xA else "bsr", addr))
        elif top == 0xC and ((w >> 8) & 0xF) == 0x7:
            # mova @(disp,pc),r0 — 計算結果そのものがアドレス
            resolved = ((addr & ~3) + 4 + (w & 0xFF) * 4) & M32
            index.setdefault(resolved, []).append((addr, "mova", resolved))

    return index


# ---------------------------------------------------------------------------
# 解析フック (find_writers / データ判定 / switch 展開 / 関数入口)
#
# disasm/__init__.py の登録所経由で MCP から呼ばれます。実装していないアーキでは
# 関数自体が存在しないので、共通層が「未対応」と明示エラーを返します。
# ---------------------------------------------------------------------------

# 汎用レジスタを 1 つも書き換えない 0x4nXX 系のサブオペコード (下位 8bit)。
_OP4_NO_GPR_WRITE = frozenset((
    0x11, 0x15,                                     # cmp/pz, cmp/pl
    0x0B, 0x2B,                                     # jsr, jmp
    0x1B,                                           # tas.b @Rn
    0x0A, 0x1A, 0x2A, 0x5A, 0x6A,                   # lds Rm,MACH/MACL/PR/FPUL/FPSCR
    0x0E, 0x1E, 0x2E, 0x3A, 0x3E, 0x4E, 0x5E, 0x6E, 0x7E, 0xFA,   # ldc Rm,xxx
))

# ストア命令: (top, 下位ニブル) -> 幅バイト数。ベースは Rn (bit 8-11)、ソースは Rm。
_STORE_AT_RN = {0x0: 1, 0x1: 2, 0x2: 4}          # mov.x Rm,@Rn      (0x2nm0/1/2)
_STORE_AT_MINUS_RN = {0x4: 1, 0x5: 2, 0x6: 4}    # mov.x Rm,@-Rn     (0x2nm4/5/6)
_STORE_AT_R0_RN = {0x4: 1, 0x5: 2, 0x6: 4}       # mov.x Rm,@(R0,Rn) (0x0nm4/5/6)

# ロード命令: 下位ニブル -> 幅。ベースは Rm (bit 4-7)。
_LOAD_AT_RM = {0x0: 1, 0x1: 2, 0x2: 4}           # mov.x @Rm,Rn      (0x6nm0/1/2)
_LOAD_AT_RM_INC = {0x4: 1, 0x5: 2, 0x6: 4}       # mov.x @Rm+,Rn     (0x6nm4/5/6)
_LOAD_AT_R0_RM = {0xC: 1, 0xD: 2, 0xE: 4}        # mov.x @(R0,Rm),Rn (0x0nmC/D/E)


def _dest_gprs(word):
    """その命令が書き換える汎用レジスタ番号の tuple を返します (無ければ空)。

    レジスタ追跡で「プールから読んだ値が潰れたか」を判定するために使います。
    **取りこぼすと誤検出 (別の値を持つレジスタへの store を拾う) につながる**ので、
    迷ったら「書き換える」側に倒しています。

    ⚠️ jsr/bsr による caller-saved レジスタ (r0-r7) の破壊はここでは見ていません。
       呼び出し側が必要に応じて考慮してください (find_writers は note に明記します)。
    """
    top = (word >> 12) & 0xF
    n = (word >> 8) & 0xF
    m = (word >> 4) & 0xF
    lo = word & 0xF

    if top == 0x0:
        if lo in _LOAD_AT_R0_RM:                  # mov.b/w/l @(R0,Rm),Rn
            return (n,)
        if lo == 0x2:                             # stc SR/GBR/...,Rn
            return (n,)
        if lo == 0xA:                             # sts MACH/MACL/PR,Rn
            return (n,)
        if lo == 0x9 and m == 0x2:                # movt Rn
            return (n,)
        return ()
    if top == 0x1:                                # mov.l Rm,@(disp,Rn) — store
        return ()
    if top == 0x2:
        if lo in _STORE_AT_RN:                    # store (@Rn)
            return ()
        if lo in _STORE_AT_MINUS_RN:              # mov.x Rm,@-Rn は Rn を進める
            return (n,)
        if lo in (0x7, 0x8, 0xC, 0xE, 0xF):       # div0s / tst / cmp/str / mulu / muls
            return ()
        return (n,)                               # and / xor / or / xtrct
    if top == 0x3:
        if lo in (0x0, 0x2, 0x3, 0x6, 0x7):       # cmp/eq, cmp/hs, cmp/ge, cmp/hi, cmp/gt
            return ()
        if lo in (0x5, 0xD):                      # dmulu.l / dmuls.l (MAC のみ)
            return ()
        return (n,)
    if top == 0x4:
        if (word & 0xFF) in _OP4_NO_GPR_WRITE:
            return ()
        return (n,)                               # shift/rotate/dt/sts.l/lds.l/stc.l/ldc.l
    if top == 0x5:                                # mov.l @(disp,Rm),Rn
        return (n,)
    if top == 0x6:
        if lo in _LOAD_AT_RM_INC:                 # @Rm+ は Rm も進む
            return (n, m)
        return (n,)
    if top == 0x7:                                # add #imm,Rn
        return (n,)
    if top == 0x8:
        if ((word >> 8) & 0xF) in (0x4, 0x5):     # mov.b/w @(disp,Rm),R0
            return (0,)
        return ()
    if top == 0x9:                                # mov.w @(disp,pc),Rn
        return (n,)
    if top in (0xA, 0xB):                         # bra / bsr
        return ()
    if top == 0xC:
        sub = (word >> 8) & 0xF
        if sub in (0x4, 0x5, 0x6, 0x7, 0x9, 0xA, 0xB):
            return (0,)                           # @(disp,GBR)→R0 / mova / and|xor|or #imm,R0
        return ()
    if top == 0xD:                                # mov.l @(disp,pc),Rn
        return (n,)
    if top == 0xE:                                # mov #imm,Rn
        return (n,)
    return ()                                     # 0xF: FPU は GPR を書かない


def _classify_access(word, reg):
    """命令が reg をベースにしたメモリアクセスなら (種別, 幅, ソース/宛先, disp) を返します。

    種別は "store" / "read"。該当しなければ None。
    """
    top = (word >> 12) & 0xF
    n = (word >> 8) & 0xF
    m = (word >> 4) & 0xF
    lo = word & 0xF

    if top == 0x2:
        if lo in _STORE_AT_RN and n == reg:
            return ("store", _STORE_AT_RN[lo], m, 0)
        if lo in _STORE_AT_MINUS_RN and n == reg:
            return ("store", _STORE_AT_MINUS_RN[lo], m, None)
    if top == 0x1 and n == reg:                   # mov.l Rm,@(disp,Rn)
        return ("store", 4, m, lo * 4)
    if top == 0x0:
        if lo in _STORE_AT_R0_RN and n == reg:    # mov.x Rm,@(R0,Rn)
            return ("store", _STORE_AT_R0_RN[lo], m, None)
        if lo in _LOAD_AT_R0_RM and m == reg:     # mov.x @(R0,Rm),Rn
            return ("read", _LOAD_AT_R0_RM[lo], n, None)
    if top == 0x8:
        sub = (word >> 8) & 0xF
        base = m                                  # 0x80/0x81/0x84/0x85 は bit4-7 がベース
        if sub == 0x0 and base == reg:
            return ("store", 1, 0, lo)            # mov.b R0,@(disp,Rn)
        if sub == 0x1 and base == reg:
            return ("store", 2, 0, lo * 2)        # mov.w R0,@(disp,Rn)
        if sub == 0x4 and base == reg:
            return ("read", 1, 0, lo)             # mov.b @(disp,Rm),R0
        if sub == 0x5 and base == reg:
            return ("read", 2, 0, lo * 2)         # mov.w @(disp,Rm),R0
    if top == 0x6:
        if lo in _LOAD_AT_RM and m == reg:
            return ("read", _LOAD_AT_RM[lo], n, 0)
        if lo in _LOAD_AT_RM_INC and m == reg:
            return ("read", _LOAD_AT_RM_INC[lo], n, None)
    if top == 0x5 and m == reg:                   # mov.l @(disp,Rm),Rn
        return ("read", 4, n, lo * 4)
    return None


def find_pools(data, base_addr, big_endian, target, mask=0xFFFFFFFF):
    """値が target と一致する 4 バイト境界のワード (定数プール) を全て列挙します。"""
    order = "big" if big_endian else "little"
    wanted = target & mask
    pools = []
    size = len(data) - 3
    step = 4
    start = (-base_addr) % 4          # base_addr が 4 の倍数でない場合に合わせる
    for off in range(start, size, step):
        if (int.from_bytes(data[off:off + 4], order) & mask) == wanted:
            pools.append(base_addr + off)
    return pools


def _trace_immediate(words, base_addr, store_index, src_reg, trace_imm):
    """store の直前を遡って `mov #imm,Rm` を探し、即値を返します (見つからなければ None)。"""
    lowest = max(0, store_index - trace_imm)
    for j in range(store_index - 1, lowest - 1, -1):
        w = words[j]
        if (w >> 12) == 0xE and ((w >> 8) & 0xF) == src_reg:
            return _s8(w & 0xFF)              # mov #imm,Rn は符号拡張
        if src_reg in _dest_gprs(w):
            return None                        # 別の命令で作られている
    return None


SWITCH_NOTE = (
    "SH-4 のスイッチ表は 16bit オフセットで、飛び先が 32bit アドレスとして"
    "どこにも現れないため find_address_refs では見つかりません。"
    "エントリ数は範囲チェック (cmp/hs) から取れなければ推定です "
    "(count_is_estimated を確認してください)。")


def find_writers(data, base_addr, big_endian, target, mask=0xFFFFFFFF,
                 max_scan=12, trace_imm=16):
    """その番地に **書き込んでいる命令** を、可能なら書く値まで添えて列挙します。

    `find_address_refs` の対になる機能です。SH-4 の手順:

      1. 値が target のワード (定数プール) を全て列挙
      2. それを読む `mov.l @(disp,pc),Rn` を列挙し、ロード先レジスタ Rn を記録
      3. 各ロードから前方 max_scan 命令を走査し、Rn ベースの store / read を探す
         (Rn が別の値で潰れたら打ち切り)
      4. store ならソースレジスタを直前 trace_imm 命令遡って `mov #imm` を探す

    ★取りこぼす条件 (呼び出し側が note で明示すること):
      - GBR 相対の書き込み (`mov.l R0,@(disp,gbr)`) はプールに現れないので拾えない
      - ロード結果を別レジスタへ写してから書く形
      - max_scan を越えた位置の store
      - jsr/bsr による caller-saved レジスタ (r0-r7) の破壊は追跡していない
    """
    words = to_words(data, big_endian)
    count = len(words)
    order = "big" if big_endian else "little"
    size = len(data)

    pools = set(find_pools(data, base_addr, big_endian, target, mask))
    writers = []
    offset_writers = []
    readers = []
    unresolved = []
    truncated = 0

    for i in range(count):
        w = words[i]
        if (w >> 12) != 0xD:                  # mov.l @(disp,pc),Rn 以外は関係無い
            continue
        addr = base_addr + i * 2
        pool = ((addr & ~3) + 4 + (w & 0xFF) * 4) & M32
        if pool not in pools:
            continue
        reg = (w >> 8) & 0xF

        found = None
        for j in range(i + 1, min(i + 1 + max_scan, count)):
            wj = words[j]
            access = _classify_access(wj, reg)
            if access is not None:
                found = (j, access)
                break
            if reg in _dest_gprs(wj):
                break                          # 値が潰れた

        if found is None:
            unresolved.append({
                "load_addr": _hex(addr),
                "load_reg": _r(reg),
                "pool_addr": _hex(pool),
                "reason": "max_scan 内に store/read が無い、またはレジスタが潰れた",
            })
            truncated += 1
            continue

        j, (kind, width, other, disp) = found
        at = base_addr + j * 2
        text = decode(words[j], at)["text"]
        if kind == "read":
            readers.append({
                "load_addr": _hex(addr),
                "read_addr": _hex(at),
                "width": width,
                "text": text,
            })
            continue

        value = _trace_immediate(words, base_addr, j, other, trace_imm)
        # disp==0 のときだけ「まさにこの番地へ書く」。disp!=0 や @(R0,Rn) /
        # @-Rn は実効アドレスが target とずれる (または実行時に決まる) ので、
        # 別バケツに分けて数える。ここを混ぜると「潰し漏れは無いか」の答えが狂う。
        bucket = writers if disp == 0 else offset_writers
        bucket.append({
            "load_addr": _hex(addr),
            "load_reg": _r(reg),
            "pool_addr": _hex(pool),
            "store_addr": _hex(at),
            "opcode": "0x{0:04x}".format(words[j]),
            "width": width,
            "src_reg": _r(other),
            "disp": disp,
            "value": value,
            "writes_zero": (value == 0),
            "text": text,
        })

    return {
        "pools": sorted(_hex(p) for p in pools),
        "pool_count": len(pools),
        "load_count": (len(writers) + len(offset_writers)
                       + len(readers) + len(unresolved)),
        "writers": writers,
        "offset_writers": offset_writers,
        "readers": readers,
        "unresolved": unresolved,
        "max_scan_reached": truncated,
    }


def pc_relative_targets(data, base_addr, big_endian, lo_addr, hi_addr):
    """[lo_addr, hi_addr] の命令が読む PC 相対プールの番地を {番地: 幅} で返します。

    「その番地はコードではなくデータである」と判定するための材料です。
    mov.l @(disp,pc) と mova は 4 バイト、mov.w @(disp,pc) は 2 バイト。
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
        top = w >> 12
        if top == 0xD:
            out[((addr & ~3) + 4 + (w & 0xFF) * 4) & M32] = 4
        elif top == 0x9:
            out[(addr + 4 + (w & 0xFF) * 2) & M32] = 2
        elif top == 0xC and ((w >> 8) & 0xF) == 0x7:
            out[((addr & ~3) + 4 + (w & 0xFF) * 4) & M32] = 4
    return out


def is_unconditional_flow_end(word):
    """その命令の後ろが (遅延スロットを除き) 到達不能になるかを返します。

    bra / rts / jmp / braf は無条件に飛ぶので、直後の 1 命令 (遅延スロット) の
    さらに後ろは、分岐先になっていなければ到達不能 = データの可能性があります。
    """
    top = (word >> 12) & 0xF
    if top == 0xA:                                    # bra
        return True
    if word == 0x000B:                                # rts
        return True
    if top == 0x4 and (word & 0xFF) == 0x2B:          # jmp @Rn
        return True
    if top == 0x0 and (word & 0xFF) == 0x23:          # braf Rn
        return True
    return False


def expand_switch(data, base_addr, big_endian, braf_addr, max_back=16,
                  max_entries=256):
    """`braf` / `bsrf` によるスイッチ表を展開します。

    SH-4 のスイッチ文は 16bit オフセット表で、**飛び先が 32bit アドレスとして
    どこにも現れない**ため参照検索に一切かかりません。その盲点を塞ぎます。

        mova @(disp,pc),r0      ; r0 = 表の先頭
        mov.w @(r0,Rn),r0       ; r0 = word[表 + index*2]  (符号拡張)
        braf r0                 ; 飛び先 = braf のアドレス + 4 + r0

    エントリ数は直前の範囲チェック (`mov #N,Rm` / `cmp/hs Rm,r0` / `bt`) から
    推定します。取れない場合は「飛び先がコード範囲に収まる間」読み進め、
    どちらで決めたかを `count_source` に記録します。
    """
    words = to_words(data, big_endian)
    order = "big" if big_endian else "little"
    size = len(data)

    def word_index(addr):
        off = addr - base_addr
        if off < 0 or off + 2 > size:
            return None
        return off // 2

    # 指定アドレスが braf/bsrf でなければ、その近傍を探す (「braf 近傍」指定を許す)。
    idx = word_index(braf_addr)
    if idx is None:
        raise ValueError("アドレス {0} が memory イメージの範囲外です。".format(
            _hex(braf_addr)))
    found_idx = None
    for cand in [idx] + [idx + d for d in range(1, max_back + 1)] + \
                [idx - d for d in range(1, max_back + 1)]:
        if cand < 0 or cand >= len(words):
            continue
        w = words[cand]
        if (w >> 12) == 0x0 and (w & 0xFF) in (0x23, 0x03):
            found_idx = cand
            break
    if found_idx is None:
        raise ValueError(
            "{0} の前後 {1} 命令に braf / bsrf が見つかりません。"
            "braf 命令のアドレスを指定してください。".format(_hex(braf_addr), max_back))

    br_word = words[found_idx]
    br_addr = base_addr + found_idx * 2
    br_name = "braf" if (br_word & 0xFF) == 0x23 else "bsrf"
    br_reg = (br_word >> 8) & 0xF

    # 手前へ遡って mova (表の先頭) と mov.w @(r0,Rn),r0 (表引き) を探す。
    table_addr = None
    index_reg = None
    for j in range(found_idx - 1, max(-1, found_idx - 1 - max_back), -1):
        w = words[j]
        addr = base_addr + j * 2
        if table_addr is None and (w >> 12) == 0xC and ((w >> 8) & 0xF) == 0x7:
            table_addr = ((addr & ~3) + 4 + (w & 0xFF) * 4) & M32
        if index_reg is None and (w >> 12) == 0x0 and (w & 0xF) == 0xD \
                and ((w >> 8) & 0xF) == 0:
            index_reg = (w >> 4) & 0xF          # mov.w @(r0,Rm),r0
        if table_addr is not None and index_reg is not None:
            break
    if table_addr is None:
        raise ValueError(
            "{0} の手前 {1} 命令に mova (表の先頭) が見つかりません。"
            "この braf は表引きではない可能性があります。".format(_hex(br_addr), max_back))

    # 範囲チェック (mov #N,Rm / cmp/hs Rm,r0 / bt) からエントリ数を推定する。
    entry_count = None
    count_source = None
    limit_reg = None
    for j in range(found_idx - 1, max(-1, found_idx - 1 - max_back * 2), -1):
        w = words[j]
        if (w >> 12) == 0x3 and (w & 0xF) == 0x2 and ((w >> 8) & 0xF) == 0:
            limit_reg = (w >> 4) & 0xF          # cmp/hs Rm,r0
            continue
        if limit_reg is not None and (w >> 12) == 0xE \
                and ((w >> 8) & 0xF) == limit_reg:
            entry_count = _s8(w & 0xFF)         # mov #N,Rm
            count_source = "範囲チェック (cmp/hs) から"
            break

    code_lo = base_addr
    code_hi = base_addr + size - 1
    entries = []
    guessed = entry_count is None
    limit = entry_count if entry_count is not None else max_entries
    for k in range(max(0, limit)):
        off = table_addr - base_addr + k * 2
        if off < 0 or off + 2 > size:
            break
        raw = int.from_bytes(data[off:off + 2], order)
        offset = raw - 0x10000 if raw & 0x8000 else raw
        target = (br_addr + 4 + offset) & M32
        if guessed and not (code_lo <= target <= code_hi):
            break
        entries.append({
            "index": k,
            "entry_addr": _hex(table_addr + k * 2),
            "offset": offset,
            "target": _hex(target),
        })
    if guessed:
        count_source = "飛び先がコード範囲に収まる間 (推定。範囲チェックを見つけられなかった)"

    return {
        "braf_addr": _hex(br_addr),
        "mnemonic": br_name,
        "branch_reg": _r(br_reg),
        "table_addr": _hex(table_addr),
        "index_reg": _r(index_reg) if index_reg is not None else None,
        "base_addr": _hex((br_addr + 4) & M32),
        "entry_count": len(entries),
        "count_source": count_source,
        "count_is_estimated": guessed,
        "entries": entries,
    }


# 関数プロローグの push 命令 (スタックへ積む形)。
def _is_push(word):
    """`@-r15` へ積む命令かどうかを返します。"""
    top = word >> 12
    if top == 0x2 and (word & 0xF) == 0x6 and ((word >> 8) & 0xF) == 0xF:
        return True                                   # mov.l Rm,@-r15
    if top == 0x4 and ((word >> 8) & 0xF) == 0xF and \
            (word & 0xFF) in (0x02, 0x12, 0x22, 0x52, 0x62,
                              0x03, 0x13, 0x23, 0x33, 0x43, 0x53, 0x63):
        return True                                   # sts.l / stc.l xxx,@-r15
    if top == 0xF and (word & 0xF) == 0xB and ((word >> 8) & 0xF) == 0xF:
        return True                                   # fmov.s FRm,@-r15
    return False


def _is_pop(word):
    """`@r15+` から戻す命令かどうかを返します。"""
    top = word >> 12
    if top == 0x6 and (word & 0xF) == 0x6 and ((word >> 4) & 0xF) == 0xF:
        return True                                   # mov.l @r15+,Rn
    if top == 0x4 and ((word >> 8) & 0xF) == 0xF and \
            (word & 0xFF) in (0x06, 0x16, 0x26, 0x56, 0x66,
                              0x07, 0x17, 0x27, 0x37, 0x47, 0x57, 0x67):
        return True                                   # lds.l / ldc.l @r15+,xxx
    if top == 0xF and (word & 0xF) == 0x9 and ((word >> 4) & 0xF) == 0xF:
        return True                                   # fmov.s @r15+,FRn
    return False


def _frame_delta(word):
    """`add #N,r15` の N を返します (r15 以外なら None)。"""
    if (word >> 12) == 0x7 and ((word >> 8) & 0xF) == 0xF:
        return _s8(word & 0xFF)
    return None


def _prologue_start(words, idx, max_gap=2, min_pushes=2):
    """idx を含む push 連続の先頭 index を返します (プロローグでなければ None)。

    ★プロローグは push だけが並ぶとは限りません。例えば
      `mov.l r14,@-r15` / `mov #0,r5` / `mov.l r13,@-r15` の順だと、
      素朴に「push が続く間」だけ遡ると 2 命令ぶん入口を読み違えます。
      そこで max_gap 命令までの非 push を挟んでも同じプロローグとみなします。
      ただし pop や関数末尾に当たったら**前の関数**なので必ず止めます。

    min_pushes 個以上の push が無い場合は None (関数途中のレジスタ退避を
    プロローグと誤認しないため)。
    """
    if not _is_push(words[idx]):
        return None
    first = idx
    pushes = 1
    gap = 0
    j = idx - 1
    while j >= 0:
        w = words[j]
        if _is_push(w):
            first = j
            pushes += 1
            gap = 0
            j -= 1
            continue
        if _is_pop(w) or _is_function_end(w):
            break
        gap += 1
        if gap > max_gap:
            break
        j -= 1
    # 先頭から前方も数えて、プロローグらしい規模かを確認する。
    k = first + 1
    gap = 0
    while k < len(words) and gap <= max_gap:
        if _is_push(words[k]):
            pushes += 1
            gap = 0
        else:
            gap += 1
        k += 1
    return first if pushes >= min_pushes else None


def _is_function_end(word):
    """関数の末尾になりうる命令かを返します (直後の 1 命令は遅延スロット)。

    `rts` のほか、末尾テールコールの `jmp @Rn` / `braf Rn` も境界として扱います
    (直前の関数が `jmp @r2` で終わっていると、rts だけを見ても入口を見つけられません)。
    `bra` は関数内ジャンプにも使われるので含めません。
    """
    if word == 0x000B:                                  # rts
        return True
    if (word >> 12) == 0x4 and (word & 0xFF) == 0x2B:   # jmp @Rn
        return True
    if (word >> 12) == 0x0 and (word & 0xFF) == 0x23:   # braf Rn
        return True
    return False


def _analyze_function(words, base_addr, entry_index, max_forward):
    """入口候補から前方へ走査し、push/pop・フレーム増減・末尾を数えます。

    ★`rts` の **遅延スロットも数える**こと。SH-4 のエピローグは
    `rts` / `mov.l @r15+,r14` の順で並ぶのが定型で、遅延スロットの pop は
    確実に実行されます。ここを飛ばすと push が 1 多く見え、
    正しい入口を「不均衡」と誤判定します。
    """
    push_count = 0
    pop_count = 0
    frame_alloc = 0
    frame_free = 0
    prologue = []
    epilogue = []
    end_index = None
    in_prologue = True

    def note(bucket, idx):
        at = base_addr + idx * 2
        bucket.append({"addr": _hex(at), "text": decode(words[idx], at)["text"]})

    def tally(idx, is_delay_slot=False):
        """1 命令ぶんの push/pop/フレームを数えます。"""
        nonlocal_push = _is_push(words[idx])
        if nonlocal_push:
            return "push"
        if _is_pop(words[idx]):
            return "pop"
        return None

    j = entry_index
    limit = min(len(words), entry_index + max_forward)
    while j < limit:
        w = words[j]
        kind = tally(j)
        if kind == "push":
            push_count += 1
            if in_prologue:
                note(prologue, j)
            j += 1
            continue
        if kind == "pop":
            pop_count += 1
            note(epilogue, j)
            in_prologue = False
            j += 1
            continue
        delta = _frame_delta(w)
        if delta is not None:
            if delta < 0:
                frame_alloc += -delta
                if in_prologue:
                    note(prologue, j)
            else:
                frame_free += delta
                note(epilogue, j)
            j += 1
            continue
        in_prologue = False
        if w == 0x000B:                                  # rts + 遅延スロット
            if j + 1 < len(words):
                ds = tally(j + 1)
                if ds == "push":
                    push_count += 1
                elif ds == "pop":
                    pop_count += 1
                    note(epilogue, j + 1)
                else:
                    delta = _frame_delta(words[j + 1])
                    if delta is not None and delta > 0:
                        frame_free += delta
                        note(epilogue, j + 1)
                end_index = j + 1
            else:
                end_index = j
            break
        j += 1

    return {
        "push_count": push_count,
        "pop_count": pop_count,
        "frame_alloc": frame_alloc,
        "frame_free": frame_free,
        "prologue": prologue,
        "epilogue": epilogue,
        "end_index": end_index,
    }


def find_function_entry(data, base_addr, big_endian, address,
                        max_back=4096, max_forward=8192, max_candidates=12):
    """指定アドレスを含む関数の入口を **命令列から** 判定します。

    Ghidra の関数情報を鵜呑みにしません (Ghidra 自身が入口を誤認している例があるため)。
    数バイト後ろから関数を呼ぶと push と pop の数が合わずスタックが壊れ、
    `rts` がゴミへ飛びます。**push 数と pop 数の一致**がその誤りを弾く条件です。

    手順:
      1. address から後方へ「関数末尾 (rts / jmp @Rn / braf) + 遅延スロット」の
         境界を集める。その直後が入口候補
      2. 近い候補から順に前方走査し、**その関数の範囲が address を含み**、かつ
         **push 数と pop 数が一致する**ものを採用する
      3. どれも条件を満たさなければ最も近い候補を返し、`balanced: false` と
         理由を明示する

    ★取りこぼす条件:
      - `bra` で終わる関数は境界として数えない (関数内ジャンプと区別できないため)
      - 複数出口 (早期 rts) がある関数は、最初の rts を末尾とみなす
      - プロローグを持たないリーフ関数は境界からしか見つけられない
    """
    words = to_words(data, big_endian)
    size = len(data)

    off = address - base_addr
    if off < 0 or off + 2 > size:
        raise ValueError("アドレス {0} が memory イメージの範囲外です。".format(
            _hex(address)))
    start_index = off // 2

    # --- 入口候補を後方から集める ---------------------------------------
    # 2 系統から集めて「近い順」に評価します:
    #   (a) 関数末尾 (rts / jmp / braf) + 遅延スロットの直後
    #   (b) プロローグ (push 連続) の先頭
    # (a) だけだと、前の関数との間にデータが挟まっている場合に入口を飛ばします
    # (データが命令として読まれるため)。
    # (b) だけだと、プロローグ途中の非 push で切れて数命令ずれます。
    found = {}
    for j in range(start_index, max(-1, start_index - max_back), -1):
        if j < start_index and _is_function_end(words[j]):
            cand = j + 2                                 # 末尾 + 遅延スロットの次
            if cand <= start_index:
                found.setdefault(cand, "関数末尾 (rts / jmp / braf) + 遅延スロットの直後")
        if _is_push(words[j]):
            cand = _prologue_start(words, j)
            if cand is not None and cand <= start_index:
                found.setdefault(cand, "プロローグ (push 連続) の先頭")
        if len(found) >= max_candidates:
            break
    candidates = sorted(found, reverse=True)             # 近い順
    how = found.get(candidates[0]) if candidates else None
    if not candidates:
        return {
            "address": _hex(address),
            "entry": None,
            "is_entry": False,
            "balanced": None,
            "confidence": "low",
            "note": "後方 {0} 命令に関数末尾もプロローグも見つかりません。"
                    "コードではない可能性があります。".format(max_back),
        }

    # --- 近い候補から順に「address を含み、かつ push/pop が一致」を探す ---
    chosen = None
    chosen_info = None
    rejected = []
    for cand in candidates:
        info = _analyze_function(words, base_addr, cand, max_forward)
        end_index = info["end_index"]
        covers = end_index is not None and cand <= start_index <= end_index
        balanced = info["push_count"] == info["pop_count"]
        if chosen is None and covers and balanced:
            chosen, chosen_info = cand, info
            break
        rejected.append((cand, info, covers, balanced))
    if chosen is None:
        chosen, chosen_info = candidates[0], _analyze_function(
            words, base_addr, candidates[0], max_forward)
    how = found.get(chosen, how)

    entry_addr = base_addr + chosen * 2
    end_index = chosen_info["end_index"]
    end_addr = base_addr + end_index * 2 if end_index is not None else None
    balanced = chosen_info["push_count"] == chosen_info["pop_count"]
    frame_balanced = chosen_info["frame_alloc"] == chosen_info["frame_free"]
    covers = end_index is not None and chosen <= start_index <= end_index

    notes = []
    if not balanced:
        notes.append("★push {0} / pop {1} が一致しません。ここは関数入口ではない"
                     "可能性が高いです (この番地から呼ぶとスタックが壊れます)。".format(
                         chosen_info["push_count"], chosen_info["pop_count"]))
    if end_index is None:
        notes.append("前方 {0} 命令内に rts が見つかりませんでした "
                     "(jmp で終わるテールコール関数かもしれません)。".format(max_forward))
    elif not covers:
        notes.append("★この関数の範囲 ({0}〜{1}) は指定アドレスを含みません。"
                     "候補を出し切っても条件を満たすものがありませんでした。".format(
                         _hex(entry_addr), _hex(end_addr)))
    if not frame_balanced:
        notes.append("フレーム確保 {0} / 解放 {1} が一致しません "
                     "(複数出口や可変フレームなら正常なこともあります)。".format(
                         chosen_info["frame_alloc"], chosen_info["frame_free"]))

    if balanced and covers:
        confidence = "high"
    elif balanced:
        confidence = "medium"
    else:
        confidence = "low"

    return {
        "address": _hex(address),
        "entry": _hex(entry_addr),
        "is_entry": entry_addr == address,
        "offset_from_entry": address - entry_addr,
        "end": _hex(end_addr) if end_addr is not None else None,
        "covers_address": covers,
        "how": how,
        "prologue": chosen_info["prologue"],
        "epilogue": chosen_info["epilogue"],
        "push_count": chosen_info["push_count"],
        "pop_count": chosen_info["pop_count"],
        "balanced": balanced,
        "frame_alloc": chosen_info["frame_alloc"],
        "frame_free": chosen_info["frame_free"],
        "frame_balanced": frame_balanced,
        "candidates_examined": len(rejected) + 1,
        "confidence": confidence,
        "note": " ".join(notes) if notes else
                "push/pop が一致し、rts まで到達し、指定アドレスを範囲に含みます。"
                "入口として矛盾はありません。",
    }
