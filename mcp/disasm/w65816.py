# -*- coding: utf-8 -*-
"""WDC 65C816 (SNES / SFC の Ricoh 5A22) の逆アセンブラと参照走査 (Python 3.13 前提)。

読み取り専用 MCP (`ghidra_readonly_mcp.py`) から呼ばれ、
`ghidra_exports/memory/*.bin` の生バイト列をデコードします。
Ghidra にも Ghidra プロジェクトにも触れません (バイト列を受け取るだけ)。

★このアーキだけ **命令長が CPU の状態で変わります**。
  P レジスタの M フラグ (A / メモリの幅) と X フラグ (X / Y の幅) が 1 なら 8bit、
  0 なら 16bit で、`LDA #imm` は 2 バイトにも 3 バイトにもなります。
  幅を 1 つ読み違えるとそれ以降の命令が全部ずれ、**それらしいゴミ**になります。

  そこで幅の出どころを命令ごとに記録します (`width_source`):

    cdl_recorded     Mesen の CDL に「その幅で実行された」と記録がある (最も強い)
    cdl_static_only  CDL の記録から静的に延長した区間 (未実行だが幅は継承)
    given            呼び出し側が m / x を明示した (Mesen の P レジスタ等)
    tracked          この読み取りの中の REP / SEP で決まった
    carried          CDL の区間を抜けた後、最後の CDL の幅を引き継いでいる
    ambiguous        CDL が「幅が決まらない / 矛盾する」とした区間
    unknown          PLP / RTI / XCE の後 (スタックやキャリー次第で静的には不明)
    assumed          誰も知らない。8bit (m=1, x=1) を仮定した ← **推測**

  **幅を黙って推測しないこと**がこのモジュールの約束です。
  assumed / unknown / ambiguous の幅で読んだ即値命令には `width_uncertain: true`
  を付けます。

M/X の供給源 (MCP 側が WidthContext を作って渡す):

  (a) bridge_config.json の `cdl_jsonl` — `mesen_debug/ghidra_export.py` が出す
      JSONL の `"record": "context_span"` (canonical_address / length / m / x /
      certainty = recorded / static_only / ambiguous)
  (b) 無ければ REP / SEP の追跡だけ (`assumed` から始まる)

オペランドの実効番地:

  - direct page: D は **$0000 と仮定** (bridge_config の `direct_page` で変更可)。
    TCD / PLD の後は `d_changed` を付ける。
  - absolute: データバンク DBR は静的に分からない。bridge_config の `data_bank`
    が無ければ **その命令のプログラムバンク (PHK/PLB 慣用) と仮定**し、
    $2000 以上 (DBR で結果が変わる範囲) には `dbr_assumed` を付ける。
  - long: 24bit そのもの。
  - 番地は正規化して比較する: $00-$3F/$80-$BF の $0000-$1FFF は WRAM
    $7E:0000-1FFF へ、$2000-$7FFF (I/O) は bank $00 へ。ROM は Program に
    載っている方のミラー (例: $80-$8F) へ寄せる。
"""

import bisect
import json
from pathlib import Path


# --- モジュール識別 (disasm/__init__.py の登録所が読む) -------------------
NAME = "65816"
DISPLAY = "WDC 65C816 (SNES/SFC 5A22)。可変長 1〜4 バイト、即値幅は M/X フラグ依存"
# 命令はバイト境界。固定長ではないので共通層は VARIABLE_LENGTH を見て専用経路へ回す。
INSTRUCTION_SIZE = 1
VARIABLE_LENGTH = True
# M/X と D / DBR の前提 (WidthContext) を MCP 側から受け取る。
NEEDS_WIDTH_CONTEXT = True
HAS_DELAY_SLOTS = False
# 番地は 24bit。応答では 0x809447 の 6 桁で出す。
ADDR_FORMAT = "0x{0:06x}"

# find_address_refs の範囲検索で既定で除く form (分岐先は範囲に必ず混ざるため)。
BRANCH_FORMS = ("branch", "bra", "brl", "jmp", "jml", "jsr", "jsl")

REFS_NOTE = (
    "65816 のオペランド (direct page / absolute / long、各 ,X ,Y 付き) から実効番地を"
    "作って索引しています。★即値幅は M/X 次第なので、CDL (bridge_config の cdl_jsonl) "
    "があれば CDL に記録された区間だけを、その幅で読みます。CDL が無ければ "
    "functions.json の関数本体を REP/SEP 追跡で読み、幅は assumed (8bit 仮定) から"
    "始まります (items の width_source を見ること)。"
    "direct page は D=$0000、absolute の DBR は命令のバンクと仮定しています "
    "(assumptions 欄)。WRAM は $7E:xxxx、I/O は $00:2xxx/$00:4xxx に正規化して比較します。"
    "JMP/JSR (abs,X) と JMP (abs) / JML [abs] はジャンプ表 / ポインタの番地として出ます。"
    "16bit 即値 ($8000 以上) は同じバンクの ROM ポインタ候補 (form=imm16) として出ます。")

REFS_BLIND_SPOTS = (
    "★CDL に無い (一度も実行していない) コードは読んでいません。遊んでいない"
    "場面の参照は出ません。CDL を増やして再 export してください。",
    "間接アドレッシング (LDA (dp),Y / [dp],Y / (dp,X)) の最終的な行き先は"
    "実行時に決まるので出ません。出るのはポインタが置かれた direct page の番地です。",
    "D ≠ $0000 の関数 (TCD / PLD で D を変える) の direct page 参照は番地がずれます"
    "(assumptions に d_changed が付きます)。",
    "DBR ≠ 命令のバンク の absolute 参照 ($2000 以上) はバンクが違います"
    "(dbr_assumed / dbr_changed)。bridge_config の data_bank で固定できます。",
    "16bit 未満の即値や、WRAM を指す即値 (LDA #$0B20 → STA $00 で作るポインタ) は"
    "索引していません。find_bytes で 20 0B のように探してください。",
    "DMA (レジスタ $43xx に番地を書く形) と MVN/MVP のブロック転送の行き先は拾えません。",
    "スタック相対 (d,S / (d,S),Y) はローカル変数なので索引しません。",
)

WRITERS_NOTE = (
    "65816 の書き込み命令 (STA/STX/STY/STZ) と読み書き命令 "
    "(INC/DEC/ASL/LSR/ROL/ROR/TSB/TRB = access RW) を、実効番地で照合しています。"
    "16bit 幅 (m=0 / x=0) の書き込みは 2 バイトを覆うので、target-1 への 16bit 書き込みも "
    "writers に出ます (covers で上位バイトと分かる)。"
    ",X / ,Y 付きは基底番地から index_reach 以内なら offset_writers に出ます。"
    "value は同じ線形区間を遡って LDA/LDX/LDY #imm を見つけたときだけ入ります "
    "(STZ は 0)。途中に分岐先が入り込んでいる可能性は見ていません。")

WRITERS_BLIND_SPOTS = (
    "★間接アドレッシング (STA (dp),Y / [dp],Y / (dp,X) / (d,S),Y) の書き込み。"
    "行き先は実行時に決まるので照合できません (indirect_stores に件数だけ出ます)。",
    "★DMA / HDMA による WRAM・VRAM への転送、MVN/MVP のブロック転送。",
    "★CDL に無い (一度も実行していない) コードの書き込み。",
    "D ≠ $0000 の関数での direct page 書き込み、DBR ≠ 命令のバンク の absolute 書き込み。",
    "index_reach を超える添字での ,X / ,Y 書き込み (16bit 添字は任意の距離に届く)。",
)


# --- 定数 -------------------------------------------------------------------
PS_M = 0x20
PS_X = 0x10

# モード -> (オペランドのバイト数, 書式)。バイト数 -1 は M、-2 は X で決まる。
_MODES = {
    "imp": (0, ""),
    "acc": (0, "A"),
    "immM": (-1, None),
    "immX": (-2, None),
    "imm8": (1, "#${0:02X}"),
    "sig": (1, "${0:02X}"),
    "dp": (1, "${0:02X}"),
    "dpx": (1, "${0:02X},X"),
    "dpy": (1, "${0:02X},Y"),
    "idp": (1, "(${0:02X})"),
    "idx": (1, "(${0:02X},X)"),
    "idy": (1, "(${0:02X}),Y"),
    "idl": (1, "[${0:02X}]"),
    "idly": (1, "[${0:02X}],Y"),
    "sr": (1, "${0:02X},S"),
    "isy": (1, "(${0:02X},S),Y"),
    "abs": (2, "${0:04X}"),
    "abx": (2, "${0:04X},X"),
    "aby": (2, "${0:04X},Y"),
    "abl": (3, "${0:06X}"),
    "alx": (3, "${0:06X},X"),
    "ind": (2, "(${0:04X})"),
    "iax": (2, "(${0:04X},X)"),
    "ial": (2, "[${0:04X}]"),
    "rel": (1, None),
    "rell": (2, None),
    "bm": (2, None),
}

# 256 命令の表。1 行 16 個 = 上位ニブル 1 つ。"MNE mode" を空白区切りで並べる。
_TABLE_ROWS = (
    "BRK:sig ORA:idx COP:sig ORA:sr TSB:dp ORA:dp ASL:dp ORA:idl "
    "PHP:imp ORA:immM ASL:acc PHD:imp TSB:abs ORA:abs ASL:abs ORA:abl",
    "BPL:rel ORA:idy ORA:idp ORA:isy TRB:dp ORA:dpx ASL:dpx ORA:idly "
    "CLC:imp ORA:aby INC:acc TCS:imp TRB:abs ORA:abx ASL:abx ORA:alx",
    "JSR:abs AND:idx JSL:abl AND:sr BIT:dp AND:dp ROL:dp AND:idl "
    "PLP:imp AND:immM ROL:acc PLD:imp BIT:abs AND:abs ROL:abs AND:abl",
    "BMI:rel AND:idy AND:idp AND:isy BIT:dpx AND:dpx ROL:dpx AND:idly "
    "SEC:imp AND:aby DEC:acc TSC:imp BIT:abx AND:abx ROL:abx AND:alx",
    "RTI:imp EOR:idx WDM:imm8 EOR:sr MVP:bm EOR:dp LSR:dp EOR:idl "
    "PHA:imp EOR:immM LSR:acc PHK:imp JMP:abs EOR:abs LSR:abs EOR:abl",
    "BVC:rel EOR:idy EOR:idp EOR:isy MVN:bm EOR:dpx LSR:dpx EOR:idly "
    "CLI:imp EOR:aby PHY:imp TCD:imp JML:abl EOR:abx LSR:abx EOR:alx",
    "RTS:imp ADC:idx PER:rell ADC:sr STZ:dp ADC:dp ROR:dp ADC:idl "
    "PLA:imp ADC:immM ROR:acc RTL:imp JMP:ind ADC:abs ROR:abs ADC:abl",
    "BVS:rel ADC:idy ADC:idp ADC:isy STZ:dpx ADC:dpx ROR:dpx ADC:idly "
    "SEI:imp ADC:aby PLY:imp TDC:imp JMP:iax ADC:abx ROR:abx ADC:alx",
    "BRA:rel STA:idx BRL:rell STA:sr STY:dp STA:dp STX:dp STA:idl "
    "DEY:imp BIT:immM TXA:imp PHB:imp STY:abs STA:abs STX:abs STA:abl",
    "BCC:rel STA:idy STA:idp STA:isy STY:dpx STA:dpx STX:dpy STA:idly "
    "TYA:imp STA:aby TXS:imp TXY:imp STZ:abs STA:abx STZ:abx STA:alx",
    "LDY:immX LDA:idx LDX:immX LDA:sr LDY:dp LDA:dp LDX:dp LDA:idl "
    "TAY:imp LDA:immM TAX:imp PLB:imp LDY:abs LDA:abs LDX:abs LDA:abl",
    "BCS:rel LDA:idy LDA:idp LDA:isy LDY:dpx LDA:dpx LDX:dpy LDA:idly "
    "CLV:imp LDA:aby TSX:imp TYX:imp LDY:abx LDA:abx LDX:aby LDA:alx",
    "CPY:immX CMP:idx REP:imm8 CMP:sr CPY:dp CMP:dp DEC:dp CMP:idl "
    "INY:imp CMP:immM DEX:imp WAI:imp CPY:abs CMP:abs DEC:abs CMP:abl",
    "BNE:rel CMP:idy CMP:idp CMP:isy PEI:idp CMP:dpx DEC:dpx CMP:idly "
    "CLD:imp CMP:aby PHX:imp STP:imp JML:ial CMP:abx DEC:abx CMP:alx",
    "CPX:immX SBC:idx SEP:imm8 SBC:sr CPX:dp SBC:dp INC:dp SBC:idl "
    "INX:imp SBC:immM NOP:imp XBA:imp CPX:abs SBC:abs INC:abs SBC:abl",
    "BEQ:rel SBC:idy SBC:idp SBC:isy PEA:abs SBC:dpx INC:dpx SBC:idly "
    "SED:imp SBC:aby PLX:imp XCE:imp JSR:iax SBC:abx INC:abx SBC:alx",
)

OPCODES = tuple(tuple(cell.split(":")) for row in _TABLE_ROWS
                for cell in row.split())
assert len(OPCODES) == 256, len(OPCODES)

_COND_BRANCH = {"BPL", "BMI", "BVC", "BVS", "BCC", "BCS", "BNE", "BEQ"}
_RETURNS = {"RTS", "RTL", "RTI"}

# アクセスの種類。RMW (読んで書き戻す) は RW。
_WRITE_OPS = {"STA", "STX", "STY", "STZ"}
_RMW_OPS = {"INC", "DEC", "ASL", "LSR", "ROL", "ROR", "TSB", "TRB"}
# X フラグで幅が決まるメモリ命令。それ以外のメモリ命令は M で決まる。
_X_WIDTH_OPS = {"STX", "STY", "LDX", "LDY", "CPX", "CPY"}
# 実効番地を持たない / 索引しないモード。
_NO_EA_MODES = {"imp", "acc", "immM", "immX", "imm8", "sig", "sr", "isy",
                "rel", "rell", "bm"}
_DP_MODES = {"dp": "dp", "dpx": "dp,x", "dpy": "dp,y"}
_DP_PTR_MODES = {"idp": ("(dp)", 2), "idx": ("(dp,x)", 2), "idy": ("(dp),y", 2),
                 "idl": ("[dp]", 3), "idly": ("[dp],y", 3)}
_ABS_MODES = {"abs": "abs", "abx": "abs,x", "aby": "abs,y"}
_LONG_MODES = {"abl": "long", "alx": "long,x"}

# 即値の幅を決める CPU 状態を失う命令。
_WIDTH_LOST = {"PLP": "PLP で P をスタックから戻した", "RTI": "RTI で P を戻した",
               "XCE": "XCE はキャリー次第でエミュレーションモードを切り替える"}

# 幅の確からしさ。この 3 つで読んだ即値命令には width_uncertain を付ける。
UNCERTAIN_SOURCES = ("assumed", "unknown", "ambiguous")

# テキスト listing 用の 1 文字の略号。
SOURCE_LETTER = {"cdl_recorded": "R", "cdl_static_only": "S", "given": "G",
                 "tracked": "T", "carried": "C", "ambiguous": "?",
                 "unknown": "?", "assumed": "A"}


def _hex24(value):
    return "0x{0:06x}".format(value & 0xFFFFFF)


def bus_text(value):
    """$BB:AAAA 表記。"""
    value &= 0xFFFFFF
    return "${0:02X}:{1:04X}".format(value >> 16, value & 0xFFFF)


# --- 番地の正規化 ------------------------------------------------------------
def is_system_bank(bank):
    """WRAM 先頭 8KiB と I/O が見えるバンク ($00-$3F / $80-$BF) か。"""
    bank &= 0xFF
    return bank < 0x40 or 0x80 <= bank < 0xC0


def canonical_data_address(addr):
    """データ番地を比較用の正規形にします (ROM ミラーは WidthContext 側で寄せる)。

    $00-$3F/$80-$BF:0000-1FFF → $7E:0000-1FFF (WRAM 先頭 8KiB のミラー)
    $00-$3F/$80-$BF:2000-7FFF → $00:2000-7FFF (I/O・拡張。Ghidra の snes_io 側)
    """
    addr &= 0xFFFFFF
    bank, lo = addr >> 16, addr & 0xFFFF
    if is_system_bank(bank):
        if lo < 0x2000:
            return 0x7E0000 | lo
        if lo < 0x8000:
            return lo
    return addr


def parse_bus_address(text):
    """'0x809447' / '809447' / '$80:9447' / '$809447' / '80:9447' を int にします。"""
    if isinstance(text, int):
        return text & 0xFFFFFF
    if not isinstance(text, str):
        raise ValueError("アドレスは '0x809447' か '$80:9447' の形の文字列で指定してください。")
    raw = text.strip().replace("_", "")
    body = raw[1:] if raw.startswith("$") else raw
    try:
        if ":" in body:
            bank, lo = body.split(":", 1)
            return ((int(bank, 16) & 0xFF) << 16) | (int(lo, 16) & 0xFFFF)
        return int(body, 16) & 0xFFFFFF
    except ValueError:
        raise ValueError("アドレス '{0}' を 16 進として解釈できません "
                         "(例: 0x809447 / $80:9447)。".format(text))


# --- CDL (Mesen) の読み込み ---------------------------------------------------
def load_cdl_jsonl(path):
    """mesen_debug/ghidra_export.py の JSONL から幅の区間を読みます。

    返り値: dict
      spans      [(start, end_inclusive, m, x, certainty)] を start 順に
                 (m / x は ambiguous なら None)
      ambiguity  {番地: 説明} (entered_at_more_than_one_width 等)
      header     header レコード (ROM の CRC / sha256 など)
      counts     certainty 別の区間数
      call_targets  {番地: {"m","x","called_from":[番地],"certainty","multi_width"}}
                 (Mesen の SubEntryPoint = JSR/JSL/JSR (abs,X) で入った番地。
                  static_only / ambiguous は静的に辿っただけで実行はしていない)
      code_runs  [(start, end)] CDL の Code ビット (実行した) の区間
      read_runs  [(start, end)] Code ビット無しで Data ビットの区間 (データとして読まれた)
    """
    spans = []
    ambiguity = {}
    header = None
    counts = {}
    call_targets = {}
    code_runs = []
    read_runs = []
    with Path(path).open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            kind = rec.get("record")
            if kind == "header":
                header = rec
            elif kind == "context_span":
                if rec.get("region") not in (None, "rom"):
                    continue
                try:
                    start = parse_bus_address(rec.get("canonical_address")
                                              or rec.get("bus_address"))
                    length = int(rec.get("length") or 0)
                except (ValueError, TypeError):
                    continue
                if length <= 0:
                    continue
                cert = rec.get("certainty") or "recorded"
                m = rec.get("m")
                x = rec.get("x")
                if m is not None:
                    m = 1 if m else 0
                if x is not None:
                    x = 1 if x else 0
                if m is None or x is None:
                    cert = "ambiguous"
                spans.append((start, start + length - 1, m, x, cert))
                counts[cert] = counts.get(cert, 0) + 1
            elif kind == "ambiguity":
                try:
                    at = parse_bus_address(rec.get("canonical_address")
                                           or rec.get("bus_address"))
                except ValueError:
                    continue
                text = rec.get("explanation") or rec.get("reason") or "ambiguous"
                ambiguity[at] = text
            elif kind == "call_target":
                if rec.get("region") not in (None, "rom"):
                    continue
                try:
                    at = parse_bus_address(rec.get("canonical_address")
                                           or rec.get("bus_address"))
                except ValueError:
                    continue
                callers = []
                for text in rec.get("called_from") or ():
                    try:
                        callers.append(parse_bus_address(text))
                    except ValueError:
                        pass
                m = rec.get("m")
                x = rec.get("x")
                call_targets[at] = {
                    "m": None if m is None else (1 if m else 0),
                    "x": None if x is None else (1 if x else 0),
                    "called_from": callers,
                    "certainty": rec.get("certainty") or "recorded",
                    "multi_width": bool(rec.get("entered_at_more_than_one_width")),
                }
            elif kind in ("code_run", "read_run"):
                if rec.get("region") not in (None, "rom"):
                    continue
                try:
                    start = parse_bus_address(rec.get("canonical_address")
                                              or rec.get("bus_address"))
                    length = int(rec.get("length") or 0)
                except (ValueError, TypeError):
                    continue
                if length > 0:
                    (code_runs if kind == "code_run" else read_runs).append(
                        (start, start + length - 1))
    spans.sort()
    return {"spans": spans, "ambiguity": ambiguity, "header": header,
            "counts": counts, "call_targets": call_targets,
            "code_runs": sorted(code_runs), "read_runs": sorted(read_runs)}


def _in_runs(runs, starts, addr):
    """[(start, end)] (start 順) のどれかに addr が入るか。"""
    i = bisect.bisect_right(starts, addr) - 1
    return i >= 0 and runs[i][0] <= addr <= runs[i][1]


class WidthContext(object):
    """M/X と D / DBR の前提、ROM ミラーの寄せ先をまとめたもの。

    MCP 側が bridge_config.json と memory_map.json から作ります。テストでは
    直接組み立てて構いません (spans だけ / 何も無し でも動く)。
    """

    def __init__(self, spans=(), ambiguity=None, code_ranges=(), image_ranges=(),
                 direct_page=None, data_bank=None, source=None, header=None,
                 fingerprint=None, call_targets=None, code_runs=(), read_runs=()):
        self.spans = sorted(spans)
        self._starts = [s[0] for s in self.spans]
        self.ambiguity = dict(ambiguity or {})
        self.code_ranges = sorted(code_ranges)
        self.image_ranges = sorted(image_ranges)
        self.direct_page = direct_page
        self.data_bank = data_bank
        self.source = source
        self.header = header
        self.fingerprint = fingerprint
        self.call_targets = dict(call_targets or {})
        self.code_runs = sorted(code_runs)
        self._code_starts = [r[0] for r in self.code_runs]
        self.read_runs = sorted(read_runs)
        self._read_starts = [r[0] for r in self.read_runs]

    @property
    def has_cdl(self):
        return bool(self.spans)

    def in_code_run(self, addr):
        """CDL の Code ビット (実際に実行した) の区間に入るか。"""
        return _in_runs(self.code_runs, self._code_starts, addr)

    def in_read_run(self, addr):
        """CDL で「データとして読まれた (Code ビット無し)」区間に入るか。"""
        return _in_runs(self.read_runs, self._read_starts, addr)

    def span_at(self, addr):
        """addr を含む CDL 区間 (start, end, m, x, certainty)。無ければ None。"""
        i = bisect.bisect_right(self._starts, addr) - 1
        if i >= 0:
            span = self.spans[i]
            if span[0] <= addr <= span[1]:
                return span
        return None

    def spans_in(self, lo, hi):
        """[lo, hi] と重なる区間を順に返します。"""
        i = max(0, bisect.bisect_right(self._starts, lo) - 1)
        out = []
        while i < len(self.spans) and self.spans[i][0] <= hi:
            if self.spans[i][1] >= lo:
                out.append(self.spans[i])
            i += 1
        return out

    def in_image(self, addr):
        for lo, hi in self.image_ranges:
            if lo <= addr <= hi:
                return True
        return False

    def canonical_rom(self, addr):
        """ROM 番地を Program に載っているミラーへ寄せます (載っていなければそのまま)。

        LoROM の $00-$3F:8000-FFFF ⇔ $80-$BF:8000-FFFF、HiROM の $40-$7D ⇔ $C0-$FD
        はどちらも bit23 違いのミラーなので、bit23 を反転した方が image にあればそちら。
        """
        addr &= 0xFFFFFF
        if not self.image_ranges or self.in_image(addr):
            return addr
        if (addr >> 16) in (0x7E, 0x7F):
            return addr                       # WRAM。ROM のミラーではない
        if (addr & 0xFFFF) >= 0x8000 or (addr >> 16) & 0x7F >= 0x40:
            alt = addr ^ 0x800000
            if self.in_image(alt):
                return alt
        return addr

    def canonical(self, addr):
        """データ番地の正規形 (WRAM / I/O / ROM ミラー)。"""
        value = canonical_data_address(addr)
        if value == (addr & 0xFFFFFF) or value >= 0x800000:
            return self.canonical_rom(value)
        return value

    def summary(self):
        """応答に載せる要約。"""
        out = {
            "width_source": "cdl" if self.has_cdl else "rep_sep_tracking",
            "cdl_jsonl": self.source,
            "cdl_spans": len(self.spans),
            "direct_page": ("${0:04X}".format(self.direct_page)
                            if self.direct_page is not None else "$0000 (仮定)"),
            "data_bank": ("${0:02X}".format(self.data_bank)
                          if self.data_bank is not None else "命令のバンクと仮定"),
        }
        if not self.has_cdl:
            out["warning"] = (
                "CDL が設定されていないので、即値の幅は REP/SEP の追跡だけで決めています。"
                "読み始めは m=1 x=1 (8bit) の**仮定**です (width_source=assumed)。"
                "bridge_config.json に \"cdl_jsonl\" を書くと Mesen の記録で確定します。")
        return out


# --- デコード ------------------------------------------------------------------
def _le(data, offset, size):
    if offset + size > len(data):
        return None
    return int.from_bytes(bytes(data[offset:offset + size]), "little")


def operand_size(mode, m, x):
    """オペランドのバイト数 (オペコードを除く)。"""
    size = _MODES[mode][0]
    if size == -1:
        return 1 if m else 2
    if size == -2:
        return 1 if x else 2
    return size


def width_flag(mnemonic, mode):
    """この命令の **長さ** を決めるフラグ ('m' / 'x' / None)。"""
    if mode == "immM":
        return "m"
    if mode == "immX":
        return "x"
    return None


def access_flag(mnemonic, mode):
    """この命令の **メモリアクセス幅** を決めるフラグ ('m' / 'x' / None)。"""
    if mode in _NO_EA_MODES and mode not in ("immM", "immX"):
        return None
    if mnemonic in _X_WIDTH_OPS:
        return "x"
    if mnemonic in ("JMP", "JML", "JSR", "JSL", "PEA", "PEI"):
        return None
    return "m"


def decode_at(data, offset, addr, m=1, x=1):
    """data[offset] の 1 命令を、番地 addr / 幅 m・x でデコードします。

    返り値は dict (size / opcode / mnemonic / mode / operand / operands / text /
    target / flow / bytes)。バッファ末尾で切れていれば truncated=True。
    target は 24bit の int (分岐・呼び出し先。ROM ミラーの寄せは呼び出し側)。
    """
    opcode = data[offset]
    mnemonic, mode = OPCODES[opcode]
    size = operand_size(mode, m, x)
    raw = bytes(data[offset:offset + 1 + size])
    out = {"addr": addr & 0xFFFFFF, "opcode": opcode, "mnemonic": mnemonic,
           "mode": mode, "size": 1 + size, "bytes": raw, "operand": None,
           "operands": "", "text": mnemonic, "target": None, "flow": None}
    if len(raw) < 1 + size:
        out["size"] = len(raw)
        out["truncated"] = True
        out["operands"] = "<truncated>"
        out["text"] = mnemonic + " <truncated>"
        return out

    operand = _le(data, offset + 1, size) if size else None
    out["operand"] = operand
    bank = (addr >> 16) & 0xFF
    pc_next = (addr + 1 + size) & 0xFFFF

    if mode in ("immM", "immX"):
        text = "#${0:0{1}X}".format(operand, size * 2)
    elif mode == "rel":
        delta = operand - 0x100 if operand >= 0x80 else operand
        out["target"] = (bank << 16) | ((pc_next + delta) & 0xFFFF)
        text = "${0:04X}".format(out["target"] & 0xFFFF)
    elif mode == "rell":
        delta = operand - 0x10000 if operand >= 0x8000 else operand
        out["target"] = (bank << 16) | ((pc_next + delta) & 0xFFFF)
        text = "${0:04X}".format(out["target"] & 0xFFFF)
    elif mode == "bm":
        # MVN/MVP はバイト列が「転送先バンク, 転送元バンク」の順。表記は src,dst。
        text = "${0:02X},${1:02X}".format(raw[2], raw[1])
    else:
        fmt = _MODES[mode][1]
        text = fmt.format(operand) if fmt and operand is not None else (fmt or "")
    out["operands"] = text
    out["text"] = "{0} {1}".format(mnemonic, text) if text else mnemonic

    # 制御の流れ。PER は PC 相対で番地を積むだけ (分岐ではない)。
    if mnemonic in ("JSR", "JSL"):
        if mode == "abs":
            out["target"] = (bank << 16) | operand
            out["flow"] = "call"
        elif mode == "abl":
            out["target"] = operand
            out["flow"] = "call"
        else:                                   # JSR (abs,X)
            out["flow"] = "call_reg"
    elif mnemonic in ("JMP", "JML"):
        if mode == "abs":
            out["target"] = (bank << 16) | operand
            out["flow"] = "jump"
        elif mode == "abl":
            out["target"] = operand
            out["flow"] = "jump"
        else:                                   # (abs) / (abs,X) / [abs]
            out["flow"] = "jump_reg"
    elif mnemonic in ("BRA", "BRL"):
        out["flow"] = "jump"
    elif mnemonic in _COND_BRANCH:
        out["flow"] = "branch"
    elif mnemonic in _RETURNS:
        out["flow"] = "return"
    elif mnemonic == "PER":
        out["pushes"] = out.pop("target")
        out["target"] = None
    return out


def word_at(data, offset, big_endian=False):
    """共通層互換: offset から最大 4 バイトを little endian で返します。"""
    if offset >= len(data):
        return None
    chunk = bytes(data[offset:offset + 4])
    return int.from_bytes(chunk, "little")


def decode(word, addr):
    """共通層互換の 1 語デコード。**幅は m=1 x=1 の仮定**で、その旨を返します。

    65816 では可変長なので、共通層は VARIABLE_LENGTH を見て disassemble() を使う
    はずです。ここに来るのは古い経路だけで、結果には width_source=assumed が付きます。
    """
    data = int(word).to_bytes(4, "little")
    got = decode_at(data, 0, addr, 1, 1)
    flag = width_flag(got["mnemonic"], got["mode"])
    return {
        "mnemonic": got["mnemonic"], "operands": got["operands"],
        "text": got["text"] + ("  ; 幅仮定 {0}=1".format(flag) if flag else ""),
        "target": _hex24(got["target"]) if got["target"] is not None else None,
        "flow": got["flow"], "size": got["size"],
        "word": "0x" + got["bytes"].hex(),
        "width_source": "assumed" if flag else "n/a",
    }


# --- 幅の追跡 ------------------------------------------------------------------
class WidthState(object):
    """線形に読む間の M/X (と D / DBR の変化) を、出どころ付きで追跡します。

    優先順位 (フラグごと):
      1. 呼び出し側が明示したフラグ (given) — その後は REP/SEP でだけ変わる
      2. CDL の区間 (recorded / static_only)
      3. 直前の状態の持ち越し (tracked / carried / unknown / assumed)
    """

    def __init__(self, ctx=None, m=None, x=None):
        self.ctx = ctx
        self.value = {"m": 1, "x": 1}
        self.source = {"m": "assumed", "x": "assumed"}
        self.pinned = set()
        for flag, given in (("m", m), ("x", x)):
            if given is not None:
                self.value[flag] = 1 if int(given) else 0
                self.source[flag] = "given"
                self.pinned.add(flag)
        self.d_changed = False
        self.dbr_changed = False
        self.span = None

    def enter(self, addr):
        """addr の命令を読む直前に呼び、CDL の幅を反映します。区間を返します。"""
        span = self.ctx.span_at(addr) if self.ctx is not None else None
        self.span = span
        for flag, idx in (("m", 2), ("x", 3)):
            if flag in self.pinned:
                continue
            if span is not None and span[idx] is not None:
                self.value[flag] = span[idx]
                self.source[flag] = "cdl_" + span[4]
            elif span is not None:
                self.source[flag] = "ambiguous"
            elif self.source[flag].startswith("cdl_"):
                self.source[flag] = "carried"
        return span

    def leave(self, insn):
        """命令を読んだ後に呼び、REP/SEP/PLP 等による幅の変化を反映します。"""
        name = insn["mnemonic"]
        operand = insn.get("operand")
        if name in ("REP", "SEP") and operand is not None:
            for flag, bit in (("m", PS_M), ("x", PS_X)):
                if operand & bit:
                    self.value[flag] = 0 if name == "REP" else 1
                    self.source[flag] = "tracked"
        elif name in _WIDTH_LOST:
            for flag in ("m", "x"):
                self.source[flag] = "unknown"
            if name == "XCE":
                # エミュレーションモードに入ると両方 8bit に固定される。どちらに
                # 切り替わったかはキャリー次第なので値は変えず unknown にする。
                pass
        elif name in ("TCD", "PLD"):
            self.d_changed = True
        elif name == "PLB":
            self.dbr_changed = True


# --- オペランドの実効番地 ---------------------------------------------------------
def operand_refs(insn, m, x, ctx=None, d_changed=False, dbr_changed=False):
    """命令が触るメモリ番地の一覧を返します (無ければ空)。

    各要素 dict:
      ea        正規化した実効番地 (int)。,X ,Y 付きは **基底番地**
      form      dp / dp,x / abs / abs,y / long / (dp),y / jmp_table / imm16 ...
      access    R / W / RW
      size      アクセスのバイト数 (1/2/3)
      size_flag アクセス幅を決めたフラグ ('m' / 'x' / None)
      indexed   ,X / ,Y 付きか
      pointer   間接アドレッシングのポインタ置き場を読む参照か
      assumptions  ['d_assumed', 'dbr_assumed', ...]
    """
    mode = insn["mode"]
    name = insn["mnemonic"]
    op = insn.get("operand")
    if op is None or insn.get("truncated"):
        return []
    ctx = ctx or WidthContext()
    pb = (insn["addr"] >> 16) & 0xFF
    refs = []

    if name in _RMW_OPS and mode != "acc":
        access = "RW"
    elif name in _WRITE_OPS:
        access = "W"
    else:
        access = "R"
    flag = access_flag(name, mode)
    size = None
    if flag == "m":
        size = 1 if m else 2
    elif flag == "x":
        size = 1 if x else 2

    def add(ea, form, access_, size_, **extra):
        item = {"ea": ea, "form": form, "access": access_, "size": size_,
                "size_flag": extra.pop("size_flag", flag),
                "indexed": extra.pop("indexed", False),
                "pointer": extra.pop("pointer", False),
                "assumptions": extra.pop("assumptions", [])}
        item.update(extra)
        refs.append(item)

    def dp_assumptions():
        out = []
        if ctx.direct_page is None:
            out.append("d_assumed")
        if d_changed:
            out.append("d_changed")
        return out

    dp_base = ctx.direct_page or 0

    if mode in _DP_MODES:
        ea = canonical_data_address((dp_base + op) & 0xFFFF)
        add(ea, _DP_MODES[mode], access, size, indexed=(mode != "dp"),
            assumptions=dp_assumptions())
    elif mode in _DP_PTR_MODES:
        form, psize = _DP_PTR_MODES[mode]
        ea = canonical_data_address((dp_base + op) & 0xFFFF)
        # ポインタ置き場は読むだけ。最終的な行き先 (実行時) は store なら
        # indirect_store として呼び出し側で数える。
        add(ea, form, "R", psize, size_flag=None, pointer=True,
            indexed=(mode == "idx"), assumptions=dp_assumptions(),
            target_access=access)
    elif mode in _ABS_MODES and name not in ("JMP", "JSR", "PEA"):
        if ctx.data_bank is not None:
            bank = ctx.data_bank
            assumptions = []
        else:
            bank = pb
            assumptions = ["dbr_assumed"] if op >= 0x2000 else []
        if dbr_changed and op >= 0x2000:
            assumptions.append("dbr_changed")
        ea = ctx.canonical((bank << 16) | op)
        add(ea, _ABS_MODES[mode], access, size, indexed=(mode != "abs"),
            assumptions=assumptions)
    elif mode in _LONG_MODES and name not in ("JML", "JSL"):
        add(ctx.canonical(op), _LONG_MODES[mode], access, size,
            indexed=(mode == "alx"))
    elif mode == "ind":                          # JMP ($abs) : ポインタは bank 0
        add(ctx.canonical(op), "jmp_ptr", "R", 2, size_flag=None, pointer=True)
    elif mode == "ial":                          # JML [$abs] : ポインタは bank 0
        add(ctx.canonical(op), "jml_ptr", "R", 3, size_flag=None, pointer=True)
    elif mode == "iax":                          # JMP/JSR ($abs,X) : 表は PB
        add(ctx.canonical_rom((pb << 16) | op), "jmp_table", "R", 2,
            size_flag=None, pointer=True, indexed=True)
    elif name == "PEA" or (mode in ("immM", "immX") and insn["size"] == 3):
        # 16bit 即値。$8000 以上だけ「同じバンクの ROM ポインタ候補」として出す
        # (小さい値まで出すとただの定数で埋まる)。
        if op >= 0x8000:
            add(ctx.canonical_rom((pb << 16) | op), "imm16", "imm", 2,
                size_flag=None, assumptions=["same_bank_pointer_guess"])
    return refs


def _control_ref(insn, ctx):
    """分岐・呼び出し先を (番地, form) で返します。無ければ None。"""
    target = insn.get("target")
    if target is None:
        return None
    name = insn["mnemonic"]
    form = {"JSR": "jsr", "JSL": "jsl", "JMP": "jmp", "JML": "jml",
            "BRA": "bra", "BRL": "brl"}.get(name, "branch")
    if ctx is not None:
        target = ctx.canonical_rom(target)
    return target, form


# --- 線形デコード ----------------------------------------------------------------
def _width_source_of(insn, state):
    flag = width_flag(insn["mnemonic"], insn["mode"])
    return state.source[flag] if flag else "n/a"


def disassemble(data, data_addr, start=None, count=None, end=None, ctx=None,
                m=None, x=None, stop_at_return=False, with_refs=True, state=None):
    """data (番地 data_addr から始まるバイト列) を start から線形に読みます。

    count 命令 / end 番地 (含む) / data の末尾 のどれかで止まります。
    返り値は命令 dict のリスト。各命令に m / x / width_source / flags_source /
    cdl (区間の certainty) / width_uncertain / refs (with_refs のとき) が付きます。
    """
    if state is None:
        state = WidthState(ctx, m, x)
    addr = data_addr if start is None else start
    out = []
    while True:
        if count is not None and len(out) >= count:
            break
        if end is not None and addr > end:
            break
        offset = addr - data_addr
        if offset < 0 or offset >= len(data):
            break
        span = state.enter(addr)
        mv, xv = state.value["m"], state.value["x"]
        insn = decode_at(data, offset, addr, mv, xv)
        insn["m"], insn["x"] = mv, xv
        insn["m_source"] = state.source["m"]
        insn["x_source"] = state.source["x"]
        insn["width_source"] = _width_source_of(insn, state)
        insn["width_uncertain"] = insn["width_source"] in UNCERTAIN_SOURCES
        insn["cdl"] = span[4] if span is not None else None
        if ctx is not None and addr in ctx.ambiguity:
            insn["cdl_ambiguity"] = ctx.ambiguity[addr]
        if insn.get("target") is not None and ctx is not None:
            raw_target = insn["target"]
            insn["target"] = ctx.canonical_rom(raw_target)
            if insn["target"] != raw_target:
                insn["target_raw"] = raw_target
        if with_refs:
            insn["refs"] = operand_refs(insn, mv, xv, ctx, state.d_changed,
                                        state.dbr_changed)
        name = insn["mnemonic"]
        if name in _WIDTH_LOST:
            insn["note"] = _WIDTH_LOST[name] + "。以降の幅は静的には不明 (CDL があればそちらで確定)。"
        state.leave(insn)
        out.append(insn)
        if insn.get("truncated"):
            break
        addr += insn["size"]
        if stop_at_return and insn["flow"] == "return":
            break
    return out


def instruction_start_check(data, data_addr, span, target, ctx=None):
    """CDL 区間の先頭から読んで、target が命令の先頭に当たるかを確かめます。

    返り値: None (先頭に当たる / 確かめようがない) または
            {"inside": 含む命令の番地, "text": その命令} (命令の途中)。
    """
    if span is None or span[0] >= target:
        return None
    for insn in disassemble(data, data_addr, start=span[0], end=target, ctx=ctx,
                            with_refs=False):
        if insn["addr"] == target:
            return None
        if insn["addr"] < target < insn["addr"] + insn["size"]:
            return {"inside": _hex24(insn["addr"]), "text": insn["text"],
                    "size": insn["size"]}
    return None


# --- 走査範囲 --------------------------------------------------------------------
def scan_runs(ctx, lo, hi):
    """[lo, hi] の中で、線形に読んでよい区間 [(start, end, basis, segments)] を返します。

    CDL があれば CDL の区間 (隣接する区間はつなげて 1 本の run にする。幅は区間ごとに
    CDL から取るので、つなげても幅は混ざらない)。segments は run を構成する
    CDL 区間で、**各区間の先頭から読み直す** (曖昧な区間で幅を誤って次の区間へ
    はみ出しても、記録された命令境界へ戻れるように)。無ければ functions.json の
    関数本体。それも無ければブロック全体 (幅は assumed から)。
    """
    if ctx is not None and ctx.has_cdl:
        runs = []
        for s, e, _m, _x, _c in ctx.spans_in(lo, hi):
            s, e = max(s, lo), min(e, hi)
            if runs and runs[-1][1] + 1 >= s:
                runs[-1][1] = max(runs[-1][1], e)
                runs[-1][3].append((s, e))
            else:
                runs.append([s, e, "cdl", [(s, e)]])
        return [tuple(r) for r in runs]
    if ctx is not None and ctx.code_ranges:
        out = []
        for s, e in ctx.code_ranges:
            if e < lo or s > hi:
                continue
            s, e = max(s, lo), min(e, hi)
            out.append((s, e, "function_body", [(s, e)]))
        if out:
            return out
    return [(lo, hi, "whole_block", [(lo, hi)])]


def iter_code(data, base_addr, ctx=None):
    """ブロック (data, 先頭 base_addr) の走査対象コードを 1 命令ずつ返します。

    (run の番号, 命令 dict) を yield。run が変わったら値の追跡を切ること。
    """
    hi = base_addr + len(data) - 1
    for run_no, (_s, _e, basis, segments) in enumerate(scan_runs(ctx, base_addr, hi)):
        state = WidthState(ctx)
        for seg_start, seg_end in segments:
            for insn in disassemble(data, base_addr, start=seg_start, end=seg_end,
                                    ctx=ctx, state=state):
                insn["scan_basis"] = basis
                yield run_no, insn


def scan_basis(ctx):
    """走査範囲の決め方 (応答用)。"""
    if ctx is not None and ctx.has_cdl:
        return "cdl"
    if ctx is not None and ctx.code_ranges:
        return "function_body"
    return "whole_block"


# find_writers の引数名 scan_basis がこの関数名を隠すので、中からはこちらで呼ぶ。
_scan_basis_of = scan_basis


# --- find_address_refs 用の索引 ------------------------------------------------------
def _ref_extra(insn, ref=None):
    """索引の 4 つ目の要素。width_source は **アクセス幅** を決めたフラグの出どころ
    (STA $0B20 なら m)。長さが幅で変わる即値命令なら長さを決めたフラグの出どころ。"""
    source = insn["width_source"]
    if ref is not None and ref.get("size_flag") in ("m", "x"):
        source = insn[ref["size_flag"] + "_source"]
    extra = {"text": insn["text"], "m": insn["m"], "x": insn["x"],
             "width_source": source, "cdl": insn["cdl"]}
    if insn["width_uncertain"] or source in UNCERTAIN_SOURCES:
        extra["width_uncertain"] = True
    if ref is not None:
        extra["access"] = ref["access"]
        if ref.get("size"):
            extra["size"] = ref["size"]
        if ref["assumptions"]:
            extra["assumptions"] = list(ref["assumptions"])
        if ref.get("pointer"):
            extra["pointer"] = True
        if ref.get("indexed"):
            extra["indexed"] = True
    return extra


def build_ref_index(data, base_addr, big_endian=False, window=None, context=None):
    """ブロックを走査し、{参照先番地: [(命令番地, form, 命令番地, extra)]} を返します。

    extra は dict (text / access / m / x / width_source / assumptions ...)。
    共通層は先頭 3 要素だけを使い、4 つ目があれば応答にそのまま足します。
    """
    index = {}
    for _run, insn in iter_code(data, base_addr, context):
        at = insn["addr"]
        for ref in insn.get("refs") or ():
            index.setdefault(ref["ea"], []).append(
                (at, ref["form"], at, _ref_extra(insn, ref)))
        ctl = _control_ref(insn, context)
        if ctl is not None:
            index.setdefault(ctl[0], []).append(
                (at, ctl[1], at, _ref_extra(insn)))
    return index


def canonical_query(address, context=None):
    """ユーザーが渡した番地を索引と同じ正規形にします。"""
    if context is None:
        return canonical_data_address(address)
    return context.canonical(address)


# --- find_writers --------------------------------------------------------------------
_A_SETTERS_IMM = {"LDA": "A", "LDX": "X", "LDY": "Y"}
# レジスタを壊す命令 (値の追跡を打ち切る)。
_CLOBBERS = {
    "A": {"LDA", "ADC", "SBC", "AND", "ORA", "EOR", "TXA", "TYA", "PLA", "TDC",
          "TSC", "XBA", "INC", "DEC", "ASL", "LSR", "ROL", "ROR", "MVN", "MVP"},
    "X": {"LDX", "INX", "DEX", "TAX", "TYX", "TSX", "PLX", "MVN", "MVP"},
    "Y": {"LDY", "INY", "DEY", "TAY", "TXY", "PLY", "MVN", "MVP"},
}
_ACC_ONLY_CLOBBER = {"INC", "DEC", "ASL", "LSR", "ROL", "ROR"}
_STORE_REG = {"STA": "A", "STX": "X", "STY": "Y", "TSB": "A", "TRB": "A"}


def _trace_value(history, reg, limit):
    """history (同じ run の直前の命令、新しい順) から reg に入った即値を探します。"""
    for insn in history[:limit]:
        name = insn["mnemonic"]
        if insn["flow"] is not None:
            return None, "分岐/呼び出しを越えた"
        if _A_SETTERS_IMM.get(name) == reg and insn["mode"] in ("immM", "immX"):
            return insn, None
        if name in _CLOBBERS[reg]:
            if name in _ACC_ONLY_CLOBBER and insn["mode"] != "acc":
                continue                      # INC $xx はメモリ側。A は変わらない
            return None, "{0} でレジスタが変わる".format(name)
        if name in ("REP", "SEP", "PLP", "XCE"):
            # 幅が変わると上位バイトの扱いが変わる。値は言えない。
            return None, "{0} で幅が変わる".format(name)
    return None, "trace_imm の範囲に即値ロードが無い"


def _covers(ea, size, target):
    """[ea, ea+size) が target を含むなら何バイト目か、含まなければ None。"""
    if size and ea <= target < ea + size:
        return target - ea
    return None


def find_writers(data, base_addr, big_endian, target, mask=0xFFFFFFFF,
                 max_scan=12, trace_imm=16, context=None, index_reach=None,
                 scan_basis=None, analyzer=None, target_end=None):
    """その番地に書き込む命令 (と読む命令) を列挙します。

    target は正規化して比較します (0x000b20 と 0x7e0b20 は同じ)。
    mask が全ビットでなければ、基底番地 & mask == target & mask で照合します。
    index_reach: ,X ,Y 付きの基底番地から何バイト先まで届くとみなすか。
      既定は添字が 8bit なら 0xFF、16bit なら 0x7FF (後者は目安)。
    max_scan は 65816 では使いません (レジスタ経由でない直接番地なので)。
    scan_basis="bytes" なら CDL を使わずバイト列の全域から拾い、各候補に
      「CDL で実行済みか / 幅は確定か推測か / 命令の境界として妥当か」を付けます
      (w65816_flow.writers_by_bytes。analyzer が要る)。
    target_end: 渡すと [target, target_end] (両端を含む) のどこかへ触る命令を拾います
      (record_formats の「項目ごとの配列」1 項目ぶんを 1 回の走査で探すため)。
      ,X ,Y 付きは「基底 + 届く範囲」が区間と重なれば offset_writers。
      CDL 走査だけ対応 (bytes とは併用不可)。
    """
    if target_end is not None and scan_basis == "bytes":
        raise ValueError("target_end (範囲指定) は scan_basis=bytes と併用できません "
                         "(番地を 1 つずつ指定してください)。")
    if scan_basis == "bytes":
        if (mask & 0xFFFFFF) != 0xFFFFFF:
            raise ValueError("scan_basis=bytes では mask を使えません (番地 1 つを指定してください)。")
        if analyzer is None:
            raise ValueError("scan_basis=bytes には解析器が要ります (MCP の不具合)。")
        return _flow.writers_by_bytes(analyzer, data, base_addr, target,
                                      trace_imm, index_reach)
    if scan_basis not in (None, "", "cdl", "auto"):
        raise ValueError("scan_basis は cdl (既定) か bytes で指定してください: {0}".format(
            scan_basis))
    ctx = context
    tgt = canonical_query(target, ctx)
    full = (mask & 0xFFFFFF) == 0xFFFFFF
    want = tgt & mask
    if target_end is not None:
        if not full:
            raise ValueError("target_end (範囲指定) と mask は併用できません。")
        tgt_hi = canonical_query(target_end, ctx)
        if tgt_hi < tgt:
            raise ValueError("target_end が target より前です (正規化後 {0} < {1})。".format(
                _hex24(tgt_hi), _hex24(tgt)))
    else:
        tgt_hi = tgt
    writers, offset_writers, readers = [], [], []
    indirect_stores = 0
    uncertain = 0
    history = []
    run_now = None

    for run_no, insn in iter_code(data, base_addr, ctx):
        if run_no != run_now:
            history = []
            run_now = run_no
        name = insn["mnemonic"]
        for ref in insn.get("refs") or ():
            if ref.get("pointer"):
                if ref.get("target_access") in ("W", "RW"):
                    indirect_stores += 1
                continue
            if ref["access"] == "imm":
                continue
            ea, size = ref["ea"], ref.get("size") or 1
            reach = 0
            if ref["indexed"]:
                if index_reach is not None:
                    reach = int(index_reach)
                else:
                    reach = 0xFF if insn["x"] else 0x7FF
            # ,X ,Y 付きは添字次第なので「ちょうどこの番地」とは言えない。
            # 基底番地が target でも offset_writers / indexed reader に回す。
            if ref["indexed"]:
                byte = None
                if full:
                    in_reach = ea <= tgt_hi and tgt <= ea + reach + size - 1
                else:
                    in_reach = (ea & mask) == want
            elif full and tgt_hi != tgt:
                # 範囲指定: [ea, ea+size) と [tgt, tgt_hi] が重なれば拾う。
                byte = None
                for b in range(size):
                    if tgt <= ea + b <= tgt_hi:
                        byte = b
                        break
                in_reach = False
            elif full:
                byte = _covers(ea, size, tgt)
                in_reach = False
            else:
                byte = 0 if (ea & mask) == want else None
                in_reach = False
            if byte is None and not in_reach:
                continue

            item = {
                "addr": _hex24(insn["addr"]),
                "text": insn["text"],
                "op": name,
                "form": ref["form"],
                "access": ref["access"],
                "ea": _hex24(ea),
                "width": size,
                "m": insn["m"], "x": insn["x"],
                "width_source": (insn["m_source"] if ref["size_flag"] == "m"
                                 else insn["x_source"] if ref["size_flag"] == "x"
                                 else "n/a"),
                "cdl": insn["cdl"],
            }
            if item["width_source"] in UNCERTAIN_SOURCES:
                item["width_uncertain"] = True
                uncertain += 1
            if ref["assumptions"]:
                item["assumptions"] = list(ref["assumptions"])
            if byte is not None and size > 1 and tgt_hi == tgt:
                item["covers"] = ("下位バイト" if byte == 0 else
                                  "上位バイト" if byte == size - 1 else
                                  "{0} バイト目".format(byte))
            if in_reach:
                item["indexed"] = True
                if full and tgt_hi == tgt:
                    item["index_offset"] = tgt - ea
                    item["index_reach"] = reach
                elif full:
                    item["index_reach"] = reach
            if ref["access"] == "R":
                readers.append(item)
                continue

            # 書く値 (即値ロードから追えたときだけ)。
            if name == "STZ":
                item["value"] = 0
                item["writes_zero"] = True
            elif name in _STORE_REG:
                src, why = _trace_value(history, _STORE_REG[name],
                                        max(1, int(trace_imm)))
                if src is not None:
                    item["value"] = src["operand"]
                    item["value_hex"] = src["operands"]
                    item["value_from"] = "{0} @ {1}".format(
                        src["text"], _hex24(src["addr"]))
                    item["writes_zero"] = (src["operand"] == 0)
                else:
                    item["value"] = None
                    item["value_note"] = why
            else:
                item["value"] = None               # INC/DEC/ASL... は元の値次第
            (offset_writers if in_reach else writers).append(item)

        history.insert(0, insn)
        del history[64:]

    return {
        "pools": [],
        "writers": writers,
        "offset_writers": offset_writers,
        "readers": readers,
        "unresolved": [],
        "max_scan_reached": 0,
        "indirect_stores": indirect_stores,
        "width_uncertain_hits": uncertain,
        "target_canonical": _hex24(tgt),
        "target_end_canonical": _hex24(tgt_hi) if tgt_hi != tgt else None,
        "scan_basis": _scan_basis_of(ctx),
    }


# --- 制御フロー解析のフック (w65816_flow.py) ------------------------------------
# 分岐を辿る解析は別モジュールに置き、ここではフック名で公開するだけにします
# (MCP 本体は getattr(arch_mod, "<フック名>") で引く)。末尾で import するのは循環
# import を避けるため (w65816_flow はこのモジュールの関数を使う)。
from . import w65816_flow as _flow                                   # noqa: E402

WRITERS_SCAN_BASES = ("cdl", "bytes")
# find_writers が target_end (範囲指定) を受けるか。MCP 本体の record_formats
# (項目ごとの配列) がこれを見て 1 回の走査で済ませる。
WRITERS_TARGET_RANGE = True


def mirror_of(addr, context=None):
    """ROM ミラー上の番地なら、Program に実体 (バイト列) が載っている側の番地を返します。

    LoROM の $00-$3F:8000-FFFF ⇔ $80-$BF:8000-FFFF、HiROM の $40-$7D ⇔ $C0-$FD
    (bit23 違い)。WidthContext.canonical_rom と同じ規則で、載っている側が無ければ None。
    MCP の list_functions 等が「この関数は $80:xxxx の重複」と注記するのに使う。
    """
    if context is None:
        return None
    addr &= 0xFFFFFF
    alt = context.canonical_rom(addr)
    return alt if alt != addr else None


MIRROR_NOTE = ("SNES の ROM ミラー: LoROM は $00-$3F:8000-FFFF ⇔ $80-$BF:8000-FFFF、"
               "HiROM は $40-$7D ⇔ $C0-$FD (bit23 違い)。export されたメモリに実体がある側を"
               "正とします。")

# list_callees(ordered=true) の「条件分岐の後ろか」の判定に使う。flow "branch" が
# 条件分岐 (BNE 等)、"jump" が無条件 (BRA/BRL/JMP/JML)。遅延スロットは無い。
COND_BRANCH_FLOW = "branch"
make_analyzer = _flow.make_analyzer
find_calls_to = _flow.find_calls_to_hook
find_function_entry = _flow.find_function_entry_hook
expand_switch = _flow.expand_switch_hook
find_path = _flow.find_path_hook
list_memory_args = _flow.list_memory_args_hook
lint_stale_register = _flow.lint_stale_register_hook
WRITERS_BYTES_NOTE = _flow.WRITERS_BYTES_NOTE
CALLS_BLIND_SPOTS = _flow.CALLS_BLIND_SPOTS
SWITCH_NOTE = (
    "JSR ($abs,X) / JMP ($abs,X) の表を展開しました。件数は直前の CMP #n + BCS/BCC "
    "なら確定、AND #k なら上限、どちらも無ければ表の終端の推定 (count_is_estimated)。"
    "飛び先は同じバンクの番地です。")
