# -*- coding: utf-8 -*-
"""65816 (SNES / SFC) の制御フロー解析 (Python 3.13 前提)。

`w65816.py` の線形デコーダの上に、**分岐を辿る**解析を載せたものです。
読み取り専用 MCP の次の機能が使います:

  find_calls_to          指定番地を呼ぶ・飛ぶ命令 (JSL/JML/JSR/JMP/BRL/BRA/Bcc/表) の全列挙
  find_writers(bytes)    CDL 外も含めたバイト列走査での書き込み元
  find_function_entry    入口の推定 (確度つき)
  expand_switch          JSR/JMP (abs,X) の表の展開
  find_path              入口 A から番地 B への到達経路
  list_memory_args       メモリ経由の引数の「設定漏れ」一覧
  lint_stale_register    A の上位バイト (B) の持ち越し

★このアーキは**命令長が M/X で変わる**ので、分岐を辿るときに M/X も一緒に運びます。
  優先順位 (フラグごと):
    1. 明示 (given)
    2. CDL に記録された幅 (recorded / static_only)
    3. 辿ってきた幅 — 呼び出し元の幅 (caller)、REP/SEP (tracked)、PHP/PLP の対 (plp)、
       呼び出し先から戻った幅 (callee_exit)
    4. CDL の ambiguous 区間に書かれた片方の幅
    5. 分からない (after_call / unknown / assumed) — **推測**として印を付ける
  P は JSR/JSL では変わらないので、**呼び出し先の入口の幅 = 呼び出し元の幅**です。
  CDL に記録の無いコードはこれで読みます。

★「推測で断定しない / 拾えないものは拾えないと明示する」:
  - バイト列で拾った候補には、CDL の命令境界と矛盾しないか (boundary) を必ず付けます。
  - 幅を推測した命令には width_uncertain を付けます。
  - 辿れなかった間接ジャンプ・間接書き込みは件数と番地を返し、「無い」とは言いません。
"""

import bisect
import re

from . import w65816 as W


FMT = "0x{0:06x}"
_CERTAIN_CDL = ("recorded", "static_only")
# 幅が推測であることを示す出どころ (w65816.UNCERTAIN_SOURCES に after_call を足したもの)。
FLOW_UNCERTAIN = tuple(W.UNCERTAIN_SOURCES) + ("after_call",)
# ここで読みを止める命令 (ゲームのコードにはまず出ない。出たらデータを読んでいる)。
_STOP_OPS = {"BRK", "COP", "STP", "WDM"}
# 1 リージョン (入口から辿れる命令) の上限。
MAX_REGION = 6000
# 呼び出し先の要約 (幅・書き込み・A の出どころ) を何段まで再帰で求めるか。
MAX_DEPTH = 24
MEM_DEPTH = 6
UNK = -1                      # 「書いたが値は分からない」

# 命令長の表 _LEN[opcode][m][x]。
_LEN = [[[1 + W.operand_size(mode, m, x) for x in (0, 1)] for m in (0, 1)]
        for (_mn, mode) in W.OPCODES]

_BRANCH_OPS = {0x10: "BPL", 0x30: "BMI", 0x50: "BVC", 0x70: "BVS",
               0x90: "BCC", 0xB0: "BCS", 0xD0: "BNE", 0xF0: "BEQ", 0x80: "BRA"}

# 書き込み命令 (STA/STX/STY/STZ と RMW) のうち、実効番地が命令に書いてあるもの。
_WRITE_MODES = ("dp", "dpx", "dpy", "abs", "abx", "aby", "abl", "alx")
_WRITE_OPCODES = tuple(
    op for op, (mn, mode) in enumerate(W.OPCODES)
    if mode in _WRITE_MODES and (mn in W._WRITE_OPS or mn in W._RMW_OPS))
_WRITE_RE = re.compile(b"[" + b"".join(re.escape(bytes([o])) for o in _WRITE_OPCODES) + b"]")

# A を読む命令 (幅は M)。
_A_USES = {"STA", "PHA", "CMP", "ADC", "SBC", "AND", "ORA", "EOR", "BIT"}
_A_ARITH = {"AND", "ORA", "EOR", "ADC", "SBC"}
_A_RMW_ACC = {"ASL", "LSR", "ROL", "ROR", "INC", "DEC"}


def _h(value):
    return FMT.format(value & 0xFFFFFF)


def _bus(value):
    return W.bus_text(value)


def _next(addr, size):
    """同じバンクの中で size 先 (PC はバンクを越えない)。"""
    return (addr & 0xFF0000) | ((addr + size) & 0xFFFF)


def _soft(src):
    """呼び出し先の影響が分からないときの出どころ。"""
    return src if src in FLOW_UNCERTAIN else "after_call"


class Node(object):
    """リージョンの中の 1 命令。"""

    __slots__ = ("addr", "ins", "m", "x", "ms", "xs", "succ", "calls")

    def __init__(self, addr, ins, m, x, ms, xs):
        self.addr = addr
        self.ins = ins
        self.m = m
        self.x = x
        self.ms = ms
        self.xs = xs
        self.succ = []
        self.calls = None          # [(target, m, x, ms, xs, kind)] 呼び出し / 末尾ジャンプ

    @property
    def uncertain(self):
        flag = W.width_flag(self.ins["mnemonic"], self.ins["mode"])
        if flag == "m":
            return self.ms in FLOW_UNCERTAIN
        if flag == "x":
            return self.xs in FLOW_UNCERTAIN
        return False


class Region(object):
    """入口から分岐を辿って読めた命令の集まり (= 1 つの関数とみなす範囲)。

    JSR / JSL / JSR (abs,X) の先は**別のリージョン**です (calls に入る)。
    JMP / JML は、飛び先が既知の入口なら末尾ジャンプ (calls の kind=tail)、
    そうでなければ同じリージョンの続きとして辿ります。
    JMP (abs,X) の表の先も別リージョン (kind=jmp_table) です。
    """

    def __init__(self, entry, m, x, ms, xs):
        self.entry = entry
        self.m, self.x, self.ms, self.xs = m, x, ms, xs
        self.nodes = {}
        self.calls = []
        self.returns = []
        self.unresolved = []
        self.suspicious = []
        self.problems = []
        self.tables = []
        self.pushed_returns = []
        self.conflicts = 0
        self.truncated = False
        self.ends = {}
        self.widths_differ_from_cdl = False

    def back(self, addr, limit=12):
        """addr の直前を「そこへ落ちてくる命令」で遡ったもの (新しい順)。"""
        out = []
        cur = addr
        while len(out) < limit:
            prev = self.ends.get(cur)
            if prev is None:
                break
            node = self.nodes[prev]
            out.append(node)
            cur = prev
        return out

    def preds(self):
        """{番地: [前の命令の番地]}。"""
        out = {}
        for addr, node in self.nodes.items():
            for s in node.succ:
                out.setdefault(s, []).append(addr)
        return out

    def summary(self):
        """応答に載せる要約。"""
        return {
            "entry": _h(self.entry),
            "entry_bus": _bus(self.entry),
            "entry_widths": "m{0}x{1}".format(self.m, self.x),
            "instructions": len(self.nodes),
            "calls": len(self.calls),
            "unresolved_indirect": len(self.unresolved),
            "suspicious": [_h(a) for a in self.suspicious[:8]],
            "truncated": self.truncated,
            "entered_at_width_not_in_cdl": self.widths_differ_from_cdl,
        }


class Analyzer(object):
    """イメージ全体 (BusImage) と CDL (WidthContext) を抱えた解析器です。

    MCP 側が ctx の指紋ごとに 1 つ作ってキャッシュします
    (リージョンや表の展開結果を使い回すため)。
    """

    def __init__(self, image, ctx, entries=None, max_region=MAX_REGION):
        self.image = image
        self.ctx = ctx
        self.names = dict(entries or {})
        self.known = set(self.names)
        for addr in (getattr(ctx, "call_targets", None) or {}):
            self.known.add(addr)
        self._known_sorted = sorted(self.known)
        self.max_region = max_region
        self._dec = {}
        self._regions = {}
        self._inprog = set()
        self._cdl_starts = {}
        self._tables = {}
        self._dispatch = {}
        self._msum = {}
        self._asum = {}
        self._text = {}
        self._entry_cache = {}
        self._deep = False
        self._canret = {}
        self._live = {}
        self._sstack = []          # 要約を計算中のキー (循環の検出)
        self._provisional = set()  # 循環の途中の値に依存した要約 (キャッシュしない)

    # --- 基本 -------------------------------------------------------------
    def decode(self, addr, m, x):
        """1 命令をデコードします (幅に依存しない命令は m/x を無視してキャッシュ)。"""
        loc = self.image.locate(addr)
        if loc is None:
            return None
        data, base = loc
        op = data[addr - base]
        mode = W.OPCODES[op][1]
        key = (addr, m if mode == "immM" else None, x if mode == "immX" else None)
        got = self._dec.get(key)
        if got is not None:
            return got
        ins = W.decode_at(data, addr - base, addr, m, x)
        if ins.get("target") is not None:
            raw = ins["target"]
            ins["target"] = self.ctx.canonical_rom(raw)
            if ins["target"] != raw:
                ins["target_raw"] = raw
        self._dec[key] = ins
        return ins

    def text_at(self, addr):
        """リージョンで読んだときの命令文字列 (読んでいなければ幅仮定で読む)。"""
        text = self._text.get(addr)
        if text is None:
            span = self.ctx.span_at(addr)
            m = span[2] if span and span[2] is not None else 1
            x = span[3] if span and span[3] is not None else 1
            ins = self.decode(addr, m, x)
            text = ins["text"] if ins else "?"
        return text

    def name_of(self, addr):
        return self.names.get(addr)

    def is_code_byte(self, addr):
        """CDL がこの番地をコードとして記録しているか (実行 / 静的どちらでも)。"""
        return self.ctx.in_code_run(addr) or self.ctx.span_at(addr) is not None

    def entry_widths(self, entry):
        """入口の幅を CDL から (m, x, ms, xs)。分からないフラグは None。"""
        rec = (self.ctx.call_targets or {}).get(entry)
        span = self.ctx.span_at(entry)
        out = []
        for key, idx in (("m", 2), ("x", 3)):
            value, src = None, None
            if rec and rec.get(key) is not None and rec.get("certainty") in _CERTAIN_CDL:
                value, src = rec[key], "cdl_" + rec["certainty"]
            elif span is not None and span[idx] is not None and span[4] in _CERTAIN_CDL:
                value, src = span[idx], "cdl_" + span[4]
            out.append((value, src))
        return out[0][0], out[1][0], out[0][1], out[1][1]

    # --- 幅の決定 ------------------------------------------------------------
    def _widths(self, addr, st, prefer_flow=False):
        """addr を読むときの (m, x, m の出どころ, x の出どころ)。"""
        span = self.ctx.span_at(addr)
        out = []
        for idx, val, src in ((2, st[0], st[2]), (3, st[1], st[3])):
            if src == "given":
                out.append((val, src))
                continue
            if span is not None and span[idx] is not None:
                if span[4] in _CERTAIN_CDL and not (prefer_flow and src not in FLOW_UNCERTAIN):
                    out.append((span[idx], "cdl_" + span[4]))
                    continue
                if src in FLOW_UNCERTAIN:
                    out.append((span[idx], "ambiguous"))
                    continue
            out.append((val, src))
        return out[0][0], out[1][0], out[0][1], out[1][1]

    # --- リージョン (分岐を辿る) ------------------------------------------------
    def region(self, entry, m, x, ms="caller", xs="caller", depth=0):
        """entry から m / x で辿ったリージョン。再帰中・深すぎるときは None。"""
        m = 1 if m is None else m
        x = 1 if x is None else x
        ms = ms or "assumed"
        xs = xs or "assumed"
        key = (entry, m, x, ms in FLOW_UNCERTAIN, xs in FLOW_UNCERTAIN)
        got = self._regions.get(key)
        if got is not None:
            return got
        if key in self._inprog or depth > MAX_DEPTH:
            return None
        self._inprog.add(key)
        try:
            reg = Region(entry, m, x, ms, xs)
            self._explore(reg, depth)
        finally:
            self._inprog.discard(key)
        self._regions[key] = reg
        return reg

    def region_for(self, entry, m=None, x=None, depth=0):
        """CDL / 明示から入口の幅を決めてリージョンを返します (幅の出どころも返す)。"""
        cm, cx, cms, cxs = self.entry_widths(entry)
        ms = "given" if m is not None else (cms or "assumed")
        xs = "given" if x is not None else (cxs or "assumed")
        mv = m if m is not None else (cm if cm is not None else 1)
        xv = x if x is not None else (cx if cx is not None else 1)
        return self.region(entry, mv, xv, ms, xs, depth), (mv, xv, ms, xs)

    def _explore(self, reg, depth):
        """リージョンを辿ります (作業リスト。分岐の両側を見る)。"""
        ctx = self.ctx
        tgt_rec = (ctx.call_targets or {}).get(reg.entry) or {}
        multi = bool(tgt_rec.get("multi_width")) or reg.entry in ctx.ambiguity
        # 呼び出し元から確かな幅で入ったのに、CDL が入口に別の幅を記録している
        # = CDL が見ていない幅で呼ばれている (同じ処理を 2 通りの幅で呼ぶ)。
        # このときリージョンの中は辿ってきた幅を優先する (CDL の幅は別の呼ばれ方のもの)。
        span0 = ctx.span_at(reg.entry)
        if span0 is not None and span0[4] in _CERTAIN_CDL:
            if (reg.ms not in FLOW_UNCERTAIN and span0[2] is not None and span0[2] != reg.m) or \
                    (reg.xs not in FLOW_UNCERTAIN and span0[3] is not None and span0[3] != reg.x):
                multi = True
                reg.widths_differ_from_cdl = True
        work = [(reg.entry, (reg.m, reg.x, reg.ms, reg.xs, ()))]
        while work:
            addr, st = work.pop()
            node = reg.nodes.get(addr)
            if node is not None:
                mv, xv, _a, _b = self._widths(addr, st, multi)
                flag = W.width_flag(node.ins["mnemonic"], node.ins["mode"])
                if flag and (mv if flag == "m" else xv) != getattr(node, flag):
                    reg.conflicts += 1
                continue
            if len(reg.nodes) >= self.max_region:
                reg.truncated = True
                break
            mv, xv, ms, xs = self._widths(addr, st, multi)
            ins = self.decode(addr, mv, xv)
            if ins is None:
                reg.problems.append({"addr": _h(addr), "what": "イメージの外"})
                continue
            node = Node(addr, ins, mv, xv, ms, xs)
            reg.nodes[addr] = node
            self._text.setdefault(addr, ins["text"])
            if ins.get("truncated"):
                reg.problems.append({"addr": _h(addr), "what": "ブロック末尾で命令が切れている"})
                continue
            name = ins["mnemonic"]
            nxt = _next(addr, ins["size"])
            reg.ends.setdefault(nxt, addr)
            nm, nx, nms, nxs, pst = mv, xv, ms, xs, st[4]
            op = ins.get("operand")
            if name in ("REP", "SEP") and op is not None:
                if op & W.PS_M:
                    nm, nms = (0 if name == "REP" else 1), "tracked"
                if op & W.PS_X:
                    nx, nxs = (0 if name == "REP" else 1), "tracked"
            elif name == "PHP":
                pst = (pst + ((mv, xv, ms, xs),))[-8:]
            elif name == "PLP":
                if pst:
                    pm, px, pms, pxs = pst[-1]
                    pst = pst[:-1]
                    nm, nx = pm, px
                    nms = pms if pms in FLOW_UNCERTAIN else "plp"
                    nxs = pxs if pxs in FLOW_UNCERTAIN else "plp"
                else:
                    nms = nxs = "unknown"
            elif name == "XCE":
                nms = nxs = "unknown"
            if name in _STOP_OPS:
                reg.suspicious.append(addr)
                continue
            nst = (nm, nx, nms, nxs, pst)
            flow = ins["flow"]
            target = ins.get("target")
            if flow is None:
                node.succ.append(nxt)
                work.append((nxt, nst))
                if name == "PEA" and op is not None:
                    self._pushed_return(reg, node, op, nst, work)
            elif flow == "branch":
                node.succ.extend([nxt, target])
                work.append((nxt, nst))
                work.append((target, nst))
            elif flow == "jump":
                if (name in ("JMP", "JML") and target != reg.entry
                        and target in self.known):
                    node.calls = [(target, nm, nx, nms, nxs, "tail")]
                    reg.calls.append(self._call(node, target, "tail"))
                else:
                    node.succ.append(target)
                    work.append((target, nst))
            elif flow == "call":
                kind = "jsl" if name == "JSL" else "jsr"
                node.calls = [(target, nm, nx, nms, nxs, kind)]
                reg.calls.append(self._call(node, target, kind))
                after = self._after_call([(target, nm, nx, nms, nxs)], nst, depth)
                node.succ.append(nxt)
                work.append((nxt, after))
            elif flow == "call_reg":
                tbl = self.table_at(reg, node)
                reg.tables.append(tbl)
                targets = []
                node.calls = []
                for e in tbl["_entries"]:
                    node.calls.append((e, nm, nx, nms, nxs, "jsr_table"))
                    reg.calls.append(self._call(node, e, "jsr_table",
                                                tbl["_index"].get(e), tbl))
                    targets.append((e, nm, nx, nms, nxs))
                if not targets:
                    reg.unresolved.append(addr)
                after = (self._after_call(targets, nst, depth) if targets else
                         (nm, nx, _soft(nms), _soft(nxs), pst))
                node.succ.append(nxt)
                work.append((nxt, after))
            elif flow == "jump_reg":
                if ins["mode"] == "iax":
                    tbl = self.table_at(reg, node)
                    reg.tables.append(tbl)
                    node.calls = []
                    for e in tbl["_entries"]:
                        node.calls.append((e, nm, nx, nms, nxs, "jmp_table"))
                        reg.calls.append(self._call(node, e, "jmp_table",
                                                    tbl["_index"].get(e), tbl))
                    if not tbl["_entries"]:
                        reg.unresolved.append(addr)
                else:
                    reg.unresolved.append(addr)       # JMP (abs) / JML [abs]: 実行時
            elif flow == "return":
                reg.returns.append((addr, nm, nx, nms, nxs))

    def _call(self, node, target, kind, index=None, tbl=None):
        """リージョンの calls に入れる 1 件。"""
        rec = {"site": node.addr, "target": target, "kind": kind,
               "m": node.m, "x": node.x, "text": node.ins["text"]}
        if index is not None:
            rec["index"] = index
        if tbl is not None:
            rec["table"] = tbl["table"]
            rec["observed"] = target in tbl["_observed"]
        return rec

    def _pushed_return(self, reg, node, op, nst, work):
        """PEA $xxxx (+ RTL/RTS で戻る先を積む慣用) の戻り先を、CDL がコードと
        記録しているときだけ辿ります (定数を積む PEA と区別できないため)。"""
        bank = node.addr & 0xFF0000
        for prev in reg.back(node.addr, 4):
            if prev.ins["mnemonic"] == "PHK":
                break
            if prev.ins["mnemonic"] == "PHA":
                continue
            if prev.ins["mnemonic"] == "LDA" and prev.ins["mode"] == "immM":
                bank = (prev.ins["operand"] & 0xFF) << 16
                break
        target = self.ctx.canonical_rom(bank | ((op + 1) & 0xFFFF))
        if self.ctx.span_at(target) is None or not self.image.has(target):
            return
        reg.pushed_returns.append((node.addr, target))
        node.succ.append(target)
        work.append((target, (nst[0], nst[1], _soft(nst[2]), _soft(nst[3]), nst[4])))

    def _after_call(self, targets, st, depth):
        """呼び出しから戻った後の幅。呼び出し先の要約が取れなければ after_call。"""
        outs = set()
        for t, m, x, ms, xs in targets:
            got = self.exit_widths(t, m, x, ms, xs, depth)
            if got is None:
                return (st[0], st[1], _soft(st[2]), _soft(st[3]), st[4])
            outs.add(got)
        values = {(o[0], o[1]) for o in outs}
        if len(values) != 1:
            return (st[0], st[1], _soft(st[2]), _soft(st[3]), st[4])
        em, ex = values.pop()
        ems = "after_call" if any(o[2] in FLOW_UNCERTAIN for o in outs) else "callee_exit"
        exs = "after_call" if any(o[3] in FLOW_UNCERTAIN for o in outs) else "callee_exit"
        return (em, ex, ems, exs, st[4])

    def live_nodes(self, reg):
        """呼び出し元へ戻る経路 (RTS/RTL/RTI か、戻る処理への末尾ジャンプ) に乗っている
        命令の集合。ソフトリセットのような戻らない枝の呼び出しは要約に影響しない。"""
        key = id(reg)
        got = self._live.get(key)
        if got is not None and got[0] is reg:
            return got[1]
        exits = {r[0] for r in reg.returns}
        for call in reg.calls:
            if call["kind"] in ("tail", "jmp_table"):
                node = reg.nodes.get(call["site"])
                if node is not None and self.can_return(call["target"], node.m, node.x):
                    exits.add(call["site"])
        preds = reg.preds()
        live = set(exits)
        stack = list(exits)
        while stack:
            a = stack.pop()
            for p in preds.get(a, ()):
                if p not in live:
                    live.add(p)
                    stack.append(p)
        self._live[key] = (reg, live)
        return live

    def _summary_begin(self, cache, key):
        """要約の計算を始めます。(済みの値, 計算を始めたか) を返します。

        計算中のキーにもう一度来たら循環なので None を返し、その循環の途中に
        いる要約を「仮」にします (仮の要約はキャッシュしない: 循環を切った
        途中の値を、外から来た別の問い合わせに使い回さないため)。
        """
        if key in cache:
            got = cache[key]
            if got is None and key in self._sstack:
                i = self._sstack.index(key)
                self._provisional.update(self._sstack[i + 1:])
            return got, False
        cache[key] = None
        self._sstack.append(key)
        return None, True

    def _summary_end(self, cache, key, value):
        """要約の計算を終えます (仮ならキャッシュから外す)。"""
        self._sstack.pop()
        if key in self._provisional:
            self._provisional.discard(key)
            cache.pop(key, None)
        else:
            cache[key] = value
        return value

    def _summary_cut(self):
        """深さの上限で打ち切った: 計算中の要約は全部「仮」。"""
        self._provisional.update(self._sstack)

    def can_return(self, entry, m, x, _stack=None):
        """呼び出し先が呼び出し元へ戻りうるか (RTS/RTL/RTI か、戻る処理への末尾ジャンプ)。

        ソフトリセットのように main へ飛んで二度と戻らない処理を見分けるためです。
        再帰で調べている途中のものは「戻らない」とみなします (その経路だけで戻る
        ことはないので)。解析できないものは「戻る」とみなします (控えめな側)。
        """
        key = (entry, m, x)
        got = self._canret.get(key)
        if got is not None:
            return got
        stack = _stack if _stack is not None else set()
        if key in stack:
            return False
        reg = self.region(entry, m, x)
        if reg is None:
            return True
        if reg.returns:
            self._canret[key] = True
            return True
        stack.add(key)
        result = False
        for call in reg.calls:
            if call["kind"] in ("tail", "jmp_table"):
                node = reg.nodes.get(call["site"])
                if node is not None and self.can_return(call["target"], node.m,
                                                        node.x, stack):
                    result = True
                    break
        stack.discard(key)
        if _stack is None or result:
            self._canret[key] = result
        return result

    def exit_widths(self, entry, m, x, ms, xs, depth):
        """呼び出し先から戻ったときの (m, x, ms, xs)。決まらなければ None。"""
        reg = self.region(entry, m, x, "caller" if ms not in FLOW_UNCERTAIN else ms,
                          "caller" if xs not in FLOW_UNCERTAIN else xs, depth + 1)
        if reg is None:
            return None
        outs = set()
        for _a, rm, rx, rms, rxs in reg.returns:
            outs.add((rm, rx, rms, rxs))
        for call in reg.calls:
            if call["kind"] == "tail":
                node = reg.nodes[call["site"]]
                got = self.exit_widths(call["target"], node.m, node.x, node.ms,
                                       node.xs, depth + 1)
                if got is None:
                    # 末尾ジャンプ先の幅が分からない (戻らない処理 / 循環 / 深すぎる)。
                    # 自分の RTS/RTL があればそちらで決める。無ければ分からない。
                    continue
                outs.add(got)
        if not outs:
            return None
        values = {(o[0], o[1]) for o in outs}
        if len(values) != 1:
            return None
        em, ex = values.pop()
        ems = "after_call" if any(o[2] in FLOW_UNCERTAIN for o in outs) else "callee_exit"
        exs = "after_call" if any(o[3] in FLOW_UNCERTAIN for o in outs) else "callee_exit"
        return (em, ex, ems, exs)

    # --- ジャンプ表 -----------------------------------------------------------
    def table_at(self, reg, node):
        """JSR/JMP (abs,X) の表を、リージョン内の直前の命令から添字の範囲を見て展開します。"""
        key = (node.addr, node.m, node.x)
        got = self._tables.get(key)
        if got is None:
            got = self.expand_table(node.addr, node.ins, reg.back(node.addr, 12),
                                    node.m, node.x)
            self._tables[key] = got
        return got

    def expand_table(self, site, ins, back, m, x):
        """表を展開します。back は直前の命令 (Node か命令 dict、新しい順)。"""
        pb = site & 0xFF0000
        base = self.ctx.canonical_rom(pb | (ins["operand"] & 0xFFFF))
        bound = _index_bound(back)
        decisive = bool(bound and bound.get("decisive"))
        limit = 256
        if bound and bound.get("count"):
            limit = max(1, min(256, bound["count"]))
        observed = set()
        for tgt, rec in (self.ctx.call_targets or {}).items():
            if site in (rec.get("called_from") or ()):
                observed.add(tgt)
        entries = []
        stop = None
        index_of = {}
        for i in range(limit):
            slot = base + 2 * i
            if (slot & 0xFFFF) > 0xFFFE:
                stop = "バンク末尾"
                break
            if i > 0 and not decisive and (self.is_code_byte(slot)
                                           or self.is_code_byte(slot + 1)):
                stop = "CDL がこの番地をコードとして記録している (表の終わり)"
                break
            word = self.image.word16(slot)
            if word is None:
                stop = "イメージの外"
                break
            target = self.ctx.canonical_rom(pb | word)
            problem = None
            if not self.image.has(target):
                problem = "飛び先がイメージの外 (ROM ではない)"
            elif base <= target <= slot + 1:
                problem = "飛び先が表の中"
            else:
                first = self.decode(target, m, x)
                if first is None or first["mnemonic"] in _STOP_OPS:
                    problem = "飛び先の先頭が命令として不自然 ({0})".format(
                        first["text"] if first else "?")
                elif i > 0 and self.ctx.in_read_run(target) and not self.is_code_byte(target):
                    problem = "飛び先は CDL でデータとして読まれている"
            if problem and not decisive:
                stop = "{0} ({1}: {2})".format(problem, _bus(slot), _bus(target))
                break
            row = {"index": i, "slot": _h(slot), "target": _h(target),
                   "target_bus": _bus(target), "in_image": self.image.has(target),
                   "observed": target in observed,
                   "executed": self.ctx.in_code_run(target)}
            if problem:
                row["problem"] = problem
            if self.name_of(target):
                row["function"] = self.name_of(target)
            entries.append(row)
            if not problem:
                index_of.setdefault(target, i)
        if stop is None and len(entries) >= limit:
            stop = ("添字の上限 ({0}) まで".format(limit) if bound and bound.get("count")
                    else "256 件で打ち切り")
        good = [int(e["target"], 16) for e in entries if not e.get("problem")]
        return {
            "site": _h(site), "site_bus": _bus(site), "text": ins["text"],
            "kind": "jsr_table" if ins["mnemonic"] == "JSR" else "jmp_table",
            "table": _h(base), "table_bus": _bus(base),
            "count": len(entries),
            "count_is_estimated": not decisive,
            "index_bound": bound,
            "stop_reason": stop,
            "entry_widths": "m{0}x{1}".format(m, x),
            "observed_by_cdl": sorted(_h(t) for t in observed),
            "entries": entries,
            "_entries": list(dict.fromkeys(good)),
            "_index": index_of,
            "_observed": observed,
        }

    # --- CDL の命令境界 -----------------------------------------------------------
    def cdl_boundary(self, addr):
        """('start' | 'inside' | None, 情報)。None は CDL で確かめられない。"""
        span = self.ctx.span_at(addr)
        if span is None or span[2] is None or span[3] is None:
            return None, None
        if span[4] not in _CERTAIN_CDL:
            return None, None
        starts = self._cdl_starts.get(span[0])
        if starts is None:
            starts = []
            p = span[0]
            while p <= span[1]:
                op = self.image.byte(p)
                if op is None:
                    break
                starts.append(p)
                p += _LEN[op][span[2]][span[3]]
            self._cdl_starts[span[0]] = starts
        i = bisect.bisect_right(starts, addr) - 1
        if i >= 0 and starts[i] == addr:
            return "start", {"cdl": span[4]}
        if i >= 0:
            inside = starts[i]
            return "inside", {"cdl": span[4], "inside": _h(inside),
                              "inside_text": self.decode(inside, span[2], span[3])["text"]}
        return None, None

    def linear_context(self, addr, window=40):
        """addr の直前を色々な位置・幅から線形に読み直し、addr に「着地」するかを数えます。

        65816 の命令列は数命令で同期するので、addr が本当の命令の先頭なら
        大半の読み方が addr に着地し、命令の途中なら着地しません。
        着地した読み方での M/X (REP/SEP で決まったもの) と直前の命令列も返します。
        """
        loc = self.image.locate(addr)
        if loc is None:
            return {"lands": False, "votes": "0/0", "ratio": 0.0}
        data, base = loc
        lo = max(base, addr - window, addr & 0xFF0000)
        tried = landed = 0
        votes_m, votes_x = {}, {}
        best = None
        for s in range(lo, addr):
            for m0, x0 in ((1, 1), (0, 0), (1, 0), (0, 1)):
                m, x = m0, x0
                mt = xt = None
                p = s
                while p < addr:
                    span = self.ctx.span_at(p)
                    if span is not None and span[4] in _CERTAIN_CDL:
                        if span[2] is not None:
                            m, mt = span[2], ("cdl", span[0])
                        if span[3] is not None:
                            x, xt = span[3], ("cdl", span[0])
                    op = data[p - base]
                    if op in (0xC2, 0xE2) and p + 1 - base < len(data):
                        v = data[p + 1 - base]
                        if v & W.PS_M:
                            m, mt = (0 if op == 0xC2 else 1), ("tracked", p)
                        if v & W.PS_X:
                            x, xt = (0 if op == 0xC2 else 1), ("tracked", p)
                    elif op in (0x28, 0xFB, 0x40):
                        mt = xt = None
                    p += _LEN[op][m][x]
                tried += 1
                if p != addr:
                    continue
                landed += 1
                if mt is not None:
                    votes_m.setdefault(m, []).append(mt)
                if xt is not None:
                    votes_x.setdefault(x, []).append(xt)
                if best is None:
                    best = (s, m0, x0)
        ratio = (landed / tried) if tried else 0.0
        out = {"lands": landed > 0, "votes": "{0}/{1}".format(landed, tried),
               "ratio": round(ratio, 2)}
        for flag, votes in (("m", votes_m), ("x", votes_x)):
            if len(votes) == 1:
                value, how = next(iter(votes.items()))
                kinds = {h[0] for h in how}
                src_addr = max(h[1] for h in how)
                out[flag] = value
                out[flag + "_source"] = ("cdl" if kinds == {"cdl"} else "tracked")
                out[flag + "_from"] = _h(src_addr)
            elif votes:
                out[flag] = None
                out[flag + "_source"] = "conflict"
            else:
                out[flag] = None
                out[flag + "_source"] = "unknown"
        if best is not None:
            out["_history"] = self._linear_history(best[0], addr, best[1], best[2])
        return out

    def _linear_history(self, start, addr, m, x):
        """start から addr の直前までを線形に読んだ命令 (新しい順)。"""
        hist = []
        p = start
        state = W.WidthState(self.ctx, None, None)
        state.value = {"m": m, "x": x}
        while p < addr and len(hist) < 64:
            state.enter(p)
            ins = self.decode(p, state.value["m"], state.value["x"])
            if ins is None:
                break
            ins = dict(ins)
            ins["m"], ins["x"] = state.value["m"], state.value["x"]
            state.leave(ins)
            hist.insert(0, ins)
            p += ins["size"]
        return hist

    def site_check(self, addr):
        """addr が命令の先頭として妥当か (CDL の境界 / 同期の票)。"""
        kind, info = self.cdl_boundary(addr)
        if kind == "start":
            return {"boundary": "cdl_instruction_start", "boundary_ok": True,
                    "cdl": info["cdl"], "executed": self.ctx.in_code_run(addr)}
        if kind == "inside":
            return {"boundary": "inside_cdl_instruction", "boundary_ok": False,
                    "cdl": info["cdl"], "inside": info["inside"],
                    "inside_text": info["inside_text"],
                    "executed": False}
        if self.ctx.in_read_run(addr) and not self.ctx.in_code_run(addr):
            return {"boundary": "cdl_data", "boundary_ok": False, "cdl": None,
                    "executed": False,
                    "why": "CDL ではデータとして読まれただけの番地"}
        lc = self.linear_context(addr)
        span = self.ctx.span_at(addr)
        if lc["ratio"] >= 0.75:
            ok = True
        elif lc["ratio"] < 0.35:
            ok = False
        else:
            ok = None
        out = {"boundary": "not_in_cdl", "boundary_ok": ok,
               "cdl": span[4] if span else None, "executed": False,
               "sync": lc["votes"], "sync_ratio": lc["ratio"]}
        if self.ctx.has_cdl and (addr >> 16) not in self.code_banks():
            # ★データでも線形デコードは同期する (どんなバイト列も何かの命令になる)。
            #   実行された命令が 1 つも無いバンクでは、同期の票は「コードらしさ」の
            #   根拠にならないので、妥当とは言わない。
            out["boundary_ok"] = None if ok is not False else False
            out["why"] = ("このバンクには CDL で実行された命令が 1 つも無い "
                          "(データの可能性が高い。同期の票はデータでも高く出る)")
        return out

    def code_banks(self):
        """CDL で実行された命令があるバンクの集合。"""
        got = getattr(self, "_code_banks", None)
        if got is None:
            got = set()
            for start, end in self.ctx.code_runs:
                for b in range(start >> 16, (end >> 16) + 1):
                    got.add(b)
            for span in self.ctx.spans:
                got.add(span[0] >> 16)
            self._code_banks = got
        return got

    def site_widths(self, addr, deep=False):
        """addr を実行するときの (m, x, 出どころ)。CDL → 同期の推定。

        deep=True なら、それでも決まらないときに addr を含む処理の入口を推定し、
        その入口から辿ったときの幅を使います (1 段だけ。入口推定の中からは使わない)。
        """
        span = self.ctx.span_at(addr)
        if span is not None and span[4] in _CERTAIN_CDL and None not in (span[2], span[3]):
            return span[2], span[3], "cdl_" + span[4]
        lc = self.linear_context(addr)
        if lc.get("m") is not None and lc.get("x") is not None and lc["ratio"] >= 0.35:
            return lc["m"], lc["x"], "sync"
        if deep and not self._deep:
            self._deep = True
            try:
                reg, _ent = self.containing_region(addr)
            except ValueError:
                reg = None
            finally:
                self._deep = False
            node = reg.nodes.get(addr) if reg is not None else None
            if (node is not None and node.ms not in FLOW_UNCERTAIN
                    and node.xs not in FLOW_UNCERTAIN):
                return node.m, node.x, "caller_region"
        return None, None, None

    # --- 呼び出し元の列挙 -----------------------------------------------------------
    def _dispatch_sites(self, bank_start, data):
        """バンク内の JMP/JSR (abs,X) 候補を {表の番地: [命令の番地]} で返します。"""
        got = self._dispatch.get(bank_start)
        if got is not None:
            return got
        out = {}
        for opc in (0x7C, 0xFC):
            pos = data.find(bytes([opc]))
            while pos >= 0:
                if pos + 2 < len(data):
                    pb = (bank_start + pos) & 0xFF0000
                    base = pb | data[pos + 1] | (data[pos + 2] << 8)
                    out.setdefault(self.ctx.canonical_rom(base), []).append(
                        bank_start + pos)
                pos = data.find(bytes([opc]), pos + 1)
        self._dispatch[bank_start] = out
        return out

    def find_calls_to(self, target, kinds=None, check=True):
        """target を呼ぶ・飛ぶ命令をバイト列から全部拾い、境界の妥当性を付けます。"""
        target = self.ctx.canonical_rom(target)
        lo16 = target & 0xFFFF
        tbank = target >> 16
        want = set(kinds or ("jsl", "jml", "jsr", "jmp", "brl", "branch",
                             "push_return", "table"))
        hits = []
        for start, data in self.image.parts:
            end = start + len(data) - 1
            # JSR / JMP / BRL / Bcc / 表は**同じバンク**の中だけ (PC のバンクは変わらない)。
            same_bank = (start >> 16) <= tbank <= (end >> 16)
            pats = []
            if "jsl" in want:
                pats.append((0x22, "jsl", 4))
            if "jml" in want:
                pats.append((0x5C, "jml", 4))
            if same_bank and "jsr" in want:
                pats.append((0x20, "jsr", 3))
            if same_bank and "jmp" in want:
                pats.append((0x4C, "jmp", 3))
            for opc, kind, size in pats:
                needle = bytes([opc, lo16 & 0xFF, lo16 >> 8])
                pos = data.find(needle)
                while pos >= 0:
                    site = start + pos
                    if size == 4:
                        ok = (pos + 3 < len(data) and self.ctx.canonical_rom(
                            (data[pos + 3] << 16) | lo16) == target)
                    else:
                        ok = (site >> 16) == tbank
                    if ok:
                        hits.append({"site": site, "kind": kind})
                    pos = data.find(needle, pos + 1)
            if not same_bank:
                continue
            if "push_return" in want:
                ret = (lo16 - 1) & 0xFFFF
                needle = bytes([0xF4, ret & 0xFF, ret >> 8])
                pos = data.find(needle)
                while pos >= 0:
                    if ((start + pos) >> 16) == tbank:
                        hits.append({"site": start + pos, "kind": "push_return"})
                    pos = data.find(needle, pos + 1)
            if "brl" in want:
                pos = data.find(b"\x82")
                while pos >= 0:
                    if pos + 2 < len(data):
                        rel = data[pos + 1] | (data[pos + 2] << 8)
                        if rel >= 0x8000:
                            rel -= 0x10000
                        site = start + pos
                        if (site >> 16) == tbank and _next(site, 3 + rel) == target:
                            hits.append({"site": site, "kind": "brl"})
                    pos = data.find(b"\x82", pos + 1)
            if "branch" in want:
                for site in range(max(start, target - 129), min(target + 127, start + len(data) - 1)):
                    opc = data[site - start]
                    if opc not in _BRANCH_OPS or site + 1 - start >= len(data):
                        continue
                    rel = data[site + 1 - start]
                    if rel >= 0x80:
                        rel -= 0x100
                    if _next(site, 2 + rel) == target:
                        hits.append({"site": site, "kind": "bra" if opc == 0x80 else "branch",
                                     "op": _BRANCH_OPS[opc]})
            if "table" in want:
                dispatch = self._dispatch_sites(start, data)
                needle = bytes([lo16 & 0xFF, lo16 >> 8])
                pos = data.find(needle)
                while pos >= 0:
                    slot = start + pos
                    if (slot >> 16) != tbank:
                        pos = data.find(needle, pos + 1)
                        continue
                    for tbase in range(max(start, slot - 510), slot + 1):
                        if (slot - tbase) % 2 or tbase not in dispatch:
                            continue
                        for site in dispatch[tbase]:
                            hits.append({"site": site, "kind": "table",
                                         "table": tbase, "slot": slot,
                                         "index": (slot - tbase) // 2})
                    pos = data.find(needle, pos + 1)
        out = []
        seen = set()
        for hit in sorted(hits, key=lambda h: (h["site"], h["kind"])):
            key = (hit["site"], hit["kind"], hit.get("slot"))
            if key in seen:
                continue
            seen.add(key)
            row = self._call_row(hit, target, check)
            if row is not None:
                out.append(row)
        return out

    def _call_row(self, hit, target, check):
        """find_calls_to の 1 件を組み立てます。表は展開して実際に含まれるか確かめます。"""
        site = hit["site"]
        row = {"site": _h(site), "site_bus": _bus(site), "kind": hit["kind"]}
        widths = None
        if check:
            row.update(self.site_check(site))
        if hit["kind"] == "table":
            m, x, src = self.site_widths(site)
            ins = self.decode(site, m if m is not None else 1, x if x is not None else 1)
            if ins is None:
                return None
            row["kind"] = "jsr_table" if ins["mnemonic"] == "JSR" else "jmp_table"
            lc = self.linear_context(site)
            tbl = self.expand_table(site, ins, lc.get("_history") or [],
                                    m if m is not None else 1, x if x is not None else 1)
            row["text"] = ins["text"]
            row["table"] = _h(hit["table"])
            row["slot"] = _h(hit["slot"])
            row["index"] = hit["index"]
            row["within_expanded_table"] = hit["index"] < tbl["count"]
            row["table_count"] = tbl["count"]
            row["table_count_is_estimated"] = tbl["count_is_estimated"]
            row["table_stop_reason"] = tbl["stop_reason"]
            row["observed"] = target in tbl["_observed"]
            if not row["within_expanded_table"]:
                row["note"] = ("表の展開範囲 ({0} 件) の外の位置に一致しました。"
                               "偶然の一致か、表の終端推定が短すぎます。".format(tbl["count"]))
            widths = (m, x, src)
        else:
            m, x, src = self.site_widths(site)
            ins = self.decode(site, m if m is not None else 1, x if x is not None else 1)
            row["text"] = ins["text"] if ins else "?"
            widths = (m, x, src)
            if hit["kind"] == "push_return":
                row["note"] = ("PEA で「戻り先 - 1」を積んでいます。RTS/RTL で飛ぶ慣用の"
                               "ことが多いですが、ただの定数の可能性もあります。")
        if widths[0] is not None:
            row["widths"] = "m{0}x{1}".format(widths[0], widths[1])
            row["widths_source"] = widths[2]
        return row

    # --- 入口の推定 -----------------------------------------------------------
    def find_entry(self, addr, max_back=0x800, max_candidates=20):
        """addr を含む処理の入口を推定します (確度つき。断定しない)。"""
        cache_key = (addr, self._deep)
        cached = self._entry_cache.get(cache_key)
        if cached is not None:
            return cached
        loc = self.image.locate(addr)
        if loc is None:
            raise ValueError("{0} はイメージの外です。".format(_bus(addr)))
        data, base = loc
        lo = max(base, addr - max_back)
        cands = {}

        def add(c, why):
            if lo <= c <= addr:
                cands.setdefault(c, set()).add(why)

        add(addr, "address_itself")
        i = bisect.bisect_right(self._known_sorted, addr) - 1
        n = 0
        while i >= 0 and n < 4 and self._known_sorted[i] >= lo:
            e = self._known_sorted[i]
            add(e, "ghidra_function" if e in self.names else "cdl_call_target")
            i -= 1
            n += 1
        term = 0
        p = addr - 1
        while p >= lo and term < 24:
            b = data[p - base]
            if b in (0x60, 0x6B, 0x40):
                add(p + 1, "after_" + {0x60: "rts", 0x6B: "rtl", 0x40: "rti"}[b])
                term += 1
            if p - 1 >= lo and data[p - 1 - base] == 0x80:
                add(p + 1, "after_bra")
            if p - 2 >= lo and data[p - 2 - base] in (0x4C, 0x82):
                add(p + 1, "after_jmp" if data[p - 2 - base] == 0x4C else "after_brl")
            if p - 3 >= lo and data[p - 3 - base] == 0x5C:
                add(p + 1, "after_jml")
            p -= 1

        ordered = sorted(cands, reverse=True)
        evaluated = []
        for c in ordered:
            if len(evaluated) >= max_candidates:
                break
            ev = self._evaluate_entry(c, cands[c], addr)
            if ev is None:
                continue
            evaluated.append(ev)
            if ev["covers"] and ev["score"] >= 6:
                break
        covering = [e for e in evaluated if e["covers"]]
        chosen = None
        if covering:
            chosen = max(covering, key=lambda e: (e["score"], e["_c"]))
        out = {"address": _h(addr), "address_bus": _bus(addr)}
        if chosen is None:
            out.update({"entry": None, "confidence": "low",
                        "note": "後方 0x{0:x} バイトの候補のどれから辿っても {1} に届き"
                                "ませんでした。コードではない (データ) か、間接ジャンプの"
                                "先かもしれません。".format(max_back, _bus(addr))})
        else:
            score = chosen["score"]
            conf = "high" if score >= 6 else ("medium" if score >= 3 else "low")
            out.update({
                "entry": _h(chosen["_c"]), "entry_bus": _bus(chosen["_c"]),
                "is_entry": chosen["_c"] == addr,
                "offset_from_entry": addr - chosen["_c"],
                "confidence": conf,
                "entry_widths": chosen["widths"],
                "evidence": chosen["evidence"],
                "callers": chosen["callers"][:12],
                "callers_total": chosen["callers_total"],
                "covers_address": True,
                "region": chosen["region"],
            })
        out["candidates"] = [{k: v for k, v in e.items() if not k.startswith("_")}
                             for e in evaluated]
        out["_chosen"] = chosen
        self._entry_cache[cache_key] = out
        return out

    def _evaluate_entry(self, c, why, addr):
        """入口候補 c を評価します (呼び出し元・幅・到達・不自然な命令)。"""
        evidence = sorted(why)
        if why & {"after_rts", "after_rtl", "after_rti", "after_bra", "after_jmp",
                  "after_brl", "after_jml"} and not why & {"ghidra_function",
                                                           "cdl_call_target"}:
            # 終端命令がほんとうに命令か (オペランドの 60 / 6B ではないか)。
            prev_ok = False
            for back in (1, 2, 3, 4):
                p = c - back
                if self.image.byte(p) is None:
                    continue
                chk = self.site_check(p)
                if chk.get("boundary_ok"):
                    ins = self.decode(p, 1, 1)
                    if ins and _next(p, ins["size"]) == c and ins["flow"] in ("return", "jump"):
                        prev_ok = True
                        break
            if not prev_ok and "address_itself" not in why:
                return None
        callers = self.find_calls_to(c, kinds=("jsl", "jml", "jsr", "jmp", "table",
                                                "push_return"))
        callers = [r for r in callers if r.get("boundary_ok") is not False
                   and r.get("within_expanded_table", True)]
        uniq = {}
        for r in callers:
            uniq.setdefault(r["site"], r)
        callers = list(uniq.values())
        if not self._deep:
            # CDL でも同期でも幅が決まらない呼び出し元は、その呼び出し元を含む処理を
            # 辿って幅を求める (1 段だけ)。
            for r in callers:
                if r.get("widths"):
                    continue
                m_, x_, src_ = self.site_widths(int(r["site"], 16), deep=True)
                if m_ is not None:
                    r["widths"] = "m{0}x{1}".format(m_, x_)
                    r["widths_source"] = src_
        labels = [r for r in self.find_calls_to(c, kinds=("branch", "brl"))
                  if r.get("boundary_ok")]
        # 入口の幅: CDL → 呼び出し元の幅の多数決 → 4 通り試す。
        cm, cx, cms, cxs = self.entry_widths(c)
        tries = []
        if cm is not None and cx is not None:
            tries.append((cm, cx, cms, cxs, "cdl"))
        else:
            seen = {}
            for r in callers:
                if r.get("widths"):
                    seen.setdefault(r["widths"], []).append(r["site_bus"])
            if seen:
                best = max(seen.items(), key=lambda kv: len(kv[1]))[0]
                tries.append((int(best[1]), int(best[3]), "caller", "caller", "callers"))
                for w in seen:
                    if w != best:
                        tries.append((int(w[1]), int(w[3]), "caller", "caller", "callers_minority"))
            for m, x in ((1, 1), (0, 0), (1, 0), (0, 1)):
                if (cm is None or cm == m) and (cx is None or cx == x):
                    tries.append((m, x, cms or "assumed", cxs or "assumed", "tried"))
        result = None
        for m, x, ms, xs, how in tries:
            reg = self.region(c, m, x, ms, xs)
            if reg is None:
                continue
            covers = addr in reg.nodes
            bad = len(reg.suspicious) + 3 * self._cdl_conflicts(reg)
            item = (covers, -bad, how in ("cdl", "callers"), m, x, ms, xs, how, reg)
            if result is None or item[:3] > result[:3]:
                result = item
            if covers and bad == 0 and how in ("cdl", "callers"):
                break
        if result is None:
            return None
        covers, negbad, _pref, m, x, ms, xs, how, reg = result
        score = 0
        if callers:
            score += 4
            evidence.append("呼び出し元 {0} 件".format(len(callers)))
        if why & {"ghidra_function"}:
            score += 2
        if why & {"cdl_call_target"}:
            score += 3
        if why & {"after_rts", "after_rtl", "after_rti", "after_jmp", "after_jml",
                  "after_bra", "after_brl"}:
            score += 1
        first = reg.nodes.get(c)
        if first and first.ins["mnemonic"] in ("PHP", "PHB", "PHD", "REP", "SEP",
                                                "PHA", "PHX", "PHY", "PHK"):
            score += 1
            evidence.append("先頭が {0}".format(first.ins["mnemonic"]))
        if labels and not callers:
            score -= 2
            evidence.append("分岐の飛び先 ({0} 件) = 関数の途中のラベルかもしれない".format(
                len(labels)))
        score += negbad if negbad > -6 else -6
        if negbad:
            evidence.append("不自然な命令 / CDL との矛盾 {0}".format(-negbad))
        if how in ("tried",) and not callers:
            evidence.append("入口の幅は推測 (呼び出し元も CDL も無い)")
        widths = {"m": m, "x": x, "m_source": ms, "x_source": xs, "how": how}
        if how.startswith("callers"):
            widths["callers_widths"] = sorted({r.get("widths") for r in callers
                                               if r.get("widths")})
        return {"candidate": _h(c), "candidate_bus": _bus(c), "covers": covers,
                "score": score, "evidence": evidence, "widths": widths,
                "callers": [{k: r[k] for k in ("site", "site_bus", "kind", "text")
                             if k in r} for r in callers],
                "callers_total": len(callers),
                "region": reg.summary(), "_c": c, "_reg": reg}

    def _cdl_conflicts(self, reg):
        """リージョンの命令のうち、CDL の命令の途中に当たるものの数。"""
        bad = 0
        for addr in reg.nodes:
            kind, _info = self.cdl_boundary(addr)
            if kind == "inside":
                bad += 1
        return bad

    def containing_region(self, addr):
        """addr を含む処理のリージョン (入口推定 → その入口から辿る)。"""
        ent = self.find_entry(addr)
        chosen = ent.get("_chosen")
        if chosen is None:
            return None, ent
        return chosen["_reg"], ent

    # --- データフロー -----------------------------------------------------------
    @staticmethod
    def _solve(reg, init, transfer, meet):
        """前向きのデータフロー (作業リスト)。IN を返します。"""
        IN = {reg.entry: init}
        OUT = {}
        work = [reg.entry]
        while work:
            a = work.pop()
            node = reg.nodes.get(a)
            if node is None:
                continue
            out = transfer(node, IN[a])
            if a in OUT and OUT[a] == out:
                continue
            OUT[a] = out
            for s in node.succ:
                if s not in reg.nodes:
                    continue
                cur = IN.get(s)
                new = out if cur is None else meet(cur, out)
                if new != cur:
                    IN[s] = new
                    work.append(s)
        return IN, OUT

    # ---- メモリ (引数の書き込み) ----
    def _regs(self, ins, m, x, regs):
        """A/X/Y の定数伝搬 (分からなければ None)。regs = (Alo, Ahi, Xlo, Xhi, Ylo, Yhi)。"""
        alo, ahi, xlo, xhi, ylo, yhi = regs
        name, mode, op = ins["mnemonic"], ins["mode"], ins.get("operand")
        imm = mode in ("immM", "immX")
        if name == "LDA":
            if imm:
                alo = op & 0xFF
                if not m:
                    ahi = (op >> 8) & 0xFF
            else:
                alo = None
                if not m:
                    ahi = None
        elif name in ("LDX", "LDY"):
            lo_, hi_ = (op & 0xFF, 0 if x else (op >> 8) & 0xFF) if imm else (None, 0 if x else None)
            if name == "LDX":
                xlo, xhi = lo_, hi_
            else:
                ylo, yhi = lo_, hi_
        elif name in ("TAX", "TAY"):
            lo_, hi_ = alo, (0 if x else ahi)
            if name == "TAX":
                xlo, xhi = lo_, hi_
            else:
                ylo, yhi = lo_, hi_
        elif name in ("TXA", "TYA"):
            src = (xlo, xhi) if name == "TXA" else (ylo, yhi)
            alo = src[0]
            if not m:
                ahi = src[1]
        elif name == "TXY":
            ylo, yhi = xlo, (0 if x else xhi)
        elif name == "TYX":
            xlo, xhi = ylo, (0 if x else yhi)
        elif name == "XBA":
            alo, ahi = ahi, alo
        elif name in ("INX", "DEX", "INY", "DEY"):
            lo_, hi_ = (xlo, xhi) if name in ("INX", "DEX") else (ylo, yhi)
            if lo_ is not None and hi_ is not None:
                v = (lo_ | (hi_ << 8)) + (1 if name.startswith("IN") else -1)
                v &= 0xFF if x else 0xFFFF
                lo_, hi_ = v & 0xFF, v >> 8
            else:
                lo_, hi_ = None, (0 if x else None)
            if name in ("INX", "DEX"):
                xlo, xhi = lo_, hi_
            else:
                ylo, yhi = lo_, hi_
        elif name in ("AND", "ORA", "EOR") and mode == "immM":
            f = {"AND": lambda a, b: a & b, "ORA": lambda a, b: a | b,
                 "EOR": lambda a, b: a ^ b}[name]
            alo = f(alo, op & 0xFF) if alo is not None else (0 if name == "AND" and not op & 0xFF else None)
            if not m:
                hb = (op >> 8) & 0xFF
                ahi = f(ahi, hb) if ahi is not None else (0 if name == "AND" and not hb else None)
        elif name in ("INC", "DEC") and mode == "acc":
            if alo is not None and (m or ahi is not None):
                v = alo | ((ahi or 0) << 8)
                v = (v + (1 if name == "INC" else -1)) & (0xFF if m else 0xFFFF)
                alo = v & 0xFF
                if not m:
                    ahi = v >> 8
            else:
                alo = None
                if not m:
                    ahi = None
        elif name in ("ADC", "SBC", "AND", "ORA", "EOR", "PLA") or (
                name in _A_RMW_ACC and mode == "acc"):
            alo = None
            if not m:
                ahi = None
        elif name in ("TDC", "TSC"):
            alo = ahi = None
        elif name in ("PLX", "TSX"):
            xlo, xhi = None, (0 if x else None)
        elif name == "PLY":
            ylo, yhi = None, (0 if x else None)
        elif name == "SEP" and op is not None and op & W.PS_X:
            xhi = yhi = 0
        elif name in ("MVN", "MVP"):
            alo = ahi = xlo = xhi = ylo = yhi = None
        return (alo, ahi, xlo, xhi, ylo, yhi)

    def _store_values(self, ins, regs):
        """書き込み命令が書く値 [下位, 上位] (分からなければ None)。"""
        name = ins["mnemonic"]
        if name == "STZ":
            return [0, 0]
        if name == "STA":
            return [regs[0], regs[1]]
        if name == "STX":
            return [regs[2], regs[3]]
        if name == "STY":
            return [regs[4], regs[5]]
        return None

    def _mem_transfer(self, node, st, watch, depth, risks, live=None):
        """メモリ書き込みのデータフローの 1 命令ぶん。"""
        regs, must_t, may = st
        must = {k: (v, d) for k, v, d in must_t}
        may = set(may)
        ins = node.ins
        name = ins["mnemonic"]
        refs = W.operand_refs(ins, node.m, node.x, self.ctx)
        vals = self._store_values(ins, regs)
        for ref in refs:
            if ref.get("pointer"):
                if ref.get("target_access") in ("W", "RW"):
                    risks.add(("indirect", node.addr, None, ()))
                continue
            if ref["access"] not in ("W", "RW"):
                continue
            size = ref.get("size") or 1
            if ref["indexed"]:
                # 8bit 添字で届く範囲は indexed、16bit 添字 (x=0) なら届くかもしれない
                # 範囲 (目安 0x7FF) は indexed_far。後者は「書いたかもしれない」の
                # 一覧には出すが、引数の推定を弱める根拠には使わない (広すぎるため)。
                for w in watch:
                    if ref["ea"] <= w <= ref["ea"] + 0xFF + size - 1:
                        risks.add(("indexed", node.addr, w, ()))
                    elif not node.x and ref["ea"] <= w <= ref["ea"] + 0x7FF + size - 1:
                        risks.add(("indexed_far", node.addr, w, ()))
                continue
            for k in range(size):
                a = ref["ea"] + k
                if a in watch:
                    v = None
                    if ref["access"] == "W" and vals is not None:
                        v = vals[k] if k < len(vals) else None
                    must[a] = (UNK if v is None else v, (node.addr,))
                    may.add(a)
        if name in ("MVN", "MVP"):
            risks.add(("block_move", node.addr, None, ()))
        if node.calls and live is not None and node.addr not in live:
            return ((None,) * 6, tuple(sorted((k, v, d) for k, (v, d) in must.items())),
                    frozenset(may))
        if node.calls:
            sums = []
            missing = False
            for t, cm, cx, _cms, _cxs, _kind in node.calls:
                if not self.can_return(t, cm, cx):
                    continue
                s = self.mem_summary(t, cm, cx, watch, depth + 1)
                if s is None:
                    missing = True
                    risks.add(("callee_not_analyzed", node.addr, None, (t,)))
                else:
                    sums.append(s)
            if sums and not missing:
                common = None
                for s in sums:
                    keys = set(s["must"])
                    common = keys if common is None else (common & keys)
                for k in common or ():
                    vs = {s["must"][k] for s in sums}
                    must[k] = (vs.pop() if len(vs) == 1 else UNK, (node.addr,))
            for s in sums:
                may |= s["may"]
                for kind, at, w, via in s["risks"]:
                    risks.add((kind, at, w, (node.addr,) + via[:3]))
            regs = (None,) * 6
        else:
            regs = self._regs(ins, node.m, node.x, regs)
        return (regs, tuple(sorted((k, v, d) for k, (v, d) in must.items())),
                frozenset(may))

    @staticmethod
    def _mem_meet(a, b):
        regs = tuple(p if p == q else None for p, q in zip(a[0], b[0]))
        ma = {k: (v, d) for k, v, d in a[1]}
        mb = {k: (v, d) for k, v, d in b[1]}
        must = []
        for k in sorted(set(ma) & set(mb)):
            va, da = ma[k]
            vb, db = mb[k]
            must.append((k, va if va == vb else UNK, tuple(sorted(set(da) | set(db)))))
        return (regs, tuple(must), a[2] | b[2])

    def mem_dataflow(self, reg, watch, depth=0, live=None):
        """リージョンの各命令の「直前」の状態 (IN) と、見つかった危険を返します。"""
        watch = frozenset(watch)
        risks = set()
        init = ((None,) * 6, (), frozenset())
        IN, _OUT = self._solve(
            reg, init, lambda n, s: self._mem_transfer(n, s, watch, depth, risks, live),
            self._mem_meet)
        return IN, risks

    def mem_summary(self, entry, m, x, watch, depth):
        """呼び出し先が watch の番地に何を書くかの要約。深すぎる / 再帰なら None。"""
        key = (entry, m, x, frozenset(watch))
        if depth > MEM_DEPTH:
            self._summary_cut()
            return None
        got, started = self._summary_begin(self._msum, key)
        if not started:
            return got
        out = None
        try:
            out = self._mem_summary(entry, m, x, watch, depth)
        finally:
            self._summary_end(self._msum, key, out)
        return out

    def _mem_summary(self, entry, m, x, watch, depth):
        """mem_summary の本体。"""
        reg = self.region(entry, m, x)
        if reg is None:
            return None
        IN, risks = self.mem_dataflow(reg, watch, depth, self.live_nodes(reg))
        exits = []
        exit_nodes = set()
        may = set()
        for ret in reg.returns:
            if ret[0] in IN:
                exits.append({k: v for k, v, _d in IN[ret[0]][1]})
                exit_nodes.add(ret[0])
                may |= IN[ret[0]][2]
        for call in reg.calls:
            node = reg.nodes.get(call["site"])
            if call["kind"] == "tail" and node is not None and node.addr in IN:
                if not self.can_return(call["target"], node.m, node.x):
                    continue
                s = self.mem_summary(call["target"], node.m, node.x, watch, depth + 1)
                if s is None:
                    risks.add(("callee_not_analyzed", node.addr, None, (call["target"],)))
                    exits.append({})
                    exit_nodes.add(node.addr)
                    may |= IN[node.addr][2]
                elif s["returns"]:
                    base = {k: v for k, v, _d in IN[node.addr][1]}
                    base.update(s["must"])
                    exits.append(base)
                    exit_nodes.add(node.addr)
                    may |= IN[node.addr][2] | s["may"]
                    for kind, at, w, via in s["risks"]:
                        risks.add((kind, at, w, (node.addr,) + via[:3]))
        # ★戻らない経路 (ソフトリセット・無限ループ) の書き込みは、呼び出し元から見て
        #   「呼んだ後の状態」に関係しないので数えない。
        live = set(exit_nodes)
        preds = reg.preds()
        stack = list(exit_nodes)
        while stack:
            a = stack.pop()
            for p in preds.get(a, ()):
                if p not in live:
                    live.add(p)
                    stack.append(p)
        risks = {r for r in risks if (r[3][0] if r[3] else r[1]) in live}
        must = {}
        if exits:
            keys = set(exits[0])
            for e in exits[1:]:
                keys &= set(e)
            for k in keys:
                vs = {e[k] for e in exits}
                must[k] = vs.pop() if len(vs) == 1 else UNK
        return {"must": must, "may": frozenset(may), "risks": frozenset(risks),
                "returns": bool(exit_nodes)}

    # ---- A の上位バイトの出どころ ----
    # 状態 = (lo, hi, xf, stk)
    #   lo / hi  A の下位 / 上位バイトを最後に設定した命令の集合 (出どころ)。
    #            出どころ = (命令の番地, 呼び出しの連なり, 種類)。種類は
    #            "8" / "16" (値は実行時) / "8c" / "16c" (即値などで値が決まっている) /
    #            "S" (どこで積んだか分からないスタックから戻した) /
    #            "EL" / "EH" (関数の入口の値) / "U" (解析できなかった呼び出し)。
    #   xf       XBA で上位から下位へ持ってきた「よその値」 (使ったら報告)。
    #   stk      スタックに積んだバイトの出どころ (PHA で積み PLA で戻す)。
    #            PHA ... PLA で A を保存しているだけの処理を「使った」と数えないため。
    #            高さが合流で食い違ったら None (分からない)。
    def _a_transfer(self, node, st, depth, report, live=None):
        """A の各バイトの出どころを 1 命令ぶん進めます。"""
        lo, hi, xf, stk, ls = st
        ins = node.ins
        name, mode, op = ins["mnemonic"], ins["mode"], ins.get("operand")
        m, x = node.m, node.x
        # --- 使用の検査 (状態を進める前) ---
        if report is not None:
            if _uses_hi16(ins, m, x) and _mixed(lo, hi):
                report(node, "mixed_16bit_use", lo, hi, None)
            if xf and _uses_lo8(ins, m, x):
                report(node, "xba_stale_high", lo, xf, None)
        if node.calls:
            if node.calls[0][5] in ("tail", "jmp_table"):
                return st
            if live is not None and node.addr not in live:
                return (frozenset(), frozenset(), frozenset(), stk, None)
            here = node.addr
            out_lo, out_hi = set(), set()
            ok = True
            alive = False
            for t, cm, cx, _ms, _xs, kind in node.calls:
                if not self.can_return(t, cm, cx):
                    continue                  # 戻ってこない呼び出し先は後ろに影響しない
                alive = True
                s = self.a_summary(t, cm, cx, depth + 1)
                if s is None:
                    ok = False
                    break
                if report is not None and s["uses_hi"] and _mixed(lo, hi):
                    report(node, "call_consumes_high", lo, hi, (t, s["uses_hi"]))
                out_lo |= _subst(s["lo"], node.addr, lo, hi)
                out_hi |= _subst(s["hi"], node.addr, lo, hi)
            if not ok:
                unk = frozenset({(node.addr, (node.addr,), "U")})
                return (unk, unk, frozenset(), stk, here)
            if not alive:
                return (frozenset(), frozenset(), frozenset(), stk, None)
            return (_cap(out_lo), _cap(out_hi), frozenset(), stk, here)
        here = node.addr
        imm = mode in ("immM", "immX")
        # --- スタック ---
        if name == "PHA":
            return (lo, hi, xf, _push(stk, (lo,) if m else (hi, lo)), ls)
        if name == "PLA":
            if m:
                stk, got = _pop(stk, 1, here, "8")
                return (got[0], hi, frozenset(), stk, here)
            stk, got = _pop(stk, 2, here, "16")
            return (got[0], got[1], frozenset(), stk, here)
        if name in ("PHP", "PHB", "PHK"):
            return (lo, hi, xf, _push(stk, (_OPAQUE,)), ls)
        if name in ("PLP", "PLB"):
            return (lo, hi, xf, _pop(stk, 1, here, "8")[0], ls)
        if name in ("PHD", "PEA", "PEI", "PER"):
            return (lo, hi, xf, _push(stk, (_OPAQUE, _OPAQUE)), ls)
        if name == "PLD":
            return (lo, hi, xf, _pop(stk, 2, here, "16")[0], ls)
        if name in ("PHX", "PHY"):
            return (lo, hi, xf, _push(stk, (_OPAQUE,) * (1 if x else 2)), ls)
        if name in ("PLX", "PLY"):
            return (lo, hi, xf, _pop(stk, 1 if x else 2, here, "8")[0], ls)
        if name in ("TCS", "TXS"):
            stk = None
        # --- A ---
        if name == "LDA" and imm:
            if m:
                return (frozenset({(here, (), "8c")}), hi, frozenset(), stk, here)
            t = frozenset({(here, (), "16c")})
            return (t, t, frozenset(), stk, here)
        if name in ("LDA", "TXA", "TYA"):
            if m:
                return (frozenset({(here, (), "8")}), hi, frozenset(), stk, here)
            t = frozenset({(here, (), "16")})
            return (t, t, frozenset(), stk, here)
        if name in ("TDC", "TSC", "MVN", "MVP"):
            t = frozenset({(here, (), "16")})
            return (t, t, frozenset(), stk, here)
        if name == "XBA":
            moved = frozenset()
            if any(not _local(t) for t in hi) and lo and all(_local(t) for t in lo):
                moved = frozenset(t for t in hi if not _local(t))
            return (hi, lo, moved, stk, here)
        if name in _A_ARITH or (name in _A_RMW_ACC and mode == "acc"):
            new_lo = frozenset({(here, (), "8" if m else "16")})
            new_hi = hi
            if not m:
                hb = ((op or 0) >> 8) & 0xFF
                if name == "AND" and imm and hb == 0:
                    new_hi = frozenset({(here, (), "16c")})       # 上位を 0 にした
                elif name == "ORA" and imm and hb == 0xFF:
                    new_hi = frozenset({(here, (), "16c")})
                elif name in ("ASL", "ROL"):
                    new_hi = _cap(hi | lo)
            return (new_lo, new_hi, frozenset(), stk, here)
        if stk is not st[3]:
            return (lo, hi, xf, stk, ls)
        return st

    @staticmethod
    def _a_meet(a, b):
        if a[3] is None or b[3] is None or len(a[3]) != len(b[3]):
            stk = None
        else:
            stk = tuple(_cap(p | q, 16) for p, q in zip(a[3], b[3]))
        return (_cap(a[0] | b[0]), _cap(a[1] | b[1]), a[2] | b[2], stk,
                a[4] if a[4] == b[4] else None)

    def a_summary(self, entry, m, x, depth):
        """呼び出し先の A の要約: 戻ったときの各バイトの出どころと、入口の上位バイトを
        値として使う命令 (uses_hi)。深すぎる / 再帰なら None。"""
        key = (entry, m, x)
        if depth > MAX_DEPTH:
            self._summary_cut()
            return None
        got, started = self._summary_begin(self._asum, key)
        if not started:
            return got
        out = None
        try:
            out = self._a_summary(entry, m, x, depth)
        finally:
            self._summary_end(self._asum, key, out)
        return out

    def _a_summary(self, entry, m, x, depth):
        """a_summary の本体。"""
        reg = self.region(entry, m, x, depth=depth)
        if reg is None:
            return None
        uses = []
        live = self.live_nodes(reg)
        IN, _OUT = self._solve(reg, _A_INIT,
                               lambda n, s: self._a_transfer(n, s, depth, None, live),
                               self._a_meet)
        out_lo, out_hi = set(), set()
        for ret in reg.returns:
            st = IN.get(ret[0])
            if st is not None:
                out_lo |= st[0]
                out_hi |= st[1]
        for call in reg.calls:
            if call["kind"] not in ("tail", "jmp_table"):
                continue
            node = reg.nodes.get(call["site"])
            st = IN.get(call["site"])
            if node is None or st is None:
                continue
            if not self.can_return(call["target"], node.m, node.x):
                continue
            s = self.a_summary(call["target"], node.m, node.x, depth + 1)
            if s is None:
                unk = (node.addr, (node.addr,), "U")
                out_lo.add(unk)
                out_hi.add(unk)
                continue
            out_lo |= _subst(s["lo"], node.addr, st[0], st[1])
            out_hi |= _subst(s["hi"], node.addr, st[0], st[1])
            if s["uses_hi"] and any(t[2] == "EH" for t in st[1]):
                uses.append(s["uses_hi"][0])
        # 入口の上位バイト (EH) を値として使う命令。
        for addr, node in reg.nodes.items():
            st = IN.get(addr)
            if st is None:
                continue
            eh = any(t[2] == "EH" for t in st[1])
            if eh and _uses_hi16(node.ins, node.m, node.x):
                uses.append((addr, node.ins["text"]))
            if (node.calls and eh and addr in live
                    and node.calls[0][5] not in ("tail", "jmp_table")):
                for t, cm, cx, _ms, _xs, _k in node.calls:
                    if not self.can_return(t, cm, cx):
                        continue
                    s = self.a_summary(t, cm, cx, depth + 1)
                    if s and s["uses_hi"]:
                        uses.append(s["uses_hi"][0])
        return {"lo": _cap(frozenset(out_lo)), "hi": _cap(frozenset(out_hi)),
                "uses_hi": sorted(set(uses))[:4]}

    def lint_region(self, reg, findings):
        """1 リージョンを A の上位バイトの持ち越しで検査し、findings に足します。"""
        def report(node, kind, lo, hi, extra):
            key = (node.addr, kind)
            if key in findings:
                return
            findings[key] = {"node": node, "kind": kind, "lo": lo, "hi": hi,
                             "extra": extra, "entry": reg.entry,
                             "lo_site": state[0][4] if state else None}

        IN, _OUT = self._solve(reg, _A_INIT,
                               lambda n, s: self._a_transfer(n, s, 0, None),
                               self._a_meet)
        state = [None]
        for addr, node in reg.nodes.items():
            st = IN.get(addr)
            if st is not None:
                state[0] = st
                self._a_transfer(node, st, 0, report)

    # --- 到達経路 -----------------------------------------------------------
    def find_path(self, src, dst, m=None, x=None, max_regions=6000,
                  max_instructions=1500000):
        """src から dst へ (JSR/JSL・表・末尾ジャンプを辿って) 届くかを幅優先で探します。"""
        reg0, (mv, xv, ms, xs) = self.region_for(src, m, x)
        from collections import deque
        start = (src, mv, xv)
        parent = {start: None}
        srcs = {start: (ms, xs)}
        queue = deque([start])
        explored = 0
        insns = 0
        unresolved = []
        found = None
        while queue:
            key = queue.popleft()
            ms_, xs_ = srcs[key]
            reg = self.region(key[0], key[1], key[2], ms_, xs_)
            if reg is None:
                continue
            explored += 1
            insns += len(reg.nodes)
            for u in reg.unresolved:
                if len(unresolved) < 40:
                    unresolved.append((u, reg.entry))
            if dst in reg.nodes:
                found = key
                break
            if explored >= max_regions or insns >= max_instructions:
                break
            for call in reg.calls:
                node = reg.nodes[call["site"]]
                child = (call["target"], node.m, node.x)
                if child in parent:
                    continue
                parent[child] = (key, call)
                srcs[child] = ("caller" if node.ms not in FLOW_UNCERTAIN else node.ms,
                               "caller" if node.xs not in FLOW_UNCERTAIN else node.xs)
                queue.append(child)
        out = {"source": _h(src), "source_bus": _bus(src),
               "target": _h(dst), "target_bus": _bus(dst),
               "source_widths": "m{0}x{1} ({2}/{3})".format(mv, xv, ms, xs),
               "regions_explored": explored, "instructions_explored": insns,
               "budget_exhausted": found is None and bool(queue)}
        if found is None:
            out["reachable"] = None
            out["unresolved_indirect"] = [
                {"site": _h(a), "site_bus": _bus(a), "text": self.text_at(a),
                 "in_function": _bus(e)} for a, e in unresolved]
            return out
        hops = []
        cur = found
        while parent[cur] is not None:
            prev, call = parent[cur]
            hop = {"from_function": _h(prev[0]), "from_function_bus": _bus(prev[0]),
                   "site": _h(call["site"]), "site_bus": _bus(call["site"]),
                   "text": call["text"], "kind": call["kind"],
                   "to": _h(call["target"]), "to_bus": _bus(call["target"]),
                   "widths": "m{0}x{1}".format(call["m"], call["x"])}
            if "index" in call:
                hop["table_index"] = call["index"]
                hop["observed_by_cdl"] = call.get("observed")
            if self.name_of(prev[0]):
                hop["from_name"] = self.name_of(prev[0])
            hop["site_executed"] = self.ctx.in_code_run(call["site"])
            hops.append(hop)
            cur = prev
        hops.reverse()
        reg = self.region(found[0], found[1], found[2])
        node = reg.nodes[dst]
        out["reachable"] = True
        out["path"] = hops
        out["final"] = {"function": _h(found[0]), "function_bus": _bus(found[0]),
                        "reaches": _h(dst), "text": node.ins["text"],
                        "widths": "m{0}x{1}".format(node.m, node.x),
                        "width_uncertain": node.uncertain,
                        "executed": self.ctx.in_code_run(dst)}
        out["hops"] = len(hops)
        return out


# --- 補助 -------------------------------------------------------------------
def _uses_hi16(ins, m, x):
    """この命令が A の上位バイトを**値として使う**か (16bit で積む / 書く / 比べる / 移す)。

    ADC / ORA / EOR などは上位バイトを素通しで次へ渡すだけなので「使用」にしない
    (その値を最後に使う命令で検出する。同じ所見が何度も出ないように)。
    PHA も使用にしない (PLA で戻したあとに使えば、そこで検出する。保存だけなら誤検出)。
    AND #$00xx / BIT #$00xx は上位を 0 にする・見ないだけなので使用ではない。
    """
    name, mode = ins["mnemonic"], ins["mode"]
    if name in ("TCD", "TCS"):
        return True
    if name in ("TAX", "TAY"):
        return not x
    if m:
        return False
    if name in ("STA", "CMP"):
        return True
    if name in ("BIT", "AND"):
        if mode == "immM":
            return ((ins.get("operand") or 0) >> 8) != 0
        return name == "BIT"
    return False


def _uses_lo8(ins, m, x):
    """XBA で持ってきた下位バイトを使う命令か (8bit)。"""
    name = ins["mnemonic"]
    if name in ("TAX", "TAY"):
        return bool(x)
    return bool(m) and name in _A_USES


_OPAQUE = frozenset()
_A_INIT = (frozenset({(-1, (), "EL")}), frozenset({(-1, (), "EH")}), frozenset(), (), None)


def _push(stk, items):
    """スタックに出どころを積みます (items は下から順)。高さは 32 バイトまで。"""
    if stk is None:
        return None
    return (stk + tuple(items))[-32:]


def _pop(stk, n, here, kind):
    """スタックから n バイト戻します。(新しいスタック, [下位, 上位...])。

    どこで積んだか分からない (入口より前 / 高さ不明 / 他の命令が積んだ) バイトは
    この命令で作った値とみなします (種類 kind = "8" / "16")。
    """
    got = []
    unknown = frozenset({(here, (), kind)})
    for _i in range(n):
        if stk:
            top = stk[-1]
            stk = stk[:-1]
            got.append(top if top else unknown)
        else:
            got.append(unknown)
    return stk, got


def _local(tok):
    """このリージョンの中で定義した値か (呼び出し経由でも入口でもない)。"""
    return not tok[1] and tok[2] not in ("EL", "EH", "U")


def _severity(hi_tokens):
    """上位バイトの出どころ (よそから来たもの) から重要度を決めます。

    high   = 呼び出し先で、実行時の値 (メモリ・入力・計算結果) を入れたもの
    medium = 関数の入口の値 (呼び出し元次第) / 解析できなかった呼び出し
    low    = 呼び出し先が即値 / AND #$00FF などで決まった値にしたものだけ
    """
    kinds = {t[2] for t in hi_tokens}
    if any(t[1] and t[2] in ("8", "16") for t in hi_tokens):
        return "high"
    if kinds & {"EL", "EH", "U"}:
        return "medium"
    return "low"


def _mixed(lo, hi):
    """下位は**この処理が 8bit で**作ったのに、上位はよそ (呼び出し先 / 入口) から来ている。

    下位が 16bit の演算 (ORA $mem など) の結果なら、A は 16bit の値として扱われている
    ので対象外 (呼び出し先の 16bit の戻り値をそのまま加工しているだけ)。
    """
    if not lo or not hi:
        return False
    return (all(_local(t) for t in lo) and any(t[2] in ("8", "8c") for t in lo)
            and any(not _local(t) for t in hi))


def _cap(tokens, limit=48):
    """出どころの集合が大きくなりすぎないよう、決まった順で上限をかけます。"""
    tokens = frozenset(tokens)
    if len(tokens) <= limit:
        return tokens
    return frozenset(sorted(tokens, key=lambda t: (len(t[1]), t[0], t[1], t[2]))[:limit])


def _subst(tokens, site, lo, hi):
    """呼び出し先の要約の出どころを、呼び出し元の言葉に直します。"""
    out = set()
    for tok in tokens:
        if tok[2] == "EL":
            out |= lo
        elif tok[2] == "EH":
            out |= hi
        else:
            out.add((tok[0], ((site,) + tok[1])[:5], tok[2]))
    return frozenset(out)


def _index_bound(back):
    """JSR/JMP (abs,X) の直前の命令から、添字の範囲 (表の件数) を読み取ります。

    back は新しい順。TAX の前で A を作る形 (LDA → AND #k → ASL → TAX) と、
    CMP #n + BCS の形を見ます。CMP の形だけを「確定 (decisive)」とします
    (AND は上限でしかない)。
    """
    shifts = 0
    saw_tax = False
    guard = None
    mask = None
    cmp_n = None
    source = None
    how = []
    for n in back:
        ins = n.ins if isinstance(n, Node) else n
        name, mode, op = ins["mnemonic"], ins["mode"], ins.get("operand")
        if ins.get("flow") in ("call", "call_reg", "jump", "jump_reg", "return"):
            break
        if not saw_tax:
            if name in ("TAX",):
                saw_tax = True
                how.append("TAX")
                continue
            if name in ("BCS", "BCC", "BPL", "BMI"):
                guard = name
                continue
            if name == "CPX" and mode == "immX" and guard in ("BCS", "BCC"):
                cmp_n = op
                how.append("CPX #${0:X} / {1}".format(op, guard))
                return {"count": max(1, op // 2), "decisive": True,
                        "how": ", ".join(reversed(how)), "index_source": "X"}
            if name in ("LDX", "PLX", "TYX", "TSX"):
                refs = W.operand_refs(ins, 1, 1)
                if refs:
                    source = _bus(refs[0]["ea"])
                break
            if name in W._CLOBBERS["X"]:
                break
            continue
        if name == "ASL" and mode == "acc":
            shifts += 1
            how.append("ASL A")
            continue
        if name in ("BCS", "BCC", "BPL", "BMI"):
            guard = name
            continue
        if name == "AND" and mode == "immM" and mask is None:
            mask = op
            how.append("AND #${0:X}".format(op))
            continue
        if name == "CMP" and mode == "immM" and guard in ("BCS", "BCC") and cmp_n is None:
            cmp_n = op
            how.append("CMP #${0:X} / {1}".format(op, guard))
            continue
        if name == "LDA":
            refs = W.operand_refs(ins, 1, 1)
            if refs and refs[0].get("pointer"):
                # LDA [$0F] など: 添字はポインタの先 (実行時) から来る。
                source = "{0} (ポインタ ${1:02X} の先)".format(ins["text"], refs[0]["ea"] & 0xFF)
            elif refs:
                source = _bus(refs[0]["ea"])
            how.append(ins["text"])
            break
        if name in W._CLOBBERS["A"]:
            break
    if not saw_tax:
        return None
    out = {"how": ", ".join(reversed(how)), "shifts": shifts}
    if source:
        out["index_source"] = source
    if cmp_n is not None:
        count = cmp_n if shifts >= 1 else max(1, cmp_n // 2)
        out.update({"count": max(1, count), "decisive": True})
    elif mask is not None:
        count = (mask + 1) if shifts >= 1 else (mask // 2 + 1)
        out.update({"count": max(1, min(256, count)), "decisive": False})
    else:
        out["decisive"] = False
    return out


# =============================================================================
# MCP から呼ばれる入口 (w65816.py がフックとして公開する)
# =============================================================================
def make_analyzer(image, context, entries=None):
    """BusImage と WidthContext から解析器を作ります。"""
    return Analyzer(image, context, entries)


def _clean(obj):
    """先頭が _ のキー (内部用) を落とします。"""
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items() if not str(k).startswith("_")}
    if isinstance(obj, list):
        return [_clean(v) for v in obj]
    return obj


CALLS_NOTE = (
    "バイト列から JSL/JML (long)、JSR/JMP (同じバンクの abs)、BRL/BRA/Bcc (相対)、"
    "PEA (戻り先-1 を積む慣用)、JSR/JMP (abs,X) の表の中身 を拾っています。"
    "CDL の外も対象です。各件の boundary が命令の先頭として妥当かの印です: "
    "cdl_instruction_start = CDL が記録した命令の先頭 (確実) / "
    "inside_cdl_instruction = CDL の命令の途中 (**偶然の一致**) / "
    "cdl_data = CDL がデータとして読んだ場所 (偶然の一致) / "
    "not_in_cdl = CDL 外。sync はその手前を色々な位置・幅から読み直して "
    "その番地に着地した割合 (高いほど命令の先頭らしい。**推定**)。"
    "executed は CDL で実行が記録されているか。")

CALLS_BLIND_SPOTS = (
    "JMP ($abs) / JML [$abs] / JSL・JML を RAM のポインタ経由で呼ぶ形 "
    "(飛び先は実行時に決まる)。",
    "LDA 表,X / PHA / RTS のように、表から作った番地を積んで RTS/RTL で飛ぶ形。",
    "表の終端推定より後ろの位置 (table_slots_outside_expanded に件数だけ出る)。",
    "バンクの異なるミラー ($00-$3F) から JSR する形 (Program に無いミラーは読んでいない)。",
)


def find_calls_to_hook(analyzer, target, kinds=None, include_branches=True,
                       limit=200):
    """find_calls_to の本体。"""
    an = analyzer
    tgt = an.ctx.canonical_rom(W.parse_bus_address(target))
    want = list(kinds or ("jsl", "jml", "jsr", "jmp", "brl", "branch",
                          "push_return", "table"))
    if not include_branches:
        want = [k for k in want if k not in ("branch", "brl")]
    rows = an.find_calls_to(tgt, kinds=want)
    outside = [r for r in rows if r.get("within_expanded_table") is False]
    rows = [r for r in rows if r.get("within_expanded_table") is not False]
    by_kind = {}
    for r in rows:
        by_kind[r["kind"]] = by_kind.get(r["kind"], 0) + 1
    ok = sum(1 for r in rows if r.get("boundary_ok") is True)
    bad = sum(1 for r in rows if r.get("boundary_ok") is False)
    out = {
        "target": _h(tgt), "target_bus": _bus(tgt),
        "target_executed": an.ctx.in_code_run(tgt),
        "total": len(rows), "returned": min(len(rows), limit),
        "by_kind": by_kind,
        "boundary_ok": ok, "boundary_rejected": bad,
        "boundary_unclear": len(rows) - ok - bad,
        "calls": rows[:limit],
        "table_slots_outside_expanded": len(outside),
        "note": CALLS_NOTE,
    }
    if not rows:
        out["hint"] = {"message": "0 件でした。**「誰も呼んでいない」と結論する前に**"
                                  "下を疑ってください。",
                       "blind_spots": list(CALLS_BLIND_SPOTS)}
    else:
        out["blind_spots"] = list(CALLS_BLIND_SPOTS)
    return out


def find_function_entry_hook(data, base_addr, big_endian, target, analyzer=None):
    """find_function_entry の本体 (65816)。"""
    if analyzer is None:
        raise ValueError("65816 の find_function_entry には解析器が要ります (MCP の不具合)。")
    got = analyzer.find_entry(analyzer.ctx.canonical_rom(target))
    out = _clean(dict(got))
    out["note"] = (
        "**推定です。** 後ろ向きに RTS/RTL/RTI/JMP/BRA の直後、既知の入口 (functions.json / "
        "CDL の呼び出し先) を候補にし、呼び出し元の有無・入口の幅 (CDL → 呼び出し元の "
        "幅 → 4 通り試す)・その入口から分岐を辿って指定番地に届くか・不自然な命令 / CDL "
        "との矛盾が無いか、で点を付けています。entry_widths.how が tried なら入口の幅は推測。"
        "candidates に他の候補と点数があります。")
    out["balanced"] = None
    return out


def expand_switch_hook(data, base_addr, big_endian, target, read_word=None,
                       analyzer=None):
    """expand_switch の本体 (65816): JSR (abs,X) / JMP (abs,X) の表を展開します。"""
    an = analyzer
    if an is None:
        raise ValueError("65816 の expand_switch には解析器が要ります (MCP の不具合)。")
    site = an.ctx.canonical_rom(target)
    m, x, src = an.site_widths(site)
    found = None
    p = site
    for _i in range(8):
        ins = an.decode(p, m if m is not None else 1, x if x is not None else 1)
        if ins is None:
            break
        if ins["mode"] == "iax":
            found = (p, ins)
            break
        if ins["flow"] in ("return", "jump", "jump_reg"):
            break
        p = _next(p, ins["size"])
        mm, xx, ss = an.site_widths(p)
        if mm is not None:
            m, x, src = mm, xx, ss
    if found is None:
        raise ValueError(
            "{0} (とその直後) は JSR ($abs,X) / JMP ($abs,X) ではありません。"
            "表の展開は表を引く命令の番地に対して行ってください "
            "(JMP ($abs) / JML [$abs] は RAM のポインタなので展開できません)。".format(
                _bus(site)))
    p, ins = found
    if m is None:
        m, x, src = an.site_widths(p)
    lc = an.linear_context(p)
    tbl = an.expand_table(p, ins, lc.get("_history") or [],
                          m if m is not None else 1, x if x is not None else 1)
    out = _clean(tbl)
    out["address"] = _h(p)
    out["entries_declared"] = (tbl["index_bound"] or {}).get("count")
    out["widths_source"] = src or "assumed (読めなかった)"
    out["note"] = (
        "表の件数は直前の命令 (CMP #n + BCS/BCC なら確定、AND #k は上限) と、"
        "表の終端の推定 (CDL がコードと記録した番地 / ROM 外を指す値 / 不自然な飛び先で止める) "
        "で決めています。count_is_estimated=true なら推定。observed は CDL に "
        "「この命令から呼ばれた」と記録がある飛び先。entry_widths は飛び先の入口の幅 "
        "(= この命令を実行するときの M/X)。")
    return out


def find_path_hook(analyzer, source, target, m=None, x=None, max_regions=6000):
    """find_path の本体。"""
    an = analyzer
    src = an.ctx.canonical_rom(W.parse_bus_address(source))
    dst = an.ctx.canonical_rom(W.parse_bus_address(target))
    out = an.find_path(src, dst, m, x, max_regions=max_regions)
    out["note"] = (
        "src の入口から、分岐・JSR/JSL・JSR/JMP (abs,X) の表 (展開して全部)・"
        "既知の入口への JMP/JML・PEA で積んだ戻り先 (CDL がコードと記録したもの) を幅優先で"
        "辿りました。path は呼び出しの連なり、final は最後の関数の中で target に届いた命令。"
        "M/X は呼び出し元から運んでいます (CDL があればそちら)。**静的な経路**なので、"
        "実行時にその分岐を通る条件が成り立つかは別問題です。")
    if not out.get("reachable"):
        out["hint"] = {
            "message": "経路が見つかりませんでした。**「届かない」とは言えません。**",
            "blind_spots": [
                "unresolved_indirect の間接ジャンプ (JMP ($abs) / JML [$abs] / RAM の"
                "ポインタ経由) の先は辿っていない。",
                "NMI / IRQ からの経路、LDA 表,X / PHA / RTS の形の分岐。",
                "budget_exhausted=true なら探索の上限で打ち切った。",
                "target が命令の先頭でない (命令の途中) と見つからない。",
            ]}
    return out


def _tok_desc(an, tok):
    """A の出どころ 1 件を人間向けに。"""
    if tok[2] in ("EL", "EH"):
        return {"from": "関数の入口 (呼び出し元が入れた値)"}
    if tok[2] == "U":
        return {"from": "解析できなかった呼び出し", "site": _bus(tok[0])}
    out = {"def": _h(tok[0]), "bus": _bus(tok[0]), "text": an.text_at(tok[0]),
           "width": "16bit" if tok[2].startswith("16") else "8bit"}
    if tok[2].endswith("c"):
        out["constant"] = True
    if tok[1]:
        out["via"] = ["{0} {1}".format(_bus(s), an.text_at(s)) for s in tok[1]]
    return out


def lint_regions(an, max_regions=8000):
    """既知の入口 (functions.json / CDL) と、そこから呼ばれる先のリージョン全部。"""
    seen = set()
    queue = []
    for e in sorted(an.known):
        if not an.image.has(e):
            continue
        reg, _w = an.region_for(e)
        if reg is not None and (reg.entry, reg.m, reg.x) not in seen:
            seen.add((reg.entry, reg.m, reg.x))
            queue.append(reg)
    i = 0
    while i < len(queue) and len(queue) < max_regions:
        reg = queue[i]
        i += 1
        for call in reg.calls:
            node = reg.nodes[call["site"]]
            key = (call["target"], node.m, node.x)
            if key in seen:
                continue
            seen.add(key)
            child = an.region(call["target"], node.m, node.x,
                              "caller" if node.ms not in FLOW_UNCERTAIN else node.ms,
                              "caller" if node.xs not in FLOW_UNCERTAIN else node.xs)
            if child is not None:
                queue.append(child)
    return queue


def lint_stale_register_hook(analyzer, function=None, start=None, end=None,
                             min_severity="high", limit=100, max_regions=8000):
    """lint_stale_register の本体 (65816: A の上位バイト B の持ち越し)。"""
    an = analyzer
    lo = an.ctx.canonical_rom(W.parse_bus_address(start)) if start else None
    hi = an.ctx.canonical_rom(W.parse_bus_address(end)) if end else None
    order = {"high": 3, "medium": 2, "low": 1}
    if min_severity not in order:
        raise ValueError("min_severity は high / medium / low で指定してください。")
    findings = {}
    if function:
        entry = an.ctx.canonical_rom(W.parse_bus_address(function))
        reg, _w = an.region_for(entry)
        regions = [reg] if reg is not None else []
    else:
        regions = lint_regions(an, max_regions)
    for reg in regions:
        an.lint_region(reg, findings)
    rows = []
    sev_count = {"high": 0, "medium": 0, "low": 0}
    for (addr, kind), f in sorted(findings.items()):
        if lo is not None and addr < lo:
            continue
        if hi is not None and addr > hi:
            continue
        hi_toks = [t for t in f["hi"] if not _local(t)]
        severity = _severity(hi_toks)
        sev_count[severity] += 1
        if order[severity] < order[min_severity]:
            continue
        node = f["node"]
        lo_defs = sorted(t[0] for t in f["lo"] if _local(t))
        row = {"use": _h(addr), "use_bus": _bus(addr), "text": node.ins["text"],
               "kind": kind, "severity": severity,
               "function": _h(f["entry"]), "function_bus": _bus(f["entry"]),
               "widths": "m{0}x{1}".format(node.m, node.x)}
        if node.uncertain or node.ms in FLOW_UNCERTAIN:
            row["width_uncertain"] = True
        if lo_defs:
            first = f.get("lo_site") or min(lo_defs)
            row["range"] = "{0}-{1:04X}".format(_bus(first), addr & 0xFFFF)
            if f.get("lo_site") and f["lo_site"] not in lo_defs:
                row["low_byte_set_at"] = "{0} {1}".format(_bus(f["lo_site"]),
                                                          an.text_at(f["lo_site"]))
            row["low_byte_from"] = [_tok_desc(an, t) for t in sorted(f["lo"])
                                    if _local(t)][:4]
        cands = sorted(hi_toks, key=lambda t: (t[2] in ("EL", "EH", "U"),
                                               t[2] != "16",
                                               -len(t[1]), t[0], t[1]))
        row["high_byte_candidates"] = [_tok_desc(an, t) for t in cands[:12]]
        row["high_byte_candidates_total"] = len(cands)
        if f["extra"]:
            callee, uses = f["extra"]
            row["callee"] = _bus(callee)
            row["callee_uses_high_byte_at"] = ["{0} {1}".format(_bus(a), t)
                                               for a, t in uses]
        rows.append(row)
    total = len(rows)
    return {
        "scope": ("function " + _bus(an.ctx.canonical_rom(W.parse_bus_address(function)))
                  if function else "known entries + their callees"),
        "regions_analyzed": len(regions),
        "min_severity": min_severity,
        "severity_counts": sev_count,
        "total": total,
        "returned": min(total, limit),
        "findings": rows[:limit],
        "note": (
            "A の上位バイト (B) が「この処理で作った下位バイト」と組で 16bit として使われる"
            "箇所を探しています。kind: mixed_16bit_use = 下位はこの処理で 8bit で作ったのに"
            "上位は呼び出し先 / 入口から来た値のまま 16bit で PHA/STA/CMP/TAX(x=0) 等に使う / "
            "call_consumes_high = 同じ状態で、入口の上位バイトを 16bit で使う処理を呼ぶ / "
            "xba_stale_high = 上位を XBA で下位へ持ってきて使う。"
            "severity=high は上位バイトが呼び出し先で最後に設定された実行時の値 "
            "(high_byte_candidates の via が経路)、medium は関数の入口の値 (呼び出し元次第) か"
            "解析できなかった呼び出し、low は呼び出し先が即値 / AND #$00FF などで決まった値に"
            "したものだけ (意図した戻り値のことが多い)。min_severity で下げると出る。"
            "PHA ... PLA の保存は辿っているので、A を保存するだけの処理は使用に数えない。"
            "**候補は静的に辿った全経路の和**で、どれが実際に残るかは実行時次第。"
            "呼び出し先が意図して A を返している場合は誤検出です。"),
    }


WRITERS_BYTES_NOTE = (
    "scan_basis=bytes: CDL を使わず、バイト列の全域から書き込み命令 (STA/STX/STY/STZ と "
    "INC/DEC/ASL/LSR/ROL/ROR/TSB/TRB の dp / abs / long、各 ,X ,Y) を拾っています。"
    "各候補の executed は CDL で実行の記録があるか、boundary / boundary_ok は命令の先頭と"
    "して妥当か (CDL の命令の途中・CDL がデータとして読んだ場所なら偶然の一致として "
    "boundary_rejected へ)、width / width_certainty は 8bit/16bit とその確からしさ "
    "(cdl = CDL の記録、inferred = 手前の REP/SEP から推定、unknown = 決まらない)。"
    "target の 1 つ手前への書き込みは 16bit のときだけ target を上位バイトとして覆うので、"
    "8bit と分かったものは not_covering に、幅が分からないものは writers に "
    "covers=上位バイト (16bit のときだけ) で出します。found_by_cdl_scan=false が、"
    "scan_basis=cdl では拾えなかった候補です。,X / ,Y 付きは基底番地が 0xFF 以内のものだけ "
    "offset_writers に出し、それより遠い (16bit 添字なら届くかもしれない) ものは "
    "offset_writers_far に件数だけ出します (index_reach を渡すとその距離まで一覧に出る)。")


def writers_by_bytes(an, data, base_addr, target, trace_imm=16, index_reach=None):
    """find_writers(scan_basis="bytes") の 1 ブロックぶん。"""
    tgt = W.canonical_query(target, an.ctx)
    buckets = {"writers": [], "offset": [], "not_covering": [], "rejected": [],
               "rejected_indexed": []}
    far = 0
    for mt in _WRITE_RE.finditer(data):
        pos = mt.start()
        addr = base_addr + pos
        ins = W.decode_at(data, pos, addr, 1, 1)
        if ins.get("truncated"):
            continue
        for ref in W.operand_refs(ins, 1, 1, an.ctx):
            if ref.get("pointer") or ref["access"] not in ("W", "RW"):
                continue
            ea = ref["ea"]
            if ref["indexed"]:
                if not ea <= tgt <= ea + 0x800:
                    continue
                if index_reach is None and tgt - ea > 0xFF:
                    # 16bit 添字なら届くかもしれない遠い基底番地。全域走査では
                    # 数百件になるので件数だけ (index_reach を渡せば一覧に出る)。
                    far += 1
                    continue
                if index_reach is not None and tgt - ea > int(index_reach) + 1:
                    continue
            elif ea not in (tgt, tgt - 1):
                continue
            row = _bytes_writer_row(an, ins, ref, tgt, trace_imm, index_reach)
            if row is not None:
                bucket = row.pop("_bucket")
                if bucket == "rejected" and row.get("indexed_candidate"):
                    bucket = "rejected_indexed"
                buckets[bucket].append(row)
    return {"pools": [], "writers": buckets["writers"],
            "offset_writers": buckets["offset"],
            "readers": [], "unresolved": [], "max_scan_reached": 0,
            "not_covering": buckets["not_covering"],
            "boundary_rejected": buckets["rejected"],
            "boundary_rejected_indexed": len(buckets["rejected_indexed"]),
            "offset_writers_far": far,
            "target_canonical": _h(tgt), "scan_basis": "bytes"}


def _bytes_writer_row(an, ins, ref, tgt, trace_imm, index_reach):
    """バイト列で拾った書き込み候補 1 件を検証して行にします。"""
    addr = ins["addr"]
    chk = an.site_check(addr)
    name = ins["mnemonic"]
    flag = "x" if name in W._X_WIDTH_OPS else "m"
    idx, other_idx = (2, 3) if flag == "m" else (3, 2)
    span = an.ctx.span_at(addr)
    width = None
    certainty = "unknown"
    why = None
    other = None
    lc = None
    if span is not None and span[4] in _CERTAIN_CDL and span[idx] is not None:
        width = 8 if span[idx] else 16
        certainty = "cdl"
        why = "CDL ({0})".format(span[4])
        other = span[other_idx]
    else:
        lc = an.linear_context(addr)
        if lc.get(flag) is not None:
            width = 8 if lc[flag] else 16
            certainty = "inferred"
            why = "{0} の {1} から (同期 {2})".format(
                "CDL 区間" if lc[flag + "_source"] == "cdl" else "REP/SEP",
                _bus(int(lc[flag + "_from"], 16)), lc["votes"])
        other = lc.get("x" if flag == "m" else "m")
    row = {"addr": _h(addr), "bus": _bus(addr), "text": ins["text"], "op": name,
           "form": ref["form"], "access": ref["access"], "ea": _h(ref["ea"]),
           "width": width, "width_certainty": certainty}
    if why:
        row["width_why"] = why
    if ref["assumptions"]:
        row["assumptions"] = list(ref["assumptions"])
    row.update(chk)
    row["found_by_cdl_scan"] = span is not None
    if ref["indexed"]:
        row["indexed_candidate"] = True
    if chk.get("boundary_ok") is False:
        row["_bucket"] = "rejected"
        return row
    row.pop("indexed_candidate", None)
    ea = ref["ea"]
    if ref["indexed"]:
        # 添字の幅が 16bit と分かっているときだけ 0x7FF まで (scan_basis=cdl と同じ目安)。
        # 分からなければ 8bit の 0xFF (データをコードと読んだ偶然の一致で埋まらないように)。
        reach = int(index_reach) if index_reach is not None else 0xFF
        if not ea <= tgt <= ea + reach + (2 if width == 16 else 1) - 1:
            return None
        row["indexed"] = True
        row["index_offset"] = tgt - ea
        row["index_reach"] = reach
        row["_bucket"] = "offset"
        return row
    if ea == tgt - 1:
        if width == 8:
            row["covers"] = "覆わない (8bit)"
            row["_bucket"] = "not_covering"
            return row
        row["covers"] = "上位バイト" if width == 16 else "上位バイト (16bit のときだけ)"
    elif width == 16:
        row["covers"] = "下位バイト"
    if name == "STZ":
        row["value"] = 0
        row["writes_zero"] = True
    elif name in W._STORE_REG:
        hist = (lc or an.linear_context(addr)).get("_history") or []
        src, why_v = W._trace_value(hist, W._STORE_REG[name], max(1, int(trace_imm)))
        if src is not None:
            row["value"] = src["operand"]
            row["value_hex"] = src["operands"]
            row["value_from"] = "{0} @ {1}".format(src["text"], _bus(src["addr"]))
            row["writes_zero"] = src["operand"] == 0
        else:
            row["value"] = None
            row["value_note"] = why_v
    else:
        row["value"] = None
    if certainty != "cdl":
        row["width_uncertain"] = True
    row["_bucket"] = "writers"
    return row


MEMORY_ARGS_NOTE = (
    "target を呼ぶ箇所 (find_calls_to の JSL/JSR/JML/JMP/表) ごとに、その呼び出しを含む"
    "処理の入口 (find_function_entry の推定) から分岐を辿り、呼ぶ直前までに各番地を"
    "書いたかをデータフローで調べています。途中で呼んだ処理 (JSL 等) の中の直接の"
    "書き込みも数えます。status: written = 全経路で書いた (value は全経路で同じ値のときだけ) / "
    "partially_written = 一部の経路だけ / not_written = どの経路でも直接は書いていない "
    "(= この処理より外から来た値のまま) / unknown = 呼び出し元を辿れなかった。"
    "could_be_written_by は間接 (STA [dp],Y 等)・添字付き・ブロック転送・解析できなかった"
    "呼び出しで、**その番地に書いているかもしれない**命令 (静的には否定できない)。")


def list_memory_args_hook(analyzer, target, args=None, limit=200,
                          include_weak=False):
    """list_memory_args の本体。"""
    an = analyzer
    tgt = an.ctx.canonical_rom(W.parse_bus_address(target))
    callers = an.find_calls_to(tgt, kinds=("jsl", "jml", "jsr", "jmp", "table",
                                           "push_return"))
    callers = [c for c in callers if c.get("boundary_ok") is not False
               and c.get("within_expanded_table", True)]
    uniq = {}
    for c in callers:
        uniq.setdefault((c["site"], c["kind"]), c)
    callers = list(uniq.values())
    callers_found = len(callers)
    # 呼び出し元ごとに入口を推定して辿るので (1 件 1 秒前後)、limit 件までにする。
    callers = callers[:max(1, int(limit))]
    # --- 呼び出し元を含む処理を先に推定する (その幅が target の入口の幅になる) ---
    located = []
    for c in callers:
        site = int(c["site"], 16)
        try:
            creg, ent = an.containing_region(site)
        except ValueError as exc:
            creg, ent = None, {"note": str(exc)}
        located.append((c, creg, ent))
    # --- target の入口の幅 (CDL → 呼び出し元を辿ったときの幅の多数決) ---
    cm, cx, cms, cxs = an.entry_widths(tgt)
    widths_votes = {}
    if cm is None or cx is None:
        for c, creg, _ent in located:
            node = creg.nodes.get(int(c["site"], 16)) if creg is not None else None
            if node is not None and node.ms not in FLOW_UNCERTAIN \
                    and node.xs not in FLOW_UNCERTAIN:
                widths_votes.setdefault((node.m, node.x), []).append(c["site_bus"])
            else:
                m_, x_, _src = an.site_widths(int(c["site"], 16))
                if m_ is not None:
                    widths_votes.setdefault((m_, x_), []).append(c["site_bus"] + " (sync)")
        if widths_votes:
            best = max(widths_votes.items(), key=lambda kv: len(kv[1]))[0]
            if cm is None:
                cm, cms = best[0], "caller"
            if cx is None:
                cx, cxs = best[1], "caller"
    reg = an.region(tgt, 1 if cm is None else cm, 1 if cx is None else cx,
                    cms or "assumed", cxs or "assumed")
    if reg is None:
        raise ValueError("{0} を辿れませんでした。".format(_bus(tgt)))
    # --- 引数とみなす番地 ---
    arg_rows = []
    if args:
        if isinstance(args, str):
            args = [a for a in args.replace(",", " ").split() if a]
        for text in args:
            a = W.canonical_query(W.parse_bus_address(text), an.ctx)
            arg_rows.append({"addr": a, "source": "given", "weak": False})
    else:
        reads = {}
        for node in reg.nodes.values():
            for ref in W.operand_refs(node.ins, node.m, node.x, an.ctx):
                if ref.get("pointer") or ref["indexed"] or ref["access"] not in ("R", "RW"):
                    continue
                if not 0x7E0000 <= ref["ea"] <= 0x7FFFFF:
                    continue
                size = ref.get("size") or 1
                for k in range(size):
                    reads.setdefault(ref["ea"] + k, []).append((node.addr, k > 0))
        IN, risks = an.mem_dataflow(reg, set(reads))
        preds = reg.preds()
        back_cache = {}

        def before(at):
            """at より前に実行されうる命令の集合。"""
            got = back_cache.get(at)
            if got is None:
                got = set()
                stack = list(preds.get(at, ()))
                while stack:
                    p = stack.pop()
                    if p not in got:
                        got.add(p)
                        stack.extend(preds.get(p, ()))
                back_cache[at] = got
            return got

        for a, uses in sorted(reads.items()):
            exposed = [(at, weak) for at, weak in uses
                       if at in IN and a not in {k for k, _v, _d in IN[at][1]}]
            if not exposed:
                continue
            strong = [at for at, weak in exposed if not weak]
            first = min(strong or [at for at, _w in exposed])
            row = {"addr": a, "source": "read_before_write",
                   "weak": not strong, "first_read": first}
            # 読む前に、添字付き / ブロック転送で書いているかもしれない命令がある
            # (例: 呼び出し先が作業用の記録を STA $7F4400,X で丸ごと写す)。
            # target 自身か、target が直接呼ぶ処理の中のものだけを根拠にする
            # (深い所の STA $0862,X まで数えると、本物の引数まで弱く見えるため)。
            prior = before(first)
            for kind, at, w, via in sorted(risks, key=lambda r: (r[1], r[0], r[3])):
                here = via[0] if via else at
                if len(via) > 1:
                    continue
                if here in prior and (kind == "block_move" or (kind == "indexed" and w == a)):
                    row["weak"] = True
                    row["weak_reason"] = "{0} {1} ({2}{3}) が先に書いているかもしれない".format(
                        _bus(at), an.text_at(at), kind,
                        " via " + " → ".join(_bus(v) for v in via) if via else "")
                    break
            if not strong and "weak_reason" not in row:
                row["weak_reason"] = "16bit 読みの上位バイトとしてしか読んでいない"
            arg_rows.append(row)
        if not include_weak:
            arg_rows = [r for r in arg_rows if not r["weak"]]
    watch = frozenset(r["addr"] for r in arg_rows)
    # --- 呼び出し元ごと ---
    caller_rows = []
    for c, creg, ent in located:
        caller_rows.append(_memory_args_caller(an, c, watch, creg, ent))
    # --- まとめ ---
    missing = {}
    stats = {}
    for r in caller_rows:
        for a, cell in r["args"].items():
            s = stats.setdefault(a, {"written": 0, "partially_written": 0,
                                     "not_written": 0, "unknown": 0})
            s[cell["status"]] += 1
            if cell["status"] in ("not_written", "partially_written"):
                missing.setdefault(a, []).append(r["site_bus"])
    suspicious = []
    for a, s in sorted(stats.items()):
        if s["written"] and (s["not_written"] or s["partially_written"]):
            suspicious.append({"arg": a, "written_by": s["written"],
                               "missing_in": missing.get(a, [])})
    out = {
        "target": _h(tgt), "target_bus": _bus(tgt),
        "target_widths": "m{0}x{1}".format(reg.m, reg.x),
        "target_widths_source": "{0}/{1}".format(reg.ms, reg.xs),
        "target_widths_votes": {"m{0}x{1}".format(*k): v
                                for k, v in widths_votes.items()},
        "args": [{"addr": _bus(r["addr"]), "source": r["source"],
                  "first_read": _bus(r["first_read"]) if r.get("first_read") else None,
                  "first_read_text": (an.text_at(r["first_read"])
                                      if r.get("first_read") else None),
                  "weak": r["weak"], "weak_reason": r.get("weak_reason"),
                  "callers": stats.get(_bus(r["addr"]))}
                 for r in arg_rows],
        "callers_total": callers_found,
        "returned": len(caller_rows),
        "callers": caller_rows,
        "callers_not_writing": missing,
        "suspicious": suspicious,
        "note": MEMORY_ARGS_NOTE,
    }
    if not args:
        out["args_note"] = (
            "args 省略時は、target から分岐を辿って (呼び出し先の書き込みも数えて) "
            "**書く前に読む** WRAM 番地を引数とみなしています (直接番地だけ。,X / 間接は除く)。"
            "大域変数 (入力やフレームカウンタ) も混ざるので、suspicious "
            "(書く呼び出し元と書かない呼び出し元が混在する番地) から見てください。"
            "weak (16bit 読みの上位バイトだけ / 読む前に呼び出し先が添字付き・ブロック転送で"
            "書いているかもしれないもの) は include_weak=true で出ます。")
    if callers_found > len(caller_rows):
        out["truncated_note"] = (
            "呼び出し元 {0} 件のうち先頭 {1} 件だけを辿りました (limit)。"
            "まとめ (suspicious / callers_not_writing) もその範囲のものです。".format(
                callers_found, len(caller_rows)))
    if not caller_rows:
        out["hint"] = {"message": "呼び出し元が 0 件でした (find_calls_to の blind_spots 参照)。",
                       "blind_spots": list(CALLS_BLIND_SPOTS)}
    return out


def _memory_args_caller(an, c, watch, creg, ent):
    """list_memory_args の呼び出し元 1 件。"""
    site = int(c["site"], 16)
    row = {"site": c["site"], "site_bus": c["site_bus"], "kind": c["kind"],
           "text": c.get("text"), "boundary": c.get("boundary"),
           "executed": c.get("executed")}
    if c.get("index") is not None:
        row["table_index"] = c["index"]
    if creg is None or site not in creg.nodes:
        row["function_entry"] = None
        row["args"] = {_bus(a): {"status": "unknown"} for a in sorted(watch)}
        row["note"] = "呼び出しを含む処理の入口が分かりませんでした ({0})。".format(
            (ent or {}).get("note") or "到達しない")
        return row
    row["function_entry"] = _bus(creg.entry)
    row["entry_confidence"] = ent.get("confidence")
    row["entry_widths"] = "m{0}x{1} ({2}/{3})".format(creg.m, creg.x, creg.ms, creg.xs)
    node = creg.nodes[site]
    if node.ms in FLOW_UNCERTAIN or node.xs in FLOW_UNCERTAIN:
        row["width_uncertain"] = True
    IN, risks = an.mem_dataflow(creg, watch)
    st = IN.get(site)
    preds = creg.preds()
    back = set()
    stack = list(preds.get(site, ()))
    while stack:
        a = stack.pop()
        if a in back:
            continue
        back.add(a)
        stack.extend(preds.get(a, ()))
    must = {k: (v, d) for k, v, d in st[1]} if st else {}
    may = st[2] if st else frozenset()
    args_out = {}
    for a in sorted(watch):
        rel = []
        for kind, at, w, via in sorted(risks, key=lambda r: (r[1], r[0], r[3])):
            here = via[0] if via else at
            if here not in back:
                continue
            if kind in ("indexed", "indexed_far") and w != a:
                continue
            desc = "{0} {1} ({2})".format(_bus(at), an.text_at(at), kind)
            if via:
                desc += " via " + " → ".join(_bus(v) for v in via)
            rel.append(desc)
        if st is None:
            cell = {"status": "unknown", "why": "入口から辿って呼び出しに届く状態が無い"}
        elif a in must:
            v, d = must[a]
            cell = {"status": "written", "value": None if v == UNK else v,
                    "written_at": [_bus(p) for p in d][:6]}
            if v != UNK:
                cell["value_hex"] = "${0:02X}".format(v)
        elif a in may:
            cell = {"status": "partially_written"}
        else:
            cell = {"status": "not_written"}
        if rel and cell["status"] != "written":
            cell["could_be_written_by"] = rel[:6]
            cell["could_be_written_total"] = len(rel)
        args_out[_bus(a)] = cell
    row["args"] = args_out
    return row
