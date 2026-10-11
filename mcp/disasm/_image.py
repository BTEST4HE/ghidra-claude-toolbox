# -*- coding: utf-8 -*-
"""複数ブロックにまたがるメモリイメージの読み取り (Python 3.13 前提)。

アーキ別の解析フックの多くは「1 ブロックのバイト列」だけを受け取ります。
65816 の JSL のようにバンク (ブロック) をまたいで辿る解析では、
全ブロックを番地で引ける読み取り口が要るので、ここにまとめます。

★読むだけです。MCP 側が export 済みブロックのバイト列を渡して作ります
  (Ghidra にもファイルにも触れません)。
"""

import bisect


class BusImage(object):
    """[(先頭番地, バイト列)] を番地で引けるようにしたものです。"""

    def __init__(self, parts):
        """parts: [(start, data)]。重なりは想定しません (先に来た方が勝ちます)。"""
        self.parts = sorted(((int(s), bytes(d)) for s, d in parts if d),
                            key=lambda p: p[0])
        self._starts = [p[0] for p in self.parts]

    def locate(self, addr):
        """addr を含む (data, start) を返します。無ければ None。"""
        i = bisect.bisect_right(self._starts, addr) - 1
        if i >= 0:
            start, data = self.parts[i]
            if addr < start + len(data):
                return data, start
        return None

    def has(self, addr):
        """addr のバイトが読めるか。"""
        return self.locate(addr) is not None

    def byte(self, addr):
        """1 バイト読みます。範囲外なら None。"""
        loc = self.locate(addr)
        if loc is None:
            return None
        data, start = loc
        return data[addr - start]

    def read(self, addr, length):
        """addr から length バイト (1 ブロック内で読める分だけ) を返します。"""
        loc = self.locate(addr)
        if loc is None:
            return b""
        data, start = loc
        off = addr - start
        return data[off:off + length]

    def word16(self, addr):
        """little endian の 16bit を読みます。読めなければ None。"""
        raw = self.read(addr, 2)
        if len(raw) < 2:
            return None
        return raw[0] | (raw[1] << 8)

    def total_bytes(self):
        """全ブロックの合計バイト数。"""
        return sum(len(d) for _s, d in self.parts)
