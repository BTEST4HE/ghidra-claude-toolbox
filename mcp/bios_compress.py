# -*- coding: utf-8 -*-
"""GBA / NDS の BIOS 圧縮を展開します (Python 3.13 前提)。

読み取り専用 MCP の `decompress` / `find_compressed_blocks` から使います。
バイト列を受け取って展開するだけで、ファイルにも Ghidra にも触れません。

対応形式 (GBATEK の圧縮ヘッダ):

| byte0 | 形式 | SWI |
|---|---|---|
| `0x10` | LZ77 | 0x11 / 0x12 |
| `0x24` / `0x28` | Huffman (4bit / 8bit シンボル) | 0x13 |
| `0x30` | RLE (ランレングス) | 0x14 / 0x15 |
| `0x81` / `0x82` | Diff フィルタ (8bit / 16bit) | 0x16-0x18 |

ヘッダは 4 バイト: `byte0` が形式、`byte1..3` が **展開後サイズ (24bit LE)**。

⚠️ **Diff フィルタは `0x40` ではなく `0x8n`** です (GBATEK: Bit4-7 が Type=8、
Bit0-3 がデータ幅 8/16)。`0x4n` は BIOS の標準形式に存在しないため、
そう指定されたら理由つきでエラーにします。
"""

import math


# byte0 の上位ニブル -> 形式名。
TYPE_LZ77 = 0x1
TYPE_HUFFMAN = 0x2
TYPE_RLE = 0x3
TYPE_DIFF = 0x8

_TYPE_NAMES = {
    TYPE_LZ77: "lz77",
    TYPE_HUFFMAN: "huffman",
    TYPE_RLE: "rle",
    TYPE_DIFF: "diff",
}
# 名前 -> 上位ニブル (type 明示指定用)。
NAME_TO_TYPE = {v: k for k, v in _TYPE_NAMES.items()}

# 展開後サイズの上限 (暴走した壊れたヘッダで巨大確保しないための保険)。
DEFAULT_MAX_SIZE = 0x40000

# find_blocks の処理予算の既定値。棄却され続ける候補でも、ここで必ず止まる。
# (MCP は自分の絶対上限を明示的に渡す。引数で None を渡しても無制限にはしない。)
DEFAULT_FIND_MAX_ATTEMPTS = 20000
DEFAULT_FIND_MAX_WORK = 256 * 1024 * 1024


class DecompressError(Exception):
    """展開に失敗したことを表します (壊れたデータ / 非対応形式)。"""


# reveal_bytes=False のとき、エラー文で入力由来の値の代わりに出す文字列。
_HIDDEN = "(非表示)"


def _shown(reveal, text):
    """reveal が真なら text を、偽なら値を伏せた印を返します。"""
    return text if reveal else _HIDDEN


def read_header(data, offset=0, reveal_bytes=True):
    """圧縮ヘッダを読み、(形式名, 展開後サイズ, ヘッダ長, 付加情報) を返します。

    形式として成立しないときは DecompressError を投げます。
    ヘッダは通常 4 バイトですが、サイズ 0 のときは 32bit の拡張サイズが続きます。
    reveal_bytes=False にすると、エラー文に入力のバイト値を入れません
    (MCP がローカルファイルを読むとき。中身をエラー経由で漏らさないため)。
    """
    if offset + 4 > len(data):
        raise DecompressError("ヘッダを読むにはデータが短すぎます。")
    head = data[offset]
    kind = (head >> 4) & 0xF
    extra = head & 0xF
    if kind not in _TYPE_NAMES:
        raise DecompressError(
            "byte0={0} は BIOS 圧縮ヘッダとして未対応です "
            "(0x1n=LZ77 / 0x2n=Huffman / 0x3n=RLE / 0x8n=Diff)。".format(
                _shown(reveal_bytes, "0x{0:02X}".format(head))))
    size = int.from_bytes(data[offset + 1:offset + 4], "little")
    header_len = 4
    if size == 0:
        if offset + 8 > len(data):
            raise DecompressError("拡張サイズを読むにはデータが短すぎます。")
        size = int.from_bytes(data[offset + 4:offset + 8], "little")
        header_len = 8
    if kind == TYPE_HUFFMAN and extra not in (4, 8):
        raise DecompressError(
            "Huffman のシンボル幅が {0} です (4 か 8 のはず)。".format(
                _shown(reveal_bytes, "0x{0:X}".format(extra))))
    if kind == TYPE_DIFF and extra not in (1, 2):
        raise DecompressError(
            "Diff フィルタのデータ幅が {0} です "
            "(1=8bit / 2=16bit のはず)。".format(
                _shown(reveal_bytes, "0x{0:X}".format(extra))))
    return _TYPE_NAMES[kind], size, header_len, extra


def decompress(data, offset=0, max_size=DEFAULT_MAX_SIZE, force_type=None,
               reveal_bytes=True):
    """圧縮データを展開し、(bytes, 情報 dict) を返します。

    force_type に "lz77" / "huffman" / "rle" / "diff" を渡すとヘッダの形式判定を
    上書きします (サイズはヘッダから読みます)。
    reveal_bytes=False にすると、失敗時のエラー文に入力由来の値
    (ヘッダのバイト・宣言サイズ・参照距離など) を入れません。
    """
    if force_type is not None:
        name = str(force_type).strip().lower()
        if name in ("0x40", "diff8", "diff16"):
            name = "diff"
        if name not in NAME_TO_TYPE:
            raise DecompressError(
                "type '{0}' は未対応です。lz77 / huffman / rle / diff の"
                "いずれかを指定してください "
                "(Diff フィルタのヘッダは 0x40 ではなく 0x81 / 0x82 です)。".format(
                    force_type))

    kind, size, header_len, extra = read_header(data, offset, reveal_bytes)
    if force_type is not None:
        kind = str(force_type).strip().lower()
        if kind in ("0x40", "diff8", "diff16"):
            kind = "diff"
    if size <= 0:
        raise DecompressError("展開後サイズが 0 です。")
    if size > max_size:
        raise DecompressError(
            "展開後サイズ {0} バイトが上限 {1} を超えます "
            "(max_size で上げられます)。".format(
                _shown(reveal_bytes, str(size)), max_size))

    body = offset + header_len
    try:
        if kind == "lz77":
            out, used = _lz77(data, body, size)
        elif kind == "huffman":
            out, used = _huffman(data, body, size, extra)
        elif kind == "rle":
            out, used = _rle(data, body, size)
        elif kind == "diff":
            out, used = _diff(data, body, size, extra)
        else:                                   # ここには来ない
            raise DecompressError("形式 '{0}' の展開は未実装です。".format(kind))
    except DecompressError:
        if reveal_bytes:
            raise
        # 各形式の詳細 (参照距離・ラン長・シンボル値) は入力由来なので伏せる。
        raise DecompressError(
            "{0}: 圧縮データが途中で壊れています "
            "(ファイル入力のため詳細な値は表示しません)。".format(kind))

    if len(out) != size:
        raise DecompressError(
            "展開後サイズがヘッダと一致しません "
            "(ヘッダ {0} / 実際 {1})。".format(
                _shown(reveal_bytes, str(size)), _shown(reveal_bytes, str(len(out)))))
    return bytes(out), {
        "type": kind,
        "type_detail": _detail(kind, extra),
        "declared_size": size,
        "compressed_size": header_len + used,
        "ratio": round(size / float(header_len + used), 2) if used else None,
    }


def _detail(kind, extra):
    """形式の補足 (Huffman のシンボル幅・Diff の語幅) を返します。"""
    if kind == "huffman":
        return "{0}bit シンボル".format(extra)
    if kind == "diff":
        return "{0}bit".format(8 if extra == 1 else 16)
    if kind == "lz77":
        return "GBA BIOS LZ77 (窓 4KB)"
    if kind == "rle":
        return "GBA BIOS RLE"
    return kind


# ---------------------------------------------------------------------------
# 各形式
# ---------------------------------------------------------------------------

def _lz77(data, pos, size):
    """LZ77 (0x10) を展開します。戻り値は (出力, 消費した圧縮バイト数)。"""
    start = pos
    out = bytearray()
    n = len(data)
    while len(out) < size:
        if pos >= n:
            raise DecompressError("LZ77: フラグを読む前にデータが尽きました。")
        flags = data[pos]
        pos += 1
        for bit in range(8):
            if len(out) >= size:
                break
            if flags & (0x80 >> bit):
                if pos + 2 > n:
                    raise DecompressError("LZ77: 参照 2 バイトが読めません。")
                b0, b1 = data[pos], data[pos + 1]
                pos += 2
                length = (b0 >> 4) + 3
                disp = (((b0 & 0xF) << 8) | b1) + 1
                if disp > len(out):
                    raise DecompressError(
                        "LZ77: 出力の先頭より前 (-{0}) を参照しています。".format(disp))
                base = len(out) - disp
                for k in range(length):
                    if len(out) >= size:
                        break
                    out.append(out[base + k])
            else:
                if pos >= n:
                    raise DecompressError("LZ77: リテラル 1 バイトが読めません。")
                out.append(data[pos])
                pos += 1
    return out, pos - start


def _rle(data, pos, size):
    """RLE (0x30) を展開します。"""
    start = pos
    out = bytearray()
    n = len(data)
    while len(out) < size:
        if pos >= n:
            raise DecompressError("RLE: フラグを読む前にデータが尽きました。")
        flag = data[pos]
        pos += 1
        if flag & 0x80:
            run = (flag & 0x7F) + 3
            if pos >= n:
                raise DecompressError("RLE: 繰り返す 1 バイトが読めません。")
            out.extend(bytes([data[pos]]) * run)
            pos += 1
        else:
            run = (flag & 0x7F) + 1
            if pos + run > n:
                raise DecompressError("RLE: リテラル {0} バイトが読めません。".format(run))
            out.extend(data[pos:pos + run])
            pos += run
    del out[size:]
    return out, pos - start


def _huffman(data, pos, size, bits):
    """Huffman (0x24 / 0x28) を展開します。

    木は「ノード 1 バイト」の配列で、**次の子のアドレスは
    `(現在のアドレス AND ~1) + offset*2 + 2`** で求めます (GBATEK)。
    ビットストリームは 32bit 単位で、**上位ビットから**読みます。
    """
    start = pos
    n = len(data)
    if pos >= n:
        raise DecompressError("Huffman: 木サイズが読めません。")
    tree_size = data[pos]
    tree_bytes = (tree_size + 1) * 2
    tree_start = pos                       # tree_size を含む位置 = ノード index 0
    if tree_start + tree_bytes > n:
        raise DecompressError("Huffman: 木テーブルが範囲外です。")
    pos = tree_start + tree_bytes

    out = bytearray()
    pending = []                           # 4bit のとき 2 個で 1 バイトにする
    root = 1                               # ノード index 1 が根 (index 0 は木サイズ)
    node = root
    parent_flag = 0

    while len(out) < size:
        if pos + 4 > n:
            raise DecompressError("Huffman: ビットストリームが尽きました。")
        chunk = int.from_bytes(data[pos:pos + 4], "little")
        pos += 4
        for shift in range(31, -1, -1):
            if len(out) >= size:
                break
            bit = (chunk >> shift) & 1
            value = data[tree_start + node]
            offset = value & 0x3F
            child = ((node & ~1) + offset * 2 + 2) + bit
            # ★子は**木テーブルの中**になければならない (GBATEK)。
            #   バッファ全体との比較にすると制約が緩すぎて、ランダムなバイト列でも
            #   「展開できてしまい」誤検出が桁違いに増える。
            if child >= tree_bytes:
                raise DecompressError("Huffman: 子ノードが木テーブルの外です。")
            end_flag = (value >> (6 + (1 - bit))) & 1     # bit7=node0 / bit6=node1
            if end_flag:
                symbol = data[tree_start + child]
                if bits == 4:
                    # 4bit シンボルなら上位ニブルは 0 のはず (GBATEK)。
                    if symbol > 0xF:
                        raise DecompressError(
                            "Huffman(4bit): データノード 0x{0:02X} の上位ビットが"
                            "立っています。".format(symbol))
                    pending.append(symbol & 0xF)
                    if len(pending) == 2:
                        # 先に来たシンボルが下位ニブル。
                        out.append(pending[0] | (pending[1] << 4))
                        pending = []
                else:
                    out.append(symbol & 0xFF)
                node = root
            else:
                node = child
    del out[size:]
    return out, pos - start


def _diff(data, pos, size, extra):
    """Diff フィルタ (0x81 / 0x82) を解除します。"""
    start = pos
    out = bytearray()
    n = len(data)
    if extra == 1:
        prev = 0
        while len(out) < size:
            if pos >= n:
                raise DecompressError("Diff8: データが尽きました。")
            prev = (prev + data[pos]) & 0xFF
            out.append(prev)
            pos += 1
    else:
        prev = 0
        while len(out) < size:
            if pos + 2 > n:
                raise DecompressError("Diff16: データが尽きました。")
            prev = (prev + int.from_bytes(data[pos:pos + 2], "little")) & 0xFFFF
            out.extend(prev.to_bytes(2, "little"))
            pos += 2
    del out[size:]
    return out, pos - start


# ---------------------------------------------------------------------------
# 候補探索 (誤検出の排除がここの肝)
# ---------------------------------------------------------------------------

def shannon_entropy(data, sample=4096):
    """バイト単位のシャノンエントロピー (0〜8 bit/byte) を返します。

    圧縮ヘッダらしく見えるだけのランダムなバイト列を弾くために使います。
    実データ (タイル・マップ・テキスト) は必ず偏るので 8 に近づきません。
    """
    chunk = data[:sample]
    if not chunk:
        return 0.0
    counts = [0] * 256
    for b in chunk:
        counts[b] += 1
    total = float(len(chunk))
    ent = 0.0
    for c in counts:
        if c:
            p = c / total
            ent -= p * math.log(p, 2)
    return ent


def find_blocks(data, base_addr, min_size=0x200, max_size=DEFAULT_MAX_SIZE,
                align=4, max_entropy=7.2, min_entropy=1.0, min_ratio=1.05,
                include_rle=False, limit=200, scan_end=None,
                max_attempts=DEFAULT_FIND_MAX_ATTEMPTS,
                max_work=DEFAULT_FIND_MAX_WORK, stats=None):
    """範囲を走査して圧縮ブロック候補を返します。

    ★**誤検出の排除がこの関数の存在意義**です。ヘッダのバイト並びだけで拾うと
      候補が数百件出て使い物になりません。次を全部通したものだけ返します:

      1. ヘッダとして成立する (形式・サイズが妥当、min_size 以上)
      2. **最後まで展開が通る** (途中でデータが尽きない / 不正参照が無い)
      3. 展開後サイズがヘッダの宣言と一致する
      4. 圧縮率が min_ratio 以上 (縮んでいないものは圧縮データではない)
      5. **展開結果のエントロピーが [min_entropy, max_entropy]**
         上限 = ランダム (=偶然そう読めただけ) を弾く
         下限 = 全部同じバイト (ゼロ埋めを RLE として読んだだけ) を弾く

    ★実装上の注意:

    - **見つけたブロックの内側を読み飛ばしてはいけない。** 誤検出が 1 つでも
      混ざると、その「長さ」ぶん先まで飛んで**本物を丸ごと取り逃します**。
      全オフセットを見ます。
    - **RLE は既定で対象外** (`include_rle=True` で有効化)。RLE は構造上の制約が
      ほぼ無く、任意のバイト列が「展開できてしまう」ため誤検出の主因になります。
      LZ77 は出力先頭より前を参照できず、Huffman は木の整合が要るので、
      この 2 つは偶然通りにくいです。
    - **入れ子の圧縮データはエントロピー上限を免除**します。中身がさらに圧縮
      されていれば出力はランダムに近くて当然だからです
      (例: Huffman の中身がさらに LZ77)。

    ★処理予算: 採用件数 (limit) だけでなく、**展開を試した回数 (max_attempts)** と
      **試した宣言サイズの累計 (max_work)** で打ち切ります。棄却され続ける候補でも
      止まるようにするためです。scan_end を渡すと、候補の開始位置はそこまでに限り
      (その先のバイトは、境界をまたぐブロックの展開にだけ使う)。
      stats に dict を渡すと、打ち切りの理由 (`stopped`)・位置 (`stopped_at`、
      data 内の offset。そこから先は未検査)・試行回数・累計を書き込みます。
    """
    found = []
    rejected = {"header": 0, "decompress": 0, "entropy": 0, "ratio": 0,
                "rle_skipped": 0}
    size = len(data)
    step = max(1, int(align))
    end = size if scan_end is None else max(0, min(size, int(scan_end)))
    attempt_cap = DEFAULT_FIND_MAX_ATTEMPTS if max_attempts is None else int(max_attempts)
    work_cap = DEFAULT_FIND_MAX_WORK if max_work is None else int(max_work)
    info_out = stats if isinstance(stats, dict) else {}
    info_out.update({"stopped": None, "stopped_at": None, "attempts": 0,
                     "work_bytes": 0, "scan_end": end})
    attempts = 0
    work = 0
    for pos in range(0, max(0, min(end, size - 8 + 1)), step):
        if len(found) >= limit:
            info_out.update({"stopped": "limit", "stopped_at": pos})
            break
        head = data[pos]
        kind_nibble = (head >> 4) & 0xF
        if kind_nibble not in _TYPE_NAMES:
            continue
        if kind_nibble == TYPE_RLE and not include_rle:
            rejected["rle_skipped"] += 1
            continue
        try:
            kind, out_size, header_len, extra = read_header(data, pos)
        except DecompressError:
            rejected["header"] += 1
            continue
        if out_size < min_size or out_size > max_size:
            rejected["header"] += 1
            continue
        if attempts >= attempt_cap:
            info_out.update({"stopped": "max_attempts", "stopped_at": pos})
            break
        if work + out_size > work_cap:
            info_out.update({"stopped": "max_work", "stopped_at": pos})
            break
        attempts += 1
        work += out_size
        info_out.update({"attempts": attempts, "work_bytes": work})
        try:
            out, info = decompress(data, pos, max_size=max_size)
        except DecompressError:
            rejected["decompress"] += 1
            continue
        if info["ratio"] is not None and info["ratio"] < min_ratio:
            rejected["ratio"] += 1
            continue
        nested = _peek_nested(out)
        ent = shannon_entropy(out)
        # 中身がさらに圧縮なら高エントロピーで当然なので上限は見ない。
        if ent < min_entropy or (nested is None and ent > max_entropy):
            rejected["entropy"] += 1
            continue
        found.append({
            "address": "0x{0:08x}".format(base_addr + pos),
            "type": info["type"],
            "type_detail": info["type_detail"],
            "compressed_size": info["compressed_size"],
            "decompressed_size": info["declared_size"],
            "ratio": info["ratio"],
            "entropy": round(ent, 2),
            "nested": nested,
        })
    return found, rejected


def _peek_nested(out):
    """展開結果の先頭がさらに圧縮ヘッダなら、その形式を返します (無ければ None)。

    Huffman の中身がさらに LZ77、のような二段構成は珍しくありません。
    一段目だけ見て「これで終わり」と思わないための手掛かりです。
    """
    try:
        kind, size, _, extra = read_header(out, 0)
    except DecompressError:
        return None
    if size < 0x40:
        return None
    return {"type": kind, "type_detail": _detail(kind, extra),
            "declared_size": size}
