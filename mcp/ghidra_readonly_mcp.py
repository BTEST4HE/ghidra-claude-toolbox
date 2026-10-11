# -*- coding: utf-8 -*-
"""Ghidra Claude Toolbox 読み取り専用 MCP サーバ (Python 3.13 前提)。

このサーバは <project>/ghidra_exports/ に出力済みの JSON / decompile を
**読むだけ** です。Ghidra にも Ghidra プロジェクトにも一切触れません。
書き込み系 (コメント反映・関数作成・リネーム・型変更・配列化) は
ツールとして定義しません (構造的に実行不能)。

対象プロジェクトの指定:
  - 環境変数 CCT_PROJECT_ROOT、または第1引数で claude_project のパスを渡す。

使い方 (Windows CMD):
  set CCT_PROJECT_ROOT=C:\\path\\to\\claude_project
  python mcp\\ghidra_readonly_mcp.py            : MCP サーバとして起動 (stdio)
  python mcp\\ghidra_readonly_mcp.py --selftest  : Ghidra/MCP SDK 不要の自己テスト

安全方針は docs/safety_rules.md を参照。
"""

import array
import bisect
import json
import re
from collections import OrderedDict
import os
import struct
import sys
from pathlib import Path

# アーキ別逆アセンブラ (mcp/disasm/) はこのスクリプトと同じ階層に置いています。
# スクリプト実行時は sys.path[0] がここになりますが、念のため明示的に足します。
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
import bios_compress  # noqa: E402
import disasm  # noqa: E402  (sys.path 調整後に import する必要がある)
from disasm._image import BusImage  # noqa: E402


# レガシーの巨大ファイル (各 380MB 級) はスキーマ外なので読み込まない。
# decompile ファイルの拡張子。
DECOMPILE_EXT = ".c"

# ページングの既定値と上限。
DEFAULT_LIMIT = 50
MAX_LIMIT = 200

# get_disassembly の既定命令数と上限 (1 回の応答が膨らみすぎないようにする)。
DEFAULT_DISASM_COUNT = 64
MAX_DISASM_COUNT = 512

# --- ファイルを読む / 書くツール (decompress / render_*) の絶対上限 ----------
# ★MCP 引数で緩められない上限です。引数 (length / max_size / scale) は
#   この範囲の中でしか効きません。
# 1 回に読む入力の上限 (source_path のファイル / memory ブロックとも)。
# length 未指定ならここで打ち切り、length がこれを超えたらエラー。
MAX_SOURCE_BYTES = 64 * 1024 * 1024
# 展開後サイズの上限 (max_size を指定してもこれは超えない)。
MAX_DECOMPRESS_SIZE = 16 * 1024 * 1024
# 描画の上限。拡大前の画素数 / 拡大・番号帯を含めた出力の画素数 / 出力の一辺。
MAX_RENDER_SOURCE_PIXELS = 4 * 1024 * 1024
MAX_RENDER_PIXELS = 16 * 1024 * 1024
MAX_RENDER_SIDE = 16384

# source_path で読んでよいフォルダ (プロジェクト直下の名前)。これ以外は
# bridge_config.json の source_roots に**人間が**書いたときだけ読む。
# 実行ファイル (program.json の executable_path 等) と cdl_jsonl も同じ許可ルートで判定する。
DEFAULT_SOURCE_DIRS = ("extracted", "dumps")

# --- 丸ごと読むファイルの絶対上限 (読む**前に**大きさで断る。引数で緩められない) ---
# ghidra_exports/*.json。大きい Program の xrefs.json は数十 MB になるので余裕を持たせる。
# 超えるときは export_xrefs=false / decompile 範囲を絞る等で export を分ける。
MAX_EXPORT_JSON_BYTES = 512 * 1024 * 1024
# 人間が書く設定・観測・スナップショット・.lines.json など、小さいはずの JSON。
MAX_SMALL_JSON_BYTES = 32 * 1024 * 1024
# decompile/*.c 1 本 (export 側の既定上限は 512KB)。
MAX_DECOMPILE_TEXT_BYTES = 16 * 1024 * 1024
# 全域走査のために丸ごと読む memory/*.bin・オーバーレイ・実行ファイルのブロック。
MAX_IMAGE_BYTES = 256 * 1024 * 1024
# ExecutableImage がセクション表を読むために丸ごと読む実行ファイル。
MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024
# cdl_jsonl (1 行ずつ読むが、件数ぶんメモリを使う)。
MAX_CDL_BYTES = 256 * 1024 * 1024

# --- find_compressed_blocks の処理予算 (1 回の呼び出しあたり。引数で緩められない) ---
# 走査するバイト数。超える範囲は打ち切り、続きの start を返す。
MAX_COMPRESS_SCAN_BYTES = 8 * 1024 * 1024
# 展開を試す回数 (棄却されたものも数える)。
MAX_COMPRESS_ATTEMPTS = 20000
# 展開を試した宣言サイズの累計 (棄却されたものも数える。展開処理の量の上限)。
MAX_COMPRESS_WORK_BYTES = 256 * 1024 * 1024

# find_address_refs の既定件数と上限。
DEFAULT_REFS_LIMIT = 100
MAX_REFS_LIMIT = 500

# read_data の既定要素数と上限。1 回の応答が膨らみすぎないようにする
# (表を読むツールなので、既定は「1 画面ぶん」くらいに抑える)。
DEFAULT_DATA_COUNT = 64
MAX_DATA_COUNT = 1024
MAX_DATA_BYTES = 64 * 1024

# read_data が扱う数値フォーマット。name -> (struct のコード, 要素バイト数)。
# hex / cstring は要素長が固定でないので別扱い (下の read_data を参照)。
DATA_FORMATS = {
    "u8": ("B", 1), "s8": ("b", 1),
    "u16": ("H", 2), "s16": ("h", 2),
    "u32": ("I", 4), "s32": ("i", 4),
    "u64": ("Q", 8), "s64": ("q", 8),
    "f32": ("f", 4), "f64": ("d", 8),
}
# 既定で 16 進表示したいフォーマット (アドレス/ポインタになりがちなもの)。
DATA_HEX_FORMATS = ("u32", "u64")
# 生バイトダンプ / NUL 終端文字列。
# translate_address の SNES の ROM 配置 (式で換算する kind)。
SNES_MAPPINGS = ("lorom", "hirom", "exhirom")

DATA_FORMAT_HEX = "hex"
DATA_FORMAT_CSTRING = "cstring"
# cstring 1 件あたりの最大長 (終端が見つからないときの暴走防止)。
MAX_CSTRING_LENGTH = 512

# describe_data が周期を推定するときに読む既定の窓 (バイト)。
# 広すぎると表の外まで読んでノイズが増え、狭すぎると周期が出ない。
DETECT_WINDOW_BYTES = 8192

# export_context.py が出力する想定のファイル名。
EXPORT_FILES = (
    "program.json",
    "functions.json",
    "strings.json",
    "comments.json",
    "xrefs.json",
    "undefined_ranges.json",
    "memory_map.json",
    # ★Ghidra が「その番地に付けた名前」と「人間が定義した型」。無いと
    #   apply_labels.py で付けたラベルも次のセッションで見えず、重複提案の原因になる。
    #   古い export には存在しないので、読めなくても動くようにしてあります。
    "labels.json",
    "defined_data.json",
    # ★構造体・クラスのレイアウト (get_struct_layout / find_field)。
    #   古い export には無いので、無くても他のツールは今まで通り動きます。
    "datatypes.json",
)


def resolve_project_root(argv):
    """CCT_PROJECT_ROOT 環境変数または第1引数からプロジェクトルートを決定します。"""
    for arg in argv[1:]:
        if not arg.startswith("--"):
            return Path(arg).resolve()
    env = os.environ.get("CCT_PROJECT_ROOT")
    if env:
        return Path(env).resolve()
    raise SystemExit(
        "エラー: 対象プロジェクトが未指定です。"
        "環境変数 CCT_PROJECT_ROOT か第1引数で claude_project のパスを指定してください。")


def parse_hex(address):
    """'0x...' 形式の 16 進アドレス文字列を int に変換します。失敗時は分かりやすく落とします。"""
    if not isinstance(address, str):
        raise ValueError("アドレスは '0x...' 形式の文字列で指定してください。")
    text = address.strip()
    try:
        return int(text, 16)
    except ValueError:
        raise ValueError("アドレス '{0}' を 16 進として解釈できません。".format(address))


def try_parse_hex(text):
    """データ側 (xrefs.json) のアドレス値を int に変換します。失敗時は None。

    Ghidra のスタック/レジスタ参照は export 時に '0xStack[-0x4]' のような
    非アドレス文字列になることがあるため、例外で落とさず None を返して
    フィルタ対象外 (スキップ) として扱います。ユーザー入力には strict な
    parse_hex を使い分けること。
    """
    if not isinstance(text, str):
        return None
    try:
        return int(text.strip(), 16)
    except ValueError:
        return None


def _parse_aob(pattern):
    """AOB 文字列を (バイト列, マスク) にします。`??` はワイルドカード。

    "48 8B ?? ?? 89" / "0F8004 08" / "0x0f,0x80" のどれでも受けます。
    マスクは 0xFF=一致必須 / 0x00=何でもよい。
    """
    if not isinstance(pattern, str):
        raise ValueError("pattern は文字列で指定してください。")
    text = re.sub(r"0x|,|\s+", " ", pattern.strip(), flags=re.I)
    tokens = []
    for chunk in text.split():
        if set(chunk) <= set("?"):
            tokens.extend(["??"] * max(1, len(chunk) // 2))
            continue
        i = 0
        while i < len(chunk):
            pair = chunk[i:i + 2]
            if len(pair) < 2:
                raise ValueError(
                    "16 進が半端です: '{0}'。1 バイト 2 桁で書いてください。".format(chunk))
            tokens.append(pair)
            i += 2
    needle = bytearray()
    mask = bytearray()
    for tok in tokens:
        if "?" in tok:
            needle.append(0)
            mask.append(0)
            continue
        try:
            needle.append(int(tok, 16))
        except ValueError:
            raise ValueError("16 進として読めません: '{0}'。".format(tok))
        mask.append(0xFF)
    return bytes(needle), bytes(mask)


def _aob_search(data, needle, mask, first, last, step):
    """[first, last) をワイルドカード付きで走査して、見つかった offset を返します。

    ワイルドカードが無いところで先に絞ってから全体を照合します
    (bytes.find は C 実装なので、素朴な総当たりより桁違いに速い)。
    """
    size = len(needle)
    if size == 0 or last - first < size:
        return
    # マスクが立っている最長の連続区間を「先に探す種」にする。
    best_i = best_n = 0
    i = 0
    while i < size:
        if mask[i]:
            j = i
            while j < size and mask[j]:
                j += 1
            if j - i > best_n:
                best_i, best_n = i, j - i
            i = j
        else:
            i += 1
    view = memoryview(data)
    if best_n == 0:
        # 全部ワイルドカード。step 刻みで全部が一致扱い。
        for pos in range(first, last - size + 1, step):
            yield pos
        return
    seed = bytes(needle[best_i:best_i + best_n])
    raw = bytes(data)
    pos = first
    while True:
        hit = raw.find(seed, pos, last)
        if hit < 0:
            return
        cand = hit - best_i
        pos = hit + 1
        if cand < first or cand + size > last:
            continue
        if step > 1 and cand % step:
            continue
        chunk = view[cand:cand + size]
        if all((not mask[k]) or chunk[k] == needle[k] for k in range(size)):
            yield cand


# ---------------------------------------------------------------------------
# 日本語 / 独自符号のテキスト (Ghidra が拾えない文字列)
#
# Ghidra の文字列検出は基本 ASCII で、Shift-JIS の日本語はほぼ拾えません。
# せっかくゲーム側に日本語ラベルがあるのに strings.json に出てこないので、
# ここで拾って **[AI] コメントとして Ghidra へ戻せる形**まで作ります。
#
# ★文字列データ型の適用 (Ghidra 上で「これは文字列だ」と型を付ける) は
#   「データ型の自動変更」に当たるので**常に禁止**です。ここが作るのは
#   あくまでコメント案で、反映は人間が apply_comments.py で行います。
#
# ★誤検出との戦いが本体です。素朴に「decode できたら文字列」とすると、
#   数千〜数十万件の誤検出が出て**まったく使い物になりません**。効く条件は次の 4 つ:
#
#     1. 半角カタカナ (0xA1-0xDF) を既定で数えない
#        — このバイト域は任意のバイナリに大量に現れる。最大の誤検出源。
#     2. 2 バイト文字を min_japanese 個以上要求する
#        — 1 文字だけ「日本語に見える」のは偶然でいくらでも起きる。
#     3. NUL 終端を要求する
#        — 本物の文字列はほぼ NUL で終わる。データの真ん中を切り出した
#          偶然の一致はここで落ちる。
#     4. 珍しい符号位置を弾く
#        — CJK 拡張A や外字が混ざったら、まず偶然の一致。
# ---------------------------------------------------------------------------

# 2 バイト Shift-JIS の第1バイト。
#
# ★既定は **JIS 第1水準まで (0x81-0x98)**。0x99 以降は第2水準の珍しい漢字と
#   外字で、ゲームのテキストにはまず出てこないのに乱数同然のデータから
#   いくらでも「読めてしまう」最大の誤検出源です。
#   人名などで第2水準が要るときだけ level2_kanji=true にしてください。
_SJIS_LEAD_L1 = tuple(range(0x81, 0x99))
_SJIS_LEAD_ALL = tuple(range(0x81, 0xA0)) + tuple(range(0xE0, 0xEB))

# 「日本語の本体」とみなす符号位置。ここを 2 バイト文字として min_japanese 個
# 以上含まないものは捨てます。
_JP_CORE = (
    (0x3041, 0x309F),   # ひらがな
    (0x30A0, 0x30FF),   # カタカナ
    (0x4E00, 0x9FFF),   # CJK 統合漢字
)
# 混ざっていてよい文字 (これ以外が 1 文字でもあれば捨てる)。
_JP_OK = _JP_CORE + (
    (0x0020, 0x007E),   # ASCII 可読
    (0x3000, 0x303F),   # 全角空白・句読点
    (0xFF01, 0xFF60),   # 全角英数記号
    (0xFF61, 0xFF9F),   # 半角カタカナ
)


def _in_ranges(code, ranges):
    """符号位置がいずれかの範囲に入るかを返します。"""
    for lo, hi in ranges:
        if lo <= code <= hi:
            return True
    return False


def _is_japanese(ch):
    """その文字が「日本語の本体」かを返します (ASCII や記号は含めません)。"""
    return _in_ranges(ord(ch), _JP_CORE)


def _sjis_runs(data, first, last, min_bytes, allow_halfwidth=False,
               level2_kanji=False):
    """Shift-JIS として成立しうるバイトの連なりを (開始, 終了) で返します。

    バイトの形だけで区切ってから decode で確かめる二段構えです。
    いきなり総当たりで decode すると、乱数同然のデータが大量に「成立」します。
    """
    i = first
    run = None
    while i < last:
        b = data[i]
        size = 0
        if 0x20 <= b <= 0x7E:                          # ASCII 可読
            size = 1
        elif allow_halfwidth and 0xA1 <= b <= 0xDF:    # 半角カタカナ
            size = 1
        elif i + 1 < last and b in (
                _SJIS_LEAD_ALL if level2_kanji else _SJIS_LEAD_L1):
            t = data[i + 1]
            if 0x40 <= t <= 0xFC and t != 0x7F:        # 2 バイト文字
                size = 2
        if size:
            if run is None:
                run = i
            i += size
            continue
        if run is not None and i - run >= min_bytes:
            yield (run, i)
        run = None
        i += 1
    if run is not None and last - run >= min_bytes:
        yield (run, last)


def _utf8_runs(data, first, last, min_bytes, allow_halfwidth=False,
               level2_kanji=False):
    """UTF-8 として成立しうるバイトの連なりを返します。"""
    i = first
    run = None
    while i < last:
        b = data[i]
        size = 0
        if 0x20 <= b <= 0x7E:
            size = 1
        elif 0xC2 <= b <= 0xDF:
            size = 2
        elif 0xE0 <= b <= 0xEF:
            size = 3
        elif 0xF0 <= b <= 0xF4:
            size = 4
        if size and i + size <= last:
            if size == 1 or all(0x80 <= data[i + k] <= 0xBF
                                for k in range(1, size)):
                if run is None:
                    run = i
                i += size
                continue
        if run is not None and i - run >= min_bytes:
            yield (run, i)
        run = None
        i += 1
    if run is not None and last - run >= min_bytes:
        yield (run, last)


def _eucjp_runs(data, first, last, min_bytes, allow_halfwidth=False,
                level2_kanji=False):
    """EUC-JP として成立しうるバイトの連なりを返します。"""
    i = first
    run = None
    while i < last:
        b = data[i]
        size = 0
        if 0x20 <= b <= 0x7E:
            size = 1
        elif 0xA1 <= b <= 0xFE and i + 1 < last and 0xA1 <= data[i + 1] <= 0xFE:
            size = 2
        if size:
            if run is None:
                run = i
            i += size
            continue
        if run is not None and i - run >= min_bytes:
            yield (run, i)
        run = None
        i += 1
    if run is not None and last - run >= min_bytes:
        yield (run, last)


_SCANNERS = {"sjis": ("shift_jis", _sjis_runs),
             "utf8": ("utf-8", _utf8_runs),
             "eucjp": ("euc_jp", _eucjp_runs)}


_KANA = ((0x3041, 0x309F), (0x30A0, 0x30FF), (0xFF66, 0xFF9F))


def _text_verdict(text, min_japanese, min_kana=1):
    """復号できた文字列が「本物らしいか」を判定します。

    戻り値は (採用してよいか, 落とした理由)。理由は呼び出し側で数えて
    「何がどれだけ落ちたか」を応答に出すために使います。
    """
    core = sum(1 for c in text if _in_ranges(ord(c), _JP_CORE))
    if core < min_japanese:
        return False, "日本語が少ない"
    # ★かなを 1 文字は要求します。乱数同然のデータは漢字だけの並びになりがちで
    #   (「秦辛」「桔信」のような形)、本物のゲームテキストは
    #   ほぼ必ずかなを含みます。漢字だけの短い見出し (「時間」等) も
    #   欲しいときは min_kana=0 にしてください。
    if min_kana and sum(1 for c in text if _in_ranges(ord(c), _KANA)) < min_kana:
        return False, "かなを含まない"
    for c in text:
        if not _in_ranges(ord(c), _JP_OK):
            return False, "珍しい符号位置が混ざる"
    return True, None


def _expand_char_table(table):
    """文字対応表を {16進キー: 文字} に展開します。

    独自符号の表はたいてい**連番**なので、1 文字ずつ書かせるのは無駄です。
    次の 3 つの書き方を受け付けます:

        {"00": "あ", "01": "い"}                      そのまま
        {"start": "0x20", "chars": "あいうえお"}      連番 (0x20 から 1 文字ずつ)
        [{"start": "0x20", "chars": "..."}, {...}]    連番を複数ブロック

    連番形式では `width` (既定 1) でキーのバイト幅を指定できます
    (2 バイト符号の表なら width=2)。
    """
    if isinstance(table, dict) and "chars" in table:
        table = [table]
    if not isinstance(table, list):
        return table
    out = {}
    for block in table:
        if not isinstance(block, dict) or "chars" not in block:
            raise ValueError(
                "連番形式のブロックには chars が要ります "
                '(例: {"start": "0x20", "chars": "あいうえお"})。')
        start = _parse_int(block.get("start", 0), "start")
        width = max(1, int(block.get("width", 1)))
        step = max(1, int(block.get("step", 1)))
        for n, ch in enumerate(block["chars"]):
            code = start + n * step
            out["{0:0{1}X}".format(code, width * 2)] = ch
    return out


# ラベル名に使える文字。**3 か所 (apply_labels.py /
# validate_proposed_labels.py / schemas/proposed_labels.schema.json) の
# NAME_RE と同じ規則**にしてあります。ここだけ緩めると
# 「提案は作れるのに反映で弾かれる」になるので、直すときは 4 か所まとめて。


def _label_char_ok(ch, first=False):
    """ラベル名に使える文字かを返します (first=True なら先頭として)。"""
    code = ord(ch)
    if ("A" <= ch <= "Z") or ("a" <= ch <= "z") or ch == "_":
        return True
    if 0x3041 <= code <= 0x3096:          # ひらがな
        return True
    if 0x30A1 <= code <= 0x30FA:          # カタカナ
        return True
    if 0x4E00 <= code <= 0x9FFF:          # 漢字
        return True
    if first:
        return False
    if "0" <= ch <= "9":
        return True
    return code in (0x30FC, 0x30FB)       # 長音符 / 中黒


def _label_from_text(text, prefix=None, max_name=48):
    """ゲーム内テキストからラベル名を作ります。戻り値は (名前, 落とした理由)。

    Ghidra はシンボル名に Unicode を許すので日本語のラベルは付けられますが、
    **空白と記号は入れません** (検索やスクリプトで扱いづらいため)。
    そこで次の正規化をかけます:

      1. 全角英数記号を半角へ (NFKC)。`７４７Ａ` -> `747A`
      2. 使えない文字 (空白 / 記号 / 括弧 / スラッシュ) を `_` へ
      3. `_` の連続をまとめ、前後の `_` を落とす
      4. 先頭が数字 / 長音符 / 中黒なら `_` を足す
      5. Ghidra 自動生成名の接頭辞 (FUN_ / LAB_ / DAT_ …) なら `_` を足す
      6. max_name 文字で切る (長い名前は Listing で読めない)

    例: `テムジン　７４７Ａ／ｃ` -> `テムジン_747A_c`
    """
    import unicodedata

    raw = (text or "").strip()
    if not raw:
        return None, "空文字です。"
# 全角英数記号だけを半角へ寄せる。かな・漢字は NFKC でも変わりません
# (半角カタカナは全角になるので、そちらは意図どおり)。
    norm = unicodedata.normalize("NFKC", raw)

    out = []
    for ch in norm:
        out.append(ch if _label_char_ok(ch) else "_")
    name = "".join(out)
    while "__" in name:
        name = name.replace("__", "_")
    name = name.strip("_")
    if not name:
        return None, "使える文字が 1 つも残りませんでした。"
    if not _label_char_ok(name[0], first=True):
        name = "_" + name
    for reserved in ("FUN_", "LAB_", "DAT_", "SUB_", "UNK_", "EXT_",
                     "switchD_", "caseD_", "PTR_", "ARRAY_"):
        if name.startswith(reserved):
            name = "_" + name
            break
    if prefix:
        name = "{0}{1}".format(prefix, name)
    if len(name) > max_name:
        name = name[:max_name].rstrip("_")
    if not name:
        return None, "切り詰めたら空になりました。"
    return name, None



def _rows(data, key):
    """export の JSON を list として取り出します (dict 包み / 生の list どちらでも)。

    labels.json / defined_data.json は {"labels": [...], "truncated": ...} の形、
    古い export や他のファイルは生の list、という違いを吸収します。
    """
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        value = data.get(key)
        if isinstance(value, list):
            return value
    return []


def _entropy_hint(entropy):
    """エントロピーの値から「その帯に何がよく居るか」を返します。

    決め手が無かったときに「次にどれを試すか」を示すための材料です。
    **断定はしません** — あくまで、その値でよく見かけるものを挙げるだけです。
    """
    if entropy < 1.0:
        return ("エントロピー {0} はほぼ単一の値です。詰め物か、未使用領域の"
                "可能性が高いので後回しで構いません。".format(entropy))
    if entropy < 3.0:
        return ("エントロピー {0} は**疎なデータ**の帯です。色数の少ない "
                "4bpp タイル / 小さい値ばかりの表 / ビットマップでよく出ます。"
                "render_tiles を bpp=4 と bpp=8 の両方で試すのが速いです。"
                .format(entropy))
    if entropy < 5.5:
        return ("エントロピー {0} は表やコードの帯です。read_data で format を"
                "変えて眺めるか、describe_data にストライドを推定させてください。"
                .format(entropy))
    if entropy < 7.0:
        return ("エントロピー {0} は**画像 / 音声 / 圧縮済み**の帯です。"
                "find_compressed_blocks で近くにヘッダが無いか探し、"
                "無ければ render_tiles で見てください。".format(entropy))
    return ("エントロピー {0} はほぼ乱数です。**圧縮済みか暗号化**の可能性が"
            "高いので、find_compressed_blocks で前後のヘッダを探してください "
            "(先頭がヘッダとは限りません)。".format(entropy))


def _zoom_and_label(Image, image, zoom, unit_w, unit_h, units,
                    show_index, index_base, index_hex):
    """タイル画像を拡大し、必要なら各単位に**番号を焼き込みます**。

    フォントの文字対応表を作るとき、「画面の何番目のタイルが符号 0x2A か」を
    人間が数えるのが一番の手間です。番号を絵の中に入れてしまえば、
    見ながらそのまま `decode_text` の表を書き起こせます。

    番号は各単位の**下に帯を足して**描きます (絵に重ねると絵が読めなくなるため)。
    """
    from PIL import ImageDraw

    src_w, src_h = image.size
    big = image.resize((src_w * zoom, src_h * zoom), Image.NEAREST)
    if not show_index:
        return big, big.size[0], big.size[1]

    cell_w = unit_w * zoom
    cell_h = unit_h * zoom
    cols = max(1, big.size[0] // cell_w)
    rows = max(1, (units + cols - 1) // cols)
    strip = 10                      # 番号を書く帯の高さ
    out_w = cols * cell_w
    out_h = rows * (cell_h + strip)
    out = Image.new("RGBA", (out_w, out_h), (0, 0, 0, 255))
    draw = ImageDraw.Draw(out)
    try:
        from PIL import ImageFont
        font = ImageFont.load_default()
    except Exception:
        font = None

    for n in range(units):
        col = n % cols
        row = n // cols
        sx, sy = col * cell_w, row * cell_h
        if sy + cell_h > big.size[1]:
            break
        out.paste(big.crop((sx, sy, sx + cell_w, sy + cell_h)),
                  (col * cell_w, row * (cell_h + strip)))
        value = index_base + n
        text = ("{0:02X}".format(value) if index_hex else str(value))
        draw.text((col * cell_w + 1, row * (cell_h + strip) + cell_h),
                  text, fill=(255, 255, 0, 255), font=font)
    return out, out_w, out_h


_DAT_RE = re.compile(r"\bDAT_([0-9a-fA-F]{8})\b")

# 実行時観測のアドレス表記。**0x 始まりの 16 進文字列だけ**を正規形とする
# (整数や負数を受けると、アドレス基準の取り違えに気づけなくなる)。
_RUNTIME_ADDR = re.compile(r"^0[xX][0-9a-fA-F]+$")


def _parse_dat_address(value):
    """'0x...' でも 'DAT_0803e1fc' でもアドレスとして受け取ります。"""
    if isinstance(value, str):
        text = value.strip()
        m = re.match(r"^(?:DAT|PTR|LAB|UNK)_([0-9a-fA-F]{6,8})$", text)
        if m:
            return int(m.group(1), 16)
    return parse_hex(value)


# --- 構造体フィールド解析の下ごしらえ -------------------------------------
#
# 疑似 C は同じアクセスを何通りにも書きます。単純な文字列一致では半分も拾えません。
# ここは「書き方の揺れ」を吸収する部分で、find_struct_field_uses の本体です。

# キャスト -> 幅。size_hint に使います。
_CAST_SIZE = {
    "byte": "u8", "char": "s8", "undefined1": "u8", "uint8_t": "u8",
    "ushort": "u16", "short": "s16", "undefined2": "u16", "uint16_t": "u16",
    "uint": "u32", "int": "s32", "undefined4": "u32", "uint32_t": "u32",
    "undefined": "u8", "code": "u32", "void": "u32",
}
# untouched_offsets の表示上限。**件数は untouched_total で必ず返します。**
MAX_UNTOUCHED = 256

_SIZE_ORDER = {"u8": 1, "s8": 1, "u16": 2, "s16": 2, "u32": 4, "s32": 4}

_NUM = r"(?:0x[0-9a-fA-F]+|\d+)"
_VAR = r"[A-Za-z_][A-Za-z_0-9]*"


def _num(text):
    """'0x70' / '112' を int にします。"""
    text = text.strip()
    return int(text, 16) if text.lower().startswith("0x") else int(text)


def _join_wrapped(lines):
    """折り返された式を 1 つにまとめ、(まとめた行, 元の行番号) を返します。

    ★Ghidra の疑似 C は長い式を平気で折り返します。例えば:

        uVar3 = uVar3 + *(byte *)((uint)*(byte *)(... + 0x25) * 0x70 +
                                  DAT_08062964 + 0x25);

    行単位で正規表現をかけると**この形を丸ごと取りこぼします**。
    括弧の釣り合いが取れるまで次の行をつなげてから判定します。
    """
    out = []
    starts = []
    buf = None
    start = 0
    for i, line in enumerate(lines):
        if buf is None:
            buf, start = line, i + 1
        else:
            buf += " " + line.strip()
        if buf.count("(") <= buf.count(")") or i + 1 >= len(lines):
            out.append(buf)
            starts.append(start)
            buf = None
    if buf is not None:
        out.append(buf)
        starts.append(start)
    return out, starts


def _base_var_tracker(base_syms, step):
    """ベースを持つ変数を**位置ごとに**追う関数を作ります。

    ★ファイル全体で 1 つの表を作ってから当てては**いけません**。例えば:

          57 行目: iVar4 = param_3 * 0x1c + DAT_x;   ← レコード変数になる
          62 行目: *(byte *)(iVar4 + 0x14)           ← ここは有効
          89 行目: iVar4 = DAT_08050ab8;             ← 別の値で上書き

      全体を先に走査すると 89 行目の上書きで iVar4 が捨てられ、
      **62 行目のアクセスまで丸ごと落ちます**。
      チャンクを順に見て、「その時点の状態」で判定します。

    戻り値は (base_vars, record_vars, update) の 3 つ。`update(chunk)` を
    **アクセスを拾った後に**呼んで、次の行のために状態を進めます。

    戻り値は (base_vars, record_vars):

      base_vars   … ベースそのもの (+K) を持つ変数。`iVar2 = DAT_x;`
                    → 使うときは `i * stride + iVar2 + off` の形になる
      record_vars … ベース + stride*i (+K) を持つ変数。`iVar3 = i * 0x70 + DAT_x;`
                    → 使うときは `iVar3 + off` の形になる

    ★K (定数の足し込み) は覚えておいて、後でオフセット側に繰り込みます。
      `iVar5 = DAT_x + 0x25;` の後の `*(byte *)(i * 0x70 + iVar5)` は
      オフセット 0x25 のアクセスです ((d) 型)。

    ★**再代入されたら捨てます。** 同じ変数が別の値で上書きされた後まで
      ベース扱いすると、無関係なアクセスを拾って嘘をつきます。
    """
    base_vars = {}
    record_vars = {}
    sym = "(?:" + "|".join(re.escape(s) for s in sorted(base_syms)) + ")"
    hexed = "0x{0:x}".format(step)
    # iVar2 = DAT_x;  /  iVar2 = DAT_x + 0x25;
    re_base = re.compile(r"^\s*(" + _VAR + r")\s*=\s*(?:\([^)]*\)\s*)?" + sym
                         + r"\s*(?:\+\s*(" + _NUM + r"))?\s*;")
    # iVar3 = <何か> * 0x70 + DAT_x;  /  iVar3 = DAT_x + <何か> * 0x70;
    re_rec_a = re.compile(r"^\s*(" + _VAR + r")\s*=\s*.*?\*\s*(?:" + hexed
                          + r"|" + str(step) + r")\s*\+\s*" + sym
                          + r"\s*(?:\+\s*(" + _NUM + r"))?\s*;")
    re_rec_b = re.compile(r"^\s*(" + _VAR + r")\s*=\s*" + sym
                          + r"\s*\+\s*.*?\*\s*(?:" + hexed + r"|" + str(step)
                          + r")\s*(?:\+\s*(" + _NUM + r"))?\s*;")
    re_assign = re.compile(r"^\s*(" + _VAR + r")\s*=[^=]")
    # ★行頭の代入だけでは足りません。Ghidra は条件式の中で代入します:
    #
    #     if (((param_2 == -2) && (iVar1 = DAT_0807ab44, uVar3 != 0xff)) || ...
    #
    #   この形を拾わないと、そのあとの `uVar2 * 0x70 + iVar1 + 0x38` を
    #   丸ごと取りこぼします。
    #   右辺がベース記号そのものである場合に限って拾います (誤検出を避けるため)。
    re_inline = re.compile(r"(" + _VAR + r")\s*=\s*" + sym
                           + r"\s*(?:\+\s*(" + _NUM + r"))?\s*[,)]")

    def update(chunk):
        """1 チャンクぶん状態を進めます (アクセスを拾った後に呼ぶこと)。"""
        m = re_rec_a.match(chunk) or re_rec_b.match(chunk)
        if m:
            record_vars[m.group(1)] = _num(m.group(2)) if m.group(2) else 0
            base_vars.pop(m.group(1), None)
            return
        m = re_base.match(chunk)
        if m:
            base_vars[m.group(1)] = _num(m.group(2)) if m.group(2) else 0
            record_vars.pop(m.group(1), None)
            return
        inline = list(re_inline.finditer(chunk))
        if inline:
            for m in inline:
                base_vars[m.group(1)] = _num(m.group(2)) if m.group(2) else 0
                record_vars.pop(m.group(1), None)
            return
        m = re_assign.match(chunk)
        if m:
            # 別の値で上書きされた → ここから先はベース扱いをやめる。
            base_vars.pop(m.group(1), None)
            record_vars.pop(m.group(1), None)

    return base_vars, record_vars, update


def _enclosing_paren(chunk, pos):
    """pos を囲んでいる `(` の位置を返します (無ければ -1)。"""
    depth = 0
    for i in range(pos - 1, -1, -1):
        ch = chunk[i]
        if ch == ")":
            depth += 1
        elif ch == "(":
            if depth == 0:
                return i
            depth -= 1
    return -1


def _cast_before(chunk, pos):
    """そのアクセスの幅を、**囲んでいる括弧の直前のキャスト**から推定します。

    ★「手前にある最後のキャスト」では駄目です。例えば:

        *(byte *)((uint)*(byte *)(iVar4 + 0x23) * 0x70 + iVar2 + 0x25)
                        ~~~~~~~~~ これは内側の別アクセスのキャスト

      `* 0x70` の手前を素朴に見ると内側の `*(byte *)` を拾ってしまい、
      外側の幅と取り違えます。括弧の対応を数えて**自分を囲む `(`** を探し、
      その直前のキャストを見ます。
    """
    open_at = _enclosing_paren(chunk, pos)
    while open_at >= 0:
        head = chunk[max(0, open_at - 32):open_at]
        m = re.search(r"\*\s*\(\s*(" + _VAR + r")\s*\*+\s*\)\s*$", head)
        if m:
            return _CAST_SIZE.get(m.group(1), "u32")
        # `((uint)...)` のような余分な括弧なら 1 つ外へ。
        if re.search(r"\(\s*$", head) or re.search(r"\)\s*$", head):
            open_at = _enclosing_paren(chunk, open_at)
            continue
        break
    return "u32"


def _kind_of(chunk, pos):
    """代入の左辺なら write、それ以外は read。"""
    eq = chunk.find("=")
    if eq < 0 or chunk[eq:eq + 2] in ("==", "=="):
        return "read"
    return "write" if pos < eq else "read"


def _match_field_access(chunk, base_syms, base_vars, record_vars, step):
    """1 つの式から `base + stride*i + offset` のアクセスを取り出します。"""
    hits = []
    hexed = "(?:0x{0:x}|{1})".format(step, step)
    sym = "(?:" + "|".join(re.escape(s) for s in sorted(base_syms)) + ")"

    def add(pos, offset, expr):
        hits.append({"offset": offset, "size_hint": _cast_before(chunk, pos),
                     "kind": _kind_of(chunk, pos), "expr": expr.strip()[:200]})

    # (a)(b) <何か> * stride + <ベース> [+ off]
    bases = [sym] + [re.escape(v) for v in sorted(base_vars)]
    for b in bases:
        pat = re.compile(r"\*\s*" + hexed + r"\s*\+\s*(" + b
                         + r")\s*(?:\+\s*(" + _NUM + r"))?")
        for m in pat.finditer(chunk):
            extra = base_vars.get(m.group(1), 0)
            off = (_num(m.group(2)) if m.group(2) else 0) + extra
            add(m.start(), off, chunk)
    # (a')(b') <ベース> + <何か> * stride [+ off]  (順序が逆の書き方)
    for b in bases:
        pat = re.compile(r"(" + b + r")\s*\+\s*[^;]{0,60}?\*\s*" + hexed
                         + r"\s*(?:\+\s*(" + _NUM + r"))?")
        for m in pat.finditer(chunk):
            extra = base_vars.get(m.group(1), 0)
            off = (_num(m.group(2)) if m.group(2) else 0) + extra
            if not any(h["offset"] == off and h["expr"] == chunk.strip()[:200]
                       for h in hits):
                add(m.start(), off, chunk)
    # (c) <レコード変数> + off
    for var, extra in sorted(record_vars.items()):
        pat = re.compile(r"\b" + re.escape(var) + r"\s*\+\s*(" + _NUM + r")\b")
        for m in pat.finditer(chunk):
            add(m.start(), _num(m.group(1)) + extra, chunk)
        # オフセット 0 (レコード先頭) の参照
        for m in re.finditer(r"\*\s*\([^)]*\*+\s*\)\s*\(\s*"
                             + re.escape(var) + r"\s*\)", chunk):
            add(m.start(), extra, chunk)

    # 同じ式から同じオフセットを複数回拾わない。
    unique = {}
    for h in hits:
        unique.setdefault((h["offset"], h["kind"]), h)
    return list(unique.values())


def _unmatched_hint(chunk, step, base_syms, base_vars, record_vars):
    """stride は合うのにベースを特定できなかった行を返します (黙って落とさない)。"""
    hexed = "0x{0:x}".format(step)
    if hexed not in chunk and "* {0}".format(step) not in chunk:
        return None
    if any(s in chunk for s in base_syms):
        return None
    if any(re.search(r"\b" + re.escape(v) + r"\b", chunk)
           for v in list(base_vars) + list(record_vars)):
        return None
    return chunk.strip()[:160]


def _context_lines(lines, index, count):
    """その行の前後 count 行を返します。"""
    if count <= 0:
        return []
    lo = max(0, index - count)
    hi = min(len(lines), index + count + 1)
    return [lines[i].rstrip() for i in range(lo, hi)]


def _struct_zero_hint(step):
    """0 件だったときに「無い」と結論させないためのヒントです。"""
    return {
        "message": "0 件でした。**「使われていない」と結論する前に**下を疑ってください。",
        "blind_spots": [
            "ベースが関数の引数で渡されている (この関数内に DAT_ が無い)。",
            "ポインタ演算で 1 レコードずつ進めている (p = p + 0x{0:x} の形)。".format(step),
            "別の関数へベースを渡し、その中で参照している。",
            "stride が違う (レコード長の推定を間違えている)。"
                "offset 省略モードの untouched_offsets が穴だらけなら、まずこれを疑う。",
            "その Program の decompile/ が一部しか export されていない "
                "(decompile_limit / decompile_targets を確認)。",
        ],
        "next_steps": [
            "offset を省略して呼び、どのオフセットが拾えているかを見る。",
            "unmatched_hints を見る (stride は合うのにベースを特定できなかった行)。",
            "find_address_refs / find_pointers_to でベースを指す箇所から辿る。",
        ],
    }


def _parallel_groups(tables, data_of, in_range, min_tables=3):
    """検出済みの表のうち、**平行に並んでいるもの**をグループにまとめます。

    GBA のリソースはほぼ必ずこの形をしています:

        0x0828558C  幅・高さ  x36  ┐
        0x08285620  パレット  x36  │  0x94 間隔で 6 本が平行
        0x082856B4  タイル    x36  │  i 番目の要素どうしが 1 セット
        0x08285748  マップL1  x36  ┘

    1 本ずつ見つけても構造が見えません。**要素数が同じで、開始番地が等間隔**
    に並ぶものをまとめて返します。

    `data_of(addr)` は「その番地の 32bit 値」、`in_range(value)` は
    「その値が探している範囲を指すか」を返す関数です。

    ★**グループの先頭は表として検出されないことがあります。** 表の切れ目は
      0 終端で判る作りですが、**1 本目の手前には終端がない**ので、手前から続く
      長い連なりの一部として飲み込まれ、グループから漏れます。
      そこで、グループができたら**同じ間隔で 1 つ手前**を見て、そこにも
      同じ要素数ぶん有効な値が並んでいればグループに加えます。
    """
    by_count = {}
    for t in tables:
        start = try_parse_hex(t.get("table_addr") or "")
        count = t.get("entry_count")
        stride = try_parse_hex(t.get("stride") or "") or 4
        if start is None or not count or stride != 4:
            continue                       # 平行表は連続 u32 が前提
        by_count.setdefault(count, []).append(start)

    groups = []
    for count, starts in by_count.items():
        starts = sorted(set(starts))
        used = set()
        for i, first in enumerate(starts):
            if first in used:
                continue
            for j in range(i + 1, len(starts)):
                spacing = starts[j] - first
                if spacing <= 0:
                    continue
                chain = [first]
                nxt = first + spacing
                while nxt in starts:
                    chain.append(nxt)
                    nxt += spacing
                if len(chain) >= min_tables and not (set(chain) & used):
                    # 1 本目の手前へ延ばす (上の ★ の理由)。
                    # ★ただし**同じ終端を持つものだけ**にすること。値が
                    #   範囲内なだけでは、手前から続く長い並びを 36 個ずつ
                    #   切り取って「表」に見せてしまいます。
                    body = count * 4
                    marker = data_of(first + body) if spacing - body == 4 else None
                    while marker is not None:
                        prev = chain[0] - spacing
                        if prev < 0 or prev in used:
                            break
                        if data_of(prev + body) != marker:
                            break
                        values = [data_of(prev + k * 4) for k in range(count)]
                        if any(v is None or not in_range(v) for v in values):
                            break
                        chain.insert(0, prev)
                    used.update(chain)
                    body = count * 4
                    gap = spacing - body
                    note = ("各表は {0} 要素 x 4 バイト = 0x{1:x}。"
                            "間隔 0x{2:x} との差は 0x{3:x} バイトです".format(
                                count, body, spacing, gap))
                    term = None
                    if gap == 4:
                        term = data_of(first + body)
                        note += ("。表の直後に 1 ワード入るので、"
                                 "終端マーカーの可能性があります")
                    elif gap:
                        note += " (詰め物か、別のデータが挟まっています)"
                    groups.append({
                        "tables": ["0x{0:08x}".format(a) for a in chain],
                        "entries": count,
                        "table_spacing": "0x{0:x}".format(spacing),
                        "terminator": (None if term is None
                                       else "0x{0:08x}".format(term)),
                        "note": note,
                    })
                    break
    groups.extend(_split_interleaved(tables, data_of, used, min_tables))
    groups.sort(key=lambda g: (-len(g["tables"]), g["tables"][0]))
    return groups


def _split_interleaved(tables, data_of, used, min_tables):
    """**区切りの無い**並行表を、1 本に見えている長い並びから割り出します。

    ★終端が入らない書き方もあります。例えば 4 本 x 5 要素が **隙間なく**
      並んでいると、走査側からは 20 要素の表 1 本にしか見えません。

    見分ける手掛かりは**列ごとのまとまり**です。i 本目の j 番目どうしは
    同じ種類のリソースを指すので、値が近い番地に固まります:

        0824E09C 08250C30 082546EC 082574F8 0825A074   <- 1 本目
        0824EA7C 08251650 0825510C 08257EF8 0825AA54   <- 2 本目
        0824E11C 08250CF0 ...                          <- 3 本目
        ~~~~~~~~ ~~~~~~~~ 列ごとに 0x0824E / 0x08250 と固まっている

    列ごとの散らばりが全体の散らばりよりはっきり小さいときだけ割ります。
    **推定なので note にそう書きます。**
    """
    out = []
    for t in tables:
        start = try_parse_hex(t.get("table_addr") or "")
        count = t.get("entry_count") or 0
        stride = try_parse_hex(t.get("stride") or "") or 4
        if start is None or stride != 4 or start in used or count < 9:
            continue
        values = [data_of(start + k * 4) for k in range(count)]
        if any(v is None for v in values):
            continue
        whole = max(values) - min(values)
        if whole <= 0:
            continue
        best = None
        for sub in range(3, count // min_tables + 1):
            if count % sub:
                continue
            parts = count // sub
            if parts < min_tables:
                continue
            spreads = []
            for j in range(sub):
                col = [values[k * sub + j] for k in range(parts)]
                spreads.append(max(col) - min(col))
            score = (sum(spreads) / float(sub)) / float(whole)
            # 列ごとの散らばりが全体の 1/3 未満なら「列にまとまっている」。
            if score < 0.34 and (best is None or score < best[0]):
                best = (score, sub, parts)
        if best is None:
            continue
        _score, sub, parts = best
        used.add(start)
        out.append({
            "tables": ["0x{0:08x}".format(start + k * sub * 4)
                       for k in range(parts)],
            "entries": sub,
            "table_spacing": "0x{0:x}".format(sub * 4),
            "terminator": None,
            "note": ("**区切りが無いので、1 本の表 (0x{0:08x} / {1} 要素) を"
                     "列のまとまりから {2} 本 x {3} 要素に割った推定です。**"
                     "列ごとの散らばりが全体の {4:.0%} しかないので"
                     "平行表とみなしました。read_data で中身を見て確かめてください。"
                     .format(start, count, parts, sub, _score)),
        })
    return out


# --- 実行ファイルからバイトを供給するフォールバック ------------------------
#
# ★`export_memory: false` の Program では、memory_map.json が無いので
#   get_disassembly / read_data / find_bytes / find_address_refs / find_writers が
#   そのままでは使えません。しかし `source_model=executable` なら実行ファイルは手元にあり、
#   program.json に `executable_path` と `memory_blocks` があります。
#   ELF のプログラムヘッダ (p_vaddr / p_offset / p_filesz) を読めば
#   「この番地はファイルのどこか」が分かるので、メモリ export が無くても
#   同じツールが動きます。再 export を待たずに解析を始められます。


def _elf_segments(data):
    """ELF のロード可能セグメントを [(vaddr, file_offset, filesz)] で返します。

    ELF32 / ELF64 の両エンディアンに対応します。ELF でなければ None。
    """
    if len(data) < 0x34 or data[:4] != b"\x7fELF":
        return None
    is64 = data[4] == 2
    big = data[5] == 2
    end = ">" if big else "<"
    try:
        if is64:
            e_phoff, = struct.unpack_from(end + "Q", data, 0x20)
            e_phentsize, e_phnum = struct.unpack_from(end + "HH", data, 0x36)
        else:
            e_phoff, = struct.unpack_from(end + "I", data, 0x1C)
            e_phentsize, e_phnum = struct.unpack_from(end + "HH", data, 0x2A)
    except struct.error:
        return None

    out = []
    for i in range(min(e_phnum, 128)):
        off = e_phoff + i * e_phentsize
        try:
            if is64:
                p_type, = struct.unpack_from(end + "I", data, off)
                p_offset, p_vaddr = struct.unpack_from(end + "QQ", data, off + 8)
                p_filesz, = struct.unpack_from(end + "Q", data, off + 0x20)
            else:
                (p_type, p_offset, p_vaddr, _p_paddr,
                 p_filesz) = struct.unpack_from(end + "5I", data, off)
        except struct.error:
            break
        if p_type != 1 or not p_filesz:          # PT_LOAD のみ
            continue
        out.append((p_vaddr, p_offset, p_filesz))
    return out or None


# ELF の section type。
_SHT_SYMTAB = 2
_SHT_MIPS_REGINFO = 0x70000006
# シンボルとして拾う STT (OBJECT / FUNC / NOTYPE)。SECTION / FILE は名前ではない。
_ELF_SYMBOL_TYPES = {0: "notype", 1: "object", 2: "func"}
# .symtab から読むシンボルの上限 (巨大なデバッグ付き ELF で膨らまないように)。
MAX_ELF_SYMBOLS = 200000


def _elf_extras(data):
    """ELF32 から entry / .reginfo の gp / .symtab のシンボルを取り出します。

    返り値: {"entry": int|None, "reginfo_gp": int|None,
             "symbols": [(name, value, size, kind)]}。ELF32 でなければ None。

    ★MCP は Ghidra に問い合わせないが、実行ファイルはもともと読んでいる
      (memory 未 export 時のバイト供給)。ここから取れる gp と名前は、
      labels.json が無い古い export でも使える (`_gp` などが .symtab にしか無いことがある)。
    """
    if len(data) < 0x34 or data[:4] != b"\x7fELF" or data[4] != 1:
        return None
    end = ">" if data[5] == 2 else "<"
    try:
        e_entry, = struct.unpack_from(end + "I", data, 0x18)
        e_shoff, = struct.unpack_from(end + "I", data, 0x20)
        e_shentsize, e_shnum = struct.unpack_from(end + "HH", data, 0x2E)
    except struct.error:
        return None
    out = {"entry": e_entry or None, "reginfo_gp": None, "symbols": []}
    sections = []
    if e_shoff and e_shentsize >= 40:
        for i in range(min(e_shnum, 4096)):
            try:
                sections.append(struct.unpack_from(
                    end + "10I", data, e_shoff + i * e_shentsize))
            except struct.error:
                break
    for sec in sections:
        (_name, sh_type, _flags, _addr, sh_offset, sh_size, sh_link,
         _info, _align, sh_entsize) = sec
        if sh_type == _SHT_MIPS_REGINFO and sh_size >= 24:
            # Elf32_RegInfo: ri_gprmask, ri_cprmask[4], ri_gp_value
            try:
                gp, = struct.unpack_from(end + "I", data, sh_offset + 20)
                out["reginfo_gp"] = gp or None
            except struct.error:
                pass
        elif sh_type == _SHT_SYMTAB and sh_link < len(sections):
            str_off = sections[sh_link][4]
            str_size = sections[sh_link][5]
            step = sh_entsize or 16
            for k in range(min(sh_size // step, MAX_ELF_SYMBOLS)):
                try:
                    (st_name, st_value, st_size, st_info, _other,
                     st_shndx) = struct.unpack_from(
                         end + "IIIBBH", data, sh_offset + k * step)
                except struct.error:
                    break
                kind = _ELF_SYMBOL_TYPES.get(st_info & 0xF)
                if kind is None or not st_name or st_name >= str_size:
                    continue
                if st_shndx == 0:              # SHN_UNDEF (外部参照)
                    continue
                start = str_off + st_name
                stop = data.find(b"\x00", start, str_off + str_size)
                if stop < 0:
                    continue
                name = data[start:stop].decode("latin-1")
                if name:
                    out["symbols"].append((name, st_value, st_size, kind))
    return out


# DOL (GameCube / Wii) のヘッダ: text 7 + data 11 = 18 セクション。
_DOL_SECTIONS = 18
_DOL_HEADER_SIZE = 0x100
# DOL が載ってよい範囲 (MEM1 キャッシュ 0x80000000-0x817fffff /
# Wii MEM2 キャッシュ 0x90000000-0x93ffffff)。
_DOL_LOAD_RANGES = ((0x80000000, 0x81800000), (0x90000000, 0x94000000))


def _dol_segments(data):
    """GameCube / Wii の DOL なら [(vaddr, file_offset, size)] を返します。

    DOL でなければ None。DOL には魔法数が無いので、ヘッダ全体の整合
    (offset がヘッダ以降かつファイル内 / 載せ先が MEM1・MEM2 / 4 バイト境界 /
    ファイル内の範囲が重ならない / entry が text の中) で判定します。
    raw binary を DOL と取り違えないよう、どれか 1 つでも崩れたら None です。

    ★平置きで読むと 0x80062dc0 がファイル 0x62dc0 になり、全く別の
      バイトを返す。
    """
    if len(data) < _DOL_HEADER_SIZE:
        return None
    try:
        offsets = struct.unpack_from(">18I", data, 0x00)
        addrs = struct.unpack_from(">18I", data, 0x48)
        sizes = struct.unpack_from(">18I", data, 0x90)
        entry, = struct.unpack_from(">I", data, 0xE0)
    except struct.error:
        return None
    out = []
    has_text = False
    entry_in_text = False
    for i in range(_DOL_SECTIONS):
        off, va, ln = offsets[i], addrs[i], sizes[i]
        if not ln:
            continue
        if off < _DOL_HEADER_SIZE or off + ln > len(data):
            return None
        if (off | va) & 3:
            return None
        if not any(lo <= va and va + ln <= hi for lo, hi in _DOL_LOAD_RANGES):
            return None
        if i < 7:
            has_text = True
            if va <= entry < va + ln:
                entry_in_text = True
        out.append((va, off, ln))
    if not has_text or not entry_in_text:
        return None
    spans = sorted((off, off + ln) for _va, off, ln in out)
    for (_a0, a1), (b0, _b1) in zip(spans, spans[1:]):
        if b0 < a1:
            return None
    return out


class ExecutableImage(object):
    """実行ファイルを「番地 -> ファイル位置」で引けるようにしたものです。"""

    def __init__(self, path, image_base=None):
        """ELF / DOL ならセクション表を、そうでなければ image_base に平置きします。"""
        self.path = Path(path)
        self.size = self.path.stat().st_size
        # ★丸ごと読む前に大きさで断る (セクション表と .symtab を読むために全体が要る)。
        data = _read_bytes_capped(self.path, MAX_EXECUTABLE_BYTES, "実行ファイル")
        self.segments = _elf_segments(data)
        self.kind = "elf"
        # ELF32 の entry / .reginfo の gp / .symtab (gp と名前の補助に使う)。
        self.elf = _elf_extras(data) if self.segments is not None else None
        if self.segments is None:
            # GameCube / Wii の DOL はセクションごとに載せ先が飛ぶ。
            # 平置きにすると番地とファイル位置が全くずれる。
            self.segments = _dol_segments(data)
            self.kind = "dol"
        if self.segments is None:
            # ELF でなければ「image_base にファイルをそのまま載せた」とみなす。
            # GBA ROM / raw binary はこの形です。
            base = image_base if image_base is not None else 0
            self.segments = [(base, 0, self.size)]
            self.kind = "flat"

    def locate(self, addr):
        """その番地を含むセグメントを (vaddr, file_offset, filesz) で返します。"""
        for vaddr, offset, filesz in self.segments:
            if vaddr <= addr < vaddr + filesz:
                return (vaddr, offset, filesz)
        return None

    def file_offset(self, addr):
        """その番地のファイル内 offset を返します (載っていなければ None)。"""
        seg = self.locate(addr)
        if seg is None:
            return None
        return seg[1] + (addr - seg[0])

    def address_of(self, offset):
        """ファイル内 offset の番地を返します (どのセグメントにも無ければ None)。"""
        for vaddr, seg_off, filesz in self.segments:
            if seg_off <= offset < seg_off + filesz:
                return vaddr + (offset - seg_off)
        return None

    def read(self, addr, length):
        """番地から length バイト読みます (セグメントの末尾で切ります)。"""
        seg = self.locate(addr)
        if seg is None:
            return b""
        vaddr, offset, filesz = seg
        avail = filesz - (addr - vaddr)
        take = max(0, min(int(length), avail))
        if not take:
            return b""
        with self.path.open("rb") as handle:
            handle.seek(offset + (addr - vaddr))
            return handle.read(take)


def _has_bytes(block):
    """そのブロックの実体を読めるか (memory の .bin か、実行ファイル由来か)。

    ★`block.get("file")` だけを見ないこと。memory を export していない
      Program では、実行ファイルからバイトを供給しています (source=executable)。
      file だけで判定すると、そういう Program で走査系が黙って 0 件になります。
    """
    return bool(block.get("file") or block.get("source") in ("executable", "overlay"))

def _scannable(blocks):
    """全域走査してよいブロックだけを残します。

    オーバーレイに "scan": false が付いていたら外します。Program のブロックと
    範囲が重なるオーバーレイを登録したとき、走査系で同じ番地が二重に出るのを
    避けるためです (アドレス指定の読み出しは scan に関係なく効きます)。
    """
    return [b for b in blocks if b.get("scan", True)]


def clamp_limit(limit):
    """limit を 1〜MAX_LIMIT の範囲に収めます。"""
    try:
        value = int(limit)
    except (TypeError, ValueError):
        return DEFAULT_LIMIT
    if value < 1:
        return 1
    if value > MAX_LIMIT:
        return MAX_LIMIT
    return value


def _parse_mask(mask):
    """アドレスマスクを int に正規化します ('0xffff0000' 文字列も受け付けます)。"""
    if mask is None:
        return 0xFFFFFFFF
    if isinstance(mask, str):
        text = mask.strip()
        if not text:
            return 0xFFFFFFFF
        try:
            value = int(text, 16) if text.lower().startswith("0x") else int(text)
        except ValueError:
            raise ValueError("mask '{0}' を数値として解釈できません。".format(mask))
    else:
        try:
            value = int(mask)
        except (TypeError, ValueError):
            raise ValueError("mask '{0}' を数値として解釈できません。".format(mask))
    value &= 0xFFFFFFFF
    if value == 0:
        raise ValueError("mask に 0 は指定できません (全アドレスが一致してしまいます)。")
    return value


# Windows の予約デバイス名 (拡張子を付けても古い Windows ではデバイスを開く)。
_RESERVED_NAMES = frozenset(
    ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"]
    + ["COM{0}".format(c) for c in "123456789¹²³"]
    + ["LPT{0}".format(c) for c in "123456789¹²³"])


def _is_unc_or_device(text):
    """UNC (\\\\server\\share) / デバイス名前空間 (\\\\?\\ \\\\.\\) のパス表記なら True。"""
    t = str(text).strip().replace("/", "\\")
    return t.startswith("\\\\")


def _is_device_namespace(text):
    """\\\\?\\ / \\\\.\\ (Win32 デバイス名前空間) のパス表記なら True。"""
    t = str(text).strip().replace("/", "\\")
    return t.startswith("\\\\?\\") or t.startswith("\\\\.\\")


def _path_within(path, root):
    """resolve 済みの path が resolve 済みの root 自身かその配下なら True。"""
    return path == root or root in path.parents


def _check_name_component(part, what="出力先"):
    """ファイル名 1 要素として安全か確かめます (だめなら ValueError)。

    予約デバイス名 (CON / NUL / COM1 …)、代替データストリーム (`:`)、
    末尾のドット / 空白、制御文字を拒否します。
    """
    text = str(part)
    if text in ("", ".", ".."):
        raise ValueError("{0}のパスに '{1}' は使えません。".format(what, text))
    if any(ord(ch) < 0x20 for ch in text) or any(ch in text for ch in ':*?"<>|'):
        raise ValueError(
            "{0}のファイル名に使えない文字があります: {1!r}".format(what, text))
    if text.endswith((".", " ")):
        raise ValueError(
            "{0}のファイル名の末尾にドットや空白は使えません: {1!r}".format(what, text))
    if text.split(".")[0].strip().upper() in _RESERVED_NAMES:
        raise ValueError(
            "{0}のファイル名に Windows の予約デバイス名は使えません: {1!r}".format(
                what, text))


def _read_bytes_capped(path, cap, what):
    """path を最大 cap バイトまで読みます。大きければ**読む前に**断ります。

    stat で断ったあとも、読む間に伸びた場合に備えて cap+1 バイトまでしか読みません。
    """
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ValueError("{0} を開けません: {1}".format(what, exc.strerror or exc))
    if size > cap:
        raise ValueError(
            "{0} が大きすぎます ({1} バイト > 上限 {2})。読み込みを中止しました。".format(
                what, size, cap))
    with path.open("rb") as handle:
        data = handle.read(cap + 1)
    if len(data) > cap:
        raise ValueError(
            "{0} が読み込み中に上限 {1} バイトを超えました。".format(what, cap))
    return data


def _read_text_capped(path, cap, what):
    """_read_bytes_capped の UTF-8 テキスト版です。

    Path.read_text() と同じく改行を \n にそろえます (universal newlines)。
    疑似 C の本文 (`code`) を従来と 1 文字も変えないためです。
    """
    text = _read_bytes_capped(path, cap, what).decode("utf-8")
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _parse_int(value, what):
    """'0x...' 文字列 / 10 進文字列 / 整数を int にします。"""
    if value is None:
        raise ValueError("{0} が指定されていません。".format(what))
    if isinstance(value, str):
        text = value.strip()
        # 符号つきの 16 進も受ける (差分の規則は "-0x80000000" のように書く)。
        sign = 1
        if text[:1] in ("+", "-"):
            sign = -1 if text[0] == "-" else 1
            text = text[1:].strip()
        try:
            body = int(text, 16) if text.lower().startswith("0x") else int(text)
        except ValueError:
            raise ValueError("{0} '{1}' を数値として解釈できません。".format(what, value))
        return sign * body
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ValueError("{0} '{1}' を数値として解釈できません。".format(what, value))


def clamp_count(value, default, maximum):
    """件数指定を 1〜maximum に収めます (解釈できなければ default)。"""
    try:
        count = int(value)
    except (TypeError, ValueError):
        return default
    if count < 1:
        return 1
    if count > maximum:
        return maximum
    return count


class ExportRepo(object):
    """ghidra_exports/ 配下の JSON / decompile を読み取り専用で提供するリポジトリです。

    読み込んだ JSON はインスタンス内にキャッシュします (stdio サーバは常駐するため)。
    """

    def __init__(self, project_root):
        """プロジェクトルートと exports ディレクトリを検証して初期化します。"""
        self.project_root = Path(project_root).resolve()
        self.exports_dir = self.project_root / "ghidra_exports"
        self.decompile_dir = self.exports_dir / "decompile"
        self.memory_dir = self.exports_dir / "memory"
        if not self.exports_dir.is_dir():
            raise SystemExit(
                "エラー: ghidra_exports/ が見つかりません: {0}\n"
                "先に Ghidra GUI で export_context.py を実行してください。".format(self.exports_dir))
        # filename -> (mtime, data)。ファイル更新を検知したら自動で読み直します。
        self._cache = {}
        # xref 索引と、それを構築した時点の xrefs.json mtime。
        self._xref_index = None
        self._xref_index_mtime = None
        # 即値ペア索引: bin ファイル名 -> (mtime, {合成アドレス: [(参照元, form, lui)]})。
        self._ref_index = {}
        # シンボル索引 (read_data の注釈用) と、構築時点の mtime。
        self._symbols = None
        self._symbols_mtime = None
        # 全域走査ツール用の .bin キャッシュ (直近 1 ブロックだけ)。
        self._image_cache = None
        # 実行ファイル。False = まだ探していない / None = 見つからない。
        self._exe_image = False
        # 実行時観測 (runtime_observations/*.json)。ファイル名 -> (mtime, 解析結果)。
        self._runtime_cache = {}
        # datatypes.json の索引と、構築時点の mtime。
        self._types = None
        self._types_mtime = None
        # gp の計算結果 (元ファイルの mtime の組, 結果)。
        self._gp_cache = None
        # 実行ファイルの .symtab 索引 (ELF 情報の id, 索引)。
        self._elf_symbols = None

    # --- 読み取り境界 (リンク / ジャンクション経由の脱出を塞ぐ) ---------------
    def _trusted_dir(self, path, what):
        """path (プロジェクト内の基準ディレクトリ) の実体を resolve して返します。

        ★基準ディレクトリを resolve しただけで信用しないこと。ghidra_exports/ や
          decompile/ 自体が外部へのリンク / ジャンクションなら、実体は外にあります。
          **実体がプロジェクトフォルダの中にあるときだけ**基準として使います
          (プロジェクト内に収まるリンクは従来どおり使えます)。
        """
        try:
            real = Path(path).resolve()
        except (OSError, RuntimeError):
            raise ValueError("{0} を解決できません。".format(what))
        if not _path_within(real, self.project_root):
            raise ValueError(
                "{0} の実体がプロジェクトフォルダの外です (リンク / ジャンクション)。"
                "読みません。".format(what))
        return real

    def _checked_file(self, base_dir, name, what):
        """base_dir / name を resolve し、base_dir の実体の配下なら返します。

        個別ファイルがリンクで外 (base_dir の外) を指していたら拒否します。
        存在の確認はこの後で呼び出し側が行います (範囲外なら有無を言わない)。
        """
        base_real = self._trusted_dir(base_dir, what)
        try:
            real = (Path(base_dir) / name).resolve()
        except (OSError, RuntimeError):
            raise ValueError("不正なパスです ({0} の配下を解決できません)。".format(what))
        if real == base_real or not _path_within(real, base_real):
            raise ValueError(
                "不正なパスです。{0} の配下 (リンクの実体も含めて) だけ参照できます。".format(what))
        return real

    def _project_relative(self, text, what):
        """設定 / export 情報に書かれたパス文字列を、触る前に検査して Path にします。

        - UNC / デバイスパスは**文字列のまま**拒否します (stat / resolve 等で触らない)。
        - 相対パスはプロジェクトフォルダ基準です (起動時のカレントに依存させない)。
          `C:foo` (ドライブ相対) や `\\foo` (ルート相対) はカレントに依存するので拒否します。
        """
        s = str(text or "").strip()
        if not s or "\x00" in s:
            raise ValueError("{0} が空か、不正な文字を含みます。".format(what))
        if _is_unc_or_device(s):
            raise ValueError("{0} に UNC / デバイスパスは使えません。".format(what))
        p = Path(s)
        if not p.is_absolute():
            if p.drive or p.root:
                raise ValueError(
                    "{0} はドライブ相対 / ルート相対のパスです。絶対パスか、"
                    "プロジェクトフォルダからの相対パスで書いてください。".format(what))
            p = self.project_root / p
        return p

    def _resolve_allowed_file(self, text, what, allow_project=False):
        """設定 / export 情報に書かれたファイルを許可ルートで検査して返します。

        許可ルートは source_path と同じ (`_source_roots()`)。allow_project=True なら
        プロジェクトフォルダ全体も許可します (cdl_jsonl のように、人間が設定に書いた
        プロジェクト内の場所を従来どおり読むため)。
        ★範囲外のときは**ファイルの有無を確かめずに**拒否します。
        """
        p = self._project_relative(text, what)
        try:
            real = p.resolve()
        except (OSError, RuntimeError):
            raise ValueError("{0} を解決できません。".format(what))
        roots = list(self._source_roots())
        if allow_project:
            roots.append(self.project_root)
        if not any(_path_within(real, r) and real != r for r in roots):
            raise ValueError(
                "{0} は許可ルートの外です (存在は確認していません)。読ませるときは、"
                "人間が bridge_config.json の source_roots にそのフォルダを"
                "書き足してください。".format(what))
        return real

    def _load(self, filename):
        """指定 JSON を UTF-8 で読み込みキャッシュします。

        ファイルの mtime が変わっていれば自動で読み直します。これにより
        再 export 後もサーバを再起動せず最新の内容を返せます。

        ★読み直すたびに、ghidra_exports/ の実体とファイルの実体がプロジェクト内
          (ghidra_exports/ の配下) かを確かめ、大きさの上限
          (MAX_EXPORT_JSON_BYTES) を**読む前に**確かめます。
        """
        path = self.exports_dir / filename
        cached = self._cache.get(filename)
        if cached is not None:
            try:
                if path.stat().st_mtime == cached[0]:
                    return cached[1]
            except OSError:
                pass
        real = self._checked_file(self.exports_dir, filename, "ghidra_exports/")
        if not real.is_file():
            raise ValueError(
                "{0} が見つかりません。export_context.py を再実行してください。".format(filename))
        mtime = real.stat().st_mtime
        try:
            data = json.loads(_read_text_capped(real, MAX_EXPORT_JSON_BYTES, filename))
        except json.JSONDecodeError as exc:
            raise ValueError("{0} を JSON として解析できません: {1}".format(filename, exc))
        except UnicodeDecodeError:
            raise ValueError("{0} が UTF-8 ではありません。".format(filename))
        self._cache[filename] = (mtime, data)
        return data

    def _get_xref_index(self):
        """xrefs.json の to/from アドレス索引を構築 (キャッシュ) して返します。

        46万件規模の xrefs.json を毎クエリで全走査しないための索引です。
        xrefs.json が再 export で更新されたら自動で作り直します。
        非16進アドレス (Ghidra のスタック/レジスタ参照 '0xStack[-0x4]' 等) は
        アドレス検索できないため索引対象外にします。
        """
        path = self.exports_dir / "xrefs.json"
        mtime = path.stat().st_mtime if path.is_file() else None
        if self._xref_index is not None and self._xref_index_mtime == mtime:
            return self._xref_index
        to_index = {}
        from_index = {}
        for x in self._load("xrefs.json"):
            ti = try_parse_hex(x.get("to"))
            if ti is not None:
                to_index.setdefault(ti, []).append(x)
            fi = try_parse_hex(x.get("from"))
            if fi is not None:
                from_index.setdefault(fi, []).append(x)
        self._xref_index = {"to": to_index, "from": from_index}
        self._xref_index_mtime = mtime
        return self._xref_index

    # --- ツール 1: program 情報 ---------------------------------------
    def get_program_info(self):
        """program.json を返します (小さいファイル)。MIPS なら gp を足します。

        ★gp は `lw v0,-29048(gp)` の参照先を決めるのに要る。どの根拠から
          採ったかを gp_source に、全候補を gp_candidates に入れる。
          gp の計算で失敗しても program.json 自体は必ず返す。
        """
        info = dict(self._load("program.json"))       # キャッシュを汚さないよう複製
        try:
            gp = self._public_gp()
        except Exception as exc:                        # gp のせいで基本情報を落とさない
            gp = {"gp": None, "gp_warnings": ["gp を計算できませんでした: {0}".format(exc)]}
        if gp is not None:
            info.update(gp)
        return info

    # --- ツール 2: 関数一覧 (フィルタ + ページング) -------------------
    def list_functions(self, name_contains=None, start=None, end=None,
                        offset=0, limit=DEFAULT_LIMIT, hide_mirrors=False):
        """関数一覧を名前部分一致・アドレス範囲で絞り、ページングして返します。

        ROM ミラーを持つアーキ (65816: mirror_of フック) では、各関数に
        「この関数は $80:xxxx の重複」(mirror_of) / 「この EXT_FUN の実体は $82:xxxx」
        (ext_real) を添えます。hide_mirrors=True でミラー上の重複を一覧から外します。
        """
        funcs = self._load("functions.json")
        start_i = parse_hex(start) if start else None
        end_i = parse_hex(end) if end else None
        needle = name_contains.lower() if name_contains else None

        matched = []
        for f in funcs:
            name = f.get("name") or ""
            if needle and needle not in name.lower():
                continue
            entry = f.get("entry")
            if (start_i is not None or end_i is not None) and entry:
                entry_i = parse_hex(entry)
                if start_i is not None and entry_i < start_i:
                    continue
                if end_i is not None and entry_i > end_i:
                    continue
            matched.append(f)

        mirrors = self._safe(lambda: self._mirror_annotator(), None)
        if mirrors is None:
            if hide_mirrors:
                raise ValueError("このアーキには ROM ミラーの判定 (mirror_of) がありません。")
            return self._paginate(matched, offset, limit)
        notes = [mirrors(f) for f in matched]
        dup_total = sum(1 for n in notes if n.get("mirror_of"))
        ext_total = sum(1 for n in notes if n.get("ext_real"))
        rows = []
        for f, n in zip(matched, notes):
            if hide_mirrors and n.get("mirror_of"):
                continue
            rows.append(dict(f, **n) if n else f)
        result = self._paginate(rows, offset, limit)
        result["mirror_summary"] = {
            "mirror_duplicates": dup_total,
            "ext_with_real_body": ext_total,
            "hidden": dup_total if hide_mirrors else 0,
            "note": mirrors.note,
        }
        return result

    def _mirror_annotator(self):
        """関数 1 件に ROM ミラーの注記 (dict) を返す関数を作ります。対応しないアーキは None。

        判断材料は 2 つ:
          address_rule … アーキの mirror_of フック (LoROM の bit23 違い等) で、
                         **バイト列が export されている側**の番地が見つかった
          memory_block … 関数の居るブロックが memory_map にあるのに export されて
                         いない (ローダーが作ったミラーのブロック)
        EXT_FUN_xxxxxx (Program に載っていない番地への参照) は、その番地のミラーに
        実体があれば ext_real に出します。
        """
        try:
            mm, blocks = self._exported_blocks()
        except ValueError:
            return None
        arch_mod = disasm.resolve_arch(mm)
        hook = getattr(arch_mod, "mirror_of", None)
        if hook is None:
            return None
        ctx = (self._width_context(blocks)
               if getattr(arch_mod, "NEEDS_WIDTH_CONTEXT", False) else None)
        fmt = getattr(arch_mod, "ADDR_FORMAT", "0x{0:08x}")
        by_entry = {}
        for f in self._safe(lambda: self._load("functions.json"), []) or []:
            e = try_parse_hex(f.get("entry") or "")
            if e is not None:
                by_entry[e] = f.get("name")
        all_blocks = self._safe(lambda: self._memory_map().get("blocks"), []) or []

        def block_of(addr):
            for b in all_blocks:
                lo, hi = self._safe(lambda: self._block_range(b), (None, None))
                if lo is not None and lo <= addr <= hi:
                    return b
            return None

        def real_side(addr):
            alt = hook(addr, ctx)
            if alt is None:
                return None
            blk = self._find_block(alt, blocks)
            if blk is None or not _has_bytes(blk):
                return None
            return alt

        def annotate(f):
            out = {}
            entry = try_parse_hex(f.get("entry") or "")
            if entry is not None:
                alt = real_side(entry)
                if alt is not None:
                    basis = ["address_rule"]
                    blk = block_of(entry)
                    if blk is not None and not _has_bytes(blk):
                        basis.append("memory_block:{0}".format(blk.get("name")))
                    out["mirror_of"] = fmt.format(alt)
                    out["mirror_function"] = by_entry.get(alt)
                    out["mirror_basis"] = basis
            m = re.search(r"EXT_FUN_([0-9A-Fa-f]{4,8})$", f.get("name") or "")
            if m:
                ext = int(m.group(1), 16)
                real = real_side(ext)
                if real is not None:
                    out["ext_target"] = fmt.format(ext)
                    out["ext_real"] = fmt.format(real)
                    out["ext_real_function"] = by_entry.get(real)
            return out

        annotate.note = (getattr(arch_mod, "MIRROR_NOTE", "") +
                         " mirror_of = この関数は実体側 (mirror_function) の重複 "
                         "(CDL の M/X の裏付けも実体側にある)。ext_real = EXT_FUN の飛び先の実体。"
                         "mirror_basis の memory_block は「ローダーが作った未 export のミラー」。")
        return annotate

    def _ext_notes_for_code(self, code):
        """疑似 C に出てくる EXT_FUN_xxxxxx の実体 (ミラー側) を返します。"""
        mirrors = self._safe(lambda: self._mirror_annotator(), None)
        if mirrors is None:
            return []
        out = []
        seen = set()
        for m in re.finditer(r"\b(?:thunk_)?EXT_FUN_[0-9A-Fa-f]{4,8}\b", code):
            name = m.group(0)
            if name in seen:
                continue
            seen.add(name)
            note = mirrors({"name": name})
            if note.get("ext_real"):
                out.append(dict({"name": name}, **note))
        return out

    # --- ツール 3: 指定アドレス周辺の関数 -----------------------------
    def get_functions_near_address(self, address, window=0x200):
        """指定アドレスを body に含む関数と、entry が窓内にある近傍関数を返します。"""
        target = parse_hex(address)
        try:
            win = int(window)
        except (TypeError, ValueError):
            win = 0x200

        containing = []
        nearby = []
        for f in self._load("functions.json"):
            entry = f.get("entry")
            entry_i = parse_hex(entry) if entry else None

            in_body = False
            for rng in f.get("body_ranges", []):
                rs = rng.get("start")
                re_ = rng.get("end")
                if rs and re_ and parse_hex(rs) <= target <= parse_hex(re_):
                    in_body = True
                    break
            if in_body:
                containing.append(f)
            elif entry_i is not None and abs(entry_i - target) <= win:
                nearby.append(f)

        mirrors = self._safe(lambda: self._mirror_annotator(), None)
        if mirrors is not None:
            containing = [dict(f, **mirrors(f)) for f in containing]
            nearby = [dict(f, **mirrors(f)) for f in nearby]
        return {
            "address": address,
            "window": "0x{0:x}".format(win),
            "containing": containing,
            "nearby": nearby,
        }

    # --- ツール 4: 文字列一覧 (フィルタ + ページング) -----------------
    def list_strings(self, contains=None, min_refs=0, offset=0, limit=DEFAULT_LIMIT):
        """文字列一覧を部分一致・最小参照数で絞り、ページングして返します。"""
        strings = self._load("strings.json")
        needle = contains if contains else None
        try:
            min_r = int(min_refs)
        except (TypeError, ValueError):
            min_r = 0

        matched = []
        for s in strings:
            value = s.get("value") or ""
            if needle and needle not in value:
                continue
            if len(s.get("referenced_from", [])) < min_r:
                continue
            matched.append(s)

        return self._paginate(matched, offset, limit)

    # --- ツール 5: xref 取得 (to/from のいずれか必須) -----------------
    def get_xrefs(self, to_address=None, from_address=None, limit=DEFAULT_LIMIT):
        """to_address / from_address のいずれかに一致する xref のみ返します。

        67MB 級の xrefs.json を丸ごと返さないよう、フィルタを必須にしています。
        """
        if not to_address and not from_address:
            raise ValueError(
                "get_xrefs は to_address か from_address のいずれかが必須です "
                "(全件取得は禁止)。")
        to_i = parse_hex(to_address) if to_address else None
        from_i = parse_hex(from_address) if from_address else None
        lim = clamp_limit(limit)
        index = self._get_xref_index()

        # 索引で候補を絞ってから、残りの条件で filter します (全走査を回避)。
        matched = []
        if to_i is not None:
            # 候補は全て to == to_i。from 指定があればさらに絞る。
            for x in index["to"].get(to_i, []):
                if from_i is not None and try_parse_hex(x.get("from")) != from_i:
                    continue
                matched.append(x)
                if len(matched) >= lim:
                    break
        else:
            # from のみ指定。候補は全て from == from_i。
            for x in index["from"].get(from_i, []):
                matched.append(x)
                if len(matched) >= lim:
                    break

        return {
            "to_address": to_address,
            "from_address": from_address,
            "limit": lim,
            "returned": len(matched),
            "items": matched,
        }

    # --- ツール 6: decompile 取得 (1 関数) ----------------------------
    def get_decompiled_function(self, function_name=None, entry_address=None,
                                resolve_pool=True, pool_limit=64,
                                with_addresses=False, rename=False,
                                rename_map=None):
        """指定関数の疑似 C コードを decompile/ から 1 件返します。

        `resolve_pool=True` (既定) のとき、本文に出てくる `DAT_xxxxxxxx` を
        全部引いて **`pool` キーに別立てで**添えます。**疑似 C 本文は変えません**
        (書き換えると Ghidra の出力との差分が読めなくなるため)。
        応答を細くしたいときは `resolve_pool=False` で完全に消せます。

        `with_addresses=True` のとき、**行ごとの命令アドレス**を
        `line_addresses` と `listing` に添えます (`code` は手つかずのまま)。
        疑似 C で怪しい行を見つけても番地が分からないと、毎回 get_disassembly を
        並べて対応を取ることになるためです。番地はメモにも改造コードにも
        ブレークポイントにもそのまま使えます。

        `rename=True` のとき、関数の入口に付いている **[AI] 変数メモ**
        (`propose_variable_notes` で提案し、`apply_comments.py` で反映したもの)
        を読み、**読みやすい疑似 C を `code_renamed` に別立てで**添えます。
        `rename_map` を渡せばその場限りの対応表も使えます。
        **`code` (Ghidra の出力そのまま) は絶対に変えません** — 変えると
        Ghidra の出力との差分が読めなくなるためです。
        """
        if not function_name and not entry_address:
            raise ValueError("function_name か entry_address のいずれかを指定してください。")

        name = function_name
        entry = entry_address
        if not (name and entry):
            # functions.json から相方を補完します。
            for f in self._load("functions.json"):
                if function_name and f.get("name") == function_name:
                    name = f.get("name")
                    entry = f.get("entry")
                    break
                if entry_address and f.get("entry") == entry_address:
                    name = f.get("name")
                    entry = f.get("entry")
                    break
        if not (name and entry):
            raise ValueError("該当する関数が functions.json に見つかりません。")

        entry_token = entry[2:] if entry.lower().startswith("0x") else entry
        filename = self._sanitize("{0}_{1}{2}".format(name, entry_token, DECOMPILE_EXT))
        # パストラバーサル防止: decompile/ の実体がプロジェクト内で、
        # 解決後パスがその配下であること (リンク / ジャンクション経由も拒否)。
        path = self._checked_file(self.decompile_dir, filename, "ghidra_exports/decompile/")
        if not path.is_file():
            raise ValueError(
                "decompile が見つかりません: {0} "
                "(export で逆コンパイルに失敗/上限到達の可能性)。".format(filename))

        code = _read_text_capped(path, MAX_DECOMPILE_TEXT_BYTES, filename)
        result = {
            "name": name,
            "entry": entry,
            "file": filename,
            "code": code,
        }
        if with_addresses:
            result.update(self._line_map_for(filename, code))
        if rename or rename_map:
            result.update(self._rename_view(code, entry, rename, rename_map))
        ext_notes = self._ext_notes_for_code(code) if "EXT_FUN_" in code else []
        if ext_notes:
            # code は変えない (Ghidra の出力そのまま)。実体の番地は別欄に添える。
            result["ext_functions"] = ext_notes
            result["ext_note"] = ("EXT_FUN_xxxxxx は Program に載っていない番地 (ROM ミラー側) への"
                                  "呼び出しです。ext_real がその実体 (export された側) の番地。")
        if resolve_pool:
            # memory イメージが無ければ黙って諦める (疑似 C 自体は返す)。
            try:
                _mm, blocks = self._exported_blocks()
            except Exception:
                blocks = None
            if blocks:
                pool, total = self._pool_for_text(code, blocks,
                                                  clamp_count(pool_limit, 64, 512))
                if pool:
                    result["pool"] = pool
                    result["pool_total"] = total
                    if total > len(pool):
                        result["pool_truncated"] = (
                            "DAT_ が {0} 個ありますが {1} 個で切りました "
                            "(pool_limit で増やせます)。".format(total, len(pool)))
                    result["pool_note"] = (
                        "疑似 C 本文 (code) は変えていません。DAT_ の中身は"
                        "この pool を見てください。note は弱い所見なので裏を取ること。"
                        "応答を細くしたいときは resolve_pool=false。")
        return result

    # --- 疑似 C の行 <-> 命令アドレス -----------------------------------
    def _line_map_for(self, filename, code):
        """疑似 C の行に命令アドレスを添えた結果を組み立てて返します。

        対応表 (`decompile/<関数>_<entry>.lines.json`) は **export のときにしか
        作れません** (decompiler のマークアップからしか取れないため)。
        無いときは「どうすれば出るか」を返し、疑似 C 自体は普通に返します。
        """
        try:
            side = self._checked_file(
                self.decompile_dir, filename[:-len(DECOMPILE_EXT)] + ".lines.json",
                "ghidra_exports/decompile/")
        except ValueError as exc:
            return {"line_map": False, "line_map_hint": str(exc)}
        if not side.is_file():
            return {
                "line_map": False,
                "line_map_hint": (
                    "行 -> 番地の対応表がありません。bridge_config.json に "
                    "\"decompile_line_map\": true を書いて (既定は true)、"
                    "Ghidra GUI で export_context.py を再実行してください。"
                    "この対応は decompiler のマークアップからしか取れないので、"
                    "MCP 側では後から作れません。"
                    "それまでは get_disassembly で番地を突き合わせてください。"),
            }
        try:
            data = json.loads(_read_text_capped(side, MAX_SMALL_JSON_BYTES, side.name))
        except (ValueError, OSError) as exc:
            return {"line_map": False,
                    "line_map_hint": "対応表を読めません ({0})。再 export してください。".format(exc)}

        lines = code.split("\n")
        rows = [r for r in (data.get("lines") or []) if isinstance(r, dict)]
        shift, score, checked = self._align_line_map(lines, rows)

        # ★対応表が .c より古い = 対応表を出さない設定で再 export した跡。
        #   番地がずれていても行頭が偶然そろうことはあるので、日付でも見ます。
        stale = None
        try:
            if side.stat().st_mtime + 1 < (self.decompile_dir / filename).stat().st_mtime:
                stale = ("対応表が疑似 C より古いです "
                         "(対応表を出さない設定で再 export した可能性)。"
                         "**番地がずれているかもしれません。**")
        except OSError:
            pass

        items = []
        listing = []
        mapped = {}
        for row in rows:
            try:
                index = int(row["line"]) - 1 + shift
            except (KeyError, TypeError, ValueError):
                continue
            if not (0 <= index < len(lines)):
                continue
            mapped[index] = row
            items.append({
                "line": index + 1,
                "start": row.get("min"),
                "end": row.get("max"),
                "instructions": row.get("count"),
            })
        for index, text in enumerate(lines):
            row = mapped.get(index)
            addr = (row or {}).get("min") or ""
            listing.append("{0:<10}  {1}".format(addr, text))

        out = {
            "line_map": True,
            "line_addresses": items,
            "listing": "\n".join(listing),
            "line_map_mapped": len(items),
            "line_map_lines": len(lines),
            "line_map_shift": shift,
            "line_map_note": (
                "listing は '<番地>  <疑似 C の 1 行>' です。番地のある行だけに"
                "番地が付きます (宣言や } は命令に対応しません)。"
                "start/end はその行が対応する命令の**範囲**で、"
                "1 行が複数命令に散ることも、複数行が同じ命令を指すこともあります。"
                "**code (疑似 C 本文) は変えていません。**"),
        }
        if checked:
            out["line_map_verified"] = "{0}/{1}".format(score, checked)
            if score < checked * 0.8:
                out["line_map_warning"] = (
                    "対応表の行頭と疑似 C の行が {0}/{1} しか一致しません。"
                    "**番地がずれている可能性があります。** .c と .lines.json の"
                    "どちらかが古いので、再 export してから使ってください。".format(
                        score, checked))
        if shift:
            out["line_map_warning"] = (out.get("line_map_warning") or "") + (
                "行番号を {0:+d} ずらして合わせました。".format(shift))
        if stale:
            out["line_map_warning"] = (out.get("line_map_warning") or "") + stale
            out["line_map_stale"] = True
        return out

    @staticmethod
    def _align_line_map(lines, rows):
        """対応表の行番号と疑似 C の行がずれていないかを確かめます。

        export 側が入れた `head` (行頭 20 文字) と実際の行を突き合わせ、
        **一番よく一致するずらし量**を返します。ずれたまま番地を答えると、
        1 命令の違いを追う作業が丸ごと狂うためです。
        戻り値は (ずらし量, 一致数, 照合数)。
        """
        best = (0, -1, 0)
        for shift in (0, -1, 1, -2, 2):
            score = 0
            checked = 0
            for row in rows:
                head = row.get("head")
                if not head:
                    continue
                try:
                    index = int(row["line"]) - 1 + shift
                except (KeyError, TypeError, ValueError):
                    continue
                if not (0 <= index < len(lines)):
                    continue
                checked += 1
                if lines[index].strip()[:len(head)] == head:
                    score += 1
            if checked and score > best[1]:
                best = (shift, score, checked)
        if best[1] < 0:
            return (0, 0, 0)
        return best

    # --- 疑似 C の変数名 (意味づけ) --------------------------------------
    #
    # ★`iVar1` は「分からない」という**正しい情報**を持っています。根拠の無い
    #   名前はそれより悪い (読む人が考えるのをやめる)。そのため:
    #     - 意味づけは **[AI] コメント**として Ghidra へ戻す (許可済みの経路)
    #     - 読みやすい疑似 C は **`code_renamed` に別立て**で添え、
    #       `code` (Ghidra の出力そのまま) は絶対に変えない
    #   Ghidra のローカル変数名そのものを書き換える機能は入れていません
    #   (`iVar1` は「分からない」という正しい情報なので、根拠の無い名前の方が悪い)。

    # 変数メモのコメントはこの行で始めます。次のセッションが機械的に読み戻せる
    # ように、**印と書式を固定**します (人が読んでも自然な形)。
    VARIABLE_NOTE_HEAD = "[AI] 変数メモ"
    _VAR_LINE = re.compile(r"^\s*([A-Za-z_][A-Za-z_0-9]*)\s*=\s*(.+?)\s*$")

    @staticmethod
    def _code_identifiers(code):
        """疑似 C に出てくる識別子の集合を返します (存在確認用)。"""
        return set(re.findall(r"\b[A-Za-z_][A-Za-z_0-9]*\b", code))

    def propose_variable_notes(self, notes, function_name=None,
                               entry_address=None, confidence="medium",
                               evidence=None):
        """疑似 C の変数の意味を **[AI] コメント**にして提案します。

        `iVar1` が何なのかは、読み解いた本人にしか分かりません。それを
        **Ghidra へ戻せる形**にするのがこのツールです。関数の入口に
        plate コメントとして 1 個付けるので、次のセッションは
        `list_comments` で読み返せますし、`get_decompiled_function(rename=true)`
        が**そのコメントから読みやすい疑似 C を組み立て直します**。

        ★**疑似 C に存在しない変数名は拒否します。** 存在しない名前へメモを
          付けると、次のセッションが「そういう変数がある」と誤解します。

        MCP はファイルを書きません。返った JSON を `proposals/` に保存して、
        Ghidra GUI で `apply_comments.py` を実行してください。
        """
        if not isinstance(notes, dict) or not notes:
            raise ValueError(
                "notes に {\"iVar1\": \"残り時間\", ...} の形で指定してください。")
        if confidence not in ("low", "medium", "high"):
            raise ValueError("confidence は low / medium / high のいずれかです。")

        target = self.get_decompiled_function(
            function_name=function_name, entry_address=entry_address,
            resolve_pool=False)
        known = self._code_identifiers(target["code"])

        unknown = [name for name in notes if name not in known]
        if unknown:
            locals_ = sorted(
                n for n in known
                if re.match(r"^(i|u|c|s|f|d|b|p|a|l)?Var\d+$", n)
                or re.match(r"^(param_|local_|uStack_|iStack_|auStack_)", n))
            raise ValueError(
                "疑似 C に無い変数名です: {0}。この関数に出てくるのは {1} です "
                "(存在しない名前にメモを付けると、次のセッションが"
                "「そういう変数がある」と誤解します)。".format(
                    ", ".join(unknown), ", ".join(locals_[:24]) or "(見当たらず)"))

        lines = [self.VARIABLE_NOTE_HEAD]
        for name in sorted(notes):
            meaning = str(notes[name]).strip().replace("\n", " ")
            if not meaning:
                raise ValueError("'{0}' の意味が空です。".format(name))
            lines.append("{0} = {1}".format(name, meaning))
        comment = "\n".join(lines)

        proposal = {
            "schema_version": "1.0",
            "target_program": self._safe(
                lambda: (self._load("program.json") or {}).get("program_name"),
                None),
            "generated_by": "ghidra_readonly_mcp propose_variable_notes",
            "comments": [{
                "address": target["entry"],
                "address_basis": "ghidra",
                "type": "plate",
                "comment": comment,
                "confidence": confidence,
                "reason": "疑似 C のローカル変数が何を指すかのメモです。"
                          "Ghidra の変数名 (iVar1 等) は意味を持たないので、"
                          "読み解いた結果をコメントとして残します。",
                "evidence": list(evidence or []),
            }],
            "note": "MCP はこの JSON を保存しません。proposals/ に保存して、"
                    "Ghidra GUI で apply_comments.py を実行してください "
                    "(反映は必ず人間がトリガします)。",
        }
        return {
            "name": target["name"],
            "entry": target["entry"],
            "variables": len(notes),
            "comment_preview": comment,
            "proposal": proposal,
            "note": ("関数の入口に plate コメントとして 1 個付ける案です。"
                     "反映後は list_comments で読み返せますし、"
                     "**get_decompiled_function(rename=true) がこのコメントから"
                     "読みやすい疑似 C を組み立てます** (code は変えません)。"
                     "★根拠の無い名前は付けないこと。`iVar1` は「分からない」"
                     "という正しい情報を持っているので、間違った名前はそれより"
                     "悪いです (読む人が考えるのをやめます)。"),
        }

    def _rename_view(self, code, entry, rename, rename_map):
        """読みやすい疑似 C (`code_renamed`) を組み立てて返します。

        `code` は呼び出し側で変えません。ここで返すのは**足すキーだけ**です。
        """
        mapping = {}
        sources = []
        if rename:
            stored = self._stored_variable_notes(entry)
            if stored:
                mapping.update(stored)
                sources.append("comments")
        if rename_map:
            if not isinstance(rename_map, dict):
                raise ValueError(
                    "rename_map は {\"iVar1\": \"残り時間\"} の形で指定してください。")
            mapping.update(rename_map)
            sources.append("rename_map")
        if not mapping:
            return {
                "code_renamed": None,
                "rename_note": (
                    "この関数には [AI] 変数メモが付いていません。"
                    "propose_variable_notes で提案 → proposals/ に保存 → "
                    "Ghidra GUI で apply_comments.py、の順で付けられます "
                    "(反映後は再 export が要ります)。"),
            }
        renamed, applied, missing = self._apply_rename(code, mapping)
        out = {
            "code_renamed": renamed,
            "renamed": applied,
            "rename_source": sources,
            "rename_note": (
                "**code (Ghidra の出力そのまま) は変えていません。**"
                "読みやすい版は code_renamed です。名前は [AI] 変数メモから"
                "作った**推測**なので、鵜呑みにせず根拠を確かめること。"),
        }
        if missing:
            out["rename_skipped"] = missing
        return out

    def _stored_variable_notes(self, entry):
        """その関数の入口に付いている「変数メモ」コメントを読み戻します。"""
        rows = self._safe(lambda: self._load("comments.json"), None)
        if not isinstance(rows, list):
            return {}
        entry_i = try_parse_hex(entry or "")
        out = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            if try_parse_hex(row.get("address") or "") != entry_i:
                continue
            text = row.get("comment") or ""
            if not text.lstrip().startswith(self.VARIABLE_NOTE_HEAD):
                continue
            for line in text.split("\n")[1:]:
                hit = self._VAR_LINE.match(line)
                if hit:
                    out[hit.group(1)] = hit.group(2)
        return out

    def _apply_rename(self, code, mapping):
        """疑似 C の変数名を置き換えた**別バージョン**を作ります。

        ★`code` そのものは書き換えません。単語境界で置くので `iVar1` が
          `iVar10` の一部に当たることはありません。
        """
        applied = []
        missing = []
        out = code
        # 長い名前から置く (iVar1 と iVar10 が両方あるときの取り違え防止)。
        for name in sorted(mapping, key=len, reverse=True):
            meaning = str(mapping[name]).strip()
            ident, why = _label_from_text(meaning, max_name=32)
            if ident is None:
                missing.append({"name": name, "why": why})
                continue
            pattern = re.compile(r"\b{0}\b".format(re.escape(name)))
            out, count = pattern.subn(ident, out)
            if count:
                applied.append({"name": name, "renamed_to": ident,
                                "meaning": meaning, "occurrences": count})
            else:
                missing.append({"name": name,
                                "why": "疑似 C に出てきません "
                                       "(名前が変わったか、別の関数のメモです)。"})
        return out, applied, missing

    # --- メモリイメージ (get_disassembly / find_address_refs の土台) ---
    def _memory_map(self):
        """memory_map.json を読みます。無い場合は「どうすれば出るか」を示すエラー。"""
        if not (self.exports_dir / "memory_map.json").is_file():
            # ★memory を export していなくても、実行ファイルが手元にあれば
            #   そこから読めます (source_model=executable の Program)。
            fallback = self._executable_memory_map()
            if fallback is not None:
                return fallback
            raise ValueError(
                "memory_map.json がありません。bridge_config.json に "
                "\"export_memory\": true を追加して、Ghidra GUI で export_context.py を"
                "再実行してください (生の逆アセンブルにはメモリイメージが必要です)。"
                "なお source_model=executable で実行ファイルが手元にあるなら、"
                "program.json の executable_path から読めます。ただし読むのは"
                "許可ルート (extracted/・dumps/・bridge_config.json の source_roots) の"
                "配下だけです — 外部にあるなら、人間が source_roots にそのフォルダを"
                "書き足してください。")
        return self._load("memory_map.json")

    def _exported_blocks(self):
        """memory_map.json と、実際にバイト列を出力済みのブロック一覧を返します。

        ★**オーバーレイ (bridge_config.json の overlays) を先頭に混ぜます。**
          実行時に RAM へ読み込まれる外部ファイル (ステージデータ / 地形の高さ表)
          は Ghidra の Program に入っていないため、これが無いと read_data /
          find_bytes / describe_data / classify_range / find_pointers_to が
          **1 つも使えません**。先頭に置くのは、範囲が Program のブロックと
          重なったとき「登録した側」を正とするためです (重なりは list_overlays
          が警告します)。
        """
        # 実体の無いオーバーレイ (path が存在しない等) は混ぜません。
        # 一覧と理由は list_overlays が返します。
        overlays = [b for b in self._overlay_blocks() if b.get("exported")]
        try:
            mm = self._memory_map()
        except ValueError:
            if overlays:
                # Program 側の memory が無くても、オーバーレイだけで動かせます。
                return self._overlay_only_memory_map(overlays), overlays
            raise
        blocks = mm.get("blocks") if isinstance(mm, dict) else None
        if not isinstance(blocks, list):
            raise ValueError("memory_map.json の blocks が読めません。再 export してください。")
        exported = [b for b in blocks
                    if isinstance(b, dict) and b.get("exported")
                    and _has_bytes(b)]
        if not exported and not overlays:
            raise ValueError(
                "memory イメージが 1 ブロックも出力されていません。"
                "export_memory_max_mb / export_memory_total_max_mb の上限で"
                "スキップされた可能性があります (memory_map.json の skipped_reason を確認)。")
        return mm, overlays + exported

    # --- オーバーレイ (実行時に読み込まれる外部ファイル) -----------------
    def _overlay_only_memory_map(self, overlays):
        """Program 側の memory が無いときに使う、最小の memory_map 相当です。"""
        info = self._safe(lambda: self._load("program.json"), {}) or {}
        cfg = self._safe(lambda: self._bridge_config(), {}) or {}
        return {
            "endian": ("big" if "BE" in (info.get("language_id") or "")
                       else "little"),
            "language_id": info.get("language_id"),
            "processor": (info.get("language_id") or "").split(":")[0] or None,
            "disasm_arch": cfg.get("disasm_arch"),
            "blocks": overlays,
            "source": "overlay",
            "note": ("Program 側の memory イメージが無いので、"
                     "**オーバーレイだけ**を見ています。"),
        }

    def _overlay_blocks(self):
        """bridge_config.json の overlays を仮想ブロックに変換して返します。

        定義の形 (bridge_config.json):

            {"overlays": [
              {"name": "stage01", "path": "dumps/STAGE01.BIN",
               "base": "0x801c0000", "offset": 0, "length": null,
               "note": "ステージデータ (実行時に 0x801c0000 へ読み込まれる)",
               "scan": true, "execute": false}]}

        - `path` は **プロジェクトフォルダの中**だけ (外へは出られません)
        - `base` が「実行時にそのファイルの先頭が置かれる番地」
        - `offset` / `length` でファイルの一部だけを載せられます
          (ヘッダを飛ばす / 連結ファイルの 1 区画だけ使う)
        - `scan=false` にすると、全域走査するツールの対象から外れます
          (Program のブロックと範囲が重なるときに使ってください)

        ★MCP はここでも**読むだけ**です。ファイルは開いて読むだけで、
          Ghidra にも overlays にも一切書き戻しません。
        """
        cfg = self._safe(lambda: self._bridge_config(), {}) or {}
        raw = cfg.get("overlays") or []
        if not isinstance(raw, list):
            raise ValueError(
                "bridge_config.json の overlays は配列で書いてください。")
        root = self.project_root.resolve()
        blocks = []
        seen = set()
        for i, item in enumerate(raw):
            if not isinstance(item, dict):
                raise ValueError("overlays[{0}] が辞書ではありません。".format(i))
            name = str(item.get("name") or "").strip()
            if not name:
                raise ValueError("overlays[{0}] に name がありません。".format(i))
            if name in seen:
                raise ValueError("オーバーレイ名 '{0}' が重複しています。".format(name))
            seen.add(name)
            if not item.get("path"):
                raise ValueError("オーバーレイ '{0}' に path がありません。".format(name))
            # ★UNC / デバイスパス / ドライブ相対は、resolve 等で触る前に文字列で拒否する。
            path = self._project_relative(
                item["path"], "オーバーレイ '{0}' の path".format(name)).resolve()
            if root not in path.parents and path != root:
                raise ValueError(
                    "オーバーレイ '{0}' の path がプロジェクトフォルダの外です: {1} "
                    "(読み取り専用の道具なので、プロジェクト配下だけを見ます)。".format(
                        name, path))
            base = _parse_int(item.get("base"), "overlays[{0}].base".format(name))
            offset = _parse_int(item.get("offset", 0),
                                "overlays[{0}].offset".format(name))
            if offset < 0:
                raise ValueError("オーバーレイ '{0}' の offset が負です。".format(name))
            block = {
                "name": "overlay:{0}".format(name),
                "overlay": name,
                "source": "overlay",
                "path": str(path),
                "file_offset": offset,
                "start": "0x{0:08x}".format(base),
                "exported": True,
                "file": None,
                "execute": bool(item.get("execute")),
                "read": True,
                "write": False,
                "scan": item.get("scan", True) is not False,
                "note": item.get("note"),
            }
            if not path.is_file():
                block["missing"] = (
                    "ファイルがありません: {0}。bridge_config.json の overlays を"
                    "確認してください。".format(path))
                block["exported"] = False
                blocks.append(block)
                continue
            size = path.stat().st_size
            avail = max(0, size - offset)
            length = item.get("length")
            if length in (None, "", 0):
                length = avail
            else:
                length = min(_parse_int(length,
                                        "overlays[{0}].length".format(name)),
                             avail)
            if length <= 0:
                block["missing"] = (
                    "offset {0} がファイルサイズ {1} を超えています。".format(offset, size))
                block["exported"] = False
                blocks.append(block)
                continue
            block["length"] = length
            block["end"] = "0x{0:08x}".format(base + length - 1)
            block["file_size"] = size
            blocks.append(block)
        return [b for b in blocks if b.get("exported")] + \
               [b for b in blocks if not b.get("exported")]

    def _overlay_path(self, block):
        """オーバーレイの実ファイルパスを検証して返します。"""
        path = Path(block.get("path") or "")
        root = self.project_root.resolve()
        if root not in path.parents and path != root:
            raise ValueError(
                "オーバーレイ '{0}' の path がプロジェクトフォルダの外です。".format(
                    block.get("overlay")))
        if not path.is_file():
            raise ValueError(
                "オーバーレイ '{0}' のファイルがありません: {1}".format(
                    block.get("overlay"), path))
        return path

    def list_overlays(self):
        """登録済みオーバーレイを一覧し、**Program と重なっていないか**も返します。

        オーバーレイは「このファイルを、この番地に置かれたものとして扱う」
        という宣言です。実行時に RAM へ読み込まれる外部ファイル
        (ステージデータ / 地形の高さ表 / オーバーレイコード) を、EXE 内の表と
        同じツール群で読むために使います。
        """
        overlays = self._overlay_blocks()
        program_blocks = []
        try:
            mm = self._memory_map()
            program_blocks = [b for b in (mm.get("blocks") or [])
                              if isinstance(b, dict) and b.get("exported")
                              and _has_bytes(b)]
        except ValueError:
            mm = None

        items = []
        for block in overlays:
            start, end = self._block_range(block)
            overlaps = []
            for other in program_blocks:
                ostart, oend = self._block_range(other)
                if (start is not None and end is not None
                        and ostart is not None and oend is not None
                        and start <= oend and ostart <= end):
                    overlaps.append(other.get("name"))
            item = {
                "overlay": block.get("overlay"),
                "block": block.get("name"),
                "path": block.get("path"),
                "available": bool(block.get("exported")),
                "start": block.get("start"),
                "end": block.get("end"),
                "length": block.get("length"),
                "file_offset": block.get("file_offset"),
                "file_size": block.get("file_size"),
                "scan": block.get("scan"),
                "execute": block.get("execute"),
                "note": block.get("note"),
            }
            if block.get("missing"):
                item["problem"] = block["missing"]
            if overlaps:
                item["overlaps_program_blocks"] = overlaps
                item["overlap_warning"] = (
                    "Program のブロック {0} と範囲が重なっています。"
                    "**この範囲の読み出しはオーバーレイ側が優先されます。**"
                    "走査系で二重に出るのが邪魔なら \"scan\": false にしてください。"
                    .format(", ".join(str(x) for x in overlaps)))
            items.append(item)

        return {
            "total": len(items),
            "available": sum(1 for x in items if x["available"]),
            "config": str(self.project_root / "bridge_config.json"),
            "overlays": items,
            "note": ("overlays は bridge_config.json に書いて使い回します。"
                     "登録すると read_data / find_bytes / describe_data / "
                     "classify_range / find_pointers_to がその範囲でも効きます。"
                     "応答の block は必ず \"overlay:<名前>\" になるので、"
                     "Program 本体の値と取り違えません。"
                     "**MCP は overlays を読むだけで、書き換えません。**"
                     if items else
                     "オーバーレイは登録されていません。実行時に RAM へ読み込む"
                     "外部ファイル (ステージデータ等) を読むときは "
                     "bridge_config.json に overlays を書いてください。"),
        }

    @staticmethod
    def _overlay_of(block):
        """ブロックがオーバーレイならその名前を、違えば None を返します。"""
        return (block or {}).get("overlay")

    def _mark_overlay(self, result, block):
        """単一ブロックを読んだ結果に「どのオーバーレイの値か」を必ず入れます。"""
        name = self._overlay_of(block)
        result["overlay"] = name
        if name:
            result["overlay_note"] = (
                "**この値は Program 本体ではなく、オーバーレイ '{0}' "
                "({1}) の中身です。** 実行時にこの番地へ読み込まれる前提で"
                "見ています。".format(name, block.get("path")))
        return result

    def _mark_overlays_scanned(self, result, blocks):
        """走査した結果に、混ざったオーバーレイの一覧を入れます。"""
        names = sorted({self._overlay_of(b) for b in blocks
                        if self._overlay_of(b)})
        if names:
            result["overlays_scanned"] = names
            result["overlay_note"] = (
                "オーバーレイ {0} も走査しました。各件の block が "
                "\"overlay:<名前>\" になっているものがその中身です "
                "(Program 本体の値ではありません)。".format(", ".join(names)))
        return result

    @staticmethod
    def _block_range(block):
        """ブロックの開始・終了アドレスを int で返します。壊れていれば (None, None)。"""
        start = try_parse_hex(block.get("start"))
        if start is None:
            return (None, None)
        length = block.get("length")
        try:
            length = int(length)
        except (TypeError, ValueError):
            length = None
        if length:
            return (start, start + length - 1)
        return (start, try_parse_hex(block.get("end")))

    def _find_block(self, address_i, blocks):
        """指定アドレスを含む export 済みブロックを返します。無ければ None。"""
        for block in blocks:
            start, end = self._block_range(block)
            if start is None or end is None:
                continue
            if start <= address_i <= end:
                return block
        return None

    def _memory_path(self, block):
        """ブロックの .bin へのパスを、memory/ 配下であることを検証して返します。"""
        filename = self._sanitize(str(block.get("file")))
        path = self._checked_file(self.memory_dir, filename, "ghidra_exports/memory/")
        if not path.is_file():
            raise ValueError(
                "メモリイメージ {0} が見つかりません。export_context.py を再実行してください。".format(
                    filename))
        return path

    def _read_memory(self, block, offset, length):
        """ブロックの実体から offset..offset+length を読みます (全読みしない)。"""
        if block.get("source") == "overlay":
            path = self._overlay_path(block)
            with path.open("rb") as handle:
                handle.seek(int(block.get("file_offset") or 0) + int(offset))
                return handle.read(int(length))
        if block.get("source") == "executable":
            image = self._executable_image()
            if image is None:
                raise ValueError("実行ファイルを開けません。")
            with image.path.open("rb") as handle:
                handle.seek(int(block.get("exe_offset") or 0) + int(offset))
                return handle.read(int(length))
        path = self._memory_path(block)
        with path.open("rb") as handle:
            handle.seek(offset)
            return handle.read(length)

    # --- ツール 7: 生の逆アセンブル -----------------------------------
    def get_disassembly(self, address, count=DEFAULT_DISASM_COUNT, arch=None,
                        stop_at_return=False, format="json", resolve_gp=True,
                        m=None, x=None, snap=True):
        """指定アドレスから生の逆アセンブルを返します (Ghidra には問い合わせません)。

        未関数化 (LAB_xxxxxxxx) で疑似 C が存在しないコードを読むための手段です。
        ghidra_exports/memory/*.bin をこの MCP 側でデコードします。
        resolve_gp=True なら gp 相対の命令に `= 0x00240e88 名前` を注記します
        (アーキが gp_relative フックを持つときだけ。今は MIPS)。
        m / x は 65816 専用 (P レジスタの M / X フラグ。1 = 8bit)。
        snap は可変長アーキ (65816) 専用: 読み始めが CDL に記録された命令の途中なら、
        その命令の先頭へ合わせて読み直します (既定 true。false なら従来どおり
        alignment_warning だけ付けて、ずれたまま返す)。
        """
        mm, blocks = self._exported_blocks()
        arch_mod = disasm.resolve_arch(mm, arch)
        if getattr(arch_mod, "VARIABLE_LENGTH", False):
            return self._get_disassembly_variable(
                arch_mod, mm, blocks, address, count, stop_at_return, format, m, x,
                snap)
        if m is not None or x is not None:
            raise ValueError("m / x は 65816 専用の指定です ({0} では使えません)。".format(
                arch_mod.NAME))
        target = parse_hex(address)
        big_endian = (mm.get("endian") == "big")
        size = arch_mod.INSTRUCTION_SIZE

        if target % size:
            raise ValueError(
                "アドレス {0} が {1} バイト境界に揃っていません ({2} は固定長命令です)。"
                "0x{3:x} などを指定してください。".format(
                    address, size, arch_mod.NAME, target - (target % size)))

        block = self._find_block(target, blocks)
        if block is None:
            raise ValueError(
                "アドレス {0} を含む memory ブロックが export されていません。"
                "memory_map.json の blocks / skipped_reason を確認してください。".format(address))

        start, end = self._block_range(block)
        want = clamp_count(count, DEFAULT_DISASM_COUNT, MAX_DISASM_COUNT)
        available = (end - target + 1) // size
        n = min(want, available)
        if n <= 0:
            raise ValueError("アドレス {0} はブロック末尾で、命令を取り出せません。".format(address))

        data = self._read_memory(block, target - start, n * size)
        n = min(n, len(data) // size)

        # ★データをコードとして描かない (機能2)。
        #   要求範囲の少し外まで見て「PC 相対ロードが指している番地」を集め、
        #   そこは命令ではなく .long / .word として出す。定数プールやポインタ表が
        #   それらしい命令列に化けて判断を誤らせるのを防ぐ。
        pool_map = self._pool_targets(arch_mod, block, start, big_endian,
                                      target, target + n * size - 1)

        items = []
        branch_targets = []
        call_targets = []
        delay_left = None
        data_count = 0
        skip_until = None
        for i in range(n):
            addr_i = target + i * size
            if skip_until is not None and addr_i < skip_until:
                continue                      # 直前の .long が食べたぶん
            word = arch_mod.word_at(data, i * size, big_endian)
            if word is None:
                break

            pool_size = pool_map.get(addr_i)
            if pool_size:
                item = self._data_word_item(addr_i, data, i * size, pool_size,
                                            big_endian, blocks)
                if item is not None:
                    items.append(item)
                    data_count += 1
                    skip_until = addr_i + pool_size
                    continue

            info = arch_mod.decode(word, addr_i)
            # ★可変長命令への対応 (Thumb の bl は 16bit 命令 2 つで 1 命令)。
            #   decode() が "size" を返したアーキだけ、その分を 1 命令として扱い、
            #   食べたぶんを skip_until で読み飛ばす。"size" を返さない
            #   mips / sh4 は従来どおり INSTRUCTION_SIZE 固定で動く。
            step = int(info.get("size") or size)
            if step > size:
                skip_until = addr_i + step
            raw = data[i * size:i * size + step]
            items.append({
                "addr": "0x{0:08x}".format(addr_i),
                "bytes": raw.hex(),
                # 先読みを含む語を返すアーキ (thumb) は表示用の語を自前で持つ。
                "word": info.get("word") or "0x{0:08x}".format(word),
                "mnemonic": info["mnemonic"],
                "operands": info["operands"],
                "text": info["text"],
                "target": info["target"],
                "flow": info["flow"],
            })
            if info["target"]:
                if info["flow"] == "call":
                    if info["target"] not in call_targets:
                        call_targets.append(info["target"])
                elif info["flow"] in ("branch", "jump"):
                    if info["target"] not in branch_targets:
                        branch_targets.append(info["target"])

            if delay_left is not None:
                delay_left -= 1
                if delay_left <= 0:
                    break
            elif stop_at_return and info["flow"] == "return":
                # 遅延スロットのあるアーキでは次の 1 命令まで含めてから止める。
                delay_left = 1 if getattr(arch_mod, "HAS_DELAY_SLOTS", False) else 0
                if delay_left <= 0:
                    break

        gp_done = gp_missing = 0
        gp_sources = None
        if resolve_gp:
            try:
                gp_done, gp_missing, gp_sources = self._annotate_gp(items, arch_mod)
            except Exception as exc:                    # 注記の失敗で逆アセンブルを落とさない
                gp_missing, gp_sources = -1, str(exc)

        result = {
            "address": address,
            "arch": arch_mod.NAME,
            "arch_display": arch_mod.DISPLAY,
            "endian": mm.get("endian"),
            "block": block.get("name"),
            "requested": want,
            "returned": len(items),
            "truncated": len(items) < want,
            "data_words": data_count,
            "overlay": self._overlay_of(block),
            "data_note": (
                "kind=\"data\" の行は、範囲内の PC 相対ロードが指している番地です。"
                "命令ではなくデータとして出しています。"
                "参照が範囲外にしか無いプールは検出できないので、"
                "命令として出ている行にもデータが混じることがあります。"
                if pool_map else
                "このアーキ / 範囲では PC 相対プールを検出していません "
                "(MIPS のように定数プールを使わないアーキでは常に空です)。"),
        }
        if gp_done:
            result["gp_resolved"] = gp_done
            result["gp_source"] = ", ".join(gp_sources or [])
            result["gp_note"] = ("gp 相対の命令に gp_ref (絶対番地と名前) と comment を"
                                 "付けました。gp の根拠は gp_source です "
                                 "(get_program_info の gp_candidates に全候補)。")
        if gp_missing == -1:
            result["gp_note"] = "gp 相対の注記に失敗しました: {0}".format(gp_sources)
        elif gp_missing:
            result["gp_unresolved"] = gp_missing
            result["gp_note"] = ("gp 相対の命令が {0} 個ありますが、gp の値を求められ"
                                 "なかったので注記していません (get_program_info の "
                                 "gp_warnings を参照)。".format(gp_missing))

        fmt = (format or "json").strip().lower()
        if fmt == "text":
            # ★1 命令 1 行のテキスト。JSON だと 30 命令で数 KB になり、長い関数を
            #   追うだけで文脈を食い潰すため (実際に読み進めを諦める事態になった)。
            #   分岐先の注記は行に残し、要約は末尾に 1 ブロックだけ付ける。
            result["listing"] = self._disasm_listing(items, branch_targets,
                                                     call_targets)
            result["format"] = "text"
            result["note"] = (
                "listing は 1 命令 1 行の '<addr>  <bytes>  <text>' 形式です。"
                "分岐先の一覧は listing 末尾にまとめてあります "
                "(JSON 配列としては返しません。format=\"json\" で従来の形になります)。")
            return result
        if fmt != "json":
            raise ValueError(
                "format '{0}' は未対応です。json か text を指定してください。".format(format))
        result["format"] = "json"
        result["instructions"] = items
        result["branch_targets"] = branch_targets
        result["call_targets"] = call_targets
        return result

    # --- 65816 (可変長・M/X 依存) の逆アセンブル -----------------------
    @staticmethod
    def _parse_flag(value, name):
        """m / x 指定を 0 / 1 / None に正規化します。"""
        if value is None or value == "":
            return None
        if isinstance(value, str):
            text = value.strip().lower()
            if text in ("8", "8bit", "1", "true"):
                return 1
            if text in ("16", "16bit", "0", "false"):
                return 0
            raise ValueError("{0} は 1 (8bit) か 0 (16bit) で指定してください。".format(name))
        return 1 if int(value) else 0

    @staticmethod
    def _parse_byte_setting(value, name, bits):
        """bridge_config の direct_page / data_bank を int にします (無ければ None)。"""
        if value is None or value == "":
            return None
        if isinstance(value, int) and not isinstance(value, bool):
            number = value
        else:
            text = str(value).strip().lstrip("$")
            try:
                number = int(text, 16)
            except ValueError:
                raise ValueError(
                    "bridge_config.json の {0} '{1}' を 16 進として読めません。".format(
                        name, value))
        if number < 0 or number >= (1 << bits):
            raise ValueError("bridge_config.json の {0} が範囲外です: {1}".format(name, value))
        return number

    def _width_context(self, blocks=None):
        """65816 の M/X (CDL) と D / DBR の前提をまとめた WidthContext を返します。

        bridge_config.json:
          "cdl_jsonl":   CDL を変換した JSONL (絶対パスか project root 相対)
          "direct_page": D の値 (既定は $0000 と**仮定**)
          "data_bank":   DBR の値 (既定は命令のバンクと**仮定**)

        cdl_jsonl が書いてあるのにファイルが無ければエラーにします
        (黙って REP/SEP 追跡へ落とすと、推測した幅を CDL の幅と取り違えるため)。
        """
        w65816 = disasm.get_arch("65816")
        cfg = self._safe(lambda: self._bridge_config(), {}) or {}
        if blocks is None:
            _mm, blocks = self._exported_blocks()
        cdl_text = cfg.get("cdl_jsonl")
        cdl_path = None
        cdl_mtime = None
        if cdl_text:
            # ★人間の設定でも、UNC / デバイスパス / 許可ルート外は読まない
            #   (プロジェクト内 + source_roots。外部の CDL は source_roots に足す)。
            cdl_path = self._resolve_allowed_file(
                cdl_text, "bridge_config.json の cdl_jsonl", allow_project=True)
            if not cdl_path.is_file():
                raise ValueError(
                    "bridge_config.json の cdl_jsonl が見つかりません: {0}。"
                    "パスを直すか、項目を消して REP/SEP 追跡 (幅は仮定) で読んでください。".format(
                        cdl_path))
            cdl_mtime = cdl_path.stat().st_mtime
            if cdl_path.stat().st_size > MAX_CDL_BYTES:
                raise ValueError(
                    "cdl_jsonl が大きすぎます ({0} バイト > 上限 {1})。".format(
                        cdl_path.stat().st_size, MAX_CDL_BYTES))
        direct_page = self._parse_byte_setting(cfg.get("direct_page"), "direct_page", 16)
        data_bank = self._parse_byte_setting(cfg.get("data_bank"), "data_bank", 8)
        funcs_path = self.exports_dir / "functions.json"
        funcs_mtime = funcs_path.stat().st_mtime if funcs_path.is_file() else None
        image = []
        for b in blocks:
            lo, hi = self._block_range(b)
            if _has_bytes(b) and lo is not None and hi is not None:
                image.append((lo, hi))
        image = tuple(sorted(image))
        key = (str(cdl_path), cdl_mtime, direct_page, data_bank, funcs_mtime, image)
        cached = getattr(self, "_w65816_ctx", None)
        if cached is not None and cached[0] == key:
            return cached[1]

        spans, ambiguity, header = (), {}, None
        call_targets, code_runs, read_runs = {}, (), ()
        if cdl_path is not None:
            loaded = w65816.load_cdl_jsonl(cdl_path)
            spans, ambiguity, header = (loaded["spans"], loaded["ambiguity"],
                                        loaded["header"])
            # 呼び出し先 (SubEntryPoint) / 実行した区間 / データとして読まれた区間。
            # 分岐を辿る解析 (find_calls_to / find_function_entry / ...) が使う。
            call_targets = loaded.get("call_targets") or {}
            code_runs = loaded.get("code_runs") or ()
            read_runs = loaded.get("read_runs") or ()
        code_ranges = []
        for f in self._safe(lambda: self._load("functions.json"), []) or []:
            for rng in f.get("body_ranges") or []:
                rs = try_parse_hex(rng.get("start") or "")
                re_ = try_parse_hex(rng.get("end") or "")
                if rs is not None and re_ is not None and re_ >= rs:
                    code_ranges.append((rs, re_))
        ctx = w65816.WidthContext(
            spans=spans, ambiguity=ambiguity, code_ranges=sorted(set(code_ranges)),
            image_ranges=image, direct_page=direct_page, data_bank=data_bank,
            source=str(cdl_path) if cdl_path else None, header=header,
            fingerprint=key, call_targets=call_targets, code_runs=code_runs,
            read_runs=read_runs)
        ctx.rom_check = self._cdl_rom_check(header, blocks)
        self._w65816_ctx = (key, ctx)
        return ctx

    def _block_stamp(self, block):
        """ブロックの実体の更新時刻 (キャッシュの鍵用。取れなければ None)。"""
        try:
            if block.get("source") == "overlay":
                return self._overlay_path(block).stat().st_mtime
            if block.get("source") == "executable":
                image = self._executable_image()
                return image.path.stat().st_mtime if image is not None else None
            return self._memory_path(block).stat().st_mtime
        except (OSError, ValueError):
            return None

    def _arch_analyzer(self, arch_mod, blocks=None):
        """分岐を辿る解析器 (アーキの make_analyzer) を作ってキャッシュします。

        全ブロックを番地で引ける BusImage と、65816 なら WidthContext (CDL) を渡します。
        export か CDL か functions.json が変わったら作り直します (リージョンや表の展開を
        使い回すので、同じ条件なら 2 回目以降の問い合わせは速い)。
        """
        make = self._arch_hook(arch_mod, "make_analyzer", "分岐を辿る解析")
        if blocks is None:
            _mm, blocks = self._exported_blocks()
        scan = _scannable([b for b in blocks if b.get("execute") and _has_bytes(b)]) \
            or _scannable([b for b in blocks if _has_bytes(b)])
        ctx = None
        if getattr(arch_mod, "NEEDS_WIDTH_CONTEXT", False):
            ctx = self._width_context(blocks)
        funcs_path = self.exports_dir / "functions.json"
        key = (arch_mod.NAME, ctx.fingerprint if ctx is not None else None,
               funcs_path.stat().st_mtime if funcs_path.is_file() else None,
               tuple((b.get("name"), self._block_range(b)[0], self._block_stamp(b))
                     for b in scan))
        cached = getattr(self, "_analyzer_cache", None)
        if cached is not None and cached[0] == key:
            return cached[1]
        image = BusImage([(self._block_range(b)[0], self._image_bytes(b)) for b in scan])
        entries = {}
        for f in self._safe(lambda: self._load("functions.json"), []) or []:
            entry = try_parse_hex(f.get("entry") or "")
            if entry is not None:
                if ctx is not None:
                    entry = ctx.canonical_rom(entry)
                entries[entry] = f.get("name")
        analyzer = make(image, ctx, entries)
        self._analyzer_cache = (key, analyzer)
        return analyzer

    def _arch_address(self, arch_mod, address):
        """アーキの番地表記を受け付けて int にします (65816 は $80:9447 も可)。"""
        parse = getattr(arch_mod, "parse_bus_address", None)
        if parse is not None:
            return parse(address)
        return parse_hex(address)

    def _cdl_rom_check(self, header, blocks):
        """CDL の header にある ROM の CRC32 と、export したイメージを突き合わせます。

        export 済みブロックを番地順につなげた長さが ROM と同じときだけ比べます
        (LoROM の $80-$8F:8000-FFFF はファイルの並びそのもの)。別の並びなら
        比べようがないので checked=false。別 ROM の CDL を当てると全命令の幅が
        ずれるので、ここで気付けるようにしておきます。
        """
        if not header:
            return {"checked": False, "reason": "CDL が無いか header がありません。"}
        rom = header.get("rom") or {}
        want = str(rom.get("crc32_cartridge") or "").strip().upper()
        size = rom.get("size")
        if not want or not size:
            return {"checked": False,
                    "reason": "header に crc32_cartridge / size がありません。"}
        import zlib
        parts = sorted(((self._block_range(b)[0], b) for b in blocks
                        if _has_bytes(b) and b.get("source") != "overlay"),
                       key=lambda item: item[0])
        total = sum(int(b.get("length") or 0) for _s, b in parts)
        if total != int(size):
            return {"checked": False,
                    "reason": "export 済みブロックの合計 {0} バイトが ROM {1} バイトと"
                              "違うので比べていません。".format(total, size)}
        crc = 0
        for _s, b in parts:
            crc = zlib.crc32(self._read_memory(b, 0, int(b.get("length") or 0)), crc)
        got = "{0:08X}".format(crc & 0xFFFFFFFF)
        return {"checked": True, "match": got == want, "cdl_crc32": want,
                "image_crc32": got, "rom_name": rom.get("name")}

    def _get_disassembly_variable(self, arch_mod, mm, blocks, address, count,
                                  stop_at_return, format, m, x, snap=True):
        """可変長アーキ (65816) の get_disassembly。幅の出どころを命令ごとに返します。"""
        m = self._parse_flag(m, "m")
        x = self._parse_flag(x, "x")
        ctx = self._width_context(blocks)
        requested = arch_mod.parse_bus_address(address)
        target = ctx.canonical_rom(requested)
        snapped = None
        if snap and m is None and x is None:
            # ★命令の途中から読むと以降が全部ずれる。CDL に記録された命令の
            #   先頭 (= target を含む命令) へ合わせて読み直す。
            span0 = ctx.span_at(target)
            block0 = self._find_block(target, blocks)
            if span0 is not None and block0 is not None and _has_bytes(block0) \
                    and span0[0] < target:
                bstart0, bend0 = self._block_range(block0)
                if bstart0 <= span0[0]:
                    data0 = self._read_memory(block0, span0[0] - bstart0,
                                              min(bend0, target + 4) - span0[0] + 1)
                    hit = arch_mod.instruction_start_check(data0, span0[0], span0,
                                                           target, ctx)
                    if hit is not None:
                        snapped = {"from": "0x{0:06x}".format(target),
                                   "to": hit["inside"], "inside_text": hit["text"]}
                        target = int(hit["inside"], 16)
        block = self._find_block(target, blocks)
        if block is None or not _has_bytes(block):
            raise ValueError(
                "アドレス {0} を含む memory ブロックが export されていません。"
                "memory_map.json の blocks / skipped_reason を確認してください "
                "(SNES は ROM の正規窓 (例 $80-$8F) 側を指定すること)。".format(address))
        start, end = self._block_range(block)
        want = clamp_count(count, DEFAULT_DISASM_COUNT, MAX_DISASM_COUNT)

        # CDL の区間の途中から読み始めるときは、区間の先頭から読んで
        # 「命令の途中ではないか」を確かめる (途中なら全行がずれる)。
        span = ctx.span_at(target)
        read_from = target
        if span is not None and start <= span[0] < target:
            read_from = span[0]
        length = min(end - read_from + 1, (target - read_from) + want * 4 + 4)
        data = self._read_memory(block, read_from - start, length)
        alignment = None
        if read_from < target and m is None and x is None:
            alignment = arch_mod.instruction_start_check(data, read_from, span,
                                                         target, ctx)
        insns = arch_mod.disassemble(data, read_from, start=target, count=want,
                                     ctx=ctx, m=m, x=x,
                                     stop_at_return=stop_at_return)

        items = []
        branch_targets = []
        call_targets = []
        uncertain = 0
        fmt24 = arch_mod.ADDR_FORMAT
        namer = self._ram_namer(arch_mod, ctx)
        for ins in insns:
            item = {
                "addr": fmt24.format(ins["addr"]),
                "bytes": ins["bytes"].hex(),
                "word": "0x" + ins["bytes"].hex(),
                "mnemonic": ins["mnemonic"],
                "operands": ins["operands"],
                "text": ins["text"],
                "target": (fmt24.format(ins["target"])
                           if ins["target"] is not None else None),
                "flow": ins["flow"],
                "m": ins["m"],
                "x": ins["x"],
                "width_source": ins["width_source"],
                "flags_source": (ins["m_source"] if ins["m_source"] == ins["x_source"]
                                 else "m:{0} x:{1}".format(ins["m_source"],
                                                           ins["x_source"])),
                "cdl": ins["cdl"],
            }
            comments = []
            if ins["width_uncertain"]:
                uncertain += 1
                item["width_uncertain"] = True
                flag = arch_mod.width_flag(ins["mnemonic"], ins["mode"])
                comments.append("★幅未確定 ({0}={1} で読んだ: {2})".format(
                    flag, ins[flag], ins["width_source"]))
            if ins.get("target_raw") is not None:
                item["target_raw"] = fmt24.format(ins["target_raw"])
                comments.append("= " + arch_mod.bus_text(ins["target"]))
            refs = []
            for ref in ins.get("refs") or ():
                row = {"ea": fmt24.format(ref["ea"]), "form": ref["form"],
                       "access": ref["access"]}
                if ref.get("size"):
                    row["size"] = ref["size"]
                if ref["assumptions"]:
                    row["assumptions"] = list(ref["assumptions"])
                hit = namer(ref["ea"], ref["indexed"]) if (
                    namer is not None and ref["access"] != "imm") else None
                if hit is not None:
                    row["name"] = hit.get("name")
                    if hit.get("bits"):
                        row["bits"] = hit["bits"]
                refs.append(row)
                if ref["access"] != "imm":
                    label = ""
                    if hit is not None:
                        label = " ({0})".format(hit.get("name") or ",".join(
                            "bit{0}={1}".format(b, n) for b, n in hit.get("bits", {}).items()))
                    comments.append("{0} {1}{2}{3}".format(
                        "ptr" if ref.get("pointer") else ref["access"],
                        arch_mod.bus_text(ref["ea"]), "+idx" if ref["indexed"] else "",
                        label))
            if refs:
                item["refs"] = refs
            if ins.get("note"):
                item["note"] = ins["note"]
            if ins.get("cdl_ambiguity"):
                item["cdl_ambiguity"] = ins["cdl_ambiguity"]
                comments.append("CDL: 呼び出し元で幅が変わる入口")
            if ins["flow"] in ("call", "jump") and ins["target"] is not None:
                info = self._safe(
                    lambda: self._describe_address(ins["target"], blocks), None)
                if info and info.get("function"):
                    comments.append(info["function"])
            if comments:
                item["comment"] = "; ".join(comments)
            items.append(item)
            if item["target"] and ins["flow"] in ("call", "branch", "jump"):
                bucket = call_targets if ins["flow"] == "call" else branch_targets
                if item["target"] not in bucket:
                    bucket.append(item["target"])

        result = {
            "address": address,
            "address_canonical": fmt24.format(target) if target != requested else None,
            "arch": arch_mod.NAME,
            "arch_display": arch_mod.DISPLAY,
            "endian": mm.get("endian"),
            "block": block.get("name"),
            "requested": want,
            "returned": len(items),
            "truncated": len(items) < want,
            "data_words": 0,
            "overlay": self._overlay_of(block),
            "width_context": ctx.summary(),
            "width_given": ({"m": m, "x": x}
                            if (m is not None or x is not None) else None),
            "width_uncertain_count": uncertain,
            "width_note": (
                "m / x は各命令を読んだときの P の M / X (1 = 8bit)。width_source は"
                "即値の長さを決めたフラグの出どころ (n/a = 長さが幅に依存しない命令)。"
                "cdl_recorded / cdl_static_only = Mesen CDL、given = 引数、"
                "tracked = REP/SEP、carried = CDL 区間の外へ持ち越し、"
                "ambiguous / unknown / assumed = **推測** (width_uncertain=true)。"),
            "data_note": ("65816 では PC 相対の定数プールを検出しません。CDL に記録の無い"
                          "(cdl=null) 行はデータかもしれません。"),
        }
        rom_check = getattr(ctx, "rom_check", None) or {}
        if rom_check.get("checked") and not rom_check.get("match"):
            result["cdl_rom_mismatch"] = rom_check
        if snapped is not None:
            result["snapped"] = snapped
            result["alignment_note"] = (
                "{0} は CDL に記録された命令 {1} ({2}) の途中だったので、{1} から読み直し"
                "ました (snap=false でずれたまま読めます)。".format(
                    address, snapped["to"], snapped["inside_text"]))
        if alignment is not None:
            result["alignment_warning"] = (
                "{0} は CDL に記録された命令 {1} ({2}, {3} バイト) の途中です。"
                "以下の行は全部ずれています。{1} から読み直してください。".format(
                    address, alignment["inside"], alignment["text"], alignment["size"]))
        if span is None and ctx.has_cdl:
            result["cdl_note"] = ("読み始めの番地は CDL に記録がありません "
                                  "(未実行のコードかデータ)。幅は CDL 以外から決めています。"
                                  "CDL の外を読むなら find_function_entry で入口と入口の幅を"
                                  "推定し、m / x を渡して入口から読むと確実です。")

        fmt = (format or "json").strip().lower()
        if fmt == "text":
            result["listing"] = self._disasm_listing_65816(
                items, branch_targets, call_targets, arch_mod)
            result["format"] = "text"
            result["note"] = (
                "listing は 1 命令 1 行の '<addr>  <bytes>  <src> m<M>x<X>  <text>  ; 注記' "
                "形式です。src は幅の出どころ: R=CDL 記録 / S=CDL 静的延長 / G=引数 / "
                "T=REP・SEP 追跡 / C=CDL の持ち越し / A=仮定 / ?=不明・曖昧。"
                "注記の W / R / RW / ptr は実効番地 (D=$0000・DBR=命令のバンク を仮定。"
                "詳細は format=\"json\" の refs[].assumptions)。")
            return result
        if fmt != "json":
            raise ValueError(
                "format '{0}' は未対応です。json か text を指定してください。".format(format))
        result["format"] = "json"
        result["instructions"] = items
        result["branch_targets"] = branch_targets
        result["call_targets"] = call_targets
        return result

    @staticmethod
    def _disasm_listing_65816(items, branch_targets, call_targets, arch_mod):
        """65816 用の 1 命令 1 行テキスト (幅の出どころの列付き)。"""
        width = max((len(it["bytes"]) for it in items), default=8)
        lines = []
        for it in items:
            src = it["width_source"]
            if src == "n/a":
                # 長さが幅に依存しない命令は、m の出どころを代表として出す。
                src = it["flags_source"].split(" ")[0].replace("m:", "")
            letter = arch_mod.SOURCE_LETTER.get(src, "?")
            line = "{0}  {1:<{2}}  {3} m{4}x{5}  {6}".format(
                it["addr"][2:], it["bytes"], width, letter, it["m"], it["x"],
                it["text"])
            if it.get("comment"):
                line += "  ; " + it["comment"]
            lines.append(line)
        tail = []
        if branch_targets:
            tail.append("-- branch targets: " + ", ".join(branch_targets))
        if call_targets:
            tail.append("-- call targets:   " + ", ".join(call_targets))
        if tail:
            lines.append("")
            lines.extend(tail)
        return "\n".join(lines)

    @staticmethod
    def _disasm_listing(items, branch_targets, call_targets):
        """逆アセンブル結果を 1 命令 1 行のテキストにまとめます。

        バイト列の桁数はアーキで違う (Thumb 2 / ARM・MIPS 4) ので、実際に出た
        最大幅に合わせて揃えます。
        """
        width = max((len(it["bytes"]) for it in items), default=8)
        lines = []
        for it in items:
            line = "{0}  {1:<{2}}  {3}".format(
                it["addr"][2:] if it["addr"].startswith("0x") else it["addr"],
                it["bytes"], width, it["text"])
            if it.get("comment"):
                line += "  ; " + it["comment"]
            lines.append(line)
        tail = []
        if branch_targets:
            tail.append("-- branch targets: " + ", ".join(branch_targets))
        if call_targets:
            tail.append("-- call targets:   " + ", ".join(call_targets))
        if tail:
            lines.append("")
            lines.extend(tail)
        return "\n".join(lines)

    # --- ツール 8: アドレス参照検索 (Ghidra の xref に頼らない) -------
    def _ref_index_for(self, block, arch_mod, big_endian):
        """ブロックの即値ペア索引を構築し、mtime キャッシュして返します。

        構築は 1 ブロックにつき 1 回だけ (全走査は数十万〜数百万命令になるため)。
        .bin が再 export で更新されたら自動で作り直します。索引だけを保持し、
        バイト列そのものは構築後に捨てます (16MB イメージを常駐させない)。
        """
        # 実行ファイル由来のブロックには .bin がありません
        # (memory 未 export の Program)。同じ扱いにするため、
        # 実体の取り出しは _image_bytes に任せます。
        if block.get("source") == "executable":
            image = self._executable_image()
            if image is None:
                raise ValueError("実行ファイルを開けません。")
            mtime = image.path.stat().st_mtime
            key = ("exe", block.get("name"), block.get("exe_offset"))
        else:
            path = self._memory_path(block)
            mtime = path.stat().st_mtime
            key = block.get("file")
        ctx = None
        if getattr(arch_mod, "NEEDS_WIDTH_CONTEXT", False):
            # 65816: 幅 (CDL) / D / DBR の前提が変われば索引も作り直す。
            ctx = self._width_context()
            key = (key, arch_mod.NAME, ctx.fingerprint)
        cached = self._ref_index.get(key)
        if cached is not None and cached[0] == mtime:
            return cached[1], False
        start, _ = self._block_range(block)
        if ctx is not None:
            index = arch_mod.build_ref_index(self._image_bytes(block), start,
                                             big_endian, context=ctx)
        else:
            index = arch_mod.build_ref_index(self._image_bytes(block), start,
                                             big_endian)
        self._ref_index[key] = (mtime, index)
        return index, True

    def find_address_refs(self, address, mask=0xFFFFFFFF, limit=DEFAULT_REFS_LIMIT,
                          range_end=None, include_branches=False):
        """指定アドレスを参照しているコードを、命令の即値から再構成して探します。

        Ghidra が「データ参照」と認識していない (未定義領域に置かれた) テーブルでも
        見つけられるのが `get_xrefs` との違いです。MIPS なら
        `lui rX, hi` + 後続の `addiu/lw/sw/...` の下位 16bit を合成して比較します。

        mask を使うと帯域検索になります (例 mask=0xffff0000 で 0x8008xxxx 全部)。
        """
        mm, blocks = self._exported_blocks()
        arch_mod = disasm.resolve_arch(mm)
        big_endian = (mm.get("endian") == "big")
        width_ctx = None
        if getattr(arch_mod, "NEEDS_WIDTH_CONTEXT", False):
            # 65816: '$80:9447' 表記も受け付け、WRAM ミラー ($00:0B20 = $7E:0B20)
            # や ROM ミラー ($00:xxxx = $80:xxxx) を索引と同じ正規形に寄せる。
            width_ctx = self._width_context(blocks)

            def parse_target(text):
                return arch_mod.canonical_query(arch_mod.parse_bus_address(text),
                                                width_ctx)
        else:
            parse_target = parse_hex
        target = parse_target(address)
        mask_i = _parse_mask(mask)
        lim = clamp_count(limit, DEFAULT_REFS_LIMIT, MAX_REFS_LIMIT)
        # range_end を指定すると [address, range_end] のどこかを指す参照を探す。
        # 表の「先頭」ではなく「途中」を指す参照を取りこぼさないための指定。
        # mask と併用された場合は範囲を優先する (両立させると意味が取りにくいため)。
        hi_i = parse_target(range_end) if range_end else None
        if hi_i is not None and hi_i < target:
            raise ValueError("range_end が address より小さいです。")
        if hi_i is not None:
            mask_i = 0xFFFFFFFF
        branch_forms = getattr(arch_mod, "BRANCH_FORMS", ("bra", "bsr", "j", "jal"))
        addr_fmt = getattr(arch_mod, "ADDR_FORMAT", "0x{0:08x}")
        # コードは実行属性のあるブロックにある。1 つも無ければ全ブロックを見る
        # (raw binary 由来だと属性が付いていないことがあるため)。
        scan = _scannable([b for b in blocks if b.get("execute")]) \
            or _scannable(blocks)

        matched = []
        built = []
        wanted = target & mask_i
        for block in scan:
            index, was_built = self._ref_index_for(block, arch_mod, big_endian)
            if was_built:
                built.append(block.get("name"))
            if hi_i is not None:
                # ★範囲検索では分岐 (bra/bsr/j/jal) を除く。
                #   どんなコード範囲にも分岐先は必ず含まれるので、そのまま出すと
                #   本命のデータ参照が埋もれる。include_branches=True で戻せる。
                buckets = []
                for addr, refs in index.items():
                    if not (target <= addr <= hi_i):
                        continue
                    if include_branches:
                        buckets.append((addr, refs))
                        continue
                    kept = [r for r in refs if r[1] not in branch_forms]
                    if kept:
                        buckets.append((addr, kept))
            elif mask_i == 0xFFFFFFFF:
                buckets = [(target, index.get(target, []))]
            else:
                buckets = [(addr, refs) for addr, refs in index.items()
                           if (addr & mask_i) == wanted]
            for resolved, refs in buckets:
                for ref in refs:
                    ref_addr, form, hi_addr = ref[:3]
                    row = {
                        "ref_addr": addr_fmt.format(ref_addr),
                        "resolved_addr": addr_fmt.format(resolved),
                        "form": form,
                        "hi_addr": addr_fmt.format(hi_addr),
                        "block": block.get("name"),
                        "_sort": ref_addr,
                        "_block": block,
                    }
                    # 4 つ目を持つアーキ (65816) は、命令の text・幅の出どころ・
                    # 前提 (D / DBR の仮定) を索引の時点で持っている。
                    if len(ref) > 3 and ref[3]:
                        row.update(ref[3])
                    matched.append(row)

        matched.sort(key=lambda item: item["_sort"])
        items = matched[:lim]
        self._annotate_ref_text(items, arch_mod, big_endian)
        namer = self._ram_namer(arch_mod, width_ctx)
        self._name_items(items, namer, key="resolved_addr", out_key="resolved_name")
        for item in items:
            item.pop("_sort", None)
            item.pop("_block", None)

        result = {
            "address": address,
            "range_end": range_end,
            "range_is_inclusive": True if hi_i is not None else None,
            "branches_excluded": (hi_i is not None and not include_branches),
            "mask": "0x{0:08x}".format(mask_i) if hi_i is None else None,
            "arch": arch_mod.NAME,
            "scanned_blocks": [b.get("name") for b in scan],
            "index_built_this_call": built,
            "total": len(matched),
            "limit": lim,
            "returned": len(items),
            "items": items,
            # 取りこぼしの注意はアーキごとに全く違う (MIPS=即値ペアの窓 /
            # SH-4=定数プールと GBR 相対) ので、arch モジュールに書かせる。
            "note": getattr(arch_mod, "REFS_NOTE",
                            "このアーキの取りこぼし条件は未記載です。"),
        }
        if namer is not None:
            hit = namer(target)
            if hit is not None:
                result["target_name"] = hit.get("name")
                if hit.get("bits"):
                    result["target_bits"] = hit["bits"]
        if width_ctx is not None:
            result["target_canonical"] = addr_fmt.format(target)
            result["width_context"] = width_ctx.summary()
            result["scan_basis"] = arch_mod.scan_basis(width_ctx)
            result["width_uncertain_hits"] = sum(
                1 for it in matched if it.get("width_uncertain"))
        if not matched:
            # ★ 0 件を「参照が無い」と誤結論させない。このツールは原理的に
            #   拾えない形がある (SH-4 の GBR 相対、MIPS の addu 経由コピー等)。
            #   docs に書くだけでは見落とされるので、道具自身に言わせる。
            result["hint"] = self._zero_refs_hint(arch_mod, target, mask_i, scan)
        return result

    def _zero_refs_hint(self, arch_mod, target, mask_i, scan):
        """0 件だったときの「次に疑うべきこと」を組み立てます。

        このツールは命令の形からアドレスを再構成するので、**原理的に
        拾えない参照の形があります** (SH-4 の GBR 相対、MIPS の addu 経由コピー等)。
        0 件を「参照が無い」と誤結論されるのを防ぐため、アーキ固有の
        盲点と具体的な次の一手を応答に入れます。
        """
        blind = list(getattr(arch_mod, "REFS_BLIND_SPOTS", ()))
        steps = []
        if mask_i == 0xFFFFFFFF:
            steps.append(
                "mask=\"0xffff0000\" で帯域検索する — 近い番地への参照があれば、"
                "その先頭 + オフセットで引かれている可能性が高い。")
        else:
            steps.append("mask を緩める (例: 0xffff0000 → 0xfff00000) か、mask 無しでも試す。")
        steps.append(
            "get_xrefs(to_address=...) で Ghidra 側の認識も見る "
            "(定義済みデータならこちらにだけ出る)。")
        steps.append(
            "read_data でその番地の中身を見る — そもそもテーブルなのかを確かめる。")
        steps.append(
            "表の先頭ではなく途中の番地を探していないか見直す "
            "(コードには先頭しか現れないことが多い)。")
        if len(scan) == 1:
            steps.append(
                "走査したのはブロック {0} だけ。参照元が別 Program "
                "(オーバーレイ/ダンプ) にある可能性を疑う。".format(
                    scan[0].get("name")))
        return {
            "message": "0 件でした。**「参照が無い」と結論する前に**、"
                       "このツールが原理的に拾えない形を疑ってください。",
            "blind_spots": blind,
            "next_steps": steps,
        }

    def _pool_targets(self, arch_mod, block, start, big_endian, lo, hi,
                      pad=512):
        """要求範囲の前後まで見て「PC 相対ロードが指す番地」を集めます。

        pad ぶん広げるのは、プールを指すロード命令が要求範囲の外にいることが
        多いためです (プールは関数の末尾にまとまって置かれる)。
        アーキが PC 相対プールを使わない (MIPS 等) 場合は空 dict を返します。
        """
        hook = getattr(arch_mod, "pc_relative_targets", None)
        if hook is None:
            return {}
        bstart, bend = self._block_range(block)
        scan_lo = max(bstart, lo - pad)
        scan_hi = min(bend, hi + pad)
        if scan_hi < scan_lo:
            return {}
        try:
            data = self._read_memory(block, scan_lo - bstart, scan_hi - scan_lo + 1)
        except (ValueError, OSError):
            return {}
        return hook(data, scan_lo, big_endian, scan_lo, scan_hi)

    def _data_word_item(self, addr, data, offset, width, big_endian, blocks):
        """データ語 1 件を `.long` / `.word` 行として組み立てます。"""
        if offset + width > len(data):
            return None
        raw = data[offset:offset + width]
        value = int.from_bytes(raw, "big" if big_endian else "little")
        mnemonic = ".long" if width == 4 else ".word"
        operands = "0x{0:0{1}x}".format(value, width * 2)
        text = "{0} {1}".format(mnemonic, operands)
        item = {
            "addr": "0x{0:08x}".format(addr),
            "bytes": raw.hex(),
            "word": operands,
            "kind": "data",
            "mnemonic": mnemonic,
            "operands": operands,
            "text": text,
            "target": None,
            "flow": None,
        }
        if width == 4:
            resolved = self._resolve_pointer(value, blocks)
            if resolved:
                item["resolved"] = resolved
                label = resolved.get("string")
                via = resolved.get("string_via_pointer")
                if label is not None:
                    item["text"] = '{0}        ; -> "{1}"'.format(text, label)
                elif via is not None:
                    item["text"] = '{0}        ; -> "{1}"'.format(text, via)
                elif resolved.get("function"):
                    item["text"] = "{0}        ; -> {1}".format(
                        text, resolved["function"])
        return item

    def _annotate_ref_text(self, items, arch_mod, big_endian):
        """参照元命令を 1 命令だけ逆アセンブルして text を添えます (可読性のため)。

        .bin はブロックごとに 1 回だけ open します (件数ぶん open すると
        数十 ms 単位で無駄が出るため)。
        """
        size = arch_mod.INSTRUCTION_SIZE
        by_block = {}
        for item in items:
            if item.get("text"):
                continue                      # 索引が text を持っている (65816)
            item["text"] = None
            if getattr(arch_mod, "VARIABLE_LENGTH", False):
                continue                      # 可変長は 1 語だけ読んでも正しく出ない
            block = item.get("_block")
            if block:
                by_block.setdefault(id(block), (block, []))[1].append(item)

        for block, group in by_block.values():
            start, _ = self._block_range(block)
            if start is None:
                continue
            try:
                path = self._memory_path(block)
            except ValueError:
                continue
            with path.open("rb") as handle:
                for item in group:
                    addr_i = int(item["ref_addr"], 16)
                    try:
                        handle.seek(addr_i - start)
                        word = arch_mod.word_at(handle.read(size), 0, big_endian)
                    except OSError:
                        continue
                    if word is not None:
                        item["text"] = arch_mod.decode(word, addr_i)["text"]

    # --- 解析ツール共通の土台 -----------------------------------------
    def _image_bytes(self, block):
        """ブロックの .bin を丸ごと読み、直近 1 件だけキャッシュします。

        find_writers / find_pointer_tables のように全域走査が要る機能のためです。
        16MB 級を複数抱えないよう、キャッシュは 1 ブロックぶんに限ります。
        """
        if block.get("source") == "overlay":
            path = self._overlay_path(block)
            key = (block.get("name"), block.get("file_offset"),
                   path.stat().st_mtime)
            if self._image_cache is not None and self._image_cache[0] == key:
                return self._image_cache[1]
            offset = int(block.get("file_offset") or 0)
            length = int(block.get("length") or 0)
            if length > MAX_IMAGE_BYTES:
                raise ValueError(
                    "オーバーレイ '{0}' が大きすぎます ({1} バイト > 上限 {2})。"
                    "overlays の length で区切ってください。".format(
                        block.get("overlay"), length, MAX_IMAGE_BYTES))
            with path.open("rb") as handle:
                handle.seek(offset)
                data = handle.read(length)
            self._image_cache = (key, data)
            return data
        if block.get("source") == "executable":
            image = self._executable_image()
            if image is None:
                raise ValueError("実行ファイルを開けません。")
            key = (block.get("name"), block.get("exe_offset"),
                   image.path.stat().st_mtime)
            if self._image_cache is not None and self._image_cache[0] == key:
                return self._image_cache[1]
            start, _end = self._block_range(block)
            length = int(block.get("length") or 0)
            if length > MAX_IMAGE_BYTES:
                raise ValueError(
                    "ブロック '{0}' が大きすぎます ({1} バイト > 上限 {2})。".format(
                        block.get("name"), length, MAX_IMAGE_BYTES))
            data = image.read(start, length)
            self._image_cache = (key, data)
            return data
        path = self._memory_path(block)
        key = (block.get("file"), path.stat().st_mtime)
        if self._image_cache is not None and self._image_cache[0] == key:
            return self._image_cache[1]
        data = _read_bytes_capped(path, MAX_IMAGE_BYTES, "memory/{0}".format(path.name))
        self._image_cache = (key, data)
        return data

    @staticmethod
    def _arch_hook(arch_mod, name, what):
        """arch モジュールの解析フックを取り出します。無ければ「未対応」エラー。"""
        hook = getattr(arch_mod, name, None)
        if hook is None:
            raise ValueError(
                "{0} は {1} では未対応です ({2})。"
                "mcp/disasm/{1}.py に {3}() を実装すれば使えるようになります。"
                "当面は Ghidra GUI の Listing を直接読んでください。".format(
                    what, arch_mod.NAME, arch_mod.DISPLAY, name))
        return hook

    def _analysis_context(self, address, arch=None):
        """解析ツール共通の (memory_map, blocks, block, arch モジュール, データ) を返します。"""
        mm, blocks = self._exported_blocks()
        arch_mod = disasm.resolve_arch(mm, arch)
        target = self._arch_address(arch_mod, address)
        if getattr(arch_mod, "NEEDS_WIDTH_CONTEXT", False):
            # 65816: ROM のミラー ($00-$3F) は Program に載っている方へ寄せる。
            target = self._width_context(blocks).canonical_rom(target)
        block = self._find_block(target, blocks)
        if block is None:
            raise ValueError(
                "アドレス {0} を含む memory ブロックが export されていません。"
                "memory_map.json の blocks / skipped_reason を確認してください。".format(address))
        start, _ = self._block_range(block)
        return target, mm, blocks, block, start, arch_mod

    def _read_cstring_at(self, address, blocks, max_len=96):
        """指定アドレスから NUL 終端文字列を読みます。読めなければ None。"""
        block = self._find_block(address, blocks)
        if block is None:
            return None
        start, end = self._block_range(block)
        length = min(max_len, end - address + 1)
        if length <= 0:
            return None
        try:
            raw = self._read_memory(block, address - start, length)
        except (ValueError, OSError):
            return None
        cut = raw.find(b"\x00")
        if cut < 0:
            return None
        chunk = raw[:cut]
        if not chunk:
            return None
        if not all(0x20 <= b < 0x7F or b in (9,) for b in chunk):
            return None
        return chunk.decode("ascii", "replace")

    def _resolve_pointer(self, value, blocks, follow=True):
        """ポインタ値の指す先を人間向けに 1 行で説明します (分からなければ None)。

        直接の指し先が文字列でなければ、**1 段だけ間接参照を追います**。
        ポインタ表を指すポインタ (表 -> 文字列) が実際に多く、そこで諦めると
        「何を指しているのか」が分からないままになるためです。
        """
        info = self._describe_address(value, blocks)
        text = self._read_cstring_at(value, blocks)
        if text:
            out = dict(info or {})
            out["string"] = text
            return out
        if follow and self._find_block(value, blocks) is not None:
            inner = self._deref_u32(value, blocks)
            if inner is not None:
                deeper = self._read_cstring_at(inner, blocks)
                if deeper:
                    out = dict(info or {})
                    out["points_to"] = "0x{0:08x}".format(inner)
                    out["string_via_pointer"] = deeper
                    return out
        return info

    def _deref_u32(self, address, blocks):
        """指定アドレスの 32bit 値を読みます (読めなければ None)。"""
        block = self._find_block(address, blocks)
        if block is None:
            return None
        start, end = self._block_range(block)
        if address + 4 > end + 1:
            return None
        try:
            raw = self._read_memory(block, address - start, 4)
        except (ValueError, OSError):
            return None
        if len(raw) < 4:
            return None
        mm = self._safe(lambda: self._load("memory_map.json"), {})
        order = "big" if (isinstance(mm, dict) and mm.get("endian") == "big") else "little"
        return int.from_bytes(raw, order)

    # --- ツール: find_writers ------------------------------------------
    def find_writers(self, address, mask=0xFFFFFFFF, max_scan=12, trace_imm=16,
                     scan_basis=None, index_reach=None, target_end=None):
        """その番地に **書き込んでいる命令** を、可能なら書く値まで添えて列挙します。

        `find_address_refs` の対になる機能です。「このフラグを 0 に戻している命令を
        全部潰したい。潰し漏れはないか」に答えるための道具です。
        scan_basis はアーキが WRITERS_SCAN_BASES で受け付けるものだけ (65816: cdl / bytes)。
        address に '@配列.項目' / '@配列.項目[k]' (record_formats の項目ごとの配列) を
        渡すと、その項目の全要素 (または要素 k) へ触る命令を項目名つきで返します。
        target_end は内部用 (アーキが WRITERS_TARGET_RANGE を持つときだけ)。
        """
        if isinstance(address, str) and address.strip().startswith("@"):
            return self._find_writers_soa(address, max_scan, trace_imm, scan_basis,
                                          index_reach)
        mask_i = _parse_mask(mask)
        mm, blocks = self._exported_blocks()
        arch_mod = disasm.resolve_arch(mm)
        hook = self._arch_hook(arch_mod, "find_writers", "find_writers")
        big_endian = (mm.get("endian") == "big")
        width_ctx = None
        extra = {}
        basis = (scan_basis or "").strip().lower() or None
        bases = getattr(arch_mod, "WRITERS_SCAN_BASES", ())
        if basis is not None and basis not in bases:
            raise ValueError(
                "scan_basis='{0}' は {1} では使えません{2}。".format(
                    scan_basis, arch_mod.NAME,
                    " (使えるのは {0})".format(" / ".join(bases)) if bases else
                    " (このアーキは scan_basis を持ちません)"))
        if getattr(arch_mod, "NEEDS_WIDTH_CONTEXT", False):
            # 65816: 番地は '$7E:0B20' 表記も可。正規化はモジュール側で行う。
            width_ctx = self._width_context(blocks)
            target = arch_mod.parse_bus_address(address)
            extra["context"] = width_ctx
            if index_reach is not None:
                extra["index_reach"] = int(index_reach)
            if target_end is not None:
                extra["target_end"] = arch_mod.parse_bus_address(target_end)
            if basis == "bytes":
                extra["scan_basis"] = "bytes"
                extra["analyzer"] = self._arch_analyzer(arch_mod, blocks)
        else:
            target = parse_hex(address)
        if target_end is not None and not getattr(arch_mod, "WRITERS_TARGET_RANGE", False):
            raise ValueError("{0} の find_writers は範囲指定 (target_end) に対応していません。".format(
                arch_mod.NAME))

        # ★書き込み先は **export されたブロックの外**にあるのが普通です
        #   (BSS / スクラッチパッド / IO レジスタ)。ターゲットの居るブロックを
        #   探しに行くと「export されていません」で門前払いになるので、
        #   find_address_refs と同じく**コード側**を走査します。
        scan = _scannable([b for b in blocks if b.get("execute")]) \
            or _scannable(blocks)
        merged = {"pools": [], "writers": [], "offset_writers": [],
                  "readers": [], "unresolved": [], "max_scan_reached": 0}
        scanned = []
        for blk in scan:
            bstart, _ = self._block_range(blk)
            part = hook(self._image_bytes(blk), bstart, big_endian, target,
                        mask_i, clamp_count(max_scan, 12, 128),
                        clamp_count(trace_imm, 16, 128), **extra)
            scanned.append(blk.get("name"))
            for key in ("pools", "writers", "offset_writers", "readers",
                        "unresolved", "not_covering", "boundary_rejected"):
                if key in part:
                    merged.setdefault(key, []).extend(part.get(key) or [])
            merged["max_scan_reached"] += part.get("max_scan_reached") or 0
            for key, value in part.items():
                if key not in merged:
                    merged[key] = value
                elif (key not in ("max_scan_reached", "pool_count", "load_count")
                      and isinstance(value, int) and not isinstance(value, bool)
                      and isinstance(merged[key], int)):
                    merged[key] += value          # ブロックごとの件数は合算する

        result = merged
        result["pools"] = sorted(set(result["pools"]))
        result["pool_count"] = len(result["pools"])
        result["load_count"] = (len(result["writers"])
                                + len(result["offset_writers"])
                                + len(result["readers"])
                                + len(result["unresolved"]))
        result["address"] = address
        result["mask"] = "0x{0:08x}".format(mask_i)
        result["arch"] = arch_mod.NAME
        result["scanned_blocks"] = scanned
        result["block"] = scanned[0] if len(scanned) == 1 else None
        result["note"] = getattr(arch_mod, "WRITERS_NOTE",
                                 "このアーキの取りこぼし条件は未記載です。")
        namer = self._ram_namer(arch_mod, width_ctx)
        if namer is not None:
            for key in ("writers", "offset_writers", "readers", "not_covering",
                        "boundary_rejected"):
                self._name_items(result.get(key), namer)
            hit = namer(self._arch_canonical(arch_mod, width_ctx, target))
            if hit is not None:
                result["target_name"] = hit.get("name")
                if hit.get("bits"):
                    result["target_bits"] = hit["bits"]
        if width_ctx is not None:
            result["width_context"] = width_ctx.summary()
            result["mask"] = "0x{0:06x}".format(mask_i & 0xFFFFFF)
            for key in ("writers", "offset_writers", "readers", "not_covering",
                        "boundary_rejected"):
                if key in result:
                    result[key].sort(key=lambda it: it["addr"])
            if basis == "bytes":
                result["note"] = getattr(arch_mod, "WRITERS_BYTES_NOTE", result["note"])
                for it in result["writers"] + result["offset_writers"]:
                    info = self._describe_address(int(it["addr"], 16), blocks) or {}
                    if info.get("function"):
                        it["function"] = info["function"]
                result["summary"] = {
                    "writers": len(result["writers"]),
                    "writers_not_found_by_cdl_scan": sum(
                        1 for it in result["writers"] if not it.get("found_by_cdl_scan")),
                    "writers_width_unknown": sum(
                        1 for it in result["writers"] if it.get("width") is None),
                    "not_covering": len(result.get("not_covering") or []),
                    "boundary_rejected": len(result.get("boundary_rejected") or []),
                }
        if not result.get("writers"):
            result["hint"] = {
                "message": "書き込みが 0 件でした。**「誰も書いていない」と結論する前に**"
                           "下を疑ってください。",
                "blind_spots": list(getattr(arch_mod, "WRITERS_BLIND_SPOTS", ())),
                "next_steps": [
                    "max_scan を増やす (既定 12 命令)。ロードから離れた位置で書いているかもしれない。",
                    "offset_writers を見る — 近傍の番地へ書いている命令があるかもしれない。",
                    "find_address_refs でそもそも参照があるかを確認する。",
                    "読み出しだけなら、値は別の経路 (DMA / 別 Program / 初期化データ) で入る。",
                ],
            }
            if width_ctx is not None:
                result["hint"]["next_steps"] = [
                    "offset_writers を見る — ,X / ,Y 付きで近くの基底番地から書いている。",
                    "indirect_stores が 0 でなければ STA (dp),Y 等の間接書き込みがある。"
                    "行き先は実行時に決まるので、Mesen の書き込みウォッチで確かめる。",
                    "CDL に記録の無いコードは読んでいない。その場面を遊んで CDL を増やす。",
                    "DMA ($43xx) / MVN・MVP で入る値なら命令としての書き込みは出ない。",
                ]
        return result

    # --- ツール: list_call_sites ---------------------------------------
    def _resolve_function_target(self, target):
        """関数名 / アドレスのどちらでも受け取り、(int, 名前) を返します。"""
        text = (target or "").strip()
        if not text:
            raise ValueError("target に関数名かアドレス (0x...) を指定してください。")
        value = try_parse_hex(text)
        if value is not None:
            name = None
            for f in self._safe(lambda: self._load("functions.json"), []) or []:
                if try_parse_hex(f.get("entry") or "") == value:
                    name = f.get("name")
                    break
            return value, name
        matched = [f for f in (self._safe(lambda: self._load("functions.json"), []) or [])
                   if f.get("name") == text]
        if not matched:
            near = [f.get("name") for f in
                    (self._safe(lambda: self._load("functions.json"), []) or [])
                    if text.lower() in (f.get("name") or "").lower()][:8]
            raise ValueError(
                "関数 '{0}' が functions.json にありません。{1}".format(
                    text,
                    "もしかして: {0}".format(", ".join(near)) if near else
                    "アドレス (0x...) で指定することもできます。"))
        entry = try_parse_hex(matched[0].get("entry") or "")
        if entry is None:
            raise ValueError("関数 '{0}' の entry が読めません。".format(text))
        return entry, matched[0].get("name")

    def list_call_sites(self, target, max_back=24, limit=DEFAULT_LIMIT,
                        arch=None, as_markdown=False, indirect_window=8):
        """その関数を呼ぶ箇所を、**呼び出し時の引数レジスタつき**で列挙します。

        疑似 C は `FUN_801a1a0c(param_1,3)` のように引数を落とすことがあり、
        3 番目が何かは逆アセンブルで `addiu $a2,$zero,1` を見るまで分かりません。
        初期化処理やテーブル駆動のコードでは、この**呼び出し時の定数**が解析の
        要になるので、毎回手読みしないための道具です。

        遅延スロット (`jal` の次の 1 命令) は呼び出しより先に実行されるので、
        引数設定として数えます。直前の呼び出しより先には遡りません
        (引数レジスタは呼び出しで壊れるため)。
        """
        entry, entry_name = self._resolve_function_target(target)
        mm, blocks = self._exported_blocks()
        arch_mod = disasm.resolve_arch(mm, arch)
        hook = self._arch_hook(arch_mod, "list_call_sites", "list_call_sites")
        big_endian = (mm.get("endian") == "big")
        lim = clamp_limit(limit)
        back = clamp_count(max_back, 24, 256)

        # ★呼び出し元はコード側にしかいません (find_writers と同じ理由で
        #   実行属性のあるブロックだけを走査します)。
        scan = _scannable([b for b in blocks
                           if b.get("execute") and _has_bytes(b)]) \
            or _scannable([b for b in blocks if _has_bytes(b)])
        sites = []
        taken = []
        scanned = []
        for blk in scan:
            bstart, _ = self._block_range(blk)
            part = hook(self._image_bytes(blk), bstart, big_endian, entry,
                        back, clamp_count(indirect_window, 8, 64))
            scanned.append(blk.get("name"))
            for site in part.get("sites") or []:
                site["block"] = blk.get("name")
                sites.append(site)
            for item in part.get("address_taken") or []:
                item["block"] = blk.get("name")
                taken.append(item)

        sites.sort(key=lambda s: s["call_addr"])
        total = len(sites)
        sites = sites[:lim]
        for site in sites:
            caller = self._describe_address(parse_hex(site["call_addr"]), blocks)
            site["caller"] = (caller or {}).get("function")
            for arg in site.get("args") or []:
                self._annotate_arg(arg, blocks)

        result = {
            "target": "0x{0:08x}".format(entry),
            "target_function": entry_name,
            "arch": arch_mod.NAME,
            "arg_registers": list(getattr(arch_mod, "ARG_REG_NAMES", ())),
            "max_back": back,
            "scanned_blocks": scanned,
            "total": total,
            "returned": len(sites),
            "limit": lim,
            "call_sites": sites,
            "address_taken": taken[:lim],
            "address_taken_total": len(taken),
            "constants": self._call_arg_constants(sites),
            "note": getattr(arch_mod, "CALL_SITES_NOTE",
                            "このアーキの取りこぼし条件は未記載です。"),
        }
        self._mark_overlays_scanned(result, scan)
        if as_markdown:
            # read_data と同じ約束: 表にしたら生の配列は返さない (二重になるため)。
            # 各引数の「なぜ追えなかったか」まで要るときは as_markdown=false。
            result["markdown"] = self._call_sites_markdown(sites, result)
            result.pop("call_sites", None)
        if not total:
            result["hint"] = {
                "message": "呼び出し元が 0 件でした。**「誰も呼んでいない」と結論する前に**"
                           "下を疑ってください。",
                "blind_spots": list(getattr(arch_mod, "CALL_SITES_BLIND_SPOTS", ())),
                "next_steps": [
                    "target が**関数の入口**か確認する "
                    "(find_function_entry。数バイトずれた番地は誰も呼ばない)。",
                    "address_taken を見る — 関数ポインタ表に入っているだけかもしれない。",
                    "find_pointers_to でデータ中の生ポインタを探す "
                    "(表から引いて呼ぶ形はここでは拾えない)。",
                    "呼び出し元が別 Program (オーバーレイ / 別実行ファイル) にある可能性を疑う。",
                ],
            }
        return result

    def _annotate_arg(self, arg, blocks):
        """引数 1 件に「その値の先に何があるか」を添えます (アドレスらしい値だけ)。"""
        value = None
        if arg.get("kind") in ("imm", "address") and arg.get("value") is not None:
            value = arg["value"]
        elif arg.get("kind") == "runtime":
            value = try_parse_hex(arg.get("load_from") or "")
        if value is None:
            return
        # ★`lui + ori` は 32bit の**数値**を作るのにも使われます (アーキ側は
        #   組み立て方しか見ていないので address と言ってくる)。どのブロックにも
        #   入らない値をアドレスと呼ぶと、その先を探しに行って空振りします。
        if arg.get("kind") == "address" and self._find_block(value, blocks) is None:
            arg["kind"] = "imm"
            arg["signed"] = (value - 0x100000000 if value & 0x80000000 else value)
            arg["note"] = ("{0} で組み立てた 32bit 定数ですが、どのメモリブロックにも"
                           "入らないのでアドレスではなく**数値**のようです。".format(
                               arg.get("form") or "lui+lo"))
        if value < 0x1000:
            return
        info = self._resolve_pointer(value, blocks)
        if info:
            arg["points_to"] = info

    @staticmethod
    def _call_arg_constants(sites):
        """レジスタごとに「どの定数が何回渡されているか」をまとめます。

        テーブル駆動のコードでは、**同じ引数に入る定数の一覧そのもの**が
        答えになります (例: 第3引数 = 種類 ID)。
        """
        buckets = {}
        for site in sites:
            for arg in site.get("args") or []:
                if arg.get("kind") not in ("imm", "address"):
                    continue
                reg = arg["reg"]
                key = arg.get("hex")
                row = buckets.setdefault(reg, {}).setdefault(
                    key, {"value": arg.get("value"), "hex": key,
                          "signed": arg.get("signed"), "count": 0, "at": []})
                row["count"] += 1
                if len(row["at"]) < 8:
                    row["at"].append(site["call_addr"])
        return {reg: sorted(rows.values(), key=lambda r: -r["count"])
                for reg, rows in buckets.items()}

    @staticmethod
    def _arg_cell(arg):
        """引数 1 件を表の 1 セルに縮めます。"""
        kind = arg.get("kind")
        if kind == "imm":
            # 表の中では 0x00000010 より 0x10 の方が読める (hex キーは 8 桁のまま)。
            value = arg.get("value") or 0
            signed = arg.get("signed")
            if signed is not None and signed < 0:
                return "-0x{0:x} ({1})".format(-signed, signed)
            return "0x{0:x} ({1})".format(value, value)
        if kind == "address":
            points = arg.get("points_to") or {}
            label = (points.get("string") or points.get("function")
                     or points.get("label"))
            if label:
                return "{0} -> {1}".format(arg.get("hex"), label)
            return arg.get("hex")
        if kind == "runtime":
            src = arg.get("load_from")
            return "runtime ({0})".format(src) if src else "runtime"
        return kind

    def _call_sites_markdown(self, sites, result):
        """呼び出し元一覧を Markdown の表にします (notes/*.md へそのまま貼れるように)。"""
        regs = result["arg_registers"] or ["arg0", "arg1", "arg2", "arg3"]
        header = ["call", "caller", "form"] + list(regs)
        lines = ["| " + " | ".join(header) + " |",
                 "|" + "|".join(["---"] * len(header)) + "|"]
        for site in sites:
            by_reg = {a["reg"]: a for a in (site.get("args") or [])}
            cells = ["`{0}`".format(site["call_addr"]),
                     site.get("caller") or "-", site.get("form") or "-"]
            for reg in regs:
                arg = by_reg.get(reg)
                cells.append(self._arg_cell(arg).replace("|", "\\|")
                             if arg else "-")
            lines.append("| " + " | ".join(cells) + " |")
        return "\n".join(lines)

    # --- ツール: infer_signature ---------------------------------------
    def _function_body(self, entry):
        """関数の body_ranges から (先頭, 末尾) を返します。無ければ (entry, None)。"""
        for f in self._safe(lambda: self._load("functions.json"), []) or []:
            if try_parse_hex(f.get("entry") or "") != entry:
                continue
            lo = hi = None
            for rng in f.get("body_ranges") or []:
                rs = try_parse_hex(rng.get("start") or "")
                re_ = try_parse_hex(rng.get("end") or "")
                if rs is None or re_ is None:
                    continue
                lo = rs if lo is None else min(lo, rs)
                hi = re_ if hi is None else max(hi, re_)
            return (lo if lo is not None else entry, hi)
        return (entry, None)

    def infer_signature(self, target, max_back=24, sample=200, arch=None):
        """その関数が **実際に何個引数を取るか** を推定します。

        疑似 C が `FUN_801a1a0c(param_1,3)` のように引数を落とすとき、
        そもそも何個受け取る関数なのかが分かりません。ここでは 2 方向から見ます:

        - **呼び出し側** (`list_call_sites`): どの引数レジスタに値を積んでいるか
        - **呼ばれる側**: 引数レジスタを**読むのが先か、書くのが先か**

        ★**断定しません。** 両方の根拠と食い違いを返すので、確度を見て
          判断してください (片方しか無いときは confidence を下げます)。
        """
        entry, name = self._resolve_function_target(target)
        mm, blocks = self._exported_blocks()
        arch_mod = disasm.resolve_arch(mm, arch)
        big_endian = (mm.get("endian") == "big")
        regs = list(getattr(arch_mod, "ARG_REGS", ()))
        reg_names = list(getattr(arch_mod, "ARG_REG_NAMES", ()))
        if not regs:
            raise ValueError(
                "infer_signature は {0} では未対応です ({1})。"
                "mcp/disasm/{0}.py に ARG_REGS / arg_register_use() を実装すれば"
                "使えるようになります。".format(arch_mod.NAME, arch_mod.DISPLAY))

        # --- 呼び出し側の根拠 ------------------------------------------
        callers = self._safe(
            lambda: self.list_call_sites(target, max_back=max_back,
                                         limit=clamp_limit(sample), arch=arch),
            None)
        caller_set = {n: 0 for n in reg_names}
        caller_kinds = {n: {} for n in reg_names}
        sites = (callers or {}).get("call_sites") or []
        for site in sites:
            for arg in site.get("args") or []:
                kind = arg.get("kind")
                caller_kinds[arg["reg"]][kind] = \
                    caller_kinds[arg["reg"]].get(kind, 0) + 1
                if kind != "inherited":
                    caller_set[arg["reg"]] += 1

        # --- 呼ばれる側の根拠 ------------------------------------------
        callee = {}
        callee_note = None
        hook = getattr(arch_mod, "arg_register_use", None)
        if hook is None:
            callee_note = (
                "{0} には arg_register_use() が無いので、呼ばれる側の根拠は"
                "見ていません (呼び出し側だけの推定です)。".format(arch_mod.NAME))
        else:
            lo, hi = self._function_body(entry)
            block = self._find_block(lo, blocks)
            if block is None:
                callee_note = ("関数の本体を含む memory ブロックが export されて"
                               "いないので、呼ばれる側の根拠は見ていません。")
            else:
                bstart, bend = self._block_range(block)
                end = min(hi if hi is not None else bend, bend)
                callee = hook(self._image_bytes(block), bstart, big_endian,
                              lo, end, tuple(regs))
                if hi is None:
                    callee_note = ("functions.json に body_ranges が無いので、"
                                   "ブロック末尾まで見ています (広すぎる可能性)。")

        # --- 突き合わせ -------------------------------------------------
        args = []
        used_upto = -1
        conflicts = []
        for index, (reg, reg_name) in enumerate(zip(regs, reg_names)):
            side = callee.get(reg) or {}
            by_callee = side.get("first")
            by_caller = caller_set[reg_name] > 0
            if by_callee == "read":
                verdict, why = "used", "呼ばれる側が読んでいます。"
            elif by_callee == "write":
                verdict, why = "unused", "呼ばれる側が読む前に書いています (作業用)。"
            elif by_caller:
                verdict, why = "probably_used", \
                    "呼ばれる側では触っていませんが、呼び出し側が値を積んでいます。"
            else:
                verdict, why = "unused", "どちらの側でも使われていません。"
            if by_callee == "write" and by_caller:
                conflicts.append(
                    "{0}: 呼ばれる側は作業用として使っていますが、呼び出し元 {1} 件が"
                    "値を積んでいます (引数ではない可能性が高いですが、"
                    "呼び出し元の意図と食い違います)。".format(
                        reg_name, caller_set[reg_name]))
            if verdict in ("used", "probably_used"):
                used_upto = index
            args.append({
                "index": index,
                "reg": reg_name,
                "verdict": verdict,
                "why": why,
                "callee_first": by_callee,
                "callee_at": side.get("at"),
                "callee_text": side.get("text"),
                "callers_setting_it": caller_set[reg_name],
                "caller_kinds": caller_kinds[reg_name] or None,
            })

        have_callee = bool(callee)
        have_caller = bool(sites)
        if have_callee and have_caller and not conflicts:
            confidence = "high"
        elif have_callee or have_caller:
            confidence = "medium"
        else:
            confidence = "low"

        result = {
            "target": "0x{0:08x}".format(entry),
            "target_function": name,
            "arch": arch_mod.NAME,
            "arg_count": used_upto + 1,
            "confidence": confidence,
            "call_sites_seen": len(sites),
            "args": args,
            "conflicts": conflicts,
            "signature_hint": "{0}({1})".format(
                name or "FUN_{0:08x}".format(entry),
                ", ".join(a["reg"] for a in args
                          if a["verdict"] in ("used", "probably_used")) or "void"),
            "note": ("**推定です。** 呼び出し側 (どの引数レジスタに積んでいるか) と"
                     "呼ばれる側 (読むのが先か書くのが先か) の 2 方向から見ています。"
                     "引数の**個数**は「使われている一番後ろの引数まで」なので、"
                     "途中を使っていない関数では多めに出ます。"
                     + (" " + getattr(arch_mod, "ARG_USE_NOTE", "")
                        if have_callee else "")),
        }
        if callee_note:
            result["callee_note"] = callee_note
        if not have_callee and not have_caller:
            result["hint"] = {
                "message": "根拠が 1 つも取れませんでした。",
                "next_steps": [
                    "target が**関数の入口**か確認する (find_function_entry)。",
                    "memory を export しているか確認する "
                    "(get_export_status の memory.available)。",
                    "呼び出し元が別 Program にある可能性を疑う。",
                ],
            }
        return result

    # --- ツール: list_callees ------------------------------------------
    def list_callees(self, target, depth=1, limit=DEFAULT_LIMIT, arch=None,
                     max_instructions=4096, follow_tables=False, ordered=False):
        """その関数が **何を呼ぶか** を、深さ指定で辿ります。

        ordered=True なら、対象関数 (根) の呼び出しを **命令の並び順** に全部
        (同じ相手への複数回も) `call_order` に並べ、それぞれが条件分岐の後ろに
        あるか (`conditional`) を添えます。1 フレームの処理が「どの順で何を呼ぶか」を
        手で書き出さずに済ませるためのものです。
        """
        result = self._list_callees_impl(target, depth, limit, arch,
                                         max_instructions, follow_tables)
        if ordered:
            mm, blocks = self._exported_blocks()
            arch_mod = disasm.resolve_arch(mm, arch)
            entry = try_parse_hex(result.get("target") or "")
            if entry is not None:
                result.update(self._ordered_calls(arch_mod, mm, blocks, entry,
                                                  max_instructions))
        return result

    def _ordered_calls(self, arch_mod, mm, blocks, entry, max_instructions=4096):
        """根の関数の呼び出しを並び順に返し、無条件に実行されるかを判定します。

        判定は関数本体 (functions.json の body_ranges) の命令から作った制御フロー
        グラフで行います: **入口から出口までのどの経路でも通る** 呼び出しだけを
        conditional=false にします (その呼び出しを取り除くと出口へ届かなくなるか)。
        判定できるのは「条件分岐 = flow "branch"、遅延スロット無し」と宣言した
        アーキだけ (COND_BRANCH_FLOW)。それ以外は conditional=null で順番だけ返します。
        """
        lo, hi = self._function_body(entry)
        out = {"call_order": [], "call_order_note": None}
        block = self._find_block(lo, blocks)
        if block is None or not _has_bytes(block):
            out["call_order_note"] = "本体を含む memory ブロックが export されていないので並べられません。"
            return out
        bstart, bend = self._block_range(block)
        end = min(hi if hi is not None else bend, bend)
        insns = []          # (addr, size, flow, target)
        if getattr(arch_mod, "VARIABLE_LENGTH", False):
            ctx = self._width_context(blocks)
            data = self._read_memory(block, lo - bstart, end - lo + 1)
            for got in arch_mod.disassemble(data, lo, start=lo, end=end, ctx=ctx,
                                            stop_at_return=(hi is None), with_refs=False,
                                            count=int(max_instructions)):
                insns.append((got["addr"], got["size"], got["flow"], got["target"]))
        else:
            size = arch_mod.INSTRUCTION_SIZE
            count = min(int(max_instructions), (end - lo) // size + 1)
            data = self._read_memory(block, lo - bstart, count * size)
            big_endian = (mm.get("endian") == "big")
            for i in range(count):
                word = arch_mod.word_at(data, i * size, big_endian)
                if word is None:
                    break
                got = arch_mod.decode(word, lo + i * size)
                tgt = got.get("target")
                if isinstance(tgt, str):
                    tgt = try_parse_hex(tgt)
                insns.append((lo + i * size, size, got.get("flow"), tgt))
                if hi is None and got.get("flow") == "return":
                    break
        cond_flow = getattr(arch_mod, "COND_BRANCH_FLOW", None)
        can_judge = bool(cond_flow) and not getattr(arch_mod, "HAS_DELAY_SLOTS", False)

        index = {a: i for i, (a, _s, _f, _t) in enumerate(insns)}
        exit_node = len(insns)

        def succ(i):
            addr, size, flow, tgt = insns[i]
            nxt = index.get(addr + size, exit_node)
            if flow == "return" or flow == "jump_reg":
                return [exit_node]
            if flow == "jump":
                return [index.get(tgt, exit_node)] if tgt is not None else [exit_node]
            if flow == cond_flow:
                return [nxt, index.get(tgt, exit_node) if tgt is not None else exit_node]
            return [nxt]

        def reaches_exit(skip):
            if not insns or skip == 0:
                return False
            seen = {0}
            work = [0]
            while work:
                i = work.pop()
                for j in succ(i):
                    if j == exit_node:
                        return True
                    if j != skip and j not in seen:
                        seen.add(j)
                        work.append(j)
            return False

        reachable = set()
        if can_judge and insns:
            work = [0]
            reachable.add(0)
            while work:
                for j in succ(work.pop()):
                    if j != exit_node and j not in reachable:
                        reachable.add(j)
                        work.append(j)
        fmt = getattr(arch_mod, "ADDR_FORMAT", "0x{0:08x}")
        last_branch = None
        for i, (addr, size, flow, tgt) in enumerate(insns):
            if can_judge and flow == cond_flow:
                last_branch = addr
            if flow not in ("call", "call_reg"):
                continue
            row = {"order": len(out["call_order"]) + 1, "site": fmt.format(addr),
                   "kind": "direct" if flow == "call" else "indirect"}
            if flow == "call" and tgt is not None:
                row["target"] = fmt.format(tgt)
                info = self._describe_address(tgt, blocks) or {}
                row["name"] = info.get("function")
            if can_judge:
                if i not in reachable:
                    row["conditional"] = None
                    row["reachable"] = False
                else:
                    row["conditional"] = reaches_exit(i)
                    if row["conditional"] and last_branch is not None:
                        row["last_branch_before"] = fmt.format(last_branch)
            else:
                row["conditional"] = None
            out["call_order"].append(row)
        out["call_order_note"] = (
            "根の関数の呼び出しを命令の並び順に全部並べました (同じ相手への複数回も別行)。"
            + ("conditional=false は入口から出口までのどの経路でも通る呼び出し、true は"
               "条件分岐で飛ばされうる呼び出し (last_branch_before は直前の条件分岐)。"
               "reachable=false は本体の中で入口から辿れなかった呼び出し (間接ジャンプの先など)。"
               "並び順は**番地の順**で、ループや後ろ向きの分岐があると実行順と違いうる。"
               "関数本体は functions.json の body_ranges に従う。"
               if can_judge else
               "このアーキは条件分岐の判定をしない (遅延スロット等) ので conditional=null。"))
        return out

    def _list_callees_impl(self, target, depth=1, limit=DEFAULT_LIMIT, arch=None,
                           max_instructions=4096, follow_tables=False):
        """list_callees の本体 (ordered の前まで)。

        `list_call_sites` の逆向きです。「この初期化関数は何を仕込むのか」を
        追うときに、`get_disassembly` を何度も呼ぶ代わりになります。

        ★**循環は必ず検出して打ち切ります** (再帰関数で無限に広がるため)。
          間接呼び出し (レジスタ経由) は飛び先が分からないので、件数だけ
          数えて `indirect` に入れます (**「呼んでいない」ではありません**)。
        """
        mm, blocks = self._exported_blocks()
        arch_mod = disasm.resolve_arch(mm, arch)
        if follow_tables:
            # 分岐を辿る解析器 (65816) が要る。持たないアーキは未対応エラー。
            self._arch_hook(arch_mod, "make_analyzer", "list_callees(follow_tables=true)")
            return self._list_callees_flow(arch_mod, blocks, target, depth, limit)
        entry, name = self._resolve_function_target(target)
        big_endian = (mm.get("endian") == "big")
        try:
            levels = max(1, min(int(depth), 5))
        except (TypeError, ValueError):
            levels = 1
        lim = clamp_limit(limit)

        seen = {}
        truncated = []

        def walk(addr, level):
            """1 関数を走査し、呼び出し先の木を返します。"""
            key = "0x{0:08x}".format(addr)
            info = self._describe_address(addr, blocks) or {}
            node = {"entry": key, "name": info.get("function")}
            if key in seen:
                node["repeat"] = True     # ★既に辿った (循環 / 共通ルーチン)
                return node
            seen[key] = True
            if level > levels:
                node["truncated"] = "depth 上限"
                return node

            lo, hi = self._function_body(addr)
            block = self._find_block(lo, blocks)
            if block is None or not _has_bytes(block):
                node["problem"] = "本体を含む memory ブロックが export されていません。"
                return node
            bstart, bend = self._block_range(block)
            end = min(hi if hi is not None else bend, bend)
            if hi is None:
                node["body_unknown"] = (
                    "functions.json に body_ranges が無いので、"
                    "最初の return まで読んでいます。")
            size = arch_mod.INSTRUCTION_SIZE
            count = min(int(max_instructions), (end - lo) // size + 1)
            data = self._read_memory(block, lo - bstart, count * size)

            calls = []
            indirect = 0
            delay_left = None
            if getattr(arch_mod, "VARIABLE_LENGTH", False):
                # 65816: 固定長で 1 バイトずつ読むとオペランドが命令に化ける。
                #   CDL の幅で線形に読む。
                ctx = self._width_context(blocks)
                insns = arch_mod.disassemble(
                    data, lo, start=lo, end=end, ctx=ctx,
                    stop_at_return=(hi is None), with_refs=False,
                    count=int(max_instructions))
                uncertain = 0
                jumps = 0
                for got in insns:
                    if got["width_uncertain"]:
                        uncertain += 1
                    if got["flow"] == "call" and got["target"] is not None:
                        if got["target"] != addr:
                            calls.append((got["addr"], got["target"]))
                    elif got["flow"] == "call_reg":
                        indirect += 1
                    elif got["flow"] == "jump_reg":
                        jumps += 1
                if uncertain:
                    node["width_uncertain"] = uncertain
                if jumps:
                    # JMP ($abs,X) / JMP ($abs) / JML [$abs]: 飛び先は表か実行時。
                    node["indirect_jumps"] = jumps
                count = 0                     # 下の固定長ループは回さない
            for i in range(count):
                word = arch_mod.word_at(data, i * size, big_endian)
                if word is None:
                    break
                at = lo + i * size
                got = arch_mod.decode(word, at)
                flow = got.get("flow")
                if flow == "call" and got.get("target"):
                    tgt = try_parse_hex(got["target"])
                    if tgt is not None and tgt != addr:
                        calls.append((at, tgt))
                elif flow in ("call_reg",):
                    indirect += 1
                elif hi is None and flow == "return":
                    # body_ranges が無いときは最初の return で打ち切る
                    # (遅延スロットがあるアーキは 1 命令だけ余計に読む)。
                    delay_left = 1 if getattr(arch_mod, "HAS_DELAY_SLOTS",
                                              False) else 0
                if delay_left is not None:
                    delay_left -= 1
                    if delay_left < 0:
                        break

            node["calls"] = len(calls)
            node["indirect_calls"] = indirect
            children = []
            done = set()
            for at, tgt in calls:
                if tgt in done:
                    continue
                done.add(tgt)
                if len(children) >= lim:
                    truncated.append(key)
                    break
                child = walk(tgt, level + 1)
                child["called_at"] = "0x{0:08x}".format(at)
                children.append(child)
            if children:
                node["callees"] = children
            return node

        tree = walk(entry, 1)
        flat = {}

        def collect(node):
            """木を平らにして、関数ごとの呼ばれ方をまとめます。"""
            for child in node.get("callees") or []:
                row = flat.setdefault(child["entry"], {
                    "entry": child["entry"], "name": child.get("name"),
                    "called_from": []})
                if node["entry"] not in row["called_from"]:
                    row["called_from"].append(node["entry"])
                collect(child)

        collect(tree)
        result = {
            "target": "0x{0:08x}".format(entry),
            "target_function": name,
            "arch": arch_mod.NAME,
            "depth": levels,
            "tree": tree,
            "unique_callees": len(flat),
            "callees": sorted(flat.values(), key=lambda x: x["entry"]),
            "note": ("直接呼び出し (飛び先が命令に書いてあるもの) だけを辿ります。"
                     "**間接呼び出し (レジスタ経由) は飛び先が分からないので "
                     "indirect_calls に件数だけ出します — 「呼んでいない」では"
                     "ありません。** 関数ポインタ表から呼ぶ形は "
                     "find_pointer_tables / find_pointers_to で追ってください。"
                     "repeat=true は既に辿った関数 (循環 / 共通ルーチン) です。"),
        }
        if truncated:
            result["truncated_at"] = truncated
            result["truncated_note"] = (
                "呼び出し先が limit ({0}) を超えた関数があります。".format(lim))
        return result

    def _list_callees_flow(self, arch_mod, blocks, target, depth, limit):
        """list_callees(follow_tables=true): 分岐を辿り、JSR/JMP (abs,X) の表も展開して辿る。"""
        an = self._arch_analyzer(arch_mod, blocks)
        text = (target or "").strip()
        value = try_parse_hex(text)
        if value is None:
            try:
                value = self._arch_address(arch_mod, text)
            except ValueError:
                value, _nm = self._resolve_function_target(text)
        entry = an.ctx.canonical_rom(value) if an.ctx is not None else value
        try:
            levels = max(1, min(int(depth), 5))
        except (TypeError, ValueError):
            levels = 1
        lim = clamp_limit(limit)
        fmt = getattr(arch_mod, "ADDR_FORMAT", "0x{0:08x}")
        seen = set()
        truncated = []

        def walk(addr, m, x, ms, xs, level):
            """1 関数を分岐ごと辿り、呼び出し先の木を返します。"""
            key = fmt.format(addr)
            info = self._describe_address(addr, blocks) or {}
            node = {"entry": key, "name": info.get("function"),
                    "widths": "m{0}x{1}".format(m, x)}
            if (addr, m, x) in seen:
                node["repeat"] = True
                return node
            seen.add((addr, m, x))
            if level > levels:
                node["truncated"] = "depth 上限"
                return node
            reg = an.region(addr, m, x, ms, xs)
            if reg is None:
                node["problem"] = "辿れませんでした (再帰の途中)。"
                return node
            node["instructions"] = len(reg.nodes)
            node["calls"] = len(reg.calls)
            node["indirect_calls"] = len(reg.unresolved)
            if reg.unresolved:
                node["unresolved_at"] = [fmt.format(a) for a in reg.unresolved[:8]]
            if reg.tables:
                node["tables"] = [{"site": t["site"], "table": t["table"],
                                   "count": t["count"],
                                   "count_is_estimated": t["count_is_estimated"]}
                                  for t in reg.tables]
            children = []
            done = set()
            for call in reg.calls:
                tgt = call["target"]
                if (tgt, call["kind"]) in done:
                    continue
                done.add((tgt, call["kind"]))
                if len(children) >= lim:
                    truncated.append(key)
                    break
                site = reg.nodes[call["site"]]
                child = walk(tgt, site.m, site.x,
                             "caller" if site.ms not in ("assumed", "unknown", "ambiguous",
                                                         "after_call") else site.ms,
                             "caller" if site.xs not in ("assumed", "unknown", "ambiguous",
                                                         "after_call") else site.xs,
                             level + 1)
                child["called_at"] = fmt.format(call["site"])
                child["kind"] = call["kind"]
                if "index" in call:
                    child["table_index"] = call["index"]
                children.append(child)
            if children:
                node["callees"] = children
            return node

        reg0, (m0, x0, ms0, xs0) = an.region_for(entry)
        tree = walk(entry, m0, x0, ms0, xs0, 1)
        flat = {}

        def collect(node):
            """木を平らにして、関数ごとの呼ばれ方をまとめます。"""
            for child in node.get("callees") or []:
                row = flat.setdefault(child["entry"], {
                    "entry": child["entry"], "name": child.get("name"),
                    "called_from": []})
                if node["entry"] not in row["called_from"]:
                    row["called_from"].append(node["entry"])
                collect(child)

        collect(tree)
        result = {
            "target": fmt.format(entry),
            "target_function": (self._describe_address(entry, blocks) or {}).get("function"),
            "arch": arch_mod.NAME,
            "depth": levels,
            "follow_tables": True,
            "tree": tree,
            "unique_callees": len(flat),
            "callees": sorted(flat.values(), key=lambda r: r["entry"]),
            "note": ("分岐を辿り、JSR/JSL・JSR/JMP (abs,X) の表 (展開した全件。kind="
                     "jsr_table / jmp_table と table_index)・既知の入口への JMP/JML (kind=tail) "
                     "を呼び出し先として辿りました。M/X は呼び出し元から運んでいます "
                     "(widths)。indirect_calls は表として展開できなかった間接ジャンプの件数で、"
                     "**「呼んでいない」ではありません**。表の件数が推定かは tables の "
                     "count_is_estimated を見ること。"),
        }
        if truncated:
            result["truncated_at"] = truncated
            result["truncated_note"] = "呼び出し先が limit ({0}) を超えた関数があります。".format(lim)
        return result

    # --- ツール: find_calls_to / find_path / list_memory_args / lint ------
    def _flow_tool(self, name, what):
        """分岐を辿る解析ツールの共通部分 (arch モジュール, フック, 解析器, ブロック)。"""
        mm, blocks = self._exported_blocks()
        arch_mod = disasm.resolve_arch(mm)
        hook = self._arch_hook(arch_mod, name, what)
        analyzer = self._arch_analyzer(arch_mod, blocks)
        return arch_mod, hook, analyzer, blocks

    def _name_rows(self, rows, blocks, key="site", field="function"):
        """行に関数名を添えます (番地 key の列から)。"""
        for row in rows:
            value = try_parse_hex(row.get(key) or "")
            if value is None:
                continue
            info = self._describe_address(value, blocks) or {}
            if info.get("function"):
                row[field] = info["function"]

    def find_calls_to(self, address, include_branches=True, kinds=None,
                      limit=DEFAULT_REFS_LIMIT):
        """指定番地を呼ぶ・飛ぶ命令を**バイト列から**全部列挙します (CDL の外も)。"""
        arch_mod, hook, an, blocks = self._flow_tool("find_calls_to", "find_calls_to")
        if isinstance(kinds, str):
            kinds = [k for k in kinds.replace(",", " ").split() if k]
        result = hook(an, address, kinds=kinds, include_branches=include_branches,
                      limit=clamp_count(limit, DEFAULT_REFS_LIMIT, MAX_REFS_LIMIT))
        self._name_rows(result.get("calls") or [], blocks)
        result["arch"] = arch_mod.NAME
        return result

    def find_path(self, source, target, m=None, x=None, max_functions=6000):
        """入口 source から番地 target に (静的に) 届くか、届くならその経路を返します。"""
        arch_mod, hook, an, blocks = self._flow_tool("find_path", "find_path")
        result = hook(an, source, target, m=self._parse_flag(m, "m"),
                      x=self._parse_flag(x, "x"),
                      max_regions=clamp_count(max_functions, 6000, 20000))
        self._name_rows(result.get("path") or [], blocks, key="to", field="to_name")
        result["arch"] = arch_mod.NAME
        return result

    def list_memory_args(self, target, args=None, limit=DEFAULT_LIMIT,
                         include_weak=False, as_markdown=False):
        """メモリ経由の引数を、呼び出し元ごとに「呼ぶ前に書いたか」で一覧にします。"""
        arch_mod, hook, an, blocks = self._flow_tool("list_memory_args",
                                                     "list_memory_args")
        result = hook(an, target, args=args, limit=clamp_limit(limit),
                      include_weak=bool(include_weak))
        self._name_rows(result.get("callers") or [], blocks)
        result["arch"] = arch_mod.NAME
        if as_markdown:
            names = [a["addr"] for a in result.get("args") or []]
            lines = ["| call | function | entry | " + " | ".join(names) + " |",
                     "|" + "---|" * (3 + len(names))]
            for row in result.get("callers") or []:
                cells = []
                for a in names:
                    cell = (row.get("args") or {}).get(a) or {}
                    st = cell.get("status")
                    if st == "written":
                        text = "書いた" + ("=" + cell["value_hex"] if cell.get("value_hex") else "")
                    elif st == "partially_written":
                        text = "一部の経路だけ"
                    elif st == "not_written":
                        text = "**書いていない**"
                        if cell.get("could_be_written_by"):
                            text += " (?{0})".format(cell.get("could_be_written_total"))
                    else:
                        text = "?"
                    cells.append(text)
                lines.append("| `{0}` | {1} | {2} | {3} |".format(
                    row["site_bus"], row.get("function") or "-",
                    row.get("function_entry") or "-", " | ".join(cells)))
            result["markdown"] = "\n".join(lines)
            result.pop("callers", None)
        return result

    def lint_stale_register(self, function=None, start=None, end=None,
                            min_severity="high", limit=DEFAULT_LIMIT):
        """レジスタの持ち越し (65816: A の上位バイト B) を機械的に探します。"""
        arch_mod, hook, an, blocks = self._flow_tool("lint_stale_register",
                                                     "lint_stale_register")
        result = hook(an, function=function, start=start, end=end,
                      min_severity=(min_severity or "high").strip().lower(),
                      limit=clamp_count(limit, DEFAULT_LIMIT, 500))
        self._name_rows(result.get("findings") or [], blocks, key="use")
        result["arch"] = arch_mod.NAME
        return result

    # --- ツール: find_immediate ----------------------------------------
    def find_immediate(self, value, start=None, end=None,
                       include_offsets=False, include_pairs=True,
                       limit=DEFAULT_LIMIT, arch=None, as_markdown=False):
        """その **数値** を即値として使っている命令を探します。

        `find_address_refs` は**アドレス**、`find_bytes` は**バイト列**を探す
        道具で、`addiu $a0,$zero,100` のような**即値**はどちらでも引けません。
        閾値・ID・フラグ値の出どころ探し (改造コードを作るときの定番)
        に使います。

        kind で「定数を作っている (const)」「その値と比べている (compare)」
        「足し引きしている (add)」を分けるので、大量に出ても本命を選べます。
        """
        want = _parse_int(value, "value")
        mm, blocks = self._exported_blocks()
        arch_mod = disasm.resolve_arch(mm, arch)
        hook = self._arch_hook(arch_mod, "find_immediate", "find_immediate")
        big_endian = (mm.get("endian") == "big")
        lim = clamp_limit(limit)
        lo = parse_hex(start) if start else None
        hi = parse_hex(end) if end else None
        if lo is not None and hi is not None and hi < lo:
            raise ValueError("end が start より小さいです。")

        scan = _scannable([b for b in blocks
                           if b.get("execute") and _has_bytes(b)]) \
            or _scannable([b for b in blocks if _has_bytes(b)])
        hits = []
        scanned = []
        instructions = 0
        for blk in scan:
            bstart, bend = self._block_range(blk)
            if lo is not None and bend < lo:
                continue
            if hi is not None and bstart > hi:
                continue
            pair_index = None
            if include_pairs:
                # ★索引は MCP 側のキャッシュを使う (アーキ側で作り直さない)。
                try:
                    pair_index, _built = self._ref_index_for(blk, arch_mod,
                                                             big_endian)
                except (ValueError, OSError):
                    pair_index = None
            part = hook(self._image_bytes(blk), bstart, big_endian, want,
                        bool(include_offsets), bool(include_pairs),
                        pair_index, lo, hi)
            scanned.append(blk.get("name"))
            instructions += part.get("scanned_instructions") or 0
            for hit in part.get("hits") or []:
                hit["block"] = blk.get("name")
                hits.append(hit)

        hits.sort(key=lambda h: h["addr"])
        total = len(hits)
        by_kind = {}
        for hit in hits:
            by_kind[hit["kind"]] = by_kind.get(hit["kind"], 0) + 1
        page = hits[:lim]
        for hit in page:
            info = self._describe_address(parse_hex(hit["addr"]), blocks)
            if info and info.get("function"):
                hit["function"] = info["function"]

        result = {
            "value": want,
            "hex": "0x{0:x}".format(want & 0xFFFFFFFF),
            "arch": arch_mod.NAME,
            "start": start,
            "end": end,
            "include_offsets": bool(include_offsets),
            "scanned_blocks": scanned,
            "scanned_instructions": instructions,
            "total": total,
            "returned": len(page),
            "limit": lim,
            "by_kind": by_kind,
            "hits": page,
            "note": getattr(arch_mod, "IMMEDIATE_NOTE",
                            "このアーキの取りこぼし条件は未記載です。"),
        }
        self._mark_overlays_scanned(result, scan)
        if as_markdown:
            lines = ["| addr | kind | function | text |", "|---|---|---|---|"]
            for hit in page:
                lines.append("| `{0}` | {1} | {2} | `{3}` |".format(
                    hit["addr"], hit["kind"], hit.get("function") or "-",
                    (hit.get("text") or "").replace("|", "\\|")))
            result["markdown"] = "\n".join(lines)
            result.pop("hits", None)
        if not total:
            result["hint"] = {
                "message": "0 件でした。**「この値はコードに出てこない」と結論する前に**"
                           "下を疑ってください。",
                "blind_spots": list(getattr(arch_mod, "IMMEDIATE_BLIND_SPOTS", ())),
                "next_steps": [
                    "find_bytes でデータとして置かれていないか探す "
                    "(表に入っている値は命令ではない)。",
                    "値が別の単位かもしれない "
                    "(フレーム数 vs 秒、内部値 vs 表示値、×2 されている等)。",
                    "include_offsets=true にして、構造体のオフセットとして"
                    "出ていないかを見る。",
                    "16bit に収まらない値なら include_pairs のまま "
                    "lui+下位16bit の合成を探しているが、別の作り方 "
                    "(シフトや加算) だと拾えない。",
                ],
            }
        return result

    # --- ツール: expand_switch -----------------------------------------
    def expand_switch(self, address, arch=None):
        """`braf` / `bsrf` によるスイッチ表を展開します (参照検索の盲点を塞ぐ)。"""
        target, mm, blocks, block, start, arch_mod = self._analysis_context(address, arch)
        hook = self._arch_hook(arch_mod, "expand_switch", "expand_switch")
        data = self._image_bytes(block)
        if getattr(arch_mod, "make_analyzer", None) is not None:
            # 65816: 表を引く命令の幅 (CDL) と表の終端の判定 (CDL のコード区間) が要る。
            result = hook(data, start, (mm.get("endian") == "big"), target,
                          analyzer=self._arch_analyzer(arch_mod, blocks))
        else:
            # ★飛び先表は .rodata に置かれるのが普通で、jr のある .text とは
            #   別ブロックです。ブロックを跨いで読めるリーダを渡します
            #   (渡さないと「表は求まったのに 0 件」になる)。
            try:
                result = hook(data, start, (mm.get("endian") == "big"), target,
                              read_word=lambda a: self._pool_word(a, blocks))
            except TypeError:
                result = hook(data, start, (mm.get("endian") == "big"), target)
        result["arch"] = arch_mod.NAME
        result["block"] = block.get("name")
        # 飛び先に既知の関数名が付くなら添える (どの状態が何をするかの手掛かり)。
        for entry in result.get("entries", []):
            info = self._describe_address(int(entry["target"], 16), blocks)
            if info and info.get("function"):
                entry["function"] = info["function"]
        result["note"] = getattr(
            arch_mod, "SWITCH_NOTE",
            "スイッチ表の飛び先は 32bit アドレスとして命令に現れないため "
            "find_address_refs では見つかりません。エントリ数が範囲チェックから"
            "取れなければ推定です (count_is_estimated を確認してください)。")
        return result

    # --- ツール: find_function_entry -----------------------------------
    def find_function_entry(self, address, arch=None):
        """指定アドレスを含む関数の入口を **命令列から** 判定します。"""
        target, mm, blocks, block, start, arch_mod = self._analysis_context(address, arch)
        hook = self._arch_hook(arch_mod, "find_function_entry", "find_function_entry")
        data = self._image_bytes(block)
        if getattr(arch_mod, "make_analyzer", None) is not None:
            # 65816: 入口の幅 (呼び出し元の幅) と、そこから分岐を辿って届くかで判定する。
            result = hook(data, start, (mm.get("endian") == "big"), target,
                          analyzer=self._arch_analyzer(arch_mod, blocks))
        else:
            result = hook(data, start, (mm.get("endian") == "big"), target)
        result["arch"] = arch_mod.NAME
        result["block"] = block.get("name")

        # Ghidra の見解も併記する。**一致を要求しない** —
        # Ghidra 自身が入口を誤認している例があるため、突き合わせ材料として出すだけ。
        ghidra = self._describe_address(target, blocks) or {}
        entry_i = try_parse_hex(result.get("entry") or "")
        ghidra_entry = self._describe_address(entry_i, blocks) if entry_i else None
        result["ghidra_says"] = {
            "at_address": ghidra.get("function"),
            "at_entry": (ghidra_entry or {}).get("function"),
            "note": "Ghidra の関数情報は参考です。命令列の判定と食い違うことがあります。",
        }
        return result

    # --- ツール: find_pointer_tables -----------------------------------
    def find_pointer_tables(self, target_lo, target_hi, min_entries=3,
                            limit=DEFAULT_LIMIT, stride=4, min_count=None,
                            thumb_pointers=False, align=4,
                            detect_parallel=False):
        """[target_lo, target_hi] を指す値が **stride 間隔で連続する**箇所を探します。

        「範囲 R に入る値が N 個以上連続する箇所」という走査は手書きの常連なので
        道具にしました。表のエントリ間隔は 4 とは限りません
        (8 / 0x14 / 0x2000 などもありえます)。

        - `stride`: **表のエントリ間隔** (バイト)。値の間隔ではありません。
        - `min_count`: 連続とみなす最小件数 (旧 `min_entries` も受け付けます)。
        - `thumb_pointers=True`: 奇数アドレス (entry|1) を Thumb 関数ポインタとして
          扱います。**これを付けないと Thumb の関数ポインタ表は 1 件も見つかりません。**
        - `detect_parallel=True`: **平行に並ぶ表をグループにまとめます**。
          GBA のリソースは「幅高さ / パレット / タイル / マップ」のような表が
          等間隔で何本も並ぶ形がほぼ必ずで、1 本ずつ見ても構造が見えません。
        """
        lo = parse_hex(target_lo)
        hi = parse_hex(target_hi)
        if hi < lo:
            raise ValueError("target_hi が target_lo より小さいです。")
        try:
            step = int(stride)
        except (TypeError, ValueError):
            raise ValueError("stride は整数で指定してください。")
        if step < 4 or step % 4:
            raise ValueError("stride は 4 の倍数で指定してください (4 以上)。")
        need = min_count if min_count is not None else min_entries
        try:
            need = max(2, int(need))
        except (TypeError, ValueError):
            need = 4
        try:
            grid = max(4, int(align))
        except (TypeError, ValueError):
            grid = 4
        lim = clamp_limit(limit)
        thumb = bool(thumb_pointers)

        mm, blocks = self._exported_blocks()
        big_endian = (mm.get("endian") == "big")
        order = "big" if big_endian else "little"

        tables = []
        all_tables = []
        total = 0
        for block in _scannable(blocks):
            start, end = self._block_range(block)
            if start is None:
                continue
            data = self._image_bytes(block)
            size = len(data)

            def value_at(off):
                """off の 32bit 値を、範囲判定に使う形にして返します。"""
                if off < 0 or off + 4 > size:
                    return None
                v = int.from_bytes(data[off:off + 4], order)
                return (v & ~1) if thumb else v

            begin = (-start) % grid
            for off in range(begin, size - 3, grid):
                v = value_at(off)
                if v is None or not (lo <= v <= hi):
                    continue
                # 直前のエントリも範囲内なら、ここは連なりの途中なので飛ばす
                # (同じ表を少しずつずらして何度も報告しない)。
                prev = value_at(off - step)
                if prev is not None and lo <= prev <= hi:
                    continue
                count = 0
                while True:
                    nv = value_at(off + count * step)
                    if nv is None or not (lo <= nv <= hi):
                        break
                    count += 1
                if count < need:
                    continue
                total += 1
                # ★グループ検出は**切る前の全件**で行う必要があります。
                #   返すぶん (limit) だけで組むと、ページから外れた表が
                #   グループに入らず、並びが見えません (目的の表を取りこぼす)。
                #   軽い情報だけ全件ぶん持っておきます。
                all_tables.append({
                    "table_addr": "0x{0:08x}".format(start + off),
                    "entry_count": count,
                    "stride": "0x{0:x}".format(step),
                })
                if len(tables) < lim:
                    tables.append(self._pointer_table(
                        block, start, data, off, count, step, order, thumb, blocks))

        return {
            "target_lo": target_lo,
            "target_hi": target_hi,
            "stride": "0x{0:x}".format(step),
            "min_count": need,
            "thumb_pointers": thumb,
            "total": total,
            "limit": lim,
            "returned": len(tables),
            "tables": tables,
            "parallel_groups": (
                _parallel_groups(all_tables,
                                 lambda a: self._pool_word(a, blocks),
                                 lambda v: lo <= (v & ~1 if thumb else v) <= hi)
                if detect_parallel else None),
            "note": ("4 バイト境界のワードだけを見ています (align で変更可)。"
                     "stride は**表のエントリ間隔**で、指す先の間隔ではありません。"
                     "min_count を下げると誤検出 (偶然範囲に入る数値) が増えます。"
                     "Thumb の関数ポインタは下位ビットが 1 なので、"
                     "thumb_pointers=true を付けないと見つかりません。"
                     + ("**parallel_groups は、要素数が同じで開始番地が等間隔に"
                        "並ぶ表をまとめたものです。** GBA のリソースはこの形が"
                        "ほぼ必ずなので、1 本ずつ見るより構造が分かります。"
                        if detect_parallel else
                        "detect_parallel=true にすると、平行に並ぶ表を"
                        "グループにまとめます。")),
        }

    def _pointer_table(self, block, start, data, off, count, step, order,
                       thumb, blocks):
        """ポインタ表 1 件を、各エントリの解決結果つきで組み立てます。"""
        entries = []
        for k in range(count):
            pos = off + k * step
            raw = int.from_bytes(data[pos:pos + 4], order)
            value = (raw & ~1) if thumb else raw
            item = {
                "addr": "0x{0:08x}".format(start + pos),
                "value": "0x{0:08x}".format(raw),
            }
            if thumb and (raw & 1):
                item["thumb"] = True
                item["target"] = "0x{0:08x}".format(value)
            resolved = self._resolve_pointer(value, blocks)
            if resolved:
                item["resolved"] = resolved
            entries.append(item)
        return {
            "table_addr": "0x{0:08x}".format(start + off),
            "block": block.get("name"),
            "entry_count": count,
            "stride": "0x{0:x}".format(step),
            "entries": entries,
        }

    # --- ツール: list_undefined_ranges -----------------------------------
    def list_undefined_ranges(self, min_size=0x40, block=None,
                              executable_only=False, initialized_only=True,
                              sort="size", offset=0, limit=DEFAULT_LIMIT,
                              with_refs=False, classify=False):
        """まだ Ghidra が何も割り当てていない領域を、**大きい順**に返します。

        `undefined_ranges.json` は数万件になることがあり、件数だけでは使えません。
        「次にどこを見るか」を決めるための道具です。

        - **既定で 1 バイトのゴミを弾きます** (`min_size`)。小さい隙間が大半で、
          そのまま並べても読めません。
        - **既定で未初期化ブロックを除きます** (`initialized_only`)。
          BSS / VRAM は「まだ解析していない領域」ではなく、そもそも中身がありません。
        - `with_refs=true` を付けると、返した範囲**だけ**について
          「そこを指しているコードがあるか」を数えます (全件やると重いため)。
          **参照があるのに未定義な領域は、読む価値が高い**です。
        """
        rows = self._load("undefined_ranges.json")
        if isinstance(rows, dict):
            rows = rows.get("undefined_ranges") or rows.get("ranges") or []
        need = max(0, int(min_size))
        want_block = (block or "").strip() or None

        kept = []
        skipped = {"小さすぎる": 0, "未初期化": 0, "実行属性なし": 0, "別ブロック": 0}
        by_block = {}
        total_bytes = 0
        for r in rows:
            size = int(r.get("size") or 0)
            name = r.get("block_name")
            stat = by_block.setdefault(name, {"count": 0, "bytes": 0})
            stat["count"] += 1
            stat["bytes"] += size
            total_bytes += size
            if want_block and name != want_block:
                skipped["別ブロック"] += 1
                continue
            if initialized_only and not r.get("initialized"):
                skipped["未初期化"] += 1
                continue
            if executable_only and not r.get("in_executable_block"):
                skipped["実行属性なし"] += 1
                continue
            if size < need:
                skipped["小さすぎる"] += 1
                continue
            kept.append(r)

        key = (lambda r: try_parse_hex(r.get("start") or "") or 0) \
            if sort == "address" else (lambda r: -int(r.get("size") or 0))
        kept.sort(key=key)

        off = max(0, int(offset))
        lim = clamp_limit(limit)
        page = kept[off:off + lim]
        items = []
        for r in page:
            row = {
                "start": r.get("start"),
                "end": r.get("end"),
                "size": r.get("size"),
                "block": r.get("block_name"),
                "in_executable_block": r.get("in_executable_block"),
                "initialized": r.get("initialized"),
                "nearest_function": r.get("nearest_function"),
            }
            if with_refs:
                row["refs"] = self._count_refs_in_range(r.get("start"),
                                                        r.get("end"))
            if classify:
                # 返した範囲**だけ**を調べます (全件やると重いため)。
                try:
                    verdict = self.classify_range(r.get("start"), r.get("end"))
                    row["classify"] = {
                        "verdict": verdict["verdict"],
                        "confidence": verdict["confidence"],
                        "entropy": verdict["entropy"],
                        "top": [{"label": x["label"], "score": x["score"]}
                                for x in verdict["signals"][:2]],
                        "next": verdict["next"][:2],
                    }
                except Exception as exc:
                    row["classify"] = {"verdict": None, "why": str(exc)[:120]}
            items.append(row)

        return {
            "total_ranges": len(rows),
            "matched": len(kept),
            "returned": len(items),
            "offset": off,
            "limit": lim,
            "min_size": need,
            "sort": "address" if sort == "address" else "size",
            "undefined_bytes_total": total_bytes,
            "by_block": {k: v for k, v in sorted(
                by_block.items(), key=lambda kv: -kv[1]["bytes"])},
            "filtered_out": skipped,
            "ranges": items,
            "note": ("大きい順に並べています。**既定で 1 バイトの隙間と未初期化"
                     "ブロックを除いています** (min_size / initialized_only で"
                     "変えられます)。with_refs=true にすると、返した範囲を指す"
                     "コードの件数が付きます — **参照があるのに未定義な領域は"
                     "読む価値が高い**です。"
                     "**classify=true にすると、返した範囲が何なのか "
                     "(コード / ポインタ表 / 文字列 / 浮動小数 / 圧縮 / 詰め物) を"
                     "推定して、次に呼ぶツールまで添えます。**"),
        }

    def _count_refs_in_range(self, start, end):
        """その範囲を指しているコードの件数を数えます (見つからなければ 0)。"""
        try:
            res = self.find_address_refs(start, range_end=end, limit=1)
            return {"total": res.get("total", 0),
                    "first": (res.get("refs") or [{}])[0].get("from")
                    if res.get("total") else None}
        except Exception:
            return {"total": None, "first": None,
                    "why": "memory イメージが無いか、範囲外です。"}

    # --- ツール: find_bytes ----------------------------------------------
    def find_bytes(self, pattern, start=None, end=None, align=1,
                   limit=DEFAULT_LIMIT, context=16):
        """export 済みメモリイメージから **バイト列を検索**します (AOB スキャン)。

        `??` をワイルドカードにできます:

            "48 8B ?? ?? 89"      ワイルドカード付き
            "0f 80 04 08"         そのまま
            "0F8004 08"           空白は自由

        既知シグネチャ探し、「この構造体は他にもあるか」、命令パターン探しに使えます。
        """
        needle, mask = _parse_aob(pattern)
        if not needle:
            raise ValueError("検索するバイトがありません。")
        step = max(1, int(align))
        lim = clamp_limit(limit)
        ctx = max(0, min(int(context), 64))

        mm, blocks = self._exported_blocks()
        lo = parse_hex(start) if start else None
        hi = parse_hex(end) if end else None
        if lo is not None and hi is not None and hi < lo:
            raise ValueError("end が start より小さいです。")

        matches = []
        total = 0
        scanned = []
        for blk in _scannable(blocks):
            if not _has_bytes(blk):
                continue
            bstart, bend = self._block_range(blk)
            if lo is not None and bend < lo:
                continue
            if hi is not None and bstart > hi:
                continue
            data = self._image_bytes(blk)
            first = max(0, (lo - bstart)) if lo is not None else 0
            last = min(len(data), (hi - bstart) + 1) if hi is not None else len(data)
            if first >= last:
                continue
            scanned.append(blk.get("name"))
            for pos in _aob_search(data, needle, mask, first, last, step):
                total += 1
                if len(matches) >= lim:
                    continue
                addr = bstart + pos
                c0 = max(0, pos - ctx)
                c1 = min(len(data), pos + len(needle) + ctx)
                matches.append({
                    "address": "0x{0:08x}".format(addr),
                    "block": blk.get("name"),
                    "match": bytes(data[pos:pos + len(needle)]).hex(" "),
                    "context_start": "0x{0:08x}".format(bstart + c0),
                    "context": bytes(data[c0:c1]).hex(" "),
                })

        return self._mark_overlays_scanned({
            "pattern": pattern,
            "length": len(needle),
            "wildcards": mask.count(0),
            "align": step,
            "scanned_blocks": scanned,
            "total": total,
            "returned": len(matches),
            "limit": lim,
            "matches": matches,
            "note": ("export 済みの memory イメージだけを見ています "
                     "(Ghidra には問い合わせません)。`??` はワイルドカードです。"
                     "命令列を探すときは align=4 (MIPS/ARM) や 2 (SH/Thumb) を"
                     "指定すると誤検出が減ります。"
                     "total は上限前の真の件数です。"),
        }, [b for b in _scannable(blocks) if _has_bytes(b)])

    # --- ツール: find_text (日本語 / Ghidra が拾えない文字列) --------------
    def find_text(self, encodings=None, min_chars=3, min_japanese=2,
                  start=None, end=None, require_terminator=True,
                  allow_halfwidth=False, level2_kanji=False,
                  min_kana=1, only_missing=True,
                  limit=DEFAULT_LIMIT, as_proposal=False,
                  proposal_kind="comments", label_prefix=None):
        """memory イメージから **Ghidra が拾えなかった文字列**を探します。

        Ghidra の文字列検出は基本 ASCII なので、Shift-JIS の日本語ラベルは
        strings.json にほとんど出てきません。ここで拾い直します。

        ★誤検出との戦いが本体です。素朴に「decode できたら文字列」とすると
        数千〜数十万件の誤検出が出て使い物になりません。既定では:

        - `allow_halfwidth=false`: **半角カタカナ (0xA1-0xDF) を数えません**。
          このバイト域は任意のバイナリに大量に現れる、最大の誤検出源です。
        - `min_japanese=2`: かな / 漢字を 2 文字以上要求します。1 文字だけ
          「日本語に見える」のは偶然でいくらでも起きます。
        - `require_terminator=true`: **NUL 終端を要求**します。本物の文字列は
          ほぼ NUL で終わるので、データの真ん中を切り出した偶然はここで落ちます。
        - 珍しい符号位置 (CJK 拡張A / 外字) が混ざったら捨てます。
        - `only_missing=true`: strings.json に既にある番地は除きます。
          「Ghidra が取りこぼしたもの」だけが欲しいからです。
        - `as_proposal=true`: そのまま `proposals/proposed_comments.json` に
          保存できる形 (`[AI]` 付き) を `proposal` に入れて返します。
          **反映は人間が apply_comments.py で行ってください** (MCP は書きません)。
        """
        wanted = [e.strip().lower() for e in (encodings or ["sjis", "utf8"])]
        for name in wanted:
            if name not in _SCANNERS:
                raise ValueError(
                    "encoding '{0}' は未対応です。使えるのは {1} です。".format(
                        name, ", ".join(sorted(_SCANNERS))))
        need = max(1, int(min_chars))
        need_jp = max(0, int(min_japanese))
        lim = clamp_limit(limit)

        mm, blocks = self._exported_blocks()
        lo = parse_hex(start) if start else None
        hi = parse_hex(end) if end else None
        known = set()
        if only_missing:
            for s in (self._safe(lambda: self._load("strings.json"), []) or []):
                a = try_parse_hex((s or {}).get("address") or "")
                if a is not None:
                    known.add(a)
            # ★既にラベルや型が付いている番地も除く。付け直しを提案しても
            #   人間の作業を上書きするだけで、apply 側にも弾かれます。
            index = self._symbol_index()
            known.update(index["labels"])
            known.update(index["typed"])

        found = {}
        total = 0
        skipped = {"日本語が少ない": 0, "かなを含まない": 0,
                   "珍しい符号位置が混ざる": 0,
                   "NUL 終端でない": 0, "Ghidra が既に持っている": 0,
                   "短すぎる": 0, "デコードできない": 0}
        for blk in _scannable(blocks):
            if not _has_bytes(blk):
                continue
            bstart, bend = self._block_range(blk)
            if lo is not None and bend < lo:
                continue
            if hi is not None and bstart > hi:
                continue
            data = self._image_bytes(blk)
            first = max(0, lo - bstart) if lo is not None else 0
            last = min(len(data), (hi - bstart) + 1) if hi is not None else len(data)
            if first >= last:
                continue
            for name in wanted:
                codec, scanner = _SCANNERS[name]
                for rs, rend in scanner(data, first, last, need,
                                        bool(allow_halfwidth),
                                        bool(level2_kanji)):
                    if require_terminator and not (
                            rend >= len(data) or data[rend] == 0):
                        skipped["NUL 終端でない"] += 1
                        continue
                    chunk = bytes(data[rs:rend])
                    try:
                        text = chunk.decode(codec)
                    except UnicodeDecodeError:
                        skipped["デコードできない"] += 1
                        continue
                    text = text.rstrip("\x00")
                    if len(text) < need:
                        skipped["短すぎる"] += 1
                        continue
                    good, why = _text_verdict(text, need_jp,
                                              max(0, int(min_kana)))
                    if not good:
                        skipped[why] += 1
                        continue
                    addr = bstart + rs
                    if addr in known:
                        skipped["Ghidra が既に持っている"] += 1
                        continue
                    total += 1
                    # 同じ番地を複数の符号化が拾ったら、長い方を残す。
                    old = found.get(addr)
                    if old is None or len(text) > len(old["text"]):
                        found[addr] = {
                            "address": "0x{0:08x}".format(addr),
                            "encoding": name,
                            "length": len(chunk),
                            "chars": len(text),
                            "text": text,
                            "block": blk.get("name"),
                        }

        items = [found[a] for a in sorted(found)]
        page = items[:lim]
        result = {
            "encodings": wanted,
            "min_chars": need,
            "min_japanese": need_jp,
            "require_terminator": bool(require_terminator),
            "allow_halfwidth": bool(allow_halfwidth),
            "level2_kanji": bool(level2_kanji),
            "min_kana": max(0, int(min_kana)),
            "only_missing": bool(only_missing),
            "total": len(items),
            "returned": len(page),
            "limit": lim,
            "raw_candidates": total,
            "filtered_out": skipped,
            "strings": page,
            "note": ("Ghidra の文字列検出は基本 ASCII なので、Shift-JIS の日本語は "
                     "strings.json にほとんど出てきません。ここは memory イメージを"
                     "直接走査しています。**推定なので誤検出は必ず混ざります** — "
                     "text を読んで意味が通るものだけ採用してください。"
                     "as_proposal=true にすると proposed_comments.json の形で返します。"),
        }
        if not items:
            result["hint"] = {
                "message": "標準の符号化では日本語が見つかりませんでした。"
                           "**「日本語が無い」とは限りません** — この年代の"
                           "ゲームは、テキストをフォントタイルへの"
                           "**独自インデックス**で持っているのが普通です。",
                "next_steps": [
                    "フォントのタイルを render_tiles で PNG にして、"
                    "文字の並び順を目で読む (4bpp / 8bpp を両方試す)。",
                    "並び順から文字対応表を作り、decode_text の table に渡す "
                    "(連番なら chars= で 1 行で書けます)。",
                    "うまく読めたら bridge_config.json の text_tables に"
                    "名前を付けて置き、以後は table_name で使い回す。",
                    "テキストが圧縮されていることもあります "
                    "(decompress / find_compressed_blocks)。",
                ],
            }
        if as_proposal:
            how = "Shift-JIS / UTF-8 として復号した文字列"
            kind = (proposal_kind or "comments").strip().lower()
            if kind not in ("comments", "labels", "both"):
                raise ValueError(
                    "proposal_kind は comments / labels / both のいずれかです。")
            if kind in ("comments", "both"):
                result["proposal"] = self._text_proposal(page, how)
            if kind in ("labels", "both"):
                result["label_proposal"] = self._label_proposal(
                    page, how, label_prefix)
        return result

    def _text_proposal(self, items, how):
        """`proposals/proposed_comments.json` にそのまま保存できる形を作ります。

        ★MCP は書きません。返した JSON を人間 (か解析セッション) が保存し、
          Ghidra GUI で apply_comments.py を実行して反映します。
          文字列データ型の適用は「データ型の自動変更」なので**常に禁止**です。
        """
        return {
            "schema_version": "1.0",
            # apply_* はこの名前を現在の Program と突き合わせ、一致しなければ
            # (無い・空でも) 何も変更せずに中止するので、program.json の program_name を入れる。
            "target_program": self._safe(
                lambda: (self._load("program.json") or {}).get("program_name"),
                None),
            "generated_by": "ghidra_readonly_mcp find_text/decode_text",
            "comments": [{
                "address": x["address"],
                "address_basis": "ghidra",
                "type": "eol",
                "comment": "[AI] {0}".format(x["text"]),
                "confidence": "medium",
                "reason": "memory イメージを {0} として復号した結果です。"
                          "Ghidra の文字列検出は ASCII 中心のため "
                          "strings.json に出ていません。".format(how),
                "evidence": ["encoding={0}".format(x.get("encoding", "custom")),
                             "bytes={0}".format(x["length"]),
                             "block={0}".format(x.get("block"))],
            } for x in items],
            "note": "MCP はこの JSON を保存しません。proposals/ に保存して、"
                    "Ghidra GUI で apply_comments.py を実行してください "
                    "(反映は必ず人間がトリガします)。",
        }

    # --- ゲーム内テキスト -> ラベル名 ------------------------------------
    def _label_proposal(self, items, how, prefix=None, max_name=48):
        """`proposals/proposed_labels.json` にそのまま保存できる形を作ります。

        ★ラベルは実質リネームなので、他の提案より縛りが強いです:
          - `bridge_config.json` の `allowed_apply_operations` に `"labels"` が
            無ければ apply 側が何もせず終了します (既定禁止)
          - **関数エントリには付きません** (apply 側が force でも拒否)
          - 既存の名前は上書きしません (自動生成名 LAB_ / DAT_ は上書き可)
          - 台帳に記録されるので `revert_operations.py` で巻き戻せます

        MCP はこの JSON を保存しません。返した内容を人間が `proposals/` へ
        保存し、`validate_proposed_labels.py` で確認してから
        Ghidra GUI で `apply_labels.py` を実行します。
        """
        labels = []
        skipped = []
        seen = {}
        for x in items:
            name, why = _label_from_text(x["text"], prefix, max_name)
            if name is None:
                skipped.append({"address": x["address"], "text": x["text"],
                                "why": why})
                continue
            # 同じ名前が並ぶと Ghidra 側で紛らわしいので連番を足す
            # (「テムジン」系のように似た名前が並ぶ表では普通に起きます)。
            if name in seen:
                seen[name] += 1
                name = "{0}_{1}".format(name, seen[name])
            else:
                seen[name] = 0
            labels.append({
                "address": x["address"],
                "name": name,
                "operation": "set_label",
                "address_basis": "ghidra",
                "confidence": "medium",
                "reason": "その番地のテキストを {0} から起こした名前です。"
                          "Ghidra はここを文字列と認識していません。".format(how),
                "evidence": ["text={0}".format(x["text"]),
                             "encoding={0}".format(x.get("encoding", "custom")),
                             "bytes={0}".format(x["length"])],
            })
        return {
            "schema_version": "1.0",
            "target_program": self._safe(
                lambda: (self._load("program.json") or {}).get("program_name"),
                None),
            "generated_by": "ghidra_readonly_mcp find_text/decode_text",
            "labels": labels,
            "skipped": skipped,
            "note": "MCP はこの JSON を保存しません。proposals/ に保存し、"
                    "validate_proposed_labels.py で確認してから Ghidra GUI で "
                    "apply_labels.py を実行してください。"
                    "★allowed_apply_operations に \"labels\" が無いと"
                    "apply 側は何もせず終了します (既定禁止)。"
                    "関数エントリには付きません (force でも拒否)。"
                    "skipped は名前にできなかったものです (理由つき)。",
        }

    # --- ツール: decode_text (独自符号) ----------------------------------
    def decode_text(self, address, table=None, table_name=None, length=256,
                    stop_at=None, as_proposal=False,
                    proposal_kind="comments", label_prefix=None):
        """**独自符号のテキスト**を、文字対応表を使って読みます。

        ゲーム独自の文字コード (0x00 が 'あ' のような自前の並び) は、どの
        標準符号化でも読めません。対応表を渡して復号します。

        - `table`: 16進キーと文字の辞書、または **連番形式**
          (`{"start": "0x20", "chars": "あいうえお"}`) をその場で渡す。
          独自符号の表はたいてい連番なので、1 文字ずつ書かずに済みます。
        - `table_name`: `bridge_config.json` の `text_tables` に置いた表を名前で使う
        - `stop_at`: 終端バイト (既定は表に無いバイトで止める)

        表は 1 バイト単位でも 2 バイト単位でも書けます (キーの桁数で判断)。
        """
        mapping = self._text_table(table, table_name)
        raw, where, origin = self._bytes_for(address, int(length), None, 0)
        widths = sorted({len(k) // 2 for k in mapping}, reverse=True)
        stop = None
        if stop_at is not None:
            stop = _parse_int(stop_at, "stop_at") & 0xFF

        out = []
        unknown = []
        i = 0
        while i < len(raw):
            if stop is not None and raw[i] == stop:
                break
            hit = None
            for w in widths:
                if i + w > len(raw):
                    continue
                key = bytes(raw[i:i + w]).hex().upper()
                if key in mapping:
                    hit = (mapping[key], w)
                    break
            if hit is None:
                unknown.append("0x{0:02x}".format(raw[i]))
                if stop_at is None:
                    break              # 表に無いバイト = 終端とみなす
                out.append("?")
                i += 1
                continue
            out.append(hit[0])
            i += hit[1]

        text = "".join(out)
        item = {"address": address, "encoding": "custom",
                "length": i, "chars": len(text), "text": text,
                "block": where}
        result = {
            "address": address,
            "table": table_name or "(その場で渡された表)",
            "table_entries": len(mapping),
            "consumed_bytes": i,
            "text": text,
            "chars": len(text),
            "unknown_bytes": unknown,
            "note": ("表に無いバイトで止めています (stop_at を指定すると"
                     "そのバイトまで読み、未知は ? になります)。"
                     "表は bridge_config.json の text_tables に名前を付けて"
                     "置いておくと使い回せます。"),
        }
        if as_proposal:
            kind = (proposal_kind or "comments").strip().lower()
            if kind not in ("comments", "labels", "both"):
                raise ValueError(
                    "proposal_kind は comments / labels / both のいずれかです。")
            if kind in ("comments", "both"):
                result["proposal"] = self._text_proposal([item], "独自符号の対応表")
            if kind in ("labels", "both"):
                result["label_proposal"] = self._label_proposal(
                    [item], "独自符号の対応表", label_prefix)
        return result

    def _text_table(self, table, table_name):
        """文字対応表を {16進キー: 文字} に正規化します。"""
        if table and table_name:
            raise ValueError("table と table_name はどちらか一方にしてください。")
        if table_name:
            tables = (self._bridge_config().get("text_tables") or {})
            table = tables.get(table_name)
            if table is None:
                raise ValueError(
                    "text_tables に '{0}' がありません。使えるのは {1} です "
                    "({2} に書きます)。".format(
                        table_name, ", ".join(sorted(tables)) or "(まだ無し)",
                        self.project_root / "bridge_config.json"))
        table = _expand_char_table(table)
        if not isinstance(table, dict) or not table:
            raise ValueError(
                "table か table_name のどちらかを指定してください。"
                "table は 16 進キーと文字の辞書、または "
                "{\"start\": \"0x20\", \"chars\": \"あいうえお\"} 形式です。")
        out = {}
        for key, value in table.items():
            k = str(key).lower().replace("0x", "").strip()
            if len(k) % 2 or not k:
                raise ValueError(
                    "表のキー '{0}' が 16 進として半端です "
                    "(1 バイト 2 桁で書いてください)。".format(key))
            out[k.upper()] = str(value)
        return out


    # --- 生成物の書き出し先 ---------------------------------------------
    def _extract_dir(self, create=True):
        """展開結果 / 画像の書き出し先を返します (無ければ作ります)。

        ★このツール群は MCP で**唯一ファイルを書く**機能です。安全境界を保つため:
          - 書くのは `<project_root>/extracted/` の**下だけ**
          - `ghidra_exports/` にも Ghidra プロジェクトにも**絶対に書かない**
          - 既存ファイルは上書きしない (同名なら連番を付ける)
        """
        root = self.project_root.resolve()
        out = root / "extracted"
        if out.is_symlink() or (hasattr(out, "is_junction") and out.is_junction()):
            raise ValueError(
                "extracted/ がシンボリックリンク / ジャンクションです。書き出し先は"
                "プロジェクト内の実フォルダに限ります: {0}".format(out))
        if not create and not out.exists():
            return None                       # 一覧・比較では作らない
        out.mkdir(parents=True, exist_ok=True)
        real = out.resolve()
        if real != out:
            raise ValueError(
                "extracted/ の実体がプロジェクトフォルダの外です。書き出しません: {0}".format(
                    out))
        return real

    def _resolve_out_path(self, out_path, default_name):
        """出力パスを決めます。extracted/ の外は拒否し、既存は連番で避けます。

        ★既定名 (default_name) でも明示指定 (out_path) でも、**resolve した後の
          パス**が extracted/ の配下かを確かめます (`..` / シンボリックリンク /
          ジャンクション / UNC / デバイスパスでの脱出を塞ぐ)。
        実際に作るときは `_create_out_file` で排他作成します。
        """
        base = self._extract_dir()
        if out_path:
            text = str(out_path).strip()
            if "\x00" in text:
                raise ValueError("出力先に NUL 文字は使えません。")
            if _is_unc_or_device(text):
                raise ValueError(
                    "出力先に UNC / デバイスパスは使えません。{0} の配下を"
                    "指定してください (指定: {1})。".format(base, out_path))
            path = Path(text)
            # resolve は末尾のドット / 空白を黙って落とすので、その前に各要素を見る。
            parts = path.parts[1:] if path.anchor else path.parts
            for part in parts:
                if part not in (".", ".."):
                    _check_name_component(part)
            if not path.is_absolute():
                path = base / path
        else:
            name = str(default_name)
            if Path(name).name != name:
                raise ValueError("内部エラー: 既定の出力名にパス区切りがあります。")
            _check_name_component(name)
            path = base / name
        path = path.resolve()
        if path == base or base not in path.parents:
            raise ValueError(
                "出力先は {0} の配下にしてください (指定: {1})。".format(
                    base, out_path if out_path else default_name))
        for part in path.relative_to(base).parts:
            _check_name_component(part)
        path.parent.mkdir(parents=True, exist_ok=True)
        # 作った後にもう一度確かめる (途中のフォルダがリンクだった場合)。
        if not _path_within(path.parent.resolve(), base):
            raise ValueError(
                "出力先のフォルダが {0} の外を指しています (リンク等)。".format(base))
        stem, suffix = path.stem, path.suffix
        n = 1
        while path.exists() or path.is_symlink():
            path = path.parent / "{0}_{1}{2}".format(stem, n, suffix)
            n += 1
        return path

    def _create_out_file(self, out_path, default_name):
        """出力ファイルを**排他作成**し、(パス, 書き込みハンドル) を返します。

        `_resolve_out_path` の確認と作成の間に同名ファイルができても上書きしない
        ように `xb` で開き、作れなければ次の連番を試します。
        """
        path = self._resolve_out_path(out_path, default_name)
        base = self._extract_dir()
        stem, suffix = path.stem, path.suffix
        n = 1
        while True:
            try:
                handle = path.open("xb")
            except FileExistsError:
                path = path.parent / "{0}_{1}{2}".format(stem, n, suffix)
                n += 1
                continue
            if not _path_within(path.resolve(), base):
                # 確認と作成の間にフォルダがリンクへ差し替えられた。いま作った
                # 空ファイルだけを片付けて中止する。
                handle.close()
                try:
                    path.unlink()
                except OSError:
                    pass
                raise ValueError(
                    "出力先が {0} の外に解決されました。書き出しを中止します。".format(base))
            return path, handle

    @staticmethod
    def _default_out_stem(address):
        """既定の出力名に使う番地の部分を返します (検証済みの 16 進だけ)。"""
        if not address:
            return "file"
        return "{0:08x}".format(parse_hex(address))

    def _source_roots(self):
        """source_path で読んでよいフォルダ (resolve 済み) を返します。

        - 既定: プロジェクト直下の `extracted/` と `dumps/`
          (実体がプロジェクトの外にあるリンク / ジャンクションなら使わない)
        - 追加: `bridge_config.json` の `source_roots` (人間が書く。相対パスは
          プロジェクトフォルダ基準)。**MCP の引数からは増やせません。**
        """
        root = self.project_root.resolve()
        roots = []
        for name in DEFAULT_SOURCE_DIRS:
            path = root / name
            if not path.is_dir():
                continue
            real = path.resolve()
            if _path_within(real, root):
                roots.append(real)
        cfg = self._safe(lambda: self._bridge_config(), {}) or {}
        extra = cfg.get("source_roots") or []
        if isinstance(extra, str):
            extra = [extra]
        for item in extra if isinstance(extra, list) else []:
            text = str(item or "").strip()
            # ★UNC / デバイスパスは resolve で触る前に捨てる (ネットワークに触れない)。
            if not text or "\x00" in text or _is_unc_or_device(text):
                continue
            path = Path(text)
            if not path.is_absolute():
                if path.drive or path.root:
                    continue                  # ドライブ相対 / ルート相対はカレント依存なので使わない
                path = root / path
            try:
                real = path.resolve()
            except (OSError, RuntimeError):
                continue                      # 解決できない設定は無視 (広げない側に倒す)
            if real.is_dir() and real not in roots:
                roots.append(real)
        return roots

    def _resolve_source_path(self, source_path):
        """source_path を検証し、読んでよい実ファイルのパスを返します。

        ★**resolve した後のパス**が許可フォルダ (`_source_roots`) の配下に
          あるときだけ読みます。`..` / シンボリックリンク / ジャンクション /
          UNC / デバイスパスでの脱出は拒否します。範囲外のときは
          **ファイルの有無を言いません** (存在確認に使われないため)。
        """
        text = str(source_path).strip()
        if not text or "\x00" in text:
            raise ValueError("source_path が空か、不正な文字を含みます。")
        roots = self._source_roots()
        allowed = ", ".join(str(r) for r in roots) or "(無し)"
        if _is_unc_or_device(text):
            raise ValueError(
                "source_path に UNC / デバイスパスは使えません。読めるのは "
                "{0} の配下だけです。".format(allowed))
        path = self._project_relative(text, "source_path")
        try:
            real = path.resolve()
        except (OSError, RuntimeError):
            real = None
        if real is None or not any(_path_within(real, r) and real != r
                                   for r in roots):
            raise ValueError(
                "source_path は許可されたフォルダの配下だけ読めます "
                "(指定: {0} / 許可: {1})。外部のファイルを読むときは、"
                "人間が bridge_config.json の source_roots にフォルダを"
                "書き足してください。".format(source_path, allowed))
        if not real.is_file():
            raise ValueError("ファイルが見つかりません: {0}".format(source_path))
        return real

    @staticmethod
    def _read_span(want, length):
        """読む長さを決めます。length 未指定は上限で打ち切り、超える指定はエラー。"""
        if length:
            n = int(length)
            if n < 0:
                raise ValueError("length は 0 以上で指定してください。")
            if n > MAX_SOURCE_BYTES:
                raise ValueError(
                    "length {0} が 1 回に読める上限 {1} バイトを超えます。"
                    "範囲を分けて呼んでください。".format(n, MAX_SOURCE_BYTES))
            return min(want, n)
        return min(want, MAX_SOURCE_BYTES)

    def _bytes_for(self, address, length, source_path=None, offset=0):
        """メモリイメージ or ローカルファイルからバイト列を取り出します。

        source_path を渡すとそのファイルを読みます (展開結果を続けて扱うため)。
        ★読めるのは `_source_roots()` の配下だけで、読む量は
          `MAX_SOURCE_BYTES` まで (全体を読んでから切ることはしません)。
        """
        if source_path:
            path = self._resolve_source_path(source_path)
            size = path.stat().st_size
            off = int(offset or 0)
            if off < 0 or off > size:
                raise ValueError("offset {0} がファイル範囲外です。".format(offset))
            span = self._read_span(size - off, length)
            with path.open("rb") as handle:
                handle.seek(off)
                raw = handle.read(span)
            return raw, "file:{0}".format(path.name), off
        if not address:
            raise ValueError("address か source_path のどちらかを指定してください。")
        target = parse_hex(address)
        mm, blocks = self._exported_blocks()
        block = self._find_block(target, blocks)
        if block is None:
            raise ValueError(
                "アドレス {0} を含む memory ブロックが export されていません。".format(address))
        start, end = self._block_range(block)
        span = self._read_span(end - target + 1, length)
        return (self._read_memory(block, target - start, span),
                block.get("name"), target)

    @staticmethod
    def _check_render_size(src_w, src_h, out_w, out_h):
        """描画する前に画像の大きさを上限と比べます (確保する前に断る)。"""
        if src_w * src_h > MAX_RENDER_SOURCE_PIXELS:
            raise ValueError(
                "描く画素数 {0}x{1} が上限 {2} を超えます。length を絞るか、"
                "範囲を分けてください。".format(src_w, src_h, MAX_RENDER_SOURCE_PIXELS))
        if (out_w > MAX_RENDER_SIDE or out_h > MAX_RENDER_SIDE
                or out_w * out_h > MAX_RENDER_PIXELS):
            raise ValueError(
                "出力画像 {0}x{1} が上限 (一辺 {2} / 画素数 {3}) を超えます。"
                "scale を下げるか、tiles_per_row / length を絞ってください。".format(
                    out_w, out_h, MAX_RENDER_SIDE, MAX_RENDER_PIXELS))

    # --- ツール: decompress --------------------------------------------
    def decompress(self, address=None, type=None, max_size=None,
                   source_path=None, offset=0, out_path=None):
        """GBA / NDS の BIOS 圧縮を展開し、**ファイルへ保存**してパスを返します。

        展開結果は数十〜数百 KB になるので、中身は応答に載せません
        (先頭のプレビューだけ返します)。続けて render_tiles / read_data に
        source_path として渡せます。
        """
        cap = int(max_size) if max_size else bios_compress.DEFAULT_MAX_SIZE
        if cap < 1 or cap > MAX_DECOMPRESS_SIZE:
            raise ValueError(
                "max_size は 1〜{0} バイトで指定してください (指定: {1})。".format(
                    MAX_DECOMPRESS_SIZE, max_size))
        stem = self._default_out_stem(address)
        # 圧縮ストリーム自体の長さは事前に分からないので、上限の数倍を読む
        # (ただし 1 回に読む絶対上限 MAX_SOURCE_BYTES は超えない)。
        raw, where, origin = self._bytes_for(
            address, min(cap * 4 + 0x1000, MAX_SOURCE_BYTES), source_path, offset)
        try:
            out, info = bios_compress.decompress(
                raw, 0, max_size=cap, force_type=type,
                reveal_bytes=not source_path)
        except bios_compress.DecompressError as exc:
            raise ValueError("展開できません: {0}".format(exc))

        kind = re.sub(r"[^0-9A-Za-z_-]", "_", str(info["type"]))
        name = "decompressed_{0}_{1}.bin".format(stem, kind)
        path, handle = self._create_out_file(out_path, name)
        with handle:
            handle.write(out)

        nested = bios_compress._peek_nested(out)
        return {
            "source": address or str(source_path),
            "source_block": where,
            "type": info["type"],
            "type_detail": info["type_detail"],
            "compressed_size": info["compressed_size"],
            "decompressed_size": len(out),
            "ratio": info["ratio"],
            "entropy": round(bios_compress.shannon_entropy(out), 2),
            "out_path": str(path),
            "preview": out[:32].hex(" "),
            "nested": nested,
            "note": ("展開結果はファイルに保存しました (応答には載せません)。"
                     "render_tiles / decompress の source_path に渡せます。" +
                     ("★中身がさらに {0} で圧縮されています。もう一度 decompress を"
                      "source_path で呼んでください。".format(nested["type"])
                      if nested else "")),
        }

    # --- ツール: find_compressed_blocks ---------------------------------
    def find_compressed_blocks(self, start, end, min_size=0x200,
                               include_rle=False, limit=100):
        """範囲を走査して圧縮ブロック候補を列挙します (誤検出を落としてから返す)。

        ★処理予算 (MCP 引数では緩められない):
          - 1 回に走査するのは MAX_COMPRESS_SCAN_BYTES まで。範囲がそれより広ければ
            打ち切り、`next_start` から続きを呼べるようにします。
          - 展開を試す回数 MAX_COMPRESS_ATTEMPTS と、試した宣言サイズの累計
            MAX_COMPRESS_WORK_BYTES でも止めます (棄却され続ける候補でも止まる)。
          - 打ち切ったときは `complete=false` と `stopped` / `unscanned` を返します。
            **候補が 0 件でも「圧縮データは無い」とは限りません。**
        """
        lo = parse_hex(start)
        hi = parse_hex(end)
        if hi <= lo:
            raise ValueError("end は start より大きくしてください。")
        min_sz = int(min_size)
        if min_sz < 0:
            raise ValueError("min_size は 0 以上で指定してください。")
        mm, blocks = self._exported_blocks()
        block = self._find_block(lo, blocks)
        if block is None:
            raise ValueError(
                "アドレス {0} を含む memory ブロックが export されていません。".format(start))
        bstart, bend = self._block_range(block)
        hi = min(hi, bend + 1)
        scan_hi = min(hi, lo + MAX_COMPRESS_SCAN_BYTES)
        # 走査範囲の終わりをまたぐブロックも展開できるように、展開に使うぶんだけ
        # 少し先まで読む (候補の開始位置は scan_hi まで)。ブロック全体は読まない。
        tail = bios_compress.DEFAULT_MAX_SIZE * 2 + 0x1000
        read_hi = min(hi, scan_hi + tail)
        data = self._read_memory(block, lo - bstart, read_hi - lo)

        stats = {}
        found, rejected = bios_compress.find_blocks(
            data, lo, min_size=min_sz, include_rle=bool(include_rle),
            limit=clamp_limit(limit), scan_end=scan_hi - lo,
            max_attempts=MAX_COMPRESS_ATTEMPTS, max_work=MAX_COMPRESS_WORK_BYTES,
            stats=stats)

        reasons = {
            "limit": "採用件数が limit に達した",
            "max_attempts": "展開を試す回数の上限 ({0}) に達した".format(MAX_COMPRESS_ATTEMPTS),
            "max_work": "展開を試した量の上限 ({0} バイト) に達した".format(
                MAX_COMPRESS_WORK_BYTES),
        }
        stopped = None
        next_start = None
        if stats.get("stopped"):
            next_start = lo + int(stats.get("stopped_at") or 0)
            stopped = {"reason": stats["stopped"], "why": reasons.get(stats["stopped"])}
        elif scan_hi < hi:
            next_start = scan_hi
            stopped = {"reason": "max_scan_bytes",
                       "why": "1 回に走査できる量 ({0} バイト) を超える範囲".format(
                           MAX_COMPRESS_SCAN_BYTES)}
        complete = stopped is None
        result = {
            "start": start,
            "end": "0x{0:08x}".format(hi),
            "block": block.get("name"),
            "scanned_bytes": (next_start if next_start is not None else scan_hi) - lo,
            "min_size": min_sz,
            "include_rle": bool(include_rle),
            "total": len(found),
            "blocks": found,
            "rejected": rejected,
            "complete": complete,
            "budget": {"attempts": stats.get("attempts"),
                       "max_attempts": MAX_COMPRESS_ATTEMPTS,
                       "work_bytes": stats.get("work_bytes"),
                       "max_work_bytes": MAX_COMPRESS_WORK_BYTES,
                       "max_scan_bytes": MAX_COMPRESS_SCAN_BYTES},
            "note": ("ヘッダらしく見えるだけの誤検出を、展開の成否・宣言サイズ一致・"
                     "圧縮率・エントロピーで落としてから返しています。"
                     "**RLE は既定で対象外**です (構造の制約がほぼ無く、任意のバイト列が"
                     "展開できてしまうため誤検出の主因になります。include_rle=true で有効化)。"
                     "nested が付いた候補は中身がさらに圧縮されています。"),
        }
        if not complete:
            result["stopped"] = stopped
            result["next_start"] = "0x{0:08x}".format(next_start)
            result["unscanned"] = ["0x{0:08x}".format(next_start), "0x{0:08x}".format(hi)]
            result["note"] = (
                "★途中で打ち切りました ({0})。0x{1:08x} 以降は**未検査**なので、"
                "候補が少なくても「圧縮データは無い」とは言えません。"
                "続きは start=\"0x{1:08x}\" で呼んでください。".format(
                    stopped["why"], next_start) + result["note"])
        return result

    # --- ツール: render_tiles -------------------------------------------
    def render_tiles(self, address=None, length=None, bpp=4, tiles_per_row=32,
                     palette_address=None, sprite_size=None, source_path=None,
                     offset=0, out_path=None, scale=1, show_index=False,
                     index_base=0, index_hex=True, layout="tiles", width=None):
        """タイル / 直線配置のグラフィックを PNG に描き出し、パスを返します。

        `layout="linear"` にすると **8x8 タイルに並べ替えず**、`width` ピクセル
        ごとに折り返して描きます。PS1 のテクスチャや、素のビットマップは
        タイル配置ではないので、これを付けないと形が崩れます
        (PS1 の TIM ならヘッダを読む `render_tim` の方が確実です)。

        形式当ては「見る」のが一番速いのに、毎回 Pillow スクリプトを書くのは
        無駄なのでツールにしました。

        sprite_size に (4,4) のような (横タイル数, 縦タイル数) を渡すと、
        **1D マッピングのスプライト単位で並べ直します**。これをやらないと
        32x32 スプライトは形が読めません。

        `show_index=true` にすると **各タイルの番号を焼き込みます**。
        フォントの文字対応表を作るときに要る「何番目がどの文字か」を、
        画像を見ながらそのまま読み取れます。`index_base` に符号の開始値
        (例 0x20) を渡すと、その値から振ります。番号を入れるときは自動で
        拡大するので、`scale` は省略できます。
        """
        try:
            from PIL import Image
        except ImportError:
            raise ValueError(
                "Pillow が必要です。'python -m pip install Pillow' で導入してください。")

        depth = int(bpp)
        if depth not in (4, 8):
            raise ValueError("bpp は 4 か 8 を指定してください。")
        mode = (layout or "tiles").strip().lower()
        if mode not in ("tiles", "linear"):
            raise ValueError("layout は tiles か linear を指定してください。")
        if mode == "linear":
            return self._render_linear(address, length, depth, palette_address,
                                       source_path, offset, out_path, scale,
                                       width)
        tile_bytes = 32 if depth == 4 else 64
        stem = self._default_out_stem(address)
        raw, where, origin = self._bytes_for(address, length, source_path, offset)
        tile_count = len(raw) // tile_bytes
        if tile_count == 0:
            raise ValueError(
                "タイルが 1 枚も取れません (1 タイル {0} バイト必要)。".format(tile_bytes))

        palette = self._load_palette(palette_address, depth)
        sprite = self._parse_sprite_size(sprite_size)
        per_row = max(1, int(tiles_per_row))
        if per_row > MAX_RENDER_SIDE // 8:
            raise ValueError(
                "tiles_per_row は 1〜{0} で指定してください。".format(MAX_RENDER_SIDE // 8))
        zoom = max(1, min(int(scale or 1), 16))
        if show_index and zoom < 3:
            # 番号を読める大きさにする。1 倍だと 8px しかなく数字が潰れます。
            zoom = 3

        if sprite:
            sw, sh = sprite
            per_sprite = sw * sh
            sprites = tile_count // per_sprite
            if sprites == 0:
                raise ValueError(
                    "スプライト 1 個ぶん ({0} タイル) に足りません。".format(per_sprite))
            cols = max(1, per_row // sw)
            rows = (sprites + cols - 1) // cols
            width, height = cols * sw * 8, rows * sh * 8
        else:
            cols = per_row
            rows = (tile_count + cols - 1) // cols
            width, height = cols * 8, rows * 8

        # ★確保する前に、拡大・番号帯まで含めた最終の大きさを上限と比べる。
        unit_w, unit_h = ((sprite[0] * 8, sprite[1] * 8) if sprite else (8, 8))
        units = (tile_count // (sprite[0] * sprite[1])) if sprite else tile_count
        if show_index:
            label_cols = max(1, width // unit_w)
            label_rows = max(1, (units + label_cols - 1) // label_cols)
            out_w = label_cols * unit_w * zoom
            out_h = label_rows * (unit_h * zoom + 10)
        else:
            out_w, out_h = width * zoom, height * zoom
        self._check_render_size(width, height, out_w, out_h)

        image = Image.new("RGBA", (width, height), (0, 0, 0, 0))
        px = image.load()
        for index in range(tile_count):
            if sprite:
                sw, sh = sprite
                per_sprite = sw * sh
                s_index, within = divmod(index, per_sprite)
                if s_index >= (width // (sw * 8)) * (height // (sh * 8)):
                    break
                s_col = s_index % max(1, (width // (sw * 8)))
                s_row = s_index // max(1, (width // (sw * 8)))
                tx = s_col * sw + (within % sw)
                ty = s_row * sh + (within // sw)
            else:
                tx, ty = index % cols, index // cols
            self._blit_tile(px, raw, index * tile_bytes, depth, tx * 8, ty * 8,
                            palette, width, height)

        if zoom > 1 or show_index:
            image, width, height = _zoom_and_label(
                Image, image, zoom, unit_w, unit_h, units,
                bool(show_index), int(index_base or 0), bool(index_hex))

        name = "tiles_{0}_{1}bpp{2}.png".format(
            stem, depth, "_indexed" if show_index else "")
        path, handle = self._create_out_file(out_path, name)
        with handle:
            image.save(handle, format="PNG")
        return {
            "source": address or str(source_path),
            "source_block": where,
            "bpp": depth,
            "tiles": tile_count,
            "tiles_per_row": per_row,
            "sprite_size": list(sprite) if sprite else None,
            "palette": palette_address,
            "scale": zoom,
            "show_index": bool(show_index),
            "index_base": ("0x{0:x}".format(int(index_base or 0))
                           if show_index else None),
            "units_labeled": units if show_index else None,
            "size": [width, height],
            "out_path": str(path),
            "note": ("GBA の 8x8 タイル形式で描いています。"
                     "スプライトが崩れて見えるときは sprite_size=[4,4] のように"
                     "指定して 1D マッピング単位で並べ直してください。"
                     "palette_address 省略時はグレースケールです "
                     "(色が合わないのは配色の問題で、形が読めれば形式は合っています)。"
                     "**フォントの文字対応表を作るときは show_index=true**。"
                     "各タイルに番号が入るので、画像を見ながら "
                     "decode_text の表 (連番形式なら chars= に並べるだけ) を"
                     "書き起こせます。"),
        }

    @staticmethod
    def _parse_sprite_size(sprite_size):
        """sprite_size を (横タイル数, 縦タイル数) に正規化します。"""
        if not sprite_size:
            return None
        if isinstance(sprite_size, str):
            parts = [p for p in re.split(r"[^0-9]+", sprite_size) if p]
        else:
            parts = list(sprite_size)
        if len(parts) == 1:
            parts = [parts[0], parts[0]]
        if len(parts) != 2:
            raise ValueError("sprite_size は [横タイル数, 縦タイル数] で指定してください。")
        w, h = int(parts[0]), int(parts[1])
        if w < 1 or h < 1 or w > 32 or h > 32:
            raise ValueError("sprite_size は 1〜32 の範囲で指定してください。")
        return (w, h)

    def _load_palette(self, palette_address, depth):
        """GBA の BGR555 パレットを読み、RGBA のリストにします (省略時はグレー)。"""
        count = 16 if depth == 4 else 256
        if not palette_address:
            # グレースケール。0 番は透明にして「未使用」が見て分かるようにする。
            step = 255 // max(1, count - 1)
            return [(0, 0, 0, 0)] + [(i * step, i * step, i * step, 255)
                                     for i in range(1, count)]
        raw, _, _ = self._bytes_for(palette_address, count * 2, None, 0)
        out = []
        for i in range(count):
            if i * 2 + 2 > len(raw):
                out.append((0, 0, 0, 255))
                continue
            v = int.from_bytes(raw[i * 2:i * 2 + 2], "little")
            r = (v & 0x1F) << 3
            g = ((v >> 5) & 0x1F) << 3
            b = ((v >> 10) & 0x1F) << 3
            out.append((r, g, b, 0 if i == 0 else 255))
        return out

    def _render_linear(self, address, length, depth, palette_address,
                       source_path, offset, out_path, scale, width):
        """8x8 タイルに並べ替えず、width ピクセルごとに折り返して描きます。"""
        from PIL import Image

        if not width:
            raise ValueError(
                "layout=\"linear\" のときは width (1 行のピクセル数) が要ります。"
                "PS1 のテクスチャなら 64 / 128 / 256 あたりから試してください。")
        pix_width = int(width)
        if pix_width < 1 or pix_width > 4096:
            raise ValueError("width は 1〜4096 で指定してください。")
        stem = self._default_out_stem(address)
        raw, where, _origin = self._bytes_for(address, length, source_path, offset)
        row_bytes = pix_width // 2 if depth == 4 else pix_width
        if row_bytes < 1:
            raise ValueError("width が小さすぎます (4bpp なら 2 以上)。")
        rows = len(raw) // row_bytes
        if rows == 0:
            raise ValueError(
                "1 行ぶん ({0} バイト) に足りません。".format(row_bytes))
        zoom = max(1, min(int(scale or 1), 16))
        self._check_render_size(pix_width, rows, pix_width * zoom, rows * zoom)

        palette = self._load_palette(palette_address, depth)
        limit = len(palette) - 1
        image = Image.new("RGBA", (pix_width, rows), (0, 0, 0, 0))
        px = image.load()
        for y in range(rows):
            base = y * row_bytes
            for x in range(pix_width):
                if depth == 4:
                    b = raw[base + x // 2]
                    value = (b & 0xF) if x % 2 == 0 else (b >> 4)
                else:
                    value = raw[base + x]
                px[x, y] = palette[min(value, limit)]
        if zoom > 1:
            image = image.resize((pix_width * zoom, rows * zoom), Image.NEAREST)

        name = "linear_{0}_{1}bpp.png".format(stem, depth)
        path, handle = self._create_out_file(out_path, name)
        with handle:
            image.save(handle, format="PNG")
        return {
            "source": address or str(source_path),
            "source_block": where,
            "layout": "linear",
            "bpp": depth,
            "size": [pix_width, rows],
            "palette": palette_address,
            "scale": zoom,
            "out_path": str(path),
            "note": ("8x8 タイルに並べ替えず、width ピクセルごとに折り返して"
                     "描いています (PS1 のテクスチャなど直線配置向け)。"
                     "形が崩れるときは width を変えてください "
                     "(64 / 128 / 256 あたりが定番)。"
                     "PS1 の TIM なら render_tim の方が確実です "
                     "(幅も深さも CLUT もヘッダから読みます)。"),
        }

    # --- PS1 の TIM / 直線配置 -------------------------------------------
    @staticmethod
    def _bgr555(value, index=None):
        """BGR555 1 語を RGBA にします。

        PS1 も GBA も色の並びは同じ (bit0-4 R / 5-9 G / 10-14 B) ですが、
        **PS1 は bit15 が半透明フラグ (STP)** で、`色 0x0000 かつ STP=0` が
        「透明」の約束です。この区別が無いと、抜き色が黒で塗り潰されて
        形が読めなくなります。
        """
        r = (value & 0x1F) << 3
        g = ((value >> 5) & 0x1F) << 3
        b = ((value >> 10) & 0x1F) << 3
        stp = (value >> 15) & 1
        alpha = 0 if (value == 0 and not stp) else 255
        return (r, g, b, alpha)

    def _tim_palette(self, raw, clut_off, entries, clut_index):
        """TIM の CLUT ブロックから、指定番号のパレットを RGBA で取り出します。"""
        base = clut_off + clut_index * entries * 2
        out = []
        for i in range(entries):
            pos = base + i * 2
            if pos + 2 > len(raw):
                out.append((0, 0, 0, 255))
                continue
            out.append(self._bgr555(int.from_bytes(raw[pos:pos + 2], "little")))
        return out

    def render_tim(self, address=None, source_path=None, offset=0,
                   clut_index=0, out_path=None, scale=1):
        """PS1 の TIM 画像を PNG に描き出し、パスを返します。

        TIM は PS1 のテクスチャ / フォント / UI がほぼこの形で入っている形式です。
        `render_tiles` は GBA の **8x8 タイル**前提なので、**直線配置**の TIM は
        そのままでは読めません (形が崩れます)。ここでヘッダを読んで、
        幅・深さ・CLUT を全部 TIM 自身から決めます。

        `clut_index` で何番目のパレットを使うかを選べます (1 枚の絵に対して
        色違いの CLUT が複数入っているのが普通です)。
        """
        try:
            from PIL import Image
        except ImportError:
            raise ValueError(
                "Pillow が必要です。'python -m pip install Pillow' で導入してください。")

        stem = self._default_out_stem(address)
        raw, where, origin = self._bytes_for(address, None, source_path, offset)
        # ★ファイル入力では、ヘッダの値 (先頭のバイト列など) をエラー文に出さない。
        info = self._parse_tim_header(raw, reveal=not source_path)
        depth = info["bpp"]
        width, height = info["width"], info["height"]
        zoom = max(1, min(int(scale or 1), 16))
        self._check_render_size(width, height, width * zoom, height * zoom)

        palette = None
        if info["has_clut"]:
            entries = info["clut_entries"]
            count = info["clut_count"]
            if not (0 <= int(clut_index) < count):
                raise ValueError(
                    "clut_index {0} は範囲外です (この TIM の CLUT は {1} 個)。".format(
                        clut_index, count))
            palette = self._tim_palette(raw, info["clut_data_offset"], entries,
                                        int(clut_index))
        elif depth in (4, 8):
            raise ValueError(
                "CLUT の無い {0}bpp TIM です (壊れているか TIM ではありません)。".format(depth))

        image = Image.new("RGBA", (width, height), (0, 0, 0, 0))
        px = image.load()
        data_off = info["image_data_offset"]
        for y in range(height):
            for x in range(width):
                value = self._tim_pixel(raw, data_off, info, x, y)
                if value is None:
                    break
                if palette is not None:
                    px[x, y] = palette[min(value, len(palette) - 1)]
                elif depth == 16:
                    px[x, y] = self._bgr555(value)
                else:                                  # 24bpp (R,G,B の生並び)
                    px[x, y] = value

        if zoom > 1:
            image = image.resize((width * zoom, height * zoom), Image.NEAREST)

        name = "tim_{0}_{1}bpp.png".format(stem, depth)
        path, handle = self._create_out_file(out_path, name)
        with handle:
            image.save(handle, format="PNG")
        return {
            "source": address or str(source_path),
            "source_block": where,
            "format": "TIM",
            "bpp": depth,
            "size": [width, height],
            "has_clut": info["has_clut"],
            "clut_entries": info["clut_entries"],
            "clut_count": info["clut_count"],
            "clut_index": int(clut_index) if info["has_clut"] else None,
            "vram": {"x": info["image_x"], "y": info["image_y"]},
            "scale": zoom,
            "out_path": str(path),
            "note": ("TIM のヘッダから幅・深さ・CLUT を読んで描いています "
                     "(render_tiles と違って 8x8 タイルには並べ替えません)。"
                     "色が違うときは clut_index を変えてください "
                     "(この TIM には CLUT が {0} 個あります)。"
                     "透明は「色 0x0000 かつ STP ビット 0」で判定しています。".format(
                         info["clut_count"])),
        }

    @staticmethod
    def _parse_tim_header(raw, reveal=True):
        """TIM のヘッダを読み、描画に要る値を dict で返します。

        壊れている / TIM でないときは **どこがおかしいか** を書いて失敗します
        (「読めません」だけだと、次に何をすればいいか分からないため)。

        ★reveal=False (source_path でファイルを読んだとき) は、エラー文に
          **入力のバイト値を入れません** (先頭 4 バイト・フラグ・大きさ等)。
          どこがおかしいかの説明は残し、値だけ伏せます。
        """
        def shown(text):
            return text if reveal else "(非表示)"

        if len(raw) < 8:
            raise ValueError("短すぎて TIM ヘッダが読めません。")
        magic = int.from_bytes(raw[0:4], "little")
        if magic != 0x10:
            raise ValueError(
                "TIM ではありません (先頭 4 バイトが 0x00000010 ではなく "
                "{0})。address / offset を確認してください。".format(
                    shown("0x{0:08x}".format(magic))))
        flags = int.from_bytes(raw[4:8], "little")
        if flags & ~0xF:
            raise ValueError(
                "TIM のフラグが変です ({0})。使うのは下位 4bit だけ "
                "(pmode 3bit + CLUT 1bit) なので、TIM ではありません。".format(
                    shown("0x{0:08x}".format(flags))))
        pmode = flags & 7
        has_clut = bool(flags & 8)
        bpp = {0: 4, 1: 8, 2: 16, 3: 24}.get(pmode)
        if bpp is None:
            raise ValueError(
                "未対応の pmode={0} です (0=4bpp / 1=8bpp / 2=16bpp / 3=24bpp)。".format(
                    shown(str(pmode))))

        pos = 8
        clut_entries = clut_count = 0
        clut_bnum = 0
        clut_data_offset = None
        if has_clut:
            if len(raw) < pos + 12:
                raise ValueError("CLUT ブロックのヘッダが途中で切れています。")
            bnum = clut_bnum = int.from_bytes(raw[pos:pos + 4], "little")
            clut_entries = int.from_bytes(raw[pos + 8:pos + 10], "little")
            clut_count = int.from_bytes(raw[pos + 10:pos + 12], "little")
            clut_data_offset = pos + 12
            if clut_entries <= 0 or clut_count <= 0:
                raise ValueError(
                    "CLUT の大きさが変です (entries={0} count={1})。".format(
                        shown(str(clut_entries)), shown(str(clut_count))))
            pos += bnum if bnum >= 12 else (12 + clut_entries * clut_count * 2)

        if len(raw) < pos + 12:
            raise ValueError("画像ブロックのヘッダが途中で切れています。")
        image_bnum = int.from_bytes(raw[pos:pos + 4], "little")
        image_x = int.from_bytes(raw[pos + 4:pos + 6], "little")
        image_y = int.from_bytes(raw[pos + 6:pos + 8], "little")
        words = int.from_bytes(raw[pos + 8:pos + 10], "little")
        height = int.from_bytes(raw[pos + 10:pos + 12], "little")
        # ★TIM の幅は **16bit 単位**。ピクセル幅は深さで変わる。
        width = {4: words * 4, 8: words * 2, 16: words, 24: words * 2 // 3}[bpp]
        if width <= 0 or height <= 0 or width > 4096 or height > 4096:
            raise ValueError(
                "画像の大きさが変です ({0}x{1})。TIM でない可能性があります。".format(
                    shown(str(width)), shown(str(height))))
        return {
            "bpp": bpp,
            "has_clut": has_clut,
            "clut_entries": clut_entries,
            "clut_count": clut_count,
            "clut_bnum": clut_bnum,
            "image_bnum": image_bnum,
            "clut_data_offset": clut_data_offset,
            "image_data_offset": pos + 12,
            "image_x": image_x,
            "image_y": image_y,
            "width": width,
            "height": height,
            "row_bytes": words * 2,
        }

    @staticmethod
    def _tim_looks_real(info):
        """走査で拾った候補が**本物の TIM らしいか**を厳しく見ます。

        ★ヘッダが読めるだけで出すと、4MB も舐めれば偶然の一致が必ず混ざります。
          宣言サイズの一致と、CLUT の大きさが
          規定どおり (4bpp=16 色 / 8bpp=256 色) であることを要求します。
          `render_tim` に番地を直接渡すときはここまで要求しません
          (人が「これは TIM だ」と言っているものを道具が断らないため)。
        """
        if info["has_clut"]:
            need = 16 if info["bpp"] == 4 else 256
            if info["clut_entries"] != need:
                return False
            if not (1 <= info["clut_count"] <= 256):
                return False
            if info["clut_bnum"] != 12 + info["clut_entries"] * info["clut_count"] * 2:
                return False
        elif info["bpp"] in (4, 8):
            return False                       # CLUT 無しの 4/8bpp はありえない
        if info["image_bnum"] != 12 + info["row_bytes"] * info["height"]:
            return False
        # VRAM 座標 (1024x512 のフレームバッファに収まる値であるはず)。
        if info["image_x"] >= 1024 or info["image_y"] >= 512:
            return False
        return True

    @staticmethod
    def _tim_pixel(raw, base, info, x, y):
        """TIM の 1 ピクセルを返します (CLUT 番号 / BGR555 値 / RGBA)。範囲外は None。"""
        row = base + y * info["row_bytes"]
        bpp = info["bpp"]
        if bpp == 4:
            pos = row + x // 2
            if pos >= len(raw):
                return None
            b = raw[pos]
            return (b & 0xF) if x % 2 == 0 else (b >> 4)
        if bpp == 8:
            pos = row + x
            return raw[pos] if pos < len(raw) else None
        if bpp == 16:
            pos = row + x * 2
            if pos + 2 > len(raw):
                return None
            return int.from_bytes(raw[pos:pos + 2], "little")
        pos = row + x * 3
        if pos + 3 > len(raw):
            return None
        return (raw[pos], raw[pos + 1], raw[pos + 2], 255)

    def find_tim_blocks(self, start=None, end=None, limit=DEFAULT_LIMIT):
        """範囲を走査して **TIM 画像**の位置を列挙します。

        CD 内のファイルやオーバーレイには TIM がまとめて置かれているのが普通で、
        位置が分からないと `render_tim` を呼べません。ヘッダが読めて、
        宣言サイズが範囲に収まるものだけを出します (見た目だけ似たゴミを弾く)。
        """
        mm, blocks = self._exported_blocks()
        lo = parse_hex(start) if start else None
        hi = parse_hex(end) if end else None
        if lo is not None and hi is not None and hi < lo:
            raise ValueError("end が start より小さいです。")
        lim = clamp_limit(limit)

        items = []
        total = 0
        scanned = []
        for blk in _scannable(blocks):
            if not _has_bytes(blk):
                continue
            bstart, bend = self._block_range(blk)
            if lo is not None and bend < lo:
                continue
            if hi is not None and bstart > hi:
                continue
            data = self._image_bytes(blk)
            first = max(0, (lo - bstart)) if lo is not None else 0
            last = min(len(data), (hi - bstart) + 1) if hi is not None else len(data)
            scanned.append(blk.get("name"))
            pos = first
            while pos + 8 <= last:
                # TIM は 4 バイト境界に置かれる。先頭 4 バイトが 0x10 のところだけ見る。
                found = bytes(data).find(b"\x10\x00\x00\x00", pos, last)
                if found < 0:
                    break
                pos = found + 4
                if found % 4:
                    continue
                try:
                    info = self._parse_tim_header(bytes(data[found:found + 4096]))
                except ValueError:
                    continue
                # ★走査では**厳しく**見る。4MB を舐めれば「たまたま TIM に
                #   見えるバイト列」は必ず出るので、ヘッダが読めるだけでは
                #   出さない (find_text の 4 条件と同じ考え方)。
                if not self._tim_looks_real(info):
                    continue
                # image_data_offset は found からの相対。TIM 1 個ぶんの長さ。
                size = info["image_data_offset"] + info["row_bytes"] * info["height"]
                if found + size > last:
                    continue                       # 途中で切れている = たぶんゴミ
                total += 1
                if len(items) < lim:
                    items.append({
                        "address": "0x{0:08x}".format(bstart + found),
                        "block": blk.get("name"),
                        "bpp": info["bpp"],
                        "size": [info["width"], info["height"]],
                        "clut_count": info["clut_count"],
                        "bytes": size,
                        "vram": {"x": info["image_x"], "y": info["image_y"]},
                    })
                pos = found + size

        result = {
            "start": start,
            "end": end,
            "scanned_blocks": scanned,
            "total": total,
            "returned": len(items),
            "limit": lim,
            "items": items,
            "note": ("ヘッダが読めて宣言サイズが範囲に収まるものだけを出しています。"
                     "見つけた address をそのまま render_tim に渡せます。"
                     "**CD 内のファイルを見るなら、先に overlays に登録するか "
                     "source_path で直接読んでください** "
                     "(この走査は export 済みブロックとオーバーレイだけを見ます)。"),
        }
        self._mark_overlays_scanned(result, _scannable(blocks))
        if not total:
            result["hint"] = {
                "message": "0 件でした。TIM が無いとは限りません。",
                "blind_spots": [
                    "圧縮されて入っている (decompress で展開してから探す)。",
                    "TIM ではなく独自形式 (classify_range / render_tiles で当てる)。",
                    "CD 内の別ファイルにある (overlays に登録するか source_path で読む)。",
                ],
                "next_steps": [
                    "find_compressed_blocks で圧縮ブロックを探す。",
                    "render_tiles を bpp=4 / 8 で試して、生のタイルかを見る。",
                ],
            }
        return result

    @staticmethod
    def _blit_tile(px, raw, offset, depth, x0, y0, palette, width, height):
        """1 枚の 8x8 タイルを描き込みます。"""
        limit = len(palette) - 1
        for row in range(8):
            for col in range(8):
                if depth == 4:
                    byte_i = offset + row * 4 + col // 2
                    if byte_i >= len(raw):
                        return
                    b = raw[byte_i]
                    # 4bpp は 1 バイトに 2 ピクセル。**下位ニブルが左**。
                    value = (b & 0xF) if col % 2 == 0 else (b >> 4)
                else:
                    byte_i = offset + row * 8 + col
                    if byte_i >= len(raw):
                        return
                    value = raw[byte_i]
                x, y = x0 + col, y0 + row
                if 0 <= x < width and 0 <= y < height:
                    px[x, y] = palette[min(value, limit)]

    def _label_summary(self):
        """get_export_status 用に、ラベルと定義済みデータの件数をまとめます。"""
        raw = self._safe(lambda: self._load("labels.json"), None)
        data = self._safe(lambda: self._load("defined_data.json"), None)
        if raw is None and data is None:
            return {"available": False,
                    "note": "labels.json / defined_data.json がありません。"
                            "Ghidra GUI で export_context.py を再実行すると、"
                            "その番地に付いた名前と人間が定義した型が見えるように"
                            "なります (古い export には無い工程です)。"}
        index = self._symbol_index()
        by_source = {}
        for row in _rows(raw, "labels"):
            key = (row or {}).get("source") or "unknown"
            by_source[key] = by_source.get(key, 0) + 1
        return {
            "available": True,
            "labels": len(index["labels"]),
            "labels_by_source": by_source,
            "defined_data": len(index["typed"]),
            "truncated": bool((isinstance(raw, dict) and raw.get("truncated"))
                              or (isinstance(data, dict) and data.get("truncated"))),
        }

    # --- 実行ファイルからの供給 (memory 未 export のときのフォールバック) ---
    def _executable_path(self):
        """program.json / bridge_config から実行ファイルの実体パスを探します。

        Ghidra の `executable_path` は `/H:/...` のような形で入っているので
        直してから試します。無ければ bridge_config の `roots.materials` や
        `paths.rom_dir` の下も探します。

        ★**どの候補も、許可ルート (`_source_roots()` = extracted/・dumps/・
          bridge_config.json の source_roots) の配下でなければ開きません。**
          program.json は export 情報なので、そこに書かれた場所 (やその親フォルダ)
          を自動で許可しません。UNC / デバイスパスは触る前に文字列で拒否し、
          相対パスはプロジェクトフォルダ基準で解きます (起動時のカレントに依存しない)。
          候補ごとの不採用理由は `self._exe_rejected` に残します
          (許可ルート外の候補は**存在も確かめていません**)。
        """
        info = self._safe(lambda: self._load("program.json"), {}) or {}
        texts = []
        raw = info.get("executable_path")
        if isinstance(raw, str) and raw:
            text = raw.replace("\\", "/")
            if re.match(r"^/[A-Za-z]:/", text):
                text = text[1:]              # "/H:/..." -> "H:/..."
            texts.append(("program.json の executable_path", text))
        name = info.get("program_name") or self._safe(
            lambda: self._bridge_config().get("main_executable"), None)
        if isinstance(name, str) and name:
            cfg = self._safe(lambda: self._bridge_config(), {}) or {}
            roots = [("bridge_config の paths.rom_dir", (cfg.get("paths") or {}).get("rom_dir")),
                     ("bridge_config の roots.materials", (cfg.get("roots") or {}).get("materials")),
                     ("bridge_config の paths.materials_dir",
                      (cfg.get("paths") or {}).get("materials_dir"))]
            for what, root in roots:
                if isinstance(root, str) and root:
                    texts.append((what, str(Path(root) / name)))
                    texts.append((what, str(Path(root) / "ROM" / name)))
        rejected = []
        for what, text in texts:
            try:
                real = self._resolve_allowed_file(text, what)
            except ValueError as exc:
                rejected.append({"candidate": what, "why": str(exc)})
                continue
            try:
                if real.is_file():
                    self._exe_rejected = rejected
                    return real
            except OSError:
                pass
            rejected.append({"candidate": what,
                             "why": "許可ルートの中に該当するファイルがありません。"})
        self._exe_rejected = rejected
        return None

    def _executable_image(self):
        """実行ファイルを ExecutableImage として返します (無ければ None)。

        結果は program.json / bridge_config.json が変わるまでキャッシュします
        (source_roots を書き足したら、再起動しなくても次の呼び出しで読み直す)。
        """
        key = (self._safe(lambda: (self.exports_dir / "program.json").stat().st_mtime, None),
               self._safe(lambda: (self.project_root / "bridge_config.json").stat().st_mtime,
                          None))
        if self._exe_image is not False and getattr(self, "_exe_image_key", None) == key:
            return self._exe_image
        self._exe_image_key = key
        path = self._executable_path()
        if path is None:
            self._exe_image = None
            return None
        info = self._safe(lambda: self._load("program.json"), {}) or {}
        # ★平置き (ELF でない raw binary / ROM) のときの載せ位置。
        #   image_base は 0 のままのことがあるので、実際に使われている
        #   最小アドレスを優先します (メモリダンプは RAM の先頭番地に載せることが多い)。
        base = try_parse_hex(info.get("min_address") or "")
        if base is None:
            base = try_parse_hex(info.get("image_base") or "")
        try:
            self._exe_image = ExecutableImage(path, base)
        except Exception as exc:          # 大きすぎる / 読めない
            self._exe_rejected = list(getattr(self, "_exe_rejected", []) or []) + [
                {"candidate": path.name, "why": str(exc)}]
            self._exe_image = None
        return self._exe_image

    def _executable_memory_map(self):
        """program.json + 実行ファイルから memory_map 相当を組み立てます。

        ★これが無いと `export_memory: false` の Program では逆アセンブル系が
          **1 つも使えません**。実行ファイルが手元にあるなら、そこから読めば
          再 export を待たずに同じことができます。
        """
        image = self._executable_image()
        if image is None:
            return None
        info = self._safe(lambda: self._load("program.json"), {}) or {}
        raw_blocks = info.get("memory_blocks")
        if not isinstance(raw_blocks, list) or not raw_blocks:
            return None

        blocks = []
        skipped = []
        for b in raw_blocks:
            if not isinstance(b, dict):
                continue
            start = try_parse_hex(b.get("start") or "")
            end = try_parse_hex(b.get("end") or "")
            if start is None or end is None or end < start:
                continue
            name = b.get("name")
            if not b.get("initialized"):
                # .bss / .sbss は実行時に 0 で埋まる領域で、ファイルには無い。
                skipped.append({"name": name, "why": "未初期化 (ファイルに実体が無い)"})
                continue
            seg = image.locate(start)
            if seg is None:
                skipped.append({"name": name,
                                "why": "実行ファイルのどのセグメントにも載っていない"})
                continue
            vaddr, offset, filesz = seg
            avail = filesz - (start - vaddr)
            length = min(end - start + 1, avail)
            if length <= 0:
                skipped.append({"name": name, "why": "ファイル側の実体が 0 バイト"})
                continue
            blocks.append({
                "name": name,
                "start": "0x{0:08x}".format(start),
                "end": "0x{0:08x}".format(start + length - 1),
                "length": length,
                "exported": True,
                "file": None,
                "source": "executable",
                "exe_offset": offset + (start - vaddr),
                "execute": bool(b.get("execute")),
                "read": bool(b.get("read", True)),
                "write": bool(b.get("write")),
                "initialized": True,
                "truncated_from": (None if length == end - start + 1
                                   else "0x{0:08x}".format(end)),
            })
        if not blocks:
            return None
        return {
            "endian": ("big" if "BE" in (info.get("language_id") or "")
                       else "little"),
            "language_id": info.get("language_id"),
            "processor": (info.get("language_id") or "").split(":")[0] or None,
            "blocks": blocks,
            "source": "executable",
            "executable": str(image.path),
            "executable_kind": image.kind,
            "skipped": skipped,
            "note": ("memory_map.json が無いので、**実行ファイルから直接**"
                     "バイトを供給しています ({0})。"
                     "未初期化ブロック (.bss 等) はファイルに実体が無いので"
                     "読めません。実行時に書き換わる値を見たいときは "
                     'bridge_config.json に "export_memory": true を入れて'
                     "再 export するか、RAM ダンプを使ってください。".format(image.kind)),
        }

    # --- 定数プール (DAT_xxxxxxxx) の解決 --------------------------------
    def _pool_word(self, addr, blocks=None):
        """その番地の 32bit 値を返します (読めなければ None)。"""
        if blocks is None:
            _mm, blocks = self._exported_blocks()
        block = self._find_block(addr, blocks)
        if block is None or not _has_bytes(block):
            return None
        start, end = self._block_range(block)
        if addr + 4 > end + 1:
            return None
        try:
            raw = self._read_memory(block, addr - start, 4)
        except Exception:
            return None
        mm, _ = self._exported_blocks()
        order = "big" if mm.get("endian") == "big" else "little"
        return int.from_bytes(bytes(raw), order)

    def _all_blocks(self):
        """memory_map.json の**全**ブロックを返します (未 export も含む)。

        ★`_exported_blocks` は .bin を出したものだけです。プールの指す先は
          WRAM / VRAM / IO のことが多く、そこは export されません。
          「範囲外」と「export していないだけ」を混同しないための区別です。
        """
        mm = self._memory_map()
        blocks = mm.get("blocks") if isinstance(mm, dict) else None
        return [b for b in (blocks or []) if isinstance(b, dict)]

    def _pool_entry(self, addr, blocks, peek_bytes=16):
        """プール 1 語ぶんの情報 (値 / 指す先 / 覗き見 / 弱い所見) を作ります。"""
        value = self._pool_word(addr, blocks)
        entry = {
            "name": "DAT_{0:08x}".format(addr),
            "address": "0x{0:08x}".format(addr),
            "value": None if value is None else "0x{0:08x}".format(value),
            "points_to": None,
            "peek": None,
            "note": None,
        }
        if value is None:
            entry["note"] = "この番地は export された memory ブロックの外です。"
            return entry
        # 名前は全ブロックから引く (WRAM 等は export されないが番地としては有効)。
        named = self._find_block(value, self._safe(lambda: self._all_blocks(), []))
        entry["points_to"] = named.get("name") if named else "範囲外"
        target = self._find_block(value, blocks)
        if target is None or not _has_bytes(target):
            if named is not None and not _has_bytes(named):
                entry["note"] = ("{0} は export されていないので中身は見られません "
                                 "(実行時にだけ値が入る領域です)。".format(
                                     named.get("name")))
            return entry
        start, end = self._block_range(target)
        span = min(int(peek_bytes), end - value + 1)
        if span <= 0:
            return entry
        try:
            raw = bytes(self._read_memory(target, value - start, span))
        except Exception:
            return entry
        entry["peek"] = raw.hex(" ")
        entry["note"] = self._pool_note(raw, value, blocks)
        return entry

    def _pool_note(self, raw, value, blocks):
        """覗いた中身から**弱い**所見を返します。断定はしません。

        ★ここで断定しないこと。「〜らしい」で止めるのは、外したときに
          その後の解析を丸ごと誤らせるからです。判断材料を出すだけにします。
        """
        notes = []
        if len(raw) >= 8:
            words = [int.from_bytes(raw[i:i + 4], "little")
                     for i in range(0, len(raw) - 3, 4)]
            inside = sum(1 for w in words
                         if self._find_block(w, blocks) is not None)
            if words and inside == len(words):
                notes.append("4 バイト境界に有効な番地が連続 → "
                             "ポインタ表の可能性 (find_pointer_tables で確認)")
        if raw and raw[0] in (0x10, 0x24, 0x28, 0x30) and len(raw) >= 4:
            size = int.from_bytes(raw[1:4], "little")
            if size:
                notes.append("先頭が BIOS 圧縮ヘッダらしい "
                             "(0x{0:02X}, 展開後 {1} バイト?) → decompress で確認".format(
                                 raw[0], size))
        if len(raw) >= 16 and all(b & 0x80 == 0 for b in raw[1::2]):
            notes.append("上位ビットが立たない 16bit の並び → "
                         "BGR555 パレットの可能性 (render_tiles の palette_address)")
        return " / ".join(notes) if notes else None

    @staticmethod
    def _dat_names(text):
        """疑似 C 本文に出てくる DAT_xxxxxxxx を出現順に返します。"""
        seen = []
        # findall はキャプチャ (16 進部分だけ) を返すので、名前に組み立て直す。
        for hex_part in _DAT_RE.findall(text):
            name = "DAT_{0}".format(hex_part.lower())
            if name not in seen:
                seen.append(name)
        return seen

    def _pool_for_text(self, text, blocks, limit=64):
        """疑似 C に出てくる DAT_ を全部引いて一覧にします。"""
        names = self._dat_names(text)
        out = []
        for name in names[:limit]:
            out.append(self._pool_entry(int(name[4:], 16), blocks))
        return out, len(names)

    def resolve_pool(self, address, count=1):
        """定数プール (`DAT_xxxxxxxx`) の中身を読んで、何を指しているか返します。

        Thumb は 32bit 即値を命令に持てないので、**アドレスは必ず定数プール経由**に
        なります。そのため疑似 C は `DAT_0803e1fc` のような名前だらけになり、
        中身を引かないと 1 行も読めません。毎回 ROM から手で引くのをやめるための道具です。

        `address` は `0x0803e1fc` でも **`DAT_0803e1fc` という名前でも受けます**。

        - `value` … その番地にある 32bit 値
        - `points_to` … その値が入る memory ブロック名 (rom / wram / …)
        - `peek` … ROM を指しているときだけ、先頭 16 バイト
        - `note` … 「ポインタ表らしい」「圧縮ヘッダらしい」程度の**弱い所見**。
          **断定はしません** (外すと以降の解析を丸ごと誤らせるため)
        """
        addr = _parse_dat_address(address)
        n = max(1, min(int(count or 1), 256))
        _mm, blocks = self._exported_blocks()
        items = [self._pool_entry(addr + i * 4, blocks) for i in range(n)]
        return {
            "address": "0x{0:08x}".format(addr),
            "count": n,
            "pool": items,
            "note": ("note は弱い所見です。断定していないので、"
                     "ポインタ表なら find_pointer_tables、圧縮なら decompress、"
                     "パレットなら render_tiles で必ず裏を取ってください。"),
        }

    # --- ツール: find_struct_field_uses ----------------------------------
    def find_struct_field_uses(self, base, stride, offset=None, limit=50,
                               context=2, max_files=None):
        """構造体の**どのオフセットがどこから触られているか**を疑似 C から探します。

        表の各オフセットが何の数値なのかを突き止めるのが、データ構造解析で
        いちばん時間を食う作業です。手掛かりになるのは疑似 C への grep です:

            grep -rn "0x70 + [A-Za-z_0-9]* + 0x25" decompile/*.c
            → +0x25 を読んでいる式を見れば、そのフィールドの意味が分かる

        これを道具にしたものです。**`offset` を省略したときが本命**で、
        「どのオフセットが何回、どの関数から触られているか」の一覧を返します。
        `untouched_offsets` (誰も触っていない穴) も出るので、
        レコード長の推定が合っているかの検算にもなります。

        ★**取りこぼす形** (疑似 C は同じアクセスを何通りにも書きます):

            (a) *(byte *)(i * 0x70 + DAT_x + 0x25)      ベースが DAT_ のまま
            (b) iVar2 = DAT_x; ... *(byte *)(i * 0x70 + iVar2 + 0x25)   ★最頻出
            (c) iVar3 = i * 0x70 + DAT_x; ... *(byte *)(iVar3 + 0x25)
            (d) iVar5 = DAT_x + 0x25; ... *(byte *)(i * 0x70 + iVar5)

        (a)〜(d) は拾います。**拾わないのは**「ベースを関数の引数で受け渡す形」
        「ポインタ演算で 1 レコードずつ進める形 (`p = p + 0x70`)」
        「別関数へベースを渡してその中で参照する形」です。
        `unmatched_hints` に「stride は合うがベースを特定できなかった行」を
        入れるので、**黙って落としていないか必ず見てください**。
        """
        if isinstance(base, str) and base.strip().startswith("@"):
            # record_formats の「項目ごとの配列」(layout=soa)。疑似 C ではなく
            # 逆アセンブルから数える (65816 の疑似 C は in_DP 等で読めないため)。
            return self._struct_field_uses_soa(base, offset, limit)
        if stride is None:
            raise ValueError("stride を指定してください (base が '@配列名' のときだけ省略できます)。")
        base_i = parse_hex(base)
        step = int(stride)
        if step <= 0:
            raise ValueError("stride は 1 以上にしてください。")
        want = None if offset is None else _parse_int(offset, "offset")
        lim = clamp_limit(limit)
        ctx = max(0, min(int(context), 12))

        files = self._decompile_files()
        if not files:
            raise ValueError(
                "decompile/ に疑似 C がありません。bridge_config.json に "
                '"export_decompile": true を入れて Ghidra GUI で '
                "export_context.py を再実行してください "
                "(このツールは疑似 C を読むので、逆アセンブルだけでは動きません)。")
        _mm, blocks = self._exported_blocks()

        fields = {}
        items = []
        unmatched = []
        scanned = 0
        limited = 0 if max_files is None else max(1, int(max_files))
        for path in files:
            if limited and scanned >= limited:
                break
            try:
                text = _read_text_capped(path, MAX_DECOMPILE_TEXT_BYTES, path.name)
            except (OSError, ValueError):
                continue
            if "DAT_" not in text and "0x{0:x}".format(step) not in text:
                continue
            scanned += 1
            hits, misses = self._scan_struct_file(
                path, text, base_i, step, blocks, ctx)
            unmatched.extend(misses)
            for hit in hits:
                key = hit["offset_value"]
                slot = fields.setdefault(key, {
                    "offset": "+0x{0:x}".format(key),
                    "size_hint": hit["size_hint"],
                    "read_sites": 0, "write_sites": 0, "functions": [],
                })
                slot["read_sites" if hit["kind"] == "read" else "write_sites"] += 1
                fn = hit["function"]
                if fn not in slot["functions"]:
                    slot["functions"].append(fn)
                # 幅は「大きい方」を採る (同じ番地を byte でも読む書き方があるため)
                if _SIZE_ORDER.get(hit["size_hint"], 0) > \
                        _SIZE_ORDER.get(slot["size_hint"], 0):
                    slot["size_hint"] = hit["size_hint"]
                if want is not None and key == want:
                    items.append({k: v for k, v in hit.items()
                                  if k != "offset_value"})

        common = {
            "base": "0x{0:08x}".format(base_i),
            "stride": step,
            "files_scanned": scanned,
            "unmatched_hints": unmatched[:20],
            "unmatched_total": len(unmatched),
        }
        if want is not None:
            common.update({
                "offset": "+0x{0:x}".format(want),
                "total": len(items),
                "returned": min(len(items), lim),
                "items": items[:lim],
            })
            if not items:
                common["hint"] = _struct_zero_hint(step)
            return common

        ordered = [fields[k] for k in sorted(fields)]
        touched = set(fields)
        untouched_list = ["+0x{0:x}".format(o) for o in range(step)
                          if o not in touched]
        common.update({
            "fields": ordered[:lim],
            "field_count": len(ordered),
            # ★ここを黙って切らないこと。切ると「誰も触っていないオフセット」の
            #   一覧が尻切れになり、**触られているのに一覧に無い**ように見えます。
            #   切るなら必ず件数を出す。
            "untouched_offsets": untouched_list[:MAX_UNTOUCHED],
            "untouched_total": len(untouched_list),
            "note": ("**offset を指定すると、その 1 フィールドの使用箇所と前後の"
                     "コード片が出ます。** untouched_offsets は「誰も触っていない"
                     "オフセット」で、レコード長 (stride) の推定が合っているかの"
                     "検算に使えます (穴だらけなら stride が違うかもしれません)。"
                     "**unmatched_total を必ず見てください** — stride は合うのに"
                     "ベースを特定できなかった行の数です。"
                     "untouched_offsets が untouched_total より少ないときは"
                     "表示だけを切っています (件数は untouched_total が正)。"),
        })
        if not ordered:
            common["hint"] = _struct_zero_hint(step)
        return common

    def _decompile_files(self):
        """decompile/*.c の一覧を返します (無ければ空)。"""
        if not self.decompile_dir.is_dir():
            return []
        try:
            base = self._trusted_dir(self.decompile_dir, "ghidra_exports/decompile/")
        except ValueError:
            return []
        out = []
        for path in sorted(self.decompile_dir.glob("*" + DECOMPILE_EXT)):
            try:
                real = path.resolve()
            except (OSError, RuntimeError):
                continue
            if real.parent == base:          # 個別ファイルのリンクで外へは出さない
                out.append(real)
        return out

    def _scan_struct_file(self, path, text, base_i, step, blocks, ctx):
        """1 ファイルぶん走査して (見つけたアクセス, 拾えなかった手掛かり) を返します。"""
        lines = text.splitlines()
        joined, line_of = _join_wrapped(lines)

        # (1) この関数の DAT_ を引いて、値が base と一致するものを集める。
        base_syms = set()
        for name in self._dat_names(text):
            value = self._pool_word(int(name[4:], 16), blocks)
            if value == base_i:
                base_syms.add(name)
        if not base_syms:
            return [], []

        # (2) ベースを持つ変数を集める。**単純な前方参照だけ** (SSA はやらない)。
        #     base_vars   … ベースそのもの (+K) を持つ変数   → i*stride + var + off
        #     record_vars … ベース + stride*i (+K) を持つ変数 → var + off
        base_vars, record_vars, advance = _base_var_tracker(base_syms, step)

        # ファイル名は "<関数名>_<エントリ16進>.c"。関数名自体に _0 が入るので
        # split("_0") では切れない (FUN_080628b8 が "FUN" になる)。
        m = re.match(r"^(.*)_[0-9a-fA-F]{6,8}$", path.stem)
        func = m.group(1) if m else path.stem
        hits = []
        misses = []
        for idx, chunk in enumerate(joined):
            # ★アクセスを先に拾い、そのあとで代入を反映します。同じ行で
            #   「古い値を使って新しい値を代入する」形 (Ghidra が普通に出す)
            #   を正しく扱うためです。
            matched = _match_field_access(chunk, base_syms, base_vars,
                                          record_vars, step)
            for hit in matched:
                line_no = line_of[idx]
                hits.append({
                    "function": func,
                    "file": path.name,
                    "line": line_no,
                    "kind": hit["kind"],
                    "size_hint": hit["size_hint"],
                    "offset_value": hit["offset"],
                    "expr": hit["expr"],
                    "context": _context_lines(lines, line_no - 1, ctx),
                })
            if not matched:
                miss = _unmatched_hint(chunk, step, base_syms, base_vars,
                                       record_vars)
                if miss:
                    misses.append({"file": path.name, "line": line_of[idx],
                                   "text": miss})
            advance(chunk)
        return hits, misses

    # --- ツール: find_pointers_to ----------------------------------------
    def find_pointers_to(self, address, range_end=None, alignment=4,
                         blocks=None, limit=100):
        """その番地を指している **データ中の生の 32bit ポインタ**を探します。

        `find_address_refs` との違いを必ず意識してください:

        | | 拾うもの |
        |---|---|
        | `find_address_refs` | **コード**からの参照 (Thumb の定数プール, MIPS の lui/addiu) |
        | `find_pointers_to` | **データ**中の生の 32bit ポインタ |

        ★**これは「無い」と言うための道具でもあります。** GBA のリソースは
          データ表から参照されることが圧倒的に多く、コード参照だけを見ると
          「どこからも参照されない没データ」と誤って結論しがちです
          (アニメ記述子などのデータから参照されている)。

        表の途中を指す参照を取りこぼさないよう、`range_end` で範囲指定できます。
        """
        lo = parse_hex(address)
        hi = parse_hex(range_end) if range_end else lo
        if hi < lo:
            raise ValueError("range_end が address より小さいです。")
        step = max(1, int(alignment))
        lim = clamp_limit(limit)
        _mm, all_blocks = self._exported_blocks()
        want = {(b or "").strip() for b in (blocks or [])} - {""}
        scan = [b for b in (all_blocks if want else _scannable(all_blocks))
                if not want or (b.get("name") or "") in want]
        if not scan:
            raise ValueError(
                "指定したブロックが export されていません。使えるのは {0} です。".format(
                    ", ".join(str(b.get("name")) for b in all_blocks)))

        order = "big" if _mm.get("endian") == "big" else "little"
        items = []
        total = 0
        scanned = []
        for blk in scan:
            bstart, bend = self._block_range(blk)
            data = self._image_bytes(blk)
            n = len(data)
            scanned.append({"block": blk.get("name"),
                            "start": "0x{0:08x}".format(bstart),
                            "end": "0x{0:08x}".format(bstart + n - 1),
                            "step": step})
            for off in range(0, n - 3, step):
                value = int.from_bytes(bytes(data[off:off + 4]), order)
                if not (lo <= value <= hi):
                    continue
                total += 1
                if len(items) >= lim:
                    continue
                at = bstart + off
                items.append({
                    "at": "0x{0:08x}".format(at),
                    "block": blk.get("name"),
                    "value": "0x{0:08x}".format(value),
                    "container_hint": self._container_hint(
                        data, bstart, off, order, n),
                })

        result = {
            "address": "0x{0:08x}".format(lo),
            "range_end": "0x{0:08x}".format(hi) if range_end else None,
            "alignment": step,
            "scanned": scanned,
            "total": total,
            "returned": len(items),
            "limit": lim,
            "items": items,
            "note": ("**データ中の生ポインタだけ**を見ています。コードからの参照は "
                     "find_address_refs です (Thumb の定数プールはそちら)。"
                     "container_hint は「同じ間隔で有効な番地が並んでいるか」から出した"
                     "**推定**です。断定せず、find_pointer_tables で裏を取ってください。"
                     "scanned に走査した範囲と刻みを出しているので、"
                     "**「見つからなかった」と「探していない」を区別できます**。"),
        }
        self._mark_overlays_scanned(result, scan)
        if not total:
            result["hint"] = {
                "message": "0 件でした。**「どこからも参照されていない」と結論する前に**"
                           "下を疑ってください。",
                "blind_spots": [
                    "ベース + オフセットで引かれている "
                    "(表の先頭だけがポインタで、目的の番地は実行時に足される)。"
                    " → range_end を広げて、表の先頭を含む範囲で探し直す。",
                    "圧縮データの中に埋まっている "
                    "(decompress してから、その中を探す必要がある)。",
                    "16bit の相対値やインデックスで参照されている "
                    "(32bit の生ポインタではない)。",
                    "コードからだけ参照されている → find_address_refs を使う。",
                    "そのブロックが export されていない "
                    "(scanned に出ている範囲だけを見ています)。",
                ],
                "next_steps": [
                    "range_end を付けて範囲で探す (表の途中を指す参照も拾える)。",
                    "alignment=1 で境界に揃っていない参照も探す。",
                    "find_address_refs でコードからの参照を確認する。",
                ],
            }
        return result

    @staticmethod
    def _container_hint(data, bstart, off, order, size):
        """ヒットした番地が「等間隔の表の中」かどうかの**推定**を返します。

        同じ間隔で有効そうな番地が並んでいれば、表の中である可能性が高い、
        という程度の弱い判定です。**断定はしません。**
        """
        for stride in (4, 8, 0xC, 0x10, 0x14, 0x18, 0x1C, 0x20, 0x24, 0x28,
                       0x2C, 0x38, 0x40, 0x70, 0x94):
            run = 0
            first = off
            for k in range(1, 9):
                back = off - k * stride
                if back < 0:
                    break
                value = int.from_bytes(bytes(data[back:back + 4]), order)
                if not (0x08000000 <= value <= 0x0A000000
                        or 0x02000000 <= value <= 0x03008000):
                    break
                run += 1
                first = back
            forward = 0
            for k in range(1, 9):
                ahead = off + k * stride
                if ahead + 4 > size:
                    break
                value = int.from_bytes(bytes(data[ahead:ahead + 4]), order)
                if not (0x08000000 <= value <= 0x0A000000
                        or 0x02000000 <= value <= 0x03008000):
                    break
                forward += 1
            if run + forward >= 3:
                return ("0x{0:08x} + 0x{1:x}*{2} (ストライド 0x{1:x} の表の中?"
                        " 前後に {3} 件の並びあり)。**推定です** — "
                        "find_pointer_tables で確かめてください。".format(
                            bstart + first, stride, run, run + forward + 1))
        return None

    # --- ツール: find_undefined_targets ----------------------------------
    def find_undefined_targets(self, table_address=None, stride=4, count=None,
                               addresses=None, source="table",
                               executable_only=True, limit=DEFAULT_LIMIT,
                               as_proposal=False):
        """**参照されているのに関数化されていない**入口を洗い出します。

        `list_undefined_ranges` は「未定義**領域**」で、
        こちらは「参照されている未定義な**関数入口**」です。的が違います。
        関数ポインタ表を渡すと、その飛び先のうち Ghidra が関数にしていない
        ものだけが残るので、そのまま `apply_functions.py` に流せます。

        表の飛び先の一部が未関数化で疑似 C が出ていない、というのはよくあります。
        それを手で突き合わせる作業を道具にしたものです。

        - `source="table"` … `table_address` から `stride` 間隔で `count` 件読む
          (`count` 省略時は「表の外を指すまで」= 終端で止める)
        - `source="xrefs"` … `xrefs.json` の参照先を全部見る
        - `addresses` … 番地の配列を直接渡す
        - `as_proposal=true` … `proposals/proposed_functions.json` の形で返す
          (**保存も反映も人間が行います。** MCP は書きません)

        ★**「未関数化 = 関数である」ではありません。** データを指している
          エントリも混ざります。`looks_like_code` と `prologue` を見て、
          コードでないものは外してから apply してください。
        """
        kind = (source or "table").strip().lower()
        targets = []
        scanned = {}
        if addresses:
            targets = [parse_hex(a) for a in addresses]
            scanned = {"source": "addresses", "count": len(targets)}
        elif kind == "xrefs":
            seen = []
            for row in (self._safe(lambda: self._load("xrefs.json"), []) or []):
                a = try_parse_hex((row or {}).get("to") or (row or {}).get("to_address") or "")
                if a is not None:
                    seen.append(a)
            targets = sorted(set(seen))
            scanned = {"source": "xrefs.json", "count": len(targets)}
        elif kind == "table":
            if not table_address:
                raise ValueError(
                    "table_address を指定してください "
                    "(source='xrefs' か addresses を使う手もあります)。")
            targets, scanned = self._read_table_targets(
                parse_hex(table_address), int(stride), count)
        else:
            raise ValueError(
                "source は table / xrefs のいずれかです (指定: {0})。".format(source))

        index = self._symbol_index()
        _mm, blocks = self._exported_blocks()
        starts = index["body_starts"]
        bodies = index["bodies"]

        defined = 0
        outside = 0
        items = []
        seen = set()
        for addr in targets:
            if addr in seen:
                continue
            seen.add(addr)
            pos = bisect.bisect_right(starts, addr) - 1
            covered = (pos >= 0 and bodies[pos][0] <= addr <= bodies[pos][1])
            if covered:
                defined += 1
                continue
            block = self._find_block(addr, blocks)
            if block is None or (executable_only and not block.get("execute")):
                outside += 1
                continue
            items.append(self._undefined_target_row(addr, block, index))

        lim = clamp_limit(limit)
        page = items[:lim]
        result = {
            "scanned": scanned,
            "candidates": len(targets),
            "already_defined": defined,
            "outside_code": outside,
            "undefined": len(items),
            "returned": len(page),
            "limit": lim,
            "targets": page,
            "note": ("**参照されているのに関数化されていない入口**だけを返しています "
                     "(list_undefined_ranges の「未定義領域」とは別物です)。"
                     "already_defined は既に関数の body に入っていたもの、"
                     "outside_code は実行属性のブロック外だったものです "
                     "(executable_only=false で後者も出せます)。"
                     "★**looks_like_code が false のものは関数ではありません。**"
                     "データを指すエントリが混ざるので、apply する前に必ず見てください。"),
        }
        if as_proposal:
            result["proposal"] = self._function_proposal(page)
        return result

    def _read_table_targets(self, table, stride, count):
        """ポインタ表から飛び先を読みます (count 省略時は終端まで)。"""
        _mm, blocks = self._exported_blocks()
        block = self._find_block(table, blocks)
        if block is None:
            raise ValueError(
                "表のアドレス 0x{0:08x} を含むブロックがありません。".format(table))
        step = max(4, int(stride))
        want = int(count) if count else 4096
        order = "big" if _mm.get("endian") == "big" else "little"
        start, end = self._block_range(block)
        out = []
        stopped = "count に達しました"
        for n in range(want):
            at = table + n * step
            if at + 4 > end + 1:
                stopped = "ブロックの終わりに達しました"
                break
            value = int.from_bytes(
                bytes(self._read_memory(block, at - start, 4)), order)
            if not count:
                # 件数を渡されていないので、表の外を指したら終わりとみなす。
                if value == 0 or self._find_block(value, blocks) is None:
                    stopped = ("0x{0:08x} で表の外 (0x{1:08x}) を指したので"
                               "そこで止めました".format(at, value))
                    break
            out.append(value)
        return out, {"source": "table", "table": "0x{0:08x}".format(table),
                     "stride": "0x{0:x}".format(step), "read": len(out),
                     "stopped": stopped}

    def _undefined_target_row(self, addr, block, index):
        """未関数化の飛び先 1 件を、コードらしさの判定つきで返します。"""
        row = {
            "address": "0x{0:08x}".format(addr),
            "block": block.get("name"),
            "label": index["labels"].get(addr),
        }
        pos = bisect.bisect_right(index["body_starts"], addr) - 1
        if pos >= 0:
            bstart, bend, bname = index["bodies"][pos]
            row["nearest_function"] = {
                "name": bname, "start": "0x{0:08x}".format(bstart),
                "distance": addr - bend,
            }
        # 入口らしさ: プロローグが立っているか (アーキ固有の判定は disasm 側)。
        try:
            entry = self.find_function_entry(row["address"])
            # ★「入口候補が返った」だけでは駄目です。find_function_entry は
            #   コードでない番地でも「最も近い候補」を返し、balanced=False /
            #   confidence=low で知らせます。ゼロ埋めを「関数」と report して
            #   apply に流すと、データ域に関数を作ってしまいます。
            row["looks_like_code"] = bool(
                entry.get("entry") and entry.get("covers_address")
                and entry.get("balanced"))
            row["is_entry"] = bool(entry.get("is_entry"))
            row["balanced"] = entry.get("balanced")
            row["prologue"] = [p["text"] for p in (entry.get("prologue") or [])][:3]
            row["confidence"] = entry.get("confidence")
        except Exception:
            # そのアーキに入口判定が無いときは、素直に「分からない」と言う。
            row["looks_like_code"] = None
            row["confidence"] = "low"
            row["why"] = ("このアーキには関数入口の判定がありません。"
                          "get_disassembly で中身を見てから判断してください。")
        return row

    def _function_proposal(self, items):
        """`proposals/proposed_functions.json` にそのまま保存できる形を作ります。

        ★MCP は保存しません。人間が `proposals/` に置き、
          `tools/validate_proposed_functions.py` で検証してから
          Ghidra GUI で `apply_functions.py` を実行します
          (`allowed_apply_operations` に `"functions"` が必要)。
        """
        info = self._safe(lambda: self._load("program.json"), {}) or {}
        return {
            "schema_version": "1.0",
            "target_program": info.get("program_name"),
            "generated_by": "ghidra_readonly_mcp find_undefined_targets",
            "functions": [{
                "address": x["address"],
                "operation": "define_function",
                "address_basis": "ghidra",
                "confidence": x.get("confidence") or "low",
                "reason": "関数ポインタ表 / 参照から到達できるのに、"
                          "Ghidra 上でどの関数の body にも入っていません。",
                "evidence": [
                    "block={0}".format(x.get("block")),
                    "looks_like_code={0}".format(x.get("looks_like_code")),
                    "prologue={0}".format(", ".join(x.get("prologue") or []) or "不明"),
                ],
            } for x in items if x.get("looks_like_code") is not False],
            "note": "MCP はこの JSON を保存しません。proposals/ に保存し、"
                    "validate_proposed_functions.py で確認してから Ghidra GUI で "
                    "apply_functions.py を実行してください "
                    '(allowed_apply_operations に "functions" が必要)。'
                    "★looks_like_code=false のものは除いてありますが、"
                    "残ったものも必ず目で確認してください。",
        }

    # --- ツール: classify_range (未定義領域の正体当て) --------------------
    def classify_range(self, start, end=None, length=None, sample=0x800):
        """その範囲が **何なのか** を推定し、次に呼ぶべきツールまで返します。

        `list_undefined_ranges` は「未定義領域が 1,694 件あります」までしか
        言えません。どれから見るかを決めるには、結局その場で逆アセンブルしたり
        ポインタらしさを数えたりすることになります。それを道具にしたものです。

        ★**判定は推定です。** 各観点のスコアと**その根拠になった数字**を必ず
          返すので、鵜呑みにせず数字を見てください。決め手が無いときは
          「決め手なし」と返します (無理に断定しません)。

        大きい範囲は先頭 `sample` バイトだけを見ます (全部見ても結論は変わらず、
        時間だけ食うため)。
        """
        lo = parse_hex(start)
        if end is not None:
            hi = parse_hex(end)
        elif length is not None:
            hi = lo + int(length) - 1
        else:
            raise ValueError("end か length のどちらかを指定してください。")
        if hi < lo:
            raise ValueError("end が start より小さいです。")

        mm, blocks = self._exported_blocks()
        block = self._find_block(lo, blocks)
        if block is None:
            raise ValueError(
                "アドレス {0} を含む memory ブロックが export されていません。".format(start))
        bstart, bend = self._block_range(block)
        hi = min(hi, bend)
        full = hi - lo + 1
        take = min(full, max(64, int(sample)))
        data = self._read_memory(block, lo - bstart, take)
        big_endian = (mm.get("endian") == "big")

        entropy = round(bios_compress.shannon_entropy(bytes(data)), 2)

        signals = []
        signals.append(self._sig_padding(data))
        signals.append(self._sig_compressed(block, bstart, lo, bend, data))
        signals.append(self._sig_pointers(data, lo, blocks, big_endian))
        signals.append(self._sig_code(data, lo, mm, big_endian))
        signals.append(self._sig_text(data))
        signals.append(self._sig_floats(data, big_endian))
        signals = [x for x in signals if x]
        self._cross_penalties(signals, entropy)
        signals.sort(key=lambda x: -x["score"])

        best = signals[0] if signals else None
        verdict = best["kind"] if best and best["score"] >= 0.6 else None
        confidence = ("high" if best and best["score"] >= 0.85 else
                      "medium" if verdict else "low")

        note = ("各観点のスコアと根拠になった数字を出しています。"
                "**推定なので数字を見て判断してください。**")
        if verdict is None:
            note += " 決め手がありませんでした。" + _entropy_hint(entropy)
        return self._mark_overlay({
            "start": "0x{0:08x}".format(lo),
            "end": "0x{0:08x}".format(hi),
            "size": full,
            "sampled": take,
            "block": block.get("name"),
            "entropy": entropy,
            "verdict": verdict,
            "confidence": confidence,
            "signals": signals,
            "next": (best or {}).get("next") or [
                "render_tiles(address, length, bpp=4) と bpp=8 の両方で見る",
                "find_address_refs でここを指す参照を探す "
                "(参照元の処理から用途が分かることが多い)",
                "read_data で format を変えて中身を眺める",
            ],
            "note": note,
        }, block)

    @staticmethod
    def _cross_penalties(signals, entropy):
        """観点どうしの矛盾を潰します。**ここが無いと判定が使い物になりません。**

        素朴に各観点を独立に採点すると、次の 3 つで必ず外します:

          - **圧縮データが「コード」になる。** Thumb は 16bit 固定長なので、
            乱数同然のバイト列でも 88% が「読める命令」に化けます。
          - **文字列が「コード」になる。** ASCII の並びも同様に読めてしまいます。
          - **ポインタ表が「コード」になる。** アドレスの並びも命令に見えます。

        コードは entropy が 4〜5.5 に収まるのが普通なので、超えたぶんだけ
        コードらしさを下げ、文字列 / ポインタ表と両立しないことで更に下げます。
        """
        by_kind = {x["kind"]: x for x in signals}
        code = by_kind.get("code")
        if not code:
            return
        reasons = []
        if entropy > 5.5:
            factor = max(0.05, 1.0 - (entropy - 5.5) / 2.0)
            code["score"] = round(code["score"] * factor, 2)
            reasons.append(
                "エントロピー {0} はコードにしては高すぎます "
                "(圧縮 / 音声 / 画像の帯)。x{1}".format(
                    entropy, round(factor, 2)))
        elif entropy < 3.0:
            # 命令には最低限の多様性があります。ここまで低いのは、
            # ゼロ埋めか同じ値の並び (= 表か詰め物) です。
            factor = max(0.1, entropy / 3.0)
            code["score"] = round(code["score"] * factor, 2)
            reasons.append(
                "エントロピー {0} はコードにしては低すぎます "
                "(詰め物 / 同じ値の並び)。x{1}".format(
                    entropy, round(factor, 2)))
        text = by_kind.get("text")
        if text and text["evidence"].get("printable_ratio", 0) >= 0.7:
            code["score"] = round(code["score"] * 0.35, 2)
            reasons.append("可読 ASCII が大半を占めます。"
                           "文字列とコードは両立しません。x0.35")
        ptr = by_kind.get("pointer_table")
        if ptr and ptr["score"] >= 0.9:
            code["score"] = round(code["score"] * 0.4, 2)
            reasons.append("ワードのほぼ全部が有効な番地を指しています。"
                           "ポインタ表とコードは両立しません。x0.40")
        comp = by_kind.get("compressed")
        if comp and comp["evidence"].get("decompressed_ok"):
            code["score"] = round(code["score"] * 0.2, 2)
            reasons.append("実際に展開できました。圧縮データです。x0.20")
        if reasons:
            code["evidence"]["penalties"] = reasons
    @staticmethod
    def _sig_padding(data):
        """ゼロ埋め / 単一バイトの繰り返しか。"""
        if not data:
            return None
        zeros = data.count(0)
        ratio = zeros / float(len(data))
        top = max(set(data), key=data.count) if len(data) < 4096 else None
        same = data.count(top) / float(len(data)) if top is not None else ratio
        score = max(ratio, same)
        # 0.9 だと「ほぼゼロだが少し中身がある」領域を取りこぼし、
        # そちらが「コード」に化けます。閾値を下げて素点をそのまま使う。
        if score < 0.75:
            return None
        return {
            "kind": "padding",
            "label": "詰め物 (ゼロ埋め / 同じバイトの繰り返し)",
            "score": round(score, 2),
            "evidence": {"zero_ratio": round(ratio, 3),
                         "most_common_ratio": round(same, 3)},
            "next": ["ここは中身が無いので見なくてよい。"
                     "list_undefined_ranges の min_size を上げて除外する。"],
        }

    def _sig_compressed(self, block, bstart, lo, bend, data):
        """BIOS 圧縮のヘッダに見えるか。**実際に展開できるかまで確かめます。**

        ヘッダ 4 バイトが形になっているだけでは弱く、任意のバイト列が
        「それらしいヘッダ」になります。ただし展開にはサンプル範囲より多くの
        バイトが要るので、ヘッダが通ったときだけブロックから読み直します。
        """
        try:
            kind, size, head_len, extra = bios_compress.read_header(bytes(data), 0)
        except Exception:
            return None
        del head_len, extra
        # 展開に必要なぶんだけ読み直す (上限つき)。圧縮率はせいぜい 10 倍なので、
        # 展開後サイズと同じだけ読めれば、まず足ります。
        want = min(int(size) + 0x1000, bend - lo + 1, 0x200000)
        try:
            data = self._read_memory(block, lo - bstart, want)
        except Exception:
            pass
        # ★ヘッダ 4 バイトが「それらしい」だけでは弱いので、実際に展開できるかを
        #   確かめます。任意のバイト列がヘッダに見えることは普通に起きます。
        try:
            out, _info = bios_compress.decompress(bytes(data), 0, max_size=size)
            works = len(out) == size
        except Exception:
            works = False
        return {
            "kind": "compressed",
            "label": "圧縮データ ({0})".format(kind),
            "score": 0.95 if works else 0.45,
            "evidence": {"type": kind, "declared_size": size,
                         "decompressed_ok": works,
                         "why": ("先頭を実際に展開できました。" if works else
                                 "ヘッダは形になっていますが、サンプル範囲だけでは"
                                 "展開しきれませんでした (範囲が途中で切れている"
                                 "だけかもしれません)。")},
            "next": ["decompress(address) で展開する "
                     "(展開できなければヘッダの偶然一致)。",
                     "展開できたら nested を見る — 中身がさらに圧縮のことがある。"],
        }

    def _sig_pointers(self, data, addr, blocks, big_endian):
        """4 バイト境界の値が、export 済みの番地を指しているか。"""
        order = "big" if big_endian else "little"
        count = len(data) // 4
        if count < 4:
            return None
        inside = 0
        thumb = 0
        for i in range(count):
            value = int.from_bytes(bytes(data[i * 4:i * 4 + 4]), order)
            if self._find_block(value, blocks) is not None:
                inside += 1
            elif value & 1 and self._find_block(value & ~1, blocks) is not None:
                thumb += 1
        ratio = (inside + thumb) / float(count)
        if ratio < 0.5:
            return None
        return {
            "kind": "pointer_table",
            "label": "ポインタ表",
            "score": round(min(1.0, ratio), 2),
            "evidence": {"words": count, "in_image": inside,
                         "thumb_style": thumb, "ratio": round(ratio, 3)},
            "next": ["find_pointer_tables(target_lo, target_hi) で表の範囲を確定する"
                     + ("。**thumb_pointers=true を付けること** "
                        "(entry|1 の形が混ざっています)。" if thumb else "。"),
                     "read_data(format='u32', annotate=true) で指す先に何があるか見る。"],
        }

    def _sig_code_cdl(self, data, addr, arch_mod):
        """65816: 256 通りのバイト値が全部命令なので「読めた率」では判定できない。

        CDL (実行記録) が範囲の半分以上を覆うときだけコードと言います。
        CDL が無ければ判定しません (None)。
        """
        try:
            ctx = self._width_context()
        except ValueError:
            return None
        if not ctx.has_cdl or not data:
            return None
        lo, hi = addr, addr + len(data) - 1
        covered = 0
        certs = {}
        for s, e, _m, _x, cert in ctx.spans_in(lo, hi):
            n = min(e, hi) - max(s, lo) + 1
            covered += n
            certs[cert] = certs.get(cert, 0) + n
        ratio = covered / float(len(data))
        if ratio < 0.5:
            return None
        return {
            "kind": "code",
            "label": "コード ({0}, CDL)".format(arch_mod.NAME),
            "score": round(min(1.0, ratio), 2),
            "evidence": {"cdl_covered_bytes": covered, "bytes": len(data),
                         "by_certainty": certs},
            "next": ["get_disassembly(format='text') で読む (幅は CDL から取る)。"],
        }

    def _sig_code(self, data, addr, mm, big_endian):
        """命令として素直に読めるか。分岐先がイメージ内に収まるかも見る。"""
        try:
            arch_mod = disasm.resolve_arch(mm)
        except Exception:
            return None
        if getattr(arch_mod, "VARIABLE_LENGTH", False):
            return self._sig_code_cdl(data, addr, arch_mod)
        size = arch_mod.INSTRUCTION_SIZE
        count = len(data) // size
        if count < 8:
            return None
        decoded = 0
        flows = 0
        sane_targets = 0
        zero_words = 0
        real = 0
        for i in range(count):
            word = arch_mod.word_at(data, i * size, big_endian)
            if word is None:
                continue
            # ★ゼロワードを「読めた命令」に数えないこと。MIPS では nop、
            #   Thumb では `movs r0,r0` に化けるので、**ゼロ埋めの領域が
            #   decoded_ratio 1.0 のコード**に見えます。
            if word == 0:
                zero_words += 1
                continue
            real += 1
            out = arch_mod.decode(word, addr + i * size)
            if out["mnemonic"] not in (".word", ".hword", "mmi"):
                decoded += 1
            if out.get("flow"):
                flows += 1
                # decode() の target は "0x........" 文字列で返ります。
                target = try_parse_hex(out.get("target") or "")
                if target is not None and abs(target - addr) < 0x200000:
                    sane_targets += 1
        if real < 8 or zero_words > count * 0.5:
            # 中身の半分以上がゼロなら、コードではなく詰め物です。
            return None
        ratio = decoded / float(real)
        # ★「読めた命令の割合」だけでは足りません。データでも 8 割は何かの命令に
        #   化けます。**分岐が近くを指しているか**を併せて見ます。
        flow_ratio = (sane_targets / float(flows)) if flows else 0.0
        score = ratio * (0.6 + 0.4 * flow_ratio)
        if score < 0.5:
            return None
        return {
            "kind": "code",
            "label": "コード ({0})".format(arch_mod.NAME),
            "score": round(min(1.0, score), 2),
            "evidence": {"instructions": count, "zero_words": zero_words,
                         "counted": real, "decoded": decoded,
                         "decoded_ratio": round(ratio, 3),
                         "branches": flows,
                         "branch_targets_near": sane_targets,
                         "branch_sane_ratio": round(flow_ratio, 3)},
            "next": ["get_disassembly(address, format='text') で読む。",
                     "find_function_entry で入口を確かめてから関数化を検討する "
                     "(関数化は allowed_apply_operations に 'functions' が要る)。"],
        }

    @staticmethod
    def _sig_text(data):
        """NUL 終端の可読文字列がどれだけ詰まっているか (日本語も見ます)。"""
        if len(data) < 16:
            return None
        # Shift-JIS の日本語は ASCII の数え方では拾えません。find_text と同じ
        # 判定 (かな要求 / JIS 第1水準まで) を使って本物だけ数えます。
        jp = 0
        for rs, rend in _sjis_runs(data, 0, len(data), 6, False, False):
            try:
                text = bytes(data[rs:rend]).decode("shift_jis")
            except UnicodeDecodeError:
                continue
            good, _why = _text_verdict(text, 2, 1)
            if good:
                jp += 1
        printable = sum(1 for b in data if 0x20 <= b <= 0x7E)
        ratio = printable / float(len(data))
        runs = 0
        run = 0
        for b in data:
            if 0x20 <= b <= 0x7E:
                run += 1
                continue
            if b == 0 and run >= 4:
                runs += 1
            run = 0
        if ratio < 0.5 and runs < 3 and jp < 2:
            return None
        score = min(1.0, ratio * 0.7 + min(runs, 10) / 10.0 * 0.3
                    + min(jp, 5) / 5.0 * 0.6)
        if score < 0.5:
            return None
        return {
            "kind": "text",
            "label": "文字列" + (" (日本語を含む)" if jp else ""),
            "score": round(min(1.0, score), 2),
            "evidence": {"printable_ratio": round(ratio, 3),
                         "nul_terminated_runs": runs,
                         "japanese_strings": jp},
            "next": (["find_text で拾って as_proposal でラベル / コメントにする。"]
                     if jp else []) + [
                "read_data(format='cstring') で読む。",
                "日本語が出てこないなら **独自符号を疑う** — フォントを "
                "render_tiles で見て decode_text に対応表を渡す "
                "(この年代は独自符号が普通)。"],
        }

    @staticmethod
    def _sig_floats(data, big_endian):
        """32bit 浮動小数の並びに見えるか (座標 / 行列でよく出ます)。"""
        import struct
        order = ">" if big_endian else "<"
        count = len(data) // 4
        if count < 8:
            return None
        sane = 0
        for i in range(count):
            value, = struct.unpack_from(order + "f", bytes(data), i * 4)
            if value == 0.0:
                sane += 1
                continue
            av = abs(value)
            if 1e-4 < av < 1e6:
                sane += 1
        ratio = sane / float(count)
        if ratio < 0.9:
            return None
        return {
            "kind": "float_table",
            "label": "浮動小数の並び (座標 / 行列)",
            "score": round(ratio * 0.8, 2),
            "evidence": {"words": count, "plausible": sane,
                         "ratio": round(ratio, 3)},
            "next": ["read_data(format='f32', columns=3 or 4) で読む "
                     "(3 なら座標、4 なら行列の 1 行のことが多い)。",
                     "describe_data でストライドを推定する。"],
        }

    # --- ツール: list_labels ---------------------------------------------
    def list_labels(self, name_contains=None, start=None, end=None,
                    source=None, include_functions=False, with_type=True,
                    offset=0, limit=DEFAULT_LIMIT):
        """Ghidra 上でその番地に**付いている名前**を一覧します。

        ★これが無いと「人間が既に名付けたもの」が AI から見えません。
          関数名は functions.json にありますが、**データに付いたラベルは
          labels.json にしか出ません**。
          `apply_labels.py` で付けたラベルも、これが無いと次のセッションで
          見えず、同じ番地へ重複提案を出す原因になります。

        `defined_data.json` があれば、その番地の**人間が付けた型**も添えます。
        describe_data の推定より**こちらが正**です。
        """
        rows = _rows(self._safe(lambda: self._load("labels.json"), None), "labels")
        raw = self._safe(lambda: self._load("labels.json"), None)
        if not rows and not isinstance(raw, (list, dict)):
            raise ValueError(
                "labels.json がありません。Ghidra GUI で export_context.py を"
                "再実行してください (古い export には無い工程です)。"
                "bridge_config.json の export_only を使っているなら "
                '"labels" と "defined_data" を足してください。')

        lo = parse_hex(start) if start else None
        hi = parse_hex(end) if end else None
        probe = (name_contains or "").lower() or None
        want_source = (source or "").strip().upper() or None
        index = self._symbol_index()

        matched = []
        skipped = {"名前が一致しない": 0, "範囲外": 0, "source が違う": 0,
                   "関数シンボル": 0}
        for row in rows:
            name = (row or {}).get("name") or ""
            if not include_functions and row.get("type") == "Function":
                skipped["関数シンボル"] += 1
                continue
            if probe and probe not in name.lower():
                skipped["名前が一致しない"] += 1
                continue
            addr = try_parse_hex(row.get("address") or "")
            if addr is None:
                continue
            if (lo is not None and addr < lo) or (hi is not None and addr > hi):
                skipped["範囲外"] += 1
                continue
            if want_source and (row.get("source") or "").upper() != want_source:
                skipped["source が違う"] += 1
                continue
            matched.append((addr, row))

        matched.sort(key=lambda x: x[0])
        off = max(0, int(offset))
        lim = clamp_limit(limit)
        page = []
        for addr, row in matched[off:off + lim]:
            item = {
                "address": row.get("address"),
                "name": row.get("name"),
                "type": row.get("type"),
                "source": row.get("source"),
                "namespace": row.get("namespace"),
                "ref_count": row.get("ref_count"),
            }
            if with_type:
                typed = index["typed"].get(addr)
                if typed:
                    item["data_type"] = typed["type"]
                    item["data_kind"] = typed.get("kind")
                    item["elements"] = typed.get("count")
            page.append(item)

        truncated = bool(isinstance(raw, dict) and raw.get("truncated"))
        return {
            "total_labels": len(rows),
            "matched": len(matched),
            "returned": len(page),
            "offset": off,
            "limit": lim,
            "filtered_out": skipped,
            "export_truncated": truncated,
            "labels": page,
            "note": ("Ghidra が自動生成した名前 (LAB_ / DAT_ 等) は export の時点で"
                     "除いてあります。ここに出るのは**誰かが意味を与えた名前**だけです。"
                     "source=USER_DEFINED が人間 (か apply_labels.py) の付けたもの、"
                     "IMPORTED はシンボルテーブル由来、ANALYSIS は Ghidra の解析結果です。"
                     + ("★export が上限で打ち切られています。件数は実際より少ないです。"
                        if truncated else "")),
        }

    # --- 構造体・クラスのレイアウト (datatypes.json) ----------------------
    #
    # ★疑似 C には `self->resourceTable` と**名前**は出るが、**何バイト目か**は出ない。
    #   逆アセンブルの `lw a2,388(s1)` から 1 フィールドずつ拾うと、
    #   1 フィールドにつき数回のツール呼び出しが要る。
    #   export_context.py の datatypes 工程が Ghidra の型を書き出すので、それを引く。
    #   **Ghidra の型には一切触れない** (読むだけ。構造体の適用は常に禁止)。

    # flatten で入れ子を辿る深さと、返す行数の上限。
    STRUCT_FLATTEN_MAX_DEPTH = 8
    STRUCT_FLATTEN_MAX_ROWS = 2000
    # これより要素数の多いスカラ配列は 1 行にまとめる (char name[256] を 256 行にしない)。
    STRUCT_ARRAY_EXPAND = 64
    # find_field で「その型を値として持つ型 (派生クラス等)」を何段まで辿るか。
    FIELD_EMBED_DEPTH = 3
    FIELD_EMBED_MAX = 20

    _FIELD_SEG = re.compile(r"^([^\[\]\s]+)((?:\[\s*(?:0[xX][0-9a-fA-F]+|\d+)\s*\])*)$")

    def _datatypes(self):
        """datatypes.json を読み、名前 / パス / フィールド名の索引つきで返します。

        無ければ「export を再実行して」と言う ValueError です
        (他のツールは datatypes.json が無くても今まで通り動きます)。
        """
        path = self.exports_dir / "datatypes.json"
        if not path.is_file():
            raise ValueError(
                "datatypes.json がありません。Ghidra GUI で export_context.py を"
                "再実行してください (古い export には無い工程 datatypes です)。"
                "bridge_config.json の export_only を使っているなら "
                '"datatypes" を足してください。')
        mtime = path.stat().st_mtime
        if self._types is not None and self._types_mtime == mtime:
            return self._types
        raw = self._load("datatypes.json")
        by_path = {}
        for row in _rows(raw, "datatypes"):
            if isinstance(row, dict) and row.get("name"):
                by_path[row.get("path") or row["name"]] = row
        by_name = {}
        fields = {}
        embedded = {}
        for key, row in by_path.items():
            by_name.setdefault(row["name"], []).append(row)
            for f in row.get("fields") or []:
                if not isinstance(f, dict):
                    continue
                if f.get("name"):
                    fields.setdefault(f["name"], []).append((row, f))
                # 値として埋め込まれている型 (継承の基底 = 先頭の super 等)。
                if f.get("ref") and not f.get("dims"):
                    embedded.setdefault(f["ref"], []).append((row, f))
        aliases = {}
        typedefs = raw.get("typedefs") if isinstance(raw, dict) else None
        for td in typedefs or []:
            target = by_path.get((td or {}).get("target"))
            if target is not None and td.get("name"):
                aliases.setdefault(td["name"], []).append(target)
        self._types = {
            "rows": list(by_path.values()),
            "by_path": by_path,
            "by_name": by_name,
            "aliases": aliases,
            "fields": fields,
            "embedded": embedded,
            "truncated": bool(isinstance(raw, dict) and raw.get("truncated")),
        }
        self._types_mtime = mtime
        return self._types

    @staticmethod
    def _unique_rows(rows):
        """型の行を path で重複排除します (順序は保つ)。"""
        seen = set()
        out = []
        for row in rows:
            key = row.get("path") or row.get("name")
            if key in seen:
                continue
            seen.add(key)
            out.append(row)
        return out

    @staticmethod
    def _type_brief(row):
        """候補一覧用の短い要約です。"""
        size = row.get("size")
        return {
            "name": row.get("name"),
            "path": row.get("path"),
            "kind": row.get("kind"),
            "size": size,
            "size_hex": "0x{0:x}".format(size) if isinstance(size, int) else None,
            "field_count": len(row.get("fields") or []),
            "vtable": bool(row.get("vtable")),
        }

    def _match_types(self, type_name):
        """型名を 完全一致 → 大文字小文字を無視 → 部分一致 の順で探します。

        名前・パス (`/game/GmGameMgr`)・typedef の別名のどれでも引けます。
        疑似 C の表記 (`struct GmGameMgr` / `GmGameMgr *`) も受けます。
        返り値: (段階 "exact"/"ignore_case"/"partial", [行...])
        """
        types = self._datatypes()
        probe = (type_name or "").strip()
        probe = re.sub(r"^(?:struct|union|class)\s+", "", probe).rstrip(" *").strip()
        if not probe:
            raise ValueError("type_name を指定してください (例 GmGameMgr / /game/GmGameMgr)。")
        exact = []
        if probe in types["by_path"]:
            exact.append(types["by_path"][probe])
        exact += types["by_name"].get(probe, [])
        exact += types["aliases"].get(probe, [])
        exact = self._unique_rows(exact)
        if exact:
            return "exact", exact
        low = probe.lower()
        ci = [r for r in types["rows"]
              if (r.get("name") or "").lower() == low
              or (r.get("path") or "").lower() == low]
        for alias, targets in types["aliases"].items():
            if alias.lower() == low:
                ci += targets
        ci = self._unique_rows(ci)
        if ci:
            return "ignore_case", ci
        part = [r for r in types["rows"]
                if low in (r.get("path") or r.get("name") or "").lower()]
        return "partial", self._unique_rows(part)

    @staticmethod
    def _field_out(f):
        """フィールド 1 件を応答用に整えます (offset_hex を足すだけ)。"""
        out = dict(f)
        off = f.get("offset")
        if isinstance(off, int):
            out["offset_hex"] = "0x{0:x}".format(off)
        return out

    def get_struct_layout(self, type_name, flatten=False,
                          max_depth=STRUCT_FLATTEN_MAX_DEPTH,
                          limit=STRUCT_FLATTEN_MAX_ROWS):
        """構造体 / 共用体 / クラスのフィールド配置 (オフセット付き) を返します。

        flatten=True なら入れ子の構造体と配列を展開し、`xformUnit.matrix.m[3][0]`
        のような最終的なパスとオフセットで返します。候補が複数なら候補一覧です。
        """
        types = self._datatypes()
        how, rows = self._match_types(type_name)
        if not rows:
            raise ValueError(
                "'{0}' という型は datatypes.json にありません ({1} 型を検索)。"
                "フィールド名しか分からないときは find_field を使ってください。".format(
                    type_name, len(types["rows"])))
        if len(rows) > 1:
            rows = sorted(rows, key=lambda r: (r.get("name") or "", r.get("path") or ""))
            return {
                "type_name": type_name,
                "match": how,
                "ambiguous": True,
                "candidates_total": len(rows),
                "candidates": [self._type_brief(r) for r in rows[:DEFAULT_LIMIT]],
                "note": ("候補が複数あります。path (例 /game/GmGameMgr) を"
                         "type_name に渡して指定し直してください。"),
            }
        row = rows[0]
        result = self._type_brief(row)
        result["match"] = how
        for key in ("category", "packed", "description", "not_yet_defined",
                    "fields_truncated"):
            if row.get(key) is not None:
                result[key] = row[key]
        result["fields"] = [self._field_out(f) for f in row.get("fields") or []]
        outer = []
        for orow, of in types["embedded"].get(row.get("path") or row["name"], [])[:self.FIELD_EMBED_MAX]:
            outer.append({"type": orow.get("name"), "path": orow.get("path"),
                          "field": of.get("name"), "offset": of.get("offset"),
                          "offset_hex": "0x{0:x}".format(of.get("offset") or 0)})
        if outer:
            # 継承 (派生クラスの先頭に基底が入る形) を見つけやすくするため。
            result["embedded_in"] = outer
        if flatten:
            try:
                depth = max(1, min(int(max_depth), 32))
            except (TypeError, ValueError):
                depth = self.STRUCT_FLATTEN_MAX_DEPTH
            try:
                cap = max(1, min(int(limit), 20000))
            except (TypeError, ValueError):
                cap = self.STRUCT_FLATTEN_MAX_ROWS
            state = {"rows": [], "cap": cap, "depth": depth, "truncated": False,
                     "collapsed": 0}
            self._flatten_type(row, 0, "", 0, [row.get("path")], state)
            result["flat"] = state["rows"]
            result["flat_truncated"] = state["truncated"]
            result["listing"] = "\n".join(
                "+0x{0:04x}  {1:<40} {2} ({3})".format(
                    r["offset"], r["path"], r.get("type"), r.get("size"))
                for r in state["rows"])
            if state["collapsed"]:
                result["flat_note"] = (
                    "要素数が {0} を超えるスカラ配列 {1} 個は展開せず 1 行にしています "
                    "(dims と elem_size から番地を計算できます)。".format(
                        self.STRUCT_ARRAY_EXPAND, state["collapsed"]))
        if types["truncated"]:
            result["export_truncated"] = True
        result["note"] = (
            "offset は型の先頭からのバイト数です (Ghidra の型定義そのまま)。"
            "Ghidra の型が実物と合っている保証はありません — 実機のメモリで"
            "確かめてから改造コードに使ってください。"
            "基底クラスは先頭フィールド (super 等) として入っています。")
        return result

    def _flatten_emit(self, state, path, off, type_name, size, extra=None):
        """flatten の 1 行を足します (上限を超えたら truncated を立てる)。"""
        if len(state["rows"]) >= state["cap"]:
            state["truncated"] = True
            return False
        row = {"path": path, "offset": off, "offset_hex": "0x{0:x}".format(off),
               "type": type_name, "size": size}
        if extra:
            row.update(extra)
        state["rows"].append(row)
        return True

    def _flatten_type(self, row, base, prefix, depth, stack, state):
        """構造体 row の各フィールドを base からのオフセットで展開します。"""
        for f in row.get("fields") or []:
            if state["truncated"]:
                return
            if not isinstance(f, dict):
                continue
            path = prefix + (f.get("name") or "?")
            self._flatten_field(f, base + int(f.get("offset") or 0), path,
                                depth, stack, state)

    def _flatten_field(self, f, off, path, depth, stack, state):
        """フィールド 1 件を展開します (入れ子の構造体と配列を辿る)。"""
        types = self._types
        target = types["by_path"].get(f.get("ref")) if f.get("ref") else None
        can_descend = (target is not None and depth + 1 <= state["depth"]
                       and target.get("path") not in stack
                       and (target.get("fields") or []))
        extra = {}
        if f.get("bitfield"):
            extra["bitfield"] = f["bitfield"]
        dims = [int(d) for d in (f.get("dims") or []) if isinstance(d, int) and d > 0]
        if dims:
            elem_size = f.get("elem_size") or 0
            total = 1
            for d in dims:
                total *= d
            if elem_size > 0 and (can_descend or total <= self.STRUCT_ARRAY_EXPAND):
                import itertools
                for lin, idx in enumerate(itertools.product(*[range(d) for d in dims])):
                    if state["truncated"]:
                        return
                    epath = path + "".join("[{0}]".format(k) for k in idx)
                    eoff = off + lin * elem_size
                    if can_descend:
                        self._flatten_type(target, eoff, epath + ".", depth + 1,
                                           stack + [target.get("path")], state)
                    else:
                        self._flatten_emit(state, epath, eoff,
                                           f.get("elem_type"), elem_size, extra)
                return
            if total > self.STRUCT_ARRAY_EXPAND:
                state["collapsed"] += 1
            extra = dict(extra, dims=dims, elem_size=elem_size or None)
            self._flatten_emit(state, path, off, f.get("type"), f.get("size"), extra)
            return
        if can_descend:
            self._flatten_type(target, off, path + ".", depth + 1,
                               stack + [target.get("path")], state)
            return
        if f.get("pointee"):
            extra["pointee"] = f["pointee"]
        self._flatten_emit(state, path, off, f.get("type"), f.get("size"), extra)

    def _parse_field_path(self, field_path):
        """`unit->xformUnit.matrix.m[3]` を [(区切り, 名前, [添字...])] に分けます。

        区切りは最初の要素が None、以降は "." か "->" です。
        疑似 C からそのまま貼った括弧や `*` / `&` は外します。
        """
        text = (field_path or "").strip()
        text = text.strip("()*& ;")
        if not text:
            raise ValueError("field_path を指定してください (例 resourceTable / xformUnit.matrix.m)。")
        parts = re.split(r"(->|\.)", text)
        segs = []
        sep = None
        for part in parts:
            if part in ("->", "."):
                sep = part
                continue
            token = part.strip().strip("()*& ")
            if not token:
                continue
            m = self._FIELD_SEG.match(token)
            if not m:
                raise ValueError(
                    "field_path の '{0}' を読めません。フィールド名と [添字] だけを"
                    "'.' か '->' でつないでください。".format(token))
            idx = [int(x, 0) for x in re.findall(r"\[\s*(0[xX][0-9a-fA-F]+|\d+)\s*\]",
                                                  m.group(2) or "")]
            segs.append((sep, m.group(1), idx))
            sep = None
        if not segs:
            raise ValueError("field_path にフィールド名がありません。")
        return segs

    @staticmethod
    def _index_offset(f, idx):
        """配列フィールドに添字を当てたときの (追加オフセット, 型名, サイズ) を返します。"""
        if not idx:
            return 0, f.get("type"), f.get("size")
        dims = [int(d) for d in (f.get("dims") or [])]
        if len(idx) > len(dims):
            raise ValueError("'{0}' は {1} 次元の配列ではありません (dims={2})。".format(
                f.get("name"), len(idx), dims or "なし"))
        elem = int(f.get("elem_size") or 0)
        extra = 0
        for k, i in enumerate(idx):
            if i >= dims[k]:
                raise ValueError("'{0}' の添字 {1} は範囲外です (dims={2})。".format(
                    f.get("name"), i, dims))
            stride = elem
            for d in dims[k + 1:]:
                stride *= d
            extra += i * stride
        rest = dims[len(idx):]
        size = elem
        for d in rest:
            size *= d
        type_name = (f.get("elem_type") or "?") + "".join("[{0}]".format(d) for d in rest)
        return extra, type_name, size

    def _walk_field_path(self, segs, restrict, ignore_case):
        """先頭フィールド名を持つ型から、残りのフィールドを辿ります。"""
        types = self._datatypes()
        first = segs[0][1]
        if ignore_case:
            low = first.lower()
            pairs = [p for name, lst in types["fields"].items()
                     if name.lower() == low for p in lst]
        else:
            pairs = list(types["fields"].get(first, []))

        def same(a, b):
            return a.lower() == b.lower() if ignore_case else a == b

        hits = []
        for row, f in pairs:
            if restrict is not None and (row.get("path") or row["name"]) not in restrict:
                continue
            try:
                extra, ftype, fsize = self._index_offset(f, segs[0][2])
            except ValueError:
                continue
            root = row
            base_row = row
            off = int(f.get("offset") or 0) + extra
            chain = [{"type": row.get("name"), "field": f.get("name"),
                      "offset": int(f.get("offset") or 0)}]
            cur = f
            ok = True
            for sep, name, idx in segs[1:]:
                nxt = types["by_path"].get(cur.get("ref")) if cur.get("ref") else None
                if nxt is None and cur.get("pointee"):
                    # `a->b` でポインタの先へ進む。ここからは別のオブジェクトなので
                    # オフセットはポインタ先の型の先頭から数え直す。
                    nxt = types["by_path"].get(cur["pointee"])
                    if nxt is not None:
                        chain.append({"deref": cur.get("name"), "type": nxt.get("name")})
                        base_row = nxt
                        off = 0
                if nxt is None:
                    ok = False
                    break
                sub = None
                for cand in nxt.get("fields") or []:
                    if isinstance(cand, dict) and cand.get("name") and same(cand["name"], name):
                        sub = cand
                        break
                if sub is None:
                    ok = False
                    break
                try:
                    extra, ftype, fsize = self._index_offset(sub, idx)
                except ValueError:
                    ok = False
                    break
                off += int(sub.get("offset") or 0) + extra
                chain.append({"type": nxt.get("name"), "field": sub.get("name"),
                              "offset": int(sub.get("offset") or 0)})
                cur = sub
            if not ok:
                continue
            hit = {
                "type": base_row.get("name"),
                "type_path": base_row.get("path"),
                "type_size": base_row.get("size"),
                "offset": off,
                "offset_hex": "0x{0:x}".format(off),
                "field_type": ftype,
                "size": fsize,
                "chain": chain,
            }
            if base_row is not root:
                hit["root_type"] = root.get("name")
                hit["note"] = ("ポインタを辿ったので、offset は {0} の先頭からです。".format(
                    base_row.get("name")))
            if base_row.get("vtable"):
                hit["vtable"] = True
            hits.append(hit)
        return hits

    def _embedders(self, type_path, offset):
        """その型を値として持つ型 (派生クラス等) と、そこでのオフセットを返します。"""
        types = self._datatypes()
        out = []
        seen = {type_path}
        frontier = [(type_path, offset, [])]
        for _level in range(self.FIELD_EMBED_DEPTH):
            nxt = []
            for path, off, via in frontier:
                for orow, of in types["embedded"].get(path, []):
                    key = orow.get("path") or orow.get("name")
                    if key in seen:
                        continue
                    seen.add(key)
                    total = int(of.get("offset") or 0) + off
                    chain = via + [of.get("name")]
                    out.append({"type": orow.get("name"), "path": orow.get("path"),
                                "offset": total, "offset_hex": "0x{0:x}".format(total),
                                "via": ".".join(chain)})
                    if len(out) >= self.FIELD_EMBED_MAX:
                        return out
                    nxt.append((key, total, chain))
            frontier = nxt
            if not frontier:
                break
        return out

    def find_field(self, field_path, type_name=None, limit=DEFAULT_LIMIT):
        """フィールド名 (疑似 C からそのまま貼ったもの) から、型とオフセットを返します。

        `resourceTable` / `xformUnit.matrix.m[3]` / `self->resourceTable` を受けます。
        先頭が変数名 (self / unit など) でフィールドに見つからなければ、
        先頭から 1 つずつ外して探し直します (外したものは ignored_prefix)。
        """
        types = self._datatypes()
        segs = self._parse_field_path(field_path)
        restrict = None
        type_match = None
        if type_name:
            type_match, rows = self._match_types(type_name)
            if not rows:
                raise ValueError("type_name '{0}' に一致する型がありません。".format(type_name))
            restrict = set((r.get("path") or r["name"]) for r in rows)
        hits = []
        how = "exact"
        ignored = []
        for drop in range(len(segs)):
            sub = segs[drop:]
            hits = self._walk_field_path(sub, restrict, False)
            how = "exact"
            if not hits:
                hits = self._walk_field_path(sub, restrict, True)
                how = "ignore_case"
            if hits:
                ignored = [s[1] for s in segs[:drop]]
                break
        if not hits and restrict is not None:
            # 指定された型そのものに無ければ、その型が値として持つ基底側を探す。
            base_paths = set()
            for path in restrict:
                row = types["by_path"].get(path)
                for f in (row or {}).get("fields") or []:
                    if isinstance(f, dict) and f.get("ref") and not f.get("dims"):
                        base_paths.add(f["ref"])
            if base_paths:
                hits = self._walk_field_path(segs, base_paths, False) \
                    or self._walk_field_path(segs, base_paths, True)
                how = "base_of_type"

        hits.sort(key=lambda h: ((h.get("type") or ""), h.get("offset") or 0))
        try:
            lim = max(1, min(int(limit), MAX_LIMIT))
        except (TypeError, ValueError):
            lim = DEFAULT_LIMIT
        for hit in hits[:lim]:
            outer = self._embedders(hit.get("type_path") or hit.get("type"), hit["offset"])
            if outer:
                hit["also_at"] = outer
        result = {
            "field_path": field_path,
            "match": how if hits else None,
            "matched": len(hits),
            "returned": min(len(hits), lim),
            "hits": hits[:lim],
        }
        if type_name:
            result["type_name"] = type_name
            result["type_match"] = type_match
        if ignored:
            result["ignored_prefix"] = ignored
            result["ignored_note"] = ("先頭の {0} はどの型のフィールドにも無かったので、"
                                      "変数名とみなして外しました。".format(".".join(ignored)))
        if not hits:
            last = segs[-1][1].lower()
            near = []
            for name, pairs in types["fields"].items():
                if last in name.lower():
                    for row, f in pairs[:3]:
                        near.append("{0}.{1} @+0x{2:x}".format(
                            row.get("name"), name, int(f.get("offset") or 0)))
                if len(near) >= 20:
                    break
            result["suggestions"] = near
            result["note"] = ("一致するフィールドがありません ({0} 型を検索)。"
                              "suggestions は名前の部分一致です。".format(len(types["rows"])))
        else:
            result["note"] = (
                "offset は hits[].type の先頭からです。also_at は、その型を値として"
                "持つ型 (派生クラスの先頭に基底が入る形など) で見たときのオフセットです。"
                "Ghidra の型定義から出しているので、改造コードに使う前に実機で確かめること。")
        if types["truncated"]:
            result["export_truncated"] = True
        return result

    # --- シンボル (名前 → 番地) -------------------------------------------
    def _elf_info(self):
        """実行ファイル (ELF32) の entry / .reginfo / .symtab を返します。無ければ None。"""
        image = self._safe(lambda: self._executable_image(), None)
        if image is None:
            return None
        return getattr(image, "elf", None)

    def _elf_symbol_index(self):
        """ELF .symtab の名前索引です (labels.json が無い古い export の補助)。"""
        elf = self._elf_info()
        key = id(elf)
        if self._elf_symbols is not None and self._elf_symbols[0] == key:
            return self._elf_symbols[1]
        by_addr = {}
        by_name = {}
        spans = []
        for name, value, size, kind in (elf or {}).get("symbols") or []:
            by_addr.setdefault(value, []).append((name, size, kind))
            by_name.setdefault(name, []).append((value, size, kind))
            if size and kind == "object":
                spans.append((value, value + size - 1, name))
        spans.sort()
        index = {"by_addr": by_addr, "by_name": by_name, "spans": spans,
                 "span_starts": [s[0] for s in spans]}
        self._elf_symbols = (key, index)
        return index

    def _typed_spans(self):
        """defined_data の (開始, 終了, ラベル, 型) を開始順で返します。"""
        index = self._symbol_index()
        if "typed_spans" not in index:
            spans = []
            for addr, typed in index["typed"].items():
                length = typed.get("length") or 0
                if length > 0:
                    spans.append((addr, addr + length - 1, typed.get("label"),
                                  typed.get("type")))
            spans.sort()
            index["typed_spans"] = spans
            index["typed_starts"] = [s[0] for s in spans]
        return index["typed_spans"], index["typed_starts"]

    def _name_for(self, value):
        """番地に付いている名前を {name, kind, source} で返します (無ければ None)。

        順番: labels.json → functions.json → defined_data.json のラベル →
        実行ファイルの .symtab。完全一致が無ければ、サイズの分かっている
        データ (defined_data / .symtab の OBJECT) に含まれるかを見て `名前+0x4` の形にします。
        """
        index = self._symbol_index()
        label = index["labels"].get(value)
        if label:
            return {"name": label, "kind": "label", "source": "labels.json"}
        func = index["entries"].get(value)
        if func:
            return {"name": func, "kind": "function", "source": "functions.json"}
        typed = index["typed"].get(value)
        if typed and typed.get("label"):
            return {"name": typed["label"], "kind": "data",
                    "source": "defined_data.json", "data_type": typed.get("type")}
        elf = self._elf_symbol_index()
        syms = elf["by_addr"].get(value)
        if syms:
            name, _size, kind = sorted(syms, key=lambda s: (s[2] != "object", s[0]))[0]
            return {"name": name, "kind": "function" if kind == "func" else "data",
                    "source": "elf_symtab"}
        spans, starts = self._typed_spans()
        pos = bisect.bisect_right(starts, value) - 1
        if pos >= 0 and spans[pos][0] <= value <= spans[pos][1] and spans[pos][2]:
            return {"name": "{0}+0x{1:x}".format(spans[pos][2], value - spans[pos][0]),
                    "kind": "data_inside", "source": "defined_data.json",
                    "data_type": spans[pos][3]}
        pos = bisect.bisect_right(elf["span_starts"], value) - 1
        if pos >= 0 and elf["spans"][pos][0] <= value <= elf["spans"][pos][1]:
            start, _end, name = elf["spans"][pos]
            return {"name": "{0}+0x{1:x}".format(name, value - start),
                    "kind": "data_inside", "source": "elf_symtab"}
        return None

    @staticmethod
    def _symbol_kind(name, kind):
        """`_vt_` で始まる名前は vtable とします (GCC 2.x の vtable 名)。

        ELF の .symtab 上は `_vt$7GmStage` / `_vt.7GmStage` の形 (Ghidra は `_` にする)。
        """
        if name[:4] in ("_vt_", "_vt$", "_vt.") or name.startswith("_ZTV"):
            return "vtable"
        return kind

    @staticmethod
    def _symbol_norm(name):
        """GCC 2.x の区切り (`$` / `.`) を `_` に寄せ、小文字にした名前です。

        疑似 C の `_vt_7GmStage` と .symtab の `_vt$7GmStage` を同じものとして引くため
        (Ghidra は取り込み時に `$` を `_` へ置き換える)。
        """
        return re.sub(r"[$.]", "_", name).lower()

    def resolve_symbol(self, name, limit=20):
        """名前から番地を引きます (functions → labels → defined_data → 実行ファイル)。"""
        probe = (name or "").strip()
        if not probe:
            raise ValueError("name を指定してください (例 _vt_7GmStage / GameManagerInst)。")
        warnings = []
        entries = []                     # (名前, 番地, 種類, 出典, 付加情報)
        for f in self._safe(lambda: self._load("functions.json"), []) or []:
            if isinstance(f, dict) and f.get("name") and f.get("entry"):
                entries.append((f["name"], f["entry"], "function", "functions.json", {}))
        labels_raw = self._safe(lambda: self._load("labels.json"), None)
        if labels_raw is None:
            warnings.append(
                "labels.json がありません。functions.json だけで探しました "
                "(実行ファイルの .symtab も補助に使っています)。データに付いた名前 "
                "(vtable やグローバル変数) まで引くには、Ghidra GUI で "
                "export_context.py を再実行してください。")
        for row in _rows(labels_raw, "labels"):
            if isinstance(row, dict) and row.get("name") and row.get("address"):
                entries.append((row["name"], row["address"], "label", "labels.json",
                                {"symbol_type": row.get("type"),
                                 "namespace": row.get("namespace")}))
        typed_raw = self._safe(lambda: self._load("defined_data.json"), None)
        if typed_raw is None and labels_raw is not None:
            warnings.append("defined_data.json がありません (型付きデータのラベルは"
                            "探していません)。export_context.py の再実行で出ます。")
        for row in _rows(typed_raw, "defined_data"):
            if isinstance(row, dict) and row.get("label") and row.get("address"):
                entries.append((row["label"], row["address"], "data", "defined_data.json",
                                {"data_type": row.get("type"), "size": row.get("length")}))
        elf = self._elf_symbol_index()
        for sym_name, syms in elf["by_name"].items():
            for value, size, kind in syms:
                entries.append((sym_name, "0x{0:08x}".format(value),
                                "function" if kind == "func" else "data", "elf_symtab",
                                {"size": size or None}))

        def collect(pred):
            out = []
            seen = {}
            for ent_name, addr, kind, source, extra in entries:
                if not pred(ent_name):
                    continue
                addr_i = try_parse_hex(addr)
                key = (ent_name, addr_i)
                if key in seen:
                    seen[key].setdefault("also_in", []).append(source)
                    continue
                item = {"name": ent_name,
                        "address": "0x{0:08x}".format(addr_i) if addr_i is not None else addr,
                        "kind": self._symbol_kind(ent_name, kind),
                        "source": source}
                for k, v in extra.items():
                    if v is not None:
                        item[k] = v
                seen[key] = item
                out.append(item)
            return out

        matches = collect(lambda n: n == probe)
        how = "exact"
        if not matches:
            low = probe.lower()
            matches = collect(lambda n: n.lower() == low)
            how = "ignore_case"
        if not matches:
            norm = self._symbol_norm(probe)
            matches = collect(lambda n: self._symbol_norm(n) == norm)
            how = "normalized"
        try:
            lim = max(1, min(int(limit), MAX_LIMIT))
        except (TypeError, ValueError):
            lim = 20
        result = {"name": probe, "match": how if matches else None,
                  "matched": len(matches), "matches": matches[:lim]}
        if not matches:
            low = probe.lower()
            result["suggestions"] = collect(lambda n: low in n.lower())[:lim]
            result["note"] = ("一致する名前がありません。suggestions は部分一致です。"
                              "疑似 C の DAT_xxxxxxxx は名前ではなく番地そのものです。")
        else:
            result["note"] = (
                "kind=vtable は `_vt_` で始まる名前 (GCC 2.x の vtable)。"
                "match=normalized は `$` / `.` を `_` と同一視して一致したもの "
                "(.symtab の `_vt$7GmStage` = Ghidra の `_vt_7GmStage`)。"
                "source=elf_symtab は Ghidra の export ではなく実行ファイルの .symtab から"
                "引いたもので、Ghidra 上で名前が変えられていても反映されていません。")
        if warnings:
            result["warnings"] = warnings
        return result

    # --- gp 相対 (MIPS) ----------------------------------------------------
    #
    # ★PS2 (r5900) の小さいグローバルは `lw v0,-29048(gp)` で読まれ、参照先が
    #   命令に現れない (gp を別の変数から逆算するのは行き詰まりやすい)。
    #   gp は根拠の強い順に求め、**どこから採ったかを必ず返す**。
    #   根拠どうしが食い違ったら黙って 1 つに決めず gp_warnings に出す。

    # entry から何命令ぶん gp の設定を探すか。
    GP_ENTRY_SCAN = 96
    # gp の根拠の強い順。
    GP_SOURCE_ORDER = ("symbol", "elf_reginfo", "entry", "ghidra_context", "code_scan")

    def _is_mips(self):
        """この Program が MIPS かどうかを program.json / memory_map から判定します。"""
        info = self._safe(lambda: self._load("program.json"), {}) or {}
        probe = {"language_id": info.get("language_id")}
        mm = self._safe(lambda: self._load("memory_map.json"), None)
        if isinstance(mm, dict):
            probe = dict(mm, language_id=mm.get("language_id") or info.get("language_id"))
        try:
            return disasm.resolve_arch(probe, None).NAME == "mips"
        except ValueError:
            return False

    def _gp_stamp(self):
        """gp の計算に使うファイルの mtime (変わったら計算し直す)。"""
        names = ("program.json", "labels.json", "functions.json", "memory_map.json")
        return tuple((self.exports_dir / n).stat().st_mtime
                     if (self.exports_dir / n).is_file() else None for n in names)

    def _gp_entry_points(self, info, elf):
        """gp の設定を探す起点 (entry) を集めます。"""
        points = []
        for text in info.get("entry_points") or []:
            value = try_parse_hex(text or "")
            if value is not None:
                points.append((value, "program.json entry_points"))
        if elf and elf.get("entry"):
            points.append((elf["entry"], "ELF e_entry"))
        for f in self._safe(lambda: self._load("functions.json"), []) or []:
            if isinstance(f, dict) and (f.get("name") or "") in (
                    "entry", "_start", "__start", "start", "_entry"):
                value = try_parse_hex(f.get("entry") or "")
                if value is not None:
                    points.append((value, "関数 {0}".format(f["name"])))
        seen = set()
        out = []
        for value, why in points:
            if value not in seen:
                seen.add(value)
                out.append((value, why))
        return out

    def _gp_scan(self, arch_mod, start=None, count=None):
        """gp を組み立てる命令列を探します (start を省くと実行ブロック全体)。"""
        hook = getattr(arch_mod, "find_gp_setup", None)
        if hook is None:
            return []
        mm, blocks = self._exported_blocks()
        big_endian = (mm.get("endian") == "big")
        found = []
        if start is not None:
            block = self._find_block(start, blocks)
            if block is None:
                return []
            bstart, bend = self._block_range(block)
            length = min(int(count) * 4, bend - start + 1)
            data = self._read_memory(block, start - bstart, length)
            return hook(data, start, big_endian, start, len(data) // 4)
        for block in _scannable(blocks):
            if self._overlay_of(block) or not block.get("execute"):
                continue
            bstart, _ = self._block_range(block)
            found.extend(hook(self._image_bytes(block), bstart, big_endian))
        return found

    def _gp_info(self):
        """gp の値を根拠つきで求めます (MIPS 以外は None)。

        根拠の強い順: シンボル `_gp` (labels.json / 実行ファイルの .symtab) →
        ELF の .reginfo → エントリ処理の gp 設定 → Ghidra のコンテキスト値 →
        (どれも無いときだけ) コード全体の走査。
        """
        stamp = self._gp_stamp()
        if self._gp_cache is not None and self._gp_cache[0] == stamp:
            return self._gp_cache[1]
        if not self._is_mips():
            self._gp_cache = (stamp, None)
            return None
        info = self._safe(lambda: self._load("program.json"), {}) or {}
        elf = self._elf_info()
        candidates = []
        warnings = []

        def add(source, value, detail, **extra):
            item = {"source": source, "value": "0x{0:08x}".format(value & 0xFFFFFFFF),
                    "detail": detail}
            item.update(extra)
            candidates.append(item)

        for row in _rows(self._safe(lambda: self._load("labels.json"), None), "labels"):
            if isinstance(row, dict) and row.get("name") == "_gp":
                value = try_parse_hex(row.get("address") or "")
                if value is not None:
                    add("symbol", value, "labels.json の _gp")
        for value, _size, _kind in self._elf_symbol_index()["by_name"].get("_gp", []):
            add("symbol", value, "実行ファイル (ELF .symtab) の _gp")
        if elf and elf.get("reginfo_gp"):
            add("elf_reginfo", elf["reginfo_gp"], "実行ファイル (ELF) の .reginfo ri_gp_value")

        arch_mod = None
        try:
            arch_mod = disasm.get_arch("mips")
        except Exception:
            arch_mod = None
        read_error = None                 # コードのバイトを読めない理由 (1 回だけ出す)
        if arch_mod is not None:
            for entry, why in self._gp_entry_points(info, elf):
                try:
                    hits = self._gp_scan(arch_mod, entry, self.GP_ENTRY_SCAN)
                except Exception as exc:          # 読めない entry で gp 全体を止めない
                    read_error = str(exc)
                    break
                for hit in hits[:1]:
                    add("entry", hit["value"], "{0} (0x{1:08x}) からの {2}".format(
                        why, entry, hit["form"]), at=hit["at"])

        ranges = []
        ctx = (info.get("register_context") or {}).get("gp")
        if isinstance(ctx, dict):
            for rng in ctx.get("ranges") or []:
                lo = try_parse_hex((rng or {}).get("start") or "")
                hi = try_parse_hex((rng or {}).get("end") or "")
                value = try_parse_hex((rng or {}).get("value") or "")
                if lo is not None and hi is not None and value is not None:
                    ranges.append((lo, hi, value & 0xFFFFFFFF))
            values = {}
            for lo, hi, value in ranges:
                values[value] = values.get(value, 0) + (hi - lo + 1)
            if values:
                best = max(values, key=lambda v: values[v])
                add("ghidra_context", best,
                    "Ghidra のコンテキスト値 ({0} 範囲{1})".format(
                        len(ranges), "、値は {0} 種類".format(len(values))
                        if len(values) > 1 else ""))
            elif try_parse_hex(ctx.get("default") or "") is not None:
                add("ghidra_context", try_parse_hex(ctx["default"]),
                    "Ghidra のコンテキスト既定値")

        if not candidates and arch_mod is not None and read_error is None:
            try:
                hits = self._gp_scan(arch_mod)
            except Exception as exc:              # 走査できなくても gp=None で返す
                hits = []
                read_error = str(exc)
            counts = {}
            for hit in hits:
                counts[hit["value"]] = counts.get(hit["value"], 0) + 1
            for value in sorted(counts, key=lambda v: -counts[v]):
                add("code_scan", value, "コード全体で gp を組み立てている箇所 {0} 件".format(
                    counts[value]), count=counts[value])

        if read_error:
            warnings.append("コードのバイトを読めないので、entry の gp 設定とコード走査は"
                            "見ていません: {0}".format(read_error))
        if not candidates:
            result = {"gp": None, "gp_source": None, "gp_candidates": [],
                      "gp_warnings": warnings + [
                          "gp を求められませんでした。labels.json の _gp、ELF の .reginfo、"
                          "entry の gp 設定、Ghidra のコンテキスト値のどれも見つかりません。"
                          "export_context.py を再実行すると Ghidra の gp が program.json の "
                          "register_context に出ます。"]}
            self._gp_cache = (stamp, result)
            return result

        order = {name: i for i, name in enumerate(self.GP_SOURCE_ORDER)}
        pick = sorted(candidates, key=lambda c: order.get(c["source"], 99))[0]
        others = sorted(set(c["value"] for c in candidates if c["value"] != pick["value"]))
        if others:
            warnings.append(
                "gp の根拠どうしが食い違っています (採用 {0} / 他 {1})。"
                "gp_candidates を見て、実機のレジスタ値で確かめてください。".format(
                    pick["value"], ", ".join(others)))
        distinct = sorted(set(r[2] for r in ranges))
        result = {"gp": pick["value"], "gp_source": pick["source"],
                  "gp_candidates": candidates}
        if len(distinct) > 1:
            # 範囲ごとに gp が違う Program (別モジュール等)。命令の番地で引き分ける。
            result["gp_ranges"] = [{"start": "0x{0:08x}".format(lo),
                                    "end": "0x{0:08x}".format(hi),
                                    "value": "0x{0:08x}".format(v)}
                                   for lo, hi, v in ranges[:64]]
            warnings.append("Ghidra のコンテキストでは gp が範囲ごとに {0} 種類あります。"
                            "get_disassembly / resolve_gp_offset(at=...) は命令の番地で"
                            "引き分けます。".format(len(distinct)))
        if warnings:
            result["gp_warnings"] = warnings
        result["_ranges"] = ranges if len(distinct) > 1 else []
        self._gp_cache = (stamp, result)
        return result

    def _gp_at(self, address=None):
        """その番地で使う gp を (値, 出典) で返します。求められなければ (None, None)。"""
        info = self._gp_info()
        if not info or not info.get("gp"):
            return None, None
        if address is not None:
            for lo, hi, value in info.get("_ranges") or []:
                if lo <= address <= hi:
                    return value, "ghidra_context (範囲 0x{0:08x}-0x{1:08x})".format(lo, hi)
        return int(info["gp"], 16), info["gp_source"]

    def _public_gp(self):
        """get_program_info に載せる gp の情報です (内部用のキーを除く)。"""
        info = self._gp_info()
        if info is None:
            return None
        return {k: v for k, v in info.items() if not k.startswith("_")}

    @staticmethod
    def _parse_gp_offset(offset):
        """gp の変位を int にします (-29048 / "-0x7178" / 16bit の生値 0x8e88)。"""
        if isinstance(offset, bool):
            raise ValueError("offset は数値で指定してください。")
        is_hex = False
        if isinstance(offset, int):
            value = offset
        else:
            text = str(offset or "").strip().replace(" ", "")
            if text.endswith("(gp)") or text.endswith("($gp)"):
                text = text[:text.index("(")]
            is_hex = text.lower().startswith("0x")
            try:
                value = int(text, 0)
            except ValueError:
                raise ValueError("offset '{0}' を数値として読めません "
                                 "(例 -29048 / -0x7178)。".format(offset))
        raw = False
        if is_hex and 0x8000 <= value <= 0xFFFF:
            # 命令の即値欄をそのまま写した 16 進 (0x8e88) は符号拡張して読む。
            # 10 進の 40000 は写し間違いの可能性が高いので、ここでは拒否する。
            value -= 0x10000
            raw = True
        if not -0x8000 <= value <= 0x7FFF:
            raise ValueError("offset {0} は 16bit 符号付きの範囲 (-32768〜32767) の外です。".format(
                offset))
        return value, raw

    def resolve_gp_offset(self, offset, at=None):
        """gp 相対の変位 (-29048 等) を絶対番地と名前に直します。"""
        off, raw = self._parse_gp_offset(offset)
        if not self._is_mips():
            raise ValueError("gp 相対は MIPS の Program だけで使えます "
                             "(この Program は MIPS と判定されませんでした)。")
        at_i = parse_hex(at) if at else None
        gp, source = self._gp_at(at_i)
        if gp is None:
            info = self._public_gp() or {}
            raise ValueError("gp を求められませんでした。{0}".format(
                " ".join(info.get("gp_warnings") or [])))
        target = (gp + off) & 0xFFFFFFFF
        result = {
            "offset": off,
            "offset_hex": "{0}0x{1:x}".format("-" if off < 0 else "", abs(off)),
            "gp": "0x{0:08x}".format(gp),
            "gp_source": source,
            "address": "0x{0:08x}".format(target),
        }
        if raw:
            result["offset_note"] = ("{0} は 16bit の生値とみなして符号拡張しました。".format(offset))
        name = self._name_for(target)
        if name:
            result.update({"name": name["name"], "name_kind": name["kind"],
                           "name_source": name["source"]})
            if name.get("data_type"):
                result["data_type"] = name["data_type"]
        info = self._safe(lambda: self._load("program.json"), {}) or {}
        for block in info.get("memory_blocks") or []:
            lo = try_parse_hex((block or {}).get("start") or "")
            hi = try_parse_hex((block or {}).get("end") or "")
            if lo is not None and hi is not None and lo <= target <= hi:
                result["block"] = block.get("name")
                if not block.get("initialized"):
                    result["block_note"] = ("未初期化ブロックです (実行時にしか値が入りません。"
                                            "実機のメモリで読んでください)。")
                break
        gp_info = self._public_gp() or {}
        if gp_info.get("gp_warnings"):
            result["gp_warnings"] = gp_info["gp_warnings"]
        result["note"] = ("address = gp + offset。gp の根拠は gp_source です "
                          "(get_program_info の gp_candidates に全候補)。")
        return result

    def _annotate_gp(self, items, arch_mod):
        """逆アセンブル結果の gp 相対命令に「= 絶対番地 名前」を付けます。

        返り値: (注記した件数, gp が分からず注記できなかった件数, 使った gp の出典)
        """
        hook = getattr(arch_mod, "gp_relative", None)
        if hook is None:
            return 0, 0, None
        done = missing = 0
        sources = set()
        for item in items:
            if item.get("kind") == "data":
                continue
            try:
                word = int(item.get("word") or "", 16)
            except ValueError:
                continue
            off = hook(word)
            if off is None:
                continue
            addr = int(item["addr"], 16)
            gp, source = self._gp_at(addr)
            if gp is None:
                missing += 1
                continue
            target = (gp + off) & 0xFFFFFFFF
            name = self._name_for(target)
            ref = {"address": "0x{0:08x}".format(target), "offset": off}
            comment = "= 0x{0:08x}".format(target)
            if name:
                ref["name"] = name["name"]
                ref["name_source"] = name["source"]
                comment += " " + name["name"]
            item["gp_ref"] = ref
            item["comment"] = comment
            sources.add(source)
            done += 1
        return done, missing, sorted(sources)

    # --- 実行時観測 (runtime_observations/) ------------------------------
    #
    # ★この MCP は **エミュレータを起動も接続も制御もしません。** 読むのは
    #   人間か解析セッションが `<project_root>/runtime_observations/` に保存した
    #   JSON だけです (外部のデバッガをここから呼ぶことはしません)。
    #
    # ★**観測されなかったことは「未使用」の証明ではありません。** どの場面を
    #   どこまで実行したかで結果は変わります。この層は必ず `not_observed` /
    #   `coverage_unknown` として返し、`unused` とは言いません。

    RUNTIME_DIR_NAME = "runtime_observations"
    RUNTIME_KINDS = ("execute", "read", "write")
    RUNTIME_BASES = ("runtime", "ghidra")
    # 1 ファイルあたりの観測件数の上限 (巨大なアクセスカウンタの丸投げを防ぐ)。
    RUNTIME_MAX_OBSERVATIONS = 100000
    # 1 観測が覆ってよい最大バイト数 (size の暴走を弾く)。
    RUNTIME_MAX_SIZE = 0x10000

    def _runtime_dir(self):
        """観測ファイルの置き場を返します (作りません。読むだけ)。"""
        return self.project_root / self.RUNTIME_DIR_NAME

    def _runtime_files(self):
        """runtime_observations/ 直下の *.json を返します。

        ★**ここから外へは出られません。** 解決後のパスの親がこのフォルダ自身で
          ない限り読みません (`..` もシンボリックリンク経由の脱出も弾きます)。
        """
        base = self._runtime_dir()
        if not base.is_dir():
            return [], []
        try:
            # ★フォルダ自体が外部へのリンクなら、resolve 先を信用しない。
            root = self._trusted_dir(base, self.RUNTIME_DIR_NAME + "/")
        except ValueError as exc:
            return [], [{"name": self.RUNTIME_DIR_NAME, "why": str(exc)}]
        good, rejected = [], []
        for path in sorted(base.glob("*.json")):
            try:
                real = path.resolve()
            except OSError as exc:
                rejected.append({"name": path.name, "why": str(exc)})
                continue
            if real.parent != root or not real.is_file():
                rejected.append({
                    "name": path.name,
                    "why": "{0}/ の外を指しています (シンボリックリンク等)。"
                           "読みませんでした。".format(self.RUNTIME_DIR_NAME)})
                continue
            good.append(path)
        return good, rejected

    def _runtime_one_file(self, name):
        """名前で 1 ファイルを指定します。**素のファイル名だけ**を受けます。"""
        text = str(name).strip()
        if not text:
            raise ValueError("file が空です。")
        if text != Path(text).name or text in (".", ".."):
            raise ValueError(
                "file には {0}/ 直下のファイル名だけを指定してください "
                "(パス区切りや .. は受け付けません): {1}".format(
                    self.RUNTIME_DIR_NAME, name))
        if not text.endswith(".json"):
            text += ".json"
        good, _rejected = self._runtime_files()
        for path in good:
            if path.name == text:
                return path
        raise ValueError(
            "観測ファイル '{0}' がありません。あるのは {1} です。".format(
                text, ", ".join(p.name for p in good) or "(1 件もありません)"))

    @staticmethod
    def _runtime_context(raw, fallback):
        """address_context を正規化します。壊れていれば ValueError。"""
        base = dict(fallback or {})
        if raw is None:
            return base
        if not isinstance(raw, dict):
            raise ValueError("address_context は辞書で書いてください。")
        if "basis" in raw:
            basis = str(raw.get("basis") or "").strip().lower()
            if basis not in ExportRepo.RUNTIME_BASES:
                raise ValueError(
                    "basis '{0}' は使えません ({1} のいずれか)。".format(
                        raw.get("basis"), " / ".join(ExportRepo.RUNTIME_BASES)))
            base["basis"] = basis
        if "translation" in raw:
            rule = raw.get("translation")
            base["translation"] = str(rule).strip() if rule else None
        if "reverse" in raw:
            base["reverse"] = bool(raw.get("reverse"))
        return base

    def _runtime_parse(self, path):
        """1 ファイルを読み、検証して正規化します (mtime キャッシュつき)。

        戻り値は {"capture":…, "context":…, "items":[…], "rejected":[…]} か、
        ファイル自体が駄目なら {"problem": 理由}。**例外は投げません** —
        1 ファイルの不備で他のファイルまで読めなくなるのを避けるためです。
        """
        try:
            mtime = path.stat().st_mtime
        except OSError as exc:
            return {"problem": "stat できません: {0}".format(exc)}
        cached = self._runtime_cache.get(path.name)
        if cached is not None and cached[0] == mtime:
            return cached[1]

        try:
            data = json.loads(_read_text_capped(path, MAX_SMALL_JSON_BYTES, path.name))
        except (ValueError, OSError) as exc:
            out = {"problem": "JSON として読めません: {0}".format(exc)}
            self._runtime_cache[path.name] = (mtime, out)
            return out

        out = self._runtime_validate(data)
        self._runtime_cache[path.name] = (mtime, out)
        return out

    def _runtime_validate(self, data):
        """読み込んだ JSON を検証して正規化します (schema v1)。"""
        if not isinstance(data, dict):
            return {"problem": "トップレベルが辞書ではありません。"}
        version = data.get("schema_version")
        if version != 1:
            return {"problem":
                    "schema_version が {0} です (対応しているのは 1 だけ)。"
                    "schemas/runtime_observations.schema.json を見てください。".format(
                        version)}
        capture = data.get("capture")
        if capture is not None and not isinstance(capture, dict):
            return {"problem": "capture は辞書で書いてください。"}
        capture = dict(capture or {})

        try:
            context = self._runtime_context(
                data.get("address_context"),
                {"basis": "runtime", "translation": None, "reverse": False})
        except ValueError as exc:
            return {"problem": "address_context: {0}".format(exc)}

        raw_items = data.get("observations")
        if not isinstance(raw_items, list):
            return {"problem": "observations が配列ではありません。"}
        if len(raw_items) > self.RUNTIME_MAX_OBSERVATIONS:
            return {"problem":
                    "observations が {0} 件あります (上限 {1})。"
                    "範囲や場面で分けて保存してください。".format(
                        len(raw_items), self.RUNTIME_MAX_OBSERVATIONS)}

        items, rejected = [], []
        for index, raw in enumerate(raw_items):
            try:
                items.append(self._runtime_item(raw, context, capture))
            except ValueError as exc:
                # ★捨てずに理由つきで残す (黙って減らすと件数が信用できない)。
                rejected.append({"index": index, "why": str(exc)})
        return {"capture": capture, "context": context,
                "items": items, "rejected": rejected}

    def _runtime_item(self, raw, file_context, capture):
        """観測 1 件を検証して正規化します。駄目なら ValueError。"""
        if not isinstance(raw, dict):
            raise ValueError("観測が辞書ではありません。")
        kind = str(raw.get("kind") or "").strip().lower()
        if kind not in self.RUNTIME_KINDS:
            raise ValueError(
                "kind '{0}' は使えません ({1} のいずれか)。".format(
                    raw.get("kind"), " / ".join(self.RUNTIME_KINDS)))

        address = raw.get("address")
        if not isinstance(address, str) or not _RUNTIME_ADDR.match(address.strip()):
            raise ValueError(
                "address は 0x 始まりの 16 進文字列で書いてください "
                "(整数や負数は受け付けません): {0!r}".format(address))
        addr_i = int(address.strip(), 16)

        pc = raw.get("pc")
        if pc is not None:
            if not isinstance(pc, str) or not _RUNTIME_ADDR.match(pc.strip()):
                raise ValueError(
                    "pc は 0x 始まりの 16 進文字列で書いてください: {0!r}".format(pc))
            pc = "0x{0:08x}".format(int(pc.strip(), 16))

        size = raw.get("size", 1)
        if isinstance(size, bool) or not isinstance(size, int):
            raise ValueError("size は整数で書いてください: {0!r}".format(size))
        if size < 1:
            raise ValueError("size は 1 以上にしてください: {0}".format(size))
        if size > self.RUNTIME_MAX_SIZE:
            raise ValueError(
                "size が大きすぎます ({0} > {1})。".format(size, self.RUNTIME_MAX_SIZE))

        count = raw.get("count", 1)
        if isinstance(count, bool) or not isinstance(count, int):
            raise ValueError("count は整数で書いてください: {0!r}".format(count))
        if count < 1:
            raise ValueError("count は 1 以上にしてください: {0}".format(count))

        context = self._runtime_context(raw.get("address_context"), file_context)
        metadata = raw.get("metadata")
        if metadata is not None and not isinstance(metadata, dict):
            raise ValueError("metadata は辞書で書いてください。")

        return {
            "kind": kind,
            "address": "0x{0:08x}".format(addr_i),
            "address_int": addr_i,
            "size": size,
            "count": count,
            "pc": pc,
            "scenario": raw.get("scenario") or capture.get("scenario"),
            "note": raw.get("note"),
            "context": context,
            "metadata": metadata,
        }

    def _runtime_to_ghidra(self, item, memo):
        """観測 1 件を Ghidra 番地へ直します。

        ★**変換は `translate_address` にそのまま任せます** (規則も理由付けも
          1 か所に保つため)。規則が無い / 引けない / 範囲外のものは
          **推測せず** `unmapped` として理由つきで返します。
        戻り値は (ghidra 番地 int or None, 説明 dict)。
        """
        context = item["context"]
        basis = context.get("basis") or "runtime"
        if basis == "ghidra":
            return item["address_int"], {"basis": "ghidra", "translation": None,
                                         "reasoning": "basis=ghidra なので変換不要。"}
        rule = context.get("translation")
        if not rule:
            return None, {"basis": basis, "translation": None,
                          "why": "basis=runtime なのに translation (変換規則名) が"
                                 "ありません。bridge_config.json の "
                                 "address_translations に規則を書き、観測ファイルの "
                                 "address_context.translation に名前を入れてください。"
                                 "**推測変換はしません。**"}
        reverse = bool(context.get("reverse"))
        key = (rule, reverse, item["address_int"])
        if key in memo:
            return memo[key]
        try:
            got = self.translate_address(item["address"], using=rule,
                                         reverse=reverse)
            value = (try_parse_hex(got.get("result") or ""),
                     {"basis": basis, "translation": rule, "reverse": reverse,
                      "reasoning": got.get("reasoning")})
        except ValueError as exc:
            value = (None, {"basis": basis, "translation": rule,
                            "reverse": reverse, "why": str(exc)})
        memo[key] = value
        return value

    def _runtime_collect(self, source=None, kind=None, scenario=None, file=None):
        """観測をすべて読み、Ghidra 番地へ直した一覧を返します (内部共通)。"""
        if file:
            paths = [self._runtime_one_file(file)]
            rejected_files = []
        else:
            paths, rejected_files = self._runtime_files()

        want_kind = (kind or "").strip().lower() or None
        if want_kind and want_kind not in self.RUNTIME_KINDS:
            raise ValueError(
                "kind '{0}' は使えません ({1} のいずれか)。".format(
                    kind, " / ".join(self.RUNTIME_KINDS)))
        want_source = (source or "").strip().lower() or None
        probe = scenario or None

        memo = {}
        mapped, unmapped, invalid = [], [], list(rejected_files)
        files = []
        for path in paths:
            parsed = self._runtime_parse(path)
            if "problem" in parsed:
                invalid.append({"name": path.name, "why": parsed["problem"]})
                continue
            capture = parsed["capture"]
            files.append({
                "file": path.name,
                "source": capture.get("source"),
                "captured_at": capture.get("captured_at"),
                "scenario": capture.get("scenario"),
                "coverage_note": capture.get("coverage_note"),
                "target_id": capture.get("target_id"),
                "observations": len(parsed["items"]),
                "rejected": len(parsed["rejected"]),
            })
            for bad in parsed["rejected"]:
                invalid.append({"name": path.name,
                                "why": "observations[{0}]: {1}".format(
                                    bad["index"], bad["why"])})
            src = (capture.get("source") or "").strip().lower() or None
            if want_source and src != want_source:
                continue
            for item in parsed["items"]:
                if want_kind and item["kind"] != want_kind:
                    continue
                if probe and probe not in (item.get("scenario") or ""):
                    continue
                ghidra, how = self._runtime_to_ghidra(item, memo)
                row = {
                    "file": path.name,
                    "source": capture.get("source"),
                    "kind": item["kind"],
                    "address": item["address"],
                    "basis": how.get("basis"),
                    "translation": how.get("translation"),
                    "size": item["size"],
                    "count": item["count"],
                    "pc": item["pc"],
                    "scenario": item.get("scenario"),
                    "note": item.get("note"),
                }
                if ghidra is None:
                    row["why_unmapped"] = how.get("why")
                    unmapped.append(row)
                    continue
                row["ghidra_address"] = "0x{0:08x}".format(ghidra)
                row["ghidra_end"] = "0x{0:08x}".format(ghidra + item["size"] - 1)
                row["reasoning"] = how.get("reasoning")
                row["_start"] = ghidra
                row["_end"] = ghidra + item["size"] - 1
                if item.get("metadata"):
                    row["metadata"] = item["metadata"]
                mapped.append(row)
        return files, mapped, unmapped, invalid

    def list_runtime_observations(self, source=None, kind=None, scenario=None,
                                  start=None, end=None, file=None,
                                  offset=0, limit=DEFAULT_LIMIT):
        """`runtime_observations/` に保存された **実行時の観測**を一覧します。

        エミュレータのデバッガなど (観測の手段は問わない) で観測した
        結果を、**Ghidra の番地に直して**照会するためのものです。
        この MCP はエミュレータを起動も接続も制御もしません。読むのは
        プロジェクト内に保存された JSON だけです。

        ★**観測が 0 件でも「未使用」ではありません。** どの場面をどこまで
          実行したかで結果は変わります (`coverage_note` を必ず見てください)。
        """
        files, mapped, unmapped, invalid = self._runtime_collect(
            source, kind, scenario, file)

        lo = parse_hex(start) if start else None
        hi = parse_hex(end) if end else None
        if lo is not None and hi is not None and hi < lo:
            raise ValueError("end が start より小さいです。")
        out_of_range = 0
        if lo is not None or hi is not None:
            kept = []
            for row in mapped:
                if lo is not None and row["_end"] < lo:
                    out_of_range += 1
                    continue
                if hi is not None and row["_start"] > hi:
                    out_of_range += 1
                    continue
                kept.append(row)
            mapped = kept

        mapped.sort(key=lambda r: (r["_start"], r["kind"]))
        off = max(0, int(offset))
        lim = clamp_limit(limit)
        page = [dict(r) for r in mapped[off:off + lim]]
        for row in page:
            row.pop("_start", None)
            row.pop("_end", None)

        result = {
            "dir": str(self._runtime_dir()),
            "files": files,
            "filters": {"source": source, "kind": kind, "scenario": scenario,
                        "start": start, "end": end, "file": file},
            "total": len(mapped),
            "returned": len(page),
            "offset": off,
            "limit": lim,
            "out_of_range": out_of_range if (lo is not None or hi is not None) else None,
            "observations": page,
            "unmapped": unmapped[:lim],
            "unmapped_total": len(unmapped),
            "invalid": invalid[:lim],
            "invalid_total": len(invalid),
            "note": ("外部エミュレータで観測した結果を読んでいます。"
                     "**この MCP はエミュレータを起動も接続も制御もしません** — "
                     "読むのは runtime_observations/ に保存された JSON だけです。"
                     "start/end は **Ghidra 番地**での絞り込みです。"
                     "unmapped は変換できなかった観測で、**捨てずに残して**います "
                     "(規則が無い / 範囲外 / 規則名が違う)。**推測変換はしません。**"
                     "★観測が 0 件でも「未使用」ではありません。"
                     "各ファイルの coverage_note で、どこまで実行したかを確認してください。"),
        }
        if not files:
            result["hint"] = {
                "message": "観測ファイルがありません (エラーではありません)。",
                "how": [
                    "エミュレータのデバッガなど (手段は問わない) で"
                    "実行・観測する。",
                    "その結果を schemas/runtime_observations.schema.json の形にして "
                    "{0}/ に保存する (人間か解析セッションが保存します)。".format(
                        self.RUNTIME_DIR_NAME),
                    "samples/runtime_observations.sample.json が最小例です。",
                ],
            }
        return result

    def get_runtime_range_evidence(self, start, end=None, length=None,
                                   source=None, scenario=None, file=None,
                                   include_static_xrefs=False,
                                   max_pcs=5):
        """Ghidra の番地範囲に重なる **実行時観測**を要約します。

        「この表は本当に使われているのか」「この関数は通るのか」に、
        **観測できた範囲で**答えます。

        ★`verdict` は必ず次のどれかで、**`unused` とは言いません**:
          observed_execute / observed_read / observed_write / observed_multiple /
          not_observed / coverage_unknown

        ★**`not_observed` は「未使用」の証明ではありません。** 観測していない
          場面で使われている可能性は常に残ります。どのファイル・どの場面だけを
          見たかを応答に必ず入れます。
        """
        lo = parse_hex(start)
        if end is not None:
            hi = parse_hex(end)
        elif length is not None:
            try:
                span = int(length)
            except (TypeError, ValueError):
                raise ValueError("length は整数で指定してください。")
            if span < 1:
                raise ValueError("length は 1 以上にしてください。")
            hi = lo + span - 1
        else:
            hi = lo
        if hi < lo:
            raise ValueError("end が start より小さいです。")

        files, mapped, unmapped, invalid = self._runtime_collect(
            source, None, scenario, file)

        # ★1 バイトでも重なれば該当 (size のある read/write は範囲として扱う)。
        hits = [r for r in mapped if r["_start"] <= hi and lo <= r["_end"]]

        try:
            top = max(1, min(int(max_pcs), 20))
        except (TypeError, ValueError):
            top = 5

        by_kind = {}
        for kind in self.RUNTIME_KINDS:
            rows = [r for r in hits if r["kind"] == kind]
            if not rows:
                continue
            pcs = {}
            for row in rows:
                if row.get("pc"):
                    pcs[row["pc"]] = pcs.get(row["pc"], 0) + row["count"]
            by_kind[kind] = {
                "observations": len(rows),
                "total_count": sum(r["count"] for r in rows),
                "addresses": sorted({r["ghidra_address"] for r in rows})[:top],
                "top_pcs": [{"pc": pc, "count": n} for pc, n in
                            sorted(pcs.items(), key=lambda x: -x[1])[:top]],
                "scenarios": sorted({r["scenario"] for r in rows if r["scenario"]}),
                "sources": sorted({r["source"] for r in rows if r["source"]}),
                "files": sorted({r["file"] for r in rows}),
            }

        kinds = sorted(by_kind)
        if not files:
            verdict = "coverage_unknown"
            why = ("観測ファイルが 1 件もありません。"
                   "**実行時に使われているかどうかは分かりません。**")
        elif not hits and not mapped:
            # ★**1 件も Ghidra 番地に置けなかった**とき。観測はあるのに
            #   どこを指しているか分からないので、not_observed とは言えない。
            verdict = "coverage_unknown"
            why = ("観測は {0} 件ありますが、**1 件も Ghidra 番地に変換できません**"
                   "でした。どこを触ったのか分からないので、この範囲について何も"
                   "言えません。unmapped の理由を解消してから judge してください。"
                   .format(len(unmapped)))
        elif not hits:
            verdict = "not_observed"
            why = ("読んだ観測の中に、この範囲へ触れたものはありませんでした。"
                   "**これは「使われていない」証明ではありません。**"
                   "観測していない場面で使われている可能性は残ります。")
            if unmapped:
                # 無関係な観測 1 件が変換できないだけで coverage_unknown に
                # 落とすと、not_observed がほぼ出なくなって意味を失う。
                # verdict は保ったまま、**取りこぼしの可能性は必ず添える**。
                why += ("なお、変換できなかった観測が {0} 件あります — "
                        "それがこの範囲を指している可能性も残ります。".format(
                            len(unmapped)))
        elif len(kinds) > 1:
            verdict = "observed_multiple"
            why = "{0} が観測されています。".format(" / ".join(kinds))
        else:
            verdict = "observed_{0}".format(kinds[0])
            why = "{0} だけが観測されています。".format(kinds[0])

        searched = {
            "files": [f["file"] for f in files],
            "scenarios": sorted({f["scenario"] for f in files if f.get("scenario")}),
            "coverage_notes": [
                {"file": f["file"], "coverage_note": f.get("coverage_note")}
                for f in files if f.get("coverage_note")],
            "sources": sorted({f["source"] for f in files if f.get("source")}),
            "filters": {"source": source, "scenario": scenario, "file": file},
        }

        result = {
            "start": "0x{0:08x}".format(lo),
            "end": "0x{0:08x}".format(hi),
            "size": hi - lo + 1,
            "verdict": verdict,
            "why": why,
            "by_kind": by_kind,
            "matched_observations": len(hits),
            "searched": searched,
            "unmapped_total": len(unmapped),
            "invalid_total": len(invalid),
            "note": ("実行時観測は「観測できたこと」しか言えません。"
                     "**verdict に unused はありません** — 観測されなかったことは"
                     "未使用の証明ではないからです。"
                     "静的側 (find_address_refs / find_pointers_to / get_xrefs) と"
                     "**両方**を見て判断してください。"
                     "この MCP はエミュレータを起動も接続も制御もしません。"),
        }
        if unmapped:
            result["unmapped_note"] = (
                "変換できなかった観測が {0} 件あります。"
                "list_runtime_observations の unmapped で理由を見てください "
                "(規則が無い / 範囲外 / 規則名が違う)。".format(len(unmapped)))
        if verdict in ("not_observed", "coverage_unknown"):
            result["hint"] = {
                "message": "**「使われていない」と結論しないこと。**",
                "next_steps": [
                    "coverage_note を読む — その場面を実行していないだけかもしれない。",
                    "別の場面 (メニュー / ポーズ / 別ステージ / エンディング) を"
                    "観測して、もう 1 ファイル保存する。",
                    "静的側で参照を探す "
                    "(find_address_refs はコードから、find_pointers_to はデータから)。",
                    "unmapped が残っていないか確認する "
                    "(変換規則が無いだけで、実は触っているかもしれない)。",
                ],
            }

        if include_static_xrefs:
            # ★軽い補助だけ。xrefs.json の索引を引くだけで、
            #   find_address_refs や全メモリ走査は**起こしません**。
            refs = self._safe(lambda: self.get_xrefs(
                to_address="0x{0:08x}".format(lo), limit=10), None)
            result["static_xrefs"] = {
                "to_start": (refs or {}).get("items") if refs else None,
                "note": ("範囲の**先頭番地**への xref を 10 件だけ引いたものです "
                         "(xrefs.json の索引を読むだけ)。"
                         "**コードからの参照を網羅したいなら find_address_refs、"
                         "データ中のポインタなら find_pointers_to を明示的に"
                         "呼んでください** — ここからは起動しません (重いため)。"),
            }
        return result

    # --- ツール: list_comments (前回までの結論を読み返す) -----------------
    def list_comments(self, contains=None, start=None, end=None, type=None,
                      ai_only=False, with_function=True, offset=0,
                      limit=DEFAULT_LIMIT):
        """Ghidra 上でその番地に**付いているコメント**を一覧します。

        ★これが無いと **前のセッションの結論を読み返せません**。この道具箱の
          往復は「AI がコメント案を出す → 人間が `apply_comments.py` で反映 →
          次のセッションが続きからやる」ですが、反映したコメントを読む手段が
          無いと、次のセッションは同じ場所を一から解析し直すことになります。
          未定義領域やデータ番地のコメントは疑似 C にも出ないので、なおさらです。

        `ai_only=True` で `[AI]` で始まるものだけに絞れます
        (自分が前回出した所見と、人間が書いた確定情報を分けて読むため)。
        """
        rows = self._safe(lambda: self._load("comments.json"), None)
        if not isinstance(rows, list):
            raise ValueError(
                "comments.json がありません。Ghidra GUI で export_context.py を"
                "再実行してください。bridge_config.json の export_only を"
                ' 使っているなら "comments" を足してください。')

        lo = parse_hex(start) if start else None
        hi = parse_hex(end) if end else None
        probe = contains or None
        want_type = (type or "").strip().lower() or None
        known_types = sorted({(r or {}).get("type") for r in rows
                              if isinstance(r, dict) and r.get("type")})
        if want_type and want_type not in known_types:
            raise ValueError(
                "type '{0}' はありません。この export にあるのは {1} です。".format(
                    type, ", ".join(known_types) or "(コメント 0 件)"))

        matched = []
        skipped = {"本文が一致しない": 0, "範囲外": 0, "種別が違う": 0,
                   "[AI] でない": 0}
        for row in rows:
            if not isinstance(row, dict):
                continue
            text = row.get("comment") or ""
            if ai_only and not row.get("is_ai_comment"):
                skipped["[AI] でない"] += 1
                continue
            if want_type and (row.get("type") or "").lower() != want_type:
                skipped["種別が違う"] += 1
                continue
            if probe and probe not in text:
                skipped["本文が一致しない"] += 1
                continue
            addr = try_parse_hex(row.get("address") or "")
            if addr is None:
                continue
            if (lo is not None and addr < lo) or (hi is not None and addr > hi):
                skipped["範囲外"] += 1
                continue
            matched.append((addr, row))

        matched.sort(key=lambda x: x[0])
        off = max(0, int(offset))
        lim = clamp_limit(limit)
        index = self._symbol_index()
        page = []
        for addr, row in matched[off:off + lim]:
            item = {
                "address": row.get("address"),
                "type": row.get("type"),
                "comment": row.get("comment"),
                "is_ai_comment": bool(row.get("is_ai_comment")),
            }
            if with_function:
                # どの関数の中の話かが分からないと、番地だけ見ても読み返せない。
                name = index["entries"].get(addr)
                if name:
                    item["function"] = name
                else:
                    starts = index["body_starts"]
                    pos = bisect.bisect_right(starts, addr) - 1
                    if pos >= 0:
                        bstart, bend, bname = index["bodies"][pos]
                        if bstart <= addr <= bend:
                            item["function"] = "{0}+0x{1:x}".format(
                                bname, addr - bstart)
                label = index["labels"].get(addr)
                if label:
                    item["label"] = label
            page.append(item)

        ai_total = sum(1 for r in rows
                       if isinstance(r, dict) and r.get("is_ai_comment"))
        return {
            "total_comments": len(rows),
            "ai_comments": ai_total,
            "types": known_types,
            "matched": len(matched),
            "returned": len(page),
            "offset": off,
            "limit": lim,
            "filtered_out": skipped,
            "comments": page,
            "note": ("**前のセッションで確定したことはここに書かれています。**"
                     "解析を始める前に、対象範囲をこれで一度さらってください "
                     "(同じ場所を二度解析するのを防げます)。"
                     "is_ai_comment=true は AI が出した所見 ([AI] 始まり) で、"
                     "false は人間が書いたものです。**人間のコメントの方が強い**"
                     "情報として扱ってください。"
                     "反映は `apply_comments.py` で人間が行うので、この MCP から"
                     "コメントを書くことはできません。"),
        }

    # --- ツール: translate_address (Program 間のアドレス変換) -------------
    def _bridge_config(self):
        """`<project_root>/bridge_config.json` を読みます (mtime キャッシュ)。

        ★この MCP が `ghidra_exports/` の外を読む**唯一の場所**です。
          変換規則は解析中に手で書き足すもので、書くたびに Ghidra から再 export
          させるのは現実的でないため、プロジェクト直下を直接読みます。
          読み取り専用で、書き込みは一切しません。
        """
        path = self.project_root / "bridge_config.json"
        if not path.is_file():
            return {}
        mtime = path.stat().st_mtime
        cached = self._cache.get("__bridge_config__")
        if cached is not None and cached[0] == mtime:
            return cached[1]
        # ★bridge_config.json がプロジェクト外へのリンクなら読まない。
        real = self._checked_file(self.project_root, "bridge_config.json", "プロジェクトフォルダ")
        try:
            data = json.loads(_read_text_capped(real, MAX_SMALL_JSON_BYTES, "bridge_config.json"))
        except UnicodeDecodeError:
            raise ValueError("bridge_config.json が UTF-8 ではありません。")
        except json.JSONDecodeError as exc:
            raise ValueError(
                "bridge_config.json を JSON として解析できません: {0}".format(exc))
        self._cache["__bridge_config__"] = (mtime, data)
        return data if isinstance(data, dict) else {}

    def _translation_rules(self):
        """使える変換規則を {名前: 規則} で返します (設定 + 組み込み)。

        設定 (`bridge_config.json` の `address_translations`) に書いたものに加え、
        **設定なしで使える組み込み規則**も混ぜます。実行時デバッガやヘックス
        エディタとの往復で毎回手計算するのが、このプロジェクトが最も警戒している
        取り違えの元だからです。
        """
        cfg = self._safe(lambda: self._bridge_config(), {}) or {}
        out = {}
        for rule in (cfg.get("address_translations") or []):
            if isinstance(rule, dict) and rule.get("name"):
                out[str(rule["name"])] = dict(rule)
        for name, rule in self._builtin_rules().items():
            out.setdefault(name, rule)      # 設定側の同名を優先する
        return out

    def _builtin_rules(self):
        """設定不要で使える変換規則を返します。"""
        out = {}
        info = self._safe(lambda: self._load("program.json"), {}) or {}
        lang = (info.get("language_id") or "").lower()

        image = self._safe(lambda: self._executable_image(), None)
        if image is not None:
            out["file_offset"] = {
                "name": "file_offset",
                "kind": "file_offset",
                "note": "Ghidra のアドレス <-> 実行ファイル内のオフセット "
                        "(ヘックスエディタで開く位置)。",
                "builtin": True,
            }
        if lang.startswith("65816"):
            # SNES: ローダーがブロック名に配置を書いていれば (bank_80_lorom 等)、
            # その式の規則を設定なしで出す。書いていなければ出さない (推測しない)。
            mm = self._safe(lambda: self._memory_map(), {}) or {}
            names = " ".join(str(b.get("name") or "").lower()
                             for b in (mm.get("blocks") or []))
            found = [k for k in ("exhirom", "hirom", "lorom")
                     if re.search(r"(^|[^a-z]){0}($|[^a-z])".format(k), names)]
            if len(found) == 1:
                out["snes_rom"] = {
                    "name": "snes_rom",
                    "kind": found[0],
                    "copier_header": "auto",
                    "note": "SNES のバス番地 <-> ROM ファイル内 offset ({0}。memory_map の"
                            "ブロック名から判断)。reverse=true で逆。コピアヘッダは ROM ファイルの"
                            "大きさから自動判定。".format(found[0]),
                    "builtin": True,
                }
        if lang.startswith("r5900") or "mips" in lang:
            # PS2 の EE は KSEG0 (0x8xxxxxxx) が物理 RAM の 0x0xxxxxxx に対応する。
            # PCSX2 のダンプやヘックスエディタの表示はこの物理側です。
            out["ee_kseg0_to_ram"] = {
                "name": "ee_kseg0_to_ram",
                "kind": "offset",
                "delta": "-0x80000000",
                "src_range": ["0x80000000", "0x9fffffff"],
                "note": "PS2 EE の KSEG0 (0x8xxxxxxx) <-> RAM ダンプ / "
                        "ヘックスエディタの表示 (0x0xxxxxxx)。",
                "builtin": True,
            }
        return out

    def translate_address(self, address, using=None, reverse=False):
        """Program 間でアドレスを換算し、**根拠つき**で返します。

        1 ゲームで複数のアドレス空間 (親 ROM / ローダ / 本編) を扱うと、
        手計算の取り違えが常に起きます。規則を bridge_config.json に持たせて
        ここから引くことで、換算を毎回やり直さずに済みます。

        規則の形 (bridge_config.json):

            {"name": "client_to_rom",
             "note": "おすそわけ受信バッファ -> 親 ROM",
             "block_size": "0x2000",
             "src_base": "0x02000000",
             "table": ["0x083477B8", "0x083497B8", ...]}

        `src_base` からの距離を `block_size` で割ってブロック番号を出し、
        `table[番号] + ブロック内オフセット` を答えにします。
        `reverse=true` なら逆向き (table 側のアドレス -> src 側) に引きます。
        """
        rules = self._translation_rules()
        if not rules:
            raise ValueError(
                "使える変換規則がありません。{0} の address_translations に"
                "書いてください。kind は table (既定 / ブロック表) / "
                "offset (差を足し引き) / mask (上位ビットを落とす) / "
                "file_offset (実行ファイル内の位置) / lorom / hirom / exhirom "
                "(SNES の ROM 配置) から選べます。".format(
                    self.project_root / "bridge_config.json"))
        if using is None:
            if len(rules) == 1:
                using = next(iter(rules))
            else:
                raise ValueError(
                    "using を指定してください。使える規則: {0}".format(
                        ", ".join(sorted(rules))))
        rule = rules.get(using)
        if rule is None:
            raise ValueError(
                "規則 '{0}' がありません。使える規則: {1}".format(
                    using, ", ".join(sorted(rules))))

        kind = (rule.get("kind") or "table").strip().lower()
        if kind in SNES_MAPPINGS:
            return self._translate_snes(address, using, rule, kind, bool(reverse))
        value = parse_hex(address)
        if kind != "table":
            return self._translate_simple(address, value, using, rule, kind,
                                          bool(reverse))
        block_size = _parse_int(rule.get("block_size"), "block_size")
        src_base = _parse_int(rule.get("src_base"), "src_base")
        table = [_parse_int(x, "table[]") for x in (rule.get("table") or [])]
        if block_size <= 0:
            raise ValueError("block_size は 1 以上にしてください。")
        if not table:
            raise ValueError("規則 '{0}' の table が空です。".format(using))

        if not reverse:
            delta = value - src_base
            if delta < 0:
                raise ValueError(
                    "アドレス {0} が src_base 0x{1:08x} より前です。"
                    "reverse=true を使うべきかもしれません。".format(address, src_base))
            index, offset = divmod(delta, block_size)
            if index >= len(table):
                raise ValueError(
                    "ブロック番号 {0} が table の件数 {1} を超えます "
                    "(範囲外のアドレスです)。".format(index, len(table)))
            result = table[index] + offset
            direction = "src -> table"
            reasoning = (
                "{0} - 0x{1:08x} = 0x{2:x} なのでブロック {3} + 0x{4:x}。"
                "table[{3}] = 0x{5:08x} だから 0x{5:08x} + 0x{4:x} = 0x{6:08x}".format(
                    address, src_base, delta, index, offset, table[index], result))
        else:
            index = None
            offset = 0
            for k, base in enumerate(table):
                if base <= value < base + block_size:
                    index, offset = k, value - base
                    break
            if index is None:
                raise ValueError(
                    "アドレス {0} は table のどのブロックにも入りません。".format(address))
            result = src_base + index * block_size + offset
            direction = "table -> src"
            reasoning = (
                "{0} は table[{1}] = 0x{2:08x} + 0x{3:x}。"
                "だから 0x{4:08x} + {1}*0x{5:x} + 0x{3:x} = 0x{6:08x}".format(
                    address, index, table[index], offset, src_base,
                    block_size, result))

        return {
            "address": address,
            "using": using,
            "reverse": bool(reverse),
            "direction": direction,
            "result": "0x{0:08x}".format(result),
            "block_index": index,
            "block_offset": "0x{0:x}".format(offset),
            "block_size": "0x{0:x}".format(block_size),
            "table_entry": "0x{0:08x}".format(table[index]),
            "src_base": "0x{0:08x}".format(src_base),
            "rule_note": rule.get("note"),
            "reasoning": reasoning,
            "note": "変換は bridge_config.json の規則そのままです。"
                    "規則が間違っていれば結果も間違うので、"
                    "初回は既知の対応で 1 件確かめてください。",
        }

    def _translate_simple(self, address, value, using, rule, kind, reverse):
        """表を使わない変換 (offset / mask / file_offset) を行います。"""
        if kind == "offset":
            delta = _parse_int(rule.get("delta"), "delta")
            lo, hi = self._rule_range(rule, "src_range" if not reverse else None)
            if not reverse and lo is not None and not (lo <= value <= hi):
                raise ValueError(
                    "アドレス {0} は規則 '{1}' の src_range "
                    "(0x{2:08x}〜0x{3:08x}) の外です。reverse=true を使うべきか"
                    "確認してください。".format(address, using, lo, hi))
            result = (value - delta) if reverse else (value + delta)
            # delta 自体が負のことがあるので、実際に足したか引いたかで書く。
            applied = -delta if reverse else delta
            reasoning = "{0} {1} 0x{2:x} = 0x{3:08x}".format(
                address, "-" if applied < 0 else "+", abs(applied), result)
        elif kind == "mask":
            mask = _parse_int(rule.get("mask"), "mask")
            add = _parse_int(rule.get("set", 0), "set")
            if reverse:
                result = (value & mask) | add
                reasoning = "{0} & 0x{1:08x} | 0x{2:08x} = 0x{3:08x}".format(
                    address, mask, add, result)
            else:
                result = value & mask
                reasoning = "{0} & 0x{1:08x} = 0x{2:08x}".format(
                    address, mask, result)
        elif kind == "file_offset":
            image = self._executable_image()
            if image is None:
                raise ValueError(
                    "実行ファイルを読めないので file_offset は使えません "
                    "(許可ルートの外か、見つからない)。外部の実行ファイルは、人間が "
                    "bridge_config.json の source_roots にそのフォルダを書き足してください。")
            if reverse:
                got = image.address_of(value)
                what = "ファイル内 offset"
            else:
                got = image.file_offset(value)
                what = "アドレス"
            if got is None:
                raise ValueError(
                    "{0} 0x{1:08x} は実行ファイルのどのセグメントにも"
                    "載っていません ({2})。".format(what, value, image.path.name))
            result = got
            reasoning = ("{0} は {1} のセグメントから引いて 0x{2:08x} "
                         "({3})".format(address, image.path.name, result,
                                        "アドレス" if reverse else "ファイル内 offset"))
        else:
            raise ValueError(
                "kind '{0}' は未対応です。table / offset / mask / file_offset / "
                "lorom / hirom / exhirom のいずれかにしてください。".format(kind))

        return {
            "address": address,
            "using": using,
            "kind": kind,
            "reverse": bool(reverse),
            "result": "0x{0:08x}".format(result & 0xFFFFFFFF),
            "rule_note": rule.get("note"),
            "builtin": bool(rule.get("builtin")),
            "reasoning": reasoning,
            "note": ("変換は規則そのままです。規則が間違っていれば結果も"
                     "間違うので、初回は既知の対応で 1 件確かめてください。"),
        }

    # --- SNES の ROM 配置 (kind = lorom / hirom / exhirom) -----------------
    @staticmethod
    def _parse_bus(text):
        """'$81:8000' / '$818000' / '0x818000' / '818000' を int にします。"""
        raw = str(text).strip().replace("_", "")
        body = raw[1:] if raw.startswith("$") else raw
        try:
            if ":" in body:
                bank, lo = body.split(":", 1)
                return ((int(bank, 16) & 0xFF) << 16) | (int(lo, 16) & 0xFFFF)
            return int(body, 16)
        except ValueError:
            raise ValueError("アドレス '{0}' を解釈できません (例 $81:8000 / 0x818000)。".format(text))

    def _snes_header(self, rule):
        """コピアヘッダ (512 バイト) の有無を (バイト数, 根拠) で返します。"""
        h = rule.get("copier_header", "auto")
        if isinstance(h, bool):
            return (512 if h else 0), "規則の copier_header={0}".format(h)
        if str(h).strip().lower() != "auto":
            size = _parse_int(h, "copier_header")
            if size not in (0, 512):
                raise ValueError("copier_header は 0 / 512 / true / false / \"auto\" にしてください。")
            return size, "規則の copier_header={0}".format(size)
        path = self._safe(lambda: self._executable_path(), None)
        if path is not None and Path(path).is_file():
            size = Path(path).stat().st_size
            got = 512 if size % 0x400 == 0x200 else 0
            return got, "auto: {0} の大きさ {1:#x} を 1KiB で割った余りが {2:#x}".format(
                Path(path).name, size, size % 0x400)
        return 0, "auto: ROM ファイルが見つからないので「ヘッダ無し」と仮定 (copier_header を書くと確定)"

    def _snes_rom_size(self, rule, header):
        """ROM 本体の大きさ (ヘッダを除く) を返します。分からなければ None。"""
        if rule.get("rom_size") is not None:
            return _parse_int(rule.get("rom_size"), "rom_size")
        path = self._safe(lambda: self._executable_path(), None)
        if path is not None and Path(path).is_file():
            return Path(path).stat().st_size - header
        return None

    @staticmethod
    def _snes_not_rom(bank, lo):
        """ROM でない番地の中身の名前を返します。"""
        if bank in (0x7E, 0x7F):
            return "WRAM ($7E-$7F)"
        sys_bank = bank < 0x40 or 0x80 <= bank < 0xC0
        if sys_bank and lo < 0x2000:
            return "WRAM 先頭 8KiB のミラー ($00-$3F/$80-$BF:0000-1FFF)"
        if sys_bank and lo < 0x6000:
            return "I/O レジスタ ($2000-$5FFF)"
        if sys_bank:
            return "拡張 / SRAM 窓 ($6000-$7FFF、カートリッジ次第)"
        return "ROM の窓の外 (SRAM か未接続。カートリッジ次第)"

    @staticmethod
    def _snes_to_rom(kind, value):
        """バス番地 -> (ROM 内 offset, 説明)。ROM でなければ (None, 理由)。"""
        bank, lo = (value >> 16) & 0xFF, value & 0xFFFF
        if bank in (0x7E, 0x7F):
            return None, None
        if kind == "lorom":
            bb = bank & 0x7F
            if lo < 0x8000:
                return None, None
            off = bb * 0x8000 + (lo - 0x8000)
            return off, "LoROM: (バンク ${0:02X} & $7F) × $8000 + (${1:04X} - $8000)".format(bank, lo)
        if kind == "hirom":
            bb = bank & 0x7F
            if bb >= 0x40:
                off = ((bb - 0x40) << 16) | lo
                return off, "HiROM: ((バンク ${0:02X} & $7F) - $40) × $10000 + ${1:04X}".format(bank, lo)
            if lo < 0x8000:
                return None, None
            off = (bb << 16) | lo
            return off, "HiROM: $00-$3F/$80-$BF:8000-FFFF は $C0-$FF の上半分のミラー"
        # exhirom
        if bank >= 0xC0:
            return ((bank - 0xC0) << 16) | lo, "ExHiROM: $C0-$FF は先頭 4MiB"
        if 0x40 <= bank <= 0x7D:
            return 0x400000 + (((bank - 0x40) << 16) | lo), "ExHiROM: $40-$7D は後半 4MiB"
        if lo < 0x8000:
            return None, None
        if bank < 0x40:
            return 0x400000 + ((bank << 16) | lo), "ExHiROM: $00-$3F:8000-FFFF は後半 4MiB の上半分のミラー"
        return ((bank - 0x80) << 16) | lo, "ExHiROM: $80-$BF:8000-FFFF は先頭 4MiB の上半分のミラー"

    @staticmethod
    def _snes_from_rom(kind, off, prefer):
        """ROM 内 offset -> 正規のバス番地 (prefer=fast: $80- 側 / slow: $00- 側) と別名の一覧。"""
        aliases = []
        if kind == "lorom":
            bb, lo = off // 0x8000, 0x8000 + off % 0x8000
            if bb > 0x7F:
                return None, []
            fast = ((0x80 | bb) << 16) | lo
            slow = (bb << 16) | lo
            canon = fast if prefer != "slow" or bb >= 0x7E else slow
            aliases = [a for a in (fast, slow) if a != canon and (a >> 16) not in (0x7E, 0x7F)]
            return canon, aliases
        if kind == "hirom":
            bb, lo = off >> 16, off & 0xFFFF
            if bb > 0x3F:
                return None, []
            fast = ((0xC0 + bb) << 16) | lo
            slow = ((0x40 + bb) << 16) | lo
            canon = fast if prefer != "slow" or 0x40 + bb >= 0x7E else slow
            aliases = [a for a in (fast, slow) if a != canon and (a >> 16) not in (0x7E, 0x7F)]
            if lo >= 0x8000:
                aliases += [(bb << 16) | lo, ((0x80 + bb) << 16) | lo]
            return canon, aliases
        # exhirom
        if off < 0x400000:
            bb, lo = off >> 16, off & 0xFFFF
            canon = ((0xC0 + bb) << 16) | lo
            if lo >= 0x8000:
                aliases.append(((0x80 + bb) << 16) | lo)
            return canon, aliases
        rel = off - 0x400000
        bb, lo = rel >> 16, rel & 0xFFFF
        if bb > 0x3F:
            return None, []
        if 0x40 + bb <= 0x7D:
            canon = ((0x40 + bb) << 16) | lo
            if lo >= 0x8000:
                aliases.append((bb << 16) | lo)
            return canon, aliases
        if lo < 0x8000:
            return None, []          # $7E/$7F に重なる位置の下半分は見えない
        return (bb << 16) | lo, aliases

    def _translate_snes(self, address, using, rule, kind, reverse):
        """SNES の ROM 配置 (LoROM / HiROM / ExHiROM) でバス番地 <-> ファイル内 offset を換算します。

        ★組み込みの file_offset は ROM を平置きとして扱うので、LoROM では誤ります
          ($81:8000 が「セグメントに無い」)。表 (kind=table) を手で 31 要素書かずに
          済むよう、配置ごとの式で計算します。ミラー ($00-$3F ⇔ $80-$BF など) は
          正規の番地 (canonical) にそろえ、ROM でない番地は is_rom=false で返します。
        """
        header, header_why = self._snes_header(rule)
        rom_size = self._snes_rom_size(rule, header)
        prefer = str(rule.get("canonical") or "fast").strip().lower()
        fmt_bus = lambda v: "${0:02X}:{1:04X}".format((v >> 16) & 0xFF, v & 0xFFFF)  # noqa: E731
        out = {"address": address, "using": using, "kind": kind, "reverse": bool(reverse),
               "copier_header": header, "copier_header_basis": header_why,
               "rom_size": None if rom_size is None else "0x{0:x}".format(rom_size),
               "rule_note": rule.get("note"), "builtin": bool(rule.get("builtin"))}
        if not reverse:
            value = self._parse_bus(address) & 0xFFFFFF
            off, why = self._snes_to_rom(kind, value)
            if off is None:
                region = self._snes_not_rom((value >> 16) & 0xFF, value & 0xFFFF)
                out.update({"is_rom": False, "result": None, "region": region,
                            "reasoning": "{0} は {1} の ROM ではありません ({2})。".format(
                                fmt_bus(value), kind, region)})
                return out
            if rom_size is not None and off >= rom_size:
                out.update({"is_rom": False, "result": None,
                            "region": "ROM の大きさ (0x{0:x}) の外".format(rom_size),
                            "reasoning": "{0} は ROM 内 offset 0x{1:x} になりますが、ROM は "
                                         "0x{2:x} バイトしかありません (ミラーか未接続)。".format(
                                             fmt_bus(value), off, rom_size)})
                return out
            canon, aliases = self._snes_from_rom(kind, off, prefer)
            out.update({
                "is_rom": True,
                "result": "0x{0:06x}".format(off + header),
                "file_offset": "0x{0:06x}".format(off + header),
                "rom_offset": "0x{0:06x}".format(off),
                "canonical": "0x{0:06x}".format(canon) if canon is not None else None,
                "canonical_bus": fmt_bus(canon) if canon is not None else None,
                "is_mirror": canon is not None and canon != value,
                "also_at": [fmt_bus(a) for a in aliases if a != value],
                "reasoning": "{0}: {1} = ROM 内 0x{2:x}{3}".format(
                    fmt_bus(value), why, off,
                    " + ヘッダ 0x200 = ファイル内 0x{0:x}".format(off + header) if header else ""),
            })
            return out
        value = parse_hex(address) if not str(address).strip().startswith("$") \
            else self._parse_bus(address)
        off = value - header
        if off < 0:
            raise ValueError("ファイル内 offset {0} はコピアヘッダ (0x200 バイト) の中です。".format(address))
        if rom_size is not None and off >= rom_size:
            raise ValueError("ファイル内 offset {0} は ROM (0x{1:x} バイト) の外です。".format(
                address, rom_size))
        canon, aliases = self._snes_from_rom(kind, off, prefer)
        if canon is None:
            raise ValueError("ROM 内 offset 0x{0:x} は {1} ではバスから見えません。".format(off, kind))
        out.update({
            "is_rom": True,
            "result": "0x{0:06x}".format(canon),
            "canonical_bus": fmt_bus(canon),
            "rom_offset": "0x{0:06x}".format(off),
            "also_at": [fmt_bus(a) for a in aliases],
            "reasoning": "ファイル内 {0}{1} = ROM 内 0x{2:x} -> {3} ({4}。canonical={5})".format(
                address, " - ヘッダ 0x200" if header else "", off, fmt_bus(canon), kind, prefer),
        })
        return out

    @staticmethod
    def _rule_range(rule, key):
        """規則の範囲指定を (lo, hi) で返します (無ければ (None, None))。"""
        if not key:
            return (None, None)
        span = rule.get(key)
        if not isinstance(span, (list, tuple)) or len(span) != 2:
            return (None, None)
        return (_parse_int(span[0], key), _parse_int(span[1], key))

    # --- ツール: describe_data (構造体・配列の推定) ---------------------
    @staticmethod
    def _classify_words(data, order, pointer_ok):
        """4 バイト語ごとに種別を並べた文字列を作ります (周期検出の材料)。

        記号: '0'=ゼロ / 'S'=インライン文字列の先頭 / 's'=文字列の続き /
              'P'=ポインタらしい値 / 'n'=それ以外の数値
        """
        n = len(data) // 4
        kinds = ["n"] * n
        # 先にインライン文字列の位置を塗る (4 バイト境界から始まるものだけ見る)。
        i = 0
        while i < n:
            off = i * 4
            end = off
            while end < len(data) and 0x20 <= data[end] < 0x7F:
                end += 1
            length = end - off
            if length >= 3 and end < len(data) and data[end] == 0:
                kinds[i] = "S"
                for k in range(i + 1, min(n, (end + 3) // 4 + 1)):
                    kinds[k] = "s"
                i = (end + 3) // 4 + 1
                continue
            i += 1
        for i in range(n):
            if kinds[i] != "n":
                continue
            value = int.from_bytes(data[i * 4:i * 4 + 4], order)
            if value == 0:
                kinds[i] = "0"
            elif pointer_ok(value):
                kinds[i] = "P"
        return "".join(kinds)

    @staticmethod
    def _score_stride(kinds, stride_words, min_periods=3):
        """種別列がその周期で繰り返しているかを 0..1 で採点します。

        ゼロ埋めだけが一致しても意味が無いので、**両方ゼロの位置は数えません**
        (数えると「全部ゼロ = 完全一致」になり、どんな周期でも満点になる)。
        """
        n = len(kinds)
        if stride_words < 1 or n < stride_words * min_periods:
            return 0.0
        hit = 0
        total = 0
        for i in range(n - stride_words):
            a = kinds[i]
            b = kinds[i + stride_words]
            # ★どちらかがゼロの位置は数えない。
            #   レコード長が可変 (使っていない要素がゼロ埋め) の表では、
            #   ゼロとの不一致を減点すると **本当のレコード長が負ける**。
            if a == "0" or b == "0":
                continue
            total += 1
            if a == b:
                hit += 1
        if total < stride_words:
            return 0.0
        return hit / float(total)

    @staticmethod
    def _boundary_score(data, order, stride):
        """「レコード先頭は非ゼロ・その直前はゼロ (末尾パディング)」の一致率です。

        種別の並びだけでは **本当のレコード長と、その ±1 要素ずれ / 整数倍が
        区別できません** (どれも満点になりうる)。実際の値を使って「レコードの
        切れ目らしさ」を測り、二次判定に使います。
        """
        n = len(data) // stride
        if n < 3:
            return 0.0
        hit = 0
        total = 0
        for r in range(1, n):
            off = r * stride
            if off + 4 > len(data):
                break
            total += 1
            head = int.from_bytes(data[off:off + 4], order)
            tail = int.from_bytes(data[off - 4:off], order)
            if head != 0 and tail == 0:
                hit += 1
        return hit / float(total) if total else 0.0

    def _guess_stride(self, kinds, lo_words, hi_words, prefer_larger=0.02,
                      data=None, order="little"):
        """周期の候補を採点し、(最良, 上位候補) を返します。

        スコアが僅差なら **大きい周期を選びます**。入れ子構造 (レコードの中に
        要素が並ぶ) では小さい周期も高得点になりますが、利用者が知りたいのは
        普通は外側のレコード長だからです。
        """
        scored = []
        for w in range(lo_words, hi_words + 1):
            score = self._score_stride(kinds, w)
            if score > 0:
                scored.append((w * 4, score))
        if not scored:
            return None, []
        best_score = max(sc for _, sc in scored)
        good = [(st, sc) for st, sc in scored if sc >= best_score - prefer_larger]
        if data is None:
            best = max(good, key=lambda item: item[0])
            ranked = sorted(scored, key=lambda item: (-item[1], -item[0]))[:8]
            return best, [{"stride": "0x{0:x}".format(st), "bytes": st,
                           "score": round(sc, 4), "boundary": None}
                          for st, sc in ranked]
        # 同点が大量に並ぶ (要素長・その整数倍・±1 要素ずれ) ので、実際の値で
        # 「レコードの切れ目らしさ」を見て決める。同じなら **小さい方** を取る
        # (整数倍を選ばないため)。
        withb = [(st, sc, self._boundary_score(data, order, st)) for st, sc in good]
        best_b = max(b for _, _, b in withb)
        finalists = [item for item in withb if item[2] >= best_b - 1e-9]
        chosen = min(finalists, key=lambda item: item[0])
        ranked = sorted(withb, key=lambda item: (-item[2], -item[1], item[0]))[:8]
        return (chosen[0], chosen[1]), [
            {"stride": "0x{0:x}".format(st), "bytes": st,
             "score": round(sc, 4), "boundary": round(b, 4)}
            for st, sc, b in ranked]

    def describe_data(self, address, stride_hint=None, count=8, max_fields=48):
        """表の構造 (ストライド・要素サイズ・インライン文字列) を推定します。

        各 4 バイト語を u32 / ポインタ / インライン ASCII 文字列に分類し、
        同じ並びが繰り返す周期をストライドとみなします。
        `stride_hint` を与えればそれを使います (推定より確実)。
        """
        target = parse_hex(address)
        mm, blocks = self._exported_blocks()
        block = self._find_block(target, blocks)
        if block is None:
            raise ValueError(
                "アドレス {0} を含む memory ブロックが export されていません。".format(address))
        bstart, bend = self._block_range(block)
        order = "big" if (mm.get("endian") == "big") else "little"
        rec_count = clamp_count(count, 8, 64)

        hint = None
        if stride_hint is not None:
            hint = _parse_mask(stride_hint) if isinstance(stride_hint, str) \
                else int(stride_hint)
            if hint < 4 or hint % 4:
                raise ValueError("stride_hint は 4 の倍数で指定してください。")

        # 周期検出の窓。広すぎると表の外まで読んでノイズが増えるので既定は控えめ。
        detect_span = min(DETECT_WINDOW_BYTES, bend - target + 1)
        span = hint * rec_count if hint else detect_span
        span = min(span, bend - target + 1, MAX_DATA_BYTES)
        span -= span % 4
        if span < 8:
            raise ValueError("解析できるだけのデータがありません (ブロック末尾)。")
        data = self._read_memory(block, target - bstart, span)

        ranges = [self._block_range(b) for b in blocks]
        def pointer_ok(value):
            return any(lo is not None and lo <= value <= hi for lo, hi in ranges)

        kinds = self._classify_words(data, order, pointer_ok)
        candidates = []
        if hint:
            stride = hint
            stride_source = "stride_hint で指定"
        else:
            best, candidates = self._guess_stride(
                kinds, 2, min(len(kinds) // 2, 1024), data=data, order=order)
            if best is None:
                raise ValueError(
                    "周期が見つかりませんでした。stride_hint を指定するか、"
                    "read_data で生の並びを確認してください。")
            stride = best[0]
            stride_source = "種別の並びの周期から推定 (score={0:.3f})".format(best[1])
            # 推定できたらレコード数ぶん読み直す (検出窓より広いことがある)。
            need = min(stride * rec_count, bend - target + 1, MAX_DATA_BYTES)
            need -= need % 4
            if need > len(data):
                data = self._read_memory(block, target - bstart, need)
                kinds = self._classify_words(data, order, pointer_ok)

        # 内側の要素ストライド (レコードの中に並ぶ要素) を探す。
        # 内側の要素ストライド (レコードの中に並ぶ固定長要素) を探す。
        # 上位候補リストは境界スコア順なので、要素長 (境界スコアは低い) は
        # そこに載りません。ここでは「(stride - ヘッダ) を割り切る長さ」だけを
        # 直接試します。
        element = None
        header = 0
        for head in (0, 4, 8, 12, 16):
            body = stride - head
            if body <= 8:
                continue
            for size_b in range(8, body, 4):
                if body % size_b:
                    continue
                if self._score_stride(kinds, size_b // 4) >= 0.95:
                    element, header = size_b, head
                    break
            if element:
                break

        records = []
        for r in range(rec_count):
            off = r * stride
            if off + stride > len(data):
                break
            chunk = data[off:off + stride]
            rec = {
                "index": r,
                "addr": "0x{0:08x}".format(target + off),
                "fields": self._decode_fields(chunk, target + off, order,
                                              blocks, max_fields),
            }
            if element:
                rec["elements"] = self._decode_elements(
                    chunk, target + off, header, element, order, blocks)
            records.append(rec)

        return self._mark_overlay({
            "address": address,
            "block": block.get("name"),
            "guessed_stride": "0x{0:x}".format(stride),
            "stride_bytes": stride,
            "stride_source": stride_source,
            "stride_candidates": candidates,
            "element_stride": "0x{0:x}".format(element) if element else None,
            "header_bytes": header if element else None,
            "record_count": len(records),
            "records": records,
            "note": "ストライドと種別は**推定**です。u32 / ポインタ / インライン文字列の "
                    "3 種類しか見分けません (s16 の組や float は u32 に見えます)。"
                    "確定させるには参照元のコードを get_disassembly で読んでください。"
                    "違うと思ったら stride_hint を指定して読み直せます。",
        }, block)

    def _decode_fields(self, chunk, base, order, blocks, max_fields):
        """1 レコードぶんのバイト列を、u32 / ポインタ / 文字列 / ゼロ列に分解します。"""
        fields = []
        i = 0
        while i + 4 <= len(chunk) and len(fields) < max_fields:
            # インライン文字列
            end = i
            while end < len(chunk) and 0x20 <= chunk[end] < 0x7F:
                end += 1
            if end - i >= 3 and end < len(chunk) and chunk[end] == 0:
                text = chunk[i:end].decode("ascii", "replace")
                fields.append({"offset": i, "addr": "0x{0:08x}".format(base + i),
                               "kind": "string", "value": text,
                               "length": end - i})
                i = ((end + 4) // 4) * 4
                continue
            value = int.from_bytes(chunk[i:i + 4], order)
            if value == 0:
                run = i
                while run + 4 <= len(chunk) and \
                        int.from_bytes(chunk[run:run + 4], order) == 0:
                    run += 4
                fields.append({"offset": i, "addr": "0x{0:08x}".format(base + i),
                               "kind": "zeros", "words": (run - i) // 4})
                i = run
                continue
            resolved = self._resolve_pointer(value, blocks)
            if resolved and (resolved.get("string") or resolved.get("string_via_pointer")
                             or resolved.get("function")):
                fields.append({"offset": i, "addr": "0x{0:08x}".format(base + i),
                               "kind": "pointer", "value": "0x{0:08x}".format(value),
                               "resolved": resolved})
            else:
                fields.append({"offset": i, "addr": "0x{0:08x}".format(base + i),
                               "kind": "u32", "value": value,
                               "hex": "0x{0:08x}".format(value)})
            i += 4
        return fields

    def _decode_elements(self, chunk, base, header, element, order, blocks):
        """レコード内に並ぶ固定長要素をデコードします (先頭の空でないものだけ)。"""
        out = []
        pos = header
        index = 0
        while pos + element <= len(chunk):
            piece = chunk[pos:pos + element]
            if any(piece):
                out.append({
                    "index": index,
                    "addr": "0x{0:08x}".format(base + pos),
                    "fields": self._decode_fields(piece, base + pos, order,
                                                  blocks, 12),
                })
            index += 1
            pos += element
        return out

    # --- ツール 9: データ読み取り (テーブルの中身を読む) --------------
    def _symbol_index(self):
        """アドレス -> 既知のシンボル (関数 entry / 関数 body / 文字列) の索引を返します。

        read_data がポインタらしき値に「その先に何があるか」を添えるために使います。
        functions.json / strings.json が無い (memory だけ export した) 場合は
        空の索引を返し、注釈なしで動きます。mtime が変われば自動で作り直します。
        """
        paths = [self.exports_dir / name for name in
                 ("functions.json", "strings.json", "labels.json",
                  "defined_data.json")]
        mtime = tuple(p.stat().st_mtime if p.is_file() else None for p in paths)
        if self._symbols is not None and self._symbols_mtime == mtime:
            return self._symbols

        entries = {}
        bodies = []
        for f in self._safe(lambda: self._load("functions.json"), []) or []:
            name = f.get("name")
            entry = try_parse_hex(f.get("entry"))
            if entry is not None and name:
                entries[entry] = name
            for rng in f.get("body_ranges", []) or []:
                rs = try_parse_hex(rng.get("start"))
                re_ = try_parse_hex(rng.get("end"))
                if rs is not None and re_ is not None and name:
                    bodies.append((rs, re_, name))
        bodies.sort()

        strings = {}
        for s in self._safe(lambda: self._load("strings.json"), []) or []:
            addr = try_parse_hex(s.get("address"))
            if addr is not None:
                strings[addr] = s.get("value")

        # ラベル (データに付いた名前)。関数名は functions.json 側にあります。
        labels = {}
        for row in _rows(self._safe(lambda: self._load("labels.json"), None),
                         "labels"):
            addr = try_parse_hex((row or {}).get("address") or "")
            if addr is not None and row.get("name"):
                # 同じ番地に複数付くことがあるので primary を優先。
                if addr not in labels or row.get("primary"):
                    labels[addr] = row["name"]

        # 人間が型を付けたデータ。describe_data の推定より**こちらが正**です。
        typed = {}
        for row in _rows(self._safe(lambda: self._load("defined_data.json"), None),
                         "defined_data"):
            addr = try_parse_hex((row or {}).get("address") or "")
            if addr is not None and row.get("type"):
                typed[addr] = {"type": row["type"], "kind": row.get("kind"),
                               "length": row.get("length"),
                               "count": row.get("count"),
                               "label": row.get("label")}

        self._symbols = {
            "entries": entries,
            "bodies": bodies,
            "body_starts": [b[0] for b in bodies],
            "strings": strings,
            "labels": labels,
            "typed": typed,
        }
        self._symbols_mtime = mtime
        return self._symbols

    def _describe_address(self, value, blocks):
        """アドレス値に「そこに何があるか」の注釈を付けます。何も分からなければ None。"""
        index = self._symbol_index()
        info = {}

        name = index["entries"].get(value)
        if name:
            info["function"] = name
        else:
            starts = index["body_starts"]
            pos = bisect.bisect_right(starts, value) - 1
            if pos >= 0:
                bstart, bend, bname = index["bodies"][pos]
                if bstart <= value <= bend:
                    info["function"] = "{0}+0x{1:x}".format(bname, value - bstart)

        text = index["strings"].get(value)
        if text is not None:
            info["string"] = text

        label = index["labels"].get(value)
        if label:
            info["label"] = label

        typed = index["typed"].get(value)
        if typed:
            info["data_type"] = typed["type"]
            if typed.get("kind") in ("array", "struct"):
                info["elements"] = typed.get("count")

        block = self._find_block(value, blocks)
        if block is not None:
            info["block"] = block.get("name")
        return info or None

    def read_data(self, address, format=DATA_FORMAT_HEX, count=DEFAULT_DATA_COUNT,
                  columns=None, stride=None, base="auto", annotate=True,
                  as_markdown=False, record=None, index=None):
        """メモリイメージから **データとして** 値を読みます (命令デコードはしません)。

        find_address_refs で見つけたテーブルの中身を読むためのツールです。
        Ghidra にデータ型を適用しなくても (道具箱では型変更は常に禁止) 解釈だけ試せます。

        count は常に「読む要素数」です。columns を指定すると行に折り返し、
        stride (バイト) を併用すると **1 レコードの先頭だけを拾う** 読み方ができます
        (例: 16 バイトのレコードから先頭 3 個の s16 だけ取る)。

        `record` を指定すると **型が混ざった固定長レコード**を 1 レコード 1 行で
        読めます (例: `record="u8,s8,s8,s8,s8"` = 1 バイトの ID + 符号つき 1 バイト
        × 4 の 5 バイトレコード)。`name:type` で列に名前も付けられます。
        このとき count は**レコード数**、format は無視されます。
        `record="@名前"` と書くと bridge_config.json の `record_formats` から
        引きます (同じ表を読むたびに定義を書き直さないため)。
        その定義が **項目ごとの配列** (layout="soa") なら `index` で
        「要素 index の全項目」を 1 行で読みます (address は省略可 = 定義の base)。
        """
        soa = self._soa_for_record(record)
        if soa is not None:
            return self._read_soa(soa, address, index, base, as_markdown)
        if index is not None:
            raise ValueError(
                "index は record_formats の「項目ごとの配列」(layout=\"soa\") を "
                "record=\"@名前\" で指定したときだけ使えます。")
        if address is None:
            raise ValueError("address を指定してください。")
        target = parse_hex(address)
        mm, blocks = self._exported_blocks()
        big_endian = (mm.get("endian") == "big")
        fmt = (format or DATA_FORMAT_HEX).strip().lower()

        block = self._find_block(target, blocks)
        if block is None:
            raise ValueError(
                "アドレス {0} を含む memory ブロックが export されていません。"
                "memory_map.json の blocks / skipped_reason を確認してください。".format(address))
        bstart, bend = self._block_range(block)
        available = bend - target + 1
        warnings = []

        if record:
            return self._read_records(address, target, block, bstart, available,
                                      record, count, stride, base, annotate,
                                      as_markdown, big_endian, blocks, mm,
                                      fmt, columns)

        if fmt == DATA_FORMAT_CSTRING:
            return self._read_cstrings(address, target, block, bstart, available,
                                       count, as_markdown)

        if fmt == DATA_FORMAT_HEX:
            code, elem = None, 1
        elif fmt in DATA_FORMATS:
            code, elem = DATA_FORMATS[fmt]
        else:
            raise ValueError(
                "format '{0}' は未対応です。使えるのは {1} と {2} / {3} です。".format(
                    format, ", ".join(sorted(DATA_FORMATS)),
                    DATA_FORMAT_HEX, DATA_FORMAT_CSTRING))

        if elem > 1 and target % elem:
            warnings.append(
                "アドレスが {0} バイト境界に揃っていません。"
                "ずれた解釈になっている可能性があります。".format(elem))

        want = clamp_count(count, DEFAULT_DATA_COUNT, MAX_DATA_COUNT)
        cols = self._data_columns(columns, fmt)
        stride_b = self._data_stride(stride, cols, elem)

        # 読み出す範囲を決める (stride 指定時は行ごとに飛ぶので span が広くなる)。
        if stride_b is None:
            span = want * elem
        else:
            rows_wanted = max(1, want // cols)
            span = (rows_wanted - 1) * stride_b + cols * elem
        span = min(span, available, MAX_DATA_BYTES)
        raw = self._read_memory(block, target - bstart, span)

        order = ">" if big_endian else "<"
        values = []
        row_addrs = []
        rows = []
        if stride_b is None:
            n = min(want, len(raw) // elem)
            if fmt == DATA_FORMAT_HEX:
                values = list(raw[:n])
            else:
                values = list(struct.unpack_from(
                    "{0}{1}{2}".format(order, n, code), raw, 0))
            if cols:
                for i in range(0, n, cols):
                    rows.append(values[i:i + cols])
                    row_addrs.append(target + i * elem)
        else:
            n = 0
            offset = 0
            while n + cols <= want and offset + cols * elem <= len(raw):
                if fmt == DATA_FORMAT_HEX:
                    chunk = list(raw[offset:offset + cols])
                else:
                    chunk = list(struct.unpack_from(
                        "{0}{1}{2}".format(order, cols, code), raw, offset))
                rows.append(chunk)
                row_addrs.append(target + offset)
                values.extend(chunk)
                n += cols
                offset += stride_b

        number_format = self._data_number_format(base, fmt)
        annotations = None
        if annotate and fmt in ("u32", "s32", "u64", "s64"):
            annotations = self._annotate_values(values, blocks, elem)

        result = {
            "address": address,
            "format": fmt,
            "endian": mm.get("endian"),
            "block": block.get("name"),
            "element_size": elem,
            "requested": want,
            "count": n,
            "bytes_read": len(raw),
            "columns": cols,
            "stride": stride_b,
            "number_format": number_format,
            "truncated": n < want,
        }
        self._mark_overlay(result, block)
        if warnings:
            result["warnings"] = warnings
        if annotations:
            result["annotations"] = annotations

        if as_markdown:
            result["markdown"] = self._data_markdown(
                rows, row_addrs, values, target, elem, fmt, number_format,
                cols, annotations)
            return result

        if cols:
            result["rows"] = [
                {"addr": "0x{0:08x}".format(a),
                 "values": [self._data_render(v, fmt, number_format) for v in r]}
                for a, r in zip(row_addrs, rows)]
        else:
            result["values"] = [self._data_render(v, fmt, number_format)
                                for v in values]
        return result

    # --- レコード指定 (型が混ざった固定長の表) --------------------------
    def _record_formats(self):
        """bridge_config.json の `record_formats` を {名前: 定義} で返します。

        同じ表を読むたびに `record="id:u8,dx:s8,..."` を書き直すのは無駄なので、
        プロジェクトに置いて使い回せるようにしたものです。

        ★キー名を `structs` にしていないのは、**Ghidra の構造体とは別物**
          だからです (この道具箱では構造体の適用は常に禁止)。ここに書くのは
          「read_data がどう区切って読むか」だけで、Ghidra には一切触りません。
        """
        cfg = self._safe(lambda: self._bridge_config(), {}) or {}
        raw = cfg.get("record_formats") or {}
        if not isinstance(raw, dict):
            raise ValueError(
                "bridge_config.json の record_formats は "
                '{"名前": "u8,s8,s8", ...} の形で書いてください。')
        out = {}
        for name, spec in raw.items():
            key = str(name).strip()
            if not key:
                raise ValueError("record_formats に空の名前があります。")
            if not isinstance(spec, (str, dict)):
                raise ValueError(
                    "record_formats['{0}'] は文字列 (例 \"id:u8,dx:s8,dy:s8\") か、"
                    "項目ごとの配列の定義 ({{\"layout\": \"soa\", ...}}) で"
                    "書いてください。".format(key))
            out[key] = spec
        return out

    def _resolve_record(self, record):
        """`@名前` なら bridge_config の record_formats から引いて返します。"""
        text = str(record).strip()
        if not text.startswith("@"):
            return text, None
        name = text[1:].strip()
        formats = self._record_formats()
        if name not in formats:
            raise ValueError(
                "record_formats に '{0}' がありません。使えるのは {1} です "
                "(bridge_config.json の record_formats に書きます。"
                "list_record_formats で一覧できます)。".format(
                    name, ", ".join(sorted(formats)) or "(登録なし)"))
        return formats[name], name

    def list_record_formats(self):
        """使い回せるレコード定義の一覧を返します (`read_data(record="@名前")`)。"""
        formats = self._record_formats()
        items = []
        for name in sorted(formats):
            if isinstance(formats[name], dict):
                items.append(self._soa_listing(name, formats[name]))
                continue
            item = {"name": name, "record": formats[name],
                    "use": 'read_data(address, record="@{0}")'.format(name)}
            try:
                fields, size = self._parse_record_spec(formats[name])
                item["record_size"] = size
                item["fields"] = [{"name": f["name"], "format": f["format"],
                                   "offset": f["offset"], "size": f["size"]}
                                  for f in fields]
            except ValueError as exc:
                item["problem"] = str(exc)
            items.append(item)
        return {
            "total": len(items),
            "config": str(self.project_root / "bridge_config.json"),
            "record_formats": items,
            "note": ("bridge_config.json の record_formats に書いた定義です。"
                     '`read_data(address, record="@名前")` で使えます。'
                     "**Ghidra の構造体とは別物**で、read_data がどう区切って"
                     "読むかを決めるだけです (Ghidra には一切触りません)。"
                     if items else
                     "登録なし。同じ表を何度も読むなら bridge_config.json の "
                     'record_formats に {"名前": "id:u8,dx:s8,dy:s8"} の形で'
                     "書いておくと使い回せます。"),
        }

    # --- RAM の名前表 (bridge_config の ram_map) ---------------------------
    #
    # notes にしか無かった RAM の意味 ($D9 = グリップ固定フラグ 等) を、逆アセンブル・
    # find_writers・find_address_refs の結果に添えるためのもの。**Ghidra のラベルとは
    # 別物**で、Ghidra には一切触らない (apply は無い。MCP の表示だけ)。
    def _ram_map_entries(self, canon):
        """bridge_config の ram_map を (exact, indexed, bits) の 3 つの表にします。

        書き方:
            "ram_map": {
              "$00D9": "grip_flag",                       番地 1 つ
              "$00DA": {"name": "air_accel", "size": 2},   幅つき (上位バイトは +1)
              "$0B20,X": "car.speed",                     ,X / ,Y 付きの基底番地
              "$0D51.bit7": "airborne"                    ビットの名前
            }
        canon は番地をアーキの正規形にする関数 (65816 は $00D9 -> $7E:00D9)。
        """
        cfg = self._safe(lambda: self._bridge_config(), {}) or {}
        raw = cfg.get("ram_map") or {}
        if not isinstance(raw, dict):
            raise ValueError('bridge_config.json の ram_map は {"$00D9": "名前", ...} の形で書いてください。')
        exact, indexed, bits = {}, {}, {}
        for key, value in raw.items():
            text = str(key).strip()
            if text.startswith("_"):
                continue                      # "_note" などの注釈
            if isinstance(value, dict):
                name = str(value.get("name") or "").strip()
                size = _parse_int(value.get("size", 1), "ram_map['{0}'].size".format(text))
                note = value.get("note")
            else:
                name, size, note = str(value).strip(), 1, None
            if not name:
                raise ValueError("ram_map['{0}'] の名前が空です。".format(text))
            m = re.match(r"^(.*?)\s*(?:,\s*([XYxy]))?\s*(?:\.\s*bit\s*([0-7]))?$", text)
            addr = canon(self._parse_bus(m.group(1)))
            if m.group(3) is not None:
                bits.setdefault(addr, {})[int(m.group(3))] = name
            elif m.group(2) is not None:
                indexed[addr] = {"name": name, "note": note}
            else:
                exact[addr] = {"name": name, "size": max(1, size), "note": note}
        return exact, indexed, bits

    def _ram_namer(self, arch_mod=None, width_ctx=None):
        """実効番地 -> 名前 (dict) を返す関数を作ります。名前の表が無ければ None。

        出どころは ram_map と、record_formats の「項目ごとの配列」(cars.speed[1] 等)。
        """
        cfg = self._safe(lambda: self._bridge_config(), {}) or {}

        def canon(value):
            return self._arch_canonical(arch_mod, width_ctx, value) if arch_mod else value

        exact, indexed, bits = self._ram_map_entries(canon)
        soas = []
        for name, spec in (cfg.get("record_formats") or {}).items():
            if isinstance(spec, dict):
                lay = self._safe(lambda: self._soa_layout(str(name), spec), None)
                if lay is not None:
                    soas.append((lay, canon(lay["base"])))
        if not exact and not indexed and not bits and not soas:
            return None
        max_size = max([e["size"] for e in exact.values()] or [1])

        def name_of(ea, is_indexed=False):
            hit = None
            if is_indexed and ea in indexed:
                hit = {"name": indexed[ea]["name"], "source": "ram_map"}
                if indexed[ea].get("note"):
                    hit["note"] = indexed[ea]["note"]
            if hit is None:
                for back in range(max_size):
                    e = exact.get(ea - back)
                    if e is not None and back < e["size"]:
                        hit = {"name": e["name"] + ("+{0}".format(back) if back else ""),
                               "source": "ram_map"}
                        if e.get("note"):
                            hit["note"] = e["note"]
                        break
            if hit is None:
                for lay, base_canon in soas:
                    got = self._soa_attribute(lay, ea, base_canon)
                    if got is not None:
                        f, k = got
                        label = "{0}.{1}".format(lay["name"], f["name"])
                        hit = {"name": "{0}[{1}]".format(
                            label, ("idx" if not k else "{0}+idx".format(k))
                            if is_indexed else k), "source": "record_formats"}
                        break
            if ea in bits:
                hit = hit or {"name": None, "source": "ram_map"}
                hit["bits"] = {str(b): n for b, n in sorted(bits[ea].items())}
            return hit

        return name_of

    def _name_items(self, items, namer, key="ea", out_key="ea_name"):
        """結果の各行の番地 (key) に名前を添えます。"""
        if namer is None:
            return
        for it in items or []:
            value = try_parse_hex(it.get(key) or "")
            if value is None:
                continue
            hit = namer(value, bool(it.get("indexed")))
            if hit is not None:
                it[out_key] = hit["name"] if hit.get("name") else None
                if hit.get("bits"):
                    it[out_key + "_bits"] = hit["bits"]

    # --- 項目ごとの配列 (record_formats の layout="soa") -----------------
    #
    # データが「構造体の配列」ではなく「項目ごとの配列」になっていることがある:
    #     $0B00 + 項目×$10 + 要素番号×2
    # 1 要素ぶんを集めるのも、項目の意味を割り出すのも手作業になるので、
    # bridge_config の record_formats にこの並びを書けるようにしたもの。
    # ★Ghidra の構造体とは別物 (構造体の適用は常に禁止)。読み方と名前だけ。
    SOA_LAYOUTS = ("soa", "fields_as_arrays")

    def _soa_layout(self, name, spec):
        """record_formats の dict 定義 (項目ごとの配列) を検証して展開します。

        書き方:
            {"layout": "soa", "base": "0x0B00", "field_stride": "0x10",
             "element_size": 2, "count": 6,
             "fields": {"0x10": "input", "0x20": "speed:s16"},
             "element_names": ["player", "cpu1", ...]}
        fields は {オフセット: "名前[:型]"} か、項目番号順の名前の配列
        (i 番目のオフセット = i × field_stride。null は飛ばす)。
        型の既定は element_size の幅の符号なし整数。
        """
        layout = str(spec.get("layout") or spec.get("kind") or "").strip().lower()
        if layout not in self.SOA_LAYOUTS:
            raise ValueError(
                "record_formats['{0}'] の layout が '{1}' です。項目ごとの配列は "
                "\"layout\": \"soa\" と書いてください。".format(name, layout))
        what = "record_formats['{0}'].".format(name)
        base = _parse_int(spec.get("base"), what + "base")
        fstride = _parse_int(spec.get("field_stride"), what + "field_stride")
        esize = _parse_int(spec.get("element_size", 1), what + "element_size")
        count = _parse_int(spec.get("count"), what + "count")
        if fstride < 1 or esize < 1 or count < 1:
            raise ValueError("record_formats['{0}']: field_stride / element_size / count は "
                             "1 以上にしてください。".format(name))
        if count > 256:
            raise ValueError("record_formats['{0}']: count は 256 以下にしてください。".format(name))
        if count * esize > fstride:
            raise ValueError(
                "record_formats['{0}']: 要素 {1} 個 × {2} バイト = {3} バイトが "
                "項目の間隔 field_stride={4:#x} を超えます (隣の項目と重なる)。".format(
                    name, count, esize, count * esize, fstride))
        raw = spec.get("fields")
        pairs = []
        if isinstance(raw, dict):
            for off_text, field in raw.items():
                pairs.append((_parse_int(off_text, what + "fields のオフセット"), field))
        elif isinstance(raw, list):
            for i, field in enumerate(raw):
                if field:
                    pairs.append((i * fstride, field))
        else:
            raise ValueError("record_formats['{0}'].fields は {{\"0x20\": \"speed:s16\"}} か "
                             "名前の配列で書いてください。".format(name))
        default_fmt = {1: "u8", 2: "u16", 4: "u32", 8: "u64"}.get(esize)
        fields = []
        seen = set()
        for off, field in sorted(pairs, key=lambda kv: kv[0]):
            fname, _, ftype = str(field).strip().partition(":")
            fname = fname.strip()
            ftype = ftype.strip().lower() or default_fmt
            if not fname:
                raise ValueError("record_formats['{0}']: オフセット {1:#x} の名前が空です。".format(
                    name, off))
            if fname in seen:
                raise ValueError("record_formats['{0}']: 項目名 '{1}' が重複しています。".format(
                    name, fname))
            seen.add(fname)
            if ftype is None:
                raise ValueError(
                    "record_formats['{0}']: element_size={1} には既定の型が無いので、"
                    "'{2}:u8' のように型を書いてください。".format(name, esize, fname))
            if ftype not in DATA_FORMATS:
                raise ValueError("record_formats['{0}']: 型 '{1}' は使えません ({2})。".format(
                    name, ftype, ", ".join(sorted(DATA_FORMATS))))
            if DATA_FORMATS[ftype][1] > esize:
                raise ValueError(
                    "record_formats['{0}']: '{1}' の型 {2} ({3} バイト) が "
                    "element_size={4} より大きいです。".format(
                        name, fname, ftype, DATA_FORMATS[ftype][1], esize))
            if off < 0:
                raise ValueError("record_formats['{0}']: オフセットが負です。".format(name))
            fields.append({"name": fname, "offset": off, "format": ftype})
        if not fields:
            raise ValueError("record_formats['{0}']: fields が空です。".format(name))
        for a, b in zip(fields, fields[1:]):
            if b["offset"] < a["offset"] + count * esize:
                raise ValueError(
                    "record_formats['{0}']: 項目 '{1}' (+{2:#x}) の要素が "
                    "'{3}' (+{4:#x}) と重なります。".format(
                        name, a["name"], a["offset"], b["name"], b["offset"]))
        names = spec.get("element_names") or []
        if not isinstance(names, list):
            raise ValueError("record_formats['{0}'].element_names は配列にしてください。".format(name))
        return {"name": name, "base": base, "field_stride": fstride,
                "element_size": esize, "count": count, "fields": fields,
                "element_names": [str(x) for x in names[:count]],
                "span_end": base + fields[-1]["offset"] + count * esize - 1}

    def _soa_by_name(self, name):
        """record_formats の項目ごとの配列を名前で引いて展開します。"""
        spec, _ = self._resolve_record("@" + name)
        if not isinstance(spec, dict):
            raise ValueError("record_formats['{0}'] は項目ごとの配列ではありません "
                             "(文字列の定義は read_data の record 用です)。".format(name))
        return self._soa_layout(name, spec)

    def _soa_for_record(self, record):
        """record が `@名前` で項目ごとの配列を指すなら展開した定義を、違えば None を返します。"""
        if not record or not str(record).strip().startswith("@"):
            return None
        name = str(record).strip()[1:].strip()
        if "." in name:
            raise ValueError(
                "read_data の record は '@{0}' のように配列名だけを書いてください "
                "(項目は index の全項目として返します)。".format(name.split(".", 1)[0]))
        spec, _ = self._resolve_record(record)
        if not isinstance(spec, dict):
            return None
        return self._soa_layout(name, spec)

    def _soa_listing(self, name, spec):
        """list_record_formats 用に項目ごとの配列の定義を 1 件にまとめます。"""
        item = {"name": name, "layout": "soa",
                "use": 'read_data(record="@{0}", index=0) / '
                       'find_writers(address="@{0}.<項目>") / '
                       'find_struct_field_uses(base="@{0}")'.format(name)}
        try:
            lay = self._soa_layout(name, spec)
        except ValueError as exc:
            item["problem"] = str(exc)
            return item
        item.update({
            "base": "0x{0:06x}".format(lay["base"]),
            "field_stride": lay["field_stride"],
            "element_size": lay["element_size"],
            "count": lay["count"],
            "span_end": "0x{0:06x}".format(lay["span_end"]),
            "fields": [{"name": f["name"], "offset": "+0x{0:x}".format(f["offset"]),
                        "format": f["format"],
                        "address": "0x{0:06x}".format(lay["base"] + f["offset"])}
                       for f in lay["fields"]],
        })
        if lay["element_names"]:
            item["element_names"] = lay["element_names"]
        return item

    def _soa_field_ref(self, text):
        """'@名前.項目' / '@名前.項目[k]' を (定義, 項目, k または None) にします。"""
        m = re.match(r"^@\s*([^.\[\]\s]+)\.([^.\[\]\s]+)\s*(?:\[\s*(\w+)\s*\])?\s*$",
                     str(text).strip())
        if not m:
            raise ValueError(
                "'{0}' は '@配列名.項目' か '@配列名.項目[要素番号]' の形で書いてください "
                "(例 @cars.speed / @cars.speed[0])。".format(text))
        lay = self._soa_by_name(m.group(1))
        field = next((f for f in lay["fields"] if f["name"] == m.group(2)), None)
        if field is None:
            raise ValueError("record_formats['{0}'] に項目 '{1}' がありません。使えるのは {2} です。".format(
                lay["name"], m.group(2), ", ".join(f["name"] for f in lay["fields"])))
        k = None
        if m.group(3) is not None:
            k = _parse_int(m.group(3), "要素番号")
            if not 0 <= k < lay["count"]:
                raise ValueError("要素番号 {0} は 0〜{1} の範囲にしてください。".format(
                    k, lay["count"] - 1))
        return lay, field, k

    def _read_soa(self, lay, address, index, base, as_markdown):
        """項目ごとの配列を「要素ごとに全項目」で読みます (index 省略で全要素)。"""
        mm, blocks = self._exported_blocks()
        order = ">" if mm.get("endian") == "big" else "<"
        start = lay["base"]
        warnings = []
        if address is not None and str(address).strip() and \
                not str(address).strip().startswith("@"):
            override = parse_hex(address)
            if override != start:
                warnings.append("base を address={0} で読み替えました (定義の base は "
                                "0x{1:06x})。".format(address, start))
                start = override
        if index is None:
            indices = list(range(lay["count"]))
        else:
            k = _parse_int(index, "index")
            if not 0 <= k < lay["count"]:
                raise ValueError("index {0} は 0〜{1} の範囲にしてください。".format(
                    k, lay["count"] - 1))
            indices = [k]
        missing = []
        elements = []
        for k in indices:
            values = {}
            addrs = {}
            for f in lay["fields"]:
                addr = start + f["offset"] + k * lay["element_size"]
                addrs[f["name"]] = "0x{0:06x}".format(addr)
                code, size = DATA_FORMATS[f["format"]]
                block = self._find_block(addr, blocks)
                value = None
                if block is not None and _has_bytes(block):
                    bstart, bend = self._block_range(block)
                    if addr + size - 1 <= bend:
                        raw = self._read_memory(block, addr - bstart, size)
                        if len(raw) == size:
                            value = struct.unpack_from(order + code, raw, 0)[0]
                if value is None:
                    if f["name"] not in missing:
                        missing.append(f["name"])
                    values[f["name"]] = None
                else:
                    values[f["name"]] = self._data_render(
                        value, f["format"], self._data_number_format(base, f["format"]))
            row = {"index": k, "values": values, "addresses": addrs}
            if k < len(lay["element_names"]):
                row["element_name"] = lay["element_names"][k]
            elements.append(row)
        if missing:
            warnings.append(
                "export されたメモリに無い項目は値を null にしました: {0}。"
                "番地 (addresses) は定義から計算したものなので有効です。".format(
                    ", ".join(missing)))
        result = {
            "record_format": lay["name"],
            "format": "record_soa",
            "layout": "soa",
            "base": "0x{0:06x}".format(start),
            "field_stride": lay["field_stride"],
            "element_size": lay["element_size"],
            "count": lay["count"],
            "index": None if index is None else indices[0],
            "fields": [{"name": f["name"], "offset": "+0x{0:x}".format(f["offset"]),
                        "format": f["format"]} for f in lay["fields"]],
            "elements": elements,
            "note": ("項目ごとの配列: 要素 k の項目 f は base + f.offset + k × element_size。"
                     "値は **Program のメモリイメージ**のもので、RAM なら実行時の値ではありません "
                     "(実行時の値は Mesen 等で addresses を読む)。Ghidra には触っていません。"),
        }
        if warnings:
            result["warnings"] = warnings
        if as_markdown:
            head = ["index"] + [f["name"] for f in lay["fields"]]
            lines = ["| " + " | ".join(head) + " |",
                     "| " + " | ".join(["---"] + ["---:"] * len(lay["fields"])) + " |"]
            for row in elements:
                label = str(row["index"])
                if row.get("element_name"):
                    label += " ({0})".format(row["element_name"])
                cells = [label] + ["" if row["values"][f["name"]] is None
                                   else str(row["values"][f["name"]]) for f in lay["fields"]]
                lines.append("| " + " | ".join(cells) + " |")
            result["markdown"] = "\n".join(lines)
            result.pop("elements")
        return result

    @staticmethod
    def _arch_canonical(arch_mod, width_ctx, value):
        """番地をアーキの正規形にします (65816 は WRAM ミラーを $7E へ寄せる)。無ければそのまま。"""
        fn = getattr(arch_mod, "canonical_query", None)
        if fn is None or width_ctx is None:
            return value
        return fn(value, width_ctx)

    @staticmethod
    def _soa_attribute(lay, ea_canon, base_canon):
        """正規化した実効番地を (項目, 要素番号) にします。どの項目の要素でもなければ None。"""
        rel = ea_canon - base_canon
        for f in lay["fields"]:
            inner = rel - f["offset"]
            if 0 <= inner < lay["count"] * lay["element_size"]:
                return f, inner // lay["element_size"]
        return None

    def _soa_scan(self, lay, lo, hi, index_reach, max_scan=12, trace_imm=16):
        """[lo, hi] に触る命令を 1 回の走査で集め、項目・要素に振り分けます。

        戻り値: (find_writers の結果, [(kind, item, 項目, 要素番号)], 項目の外の基底の件,
                 blocks)。kind は write / read。
        """
        mm, blocks = self._exported_blocks()
        arch_mod = disasm.resolve_arch(mm)
        if not getattr(arch_mod, "WRITERS_TARGET_RANGE", False):
            raise ValueError(
                "{0} の find_writers は範囲指定に対応していないので、項目ごとの配列の"
                "走査はできません (番地を 1 つずつ find_writers に渡してください)。".format(
                    arch_mod.NAME))
        width_ctx = (self._width_context(blocks)
                     if getattr(arch_mod, "NEEDS_WIDTH_CONTEXT", False) else None)
        raw = self.find_writers("0x{0:06x}".format(lo), max_scan=max_scan,
                                trace_imm=trace_imm, index_reach=index_reach,
                                target_end="0x{0:06x}".format(hi))
        base_canon = self._arch_canonical(arch_mod, width_ctx, lay["base"])
        rows = []
        outside = []
        for kind, key in (("write", "writers"), ("write", "offset_writers"),
                          ("read", "readers")):
            for it in raw.get(key) or []:
                hit = self._soa_attribute(lay, int(it["ea"], 16), base_canon)
                if hit is None:
                    outside.append(it)
                else:
                    rows.append((kind, it, hit[0], hit[1]))
        return raw, rows, outside, blocks

    def _soa_item(self, lay, it, field, k, blocks):
        """走査結果の 1 件に「どの配列のどの項目・どの要素か」を添えます。"""
        it = dict(it)
        label = "{0}.{1}".format(lay["name"], field["name"])
        if it.get("indexed"):
            it["record_field"] = ("{0}[{1}+idx]".format(label, k) if k
                                  else "{0}[idx]".format(label))
        else:
            it["record_field"] = "{0}[{1}]".format(label, k)
            if k < len(lay["element_names"]):
                it["element_name"] = lay["element_names"][k]
        if not it.get("function"):
            info = self._safe(lambda: self._describe_address(int(it["addr"], 16), blocks), None)
            if info and info.get("function"):
                it["function"] = info["function"]
        return it

    def _find_writers_soa(self, address, max_scan, trace_imm, scan_basis, index_reach):
        """find_writers(address="@配列.項目[k]") の本体。"""
        lay, field, k = self._soa_field_ref(address)
        if scan_basis and str(scan_basis).strip().lower() == "bytes":
            raise ValueError("@配列.項目 は scan_basis=cdl (既定) でだけ使えます。"
                             "bytes で探すなら番地を 1 つずつ渡してください。")
        lo = lay["base"] + field["offset"]
        hi = lo + lay["count"] * lay["element_size"] - 1
        if k is not None:
            lo += k * lay["element_size"]
            hi = lo + lay["element_size"] - 1
        reach = index_reach
        if reach is None:
            reach = (lay["count"] - 1) * lay["element_size"]
        raw, rows, outside, blocks = self._soa_scan(lay, lo, hi, reach, max_scan, trace_imm)
        result = {
            "address": address,
            "record_format": lay["name"],
            "field": field["name"],
            "element": k,
            "range": ["0x{0:06x}".format(lo), "0x{0:06x}".format(hi)],
            "index_reach": reach,
            "arch": raw.get("arch"),
            "writers": [], "offset_writers": [], "readers": [],
            "indirect_stores": raw.get("indirect_stores"),
            "width_context": raw.get("width_context"),
            "scan_basis": raw.get("scan_basis"),
        }
        for kind, it, f, kk in rows:
            # 要素 k を聞かれたときは、k の番地を直接書く命令と、k 以前の要素を
            # 基底にした ,X ,Y (添字で k に届く) だけを残す。
            if f is not field or (k is not None and (kk > k or (kk != k and not it.get("indexed")))):
                outside.append(it)
                continue
            row = self._soa_item(lay, it, f, kk, blocks)
            if kind == "read":
                result["readers"].append(row)
            elif it.get("indexed"):
                result["offset_writers"].append(row)
            else:
                result["writers"].append(row)
        result["outside_field_base"] = outside[:50]
        result["outside_field_base_total"] = len(outside)
        result["note"] = (
            "項目ごとの配列 {0} の {1} ({2}..{3}) に触る命令です。record_field の [k] は要素番号、"
            "[idx] は ,X / ,Y で要素を選ぶ形。index_reach の既定は (count-1)×element_size で、"
            "**添字で項目をまたぐ形 (X = 項目×field_stride + 要素×element_size) は拾いません** — "
            "その形を疑うなら index_reach を大きくして outside_field_base を見てください "
            "(基底番地がこの項目の外にある ,X 付きの命令が入ります)。{4}".format(
                lay["name"], field["name"], result["range"][0], result["range"][1],
                raw.get("note") or ""))
        if not result["writers"] and not result["offset_writers"]:
            result["hint"] = raw.get("hint")
        return result

    def _struct_field_uses_soa(self, base, offset, limit):
        """find_struct_field_uses(base="@配列") の本体 (逆アセンブルから数える)。"""
        lay = self._soa_by_name(str(base).strip()[1:].strip())
        want = None
        if offset is not None:
            want = next((f for f in lay["fields"] if f["name"] == str(offset).strip()), None)
            if want is None:
                try:
                    off_i = _parse_int(offset, "offset")
                except ValueError:
                    off_i = None
                want = next((f for f in lay["fields"] if f["offset"] == off_i), None)
            if want is None:
                raise ValueError("record_formats['{0}'] に項目 '{1}' がありません。使えるのは {2} です。".format(
                    lay["name"], offset, ", ".join(f["name"] for f in lay["fields"])))
        lim = clamp_limit(limit)
        reach = (lay["count"] - 1) * lay["element_size"]
        raw, rows, outside, blocks = self._soa_scan(lay, lay["base"], lay["span_end"], reach)
        per = {}
        items = []
        for kind, it, f, k in rows:
            slot = per.setdefault(f["name"], {
                "field": f["name"], "offset": "+0x{0:x}".format(f["offset"]),
                "format": f["format"], "read_sites": 0, "write_sites": 0,
                "indexed_sites": 0, "functions": []})
            slot["read_sites" if kind == "read" else "write_sites"] += 1
            if it.get("indexed"):
                slot["indexed_sites"] += 1
            row = self._soa_item(lay, it, f, k, blocks)
            fn = row.get("function")
            if fn and fn not in slot["functions"]:
                slot["functions"].append(fn)
            if want is not None and f is want:
                row["kind"] = kind
                items.append(row)
        common = {
            "base": "@" + lay["name"],
            "layout": "soa",
            "base_address": "0x{0:06x}".format(lay["base"]),
            "field_stride": lay["field_stride"],
            "element_size": lay["element_size"],
            "count": lay["count"],
            "source": "disassembly",
            "scan_basis": raw.get("scan_basis"),
            "indirect_stores": raw.get("indirect_stores"),
            "outside_field_total": len(outside),
            "note": ("項目ごとの配列は疑似 C ではなく **逆アセンブル (find_writers と同じ走査)** "
                     "から数えます。CDL (cdl_jsonl) に記録されたコードだけが対象で、間接 "
                     "(STA (dp),Y 等) は indirect_stores に件数だけ。untouched_fields は "
                     "「この走査で触る命令が見つからなかった項目」で、未使用の証明ではありません。"
                     "outside_field_total は範囲内だが定義した項目の要素に当たらない参照の件数 "
                     "(項目の書き漏れ・項目間の隙間の可能性)。"),
        }
        if want is not None:
            items.sort(key=lambda r: r["addr"])
            common.update({"field": want["name"], "total": len(items),
                           "returned": min(len(items), lim), "items": items[:lim]})
            return common
        common.update({
            "fields": [per[f["name"]] for f in lay["fields"] if f["name"] in per],
            "untouched_fields": [f["name"] for f in lay["fields"] if f["name"] not in per],
        })
        return common

    @staticmethod
    def _parse_record_spec(record):
        """`record` 文字列を項目の並びに変換します。

        書き方:

            "u8,s8,s8,s8,s8"          型だけを並べる (5 バイトのレコード)
            "id:u8,dx:s8,dy:s8"       `名前:型` で列に名前を付ける
            "u8,x3,u16"               `xN` / `padN` は N バイトの詰め物 (読み飛ばす)

        使える型は read_data の format と同じ数値型です
        (u8/s8/u16/s16/u32/s32/u64/s64/f32/f64)。
        """
        text = str(record).strip()
        if not text:
            raise ValueError("record が空です。")
        fields = []
        offset = 0
        for i, part in enumerate(x.strip() for x in text.split(",")):
            if not part:
                raise ValueError(
                    "record の {0} 番目が空です (カンマが余っていませんか)。".format(i + 1))
            name = None
            if ":" in part:
                name, part = (x.strip() for x in part.split(":", 1))
                if not name or not part:
                    raise ValueError(
                        "record の '{0}' は `名前:型` の形で書いてください。".format(part))
            key = part.lower()
            pad = re.match(r"^(?:x|pad)(\d*)$", key)
            if pad:
                size = int(pad.group(1) or 1)
                if size < 1 or size > 256:
                    raise ValueError("詰め物のバイト数は 1〜256 にしてください。")
                fields.append({"name": name, "format": "pad", "offset": offset,
                               "size": size, "code": None})
                offset += size
                continue
            if key not in DATA_FORMATS:
                raise ValueError(
                    "record の型 '{0}' は使えません。使えるのは {1} と "
                    "xN (N バイトの詰め物) です。".format(
                        part, ", ".join(sorted(DATA_FORMATS))))
            code, size = DATA_FORMATS[key]
            fields.append({"name": name, "format": key, "offset": offset,
                           "size": size, "code": code})
            offset += size
        if offset < 1:
            raise ValueError("record の大きさが 0 バイトです。")
        if offset > 256:
            raise ValueError(
                "1 レコードが {0} バイトあります (上限 256)。".format(offset))
        if not [f for f in fields if f["code"]]:
            raise ValueError("record が詰め物だけです。読む型を 1 つ以上入れてください。")
        return fields, offset

    def _read_records(self, address, target, block, bstart, available, record,
                      count, stride, base, annotate, as_markdown, big_endian,
                      blocks, mm, fmt, columns):
        """型が混ざった固定長レコードの表を、1 レコード 1 行で読みます。

        「1 バイトの ID + 符号つき 1 バイト × 4」のような表は read_data の
        1 呼び出し 1 形式では読めず、struct.unpack へ逃げることになります。
        そこを塞ぐためのものです。
        """
        record, format_name = self._resolve_record(record)
        if isinstance(record, dict):
            raise ValueError("record_formats['{0}'] は項目ごとの配列です "
                             "(read_data の index で読みます)。".format(format_name))
        fields, size = self._parse_record_spec(record)
        warnings = []
        if columns is not None:
            raise ValueError(
                "record と columns は一緒に使えません "
                "(レコードの区切りは record が決めます)。")
        if fmt not in (DATA_FORMAT_HEX,):
            warnings.append(
                "record を指定したので format='{0}' は無視しました。".format(fmt))

        step = size
        if stride is not None:
            # レコードの間隔がレコード長より広い形 (5 バイトの中身が 8 バイト
            # 間隔で並ぶ等) を読むための指定。
            step = _parse_int(stride, "stride")
            if step < size:
                raise ValueError(
                    "stride ({0}) が 1 レコード ({1} バイト) より小さいです。".format(
                        step, size))

        want = clamp_count(count, min(DEFAULT_DATA_COUNT, 64), MAX_DATA_COUNT)
        span = min((want - 1) * step + size, available, MAX_DATA_BYTES)
        raw = self._read_memory(block, target - bstart, span)

        order = ">" if big_endian else "<"
        rows = []
        values_by_format = {}
        offset = 0
        while len(rows) < want and offset + size <= len(raw):
            values = []
            named = {}
            for field in fields:
                if not field["code"]:
                    continue
                value = struct.unpack_from(
                    "{0}{1}".format(order, field["code"]), raw,
                    offset + field["offset"])[0]
                values.append(value)
                if field["name"]:
                    named[field["name"]] = value
                values_by_format.setdefault(field["format"], []).append(value)
            row = {"addr": "0x{0:08x}".format(target + offset),
                   "values": values}
            if named:
                row["named"] = named
            rows.append(row)
            offset += step

        # 数値の見せ方は項目ごとに決める (u32 は 16 進、s8 は 10 進が読みやすい)。
        for field in fields:
            if field["code"]:
                field["number_format"] = self._data_number_format(
                    base, field["format"])

        annotations = None
        if annotate:
            # ★桁幅は型ごとに違う (u32 と u64 が混ざる表が実在する)。
            #   まとめて 1 つの幅で作ると、注釈のキーが値の表記と合わなくなる。
            merged = {}
            for name in ("u32", "s32", "u64", "s64"):
                values = values_by_format.get(name)
                if values:
                    merged.update(self._annotate_values(
                        values, blocks, DATA_FORMATS[name][1]))
            annotations = merged or None

        rendered = [f for f in fields if f["code"]]
        for row in rows:
            row["values"] = [self._data_render(v, f["format"],
                                               f["number_format"])
                             for v, f in zip(row["values"], rendered)]
            if row.get("named"):
                row["named"] = {
                    f["name"]: self._data_render(row["named"][f["name"]],
                                                 f["format"],
                                                 f["number_format"])
                    for f in rendered if f["name"]}

        result = {
            "address": address,
            "format": "record",
            "record": record,
            "record_format": format_name,
            "record_size": size,
            "endian": mm.get("endian"),
            "block": block.get("name"),
            "fields": [{"name": f["name"], "format": f["format"],
                        "offset": f["offset"], "size": f["size"]}
                       for f in fields],
            "requested": want,
            "count": len(rows),
            "bytes_read": len(raw),
            "stride": step,
            "truncated": len(rows) < want,
            "note": ("1 レコード 1 行で返しています。values は record に書いた順で、"
                     "詰め物 (xN) は入りません。count は**レコード数**です。"
                     "Ghidra にデータ型は適用していません (型変更は常に禁止)。"),
        }
        self._mark_overlay(result, block)
        if warnings:
            result["warnings"] = warnings
        if annotations:
            result["annotations"] = annotations
        if as_markdown:
            result["markdown"] = self._record_markdown(rows, rendered,
                                                       annotations)
        else:
            result["records"] = rows
        return result

    @staticmethod
    def _record_markdown(rows, fields, annotations):
        """レコードを Markdown の表にします (notes/*.md へそのまま貼れるように)。"""
        header = ["addr"] + [f["name"] or "+{0}".format(f["offset"])
                             for f in fields]
        align = ["---"] + ["---:"] * len(fields)
        if annotations:
            header.append("参照先")
            align.append("---")
        lines = ["| " + " | ".join(header) + " |",
                 "|" + "|".join(align) + "|"]
        for row in rows:
            cells = ["`{0}`".format(row["addr"])]
            cells += ["{0}".format(v) for v in row["values"]]
            if annotations:
                notes = []
                for value in row["values"]:
                    info = annotations.get(value) if isinstance(value, str) else None
                    if info:
                        notes.append(info.get("function") or info.get("string")
                                     or info.get("label") or info.get("block"))
                cells.append(", ".join(str(x) for x in notes if x))
            lines.append("| " + " | ".join(cells) + " |")
        return "\n".join(lines)

    @staticmethod
    def _data_columns(columns, fmt):
        """1 行あたりの要素数を決めます (hex は既定 16、その他は既定 None=折り返さない)。"""
        if columns is None:
            return 16 if fmt == DATA_FORMAT_HEX else None
        try:
            cols = int(columns)
        except (TypeError, ValueError):
            raise ValueError("columns は整数で指定してください。")
        if cols < 1:
            raise ValueError("columns は 1 以上にしてください。")
        if cols > MAX_DATA_COUNT:
            raise ValueError("columns が大きすぎます (上限 {0})。".format(MAX_DATA_COUNT))
        return cols

    @staticmethod
    def _data_stride(stride, cols, elem):
        """レコード間のバイト間隔を検証して返します。未指定なら None (連続読み)。"""
        if stride is None:
            return None
        try:
            if isinstance(stride, str) and stride.strip().lower().startswith("0x"):
                value = int(stride, 16)
            else:
                value = int(stride)
        except (TypeError, ValueError):
            raise ValueError("stride は整数で指定してください。")
        if not cols:
            raise ValueError(
                "stride を使うときは columns (1 レコードから読む要素数) も"
                "指定してください。")
        if value < cols * elem:
            raise ValueError(
                "stride ({0}) が 1 行ぶんのサイズ ({1} = columns {2} × {3} バイト) "
                "より小さいです。".format(value, cols * elem, cols, elem))
        return value

    @staticmethod
    def _data_number_format(base, fmt):
        """値を 10 進で出すか 16 進で出すかを決めます。"""
        mode = (base or "auto").strip().lower()
        if mode not in ("auto", "dec", "hex"):
            raise ValueError("base は auto / dec / hex のいずれかにしてください。")
        if fmt in ("f32", "f64"):
            return "dec"
        if mode == "auto":
            return "hex" if (fmt in DATA_HEX_FORMATS
                             or fmt == DATA_FORMAT_HEX) else "dec"
        return mode

    @staticmethod
    def _data_render(value, fmt, number_format):
        """1 個の値を JSON へ出す形に整えます。"""
        if number_format != "hex" or fmt in ("f32", "f64"):
            return value
        if fmt == DATA_FORMAT_HEX:
            return "{0:02x}".format(value)
        width = DATA_FORMATS[fmt][1] * 2
        if value < 0:
            value &= (1 << (width * 4)) - 1
        return "0x{0:0{1}x}".format(value, width)

    def _annotate_values(self, values, blocks, elem):
        """ポインタらしき値に「その先に何があるか」を付けます。{値: 注釈} を返します。"""
        out = {}
        mask = (1 << (elem * 8)) - 1
        for value in set(values):
            if value is None or value <= 0:
                continue
            info = self._describe_address(value, blocks)
            if info:
                out["0x{0:0{1}x}".format(value & mask, elem * 2)] = info
        return out

    def _read_cstrings(self, address, target, block, bstart, available,
                       count, as_markdown):
        """NUL 終端文字列を count 件読みます (文字列テーブル用)。"""
        want = clamp_count(count, 16, 256)
        span = min(available, MAX_DATA_BYTES)
        raw = self._read_memory(block, target - bstart, span)

        items = []
        offset = 0
        skipped_empty = 0
        while len(items) < want and offset < len(raw):
            end = raw.find(b"\x00", offset)
            if end < 0:
                end = min(offset + MAX_CSTRING_LENGTH, len(raw))
                terminated = False
            else:
                terminated = True
            chunk = raw[offset:end]
            if len(chunk) > MAX_CSTRING_LENGTH:
                chunk = chunk[:MAX_CSTRING_LENGTH]
            if not chunk:
                # NUL パディング。文字列表を読むときのノイズなので
                # count を消費させずに飛ばす。
                skipped_empty += 1
                offset = end + 1
                continue
            items.append({
                "addr": "0x{0:08x}".format(target + offset),
                "length": len(chunk),
                "value": chunk.decode("utf-8", "replace"),
                "terminated": terminated,
            })
            offset = end + 1 if terminated else end

        result = {
            "address": address,
            "format": DATA_FORMAT_CSTRING,
            "block": block.get("name"),
            "requested": want,
            "count": len(items),
            "bytes_read": len(raw),
            "skipped_empty": skipped_empty,
            "truncated": len(items) < want,
            "note": "文字コードは UTF-8 として解釈しています。Shift_JIS 等の場合は "
                    "hex で読んで別途デコードしてください。",
        }
        self._mark_overlay(result, block)
        if as_markdown:
            lines = ["| addr | len | value |", "|---|---:|---|"]
            for item in items:
                text = item["value"].replace("|", "\\|").replace("\n", "\\n")
                lines.append("| `{0}` | {1} | {2} |".format(
                    item["addr"], item["length"], text))
            result["markdown"] = "\n".join(lines)
        else:
            result["items"] = items
        return result

    def _data_markdown(self, rows, row_addrs, values, target, elem, fmt,
                       number_format, cols, annotations):
        """読んだ値を Markdown の表にします (notes/*.md へそのまま貼れるように)。"""
        if not cols:
            # 折り返し指定が無いときは 1 列の縦持ちにする。
            lines = ["| addr | value |", "|---|---|"]
            for i, value in enumerate(values):
                lines.append("| `0x{0:08x}` | {1} |".format(
                    target + i * elem, self._data_render(value, fmt, number_format)))
            return "\n".join(lines)

        if fmt == DATA_FORMAT_HEX:
            lines = ["| addr | bytes | ascii |", "|---|---|---|"]
            for addr, row in zip(row_addrs, rows):
                text = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in row)
                lines.append("| `0x{0:08x}` | `{1}` | `{2}` |".format(
                    addr, " ".join("{0:02x}".format(b) for b in row),
                    text.replace("|", "\\|")))
            return "\n".join(lines)

        header = ["addr"] + ["+{0}".format(i * elem) for i in range(cols)]
        align = ["---"] + ["---:"] * cols
        if annotations:
            header.append("参照先")
            align.append("---")
        lines = ["| " + " | ".join(header) + " |",
                 "|" + "|".join(align) + "|"]
        mask = (1 << (elem * 8)) - 1
        for addr, row in zip(row_addrs, rows):
            cells = ["`0x{0:08x}`".format(addr)]
            cells += ["{0}".format(self._data_render(v, fmt, number_format))
                      for v in row]
            if annotations:
                notes = []
                for value in row:
                    info = annotations.get(
                        "0x{0:0{1}x}".format(value & mask, elem * 2))
                    if info:
                        notes.append(info.get("function") or info.get("string")
                                     or info.get("block"))
                cells.append(", ".join(str(x) for x in notes if x))
            lines.append("| " + " | ".join(cells) + " |")
        return "\n".join(lines)

    # --- ツール: export の世代差分 -------------------------------------
    def _snapshot_dir(self, create=True):
        """スナップショットの置き場 (`<project>/extracted/snapshots/`) の実体を返します。

        create=False (一覧・比較) のときは**作らず**、無ければ None を返します。
        snapshots/ が extracted/ の外を指すリンク / ジャンクションなら拒否します。
        """
        base = self._extract_dir(create=create)
        if base is None:
            return None
        path = base / "snapshots"
        if not path.exists() and not path.is_symlink():
            if not create:
                return None
            path.mkdir(parents=True, exist_ok=True)
        real = self._trusted_dir(path, "extracted/snapshots/")
        if real == base or not _path_within(real, base):
            raise ValueError("snapshots/ が extracted/ の外を指しています (リンク等)。")
        return real

    def _snapshot_files(self):
        """保存済みスナップショット (実体が snapshots/ 直下の *.json) を返します。作りません。"""
        folder = self._snapshot_dir(create=False)
        if folder is None:
            return []
        out = []
        for path in sorted(folder.glob("*.json")):
            try:
                real = path.resolve()
            except (OSError, RuntimeError):
                continue
            if real.parent == folder and real.is_file():
                out.append(real)
        return out

    @staticmethod
    def _read_snapshot(path):
        """スナップショット 1 件を上限付きで読みます。"""
        return json.loads(_read_text_capped(path, MAX_SMALL_JSON_BYTES, path.name))

    def _build_snapshot(self):
        """今の export の要約を作ります (差分を取るのに要るものだけ)。"""
        import datetime

        functions = {}
        for f in self._safe(lambda: self._load("functions.json"), []) or []:
            entry = f.get("entry")
            if entry:
                functions[entry] = f.get("name")
        labels = {}
        for row in _rows(self._safe(lambda: self._load("labels.json"), None),
                         "labels"):
            addr = (row or {}).get("address")
            if addr and row.get("name"):
                if addr not in labels or row.get("primary"):
                    labels[addr] = row["name"]
        comments = {}
        for row in self._safe(lambda: self._load("comments.json"), []) or []:
            if not isinstance(row, dict) or not row.get("address"):
                continue
            key = "{0}|{1}".format(row["address"], row.get("type"))
            text = row.get("comment") or ""
            # 本文そのものは持たない (大きくなるだけ)。変化の検出には長さ + 先頭で足りる。
            comments[key] = "{0}:{1}".format(len(text), text[:24])
        info = self._safe(lambda: self._load("program.json"), {}) or {}
        return {
            "schema_version": 1,
            "taken": datetime.datetime.now().isoformat(timespec="seconds"),
            "program_name": info.get("program_name"),
            "counts": {"functions": len(functions), "labels": len(labels),
                       "comments": len(comments)},
            "functions": functions,
            "labels": labels,
            "comments": comments,
        }

    def save_export_snapshot(self, name=None):
        """今の export の要約を `extracted/snapshots/` に保存します。

        次に `diff_exports` を呼ぶと「前回からどこが進んだか」が出ます。
        往復運用 (関数化 → 再 export → 読む) で、**同じ場所を二度解析しない**
        ためのものです。

        ★保存先は `<project_root>/extracted/` の配下だけです
          (`ghidra_exports/` には書きません)。既存ファイルも上書きしません。
        """
        snapshot = self._build_snapshot()
        safe = self._sanitize(str(name)) if name else "snapshot"
        if not safe.endswith(".json"):
            safe += ".json"
        _check_name_component(safe, "スナップショット")
        base = self._snapshot_dir()
        if not _path_within(base.resolve(), self._extract_dir()):
            raise ValueError("snapshots/ が extracted/ の外を指しています (リンク等)。")
        path = base / safe
        n = 1
        payload = json.dumps(snapshot, ensure_ascii=False).encode("utf-8")
        while True:
            try:
                with path.open("xb") as handle:   # 既存は上書きしない (排他作成)
                    handle.write(payload)
                break
            except FileExistsError:
                path = path.parent / "{0}_{1}.json".format(safe[:-5], n)
                n += 1
        return {
            "out_path": str(path),
            "taken": snapshot["taken"],
            "counts": snapshot["counts"],
            "note": ("次に diff_exports を呼ぶと、このスナップショットとの差分が"
                     "出ます。**解析を始める前に 1 回取っておく**のが使い方です。"
                     "保存先は extracted/ の配下だけで、ghidra_exports/ には"
                     "書きません。"),
        }

    def list_export_snapshots(self):
        """保存済みスナップショットを新しい順に返します。"""
        items = []
        for path in self._snapshot_files():
            try:
                data = self._read_snapshot(path)
            except (ValueError, OSError) as exc:
                items.append({"name": path.name, "problem": str(exc)})
                continue
            items.append({
                "name": path.name,
                "taken": data.get("taken"),
                "program_name": data.get("program_name"),
                "counts": data.get("counts"),
            })
        items.sort(key=lambda x: x.get("taken") or "", reverse=True)
        return {
            "total": len(items),
            "dir": str(self.project_root / "extracted" / "snapshots"),
            "snapshots": items,
            "note": ("save_export_snapshot で作り、diff_exports で比べます。"
                     if items else
                     "まだありません。save_export_snapshot で作ってください。"),
        }

    def diff_exports(self, snapshot=None, limit=DEFAULT_LIMIT):
        """前に取ったスナップショットと今の export を比べます。

        `diff_programs` は**別 Program 同士**の比較で、**同じ Program の時間差**は
        見られません。往復運用 (関数化 → 再 export → 読む) で
        「前回からどこが進んだか」を出すのがこのツールです。
        """
        files = self._snapshot_files()
        if not files:
            raise ValueError(
                "スナップショットがありません。先に save_export_snapshot を"
                "呼んでください (解析を始める前に 1 回取るのが使い方です)。")
        if snapshot:
            want = self._sanitize(str(snapshot))
            by_name = {p.name: p for p in files}
            path = by_name.get(want) or by_name.get(want + ".json")
            if path is None:
                raise ValueError(
                    "スナップショット '{0}' がありません。あるのは {1} です。".format(
                        snapshot, ", ".join(p.name for p in files)))
        else:
            # 一番新しいもの (taken で選ぶ。ファイル名順ではない)。
            def taken_of(p):
                try:
                    return self._read_snapshot(p).get("taken") or ""
                except (ValueError, OSError, AttributeError):
                    return ""
            path = max(files, key=taken_of)
        try:
            old = self._read_snapshot(path)
        except (ValueError, OSError) as exc:
            raise ValueError("スナップショットを読めません ({0})。".format(exc))

        now = self._build_snapshot()
        lim = clamp_limit(limit)
        warnings = []
        if old.get("program_name") and now.get("program_name") \
                and old["program_name"] != now["program_name"]:
            warnings.append(
                "★Program 名が違います ({0} → {1})。別のゲームのスナップショットを"
                "見ている可能性があります。".format(
                    old["program_name"], now["program_name"]))

        old_funcs = old.get("functions") or {}
        new_funcs = now["functions"]
        added = [{"entry": k, "name": new_funcs[k]}
                 for k in new_funcs if k not in old_funcs]
        removed = [{"entry": k, "name": old_funcs[k]}
                   for k in old_funcs if k not in new_funcs]
        renamed = [{"entry": k, "before": old_funcs[k], "after": new_funcs[k]}
                   for k in new_funcs
                   if k in old_funcs and old_funcs[k] != new_funcs[k]]

        old_labels = old.get("labels") or {}
        new_labels = now["labels"]
        labels_added = [{"address": k, "name": new_labels[k]}
                        for k in new_labels if k not in old_labels]
        labels_changed = [{"address": k, "before": old_labels[k],
                           "after": new_labels[k]}
                          for k in new_labels
                          if k in old_labels and old_labels[k] != new_labels[k]]

        old_cm = old.get("comments") or {}
        new_cm = now["comments"]
        comments_added = []
        for key in new_cm:
            if key not in old_cm:
                addr, _, ctype = key.partition("|")
                comments_added.append({"address": addr, "type": ctype})
        comments_changed = [
            {"address": k.partition("|")[0], "type": k.partition("|")[2]}
            for k in new_cm if k in old_cm and old_cm[k] != new_cm[k]]

        result = {
            "snapshot": path.name,
            "snapshot_taken": old.get("taken"),
            "now": now["taken"],
            "counts_before": old.get("counts"),
            "counts_after": now["counts"],
            "functions": {
                "added": len(added), "removed": len(removed),
                "renamed": len(renamed),
                "added_items": added[:lim],
                "removed_items": removed[:lim],
                "renamed_items": renamed[:lim],
            },
            "labels": {
                "added": len(labels_added), "changed": len(labels_changed),
                "added_items": labels_added[:lim],
                "changed_items": labels_changed[:lim],
            },
            "comments": {
                "added": len(comments_added), "changed": len(comments_changed),
                "added_items": comments_added[:lim],
                "changed_items": comments_changed[:lim],
            },
            "limit": lim,
            "note": ("スナップショットとの差分です。**増えた関数 / 付いた名前 / "
                     "書かれたコメント**が、前回からの進捗そのものです。"
                     "コメントの本文は持っていないので、中身は list_comments で"
                     "見てください。removed が出たときは、関数化を取り消したか "
                     "(apply_undefine)、別の Program のスナップショットを"
                     "見ています。"),
        }
        if warnings:
            result["warnings"] = warnings
        if not (added or removed or renamed or labels_added or labels_changed
                or comments_added or comments_changed):
            result["hint"] = (
                "差分が 0 件でした。再 export していないか、"
                "スナップショットを取った後に何も反映していません "
                "(apply の後は Ghidra GUI で export_context.py の実行が要ります)。")
        return result

    # --- ツール 10: export 鮮度・件数サマリ ---------------------------
    def get_export_status(self):
        """ghidra_exports/ の鮮度 (mtime) と件数サマリを返します (再 export は促すだけ)。"""
        files = {}
        for name in EXPORT_FILES:
            path = self.exports_dir / name
            files[name] = {
                "exists": path.is_file(),
                "mtime": self._mtime_iso(path) if path.is_file() else None,
                "size": path.stat().st_size if path.is_file() else None,
            }

        program = self._safe(lambda: self._load("program.json"), {})
        comments = self._safe(lambda: self._load("comments.json"), [])
        ai_comments = sum(1 for c in comments if c.get("is_ai_comment")) if isinstance(comments, list) else 0
        decompile_files = self._count_decompile()

        try:
            overlays, overlay_error = self._overlay_blocks(), None
        except ValueError as exc:
            # ★設定の誤りを黙って「登録なし」にしない (直すべきものが見えなくなる)。
            overlays, overlay_error = [], str(exc)
        overlay_status = {
            "total": len(overlays),
            "available": sum(1 for b in overlays if b.get("exported")),
            "names": [b.get("overlay") for b in overlays],
            "note": ("実行時に RAM へ読み込む外部ファイルの登録です。"
                     "詳細と重なりの警告は list_overlays で見てください。"
                     if overlays else
                     "登録なし。ステージデータ等を読むときは bridge_config.json "
                     "の overlays に書いてください (list_overlays 参照)。"),
        }
        if overlay_error:
            overlay_status["problem"] = (
                "bridge_config.json の overlays が読めません: {0}".format(overlay_error))
        obs_files, _rejected = self._safe(lambda: self._runtime_files(), ([], []))
        return {
            "memory": self._memory_summary(),
            "overlays": overlay_status,
            "runtime_observations": {
                "files": len(obs_files),
                "dir": str(self._runtime_dir()),
                "note": ("外部エミュレータで観測した実行時の記録です。"
                         "list_runtime_observations / get_runtime_range_evidence "
                         "で引けます。**観測 0 件は「未使用」ではありません。**"
                         if obs_files else
                         "観測ファイルなし。エミュレータのデバッガなどで観測した結果を "
                         "schemas/runtime_observations.schema.json の形で "
                         "runtime_observations/ に保存すると引けるようになります "
                         "(保存するのは人間か解析セッション。MCP は書きません)。"),
            },
            "address_translations": sorted(
                self._safe(lambda: self._translation_rules(), {})),
            "labels": self._label_summary(),
            "program_name": program.get("program_name") if isinstance(program, dict) else None,
            "source_model": program.get("source_model") if isinstance(program, dict) else None,
            "schema_version": program.get("schema_version") if isinstance(program, dict) else None,
            "counts": {
                "functions": self._count("functions.json"),
                "strings": self._count("strings.json"),
                "comments": len(comments) if isinstance(comments, list) else None,
                "ai_comments": ai_comments,
                "xrefs": self._count("xrefs.json"),
                "undefined_ranges": self._count("undefined_ranges.json"),
                "decompile_files": decompile_files,
                "datatypes": len(_rows(self._safe(
                    lambda: self._load("datatypes.json"), None), "datatypes")),
            },
            "decompile_hit_cap": decompile_files == 200,
            "files": files,
            "note": "再 export が必要な場合は Ghidra GUI で export_context.py を実行してください "
                    "(この MCP は Ghidra に書き込みません)。",
        }

    def _memory_summary(self):
        """メモリイメージ export の有無と、逆アセンブル可能かどうかを要約します。"""
        source = "memory export"
        if not (self.exports_dir / "memory_map.json").is_file():
            # 実行ファイルから供給できるならそれを報告する
            # (「使えない」と誤って伝えると、使える道具を使わずに手作業へ行く)。
            mm = self._safe(lambda: self._executable_memory_map(), None)
            if mm is None:
                return {
                    "available": False,
                    "note": "memory イメージ未 export。get_disassembly / "
                            "find_address_refs / read_data を使うには "
                            'bridge_config.json に "export_memory": true を足して'
                            "再 export してください。"
                            "source_model=executable なら実行ファイルからも読めますが、"
                            "実行ファイルを読めませんでした (許可ルートの外か、見つからない)。"
                            "外部の実行ファイルは、人間が bridge_config.json の "
                            "source_roots にそのフォルダを書き足すと読めます。",
                    "executable_rejected": list(getattr(self, "_exe_rejected", None) or []),
                }
            source = "executable"
        else:
            mm = self._safe(lambda: self._load("memory_map.json"), {})
        blocks = mm.get("blocks") if isinstance(mm, dict) else []
        blocks = blocks if isinstance(blocks, list) else []
        exported = [b for b in blocks if isinstance(b, dict) and b.get("exported")]
        try:
            arch = disasm.resolve_arch(mm).NAME
            arch_note = None
        except ValueError as exc:
            arch = None
            arch_note = str(exc)
        width_context = None
        if arch and getattr(disasm.get_arch(arch), "NEEDS_WIDTH_CONTEXT", False):
            # 65816: 命令長が M/X で変わるので、幅をどこから取るかも報告する。
            try:
                ctx = self._width_context([b for b in blocks if isinstance(b, dict)])
                width_context = ctx.summary()
                width_context["rom_check"] = getattr(ctx, "rom_check", None)
            except ValueError as exc:
                width_context = {"error": str(exc)}
        return {
            "width_context": width_context,
            "available": bool(exported),
            "source": source,
            "source_note": (
                "memory を export していないので、**実行ファイルから直接**"
                "読んでいます ({0})。未初期化ブロック (.bss 等) は"
                "ファイルに実体が無いので読めません。".format(mm.get("executable"))
                if source == "executable" else None),
            "arch": arch,
            "arch_note": arch_note,
            "endian": mm.get("endian"),
            "processor": mm.get("processor"),
            "blocks_exported": len(exported),
            "blocks_total": len(blocks),
            "exported_bytes": mm.get("exported_bytes"),
            "skipped": [{"name": b.get("name"), "reason": b.get("skipped_reason")}
                        for b in blocks
                        if isinstance(b, dict) and b.get("skipped_reason")
                        and b.get("skipped_reason") != "uninitialized"],
        }

    # --- ヘルパ -------------------------------------------------------
    def _paginate(self, items, offset, limit):
        """配列を offset/limit でページングし、total 付きで返します。"""
        try:
            off = max(0, int(offset))
        except (TypeError, ValueError):
            off = 0
        lim = clamp_limit(limit)
        return {
            "total": len(items),
            "offset": off,
            "limit": lim,
            "items": items[off:off + lim],
        }

    def _count(self, filename):
        """JSON 配列の件数を返します。読めなければ None。"""
        data = self._safe(lambda: self._load(filename), None)
        return len(data) if isinstance(data, list) else None

    def _count_decompile(self):
        """decompile/ 内の .c ファイル数を返します。"""
        if not self.decompile_dir.is_dir():
            return 0
        return sum(1 for p in self.decompile_dir.iterdir()
                   if p.is_file() and p.suffix == DECOMPILE_EXT)

    @staticmethod
    def _sanitize(name):
        """ファイル名に使えない文字をアンダースコアへ置換します。"""
        bad = "\\/:*?\"<>|"
        return "".join("_" if ch in bad else ch for ch in name)

    @staticmethod
    def _mtime_iso(path):
        """ファイルの更新時刻を ISO 文字列で返します。"""
        import datetime
        ts = path.stat().st_mtime
        return datetime.datetime.fromtimestamp(ts).isoformat(timespec="seconds")

    @staticmethod
    def _safe(func, default):
        """例外を握りつぶして default を返すヘルパーです。"""
        try:
            return func()
        except Exception:
            return default


def run_selftest(repo):
    """手元の export に対し、各ツールが期待どおり動くか確認します。"""
    print("=== selftest: {0} ===".format(repo.project_root))

    # JSON 系 ([1]〜[6]) は memory イメージだけを持つ export では動かないため、
    # 欠けていてもここで打ち切らず、逆アセンブル系 ([8]) まで進めます。
    try:
        run_json_selftest(repo)
    except ValueError as exc:
        print("[1-6] JSON 系はスキップ (export が揃っていません): {0}".format(str(exc)[:80]))

    run_disasm_selftest(repo)
    run_types_gp_selftest(repo)

    status = repo.get_export_status()
    print("[9] status counts={0} hit_cap={1}".format(
        status["counts"], status["decompile_hit_cap"]))
    print("[9b] memory={0}".format(status["memory"]))

    print("=== selftest 完了 ===")


def run_types_gp_selftest(repo):
    """gp / 構造体レイアウト / シンボル逆引きを実 export で確認します ([gp] [types] [sym])。

    gp-0x7ff0 (small data 領域の先頭) を引けるか、`_gp` を逆引きできるかを見ます。
    正解の値は Program ごとに違うので、ここでは表示だけです。
    """
    try:
        gp = repo._public_gp()
    except Exception as exc:                  # selftest は止めずに NG として表示する
        print("[gp] NG: gp の計算で例外: {0}".format(exc))
        gp = None
    if gp is None:
        print("[gp] MIPS ではないのでスキップ")
    elif not gp.get("gp"):
        print("[gp] gp を求められませんでした: {0}".format(
            " / ".join(w[:50] for w in gp.get("gp_warnings") or [])))
    else:
        print("[gp] gp={0} source={1} 候補={2}{3}".format(
            gp["gp"], gp["gp_source"],
            ",".join(c["source"] for c in gp["gp_candidates"]),
            " ★食い違いあり" if gp.get("gp_warnings") else ""))
        try:
            r = repo.resolve_gp_offset(-0x7ff0)
            print("[gp] -0x7ff0(gp) -> {0} {1}".format(r["address"], r.get("name") or "(名前なし)"))
        except ValueError as exc:
            print("[gp] resolve_gp_offset 不可: {0}".format(str(exc)[:60]))

    try:
        types = repo._datatypes()
        first = types["rows"][0] if types["rows"] else None
        if first is None:
            print("[types] datatypes.json に型がありません")
        else:
            lay = repo.get_struct_layout(first.get("path") or first["name"], flatten=True)
            print("[types] {0} 型 / 例 {1}: fields={2} flat={3}".format(
                len(types["rows"]), first["name"], len(lay.get("fields") or []),
                len(lay.get("flat") or [])))
            field = next((f["name"] for f in first.get("fields") or [] if f.get("name")), None)
            if field:
                hits = repo.find_field(field)["hits"]
                ok = any(h["type_path"] == first.get("path") for h in hits)
                print("[types] find_field({0}) -> {1} 件 {2}".format(
                    field, len(hits), "OK" if ok else "NG (元の型が出ない)"))
    except ValueError as exc:
        print("[types] スキップ: {0}".format(str(exc)[:60]))

    for name in ("_gp", "main"):
        r = repo.resolve_symbol(name)
        print("[sym] {0} -> {1}{2}".format(
            name, ", ".join("{0} ({1}/{2})".format(x["address"], x["kind"], x["source"])
                            for x in r["matches"][:3]) or "なし",
            " ★warnings あり" if r.get("warnings") else ""))


def run_json_selftest(repo):
    """既存の JSON 系ツール ([1]〜[6]) を確認します。"""
    info = repo.get_program_info()
    print("[1] program_name={0} language_id={1} source_model={2}".format(
        info.get("program_name"), info.get("language_id"), info.get("source_model")))

    fl = repo.list_functions(limit=5)
    print("[2] list_functions total={0} returned={1}".format(fl["total"], len(fl["items"])))

    first_entry = fl["items"][0]["entry"] if fl["items"] else None
    if first_entry:
        near = repo.get_functions_near_address(first_entry)
        print("[3] near {0}: containing={1} nearby={2}".format(
            first_entry, len(near["containing"]), len(near["nearby"])))

    sl = repo.list_strings(limit=5)
    print("[4] list_strings total={0} returned={1}".format(sl["total"], len(sl["items"])))

    if first_entry:
        xr = repo.get_xrefs(to_address=first_entry, limit=10)
        print("[5] xrefs to {0}: returned={1}".format(first_entry, xr["returned"]))

        # 索引版が全走査版と同じ結果になるか検証 (limit 上限まで)。
        to_i = parse_hex(first_entry)
        naive = [x for x in repo._load("xrefs.json")
                 if try_parse_hex(x.get("to")) == to_i]
        idx_all = repo.get_xrefs(to_address=first_entry, limit=MAX_LIMIT)
        expected = min(len(naive), MAX_LIMIT)
        ok = idx_all["returned"] == expected
        print("[5c] index vs naive: naive={0} index_returned={1} -> {2}".format(
            len(naive), idx_all["returned"], "OK" if ok else "NG"))

    try:
        repo.get_xrefs()
        print("[5b] NG: フィルタ無し get_xrefs がエラーになりませんでした。")
    except ValueError:
        print("[5b] OK: フィルタ無し get_xrefs は拒否されました。")

    if fl["items"]:
        try:
            dc = repo.get_decompiled_function(function_name=fl["items"][0]["name"],
                                              with_addresses=True)
            print("[6] decompile {0}: {1} chars".format(dc["file"], len(dc["code"])))
            if dc.get("line_map"):
                print("[6c] 行 -> 番地: {0}/{1} 行に番地あり 照合={2} ずらし={3}".format(
                    dc["line_map_mapped"], dc["line_map_lines"],
                    dc.get("line_map_verified"), dc["line_map_shift"]))
                if dc.get("line_map_warning"):
                    print("[6c] ★警告: {0}".format(dc["line_map_warning"][:70]))
            else:
                print("[6c] 行 -> 番地: 対応表なし ({0})".format(
                    (dc.get("line_map_hint") or "")[:60]))
        except ValueError as exc:
            print("[6] decompile 取得不可 (上限/失敗の可能性): {0}".format(exc))

    try:
        repo.get_decompiled_function(function_name="../../etc/passwd")
        print("[6b] NG: パストラバーサルが拒否されませんでした。")
    except ValueError:
        print("[6b] OK: パストラバーサルは拒否されました。")

    # ★前のセッションの結論が読み返せるか (これが無いと二度手間になる)。
    try:
        cm = repo.list_comments(limit=3)
        print("[6d] list_comments: 全 {0} 件 (うち [AI] {1} 件) 種別={2}".format(
            cm["total_comments"], cm["ai_comments"], cm["types"]))
        ai = repo.list_comments(ai_only=True, limit=1)
        ok = ai["matched"] <= cm["total_comments"]
        print("[6e] {0}: ai_only で絞れる -> {1} 件".format(
            "OK" if ok else "NG", ai["matched"]))
    except ValueError as exc:
        print("[6d] list_comments 取得不可: {0}".format(str(exc)[:60]))

    # ★変数メモ: 反映済みなら読みやすい疑似 C になるか。
    if fl["items"]:
        try:
            rn = repo.get_decompiled_function(
                function_name=fl["items"][0]["name"], resolve_pool=False,
                rename=True)
            if rn.get("code_renamed"):
                print("[6f] 変数メモ: {0} 個を適用 (出どころ={1})".format(
                    len(rn.get("renamed") or []), rn.get("rename_source")))
            else:
                print("[6f] 変数メモ: 未登録 (propose_variable_notes で提案できます)")
            ok = rn["code"] == repo.get_decompiled_function(
                function_name=fl["items"][0]["name"], resolve_pool=False)["code"]
            print("[6g] {0}: ★rename しても code は変わらない".format(
                "OK" if ok else "NG"))
        except ValueError:
            print("[6f] 変数メモ: 疑似 C が無いのでスキップ")


# MIPS デコーダの単体テスト。実データ不要なので必ず走ります。
# すべて合成の命令語です (番地・即値は検証用に選んだ値で、特定の Program 由来ではない)。
# 境界ケース (遅延スロット付き分岐・負の即値・j/jal の飛び先計算) を含みます。
DISASM_UNIT_CASES = (
    (0x00803021, 0x80020000, "addu $a2, $a0, $zero"),
    (0x00004821, 0x80020004, "addu $t1, $zero, $zero"),
    (0x3C028004, 0x80020008, "lui $v0, 0x8004"),
    (0x2442F000, 0x8002000C, "addiu $v0, $v0, -4096"),
    (0x3C048005, 0x80030000, "lui $a0, 0x8005"),
    (0x24841234, 0x80030004, "addiu $a0, $a0, 4660"),
    (0x00000000, 0x80010000, "nop"),
    (0x03E00008, 0x80010004, "jr $ra"),
    (0x0C012345, 0x80010008, "jal 0x80048d14"),
    (0x1440FFFB, 0x8001000C, "bne $v0, $zero, 0x8000fffc"),
    (0x8FBF0014, 0x80010010, "lw $ra, 20($sp)"),
    (0x27BDFFE8, 0x80010014, "addiu $sp, $sp, -24"),
    (0x00051880, 0x80030008, "sll $v1, $a1, 2"),
)

# SH-4 (SuperH, 16bit)。合成の命令語 (番地は検証用に選んだ値)。
# PC 相対 (mova / mov.l @(disp,pc) / bt / bra) は 4 バイト境界の扱いを見るため、
# わざと 4 の倍数でない番地に置いています。
SH4_UNIT_CASES = (
    (0x0009, 0x0C001000, "nop"),
    (0x000B, 0x0C001002, "rts"),
    (0xC709, 0x0C001006, "mova @(36,pc),r0  ; 0x0c00102c"),
    (0x4016, 0x0C001008, "lds.l @r0+,macl"),
    (0x0112, 0x0C00100A, "stc gbr,r1"),
    (0x010F, 0x0C001014, "mac.l @r0+,@r1+"),
    (0x6009, 0x0C00101A, "swap.w r0,r0"),
    (0x4009, 0x0C00101C, "shlr2 r0"),
    (0x402A, 0x0C001022, "lds r0,pr"),        # 0x0 系の sts と取り違えやすい
    (0x002A, 0x0C001024, "sts pr,r0"),        # その逆向き
    (0xD32D, 0x0C00103E, "mov.l @(180,pc),r3  ; 0x0c0010f4"),
    (0x8804, 0x0C001042, "cmp/eq #4,r0"),
    (0x8905, 0x0C001044, "bt 0x0c001052"),
    (0xA02E, 0x0C00104E, "bra 0x0c0010ae"),
    (0x402B, 0x0C001060, "jmp @r0"),
    (0x430B, 0x0C001062, "jsr @r3"),
    (0xE301, 0x0C001064, "mov #1,r3"),
    (0x2012, 0x0C001066, "mov.l r1,@r0"),
    (0x2118, 0x0C001068, "tst r1,r1"),
    (0xC237, 0x0C00106A, "mov.l r0,@(220,gbr)"),   # GBR 相対の書き戻し
    (0xF19D, 0x0C00106C, "fldi1 fr1"),             # capstone は FPU 非対応
    (0xF11D, 0x0C00106E, "flds fr1,fpul"),
    (0xF3FD, 0x0C001070, "fschg"),
)


ARM_UNIT_CASES = (
    # 期待値は capstone 5.0.7 と突き合わせ済み。命令語は汎用の形。
    (0xEA00002E, 0x08000000, "b 0x080000c0"),   # b (ROM エントリ)
    (0xE3A00012, 0x080000C0, "mov r0, #0x12"),   # mov r0,#0x12
    (0xE129F000, 0x080000C4, "msr cpsr_fc, r0"),   # msr cpsr_fc,r0
    (0xE59FD028, 0x080000C8, "ldr sp, [pc, #0x28]  ; =0x080000f8"),   # ldr sp,[pc,#0x28] (定数プール)
    (0xE28F0018, 0x080000DC, "add r0, pc, #0x18"),   # add r0,pc,#0x18
    (0xE5810000, 0x080000E0, "str r0, [r1]"),   # str r0,[r1]
    (0xE1A0E00F, 0x080000E8, "mov lr, pc"),   # mov lr,pc
    (0xE12FFF11, 0x080000EC, "bx r1"),   # bx r1
    (0xEB000010, 0x08000100, "bl 0x08000148"),   # bl
    (0xE92D4010, 0x08000104, "push {r4, lr}"),   # push {r4,lr} (stmdb sp!)
    (0xE8BD8010, 0x08000108, "pop {r4, pc}"),   # pop {r4,pc} (ldmia sp!)
    (0xE0000291, 0x0800010C, "mul r0, r1, r2"),   # mul
    (0xE10F0000, 0x08000110, "mrs r0, cpsr"),   # mrs r0,cpsr
    (0xE1D100B0, 0x08000114, "ldrh r0, [r1]"),   # ldrh
    (0xE1C100B0, 0x08000118, "strh r0, [r1]"),   # strh
    (0xE1010092, 0x0800011C, "swp r0, r2, [r1]"),   # swp
    (0xE3500000, 0x08000120, "cmp r0, #0"),   # cmp r0,#0
    (0x11000, 0x08000124, "andeq r1, r1, r0"),   # (未使用)
    (0xE0110002, 0x08000128, "ands r0, r1, r2"),   # ands
    (0x1A000005, 0x0800012C, "bne 0x08000148"),   # bne (条件付き分岐)
    (0xE1A00280, 0x08000130, "mov r0, r0, lsl #5"),   # mov + シフト (UAL の優先表記は lsl。符号化は mov)
)


THUMB_UNIT_CASES = (
    # word は word_at() が返す値 (下位 16bit=命令, 上位 16bit=次の 16bit。bl 用)。
    # 期待値は capstone 5.0.7 と突き合わせ済み。命令語は汎用の形。
    (0xB5F0, 0x08000B2C, "push {r4, r5, r6, r7, lr}"),   # push {r4-r7,lr}
    (0xBDF0, 0x08000C00, "pop {r4, r5, r6, r7, pc}"),   # pop {r4-r7,pc}
    (0xF8F3F0F1, 0x08000B36, "bl 0x080f1d20"),   # bl (16bit x2 = 1 命令)
    (0x4810, 0x08000B3A, "ldr r0, [pc, #0x40]  ; =0x08000b7c"),   # ldr r0,[pc,#0x40] (定数プール)
    (0x4A10, 0x08000B3C, "ldr r2, [pc, #0x40]  ; =0x08000b80"),   # ldr r2,[pc,...] 偶数ワード位置
    (0x4A10, 0x08000B3E, "ldr r2, [pc, #0x40]  ; =0x08000b80"),   # 同じ語でも奇数ワード位置だとプール位置が変わる
    (0xA004, 0x0803DB18, "adr r0, 0x0803db2c"),   # adr r0,<label> (add Rd,pc,#imm)
    (0x4770, 0x08001000, "bx lr"),   # bx lr (return)
    (0x0000, 0x08001002, "movs r0, r0"),   # lsl #0 は movs
    (0x0849, 0x08001004, "lsrs r1, r1, #1"),   # lsrs
    (0x1C40, 0x08001006, "adds r0, r0, #1"),   # adds Rd,Rs,#1
    (0x2064, 0x08001008, "movs r0, #0x64"),   # movs r0,#0x64
    (0x4240, 0x0800100A, "rsbs r0, r0, #0"),   # rsbs (neg)
    (0x4348, 0x0800100C, "muls r0, r1"),   # muls
    (0x5618, 0x0800100E, "ldrsb r0, [r3, r0]"),   # ldrsb
    (0x5E18, 0x08001010, "ldrsh r0, [r3, r0]"),   # ldrsh
    (0x8858, 0x08001012, "ldrh r0, [r3, #2]"),   # ldrh 即値オフセット (2 倍)
    (0xD1F5, 0x08001018, "bne 0x08001006"),   # bne (後方分岐)
    (0xE7FE, 0x0800101A, "b 0x0800101a"),   # b 自分自身 (無限ループ)
    (0xDF06, 0x0804A5DC, "svc #6"),   # svc #6 (BIOS 呼び出し)
    (0xB082, 0x0800101E, "sub sp, #8"),   # sub sp,#8
    (0x4694, 0x08001020, "mov r12, r2"),   # mov r12,r2 (上位レジスタ)
    (0xC30E, 0x08001014, "stmia r3!, {r1, r2, r3}"),   # stmia (capstone は stm と書く別名)
    (0xCB0E, 0x08001016, "ldmia r3!, {r1, r2, r3}"),   # ldmia (capstone は ldm と書く別名)
)

def _run_unit_cases(tag, arch, cases):
    """1 アーキぶんのデコーダ単体テストを回します。"""
    ng = 0
    module = disasm.get_arch(arch)
    for word, addr, expected in cases:
        got = module.decode(word, addr)["text"]
        if got != expected:
            ng += 1
            print("[{0}] NG: 0x{1:x} @0x{2:08x} -> '{3}' (期待 '{4}')".format(
                tag, word, addr, got, expected))
    print("[{0}] {1} decoder unit: {2}/{3} OK".format(
        tag, arch, len(cases) - ng, len(cases)))
    return ng


def run_disasm_unit_test():
    """各アーキのデコーダを既知の命令語で検証します (実データ不要)。"""
    _run_unit_cases("8", "mips", DISASM_UNIT_CASES)
    _run_unit_cases("8a", "sh4", SH4_UNIT_CASES)
    _run_unit_cases("8a1", "arm", ARM_UNIT_CASES)
    _run_unit_cases("8a2", "thumb", THUMB_UNIT_CASES)

    # SH-4 は memory_map.json の processor / language_id / platform_profile の
    # どれからでも解決できること。
    for mm in ({"processor": "SuperH", "language_id": "SuperH4:LE:32:default"},
               {"language_id": "SuperH4:LE:32:default"},
               {"platform_profile": "sh4"}):
        got = disasm.resolve_arch(mm).NAME
        if got != "sh4":
            print("[8b] NG: {0} -> {1} (期待 sh4)".format(mm, got))
            break
    else:
        print("[8b] OK: SH-4 は processor / language_id / platform_profile から解決できます。")

    # ARM (arm / thumb)。ARM モードへ解決できること、
    # および Thumb は disasm_arch で明示的に選べることを確認する。
    got = disasm.resolve_arch({"processor": "ARM", "language_id": "ARM:LE:32:v4t"}).NAME
    if got != "arm":
        print("[8c0] NG: ARM -> {0} (期待 arm)".format(got))
    else:
        print("[8c0] OK: ARM は arm モジュールへ解決されます。")

    got = disasm.resolve_arch({"disasm_arch": "thumb", "processor": "ARM",
                               "language_id": "ARM:LE:32:v4t"}).NAME
    if got != "thumb":
        print("[8c1] NG: disasm_arch=thumb -> {0} (期待 thumb)".format(got))
    else:
        print("[8c1] OK: disasm_arch で Thumb を既定にできます。")

    got = disasm.resolve_arch({"processor": "PowerPC",
                               "language_id": "PowerPC:BE:32:Gekko_Broadway"}).NAME
    if got != "ppc":
        print("[8c2] NG: PowerPC -> {0} (期待 ppc)".format(got))
    else:
        print("[8c2] OK: PowerPC は ppc モジュールへ解決されます "
              "(GameCube / Wii。★ビッグエンディアン)。")

    try:
        disasm.resolve_arch({"processor": "x86", "language_id": "x86:LE:32:default"})
        print("[8c3] NG: 未対応アーキ (x86) がエラーになりませんでした。")
    except ValueError as exc:
        print("[8c3] OK: 未対応アーキは拒否されました: {0}".format(str(exc)[:60]))


def run_disasm_selftest(repo):
    """memory イメージが export されていれば get_disassembly を実行します。"""
    run_disasm_unit_test()

    try:
        mm, blocks = repo._exported_blocks()
    except ValueError as exc:
        print("[8c] memory イメージ無しのためスキップ: {0}".format(str(exc)[:80]))
        return

    start = try_parse_hex(blocks[0].get("start"))
    dis = repo.get_disassembly("0x{0:x}".format(start), count=4)
    print("[8c] get_disassembly @{0} arch={1} block={2} returned={3}".format(
        dis["address"], dis["arch"], dis["block"], dis["returned"]))
    for item in dis["instructions"]:
        print("      {0}  {1}  {2}".format(item["addr"], item["bytes"], item["text"]))

    if getattr(disasm.get_arch(dis["arch"]), "VARIABLE_LENGTH", False):
        print("[8d] skip: {0} は可変長 (バイト境界) なので非境界の検査はありません "
              "(CDL の命令の途中なら alignment_warning が出ます)。".format(dis["arch"]))
    else:
        try:
            repo.get_disassembly("0x{0:x}".format(start + 1), count=1)
            print("[8d] NG: 非境界アドレスがエラーになりませんでした。")
        except ValueError:
            print("[8d] OK: 非境界アドレスは拒否されました。")

    try:
        repo.get_disassembly("0x1", count=1)
        print("[8e] NG: 範囲外アドレスがエラーになりませんでした。")
    except ValueError:
        print("[8e] OK: 範囲外アドレスは拒否されました。")

    # find_address_refs: 索引構築 → 同じクエリを 2 回投げてキャッシュが効くか見る。
    import time
    t0 = time.time()
    refs = repo.find_address_refs("0x{0:x}".format(start))
    build_ms = (time.time() - t0) * 1000.0
    t0 = time.time()
    repo.find_address_refs("0x{0:x}".format(start))
    cached_ms = (time.time() - t0) * 1000.0
    print("[8f] find_address_refs total={0} 索引構築={1:.0f}ms キャッシュ後={2:.2f}ms".format(
        refs["total"], build_ms, cached_ms))

    band = repo.find_address_refs("0x{0:x}".format(start), mask="0xffff0000", limit=3)
    print("[8g] 帯域検索 (mask=0xffff0000) total={0} returned={1}".format(
        band["total"], band["returned"]))

    try:
        repo.find_address_refs("0x{0:x}".format(start), mask=0)
        print("[8h] NG: mask=0 がエラーになりませんでした。")
    except ValueError:
        print("[8h] OK: mask=0 は拒否されました。")

    run_data_selftest(repo, blocks)
    run_analysis_selftest(repo, blocks)
    run_struct_selftest(repo, blocks)
    run_exec_selftest(repo, blocks)


def run_data_selftest(repo, blocks):
    """read_data (テーブルの中身を読む) を確認します。"""
    start = try_parse_hex(blocks[0].get("start"))
    addr = "0x{0:x}".format(start)

    dump = repo.read_data(addr, format="hex", count=32)
    print("[10a] read_data hex: count={0} columns={1} rows={2}".format(
        dump["count"], dump["columns"], len(dump.get("rows", []))))

    table = repo.read_data(addr, format="s16", count=12, columns=3)
    ok = all(len(r["values"]) == 3 for r in table["rows"])
    print("[10b] read_data s16 columns=3: rows={0} 各行3列={1}".format(
        len(table["rows"]), "OK" if ok else "NG"))

    strided = repo.read_data(addr, format="s16", count=9, columns=3, stride=16)
    gaps = [int(r["addr"], 16) for r in strided["rows"]]
    ok = all(b - a == 16 for a, b in zip(gaps, gaps[1:]))
    print("[10c] read_data stride=16: rows={0} 間隔が16={1}".format(
        len(gaps), "OK" if ok else "NG"))

    md = repo.read_data(addr, format="u32", count=8, columns=2, as_markdown=True)
    lines = md["markdown"].splitlines()
    ok = len(lines) >= 3 and lines[0].startswith("| addr") and "rows" not in md
    print("[10d] as_markdown: {0} 行, 先頭='{1}' -> {2}".format(
        len(lines), lines[0][:24], "OK" if ok else "NG"))

    hexed = repo.read_data(addr, format="u32", count=2)
    ok = all(isinstance(v, str) and v.startswith("0x") for v in hexed["values"])
    print("[10e] u32 は既定で 16 進表記: {0} -> {1}".format(
        hexed["values"], "OK" if ok else "NG"))
    dec = repo.read_data(addr, format="u32", count=2, base="dec")
    ok = all(isinstance(v, int) for v in dec["values"])
    print("[10f] base=dec で 10 進: {0} -> {1}".format(
        dec["values"], "OK" if ok else "NG"))

    rec = repo.read_data(addr, record="id:u8,dx:s8,dy:s8,dz:s8,dw:s8", count=4)
    ok = (rec["record_size"] == 5
          and all(len(r["values"]) == 5 for r in rec["records"]))
    print("[10h] record='u8,s8x4': size={0} records={1} 各行5列={2}".format(
        rec["record_size"], rec["count"], "OK" if ok else "NG"))
    recmd = repo.read_data(addr, record="id:u8,dx:s8", count=3,
                           as_markdown=True)
    ok = recmd["markdown"].splitlines()[0].startswith("| addr | id | dx")
    print("[10i] record + as_markdown: 先頭='{0}' -> {1}".format(
        recmd["markdown"].splitlines()[0][:28], "OK" if ok else "NG"))

    fmts = repo.list_record_formats()
    print("[10j] record_formats: {0} 件 {1}".format(
        fmts["total"], [x["name"] for x in fmts["record_formats"]][:4]))
    bad = [x for x in fmts["record_formats"] if x.get("problem")]
    if bad:
        print("[10j] ★壊れた定義: {0}".format(
            ", ".join("{0} ({1})".format(x["name"], x["problem"][:30])
                      for x in bad)))

    for name, kw in (
            ("未対応 format", {"format": "u24"}),
            ("stride のみ (columns 無し)", {"format": "u16", "stride": 8}),
            ("stride < 行サイズ", {"format": "u16", "columns": 4, "stride": 4}),
            ("record の未対応型", {"record": "u8,zzz"}),
            ("record + columns", {"record": "u8,u8", "columns": 2}),
            ("base 不正", {"format": "u8", "base": "oct"})):
        try:
            repo.read_data(addr, **kw)
            print("[10g] NG: {0} がエラーになりませんでした。".format(name))
        except ValueError:
            print("[10g] OK: {0} は拒否されました。".format(name))


def run_struct_selftest(repo, blocks):
    """構造体フィールド / 定数プール / 逆引きポインタを確認します。

    どの Program でも通る一般の確認だけを行います。
    「動いた」と「正しい答えが出た」は別なので、答えが分かっている Program では
    既知値の突き合わせを足してください (公開コピーには含めていません)。
    """
    lo, hi = repo._block_range(blocks[0])

    # --- 定数プール: イメージ内の任意の番地を引けること ---
    pool = repo.resolve_pool("0x{0:x}".format(lo), count=2)
    print("[12a] resolve_pool({0}): {1} 件 / 先頭 = {2} ({3})".format(
        "0x{0:x}".format(lo), len(pool["pool"]), pool["pool"][0]["value"],
        pool["pool"][0]["points_to"]))
    named = repo.resolve_pool("DAT_{0:08x}".format(lo))
    print("[12b] {0}: DAT_ 名でも引ける".format(
        "OK" if named["pool"][0]["value"] == pool["pool"][0]["value"] else "NG"))

    # --- 逆引きポインタ: 0 件でも「探した範囲」と hint を返すこと ---
    miss = repo.find_pointers_to("0x0badf00d")
    ok = (miss["total"] == 0 and "hint" in miss and miss["scanned"])
    print("[12c] {0}: 0 件のとき hint と走査範囲を返す (「参照が無い」と"
          "誤読させない)".format("OK" if ok else "NG"))

    # --- 構造体フィールド: decompile が無ければ、その旨をエラーで言うこと ---
    if not repo._decompile_files():
        try:
            repo.find_struct_field_uses("0x{0:x}".format(lo), 0x10)
            print("[12d] NG: decompile が無いのにエラーになりませんでした。")
        except ValueError as exc:
            ok = "decompile" in str(exc)
            print("[12d] {0}: decompile が無いことを理由つきで拒否 ({1})".format(
                "OK" if ok else "NG", str(exc)[:44]))
    else:
        zero = repo.find_struct_field_uses("0x{0:x}".format(hi - 0x10), 0x10)
        ok = "hint" in zero
        print("[12d] {0}: 0 件のとき hint を返す (「使われていない」と"
              "結論させない)".format("OK" if ok else "NG"))

    # --- 平行ポインタ表: 付けなければ従来どおりであること ---
    plain = repo.find_pointer_tables("0x{0:x}".format(lo), "0x{0:x}".format(hi),
                                     min_count=8, limit=5)
    print("[12e] {0}: detect_parallel 無しでは parallel_groups を作らない".format(
        "OK" if plain.get("parallel_groups") is None else "NG"))

    # ★特定の Program の既知値との突き合わせ ([12f]〜[12j]) は、公開コピーでは
    #   外しています (実ゲームの export に依存するため)。手元の Program で
    #   正解が分かっているなら、ここに同じ形で足してください。
    print("[12f] 既知値の突き合わせは公開コピーでは省略")


def run_exec_selftest(repo, blocks):
    """実行ファイル供給 / 未関数化の洗い出し / 変換規則を確認します。"""
    import pathlib

    # --- 実行ファイル供給 / 未関数化の洗い出し / 変換規則 ---
    exe = repo._safe(lambda: repo._executable_image(), None)
    mm2 = repo._safe(lambda: repo._exported_blocks()[0], {}) or {}
    if mm2.get("source") == "executable":
        print("[13a] memory 未 export だが実行ファイルから供給中: {0} ({1}) / "
              "ブロック {2}".format(
                  pathlib.Path(mm2.get("executable") or "?").name,
                  mm2.get("executable_kind"), len(mm2.get("blocks") or [])))
    else:
        print("[13a] memory export あり (実行ファイル供給は使っていない)")
    if exe is not None:
        start, _end = repo._block_range(blocks[0])
        off = exe.file_offset(start)
        back = exe.address_of(off) if off is not None else None
        if off is None:
            print("[13b] 0x{0:x} は実行ファイルに載っていないので往復確認は"
                  "スキップ ({1})".format(start, exe.path.name))
        else:
            ok = back == start
            print("[13b] {0}: アドレス <-> ファイル内 offset が往復する "
                  "(0x{1:x} <-> 0x{2:x})".format("OK" if ok else "NG",
                                                 start, off))
    else:
        print("[13b] 実行ファイルが見つからないのでスキップ")

    rules = sorted(repo._safe(lambda: repo._translation_rules(), {}))
    print("[13c] 使える変換規則: {0}".format(rules or "(なし)"))
    if "ee_kseg0_to_ram" in rules:
        got = repo.translate_address("0x8093ec14", "ee_kseg0_to_ram")
        ok = got["result"] == "0x0093ec14"
        print("[13d] {0}: EE 0x8093ec14 -> {1} (RAM ダンプ / ヘックスエディタ表示)"
              .format("OK" if ok else "NG", got["result"]))

    try:
        undef = repo.find_undefined_targets(addresses=[
            "0x{0:x}".format(repo._block_range(blocks[0])[0])], limit=5)
        print("[13e] find_undefined_targets: 候補 {0} / 既に関数 {1} / "
              "未関数化 {2}".format(undef["candidates"], undef["already_defined"],
                                    undef["undefined"]))
    except ValueError as exc:
        print("[13e] find_undefined_targets: {0}".format(str(exc)[:60]))


def run_analysis_selftest(repo, blocks):
    """解析ツール (find_writers / expand_switch / find_function_entry / 表検出) を確認します。

    アーキ固有フックを持たないアーキでは「未対応」と明示エラーになることも確認します
    (黙って空を返すと「無い」と誤読されるため)。
    """
    start = try_parse_hex(blocks[0].get("start"))
    addr = "0x{0:x}".format(start)
    mm, _ = repo._exported_blocks()
    arch_mod = disasm.resolve_arch(mm)
    # ★フックの有無は**ツール単位**で違う。thumb / arm は find_function_entry
    #   だけ持ち、find_writers / expand_switch は持たない。まとめて
    #   「このアーキは対応/未対応」と判定すると、対応済みのツールまで
    #   「未対応エラーが出ない」と誤判定する。
    checks = (("find_writers", lambda: repo.find_writers(addr)),
              ("expand_switch", lambda: repo.expand_switch(addr)),
              ("find_function_entry", lambda: repo.find_function_entry(addr)),
              ("list_call_sites", lambda: repo.list_call_sites(addr)),
              ("find_calls_to", lambda: repo.find_calls_to(addr)),
              ("find_path", lambda: repo.find_path(addr, addr)),
              ("list_memory_args", lambda: repo.list_memory_args(addr)),
              ("lint_stale_register", lambda: repo.lint_stale_register(function=addr)))
    for name, call in checks:
        if hasattr(arch_mod, name):
            continue
        try:
            call()
            print("[11] NG: {0} が {1} で未対応エラーになりませんでした。".format(
                name, arch_mod.NAME))
        except ValueError as exc:
            ok = "未対応" in str(exc)
            print("[11] {0}: {1} は {2} で未対応と明示 ({3})".format(
                "OK" if ok else "NG", name, arch_mod.NAME, str(exc)[:40]))

    if hasattr(arch_mod, "find_writers"):
        writers = repo.find_writers(addr)
        print("[11a] find_writers({0}): pools={1} loads={2} 書込={3} 読出={4}".format(
            addr, writers["pool_count"], writers["load_count"],
            len(writers["writers"]), len(writers["readers"])))
        ok = "hint" in writers if not writers["writers"] else "hint" not in writers
        print("[11b] {0}: 書き込み 0 件のときだけ hint が付く".format("OK" if ok else "NG"))

    if hasattr(arch_mod, "find_function_entry"):
        entry = repo.find_function_entry(addr)
        print("[11c] find_function_entry({0}): entry={1} balanced={2} conf={3}".format(
            addr, entry.get("entry"), entry.get("balanced"), entry.get("confidence")))

    if hasattr(arch_mod, "find_calls_to"):
        # 分岐を辿る解析 (65816)。selftest では「落ちずに答えが返る」ことだけ見る。
        calls = repo.find_calls_to(addr)
        print("[11m] find_calls_to({0}): total={1} 種別={2} 境界OK={3} 却下={4}".format(
            addr, calls["total"], calls["by_kind"], calls["boundary_ok"],
            calls["boundary_rejected"]))
        lint = repo.lint_stale_register(function=addr)
        print("[11n] lint_stale_register({0}): severity={1}".format(
            addr, lint["severity_counts"]))

    if hasattr(arch_mod, "expand_switch"):
        try:
            repo.expand_switch(addr)
            print("[11d] expand_switch: 実行できました")
        except ValueError as exc:
            # ★アーキ固有の語 (SH-4 の braf / MIPS の jr) で判定しないこと。
            #   ここで見たいのは「スイッチでない番地を**理由つきで**拒否したか」。
            ok = ("ではありません" in str(exc)) or ("見つかりません" in str(exc))
            print("[11d] {0}: スイッチでない番地は理由つきで拒否 ({1})".format(
                "OK" if ok else "NG", str(exc)[:44]))


    lo, hi = repo._block_range(blocks[0])
    tables = repo.find_pointer_tables("0x{0:x}".format(lo),
                                      "0x{0:x}".format(min(hi, lo + 0xFF)),
                                      min_entries=4, limit=3)
    print("[11e] find_pointer_tables: total={0} returned={1}".format(
        tables["total"], tables["returned"]))

    try:
        desc = repo.describe_data(addr, count=2)
        print("[11f] describe_data({0}): stride={1} element={2} records={3}".format(
            addr, desc["guessed_stride"], desc["element_stride"],
            desc["record_count"]))
    except ValueError as exc:
        print("[11f] describe_data: 周期なしとして拒否 ({0})".format(str(exc)[:40]))

    refs = repo.find_address_refs(addr, range_end="0x{0:x}".format(
        min(hi, lo + 0x400)))
    print("[11g] range 検索: total={0} 分岐除外={1}".format(
        refs["total"], refs["branches_excluded"]))

    if hasattr(arch_mod, "list_call_sites"):
        # 実 export では「よく呼ばれている関数」を 1 つ選んで回す。
        funcs = repo._safe(lambda: repo._load("functions.json"), []) or []
        target = None
        for f in funcs:
            entry = try_parse_hex(f.get("entry") or "")
            if entry is not None and repo._find_block(entry, blocks) is not None:
                target = f
                break
        if target is None:
            print("[11h] list_call_sites: 対象にできる関数がありません (スキップ)")
        else:
            sites = repo.list_call_sites(target["entry"], limit=5)
            consts = sum(len(v) for v in sites["constants"].values())
            print("[11h] list_call_sites({0}): total={1} 定数={2} "
                  "アドレスだけ取得={3}".format(
                      target.get("name"), sites["total"], consts,
                      len(sites["address_taken"])))
            ok = ("hint" in sites) if not sites["total"] else ("hint" not in sites)
            print("[11i] {0}: 0 件のときだけ hint が付く".format("OK" if ok else "NG"))

    if hasattr(arch_mod, "find_immediate"):
        # 0 はどのコードにも大量にあるので、当たるかどうかの確認に使える。
        imm = repo.find_immediate(1, limit=3)
        print("[11k] find_immediate(1): total={0} 種別={1}".format(
            imm["total"], imm["by_kind"]))
        miss = repo.find_immediate("0x7ffe1357", limit=1)
        ok = ("hint" in miss) if not miss["total"] else ("hint" not in miss)
        print("[11k] {0}: 0 件のときだけ hint が付く".format("OK" if ok else "NG"))
    else:
        try:
            repo.find_immediate(1)
            print("[11k] NG: find_immediate が {0} で未対応エラーになりませんでした。".format(
                arch_mod.NAME))
        except ValueError as exc:
            ok = "未対応" in str(exc)
            print("[11k] {0}: find_immediate は {1} で未対応と明示".format(
                "OK" if ok else "NG", arch_mod.NAME))

    tims = repo.find_tim_blocks(limit=3)
    print("[11l] find_tim_blocks: {0} 件{1}".format(
        tims["total"],
        " 先頭={0}".format(tims["items"][0]["address"]) if tims["items"] else ""))

    overlays = repo.list_overlays()
    print("[11j] list_overlays: {0}/{1} 件が利用可能{2}".format(
        overlays["available"], overlays["total"],
        " (" + ", ".join(str(x.get("overlay")) for x in overlays["overlays"]) + ")"
        if overlays["total"] else ""))
    bad = [x for x in overlays["overlays"] if x.get("problem")]
    if bad:
        print("[11j] ★問題のあるオーバーレイ: {0}".format(
            ", ".join("{0} ({1})".format(x["overlay"], x["problem"][:30])
                      for x in bad)))


# 複数 Program モードで同時に「熱い」状態に保つ Program 数の既定値。
# ExportRepo は xrefs 索引 (46 万件) や 16MB のメモリイメージを抱えるので、
# 際限なく持つとメモリを食う。超えたら最も長く使っていないものを捨てる。
DEFAULT_MAX_HOT_PROGRAMS = 3


def parse_program_registry(path):
    """mcp_registry.json から {キー: {root, label}} と既定 Program を読みます。

    書式は samples/mcp_registry.sample.json を参照してください。2 形式を読みます。
    (別の管理ツールで同じファイルを書いている場合は、形式を変えるときに**両方**
    直してください。)

        旧 (1 Program)   "game_a": {"root": "...", "label": "..."}
        新 (複数 Program) "game_b": {"programs": {"main": {"root": "..."}, ...}}

    複数形式のキーは `game_b:main` のように `ゲーム:Program` になります。

    読めなければ ValueError を投げます (稼働中の読み直しで**サーバを落とさない**ため)。
    起動時は load_program_registry を使ってください。
    """
    path = Path(path)
    if not path.is_file():
        raise ValueError(
            "レジストリが見つかりません: {0}\n"
            "--registry <path> で場所を指定するか、"
            "道具箱の 1 つ上に mcp_registry.json を置いてください "
            "(書式は samples/mcp_registry.sample.json)。".format(path))
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ValueError("レジストリを読めません: {0}".format(exc))
    if size > MAX_SMALL_JSON_BYTES:
        raise ValueError("レジストリが大きすぎます ({0} バイト > 上限 {1})。".format(
            size, MAX_SMALL_JSON_BYTES))
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("レジストリの JSON が壊れています: {0}".format(exc))
    except (OSError, UnicodeDecodeError) as exc:
        # 保存中でロックされている / 書きかけ、など。
        raise ValueError("レジストリを読めません: {0}".format(exc))
    if not isinstance(data, dict) or not isinstance(data.get("games") or {}, dict):
        raise ValueError(
            "レジストリの最上位 / games が JSON オブジェクトではありません: {0}".format(path))

    programs = {}
    for name, game in (data.get("games") or {}).items():
        if name.startswith("_") or not isinstance(game, dict):
            continue
        sub = game.get("programs")
        if isinstance(sub, dict) and sub:
            for prog, spec in sub.items():
                if prog.startswith("_") or not isinstance(spec, dict):
                    continue
                if not spec.get("root"):
                    continue
                label = spec.get("label") or game.get("label") or ""
                programs["{0}:{1}".format(name, prog)] = {
                    "root": spec["root"], "label": label}
        elif game.get("root"):
            programs[name] = {"root": game["root"],
                              "label": game.get("label") or ""}
    if not programs:
        raise ValueError(
            "レジストリに Program が 1 つもありません: {0}".format(path))
    return programs, data.get("default_program")


def load_program_registry(path):
    """起動時用の parse_program_registry です。読めなければ SystemExit で止めます。"""
    try:
        return parse_program_registry(path)
    except ValueError as exc:
        raise SystemExit("エラー: {0}".format(exc))


def _hex32(value):
    """32bit アドレスを 0x........ 表記にします。"""
    return "0x{0:08x}".format(value & 0xFFFFFFFF)


# ---------------------------------------------------------------------------
# Program をまたぐ道具 (検索 / 差分)
#
# ★ここだけは 1 つの ExportRepo で完結しません。resolver から Program を順に
#   取り出して回します。常駐数は resolver 側の LRU で抑えられるので、
#   13 Program を回してもメモリは 3 つぶんまでしか増えません。
# ---------------------------------------------------------------------------

def _load_items(repo, name, key=None):
    """export の JSON を list として読みます (無ければ空)。"""
    try:
        data = repo._load(name)
    except Exception:
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if key and isinstance(data.get(key), list):
            return data[key]
        for value in data.values():
            if isinstance(value, list):
                return value
    return []


def _func_map(repo):
    """{入口アドレス(int): 関数名} を返します。"""
    out = {}
    for f in _load_items(repo, "functions.json", "functions"):
        entry = try_parse_hex(f.get("entry") or "")
        if entry is not None:
            out[entry] = f.get("name")
    return out


def search_programs_impl(resolver, query, kind="strings", limit=DEFAULT_LIMIT,
                    programs=None, align=1, ignore_case=True):
    """**全 Program を横断して**探します。

    「この文字列 / バイト列 / 関数名はどの Program にある?」に一発で答えます。
    1 ゲームに複数 Program がある構成 (EXE 本体 + オーバーレイ、ROM + 展開後、
    製品版 + 修正版) で特に効きます。

    kind:
      - `strings`   … strings.json の値を部分一致 (既定)
      - `functions` … 関数名を部分一致
      - `bytes`     … memory イメージを AOB 検索 (`??` ワイルドカード可)
    """
    known = resolver.keys()
    keys = list(programs) if programs else known
    unknown = [k for k in keys if k not in known]
    if unknown:
        raise ValueError(
            "program '{0}' はレジストリにありません。使えるキー: {1}".format(
                ", ".join(unknown), ", ".join(known)))
    lim = clamp_limit(limit)
    kind = (kind or "strings").strip().lower()
    if kind not in ("strings", "functions", "bytes"):
        raise ValueError(
            "kind は strings / functions / bytes のいずれかです (指定: {0})。".format(kind))
    if kind == "bytes":
        needle, mask = _parse_aob(query)
    else:
        if not isinstance(query, str) or not query:
            raise ValueError("query を指定してください。")
        probe = query.lower() if ignore_case else query

    results = []
    errors = {}
    grand = 0
    for key in keys:
        try:
            _, repo = resolver.get(key, remember=False)
        except ValueError as exc:
            errors[key] = str(exc)
            continue
        hits = []
        total = 0
        try:
            if kind == "strings":
                for s in _load_items(repo, "strings.json", "strings"):
                    value = s.get("value") or ""
                    hay = value.lower() if ignore_case else value
                    if probe in hay:
                        total += 1
                        if len(hits) < lim:
                            hits.append({"address": s.get("address"),
                                         "value": value,
                                         "refs": len(s.get("referenced_from") or [])})
            elif kind == "functions":
                for f in _load_items(repo, "functions.json", "functions"):
                    name = f.get("name") or ""
                    hay = name.lower() if ignore_case else name
                    if probe in hay:
                        total += 1
                        if len(hits) < lim:
                            hits.append({"entry": f.get("entry"), "name": name})
            else:
                mm, blocks = repo._exported_blocks()
                for blk in _scannable(blocks):
                    if not _has_bytes(blk):
                        continue
                    bstart, _ = repo._block_range(blk)
                    data = repo._image_bytes(blk)
                    for pos in _aob_search(data, needle, mask, 0, len(data),
                                           max(1, int(align))):
                        total += 1
                        if len(hits) < lim:
                            hits.append({
                                "address": "0x{0:08x}".format(bstart + pos),
                                "block": blk.get("name"),
                                "match": bytes(data[pos:pos + len(needle)]).hex(" "),
                            })
        except Exception as exc:
            errors[key] = str(exc)
            continue
        grand += total
        if total:
            results.append({"program": key, "total": total,
                            "returned": len(hits), "hits": hits})

    results.sort(key=lambda r: -r["total"])
    return {
        "query": query,
        "kind": kind,
        "searched_programs": keys,
        "programs_with_hits": len(results),
        "total": grand,
        "results": results,
        "errors": errors,
        "note": ("全 Program を順に開いて調べています (常駐は LRU で 3 つまで)。"
                 "export されていない Program は errors に理由が入ります — "
                 "**0 件と「そもそも調べられなかった」を混同しないでください**。"
                 "kind='bytes' では align=4 (MIPS/ARM) / 2 (SH/Thumb) を"
                 "指定すると誤検出が減ります。"),
    }


def _diff_bytes(repo_a, repo_b, gap, limit):
    """同じ番地に載る 2 つの memory イメージを比べ、違う区間をまとめて返します。

    **製品版と修正版の差分**を取るための本体です。同じ番地に置かれている
    ブロックだけを比べます (基準が違うものを比べても意味が無いため)。
    識別できた区間には、その番地を含む関数名を A / B 両方から添えます —
    「どの関数が変わったか」がそのまま答えになります。
    """
    _, blocks_a = repo_a._exported_blocks()
    _, blocks_b = repo_b._exported_blocks()
    ranges_b = [(repo_b._block_range(b), b) for b in blocks_b if _has_bytes(b)]

    runs = []
    compared = 0
    skipped = []
    for blk in blocks_a:
        if not _has_bytes(blk):
            continue
        (a_lo, a_hi) = repo_a._block_range(blk)
        partner = None
        for (b_lo, b_hi), other in ranges_b:
            if b_lo == a_lo:                       # 同じ番地から始まるブロック
                partner = (b_lo, b_hi, other)
                break
        if partner is None:
            skipped.append({"block": blk.get("name"),
                            "why": "相手側に同じ開始番地のブロックがありません。"})
            continue
        b_lo, b_hi, other = partner
        da = repo_a._image_bytes(blk)
        db = repo_b._image_bytes(other)
        n = min(len(da), len(db))
        compared += n
        if len(da) != len(db):
            skipped.append({
                "block": blk.get("name"),
                "why": "サイズが違います (A={0} / B={1})。重なる {2} バイトだけ"
                       "比べました。".format(len(da), len(db), n)})

        # 同じ 4KB ごとにまとめて弾く (一致部分は C 側の比較で一瞬で済む)。
        step = 4096
        diffs = []
        for off in range(0, n, step):
            ca = da[off:off + step]
            cb = db[off:off + step]
            if ca == cb:
                continue
            for k in range(len(ca)):
                if ca[k] != cb[k]:
                    diffs.append(off + k)
        # 近い差分を 1 区間にまとめる (gap バイトまでの隙間は同じ変更とみなす)。
        for pos in diffs:
            if runs and runs[-1]["_block"] is blk and pos - runs[-1]["_end"] <= gap:
                runs[-1]["_end"] = pos
                runs[-1]["_count"] += 1
                continue
            runs.append({"_block": blk, "_start": pos, "_end": pos, "_count": 1,
                         "_base": a_lo})

    total = len(runs)
    out = []
    for run in runs[:limit]:
        start = run["_base"] + run["_start"]
        end = run["_base"] + run["_end"]
        length = run["_end"] - run["_start"] + 1
        da = repo_a._image_bytes(run["_block"])
        show = min(length, 16)
        item = {
            "start": "0x{0:08x}".format(start),
            "end": "0x{0:08x}".format(end),
            "length": length,
            "changed_bytes": run["_count"],
            "block": run["_block"].get("name"),
            "a_bytes": bytes(da[run["_start"]:run["_start"] + show]).hex(" "),
        }
        info_a = repo_a._describe_address(start, blocks_a) or {}
        info_b = repo_b._describe_address(start, blocks_b) or {}
        item["a_function"] = info_a.get("function")
        item["b_function"] = info_b.get("function")
        out.append(item)
    return out, total, compared, skipped


def diff_programs_impl(resolver, program_a, program_b, what="all",
                  limit=DEFAULT_LIMIT, gap=8):
    """2 つの Program を比べます (製品版 vs 修正版 / EXE vs オーバーレイ)。

    what:
      - `functions` … 入口アドレスをキーに、増えた / 減った / 名前が変わった
      - `strings`   … 文字列の増減
      - `bytes`     … **同じ番地のバイト差分**。変わった区間ごとに関数名を添える
      - `all`       … 上の全部 (既定)

    ★番地が揃っている前提です。基準がずれている Program 同士 (ROM と展開後など)
      を bytes で比べても意味がありません。まず translate_address で
      対応を確かめてください。
    """
    key_a, repo_a = resolver.get(program_a, remember=False)
    key_b, repo_b = resolver.get(program_b, remember=False)
    if key_a == key_b:
        raise ValueError("同じ Program 同士は比べられません ({0})。".format(key_a))
    want = (what or "all").strip().lower()
    if want not in ("all", "functions", "strings", "bytes"):
        raise ValueError(
            "what は all / functions / strings / bytes のいずれかです。")
    lim = clamp_limit(limit)
    result = {"program_a": key_a, "program_b": key_b, "what": want}

    if want in ("all", "functions"):
        fa, fb = _func_map(repo_a), _func_map(repo_b)
        only_a = sorted(set(fa) - set(fb))
        only_b = sorted(set(fb) - set(fa))
        renamed = [(e, fa[e], fb[e]) for e in sorted(set(fa) & set(fb))
                   if fa[e] != fb[e]]
        result["functions"] = {
            "count_a": len(fa), "count_b": len(fb),
            "only_in_a": len(only_a), "only_in_b": len(only_b),
            "renamed": len(renamed),
            "only_in_a_sample": [{"entry": _hex32(e), "name": fa[e]}
                                 for e in only_a[:lim]],
            "only_in_b_sample": [{"entry": _hex32(e), "name": fb[e]}
                                 for e in only_b[:lim]],
            "renamed_sample": [{"entry": _hex32(e), "a": x, "b": y}
                               for e, x, y in renamed[:lim]],
        }

    if want in ("all", "strings"):
        sa = {s.get("value") for s in _load_items(repo_a, "strings.json", "strings")}
        sb = {s.get("value") for s in _load_items(repo_b, "strings.json", "strings")}
        only_a = sorted(x for x in sa - sb if x)
        only_b = sorted(x for x in sb - sa if x)
        result["strings"] = {
            "count_a": len(sa), "count_b": len(sb),
            "only_in_a": len(only_a), "only_in_b": len(only_b),
            "only_in_a_sample": only_a[:lim],
            "only_in_b_sample": only_b[:lim],
        }

    if want in ("all", "bytes"):
        try:
            runs, total, compared, skipped = _diff_bytes(
                repo_a, repo_b, max(0, int(gap)), lim)
            result["bytes"] = {
                "compared_bytes": compared,
                "changed_runs": total,
                "returned": len(runs),
                "gap": int(gap),
                "runs": runs,
                "skipped_blocks": skipped,
            }
        except ValueError as exc:
            result["bytes"] = {"error": str(exc)}

    result["note"] = (
        "★bytes は**同じ番地に載っている前提**の比較です。基準がずれている "
        "Program 同士 (ROM と展開後など) を比べても意味がありません — "
        "先に translate_address で対応を確かめてください。"
        "changed_runs は gap バイト以内の差分を 1 件にまとめた数です "
        "(1 命令の書き換えが 4 件に散らばらないようにするため)。"
        "a_function / b_function がその区間を含む関数です。")
    return result

class _ProgramKey(str):
    """解決した Program キーです。既定値で決めたときは defaulted が立ちます。

    str のサブクラスにしてあるのは、各ツールの `key, target = resolver.get(program)`
    / `_echo(result, key)` を 1 行も変えずに「既定値を使った」ことを運ぶためです。
    """

    defaulted = False
    default_source = None


class ProgramResolver(object):
    """`program` キーから ExportRepo を解決します (単一 / 複数モード共通の入口)。

    複数モードで program を省略したときは、**このセッションで最後に使った
    Program**、それも無ければ**レジストリの `default_program`** を使います
    (毎回 program= を書かなくてもよいように)。
    どちらも無ければ、従来どおり候補を列挙したエラーです。
    ★取り違え防止は維持する: 応答には必ず `program` が入り、既定値を使ったときは
      `program_defaulted: true` と `program_default_source` が付きます。

    複数モードで registry_path を渡すと、**レジストリの更新を検知して次の
    呼び出しで読み直します** (ゲームを足してもサーバの再起動が要らない)。
    """

    def __init__(self, programs=None, single_key=None, single_root=None,
                 max_hot=DEFAULT_MAX_HOT_PROGRAMS, registry_path=None):
        """単一モードなら single_key/single_root、複数モードなら programs を渡します。

        複数モードで registry_path を渡したときは programs を使わず、
        そのレジストリから読みます (起動時に読めなければ SystemExit)。
        """
        self.programs = programs or {}
        self.single_key = single_key
        self.single_root = single_root
        self.max_hot = max(1, int(max_hot))
        self._hot = OrderedDict()          # キー -> ExportRepo (LRU)
        # program 省略時の既定値: レジストリの default_program と、最後に使ったキー。
        self.default_program = None
        self.last_program = None
        # レジストリの場所と、programs を読んだ時点の (mtime_ns, size)。
        self.registry_path = None
        self._registry_stamp = None
        # 読み直しに失敗した理由 (直前の programs を使い続けている間だけ入る)。
        self.registry_warning = None
        if registry_path is not None and self.multi:
            self.registry_path = Path(registry_path)
            # ★stat を読むより先に取る。読んでいる最中に書き換わっても、
            #   次の呼び出しで stamp の違いとして気づける。
            self._registry_stamp = self._registry_stat()
            self.programs, self.default_program = load_program_registry(
                self.registry_path)

    @property
    def multi(self):
        """複数 Program モードかどうか。"""
        return self.single_root is None

    def _registry_stat(self):
        """レジストリの (mtime_ns, size) を返します。読めなければ None。"""
        try:
            st = self.registry_path.stat()
        except OSError:
            return None
        return (st.st_mtime_ns, st.st_size)

    def _refresh(self):
        """レジストリが書き換わっていたら読み直します (registry_path があるときだけ)。

        ★読み直しに失敗しても**落とさない**。直前に読めた programs を使い続け、
          理由を registry_warning に残す (list_programs と「キーが無い」エラーに出る)。
          保存し直されれば stamp が変わるので、次の呼び出しで再挑戦する。
        """
        if self.registry_path is None:
            return
        stamp = self._registry_stat()
        if stamp == self._registry_stamp:
            return
        self._registry_stamp = stamp
        try:
            programs, default_program = parse_program_registry(self.registry_path)
        except ValueError as exc:
            self.registry_warning = (
                "レジストリを読み直せなかったので、直前に読めた内容 ({0} Program) を "
                "使い続けています: {1}".format(len(self.programs), exc))
            return
        # 消えたキー / root が変わったキーの ExportRepo は捨てる
        # (残すと、古い root の export をそのキーの結果として返してしまう)。
        for key in list(self._hot):
            if (programs.get(key) or {}).get("root") != self.programs[key]["root"]:
                del self._hot[key]
        self.programs = programs
        self.default_program = default_program
        if self.last_program not in programs:
            self.last_program = None       # 消えた / 付け替えたキーを既定値にしない
        self.registry_warning = None

    def keys(self):
        """利用できる Program キーの一覧です。"""
        if not self.multi:
            return [self.single_key]
        self._refresh()
        return sorted(self.programs)

    def _default_key(self):
        """program 省略時に使うキーと、その出典を返します (無ければ (None, None))。"""
        if self.last_program and self.last_program in self.programs:
            return self.last_program, "last_used"
        if self.default_program and self.default_program in self.programs:
            return self.default_program, "registry_default"
        return None, None

    def get(self, program=None, remember=True):
        """(キー, ExportRepo) を返します。解決できなければ分かりやすい ValueError。

        remember=False は Program を横断する道具 (search_programs / diff_programs)
        用です。そこで触った Program を「最後に使った Program」にしないため。
        """
        if not self.multi:
            if program and program != self.single_key:
                raise ValueError(
                    "このサーバは単一 Program モードで、'{0}' だけを見ています "
                    "(指定された '{1}' は扱えません)。".format(self.single_key, program))
            return self.single_key, self._repo(self.single_key, self.single_root)

        keys = self.keys()                 # ここでレジストリの更新も拾う
        default_source = None
        if not program:
            program, default_source = self._default_key()
        if not program:
            hint = ""
            if self.default_program:
                hint = ("  ★レジストリの default_program '{0}' はキーにありません。".format(
                    self.default_program))
            raise ValueError(
                "program を指定してください (複数 Program モードです)。"
                "使えるキー: {0}。list_programs で一覧と中身を確認できます。"
                "一度指定すれば、以降は省略するとその Program を使います "
                "(レジストリの default_program でも既定値を決められます)。{1}".format(
                    ", ".join(keys), hint))
        spec = self.programs.get(program)
        if spec is None:
            near = [k for k in keys if program.lower() in k.lower()]
            hint = "  もしかして: {0}".format(", ".join(near)) if near else ""
            if self.registry_warning:
                hint += "  ★{0}".format(self.registry_warning)
            raise ValueError(
                "program '{0}' はレジストリにありません。使えるキー: {1}。{2}".format(
                    program, ", ".join(keys), hint))
        repo = self._repo(program, spec["root"])
        key = _ProgramKey(program)
        if default_source:
            key.defaulted = True
            key.default_source = default_source
        if remember:
            self.last_program = program
        return key, repo

    def _repo(self, key, root):
        """ExportRepo を取り出します (無ければ作り、LRU で常駐数を抑えます)。"""
        repo = self._hot.pop(key, None)
        if repo is None:
            try:
                repo = ExportRepo(root)
            except SystemExit as exc:
                if not self.multi:
                    raise
                # ★複数モードでは ValueError に替える。MCP の例外処理は Exception
                #   しか拾わないので、SystemExit のままだと export 前の Program を
                #   1 回引いただけでサーバごと落ちる (登録直後のゲームで起きやすい)。
                raise ValueError("program '{0}': {1}".format(key, exc))
            while len(self._hot) >= self.max_hot:
                # 最も長く使っていない Program を丸ごと捨てる
                # (ExportRepo と一緒に xrefs 索引・メモリイメージも解放される)。
                self._hot.popitem(last=False)
        self._hot[key] = repo
        return repo

    def list_programs(self):
        """登録 Program の一覧を、export の有無つきで返します。"""
        items = []
        for key in self.keys():
            root = (self.single_root if not self.multi
                    else self.programs[key]["root"])
            label = "" if not self.multi else self.programs[key].get("label", "")
            exports = Path(root) / "ghidra_exports"
            # ★フォルダがあるだけでは export 済みと見なさない。ひな形の生成で
            #   空の ghidra_exports/ が先にできるので、program.json で判定する。
            entry = {
                "program": key,
                "label": label,
                "root": str(root),
                "exports_found": (exports / "program.json").is_file(),
                "loaded": key in self._hot,
            }
            if not entry["exports_found"] and exports.is_dir():
                entry["note"] = ("ghidra_exports/ はありますが program.json がありません "
                                 "(export 未実行か、途中で止まっています)。")
            if entry["exports_found"]:
                try:
                    repo = self._repo(key, root)
                    info = repo._safe(lambda: repo._load("program.json"), {})
                    entry["program_name"] = info.get("program_name")
                    entry["language_id"] = info.get("language_id")
                    entry["memory"] = repo._memory_summary().get("available")
                    entry["arch"] = repo._memory_summary().get("arch")
                except Exception:
                    entry["note"] = "exports を読めませんでした"
            items.append(entry)
        result = {
            "mode": "multi" if self.multi else "single",
            "total": len(items),
            "programs": items,
            "note": ("各ツールの program 引数にこのキーを渡してください。"
                     "省略すると default_program (最後に使った Program、無ければ"
                     "レジストリの default_program) を使い、応答に "
                     "program_defaulted: true が付きます。"
                     "応答には必ず program が入るので、取り違えたら気づけます。"
                     "レジストリを書き換えると次の呼び出しで読み直します (reconnect 不要)。"
                     if self.multi else
                     "単一 Program モードです。program 引数は省略できます。"),
        }
        if self.registry_path is not None:
            result["registry"] = str(self.registry_path)
        if self.multi:
            default_key, source = self._default_key()
            result["default_program"] = default_key
            result["default_program_source"] = source
            if self.default_program and self.default_program not in self.programs:
                result["default_program_warning"] = (
                    "レジストリの default_program '{0}' はキーにありません。".format(
                        self.default_program))
        if self.registry_warning:
            result["registry_warning"] = self.registry_warning
        return result


def _echo(result, program):
    """応答に「どの Program を見たか」を必ず入れます (取り違え防止)。

    program を省略して既定値で決めたときは program_defaulted: true と、
    その出典 (last_used / registry_default) も入れます。
    """
    if isinstance(result, dict):
        result["program"] = str(program)
        if getattr(program, "defaulted", False):
            result["program_defaulted"] = True
            result["program_default_source"] = program.default_source
    return result

def build_tools(resolver):
    """FastMCP サーバを構築し、読み取り専用ツールを登録して返します。"""
    from mcp.server.fastmcp import FastMCP

    server = FastMCP("ghidra-readonly")

    @server.tool()
    def list_programs() -> dict:
        """このサーバが扱える Program の一覧を返す。**最初にこれを呼ぶこと。**

        各ツールの program 引数にはここで返るキー (例 "game_a" / "game_b:main") を渡す。
        exports_found が false の Program はまだ export されていない
        (ghidra_exports/program.json の有無で判定する)。
        レジストリにゲームを足したら、次の呼び出しで一覧に出る (reconnect 不要)。
        registry_warning があれば、レジストリが壊れていて直前の内容で動いている。
        """
        return resolver.list_programs()

    @server.tool()
    def get_program_info(program: str = None) -> dict:
        """対象 Program の基本情報 (名前/言語/コンパイラ/アドレス範囲/メモリブロック等) を返す。

        MIPS なら gp (gp 相対の基準値) と gp_source (symbol / elf_reginfo / entry /
        ghidra_context / code_scan のどれで求めたか)、全候補の gp_candidates を足す。
        根拠が食い違うときは gp_warnings に出る。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.get_program_info(), key)

    @server.tool()
    def list_functions(name_contains: str = None, start: str = None, end: str = None, offset: int = 0, limit: int = DEFAULT_LIMIT, hide_mirrors: bool = False, program: str = None) -> dict:
        """関数一覧を返す。name_contains で名前部分一致、start/end でアドレス範囲を絞れる。ページング対応。

        65816 (SNES) では ROM ミラー上の重複関数に mirror_of (実体側の番地) /
        mirror_function、EXT_FUN の飛び先に実体があれば ext_real を添える
        (例: ローダーが作った $00:8000-FFFF の関数は $80 側の重複。JML $02:C4B1 の
        EXT_FUN の実体は $82:C4B1)。hide_mirrors=true で重複を一覧から外す。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.list_functions(name_contains, start, end, offset, limit, hide_mirrors), key)

    @server.tool()
    def get_functions_near_address(address: str, window: int = 0x200, program: str = None) -> dict:
        """指定アドレス (0x...) を body に含む関数と、entry が window 内にある近傍関数を返す。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.get_functions_near_address(address, window), key)

    @server.tool()
    def list_strings(contains: str = None, min_refs: int = 0, offset: int = 0, limit: int = DEFAULT_LIMIT, program: str = None) -> dict:
        """文字列一覧を返す。contains で部分一致、min_refs で最小参照数を絞れる。ページング対応。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.list_strings(contains, min_refs, offset, limit), key)

    @server.tool()
    def get_xrefs(to_address: str = None, from_address: str = None, limit: int = DEFAULT_LIMIT, program: str = None) -> dict:
        """xref を返す。to_address か from_address のいずれかが必須 (全件取得は不可)。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.get_xrefs(to_address, from_address, limit), key)

    @server.tool()
    def get_decompiled_function(function_name: str = None, entry_address: str = None,
                                resolve_pool: bool = True, pool_limit: int = 64,
                                with_addresses: bool = False,
                                rename: bool = False, rename_map: dict = None,
                                program: str = None) -> dict:
        """指定関数の疑似 C コードを decompile/ から 1 件返す。function_name か entry_address を指定。

        **resolve_pool=true (既定) だと、本文の DAT_xxxxxxxx を全部引いて
        pool キーに添える。** Thumb は 32bit 即値を命令に持てず必ず定数プール
        経由になるので、これが無いと疑似 C が読めない。
        疑似 C 本文 (code) は変えないので、Ghidra の出力との差分は保たれる。
        応答を細くしたいときは resolve_pool=false で完全に消せる。

        **with_addresses=true で、行ごとの命令アドレスが付く。**
        listing が '<番地>  <疑似 C の 1 行>'、line_addresses が行と範囲の対応。
        1 命令の違い (比較するレジスタの取り違え等) を追うときは、疑似 C の行から
        番地が 1 回で分かるこちらを使うこと。**code は手つかずのまま返す。**
        対応表は export のときにしか作れないので、line_map=false なら
        line_map_hint の手順で再 export すること。

        **rename=true で、関数入口の [AI] 変数メモから読みやすい疑似 C を
        code_renamed に添える** (`iVar1` → `残り時間` 等)。メモは
        propose_variable_notes で提案し、apply_comments.py で反映したもの。
        rename_map={"iVar1": "残り時間"} でその場限りの対応表も使える。
        **code (Ghidra の出力そのまま) は絶対に変えない。**

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.get_decompiled_function(function_name, entry_address,
                                                    resolve_pool, pool_limit,
                                                    with_addresses, rename,
                                                    rename_map), key)

    @server.tool()
    def propose_variable_notes(notes: dict, function_name: str = None,
                               entry_address: str = None,
                               confidence: str = "medium",
                               evidence: list = None,
                               program: str = None) -> dict:
        """疑似 C の変数の意味を **[AI] コメント**にして提案する。

        `iVar1` が何なのかは読み解いた本人にしか分からない。それを Ghidra へ
        戻せる形にするのがこのツール。関数の入口に plate コメントを 1 個付ける
        案を返すので、`proposals/` に保存して apply_comments.py で反映する。
        反映後は **list_comments で読み返せる**し、
        **get_decompiled_function(rename=true) がそのコメントから読みやすい
        疑似 C を組み立てる**。
        notes は {"iVar1": "残り時間 (フレーム)", "param_1": "プレイヤー構造体"}。

        ★**疑似 C に無い変数名は拒否する。** 存在しない名前にメモを付けると、
        次のセッションが「そういう変数がある」と誤解する。
        ★根拠の無い名前を付けないこと。`iVar1` は「分からない」という**正しい
        情報**を持っているので、間違った名前はそれより悪い。
        MCP はファイルを書かない (反映は必ず人間がトリガする)。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.propose_variable_notes(notes, function_name,
                                                   entry_address, confidence,
                                                   evidence), key)

    @server.tool()
    def find_struct_field_uses(base: str, stride: int = None, offset: str = None,
                               limit: int = 50, context: int = 2,
                               program: str = None) -> dict:
        """構造体の**どのオフセットがどこから触られているか**を疑似 C から探す。

        表の各オフセットが何の数値なのかを突き止めるのは、データ構造解析で
        いちばん時間を食う作業。**offset を省略したときが本命**で、
        「どのオフセットが何回、どの関数から触られているか」の一覧が出る。
        untouched_offsets (誰も触っていない穴) は stride の推定が
        合っているかの検算になる。offset を指定すると、その 1 フィールドの
        使用箇所と前後のコード片が返る (context 行数は既定 2)。

        ★疑似 C は同じアクセスを何通りにも書く。ベースが DAT_ のまま /
        変数に入っている / 2 行に割れている / オフセットを先に足す、の
        4 形は拾うが、**ベースを引数で渡す形とポインタ演算で進める形は
        拾えない**。unmatched_hints を必ず見ること (黙って落としていない)。
        要 export_decompile=true。
        ★base="@配列名" (bridge_config の record_formats に layout="soa" で書いた
        **項目ごとの配列**。例 $0B00 + 項目×$10 + 要素×2) なら stride 不要で、
        疑似 C ではなく**逆アセンブル**から「どの項目が何回・どの関数から読み書きされるか」を
        数える (offset に項目名を渡すとその項目の命令一覧)。65816 (CDL 走査) 対応。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.find_struct_field_uses(base, stride, offset,
                                                   limit, context), key)

    @server.tool()
    def find_pointers_to(address: str, range_end: str = None,
                         alignment: int = 4, blocks: list = None,
                         limit: int = 100, program: str = None) -> dict:
        """その番地を指している**データ中の生の 32bit ポインタ**を探す。

        find_address_refs は**コード**からの参照 (Thumb の定数プール等)、
        こちらは**データ**中の生ポインタ。GBA のリソースはデータ表から
        参照されることが圧倒的に多いので、両方見ないと参照を見落とす。

        ★**「無い」と言うための道具でもある。** コード参照だけを見ると
        「どこからも参照されない没データ」と誤って結論しがち
        (アニメ記述子などのデータから参照されている)。0 件のときは hint に
        疑うべき形が並ぶので、必ず読んでから結論すること。
        range_end で範囲指定すると、表の途中を指す参照も拾える。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.find_pointers_to(address, range_end, alignment,
                                             blocks, limit), key)

    @server.tool()
    def find_undefined_targets(table_address: str = None, stride: int = 4,
                               count: int = None, addresses: list = None,
                               source: str = "table",
                               executable_only: bool = True,
                               limit: int = DEFAULT_LIMIT,
                               as_proposal: bool = False,
                               program: str = None) -> dict:
        """**参照されているのに関数化されていない**入口を洗い出す。

        list_undefined_ranges は「未定義**領域**」、こちらは
        「参照されている未定義な**関数入口**」。的が違う。
        関数ポインタ表を渡すと、飛び先のうち Ghidra が関数にしていない
        ものだけが残るので、そのまま apply_functions.py に流せる
        (as_proposal=true で proposed_functions.json の形も返す)。
        source は table (既定) / xrefs。addresses で番地を直接渡すこともできる。

        ★**「未関数化 = 関数である」ではない。** データを指すエントリも
        混ざるので、looks_like_code と prologue を見てから apply すること。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.find_undefined_targets(
            table_address, stride, count, addresses, source,
            executable_only, limit, as_proposal), key)

    @server.tool()
    def resolve_pool(address: str, count: int = 1, program: str = None) -> dict:
        """定数プール (DAT_xxxxxxxx) の中身を読んで、何を指しているか返す。

        Thumb は 32bit 即値を命令に持てないので、アドレスは必ず定数プール経由。
        疑似 C の DAT_ を毎回 ROM から手で引くのをやめるための道具。
        **address は "0x0803e1fc" でも "DAT_0803e1fc" でも受ける。**
        note は「ポインタ表らしい」程度の弱い所見で、断定はしない。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.resolve_pool(address, count), key)

    @server.tool()
    def get_disassembly(address: str, count: int = DEFAULT_DISASM_COUNT, arch: str = None, stop_at_return: bool = False, format: str = "json", resolve_gp: bool = True, m: int = None, x: int = None, snap: bool = True, program: str = None) -> dict:
        """未関数化コードを生の逆アセンブルで読む。address(0x...) から count 命令ぶん。

        疑似 C が無い LAB_xxxxxxxx を読むための手段。ghidra_exports/memory/*.bin を
        デコードするだけで、Ghidra には問い合わせない。要 export_memory=true。
        分岐先は branch_targets / call_targets にまとめて返す。
        stop_at_return=true なら return 命令 (+遅延スロット) で打ち切る。
        **format="text" にすると 1 命令 1 行のテキストで返る (応答が数分の 1 になる)。**
        長い関数を追うときは text を使うこと。既定は従来どおり json。
        対応アーキ: MIPS (R3000/R5900) / SuperH SH-4・SH-2 / ARMv4T (arm・thumb) /
        PowerPC (Gekko・Broadway = GameCube/Wii。★ビッグエンディアン)。
        ★ARM は arm (32bit) と thumb (16bit) が同じ Program に混在し自動判別できない。
        既定は memory_map.json の disasm_arch → processor の順で決まる。GBA など
        Thumb 主体なら bridge_config に disasm_arch="thumb" を書くか arch で明示する。
        モードを間違えるとデータが命令に化けるので、結果が支離滅裂ならモードを疑うこと。
        resolve_gp=true (既定) なら MIPS の gp 相対 (`lw v0,-29048(gp)`) に
        gp_ref / comment (`= 0x00240e88 GameManagerInst`) を付ける。gp の根拠は gp_source。

        ★65816 (SNES/SFC) は可変長で、即値の長さが M/X フラグで変わる。
        幅は bridge_config.json の cdl_jsonl (Mesen CDL の JSONL) から命令ごとに取り、
        無ければ REP/SEP 追跡 (読み始めは m=1 x=1 の**仮定**)。各命令の
        width_source (cdl_recorded / cdl_static_only / given / tracked / carried /
        ambiguous / unknown / assumed) と width_uncertain を必ず見ること。
        m / x (1 = 8bit, 0 = 16bit) を渡すと、そのフラグは CDL より優先する
        (Mesen の P レジスタを写す / 呼び元で幅が変わる入口を別の幅で読む)。
        address は 0x809447 / $80:9447 のどちらでもよい。refs に実効番地
        (D=$0000・DBR=命令のバンク の仮定付き) が出る。
        snap=true (既定) なら、読み始めが CDL に記録された命令の途中のとき、その命令の
        先頭へ合わせて読み直す (snapped / alignment_note が付く)。false なら従来どおり
        alignment_warning だけ付けてずれたまま返す。m / x を渡したときは合わせない。
        CDL の外を読むときは find_function_entry で入口と入口の幅を推定してから読むこと。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.get_disassembly(address, count, arch, stop_at_return,
                                            format, resolve_gp, m, x, snap), key)

    @server.tool()
    def find_address_refs(address: str, mask: str = "0xffffffff", limit: int = DEFAULT_REFS_LIMIT, range_end: str = None, include_branches: bool = False, program: str = None) -> dict:
        """このアドレスを参照しているコードを探す。Ghidra が xref を持っていなくても見つかる。

        未定義領域に置かれたデータテーブルの参照元探しに使う。命令の即値から
        アドレスを再構成して照合する (MIPS なら lui + addiu/lw/sw ... のペア、
        SH-4 なら mov.l @(disp,pc),Rn が読む定数プールの中身)。
        mask に 0xffff0000 等を渡すと帯域検索になる。
        range_end を渡すと [address, range_end] のどこかを指す参照を探す
        (表の途中を指す参照を取りこぼさないため。範囲は両端を含む)。
        範囲検索では分岐先が大量に混ざるので既定で除外する
        (include_branches=true で戻せる)。要 export_memory=true。
        get_xrefs は Ghidra が「データ」と認識した箇所しか持たないので、
        未定義領域の表にはこちらを使う。
        SH-4 は即値ペアではなく **PC 相対の定数プール**を辿る
        (mov.l @(disp,pc),Rn が読む 32bit 値と照合)。
        65816 (SNES/SFC) は dp / abs / long (各 ,X ,Y) の実効番地で照合する。
        WRAM は $7E:xxxx、I/O は $00:2xxx に正規化するので 0x000b20 と 0x7e0b20 は
        同じ。CDL (cdl_jsonl) があれば記録された区間だけをその幅で読む。
        items の access (R/W/RW)・width_source・assumptions を見ること。
        bridge_config の ram_map (RAM の名前表) / record_formats の項目ごとの配列があれば
        resolved_name / target_name に名前を添える (Ghidra のラベルとは別物、表示だけ)。
        対応アーキ: MIPS (R3000/R5900) / SuperH SH-4・SH-2 / ARMv4T (arm・thumb) /
        PowerPC (Gekko・Broadway = GameCube/Wii。★ビッグエンディアン) / 65816。
        ★ARM は arm (32bit) と thumb (16bit) が同じ Program に混在し自動判別できない。
        既定は memory_map.json の disasm_arch → processor の順で決まる。GBA など
        Thumb 主体なら bridge_config に disasm_arch="thumb" を書くか arch で明示する。
        モードを間違えるとデータが命令に化けるので、結果が支離滅裂ならモードを疑うこと。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.find_address_refs(address, mask, limit, range_end, include_branches), key)

    @server.tool()
    def read_data(address: str = None, format: str = "hex", count: int = DEFAULT_DATA_COUNT, columns: int = None, stride: int = None, base: str = "auto", annotate: bool = True, as_markdown: bool = False, record: str = None, index: int = None, program: str = None) -> dict:
        """データテーブルの中身を読む。find_address_refs で見つけた表の解釈に使う。

        format: u8/s8/u16/s16/u32/s32/u64/s64/f32/f64 と hex (生バイト) / cstring。
        count は読む要素数。columns で行に折り返す (例: x/y/z なら columns=3)。
        stride (バイト) を併用すると 1 レコードの先頭だけ拾える
        (例: 16 バイトのレコードから先頭 3 個の s16 → columns=3, stride=16)。

        **型が混ざった固定長レコードの表は record= で 1 レコード 1 行で読む。**
        例: record="u8,s8,s8,s8,s8" (1 バイトの ID + 符号つき 1 バイト × 4)。
        `name:type` で列名も付く (record="id:u8,dx:s8,dy:s8")。`xN` は N バイトの
        詰め物。record を使うとき count は**レコード数**で、format は無視される。
        レコードより広い間隔で並ぶなら stride も付ける。as_markdown も効く。
        **同じ表を何度も読むなら bridge_config.json の record_formats に登録して
        `record="@名前"` で引く** (list_record_formats で一覧)。
        **項目ごとの配列** (record_formats に layout="soa": base / field_stride /
        element_size / count / fields) なら record="@cars", index=0 で
        「要素 0 の全項目」を 1 行で読む (address 省略可。index 省略で全要素)。
        各項目の番地 (addresses) も返るので、実行時の値は Mesen 等でそこを読む。

        u32/s32 の値には「その先に何があるか」(関数名/文字列/ブロック名) を添える。
        as_markdown=true で notes/*.md へそのまま貼れる Markdown 表を返す。
        Ghidra にデータ型は適用しない (型変更は常に禁止)。要 export_memory=true。
        **overlays に登録した外部ファイルの範囲もそのまま読める**
        (その場合 block が "overlay:<名前>" になる。list_overlays 参照)。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.read_data(address, format, count, columns, stride, base, annotate, as_markdown, record, index), key)

    @server.tool()
    def find_writers(address: str, mask: str = "0xffffffff", max_scan: int = 12, trace_imm: int = 16, scan_basis: str = None, index_reach: int = None, program: str = None) -> dict:
        """その番地に **書き込んでいる命令** を、可能なら書く値まで添えて列挙する。

        find_address_refs の対。「このフラグを 0 に戻している命令を全部潰したい。
        潰し漏れはないか」に答えるための道具。
        writers は **ちょうどこの番地** へ書く命令、offset_writers は近傍へ書く命令、
        readers は読むだけの箇所。value に即値を特定できた場合の書き込み値が入る。
        65816 (SNES/SFC): STA/STX/STY/STZ = W、INC/DEC/ASL/LSR/ROL/ROR/TSB/TRB = RW。
        16bit 書き込みが target を上位バイトとして覆う場合も writers に出る (covers)。
        ,X ,Y 付きは offset_writers (index_offset)。間接 (STA (dp),Y 等) は
        indirect_stores に件数だけ。幅は CDL (cdl_jsonl) から取る。
        ★65816 は既定 (scan_basis="cdl") だと **CDL に記録された区間しか読まない**ので、
        遊んでいない場面のコードの書き込みは出ない。**scan_basis="bytes"** にすると
        バイト列の全域から STA/STX/STY/STZ/INC/DEC/TSB/TRB… (dp / abs / long、各 ,X ,Y) を
        拾い、各候補に executed (CDL で実行済みか)・boundary / boundary_ok (命令の先頭として
        妥当か。CDL の命令の途中・データとして読まれた場所なら boundary_rejected へ)・
        width / width_certainty (8bit/16bit が cdl / inferred / unknown) を付ける。
        target-1 への書き込みは 16bit のときだけ上位バイトとして覆うので、8bit と分かった
        ものは not_covering に分ける。found_by_cdl_scan=false が CDL 走査では拾えないもの。
        index_reach: ,X ,Y 付きを基底番地から何バイト先まで数えるか (bytes の既定は 0xFF)。
        address="@cars.speed" / "@cars.speed[0]" (record_formats の項目ごとの配列) なら、
        その項目の全要素 (要素 0 だけ) へ触る命令を record_field (例 cars.speed[idx]) つきで
        返す (65816 の CDL 走査のみ)。
        bridge_config の ram_map があれば ea_name / target_name に名前を添える
        (例 "ram_map": {"$00D9": "grip_flag", "$0B20,X": "car.speed", "$0D51.bit7": "airborne"}。
        幅つきは {"name": .., "size": 2}。Ghidra のラベルとは別物で、表示だけ)。
        対応: SH-4 / MIPS / 65816 (他アーキは未対応と明示エラー)。要 export_memory=true。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.find_writers(address, mask, max_scan, trace_imm,
                                         scan_basis, index_reach), key)

    @server.tool()
    def list_overlays(program: str = None) -> dict:
        """実行時に RAM へ読み込む **外部ファイル** の登録状況を返す。

        ステージデータ / 地形の高さ表 / オーバーレイコードのように、
        **Ghidra の Program には入っていないが実行時は特定番地に載るファイル**を
        「この番地に置かれたもの」として扱う仕組み。登録すると read_data /
        find_bytes / describe_data / classify_range / find_pointers_to が
        その範囲でも効くようになる (EXE 内の表と同じ道具で読める)。
        登録は bridge_config.json の overlays に書く (MCP は読むだけ):

          "overlays": [{"name": "stage01", "path": "dumps/STAGE01.BIN",
                        "base": "0x801c0000", "offset": 0, "length": null,
                        "note": "ステージデータ", "scan": true}]

        応答の block は必ず "overlay:<名前>" になるので、Program 本体の値と
        取り違えない。Program のブロックと範囲が重なる場合は警告が出る
        (読み出しはオーバーレイ側が優先。走査で二重に出るなら scan=false)。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.list_overlays(), key)

    @server.tool()
    def list_record_formats(program: str = None) -> dict:
        """使い回せる **レコード定義** の一覧を返す (`read_data(record="@名前")`)。

        同じ表を読むたびに record="id:u8,dx:s8,dy:s8" を書き直すのは無駄なので、
        bridge_config.json の record_formats に置いて使い回す:

          "record_formats": {"part_entry": "id:u8,dx:s8,dy:s8,dz:s8,dw:s8"}

        ★**Ghidra の構造体とは別物**。read_data がどう区切って読むかを決めるだけで、
        Ghidra には一切触らない (構造体の適用は常に禁止)。登録は人間が行う。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.list_record_formats(), key)

    @server.tool()
    def list_call_sites(target: str, max_back: int = 24,
                        limit: int = DEFAULT_LIMIT, arch: str = None,
                        as_markdown: bool = False, indirect_window: int = 8,
                        program: str = None) -> dict:
        """その関数を呼ぶ箇所を **呼び出し時の引数レジスタつき** で列挙する。

        疑似 C は `FUN_801a1a0c(param_1,3)` のように引数を落とすことがあり、
        3 番目が何かは逆アセンブルで `addiu $a2,$zero,1` を見るまで分からない。
        **初期化処理やテーブル駆動のコードでは、この呼び出し時の定数が解析の要。**
        target は関数名でもアドレス (0x...) でもよい。
        各引数の kind は imm (即値) / address (lui+下位16bit のアドレス定数) /
        runtime (実行時に決まる) / inherited (窓の中で書かれていない = param_N) の別。
        **遅延スロット (jal の次の 1 命令) も引数設定として数える。**
        直前の呼び出しより先には遡らない (引数レジスタは呼び出しで壊れるため)。
        constants に「どの引数にどの定数が何回渡されているか」がまとまる。
        as_markdown=true で notes/*.md へそのまま貼れる表を返す。
        MIPS / PowerPC 対応 (他アーキは未対応と明示エラー)。要 export_memory=true。
        ★PowerPC に遅延スロットは無い (MIPS の感覚で読まないこと)。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, tgt = resolver.get(program)
        return _echo(tgt.list_call_sites(target, max_back, limit, arch,
                                         as_markdown, indirect_window), key)

    @server.tool()
    def infer_signature(target: str, max_back: int = 24, sample: int = 200,
                        arch: str = None, program: str = None) -> dict:
        """その関数が **実際に何個引数を取るか** を推定する。

        疑似 C が `FUN_801a1a0c(param_1,3)` と引数を落とすとき、そもそも何個
        受け取る関数なのかが分からない。**2 方向**から見る:
        呼び出し側 (どの引数レジスタに積んでいるか) と、
        呼ばれる側 (引数レジスタを**読むのが先か書くのが先か**)。
        verdict は used (呼ばれる側が読んでいる) / probably_used (呼び出し側だけ) /
        unused。**断定しない** — confidence と conflicts を必ず見ること。
        signature_hint にそれらしい形が出る。
        MIPS / PowerPC 対応 (他アーキは未対応と明示エラー)。要 export_memory=true。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, tgt = resolver.get(program)
        return _echo(tgt.infer_signature(target, max_back, sample, arch), key)

    @server.tool()
    def list_callees(target: str, depth: int = 1, limit: int = DEFAULT_LIMIT,
                     arch: str = None, max_instructions: int = 4096,
                     follow_tables: bool = False, ordered: bool = False,
                     program: str = None) -> dict:
        """その関数が **何を呼ぶか** を深さ指定で辿る (list_call_sites の逆向き)。

        「この初期化関数は何を仕込むのか」を追うときに、get_disassembly を
        何度も呼ぶ代わりになる。depth は 1〜5。
        **循環は必ず検出して打ち切る** (repeat=true が既に辿った関数)。
        ★**間接呼び出し (レジスタ経由) は飛び先が分からないので
        indirect_calls に件数だけ出す — 「呼んでいない」ではない。**
        関数ポインタ表から呼ぶ形は find_pointer_tables / find_pointers_to で追う。
        アーキ非依存 (decode の flow を見る)。要 export_memory=true。
        ★65816 は follow_tables=true で、分岐を辿りながら JSR ($abs,X) / JMP ($abs,X) の
        表を展開して (expand_switch と同じ判定) その先も辿る (kind=jsr_table / jmp_table、
        table_index)。状態機械 (JSR ($A4BA,X) など) の先を追うときに使う。M/X は呼び出し元
        から運ぶ (CDL の外も正しい幅で読める)。target は $80:A3F4 表記も可。
        **ordered=true** で、根の関数の呼び出しを**命令の並び順**に全部 (同じ相手への
        複数回も) call_order に並べ、各呼び出しが条件分岐で飛ばされうるか (conditional) を
        添える (「どの処理が先に走るか」を手で書き出さないため。判定は 65816 のみ、
        他アーキは順番だけで conditional=null)。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, tgt = resolver.get(program)
        return _echo(tgt.list_callees(target, depth, limit, arch,
                                      max_instructions, follow_tables, ordered), key)

    @server.tool()
    def save_export_snapshot(name: str = None, program: str = None) -> dict:
        """今の export の要約を保存する (後で diff_exports で差分を見るため)。

        **解析を始める前に 1 回取っておく**のが使い方。関数化やコメント反映の後に
        再 export してから diff_exports を呼ぶと、「前回からどこが進んだか」が出る。
        保存先は `<project_root>/extracted/snapshots/` だけ
        (ghidra_exports/ には書かない。既存ファイルも上書きしない)。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.save_export_snapshot(name), key)

    @server.tool()
    def list_export_snapshots(program: str = None) -> dict:
        """保存済みの export スナップショットを新しい順に返す。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.list_export_snapshots(), key)

    @server.tool()
    def diff_exports(snapshot: str = None, limit: int = DEFAULT_LIMIT,
                     program: str = None) -> dict:
        """前に取ったスナップショットと今の export を比べる (同じ Program の時間差)。

        diff_programs は**別 Program 同士**の比較で、同じ Program の時間差は
        見られない。**増えた関数 / 付いた名前 / 書かれたコメント**が、
        前回からの進捗そのもの。snapshot 省略時は一番新しいものと比べる。
        コメントの本文は持っていないので、中身は list_comments で見ること。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.diff_exports(snapshot, limit), key)

    @server.tool()
    def find_immediate(value: str, start: str = None, end: str = None,
                       include_offsets: bool = False, include_pairs: bool = True,
                       limit: int = DEFAULT_LIMIT, arch: str = None,
                       as_markdown: bool = False, program: str = None) -> dict:
        """その **数値** を即値として使っている命令を探す。「この 100 はどこで設定されるか」。

        find_address_refs は**アドレス**、find_bytes は**バイト列**を探す道具で、
        `addiu $a0,$zero,100` のような**即値**はどちらでも引けない。
        閾値・ID・フラグ値の出どころ探し（改造コードを作るときの定番）に使う。
        value は 10 進でも "0x64" でも負数でもよい。

        kind で本命を選べる: **const**(定数を作っている) / **compare**(その値と
        比べている ← 閾値はたいていこれ) / add(足し引き) / logic(論理演算) /
        upper(上位16bitだけ) / pair(lui と組で 32bit) / offset(変位。既定で除外)。
        by_kind に種別ごとの件数が出るので、多すぎるときは start/end で
        関数の範囲に絞ること。as_markdown=true で表になる。
        MIPS / PowerPC 対応 (他アーキは未対応と明示エラー)。要 export_memory=true。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.find_immediate(value, start, end, include_offsets,
                                           include_pairs, limit, arch,
                                           as_markdown), key)

    @server.tool()
    def expand_switch(address: str, arch: str = None, program: str = None) -> dict:
        """braf / bsrf のスイッチ表を展開して、全分岐先を列挙する。

        SH-4 のスイッチ文は 16bit オフセット表で実装されており、飛び先が 32bit
        アドレスとしてどこにも現れないため find_address_refs では見つからない。
        その盲点を塞ぐ。address には braf 命令 (かその近傍) を渡す。
        entry_count が推定かどうかは count_is_estimated を見ること。
        ★65816 (SNES/SFC): JSR ($abs,X) / JMP ($abs,X) の表を展開する。件数は直前の
        CMP #n + BCS/BCC なら確定、AND #k なら上限、無ければ表の終端の推定 (CDL がコードと
        記録した番地 / ROM 外を指す値 / 不自然な飛び先で止める。stop_reason)。
        index_bound に添字の出どころ (例 LDA $074A, AND #$FF, ASL A, TAX)。
        executed は飛び先が CDL で実行されたか。entry_widths は飛び先の入口の M/X。
        SH-4 / MIPS / 65816 対応。要 export_memory=true。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.expand_switch(address, arch), key)

    @server.tool()
    def find_function_entry(address: str, arch: str = None, program: str = None) -> dict:
        """指定アドレスを含む関数の入口を **命令列から** 判定する。

        数バイト後ろから関数を呼ぶと push と pop の数が合わずスタックが壊れ、
        rts がゴミへ飛ぶ。**関数を呼ぶ前に必ずこれで入口を確認すること。**
        balanced=false なら入口ではない。Ghidra の関数情報は ghidra_says に
        併記するだけで、判定には使わない (Ghidra 自身が誤認している例があるため)。
        ★65816 (SNES/SFC): 後ろ向きに RTS/RTL/RTI/JMP/BRA の直後と既知の入口を候補にし、
        呼び出し元 (JSL/JSR/表) の有無、入口の M/X (CDL → 呼び出し元の幅 → 4 通り試す)、
        その入口から分岐を辿って address に届くか、不自然な命令 / CDL との矛盾で点を付ける。
        confidence (high/medium/low) と entry_widths (m/x とその出どころ)、candidates を見る。
        **推定であり断定しない** (balanced は常に null)。address は $83:CFE4 表記も可。
        SH-4 / MIPS / ARM / Thumb / PowerPC / 65816 対応。要 export_memory=true。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.find_function_entry(address, arch), key)

    @server.tool()
    def find_calls_to(address: str, include_branches: bool = True,
                      kinds: str = None, limit: int = DEFAULT_REFS_LIMIT,
                      program: str = None) -> dict:
        """指定番地を **呼ぶ・飛ぶ命令** をバイト列から全部列挙する (CDL の外も)。

        Ghidra の xref は関数化されていない領域の呼び出しを持たないことが多く、
        `22 BE FB 83` を find_bytes で手探しする代わりに使う。65816 (SNES/SFC):
        JSL / JML (long。ミラーの $03 等も同じ番地とみなす)、JSR / JMP (同じバンクの abs)、
        BRL / BRA / Bcc (相対)、PEA (戻り先-1 を積む慣用)、JSR ($abs,X) / JMP ($abs,X)
        の**表の中身** (表を展開して実際にその位置まで含まれるものだけ)。
        各件の boundary / boundary_ok が**命令の境界として妥当か**の印:
        cdl_instruction_start (CDL が記録した命令の先頭 = 確実) / inside_cdl_instruction・
        cdl_data (偶然の一致) / not_in_cdl (sync = 手前を読み直して着地した割合。推定)。
        executed は CDL で実行の記録があるか、widths はその命令の M/X。
        kinds で絞れる (jsl,jml,jsr,jmp,brl,branch,push_return,table)。
        include_branches=false で BRA/Bcc/BRL を除く。65816 のみ対応。要 export_memory=true。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.find_calls_to(address, include_branches, kinds, limit), key)

    @server.tool()
    def find_path(source: str, target: str, m: int = None, x: int = None,
                  max_functions: int = 6000, program: str = None) -> dict:
        """入口 source から番地 target に **届くか、届くならその経路** を返す (静的)。

        「リセット後〜章開幕までに $08F2 を書く処理はあるか」のような問いに使う。
        source の入口から分岐を辿り、JSR / JSL、JSR ($abs,X) / JMP ($abs,X) の表
        (展開して全部)、既知の入口への JMP / JML、PEA で積んだ戻り先を幅優先で辿る
        (状態機械の表も辿れる)。path に呼び出しの連なり (site / text / kind / table_index /
        widths / site_executed)、final に最後の関数の中で target に届いた命令。
        M/X は呼び出し元から運ぶので CDL の外も読める。m / x で source の入口の幅を指定できる。
        **静的な経路**なので、その分岐を実際に通る条件が成り立つかは別問題。
        見つからなくても「届かない」とは言えない (unresolved_indirect / budget_exhausted /
        hint を見る)。65816 のみ対応。要 export_memory=true。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, repo = resolver.get(program)
        return _echo(repo.find_path(source, target, m, x, max_functions), key)

    @server.tool()
    def list_memory_args(target: str, args: list = None, limit: int = DEFAULT_LIMIT,
                         include_weak: bool = False, as_markdown: bool = False,
                         program: str = None) -> dict:
        """**メモリ経由の引数の「設定漏れ」** を呼び出し元ごとに一覧にする。

        target (処理の入口) を呼ぶ箇所ごとに、その呼び出しを含む処理の入口を推定して
        分岐を辿り、呼ぶ直前までに各番地を「書いたか (written + value)」
        「一部の経路だけ (partially_written)」「書いていない (not_written)」
        「分からない (unknown)」で返す。途中で呼んだ処理の中の書き込みも数える。
        args (例 ["$08ED", "$08F1", "$08F2"]) を省略すると、target が書く前に読む
        WRAM 番地を自動で引数とみなす (大域変数も混ざる。weak は include_weak=true)。
        suspicious = 書く呼び出し元と書かない呼び出し元が混在する番地 (設定漏れの典型)、
        callers_not_writing = 番地ごとに書いていない呼び出し元。
        could_be_written_by は間接・添字付き・ブロック転送で書いているかもしれない命令
        (静的には否定できない)。as_markdown=true で表。65816 のみ対応。要 export_memory=true。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, repo = resolver.get(program)
        return _echo(repo.list_memory_args(target, args, limit, include_weak,
                                           as_markdown), key)

    @server.tool()
    def lint_stale_register(function: str = None, start: str = None, end: str = None,
                            min_severity: str = "high", limit: int = DEFAULT_LIMIT,
                            program: str = None) -> dict:
        """**レジスタの持ち越し**を機械的に探す (65816: A の上位バイト B)。

        8bit の PLA / LDA で下位バイトだけ作り、上位バイトは呼び出し先から戻ったときの
        値のまま 16bit で使う形 (STA / CMP / BIT #$FF00 / TAX (x=0) / TCD など) を検出する
        (kind=mixed_16bit_use)。同じ状態で「入口の上位バイトを 16bit で使う処理」を呼ぶ形
        (call_consumes_high。callee_uses_high_byte_at に使う命令)、上位を XBA で下位へ
        持ってきて使う形 (xba_stale_high) も出す。PHA ... PLA の保存は辿るので保存だけは
        使用に数えない。high_byte_candidates に「上位バイトを最後に設定した候補」
        (呼び出し先の 16bit LDA など。via が呼び出しの連なり)、range に下位を作った命令〜
        使った命令。severity: high = 呼び出し先が入れた実行時の値 / medium = 関数の入口の値 /
        low = 呼び出し先が即値などで決めた値だけ。function で 1 関数、start/end で番地の範囲に
        絞れる (省略時は既知の入口とその呼び出し先の全部)。65816 のみ対応。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, repo = resolver.get(program)
        return _echo(repo.lint_stale_register(function, start, end, min_severity,
                                              limit), key)

    @server.tool()
    def find_pointer_tables(target_lo: str, target_hi: str, min_entries: int = 3, limit: int = DEFAULT_LIMIT, stride: int = 4, min_count: int = None, thumb_pointers: bool = False, detect_parallel: bool = False, program: str = None) -> dict:
        """[target_lo, target_hi] を指すワードが連続して並ぶ箇所 (ポインタ表) を探す。

        「連続する N 個のワードが全部この範囲を指している = ポインタ表」という規則。
        文字列表の構造を見つけるのに効く (各エントリの指す文字列も併記する)。
        stride は**表のエントリ間隔** (4 以外に 8 / 0x14 等が実在する)。
        **Thumb の関数ポインタ表は thumb_pointers=true が必須** (値の下位ビットが 1)。
        アーキ非依存。要 export_memory=true。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.find_pointer_tables(target_lo, target_hi, min_entries,
                                                limit, stride, min_count,
                                                thumb_pointers,
                                                detect_parallel=detect_parallel),
                     key)

    @server.tool()
    def describe_data(address: str, stride_hint: str = None, count: int = 8, program: str = None) -> dict:
        """表の構造 (ストライド・要素サイズ・インライン文字列) を推定する。

        各 4 バイト語を u32 / ポインタ / インライン ASCII 文字列に分類し、
        同じ並びが繰り返す周期をストライドとみなす。stride_hint を渡せば
        推定せずそれを使う (推定は外れることがあるので、分かっているなら渡す)。
        アーキ非依存。要 export_memory=true。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.describe_data(address, stride_hint, count), key)

    @server.tool()
    def decompress(address: str = None, type: str = None, max_size: int = None,
                   source_path: str = None, offset: int = 0,
                   out_path: str = None, program: str = None) -> dict:
        """GBA / NDS の BIOS 圧縮を展開し、ファイルへ保存してパスを返す。

        type 未指定なら先頭バイトから自動判定 (0x10 LZ77 / 0x2n Huffman /
        0x30 RLE / 0x8n Diff フィルタ)。★Diff は 0x40 ではなく 0x81 / 0x82。
        展開結果は応答に載せず `<project>/extracted/` に保存する (数十〜数百 KB になるため)。
        返り値の nested が付いていたら**中身がさらに圧縮**されているので、
        out_path を source_path に渡してもう一度呼ぶこと。
        source_path を指定すると memory ではなくそのファイルを読む。
        ★source_path で読めるのは <project>/extracted/ と <project>/dumps/、
        bridge_config.json の source_roots に人間が書いたフォルダの配下だけ
        (resolve 後に判定。範囲外・UNC・デバイスパスは拒否)。
        max_size の上限は 16MB、out_path は extracted/ の配下だけ。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.decompress(address, type, max_size, source_path,
                                       offset, out_path), key)

    @server.tool()
    def find_compressed_blocks(start: str, end: str, min_size: int = 0x200,
                               include_rle: bool = False,
                               limit: int = DEFAULT_LIMIT,
                               program: str = None) -> dict:
        """範囲を走査して圧縮ブロック候補を列挙する。

        ヘッダらしく見えるだけの誤検出を、展開の成否・宣言サイズ一致・圧縮率・
        エントロピーで落としてから返す (素朴な走査だと候補が数百件出る)。
        **RLE は既定で対象外** (任意のバイト列が展開できてしまい誤検出の主因)。
        nested が付いた候補は中身がさらに圧縮されている。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.find_compressed_blocks(start, end, min_size,
                                                   include_rle, limit), key)

    @server.tool()
    def render_tiles(address: str = None, length: int = None, bpp: int = 4,
                     tiles_per_row: int = 32, palette_address: str = None,
                     sprite_size: str = None, source_path: str = None,
                     offset: int = 0, out_path: str = None, scale: int = 1,
                     show_index: bool = False, index_base: int = 0,
                     index_hex: bool = True, layout: str = "tiles",
                     width: int = None, program: str = None) -> dict:
        """タイル / 直線配置のグラフィックを PNG に描き出してパスを返す。

        形式当ては「見る」のが一番速い。4bpp / 8bpp を切り替えて試すこと。
        **sprite_size="[4,4]" のように渡すと 32x32 スプライト単位で並べ直す**
        (1D マッピングのスプライトはこれをやらないと形が読めない)。
        palette_address を渡すと BGR555 で着色、省略時はグレースケール。
        source_path を指定すると memory ではなくそのファイルを読む
        (decompress の出力をそのまま渡せる)。
        ★source_path で読めるのは <project>/extracted/ と <project>/dumps/、
        bridge_config.json の source_roots に人間が書いたフォルダの配下だけ
        (resolve 後に判定。範囲外・UNC・デバイスパスは拒否)。
        出力画像は一辺 16384 / 1600 万画素まで (超えるときは length / scale を絞る)。

        **フォントの文字対応表を作るときは show_index=true。** 各タイルに番号が
        焼き込まれるので、画像を見ながら decode_text の表をそのまま書き起こせる。
        index_base に符号の開始値 (例 0x20) を渡すとその値から振る。

        **layout="linear" + width=... にすると 8x8 タイルに並べ替えない。**
        PS1 のテクスチャや素のビットマップはタイル配置ではないので、
        これを付けないと形が崩れる (PS1 の TIM なら render_tim の方が確実)。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.render_tiles(address, length, bpp, tiles_per_row,
                                         palette_address, sprite_size,
                                         source_path, offset, out_path,
                                         scale, show_index, index_base,
                                         index_hex, layout, width), key)

    @server.tool()
    def render_tim(address: str = None, source_path: str = None,
                   offset: int = 0, clut_index: int = 0,
                   out_path: str = None, scale: int = 1,
                   program: str = None) -> dict:
        """**PS1 の TIM 画像**を PNG に描き出してパスを返す。

        PS1 のテクスチャ / フォント / UI はほぼ TIM で入っている。
        render_tiles は GBA の **8x8 タイル**前提なので、**直線配置**の TIM は
        そのままでは形が崩れる。こちらは幅・深さ・CLUT を全部ヘッダから読む。
        4bpp / 8bpp (CLUT) / 16bpp / 24bpp に対応。
        **clut_index で色違いのパレットを切り替えられる**
        (1 枚の絵に CLUT が複数入っているのが普通)。
        透明は「色 0x0000 かつ STP ビット 0」で判定する。
        位置が分からないときは find_tim_blocks で探す。
        source_path を指定すると memory ではなくそのファイルを読む
        (dumps/ に置いた CD 内のファイルや decompress の出力をそのまま渡せる)。
        ★source_path で読めるのは <project>/extracted/ と <project>/dumps/、
        bridge_config.json の source_roots に人間が書いたフォルダの配下だけ
        (resolve 後に判定。範囲外・UNC・デバイスパスは拒否)。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.render_tim(address, source_path, offset,
                                       clut_index, out_path, scale), key)

    @server.tool()
    def find_tim_blocks(start: str = None, end: str = None,
                        limit: int = DEFAULT_LIMIT,
                        program: str = None) -> dict:
        """範囲を走査して **PS1 の TIM 画像**の位置を列挙する。

        CD 内のファイルやオーバーレイには TIM がまとめて置かれているのが普通で、
        位置が分からないと render_tim を呼べない。ヘッダが読めて宣言サイズが
        範囲に収まるものだけを出す (見た目だけ似たゴミを弾く)。
        見つけた address をそのまま render_tim に渡せる。
        **CD 内のファイルを見るなら、先に overlays に登録すること**
        (この走査は export 済みブロックとオーバーレイだけを見る)。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.find_tim_blocks(start, end, limit), key)

    @server.tool()
    def list_undefined_ranges(min_size: int = 0x40, block: str = None,
                              executable_only: bool = False,
                              initialized_only: bool = True,
                              sort: str = "size", offset: int = 0,
                              limit: int = DEFAULT_LIMIT,
                              with_refs: bool = False, classify: bool = False,
                              program: str = None) -> dict:
        """Ghidra がまだ何も割り当てていない領域を大きい順に返す。

        「次にどこを見るか」を決めるための道具。undefined_ranges.json は
        数万件になることがあり、件数だけでは使えない。
        既定で 1 バイトの隙間と未初期化ブロック (BSS/VRAM) を除く。
        **with_refs=true にすると、返した範囲を指すコードの件数が付く** —
        参照があるのに未定義な領域は読む価値が高い。
        **classify=true にすると、それぞれが何なのか (コード / ポインタ表 /
        文字列 / 浮動小数 / 圧縮 / 詰め物) を推定して、次に呼ぶツールも添える。**

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.list_undefined_ranges(
            min_size, block, executable_only, initialized_only, sort,
            offset, limit, with_refs, classify), key)

    @server.tool()
    def find_bytes(pattern: str, start: str = None, end: str = None,
                   align: int = 1, limit: int = DEFAULT_LIMIT,
                   context: int = 16, program: str = None) -> dict:
        """export 済みメモリイメージからバイト列を検索する (AOB スキャン)。

        `??` がワイルドカード ("48 8B ?? ?? 89")。空白は自由。
        既知シグネチャ探し、「この構造体は他にもあるか」、命令パターン探しに使う。
        命令列を探すときは align=4 (MIPS/ARM) / 2 (SH/Thumb) を付けると
        誤検出が減る。total は limit 前の真の件数。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.find_bytes(pattern, start, end, align, limit,
                                       context), key)

    @server.tool()
    def search_programs(query: str, kind: str = "strings",
                        limit: int = DEFAULT_LIMIT, programs: list = None,
                        align: int = 1, ignore_case: bool = True) -> dict:
        """**全 Program を横断して**探す (この 1 つだけ program 引数が不要)。

        「この文字列 / バイト列 / 関数名はどの Program にある?」に一発で答える。
        kind は strings (既定) / functions / bytes。bytes は `??` ワイルドカード可。
        EXE 本体 + オーバーレイ、ROM + 展開後、**製品版 + 修正版**のような
        構成で特に効く。programs で対象を絞れる。
        errors に入った Program は「0 件」ではなく「調べられなかった」なので、
        混同しないこと。
        """
        return search_programs_impl(resolver, query, kind, limit, programs,
                                    align, ignore_case)

    @server.tool()
    def diff_programs(program_a: str, program_b: str, what: str = "all",
                      limit: int = DEFAULT_LIMIT, gap: int = 8) -> dict:
        """2 つの Program を比べる (製品版 vs 修正版など)。

        what=functions で増減とリネーム、strings で文字列の増減、
        **bytes で同じ番地のバイト差分**を返す。bytes の各区間には
        A / B それぞれの関数名が付くので「どの関数が変わったか」が分かる。

        ★bytes は**番地が揃っている前提**。基準がずれている Program 同士
        (ROM と展開後など) を比べても意味がないので、先に translate_address で
        対応を確かめること。
        """
        return diff_programs_impl(resolver, program_a, program_b, what,
                                  limit, gap)

    @server.tool()
    def find_text(encodings: list = None, min_chars: int = 3,
                  min_japanese: int = 2, start: str = None, end: str = None,
                  require_terminator: bool = True,
                  allow_halfwidth: bool = False, level2_kanji: bool = False,
                  min_kana: int = 1, only_missing: bool = True,
                  limit: int = DEFAULT_LIMIT, as_proposal: bool = False,
                  proposal_kind: str = "comments", label_prefix: str = None,
                  program: str = None) -> dict:
        """Ghidra が拾えなかった文字列 (主に日本語) を memory イメージから探す。

        Ghidra の文字列検出は基本 ASCII なので、Shift-JIS の日本語ラベルは
        strings.json にほとんど出てこない。encodings は sjis / utf8 / eucjp。
        誤検出との戦いが本体。既定で半角カタカナを数えず、かな/漢字 2 文字以上と
        NUL 終端を要求し、珍しい符号位置が混ざるものを捨てる (この 4 つが無いと
        数万件の誤検出が出る)。緩めたいときは allow_halfwidth /
        min_japanese / require_terminator を調整する。
        **推定なので誤検出は必ず混ざる** — text を読んで意味が通るものだけ採用する。
        as_proposal=true で提案の形も返す。proposal_kind で種類を選ぶ:
        comments (既定) = proposed_comments.json / labels = proposed_labels.json /
        both = 両方。**labels は allowed_apply_operations に "labels" が要る**
        (既定禁止)。テキストは自動で名前に正規化される
        (全角英数は半角へ、空白と記号は _ へ)。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.find_text(encodings, min_chars, min_japanese,
                                      start, end, require_terminator,
                                      allow_halfwidth, level2_kanji,
                                      min_kana, only_missing, limit,
                                      as_proposal, proposal_kind,
                                      label_prefix), key)

    @server.tool()
    def decode_text(address: str, table: dict = None, table_name: str = None,
                    length: int = 256, stop_at: str = None,
                    as_proposal: bool = False, proposal_kind: str = "comments",
                    label_prefix: str = None, program: str = None) -> dict:
        """独自符号のテキストを、文字対応表を使って読む。

        ゲーム独自の文字コードは標準の符号化では読めない。table に
        16 進キーと文字の辞書をその場で渡すか、bridge_config.json の
        text_tables に置いた表を table_name で使う。2 バイト単位の表も可。
        as_proposal=true で提案の形も返す (proposal_kind: comments / labels / both)。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.decode_text(address, table, table_name, length,
                                        stop_at, as_proposal, proposal_kind,
                                        label_prefix), key)

    @server.tool()
    def classify_range(start: str, end: str = None, length: int = None,
                       sample: int = 0x800, program: str = None) -> dict:
        """その範囲が **何なのか** を推定し、次に呼ぶべきツールまで返す。

        list_undefined_ranges は「未定義領域が何件ある」までしか言えない。
        コード / ポインタ表 / 文字列 / 浮動小数 / 圧縮 / 詰め物 を見分けて、
        優先順位を付けるための道具。**推定なので、各観点のスコアと
        根拠になった数字を必ず見ること。** 決め手が無ければ verdict=null を返す
        (無理に断定しない)。大きい範囲は先頭 sample バイトだけ見る。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.classify_range(start, end, length, sample), key)

    @server.tool()
    def list_runtime_observations(source: str = None, kind: str = None,
                                  scenario: str = None, start: str = None,
                                  end: str = None, file: str = None,
                                  offset: int = 0, limit: int = DEFAULT_LIMIT,
                                  program: str = None) -> dict:
        """外部エミュレータで観測した **実行時の記録** を Ghidra 番地で一覧する。

        エミュレータのデバッガなど (観測の手段は問わない) で観測した結果を、
        `<project_root>/runtime_observations/` に JSON で保存しておくと、
        ここから**静的解析と同じアドレス基準で**引ける。

        ★**この MCP はエミュレータを起動も接続も制御もしない。**
        読むのはプロジェクト内に保存された JSON だけ (保存するのは人間か解析セッション)。
        書き込み・ブレーク・入力・セーブステート操作は一切行わない。

        kind は execute / read / write。start/end は **Ghidra 番地**で絞る。
        変換できなかった観測は捨てずに `unmapped` へ理由つきで入る
        (規則が無い / 範囲外 / 規則名が違う)。**推測変換はしない。**
        ★**観測 0 件は「未使用」ではない。** 各ファイルの coverage_note で
        どこまで実行したかを必ず確認すること。
        形式は schemas/runtime_observations.schema.json、
        最小例は samples/runtime_observations.sample.json。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.list_runtime_observations(
            source, kind, scenario, start, end, file, offset, limit), key)

    @server.tool()
    def get_runtime_range_evidence(start: str, end: str = None,
                                   length: int = None, source: str = None,
                                   scenario: str = None, file: str = None,
                                   include_static_xrefs: bool = False,
                                   max_pcs: int = 5,
                                   program: str = None) -> dict:
        """Ghidra の番地範囲に **実行時に触れた記録があるか** を要約する。

        「この表は本当に使われているのか」「この関数は通るのか」に、
        **観測できた範囲で**答える。execute / read / write を分けて集計し、
        合計回数・代表的な PC・場面・観測元・ファイルを返す。

        ★verdict は observed_execute / observed_read / observed_write /
        observed_multiple / **not_observed** / **coverage_unknown** のいずれか。
        **`unused` は無い。観測されなかったことは未使用の証明ではない。**
        not_observed のときは、どのファイル・どの場面だけを見たかを必ず添える。

        size のある read/write は範囲として扱い、1 バイトでも重なれば該当。
        include_static_xrefs=true にすると範囲先頭への xref を 10 件だけ添える
        (xrefs.json の索引を読むだけ)。**find_address_refs や全メモリ走査は
        ここからは起こさない** — 重い静的探索は呼ぶ側が明示的に行うこと。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.get_runtime_range_evidence(
            start, end, length, source, scenario, file,
            include_static_xrefs, max_pcs), key)

    @server.tool()
    def list_comments(contains: str = None, start: str = None, end: str = None,
                      type: str = None, ai_only: bool = False,
                      with_function: bool = True, offset: int = 0,
                      limit: int = DEFAULT_LIMIT, program: str = None) -> dict:
        """その番地に付いている **コメント** を一覧する。

        ★**前のセッションで確定したことはここに書かれている。**
        解析を始める前に、対象範囲をこれで一度さらうこと（同じ場所を二度解析するのを防ぐ）。
        この道具箱の往復は「AI がコメント案 → 人間が apply_comments.py で反映 →
        次のセッションが続きから」なので、これを読まないと前回の結論が失われる。
        未定義領域やデータ番地のコメントは疑似 C には出ないので、なおさら。

        ai_only=true で `[AI]` 始まり (AI の所見) だけに絞れる。
        is_ai_comment=false は**人間が書いたもので、こちらの方が強い情報**。
        start/end でアドレス範囲、contains で本文、type で種別
        (eol / pre / post / plate / repeatable) を絞る。
        どの関数の中かも添えるので、番地だけ見て迷わない。
        反映は人間が行うので、この MCP からコメントを書くことはできない。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.list_comments(contains, start, end, type, ai_only,
                                          with_function, offset, limit), key)

    @server.tool()
    def list_labels(name_contains: str = None, start: str = None,
                    end: str = None, source: str = None,
                    include_functions: bool = False, with_type: bool = True,
                    offset: int = 0, limit: int = DEFAULT_LIMIT,
                    program: str = None) -> dict:
        """その番地に**付いている名前**を一覧する (データラベル)。

        関数名は list_functions、**データに付いた名前はこちら**。
        「人間が既に何を名付けたか」「apply_labels.py で何を付けたか」が分かる。
        自動生成名 (LAB_ / DAT_ 等) は export の時点で除いてある。
        defined_data.json があれば人間が付けた型も添える
        (**describe_data の推定よりこちらが正**)。
        source で USER_DEFINED / IMPORTED / ANALYSIS を絞れる。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.list_labels(name_contains, start, end, source,
                                        include_functions, with_type,
                                        offset, limit), key)

    @server.tool()
    def get_struct_layout(type_name: str, flatten: bool = False,
                          max_depth: int = 8, limit: int = 2000,
                          program: str = None) -> dict:
        """構造体 / クラスのフィールド配置をオフセット付きで返す (datatypes.json)。

        疑似 C の `self->resourceTable` が **何バイト目か** を引く。型名は
        完全一致 → 大文字小文字無視 → 部分一致 の順で探し、候補が複数なら
        candidates を返す (path で指定し直す)。基底クラスは先頭フィールド
        (super 等) としてそのまま出る。embedded_in はその型を値として持つ型。
        flatten=true で入れ子の構造体と配列を展開し、`xformUnit.matrix.m[3][0]`
        の形で最終オフセットを flat / listing に出す。
        datatypes.json が無ければ export_context.py の再実行を促すエラー。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.get_struct_layout(type_name, flatten, max_depth,
                                              limit), key)

    @server.tool()
    def find_field(field_path: str, type_name: str = None,
                   limit: int = DEFAULT_LIMIT, program: str = None) -> dict:
        """フィールド名から、それを持つ型とオフセットを返す (datatypes.json)。

        疑似 C に出たものをそのまま貼ってよい: `resourceTable` /
        `xformUnit.matrix.m[3]` / `unit->xformUnit.matrix.m[3]`
        (先頭の変数名はフィールドに無ければ外す = ignored_prefix)。
        `a->b` でポインタを辿ったときは、offset はポインタ先の型の先頭から。
        also_at はその型を値として持つ型 (派生クラス等) で見たときのオフセット。
        type_name で型を絞れる (その型に無ければ基底側も探す)。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.find_field(field_path, type_name, limit), key)

    @server.tool()
    def resolve_gp_offset(offset: str, at: str = None, program: str = None) -> dict:
        """MIPS の gp 相対の変位 (-29048 / -0x7178) を絶対番地と名前に直す。

        `lw v0,-29048(gp)` の参照先を引く。名前は labels → functions →
        defined_data → 実行ファイルの .symtab の順で探す。
        at に命令の番地を渡すと、範囲ごとに gp が違う Program でもその番地の gp を使う。
        gp の根拠は gp_source (全候補は get_program_info の gp_candidates)。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.resolve_gp_offset(offset, at), key)

    @server.tool()
    def resolve_symbol(name: str, limit: int = 20, program: str = None) -> dict:
        """名前から番地を引く (functions.json → labels.json → defined_data.json → .symtab)。

        疑似 C の `_vt_7GmStage` や `GameManagerInst` を番地にする。
        `_vt_` で始まる名前は kind=vtable。完全一致 → 大文字小文字無視 の順で、
        無ければ部分一致を suggestions に出す。labels.json が無い古い export でも
        止めずに functions.json と実行ファイルの .symtab で探し、warnings で
        export_context.py の再実行を促す。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.resolve_symbol(name, limit), key)

    @server.tool()
    def translate_address(address: str, using: str = None,
                          reverse: bool = False, program: str = None) -> dict:
        """Program 間でアドレスを換算し、根拠つきで返す。

        1 ゲームで複数のアドレス空間 (親 ROM / ローダ / 本編) を扱うときに、
        手計算の取り違えを防ぐ。規則は bridge_config.json の address_translations
        に書く (name / src_base / block_size / table)。reverse=true で逆向き。
        使える規則名は get_export_status にも出る。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.translate_address(address, using, reverse), key)

    @server.tool()
    def get_export_status(program: str = None) -> dict:
        """export の鮮度 (各ファイルの mtime) と件数サマリを返す。再 export は人間が GUI で行う。

        program: 対象 Program のキー (list_programs で確認)。複数 Program
        モードで省略すると直前に使った Program (program_defaulted=true)。
        """
        key, target = resolver.get(program)
        return _echo(target.get_export_status(), key)

    return server


def main():
    """エントリポイント。単一 Program / 複数 Program の 2 モードを切り替えます。

    単一 Program モード (従来どおり・後方互換):
        CCT_PROJECT_ROOT=<claude_project> か、第1引数にそのパスを渡す。

    複数 Program モード:
        --multi                  … 既定のレジストリ (<toolbox>/../mcp_registry.json)
        --registry <path>        … レジストリを明示指定
        CCT_MCP_REGISTRY=<path>  … 環境変数でも可
      サーバ 1 個で全 Program を扱えるので、ゲームを増やしてもツール定義が
      増えません (13 Program × 15 ツール = 195 個 → 16 個)。
    """
    argv = sys.argv[1:]
    selftest = "--selftest" in argv

    registry_path = os.environ.get("CCT_MCP_REGISTRY")
    multi = "--multi" in argv or bool(registry_path)
    positional = []
    skip = False
    for i, arg in enumerate(argv):
        if skip:
            skip = False
            continue
        if arg == "--registry":
            if i + 1 >= len(argv):
                raise SystemExit("エラー: --registry の後にパスを指定してください。")
            registry_path = argv[i + 1]
            multi = True
            skip = True
        elif arg.startswith("--"):
            continue
        else:
            positional.append(arg)

    if multi:
        if not registry_path:
            registry_path = _HERE.parent.parent / "mcp_registry.json"
        try:
            max_hot = int(os.environ.get("CCT_MAX_HOT_PROGRAMS",
                                         DEFAULT_MAX_HOT_PROGRAMS))
        except ValueError:
            max_hot = DEFAULT_MAX_HOT_PROGRAMS
        # registry_path ごと渡す (起動後にレジストリが変わっても読み直せるように)。
        resolver = ProgramResolver(registry_path=registry_path, max_hot=max_hot)
        if selftest:
            run_multi_selftest(resolver, positional[0] if positional else None)
            return
    else:
        root = resolve_project_root(sys.argv)
        resolver = ProgramResolver(single_key=Path(root).name, single_root=root)
        if selftest:
            run_selftest(resolver.get()[1])
            return

    server = build_tools(resolver)
    server.run()


def run_multi_selftest(resolver, program=None):
    """複数 Program モードの解決まわりを確認します (全 Program は回しません)。"""
    listing = resolver.list_programs()
    print("=== multi selftest: {0} Program ===".format(listing["total"]))
    for item in listing["programs"]:
        print("  {0:<28} exports={1} {2}".format(
            item["program"], item["exports_found"],
            item.get("program_name") or ""))

    try:
        resolver.get()
        print("[m1] NG: program 省略がエラーになりませんでした。")
    except ValueError as exc:
        print("[m1] OK: program 省略は候補つきで拒否 ({0}…)".format(str(exc)[:36]))
    try:
        resolver.get("no_such_program")
        print("[m2] NG: 未知の program がエラーになりませんでした。")
    except ValueError as exc:
        print("[m2] OK: 未知の program は候補つきで拒否 ({0}…)".format(str(exc)[:36]))

    _selftest_registry_reload(resolver.max_hot)

    ready =[i["program"] for i in listing["programs"] if i["exports_found"]]
    target = program or (ready[0] if ready else None)
    if target is None:
        print("[m3] export 済みの Program が無いのでスキップ。")
        return
    key, repo = resolver.get(target)
    print("[m3] OK: {0} を解決 ({1})".format(key, repo.project_root))
    print("[m4] echo: {0}".format(_echo({"x": 1}, key)))

    # LRU が上限を守るか (max_hot を超えて触っても常駐数が増えないこと)。
    for item in listing["programs"]:
        if item["exports_found"]:
            resolver.get(item["program"])
    hot = len(resolver._hot)
    print("[m5] {0}: 常駐 Program 数 {1} <= 上限 {2}".format(
        "OK" if hot <= resolver.max_hot else "NG", hot, resolver.max_hot))

    run_selftest(repo)


def _selftest_registry_reload(max_hot):
    """[m6] レジストリを書き換えたら**再起動なしで**新しいキーが引けるかを確かめます。

    本物のレジストリは触らず、一時フォルダに作ったものを書き換えます
    """
    import tempfile
    import time

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        roots = {}
        for name in ("old", "new"):
            roots[name] = tmp / name / "ghidra_exports"
            roots[name].mkdir(parents=True)
            (roots[name] / "program.json").write_text("{}", encoding="utf-8")
        reg = tmp / "mcp_registry.json"
        base = time.time_ns()

        def write(text, step):
            """レジストリを書き、mtime を step 秒ずつ進めます (人手の保存を模す)。"""
            reg.write_text(text, encoding="utf-8")
            os.utime(reg, ns=(base + step * 10**9, base + step * 10**9))

        old = {"old": {"root": str(roots["old"].parent)}}
        write(json.dumps({"games": old}), 0)
        resolver = ProgramResolver(registry_path=reg, max_hot=max_hot)
        resolver.get("old")

        grown = dict(old, added={"programs": {
            "main": {"root": str(roots["new"].parent)}}})
        write(json.dumps({"games": grown}), 1)
        try:
            key, repo = resolver.get("added:main")
            ok = key == "added:main" and repo.project_root == roots["new"].parent.resolve()
            print("[m6a] {0}: 追加したゲームを再起動なしで解決 ({1})".format(
                "OK" if ok else "NG", key))
        except ValueError as exc:
            print("[m6a] NG: 追加したゲームが引けません ({0}…)".format(str(exc)[:40]))

        write("{ 壊れた JSON", 2)
        try:
            resolver.get("added:main")
            warned = "registry_warning" in resolver.list_programs()
            print("[m6b] {0}: 壊れたレジストリでも落ちず、直前の内容を使う (warning={1})".format(
                "OK" if warned else "NG", warned))
        except Exception as exc:          # 落ちたら NG として表示する
            print("[m6b] NG: 壊れたレジストリで例外 ({0}…)".format(str(exc)[:40]))

        write(json.dumps({"games": old}), 3)
        try:
            resolver.get("added:main")
            print("[m6c] NG: 消したゲームがまだ引けます。")
        except ValueError:
            gone = "added:main" not in resolver._hot
            print("[m6c] {0}: 消したゲームは拒否し、常駐からも外す".format(
                "OK" if gone else "NG"))


if __name__ == "__main__":
    main()
