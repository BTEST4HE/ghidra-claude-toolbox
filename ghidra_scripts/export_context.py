# -*- coding: utf-8 -*-
# Ghidra Claude Toolbox - export_context.py
#
# Ghidra GUI (Script Manager) から手動実行するスクリプトです。
# 現在開いている currentProgram から、Claude Code / Codex が読める
# 解析情報を JSON として ghidra_exports/ 配下に出力します。
#
# 本スクリプトは Ghidra 上の Jython (Python 2.7 互換) で動作します。
# そのため f-string や Python 3 専用構文は使用していません。
#
# 注意:
#   - このスクリプトは export 専用です。Program を一切書き換えません。
#   - 特定 Ghidra バージョンに強く依存しないよう、取得できない情報は
#     None / "unknown" を入れて握りつぶし、ログに残す方針です。
#
#@category ClaudeToolbox
#@menupath Tools.ClaudeToolbox.Export Context
#@runtime Jython

from __future__ import print_function

import json
import os
import sys
import time
import traceback

try:
    import threading
except Exception:
    threading = None

from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import RefType


# Ghidra のコメント種別 (CodeUnit 定数) と、道具箱で使う名前の対応表です。
COMMENT_TYPE_TO_NAME = {
    CodeUnit.EOL_COMMENT: "eol",
    CodeUnit.PRE_COMMENT: "pre",
    CodeUnit.POST_COMMENT: "post",
    CodeUnit.PLATE_COMMENT: "plate",
    CodeUnit.REPEATABLE_COMMENT: "repeatable",
}

# decompile/ に出力する関数の上限です。0 以下なら無制限になります。
# bridge_config.json の "decompile_limit" で上書き可。
# ※ 無制限 (0) で全関数を逐次 decompile すると、RAM ダンプ等では「関数」と誤認
#   された領域がタイムアウトを連発し非常に遅くなる。範囲を絞る (下記) のが安全。
DECOMPILE_LIMIT = 0

# decompile のタイムアウト秒数です。bridge_config.json の
# "decompile_timeout_seconds" で上書き可。ゴミ関数を素早く諦めるため既定を短くしている。
DECOMPILE_TIMEOUT_SECONDS = 20

# ★ハードタイムアウト秒数 (bridge_config.json の "decompile_hard_timeout_seconds" で上書き可)。
# 上の DECOMPILE_TIMEOUT_SECONDS は Ghidra decompiler 側が経過時間を自分でチェックして
# 諦める「協調的」タイムアウトで、巨大な switch/ジャンプテーブルを含む病的関数では
# チェック地点に到達せず永久に戻ってこないことがある (GUI ごとハングする)。
# そこで decompile を別スレッドで走らせ、この秒数を過ぎたらスレッドを見捨てて次の関数へ進む。
# None なら実行時に decompile_timeout_seconds + 15 秒。0 以下なら無効 (従来どおり Ghidra 任せ)。
DECOMPILE_HARD_TIMEOUT_SECONDS = None

# メモリイメージ export の既定値です (bridge_config.json で上書き可)。
# 既定は False。読み取り専用 MCP の get_disassembly / find_address_refs を使う
# ゲームだけ true にしてください (未関数化コードを生の逆アセンブルで読むための入力)。
# ⚠️ 生バイナリなので巨大になりえます。必ず下の 2 段の上限で守ること
#    (旧 *_instructions.json が各 380MB になった反省)。
EXPORT_MEMORY = False
EXPORT_MEMORY_MAX_MB = 32          # 1 ブロックあたりの上限
EXPORT_MEMORY_TOTAL_MAX_MB = 128   # 全ブロック合計の上限

# decompile を特定アドレス範囲に絞るための既定値です (None=全域)。
# bridge_config.json の "decompile_start" / "decompile_end" で上書きするのが基本。
# 解析対象の関数群が固まっているなら範囲指定で export 時間を劇的に短縮できる。
DECOMPILE_START = None
DECOMPILE_END = None

# ★未初期化ブロックの関数を decompile 対象から外すかどうか (bridge_config の
# "decompile_skip_uninitialized")。既定 True。
# 未初期化ブロックのダミー関数は、decompile が戻った後 (getC() / 書き込み側) で
# Ghidra ごと固まることがある (ハードタイムアウトの外側なので止められない)。
# バイト実体が無いので decompile しても得るものが無く、外しても失うものが無い。
DECOMPILE_SKIP_UNINITIALIZED = True

# ★body が 1 バイトしかない関数を decompile 対象から外すかどうか
# ("decompile_skip_tiny")。既定 True。上記のようなダミー関数は body が 1 バイトで、
# 実コードで 1 バイト関数はまず存在しない。
DECOMPILE_SKIP_TINY = True

# ★getC() の出力がこのサイズを超えたら書き込まずに skip する
# ("decompile_max_output_kb")。0 以下で無効。巨大文字列の書き出しで GC が
# スラッシングする (=エラーも出ずに CPU だけ回り続ける) のを避けるためのガード。
DECOMPILE_MAX_OUTPUT_KB = 512

# ★decompile する直前に関数名をログへ出すか ("decompile_verbose")。既定 False。
# True にすると固まったときログ末尾で犯人が即分かる (冗長になるので既定は off)。
DECOMPILE_VERBOSE = False

# ★疑似 C の 1 行 <-> 命令アドレスの対応表を出すか ("decompile_line_map")。既定 True。
# 疑似 C で怪しい行を見つけても、その行がどの番地かが分からないと、毎回
# get_disassembly を並べて対応を取ることになる (行の番地はメモにも改造コードにも
# ブレークポイントにもそのまま使う)。この対応は **decompiler のマークアップから
# しか取れない**ので、ここで一緒に出しておく。
# 出力先は decompile/<name>_<entry>.lines.json (疑似 C 本体とは別ファイル)。
# 失敗しても decompile 自体は止めない (対応表が無くても .c は読める)。
DECOMPILE_LINE_MAP = True

# ★decompile の対象範囲を **実行前に** 選ばせるかどうか ("decompile_scope")。
# "ask"   … 既定。export を始める前にダイアログで
#           「上限 N 件だけ / 全関数 / decompile しない」を選ぶ。
#           xrefs 等の重い工程が終わってから「20 件しか出ていない」と気づくのを防ぐ。
# "limit" … 聞かずに decompile_limit をそのまま使う (従来どおり)。
# "all"   … 聞かずに全関数を decompile する (上限なし)。
# decompile_targets が指定されているときは対象が確定しているので聞かない。
# ダイアログを出せない環境 (ヘッドレス等) では設定値のまま続行する。
DECOMPILE_SCOPE = "ask"
DECOMPILE_SCOPES = ("ask", "limit", "all")

# decompile ループの進捗ログを何件ごとに出すか。0 以下で無効。
DECOMPILE_PROGRESS_EVERY = 50

# export できる工程の名前。bridge_config の "export_only" でこの中から選べる。
# 例: "export_only": ["decompile"] なら decompile だけ作り直し、他は既存ファイルを残す。
# 「関数化 → 再 export → 疑似C を読む」を回すとき、xrefs (48MB) まで毎回作り直さずに済む。
EXPORT_SECTIONS = ("program", "memory", "functions", "strings", "comments",
                   "labels", "defined_data", "datatypes",
                   "xrefs", "undefined_ranges", "decompile")


class ExportLogger(object):
    """export 処理の進捗とエラーを画面とログファイルへ **逐次** 残すロガーです。

    ⚠️ 最後にまとめて書き出す方式だと、途中でハングして強制終了したとき
       **export_log.txt が 1 行も残らず**、原因を調べられません。
       `open_log()` 後は `log()` のたびに write + flush するので、
       強制終了しても直前までのログが残ります。

    出力先が決まる前 (askDirectory の前) のログはメモリに貯め、`open_log()` で
    まとめて書き出します。
    """

    def __init__(self):
        """ログ行バッファとストリームを初期化します。"""
        self.lines = []
        self._stream = None
        self._path = None

    def open_log(self, log_path):
        """ログファイルを開き、それまでに貯めた行を書き出して逐次書き込みに切り替えます。"""
        import codecs
        try:
            stream = codecs.open(log_path, "w", "utf-8")
        except Exception:
            self.log(u"WARNING: ログファイルを開けませんでした: {0}".format(log_path))
            return
        self._stream = stream
        self._path = log_path
        for line in self.lines:
            self._emit(line)
        self.log(u"[log] 逐次書き出しを開始しました: {0}".format(log_path))

    def _emit(self, text):
        """1 行をファイルへ書いて即 flush します (ハング時にも残るように)。"""
        if self._stream is None:
            return
        try:
            self._stream.write(text)
            self._stream.write(u"\n")
            self._stream.flush()
        except Exception:
            # ログ書き込みの失敗で export 本体を止めない。
            self._stream = None

    def log(self, message):
        """1 行ログを記録し、Ghidra コンソールとログファイルへ出力します。"""
        text = u"{0}".format(message)
        self.lines.append(text)
        self._emit(text)
        try:
            println(text)
        except Exception:
            print(text)

    def save(self, log_path):
        """ログを確定します。

        逐次書き出し中ならストリームを閉じるだけです (中身は既に書けている)。
        open_log を通らなかった場合のみ、従来どおり全行をまとめて書き出します。
        """
        if self._stream is not None:
            try:
                self._stream.flush()
                self._stream.close()
            except Exception:
                pass
            self._stream = None
            return
        write_text(log_path, u"\n".join(self.lines) + u"\n")


def _replace_file(tmp_path, path):
    """一時ファイルを最終パスへ置き換えます (可能なら原子的に)。"""
    try:
        # 同一ディレクトリ内なら Windows でも原子的に置き換えられる。
        from java.nio.file import Paths, Files, StandardCopyOption
        Files.move(Paths.get(tmp_path), Paths.get(path),
                   StandardCopyOption.REPLACE_EXISTING)
        return
    except Exception:
        pass
    # フォールバック: Python 2.7 の os.rename は Windows で上書きできないので先に消す。
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass
    os.rename(tmp_path, path)


def _write_parts(path, parts, atomic):
    """複数の文字列を順に UTF-8 で書き出します。

    parts をリストで受けるのは、巨大な文字列を連結してコピーを作らないためです
    (xrefs.json は 48MB 級。`text + u"\\n"` だけで 48MB の複製が生まれる)。
    atomic=True なら一時ファイルへ書いてから置き換えます。
    """
    import codecs
    target = path + ".tmp" if atomic else path
    f = codecs.open(target, "w", "utf-8")
    try:
        for part in parts:
            f.write(part)
        f.flush()
    except Exception:
        try:
            f.close()
        except Exception:
            pass
        if atomic:
            # 中途半端な一時ファイルを残さない。
            try:
                os.remove(target)
            except Exception:
                pass
        raise
    f.close()
    if atomic:
        _replace_file(target, path)


def write_text(path, text, atomic=False):
    """文字列を UTF-8 でファイルに書き出します。

    atomic=True のときは一時ファイルへ書いてから置き換えます。途中で失敗しても
    **中途半端なファイルを残さない**ためです (0 バイトの .c が残ると、次回以降
    「decompile 済み」と誤認する)。
    """
    _write_parts(path, [text], atomic)


def write_json(path, obj, compact=False):
    """オブジェクトを UTF-8 JSON として書き出します。

    compact=True のときは indent / sort_keys を付けず separators を詰めて出力します。
    xrefs.json のような巨大・機械読み専用のファイルで直列化コストとサイズを下げる用途。
    書き出しは atomic (一時ファイル + 置き換え) です。途中で失敗したときに
    壊れた JSON が残ると、MCP 側がパースできず「再 export しろ」と言うしかなくなるため。
    """
    if compact:
        text = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
    else:
        text = json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False)
    _write_parts(path, [text, u"\n"], True)


def addr_to_str(address):
    """Ghidra Address を 0x 付き 16 進文字列に変換します。None も安全に扱います。"""
    if address is None:
        return None
    try:
        return "0x{0}".format(address.toString())
    except Exception:
        return None


def safe_call(func, default=None):
    """取得できないと例外になる API を、安全に呼び出すためのヘルパーです。"""
    try:
        return func()
    except Exception:
        return default


def load_bridge_config(out_root, logger):
    """出力先の親 (または直下) の bridge_config.json を読み、dict を返します。

    無い/壊れている場合は空 dict を返します。source_model や decompile_* の
    オプションをここから取り出します。bridge_config.json は通常 claude_project/
    直下にあり、ghidra_exports/ はその子フォルダなので親をたどって探します。
    """
    candidates = []
    parent = os.path.dirname(out_root)
    candidates.append(os.path.join(parent, "bridge_config.json"))
    candidates.append(os.path.join(out_root, "bridge_config.json"))
    for cfg_path in candidates:
        if os.path.isfile(cfg_path):
            try:
                import codecs
                f = codecs.open(cfg_path, "r", "utf-8")
                try:
                    data = json.load(f)
                finally:
                    f.close()
                logger.log(u"bridge_config.json found: source_model={0}".format(
                    data.get("source_model", "unknown")))
                return data
            except Exception:
                logger.log(u"WARNING: bridge_config.json の読み込みに失敗しました: {0}".format(cfg_path))
                return {}
    logger.log(u"bridge_config.json は見つかりませんでした。source_model=unknown とします。")
    return {}


def parse_cfg_addr(value):
    """bridge_config の decompile_start/end を int に変換します。

    '0x...' 文字列・10 進文字列・整数を受け付け、None / 不正は None を返します。
    """
    if value is None:
        return None
    try:
        text = str(value).strip()
        if text == "":
            return None
        if text.lower().startswith("0x"):
            return int(text, 16)
        return int(text)
    except Exception:
        return None


def cfg_flag(value, default=True):
    """bridge_config の真偽フラグを解釈します。

    JSON の true/false はもちろん、"false"/"0"/"no"/"off" 等の文字列も
    False とみなします (文字列はすべて truthy になる罠を避けるため)。
    """
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() not in ("false", "0", "no", "off", "")


def parse_export_only(value, logger):
    """bridge_config の "export_only" を工程名の set に正規化します。

    空 / 未指定なら空 set を返し、その場合は**全工程を実行**します
    (従来どおりの動作)。文字列 1 個も受け付けます ("decompile" など)。
    未知の名前は警告して無視します (タイプミスで黙って全部飛ぶのを防ぐため)。

    使いどころ: 「関数化 → 再 export → 疑似C を読む」の往復。decompile だけ
    作り直したいのに xrefs (大きい Program では数十 MB) まで毎回生成し直すのは無駄なので、
    "export_only": ["decompile"] で工程を絞れます。
    """
    if value is None:
        return set()
    if isinstance(value, basestring):   # noqa: F821 (Jython/Python2.7)
        value = [value]
    try:
        items = list(value)
    except Exception:
        logger.log(u"WARNING: export_only を解釈できません。全工程を実行します。")
        return set()

    wanted = set()
    for item in items:
        try:
            name = u"{0}".format(item).strip().lower()
        except Exception:
            continue
        if not name:
            continue
        if name in EXPORT_SECTIONS:
            wanted.add(name)
        else:
            logger.log(u"WARNING: export_only の '{0}' は未知の工程名です。無視します "
                       u"(使えるのは {1})。".format(name, u", ".join(EXPORT_SECTIONS)))
    return wanted


def _t():
    """現在時刻 (秒, float) を返します。取得できない環境では None。"""
    try:
        return time.time()
    except Exception:
        return None


def log_elapsed(logger, label, start, overall):
    """1 セクションの所要時間と、開始からの累計経過を [time] ログで出します。"""
    end = _t()
    if start is None or end is None or overall is None:
        return
    logger.log(u"[time] {0}: {1:.1f}s (elapsed {2:.1f}s)".format(
        label, end - start, end - overall))


def export_program(program, source_model, logger):
    """program.json 用の基本情報・メモリブロック・アドレス範囲を収集します。"""
    memory = program.getMemory()

    blocks = []
    exec_ranges = []
    initialized_ranges = []
    for block in memory.getBlocks():
        start = block.getStart()
        end = block.getEnd()
        block_info = {
            "name": safe_call(lambda: block.getName()),
            "start": addr_to_str(start),
            "end": addr_to_str(end),
            "size": safe_call(lambda: int(block.getSize())),
            "read": safe_call(lambda: bool(block.isRead())),
            "write": safe_call(lambda: bool(block.isWrite())),
            "execute": safe_call(lambda: bool(block.isExecute())),
            "initialized": safe_call(lambda: bool(block.isInitialized())),
        }
        blocks.append(block_info)
        rng = {"start": addr_to_str(start), "end": addr_to_str(end)}
        if block_info["execute"]:
            exec_ranges.append(rng)
        if block_info["initialized"]:
            initialized_ranges.append(rng)

    info = {
        "schema_version": "0.1",
        "source_model": source_model,
        "entry_points": export_entry_points(program, logger),
        "program_name": safe_call(lambda: program.getName()),
        "executable_path": safe_call(lambda: program.getExecutablePath()),
        "executable_format": safe_call(lambda: program.getExecutableFormat()),
        "language_id": safe_call(lambda: program.getLanguageID().getIdAsString()),
        "compiler_spec_id": safe_call(
            lambda: program.getCompilerSpec().getCompilerSpecID().getIdAsString()),
        "image_base": addr_to_str(safe_call(lambda: program.getImageBase())),
        "min_address": addr_to_str(safe_call(lambda: program.getMinAddress())),
        "max_address": addr_to_str(safe_call(lambda: program.getMaxAddress())),
        "memory_blocks": blocks,
        "address_ranges": {
            "min_address": addr_to_str(safe_call(lambda: program.getMinAddress())),
            "max_address": addr_to_str(safe_call(lambda: program.getMaxAddress())),
            "executable_block_ranges": exec_ranges,
            "initialized_block_ranges": initialized_ranges,
        },
    }
    context = export_register_context(program, logger)
    if context:
        info["register_context"] = context
    logger.log(u"program info collected: {0} memory blocks".format(len(blocks)))
    return info


# program.json に出すエントリポイントの上限 (ELF / PE なら普通は 1〜数個)。
MAX_ENTRY_POINTS = 64

# program.json の register_context に出すレジスタ。
# ★MIPS の gp は、`lw v0,-29048(gp)` の参照先を決めるのに要る。Ghidra は ELF の
#   `_gp` / .reginfo から gp をコンテキスト値として持っていて、疑似 C の
#   `GameManagerInst` はその値で解決されている。MCP は Ghidra に問い合わせないので、
#   ここで書き出しておかないと「Ghidra が使った gp」が MCP から見えない。
#   Program に無いレジスタは黙って飛ばす (MIPS 以外では何も出ない)。
CONTEXT_REGISTERS = ("gp",)
MAX_CONTEXT_RANGES = 256


def export_entry_points(program, logger):
    """外部エントリポイント (ELF の e_entry 等) の番地一覧を返します。

    MCP 側が「エントリ処理の lui gp / addiu gp」を探す起点にします。
    取れなければ空リストです (古い Ghidra でも export 自体は止めない)。
    """
    results = []
    table = safe_call(lambda: program.getSymbolTable())
    if table is None:
        return results
    try:
        iterator = table.getExternalEntryPointIterator()
    except Exception:
        return results
    try:
        for addr in iterator:
            if len(results) >= MAX_ENTRY_POINTS:
                break
            text = addr_to_str(addr)
            if text and text not in results:
                results.append(text)
    except Exception:
        logger.log(u"WARNING: エントリポイントの列挙に失敗しました。")
    return results


def _big_to_hex(value):
    """Java BigInteger / Python int を 0x 付き 16 進にします (取れなければ None)。"""
    if value is None:
        return None
    try:
        return u"0x{0:x}".format(long(value.toString()))   # noqa: F821 (Jython)
    except Exception:
        pass
    try:
        return u"0x{0:x}".format(int(value))
    except Exception:
        return None


def export_register_context(program, logger):
    """CONTEXT_REGISTERS の Ghidra コンテキスト値を、番地範囲ごとに返します。

    形: {"gp": {"ranges": [{"start", "end", "value"}], "truncated": bool}}
    範囲指定の値が無いときは既定値 (`getDefaultValue`) を "default" に入れます。
    どれも取れないレジスタは出しません (推測値を書かないため)。
    """
    ctx = safe_call(lambda: program.getProgramContext())
    if ctx is None:
        return {}
    out = {}
    for reg_name in CONTEXT_REGISTERS:
        reg = safe_call(lambda: ctx.getRegister(reg_name))
        if reg is None:
            continue
        ranges = []
        truncated = False
        try:
            for rng in ctx.getRegisterValueAddressRanges(reg):
                if len(ranges) >= MAX_CONTEXT_RANGES:
                    truncated = True
                    break
                start = rng.getMinAddress()
                value = _big_to_hex(safe_call(lambda: ctx.getValue(reg, start, False)))
                if value is None:
                    continue
                ranges.append({"start": addr_to_str(start),
                               "end": addr_to_str(rng.getMaxAddress()),
                               "value": value})
        except Exception:
            logger.log(u"WARNING: {0} のコンテキスト値を列挙できませんでした。".format(reg_name))
        entry = {"ranges": ranges, "truncated": truncated}
        if not ranges:
            probe = safe_call(lambda: program.getMinAddress())
            default = safe_call(lambda: ctx.getDefaultValue(reg, probe))
            value = _big_to_hex(safe_call(lambda: default.getUnsignedValue()))
            if value is None:
                continue
            entry["default"] = value
        out[reg_name] = entry
        logger.log(u"register_context: {0} = {1} 範囲{2}".format(
            reg_name, len(ranges), u" (上限で打ち切り)" if truncated else u""))
    return out


def _memory_block_bytes(memory, block, path, logger):
    """1 メモリブロックの生バイトをファイルへ書き出し、書けたバイト数を返します。

    1MB ずつ Java の byte[] に読んで FileOutputStream へ流します
    (Jython で 1 バイトずつ扱うと極端に遅いため)。
    """
    from jarray import zeros
    from java.io import FileOutputStream, BufferedOutputStream

    chunk = 1024 * 1024
    buf = zeros(chunk, "b")
    start = block.getStart()
    total = int(block.getSize())
    written = 0

    out = BufferedOutputStream(FileOutputStream(path))
    try:
        while written < total:
            if monitor.isCancelled():
                break
            want = chunk
            if total - written < chunk:
                want = total - written
            try:
                got = memory.getBytes(start.add(written), buf, 0, want)
            except Exception:
                logger.log(u"WARNING: memory: {0} の +0x{1:x} 以降が読めません。ここで打ち切ります。".format(
                    safe_call(lambda: block.getName()), written))
                break
            if got <= 0:
                break
            out.write(buf, 0, got)
            written += got
    finally:
        out.close()
    return written


def export_memory(program, out_root, logger, cfg):
    """メモリブロックの生バイトを memory/ 配下へ出力し、memory_map.json を返します。

    読み取り専用 MCP の `get_disassembly` / `find_address_refs` が、Ghidra に
    問い合わせずに未関数化コードを読むための入力です。**opt-in** (bridge_config の
    `export_memory: true`) で、既定では何も出力しません。

    サイズ暴走を防ぐため 2 段の上限を持ちます (旧 *_instructions.json が各 380MB に
    なった反省)。上限を超えたブロックは **スキップして memory_map に記録だけ残します**。
      - `export_memory_max_mb` (既定 32): 1 ブロックあたりの上限
      - `export_memory_total_max_mb` (既定 128): 合計の上限
      - `export_memory_blocks`: 出力するブロック名のリスト (省略時は全ブロック)
    未初期化ブロックは常に出力しません (中身が無いため)。
    """
    mem_dir = os.path.join(out_root, "memory")
    if not os.path.isdir(mem_dir):
        os.makedirs(mem_dir)

    try:
        max_mb = int(cfg.get("export_memory_max_mb", EXPORT_MEMORY_MAX_MB))
    except Exception:
        max_mb = EXPORT_MEMORY_MAX_MB
    try:
        total_max_mb = int(cfg.get("export_memory_total_max_mb", EXPORT_MEMORY_TOTAL_MAX_MB))
    except Exception:
        total_max_mb = EXPORT_MEMORY_TOTAL_MAX_MB
    max_bytes = max_mb * 1024 * 1024
    total_max_bytes = total_max_mb * 1024 * 1024

    only = cfg.get("export_memory_blocks") or []
    only_names = set()
    for name in only:
        try:
            only_names.add(u"{0}".format(name))
        except Exception:
            continue
    if only_names:
        logger.log(u"memory: 対象ブロックを {0} 個に限定します。".format(len(only_names)))

    # 前回 export の .bin を控えておき、今回参照されなくなったものを警告する
    # (勝手に消さない。消すかどうかは人間が決める)。
    stale = set()
    try:
        for fname in os.listdir(mem_dir):
            if fname.lower().endswith(".bin"):
                stale.add(fname)
    except Exception:
        pass

    memory = program.getMemory()
    language = safe_call(lambda: program.getLanguage())

    entries = []
    used_names = {}
    written_total = 0
    exported_count = 0
    for block in memory.getBlocks():
        name = safe_call(lambda: block.getName()) or "block"
        start = block.getStart()
        end = block.getEnd()
        size = safe_call(lambda: int(block.getSize()), 0)
        entry = {
            "name": name,
            "start": addr_to_str(start),
            "end": addr_to_str(end),
            "length": size,
            "initialized": safe_call(lambda: bool(block.isInitialized())),
            "read": safe_call(lambda: bool(block.isRead())),
            "write": safe_call(lambda: bool(block.isWrite())),
            "execute": safe_call(lambda: bool(block.isExecute())),
            "overlay": safe_call(lambda: bool(block.isOverlay())),
            "file": None,
            "exported": False,
            "skipped_reason": None,
        }

        if not entry["initialized"]:
            entry["skipped_reason"] = "uninitialized"
        elif only_names and name not in only_names:
            entry["skipped_reason"] = "not in export_memory_blocks"
        elif size > max_bytes:
            entry["skipped_reason"] = "block size {0} bytes > export_memory_max_mb ({1}MB)".format(
                size, max_mb)
            logger.log(u"WARNING: memory: ブロック {0} ({1} bytes) が上限 {2}MB を超えるためスキップします。".format(
                name, size, max_mb))
        elif written_total + size > total_max_bytes:
            entry["skipped_reason"] = "total size would exceed export_memory_total_max_mb ({0}MB)".format(
                total_max_mb)
            logger.log(u"WARNING: memory: 合計上限 {0}MB を超えるためブロック {1} 以降をスキップします。".format(
                total_max_mb, name))
        else:
            fname = sanitize_filename(u"{0}.bin".format(name))
            if fname in used_names:
                # Ghidra はブロック名の重複を許すので、開始アドレスで一意化する。
                fname = sanitize_filename(u"{0}_{1}.bin".format(name, start.toString()))
            used_names[fname] = True
            path = os.path.join(mem_dir, fname)
            written = _memory_block_bytes(memory, block, path, logger)
            if written <= 0:
                entry["skipped_reason"] = "read failed (0 bytes)"
                logger.log(u"WARNING: memory: ブロック {0} を読めませんでした。".format(name))
            else:
                entry["file"] = fname
                entry["exported"] = True
                entry["length"] = written
                written_total += written
                exported_count += 1
                stale.discard(fname)
                logger.log(u"memory: {0} -> {1} ({2:.2f} MB)".format(
                    name, fname, written / 1048576.0))

        if entry["skipped_reason"] and entry["skipped_reason"] != "uninitialized":
            logger.log(u"memory: skip {0}: {1}".format(name, entry["skipped_reason"]))
        entries.append(entry)

    if stale:
        logger.log(u"WARNING: memory/ に今回参照されない .bin が残っています "
                   u"(自動削除しません。不要なら手で消してください): {0}".format(
                       u", ".join(sorted(stale))))

    memory_map = {
        "schema_version": "0.1",
        "program_name": safe_call(lambda: program.getName()),
        "language_id": safe_call(lambda: program.getLanguageID().getIdAsString()),
        "processor": safe_call(lambda: language.getProcessor().toString()) if language else None,
        "endian": ("big" if safe_call(lambda: bool(language.isBigEndian()), False) else "little")
                  if language else None,
        "pointer_size": safe_call(lambda: int(program.getDefaultPointerSize())),
        "image_base": addr_to_str(safe_call(lambda: program.getImageBase())),
        "platform_profile": cfg.get("platform_profile"),
        # 逆アセンブラの既定アーキを bridge_config から明示指定できるようにする。
        # processor / language_id だけでは決まらないケース用 (ARM は同じ Program に
        # ARM モードと Thumb モードが混在し、language_id は "ARM:LE:32:v4t" で
        # 両方を指すため、GBA のように Thumb 主体なら "thumb" と書いておく)。
        # 未指定なら None。MCP 側の resolve_arch がこれを最優先で読む。
        "disasm_arch": cfg.get("disasm_arch"),
        "source_model": cfg.get("source_model", "unknown"),
        "limits": {
            "export_memory_max_mb": max_mb,
            "export_memory_total_max_mb": total_max_mb,
        },
        "exported_bytes": written_total,
        "blocks": entries,
    }
    logger.log(u"memory collected: {0}/{1} blocks, {2:.2f} MB".format(
        exported_count, len(entries), written_total / 1048576.0))
    return memory_map


def export_functions(program, logger):
    """全関数の情報 (名前・アドレス・引数・戻り値など) を収集します。"""
    results = []
    fm = program.getFunctionManager()
    for func in fm.getFunctions(True):
        try:
            body = func.getBody()
            ranges = []
            for rng in body.getAddressRanges():
                ranges.append({
                    "start": addr_to_str(rng.getMinAddress()),
                    "end": addr_to_str(rng.getMaxAddress()),
                })

            params = []
            for p in safe_call(lambda: func.getParameters(), []):
                params.append({
                    "name": safe_call(lambda: p.getName()),
                    "type": safe_call(lambda: p.getDataType().getName()),
                })

            results.append({
                "name": safe_call(lambda: func.getName()),
                "entry": addr_to_str(func.getEntryPoint()),
                "body_ranges": ranges,
                "is_thunk": safe_call(lambda: bool(func.isThunk())),
                "is_external": safe_call(lambda: bool(func.isExternal())),
                "calling_convention": safe_call(lambda: func.getCallingConventionName()),
                "parameters": params,
                "return_type": safe_call(lambda: func.getReturnType().getName()),
            })
        except Exception:
            logger.log(u"WARNING: 関数情報の取得に失敗: {0}".format(
                addr_to_str(safe_call(lambda: func.getEntryPoint()))))
    logger.log(u"functions collected: {0}".format(len(results)))
    return results


def export_strings(program, logger):
    """定義済み文字列データと、その参照元アドレス一覧を収集します。"""
    results = []
    listing = program.getListing()
    ref_mgr = program.getReferenceManager()
    data_iter = listing.getDefinedData(True)
    for data in data_iter:
        try:
            if not data.hasStringValue():
                continue
            addr = data.getAddress()
            refs = []
            for ref in ref_mgr.getReferencesTo(addr):
                refs.append(addr_to_str(ref.getFromAddress()))
            results.append({
                "address": addr_to_str(addr),
                "value": safe_call(lambda: u"{0}".format(data.getValue())),
                "length": safe_call(lambda: int(data.getLength())),
                "referenced_from": refs,
            })
        except Exception:
            continue
    logger.log(u"strings collected: {0}".format(len(results)))
    return results




# ラベル / 定義済みデータの上限。ここを超えたら truncated を立てて打ち切る。
# シンボル付きの Program では数万件になるので、
# 無制限にすると JSON が巨大化して MCP 側の読み込みが重くなる。
MAX_LABELS = 200000
MAX_DEFINED_DATA = 200000

# 「定義済み」と呼べないデータ型。Ghidra が未解析バイトに付ける仮の型なので、
# これを出しても「人間が定義した」情報にはならない。
UNDEFINED_TYPE_NAMES = ("undefined", "undefined1", "undefined2", "undefined3",
                        "undefined4", "undefined5", "undefined6", "undefined7",
                        "undefined8")


def symbol_type_name(symbol):
    """シンボル種別を文字列で返します (取れなければ "unknown")。

    ★`SymbolType` を import して比較しない。Ghidra のバージョン間で定数の
      置き場所が変わることがあるため、文字列で比べる (取れる情報だけを出す方針)。
    """
    try:
        return u"{0}".format(symbol.getSymbolType())
    except Exception:
        return u"unknown"


def export_labels(program, logger):
    """人間 / 解析が付けたシンボル (ラベル) を収集します。

    ★これが無いと、MCP 側は「その番地に何という名前が付いているか」を
      一切知れません。関数名は functions.json にありますが、**データに付いた
      ラベル**はここで出さないと、人間が Ghidra で名付けても AI からは
      `DAT_...` にしか見えず、apply_labels.py で付けたラベルも次のセッションで
      見えません (重複提案の原因になる)。

    `getDefinedSymbols()` は **自動生成名 (LAB_ / DAT_ 等) を含みません**。
    欲しいのは「誰かが意味を与えた名前」だけなので、これで十分です。
    関数シンボルは functions.json と重複するので `is_function` を立てて
    区別できるようにしつつ、既定では除きます。
    """
    results = []
    truncated = False
    skipped_functions = 0
    table = safe_call(lambda: program.getSymbolTable())
    if table is None:
        logger.log(u"labels: SymbolTable を取得できません。スキップします。")
        return {"labels": [], "total": 0, "truncated": False}

    try:
        iterator = table.getDefinedSymbols()
    except Exception:
        logger.log(u"labels: getDefinedSymbols() が使えません。スキップします。")
        return {"labels": [], "total": 0, "truncated": False}

    for symbol in iterator:
        try:
            kind = symbol_type_name(symbol)
            if kind == u"Function":
                skipped_functions += 1
                continue
            if len(results) >= MAX_LABELS:
                truncated = True
                break
            results.append({
                "address": addr_to_str(symbol.getAddress()),
                "name": safe_call(lambda: u"{0}".format(symbol.getName())),
                "type": kind,
                "source": safe_call(lambda: u"{0}".format(symbol.getSource())),
                "namespace": safe_call(
                    lambda: u"{0}".format(symbol.getParentNamespace().getName())),
                "primary": safe_call(lambda: bool(symbol.isPrimary())),
                "ref_count": safe_call(lambda: int(symbol.getReferenceCount())),
            })
        except Exception:
            continue

    logger.log(u"labels collected: {0} (関数シンボル {1} 件は functions.json と"
               u"重複するため除外{2})".format(
                   len(results), skipped_functions,
                   u" / 上限で打ち切り" if truncated else u""))
    return {"labels": results, "total": len(results), "truncated": truncated}


def data_type_name(data):
    """データ型の表示名を返します (取れなければ None)。"""
    try:
        dt = data.getDataType()
    except Exception:
        return None
    for getter in ("getDisplayName", "getName"):
        try:
            return u"{0}".format(getattr(dt, getter)())
        except Exception:
            continue
    return None


def export_defined_data(program, logger):
    """人間 / 解析が型を付けたデータを収集します。

    ★これが無いと、人間が定義した構造体・配列が MCP から見えず、
      describe_data が毎回ゼロから推定し直すことになります。

    文字列は strings.json にあるので除きます。`undefined*` 型も
    「まだ何も決まっていない」ことを表すだけなので除きます。
    """
    results = []
    truncated = False
    skipped_strings = 0
    skipped_undefined = 0
    listing = safe_call(lambda: program.getListing())
    if listing is None:
        logger.log(u"defined_data: Listing を取得できません。スキップします。")
        return {"defined_data": [], "total": 0, "truncated": False}

    for data in listing.getDefinedData(True):
        try:
            if safe_call(lambda: bool(data.hasStringValue())):
                skipped_strings += 1
                continue
            type_name = data_type_name(data)
            if type_name is None:
                continue
            base = type_name.split(u"[")[0].strip()
            if base in UNDEFINED_TYPE_NAMES:
                skipped_undefined += 1
                continue
            if len(results) >= MAX_DEFINED_DATA:
                truncated = True
                break
            row = {
                "address": addr_to_str(data.getAddress()),
                "type": type_name,
                "length": safe_call(lambda: int(data.getLength())),
                "label": safe_call(lambda: data.getLabel()),
            }
            # 配列 / 構造体は「何がいくつ並ぶか」が本体なので、そこだけ足す。
            if safe_call(lambda: bool(data.isArray())):
                row["kind"] = "array"
                row["count"] = safe_call(lambda: int(data.getNumComponents()))
            elif safe_call(lambda: bool(data.isStructure())):
                row["kind"] = "struct"
                row["count"] = safe_call(lambda: int(data.getNumComponents()))
            else:
                row["kind"] = "scalar"
            results.append(row)
        except Exception:
            continue

    logger.log(u"defined_data collected: {0} (文字列 {1} 件は strings.json と"
               u"重複するため除外 / undefined 型 {2} 件は除外{3})".format(
                   len(results), skipped_strings, skipped_undefined,
                   u" / 上限で打ち切り" if truncated else u""))
    return {"defined_data": results, "total": len(results),
            "truncated": truncated}


# データ型 (構造体 / 共用体) の上限。超えたら truncated を立てて打ち切る。
# C++ のシンボル付き ELF ではクラスが数千になる。
MAX_DATATYPES = 100000
# 1 型あたりのフィールド上限。巨大な自動生成構造体で JSON が膨らむのを防ぐ。
MAX_FIELDS_PER_TYPE = 4096
# typedef の多段を辿る上限 (壊れた循環で止まらないように)。
MAX_TYPEDEF_DEPTH = 16


def _java_class_name(obj):
    """Java オブジェクトのクラス名 (単純名) を返します。取れなければ空文字。

    ★Structure / Union 等を import して isinstance しない。Ghidra の版で
      置き場所が変わりうるので、クラス名の文字列で判定する
      (labels の SymbolType と同じ方針)。
    """
    try:
        return u"{0}".format(obj.getClass().getSimpleName())
    except Exception:
        pass
    try:
        return u"{0}".format(type(obj).__name__)
    except Exception:
        return u""


def datatype_kind(dt):
    """構造体なら "struct"、共用体なら "union"、それ以外は None を返します。

    Ghidra のクラスは StructureDB / StructureDataType / UnionDB / UnionDataType。
    C++ のクラスも Ghidra 上は Structure として持たれる (vtable 型も同じ)。
    """
    if dt is None:
        return None
    name = _java_class_name(dt).lower()
    if "union" in name:
        return "union"
    if "structure" in name:
        return "struct"
    return None


def _unwrap_typedef(dt):
    """typedef を剥がした実体の型を返します (typedef でなければそのまま)。"""
    depth = 0
    while dt is not None and depth < MAX_TYPEDEF_DEPTH:
        if u"typedef" not in _java_class_name(dt).lower():
            return dt
        base = safe_call(lambda: dt.getBaseDataType())
        if base is None or base is dt:
            return dt
        dt = base
        depth += 1
    return dt


def _dt_display(dt):
    """データ型の表示名 (`GmRes3D *` / `float[4][4]` 等) を返します。"""
    for getter in ("getDisplayName", "getName"):
        try:
            return u"{0}".format(getattr(dt, getter)())
        except Exception:
            continue
    return None


def _dt_path(dt):
    """データ型のパス名 (`/game/GmGameMgr`) を返します。"""
    return safe_call(lambda: u"{0}".format(dt.getPathName()))


def datatype_ref(dt):
    """フィールドの型から、MCP が入れ子を辿るのに要る情報を取り出します。

    - 配列なら dims (外側から) / elem_size / elem_type
    - 実体 (typedef・配列を剥がした先) が構造体/共用体なら ref / ref_kind
    - ポインタの先が構造体/共用体なら pointee (辿りはしない。手掛かりだけ)
    """
    out = {}
    base = _unwrap_typedef(dt)
    dims = []
    while base is not None and u"array" in _java_class_name(base).lower():
        count = safe_call(lambda: int(base.getNumElements()))
        inner = safe_call(lambda: base.getDataType())
        if count is None or inner is None:
            break
        dims.append(count)
        base = _unwrap_typedef(inner)
        if len(dims) >= 8:
            break
    if dims:
        out["dims"] = dims
        out["elem_size"] = safe_call(lambda: int(base.getLength()))
        out["elem_type"] = _dt_display(base)
    kind = datatype_kind(base)
    if kind:
        out["ref"] = _dt_path(base)
        out["ref_kind"] = kind
    elif base is not None and u"pointer" in _java_class_name(base).lower():
        target = safe_call(lambda: base.getDataType())
        target = _unwrap_typedef(target) if target is not None else None
        if datatype_kind(target):
            out["pointee"] = _dt_path(target)
    return out


def _field_row(comp):
    """構造体 / 共用体の 1 要素を JSON 用の dict にします。"""
    dt = safe_call(lambda: comp.getDataType())
    name = safe_call(lambda: comp.getFieldName())
    row = {
        "offset": safe_call(lambda: int(comp.getOffset())),
        "name": u"{0}".format(name) if name else None,
        "type": _dt_display(dt) if dt is not None else None,
        "size": safe_call(lambda: int(comp.getLength())),
    }
    if not row["name"]:
        # 名前の無い要素は Ghidra の既定名 (field_0x10) を出し、無名だと分かるようにする。
        row["name"] = safe_call(lambda: u"{0}".format(comp.getDefaultFieldName()))
        row["unnamed"] = True
    comment = safe_call(lambda: comp.getComment())
    if comment:
        row["comment"] = u"{0}".format(comment)
    if safe_call(lambda: bool(comp.isBitFieldComponent()), False):
        row["bitfield"] = {
            "bit_offset": safe_call(lambda: int(dt.getBitOffset())),
            "bit_size": safe_call(lambda: int(dt.getBitSize())),
        }
    if dt is not None:
        row.update(datatype_ref(dt))
    return row


def _is_vtable_name(name):
    """型名が vtable らしいか (`GmStage__vtable` / `_vtbl` 等) を返します。"""
    low = (name or u"").lower()
    return low.endswith(u"vtable") or low.endswith(u"_vtbl") or low.startswith(u"_vt_")


def _composite_row(dt, kind):
    """構造体 / 共用体 1 個を JSON 用の dict にします。"""
    name = safe_call(lambda: u"{0}".format(dt.getName()))
    row = {
        "name": name,
        "path": _dt_path(dt),
        "category": safe_call(lambda: u"{0}".format(dt.getCategoryPath().getPath())),
        "kind": kind,
        "size": safe_call(lambda: int(dt.getLength())),
        "vtable": _is_vtable_name(name),
    }
    if safe_call(lambda: bool(dt.isNotYetDefined()), False):
        row["not_yet_defined"] = True
    packed = safe_call(lambda: bool(dt.isPackingEnabled()))
    if packed is not None:
        row["packed"] = packed
    desc = safe_call(lambda: dt.getDescription())
    if desc:
        row["description"] = u"{0}".format(desc)

    # ★getDefinedComponents は未定義の詰め物 (undefined1 の並び) を含まない。
    #   欲しいのは「名前と型が決まっている要素」なのでこちらを使う。
    comps = safe_call(lambda: dt.getDefinedComponents())
    if comps is None:
        comps = safe_call(lambda: dt.getComponents(), [])
    fields = []
    for comp in comps or []:
        if len(fields) >= MAX_FIELDS_PER_TYPE:
            row["fields_truncated"] = True
            break
        try:
            fields.append(_field_row(comp))
        except Exception:
            continue
    row["fields"] = fields
    return row


def _iter_datatypes(dtm):
    """DataTypeManager の全型を列挙します。

    ★getAllComposites() を先に使わないこと。typedef が返らず、構造体の別名
      (typedefs) が 1 件も出なくなる。全型を回して自分で振り分ける。
    """
    for getter in ("getAllDataTypes", "getAllComposites"):
        try:
            return getattr(dtm, getter)()
        except Exception:
            continue
    return []


def export_datatypes(program, logger):
    """構造体・共用体 (C++ のクラスと vtable 型を含む) のレイアウトを収集します。

    ★疑似 C には `self->resourceTable` とフィールド名が出るが、**それが何バイト目か**は
      出ない (逆アセンブルの `lw a2,388(s1)` から 1 フィールドずつ拾うしかない)。
      Ghidra は型を持っているので、ここで書き出して MCP の get_struct_layout /
      find_field で引けるようにする。

    継承 (基底クラスが先頭フィールドとして入る形) は**そのまま 1 フィールドとして出す**
    (展開は MCP の flatten でやる)。typedef で構造体に別名が付いているものは
    typedefs に別に出す (別名で引けるように)。Program は書き換えない。
    """
    results = []
    typedefs = []
    truncated = False
    skipped = 0
    dtm = safe_call(lambda: program.getDataTypeManager())
    if dtm is None:
        logger.log(u"datatypes: DataTypeManager を取得できません。スキップします。")
        return {"datatypes": [], "typedefs": [], "total": 0, "truncated": False}

    for dt in _iter_datatypes(dtm):
        try:
            kind = datatype_kind(dt)
            if kind is None:
                if u"typedef" in _java_class_name(dt).lower():
                    base = _unwrap_typedef(dt)
                    base_kind = datatype_kind(base)
                    if base_kind and len(typedefs) < MAX_DATATYPES:
                        typedefs.append({
                            "name": safe_call(lambda: u"{0}".format(dt.getName())),
                            "path": _dt_path(dt),
                            "target": _dt_path(base),
                            "target_kind": base_kind,
                        })
                else:
                    skipped += 1
                continue
            if len(results) >= MAX_DATATYPES:
                truncated = True
                break
            results.append(_composite_row(dt, kind))
        except Exception:
            continue

    results.sort(key=lambda r: r.get("path") or u"")
    typedefs.sort(key=lambda r: r.get("path") or u"")
    fields = sum(len(r.get("fields") or []) for r in results)
    logger.log(u"datatypes collected: {0} 型 / {1} フィールド / typedef 別名 {2}{3}".format(
        len(results), fields, len(typedefs),
        u" / 上限で打ち切り" if truncated else u""))
    return {"datatypes": results, "typedefs": typedefs, "total": len(results),
            "truncated": truncated}


def is_ai_comment(text):
    """コメント文が [AI] で始まる行を含むかどうかを判定します。"""
    if text is None:
        return False
    for line in text.split(u"\n"):
        if line.strip().startswith(u"[AI]"):
            return True
    return False


def export_comments(program, logger):
    """既存コメントを種別ごとに収集します。[AI] 判定情報も付けます。

    全 code unit を走査すると、raw binary / メモリダンプでは未定義バイト 1 つ
    ずつが code unit になり数百万件を舐めて極端に遅くなる (2〜3 分)。代わりに
    getCommentAddressIterator で「コメントが付いているアドレスだけ」を巡回する。
    """
    results = []
    listing = program.getListing()
    addr_set = program.getMemory()  # AddressSetView (全初期化領域)
    for ctype, cname in COMMENT_TYPE_TO_NAME.items():
        try:
            it = listing.getCommentAddressIterator(ctype, addr_set, True)
        except Exception:
            logger.log(u"WARNING: getCommentAddressIterator 失敗 (type={0})。この種別をスキップします。".format(cname))
            continue
        for addr in it:
            if monitor.isCancelled():
                break
            text = safe_call(lambda: listing.getComment(ctype, addr))
            if text:
                results.append({
                    "address": addr_to_str(addr),
                    "type": cname,
                    "comment": text,
                    "is_ai_comment": is_ai_comment(text),
                })
    logger.log(u"comments collected: {0}".format(len(results)))
    return results


def export_xrefs(program, logger):
    """参照 (xref) 情報を収集します。from/to/種別/operand などを記録します。

    464k 件規模になるため高速化している:
      - 内側の safe_call (ラムダ + try/except) を排し、外側 1 つの try/except に集約。
        1 フィールドでも失敗したらその ref をスキップする (Jython のラムダ生成コスト削減)。
      - addr 文字列化を inline 化 (addr_to_str の None 判定/例外を省く)。
      - 呼び出し側で compact JSON 出力にして直列化コストとファイルサイズを削減。
    """
    results = []
    append = results.append
    ref_mgr = program.getReferenceManager()
    for from_addr in ref_mgr.getReferenceSourceIterator(program.getMinAddress(), True):
        if monitor.isCancelled():
            break
        for ref in ref_mgr.getReferencesFrom(from_addr):
            try:
                append({
                    "from": "0x" + ref.getFromAddress().toString(),
                    "to": "0x" + ref.getToAddress().toString(),
                    "ref_type": ref.getReferenceType().getName(),
                    "operand_index": int(ref.getOperandIndex()),
                    "source_type": ref.getSource().toString(),
                })
            except Exception:
                continue
    logger.log(u"xrefs collected: {0}".format(len(results)))
    return results


def find_block_for_address(program, address):
    """指定アドレスが属するメモリブロックを返します。無ければ None。"""
    if address is None:
        return None
    return safe_call(lambda: program.getMemory().getBlock(address))


def find_nearest_function(program, address, logger):
    """指定アドレス以前にある最も近い関数の情報を返します。"""
    try:
        fm = program.getFunctionManager()
        func = fm.getFunctionContaining(address)
        if func is None:
            func = safe_call(lambda: program.getListing().getFunctionBefore(address))
        if func is None:
            return None
        return {
            "name": safe_call(lambda: func.getName()),
            "entry": addr_to_str(func.getEntryPoint()),
        }
    except Exception:
        return None


def export_undefined_ranges(program, logger):
    """未定義領域を範囲としてまとめます。

    まず AddressSet 演算による高速版を試し、使えない/失敗した環境でのみ
    1 バイトずつ辿る旧方式 (_undefined_ranges_slow) にフォールバックします。
    旧方式は raw binary / メモリダンプの巨大な未定義領域で数百万回ループし、
    getUndefinedDataAfter の "Searching address" で固まることがあるため。
    """
    fast = _undefined_ranges_fast(program, logger)
    if fast is not None:
        return fast
    logger.log(u"undefined_ranges: 高速版が使えないため旧方式にフォールバックします。")
    return _undefined_ranges_slow(program, logger)


def _undefined_ranges_fast(program, logger):
    """[本命] AddressSet 演算で未定義範囲を求めます。

    「初期化メモリ全体 − (命令 + 定義済みデータ)」の差集合が未定義領域。
    計算量は O(定義済み要素数) で未定義バイト数に依存しないため高速。
    AddressSet が無い/失敗した場合は None を返し、呼び出し側が旧方式に回す。
    """
    try:
        from ghidra.program.model.address import AddressSet
    except Exception:
        return None
    try:
        listing = program.getListing()
        memory = program.getMemory()
        defined = AddressSet()
        for data in listing.getDefinedData(True):
            if monitor.isCancelled():
                return None
            defined.addRange(data.getMinAddress(), data.getMaxAddress())
        for instr in listing.getInstructions(True):
            if monitor.isCancelled():
                return None
            defined.addRange(instr.getMinAddress(), instr.getMaxAddress())
        undefined_set = memory.subtract(defined)
    except Exception:
        logger.log(u"WARNING: AddressSet による未定義計算に失敗しました。")
        return None

    results = []
    for rng in undefined_set.getAddressRanges():
        if monitor.isCancelled():
            break
        start = rng.getMinAddress()
        end = rng.getMaxAddress()
        block = find_block_for_address(program, start)
        try:
            size = int(end.subtract(start)) + 1
        except Exception:
            size = None
        results.append({
            "start": addr_to_str(start),
            "end": addr_to_str(end),
            "size": size,
            "block_name": safe_call(lambda: block.getName()) if block else None,
            "in_executable_block": safe_call(lambda: bool(block.isExecute())) if block else None,
            "initialized": safe_call(lambda: bool(block.isInitialized())) if block else None,
            "nearest_function": find_nearest_function(program, start, logger),
        })
    logger.log(u"undefined ranges collected: {0} (fast/AddressSet)".format(len(results)))
    return results


def _undefined_ranges_slow(program, logger):
    """[フォールバック] 未定義データを 1 つずつ辿る旧方式。巨大未定義領域で遅い。"""
    results = []
    listing = program.getListing()

    run_start = None
    run_prev = None

    def flush_run(start, end):
        """連続した未定義領域 1 区間を結果に追加します。"""
        block = find_block_for_address(program, start)
        try:
            size = int(end.subtract(start)) + 1
        except Exception:
            size = None
        results.append({
            "start": addr_to_str(start),
            "end": addr_to_str(end),
            "size": size,
            "block_name": safe_call(lambda: block.getName()) if block else None,
            "in_executable_block": safe_call(lambda: bool(block.isExecute())) if block else None,
            "initialized": safe_call(lambda: bool(block.isInitialized())) if block else None,
            "nearest_function": find_nearest_function(program, start, logger),
        })

    # 未定義データを順にたどり、アドレスが連続している間は 1 区間にまとめます。
    undef = listing.getFirstUndefinedData(program.getMemory(), monitor)
    while undef is not None:
        addr = undef.getAddress()
        if run_start is None:
            run_start = addr
            run_prev = addr
        else:
            try:
                expected = run_prev.add(1)
            except Exception:
                expected = None
            if expected is not None and addr.equals(expected):
                run_prev = addr
            else:
                flush_run(run_start, run_prev)
                run_start = addr
                run_prev = addr
        if monitor.isCancelled():
            break
        next_addr = safe_call(lambda: run_prev.add(1))
        if next_addr is None:
            break
        undef = listing.getUndefinedDataAfter(run_prev, monitor)

    if run_start is not None:
        flush_run(run_start, run_prev)

    logger.log(u"undefined ranges collected: {0} (slow/byte-walk)".format(len(results)))
    return results


def _thread_is_alive(t):
    """Thread が生存中かを返します (Python 2.7 / Jython の名称ゆれを吸収)。"""
    try:
        return t.is_alive()
    except AttributeError:
        return t.isAlive()


def _open_decomp_interface(program, logger):
    """DecompInterface を生成して program を開きます。失敗したら None を返します。"""
    try:
        from ghidra.app.decompiler import DecompInterface
    except Exception:
        logger.log(u"WARNING: DecompInterface を import できませんでした。")
        return None
    try:
        ifc = DecompInterface()
        ifc.openProgram(program)
    except Exception:
        logger.log(u"WARNING: DecompInterface の初期化に失敗しました。")
        return None
    return ifc


def _dispose_decomp_interface(ifc):
    """DecompInterface を破棄し、外部 decompiler プロセスも落とします。

    decompile 本体は Ghidra 本体とは別の native プロセスで動くため、
    stopProcess() でそれを殺すのがハングからの唯一確実な復帰手段です。
    Ghidra のバージョン差を考慮して、存在するメソッドだけ順に呼びます。
    """
    if ifc is None:
        return
    for name in ("stopProcess", "dispose"):
        try:
            fn = getattr(ifc, name, None)
            if fn is not None:
                fn()
        except Exception:
            pass


def _decompile_one(ifc, func, timeout, hard_timeout, logger):
    """1 関数を decompile します。戻り値は (res, timed_out) のタプル。

    Ghidra の decompile タイムアウト (decompileFunction の第3引数) は「協調的」で、
    decompiler が経過時間をチェックしに来ない病的関数では効きません。
    そこで別スレッドで走らせ、hard_timeout 秒待っても終わらなければそのスレッドを
    見捨てて timed_out=True を返します。

    ⚠️ timed_out=True のとき、見捨てたスレッドが ifc を掴んだままなので
       呼び出し側は必ず DecompInterface を作り直してください (再利用不可)。
    """
    if threading is None or hard_timeout is None or hard_timeout <= 0:
        # フォールバック: 従来どおり直接呼ぶ (Ghidra 任せ)。
        return (ifc.decompileFunction(func, timeout, monitor), False)

    holder = {}

    def _work():
        try:
            holder["res"] = ifc.decompileFunction(func, timeout, monitor)
        except Exception:
            holder["err"] = traceback.format_exc()

    t = threading.Thread(target=_work)
    t.setDaemon(True)
    t.start()
    t.join(hard_timeout)

    if _thread_is_alive(t):
        logger.log(u"decompile ハードタイムアウト ({0}s): {1} ({2}) — 諦めて次の関数へ進みます。".format(
            hard_timeout, func.getName(), addr_to_str(func.getEntryPoint())))
        # 暴走中の native decompiler プロセスを殺す。これをしないと CPU を食い続ける。
        _dispose_decomp_interface(ifc)
        return (None, True)

    if "err" in holder:
        logger.log(u"decompile 例外: {0} ({1})\n{2}".format(
            func.getName(), addr_to_str(func.getEntryPoint()), holder["err"]))
        return (None, False)
    return (holder.get("res"), False)


def _decompile_skip_reason(program, func, skip_uninitialized, skip_tiny):
    """decompile 前に「そもそも中身が無い関数」を弾く理由を返します。無ければ None。

    ⚠️ 未初期化ブロックにあるダミー関数 (例: PSY-Q の GTE マクロ用) は body が
       1 バイトでバイト実体も無く、decompile しても得るものが無いのに、踏むと
       **非決定的に** Ghidra ごと固まることがあります (ハードタイムアウトの外側で
       固まるので watchdog も効かない)。その対策です。
    """
    if skip_uninitialized:
        try:
            block = program.getMemory().getBlock(func.getEntryPoint())
        except Exception:
            block = None
        if block is None:
            return "uninitialized"
        try:
            if not bool(block.isInitialized()):
                return "uninitialized"
        except Exception:
            pass
    if skip_tiny:
        try:
            size = int(func.getBody().getNumAddresses())
        except Exception:
            size = None
        if size is not None and size <= 1:
            return "tiny"
    return None


# 確認ダイアログの説明文を折り返す幅 (全角の文字数)。
# askChoice は説明文を 1 行で横に並べるので、画面幅いっぱいの横長になる。
DIALOG_WRAP_CHARS = 20


def _ask_choice_narrow(title, message, choices, default):
    """説明文を全角 DIALOG_WRAP_CHARS 文字幅で折り返し、その下に選択肢を置く
    縦並びのダイアログで 1 つ選ばせる。

    戻り値: 選んだ文字列 / キャンセルなら u"" / このダイアログを出せない
    (ヘッドレス等) なら None (呼び出し側は askChoice に戻す)。
    """
    try:
        from java.awt import GraphicsEnvironment
        from javax.swing import JOptionPane, UIManager
        from java.lang import Object
        from jarray import array
        if GraphicsEnvironment.isHeadless():
            return None
        font = UIManager.getFont("Label.font")
        width_px = int((font.getSize() if font is not None else 12)
                       * DIALOG_WRAP_CHARS)
        esc = (message.replace(u"&", u"&amp;").replace(u"<", u"&lt;")
               .replace(u">", u"&gt;").replace(u"\n", u"<br>"))
        html = u"<html><body style='width: {0}px'>{1}</body></html>".format(
            width_px, esc)
        picked = JOptionPane.showInputDialog(
            None, html, title, JOptionPane.QUESTION_MESSAGE, None,
            array(choices, Object), default)
    except Exception:
        return None
    except:
        return None
    if picked is None:
        return u""
    return u"{0}".format(picked)


def resolve_decompile_scope(program, scope, limit, targets, start_i, end_i,
                            logger):
    """decompile の対象範囲を **export を始める前に** 決めます。

    返り値は `(limit, run)`。`run=False` なら decompile 工程を丸ごと飛ばします。

    ★**ここで聞くのは「先に決めたい」から**です。decompile は export の最後の工程
      なので、走らせてから「上限 20 件しか出ていない」と気づくと、xrefs 等の重い
      工程まで含めてやり直しになります。

    `decompile_targets` があるときは対象が確定しているので聞きません。
    ダイアログを出せない環境 (ヘッドレス等) では設定値のまま続行します。
    """
    key = (scope or DECOMPILE_SCOPE)
    try:
        key = key.strip().lower()
    except Exception:
        key = DECOMPILE_SCOPE
    if key not in DECOMPILE_SCOPES:
        logger.log(u"WARNING: decompile_scope '{0}' は不明です。{1} のいずれかを"
                   u"指定してください。今回は '{2}' として扱います。".format(
                       scope, u" / ".join(DECOMPILE_SCOPES), DECOMPILE_SCOPE))
        key = DECOMPILE_SCOPE

    if targets:
        logger.log(u"decompile 対象: targets で指定された {0} 関数 "
                   u"(decompile_scope は聞きません)".format(len(targets)))
        return (limit, True)
    if key == "limit":
        logger.log(u"decompile 対象: 設定どおり (limit={0})".format(
            limit if limit > 0 else u"無制限"))
        return (limit, True)
    if key == "all":
        logger.log(u"decompile 対象: 全関数 (decompile_scope=all)")
        return (0, True)

    total = safe_call(lambda: int(program.getFunctionManager().getFunctionCount()),
                      None)
    where = u""
    if start_i is not None or end_i is not None:
        where = u"\n対象範囲: {0} 〜 {1}".format(
            hex(start_i) if start_i is not None else u"先頭",
            hex(end_i) if end_i is not None else u"末尾")

    all_label = u"全関数を decompile する"
    if total is not None:
        all_label = u"全関数を decompile する ({0} 件)".format(total)
    limit_label = u"上限 {0} 件だけ decompile する".format(limit)
    skip_label = u"decompile しない (他の工程だけ実行する)"

    choices = []
    if limit > 0:
        choices.append(limit_label)
    choices.append(all_label)
    choices.append(skip_label)
    default = limit_label if limit > 0 else all_label

    message = (u"疑似 C (decompile) をどこまで出しますか。\n"
               u"**後から増やすには export をやり直すことになる**ので、先に決めます。"
               u"{0}\n\n"
               u"・上限つき … 速い。まず全体を見たいときはこれで十分\n"
               u"・全関数 … 時間がかかる。病的関数を踏むと 1 件あたり最大 {1} 秒待つ"
               u" (ハードタイムアウトで次へ進むので固まりはしない)\n"
               u"・しない … functions/strings/xrefs だけ作り直したいとき\n\n"
               u"この選択は今回の実行にだけ効きます。毎回同じにしたいときは"
               u"bridge_config.json の \"decompile_scope\" を \"limit\" / \"all\" に"
               u"してください。").format(where, DECOMPILE_TIMEOUT_SECONDS)

    # 選択肢は java.util.List で渡す (Jython の list 変換に頼らない)。
    try:
        from java.util import ArrayList
        items = ArrayList()
        for c in choices:
            items.add(c)
    except Exception:
        items = choices

    picked = None
    failure = None
    narrow = _ask_choice_narrow(u"decompile の範囲", message, choices, default)
    if narrow is not None:
        if narrow == u"":
            logger.log(u"decompile 対象: 選択がキャンセルされたので **スキップ** します。")
            return (limit, False)
        picked = narrow
    else:
        try:
            picked = askChoice(u"decompile の範囲", message, items, default)
        except Exception:
            failure = sys.exc_info()[0]
        except:
            # ★Jython では Java の Throwable が Python の Exception に入らないことが
            #   あるので、素の except も要る (CancelledException がここへ来る)。
            failure = sys.exc_info()[0]

    if failure is not None:
        name = u"{0}".format(getattr(failure, "__name__", failure))
        if u"Cancel" in name:
            # 人が明示的に取りやめた。勝手に既定で走らせない。
            logger.log(u"decompile 対象: 選択がキャンセルされたので **スキップ** します。")
            return (limit, False)
        # ダイアログを出せない (ヘッドレス等)。設定値のまま続行する。
        logger.log(u"decompile 対象: 選択ダイアログを出せなかったので設定どおり "
                   u"(limit={0} / {1})".format(
                       limit if limit > 0 else u"無制限", name))
        return (limit, True)

    picked = u"{0}".format(picked)
    if picked == skip_label:
        logger.log(u"decompile 対象: **今回はスキップ** (選択)。"
                   u"既存の decompile/ はそのまま残します。")
        return (limit, False)
    if picked == all_label:
        logger.log(u"decompile 対象: **全関数** (選択{0})".format(
            u" / {0} 件".format(total) if total is not None else u""))
        return (0, True)
    logger.log(u"decompile 対象: 上限 {0} 件 (選択)".format(limit))
    return (limit, True)


def _clang_leaves(node, out, depth=0):
    """ClangTokenGroup を再帰で辿り、葉のトークンだけを集めます。

    `DecompilerUtils.toLines()` を使わないのは、Ghidra のバージョンで置き場所が
    変わりうるユーティリティに依存しないためです (道具箱の方針: Ghidra API 依存は
    浅く保つ)。ClangNode の numChildren() / Child() はずっと安定しています。
    """
    if depth > 64:
        return
    try:
        count = node.numChildren()
    except Exception:
        count = 0
    if count:
        for i in range(count):
            try:
                child = node.Child(i)
            except Exception:
                continue
            if child is not None:
                _clang_leaves(child, out, depth + 1)
    else:
        out.append(node)


def build_decompile_line_map(res, code):
    """疑似 C の「行 -> 命令アドレス」対応表を作ります。失敗したら None。

    ★この対応は **decompiler のマークアップからしか取れません**。疑似 C の
      テキストだけを見て後から推測することはできないので、export のときに
      一緒に出しておきます。

    返す dict:
      lines_in_markup … マークアップ側の行数
      lines_in_code   … 実際に書き出す .c の行数 (ずれ検出用)
      lines           … [{"line":N, "min":"0x..", "max":"0x..", "count":K,
                          "head":"行頭 20 文字"}, ...] (アドレスのある行だけ)

    head を入れているのは、**行番号のずれを MCP 側が検出できるようにする**ためです。
    ずれたまま番地を答えると、1 命令の違いを追う作業が丸ごと狂います。
    """
    try:
        markup = res.getCCodeMarkup()
    except Exception:
        return None
    if markup is None:
        return None

    leaves = []
    _clang_leaves(markup, leaves)
    if not leaves:
        return None

    rows = {}
    heads = {}
    max_line = 0
    for tok in leaves:
        try:
            parent = tok.getLineParent()
        except Exception:
            parent = None
        if parent is None:
            continue
        try:
            num = int(parent.getLineNumber())
        except Exception:
            continue
        if num > max_line:
            max_line = num
        if num not in heads:
            try:
                heads[num] = unicode(parent.toString()).strip()[:20]
            except Exception:
                heads[num] = None
        lo = hi = None
        try:
            a = tok.getMinAddress()
            if a is not None:
                lo = int(a.getOffset())
        except Exception:
            lo = None
        try:
            a = tok.getMaxAddress()
            if a is not None:
                hi = int(a.getOffset())
        except Exception:
            hi = None
        if lo is None and hi is None:
            continue
        if lo is None:
            lo = hi
        if hi is None:
            hi = lo
        row = rows.get(num)
        if row is None:
            rows[num] = {"min": lo, "max": hi, "addrs": set([lo])}
        else:
            if lo < row["min"]:
                row["min"] = lo
            if hi > row["max"]:
                row["max"] = hi
            row["addrs"].add(lo)

    if not rows:
        return None
    out = []
    for num in sorted(rows):
        row = rows[num]
        out.append({
            "line": num,
            "min": u"0x{0:08x}".format(row["min"]),
            "max": u"0x{0:08x}".format(row["max"]),
            "count": len(row["addrs"]),
            "head": heads.get(num),
        })
    return {
        "schema_version": 1,
        "lines_in_markup": max_line,
        "lines_in_code": code.count(u"\n") + 1,
        "mapped": len(out),
        "lines": out,
    }


def export_decompile(program, out_dir, logger, start_i=None, end_i=None,
                     timeout=DECOMPILE_TIMEOUT_SECONDS, limit=DECOMPILE_LIMIT,
                     targets=None, hard_timeout=None,
                     skip_uninitialized=DECOMPILE_SKIP_UNINITIALIZED,
                     skip_tiny=DECOMPILE_SKIP_TINY,
                     max_output_kb=DECOMPILE_MAX_OUTPUT_KB,
                     verbose=DECOMPILE_VERBOSE,
                     line_map=DECOMPILE_LINE_MAP):
    """関数ごとの疑似 C コードを decompile/ 配下に出力します。

    targets (entry int の集合) が指定されたら、その関数だけを decompile し
    range/limit は無視する (病的関数を踏まずに特定関数だけ確実に取るため)。
    targets=None のときは start_i / end_i (None=無制限) で範囲を絞り、limit で件数上限。
    timeout は 1 関数あたりの decompile 制限秒 (Ghidra の協調的タイムアウト)。
    hard_timeout はそれが効かなかったときにスレッドごと見捨てる秒数 (None/0以下で無効)。
    skip_uninitialized / skip_tiny は「中身が無い関数」を対象から外すガード。
    max_output_kb は getC() の出力サイズ上限 (0 以下で無効)。
    verbose=True なら 1 関数ごとに「今からやる」をログへ出す (固まったとき犯人が分かる)。
    line_map=True なら疑似 C の行 <-> 命令アドレスの対応表 (.lines.json) も出す。
    """
    ifc = _open_decomp_interface(program, logger)
    if ifc is None:
        logger.log(u"WARNING: decompile をスキップしました。")
        return

    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)

    max_output_bytes = max_output_kb * 1024 if max_output_kb > 0 else 0
    fm = program.getFunctionManager()
    count = 0
    ok = 0
    failed = 0
    skipped_range = 0
    skipped_uninit = 0
    skipped_tiny = 0
    skipped_huge = 0
    hard_timeouts = 0
    line_maps = 0
    for func in fm.getFunctions(True):
        if monitor.isCancelled():
            break
        if func.isThunk() or func.isExternal():
            continue
        targeted = False
        if targets:
            # 特定関数のみモード: entry が targets に無ければスキップ (range/limit 無視)。
            try:
                entry_i = int(func.getEntryPoint().getOffset())
            except Exception:
                entry_i = None
            if entry_i not in targets:
                skipped_range += 1
                continue
            targeted = True
        else:
            # アドレス範囲フィルタ (指定時のみ)。範囲外は break ではなく continue で
            # スキップする。getFunctions(True) の反復順がアドレス昇順とは限らないため、
            # 早期 break すると範囲内の関数を取りこぼす (実機で確認済み)。順序非依存にする。
            if start_i is not None or end_i is not None:
                entry_i = None
                try:
                    entry_i = int(func.getEntryPoint().getOffset())
                except Exception:
                    entry_i = None
                if entry_i is not None:
                    if start_i is not None and entry_i < start_i:
                        skipped_range += 1
                        continue
                    if end_i is not None and entry_i > end_i:
                        skipped_range += 1
                        continue
            if limit > 0 and count >= limit:
                logger.log(u"decompile 上限 {0} 件に達したため打ち切りました。".format(limit))
                break

        # ★中身が無い関数を弾く (Ghidra が固まるのを避ける)。
        reason = _decompile_skip_reason(program, func, skip_uninitialized, skip_tiny)
        if reason is not None:
            if reason == "uninitialized":
                skipped_uninit += 1
            else:
                skipped_tiny += 1
            # 明示的に targets で指名された関数は、黙って飛ばすと混乱するので必ず出す。
            if targeted or verbose:
                logger.log(u"decompile skip ({0}): {1} ({2})".format(
                    reason, func.getName(), addr_to_str(func.getEntryPoint())))
            continue

        count += 1
        if verbose:
            logger.log(u"decompile start: {0} ({1})".format(
                func.getName(), addr_to_str(func.getEntryPoint())))
        elif DECOMPILE_PROGRESS_EVERY > 0 and count % DECOMPILE_PROGRESS_EVERY == 0:
            logger.log(u"decompile 進捗 {0} 件目 現在: {1} ({2})".format(
                count, func.getName(), addr_to_str(func.getEntryPoint())))
        try:
            res, timed_out = _decompile_one(ifc, func, timeout, hard_timeout, logger)
            if timed_out:
                failed += 1
                hard_timeouts += 1
                # 見捨てたスレッドが古い ifc を掴んでいるので必ず作り直す。
                ifc = _open_decomp_interface(program, logger)
                if ifc is None:
                    logger.log(u"WARNING: DecompInterface を再作成できず decompile を打ち切りました。")
                    break
                continue
            if res is not None and res.decompileCompleted():
                # u"{0}".format(code) は巨大文字列をもう 1 個複製して GC を悪化させるので
                # 使わない (unicode() は既に unicode なら同一オブジェクトを返す)。
                code = unicode(res.getDecompiledFunction().getC())
                # ★巨大出力ガード: 書き出し側で固まる事例があるため、先に長さを見る。
                if max_output_bytes and len(code) > max_output_bytes:
                    skipped_huge += 1
                    logger.log(u"decompile skip (出力が {0}KB 超): {1} ({2}) size={3}".format(
                        max_output_kb, func.getName(),
                        addr_to_str(func.getEntryPoint()), len(code)))
                    continue
                fname = "{0}_{1}.c".format(
                    func.getName(), func.getEntryPoint().toString())
                fname = sanitize_filename(fname)
                # atomic=True: 途中で失敗しても 0 バイトの .c を残さない
                # (残ると次回以降「decompile 済み」と誤認する)。
                write_text(os.path.join(out_dir, fname), code, atomic=True)
                ok += 1
                # ★行 <-> 番地の対応表。失敗しても decompile 自体は止めない
                #   (対応表が無くても .c は読める。ここで落とすと本末転倒)。
                if line_map:
                    # 対応表の失敗で decompile 自体を失敗にしない
                    # (.c は既に書けている。ここで落とすと本末転倒)。
                    try:
                        lmap = build_decompile_line_map(res, code)
                        if lmap:
                            lmap["name"] = unicode(func.getName())
                            lmap["entry"] = addr_to_str(func.getEntryPoint())
                            write_json(os.path.join(
                                out_dir, fname[:-2] + ".lines.json"), lmap,
                                compact=True)
                            line_maps += 1
                    except Exception:
                        logger.log(u"line_map 失敗 (疑似 C は書けています): {0} ({1})".format(
                            func.getName(), addr_to_str(func.getEntryPoint())))
            else:
                failed += 1
                msg = u"unknown"
                if res is not None:
                    msg = safe_call(lambda: res.getErrorMessage(), u"unknown")
                logger.log(u"decompile 失敗: {0} ({1}) reason={2}".format(
                    func.getName(), addr_to_str(func.getEntryPoint()), msg))
        except Exception:
            failed += 1
            logger.log(u"decompile 例外: {0} ({1})".format(
                func.getName(), addr_to_str(func.getEntryPoint())))
    logger.log(u"decompile line_map: {0} 件出力 (疑似 C の行 -> 番地)".format(line_maps)
               if line_map else
               u"decompile line_map: skip (decompile_line_map=false)")
    logger.log(u"decompile done: ok={0} failed={1} range_skipped={2} "
               u"skipped_uninitialized={3} skipped_tiny={4} skipped_huge={5} "
               u"hard_timeout={6}".format(
                   ok, failed, skipped_range, skipped_uninit, skipped_tiny,
                   skipped_huge, hard_timeouts))
    if hard_timeouts:
        logger.log(u"※ ハードタイムアウトした {0} 関数は病的関数の可能性が高いです。"
                   u"decompile_targets から外すことを検討してください。".format(hard_timeouts))
    _dispose_decomp_interface(ifc)


def sanitize_filename(name):
    """ファイル名として使えない文字をアンダースコアに置き換えます。"""
    bad = u"\\/:*?\"<>|"
    out = []
    for ch in name:
        if ch in bad:
            out.append(u"_")
        else:
            out.append(ch)
    return u"".join(out)


def run():
    """export 処理全体のエントリポイントです。出力先を選択して実行します。"""
    logger = ExportLogger()

    program = currentProgram
    if program is None:
        printerr(u"currentProgram がありません。Ghidra で対象を開いてから実行してください。")
        return

    out_dir_file = askDirectory(
        "Select output base folder (claude_project or any folder)",
        "Select")
    out_base = out_dir_file.getAbsolutePath()
    # 二重ネスト事前警告: 選択フォルダ名が既に 'ghidra_exports' だと、ここで更に
    # 'ghidra_exports' を付け足すと out_root = ghidra_exports/ghidra_exports になり、
    # ghidra readonly MCP (CCT_PROJECT_ROOT/ghidra_exports を読む) も load_bridge_config
    # (out_root の親/直下を見る) も対象を見失う。事前に警告して回避させる。
    base_name = os.path.basename(os.path.normpath(out_base))
    if base_name.lower() == "ghidra_exports":
        warn = (u"選択フォルダ名が既に 'ghidra_exports' です。\n\n"
                u"このまま進めると出力先が\n  {0}\\ghidra_exports\n"
                u"になり、二重ネストで ghidra readonly MCP / bridge_config.json が\n"
                u"見つからなくなります。\n\n"
                u"[はい]   選択フォルダにそのまま出力する (推奨・二重ネスト回避)\n"
                u"[いいえ] それでも ghidra_exports を付け足して続行").format(out_base)
        avoid_nest = True
        try:
            avoid_nest = askYesNo(u"ghidra_exports 二重ネスト警告", warn)
        except Exception:
            # ダイアログ不可 (ヘッドレス等) のときは安全側に倒して回避する。
            logger.log(u"WARNING: " + warn.replace(u"\n", u" "))
        if avoid_nest:
            out_root = out_base
            logger.log(u"二重ネスト回避: 出力先を選択フォルダ自身 ({0}) にしました。".format(out_root))
        else:
            out_root = os.path.join(out_base, "ghidra_exports")
            logger.log(u"WARNING: 二重ネストのまま続行します: {0}".format(out_root))
    else:
        out_root = os.path.join(out_base, "ghidra_exports")
    if not os.path.isdir(out_root):
        os.makedirs(out_root)

    # ★出力先が決まった時点でログの逐次書き出しを始める。以降は log() のたびに
    #   flush するので、途中でハングして強制終了しても直前までのログが残る。
    logger.open_log(os.path.join(out_root, "export_log.txt"))

    logger.log(u"=== Ghidra Claude Toolbox export_context ===")
    logger.log(u"output: {0}".format(out_root))

    cfg = load_bridge_config(out_root, logger)
    source_model = cfg.get("source_model", "unknown")

    # decompile オプション (bridge_config.json で上書き可)
    dc_start = parse_cfg_addr(cfg.get("decompile_start", DECOMPILE_START))
    dc_end = parse_cfg_addr(cfg.get("decompile_end", DECOMPILE_END))
    try:
        dc_timeout = int(cfg.get("decompile_timeout_seconds", DECOMPILE_TIMEOUT_SECONDS))
    except Exception:
        dc_timeout = DECOMPILE_TIMEOUT_SECONDS
    try:
        dc_limit = int(cfg.get("decompile_limit", DECOMPILE_LIMIT))
    except Exception:
        dc_limit = DECOMPILE_LIMIT
    # ハードタイムアウト: 未指定なら協調的タイムアウト + 15 秒。
    dc_hard = cfg.get("decompile_hard_timeout_seconds", DECOMPILE_HARD_TIMEOUT_SECONDS)
    try:
        dc_hard = int(dc_hard) if dc_hard is not None else (dc_timeout + 15)
    except Exception:
        dc_hard = dc_timeout + 15
    # ★中身が無い関数を decompile 対象から外すガード (既定 True)。
    #   未初期化ブロックのダミー関数を踏むと Ghidra ごと固まることがあるため。
    #   無効化は明示指定が必要。
    dc_skip_uninit = cfg_flag(cfg.get("decompile_skip_uninitialized"),
                              DECOMPILE_SKIP_UNINITIALIZED)
    dc_skip_tiny = cfg_flag(cfg.get("decompile_skip_tiny"), DECOMPILE_SKIP_TINY)
    try:
        dc_max_out_kb = int(cfg.get("decompile_max_output_kb", DECOMPILE_MAX_OUTPUT_KB))
    except Exception:
        dc_max_out_kb = DECOMPILE_MAX_OUTPUT_KB
    dc_verbose = cfg_flag(cfg.get("decompile_verbose"), DECOMPILE_VERBOSE)
    # ★decompile の範囲を実行前に選ばせるか ("ask" / "limit" / "all")。
    dc_scope = cfg.get("decompile_scope", DECOMPILE_SCOPE)
    # ★疑似 C の行 -> 番地の対応表 (既定 True)。.c 1 個につき .lines.json が 1 個増える。
    dc_line_map = cfg_flag(cfg.get("decompile_line_map"), DECOMPILE_LINE_MAP)
    # 特定関数のみ decompile する指定 (range/limit より優先)。病的関数を踏まずに
    # 目的の関数だけ確実に取りたいとき用。
    dc_targets = set()
    for t in (cfg.get("decompile_targets") or []):
        v = parse_cfg_addr(t)
        if v is not None:
            dc_targets.add(v)
    if dc_targets:
        logger.log(u"decompile targets: {0} 関数のみ (range/limit 無視)".format(len(dc_targets)))
    elif dc_start is not None or dc_end is not None:
        logger.log(u"decompile 範囲: start={0} end={1}".format(
            hex(dc_start) if dc_start is not None else None,
            hex(dc_end) if dc_end is not None else None))
    if threading is None and dc_hard > 0:
        logger.log(u"WARNING: threading が使えないためハードタイムアウトは無効です (Ghidra 任せ)。")
        dc_hard = 0
    logger.log(u"decompile timeout={0}s hard_timeout={1}s limit={2} (設定値)".format(
        dc_timeout, dc_hard if dc_hard > 0 else u"無効", dc_limit))
    logger.log(u"decompile guards: skip_uninitialized={0} skip_tiny={1} "
               u"max_output_kb={2} verbose={3}".format(
                   dc_skip_uninit, dc_skip_tiny,
                   dc_max_out_kb if dc_max_out_kb > 0 else u"無効", dc_verbose))
    if not dc_skip_uninit:
        logger.log(u"WARNING: decompile_skip_uninitialized=false です。未初期化ブロックの"
                   u"ダミー関数 (PSY-Q の GTE マクロ等) を踏むと Ghidra ごと固まることが"
                   u"あります。")

    # 重い工程の ON/OFF (bridge_config.json で上書き可、既定は出力)
    do_xrefs = cfg_flag(cfg.get("export_xrefs"), True)
    do_undefined = cfg_flag(cfg.get("export_undefined_ranges"), True)
    # decompile 工程の ON/OFF。既定 True (後方互換)。
    # ⚠️ targets/range/limit いずれも無指定だと「全域 decompile」になり、病的関数1個で
    #    Ghidra が無限ハングする。初回 export など
    #    decompile が不要・危険なときは bridge_config で export_decompile=false にして丸ごと飛ばす。
    do_decompile = cfg_flag(cfg.get("export_decompile"), True)
    # メモリイメージ出力。**既定 false** (opt-in)。生バイナリを出すので明示指定を要求する。
    do_memory = cfg_flag(cfg.get("export_memory"), EXPORT_MEMORY)

    # ★工程の選択 (export_only)。空なら従来どおり全工程。
    #   指定された工程以外は **既存ファイルを残したまま** スキップする。
    only_sections = parse_export_only(cfg.get("export_only"), logger)

    def want_section(name):
        """その工程を今回実行するかを返します (export_only 未指定なら常に True)。"""
        return (not only_sections) or (name in only_sections)

    if only_sections:
        logger.log(u"export_only: {0} のみ実行します (他の工程は既存ファイルを残置)".format(
            u", ".join(sorted(only_sections))))
        if "decompile" in only_sections and not do_decompile:
            logger.log(u"WARNING: export_only に decompile があるのに "
                       u"export_decompile=false です。何も生成されません。")

    # ★decompile の範囲は **重い工程を始める前に** 決める。
    #   最後の工程なので、走らせてから「上限ぶんしか出ていない」と気づくと
    #   xrefs (48MB 級) まで含めてやり直しになる。
    dc_skip_reason = u"export_decompile=false"
    if do_decompile and want_section("decompile"):
        dc_limit, do_decompile = resolve_decompile_scope(
            program, dc_scope, dc_limit, dc_targets, dc_start, dc_end, logger)
        if not do_decompile:
            # 選択でスキップした場合と export_decompile=false を区別する
            # (後段のログで理由が分かるようにするため)。
            dc_skip_reason = u"decompile_scope の選択でスキップ"

    overall = _t()
    try:
        if want_section("program"):
            sec = _t()
            write_json(os.path.join(out_root, "program.json"),
                       export_program(program, source_model, logger))
            log_elapsed(logger, "program", sec, overall)
        else:
            logger.log(u"program: skip (export_only) — 既存 program.json は残置")

        if not want_section("memory"):
            logger.log(u"memory: skip (export_only) — 既存 memory/ は残置")
        elif do_memory:
            sec = _t()
            write_json(os.path.join(out_root, "memory_map.json"),
                       export_memory(program, out_root, logger, cfg))
            log_elapsed(logger, "memory", sec, overall)
        else:
            logger.log(u"memory: skip (export_memory=false) — "
                       u"get_disassembly / find_address_refs / read_data を使うなら "
                       u"true にしてください")

        if want_section("functions"):
            sec = _t()
            write_json(os.path.join(out_root, "functions.json"),
                       export_functions(program, logger))
            log_elapsed(logger, "functions", sec, overall)
        else:
            logger.log(u"functions: skip (export_only) — 既存 functions.json は残置")

        if want_section("strings"):
            sec = _t()
            write_json(os.path.join(out_root, "strings.json"),
                       export_strings(program, logger))
            log_elapsed(logger, "strings", sec, overall)
        else:
            logger.log(u"strings: skip (export_only) — 既存 strings.json は残置")

        if want_section("labels"):
            sec = _t()
            write_json(os.path.join(out_root, "labels.json"),
                       export_labels(program, logger))
            log_elapsed(logger, "labels", sec, overall)
        else:
            logger.log(u"labels: skip (export_only) — 既存 labels.json は残置")

        if want_section("defined_data"):
            sec = _t()
            write_json(os.path.join(out_root, "defined_data.json"),
                       export_defined_data(program, logger))
            log_elapsed(logger, "defined_data", sec, overall)
        else:
            logger.log(u"defined_data: skip (export_only) — 既存 JSON は残置")

        if want_section("datatypes"):
            sec = _t()
            write_json(os.path.join(out_root, "datatypes.json"),
                       export_datatypes(program, logger), compact=True)
            log_elapsed(logger, "datatypes", sec, overall)
        else:
            logger.log(u"datatypes: skip (export_only) — 既存 datatypes.json は残置")

        if want_section("comments"):
            sec = _t()
            write_json(os.path.join(out_root, "comments.json"),
                       export_comments(program, logger))
            log_elapsed(logger, "comments", sec, overall)
        else:
            logger.log(u"comments: skip (export_only) — 既存 comments.json は残置")

        if not want_section("xrefs"):
            logger.log(u"xrefs: skip (export_only) — 既存 xrefs.json は残置")
        elif do_xrefs:
            sec = _t()
            write_json(os.path.join(out_root, "xrefs.json"),
                       export_xrefs(program, logger), compact=True)
            log_elapsed(logger, "xrefs", sec, overall)
        else:
            logger.log(u"xrefs: skip (export_xrefs=false)")

        if not want_section("undefined_ranges"):
            logger.log(u"undefined_ranges: skip (export_only) — 既存 JSON は残置")
        elif do_undefined:
            sec = _t()
            write_json(os.path.join(out_root, "undefined_ranges.json"),
                       export_undefined_ranges(program, logger))
            log_elapsed(logger, "undefined_ranges", sec, overall)
        else:
            logger.log(u"undefined_ranges: skip (export_undefined_ranges=false) — 既存 JSON は残置")

        if not want_section("decompile"):
            logger.log(u"decompile: skip (export_only) — 既存 decompile/ は残置")
        elif do_decompile:
            if not dc_targets and dc_start is None and dc_end is None and dc_limit <= 0:
                logger.log(u"WARNING: decompile が targets/range/limit いずれも無指定です。"
                           u"全域 decompile になり病的関数で Ghidra が無限ハングする恐れがあります。"
                           u"中断するには Ghidra の Cancel を押してください。")
            sec = _t()
            export_decompile(program, os.path.join(out_root, "decompile"), logger,
                             start_i=dc_start, end_i=dc_end,
                             timeout=dc_timeout, limit=dc_limit, targets=dc_targets,
                             hard_timeout=dc_hard,
                             skip_uninitialized=dc_skip_uninit,
                             skip_tiny=dc_skip_tiny,
                             max_output_kb=dc_max_out_kb,
                             verbose=dc_verbose,
                             line_map=dc_line_map)
            log_elapsed(logger, "decompile", sec, overall)
        else:
            logger.log(u"decompile: skip ({0}) — 既存 decompile/ は残置".format(
                dc_skip_reason))

        end = _t()
        if overall is not None and end is not None:
            logger.log(u"[time] TOTAL: {0:.1f}s".format(end - overall))
        logger.log(u"=== export 完了 ===")
    except Exception:
        logger.log(u"FATAL: export 中に予期しないエラーが発生しました。")
        logger.log(traceback.format_exc())
        printerr(u"export 中にエラーが発生しました。export_log.txt を確認してください。")
    finally:
        logger.save(os.path.join(out_root, "export_log.txt"))


run()
