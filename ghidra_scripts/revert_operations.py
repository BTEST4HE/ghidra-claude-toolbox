# -*- coding: utf-8 -*-
# Ghidra Claude Toolbox - revert_operations.py
#
# Ghidra GUI (Script Manager) から手動実行するスクリプトです。
# 共有台帳 defined_functions.json を読み、各記録を operation に応じて巻き戻します。
# apply_functions.py / apply_undefine.py が書いた記録の逆操作を行います。
# (revert_functions.py を発展・吸収したもの。define 専用台帳も後方互換で扱えます。)
#
# 本スクリプトは Ghidra 上の Jython (Python 2.7 互換) で動作します。
#
# 巻き戻し対応:
#   - define_function 記録   → 作成した関数を削除 (disassembled なら命令もクリア)
#   - undefine_function 記録 → mode を復元して再 disassemble + 再関数化
#   - clear_code 記録        → mode を復元して範囲を再 disassemble (関数は作らない)
#   - set_label 記録         → 付けたラベルを削除 (新規作成時) / 元の名前へ戻す (force リネーム時)
#   - set_register_DP / set_register_DBR 記録 (apply_snes_context.py)
#                            → 範囲の値を消し、設定前に明示値のあった範囲だけ元の値へ戻す
#
# 安全ルール:
#   - define_function の巻き戻しは、関数名が記録時 (既定名) から変わっていたら SKIP
#     (人間が採用/リネームしたとみなす)。
#   - undefine/clear の巻き戻しは、その場所に既に関数/命令があれば SKIP (二重化回避)。
#   - set_label の巻き戻しも、現在の名前が記録時と違えば SKIP (人間が直したとみなす)。
#     関数シンボルには触りません。
#   - set_register_* の巻き戻しも、範囲の両端の値が記録時と違えば SKIP (人間が直したとみなす)。
#     扱うのは DP / DBR だけ (コンテキスト ctx_MF 等は記録があっても触りません)。
#   - revert はベストエフォート (flow 追跡で完全一致は保証しない)。保存はしません。
#
#@category ClaudeToolbox
#@menupath Tools.ClaudeToolbox.Revert Operations
#@runtime Jython

from __future__ import print_function

import codecs
import json
import os
import traceback


BUILTIN_PROFILES = {
    "gba": {"name": "gba", "context_register": "TMode", "mode_values": {"arm": 0, "thumb": 1}},
    "sh4": {"name": "sh4"}, "psx": {"name": "psx"}, "wii": {"name": "wii"},
}


class RevertLogger(object):
    def __init__(self):
        self.lines = []
        self.reverted = 0
        self.skipped = 0
        self.errors = 0

    def log(self, message):
        text = u"{0}".format(message)
        self.lines.append(text)
        try:
            println(text)
        except Exception:
            print(text)


def read_json(path):
    f = codecs.open(path, "r", "utf-8")
    try:
        return json.load(f)
    finally:
        f.close()


def toolbox_root():
    try:
        return os.path.dirname(os.path.dirname(getSourceFile().getAbsolutePath()))
    except Exception:
        return None


def load_platform_profile(name):
    if not name:
        return {}
    root = toolbox_root()
    if root is not None:
        path = os.path.join(root, "platform_profiles", str(name) + ".json")
        if os.path.isfile(path):
            try:
                return read_json(path)
            except Exception:
                pass
    return dict(BUILTIN_PROFILES.get(str(name), {}))


def get_address(program, text):
    try:
        return program.getAddressFactory().getAddress(str(text))
    except Exception:
        return None


def set_mode(program, addr, mode, profile, logger):
    reg_name = profile.get("context_register")
    if not reg_name or mode is None:
        return True
    mode_values = profile.get("mode_values", {})
    if mode not in mode_values:
        return False
    try:
        from java.math import BigInteger
        pc = program.getProgramContext()
        reg = pc.getRegister(reg_name)
        if reg is None:
            return False
        pc.setValue(reg, addr, addr, BigInteger.valueOf(int(mode_values[mode])))
        return True
    except Exception:
        logger.log(u"WARN: モード復元に失敗 ({0}={1})".format(reg_name, mode))
        return False


def revert_define(program, item, logger):
    """define_function の巻き戻し = 作成した関数を削除。"""
    entry_s = item.get("entry") or item.get("address")
    recorded_name = item.get("name")
    addr = get_address(program, entry_s)
    if addr is None:
        logger.log(u"SKIP (invalid address): {0}".format(entry_s))
        return "skipped"
    func = getFunctionAt(addr)
    if func is None:
        logger.log(u"SKIP (関数が無い): {0}".format(entry_s))
        return "skipped"
    if recorded_name is not None and func.getName() != recorded_name:
        logger.log(u"SKIP (renamed by human: {0}): {1}".format(func.getName(), entry_s))
        return "skipped"
    body = func.getBody()
    bmin = body.getMinAddress()
    bmax = body.getMaxAddress()
    try:
        removeFunction(func)
    except Exception:
        logger.log(u"ERROR: removeFunction 失敗: {0}".format(entry_s))
        return "error"
    if item.get("disassembled"):
        rmin = get_address(program, item.get("body_min")) or bmin
        rmax = get_address(program, item.get("body_max")) or bmax
        try:
            clearListing(rmin, rmax)
        except Exception:
            pass
    logger.log(u"REVERT define: {0} (関数削除)".format(entry_s))
    return "reverted"


def revert_undefine(program, item, logger, profile_cache):
    """undefine_function / clear_code の巻き戻し = 再 disassemble (+ 再関数化)。"""
    entry_s = item.get("entry") or item.get("address")
    operation = item.get("operation")
    addr = get_address(program, entry_s)
    if addr is None:
        logger.log(u"SKIP (invalid address): {0}".format(entry_s))
        return "skipped"

    # 既に何かある場合は二重化を避けて SKIP。
    if getInstructionAt(addr) is not None or getFunctionAt(addr) is not None:
        logger.log(u"SKIP (既に命令/関数あり — 二重化回避): {0}".format(entry_s))
        return "skipped"

    platform = item.get("platform")
    if platform not in profile_cache:
        profile_cache[platform] = load_platform_profile(platform)
    profile = profile_cache.get(platform, {})
    set_mode(program, addr, item.get("mode"), profile, logger)

    try:
        disassemble(addr)
    except Exception:
        logger.log(u"ERROR: disassemble 失敗: {0}".format(entry_s))
        return "error"

    if operation == "undefine_function" or item.get("was_function"):
        try:
            createFunction(addr, None)
        except Exception:
            logger.log(u"WARN: createFunction 失敗 (命令のみ復元): {0}".format(entry_s))
    logger.log(u"REVERT {0}: {1} (再 disassemble)".format(operation, entry_s))
    return "reverted"


def revert_label(program, item, logger):
    """set_label の巻き戻し = 付けたラベルを削除、または元の名前へ戻す。

    apply_labels.py が記録した created / previous_name を見て動作を決めます。
      created=True  … 新規に付けたラベルなので削除する。
      created=False … force で既存シンボルをリネームしたので、元の名前へ戻す。
    現在の名前が記録時と違う場合は、人間が手で直したとみなして SKIP します。
    """
    addr_s = item.get("entry") or item.get("address")
    recorded_name = item.get("name")
    addr = get_address(program, addr_s)
    if addr is None:
        logger.log(u"SKIP (invalid address): {0}".format(addr_s))
        return "skipped"

    # 関数シンボルには触らない (apply_labels は関数エントリを拒否しているが念のため)。
    try:
        if getFunctionAt(addr) is not None:
            logger.log(u"SKIP (関数エントリ — シンボルに触りません): {0}".format(addr_s))
            return "skipped"
    except Exception:
        pass

    try:
        symbol_table = program.getSymbolTable()
        symbol = symbol_table.getPrimarySymbol(addr)
    except Exception:
        logger.log(u"ERROR: シンボルを取得できません: {0}".format(addr_s))
        return "error"
    if symbol is None:
        logger.log(u"SKIP (シンボルが無い): {0}".format(addr_s))
        return "skipped"

    current_name = u"{0}".format(symbol.getName())
    if recorded_name is not None and current_name != recorded_name:
        logger.log(u"SKIP (名前が記録時と違う: {0} != {1}) — 人間が直したとみなします: {2}".format(
            current_name, recorded_name, addr_s))
        return "skipped"

    previous_name = item.get("previous_name")
    if item.get("created", previous_name is None):
        # 新規に付けたラベルなので削除する。
        try:
            if not bool(symbol.delete()):
                logger.log(u"ERROR: ラベル削除に失敗: {0}".format(addr_s))
                return "error"
        except Exception:
            logger.log(u"ERROR: ラベル削除で例外: {0}".format(addr_s))
            return "error"
        logger.log(u"REVERT set_label: {0} (ラベル {1} を削除)".format(addr_s, current_name))
        return "reverted"

    # force リネームの巻き戻し = 元の名前へ戻す。
    if not previous_name:
        logger.log(u"SKIP (元の名前が記録されていません): {0}".format(addr_s))
        return "skipped"
    try:
        from ghidra.program.model.symbol import SourceType
        source = SourceType.USER_DEFINED
        recorded_source = item.get("previous_source")
        if recorded_source:
            try:
                source = getattr(SourceType, str(recorded_source).upper(), source)
            except Exception:
                source = SourceType.USER_DEFINED
        symbol.setName(previous_name, source)
    except Exception:
        logger.log(u"ERROR: 元の名前 '{0}' へ戻せませんでした: {1}".format(previous_name, addr_s))
        return "error"
    logger.log(u"REVERT set_label: {0} ({1} -> {2} へ復元)".format(
        addr_s, current_name, previous_name))
    return "reverted"


REVERTABLE_REGISTERS = ("DP", "DBR")


def ledger_int(value):
    """台帳の数値を int にします。整数以外 (None / 文字列 / bool など) は None。"""
    if isinstance(value, bool):
        return None
    try:
        integer_types = (int, long)
    except NameError:
        integer_types = (int,)
    if isinstance(value, integer_types):
        return int(value)
    return None


def register_range_problem(context, register, start, end, wanted):
    """[start, end] の全番地に wanted が明示的に設定されているかを確かめます。

    値の設定された範囲を列挙し、start から end まで隙間なく続いていて、
    どの範囲の値も wanted であることを求めます。全範囲が一致すれば None、
    そうでなければ理由の文字列を返します (確認中の例外も「確認できない」として返す)。
    """
    try:
        ranges = context.getRegisterValueAddressRanges(register, start, end)
        expected = start
        while ranges.hasNext():
            rng = ranges.next()
            lo = rng.getMinAddress()
            hi = rng.getMaxAddress()
            if lo.compareTo(expected) != 0:
                return u"値の無い番地がある: 0x{0}".format(expected.toString())
            for where in (lo, hi):
                # Jython では getValue の BigInteger が Python の long になって返る (実測)
                current = context.getValue(register, where, False)
                if current is None or int(current) != wanted:
                    return u"値が記録時と違う: 0x{0}={1} != {2}".format(
                        where.toString(), current, wanted)
            if hi.compareTo(end) >= 0:
                return None
            expected = hi.next()
            if expected is None:
                return u"範囲の終わりを確認できない"
        return u"値の無い番地がある: 0x{0}".format(expected.toString())
    except Exception as exc:
        return u"値を確認できない ({0})".format(exc)


def revert_register(program, item, logger):
    """set_register_DP / set_register_DBR の巻き戻し (apply_snes_context.py の逆操作)。

    範囲 [entry, end] の値を消してから、記録 previous にある
    「設定前に明示値のあった範囲」だけ元の値で設定し直します。
    範囲の**全番地**が記録した値のままのときだけ戻します。1 番地でも違う・
    値が無い・確認できないときは、人間が後から直したとみなして何も変えずに SKIP。
    """
    reg_name = item.get("register")
    start_s = item.get("entry")
    end_s = item.get("end") or start_s
    if reg_name not in REVERTABLE_REGISTERS:
        logger.log(u"SKIP (register={0} は巻き戻し対象外): {1}".format(reg_name, start_s))
        return "skipped"
    start = get_address(program, start_s)
    end = get_address(program, end_s)
    if start is None or end is None:
        logger.log(u"SKIP (invalid address): {0}..{1}".format(start_s, end_s))
        return "skipped"
    wanted = ledger_int(item.get("value"))
    if wanted is None:
        logger.log(u"SKIP (記録の value が整数でない): {0}={1}".format(reg_name, item.get("value")))
        return "skipped"
    try:
        from java.math import BigInteger
        context = program.getProgramContext()
        register = context.getRegister(reg_name)
    except Exception:
        logger.log(u"ERROR: レジスタ {0} を取得できません".format(reg_name))
        return "error"
    if register is None:
        logger.log(u"SKIP (この言語に {0} が無い): {1}".format(reg_name, start_s))
        return "skipped"
    try:
        if bool(register.isProcessorContext()):
            logger.log(u"SKIP ({0} がコンテキストレジスタ — 触りません)".format(reg_name))
            return "skipped"
    except Exception:
        pass

    # 戻す値は変更前にすべて読んでおく (途中で読めないと、消しただけで終わるため)
    restore = []
    for prev in item.get("previous") or []:
        p_start = get_address(program, prev.get("start"))
        p_end = get_address(program, prev.get("end"))
        p_value = ledger_int(prev.get("value"))
        if p_start is None or p_end is None or p_value is None:
            logger.log(u"SKIP (previous が読めない: {0}) — 何も変えません".format(prev))
            return "skipped"
        restore.append((p_start, p_end, BigInteger.valueOf(p_value)))

    problem = register_range_problem(context, register, start, end, wanted)
    if problem is not None:
        logger.log(u"SKIP ({0}: {1}..{2}) — 人間が直したとみなし、何も変えません".format(
            problem, start_s, end_s))
        return "skipped"

    try:
        context.remove(start, end, register)
        for p_start, p_end, p_value in restore:
            context.setValue(register, p_start, p_end, p_value)
    except Exception:
        logger.log(u"ERROR: {0} の巻き戻しで例外: {1}..{2}".format(reg_name, start_s, end_s))
        logger.log(traceback.format_exc())
        return "error"
    logger.log(u"REVERT {0}: {1}..{2} (元の明示値 {3} 範囲を復元)".format(
        reg_name, start_s, end_s, len(restore)))
    return "reverted"


# ---- 安全ゲート (BEGIN) -----------------------------------------------------
# ★apply_comments / apply_functions / apply_undefine / apply_labels /
#   apply_snes_context / revert_operations で**同一の内容**です。片方だけ直さないこと
#   (直すときは 6 本を同時に直すこと)。
#   どの検査も、トランザクション開始・モード変更・逆アセンブル・関数の作成/削除・
#   Listing のクリア・台帳の書き込みより**前に**呼びます。
try:
    _GATE_TEXT_TYPES = (basestring,)   # noqa: F821 (Jython / Python 2.7)
except NameError:                      # Python 3 (オフライン検証)
    _GATE_TEXT_TYPES = (str,)

GATE_CONFIG_NAME = "bridge_config.json"


def gate_target_program(data, program, what):
    """data の target_program が現在の Program 名と一致しなければ理由を返します。

    一致すれば None。target_program が無い・空・文字列でない場合も拒否します。
    ★これは「同じ名前か」の確認でしかありません。同名の別 Program
      (版違いのコピー等) までは区別できません。
    """
    if not isinstance(data, dict):
        return u"{0} が JSON オブジェクトではありません。".format(what)
    target = data.get("target_program")
    if target is None:
        return u"{0} に target_program がありません。".format(what)
    if not isinstance(target, _GATE_TEXT_TYPES):
        return u"{0} の target_program が文字列ではありません。".format(what)
    if not target.strip():
        return u"{0} の target_program が空です。".format(what)
    current = u"{0}".format(program.getName())
    if target != current:
        return u"{0} の target_program='{1}' が現在の Program='{2}' と一致しません。".format(
            what, target, current)
    return None


def gate_ledger(path, program):
    """共有台帳を変更前に確かめ、(台帳 dict, 問題) を返します。問題が無ければ問題は None。

    - 無い → 空の台帳
    - 読めない / 形が不正 → 問題 (上書きすると記録を失うため)
    - 記録があるのに target_program が無い / 別 Program 用 → 問題
    """
    if not os.path.exists(path):
        return {"schema_version": "0.1", "defined": []}, None
    try:
        with codecs.open(path, "r", "utf-8") as handle:
            data = json.load(handle)
    except Exception:
        return None, u"台帳 {0} を JSON として読めません (上書きすると記録を失うので中止します)。".format(
            path)
    if not isinstance(data, dict) or not isinstance(data.get("defined"), list):
        return None, u"台帳 {0} の形が不正です (defined 配列がありません)。".format(path)
    if data["defined"]:
        problem = gate_target_program(data, program, u"台帳 {0}".format(path))
        if problem:
            return None, problem
    return data, None


def gate_operation_allowed(in_path, operation):
    """bridge_config.json の allowed_apply_operations に operation があるか確かめます。

    許可されていれば None、そうでなければ理由を返します。bridge_config.json が無い・
    壊れている・allowed_apply_operations が配列でない場合も拒否します。
    探す場所は入力 JSON の近傍 (同じフォルダ〜2 つ上) で、最初に見つかったものを使います。
    """
    d = os.path.dirname(in_path)
    candidates = [os.path.join(d, GATE_CONFIG_NAME),
                  os.path.join(os.path.dirname(d), GATE_CONFIG_NAME),
                  os.path.join(os.path.dirname(os.path.dirname(d)), GATE_CONFIG_NAME)]
    cfg_path = None
    for c in candidates:
        if os.path.isfile(c):
            cfg_path = c
            break
    how = (u"許可するには、そのプロジェクトの bridge_config.json の "
           u"allowed_apply_operations に \"{0}\" を追加してください。".format(operation))
    if cfg_path is None:
        return u"bridge_config.json が見つかりません ({0} の近傍を探しました)。{1}".format(d, how)
    try:
        with codecs.open(cfg_path, "r", "utf-8") as handle:
            cfg = json.load(handle)
    except Exception:
        return u"bridge_config.json を JSON として読めません: {0}。{1}".format(cfg_path, how)
    if not isinstance(cfg, dict):
        return u"bridge_config.json がオブジェクトではありません: {0}。{1}".format(cfg_path, how)
    allowed = cfg.get("allowed_apply_operations")
    if not isinstance(allowed, (list, tuple)):
        return u"allowed_apply_operations が配列ではありません ({0})。{1}".format(cfg_path, how)
    for op in allowed:
        if isinstance(op, _GATE_TEXT_TYPES) and op.strip().lower() == operation:
            return None
    return u"\"{0}\" は許可されていません (allowed_apply_operations={1}, {2})。{3}".format(
        operation, allowed, cfg_path, how)
# ---- 安全ゲート (END) -------------------------------------------------------


def run():
    logger = RevertLogger()
    program = currentProgram
    if program is None:
        printerr(u"currentProgram がありません。Ghidra で対象を開いてから実行してください。")
        return

    in_file = askFile("Select defined_functions.json (shared ledger: define/undefine/label)",
                      "Open")
    in_path = in_file.getAbsolutePath()

    logger.log(u"=== Ghidra Claude Toolbox revert_operations ===")
    logger.log(u"input: {0}".format(in_path))

    try:
        data = read_json(in_path)
    except Exception:
        printerr(u"JSON として読み込めませんでした: {0}".format(in_path))
        return
    if not isinstance(data.get("defined"), list):
        printerr(u"defined 配列がありません。")
        return

    # ★台帳の対象 Program の照合 (不一致・欠落なら変更前に中止)。
    problem = gate_target_program(data, program, u"台帳")
    if problem:
        printerr(u"対象 Program を確認できないので中止しました。何も変更していません。\n  "
                 + problem + u"\n" + u"  提案 / 台帳の target_program を、いま開いている Program の名前と照合します。\n  正しい Program を開いているか確かめ、提案を作り直すか、確認のうえで\n  target_program に Program 名を書いてください (docs/safety_rules.md「対象 Program の照合」)。")
        return

    profile_cache = {}
    tx_id = program.startTransaction("Revert [AI] operations")
    try:
        for item in data["defined"]:
            operation = item.get("operation", "define_function")
            try:
                if operation == "define_function":
                    result = revert_define(program, item, logger)
                elif operation in ("undefine_function", "clear_code"):
                    result = revert_undefine(program, item, logger, profile_cache)
                elif operation == "set_label":
                    result = revert_label(program, item, logger)
                elif str(operation).startswith("set_register_"):
                    result = revert_register(program, item, logger)
                else:
                    logger.log(u"SKIP (未知 operation={0})".format(operation))
                    result = "skipped"
            except Exception:
                result = "error"
                logger.log(u"ERROR: 想定外の例外。")
                logger.log(traceback.format_exc())
            if result == "reverted":
                logger.reverted += 1
            elif result == "skipped":
                logger.skipped += 1
            else:
                logger.errors += 1
    finally:
        program.endTransaction(tx_id, logger.reverted > 0)

    logger.log(u"=== revert 完了 ===")
    logger.log(u"reverted={0} skipped={1} errors={2}".format(
        logger.reverted, logger.skipped, logger.errors))
    logger.log(u"※ 保存していません。状態を確定するなら Ctrl+S。")


run()
