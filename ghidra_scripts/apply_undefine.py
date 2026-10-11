# -*- coding: utf-8 -*-
# Ghidra Claude Toolbox - apply_undefine.py
#
# Ghidra GUI (Script Manager) から手動実行するスクリプトです。
# proposed_functions.json (混在ファイル) のうち operation が undefine_function /
# clear_code の item を処理し、誤って関数化/逆アセンブルされたコードを
# 「未定義に戻す」(破壊的) スクリプトです。apply_functions.py の逆操作。
#
# 本スクリプトは Ghidra 上の Jython (Python 2.7 互換) で動作します。
#
# 安全ルール (破壊的なので define より慎重):
#   - protect チェックに該当したら SKIP (人間の成果を守る):
#       * リネーム済み (名前が FUN_<addr> でない)
#       * コメントが付いている (entry/body)
#       * 実 CALL ターゲット (定義済みコードから CALL されている)
#       * ユーザー定義ラベル / Note ブックマーク
#     ただし item の force=true で protect を無視できる (範囲上限は無視不可)。
#   - 範囲/関数 body が undefine_max_bytes を超えたら REJECT (force でも不可)。
#   - clear するアドレス/範囲・元が関数か・mode を共有台帳に記録 (revert 用)。
#   - address_basis が ghidra/未指定のものだけ処理。
#   - このスクリプトは Program を保存しません。
#
#@category ClaudeToolbox
#@menupath Tools.ClaudeToolbox.Apply Undefine
#@runtime Jython

from __future__ import print_function

import codecs
import json
import os
import traceback


SAFE_ADDRESS_BASIS = ("ghidra", "", None)
DEFAULT_UNDEFINE_MAX_BYTES = 0x4000
RECORD_NAME = "defined_functions.json"   # 共有台帳 (define/undefine 混在)
UNDEFINE_OPERATIONS = ("undefine_function", "clear_code")

BUILTIN_PROFILES = {
    "gba": {"name": "gba", "context_register": "TMode", "mode_values": {"arm": 0, "thumb": 1}},
    "sh4": {"name": "sh4"}, "psx": {"name": "psx"}, "wii": {"name": "wii"},
}


class ApplyLogger(object):
    def __init__(self):
        self.lines = []
        self.applied = 0
        self.skipped = 0
        self.rejected = 0
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


def write_json(path, obj):
    f = codecs.open(path, "w", "utf-8")
    try:
        f.write(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False))
        f.write(u"\n")
    finally:
        f.close()


def load_existing_record(path):
    if not os.path.isfile(path):
        return {"schema_version": "0.1", "defined": []}
    try:
        data = read_json(path)
        if not isinstance(data.get("defined"), list):
            data["defined"] = []
        return data
    except Exception:
        return {"schema_version": "0.1", "defined": []}


def load_bridge_config(in_path):
    d = os.path.dirname(in_path)
    for cfg in (os.path.join(d, "bridge_config.json"),
                os.path.join(os.path.dirname(d), "bridge_config.json"),
                os.path.join(os.path.dirname(os.path.dirname(d)), "bridge_config.json")):
        if os.path.isfile(cfg):
            try:
                return read_json(cfg)
            except Exception:
                return {}
    return {}


def toolbox_root():
    try:
        return os.path.dirname(os.path.dirname(getSourceFile().getAbsolutePath()))
    except Exception:
        return None


def load_platform_profile(name, logger):
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


def addr_str(address):
    return u"0x{0}".format(address.toString())


def item_addr(item):
    return item.get("address") or item.get("entry")


def capture_mode(program, addr, profile):
    """mode 持ちアーキで対象アドレスのモード名 (arm/thumb 等) を読みます。無ければ None。"""
    reg_name = profile.get("context_register")
    if not reg_name:
        return None
    try:
        pc = program.getProgramContext()
        reg = pc.getRegister(reg_name)
        if reg is None:
            return None
        val = pc.getValue(reg, addr, False)
        if val is None:
            return None
        ival = int(val.intValue())
        for k, v in profile.get("mode_values", {}).items():
            if int(v) == ival:
                return k
        return None
    except Exception:
        return None


def body_has_comment(program, body):
    """body 範囲にコメントが 1 つでもあるか。"""
    try:
        it = program.getListing().getCommentAddressIterator(body, True)
        return it.hasNext()
    except Exception:
        return False


def has_user_label(program, addr):
    try:
        from ghidra.program.model.symbol import SourceType
        sym = getSymbolAt(addr)
        if sym is not None and sym.getSource() == SourceType.USER_DEFINED:
            return True
    except Exception:
        pass
    return False


def has_note_bookmark(program, addr):
    try:
        bms = program.getBookmarkManager().getBookmarks(addr)
        for bm in bms:
            if bm.getTypeString() == "Note":
                return True
    except Exception:
        pass
    return False


def is_real_call_target(program, addr):
    """定義済みコードから CALL されているか (= 本物のコードの可能性)。"""
    try:
        rm = program.getReferenceManager()
        for ref in rm.getReferencesTo(addr):
            try:
                if ref.getReferenceType().isCall():
                    if getFunctionContaining(ref.getFromAddress()) is not None:
                        return True
            except Exception:
                continue
    except Exception:
        pass
    return False


def protect_reason(program, addr, func, body):
    """human の成果を守る protect チェック。理由文字列を返す (守る必要なし→None)。"""
    if func is not None:
        try:
            default_name = u"FUN_{0}".format(addr.toString())
            if func.getName() != default_name:
                return u"renamed({0})".format(func.getName())
        except Exception:
            pass
    if body is not None and body_has_comment(program, body):
        return u"has_comment"
    if is_real_call_target(program, addr):
        return u"is_call_target"
    if has_user_label(program, addr):
        return u"user_label"
    if has_note_bookmark(program, addr):
        return u"note_bookmark"
    return None


def range_size(start, end):
    try:
        return int(end.subtract(start)) + 1
    except Exception:
        return None


def apply_one(program, item, logger, new_records, profile_cache, default_platform, max_bytes):
    operation = item.get("operation")
    if operation not in UNDEFINE_OPERATIONS:
        return None  # define_function 等はこのスクリプトの対象外 (黙ってスキップ)

    addr_s = item_addr(item)
    basis = item.get("address_basis")
    if basis not in SAFE_ADDRESS_BASIS:
        logger.log(u"SKIP (address_basis={0}): {1}".format(basis, addr_s))
        return "skipped"

    try:
        addr = program.getAddressFactory().getAddress(str(addr_s))
    except Exception:
        addr = None
    if addr is None or not program.getMemory().contains(addr):
        logger.log(u"SKIP (invalid/not in memory): {0}".format(addr_s))
        return "skipped"

    platform = item.get("platform") or default_platform
    if platform not in profile_cache:
        profile_cache[platform] = load_platform_profile(platform, logger)
    profile = profile_cache.get(platform, {})

    force = bool(item.get("force", False))

    # 対象範囲と「元が関数か」を決める。
    if operation == "undefine_function":
        func = getFunctionAt(addr)
        if func is None:
            logger.log(u"SKIP (関数が無い): {0}".format(addr_s))
            return "skipped"
        body = func.getBody()
        bmin = body.getMinAddress()
        bmax = body.getMaxAddress()
        was_function = True
    else:  # clear_code
        end_s = item.get("end")
        try:
            bmax = program.getAddressFactory().getAddress(str(end_s))
        except Exception:
            bmax = None
        if bmax is None or not program.getMemory().contains(bmax):
            logger.log(u"SKIP (clear_code: end 不正): {0}".format(addr_s))
            return "skipped"
        func = getFunctionContaining(addr)
        bmin = addr
        body = None
        was_function = False

    # 範囲上限 (force でも無視不可)。
    size = range_size(bmin, bmax)
    if size is None or size > max_bytes:
        logger.log(u"REJECT (range {0} bytes > undefine_max_bytes {1}): {2}".format(
            size, max_bytes, addr_s))
        return "rejected"

    # protect チェック。
    reason = protect_reason(program, addr, func, body)
    if reason is not None:
        if force:
            logger.log(u"FORCE (protect 無視: {0}): {1}".format(reason, addr_s))
        else:
            logger.log(u"SKIP (protect: {0}): {1}".format(reason, addr_s))
            return "skipped"

    # revert 用に mode を記録。
    mode = capture_mode(program, addr, profile)

    # 記録は「消す前」に作る。
    record = {
        "operation": operation,
        "entry": addr_str(addr),
        "body_min": addr_str(bmin),
        "body_max": addr_str(bmax),
        "was_function": was_function,
        "mode": mode,
        "platform": platform,
    }

    # 実行: 関数削除 + 範囲クリア。
    try:
        if was_function and func is not None:
            removeFunction(func)
        clearListing(bmin, bmax)
    except Exception:
        logger.log(u"ERROR: undefine 失敗: {0}".format(addr_s))
        logger.log(traceback.format_exc())
        return "error"

    new_records.append(record)
    logger.log(u"UNDEFINE: {0} op={1} range={2}-{3} ({4}B) was_function={5} mode={6}".format(
        addr_s, operation, record["body_min"], record["body_max"], size, was_function, mode))
    return "applied"


def merge_record(existing, new_records, program):
    by_key = {}
    for d in existing.get("defined", []):
        k = (d.get("operation", "define_function"), (d.get("entry") or "").lower())
        by_key[k] = d
    for d in new_records:
        by_key[(d["operation"], d["entry"].lower())] = d
    return {
        "schema_version": "0.1",
        "target_program": program.getName(),
        "defined": list(by_key.values()),
    }


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
    logger = ApplyLogger()
    program = currentProgram
    if program is None:
        printerr(u"currentProgram がありません。Ghidra で対象を開いてから実行してください。")
        return

    in_file = askFile("Select proposed_functions.json (undefine items)", "Open")
    in_path = in_file.getAbsolutePath()

    logger.log(u"=== Ghidra Claude Toolbox apply_undefine ===")
    logger.log(u"input: {0}".format(in_path))

    # ★opt-in ゲート。未定義化 (undefine) は既定で禁止。許可が無ければ何も変更せず終了する
    #   (Script Manager から手動で実行したことや、JSON を選んだことは許可の代わりにしない)。
    problem = gate_operation_allowed(in_path, "undefine")
    if problem:
        printerr(u"未定義化 (undefine) は許可されていません。何も変更していません。\n  " + problem)
        return
    logger.log(u"opt-in 確認 OK: allowed_apply_operations に \"undefine\" があります")

    try:
        data = read_json(in_path)
    except Exception:
        printerr(u"JSON として読み込めませんでした: {0}".format(in_path))
        return
    if not isinstance(data.get("functions"), list):
        printerr(u"functions 配列がありません。")
        return

    # ★対象 Program の照合 (不一致・欠落なら変更前に中止。警告だけで続行しない)。
    problem = gate_target_program(data, program, u"提案 JSON")
    if problem:
        printerr(u"対象 Program を確認できないので中止しました。何も変更していません。\n  "
                 + problem + u"\n" + u"  提案 / 台帳の target_program を、いま開いている Program の名前と照合します。\n  正しい Program を開いているか確かめ、提案を作り直すか、確認のうえで\n  target_program に Program 名を書いてください (docs/safety_rules.md「対象 Program の照合」)。")
        return

    cfg = load_bridge_config(in_path)
    default_platform = data.get("platform") or cfg.get("platform_profile")
    try:
        max_bytes = int(cfg.get("undefine_max_bytes", DEFAULT_UNDEFINE_MAX_BYTES))
    except Exception:
        max_bytes = DEFAULT_UNDEFINE_MAX_BYTES
    logger.log(u"undefine_max_bytes={0} platform={1}".format(max_bytes, default_platform))

    record_path = os.path.join(os.path.dirname(in_path), RECORD_NAME)
    # ★共有台帳の確認 (壊れている / 別 Program 用なら、上書きせず変更前に中止)。
    existing_record, problem = gate_ledger(record_path, program)
    if problem:
        printerr(u"台帳を確認できないので中止しました。何も変更していません。\n  "
                 + problem + u"\n" + u"  提案 / 台帳の target_program を、いま開いている Program の名前と照合します。\n  正しい Program を開いているか確かめ、提案を作り直すか、確認のうえで\n  target_program に Program 名を書いてください (docs/safety_rules.md「対象 Program の照合」)。")
        return
    new_records = []
    profile_cache = {}

    tx_id = program.startTransaction("Apply [AI] undefine")
    try:
        for item in data["functions"]:
            try:
                result = apply_one(program, item, logger, new_records,
                                   profile_cache, default_platform, max_bytes)
            except Exception:
                result = "error"
                logger.log(u"ERROR: 想定外の例外。")
                logger.log(traceback.format_exc())
            if result is None:
                continue
            if result == "applied":
                logger.applied += 1
            elif result == "skipped":
                logger.skipped += 1
            elif result == "rejected":
                logger.rejected += 1
            else:
                logger.errors += 1
    finally:
        program.endTransaction(tx_id, logger.applied > 0)

    if logger.applied > 0:
        try:
            merged = merge_record(existing_record, new_records, program)
            write_json(record_path, merged)
            logger.log(u"record written: {0} (total={1})".format(record_path, len(merged["defined"])))
        except Exception:
            logger.log(u"WARNING: 台帳の書き込みに失敗。revert 記録が残りません。")
            logger.log(traceback.format_exc())

    logger.log(u"=== apply_undefine 完了 ===")
    logger.log(u"applied={0} skipped={1} rejected={2} errors={3}".format(
        logger.applied, logger.skipped, logger.rejected, logger.errors))
    logger.log(u"※ 保存していません。確認後 Ctrl+S。取り消すなら revert_operations.py に {0} を渡す。".format(
        RECORD_NAME))


run()
