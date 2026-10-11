# -*- coding: utf-8 -*-
# Ghidra Claude Toolbox - apply_functions.py
#
# Ghidra GUI (Script Manager) から手動実行するスクリプトです。
# proposals/proposed_functions.json を読み込み、未定義コードのエントリを
# 「関数化 (Create Function)」します。必要なら先に Disassemble します。
# 作成した関数を検証し、検証を通ったものだけ defined_functions.json に
# 記録します (revert_functions.py が後で正確に巻き戻すための台帳)。
#
# 本スクリプトは Ghidra 上の Jython (Python 2.7 互換) で動作します。
#
# マルチプラットフォーム対応 (PS1/GBA/Wii/SH4 等):
#   - return 検出は FlowType.isTerminal() を使う (アーキ非依存)。
#   - アーキ固有値は platform_profiles/<name>.json に置く。bridge_config.json の
#     "platform_profile" (or proposal の platform) で選ぶ。
#   - GBA など mode を持つアーキは、未定義領域の関数化に mode (arm/thumb) を必須に
#     する (誤モードでデータが命令に化けるため)。mode 未指定は拒否。ただし既に
#     関数の一部 or 既存コンテキストが確定している場合は省略可。
#
# 安全ルール:
#   - 反映対象は「関数化」のみ。リネーム・型変更・配列化はしません (既定名のまま)。
#   - 既に関数の一部のアドレスは触りません (人間の定義を尊重)。
#   - address_basis が "ghidra" または未指定のものだけ処理します。
#   - 検証 (命令数>0 / サイズ上限以下) に通らない関数は即座に巻き戻します。
#   - 自分が作成した関数だけを defined_functions.json に記録します。
#   - このスクリプトは Program を保存しません。
#
#@category ClaudeToolbox
#@menupath Tools.ClaudeToolbox.Apply Functions
#@runtime Jython

from __future__ import print_function

import codecs
import json
import os
import traceback


SAFE_ADDRESS_BASIS = ("ghidra", "", None)
VERIFY_MAX_BYTES = 0x4000
RECORD_NAME = "defined_functions.json"

# platform_profiles/ が見つからない時の最終フォールバック。
BUILTIN_PROFILES = {
    "gba": {"name": "gba", "mode_required": True, "context_register": "TMode",
            "mode_values": {"arm": 0, "thumb": 1}, "modes": ["arm", "thumb"]},
    "sh4": {"name": "sh4", "mode_required": False},
    "psx": {"name": "psx", "mode_required": False},
    "wii": {"name": "wii", "mode_required": False},
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


def load_bridge_config(in_path, logger):
    """入力 JSON の近傍 (同階層〜2 つ上) から bridge_config.json を探して返します。"""
    d = os.path.dirname(in_path)
    candidates = [
        os.path.join(d, "bridge_config.json"),
        os.path.join(os.path.dirname(d), "bridge_config.json"),
        os.path.join(os.path.dirname(os.path.dirname(d)), "bridge_config.json"),
    ]
    for cfg in candidates:
        if os.path.isfile(cfg):
            try:
                return read_json(cfg)
            except Exception:
                logger.log(u"WARNING: bridge_config.json の読み込みに失敗: {0}".format(cfg))
                return {}
    return {}


def toolbox_root():
    """このスクリプト (ghidra_scripts/apply_functions.py) からツール箱ルートを推定します。"""
    try:
        path = getSourceFile().getAbsolutePath()
        return os.path.dirname(os.path.dirname(path))
    except Exception:
        return None


def load_platform_profile(name, logger):
    """platform_profiles/<name>.json を読み、無ければ内蔵フォールバックを返します。"""
    if not name:
        return {}
    root = toolbox_root()
    if root is not None:
        path = os.path.join(root, "platform_profiles", str(name) + ".json")
        if os.path.isfile(path):
            try:
                return read_json(path)
            except Exception:
                logger.log(u"WARNING: profile 読み込み失敗 ({0})。内蔵値にフォールバック。".format(path))
    builtin = BUILTIN_PROFILES.get(str(name))
    if builtin is not None:
        logger.log(u"profile '{0}': 内蔵フォールバックを使用。".format(name))
        return dict(builtin)
    logger.log(u"profile '{0}' が見つかりません。mode 非対応として扱います。".format(name))
    return {}


def addr_str(address):
    return u"0x{0}".format(address.toString())


def item_addr(item):
    return item.get("address") or item.get("entry")


def context_is_set(program, addr, profile):
    """mode 持ちアーキで、対象アドレスのコンテキスト (例 TMode) が既に確定しているか。"""
    reg_name = profile.get("context_register")
    if not reg_name:
        return True
    try:
        pc = program.getProgramContext()
        reg = pc.getRegister(reg_name)
        if reg is None:
            return False
        return pc.getValue(reg, addr, False) is not None
    except Exception:
        return False


def set_mode(program, addr, mode, profile, logger):
    """profile に従ってモードコンテキスト (例 TMode=thumb) を設定します。成功で True。"""
    reg_name = profile.get("context_register")
    if not reg_name or mode is None:
        return True
    mode_values = profile.get("mode_values", {})
    if mode not in mode_values:
        logger.log(u"WARN: profile に mode '{0}' の値がありません。".format(mode))
        return False
    try:
        from java.math import BigInteger
        pc = program.getProgramContext()
        reg = pc.getRegister(reg_name)
        if reg is None:
            logger.log(u"WARN: context register '{0}' が見つかりません。".format(reg_name))
            return False
        pc.setValue(reg, addr, addr, BigInteger.valueOf(int(mode_values[mode])))
        return True
    except Exception:
        logger.log(u"WARN: モードコンテキスト設定に失敗 ({0}={1})。".format(reg_name, mode))
        return False


def verify_function(program, func):
    """作成した関数を検証 (アーキ非依存)。FlowType.isTerminal() で return を判定。"""
    body = func.getBody()
    try:
        byte_size = int(body.getNumAddresses())
    except Exception:
        byte_size = None

    listing = program.getListing()
    instr_count = 0
    last_mnemonic = None
    has_return = False
    try:
        it = listing.getInstructions(body, True)
        for ins in it:
            instr_count += 1
            try:
                last_mnemonic = ins.getMnemonicString()
            except Exception:
                pass
            try:
                ft = ins.getFlowType()
                if ft is not None and ft.isTerminal():
                    has_return = True
            except Exception:
                pass
    except Exception:
        pass

    reasons = []
    ok = True
    if instr_count == 0:
        ok = False
        reasons.append("no_instructions")
    if byte_size is not None and byte_size > VERIFY_MAX_BYTES:
        ok = False
        reasons.append("too_large({0})".format(byte_size))

    return {
        "ok": ok,
        "reasons": reasons,
        "instr_count": instr_count,
        "byte_size": byte_size,
        "has_return": has_return,
        "last_mnemonic": last_mnemonic,
    }


def apply_one(program, item, logger, new_defined, default_platform, profile_cache):
    entry_s = item_addr(item)
    operation = item.get("operation", "define_function")
    if operation != "define_function":
        logger.log(u"SKIP (operation={0} は未対応): {1}".format(operation, entry_s))
        return "skipped"

    basis = item.get("address_basis")
    if basis not in SAFE_ADDRESS_BASIS:
        logger.log(u"SKIP (address_basis={0}): {1}".format(basis, entry_s))
        return "skipped"

    try:
        addr = program.getAddressFactory().getAddress(str(entry_s))
    except Exception:
        addr = None
    if addr is None:
        logger.log(u"SKIP (invalid address): {0}".format(entry_s))
        return "skipped"
    if not program.getMemory().contains(addr):
        logger.log(u"SKIP (not in memory): {0}".format(entry_s))
        return "skipped"

    existing = getFunctionContaining(addr)
    if existing is not None:
        logger.log(u"SKIP (already in function {0}): {1}".format(existing.getName(), entry_s))
        return "skipped"

    # --- プラットフォーム/モード処理 ---
    platform = item.get("platform") or default_platform
    if platform not in profile_cache:
        profile_cache[platform] = load_platform_profile(platform, logger)
    profile = profile_cache.get(platform, {})
    mode = item.get("mode")
    mode_required = bool(profile.get("mode_required", False))

    if mode_required:
        if mode is None:
            # 既存コンテキストが確定しているなら省略可。そうでなければ拒否。
            if context_is_set(program, addr, profile):
                logger.log(u"INFO (mode 省略だが既存コンテキスト確定): {0}".format(entry_s))
            else:
                logger.log(u"REJECT (mode required for platform={0}, mode 未指定): {1}".format(
                    platform, entry_s))
                return "rejected"
        else:
            if not set_mode(program, addr, mode, profile, logger):
                logger.log(u"REJECT (mode 設定失敗 mode={0}): {1}".format(mode, entry_s))
                return "rejected"

    # --- 逆アセンブル (必要時) → 関数化 ---
    disassembled = False
    if getInstructionAt(addr) is None:
        ok = False
        try:
            ok = bool(disassemble(addr))
        except Exception:
            ok = False
        disassembled = True
        if not ok or getInstructionAt(addr) is None:
            logger.log(u"REJECT (disassemble failed): {0}".format(entry_s))
            try:
                clearListing(addr)
            except Exception:
                pass
            return "rejected"

    func = None
    try:
        func = createFunction(addr, None)
    except Exception:
        func = None
    if func is None:
        logger.log(u"REJECT (createFunction failed): {0}".format(entry_s))
        if disassembled:
            try:
                clearListing(addr)
            except Exception:
                pass
        return "rejected"

    v = verify_function(program, func)
    body = func.getBody()
    bmin = body.getMinAddress()
    bmax = body.getMaxAddress()

    if not v["ok"]:
        logger.log(u"REJECT (verify: {0}): {1}".format(u",".join(v["reasons"]), entry_s))
        try:
            removeFunction(func)
        except Exception:
            pass
        if disassembled:
            try:
                clearListing(bmin, bmax)
            except Exception:
                pass
        return "rejected"

    new_defined.append({
        "operation": "define_function",
        "entry": addr_str(addr),
        "name": func.getName(),
        "platform": platform,
        "mode": mode,
        "body_min": addr_str(bmin),
        "body_max": addr_str(bmax),
        "disassembled": disassembled,
        "verify": v,
    })
    warn = u"" if v["has_return"] else u"  (WARN: no terminal/return — 疑似C を要確認)"
    logger.log(u"DEFINE: {0} name={1} instr={2} size={3} ret={4} mode={5}{6}".format(
        entry_s, func.getName(), v["instr_count"], v["byte_size"], v["has_return"], mode, warn))
    return "applied"


def merge_record(existing, new_defined, program):
    """共有台帳へ define 記録をマージします。

    キーは (operation, entry) です。同じアドレスに undefine_function 記録や
    set_label 記録が併存できるようにするため、entry だけでキーにしません
    (apply_undefine.py / apply_labels.py と同じ方式)。
    """
    by_key = {}
    for d in existing.get("defined", []):
        entry = d.get("entry")
        if entry:
            by_key[(d.get("operation", "define_function"), entry.lower())] = d
    for d in new_defined:
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

    in_file = askFile("Select proposed_functions.json", "Open")
    in_path = in_file.getAbsolutePath()

    logger.log(u"=== Ghidra Claude Toolbox apply_functions ===")
    logger.log(u"input: {0}".format(in_path))

    # ★opt-in ゲート。関数化 (functions) は既定で禁止。許可が無ければ何も変更せず終了する
    #   (Script Manager から手動で実行したことや、JSON を選んだことは許可の代わりにしない)。
    problem = gate_operation_allowed(in_path, "functions")
    if problem:
        printerr(u"関数化 (functions) は許可されていません。何も変更していません。\n  " + problem)
        return
    logger.log(u"opt-in 確認 OK: allowed_apply_operations に \"functions\" があります")

    try:
        data = read_json(in_path)
    except Exception:
        printerr(u"JSON として読み込めませんでした: {0}".format(in_path))
        return
    if not isinstance(data.get("functions"), list):
        printerr(u"functions 配列がありません。スキーマを確認してください。")
        return

    # ★対象 Program の照合 (不一致・欠落なら変更前に中止。警告だけで続行しない)。
    problem = gate_target_program(data, program, u"提案 JSON")
    if problem:
        printerr(u"対象 Program を確認できないので中止しました。何も変更していません。\n  "
                 + problem + u"\n" + u"  提案 / 台帳の target_program を、いま開いている Program の名前と照合します。\n  正しい Program を開いているか確かめ、提案を作り直すか、確認のうえで\n  target_program に Program 名を書いてください (docs/safety_rules.md「対象 Program の照合」)。")
        return

    cfg = load_bridge_config(in_path, logger)
    default_platform = data.get("platform") or cfg.get("platform_profile")
    if default_platform:
        logger.log(u"platform (default): {0}".format(default_platform))
    profile_cache = {}

    record_path = os.path.join(os.path.dirname(in_path), RECORD_NAME)
    # ★共有台帳の確認 (壊れている / 別 Program 用なら、上書きせず変更前に中止)。
    existing_record, problem = gate_ledger(record_path, program)
    if problem:
        printerr(u"台帳を確認できないので中止しました。何も変更していません。\n  "
                 + problem + u"\n" + u"  提案 / 台帳の target_program を、いま開いている Program の名前と照合します。\n  正しい Program を開いているか確かめ、提案を作り直すか、確認のうえで\n  target_program に Program 名を書いてください (docs/safety_rules.md「対象 Program の照合」)。")
        return
    new_defined = []

    tx_id = program.startTransaction("Apply [AI] function definitions")
    try:
        for item in data["functions"]:
            try:
                result = apply_one(program, item, logger, new_defined,
                                   default_platform, profile_cache)
            except Exception:
                result = "error"
                logger.log(u"ERROR: 想定外の例外が発生しました。")
                logger.log(traceback.format_exc())
            if result == "applied":
                logger.applied += 1
            elif result == "skipped":
                logger.skipped += 1
            elif result == "rejected":
                logger.rejected += 1
            else:
                logger.errors += 1
    finally:
        commit = logger.applied > 0
        program.endTransaction(tx_id, commit)

    if logger.applied > 0:
        try:
            merged = merge_record(existing_record, new_defined, program)
            write_json(record_path, merged)
            logger.log(u"record written: {0} (total defined={1})".format(
                record_path, len(merged["defined"])))
        except Exception:
            logger.log(u"WARNING: 台帳の書き込みに失敗しました。revert 用の記録が残りません。")
            logger.log(traceback.format_exc())

    logger.log(u"=== apply 完了 ===")
    logger.log(u"applied={0} skipped={1} rejected={2} errors={3}".format(
        logger.applied, logger.skipped, logger.rejected, logger.errors))
    logger.log(u"※ 保存はしていません。疑似C を確認し、問題なければ Ctrl+S。"
               u"取り消すなら revert_operations.py に {0} を渡してください。".format(RECORD_NAME))


run()
