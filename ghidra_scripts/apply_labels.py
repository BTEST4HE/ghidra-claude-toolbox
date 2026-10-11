# -*- coding: utf-8 -*-
# Ghidra Claude Toolbox - apply_labels.py
#
# Ghidra GUI (Script Manager) から手動実行するスクリプトです。
# proposals/proposed_labels.json を読み込み、データテーブル等のアドレスに
# ラベル (シンボル名) を付けます。付けた内容は共有台帳 defined_functions.json に
# 記録し、revert_operations.py で巻き戻せるようにします。
#
# 本スクリプトは Ghidra 上の Jython (Python 2.7 互換) で動作します。
#
# ★ラベル付けは実質リネームなので、他の apply より厳しく縛っています:
#
#   1. **opt-in 必須**: bridge_config.json の allowed_apply_operations に
#      "labels" が無ければ、何もせず終了します (既定禁止)。
#   2. **既存の名前を上書きしない**のが既定。既に自動生成でないシンボルが
#      付いているアドレスは SKIP。item の force=true のときだけリネームします。
#   3. **関数エントリには付けません** (force でも拒否)。関数名の自動変更は
#      常に禁止のため、ラベル経由での実質リネームも塞いでいます。
#   4. address_basis が "ghidra" または未指定のものだけ処理します。
#   5. 名前は英数字 / _ / ひらがな / カタカナ / 漢字 / 長音符 / 中黒 のみ
#      (先頭は英字 / _ / かな / 漢字)。**空白・記号・全角英数は不可**。
#      Ghidra 自動生成名の接頭辞 (FUN_ / LAB_ / DAT_ …) は拒否します。
#   6. 反映件数が 0 のトランザクションはコミットしません。
#   7. このスクリプトは Program を保存しません (人間が確認して Ctrl+S)。
#
#@category ClaudeToolbox
#@menupath Tools.ClaudeToolbox.Apply Labels
#@runtime Jython

from __future__ import print_function

import codecs
import json
import os
import re
import traceback


SAFE_ADDRESS_BASIS = ("ghidra", "", None)
RECORD_NAME = "defined_functions.json"   # 共有台帳 (define/undefine/label 混在)
LABEL_OPERATION = "set_label"
REQUIRED_APPLY_OPERATION = "labels"

MAX_NAME_LENGTH = 128
# 名前には日本語 (ひらがな / カタカナ / 漢字) も使えます (Ghidra はシンボル名に
#   Unicode を許す)。ただし **空白・記号・全角英数は入れません** (Ghidra の検索や
#   スクリプトで扱いづらいため)。全角英数は半角へ、空白は _ へ寄せる
#   正規化を MCP 側 (find_text / decode_text の as_proposal) が行います。
#   許すのは: 英数字 / _ / ひらがな / カタカナ / 漢字 / 長音符 / 中黒
#   先頭に数字・長音符・中黒は置けません。
#   ※ この文字クラスは 3 か所 (apply_labels.py / validate_proposed_labels.py /
#      schemas/proposed_labels.schema.json) に同じものがあります。片方だけ直すと
#      「検証は通るのに反映で弾かれる」になるので **まとめて直すこと。**
NAME_RE = re.compile(u"^[A-Za-z_\u3041-\u3096\u30A1-\u30FA\u4E00-\u9FFF][A-Za-z_\u3041-\u3096\u30A1-\u30FA\u4E00-\u9FFF0-9\u30FC\u30FB]*$", re.UNICODE)
RESERVED_PREFIXES = ("FUN_", "LAB_", "DAT_", "SUB_", "UNK_", "EXT_",
                     "switchD_", "caseD_", "PTR_", "ARRAY_")


class ApplyLogger(object):
    """apply 処理の進捗と件数を記録するロガーです。"""

    def __init__(self):
        """ログ行と件数カウンタを初期化します。"""
        self.lines = []
        self.applied = 0
        self.skipped = 0
        self.rejected = 0
        self.errors = 0

    def log(self, message):
        """1 行ログを記録し、Ghidra コンソールにも出力します。"""
        text = u"{0}".format(message)
        self.lines.append(text)
        try:
            println(text)
        except Exception:
            print(text)


def read_json(path):
    """JSON を UTF-8 で読み込みます。"""
    f = codecs.open(path, "r", "utf-8")
    try:
        return json.load(f)
    finally:
        f.close()


def write_json(path, obj):
    """オブジェクトを UTF-8 JSON として書き出します。"""
    f = codecs.open(path, "w", "utf-8")
    try:
        f.write(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False))
        f.write(u"\n")
    finally:
        f.close()


def load_existing_record(path):
    """共有台帳を読み込みます。無い/壊れている場合は空の台帳を返します。"""
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
    """入力 JSON の近傍 (同階層〜2 つ上) から bridge_config.json を探して返します。

    見つからなければ (None, None) を返します。ラベル付けは opt-in 必須なので、
    「設定が無い」と「設定はあるが labels が無い」を呼び出し側で区別できるように
    (config, path) のタプルで返します。
    """
    d = os.path.dirname(in_path)
    candidates = [
        os.path.join(d, "bridge_config.json"),
        os.path.join(os.path.dirname(d), "bridge_config.json"),
        os.path.join(os.path.dirname(os.path.dirname(d)), "bridge_config.json"),
    ]
    for cfg_path in candidates:
        if os.path.isfile(cfg_path):
            try:
                return (read_json(cfg_path), cfg_path)
            except Exception:
                logger.log(u"WARNING: bridge_config.json の読み込みに失敗: {0}".format(cfg_path))
                return (None, cfg_path)
    return (None, None)


def labels_allowed(cfg):
    """bridge_config の allowed_apply_operations に "labels" があるかを返します。"""
    if not isinstance(cfg, dict):
        return False
    allowed = cfg.get("allowed_apply_operations")
    if not isinstance(allowed, (list, tuple)):
        return False
    for op in allowed:
        try:
            if u"{0}".format(op).strip().lower() == REQUIRED_APPLY_OPERATION:
                return True
        except Exception:
            continue
    return False


def addr_str(address):
    """Ghidra Address を 0x 付き 16 進文字列に変換します。"""
    return u"0x{0}".format(address.toString())


def name_problem(name):
    """ラベル名の問題点を文字列で返します。問題なければ None。"""
    if not name:
        return "empty"
    try:
        name = u"{0}".format(name)
    except Exception:
        return "not_a_string"
    if len(name) > MAX_NAME_LENGTH:
        return "too_long({0})".format(len(name))
    if NAME_RE.match(name) is None:
        return "invalid_chars"
    for reserved in RESERVED_PREFIXES:
        if name.startswith(reserved):
            return "reserved_prefix({0})".format(reserved)
    return None


def source_name(symbol):
    """シンボルの SourceType 名を文字列で返します。取れなければ "unknown"。"""
    try:
        return u"{0}".format(symbol.getSource().toString())
    except Exception:
        return u"unknown"


def existing_symbol_info(program, addr):
    """指定アドレスの主シンボル情報を返します。

    戻り値: (symbol, is_auto_generated)。symbol が None なら何も付いていません。
    is_auto_generated が True なら Ghidra の自動名 (LAB_ / DAT_ 等) なので、
    上書きしても人間の成果を壊しません。
    """
    try:
        symbol = program.getSymbolTable().getPrimarySymbol(addr)
    except Exception:
        return (None, True)
    if symbol is None:
        return (None, True)
    try:
        if bool(symbol.isDynamic()):
            # 動的シンボル (LAB_xxxx / DAT_xxxx) は実体を持たない自動名。
            return (symbol, True)
    except Exception:
        pass
    try:
        from ghidra.program.model.symbol import SourceType
        if symbol.getSource() == SourceType.DEFAULT:
            return (symbol, True)
    except Exception:
        pass
    return (symbol, False)


def apply_one(program, item, logger, new_records):
    """1 件のラベル案を反映します。戻り値は applied/skipped/rejected のいずれか。"""
    addr_text = item.get("address")
    operation = item.get("operation", LABEL_OPERATION)
    if operation != LABEL_OPERATION:
        logger.log(u"SKIP (operation={0} は未対応): {1}".format(operation, addr_text))
        return "skipped"

    basis = item.get("address_basis")
    if basis not in SAFE_ADDRESS_BASIS:
        logger.log(u"SKIP (address_basis={0}): {1}".format(basis, addr_text))
        return "skipped"

    name = item.get("name")
    problem = name_problem(name)
    if problem is not None:
        logger.log(u"REJECT (name {0}): {1} name={2}".format(problem, addr_text, name))
        return "rejected"

    try:
        addr = program.getAddressFactory().getAddress(str(addr_text))
    except Exception:
        addr = None
    if addr is None:
        logger.log(u"SKIP (invalid address): {0}".format(addr_text))
        return "skipped"
    if not program.getMemory().contains(addr):
        logger.log(u"SKIP (not in memory): {0}".format(addr_text))
        return "skipped"

    # ★関数エントリへのラベル付けは force でも拒否する。
    #   関数名の自動変更 (リネーム) は常に禁止で、ラベル経由の実質リネームも塞ぐ。
    try:
        func = getFunctionAt(addr)
    except Exception:
        func = None
    if func is not None:
        logger.log(u"REJECT (関数エントリなので不可 — 関数名の自動変更は常に禁止): "
                   u"{0} func={1}".format(addr_text, func.getName()))
        return "rejected"

    force = bool(item.get("force", False))
    symbol, auto_generated = existing_symbol_info(program, addr)
    previous_name = None
    previous_source = None

    if symbol is not None and not auto_generated:
        previous_name = u"{0}".format(symbol.getName())
        previous_source = source_name(symbol)
        if previous_name == name:
            logger.log(u"SKIP (既に同じ名前): {0} name={1}".format(addr_text, name))
            return "skipped"
        if not force:
            logger.log(u"SKIP (既存の名前を上書きしない — force 未指定): "
                       u"{0} existing={1} ({2})".format(
                           addr_text, previous_name, previous_source))
            return "skipped"

    try:
        from ghidra.program.model.symbol import SourceType
    except Exception:
        logger.log(u"REJECT (SourceType を import できません): {0}".format(addr_text))
        return "rejected"

    created = True
    try:
        if previous_name is not None:
            # force 指定で既存シンボルをリネームする。
            symbol.setName(name, SourceType.USER_DEFINED)
            created = False
            new_symbol = symbol
        else:
            new_symbol = program.getSymbolTable().createLabel(
                addr, name, SourceType.USER_DEFINED)
            if new_symbol is None:
                logger.log(u"REJECT (createLabel が None): {0}".format(addr_text))
                return "rejected"
        try:
            new_symbol.setPrimary()
        except Exception:
            # 主シンボルにできなくてもラベル自体は付いているので続行する。
            logger.log(u"WARN (setPrimary 失敗、ラベルは付与済み): {0}".format(addr_text))
    except Exception:
        logger.log(u"REJECT (ラベル設定で例外): {0} name={1}".format(addr_text, name))
        logger.log(traceback.format_exc())
        return "rejected"

    new_records.append({
        "operation": LABEL_OPERATION,
        "entry": addr_str(addr),
        "name": name,
        "previous_name": previous_name,
        "previous_source": previous_source,
        "created": created,
        "forced": force,
    })
    if created:
        logger.log(u"LABEL: {0} -> {1}".format(addr_text, name))
    else:
        logger.log(u"RENAME (force): {0} {1} -> {2}".format(
            addr_text, previous_name, name))
    return "applied"


def merge_record(existing, new_records, program):
    """共有台帳へ label 記録をマージします。

    キーは (operation, entry) です。同じアドレスに define_function 記録と
    set_label 記録が併存できるようにするため、entry だけでキーにしません
    (apply_undefine.py と同じ方式)。
    """
    by_key = {}
    for d in existing.get("defined", []):
        key = (d.get("operation", "define_function"), (d.get("entry") or "").lower())
        by_key[key] = d
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
    """apply 処理全体のエントリポイントです。"""
    logger = ApplyLogger()

    program = currentProgram
    if program is None:
        printerr(u"currentProgram がありません。Ghidra で対象を開いてから実行してください。")
        return

    in_file = askFile("Select proposed_labels.json", "Open")
    in_path = in_file.getAbsolutePath()

    logger.log(u"=== Ghidra Claude Toolbox apply_labels ===")
    logger.log(u"input: {0}".format(in_path))

    # ★opt-in ゲート。ラベル付けは実質リネームなので、明示許可が無ければ何もしない。
    cfg, cfg_path = load_bridge_config(in_path, logger)
    if cfg is None:
        printerr(u"bridge_config.json が見つかりません ({0} の近傍を探しました)。\n"
                 u"ラベル付けは opt-in 機能です。bridge_config.json の "
                 u"allowed_apply_operations に \"labels\" を追加してください。".format(
                     os.path.dirname(in_path)))
        return
    if not labels_allowed(cfg):
        printerr(u"ラベル付けは許可されていません。何も変更していません。\n"
                 u"  bridge_config: {0}\n"
                 u"  allowed_apply_operations: {1}\n"
                 u"許可するには allowed_apply_operations に \"labels\" を追加してください "
                 u"(ラベル付けは実質リネームなので既定では禁止です)。".format(
                     cfg_path, cfg.get("allowed_apply_operations")))
        return
    logger.log(u"opt-in 確認 OK: allowed_apply_operations に \"labels\" があります ({0})".format(
        cfg_path))

    try:
        data = read_json(in_path)
    except Exception:
        printerr(u"JSON として読み込めませんでした: {0}".format(in_path))
        return
    if not isinstance(data.get("labels"), list):
        printerr(u"labels 配列がありません。schemas/proposed_labels.schema.json を確認してください。")
        return

    # ★対象 Program の照合 (不一致・欠落なら変更前に中止。警告だけで続行しない)。
    problem = gate_target_program(data, program, u"提案 JSON")
    if problem:
        printerr(u"対象 Program を確認できないので中止しました。何も変更していません。\n  "
                 + problem + u"\n" + u"  提案 / 台帳の target_program を、いま開いている Program の名前と照合します。\n  正しい Program を開いているか確かめ、提案を作り直すか、確認のうえで\n  target_program に Program 名を書いてください (docs/safety_rules.md「対象 Program の照合」)。")
        return

    record_path = os.path.join(os.path.dirname(in_path), RECORD_NAME)
    # ★共有台帳の確認 (壊れている / 別 Program 用なら、上書きせず変更前に中止)。
    existing_record, problem = gate_ledger(record_path, program)
    if problem:
        printerr(u"台帳を確認できないので中止しました。何も変更していません。\n  "
                 + problem + u"\n" + u"  提案 / 台帳の target_program を、いま開いている Program の名前と照合します。\n  正しい Program を開いているか確かめ、提案を作り直すか、確認のうえで\n  target_program に Program 名を書いてください (docs/safety_rules.md「対象 Program の照合」)。")
        return
    new_records = []

    tx_id = program.startTransaction("Apply [AI] labels")
    try:
        for item in data["labels"]:
            try:
                result = apply_one(program, item, logger, new_records)
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
        # 反映が 0 件のトランザクションはコミットしない。
        program.endTransaction(tx_id, logger.applied > 0)

    if logger.applied > 0:
        try:
            merged = merge_record(existing_record, new_records, program)
            write_json(record_path, merged)
            logger.log(u"record written: {0} (total records={1})".format(
                record_path, len(merged["defined"])))
        except Exception:
            logger.log(u"WARNING: 台帳の書き込みに失敗しました。revert 用の記録が残りません。")
            logger.log(traceback.format_exc())

    logger.log(u"=== apply 完了 ===")
    logger.log(u"applied={0} skipped={1} rejected={2} errors={3}".format(
        logger.applied, logger.skipped, logger.rejected, logger.errors))
    logger.log(u"※ 保存はしていません。Listing でラベルを確認し、問題なければ Ctrl+S。"
               u"取り消すなら revert_operations.py に {0} を渡してください。".format(RECORD_NAME))


run()
