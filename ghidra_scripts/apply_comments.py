# -*- coding: utf-8 -*-
# Ghidra Claude Toolbox - apply_comments.py
#
# Ghidra GUI (Script Manager) から手動実行するスクリプトです。
# proposals/proposed_comments.json を読み込み、currentProgram へ
# [AI] コメントだけを安全に反映します。
#
# 本スクリプトは Ghidra 上の Jython (Python 2.7 互換) で動作します。
#
# 安全ルール:
#   - 反映対象はコメントのみ (ラベル/関数/型/配列化は一切行いません)。
#   - コメント文は必ず "[AI]" で始まるものだけ許可します。
#   - 既存の人間コメントは削除しません (追記またはスキップのみ)。
#   - 同一の [AI] コメントが既にある場合は重複させません。
#   - 無効なアドレス・不明なコメント種別・文字列でない address/type/comment は
#     スキップしてログに残します。
#   - address_basis が "ghidra" または未指定のものだけ反映します。
#     "runtime" / "dump_offset" などは Ghidra address ではない可能性が
#     あるため、安全のためスキップしてログに残します。
#
#@category ClaudeToolbox
#@menupath Tools.ClaudeToolbox.Apply Comments
#@runtime Jython

from __future__ import print_function

import codecs
import json
import os
import traceback

from ghidra.program.model.listing import CodeUnit


# 道具箱で使うコメント種別名と Ghidra の CodeUnit 定数の対応表です。
NAME_TO_COMMENT_TYPE = {
    "eol": CodeUnit.EOL_COMMENT,
    "pre": CodeUnit.PRE_COMMENT,
    "post": CodeUnit.POST_COMMENT,
    "plate": CodeUnit.PLATE_COMMENT,
    "repeatable": CodeUnit.REPEATABLE_COMMENT,
}

# Ghidra address として安全に扱える address_basis です。
SAFE_ADDRESS_BASIS = ("ghidra", "", None)

# address / type / comment に許す型です (Jython では str と unicode の両方)。
try:
    TEXT_TYPES = (basestring,)   # noqa: F821 (Jython / Python 2.7)
except NameError:                # Python 3 (オフライン検証)
    TEXT_TYPES = (str,)


class ApplyLogger(object):
    """apply 処理のログを画面に出しつつ集計するロガーです。"""

    def __init__(self):
        """ログ行と集計カウンタを初期化します。"""
        self.lines = []
        self.applied = 0
        self.skipped = 0
        self.errors = 0

    def log(self, message):
        """1 行ログを記録し、Ghidra コンソールにも出力します。"""
        text = u"{0}".format(message)
        self.lines.append(text)
        try:
            println(text)
        except Exception:
            print(text)


def load_proposals(path, logger):
    """proposed_comments.json を UTF-8 で読み込み、辞書として返します。"""
    import codecs
    try:
        f = codecs.open(path, "r", "utf-8")
        try:
            data = json.load(f)
        finally:
            f.close()
    except ValueError:
        raise RuntimeError(u"JSON として読み込めませんでした: {0}".format(path))
    except Exception:
        raise RuntimeError(u"ファイルを開けませんでした: {0}".format(path))
    if "comments" not in data or not isinstance(data["comments"], list):
        raise RuntimeError(u"comments 配列がありません。スキーマを確認してください。")
    return data


def comment_already_contains(existing, new_text):
    """既存コメント内に、新しい [AI] コメント行が既に含まれているか判定します。"""
    if existing is None:
        return False
    existing_lines = [l.strip() for l in existing.split(u"\n")]
    return new_text.strip() in existing_lines


def merge_comment(existing, new_text):
    """既存コメントを残したまま新コメントを追記した文字列を返します。"""
    if existing is None or existing == u"":
        return new_text
    return existing + u"\n" + new_text


def apply_one(program, item, logger):
    """コメント案 1 件を検証し、安全なら反映します。結果種別を文字列で返します。

    戻り値: "applied" / "skipped" / "error" のいずれか。
    """
    address_str = item.get("address")
    ctype_name = item.get("type")
    comment = item.get("comment")
    basis = item.get("address_basis")

    # address / type / comment が文字列でなければ、Ghidra へ渡す前にスキップします
    # (数値を str() で番地に読み替えると、別の番地に書いてしまうため)。
    for key, value in ((u"address", address_str), (u"type", ctype_name), (u"comment", comment)):
        if not isinstance(value, TEXT_TYPES):
            logger.log(u"SKIP ({0} が文字列でない: {1}): {2}".format(
                key, type(value).__name__, repr(address_str)))
            return "skipped"

    # address_basis が ghidra/未指定でなければスキップします。
    if basis not in SAFE_ADDRESS_BASIS:
        logger.log(u"SKIP (address_basis={0}): Ghidra address ではない可能性があるため反映しません: {1}".format(
            basis, address_str))
        return "skipped"

    if not comment or not comment.lstrip().startswith(u"[AI]"):
        logger.log(u"SKIP (not [AI]): {0}".format(address_str))
        return "skipped"

    if ctype_name not in NAME_TO_COMMENT_TYPE:
        logger.log(u"SKIP (unknown type='{0}'): {1}".format(ctype_name, address_str))
        return "skipped"

    # アドレスを解釈します。失敗したらスキップ扱いです。
    try:
        address = program.getAddressFactory().getAddress(str(address_str))
    except Exception:
        address = None
    if address is None:
        logger.log(u"SKIP (invalid address): {0}".format(address_str))
        return "skipped"

    ctype = NAME_TO_COMMENT_TYPE[ctype_name]
    listing = program.getListing()

    try:
        existing = listing.getComment(ctype, address)
        # 同一の [AI] コメントが既にあれば重複させずスキップします。
        if comment_already_contains(existing, comment):
            logger.log(u"SKIP (duplicate): {0} [{1}]".format(address_str, ctype_name))
            return "skipped"
        merged = merge_comment(existing, comment)
        listing.setComment(address, ctype, merged)
        action = u"APPEND" if existing else u"ADD"
        logger.log(u"{0}: {1} [{2}] {3}".format(action, address_str, ctype_name, comment))
        return "applied"
    except Exception:
        logger.log(u"ERROR: 反映に失敗: {0} [{1}]".format(address_str, ctype_name))
        logger.log(traceback.format_exc())
        return "error"


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
    """apply 処理全体のエントリポイントです。対象ファイルを選択して実行します。"""
    logger = ApplyLogger()

    program = currentProgram
    if program is None:
        printerr(u"currentProgram がありません。Ghidra で対象を開いてから実行してください。")
        return

    in_file = askFile("Select proposed_comments.json", "Open")
    in_path = in_file.getAbsolutePath()

    logger.log(u"=== Ghidra Claude Toolbox apply_comments ===")
    logger.log(u"input: {0}".format(in_path))

    try:
        data = load_proposals(in_path, logger)
    except RuntimeError as e:
        printerr(u"{0}".format(e))
        return

    # ★対象 Program の照合 (不一致・欠落なら変更前に中止。警告だけで続行しない)。
    problem = gate_target_program(data, program, u"提案 JSON")
    if problem:
        printerr(u"対象 Program を確認できないので中止しました。何も変更していません。\n  "
                 + problem + u"\n" + u"  提案 / 台帳の target_program を、いま開いている Program の名前と照合します。\n  正しい Program を開いているか確かめ、提案を作り直すか、確認のうえで\n  target_program に Program 名を書いてください (docs/safety_rules.md「対象 Program の照合」)。")
        return

    tx_id = program.startTransaction("Apply [AI] comments")
    try:
        for item in data["comments"]:
            try:
                result = apply_one(program, item, logger)
            except Exception:
                result = "error"
                logger.log(u"ERROR: 想定外の例外が発生しました。")
                logger.log(traceback.format_exc())
            if result == "applied":
                logger.applied += 1
            elif result == "skipped":
                logger.skipped += 1
            else:
                logger.errors += 1
    finally:
        # コメント反映があったときだけコミットします。
        commit = logger.applied > 0
        program.endTransaction(tx_id, commit)

    logger.log(u"=== apply 完了 ===")
    logger.log(u"applied={0} skipped={1} errors={2}".format(
        logger.applied, logger.skipped, logger.errors))


run()
