# -*- coding: utf-8 -*-
# Ghidra Claude Toolbox - apply_snes_context.py
#
# Ghidra GUI (Script Manager) から手動実行するスクリプトです。
# proposals/proposed_context.json を読み込み、65816 (ghidra-snes) の
# ダイレクトページ (D) / データバンク (DBR) の値を、指定範囲の
# 「レジスタの値 (Set Register Values と同じもの)」として設定します。
# 疑似 C の `in_DP + 0xbc` / `(uint3)in_DBR * 0x10000 + 0xdc9` を
# 定数の番地として読ませるのが目的です。
#
# 本スクリプトは Ghidra 上の Jython (Python 2.7 互換) で動作します。
#
# ★ghidra-snes の SLEIGH (data/languages/658xx.sinc) での定義
#   (Ghidra 11.3 / 12.0.4 用の拡張で同一):
#     define register offset=0x10 size=2 [ C X Y DP SP ];   # D は "DP" (16bit)
#     define register offset=0x20 size=1 [ DBR ];           # DBR は "DBR" (8bit)
#     define context contextreg ctx_MF=(0,0) ctx_XF=(1,1) ctx_EF=(3,3);
#   DP / DBR は**普通のレジスタ**で、コンテキスト (contextreg) ではありません。
#   したがって既存の命令があっても設定でき、逆アセンブルの結果は変わりません
#   (変わるのは decompiler が使う「その範囲での既知の値」だけ)。
#   ctx_MF / ctx_XF / ctx_EF は命令長を変えるので**このスクリプトでは扱いません**
#   (Mesen の CDL から ApplySnesTrace.java が書くもの)。
#   ※ "B" は SLEIGH ではアキュムレータの上位バイトです。DBR の別名として受けません。
#
# 安全ルール:
#   1. **opt-in 必須**: bridge_config.json の allowed_apply_operations に
#      "context" が無ければ、何もせず終了します (既定禁止)。
#   2. Program の言語が 65816 でなければ何もしません (他機種を巻き込まない)。
#   3. 設定できるのは DP / DBR だけ (別名 "D" -> DP)。値の幅も検査します。
#   4. 各 item に根拠 (evidence) が 1 件以上必須。confidence=low は反映しません。
#   5. 設定前の値 (明示設定されていた範囲と値) を共有台帳 defined_functions.json に
#      記録し、revert_operations.py で元へ戻せます。
#   6. address_basis が "ghidra" または未指定のものだけ処理します。
#   7. 反映件数が 0 のトランザクションはコミットしません。保存もしません。
#
#@category ClaudeToolbox
#@menupath Tools.ClaudeToolbox.Apply SNES Context (DP / DBR)
#@runtime Jython

from __future__ import print_function

import codecs
import json
import os
import traceback

try:
    long
except NameError:   # Python 3 で読み込むとき用
    long = int


SAFE_ADDRESS_BASIS = ("ghidra", "", None)
RECORD_NAME = "defined_functions.json"   # 共有台帳 (define/undefine/label/context 混在)
REQUIRED_APPLY_OPERATION = "context"
# 台帳の operation は「レジスタごとに別の名前」にする。他の apply スクリプトの
# merge_record は (operation, entry) をキーにするので、同じ開始番地に DP と DBR を
# 設定したとき片方が消えないようにするため。
OPERATION_PREFIX = "set_register_"

# 名前 -> (SLEIGH 上の正式名, ビット幅)。ここに無いものは一切設定しない。
ALLOWED_REGISTERS = {
    "DP": ("DP", 16),
    "D": ("DP", 16),
    "DBR": ("DBR", 8),
}
# 名前を間違えたときに理由を返すための表 (設定はしない)。
REFUSED_REGISTERS = {
    "CTX_MF": u"命令長を変えるコンテキスト。M/X/E は ApplySnesTrace.java (CDL) の担当です",
    "CTX_XF": u"命令長を変えるコンテキスト。M/X/E は ApplySnesTrace.java (CDL) の担当です",
    "CTX_EF": u"命令長を変えるコンテキスト。M/X/E は ApplySnesTrace.java (CDL) の担当です",
    "CONTEXTREG": u"コンテキストレジスタそのものは触りません",
    "PBR": u"PBR は PC のバンクそのもの (Ghidra は番地から決める) なので設定しません",
    "B": u"SLEIGH の B はアキュムレータの上位バイトです。データバンクは DBR と書いてください",
    "DB": u"データバンクは DBR と書いてください (ghidra-snes の名前)",
    "DPLOW": u"DP (16bit) を設定してください",
}


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
    """入力 JSON の近傍 (同階層〜2 つ上) から bridge_config.json を探して (config, path) を返します。"""
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


def context_allowed(cfg):
    """bridge_config の allowed_apply_operations に "context" があるかを返します。"""
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


def is_65816(program):
    """Program の言語が 65816 系かを返します (processor 名 / language id の両方を見る)。"""
    texts = []
    try:
        texts.append(u"{0}".format(program.getLanguage().getProcessor()))
    except Exception:
        pass
    try:
        texts.append(u"{0}".format(program.getLanguageID()))
    except Exception:
        pass
    for text in texts:
        if text.strip().startswith(u"65816"):
            return True
    return False


def parse_int(value):
    """'0x..' / '$..' / 10 進文字列 / int を int にします。読めなければ None。"""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, long)):
        return int(value)
    try:
        text = u"{0}".format(value).strip().replace(u"_", u"")
        if text.startswith(u"$"):
            return int(text[1:], 16)
        if text.lower().startswith(u"0x"):
            return int(text[2:], 16)
        return int(text, 10)
    except Exception:
        return None


def register_problem(name):
    """レジスタ名を検査します。戻り値: (正式名, ビット幅, None) または (None, None, 理由)。"""
    if not name:
        return (None, None, u"register が空です")
    key = u"{0}".format(name).strip().upper()
    if key in ALLOWED_REGISTERS:
        real, bits = ALLOWED_REGISTERS[key]
        return (real, bits, None)
    if key in REFUSED_REGISTERS:
        return (None, None, REFUSED_REGISTERS[key])
    return (None, None, u"{0} は設定できません (DP / DBR だけ)".format(name))


def evidence_problem(evidence):
    """根拠の配列を検査します。問題なければ None。"""
    if not isinstance(evidence, list) or not evidence:
        return u"evidence が無い (値の根拠は必須)"
    for ev in evidence:
        if isinstance(ev, dict):
            detail = ev.get("detail")
        else:
            detail = ev
        if not detail or not u"{0}".format(detail).strip():
            return u"evidence に中身の無い項目がある"
    return None


def addr_str(address):
    """Ghidra Address を 0x 付き 16 進文字列に変換します。"""
    return u"0x{0}".format(address.toString())


def current_ranges(context, register, start, end):
    """[start, end] の中で明示的に値が設定されている範囲と値の一覧を返します。

    戻り値: [{"start": "0x..", "end": "0x..", "value": int}, ...]
    revert で「設定前に戻す」ための記録に使います。
    """
    out = []
    try:
        it = context.getRegisterValueAddressRanges(register, start, end)
    except Exception:
        return out
    while it is not None and it.hasNext():
        rng = it.next()
        lo = rng.getMinAddress()
        hi = rng.getMaxAddress()
        try:
            value = context.getValue(register, lo, False)
        except Exception:
            value = None
        if value is None:
            continue
        # Jython では getValue の BigInteger が Python の long になって返る (実測)
        out.append({"start": addr_str(lo), "end": addr_str(hi), "value": int(value)})
    return out


def apply_one(program, item, logger, new_records):
    """1 件の設定案を反映します。戻り値は applied/skipped/rejected のいずれか。"""
    start_text = item.get("start")
    end_text = item.get("end", start_text)

    basis = item.get("address_basis")
    if basis not in SAFE_ADDRESS_BASIS:
        logger.log(u"SKIP (address_basis={0}): {1}".format(basis, start_text))
        return "skipped"

    real, bits, problem = register_problem(item.get("register"))
    if problem is not None:
        logger.log(u"REJECT (register): {0} — {1}".format(item.get("register"), problem))
        return "rejected"

    value = parse_int(item.get("value"))
    if value is None or value < 0 or value >= (1 << bits):
        logger.log(u"REJECT (value が {0}bit に収まらない): {1}={2}".format(
            bits, real, item.get("value")))
        return "rejected"

    problem = evidence_problem(item.get("evidence"))
    if problem is not None:
        logger.log(u"REJECT ({0}): {1} {2}".format(problem, real, start_text))
        return "rejected"
    if u"{0}".format(item.get("confidence", "")).lower() == "low":
        logger.log(u"SKIP (confidence=low は反映しない): {0} {1}".format(real, start_text))
        return "skipped"

    factory = program.getAddressFactory()
    try:
        start = factory.getAddress(str(start_text))
        end = factory.getAddress(str(end_text))
    except Exception:
        start = end = None
    if start is None or end is None:
        logger.log(u"SKIP (invalid address): {0}..{1}".format(start_text, end_text))
        return "skipped"
    if end.compareTo(start) < 0:
        logger.log(u"REJECT (end が start より前): {0}..{1}".format(start_text, end_text))
        return "rejected"
    memory = program.getMemory()
    if not memory.contains(start) or not memory.contains(end):
        logger.log(u"SKIP (範囲の端がメモリに無い): {0}..{1}".format(start_text, end_text))
        return "skipped"

    context = program.getProgramContext()
    register = context.getRegister(real)
    if register is None:
        names = []
        try:
            names = [u"{0}".format(r.getName()) for r in context.getRegisters()][:40]
        except Exception:
            pass
        logger.log(u"REJECT (この言語に {0} が無い。ghidra-snes 以外の 65816 定義か?): "
                   u"使えるレジスタ={1}".format(real, names))
        return "rejected"
    try:
        actual_bits = int(register.getBitLength())
    except Exception:
        actual_bits = bits
    if actual_bits != bits:
        logger.log(u"REJECT ({0} の幅が {1}bit (想定 {2}bit)。SLEIGH 定義を確認してください)".format(
            real, actual_bits, bits))
        return "rejected"
    try:
        if bool(register.isProcessorContext()):
            logger.log(u"REJECT ({0} がコンテキストレジスタになっている。命令長を変えうるので触りません)".format(real))
            return "rejected"
    except Exception:
        pass

    previous = current_ranges(context, register, start, end)
    if (len(previous) == 1 and previous[0]["value"] == value
            and previous[0]["start"].lower() == addr_str(start).lower()
            and previous[0]["end"].lower() == addr_str(end).lower()):
        logger.log(u"SKIP (既に同じ値): {0}={1:#x} {2}..{3}".format(
            real, value, start_text, end_text))
        return "skipped"

    try:
        from java.math import BigInteger
        context.setValue(register, start, end, BigInteger.valueOf(value))
    except Exception:
        logger.log(u"REJECT (setValue で例外): {0} {1}..{2}".format(real, start_text, end_text))
        logger.log(traceback.format_exc())
        return "rejected"

    new_records.append({
        "operation": OPERATION_PREFIX + real,
        "entry": addr_str(start),
        "end": addr_str(end),
        "register": real,
        "value": value,
        "previous": previous,
        "evidence": item.get("evidence"),
    })
    logger.log(u"SET: {0}={1:#x} {2}..{3} (設定前に明示値のあった範囲 {4} 件)".format(
        real, value, addr_str(start), addr_str(end), len(previous)))
    return "applied"


def merge_record(existing, new_records, program):
    """共有台帳へ context 記録をマージします。

    キーは (operation, entry)。operation がレジスタごとに別名なので、
    同じ開始番地の DP と DBR は併存します。同じ範囲へ再設定したときは
    **最初の previous (本当の設定前の状態) を引き継ぐ** — 上書きすると
    revert が「1 回目の反映後」にしか戻らなくなるためです。
    """
    by_key = {}
    for d in existing.get("defined", []):
        key = (d.get("operation", "define_function"), (d.get("entry") or "").lower())
        by_key[key] = d
    for d in new_records:
        key = (d["operation"], d["entry"].lower())
        old = by_key.get(key)
        if old is not None and (old.get("end") or "").lower() == d["end"].lower():
            d["previous"] = old.get("previous", d["previous"])
        by_key[key] = d
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

    if not is_65816(program):
        printerr(u"この Program は 65816 ではありません。何も変更していません。")
        return

    in_file = askFile("Select proposed_context.json", "Open")
    in_path = in_file.getAbsolutePath()

    logger.log(u"=== Ghidra Claude Toolbox apply_snes_context ===")
    logger.log(u"input: {0}".format(in_path))

    cfg, cfg_path = load_bridge_config(in_path, logger)
    if cfg is None:
        printerr(u"bridge_config.json が見つかりません ({0} の近傍を探しました)。\n"
                 u"DP / DBR の設定は opt-in 機能です。allowed_apply_operations に "
                 u"\"context\" を追加してください。".format(os.path.dirname(in_path)))
        return
    if not context_allowed(cfg):
        printerr(u"DP / DBR の設定は許可されていません。何も変更していません。\n"
                 u"  bridge_config: {0}\n"
                 u"  allowed_apply_operations: {1}\n"
                 u"許可するには allowed_apply_operations に \"context\" を追加してください。".format(
                     cfg_path, cfg.get("allowed_apply_operations")))
        return
    logger.log(u"opt-in 確認 OK: allowed_apply_operations に \"context\" があります ({0})".format(
        cfg_path))

    try:
        data = read_json(in_path)
    except Exception:
        printerr(u"JSON として読み込めませんでした: {0}".format(in_path))
        return
    if not isinstance(data.get("contexts"), list):
        printerr(u"contexts 配列がありません。schemas/proposed_context.schema.json を確認してください。")
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

    tx_id = program.startTransaction("Apply [AI] SNES context (DP/DBR)")
    try:
        for item in data["contexts"]:
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
    logger.log(u"※ 保存はしていません。疑似 C を開き直して in_DP / in_DBR が消えたか確認し、"
               u"問題なければ Ctrl+S。取り消すなら revert_operations.py に {0} を渡してください。".format(
                   RECORD_NAME))


run()
