# -*- coding: utf-8 -*-
"""proposed_context.json (65816 の DP / DBR 設定案) を検証する外部ツールです (Python 3.13 前提)。

Windows CMD での使い方:

    python tools\\validate_proposed_context.py proposals\\proposed_context.json

引数を省略した場合は samples\\proposed_context.sample.json を検証します。
apply_snes_context.py に渡す前に、人間がこのツールで OK を確認してください。

検証すること:
- register は DP / DBR だけ (別名 D -> DP)。ctx_MF / PBR / B などは理由つきで拒否。
  ※ ghidra-snes の SLEIGH では D は "DP" (16bit)、DBR は "DBR" (8bit) で、
    どちらも普通のレジスタ (contextreg ではない)。"B" はアキュムレータ上位バイト。
- value が幅 (DP=16bit / DBR=8bit) に収まること。
- start <= end、どちらも 16 進。
- evidence (根拠) が 1 件以上あり、空でないこと。種類 kind は
  runtime (エミュレータでの実測) / code (コードの事実) / cdl / doc のいずれか。
- 同じレジスタで重なる範囲に違う値を入れていないこと (同じ値の重なりは警告)。
- confidence=low は apply でスキップされる旨を警告。
"""

import json
import re
import sys
from pathlib import Path


ALLOWED_CONFIDENCE = ("low", "medium", "high")
ALLOWED_BASIS = ("ghidra", "runtime", "dump_offset", "unknown")
ALLOWED_EVIDENCE_KIND = ("runtime", "code", "cdl", "doc")

# apply_snes_context.py の ALLOWED_REGISTERS / REFUSED_REGISTERS と同じ表。
# ★片方だけ直すと「検証は通るのに反映で弾かれる」ので、必ずまとめて直すこと。
ALLOWED_REGISTERS = {"DP": ("DP", 16), "D": ("DP", 16), "DBR": ("DBR", 8)}
REFUSED_REGISTERS = {
    "CTX_MF": "命令長を変えるコンテキスト。M/X/E は ApplySnesTrace.java (CDL) の担当です",
    "CTX_XF": "命令長を変えるコンテキスト。M/X/E は ApplySnesTrace.java (CDL) の担当です",
    "CTX_EF": "命令長を変えるコンテキスト。M/X/E は ApplySnesTrace.java (CDL) の担当です",
    "CONTEXTREG": "コンテキストレジスタそのものは触りません",
    "PBR": "PBR は PC のバンクそのもの (Ghidra は番地から決める) なので設定しません",
    "B": "SLEIGH の B はアキュムレータの上位バイトです。データバンクは DBR と書いてください",
    "DB": "データバンクは DBR と書いてください (ghidra-snes の名前)",
    "DPLOW": "DP (16bit) を設定してください",
}

HEX_ADDRESS_RE = re.compile(r"^0[xX][0-9a-fA-F]+$")
DEFAULT_TARGET = "samples/proposed_context.sample.json"


def load_json(path):
    """指定パスの JSON を UTF-8 で読み込みます。失敗時は分かりやすく落とします。"""
    if not path.exists():
        raise SystemExit(f"エラー: ファイルが見つかりません: {path}")
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SystemExit(f"エラー: ファイルを読み込めません: {path} ({exc})")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise SystemExit(
            f"エラー: JSON として解析できません: {path} "
            f"(行 {exc.lineno} 桁 {exc.colno}: {exc.msg})")


def parse_value(value):
    """'0x..' / '$..' / 10 進文字列 / int を int にします。読めなければ None。"""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if not isinstance(value, str):
        return None
    text = value.strip().replace("_", "")
    try:
        if text.startswith("$"):
            return int(text[1:], 16)
        if text.lower().startswith("0x"):
            return int(text[2:], 16)
        return int(text, 10)
    except ValueError:
        return None


def validate_evidence(evidence, prefix, errors):
    """根拠の配列を検証します。"""
    if not isinstance(evidence, list) or not evidence:
        errors.append(
            f"{prefix}: evidence (根拠) が必須です。実測 (例: Mesen で $00:9153 実行中 D=$0000) や"
            f"コードの事実 (例: TCD は $80:80E3 の初期化だけで PLD で戻る) を書いてください。")
        return
    for j, ev in enumerate(evidence):
        where = f"{prefix}.evidence[{j}]"
        if isinstance(ev, str):
            if not ev.strip():
                errors.append(f"{where}: 空の根拠です。")
            continue
        if not isinstance(ev, dict):
            errors.append(f"{where}: 文字列か {{kind, detail}} のオブジェクトにしてください。")
            continue
        if not str(ev.get("detail") or "").strip():
            errors.append(f"{where}: detail が空です。")
        kind = ev.get("kind")
        if kind is not None and kind not in ALLOWED_EVIDENCE_KIND:
            errors.append(f"{where}: kind '{kind}' は {ALLOWED_EVIDENCE_KIND} のいずれかにしてください。")


def check_target_program(data, errors):
    """target_program (対象の Ghidra Program 名) が空でない文字列かを確かめます。

    apply は現在の Program 名と一致しないと**何も変更せずに中止**します
    (無い・空・文字列でないときも中止)。ここで先に気づけるようにします。
    """
    target = data.get("target_program")
    if not isinstance(target, str) or not target.strip():
        errors.append("必須キー 'target_program' (対象の Ghidra Program 名。空でない文字列) がありません。"
                      "apply は現在の Program 名と一致しないと何も変更せずに中止します。")


def validate(data):
    """読み込んだデータを検証し、(エラー, 警告) のリストを返します (エラーが空なら OK)。"""
    errors = []
    warnings = []
    if not isinstance(data, dict):
        return (["トップレベルが JSON オブジェクトではありません。"], warnings)
    if "schema_version" not in data:
        errors.append("必須キー 'schema_version' がありません。")
    check_target_program(data, errors)
    items = data.get("contexts")
    if not isinstance(items, list):
        errors.append("必須キー 'contexts' が配列ではありません。")
        return (errors, warnings)

    spans = []   # (register, start, end, value, prefix)
    for index, item in enumerate(items):
        prefix = f"contexts[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix}: オブジェクトではありません。")
            continue

        reg_text = str(item.get("register") or "").strip().upper()
        real = bits = None
        if reg_text in ALLOWED_REGISTERS:
            real, bits = ALLOWED_REGISTERS[reg_text]
        elif reg_text in REFUSED_REGISTERS:
            errors.append(f"{prefix}: register '{item.get('register')}' は不可 — {REFUSED_REGISTERS[reg_text]}")
        else:
            errors.append(f"{prefix}: register '{item.get('register')}' は不可 (DP / DBR だけ)。")

        value = parse_value(item.get("value"))
        if value is None:
            errors.append(f"{prefix}: value '{item.get('value')}' が数値として読めません。")
        elif bits is not None and not (0 <= value < (1 << bits)):
            errors.append(f"{prefix}: value {item.get('value')} が {real} ({bits}bit) に収まりません。")

        start_text = item.get("start")
        end_text = item.get("end", start_text)
        start = end = None
        for key, text in (("start", start_text), ("end", end_text)):
            if not (isinstance(text, str) and HEX_ADDRESS_RE.match(text)):
                errors.append(f"{prefix}: {key} '{text}' が 16 進表記 (0x...) ではありません。")
        if isinstance(start_text, str) and HEX_ADDRESS_RE.match(start_text):
            start = int(start_text, 16)
        if isinstance(end_text, str) and HEX_ADDRESS_RE.match(end_text):
            end = int(end_text, 16)
        if start is not None and end is not None and end < start:
            errors.append(f"{prefix}: end ({end_text}) が start ({start_text}) より前です。")

        validate_evidence(item.get("evidence"), prefix, errors)

        confidence = item.get("confidence")
        if confidence is not None and confidence not in ALLOWED_CONFIDENCE:
            errors.append(f"{prefix}: confidence '{confidence}' は low/medium/high のいずれかにしてください。")
        if confidence == "low":
            warnings.append(f"{prefix}: confidence=low は apply でスキップされます。")

        basis = item.get("address_basis")
        if basis is not None and basis not in ALLOWED_BASIS:
            errors.append(f"{prefix}: address_basis '{basis}' は許可されていません ({ALLOWED_BASIS})。")
        if basis in ("runtime", "dump_offset", "unknown"):
            warnings.append(f"{prefix}: address_basis '{basis}' は apply でスキップされます (Ghidra 番地にしてください)。")

        if real and value is not None and start is not None and end is not None and end >= start:
            spans.append((real, start, end, value, prefix))

    for i, a in enumerate(spans):
        for b in spans[i + 1:]:
            if a[0] != b[0] or a[2] < b[1] or b[2] < a[1]:
                continue
            if a[3] != b[3]:
                errors.append(
                    f"{b[4]}: {a[4]} と範囲が重なり、{a[0]} の値が違います "
                    f"({a[3]:#x} と {b[3]:#x})。後から適用した方が勝つので、範囲を分けてください。")
            else:
                warnings.append(f"{b[4]}: {a[4]} と範囲が重なっています (値は同じ)。")
    return (errors, warnings)


def main():
    """コマンドライン引数を解釈し、検証結果を表示します。"""
    if len(sys.argv) >= 2:
        target = Path(sys.argv[1])
    else:
        target = Path(DEFAULT_TARGET)
        print(f"引数が無いため既定の対象を検証します: {target}")

    data = load_json(target)
    errors, warnings = validate(data)
    for w in warnings:
        print(f"  WARN: {w}")
    if errors:
        print(f"NG: {target} に {len(errors)} 件の問題があります。")
        for err in errors:
            print(f"  - {err}")
        raise SystemExit(1)
    print(f"OK: {target} は妥当です (設定案 {len(data.get('contexts', []))} 件)。")
    print("  ※ apply には bridge_config.json の allowed_apply_operations に "
          "\"context\" が必要です。疑似 C が読みやすくなったかは Ghidra で確認してください。")


if __name__ == "__main__":
    main()
