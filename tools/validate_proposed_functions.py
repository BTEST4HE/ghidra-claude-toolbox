# -*- coding: utf-8 -*-
"""proposed_functions.json を検証する外部ツールです (Python 3.13 前提)。

Windows CMD での使い方:

    python tools\\validate_proposed_functions.py proposals\\proposed_functions.json

引数を省略した場合は samples\\proposed_functions.sample.json を検証します。
apply_functions.py に渡す前に、人間がこのツールで OK を確認してください。

マルチプラットフォーム対応:
- item は address か entry のいずれかでアドレスを指定。
- operation は define_function のみ (省略時は define_function とみなす)。
- モード持ちアーキ (現状 gba) の define は mode (arm/thumb) 必須。
  → mode 未指定の gba 提案はエラーにする (apply 側でも拒否される)。
"""

import json
import re
import sys
from pathlib import Path


ALLOWED_CONFIDENCE = ("low", "medium", "high")
ALLOWED_BASIS = ("ghidra", "runtime", "dump_offset", "unknown")
ALLOWED_OPERATION = ("define_function", "undefine_function", "clear_code")
ALLOWED_MODE = ("arm", "thumb")

# clear_code の範囲がこれを超える提案は明らかに誤りとして弾く (静的ガード)。
# 実運用の上限は bridge_config の undefine_max_bytes で apply 側が強制する。
STATIC_RANGE_GUARD = 0x100000

# モード必須のプラットフォーム (platform_profiles の mode_required=true と対応)。
MODE_REQUIRED_PLATFORMS = ("gba",)

HEX_ADDRESS_RE = re.compile(r"^0[xX][0-9a-fA-F]+$")
DEFAULT_TARGET = "samples/proposed_functions.sample.json"


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
        raise SystemExit(f"エラー: JSON として解析できません: {path} (行 {exc.lineno} 桁 {exc.colno}: {exc.msg})")


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
    """読み込んだデータを検証し、エラーメッセージのリストを返します (空なら OK)。"""
    errors = []
    if not isinstance(data, dict):
        return ["トップレベルが JSON オブジェクトではありません。"]
    if "schema_version" not in data:
        errors.append("必須キー 'schema_version' がありません。")
    check_target_program(data, errors)

    top_platform = data.get("platform")
    functions = data.get("functions")
    if not isinstance(functions, list):
        errors.append("必須キー 'functions' が配列ではありません。")
        return errors

    seen = set()
    for index, item in enumerate(functions):
        prefix = f"functions[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix}: オブジェクトではありません。")
            continue

        addr = item.get("address") or item.get("entry")
        if addr is None:
            errors.append(f"{prefix}: 'address' または 'entry' が必要です。")
        if isinstance(addr, str) and not HEX_ADDRESS_RE.match(addr):
            errors.append(f"{prefix}: アドレス '{addr}' が 16 進表記ではありません。")

        operation = item.get("operation", "define_function")
        if operation not in ALLOWED_OPERATION:
            errors.append(f"{prefix}: operation '{operation}' は許可されていません ({ALLOWED_OPERATION})。")

        confidence = item.get("confidence")
        if confidence is not None and confidence not in ALLOWED_CONFIDENCE:
            errors.append(f"{prefix}: confidence '{confidence}' は low/medium/high のいずれかにしてください。")

        basis = item.get("address_basis")
        if basis is not None and basis not in ALLOWED_BASIS:
            errors.append(f"{prefix}: address_basis '{basis}' は許可されていません ({ALLOWED_BASIS})。")
        if basis in ("runtime", "dump_offset"):
            errors.append(f"{prefix}: address_basis '{basis}' は apply 時にスキップされます (Ghidra address ではない)。")

        mode = item.get("mode")
        if mode is not None and mode not in ALLOWED_MODE:
            errors.append(f"{prefix}: mode '{mode}' は arm/thumb のいずれかにしてください。")

        # モード必須プラットフォームの define は mode を必須にする (undefine は不要)。
        platform = item.get("platform", top_platform)
        if platform in MODE_REQUIRED_PLATFORMS and operation == "define_function" and mode is None:
            errors.append(
                f"{prefix}: platform '{platform}' の define_function は mode (arm/thumb) 必須です。"
                f" 誤モードでデータが命令に化けるため、明示してください (evidence に根拠も)。")

        # clear_code は end (>= address) が必須。範囲の静的サニティガードも見る。
        if operation == "clear_code":
            end = item.get("end")
            if end is None:
                errors.append(f"{prefix}: operation 'clear_code' は 'end' (終端アドレス) が必須です。")
            elif not (isinstance(end, str) and HEX_ADDRESS_RE.match(end)):
                errors.append(f"{prefix}: end '{end}' が 16 進表記ではありません。")
            elif isinstance(addr, str) and HEX_ADDRESS_RE.match(addr):
                lo = int(addr, 16)
                hi = int(end, 16)
                if hi < lo:
                    errors.append(f"{prefix}: end ({end}) が address ({addr}) より小さいです。")
                elif (hi - lo + 1) > STATIC_RANGE_GUARD:
                    errors.append(
                        f"{prefix}: 範囲が広すぎます ({hi - lo + 1} bytes > {STATIC_RANGE_GUARD})。"
                        f" 明らかに誤りなので分割/再検討してください。")

        force = item.get("force")
        if force is not None and not isinstance(force, bool):
            errors.append(f"{prefix}: force は true/false にしてください。")

        if isinstance(addr, str):
            key = addr.lower()
            if key in seen:
                errors.append(f"{prefix}: アドレス '{addr}' が重複しています。")
            else:
                seen.add(key)

    return errors


def main():
    """コマンドライン引数を解釈し、検証結果を表示します。"""
    if len(sys.argv) >= 2:
        target = Path(sys.argv[1])
    else:
        target = Path(DEFAULT_TARGET)
        print(f"引数が無いため既定の対象を検証します: {target}")

    data = load_json(target)
    errors = validate(data)

    if errors:
        print(f"NG: {target} に {len(errors)} 件の問題があります。")
        for err in errors:
            print(f"  - {err}")
        raise SystemExit(1)

    count = len(data.get("functions", []))
    print(f"OK: {target} は妥当です (関数案 {count} 件)。")


if __name__ == "__main__":
    main()
