# -*- coding: utf-8 -*-
"""proposed_comments.json を検証する外部ツールです (Python 3.13 前提)。

Windows CMD での使い方:

    python tools\\validate_proposed_comments.py samples\\proposed_comments.sample.json

引数を省略した場合は samples\\proposed_comments.sample.json を検証します。
argparse は使わず、sys.argv を直接見ます (引数が 1 個で十分なため)。
"""

import json
import re
import sys
from pathlib import Path


# 許可されるコメント種別です。
ALLOWED_TYPES = ("plate", "pre", "eol", "repeatable", "post")

# 許可される confidence の値です。
ALLOWED_CONFIDENCE = ("low", "medium", "high")

# 許可される address_basis の値です (省略可)。
ALLOWED_BASIS = ("ghidra", "runtime", "dump_offset", "unknown")

# 16 進アドレスの正規表現です。
HEX_ADDRESS_RE = re.compile(r"^0[xX][0-9a-fA-F]+$")

# デフォルトの検証対象です。
DEFAULT_TARGET = "samples/proposed_comments.sample.json"


def load_json(path):
    """指定パスの JSON を UTF-8 で読み込んで返します。失敗時は分かりやすく落とします。"""
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


def json_type_name(value):
    """値の JSON での型名 (null / boolean / number / string / array / object) を返します。"""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


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
    """読み込んだデータを検証し、エラーメッセージのリストを返します。

    空のリストが返れば検証 OK です。
    """
    errors = []

    if not isinstance(data, dict):
        return ["トップレベルが JSON オブジェクトではありません。"]

    if "schema_version" not in data:
        errors.append("必須キー 'schema_version' がありません。")
    check_target_program(data, errors)

    comments = data.get("comments")
    if not isinstance(comments, list):
        errors.append("必須キー 'comments' が配列ではありません。")
        return errors

    seen = set()
    for index, item in enumerate(comments):
        prefix = f"comments[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix}: オブジェクトではありません。")
            continue

        address = item.get("address")
        ctype = item.get("type")
        comment = item.get("comment")
        confidence = item.get("confidence")
        basis = item.get("address_basis")

        # 必須キーの存在と、値が文字列かをチェックします (null / 数値 / bool / 配列 / オブジェクトは不可)。
        for key in ("address", "type", "comment"):
            if key not in item:
                errors.append(f"{prefix}: 必須キー '{key}' がありません。")
            elif not isinstance(item[key], str):
                errors.append(f"{prefix}: {key} は文字列にしてください (実際は {json_type_name(item[key])})。")

        # address が 16 進表記として妥当かチェックします。
        if isinstance(address, str) and not HEX_ADDRESS_RE.match(address):
            errors.append(f"{prefix}: address '{address}' が 16 進表記ではありません。")

        # comment が [AI] で始まるかチェックします。
        if isinstance(comment, str) and not comment.lstrip().startswith("[AI]"):
            errors.append(f"{prefix}: comment が '[AI]' で始まっていません。")

        # type が許可された種別かチェックします。
        if isinstance(ctype, str) and ctype not in ALLOWED_TYPES:
            errors.append(f"{prefix}: type '{ctype}' は許可されていません ({ALLOWED_TYPES})。")

        # confidence は任意ですが、あれば値を検証します。
        if confidence is not None and confidence not in ALLOWED_CONFIDENCE:
            errors.append(f"{prefix}: confidence '{confidence}' は low/medium/high のいずれかにしてください。")

        # address_basis は任意ですが、あれば値を検証します。
        if basis is not None and basis not in ALLOWED_BASIS:
            errors.append(f"{prefix}: address_basis '{basis}' は許可されていません ({ALLOWED_BASIS})。")

        # 同一アドレス・同一コメントの重複をチェックします。
        if isinstance(address, str) and isinstance(ctype, str) and isinstance(comment, str):
            key = (address.lower(), ctype, comment.strip())
            if key in seen:
                errors.append(f"{prefix}: address '{address}' と同一 type/comment の重複があります。")
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

    count = len(data.get("comments", []))
    print(f"OK: {target} は妥当です (コメント案 {count} 件)。")


if __name__ == "__main__":
    main()
