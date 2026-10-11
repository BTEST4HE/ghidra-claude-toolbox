# -*- coding: utf-8 -*-
"""proposed_labels.json を検証する外部ツールです (Python 3.13 前提)。

Windows CMD での使い方:

    python tools\\validate_proposed_labels.py proposals\\proposed_labels.json

引数を省略した場合は samples\\proposed_labels.sample.json を検証します。
apply_labels.py に渡す前に、人間がこのツールで OK を確認してください。

ラベル付けは実質リネームなので、他の validate より厳しくしています:
- 名前は英数字 / _ / 日本語 (かな・漢字・長音符・中黒) のみ。空白・記号・全角英数は不可。
- Ghidra 自動生成名の接頭辞 (FUN_ / LAB_ / DAT_ …) は拒否 (情報量が無い)。
- 名前の重複を拒否 (Ghidra は許すが、まず提案側の間違い)。
- confidence=low の item に force は指定できない (低確度で上書きは危険)。
"""

import json
import re
import sys
from pathlib import Path


ALLOWED_CONFIDENCE = ("low", "medium", "high")
ALLOWED_BASIS = ("ghidra", "runtime", "dump_offset", "unknown")
ALLOWED_OPERATION = ("set_label",)

# Ghidra が自動生成する名前の接頭辞。これを提案されても情報量が無く、
# 既存の自動名と衝突するだけなので拒否する。
RESERVED_PREFIXES = ("FUN_", "LAB_", "DAT_", "SUB_", "UNK_", "EXT_",
                     "switchD_", "caseD_", "PTR_", "ARRAY_")

MAX_NAME_LENGTH = 128

HEX_ADDRESS_RE = re.compile(r"^0[xX][0-9a-fA-F]+$")
# 名前には日本語 (ひらがな / カタカナ / 漢字) も使えます (Ghidra はシンボル名に
#   Unicode を許す)。ただし **空白・記号・全角英数は入れません** (Ghidra の検索や
#   スクリプトで扱いづらいため)。全角英数は半角へ、空白は _ へ寄せる
#   正規化を MCP 側 (find_text / decode_text の as_proposal) が行います。
#   許すのは: 英数字 / _ / ひらがな / カタカナ / 漢字 / 長音符 / 中黒
#   先頭に数字・長音符・中黒は置けません。
#   ※ この文字クラスは 3 か所 (apply_labels.py / validate_proposed_labels.py /
#      schemas/proposed_labels.schema.json) に同じものがあります。片方だけ直すと
#      「検証は通るのに反映で弾かれる」になるので **まとめて直すこと。**
NAME_RE = re.compile("^[A-Za-z_\u3041-\u3096\u30A1-\u30FA\u4E00-\u9FFF][A-Za-z_\u3041-\u3096\u30A1-\u30FA\u4E00-\u9FFF0-9\u30FC\u30FB]*$")
ASCII_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
DEFAULT_TARGET = "samples/proposed_labels.sample.json"


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


def validate_name(name, prefix, errors):
    """ラベル名を検証し、問題をエラーリストへ追加します。"""
    if not isinstance(name, str) or not name:
        errors.append(f"{prefix}: 'name' が必要です (空文字は不可)。")
        return
    if len(name) > MAX_NAME_LENGTH:
        errors.append(f"{prefix}: name が長すぎます ({len(name)} > {MAX_NAME_LENGTH})。")
    if not NAME_RE.match(name):
        errors.append(
            f"{prefix}: name '{name}' に使えない文字があります。"
            f"英数字 / _ / ひらがな / カタカナ / 漢字 / 長音符 / 中黒 のみ "
            f"(先頭は英字・_・かな・漢字)。**空白・記号・全角英数は不可**です "
            f"(全角英数は半角へ、空白は _ へ寄せてください)。")
    for reserved in RESERVED_PREFIXES:
        if name.startswith(reserved):
            errors.append(
                f"{prefix}: name '{name}' は Ghidra 自動生成名の接頭辞 "
                f"'{reserved}' で始まっています。用途が分かる名前を付けてください。")
            break


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

    labels = data.get("labels")
    if not isinstance(labels, list):
        errors.append("必須キー 'labels' が配列ではありません。")
        return errors

    seen_addr = {}
    seen_name = {}
    for index, item in enumerate(labels):
        prefix = f"labels[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix}: オブジェクトではありません。")
            continue

        addr = item.get("address")
        if addr is None:
            errors.append(f"{prefix}: 'address' が必要です。")
        elif not (isinstance(addr, str) and HEX_ADDRESS_RE.match(addr)):
            errors.append(f"{prefix}: アドレス '{addr}' が 16 進表記ではありません。")

        name = item.get("name")
        validate_name(name, prefix, errors)

        operation = item.get("operation", "set_label")
        if operation not in ALLOWED_OPERATION:
            errors.append(
                f"{prefix}: operation '{operation}' は許可されていません ({ALLOWED_OPERATION})。")

        confidence = item.get("confidence")
        if confidence is not None and confidence not in ALLOWED_CONFIDENCE:
            errors.append(
                f"{prefix}: confidence '{confidence}' は low/medium/high のいずれかにしてください。")

        basis = item.get("address_basis")
        if basis is not None and basis not in ALLOWED_BASIS:
            errors.append(f"{prefix}: address_basis '{basis}' は許可されていません ({ALLOWED_BASIS})。")
        if basis in ("runtime", "dump_offset"):
            errors.append(
                f"{prefix}: address_basis '{basis}' は apply 時にスキップされます "
                f"(Ghidra address ではない)。")

        force = item.get("force")
        if force is not None and not isinstance(force, bool):
            errors.append(f"{prefix}: force は true/false にしてください。")
        elif force is True:
            if confidence == "low":
                errors.append(
                    f"{prefix}: confidence=low の item に force は指定できません "
                    f"(低確度で既存の名前を上書きするのは危険)。")
            if not item.get("evidence"):
                errors.append(
                    f"{prefix}: force=true には evidence (根拠) を必ず書いてください "
                    f"(既存の名前を上書きするため)。")

        if isinstance(addr, str):
            key = addr.lower()
            if key in seen_addr:
                errors.append(
                    f"{prefix}: アドレス '{addr}' が {seen_addr[key]} と重複しています。")
            else:
                seen_addr[key] = prefix
        if isinstance(name, str) and name:
            if name in seen_name:
                errors.append(
                    f"{prefix}: name '{name}' が {seen_name[name]} と重複しています。")
            else:
                seen_name[name] = prefix

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

    labels = data.get("labels", [])
    forced = sum(1 for item in labels if isinstance(item, dict) and item.get("force"))
    print(f"OK: {target} は妥当です (ラベル案 {len(labels)} 件, うち force={forced} 件)。")
    if forced:
        print("  ※ force=true の item は既存の名前を上書きします。反映前に必ず目視確認を。")
    print("  ※ apply には bridge_config.json の allowed_apply_operations に "
          "\"labels\" が必要です。")


if __name__ == "__main__":
    main()
