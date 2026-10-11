# -*- coding: utf-8 -*-
"""各ゲーム用の Claude / Codex 受け渡しプロジェクトを作る外部ツールです (Python 3.13 前提)。

Windows CMD での使い方:

    python tools\\make_game_project.py C:\\RE\\games\\my_game\\claude_project

作成される構成:

    claude_project/
      CLAUDE.md
      bridge_config.json
      ghidra_exports/
      proposals/
      notes/
        address_map.md
      dumps/
      logs/
      runtime_observations/

templates/game_claude_project/ をひな形として使い、既存ファイルは
上書きしません (破壊しにくさを優先)。argparse は使わず sys.argv を見ます。
"""

import shutil
import sys
from pathlib import Path


# このスクリプトから見たテンプレートフォルダの場所です。
TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates" / "game_claude_project"

# プロジェクト内に必ず用意する空フォルダです。
PROJECT_DIRS = ("ghidra_exports", "proposals", "notes", "dumps", "logs",
                "runtime_observations")


def copy_file_safe(src, dst):
    """ファイルをコピーします。コピー先が既にあれば上書きせずスキップします。"""
    if dst.exists():
        print(f"スキップ (既存): {dst}")
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    print(f"作成: {dst}")


def make_project(target):
    """指定フォルダにゲーム解析プロジェクトのひな形を作成します。"""
    if not TEMPLATE_DIR.is_dir():
        raise SystemExit(f"エラー: テンプレートが見つかりません: {TEMPLATE_DIR}")

    target = Path(target).resolve()
    target.mkdir(parents=True, exist_ok=True)
    print(f"出力先: {target}")

    # 空フォルダを作成します。
    for name in PROJECT_DIRS:
        (target / name).mkdir(parents=True, exist_ok=True)

    # ルート直下のファイルをコピーします。
    copy_file_safe(TEMPLATE_DIR / "CLAUDE.md", target / "CLAUDE.md")
    copy_file_safe(TEMPLATE_DIR / "bridge_config.json", target / "bridge_config.json")

    # notes/address_map.md をコピーします。
    src_map = TEMPLATE_DIR / "notes" / "address_map.md"
    if src_map.exists():
        copy_file_safe(src_map, target / "notes" / "address_map.md")

    # runtime_observations/README.md をコピーします。
    # 空フォルダを .gitkeep で保持する代わりに、**何を置く場所かを書いた
    # README** を置きます (ひな形をコピーした人が説明ごと受け取れるため)。
    src_obs = TEMPLATE_DIR / "runtime_observations" / "README.md"
    if src_obs.exists():
        copy_file_safe(src_obs, target / "runtime_observations" / "README.md")

    print("完了: プロジェクトのひな形を作成しました。")
    print("次の手順: bridge_config.json の game_name / source_model などを編集してください。")


def main():
    """コマンドライン引数から出力先を取得し、プロジェクトを作成します。"""
    if len(sys.argv) < 2:
        print("使い方: python tools\\make_game_project.py <出力先フォルダ>")
        print("例:     python tools\\make_game_project.py C:\\RE\\games\\my_game\\claude_project")
        raise SystemExit(1)

    make_project(sys.argv[1])


if __name__ == "__main__":
    main()
