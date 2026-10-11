# Ghidra Version Policy — Ghidra バージョン運用方針

## 基本ルール

- **Ghidra は上書き更新しない。** 新バージョンは別フォルダに展開する
  （例: `C:\Tools\ghidra_11.3_PUBLIC` と `C:\Tools\ghidra_11.4_PUBLIC` を併存）。
- **ゲームごとに使った Ghidra を記録する。** `bridge_config.json` の
  `ghidra_version` / `ghidra_path` に書く（`toolbox_schema_version` も併記）。
- **新バージョンを試すときは、Ghidra プロジェクトをコピーしてから開く。**
  新しい Ghidra で更新したプロジェクトは、古い Ghidra で開けなくなることがあります。

## Ghidra 12 以降で ghidra_scripts/ を動かすには（Jython）

`ghidra_scripts/` は Jython (Python 2.7) 用です。Ghidra 12 では次の 2 つが必要です。

1. **Jython 拡張を入れる。** プロジェクト画面で
   **File → Install Extensions → Jython にチェック → OK → Ghidra を再起動**
   （Ghidra のバージョンごとに 1 回）。
2. **スクリプトのヘッダに `#@runtime Jython`。** 道具箱のスクリプトはすべて対応済みです
   （11.2 以降の Ghidra なら、この指定があっても問題ありません）。

どちらかが欠けると、Script Manager で次のエラーになります。

```
Unable to load script: export_context.py
  detail: Ghidra was not started with PyGhidra. Python is not available
```

Ghidra は通常の `ghidraRun.bat` で起動してかまいません。

## 道具箱の方針

- JSON の形（`schemas/`）は Ghidra のバージョンが変わっても変えない。
- Ghidra API への依存は `ghidra_scripts/` に閉じ込める。
- `export_context.py` は取れない情報を `null` / `unknown` にして、特定バージョンに依存しない。
