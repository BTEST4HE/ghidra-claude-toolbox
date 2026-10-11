# platform_profiles/

プラットフォーム (アーキ) 固有の設定をここに置きます。スクリプト本体に
アーキ固有値 (return ニーモニック / モード / エンディアン等) を埋め込まず、
ここから読むことで PS1 / GBA / Wii / SH4 等を横断運用できます。

## 選び方
- `bridge_config.json` の `"platform_profile"` (例: `"sh4"`) で選ぶ。
- または proposal の `platform` (トップレベル/item) で上書きする。

## apply_functions.py が使うキー
- `mode_required` (bool): true なら未定義の関数化に mode 必須 (GBA)。
- `context_register` (str): モードを表すコンテキストレジスタ名 (GBA は `"TMode"`)。
- `mode_values` (obj): モード名→数値 (GBA は `{"arm":0,"thumb":1}`)。
- `modes` (list): 取り得るモード。

## 共通方針
- **return 検出はニーモニックでなく FlowType.isTerminal()** を使う (アーキ非依存)。
  そのため return ニーモニックはプロファイルに持たない (notes に記載するのみ)。
- 取得できないキーは安全側 (mode_required=false 等) に倒す。
- 一覧: `sh4` / `psx` / `ps1` / `ps2` / `saturn` / `SS` / `gba` / `wii` / `sfc`。新機種はファイルを足すだけ。
  (`sfc` = 65816。M/X フラグで即値幅が変わるモード持ちだが、2 フラグ + レジスタ名が拡張依存のため
   現状 mode_required=false。詳細は sfc.json の notes。)
  (`ps1` は `psx` と、`SS` は `saturn` と同じ内容の別名。)
- **MCP の生逆アセンブル (`get_disassembly` / `find_address_refs`) が使えるのは
  `mcp/disasm/` にモジュールがある arch だけ** — 現在 `mips` (psx/ps1/ps2) と
  `sh4` (sh4/saturn)。profile があっても arch モジュールが無ければ
  「未対応」と明示してエラーになる (黙って誤デコードは返さない)。
- 新規ゲームのセットアップは `templates/new_game_setup_prompt.md`(貼るだけのテンプレ)を使う。
