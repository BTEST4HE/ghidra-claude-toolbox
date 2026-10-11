# Ghidra Claude Toolbox

Ghidra と Claude Code / Codex の間で、解析情報を **安全に** 受け渡しするための
道具箱です。コマンド例はすべて Windows CMD 前提です。

## 目的

- Ghidra の解析結果を JSON / 疑似C として **export** する。
- Claude Code / Codex がそれを（ファイル直読み or **読み取り専用 MCP**で）読んで、
  解析メモ・コメント案・関数化案を作る。
- 人間が確認した案 **だけ** を Ghidra へ反映する（コメントは既定許可、関数化/未定義化は
  per-project の opt-in）。

Ghidra プロジェクト本体を Claude Code / Codex に直接編集させません。**リネーム・データ型変更・
配列化・構造体適用は行いません**（apply はコメント反映と、opt-in の関数化/未定義化のみ）。

## 前提環境と導入

- OS: Windows 11（コマンド例は CMD。他 OS でもパス表記を読み替えれば動く想定ですが未検証）
- 外部 Python: 3.12 以上（3.13 推奨。`tools/` と `mcp/` のスクリプト用）
- Ghidra: バージョン差を許容（特定バージョンに強く依存しない）。
  `ghidra_scripts/` は Ghidra 上で動くため Jython (Python 2.7) 互換。
  **Ghidra 12 以降は Jython が拡張機能**なので、`File → Install Extensions → Jython` を
  入れて再起動してください（[docs/ghidra_version_policy.md](docs/ghidra_version_policy.md)）。

```
:: 1. 取得したフォルダに移動
cd C:\path\to\ghidra_toolbox

:: 2. MCP サーバの依存 (mcp SDK と、画像を描くツール用の Pillow)
python -m pip install -r mcp\requirements.txt

:: 3. 動作確認 (Ghidra も SDK も不要。サンプルを検証ツールに通す)
python tools\validate_proposed_comments.py samples\proposed_comments.sample.json
```

- `--selftest` と `tools/validate_proposed_*.py` は MCP SDK 無しで動きます。
- この道具箱は **ROM / BIOS / ゲームのデータを一切含みません**。解析対象は
  利用者が自分で用意し、各ゲームのプロジェクトフォルダ（`dumps/` 等）に置きます。

## フォルダ構成

```
ghidra_toolbox/
  README.md / LICENSE / .gitignore
  ghidra_scripts/      Ghidra Script Manager から実行する Jython スクリプト
    export_context.py     Ghidra → JSON/疑似C を書き出す（★このツールの心臓）
    apply_comments.py     [AI] コメント案を反映
    apply_functions.py    未定義コードを関数化 (define_function, opt-in)
    apply_undefine.py     誤関数化のクリア (undefine_function/clear_code, opt-in)
    apply_labels.py       データテーブル等の命名 (set_label, opt-in)
    revert_operations.py  台帳ベースで apply を巻き戻す (define/undefine/label)
  mcp/                 読み取り専用 MCP サーバ
    ghidra_readonly_mcp.py   ghidra_exports/ を問い合わせる（書き込み系ツールは存在しない）
    disasm/                  アーキ別逆アセンブラ（mips / sh4 / arm / thumb / ppc / w65816。未対応は明示エラー）
                             _prologue.py (関数入口判定) / _callargs.py (呼び出し引数の復元)
                             は**共通の骨格**。アーキ側は判定だけを渡す
    requirements.txt / README.md
  schemas/             受け渡し JSON の仕様（安定層）
    proposed_comments.schema.json / proposed_functions.schema.json /
    proposed_labels.schema.json / context.schema.json /
    runtime_observations.schema.json（★外部エミュレータの観測を読む共通形式）
  platform_profiles/   アーキ固有値（psx / ps2 / saturn / sh4 / gba / wii …）
  tools/               外部 Python 3.13 ツール
    validate_proposed_comments.py / validate_proposed_functions.py /
    validate_proposed_labels.py / make_game_project.py
    validate_proposed_context.py
  templates/
    game_claude_project/       ゲームごとのプロジェクトひな形
                               （runtime_observations/ の説明もここに入っている）
    new_game_setup_prompt.md   ★新規ゲームの Ghidra+MCP セットアップ手順プロンプト
    session_start_prompt.md    ★セットアップ済みゲームで解析セッションを開始/再開する時のプロンプト
  docs/                workflow / safety_rules / ghidra_version_policy /
                       ghidra_gui_overlay_import(★人間向け: Import / Raw Binary / G→D→F で関数化 / export の手順)
  samples/             サンプル JSON（bridge_config / mcp_registry / 提案 JSON / 実行時観測）
```

## 全体ワークフロー（往復）

```
[Ghidra GUI] --export_context.py--> ghidra_exports/*.json + decompile/*.c
        │
        ├─(A) Claude が直読み        … decompile/ や functions.json をファイルとして読む
        └─(B) 読み取り専用 MCP 経由  … 巨大な xrefs.json をフィルタ付きで問い合わせ
        │
        v
   Claude が解析 → notes/*.md（確定/不明を分ける）
        │
        ├─ proposals/proposed_comments.json   ([AI] コメント案)
        ├─ proposals/proposed_functions.json  (関数化する未定義エントリ, opt-in)
        └─ proposals/proposed_labels.json     (データテーブル等の命名, opt-in)
        │
        v
   tools\validate_proposed_*.py で検証（人間）
        │
        v
[Ghidra GUI] --apply_comments.py / apply_functions.py / apply_labels.py--> Program に反映
        │
        v
   （関数化した場合）export_context.py を再実行 → 新しい関数が decompile 可能に
```

### 実行時の観測を証拠として足す（任意）

静的解析だけでは「本当に使われているのか」が分かりません。エミュレータのデバッガなどで
観測した結果を決まった形式の JSON にして置いておくと、Ghidra Toolbox 側から
**静的解析と同じアドレス基準で**引けます。観測の手段（どのエミュレータか、手作業で
記録するか、各自のツールで書き出すか）は問いません。**観測用のツールは同梱していません。**

1. 静的に候補を絞る — `find_address_refs` / `find_pointers_to` / `classify_range`
2. その範囲だけを、各自の環境のデバッガで観測する
   （Toolbox はエミュレータを起動も接続も制御もしません）
3. 結果を `<project_root>/runtime_observations/*.json` に保存する
   — 形式は [`schemas/runtime_observations.schema.json`](schemas/runtime_observations.schema.json)、
   最小例は [`samples/runtime_observations.sample.json`](samples/runtime_observations.sample.json)
4. 根拠として照会する — `list_runtime_observations` / `get_runtime_range_evidence`

- 実行時アドレスは `bridge_config.json` の `address_translations` の規則でだけ
  Ghidra 番地に直します。**規則が無いものは推測せず `unmapped` として残します。**
- ★**「観測されなかった」は「使われていない」の証明ではありません。**
  `verdict` に `unused` はありません（`not_observed` / `coverage_unknown` まで）。
  どの場面をどこまで実行したか（`coverage_note`）を必ず添えて返します。
- ★エミュレータ側の書き込み（`write_memory` / レジスタ変更 / 入力 / セーブステート）は
  **このスコープ外**で、観測 JSON を読む機能はそれらを実行しません。

詳細は [docs/workflow.md](docs/workflow.md) を参照。

## 読み取り専用 MCP

`ghidra_exports/` の JSON を、Claude Code / Codex から**必要な部分だけ**問い合わせる
読み取り専用 MCP サーバ（`mcp/ghidra_readonly_mcp.py`）。**Ghidra にも Ghidra プロジェクトにも
触れず**、書き込み系ツール（コメント反映・関数作成・リネーム・型変更）は存在しません。

- 提供ツール: `get_program_info` / `list_functions` / `get_functions_near_address` /
  `list_strings` / `get_xrefs`(to/from 必須) /
  **`get_decompiled_function`**(`with_addresses=true` で**行ごとの命令アドレス**つき) /
  **`list_call_sites`**(呼び出し時の引数レジスタを復元。MIPS / PowerPC) /
  **`infer_signature`**(その関数が実際に何個引数を取るか) /
  **`list_callees`**(その関数が何を呼ぶか。深さ指定) /
  **`save_export_snapshot`** / **`list_export_snapshots`** / **`diff_exports`**
  (同じ Program の時間差 = 前回からの進捗) /
  **`list_overlays`**(実行時に読み込まれる外部ファイルの登録状況) /
  **`list_comments`**(その番地に付いているコメント = 前回までの結論) /
  **`list_runtime_observations`** / **`get_runtime_range_evidence`**
  (外部エミュレータで観測した実行時の記録を Ghidra 番地で照会) /
  **`propose_variable_notes`**(疑似 C の変数の意味を [AI] コメントにする) /
  **`find_immediate`**(その数値を即値として使っている命令。MIPS) /
  **`list_record_formats`**(使い回せるレコード定義) /
  **`render_tim`** / **`find_tim_blocks`**(PS1 の TIM 画像) /
  **`get_disassembly`**(未関数化コードの生逆アセンブル) /
  **`find_address_refs`**(Ghidra が xref を持たない表の参照元探し) /
  **`read_data`**(見つけたテーブルの中身を読む。`record=` で型混在の固定長レコード) /
  **`find_writers`**(誰がここに何を書くか。SH-4 / MIPS) /
  **`expand_switch`**(スイッチ表の展開。SH-4 / MIPS) /
  **`find_function_entry`**(関数入口の判定。SH-4 / MIPS / ARM / Thumb) /
  **`find_undefined_targets`**(参照されているのに関数化されていない入口) /
  **`find_struct_field_uses`**(構造体のどのオフセットが何に使われているか) /
  **`resolve_pool`**(定数プール DAT_xxxxxxxx の中身) /
  **`find_pointers_to`**(データ中の生ポインタの逆引き) /
  **`list_labels`**(その番地に付いている名前 + 人間が付けた型) /
  **`resolve_symbol`**(名前 → 番地。vtable は kind=vtable) /
  **`get_struct_layout`** / **`find_field`**(構造体・クラスのフィールドが何バイト目か) /
  **`resolve_gp_offset`**(MIPS の gp 相対 → 絶対番地と名前) /
  **`classify_range`**(未定義領域の正体当て) /
  **`list_undefined_ranges`**(まだ手つかずの領域を大きい順に) /
  **`find_bytes`**(バイト列検索 / AOB) /
  **`search_programs`**(全 Program 横断の検索) /
  **`diff_programs`**(製品版 vs 修正版の差分) /
  **`find_text`**(Ghidra が拾えない日本語) /
  **`decode_text`**(独自符号を文字対応表で読む) /
  **`find_pointer_tables`** / **`describe_data`**(構造体・配列の推定) /
  **`translate_address`**(Program 間のアドレス換算) /
  **`decompress`**(GBA/NDS の BIOS 圧縮を展開) /
  **`find_compressed_blocks`**(圧縮ブロック探し) /
  **`render_tiles`**(タイルを PNG で見る) / `get_export_status`。
- `get_disassembly` は `format="text"` で**1 命令 1 行**の出力に切り替わります
  （30 命令で 5,305 → 1,542 文字。コンテキストを食い潰さないため）。
- **疑似 C の行 → 命令アドレスが引けます**（`get_decompiled_function(with_addresses=true)`）。
  1 命令の違い（比べるべき値と別のレジスタを比べている等）を追うとき、疑似 C の
  怪しい行から番地が 1 回の呼び出しで出ます。**`code`(疑似 C 本文) は手つかず**で、
  `listing` と `line_addresses` が増えるだけです。対応表は decompiler の
  マークアップからしか取れないので **export のときに一緒に出します**
  (`decompile/<関数>_<entry>.lines.json`、`decompile_line_map` で制御・既定 true)。
  `.c` と対応表がずれていたら、行頭を突き合わせて**気づいて警告します**。
- **`list_call_sites` は「疑似 C が落とした引数」を埋めます**(MIPS)。
  `FUN_801a1a0c(param_1,3)` の 3 番目が何かは、呼び出し直前の
  `addiu $a2,$zero,1` を見るまで分かりません。各呼び出しの `$a0`〜`$a3` を
  **即値 / アドレス / 実行時 / 呼び出し元から持ち回り**に分けて返し、
  **遅延スロット**(jal の次の 1 命令)も引数設定として数え、
  **直前の呼び出しより先には遡りません**(引数レジスタは呼び出しで壊れるため)。
  `constants` に「どの引数にどの定数が何回渡されているか」がまとまります。
- **外部エミュレータの観測を「証拠」として読み込めます**
  (`list_runtime_observations` / `get_runtime_range_evidence`)。
  エミュレータのデバッガなどで観測した結果 (観測の手段は問いません) を
  `<project_root>/runtime_observations/` に JSON で保存しておくと、
  **静的解析と同じアドレス基準で**引けます。
  ★**この MCP はエミュレータを起動も接続も制御もしません。** 読むのは
  プロジェクト内に保存された JSON だけです (保存するのは人間か解析セッション)。
  ★**「観測されなかった」は「使われていない」の証明ではありません。**
  `verdict` は `not_observed` / `coverage_unknown` までで、
  **`unused` という値はありません**。どの場面をどこまで実行したか
  (`coverage_note`) を必ず添えて返します。
  実行時アドレスは既存の `address_translations` の規則でだけ変換し、
  **規則が無いものは推測せず `unmapped` として理由つきで残します**。
- **`list_comments` で前のセッションの結論を読み返せます。** この道具箱の往復は
  「AI がコメント案 → 人間が `apply_comments.py` で反映 → 次のセッションが
  続きから」ですが、**反映したコメントを読む手段がありませんでした**
  (`comments.json` は export していたのに、件数を数えるだけだった)。
  `ai_only=true` で `[AI]` の所見だけに絞れます。どの関数の中かも添えるので、
  番地だけ見て迷いません。
- **疑似 C の変数に意味を付けられます**(`propose_variable_notes` →
  `get_decompiled_function(rename=true)`)。`iVar1` が何なのかは読み解いた本人に
  しか分かりません。それを**関数入口の `[AI]` コメント**として Ghidra へ戻し、
  次のセッションは `list_comments` で読み返せるほか、`rename=true` で
  **読みやすい疑似 C (`code_renamed`) を自動で組み立てます**。
  **`code` (Ghidra の出力そのまま) は絶対に変えません。**
  疑似 C に無い変数名は拒否します（存在しない名前にメモを付けると、次の
  セッションが「そういう変数がある」と誤解するため）。
  ★**Ghidra のローカル変数名そのものを書き換える機能は入れていません。**
  `iVar1` は「分からない」という正しい情報を持っているので、根拠の無い名前は
  それより悪いからです。
- **`infer_signature` は「この関数は実際に何個引数を取るか」を推定します。**
  疑似 C が引数を落とすとき、そもそも何個受け取る関数なのかが分かりません。
  **呼び出し側**(どの引数レジスタに積んでいるか) と **呼ばれる側**
  (引数レジスタを読むのが先か書くのが先か) の 2 方向から見て、
  食い違いは `conflicts` に出します。**断定しません。**
- **`list_callees` は `list_call_sites` の逆向き**です。「この初期化関数は
  何を仕込むのか」を深さ指定で辿ります。**循環は必ず検出して打ち切り**、
  間接呼び出しは件数だけ出します (「呼んでいない」ではありません)。
- **`diff_exports` で「前回からどこが進んだか」が出ます。** `diff_programs` は
  別 Program 同士の比較で、**同じ Program の時間差**は見られませんでした。
  解析を始める前に `save_export_snapshot` を 1 回取っておき、
  関数化やコメント反映 → 再 export の後に呼びます。
- **`find_immediate` は「この数値はどこで設定されるか」に答えます**(MIPS / PowerPC)。
  `find_address_refs` は**アドレス**、`find_bytes` は**バイト列**を探す道具で、
  `addiu $a0,$zero,100` のような**即値**はどちらでも引けませんでした。
  kind で **const**(定数を作っている) / **compare**(その値と比べている ← 閾値は
  たいていこれ) / add / logic / upper / pair を分けるので、件数が多くても
  本命を選べます。ロードストアの変位は既定で除きます (小さい値で埋まるため)。
- **同じ表を何度も読むなら `record_formats` に登録して使い回せます**
  (`bridge_config.json`)。`read_data(record="@part_entry")` で引けます。
  **Ghidra の構造体とは別物**で、read_data がどう区切って読むかを決めるだけです。
- **PS1 の TIM 画像を読めます** (`render_tim` / `find_tim_blocks`)。
  `render_tiles` は GBA の **8x8 タイル**前提なので、**直線配置**の TIM は
  そのままでは形が崩れます。`render_tim` は幅・深さ・CLUT を全部ヘッダから
  読み、**色違いの CLUT も `clut_index` で切り替えられます**。
  透明は「色 0x0000 かつ STP ビット 0」で判定します。
  タイル形式でない素のビットマップは `render_tiles(layout="linear", width=...)`。
- **実行時に RAM へ読み込まれる外部ファイルを「オーバーレイ」として登録できます**
  (`bridge_config.json` の `overlays`)。ステージデータや地形の高さテーブルは
  Ghidra の Program に入っていないので、従来は自前 Python でパースするしか
  ありませんでした。登録すると `read_data` / `find_bytes` / `describe_data` /
  `classify_range` / `find_pointers_to` が**その範囲でも同じように効きます**。
  応答の `block` は必ず `overlay:<名前>` になるので、Program 本体の値と混ざりません。
  **MCP は overlays を読むだけ**で、ファイルにも Ghidra にも書きません。
- **`export_memory: false` でも逆アセンブル系が動きます。** `memory_map.json` が
  無いときは `program.json` の `executable_path` と `memory_blocks` から
  自動でメモリマップを組み立てます (ELF はプログラムヘッダ、DOL はセクション表、
  それ以外は平置き)。未初期化ブロック (.bss) はファイルに実体が無いので出しません。
  ★**読むのは実行ファイルが許可ルート (`extracted/`・`dumps/`・`source_roots`) の
  配下にあるときだけ**です (2026-10)。Ghidra に取り込んだ元ファイルが素材フォルダ等
  プロジェクトの外にあるなら、人間が `bridge_config.json` に
  `"source_roots": ["<そのフォルダ>"]` を書き足してください (再起動は不要)。
  `program.json` の場所を自動で許可することはしません。
- **Ghidra のラベルとデータ定義も export します**(`labels.json` /
  `defined_data.json`)。これが無いと、人間が Ghidra で名付けたものも
  `apply_labels.py` で付けたラベルも AI から見えませんでした。
  **既存プロジェクトは再 export が必要**です(`export_only` を使っているなら
  `"labels"` と `"defined_data"` を追加)。
- **構造体・クラスのレイアウトも export します**(`datatypes.json`、2026-09)。
  `find_field` / `get_struct_layout` はこれを読みます。`program.json` には
  エントリポイントと Ghidra の gp コンテキスト値も出ます。**既存プロジェクトは
  再 export が必要**です(`export_only` を使っているなら `"datatypes"` と
  `"program"` を追加)。無くても他のツールは今までどおり動きます。
- **Ghidra は日本語文字列をほとんど拾えません。** `find_text` で拾い直し、
  `as_proposal=true` で `proposed_comments.json` の形にして
  `apply_comments.py` から Ghidra へ戻せます（コメントとして。**文字列データ型の
  適用は常に禁止**）。独自符号は `decode_text` に文字対応表を渡します。
- **`decompress` / `render_tiles` / `render_tim` だけはファイルを書きます**（展開データ / PNG は
  応答に載せられないため）。書き先は `<project_root>/extracted/` 配下に限定で、
  既存ファイルは上書きしません。`ghidra_exports/` には書きません。
- ★**これらの `source_path` で読めるのは許可ルートの配下だけ**です
  （既定 `<project_root>/extracted/` と `<project_root>/dumps/`）。
  外部の素材フォルダを読ませたいときは、**人間が** `bridge_config.json` に
  `"source_roots": ["C:\\RE\\game_analysis\\GAME_A\\materials"]` のように書きます。
  MCP の引数から許可範囲を広げる手段はありません。判定は resolve 後のパスで行い、
  `..` / リンク / ジャンクション / UNC / デバイスパスでの脱出は拒否します。
  読む量・展開後サイズ・画像サイズには絶対上限があります
  （詳細は [docs/safety_rules.md](docs/safety_rules.md)）。
- ★**読み取りでも境界を確かめます**（2026-10）: `ghidra_exports/` などの基準フォルダや
  個別ファイルが**プロジェクトの外を指すリンク / ジャンクションなら読みません**
  （プロジェクト内に収まるリンクは使えます）。UNC / デバイスパスは触る前に拒否し、
  JSON・memory・実行ファイルなどは丸ごと読む前に大きさで断ります。
  `find_compressed_blocks` は走査量・試行回数・展開量の予算で打ち切り、そのときは
  `complete: false` と未検査範囲を返します（「候補なし」ではありません）。
  `list_export_snapshots` / `diff_exports` は**フォルダを作りません**。
  上限の値と防げないものは [docs/safety_rules.md](docs/safety_rules.md)「リンク・UNC・大きさの扱い」。

### MCP サーバの登録

この公開コピーだけで登録できます（別の管理ツールは要りません）。どちらの方式も
**サーバは読み取り専用**で、Ghidra には接続しません。

#### 方式 A: 1 サーバで全 Program を扱う（推奨）

1. レジストリ（JSON）を作ります。書式は
   [`samples/mcp_registry.sample.json`](samples/mcp_registry.sample.json):

   ```json
   {
     "default_program": "game_a",
     "games": {
       "game_a": {"root": "C:\\RE\\ai_workspaces\\GAME_A", "label": "ゲームA"},
       "game_b": {"label": "ゲームB", "programs": {
         "main":    {"root": "C:\\RE\\ai_workspaces\\GAME_B",         "label": "EXE 本体"},
         "overlay": {"root": "C:\\RE\\ai_workspaces\\GAME_B\\overlay", "label": "実行時オーバーレイ"}}}
     }
   }
   ```

   `root` は各ゲームの AI_WORKSPACE（`ghidra_exports/` の親）です。
2. MCP クライアントに登録します（Claude Code の例。パスは自分の環境に合わせる）:

   ```
   claude mcp add ghidra-readonly -- python C:\path\to\ghidra_toolbox\mcp\ghidra_readonly_mcp.py --registry C:\RE\mcp_registry.json
   ```

   `.mcp.json` に書く場合:

   ```json
   {"mcpServers": {"ghidra-readonly": {
     "command": "python",
     "args": ["C:\\path\\to\\ghidra_toolbox\\mcp\\ghidra_readonly_mcp.py",
              "--registry", "C:\\RE\\mcp_registry.json"]}}}
   ```

   `--registry` の代わりに環境変数 `CCT_MCP_REGISTRY` でも指定できます。
   `--multi` だけを付けると、道具箱の 1 つ上のフォルダの `mcp_registry.json` を読みます。

- 各ツールに `program` 引数（`"game_a"` / `"game_b:main"` など）を渡します。
  **省略すると直前に使った Program → レジストリの `default_program` の順で決め、
  応答に `program_defaulted: true` を付けます**。どちらも無ければ候補を列挙してエラーに
  なります。**応答には必ず `program` が入ります**（黙って別ゲームを読まないための仕様）。
  `list_programs` でキーを確認できます。
- **ゲームを追加しても reconnect 不要**（レジストリの更新を検知して、次の呼び出しで読み直します）。
  JSON を書き損じてもサーバは落ちず、直前の内容で動き続けます
  （理由は `list_programs` の `registry_warning` に出ます）。
- `list_programs` の `exports_found` は `ghidra_exports\program.json` の有無で判定します
  （空の `ghidra_exports\` だけでは `false`）。
- 常駐 Program 数は LRU で既定 3（環境変数 `CCT_MAX_HOT_PROGRAMS`）。

#### 方式 B: 1 Program 専用に起動する（従来どおり）

環境変数 `CCT_PROJECT_ROOT`（=そのゲームの AI_WORKSPACE）か第 1 引数で、
1 Program 専用に起動します。この場合 `program` 引数は省略できます。

```
claude mcp add ghidra-game-a -e CCT_PROJECT_ROOT=C:\RE\ai_workspaces\GAME_A -- python C:\path\to\ghidra_toolbox\mcp\ghidra_readonly_mcp.py
```

### 1 ゲームに複数 Program がある場合（EXE 本体 / オーバーレイ / メモリダンプ）

**1 ゲーム = 1 root のままオーバーレイを export すると、EXE 側の `ghidra_exports` を
上書きしてしまい、MCP も xrefs も EXE 側を引けなくなります**（実際に踏んだ事故）。
Program ごとに root（= `ghidra_exports` の親）を分け、レジストリでは上の `game_b`
のように `programs` で両方登録してください。キーは `game_b:main` / `game_b:overlay`
（`ゲーム:Program`）になります。

- キャッシュは mtime 自動リロード。**再 export 後もサーバ再起動なしで最新を返す**
  （`get_decompiled_function` は decompile/ をディスク直読みするので特に確実）。
- 詳細は [mcp/README.md](mcp/README.md)。

## 使い方（要点）

新規ゲームを丸ごとセットアップするときは、**[templates/new_game_setup_prompt.md](templates/new_game_setup_prompt.md)**
の「プロンプト本文」を Claude Code に貼るのが早い（ディレクトリ雛形→bridge_config→MCP登録→export→検証まで）。
既にセットアップ済みのゲームで解析を始める/再開するときは
**[templates/session_start_prompt.md](templates/session_start_prompt.md)** を貼る。
どちらも、貼る前に《 》の placeholder を自分の値に書き換えます。

- **（任意）**の項目を使わないときは、その行（`【…】`見出しにある場合はブロックごと）を消す。
- **必須の項目は空のまま残さない。** 埋め忘れると冒頭の「このセッションは〜です」が
  意味をなさず、AI が何のセッションか分からないまま動き出す。

> ★**この 2 つは別物**。取り違えると、セットアップのつもりで
> 「ROM の解析を始める」プロンプトを貼ることになる。どちらのプロンプトにも
> 冒頭に **「Ghidra 本体を起動しない（`analyzeHeadless` 含む）」** を明記してある —
> `ghidra_scripts/` は**すべて人間が Ghidra GUI で実行する**もので、
> AI がやるのは手順の提示までです。

以下は各ステップの単体手順。

### 1. ghidra_scripts を Script Manager に登録

1. Ghidra GUI で対象 Program を開く。
2. **Window > Script Manager** → **Manage Script Directories** → このリポジトリの
   `ghidra_scripts` を **Add**。
3. `export_context.py` / `apply_comments.py` / `apply_functions.py` 等が見える
   （カテゴリ `ClaudeToolbox`）。見えなければ更新ボタン。

### 2. ゲーム用プロジェクトを作る

```
python tools\make_game_project.py <AI_WORKSPACE>
```

作成後 `bridge_config.json` を編集（`game_name` / `platform` / `platform_profile` /
`source_model` / `ghidra_program_source` / `ghidra_version` / `ghidra_path` /
`allowed_apply_operations`）。**`address_basis` は最初 `unknown`**、export 後に
program.json の image_base/memory_blocks で確定する。

### 3. export_context.py を実行（Ghidra GUI）

Script Manager で実行 → 出力先に AI_WORKSPACE を選ぶ → `ghidra_exports/` に出力:

```
ghidra_exports/
  program.json / functions.json / strings.json / comments.json
  xrefs.json / undefined_ranges.json
  decompile/        関数ごとの疑似C（上限あり）
  memory_map.json / memory/*.bin   メモリイメージ（opt-in。既定では出ない）
  export_log.txt
```

#### メモリイメージ関連の bridge_config キー
（`get_disassembly` / `find_address_refs` / `read_data` を使うとき）

未関数化 (`LAB_xxxxxxxx`) のコードは疑似C が無いので `get_decompiled_function` では
読めません。MCP の `get_disassembly`（**生の逆アセンブル**）、`find_address_refs`
（**Ghidra が xref を持たないテーブルの参照元探し**）、`read_data`
（**見つけたテーブルの中身を読む**）を使うには、先にメモリ
イメージを export しておく必要があります（MCP は Ghidra に問い合わせず、この
イメージをデコードするだけ）。

| キー | 既定 | 意味 |
|---|---|---|
| `export_memory` | `false` | **opt-in**。true で `memory/<block>.bin` + `memory_map.json` を出力 |
| `export_memory_max_mb` | `32` | 1 ブロックあたりの上限。超えたブロックはスキップして理由を記録 |
| `export_memory_total_max_mb` | `128` | 全ブロック合計の上限 |
| `export_memory_blocks` | `[]`(全部) | 出力するブロック名のリスト |

> 未初期化ブロックは常に出力しません。旧 `*_instructions.json`（各 380MB）の
> 二の舞にしないため上限は必ず効かせます（生バイナリなので 16MB のダンプなら 16MB）。
> **逆アセンブルの対応アーキは MIPS (R3000/R5900) / SuperH (SH-4/SH-2) /
> ARM・Thumb (ARMv4T) / PowerPC (Gekko/Broadway) / 65816**。それ以外は未対応と
> 明示エラー。`read_data` はアーキに依らず使えます
> （endian だけ見るので、未対応アーキの Program でもテーブルは読めます）。

> ★**全域 decompile は絶対にしない**（病的関数1個で Ghidra が無限ハング）。特定関数は
> `decompile_targets`、帯域は `decompile_start/end` を狭く。

#### decompile 関連の bridge_config キー

| キー | 既定 | 意味 |
|---|---|---|
| `decompile_targets` | `[]` | **推奨**。entry アドレスのリスト。指定するとその関数だけを decompile し `start/end/limit` は無視。病的関数を踏まずに目的の関数だけ安全に取れる |
| `decompile_start` / `decompile_end` | `null` | 帯域指定モード（`targets` が空のときのみ有効）。狭く切ること |
| `decompile_scope` | `"ask"` | ★**実行前に対象範囲を選ばせる**。`ask` は export を始める前にダイアログで「上限 N 件だけ / 全関数 / decompile しない」を聞く（decompile は最後の工程なので、走らせてから足りないと気づくと xrefs まで含めてやり直しになるため）。`limit` / `all` にすると聞かずにそれぞれ設定どおり / 全関数。`decompile_targets` があるときは聞かない。ダイアログを出せない環境では設定どおり |
| `decompile_limit` | `0`(無制限) | 帯域モードでの件数上限。**`targets` も `start/end` も無指定なら必ず小さい値を入れる**（無制限＝全域 decompile になり危険） |
| `decompile_timeout_seconds` | `20` | 1関数あたりの Ghidra 側タイムアウト。**「協調的」なので病的関数には効かないことがある** |
| `decompile_hard_timeout_seconds` | `timeout + 15` | ★**保険**。上記が効かなかったとき、decompile スレッドを見捨てて次の関数へ進む秒数。`0` 以下で無効 |
| `decompile_skip_uninitialized` | `true` | ★**未初期化ブロックの関数を対象から外す**。バイト実体が無いので得るものが無く、踏むと Ghidra ごと固まる。**外さないこと** |
| `decompile_skip_tiny` | `true` | ★body が 1 バイトの関数を対象から外す（PSY-Q の GTE マクロ用ダミー等） |
| `decompile_max_output_kb` | `512` | `getC()` の出力がこれを超えたら書き込まずに skip。`0` 以下で無効 |
| `decompile_verbose` | `false` | `true` で 1 関数ごとに `decompile start` をログへ。**固まったときログ末尾で犯人が分かる** |
| `decompile_line_map` | `true` | ★**疑似 C の行 → 命令アドレスの対応表**を `decompile/<関数>_<entry>.lines.json` に出す。`get_decompiled_function(with_addresses=true)` が使う。**この対応は decompiler のマークアップからしか取れないので、後から作れない**。失敗しても decompile 自体は止めない |
| `export_decompile` | `true` | `false` で decompile 工程を丸ごとスキップ（既存 `decompile/` は残置） |
| `export_only` | `[]`(全部) | ★**実行する工程を選ぶ**。`["decompile"]` なら decompile だけ作り直し、他は既存ファイルを残置 |

> **`export_only` の使いどころ**: 「関数化 → 再 export → 疑似C を読む」の往復。
> decompile だけ更新したいのに `xrefs.json`（大きい Program では数十 MB）まで毎回作り直すのは無駄です。
> 指定できるのは `program` / `memory` / `functions` / `strings` / `comments` /
> `xrefs` / `undefined_ranges` / `decompile`。未知の名前は**警告して無視**します
> （タイプミスで全工程が黙って飛ぶのを防ぐため）。既存の `export_xrefs` 等のフラグとは
> AND で効きます。

> **ハードタイムアウトについて**: Ghidra の decompile 本体は別の native プロセスで動く。
> ハードタイムアウト時は `stopProcess()` でそれを強制終了し、`DecompInterface` を作り直して
> **export を継続**する（ログに `hard_timeout=N` と警告が出る）。
> ただしこれは**保険であって全域 decompile の解禁ではない**。`hard_timeout` が出た関数は
> 病的関数の可能性が高いので `decompile_targets` から外すこと。

> ⚠️ **ハードタイムアウトが守るのは `decompileFunction()` の中だけ**です。
> **decompile が成功して戻ったあと、`getC()` や書き込み側で固まる事例が実在します**
> （未初期化ブロックのダミー関数で 30 分フリーズし、強制終了した実例があります）。
> そのため上の `decompile_skip_*` ガードが既定で有効です。
> 完了ログに `skipped_uninitialized=N skipped_tiny=N skipped_huge=N` が出ます。
> なお `export_log.txt` は **1 行ごとに flush** されるので、途中で固まっても
> そこまでのログが残ります（進捗は 50 件ごと。`decompile_verbose` で毎件に）。

### 4. Claude で解析

AI_WORKSPACE を Claude Code で開き、同梱 `CLAUDE.md` に従う。`ghidra_exports/` +
`dumps/` + `notes/address_map.md` を突き合わせ、`notes/*.md` に確定/不明を分けて記録。

### 5. 提案 JSON を作る → 検証

- コメント: `proposals/proposed_comments.json`（`schemas/proposed_comments.schema.json`）。
  必ず `[AI]` 始まり、`confidence`(low/medium/high)、`address_basis`(ghidra/runtime/dump_offset/unknown)。
- 関数化: `proposals/proposed_functions.json`（`schemas/proposed_functions.schema.json`）。
  `operation:"define_function"`、`entry`/`address`、`platform`、必要なら `mode`(ARM/Thumb)。
  apply はリネームせず `FUN_<addr>` になる（`name_hint` は参考のみ）。
- 命名（ラベル）: `proposals/proposed_labels.json`（`schemas/proposed_labels.schema.json`）。
  `address` / `name` / `reason` / `confidence` / `evidence`、必要なら `force`。
  **`allowed_apply_operations` に `"labels"` が要る opt-in 機能。**

```
python tools\validate_proposed_comments.py proposals\proposed_comments.json
python tools\validate_proposed_functions.py proposals\proposed_functions.json
python tools\validate_proposed_labels.py proposals\proposed_labels.json
```

### 6. apply（Ghidra GUI, 人間がトリガ）

| スクリプト | 何を変えるか | 必要な `allowed_apply_operations` |
|---|---|---|
| `apply_comments.py` | `[AI]` 始まり かつ `address_basis` が ghidra/未指定 のコメントだけ | 不要（既定で許可） |
| `apply_functions.py` | `define_function`（protect チェック + 台帳記録） | **`"functions"`** |
| `apply_undefine.py` | 関数の削除・コードのクリア（台帳記録） | **`"undefine"`** |
| `apply_labels.py` | `set_label`（下の縛りあり） | **`"labels"`** |
| `apply_snes_context.py` | 65816 の DP / DBR | **`"context"`** |
| `revert_operations.py` | 台帳の記録を巻き戻す | 不要（台帳の照合あり） |

> Ghidra 本体だけでは扱えない機種は、外部の拡張が要ります（例: SFC / 65816 は ghidra-snes）。
> `apply_snes_context.py` は ghidra-snes の 65816 言語の Program 専用で、それ以外の Program では
> 何もしません。

- 許可が無い・`bridge_config.json` が壊れている・型が不正なら、**何も変更せずに終了**します
  （`apply_functions.py` / `apply_undefine.py` も 2026-10 からこの判定をします）。
- ★**`target_program` が今開いている Program 名と一致しない、または無い・空なら、
  すべてのスクリプトが変更前に中止します**（警告だけで続行しません）。共有台帳
  `defined_functions.json` が壊れている / 別 Program 用のときも中止します（上書きしない）。
  名前の一致しか見ていないので、同名の別 Program までは区別できません。
  古い提案・台帳の移行方法は [docs/safety_rules.md](docs/safety_rules.md)「対象 Program の照合」。
- どのスクリプトも Program を保存しません（確認して Ctrl+S するのは人間）。
- 反映後に **export_context.py を再実行**すると、新しく関数化したエントリが decompile される。
- 誤りは `apply_undefine.py` / `revert_operations.py` で戻す（label も巻き戻せる）。

#### ラベル付け（`apply_labels.py`）の縛り — 他の apply より強い

ラベル付けは **実質リネーム** なので、既定では完全に無効です。

| 縛り | 内容 |
|---|---|
| opt-in 必須 | `allowed_apply_operations` に `"labels"` が無ければ**何もせず終了**（トランザクションも開かない） |
| 既存名を上書きしない | `USER_DEFINED` / `IMPORTED` / `ANALYSIS` な既存シンボルは SKIP。`force: true` のときだけリネームし**元の名前を台帳に記録** |
| 自動名は上書き可 | `LAB_xxxx` / `DAT_xxxx`（dynamic / `DEFAULT` ソース）は人間の成果ではないので `force` 無しで可 |
| **関数エントリは拒否** | `force` でも拒否。**関数名の自動変更は常に禁止**なので、ラベル経由の実質リネームも塞ぐ |
| 名前の形式 | 英数字と `_` のみ（先頭は英字か `_`、128 文字以内）。`FUN_`/`LAB_`/`DAT_`/`switchD_` 等の接頭辞は拒否 |
| 巻き戻し | 台帳に `operation:"set_label"` で記録。新規なら削除、`force` リネームなら元の名前へ復元。**現在の名前が記録時と違えば SKIP**（人間が直したとみなす） |

```
:: 許可する場合は bridge_config.json をこうする
::   "allowed_apply_operations": ["comments", "labels"]
:: 提案は apply の前に検証ツールに通す
python tools\validate_proposed_labels.py proposals\proposed_labels.json
```

## 応用: オーバーレイ / ダンプ由来コードの解析

静的 EXE に含まれない**オーバーレイ（実行時ロードのコード）**は、そのオーバーレイが載った
RAM ダンプから当該領域を切り出し、Ghidra に **別 Program（Raw Binary, 正しいベースアドレス）**
として読み込む → Auto Analyze → `proposed_functions.json` で関数化 → export、で疑似C 化できる。
GUI の具体的な操作 (言語・ベースアドレスの指定、入口での G → D → F) は
[docs/ghidra_gui_overlay_import.md](docs/ghidra_gui_overlay_import.md) を参照。

> ⚠️ **別 Program にしたら export 先も分けること。** `export_context.py` は選んだ
> フォルダ配下の `ghidra_exports/` を**上書き**するので、EXE 本体と同じ AI_WORKSPACE に
> オーバーレイを export すると **EXE 側の `ghidra_exports` が消えます**（MCP も xrefs も
> EXE 側を引けなくなる。実際に踏んだ事故）。

```
ai_workspaces\GAME_B\                 ← Program 1: EXE 本体。export 先はここ
  bridge_config.json / ghidra_exports\ / notes\ / proposals\
  overlay\                            ← Program 2: オーバーレイ。export 先はこっち
    bridge_config.json / ghidra_exports\
```

`notes/` と `proposals/` は親（EXE 側）に集約してよい。分けるのは
**`ghidra_exports/` とその親フォルダ**、そして `bridge_config.json`（Program ごとに
`source_model` / `address_basis` / `platform_profile` が違うため）。
`mcp_registry.json` には `programs` で 2 つとも登録する（前節参照）。

### データだけのファイル（ステージデータ / 高さテーブル）は `overlays` で十分

上のやり方は**オーバーレイの「コード」を疑似C 化したいとき**のものです。
ステージデータや地形の高さテーブルのように **データしか入っていないファイル**なら、
Ghidra へ別 Program として読み込むまでもありません。`bridge_config.json` に

```json
"overlays": [
  {"name": "stage01", "path": "dumps/STAGE01.BIN", "base": "0x801c0000",
   "note": "実行時に 0x801c0000 へ読み込まれる", "scan": true}
]
```

と書けば、MCP がそのファイルを「この番地に置かれたもの」として扱い、
`read_data` / `find_bytes` / `describe_data` / `classify_range` /
`find_pointers_to` が **EXE 内の表と同じように**その範囲で効きます
（`list_overlays` で登録状況と、Program のブロックとの重なりを確認できます）。

- `path` は**プロジェクトフォルダの中**だけ（外へは出られません）。
- `offset` / `length` でファイルの一部だけを載せられます（ヘッダを飛ばす等）。
- Program のブロックと範囲が重なる場合、**読み出しはオーバーレイ側が優先**されます
  （登録した方が正）。走査系で二重に出るのが邪魔なら `"scan": false`。
- 応答の `block` は必ず `overlay:<名前>` になるので、**Program 本体の値と混ざりません**。
- **MCP は overlays を読むだけ**で、ファイルにも Ghidra にも書きません。

## Ghidra バージョン運用

- Ghidra は上書き更新せず、バージョンごとに別フォルダへ展開。
- ゲームごとに `bridge_config.json` の `ghidra_version` / `ghidra_path` を記録。
- 新バージョンはプロジェクトをコピーしてから開く。詳細 [docs/ghidra_version_policy.md](docs/ghidra_version_policy.md)。

## 入力ソースの多様性

対象は実行ファイルとは限らない（raw binary / メモリダンプ / ROM / overlay / 複数 Program）。
`export_context.py` は現在開いている `currentProgram` の情報を可能な範囲で export する。
アドレス基準は `notes/address_map.md` と `bridge_config.json` の `source_model` で管理する。

## 安全方針（要点。詳細 docs/safety_rules.md）

- やってよい: export / 読み取り / メモ作成 / `[AI]` コメント案 / 確認後のコメント反映 /
  **opt-in の関数化・未定義化・ラベル付け**。
- **既定で禁止（明示 opt-in でのみ限定許可）**: 関数作成 (`"functions"`) ・
  未定義化 (`"undefine"`) ・**ラベル付け (`"labels"`)**。
- **常に禁止**: 関数名の自動変更（リネーム）・データ型変更・配列化・構造体適用。
  ラベル付けが関数エントリを `force` でも拒否するのはこのため。
- apply は必ず人間がトリガ。自動保存しない。既存の人間コメントは消さない。
- MCP は Ghidra に書かない。**書くのは `decompress` / `render_tiles` / `render_tim` の生成物と
  スナップショットだけ**で、`<project_root>/extracted/` の配下に限定（上書きもしない）。
- MCP が `source_path` で読むのは許可ルート（`extracted/` / `dumps/` / 人間が書いた
  `source_roots`）の配下だけ。

## 最小の動作確認（Ghidra 無しで確認）

```
:: 検証ツールがサンプルを通す
python tools\validate_proposed_comments.py samples\proposed_comments.sample.json
python tools\validate_proposed_functions.py samples\proposed_functions.sample.json
python tools\validate_proposed_labels.py samples\proposed_labels.sample.json
python tools\validate_proposed_context.py samples\proposed_context.sample.json

:: プロジェクト雛形を作れる
python tools\make_game_project.py %TEMP%\cct_test_project

:: MCP サーバの自己テスト（SDK 不要。手元の既存 exports を指す）
::   デコーダの単体テスト ([8] 系) は exports の中身に関係なく必ず走る
set CCT_PROJECT_ROOT=<既存ゲームの AI_WORKSPACE>
python mcp\ghidra_readonly_mcp.py --selftest
```

export / apply（Ghidra API 依存）は GUI で手動実行して確認する。

## ライセンスと権利について

- **0BSD（Zero-Clause BSD）** です（[LICENSE](LICENSE)）。使用・複製・改変・再配布は、
  有償・無償を問わず自由です。著作権表示を残す義務もありません。
  **無保証**で、このツールの使用によって生じた損害について作者は責任を負いません。
- この道具箱には ROM / BIOS / ゲームのデータ・export・解析ログを含めていません。
- 依存: `mcp`（MIT）/ `Pillow`（MIT-CMU）。`Pillow` は 12.3.0 以上、`mcp` は 1.28.1 以上を推奨します
  （それより前の版には修正済みの既知の脆弱性があります）。
- 解析対象の入手と利用は、利用者がそれぞれの法令・権利者の規約に従って行ってください。
