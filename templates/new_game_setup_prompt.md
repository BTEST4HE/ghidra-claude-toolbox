# 新規ゲーム Ghidra+MCP セットアップ用 テンプレートプロンプト

新しいゲーム (PS2 / SS / GBA 等) を解析し始めるとき、下の「プロンプト本文」を
**そのゲームの ai_workspace をルートにした Claude Code セッション**に貼る。
先に《 》の placeholder を埋めること。この道具箱一式
(toolbox / mcp_registry / platform_profiles) を前提にしている。

---

## 1. 記入する placeholder

| placeholder | 例 | 説明 |
|---|---|---|
| 《GAME_KEY》 | `game_a` | 一意な短いキー。**mcp_registry のキー = MCP ツールの program 引数に渡す値** |
| 《GAME_NAME》 | `ゲームA` | 正式名 |
| 《PLATFORM》 | `Dreamcast (SH-4)` | 機種 |
| 《PLATFORM_PROFILE》 | `sh4` | platform_profiles/<これ>.json (下表参照。無ければ作る) |
| 《AI_WORKSPACE》 | `C:\RE\ai_workspaces\GAME_A` | ①AI作業ルート (CLAUDE.md/bridge_config/ghidra_exports/notes…の親) |
| 《MATERIALS_DIR》 | `C:\RE\game_analysis\GAME_A\materials` | ②ROM/メモリダンプ等の素材置き場 |
| 《GHIDRA_PROJECT_DIR》 | `C:\RE\ghidra_project\GAME_A` | ③Ghidra プロジェクト (.gpr/.rep) の置き場 |
| 《SOURCE_MODEL》 | `memory_dump` | executable / raw_binary / rom / memory_dump / overlay / mixed / unknown |
| 《GHIDRA_PROGRAM》 | `game_a_dump.bin (Raw Binary)` | Ghidra で開いている Program の由来 |

※ アドレス基準 (address_basis) は**最初は記入しない**。Ghidra で export するまで分からないので、
bridge_config では `unknown` にしておき、export 後に program.json の image_base/memory_blocks で確定する (手順 F)。

④**Ghidra MCP の場所は全ゲーム共有・固定** (placeholder 不要):
`C:\path\to\ghidra_toolbox\mcp\ghidra_readonly_mcp.py`。
★1 サーバ方式では **サーバも 1 個で固定** (`ghidra-readonly`)。ゲームごとに変わるのは
ツールに渡す `program` の値だけ。対応表は mcp_registry.json が持つ。

### ディレクトリ 4 ルート構成 (推奨の運用)
```
①AI作業       《AI_WORKSPACE》        … CLAUDE.md / bridge_config.json / ghidra_exports / dumps / notes / proposals
②素材         《MATERIALS_DIR》       … ROM / メモリダンプ / カード等 (容量大。AI作業とは分離)
③Ghidraプロジェクト 《GHIDRA_PROJECT_DIR》 … .gpr / .rep (Ghidra が管理。AI は直接編集しない)
④MCP/道具箱   (共有・固定)            … この道具箱。MCP は 1 サーバ共有 (program 引数で切替)
```
規約: `<RE_root>\<route>\<board>\<GAME>` (例 board=dc/ps2/saturn…)。①②③ は route が違うだけで同じ枝。

### プラットフォーム早見表 (platform_profile / 基準)

| 機種 | profile | arch | endian | return | 代表ベース |
|---|---|---|---|---|---|
| Dreamcast/NAOMI | `sh4` | SH-4 | LE | rts/rte | 0x8C000000(DC) |
| PS1 | `psx` | MIPS R3000 | LE | jr ra | EXE 0x80010000 |
| PS2 | `ps2` | MIPS R5900(EE) | LE | jr ra | EE RAM 0x00100000〜 |
| SS (Saturn) | `saturn` | SH-2 ×2 | **BE** | rts | HWRAM 0x06000000 / LWRAM 0x00200000 |
| GBA | `gba` | ARM7TDMI | LE | bx lr / pop{pc} | ROM 0x08000000 |
| GC/Wii | `wii` | PowerPC | BE | blr | 0x80000000 |

※ 上記 profile は `platform_profiles/` に**すべて実在**（psx/ps2/saturn/sh4/gba/wii）。
  新機種のときだけ手順 C で新規作成する。既存例: PS1 は `psx`、PS2 は `ps2`。

---

## 2. プロンプト本文 (ここから下を貼る)

```
このセッションは新規ゲーム《GAME_NAME》(《PLATFORM》) の Ghidra 解析セットアップです。
道具箱: C:\path\to\ghidra_toolbox
レジストリ: MCP サーバを `--registry <path>` で起動しているならそのファイル
(`--multi` だけなら道具箱の 1 つ上の mcp_registry.json。書式は samples/mcp_registry.sample.json)

前提パラメータ (4 ルート):
- GAME_KEY = 《GAME_KEY》
- AI_WORKSPACE        = 《AI_WORKSPACE》        # ①AI作業 (このセッションのルート)
- MATERIALS_DIR       = 《MATERIALS_DIR》       # ②ROM/メモリダンプ素材置き場
- GHIDRA_PROJECT_DIR  = 《GHIDRA_PROJECT_DIR》  # ③Ghidra プロジェクト置き場
- (MCP/道具箱は共有固定: 上の道具箱。1 サーバ方式なので
   ツールには program=《GAME_KEY》 を渡す)
- PLATFORM_PROFILE = 《PLATFORM_PROFILE》
- SOURCE_MODEL = 《SOURCE_MODEL》
- GHIDRA_PROGRAM = 《GHIDRA_PROGRAM》
- (address_basis は最初 unknown。export 後に program.json で確定する)

【このセッションでやらないこと（最初に確認）】
- **Ghidra 本体を起動しない。** `ghidraRun` / `analyzeHeadless` / Ghidra の
  スクリプトを AI が実行することはない。`ghidra_scripts/` の
  export_context.py / apply_*.py は**すべて人間が Ghidra GUI の
  Script Manager から実行する**。AI がやるのは手順の提示まで。
- **.gpr / .rep を作らない・触らない。** Ghidra プロジェクトは人間が作る。
- **ROM / メモリダンプの解析を始めない。** これはセットアップのセッションで、
  中身を読むのは export が済んで MCP が繋がってからの別セッション
  (session_start_prompt.md) の仕事。ここでやるのは
  「ディレクトリ・設定・登録・疎通確認」だけ。

次を順に行ってください (Ghidra GUI 操作は人間がやるので手順提示に留める):

【A. ディレクトリ・雛形】
1. 4 ルートの存在確認、無ければ最小作成 (既存は上書きしない):
   - ①《AI_WORKSPACE》 … 解析プロジェクト本体を作る。toolbox の
     tools/make_game_project.py があればそれで雛形生成、無ければ
     templates/game_claude_project/ を参考に手動作成:
     CLAUDE.md / bridge_config.json / ghidra_exports/ / dumps/ / notes/address_map.md / proposals/。
   - ②《MATERIALS_DIR》 … ROM/ダンプ素材置き場 (無ければ空フォルダ作成。中身は人間が置く)。
   - ③《GHIDRA_PROJECT_DIR》 … 空フォルダ作成のみ。**.gpr/.rep は Ghidra が作るので AI は触らない**。

【B. bridge_config.json】
   次のキーを埋める (判断不能は unknown、勝手に断定しない):
   - game_name=《GAME_KEY》, platform=《PLATFORM》, platform_profile=《PLATFORM_PROFILE》
   - source_model=《SOURCE_MODEL》, ghidra_program_source=《GHIDRA_PROGRAM》
   - address_basis="unknown" (最初は確定しない。export 後に program.json の
     image_base/memory_blocks を見て確定し、notes/address_map.md と合わせて埋める ← 手順 F)
   - ghidra_exports_dir="ghidra_exports", dumps_dir="dumps"
   - **4 ルートのパスを roots/paths に記録** (ツール/スクリプトの読み元):
     roots = { ai_workspace:《AI_WORKSPACE》, materials:《MATERIALS_DIR》, ghidra_project:《GHIDRA_PROJECT_DIR》 }
     paths = { materials_dir:《MATERIALS_DIR》, ghidra_exports_dir, dumps_dir, … 必要に応じ rom_dir 等 }
   - toolbox_schema_version="0.1", allowed_apply_operations=["comments"]
   - decompile_start=null, decompile_end=null, decompile_timeout_seconds=15,
     decompile_hard_timeout_seconds=30, decompile_limit=20, decompile_targets=[],
     decompile_scope="ask"
     (★全域 decompile は禁止。後で範囲か targets を指定する。理由は道具箱 README の「decompile 関連の bridge_config キー」。
      decompile_limit は「targets も start/end も未指定」のときの暴走止めなので 0=無制限に
      しないこと。decompile_hard_timeout_seconds は病的関数を踏んだとき Ghidra ごと
      フリーズせず次へ進むための保険。
      ★decompile_scope="ask" だと、export_context.py が **走り出す前に**
      「上限 20 件だけ / 全関数 / decompile しない」を聞いてくる。初回は上限つきで
      全体を眺め、対象が絞れてから targets を指定するのが安全。毎回同じでよいなら
      "limit" (聞かない) / "all" (全関数) にする)
   - export_xrefs=true, export_undefined_ranges=true

【C. platform_profile】
   platform_profiles/《PLATFORM_PROFILE》.json が無ければ作る。
   return 判定は FlowType.isTerminal() (アーキ非依存) なので return ニーモニックは
   持たせない。mode を持つアーキ (ARM/Thumb 等) のみ mode_required=true +
   context_register + mode_values を設定する。endian は早見表参照。

【D. MCP 登録 (グローバル集中・★1 サーバ方式)】
   ★ 現在の推奨は「全 Program 共通の 1 サーバ (ghidra-readonly)」。
     ゲームを増やしても **MCP のオプションもツール定義も増えない**
     (per-game 方式だと 13 Program × 16 ツール = 208 個の定義が載る)。

   1. mcp_registry.json の games に **追加するだけ**:
      "《GAME_KEY》": {"root":"《AI_WORKSPACE》","label":"《GAME_NAME》"}
      ※ 1 サーバ方式では "server" キーは不要 (書いてあっても無害)。
   2. **reconnect は不要。** 1 サーバ版はレジストリの更新を検知して読み直すので、
      次の呼び出しから list_programs に出る。まず list_programs で 《GAME_KEY》 が
      見えることを確認する。
      出ないときは、応答の registry_warning を見る (JSON の書き損じ。直して保存し直せば
      次の呼び出しで読み直す)。warning も無いのに出なければ、サーバが読み直し対応前の
      コードで動いているので、人間に「/mcp で ghidra-readonly を reconnect」を案内する。
      ※ export 前の Program は exports_found=false (空の ghidra_exports/ だけでも false)。
   3. 以降、各ツールに **program="《GAME_KEY》" を必ず渡す**。省略すると
      「使えるキー」を列挙したエラーになる (黙って別ゲームを読まないための仕様)。
      応答にも program が入るので、取り違えたらその場で気づける。

   ※ 1 サーバ版 (ghidra-readonly) がまだ MCP クライアントに登録されていなければ、
     人間に **1 回だけ** 道具箱 README の「MCP サーバの登録」を案内する (登録後 /mcp で reconnect)。
   ※ per-game 方式 (ゲームごとに 1 サーバ) も引き続き動く。使う場合は
     CCT_PROJECT_ROOT=《AI_WORKSPACE》 でサーバを 1 つ登録する (README 参照)。
     このときは program 引数を省略できる。
   ※ project .mcp.json は作らない (グローバル一本化)。
   ※ 最初から Program が複数 (EXE本体 + オーバーレイ + ダンプ 等) と分かっている場合は
      programs 形式で登録する (下の【D2】)。1つだけなら上の形式でよい。

【D2. 1ゲームに複数 Program がある場合 — export 先の分け方】
   ★ export_context.py は選んだフォルダ配下の ghidra_exports/ を「上書き」する。
     したがって Program ごとに **root (=ghidra_exports の親) を分ける**。同じ
     AI_WORKSPACE に両方 export すると、後から export した方が前の ghidra_exports を
     消してしまい、MCP も xrefs も前の Program を引けなくなる (実際に踏んだ事故)。

   推奨レイアウト:
     《AI_WORKSPACE》\                  ← Program 1 (EXE本体)。export 先はここ
       CLAUDE.md / bridge_config.json / ghidra_exports\ / dumps\ / notes\ / proposals\
       overlay\                        ← Program 2 (オーバーレイ)。export 先はこっち
         bridge_config.json / ghidra_exports\
       dump\                           ← Program 3 (メモリダンプ) が要るならこう
         bridge_config.json / ghidra_exports\

   - 分けるのは ghidra_exports/ とその親、および bridge_config.json
     (Program ごとに source_model / address_basis / platform_profile が違う)。
   - notes/ と proposals/ は親に集約してよい (人間が読む資料なので分けない)。
   - レジストリは programs 形式で両方登録する:
       "《GAME_KEY》": {
         "label": "《GAME_NAME》",
         "programs": {
           "exe":     {"root": "《AI_WORKSPACE》",           "label": "EXE 本体"},
           "overlay": {"root": "《AI_WORKSPACE》\\overlay",  "label": "実行時オーバーレイ"}
         }
       }
     → **program キーは 《GAME_KEY》:exe / 《GAME_KEY》:overlay** になる。
       1 サーバ方式なら追加はこれだけ (reconnect 不要)。ツール呼び出しでは
       program="《GAME_KEY》:exe" のように Program まで指定する。
       per-game 方式の場合は Program ごとに CCT_PROJECT_ROOT を変えて
       サーバを登録する。
   - notes/address_map.md に「どの Program がどのアドレス基準か」を必ず書く
     (EXE は Ghidra addr=実行時 addr でも、オーバーレイの Raw Binary はベースを
      自分で指定しているので取り違えやすい)。

【E. Ghidra export (人間が GUI)】
   案内する手順:
   0. **Ghidra 12 以降なら Jython 拡張を入れる** (その Ghidra で未導入なら 1 回だけ):
      プロジェクト画面の File → Install Extensions → Jython にチェック → OK → 再起動。
      入っていないと「Ghidra was not started with PyGhidra. Python is not available」になる
      (詳細は docs/ghidra_version_policy.md)。起動は通常の ghidraRun でよい。
   1. Script Manager に toolbox の ghidra_scripts/ を登録 (未登録なら)。
   2. 対象 Program を開く。
   3. export_context.py を実行、出力 base に 《AI_WORKSPACE》 を選ぶ
      (→ 《AI_WORKSPACE》\ghidra_exports\ に JSON 群が出る)。

【F. 検証】
   1. list_programs に 《GAME_KEY》 が出て exports_found=true になっていることを確認。
      (1 サーバ方式なら reconnect 不要。per-game 方式なら reconnect 後に確認)
      exports_found は ghidra_exports\program.json があるかで判定する。false のままなら
      export の出力先に 《AI_WORKSPACE》 を選んだか (別のフォルダではないか) を確認する。
   2. get_export_status(program="《GAME_KEY》") / get_program_info(program="《GAME_KEY》")
      で疎通確認。**応答の program が 《GAME_KEY》 になっていること**も見る
      (別ゲームを読んでいないかの確認)。
   3. program.json の image_base / memory_blocks を見て、notes/address_map.md の
      「未確認」を埋める (Ghidra addr=実行時 addr か等)。

【守ること】
- 全域 decompile は絶対にしない (病的関数1個で Ghidra が無限ハング)。
  特定関数は decompile_targets、帯域は decompile_start/end を狭く。
  decompile_hard_timeout_seconds は保険であって、全域 decompile を解禁するものではない。
- getFunctions の昇順を仮定しない。
- アドレス基準 (Ghidra / 実行時 RAM / dump offset) を混同しない。不明は address_map に
  「未確認」と明記。
```

---

## 3. セットアップ完了後（＝ここまでで MCP 連携は完了）
手順 F で MCP 疎通が取れたら、以降は通常の往復ワークフロー（詳細は道具箱 README）:
- **MCP ツールには毎回 `program="《GAME_KEY》"` を渡す**（1 サーバ方式の場合）。
  省略すると候補を列挙したエラーになる。応答の `program` で取り違えを検知できる。
- **読む**: decompile/ をファイル直読み、または MCP (`get_decompiled_function` /
  `get_xrefs` 等)。巨大な xrefs は MCP のフィルタ付きが速い。
- **提案**: `notes/*.md` に解析、`proposals/proposed_comments.json`（[AI]コメント）/
  `proposals/proposed_functions.json`（未定義ハンドラの関数化）を出す → validate。
- **反映**: 人間が Ghidra GUI で apply_comments / apply_functions → **関数化したら
  export_context.py を再実行**すると新関数が decompile される。
- **オーバーレイ**（実行時ロードで静的EXEに無いコード）: そのオーバーレイが載った RAM
  ダンプから領域を切り出し、Raw Binary 別 Program として正しいベースで読み込み → 解析 →
  export で疑似C化できる。**export 先は EXE 本体と分ける**（同じ AI_WORKSPACE へ出すと
  EXE 側の ghidra_exports を上書きする）。手順は上の【D2】/ README「応用」参照。
- **未関数化 (`LAB_xxxxxxxx`) で疑似C が無いコード**: `bridge_config.json` に
  `"export_memory": true` を足して再 export すると、MCP の `get_disassembly` で
  生の逆アセンブルが読める。未定義領域に置かれたテーブルの参照元は
  `find_address_refs` で探せる（`get_xrefs` は Ghidra がデータと認識した箇所しか
  持たないため）。**対応アーキは MIPS (R3000/R5900) / SuperH SH-4・SH-2 /
  ARMv4T (ARM モード・Thumb モード。GBA / NDS)。**
  長く読むときは `format="text"` を付ける（1 命令 1 行。JSON だと 30 命令で
  5KB を超えてコンテキストが尽きる）。
  SH-4 は即値ペアではなく PC 相対の定数プールを辿る（GBR 相対は拾えない）。
  見つけた表の中身は `read_data`、構造の推定は `describe_data`、
  ポインタ表そのものは `find_pointer_tables` で読める（アーキ非依存）。
- **アーキ固有の解析ツール**: `find_writers`（その番地に書く命令と書く値。SH-4 / MIPS）/
  `expand_switch`（スイッチ表の展開。参照検索の盲点。SH-4 / MIPS）/
  `find_function_entry`（関数入口の判定。**SH-4 / MIPS / ARM / Thumb**。
  **関数を呼ぶ前に必ず通す** — 数バイトずれた番地から呼ぶと push/pop が合わず
  スタックが壊れる）。未対応アーキでは「未対応」と明示エラーになる（黙って空を返さない）。
- **GBA / NDS のとき**: `decompress`（BIOS 圧縮の展開。**入れ子の圧縮**は珍しくない）/
  `find_compressed_blocks`（圧縮ブロック探し）/ `render_tiles`（タイルを PNG で見る。
  1D マッピングのスプライトは `sprite_size=[4,4]` で並べ直す）。
  この 2 つは MCP で唯一ファイルを書くツールで、書き先は
  `<project_root>/extracted/` の配下だけ（既存は上書きしない）。
- **解析の取っ掛かりが無いとき**: `list_undefined_ranges`（`with_refs=true`）で
  「まだ手つかずなのに参照されている領域」を探す。`find_bytes` で既知の
  シグネチャや命令パターンを探す。どの Program にあるか分からなければ
  `search_programs`（全 Program 横断。この 1 つだけ `program` 引数が不要）。
- **版違いがあるとき**: `diff_programs` で製品版と修正版を比べる。
  `what="bytes"` なら変わった区間に A / B の関数名が付く。
- **日本語テキスト**: Ghidra は日本語をほとんど拾わないので `find_text` を通す。
  **この年代のゲームは独自符号が普通**（Shift-JIS が 0 件でも異常ではない）。
  その場合はフォントを `render_tiles` で見て文字対応表を作り `decode_text`、
  表は `bridge_config.json` の `text_tables` に置いて使い回す。
  Ghidra へ戻すときは `as_proposal=true` → `proposals/` に保存 → 人間が
  `apply_comments.py`（**文字列データ型の適用は常に禁止**、コメントまで）。
- **複数のアドレス空間があるとき**: `bridge_config.json` の `address_translations`
  に規則（`name` / `src_base` / `block_size` / `table`）を書くと、`translate_address`
  が**根拠つきで換算**してくれる。手計算での取り違えを防ぐため、
  親 ROM / 展開先が別々にある構成では必ず書いておくこと。

## 4. 道具を増やしたら
- 新 profile (機種) を作ったら、この早見表と platform_profiles/README に 1 行足す。
- 新ゲームを登録したら mcp_registry.json の games に追記（例: `game_b`=PS1 のゲームB）。
  1 サーバ方式なら **それだけで使える**（reconnect も server 名も不要）。
- toolbox の挙動を変えたら README / docs/ に引き継ぎを書く。
