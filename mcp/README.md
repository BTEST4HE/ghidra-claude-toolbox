# Ghidra Claude Toolbox — 読み取り専用 MCP サーバ

`ghidra_exports/` に出力済みの JSON / decompile を、Claude Code / Codex から
**必要な部分だけ問い合わせる**ための読み取り専用 MCP サーバです。

- **Ghidra にも Ghidra プロジェクトにも触れません。** Ghidra を変更する手段はありません。
- ファイルシステムへの書き込みは**ゼロではありません**: `decompress` / `render_tiles` /
  `render_tim` の生成物と `save_export_snapshot` を `<project_root>/extracted/` の配下に
  書きます（上書きしない）。それ以外のツールは読むだけで、一覧・比較でもフォルダを作りません。
- 読む範囲・リンク / UNC の扱い・大きさの上限は
  [../docs/safety_rules.md](../docs/safety_rules.md) が正です。
- **エミュレータも起動・接続・制御しません。** 実行時の観測は、外部の
  デバッガ MCP が出した結果を **JSON ファイルとして読むだけ**です
  （`list_runtime_observations` / `get_runtime_range_evidence`）。
- 書き込み系（コメント反映・関数作成・リネーム・型変更・配列化）は
  ツールとして**存在しません**（構造的に実行不能）。

## 提供ツール（全て読み取り専用）

| ツール | 説明 |
|---|---|
| `get_program_info` | program 名 / 言語 / コンパイラ / アドレス範囲 / メモリブロック |
| `list_functions` | 関数一覧（name 部分一致・アドレス範囲・ページング） |
| `get_functions_near_address` | 指定アドレスを含む/近傍の関数 |
| `list_strings` | 文字列一覧（部分一致・最小参照数・ページング） |
| `get_xrefs` | xref（**to_address / from_address のいずれか必須**） |
| `get_decompiled_function` | 指定関数の疑似 C コード 1 件 |
| `get_disassembly` | **生の逆アセンブル**（未関数化コード用。要 `export_memory`） |
| `find_address_refs` | **アドレス参照検索**（Ghidra が xref を持たない表でも。要 `export_memory`） |
| `read_data` | **テーブルの中身を読む**（数値 / 生バイト / 文字列。要 `export_memory`） |
| `find_writers` | **誰がここに何を書くか**（`find_address_refs` の対。SH-4 / MIPS / 65816。65816 は `scan_basis="bytes"` で CDL の外も）|
| `expand_switch` | **スイッチ表の展開**（参照検索の盲点。SH-4 / MIPS / 65816 の `JSR/JMP ($abs,X)`）|
| `find_function_entry` | **関数入口の判定**（収支一致で誤りを弾く。SH-4 / MIPS / ARM / Thumb / 65816 は確度つき推定）|
| `find_calls_to` | **その番地を呼ぶ・飛ぶ命令の全列挙**（JSL/JSR/JML/JMP/BRL/Bcc/表。CDL の外も。境界の妥当性つき。65816）|
| `find_path` | **入口 A から番地 B へ届く経路**（表・JSL/JSR を辿る静的な到達性。65816）|
| `list_memory_args` | **メモリ経由の引数の「設定漏れ」一覧**（呼び出し元ごとに書いた / 書いていない。65816）|
| `lint_stale_register` | **A の上位バイト (B) の持ち越し**の機械検出（上位を最後に設定した候補つき。65816）|
| `find_pointer_tables` | **ポインタ表そのものを探す**（アーキ非依存）|
| `describe_data` | **構造体・配列の推定**（ストライド / 要素 / 文字列。アーキ非依存）|
| `find_undefined_targets` | **参照されているのに関数化されていない入口**を洗い出す |
| `find_struct_field_uses` | **構造体のどのオフセットが何に使われているか**（疑似 C から）|
| `resolve_pool` | **定数プール (`DAT_xxxxxxxx`) の中身**を読む（Thumb は必須）|
| `find_pointers_to` | **データ中の生ポインタ**の逆引き（`find_address_refs` の対）|
| `list_labels` | **その番地に付いている名前**（データラベル + 人間が付けた型）|
| `resolve_symbol` | **名前 → 番地**（functions → labels → defined_data → 実行ファイルの .symtab）|
| `get_struct_layout` | **構造体 / クラスのフィールド配置**（オフセット付き。`flatten` で入れ子を展開）|
| `find_field` | **疑似 C のフィールド名 → 型とオフセット**（`self->resourceTable` をそのまま貼れる）|
| `resolve_gp_offset` | **MIPS の gp 相対 (`-29048(gp)`) → 絶対番地と名前** |
| `classify_range` | **未定義領域の正体当て**（コード / 表 / 文字列 / 圧縮 / 詰め物）|
| `list_undefined_ranges` | **まだ手つかずの領域**を大きい順に（参照 / 正体つき）|
| `find_bytes` | **バイト列検索**（AOB。`??` ワイルドカード可）|
| `search_programs` | **全 Program 横断の検索**（文字列 / 関数名 / バイト列）|
| `diff_programs` | **Program 同士の差分**（製品版 vs 修正版。関数名つき）|
| `find_text` | **Ghidra が拾えない日本語**（Shift-JIS / UTF-8 / EUC-JP）|
| `decode_text` | **独自符号のテキスト**を文字対応表で読む |
| `list_runtime_observations` | **外部エミュレータで観測した実行時の記録**を Ghidra 番地で一覧 |
| `get_runtime_range_evidence` | **その範囲に実行時に触れた記録があるか**を要約（`unused` とは言わない）|
| `translate_address` | **アドレス換算**（Program 間 / 実行時 / ファイル内。根拠つき）|
| `decompress` | **GBA / NDS の BIOS 圧縮を展開**してファイルに保存（LZ77 / Huffman / RLE / Diff）|
| `find_compressed_blocks` | **圧縮ブロックを探す**（誤検出を落としてから返す）|
| `render_tiles` | **タイルデータを PNG に描く**（形式当ては「見る」のが速い）|
| `get_export_status` | export の鮮度（mtime）と件数サマリ + memory イメージの有無 |

> `get_xrefs` がフィルタ必須なのは、`xrefs.json` が巨大（実データ (SH-4) 実測で約 46 万件 /
> 67MB）なためです。サーバ側でフィルタ・ページング・上限を強制し、コンテキスト
> を圧迫しません。

## `get_disassembly` — 未関数化コードを読む

Ghidra が関数として認識していない `LAB_xxxxxxxx` には疑似 C が存在せず、
`get_decompiled_function` では読めません。かといって「読まないと関数化して
よいか分からない / 関数化しないと読めない」の鶏卵状態になります。
`get_disassembly` はその出口で、**export しておいたメモリイメージを MCP 側で
デコード**して生の逆アセンブルを返します（Ghidra には問い合わせません）。

| 引数 | 既定 | 意味 |
|---|---|---|
| `address` | 必須 | 開始アドレス（`0x...`）。命令長の境界に揃っていること |
| `count` | 64 | 命令数。上限 512 |
| `arch` | 自動 | 通常不要。`memory_map.json` の processor から決まる |
| `stop_at_return` | false | true なら return 命令（+遅延スロット）で打ち切る |
| `format` | `json` | `text` にすると**1 命令 1 行のテキスト**を返す（下記）|
| `resolve_gp` | true | MIPS の gp 相対に `; = 0x00240e88 GameManagerInst` を注記（json では `gp_ref` / `comment`）|

返り値は `instructions[]`（`addr` / `bytes` / `word` / `mnemonic` / `operands` /
`text` / `target` / `flow`）と、追いかけやすいように `branch_targets` /
`call_targets` を別立てで返します。

### `format="text"` — コンテキストを食い潰さないための出力

既定の JSON は 1 命令あたり 7 フィールドあり、**30 命令で 5KB を超えます**。
「まず 100 命令ざっと眺めたい」ときにこれをやると、読む前にコンテキストが尽きます
（GBA 解析で実際に起きて、読むのを諦めた）。`format="text"` は同じ内容を
`listing` という 1 本の文字列で返します:

```
08036c12  0a38      subs r0, #0xa
08036c14  2070      strb r0, [r4]
08036c16  0879      ldrb r0, [r1, #4]
...

-- branch targets: 0x08036c2a, 0x08036c40
-- call targets:   0x0803a118
```

実測（実データ (GBA)）: 12 命令で 2,330 → 885 文字（62% 減）、
30 命令で 5,305 → 1,542 文字（**71% 減**）。データ行（`.long` / `.hword`）や
分岐先の注記は行末に残るので、**情報は落ちません**。

> 個々の命令のバイト列や `flow` をプログラムで扱いたいときだけ `json` を使ってください。
> 人間 / LLM が読むだけなら `text` で足ります。

### 事前準備（1 回だけ）

`bridge_config.json` に以下を足して Ghidra GUI で `export_context.py` を再実行:

```json
{
  "export_memory": true,
  "export_memory_max_mb": 32,
  "export_memory_total_max_mb": 128
}
```

`ghidra_exports/memory/<block>.bin` と `ghidra_exports/memory_map.json` が
出力されます。未初期化ブロックは出力されません。上限を超えたブロックは
スキップされ、理由が `memory_map.json` の `skipped_reason` に残ります。

### 対応アーキ

| arch | 対応 | 備考 |
|---|---|---|
| `mips` | ✅ | R3000 / R5900。PS1 / PS2 / N64 |
| `sh4` | ✅ | SuperH SH-4 / SH-2。Dreamcast / Saturn |
| `arm` | ✅ | ARMv4T の **ARM モード** (32bit 固定長)。GBA / NDS / 初期 ARM 機 |
| `thumb` | ✅ | ARMv4T の **Thumb モード** (16bit。bl だけ 32bit) |
| `ppc` | ✅ | PowerPC **Gekko / Broadway**（GameCube / Wii）。★ビッグエンディアン / 遅延スロット無し |
| `65816` | ✅ | WDC 65C816（SNES / SFC の 5A22）。★**可変長・即値幅が M/X 依存**。幅は CDL から（下記） |
| その他（x86 / 68000 / AArch64 …） | ❌ | 「未対応」と明示してエラーを返す |

未対応アーキは**黙って誤ったデコードを返しません**。
足すときは `mcp/disasm/<arch>.py` を作り、`mcp/disasm/__init__.py` の
`_ARCHS` / `_ALIASES` に登録します。

#### ★ARM / Thumb はモードを自分で選ぶ

ARM は同じ Program の中に ARM モード (32bit) と Thumb モード (16bit) が混在し、
**アドレスだけからはどちらか判別できません**。そのため自動判定はせず、
別 arch として登録しています。

- `language_id` が `ARM:LE:32:v4t` だと既定は **`arm`** になります。
- GBA のように実コードのほぼ全てが Thumb の場合は、`bridge_config.json` に
  `"disasm_arch": "thumb"` を書いてください (export 時に `memory_map.json` へ
  写され、`resolve_arch` が最優先で読みます)。
- 単発で切り替えたいときは `get_disassembly(arch="arm")` のように明示します。

モードを間違えると**データがそれらしい命令列に化けます**。読んだ結果が
支離滅裂なときは、まずモードを疑ってください。

capstone との突き合わせで、実コード約 8.7 万命令の不一致 0 件を確認済みです。
なお capstone の Thumb/ARM モードは ARMv7 相当なので、**v4T に存在しない命令
(blx / movw / ldrd / VFP / mcrr 等) を capstone だけが読む**ことがあります。
その差分はこちらのデコーダが正しく、不一致ではありません。

#### ★65816 (SNES / SFC) は命令長が CPU の状態で変わる

`LDA #imm` は P の M フラグが 1 なら 2 バイト、0 なら 3 バイトです (X フラグは
`LDX/LDY/CPX/CPY #imm`)。**幅を 1 つ読み違えると以降が全部それらしいゴミ**になるので、
`get_disassembly` は命令ごとに**幅の出どころ** (`width_source`) を返します。

| width_source | 意味 |
|---|---|
| `cdl_recorded` | Mesen の CDL に「その幅で実行された」記録がある（最も強い） |
| `cdl_static_only` | CDL の記録から静的に延長した区間 |
| `given` | 呼び出し側が `m` / `x` を渡した（Mesen の P レジスタ等。CDL より優先） |
| `tracked` | 読んでいる途中の `REP` / `SEP` で決まった |
| `carried` | CDL の区間を抜けた後、最後の CDL の幅を持ち越している |
| `ambiguous` / `unknown` / `assumed` | **推測**（`width_uncertain: true`）。CDL が曖昧 / PLP・RTI・XCE の後 / 何の情報も無く 8bit を仮定 |

`bridge_config.json` の設定:

```json
"cdl_jsonl": "C:\\RE\\runs\\<run>\\<game>_<date>.jsonl",
"direct_page": "0x0000",
"data_bank": "0x7E"
```

- `cdl_jsonl` … `mesen_debug/ghidra_export.py` が出す JSONL（`"record": "context_span"`）。
  **Ghidra の Program を作った CDL と同じ run のもの**を指すこと。header の CRC32 と
  export したイメージを突き合わせ、違えば `cdl_rom_mismatch` を返します。
  書いてあるのにファイルが無ければ**エラー**です（黙って仮定に落とさない）。
- 無ければ REP / SEP の追跡だけで読み、読み始めは `m=1 x=1` の**仮定**です。
- `direct_page` … D の値。省略時は **$0000 と仮定**（`assumptions: d_assumed`）。
- `data_bank` … DBR の値。省略時は **命令のバンクと仮定**（$2000 以上の absolute に `dbr_assumed`）。

番地は `0x809447` でも `$80:9447` でもよく、比較は正規形で行います:
`$00-$3F/$80-$BF:0000-1FFF` → WRAM `$7E:xxxx`、`:2000-7FFF` → I/O `$00:xxxx`、
ROM のミラー（`$00:9447` / `JSL $02:C4B1`）→ Program に載っている正規窓（`$80` / `$82`）。

`find_address_refs` / `find_writers` は **CDL の区間だけ**（無ければ functions.json の
関数本体）を走査します。アクセスは `R` / `W` / `RW`（INC/DEC/ASL/LSR/ROL/ROR/TSB/TRB）で、
16bit の書き込みは 2 バイトを覆います（`STA $0B1F` (m=0) は `$0B20` の上位バイトの writer）。
`,X` / `,Y` 付きは `offset_writers`、間接 (`STA ($10),Y`) は件数 (`indirect_stores`) だけです。
`list_call_sites` / `find_immediate` は未対応です。

`get_disassembly` は既定 (`snap=true`) で、読み始めが **CDL に記録された命令の途中なら
その命令の先頭へ合わせて読み直します** (`snapped` / `alignment_note`)。`snap=false` なら
従来どおり `alignment_warning` だけ付けてずれたまま返します。

#### 65816 の分岐を辿る解析 (2026-10 追加。`mcp/disasm/w65816_flow.py`)

SFC のバグ解析で手作業になった所を道具にしたものです。
**分岐を辿りながら M/X も運ぶ**ので、CDL に記録の無いコードも正しい幅で読めます:
P は JSR/JSL で変わらないので「呼び出し先の入口の幅 = 呼び出し元の幅」、
`PHP`…`PLP` は対で戻し、呼び出しから戻った後は呼び出し先が戻すときの幅を使います。
CDL の記録 (recorded / static_only) が常に優先ですが、**CDL が見たのと違う幅で
呼ばれている処理** (入口の幅が CDL と食い違う) の中では辿ってきた幅を優先します。

| ツール | 何をするか / 何を返すか |
|---|---|
| `find_calls_to` | JSL/JML (ミラー込み)、JSR/JMP (同じバンク)、BRL/BRA/Bcc、PEA (戻り先-1)、`JSR/JMP ($abs,X)` の**表の中身** (展開して実際に含まれるものだけ)。各件に `boundary` (`cdl_instruction_start` = 確実 / `inside_cdl_instruction`・`cdl_data` = 偶然の一致 / `not_in_cdl` + `sync`)、`executed`、`widths` |
| `find_function_entry` | 後ろ向きに RTS/RTL/RTI/JMP/BRA の直後と既知の入口を候補にし、呼び出し元・入口の幅 (CDL → 呼び出し元の幅 → 4 通り試す)・届くか・不自然な命令で点数。`confidence` / `entry_widths` / `candidates` |
| `expand_switch` | `JSR ($abs,X)` / `JMP ($abs,X)` の表。件数は `CMP #n + BCS` なら確定、`AND #k` は上限、無ければ表の終端の推定 (CDL がコードと記録した番地 / ROM 外の値 / 不自然な飛び先)。`index_bound` に添字の出どころ |
| `list_callees(follow_tables=true)` | 表を展開してその先も辿る (状態機械の先を追う) |
| `find_path` | 入口から番地まで、表・JSL/JSR・末尾ジャンプ・PEA の戻り先を幅優先で。`path` (呼び出しの連なり) と `final`。見つからなくても「届かない」とは言わない |
| `find_writers(scan_basis="bytes")` | CDL を使わずバイト列の全域から書き込み命令を拾い、`executed` / `boundary_ok` / `width`+`width_certainty` (cdl / inferred / unknown) を付ける。8bit と分かった `STA target-1` は `not_covering`、CDL の命令の途中は `boundary_rejected` |
| `list_memory_args` | 処理を呼ぶ箇所ごとに、その呼び出しを含む処理の入口から辿って、呼ぶ前に各番地を `written` (値) / `partially_written` / `not_written` / `unknown`。途中で呼んだ処理の中の書き込みも数える。`args` 省略時は「書く前に読む WRAM」を自動推定。`suspicious` = 書く呼び出し元と書かない呼び出し元が混在 |
| `lint_stale_register` | 8bit で下位だけ作り、上位 (B) は呼び出し先から戻ったときのまま 16bit で使う形 (`mixed_16bit_use` / `call_consumes_high` / `xba_stale_high`)。`high_byte_candidates` に上位を最後に設定した命令と経路 (`via`)。PHA…PLA の保存は辿るので保存だけは使用に数えない |

**推測で断定しない**ための約束:
- バイト列で拾った候補には必ず `boundary` を付ける。★データでも線形デコードは同期する
  (どんなバイト列も何かの命令になる) ので、**CDL で実行された命令が 1 つも無いバンク**
  では `sync` が高くても `boundary_ok` を true にしない (`why` に理由)。
- 幅を推測で読んだ所は `width_uncertain` / `*_source` (`after_call` / `assumed` / …) で言う。
- 戻らない経路 (ソフトリセットの `JMP $A3F4` など) の書き込み・A の値は、呼び出し元から
  見た「呼んだ後の状態」に数えない。
- 辿れなかった間接ジャンプ・間接書き込みは件数と番地で返し、「無い」とは言わない
  (`unresolved_indirect` / `could_be_written_by`)。

#### SFC 解析由来の追加 (2026-10-02)

**項目ごとの配列 (`record_formats` の `layout: "soa"`)** — 車のデータが
`$0B00 + 項目×$10 + 車番号×2` のように「項目ごとに配列」になっている形:

```json
"record_formats": {
  "cars": {"layout": "soa", "base": "0x0B00", "field_stride": "0x10",
           "element_size": 2, "count": 6,
           "fields": {"0x10": "input", "0x20": "speed:s16", "0xD0": "heading", "0xE0": "course"},
           "element_names": ["player", "cpu1", "cpu2", "cpu3", "cpu4", "cpu5"]}
}
```

| 呼び方 | 返すもの |
|---|---|
| `read_data(record="@cars", index=0)` | 車 0 の全項目 (値と**番地**)。`index` 省略で全車。RAM はメモリイメージに無いので値は null + 警告、番地は有効 |
| `find_writers(address="@cars.speed")` | 速度のどの要素かに書く命令。`record_field` = `cars.speed[1]` (直接) / `cars.speed[idx]` (`,X` で選ぶ形) |
| `find_writers(address="@cars.speed[0]")` | 要素 0 (プレイヤー) に届くものだけ |
| `find_struct_field_uses(base="@cars")` | 項目ごとの読み書き件数・関数・`untouched_fields`。**疑似 C ではなく逆アセンブル** (CDL 走査) から数える。`offset="speed"` でその項目の命令一覧 |

`index_reach` の既定は `(count-1)×element_size` なので、**添字で項目をまたぐ形
(`X = 項目×$10 + 車×2`) は拾いません** (`outside_field_base` / `outside_field_total` に件数)。

**RAM の名前表 (`ram_map`)** — notes にしか無かった RAM の意味を結果に添えます
(**Ghidra のラベルとは別物**。apply は無く表示だけ):

```json
"ram_map": {"$00D9": "grip_flag", "$00DA": {"name": "air_accel", "size": 2},
            "$0B20,X": "car.speed", "$0D51.bit7": "airborne"}
```

`get_disassembly` (`refs[].name` と注記)・`find_writers` (`ea_name` / `target_name`)・
`find_address_refs` (`resolved_name` / `target_name`) に出ます。`,X` 付きのキーは添字付きの
アクセスにだけ、`.bitN` は `*_bits` に出ます。`record_formats` の項目ごとの配列も
名前の出どころになります (`cars.speed[1]`)。

**ミラー上の重複関数** — `list_functions` / `get_functions_near_address` が、ローダーの
作った `$00:8000-FFFF` の関数に `mirror_of` (実体 `$80:xxxx`) / `mirror_function` /
`mirror_basis` (`address_rule` / `memory_block:<未 export のブロック名>`) を、
`thunk_EXT_FUN_02c4b1` に `ext_real` (`$82:C4B1`) を添えます。`hide_mirrors=true` で
重複を一覧から外します。`get_decompiled_function` も疑似 C に出る `EXT_FUN_` の実体を
`ext_functions` に添えます (`code` は変えません)。

**呼ぶ順番 (`list_callees(ordered=true)`)** — 根の関数の呼び出しを番地の順に全部
`call_order` に並べ、各呼び出しに `conditional` (条件分岐で飛ばされうるか。入口から出口への
全経路が通るなら false) を添えます。判定は `COND_BRANCH_FLOW` を宣言したアーキ (65816) だけ。

**LoROM / HiROM の換算** — `translate_address` の `kind: "lorom" / "hirom" / "exhirom"`
(「規則の種類」)。

**DP / DBR を Ghidra に設定する** — `ghidra_scripts/apply_snes_context.py`
(`allowed_apply_operations` に `"context"` が必要。[docs/safety_rules.md](../docs/safety_rules.md))。
疑似 C の `in_DP + 0xbc` / `in_DBR * 0x10000` を定数番地にするためのものです。

**アーキで参照の探し方が変わります** (`find_address_refs`):

- **MIPS** … `lui rX, hi` + 後続命令の下位 16bit を合成する**即値ペア走査**。
  lui の結果を別レジスタへ写す形と、窓 (既定 8 命令) を越える形は拾えません。
- **SH-4** … 16bit 命令に 32bit 即値が入らないので、**PC 相対の定数プール**を辿ります
  (`mov.l @(disp,pc),Rn` が読む 32bit 値と照合)。レジスタ上書きによる取りこぼしは
  原理的にありません。代わりに **GBR 相対アクセス
  (`mov.l R0,@(disp,gbr)`) は拾えません** — 参照先が命令にもプールにも現れないためです。
- **ARM / Thumb** … SH-4 と同じく **PC 相対の定数プール**を辿ります
  (`ldr Rd,[pc,#imm]` が読む 32bit 値)。`adr` / `add Rd,pc,#imm` の計算結果と
  `b` / `bl` の飛び先も登録します。**プールから読んだ基底に後から加算する形**
  (テーブル先頭 + オフセット) は「基底への参照」としてしか出ません。
  ★**モードが違うと全く拾えません** — Thumb のコードを `arch="arm"` で
  走査しても 0 件になるだけです。0 件だったらモードを疑ってください。

## `find_address_refs` — Ghidra が知らない参照を探す

`get_xrefs` は **Ghidra が「データ」と認識した箇所しか持ちません**。未定義領域に
置かれたテーブルには効かないので、「このアドレスを参照しているコードはどこか」を
命令の即値から再構成して探すのがこのツールです。

| 引数 | 既定 | 意味 |
|---|---|---|
| `address` | 必須 | 探したいアドレス（`0x...`） |
| `mask` | `0xffffffff` | `(合成アドレス & mask) == (address & mask)` で比較。`0xffff0000` なら帯域検索 |
| `limit` | 100 | 返す件数。上限 500（`total` は真の件数を返す） |

返り値の各要素: `ref_addr`（下位 16bit を足した命令）/ `hi_addr`（`lui` の位置）/
`resolved_addr` / `form`（`lui+addiu` 等）/ `text`（その命令の逆アセンブル）/ `block`。

MIPS では `lui rX, hi` + 後続数命令の `addiu / ori / lw / sw / lh / lb / ...` を組にし、
**`(hi << 16) + sext16(lo)`** で合成します（`lo` が負なら上位が -0x10000 される）。
`j` / `jal` の飛び先も同じ索引に入ります。

> 初回クエリで全走査して索引を作り、以降はキャッシュします（`.bin` の mtime が
> 変われば自動で作り直し）。実測: 473KB で構築 35ms、16MB で 1.1s。
> 構築後のクエリは 1〜2ms。

**拾えない形（正直に）**: `lui` の結果を `addu` 等で別レジスタへ写してから使う形、
`lui` から 8 命令以上離れて使う形。逆に、`lui` の結果レジスタが**途中で上書き
されたら打ち切る**ので、素朴な総当たりよりは誤検出が少ないです。
SH-4 は定数プールを辿るのでこの制約はありませんが、**GBR 相対アクセスは
原理的に拾えません**（参照先が命令にもプールにも現れない）。

### 0 件だったときは `hint` が付きます

`total: 0` のときだけ、応答に `hint` が入ります。**「参照が無い」と結論する前に**
これを読んでください。

- `hint.blind_spots` … そのアーキで原理的に拾えない形（MIPS なら `$gp` 相対や
  ポインタ表経由、SH-4 なら **GBR 相対**）
- `hint.next_steps` … `mask="0xffff0000"` で帯域検索する / `get_xrefs` も見る /
  `read_data` でその番地の中身を確かめる / 表の先頭を探す、など

> 実データ (SH-4) の乱数の種 `0x0C71093C` は `GBR+0xDC` でアクセスされており、
> プール検索では最後まで見つかりませんでした。0 件は「無い」ではありません。

## `read_data` — 見つけたテーブルの中身を読む

`find_address_refs` で表を見つけても、**中身を読む手段が無い**と結局
`.bin` を読む使い捨てスクリプトを書くことになります。それを埋めるツールです。
**Ghidra にデータ型を適用せず**（型変更は常に禁止）、解釈だけを試せます。

| 引数 | 既定 | 意味 |
|---|---|---|
| `address` | 必須 | 読み始めるアドレス（`0x...`）|
| `format` | `hex` | `u8`/`s8`/`u16`/`s16`/`u32`/`s32`/`u64`/`s64`/`f32`/`f64` と `hex`（生バイト）/ `cstring` |
| `count` | 64 | **読む要素数**。上限 1024 / 64KB |
| `columns` | `hex`は16 | 行に折り返す列数（x/y/z なら `3`）|
| `stride` | なし | レコード間のバイト間隔。`columns` と併用して**先頭だけ拾う** |
| `base` | `auto` | `dec`/`hex`。auto は u32/u64/hex を 16 進、それ以外を 10 進 |
| `annotate` | `true` | u32/s32 の値に「その先に何があるか」（関数名/文字列/ブロック）を添える |
| `as_markdown` | `false` | `true` で **notes/*.md へそのまま貼れる Markdown 表**を返す |

### 使い分け

```
まず形を見る        read_data(addr, "hex", count=48)          → 16 バイト/行 + ASCII
要素サイズを試す    read_data(addr, "s16", count=24, columns=3)
パディングを飛ばす  read_data(addr, "s16", count=15, columns=3, stride=10)
ポインタ表        read_data(addr, "u32", count=16, columns=1)  → 各値に関数名が付く
文字列表          read_data(addr, "cstring", count=16)
```

> `stride` は「1 レコード 16 バイトのうち先頭 3 個の s16 だけ欲しい」ときに使います。
> `count` は常に**要素数**なので、`columns=3, stride=16, count=15` なら 5 行返ります。
> `cstring` は **長さ 0 のエントリ（NUL パディング）を飛ばし**、`skipped_empty` に件数を返します
> （飛ばさないと count がパディングで埋まる）。文字コードは UTF-8 として解釈するので、
> Shift_JIS なら `hex` で読んで別途デコードしてください。

### 出力例（合成データ / `as_markdown=true`）

```
| addr | +0 | +2 | +4 |
|---|---:|---:|---:|
| `0x80020000` | 0 | -1 | 0 |
| `0x8002000a` | 1 | 0 | 0 |
| `0x80020014` | 2 | 0 | 0 |
| `0x8002001e` | 3 | 2 | 0 |
```

非境界アドレスは**エラーにせず `warnings` を返します**
（データ表は境界に揃っていないことがあるため）。

## 解析ツール群（2026-08 追加）

「逆アセンブルの外側」でその場しのぎの Python を書いていた作業を道具にしたものです。
**`find_writers` は SH-4 / MIPS / 65816、`expand_switch` は SH-4 / MIPS / 65816**、
**`find_function_entry` は SH-4 / MIPS / ARM / Thumb / 65816** が対応です
(65816 の判定方法は上の「65816 の分岐を辿る解析」)。
未対応アーキでは「未対応」と明示エラーを返します（黙って空を返しません）。
`find_pointer_tables` / `describe_data` はアーキ非依存です。

### `find_writers` — 誰がここに何を書くか

`find_address_refs` の対。「このフラグを 0 に戻している命令を全部潰したい。
潰し漏れはないか」に答えます。

| 返り値 | 意味 |
|---|---|
| `writers` | **ちょうどこの番地**へ書く命令（`value` に即値を特定できた書き込み値）|
| `offset_writers` | 近傍へ書く命令（`disp != 0` や `@(R0,Rn)`。実効アドレスがずれる）|
| `readers` | 読むだけの箇所 |
| `unresolved` | ロードはしたが store/read を特定できなかった箇所 |

SH-4 では「値が一致する定数プール → それを読む `mov.l @(disp,pc),Rn` →
そのレジスタをベースにした store」を追います。`max_scan`（既定 12 命令）で打ち切り、
`store` のソースレジスタを `trace_imm`（既定 16 命令）遡って `mov #imm` を探します。

> **書き込み 0 件は「誰も書いていない」ではありません。** そのときだけ `hint` が付き、
> GBR 相対・別レジスタ経由・`max_scan` 超過などの疑い先を返します。

### `expand_switch` — braf スイッチ表の展開

SH-4 のスイッチ文は 16bit オフセット表で、**飛び先が 32bit アドレスとして
どこにも現れない**ため `find_address_refs` に一切かかりません。その盲点を塞ぎます。

```
mova @(disp,pc),r0      ; 表の先頭
mov.w @(r0,Rn),r0       ; word[表 + index*2]
braf r0                 ; 飛び先 = braf のアドレス + 4 + r0
```

`address` には `braf` 命令（かその近傍）を渡します。エントリ数は直前の範囲チェック
（`mov #N,Rm` / `cmp/hs Rm,r0`）から取ります。取れなければ「飛び先がコード範囲に
収まる間」読み進め、**`count_is_estimated: true`** を立てます。

### `find_function_entry` — 関数入口の判定

**関数を呼ぶ前に必ずこれを通してください。** 数バイト後ろから呼ぶと push と pop の
数が合わずスタックが壊れ、`rts` がゴミへ飛びます（このプロジェクトで 3 回踏んで
3 回とも実機停止）。

- 後方の「関数末尾（`rts` / `jmp @Rn` / `braf`）+ 遅延スロット」の直後と、
  プロローグ（push 連続）の先頭を候補に集め、**近い順**に検証します
- 採用条件は **その関数の範囲が指定アドレスを含み、かつ push 数と pop 数が一致**すること
- `balanced: false` なら入口ではありません
- Ghidra の見解は `ghidra_says` に**併記するだけ**（Ghidra 自身が誤認する例があるため）

> ★`rts` の**遅延スロットも数える**必要があります。SH-4 のエピローグは
> `rts` / `mov.l @r15+,r14` の順が定型で、ここを飛ばすと push が 1 多く見え、
> 正しい入口を「不均衡」と誤判定します。

**対応アーキと「入口らしい push」**（判定はアーキ側の数行だけで、骨格は
`mcp/disasm/_prologue.py` で共有しています）:

| arch | 入口 | 関数の終わり |
|---|---|---|
| `sh4` | `mov.l Rn,@-r15` の連続 | `rts` / `jmp @Rn` / `braf`（+遅延スロット）|
| `thumb` | `push {..,lr}` = `0xB5xx` | `pop {..,pc}` = `0xBDxx` / `bx lr` = `0x4770` |
| `arm` | `stmfd sp!,{..,lr}` = `0xE92D....` | `ldmfd sp!,{..,pc}` / `bx lr` / `mov pc,lr` |
| `mips` | `addiu $sp,$sp,-N` (フレーム確保) | `jr $ra` **+ 遅延スロット** |

> ★Thumb では **`bx lr`（`0x4770`）だけ**を復帰とみなします。`bx Rm` を一律に
> 「関数の終わり」扱いすると、ARMv4T の**間接呼び出しの定型**
> `mov lr,pc` / `bx r3` を終端と誤読し、関数が途中で切れて push/pop の収支が
> 合わなくなります（実測で発生）。
>
> ARM / Thumb では `bl` と**関数ポインタ（Thumb は `entry|1`）**の両方を探して
> `referenced_by` に入れます。ここが 0 件なら間接呼び出しの可能性があります。
>
> ★MIPS では `jr $rX`（`$ra` 以外）は**スイッチの表引き**であって関数の終わりでは
> ありません。ここを一律に終わり扱いすると関数が途中で切れます。
> また `jr $ra` の**遅延スロットは必ず実行される**ので収支に数えます。
>
> 実測（実データ (PS1), 60 関数）: **命令列から見て 60/60 が妥当**。
> Ghidra と一致したのは 47 件で、食い違った 13 件は **Ghidra 側の誤り**でした
> （`*_OBJ_<offset>` のようなオブジェクト内オフセット名で 1 つの関数を刻んでいた）。
> だから `ghidra_says` は併記するだけで、一致を要求しません。

### `find_pointer_tables` — ポインタ表そのものを探す

`[target_lo, target_hi]` を指すワードが `min_entries` 個以上**連続**して並ぶ箇所を返します。
各エントリの指す文字列も解決して併記します。

| 引数 | 既定 | 意味 |
|---|---|---|
| `target_lo` / `target_hi` | 必須 | **ポインタの指す先**の範囲（表そのものの範囲ではありません）|
| `stride` | 4 | **表のエントリ間隔**。レコードの先頭にポインタがある表なら `0x14` など |
| `min_count` | `min_entries`(3) | 連続して並ぶ最小件数 |
| `thumb_pointers` | false | true なら **`entry|1` の Thumb 関数ポインタ**として扱う |

> **`stride` は「表のエントリ間隔」であって「指す先の間隔」ではありません。**
> ここを取り違えると 1 件も出ません。値が一定間隔で増えていく表（転送ブロック表など）
> でも、**エントリ自体が連続する u32 なら `stride=4`** です。
>
> `thumb_pointers=true` を指定しないと、Thumb 関数の表は**1 件も見つかりません**
> （実アドレス +1 になっているため）。

例（GBA の Program での使い分け）:

| 表の種類 | `stride` | `thumb_pointers` |
|---|---|---|
| 転送ブロック表 (ポインタだけの並び) | `4` | false |
| グラフィック表 (20 バイトのレコード) | `0x14` | false |
| Thumb 関数表 | `4` | **true** |

### `describe_data` — 構造体・配列の推定

各 4 バイト語を u32 / ポインタ / インライン ASCII 文字列に分類し、同じ並びが繰り返す
周期をストライドとみなします。`element_stride`（レコード内に並ぶ固定長要素）と
`header_bytes` も推定します。

> ストライドは**種別の並びだけでは決まりません**。要素長・その整数倍・±1 要素ずれが
> すべて満点になるため、実際の値で「レコード先頭は非ゼロ・直前はゼロ（末尾パディング）」
> という**境界スコア**を二次判定に使っています。それでも推定は推定なので、
> 分かっているなら `stride_hint` を渡してください。

### `find_address_refs` の範囲指定

`range_end` を渡すと `[address, range_end]`（**両端を含む**）のどこかを指す参照を探します。
表の途中を指す参照を取りこぼさないための指定です。
範囲検索では分岐先が大量に混ざるので**既定で分岐を除外**します
（`include_branches=true` で戻せます）。

## 次にどこを見るか / 横断して探す (2026-08 追加)

### `list_undefined_ranges` — まだ手つかずの領域を大きい順に

`undefined_ranges.json` は export されているのに、件数を数えるだけで中身が
見えていませんでした (実データ (GBA) で 27,928 件)。**「次にどこを見るか」を決める
道具**です。

| 引数 | 既定 | 意味 |
|---|---|---|
| `min_size` | 0x40 | これ未満は捨てる。**1 バイトの隙間が大半**で、並べても読めない |
| `initialized_only` | true | BSS / VRAM を除く。「未解析」ではなく**そもそも中身が無い** |
| `executable_only` | false | true なら実行属性のあるブロックだけ |
| `sort` | `size` | `address` にすると番地順 |
| `with_refs` | false | **返した範囲だけ**「そこを指すコードがあるか」を数える |
| `classify` | false | **返した範囲だけ**正体を推定する（`classify_range` と同じ判定）|

> **`with_refs=true` が本命です。参照があるのに未定義な領域は読む価値が高い。**
> 実測 (実データ (GBA)): 最大の未定義領域は 6,494 バイトで**参照 253 件** — 誰も
> 見ていない重要な表がそこにありました。
>
> コードらしければ `get_disassembly`、表らしければ `read_data` / `describe_data` へ。

### `find_bytes` — バイト列検索 (AOB スキャン)

PulseHexPy は実行中プロセスに対して AOB できますが、**export 済みイメージに対する
手段がありませんでした**。`??` がワイルドカードです (PulseHexPy と同じ書き方)。

```
"48 8B ?? ?? 89"      ワイルドカード付き
"0F8004 08"           空白は自由
```

既知シグネチャ探し、「この構造体は他にもあるか」、命令パターン探しに使います。
**命令列を探すときは `align=4` (MIPS/ARM) / `2` (SH/Thumb) を付けてください** —
境界を跨いだ誤検出が減ります。`total` は `limit` 前の真の件数です。

### `search_programs` — 全 Program を横断して探す

**このツールだけ `program` 引数が要りません**（全部を見るため）。

| `kind` | 探すもの |
|---|---|
| `strings` (既定) | `strings.json` の値を部分一致 |
| `functions` | 関数名を部分一致 |
| `bytes` | memory イメージを AOB 検索 |

EXE 本体 + オーバーレイ、ROM + 展開後、**製品版 + 修正版**のような構成で効きます。
実測: `"SPRITE"` → 13 Program 中 7 に 355 件、`"memcpy"` → 4 Program。

> **`errors` に入った Program は「0 件」ではなく「調べられなかった」です。**
> 混同しないでください (memory 未 export など)。

### `diff_programs` — 製品版 vs 修正版を比べる

| `what` | 比べるもの |
|---|---|
| `functions` | 入口アドレスをキーに、増えた / 減った / **同じ番地で名前が変わった** |
| `strings` | 文字列の増減 |
| `bytes` | **同じ番地のバイト差分**。区間ごとに A / B の関数名が付く |
| `all` (既定) | 上の全部 |

`bytes` が本命です。変わった区間に関数名が付くので、**「どの関数が変わったか」が
そのまま答え**になります。`gap` バイト以内の差分は 1 区間にまとめます
(1 命令の書き換えが 4 件に散らばらないように)。

> ★**bytes は番地が揃っている前提**です。基準がずれている Program 同士
> (ROM と展開後など) を比べても意味がありません — 先に `translate_address` で
> 対応を確かめてください。揃っていないブロックは `skipped_blocks` に理由が入ります。

## `export_memory` が false でも動く — 実行ファイルからの供給（2026-08 追加）

`export_memory: false` の Program では、`get_disassembly` / `read_data` /
`find_bytes` / `find_address_refs` / `find_writers` が**すべて使えません**でした。
しかし `source_model=executable` なら実行ファイルは手元にあります。

**`memory_map.json` が無いときは、`program.json` の `executable_path` と
`memory_blocks` から自動でメモリマップを組み立てます。** ELF ならプログラム
ヘッダ（`p_vaddr` / `p_offset` / `p_filesz`）を読むので、番地とファイル位置の
対応は正確です。ELF でなければ、実際の最小アドレスにファイルを平置きします
（raw binary / ROM 用）。

- **再 export を待たずに使えます。**
- ★**実行ファイルは許可ルート（`extracted/`・`dumps/`・`bridge_config.json` の
  `source_roots`）の配下にあるときだけ開きます**（2026-10）。`program.json` の
  `executable_path` がプロジェクト外を指すなら、人間が `source_roots` にそのフォルダを
  書き足してください。読めなかった理由は `get_export_status` の
  `memory.executable_rejected` に出ます（許可ルート外の候補は**存在も確かめません**）。
  UNC / デバイスパスは触らずに拒否、相対パスはプロジェクト基準、256 MiB を超える
  ファイルは読む前に断ります。DOL はセクション表で読みます
- `get_export_status` の `memory.source` が `executable` になり、
  どこから読んでいるかが分かります
- **未初期化ブロック（`.bss` / `.sbss`）は出しません。** ファイルに実体が無いので、
  読めるふりをして 0 を返すより「読めない」と言う方が安全です。実行時の値が
  見たいときは RAM ダンプか `export_memory: true` が要ります

> 実測（実データ (PS2) / PS2 ELF）: `.text` 以下 12 ブロックが読めるようになり、
> `get_disassembly` / `read_data` / `find_bytes` / `find_address_refs` /
> `find_writers` / `find_pointers_to` / `expand_switch` がそのまま動きました。

## `find_undefined_targets` — 関数化されていない入口を洗い出す（2026-08 追加）

`list_undefined_ranges` は「未定義**領域**」、こちらは「参照されている未定義な
**関数入口**」です。**的が違います。**

関数ポインタ表を渡すと、飛び先のうち Ghidra が関数にしていないものだけが残ります。

```
find_undefined_targets(table_address="0x00233358", stride=8, count=682)
  -> 読んだ 682 / 既に関数 649 / コード外 0 / **未関数化 33**
```

`as_proposal=true` で `proposals/proposed_functions.json` の形も返します
（保存も反映も人間が行います）。`source="xrefs"` で `xrefs.json` の参照先全部、
`addresses` で番地を直接渡すこともできます。

> ★**「未関数化 = 関数である」ではありません。** データを指すエントリも混ざります。
> `looks_like_code` は「入口候補が返った」ではなく
> **「関数の範囲が指定アドレスを含み、かつ push/pop の収支が合う」**で判定します。
> ゼロ埋めを関数として apply すると、データ域に関数を作ってしまいます。
> 実測 33 件のうち 2 件がこれで外れました（提案は 31 件）。

## その番地に付いている名前を見る（2026-08 追加）

### `list_labels` — 人間が既に名付けたもの

**これが無いと「誰かが既に名付けたもの」が AI から見えません。** 関数名は
`functions.json` にありましたが、**データに付いたラベルはどこにも出ていません
でした**（`export_context.py` が `getSymbolTable` を一度も呼んでいなかった）。

そのせいで起きていたこと:

- 人間が Ghidra で表に `CarParams` と名付けても、AI からは `DAT_8008b654` のまま
- **`apply_labels.py` で付けたラベルすら次のセッションで見えず**、同じ番地へ
  重複提案を出しかねない
- 人間が定義した構造体・配列が見えず、`describe_data` が毎回ゼロから推定し直す

`export_context.py` に **`labels.json` と `defined_data.json`** を足し、
MCP がそれを引くようにしました。

| 引数 | 意味 |
|---|---|
| `name_contains` | 名前の部分一致（日本語も可） |
| `start` / `end` | アドレス範囲 |
| `source` | `USER_DEFINED`（人間 / `apply_labels.py`）/ `IMPORTED`（シンボルテーブル）/ `ANALYSIS`（Ghidra の解析） |
| `include_functions` | 既定 false（`functions.json` と重複するため） |
| `with_type` | 既定 true。人間が付けた型を添える |

> **自動生成名（`LAB_` / `DAT_` 等）は export の時点で除いてあります。**
> `getDefinedSymbols()` がそもそも返しません。ここに出るのは
> **誰かが意味を与えた名前だけ**です。
>
> `defined_data.json` の型は**推定ではなく人間が付けたもの**なので、
> `describe_data` の推定と食い違ったら**こちらが正**です。

ラベルは `_describe_address` 経由で `read_data` / `find_pointer_tables` /
`diff_programs` の注釈にも出ます。`find_text` の `only_missing` は
**既にラベルや型が付いている番地も除く**ようになりました（付け直しを提案しても
人間の作業を上書きするだけなので）。

**再 export が要ります。** `bridge_config.json` で `export_only` を使っている場合は
`"labels"` と `"defined_data"` を足してください。古い export のままでも
`list_labels` が「まだ export されていません」と言うだけで、他は今までどおり動きます。

## 構造体レイアウト / gp 相対 / 名前 → 番地（2026-09 追加）

2026-09-24、実データ (PS2) (PS2) で TOC 書き換えフックを作ったときに詰まった 4 点を
道具にしました。**どれも読むだけ**で、Ghidra の型にもシンボルにも触れません。

### `get_struct_layout` / `find_field` — そのフィールドは何バイト目か

疑似 C には `self->resourceTable` と**名前**は出ますが、**何バイト目か**は出ません。
これまでは逆アセンブルの `lw a2,388(s1)` から 1 フィールドずつ拾っていました。
`export_context.py` の新工程 **`datatypes`** が Ghidra の構造体・共用体
（C++ のクラスと vtable 型を含む）を `datatypes.json` に書き出し、それを引きます。

| ツール | 使い方 |
|---|---|
| `get_struct_layout(type_name, flatten=false)` | 型名は 完全一致 → 大文字小文字無視 → 部分一致。候補が複数なら `candidates`（path で指定し直す）。`flatten=true` で `xformUnit.matrix.m[3][0] @ +0x80` の形に展開 |
| `find_field(field_path, type_name=None)` | `resourceTable` / `xformUnit.matrix.m[3]` / `unit->xformUnit...` を受ける。先頭の変数名は外して `ignored_prefix` に。`a->b` はポインタの先の型から数え直す |

- **継承は展開しません。** 基底クラスは先頭フィールド（`super` 等）としてそのまま出ます。
  代わりに `embedded_in` / `also_at` が「その型を値として持つ型（派生クラス）」での
  オフセットを出します（`find_field("memFile")` → `IoFileBase +0x24`、`IoFile` でも `+0x24`）。
- 要素数が 64 を超えるスカラ配列（`char name[256]` 等）は flatten でも 1 行にまとめます。
- **Ghidra の型が実物と合っている保証はありません。** 改造コードに使う前に実機で確かめること。
- `datatypes.json` が無い古い export では、この 2 つだけが「再 export して」と返します。

### gp 相対 — `get_program_info` の `gp` / `get_disassembly` の `resolve_gp` / `resolve_gp_offset`

PS2 の小さいグローバルは `lw v0,-29048(gp)` で読まれ、参照先が命令に現れません。
gp は**根拠の強い順**に求め、**どれで求めたかを `gp_source` に**、全候補を
`gp_candidates` に返します。食い違えば `gp_warnings` に出します（黙って 1 つに決めない）。

| 順 | `gp_source` | 根拠 |
|---|---|---|
| 1 | `symbol` | シンボル `_gp`（labels.json、無ければ実行ファイルの ELF .symtab）|
| 2 | `elf_reginfo` | 実行ファイルの `.reginfo`（MIPS ELF の `ri_gp_value`）|
| 3 | `entry` | エントリ処理の `lui gp,HI` / `addiu gp,gp,LO`、または **PS2 crt0 の `SetupThread` に渡す `$a0`**（Sony の crt0 は gp を直接組まない）|
| 4 | `ghidra_context` | Ghidra のコンテキスト値（export が `program.json` の `register_context` に出す）|
| 5 | `code_scan` | 上のどれも無いときだけ、コード全体で gp を組み立てている箇所 |

Ghidra のコンテキストで gp が範囲ごとに違う Program では、`get_disassembly` と
`resolve_gp_offset(at=...)` は命令の番地で引き分けます。
例（合成データ）: gp = 0x00248000
（1〜3 の全部が一致）、`-29048(gp)` = 0x00240e88 `GameManagerInst`。

### `resolve_symbol` — 名前から番地

`functions.json` → `labels.json` → `defined_data.json` → 実行ファイルの `.symtab`
の順に探します。`_vt_` で始まる名前は `kind: "vtable"`。
**labels.json が無い古い export でも止めずに**探し、`warnings` で再 export を促します。
`.symtab` の `_vt$7GmStage` は Ghidra 上の `_vt_7GmStage` と同じものなので、
`$` / `.` を `_` と同一視する `match: "normalized"` の段階があります。

### `program` の既定値（複数 Program モード）

`program` を省略すると、**このセッションで最後に使った Program**、それも無ければ
**レジストリ (`mcp_registry.json`) の最上位 `default_program`** を使います。
既定値を使った応答には **`program_defaulted: true`** と `program_default_source`
（`last_used` / `registry_default`）が付き、`program` は常に入ります（取り違え防止は維持）。
`search_programs` / `diff_programs` で触った Program は「最後に使った」扱いにしません。

## `classify_range` — 未定義領域の正体を当てる（2026-08 追加）

`list_undefined_ranges` は「未定義領域が 1,694 件あります」までしか言えません。
どれから見るかを決めるには結局その場で逆アセンブルしたり、ポインタらしさを
数えたりすることになります。それを道具にしたものです。

| 判定 | 主な根拠 |
|---|---|
| `code` | 命令として読める割合 + **分岐先が近くを指しているか** |
| `pointer_table` | 4 バイト境界の値が export 済みの番地を指す割合（Thumb の `entry\|1` も見る）|
| `text` | 可読 ASCII の密度 + NUL 終端の数 + **Shift-JIS の日本語**|
| `float_table` | f32 として妥当な値の割合（座標 / 行列）|
| `compressed` | BIOS ヘッダ + **実際に展開できるか**|
| `padding` | ゼロ埋め / 同じバイトの繰り返し |

`list_undefined_ranges(classify=true)` で、返した範囲ぶんだけ実行できます
（全件やると重いので、ページ単位です）。

### ★観点どうしの矛盾を潰さないと使い物になりません

各観点を独立に採点すると、実測で**必ず**次を外しました:

| 実際 | 素朴な判定 | なぜ |
|---|---|---|
| 圧縮データ | code (0.84) | Thumb は 16bit 固定長なので、乱数同然でも **88% が読める命令**に化ける |
| ASCII 文字列 | code (0.94) | 文字の並びも命令として読める |
| ゼロ埋め | code (1.00) | ゼロワードが MIPS の `nop` / Thumb の `movs r0,r0` になる |

そこで:

- **ゼロワードを「読めた命令」に数えない**（半分以上ゼロならコード判定自体を捨てる）
- エントロピーが **5.5 超**（圧縮 / 画像の帯）または **3.0 未満**（詰め物の帯）なら
  コードらしさを下げる
- 文字列 / ポインタ表 / 圧縮が強ければ、コードとは両立しないので下げる

これで既知 9 件のうち **8 件が正解、残り 1 件は「決め手なし」**（誤答ではなく棄権）に
なりました。落とした理由は `evidence.penalties` に残ります。

> **決め手が無いときは `verdict: null` を返します。無理に断定しません。**
> そのときはエントロピーの帯から「次に何を試すか」を返します
> （2.0 なら疎なデータ = 色数の少ないタイル、7.0 超ならほぼ乱数 = 圧縮か暗号化）。

## `render_tiles` の `show_index` — フォントの文字対応表を作る（2026-08 追加）

独自符号の対応表を作るとき、**「画面の何番目のタイルが符号 0x2A か」を人間が
数える**のが最大の手間でした。番号を絵に焼き込んでしまえば、見ながらそのまま
`decode_text` の表を書き起こせます。

| 引数 | 意味 |
|---|---|
| `show_index` | 各タイル（`sprite_size` 指定時はスプライト）に番号を焼き込む |
| `index_base` | 番号の開始値。符号が `0x20` から始まるなら `0x20` |
| `index_hex` | 既定 true（16 進）。10 進が良ければ false |
| `scale` | 拡大率。`show_index` のときは自動で 3 倍以上になる（8px だと数字が潰れるため）|

番号は絵に重ねず、**各タイルの下に帯を足して**描きます（重ねると絵が読めなくなる）。

```
render_tiles(source_path=..., bpp=4, tiles_per_row=16,
             show_index=true, index_base=0x20)
   ↓ 画像を見て並び順を読む
decode_text(address=..., table={"start": "0x20", "chars": "　あいうえお..."})
   ↓ 通ったら
bridge_config.json の text_tables に置いて使い回す
```


## 日本語 / 独自符号のテキスト (2026-08 追加)

Ghidra の文字列検出は基本 ASCII で、**Shift-JIS の日本語ラベルは
`strings.json` にほとんど出てきません**。せっかくゲーム側に日本語があるのに
取得できない、という問題への答えです。

### `find_text` — Ghidra が拾えなかった文字列

`encodings` は `sjis` / `utf8` / `eucjp`。**誤検出との戦いが本体**で、素朴に
「decode できたら文字列」とすると実測で数万件出ます:

| 条件 | 実測の件数 (SH-4 の Program 1 本) |
|---|---|
| 素朴に decode できたもの全部 | 223,222 |
| + 半角カタカナを数えない / NUL 終端を要求 / 珍しい符号位置を弾く | 1,656 |
| + JIS 第1水準まで (lead `0x81-0x98`) | 814 |
| + かなを 1 文字以上要求 | **129** |

最後の 129 件は**全部本物**でした (固定長レコードに並んだキャラクター名の表など)。

| 引数 | 既定 | なぜそうしているか |
|---|---|---|
| `allow_halfwidth` | false | 半角カタカナ (0xA1-0xDF) は**任意のバイナリに大量に出る**。最大の誤検出源 |
| `min_japanese` | 2 | 1 文字だけ「日本語に見える」のは偶然でいくらでも起きる |
| `min_kana` | 1 | 乱数は漢字だけの並びになりがち。本物はほぼかなを含む |
| `level2_kanji` | false | JIS 第2水準は乱数からいくらでも読めてしまう。人名で要るときだけ true |
| `require_terminator` | true | 本物はほぼ NUL で終わる。データの真ん中の偶然一致が落ちる |
| `only_missing` | true | `strings.json` に既にある番地を除く (取りこぼしだけが欲しい) |

> **推定なので誤検出は必ず混ざります。** `text` を読んで意味が通るものだけ採用してください。

### `decode_text` — 独自符号を文字対応表で読む

**この年代のゲームに Shift-JIS はほぼ入っていません。** 登録 13 Program を横断して
「ボタン」「セーブ」等を検索したら 0 件でした (実データ (SH-4) の機体名だけが例外)。
テキストは**フォントタイルへの独自インデックス**で持つのが普通です。
`find_text` が 0 件のときは、その道筋が `hint` に出ます:

```
フォントを render_tiles で PNG にする → 文字の並び順を目で読む
→ 対応表を作って decode_text → bridge_config.json の text_tables に置いて使い回す
```

表は**連番形式**で 1 行で書けます (独自符号はたいてい連番のため):

```json
{"start": "0x20", "chars": "　あいうえおかきくけこ..."}
```

明示的な辞書 (`{"00": "あ", "01": "い"}`)、連番ブロックの配列、2 バイト符号
(`"width": 2`) にも対応します。`bridge_config.json` に置くとこうなります:

```json
"text_tables": {
  "font_main": {"start": "0x20", "chars": "　あいうえお..."}
}
```

以後は `decode_text(address, table_name="font_main")` で使い回せます。

### Ghidra へ戻す

`find_text` / `decode_text` に **`as_proposal=true`** を付けると、
`proposals/proposed_comments.json` にそのまま保存できる形 (`[AI]` 付き) が
`proposal` に入って返ります。`tools/validate_proposed_comments.py` を通ります。

**MCP はこの JSON を保存しません。** 人間 (か解析セッション) が `proposals/` に
保存し、Ghidra GUI で `apply_comments.py` を実行して反映します。

`proposal_kind` で提案の種類を選べます:

| `proposal_kind` | 出るもの | 反映スクリプト |
|---|---|---|
| `comments` (既定) | `proposed_comments.json` (`[AI]` 付き) | `apply_comments.py` |
| `labels` | `proposed_labels.json` | `apply_labels.py` (**opt-in 必須**) |
| `both` | 両方 | 両方 |

### ラベルにするときの名前づくり

**Ghidra は日本語や独自符号を自動でラベルにしてくれません。** そこで
`proposal_kind="labels"` を付けると、読んだテキストから**ラベル名を正規化して**
作ります。ラベル名には日本語 (かな・漢字・長音符 `ー`・中黒 `・`) を使えますが、
**空白・記号・全角英数は入れません** (Ghidra の検索やスクリプトで扱いづらいため)。

| 元のテキスト | ラベル名 |
|---|---|
| `テムジン　７４７Ａ` | `テムジン_747A` |
| `テムジン　７４７Ａ／ｃ` | `テムジン_747A_c` |
| `フェイ・イェン with ＶＨ` | `フェイ・イェン_with_VH` |
| `スペシネフ１３「罪」` | `スペシネフ13_罪` |
| `極破壊少女戦機「ガラヤカ」` | `極破壊少女戦機_ガラヤカ` |

名前にできなかったものは `skipped` に理由つきで入ります。
同じ名前が並んだら連番を足します (似た名前が並ぶ表では普通に起きます)。
`label_prefix` を渡すと全部に接頭辞を付けられます。

> ★**ラベルの縛りは緩めていません。** `bridge_config.json` の
> `allowed_apply_operations` に `"labels"` が無ければ `apply_labels.py` は
> 何もせず終了します（既定禁止）。**関数エントリには付きません**（`force` でも拒否）。
> 既存の名前は上書きせず、台帳に記録されるので `revert_operations.py` で
> 巻き戻せます。保存も人間が行います。
>
> ★**文字列データ型の適用はしません。** Ghidra 上で「これは文字列だ」と型を付けるのは
> 「データ型の自動変更」に当たり**常に禁止**です。反映できるのは
> **ラベルとコメントまで**で、型を付けたい場合は人間が Ghidra 上で行ってください。


## GBA / 携帯機向けツール群（2026-08 追加）

GBA の解析で「毎回その場で Python を書いていた」作業を道具にしたものです。
**`decompress` / `render_tiles` / `render_tim` はこの MCP でファイルを書くツール**で、
書き先は `<project_root>/extracted/` に限定されています（ほかに `save_export_snapshot`）。

> ★**`source_path` で読めるのは許可ルートの配下だけ**です: 既定は
> `<project_root>/extracted/`（この道具の生成物）と `<project_root>/dumps/`（人間が
> 置いた素材）。外部の素材フォルダは、**人間が** `bridge_config.json` の
> `source_roots` に書いたときだけ読みます（MCP の引数からは広げられません）。
> 判定は resolve 後のパスで行い、`..` / リンク / ジャンクション / UNC / デバイスパスでの
> 脱出は拒否、範囲外ではファイルの有無も言いません。
>
> **絶対上限**（引数で緩められない）: 1 回に読むのは 64 MiB まで（`length` 未指定は
> そこで打ち切り）、`max_size` は 16 MiB まで、画像は拡大前 400 万画素・出力 1600 万画素・
> 一辺 16384 まで。ファイル入力のエラー文には入力のバイト値を出しません。
> 詳細は [../docs/safety_rules.md](../docs/safety_rules.md)。

### `decompress` — BIOS 圧縮の展開

GBA / NDS の BIOS 展開ルーチン（GBATEK 準拠）で圧縮されたデータを展開します。
`type` 省略時は先頭バイトから自動判定します。

| ヘッダ先頭 | 形式 | 備考 |
|---|---|---|
| `0x10` | LZ77 | 窓 4KB。GBA でいちばん多い |
| `0x24` / `0x28` | Huffman | 下位ニブルがシンボル幅（4bit / 8bit）|
| `0x30` | RLE | |
| `0x81` / `0x82` | Diff フィルタ | 8bit / 16bit。**`0x40` ではありません**（下の注記）|

> **★Diff フィルタのヘッダは `0x40` ではなく `0x8n` です。** GBATEK では
> `BitUnPack`=0x00 / `LZ77`=0x10 / `Huffman`=0x20 / `RLE`=0x30 /
> `Diff filter`=0x80 と定義されています。実装は GBATEK に合わせてあり、
> `0x4n` は「未定義の形式です」と明示エラーにします（黙って別形式として
> 展開すると、それらしいゴミが出て気づけないため）。

**展開結果は応答に載せません。** 数十〜数百 KB になるのでコンテキストを潰します。
`<project_root>/extracted/` に保存して `out_path` を返すので、続けて
`render_tiles` / `decompress` の `source_path` に渡してください。

**入れ子の圧縮**（展開結果の中身がさらに圧縮されている）は珍しくありません。
検出したら `nested` を付けて返すので、`out_path` を `source_path` にして
もう一度呼びます。よくある形:

| 元 | 形式 | 展開後 |
|---|---|---|
| ROM 上の番地 A | LZ77 | そのまま使えるデータ |
| ROM 上の番地 B | Huffman(4bit) | **中身がさらに LZ77** |
| ↑の出力 (`source_path`) | LZ77 | 最終的なデータ |

### `find_compressed_blocks` — 圧縮ブロックを探す

> ★**処理予算**（2026-10。引数では緩められない）: 1 回の走査は 8 MiB まで、展開を試すのは
> 20000 回まで、試した宣言サイズの累計は 256 MiB まで（棄却された候補も数える）。
> 止まったときは `complete: false` / `stopped` / `next_start` / `unscanned` を返すので、
> **候補が少なくても「圧縮データは無い」とは読まないこと**。続きは
> `start=<next_start>` で呼びます。ブロック全体は読まず、走査範囲 (+境界をまたぐ
> ブロックを展開するぶん) だけ読みます。

範囲を走査して圧縮ブロック候補を列挙します。**肝は誤検出の排除**です。
「先頭バイトが `0x10` で 24bit サイズがそれっぽい」だけなら 192KB の走査で
数十件が引っかかり、どれが本物か分かりません。次の 4 段で落とします:

1. **最後まで展開できること**（途中で木や窓の外に出たら失格）
2. **宣言サイズと実際の出力長が一致すること**
3. **圧縮率が 1.05 倍以上**（縮んでいないものは圧縮ではない）
4. **エントロピーが極端でないこと**（乱数同然 / 単一バイト連続を弾く）

> **RLE は既定で対象外**です（`include_rle=true` で有効化）。RLE は構造上の
> 制約がほぼ無く、**任意のバイト列が「展開できてしまう」**ため誤検出の主因になります。
>
> **入れ子の圧縮はエントロピー上限を免除**します。圧縮データを含む展開結果は
> 乱数同然に見えるので、そのままだと本物を捨ててしまいます。

実測（GBA ROM, 192KB 走査）: 素朴な走査 54 件 → **7 件**（4.8 秒 → 0.4 秒）。
既知の 2 ブロックは両方残っています。

### `render_tiles` — タイルデータを PNG で見る

「4bpp か 8bpp か」「1D マッピングか」は、**見るのがいちばん速い**のに、
毎回 Pillow スクリプトを書くのは無駄なので道具にしました。

| 引数 | 既定 | 意味 |
|---|---|---|
| `address` / `source_path` | どちらか必須 | メモリから読むか、ファイル (`decompress` の出力 / `dumps/` 等の許可ルート配下) を読むか |
| `bpp` | 4 | 4 / 8。**まず両方試すこと** |
| `tiles_per_row` | 32 | 横に並べるタイル数 |
| `palette_address` | なし | BGR555 パレット。省略時はグレースケール |
| `sprite_size` | なし | `[4,4]` なら **32x32 スプライト単位で並べ直す** |

> **`sprite_size` を指定しないと 1D マッピングのスプライトは形が読めません。**
> OBJ は 8x8 タイルが「スプライト内で順に」並ぶので、素直に横 32 枚で並べると
> 1 個のスプライトが 4 行にばらけます。
>
> 色が合わないのは配色の問題です。**形が読めていれば bpp は合っています。**

### `translate_address` — Program 間のアドレス換算

1 ゲームで複数のアドレス空間（親 ROM / ローダ / 展開先）を扱うと、
`0x020181F0` → `0x0835F9A8` のような換算を毎回手計算することになり、
取り違えが常について回ります。規則を `bridge_config.json` に置いて引きます。

```json
"address_translations": [
  {
    "name": "client_to_rom",
    "note": "おすそわけ受信バッファ -> 親 ROM",
    "src_base": "0x02000000",
    "block_size": "0x2000",
    "table": ["0x083477B8", "0x083497B8", "..."]
  }
]
```

`src_base` からの距離を `block_size` で割ってブロック番号を出し、
`table[番号] + ブロック内オフセット` を答えにします。`reverse=true` で逆向き。

### 規則の種類（`kind`）と組み込み規則

| `kind` | 意味 |
|---|---|
| `table`（既定）| 上のブロック表 |
| `offset` | `delta` を足し引き（`src_range` で適用範囲を絞れる）|
| `mask` | 上位ビットを落とす（`mask` で AND、`set` で OR）|
| `file_offset` | Ghidra のアドレス ⇄ **実行ファイル内の位置**（ヘックスエディタで開く場所）|
| `lorom` / `hirom` / `exhirom` | SNES のバス番地 ⇄ ROM ファイル内 offset を**式で**換算（下記）|

SNES の 3 つは表を書かずに使えます (`{"name": "rom", "kind": "lorom"}`)。
`copier_header` (`"auto"` 既定 = ROM ファイルの大きさから判定 / `true` / `false` / `0` / `512`)、
`rom_size` (省略時は ROM ファイルから)、`canonical` (`"fast"` 既定 = `$80-`/`$C0-` 側に
そろえる / `"slow"`)。返り値の `canonical` / `is_mirror` / `also_at` でミラーを、
**ROM でない番地** (各バンクの `$0000-$7FFF` 側・WRAM・`rom_size` の外) は
`is_rom: false` + `region` で返します (エラーにも変な値にもしません)。
★組み込みの `file_offset` は ROM を平置きとして扱うので LoROM では使わないこと。

**設定なしで使える組み込み規則**があります:

| 名前 | 変換 |
|---|---|
| `file_offset` | Ghidra アドレス ⇄ ファイル内 offset（実行ファイルがあるとき）|
| `snes_rom` | 65816 で memory_map のブロック名に `lorom` / `hirom` / `exhirom` のどれか 1 つが入っているとき、その式の規則 (ヘッダは自動判定) |
| `ee_kseg0_to_ram` | PS2 EE の `0x8xxxxxxx` ⇄ RAM ダンプ / ヘックスエディタ表示の `0x0xxxxxxx`（MIPS のとき）|

> 実行時デバッガやヘックスエディタとの往復で毎回手計算するのが、
> このプロジェクトが最も警戒している取り違えの元です。**機械的に変換してください。**
> 範囲外の入力は理由つきで拒否します（黙って変な値を返しません）。
使える規則名は `get_export_status` の `address_translations` にも出ます。

返り値には必ず **`reasoning`（計算の根拠）** が入ります:

```
0x020181F0 - 0x02000000 = 0x181f0 なのでブロック 12 + 0x1f0。
table[12] = 0x0835f7b8 だから 0x0835f7b8 + 0x1f0 = 0x0835f9a8
```

> **規則が間違っていれば結果も間違います。** 初回は既知の対応 1 件で必ず確かめてください。
> ★`bridge_config.json` は、この MCP が `ghidra_exports/` の**外を読む唯一の場所**です
> （変換規則は解析中に手で書き足すもので、書くたびに Ghidra から再 export させるのは
> 現実的でないため）。読むだけで、書き込みはしません。

## 2 つの起動モード

### 複数 Program モード（推奨・サーバ 1 個）

```
python mcp\ghidra_readonly_mcp.py --multi
```

サーバ **1 個**で登録済みの全 Program を扱います。ゲームを増やしても
**MCP のオプションも、ツール定義の数も増えません**。

| | サーバ数 | ツール定義数 |
|---|---:|---:|
| per-game 方式（従来） | Program の数だけ | 13 Program × 16 = **208** |
| `--multi`（1 サーバ） | **1** | **16** |

- 各ツールに `program` 引数が付きます（`"game_a"` / `"game_b:main"` など）。
  省略すると**直前に使った Program → レジストリの `default_program`** の順で決め、
  応答に `program_defaulted: true` を付けます。どちらも無ければ候補を列挙して
  エラーになります（黙って別ゲームを読まないため）。
- **応答には必ず `program` が入ります。** 取り違えたらその場で気づけます。
- `list_programs` で使えるキーと export の有無を確認できます。
- レジストリは `mcp_registry.json`（`--multi` だけなら `<toolbox>/../mcp_registry.json`）。
  `--registry <path>` / 環境変数 `CCT_MCP_REGISTRY` で変更できます。
  書式は [../samples/mcp_registry.sample.json](../samples/mcp_registry.sample.json)。
  **ゲームを追加しても reconnect は不要**です。`ProgramResolver` がレジストリの
  更新（mtime とサイズ）を検知して、次の呼び出しで読み直します。
  - 消えたキー / `root` が変わったキーは、常駐中の `ExportRepo` も捨てます
    （古い `root` の結果をそのキーとして返さないため）。変わっていないキーは作り直しません。
  - 読み直しに失敗（JSON の書き損じ・保存中など）してもサーバは落ちません。
    直前に読めた内容で動き続け、`list_programs` の `registry_warning` と
    「レジストリにありません」エラーに理由が出ます。保存し直せば次の呼び出しで復帰します。
  - 起動時に読めないときだけは従来どおりエラーで止まります（空のまま起動しない）。
  - 追加したのに出ない & `registry_warning` も無いときは、読み直し対応
    （2026-09-17）より前のコードでサーバが動いています。`/mcp` で一度 reconnect してください。
- `list_programs` の `exports_found` は **`ghidra_exports/program.json` の有無**で判定します。
  ひな形の生成で空の `ghidra_exports/` が先にできるため、フォルダだけでは `false`
  （そのときは `note` に理由が付きます）。
- export 前（`ghidra_exports/` が無い）Program を引いても、サーバは落ちずにエラーを返します。
- 常駐 Program 数は LRU で既定 3 に制限（`CCT_MAX_HOT_PROGRAMS`）。
  `ExportRepo` は xrefs 索引や 16MB のメモリイメージを抱えるためです。

登録手順は [../README.md](../README.md)「MCP サーバの登録」を参照してください
（`claude mcp add ... --registry <path>` か `.mcp.json` に 1 つ書くだけです）。

> このサーバがレジストリから読むのは **`games` の `root` / `label` / `programs` と
> トップレベルの `default_program` だけ**です。`server` / `individual_server` /
> `extras` などのキーは、同じファイルを書く別の管理ツール向けのもので、
> このサーバは無視します（書いてあっても無害）。先頭が `_` のキーは読み飛ばします。

### 単一 Program モード（従来どおり・後方互換）

```
set CCT_PROJECT_ROOT=C:\RE\ai_workspaces\GAME_A
python mcp\ghidra_readonly_mcp.py
```

`CCT_PROJECT_ROOT`（か第1引数）を渡すと従来どおり 1 Program 専用で動き、
`program` 引数は省略できます。**既存の登録はそのまま使えます。**

> どちらのモードでも提供ツールは同じです。`program` 引数は単一モードでは
> 無視されます（違うキーを渡したときだけエラーになります）。

## 前提

- Python 3.12 以上（3.13 推奨）
- 対象プロジェクト（`claude_project`）に `ghidra_exports/` が出力済みであること
  （先に Ghidra GUI で `export_context.py` を実行）

## セットアップ

```
python -m pip install -r mcp\requirements.txt
```

> `--selftest` はこの依存（`mcp` SDK）が無くても動きます。SDK が必要なのは
> MCP サーバとして起動するときだけです。Pillow は `render_tiles` / `render_tim` で使います。

## 自己テスト（Ghidra / MCP SDK 不要）

```
set CCT_PROJECT_ROOT=C:\path\to\game_project
python mcp\ghidra_readonly_mcp.py --selftest
```

各ツールが実 export に対して動くこと、フィルタ必須・パストラバーサル拒否が
効くことを確認できます。

## MCP サーバとして起動 / クライアント登録

複数 Program モード（推奨）なら `--registry <path>` を付けてサーバを 1 つだけ登録します
（[../README.md](../README.md)「MCP サーバの登録」）。
単一 Program モードでは、対象プロジェクトを環境変数 `CCT_PROJECT_ROOT`
（または第1引数）で指定し、ゲーム（プロジェクト）ごとにサーバ定義を 1 つ登録します。

`.mcp.json`（または各クライアントの MCP 設定）の例:

```json
{
  "mcpServers": {
    "ghidra-game-a-readonly": {
      "command": "python",
      "args": ["C:\\path\\to\\ghidra_toolbox\\mcp\\ghidra_readonly_mcp.py"],
      "env": {
        "CCT_PROJECT_ROOT": "C:\\path\\to\\game_project"
      }
    }
  }
}
```

第1引数で渡す形でも可:

```json
{
  "mcpServers": {
    "ghidra-game-a-readonly": {
      "command": "python",
      "args": [
        "C:\\path\\to\\ghidra_toolbox\\mcp\\ghidra_readonly_mcp.py",
        "C:\\path\\to\\game_project"
      ]
    }
  }
}
```

## 制限事項（第1段）

- 再 export（`export_context.py` 相当）は**自動実行しません**。`get_export_status`
  で鮮度を確認し、古ければ Ghidra GUI で `export_context.py` を再実行してください。
- レガシーの巨大 `*_instructions.json`（各 380MB 級）は読み込み対象外です。
- 1 サーバ = 1 プロジェクト（`CCT_PROJECT_ROOT`）。**`--multi` なら 1 サーバで
  全 Program を扱えます**（上の「複数 Program モード」参照）。
- **ファイルを書くのは `decompress` / `render_tiles` / `render_tim` と `save_export_snapshot` だけ**で、
  書き先は `<project_root>/extracted/` に限定されています。`source_path` で読めるのは
  許可ルートの配下だけです（[../docs/safety_rules.md](../docs/safety_rules.md)）。
