# CLAUDE.md — ゲーム解析プロジェクト

このフォルダは 1 つのゲーム (または 1 つの解析対象) 用の、Ghidra と
Claude Code / Codex の受け渡し作業場です。Claude Code / Codex はこの
ファイルのルールに従って作業してください。

## このプロジェクトの読み方

- `ghidra_exports/` 以下の情報を読んで解析する。
  - `program.json` / `functions.json` / `strings.json` / `comments.json`
    / `xrefs.json` / `undefined_ranges.json` / `decompile/`
  - `memory_map.json` / `memory/*.bin` … メモリイメージ（`export_memory: true` のときだけ）
- `dumps/` には RAM dump やメモリ検索結果などの動的解析素材がある。
- `notes/address_map.md` にアドレス基準と変換ルールが書いてある。
- `ghidra_exports/`、`dumps/`、`notes/address_map.md` を突き合わせて解析する。

### 読み取り専用 MCP の使い方

MCP は **全 Program 共通の 1 サーバ**（`ghidra-readonly`）です。

- **各ツールに `program="<このゲームのキー>"` を必ず渡す。** 省略すると使える
  キーを列挙したエラーになります（黙って別ゲームを読まないための仕様）。
  キーが分からなければ `list_programs` で確認する。
- **応答の `program` を毎回見る。** 別ゲームを読んでいないかの確認になります。

主なツール:

| やりたいこと | ツール |
|---|---|
| **前回までの結論を読み返す** | `list_comments` ← **解析を始める前に必ず 1 回**。二度手間の防止 |
| 疑似C を読む | `get_decompiled_function`（`decompile/` の直読みでも可）|
| **疑似C の行がどの番地か** | `get_decompiled_function(with_addresses=true)` ← 1 命令の違いを追うときは必ずこれ |
| **変数の意味を残す / 読みやすくする** | `propose_variable_notes` → `get_decompiled_function(rename=true)` |
| **この関数は何を渡されて呼ばれるか**（MIPS/PPC） | `list_call_sites` ← 疑似C が落とした引数の定数が出る |
| **この関数は何個引数を取るのか** | `infer_signature`（断定しない。confidence と conflicts を見る）|
| **この関数は何を呼ぶのか** | `list_callees`（深さ指定。循環は打ち切る）|
| **前回の export からどこが進んだか** | `save_export_snapshot` → 再 export → `diff_exports` |
| **実行時に本当に使われているか** | `get_runtime_range_evidence` / `list_runtime_observations`（要 `runtime_observations/*.json`）|
| **未関数化 (`LAB_xxxxxxxx`) を読む** | `get_disassembly`（データは `.long`/`.word` で出る）|
| **Ghidra が xref を持たない表の参照元** | `find_address_refs`（範囲なら `range_end`）|
| 表の中身を読む / 構造を推定する | `read_data` / `describe_data` / `find_pointer_tables` |
| **型が混ざった固定長レコードの表** | `read_data(record="u8,s8,s8,s8,s8")` / `record="@名前"` (`list_record_formats`) |
| **この数値はどこで設定されるか**（MIPS） | `find_immediate` ← 閾値・ID・フラグ値の出どころ |
| **実行時に読み込まれる外部ファイルを読む** | `list_overlays` + `bridge_config.json` の `overlays` |
| **その番地に書く命令を全部知る**（SH-4 / MIPS） | `find_writers` |
| **関数入口を確かめる**（SH-4 / MIPS / ARM / Thumb） | `find_function_entry` ← 関数を呼ぶ前に必ず通す |
| switch の全分岐先（SH-4 / MIPS） | `expand_switch` |
| **関数化されていない飛び先を洗い出す** | `find_undefined_targets`（`as_proposal` で反映案）|
| **アドレス基準の変換** | `translate_address`（`file_offset` / `ee_kseg0_to_ram` は設定不要）|
| **表の各オフセットが何なのか** | `find_struct_field_uses`（offset 省略が本命）|
| **`DAT_xxxxxxxx` の中身**（Thumb/ARM） | `resolve_pool` / `get_decompiled_function` の `pool` |
| **この番地を指すポインタはどこか** | `find_pointers_to`（**データ**中の生ポインタ）|
| **その番地に何という名前が付いているか** | `list_labels`（人間が付けた型も出る）|
| **名前から番地を引く**（`_vt_7GmStage` 等） | `resolve_symbol`（vtable は kind=vtable）|
| **疑似 C のフィールドが何バイト目か**（`self->resourceTable`） | `find_field` / `get_struct_layout`（`flatten=true` で入れ子を展開）|
| **MIPS の gp 相対 (`lw v0,-29048(gp)`) の参照先** | `resolve_gp_offset` / `get_disassembly`（既定で注記）。gp の根拠は `get_program_info` の `gp_source` |
| **次にどこを見るか決める** | `list_undefined_ranges`（`with_refs=true, classify=true`）|
| **この領域は何なのか** | `classify_range`（コード / 表 / 文字列 / 圧縮 / 詰め物）|
| バイト列を探す（AOB） | `find_bytes`（`??` ワイルドカード可）|
| **どの Program にあるか横断で探す** | `search_programs`（この 1 つだけ `program` 不要）|
| 製品版と修正版の差分 | `diff_programs`（`what="bytes"` で関数名つき）|
| **Ghidra が拾えない日本語** | `find_text` → `as_proposal=true` で反映案 |
| 独自符号のテキスト | `decode_text`（文字対応表を渡す）|
| **Program 間のアドレス換算** | `translate_address`（規則は `bridge_config.json`）|
| **圧縮データを展開する**（GBA/NDS） | `decompress` / `find_compressed_blocks` |
| **タイルデータを見る**（GBA） | `render_tiles` → PNG |
| **PS1 の画像を見る** | `find_tim_blocks` → `render_tim` （直線配置なら `render_tiles(layout="linear", width=…)`）|

> **参照を探すときは `find_address_refs`（コードから）と `find_pointers_to`
> （データ中の生ポインタ）の**両方**を見ること。** GBA のリソースはデータ表から
> 参照されることが多く、コード参照だけを見て「どこからも参照されない没データ」と
> 誤断しかけた事故があります。どちらも 0 件のときだけ hint を返します。

> **`find_address_refs` の 0 件を「参照が無い」と読まないこと。** 0 件のときだけ
> 応答に `hint` が付き、原理的に拾えない形（SH-4 の GBR 相対など）が列挙されます。
> 必ず読んでから結論すること。

> **長い逆アセンブルは `get_disassembly` に `format="text"` を付けること。**
> 既定の JSON は 30 命令で 5KB を超え、読む前にコンテキストが尽きます
> （実際に読むのを諦めた事例あり）。`text` は同じ内容を 1 命令 1 行で返します
> （情報は落ちません）。バイト列や `flow` をプログラムで扱うときだけ `json`。

> **アドレス基準の変換を手計算しないこと。** ヘックスエディタの表示や
> 実行時デバッガのアドレスとの往復は `translate_address` を使う
> (`file_offset` と `ee_kseg0_to_ram` は設定不要で使える)。
> このプロジェクトが最も警戒しているミスなので、機械的に変換すること。

> **`export_memory: false` でも逆アセンブル系は動く。** 実行ファイルが手元に
> あれば自動でそこから読む。`get_export_status` の `memory.source` が
> `executable` ならその状態。ただし **.bss など未初期化領域は読めない**
> (実行時の値が要るなら RAM ダンプか再 export)。

> **`list_labels` を最初に見ること。** 人間が既に名付けた番地へ重複提案を出したり、
> `describe_data` で推定し直したりするのを防げます。**人間が付けた型は推定より正**です。
> `list_labels` が「labels.json がありません」と言ったら、Ghidra GUI で
> `export_context.py` を再実行してもらってください。

> **日本語は Ghidra がほとんど拾えません。** `strings.json` に無くても
> 「日本語が無い」とは限らないので、`find_text` を通してください。
> ただし**この年代のゲームは独自符号のことが多い**です（Shift-JIS が 0 件でも普通）。
> その場合は フォントを `render_tiles` で見る → 文字対応表を作る →
> `decode_text` → `bridge_config.json` の `text_tables` に置いて使い回す、の順。
> **`render_tiles` に `show_index=true, index_base=0x20` を付けると各タイルに
> 番号が焼き込まれる**ので、対応表をそのまま書き起こせます。
> Ghidra へ戻すときは `as_proposal=true` で提案を作り、`proposals/` に保存して
> 人間が `apply_comments.py` / `apply_labels.py` を実行します。
> `proposal_kind` で **`comments` / `labels` / `both`** を選べます
> (ラベルは `allowed_apply_operations` に `"labels"` が必要)。
> **文字列データ型の適用は常に禁止**なので、反映できるのは**ラベルとコメントまで**です。

> **`iVar1` が何か分かったら `propose_variable_notes` で残すこと。**
> 意味づけは**関数入口の `[AI]` コメント**として Ghidra へ戻します
> (`proposals/` に保存 → 人間が `apply_comments.py`)。反映後は
> `get_decompiled_function(rename=true)` が**読みやすい疑似 C
> (`code_renamed`) を自動で組み立てます**。`code` は手つかずのままです。
> その場限りなら `rename_map={"iVar1": "残り時間"}` でも効きます。
>
> ★**根拠の無い名前を付けないこと。** `iVar1` は「分からない」という**正しい
> 情報**を持っています。間違った名前はそれより悪い（読む人が考えるのをやめる）。
> 根拠は `evidence` に書き、確度は `confidence` で正直に下げてください。
> **Ghidra のローカル変数名そのものを書き換える機能はありません**（意図的）。

> **解析を始める前に `list_comments` を 1 回通すこと。**
> この道具箱の往復は「AI がコメント案 → 人間が `apply_comments.py` で反映 →
> 次のセッションが続きから」です。**前回確定したことはコメントに書かれている**ので、
> 読まずに始めると同じ場所を二度解析します。`ai_only=true` で自分の前回の所見だけ、
> 付けなければ人間が書いたものも出ます（**人間のコメントの方が強い情報**）。
> 未定義領域やデータ番地のコメントは疑似 C には出ないので、なおさらです。

> **「この数値はどこで設定されるか」は `find_immediate`（MIPS）。**
> `find_address_refs` は**アドレス**、`find_bytes` は**バイト列**なので、
> `addiu $a0,$zero,100` のような**即値**はどちらでも引けません。
> kind の **compare** が「その値と比べている」＝閾値の本命、**const** が
> 「定数を作っている」です。件数が多いときは `start`/`end` で関数の範囲に絞ること。

> **同じ表を何度も読むなら `bridge_config.json` の `record_formats` に登録する。**
> `read_data(record="@part_entry")` で引けます（`list_record_formats` で一覧）。
> **Ghidra の構造体とは別物**で、read_data がどう区切って読むかを決めるだけです。

> **PS1 の画像は `find_tim_blocks` → `render_tim`。**
> `render_tiles` は GBA の **8x8 タイル**前提なので、直線配置の TIM は形が崩れます。
> `render_tim` は幅・深さ・CLUT をヘッダから読み、**色違いは `clut_index` で
> 切り替えられます**。タイルでない素のビットマップは
> `render_tiles(layout="linear", width=…)` を使ってください。

> **疑似 C の行から番地を出すときは `with_addresses=true`。**
> 「怪しい行は見つけたが、それがどの番地か分からない」ために
> `get_disassembly` を並べて突き合わせるのは無駄です。`listing` が
> `<番地>  <疑似 C の 1 行>` で返ります（`code` は手つかず）。
> `line_map: false` が返ったら対応表が未 export なので、
> `line_map_hint` の手順で再 export してもらってください。

> **疑似 C が引数を落としていたら `list_call_sites`（MIPS）。**
> `FUN_801a1a0c(param_1,3)` の 3 番目が何かは、呼び出し直前の
> `addiu $a2,$zero,1` を見るまで分かりません。このツールは各呼び出しの
> `$a0`〜`$a3` を **即値 / アドレス / 実行時 / 呼び出し元から持ち回り** に
> 分けて返し、`constants` に「どの引数にどの定数が何回渡されているか」を
> まとめます（テーブル駆動のコードではこれ自体が答えになります）。
> **値が追えなかったものは `runtime` / `inherited` で返ります。0 と読まないこと。**

> **実行時に RAM へ読み込まれる外部ファイル（ステージデータ / 地形の高さ表 /
> オーバーレイ）は `bridge_config.json` の `overlays` に登録する。**
> 登録すれば `read_data` / `find_bytes` / `describe_data` / `classify_range` /
> `find_pointers_to` が **EXE 内の表とまったく同じように**その範囲でも効きます
> （自前 Python でパースし直さない）。応答の `block` は必ず `overlay:<名前>` に
> なるので、Program 本体の値と取り違えません。登録状況は `list_overlays`。

> **`decompress` / `render_tiles` は MCP で唯一ファイルを書くツール**です。
> 書き先は `<project_root>/extracted/` 配下だけで、既存ファイルは上書きしません。
> 展開結果は応答に載らないので、返ってきた `out_path` を次の呼び出しの
> `source_path` に渡してください（**入れ子の圧縮**は珍しくありません）。

> **実行時の観測は `runtime_observations/` に JSON で保存して使い回す。**
> エミュレータのデバッガ MCP で観測したら、その結果を
> `schemas/runtime_observations.schema.json` の形にして保存してください。
> 以後 `get_runtime_range_evidence(start=..., length=...)` で
> **Ghidra 番地のまま**「実行時に触れた記録があるか」を引けます。
> `capture.scenario` と `capture.coverage_note`（何をどこまで実行したか）を
> **必ず書くこと** — これが無いと観測 0 件の意味を読み違えます。
>
> ★**`verdict` に `unused` はありません。** `not_observed` /
> `coverage_unknown` までです。**「観測されなかった」は「使われていない」の
> 証明ではありません。** 静的側（`find_address_refs` / `find_pointers_to`）と
> **両方**を見て判断してください。どちらも 0 件でも、それは「未使用」の確定では
> ありません。
>
> ★Ghidra Toolbox の MCP は**エミュレータを起動も接続も制御もしません**。
> 観測するのはエミュレータ側の MCP、保存するのは人間か解析セッションです。

### 動的解析（実行中のメモリ）と組み合わせるとき

静的（Ghidra MCP）で分からないことは動的で埋めます。使える道具は対象によります。

| 道具 | できること |
|---|---|
| PulseHexPy（`pulsehex`） | 実行中プロセスのメモリ検索 / ポインタ追跡 / 構造体推定 / アクセス元の特定 |
| エミュデバッガ（`mgba-debugger` 等。名前は環境による） | ブレーク・ウォッチ・レジスタ・ステップ実行 |

**★アドレス基準を確認してから突き合わせること。**
静的側（Ghidra）のアドレスと動的側が返すアドレスは**基準が違うことがあります**
（プロセス仮想アドレス / ゲスト RAM アドレス / dump オフセット）。
ゲスト側のアドレスへ直してから比較し、対応が不明なら `notes/address_map.md` に
「未確認」と書く。推測で断定しないこと。

**典型的な往復**: Ghidra で構造を読む → 値の意味が分からない → 動的でその番地を
監視して「いつ何が書かれるか」を見る → アクセス元の命令アドレスを掴む → Ghidra に戻る。

> `find_address_refs` が **0 件でも「参照が無い」ではありません。** SH-4 の GBR 相対の
> ように静的に拾えない形があるので、**そのときこそ動的側で「誰が触るか」を見ます**
> （GBR+0xDC に乱数の種を置く、のような形が典型例）。

**やってよいこと / 許可が要ること**

| 層 | 例 | 扱い |
|---|---|---|
| 読み取り | メモリ検索 / 読み出し / AOB スキャン / ポインタ追跡 / 構造体推定 | **自由に使ってよい** |
| 実行への介入 | ブレーク / ウォッチ / ステップ | ゲームが止まる。**事前に一言**（対戦中・録画中は特に）|
| **書き込み** | 改造コード / `write_value` / `freeze_value` | **都度、人間の明示許可が必要** |

### ★書き込みは「改造コードテキスト」で提示するのが基本

PulseHexPy は改造コードを適用できます。**書き込みが必要なときは、直接
`write_value` を実行するのではなく、改造コードのテキストを提示してください。**

理由:

- **ユーザーが GUI で自由に ON/OFF できる**（戻すのがトグル 1 回。書き戻し手順が要らない）
- まとめて保存・再利用でき、何を当てているかが一覧で見える
- 効果が無ければ切るだけで済むので、試行錯誤が安全

**書式**（`pulsehex_code_v1`）:

```
ADDR VALUE                 # 16進。VALUE の桁数が書き込み幅
                           #   05 = 1バイト / EB01 = 2バイト / 0803A0A9 = 4バイト
!ADDR VALUE                # write-once（適用時に 1 回だけ書く）
BASE("key")+OFFSET VALUE   # ベース相対
IF(left op right) / ELSE / ENDIF
WHILE(N) / ENDWHILE / BREAK
# 行頭コメント     ADDR VALUE  // 行末コメント
```

- 値は**数値として書かれ、エンディアンは PulseHexPy が処理します**。
  命令パッチなら**命令ワードをそのまま**書けば通ります。
- **`!`（write-once）を使う場面**: 乱数の種・トグルフラグなど、毎フレーム書き続けると
  壊れるもの。迷ったら通常行ではなく `!` を検討する。
- **命令パッチには必ずコメントで「元の命令 → 新しい命令」を書く。** 例:

```
0C05C926 EB01     # mov.w 0x258,r11 (9B28) → mov #1,r11 (EB01)
```

提示するときは **タイトル（何が起きるか）/ 目的 / 対象アドレスとアドレス基準 /
元の値** を添えること。元の値はコメントに埋め込めば上の例のように 1 行で済みます。

> `write_value` / `freeze_value` の直接実行は「**その場限りの確認**」に留めてください
> （値を変えて挙動が変わるかを 1 回試す等）。恒久的に当てるものは改造コードにします。
> どちらにせよ**実行前に人間の許可が要ります**。

理由: Ghidra への apply を人間がトリガするのと同じ方針です。むしろ**実行中のゲームを
書き換える方が影響が大きい**（クラッシュ・セーブデータ破損があり得る）ので、
Ghidra への反映より緩くする理由はありません。

## やってよいこと

- `ghidra_exports/` の静的解析結果を読む。
- `dumps/` の動的情報を、静的解析を補強する材料として読む。
- `notes/` に Markdown で解析メモを整理する。
- `proposals/` に変更案を JSON として出す。
- 最初に許可する変更案は **コメントのみ**。
- **どの提案 JSON にも `target_program` (対象の Ghidra Program 名) を必ず書く。**
  `ghidra_exports/program.json` の `program_name` と同じ値にする。無い・空・違う名前だと、
  apply は**何も変更せずに中止**する (MCP の `as_proposal` で作った提案には入っている)。
  Program が複数ある構成では、提案ごとに正しい Program 名を書くこと。

## やってはいけないこと

- Ghidra プロジェクト本体を直接編集しない。
- 既存の人間コメントを削除する案を出さない。
- **関数名変更 (リネーム)・データ型変更・配列化・構造体適用は常に禁止**。
  提案もしない。
- 関数作成 (`proposed_functions.json`)・未定義化・**ラベル付け
  (`proposed_labels.json`)** は、`bridge_config.json` の
  `allowed_apply_operations` にその操作が書いてある場合のみ提案してよい。
  書いていなければ **提案自体を出さず**、`notes/` に「こう命名したい」と
  メモするだけにする。

## ラベル付け (proposed_labels.json) のルール — 出す場合

- `allowed_apply_operations` に `"labels"` が無ければ出さない。
- 名前は英数字 / `_` / **日本語 (かな・漢字・長音符・中黒)** が使える。
  **空白・記号・全角英数は不可** (全角英数は半角へ、空白は `_` へ寄せる)。
  先頭は英字・`_`・かな・漢字。`DAT_` / `LAB_` などの自動生成名の接頭辞は使わない。
- ゲーム内テキストからラベルを起こすなら `find_text` / `decode_text` に
  `as_proposal=true, proposal_kind="labels"` を付ける。名前は自動で正規化される
  (`テムジン　７４７Ａ／ｃ` → `テムジン_747A_c`)。
- **関数エントリには付けない** (関数名の自動変更は常に禁止。apply 側でも拒否される)。
- `evidence` に参照元アドレス・参照している処理・要素サイズなどの根拠を書く。
- 既存の名前を上書きする `force: true` は原則使わない。使うなら
  `confidence` を medium 以上にし、`evidence` に「なぜ既存名が誤りか」を書く。

## コメント案 (proposals/proposed_comments.json) のルール

- コメントは必ず `[AI]` で始める。
- 推測には `confidence` (low / medium / high) を付ける。
- 根拠 (`evidence`) には、xref / 文字列参照 / 呼び出し元 / 周辺処理 /
  メモリダンプとの対応などを書く。
- フォーマットは `schemas/proposed_comments.schema.json` に従う。

## 入力ソースの多様性に関するルール（重要）

Ghidra の export 元は実行ファイルとは限らない (raw binary / メモリダンプ /
ROM / overlay / 複数 Program など)。そのため:

- 必ず `bridge_config.json` の `source_model` を確認する。
- アドレスを比較する時は `notes/address_map.md` を確認する。
- **Ghidra アドレス / 実行時 RAM アドレス / dump 内 offset を混同しない。**
- アドレス変換ルールが不明な場合は、推測で断定せず
  `notes/address_map.md` に「未確認事項」として追記する。
- メモリダンプは、Ghidra の静的解析結果を補強する動的情報として扱う。
- 実行ファイルが無い解析では、Ghidra 上の Program が `memory_dump` 由来
  または `raw_binary` 由来である可能性を明記する。
- NOP 候補やコメント案を出す時は、どのアドレス基準で書いているかを
  必ず明記する (`proposed_comments.json` の `address_basis` も使う)。

## 解析メモ (notes/) のルール

- `notes/` に Markdown で整理する。
- 解析メモでは **不明点** と **確定情報** を必ず分けて書く。
