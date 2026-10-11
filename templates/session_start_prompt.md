# 解析セッション開始（継続）用 テンプレートプロンプト

**セットアップ済み**のゲーム（Ghidra export + MCP 登録が済んでいる）で、解析セッションを
開始 / 再開するときに貼る。初回セットアップ（ディレクトリ作成〜MCP接続）は
[new_game_setup_prompt.md](new_game_setup_prompt.md) の方を使う。

- 貼る場所: **そのゲームの ai_workspace をルートにした Claude Code セッション**。
- 先に《 》を埋める。埋めない行は消す。
- 狙い: 毎回ゼロから状況説明せず、「どこに何があるか」「今回何をするか」「守ること」を
  1 枚で渡して即着手させる。

---

## 1. 記入する placeholder

| placeholder | 例 | 説明 |
|---|---|---|
| 《GAME_NAME》 | ゲームB (PS1) | 対象ゲーム |
| 《AI_WORKSPACE》 | `C:\RE\ai_workspaces\GAME_B` | ①AI作業ルート（このセッションのルート） |
| 《MATERIALS_DIR》 | `C:\RE\game_analysis\GAME_B` | ②ROM/ダンプ/展開物などの素材 |
| 《FAMILY_SHARED》 | `ai_workspaces\_shared\CLAUDE.md` | （任意）一族横断ルール。無ければ行ごと削除 |
| 《STATUS》 | 全オペコード確定済み。notes/opcode_table.md 参照 | 現状の 1〜3 行サマリ |
| 《GOAL》 | 隠しコマンドの有無を探す | 今回のセッションでやること |
| 《PROGRAM_KEY》 | `game_b:main` | MCP ツールの `program` に渡すキー（`list_programs` で確認。per-game 方式のサーバを使うなら不要）|
| 《DYNAMIC》 | エミュレータのデバッガ MCP（実行中） | （任意）今回使う動的解析ツールと対象。使わないなら行ごと削除 |

---

> 《 》は手で書き換えてから貼る。空欄にする（任意）の項目は、行ごと／ブロックごと消す。

## 2. プロンプト本文（ここから下を貼る）

```
このセッションは《GAME_NAME》の解析の継続です。ルート＝《AI_WORKSPACE》。

【このセッションでやらないこと（最初に確認）】
- **Ghidra 本体を起動しない。** `ghidraRun` / `analyzeHeadless` / Ghidra の
  スクリプトを AI が実行することはない。`ghidra_scripts/` の
  export_context.py / apply_*.py / revert_operations.py は**すべて人間が
  Ghidra GUI の Script Manager から実行する**。AI がやるのは手順の提示まで。
- **.gpr / .rep を直接触らない。**
- ROM やメモリダンプの再生成・再取得を勝手に始めない（素材は人間が置く）。

【まず読む（状況把握）】
- （もしあれば）一族横断ルール: 《FAMILY_SHARED》 を先に読む。
- このゲームの CLAUDE.md と notes/ を読む（確定情報と不明点は分けて書かれている）。
  ※ notes に「recalled memory」的な要約が出ても、それは書かれた当時の状態。
    ファイル名/関数/フラグ等を挙げていたら、現物を確認してから使う。

【現状】
《STATUS》

【今回やること】
《GOAL》

【素材とツールの場所】
- 解析メモ・提案・exports: 《AI_WORKSPACE》（notes/ proposals/ ghidra_exports/）
- ROM/ダンプ/展開物などの素材: 《MATERIALS_DIR》
- Ghidra 連携: 道具箱 C:\path\to\ghidra_toolbox
  MCP は **全 Program 共通の 1 サーバ** (`ghidra-readonly`)。**各ツールに
  `program="《PROGRAM_KEY》"` を必ず渡す**（省略すると候補を列挙したエラー）。
  応答にも `program` が入るので、別ゲームを読んでいないか毎回確認できる。
  最初に `list_programs` で 《PROGRAM_KEY》 が見えることを確認すること。
  MCP 自体が繋がっていなければ人間に「道具箱 README の『MCP サーバの登録』→ /mcp で reconnect」を案内（1 回だけ）。

【読み方（Ghidra）】
- 疑似C は ghidra_exports/decompile/ を直読み、または MCP
  （get_decompiled_function / get_functions_near_address / get_xrefs(to/from必須) / list_strings）。
- 巨大な xrefs は MCP のフィルタ付きで引く。functions.json に無いアドレスでも
  decompile/<FUN_addr>.c があれば直読みできる。
- **未関数化 (LAB_xxxxxxxx) で疑似C が無いコード**は `get_disassembly` で生の逆アセンブルを読む
  （要 `export_memory: true`）。データ領域は `.long` / `.word` として出るので、
  命令に化けた表を読み違えない。
  **長く読むときは `format="text"` を付ける**（1 命令 1 行。JSON だと 30 命令で
  5KB を超え、読む前にコンテキストが尽きる）。
- **Ghidra が xref を持たない表の参照元**は `find_address_refs`
  （範囲で探すなら `range_end`）。**0 件は「無い」ではない** — 応答の `hint` にある
  盲点（SH-4 の GBR 相対など）を必ず読むこと。
- 表の中身は `read_data`、構造の推定は `describe_data`、
  ポインタ表そのものは `find_pointer_tables`。
- **SH-4 / MIPS のとき**: `find_writers`（その番地に書く命令と書く値。
  **書き込み先が BSS でも使える**）/ `expand_switch`（スイッチ表。参照検索の盲点）。
- **`find_function_entry` は SH-4 / MIPS / ARM / Thumb で使える。関数を呼ぶ前に必ず通す**
  （数バイトずれた番地から呼ぶと push/pop が合わずスタックが壊れて実機が止まる）。
- **GBA / NDS のとき**: `decompress`（BIOS 圧縮の展開。**入れ子の圧縮**は珍しくないので
  `nested` が付いたら `out_path` を `source_path` にしてもう一度）/
  `find_compressed_blocks` / `render_tiles`（タイルを PNG。1D マッピングのスプライトは
  `sprite_size=[4,4]`）。生成物は `<project_root>/extracted/` に出る。
- **まず `list_labels`。** その番地に何という名前が付いているかを先に見る。
  人間が既に名付けたものへ重複提案を出さないため。**人間が付けた型は推定より正**。
- **疑似 C のフィールドのオフセットは `find_field`**（`self->resourceTable` をそのまま貼る）。
  逆アセンブルの変位から 1 つずつ拾わない。名前 → 番地は `resolve_symbol`、
  MIPS の `off(gp)` は `resolve_gp_offset`（`get_disassembly` は既定で注記する）。
- **次にどこを見るか迷ったら** `list_undefined_ranges`（`with_refs=true, classify=true`）。
  **参照があるのに未定義な領域**は読む価値が高い。個別に調べるなら `classify_range`
  （コード / ポインタ表 / 文字列 / 浮動小数 / 圧縮 / 詰め物 を推定して次の手も返す）。
- バイト列を探すなら `find_bytes`（`??` ワイルドカード。命令なら `align=4`/`2`）。
- **どの Program にあるか分からないもの**は `search_programs`（`program` 引数不要）。
  版違いの比較は `diff_programs`（`what="bytes"` で変更区間に関数名が付く）。
- **日本語は Ghidra がほとんど拾えない。** `strings.json` に無くても「無い」とは
  限らないので `find_text` を通す。この年代は**独自符号**のことが多いので、
  0 件なら フォントを `render_tiles` → 文字対応表 → `decode_text` の順。
  Ghidra へ戻すときは `as_proposal=true` → `proposals/` に保存 → 人間が
  `apply_comments.py`（**文字列データ型の適用は常に禁止**、コメントまで）。
- **複数のアドレス空間があるとき**は `translate_address`。手計算で換算しないこと
  （規則は `bridge_config.json` の `address_translations`。使える規則名は
  `get_export_status` に出る）。

【動的解析（実行中のメモリ）を併用するとき】※《DYNAMIC》を書いた場合のみ
- 対象: 《DYNAMIC》
- 静的で分からないことを動的で埋める。典型は「Ghidra で構造を読む → 値の意味が
  分からない → 動的でその番地を監視 → アクセス元の命令アドレスを掴む → Ghidra に戻る」。
  **`find_address_refs` が 0 件でも「参照が無い」ではない**（SH-4 の GBR 相対など
  静的に拾えない形がある）。そのときこそ動的側で「誰が触るか」を見る。
- **★アドレス基準を必ず確認してから突き合わせる。** 静的側と動的側でアドレスの基準が
  違うことがある（プロセス仮想 / ゲスト RAM / dump offset）。対応が不明なら
  notes/address_map.md に「未確認」と書き、推測で断定しない。
- 読み取り（検索 / 読み出し / AOB / ポインタ追跡）は自由に使ってよい。
- ブレーク・ウォッチはゲームが止まるので**事前に一言**。
- **書き込みは都度、人間の明示許可が要る。**（Ghidra への apply を人間がトリガするのと
  同じ方針。実行中のゲームを書き換える方が影響が大きいので、緩くしない）
- **★書き込みは「改造コードテキスト」で提示するのが基本。** PulseHexPy は改造コードを
  適用できるので、直接 write_value を実行するより、**ユーザーが GUI で自由に ON/OFF
  できる改造コード**を出す方が良い（戻すのがトグル 1 回で済む）。
  書式: `ADDR VALUE`（16進。**VALUE の桁数が書き込み幅** = 05:1byte / EB01:2byte /
  0803A0A9:4byte）、`!ADDR VALUE` は write-once（乱数の種やトグルフラグ向け）、
  `BASE("key")+OFFSET VALUE`、`IF(...)/ELSE/ENDIF`、`WHILE(N)/ENDWHILE/BREAK`、
  コメントは `#` / `//`。エンディアンは PulseHexPy が処理するので命令ワードはそのまま書く。
  **命令パッチは必ずコメントで「元の命令 → 新しい命令」を書く**。例:
  `0C05C926 EB01     # mov.w 0x258,r11 (9B28) → mov #1,r11 (EB01)`
  提示時は「タイトル（何が起きるか）/ 目的 / 対象アドレスと基準 / 元の値」を添える。
- write_value / freeze_value の直接実行は**その場限りの確認**に留め、恒久化するなら
  改造コードにする。

【成果物と反映（守ること）】
- 解析は notes/*.md に、確定/不明を分けて書く。
- Ghidra への変更は proposals/ に JSON で出す。反映（apply_*）と再 export は
  **人間が Ghidra GUI で**行う。AI が .gpr/.rep を直接触ることはない。
  - proposals/proposed_comments.json … [AI] コメント
  - proposals/proposed_functions.json … 関数化 / 誤関数化の解除
  - 出したら tools/validate_*.py で検証してから人間に渡す。
- **未解析領域に当たったら apply_functions.py を積極的に使う。** 遠慮しなくてよい。
  典型例:
  - `Could not recover jumptable` で飛び先が未定義のまま残っている
  - 逆アセンブル済みなのにどの関数 body にも属さず decompile 対象外になっている
  - 間接呼び出し（関数ポインタ表）の先が関数化されていない
  これらは**手で逆アセンブルするより、関数化して Ghidra に読ませる方が速くて正確**。
  apply_functions.py は検証を通ったものだけ defined_functions.json に記録し、
  巻き戻しは revert_operations.py がある。Ghidra 側の保存は人間が最後に判断する。
  → 関数化してもらったら decompile_targets に足し、**人間に再 export を依頼して**
    から疑似 C で読む（再 export も Ghidra GUI の操作なので AI は実行しない）。
- ★関数化の落とし穴: **エントリを 1 命令ずらすと「参照が無い＝孤立関数」に見える。**
  提案前に prologue（例: SH-2 なら `mov.l Rn,@-R15` / `sts.l PR,@-R15`、
  MIPS なら `addiu sp,sp,-N`）が候補アドレスから始まっているか確認する。
  epilogue（復帰しているレジスタ）と対応が取れているかで検算できる。
  「どこからも呼ばれない」と結論する前に、必ず 1〜2 命令手前も確認すること。
- 誤関数化（BSS/データ域に関数ができている等）を見つけたら
  proposed_functions.json に `undefine_function` / `clear_code` で出す。
- **リネーム・型変更・配列化・構造体適用は提案もしない**（コメントと関数化/解除まで）。
  bridge_config.json の allowed_apply_operations がそのゲームでの許可範囲。

- **Ghidra の操作を頼むときは「手順」を出して止まる。** 自分で実行しようとしない
  （Ghidra は AI から起動しない、が上の【やらないこと】の通り）。

【正確さの作法】
- アドレス基準（Ghidra addr / 実行時 RAM / dump offset / ファイル内 offset）を混同しない。
  比較する前に notes/address_map.md を確認。不明なら「未確認」と明記して進む。
- 名前や引数個数からの一括推測は「暫定」と明記。可能なら sim 実行やダンプ実測で裏を取ってから確定。
- 矛盾（simと実ダンプが食い違う等）に気づいたら仮説を積み増さず、最小の追加確認を1つずつ。
- 記号的な混乱（意味不明な文字列が紛れる等）が起きたら、その場で止めて報告する。無理に自動実行しない。

【進め方】
- 大きめの作業は 1 回あたり手頃な粒度に分け、都度立ち止まって結果を報告する。
- 行き詰まったら、追加のメモリダンプ / 実機デバッグ / 別画面のダンプを遠慮なく依頼する。
```

---

## 3. メモ
- 家系プロジェクトは《FAMILY_SHARED》を必ず先頭で読ませる。単発ゲームなら
  その行は消す。
- 「今回やること」を空にすると探索が発散する。1 セッション 1 テーマに絞ると精度が出る。
- セッション終盤で確定した知見は notes/ に必ず落とし、必要なら proposals/ にも反映しておくと
  次セッションの立ち上がりが速い。
