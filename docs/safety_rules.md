# Safety Rules — 安全方針

この道具箱は、Ghidra プロジェクト本体を壊さないことを最優先にします。

## やってよいこと

- Ghidra から JSON へ export する。
- Claude Code / Codex が JSON を読む。
- Markdown で解析メモを作る。
- `[AI]` コメント案などの提案 JSON を作る。
- 人間が確認した提案だけを、人間が Ghidra GUI で反映する。

## 常に禁止（opt-in でも解禁しない）

- Ghidra プロジェクト本体を Claude Code / Codex に直接編集させる。
- 既存の人間コメントを削除する。
- **関数名を自動変更する（リネーム）。** `apply_labels.py` は関数エントリへのラベルを
  `force` でも拒否する（ラベル経由の実質リネームも塞ぐ）。
- データ型を自動変更する（文字列データ型の適用を含む）。
- 配列化や構造体適用を自動実行する。
- Ghidra プロジェクトを特定バージョンに強制移行する。

## apply スクリプトの許可条件

| スクリプト | 何を変えるか | 必要な `allowed_apply_operations` |
|---|---|---|
| `apply_comments.py` | `[AI]` コメント | 不要（既定で許可） |
| `apply_functions.py` | 未定義コードの関数化 | `"functions"` |
| `apply_undefine.py` | 誤関数化のクリア（未定義化） | `"undefine"` |
| `apply_labels.py` | データテーブル等の命名（ラベル付け） | `"labels"` |
| `apply_snes_context.py` | 65816 の DP / DBR の値 | `"context"` |
| `revert_operations.py` | 台帳の記録を巻き戻す | 不要 |

- `allowed_apply_operations` は、入力 JSON の近傍（同じフォルダ〜2 つ上）にある
  `bridge_config.json` から読みます。見つからない・JSON として読めない・配列でない・
  必要な操作名が無い場合は、**何も変更せずに終了**します。
- 判定はトランザクション開始・モード変更・逆アセンブル・関数の作成/削除・
  Listing のクリア・台帳の書き込みより前に行います。手動で実行したことや、
  JSON を選んだことは許可の代わりにしません。
- どのスクリプトも **Program を保存しません**（人間が確認して Ctrl+S）。
- 関数化・未定義化・ラベル・DP/DBR は共有台帳 `defined_functions.json` に記録し、
  `revert_operations.py` で巻き戻せます。

## 対象 Program の照合

変更を行うすべてのスクリプトは、提案 JSON・台帳の `target_program` を
**いま開いている Program の名前**と照合し、次の場合は**変更前に中止**します。

- `target_program` が無い / 空 / 文字列でない / 一致しない（大文字小文字も区別）
- 共有台帳が読めない / 形が不正（上書きすると記録を失うので中止）
- 共有台帳に記録があるのに `target_program` が無い / 別の Program 用

確認ダイアログや `force` で回避する手段はありません。
**これは「同じ名前か」の確認でしかなく、同名の別 Program までは区別できません。**

古い提案・台帳が拒否されたとき:

1. Ghidra で開いている Program の名前を確かめる（`ghidra_exports/program.json` の
   `program_name` と同じ）。
2. 提案 JSON は MCP の `as_proposal` 等で作り直すのが確実です。手で直すなら、
   その提案がこの Program 向けかを確かめてから、最上位に
   `"target_program": "<Program 名>"` を書き足します。
3. 古い台帳も、それを作った Program を確かめてから同じ 1 行を書き足します。
   分からないときは書き足さないでください（別 Program に巻き戻しを当てると壊れます）。
4. `tools/validate_proposed_*.py` は `target_program` の欠落をエラーにします。

## 各 apply の個別ルール

**apply_comments.py**

- `[AI]` で始まるコメントだけを反映する。既存の人間コメントは消さず、追記かスキップ。
- 同じ `[AI]` コメントは重複させない。不明なコメント種別・無効なアドレスはスキップ。
- `address_basis` が `ghidra` または未指定のものだけ反映する（`runtime` / `dump_offset`
  は Ghidra の番地ではない可能性があるのでスキップ）。

**apply_labels.py**（ラベル付けは実質リネームなので縛りが強い）

- 既存の名前は上書きしない（`USER_DEFINED` / `IMPORTED` / `ANALYSIS` は SKIP）。
  `force: true` のときだけ上書きし、元の名前を台帳に記録する。自動生成名
  （`LAB_` / `DAT_` 等）は `force` 無しで上書きできる。
- 関数エントリには付けない（`force` でも拒否）。
- 名前に使えるのは英数字・`_`・ひらがな・カタカナ・漢字・長音符・中黒（128 文字以内）。
  空白・記号・全角英数は不可。`FUN_` / `LAB_` / `DAT_` / `switchD_` などの接頭辞は拒否。
  文字の規則は `apply_labels.py` / `tools/validate_proposed_labels.py` /
  `schemas/proposed_labels.schema.json` / MCP の `_label_from_text` の 4 か所で同一。
- 巻き戻し時、現在の名前が記録時と違えば SKIP（人間が直したとみなす）。

**apply_snes_context.py**

- 設定するのは ghidra-snes の `DP`（16bit）/ `DBR`（8bit）だけ。`ctx_MF` / `ctx_XF` /
  `ctx_EF`（命令長を変える）・`PBR`・`B` は拒否。
- 根拠（`evidence`）必須、`confidence=low` は反映しない、65816 以外の Program では何もしない。
- 設定前の明示値を台帳に記録し、`revert_operations.py` で戻せる。

## export_context.py

- export 専用で、Program を書き換えない。取れない情報は `null` / `unknown` にしてログに残す。
- メモリイメージ（`export_memory`）は opt-in で既定 false。上限を超えたブロックは
  スキップして理由を残す。既存の `.bin` は自動削除しない。
- 全域 decompile はしない（病的な関数 1 個で Ghidra ごと固まる）。範囲か
  `decompile_targets` で絞る。ハードタイムアウトと未初期化ブロックの除外は外さない。

## 読み取り専用 MCP（mcp/）

### Ghidra とファイルへの書き込み

- **Ghidra / Ghidra プロジェクトには一切触れません。** 書き込み系ツール（コメント反映・
  関数作成・リネーム・型変更）はありません。エミュレータの起動・接続・制御もしません。
- **ファイルへの書き込みはゼロではありません。** 書くのは次だけです。
  - `decompress` / `render_tiles` / `render_tim` の生成物と、`save_export_snapshot`
  - 書き先は `<project_root>/extracted/` の配下だけ（`ghidra_exports/` には書かない）
  - 既定名でも `out_path` でも resolve 後のパスで判定。`extracted/` 自体がリンクなら書かない。
    UNC / デバイスパス、予約デバイス名（`CON` / `NUL` …）、`:`、末尾のドット / 空白は拒否
  - 既存ファイルは上書きしない（排他作成。同名は `_1` / `_2` と連番）
  - 一覧・比較（`list_export_snapshots` / `diff_exports`）はフォルダも作らない

### 読み取り範囲

基本は `<project_root>/ghidra_exports/` の配下です。次だけ例外として読みます（読むだけ）。

- `<project_root>/bridge_config.json`（変換規則・`overlays`・`record_formats` 等）
- `overlays` に書かれたファイル（プロジェクトフォルダの中だけ）
- `<project_root>/runtime_observations/` 直下の `*.json`
- `bridge_config.json` の `cdl_jsonl`（プロジェクト内か `source_roots` の配下だけ）
- `decompress` / `render_tiles` / `render_tim` の `source_path`、および memory 未 export の
  ときの実行ファイル（`program.json` の `executable_path` など）: **許可ルートの配下だけ**
  - 既定の許可ルート: `<project_root>/extracted/` と `<project_root>/dumps/`
  - 追加: `bridge_config.json` の `source_roots` に**人間が**書いたフォルダ
  - MCP の引数や export 情報（`program.json`）から許可範囲を広げる手段はありません
  - 範囲外ではファイルの有無を言いません

### リンク・UNC・相対パス

- 基準ディレクトリ（`ghidra_exports/`・`decompile/`・`memory/`・`runtime_observations/`・
  `extracted/`・`extracted/snapshots/`）と `bridge_config.json` は、resolve した実体が
  プロジェクトフォルダの中にあるときだけ使います。個別ファイルも実体がその配下のときだけ読みます。
  プロジェクト内に収まるリンク / ジャンクションは使えます。
- UNC（`\\server\share`）とデバイスパス（`\\?\` / `\\.\`）は、触る前に文字列で拒否します。
  ネットワーク上の素材はローカルにコピーして許可ルートに置いてください。
- 相対パスはプロジェクトフォルダ基準です。ドライブ相対（`C:foo`）・ルート相対（`\foo`）は拒否します。

### 大きさと処理量の上限（MCP の引数では緩められない）

| 対象 | 上限 |
|---|---|
| `ghidra_exports/*.json` | 512 MiB |
| 設定・観測・スナップショット・`.lines.json`・レジストリ | 32 MiB |
| `decompile/*.c` 1 本 | 16 MiB |
| 全域走査で丸ごと読む memory / オーバーレイ / 実行ファイルのブロック | 256 MiB |
| 実行ファイル全体 / `cdl_jsonl` | 256 MiB |
| `source_path` の 1 回の読み取り | 64 MiB |
| `decompress` の展開後サイズ | 16 MiB |
| 画像（拡大前 / 出力 / 一辺） | 400 万画素 / 1600 万画素 / 16384 |
| `find_compressed_blocks`（走査量 / 試行回数 / 試した展開量の累計） | 8 MiB / 20000 回 / 256 MiB |

- 丸ごと読むものは、読む前に大きさで断ります。上限を超える export は
  `export_xrefs: false` / decompile の範囲を絞る / `export_memory_blocks` などで分けてください。
- `find_compressed_blocks` が上限で止まったときは `complete: false`・`next_start`・
  `unscanned` を返します（「候補なし」ではありません）。
- `source_path` で読んだファイルについては、エラー文に入力のバイト値を入れません。

### この仕組みで防げないもの

- 確認してから開くまでの間にフォルダをリンクへ差し替える競合（読み取り側）。
- ドライブ文字に割り当てたネットワークドライブ（UNC として見分けられない）。
- ハードリンク。

## 実行時観測（runtime_observations/）

エミュレータのデバッガなど（観測の手段は問わない）で観測した結果を、人間か解析セッションが JSON で保存し、
MCP は**読むだけ**です（`list_runtime_observations` / `get_runtime_range_evidence`）。

- 実行時アドレスは `bridge_config.json` の `address_translations` の規則でだけ
  Ghidra 番地に直します。規則が無いものは推測せず `unmapped` として残します。
- **「観測されなかった」は「使われていない」の証明ではありません。** `verdict` に
  `unused` はなく、`not_observed` / `coverage_unknown` には、どのファイル・どの場面
  （`coverage_note`）だけを見たかを添えます。
- 形式: [`schemas/runtime_observations.schema.json`](../schemas/runtime_observations.schema.json)
  / 例: [`samples/runtime_observations.sample.json`](../samples/runtime_observations.sample.json)

## 動的解析ツール（外部 MCP）を併用するとき

道具箱自体は提供しませんが、同じ安全境界で扱います。

| 層 | 例 | 扱い |
|---|---|---|
| 読み取り | メモリ検索 / 読み出し / ポインタ追跡 | 自由に使ってよい |
| 実行への介入 | ブレーク / ウォッチ / ステップ | ゲームが止まるので事前に一言 |
| **書き込み** | 改造コード / メモリ書き換え | **都度、人間の明示許可が必要** |

- 書き込みを提案するときは、目的・対象アドレスとアドレス基準・書く値と元の値を添える。
  直接書き換えるより、人間が ON/OFF できる改造コードの形で示すのを基本にする。
- アドレス基準（Ghidra / 実行時 RAM / dump offset）を混同しない。不明なら
  `notes/address_map.md` に「未確認」と書く。
