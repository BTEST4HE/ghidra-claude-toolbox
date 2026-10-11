# Workflow — 解析ワークフロー

コマンド例は Windows CMD 前提です。export と apply は、どちらも人間が Ghidra GUI で実行します。

## 全体像

```
[Ghidra GUI]  --export_context.py-->  ghidra_exports/*.json + decompile/*.c
                                  |
                                  v
                [Claude Code / Codex]  読む (ファイル直読み / 読み取り専用 MCP)
                                  |    → notes/*.md に解析メモ
                                  v
                proposals/*.json  (コメント案 / 関数化案 / ラベル案 …)
                                  |
                                  v
                tools\validate_proposed_*.py  (人間が検証)
                                  |
                                  v
[Ghidra GUI]  --apply_*.py-->  人間が確認した提案だけを反映
```

## 手順

### 1. ゲーム用プロジェクトを作る

```
python tools\make_game_project.py C:\RE\games\my_game\claude_project
```

作成後、`bridge_config.json` の `game_name` / `platform` / `source_model` /
`ghidra_version` / `ghidra_path` / `allowed_apply_operations` などを編集します。

### 2. Ghidra で export する

1. Ghidra GUI で対象 Program を開く。
2. Script Manager から `export_context.py` を実行し、出力先に `claude_project` を選ぶ。
3. `claude_project\ghidra_exports\` に JSON 群が出力される。

### 3. Claude Code / Codex で解析する

1. `claude_project` を開き、`CLAUDE.md` のルールに従う。
2. `ghidra_exports/` + `dumps/` + `notes/address_map.md` を突き合わせて解析し、
   `notes/` に確定情報と不明点を分けて書く。
3. 提案を `proposals/` に出す。どの提案 JSON にも `target_program`（対象の Program 名）を書く。

### 4. 提案を検証する

```
python tools\validate_proposed_comments.py proposals\proposed_comments.json
```

NG が出たら直します。OK になるまで反映しません。

### 5. Ghidra で反映する

1. 同じ Program を開いた状態で、Script Manager から `apply_*.py` を実行し、提案 JSON を選ぶ。
2. 反映できる範囲と許可条件は [safety_rules.md](safety_rules.md) のとおり
   （コメント以外は `allowed_apply_operations` での許可が必要。`target_program` が
   一致しないと何も変更せずに中止）。
3. 保存はされないので、確認してから Ctrl+S。関数化したら export を再実行すると
   新しい関数が decompile されます。

## 応用: 実行時の観測を証拠として足す

1. 静的に「怪しい範囲」を決める（`find_address_refs` / `find_pointers_to` / `classify_range` 等）。
2. 外部エミュレータのデバッガ MCP で、その範囲だけを観測する
   （道具箱はエミュレータを起動も接続も制御もしません）。
3. 観測結果を `runtime_observations/` に 1 ファイル = 1 場面で保存する。
   `capture.scenario` と `capture.coverage_note`（何をどこまで実行したか）を必ず書く。
   実行時アドレスなら `address_context.translation` に `bridge_config.json` の規則名を入れる。
4. MCP の `get_runtime_range_evidence(start=..., length=...)` で照会する。

**「観測されなかった」は「使われていない」の証明ではありません**（`verdict` に `unused` は
ありません）。形式は `schemas/runtime_observations.schema.json`。
