# runtime_observations/ — 実行時に観測したことを置く場所

外部エミュレータのデバッガ MCP（Mesen / DuckStation / PCSX2 など）で観測した結果を、
**共通の JSON** にしてここへ保存します。保存すると、読み取り専用 MCP の
`list_runtime_observations` / `get_runtime_range_evidence` が
**Ghidra と同じアドレス基準で**引けるようになります。

- 形式: `schemas/runtime_observations.schema.json`（道具箱側）
- 最小例: `samples/runtime_observations.sample.json`（道具箱側）

## 大事なこと

- **Ghidra Toolbox はエミュレータを起動も接続も制御もしません。**
  実行・ブレーク・ウォッチ・書き込みは、エミュレータ側の MCP の仕事です。
  ここに保存するのは**人間か解析セッション**で、Toolbox は**読むだけ**です。
- **「観測されなかった」は「使われていない」の証明ではありません。**
  どの場面をどこまで実行したかで結果は変わります。必ず `coverage_note` に
  「何をどこまでやったか」を書いてください。
- 実行時アドレスは、`bridge_config.json` の `address_translations` に規則を書き、
  `address_context.translation` に規則名を入れると Ghidra 番地へ直せます。
  **規則が無いものは推測変換せず `unmapped` として残ります。**

## 置き方

1 ファイル = 1 回の観測（1 つの場面）にしておくと、後から
「どの場面の話か」を取り違えません。ファイル名は自由です。

```
runtime_observations/
  stage1_start.json
  pause_menu.json
  ending.json
```
