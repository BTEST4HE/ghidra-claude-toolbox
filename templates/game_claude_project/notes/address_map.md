# Address Map

このファイルは、Ghidra 上のアドレス・実行時メモリアドレス・メモリダンプ内
オフセットの関係を整理するためのものです。アドレスを比較・変換する前に
必ずここを確認してください。不明な点は「Caution」に未確認事項として残します。

## Source model

- source_model: executable
- Ghidra source: main ELF
- Runtime dump: PCSX2 EE RAM dump

（`bridge_config.json` の `source_model` と一致させること。
 実行ファイルが無い場合は memory_dump / raw_binary などになる。）

## Current assumption

Ghidra アドレスと実行時 EE RAM アドレスは同一基準として扱う。
（この仮定が崩れる可能性がある場合は Caution に記載すること。）

## Conversion

- runtime_address = ghidra_address
- dump_offset = runtime_address - dump_base

（dump_base は dump ファイルの先頭が表すアドレス。未確認なら Caution へ。）

## Known addresses

- Player HP candidate: 0x0034ABCD
- Damage write candidate: 0x001234A0

## Caution

- overlay は未確認
- IOP module は未解析
- 動的展開コードの有無は未確認
- dump_base が未確定（要確認）
