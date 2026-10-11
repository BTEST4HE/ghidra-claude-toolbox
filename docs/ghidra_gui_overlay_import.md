# Ghidra GUI 備忘録 — EXE / オーバーレイ (Raw Binary) の取り込みと関数化

人間が Ghidra GUI でやる操作の手順書。AI はこの操作をしない (Ghidra を起動しない・.rep に触らない)。
例は PS1 のオーバーレイを取り込んだときの形 (番地は説明用の値)。番地やファイル名は対象に合わせて読み替える。

---

## 0. 先に決めておくこと (AI 側で用意してもらう)

| 項目 | 例 | どこに書いてあるか |
|---|---|---|
| 取り込むファイル | `overlay\MENU_80060000.bin` | ゲームの `notes/` / 素材フォルダの README |
| 言語 (Language) | 対象 CPU の言語 (プロセッサ / エンディアン / ビット幅) | `bridge_config.json` の `_notes` |
| ベースアドレス | `0x80060000` | 同上 (ファイル名に入れておくと間違えない) |
| 入口 (エントリ) の番地 | `80061000` | 同上 |
| export 先フォルダ | `...\ai_workspaces\GAME_B\ov1_menu` | レジストリの `root` (1 Program = 1 フォルダ) |

---

## 1. 取り込み (Import)

### 1-a. 実行ファイル (PS-EXE / ELF など)

1. プロジェクト画面で **File → Import File…** → ファイルを選ぶ。
2. Format は自動で選ばれる (ELF など Ghidra が対応している形式)。そのまま **OK**。
   標準で対応していない形式は、対応する拡張を入れるか、下の 1-b の Raw Binary として取り込む。
3. 開いたら「Analyze?」に **Yes** → 既定のまま **Analyze**。

### 1-b. オーバーレイ / ダンプの切り出し (Raw Binary)

1. **File → Import File…** → `.bin` を選ぶ。
2. **Format: `Raw Binary`** に変える。
3. **Language:** 右の「…」ボタン → 対象 CPU の言語を選ぶ (プロセッサ・エンディアン・
   ビット幅を確かめる)。
4. **Options…** ボタン → **Base Address** に `0x80060000` を入れる → OK。
5. **OK** で取り込み → 「Analyze?」に **Yes** → **Analyze**。
6. ★**ここで終わりにしない。** Raw Binary は先頭がデータのことが多く、自動解析だけでは
   コードがほとんど見つからない → 次の「2. 関数化」を必ずやる。

> 整理: プロジェクト画面で右クリック → New Folder で `overlay` フォルダを作り、
> オーバーレイ Program をまとめておくと取り違えにくい。

---

## 2. 入口からの関数化 (G → D → F)

1 本あたり 1 分程度。

1. **Program を開く:** プロジェクト画面で Program をダブルクリック (CodeBrowser が開く)。
   「Analyze?」と聞かれたら、解析済みなら **No**。
2. **入口へ移動:** キーボード **G** (Navigation → Go To…) → 番地 (`80061000`) を入力 → OK。
3. **逆アセンブル:** その行をクリック → **D** (右クリック → Disassemble)。
   `?? 27h` のようなバイト表示が `addiu sp,sp,-0x…` のような命令に変わる。
   既に命令なら何も起きないが問題ない。
4. **関数にする:** 同じ行で **F** (Function → Create Function)。
   行の上に `undefined FUN_80061000()` のような見出しが付けば成功。
   呼び出し先も自動で辿られ、Symbol Tree の Functions に `FUN_…` が増える (少し待つ)。
5. **保存:** **Ctrl+S** (File → Save)。

---

## 3. export

1. **Window → Script Manager** → `export_context.py` を実行。
2. 出力先には **その Program 専用のフォルダ** を選ぶ (表の export 先)。
   - ★同じフォルダに別の Program を export すると、前の `ghidra_exports/` が**上書きされて消える**。
3. decompile 範囲を聞かれたら、最初は **「上限 20 件だけ」**。全域 decompile はしない
   (病的関数 1 個で Ghidra が固まる)。
4. 終わったら AI に「export した」と伝える → `list_programs` / `get_export_status` で確認してもらう。

---

## 4. AI が作った関数案を反映する (apply_functions.py)

G → D → F では届かない関数 (関数ポインタ表経由で呼ばれるもの) は、AI が
`<export 先>\proposals\proposed_functions.json` に番地の一覧を作る。それを Ghidra に流す。

前提: そのフォルダの `bridge_config.json` の `allowed_apply_operations` に `"functions"` が
入っていること (人間が許可する。入っていないと apply_functions.py は何もせずに終了する)。
一覧の `target_program` が開いている Program の名前と違う場合も、何も変更せずに中止する。

1. 対象の Program を開く (CodeBrowser)。
2. **Window → Script Manager** → 検索欄に `apply_functions` → `apply_functions.py` をダブルクリック。
3. 「Select proposed_functions.json」と聞かれたら、**その Program の export 先フォルダの**
   `proposals\proposed_functions.json` を選ぶ (別の Program の一覧を選ばないこと)。
4. Console に件数が出る (applied / skipped / rejected)。skipped は「既に関数だった」なので問題ない。
   rejected / errors があれば Console の内容を AI に貼る。
5. 自動解析が走り終わるのを待つ (右下のバーが消えるまで)。
6. **Ctrl+S** で保存 → 「3. export」と同じ手順で export。

> 一覧に入口も含めてもらえば、取り込み直後でも 2. の G → D → F を省略できる
> (apply_functions.py が必要なら先に逆アセンブルする)。
> 元に戻したいときは `revert_operations.py` に、同じフォルダの `defined_functions.json` (台帳) を渡す。

---

## 5. 取り込み直し (間違ったファイルで取り込んでしまったとき)

ファイルを作り直した場合、Ghidra 内の Program は**古い中身のまま** (取り込み時にコピーされる)。

1. CodeBrowser を閉じる。
2. プロジェクト画面で古い Program を右クリック → **Delete** (確認に OK)。
   - 自分で付けたコメントやラベルがあるなら消える。残したいものがあれば先に AI に伝える。
3. 「1-b. Raw Binary」から取り込み直す (言語・ベースアドレスをもう一度指定)。
4. 「4. 関数案の反映」→ 保存 → export。

---

## うまくいかないとき

| 症状 | 原因と対処 |
|---|---|
| G で「番地が見つからない」 | 開いている Program が違う (タイトルのファイル名を確認) / ベースアドレスの入れ間違い |
| F でエラー | 先に D (逆アセンブル) をしていない。D → F の順で |
| 関数数が妙に少ない / どのオーバーレイも同じ数 | Raw Binary の自動解析だけで止まっている。入口で G → D → F |
| 入口は関数になったのに中身が少ない | 残りが関数ポインタ表経由で呼ばれている (Ghidra は辿れない)。AI に `find_undefined_targets` で洗い出してもらい、`proposed_functions.json` → **`apply_functions.py`** で関数化 (`bridge_config.json` の `allowed_apply_operations` に `"functions"` が要る = 人間が判断) |
| 疑似 C の gp 相対の参照先がおかしい | PS-EXE ヘッダの gp0 が不正値のことがある。範囲を選択 → 右クリック → **Set Register Values** → `gp` に AI が crt0 から読んだ値を入れる |
| export 後も `exports_found=false` | 出力先フォルダの選び間違い (レジストリの `root` と一致しているか) |
| 命令に `addi $zero,$at,0x2020` のような意味の無いものが混ざる | 展開 (解凍) のやり方が違っている。AI に展開をやり直してもらい「5. 取り込み直し」 |
