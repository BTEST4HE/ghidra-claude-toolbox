# -*- coding: utf-8 -*-
"""プロローグ / エピローグから関数入口を推定する共通ロジック (Python 3.13 前提)。

`find_function_entry` の骨格をアーキ間で共有します。アーキ側は「どれが push か」
「どれが関数の終わりか」といった**判定だけ**を渡します。

判定の考え方 (SH-4 実装で確立したもの):

1. 指定アドレスから後方へ、**関数末尾の直後**と**プロローグの先頭**を候補に集める
2. 近い候補から順に前方走査し、**その関数の範囲が指定アドレスを含み**、かつ
   **積んだ数と戻した数が一致する**ものを採用する
3. どれも満たさなければ最も近い候補を返し、`balanced: false` と理由を明示する

★「積む数 = 戻す数」が誤った入口を弾く条件です。数バイトずれた番地から関数を
  呼ぶとスタックが壊れ、復帰先がゴミへ飛びます。
"""


def _hex(value):
    """32bit アドレスを '0x........' 表記にします。"""
    return "0x{0:08x}".format(value & 0xFFFFFFFF)


class PrologueSpec(object):
    """アーキ固有の判定をまとめたものです。"""

    def __init__(self, size, read, is_push, is_pop, is_end, count_regs,
                 text, is_entry_push=None, find_refs=None, delay_slots=0):
        """各判定を受け取ります。

        size        : 命令長 (バイト)
        read(i)     : index i の命令語を返す
        is_push(w)  : スタックへ積む命令か
        is_pop(w)   : スタックから戻す命令か
        is_end(w)   : 関数の終わりになりうるか
        count_regs(w): その命令が触るレジスタ本数
        text(w, addr): 逆アセンブル文字列
        is_entry_push(w): 入口らしい push か (既定は is_push と同じ)
        find_refs(entry): その入口を指す呼び出し / 関数ポインタを返す
        delay_slots : 復帰命令の後ろに何命令ぶん遅延スロットがあるか (MIPS は 1)

        ★遅延スロットを数えないと収支が合いません。MIPS のエピローグは
          `jr $ra` / `addiu $sp,$sp,N` の順が定型で、SH-4 の `rts` と同じく
          **復帰命令の後ろの 1 命令は必ず実行されます**。ここを飛ばすと
          正しい入口が「不均衡」に見えます。
        """
        self.size = size
        self.read = read
        self.is_push = is_push
        self.is_pop = is_pop
        self.is_end = is_end
        self.count_regs = count_regs
        self.text = text
        self.is_entry_push = is_entry_push or is_push
        self.find_refs = find_refs
        self.delay_slots = int(delay_slots or 0)


def prologue_start(spec, count, index, max_gap=2, min_pushes=1):
    """index を含むプロローグの先頭 index を返します (プロローグでなければ None)。

    プロローグは push だけが並ぶとは限らない (引数の設定が混じる) ので、
    max_gap 命令までの非 push を挟んでも同じプロローグとみなします。
    pop や関数末尾に当たったら**前の関数**なので必ず止めます。
    """
    if not spec.is_push(spec.read(index)):
        return None
    first = index
    pushes = 1
    gap = 0
    j = index - 1
    while j >= 0:
        w = spec.read(j)
        if spec.is_push(w):
            first = j
            pushes += 1
            gap = 0
            j -= 1
            continue
        if spec.is_pop(w) or spec.is_end(w):
            break
        gap += 1
        if gap > max_gap:
            break
        j -= 1
    return first if pushes >= min_pushes else None


def analyze(spec, count, entry_index, max_forward):
    """入口候補から前方へ走査し、積んだ数 / 戻した数 / 末尾を数えます。"""
    pushed = 0
    popped = 0
    prologue = []
    epilogue = []
    end_index = None
    in_prologue = True

    for j in range(entry_index, min(count, entry_index + max_forward)):
        w = spec.read(j)
        if spec.is_push(w):
            pushed += spec.count_regs(w)
            if in_prologue:
                prologue.append(j)
            continue
        if spec.is_pop(w):
            popped += spec.count_regs(w)
            epilogue.append(j)
            in_prologue = False
            if spec.is_end(w):
                end_index = j
                for k in range(j + 1, min(count, j + 1 + spec.delay_slots)):
                    wd = spec.read(k)
                    if spec.is_pop(wd):
                        popped += spec.count_regs(wd)
                        epilogue.append(k)
                    elif spec.is_push(wd):
                        pushed += spec.count_regs(wd)
                break
            continue
        in_prologue = False
        if spec.is_end(w):
            end_index = j
            # 遅延スロットぶんも数える (実行されるため)。
            for k in range(j + 1, min(count, j + 1 + spec.delay_slots)):
                wd = spec.read(k)
                if spec.is_pop(wd):
                    popped += spec.count_regs(wd)
                    epilogue.append(k)
                elif spec.is_push(wd):
                    pushed += spec.count_regs(wd)
            break
    return {
        "pushed": pushed,
        "popped": popped,
        "prologue": prologue,
        "epilogue": epilogue,
        "end_index": end_index,
    }


def find_entry(spec, count, base_addr, address, max_back=4096,
               max_forward=8192, max_candidates=12):
    """指定アドレスを含む関数の入口を命令列から判定して dict で返します。"""
    off = address - base_addr
    if off < 0 or off % spec.size or off // spec.size >= count:
        raise ValueError(
            "アドレス {0} が memory イメージの範囲外か、{1} バイト境界に"
            "揃っていません。".format(_hex(address), spec.size))
    start_index = off // spec.size

    # --- 候補を後方から集める (関数末尾の直後 / プロローグの先頭) ---
    found = {}
    for j in range(start_index, max(-1, start_index - max_back), -1):
        w = spec.read(j)
        if j < start_index and spec.is_end(w):
            cand = j + 1 + spec.delay_slots
            if cand <= start_index:
                found.setdefault(cand, "関数末尾の直後")
        if spec.is_entry_push(w):
            cand = prologue_start(spec, count, j)
            if cand is not None and cand <= start_index:
                found.setdefault(cand, "プロローグ (push) の先頭")
        if len(found) >= max_candidates:
            break
    candidates = sorted(found, reverse=True)
    if not candidates:
        return {
            "address": _hex(address),
            "entry": None,
            "is_entry": False,
            "balanced": None,
            "confidence": "low",
            "note": "後方 {0} 命令に関数末尾もプロローグも見つかりません。"
                    "コードではない可能性があります。".format(max_back),
        }

    # --- 近い候補から「address を含み、かつ収支が合う」ものを探す ---
    chosen = None
    info = None
    examined = 0
    for cand in candidates:
        examined += 1
        data = analyze(spec, count, cand, max_forward)
        end = data["end_index"]
        covers = (end is not None
                  and cand <= start_index <= end + spec.delay_slots)
        if covers and data["pushed"] == data["popped"]:
            chosen, info = cand, data
            break
    if chosen is None:
        chosen = candidates[0]
        info = analyze(spec, count, chosen, max_forward)

    entry_addr = base_addr + chosen * spec.size
    end_index = info["end_index"]
    # 関数の終わりは「復帰命令 + 遅延スロット」まで。指定アドレスが遅延スロットに
    # あるときも「その関数の中」なので、covers 判定もここまで含める。
    last_index = (end_index + spec.delay_slots) if end_index is not None else None
    end_addr = base_addr + last_index * spec.size if last_index is not None else None
    balanced = info["pushed"] == info["popped"]
    covers = last_index is not None and chosen <= start_index <= last_index

    notes = []
    if not balanced:
        notes.append("★積んだ {0} 本 / 戻した {1} 本が一致しません。"
                     "ここは関数入口ではない可能性が高いです "
                     "(この番地から呼ぶとスタックが壊れます)。".format(
                         info["pushed"], info["popped"]))
    if end_index is None:
        notes.append("前方 {0} 命令内に関数の終わりが見つかりませんでした。".format(
            max_forward))
    elif not covers:
        notes.append("★この関数の範囲 ({0}〜{1}) は指定アドレスを含みません。".format(
            _hex(entry_addr), _hex(end_addr)))

    refs = spec.find_refs(entry_addr) if spec.find_refs else None
    if refs is not None and not refs.get("total"):
        notes.append("この入口を指す呼び出しも関数ポインタも見つかりません "
                     "(間接呼び出しか、範囲外から呼ばれている可能性)。")

    if balanced and covers and refs and refs.get("total"):
        confidence = "high"
    elif balanced and covers:
        confidence = "medium"
    else:
        confidence = "low"

    return {
        "address": _hex(address),
        "entry": _hex(entry_addr),
        "is_entry": entry_addr == address,
        "offset_from_entry": address - entry_addr,
        "end": _hex(end_addr) if end_addr is not None else None,
        "covers_address": covers,
        "how": found.get(chosen),
        "prologue": [{"addr": _hex(base_addr + i * spec.size),
                      "text": spec.text(spec.read(i), base_addr + i * spec.size)}
                     for i in info["prologue"]],
        "epilogue": [{"addr": _hex(base_addr + i * spec.size),
                      "text": spec.text(spec.read(i), base_addr + i * spec.size)}
                     for i in info["epilogue"]],
        "pushed_regs": info["pushed"],
        "popped_regs": info["popped"],
        "balanced": balanced,
        "referenced_by": refs,
        "candidates_examined": examined,
        "confidence": confidence,
        "note": " ".join(notes) if notes else
                "積んだ数と戻した数が一致し、関数の終わりまで到達し、"
                "指定アドレスを範囲に含みます。入口として矛盾はありません。",
    }
