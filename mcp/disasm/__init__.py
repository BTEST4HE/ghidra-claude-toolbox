# -*- coding: utf-8 -*-
"""アーキ別逆アセンブラの登録所 (Python 3.13 前提)。

読み取り専用 MCP の `get_disassembly` / `find_address_refs` が使います。
新しいアーキを足すときは、このディレクトリに `<arch>.py` を作って
NAME / DISPLAY / INSTRUCTION_SIZE / decode() / word_at() / build_ref_index()
を実装し、下の _ARCHS に登録するだけです。

現状の対応: MIPS (R3000 / R5900)、SH-4 / SH-2 (SuperH)、ARMv4T (ARM / Thumb)、
PowerPC (Gekko / Broadway = GameCube / Wii)、WDC 65C816 (SNES / SFC)。

★65816 (`w65816.py`) だけは**可変長**で、命令長が M/X フラグで変わります。
  固定長前提の decode(word) / word_at では正しく読めないので、モジュールに
  `VARIABLE_LENGTH = True` を立て、MCP 側は `disassemble()` / `iter_code()` の
  専用経路を使います。M/X は bridge_config.json の `cdl_jsonl` (Mesen CDL) から取り、
  無ければ REP/SEP 追跡 (width_source=assumed から) です。
  分岐を辿る解析 (find_calls_to / find_path / list_memory_args / lint_stale_register /
  find_function_entry / expand_switch) は `w65816_flow.py` にあり、`make_analyzer()`
  で作る解析器に全ブロック (`_image.BusImage`) を渡します。他アーキでも
  `make_analyzer` と同名のフックを持たせれば MCP 本体を変えずに使えます。

★PowerPC は**ビッグエンディアン**です。memory_map.json の endian が little に
  なっていると全命令がゴミになるので、結果が支離滅裂なときはそこを疑ってください。

★ARM は「ARM モード (32bit)」と「Thumb モード (16bit)」で命令長も符号化も違うため、
  **別モジュールとして登録**しています (arm / thumb)。同じ Program の中で両モードが
  混在し、アドレスだけからは判別できないので自動判定はしません。GBA のように
  Thumb 主体のコードを読むときは `arch="thumb"` を明示するか、
  bridge_config.json に `"disasm_arch": "thumb"` を書いて既定を切り替えてください
  (export_context.py が memory_map.json へ書き出し、resolve_arch が最優先で読みます)。
"""

from . import arm
from . import mips
from . import ppc
from . import sh4
from . import thumb
from . import w65816


# arch 名 -> モジュール。新アーキはここに足す。
_ARCHS = {
    arm.NAME: arm,
    mips.NAME: mips,
    ppc.NAME: ppc,
    sh4.NAME: sh4,
    thumb.NAME: thumb,
    w65816.NAME: w65816,
}

# Ghidra の processor 名 / language_id / platform_profile 名 -> arch 名。
# 小文字で比較します。未対応アーキは載せない (載せないことが「未対応」の宣言)。
_ALIASES = {
    "mips": "mips",
    "mips32": "mips",
    "mips64": "mips",
    "r3000": "mips",
    "r5900": "mips",
    "psx": "mips",
    "ps1": "mips",
    "ps2": "mips",
    "n64": "mips",
    # SuperH。Ghidra の language_id は "SuperH4:LE:32:default" なので
    # 先頭トークン "superh4" でも引けるようにする。
    "sh4": "sh4",
    "sh-4": "sh4",
    "superh4": "sh4",
    "superh": "sh4",
    "sh2": "sh4",
    "sh-2": "sh4",
    "superh2": "sh4",
    "dreamcast": "sh4",
    "saturn": "sh4",
    # ARMv4T。Ghidra の language_id は "ARM:LE:32:v4t" なので先頭トークン
    # "arm" で ARM モードに落ちる。Thumb は明示指定 (または disasm_arch) が要る。
    "arm": "arm",
    "arm7": "arm",
    "arm7tdmi": "arm",
    "armv4t": "arm",
    "arm32": "arm",
    "thumb": "thumb",
    "armthumb": "thumb",
    "arm/thumb": "thumb",
    "v4t": "thumb",
    # platform_profile 名。GBA/NDS は実コードのほぼ全てが Thumb なので thumb を既定にする
    # (processor="ARM" の方が優先順位は上なので、実際に効くのは
    #  language_id/processor が無い export のときだけ)。
    "gba": "thumb",
    "nds": "thumb",
    # PowerPC (GameCube / Wii)。Ghidra の language_id は
    # "PowerPC:BE:32:Gekko_Broadway" なので先頭トークン "powerpc" で引ける。
    "ppc": "ppc",
    "powerpc": "ppc",
    "ppc32": "ppc",
    "gekko": "ppc",
    "broadway": "ppc",
    "gekko_broadway": "ppc",
    "gamecube": "ppc",
    "wii": "ppc",
    "gc": "ppc",
    # WDC 65C816 (SNES / SFC)。Ghidra の language_id は "65816:LE:24:snes"
    # なので先頭トークン "65816" で引ける。
    "65816": "65816",
    "w65816": "65816",
    "wdc65816": "65816",
    "65c816": "65816",
    "wdc65c816": "65816",
    "5a22": "65816",
    "snes": "65816",
    "sfc": "65816",
}

# 「未対応」と分かっていて、そう返すべきもの (メッセージを分かりやすくするため)。
_KNOWN_UNSUPPORTED = {
    "aarch64": "AArch64",
    "x86": "x86", "68000": "M68000", "z80": "Z80", "sparc": "SPARC",
}


def supported_archs():
    """対応済み arch 名の一覧を返します。"""
    return sorted(_ARCHS.keys())


def get_arch(name):
    """arch 名からモジュールを返します。未対応なら分かりやすい ValueError。"""
    key = (name or "").strip().lower()
    module = _ARCHS.get(_ALIASES.get(key, key))
    if module is not None:
        return module
    raise ValueError(_unsupported_message(name))


def _unsupported_message(name):
    """未対応アーキ用のエラーメッセージを組み立てます。"""
    pretty = _KNOWN_UNSUPPORTED.get((name or "").strip().lower())
    head = "アーキ '{0}' の逆アセンブルは未対応です。".format(name)
    if pretty:
        head = "{0} の逆アセンブルは未対応です。".format(pretty)
    return (head +
            "現在対応しているのは {0} だけです ".format(", ".join(supported_archs())) +
            "(MIPS R3000 / R5900、SuperH SH-4 / SH-2、ARMv4T の ARM / Thumb、"
            "PowerPC Gekko / Broadway、WDC 65C816 = SNES/SFC)。"
            "他アーキは mcp/disasm/ にモジュールを追加すれば "
            "足せます。当面は Ghidra GUI の Listing を直接読んでください。")


def resolve_arch(memory_map, override=None):
    """memory_map.json の内容 (と任意の override) から arch モジュールを決めます。

    優先順位: override > memory_map の disasm_arch > processor > language_id の
    先頭トークン > platform_profile。どれも該当しなければ ValueError。
    """
    if override:
        return get_arch(override)

    candidates = []
    if isinstance(memory_map, dict):
        for key in ("disasm_arch", "processor", "platform_profile"):
            value = memory_map.get(key)
            if value:
                candidates.append(str(value))
        language_id = memory_map.get("language_id")
        if language_id:
            candidates.append(str(language_id).split(":")[0])

    for value in candidates:
        key = value.strip().lower()
        target = _ALIASES.get(key, key)
        if target in _ARCHS:
            return _ARCHS[target]

    if candidates:
        raise ValueError(_unsupported_message(candidates[0]))
    raise ValueError(
        "memory_map.json にアーキ情報 (processor / language_id) がありません。"
        "arch を明示指定するか、export_context.py を新しい版で再実行してください。")
