"""Decode the XDt/ protection-module logs (obfuscated ASCII wide-char log).

The client's protection module writes one UTF-16LE file per run under XDt/.
The text is mangled with two fixups that are trivially reversible:

  1. only the low byte of every 16-bit word carries data, and it is XORed
     with an alternating key (0xFD on even indices, 0xCD on odd ones);
  2. after the XOR, every adjacent pair of characters is swapped.

The high byte of each word is a fixed marker (0x70 / 0xFE) and is irrelevant.

Usage:
    python tools/decode_xdt.py                     # decode every XDt/*.log
    python tools/decode_xdt.py <file-or-dir> ...    # decode given paths
"""

from __future__ import annotations

import sys
from pathlib import Path

KEY_EVEN = 0xFD
KEY_ODD = 0xCD
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DIR = (
    PROJECT_ROOT
    / "launcher" / "gundam" / "机动战士敢达Online" / "GundamOnline" / "XDt"
)
OUT_DIR = PROJECT_ROOT / "server" / "xdt_decoded"


def decode(raw: bytes) -> str:
    if raw[:2] == b"\xff\xfe":            # UTF-16LE BOM
        raw = raw[2:]
    low = raw[0::2]                       # data lives in the low byte
    xored = bytes(
        b ^ (KEY_EVEN if i % 2 == 0 else KEY_ODD) for i, b in enumerate(low)
    )
    out = bytearray(xored)
    for i in range(0, len(out) - 1, 2):   # swap adjacent characters
        out[i], out[i + 1] = out[i + 1], out[i]
    return out.decode("latin1")


def iter_logs(paths: list[str]) -> list[Path]:
    if not paths:
        return sorted(DEFAULT_DIR.glob("*.log"))
    found: list[Path] = []
    for raw in paths:
        p = Path(raw)
        found.extend(sorted(p.glob("*.log")) if p.is_dir() else [p])
    return found


def main() -> None:
    for log in iter_logs(sys.argv[1:]):
        text = decode(log.read_bytes())
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        target = OUT_DIR / (log.stem + ".txt")
        target.write_text(text, encoding="utf-8")
        print(f"=== {log.name} -> {target} ({len(text)} chars) ===")
        print(text[:1200])
        print()


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    main()
