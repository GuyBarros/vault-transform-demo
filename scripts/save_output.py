import os
import re
import subprocess
import sys
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

DEMO = Path(__file__).resolve().parent / "demo_retrofit.py"
OUT  = Path(__file__).resolve().parents[1] / "vault-adp.png"

# ── ANSI colour tables ────────────────────────────────────────────────────────

_STD = [
    (0,0,0),(205,49,49),(13,188,121),(229,229,16),
    (36,114,200),(188,63,188),(17,168,205),(229,229,229),
]
_BRIGHT = [
    (102,102,102),(241,76,76),(35,209,139),(245,245,67),
    (59,142,234),(214,112,214),(41,184,219),(255,255,255),
]

def _ansi256(n):
    if n < 8:   return _STD[n]
    if n < 16:  return _BRIGHT[n - 8]
    if n < 232:
        n -= 16; b = n % 6; n //= 6; g = n % 6; r = n // 6
        return (r*51, g*51, b*51)
    v = (n - 232) * 10 + 8
    return (v, v, v)

# ── ANSI parser ───────────────────────────────────────────────────────────────

_TOKEN = re.compile(r'\x1b\[([0-9;]*)m|\x1b\[[^m]*[A-Za-z]|([^\x1b\n]+)|\n')
_DEFAULT_FG = (212, 212, 212)

def parse_ansi(raw):
    """
    Parse ANSI-escaped text into lines.
    Returns: list of lines, each line = list of (text, fg_rgb, bold) segments.
    """
    fg, bold    = _DEFAULT_FG, False
    lines       = [[]]
    pending_txt = ""
    pending_fg  = fg
    pending_bold = bold

    def flush():
        nonlocal pending_txt
        if pending_txt:
            lines[-1].append((pending_txt, pending_fg, pending_bold))
            pending_txt = ""

    for m in _TOKEN.finditer(raw):
        esc, plain = m.group(1), m.group(2)

        if plain is not None:
            nonlocal_same = (pending_fg == fg and pending_bold == bold)
            if nonlocal_same:
                pending_txt += plain
            else:
                flush()
                pending_txt, pending_fg, pending_bold = plain, fg, bold

        elif m.group(0) == '\n':
            flush()
            lines.append([])
            pending_fg, pending_bold = fg, bold

        elif esc is not None:
            flush()
            params = [int(x) if x else 0 for x in esc.split(';')] if esc else [0]
            i = 0
            while i < len(params):
                p = params[i]
                if p == 0:
                    fg, bold = _DEFAULT_FG, False
                elif p == 1:
                    bold = True
                elif p in (2, 22):
                    bold = False
                elif 30 <= p <= 37:
                    fg = _STD[p - 30]
                elif 90 <= p <= 97:
                    fg = _BRIGHT[p - 90]
                elif p == 39:
                    fg = _DEFAULT_FG
                elif p == 38 and i + 1 < len(params):
                    if params[i+1] == 2 and i + 4 < len(params):
                        fg = (params[i+2], params[i+3], params[i+4]); i += 4
                    elif params[i+1] == 5 and i + 2 < len(params):
                        fg = _ansi256(params[i+2]); i += 2
                i += 1
            pending_fg, pending_bold = fg, bold

    flush()
    return lines

# ── Capture demo output with forced colour ────────────────────────────────────

env = {**os.environ, "FORCE_COLOR": "1", "COLUMNS": "120"}
result = subprocess.run(
    [sys.executable, str(DEMO)],
    capture_output=True, text=True, env=env,
)
lines = parse_ansi(result.stdout)

# ── Font ──────────────────────────────────────────────────────────────────────

FONT_SIZE   = 13
PADDING     = 24
LINE_HEIGHT = FONT_SIZE + 6
BG          = (30, 30, 30)

_font_paths = (
    "/System/Library/Fonts/Menlo.ttc",
    "/Library/Fonts/Courier New.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
)

def _load_font(bold=False):
    for p in _font_paths:
        try:
            idx = 1 if bold and p.endswith(".ttc") else 0
            return ImageFont.truetype(p, FONT_SIZE, index=idx)
        except OSError:
            pass
    return ImageFont.load_default()

font_regular = _load_font(bold=False)
font_bold    = _load_font(bold=True)

# ── Canvas dimensions ─────────────────────────────────────────────────────────

probe  = ImageDraw.Draw(Image.new("RGB", (1, 1)))
char_w = probe.textlength("M", font=font_regular)  # monospace: all chars same width

max_cols = max((sum(len(t) for t, *_ in ln) for ln in lines if ln), default=80)
width    = int(max_cols * char_w) + PADDING * 2
height   = len(lines) * LINE_HEIGHT + PADDING * 2

# ── Render ────────────────────────────────────────────────────────────────────

img  = Image.new("RGB", (width, height), color=BG)
draw = ImageDraw.Draw(img)

for row, segments in enumerate(lines):
    y = PADDING + row * LINE_HEIGHT
    x = float(PADDING)
    for text, color, bold in segments:
        f = font_bold if bold else font_regular
        draw.text((x, y), text, fill=color, font=f)
        x += draw.textlength(text, font=f)

img.save(OUT)
print(f"Saved {OUT}  ({img.width}×{img.height}px)")
