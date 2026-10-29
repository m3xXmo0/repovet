"""Render docs/social-preview.png, the GitHub social preview (1280 x 640).

Usage: uv run --group docs python scripts/social_preview.py [OUTPUT]

The report excerpt is a real summary box from repovet's terminal report for a sample
scan result, so the picture changes with the report layout. Pillow is only in the
``docs`` dependency group; the package itself does not need it. Fonts: the first one
found from a short list of common system fonts (Segoe UI and Consolas on Windows, SF and
Menlo on macOS, DejaVu on Linux), else Pillow's built-in font. Upload the PNG in the
repository settings (Settings, General, Social preview).
"""

import re
import sys
from datetime import UTC, datetime
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

from repovet import __version__
from repovet.engine.loader import load_rules
from repovet.models import Finding, Location, ScanResult
from repovet.report.terminal import render_summary

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "docs" / "social-preview.png"
SIZE = (1280, 640)
BACKGROUND = "#0d1117"
PANEL = "#161b22"
BORDER = "#30363d"
TEXT = "#e6edf3"
MUTED = "#9198a1"
ACCENT = "#58a6ff"
LEVEL_COLORS = {
    "CRITICAL": "#ff7b72",
    "HIGH": "#f85149",
    "MEDIUM": "#d29922",
    "LOW": "#58a6ff",
    "critical": "#ff7b72",
    "high": "#f85149",
    "medium": "#d29922",
}
_LEVEL = re.compile(r"\b(CRITICAL|HIGH|MEDIUM|LOW|\d+ critical|\d+ high|\d+ medium)\b")

SANS_BOLD = [
    "C:/Windows/Fonts/segoeuib.ttf",
    "/System/Library/Fonts/SFNS.ttf",
    "/Library/Fonts/Arial Bold.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/TTF/DejaVuSans-Bold.ttf",
]
SANS = [
    "C:/Windows/Fonts/segoeui.ttf",
    "/System/Library/Fonts/SFNS.ttf",
    "/Library/Fonts/Arial.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/TTF/DejaVuSans.ttf",
]
MONO = [
    "C:/Windows/Fonts/consola.ttf",
    "/System/Library/Fonts/Menlo.ttc",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
]


def font(candidates: list[str], size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    for path in candidates:
        if Path(path).is_file():
            return ImageFont.truetype(path, size)
    return ImageFont.load_default(size)


def sample_result() -> ScanResult:
    """Four findings with the real titles and levels of their rules."""
    rules = load_rules()
    places = [
        ("RC-AGENT-002", "CLAUDE.md"),
        ("RC-AUTO-021", ".vscode/tasks.json"),
        ("RC-AUTO-003", "package.json"),
        ("RC-DEP-001", "requirements.txt"),
    ]
    findings = []
    for rule_id, path in places:
        rule = rules.get(rule_id)
        if rule is None:
            raise SystemExit(f"unknown rule {rule_id}")
        findings.append(
            Finding(
                rule_id=rule.id,
                title=rule.title,
                category=rule.category,
                area=rule.area,
                severity=rule.severity,
                confidence=rule.confidence,
                location=Location(path, 3),
                message=rule.title,
                evidence=None,
                rationale="",
                recommendation="",
            )
        )
    return ScanResult(
        target="https://github.com/example/demo",
        mode="GitHub repository",
        online=False,
        tool_version=__version__,
        rules_loaded=126,
        files_scanned=42,
        started=datetime(2026, 10, 29, tzinfo=UTC),
        duration_s=1.0,
        findings=findings,
        coverage=[],
    )


def draw_line(
    draw: ImageDraw.ImageDraw,
    xy: tuple[int, int],
    line: str,
    mono: ImageFont.FreeTypeFont | ImageFont.ImageFont,
) -> None:
    x, y = xy
    position = 0
    for match in _LEVEL.finditer(line):
        before = line[position : match.start()]
        draw.text((x, y), before, font=mono, fill=TEXT)
        x += int(draw.textlength(before, font=mono))
        word = match.group(0)
        color = LEVEL_COLORS.get(word.split()[-1], TEXT)
        draw.text((x, y), word, font=mono, fill=color)
        x += int(draw.textlength(word, font=mono))
        position = match.end()
    draw.text((x, y), line[position:], font=mono, fill=TEXT)


def render(output: Path) -> None:
    image = Image.new("RGB", SIZE, BACKGROUND)
    draw = ImageDraw.Draw(image)
    title = font(SANS_BOLD, 84)
    tagline = font(SANS, 36)
    small = font(SANS, 23)
    mono = font(MONO, 22)

    draw.text((80, 28), "repovet", font=title, fill=TEXT)
    draw.text((84, 136), "Vet a Git repository before you run it.", font=tagline, fill=ACCENT)
    draw.text(
        (84, 188),
        "Static checks for auto-run code, AI agent files, obfuscation and more. "
        "Nothing from the repository is run.",
        font=small,
        fill=MUTED,
    )

    # The rows inside the summary box; the drawn panel replaces the text frame, whose
    # thin box-drawing characters do not show well at this size.
    box_lines = render_summary(sample_result()).splitlines()[2:-1]
    lines = [line[2:-2].rstrip() for line in box_lines]
    ascent, descent = mono.getmetrics() if hasattr(mono, "getmetrics") else (18, 5)
    line_height = ascent + descent + 2
    width = int(max(draw.textlength(line, font=mono) for line in lines))
    left = (SIZE[0] - width) // 2
    box_top = 262
    box = (left - 36, box_top, left + width + 36, box_top + 56 + line_height * len(lines))
    draw.rounded_rectangle(box, radius=14, fill=PANEL, outline=BORDER, width=2)
    draw.text(
        (left, box_top + 14),
        "$ repovet scan https://github.com/example/demo",
        font=mono,
        fill=MUTED,
    )
    for number, line in enumerate(lines):
        draw_line(draw, (left, box_top + 46 + number * line_height), line, mono)
    image.save(output, optimize=True)


def main(argv: list[str]) -> int:
    output = Path(argv[1]) if len(argv) > 1 else OUTPUT
    render(output)
    print(f"wrote {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
