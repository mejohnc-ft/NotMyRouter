#!/usr/bin/env python3
"""Generate NotMyRouter app icon."""
from PIL import Image, ImageDraw, ImageFont
import subprocess, os, shutil

SIZE = 1024
ICON_SIZES = [16, 32, 64, 128, 256, 512, 1024]

def create_icon(size=SIZE):
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Rounded rect background - dark charcoal with slight blue tint
    margin = int(size * 0.08)
    radius = int(size * 0.18)
    bg_color = (24, 28, 36)
    draw.rounded_rectangle(
        [margin, margin, size - margin, size - margin],
        radius=radius, fill=bg_color
    )

    # Subtle inner glow border
    border_color = (255, 100, 40, 80)
    draw.rounded_rectangle(
        [margin, margin, size - margin, size - margin],
        radius=radius, outline=border_color, width=max(2, size // 200)
    )

    # Draw signal bars (bottom right area, behind text)
    bar_x_start = int(size * 0.58)
    bar_y_bottom = int(size * 0.82)
    bar_width = int(size * 0.055)
    bar_gap = int(size * 0.02)
    bar_heights = [0.08, 0.14, 0.22, 0.32, 0.44]

    for i, h in enumerate(bar_heights):
        x = bar_x_start + i * (bar_width + bar_gap)
        bar_h = int(size * h)
        y_top = bar_y_bottom - bar_h
        # First 3 bars orange (good signal), last 2 red (bad - Cox's fault)
        if i < 3:
            color = (255, 140, 50, 60)
        else:
            color = (220, 50, 50, 50)
        draw.rounded_rectangle(
            [x, y_top, x + bar_width, bar_y_bottom],
            radius=max(2, size // 200),
            fill=color
        )

    # "X" through the last two bars (kill signal)
    x_color = (220, 50, 50, 120)
    x_w = max(3, size // 120)
    x1 = bar_x_start + 3 * (bar_width + bar_gap) - int(size * 0.01)
    x2 = bar_x_start + 4 * (bar_width + bar_gap) + bar_width + int(size * 0.01)
    y1 = bar_y_bottom - int(size * 0.44) - int(size * 0.02)
    y2 = bar_y_bottom + int(size * 0.02)
    draw.line([(x1, y1), (x2, y2)], fill=x_color, width=x_w)
    draw.line([(x1, y2), (x2, y1)], fill=x_color, width=x_w)

    # Main text "CK" - big and bold
    try:
        # Try system fonts
        for font_name in [
            '/System/Library/Fonts/SFCompact-Black.otf',
            '/System/Library/Fonts/Supplemental/Impact.ttf',
            '/System/Library/Fonts/Helvetica.ttc',
            '/System/Library/Fonts/SFNSDisplay-Bold.otf',
        ]:
            if os.path.exists(font_name):
                font_large = ImageFont.truetype(font_name, int(size * 0.42))
                break
        else:
            font_large = ImageFont.load_default()
    except:
        font_large = ImageFont.load_default()

    # Draw "CK" centered, slightly above middle
    text = "CK"
    bbox = draw.textbbox((0, 0), text, font=font_large)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    tx = (size - tw) // 2 - int(size * 0.04)
    ty = int(size * 0.18)

    # Text shadow
    shadow_offset = max(2, size // 150)
    draw.text((tx + shadow_offset, ty + shadow_offset), text, fill=(0, 0, 0, 180), font=font_large)

    # Main text - bright orange gradient effect (solid orange)
    draw.text((tx, ty), text, fill=(255, 140, 50), font=font_large)

    # Subtitle "NOTMYROUTER" at bottom
    try:
        for font_name in [
            '/System/Library/Fonts/SFCompact-Bold.otf',
            '/System/Library/Fonts/Supplemental/Arial Bold.ttf',
            '/System/Library/Fonts/Helvetica.ttc',
        ]:
            if os.path.exists(font_name):
                font_small = ImageFont.truetype(font_name, int(size * 0.075))
                break
        else:
            font_small = ImageFont.load_default()
    except:
        font_small = ImageFont.load_default()

    sub = "NOTMYROUTER"
    bbox2 = draw.textbbox((0, 0), sub, font=font_small)
    sw = bbox2[2] - bbox2[0]
    sx = (size - sw) // 2
    sy = int(size * 0.62)
    draw.text((sx, sy), sub, fill=(180, 180, 190), font=font_small)

    # Small network pulse line under subtitle
    pulse_y = int(size * 0.73)
    pulse_color = (255, 140, 50, 160)
    pw = max(2, size // 250)
    cx = size // 2
    points = [
        (cx - int(size * 0.25), pulse_y),
        (cx - int(size * 0.12), pulse_y),
        (cx - int(size * 0.08), pulse_y - int(size * 0.06)),
        (cx - int(size * 0.04), pulse_y + int(size * 0.08)),
        (cx, pulse_y - int(size * 0.10)),
        (cx + int(size * 0.04), pulse_y + int(size * 0.06)),
        (cx + int(size * 0.08), pulse_y - int(size * 0.03)),
        (cx + int(size * 0.12), pulse_y),
        (cx + int(size * 0.25), pulse_y),
    ]
    draw.line(points, fill=pulse_color, width=pw, joint='curve')

    return img


def main():
    iconset_dir = '/tmp/NotMyRouter.iconset'
    if os.path.exists(iconset_dir):
        shutil.rmtree(iconset_dir)
    os.makedirs(iconset_dir)

    base = create_icon(1024)

    for s in ICON_SIZES:
        resized = base.resize((s, s), Image.LANCZOS)
        resized.save(f'{iconset_dir}/icon_{s}x{s}.png')
        if s <= 512:
            resized2x = base.resize((s * 2, s * 2), Image.LANCZOS)
            resized2x.save(f'{iconset_dir}/icon_{s}x{s}@2x.png')

    # Create .icns
    icns_path = os.path.expanduser(
        '~/Applications/NotMyRouter.app/Contents/Resources/AppIcon.icns'
    )
    subprocess.run(['iconutil', '-c', 'icns', iconset_dir, '-o', icns_path], check=True)
    print(f'Created {icns_path}')

    # Also save a PNG for the web dashboard favicon
    favicon = base.resize((256, 256), Image.LANCZOS)
    favicon_path = os.path.expanduser('~/network-monitor/notmyrouter_icon.png')
    favicon.save(favicon_path)
    print(f'Created {favicon_path}')

    shutil.rmtree(iconset_dir)


if __name__ == '__main__':
    main()
