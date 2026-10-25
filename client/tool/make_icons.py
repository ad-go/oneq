#!/usr/bin/env python3
"""Renders every icon of oneq from one design: a rounded square with a white "1q".
  python client/tool/make_icons.py            writes the files listed below in place (needs Pillow and a bold sans-serif font)

  app/assets/tray_{connected,connecting,off}.{png,ico}     tray / menu-bar icons (green, orange, grey)
  app/windows/runner/resources/app_icon.ico                 Windows app icon
  app/macos/Runner/Assets.xcassets/AppIcon.appiconset/      macOS app icon (16 ... 1024)
  app/android/app/src/main/res/mipmap-*/ic_launcher.png     Android launcher icon
  app/android/app/src/main/res/drawable/ic_stat_oneq.png    Android notification icon (white glyph on transparent, as Android requires)
  browser/extension/icons/icon{16,32,48,128}.png            browser extension

The drawing is done at 4x and reduced (LANCZOS) so small sizes stay clean. Fonts are looked for in the usual places of Windows, macOS and Linux."""
import os
import sys

from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
CLIENT = os.path.abspath(os.path.join(HERE, ".."))
GREEN, ORANGE, GREY = (27, 107, 90), (214, 140, 20), (110, 115, 120)
FONTS = [r"C:\Windows\Fonts\segoeuib.ttf", r"C:\Windows\Fonts\arialbd.ttf", "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
         "/Library/Fonts/Arial Bold.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf"]


def font(size):
    for f in FONTS:
        if os.path.exists(f):
            return ImageFont.truetype(f, size)
    sys.exit("no bold sans-serif font found (looked in: %s)" % ", ".join(FONTS))


def glyph_layer(side, scale):
    """The white "1q" centred (by its ink box, so the descender of the q does not push it up), as an RGBA layer of side*scale pixels."""
    s = side * scale
    layer = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    size = int(s * 0.60)
    f = font(size)
    x0, y0, x1, y1 = d.textbbox((0, 0), "1q", font=f)
    w, h = x1 - x0, y1 - y0
    # the ink of "1q" is taller below the baseline than the x-height suggests: centre the ink box, nudged a little up for the optical centre
    d.text(((s - w) / 2 - x0, (s - h) / 2 - y0 - s * 0.015), "1q", font=f, fill=(255, 255, 255, 255))
    return layer


def tile(side, color, margin=0.04, radius=0.22):
    """Rounded square of `color` with the white glyph, `side` pixels."""
    k = 4
    s = side * k
    im = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    m = int(s * margin)
    d.rounded_rectangle((m, m, s - m - 1, s - m - 1), radius=int(s * radius), fill=color + (255,))
    im.alpha_composite(glyph_layer(side, k))
    return im.resize((side, side), Image.LANCZOS)


def stat(side):
    """White glyph on a transparent background (Android notification icons are masks)."""
    return glyph_layer(side, 4).resize((side, side), Image.LANCZOS)


def save_png(path, im):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    im.save(path, format="PNG", optimize=True)


def save_ico(path, im, sizes):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    im.save(path, format="ICO", sizes=[(s, s) for s in sizes])


def main():
    out = []
    a = os.path.join(CLIENT, "app")
    for name, color in (("connected", GREEN), ("connecting", ORANGE), ("off", GREY)):
        save_png(os.path.join(a, "assets", f"tray_{name}.png"), tile(64, color))
        save_ico(os.path.join(a, "assets", f"tray_{name}.ico"), tile(256, color), [16, 24, 32, 48, 64, 256])
        out.append(f"tray_{name}")
    save_ico(os.path.join(a, "windows", "runner", "resources", "app_icon.ico"), tile(256, GREEN), [16, 32, 48, 64, 128, 256])
    mac = os.path.join(a, "macos", "Runner", "Assets.xcassets", "AppIcon.appiconset")
    for s in (16, 32, 64, 128, 256, 512, 1024):
        save_png(os.path.join(mac, f"app_icon_{s}.png"), tile(s, GREEN, margin=0.08, radius=0.225))
    res = os.path.join(a, "android", "app", "src", "main", "res")
    for d, s in (("mdpi", 48), ("hdpi", 72), ("xhdpi", 96), ("xxhdpi", 144), ("xxxhdpi", 192)):
        save_png(os.path.join(res, f"mipmap-{d}", "ic_launcher.png"), tile(s, GREEN, margin=0.02, radius=0.22))
    save_png(os.path.join(res, "drawable", "ic_stat_oneq.png"), stat(96))
    for s in (16, 32, 48, 128):
        save_png(os.path.join(CLIENT, "browser", "extension", "icons", f"icon{s}.png"), tile(s, GREEN, margin=0.02 if s < 48 else 0.04))
    print("icons written:", len(out) * 2 + 1 + 7 + 5 + 1 + 4)


if __name__ == "__main__":
    main()
