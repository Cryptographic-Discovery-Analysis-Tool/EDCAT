"""Crop the captured panels into deck-ready images (2x device scale)."""
import pathlib
from PIL import Image

D = pathlib.Path(__file__).parent / "shots"
S = 2  # device_scale_factor


def crop(src, dst, x0, y0, x1, y1):
    im = Image.open(D / src)
    out = im.crop((x0 * S, y0 * S, x1 * S, y1 * S))
    out.save(D / dst)
    print(dst, out.size)


# 1. the evidence card: verdict -> data class / evidence used
crop("drawer_full.png", "card_evidence.png", 0, 20, 660, 800)

# 2. the replay strip: show your working -> re-run now
crop("drawer_full.png", "strip_replay.png", 8, 1205, 660, 1400)

# 3. closure queue: banner, tabs, ranking rule, first two tasks
crop("closure_main.png", "card_closure.png", 0, 0, 1370, 1010)
