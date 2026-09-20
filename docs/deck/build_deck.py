"""Rebuild the Pramana SIH idea deck in place.

Starts from the existing ECDAT_Pramana_SIH2026_Idea.pptx, keeps every slide's
chrome (title, subtitle, team oval, SIH logo, footer bar, page number -- shape
ids 2-9 on each content slide), and rebuilds the content region so that:

  * every official SIH template pointer appears verbatim as a section heading,
  * nothing reports build status: this is an idea deck,
  * density drops -- short lines, more white space, three real images.
"""
from __future__ import annotations

import copy
import pathlib

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.util import Inches, Pt

HERE = pathlib.Path(__file__).parent
SRC = pathlib.Path(r"C:\Users\athar\Downloads\ECDAT_Pramana_SIH2026_Idea.pptx")
DST = HERE / "out" / "ECDAT_Pramana_SIH2026_Idea.pptx"
SHOTS = HERE / "screenshots"

# --- palette, lifted from the deck it replaces -------------------------------
INK = RGBColor(0x12, 0x28, 0x3A)
MUTED = RGBColor(0x44, 0x60, 0x7A)
FAINT = RGBColor(0x7C, 0x93, 0xA3)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)
BLUE = RGBColor(0x00, 0x70, 0xC0)
RED = RGBColor(0xC0, 0x39, 0x2B)
MAROON = RGBColor(0x7B, 0x30, 0x40)
GREEN = RGBColor(0x13, 0x79, 0x5B)
AMBER = RGBColor(0xB8, 0x75, 0x14)

PANEL = RGBColor(0xF3, 0xF7, 0xF9)
BLUE_BG = RGBColor(0xEA, 0xF1, 0xF5)
RED_BG = RGBColor(0xFA, 0xE9, 0xE6)
MAROON_BG = RGBColor(0xF3, 0xE8, 0xEB)
GREEN_BG = RGBColor(0xE4, 0xF1, 0xEC)
AMBER_BG = RGBColor(0xFB, 0xF1, 0xDF)
RULE = RGBColor(0xD9, 0xE3, 0xEA)

CAL = "Calibri"
TNR = "Times New Roman"

LEFT_X = 0.42
FULL_W = 12.49
KEEP = {2, 3, 4, 5, 6, 7, 8, 9}


# --- primitives ---------------------------------------------------------------
def subtitle(slide, text):
    """Rewrite the slide's existing subtitle (chrome shape id 9) in place."""
    for sh in slide.shapes:
        if sh.shape_id == 9 and sh.has_text_frame:
            p0 = sh.text_frame.paragraphs[0]
            for extra in list(p0.runs)[1:]:
                extra._r.getparent().remove(extra._r)
            p0.runs[0].text = text
            return


def clear(slide):
    for sh in list(slide.shapes):
        if sh.shape_id not in KEEP:
            sh._element.getparent().remove(sh._element)


def rect(slide, x, y, w, h, fill=None, line=None, radius=None, dash=False):
    shape = MSO_SHAPE.ROUNDED_RECTANGLE if radius is not None else MSO_SHAPE.RECTANGLE
    sh = slide.shapes.add_shape(shape, Inches(x), Inches(y), Inches(w), Inches(h))
    if radius is not None:
        sh.adjustments[0] = radius
    if fill is None:
        sh.fill.background()
    else:
        sh.fill.solid()
        sh.fill.fore_color.rgb = fill
    if line is None:
        sh.line.fill.background()
    else:
        sh.line.color.rgb = line
        sh.line.width = Pt(0.75)
        if dash:
            from pptx.enum.dml import MSO_LINE_DASH_STYLE

            sh.line.dash_style = MSO_LINE_DASH_STYLE.DASH
    sh.shadow.inherit = False
    return sh


def dot(slide, x, y, size, color, square=False):
    shape = MSO_SHAPE.RECTANGLE if square else MSO_SHAPE.OVAL
    sh = slide.shapes.add_shape(shape, Inches(x), Inches(y), Inches(size), Inches(size))
    sh.fill.solid()
    sh.fill.fore_color.rgb = color
    sh.line.fill.background()
    sh.shadow.inherit = False
    return sh


def txt(slide, x, y, w, h, body, size=10, color=MUTED, bold=False, font=CAL,
        align=PP_ALIGN.LEFT, italic=False, spacing=None, anchor=MSO_ANCHOR.TOP):
    """body: str, or list of paragraphs; a paragraph is a str or a list of
    (text, {size,color,bold,italic,font}) run tuples."""
    box = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    tf = box.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = anchor
    tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0
    paras = body if isinstance(body, list) else [body]
    for i, para in enumerate(paras):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.alignment = align
        if spacing:
            p.line_spacing = spacing
        runs = para if isinstance(para, list) else [(para, {})]
        for text, opt in runs:
            r = p.add_run()
            r.text = text
            r.font.size = Pt(opt.get("size", size))
            r.font.bold = opt.get("bold", bold)
            r.font.italic = opt.get("italic", italic)
            r.font.name = opt.get("font", font)
            r.font.color.rgb = opt.get("color", color)
    return box


def head(slide, x, y, w, label, color=BLUE, size=11.5):
    """A section heading: small square bullet + uppercase label."""
    dot(slide, x, y + 0.075, 0.12, color, square=True)
    txt(slide, x + 0.20, y, w - 0.20, 0.26, label, size=size, color=INK, bold=True)
    return y + 0.30


def rows(slide, x, y, w, items, label_w, gap=0.245, size=9.5,
         label_color=INK, value_color=MUTED, bullet=None):
    """A stack of short label/value lines -- the deck's main list idiom."""
    for label, value in items:
        if bullet is not None:
            dot(slide, x, y + 0.055, 0.085, bullet)
            lx = x + 0.17
        else:
            lx = x
        txt(slide, lx, y, label_w, 0.22, label, size=size, color=label_color, bold=True)
        txt(slide, lx + label_w, y, w - label_w - (lx - x), 0.30, value,
            size=size, color=value_color)
        y += gap
    return y


def picture(slide, name, x, y, w):
    path = SHOTS / name
    pic = slide.shapes.add_picture(str(path), Inches(x), Inches(y), width=Inches(w))
    ln = pic.line
    ln.color.rgb = RULE
    ln.width = Pt(0.75)
    return pic


# =============================================================================
# SLIDE 2 -- IDEA TITLE
# =============================================================================
def slide2(s):
    clear(s)

    y = head(s, LEFT_X, 1.00, 6.0, "PROPOSED SOLUTION  (Describe your Idea / Solution / Prototype)")
    rect(s, LEFT_X, y, FULL_W, 0.92, fill=BLUE_BG, radius=0.06)
    txt(s, LEFT_X + 0.25, y + 0.11, FULL_W - 0.5, 0.25,
        [[("Harvest now, decrypt later: ", {"bold": True, "color": INK}),
          ("traffic recorded today is read the day a quantum computer arrives.", {})]],
        size=12)
    txt(s, LEFT_X + 0.25, y + 0.36, FULL_W - 0.5, 0.28,
        "Migration stops the bleeding. It cannot recover what already leaked.",
        size=15.5, color=RED, bold=True, font=TNR)
    txt(s, LEFT_X + 0.25, y + 0.66, FULL_W - 0.5, 0.25,
        "So Pram\u0101\u1e47a ranks every use of cryptography by how much of its protected "
        "data is still savable \u2014 not by algorithm name or key size.", size=11.5)

    y = head(s, LEFT_X, 2.40, 8.0, "DETAILED EXPLANATION  \u2014  THE OUTPUT IS FOUR BANDS, NOT A RISK SCORE")
    bands = [
        ("BLEEDING", RED, RED_BG, "Exposed now, still exposed.", "Migrate this first."),
        ("UNSAVABLE", MAROON, MAROON_BG, "Window opened, migration closed it.", "Nothing left to save."),
        ("SAVABLE", GREEN, GREEN_BG, "Still inside the deadline Z \u2212 X.", "Plan \u2014 do not panic."),
        ("UNBOUNDED", AMBER, AMBER_BG, "Evidence missing. We say so \u2014", "and name the fact that settles it."),
    ]
    bw, gapx = 3.00, 0.165
    for i, (name, col, bg, l1, l2) in enumerate(bands):
        bx = LEFT_X + i * (bw + gapx)
        rect(s, bx, y, bw, 1.02, fill=bg, radius=0.09)
        dot(s, bx + 0.18, y + 0.20, 0.155, col)
        txt(s, bx + 0.42, y + 0.14, bw - 0.55, 0.26, name, size=12.5, color=col, bold=True)
        txt(s, bx + 0.18, y + 0.46, bw - 0.36, 0.48, [l1, l2], size=9.5, spacing=1.06)
    txt(s, LEFT_X, y + 1.10, FULL_W, 0.22,
        "A fifth band, SAFE, covers what Shor does not break. Symmetric keys are reported separately as a "
        "key-size question under Grover \u2014 never given a deadline they do not have.",
        size=9, color=FAINT, italic=True)

    y = 4.30
    head(s, LEFT_X, y, 5.9, "HOW IT ADDRESSES THE PROBLEM", color=GREEN)
    txt(s, LEFT_X + 0.22, y + 0.28, 5.9, 0.22,
        "DISCOVER  \u2192  PROVE  \u2192  PRIORITISE  \u2192  RECOMMEND  \u2192  VERIFY",
        size=9, color=GREEN, bold=True)
    rows(s, LEFT_X + 0.02, y + 0.60, 5.95, [
        ("Catalogue", "algorithms, keys, certificates, protocols, libraries, HSMs, cloud KMS"),
        ("Quantum risk", "Shor-broken secrecy and identity, on two separate clocks"),
        ("Classify + Mosca", "type, data lifetime X and business criticality \u2014 Mosca, on two clocks"),
        ("Recommend", "FIPS 203 / 204 / 205 and hybrid, by purpose \u2014 size, latency, cost, compatibility"),
        ("Report", "CycloneDX 1.6 CBOM (ECMA-424) plus an interactive evidence console"),
    ], label_w=1.45, gap=0.415, bullet=GREEN)

    head(s, 6.95, y, 5.9, "INNOVATION AND UNIQUENESS", color=RED)
    txt(s, 6.95 + 0.22, y + 0.28, 5.9, 0.22,
        "RANKED, NEVER SCORED:   band  \u2192  business criticality  \u2192  longest window",
        size=9, color=RED, bold=True)
    rows(s, 6.97, y + 0.60, 5.95, [
        ("Two clocks", "secrecy leaks before Z; signatures only fail after Z"),
        ("No weights", "lexicographic on categorical fields \u2014 no score anyone has to defend"),
        ("Status per field", "Observed / Inferred / Declared / Unknown \u2014 Unknown is a result"),
        ("Closure engine", "names the one fact that would settle an unbounded row"),
        ("Replayable", "every band recomputes from its stored record \u2014 nothing is typed in"),
    ], label_w=1.45, gap=0.415, bullet=RED)


# =============================================================================
# SLIDE 3 -- TECHNICAL APPROACH
# =============================================================================
def slide3(s):
    clear(s)
    subtitle(s, "Deterministic pipeline  ·  two clocks  ·  reused sensors  ·  AI may suggest, only evidence decides")

    y = head(s, LEFT_X, 0.98, 9.5,
             "METHODOLOGY AND PROCESS FOR IMPLEMENTATION  \u2014  DETERMINISTIC, REPLAYABLE, EVIDENCE-GATED")
    steps = [
        ("OBSERVE", "sensors run"), ("STATUS", "evidence per field"),
        ("CORRELATE", "same object?"), ("BIND", "data class \u2192 X, A"),
        ("CLOCK", "scenario Z"), ("LEDGER", "band + window"),
        ("CLOSE", "next evidence"), ("ACT", "PQC option set"),
        ("VERIFY", "window closed?"),
    ]
    bw, gapx = 1.295, 0.105
    for i, (name, sub) in enumerate(steps):
        bx = LEFT_X + i * (bw + gapx)
        hot = name == "LEDGER"
        rect(s, bx, y, bw, 0.52, fill=INK if hot else PANEL, radius=0.10)
        txt(s, bx, y + 0.09, bw, 0.20, name, size=9.5,
            color=WHITE if hot else INK, bold=True, align=PP_ALIGN.CENTER)
        txt(s, bx, y + 0.29, bw, 0.18, sub, size=7.5,
            color=RGBColor(0xC9, 0xD8, 0xE4) if hot else MUTED, align=PP_ALIGN.CENTER)
        if i < len(steps) - 1:
            txt(s, bx + bw, y + 0.13, gapx, 0.22, "\u203a", size=11, color=FAINT,
                align=PP_ALIGN.CENTER)

    # --- clock 1: confidentiality --------------------------------------------
    cy = 1.86
    rect(s, LEFT_X, cy, 7.52, 2.60, fill=PANEL, radius=0.05)
    dot(s, LEFT_X + 0.22, cy + 0.19, 0.145, RED)
    txt(s, LEFT_X + 0.45, cy + 0.13, 7.0, 0.26,
        [[("1   CONFIDENTIALITY CLOCK", {"bold": True, "color": INK}),
          ("   \u2014   key exchange & key transport", {"color": MUTED})]], size=11.5)
    txt(s, LEFT_X + 0.45, cy + 0.40, 6.9, 0.22,
        "The data leaks while the channel is classical. Migration ends the leak; it does not undo it.",
        size=9.5)

    bx0, bw_tot, byy, bh = LEFT_X + 0.48, 6.56, cy + 0.72, 0.42
    seg = [(0.00, 0.30, BLUE_BG, "protected", MUTED), (0.30, 0.42, RED, "UNSAVABLE WINDOW", WHITE)]
    for f0, fw, fill, label, tc in seg:
        rect(s, bx0 + f0 * bw_tot, byy, fw * bw_tot, bh, fill=fill)
        txt(s, bx0 + f0 * bw_tot, byy + 0.115, fw * bw_tot, 0.22, label, size=9,
            color=tc, bold=(tc is WHITE), align=PP_ALIGN.CENTER)
    rect(s, bx0 + 0.72 * bw_tot, byy, 0.28 * bw_tot, bh, fill=AMBER_BG, line=AMBER, dash=True)
    txt(s, bx0 + 0.72 * bw_tot, byy + 0.115, 0.28 * bw_tot, 0.22,
        "still bleeding \u2192 until migration M", size=8, color=AMBER, align=PP_ALIGN.CENTER)

    axis_y = byy + bh + 0.06
    rect(s, bx0, axis_y, bw_tot, 0.012, fill=RULE)
    for frac, label, sub in [(0.00, "start", "first evidence of use"), (0.30, "Z \u2212 X", "deadline"),
                             (0.72, "today", ""), (1.00, "Z", "CRQC scenario")]:
        lx = bx0 + frac * bw_tot - 0.55
        txt(s, lx, axis_y + 0.06, 1.10, 0.20, label, size=8.5, color=INK, bold=True,
            align=PP_ALIGN.CENTER)
        if sub:
            txt(s, lx, axis_y + 0.25, 1.10, 0.18, sub, size=7, color=FAINT, align=PP_ALIGN.CENTER)

    fy = cy + 1.82
    rect(s, LEFT_X + 0.30, fy, 6.92, 0.46, fill=WHITE, line=RULE)
    txt(s, LEFT_X + 0.45, fy + 0.07, 6.6, 0.22,
        "unsavable window  =  [  max( start , Z \u2212 X )  ,  min( today , M )  ]",
        size=10.5, color=INK, font="Consolas")
    txt(s, LEFT_X + 0.45, fy + 0.27, 6.6, 0.18,
        "M  =  first observed migration with classical key exchange disabled", size=8, color=FAINT)
    txt(s, LEFT_X + 0.30, fy + 0.52, 7.0, 0.20,
        "Every row prints \u201cassumes capture since <start>\u201d \u2014 a stated, switchable assumption, "
        "never a claim that data was decrypted.", size=8, color=FAINT, italic=True)

    # --- clock 2: authentication ---------------------------------------------
    ax = 8.18
    rect(s, ax, cy, 4.73, 2.60, fill=PANEL, radius=0.05)
    dot(s, ax + 0.22, cy + 0.19, 0.145, GREEN)
    txt(s, ax + 0.45, cy + 0.13, 4.2, 0.26,
        [[("2   AUTHENTICATION CLOCK", {"bold": True, "color": INK}),
          ("  \u2014  signatures", {"color": MUTED})]], size=11.5)
    txt(s, ax + 0.45, cy + 0.40, 4.1, 0.22,
        "Forgery becomes possible after Z. Nothing leaks before it.", size=9.5)
    rect(s, ax + 0.30, cy + 0.68, 4.13, 0.36, fill=WHITE, line=RULE)
    txt(s, ax + 0.30, cy + 0.76, 4.13, 0.22,
        "required_until  =  signed_at  +  A", size=10.5, color=INK, font="Consolas",
        align=PP_ALIGN.CENTER)

    ry = cy + 1.14
    for cond, verdict, vcol, action in [
        ("A = 0   (session keys, JWT)", "ROTATE BEFORE Z", AMBER, "deadline  Z − Y"),
        ("required_until  ≤  Z", "SAFE UNTIL Z", GREEN, "no action on this clock"),
        ("required_until  >  Z", "RE-SIGN BEFORE Z", RED, "PQ signature or trusted timestamp"),
    ]:
        txt(s, ax + 0.30, ry, 4.13, 0.22,
            [[(cond, {"color": MUTED, "size": 8.5}),
              ("    →    ", {"color": FAINT, "size": 8.5}),
              (verdict, {"color": vcol, "size": 9.5, "bold": True})]])
        txt(s, ax + 0.30, ry + 0.21, 4.13, 0.18, action, size=7.5, color=FAINT)
        ry += 0.36

    rect(s, ax + 0.30, cy + 2.28, 4.13, 0.30, fill=WHITE, line=RULE)
    txt(s, ax + 0.30, cy + 2.34, 4.13, 0.22,
        "A root CA is urgent \u2014 but it is not bleeding.", size=9, color=INK, bold=True,
        italic=True, align=PP_ALIGN.CENTER)

    # --- technologies + prototype --------------------------------------------
    ty = 4.56
    head(s, LEFT_X, ty, 8.0, "TECHNOLOGIES TO BE USED")
    tech = [
        ("Evidence sensors", GREEN,
         "Semgrep CE + our own inventory rule packs  \u00b7  OpenSSL 3 / python-cryptography  \u00b7  sslyze  \u00b7  "
         "Trivy  \u00b7  cbomkit-theia  \u00b7  YARA + readelf  \u00b7  PKCS#11 (SoftHSM2)  \u00b7  cloud KMS metadata"),
        ("Deterministic core", BLUE,
         "Python 3.12  \u00b7  evidence model  \u00b7  crypto-function classifier  \u00b7  temporal model  \u00b7  "
         "scenario engine  \u00b7  business-context binding (owner \u00b7 criticality \u00b7 data class)  \u00b7  "
         "two ledgers  \u00b7  closure engine  \u00b7  replay record"),
        ("Platform", INK,
         "PostgreSQL (JSONB evidence + snapshots)  \u00b7  FastAPI  \u00b7  React / Vite  \u00b7  CycloneDX 1.6  \u00b7  "
         "Docker Compose, no egress  \u00b7  RBAC + audit log  \u00b7  key material never stored"),
    ]
    ry = ty + 0.34
    for label, col, value in tech:
        rect(s, LEFT_X, ry, 8.00, 0.46, fill=PANEL, radius=0.10)
        txt(s, LEFT_X + 0.16, ry + 0.11, 1.62, 0.24, label, size=9.5, color=col, bold=True)
        txt(s, LEFT_X + 1.80, ry + 0.04, 6.06, 0.42, value, size=8, color=MUTED, spacing=1.10)
        ry += 0.50

    rect(s, LEFT_X, ry + 0.02, 8.00, 0.44, fill=BLUE_BG, radius=0.10)
    txt(s, LEFT_X + 0.16, ry + 0.09, 7.70, 0.36,
        [[("AI may suggest. Only evidence may decide.  ", {"bold": True, "color": INK}),
          ("No model sits in the detection, correlation, banding or recommendation path — those are "
           "rule-driven and replayable. A model’s claim may still enter, but only as any third "
           "party’s does: DECLARED, to be confirmed by observation before it moves a deadline.", {"color": MUTED})]],
        size=7.5, spacing=1.14)

    picture(s, "strip_replay.png", 8.62, ty + 0.34, 4.29)
    txt(s, 8.62, ty + 1.70, 4.29, 0.58,
        "Working prototype \u2014 every verdict carries the rule, the fingerprint of its inputs, "
        "and a live re-run that must return the same answer.", size=8, color=FAINT, italic=True,
        spacing=1.1)


# =============================================================================
# SLIDE 4 -- FEASIBILITY AND VIABILITY
# =============================================================================
def slide4(s):
    clear(s)
    subtitle(s, "A worked example  ·  what breaks it  ·  how we handle it")

    y = head(s, LEFT_X, 0.98, 8.0, "ANALYSIS OF THE FEASIBILITY OF THE IDEA")
    feas = [
        ("Technical", "Mature open-source sensors, pinned and wrapped \u2014 not re-written."),
        ("Stack", "Python 3.12 / FastAPI, PostgreSQL, React on Docker Compose."),
        ("Operational", "On-prem, offline, passive. Probing needs written consent."),
        ("Economic", "Open-source sensors; our own rule packs, so no licence limit."),
    ]
    bw, gapx = 1.885, 0.142
    for i, (label, value) in enumerate(feas):
        bx = LEFT_X + i * (bw + gapx)
        rect(s, bx, y, bw, 0.92, fill=PANEL, radius=0.09)
        txt(s, bx + 0.15, y + 0.11, bw - 0.30, 0.22, label, size=9.5, color=BLUE, bold=True)
        txt(s, bx + 0.15, y + 0.34, bw - 0.30, 0.54, value, size=8, color=MUTED, spacing=1.1)

    # --- worked example -------------------------------------------------------
    wy = 2.36
    head(s, LEFT_X, wy, 7.5, "THE SAME RANKING ON A WORKED EXAMPLE", color=GREEN)
    ty = wy + 0.34
    cols = [(0.00, 0.34, "#"), (0.34, 3.05, "Usage context"), (3.39, 1.55, "Function"),
            (4.94, 1.72, "Band"), (6.66, 1.30, "2019 \u2192 today \u2192 Z")]
    rect(s, LEFT_X, ty, 7.96, 0.30, fill=INK)
    for cx, cw, label in cols:
        txt(s, LEFT_X + cx + 0.10, ty + 0.06, cw, 0.20, label, size=8.5, color=WHITE, bold=True)
    ry = ty + 0.30
    example = [
        ("1", "RES-001  research-data channel", "X25519 ECDHE  \u00b7  X = 25 y  \u00b7  since 2021",
         "KEY ESTABLISHMENT", "BLEEDING", "", RED, RED_BG, 0.02, 0.30),
        ("2", "PAY-001  payment key-wrap", "RSA, transformation from a config chain",
         "KEY TRANSPORT", "UNBOUNDED", "conditional BLEEDING", AMBER, AMBER_BG, 0.02, 0.30),
        ("3", "INF-001  root CA", "RSA-4096  \u00b7  A = 15 y",
         "SIGNATURE AUTH", "RE-SIGN", "BEFORE Z", MAROON, MAROON_BG, 0.78, 0.22),
        ("4", "PAY-005  edge TLS", "P-256 ECDHE  \u00b7  X = 1 y",
         "KEY ESTABLISHMENT", "SAVABLE", "deadline 2035", GREEN, GREEN_BG, 0.40, 0.36),
    ]
    rh = 0.66
    for i, (n, ctx, det, fn, band, band2, col, bg, bar0, barw) in enumerate(example):
        if i % 2 == 0:
            rect(s, LEFT_X, ry, 7.96, rh, fill=RGBColor(0xF8, 0xFB, 0xFC))
        txt(s, LEFT_X + 0.10, ry + 0.22, 0.30, 0.20, n, size=9, color=FAINT, bold=True)
        txt(s, LEFT_X + 0.44, ry + 0.11, 2.95, 0.20, ctx, size=9, color=INK, bold=True)
        txt(s, LEFT_X + 0.44, ry + 0.32, 2.95, 0.20, det, size=8, color=MUTED)
        txt(s, LEFT_X + 3.49, ry + 0.21, 1.45, 0.24, fn, size=7.5, color=MUTED, spacing=1.05)
        rect(s, LEFT_X + 5.00, ry + 0.10, 1.56, 0.46, fill=bg, line=col, radius=0.14)
        txt(s, LEFT_X + 5.00, ry + (0.20 if band2 else 0.26), 1.56, 0.20, band, size=8.5,
            color=col, bold=True, align=PP_ALIGN.CENTER)
        if band2:
            txt(s, LEFT_X + 5.00, ry + 0.36, 1.56, 0.18, band2, size=7, color=col,
                align=PP_ALIGN.CENTER)
        rect(s, LEFT_X + 6.70, ry + 0.32, 1.22, 0.012, fill=RULE)
        rect(s, LEFT_X + 6.70 + bar0 * 1.22, ry + 0.22, barw * 1.22, 0.20, fill=col)
        ry += rh

    rect(s, LEFT_X, ry + 0.08, 7.96, 0.62, fill=PANEL, radius=0.08)
    txt(s, LEFT_X + 0.18, ry + 0.15, 7.6, 0.22,
        "Why the order looks wrong \u2014 and isn\u2019t.", size=9.5, color=INK, bold=True)
    txt(s, LEFT_X + 0.18, ry + 0.37, 7.6, 0.22,
        "The root CA ranks third because its bar starts at Z: signatures fail after Z, they do not leak before it.",
        size=8.5, color=MUTED)

    # --- challenges and strategies -------------------------------------------
    cx = 8.62
    head(s, cx, 0.98, 4.3, "POTENTIAL CHALLENGES AND RISKS", color=RED)
    txt(s, cx, 1.30, 4.29, 0.20, "\u2192  STRATEGIES FOR OVERCOMING THESE CHALLENGES",
        size=9, color=GREEN, bold=True)
    ry = 1.58
    pairs = [
        ("Crypto hidden in config, reflection, stripped binaries",
         "Report the unresolved call site and the reason \u2014 never a guess"),
        ("Source key \u2260 keystore key \u2260 key on the wire",
         "Merge within one surface; across surfaces only on a certificate / SPKI hash"),
        ("Purpose, criticality and data lifetime are not scannable",
         "Declared against a cited source row, or Unknown \u2014 never inferred"),
        ("The arrival date Z is genuinely contested",
         "Three cited scenarios; we print the dates at which the ranking flips"),
        ("The inventory is itself a sensitive asset",
         "On-prem, no egress, RBAC, audit log, no key material ever stored"),
    ]
    for risk, fix in pairs:
        rect(s, cx, ry, 4.29, 0.88, fill=PANEL, radius=0.09)
        txt(s, cx + 0.18, ry + 0.10, 3.95, 0.34, risk, size=8.5, color=INK, bold=True, spacing=1.05)
        txt(s, cx + 0.18, ry + 0.45, 3.95, 0.36,
            [[("\u2192  ", {"color": GREEN, "bold": True}), (fix, {"color": MUTED})]],
            size=8.5, spacing=1.05)
        ry += 0.98


# =============================================================================
# SLIDE 5 -- IMPACT AND BENEFITS
# =============================================================================
def slide5(s):
    clear(s)
    subtitle(s, "Who it serves  ·  what they gain  ·  how progress becomes visible")

    y = head(s, LEFT_X, 0.98, 6.3, "POTENTIAL IMPACT ON THE TARGET AUDIENCE")
    rect(s, LEFT_X, y, 6.35, 0.46, fill=BLUE_BG, radius=0.10)
    txt(s, LEFT_X + 0.18, y + 0.12, 6.05, 0.30,
        "CISOs  \u00b7  PKI and crypto teams  \u00b7  Indian CII operators (power, telecom, BFSI, government)  \u00b7  "
        "banks and public-sector IT", size=8.5, color=INK)

    ry = y + 0.58
    for label, col, value in [
        ("Security", RED, "Separates what migration can still protect from what it can no longer help"),
        ("Operational", BLUE, "Analysts see the evidence and its status \u2014 not a verdict from a black box"),
        ("Economic", GREEN, "Effort follows the shortest savable window, not the biggest key"),
        ("Governance", MAROON, "A CycloneDX 1.6 CBOM plus a replayable record, for audit and for suppliers"),
    ]:
        dot(s, LEFT_X + 0.02, ry + 0.055, 0.095, col)
        txt(s, LEFT_X + 0.20, ry, 1.38, 0.22, label, size=9.5, color=INK, bold=True)
        txt(s, LEFT_X + 1.58, ry, 4.64, 0.34, value, size=9.5, color=MUTED, spacing=1.08)
        ry += 0.365

    rect(s, LEFT_X, ry + 0.04, 6.35, 0.52, fill=PANEL, radius=0.08)
    txt(s, LEFT_X + 0.18, ry + 0.11, 6.00, 0.42,
        "The DST PQC Task Force report (Feb 2026) records an expectation of a CII cryptographic "
        "inventory by 2027. This is that inventory \u2014 with the evidence behind every entry.",
        size=8.5, color=INK, spacing=1.1)

    by = ry + 0.74
    head(s, LEFT_X, by, 6.3, "BENEFITS OF THE SOLUTION  (social, economic, governance)", color=GREEN)
    ry = by + 0.32
    for label, value in [
        ("No false assurance", "Blind spots are reported per surface \u2014 \u201c12 found\u201d never means \u201cwe are clean\u201d"),
        ("Right-sized migration", "Options follow cryptographic purpose; Unknown purpose \u2192 no recommendation"),
        ("Progress is visible", "Snapshots show new exposure, closed windows and certificate change"),
    ]:
        dot(s, LEFT_X + 0.02, ry + 0.055, 0.095, GREEN)
        txt(s, LEFT_X + 0.20, ry, 1.62, 0.22, label, size=9.5, color=INK, bold=True)
        txt(s, LEFT_X + 1.82, ry, 4.40, 0.34, value, size=9.5, color=MUTED, spacing=1.08)
        ry += 0.375

    # --- findings roll up into a migration programme --------------------------
    ry += 0.02
    stages = [("DISCOVERED", BLUE), ("EXPOSED", RED), ("PLANNED", AMBER), ("VERIFIED", GREEN)]
    subs = ["every artefact", "banded + dated", "owners \u00b7 blockers", "re-scan proves it"]
    sw, sgap = 1.49, 0.13
    for i, ((name, col), sub) in enumerate(zip(stages, subs)):
        sx = LEFT_X + i * (sw + sgap)
        rect(s, sx, ry, sw, 0.46, fill=PANEL, radius=0.12)
        txt(s, sx, ry + 0.07, sw, 0.20, name, size=8.5, color=col, bold=True, align=PP_ALIGN.CENTER)
        txt(s, sx, ry + 0.25, sw, 0.18, sub, size=7, color=FAINT, align=PP_ALIGN.CENTER)
        if i < 3:
            txt(s, sx + sw, ry + 0.11, sgap, 0.20, "\u203a", size=10, color=FAINT,
                align=PP_ALIGN.CENTER)

    # --- prototype image ------------------------------------------------------
    cx = 6.85
    head(s, cx, 0.98, 6.06, "THE CLOSURE QUEUE  \u2014  EVERY UNKNOWN BECOMES ONE TASK", color=AMBER)
    picture(s, "card_closure.png", cx, 1.30, 6.06)
    txt(s, cx, 5.16, 6.06, 0.60,
        "An UNBOUNDED row is never a dead end. Pram\u0101\u1e47a names the single smallest thing that "
        "would settle it, what the answer could turn out to be, and how many days are at stake.",
        size=8.5, color=MUTED, spacing=1.1)

    rect(s, LEFT_X, 6.06, FULL_W, 0.60, fill=INK, radius=0.07)
    txt(s, LEFT_X, 6.22, FULL_W, 0.30,
        [[("FROM  \u201cWHERE IS OUR CRYPTOGRAPHY?\u201d", {"color": WHITE}),
          ("      TO      ", {"color": RGBColor(0x7C, 0x93, 0xA3)}),
          ("\u201cWHAT IS STILL SAVABLE \u2014 AND WHAT EVIDENCE SAYS SO?\u201d", {"color": WHITE})]],
        size=12.5, bold=True, font=TNR, align=PP_ALIGN.CENTER)


# =============================================================================
# SLIDE 6 -- RESEARCH AND REFERENCES
# =============================================================================
def slide6(s):
    clear(s)

    head(s, LEFT_X, 0.98, 8.0, "DETAILS / LINKS OF THE REFERENCE AND RESEARCH WORK")
    refs = [
        ("1", "Smart India Hackathon 2026 \u2014 PS SIH26164 (NTRO)",
         "Enterprise Cryptographic Discovery & Analysis Tool: discovery, quantum risk, PQC recommendation, CBOM.",
         "sih.gov.in"),
        ("2", "NIST FIPS 203 / 204 / 205  \u00b7  NIST IR 8547 (ipd)",
         "ML-KEM, ML-DSA, SLH-DSA; the draft RSA/ECC transition timeline \u2014 used only as a planning scenario.",
         "csrc.nist.gov/projects/post-quantum-cryptography"),
        ("3", "M. Mosca, IEEE Security & Privacy, 2018",
         "\u201cCybersecurity in an Era with Quantum Computers: Will We Be Ready?\u201d \u2014 the X + Y > Z framework we extend.",
         "doi.org/10.1109/MSP.2018.3761723"),
        ("4", "Global Risk Institute \u2014 Quantum Threat Timeline 2024  \u00b7  Gidney, arXiv:2505.15917",
         "Expert CRQC-arrival estimates and an RSA-2048 resource estimate \u2014 the basis for the three Z scenarios.",
         "globalriskinstitute.org  \u00b7  arxiv.org/abs/2505.15917"),
        ("5", "CycloneDX CBOM  \u00b7  ECMA-424",
         "The standard model for cryptographic assets: cryptoProperties, confidence, detection context.",
         "cyclonedx.org/capabilities/cbom"),
        ("6", "NIST NCCoE SP 1800-38 (preliminary draft)  \u00b7  NIST CSWP 39 (final)",
         "Vol B cryptographic discovery; Vol C interoperability and performance testing. CSWP 39 defines "
         "crypto agility as replacing cryptography across protocols, software, hardware and firmware "
         "while preserving operations.",
         "nccoe.nist.gov  \u00b7  csrc.nist.gov/pubs/cswp/39"),
    ]
    ry = 1.34
    for i, (n, title, desc, link) in enumerate(refs):
        col = i % 2
        rx = LEFT_X + col * 6.32
        yy = ry + (i // 2) * 1.12
        rect(s, rx, yy, 6.17, 0.98, fill=PANEL, radius=0.08)
        dot(s, rx + 0.16, yy + 0.15, 0.26, BLUE)
        txt(s, rx + 0.16, yy + 0.18, 0.26, 0.20, n, size=8.5, color=WHITE, bold=True,
            align=PP_ALIGN.CENTER)
        txt(s, rx + 0.52, yy + 0.13, 5.50, 0.22, title, size=9, color=INK, bold=True)
        txt(s, rx + 0.52, yy + 0.36, 5.50, 0.34, desc, size=8, color=MUTED, spacing=1.08)
        txt(s, rx + 0.52, yy + 0.73, 5.50, 0.20, link, size=7.5, color=BLUE)

    ty = 4.84
    head(s, LEFT_X, ty, 6.0, "TOOLING AND PRIOR ART", color=GREEN)
    txt(s, LEFT_X + 0.02, ty + 0.32, 6.10, 0.50,
        "Semgrep  \u00b7  Trivy  \u00b7  sslyze  \u00b7  cbomkit-theia  \u00b7  OpenSC pkcs11-tool + SoftHSM2  \u00b7  "
        "YARA + readelf  \u00b7  OpenSSL 3\n"
        "CBOMkit inventories source and images and is free \u2014 we run it as a sensor and add the ledger on top.",
        size=8.5, color=MUTED, spacing=1.15)

    head(s, 6.95, ty, 6.0, "STATUS DISCIPLINE", color=AMBER)
    txt(s, 6.97, ty + 0.32, 5.95, 0.60,
        "Final: FIPS 203 / 204 / 205, NIST CSWP 39.   Not final: FIPS 206 (FN-DSA), HQC, NIST IR 8547,\n"
        "SP 1800-38 (preliminary draft).   No Q-Day date is asserted \u2014 Z is always a cited scenario,\n"
        "and three are carried. Every tool claim is re-tested against pinned versions and recorded.",
        size=8.5, color=MUTED, spacing=1.15)

    rect(s, LEFT_X, 6.10, FULL_W, 0.62, fill=BLUE_BG, radius=0.07)
    txt(s, LEFT_X + 0.22, 6.20, FULL_W - 0.44, 0.44,
        [[("Positioning.  ", {"bold": True, "color": INK}),
          ("Existing tools discover cryptographic evidence. Pram\u0101\u1e47a turns that evidence into a dated, "
           "replayable exposure decision \u2014 and names exactly what it could not see.", {"color": INK})]],
        size=10, spacing=1.1)


def main():
    DST.parent.mkdir(exist_ok=True)
    prs = Presentation(str(SRC))
    slide2(prs.slides[1])
    slide3(prs.slides[2])
    slide4(prs.slides[3])
    slide5(prs.slides[4])
    slide6(prs.slides[5])
    prs.save(str(DST))
    print("saved", DST)


if __name__ == "__main__":
    main()
