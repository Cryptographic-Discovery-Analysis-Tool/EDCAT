"""Capture dashboard screenshots for the SIH deck."""
import pathlib
from playwright.sync_api import sync_playwright

OUT = pathlib.Path(__file__).parent / "shots"
OUT.mkdir(exist_ok=True)
URL = "http://localhost:8000"

with sync_playwright() as pw:
    b = pw.chromium.launch(channel="msedge")
    pg = b.new_page(viewport={"width": 1600, "height": 1040}, device_scale_factor=2)
    pg.goto(URL, wait_until="networkidle")
    pg.wait_for_selector("table tbody tr", timeout=30000)
    pg.wait_for_timeout(1200)

    pg.screenshot(path=str(OUT / "ledger_full.png"))
    print("ledger ok")

    # evidence drawer
    pg.click("table tbody tr")
    pg.wait_for_timeout(2000)
    pg.screenshot(path=str(OUT / "evidence_full.png"))
    print("evidence ok")

    # try to capture the drawer element alone
    for sel in ["aside:nth-of-type(2)", ".drawer", ".evidence", "main + *", "div.app > *:last-child"]:
        try:
            el = pg.query_selector(sel)
            if el:
                box = el.bounding_box()
                if box and box["width"] > 300:
                    el.screenshot(path=str(OUT / "evidence_panel.png"))
                    print("panel via", sel, box)
                    break
        except Exception as e:
            print("sel fail", sel, e)

    # close the drawer, go to closure queue
    try:
        pg.click("text=CLOSE", timeout=3000)
    except Exception:
        pg.keyboard.press("Escape")
    pg.wait_for_timeout(800)
    pg.click("button:has-text('Closure queue')")
    pg.wait_for_timeout(1500)
    pg.screenshot(path=str(OUT / "closure_full.png"))
    print("closure ok")

    # move-to tab, for reference
    pg.click("button:has-text('Move to')")
    pg.wait_for_timeout(1500)
    pg.screenshot(path=str(OUT / "moveto_full.png"))

    # coverage tab
    pg.click("button:has-text('Coverage')")
    pg.wait_for_timeout(1500)
    pg.screenshot(path=str(OUT / "coverage_full.png"))
    print("all ok")
    b.close()
