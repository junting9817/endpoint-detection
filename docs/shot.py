#!/usr/bin/env python3
"""Screenshot site/index.html for the README. Runs inside a Playwright container (docs/screenshot.sh)."""
import os

from playwright.sync_api import sync_playwright

TOP = int(os.environ.get("TOP", "0"))
WIDTH = int(os.environ.get("WIDTH", "1280"))

with sync_playwright() as pw:
    browser = pw.chromium.launch()
    page = browser.new_page(viewport={"width": WIDTH, "height": 900}, device_scale_factor=2)
    page.goto("file:///site/index.html", wait_until="load")
    page.wait_for_timeout(3000)  # the web fonts arrive after load; without this the shot uses fallbacks
    if TOP:
        page.screenshot(path="/out/page.png", clip={"x": 0, "y": 0, "width": WIDTH, "height": TOP})
    else:
        page.screenshot(path="/out/page.png", full_page=True)
    browser.close()
print("captured")
