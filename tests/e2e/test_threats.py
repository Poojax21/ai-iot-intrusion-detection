import json
import time
from playwright.sync_api import sync_playwright

def test_threat_vectors():
    with sync_playwright() as p:
        browser = p.chromium.launch(channel='msedge', headless=True)
        context = browser.new_context(viewport={'width': 1400, 'height': 900})
        page = context.new_page()

        print("Navigating to http://127.0.0.1:4173...", flush=True)
        page.goto('http://127.0.0.1:4173')
        time.sleep(2)

        # Ensure bootstrap has completed
        page.wait_for_function("() => window.S && window.S.devs && window.S.devs.length > 0", timeout=15000)
        
        # Click Threat Vectors tab
        print("Switching to Threat Vectors tab...", flush=True)
        threats_tab = page.query_selector('nav button[data-id="threats"]')
        if threats_tab:
            threats_tab.click()
        else:
            page.evaluate("location.hash = '#threats'")

        time.sleep(2)

        # Inspect the rendered cards and telemetry
        info = page.evaluate("""() => {
            const container = document.getElementById('threat-cards-container');
            const summaryTotal = document.getElementById('threat-total-summary-count');
            const fpsEl = document.getElementById('fps');
            const cards = container ? Array.from(container.querySelectorAll('.threat-card')) : [];
            
            const cardData = cards.map(c => {
                const title = c.querySelector('h3 span')?.textContent?.trim();
                const mitre = c.querySelector('.pill')?.textContent?.trim();
                const totalDetections = c.querySelector('b')?.textContent?.trim();
                const targetItems = Array.from(c.querySelectorAll('.threat-target-item')).map(t => t.textContent.trim().replace(/\\s+/g, ' '));
                return {
                    title,
                    mitre,
                    totalDetections,
                    targetsCount: targetItems.length,
                    targets: targetItems
                };
            });

            return {
                summaryTotal: summaryTotal ? summaryTotal.textContent.trim() : null,
                fps: fpsEl ? fpsEl.textContent.trim() : null,
                cardsCount: cards.length,
                cards: cardData
            };
        }""")

        print("Threat Vector Analysis Status:")
        print(json.dumps(info, indent=2))

        # Take screenshot of the Threat Vectors view
        screenshot_path = "tests/threat_vectors_screenshot.png"
        page.screenshot(path=screenshot_path, full_page=False)
        print(f"Screenshot saved to {screenshot_path}", flush=True)

        browser.close()

if __name__ == '__main__':
    test_threat_vectors()
