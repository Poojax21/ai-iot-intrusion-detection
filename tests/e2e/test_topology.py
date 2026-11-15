import json
import time
import sys
from playwright.sync_api import sync_playwright

def test_topology():
    with sync_playwright() as p:
        browser = p.chromium.launch(channel='msedge', headless=True)
        context = browser.new_context(viewport={'width': 1400, 'height': 900})
        page = context.new_page()
        
        print("Navigating to http://127.0.0.1:4173...", flush=True)
        page.goto('http://127.0.0.1:4173')
        
        # Wait for S.devs to have 106 items
        print("Waiting for S.devs to populate...", flush=True)
        page.wait_for_function("() => window.S && window.S.devs && window.S.devs.length >= 100", timeout=15000)
        dev_count = page.evaluate("() => window.S.devs.length")
        print(f"Loaded {dev_count} devices into state S.devs.", flush=True)

        # Click Topology Map tab
        print("Switching to Topology Map tab...", flush=True)
        topo_tab = page.query_selector('nav button[data-id="topology"]')
        if topo_tab:
            topo_tab.click()
        else:
            page.evaluate("location.hash = '#topology'")
            
        # Give simulation time to run ticks
        time.sleep(2)
        
        # Check canvas and container dimensions and node positions
        info = page.evaluate("""() => {
            const wrap = document.getElementById('topo-canvas-wrap');
            const cv = document.getElementById('cv');
            const rect = cv.getBoundingClientRect();
            const nodes = cv._nodes || [];
            
            const gw = nodes.find(n => n.isGateway);
            const otherNodes = nodes.filter(n => !n.isGateway);
            
            let minX = 999999, maxX = -999999, minY = 999999, maxY = -999999;
            for (const n of nodes) {
                if (n.x < minX) minX = n.x;
                if (n.x > maxX) maxX = n.x;
                if (n.y < minY) minY = n.y;
                if (n.y > maxY) maxY = n.y;
            }
            
            return {
                wrapWidth: wrap ? wrap.clientWidth : null,
                wrapHeight: wrap ? wrap.clientHeight : null,
                canvasWidth: cv.width,
                canvasHeight: cv.height,
                rectWidth: rect.width,
                rectHeight: rect.height,
                totalNodes: nodes.length,
                gateway: gw ? { x: Math.round(gw.x), y: Math.round(gw.y) } : null,
                bounds: {
                    minX: Math.round(minX),
                    maxX: Math.round(maxX),
                    minY: Math.round(minY),
                    maxY: Math.round(maxY),
                    spanX: Math.round(maxX - minX),
                    spanY: Math.round(maxY - minY)
                },
                renderedBadge: document.getElementById('topo-rendered-count-badge') ? document.getElementById('topo-rendered-count-badge').textContent : null,
                zoomBadge: document.getElementById('topo-zoom-badge') ? document.getElementById('topo-zoom-badge').textContent : null
            };
        }""")
        
        print("Topology info:", flush=True)
        print(json.dumps(info, indent=2), flush=True)
        
        # Test Zoom In button
        btn_zoom_in = page.query_selector('#topo-btn-zin')
        if btn_zoom_in:
            print("Clicking Zoom In...", flush=True)
            btn_zoom_in.click()
            time.sleep(0.5)
            zoom_after_in = page.evaluate("() => document.getElementById('topo-zoom-badge').textContent")
            print("Zoom after zoom in:", zoom_after_in, flush=True)
            
        # Test Zoom Out button
        btn_zoom_out = page.query_selector('#topo-btn-zout')
        if btn_zoom_out:
            print("Clicking Zoom Out...", flush=True)
            btn_zoom_out.click()
            time.sleep(0.5)
            zoom_after_out = page.evaluate("() => document.getElementById('topo-zoom-badge').textContent")
            print("Zoom after zoom out:", zoom_after_out, flush=True)

        # Test Center View button
        btn_reset = page.query_selector('#topo-btn-reset')
        if btn_reset:
            print("Clicking Center View...", flush=True)
            btn_reset.click()
            time.sleep(0.5)
            zoom_after_reset = page.evaluate("() => document.getElementById('topo-zoom-badge').textContent")
            print("Zoom after reset:", zoom_after_reset, flush=True)

        # Test Hover over node to see tooltip
        hover_result = page.evaluate("""() => {
            const cv = document.getElementById('cv');
            const nodes = cv._nodes || [];
            const target = nodes.find(n => !n.isGateway);
            if (!target) return null;
            
            const rect = cv.getBoundingClientRect();
            const evt = new MouseEvent('mousemove', {
                clientX: rect.left + target.x,
                clientY: rect.top + target.y,
                bubbles: true
            });
            cv.dispatchEvent(evt);
            
            const tip = document.getElementById('tip');
            return {
                targetName: target.name,
                tipDisplay: tip ? tip.style.display : null,
                tipContent: tip ? tip.textContent : null
            };
        }""")
        print("Hover test:", hover_result, flush=True)

        # Save screenshot
        screenshot_path = "tests/topology_screenshot.png"
        page.screenshot(path=screenshot_path, full_page=False)
        print(f"Screenshot saved to {screenshot_path}", flush=True)

        browser.close()

if __name__ == '__main__':
    test_topology()
