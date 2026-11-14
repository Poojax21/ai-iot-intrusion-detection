import subprocess, time, json, urllib.request, websocket

edge_path = r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
user_data = r'C:\Users\Hi\AppData\Local\Temp\edge_test_profile'
proc = subprocess.Popen([edge_path, '--headless', f'--user-data-dir={user_data}', '--remote-debugging-port=9222', 'http://127.0.0.1:4173'])
time.sleep(2)

try:
    with urllib.request.urlopen('http://127.0.0.1:9222/json') as r:
        tabs = json.loads(r.read())
    target = [t for t in tabs if '4173' in t.get('url', '')][0]
    ws = websocket.create_connection(target['webSocketDebuggerUrl'])
    ws.send(json.dumps({'id': 1, 'method': 'Runtime.enable'}))

    # Wait for S and alerts
    for _ in range(20):
        ws.send(json.dumps({
            'id': 99,
            'method': 'Runtime.evaluate',
            'params': {'expression': "typeof S !== 'undefined' && S.alerts ? S.alerts.length : 0", 'returnByValue': True}
        }))
        m = json.loads(ws.recv())
        val = m.get('result', {}).get('result', {}).get('value')
        if val and val > 0:
            print("Alerts loaded in client:", val)
            break
        time.sleep(0.3)

    def send_and_recv(req_id, expr):
        ws.send(json.dumps({
            'id': req_id,
            'method': 'Runtime.evaluate',
            'params': {'expression': expr, 'returnByValue': True}
        }))
        t0 = time.time()
        while time.time() - t0 < 3:
            raw = ws.recv()
            m = json.loads(raw)
            if m.get('id') == req_id:
                return m.get('result', {}).get('result', {}).get('value')
        return None

    # Click explainability tab and wait 0.5s for async render
    send_and_recv(10, """(function(){
        const btn = document.querySelector('nav button[data-id="explainability"]');
        if (btn) btn.click();
        return true;
    })()""")
    time.sleep(0.5)

    res15 = send_and_recv(15, """(function(){
        const box = document.getElementById('explain-detail-box');
        return {
            currentTab: document.querySelector('.tab.on')?.id,
            selectCount: document.getElementById('explain-alert-select')?.options.length,
            selectedAlertId: document.getElementById('explain-alert-select')?.value,
            detailBoxTextSnippet: box?.textContent?.trim()?.slice(0, 150),
            hasEquation: box?.innerHTML?.includes('TreeSHAP Equation'),
            hasWaterfall: box?.innerHTML?.includes('Shapley Value Feature Contributions'),
            hasFeatureTable: box?.innerHTML?.includes('Exact Feature Vector')
        };
    })()""")
    print("AI EXPLAINABILITY TAB TEST RESULT:")
    print(json.dumps(res15, indent=2))

    # Test clicking Inspect TreeSHAP button
    res20 = send_and_recv(20, """(function(){
        const btn = document.getElementById('explain-btn');
        if (btn) btn.click();
        const drawerOpen = document.getElementById('dr')?.classList.contains('open');
        const box = document.getElementById('explain-detail-box');
        return {
            drawerOpen,
            boxHasContent: box?.innerHTML?.length > 100
        };
    })()""")
    print("\nINSPECT TREESHAP BUTTON CLICK TEST:")
    print(json.dumps(res20, indent=2))

    ws.close()
finally:
    proc.terminate()
