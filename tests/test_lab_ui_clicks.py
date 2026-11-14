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
    ws.send(json.dumps({'id': 2, 'method': 'Page.enable'}))
    
    # Reload page and wait for bootstrap
    ws.send(json.dumps({'id': 3, 'method': 'Page.reload'}))
    time.sleep(1)

    def eval_expr(expr, req_id):
        ws.send(json.dumps({
            'id': req_id,
            'method': 'Runtime.evaluate',
            'params': {'expression': expr, 'returnByValue': True}
        }))
        t0 = time.time()
        while time.time() - t0 < 3:
            try:
                raw = ws.recv()
                m = json.loads(raw)
                if m.get('id') == req_id:
                    res = m.get('result', {})
                    if 'exceptionDetails' in res:
                        print("EXPR ERROR:", res['exceptionDetails'])
                    return res.get('result', {}).get('value')
            except Exception as e:
                print("recv error:", e)
                break
        return None

    # Wait for S and simTargets to load
    for _ in range(20):
        cnt = eval_expr("typeof S !== 'undefined' && S.simTargets ? S.simTargets.length : 0", 999)
        if cnt and cnt > 0:
            print(f"Page loaded: {cnt} targets ready")
            break
        time.sleep(0.3)

    # Step 1: Switch to lab tab
    s1 = eval_expr("""(function(){
        const labBtn = document.querySelector('nav button[data-id="lab"]');
        if (labBtn) labBtn.click();
        return {
            currentTab: document.querySelector('.tab.on')?.id,
            devCards: document.querySelectorAll('#sim-device-list .sim-pick-card').length,
            atkCards: document.querySelectorAll('#sim-attack-list .sim-pick-card').length,
            legitCards: document.querySelectorAll('#sim-legit-list .sim-pick-card').length,
            selectedTargets: Array.from(S.selectedSimTargets),
            selectedAttacks: Array.from(S.selectedAttacks),
            selectedLegit: Array.from(S.selectedLegit),
            targetBadge: document.getElementById('sim-active-target-badge')?.textContent,
            summary: document.getElementById('sim-workers-summary')?.textContent
        };
    })()""", 10)
    print("STEP 1 - INITIAL LAB TAB STATE:")
    print(json.dumps(s1, indent=2))

    # Step 2: Click on 2nd device card, 2nd attack card, 3rd legit card
    s2 = eval_expr("""(function(){
        const devCards = document.querySelectorAll('#sim-device-list .sim-pick-card');
        if (devCards.length > 1) devCards[1].click();

        const atkCards = document.querySelectorAll('#sim-attack-list .sim-pick-card');
        if (atkCards.length > 1) atkCards[1].click();

        const legitCards = document.querySelectorAll('#sim-legit-list .sim-pick-card');
        if (legitCards.length > 2) legitCards[2].click();

        return {
            selectedTargets: Array.from(S.selectedSimTargets),
            selectedAttacks: Array.from(S.selectedAttacks),
            selectedLegit: Array.from(S.selectedLegit),
            summary: document.getElementById('sim-workers-summary')?.textContent,
            targetBadge: document.getElementById('sim-active-target-badge')?.textContent
        };
    })()""", 20)
    print("\nSTEP 2 - AFTER CLICKING 2ND DEVICE, 2ND ATTACK, 3RD LEGIT:")
    print(json.dumps(s2, indent=2))

    # Step 3: Deselect by clicking the same cards again
    s3 = eval_expr("""(function(){
        const devCards = document.querySelectorAll('#sim-device-list .sim-pick-card');
        if (devCards.length > 1) devCards[1].click();

        const atkCards = document.querySelectorAll('#sim-attack-list .sim-pick-card');
        if (atkCards.length > 1) atkCards[1].click();

        return {
            selectedTargets: Array.from(S.selectedSimTargets),
            selectedAttacks: Array.from(S.selectedAttacks),
            selectedLegit: Array.from(S.selectedLegit),
            summary: document.getElementById('sim-workers-summary')?.textContent
        };
    })()""", 30)
    print("\nSTEP 3 - AFTER CLICKING AGAIN TO DESELECT:")
    print(json.dumps(s3, indent=2))

    # Step 4: All / Clear buttons
    s4 = eval_expr("""(function(){
        selectAllDevices(true);
        selectAllAttacks(true);
        selectAllLegit(true);
        const allSummary = document.getElementById('sim-workers-summary')?.textContent;

        selectAllAttacks(false);
        selectAllLegit(false);
        const clearSummary = document.getElementById('sim-workers-summary')?.textContent;

        return {
            allSummary,
            clearSummary,
            selectedTargetsCount: S.selectedSimTargets.size,
            selectedAttacksCount: S.selectedAttacks.size,
            selectedLegitCount: S.selectedLegit.size
        };
    })()""", 40)
    print("\nSTEP 4 - ALL / CLEAR TEST:")
    print(json.dumps(s4, indent=2))

    # Step 5: Test switching to other tabs and back to lab
    s5 = eval_expr("""(function(){
        const tabs = ['overview', 'network', 'alerts', 'devices', 'lab'];
        const log = [];
        for (const t of tabs) {
            const btn = document.querySelector(`nav button[data-id="${t}"]`);
            if (btn) {
                btn.click();
                const active = document.querySelector('.tab.on')?.id;
                log.push({ requested: t, active: active, matched: active === t });
            }
        }
        return log;
    })()""", 50)
    print("\nSTEP 5 - TAB SWITCHING TEST:")
    print(json.dumps(s5, indent=2))

    ws.close()
finally:
    proc.terminate()
