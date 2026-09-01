"""The self-contained dashboard page (no external resources)."""

DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>breachload dashboard</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin: 0; font: 14px/1.5 ui-monospace, Menlo, Consolas, monospace;
         background: #0d1117; color: #c9d1d9; }
  header { padding: 12px 18px; background: #161b22; border-bottom: 1px solid #30363d;
           display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
  header h1 { font-size: 16px; margin: 0; color: #58a6ff; }
  #conn { font-size: 12px; padding: 2px 8px; border-radius: 10px; background: #30363d; }
  #conn.up { background: #196c2e; color: #fff; } #conn.down { background: #8b1a1a; color: #fff; }
  #phase { color: #bc8cff; } #flags { color: #3fb950; margin-left: auto; }
  main { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; padding: 12px; }
  @media (max-width: 850px) { main { grid-template-columns: 1fr; } }
  section { background: #161b22; border: 1px solid #30363d; border-radius: 8px; overflow: hidden; }
  section h2 { font-size: 13px; margin: 0; padding: 8px 12px; background: #21262d;
               border-bottom: 1px solid #30363d; text-transform: uppercase; letter-spacing: .5px; }
  .body { padding: 10px 12px; max-height: 70vh; overflow: auto; }
  #log div { white-space: pre-wrap; padding: 1px 0; border-bottom: 1px solid #21262d; }
  .tag { display: inline-block; min-width: 66px; text-align: right; margin-right: 8px; opacity: .9; }
  .run { color: #58a6ff; } .note { color: #3fb950; } .finding { color: #d29922; font-weight: bold; }
  .blocked, .error { color: #f85149; } .skipped { color: #d29922; } .phase { color: #bc8cff; }
  .flag { color: #3fb950; font-weight: bold; } .stopped { color: #f85149; font-weight: bold; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 3px 6px; border-bottom: 1px solid #21262d; font-size: 13px; }
  th { color: #8b949e; }
  .sev-critical { color: #f85149; font-weight: bold; } .sev-high { color: #ff7b72; }
  .sev-medium { color: #d29922; } .sev-low { color: #58a6ff; } .sev-info { color: #8b949e; }
  #confirm { position: fixed; inset: 0; background: rgba(0,0,0,.6); display: none;
             align-items: center; justify-content: center; }
  #confirm .box { background: #161b22; border: 1px solid #f85149; border-radius: 8px;
                  padding: 18px; max-width: 560px; }
  #confirm pre { white-space: pre-wrap; color: #e6edf3; }
  button { font: inherit; padding: 6px 14px; border-radius: 6px; border: 1px solid #30363d;
           cursor: pointer; margin-right: 8px; background: #21262d; color: #c9d1d9; }
  .approve { background: #196c2e; color: #fff; } .deny, #stop { background: #8b1a1a; color: #fff; }
</style>
</head>
<body>
<header>
  <h1>breachload</h1>
  <span id="conn" class="down">connecting...</span>
  <span id="phase"></span>
  <button id="stop">Stop engagement</button>
  <span id="flags"></span>
</header>
<main>
  <section><h2>Live stream</h2><div class="body" id="log"></div></section>
  <section>
    <h2>Hosts &amp; services</h2><div class="body" id="hosts"></div>
    <h2>Findings <span id="fcount" style="opacity:.7"></span>
      <span style="float:right;font-weight:normal">
        <label style="opacity:.7">show:
          <select id="sev-filter" style="background:#0d1117;color:#c9d1d9;
                                          border:1px solid #30363d;padding:2px 4px">
            <option value="all">all</option>
            <option value="confirmed">confirmed only</option>
            <option value="critical">critical+high</option>
          </select>
        </label>
      </span>
    </h2>
    <div class="body" id="findings"></div>
  </section>
</main>
<div id="confirm"><div class="box">
  <h2>Confirmation required</h2><pre id="confirm-text"></pre>
  <button class="approve" id="btn-approve">Approve</button>
  <button class="deny" id="btn-deny">Deny</button>
</div></div>
<script>
(function () {
  var log = document.getElementById('log');
  var conn = document.getElementById('conn');
  var confirmBox = document.getElementById('confirm');
  var pendingId = null, ws = null;

  function esc(s) { var d = document.createElement('div'); d.textContent = s == null ? '' : s; return d.innerHTML; }

  function line(event, message) {
    var d = document.createElement('div');
    var t = document.createElement('span');
    t.className = 'tag ' + event; t.textContent = event;
    d.appendChild(t); d.appendChild(document.createTextNode(message || ''));
    log.appendChild(d); log.scrollTop = log.scrollHeight;
  }

  function showConfirm(id, prompt) {
    pendingId = id;
    document.getElementById('confirm-text').textContent = prompt;
    confirmBox.style.display = 'flex';
  }
  function answer(approved) {
    if (pendingId && ws) ws.send(JSON.stringify({type: 'confirm', id: pendingId, approved: approved}));
    pendingId = null; confirmBox.style.display = 'none';
  }
  document.getElementById('btn-approve').onclick = function () { answer(true); };
  document.getElementById('btn-deny').onclick = function () { answer(false); };
  document.getElementById('stop').onclick = function () { fetch('/api/stop', {method: 'POST'}); };

  function renderState(s) {
    if (!s) return;
    window._lastState = s;   // cached so the sev-filter can re-render live
    document.getElementById('phase').textContent = s.phase ? 'phase: ' + s.phase : '';
    var flags = s.flags || [];
    document.getElementById('flags').textContent = flags.length ? ('flags: ' + flags.join('  ')) : '';

    var hosts = s.hosts || {};
    var rows = '<table><tr><th>Host</th><th>OS</th><th>Services</th></tr>';
    Object.keys(hosts).forEach(function (addr) {
      var h = hosts[addr]; var svcs = Object.values(h.services || {}).map(function (v) {
        return v.port + '/' + v.protocol + ' ' + (v.name || '?'); }).join(', ');
      rows += '<tr><td>' + esc(addr) + '</td><td>' + esc(h.os_guess || '?') + '</td><td>' + esc(svcs) + '</td></tr>';
    });
    document.getElementById('hosts').innerHTML = rows + '</table>';

    var fs = s.findings || [];
    var mode = document.getElementById('sev-filter').value;
    var shown = fs.filter(function (x) {
      if (mode === 'confirmed') return x.validation === 'confirmed';
      if (mode === 'critical') return x.severity === 'critical' || x.severity === 'high';
      return true;
    });
    var confirmed = fs.filter(function (x) { return x.validation === 'confirmed'; }).length;
    document.getElementById('fcount').textContent =
      '(' + confirmed + ' confirmed / ' + fs.length + ' total)';
    var f = '<table><tr><th>Sev</th><th>Status</th><th>Title</th><th>Host</th></tr>';
    shown.forEach(function (x) {
      var badge = x.validation === 'confirmed'
        ? '<span style="color:#3fb950">CONFIRMED</span>'
        : '<span style="opacity:.6">suspected</span>';
      f += '<tr><td class="sev-' + esc(x.severity) + '">' + esc(x.severity) + '</td>' +
           '<td>' + badge + '</td><td>' + esc(x.title) + '</td>' +
           '<td>' + esc(x.host || '') + '</td></tr>';
    });
    document.getElementById('findings').innerHTML = f + '</table>';
  }

  // Re-render on filter change so the user's choice takes effect immediately.
  document.addEventListener('change', function (e) {
    if (e.target && e.target.id === 'sev-filter' && window._lastState) {
      renderState(window._lastState);
    }
  });

  function connect() {
    var proto = location.protocol === 'https:' ? 'wss' : 'ws';
    ws = new WebSocket(proto + '://' + location.host + '/ws');
    ws.onopen = function () { conn.textContent = 'live'; conn.className = 'up'; };
    ws.onclose = function () { conn.textContent = 'disconnected'; conn.className = 'down';
                              setTimeout(connect, 2000); };
    ws.onmessage = function (ev) {
      var m = JSON.parse(ev.data);
      if (m.type === 'confirm') { showConfirm(m.id, m.prompt); }
      else if (m.type === 'state') { renderState(m.state); }
      else { line(m.event, m.message); }
    };
  }

  // Live state arrives over the WS; poll as a fallback if the socket is down.
  function refresh() { fetch('/api/state').then(function (r) { return r.json(); }).then(renderState).catch(function () {}); }
  connect(); refresh(); setInterval(function () { if (!ws || ws.readyState !== 1) refresh(); }, 3000);
})();
</script>
</body>
</html>
"""
