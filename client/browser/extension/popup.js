const $ = id => document.getElementById(id);
// DOM built with textContent only: nothing from the proxy's status page is ever parsed as HTML
function el(tag, props, ...kids) {
  const e = document.createElement(tag);
  if (props) for (const k of Object.keys(props)) { if (k === 'class') e.className = props[k]; else e[k] = props[k]; }
  for (const k of kids) e.append(k);
  return e;
}
function table(rows) {
  return el('table', null, ...rows.map(r => el('tr', null, ...r)));
}

function bytes(n) { return n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : (n / 1048576).toFixed(1) + ' MB'; }

async function render() {
  const s = await chrome.runtime.sendMessage({ type: 'state' });
  const snap = s.status && s.status.snapshot;
  const connected = !!(snap && snap.state === 'connected');
  $('dot').className = 'dot ' + (connected ? 'ok' : s.running ? 'mid' : '');
  $('title').textContent = connected ? 'Connected to the mesh' : s.running ? 'Starting (' + (snap.state || '?') + ')' : 'Proxy not running';
  $('sub').textContent = snap && snap.community ? snap.community + ' · ' + snap.ip + '/' + snap.prefix : '';
  $('enabled').checked = !!s.config.enabled;

  const warn = $('warn');
  warn.hidden = true;
  if (s.control && s.control !== 'controlled_by_this_extension' && s.control !== 'controllable_by_this_extension' && s.config.enabled) {
    warn.hidden = false;
    warn.textContent = 'Another extension or a policy controls the proxy settings of the browser (' + s.control.replace(/_/g, ' ') + '): the mesh addresses will not use the oneq proxy.';
  } else if (!s.running && s.native && s.native.available === false) {
    warn.hidden = false;
    warn.replaceChildren('The oneq connection manager is not installed. Install the oneq client and run', el('br'), el('code', null, 'oneqclient native-host install'),
      el('br'), 'or start the proxy yourself:', el('br'), el('code', null, 'oneqclient proxy --relay https://… --community … --user … --password-file …'));
  } else if (!s.running && s.native && s.native.data && !s.native.data.complete) {
    warn.hidden = false;
    warn.textContent = 'Not set up yet: open Settings below and enter the relay, community, user and password.';
  } else if (!s.running && s.native && s.native.data && s.native.data.complete) {
    warn.hidden = false;
    const why = s.native.startError || (s.native.data.running ? '' : s.native.data.log) || '';
    warn.textContent = s.native.data.running ? 'Connecting to the mesh…' : 'Not connected.' + (why ? ' ' + why : '');
  } else if (!s.running) {
    warn.hidden = false;
    warn.replaceChildren('Start the proxy on this computer:', el('br'), el('code', null, 'oneqclient proxy --relay https://… --community … --user … --password-file …'));
  } else if (snap && snap.message) {
    warn.hidden = false;
    warn.textContent = snap.message;
  }

  // connect / disconnect through the connection manager (only when it manages the proxy)
  const btn = $('connbtn');
  const d = s.native && s.native.data;
  btn.hidden = true;
  if (d && d.complete && (d.running || !s.running)) {
    btn.hidden = false;
    btn.textContent = d.running ? 'Disconnect' : 'Connect';
    btn.onclick = async () => { btn.disabled = true; await chrome.runtime.sendMessage({ type: d.running ? 'native-stop' : 'native-start' }); btn.disabled = false; render(); };
  } else if (d && !d.complete) {
    btn.hidden = false;
    btn.textContent = 'Set up connection…';
    btn.onclick = () => chrome.runtime.openOptionsPage();
  }

  const info = $('info');
  info.replaceChildren();
  if (s.running) {
    const pr = s.status.proxy;
    const rows = [['Proxy', pr.socks + (pr.restricted === true ? ' · browsers only' : pr.restricted === false ? ' · any local program' : '')], ['Mesh', pr.subnet],
      ['NAT', (snap.nat_type || '-') + (snap.nat_public ? ' · ' + snap.nat_public : '')],
      ['Relay', snap.relay_connected ? 'connected' : 'down'], ['Traffic', '↑ ' + bytes(snap.tx_bytes) + '  ↓ ' + bytes(snap.rx_bytes)]];
    info.append(table(rows.map(r => [el('td', { class: 'k' }, r[0]), el('td', null, String(r[1]))])));
  }
  const m = $('members');
  m.replaceChildren();
  const peers = (snap && snap.peers) || [];
  if (peers.length) {
    m.append(table(peers.map(p => [el('td', null, String(p.name) + ' ', el('span', { class: 'muted' }, String(p.ip))),
      el('td', null, p.session ? String(p.path) : p.online ? 'connecting' : 'offline')])));
  }
  const first = peers.find(p => p.session);
  const hint = $('hint');
  hint.replaceChildren();
  if (s.running) {
    hint.append('Open mesh hosts by address (', el('code', null, 'http://' + (first ? first.ip : '10.x.y.z') + '/'), ') or by name (', el('code', null, 'http://name.oneq/'), ').');
  }
}

$('enabled').addEventListener('change', async e => {
  await chrome.runtime.sendMessage({ type: 'set', values: { enabled: e.target.checked } });
  render();
});
$('opts').addEventListener('click', e => { e.preventDefault(); chrome.runtime.openOptionsPage(); });
render();
setInterval(render, 3000);
