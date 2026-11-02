const $ = id => document.getElementById(id);
const DEFAULTS = { socks: '127.0.0.1:1080', status: '127.0.0.1:1081', extraNets: [] };

async function load() {
  const c = Object.assign({}, DEFAULTS, await chrome.storage.local.get(Object.keys(DEFAULTS)));
  $('socks').value = c.socks;
  $('status').value = c.status;
  $('extra').value = (c.extraNets || []).join('\n');
  await loadConnection();
}

// ---- Connection: the settings live in the oneq connection manager (native host), not in the extension
async function loadConnection() {
  const s = await chrome.runtime.sendMessage({ type: 'state' });
  const n = s && s.native;
  const note = $('hostnote');
  note.hidden = true;
  if (n && n.available === false) {
    note.hidden = false;
    note.replaceChildren('The oneq connection manager is not installed on this computer. Install the oneq client and run ', code('oneqclient native-host install'),
      ', then reload this page. (You can still start ', code('oneqclient proxy'), ' yourself.)');
  }
  const d = n && n.data;
  if (d) {
    $('relays').value = (d.config.relays || []).join('\n');
    $('community').value = d.config.community || '';
    $('user').value = d.config.user || '';
    $('name').value = d.config.name || '';
    $('ca').placeholder = d.config.ca_set ? '(a certificate is stored; paste another to replace it)' : '-----BEGIN CERTIFICATE-----';
    $('pwnote').textContent = d.has_password ? '(stored; leave empty to keep it)' : '';
  }
}

function code(t) {
  const e = document.createElement('code');
  e.textContent = t;
  return e;
}

$('connect').addEventListener('click', async () => {
  const msg = $('connmsg');
  msg.textContent = 'Connecting…';
  const config = {
    relays: $('relays').value.split(/\s+/).filter(Boolean),
    community: $('community').value.trim(),
    user: $('user').value.trim(),
    name: $('name').value.trim(),
  };
  const ca = $('ca').value.trim();
  if (ca) config.ca_pem = ca;
  const pw = $('password').value;
  const r = await chrome.runtime.sendMessage({ type: 'native-set', config, password: pw || undefined });
  $('password').value = '';
  if (!r || !r.ok) {
    msg.textContent = (r && r.error) || 'The connection manager did not answer.';
    return;
  }
  msg.textContent = r.running ? 'Saved. The proxy is starting; open the popup to see the connection.' : 'Saved.' + (r.complete ? '' : ' (a password is still needed)');
  await loadConnection();
});

// A settings file as exported by the oneq apps: {"format":"oneq-settings","version":1,"settings":{relays,community,user,name,ca_pem},"password":"…"}
$('importbtn').addEventListener('click', () => $('importfile').click());
$('importfile').addEventListener('change', async e => {
  const f = e.target.files && e.target.files[0];
  e.target.value = '';
  if (!f) return;
  const msg = $('connmsg');
  try {
    const j = JSON.parse(await f.text());
    if (j.format !== 'oneq-settings' || j.version !== 1 || !j.settings) throw new Error('This is not a oneq settings file.');
    const s = j.settings;
    $('relays').value = (s.relays || []).join('\n');
    $('community').value = s.community || '';
    $('user').value = s.user || '';
    $('name').value = s.name || '';
    $('ca').value = s.ca_pem || '';
    if (typeof j.password === 'string' && j.password) $('password').value = j.password;
    msg.textContent = 'Imported. Check the fields and press "Save and connect".' + (j.password ? '' : ' Type the password.');
  } catch (err) {
    msg.textContent = err.message || String(err);
  }
});

$('save').addEventListener('click', async () => {
  try {
    const socks = $('socks').value.trim();
    const status = $('status').value.trim();
    if (!OneqPac.socksTarget(socks)) throw new Error('The proxy address must be 127.x.x.x:PORT or localhost:PORT.');
    if (!OneqPac.socksTarget(status)) throw new Error('The status address must be 127.x.x.x:PORT or localhost:PORT.');
    const extra = $('extra').value.split(/\s+/).filter(Boolean);
    for (const e of extra) if (!OneqPac.cidrParts(e)) throw new Error('Not a network (a.b.c.d/n): ' + e);
    await chrome.runtime.sendMessage({ type: 'set', values: { socks, status, extraNets: extra, pacSig: null } });
    $('msg').textContent = 'Saved.';
  } catch (e) {
    $('msg').textContent = e.message;
  }
});

// ---- updates
let lastUpd = null;
$('updauto').addEventListener('change', e => chrome.storage.local.set({ update_check: e.target.checked }));
$('updnow').addEventListener('click', async () => {
  const msg = $('updmsg');
  msg.textContent = 'Checking...';
  $('upddl').hidden = true;
  const r = await OneqUpdate.check({ force: true });
  lastUpd = r;
  if (r.status === 'error') msg.textContent = 'Update check failed: ' + r.error;
  else if (r.update_available) {
    msg.textContent = 'Version ' + r.latest + ' is available (you have ' + r.current + ').';
    $('upddl').hidden = !r.asset;
  } else if (r.status === 'unknown') msg.textContent = 'Could not compare versions.';
  else msg.textContent = 'You have the latest version (' + r.current + ').';
});
$('upddl').addEventListener('click', async () => {
  const msg = $('updmsg');
  msg.textContent = 'Downloading and verifying...';
  const d = await OneqUpdate.downloadVerified(lastUpd);
  msg.textContent = d.ok ? 'Downloaded and verified: ' + d.path + '. Install it when you are ready.' : 'Download failed: ' + d.error;
});
chrome.storage.local.get('update_check').then(o => { $('updauto').checked = o.update_check !== false; });
load();
