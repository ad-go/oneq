// Service worker (Chrome, Edge, Brave) or event page (Firefox): polls the status page of `oneqclient proxy`, keeps the browser's proxy settings in line
// (Chromium: a PAC script; Firefox: a proxy.onRequest listener; both send only the mesh through the local SOCKS5 proxy) and the toolbar badge.
// Nothing leaves this machine: the proxy and its status page are on 127.0.0.1.
if (typeof importScripts === 'function') importScripts('pac.js', 'update.js');   // Firefox loads both from the manifest's background.scripts

// Firefox has no PAC through the extension API and no chrome.proxy.settings: it asks proxy.onRequest for every request instead.
const FIREFOX = typeof browser !== 'undefined' && !!(browser.proxy && browser.proxy.onRequest);

const DEFAULTS = { enabled: true, manualStop: false, socks: '127.0.0.1:1080', status: '127.0.0.1:1081', extraNets: [] };
const POLL_MS = 5000;

async function cfg() {
  return Object.assign({}, DEFAULTS, await chrome.storage.local.get(Object.keys(DEFAULTS)));
}

// ---- the connection manager: the native messaging host `oneqclient native-host` keeps the connection settings (and the password), starts
// `oneqclient proxy` with them when the browser asks and stops it when the browser goes away. The password never rests in this extension.
const HOST = 'ro.1q.oneq';
let nativePort = null;
let nativeSeq = 0;
const nativePending = new Map();
const native = { available: null, error: null, data: null, checked: 0, lastStart: 0, startError: null };

function nativeDrop(err) {
  nativePort = null;
  native.error = err;
  if (/not found|forbidden|not allowed|no such native/i.test(err)) native.available = false;
  for (const f of nativePending.values()) f({ ok: false, error: err });
  nativePending.clear();
}

function nativeOpen() {
  if (nativePort) return true;
  try {
    const port = chrome.runtime.connectNative(HOST);
    port.onMessage.addListener(m => {
      const f = nativePending.get(m && m.id);
      if (f) { nativePending.delete(m.id); f(m); }
    });
    port.onDisconnect.addListener(p => {
      const e = (p && p.error) || chrome.runtime.lastError;
      nativeDrop((e && e.message) || 'the connection manager closed');
    });
    nativePort = port;
    return true;
  } catch (e) {
    nativeDrop(String((e && e.message) || e));
    return false;
  }
}

function nativeCall(cmd, extra, ms) {
  return new Promise(resolve => {
    if (!nativeOpen()) return resolve({ ok: false, error: native.error });
    const id = ++nativeSeq;
    const t = setTimeout(() => { nativePending.delete(id); resolve({ ok: false, error: 'the connection manager did not answer' }); }, ms || 15000);
    nativePending.set(id, m => { clearTimeout(t); resolve(m); });
    try {
      nativePort.postMessage(Object.assign({ id, cmd }, extra || {}));
    } catch (e) {
      clearTimeout(t);
      nativePending.delete(id);
      resolve({ ok: false, error: String((e && e.message) || e) });
    }
  });
}

function nativeNote(r) {
  if (r && r.config) { native.available = true; native.error = null; native.data = r; return true; }
  return false;
}

async function refreshNative() {
  const r = await nativeCall('get');
  if (!nativeNote(r)) native.data = null;
  native.checked = Date.now();
}

// what the popup and the options page may see: no secrets exist here, the host never sends the password
function nativeView() {
  return { available: native.available, error: native.error, startError: native.startError, data: native.data };
}

async function fetchStatus(c) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), 2000);
  try {
    const r = await fetch('http://' + c.status + '/status', { cache: 'no-store', signal: ctl.signal });
    if (!r.ok) return null;
    return await r.json();
  } catch (e) {
    return null;
  } finally {
    clearTimeout(t);
  }
}

function levelOfControl() {
  if (FIREFOX) return Promise.resolve('controlled_by_this_extension');   // onRequest listeners do not compete with other settings
  return new Promise(res => chrome.proxy.settings.get({ incognito: false }, d => res(d.levelOfControl)));
}

// ---- Firefox: the listener must be registered synchronously when the event page starts; the decision data comes from storage (the page may be unloaded)
let meshMatcher = null;
let matcherReady = null;
async function loadMatcher() {
  const c = await cfg();
  const mem = await chrome.storage.local.get(['lastSubnet', 'liveSocks']);
  meshMatcher = c.enabled && mem.lastSubnet ? OneqPac.matcher([mem.lastSubnet].concat(c.extraNets || []), mem.liveSocks || c.socks) : null;
}
if (FIREFOX) {
  matcherReady = loadMatcher().catch(() => { meshMatcher = null; });
  browser.proxy.onRequest.addListener(async info => {
    await matcherReady;
    const t = meshMatcher && meshMatcher(info.url);
    return t ? { type: 'socks', host: t.host, port: t.port, proxyDNS: true } : { type: 'direct' };
  }, { urls: ['<all_urls>'] });
  browser.proxy.onError.addListener(e => console.warn('proxy error:', e && e.message));
}

async function applyProxy(c, st) {
  const mem = await chrome.storage.local.get(['pacSig']);
  if (!c.enabled) {
    if (FIREFOX) { meshMatcher = null; await chrome.storage.local.remove('pacSig'); return; }
    if (mem.pacSig) {
      await chrome.proxy.settings.clear({ scope: 'regular' });
      await chrome.storage.local.remove('pacSig');
    }
    return;
  }
  // the subnet comes from the running proxy; when it is down the last PAC stays (a clear "proxy refused" is better than a silent direct try)
  let subnet = st && st.proxy && st.proxy.subnet;
  if (subnet) await chrome.storage.local.set({ lastSubnet: subnet });
  else subnet = (await chrome.storage.local.get('lastSubnet')).lastSubnet;
  if (!subnet) return;
  const socks = (st && st.proxy && st.proxy.socks) || c.socks;
  const nets = [subnet].concat(c.extraNets || []);
  const sig = JSON.stringify([nets, socks]);
  if (FIREFOX) {
    if (mem.pacSig !== sig || !meshMatcher) {
      meshMatcher = OneqPac.matcher(nets, socks);
      await chrome.storage.local.set({ pacSig: sig, liveSocks: socks });
    }
    return;
  }
  if (mem.pacSig === sig) return;
  const pac = OneqPac.buildPac(nets, socks);
  await chrome.proxy.settings.set({ value: { mode: 'pac_script', pacScript: { data: pac, mandatory: false } }, scope: 'regular' });
  await chrome.storage.local.set({ pacSig: sig });
}

async function state() {
  const c = await cfg();
  if (native.available !== false || Date.now() - native.checked > 30000) await refreshNative();
  // start the connection when the settings are complete (unless the user disconnected it on purpose); retried every 20 s
  if (c.enabled && !c.manualStop && native.data && native.data.complete && !native.data.running && Date.now() - native.lastStart > 20000) {
    native.lastStart = Date.now();
    const r = await nativeCall('start');
    native.startError = r && r.ok === false ? r.error : null;
    nativeNote(r);
  }
  const st = await fetchStatus(c);
  await applyProxy(c, st).catch(e => console.warn('proxy settings:', e));
  const snap = st && st.snapshot;
  const connected = !!(snap && snap.state === 'connected');
  chrome.action.setBadgeBackgroundColor({ color: connected ? '#2e7d32' : (st ? '#ef6c00' : '#757575') });
  chrome.action.setBadgeText({ text: connected ? '' : (st ? '…' : '!') });
  chrome.action.setTitle({ title: 'oneq mesh: ' + (connected ? 'connected' : st ? (snap.state || 'starting') : 'proxy not running') });
  return { config: c, native: nativeView(), running: !!st, status: st, control: await levelOfControl(), pacSig: (await chrome.storage.local.get('pacSig')).pacSig || null };
}

chrome.runtime.onMessage.addListener((msg, _sender, reply) => {
  if (msg && msg.type === 'state') {
    state().then(reply);
    return true;
  }
  if (msg && (msg.type === 'native-set' || msg.type === 'native-start' || msg.type === 'native-stop')) {
    (async () => {
      let r;
      if (msg.type === 'native-set') {
        r = await nativeCall('set', { config: msg.config, password: msg.password, clear_password: msg.clear_password });
        if (nativeNote(r)) await chrome.storage.local.set({ manualStop: false });
        if (r.ok && r.complete) { native.lastStart = Date.now(); r = await nativeCall('start'); nativeNote(r); }
      } else if (msg.type === 'native-start') {
        await chrome.storage.local.set({ manualStop: false, enabled: true });
        native.lastStart = Date.now();
        r = await nativeCall('start');
        native.startError = r && r.ok === false ? r.error : null;
        nativeNote(r);
      } else {
        await chrome.storage.local.set({ manualStop: true });
        r = await nativeCall('stop');
        nativeNote(r);
      }
      reply({ ok: !!(r && r.ok), error: r && r.error, running: !!(r && r.running), complete: !!(r && r.complete) });
    })();
    return true;
  }
  if (msg && msg.type === 'set') {
    chrome.storage.local.set(msg.values).then(() => state()).then(reply);
    return true;
  }
  return false;
});

chrome.runtime.onInstalled.addListener(() => { state(); });
chrome.runtime.onStartup.addListener(() => { state(); });
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && Object.keys(changes).some(k => k in DEFAULTS)) state();   // the settings changed (not our own bookkeeping)
});
chrome.alarms.create('poll', { periodInMinutes: 0.5 });
chrome.alarms.onAlarm.addListener(a => { if (a.name === 'poll') state(); });

// ---- update check: first look 1-2 minutes after start, then every 24 h, only while the option `update_check` (default on) is set. The result is
// stored for the popup banner; no badge (the badge shows the connection state) and nothing is downloaded here.
async function updateTick() {
  const o = await chrome.storage.local.get('update_check');
  if (o.update_check === false) return;
  try { await OneqUpdate.check({ force: false }); } catch (e) { /* silent */ }
}
chrome.alarms.get('update', a => {
  if (!a) chrome.alarms.create('update', { delayInMinutes: 1 + Math.random(), periodInMinutes: 1440 });
});
chrome.alarms.onAlarm.addListener(a => { if (a.name === 'update') updateTick(); });
setInterval(state, POLL_MS);   // while the worker is awake (popup open, requests flowing)
state();
