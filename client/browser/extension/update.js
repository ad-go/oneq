// Update check (spec: one shared rule set for every oneq component). Looks at the latest GitHub release, tells the user, and on request downloads
// the matching package with SHA-256 verification. Nothing is installed or run: the verified file lands in the browser's download folder.
// Loaded as a plain script (popup, options, background; Firefox event page) and as a CommonJS module by the node tests.
(function (root) {
  'use strict';
  const API_URL = 'https://api.github.com/repos/ad-go/oneq/releases/latest';
  const HOSTS = ['api.github.com', 'github.com', 'objects.githubusercontent.com', 'release-assets.githubusercontent.com'];
  const CACHE_MS = 6 * 3600 * 1000;
  const MANUAL_GAP_MS = 60 * 1000;
  const MAX_API = 1024 * 1024, MAX_SUMS = 64 * 1024, MAX_DOWNLOAD = 200 * 1024 * 1024;
  const NAME_RE = /^[A-Za-z0-9._-]+$/;
  const KEY = 'updateState';   // { result, fetchedAt, manualAt }

  function hostAllowed(h) {
    h = String(h || '').toLowerCase();
    return HOSTS.includes(h) || /^[a-z0-9-]+(\.[a-z0-9-]+)*\.githubusercontent\.com$/.test(h);
  }
  function urlAllowed(u) {
    try { const x = new URL(u); return x.protocol === 'https:' && hostAllowed(x.hostname); } catch (e) { return false; }
  }

  // numeric tuple of "v1.2.3-rc1+b" -> [1,2,3]; null when it does not parse
  function parseVersion(v) {
    v = String(v == null ? '' : v).trim().replace(/^v/i, '').split(/[-+]/)[0];
    if (!/^\d+(\.\d+)*$/.test(v)) return null;
    return v.split('.').map(Number);
  }
  // 1 remote newer, 0 equal, -1 older, null unknown
  function compareVersions(remote, local) {
    const a = parseVersion(remote), b = parseVersion(local);
    if (!a || !b) return null;
    for (let i = 0; i < Math.max(a.length, b.length); i++) {
      const x = a[i] || 0, y = b[i] || 0;
      if (x !== y) return x > y ? 1 : -1;
    }
    return 0;
  }

  // SHA256SUMS: "<64 hex> *name" or "<hex>  name", name may carry "./" or a directory: the basename counts
  function parseSums(text) {
    const out = {};
    for (const line of String(text).split(/\r?\n/)) {
      const m = /^([0-9a-fA-F]{64})\s+\*?(.+?)\s*$/.exec(line);
      if (!m) continue;
      out[m[2].split(/[\\/]/).pop()] = m[1].toLowerCase();
    }
    return out;
  }

  function isFirefox() {
    try { if (typeof browser !== 'undefined' && browser.runtime && browser.runtime.getBrowserInfo) return true; } catch (e) { /* ignore */ }
    try { const m = chrome.runtime.getManifest(); if (m && m.browser_specific_settings && m.browser_specific_settings.gecko) return true; } catch (e) { /* ignore */ }
    return false;
  }
  function assetName(version, firefox) {
    return 'oneq-mesh-' + (firefox ? 'firefox' : 'chromium') + '-' + String(version).replace(/^v/i, '') + '.zip';
  }

  function emptyResult(current, status, error) {
    return { current, latest: null, update_available: false, status, url: '', notes: '', asset: null, checked_at: Math.floor(Date.now() / 1000), error: error || null };
  }

  // release JSON -> result object
  function interpret(rel, current, firefox) {
    if (!rel || typeof rel !== 'object' || typeof rel.tag_name !== 'string') return emptyResult(current, 'error', 'unexpected answer');
    const r = emptyResult(current, 'current');
    if (rel.draft === true || rel.prerelease === true) return r;
    r.latest = rel.tag_name.replace(/^v/i, '');
    const c = compareVersions(rel.tag_name, current);
    r.status = c === null ? 'unknown' : c > 0 ? 'newer' : 'current';
    r.update_available = c === 1;
    if (typeof rel.html_url === 'string' && urlAllowed(rel.html_url)) r.url = rel.html_url;
    r.notes = String(rel.body || '').slice(0, 600);
    if (r.update_available) {
      const want = assetName(r.latest, firefox);
      const a = (rel.assets || []).find(x => x && x.name === want && NAME_RE.test(x.name) && urlAllowed(x.browser_download_url));
      if (a) r.asset = { name: a.name, size: Number(a.size) || 0, download_url: a.browser_download_url };
    }
    return r;
  }

  // fetch with the policy: https allowlist (checked on the final URL, data dropped otherwise), no cookies, size cap while streaming
  async function fetchLimited(url, max, accept, signal) {
    if (!urlAllowed(url)) throw new Error('address not allowed');
    const resp = await fetch(url, { credentials: 'omit', redirect: 'follow', cache: 'no-store', headers: { Accept: accept }, signal });
    if (!urlAllowed(resp.url || url)) throw new Error('redirected to a host that is not allowed');
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    const len = Number(resp.headers.get('content-length'));
    if (len > max) throw new Error('too large');
    const chunks = [];
    let n = 0;
    if (resp.body && resp.body.getReader) {
      const rd = resp.body.getReader();
      for (;;) {
        const { done, value } = await rd.read();
        if (done) break;
        n += value.length;
        if (n > max) { try { await rd.cancel(); } catch (e) { /* ignore */ } throw new Error('too large'); }
        chunks.push(value);
      }
    } else {
      const b = new Uint8Array(await resp.arrayBuffer());
      if (b.length > max) throw new Error('too large');
      chunks.push(b); n = b.length;
    }
    const all = new Uint8Array(n);
    let o = 0;
    for (const c of chunks) { all.set(c, o); o += c.length; }
    return all;
  }

  function withTimeout(ms) {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), ms);
    return { signal: ctl.signal, done: () => clearTimeout(t) };
  }

  function localVersion() { return chrome.runtime.getManifest().version; }

  async function readState() {
    try { return (await chrome.storage.local.get(KEY))[KEY] || {}; } catch (e) { return {}; }
  }

  // check({force}): cached 6 h; a forced (manual) check bypasses the cache, but not more than once per 60 s
  async function check(opts) {
    const force = !!(opts && opts.force);
    const current = localVersion();
    const st = await readState();
    const now = Date.now();
    if (st.result && st.result.current === current) {
      if (!force && now - (st.fetchedAt || 0) < CACHE_MS) return st.result;
      if (force && now - (st.manualAt || 0) < MANUAL_GAP_MS) return st.result;
    }
    const t = withTimeout(30000);
    let result;
    try {
      const bytes = await fetchLimited(API_URL, MAX_API, 'application/vnd.github+json', t.signal);
      result = interpret(JSON.parse(new TextDecoder().decode(bytes)), current, isFirefox());
    } catch (e) {
      result = emptyResult(current, 'error', String((e && e.message) || e).slice(0, 120));
    } finally { t.done(); }
    const ns = { result, fetchedAt: now, manualAt: force ? now : (st.manualAt || 0) };
    try { await chrome.storage.local.set({ [KEY]: ns }); } catch (e) { /* ignore */ }
    return result;
  }

  // the last stored answer without any network access (popup banner)
  async function lastResult() {
    const st = await readState();
    return st.result && st.result.current === localVersion() ? st.result : null;
  }

  function hex(buf) { return Array.from(new Uint8Array(buf), b => b.toString(16).padStart(2, '0')).join(''); }

  // Fetches the asset, verifies it against SHA256SUMS of the same release, and only then hands it to chrome.downloads (Blob URL, revoked afterwards).
  // Needs a page with URL.createObjectURL (popup or options page), not the Chrome service worker.
  async function downloadVerified(result) {
    try {
      const a = result && result.asset;
      if (!a || !NAME_RE.test(a.name) || !urlAllowed(a.download_url)) return { ok: false, error: 'no package to download' };
      const sumsUrl = a.download_url.replace(/[^/]*$/, 'SHA256SUMS');
      const t = withTimeout(120000);
      try {
        const sums = parseSums(new TextDecoder().decode(await fetchLimited(sumsUrl, MAX_SUMS, 'application/octet-stream', t.signal)));
        const want = sums[a.name];
        if (!want) return { ok: false, error: 'no checksum for ' + a.name + ' in SHA256SUMS' };
        const data = await fetchLimited(a.download_url, MAX_DOWNLOAD, 'application/octet-stream', t.signal);
        const got = hex(await crypto.subtle.digest('SHA-256', data));
        if (got !== want) return { ok: false, error: 'checksum mismatch, file discarded' };
        const url = URL.createObjectURL(new Blob([data], { type: 'application/zip' }));
        try {
          const id = await chrome.downloads.download({ url, filename: a.name, saveAs: false, conflictAction: 'uniquify' });
          return { ok: true, path: a.name + ' (in the browser download folder)', name: a.name, size: data.length, sha256: got, id };
        } finally { setTimeout(() => URL.revokeObjectURL(url), 60000); }
      } finally { t.done(); }
    } catch (e) {
      return { ok: false, error: String((e && e.message) || e).slice(0, 160) };
    }
  }

  const api = { API_URL, HOSTS, hostAllowed, urlAllowed, parseVersion, compareVersions, parseSums, isFirefox, assetName, interpret, check, lastResult, downloadVerified, KEY };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.OneqUpdate = api;
})(typeof self !== 'undefined' ? self : this);
