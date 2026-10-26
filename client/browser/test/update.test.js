// Node tests of the update check: `node --test client/browser/test`
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const path = require('node:path');
const U = require(path.join('..', 'extension', 'update.js'));

const store = {};
global.chrome = {
  runtime: { getManifest: () => ({ version: '0.0.1' }) },
  storage: { local: { get: async k => ({ [k]: store[k] }), set: async o => { Object.assign(store, o); } } },
  downloads: { saved: [], download: async function (o) { this.saved.push(o); return 7; } },
};
global.URL.createObjectURL = () => 'blob:x';
global.URL.revokeObjectURL = () => {};

test('version compare', () => {
  assert.strictEqual(U.compareVersions('v0.0.2', '0.0.1'), 1);
  assert.strictEqual(U.compareVersions('0.0.1', '0.0.1'), 0);
  assert.strictEqual(U.compareVersions('0.1', '0.0.9'), 1);
  assert.strictEqual(U.compareVersions('1.0', '1.0.0'), 0);
  assert.strictEqual(U.compareVersions('0.0.1', '0.0.2'), -1);
  assert.strictEqual(U.compareVersions('0.0.2-rc1', '0.0.1'), 1);
  assert.strictEqual(U.compareVersions('abc', '0.0.1'), null);
  assert.strictEqual(U.compareVersions('0.0.2', ''), null);
});

test('SHA256SUMS parsing', () => {
  const h = 'a'.repeat(64), g = 'B'.repeat(64);
  const s = U.parseSums(h + ' *one.zip\n' + g + '  ./dir/two.zip\r\nnot a line\n');
  assert.strictEqual(s['one.zip'], h);
  assert.strictEqual(s['two.zip'], 'b'.repeat(64));
});

test('asset selection and release interpretation', () => {
  const rel = { tag_name: 'v0.0.2', html_url: 'https://github.com/ad-go/oneq/releases/tag/v0.0.2', body: 'x'.repeat(900), assets: [
    { name: 'oneq-mesh-chromium-0.0.2.zip', size: 5, browser_download_url: 'https://github.com/ad-go/oneq/releases/download/v0.0.2/oneq-mesh-chromium-0.0.2.zip' },
    { name: 'oneq-mesh-firefox-0.0.2.zip', size: 6, browser_download_url: 'https://github.com/ad-go/oneq/releases/download/v0.0.2/oneq-mesh-firefox-0.0.2.zip' }] };
  const c = U.interpret(rel, '0.0.1', false), f = U.interpret(rel, '0.0.1', true);
  assert.strictEqual(c.status, 'newer'); assert.ok(c.update_available);
  assert.strictEqual(c.asset.name, 'oneq-mesh-chromium-0.0.2.zip');
  assert.strictEqual(f.asset.name, 'oneq-mesh-firefox-0.0.2.zip');
  assert.strictEqual(c.notes.length, 600);
  assert.strictEqual(U.interpret(rel, '0.0.2', false).update_available, false);
  assert.strictEqual(U.interpret(Object.assign({}, rel, { prerelease: true }), '0.0.1', false).update_available, false);
  assert.strictEqual(U.interpret({}, '0.0.1', false).status, 'error');
});

test('host allowlist', () => {
  for (const u of ['https://api.github.com/x', 'https://github.com/x', 'https://objects.githubusercontent.com/x', 'https://release-assets.githubusercontent.com/x', 'https://foo.githubusercontent.com/x'])
    assert.ok(U.urlAllowed(u), u);
  for (const u of ['http://github.com/x', 'https://evil.com/x', 'https://github.com.evil.com/x', 'https://evilgithubusercontent.com/x', 'ftp://github.com/x', 'nonsense'])
    assert.ok(!U.urlAllowed(u), u);
});

const ASSET = 'oneq-mesh-chromium-0.0.2.zip';
const BASE = 'https://github.com/ad-go/oneq/releases/download/v0.0.2/';
function mockFetch(files, finalHost) {
  global.fetch = async (url, opts) => {
    assert.strictEqual(opts.credentials, 'omit');
    const name = url.split('/').pop();
    if (!(name in files)) return { ok: false, status: 404, url, headers: new Map() };
    const body = Buffer.from(files[name]);
    return { ok: true, status: 200, url: finalHost ? 'https://' + finalHost + '/' + name : url, headers: new Map([['content-length', String(body.length)]]),
      body: { getReader() { let done = false; return { read: async () => done ? { done: true } : (done = true, { done: false, value: new Uint8Array(body) }), cancel: async () => {} }; } } };
  };
}
const res = () => ({ asset: { name: ASSET, size: 4, download_url: BASE + ASSET } });
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
global.crypto = global.crypto || crypto.webcrypto;

test('hash mismatch refuses to save', async () => {
  chrome.downloads.saved.length = 0;
  mockFetch({ SHA256SUMS: sha('other') + ' *' + ASSET + '\n', [ASSET]: 'data' });
  const r = await U.downloadVerified(res());
  assert.strictEqual(r.ok, false);
  assert.match(r.error, /mismatch/);
  assert.strictEqual(chrome.downloads.saved.length, 0);
});

test('missing checksum entry refuses to save', async () => {
  chrome.downloads.saved.length = 0;
  mockFetch({ SHA256SUMS: sha('x') + ' *other.zip\n', [ASSET]: 'data' });
  assert.strictEqual((await U.downloadVerified(res())).ok, false);
  assert.strictEqual(chrome.downloads.saved.length, 0);
});

test('redirect to a foreign host is discarded', async () => {
  chrome.downloads.saved.length = 0;
  mockFetch({ SHA256SUMS: sha('data') + ' *' + ASSET + '\n', [ASSET]: 'data' }, 'evil.example.com');
  assert.strictEqual((await U.downloadVerified(res())).ok, false);
  assert.strictEqual(chrome.downloads.saved.length, 0);
});

test('success path saves through chrome.downloads', async () => {
  chrome.downloads.saved.length = 0;
  mockFetch({ SHA256SUMS: sha('data') + '  ' + ASSET + '\n', [ASSET]: 'data' }, 'release-assets.githubusercontent.com');
  const r = await U.downloadVerified(res());
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.sha256, sha('data'));
  assert.strictEqual(chrome.downloads.saved.length, 1);
  assert.strictEqual(chrome.downloads.saved[0].filename, ASSET);
});

test('check() uses the cache and the 60 s manual limit', async () => {
  let calls = 0;
  const rel = { tag_name: 'v0.0.2', html_url: 'https://github.com/ad-go/oneq/releases/tag/v0.0.2', assets: [] };
  global.fetch = async url => { calls++; const b = Buffer.from(JSON.stringify(rel)); return { ok: true, url, headers: new Map(), arrayBuffer: async () => b }; };
  const a = await U.check({ force: false });
  assert.ok(a.update_available);
  await U.check({ force: false });
  assert.strictEqual(calls, 1);
  await U.check({ force: true });
  assert.strictEqual(calls, 2);
  await U.check({ force: true });
  assert.strictEqual(calls, 2);
});
