// Node tests of the PAC script: `node --test client/browser/test`
const test = require('node:test');
const assert = require('node:assert');
const vm = require('node:vm');
const path = require('node:path');
const { buildPac, cidrParts, socksTarget, matcher } = require(path.join('..', 'extension', 'pac.js'));

// the PAC runtime functions the browser provides, enough for the script
function runPac(pac, host) {
  const ctx = {
    isInNet(h, net, mask) {
      const n = s => s.split('.').reduce((a, b) => ((a << 8) | Number(b)) >>> 0, 0);
      return ((n(h) & n(mask)) >>> 0) === ((n(net) & n(mask)) >>> 0);
    },
    dnsResolve() { throw new Error('the PAC script must not resolve names'); },
  };
  vm.createContext(ctx);
  vm.runInContext(pac, ctx);
  return vm.runInContext('FindProxyForURL("http://x/", ' + JSON.stringify(host) + ')', ctx);
}

test('only mesh addresses and *.oneq go through the proxy', () => {
  const pac = buildPac(['10.78.0.0/24'], '127.0.0.1:1080');
  assert.strictEqual(runPac(pac, '10.78.0.189'), 'SOCKS5 127.0.0.1:1080');
  assert.strictEqual(runPac(pac, '10.78.0.1'), 'SOCKS5 127.0.0.1:1080');
  assert.strictEqual(runPac(pac, 'x.oneq'), 'SOCKS5 127.0.0.1:1080');
  assert.strictEqual(runPac(pac, 'ALICE-PC.ONEQ'), 'SOCKS5 127.0.0.1:1080');
  assert.strictEqual(runPac(pac, '10.78.1.5'), 'DIRECT');
  assert.strictEqual(runPac(pac, '10.79.0.5'), 'DIRECT');
  assert.strictEqual(runPac(pac, 'example.com'), 'DIRECT');
  assert.strictEqual(runPac(pac, 'oneq'), 'DIRECT');
  assert.strictEqual(runPac(pac, 'evil.oneq.example.com'), 'DIRECT');
  assert.strictEqual(runPac(pac, '8.8.8.8'), 'DIRECT');
});

test('names are never resolved (no DNS lookups from the PAC script)', () => {
  const pac = buildPac(['10.78.0.0/24'], '127.0.0.1:1080');
  assert.doesNotThrow(() => runPac(pac, 'intranet.example.org'));
});

test('several networks, a wide one and a narrow one', () => {
  const pac = buildPac(['10.0.0.0/8', '192.168.7.0/30'], 'localhost:9050');
  assert.strictEqual(runPac(pac, '10.200.1.1'), 'SOCKS5 localhost:9050');
  assert.strictEqual(runPac(pac, '192.168.7.2'), 'SOCKS5 localhost:9050');
  assert.strictEqual(runPac(pac, '192.168.7.9'), 'DIRECT');
});

test('the proxy address is restricted to this computer and checked', () => {
  assert.strictEqual(socksTarget('127.0.0.1:1080'), 'SOCKS5 127.0.0.1:1080');
  assert.strictEqual(socksTarget('localhost:1080'), 'SOCKS5 localhost:1080');
  for (const bad of ['10.0.0.1:1080', 'evil.example.com:1080', '127.0.0.1', '127.0.0.1:0', '127.0.0.1:99999', '127.0.0.1:1080"; alert(1);//', '']) {
    assert.strictEqual(socksTarget(bad), null, bad);
    assert.throws(() => buildPac(['10.0.0.0/8'], bad));
  }
});

test('subnets are parsed strictly', () => {
  assert.deepStrictEqual(cidrParts('10.78.0.77/24'), { net: '10.78.0.0', mask: '255.255.255.0' });
  assert.deepStrictEqual(cidrParts('0.0.0.0/0'), { net: '0.0.0.0', mask: '0.0.0.0' });
  for (const bad of ['10.78.0.0', '10.78.0.0/33', '300.1.1.1/8', 'a.b.c.d/8', '10.78.0.0/24; x']) assert.strictEqual(cidrParts(bad), null, bad);
  assert.throws(() => buildPac(['nonsense'], '127.0.0.1:1080'));
});

test('the Firefox matcher takes the same decisions as the PAC script', () => {
  const nets = ['10.78.0.0/24', '192.168.7.0/30'];
  const pac = buildPac(nets, '127.0.0.1:1080');
  const m = matcher(nets, '127.0.0.1:1080');
  for (const h of ['10.78.0.189', '10.78.0.1', 'x.oneq', 'ALICE-PC.ONEQ', '10.78.1.5', '10.79.0.5', 'example.com', 'oneq', 'evil.oneq.example.com', '8.8.8.8',
                   '192.168.7.2', '192.168.7.9', '999.1.1.1', '10.78.0.256', '']) {
    const viaPac = runPac(pac, h) === 'SOCKS5 127.0.0.1:1080';
    const viaMatcher = m('http://' + (h || 'x') + '/') !== null && h !== '';
    assert.strictEqual(viaMatcher, viaPac, h);
  }
  assert.deepStrictEqual(m('http://10.78.0.5:8080/a?b'), { host: '127.0.0.1', port: 1080 });
  assert.strictEqual(m('not a url'), null);
  assert.strictEqual(m('http://[::1]/'), null);
  assert.throws(() => matcher(nets, 'evil.example.com:1080'));
  assert.throws(() => matcher(['10.0.0.0/99'], '127.0.0.1:1080'));
});
