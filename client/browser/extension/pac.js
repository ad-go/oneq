// PAC script of the extension: only the mesh goes through the local oneqclient proxy, everything else stays DIRECT.
// Shared by the service worker (importScripts) and the Node tests.
(function (root) {
  'use strict';

  function cidrParts(cidr) {
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/.exec(String(cidr).trim());
    if (!m) return null;
    const o = [m[1], m[2], m[3], m[4]].map(Number);
    const bits = Number(m[5]);
    if (o.some(x => x > 255) || bits > 32) return null;
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    const ip = ((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]) >>> 0;
    const net = (ip & mask) >>> 0;
    const dotted = n => [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
    return { net: dotted(net), mask: dotted(mask) };
  }

  // "127.0.0.1:1080" -> "SOCKS5 127.0.0.1:1080"; anything else is refused (the value ends up inside a script)
  function socksTarget(addr) {
    const m = /^(127\.\d{1,3}\.\d{1,3}\.\d{1,3}|localhost):(\d{1,5})$/.exec(String(addr).trim());
    if (!m || Number(m[2]) < 1 || Number(m[2]) > 65535) return null;
    return 'SOCKS5 ' + m[1] + ':' + m[2];
  }

  function buildPac(subnets, socks) {
    const target = socksTarget(socks);
    if (!target) throw new Error('the proxy address must be 127.x.x.x:PORT or localhost:PORT');
    const nets = [];
    for (const s of subnets) {
      const p = cidrParts(s);
      if (!p) throw new Error('bad subnet: ' + s);
      nets.push(p);
    }
    const netsJson = JSON.stringify(nets);
    return [
      'function FindProxyForURL(url, host) {',
      '  var nets = ' + netsJson + ';',
      '  if (host.length > 5 && host.slice(-5).toLowerCase() === ".oneq") return ' + JSON.stringify(target) + ';',
      '  if (/^\\d+\\.\\d+\\.\\d+\\.\\d+$/.test(host)) {',          // IP literals only: isInNet() would resolve names
      '    for (var i = 0; i < nets.length; i++) if (isInNet(host, nets[i].net, nets[i].mask)) return ' + JSON.stringify(target) + ';',
      '  }',
      '  return "DIRECT";',
      '}',
    ].join('\n');
  }

  // Firefox has no inline PAC: proxy.onRequest asks this function per request. Same decision as the PAC script: IP literals inside a mesh network and
  // names ending in ".oneq" -> {host, port} of the SOCKS5 proxy, everything else null (direct). Names are never resolved here either.
  function matcher(subnets, socks) {
    const target = socksTarget(socks);
    if (!target) throw new Error('the proxy address must be 127.x.x.x:PORT or localhost:PORT');
    const [host, port] = target.replace('SOCKS5 ', '').split(':');
    const nets = subnets.map(s => {
      const p = cidrParts(s);
      if (!p) throw new Error('bad subnet: ' + s);
      const n = a => a.split('.').reduce((x, y) => ((x << 8) | Number(y)) >>> 0, 0);
      return { net: n(p.net), mask: n(p.mask) };
    });
    return function (url) {
      let h;
      try { h = new URL(url).hostname; } catch (e) { return null; }
      h = h.toLowerCase();
      if (h.length > 5 && h.slice(-5) === '.oneq') return { host, port: Number(port) };
      const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
      if (!m || m.slice(1).some(x => Number(x) > 255)) return null;
      const ip = ((Number(m[1]) << 24) | (Number(m[2]) << 16) | (Number(m[3]) << 8) | Number(m[4])) >>> 0;
      for (const n of nets) if (((ip & n.mask) >>> 0) === ((n.net & n.mask) >>> 0)) return { host, port: Number(port) };
      return null;
    };
  }

  const api = { buildPac, cidrParts, socksTarget, matcher };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.OneqPac = api;
})(typeof self !== 'undefined' ? self : this);
