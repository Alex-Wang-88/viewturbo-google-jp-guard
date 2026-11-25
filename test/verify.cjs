const assert = require('node:assert/strict');
const net = require('node:net');
const dgram = require('node:dgram');
const { spawn } = require('node:child_process');
const { once } = require('node:events');

const BASE = 29832;
const sleep = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));

async function api(method, name, token = 'lab-secret') {
  const response = await fetch('http://127.0.0.1:' + BASE + '/proxies/google-gate', {
    method,
    headers: { authorization: 'Bearer ' + token, 'content-type': 'application/json' },
    body: name ? JSON.stringify({ name }) : undefined,
    signal: AbortSignal.timeout(1500),
  });
  if (method === 'GET') return { status: response.status, body: await response.json() };
  return response.status;
}

function read(socket, size) {
  return new Promise((resolve, reject) => {
    function cleanup() {
      socket.off('readable', onReadable);
      socket.off('error', onError);
      socket.off('end', onEnd);
      socket.off('close', onEnd);
      clearTimeout(timer);
    }
    function onError(error) { cleanup(); reject(error); }
    function onEnd() { onError(new Error('Socket closed before reply')); }
    function onReadable() {
      const data = socket.read(size);
      if (data !== null) { cleanup(); resolve(data); }
    }
    const timer = setTimeout(() => onError(new Error('Timed out waiting for socket data')), 5000);
    socket.on('readable', onReadable);
    socket.once('error', onError);
    socket.once('end', onEnd);
    socket.once('close', onEnd);
    onReadable();
    if (socket.destroyed || socket.readableEnded) onEnd();
  });
}

async function socksRequest(socket) {
  const hello = await read(socket, 2);
  assert.equal(hello[0], 5);
  assert.ok((await read(socket, hello[1])).includes(0));
  socket.write(Buffer.from([5, 0]));
  const request = await read(socket, 4);
  let host;
  if (request[3] === 1) host = Array.from(await read(socket, 4)).join('.');
  else if (request[3] === 3) host = (await read(socket, (await read(socket, 1))[0])).toString();
  else throw Error('Unexpected upstream address type');
  const port = (await read(socket, 2)).readUInt16BE(0);
  return { host, port };
}

async function connect(port, address = '127.0.0.1') {
  const socket = net.createConnection(port, address);
  await once(socket, 'connect');
  socket.on('error', () => {});
  return socket;
}

async function subscribe(host, port) {
  const socket = await connect(BASE + 3);
  try {
    socket.write(Buffer.from([5, 1, 0]));
    assert.deepEqual(Array.from(await read(socket, 2)), [5, 0]);
    const data = net.isIPv4(host)
      ? Buffer.from([5, 1, 0, 1, ...host.split('.').map(Number)])
      : Buffer.concat([Buffer.from([5, 1, 0, 3, host.length]), Buffer.from(host)]);
    const portBytes = Buffer.alloc(2);
    portBytes.writeUInt16BE(port);
    socket.write(Buffer.concat([data, portBytes]));
    const response = await read(socket, 4);
    assert.deepEqual(Array.from(response).slice(0, 2), [5, 0]);
    let addressSize;
    if (response[3] === 1) addressSize = 4;
    else if (response[3] === 4) addressSize = 16;
    else if (response[3] === 3) addressSize = (await read(socket, 1))[0];
    else throw Error('Unexpected downstream address type');
    await read(socket, addressSize + 2);
    return socket;
  } catch (error) {
    socket.destroy();
    throw error;
  }
}

function dnsLookup(name) {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket('udp4');
    const timeout = setTimeout(() => { socket.close(); reject(Error('DNS timeout')); }, 4000);
    const question = Buffer.concat(name.split('.').map(label => Buffer.concat([Buffer.from([label.length]), Buffer.from(label)])));
    const dns = Buffer.concat([Buffer.from('152701000001000000000000', 'hex'), question, Buffer.from('0000010001', 'hex')]);
    socket.once('message', data => {
      clearTimeout(timeout);
      socket.close();
      resolve(data);
    });
    socket.send(dns, BASE + 4, '127.0.0.53');
  });
}

async function main() {
  const seen = [];
  const sockets = new Set();
  const upstream = net.createServer(async socket => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    try {
      seen.push(await socksRequest(socket));
      socket.write(Buffer.from([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]));
      socket.on('data', () => socket.write('PROXY'));
    } catch { socket.destroy(); }
  });
  upstream.listen(BASE + 2, '127.0.0.1');
  await once(upstream, 'listening');
  const child = spawn(process.argv[2], ['run', '-c', process.argv[3]], {
    windowsHide: true,
    stdio: ['ignore', 'inherit', 'inherit'],
    env: { ...process.env, GOMAXPROCS: '4' },
  });
  try {
    let state;
    for (let attempt = 0; attempt < 35; attempt++) {
      if (child.exitCode !== null) throw Error('Engine exited');
      try { state = await api('GET'); break; } catch { await sleep(100); }
    }
    assert.equal(state?.body.now, 'closed');
    assert.equal((await api('GET', '', 'wrong')).status, 401);
    const dns = await dnsLookup('gemini.google.com');
    assert.equal(dns.readUInt16BE(6), 1);
    const fake = Array.from(dns.subarray(dns.length - 4)).join('.');
    assert.match(fake, /^198\.19\./);
    const refused = await dnsLookup('ordinary.example');
    assert.equal(refused[3] & 15, 5);

    const ordinary = await subscribe('ordinary.example', 443);
    ordinary.write('hello');
    assert.equal((await read(ordinary, 5)).toString(), 'PROXY');
    assert.deepEqual(seen.shift(), { host: 'ordinary.example', port: 443 });
    for (const target of ['gemini.google.com', '8.8.8.8', fake]) {
      const blocked = await subscribe(target, 443).catch(() => null);
      if (blocked) {
        blocked.write('blocked');
        await assert.rejects(read(blocked, 1), /closed/i, target + ' received unexpected data');
        blocked.destroy();
      }
    }
    assert.deepEqual(seen, []);
    const httpBlocked = await connect(BASE + 3);
    httpBlocked.write('CONNECT gemini.google.com:443 HTTP/1.1\r\nHost: gemini.google.com:443\r\n\r\n');
    await assert.rejects(read(httpBlocked, 128), /closed|ECONNRESET/i);
    assert.deepEqual(seen, []);
    httpBlocked.destroy();
    console.log('PASS default closed, authenticated control, ordinary SOCKS forwarding, protected DNS and HTTP/SOCKS blocking');

    const proof = await connect(BASE + 1);
    proof.write('test');
    assert.equal((await read(proof, 5)).toString(), 'PROXY');
    assert.deepEqual(seen.shift(), { host: 'one.one.one.one', port: 443 });
    proof.destroy();
    assert.equal(await api('PUT', 'viewturbo'), 204);
    const opened = await subscribe(fake, 443);
    opened.write('hello');
    assert.equal((await read(opened, 5)).toString(), 'PROXY');
    assert.ok(seen.some(record => record.host === 'gemini.google.com' && record.port === 443));
    assert.equal(await api('PUT', 'closed'), 204);
    await assert.rejects(read(opened, 1), /closed/i);
    opened.destroy();
    ordinary.write('still active');
    assert.equal((await read(ordinary, 5)).toString(), 'PROXY');
    ordinary.destroy();
    console.log('PASS proof isolated from gate, protected hostname via SOCKS, and only protected stream terminated on reblock');
  } finally {
    child.kill();
    for (const socket of sockets) socket.destroy();
    upstream.close();
  }
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
