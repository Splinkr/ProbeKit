// Executa somente replay local; perfil novo, proxy sem encaminhamento e Fetch interceptado.
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { createServer, isIP } from 'node:net';

const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
let input = '';
for await (const chunk of process.stdin) input += chunk;
const options = JSON.parse(input);
const result = { status: 'error', confirmed: false, target_network_requests: 0, cases: [] };
result.network_policy = 'Fetch fulfillment/abort only; proxy drops all connections; no forwarding';
const overallDeadline = Date.now() + options.timeout_ms + 10000;
let browser, socket, profile, proxy, client;
let blockedConnections = 0;
try {
  if (typeof WebSocket !== 'function' || !/^wvxss_[a-f0-9]{24}$/.test(options.callback)) throw Error('Runtime indisponível.');
  if (!options.cases.length || options.cases.length > 5) throw Error('Casos inválidos.');
  const allowed = new URL(options.cases[0].url).origin;
  for (const item of options.cases) {
    const url = new URL(item.url), host = url.hostname.replace(/^\[|\]$/g, '');
    if (!['http:', 'https:'].includes(url.protocol) || url.origin !== allowed || url.username || url.password ||
        !(host === '::1' || (isIP(host) === 4 && host.startsWith('127.'))) || item.content_type.split(';')[0].trim().toLowerCase() !== 'text/html') {
      throw Error('Replay fora do escopo.');
    }
  }
  proxy = createServer(connection => { blockedConnections++; connection.destroy(); });
  await new Promise(resolve => proxy.listen(0, '127.0.0.1', resolve));
  profile = await mkdtemp(join(tmpdir(), 'webvuln-xss-'));
  browser = spawn(options.browser, [
    '--headless=new', '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0',
    `--user-data-dir=${profile}`, '--no-first-run', '--no-default-browser-check',
    '--disable-extensions', '--disable-sync', '--disable-background-networking', '--disable-component-update',
    '--disable-features=MediaRouter,OptimizationHints,AutofillServerCommunication',
    '--force-webrtc-ip-handling-policy=disable_non_proxied_udp', '--host-resolver-rules=MAP * ~NOTFOUND',
    `--proxy-server=http://127.0.0.1:${proxy.address().port}`, '--proxy-bypass-list=<-loopback>', 'about:blank',
  ], { windowsHide: true, stdio: ['ignore', 'ignore', 'ignore'] });
  const deadline = Date.now() + options.timeout_ms;
  let active;
  while (Date.now() < deadline) {
    try { active = (await readFile(join(profile, 'DevToolsActivePort'), 'utf8')).trim().split('\n'); break; }
    catch { await pause(40); }
  }
  if (!active || !/^\d+$/.test(active[0]) || !active[1].startsWith('/devtools/browser/')) throw Error('Navegador indisponível.');
  socket = new WebSocket(`ws://127.0.0.1:${active[0]}${active[1]}`);
  await new Promise((resolve, reject) => { socket.addEventListener('open', resolve); socket.addEventListener('error', reject); });
  let sequence = 0;
  const pending = new Map(), listeners = new Set();
  client = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
    const id = ++sequence;
    const timer = setTimeout(() => { pending.delete(id); reject(Error('Timeout CDP.')); }, Math.min(options.timeout_ms, Math.max(100, overallDeadline - Date.now())));
    pending.set(id, { resolve, reject, timer });
    socket.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
  });
  socket.addEventListener('message', event => {
    const message = JSON.parse(event.data);
    if (message.id) {
      const item = pending.get(message.id);
      if (!item) return;
      clearTimeout(item.timer); pending.delete(message.id);
      message.error ? item.reject(Error('Comando CDP rejeitado.')) : item.resolve(message.result);
    } else for (const listener of listeners) listener(message);
  });
  result.browser_version = (await client('Browser.getVersion')).product;
  await client('Browser.setDownloadBehavior', { behavior: 'deny' });
  for (const item of options.cases) {
    if (Date.now() > overallDeadline) throw Error('Prazo global do navegador excedido.');
    const { targetId } = await client('Target.createTarget', { url: 'about:blank' });
    const { sessionId } = await client('Target.attachToTarget', { targetId, flatten: true });
    const contexts = new Map(), callbacks = [];
    let replayed = false, loaded = false, blocked = 0, eventFailure = false;
    const listener = message => {
      if (message.sessionId !== sessionId) return;
      const data = message.params;
      if (message.method === 'Runtime.executionContextCreated') contexts.set(data.context.id, data.context.auxData);
      if (message.method === 'Runtime.bindingCalled' && data.name === options.callback && data.payload === item.marker) callbacks.push(data.executionContextId);
      if (message.method === 'Page.loadEventFired') loaded = true;
      if (message.method === 'Fetch.requestPaused') {
        const initial = !replayed && data.resourceType === 'Document' && new URL(data.request.url).href === new URL(item.url).href;
        let operation;
        if (initial) {
          replayed = true;
          const responseHeaders = [{ name: 'Content-Type', value: item.content_type },
            ...Object.entries(item.headers).map(([name, value]) => ({ name, value })),
            // Restrição adicional: nunca relaxa a CSP original e proíbe recursos/conexões.
            { name: 'Content-Security-Policy', value: "default-src 'none'; script-src 'unsafe-inline'; connect-src 'none'; img-src 'none'; frame-src 'none'; worker-src 'none'; form-action 'none'; base-uri 'none'" }];
          operation = client('Fetch.fulfillRequest', { requestId: data.requestId, responseCode: item.status, responseHeaders, body: item.body }, sessionId);
        } else {
          blocked++;
          operation = client('Fetch.failRequest', { requestId: data.requestId, errorReason: 'BlockedByClient' }, sessionId);
        }
        operation.catch(() => { eventFailure = true; });
      }
    };
    listeners.add(listener);
    await client('Page.enable', {}, sessionId);
    await client('Runtime.enable', {}, sessionId);
    await client('Runtime.addBinding', { name: options.callback }, sessionId);
    await client('Fetch.enable', { patterns: [{ urlPattern: '*', requestStage: 'Request' }] }, sessionId);
    const navigation = await client('Page.navigate', { url: item.url }, sessionId);
    const end = Math.min(Date.now() + options.timeout_ms, overallDeadline);
    while (!loaded && Date.now() < end) await pause(20);
    await pause(40);
    const main = callbacks.find(id => contexts.get(id)?.isDefault && contexts.get(id)?.frameId === navigation.frameId);
    result.cases.push({ role: item.role, request_id: item.request_id, marker: item.marker,
      body_sha256: item.body_sha256, replayed, executed: !!main && !eventFailure, main_frame: !!main,
      execution_context_id: main ?? null, blocked_resource_requests: blocked, csp_preserved: true });
    listeners.delete(listener);
    await client('Target.closeTarget', { targetId });
  }
  result.status = 'completed';
} catch {
  result.status = 'error';
  result.reason = 'Confirmação isolada indisponível, bloqueada ou excedeu o timeout.';
} finally {
  if (client) { try { await client('Browser.close'); } catch {} }
  if (socket) socket.close();
  if (browser && browser.exitCode === null) {
    await Promise.race([new Promise(resolve => browser.once('exit', resolve)), pause(1500)]);
    if (browser.exitCode === null) browser.kill();
  }
  if (proxy) proxy.close();
  result.blocked_proxy_connections = blockedConnections;
  if (profile && dirname(resolve(profile)) === resolve(tmpdir()) && basename(profile).startsWith('webvuln-xss-')) {
    try { await rm(profile, { recursive: true, force: true, maxRetries: 4, retryDelay: 100 }); } catch {}
  }
}
process.stdout.write(JSON.stringify(result));
