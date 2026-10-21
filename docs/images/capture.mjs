// Screenshots of Directory Console's demo (fake directory) for docs/SCREENSHOTS.md, through Chrome's DevTools protocol.
// Needs DemoServer on 8443 and `npm run dev` in console-web on 5173. Run against the demo only: it signs in with the
// demo's fixture administrator and removes the demo's short-lived trusted certificates to clear their warnings.
// node docs/images/capture.mjs docs/images [only-name]      (Node 22 or later; CHROME overrides the browser path)
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const OUT = process.argv[2];
const ONLY = process.argv[3];
const BASE = process.env.CONSOLE_DEV_URL ?? 'http://localhost:5173';
const CHROME = process.env.CHROME ?? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const PORT = 9333;

const chrome = spawn(CHROME, ['--headless=new', `--remote-debugging-port=${PORT}`, `--user-data-dir=${mkdtempSync(join(tmpdir(), 'dc-shots-'))}`,
  '--no-first-run', '--no-default-browser-check', '--hide-scrollbars', '--window-size=1440,900', 'about:blank'], { stdio: 'ignore' });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let ws; let id = 0; const pending = new Map();
async function connect() {
  for (let i = 0; i < 50; i++) {
    try {
      const list = await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json();
      const page = list.find((t) => t.type === 'page');
      if (page) {
        ws = new WebSocket(page.webSocketDebuggerUrl);
        await new Promise((r) => ws.addEventListener('open', r, { once: true }));
        ws.addEventListener('message', (e) => {
          const m = JSON.parse(e.data);
          if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); }
        });
        return;
      }
    } catch { /* not up yet */ }
    await sleep(200);
  }
  throw new Error('Chrome did not start');
}
const send = (method, params = {}) => new Promise((resolve, reject) => {
  const n = ++id;
  pending.set(n, (m) => (m.error ? reject(new Error(`${method}: ${m.error.message}`)) : resolve(m.result)));
  ws.send(JSON.stringify({ id: n, method, params }));
});
const js = async (expression) => {
  const r = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
  if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description ?? r.exceptionDetails.text);
  return r.result.value;
};
const go = async (path, wait = 1800) => { await send('Page.navigate', { url: BASE + path }); await sleep(wait); };
const shot = async (name) => {
  const r = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false });
  writeFileSync(join(OUT, `${name}.png`), Buffer.from(r.data, 'base64'));
  console.log('saved', name);
};
const clickText = (text, selector = 'button, a, [role=tab], [role=menuitem]') =>
  js(`(() => { const el = [...document.querySelectorAll(${JSON.stringify(selector)})].find((b) => b.textContent.trim() === ${JSON.stringify(text)}); if (!el) return false; el.click(); return true; })()`);
const typeInto = (selector, value) => js(`(() => {
  const el = document.querySelector(${JSON.stringify(selector)}); if (!el) return false;
  const proto = el.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, ${JSON.stringify(value)});
  el.dispatchEvent(new Event('input', { bubbles: true })); return true; })()`);

try {
  await connect();
  await send('Page.enable');
  await send('Runtime.enable');
  await send('Emulation.setDeviceMetricsOverride', { width: 1440, height: 900, deviceScaleFactor: 1, mobile: false });
  await send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: 'light' }] });

  // the sign-in page, before signing in
  await go('/', 2500);
  if (!ONLY || ONLY === 'sign-in') await shot('sign-in');

  // sign in as the demo's administrator (fixture credentials), and clear the demo's certificate warnings
  const ids = await js(`(async () => {
    localStorage.setItem('dc-theme', 'light');
    const r = await fetch('/api/v2/session', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ directory: 'acme', name: 'cn=admin,o=system', password: 'admin-pw' }) });
    const me = await r.json();
    const H = { 'Content-Type': 'application/json', 'X-CSRF-Token': me.csrf };
    const t = await (await fetch('/api/v2/trust/certificates')).json();
    for (const a of t.alerts ?? []) await fetch('/api/v2/trust/alerts', { method: 'DELETE', headers: H, body: JSON.stringify({ host: a.host, port: a.port }) });
    for (const c of t.certificates ?? []) {
      if ((new Date(c.notAfter) - Date.now()) / 86400000 < 30) await fetch('/api/v2/trust/certificates/' + (c.key ?? c.id), { method: 'DELETE', headers: H });
    }
    const dn = async (d) => (await (await fetch('/api/v2/trees/acme/objects?dn=' + encodeURIComponent(d))).json()).guid;
    const sets = await (await fetch('/api/v2/trees/acme/idm/driversets')).json();
    const set = await (await fetch('/api/v2/trees/acme/idm/driversets/' + sets.items[0].guid)).json();
    const servers = await (await fetch('/api/v2/trees/acme/edir/servers')).json();
    const ldap = await (await fetch('/api/v2/trees/acme/edir/ldap')).json();
    const pol = await (await fetch('/api/v2/trees/acme/security/password-policies')).json();
    return { status: r.status, pat: await dn('cn=pat,ou=Sales,ou=Users,o=acme'), sales: await dn('ou=Sales,ou=Users,o=acme'),
      users: await dn('ou=Users,o=acme'), set: sets.items[0].guid, driver: set.drivers[0].guid, server: servers[0]?.guid,
      ldapServer: (ldap.servers ?? [])[0]?.guid, staff: pol.find((p) => p.name === 'Staff')?.guid };
  })()`);
  console.log('ids', JSON.stringify(ids));

  const plan = [
    ['browse', async () => { await go(`/browse/${ids.sales}?object=${ids.pat}`, 2500); }],
    ['object-attributes', async () => { await go(`/objects/${ids.pat}`, 2200); }],
    ['set-password', async () => {
      await go(`/objects/${ids.pat}`, 2200);
      await js(`[...document.querySelectorAll('button')].find((b) => b.getAttribute('aria-label') === 'Actions' || b.textContent.trim() === 'Actions').click()`);
      await sleep(400); await clickText('Set password'); await sleep(1200); await clickText('Generate'); await sleep(1500);
    }],
    ['search', async () => {
      await go('/search', 1800);
      await typeInto('#columns', 'title, mail, groupMembership');
      await js(`document.querySelector('input[aria-label=Value]') && (() => { const el = document.querySelector('input[aria-label=Value]'); Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(el, ''); el.dispatchEvent(new Event('input', { bubbles: true })); })()`);
      await js(`(document.querySelector('main form button[type=submit]') ?? [...document.querySelectorAll('main button')].find((b) => b.textContent.trim() === 'Search'))?.click()`); await sleep(2500);
      await js(`(() => { for (let e = [...document.querySelectorAll('table')].pop(); e; e = e.parentElement) e.scrollTop = 0; const h = [...document.querySelectorAll('main h1, main h2')][0]; h?.scrollIntoView({ block: 'start' }); const b = document.querySelector('main form button[type=submit]') ?? [...document.querySelectorAll('main button')].find((x) => x.textContent.trim() === 'Search'); b?.scrollIntoView({ block: 'start' }); })()`); await sleep(300);
    }],
    ['schema', async () => { await go('/schema', 2500); await clickText('inetOrgPerson', 'li, button, a, td, span'); await sleep(1200); }],
    ['edir-partitions', async () => { await go('/edir', 2500); }],
    ['edir-server', async () => { await go(`/edir/servers/${ids.server}`, 2500); }],
    ['edir-ldap-server', async () => { if (ids.ldapServer) await go(`/edir/ldap-servers/${ids.ldapServer}`, 2500); }],
    ['security-certificates', async () => { await go('/security/certificates', 2500); }],
    ['password-policy', async () => {
      await go(`/security/password-policies/${ids.staff}`, 2200);
      await js(`document.querySelector('h2') && [...document.querySelectorAll('h2')].find((h) => h.textContent === 'Test a password')?.scrollIntoView({ block: 'start' })`);
      await sleep(400);
    }],
    ['idm-driver-set', async () => { await go(`/idm/driversets/${ids.set}`, 2800); }],
    ['idm-driver', async () => { await go(`/idm/drivers/${ids.driver}`, 2800); }],
    ['idm-jobs', async () => {
      await go(`/idm/driversets/${ids.set}`, 2800); await clickText('Jobs'); await sleep(1500);
      await js(`[...document.querySelectorAll('table a, table button')].find((a) => a.textContent.trim() === 'Weekly trigger')?.click()`); await sleep(1800);
    }],
    ['audit-log', async () => { await go('/audit', 2500); }],
    ['settings-sso', async () => { await go('/settings?tab=sso', 2500); }],
    ['settings-trusted-certificates', async () => { await go('/settings?tab=trust', 3000); }],
    ['settings-history-backup', async () => { await go('/settings?tab=backup', 2500); }],
    ['settings-console-certificate', async () => { await go('/settings?tab=certificate', 2500); }],
  ];
  for (const [name, run] of plan) {
    if (ONLY && ONLY !== name) continue;
    await run();
    await shot(name);
  }
} finally {
  try { ws?.close(); } catch { /* closing */ }
  chrome.kill();
}
