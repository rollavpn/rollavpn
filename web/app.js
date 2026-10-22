// UI glue: walks the user through six steps. All state lives in this closure,
// in memory only. Nothing is written to localStorage, cookies or anywhere else;
// the only way it outlives the tab is a save file the user downloads on purpose.
(function () {
  'use strict';

  const WG = globalThis.RollaWG;
  const P = globalThis.RollaProviders;
  const $ = (id) => document.getElementById(id);

  // Time from "server is running" until the setup script has normally finished.
  const INSTALL_SECONDS = 180;

  const state = {
    provider: null,
    token: '',
    regions: [],
    region: null,
    keys: null,
    server: null, // { id, name, ipv4 }
    exit: null, // parsed WireGuard config of the second hop
    balance: 0, // anonymous providers: prepaid balance in cents
    cost: 0, // anonymous providers: price of the chosen run time in cents
    configs: [], // { name, text }
    downloaded: false,
    imported: false, // opened from a save file
  };

  // ------------------------------------------------------------------ helpers
  function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === 'class') node.className = v;
      else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
      else if (v !== false && v != null) node.setAttribute(k, v === true ? '' : v);
    }
    for (const c of children.flat()) if (c != null) node.append(c);
    return node;
  }

  function setStatus(id, msg, kind) {
    const node = $(id);
    node.textContent = msg || '';
    node.className = 'status' + (kind ? ' ' + kind : '');
  }

  function unlock(n) {
    for (let i = 1; i <= 6; i++) {
      const s = $(`step-${i}`);
      s.classList.toggle('locked', i > n);
      s.classList.toggle('done', i < n);
      s.classList.toggle('active', i === n);
    }
    const target = $(`step-${n}`);
    if (n > 1) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  async function busy(btn, label, fn) {
    const old = btn.textContent;
    btn.disabled = true;
    btn.classList.add('loading');
    btn.textContent = label;
    try {
      return await fn();
    } finally {
      btn.disabled = false;
      btn.classList.remove('loading');
      btn.textContent = old;
    }
  }

  function download(name, text) {
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
    const a = el('a', { href: url, download: name });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    state.downloaded = true;
  }

  function drawQR(canvas, text) {
    const qr = globalThis.qrcode(0, 'M');
    qr.addData(text);
    qr.make();
    const n = qr.getModuleCount();
    const margin = 3;
    const scale = Math.max(3, Math.floor(260 / (n + margin * 2)));
    const size = (n + margin * 2) * scale;
    canvas.width = canvas.height = size;
    const ctx = canvas.getContext('2d');
    ctx.fillStyle = '#fff';
    ctx.fillRect(0, 0, size, size);
    ctx.fillStyle = '#000';
    for (let r = 0; r < n; r++) {
      for (let c = 0; c < n; c++) {
        if (qr.isDark(r, c)) ctx.fillRect((c + margin) * scale, (r + margin) * scale, scale, scale);
      }
    }
  }

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  // ------------------------------------------------------------------ step 1
  function renderProviders() {
    const wrap = $('providers');
    for (const p of P.list) {
      const btn = el('button', {
        class: 'provider',
        role: 'radio',
        'aria-checked': 'false',
        'data-id': p.id,
        onclick: () => chooseProvider(p),
      }, el('strong', {}, p.name), el('span', {}, p.from));
      wrap.append(btn);
    }
  }

  // Shows the parts of the page for a cloud provider or for the user's own server.
  function setMode(own) {
    for (const n of document.querySelectorAll('[data-mode]')) n.hidden = n.dataset.mode !== (own ? 'own' : 'cloud');
    $('btn-launch').textContent = own ? 'Get setup script' : 'Launch server';
    updateSshField();
  }

  function updateSshField() {
    $('ssh-field').hidden = !!(state.provider && state.provider.manual && $('keep-ssh').checked);
  }

  function chooseProvider(p) {
    state.provider = p;
    for (const b of $('providers').children) b.setAttribute('aria-checked', String(b.dataset.id === p.id));
    setMode(!!p.manual);
    // WARP by default, except on the user's own machine, which they may want for its own IP.
    $('warp-on').checked = !p.manual;
    $('own-area').hidden = !p.manual;
    $('token-area').hidden = !!p.manual;
    if (p.manual) {
      state.token = '';
      setStatus('status-1', '');
      return;
    }
    $('token-link').href = p.tokenUrl;
    $('token-link').textContent = p.anonymous ? `About ${p.name} ↗` : `Create a ${p.name} API token ↗`;
    $('token-help').textContent = p.tokenHelp;
    $('token-label').textContent = p.anonymous ? `${p.name} token` : 'API token';
    $('token').type = p.anonymous ? 'text' : 'password';
    $('token').placeholder = p.anonymous ? 'ss_t_…' : 'Paste your API token';
    $('btn-new-account').hidden = !p.anonymous;
    $('anon-tip').hidden = !p.anonymous;
    $('token-save').hidden = true;
    $('existing').hidden = true;
    setStatus('status-1', '');
    $('token').focus();
  }

  async function newAccount() {
    try {
      const token = await busy($('btn-new-account'), 'Creating…', () => state.provider.newAccount());
      $('token').value = token;
      $('btn-connect').disabled = false;
      $('token-save').hidden = false;
      setStatus('status-1', 'Account created. Save the token, then Connect.', 'ok');
    } catch (e) {
      setStatus('status-1', e.message, 'bad');
    }
  }

  async function connect() {
    state.token = $('token').value.trim();
    if (!state.token) return;
    setStatus('status-1', '');
    try {
      await busy($('btn-connect'), 'Checking token…', async () => {
        const [existing, regions] = await Promise.all([
          state.provider.list(state.token),
          state.provider.regions(state.token),
        ]);
        state.regions = regions;
        if (state.provider.balance) state.balance = (await state.provider.balance(state.token)).cents;
        renderExisting(existing);
        renderRegions();
      });
      const bal = state.provider.balance ? ` Balance: $${(state.balance / 100).toFixed(2)}.` : '';
      setStatus('status-1', `Connected to ${state.provider.name}.${bal}`, 'ok');
      unlock(2);
    } catch (e) {
      setStatus('status-1', e.message, 'bad');
    }
  }

  function renderExisting(servers) {
    const list = $('existing-list');
    list.replaceChildren();
    $('existing').hidden = servers.length === 0;
    for (const s of servers) {
      const status = el('span', { class: 'muted' });
      const del = el('button', { class: 'btn small danger-btn' }, 'Delete');
      del.addEventListener('click', async () => {
        if (!confirm(`Delete ${s.name}? Devices using it will stop working.`)) return;
        try {
          await busy(del, 'Deleting…', () => state.provider.destroy(state.token, s.id));
          li.classList.add('gone');
          status.textContent = 'deleted';
          del.remove();
        } catch (e) {
          status.textContent = e.message;
        }
      });
      let extend = null;
      if (state.provider.extend) {
        extend = el('button', { class: 'btn small' }, '+30 days');
        extend.addEventListener('click', async () => {
          try {
            await busy(extend, 'Adding…', () => state.provider.extend(state.token, s.id, 30));
            status.textContent = 'extended by 30 days';
          } catch (e) {
            status.textContent = e.message;
          }
        });
      }
      const expiry = s.expires ? ` · paid until ${s.expires.toLocaleDateString()}` : '';
      const li = el('li', {},
        el('span', {}, el('strong', {}, s.name), ` · ${s.region || ''} · ${s.ipv4 || 'no IP'}${expiry}`),
        status, el('span', { class: 'row tight' }, extend, del));
      list.append(li);
    }
  }

  // ------------------------------------------------------------------ step 2
  // IPv4, IPv6 or a hostname. IPv6 goes in brackets so it can be followed by :port.
  function parseEndpoint(text) {
    const t = String(text || '').trim().replace(/^\[|\]$/g, '');
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(t) && t.split('.').every((n) => Number(n) <= 255)) return t;
    if (/^[0-9a-f:]+$/i.test(t) && t.includes(':')) return `[${t.toLowerCase()}]`;
    if (/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(t)) return t.toLowerCase();
    return null;
  }

  function useOwnServer() {
    unlock(2);
    $('own-endpoint').focus();
  }

  function chooseEndpoint() {
    const endpoint = parseEndpoint($('own-endpoint').value);
    if (!endpoint) {
      setStatus('status-2', 'Enter a public IP or hostname.', 'bad');
      return;
    }
    if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.)/.test(endpoint)) {
      setStatus('status-2', "That's a private address. Use the public one.", 'bad');
      return;
    }
    if (/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(endpoint)) {
      setStatus('status-2', 'That\'s a CGNAT address, which can\'t be reached from outside.', 'bad');
      return;
    }
    setStatus('status-2', '');
    state.region = { label: endpoint };
    state.server = { id: endpoint, name: 'rollavpn-own', ipv4: endpoint };
    unlock(3);
  }

  function renderRegions() {
    const sel = $('region');
    sel.replaceChildren(...state.regions.map((r, i) => el('option', { value: i }, r.label)));
    updatePrice();
  }

  function updatePrice() {
    const r = state.regions[$('region').value];
    $('price').textContent = r ? `${r.price} · server size ${r.plan}` : '';
  }

  function chooseRegion() {
    state.region = state.regions[$('region').value];
    if (!state.region) return;
    unlock(3);
  }

  // ------------------------------------------------------------------ step 3
  function addDeviceRow(name) {
    const rows = $('devices');
    if (rows.children.length >= 20) return;
    const input = el('input', { type: 'text', value: name || '', placeholder: 'device name', maxlength: '24', spellcheck: 'false', 'aria-label': 'Device name' });
    const remove = el('button', { class: 'icon-btn', 'aria-label': 'Remove device', title: 'Remove' }, '×');
    const row = el('div', { class: 'device' }, input, remove);
    remove.addEventListener('click', () => { if (rows.children.length > 1) row.remove(); });
    rows.append(row);
    return input;
  }

  function renderDns() {
    const sel = $('dns');
    for (const [k, v] of Object.entries(WG.DNS)) sel.append(el('option', { value: k }, v.label));
    sel.value = 'own-block';
  }

  function readExit() {
    setStatus('exit-status', '');
    if (!$('exit-on').checked) {
      state.exit = null;
      return true;
    }
    try {
      state.exit = WG.parseExitConfig($('exit-conf').value);
      if (!state.exit) throw new Error('Paste the device config from your second server, or untick Second hop.');
      setStatus('exit-status', `✓ Second hop via ${state.exit.endpoint}.`, 'ok');
      return true;
    } catch (e) {
      state.exit = null;
      setStatus('exit-status', e.message, 'bad');
      return false;
    }
  }

  async function makeKeys() {
    if (!readExit()) return;
    const names = [...$('devices').querySelectorAll('input')].map((i) => i.value);
    const btn = $('btn-keys');
    await busy(btn, 'Generating…', async () => {
      state.keys = await WG.generateKeys(names, state.exit && state.exit.address4);
    });
    const out = $('keys-out');
    out.hidden = false;
    out.replaceChildren(
      el('p', { class: 'ok' }, `✓ ${state.keys.peers.length + 1} key pairs made. Public keys:`),
      el('table', {},
        el('tbody', {},
          el('tr', {}, el('th', {}, 'server'), el('td', {}, el('code', {}, state.keys.server.publicKey))),
          state.keys.peers.map((p) => el('tr', {}, el('th', {}, p.name), el('td', {}, el('code', {}, p.publicKey)))))),
    );
    btn.textContent = 'Regenerate keys';
    renderSummary();
    unlock(4);
  }

  // ------------------------------------------------------------------ step 4
  function options() {
    const keepLogins = !!(state.provider.manual && $('keep-ssh').checked);
    const warp = !state.exit && $('warp-on').checked;
    return { port: Number($('port').value), dns: $('dns').value, sshKey: keepLogins ? '' : $('ssh').value, exit: state.exit, keepLogins, warp };
  }

  function renderSummary() {
    const o = options();
    const own = !!state.provider.manual;
    const rows = [
      ['Provider', state.provider.name],
      [own ? 'Address' : 'Location', state.region.label],
      ...(own ? [] : [['Cost', state.region.price]]),
      ...(own ? [] : [['Pays', state.provider.anonymous ? 'Prepaid token' : `Your ${state.provider.name} account`]]),
      ['Exit', o.exit ? `Second hop at ${o.exit.endpoint} (kill switch on)` : o.warp ? 'Cloudflare WARP (kill switch on)' : 'Your server'],
      ['Devices', state.keys.peers.map((p) => p.name).join(', ')],
      ['DNS', WG.DNS[o.dns].label],
      ['Port', `UDP ${o.port}`],
      ['SSH', o.keepLogins ? 'Unchanged' : o.sshKey.trim() ? 'Your key only' : 'Off'],
    ];
    $('summary').replaceChildren(...rows.flatMap(([k, v]) => [el('dt', {}, k), el('dd', {}, v)]));
    let script;
    try {
      script = WG.serverScript({ keys: state.keys, ...o });
    } catch (e) {
      script = `Error: ${e.message}`;
    }
    // Hide the server private key on screen; it's still in the script that's sent.
    let n = 0;
    $('script-preview').textContent = script.replace(/^PrivateKey = [A-Za-z0-9+/]{43}=$/gm, () => (n++ === 0
      ? 'PrivateKey = ••••••••  (server key, hidden)'
      : 'PrivateKey = ••••••••  (second hop key, hidden)'));
    $('billing').hidden = !state.provider.anonymous;
    if (own) $('btn-launch').disabled = false;
    if (state.provider.anonymous) updateQuote();
    else $('btn-launch').disabled = false;
  }

  // ---- anonymous payment (SporeStack)
  let payTimer = null;

  async function updateQuote() {
    const days = Number($('days').value);
    try {
      state.cost = await state.provider.quote(state.region, days);
      state.balance = (await state.provider.balance(state.token)).cents;
    } catch (e) {
      setStatus('status-pay', e.message, 'bad');
      return;
    }
    const enough = state.balance >= state.cost;
    $('quote').textContent = `${days} days: $${(state.cost / 100).toFixed(2)} · balance: $${(state.balance / 100).toFixed(2)}`;
    $('btn-launch').disabled = !enough;
    $('topup').hidden = enough;
    if (!enough && !$('dollars').value) $('dollars').value = Math.max(5, Math.ceil((state.cost - state.balance) / 100));
    if (enough) {
      clearInterval(payTimer);
      payTimer = null;
      if (!$('invoice').hidden) setStatus('status-pay', 'Payment received.', 'ok');
      $('invoice').hidden = true;
    }
  }

  async function createInvoice() {
    const dollars = Math.max(5, Math.round(Number($('dollars').value) || 0));
    const currency = $('currency').value;
    let inv;
    try {
      inv = await busy($('btn-invoice'), 'Creating…', () => state.provider.invoice(state.token, dollars, currency));
    } catch (e) {
      setStatus('status-pay', e.message, 'bad');
      return;
    }
    const uri = inv.payment_uri;
    const [, addr = uri, query = ''] = uri.match(/^[a-z]+:([^?]+)\??(.*)$/i) || [];
    const params = new URLSearchParams(query);
    const amount = params.get('tx_amount') || params.get('amount') || '';
    $('invoice').hidden = false;
    $('invoice-amount').textContent = `${amount} ${currency.toUpperCase()}`.trim();
    $('invoice-address').textContent = addr;
    $('invoice-open').href = uri;
    $('invoice-expiry').textContent = inv.expires ? `Expires at ${new Date(inv.expires * 1000).toLocaleTimeString()}.` : '';
    drawQR($('invoice-qr'), uri);
    setStatus('status-pay', currency === 'xmr'
      ? 'Waiting for payment… Monero takes 10–20 minutes to confirm.'
      : 'Waiting for payment…');
    clearInterval(payTimer);
    payTimer = setInterval(updateQuote, 20000);
  }

  async function launch() {
    const o = options();
    let userData;
    try {
      userData = WG.serverScript({ keys: state.keys, ...o });
    } catch (e) {
      setStatus('status-4', e.message, 'bad');
      return;
    }
    setStatus('status-4', '');
    if (state.provider.manual) {
      state.options = o;
      state.script = userData;
      $('own-scp').textContent = `scp rollavpn-setup.sh you@${state.server.ipv4}:`; // IPv6 keeps its brackets, as scp needs
      for (const n of document.querySelectorAll('.own-port')) n.textContent = o.port;
      lockInputs();
      unlock(5);
      buildConfigs();
      $('step-5').scrollIntoView({ behavior: 'smooth', block: 'start' });
      return;
    }
    try {
      const days = Number($('days').value);
      const sshKey = o.sshKey.trim() || await WG.lockedSshKey();
      const server = await busy($('btn-launch'), 'Ordering server…', () =>
        state.provider.create(state.token, { region: state.region, userData, days, sshKey }));
      state.server = server;
      state.options = o;
      lockInputs();
      unlock(5);
      watch();
    } catch (e) {
      setStatus('status-4', e.message, 'bad');
    }
  }

  function lockInputs() {
    clearInterval(payTimer);
    for (const id of ['btn-connect', 'btn-new-account', 'btn-region', 'btn-keys', 'btn-launch', 'btn-add-device', 'token', 'region', 'dns', 'port', 'ssh', 'exit-on', 'exit-conf', 'days', 'btn-invoice', 'btn-own', 'own-endpoint', 'btn-own-endpoint', 'keep-ssh', 'warp-on']) {
      $(id).disabled = true;
    }
    for (const b of $('providers').children) b.disabled = true;
    for (const i of $('devices').querySelectorAll('input, button')) i.disabled = true;
  }

  // ------------------------------------------------------------------ step 5
  function mark(k, cls) {
    const li = $('progress').querySelector(`[data-k="${k}"]`);
    li.className = cls;
  }

  function setBar(frac) {
    $('bar-fill').style.width = `${Math.round(Math.min(1, frac) * 100)}%`;
  }

  async function watch() {
    mark('create', 'done');
    mark('boot', 'doing');
    setBar(0.08);
    let info;
    const started = Date.now();
    for (;;) {
      try {
        info = await state.provider.status(state.token, state.server.id);
        if (info.running) break;
        setStatus('status-5', `Server is ${info.state}…`);
      } catch (e) {
        setStatus('status-5', `Still waiting (${e.message})`, 'warn');
      }
      setBar(0.08 + Math.min(0.22, (Date.now() - started) / 1000 / 90 * 0.22));
      await sleep(4000);
    }
    state.server.ipv4 = info.ipv4;
    mark('boot', 'done');
    mark('install', 'doing');
    buildConfigs();

    const t0 = Date.now();
    for (;;) {
      const elapsed = (Date.now() - t0) / 1000;
      const left = Math.max(0, Math.ceil(INSTALL_SECONDS - elapsed));
      setBar(0.3 + 0.7 * (elapsed / INSTALL_SECONDS));
      setStatus('status-5', left > 0
        ? `Up at ${info.ipv4}. Setting up, about ${left}s left. You can save your configs now.`
        : '');
      if (left === 0) break;
      await sleep(1000);
    }
    mark('install', 'done');
    mark('ready', 'done');
    const paid = info.expires ? ` Paid until ${info.expires.toLocaleDateString()}.` : '';
    const via = state.options.exit ? ' Sites see your second server.'
      : state.options.warp ? ' Sites see a Cloudflare address.' : '';
    setStatus('status-5', `Your VPN is running at ${info.ipv4}.${via}${paid}`, 'ok');
    $('step-5').classList.add('done');
    $('step-5').classList.remove('active');
  }

  // ------------------------------------------------------------------ step 6
  function buildConfigs() {
    for (const n of document.querySelectorAll('.provider-name')) n.textContent = state.provider.name;
    const { port, dns } = state.options;
    state.configs = state.keys.peers.map((peer) => ({
      name: peer.name,
      text: WG.clientConfig({ keys: state.keys, peer, endpoint: state.server.ipv4, port, dns }),
    }));
    const wrap = $('clients');
    wrap.replaceChildren();
    for (const c of state.configs) {
      const canvas = el('canvas', { class: 'qr', 'aria-label': `QR code for ${c.name}` });
      const fname = `rollavpn-${c.name}.conf`;
      const copyBtn = el('button', { class: 'btn small' }, 'Copy');
      copyBtn.addEventListener('click', async () => {
        await navigator.clipboard.writeText(c.text);
        copyBtn.textContent = 'Copied ✓';
        state.downloaded = true;
        setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1500);
      });
      const card = el('article', { class: 'client' },
        el('h3', {}, c.name),
        canvas,
        el('div', { class: 'row' },
          el('button', { class: 'btn small primary', onclick: () => download(fname, c.text) }, `Download ${fname}`),
          copyBtn),
        el('details', {}, el('summary', {}, 'Show config text'), el('pre', {}, c.text)));
      wrap.append(card);
      drawQR(canvas, c.text);
    }
    $('step-6').classList.remove('locked');
    $('step-6').classList.add('active');
  }

  function downloadAll() {
    for (const c of state.configs) download(`rollavpn-${c.name}.conf`, c.text);
  }

  async function destroy() {
    if (!state.server || state.server.deleted) return;
    if (!confirm('Delete this server? Every device using it will stop working.')) return;
    try {
      await busy($('btn-destroy'), 'Deleting…', () => state.provider.destroy(state.token, state.server.id));
      const after = state.provider.anonymous ? 'Delete your save file.' : 'Delete your save file and revoke your API token.';
      setStatus('status-6', `Server deleted. ${after}`, 'ok');
      $('btn-destroy').disabled = true;
      $('btn-extend').disabled = true;
      $('btn-refresh').disabled = true;
      state.server.deleted = true;
      state.downloaded = true;
    } catch (e) {
      setStatus('status-6', e.message, 'bad');
    }
  }

  // ------------------------------------------------------------------ save file
  // A JSON file with everything needed to manage this VPN later. With a password it's
  // encrypted with AES-256-GCM under a PBKDF2-SHA256 key, all via WebCrypto.
  const SAVE_FORMAT = 'rollavpn-save';
  const KDF_ITERATIONS = 600000;
  const KEY_RE = /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$/;

  function unb64(text) {
    return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
  }

  async function passwordKey(password, salt, iterations) {
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, base,
      { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }

  function snapshot() {
    const { port, dns, sshKey, exit, keepLogins, warp } = state.options;
    return {
      provider: state.provider.id,
      token: state.token,
      server: { id: state.server.id, name: state.server.name, ipv4: state.server.ipv4, region: state.region ? state.region.label : '' },
      keys: state.keys,
      options: { port, dns, sshKey, exit, keepLogins, warp },
    };
  }

  async function saveFile() {
    const pass = $('save-pass').value;
    if (pass && pass.length < 8) {
      setStatus('status-save', 'Use at least 8 characters.', 'bad');
      return;
    }
    if (pass !== $('save-pass2').value) {
      setStatus('status-save', "The passwords don't match.", 'bad');
      return;
    }
    if (!pass && !confirm('Save without a password? Anyone with the file gets every key and your token.')) return;
    const file = {
      format: SAVE_FORMAT,
      version: 1,
      saved: new Date().toISOString(),
      warning: 'Keep this file secret. It contains private keys and your provider token.',
    };
    const json = JSON.stringify(snapshot());
    if (pass) {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const iv = crypto.getRandomValues(new Uint8Array(12));
      await busy($('btn-save'), 'Encrypting…', async () => {
        const key = await passwordKey(pass, salt, KDF_ITERATIONS);
        const data = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(json)));
        file.encrypted = { kdf: 'PBKDF2-SHA256', iterations: KDF_ITERATIONS, salt: WG.b64(salt), cipher: 'AES-256-GCM', iv: WG.b64(iv), data: WG.b64(data) };
      });
    } else {
      file.vpn = JSON.parse(json);
    }
    download(`${state.server.name}-save.json`, JSON.stringify(file, null, 2) + '\n');
    $('save-pass').value = $('save-pass2').value = '';
    setStatus('status-save', pass
      ? '✓ Saved and encrypted. The password can\'t be recovered.'
      : '✓ Saved without a password.', 'ok');
  }

  let restoreFile = null;

  async function pickRestoreFile() {
    restoreFile = null;
    $('btn-restore').disabled = true;
    $('restore-pass-wrap').hidden = true;
    setStatus('status-restore', '');
    const f = $('restore-file').files[0];
    if (!f) return;
    try {
      if (f.size > 1e6) throw new Error();
      const data = JSON.parse(await f.text());
      if (!data || data.format !== SAVE_FORMAT) throw new Error();
      restoreFile = data;
    } catch {
      setStatus('status-restore', "That isn't a rollavpn save file.", 'bad');
      return;
    }
    $('restore-pass-wrap').hidden = !restoreFile.encrypted;
    $('btn-restore').disabled = false;
    if (restoreFile.encrypted) $('restore-pass').focus();
  }

  function checkSave(v) {
    const bad = (what) => { throw new Error(`This save file looks damaged (${what}).`); };
    if (!v || typeof v !== 'object' || !Object.hasOwn(P.byId, v.provider)) bad('unknown provider');
    const manual = P.byId[v.provider].manual;
    if (typeof v.token !== 'string' || (!v.token && !manual)) bad('token');
    const s = v.server || {};
    if (!['string', 'number'].includes(typeof s.id) || typeof s.name !== 'string') bad('server');
    if (!(manual ? parseEndpoint(s.ipv4) === s.ipv4 : /^\d{1,3}(\.\d{1,3}){3}$/.test(s.ipv4 || ''))) bad('server address');
    const k = v.keys || {};
    if (!k.server || !KEY_RE.test(k.server.publicKey) || !KEY_RE.test(k.server.privateKey)) bad('server key');
    if (!k.net || !/^10\.\d{1,3}\.\d{1,3}$/.test(k.net.v4) || !/^fd[0-9a-f]{2}:[0-9a-f]{1,4}:[0-9a-f]{1,4}:$/.test(k.net.v6)) bad('addresses');
    if (!Array.isArray(k.peers) || !k.peers.length) bad('devices');
    for (const p of k.peers) {
      if (!/^[A-Za-z0-9_-]{1,40}$/.test(p.name) || ![p.privateKey, p.publicKey, p.presharedKey].every((x) => KEY_RE.test(x))
        || !String(p.address4).startsWith(k.net.v4 + '.') || !String(p.address6).startsWith(k.net.v6)) bad('a device');
    }
    const o = v.options || {};
    if (!Object.hasOwn(WG.DNS, o.dns)) bad('DNS');
    if (!Number.isInteger(o.port) || o.port < 1 || o.port > 65535) bad('port');
  }

  async function restore() {
    let vpn = restoreFile.vpn;
    try {
      if (restoreFile.encrypted) {
        const e = restoreFile.encrypted;
        if (e.kdf !== 'PBKDF2-SHA256' || e.cipher !== 'AES-256-GCM') throw new Error('This save file uses an unknown encryption.');
        const pass = $('restore-pass').value;
        if (!pass) throw new Error('Enter the file\'s password.');
        vpn = await busy($('btn-restore'), 'Decrypting…', async () => {
          try {
            const key = await passwordKey(pass, unb64(e.salt), e.iterations);
            const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(e.iv) }, key, unb64(e.data));
            return JSON.parse(new TextDecoder().decode(plain));
          } catch {
            throw new Error('Wrong password, or the file is damaged.');
          }
        });
      }
      checkSave(vpn);
    } catch (e) {
      setStatus('status-restore', e.message, 'bad');
      return;
    }
    $('restore-pass').value = '';
    const o = vpn.options;
    state.provider = P.byId[vpn.provider];
    state.token = vpn.token;
    state.server = { id: vpn.server.id, name: vpn.server.name, ipv4: vpn.server.ipv4 };
    state.region = { label: vpn.server.region || '' };
    state.keys = vpn.keys;
    state.exit = o.exit || null;
    state.options = { port: o.port, dns: o.dns, sshKey: o.sshKey || '', exit: state.exit, keepLogins: !!o.keepLogins, warp: !!o.warp };
    state.imported = true;
    state.downloaded = true;

    for (let i = 1; i <= 5; i++) $(`step-${i}`).hidden = true;
    $('restore').hidden = true;
    $('save-now').hidden = true;
    $('manage').hidden = false;
    $('btn-extend').hidden = !state.provider.extend;
    setMode(!!state.provider.manual);
    $('btn-refresh').hidden = !!state.provider.manual;
    buildConfigs();
    $('step-6').scrollIntoView({ block: 'start' });
    refreshStatus();
  }

  async function refreshStatus() {
    if (state.server.deleted) return;
    if (state.provider.manual) {
      setStatus('manage-status', `Your own server at ${state.server.ipv4}. rollavpn can't check on it; manage it directly.`);
      return;
    }
    const where = state.region.label ? ` in ${state.region.label}` : '';
    try {
      const info = await busy($('btn-refresh'), 'Checking…', () => state.provider.status(state.token, state.server.id));
      $('retoken').hidden = true;
      let moved = '';
      if (info.ipv4 && info.ipv4 !== state.server.ipv4) {
        state.server.ipv4 = info.ipv4;
        buildConfigs();
        moved = ' Its address changed, so the configs are updated. Save the file again.';
      }
      const paid = info.expires ? ` Paid until ${info.expires.toLocaleDateString()}.` : '';
      const now = info.running ? `running at ${info.ipv4}` : info.state;
      setStatus('manage-status', `${state.server.name}, ${state.provider.name}${where}: ${now}.${paid}${moved}`, info.running ? 'ok' : 'warn');
    } catch (e) {
      if (e.status === 401 || e.status === 403) {
        setStatus('manage-status', `${e.message} Paste a new ${state.provider.name} token below.`, 'bad');
        $('retoken').hidden = false;
      } else if (e.status === 404) {
        setStatus('manage-status', `${state.server.name} no longer exists. It was deleted or ran out of paid time.`, 'warn');
        $('btn-destroy').disabled = true;
        $('btn-extend').disabled = true;
      } else {
        setStatus('manage-status', e.message, 'bad');
      }
    }
  }

  async function extendServer() {
    try {
      await busy($('btn-extend'), 'Adding…', () => state.provider.extend(state.token, state.server.id, 30));
      await refreshStatus();
    } catch (e) {
      setStatus('manage-status', e.message, 'bad');
    }
  }

  function useNewToken() {
    const t = $('retoken-input').value.trim();
    if (!t) return;
    state.token = t;
    $('retoken-input').value = '';
    setStatus('status-save', 'Token changed. Download the save file again.', 'warn');
    refreshStatus();
  }

  // ------------------------------------------------------------------ init
  function init() {
    if (!globalThis.crypto || !crypto.subtle) {
      $('unsupported').hidden = false;
      return;
    }
    crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']).catch(() => { $('unsupported').hidden = false; });

    renderProviders();
    renderDns();
    ['phone', 'laptop'].forEach(addDeviceRow);

    $('token').addEventListener('input', () => { $('btn-connect').disabled = !$('token').value.trim(); });
    $('token').addEventListener('keydown', (e) => { if (e.key === 'Enter') connect(); });
    $('btn-connect').addEventListener('click', connect);
    $('btn-new-account').addEventListener('click', newAccount);
    $('warp-on').addEventListener('change', () => { if (state.keys) renderSummary(); });
    $('exit-on').addEventListener('change', () => {
      $('exit-area').hidden = !$('exit-on').checked;
      $('warp-on').disabled = $('exit-on').checked;
      if ($('exit-on').checked) $('exit-conf').focus();
      if (state.keys) { readExit(); renderSummary(); }
    });
    $('exit-conf').addEventListener('change', () => { readExit(); if (state.keys) renderSummary(); });
    $('days').addEventListener('change', updateQuote);
    $('btn-invoice').addEventListener('click', createInvoice);
    $('btn-copy-address').addEventListener('click', () => navigator.clipboard.writeText($('invoice-address').textContent));
    $('region').addEventListener('change', updatePrice);
    $('btn-region').addEventListener('click', chooseRegion);
    $('btn-add-device').addEventListener('click', () => addDeviceRow('').focus());
    $('btn-keys').addEventListener('click', makeKeys);
    for (const id of ['dns', 'port', 'ssh']) $(id).addEventListener('change', () => { if (state.keys) renderSummary(); });
    $('btn-launch').addEventListener('click', launch);
    $('btn-download-all').addEventListener('click', downloadAll);
    $('btn-destroy').addEventListener('click', destroy);
    $('btn-save').addEventListener('click', saveFile);
    $('btn-own').addEventListener('click', useOwnServer);
    $('btn-own-endpoint').addEventListener('click', chooseEndpoint);
    $('own-endpoint').addEventListener('keydown', (e) => { if (e.key === 'Enter') chooseEndpoint(); });
    $('keep-ssh').addEventListener('change', () => { updateSshField(); if (state.keys) renderSummary(); });
    $('btn-dl-script').addEventListener('click', () => download('rollavpn-setup.sh', state.script));
    $('btn-copy-script').addEventListener('click', async () => {
      await navigator.clipboard.writeText(state.script);
      $('btn-copy-script').textContent = 'Copied ✓';
      setTimeout(() => { $('btn-copy-script').textContent = 'Copy script'; }, 1500);
    });
    $('restore-file').addEventListener('change', pickRestoreFile);
    $('restore-pass').addEventListener('keydown', (e) => { if (e.key === 'Enter') restore(); });
    $('btn-restore').addEventListener('click', restore);
    $('btn-refresh').addEventListener('click', refreshStatus);
    $('btn-extend').addEventListener('click', extendServer);
    $('btn-retoken').addEventListener('click', useNewToken);
    $('btn-start-over').addEventListener('click', () => location.reload());

    window.addEventListener('beforeunload', (e) => {
      if (state.configs.length && !state.downloaded) {
        e.preventDefault();
        e.returnValue = '';
      }
    });

    setMode(false);
    unlock(1);
  }

  init();
})();
