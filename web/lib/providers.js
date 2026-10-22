// Cloud provider adapters. Every request goes straight from your browser to the
// provider's public API (all three allow cross-origin requests). Nothing is proxied.
(function (root) {
  'use strict';

  const TAG = 'rollavpn';

  class ApiError extends Error {
    constructor(message, status) {
      super(message);
      this.status = status;
    }
  }

  function errorMessage(data) {
    if (!data) return '';
    if (data.message) return data.message; // DigitalOcean
    if (typeof data.detail === 'string') return data.detail; // SporeStack
    if (Array.isArray(data.detail)) return data.detail.map((d) => d.msg).join('; ');
    if (data.error && data.error.message) return data.error.message; // Hetzner
    if (Array.isArray(data.errors)) {
      return data.errors.map((e) => (e.field ? `${e.field}: ` : '') + e.reason).join('; '); // Linode
    }
    return '';
  }

  async function call(base, token, method, path, body, headers) {
    let res;
    try {
      res = await fetch(base + path, {
        method,
        headers: {
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
          ...(body ? { 'Content-Type': 'application/json' } : {}),
          ...headers,
        },
        body: body ? JSON.stringify(body) : undefined,
        cache: 'no-store',
        credentials: 'omit',
        referrerPolicy: 'no-referrer',
      });
    } catch (e) {
      throw new ApiError('Couldn\'t reach the provider. Check your connection or ad blocker.', 0);
    }
    if (res.status === 204) return null;
    const text = await res.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch { data = null; }
    if (!res.ok) {
      const msg = errorMessage(data) || `HTTP ${res.status}`;
      if (res.status === 401) throw new ApiError(`Token rejected (${msg}).`, 401);
      if (res.status === 403) throw new ApiError(`Token is missing a permission (${msg}).`, 403);
      throw new ApiError(msg, res.status);
    }
    return data;
  }

  function serverName() {
    return `${TAG}-${root.RollaWG.randomToken(6).toLowerCase()}`;
  }

  function flag(cc) {
    if (!cc || cc.length !== 2) return '';
    return String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 0x1f1a5 + c.charCodeAt(0)));
  }

  // ---------------------------------------------------------------- DigitalOcean
  const DO_BASE = 'https://api.digitalocean.com/v2';
  const doCall = (t, m, p, b) => call(DO_BASE, t, m, p, b);
  const DO_COUNTRY = { nyc: 'US', sfo: 'US', ams: 'NL', sgp: 'SG', lon: 'GB', fra: 'DE', tor: 'CA', blr: 'IN', syd: 'AU', atl: 'US', ric: 'US' };

  const digitalocean = {
    id: 'digitalocean',
    name: 'DigitalOcean',
    from: 'from $6/mo',
    tokenUrl: 'https://cloud.digitalocean.com/account/api/tokens/new',
    tokenHelp: 'Generate a token with a 1-day expiry. Full Access works, or use Custom Scopes: droplet (create, read, delete), regions:read, sizes:read, tag:create.',
    async list(token) {
      const d = await doCall(token, 'GET', `/droplets?tag_name=${TAG}&per_page=200`);
      return d.droplets.map((s) => ({
        id: s.id,
        name: s.name,
        region: s.region && s.region.name,
        ipv4: ((s.networks.v4 || []).find((n) => n.type === 'public') || {}).ip_address,
        created: s.created_at,
      }));
    },
    async regions(token) {
      const [r, s] = await Promise.all([
        doCall(token, 'GET', '/regions?per_page=200'),
        doCall(token, 'GET', '/sizes?per_page=200'),
      ]);
      // 1 GB minimum: the private DNS resolver with its blocklist needs ~200 MB headroom.
      const sizes = s.sizes.filter((z) => z.available && z.slug.startsWith('s-') && z.memory >= 1024).sort((a, b) => a.price_monthly - b.price_monthly);
      return r.regions
        .filter((reg) => reg.available)
        .map((reg) => {
          const size = sizes.find((z) => z.regions.includes(reg.slug) && reg.sizes.includes(z.slug));
          if (!size) return null;
          return {
            id: reg.slug,
            label: `${flag(DO_COUNTRY[reg.slug.replace(/\d+$/, '')])} ${reg.name}`.trim(),
            plan: size.slug,
            price: `$${size.price_monthly}/mo`,
          };
        })
        .filter(Boolean)
        .sort((a, b) => a.label.localeCompare(b.label));
    },
    async create(token, { region, userData }) {
      const d = await doCall(token, 'POST', '/droplets', {
        name: serverName(),
        region: region.id,
        size: region.plan,
        image: 'ubuntu-24-04-x64',
        ipv6: true,
        monitoring: false,
        user_data: userData,
        tags: [TAG],
      });
      return { id: d.droplet.id, name: d.droplet.name };
    },
    async status(token, id) {
      const { droplet: s } = await doCall(token, 'GET', `/droplets/${id}`);
      const ipv4 = ((s.networks.v4 || []).find((n) => n.type === 'public') || {}).ip_address;
      return { running: s.status === 'active' && !!ipv4, state: s.status, ipv4 };
    },
    async destroy(token, id) {
      await doCall(token, 'DELETE', `/droplets/${id}`);
    },
  };

  // ---------------------------------------------------------------- Hetzner
  const HZ_BASE = 'https://api.hetzner.cloud/v1';
  const hzCall = (t, m, p, b) => call(HZ_BASE, t, m, p, b);

  const hetzner = {
    id: 'hetzner',
    name: 'Hetzner',
    from: 'from ~€4/mo',
    tokenUrl: 'https://console.hetzner.cloud/projects',
    tokenHelp: 'Open a project → Security → API tokens → Generate, with Read & Write.',
    async list(token) {
      const d = await hzCall(token, 'GET', `/servers?label_selector=${TAG}&per_page=50`);
      return d.servers.map((s) => ({
        id: s.id,
        name: s.name,
        region: s.datacenter && s.datacenter.location && s.datacenter.location.city,
        ipv4: s.public_net.ipv4 && s.public_net.ipv4.ip,
        created: s.created,
      }));
    },
    async regions(token) {
      const [l, t] = await Promise.all([
        hzCall(token, 'GET', '/locations'),
        hzCall(token, 'GET', '/server_types?per_page=50'),
      ]);
      const types = t.server_types.filter((st) => st.architecture === 'x86' && !st.deprecation && !st.deprecated);
      return l.locations
        .map((loc) => {
          let best = null;
          for (const st of types) {
            if (Array.isArray(st.locations)) {
              const avail = st.locations.find((x) => x.name === loc.name);
              if (!avail || avail.deprecation) continue;
            }
            const p = st.prices.find((x) => x.location === loc.name);
            if (!p) continue;
            const monthly = parseFloat(p.price_monthly.gross);
            if (!best || monthly < best.monthly) best = { st, monthly };
          }
          if (!best) return null;
          return {
            id: loc.name,
            label: `${flag(loc.country)} ${loc.city}`.trim(),
            plan: best.st.name,
            price: `€${best.monthly.toFixed(2)}/mo + IPv4`,
          };
        })
        .filter(Boolean)
        .sort((a, b) => a.label.localeCompare(b.label));
    },
    async create(token, { region, userData }) {
      const d = await hzCall(token, 'POST', '/servers', {
        name: serverName(),
        server_type: region.plan,
        image: 'ubuntu-24.04',
        location: region.id,
        user_data: userData,
        labels: { [TAG]: '1' },
        public_net: { enable_ipv4: true, enable_ipv6: true },
        start_after_create: true,
      });
      return { id: d.server.id, name: d.server.name };
    },
    async status(token, id) {
      const { server: s } = await hzCall(token, 'GET', `/servers/${id}`);
      const ipv4 = s.public_net.ipv4 && s.public_net.ipv4.ip;
      return { running: s.status === 'running' && !!ipv4, state: s.status, ipv4 };
    },
    async destroy(token, id) {
      await hzCall(token, 'DELETE', `/servers/${id}`);
    },
  };

  // ---------------------------------------------------------------- Linode / Akamai
  const LN_BASE = 'https://api.linode.com/v4';
  const lnCall = (t, m, p, b, h) => call(LN_BASE, t, m, p, b, h);
  const LN_TYPE = 'g6-nanode-1';

  const linode = {
    id: 'linode',
    name: 'Linode (Akamai)',
    from: 'from $5/mo',
    tokenUrl: 'https://cloud.linode.com/profile/tokens',
    tokenHelp: 'Create a Personal Access Token with a short expiry: Linodes Read/Write, everything else No Access.',
    async list(token) {
      const d = await lnCall(token, 'GET', '/linode/instances?page_size=100', null, { 'X-Filter': JSON.stringify({ tags: TAG }) });
      return d.data.map((s) => ({
        id: s.id,
        name: s.label,
        region: s.region,
        ipv4: (s.ipv4 || [])[0],
        created: s.created,
      }));
    },
    async regions(token) {
      const [r, t] = await Promise.all([
        lnCall(token, 'GET', '/regions?page_size=500'),
        lnCall(token, 'GET', `/linode/types/${LN_TYPE}`),
      ]);
      return r.data
        .filter((reg) => reg.status === 'ok' && reg.capabilities.includes('Linodes') && reg.capabilities.includes('Metadata'))
        .map((reg) => {
          const rp = (t.region_prices || []).find((x) => x.id === reg.id);
          const monthly = rp ? rp.monthly : t.price.monthly;
          return {
            id: reg.id,
            label: `${flag(reg.country)} ${reg.label}`.trim(),
            plan: LN_TYPE,
            price: `$${monthly}/mo`,
          };
        })
        .sort((a, b) => a.label.localeCompare(b.label));
    },
    async create(token, { region, userData }) {
      const userDataB64 = root.RollaWG.b64(new TextEncoder().encode(userData));
      if (userDataB64.length > 16384) throw new ApiError('Too many devices for Linode. Remove a few.', 0);
      const d = await lnCall(token, 'POST', '/linode/instances', {
        label: serverName(),
        region: region.id,
        type: region.plan,
        image: 'linode/ubuntu24.04',
        // Linode insists on a root password. It is random, never shown or stored,
        // and the setup script locks the root password anyway.
        root_pass: root.RollaWG.randomToken(40) + '!7',
        metadata: { user_data: userDataB64 },
        tags: [TAG],
        booted: true,
      });
      return { id: d.id, name: d.label };
    },
    async status(token, id) {
      const s = await lnCall(token, 'GET', `/linode/instances/${id}`);
      const ipv4 = (s.ipv4 || []).find((ip) => !/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/.test(ip));
      return { running: s.status === 'running' && !!ipv4, state: s.status, ipv4 };
    },
    async destroy(token, id) {
      await lnCall(token, 'DELETE', `/linode/instances/${id}`);
    },
  };

  // ---------------------------------------------------------------- SporeStack (anonymous)
  // No account, email or ID: the account is a random token, topped up with cryptocurrency.
  // Servers run on Vultr or DigitalOcean under SporeStack's own accounts.
  const SS_BASE = 'https://api.sporestack.com';
  const ssCall = (m, p, b) => call(SS_BASE, null, m, p, b);
  // SporeStack hands user_data to the host as-is. Vultr only accepts it base64-encoded and
  // fails the whole launch otherwise; DigitalOcean wants plain text.
  const SS_HOSTS = {
    vultr: { name: 'Vultr', os: 'ubuntu-24.04', base64UserData: true },
    digitalocean: { name: 'DigitalOcean', os: 'ubuntu-24-04' },
  };
  const tok = (t) => {
    if (!/^ss_t_[A-Za-z0-9_-]{8,}$/.test(t)) throw new ApiError('SporeStack tokens start with "ss_t_".', 0);
    return encodeURIComponent(t);
  };
  const usd = (cents) => `$${(cents / 100).toFixed(2)}`;

  const sporestack = {
    id: 'sporestack',
    name: 'SporeStack',
    from: 'no account · Monero',
    anonymous: true,
    tokenUrl: 'https://sporestack.com/',
    tokenHelp: 'No account or email. Your account is a random token: create one below or paste yours, then top it up with Monero here.',
    async newAccount() {
      let res;
      try {
        res = await fetch(`${SS_BASE}/token`, { cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' });
      } catch {
        throw new ApiError('Couldn\'t reach SporeStack. Check your connection or ad blocker.', 0);
      }
      const t = (await res.text()).trim().replace(/^"|"$/g, '');
      if (!res.ok || !/^ss_t_/.test(t)) throw new ApiError('SporeStack didn\'t return a token. Try again shortly.', res.status);
      return t;
    },
    async balance(token) {
      const i = await ssCall('GET', `/token/${tok(token)}/info`);
      return { cents: i.balance_cents, label: i.balance_usd };
    },
    async list(token) {
      const d = await ssCall('GET', `/token/${tok(token)}/servers`);
      return d.servers.filter((s) => !s.deleted_at).map((s) => ({
        id: s.machine_id,
        name: s.hostname || s.machine_id.slice(0, 10),
        region: s.region,
        ipv4: s.ipv4,
        created: new Date(s.created_at * 1000).toISOString(),
        expires: s.expiration ? new Date(s.expiration * 1000) : null,
      }));
    },
    async regions() {
      const [flavors, regions] = await Promise.all([ssCall('GET', '/slugs/flavors'), ssCall('GET', '/slugs/regions')]);
      const names = Object.fromEntries(regions.map((r) => [`${r.provider}:${r.slug}`, r.name]));
      const out = [];
      for (const host of Object.keys(SS_HOSTS)) {
        // Cheapest daily-billed 1 GB+ server (the private resolver needs the memory).
        const flavor = flavors
          .filter((f) => f.provider === host && f.memory >= 1024 && f.price > 0 && (f.type || 'vps') === 'vps' && !(f.features || []).length)
          .sort((a, b) => a.price - b.price)[0];
        if (!flavor) continue;
        const avail = await ssCall('GET', `/availability/by-flavor/${host}/${flavor.slug}`);
        for (const slug of avail) {
          out.push({
            id: slug,
            host,
            label: `${names[`${host}:${slug}`] || slug} · ${SS_HOSTS[host].name}`,
            plan: flavor.slug,
            price: `~${usd(flavor.price * 30)}/mo (${usd(flavor.price)}/day)`,
          });
        }
      }
      return out.sort((a, b) => a.label.localeCompare(b.label));
    },
    async quote(region, days) {
      const q = await ssCall('GET', `/server/quote?days=${days}&flavor=${encodeURIComponent(region.plan)}&provider=${region.host}`);
      return q.cents;
    },
    async invoice(token, dollars, currency) {
      const d = await ssCall('POST', `/token/${tok(token)}/add`, { currency, dollars });
      return d.invoice;
    },
    async create(token, { region, userData, days, sshKey }) {
      const name = serverName();
      const d = await ssCall('POST', `/token/${tok(token)}/servers`, {
        provider: region.host,
        region: region.id,
        flavor: region.plan,
        operating_system: SS_HOSTS[region.host].os,
        ssh_key: sshKey,
        days,
        autorenew: false,
        hostname: name,
        user_data: SS_HOSTS[region.host].base64UserData ? root.RollaWG.b64(new TextEncoder().encode(userData)) : userData,
      });
      return { id: d.machine_id, name };
    },
    async status(token, id) {
      const s = await ssCall('GET', `/token/${tok(token)}/servers/${encodeURIComponent(id)}`);
      const ipv4 = s.ipv4 && s.ipv4 !== '0.0.0.0' ? s.ipv4 : null;
      return { running: !!s.running && !!ipv4, state: s.running ? 'starting' : 'being created', ipv4, expires: new Date(s.expiration * 1000) };
    },
    async extend(token, id, days) {
      await ssCall('POST', `/token/${tok(token)}/servers/${encodeURIComponent(id)}/topup`, { days });
    },
    async destroy(token, id) {
      await ssCall('DELETE', `/token/${tok(token)}/servers/${encodeURIComponent(id)}`);
    },
  };

  // A machine the user already has. Nothing to call: they run the setup script themselves.
  const own = {
    id: 'own',
    name: 'Your own server',
    from: 'any Ubuntu 24.04 machine',
    manual: true,
  };

  root.RollaProviders = {
    list: [sporestack, digitalocean, hetzner, linode, own],
    byId: { sporestack, digitalocean, hetzner, linode, own },
    ApiError,
  };
})(globalThis);
