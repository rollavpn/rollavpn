// WireGuard key generation and config/script templating.
// Runs entirely in the browser (or Node >= 20 for tests). No network access.
(function (root) {
  'use strict';


  // HaGeZi "Multi PRO mini": ads, trackers, telemetry, malware, phishing (~145k domains).
  // The "mini" edition keeps memory use low enough for a 512 MB server.
  const BLOCKLIST_URL = 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/rpz/pro.mini.txt';

  const DNS = {
    'own-block': { label: 'Your server, blocking ads and trackers', unbound: true, block: true },
    own: { label: 'Your server, no blocking', unbound: true },
    quad9: { label: 'Quad9 (9.9.9.9)', servers: ['9.9.9.9', '149.112.112.112', '2620:fe::fe'] },
    cloudflare: { label: 'Cloudflare (1.1.1.1)', servers: ['1.1.1.1', '1.0.0.1', '2606:4700:4700::1111'] },
  };

  function b64(bytes) {
    let s = '';
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s);
  }

  async function genKeyPair() {
    const kp = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
    const pub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey));
    // PKCS#8 for X25519 is a fixed 16-byte header followed by the 32-byte scalar.
    const priv = pkcs8.slice(pkcs8.length - 32);
    // Clamp like `wg genkey` does. X25519 clamps internally, so the public key is unchanged.
    priv[0] &= 248;
    priv[31] &= 127;
    priv[31] |= 64;
    return { privateKey: b64(priv), publicKey: b64(pub) };
  }

  function genPresharedKey() {
    return b64(crypto.getRandomValues(new Uint8Array(32)));
  }

  function randomToken(len) {
    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
    const out = [];
    while (out.length < len) {
      for (const b of crypto.getRandomValues(new Uint8Array(len * 2))) {
        if (b < 4 * alphabet.length) out.push(alphabet[b % alphabet.length]); // avoids modulo bias
        if (out.length === len) break;
      }
    }
    return out.join('');
  }

  // Each VPN gets its own random private subnet (10.16–239.x.0/24 and a random fd00::/8 /64),
  // so two rollavpn servers can be chained as a second hop without their addresses clashing.
  function randomNet(avoid4) {
    for (;;) {
      const r = crypto.getRandomValues(new Uint8Array(7));
      const hex = (a, b) => ((a << 8) | b).toString(16);
      const net = { v4: `10.${16 + (r[0] % 224)}.${r[1]}`, v6: `fd${r[2].toString(16).padStart(2, '0')}:${hex(r[3], r[4])}:${hex(r[5], r[6])}:` };
      if (!avoid4 || !String(avoid4).startsWith(net.v4 + '.')) return net;
    }
  }

  function inNet(keys, address4) {
    return String(address4 || '').startsWith(keys.net.v4 + '.');
  }

  function dnsServers(keys, dns) {
    return DNS[dns].unbound ? [`${keys.net.v4}.1`, `${keys.net.v6}:1`] : DNS[dns].servers;
  }

  function sanitizeName(name, i) {
    const clean = String(name || '').trim().replace(/[^A-Za-z0-9_-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 24);
    return clean || `device-${i + 1}`;
  }

  // Generates everything needed for a VPN: one server keypair, one keypair + PSK per device.
  // avoid4: an address (the second hop's) that must not fall inside this VPN's subnet.
  async function generateKeys(deviceNames, avoid4) {
    const server = await genKeyPair();
    const net = randomNet(avoid4);
    const used = new Set();
    const peers = [];
    for (let i = 0; i < deviceNames.length; i++) {
      let name = sanitizeName(deviceNames[i], i);
      while (used.has(name)) name += '-' + (i + 1);
      used.add(name);
      const kp = await genKeyPair();
      peers.push({
        name,
        ...kp,
        presharedKey: genPresharedKey(),
        address4: `${net.v4}.${i + 2}`,
        address6: `${net.v6}:${(i + 2).toString(16)}`,
      });
    }
    return { server, peers, net };
  }

  function clientConfig({ keys, peer, endpoint, port, dns }) {
    return [
      '[Interface]',
      `# rollavpn: ${peer.name}`,
      `PrivateKey = ${peer.privateKey}`,
      `Address = ${peer.address4}/32, ${peer.address6}/128`,
      `DNS = ${dnsServers(keys, dns).join(', ')}`,
      '',
      '[Peer]',
      `PublicKey = ${keys.server.publicKey}`,
      `PresharedKey = ${peer.presharedKey}`,
      `Endpoint = ${endpoint}:${port}`,
      'AllowedIPs = 0.0.0.0/0, ::/0',
      'PersistentKeepalive = 25',
      '',
    ].join('\n');
  }

  const KEY_RE = /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$/;

  // Parses a WireGuard client config (normally a device config from a second rollavpn server)
  // to use as this server's upstream exit, the second hop. Returns null for empty input; throws on bad input.
  function parseExitConfig(text) {
    if (!String(text || '').trim()) return null;
    const sections = { interface: {}, peer: {} };
    let cur = null;
    for (const raw of String(text).split(/\r?\n/)) {
      const line = raw.replace(/#.*/, '').trim();
      if (!line) continue;
      const sec = line.match(/^\[(\w+)\]$/);
      if (sec) {
        cur = sec[1].toLowerCase();
        if (cur === 'peer' && Object.keys(sections.peer).length) throw new Error('Second-hop config: needs exactly one [Peer].');
        continue;
      }
      const kv = line.match(/^(\w+)\s*=\s*(.+)$/);
      if (kv && sections[cur]) sections[cur][kv[1].toLowerCase()] = kv[2].trim();
    }
    const i = sections.interface;
    const pr = sections.peer;
    if (!KEY_RE.test(i.privatekey || '')) throw new Error('Second-hop config: missing [Interface] PrivateKey.');
    if (!KEY_RE.test(pr.publickey || '')) throw new Error('Second-hop config: missing [Peer] PublicKey.');
    if (pr.presharedkey && !KEY_RE.test(pr.presharedkey)) throw new Error('Second-hop config: bad PresharedKey.');
    if (!/^([A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\]):\d{1,5}$/.test(pr.endpoint || '')) throw new Error('Second-hop config: missing [Peer] Endpoint.');
    const addrs = (i.address || '').split(',').map((a) => a.trim().replace(/\/\d+$/, '')).filter(Boolean);
    const address4 = addrs.find((a) => /^\d{1,3}(\.\d{1,3}){3}$/.test(a));
    const address6 = addrs.find((a) => /^[0-9A-Fa-f:]+$/.test(a) && a.includes(':'));
    if (!address4) throw new Error('Second-hop config: needs an IPv4 Address.');
    return { privateKey: i.privatekey, address4, address6: address6 || null, publicKey: pr.publickey, presharedKey: pr.presharedkey || null, endpoint: pr.endpoint };
  }

  // An SSH public key whose private half is thrown away immediately, for providers that insist
  // on one. Nobody can ever log in with it (and the setup script switches SSH off anyway).
  async function lockedSshKey() {
    let pub;
    try {
      const kp = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
      pub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
    } catch {
      pub = crypto.getRandomValues(new Uint8Array(32));
    }
    const type = new TextEncoder().encode('ssh-ed25519');
    const blob = new Uint8Array(4 + type.length + 4 + 32);
    const view = new DataView(blob.buffer);
    view.setUint32(0, type.length);
    blob.set(type, 4);
    view.setUint32(4 + type.length, 32);
    blob.set(pub, 8 + type.length);
    return `ssh-ed25519 ${b64(blob)} rollavpn-no-login`;
  }

  // The script the cloud provider runs once on first boot (cloud-init user-data).
  // It is shown to the user verbatim (minus the server private key) before launch.
  // exit: a pasted WireGuard config for the second hop. warp: use Cloudflare WARP as the exit
  // instead, registered by the server itself during setup. A pasted exit wins over WARP.
  function serverScript({ keys, port, dns, sshKey, exit, keepLogins, warp }) {
    const peerBlocks = keys.peers.map((p) => [
      '',
      '[Peer]',
      `PublicKey = ${p.publicKey}`,
      `PresharedKey = ${p.presharedKey}`,
      `AllowedIPs = ${p.address4}/32, ${p.address6}/128`,
    ].join('\n')).join('\n');

    // keepLogins: the user's own machine. Leave its logins alone and let SSH through the firewall.
    const ssh = keepLogins ? '' : (sshKey || '').trim();
    if (/['\n\r\\]/.test(ssh)) throw new Error('SSH key contains invalid characters');
    if (ssh && !/^(ssh-(ed25519|rsa)|ecdsa-sha2-nistp\d+|sk-[\w@.-]+) [A-Za-z0-9+/=]+( .*)?$/.test(ssh)) {
      throw new Error("That doesn't look like an SSH public key (it should start with ssh-ed25519, ssh-rsa or ecdsa-…)");
    }
    const { unbound, block } = DNS[dns];
    const NET4 = keys.net.v4;
    const NET6 = keys.net.v6;
    const SERVER4 = `${NET4}.1`;
    const SERVER6 = `${NET6}:1`;
    if (exit && inNet(keys, exit.address4)) throw new Error('The second hop uses the same internal addresses. Press "Regenerate keys".');
    const useWarp = !exit && !!warp;
    const hop = !!exit || useWarp; // traffic leaves through wg1, not straight out
    const T = 51821; // routing table for the second hop
    const EXIT_PORT = 51822; // local UDP port of the tunnel to the second hop

    return `#!/bin/bash
# rollavpn server setup. Generated in your browser; runs once on first boot.
# Goal: a WireGuard server that keeps no logs and holds as little data as possible.
set -euo pipefail
# Run by hand from a downloaded file: delete it on exit (even on failure), since it contains the
# server key. Done from a trap so bash has finished reading the file before it's overwritten.
trap 'case "$0" in *rollavpn-setup.sh) shred -u -- "$0" 2>/dev/null || rm -f -- "$0" ;; esac' EXIT
export DEBIAN_FRONTEND=noninteractive
APT="apt-get -y -o DPkg::Lock::Timeout=600"
say() { echo "rollavpn: $*"; }

say "removing provider agents, telemetry and log daemons"
# droplet-agent / do-agent: DigitalOcean's console and metrics agents.
# qemu-guest-agent: lets the hypervisor run commands inside the VM.
# rsyslog: writes /var/log/syslog and auth.log to disk.
# sysstat: records network throughput every 10 minutes. landscape-common: writes sysinfo.log.
# ufw/firewalld: some images ship with them on; rollavpn installs its own firewall.
command -v ufw >/dev/null && ufw --force disable >/dev/null 2>&1 || true
for pkg in droplet-agent do-agent qemu-guest-agent rsyslog sysstat snapd apport popularity-contest ubuntu-report landscape-client landscape-common ufw firewalld; do
  if dpkg -s "$pkg" >/dev/null 2>&1; then $APT purge "$pkg" >/dev/null || true; fi
done
systemctl disable --now motd-news.timer apt-news.service esm-cache.service 2>/dev/null || true
pro config set apt_news=false >/dev/null 2>&1 || true

say "installing packages"
$APT update
$APT install --no-install-recommends wireguard-tools iproute2 iptables unattended-upgrades${unbound ? ' unbound dns-root-data' : ''}${useWarp ? ' curl ca-certificates python3' : ''}

WAN=$(ip -o -4 route show to default | awk '{print $5; exit}')

${keepLogins ? `say "leaving your logins as they are"` : `say "locking down logins"
passwd -l root || true
${ssh ? `mkdir -p /root/.ssh && chmod 700 /root/.ssh
echo '${ssh}' > /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
printf 'PasswordAuthentication no\\nKbdInteractiveAuthentication no\\nPermitRootLogin prohibit-password\\nLogLevel QUIET\\n' > /etc/ssh/sshd_config.d/00-rollavpn.conf
systemctl restart ssh.service || systemctl restart sshd.service || true` : `# No SSH key given: nobody can log in. SSH is switched off entirely.
systemctl disable --now ssh.socket ssh.service 2>/dev/null || true
systemctl mask ssh.socket ssh.service 2>/dev/null || true`}`}

say "turning off logging"
# The system journal is discarded instead of being stored.
mkdir -p /etc/systemd/journald.conf.d
printf '[Journal]\\nStorage=none\\nForwardToSyslog=no\\nForwardToWall=no\\n' > /etc/systemd/journald.conf.d/rollavpn.conf
# Anything else that writes to /var/log writes to RAM, and it's gone on reboot.
grep -q '^tmpfs /var/log ' /etc/fstab || echo 'tmpfs /var/log tmpfs rw,nosuid,nodev,noexec,noatime,mode=0755,size=32M,nofail 0 0' >> /etc/fstab
mkdir -p /etc/tmpfiles.d
printf 'd /var/log/apt 0755 root root -\\nd /var/log/unattended-upgrades 0755 root root -\\n' > /etc/tmpfiles.d/rollavpn-log.conf
# No swap, so nothing in memory (keys, RAM logs) is ever written to disk. Swap files are deleted
# too: some images (Vultr's) swap during first boot, which can leave this script in the file.
SWAPFILES=$( { awk 'NR > 1 && $2 == "file" {print $1}' /proc/swaps; awk '$1 !~ /^#/ && $3 == "swap" {print $1}' /etc/fstab; } 2>/dev/null | sort -u || true)
swapoff -a 2>/dev/null || true
sed -i -E '/^[^#].*[[:space:]]swap[[:space:]]/s/^/#/' /etc/fstab
for f in $SWAPFILES; do if [ -f "$f" ]; then rm -f -- "$f"; fi; done
# No core dumps (they could contain keys or traffic).
mkdir -p /etc/systemd/coredump.conf.d
printf '[Coredump]\\nStorage=none\\nProcessSizeMax=0\\n' > /etc/systemd/coredump.conf.d/rollavpn.conf

say "enabling automatic security updates"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
cat > /etc/apt/apt.conf.d/52rollavpn <<'EOF'
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";
EOF

${hop ? `say "stopping the network manager from removing the exit's routing"
# By default systemd-networkd deletes routing rules and routes it didn't create whenever it restarts
# or renews the server's address (every 12 hours on some hosts). That would cut traffic to the exit.
mkdir -p /etc/systemd/networkd.conf.d
printf '[Network]\\nManageForeignRoutingPolicyRules=no\\nManageForeignRoutes=no\\n' > /etc/systemd/networkd.conf.d/rollavpn.conf
if systemctl is-active -q systemd-networkd 2>/dev/null; then
  systemctl restart systemd-networkd
  /usr/lib/systemd/systemd-networkd-wait-online --timeout=60 >/dev/null 2>&1 || true
fi

` : ''}say "configuring the kernel"
cat > /etc/sysctl.d/99-rollavpn.conf <<EOF
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.$WAN.accept_ra = 2
kernel.core_pattern = |/bin/false
fs.suid_dumpable = 0
kernel.dmesg_restrict = 1
EOF
sysctl --system >/dev/null 2>&1 || true

say "writing firewall rules"
cat > /etc/wireguard/rollavpn-fw.sh <<'EOF'
#!/bin/bash
# Called by wg-quick: "up" adds the rules, "down" removes them.
OP=$([ "$1" = up ] && echo -A || echo -D)
WAN=$(ip -o -4 route show to default | awk '{print $5; exit}')
${keepLogins ? `SSH_PORTS=$(sshd -T 2>/dev/null | awk '$1 == "port" {print $2}' | sort -u)
SSH_PORTS=\${SSH_PORTS:-22}
` : ''}${hop ? `# The exit's addresses (written during setup). Without them, traffic goes straight out.
EXIT4=; EXIT6=
[ -f /etc/wireguard/rollavpn-exit.env ] && . /etc/wireguard/rollavpn-exit.env
` : ''}for ipt in iptables ip6tables; do
  if [ $ipt = iptables ]; then
    NET=${NET4}.0/24; ICMP=icmp
    PRIVATE="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 169.254.0.0/16"
  else
    NET=${NET6}:/64; ICMP=ipv6-icmp
    PRIVATE="fc00::/7 fe80::/10"
  fi
  # From the internet, only the WireGuard port${ssh || keepLogins ? ' and SSH' : ''} can be reached.
  $ipt $OP INPUT -i $WAN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  $ipt $OP INPUT -i $WAN -p udp --dport ${port} -j ACCEPT
  # Don't track WireGuard packets, so connection tracking never holds a device's home IP.
  $ipt -t raw $OP PREROUTING -p udp --dport ${port} -m addrtype --dst-type LOCAL -j NOTRACK
  $ipt -t raw $OP OUTPUT -p udp --sport ${port} -j NOTRACK
${ssh ? `  $ipt $OP INPUT -i $WAN -p tcp --dport 22 -j ACCEPT\n` : ''}${keepLogins ? `  for p in $SSH_PORTS; do $ipt $OP INPUT -i $WAN -p tcp --dport $p -j ACCEPT; done\n` : ''}  $ipt $OP INPUT -i $WAN -p $ICMP -j ACCEPT
  $ipt $OP INPUT -i $WAN -p udp -m multiport --dports 68,546 -j ACCEPT
  $ipt $OP INPUT -i $WAN -j DROP
  # Devices can't see each other, the provider's private network or its metadata service.
  $ipt $OP FORWARD -i wg0 -o wg0 -j DROP
${hop ? `  if [ -n "$EXIT4" ]; then
  # Exit (second hop or WARP): device traffic may never leave directly, only through wg1.
  $ipt $OP FORWARD -i wg0 -o $WAN -j DROP
  # Nothing on the exit's side can open connections to this server.
  $ipt $OP INPUT -i wg1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  $ipt $OP INPUT -i wg1 -j DROP
${unbound ? `  # The resolver may not talk to the internet directly either. (The tunnel's own packets,
  # which the kernel still attributes to the resolver, leave from the exit port and are allowed.)
  $ipt $OP OUTPUT -o $WAN -p udp --sport ${EXIT_PORT} -j ACCEPT
${block ? `  # Downloading the public blocklist (HTTPS to GitHub) reveals nothing about your browsing.
  $ipt $OP OUTPUT -o $WAN -p tcp --dport 443 -m owner --uid-owner unbound -j ACCEPT
` : ''}  $ipt $OP OUTPUT -o $WAN -m owner --uid-owner unbound -j REJECT
` : ''}  fi
` : ''}  for p in $PRIVATE; do $ipt $OP FORWARD -i wg0 -d $p -j DROP; done
  $ipt $OP FORWARD -i wg0 -j ACCEPT
  $ipt $OP FORWARD -o wg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  # Nothing else is forwarded: nobody outside can reach your devices or route through the server.
  $ipt $OP FORWARD -j DROP
  $ipt -t nat $OP POSTROUTING -s $NET -o $WAN -j MASQUERADE
${hop ? `  [ -n "$EXIT4" ] && $ipt -t nat $OP POSTROUTING -s $NET -o wg1 -j MASQUERADE
` : ''}  $ipt -t mangle $OP FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
done 2>/dev/null
${hop ? `if [ -n "$EXIT4" ]; then
  # Route device traffic${unbound ? ' and DNS lookups' : ''} via table ${T}, which sends it into wg1.
  # The blackhole route means that if wg1 is down, traffic is dropped instead of leaking.
  RULE=$([ "$1" = up ] && echo add || echo del)
  ip -4 rule $RULE iif wg0 lookup ${T} priority 1000
  ip -6 rule $RULE iif wg0 lookup ${T} priority 1000
  ip -4 rule $RULE from $EXIT4 lookup ${T} priority 1001
  [ -n "$EXIT6" ] && ip -6 rule $RULE from $EXIT6 lookup ${T} priority 1001
  ip -4 route replace blackhole default table ${T} metric 4000
  ip -6 route replace blackhole default table ${T} metric 4000
fi
` : ''}# Forget idle TCP connection mappings after ~2 hours instead of the default 5 days.
sysctl -qw net.netfilter.nf_conntrack_tcp_timeout_established=7440 2>/dev/null || true
# Room for plenty of connections (~20 MB at most). The default on a 1 GB server is 8192; when it's
# full, new connections are silently dropped.
sysctl -qw net.netfilter.nf_conntrack_max=65536 2>/dev/null || true
exit 0
EOF
chmod 700 /etc/wireguard/rollavpn-fw.sh

say "writing WireGuard config"
umask 077
cat > /etc/wireguard/wg0.conf <<'EOF'
[Interface]
Address = ${SERVER4}/24, ${SERVER6}/64
ListenPort = ${port}
PrivateKey = ${keys.server.privateKey}
PostUp = /etc/wireguard/rollavpn-fw.sh up
PostDown = /etc/wireguard/rollavpn-fw.sh down
${peerBlocks}
EOF
umask 022
${exit ? `
say "connecting to the second hop"
umask 077
cat > /etc/wireguard/wg1.conf <<'EOF'
[Interface]
PrivateKey = ${exit.privateKey}
Address = ${exit.address4}/32${exit.address6 ? `, ${exit.address6}/128` : ''}
ListenPort = ${EXIT_PORT}
Table = off
PostUp = /etc/wireguard/rollavpn-exit.sh

[Peer]
PublicKey = ${exit.publicKey}
${exit.presharedKey ? `PresharedKey = ${exit.presharedKey}
` : ''}Endpoint = ${exit.endpoint}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
printf 'EXIT4=%s\\nEXIT6=%s\\n' '${exit.address4}' '${exit.address6 || ''}' > /etc/wireguard/rollavpn-exit.env
umask 022
` : ''}${useWarp ? `
say "registering with Cloudflare WARP (anonymous: no account or email)"
# Registration is its own script, so the watchdog can register again if WARP stops working.
# The server makes its own WARP key; it never leaves this machine. Cloudflare learns only this
# server's IP. If registration fails, the server sends traffic straight out instead.
cat > /usr/local/sbin/rollavpn-warp <<'WARP'
#!/bin/bash
umask 077
OLD6=$( [ -f /etc/wireguard/rollavpn-exit.env ] && . /etc/wireguard/rollavpn-exit.env && echo "$EXIT6" )
KEY=$(wg genkey)
BODY=$(printf '{"key":"%s","install_id":"","fcm_token":"","tos":"%s","model":"PC","serial_number":"","locale":"en_US","os_version":"16.0.0","key_type":"curve25519","tunnel_type":"wireguard"}' "$(echo "$KEY" | wg pubkey)" "$(date -u +%Y-%m-%dT%H:%M:%S.000Z)")
REG=
for i in 1 2 3 4 5; do
  REG=$(curl -fsS --max-time 30 -X POST https://api.cloudflareclient.com/v0a5641/reg \\
    -H 'User-Agent: 1.1.1.1/6.38.9-5641 (Android 16.0.0)' -H 'CF-Client-Version: a-6.38.9-5641' \\
    -H 'Content-Type: application/json; charset=UTF-8' -d "$BODY") && break
  REG=; sleep 10
done
[ -n "$REG" ] || exit 1
VARS=$(printf '%s' "$REG" | python3 -c '
import json, re, shlex, sys
c = json.load(sys.stdin)["config"]
p, a = c["peers"][0], c["interface"]["addresses"]
v = {"PEER": p["public_key"], "ENDPOINT": p["endpoint"]["v4"].rsplit(":", 1)[0] + ":2408",
     "EXIT4": a["v4"], "EXIT6": a.get("v6") or ""}
# These go into root-run config files, so accept only what they should look like.
if not (re.fullmatch("[A-Za-z0-9+/]{43}=", v["PEER"]) and re.fullmatch("[0-9.]+:2408", v["ENDPOINT"])
        and re.fullmatch("[0-9.]+", v["EXIT4"]) and re.fullmatch("[0-9a-fA-F:]*", v["EXIT6"])):
    sys.exit("unexpected WARP reply")
for k in v:
    print(k + "=" + shlex.quote(v[k]))
') || exit 1
eval "$VARS"
cat > /etc/wireguard/wg1.conf <<CONF
[Interface]
PrivateKey = $KEY
Address = $EXIT4/32\${EXIT6:+, $EXIT6/128}
MTU = 1280
ListenPort = ${EXIT_PORT}
Table = off
PostUp = /etc/wireguard/rollavpn-exit.sh

[Peer]
PublicKey = $PEER
Endpoint = $ENDPOINT
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
CONF
printf 'EXIT4=%s\\nEXIT6=%s\\n' "$EXIT4" "$EXIT6" > /etc/wireguard/rollavpn-exit.env
# On a re-registration the IPv6 address can change: move its routing rule and the resolver along.
if [ -n "$OLD6" ] && [ "$OLD6" != "$EXIT6" ]; then ip -6 rule del from "$OLD6" lookup ${T} 2>/dev/null; fi
if [ -n "$EXIT6" ] && ip link show wg0 >/dev/null 2>&1 && ! ip -6 rule show from "$EXIT6" | grep -q ${T}; then
  ip -6 rule add from "$EXIT6" lookup ${T} priority 1001
fi
if [ -x /usr/local/sbin/rollavpn-exit-dns ]; then /usr/local/sbin/rollavpn-exit-dns; fi
exit 0
WARP
chmod 700 /usr/local/sbin/rollavpn-warp
if /usr/local/sbin/rollavpn-warp; then
  say "WARP ready: traffic will leave through Cloudflare"
else
  say "WARP registration failed: traffic will leave straight from this server"
fi
` : ''}${hop ? `cat > /etc/wireguard/rollavpn-exit.sh <<'EOF'
#!/bin/bash
. /etc/wireguard/rollavpn-exit.env
ip -4 route replace default dev wg1 table ${T}
[ -n "$EXIT6" ] && ip -6 route replace default dev wg1 table ${T}
exit 0
EOF
chmod 700 /etc/wireguard/rollavpn-exit.sh
` : ''}
say "making the server forget your home IP address when you disconnect"
# WireGuard remembers each device's last IP address and traffic counters in memory.
# Every minute, reset any device idle for 3+ minutes so that information is wiped.
cat > /usr/local/sbin/rollavpn-forget <<'EOF'
#!/bin/bash
MAX_IDLE=\${1:-180}
now=$(date +%s); changed=0
while read -r peer endpoint; do
  [ "$endpoint" = "(none)" ] && continue
  hs=$(wg show wg0 latest-handshakes | awk -v p="$peer" '$1 == p {print $2}')
  if [ $((now - hs)) -ge "$MAX_IDLE" ]; then wg set wg0 peer "$peer" remove; changed=1; fi
done < <(wg show wg0 endpoints)
[ $changed = 1 ] && wg syncconf wg0 <(wg-quick strip wg0)
exit 0
EOF
chmod 700 /usr/local/sbin/rollavpn-forget
mkdir -p /etc/systemd/system
cat > /etc/systemd/system/rollavpn-forget.service <<'EOF'
[Unit]
Description=Wipe remembered IP addresses of idle WireGuard devices
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/rollavpn-forget
EOF
cat > /etc/systemd/system/rollavpn-forget.timer <<'EOF'
[Unit]
Description=Wipe remembered IP addresses of idle WireGuard devices
[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
AccuracySec=5s
[Install]
WantedBy=timers.target
EOF
${hop ? `
say "setting up a watchdog for the exit tunnel"
cat > /usr/local/sbin/rollavpn-watch <<'EOF'
#!/bin/bash
# Runs every minute. If the exit tunnel (WARP or second hop) has had no handshake for 5 minutes,
# restart it; if that doesn't help and it's WARP, register again (at most every 30 minutes).
# Until it works, the kill switch keeps device traffic blocked rather than sending it out directly.
MAX_AGE=\${1:-300}
[ -f /etc/wireguard/wg1.conf ] || exit 0
# Put back any routing rule something else removed. Without them the kill switch blocks everything.
. /etc/wireguard/rollavpn-exit.env
ip -4 rule show | grep -q "iif wg0 lookup ${T}" || ip -4 rule add iif wg0 lookup ${T} priority 1000
ip -6 rule show | grep -q "iif wg0 lookup ${T}" || ip -6 rule add iif wg0 lookup ${T} priority 1000
ip -4 rule show | grep -q "from $EXIT4 lookup ${T}" || ip -4 rule add from "$EXIT4" lookup ${T} priority 1001
if [ -n "$EXIT6" ]; then ip -6 rule show | grep -q "from $EXIT6 lookup ${T}" || ip -6 rule add from "$EXIT6" lookup ${T} priority 1001; fi
ip -4 route replace blackhole default table ${T} metric 4000
ip -6 route replace blackhole default table ${T} metric 4000
if ip link show wg1 >/dev/null 2>&1; then /etc/wireguard/rollavpn-exit.sh; fi
last() { wg show wg1 latest-handshakes 2>/dev/null | awk '{print $2; exit}'; }
fresh_since() { for i in $(seq 15); do [ "$(last)" -ge "$1" ] 2>/dev/null && return 0; sleep 2; done; return 1; }
hs=$(last)
[ $(( $(date +%s) - \${hs:-0} )) -lt "$MAX_AGE" ] && exit 0
t=$(date +%s)
systemctl restart wg-quick@wg1
fresh_since "$t" && exit 0
STAMP=/run/rollavpn-warp-retry
if [ -x /usr/local/sbin/rollavpn-warp ] && { [ ! -e $STAMP ] || [ -n "$(find $STAMP -mmin +30)" ]; }; then
  touch $STAMP
  if /usr/local/sbin/rollavpn-warp; then
    systemctl restart wg-quick@wg1
    if [ -x /usr/sbin/unbound ]; then systemctl restart unbound; fi
  fi
fi
exit 0
EOF
chmod 700 /usr/local/sbin/rollavpn-watch
cat > /etc/systemd/system/rollavpn-watch.service <<'EOF'
[Unit]
Description=Keep the rollavpn exit tunnel working
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/rollavpn-watch
EOF
cat > /etc/systemd/system/rollavpn-watch.timer <<'EOF'
[Unit]
Description=Keep the rollavpn exit tunnel working
[Timer]
OnBootSec=3min
OnUnitActiveSec=1min
[Install]
WantedBy=timers.target
EOF
` : ''}${unbound ? `
say "configuring private DNS resolver"
cat > /etc/unbound/unbound.conf.d/rollavpn.conf <<'EOF'
server:
  interface: ${SERVER4}
  interface: ${SERVER6}
  ip-freebind: yes
  access-control: ${NET4}.0/24 allow
  access-control: ${NET6}:/64 allow
  # Never log queries or answers.
  verbosity: 0
  log-queries: no
  log-replies: no
  log-local-actions: no
  log-servfail: no
  # Send each nameserver as little as possible; validate DNSSEC.
  qname-minimisation: yes
  aggressive-nsec: yes
  harden-glue: yes
  harden-dnssec-stripped: yes
  harden-below-nxdomain: yes
  hide-identity: yes
  hide-version: yes
  # Small cache that forgets within an hour.
  cache-max-ttl: 3600
  msg-cache-size: 8m
  rrset-cache-size: 16m
  prefetch: yes
${block ? `  module-config: "respip validator iterator"

# Ad/tracker/malware blocklist, fetched and refreshed by Unbound itself.
rpz:
  name: blocklist.rollavpn
  url: ${BLOCKLIST_URL}
  zonefile: /var/lib/unbound/blocklist.rpz
  rpz-log: no
  # Only ever block. The list can't redirect a name to an address of its choosing.
  rpz-action-override: nxdomain
  rpz-signal-nxdomain-ra: yes
` : ''}EOF
# If it ever crashes (say, out of memory), always bring it back.
mkdir -p /etc/systemd/system/unbound.service.d
printf '[Unit]\nStartLimitIntervalSec=0\n[Service]\nRestart=always\nRestartSec=5\n' > /etc/systemd/system/unbound.service.d/rollavpn-restart.conf
${hop ? `cat > /usr/local/sbin/rollavpn-exit-dns <<'EOF'
#!/bin/bash
# Look names up through the exit, never from this server's own IP.
. /etc/wireguard/rollavpn-exit.env
{ echo 'server:'
  echo "  outgoing-interface: $EXIT4"
  if [ -n "$EXIT6" ]; then echo "  outgoing-interface: $EXIT6"; else echo '  prefer-ip4: yes'; fi
  echo '  outgoing-port-avoid: ${EXIT_PORT}'
} > /etc/unbound/unbound.conf.d/rollavpn-exit.conf
EOF
chmod 700 /usr/local/sbin/rollavpn-exit-dns
if [ -f /etc/wireguard/rollavpn-exit.env ]; then /usr/local/sbin/rollavpn-exit-dns; fi
` : ''}` : ''}
say "starting WireGuard"
systemctl daemon-reload
systemctl enable wg-quick@wg0 rollavpn-forget.timer
systemctl restart wg-quick@wg0
systemctl start rollavpn-forget.timer
${hop ? `if [ -f /etc/wireguard/wg1.conf ]; then
systemctl enable wg-quick@wg1 rollavpn-watch.timer
systemctl restart wg-quick@wg1
systemctl start rollavpn-watch.timer
${unbound ? `mkdir -p /etc/systemd/system/unbound.service.d
printf '[Unit]\\nAfter=wg-quick@wg1.service\\nWants=wg-quick@wg1.service\\n' > /etc/systemd/system/unbound.service.d/rollavpn.conf
systemctl daemon-reload
` : ''}fi
` : ''}${unbound ? 'systemctl enable unbound\nsystemctl restart unbound\n' : ''}
say "erasing setup traces"
# Stop cloud-init from running again, so nothing can be injected through the provider's metadata later.
touch /etc/cloud/cloud-init.disabled 2>/dev/null || true
# Remove cloud-init's on-disk copies of this script (they contain the server key), including
# obj.pkl and the instance-data files in /run, which can hold everything the provider sent.
# Then remove every log written so far
# and move /var/log into RAM.
SCRUB='rm -rf /var/lib/cloud/instances/*/user-data* /var/lib/cloud/instances/*/scripts /var/lib/cloud/instances/*/vendor-data* /var/lib/cloud/instances/*/*cloud-config.txt /var/lib/cloud/instances/*/obj.pkl /var/lib/cloud/data/*.pkl /run/cloud-init/instance-data*.json /run/cloud-init/combined-cloud-config.json /var/log/cloud-init*.log'
sh -c "$SCRUB" 2>/dev/null || true
# Once more after cloud-init has finished, in case it rewrites its cache on the way out.
systemd-run --on-active=300 --unit=rollavpn-scrub /bin/sh -c "$SCRUB; fstrim -a" >/dev/null 2>&1 || true
systemctl restart systemd-journald 2>/dev/null || true
find /var/log -type f -delete 2>/dev/null || true
rm -rf /var/log/journal/* /run/log/journal/* 2>/dev/null || true
mountpoint -q /var/log || mount /var/log || true
systemd-tmpfiles --create /etc/tmpfiles.d/rollavpn-log.conf 2>/dev/null || true
fstrim -a 2>/dev/null || true

mkdir -p /var/lib/rollavpn && touch /var/lib/rollavpn/ready
echo "rollavpn: READY" > /dev/console 2>/dev/null || true
`;
  }

  root.RollaWG = { DNS, BLOCKLIST_URL, generateKeys, inNet, clientConfig, serverScript, parseExitConfig, lockedSshKey, randomToken, b64 };
})(globalThis);
