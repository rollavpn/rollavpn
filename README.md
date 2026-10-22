# rollavpn

Your own WireGuard VPN on your own cloud account, set up from your browser.

Source: https://github.com/rollavpn/rollavpn · Contact: rollavpn@proton.me

Pick a provider, paste an API token, choose a location, name your devices and press **Launch**. A few minutes later you get a QR code and a `.conf` file for each device.

Providers: **SporeStack** (no account, pay with Monero), **DigitalOcean**, **Hetzner Cloud**, **Linode**, or **your own server**.

## Your own server

Use a machine you already have: a rented server, a PC or a Raspberry Pi. You need a fresh Ubuntu 24.04 install with 1 GB+ of memory, a public IP (CGNAT won't work), and root.

The page gives you `rollavpn-setup.sh`. Copy it over and run `sudo bash rollavpn-setup.sh`. It prints `rollavpn: READY` and deletes itself, since it holds the server's private key. At home, forward one UDP port to the machine.

*Keep my current SSH access* is on by default. rollavpn can't check on or delete a server it didn't create; wipe the machine to remove it.

## Cloudflare WARP (on by default)

Cloud IPs are listed as datacenter or VPN. So the server registers with Cloudflare's free WARP during setup, with no account, and sends traffic and DNS out through it. Sites see a Cloudflare address shared with millions of people, so few block it. Detection services still list it as VPN, and the address changes from time to time.

If WARP drops, traffic stops. If registration fails, the server goes direct. This uses the private API of Cloudflare's 1.1.1.1 app and accepts Cloudflare's [app terms](https://www.cloudflare.com/application/terms/); Cloudflare could change or block it at any time. WARP is off by default for your own server, and a second hop replaces it.

## Anonymous mode

Your provider normally knows who pays. Two switches change that:

1. **SporeStack.** Your account is a random token, paid with Monero. Servers run on Vultr or DigitalOcean under SporeStack's account. About $9.60–11.40/month.
2. **Second hop.** Launch a second server in another country with one device named `hop`, and paste its config into step 3 of the first. If the second hop drops, traffic stops.

Then the first host sees your IP but not where you go, and the second sees where you go but not you. For more, do the setup in Tor Browser. Logins and fingerprinting still identify you.

## Open source

WireGuard is built into Linux, small enough to read, and has [formal proofs](https://www.wireguard.com/formal-verification/). To skip app-store binaries, build it from the [official source](https://www.wireguard.com/repositories/):

```sh
git clone https://git.zx2c4.com/wireguard-tools
make -C wireguard-tools/src && sudo make -C wireguard-tools/src install
```

The other apps are in `wireguard-apple`, `wireguard-android` and `wireguard-windows`.

A cloud server runs on someone else's hardware, and its owner can read memory and watch traffic. No logs means nothing to hand over, but nothing on the server stops a host that's watching. That's true of every VPN. rollavpn limits what one host can learn instead: pay anonymously, add a second hop, delete old servers.

## Why it's trustless

- **No backend.** Static files. Your browser calls the provider's API directly.
- **Locked-down page.** The Content-Security-Policy only allows requests to `api.sporestack.com`, `api.digitalocean.com`, `api.hetzner.cloud` and `api.linode.com`.
- **Keys made in your browser** with WebCrypto X25519. They only leave in files you download. The server's key goes in its setup script, which only your provider sees.
- **Nothing stored.** No localStorage, cookies or analytics.
- **Sealed server.** SSH is off and root is locked unless you add a key.
- **Readable.** About 2,600 lines, no build step. One vendored library: [`qrcode-generator`](https://github.com/kazuhikoarase/qrcode-generator) 1.4.4 (MIT), sha256 `18ae399f…bf1780`.

## Save file

At the end you can download `rollavpn-xxxxxx-save.json`. Open it later to get your configs, check the server, add 30 days (SporeStack), swap in a new token, or delete the server.

It holds every key and your provider token, so keep it secret. With a password it's encrypted with AES-256-GCM under PBKDF2-SHA256 (600,000 iterations). The password can't be recovered.

## Run it locally

```sh
node serve.mjs            # http://localhost:8000, 127.0.0.1 only
# or
python3 -m http.server -d web 8000
```

Opening `index.html` as a file won't work; browsers block WebCrypto and some CORS on `file://`.

## Host it on Cloudflare

`wrangler.jsonc` serves `web/` as static files on Cloudflare Workers, with the security headers from `web/_headers`. There's no server code.

```sh
npx wrangler login     # once
npx wrangler deploy    # prints your https://rollavpn.<you>.workers.dev URL
```

To use your own domain, add it under the Worker's **Settings → Domains & Routes** in the Cloudflare dashboard. On that domain, leave off anything that injects scripts into pages (Web Analytics auto-install, Rocket Loader, Email Address Obfuscation, Zaraz). The page's Content-Security-Policy blocks them anyway.

Cloudflare sees visitors' IPs, like any host, and whoever deploys the site controls the code it serves. That's why the page also offers running it locally.

Any other static host works too: publish `web/` and set the headers in `web/_headers`.

## What the server gets

Ubuntu 24.04 on the cheapest 1 GB plan, set up by a script you can read in step 4:

- **WireGuard** on UDP 51820 or 443. All IPv4 and IPv6 goes through the tunnel, with a preshared key per device.
- **No logs.** Journal `Storage=none`, rsyslog purged, `/var/log` in RAM, swap off and swap files deleted, no core dumps, SSH logging `QUIET`.
- **Forgets devices.** A device's IP and counters are wiped 3 minutes after it goes quiet. WireGuard packets are never connection-tracked, so the kernel's tracking table doesn't hold home IPs. Idle TCP NAT entries expire after about 2 hours.
- **Private DNS** with Unbound: no query logs, QNAME minimisation, DNSSEC, a one-hour cache, and the [HaGeZi Multi PRO mini](https://github.com/hagezi/dns-blocklists) blocklist, which can only block names, never redirect them. Quad9 and Cloudflare are also options.
- **No extras.** Purges `droplet-agent`, `do-agent`, `qemu-guest-agent`, sysstat (which records traffic stats), snapd, apport, landscape and popularity-contest, and turns off motd-news and apt-news.
- **Sealed.** Only the WireGuard port is open (plus 22 with an SSH key). Nothing is forwarded except device traffic out and its replies, so nobody outside can reach a device. Devices can't reach each other, the provider's private network or the metadata service. cloud-init is disabled after setup.
- **No setup traces.** First-boot logs and cloud-init's copies of the script, on disk and in `/run`, are deleted, and the disk is trimmed.
- **Auto-patched**, rebooting at 04:00 when needed.
- **Watches itself.** systemd-networkd is told to leave the exit's routing alone (by default it deletes it when it restarts or renews the address). Every minute a watchdog puts back any routing rule that's missing; if the WARP or second-hop tunnel goes 5 minutes without a handshake, it restarts it, and registers WARP again if that doesn't help. Traffic stays blocked meanwhile. The DNS resolver always restarts if it crashes, and the connection-tracking table holds 65,536 entries instead of 8,192.

The provider can still watch traffic, snapshot the VM, and keeps the setup script in its metadata service. It controls the machine anyway, so pick one you're comfortable with.

Without an SSH key you can't edit the server. To add a device, launch a new one and delete the old.

## Layout

```
web/index.html         page + CSP
web/app.js             step-by-step UI
web/lib/wg.js          keys, client configs, server setup script
web/lib/providers.js   provider API adapters
web/vendor/qrcode.js   QR encoder (vendored)
serve.mjs              local server, no dependencies
web/_headers           security headers (used by Cloudflare and serve.mjs)
wrangler.jsonc         Cloudflare Workers config
test/gen.mjs           checks generated keys against Node's X25519
test/e2e.sh            Docker end-to-end test
```

## Tests

```sh
test/e2e.sh own-block           # or: own | quad9 | cloudflare
EXIT=1 test/e2e.sh own-block    # second hop
WARP=1 test/e2e.sh own-block    # Cloudflare WARP (needs internet)
OWN=1 test/e2e.sh own-block     # your own server
```

Runs the real setup script in an Ubuntu 24.04 container and connects a client from another. It checks the handshake, that traffic exits through the server, device isolation, DNS and blocking, the firewall, idle-device wiping, that no logs are left, and with `EXIT=1` that nothing leaks while the second hop is down.

Needs Docker and Node 20+.

## License

[MIT](LICENSE), no warranty. You're responsible for how you use it, what your provider charges, and following the law and your provider's terms. See [web/terms.html](web/terms.html). WireGuard is a registered trademark of Jason A. Donenfeld; rollavpn isn't affiliated with it or any provider.
