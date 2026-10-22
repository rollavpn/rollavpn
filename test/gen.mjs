// Generates a server setup script and client configs using the exact browser code.
// Usage: node test/gen.mjs <outdir> <endpoint> <dns> <port> [upstream-endpoint]
// With an upstream endpoint, also generates a second rollavpn server (hop.sh) whose "hop" device
// config is pasted into the first server as its second hop, exactly as a user would.
import { mkdirSync, writeFileSync } from 'node:fs';
import { createPublicKey, createPrivateKey } from 'node:crypto';

await import('../web/lib/wg.js');
const WG = globalThis.RollaWG;
const [outdir, endpoint, dns = 'own', port = '51820', upstream] = process.argv.slice(2);

const keys = await WG.generateKeys(['phone', 'laptop']);

// Cross-check every key pair with Node's own X25519 implementation.
const PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');
for (const kp of [keys.server, ...keys.peers]) {
  const priv = createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, Buffer.from(kp.privateKey, 'base64')]), format: 'der', type: 'pkcs8' });
  const pub = createPublicKey(priv).export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64');
  if (pub !== kp.publicKey) throw new Error(`key mismatch: ${pub} != ${kp.publicKey}`);
}

mkdirSync(outdir, { recursive: true });
let exit = null;
if (upstream) {
  const hop = await WG.generateKeys(['hop']);
  writeFileSync(`${outdir}/hop.sh`, WG.serverScript({ keys: hop, port: 51820, dns, sshKey: '', exit: null }));
  const hopConf = WG.clientConfig({ keys: hop, peer: hop.peers[0], endpoint: upstream, port: 51820, dns });
  writeFileSync(`${outdir}/hop.conf`, hopConf);
  exit = WG.parseExitConfig(hopConf);
  if (WG.inNet(keys, exit.address4)) throw new Error('subnet clash; rerun');
}
// OWN=1: the user's own machine, where they keep SSH and run the script by hand.
writeFileSync(`${outdir}/server.sh`, WG.serverScript({ keys, port: Number(port), dns, sshKey: '', exit, keepLogins: !!process.env.OWN, warp: !!process.env.WARP }));
writeFileSync(`${outdir}/net`, keys.net.v4);
for (const peer of keys.peers) {
  writeFileSync(`${outdir}/${peer.name}.conf`, WG.clientConfig({ keys, peer, endpoint, port: Number(port), dns }));
}
console.log(`ok: ${keys.peers.length + 1} key pairs verified, files written to ${outdir}`);
