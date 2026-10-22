#!/bin/bash
# End-to-end test in Docker: runs the real generated server script in an Ubuntu 24.04
# container, connects a WireGuard client to it, and checks that traffic and DNS go
# through the tunnel.
#
#   lan: client <-> server        wan: server <-> web
#
# The client can only reach "web" by going through the VPN server.
# With EXIT=1, a fourth container runs a second rollavpn server that the first uses as its second hop:
#   client -> server -> upstream (hop) -> web
# With OWN=1, the server is "your own server": it runs SSH, and the script is run by hand
# from a downloaded rollavpn-setup.sh, which must keep SSH reachable and delete itself.
# With WARP=1, the server exits through Cloudflare WARP (needs real internet access).
# Usage: [EXIT=1] [OWN=1] [WARP=1] test/e2e.sh [own-block|own|quad9|cloudflare]
set -euo pipefail
cd "$(dirname "$0")/.."
DNS=${1:-own-block}
ID=rollavpn-e2e-$$
OUT=$(mktemp -d)
cleanup() {
  docker rm -f $ID-server $ID-client $ID-web $ID-upstream >/dev/null 2>&1 || true
  docker network rm $ID-lan $ID-wan >/dev/null 2>&1 || true
  rm -rf "$OUT"
}
[ -n "${KEEP:-}" ] || trap 'rc=$?; cleanup; exit $rc' EXIT

docker network create --subnet 198.18.0.0/24 $ID-wan >/dev/null
docker network create $ID-lan >/dev/null

echo "== starting containers"
docker run -d --name $ID-web --cap-add NET_ADMIN --network $ID-wan nginx:alpine >/dev/null
docker run -d --name $ID-server --privileged --network $ID-wan ubuntu:24.04 sleep infinity >/dev/null
docker network connect $ID-lan $ID-server
docker run -d --name $ID-client --privileged --network $ID-lan ubuntu:24.04 sleep infinity >/dev/null
if [ -n "${EXIT:-}" ]; then
  docker run -d --name $ID-upstream --privileged --network $ID-wan ubuntu:24.04 sleep infinity >/dev/null
  UPSTREAM=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$ID-wan\").IPAddress}}" $ID-upstream)
fi

SERVER_LAN=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$ID-lan\").IPAddress}}" $ID-server)
SERVER_WAN=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$ID-wan\").IPAddress}}" $ID-server)
WEB=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$ID-wan\").IPAddress}}" $ID-web)
WAN_GW=$(docker network inspect -f '{{(index .IPAM.Config 0).Gateway}}' $ID-wan)
# Like a real cloud server, the server's default route must point at the internet side.
docker exec $ID-server bash -c "apt-get update -qq && apt-get install -y -qq iproute2 conntrack >/dev/null && ip route replace default via $WAN_GW"

echo "== generating keys and configs with the browser code"
node test/gen.mjs "$OUT" "$SERVER_LAN" "$DNS" 51820 ${UPSTREAM:-}

NET=$(cat "$OUT/net")

# Containers have no systemd; stand in for the few systemctl calls the script makes.
setup() { # <container> <script>
  docker exec -i $1 bash -c 'cat > /usr/local/bin/systemctl; chmod +x /usr/local/bin/systemctl' <<'SHIM'
#!/bin/bash
case "$*" in
  "restart systemd-journald") pkill -x systemd-journald; exit 0 ;;
  "restart wg-quick@"*) i=${2#wg-quick@}; wg-quick down $i 2>/dev/null; exec wg-quick up $i ;;
  "restart unbound") /usr/libexec/unbound-helper root_trust_anchor_update; unbound-checkconf && unbound ;;
  *) exit 0 ;;
esac
SHIM
  docker cp "$OUT/$2" $1:/root/${3:-setup.sh}
  docker exec -w /root $1 bash ${3:-setup.sh} > "$OUT/$2.log" 2>&1 || { tail -n 30 "$OUT/$2.log"; echo "FAIL: setup script $2 failed"; exit 1; }
  docker exec $1 test -f /var/lib/rollavpn/ready
}

if [ -n "${EXIT:-}" ]; then
  echo "== setting up the second rollavpn server (the second hop)"
  docker exec $ID-upstream bash -c 'apt-get update -qq && apt-get install -y -qq iproute2 >/dev/null'
  setup $ID-upstream hop.sh
  grep "^rollavpn" "$OUT/hop.sh.log" | sed "s/^/   hop| /"
fi

echo "== running the server setup script"
if [ -n "${OWN:-}" ]; then
  # An existing machine with SSH running, set up by hand the way the page tells the user to.
  docker exec $ID-server bash -c 'DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssh-server >/dev/null && mkdir -p /run/sshd && /usr/sbin/sshd'
  setup $ID-server server.sh rollavpn-setup.sh
  docker exec $ID-server test ! -e /root/rollavpn-setup.sh || { echo "FAIL: the setup script did not delete itself"; exit 1; }
  echo "   ok  the hand-run setup script deleted itself (it contains the server key)"
else
  setup $ID-server server.sh
fi
grep "^rollavpn" "$OUT/server.sh.log" | sed "s/^/   server| /"

echo "== connecting the client"
docker exec $ID-client bash -c 'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wireguard-tools iproute2 iptables curl dnsutils iputils-ping >/dev/null'
# Containers have no resolvconf, so drop the DNS line; the resolver is checked with dig below.
sed "/^DNS/d" "$OUT/phone.conf" > "$OUT/client.conf"
docker cp "$OUT/client.conf" $ID-client:/etc/wireguard/wg0.conf
docker exec $ID-client wg-quick up wg0 2>&1 | sed 's/^/   client| /'

fail() { echo "FAIL: $*"; docker exec $ID-server wg show || true; exit 1; }

echo "== checks"
docker exec $ID-client ping -c 2 -W 2 $NET.1 >/dev/null || fail "client cannot ping server tunnel address"
echo "   ok  tunnel is up (client pings $NET.1)"

docker exec $ID-server wg show wg0 latest-handshakes | awk '$2 > 0 {found=1} END {exit !found}' || fail "no handshake"
echo "   ok  WireGuard handshake completed"

if [ -n "${WARP:-}" ]; then
  docker exec $ID-server grep -q EXIT4= /etc/wireguard/rollavpn-exit.env || fail "WARP registration failed"
  docker exec $ID-client bash -c "echo nameserver $NET.1 > /etc/resolv.conf"
  TRACE=$(docker exec $ID-client curl -s -m 15 https://www.cloudflare.com/cdn-cgi/trace)
  echo "$TRACE" | grep -q '^warp=on' || fail "traffic does not leave through WARP: $(echo "$TRACE" | grep -E '^(ip|warp)=' | tr '\n' ' ')"
  echo "   ok  traffic leaves through Cloudflare WARP ($(echo "$TRACE" | grep -E '^(ip|warp)=' | tr '\n' ' '))"
  docker exec $ID-server wg-quick down wg1 >/dev/null 2>&1
  if docker exec $ID-client curl -s -m 5 -o /dev/null https://1.1.1.1/; then fail "traffic leaked out directly while WARP was down"; fi
  if docker exec $ID-client dig +short +time=2 +tries=1 @$NET.1 wikipedia.org A | grep -q '^[0-9]'; then fail "DNS lookups leaked out directly while WARP was down"; fi
  docker exec $ID-server wg-quick up wg1 >/dev/null 2>&1
  docker exec $ID-client curl -s -m 15 https://www.cloudflare.com/cdn-cgi/trace | grep -q '^warp=on' || fail "traffic did not resume after WARP came back"
  echo "   ok  kill switch: with WARP down, nothing leaves the server; it resumes when WARP is back"
  # Watchdog: a tunnel pointed at a dead endpoint is restarted from its config...
  docker exec $ID-server bash -c 'wg set wg1 peer "$(wg show wg1 peers)" endpoint 192.0.2.1:2408'
  docker exec $ID-server /usr/local/sbin/rollavpn-watch 0
  docker exec $ID-client curl -s -m 15 https://www.cloudflare.com/cdn-cgi/trace | grep -q '^warp=on' || fail "watchdog did not restart a stuck WARP tunnel"
  # ...and one Cloudflare no longer accepts (here: a key it never registered) gets a fresh registration.
  docker exec $ID-server bash -c 'sed -i "s|^PrivateKey = .*|PrivateKey = $(wg genkey)|" /etc/wireguard/wg1.conf; wg-quick down wg1; wg-quick up wg1' >/dev/null 2>&1
  BAD=$(docker exec $ID-server awk '/^PrivateKey/ {print $3}' /etc/wireguard/wg1.conf)
  docker exec $ID-server /usr/local/sbin/rollavpn-watch 0
  [ "$(docker exec $ID-server awk '/^PrivateKey/ {print $3}' /etc/wireguard/wg1.conf)" != "$BAD" ] || fail "watchdog did not register WARP again"
  docker exec $ID-client curl -s -m 15 https://www.cloudflare.com/cdn-cgi/trace | grep -q '^warp=on' || fail "traffic did not resume after WARP was registered again"
  docker exec $ID-client dig +short +time=3 @$NET.1 example.com A | grep -q '^[0-9]' || fail "DNS did not resume after WARP was registered again"
  echo "   ok  watchdog: restarts a stuck WARP tunnel, and registers again when Cloudflare stops accepting it"
  # Something else (systemd-networkd, on a real server) wipes the exit's routing rules and fallback route.
  docker exec $ID-server bash -c 'ip -4 rule flush table 51821; ip -6 rule flush table 51821; ip route del blackhole default table 51821; ip -6 route del blackhole default table 51821' 2>/dev/null || true
  if docker exec $ID-client curl -s -m 5 -o /dev/null https://1.1.1.1/; then fail "traffic leaked out directly with the exit's routing rules gone"; fi
  docker exec $ID-server /usr/local/sbin/rollavpn-watch
  docker exec $ID-client curl -s -m 15 https://www.cloudflare.com/cdn-cgi/trace | grep -q '^warp=on' || fail "watchdog did not restore the exit's routing"
  docker exec $ID-client dig +short +time=3 @$NET.1 example.com A | grep -q '^[0-9]' || fail "DNS did not resume after the watchdog restored routing"
  echo "   ok  watchdog: puts back routing rules something else removed (nothing leaks meanwhile)"
else
docker exec $ID-client curl -sf -m 5 -o /dev/null "http://$WEB/" || fail "client cannot reach web via VPN"
SRC=$(docker logs $ID-web 2>/dev/null | grep 'GET / ' | tail -n 1 | awk '{print $1}')
EXPECT=${UPSTREAM:-$SERVER_WAN}
[ "$SRC" = "$EXPECT" ] || fail "web saw $SRC, expected $EXPECT"
if [ -n "${EXIT:-}" ]; then
  echo "   ok  traffic exits through the second hop, not the first server (web saw $SRC)"
else
  echo "   ok  traffic exits through the VPN server (web saw $SRC)"
fi
fi

if docker exec $ID-client ping -c 1 -W 2 $NET.3 >/dev/null 2>&1; then fail "peers can reach each other"; fi
echo "   ok  devices are isolated from each other"

if [ "$DNS" = own ] || [ "$DNS" = own-block ]; then
  for i in $(seq 1 10); do
    ANS=$(docker exec $ID-client dig +short +time=3 @$NET.1 example.com A | grep -E '^[0-9.]+$' | head -n 1 || true)
    [ -n "$ANS" ] && break
    sleep 2
  done
  [ -n "$ANS" ] || fail "private resolver did not answer"
  echo "   ok  private DNS resolver on the server answers (example.com -> $ANS)"
fi

if [ "$DNS" = own-block ]; then
  for i in $(seq 1 30); do
    RC=$(docker exec $ID-client dig +time=3 @$NET.1 app-measurement.com A | awk '/status:/ {print $6}' | tr -d ,)
    [ "$RC" = NXDOMAIN ] && break
    sleep 2
  done
  [ "$RC" = NXDOMAIN ] || fail "tracker domain was not blocked (status $RC)"
  echo "   ok  tracker domains are blocked (app-measurement.com -> NXDOMAIN)"
fi

if [ -n "${EXIT:-}" ]; then
  docker exec $ID-server wg-quick down wg1 >/dev/null 2>&1
  if docker exec $ID-client curl -sf -m 4 -o /dev/null "http://$WEB/"; then fail "traffic leaked out directly while the exit was down"; fi
  if [ "$DNS" = own ] || [ "$DNS" = own-block ]; then
    if docker exec $ID-client dig +short +time=2 +tries=1 @$NET.1 wikipedia.org A | grep -q '^[0-9]'; then fail "DNS lookups leaked out directly while the exit was down"; fi
  fi
  docker exec $ID-server wg-quick up wg1 >/dev/null 2>&1
  docker exec $ID-client curl -sf -m 10 -o /dev/null "http://$WEB/" || fail "traffic did not resume after the exit came back"
  echo "   ok  kill switch: with the second hop down, nothing leaves the server; it resumes when the second hop is back"
fi

docker exec -d $ID-server python3 -m http.server 8080
sleep 1
if docker exec $ID-web wget -q -T 3 -O /dev/null "http://$SERVER_WAN:8080/" 2>/dev/null; then fail "a stray service on the server is reachable from the internet"; fi
docker exec $ID-web ping -c 1 -W 2 $SERVER_WAN >/dev/null || fail "server does not answer ping"
if [ -n "${OWN:-}" ]; then
  docker exec $ID-web sh -c "nc -w 3 $SERVER_WAN 22 </dev/null | head -c 4" | grep -q SSH- || fail "SSH was cut off on the user's own server"
  docker exec $ID-server test ! -e /etc/ssh/sshd_config.d/00-rollavpn.conf || fail "SSH settings were changed on the user's own server"
  echo "   ok  firewall: only WireGuard and the user's SSH are reachable; logins left alone"
else
  echo "   ok  firewall: only WireGuard is reachable from the internet"
fi
# A neighbour on the internet side routes the VPN's subnet via the server and tries to reach a device.
docker exec $ID-web ip route add $NET.0/24 via $SERVER_WAN
if docker exec $ID-web ping -c 1 -W 2 $NET.2 >/dev/null 2>&1; then fail "a device is reachable from the internet through the server"; fi
echo "   ok  firewall: nothing outside can reach a device through the server"
CLIENT_LAN=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$ID-lan\").IPAddress}}" $ID-client)
if docker exec $ID-server conntrack -L 2>/dev/null | grep -q "src=$CLIENT_LAN "; then fail "connection tracking holds the device's home IP"; fi
echo "   ok  connection tracking never holds a device's home IP"

docker exec $ID-server wg show wg0 endpoints | grep -q "$(docker inspect -f "{{(index .NetworkSettings.Networks \"$ID-lan\").IPAddress}}" $ID-client)" || fail "endpoint not recorded"
# Force a forget even though the client is active (in real use only devices silent for 3+ min,
# whose sessions have already expired, are forgotten). The client re-handshakes within ~15s.
docker exec $ID-server /usr/local/sbin/rollavpn-forget 0
docker exec $ID-server wg show wg0 endpoints | awk '$2 != "(none)" {exit 1}' || fail "client IP still remembered after forget"
docker exec $ID-server wg show wg0 transfer | awk '$2 != 0 || $3 != 0 {exit 1}' || fail "traffic counters not wiped"
docker exec $ID-client ping -c 1 -w 40 $NET.1 >/dev/null || fail "client could not reconnect after being forgotten"
echo "   ok  server forgets idle devices' IP addresses, and they reconnect transparently"

[ "$(docker exec $ID-server find /var/log -type f | wc -l)" -le 2 ] || { docker exec $ID-server find /var/log -type f; fail "log files left behind"; }
docker exec $ID-server bash -c 'mountpoint -q /var/log' || fail "/var/log is not in RAM"
docker exec $ID-server grep -q 'Storage=none' /etc/systemd/journald.conf.d/rollavpn.conf || fail "journal not disabled"
echo "   ok  no logs on disk: journal disabled, /var/log is a RAM disk"

echo "PASS"
