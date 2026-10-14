#!/bin/bash
# Builds PC1 -> Device1 -> Device2 -> PC2 out of Linux network namespaces and
# starts secgw on both devices.  Run as root:  sudo ./demo-netns.sh up|down
#
#   pc1 10.0.1.2 --[10.0.1.1] dev1 [10.0.12.1]--[10.0.12.2] dev2 [10.0.2.1]-- 10.0.2.2 pc2
set -euo pipefail
P=${PORT:-8080}                      # protected TCP port (src OR dst)
BIN=${BIN:-$(dirname "$(readlink -f "$0")")/secgw}
PSK=/tmp/secgw.psk
R() { ip netns exec "$@"; }

down() {
  pkill -f "$BIN" 2>/dev/null || true
  for n in pc1 dev1 dev2 pc2; do ip netns del $n 2>/dev/null || true; done
}

up() {
  down
  for n in pc1 dev1 dev2 pc2; do ip netns add $n; done
  ip link add v-p1  type veth peer name v-d1l ; ip link set v-p1  netns pc1  ; ip link set v-d1l netns dev1
  ip link add v-d1p type veth peer name v-d2p ; ip link set v-d1p netns dev1 ; ip link set v-d2p netns dev2
  ip link add v-d2l type veth peer name v-p2  ; ip link set v-d2l netns dev2 ; ip link set v-p2  netns pc2

  R pc1  ip addr add 10.0.1.2/24  dev v-p1  ; R dev1 ip addr add 10.0.1.1/24  dev v-d1l
  R dev1 ip addr add 10.0.12.1/30 dev v-d1p ; R dev2 ip addr add 10.0.12.2/30 dev v-d2p
  R dev2 ip addr add 10.0.2.1/24  dev v-d2l ; R pc2  ip addr add 10.0.2.2/24  dev v-p2
  for n in pc1 dev1 dev2 pc2; do R $n ip link set lo up; done
  R pc1 ip link set v-p1 up; R dev1 ip link set v-d1l up; R dev1 ip link set v-d1p up
  R dev2 ip link set v-d2p up; R dev2 ip link set v-d2l up; R pc2 ip link set v-p2 up

  R pc1 ip route add default via 10.0.1.1 ; R pc2 ip route add default via 10.0.2.1
  R dev1 ip route add 10.0.2.0/24 via 10.0.12.2
  R dev2 ip route add 10.0.1.0/24 via 10.0.12.1
  R dev1 sysctl -qw net.ipv4.ip_forward=1 ; R dev2 sysctl -qw net.ipv4.ip_forward=1

  # NFQUEUE hands the daemon unsegmented, offload-free packets
  for pair in pc1:v-p1 dev1:v-d1l dev1:v-d1p dev2:v-d2p dev2:v-d2l pc2:v-p2; do
    R "${pair%%:*}" ethtool -K "${pair##*:}" tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
  done

  head -c 32 /dev/urandom > $PSK

  for d in dev1:v-d1l:v-d1p dev2:v-d2l:v-d2p; do
    IFS=: read ns LAN PEER <<<"$d"
    # fail closed: NO --queue-bypass; if secgw dies, protected traffic stops
    R $ns iptables -A FORWARD -i $LAN  -p tcp -m multiport --ports $P -j NFQUEUE --queue-num 0
    R $ns iptables -A FORWARD -i $PEER -p tcp -m multiport --ports $P -j NFQUEUE --queue-num 1
    # +24 bytes per packet: keep MSS small enough that nothing needs fragmenting
    R $ns iptables -t mangle -A FORWARD -i $LAN -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1400
    # conntrack would see inflated segment lengths on the inter-device hop
    R $ns iptables -t raw -A PREROUTING -p tcp -m multiport --ports $P -j CT --notrack 2>/dev/null || true
  done

  R dev2 "$BIN" -m responder -p 10.0.12.1 -k $PSK -v &> /tmp/secgw-dev2.log &
  sleep 1
  R dev1 "$BIN" -m initiator -p 10.0.12.2 -k $PSK -v &> /tmp/secgw-dev1.log &
  sleep 2
  echo "up.  logs: /tmp/secgw-dev{1,2}.log"
  echo "try:"
  echo "  sudo ip netns exec pc2 python3 -m http.server $P &"
  echo "  sudo ip netns exec pc1 curl -s http://10.0.2.2:$P/ | head"
  echo "  sudo ip netns exec dev1 tcpdump -ni v-d1p -A tcp port $P   # ciphertext on the wire"
}
"${1:-up}"
