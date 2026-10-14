```
 ___       _             ____            
|_ _|_ __ | |_ ___ _ __ / ___|  ___  ___ 
 | || '_ \| __/ _ \ '__\___ \ / _ \/ __|
 | || | | | ||  __/ |   ___) |  __/ (__ 
|___|_| |_|\__\___|_|  |____/ \___|\___|
```

# InterSec

A small Linux prototype that protects TCP traffic between two machines sitting in the middle of a network path:

```
PC1  ──►  Device1  ═══════ protected link ═══════►  Device2  ──►  PC2
          (initiator)                               (responder)
```

PC1 and PC2 don't know anything about it. They talk plain TCP. Device1 and Device2 agree on a key, encrypt the TCP payload of the packets in between, and hand the clear packets to the other side. Anyone listening on the link between the two devices only sees ciphertext.

**Author:** Maria Arshakyan, student at a French university in Armenia
**Professor:** Mamikon Mirzoyan

---

## What it does, in plain words

1. The two devices first meet on a separate control connection and run a Diffie–Hellman key exchange. Out of that comes a shared secret, which is turned into one AES key per direction.
2. Until that is done, nothing protected goes through. Packets are simply dropped.
3. After that, every selected TCP packet gets its payload encrypted with AES-256-GCM. The IP header and the TCP header stay exactly as they were. The sender adds two things at the end of the payload: an 8-byte counter and the 16-byte GCM authentication tag.
4. The packet is forwarded to the other device as it is, with no UDP tunnel and no extra protocol header.
5. The receiving device checks the tag. If it is good, it decrypts, removes the counter and tag, recalculates the IP and TCP checksums, and sends the packet on to the destination host. If it is not good, the packet is dropped.

## Features

- **Diffie–Hellman handshake** (RFC 7919 group `ffdhe2048`), fresh keys for every session, peer value is checked before use.
- **AES-256-GCM** on the TCP payload only. Headers are kept, the tag is appended to the encrypted payload.
- **Unique nonce for every packet.** The 12-byte nonce is a 4-byte salt (different for each direction, derived from the key exchange) plus an 8-byte counter that goes up by one for every packet. The counter is written in the packet, so a lost or reordered packet cannot make the two sides lose sync. A retransmitted TCP segment gets a new counter, never an old one.
- **Headers are authenticated too.** Source and destination IP, ports, sequence number, ack number and TCP flags are fed to GCM as additional data. Someone cannot take a valid packet and move it to another flow, or flip a flag to forge a RST.
- **Replay protection** with a sliding window of 64 packets.
- **Fail closed.** No session means no traffic. If the program crashes, iptables keeps sending packets to a queue nobody reads, so they are dropped instead of leaking in clear.
- **Optional pre-shared key** to authenticate the handshake. Without it, plain Diffie–Hellman can be attacked by someone who sits in the middle of the control connection.
- **Optional periodic rekeying** from the initiator.
- **Built-in self-test** that needs no root and no network setup.
- **Demo script** that builds the whole PC1 / Device1 / Device2 / PC2 topology with network namespaces.

## Project structure

```
secgw/
├── README.md        this file
├── Makefile         builds the binary and runs the self-test
├── secgw.c          the whole program (one file, about 1,000 lines)
└── demo-netns.sh    builds a four-host test network and starts both devices
```

The binary is called `secgw`; InterSec is the name of the project. Inside `secgw.c`, from top to bottom:

| Part | What it does |
|---|---|
| session state | keys, salts, packet counter, replay window |
| IPv4 / TCP parsing and checksums | checks the packet is a valid unfragmented TCP/IPv4 packet, recomputes checksums |
| AES-GCM | encrypt and decrypt helpers on top of OpenSSL |
| `protect_packet` / `unprotect_packet` | the per-packet logic, the heart of the project |
| handshake | Diffie–Hellman, HKDF key derivation, key confirmation messages |
| NFQUEUE workers | one thread for the encrypt queue, one for the decrypt queue |
| control thread | opens or accepts the control connection, installs the session, notices when the peer disappears |
| self-test | 36 checks run with `./secgw -t` |

## How the handshake goes

```
Initiator → Responder   public value + random
Responder → Initiator   public value + random + proof that it derived the same keys
Initiator → Responder   proof that it derived the same keys       (responder starts using the session)
Responder → Initiator   "ready" proof                              (initiator starts using the session)
```

The keys come from HKDF-SHA256 over the Diffie–Hellman secret (and the pre-shared key if there is one), with a hash of the whole exchange as salt. Neither side starts using the session before the other proved it has the same keys.

---

## How to use it on Linux, step by step

Tested on Ubuntu with OpenSSL 3.0 and libnetfilter_queue 1.0.5. You need root for steps 4 to 6, because intercepting packets requires it.

### 1. Install what is needed

```bash
sudo apt update
sudo apt install -y gcc make pkg-config libssl-dev libnetfilter-queue-dev \
                    iproute2 iptables ethtool tcpdump curl python3
```

### 2. Build

```bash
cd secgw
make
```

You should now have a `secgw` binary next to the source.

### 3. Run the self-test (no root needed)

```bash
make test
# or directly:
./secgw -t
```

It runs the handshake, encrypts and decrypts packets in memory, and tries a set of attacks (flipped bits, replays, wrong key, injected clear packets…). The last line should say `SELFTEST OK (0 failures)`.

### 4. The quick way: the demo network

This creates four network namespaces (`pc1`, `dev1`, `dev2`, `pc2`), connects them in a line, sets up routing and iptables, creates a random pre-shared key and starts `secgw` on both devices.

```bash
sudo ./demo-netns.sh up
```

Addresses it uses:

| Host | Address |
|---|---|
| pc1 | 10.0.1.2 |
| dev1 | 10.0.1.1 (towards pc1) and 10.0.12.1 (towards dev2) |
| dev2 | 10.0.12.2 (towards dev1) and 10.0.2.1 (towards pc2) |
| pc2 | 10.0.2.2 |

The protected port is 8080 by default. To use another one: `sudo PORT=9000 ./demo-netns.sh up`.

Check that both devices are talking:

```bash
tail -n 20 /tmp/secgw-dev1.log /tmp/secgw-dev2.log
```

You are looking for the line `secure session installed` in both logs.

### 5. Send traffic through it

In one terminal, start a server on PC2:

```bash
sudo ip netns exec pc2 python3 -m http.server 8080
```

In a second terminal, fetch a page from PC1:

```bash
sudo ip netns exec pc1 curl -s http://10.0.2.2:8080/ | head
```

You get the normal directory listing: PC1 and PC2 never noticed anything.

### 6. Look at the wire to see the encryption

In a third terminal, listen on the link between the two devices, then repeat the `curl` from step 5:

```bash
sudo ip netns exec dev1 tcpdump -ni v-d1p -A 'tcp port 8080'
```

You will see the usual IP and TCP headers but the payload is unreadable bytes. For comparison, listen on the PC1 side, where the traffic is still clear:

```bash
sudo ip netns exec dev1 tcpdump -ni v-d1l -A 'tcp port 8080'
```

Here the HTTP request and the HTML are readable.

### 7. Prove that tampering is caught

With the demo running, kill Device2 and try again:

```bash
sudo pkill -f 'secgw -m responder'
sudo ip netns exec pc1 curl -m 5 http://10.0.2.2:8080/
```

The request hangs and times out. That is on purpose: without the peer there is no secure session, so the traffic is dropped instead of being sent in clear. Traffic on other ports (for example `ping`) is not selected and still goes through.

### 8. Clean up

```bash
sudo ./demo-netns.sh down
```

---

## Running it by hand on two real machines

The demo script is only a shortcut. On real machines the steps are the same. The examples below assume that on each device `eth0` faces the end host (PC1 or PC2) and `eth1` faces the other device, with Device1 at 10.0.12.1 and Device2 at 10.0.12.2. Adjust the names and addresses to your own network.

**On both devices**

```bash
# forward packets
sudo sysctl -w net.ipv4.ip_forward=1

# same pre-shared key on both: create it once, copy it to the other device (scp, USB…)
head -c 32 /dev/urandom > /etc/secgw.psk
chmod 600 /etc/secgw.psk

# no offloading, so the queue sees normal-sized packets
sudo ethtool -K eth0 tso off gso off gro off
sudo ethtool -K eth1 tso off gso off gro off
```

**iptables rules, on both devices** (`LAN` is the interface towards the end host, `PEER` is the one towards the other device, `8080` is the protected port):

```bash
LAN=eth0; PEER=eth1; PORT=8080

# packets coming from the end host go to the ENCRYPT queue (0)
sudo iptables -A FORWARD -i $LAN  -p tcp -m multiport --ports $PORT -j NFQUEUE --queue-num 0
# packets coming from the other device go to the DECRYPT queue (1)
sudo iptables -A FORWARD -i $PEER -p tcp -m multiport --ports $PORT -j NFQUEUE --queue-num 1

# every packet grows by 24 bytes, so keep TCP segments a bit smaller
sudo iptables -t mangle -A FORWARD -i $LAN -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1400

# the connection tracker would get confused by the longer packets between the devices
sudo iptables -t raw -A PREROUTING -p tcp -m multiport --ports $PORT -j CT --notrack
```

Note that there is deliberately no `--queue-bypass`. That is what makes the system fail closed.

**Routing:** PC1 must send its traffic for PC2 to Device1, Device1 must route towards Device2, Device2 towards PC2, and the same back. For example on Device1: `sudo ip route add <PC2 network> via <Device2 address>`.

**Start the programs**, Device2 first:

```bash
# Device2 (responder), assuming Device1 is 10.0.12.1
sudo ./secgw -m responder -p 10.0.12.1 -k /etc/secgw.psk

# Device1 (initiator), assuming Device2 is 10.0.12.2
sudo ./secgw -m initiator -p 10.0.12.2 -k /etc/secgw.psk
```

Stop with Ctrl-C. It prints how many packets were encrypted, decrypted and dropped.

## Command line options

| Option | Meaning |
|---|---|
| `-m initiator\|responder` | role. The initiator connects, the responder waits. |
| `-p IP` | address of the other device. Required for the initiator; the responder only accepts connections from it. |
| `-b IP` | responder: address to listen on (default: all). |
| `-c PORT` | control port (default 5555). It must be reachable between the two devices. |
| `-e N` / `-d N` | queue numbers for encrypt / decrypt (default 0 and 1). Must match your iptables rules. |
| `-k FILE` | pre-shared key file, at least 16 bytes. Strongly recommended. |
| `-r SECS` | initiator: renegotiate keys every SECS seconds. |
| `-v` | print one line per packet. |
| `-t` | run the self-test and exit. |

## Things to know (limits of the prototype)

- Only IPv4 and TCP. IP fragments are dropped.
- The tag and counter make each packet 24 bytes bigger, which is why the MSS is reduced. Without that, full-size packets would be too large for a normal 1500-byte link.
- Pure ACKs, SYN, FIN and RST are protected as well (empty ciphertext, counter and tag), so their headers are authenticated too. This costs 24 bytes on every selected packet.
- The checksums are recomputed on each device but not verified, because packets handled with offloading legitimately carry unfinished checksums. So corruption between an end host and its device is not detected by the device.
- Without `-k`, an attacker who can intercept the control connection can sit in the middle of the handshake.
- During a rekey, a few packets in flight can fail verification and are dropped; TCP retransmits them.
- The replay window is 64 packets. Packets reordered by more than that are dropped and TCP resends them.
- This is a university prototype: one session at a time, no privilege dropping after the queues are opened, and the iptables and NFQUEUE part has not been validated on a live network yet. The self-test covers the cryptography and packet handling, the demo script is there to cover the rest.
