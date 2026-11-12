#!/bin/sh
# First process inside the enclave. Plain sh, no network, no disk.
# Debug mode is never used with this image, and nothing here turns it on.
set -eu

# An enclave starts with the loopback interface down.
ip link set lo up

# Boot line bridge: src/host/enclave.ts connects to 127.0.0.1:5000 and reads one JSON line
# (sealed ciphertext and short-lived credentials) that the host serves on vsock CID 3 port 5000.
# KMS does not use this bridge: kmstool talks to the host vsock-proxy on the proxyPort in
# /app/enclave/config/kms.json.
socat TCP-LISTEN:5000,bind=127.0.0.1,reuseaddr,fork VSOCK-CONNECT:3:5000 &

# Outbound HTTPS for src/host/enclave-arm.ts. Each hostname maps to its own loopback address, so
# TLS (and its hostname check) runs inside the enclave and the host relays ciphertext only.
# The host must run vsock-proxy on port 8443 for S3 and 8444 for the Airwallex sandbox.
ip addr add 127.0.0.2/8 dev lo
ip addr add 127.0.0.3/8 dev lo
echo "127.0.0.2 s3.us-west-2.amazonaws.com" >> /etc/hosts
echo "127.0.0.3 api.sandbox.airwallex.com" >> /etc/hosts
socat TCP-LISTEN:443,bind=127.0.0.2,reuseaddr,fork VSOCK-CONNECT:3:8443 &
socat TCP-LISTEN:443,bind=127.0.0.3,reuseaddr,fork VSOCK-CONNECT:3:8444 &

# Outbound ACME for the RA certificate (src/host/enclave-tls.ts ACME_PLAN). Same pattern as above.
# The host must run vsock-proxy on port 8445 for production and 8446 for staging. Staging is the default.
ip addr add 127.0.0.4/8 dev lo
ip addr add 127.0.0.5/8 dev lo
echo "127.0.0.4 acme-v02.api.letsencrypt.org" >> /etc/hosts
echo "127.0.0.5 acme-staging-v02.api.letsencrypt.org" >> /etc/hosts
socat TCP-LISTEN:443,bind=127.0.0.4,reuseaddr,fork VSOCK-CONNECT:3:8445 &
socat TCP-LISTEN:443,bind=127.0.0.5,reuseaddr,fork VSOCK-CONNECT:3:8446 &

# Inbound, R1 only. The host forwards public TCP 443 and 80 to vsock CID 16 ports 443 and 80
# (scripts/run-serve-host.sh). Inside, vsock port 443 goes to 127.0.0.1:8443 (RA HTTPS, TLS ends in
# the bun process) and vsock port 80 goes to 127.0.0.1:8080 (ACME http-01). These are byte relays.
# boot.sh never starts a TLS server. The bun process does that.
socat VSOCK-LISTEN:443,reuseaddr,fork TCP:127.0.0.1:8443 &
socat VSOCK-LISTEN:80,reuseaddr,fork TCP:127.0.0.1:8080 &

# Host-only AWS credential refresh (src/host/enclave-creds.ts, scripts/host-refresh-creds.sh). Only the
# parent instance can open vsock port 5001. The host forwards no public port to it, and the public TLS
# server on 8443 has no route to 127.0.0.1:5001. Plain JSON line in, one status line out.
socat VSOCK-LISTEN:5001,reuseaddr,fork TCP:127.0.0.1:5001 &

exec /usr/local/bin/bun run /app/src/host/enclave.ts
