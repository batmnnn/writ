#!/bin/bash
# Host side of R1: forward public TCP 443 and 80 into the enclave as raw bytes. No debug mode.
# The host never ends TLS. There is no certificate, no nginx and no ALB here. The RA HMAC covers
# x-nonce only, so TLS has to end inside the enclave (src/host/enclave-tls.ts).
#
# Forwards (raw TCP to vsock CID 16, same as buildInboundForwarderArgv in src/host/enclave-parent.ts):
#   socat TCP-LISTEN:443,fork,reuseaddr VSOCK-CONNECT:16:443    RA HTTPS, ends at 127.0.0.1:8443 in the enclave
#   socat TCP-LISTEN:80,fork,reuseaddr VSOCK-CONNECT:16:80      ACME http-01, ends at 127.0.0.1:8080 in the enclave
# Outbound ACME (vsock-proxy, allowlist in enclave/parent/vsock-proxy.yaml):
#   vsock-proxy 8445 acme-v02.api.letsencrypt.org 443 --config enclave/parent/vsock-proxy.yaml
#   vsock-proxy 8446 acme-staging-v02.api.letsencrypt.org 443 --config enclave/parent/vsock-proxy.yaml
#
# This script prints the commands. On a machine without nitro-cli (a Mac) it exits 2 and writes nothing.
# It does not start an enclave and does not write PCR files.
set -euo pipefail

for arg in "$@"; do
  case "$(printf '%s' "$arg" | tr '[:upper:]' '[:lower:]')" in
    *debug*) echo "Refusing: debug mode." >&2; exit 1 ;;
  esac
done

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
eif="$root/writ.eif"

run_cmd="nitro-cli run-enclave --eif-path $eif --cpu-count 2 --memory 3072 --enclave-cid 16"
fwd_443="socat TCP-LISTEN:443,fork,reuseaddr VSOCK-CONNECT:16:443"
fwd_80="socat TCP-LISTEN:80,fork,reuseaddr VSOCK-CONNECT:16:80"
proxy_prod="vsock-proxy 8445 acme-v02.api.letsencrypt.org 443 --config $root/enclave/parent/vsock-proxy.yaml"
proxy_staging="vsock-proxy 8446 acme-staging-v02.api.letsencrypt.org 443 --config $root/enclave/parent/vsock-proxy.yaml"

echo "would run: $run_cmd"
echo "would run: $fwd_443"
echo "would run: $fwd_80"
echo "would run: $proxy_prod"
echo "would run: $proxy_staging"

if ! command -v nitro-cli >/dev/null 2>&1; then
  echo "nitro-cli not found: this is not an enclave host. Nothing started." >&2
  exit 2
fi

echo "nitro-cli found. This script only prints the plan; run the commands above by hand on the host." >&2
exit 0
