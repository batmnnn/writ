#!/bin/bash
# Ask the running-image enclave for one attestation document. No debug mode.
# Prints ATTEST_OK and the path of the raw COSE file. Never prints the API key.
set -euo pipefail

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd -- "$root"

if [ -z "${NITRO_CLI_ARTIFACTS:-}" ] && [ -d /usr/share/nitro_enclaves/blobs ]; then
  export NITRO_CLI_ARTIFACTS=/usr/share/nitro_enclaves/blobs
fi

eif="$root/writ.eif"
if [ ! -f "$eif" ]; then
  echo "Refusing: $eif is missing." >&2
  exit 1
fi

for arg in "$@"; do
  case "$(printf '%s' "$arg" | tr '[:upper:]' '[:lower:]')" in
    *debug*) echo "Refusing: debug mode." >&2; exit 1 ;;
  esac
done

nonce=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
printf '%s\n' "$nonce" > /var/log/writ-attest-nonce.txt
chmod 600 /var/log/writ-attest-nonce.txt

payload=$(NONCE="$nonce" python3 -c 'import json,os; print(json.dumps({"attestOnly": True, "nonce": os.environ["NONCE"]}))')
payload_file=$(mktemp)
chmod 600 "$payload_file"
printf '%s\n' "$payload" > "$payload_file"
unset payload

eid=""
cleanup() {
  rm -f "$payload_file"
  if [ -n "$eid" ]; then
    nitro-cli terminate-enclave --enclave-id "$eid" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

rm -f /var/log/writ-unseal-reply.log
socat "VSOCK-LISTEN:5000,reuseaddr" "EXEC:python3 ${root}/scripts/unseal-exchange.py ${payload_file}" >/var/log/writ-vsock-feed.log 2>&1 &
feed_pid=$!

run_json=$(nitro-cli run-enclave --eif-path "$eif" --cpu-count 2 --memory 3072 --enclave-cid 16)
eid=$(printf '%s' "$run_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["EnclaveID"])')
echo "enclave $eid"

for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do
  if [ -s /var/log/writ-unseal-reply.log ]; then
    break
  fi
  sleep 2
done
kill "$feed_pid" >/dev/null 2>&1 || true

line=$(tr -d '\r' < /var/log/writ-unseal-reply.log || true)
case "$line" in
  ATTEST\ *)
    printf '%s\n' "${line#ATTEST }" | base64 -d > /var/log/writ-attest.cbor
    echo "ATTEST_OK /var/log/writ-attest.cbor"
    echo "NONCE $nonce"
    exit 0
    ;;
  *)
    echo "No attestation document." >&2
    printf '%s\n' "$line" | head -c 200 >&2 || true
    echo >&2
    exit 1
    ;;
esac
