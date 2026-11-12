#!/bin/bash
# Run on the enclave host after writ.eif exists. No debug mode.
# Fetches the sealed ciphertext and short-lived role credentials, hands them to the
# enclave over vsock with the card id and client id, and prints ARMED on success.
# DECLINED is a failure. Never prints the key, the role secret, the session token, or the ciphertext.
# The payload file is mode 600 and removed on exit. It is not logged.
set +x
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

# Required before any fetch. An empty id must not reach Secrets Manager or IMDS.
if [ -z "${WRIT_CARD_ID:-}" ] || [ -z "${WRIT_CLIENT_ID:-}" ]; then
  echo "Refusing: WRIT_CARD_ID and WRIT_CLIENT_ID must both be set." >&2
  exit 1
fi

started_proxy=0
start_vsock_proxy() {
  local listen_port="$1"
  local upstream_host="$2"
  if ! pgrep -f "vsock-proxy ${listen_port} ${upstream_host} 443" >/dev/null 2>&1; then
    vsock-proxy "$listen_port" "$upstream_host" 443 >>/var/log/writ-vsock-proxy.log 2>&1 &
    started_proxy=1
  fi
}

# KMS, S3 checkpoints, and the Airwallex sandbox. Start each only if it is not already running.
start_vsock_proxy 8000 kms.us-west-2.amazonaws.com
start_vsock_proxy 8443 s3.us-west-2.amazonaws.com
start_vsock_proxy 8444 api.sandbox.airwallex.com
if [ "$started_proxy" -eq 1 ]; then
  sleep 0.5
fi

token=$(curl -fsS -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 120")
role=$(curl -fsS -H "X-aws-ec2-metadata-token: $token" http://169.254.169.254/latest/meta-data/iam/security-credentials/)
creds=$(curl -fsS -H "X-aws-ec2-metadata-token: $token" "http://169.254.169.254/latest/meta-data/iam/security-credentials/$role")
secret=$(aws secretsmanager get-secret-value --region us-west-2 --secret-id writ/airwallex/api-key.kms --query SecretString --output text)

payload=$(CREDS="$creds" SECRET="$secret" WRIT_CARD_ID="$WRIT_CARD_ID" WRIT_CLIENT_ID="$WRIT_CLIENT_ID" python3 -c '
import json, os, sys

def fail(msg):
    sys.stderr.write(msg + "\n")
    sys.exit(1)

card_id = os.environ.get("WRIT_CARD_ID", "")
client_id = os.environ.get("WRIT_CLIENT_ID", "")
if len(card_id) == 0 or len(client_id) == 0:
    fail("Refusing: WRIT_CARD_ID and WRIT_CLIENT_ID must both be set.")
try:
    creds = json.loads(os.environ["CREDS"])
except Exception:
    fail("refusing: role credentials are not JSON")
try:
    secret = json.loads(os.environ["SECRET"])
except Exception:
    fail("refusing: secret is not JSON")
if not isinstance(creds, dict):
    fail("refusing: role credentials are incomplete")
if not isinstance(secret, dict):
    fail("refusing: secret is not ciphertext")
blob = secret.get("ciphertext")
if not isinstance(blob, str) or len(blob) < 40 or blob == "SEAL_ME":
    fail("refusing: secret is not ciphertext")
for name in ("AccessKeyId", "SecretAccessKey", "Token"):
    value = creds.get(name)
    if not isinstance(value, str) or len(value) == 0:
        fail("refusing: role credentials are incomplete")
try:
    encoded = json.dumps({
        "ciphertextB64": blob,
        "accessKeyId": creds["AccessKeyId"],
        "secretAccessKey": creds["SecretAccessKey"],
        "sessionToken": creds["Token"],
        "cardId": card_id,
        "clientId": client_id,
    })
except Exception:
    fail("refusing: could not encode the boot line")
sys.stdout.write(encoded)
')
unset creds secret token role

payload_file=$(mktemp)
chmod 600 "$payload_file"
printf '%s\n' "$payload" > "$payload_file"
unset payload

cleanup() {
  rm -f "$payload_file"
  if [ -n "${eid:-}" ]; then
    nitro-cli terminate-enclave --enclave-id "$eid" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

rm -f /var/log/writ-unseal-reply.log
socat "VSOCK-LISTEN:5000,reuseaddr" "EXEC:python3 ${root}/scripts/unseal-exchange.py ${payload_file}" >/var/log/writ-vsock-feed.log 2>&1 &
feed_pid=$!

run_json=$(nitro-cli run-enclave --eif-path "$eif" --cpu-count 2 --memory 3072 --enclave-cid 16)
eid=$(printf '%s' "$run_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["EnclaveID"])')
echo "enclave $eid" >&2

# Debug mode is the only way to read the console, and it zeroes PCRs. Wait for the vsock reply.
for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do
  if [ -s /var/log/writ-unseal-reply.log ]; then
    break
  fi
  sleep 5
done
kill "$feed_pid" >/dev/null 2>&1 || true

status=""
if [ -f /var/log/writ-unseal-reply.log ]; then
  IFS= read -r status < /var/log/writ-unseal-reply.log || true
  status=${status%$'\r'}
fi
case "$status" in
  ARMED)
    printf '%s\n' ARMED
    exit 0
    ;;
  DECLINED\ *)
    printf '%s\n' "$status" >&2
    exit 1
    ;;
esac
echo "No arm status on the vsock reply." >&2
exit 1
