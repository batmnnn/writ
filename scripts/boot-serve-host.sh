#!/bin/bash
# Boot the serve enclave on the host, as root. Prints the issuer and the public ledger key only.
# Production flags only. Keeps the enclave's S3 credentials fresh with a refresh loop.
set +x
set -euo pipefail
umask 077
export PATH=/usr/local/bin:$PATH
export AWS_REGION=us-west-2
export AWS_DEFAULT_REGION=us-west-2
export NITRO_CLI_ARTIFACTS=/usr/share/nitro_enclaves/blobs
cd /opt/writ

cp enclave/parent/vsock-proxy.yaml /etc/nitro_enclaves/vsock-proxy.yaml
cfg=/etc/nitro_enclaves/vsock-proxy.yaml

nitro-cli describe-enclaves | python3 -c '
import json, sys, subprocess
raw = sys.stdin.read().strip()
if not raw:
    sys.exit(0)
try:
    data = json.loads(raw)
except Exception:
    sys.exit(0)
if isinstance(data, dict):
    data = data.get("Enclaves") or data.get("enclaves") or []
for item in data or []:
    eid = item.get("EnclaveID") or item.get("enclave_id")
    if eid:
        subprocess.run(["nitro-cli", "terminate-enclave", "--enclave-id", eid], check=False)
'

start_proxy() {
  local port="$1" host="$2"
  if ! pgrep -f "vsock-proxy ${port} ${host} 443" >/dev/null 2>&1; then
    vsock-proxy "$port" "$host" 443 --config "$cfg" >>/var/log/writ-vsock-proxy.log 2>&1 &
  fi
}
start_proxy 8000 kms.us-west-2.amazonaws.com
start_proxy 8443 s3.us-west-2.amazonaws.com
start_proxy 8444 api.sandbox.airwallex.com
start_proxy 8445 acme-v02.api.letsencrypt.org
start_proxy 8446 acme-staging-v02.api.letsencrypt.org

if ! ss -ltn | grep -q ':80 '; then
  socat TCP-LISTEN:80,fork,reuseaddr,bind=0.0.0.0 VSOCK-CONNECT:16:80 >>/var/log/writ-socat.log 2>&1 &
fi
if ! ss -ltn | grep -q ':443 '; then
  socat TCP-LISTEN:443,fork,reuseaddr,bind=0.0.0.0 VSOCK-CONNECT:16:443 >>/var/log/writ-socat.log 2>&1 &
fi
sleep 0.5

token=$(curl -fsS -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 300")
role=$(curl -fsS -H "X-aws-ec2-metadata-token: $token" http://169.254.169.254/latest/meta-data/iam/security-credentials/)
creds=$(curl -fsS -H "X-aws-ec2-metadata-token: $token" "http://169.254.169.254/latest/meta-data/iam/security-credentials/$role")
secret=$(aws secretsmanager get-secret-value --region us-west-2 --secret-id writ/airwallex/api-key.kms --query SecretString --output text)
payload_file=$(mktemp)
chmod 600 "$payload_file"
CREDS="$creds" SECRET="$secret" python3 -c '
import json, os, sys
def fail(msg):
    sys.stderr.write(msg + "\n")
    sys.exit(1)
try:
    creds = json.loads(os.environ["CREDS"])
    secret = json.loads(os.environ["SECRET"])
except Exception:
    fail("boot material is not JSON")
blob = secret.get("ciphertext") if isinstance(secret, dict) else None
ra_blob = secret.get("raCiphertext") if isinstance(secret, dict) else None
if not isinstance(blob, str) or len(blob) < 40 or blob == "SEAL_ME":
    fail("secret is not ciphertext")
for name in ("AccessKeyId", "SecretAccessKey", "Token"):
    if not isinstance(creds.get(name), str) or not creds[name]:
        fail("role credentials are incomplete")
payload = {
    "ciphertextB64": blob,
    "accessKeyId": creds["AccessKeyId"],
    "secretAccessKey": creds["SecretAccessKey"],
    "sessionToken": creds["Token"],
}
if isinstance(ra_blob, str) and len(ra_blob) > 40:
    payload["raCiphertextB64"] = ra_blob
client_id = secret.get("clientId") if isinstance(secret, dict) else None
if not isinstance(client_id, str) or not client_id:
    fail("clientId missing from the secret: the enclave cannot log in to Airwallex")
payload["clientId"] = client_id
sys.stdout.write(json.dumps(payload))
' > "$payload_file"
unset creds secret token role

rm -f /var/log/writ-unseal-reply.log
socat VSOCK-LISTEN:5000,reuseaddr "EXEC:python3 /opt/writ/scripts/unseal-exchange.py ${payload_file}" >/var/log/writ-vsock-feed.log 2>&1 &

run_json=$(nitro-cli run-enclave --eif-path /opt/writ/writ.eif --cpu-count 2 --memory 3072 --enclave-cid 16)
printf '%s\n' "$run_json" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("EnclaveID",""))' > /var/log/writ-serve.id

reply="NONE"
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
  if [ -s /var/log/writ-unseal-reply.log ]; then
    reply=$(tr -cd 'A-Za-z0-9 _:.' < /var/log/writ-unseal-reply.log)
    break
  fi
  sleep 1
done
printf '%s\n' "$reply" > /var/log/writ-ledger-pub.txt
echo "REPLY ${reply}"

issuer="NONE"
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36; do
  issuer=$(timeout 5 openssl s_client -connect 127.0.0.1:443 -servername 35-95-168-131.sslip.io </dev/null 2>/dev/null | openssl x509 -noout -issuer 2>/dev/null || true)
  if [ -n "$issuer" ] && ! printf '%s' "$issuer" | grep -q STAGING; then
    break
  fi
  sleep 5
done
echo "ISSUER ${issuer:-NONE}"
rm -f "$payload_file"

pkill -f writ-creds-loop >/dev/null 2>&1 || true
nohup bash -c 'exec -a writ-creds-loop bash -c "while true; do sleep 1200; /opt/writ/scripts/host-refresh-creds.sh >>/var/log/writ-creds.log 2>&1 || true; done"' >/dev/null 2>&1 &
