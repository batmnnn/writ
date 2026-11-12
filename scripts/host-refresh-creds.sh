#!/bin/bash
# Runs on the enclave host, as root. Reads the instance role credentials from IMDSv2 and sends them to the
# enclave over vsock CID 16 port 5001 (src/host/enclave-creds.ts), so S3 checkpoints keep working after
# the boot line credentials expire. Prints only the expiration and the enclave's one line reply.
# The credentials are not a trust root (the role cannot decrypt without the attestation), but they are
# still never printed, logged or written to disk.
#
# Run it every 30 minutes, for example from cron:
#   */30 * * * * root /opt/writ/scripts/host-refresh-creds.sh >>/var/log/writ-creds.log 2>&1
set -euo pipefail

for arg in "$@"; do
  case "$(printf '%s' "$arg" | tr '[:upper:]' '[:lower:]')" in
    *debug*) echo "Refusing: debug mode." >&2; exit 1 ;;
  esac
done

for tool in socat curl python3; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "$tool not found: run this on the enclave host. Nothing sent." >&2
    exit 2
  fi
done

cid="${WRIT_ENCLAVE_CID:-16}"
port=5001
imds="http://169.254.169.254/latest"

token=$(curl -fsS -X PUT "$imds/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
role=$(curl -fsS -H "X-aws-ec2-metadata-token: $token" "$imds/meta-data/iam/security-credentials/")
creds=$(curl -fsS -H "X-aws-ec2-metadata-token: $token" "$imds/meta-data/iam/security-credentials/$role")
unset token role

line=$(CREDS="$creds" python3 -c '
import json, os, sys
try:
    c = json.loads(os.environ["CREDS"])
except Exception:
    sys.stderr.write("refusing: role credentials are not JSON\n")
    sys.exit(1)
out = {}
for src, dst in (("AccessKeyId", "accessKeyId"), ("SecretAccessKey", "secretAccessKey"), ("Token", "sessionToken"), ("Expiration", "expiration")):
    v = c.get(src) if isinstance(c, dict) else None
    if not isinstance(v, str) or len(v) == 0:
        sys.stderr.write("refusing: role credentials are incomplete\n")
        sys.exit(1)
    out[dst] = v
sys.stdout.write(json.dumps(out))
')
expiration=$(CREDS="$creds" python3 -c 'import json, os; print(json.loads(os.environ["CREDS"])["Expiration"])')
unset creds

reply=$(printf '%s\n' "$line" | socat -t 5 - "VSOCK-CONNECT:${cid}:${port}" || true)
unset line

echo "role credentials expire $expiration"
echo "enclave: ${reply:-no reply}"
case "$reply" in
  OK\ *) exit 0 ;;
  *) exit 1 ;;
esac
