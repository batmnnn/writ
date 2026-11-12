#!/bin/bash
# Build the Writ enclave image on the EC2 host and record PCR0, PCR1, and PCR2.
# Never pass --debug-mode. Debug mode reports 96 zero PCRs, and KMS will not decrypt.
# This script takes no key id, no alias, and no signing private key.
# It does not copy .env and it does not call AWS.

set +x
set -euo pipefail

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd) || {
  echo "Refusing to run: cannot find the repo root." >&2
  exit 1
}
cd -- "$root"

flag=$(printf '%s%s' '--' 'debug-mode')

refuse_debug() {
  echo "Refusing to run: debug mode was requested." >&2
  exit 1
}

refuse_key() {
  echo "Refusing to run: this script does not take a key id, an alias, or a signing private key." >&2
  exit 1
}

lower() {
  printf '%s' "$1" | LC_ALL=C tr '[:upper:]' '[:lower:]'
}

found=$(env | LC_ALL=C tr '[:upper:]' '[:lower:]' | LC_ALL=C grep -F -c -e "$flag" || true)
case "$found" in
  ''|*[!0-9]*)
    echo "Refusing to run: debug mode check failed." >&2
    exit 1
    ;;
esac
if [ "$found" -gt 0 ]; then
  refuse_debug
fi

while IFS= read -r name; do
  [ -n "$name" ] || continue
  case "$name" in
    *[!A-Za-z0-9_]*) continue ;;
  esac
  lname=$(lower "$name")
  case "$lname" in
    debug_mode|nitro_debug|nitro_debug_mode|nitro_cli_debug|nitro_cli_debug_mode|writ_debug_mode|enclave_debug_mode)
      value=$(printenv "$name" 2>/dev/null || true)
      vlow=$(lower "$value")
      case "$vlow" in
        ""|0|false|no|off) ;;
        *) refuse_debug ;;
      esac
      ;;
  esac
done <<EOF
$(env | awk -F= 'NF { print $1 }')
EOF

for arg in "$@"; do
  low=$(lower "$arg")
  case "$low" in
    *"$flag"*|--debug|--debug=*|debug-mode|debug-mode=*)
      refuse_debug
      ;;
  esac
done

for arg in "$@"; do
  low=$(lower "$arg")
  case "$low" in
    --private-key|--private-key=*|--signing-certificate|--signing-certificate=*|--key-id|--key-id=*|--kms-key-id|--kms-key-id=*|--alias|--alias=*|alias/*|arn:aws:kms:*|*.pem|*.key|*key-id*|*private-key*|*signing-certificate*|*alias/*|*"begin private"*|*"begin openssh"*|*"begin ec private"*)
      refuse_key
      ;;
  esac
done

if [ "$#" -ne 0 ]; then
  echo "Refusing to run: this script takes no arguments." >&2
  exit 1
fi

if ! command -v nitro-cli >/dev/null 2>&1; then
  # No nitro-cli on PATH, so do not invent PCR files.
  echo "This Mac cannot build an EIF."
  exit 2
fi

if ! command -v bun >/dev/null 2>&1; then
  echo "Refusing to build the EIF: bun is not on PATH." >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "Refusing to write PCR files: python3 is not on PATH." >&2
  exit 1
fi

if ! bun run scripts/eif.ts; then
  echo "Refusing to build the EIF: image build failed." >&2
  exit 1
fi

build_out=$(mktemp)
tmp=$(mktemp -d)
eif_path="$root/writ.eif"
cleanup() {
  rm -rf "$tmp"
  rm -f "$build_out"
}
trap cleanup EXIT

if [ -z "${NITRO_CLI_ARTIFACTS:-}" ] && [ -d /usr/share/nitro_enclaves/blobs ]; then
  export NITRO_CLI_ARTIFACTS=/usr/share/nitro_enclaves/blobs
fi

if ! command nitro-cli build-enclave --docker-uri writ-enclave:dev --output-file "$eif_path" >"$build_out"; then
  rm -f "$eif_path"
  echo "Enclave image build failed." >&2
  exit 1
fi

if ! python3 - "$build_out" "$tmp" <<'PY'
import json
import pathlib
import sys

def fail(message):
    print(message, file=sys.stderr)
    sys.exit(1)

raw = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
if raw.startswith("\ufeff"):
    raw = raw[1:]

decoder = json.JSONDecoder()
measurements = None
index = 0
while index < len(raw):
    start = raw.find("{", index)
    if start < 0:
        break
    try:
        data, _end = decoder.raw_decode(raw, start)
    except json.JSONDecodeError:
        index = start + 1
        continue
    if isinstance(data, dict) and isinstance(data.get("Measurements"), dict):
        measurements = data["Measurements"]
        break
    index = start + 1

if measurements is None:
    fail("Refusing to write PCR files: measurements are missing.")

hex_digits = set("0123456789abcdefABCDEF")
zeros = "0" * 96
parsed = {}
for name in ("PCR0", "PCR1", "PCR2"):
    value = measurements.get(name)
    if not isinstance(value, str):
        fail("Refusing to write PCR files: " + name + " is missing.")
    text = "".join(value.split())
    if text[:2].lower() == "0x":
        text = text[2:]
    if text == zeros:
        fail("Refusing to write PCR files: " + name + " is 96 zeros.")
    if len(text) != 96 or any(ch not in hex_digits for ch in text):
        fail("Refusing to write PCR files: " + name + " is missing.")
    parsed[name] = text

dest = pathlib.Path(sys.argv[2])
for name in ("PCR0", "PCR1", "PCR2"):
    (dest / (name + ".txt")).write_text(parsed[name] + "\n", encoding="utf-8")
PY
then
  rm -f "$eif_path"
  exit 1
fi

if [ ! -d "$root/enclave" ]; then
  rm -f "$eif_path"
  echo "Refusing to write PCR files: enclave directory is missing." >&2
  exit 1
fi

zeros=$(printf '%096d' 0)
for name in PCR0 PCR1 PCR2; do
  file="$tmp/${name}.txt"
  if [ ! -f "$file" ]; then
    rm -f "$eif_path"
    echo "Refusing to write PCR files: ${name} is missing." >&2
    exit 1
  fi
  text=$(LC_ALL=C tr -d '[:space:]' < "$file")
  if [ "${#text}" -ne 96 ] || [ "$text" = "$zeros" ]; then
    rm -f "$eif_path"
    if [ "$text" = "$zeros" ]; then
      echo "Refusing to write PCR files: ${name} is 96 zeros." >&2
    else
      echo "Refusing to write PCR files: ${name} is missing." >&2
    fi
    exit 1
  fi
  case "$text" in
    *[!0-9a-fA-F]*)
      rm -f "$eif_path"
      echo "Refusing to write PCR files: ${name} is missing." >&2
      exit 1
      ;;
  esac
done

mv -f "$tmp/PCR0.txt" "$root/enclave/PCR0.txt"
mv -f "$tmp/PCR1.txt" "$root/enclave/PCR1.txt"
mv -f "$tmp/PCR2.txt" "$root/enclave/PCR2.txt"
echo "Wrote enclave/PCR0.txt, enclave/PCR1.txt, and enclave/PCR2.txt."
