#!/bin/bash
# Writ tunnel helper.
# Without --start, print usage and exit 0.
# With --start, run cloudflared tunnel --url http://127.0.0.1:8787.
# When a trycloudflare.com URL appears, write it to /tmp/writ-ra-url.txt and print that URL only.
# This script does not call Airwallex. It does not print secrets.

set +x
set -euo pipefail
umask 077
set +o history
unset HISTFILE

url_file="/tmp/writ-ra-url.txt"
port="${WRIT_RA_PORT:-8787}"
listener="http://127.0.0.1:${port}"
work=""

contains_secret() {
  set +x
  local text="$1"
  local name val rest
  for name in AIRWALLEX_API_KEY AIRWALLEX_RA_SHARED_SECRET; do
    val="${!name-}"
    if [ -n "$val" ]; then
      rest=${text#*"$val"}
      if [ "$rest" != "$text" ]; then
        return 0
      fi
    fi
  done
  return 1
}

refuse() {
  set +x
  local msg="${1:-Refusing to run.}"
  if contains_secret "$msg"; then
    exit 1
  fi
  printf '%s\n' "$msg" >&2
  exit 1
}

cleanup() {
  trap - EXIT INT TERM
  if [ -n "$work" ]; then
    rm -rf "$work"
    work=""
  fi
}

if [ "${1:-}" != "--start" ] || [ "$#" -ne 1 ]; then
  line1="Usage: scripts/ra-tunnel.sh --start"
  line2="Pass --start to open a tunnel to ${listener}."
  line3="The public URL is written to ${url_file}."
  if contains_secret "$line1" || contains_secret "$line2" || contains_secret "$line3"; then
    refuse
  fi
  printf '%s\n' "$line1"
  printf '%s\n' "$line2"
  printf '%s\n' "$line3"
  exit 0
fi

# The RA server in this shell needs the shared secret. cloudflared does not.
# Unset both names in the child so its logs cannot echo them.
if [ -x /opt/homebrew/bin/cloudflared ]; then
  cloudflared_bin=/opt/homebrew/bin/cloudflared
elif command -v cloudflared >/dev/null 2>&1; then
  cloudflared_bin=$(command -v cloudflared)
else
  refuse "Refusing to run: cloudflared is not on PATH."
fi

trap cleanup EXIT
trap 'cleanup; exit 1' INT TERM

work=$(mktemp -d "${TMPDIR:-/tmp}/writ-ra-tunnel.XXXXXX")
chmod 700 "$work"
printed_flag="$work/printed"
secret_flag="$work/secret"

status=0
(
  unset AIRWALLEX_API_KEY
  unset AIRWALLEX_RA_SHARED_SECRET
  exec "$cloudflared_bin" tunnel --url "$listener"
) 2>&1 | while IFS= read -r line || [ -n "${line:-}" ]; do
  if [[ "$line" =~ https?://[A-Za-z0-9.-]+\.trycloudflare\.com ]]; then
    url="${BASH_REMATCH[0]}"
    if [ ! -f "$printed_flag" ]; then
      if contains_secret "$url"; then
        : > "$secret_flag"
        exit 1
      fi
      printf '%s\n' "$url" > "$url_file"
      chmod 600 "$url_file"
      printf '%s\n' "$url"
      : > "$printed_flag"
    fi
  fi
  true
done || status=$?

if [ -f "$secret_flag" ]; then
  rm -f "$url_file"
  refuse "Refusing to run: the tunnel URL would include a secret."
fi

if [ ! -f "$printed_flag" ]; then
  refuse "Refusing to run: no trycloudflare.com URL appeared."
fi

if [ "$status" -ne 0 ]; then
  exit "$status"
fi
