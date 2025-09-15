#!/bin/sh

set -eu

die() { echo "Error: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "Missing dependency: $1"; }

need ssh-agent
need ssh-add
need age
need age-keygen
need docker

echo "Setting up SSH agent..."
eval "$(ssh-agent -s)" || die "ssh-agent failed"


printf "Enter path to SSH key (default: %s): " "$HOME/.ssh/id_rsa_gh"
read -r ssh_key
ssh_key=${ssh_key:-"$HOME/.ssh/id_rsa_gh"}

[ -f "$ssh_key" ] || die "SSH key not found at: $ssh_key"

echo "Adding SSH key to agent (enter passphrase if prompted)..."
ssh-add "$ssh_key" </dev/tty || die "Failed to add SSH key (bad path or passphrase)."

CONFIG_FILE="config.json"
if [ -f "config.dev.json" ]; then
  CONFIG_FILE="config.dev.json"
  echo "Using dev config: $CONFIG_FILE (plaintext will be kept)."
elif [ -f "config.json" ]; then
  echo "Using config.json"
else
  die "Missing config.json (or config.dev.json) in project root."
fi

echo "generating secrets..."
age-keygen -o age_key || die "age-keygen failed"
age-keygen -y age_key > public_key || die "failed to derive public key"

echo "encrypting config..."
age -a -e -r "$(cat public_key)" -o config.json.age "$CONFIG_FILE" || die "encryption failed"

echo "changing permissions config..."
chmod 750 age_key || die "chmod age_key failed"

echo "starting docker"
mkdir -p app-logs detector-logs || die "mkdir logs failed"
chmod 777 age_key ./app-logs ./detector-logs || die "chmod logs failed"

docker compose up --build -d --force-recreate || die "docker compose failed"

chmod 600 age_key || true
rm -f public_key

if [ "$CONFIG_FILE" = "config.json" ]; then
  rm -f config.json
else
  echo "Keeping $CONFIG_FILE (dev)."
fi

exec "$@"