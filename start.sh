#!/bin/sh

set -eu

die() { echo "Error: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "Missing dependency: $1"; }

need age
need age-keygen
need docker

CONFIG_FILE=${1:-}

if [ -n "$CONFIG_FILE" ]; then
    if [ ! -f "$CONFIG_FILE" ]; then
        die "Config file not found: $CONFIG_FILE"
    fi
    echo "Using provided config: $CONFIG_FILE"
elif [ -f "config.dev.json" ]; then
    CONFIG_FILE="config.dev.json"
    echo "Using dev config: $CONFIG_FILE"
elif [ -f "config.json" ]; then
    CONFIG_FILE="config.json"
    echo "Using default config.json"
else
    die "Missing config.json (or config.dev.json) in project root."
fi

echo "generating secrets..."
rm -f age_key public_key
age-keygen -o age_key || die "age-keygen failed"
age-keygen -y age_key > public_key || die "failed to derive public key"

echo "encrypting config..."
age -a -e -r "$(cat public_key)" -o config.json.age "$CONFIG_FILE" || die "encryption failed"

echo "changing permissions..."
chmod 750 age_key || die "chmod age_key failed"

echo "starting docker service..."
mkdir -p app-logs detector-logs || die "mkdir logs failed"
chmod 777 age_key ./app-logs ./detector-logs || die "chmod logs failed"

docker compose up --build -d --force-recreate auth || die "docker compose failed"

chmod 600 age_key || true
rm -f public_key

if [ "$CONFIG_FILE" = "config.json" ]; then
  rm -f config.json
  echo "Deleted sensitive config.json"
else
  echo "Keeping config file: $CONFIG_FILE"
fi