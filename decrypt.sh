#!/bin/sh
set -e

KEY_FILE="/run/secrets/age_key"
OUT="/run/app/config.json"

if [ ! -f "$KEY_FILE" ]; then
    echo "ERROR: Secret key file not found at $KEY_FILE"
    exit 1
fi

echo "Decrypting secrets..."
age -d -i "$KEY_FILE" -o "$OUT" /app/config.json.age
chmod 0400 "$OUT"

echo "Secrets decrypted and loaded into environment."
echo "Launching service..."

exec "$@"
