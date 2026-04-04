#!/bin/sh
set -e

OUT=${CONFIG_PATH:-"/run/app/config.json"}

if [ -f "$OUT" ]; then
    echo "Config already present at $OUT, skipping decryption."
    exec "$@"
fi

KEY_FILE="/run/secrets/age_key"
FILE="/run/secrets/encrypted_config"

if [ ! -f "$KEY_FILE" ]; then
    echo "ERROR: Secret key file not found at $KEY_FILE"
    exit 1
fi

if [ ! -f "$FILE" ]; then
    echo "ERROR: Encrypted config file not found at $FILE"
    exit 1
fi

echo "Decrypting secrets..."
age -d -i "$KEY_FILE" -o "$OUT" "$FILE"
chmod 0400 "$OUT"

echo "Secrets decrypted and loaded into environment."
echo "Launching service..."

exec "$@"
