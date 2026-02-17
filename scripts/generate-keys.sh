#!/usr/bin/env bash
set -euo pipefail

KEYS_DIR="${1:-./keys}"

echo "Generating cryptographic keys in ${KEYS_DIR}..."
mkdir -p "${KEYS_DIR}"

# Generate RSA 4096-bit key pair for JWT
echo "Generating RSA key pair for JWT (RS256)..."
openssl genrsa -out "${KEYS_DIR}/jwt_private.pem" 4096
openssl rsa -in "${KEYS_DIR}/jwt_private.pem" -pubout -out "${KEYS_DIR}/jwt_public.pem"
chmod 600 "${KEYS_DIR}/jwt_private.pem"
chmod 644 "${KEYS_DIR}/jwt_public.pem"

# Generate AES-256 encryption key (32 bytes = 64 hex chars)
echo "Generating AES-256 encryption key..."
ENCRYPTION_KEY=$(openssl rand -hex 32)
echo "${ENCRYPTION_KEY}" > "${KEYS_DIR}/encryption.key"
chmod 600 "${KEYS_DIR}/encryption.key"

echo ""
echo "Keys generated successfully!"
echo "  JWT Private Key: ${KEYS_DIR}/jwt_private.pem"
echo "  JWT Public Key:  ${KEYS_DIR}/jwt_public.pem"
echo "  Encryption Key:  ${KEYS_DIR}/encryption.key"
echo ""
echo "Add to .env:"
echo "  JWT_PRIVATE_KEY_PATH=${KEYS_DIR}/jwt_private.pem"
echo "  JWT_PUBLIC_KEY_PATH=${KEYS_DIR}/jwt_public.pem"
echo "  ENCRYPTION_KEY=${ENCRYPTION_KEY}"
