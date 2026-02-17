#!/usr/bin/env bash
set -euo pipefail

echo "=== ClawShield Setup ==="
echo ""

# Check prerequisites
command -v bun >/dev/null 2>&1 || { echo "Error: bun is required but not installed."; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "Error: openssl is required but not installed."; exit 1; }

# Install dependencies
echo "1. Installing dependencies..."
bun install

# Generate keys
echo "2. Generating cryptographic keys..."
bash scripts/generate-keys.sh ./keys

# Create .env from example
if [ ! -f .env ]; then
  echo "3. Creating .env from .env.example..."
  cp .env.example .env
  # Fill in generated values
  ENCRYPTION_KEY=$(cat keys/encryption.key)
  if [[ "$OSTYPE" == "darwin"* ]]; then
    sed -i '' "s|^ENCRYPTION_KEY=.*|ENCRYPTION_KEY=${ENCRYPTION_KEY}|" .env
    sed -i '' "s|^JWT_PRIVATE_KEY_PATH=.*|JWT_PRIVATE_KEY_PATH=./keys/jwt_private.pem|" .env
    sed -i '' "s|^JWT_PUBLIC_KEY_PATH=.*|JWT_PUBLIC_KEY_PATH=./keys/jwt_public.pem|" .env
  else
    sed -i "s|^ENCRYPTION_KEY=.*|ENCRYPTION_KEY=${ENCRYPTION_KEY}|" .env
    sed -i "s|^JWT_PRIVATE_KEY_PATH=.*|JWT_PRIVATE_KEY_PATH=./keys/jwt_private.pem|" .env
    sed -i "s|^JWT_PUBLIC_KEY_PATH=.*|JWT_PUBLIC_KEY_PATH=./keys/jwt_public.pem|" .env
  fi
  echo "   .env created and populated"
else
  echo "3. .env already exists, skipping..."
fi

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Next steps:"
echo "  1. Start PostgreSQL and Redis (or use docker-compose):"
echo "     cd docker && docker compose up -d postgres redis"
echo "  2. Run database migrations:"
echo "     bun run db:migrate"
echo "  3. Start development server:"
echo "     bun run dev"
