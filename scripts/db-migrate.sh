#!/usr/bin/env bash
set -euo pipefail

echo "Running database migrations..."
bunx drizzle-kit migrate

echo "Migrations complete."
