#!/usr/bin/env bash
set -euo pipefail

echo "Running database migrations..."
bunx drizzle-kit push

echo "Migrations complete."
