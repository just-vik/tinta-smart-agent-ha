#!/bin/sh
set -e
DATA_DIR="${DATA_DIR:-/data}"
export TINTA_DATA_DIR="$DATA_DIR"

# Если передан pairing code (из настроек addon), сначала bootstrap
if [ -n "${PAIRING_CODE}" ] && [ ! -f "${DATA_DIR}/access_token" ]; then
  export TINTA_PAIRING_CODE="$PAIRING_CODE"
  /usr/local/bin/tinta-agent -bootstrap
  echo "Bootstrap OK. Restart addon without pairing_code to start reporting."
  exit 0
fi

# Иначе обычный режим: heartbeat + telemetry + tunnel-status
exec /usr/local/bin/tinta-agent
