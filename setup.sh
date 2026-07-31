#!/usr/bin/env bash
# icsFuzzer setup script
# Run on Ubuntu/Debian (WSL2 recommended). See SECURITY.md before use.

set -euo pipefail

VENV_DIR="venv"

echo "[setup] icsFuzzer dependency installer"
echo "[setup] Requires: Ubuntu 22.04+ / Debian 12+ (WSL2 or native Linux)"
echo ""

# Check we're on Linux
if [[ "$(uname -s)" != "Linux" ]]; then
    echo "[error] This setup script requires Linux (or WSL2)."
    echo "        Windows users: install WSL2 with Ubuntu 24.04, then re-run."
    exit 1
fi

# System dependencies
echo "[setup] Installing system build dependencies ..."
sudo apt-get update -qq
sudo apt-get install -y -qq \
    python3 python3-pip python3-venv \
    build-essential cmake git libssl-dev \
    wireshark-common tshark

# Python virtual environment
if [[ ! -d "$VENV_DIR" ]]; then
    echo "[setup] Creating Python virtual environment ..."
    python3 -m venv "$VENV_DIR"
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
pip install --upgrade pip --quiet

# Core + Phase 2 dependencies
echo "[setup] Installing core and Phase 2 dependencies ..."
pip install --quiet \
    scapy \
    networkx \
    pyvis \
    pymodbus \
    asyncua

# Phase 3: pure-Python protocols
echo "[setup] Installing Phase 3 pure-Python protocol libraries ..."
pip install --quiet \
    pycomm3 \
    bacpypes3

# Phase 3: C++ extension protocols
echo "[setup] Installing Phase 3 C++ extension protocols ..."

echo "  [setup] Installing pydnp3 (OpenDNP3 bindings) ..."
pip install --quiet pydnp3 || {
    echo "  [warn] pydnp3 pip install failed, trying from source ..."
    pip install --quiet dnp3-python || echo "  [warn] DNP3 library not installed. DNP3 module will be unavailable."
}

echo "  [setup] Installing c104 (IEC 60870-5-104 bindings) ..."
pip install --quiet c104 || echo "  [warn] c104 not installed. IEC 104 module will be unavailable."

echo "  [setup] Installing pyiec61850-ng (libiec61850 bindings) ..."
pip install --quiet pyiec61850-ng || echo "  [warn] pyiec61850-ng not installed. IEC 61850 module will be unavailable."

echo ""
echo "[setup] Done. Activate venv with: source venv/bin/activate"
echo "[setup] Then run: python icsFuzzer.py --list-protocols"
