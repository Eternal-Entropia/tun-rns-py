#!/usr/bin/env bash
set -euo pipefail

echo ""
echo "=== ReticulumTUN Linux build ==="
echo ""

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if ! command -v python3 &>/dev/null; then
    echo "[X] Python3 not found."
    exit 1
fi

if [ ! -d ".venv" ]; then
    echo "[*] Creating .venv ..."
    python3 -m venv .venv
fi
source .venv/bin/activate

echo "[*] Installing dependencies ..."
python3 -m pip install --upgrade pip
python3 -m pip install pyinstaller rns

echo "[*] Building tun_rns_linux_gui ..."
pyinstaller --noconfirm --onefile --windowed \
    tun_rns_linux_gui.py

echo ""
echo "[+] Done: dist/tun_rns_linux_gui"
echo ""
